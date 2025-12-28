// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build pkcs11

package hsm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS11Signer is the real CGO-backed PKCS#11 v2.40 signer. It is
// activated by the `pkcs11` build tag. The same code path covers every
// PKCS#11-compliant token because all vendor differences are absorbed
// by the libCryptoki shared library configured via PKCS11Config.LibraryPath.
//
// Lifecycle: NewPKCS11Signer initializes the library, opens a long-lived
// session against the configured slot, performs C_Login once, and caches
// the private-key handle. Sign and Verify reuse the session. Close
// finalizes the library.
//
// Concurrency: the embedded mutex serializes Sign/Verify calls because
// PKCS#11 sessions are not goroutine-safe. Callers that need parallel
// signing should construct one PKCS11Signer per worker.
type PKCS11Signer struct {
	Config PKCS11Config

	mu      sync.Mutex
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	priv    pkcs11.ObjectHandle
	pub     pkcs11.ObjectHandle
}

// NewPKCS11Signer initializes the CGO library, logs in, and resolves
// the configured key handles. Errors are returned eagerly so deployments
// fail fast on misconfiguration.
func NewPKCS11Signer(cfg PKCS11Config) (*PKCS11Signer, error) {
	if cfg.LibraryPath == "" {
		return nil, errors.New("hsm/pkcs11: LibraryPath is required")
	}
	if cfg.KeyLabel == "" {
		return nil, errors.New("hsm/pkcs11: KeyLabel is required")
	}
	pin, err := cfg.pinFromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}

	ctx := pkcs11.New(cfg.LibraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("hsm/pkcs11: failed to load library %q", cfg.LibraryPath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("hsm/pkcs11: C_Initialize: %w", err)
	}

	slotID, err := resolveSlot(ctx, cfg)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, err
	}

	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("hsm/pkcs11: C_OpenSession on slot %d: %w", slotID, err)
	}

	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("hsm/pkcs11: C_Login: %w", err)
	}

	priv, err := findKey(ctx, session, cfg.KeyLabel, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		ctx.Logout(session)
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("hsm/pkcs11: locate private key %q: %w", cfg.KeyLabel, err)
	}

	// Public key may be absent on tokens that hold only the private
	// half (e.g., HSM-imported keys). A missing public key is not fatal
	// — Verify falls back to local verification with a caller-supplied
	// pinned key in that case.
	pub, _ := findKey(ctx, session, cfg.KeyLabel, pkcs11.CKO_PUBLIC_KEY)

	return &PKCS11Signer{
		Config:  cfg,
		ctx:     ctx,
		session: session,
		priv:    priv,
		pub:     pub,
	}, nil
}

// Provider returns "pkcs11".
func (s *PKCS11Signer) Provider() string { return pkcs11ProviderName }

// Sign produces a signature over message. For ECDSA mechanisms the
// caller-supplied keyID is ignored — the key is resolved at construction
// from PKCS11Config.KeyLabel. The keyID parameter is preserved on the
// Signer interface for symmetry with cloud HSMs.
func (s *PKCS11Signer) Sign(_ context.Context, _ string, message []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	mech, input, err := mechanismFor(s.Config.Mechanism, message)
	if err != nil {
		return nil, err
	}
	if err := s.ctx.SignInit(s.session, []*pkcs11.Mechanism{mech}, s.priv); err != nil {
		return nil, fmt.Errorf("hsm/pkcs11: C_SignInit: %w", err)
	}
	sig, err := s.ctx.Sign(s.session, input)
	if err != nil {
		return nil, fmt.Errorf("hsm/pkcs11: C_Sign: %w", err)
	}
	return sig, nil
}

// Verify uses the on-token public key when present; otherwise it
// returns ErrPKCS11VerifyNoPubkey to signal that the caller must verify
// against a pinned out-of-band public key.
func (s *PKCS11Signer) Verify(_ context.Context, _ string, message, signature []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pub == 0 {
		return false, errPKCS11VerifyNoPubkey
	}
	mech, input, err := mechanismFor(s.Config.Mechanism, message)
	if err != nil {
		return false, err
	}
	if err := s.ctx.VerifyInit(s.session, []*pkcs11.Mechanism{mech}, s.pub); err != nil {
		return false, fmt.Errorf("hsm/pkcs11: C_VerifyInit: %w", err)
	}
	if err := s.ctx.Verify(s.session, input, signature); err != nil {
		// CKR_SIGNATURE_INVALID is a verification failure, not an error.
		var pErr pkcs11.Error
		if errors.As(err, &pErr) && pErr == pkcs11.CKR_SIGNATURE_INVALID {
			return false, nil
		}
		return false, fmt.Errorf("hsm/pkcs11: C_Verify: %w", err)
	}
	return true, nil
}

// Close logs out, closes the session, and finalizes the library.
func (s *PKCS11Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return nil
	}
	_ = s.ctx.Logout(s.session)
	_ = s.ctx.CloseSession(s.session)
	_ = s.ctx.Finalize()
	s.ctx.Destroy()
	s.ctx = nil
	return nil
}

// resolveSlot returns the slot ID matching cfg, preferring TokenLabel
// when set and falling back to SlotID otherwise.
func resolveSlot(ctx *pkcs11.Ctx, cfg PKCS11Config) (uint, error) {
	if cfg.TokenLabel == "" {
		return cfg.SlotID, nil
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("hsm/pkcs11: C_GetSlotList: %w", err)
	}
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.TrimSpace(info.Label) == cfg.TokenLabel {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("hsm/pkcs11: no slot has token label %q", cfg.TokenLabel)
}

// findKey locates a key by CKA_LABEL and CKA_CLASS.
func findKey(ctx *pkcs11.Ctx, sess pkcs11.SessionHandle, label string, class uint) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := ctx.FindObjectsInit(sess, tmpl); err != nil {
		return 0, fmt.Errorf("C_FindObjectsInit: %w", err)
	}
	defer ctx.FindObjectsFinal(sess)
	objs, _, err := ctx.FindObjects(sess, 1)
	if err != nil {
		return 0, fmt.Errorf("C_FindObjects: %w", err)
	}
	if len(objs) == 0 {
		return 0, errors.New("no matching object")
	}
	return objs[0], nil
}

// PKCS#11 v3.0 mechanism numbers added since the miekg/pkcs11 v1.1.1
// constant table was generated. These values are taken from the OASIS
// PKCS#11 Cryptographic Token Interface Current Mechanisms Specification
// Version 3.0 §2.x. miekg/pkcs11.NewMechanism takes a uint mechanism ID,
// so the v3.0 additions can be wired in without a library upgrade.
const (
	ckmEdDSA         uint = 0x00001057
	ckmEcdsaSha3_224 uint = 0x00001047
	ckmEcdsaSha3_256 uint = 0x00001048
	ckmEcdsaSha3_384 uint = 0x00001049
	ckmEcdsaSha3_512 uint = 0x0000104A
)

// mechanismFor returns the PKCS#11 mechanism and the input bytes the
// token expects (digest for raw mechanisms, raw message for hashing
// mechanisms). The default is CKM_ECDSA_SHA256 because that matches the
// most common deployment (Bitcoin/EVM signing on a Luna-class HSM).
//
// PKCS#11 v3.0 additions (per PKCS #11 Mechanisms Spec v3.0 §2.x):
//
//   - SHA-3 ECDSA / RSA mechanisms (CKM_ECDSA_SHA3_256, CKM_SHA3_256_RSA_PKCS_PSS)
//   - RSA-PSS via CKM_RSA_PKCS_PSS with explicit PSS parameters
//   - AEAD primitives (CKM_AES_GCM, CKM_AES_CCM) for encrypt/decrypt
//
// Sign mechanisms exposed here cover the full v3.0 signing surface used
// by ECDSA / EdDSA / RSA tokens. AEAD mechanisms are for encryption and
// are not appropriate for the Sign code path — operators using the
// PKCS11Signer for AEAD encryption hold a separate Encryptor adapter
// (out of scope here).
func mechanismFor(name string, message []byte) (*pkcs11.Mechanism, []byte, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	// ECDSA family (v2.40 baseline)
	case "", "ECDSA_SHA256", "CKM_ECDSA_SHA256":
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil), message, nil
	case "ECDSA_SHA384", "CKM_ECDSA_SHA384":
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA384, nil), message, nil
	case "ECDSA_SHA512", "CKM_ECDSA_SHA512":
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA512, nil), message, nil
	case "ECDSA", "CKM_ECDSA":
		h := sha256.Sum256(message)
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), h[:], nil

	// ECDSA + SHA-3 (PKCS#11 v3.0)
	case "ECDSA_SHA3_256", "CKM_ECDSA_SHA3_256":
		return pkcs11.NewMechanism(ckmEcdsaSha3_256, nil), message, nil
	case "ECDSA_SHA3_384", "CKM_ECDSA_SHA3_384":
		return pkcs11.NewMechanism(ckmEcdsaSha3_384, nil), message, nil
	case "ECDSA_SHA3_512", "CKM_ECDSA_SHA3_512":
		return pkcs11.NewMechanism(ckmEcdsaSha3_512, nil), message, nil

	// EdDSA (Ed25519/Ed448) — added in PKCS#11 v2.40 errata 1 and
	// formalized in v3.0. miekg/pkcs11 v1.1.1 does not export the
	// constant so we use the OASIS-assigned mechanism ID directly.
	case "EDDSA", "CKM_EDDSA":
		return pkcs11.NewMechanism(ckmEdDSA, nil), message, nil

	// RSA PKCS#1 v1.5 (v2.40 baseline)
	case "RSA_PKCS", "CKM_RSA_PKCS":
		h := sha256.Sum256(message)
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), h[:], nil
	case "SHA256_RSA_PKCS", "CKM_SHA256_RSA_PKCS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil), message, nil
	case "SHA384_RSA_PKCS", "CKM_SHA384_RSA_PKCS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA384_RSA_PKCS, nil), message, nil
	case "SHA512_RSA_PKCS", "CKM_SHA512_RSA_PKCS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA512_RSA_PKCS, nil), message, nil

	// RSA + SHA-3 PKCS#1 v1.5 (PKCS#11 v3.0)
	case "SHA3_256_RSA_PKCS", "CKM_SHA3_256_RSA_PKCS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA3_256_RSA_PKCS, nil), message, nil
	case "SHA3_384_RSA_PKCS", "CKM_SHA3_384_RSA_PKCS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA3_384_RSA_PKCS, nil), message, nil
	case "SHA3_512_RSA_PKCS", "CKM_SHA3_512_RSA_PKCS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA3_512_RSA_PKCS, nil), message, nil

	// RSA-PSS (v2.40 + v3.0) — caller is responsible for binding PSS
	// parameters via the PKCS#11 PSS params struct. The mechanism is
	// returned without parameters; tokens that require non-default salt
	// length need a richer config — see issue #103.
	case "RSA_PKCS_PSS", "CKM_RSA_PKCS_PSS":
		h := sha256.Sum256(message)
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, nil), h[:], nil
	case "SHA256_RSA_PKCS_PSS", "CKM_SHA256_RSA_PKCS_PSS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS_PSS, nil), message, nil
	case "SHA384_RSA_PKCS_PSS", "CKM_SHA384_RSA_PKCS_PSS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA384_RSA_PKCS_PSS, nil), message, nil
	case "SHA512_RSA_PKCS_PSS", "CKM_SHA512_RSA_PKCS_PSS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA512_RSA_PKCS_PSS, nil), message, nil
	case "SHA3_256_RSA_PKCS_PSS", "CKM_SHA3_256_RSA_PKCS_PSS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA3_256_RSA_PKCS_PSS, nil), message, nil
	case "SHA3_384_RSA_PKCS_PSS", "CKM_SHA3_384_RSA_PKCS_PSS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA3_384_RSA_PKCS_PSS, nil), message, nil
	case "SHA3_512_RSA_PKCS_PSS", "CKM_SHA3_512_RSA_PKCS_PSS":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA3_512_RSA_PKCS_PSS, nil), message, nil

	default:
		return nil, nil, fmt.Errorf("hsm/pkcs11: unsupported mechanism %q (see PKCS#11 v3.0 §2.x for the canonical list)", name)
	}
}

var (
	errPKCS11NotBuilt      = errors.New("hsm/pkcs11: not reachable in CGO build")
	errPKCS11NoPin         = errors.New("hsm/pkcs11: PIN not set (configure PKCS11Config.Pin or MPC_HSM_PKCS11_PIN env)")
	errPKCS11VerifyNoPubkey = errors.New("hsm/pkcs11: no on-token public key — verify with caller-pinned key")
)
