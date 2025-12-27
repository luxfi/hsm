// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/crypto/threshold"
)

// Errors for threshold HSM operations.
var (
	ErrThresholdNotSupported = errors.New("hsm: threshold operations not supported by this provider")
	ErrKeyShareNotFound      = errors.New("hsm: key share not found in vault")
	ErrDecryptionFailed      = errors.New("hsm: key share decryption failed")
	ErrAttestedDataTooShort  = errors.New("hsm: attested share data too short")
	ErrShareNotAttested      = errors.New("hsm: share is not attested")
)

// ThresholdHSM extends the base Signer interface for HSMs that natively
// support threshold signing protocols. Cloud KMS providers (AWS, GCP, Azure)
// do not implement this — it targets dedicated hardware (Zymbit SCM,
// custom FPGA-based HSMs) that can execute DKG and signing rounds
// internally without ever exposing key shares.
type ThresholdHSM interface {
	Signer

	// NonceGen generates signing nonces inside the HSM hardware.
	// The nonce secret never leaves the HSM boundary.
	// Returns a commitment to broadcast and an opaque reference for SignThresholdShare.
	NonceGen(ctx context.Context, keyID, sessionID string) (commitment []byte, nonceRef string, err error)

	// SignThresholdShare produces a threshold signature share inside the HSM.
	// The nonce referenced by nonceRef is consumed (single-use).
	SignThresholdShare(ctx context.Context, keyID, sessionID, nonceRef string, message []byte, signerIndices []int) ([]byte, error)

	// ImportKeyShare imports a threshold key share into HSM-protected storage.
	ImportKeyShare(ctx context.Context, keyID string, share []byte) error

	// ExportPublicShare returns the public portion of a stored key share.
	// The private portion never leaves the HSM.
	ExportPublicShare(ctx context.Context, keyID string) ([]byte, error)
}

// ---------------------------------------------------------------------------
// Encrypted Key Share Vault
// ---------------------------------------------------------------------------

// KeyShareMeta holds public metadata about a stored key share.
// None of these fields are secret — they enable indexing and routing
// without decrypting the share itself.
type KeyShareMeta struct {
	SchemeID     threshold.SchemeID
	Index        int
	Threshold    int
	TotalParties int
	PublicShare  []byte
	GroupKey     []byte // serialized group public key
}

// KeyShareVault provides AES-256-GCM encrypted storage for threshold key shares.
// The encryption key is derived from the HSM password provider — key share
// material is never stored in plaintext and is held decrypted only for
// the duration of a single operation.
//
// Usage:
//
//	vault := hsm.NewKeyShareVault(passwordProvider, "kms-key-id")
//	vault.Store(ctx, "validator-0", share.Bytes(), meta)
//	raw, meta, _ := vault.Load(ctx, "validator-0")
//	keyShare, _ := scheme.ParseKeyShare(raw)
type KeyShareVault struct {
	mu       sync.RWMutex
	password PasswordProvider
	passKey  string
	entries  map[string]*vaultEntry
}

type vaultEntry struct {
	ciphertext []byte
	nonce      []byte
	meta       KeyShareMeta
}

// NewKeyShareVault creates a vault backed by the given password provider.
// The passKeyID is passed to PasswordProvider.GetPassword to derive the
// encryption key.
func NewKeyShareVault(pw PasswordProvider, passKeyID string) *KeyShareVault {
	return &KeyShareVault{
		password: pw,
		passKey:  passKeyID,
		entries:  make(map[string]*vaultEntry),
	}
}

func (v *KeyShareVault) deriveKey(ctx context.Context) ([]byte, error) {
	pw, err := v.password.GetPassword(ctx, v.passKey)
	if err != nil {
		return nil, fmt.Errorf("hsm: vault key derivation failed: %w", err)
	}
	key := sha256.Sum256([]byte(pw))
	return key[:], nil
}

// Store encrypts and stores key share bytes with metadata.
func (v *KeyShareVault) Store(ctx context.Context, id string, data []byte, meta KeyShareMeta) error {
	key, err := v.deriveKey(ctx)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("hsm: cipher init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("hsm: GCM init failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("hsm: nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	v.mu.Lock()
	defer v.mu.Unlock()
	v.entries[id] = &vaultEntry{
		ciphertext: ciphertext,
		nonce:      nonce,
		meta:       meta,
	}
	return nil
}

// Load decrypts and returns stored key share bytes with metadata.
func (v *KeyShareVault) Load(ctx context.Context, id string) ([]byte, *KeyShareMeta, error) {
	v.mu.RLock()
	entry, ok := v.entries[id]
	v.mu.RUnlock()
	if !ok {
		return nil, nil, ErrKeyShareNotFound
	}

	key, err := v.deriveKey(ctx)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("hsm: cipher init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("hsm: GCM init failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, entry.nonce, entry.ciphertext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	meta := entry.meta
	return plaintext, &meta, nil
}

// Delete removes a key share from the vault.
func (v *KeyShareVault) Delete(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.entries, id)
}

// List returns all stored key share IDs.
func (v *KeyShareVault) List() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	ids := make([]string, 0, len(v.entries))
	for id := range v.entries {
		ids = append(ids, id)
	}
	return ids
}

// GetMeta returns metadata for a stored key share without decrypting it.
func (v *KeyShareVault) GetMeta(id string) (*KeyShareMeta, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	entry, ok := v.entries[id]
	if !ok {
		return nil, ErrKeyShareNotFound
	}
	meta := entry.meta
	return &meta, nil
}

// ---------------------------------------------------------------------------
// HSM-Attesting Threshold Signer
// ---------------------------------------------------------------------------

// HSMAttestingSigner wraps a threshold.Signer with HSM attestation.
// Every signature share produced is co-signed by the node's HSM key,
// binding the share to specific hardware. This provides defense-in-depth:
// even if an attacker obtains threshold key shares, they cannot produce
// valid attested shares without access to the HSM.
//
// Works with any threshold scheme (BLS, FROST, CGGMP21, Ringtail).
//
// Usage:
//
//	inner, _ := scheme.NewSigner(keyShare)
//	signer := hsm.NewAttestingSigner(inner, hsmSigner, "attestation-key")
//	share, _ := signer.SignShare(ctx, message, signers, nonce)
//	ok, _ := hsm.VerifyAttestation(ctx, hsmSigner, "attestation-key", share)
type HSMAttestingSigner struct {
	inner threshold.Signer
	hsm   Signer
	keyID string
}

// NewAttestingSigner wraps a threshold signer with HSM attestation.
func NewAttestingSigner(inner threshold.Signer, hsm Signer, keyID string) *HSMAttestingSigner {
	return &HSMAttestingSigner{
		inner: inner,
		hsm:   hsm,
		keyID: keyID,
	}
}

func (s *HSMAttestingSigner) Index() int                   { return s.inner.Index() }
func (s *HSMAttestingSigner) PublicShare() []byte           { return s.inner.PublicShare() }
func (s *HSMAttestingSigner) KeyShare() threshold.KeyShare  { return s.inner.KeyShare() }

// NonceGen delegates to the inner signer.
// For schemes requiring nonce generation (FROST, CGGMP21), the nonces are
// produced by the threshold implementation. For non-interactive schemes (BLS),
// this returns nil.
func (s *HSMAttestingSigner) NonceGen(ctx context.Context) (threshold.NonceCommitment, threshold.NonceState, error) {
	return s.inner.NonceGen(ctx)
}

// SignShare creates a threshold signature share and attests it with the HSM.
func (s *HSMAttestingSigner) SignShare(ctx context.Context, message []byte, signers []int, nonce threshold.NonceState) (threshold.SignatureShare, error) {
	share, err := s.inner.SignShare(ctx, message, signers, nonce)
	if err != nil {
		return nil, err
	}

	attestation, err := s.hsm.Sign(ctx, s.keyID, share.Bytes())
	if err != nil {
		return nil, fmt.Errorf("hsm: attestation signing failed: %w", err)
	}

	return &attestedSignatureShare{
		inner:       share,
		attestation: attestation,
	}, nil
}

// attestedSignatureShare implements threshold.SignatureShare with HSM attestation.
// Bytes() returns protocol-compatible inner share bytes so that existing
// aggregators work without modification.
type attestedSignatureShare struct {
	inner       threshold.SignatureShare
	attestation []byte
}

func (s *attestedSignatureShare) Index() int                   { return s.inner.Index() }
func (s *attestedSignatureShare) SchemeID() threshold.SchemeID { return s.inner.SchemeID() }
func (s *attestedSignatureShare) Bytes() []byte                { return s.inner.Bytes() }

// Attestation returns the HSM co-signature over the inner share bytes.
func (s *attestedSignatureShare) Attestation() []byte { return s.attestation }

// InnerShare returns the underlying threshold signature share.
func (s *attestedSignatureShare) InnerShare() threshold.SignatureShare { return s.inner }

// MarshalAttested serializes the share with its attestation for transmission.
// Format: [4-byte share length (big-endian)][share bytes][attestation bytes]
func (s *attestedSignatureShare) MarshalAttested() []byte {
	shareBytes := s.inner.Bytes()
	buf := make([]byte, 4+len(shareBytes)+len(s.attestation))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(shareBytes)))
	copy(buf[4:], shareBytes)
	copy(buf[4+len(shareBytes):], s.attestation)
	return buf
}

// ParseAttestedShare deserializes an attested signature share.
// The scheme is used to parse the inner share bytes.
func ParseAttestedShare(data []byte, scheme threshold.Scheme) (*attestedSignatureShare, error) {
	if len(data) < 5 {
		return nil, ErrAttestedDataTooShort
	}
	shareLen := binary.BigEndian.Uint32(data[:4])
	if uint32(len(data)) < 4+shareLen {
		return nil, ErrAttestedDataTooShort
	}

	shareBytes := data[4 : 4+shareLen]
	attestation := data[4+shareLen:]

	share, err := scheme.ParseSignatureShare(shareBytes)
	if err != nil {
		return nil, fmt.Errorf("hsm: parse inner share: %w", err)
	}

	return &attestedSignatureShare{
		inner:       share,
		attestation: attestation,
	}, nil
}

// VerifyAttestation checks the HSM attestation on a signature share.
// Returns false if the share is not attested or the attestation is invalid.
func VerifyAttestation(ctx context.Context, hsm Signer, keyID string, share threshold.SignatureShare) (bool, error) {
	attested, ok := share.(*attestedSignatureShare)
	if !ok {
		return false, ErrShareNotAttested
	}
	return hsm.Verify(ctx, keyID, attested.inner.Bytes(), attested.attestation)
}

// ---------------------------------------------------------------------------
// Threshold Manager
// ---------------------------------------------------------------------------

// ThresholdConfig configures the HSM-backed threshold signing manager.
type ThresholdConfig struct {
	// Password provider for vault encryption.
	PasswordProvider string
	PasswordKeyID    string
	PasswordConfig   map[string]string

	// Signer provider for attestation.
	SignerProvider string
	SignerConfig   map[string]string
	AttestKeyID   string
}

// ThresholdManager integrates HSM with threshold signing protocols.
// It combines encrypted key share storage (KeyShareVault) with HSM
// attestation (HSMAttestingSigner) for a complete HSM-backed
// threshold signing solution.
//
// Supported schemes: BLS, FROST, CGGMP21, Ringtail — any scheme
// registered with the threshold.RegisterScheme registry.
//
// Usage:
//
//	mgr, _ := hsm.NewThresholdManager(hsm.ThresholdConfig{
//	    PasswordProvider: "aws",
//	    PasswordKeyID:    "arn:aws:kms:...",
//	    SignerProvider:   "local",
//	    AttestKeyID:      "node-attest",
//	})
//	mgr.StoreKeyShare(ctx, "validator-0", share)
//	signer, _ := mgr.NewSigner(ctx, "validator-0")
//	attShare, _ := signer.SignShare(ctx, msg, signers, nil)
type ThresholdManager struct {
	vault *KeyShareVault
	hsm   Signer
	keyID string
}

// NewThresholdManager creates an HSM-backed threshold manager.
func NewThresholdManager(cfg ThresholdConfig) (*ThresholdManager, error) {
	pw, err := NewPasswordProvider(cfg.PasswordProvider, cfg.PasswordConfig)
	if err != nil {
		return nil, fmt.Errorf("hsm: threshold manager password provider: %w", err)
	}

	signer, err := NewSigner(cfg.SignerProvider, cfg.SignerConfig)
	if err != nil {
		return nil, fmt.Errorf("hsm: threshold manager signer: %w", err)
	}

	return &ThresholdManager{
		vault: NewKeyShareVault(pw, cfg.PasswordKeyID),
		hsm:   signer,
		keyID: cfg.AttestKeyID,
	}, nil
}

// StoreKeyShare encrypts and stores a threshold key share.
func (m *ThresholdManager) StoreKeyShare(ctx context.Context, id string, share threshold.KeyShare) error {
	meta := KeyShareMeta{
		SchemeID:     share.SchemeID(),
		Index:        share.Index(),
		Threshold:    share.Threshold(),
		TotalParties: share.TotalParties(),
		PublicShare:  share.PublicShare(),
		GroupKey:     share.GroupKey().Bytes(),
	}
	return m.vault.Store(ctx, id, share.Bytes(), meta)
}

// LoadKeyShare decrypts and reconstructs a stored threshold key share.
// The key share's scheme must be registered with threshold.RegisterScheme.
func (m *ThresholdManager) LoadKeyShare(ctx context.Context, id string) (threshold.KeyShare, error) {
	data, meta, err := m.vault.Load(ctx, id)
	if err != nil {
		return nil, err
	}

	scheme, err := threshold.GetScheme(meta.SchemeID)
	if err != nil {
		return nil, err
	}

	return scheme.ParseKeyShare(data)
}

// NewSigner creates an HSM-attesting threshold signer from a stored key share.
// The returned signer produces signature shares co-signed by the HSM.
func (m *ThresholdManager) NewSigner(ctx context.Context, id string) (threshold.Signer, error) {
	share, err := m.LoadKeyShare(ctx, id)
	if err != nil {
		return nil, err
	}

	scheme, err := threshold.GetScheme(share.SchemeID())
	if err != nil {
		return nil, err
	}

	inner, err := scheme.NewSigner(share)
	if err != nil {
		return nil, err
	}

	return NewAttestingSigner(inner, m.hsm, m.keyID), nil
}

// Vault returns the underlying encrypted key share storage.
func (m *ThresholdManager) Vault() *KeyShareVault { return m.vault }

// HSMSigner returns the underlying HSM signer used for attestation.
func (m *ThresholdManager) HSMSigner() Signer { return m.hsm }
