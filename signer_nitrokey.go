// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"fmt"
	"os"
)

// Nitrokey HSM 2 is a USB-attached smart card HSM that exposes a
// PKCS#11 v2.40 interface via the OpenSC project's libopensc-pkcs11.so.
// It supports ECDSA on NIST P-256 and P-521, RSA up to 4096, and PSS.
//
// Architecture:
//
//   mpcd ─ CGO ─> libopensc-pkcs11.so ─ PC/SC ─> pcscd ─ USB ─> Nitrokey HSM 2
//
// The signer is a thin preconfigured wrapper around PKCS11Signer. The
// only Nitrokey-specific value is the OpenSC library path — operators
// supply slot, label, and PIN exactly as for any other PKCS#11 token.
//
// Operator setup (Linux):
//
//   1. apt-get install opensc pcscd
//   2. systemctl enable --now pcscd
//   3. pkcs11-tool --module /usr/lib/opensc-pkcs11.so --list-slots
//   4. pkcs11-tool --module /usr/lib/opensc-pkcs11.so --keypairgen \
//        --key-type EC:secp256r1 --label mpc-cosigner --login
//
// macOS: install OpenSC via `brew install opensc` (library lands at
// /opt/homebrew/lib/pkcs11/opensc-pkcs11.so on Apple Silicon, or
// /usr/local/lib/pkcs11/opensc-pkcs11.so on Intel). PC/SC is provided
// by the system pcscd.

// NitrokeyConfig configures a Nitrokey HSM 2 signer. It is identical
// to PKCS11Config minus the LibraryPath, which defaults to the OpenSC
// system path.
type NitrokeyConfig struct {
	// LibraryPath overrides the OpenSC PKCS#11 module path. When empty
	// the signer probes the standard locations.
	LibraryPath string

	// SlotID and TokenLabel select the Nitrokey among multiple PC/SC
	// readers. TokenLabel is preferred.
	SlotID     uint
	TokenLabel string

	// Pin is the user PIN. The Nitrokey factory default is "648219"
	// but operators MUST change it on first use. In production the PIN
	// is supplied via KMS — never hard-coded.
	Pin string

	// KeyLabel is the CKA_LABEL of the key generated on the device.
	KeyLabel string

	// Mechanism defaults to CKM_ECDSA_SHA256.
	Mechanism string
}

// nitrokeyDefaultLibraryPaths is the ordered probe list used when
// NitrokeyConfig.LibraryPath is empty.
var nitrokeyDefaultLibraryPaths = []string{
	"/usr/lib/opensc-pkcs11.so",
	"/usr/lib64/pkcs11/opensc-pkcs11.so",
	"/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
	"/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
	"/usr/local/lib/pkcs11/opensc-pkcs11.so",
}

// NewNitrokeySigner returns a Signer preconfigured for the Nitrokey
// HSM 2. The returned signer's Provider() reports "nitrokey" for clearer
// audit logs even though the wire protocol is PKCS#11.
func NewNitrokeySigner(cfg NitrokeyConfig) (Signer, error) {
	libPath := cfg.LibraryPath
	if libPath == "" {
		var err error
		libPath, err = probeNitrokeyLibrary()
		if err != nil {
			return nil, err
		}
	}
	mech := cfg.Mechanism
	if mech == "" {
		mech = "ECDSA_SHA256"
	}
	inner, err := NewPKCS11Signer(PKCS11Config{
		LibraryPath: libPath,
		SlotID:      cfg.SlotID,
		TokenLabel:  cfg.TokenLabel,
		Pin:         cfg.Pin,
		KeyLabel:    cfg.KeyLabel,
		Mechanism:   mech,
	})
	if err != nil {
		return nil, fmt.Errorf("hsm/nitrokey: %w", err)
	}
	return &nitrokeySigner{inner: inner}, nil
}

// nitrokeySigner re-labels a PKCS11Signer's Provider() output. All
// other behavior is delegated to the embedded PKCS#11 signer.
type nitrokeySigner struct {
	inner *PKCS11Signer
}

func (s *nitrokeySigner) Provider() string { return "nitrokey" }

func (s *nitrokeySigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	return s.inner.Sign(ctx, keyID, message)
}

func (s *nitrokeySigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	return s.inner.Verify(ctx, keyID, message, signature)
}

// Close releases the embedded PKCS#11 session.
func (s *nitrokeySigner) Close() error { return s.inner.Close() }

// probeNitrokeyLibrary returns the first existing OpenSC PKCS#11 module
// found in nitrokeyDefaultLibraryPaths.
func probeNitrokeyLibrary() (string, error) {
	for _, p := range nitrokeyDefaultLibraryPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("hsm/nitrokey: OpenSC PKCS#11 module not found in any of %v; install opensc and re-try (or set NitrokeyConfig.LibraryPath)", nitrokeyDefaultLibraryPaths)
}
