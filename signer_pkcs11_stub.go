// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !pkcs11

package hsm

import (
	"context"
	"errors"
)

// PKCS11Signer is the universal PKCS#11 v2.40 signer. The default build
// (no `pkcs11` build tag) provides only this stub. Building with
// `-tags pkcs11` swaps in the real CGO implementation that links the
// vendor's libCryptoki at runtime.
type PKCS11Signer struct {
	Config PKCS11Config
}

// NewPKCS11Signer constructs a PKCS11Signer. In the stub build all
// methods return errPKCS11NotBuilt so misconfiguration surfaces
// immediately at startup rather than on first signing attempt.
func NewPKCS11Signer(cfg PKCS11Config) (*PKCS11Signer, error) {
	return &PKCS11Signer{Config: cfg}, nil
}

// Provider returns "pkcs11".
func (s *PKCS11Signer) Provider() string { return pkcs11ProviderName }

// Sign returns errPKCS11NotBuilt in the stub build.
func (s *PKCS11Signer) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, errPKCS11NotBuilt
}

// Verify returns errPKCS11NotBuilt in the stub build.
func (s *PKCS11Signer) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errPKCS11NotBuilt
}

// Close is a no-op in the stub build.
func (s *PKCS11Signer) Close() error { return nil }

// errPKCS11NotBuilt is the error returned by every method on the stub
// PKCS11Signer. The error message tells operators exactly which build
// tag they need.
var errPKCS11NotBuilt = errors.New(
	"hsm/pkcs11: binary not built with -tags pkcs11; rebuild mpcd with " +
		"`go build -tags pkcs11 ./cmd/mpcd` to enable Thales/Utimaco/" +
		"Entrust/CloudHSM/SoftHSM2 support",
)

// errPKCS11NoPin is returned when no PIN is configured and
// MPC_HSM_PKCS11_PIN is not set.
var errPKCS11NoPin = errors.New(
	"hsm/pkcs11: PIN not set (configure PKCS11Config.Pin or " +
		"MPC_HSM_PKCS11_PIN env)",
)
