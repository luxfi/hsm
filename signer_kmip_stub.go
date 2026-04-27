// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !kmip

package hsm

import (
	"context"
	"errors"
)

// KMIPSigner is the universal KMIP 2.1 signer. The default build (no
// `kmip` build tag) provides only this stub. Building with `-tags kmip`
// swaps in the real implementation backed by github.com/gemalto/kmip-go.
type KMIPSigner struct {
	Config KMIPConfig
}

// NewKMIPSigner constructs a KMIPSigner. The stub returns it without
// contacting the server; Sign/Verify return errKMIPNotBuilt.
func NewKMIPSigner(cfg KMIPConfig) (*KMIPSigner, error) {
	return &KMIPSigner{Config: cfg}, nil
}

// Provider returns "kmip".
func (s *KMIPSigner) Provider() string { return kmipProviderName }

// Sign returns errKMIPNotBuilt in the stub build.
func (s *KMIPSigner) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, errKMIPNotBuilt
}

// Verify returns errKMIPNotBuilt in the stub build.
func (s *KMIPSigner) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errKMIPNotBuilt
}

// Activate, Revoke, Destroy return errKMIPNotBuilt in the stub build.
func (s *KMIPSigner) Activate(_ context.Context, _ string) error { return errKMIPNotBuilt }
func (s *KMIPSigner) Revoke(_ context.Context, _ string) error   { return errKMIPNotBuilt }
func (s *KMIPSigner) Destroy(_ context.Context, _ string) error  { return errKMIPNotBuilt }

// Close is a no-op in the stub build.
func (s *KMIPSigner) Close() error { return nil }

// errKMIPNotBuilt is returned by every method on the stub KMIPSigner.
var errKMIPNotBuilt = errors.New(
	"hsm/kmip: binary not built with -tags kmip; rebuild mpcd with " +
		"`go build -tags kmip ./cmd/mpcd` to enable Thales CipherTrust / " +
		"Utimaco / Entrust KeyControl / Fortanix DSM / Vault Enterprise " +
		"KMIP 2.1 management",
)
