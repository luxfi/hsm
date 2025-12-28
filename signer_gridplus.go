// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GridPlus Lattice1 is a *network* hardware wallet — unlike the
// airgapped devices in this package, it ships with a built-in WiFi /
// Ethernet stack and exposes an HTTPS endpoint on the local network.
// The host pairs with the device once (six-digit code shown on the
// Lattice's screen), exchanges an AES-GCM session key derived from a
// JOSE-like ECDH handshake, then sends signed JSON requests to the
// `/secret_signer/connect` endpoint.
//
// Architecture:
//
//   mpcd ─ HTTPS / AES-GCM ─> Lattice1 (LAN) ─ Secure Element ─> sign
//
// Wire protocol (GridPlus "Connect API", documented at
// https://docs.gridplus.io/lattice/connect-api):
//
//   1. Pair    : POST /pair       { name, ephemeralPubKey } → { sharedSecret }
//                Operator confirms 6-digit code on device.
//   2. Encrypt : derive AES-GCM key = sha256(sharedSecret || nonce)
//   3. Connect : POST /secret_signer/connect (encrypted envelope)
//   4. Sign    : POST /secret_signer/sign (encrypted SignRequest)
//   5. Decrypt : AES-GCM open → DER-encoded ECDSA signature
//
// THIS SIGNER IS A DOCUMENTED STUB.
// ----------------------------------------------------------------------
// The full Connect API requires a substantial port of the GridPlus
// reference SDK (gridplus-sdk, MIT, ~3000 lines of TypeScript). Shipping
// a partial implementation here would be misleading — every Sign call
// would fail in production with a confusing error. This file therefore
// returns an explicit ErrLatticeNotImpl from Sign and Verify, validates
// configuration eagerly so misconfiguration surfaces at startup, and
// documents the exact protocol so a follow-up port can be reviewed
// against the spec rather than reverse-engineered.
//
// The factory still routes "gridplus" to this signer — operators see a
// clear error and a clean surface for the eventual real implementation.

// LatticeConfig configures a GridPlus Lattice1 signer.
type LatticeConfig struct {
	// BaseURL is the HTTPS endpoint of the Lattice on the LAN, e.g.
	// "https://192.168.1.42". The TLS cert is self-signed by the device;
	// callers must pin or trust the cert out-of-band.
	BaseURL string

	// DeviceID is the alphanumeric ID printed on the device or shown in
	// settings.
	DeviceID string

	// AppName is the operator-visible name for this host. Shown on the
	// Lattice's screen during pairing.
	AppName string

	// PairingSecret is the 32-byte secret established during pairing.
	// Hex-encoded. Empty for first-pair flows; populated thereafter.
	PairingSecret string

	// HTTPClient overrides the default HTTPS client. Used by tests.
	HTTPClient *http.Client
}

// LatticeSigner produces signatures via a GridPlus Lattice1.
type LatticeSigner struct {
	cfg LatticeConfig
}

// NewLatticeSigner validates the configuration and returns a signer.
// The signer does NOT contact the device at construction — Sign and
// Verify drive the network round-trip. Configuration errors surface
// here so misconfigured deployments fail fast.
func NewLatticeSigner(cfg LatticeConfig) (*LatticeSigner, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("hsm/lattice: BaseURL required (e.g., https://lattice.local)")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("hsm/lattice: invalid BaseURL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("hsm/lattice: BaseURL must use HTTPS")
	}
	if cfg.DeviceID == "" {
		return nil, errors.New("hsm/lattice: DeviceID required")
	}
	if cfg.AppName == "" {
		cfg.AppName = "lux-mpc"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &LatticeSigner{cfg: cfg}, nil
}

// Provider returns "gridplus".
func (s *LatticeSigner) Provider() string { return "gridplus" }

// Sign returns ErrLatticeNotImpl. See the package doc on the Connect
// API protocol that needs to be implemented.
func (s *LatticeSigner) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, errLatticeNotImpl
}

// Verify returns ErrLatticeNotImpl.
func (s *LatticeSigner) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errLatticeNotImpl
}

// errLatticeNotImpl is returned by every Sign/Verify call until the
// Connect-API protocol is ported. The error explicitly tells operators
// to use a different signer rather than failing silently.
var errLatticeNotImpl = errors.New(strings.TrimSpace(`
hsm/lattice: GridPlus Lattice1 Connect-API not implemented in this
build. The protocol requires AES-GCM session establishment + JOSE-like
envelopes; see signer_gridplus.go for the full specification. Use
--hsm-signer=yubihsm or --hsm-signer=pkcs11 for hardware-rooted signing
in production.
`))
