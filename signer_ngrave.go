// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
)

// NGRAVE Zero is a multi-coin airgapped hardware wallet certified to
// Common Criteria EAL7+ — the highest commercially available smart-card
// certification, used by passport eIDs and military-grade systems.
//
// The Zero exchanges signing requests via animated QR codes on its
// 4-inch capacitive screen using NGRAVE's variant of the Blockchain
// Commons UR (Uniform Resources) format. The wire envelope is the same
// as Keystone (FormatUR) but NGRAVE publishes its own ur-types prefixed
// "ngr-..." for proprietary extensions.
//
// Architecture:
//
//   mpcd ─[NGRAVE UR request]─> AirgapTransport
//                                 │
//                                 │ animated QR (Liquid Air pairing)
//                                 ▼
//                               NGRAVE Zero (offline)
//                                 │
//                                 │ on-device review + fingerprint
//                                 ▼
//                               AirgapTransport ─[NGRAVE UR signed]─> mpcd
//
// In production NGRAVE supports both standard ur-types (eth-sign-request,
// btc-sign-request) for cross-vendor compatibility and ngr-* types for
// features unique to the Zero (e.g., Liquid Air pairing handshakes).
// NGRAVEConfig.URType is required and validated against the request.

// NGRAVEConfig configures an NGRAVE Zero signer.
type NGRAVEConfig struct {
	// DeviceID is the operator-facing identifier of the target device.
	DeviceID string

	// URType identifies the request format. Standard types ("eth-sign-request",
	// "btc-sign-request", "sol-sign-request") and NGRAVE-prefixed types
	// ("ngr-eth-sign-request") are both accepted.
	URType URType

	// Transport mediates the airgapped QR ceremony.
	Transport AirgapTransport
}

// NGRAVESigner produces signatures via an NGRAVE Zero.
type NGRAVESigner struct {
	cfg NGRAVEConfig
}

// NewNGRAVESigner constructs an NGRAVE Zero signer.
func NewNGRAVESigner(cfg NGRAVEConfig) (*NGRAVESigner, error) {
	if cfg.DeviceID == "" {
		return nil, errors.New("hsm/ngrave: DeviceID required")
	}
	if cfg.URType == "" {
		return nil, errors.New("hsm/ngrave: URType required")
	}
	return &NGRAVESigner{cfg: cfg}, nil
}

// Provider returns "ngrave".
func (s *NGRAVESigner) Provider() string { return "ngrave" }

// Sign blocks for the full UR round-trip with the NGRAVE Zero. The
// message MUST be a UR-encoded request matching cfg.URType.
func (s *NGRAVESigner) Sign(ctx context.Context, _ string, message []byte) ([]byte, error) {
	return airgappedSign(
		ctx,
		s.cfg.Transport,
		s.cfg.DeviceID,
		s.encodeChallenge,
		s.decodeResponse,
		message,
	)
}

// Verify is unsupported. NGRAVE signatures verify with the chain's
// native algorithm (secp256k1, ed25519, …) and the chain client.
func (s *NGRAVESigner) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errors.New("hsm/ngrave: Verify not supported (chain-specific)")
}

func (s *NGRAVESigner) encodeChallenge(message []byte, _ string) (AirgapChallenge, error) {
	if err := validateURPrefix(message, s.cfg.URType); err != nil {
		return AirgapChallenge{}, fmt.Errorf("hsm/ngrave: %w", err)
	}
	return AirgapChallenge{
		Format:  FormatUR,
		Payload: message,
	}, nil
}

func (s *NGRAVESigner) decodeResponse(response []byte) ([]byte, error) {
	if !bytes.HasPrefix(response, []byte("ur:")) {
		return nil, fmt.Errorf("hsm/ngrave: %w (response missing 'ur:' prefix)", ErrAirgapResponseInvalid)
	}
	// NGRAVE may return either standard or ngr-prefixed signature types;
	// either is acceptable.
	if !strings.HasPrefix(string(response), "ur:") {
		return nil, ErrAirgapResponseInvalid
	}
	return response, nil
}
