// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"errors"
	"fmt"
)

// Foundation Passport (Batch 2) is a Bitcoin-only airgapped hardware
// wallet that exchanges PSBTs via QR codes only — there is no microSD
// option for signing. Larger PSBTs are split into a sequence of QR
// frames using the Foundation/Coldcard "BBQr" encoding.
//
// Architecture:
//
//   mpcd ─[BBQr-encoded PSBT]─> AirgapTransport
//                                 │
//                                 │ animated QR / camera scan
//                                 ▼
//                               Foundation Passport (offline)
//                                 │
//                                 │ on-device review + PIN
//                                 ▼
//                               AirgapTransport ─[BBQr signed PSBT]─> mpcd
//
// BBQr framing is opaque to this signer: it only carries pre-encoded
// payloads end-to-end. Encoding/decoding is the AirgapTransport's
// responsibility because frame size depends on the rendering surface
// (e.g., 33 vs 100 bytes per frame on different displays).

// FoundationConfig configures a Foundation Passport signer.
type FoundationConfig struct {
	// DeviceID is the operator-facing identifier of the target device.
	DeviceID string

	// Transport mediates the airgapped QR ceremony.
	Transport AirgapTransport
}

// FoundationSigner produces signatures via a Foundation Passport.
type FoundationSigner struct {
	cfg FoundationConfig
}

// NewFoundationSigner constructs a Foundation Passport signer.
func NewFoundationSigner(cfg FoundationConfig) (*FoundationSigner, error) {
	if cfg.DeviceID == "" {
		return nil, errors.New("hsm/foundation: DeviceID required")
	}
	return &FoundationSigner{cfg: cfg}, nil
}

// Provider returns "foundation".
func (s *FoundationSigner) Provider() string { return "foundation" }

// Sign blocks for the full BBQr round-trip and returns the signed PSBT.
// keyID is ignored — derivation is encoded in the PSBT.
func (s *FoundationSigner) Sign(ctx context.Context, _ string, message []byte) ([]byte, error) {
	return airgappedSign(
		ctx,
		s.cfg.Transport,
		s.cfg.DeviceID,
		s.encodeChallenge,
		s.decodeResponse,
		message,
	)
}

// Verify is unsupported (Bitcoin signatures verify on-chain).
func (s *FoundationSigner) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errors.New("hsm/foundation: Verify not supported (verify on-chain)")
}

func (s *FoundationSigner) encodeChallenge(message []byte, _ string) (AirgapChallenge, error) {
	if !looksLikePSBT(message) {
		return AirgapChallenge{}, errors.New("hsm/foundation: message is not a PSBT")
	}
	return AirgapChallenge{
		Format:  FormatBBQr,
		Payload: message,
	}, nil
}

func (s *FoundationSigner) decodeResponse(response []byte) ([]byte, error) {
	if !looksLikePSBT(response) {
		return nil, fmt.Errorf("hsm/foundation: %w", ErrAirgapResponseInvalid)
	}
	return response, nil
}
