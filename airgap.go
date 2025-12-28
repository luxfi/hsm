// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"errors"
	"fmt"
)

// Airgapped hardware wallets (Coldcard, Foundation Passport, Keystone Pro,
// NGRAVE Zero) never connect to a network. The signing ceremony involves a
// human operator transferring a challenge (file via microSD, or QR code)
// from the host to the device, performing on-device review and approval,
// and transferring the signed response back.
//
// The Signer interface call BLOCKS for the full duration of the ceremony.
// Callers must supply an AirgapTransport that is responsible for:
//
//   1. Presenting the challenge to the operator (DisplayChallenge)
//   2. Awaiting the signed response (AwaitResponse)
//
// In production the transport is wired to a UI surface (web, CLI prompt,
// kiosk display). In tests a deterministic mock transport is used.

// AirgapFormat describes the wire format used to ferry challenges and
// responses between host and device.
type AirgapFormat string

const (
	// FormatPSBT is BIP-174 Partially Signed Bitcoin Transaction. Used by
	// Coldcard and Foundation Passport for Bitcoin transactions.
	FormatPSBT AirgapFormat = "psbt"

	// FormatBBQr is the Foundation/Coldcard QR-segmentation format for
	// PSBTs that exceed a single QR code's capacity.
	FormatBBQr AirgapFormat = "bbqr"

	// FormatUR is the Blockchain Commons "Uniform Resources" format used
	// by Keystone Pro, NGRAVE Zero, and related devices for animated QR
	// transmission of arbitrary CBOR-encoded payloads.
	FormatUR AirgapFormat = "ur"

	// FormatRawJSON is a fallback used when no chain-specific format
	// applies (test transports, generic challenge envelopes).
	FormatRawJSON AirgapFormat = "json"
)

// AirgapChallenge is the payload presented to the operator during a
// signing ceremony. Either a QR PNG or a raw byte payload is provided —
// transports may render either or both depending on UI capabilities.
type AirgapChallenge struct {
	// Format identifies the wire encoding of Payload.
	Format AirgapFormat

	// Payload is the challenge bytes (e.g., PSBT, UR-encoded CBOR).
	Payload []byte

	// QRCodePNG is an optional pre-rendered QR code. Empty for file-only
	// transports (microSD).
	QRCodePNG []byte

	// DeviceID is the operator-facing identifier of the target device,
	// matching the AirgapDeviceID configured on the signer. Used by the
	// transport to route concurrent ceremonies to the right operator.
	DeviceID string

	// SessionID is a single-use random identifier used to bind responses
	// to their challenge. Transports MUST verify the session ID echoed in
	// the response.
	SessionID string
}

// AirgapTransport is supplied by callers to mediate the offline ceremony.
// All implementations must be safe for concurrent calls keyed on
// challenge.SessionID.
type AirgapTransport interface {
	// DisplayChallenge shows the challenge to the operator and returns
	// once the operator has acknowledged it. It MUST NOT block waiting
	// for the response — use AwaitResponse for that.
	DisplayChallenge(ctx context.Context, challenge AirgapChallenge) error

	// AwaitResponse blocks until the operator returns the device's
	// signed payload (or the context is cancelled). The returned bytes
	// are in the same format as the challenge.
	AwaitResponse(ctx context.Context, sessionID string) ([]byte, error)
}

// ErrAirgapTransportRequired is returned when an airgapped signer is
// invoked without a configured transport.
var ErrAirgapTransportRequired = errors.New("hsm/airgap: AirgapTransport not configured")

// ErrAirgapResponseInvalid signals a malformed or unverifiable response
// from the device. The response is rejected and the caller MUST NOT
// retry without operator intervention.
var ErrAirgapResponseInvalid = errors.New("hsm/airgap: response failed verification")

// MockAirgapTransport is a deterministic in-memory transport used by
// tests and development. It records the latest challenge and replies
// with whatever bytes were preloaded via PreloadResponse.
type MockAirgapTransport struct {
	LastChallenge AirgapChallenge
	Response      []byte
	ResponseErr   error
}

// DisplayChallenge captures the challenge for inspection in tests.
func (m *MockAirgapTransport) DisplayChallenge(_ context.Context, c AirgapChallenge) error {
	m.LastChallenge = c
	return nil
}

// AwaitResponse returns the preloaded response (or the preloaded error).
func (m *MockAirgapTransport) AwaitResponse(_ context.Context, sessionID string) ([]byte, error) {
	if m.ResponseErr != nil {
		return nil, m.ResponseErr
	}
	if m.Response == nil {
		return nil, fmt.Errorf("hsm/airgap-mock: no response preloaded for session %s", sessionID)
	}
	return m.Response, nil
}

// newSessionID returns a 16-byte random hex session identifier. It is
// computed via crypto/rand so collisions across concurrent ceremonies
// are negligible.
func newSessionID() (string, error) {
	const size = 16
	buf := make([]byte, size)
	if _, err := readRandom(buf); err != nil {
		return "", fmt.Errorf("hsm/airgap: random read: %w", err)
	}
	out := make([]byte, size*2)
	const hexchars = "0123456789abcdef"
	for i, b := range buf {
		out[i*2] = hexchars[b>>4]
		out[i*2+1] = hexchars[b&0x0f]
	}
	return string(out), nil
}
