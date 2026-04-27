// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"errors"
	"fmt"
)

// Coldcard (Mk4 / Q1) is a Bitcoin-only airgapped hardware wallet from
// Coinkite that ships every key on a secure element and never connects
// to a network. The signing ceremony exchanges BIP-174 PSBTs with the
// host either via microSD card or via the Q1's built-in QR scanner.
//
// Architecture:
//
//   mpcd ─[PSBT bytes]─> AirgapTransport
//                         │
//                         │ operator carries microSD or shows QR
//                         ▼
//                       Coldcard (offline)
//                         │
//                         │ on-device review + PIN + tap-to-sign
//                         ▼
//                       AirgapTransport ─[signed PSBT]─> mpcd
//
// The operator is responsible for the physical transfer. This signer
// only generates the challenge envelope and parses the response — all
// human-mediated steps are encapsulated by AirgapTransport.
//
// Wire format: BIP-174 PSBT (Partially Signed Bitcoin Transaction) v0
// or v2. The Coldcard accepts both. Larger PSBTs that exceed the QR
// budget should use ColdcardConfig.Format = FormatBBQr.

// ColdcardConfig configures a Coldcard signer. The hardware wallet
// itself is stateless from the host's perspective — only the device ID
// (used by the transport to route concurrent ceremonies) and PSBT
// format need to be selected here.
type ColdcardConfig struct {
	// DeviceID is the operator-facing identifier of the target device.
	// Multiple Coldcards behind a single transport disambiguate by ID.
	DeviceID string

	// Format selects the wire encoding. FormatPSBT is the canonical
	// microSD/USB envelope. FormatBBQr is for QR-only ceremonies on the
	// Coldcard Q1 where a single PSBT exceeds one QR's capacity.
	Format AirgapFormat

	// Transport mediates the offline ceremony. Must be non-nil at sign
	// time; signers may be constructed without it for static config.
	Transport AirgapTransport
}

// ColdcardSigner produces signatures via a Coldcard hardware wallet.
type ColdcardSigner struct {
	cfg ColdcardConfig
}

// NewColdcardSigner constructs a Coldcard signer. It does NOT contact
// the device — the device is offline by construction and only sees a
// challenge during a Sign ceremony.
func NewColdcardSigner(cfg ColdcardConfig) (*ColdcardSigner, error) {
	if cfg.DeviceID == "" {
		return nil, errors.New("hsm/coldcard: DeviceID required")
	}
	if cfg.Format == "" {
		cfg.Format = FormatPSBT
	}
	if cfg.Format != FormatPSBT && cfg.Format != FormatBBQr {
		return nil, fmt.Errorf("hsm/coldcard: unsupported format %q (want psbt or bbqr)", cfg.Format)
	}
	return &ColdcardSigner{cfg: cfg}, nil
}

// Provider returns "coldcard".
func (s *ColdcardSigner) Provider() string { return "coldcard" }

// Sign blocks for the full airgapped ceremony and returns the signed
// PSBT bytes. The caller is responsible for extracting witness data and
// finalizing the transaction (e.g., via btcd/btcutil/psbt.Finalize).
//
// keyID is ignored — Coldcard-side key derivation is encoded in the
// PSBT's BIP-32 input/output paths. The interface signature is
// preserved for symmetry with cloud HSMs.
func (s *ColdcardSigner) Sign(ctx context.Context, _ string, message []byte) ([]byte, error) {
	return airgappedSign(
		ctx,
		s.cfg.Transport,
		s.cfg.DeviceID,
		s.encodeChallenge,
		s.decodeResponse,
		message,
	)
}

// Verify is unsupported on Coldcard. Bitcoin signatures embedded in a
// PSBT are verified by the chain itself — there is no offline verify
// primitive on the device. Callers MUST verify by extracting and
// broadcasting the finalized transaction (or by parsing witness data
// with a Bitcoin library and checking it against the SIGHASH).
func (s *ColdcardSigner) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errors.New("hsm/coldcard: Verify not supported (verify on-chain or via Bitcoin lib)")
}

// encodeChallenge wraps the unsigned PSBT in an AirgapChallenge using
// the configured format. Coldcard expects the raw PSBT bytes — there is
// no host-side framing.
func (s *ColdcardSigner) encodeChallenge(message []byte, _ string) (AirgapChallenge, error) {
	if !looksLikePSBT(message) {
		return AirgapChallenge{}, errors.New("hsm/coldcard: message does not look like a PSBT (missing magic 'psbt\\xff')")
	}
	return AirgapChallenge{
		Format:  s.cfg.Format,
		Payload: message,
	}, nil
}

// decodeResponse expects the device to return the signed PSBT bytes
// verbatim. The signer does not finalize — callers do that with their
// preferred Bitcoin library.
func (s *ColdcardSigner) decodeResponse(response []byte) ([]byte, error) {
	if !looksLikePSBT(response) {
		return nil, fmt.Errorf("hsm/coldcard: %w (response missing PSBT magic)", ErrAirgapResponseInvalid)
	}
	return response, nil
}

// looksLikePSBT returns true when b begins with the BIP-174 magic
// bytes "psbt\xff". This is a cheap sanity check, not a full parser.
func looksLikePSBT(b []byte) bool {
	const magic = "psbt\xff"
	if len(b) < len(magic) {
		return false
	}
	for i := 0; i < len(magic); i++ {
		if b[i] != magic[i] {
			return false
		}
	}
	return true
}
