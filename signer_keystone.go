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

// Keystone Pro (formerly Cobo Vault) is a multi-coin airgapped hardware
// wallet that exchanges arbitrary CBOR-encoded payloads through animated
// QR codes using the Blockchain Commons "Uniform Resources" (UR) format.
//
// Architecture:
//
//   mpcd ─[UR encoded request]─> AirgapTransport
//                                  │
//                                  │ animated QR scan
//                                  ▼
//                                Keystone Pro (offline)
//                                  │
//                                  │ on-device review + fingerprint + PIN
//                                  ▼
//                                AirgapTransport ─[UR signed response]─> mpcd
//
// Wire format: UR (Blockchain Commons standard, BSD-2). UR payloads
// look like:
//
//   ur:eth-sign-request/oeadtpdacscylufmtoaelfaohdcaim...
//   ur:eth-signature/oeadtpdacscylufmtoaelfaohdcaim...
//
// Keystone publishes a fixed set of "ur-types" per chain — eth-sign-request
// for Ethereum tx and personal_sign, btc-sign-request for Bitcoin PSBT,
// sol-sign-request for Solana, etc. The host MUST encode the message in
// the device-expected UR-type for the configured chain.
//
// Encoding the host-side UR is delegated to KeystoneConfig.URType +
// KeystoneConfig.Encoder so this signer remains free of CBOR
// dependencies. Production callers wire an encoder backed by
// blockchaincommons/bc-ur or an equivalent library.

// URType identifies the UR registry type for a Keystone request. See
// https://github.com/KeystoneHQ/Keystone-developer-hub.
type URType string

const (
	URTypeEthSignRequest URType = "eth-sign-request"
	URTypeBtcSignRequest URType = "btc-sign-request"
	URTypeSolSignRequest URType = "sol-sign-request"
	URTypeCryptoPSBT     URType = "crypto-psbt"
)

// KeystoneConfig configures a Keystone Pro signer.
type KeystoneConfig struct {
	// DeviceID is the operator-facing identifier of the target device.
	DeviceID string

	// URType identifies the request format the device expects. The
	// signer rejects messages that do not match this type.
	URType URType

	// Transport mediates the airgapped QR ceremony.
	Transport AirgapTransport
}

// KeystoneSigner produces signatures via a Keystone Pro.
type KeystoneSigner struct {
	cfg KeystoneConfig
}

// NewKeystoneSigner constructs a Keystone signer.
func NewKeystoneSigner(cfg KeystoneConfig) (*KeystoneSigner, error) {
	if cfg.DeviceID == "" {
		return nil, errors.New("hsm/keystone: DeviceID required")
	}
	if cfg.URType == "" {
		return nil, errors.New("hsm/keystone: URType required (e.g., eth-sign-request, btc-sign-request)")
	}
	return &KeystoneSigner{cfg: cfg}, nil
}

// Provider returns "keystone".
func (s *KeystoneSigner) Provider() string { return "keystone" }

// Sign blocks for the full UR round-trip. message MUST already be
// UR-encoded by the caller (the signer is format-agnostic and refuses
// to silently misinterpret raw bytes). The expected envelope shape is:
//
//   ur:<URType>/<bytewords>
//
// The response is expected to be a matching response UR (e.g.,
// "ur:eth-signature/...") and is returned to the caller verbatim. The
// caller decodes the UR with their UR library and extracts the
// signature bytes.
func (s *KeystoneSigner) Sign(ctx context.Context, _ string, message []byte) ([]byte, error) {
	return airgappedSign(
		ctx,
		s.cfg.Transport,
		s.cfg.DeviceID,
		s.encodeChallenge,
		s.decodeResponse,
		message,
	)
}

// Verify is unsupported. Verification depends on the chain (Ethereum
// signatures verify with secp256k1+keccak, Solana with ed25519, etc.)
// and is performed by the chain client, not the wallet device.
func (s *KeystoneSigner) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errors.New("hsm/keystone: Verify not supported (chain-specific, verify with chain client)")
}

func (s *KeystoneSigner) encodeChallenge(message []byte, _ string) (AirgapChallenge, error) {
	if err := validateURPrefix(message, s.cfg.URType); err != nil {
		return AirgapChallenge{}, err
	}
	return AirgapChallenge{
		Format:  FormatUR,
		Payload: message,
	}, nil
}

func (s *KeystoneSigner) decodeResponse(response []byte) ([]byte, error) {
	if !bytes.HasPrefix(response, []byte("ur:")) {
		return nil, fmt.Errorf("hsm/keystone: %w (response missing 'ur:' prefix)", ErrAirgapResponseInvalid)
	}
	return response, nil
}

// validateURPrefix checks the UR envelope opens with "ur:<type>/".
func validateURPrefix(message []byte, want URType) error {
	prefix := "ur:" + string(want) + "/"
	if !strings.HasPrefix(string(message), prefix) {
		return fmt.Errorf("hsm: message does not have UR prefix %q", prefix)
	}
	return nil
}
