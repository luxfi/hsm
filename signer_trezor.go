// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Trezor (One / Model T / Safe 3 / Safe 5) is a USB-connected hardware
// wallet. The device speaks Protocol Buffers over USB HID via the
// Trezor Bridge daemon (`trezord`), which exposes a localhost HTTP
// endpoint on port 21325.
//
// As with the Ledger signer, embedding the full Trezor protocol stack
// in luxfi/hsm would pull a large native dependency tree
// (libhidapi + protobuf compiled trezor-common messages). We therefore
// shell out to the Trezor CLI (`trezorctl`) which the Trezor team
// maintains and ships with `pip install trezor`.
//
// Architecture:
//
//   mpcd ─ stdin/stdout ─> trezorctl ─ HTTP ─> trezord ─ HID ─> Trezor
//
// Operator setup:
//
//   1. pip install trezor                # installs trezorctl + trezord
//   2. systemctl enable --now trezord    # or `trezord-go` packaged binary
//   3. mpcd --hsm-signer=trezor \
//          --hsm-trezor-coin=Ethereum \
//          --hsm-trezor-path="m/44'/60'/0'/0/0"
//
// The signer dispatches to the matching trezorctl sub-command per coin
// (`trezorctl ethereum sign-tx`, `trezorctl btc sign-tx`, …). The host
// passes the unsigned transaction in hex on stdin; trezorctl prints
// the signature in hex on stdout after the operator confirms on the
// device.

// TrezorConfig configures a Trezor signer.
type TrezorConfig struct {
	// ToolPath is the path to trezorctl. Empty defaults to "trezorctl"
	// on PATH.
	ToolPath string

	// Coin selects the trezorctl sub-command. Examples: "ethereum",
	// "btc", "solana", "cardano". Required.
	Coin string

	// SignAction overrides the verb after Coin. Defaults to "sign-tx".
	SignAction string

	// DerivationPath is the BIP-32 path of the key to sign with.
	// Required. Format "m/44'/60'/0'/0/0".
	DerivationPath string
}

// TrezorSigner produces signatures via a Trezor device using trezorctl.
type TrezorSigner struct {
	cfg TrezorConfig
}

// NewTrezorSigner validates configuration and returns a signer.
func NewTrezorSigner(cfg TrezorConfig) (*TrezorSigner, error) {
	if cfg.Coin == "" {
		return nil, errors.New("hsm/trezor: Coin required (e.g., ethereum, btc, solana)")
	}
	if cfg.DerivationPath == "" {
		return nil, errors.New("hsm/trezor: DerivationPath required (e.g., m/44'/60'/0'/0/0)")
	}
	if cfg.SignAction == "" {
		cfg.SignAction = "sign-tx"
	}
	return &TrezorSigner{cfg: cfg}, nil
}

// Provider returns "trezor".
func (s *TrezorSigner) Provider() string { return "trezor" }

// Sign invokes "trezorctl <coin> <sign-action>" with the message on
// stdin (hex) and returns the device signature parsed from stdout.
func (s *TrezorSigner) Sign(ctx context.Context, _ string, message []byte) ([]byte, error) {
	tool := s.cfg.ToolPath
	if tool == "" {
		tool = "trezorctl"
	}
	if _, err := exec.LookPath(tool); err != nil {
		return nil, fmt.Errorf("hsm/trezor: %s not found on PATH: %w", tool, err)
	}
	args := []string{
		s.cfg.Coin,
		s.cfg.SignAction,
		"--path", s.cfg.DerivationPath,
	}
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Stdin = strings.NewReader(hex.EncodeToString(message))
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("hsm/trezor: %s %s failed: %w", s.cfg.Coin, s.cfg.SignAction, err)
	}
	sigHex := strings.TrimSpace(out.String())
	if sigHex == "" {
		return nil, errors.New("hsm/trezor: empty signature returned")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("hsm/trezor: decode signature: %w", err)
	}
	return sig, nil
}

// Verify is unsupported. Trezor exposes no verify primitive — verify
// against a pinned pubkey or on-chain.
func (s *TrezorSigner) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errors.New("hsm/trezor: Verify not supported (verify with chain client or pinned pubkey)")
}
