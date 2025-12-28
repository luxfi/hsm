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

// Ledger Nano (S Plus / X / Stax) is a USB-connected hardware wallet.
// Unlike the Coldcard / Foundation / Keystone / NGRAVE devices in this
// package, the Ledger is online — it streams APDU commands over USB
// HID to the device while the host is connected.
//
// The native APDU transport requires HID access via a CGO-linked
// library (libusb / libhidapi) and a per-app "Ledger app" running on
// the device (Bitcoin app, Ethereum app, …). Embedding that stack in
// luxfi/hsm would pull a large native dependency tree.
//
// Architecture (this implementation):
//
//   mpcd ─ stdin/stdout ─> ledgerctl ─ HID ─> Ledger Nano
//
// We mirror the YubiHSM signer's design: shell out to the Ledger Live
// CLI / `ledgerctl` so the official Ledger toolchain owns the USB and
// app-protocol surface. mpcd never touches USB directly. Operators
// install ledgerctl on the host, plug the device in, unlock it, and
// open the relevant app before invoking Sign.
//
// Operator setup (Linux, see https://github.com/LedgerHQ/app-ethereum):
//
//   1. apt-get install ledger-live  # ships ledgerctl
//   2. Install the Ethereum app via Ledger Live ManagerThen
//      open the app on the device.
//   3. mpcd --hsm-signer=ledger \
//          --hsm-ledger-tool=ledgerctl \
//          --hsm-ledger-app=ethereum
//
// The signer asks ledgerctl to sign a hex-encoded payload. The exact
// command varies by app (eth-sign-tx, btc-sign-psbt, sol-sign-tx). Use
// LedgerConfig.SignAction to select the right verb for the app on the
// device.

// LedgerConfig configures a Ledger signer.
type LedgerConfig struct {
	// ToolPath is the path to ledgerctl. Empty defaults to "ledgerctl"
	// on PATH.
	ToolPath string

	// App identifies the Ledger app to address. Examples:
	//   "ethereum"  → eth-sign-tx
	//   "bitcoin"   → btc-sign-psbt
	//   "solana"    → sol-sign-tx
	App string

	// SignAction overrides the verb passed to ledgerctl. Defaults to
	// "{App}-sign-tx" derived from App.
	SignAction string

	// DerivationPath is the BIP-32 path of the key to sign with.
	// Required. Format "m/44'/60'/0'/0/0".
	DerivationPath string
}

// LedgerSigner produces signatures via a Ledger device using ledgerctl.
type LedgerSigner struct {
	cfg LedgerConfig
}

// NewLedgerSigner validates configuration and returns a signer.
func NewLedgerSigner(cfg LedgerConfig) (*LedgerSigner, error) {
	if cfg.App == "" {
		return nil, errors.New("hsm/ledger: App required (e.g., ethereum, bitcoin, solana)")
	}
	if cfg.DerivationPath == "" {
		return nil, errors.New("hsm/ledger: DerivationPath required (e.g., m/44'/60'/0'/0/0)")
	}
	if cfg.SignAction == "" {
		cfg.SignAction = cfg.App + "-sign-tx"
	}
	return &LedgerSigner{cfg: cfg}, nil
}

// Provider returns "ledger".
func (s *LedgerSigner) Provider() string { return "ledger" }

// Sign sends the message to ledgerctl on stdin and returns the device
// signature on stdout. The operator must approve the transaction on
// the device — the call blocks until ledgerctl returns.
//
// keyID is unused (the key is selected by DerivationPath). Preserved
// for interface symmetry.
func (s *LedgerSigner) Sign(ctx context.Context, _ string, message []byte) ([]byte, error) {
	tool := s.cfg.ToolPath
	if tool == "" {
		tool = "ledgerctl"
	}
	if _, err := exec.LookPath(tool); err != nil {
		return nil, fmt.Errorf("hsm/ledger: %s not found on PATH: %w", tool, err)
	}
	args := []string{
		s.cfg.SignAction,
		"--path", s.cfg.DerivationPath,
		"--input-format", "hex",
		"--output-format", "hex",
	}
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Stdin = strings.NewReader(hex.EncodeToString(message))
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("hsm/ledger: %s failed: %w", s.cfg.SignAction, err)
	}
	sigHex := strings.TrimSpace(out.String())
	if sigHex == "" {
		return nil, errors.New("hsm/ledger: empty signature returned")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("hsm/ledger: decode signature: %w", err)
	}
	return sig, nil
}

// Verify is unsupported on the Ledger Signer. The device exposes no
// verify primitive — verification is a public-key operation performed
// by the chain or by a host-side library against a pinned pubkey
// fetched once at provisioning.
func (s *LedgerSigner) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errors.New("hsm/ledger: Verify not supported (verify with chain client or pinned pubkey)")
}
