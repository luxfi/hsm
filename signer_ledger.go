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
	//   "ethereum"  → eth-sign-tx (handles every EVM-compat chain:
	//                 Lux C-Chain, Hanzo, Zoo, Pars; chain_id is in
	//                 the EIP-155 RLP payload)
	//   "lux"       → lux-sign-tx (Lux native P/X chain operations)
	//   "bitcoin"   → btc-sign-psbt
	//   "solana"    → sol-sign-tx
	App string

	// SignAction overrides the verb passed to ledgerctl. Defaults to
	// "{App}-sign-tx" derived from App.
	SignAction string

	// DerivationPath is the BIP-32 path of the key to sign with.
	// Required. Format "m/44'/60'/0'/0/0" for EVM, "m/44'/9000'/0'/0/0"
	// for Lux native. Construct via github.com/luxfi/ledger.BIP44PathForName
	// rather than formatting the string by hand.
	DerivationPath string

	// ChainID is the EIP-155 numeric chain id for EVM-compat signing
	// (Lux C-Chain, Hanzo, Zoo, Pars). Optional — if non-zero, it is
	// passed to ledgerctl via --chain-id so the device displays the
	// correct numeric network identifier on the review screen.
	// Ignored when App != "ethereum".
	ChainID uint64
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
	if strings.EqualFold(s.cfg.App, "ethereum") && s.cfg.ChainID != 0 {
		args = append(args, "--chain-id", fmt.Sprintf("%d", s.cfg.ChainID))
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

// GetPubKey fetches the compressed secp256k1 public key for the
// configured derivation path by invoking ledgerctl. Used by the
// approval-provider verifier to pin the on-device pubkey at enrollment
// time.
//
// The verb varies by app:
//   ethereum → eth-get-pubkey
//   lux      → lux-get-pubkey
//   <other>  → {App}-get-pubkey
//
// Output is hex; we decode and return the raw bytes.
func (s *LedgerSigner) GetPubKey(ctx context.Context) ([]byte, error) {
	tool := s.cfg.ToolPath
	if tool == "" {
		tool = "ledgerctl"
	}
	if _, err := exec.LookPath(tool); err != nil {
		return nil, fmt.Errorf("hsm/ledger: %s not found on PATH: %w", tool, err)
	}
	verb := s.cfg.App + "-get-pubkey"
	cmd := exec.CommandContext(ctx, tool, verb,
		"--path", s.cfg.DerivationPath,
		"--output-format", "hex",
	)
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("hsm/ledger: %s failed: %w", verb, err)
	}
	pkHex := strings.TrimSpace(out.String())
	if pkHex == "" {
		return nil, errors.New("hsm/ledger: empty pubkey returned")
	}
	pk, err := hex.DecodeString(pkHex)
	if err != nil {
		return nil, fmt.Errorf("hsm/ledger: decode pubkey: %w", err)
	}
	return pk, nil
}

// Verify is unsupported on the Ledger Signer. The device exposes no
// verify primitive — verification is a public-key operation performed
// by the chain or by a host-side library against a pinned pubkey
// fetched once at provisioning.
func (s *LedgerSigner) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errors.New("hsm/ledger: Verify not supported (verify with chain client or pinned pubkey)")
}
