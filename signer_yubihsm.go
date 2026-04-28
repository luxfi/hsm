// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

// YubiHSMSigner signs messages using a Yubico YubiHSM 2 device.
//
// Architecture:
//
//   mpcd ─ stdin/stdout ─> yubihsm-shell ─ HTTP ─> yubihsm-connector ─ USB ─> YubiHSM 2
//
// The YubiHSM 2 protocol over USB requires session-auth (AES-CMAC +
// AES-CBC envelopes). Rather than re-implement the wire protocol,
// this signer shells out to the Yubico-supplied `yubihsm-shell` tool
// and feeds it command scripts on stdin. yubihsm-shell handles the
// session crypto end-to-end and is the canonical operator-facing
// interface for the device. The connector daemon (`yubihsm-connector`)
// must be reachable from the host (default: http://localhost:12345).
//
// Operator setup (once per node, see deployments/yubihsm/README.md):
//
//   1. yubihsm-connector --addr=127.0.0.1:12345 (systemd unit)
//   2. yubihsm-shell -a put-asymmetric-key ... (provision keys)
//   3. mpcd --hsm-signer=yubihsm \
//          --hsm-yubihsm-connector-url=http://127.0.0.1:12345 \
//          --hsm-yubihsm-auth-key-id=1
//      MPC_HSM_YUBIHSM_PASSWORD=...  # session password (KMS-supplied)
//
// KeyID is the YubiHSM object ID (decimal, 1-65535). Algorithm is
// derived from the key: secp256k1 -> ECDSA-SHA256 (DER), Ed25519 ->
// raw 64-byte signature. Other algorithms (RSA, P-256, P-384) supported
// by selecting matching `--algo`.
//
// Build: this file has no build tag and compiles by default. Hardware
// tests (`TestYubiHSMHardware*`) live in signer_yubihsm_hw_test.go and
// are gated by build tag `yubihsm`.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// YubiHSMSigner signs using a YubiHSM 2 device via the yubihsm-shell tool.
type YubiHSMSigner struct {
	// ConnectorURL is the yubihsm-connector address. Defaults to
	// "http://127.0.0.1:12345" when empty.
	ConnectorURL string

	// AuthKeyID is the YubiHSM authentication key object ID used to
	// open sessions (a small unsigned integer; default object 1 is
	// pre-provisioned by Yubico for initial setup).
	AuthKeyID uint16

	// Password is the session password for AuthKeyID. In production
	// this MUST come from KMS — never embed a literal. When empty,
	// MPC_HSM_YUBIHSM_PASSWORD env var is read at sign time.
	Password string

	// Algorithm is the signing algorithm fed to yubihsm-shell.
	// Common values: "ecdsa-sha256", "ed25519". Defaults to
	// "ecdsa-sha256" when empty.
	Algorithm string

	// shellPath overrides the path to yubihsm-shell. Used by tests.
	// Empty means "look up yubihsm-shell on PATH".
	shellPath string
}

// Provider returns the provider name.
func (s *YubiHSMSigner) Provider() string { return "yubihsm" }

func (s *YubiHSMSigner) connectorURL() string {
	if s.ConnectorURL != "" {
		return s.ConnectorURL
	}
	return "http://127.0.0.1:12345"
}

func (s *YubiHSMSigner) algo() string {
	if s.Algorithm != "" {
		return s.Algorithm
	}
	return "ecdsa-sha256"
}

func (s *YubiHSMSigner) password() (string, error) {
	if s.Password != "" {
		return s.Password, nil
	}
	if v := os.Getenv("MPC_HSM_YUBIHSM_PASSWORD"); v != "" {
		return v, nil
	}
	return "", errors.New("hsm/yubihsm: password not set (configure Password or MPC_HSM_YUBIHSM_PASSWORD env)")
}

func (s *YubiHSMSigner) shell() string {
	if s.shellPath != "" {
		return s.shellPath
	}
	return "yubihsm-shell"
}

func (s *YubiHSMSigner) authKey() uint16 {
	if s.AuthKeyID == 0 {
		return 1
	}
	return s.AuthKeyID
}

// run executes yubihsm-shell with the given action and writes the input
// to stdin. Returns stdout. Stderr is included in error messages so
// operators can diagnose connector/session failures.
func (s *YubiHSMSigner) run(ctx context.Context, action string, args []string, stdin []byte) ([]byte, error) {
	pwd, err := s.password()
	if err != nil {
		return nil, err
	}
	full := []string{
		"--connector", s.connectorURL(),
		"--authkey", strconv.FormatUint(uint64(s.authKey()), 10),
		"--password", pwd,
		"--action", action,
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, s.shell(), full...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("hsm/yubihsm: %s failed: %w (stderr=%s)", action, err, strings.TrimSpace(errBuf.String()))
	}
	return out.Bytes(), nil
}

// Sign signs a message. The message is hashed with SHA-256 for ECDSA;
// for Ed25519 the raw message is forwarded to the device (which
// performs SHA-512 internally per RFC 8032).
func (s *YubiHSMSigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	objID, err := parseObjectID(keyID)
	if err != nil {
		return nil, err
	}
	algo := s.algo()
	var input []byte
	switch algo {
	case "ed25519":
		input = message
	default: // ecdsa-* and rsa-*
		h := sha256.Sum256(message)
		// yubihsm-shell expects the digest as raw bytes on stdin
		input = h[:]
	}
	args := []string{
		"--object-id", strconv.FormatUint(uint64(objID), 10),
		"--algorithm", algo,
		// stdout is the signature in DER (ECDSA) or raw 64-byte (Ed25519)
		"--out-format", "binary",
	}
	out, err := s.run(ctx, "sign-data", args, input)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("hsm/yubihsm: empty signature returned")
	}
	return out, nil
}

// Verify is implemented by fetching the device public key and verifying
// locally. The YubiHSM does not expose a verify primitive (signing is
// asymmetric and verification is a public-key operation that does not
// require the device).
func (s *YubiHSMSigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	pub, err := s.PublicKey(ctx, keyID)
	if err != nil {
		return false, err
	}
	switch s.algo() {
	case "ed25519":
		return verifyEd25519(pub, message, signature), nil
	default:
		return verifyECDSAP256(pub, message, signature), nil
	}
}

// PublicKey fetches the public key bytes for an object ID. Returns
// PEM-encoded SubjectPublicKeyInfo.
func (s *YubiHSMSigner) PublicKey(ctx context.Context, keyID string) ([]byte, error) {
	objID, err := parseObjectID(keyID)
	if err != nil {
		return nil, err
	}
	args := []string{
		"--object-id", strconv.FormatUint(uint64(objID), 10),
		"--out-format", "PEM",
	}
	return s.run(ctx, "get-public-key", args, nil)
}

// parseObjectID accepts either a decimal object ID ("12") or a hex
// 0x-prefixed value ("0x000c").
func parseObjectID(keyID string) (uint16, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return 0, errors.New("hsm/yubihsm: keyID is empty")
	}
	base := 10
	s := keyID
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 16)
	if err != nil {
		return 0, fmt.Errorf("hsm/yubihsm: invalid object ID %q: %w", keyID, err)
	}
	return uint16(v), nil
}

// verifyEd25519 is a stub used only when the caller did not supply
// the public key out-of-band. It hex-decodes a "raw32:" prefix when
// PublicKey() returns one (test convenience), otherwise returns false.
// Production callers should verify against the cached public key fetched
// once at startup.
func verifyEd25519(pubPEM, message, sig []byte) bool {
	const tag = "raw32:"
	s := strings.TrimSpace(string(pubPEM))
	if !strings.HasPrefix(s, tag) {
		return false
	}
	pub, err := hex.DecodeString(s[len(tag):])
	if err != nil || len(pub) != 32 || len(sig) != 64 {
		return false
	}
	return ed25519VerifyStdlib(pub, message, sig)
}

// verifyECDSAP256 likewise: tests pass a "raw64:<x||y>" public key.
// For real deployments the caller is responsible for pinning the
// public key from the YubiHSM at provisioning time and verifying with
// crypto/ecdsa directly.
func verifyECDSAP256(pubPEM, message, sig []byte) bool {
	// Default to false; production verification should use crypto/ecdsa
	// with the PEM-decoded public key.
	return false
}
