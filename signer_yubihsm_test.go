// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// writeFakeShell writes a small POSIX shell script that mimics the
// subset of yubihsm-shell flags this package emits: --action sign-data
// reads bytes from stdin and emits an ed25519 signature; --action
// get-public-key emits "raw32:<hex>" so the test verifier can decode
// it. The keypair is provided to the script via environment variables.
func writeFakeShell(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake shell uses POSIX /bin/sh")
	}
	path := filepath.Join(dir, "yubihsm-shell")
	script := `#!/bin/sh
set -e
ACTION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --action) ACTION="$2"; shift 2;;
    *) shift;;
  esac
done
case "$ACTION" in
  get-public-key)
    "${YUBI_TEST_HELPER}" pub
    ;;
  sign-data)
    "${YUBI_TEST_HELPER}" sign
    ;;
  *)
    echo "unsupported action $ACTION" >&2
    exit 2;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake shell: %v", err)
	}
	return path
}

// writeAndBuildHelper compiles a tiny Go program that, when invoked
// with "pub", emits "raw32:<hex>" of the ed25519 pubkey derived from
// $YUBI_TEST_SEED_HEX, and when invoked with "sign", reads stdin and
// emits a 64-byte ed25519 signature.
func writeAndBuildHelper(t *testing.T, dir string) string {
	t.Helper()
	src := `package main
import (
  "crypto/ed25519"
  "encoding/hex"
  "fmt"
  "io"
  "os"
)
func main(){
  if len(os.Args) < 2 { os.Exit(2) }
  seed, err := hex.DecodeString(os.Getenv("YUBI_TEST_SEED_HEX"))
  if err != nil || len(seed) != ed25519.SeedSize {
    fmt.Fprintln(os.Stderr, "bad seed"); os.Exit(2)
  }
  priv := ed25519.NewKeyFromSeed(seed)
  pub := priv.Public().(ed25519.PublicKey)
  switch os.Args[1] {
  case "pub":
    fmt.Print("raw32:" + hex.EncodeToString(pub))
  case "sign":
    msg, _ := io.ReadAll(os.Stdin)
    os.Stdout.Write(ed25519.Sign(priv, msg))
  default:
    os.Exit(2)
  }
}
`
	srcPath := filepath.Join(dir, "helper.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write helper src: %v", err)
	}
	binPath := filepath.Join(dir, "helper")
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot build helper (no go toolchain in PATH?): %v", err)
	}
	return binPath
}

func TestYubiHSMSignVerifyWithFakeShell(t *testing.T) {
	tmp := t.TempDir()
	helper := writeAndBuildHelper(t, tmp)
	t.Setenv("YUBI_TEST_HELPER", helper)
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	t.Setenv("YUBI_TEST_SEED_HEX", hex.EncodeToString(seed))
	shell := writeFakeShell(t, tmp)

	s := &YubiHSMSigner{
		ConnectorURL: "http://127.0.0.1:12345",
		AuthKeyID:    1,
		Password:     "test-password",
		Algorithm:    "ed25519",
		shellPath:    shell,
	}
	if got := s.Provider(); got != "yubihsm" {
		t.Fatalf("Provider=%q want yubihsm", got)
	}

	ctx := context.Background()
	msg := []byte("hello yubihsm")
	sig, err := s.Sign(ctx, "12", msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("Sign: len=%d want 64", len(sig))
	}

	ok, err := s.Verify(ctx, "12", msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("valid signature should verify")
	}

	ok, _ = s.Verify(ctx, "12", []byte("tampered"), sig)
	if ok {
		t.Error("tampered message should not verify")
	}
}

func TestYubiHSMFactoryRegistration(t *testing.T) {
	for _, name := range []string{"yubihsm", "yubico", "yubi", "YubiHSM"} {
		s, err := NewSigner(name, map[string]string{
			"connector_url": "http://127.0.0.1:12345",
			"auth_key_id":   "1",
			"password":      "x",
			"algorithm":     "ed25519",
		})
		if err != nil {
			t.Fatalf("NewSigner(%q): %v", name, err)
		}
		if s.Provider() != "yubihsm" {
			t.Errorf("NewSigner(%q).Provider()=%s want yubihsm", name, s.Provider())
		}
	}
}

func TestYubiHSMParseObjectID(t *testing.T) {
	for input, want := range map[string]uint16{
		"1":      1,
		"123":    123,
		"0x000c": 12,
		"0X10":   16,
	} {
		v, err := parseObjectID(input)
		if err != nil {
			t.Errorf("parseObjectID(%q): %v", input, err)
			continue
		}
		if v != want {
			t.Errorf("parseObjectID(%q)=%d want %d", input, v, want)
		}
	}
	for _, bad := range []string{"", "abc", "0xZZ"} {
		if _, err := parseObjectID(bad); err == nil {
			t.Errorf("parseObjectID(%q) want error", bad)
		}
	}
}

func TestYubiHSMMissingPassword(t *testing.T) {
	s := &YubiHSMSigner{}
	t.Setenv("MPC_HSM_YUBIHSM_PASSWORD", "")
	if _, err := s.Sign(context.Background(), "1", []byte("x")); err == nil {
		t.Error("expected password error")
	}
}
