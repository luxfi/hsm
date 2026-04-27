// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

// TestTR31RoundTrip wraps and unwraps a PIN-encryption key and checks
// that every header field and the plaintext bytes round-trip.
func TestTR31RoundTrip(t *testing.T) {
	signer, _, err := NewTR31SignerWithRandomKBPK()
	if err != nil {
		t.Fatalf("NewTR31Signer: %v", err)
	}
	defer signer.Wipe()

	pek := make([]byte, 16) // AES-128 PEK
	for i := range pek {
		pek[i] = byte(i + 0x10)
	}
	block := TR31KeyBlock{
		Usage:         TR31UsagePINEncryption,
		Algorithm:     TR31AlgAES,
		ModeOfUse:     TR31ModeBoth,
		KeyVersion:    "00",
		Exportability: TR31ExportNonExportable,
		PlaintextKey:  pek,
	}

	wrapped, err := signer.Wrap(block)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if wrapped[0] != 'D' {
		t.Errorf("version byte = %q, want D", wrapped[:1])
	}
	if !strings.HasPrefix(string(wrapped[5:7]), "P0") {
		t.Errorf("usage = %q, want P0", wrapped[5:7])
	}

	got, err := signer.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got.Usage != TR31UsagePINEncryption {
		t.Errorf("Usage = %q, want %q", got.Usage, TR31UsagePINEncryption)
	}
	if got.Algorithm != TR31AlgAES {
		t.Errorf("Algorithm = %q, want A", got.Algorithm)
	}
	if got.ModeOfUse != TR31ModeBoth {
		t.Errorf("ModeOfUse = %q, want B", got.ModeOfUse)
	}
	if got.Exportability != TR31ExportNonExportable {
		t.Errorf("Exportability = %q, want N", got.Exportability)
	}
	if hex.EncodeToString(got.PlaintextKey) != hex.EncodeToString(pek) {
		t.Errorf("plaintext mismatch: got %x want %x", got.PlaintextKey, pek)
	}
}

// TestTR31TamperHeader confirms that flipping any header byte breaks
// authentication. This is the key security property of X9.143 — the
// MAC is computed over the header so attackers cannot relabel a "M0"
// MAC key as a "P0" PIN-encryption key.
func TestTR31TamperHeader(t *testing.T) {
	signer, _, err := NewTR31SignerWithRandomKBPK()
	if err != nil {
		t.Fatalf("NewTR31Signer: %v", err)
	}
	defer signer.Wipe()

	wrapped, err := signer.Wrap(TR31KeyBlock{
		Usage:         TR31UsageMAC,
		Algorithm:     TR31AlgAES,
		ModeOfUse:     TR31ModeSign,
		KeyVersion:    "00",
		Exportability: TR31ExportNonExportable,
		PlaintextKey:  make([]byte, 16),
	})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Flip M0 to P0 (relabel as PIN key) — must fail authentication.
	tampered := append([]byte{}, wrapped...)
	tampered[5] = 'P'
	if _, err := signer.Unwrap(tampered); err == nil {
		t.Error("Unwrap of header-tampered block should have failed")
	}
}

// TestTR31TamperKey confirms that flipping any ciphertext byte breaks
// authentication.
func TestTR31TamperKey(t *testing.T) {
	signer, _, err := NewTR31SignerWithRandomKBPK()
	if err != nil {
		t.Fatalf("NewTR31Signer: %v", err)
	}
	defer signer.Wipe()

	wrapped, err := signer.Wrap(TR31KeyBlock{
		Usage:         TR31UsageDataEncryption,
		Algorithm:     TR31AlgAES,
		ModeOfUse:     TR31ModeBoth,
		KeyVersion:    "00",
		Exportability: TR31ExportTrusted,
		PlaintextKey:  make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Flip a ciphertext byte (in the body, before the 32-char authenticator).
	tampered := append([]byte{}, wrapped...)
	idx := len(tampered) - 33
	tampered[idx] ^= 0x01
	if _, err := signer.Unwrap(tampered); err == nil {
		t.Error("Unwrap of ciphertext-tampered block should have failed")
	}
}

// TestTR31WrongKBPK confirms the MAC fails when a different KBPK is used
// to unwrap.
func TestTR31WrongKBPK(t *testing.T) {
	signer1, _, _ := NewTR31SignerWithRandomKBPK()
	defer signer1.Wipe()
	signer2, _, _ := NewTR31SignerWithRandomKBPK()
	defer signer2.Wipe()

	wrapped, err := signer1.Wrap(TR31KeyBlock{
		Usage:         TR31UsageKeyEncryption,
		Algorithm:     TR31AlgAES,
		ModeOfUse:     TR31ModeBoth,
		KeyVersion:    "00",
		Exportability: TR31ExportSensitive,
		PlaintextKey:  make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := signer2.Unwrap(wrapped); err == nil {
		t.Error("Unwrap with wrong KBPK should have failed")
	}
}

// TestTR31SignerInterface exercises Register/Sign/Verify so the
// Signer interface adapter is correct.
func TestTR31SignerInterface(t *testing.T) {
	signer, _, _ := NewTR31SignerWithRandomKBPK()
	defer signer.Wipe()
	pek := make([]byte, 16)
	for i := range pek {
		pek[i] = byte(i + 1)
	}
	block := TR31KeyBlock{
		Usage:         TR31UsagePINEncryption,
		Algorithm:     TR31AlgAES,
		ModeOfUse:     TR31ModeBoth,
		KeyVersion:    "00",
		Exportability: TR31ExportNonExportable,
		PlaintextKey:  pek,
	}
	if err := signer.Register("pek-1", block); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if signer.Provider() != "tr31" {
		t.Errorf("Provider = %q, want tr31", signer.Provider())
	}
	wrapped, err := signer.Sign(context.Background(), "pek-1", nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := signer.Verify(context.Background(), "pek-1", nil, wrapped)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify(valid wrap) = false")
	}
}

// TestTR31InvalidKBPK confirms the constructor rejects wrong-size KBPKs.
func TestTR31InvalidKBPK(t *testing.T) {
	for _, n := range []int{0, 16, 24, 33, 64} {
		if _, err := NewTR31Signer(make([]byte, n)); err == nil {
			t.Errorf("NewTR31Signer(%d-byte KBPK) should have failed", n)
		}
	}
}

// TestTR31AESCMACVector uses the canonical NIST SP 800-38B test vector
// to confirm the AES-CMAC implementation matches the standard.
func TestTR31AESCMACVector(t *testing.T) {
	// NIST SP 800-38B §D.1 — AES-128 example 1 (empty message).
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	want, _ := hex.DecodeString("bb1d6929e95937287fa37d129b756746")
	got, err := aesCMAC(key, nil)
	if err != nil {
		t.Fatalf("aesCMAC: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("AES-CMAC empty: got %x want %x", got, want)
	}

	// Example 2: 16-byte message.
	msg, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	want2, _ := hex.DecodeString("070a16b46b4d4144f79bdd9dd04a287c")
	got2, err := aesCMAC(key, msg)
	if err != nil {
		t.Fatalf("aesCMAC: %v", err)
	}
	if hex.EncodeToString(got2) != hex.EncodeToString(want2) {
		t.Errorf("AES-CMAC 16B: got %x want %x", got2, want2)
	}
}
