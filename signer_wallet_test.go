// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// fakePSBT returns a minimal byte slice that satisfies looksLikePSBT.
// The bytes are not a valid BIP-174 transaction — only the magic
// prefix is asserted by the signer.
func fakePSBT() []byte {
	return append([]byte("psbt\xff"), bytes.Repeat([]byte{0x00}, 32)...)
}

func TestColdcardSignRoundtrip(t *testing.T) {
	signed := append(fakePSBT(), 0x42)
	tr := &MockAirgapTransport{Response: signed}
	s, err := NewColdcardSigner(ColdcardConfig{
		DeviceID:  "wallet-0",
		Transport: tr,
	})
	if err != nil {
		t.Fatalf("NewColdcardSigner: %v", err)
	}
	if got := s.Provider(); got != "coldcard" {
		t.Fatalf("Provider=%q want coldcard", got)
	}
	out, err := s.Sign(context.Background(), "", fakePSBT())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(out, signed) {
		t.Fatalf("Sign returned %x want %x", out, signed)
	}
	// Challenge must record the device ID and a session ID.
	if tr.LastChallenge.DeviceID != "wallet-0" {
		t.Errorf("DeviceID=%q want wallet-0", tr.LastChallenge.DeviceID)
	}
	if tr.LastChallenge.SessionID == "" {
		t.Error("SessionID empty")
	}
	if tr.LastChallenge.Format != FormatPSBT {
		t.Errorf("Format=%q want psbt", tr.LastChallenge.Format)
	}
}

func TestColdcardRejectsNonPSBT(t *testing.T) {
	tr := &MockAirgapTransport{Response: fakePSBT()}
	s, _ := NewColdcardSigner(ColdcardConfig{DeviceID: "x", Transport: tr})
	_, err := s.Sign(context.Background(), "", []byte("not a psbt"))
	if err == nil {
		t.Fatal("expected PSBT magic check to reject")
	}
}

func TestColdcardWithoutTransport(t *testing.T) {
	s, _ := NewColdcardSigner(ColdcardConfig{DeviceID: "x"})
	_, err := s.Sign(context.Background(), "", fakePSBT())
	if !errors.Is(err, ErrAirgapTransportRequired) {
		t.Fatalf("err=%v want ErrAirgapTransportRequired", err)
	}
}

func TestColdcardBadResponse(t *testing.T) {
	tr := &MockAirgapTransport{Response: []byte("not signed")}
	s, _ := NewColdcardSigner(ColdcardConfig{DeviceID: "x", Transport: tr})
	_, err := s.Sign(context.Background(), "", fakePSBT())
	if err == nil || !strings.Contains(err.Error(), "PSBT") {
		t.Fatalf("err=%v want PSBT-magic error", err)
	}
}

func TestFoundationSignRoundtrip(t *testing.T) {
	signed := append(fakePSBT(), 0x77)
	tr := &MockAirgapTransport{Response: signed}
	s, err := NewFoundationSigner(FoundationConfig{
		DeviceID:  "passport-0",
		Transport: tr,
	})
	if err != nil {
		t.Fatalf("NewFoundationSigner: %v", err)
	}
	if got := s.Provider(); got != "foundation" {
		t.Fatalf("Provider=%q want foundation", got)
	}
	out, err := s.Sign(context.Background(), "", fakePSBT())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(out, signed) {
		t.Fatalf("Sign returned %x want %x", out, signed)
	}
	if tr.LastChallenge.Format != FormatBBQr {
		t.Errorf("Format=%q want bbqr", tr.LastChallenge.Format)
	}
}

func TestKeystoneSignRoundtrip(t *testing.T) {
	req := []byte("ur:eth-sign-request/oeadtpdaecsylufmtoaelfaohdca")
	resp := []byte("ur:eth-signature/oeadtpdaecsylufmtoaelfaohdca")
	tr := &MockAirgapTransport{Response: resp}
	s, err := NewKeystoneSigner(KeystoneConfig{
		DeviceID:  "keystone-0",
		URType:    URTypeEthSignRequest,
		Transport: tr,
	})
	if err != nil {
		t.Fatalf("NewKeystoneSigner: %v", err)
	}
	if got := s.Provider(); got != "keystone" {
		t.Fatalf("Provider=%q want keystone", got)
	}
	out, err := s.Sign(context.Background(), "", req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(out, resp) {
		t.Fatalf("Sign returned %q want %q", out, resp)
	}
	if tr.LastChallenge.Format != FormatUR {
		t.Errorf("Format=%q want ur", tr.LastChallenge.Format)
	}
}

func TestKeystoneRejectsWrongURPrefix(t *testing.T) {
	tr := &MockAirgapTransport{Response: []byte("ur:eth-signature/x")}
	s, _ := NewKeystoneSigner(KeystoneConfig{
		DeviceID:  "k",
		URType:    URTypeEthSignRequest,
		Transport: tr,
	})
	// caller passes a btc-sign-request envelope by mistake
	_, err := s.Sign(context.Background(), "", []byte("ur:btc-sign-request/x"))
	if err == nil {
		t.Fatal("expected URType prefix check to reject")
	}
}

func TestNGRAVESignRoundtrip(t *testing.T) {
	req := []byte("ur:eth-sign-request/oeadtpdaecsylufmtoaelfaohdca")
	resp := []byte("ur:eth-signature/oeadtpdaecsylufmtoaelfaohdca")
	tr := &MockAirgapTransport{Response: resp}
	s, err := NewNGRAVESigner(NGRAVEConfig{
		DeviceID:  "ngrave-0",
		URType:    URTypeEthSignRequest,
		Transport: tr,
	})
	if err != nil {
		t.Fatalf("NewNGRAVESigner: %v", err)
	}
	if got := s.Provider(); got != "ngrave" {
		t.Fatalf("Provider=%q want ngrave", got)
	}
	out, err := s.Sign(context.Background(), "", req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(out, resp) {
		t.Fatalf("Sign returned %q want %q", out, resp)
	}
}

func TestColdcardConfigValidation(t *testing.T) {
	if _, err := NewColdcardSigner(ColdcardConfig{}); err == nil {
		t.Error("missing DeviceID should fail")
	}
	if _, err := NewColdcardSigner(ColdcardConfig{DeviceID: "x", Format: "weird"}); err == nil {
		t.Error("unsupported format should fail")
	}
}

func TestKeystoneConfigValidation(t *testing.T) {
	if _, err := NewKeystoneSigner(KeystoneConfig{}); err == nil {
		t.Error("missing DeviceID should fail")
	}
	if _, err := NewKeystoneSigner(KeystoneConfig{DeviceID: "x"}); err == nil {
		t.Error("missing URType should fail")
	}
}

func TestNGRAVEConfigValidation(t *testing.T) {
	if _, err := NewNGRAVESigner(NGRAVEConfig{}); err == nil {
		t.Error("missing DeviceID should fail")
	}
	if _, err := NewNGRAVESigner(NGRAVEConfig{DeviceID: "x"}); err == nil {
		t.Error("missing URType should fail")
	}
}

func TestFoundationConfigValidation(t *testing.T) {
	if _, err := NewFoundationSigner(FoundationConfig{}); err == nil {
		t.Error("missing DeviceID should fail")
	}
}

func TestLatticeConfigValidation(t *testing.T) {
	if _, err := NewLatticeSigner(LatticeConfig{}); err == nil {
		t.Error("missing BaseURL should fail")
	}
	if _, err := NewLatticeSigner(LatticeConfig{BaseURL: "http://insecure"}); err == nil {
		t.Error("non-HTTPS BaseURL should fail")
	}
	if _, err := NewLatticeSigner(LatticeConfig{BaseURL: "https://x"}); err == nil {
		t.Error("missing DeviceID should fail")
	}
	s, err := NewLatticeSigner(LatticeConfig{BaseURL: "https://l", DeviceID: "d"})
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if got := s.Provider(); got != "gridplus" {
		t.Fatalf("Provider=%q want gridplus", got)
	}
	// Sign and Verify must return the documented NotImpl error.
	if _, err := s.Sign(context.Background(), "k", []byte("m")); err == nil {
		t.Error("Sign should return NotImpl error")
	}
	if _, err := s.Verify(context.Background(), "k", []byte("m"), []byte("s")); err == nil {
		t.Error("Verify should return NotImpl error")
	}
}

func TestLedgerConfigValidation(t *testing.T) {
	if _, err := NewLedgerSigner(LedgerConfig{}); err == nil {
		t.Error("missing App should fail")
	}
	if _, err := NewLedgerSigner(LedgerConfig{App: "ethereum"}); err == nil {
		t.Error("missing DerivationPath should fail")
	}
	s, err := NewLedgerSigner(LedgerConfig{
		App:            "ethereum",
		DerivationPath: "m/44'/60'/0'/0/0",
	})
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if got := s.Provider(); got != "ledger" {
		t.Fatalf("Provider=%q want ledger", got)
	}
}

func TestTrezorConfigValidation(t *testing.T) {
	if _, err := NewTrezorSigner(TrezorConfig{}); err == nil {
		t.Error("missing Coin should fail")
	}
	if _, err := NewTrezorSigner(TrezorConfig{Coin: "ethereum"}); err == nil {
		t.Error("missing DerivationPath should fail")
	}
	s, err := NewTrezorSigner(TrezorConfig{
		Coin:           "ethereum",
		DerivationPath: "m/44'/60'/0'/0/0",
	})
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if got := s.Provider(); got != "trezor" {
		t.Fatalf("Provider=%q want trezor", got)
	}
}

func TestFactoryRegistersAllWalletProviders(t *testing.T) {
	cases := []struct {
		name  string
		cfg   map[string]string
		wantP string
	}{
		{"coldcard", map[string]string{"device_id": "x"}, "coldcard"},
		{"foundation", map[string]string{"device_id": "x"}, "foundation"},
		{"keystone", map[string]string{"device_id": "x", "ur_type": "eth-sign-request"}, "keystone"},
		{"ngrave", map[string]string{"device_id": "x", "ur_type": "eth-sign-request"}, "ngrave"},
		{"gridplus", map[string]string{"base_url": "https://l", "device_id": "d"}, "gridplus"},
		{"lattice", map[string]string{"base_url": "https://l", "device_id": "d"}, "gridplus"},
		{"ledger", map[string]string{"app": "ethereum", "path": "m/44'/60'/0'/0/0"}, "ledger"},
		{"trezor", map[string]string{"coin": "ethereum", "path": "m/44'/60'/0'/0/0"}, "trezor"},
		{"pkcs11", map[string]string{"library": "/dev/null", "key_label": "k", "pin": "1234"}, "pkcs11"},
		{"nitrokey", map[string]string{"library": "/dev/null", "key_label": "k", "pin": "1234"}, "nitrokey"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := NewSigner(c.name, c.cfg)
			if err != nil {
				t.Fatalf("NewSigner(%q): %v", c.name, err)
			}
			if got := s.Provider(); got != c.wantP {
				t.Errorf("Provider()=%q want %q", got, c.wantP)
			}
		})
	}
}

func TestFactoryUnknownProvider(t *testing.T) {
	if _, err := NewSigner("not-a-real-thing", nil); err == nil {
		t.Error("expected unknown-provider error")
	}
}
