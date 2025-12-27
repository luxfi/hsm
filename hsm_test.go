package hsm

import (
	"context"
	"testing"
)

func TestNewSignerAllProviders(t *testing.T) {
	tests := []struct {
		provider string
		wantName string
	}{
		{"aws", "aws"},
		{"gcp", "gcp"},
		{"azure", "azure"},
		{"zymbit", "zymbit"},
		{"mldsa", "mldsa"},
		{"pq", "mldsa"},
		{"local", "local"},
		{"", "local"},
	}

	for _, tt := range tests {
		s, err := NewSigner(tt.provider, nil)
		if err != nil {
			t.Errorf("NewSigner(%q) error: %v", tt.provider, err)
			continue
		}
		if got := s.Provider(); got != tt.wantName {
			t.Errorf("NewSigner(%q).Provider() = %q, want %q", tt.provider, got, tt.wantName)
		}
	}
}

func TestNewSignerUnknown(t *testing.T) {
	_, err := NewSigner("nonexistent", nil)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestNewPasswordProviderAllTypes(t *testing.T) {
	tests := []struct {
		provider string
	}{
		{"aws"},
		{"gcp"},
		{"azure"},
		{"env"},
		{"file"},
		{""},
	}

	for _, tt := range tests {
		_, err := NewPasswordProvider(tt.provider, nil)
		if err != nil {
			t.Errorf("NewPasswordProvider(%q) error: %v", tt.provider, err)
		}
	}
}

func TestLocalSignerSignVerify(t *testing.T) {
	s := NewLocalSigner()
	ctx := context.Background()
	msg := []byte("test message for signing")
	keyID := "test-key-1"

	sig, err := s.Sign(ctx, keyID, msg)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	ok, err := s.Verify(ctx, keyID, msg, sig)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !ok {
		t.Error("valid signature should verify")
	}

	// Wrong message should fail
	ok, err = s.Verify(ctx, keyID, []byte("wrong"), sig)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Error("wrong message should not verify")
	}
}

func TestMLDSASignerSignVerify(t *testing.T) {
	s, err := NewSigner("mldsa", nil)
	if err != nil {
		t.Fatalf("NewSigner(mldsa) error: %v", err)
	}

	ctx := context.Background()
	msg := []byte("post-quantum test message")
	keyID := "pq-key-1"

	sig, err := s.Sign(ctx, keyID, msg)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	ok, err := s.Verify(ctx, keyID, msg, sig)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !ok {
		t.Error("valid ML-DSA signature should verify")
	}

	// Wrong message
	ok, err = s.Verify(ctx, keyID, []byte("tampered"), sig)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Error("tampered message should not verify with ML-DSA")
	}
}

func TestManagerConstruction(t *testing.T) {
	mgr, err := New(Config{
		PasswordProvider: "env",
		SignerProvider:   "local",
		SignerKeyID:      "test-key",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if mgr.Signer() == nil {
		t.Error("Signer() should not be nil")
	}
	if mgr.PasswordProvider() == nil {
		t.Error("PasswordProvider() should not be nil")
	}
	if mgr.Signer().Provider() != "local" {
		t.Errorf("expected local signer, got %s", mgr.Signer().Provider())
	}
}

func TestManagerSignVerify(t *testing.T) {
	mgr, err := New(Config{
		PasswordProvider: "env",
		SignerProvider:   "local",
		SignerKeyID:      "mgr-key",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	ctx := context.Background()
	msg := []byte("manager integration test")

	sig, err := mgr.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	ok, err := mgr.Verify(ctx, msg, sig)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !ok {
		t.Error("manager sign/verify round-trip failed")
	}
}
