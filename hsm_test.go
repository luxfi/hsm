package hsm

import (
	"context"
	"crypto/sha256"
	"testing"
)

// ---------------------------------------------------------------------------
// Signer Factory Tests
// ---------------------------------------------------------------------------

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
		{"post-quantum", "mldsa"},
		{"local", "local"},
		{"", "local"},
		{"  LOCAL  ", "local"},
		{"AWS", "aws"},
		{"GCP", "gcp"},
		{"  Azure ", "azure"},
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

func TestNewSignerWithConfig(t *testing.T) {
	s, err := NewSigner("aws", map[string]string{"region": "eu-west-1"})
	if err != nil {
		t.Fatalf("NewSigner(aws) error: %v", err)
	}
	if s.(*AWSKMSSigner).Region != "eu-west-1" {
		t.Errorf("Region = %q, want eu-west-1", s.(*AWSKMSSigner).Region)
	}

	s, err = NewSigner("zymbit", map[string]string{"api_addr": "http://10.0.0.5:6789"})
	if err != nil {
		t.Fatalf("NewSigner(zymbit) error: %v", err)
	}
	if s.(*ZymbitSigner).APIAddr != "http://10.0.0.5:6789" {
		t.Errorf("APIAddr = %q", s.(*ZymbitSigner).APIAddr)
	}

	s, err = NewSigner("azure", map[string]string{"vault_url": "https://myvault.vault.azure.net"})
	if err != nil {
		t.Fatalf("NewSigner(azure) error: %v", err)
	}
	if s.(*AzureKVSigner).VaultURL != "https://myvault.vault.azure.net" {
		t.Errorf("VaultURL = %q", s.(*AzureKVSigner).VaultURL)
	}
}

func TestNewSignerUnknown(t *testing.T) {
	_, err := NewSigner("nonexistent", nil)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

// ---------------------------------------------------------------------------
// Password Provider Factory Tests
// ---------------------------------------------------------------------------

func TestNewPasswordProviderAllTypes(t *testing.T) {
	for _, p := range []string{"aws", "gcp", "azure", "env", "file", "", "  ENV  ", "AWS"} {
		_, err := NewPasswordProvider(p, nil)
		if err != nil {
			t.Errorf("NewPasswordProvider(%q) error: %v", p, err)
		}
	}
}

func TestNewPasswordProviderUnknown(t *testing.T) {
	_, err := NewPasswordProvider("nonexistent", nil)
	if err == nil {
		t.Error("expected error for unknown password provider")
	}
}

// ---------------------------------------------------------------------------
// Local Signer Tests
// ---------------------------------------------------------------------------

func TestLocalSignerSignVerify(t *testing.T) {
	s := NewLocalSigner()
	ctx := context.Background()
	msg := []byte("test message for signing")

	sig, err := s.Sign(ctx, "key1", msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := s.Verify(ctx, "key1", msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("valid signature should verify")
	}
}

func TestLocalSignerWrongMessage(t *testing.T) {
	s := NewLocalSigner()
	ctx := context.Background()
	sig, _ := s.Sign(ctx, "key", []byte("original"))

	ok, _ := s.Verify(ctx, "key", []byte("tampered"), sig)
	if ok {
		t.Error("wrong message should not verify")
	}
}

func TestLocalSignerWrongKey(t *testing.T) {
	s := NewLocalSigner()
	ctx := context.Background()
	sig, _ := s.Sign(ctx, "key-A", []byte("msg"))

	ok, _ := s.Verify(ctx, "key-B", []byte("msg"), sig)
	if ok {
		t.Error("different key should not verify")
	}
}

func TestLocalSignerDeterministicKey(t *testing.T) {
	s := NewLocalSigner()
	ctx := context.Background()
	msg := []byte("deterministic")

	sig1, _ := s.Sign(ctx, "same-key", msg)
	sig2, _ := s.Sign(ctx, "same-key", msg)

	ok1, _ := s.Verify(ctx, "same-key", msg, sig1)
	ok2, _ := s.Verify(ctx, "same-key", msg, sig2)
	if !ok1 || !ok2 {
		t.Error("both sigs from same key should verify")
	}
}

func TestLocalSignerEmptyMessage(t *testing.T) {
	s := NewLocalSigner()
	ctx := context.Background()
	sig, _ := s.Sign(ctx, "key", []byte{})
	ok, _ := s.Verify(ctx, "key", []byte{}, sig)
	if !ok {
		t.Error("empty message sig should verify")
	}
}

func TestLocalSignerLargeMessage(t *testing.T) {
	s := NewLocalSigner()
	ctx := context.Background()
	msg := make([]byte, 1<<20) // 1MB
	for i := range msg {
		msg[i] = byte(i)
	}
	sig, _ := s.Sign(ctx, "big-key", msg)
	ok, _ := s.Verify(ctx, "big-key", msg, sig)
	if !ok {
		t.Error("large message sig should verify")
	}
}

func TestLocalSignerProvider(t *testing.T) {
	if NewLocalSigner().Provider() != "local" {
		t.Error("want local")
	}
}

// ---------------------------------------------------------------------------
// ML-DSA Post-Quantum Signer Tests
// ---------------------------------------------------------------------------

func TestMLDSASignVerify(t *testing.T) {
	s, _ := NewSigner("mldsa", nil)
	ctx := context.Background()
	msg := []byte("post-quantum test")

	sig, err := s.Sign(ctx, "pq1", msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty sig")
	}
	ok, _ := s.Verify(ctx, "pq1", msg, sig)
	if !ok {
		t.Error("ML-DSA sig should verify")
	}
}

func TestMLDSAWrongMessage(t *testing.T) {
	s, _ := NewSigner("mldsa", nil)
	ctx := context.Background()
	sig, _ := s.Sign(ctx, "pq", []byte("original"))
	ok, _ := s.Verify(ctx, "pq", []byte("tampered"), sig)
	if ok {
		t.Error("tampered should not verify")
	}
}

func TestMLDSAProvider(t *testing.T) {
	s, _ := NewSigner("mldsa", nil)
	if s.Provider() != "mldsa" {
		t.Errorf("want mldsa, got %s", s.Provider())
	}
}

func TestMLDSALargeMessage(t *testing.T) {
	s, _ := NewSigner("mldsa", nil)
	ctx := context.Background()
	msg := make([]byte, 1<<16)
	for i := range msg {
		msg[i] = byte(i)
	}
	sig, _ := s.Sign(ctx, "pq-big", msg)
	ok, _ := s.Verify(ctx, "pq-big", msg, sig)
	if !ok {
		t.Error("large ML-DSA sig should verify")
	}
}

func TestMLDSACrossKey(t *testing.T) {
	s, _ := NewSigner("mldsa", nil)
	ctx := context.Background()
	msg := []byte("cross-key")

	sig1, _ := s.Sign(ctx, "alpha", msg)
	sig2, _ := s.Sign(ctx, "beta", msg)

	// Cross-key should fail
	ok, _ := s.Verify(ctx, "beta", msg, sig1)
	if ok {
		t.Error("cross-key should fail")
	}
	ok, _ = s.Verify(ctx, "alpha", msg, sig2)
	if ok {
		t.Error("cross-key should fail")
	}

	// Own key should pass
	ok, _ = s.Verify(ctx, "alpha", msg, sig1)
	if !ok {
		t.Error("own key should verify")
	}
	ok, _ = s.Verify(ctx, "beta", msg, sig2)
	if !ok {
		t.Error("own key should verify")
	}
}

// ---------------------------------------------------------------------------
// Manager Tests
// ---------------------------------------------------------------------------

func TestManagerConstruction(t *testing.T) {
	mgr, err := New(Config{PasswordProvider: "env", SignerProvider: "local", SignerKeyID: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if mgr.Signer() == nil || mgr.PasswordProvider() == nil {
		t.Error("nil interfaces")
	}
	if mgr.Signer().Provider() != "local" {
		t.Errorf("want local, got %s", mgr.Signer().Provider())
	}
}

func TestManagerSignVerify(t *testing.T) {
	mgr, _ := New(Config{PasswordProvider: "env", SignerProvider: "local", SignerKeyID: "mgr"})
	ctx := context.Background()
	sig, _ := mgr.Sign(ctx, []byte("test"))
	ok, _ := mgr.Verify(ctx, []byte("test"), sig)
	if !ok {
		t.Error("manager sign/verify failed")
	}
}

func TestManagerSignWithKey(t *testing.T) {
	mgr, _ := New(Config{PasswordProvider: "env", SignerProvider: "local", SignerKeyID: "default"})
	ctx := context.Background()
	sig, _ := mgr.SignWithKey(ctx, "specific", []byte("test"))
	ok, _ := mgr.VerifyWithKey(ctx, "specific", []byte("test"), sig)
	if !ok {
		t.Error("SignWithKey/VerifyWithKey failed")
	}
	// Default key should NOT verify
	ok, _ = mgr.Verify(ctx, []byte("test"), sig)
	if ok {
		t.Error("default key should not verify specific-key sig")
	}
}

func TestManagerPQ(t *testing.T) {
	mgr, _ := New(Config{PasswordProvider: "env", SignerProvider: "mldsa", SignerKeyID: "pq"})
	if mgr.Signer().Provider() != "mldsa" {
		t.Errorf("want mldsa, got %s", mgr.Signer().Provider())
	}
	ctx := context.Background()
	sig, _ := mgr.Sign(ctx, []byte("pq test"))
	ok, _ := mgr.Verify(ctx, []byte("pq test"), sig)
	if !ok {
		t.Error("PQ manager sign/verify failed")
	}
}

func TestManagerBadConfig(t *testing.T) {
	_, err := New(Config{PasswordProvider: "bad", SignerProvider: "local"})
	if err == nil {
		t.Error("want error for bad pw provider")
	}
	_, err = New(Config{PasswordProvider: "env", SignerProvider: "bad"})
	if err == nil {
		t.Error("want error for bad signer")
	}
}

// ---------------------------------------------------------------------------
// Auth Helpers
// ---------------------------------------------------------------------------

func TestSHA256Hex(t *testing.T) {
	got := sha256Hex([]byte("hello world"))
	h := sha256.Sum256([]byte("hello world"))
	want := ""
	for _, b := range h {
		want += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0xf])
	}
	if got != want {
		t.Errorf("sha256Hex mismatch")
	}
}

func TestHmacSHA256Deterministic(t *testing.T) {
	key := []byte("secret")
	data := []byte("hello")
	r1 := hmacSHA256(key, data)
	r2 := hmacSHA256(key, data)
	if len(r1) != 32 {
		t.Errorf("len = %d, want 32", len(r1))
	}
	for i := range r1 {
		if r1[i] != r2[i] {
			t.Fatal("not deterministic")
		}
	}
}

func TestParseGCPKeyResourceName(t *testing.T) {
	r := parseGCPKeyResourceName("projects/p1/locations/us/keyRings/kr/cryptoKeys/ck")
	if r == nil {
		t.Fatal("nil result")
	}
	if r["project"] != "p1" || r["location"] != "us" || r["keyRing"] != "kr" || r["cryptoKey"] != "ck" {
		t.Errorf("parsed: %v", r)
	}

	// With version
	r = parseGCPKeyResourceName("projects/prod/locations/global/keyRings/mpc/cryptoKeys/signer/cryptoKeyVersions/1")
	if r["project"] != "prod" || r["cryptoKey"] != "signer" {
		t.Errorf("with version: %v", r)
	}

	// Too short
	if parseGCPKeyResourceName("projects/foo") != nil {
		t.Error("should be nil for short input")
	}
	if parseGCPKeyResourceName("") != nil {
		t.Error("should be nil for empty")
	}
}

// ---------------------------------------------------------------------------
// Config Tests
// ---------------------------------------------------------------------------

func TestZymbitAPIAddrDefault(t *testing.T) {
	z := &ZymbitSigner{}
	if z.apiAddr() != "http://localhost:6789" {
		t.Errorf("default = %q", z.apiAddr())
	}
	z.APIAddr = "http://custom:1234"
	if z.apiAddr() != "http://custom:1234" {
		t.Errorf("custom = %q", z.apiAddr())
	}
}

func TestAzureVaultURL(t *testing.T) {
	a := &AzureKVSigner{VaultURL: "https://test.vault.azure.net/"}
	if a.vaultURL() != "https://test.vault.azure.net" {
		t.Errorf("vaultURL = %q", a.vaultURL())
	}
}

// ---------------------------------------------------------------------------
// Concurrent Safety
// ---------------------------------------------------------------------------

func TestLocalSignerConcurrent(t *testing.T) {
	s := NewLocalSigner()
	ctx := context.Background()
	msg := []byte("concurrent")
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func() {
			sig, err := s.Sign(ctx, "shared", msg)
			if err != nil {
				t.Errorf("Sign: %v", err)
				done <- false
				return
			}
			ok, _ := s.Verify(ctx, "shared", msg, sig)
			done <- ok
		}()
	}
	for i := 0; i < 20; i++ {
		if !<-done {
			t.Error("concurrent verification failed")
		}
	}
}

func TestMLDSAConcurrent(t *testing.T) {
	s, _ := NewSigner("mldsa", nil)
	ctx := context.Background()
	msg := []byte("concurrent pq")
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func() {
			sig, err := s.Sign(ctx, "shared-pq", msg)
			if err != nil {
				t.Errorf("Sign: %v", err)
				done <- false
				return
			}
			ok, _ := s.Verify(ctx, "shared-pq", msg, sig)
			done <- ok
		}()
	}
	for i := 0; i < 20; i++ {
		if !<-done {
			t.Error("concurrent PQ verification failed")
		}
	}
}

// ---------------------------------------------------------------------------
// Provider strings
// ---------------------------------------------------------------------------

func TestAllProviderStrings(t *testing.T) {
	for input, want := range map[string]string{
		"aws": "aws", "gcp": "gcp", "azure": "azure",
		"zymbit": "zymbit", "mldsa": "mldsa", "local": "local",
	} {
		s, _ := NewSigner(input, nil)
		if s.Provider() != want {
			t.Errorf("%q: got %q", input, s.Provider())
		}
	}
}
