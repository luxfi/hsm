// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/luxfi/crypto/threshold"
)

// ---------------------------------------------------------------------------
// Mock implementations for testing threshold adapter
// ---------------------------------------------------------------------------

type mockKeyShare struct {
	index, thresh, total int
	data                 []byte
	pub                  []byte
	groupKeyData         []byte
	scheme               threshold.SchemeID
}

func (m *mockKeyShare) Index() int                       { return m.index }
func (m *mockKeyShare) Threshold() int                   { return m.thresh }
func (m *mockKeyShare) TotalParties() int                { return m.total }
func (m *mockKeyShare) PublicShare() []byte               { return m.pub }
func (m *mockKeyShare) Bytes() []byte                     { return m.data }
func (m *mockKeyShare) SchemeID() threshold.SchemeID     { return m.scheme }
func (m *mockKeyShare) GroupKey() threshold.PublicKey     { return &mockPublicKey{data: m.groupKeyData, scheme: m.scheme} }

type mockPublicKey struct {
	data   []byte
	scheme threshold.SchemeID
}

func (m *mockPublicKey) Bytes() []byte                        { return m.data }
func (m *mockPublicKey) Equal(other threshold.PublicKey) bool { return string(m.data) == string(other.Bytes()) }
func (m *mockPublicKey) SchemeID() threshold.SchemeID         { return m.scheme }

type mockSignatureShare struct {
	index  int
	data   []byte
	scheme threshold.SchemeID
}

func (m *mockSignatureShare) Index() int                   { return m.index }
func (m *mockSignatureShare) Bytes() []byte                { return m.data }
func (m *mockSignatureShare) SchemeID() threshold.SchemeID { return m.scheme }

type mockThresholdSigner struct {
	share *mockKeyShare
}

func (m *mockThresholdSigner) Index() int                           { return m.share.index }
func (m *mockThresholdSigner) PublicShare() []byte                   { return m.share.pub }
func (m *mockThresholdSigner) KeyShare() threshold.KeyShare         { return m.share }

func (m *mockThresholdSigner) NonceGen(_ context.Context) (threshold.NonceCommitment, threshold.NonceState, error) {
	return nil, nil, nil // BLS-style: non-interactive
}

func (m *mockThresholdSigner) SignShare(_ context.Context, message []byte, _ []int, _ threshold.NonceState) (threshold.SignatureShare, error) {
	return &mockSignatureShare{
		index:  m.share.index,
		data:   append([]byte("share:"), message...),
		scheme: m.share.scheme,
	}, nil
}

// helper to set env for vault tests
func setVaultEnv(t *testing.T, pw string) {
	t.Helper()
	os.Setenv("LUX_MPC_PASSWORD", pw)
	t.Cleanup(func() { os.Unsetenv("LUX_MPC_PASSWORD") })
}

// ---------------------------------------------------------------------------
// KeyShareVault Tests
// ---------------------------------------------------------------------------

func TestKeyShareVaultStoreLoad(t *testing.T) {
	setVaultEnv(t, "test-vault-password-2026")

	pw, _ := NewPasswordProvider("env", nil)
	vault := NewKeyShareVault(pw, "")
	ctx := context.Background()

	data := []byte("secret-key-share-bytes-never-plaintext-at-rest")
	meta := KeyShareMeta{
		SchemeID:     threshold.SchemeBLS,
		Index:        2,
		Threshold:    2,
		TotalParties: 5,
		PublicShare:  []byte("pub-share-2"),
		GroupKey:     []byte("group-key-bls12-381"),
	}

	if err := vault.Store(ctx, "node-2", data, meta); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, gotMeta, err := vault.Load(ctx, "node-2")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if string(got) != string(data) {
		t.Errorf("data mismatch: got %q, want %q", got, data)
	}
	if gotMeta.Index != 2 {
		t.Errorf("Index = %d, want 2", gotMeta.Index)
	}
	if gotMeta.Threshold != 2 {
		t.Errorf("Threshold = %d, want 2", gotMeta.Threshold)
	}
	if gotMeta.TotalParties != 5 {
		t.Errorf("TotalParties = %d, want 5", gotMeta.TotalParties)
	}
	if gotMeta.SchemeID != threshold.SchemeBLS {
		t.Errorf("SchemeID = %v, want BLS", gotMeta.SchemeID)
	}
	if string(gotMeta.PublicShare) != "pub-share-2" {
		t.Errorf("PublicShare = %q", gotMeta.PublicShare)
	}
	if string(gotMeta.GroupKey) != "group-key-bls12-381" {
		t.Errorf("GroupKey = %q", gotMeta.GroupKey)
	}
}

func TestKeyShareVaultNotFound(t *testing.T) {
	setVaultEnv(t, "test-pw")

	pw, _ := NewPasswordProvider("env", nil)
	vault := NewKeyShareVault(pw, "")

	_, _, err := vault.Load(context.Background(), "nonexistent")
	if !errors.Is(err, ErrKeyShareNotFound) {
		t.Errorf("want ErrKeyShareNotFound, got %v", err)
	}
}

func TestKeyShareVaultWrongPassword(t *testing.T) {
	os.Setenv("LUX_MPC_PASSWORD", "password-alpha")
	pw, _ := NewPasswordProvider("env", nil)
	vault := NewKeyShareVault(pw, "")
	ctx := context.Background()

	if err := vault.Store(ctx, "test", []byte("top-secret-share"), KeyShareMeta{}); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Change password — decryption must fail
	os.Setenv("LUX_MPC_PASSWORD", "password-beta")
	_, _, err := vault.Load(ctx, "test")
	if err == nil {
		t.Error("expected decryption failure with wrong password")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("want ErrDecryptionFailed, got %v", err)
	}

	os.Unsetenv("LUX_MPC_PASSWORD")
}

func TestKeyShareVaultDeleteList(t *testing.T) {
	setVaultEnv(t, "delete-test")

	pw, _ := NewPasswordProvider("env", nil)
	vault := NewKeyShareVault(pw, "")
	ctx := context.Background()

	for _, id := range []string{"a", "b", "c"} {
		vault.Store(ctx, id, []byte(id+"-data"), KeyShareMeta{Index: int(id[0] - 'a')})
	}

	if got := len(vault.List()); got != 3 {
		t.Fatalf("want 3 entries, got %d", got)
	}

	vault.Delete("b")
	if got := len(vault.List()); got != 2 {
		t.Fatalf("want 2 after delete, got %d", got)
	}

	_, _, err := vault.Load(ctx, "b")
	if !errors.Is(err, ErrKeyShareNotFound) {
		t.Errorf("deleted key should not be found, got %v", err)
	}

	// a and c still accessible
	for _, id := range []string{"a", "c"} {
		got, _, err := vault.Load(ctx, id)
		if err != nil {
			t.Errorf("Load(%q): %v", id, err)
		}
		if string(got) != id+"-data" {
			t.Errorf("Load(%q) = %q", id, got)
		}
	}
}

func TestKeyShareVaultGetMeta(t *testing.T) {
	setVaultEnv(t, "meta-test")

	pw, _ := NewPasswordProvider("env", nil)
	vault := NewKeyShareVault(pw, "")
	ctx := context.Background()

	vault.Store(ctx, "v1", []byte("secret"), KeyShareMeta{
		SchemeID:     threshold.SchemeFROST,
		Index:        3,
		Threshold:    2,
		TotalParties: 5,
		PublicShare:  []byte("frost-pub"),
	})

	meta, err := vault.GetMeta("v1")
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if meta.Index != 3 {
		t.Errorf("Index = %d, want 3", meta.Index)
	}
	if meta.SchemeID != threshold.SchemeFROST {
		t.Errorf("SchemeID = %v, want FROST", meta.SchemeID)
	}
	if meta.Threshold != 2 || meta.TotalParties != 5 {
		t.Errorf("t-of-n = %d-of-%d, want 2-of-5", meta.Threshold, meta.TotalParties)
	}

	// Not found
	_, err = vault.GetMeta("nonexistent")
	if !errors.Is(err, ErrKeyShareNotFound) {
		t.Errorf("want ErrKeyShareNotFound, got %v", err)
	}
}

func TestKeyShareVaultOverwrite(t *testing.T) {
	setVaultEnv(t, "overwrite-test")

	pw, _ := NewPasswordProvider("env", nil)
	vault := NewKeyShareVault(pw, "")
	ctx := context.Background()

	vault.Store(ctx, "key", []byte("version-1"), KeyShareMeta{Index: 1})
	vault.Store(ctx, "key", []byte("version-2"), KeyShareMeta{Index: 2})

	got, meta, _ := vault.Load(ctx, "key")
	if string(got) != "version-2" {
		t.Errorf("want version-2, got %q", got)
	}
	if meta.Index != 2 {
		t.Errorf("Index = %d, want 2", meta.Index)
	}
}

func TestKeyShareVaultConcurrent(t *testing.T) {
	setVaultEnv(t, "concurrent-vault-test")

	pw, _ := NewPasswordProvider("env", nil)
	vault := NewKeyShareVault(pw, "")
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("node-%d", i)
			data := []byte(fmt.Sprintf("share-%d-secret", i))
			meta := KeyShareMeta{Index: i, SchemeID: threshold.SchemeBLS}

			if err := vault.Store(ctx, id, data, meta); err != nil {
				t.Errorf("Store(%s): %v", id, err)
				return
			}
			got, _, err := vault.Load(ctx, id)
			if err != nil {
				t.Errorf("Load(%s): %v", id, err)
				return
			}
			if string(got) != string(data) {
				t.Errorf("data mismatch for %s", id)
			}
		}(i)
	}
	wg.Wait()

	if got := len(vault.List()); got != 20 {
		t.Errorf("want 20 entries, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// HSMAttestingSigner Tests
// ---------------------------------------------------------------------------

func TestHSMAttestingSignerSignVerify(t *testing.T) {
	hsmSigner := NewLocalSigner()
	share := &mockKeyShare{
		index: 1, thresh: 2, total: 5,
		data: []byte("key-share-data"), pub: []byte("pub-1"),
		groupKeyData: []byte("group-key"), scheme: threshold.SchemeBLS,
	}
	inner := &mockThresholdSigner{share: share}
	attested := NewAttestingSigner(inner, hsmSigner, "attest-key")

	ctx := context.Background()
	msg := []byte("sign-this-consensus-block")

	sigShare, err := attested.SignShare(ctx, msg, []int{0, 1, 2}, nil)
	if err != nil {
		t.Fatalf("SignShare: %v", err)
	}

	if sigShare.Index() != 1 {
		t.Errorf("Index = %d, want 1", sigShare.Index())
	}
	if sigShare.SchemeID() != threshold.SchemeBLS {
		t.Errorf("SchemeID = %v, want BLS", sigShare.SchemeID())
	}

	// Verify attestation
	ok, err := VerifyAttestation(ctx, hsmSigner, "attest-key", sigShare)
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	if !ok {
		t.Error("valid attestation should verify")
	}
}

func TestHSMAttestingSignerDelegation(t *testing.T) {
	hsmSigner := NewLocalSigner()
	share := &mockKeyShare{
		index: 3, thresh: 1, total: 3,
		data: []byte("ks"), pub: []byte("pub-3"),
		groupKeyData: []byte("gk"), scheme: threshold.SchemeCMP,
	}
	inner := &mockThresholdSigner{share: share}
	attested := NewAttestingSigner(inner, hsmSigner, "key")

	if attested.Index() != 3 {
		t.Errorf("Index = %d, want 3", attested.Index())
	}
	if string(attested.PublicShare()) != "pub-3" {
		t.Errorf("PublicShare = %q", attested.PublicShare())
	}
	if attested.KeyShare().SchemeID() != threshold.SchemeCMP {
		t.Errorf("KeyShare().SchemeID() = %v", attested.KeyShare().SchemeID())
	}

	// NonceGen should delegate (returns nil for mock)
	commit, state, err := attested.NonceGen(context.Background())
	if err != nil {
		t.Fatalf("NonceGen: %v", err)
	}
	if commit != nil || state != nil {
		t.Error("mock NonceGen should return nil")
	}
}

func TestAttestedShareBytes(t *testing.T) {
	hsmSigner := NewLocalSigner()
	inner := &mockThresholdSigner{share: &mockKeyShare{
		index: 0, scheme: threshold.SchemeBLS,
		data: []byte("ks"), pub: []byte("p"), groupKeyData: []byte("g"),
	}}
	attested := NewAttestingSigner(inner, hsmSigner, "key")

	share, _ := attested.SignShare(context.Background(), []byte("msg"), []int{0}, nil)

	// Bytes() returns inner share bytes — protocol compatible
	want := []byte("share:msg")
	if string(share.Bytes()) != string(want) {
		t.Errorf("Bytes() = %q, want %q", share.Bytes(), want)
	}

	// MarshalAttested includes both share and attestation
	as := share.(*attestedSignatureShare)
	marshaled := as.MarshalAttested()
	if len(marshaled) <= len(want) {
		t.Error("MarshalAttested should be longer than inner bytes")
	}

	// Attestation is non-empty
	if len(as.Attestation()) == 0 {
		t.Error("attestation should not be empty")
	}

	// InnerShare returns the original share
	if as.InnerShare().Index() != 0 {
		t.Errorf("InnerShare().Index() = %d", as.InnerShare().Index())
	}
}

func TestAttestedShareMarshalRoundtrip(t *testing.T) {
	hsmSigner := NewLocalSigner()
	inner := &mockThresholdSigner{share: &mockKeyShare{
		index: 2, scheme: threshold.SchemeBLS,
		data: []byte("ks"), pub: []byte("p"), groupKeyData: []byte("g"),
	}}
	attested := NewAttestingSigner(inner, hsmSigner, "roundtrip-key")

	share, _ := attested.SignShare(context.Background(), []byte("roundtrip"), []int{0, 1, 2}, nil)
	as := share.(*attestedSignatureShare)

	marshaled := as.MarshalAttested()

	// Verify the marshaled format: [4-byte len][share][attestation]
	shareLen := int(marshaled[0])<<24 | int(marshaled[1])<<16 | int(marshaled[2])<<8 | int(marshaled[3])
	if shareLen != len(as.Bytes()) {
		t.Errorf("marshaled share length = %d, want %d", shareLen, len(as.Bytes()))
	}

	innerBytes := marshaled[4 : 4+shareLen]
	if string(innerBytes) != string(as.Bytes()) {
		t.Errorf("marshaled inner = %q, want %q", innerBytes, as.Bytes())
	}

	attBytes := marshaled[4+shareLen:]
	if string(attBytes) != string(as.Attestation()) {
		t.Error("marshaled attestation mismatch")
	}
}

func TestVerifyAttestationWrongKey(t *testing.T) {
	hsmSigner := NewLocalSigner()
	inner := &mockThresholdSigner{share: &mockKeyShare{
		index: 0, scheme: threshold.SchemeBLS,
		data: []byte("ks"), pub: []byte("p"), groupKeyData: []byte("g"),
	}}
	signer := NewAttestingSigner(inner, hsmSigner, "key-A")

	ctx := context.Background()
	share, _ := signer.SignShare(ctx, []byte("msg"), []int{0}, nil)

	// Verify with wrong key — should fail
	ok, _ := VerifyAttestation(ctx, hsmSigner, "key-B", share)
	if ok {
		t.Error("wrong HSM key should not verify attestation")
	}

	// Verify with correct key — should pass
	ok, _ = VerifyAttestation(ctx, hsmSigner, "key-A", share)
	if !ok {
		t.Error("correct HSM key should verify attestation")
	}
}

func TestVerifyAttestationNonAttested(t *testing.T) {
	hsmSigner := NewLocalSigner()
	plain := &mockSignatureShare{index: 0, data: []byte("plain"), scheme: threshold.SchemeBLS}

	_, err := VerifyAttestation(context.Background(), hsmSigner, "key", plain)
	if !errors.Is(err, ErrShareNotAttested) {
		t.Errorf("want ErrShareNotAttested, got %v", err)
	}
}

func TestHSMAttestingSignerConcurrent(t *testing.T) {
	hsmSigner := NewLocalSigner()
	inner := &mockThresholdSigner{share: &mockKeyShare{
		index: 0, scheme: threshold.SchemeBLS,
		data: []byte("ks"), pub: []byte("p"), groupKeyData: []byte("g"),
	}}
	attested := NewAttestingSigner(inner, hsmSigner, "concurrent-key")
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("block-%d", i))
			share, err := attested.SignShare(ctx, msg, []int{0}, nil)
			if err != nil {
				t.Errorf("SignShare(%d): %v", i, err)
				return
			}
			ok, err := VerifyAttestation(ctx, hsmSigner, "concurrent-key", share)
			if err != nil || !ok {
				t.Errorf("attestation failed for block %d", i)
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// ThresholdManager Tests
// ---------------------------------------------------------------------------

func TestThresholdManagerConstruction(t *testing.T) {
	setVaultEnv(t, "mgr-test")

	mgr, err := NewThresholdManager(ThresholdConfig{
		PasswordProvider: "env",
		SignerProvider:   "local",
		AttestKeyID:      "attest",
	})
	if err != nil {
		t.Fatalf("NewThresholdManager: %v", err)
	}
	if mgr.Vault() == nil {
		t.Error("Vault() should not be nil")
	}
	if mgr.HSMSigner() == nil {
		t.Error("HSMSigner() should not be nil")
	}
	if mgr.HSMSigner().Provider() != "local" {
		t.Errorf("provider = %q, want local", mgr.HSMSigner().Provider())
	}
}

func TestThresholdManagerStoreKeyShare(t *testing.T) {
	setVaultEnv(t, "store-test")

	mgr, _ := NewThresholdManager(ThresholdConfig{
		PasswordProvider: "env",
		SignerProvider:   "local",
		AttestKeyID:      "attest",
	})

	share := &mockKeyShare{
		index: 0, thresh: 2, total: 5,
		data: []byte("bls-secret-share"), pub: []byte("bls-pub"),
		groupKeyData: []byte("bls-group"), scheme: threshold.SchemeBLS,
	}

	ctx := context.Background()
	if err := mgr.StoreKeyShare(ctx, "validator-0", share); err != nil {
		t.Fatalf("StoreKeyShare: %v", err)
	}

	// Verify stored via vault
	meta, err := mgr.Vault().GetMeta("validator-0")
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if meta.SchemeID != threshold.SchemeBLS {
		t.Errorf("scheme = %v, want BLS", meta.SchemeID)
	}
	if meta.Index != 0 || meta.Threshold != 2 || meta.TotalParties != 5 {
		t.Errorf("meta = %+v", meta)
	}
}

func TestThresholdManagerBadConfig(t *testing.T) {
	_, err := NewThresholdManager(ThresholdConfig{
		PasswordProvider: "bad",
		SignerProvider:   "local",
	})
	if err == nil {
		t.Error("want error for bad password provider")
	}

	setVaultEnv(t, "test")
	_, err = NewThresholdManager(ThresholdConfig{
		PasswordProvider: "env",
		SignerProvider:   "bad",
	})
	if err == nil {
		t.Error("want error for bad signer provider")
	}
}

// ---------------------------------------------------------------------------
// Multi-scheme metadata
// ---------------------------------------------------------------------------

func TestKeyShareVaultMultiScheme(t *testing.T) {
	setVaultEnv(t, "multi-scheme")

	pw, _ := NewPasswordProvider("env", nil)
	vault := NewKeyShareVault(pw, "")
	ctx := context.Background()

	schemes := []struct {
		id     string
		scheme threshold.SchemeID
		data   string
	}{
		{"bls-0", threshold.SchemeBLS, "bls-share"},
		{"frost-0", threshold.SchemeFROST, "frost-share"},
		{"cmp-0", threshold.SchemeCMP, "cmp-share"},
		{"ringtail-0", threshold.SchemeRingtail, "ringtail-share"},
	}

	for _, s := range schemes {
		vault.Store(ctx, s.id, []byte(s.data), KeyShareMeta{SchemeID: s.scheme})
	}

	for _, s := range schemes {
		got, meta, err := vault.Load(ctx, s.id)
		if err != nil {
			t.Errorf("Load(%q): %v", s.id, err)
			continue
		}
		if string(got) != s.data {
			t.Errorf("Load(%q) data = %q, want %q", s.id, got, s.data)
		}
		if meta.SchemeID != s.scheme {
			t.Errorf("Load(%q) scheme = %v, want %v", s.id, meta.SchemeID, s.scheme)
		}
	}
}
