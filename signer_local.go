package hsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"
)

// LocalSigner uses a local ECDSA P-256 key for development/testing.
// NOT FOR PRODUCTION — the key exists only in memory.
type LocalSigner struct {
	mu   sync.Mutex
	keys map[string]*ecdsa.PrivateKey
}

func NewLocalSigner() *LocalSigner {
	return &LocalSigner{keys: make(map[string]*ecdsa.PrivateKey)}
}

func (s *LocalSigner) Provider() string { return "local" }

func (s *LocalSigner) getOrCreateKey(keyID string) (*ecdsa.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if k, ok := s.keys[keyID]; ok {
		return k, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s.keys[keyID] = k
	return k, nil
}

func (s *LocalSigner) Sign(_ context.Context, keyID string, message []byte) ([]byte, error) {
	key, err := s.getOrCreateKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("hsm/local: failed to get key: %w", err)
	}
	digest := sha256.Sum256(message)
	r, sv, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("hsm/local: signing failed: %w", err)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, sv})
	if err != nil {
		return nil, fmt.Errorf("hsm/local: failed to encode signature: %w", err)
	}
	return sig, nil
}

func (s *LocalSigner) Verify(_ context.Context, keyID string, message, signature []byte) (bool, error) {
	key, err := s.getOrCreateKey(keyID)
	if err != nil {
		return false, fmt.Errorf("hsm/local: failed to get key: %w", err)
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature), nil
}
