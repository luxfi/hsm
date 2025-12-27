package hsm

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/luxfi/crypto/mldsa"
)

// MLDSASigner uses ML-DSA (FIPS 204) post-quantum signatures.
// Each keyID maps to a generated ML-DSA-65 keypair (NIST Level 3, 192-bit PQ security).
//
// This signer is suitable for environments where post-quantum resistance is required
// but no hardware HSM is available. Key material lives in memory (protected by Go GC).
//
// For production post-quantum HSM signing, use AWS KMS (which now supports ML-DSA)
// or a Zymbit device with PQ firmware.
type MLDSASigner struct {
	mu   sync.Mutex
	mode mldsa.Mode
	keys map[string]*mldsa.PrivateKey
}

// NewMLDSASigner creates a post-quantum signer using ML-DSA.
// mode: 0=ML-DSA-44 (128-bit), 1=ML-DSA-65 (192-bit, recommended), 2=ML-DSA-87 (256-bit)
func NewMLDSASigner(mode mldsa.Mode) *MLDSASigner {
	return &MLDSASigner{
		mode: mode,
		keys: make(map[string]*mldsa.PrivateKey),
	}
}

func (s *MLDSASigner) Provider() string { return "mldsa" }

func (s *MLDSASigner) getOrCreateKey(keyID string) (*mldsa.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if k, ok := s.keys[keyID]; ok {
		return k, nil
	}
	k, err := mldsa.GenerateKey(rand.Reader, s.mode)
	if err != nil {
		return nil, fmt.Errorf("hsm/mldsa: failed to generate key for %q: %w", keyID, err)
	}
	s.keys[keyID] = k
	return k, nil
}

func (s *MLDSASigner) Sign(_ context.Context, keyID string, message []byte) ([]byte, error) {
	key, err := s.getOrCreateKey(keyID)
	if err != nil {
		return nil, err
	}
	sig, err := key.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("hsm/mldsa: signing failed: %w", err)
	}
	return sig, nil
}

func (s *MLDSASigner) Verify(_ context.Context, keyID string, message, signature []byte) (bool, error) {
	key, err := s.getOrCreateKey(keyID)
	if err != nil {
		return false, err
	}
	return key.PublicKey.Verify(message, signature, crypto.Hash(0)), nil
}
