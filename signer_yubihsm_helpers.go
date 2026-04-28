// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import "crypto/ed25519"

// ed25519VerifyStdlib wraps stdlib ed25519.Verify. Kept in a separate
// file so signer_yubihsm.go does not directly depend on crypto/ed25519
// (the verify path is exercised only by tests using "raw32:" pubkey
// envelopes — production callers verify with their own pinned key).
func ed25519VerifyStdlib(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
