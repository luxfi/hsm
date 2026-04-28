// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import "crypto/rand"

// readRandom is a tiny wrapper around crypto/rand.Read kept in its own
// file so airgap.go does not directly import crypto/rand. The wrapper
// exists for testability — tests may temporarily override readRandom in
// the rare case they need a deterministic session ID.
func readRandom(b []byte) (int, error) {
	return rand.Read(b)
}
