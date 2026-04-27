// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import "testing"

// TestRequireFIPSProviderAccepts confirms that providers backed by
// FIPS-validated modules pass the gate without error.
func TestRequireFIPSProviderAccepts(t *testing.T) {
	for _, p := range []string{
		"aws", "AWS",
		"gcp",
		"azure",
		"yubihsm", "yubico", "yubi",
		"pkcs11",
		"kmip",
	} {
		if err := RequireFIPSProvider(p); err != nil {
			t.Errorf("RequireFIPSProvider(%q) = %v, want nil", p, err)
		}
	}
}

// TestRequireFIPSProviderRejects confirms that pure-software and
// non-validated providers are rejected.
func TestRequireFIPSProviderRejects(t *testing.T) {
	cases := map[string]bool{
		"":           true,
		"local":      true,
		"mldsa":      true,
		"pq":         true,
		"tr31":       true,
		"nitrokey":   true,
		"zymbit":     true,
		"coldcard":   true,
		"foundation": true,
		"keystone":   true,
		"ngrave":     true,
		"ledger":     true,
		"trezor":     true,
		"gridplus":   true,
		"lattice":    true,
		"unknown":    true,
	}
	for p := range cases {
		if err := RequireFIPSProvider(p); err == nil {
			t.Errorf("RequireFIPSProvider(%q) = nil, want error", p)
		}
	}
}
