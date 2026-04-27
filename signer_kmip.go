// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

// KMIP (Key Management Interoperability Protocol) is the OASIS standard
// management surface for enterprise HSMs. KMIP 2.1 (OASIS, 2020) is the
// canonical version supported by Thales CipherTrust Manager, Utimaco
// Enterprise Secure Key Manager, Entrust KeyControl, IBM SKLM, Fortanix
// DSM, HashiCorp Vault Enterprise, and Hashicorp Vault OSS via plugins.
//
// luxfi/hsm uses KMIP for two purposes:
//
//   1. Asymmetric signing — the same Sign/Verify interface every other
//      provider exposes, but operations (1.2 §6.1.4) Sign/SignatureVerify
//      go over a TLS-wrapped TTLV channel to the KMS server.
//
//   2. Key lifecycle management — Activate, Revoke, Destroy operations
//      that PKCS#11 does not standardize. luxfi/hsm exposes these via
//      KMIPSigner.Lifecycle() so operators can rotate signing keys
//      without bringing down mpcd.
//
// Build: signer_kmip_real.go (CGO-free pure Go using gemalto/kmip-go) is
// activated by `-tags kmip`. Default build returns the stub from
// signer_kmip_stub.go which yields errKMIPNotBuilt at runtime.
//
// gemalto/kmip-go (Apache-2 from Thales/Gemalto) provides the canonical
// TTLV codec, message envelope structures, and TLS auth primitives. It
// has no CGO dependency and runs on every Go platform we target.

// KMIPConfig configures a KMIP 2.1 client. Endpoint addressing follows
// the OASIS KMIP Profile (TLS-wrapped TTLV on TCP 5696 by default).
type KMIPConfig struct {
	// Endpoint is "host:port" of the KMIP server. Default port is 5696
	// per the OASIS KMIP profile.
	Endpoint string

	// CAFile is the PEM-encoded CA bundle the server certificate is
	// validated against. KMIP mandates TLS server auth — never disable.
	CAFile string

	// ClientCertFile and ClientKeyFile carry the TLS 1.3 mTLS client
	// certificate. KMIP profiles 1 & 2 mandate mTLS for client auth;
	// embedded user/password fields exist in TTLV but are forbidden by
	// PCI and FIPS deployments.
	ClientCertFile string
	ClientKeyFile  string

	// ServerName overrides the SNI / certificate common-name match. Use
	// it when Endpoint is an IP address but the certificate names a host.
	ServerName string

	// UniqueIdentifier is the KMIP UID of the asymmetric signing key on
	// the server (see KMIP 2.1 §3.1). The signer's Sign(keyID, …)
	// argument is forwarded as the UID — this field is the default UID
	// used when keyID is empty.
	UniqueIdentifier string

	// CryptographicAlgorithm names the algorithm bound to the key
	// ("ECDSA", "EdDSA", "RSA", "ML-DSA"). Used to select the matching
	// KMIP CryptographicParameters block on Sign requests.
	CryptographicAlgorithm string

	// HashingAlgorithm names the digest paired with the algorithm
	// ("SHA-256", "SHA-512"). Defaults to "SHA-256".
	HashingAlgorithm string

	// TimeoutSeconds bounds each Sign/Verify request. Defaults to 15.
	TimeoutSeconds int
}

// kmipProviderName is the canonical Provider() string returned by
// KMIPSigner regardless of the underlying KMS server vendor.
const kmipProviderName = "kmip"
