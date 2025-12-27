package hsm

import "context"

// Signer provides asymmetric signing and verification using HSM-backed keys.
// This is the core interface consumed by the MPC API server for intent
// co-signing and settlement attestation.
//
// Implementations:
//   - AWSKMSSigner (ECDSA_SHA_256 via AWS KMS)
//   - GCPKMSSigner (EC_SIGN_P256_SHA256 via Google Cloud KMS)
//   - ZymbitSigner (ECDSA P-256 via local Zymbit SCM)
//   - MLDSASigner  (ML-DSA-65 post-quantum via Cloudflare CIRCL)
//   - LocalSigner  (ECDSA P-256 in-memory, development only)
type Signer interface {
	// Sign produces a signature over the given message using the HSM key.
	Sign(ctx context.Context, keyID string, message []byte) ([]byte, error)

	// Verify checks a signature against the given message using the HSM key.
	Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error)

	// Provider returns the provider name (e.g., "aws", "gcp", "zymbit", "mldsa", "local").
	Provider() string
}

// PasswordProvider retrieves or derives a decrypted password string from
// an external secret store. Used to unlock ZapDB encryption keys.
//
// Implementations:
//   - AWSKMSProvider  (KMS Decrypt on ZAPDB_ENCRYPTED_PASSWORD)
//   - GCPKMSProvider  (Cloud KMS Decrypt on ZAPDB_ENCRYPTED_PASSWORD)
//   - AzureKVProvider (Key Vault unwrapKey on ZAPDB_ENCRYPTED_PASSWORD)
//   - EnvProvider     (reads LUX_MPC_PASSWORD or ZAPDB_PASSWORD env var)
//   - FileProvider    (reads from a file, e.g. K8s mounted secret)
type PasswordProvider interface {
	// GetPassword returns the plaintext password identified by keyID.
	// For cloud providers, keyID is typically a key ARN or alias.
	GetPassword(ctx context.Context, keyID string) (string, error)
}
