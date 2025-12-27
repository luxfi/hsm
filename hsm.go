// Package hsm provides unified Hardware Security Module integration for the Lux ecosystem.
//
// This is the single entry point for all HSM, KMS, and custody operations.
// It consolidates:
//
//   - Password providers (symmetric decryption of ZapDB passwords via cloud KMS)
//   - Signing providers (asymmetric signing for intent co-signing, settlement attestation)
//   - Post-quantum signing (ML-DSA FIPS 204 via Cloudflare CIRCL)
//   - ZapDB-backed encrypted key storage (ChaCha20-Poly1305 over BadgerDB)
//
// Supported cloud providers:
//
//   - AWS KMS (symmetric decrypt + asymmetric sign)
//   - Google Cloud KMS (symmetric decrypt + asymmetric sign)
//   - Zymbit SCM (asymmetric sign via local PKCS#11)
//   - Azure Key Vault (symmetric decrypt)
//   - Local/Dev (in-memory ECDSA P-256)
//
// Usage:
//
//	cfg := hsm.Config{
//	    PasswordProvider: "aws",  // or "gcp", "azure", "env", "file"
//	    SignerProvider:   "aws",  // or "gcp", "zymbit", "mldsa", "local"
//	    SignerKeyID:      "arn:aws:kms:us-east-1:...",
//	    Region:           "us-east-1",
//	}
//	mgr, err := hsm.New(cfg)
//	// mgr.Signer() implements the Signer interface
//	// mgr.PasswordProvider() implements the PasswordProvider interface
package hsm
