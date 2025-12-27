package hsm

import (
	"context"
	"fmt"
)

// Config holds the unified configuration for the HSM subsystem.
type Config struct {
	// PasswordProvider selects the password provider: "aws", "gcp", "azure", "env", "file"
	PasswordProvider string

	// PasswordKeyID is the key ID for the password provider (e.g., KMS key ARN)
	PasswordKeyID string

	// SignerProvider selects the signing provider: "aws", "gcp", "azure", "zymbit", "mldsa", "local"
	SignerProvider string

	// SignerKeyID is the default key ID for signing operations
	SignerKeyID string

	// Region is the cloud region (used by AWS)
	Region string

	// Extra config (provider-specific)
	PasswordConfig map[string]string
	SignerConfig   map[string]string
}

// Manager is the unified entry point for all HSM operations.
// It provides both password decryption (for ZapDB) and asymmetric signing
// (for intent co-signing, settlement attestation, etc.).
//
// Usage:
//
//	mgr, err := hsm.New(hsm.Config{
//	    PasswordProvider: "aws",
//	    SignerProvider:   "gcp",
//	    SignerKeyID:      "projects/my-project/locations/global/...",
//	})
//	password, _ := mgr.GetPassword(ctx)
//	sig, _ := mgr.Sign(ctx, "my-key", message)
type Manager struct {
	cfg      Config
	password PasswordProvider
	signer   Signer
}

// New creates a new HSM Manager with the given configuration.
func New(cfg Config) (*Manager, error) {
	pwConfig := cfg.PasswordConfig
	if pwConfig == nil {
		pwConfig = map[string]string{}
	}
	if cfg.Region != "" {
		pwConfig["region"] = cfg.Region
	}

	pw, err := NewPasswordProvider(cfg.PasswordProvider, pwConfig)
	if err != nil {
		return nil, fmt.Errorf("hsm: failed to create password provider: %w", err)
	}

	sigConfig := cfg.SignerConfig
	if sigConfig == nil {
		sigConfig = map[string]string{}
	}
	if cfg.Region != "" {
		sigConfig["region"] = cfg.Region
	}

	signer, err := NewSigner(cfg.SignerProvider, sigConfig)
	if err != nil {
		return nil, fmt.Errorf("hsm: failed to create signer: %w", err)
	}

	return &Manager{
		cfg:      cfg,
		password: pw,
		signer:   signer,
	}, nil
}

// Signer returns the underlying Signer implementation.
// This is what should be passed to the API server via SetHSM().
func (m *Manager) Signer() Signer {
	return m.signer
}

// PasswordProvider returns the underlying PasswordProvider.
func (m *Manager) PasswordProvider() PasswordProvider {
	return m.password
}

// GetPassword retrieves the ZapDB password using the configured provider.
func (m *Manager) GetPassword(ctx context.Context) (string, error) {
	return m.password.GetPassword(ctx, m.cfg.PasswordKeyID)
}

// Sign signs a message using the configured signer and default key ID.
func (m *Manager) Sign(ctx context.Context, message []byte) ([]byte, error) {
	return m.signer.Sign(ctx, m.cfg.SignerKeyID, message)
}

// SignWithKey signs a message using a specific key ID.
func (m *Manager) SignWithKey(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	return m.signer.Sign(ctx, keyID, message)
}

// Verify verifies a signature using the configured signer and default key ID.
func (m *Manager) Verify(ctx context.Context, message, signature []byte) (bool, error) {
	return m.signer.Verify(ctx, m.cfg.SignerKeyID, message, signature)
}

// VerifyWithKey verifies a signature using a specific key ID.
func (m *Manager) VerifyWithKey(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	return m.signer.Verify(ctx, keyID, message, signature)
}
