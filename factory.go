package hsm

import (
	"fmt"
	"os"
	"strings"

	"github.com/luxfi/crypto/mldsa"
)

// NewSigner creates a Signer for the given provider type.
// Supported: "aws", "gcp", "azure", "zymbit", "mldsa", "local".
func NewSigner(providerType string, config map[string]string) (Signer, error) {
	providerType = strings.TrimSpace(strings.ToLower(providerType))
	switch providerType {
	case "aws":
		region := ""
		if config != nil {
			region = config["region"]
		}
		return &AWSKMSSigner{Region: region}, nil

	case "gcp":
		return &GCPKMSSigner{}, nil

	case "azure":
		vaultURL := ""
		if config != nil {
			vaultURL = config["vault_url"]
		}
		return &AzureKVSigner{VaultURL: vaultURL}, nil

	case "zymbit":
		apiAddr := ""
		if config != nil {
			apiAddr = config["api_addr"]
		}
		return &ZymbitSigner{APIAddr: apiAddr}, nil

	case "mldsa", "pq", "post-quantum":
		return NewMLDSASigner(mldsa.MLDSA65), nil

	case "local", "":
		return NewLocalSigner(), nil

	default:
		return nil, fmt.Errorf("hsm: unknown signer provider %q (supported: aws, gcp, azure, zymbit, mldsa, local)", providerType)
	}
}

// NewPasswordProvider creates a PasswordProvider based on the given type string.
// Supported types: "aws", "gcp", "azure", "env", "file".
func NewPasswordProvider(providerType string, config map[string]string) (PasswordProvider, error) {
	providerType = strings.TrimSpace(strings.ToLower(providerType))
	if providerType == "" {
		providerType = "env"
	}

	get := func(key, envKey string) string {
		if config != nil {
			if v, ok := config[key]; ok && v != "" {
				return v
			}
		}
		return os.Getenv(envKey)
	}

	switch providerType {
	case "aws":
		return &AWSKMSProvider{
			KeyID:  get("key_id", "MPC_HSM_KEY_ID"),
			Region: get("region", "AWS_REGION"),
		}, nil

	case "gcp":
		return &GCPKMSProvider{
			ProjectID:   get("project_id", "GCP_PROJECT_ID"),
			LocationID:  get("location", "GCP_KMS_LOCATION"),
			KeyRingID:   get("key_ring", "GCP_KMS_KEYRING"),
			CryptoKeyID: get("crypto_key", "GCP_KMS_KEY"),
		}, nil

	case "azure":
		return &AzureKVProvider{
			VaultURL:   get("vault_url", "AZURE_VAULT_URL"),
			KeyName:    get("key_name", "AZURE_KEY_NAME"),
			KeyVersion: get("key_version", "AZURE_KEY_VERSION"),
		}, nil

	case "env":
		envVar := get("env_var", "")
		if envVar == "" {
			envVar = "LUX_MPC_PASSWORD"
		}
		return &EnvProvider{EnvVar: envVar}, nil

	case "file":
		return &FileProvider{
			Path: get("path", "MPC_PASSWORD_FILE"),
		}, nil

	default:
		return nil, fmt.Errorf("hsm: unknown password provider type %q (supported: aws, gcp, azure, env, file)", providerType)
	}
}
