package hsm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ---------------------------------------------------------------------------
// AWS KMS Password Provider
// ---------------------------------------------------------------------------

// AWSKMSProvider decrypts a ciphertext blob using the AWS KMS Decrypt API.
// The ciphertext is read from the ZAPDB_ENCRYPTED_PASSWORD env var (base64).
type AWSKMSProvider struct {
	KeyID  string
	Region string
}

func (p *AWSKMSProvider) GetPassword(ctx context.Context, keyID string) (string, error) {
	if keyID != "" {
		p.KeyID = keyID
	}

	region := p.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}

	ciphertextB64 := os.Getenv("ZAPDB_ENCRYPTED_PASSWORD")
	if ciphertextB64 == "" {
		return "", fmt.Errorf("hsm/aws: ZAPDB_ENCRYPTED_PASSWORD env var is empty")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("hsm/aws: failed to base64-decode ciphertext: %w", err)
	}

	reqBody := map[string]interface{}{
		"CiphertextBlob": base64.StdEncoding.EncodeToString(ciphertext),
	}
	if p.KeyID != "" {
		reqBody["KeyId"] = p.KeyID
	}
	bodyJSON, _ := json.Marshal(reqBody)

	endpoint := fmt.Sprintf("https://kms.%s.amazonaws.com/", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return "", fmt.Errorf("hsm/aws: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Decrypt")

	if err := signAWSRequest(req, bodyJSON, region, "kms"); err != nil {
		return "", fmt.Errorf("hsm/aws: failed to sign request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hsm/aws: KMS request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hsm/aws: KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Plaintext string `json:"Plaintext"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("hsm/aws: failed to parse KMS response: %w", err)
	}
	if result.Plaintext == "" {
		return "", fmt.Errorf("hsm/aws: KMS returned empty plaintext")
	}

	plaintext, err := base64.StdEncoding.DecodeString(result.Plaintext)
	if err != nil {
		return "", fmt.Errorf("hsm/aws: failed to decode plaintext: %w", err)
	}
	return string(plaintext), nil
}

// ---------------------------------------------------------------------------
// GCP Cloud KMS Password Provider
// ---------------------------------------------------------------------------

// GCPKMSProvider decrypts a ciphertext blob using the GCP Cloud KMS REST API.
type GCPKMSProvider struct {
	ProjectID   string
	LocationID  string
	KeyRingID   string
	CryptoKeyID string
}

func (p *GCPKMSProvider) GetPassword(ctx context.Context, keyID string) (string, error) {
	if keyID != "" && strings.Contains(keyID, "/") {
		parts := parseGCPKeyResourceName(keyID)
		if parts != nil {
			p.ProjectID = parts["project"]
			p.LocationID = parts["location"]
			p.KeyRingID = parts["keyRing"]
			p.CryptoKeyID = parts["cryptoKey"]
		}
	}

	if p.ProjectID == "" {
		p.ProjectID = os.Getenv("GCP_PROJECT_ID")
	}
	if p.LocationID == "" {
		p.LocationID = os.Getenv("GCP_KMS_LOCATION")
		if p.LocationID == "" {
			p.LocationID = "global"
		}
	}
	if p.KeyRingID == "" {
		p.KeyRingID = os.Getenv("GCP_KMS_KEYRING")
	}
	if p.CryptoKeyID == "" {
		p.CryptoKeyID = os.Getenv("GCP_KMS_KEY")
	}

	if p.ProjectID == "" || p.KeyRingID == "" || p.CryptoKeyID == "" {
		return "", fmt.Errorf("hsm/gcp: ProjectID, KeyRingID, and CryptoKeyID are required")
	}

	ciphertextB64 := os.Getenv("ZAPDB_ENCRYPTED_PASSWORD")
	if ciphertextB64 == "" {
		return "", fmt.Errorf("hsm/gcp: ZAPDB_ENCRYPTED_PASSWORD env var is empty")
	}

	accessToken, err := getGCPAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("hsm/gcp: failed to get access token: %w", err)
	}

	endpoint := fmt.Sprintf(
		"https://cloudkms.googleapis.com/v1/projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s:decrypt",
		url.PathEscape(p.ProjectID),
		url.PathEscape(p.LocationID),
		url.PathEscape(p.KeyRingID),
		url.PathEscape(p.CryptoKeyID),
	)

	reqBody, _ := json.Marshal(map[string]string{"ciphertext": ciphertextB64})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return "", fmt.Errorf("hsm/gcp: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hsm/gcp: KMS request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hsm/gcp: KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("hsm/gcp: failed to parse KMS response: %w", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(result.Plaintext)
	if err != nil {
		return "", fmt.Errorf("hsm/gcp: failed to decode plaintext: %w", err)
	}
	return string(plaintext), nil
}

// ---------------------------------------------------------------------------
// Azure Key Vault Password Provider
// ---------------------------------------------------------------------------

// AzureKVProvider decrypts/unwraps a key using Azure Key Vault.
type AzureKVProvider struct {
	VaultURL   string
	KeyName    string
	KeyVersion string
}

func (p *AzureKVProvider) GetPassword(ctx context.Context, keyID string) (string, error) {
	if keyID != "" {
		parts := strings.Split(keyID, "/")
		switch len(parts) {
		case 3:
			p.VaultURL = parts[0]
			p.KeyName = parts[1]
			p.KeyVersion = parts[2]
		case 2:
			p.KeyName = parts[0]
			p.KeyVersion = parts[1]
		case 1:
			p.KeyName = parts[0]
		}
	}

	if p.VaultURL == "" {
		p.VaultURL = os.Getenv("AZURE_VAULT_URL")
	}
	if p.KeyName == "" {
		p.KeyName = os.Getenv("AZURE_KEY_NAME")
	}
	if p.KeyVersion == "" {
		p.KeyVersion = os.Getenv("AZURE_KEY_VERSION")
	}

	if p.VaultURL == "" || p.KeyName == "" {
		return "", fmt.Errorf("hsm/azure: VaultURL and KeyName are required")
	}

	ciphertextB64 := os.Getenv("ZAPDB_ENCRYPTED_PASSWORD")
	if ciphertextB64 == "" {
		return "", fmt.Errorf("hsm/azure: ZAPDB_ENCRYPTED_PASSWORD env var is empty")
	}

	accessToken, err := getAzureMSIToken(ctx)
	if err != nil {
		return "", fmt.Errorf("hsm/azure: failed to get MSI token: %w", err)
	}

	vaultURL := strings.TrimRight(p.VaultURL, "/")
	keyPath := fmt.Sprintf("%s/keys/%s", vaultURL, p.KeyName)
	if p.KeyVersion != "" {
		keyPath += "/" + p.KeyVersion
	}
	endpoint := keyPath + "/unwrapkey?api-version=7.4"

	reqBody, _ := json.Marshal(map[string]string{
		"alg":   "RSA-OAEP-256",
		"value": ciphertextB64,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return "", fmt.Errorf("hsm/azure: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hsm/azure: Key Vault request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hsm/azure: Key Vault returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("hsm/azure: failed to parse Key Vault response: %w", err)
	}

	plaintext, err := base64.RawURLEncoding.DecodeString(result.Value)
	if err != nil {
		return "", fmt.Errorf("hsm/azure: failed to decode plaintext: %w", err)
	}
	return string(plaintext), nil
}

// ---------------------------------------------------------------------------
// Env Provider (development / local)
// ---------------------------------------------------------------------------

// EnvProvider reads a password directly from an environment variable.
type EnvProvider struct {
	EnvVar string // defaults to "LUX_MPC_PASSWORD"
}

func (p *EnvProvider) GetPassword(_ context.Context, _ string) (string, error) {
	envVar := p.EnvVar
	if envVar == "" {
		envVar = "LUX_MPC_PASSWORD"
	}
	password := os.Getenv(envVar)
	if password == "" {
		password = os.Getenv("ZAPDB_PASSWORD")
	}
	if password == "" {
		return "", fmt.Errorf("hsm/env: environment variable %s is not set", envVar)
	}
	return password, nil
}

// ---------------------------------------------------------------------------
// File Provider
// ---------------------------------------------------------------------------

// FileProvider reads a password from a file on disk (K8s secrets, Docker secrets).
type FileProvider struct {
	Path string
}

func (p *FileProvider) GetPassword(_ context.Context, keyID string) (string, error) {
	path := p.Path
	if path == "" && keyID != "" {
		path = keyID
	}
	if path == "" {
		path = os.Getenv("MPC_PASSWORD_FILE")
	}
	if path == "" {
		return "", fmt.Errorf("hsm/file: no file path configured")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hsm/file: failed to read password file %s: %w", path, err)
	}
	password := strings.TrimRight(string(data), "\n\r")
	if password == "" {
		return "", fmt.Errorf("hsm/file: password file %s is empty", path)
	}
	return password, nil
}
