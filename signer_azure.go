package hsm

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AzureKVSigner signs messages using Azure Key Vault asymmetric keys.
// KeyID format: "https://{vault}.vault.azure.net/keys/{key-name}/{version}"
// or just "{key-name}" if VaultURL is set.
type AzureKVSigner struct {
	VaultURL string // e.g. "https://my-vault.vault.azure.net"
}

func (s *AzureKVSigner) Provider() string { return "azure" }

func (s *AzureKVSigner) vaultURL() string {
	if s.VaultURL != "" {
		return strings.TrimRight(s.VaultURL, "/")
	}
	return strings.TrimRight(os.Getenv("AZURE_VAULT_URL"), "/")
}

func (s *AzureKVSigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	vaultURL := s.vaultURL()
	if vaultURL == "" {
		return nil, fmt.Errorf("hsm/azure-sign: AZURE_VAULT_URL not configured")
	}

	accessToken, err := getAzureMSIToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("hsm/azure-sign: failed to get MSI token: %w", err)
	}

	digest := sha256.Sum256(message)

	// Azure Key Vault Sign API
	endpoint := fmt.Sprintf("%s/keys/%s/sign?api-version=7.4", vaultURL, keyID)
	reqBody, _ := json.Marshal(map[string]string{
		"alg":   "ES256",
		"value": base64.RawURLEncoding.EncodeToString(digest[:]),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("hsm/azure-sign: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/azure-sign: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm/azure-sign: Key Vault returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("hsm/azure-sign: failed to parse response: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(result.Value)
	if err != nil {
		return nil, fmt.Errorf("hsm/azure-sign: failed to decode signature: %w", err)
	}
	return sig, nil
}

func (s *AzureKVSigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	vaultURL := s.vaultURL()
	if vaultURL == "" {
		return false, fmt.Errorf("hsm/azure-verify: AZURE_VAULT_URL not configured")
	}

	accessToken, err := getAzureMSIToken(ctx)
	if err != nil {
		return false, fmt.Errorf("hsm/azure-verify: failed to get MSI token: %w", err)
	}

	digest := sha256.Sum256(message)

	endpoint := fmt.Sprintf("%s/keys/%s/verify?api-version=7.4", vaultURL, keyID)
	reqBody, _ := json.Marshal(map[string]string{
		"alg":    "ES256",
		"digest": base64.RawURLEncoding.EncodeToString(digest[:]),
		"value":  base64.RawURLEncoding.EncodeToString(signature),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return false, fmt.Errorf("hsm/azure-verify: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("hsm/azure-verify: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hsm/azure-verify: Key Vault returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Value bool `json:"value"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return false, fmt.Errorf("hsm/azure-verify: failed to parse response: %w", err)
	}
	return result.Value, nil
}
