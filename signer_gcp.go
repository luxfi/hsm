package hsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GCPKMSSigner signs messages using Google Cloud KMS asymmetric keys.
// KeyID should be the full resource name:
//
//	projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}
type GCPKMSSigner struct{}

func (s *GCPKMSSigner) Provider() string { return "gcp" }

func (s *GCPKMSSigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	accessToken, err := getGCPAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: failed to get access token: %w", err)
	}

	digest := sha256.Sum256(message)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"digest": map[string]string{
			"sha256": base64.StdEncoding.EncodeToString(digest[:]),
		},
	})

	endpoint := fmt.Sprintf(
		"https://cloudkms.googleapis.com/v1/%s:asymmetricSign",
		url.PathEscape(keyID),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm/gcp-sign: Cloud KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: failed to parse response: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: failed to decode signature: %w", err)
	}

	return sig, nil
}

func (s *GCPKMSSigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	// GCP Cloud KMS doesn't have a Verify API for asymmetric signing —
	// verification must be done locally using the public key.
	accessToken, err := getGCPAccessToken(ctx)
	if err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to get access token: %w", err)
	}

	endpoint := fmt.Sprintf(
		"https://cloudkms.googleapis.com/v1/%s:getPublicKey",
		url.PathEscape(keyID),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hsm/gcp-verify: Cloud KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var pubKeyResp struct {
		Pem string `json:"pem"`
	}
	if err := json.Unmarshal(respBody, &pubKeyResp); err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to parse public key: %w", err)
	}

	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to decode PEM public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("hsm/gcp-verify: public key is not ECDSA")
	}

	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(ecdsaPub, digest[:], signature), nil
}
