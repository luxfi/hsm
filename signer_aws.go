package hsm

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AWSKMSSigner signs messages using AWS KMS asymmetric keys.
// KeyID should be a KMS key ARN or alias configured for SIGN_VERIFY usage.
type AWSKMSSigner struct {
	Region string
}

func (s *AWSKMSSigner) Provider() string { return "aws" }

func (s *AWSKMSSigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	region := s.Region
	if region == "" {
		region = "us-east-1"
	}

	digest := sha256.Sum256(message)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"KeyId":            keyID,
		"Message":          base64.StdEncoding.EncodeToString(digest[:]),
		"MessageType":      "DIGEST",
		"SigningAlgorithm": "ECDSA_SHA_256",
	})

	endpoint := fmt.Sprintf("https://kms.%s.amazonaws.com/", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Sign")

	if err := signAWSRequest(req, reqBody, region, "kms"); err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: failed to sign request: %w", err)
	}

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm/aws-sign: KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Signature string `json:"Signature"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: failed to parse response: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: failed to decode signature: %w", err)
	}

	return sig, nil
}

func (s *AWSKMSSigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	region := s.Region
	if region == "" {
		region = "us-east-1"
	}

	digest := sha256.Sum256(message)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"KeyId":            keyID,
		"Message":          base64.StdEncoding.EncodeToString(digest[:]),
		"MessageType":      "DIGEST",
		"Signature":        base64.StdEncoding.EncodeToString(signature),
		"SigningAlgorithm": "ECDSA_SHA_256",
	})

	endpoint := fmt.Sprintf("https://kms.%s.amazonaws.com/", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return false, fmt.Errorf("hsm/aws-verify: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Verify")

	if err := signAWSRequest(req, reqBody, region, "kms"); err != nil {
		return false, fmt.Errorf("hsm/aws-verify: failed to sign request: %w", err)
	}

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("hsm/aws-verify: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hsm/aws-verify: KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		SignatureValid bool `json:"SignatureValid"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return false, fmt.Errorf("hsm/aws-verify: failed to parse response: %w", err)
	}

	return result.SignatureValid, nil
}
