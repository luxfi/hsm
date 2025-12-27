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

// ZymbitSigner signs messages using a local Zymbit SCM device.
// KeyID is the slot number (e.g., "0", "1").
// Communicates with the Zymbit REST API at localhost:6789.
type ZymbitSigner struct {
	APIAddr string // defaults to "http://localhost:6789"
}

func (s *ZymbitSigner) Provider() string { return "zymbit" }

func (s *ZymbitSigner) apiAddr() string {
	if s.APIAddr != "" {
		return s.APIAddr
	}
	return "http://localhost:6789"
}

func (s *ZymbitSigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"slot":   keyID,
		"digest": base64.StdEncoding.EncodeToString(digest[:]),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiAddr()+"/sign", strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit-sign: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit-sign: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm/zymbit-sign: returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("hsm/zymbit-sign: failed to parse response: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit-sign: failed to decode signature: %w", err)
	}
	return sig, nil
}

func (s *ZymbitSigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	digest := sha256.Sum256(message)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"slot":      keyID,
		"digest":    base64.StdEncoding.EncodeToString(digest[:]),
		"signature": base64.StdEncoding.EncodeToString(signature),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiAddr()+"/verify", strings.NewReader(string(reqBody)))
	if err != nil {
		return false, fmt.Errorf("hsm/zymbit-verify: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("hsm/zymbit-verify: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hsm/zymbit-verify: returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return false, fmt.Errorf("hsm/zymbit-verify: failed to parse response: %w", err)
	}
	return result.Valid, nil
}
