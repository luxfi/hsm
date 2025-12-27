package hsm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// AWS Signature V4 (shared by password providers and signers)
// ---------------------------------------------------------------------------

func signAWSRequest(req *http.Request, body []byte, region, service string) error {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	if accessKey == "" || secretKey == "" {
		creds, err := getEC2RoleCredentials()
		if err != nil {
			return fmt.Errorf("no AWS credentials: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or use an EC2 instance role: %w", err)
		}
		accessKey = creds.accessKeyID
		secretKey = creds.secretAccessKey
		sessionToken = creds.sessionToken
	}

	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	signedHeaderKeys := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if sessionToken != "" {
		signedHeaderKeys = append(signedHeaderKeys, "x-amz-security-token")
	}
	sort.Strings(signedHeaderKeys)
	signedHeaders := strings.Join(signedHeaderKeys, ";")

	var canonicalHeaders strings.Builder
	for _, h := range signedHeaderKeys {
		var val string
		switch h {
		case "host":
			val = req.URL.Host
		default:
			val = req.Header.Get(h)
		}
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(val))
		canonicalHeaders.WriteString("\n")
	}

	payloadHash := sha256Hex(body)
	canonicalRequest := strings.Join([]string{
		req.Method, canonicalURI, "",
		canonicalHeaders.String(), signedHeaders, payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", datestamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credentialScope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(datestamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature,
	))
	return nil
}

type ec2Creds struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

func getEC2RoleCredentials() (*ec2Creds, error) {
	client := &http.Client{Timeout: 2 * time.Second}

	tokenReq, _ := http.NewRequest(http.MethodPut, "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("IMDS token request failed: %w", err)
	}
	defer tokenResp.Body.Close()
	tokenBytes, _ := io.ReadAll(tokenResp.Body)
	token := strings.TrimSpace(string(tokenBytes))

	roleReq, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	roleReq.Header.Set("X-aws-ec2-metadata-token", token)
	roleResp, err := client.Do(roleReq)
	if err != nil {
		return nil, fmt.Errorf("IMDS role request failed: %w", err)
	}
	defer roleResp.Body.Close()
	roleBytes, _ := io.ReadAll(roleResp.Body)
	roleName := strings.TrimSpace(string(roleBytes))
	if roleName == "" {
		return nil, fmt.Errorf("no IAM role attached to instance")
	}

	credReq, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/iam/security-credentials/"+roleName, nil)
	credReq.Header.Set("X-aws-ec2-metadata-token", token)
	credResp, err := client.Do(credReq)
	if err != nil {
		return nil, fmt.Errorf("IMDS credential request failed: %w", err)
	}
	defer credResp.Body.Close()
	credBytes, _ := io.ReadAll(credResp.Body)

	var result struct {
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.Unmarshal(credBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse IMDS credentials: %w", err)
	}
	return &ec2Creds{
		accessKeyID:     result.AccessKeyId,
		secretAccessKey: result.SecretAccessKey,
		sessionToken:    result.Token,
	}, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// GCP Access Token (shared by password providers and signers)
// ---------------------------------------------------------------------------

func getGCPAccessToken(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata request failed (not running on GCE/GKE?): %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token from metadata")
	}
	return tokenResp.AccessToken, nil
}

// ---------------------------------------------------------------------------
// Azure MSI Token (shared by password providers and signers)
// ---------------------------------------------------------------------------

func getAzureMSIToken(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	msiEndpoint := os.Getenv("IDENTITY_ENDPOINT")
	msiHeader := os.Getenv("IDENTITY_HEADER")

	var req *http.Request
	if msiEndpoint != "" {
		tokenURL := fmt.Sprintf("%s?api-version=2019-08-01&resource=https://vault.azure.net", msiEndpoint)
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
		req.Header.Set("X-IDENTITY-HEADER", msiHeader)
	} else {
		tokenURL := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
		req.Header.Set("Metadata", "true")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("MSI token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MSI returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse MSI token: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token from MSI")
	}
	return tokenResp.AccessToken, nil
}

// ---------------------------------------------------------------------------
// GCP KMS Key Resource Name Parser
// ---------------------------------------------------------------------------

func parseGCPKeyResourceName(name string) map[string]string {
	parts := strings.Split(name, "/")
	if len(parts) < 8 {
		return nil
	}
	result := make(map[string]string)
	for i := 0; i < len(parts)-1; i += 2 {
		key := parts[i]
		val := parts[i+1]
		switch key {
		case "projects":
			result["project"] = val
		case "locations":
			result["location"] = val
		case "keyRings":
			result["keyRing"] = val
		case "cryptoKeys":
			result["cryptoKey"] = val
		}
	}
	return result
}
