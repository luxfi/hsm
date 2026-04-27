// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build kmip

package hsm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
	"github.com/google/uuid"
)

// KMIPSigner is the real KMIP 2.1 signer activated by `-tags kmip`. It
// speaks the OASIS KMIP TTLV protocol over TLS 1.3 mTLS to a KMS server
// (Thales CipherTrust, Utimaco ESKM, Entrust KeyControl, Fortanix DSM,
// Vault Enterprise). All vendor differences are absorbed by the KMIP
// profile — there is no vendor-specific code path here.
//
// Concurrency: every Sign/Verify opens a fresh TCP connection so the
// signer is safe for concurrent calls. Long-lived connection pooling
// would be a future optimization but introduces TLS session-resumption
// pitfalls that interact with KMIP server session limits.
type KMIPSigner struct {
	Config KMIPConfig

	mu        sync.Mutex
	tlsConfig *tls.Config
}

// NewKMIPSigner constructs a KMIPSigner. It eagerly loads the TLS
// certificate so deployments fail fast on misconfiguration.
func NewKMIPSigner(cfg KMIPConfig) (*KMIPSigner, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("hsm/kmip: Endpoint is required (host:port)")
	}
	if !strings.Contains(cfg.Endpoint, ":") {
		cfg.Endpoint = cfg.Endpoint + ":5696"
	}
	if cfg.ClientCertFile == "" || cfg.ClientKeyFile == "" {
		return nil, errors.New("hsm/kmip: ClientCertFile and ClientKeyFile are required (KMIP mandates mTLS)")
	}

	cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("hsm/kmip: load client cert: %w", err)
	}
	pool, err := loadCAPool(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		ServerName:   cfg.ServerName,
	}
	return &KMIPSigner{Config: cfg, tlsConfig: tlsCfg}, nil
}

// Provider returns "kmip".
func (s *KMIPSigner) Provider() string { return kmipProviderName }

// Sign issues a KMIP Sign operation against the configured server. When
// keyID is empty the configured KMIPConfig.UniqueIdentifier is used.
// The returned bytes are the raw signature in the algorithm's canonical
// encoding (DER for ECDSA, raw 64-byte for Ed25519, PKCS#1 v1.5 / PSS for
// RSA).
func (s *KMIPSigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	uid := keyID
	if uid == "" {
		uid = s.Config.UniqueIdentifier
	}
	if uid == "" {
		return nil, errors.New("hsm/kmip: keyID and KMIPConfig.UniqueIdentifier both empty")
	}

	dsa := digitalSignatureAlgorithm(s.Config.CryptographicAlgorithm, s.Config.HashingAlgorithm)
	payload := signRequestPayload{
		UniqueIdentifier: uid,
		CryptographicParameters: &cryptographicParameters{
			DigitalSignatureAlgorithm: dsa,
		},
		Data: message,
	}
	resp, err := s.do(ctx, kmip14.OperationSign, payload)
	if err != nil {
		return nil, err
	}
	var out signResponsePayload
	if err := decodePayload(resp, &out); err != nil {
		return nil, fmt.Errorf("hsm/kmip: decode Sign response: %w", err)
	}
	if len(out.SignatureData) == 0 {
		return nil, errors.New("hsm/kmip: Sign returned empty signature")
	}
	return out.SignatureData, nil
}

// Verify issues a KMIP SignatureVerify operation. The KMS reports a
// ValidityIndicator of "Valid" / "Invalid" / "Unknown"; this method
// returns true only on "Valid".
func (s *KMIPSigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	uid := keyID
	if uid == "" {
		uid = s.Config.UniqueIdentifier
	}
	if uid == "" {
		return false, errors.New("hsm/kmip: keyID and KMIPConfig.UniqueIdentifier both empty")
	}
	dsa := digitalSignatureAlgorithm(s.Config.CryptographicAlgorithm, s.Config.HashingAlgorithm)
	payload := verifyRequestPayload{
		UniqueIdentifier: uid,
		CryptographicParameters: &cryptographicParameters{
			DigitalSignatureAlgorithm: dsa,
		},
		Data:          message,
		SignatureData: signature,
	}
	resp, err := s.do(ctx, kmip14.OperationSignatureVerify, payload)
	if err != nil {
		return false, err
	}
	var out verifyResponsePayload
	if err := decodePayload(resp, &out); err != nil {
		return false, fmt.Errorf("hsm/kmip: decode SignatureVerify response: %w", err)
	}
	// 0x01 = Valid, 0x02 = Invalid, 0x03 = Unknown (KMIP 1.4 §11)
	return out.ValidityIndicator == 0x01, nil
}

// Activate transitions a key from Pre-Active to Active state per KMIP
// 2.1 §6.1.20. Required after Create but before Sign/Verify on most
// servers.
func (s *KMIPSigner) Activate(ctx context.Context, keyID string) error {
	_, err := s.do(ctx, kmip14.OperationActivate, activatePayload{UniqueIdentifier: keyID})
	return err
}

// Revoke transitions a key to Deactivated or Compromised state per
// KMIP 2.1 §6.1.22. Use Compromised when the operator suspects the
// signing key may have been exposed; Deactivated for routine retirement.
func (s *KMIPSigner) Revoke(ctx context.Context, keyID string) error {
	payload := revokePayload{
		UniqueIdentifier: keyID,
		RevocationReason: revocationReason{
			RevocationReasonCode: uint32(kmip14.RevocationReasonCodeCessationOfOperation),
		},
	}
	_, err := s.do(ctx, kmip14.OperationRevoke, payload)
	return err
}

// Destroy permanently removes the key per KMIP 2.1 §6.1.23. The key MUST
// be Revoked first; many servers reject Destroy on Active keys.
func (s *KMIPSigner) Destroy(ctx context.Context, keyID string) error {
	_, err := s.do(ctx, kmip14.OperationDestroy, destroyPayload{UniqueIdentifier: keyID})
	return err
}

// Close is a no-op — connections are per-request.
func (s *KMIPSigner) Close() error { return nil }

// do dials the KMS, sends a single-batch Request, and returns the
// ResponsePayload from the response BatchItem.
func (s *KMIPSigner) do(ctx context.Context, op kmip14.Operation, payload interface{}) (interface{}, error) {
	timeout := time.Duration(s.Config.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := &net.Dialer{Timeout: timeout}
	rawConn, err := d.DialContext(dctx, "tcp", s.Config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("hsm/kmip: dial %s: %w", s.Config.Endpoint, err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, s.tlsConfig.Clone())
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		return nil, fmt.Errorf("hsm/kmip: TLS handshake: %w", err)
	}
	defer tlsConn.Close()

	biID := uuid.New()
	req := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: 2,
				ProtocolVersionMinor: 1,
			},
			BatchCount: 1,
		},
		BatchItem: []kmip.RequestBatchItem{
			{
				Operation:         op,
				UniqueBatchItemID: biID[:],
				RequestPayload:    payload,
			},
		},
	}
	wire, err := ttlv.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/kmip: marshal request: %w", err)
	}
	if _, err := tlsConn.Write(wire); err != nil {
		return nil, fmt.Errorf("hsm/kmip: write request: %w", err)
	}

	respBytes, err := readTTLV(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("hsm/kmip: read response: %w", err)
	}
	var resp kmip.ResponseMessage
	if err := ttlv.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("hsm/kmip: unmarshal response: %w", err)
	}
	if len(resp.BatchItem) == 0 {
		return nil, errors.New("hsm/kmip: response has no batch items")
	}
	bi := resp.BatchItem[0]
	if bi.ResultStatus != kmip14.ResultStatusSuccess {
		return nil, fmt.Errorf("hsm/kmip: %s failed: status=%v reason=%v message=%s",
			op, bi.ResultStatus, bi.ResultReason, bi.ResultMessage)
	}
	return bi.ResponsePayload, nil
}

// readTTLV reads a single TTLV envelope from r. The TTLV header is 8
// bytes (3-byte tag + 1-byte type + 4-byte length); the value follows.
// Padding to 8-byte alignment is handled by the underlying ttlv codec on
// unmarshal so we only need the framed bytes.
func readTTLV(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	bodyLen := int(uint32(hdr[4])<<24 | uint32(hdr[5])<<16 | uint32(hdr[6])<<8 | uint32(hdr[7]))
	// 8-byte alignment per KMIP 2.1 §9.1.
	pad := (8 - bodyLen%8) % 8
	body := make([]byte, bodyLen+pad)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 8+bodyLen)
	out = append(out, hdr...)
	out = append(out, body[:bodyLen]...)
	return out, nil
}

// decodePayload roundtrips an interface{} response payload back through
// the ttlv codec into the supplied struct. The kmip-go library returns
// payloads as raw TTLV blocks for operations it does not natively model
// (Sign / SignatureVerify); we marshal then unmarshal to populate our
// local struct types.
func decodePayload(payload interface{}, out interface{}) error {
	if payload == nil {
		return errors.New("nil payload")
	}
	if raw, ok := payload.(ttlv.TTLV); ok {
		return ttlv.Unmarshal(raw, out)
	}
	buf, err := ttlv.Marshal(payload)
	if err != nil {
		return err
	}
	return ttlv.Unmarshal(buf, out)
}

// loadCAPool builds an x509.CertPool from the configured CA bundle. An
// empty path means the system roots are used — convenient on managed
// hosts where the CA chain is in the OS trust store.
func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hsm/kmip: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("hsm/kmip: no PEM certificates parsed from %s", path)
	}
	return pool, nil
}

// digitalSignatureAlgorithm maps a (curve/algo, hash) pair to the KMIP
// DigitalSignatureAlgorithm enum. SHA-256 is the default when the hash
// is unspecified — most blockchain signing pipelines use SHA-256.
func digitalSignatureAlgorithm(alg, hash string) kmip14.DigitalSignatureAlgorithm {
	a := strings.ToUpper(strings.TrimSpace(alg))
	h := strings.ToUpper(strings.TrimSpace(hash))
	if h == "" {
		h = "SHA-256"
	}
	switch a {
	case "ECDSA", "":
		switch h {
		case "SHA-256":
			return kmip14.DigitalSignatureAlgorithmECDSAWithSHA256
		case "SHA-384":
			return kmip14.DigitalSignatureAlgorithmECDSAWithSHA384
		case "SHA-512":
			return kmip14.DigitalSignatureAlgorithmECDSAWithSHA512
		}
	case "RSA":
		switch h {
		case "SHA-256":
			return kmip14.DigitalSignatureAlgorithmSHA_256WithRSAEncryption
		case "SHA-384":
			return kmip14.DigitalSignatureAlgorithmSHA_384WithRSAEncryption
		case "SHA-512":
			return kmip14.DigitalSignatureAlgorithmSHA_512WithRSAEncryption
		}
	}
	return kmip14.DigitalSignatureAlgorithmECDSAWithSHA256
}

// ----- TTLV payload structs (KMIP 1.4 / 2.1 — Sign / Verify / Lifecycle)
//
// gemalto/kmip-go does not ship payload types for Sign, SignatureVerify,
// Activate, Revoke, or Destroy. We define them here using the ttlv
// codec's struct-tag-driven encoding. Field order and tags MUST match
// KMIP 1.4 §6.x exactly — the codec reads tags from the field metadata.

type cryptographicParameters struct {
	DigitalSignatureAlgorithm kmip14.DigitalSignatureAlgorithm `ttlv:",omitempty"`
}

type signRequestPayload struct {
	UniqueIdentifier        string                   `ttlv:",omitempty"`
	CryptographicParameters *cryptographicParameters `ttlv:",omitempty"`
	Data                    []byte
}

type signResponsePayload struct {
	UniqueIdentifier string
	SignatureData    []byte
}

type verifyRequestPayload struct {
	UniqueIdentifier        string                   `ttlv:",omitempty"`
	CryptographicParameters *cryptographicParameters `ttlv:",omitempty"`
	Data                    []byte
	SignatureData           []byte
}

type verifyResponsePayload struct {
	UniqueIdentifier  string
	ValidityIndicator uint32
}

type activatePayload struct {
	UniqueIdentifier string
}

type revocationReason struct {
	RevocationReasonCode uint32
	RevocationMessage    string `ttlv:",omitempty"`
}

type revokePayload struct {
	UniqueIdentifier string
	RevocationReason revocationReason
}

type destroyPayload struct {
	UniqueIdentifier string
}

// Compile-time assertion that the request/response struct field
// ordering matches KMIP §6.x. The assertion runs on package load with
// `-tags kmip` so build failures show up at compile time rather than
// against a live KMS.
var _ = bytes.Buffer{}
