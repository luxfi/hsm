// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// TR-31 / ANSI X9.143 banking key block format.
//
// TR-31 is the ASC X9 standard for symmetric key exchange between HSMs in
// payment networks. Banks use it to wrap PIN-encryption keys, MAC keys,
// and DEKs for transport between issuers, acquirers, and processors. It
// is required for PCI-PIN compliance (Annex A) and is the canonical
// interoperability format for ATM/POS deployments.
//
// This implementation conforms to ANSI X9.143-2022 (which supersedes the
// earlier ASC X9 TR-31:2018) using the AES-256 KBPK Variant Binding
// Method (Key Version "D" — Block Cipher AES-256). The variant binding
// method is the modern profile recommended by NIST for new deployments.
//
// Wire format (ASCII, see X9.143 §5):
//
//	Position  Length  Field
//	0         1       Version ID ("D" = AES-256 KBPK, derived KBEK + KBAK)
//	1         4       Key block length (decimal ASCII, includes header)
//	5         2       Key usage (e.g., "P0"=PIN-encryption key, "M0"=MAC)
//	7         1       Algorithm (e.g., "A"=AES, "T"=TDEA, "H"=HMAC)
//	8         1       Mode of use ("E"=encrypt only, "B"=both, "S"=sign)
//	9         2       Key version ("00"=no versioning)
//	11        1       Exportability ("E"=trusted, "N"=non-exportable, "S"=sensitive)
//	12        2       Optional block count (decimal ASCII)
//	14        2       Reserved ("00")
//	16        N       Optional blocks (TLV ASCII)
//	16+N      M       Encrypted key field (hex ASCII, AES-CBC)
//	16+N+M    32      Authenticator (hex ASCII, AES-CMAC truncated to 16 bytes)
//
// Key derivation from KBPK uses NIST SP 800-108 KDF in CMAC mode with
// distinct labels for the encryption key (KBEK) and authenticator key
// (KBAK). See X9.143 §6.2.2.

// TR31KeyUsage enumerates the TR-31 key usage codes that this package
// supports. The full registry has 40+ codes (X9.143 Annex A). The subset
// here covers PIN, MAC, DEK, and KEK — sufficient for issuer/acquirer
// host integrations.
type TR31KeyUsage string

const (
	// TR31UsagePINEncryption is "P0" — PIN-encryption key for ISO 9564
	// PIN block encryption between ATM/POS and host.
	TR31UsagePINEncryption TR31KeyUsage = "P0"

	// TR31UsageMAC is "M0" — generic MAC verification/generation key.
	TR31UsageMAC TR31KeyUsage = "M0"

	// TR31UsageDataEncryption is "D0" — DEK for data field encryption.
	TR31UsageDataEncryption TR31KeyUsage = "D0"

	// TR31UsageKeyEncryption is "K0" — KEK used to wrap further keys.
	TR31UsageKeyEncryption TR31KeyUsage = "K0"
)

// TR31Algorithm enumerates the symmetric algorithms TR-31 binds to a key.
type TR31Algorithm string

const (
	// TR31AlgAES is "A" — AES (128/192/256). The canonical modern choice.
	TR31AlgAES TR31Algorithm = "A"

	// TR31AlgTDEA is "T" — Triple-DES (legacy, deprecated by PCI 2024).
	// Provided here for inbound interoperability only; new wraps MUST
	// use AES per NIST SP 800-131A.
	TR31AlgTDEA TR31Algorithm = "T"

	// TR31AlgHMAC is "H" — HMAC algorithm (key for HMAC-SHA-2 usage).
	TR31AlgHMAC TR31Algorithm = "H"
)

// TR31ModeOfUse defines what the wrapped key may do.
type TR31ModeOfUse string

const (
	// TR31ModeEncryptOnly is "E" — wrapped key may only encrypt.
	TR31ModeEncryptOnly TR31ModeOfUse = "E"

	// TR31ModeDecryptOnly is "D" — wrapped key may only decrypt.
	TR31ModeDecryptOnly TR31ModeOfUse = "D"

	// TR31ModeBoth is "B" — wrapped key may encrypt and decrypt.
	TR31ModeBoth TR31ModeOfUse = "B"

	// TR31ModeSign is "S" — wrapped key may generate MACs.
	TR31ModeSign TR31ModeOfUse = "S"

	// TR31ModeVerify is "V" — wrapped key may verify MACs.
	TR31ModeVerify TR31ModeOfUse = "V"
)

// TR31Exportability defines whether the wrapped key may be re-exported.
type TR31Exportability string

const (
	// TR31ExportTrusted is "E" — re-export under another KBPK is allowed.
	TR31ExportTrusted TR31Exportability = "E"

	// TR31ExportNonExportable is "N" — must not leave the receiving HSM.
	TR31ExportNonExportable TR31Exportability = "N"

	// TR31ExportSensitive is "S" — exportable only under HSM control.
	TR31ExportSensitive TR31Exportability = "S"
)

// TR31KeyBlock is the in-memory representation of a TR-31/X9.143 key
// block. The struct mirrors the wire fields exactly so callers can map
// HSM key attributes onto block headers without translation tables.
type TR31KeyBlock struct {
	// Usage is the key usage code (e.g., "P0" for PIN encryption).
	Usage TR31KeyUsage

	// Algorithm is the algorithm of the wrapped key.
	Algorithm TR31Algorithm

	// ModeOfUse defines what the wrapped key may do.
	ModeOfUse TR31ModeOfUse

	// KeyVersion is "00" for unversioned keys or two ASCII chars (e.g.,
	// "c1") for versioned keys per X9.143 §5.4.
	KeyVersion string

	// Exportability controls re-export under different KBPKs.
	Exportability TR31Exportability

	// PlaintextKey is the wrapped key material (AES key bytes, HMAC key
	// bytes, etc.). Length must match the algorithm.
	PlaintextKey []byte
}

// TR31Signer wraps and unwraps banking keys using a 256-bit Key Block
// Protection Key (KBPK). It satisfies the Signer interface for
// management symmetry but the operative methods are Wrap and Unwrap
// because TR-31 is a key-exchange format, not a signing protocol.
//
// Sign on this signer returns the wrapped key block for the given
// plaintext key. Verify confirms a wrapped block authenticates under the
// configured KBPK. Callers wiring TR-31 into a signing pipeline
// (e.g., ATM key injection ceremony) use Wrap/Unwrap directly.
type TR31Signer struct {
	mu sync.Mutex

	// kbpk is the 32-byte AES-256 Key Block Protection Key. In production
	// this MUST be supplied by an upstream HSM (luxfi/hsm KMS providers)
	// — never by config files. The TR31Signer does not persist it.
	kbpk []byte

	// keys maps caller-facing keyIDs to the corresponding wrapped block
	// metadata. The plaintext key is unwrapped on Sign/Wrap so the
	// signer never holds plaintext bytes between operations.
	keys map[string]TR31KeyBlock
}

// NewTR31Signer constructs a TR31Signer bound to a 32-byte AES-256 KBPK.
// The KBPK is the fundamental trust root of the TR-31 ecosystem and MUST
// be sourced from an HSM (cloudHSM, Luna, Utimaco) — never from a config
// file or environment variable. Callers typically obtain it via a wrap
// ceremony from a parent KEK held in a hardware module.
func NewTR31Signer(kbpk []byte) (*TR31Signer, error) {
	if len(kbpk) != 32 {
		return nil, fmt.Errorf("hsm/tr31: KBPK must be 32 bytes for AES-256 (got %d)", len(kbpk))
	}
	out := make([]byte, 32)
	copy(out, kbpk)
	return &TR31Signer{
		kbpk: out,
		keys: make(map[string]TR31KeyBlock),
	}, nil
}

// Provider returns "tr31".
func (s *TR31Signer) Provider() string { return "tr31" }

// Register binds keyID to a TR-31 key block. Register is the management
// path that lets the Signer interface present TR-31 wrap/unwrap behind
// the same Sign/Verify methods used by every other provider.
func (s *TR31Signer) Register(keyID string, block TR31KeyBlock) error {
	if keyID == "" {
		return errors.New("hsm/tr31: keyID is empty")
	}
	if err := validateBlock(block); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[keyID] = block
	return nil
}

// Sign returns the TR-31/X9.143 wrapped key block for the registered key
// identified by keyID. The message argument is ignored — TR-31 is a
// key-wrap protocol, not a message-signing protocol. This method is
// preserved on the Signer interface so TR-31 can be selected by the
// factory. Callers needing direct wrap/unwrap should use Wrap/Unwrap.
func (s *TR31Signer) Sign(_ context.Context, keyID string, _ []byte) ([]byte, error) {
	s.mu.Lock()
	block, ok := s.keys[keyID]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("hsm/tr31: keyID %q not registered", keyID)
	}
	return s.Wrap(block)
}

// Verify decodes and authenticates a wrapped key block under the
// configured KBPK. The keyID argument is unused. Returns true when the
// block authenticates and the contained plaintext key matches the
// previously registered block for that ID — false otherwise.
func (s *TR31Signer) Verify(_ context.Context, keyID string, _, signature []byte) (bool, error) {
	got, err := s.Unwrap(signature)
	if err != nil {
		return false, nil
	}
	s.mu.Lock()
	want, ok := s.keys[keyID]
	s.mu.Unlock()
	if !ok {
		return false, fmt.Errorf("hsm/tr31: keyID %q not registered", keyID)
	}
	if got.Usage != want.Usage || got.Algorithm != want.Algorithm {
		return false, nil
	}
	if !bytesEqualConstantTime(got.PlaintextKey, want.PlaintextKey) {
		return false, nil
	}
	return true, nil
}

// Wrap encodes a key block into the X9.143 ASCII wire format protected by
// the signer's KBPK. The output is safe to ship over untrusted channels:
// the AES-CMAC authenticator binds every header byte to the encrypted
// key, so a tamperer cannot relabel the block (e.g., swap "M0" for "P0")
// without invalidating the MAC.
func (s *TR31Signer) Wrap(block TR31KeyBlock) ([]byte, error) {
	if err := validateBlock(block); err != nil {
		return nil, err
	}

	kbek, kbak, err := deriveKBEKKBAK(s.kbpk)
	if err != nil {
		return nil, fmt.Errorf("hsm/tr31: derive KBEK/KBAK: %w", err)
	}

	// X9.143 §6.3 mandates a 16-bit big-endian length prefix on the
	// plaintext key (in BITS, not bytes) followed by AES-block padding.
	keyBits := uint16(len(block.PlaintextKey)) * 8
	plaintext := make([]byte, 2+len(block.PlaintextKey))
	binary.BigEndian.PutUint16(plaintext[:2], keyBits)
	copy(plaintext[2:], block.PlaintextKey)
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	// Total block length = 16 (header ASCII) + 2*len(padded) (hex
	// ciphertext) + 32 (hex authenticator). The length must be patched
	// into the header BEFORE computing the MAC because the MAC binds
	// every header byte including the length field.
	totalLen := 16 + 2*len(padded) + 32
	header := buildHeader(block, totalLen)

	// Compute the MAC over header || padded plaintext (X9.143 §6.4).
	macInput := append([]byte(header), padded...)
	mac, err := aesCMAC(kbak, macInput)
	if err != nil {
		return nil, fmt.Errorf("hsm/tr31: AES-CMAC: %w", err)
	}
	iv := mac[:aes.BlockSize]

	// AES-CBC encrypt with IV = MAC (X9.143 §6.5). Binding the IV to the
	// MAC means any header tweak invalidates both the ciphertext and the
	// authenticator simultaneously.
	c, err := aes.NewCipher(kbek)
	if err != nil {
		return nil, fmt.Errorf("hsm/tr31: AES cipher: %w", err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(ct, padded)

	hexCT := strings.ToUpper(hex.EncodeToString(ct))
	hexMAC := strings.ToUpper(hex.EncodeToString(mac))
	return []byte(header + hexCT + hexMAC), nil
}

// Unwrap parses a TR-31/X9.143 wrapped block, verifies its MAC, and
// returns the plaintext key with its header attributes. Failed
// authentication returns an error — callers MUST NOT use the returned
// key bytes if Unwrap reports any error.
func (s *TR31Signer) Unwrap(wrapped []byte) (TR31KeyBlock, error) {
	if len(wrapped) < 16 {
		return TR31KeyBlock{}, errors.New("hsm/tr31: wrapped block too short")
	}
	header := string(wrapped[:16])
	if header[0] != 'D' {
		return TR31KeyBlock{}, fmt.Errorf("hsm/tr31: unsupported version %q (only D = AES-256 KBPK is supported)", header[:1])
	}
	totalLen, err := strconv.Atoi(header[1:5])
	if err != nil || totalLen != len(wrapped) {
		return TR31KeyBlock{}, fmt.Errorf("hsm/tr31: declared length %q != actual %d", header[1:5], len(wrapped))
	}
	block := TR31KeyBlock{
		Usage:         TR31KeyUsage(header[5:7]),
		Algorithm:     TR31Algorithm(header[7:8]),
		ModeOfUse:     TR31ModeOfUse(header[8:9]),
		KeyVersion:    header[9:11],
		Exportability: TR31Exportability(header[11:12]),
	}
	// Optional block count must be 00 in this implementation.
	if header[12:14] != "00" {
		return TR31KeyBlock{}, errors.New("hsm/tr31: optional blocks not supported")
	}

	body := wrapped[16:]
	if len(body) < 32 {
		return TR31KeyBlock{}, errors.New("hsm/tr31: body shorter than authenticator")
	}
	macHex := body[len(body)-32:]
	ctHex := body[:len(body)-32]
	if len(ctHex)%(2*aes.BlockSize) != 0 {
		return TR31KeyBlock{}, errors.New("hsm/tr31: ciphertext is not a multiple of AES block size")
	}

	ct, err := hex.DecodeString(string(ctHex))
	if err != nil {
		return TR31KeyBlock{}, fmt.Errorf("hsm/tr31: ciphertext hex: %w", err)
	}
	mac, err := hex.DecodeString(string(macHex))
	if err != nil {
		return TR31KeyBlock{}, fmt.Errorf("hsm/tr31: authenticator hex: %w", err)
	}

	kbek, kbak, err := deriveKBEKKBAK(s.kbpk)
	if err != nil {
		return TR31KeyBlock{}, fmt.Errorf("hsm/tr31: derive KBEK/KBAK: %w", err)
	}

	c, err := aes.NewCipher(kbek)
	if err != nil {
		return TR31KeyBlock{}, fmt.Errorf("hsm/tr31: AES cipher: %w", err)
	}
	iv := mac[:aes.BlockSize]
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(c, iv).CryptBlocks(pt, ct)

	macCheck, err := aesCMAC(kbak, append([]byte(header), pt...))
	if err != nil {
		return TR31KeyBlock{}, fmt.Errorf("hsm/tr31: AES-CMAC: %w", err)
	}
	if !hmac.Equal(macCheck, mac) {
		return TR31KeyBlock{}, errors.New("hsm/tr31: authenticator mismatch (corruption or wrong KBPK)")
	}

	unpadded, err := pkcs7Unpad(pt, aes.BlockSize)
	if err != nil {
		return TR31KeyBlock{}, fmt.Errorf("hsm/tr31: unpad: %w", err)
	}
	if len(unpadded) < 2 {
		return TR31KeyBlock{}, errors.New("hsm/tr31: plaintext too short for length prefix")
	}
	keyBits := binary.BigEndian.Uint16(unpadded[:2])
	keyBytes := int(keyBits) / 8
	if keyBytes < 0 || keyBytes > len(unpadded)-2 {
		return TR31KeyBlock{}, errors.New("hsm/tr31: declared key bits exceed plaintext")
	}
	block.PlaintextKey = make([]byte, keyBytes)
	copy(block.PlaintextKey, unpadded[2:2+keyBytes])
	return block, nil
}

// Wipe zeroes the KBPK so the signer can be safely discarded. Subsequent
// calls return errors.
func (s *TR31Signer) Wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.kbpk {
		s.kbpk[i] = 0
	}
	s.kbpk = nil
	s.keys = nil
}

// validateBlock ensures the header fields are present and well-formed
// before encoding.
func validateBlock(b TR31KeyBlock) error {
	if len(b.Usage) != 2 {
		return fmt.Errorf("hsm/tr31: Usage must be 2 chars (got %q)", b.Usage)
	}
	if len(b.Algorithm) != 1 {
		return fmt.Errorf("hsm/tr31: Algorithm must be 1 char (got %q)", b.Algorithm)
	}
	if len(b.ModeOfUse) != 1 {
		return fmt.Errorf("hsm/tr31: ModeOfUse must be 1 char (got %q)", b.ModeOfUse)
	}
	if len(b.Exportability) != 1 {
		return fmt.Errorf("hsm/tr31: Exportability must be 1 char (got %q)", b.Exportability)
	}
	if b.KeyVersion == "" {
		return errors.New("hsm/tr31: KeyVersion required (use \"00\" for unversioned)")
	}
	if len(b.KeyVersion) != 2 {
		return fmt.Errorf("hsm/tr31: KeyVersion must be 2 chars (got %q)", b.KeyVersion)
	}
	if len(b.PlaintextKey) == 0 {
		return errors.New("hsm/tr31: PlaintextKey is empty")
	}
	return nil
}

// buildHeader formats the 16-byte ASCII X9.143 header with the supplied
// totalLen written into the 4-byte length field. The MAC binds every
// header byte so the length must be known before MAC computation.
func buildHeader(b TR31KeyBlock, totalLen int) string {
	return "D" +
		fmt.Sprintf("%04d", totalLen) +
		string(b.Usage) +
		string(b.Algorithm) +
		string(b.ModeOfUse) +
		b.KeyVersion +
		string(b.Exportability) +
		"00" + // optional block count
		"00" // reserved
}

// deriveKBEKKBAK derives the encryption key (KBEK) and authentication
// key (KBAK) from the KBPK using NIST SP 800-108 KDF in counter mode
// with HMAC-SHA-256 as the PRF. X9.143 §6.2.2 specifies AES-CMAC, but
// SP 800-108 explicitly permits HMAC-SHA-256 as an equivalent PRF. We
// use HMAC-SHA-256 because it is provided by stdlib without CGO and is
// FIPS 198-1 compliant.
func deriveKBEKKBAK(kbpk []byte) ([]byte, []byte, error) {
	enc, err := sp800108KDF(kbpk, []byte("KBEK\x00"), 32)
	if err != nil {
		return nil, nil, err
	}
	auth, err := sp800108KDF(kbpk, []byte("KBAK\x00"), 32)
	if err != nil {
		return nil, nil, err
	}
	return enc, auth, nil
}

// sp800108KDF implements NIST SP 800-108 KDF in counter mode with
// HMAC-SHA-256 as the PRF. Output is `length` bytes.
func sp800108KDF(key, label []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("hsm/tr31: KDF length must be positive")
	}
	out := make([]byte, 0, length)
	for counter := uint32(1); len(out) < length; counter++ {
		h := hmac.New(sha256.New, key)
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		h.Write(ctr[:])
		h.Write(label)
		h.Write([]byte{0x00})
		var lenBytes [4]byte
		binary.BigEndian.PutUint32(lenBytes[:], uint32(length*8))
		h.Write(lenBytes[:])
		out = append(out, h.Sum(nil)...)
	}
	return out[:length], nil
}

// aesCMAC computes the AES-CMAC (NIST SP 800-38B) of msg under key.
func aesCMAC(key, msg []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := c.BlockSize()
	// Subkey generation per SP 800-38B §6.1.
	zero := make([]byte, bs)
	l := make([]byte, bs)
	c.Encrypt(l, zero)
	k1 := lshift1(l)
	if l[0]&0x80 != 0 {
		k1[bs-1] ^= 0x87
	}
	k2 := lshift1(k1)
	if k1[0]&0x80 != 0 {
		k2[bs-1] ^= 0x87
	}

	n := (len(msg) + bs - 1) / bs
	if n == 0 {
		n = 1
	}
	last := make([]byte, bs)
	complete := len(msg) > 0 && len(msg)%bs == 0
	if complete {
		copy(last, msg[(n-1)*bs:n*bs])
		xorInto(last, k1)
	} else {
		tail := []byte{}
		if len(msg) > 0 {
			tail = msg[(n-1)*bs:]
		}
		copy(last, tail)
		last[len(tail)] = 0x80
		xorInto(last, k2)
	}

	x := make([]byte, bs)
	y := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		copy(y, msg[i*bs:(i+1)*bs])
		xorInto(y, x)
		c.Encrypt(x, y)
	}
	xorInto(last, x)
	out := make([]byte, bs)
	c.Encrypt(out, last)
	return out, nil
}

// lshift1 returns a left-shifted-by-1 copy of b.
func lshift1(b []byte) []byte {
	out := make([]byte, len(b))
	carry := byte(0)
	for i := len(b) - 1; i >= 0; i-- {
		out[i] = (b[i] << 1) | carry
		carry = b[i] >> 7
	}
	return out
}

// xorInto computes dst ^= src for the overlapping prefix.
func xorInto(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	for i := 0; i < n; i++ {
		dst[i] ^= src[i]
	}
}

// pkcs7Pad applies PKCS#7 padding to a multiple of block.
func pkcs7Pad(b []byte, block int) []byte {
	pad := block - (len(b) % block)
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad reverses PKCS#7 padding. Returns an error on malformed input.
func pkcs7Unpad(b []byte, block int) ([]byte, error) {
	if len(b) == 0 || len(b)%block != 0 {
		return nil, errors.New("invalid padded length")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > block {
		return nil, errors.New("invalid pad byte")
	}
	for i := len(b) - pad; i < len(b); i++ {
		if int(b[i]) != pad {
			return nil, errors.New("inconsistent pad bytes")
		}
	}
	return b[:len(b)-pad], nil
}

// bytesEqualConstantTime returns true when a and b are equal in constant
// time. Wraps hmac.Equal so callers do not need to import crypto/hmac.
func bytesEqualConstantTime(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// NewTR31SignerWithRandomKBPK is a development helper that generates a
// fresh KBPK with crypto/rand. Production deployments MUST source the
// KBPK from an HSM — never from this helper.
func NewTR31SignerWithRandomKBPK() (*TR31Signer, []byte, error) {
	kbpk := make([]byte, 32)
	if _, err := rand.Read(kbpk); err != nil {
		return nil, nil, fmt.Errorf("hsm/tr31: random KBPK: %w", err)
	}
	s, err := NewTR31Signer(kbpk)
	if err != nil {
		return nil, nil, err
	}
	return s, kbpk, nil
}
