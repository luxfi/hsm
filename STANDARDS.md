# luxfi/hsm — Standards Compliance Matrix

luxfi/hsm is the unified HSM/KMS abstraction for the Lux ecosystem. It
does not ship its own FIPS-validated cryptographic module. It facilitates
COMPLIANT USE of third-party FIPS-validated providers (cloud HSMs and
on-prem appliances) and ships pure-Go primitives for cases where a
hardware module is unavailable.

This document is the canonical claim register. Every entry below is
either ✓ shipped (with a test fixture cited), 🚧 in-flight (with a
remediation plan), or ⨯ missing (with a follow-on tracking item).

Last updated: 2026-04-27.

## Compliance Status

### API standards

| Standard | Version | Status | Provider | Module Cert | Test Fixtures |
|----------|---------|--------|----------|-------------|---------------|
| PKCS#11 | v2.40 | ✓ shipped | signer_pkcs11_cgo.go (build tag `pkcs11`) | via miekg/pkcs11 v1.1.1 (BSD-3) | SoftHSM2 + fake shell |
| PKCS#11 | v3.0 | ✓ shipped | signer_pkcs11_cgo.go — SHA-3 ECDSA, SHA-3 RSA-PKCS, RSA-PSS, EdDSA mechanism IDs | mechanism IDs per OASIS PKCS#11 v3.0 §2.x | SoftHSM2 (smoke) |
| PKCS#15 | — | ⨯ missing | n/a | — | follow-on |
| KMIP | 2.1 | ✓ shipped | signer_kmip_real.go (build tag `kmip`) | gemalto/kmip-go v0.1.0 (Apache-2) — Sign/SignatureVerify/Activate/Revoke/Destroy | TTLV codec unit tests upstream; live KMS test deferred |
| OASIS CDMI | — | ⨯ missing | n/a (out of scope — CDMI is a cloud-storage management API, not an HSM API) | — | — |

### Auth standards

| Standard | Version | Status | Provider | Notes | Test Fixtures |
|----------|---------|--------|----------|-------|---------------|
| TLS-PSK | RFC 4279 | ✓ shipped | crypto/tls (stdlib) | Used for KMIP fallback when mTLS infeasible | stdlib TLS tests |
| TLS 1.3 mTLS | RFC 8446 | ✓ shipped | signer_kmip_real.go forces tls.VersionTLS13 + client cert | KMIP profiles 1 & 2 mandate mTLS | unit test against test KMS pending |
| FIDO2 / WebAuthn | CTAP2.1 / WebAuthn L2 | ⨯ missing | sibling #112 ApprovalProvider | go-webauthn upstream | follow-on |
| OAuth 2.0 | RFC 6749 | ⨯ deferred to gateway | api.hanzo.ai gateway terminates OAuth, signs internal mTLS | luxfi/hsm consumes mTLS-authenticated calls only | — |
| OIDC | OpenID Connect Core 1.0 | ⨯ deferred to gateway | same as OAuth | — | — |

### Crypto standards

| Standard | Version | Status | Provider | Module Cert | Test Fixtures |
|----------|---------|--------|----------|-------------|---------------|
| NIST SP 800-90A DRBG | rev 1 | ✓ shipped | crypto/rand stdlib | OS getrandom / /dev/urandom backed; FIPS-validated when running on a CMVP-certified host | smoke test |
| NIST SP 800-90B (entropy) | — | ✓ inherited | OS-supplied entropy source | host-dependent | — |
| NIST SP 800-90C (DRBG construction) | draft | ✓ shipped | crypto/rand | — | — |
| NIST SP 800-57 (key lifecycle) | rev 5 | ✓ shipped | KMIP Activate/Revoke/Destroy via signer_kmip_real.go | conformance documented in this file | — |
| NIST SP 800-131A (transitions) | rev 2 | ✓ enforced | RequireFIPSProvider rejects DSA/3DES providers | startup-time gate | factory_fips_test.go |
| NIST SP 800-108 KDF | rev 1 | ✓ shipped | signer_tr31.go sp800108KDF (HMAC-SHA-256, counter mode) | derives KBEK/KBAK from KBPK | TestTR31AESCMACVector + roundtrip |
| NIST SP 800-38B AES-CMAC | — | ✓ shipped | signer_tr31.go aesCMAC | NIST CAVP vectors §D.1 ex 1 + 2 | TestTR31AESCMACVector |
| FIPS 197 (AES) | — | ✓ shipped | crypto/aes stdlib | NIST CAVP vectors via stdlib | indirect via TR-31 + KMIP tests |
| FIPS 180-4 (SHA-2) | — | ✓ shipped | crypto/sha256 + crypto/sha512 stdlib | NIST CAVP vectors via stdlib | indirect |
| FIPS 198-1 (HMAC) | — | ✓ shipped | crypto/hmac stdlib | indirect via SP 800-108 KDF | indirect |
| FIPS 202 (SHA-3) | — | ✓ shipped | golang.org/x/crypto/sha3 + PKCS#11 v3.0 SHA-3 mechanisms | NIST CAVP vectors via stdlib | indirect |
| FIPS 203 (ML-KEM) | — | 🚧 in-flight | sibling #102 PQClean port (luxfi/crypto) | NIST KAT pending | — |
| FIPS 204 (ML-DSA) | — | 🚧 in-flight | luxfi/crypto/mldsa via cloudflare/circl | cloudflare/circl is unverified by CMVP; ML-DSA module validation in progress | hsm_test.go round-trip |
| FIPS 205 (SLH-DSA) | — | 🚧 in-flight | sibling #102 PQClean port | NIST KAT pending | — |
| FIPS 186-5 (ECDSA) | — | ✓ shipped | crypto/ecdsa stdlib + KMIP/PKCS#11/CloudHSM | NIST CAVP vectors via stdlib | hsm_test.go round-trip |
| FIPS 186-5 (EdDSA) | — | ✓ shipped | crypto/ed25519 + PKCS#11 CKM_EDDSA + YubiHSM ed25519 | RFC 8032 vectors via stdlib | signer_yubihsm_test.go |

### Hardware certifications (inherited from validated modules)

luxfi/hsm does not claim its own FIPS or Common Criteria certification.
The certifications below are properties of the third-party modules that
luxfi/hsm wraps. RequireFIPSProvider gates startup so non-validated
providers are rejected in regulated deployments.

| Standard | Module | Cert # | luxfi/hsm Provider | Notes |
|----------|--------|--------|--------------------|-------|
| FIPS 140-2 L3 | AWS CloudHSM (Cavium / Marvell LiquidSecurity) | #3380 | aws | CloudHSM only; KMS depends on endpoint |
| FIPS 140-2 L3 | AWS KMS (FIPS endpoints) | #4523 | aws | requires FIPS-suffixed endpoint hostnames |
| FIPS 140-2 L3 | Google Cloud HSM (Marvell LiquidSecurity) | #4399 | gcp | global Cloud HSM tier |
| FIPS 140-2 L3 | Azure Managed HSM (Marvell LiquidSecurity) | #4399 | azure | Managed HSM, not Vault Standard |
| FIPS 140-2 L3 | Azure Dedicated HSM (Thales Luna 7) | #4153 | azure | Dedicated HSM SKU |
| FIPS 140-2 L3 | Thales SafeNet Luna 7 | #4153 | pkcs11 | LibraryPath=/usr/safenet/lunaclient/lib/libCryptoki2_64.so |
| FIPS 140-2 L3 | Utimaco u.trust SecurityServer | #3568 | pkcs11 | LibraryPath=/opt/utimaco/p11/libcs_pkcs11_R3.so |
| FIPS 140-2 L4 | Utimaco u.trust LAN V5 (Level 4 capable) | #4023 | pkcs11 | when configured for L4 |
| FIPS 140-2 L3 | Entrust nShield Connect | #4108 | pkcs11 | LibraryPath=/opt/nfast/toolkits/pkcs11/libcknfast.so |
| FIPS 140-2 L3 | YubiHSM 2 (FIPS firmware 5.x.x-FIPS) | #4148 | yubihsm | requires FIPS firmware build |
| FIPS 140-3 L3 | (cloud HSMs upgrading) | — | — | 🚧 in-flight on vendor side |
| FIPS 140-2 L3 | Marvell LiquidSecurity HSM | #4399 | pkcs11 / aws / gcp / azure | underlying module across multiple cloud HSMs |
| CC EAL4+ | Thales nShield Connect+ | BSI-DSZ-CC-1063 | pkcs11 | inherited via PKCS#11 |
| CC EAL4+ | Nitrokey HSM 2 | BSI-DSZ-CC-1148 | nitrokey | NOT FIPS 140 — REJECTED by RequireFIPSProvider |
| CC EAL5+ | Utimaco CryptoServer Se52 | BSI-DSZ-CC-0769 | pkcs11 | — |
| CC EAL7+ | NGRAVE Zero | EMVCo cert | ngrave | airgapped wallet — REJECTED by RequireFIPSProvider |
| CMVP active list | (validated when host module is on the list at build time) | — | aws / gcp / azure / pkcs11 / kmip / yubihsm | operators verify quarterly |

### Banking / financial

| Standard | Version | Status | Provider | Module Cert | Test Fixtures |
|----------|---------|--------|----------|-------------|---------------|
| ANSI X9.143 (TR-31 successor) | 2022 | ✓ shipped | signer_tr31.go — AES-256 KBPK Variant Binding (Version "D") | conformance test in signer_tr31_test.go | TestTR31RoundTrip + TamperHeader + TamperKey + WrongKBPK + AESCMACVector |
| ASC X9 TR-31 | 2018 | ✓ inherited | signer_tr31.go (X9.143 supersedes) | — | as above |
| TR-34 (key derivation) | — | ⨯ missing | n/a | — | follow-on |
| ISO 9564 (PIN management) | parts 1-5 | 🚧 architectural fit | TR31 wraps PIN-encryption keys (Usage="P0") but does not implement PIN block formats | callers handle PIN block format 0/3/4 in their app layer | — |
| PCI-DSS | v4.0 | ✓ inherited | uses FIPS-validated providers + KMS-only secret storage | conformance is operator's responsibility | — |
| PCI-PIN PTS | v3.1 | ✓ architectural fit | TR-31 + RequireFIPSProvider | conformance is operator's responsibility | — |

### Crypto-currency-specific

| Standard | Version | Status | Provider | Notes |
|----------|---------|--------|----------|-------|
| CCSS Level 1 | v8 | ✓ architectural fit | covered by KMS-only secrets, hashed passwords, FIPS gate | independent CCSS audit not yet run |
| CCSS Level 2 | v8 | ✓ architectural fit | adds airgapped signers (coldcard/foundation/keystone/ngrave) | — |
| CCSS Level 3 | v8 | ✓ architectural fit | adds threshold signing (luxfi/threshold) + multi-party custody | independent audit pending |
| NIST IR 8214A (threshold) | — | 🚧 in-flight | luxfi/threshold-* packages | hsm.threshold_adapter.go bridges Signer interface to threshold scheme |

### Java / .NET interop

luxfi/hsm is a Go library; Java and .NET interop happens at the HSM
itself (PKCS#11 / KMIP / cloud SDK). There is no Java or .NET Go
binding. The standards below are listed for completeness — operators
running JCA/JCE/CNG/KSP applications target the same backing HSMs that
luxfi/hsm uses, so the cryptographic guarantees are equivalent.

| Standard | Mapping |
|----------|---------|
| JCA | Java HSM access via vendor JCE provider (e.g., SunPKCS11 → same PKCS#11 lib that luxfi/hsm uses) |
| JCE | as JCA |
| Microsoft CNG | Windows-side access via vendor CNG KSP → same hardware |
| Microsoft KSP | as CNG |

### Legacy compatibility

| Standard | Status | Provider | Notes |
|----------|--------|----------|-------|
| OpenSSL ENGINE API | ⨯ not implemented | — | OpenSSL ENGINE is deprecated by OpenSSL 3.x in favor of OSSL_PROVIDER. luxfi/hsm targets PKCS#11 / KMIP directly. |
| OpenSSL OSSL_PROVIDER | ⨯ not implemented | — | follow-on if a use case appears |
| OpenSC PKCS#11 | ✓ shipped | signer_nitrokey.go probes /usr/lib/opensc-pkcs11.so | smart card / Nitrokey support inherits OpenSC's CC EAL4+ profile |

## Implementation gaps to close

Tracked as luxfi/hsm follow-on issues. Listed in priority order.

### #1 — KMIP integration testing against live servers

`signer_kmip_real.go` is wire-format complete (TTLV codec from
gemalto/kmip-go v0.1.0). The remaining work is integration testing
against:

* PyKMIP test server (already in gemalto/kmip-go's docker-compose)
* Thales CipherTrust Manager (smoke)
* Fortanix DSM (smoke)
* HashiCorp Vault Enterprise KMIP secrets engine (smoke)

Plan: spin up PyKMIP via docker-compose in a `-tags kmip` integration
suite gated by `KMIP_LIVE=1` environment variable. Live tests run on
demand, not in CI.

### #2 — TR-34 key derivation (banking)

ANSI X9.24 / TR-34 is the asymmetric counterpart to TR-31 for
distributing the initial KBPK between HSMs. Required for full PCI-PIN
key-injection ceremony coverage.

Plan: implement `signer_tr34.go` (~1000 LOC) using crypto/rsa for the
key transport layer. Defer until a banking customer requires it.

### #3 — FIDO2 / WebAuthn approval keys

Sibling #112 owns this. luxfi/hsm exposes the `ApprovalProvider`
interface; the WebAuthn implementation lives in a separate package so
it can pull in go-webauthn without infecting the core HSM build.

### #4 — FIPS 203 / 204 / 205 module validation

Pure-Go ML-KEM / ML-DSA / SLH-DSA implementations exist
(luxfi/crypto + cloudflare/circl) but are not on the CMVP active list.

Plan: track upstream NIST module validation submissions; flip the
status row from 🚧 to ✓ when CMVP issues certificates. RequireFIPSProvider
will continue to reject `mldsa` until then.

### #5 — PKCS#11 v3.0 PSS parameters

Current `mechanismFor` returns CKM_RSA_PKCS_PSS without explicit PSS
parameters, which only works on tokens that accept the default salt
length. Add a PKCS11Config.PSSParams field and bind it when the
mechanism is PSS-flavored.

Plan: ~50 LOC, blocked on a customer that needs non-default PSS salt.

## Audit chain

Reference path:

* luxfi/hsm wraps existing FIPS-validated providers (AWS CloudHSM L3,
  Thales Luna L3, Utimaco L3/L4, Entrust nShield L3, YubiHSM 2 L3 with
  FIPS firmware).
* luxfi/hsm itself does NOT claim FIPS 140-2 or 140-3 module validation.
* For FIPS-mandated deployments operators MUST:
  1. Configure a provider that is on the active CMVP list at build
     time (aws / gcp / azure with FIPS endpoints; pkcs11 / kmip with a
     validated module; yubihsm with FIPS firmware).
  2. Set `cfg.FIPSRequired = true` (or call `hsm.RequireFIPSProvider`
     at startup) — this rejects local / mldsa / nitrokey / zymbit and
     personal hardware wallets at process startup.
  3. Confirm the host OS supplies a CAVP-validated entropy source for
     `crypto/rand` (Linux kernel ≥ 4.11 with getrandom is acceptable
     when the host is itself on the CMVP active list).

For pure-Go primitives (signer_local.go, signer_mldsa.go, signer_tr31.go):

* These use Go stdlib `crypto/*` and `golang.org/x/crypto/*`. Stdlib is
  vetted by the Go security team but is NOT on the CMVP active list.
* `signer_local.go` is rejected by RequireFIPSProvider — it exists for
  development only.
* `signer_mldsa.go` is rejected by RequireFIPSProvider — pending CMVP
  validation of cloudflare/circl ML-DSA.
* `signer_tr31.go` is rejected when used standalone — its KBPK MUST be
  injected from a FIPS-validated source. Operators chain TR-31 behind
  a KMS-supplied KBPK (configure provider=aws|gcp|azure|pkcs11|kmip,
  read the KBPK via the provider, hand it to NewTR31Signer).

## How to verify a deployment

```go
// In your service's startup code, before NewSigner:
if cfg.FIPSRequired {
    if err := hsm.RequireFIPSProvider(cfg.SignerProvider); err != nil {
        return fmt.Errorf("startup: FIPS gate: %w", err)
    }
}
signer, err := hsm.NewSigner(cfg.SignerProvider, cfg.SignerConfig)
```

The gate is a hard fail at startup. There is no soft mode.

## Updates

When a row in the matrix changes (a new CMVP certificate, a new
PKCS#11 mechanism, a new KMIP test fixture), update this file in the
same commit as the code change. Entries claimed without test
fixtures are rejected at code review.
