// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

// PKCS11Config configures a PKCS#11 v2.40 token. The same configuration
// type covers Thales SafeNet Luna, Utimaco u.trust SecurityServer,
// Entrust nShield, Marvell LiquidSecurity, AWS CloudHSM (PKCS#11 client),
// GCP Cloud HSM (PKCS#11 client), Azure Dedicated HSM, IBM Cloud HSM,
// Oracle Cloud HSM, SoftHSM2, and Nitrokey HSM 2 (via OpenSC).
//
// The real signer compiled with `-tags pkcs11` lives in
// signer_pkcs11_cgo.go and depends on github.com/miekg/pkcs11 (BSD-3,
// Cloudflare-maintained) which calls into the vendor's libCryptoki
// shared library via CGO.
//
// The default build (no tag) ships only the configuration types and the
// stub returned by NewPKCS11Signer so packages that import luxfi/hsm do
// not require a CGO toolchain. Operators who need PKCS#11 support build
// mpcd with `-tags pkcs11`.
type PKCS11Config struct {
	// LibraryPath is the absolute filesystem path to the vendor's
	// PKCS#11 shared library. Examples:
	//   Thales Luna:   /usr/safenet/lunaclient/lib/libCryptoki2_64.so
	//   Utimaco:       /opt/utimaco/p11/libcs_pkcs11_R3.so
	//   Entrust:       /opt/nfast/toolkits/pkcs11/libcknfast.so
	//   AWS CloudHSM:  /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
	//   SoftHSM2:      /usr/lib/softhsm/libsofthsm2.so
	//   Nitrokey:      /usr/lib/opensc-pkcs11.so (via signer_nitrokey.go)
	LibraryPath string

	// SlotID is the PKCS#11 slot containing the token. Operators read
	// available slots with `pkcs11-tool --list-slots -L`.
	SlotID uint

	// TokenLabel is an alternative to SlotID — when non-empty the signer
	// scans all slots for a token whose CKA_LABEL matches. Preferred
	// when multiple tokens may be present.
	TokenLabel string

	// Pin is the user PIN used for C_Login. In production this MUST be
	// supplied via KMS — never embedded in config files. When empty
	// the signer reads MPC_HSM_PKCS11_PIN at sign time.
	Pin string

	// KeyLabel is the CKA_LABEL of the asymmetric key on the token.
	// The signer locates the key via C_FindObjectsInit with a template
	// of {CKA_LABEL, CKA_CLASS=CKO_PRIVATE_KEY}.
	KeyLabel string

	// Mechanism is the PKCS#11 signing mechanism. Common values:
	//   "ECDSA"          — CKM_ECDSA      (raw, host pre-hashes)
	//   "ECDSA_SHA256"   — CKM_ECDSA_SHA256
	//   "EDDSA"          — CKM_EDDSA      (Ed25519)
	//   "RSA_PKCS"       — CKM_RSA_PKCS
	//   "RSA_PKCS_PSS"   — CKM_RSA_PKCS_PSS
	// When empty the signer defaults to "ECDSA_SHA256".
	Mechanism string
}

// pkcs11ProviderName is the canonical Provider() string returned by
// PKCS11Signer regardless of which underlying token is in use.
const pkcs11ProviderName = "pkcs11"

// pinFromConfig returns the configured PIN or the value of
// MPC_HSM_PKCS11_PIN. The function is shared by the stub and the CGO
// implementation so PIN resolution behavior is identical.
func (c PKCS11Config) pinFromEnv(envLookup func(string) string) (string, error) {
	if c.Pin != "" {
		return c.Pin, nil
	}
	if v := envLookup("MPC_HSM_PKCS11_PIN"); v != "" {
		return v, nil
	}
	return "", errPKCS11NoPin
}
