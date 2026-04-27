package hsm

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/luxfi/crypto/mldsa"
)

// NewSigner creates a Signer for the given provider type.
//
// Supported providers:
//
//	Cloud HSM/KMS:    aws, gcp, azure
//	Network HSM:      zymbit, gridplus
//	USB HSM:          yubihsm, nitrokey
//	Universal:        pkcs11 (Thales / Utimaco / Entrust / CloudHSM / SoftHSM2 / …)
//	Airgapped wallet: coldcard, foundation, keystone, ngrave
//	USB wallet:       ledger, trezor
//	Post-quantum:     mldsa
//	Dev only:         local
//
// Per-provider config keys are documented in CLAUDE.md / LLM.md and on
// each signer's *Config struct. Configuration values not supplied via
// the config map are read from environment variables at the matching
// MPC_HSM_<PROVIDER>_* names.
func NewSigner(providerType string, config map[string]string) (Signer, error) {
	providerType = strings.TrimSpace(strings.ToLower(providerType))
	get := func(key, envKey string) string {
		if config != nil {
			if v, ok := config[key]; ok && v != "" {
				return v
			}
		}
		return os.Getenv(envKey)
	}
	switch providerType {
	case "aws":
		return &AWSKMSSigner{Region: get("region", "AWS_REGION")}, nil

	case "gcp":
		return &GCPKMSSigner{}, nil

	case "azure":
		return &AzureKVSigner{VaultURL: get("vault_url", "AZURE_VAULT_URL")}, nil

	case "zymbit":
		return &ZymbitSigner{APIAddr: get("api_addr", "MPC_HSM_ZYMBIT_API")}, nil

	case "yubihsm", "yubico", "yubi":
		s := &YubiHSMSigner{
			ConnectorURL: get("connector_url", "MPC_HSM_YUBIHSM_CONNECTOR_URL"),
			Password:     get("password", "MPC_HSM_YUBIHSM_PASSWORD"),
			Algorithm:    get("algorithm", "MPC_HSM_YUBIHSM_ALGORITHM"),
		}
		if v := get("auth_key_id", "MPC_HSM_YUBIHSM_AUTH_KEY_ID"); v != "" {
			if id, err := parseObjectID(v); err == nil {
				s.AuthKeyID = id
			}
		}
		return s, nil

	case "pkcs11":
		slotID, _ := strconv.ParseUint(get("slot", "MPC_HSM_PKCS11_SLOT"), 10, 64)
		return NewPKCS11Signer(PKCS11Config{
			LibraryPath: get("library", "MPC_HSM_PKCS11_LIBRARY"),
			SlotID:      uint(slotID),
			TokenLabel:  get("token_label", "MPC_HSM_PKCS11_TOKEN_LABEL"),
			Pin:         get("pin", "MPC_HSM_PKCS11_PIN"),
			KeyLabel:    get("key_label", "MPC_HSM_PKCS11_KEY_LABEL"),
			Mechanism:   get("mechanism", "MPC_HSM_PKCS11_MECHANISM"),
		})

	case "nitrokey":
		slotID, _ := strconv.ParseUint(get("slot", "MPC_HSM_NITROKEY_SLOT"), 10, 64)
		return NewNitrokeySigner(NitrokeyConfig{
			LibraryPath: get("library", "MPC_HSM_NITROKEY_LIBRARY"),
			SlotID:      uint(slotID),
			TokenLabel:  get("token_label", "MPC_HSM_NITROKEY_TOKEN_LABEL"),
			Pin:         get("pin", "MPC_HSM_NITROKEY_PIN"),
			KeyLabel:    get("key_label", "MPC_HSM_NITROKEY_KEY_LABEL"),
			Mechanism:   get("mechanism", "MPC_HSM_NITROKEY_MECHANISM"),
		})

	case "coldcard":
		return NewColdcardSigner(ColdcardConfig{
			DeviceID:  get("device_id", "MPC_HSM_AIRGAP_DEVICE_ID"),
			Format:    AirgapFormat(get("format", "MPC_HSM_COLDCARD_FORMAT")),
			Transport: airgapTransportFromConfig(config),
		})

	case "foundation":
		return NewFoundationSigner(FoundationConfig{
			DeviceID:  get("device_id", "MPC_HSM_AIRGAP_DEVICE_ID"),
			Transport: airgapTransportFromConfig(config),
		})

	case "keystone":
		return NewKeystoneSigner(KeystoneConfig{
			DeviceID:  get("device_id", "MPC_HSM_AIRGAP_DEVICE_ID"),
			URType:    URType(get("ur_type", "MPC_HSM_KEYSTONE_UR_TYPE")),
			Transport: airgapTransportFromConfig(config),
		})

	case "ngrave":
		return NewNGRAVESigner(NGRAVEConfig{
			DeviceID:  get("device_id", "MPC_HSM_AIRGAP_DEVICE_ID"),
			URType:    URType(get("ur_type", "MPC_HSM_NGRAVE_UR_TYPE")),
			Transport: airgapTransportFromConfig(config),
		})

	case "gridplus", "lattice":
		return NewLatticeSigner(LatticeConfig{
			BaseURL:       get("base_url", "MPC_HSM_LATTICE_BASE_URL"),
			DeviceID:      get("device_id", "MPC_HSM_LATTICE_DEVICE_ID"),
			AppName:       get("app_name", "MPC_HSM_LATTICE_APP_NAME"),
			PairingSecret: get("pairing_secret", "MPC_HSM_LATTICE_PAIRING_SECRET"),
		})

	case "ledger":
		return NewLedgerSigner(LedgerConfig{
			ToolPath:       get("tool", "MPC_HSM_LEDGER_TOOL"),
			App:            get("app", "MPC_HSM_LEDGER_APP"),
			SignAction:     get("sign_action", "MPC_HSM_LEDGER_SIGN_ACTION"),
			DerivationPath: get("path", "MPC_HSM_LEDGER_PATH"),
		})

	case "trezor":
		return NewTrezorSigner(TrezorConfig{
			ToolPath:       get("tool", "MPC_HSM_TREZOR_TOOL"),
			Coin:           get("coin", "MPC_HSM_TREZOR_COIN"),
			SignAction:     get("sign_action", "MPC_HSM_TREZOR_SIGN_ACTION"),
			DerivationPath: get("path", "MPC_HSM_TREZOR_PATH"),
		})

	case "mldsa", "pq", "post-quantum":
		return NewMLDSASigner(mldsa.MLDSA65), nil

	case "kmip":
		ts, _ := strconv.Atoi(get("timeout", "MPC_HSM_KMIP_TIMEOUT"))
		return NewKMIPSigner(KMIPConfig{
			Endpoint:               get("endpoint", "MPC_HSM_KMIP_ENDPOINT"),
			CAFile:                 get("ca_file", "MPC_HSM_KMIP_CA_FILE"),
			ClientCertFile:         get("client_cert", "MPC_HSM_KMIP_CLIENT_CERT"),
			ClientKeyFile:          get("client_key", "MPC_HSM_KMIP_CLIENT_KEY"),
			ServerName:             get("server_name", "MPC_HSM_KMIP_SERVER_NAME"),
			UniqueIdentifier:       get("uid", "MPC_HSM_KMIP_UID"),
			CryptographicAlgorithm: get("algorithm", "MPC_HSM_KMIP_ALGORITHM"),
			HashingAlgorithm:       get("hash", "MPC_HSM_KMIP_HASH"),
			TimeoutSeconds:         ts,
		})

	case "tr31":
		// TR-31 KBPK is sourced from configuration as hex bytes. Production
		// deployments MUST inject the KBPK via a KMS provider — never via
		// a plaintext config file. The config-based path here exists for
		// dev/test and for operators who derive the KBPK out-of-band.
		kbpkHex := get("kbpk_hex", "MPC_HSM_TR31_KBPK_HEX")
		if kbpkHex == "" {
			return nil, errors.New("hsm: tr31 requires kbpk_hex (or MPC_HSM_TR31_KBPK_HEX) — 32-byte KBPK in hex")
		}
		kbpk, err := hex.DecodeString(kbpkHex)
		if err != nil {
			return nil, fmt.Errorf("hsm: tr31 kbpk_hex decode: %w", err)
		}
		return NewTR31Signer(kbpk)

	case "local", "":
		return NewLocalSigner(), nil

	default:
		return nil, fmt.Errorf("hsm: unknown signer provider %q (supported: aws, gcp, azure, zymbit, yubihsm, pkcs11, nitrokey, coldcard, foundation, keystone, ngrave, gridplus, ledger, trezor, kmip, tr31, mldsa, local)", providerType)
	}
}

// RequireFIPSProvider returns nil when providerType is a FIPS-validated
// provider that may be used in deployments subject to FIPS 140-2 / 140-3
// or FIPS 199 controls. It returns a descriptive error otherwise so
// startup fails fast on misconfiguration in regulated environments.
//
// Validation policy (luxfi/hsm does NOT ship its own FIPS module — it
// facilitates compliant use of third-party FIPS modules):
//
//   - aws       — AWS CloudHSM is FIPS 140-2 Level 3 validated
//                 (CMVP cert #3380). AWS KMS is FIPS 140-2 Level 3 validated
//                 (cert #4523) when configured to use FIPS endpoints.
//   - gcp       — Google Cloud HSM uses Marvell LiquidSecurity HSMs that
//                 are FIPS 140-2 Level 3 validated (cert #4399).
//   - azure     — Azure Key Vault Premium / Managed HSM uses Marvell
//                 LiquidSecurity (cert #4399); Azure Dedicated HSM uses
//                 Thales Luna 7 (cert #4153, Level 3).
//   - pkcs11    — PASS through; the validation depends entirely on the
//                 vendor library configured. Operators MUST verify the
//                 specific module/firmware version is on the active CMVP
//                 list. luxfi/hsm cannot enforce this remotely.
//   - kmip      — same as pkcs11 — depends on the KMS server's CMVP cert.
//   - yubihsm   — YubiHSM 2 is FIPS 140-2 Level 3 validated (cert #4148)
//                 when running FIPS firmware (5.x.x-FIPS).
//   - nitrokey  — Nitrokey HSM 2 holds Common Criteria EAL4+ (cert
//                 BSI-DSZ-CC-1148) but is NOT FIPS 140 validated. It is
//                 REJECTED by RequireFIPSProvider.
//   - zymbit    — Zymbit SCM is NOT FIPS 140 validated. REJECTED.
//   - mldsa, local, tr31 — pure-software implementations. REJECTED.
//   - coldcard, foundation, keystone, ngrave, ledger, trezor, gridplus —
//                 personal hardware wallets, not FIPS validated. REJECTED
//                 unless the deployment is FIPS-exempt (e.g., custody
//                 ceremonies under a separate compliance regime).
//
// Callers wire RequireFIPSProvider before constructing the Signer:
//
//	if cfg.FIPSRequired {
//	    if err := hsm.RequireFIPSProvider(cfg.SignerProvider); err != nil {
//	        return fmt.Errorf("startup: %w", err)
//	    }
//	}
//	signer, err := hsm.NewSigner(cfg.SignerProvider, cfg.SignerConfig)
func RequireFIPSProvider(providerType string) error {
	p := strings.TrimSpace(strings.ToLower(providerType))
	switch p {
	case "aws", "gcp", "azure", "yubihsm", "yubico", "yubi", "pkcs11", "kmip":
		return nil
	case "":
		return errors.New("hsm/fips: provider not specified — FIPS deployments must explicitly select a validated provider")
	case "local":
		return errors.New("hsm/fips: local signer is not FIPS-validated (in-memory ECDSA, dev-only)")
	case "mldsa", "pq", "post-quantum":
		return errors.New("hsm/fips: cloudflare/circl ML-DSA is not yet on the CMVP active list (FIPS 204 module validation in progress)")
	case "tr31":
		return errors.New("hsm/fips: TR-31 signer is a key-block adapter — backing KBPK must come from a FIPS provider; configure provider=aws|gcp|azure|pkcs11|kmip|yubihsm and wrap with TR31Signer at the call site")
	case "nitrokey":
		return errors.New("hsm/fips: Nitrokey HSM 2 holds CC EAL4+ but is not FIPS 140-2/3 validated")
	case "zymbit":
		return errors.New("hsm/fips: Zymbit SCM is not FIPS 140-2/3 validated")
	case "coldcard", "foundation", "keystone", "ngrave", "ledger", "trezor", "gridplus", "lattice":
		return fmt.Errorf("hsm/fips: %s is a personal hardware wallet and is not FIPS 140-2/3 validated", p)
	default:
		return fmt.Errorf("hsm/fips: unknown provider %q — cannot assert FIPS compliance", providerType)
	}
}

// airgapTransportFromConfig extracts an AirgapTransport supplied via
// the special "_airgap_transport" config key. The factory cannot
// construct a transport on its own — the surface used to display
// challenges (terminal prompt, web UI, kiosk display) is owned by the
// host application, not by luxfi/hsm. Hosts that pass an empty config
// receive a signer whose Sign call returns ErrAirgapTransportRequired.
//
// Hosts wire transports like:
//
//	hsm.NewSigner("coldcard", map[string]string{
//	    "device_id": "wallet-0",
//	}).(*ColdcardSigner).cfg.Transport = myTransport
//
// or by constructing the *Config struct directly. The factory supports
// the latter via the per-signer New*Signer constructors.
func airgapTransportFromConfig(_ map[string]string) AirgapTransport {
	return nil
}

// NewPasswordProvider creates a PasswordProvider based on the given
// type string.
//
// Supported types: "aws", "gcp", "azure", "env", "file".
func NewPasswordProvider(providerType string, config map[string]string) (PasswordProvider, error) {
	providerType = strings.TrimSpace(strings.ToLower(providerType))
	if providerType == "" {
		providerType = "env"
	}

	get := func(key, envKey string) string {
		if config != nil {
			if v, ok := config[key]; ok && v != "" {
				return v
			}
		}
		return os.Getenv(envKey)
	}

	switch providerType {
	case "aws":
		return &AWSKMSProvider{
			KeyID:  get("key_id", "MPC_HSM_KEY_ID"),
			Region: get("region", "AWS_REGION"),
		}, nil

	case "gcp":
		return &GCPKMSProvider{
			ProjectID:   get("project_id", "GCP_PROJECT_ID"),
			LocationID:  get("location", "GCP_KMS_LOCATION"),
			KeyRingID:   get("key_ring", "GCP_KMS_KEYRING"),
			CryptoKeyID: get("crypto_key", "GCP_KMS_KEY"),
		}, nil

	case "azure":
		return &AzureKVProvider{
			VaultURL:   get("vault_url", "AZURE_VAULT_URL"),
			KeyName:    get("key_name", "AZURE_KEY_NAME"),
			KeyVersion: get("key_version", "AZURE_KEY_VERSION"),
		}, nil

	case "env":
		envVar := get("env_var", "")
		if envVar == "" {
			envVar = "MPC_PASSWORD"
		}
		return &EnvProvider{EnvVar: envVar}, nil

	case "file":
		return &FileProvider{
			Path: get("path", "MPC_PASSWORD_FILE"),
		}, nil

	default:
		return nil, fmt.Errorf("hsm: unknown password provider type %q (supported: aws, gcp, azure, env, file)", providerType)
	}
}
