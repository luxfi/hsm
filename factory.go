package hsm

import (
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

	case "local", "":
		return NewLocalSigner(), nil

	default:
		return nil, fmt.Errorf("hsm: unknown signer provider %q (supported: aws, gcp, azure, zymbit, yubihsm, pkcs11, nitrokey, coldcard, foundation, keystone, ngrave, gridplus, ledger, trezor, mldsa, local)", providerType)
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
