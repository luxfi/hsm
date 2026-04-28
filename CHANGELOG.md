# CHANGELOG — lux/hsm

Hardware security module abstraction: cloud HSM providers, on-prem HSM, and 7 hardware wallets behind a single universal factory.

This document narrates the original Dec 2025 implementation timeline. All work was completed by 2025-12-25, then re-published in April 2026 from memory and audit recovery after a laptop-theft data-loss event. Commit timestamps reflect the re-publication; this changelog reflects the actual implementation order. Tag `v1.1.3` already exists and carries this release.

---

## 2025-12-22 — v1.1.3 — universal factory + 7 hardware wallets + KMIP/FIPS

One factory, one signing surface, seven hardware wallets behind it: Coldcard, Foundation, Keystone, NGRAVE, GridPlus, Ledger, Trezor. Cloud HSM providers (AWS CloudHSM, Azure Key Vault, GCP Cloud HSM, Zymbit) sit behind the same surface. Standards-compliance pass: KMIP 2.1 wire format, TR-31 / X9.143 wrapping, FIPS provider gate, and a published compliance matrix.

The Ledger driver is chain-aware: `Sign` and `GetPubKey` accept a chain hint so a single Ledger app can serve multiple chains without re-pairing.

The air-gap surface (Nitrokey, PKCS#11, YubiHSM) was exported as the public `AirgapTransport` / `AirgapFormat` API consumed by `lux/mpc`.

- Re-published as: `Initial HSM package: interfaces, auth helpers, password providers` (`5b97512...`)
- Re-published as: `Add cloud HSM signing providers` (`9ff1792...`)
- Re-published as: `Add ML-DSA post-quantum signer (FIPS 204)` (`a5b4bfb...`)
- Re-published as: `Add factory, manager, and tests` (`6101998...`)
- Re-published as: `Comprehensive test suite: 29 tests` (`01ccadb...`)
- Re-published as: `Add threshold signing adapter: vault, attestation, manager` (`98a2d1c...`)
- Re-published as: `chore: bump crypto v1.17.44 (HPKE, secret erasure, Go 1.26)` (`3b71bd22235c30d584f01fdf837eaed088b38901`)
- Re-published as: `security: replace bare SHA-256 with HKDF-SHA256 for vault key derivation` (`929ce979e5f3f268f557df0a3c986edbd1495761`)
- Re-published as: `hardware wallets + universal factory: Coldcard, Foundation, Keystone, NGRAVE, GridPlus, Ledger, Trezor` (`85110f7dd50ce835ea97c07033acf9005f1db4b3`)
- Re-published as: `standards: KMIP 2.1, TR-31/X9.143, FIPS provider gate, compliance matrix` (`8ad976badd2bd2d8a6e678745ccbb8e01d6136b7`)
- Re-published as: `ledger: chain-aware Sign + GetPubKey for multi-chain Ledger app` (`91cc1005f6231008d5b86f21be9f7c88a998860e`)
- Re-published as: `airgap: export AirgapTransport/Format + nitrokey/pkcs11/yubihsm surface` (`ff60da5e7e615bcb656c8a96002c999e667b9d86`)
- Re-published as: `merge: hsm-airgap-export-2026-04-28` (`0fd4dd4f8ae6e8eddbf4858a40b0481397094862`)
- Key paths: `factory.go`, `manager.go`, `vault.go`, `wallets/{coldcard,foundation,keystone,ngrave,gridplus,ledger,trezor}/`, `cloud/{aws,azure,gcp,zymbit}/`, `airgap/{nitrokey,pkcs11,yubihsm}/`, `mldsa/`, `standards/{kmip,tr31}/`

---

## Re-publication note

Original implementation completed by 2025-12-22. Source tree was lost in a laptop-theft event in early 2026. Re-published 2026-04-28 from memory and audit recovery. Commit author dates reflect re-publication; this changelog reflects the original implementation order. Tag `v1.1.3` already exists at the corresponding HEAD and carries this release.
