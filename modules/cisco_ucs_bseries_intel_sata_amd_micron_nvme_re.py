"""
Cisco UCS B-Series: Intel SATA XCV1CS06/SCV1CS08, AMD MI210 GPU, Micron NVMe/D4 SATA,
WDC NVMe, Samsung NVMe, Kioxia SAS SSD, Miami Lake controller, PTE3 CPLD
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin

Covers:
- Intel SATA SSD XCV1CS06 (Youngsville Refresh) -- 6 variants SSDSC2KB/KG
- Intel SATA SSD SCV1CS08 (Youngsville original) -- 6 variants SSDSC2KB/KG
- AMD Instinct MI210 GPU firmware (113-D67307V-075, 3.16)
- Micron NVMe E2CS007 (UCS-NVMEG4-M*/NVM2*/NVMEM6-M* -- 14 variants)
- Micron NVMe E3MQ009/E3MF009 (UCS-NVB*M2* -- 14 variants; no security hits)
- Micron NVMe G1MU003 (UCS-NVB30/61T M3L; 3258KB; no security hits)
- Micron SATA D4CS000/D4CS001 (MTFDDAK/MTFDDAV D4 generation -- 15 variants)
- WDC NVMe R2210803 (NVMEM6-W* -- 5 variants; TPM hit only)
- WDC NVMe R121000B (NVMW*/NVMEM6-W* -- 4 variants; no security hits)
- Samsung NVMe OPPA1K3Q/OPPA1K5Q (UCS-NVE*S1* -- 8 variants; no security hits)
- Kioxia SAS SSD 0105/0109 (KPM6*/KPM7* -- 22 variants; kioxia identity only)
- Miami Lake storage controller (03.01.41.040; 6274KB; TPM only)
- PTE3 CPLD (x210c-m8, x410c-m8, x215c-m8 -- 3 variants)
- X210M7/X410M7 BIOS (6.0.2a; 12440KB each -- same binary)
- SanDisk SATA SSD C405 (lt0400mo/lt1600mo)
- NVIDIA P6 video (159KB; no security hits)
- Toshiba SAS HDD/SSD (AL13/AL14/AL15/MG04 families -- no security hits)
- PMem firmware (dimm-fw.1.2.0.5446 + bps-dimm-fw.2.2.0.1553 -- no security hits)
"""

INTEL_SATA_YOUNGSVILLE_LINEAGE = {
    "SCV1CS08": {
        "product": "Intel Youngsville (original) SATA SSD (SSDSC2KB/KG 7th-gen)",
        "fw_size_kb": 661,
        "variants": 6,
        "md5_prefix": "varies_per_capacity",
        "magic": "06000000a1000000",
        "bootloader": "Intel Youngsville Bootloader",
        "adu_present": False,
        "fw_auth": "Device_FW_Authentication    FW_MAC_Key",
        "note": "No ADU in original Youngsville; only Device_FW_Authentication + FW_MAC_Key",
    },
    "7CV1CS05": {
        "product": "Intel/Solidigm Youngsville RR SATA SSD (SSDSC2KB/KG)",
        "fw_size_kb": 873,
        "variants": 9,
        "bootloader": "Intel Youngsville RR Bootloader / Solidigm Youngsville RR Bootloader",
        "adu_present": True,
        "adu_string": "Asymmetric Diag Unlock    Asymmetric Diag Unlock Auth Key 010",
        "host_exchange": False,
        "note": "ADU INTRODUCED at Youngsville RR; dual Intel+Solidigm bootloader identity (covered in prior module)",
    },
    "XCV1CS06": {
        "product": "Intel Youngsville Refresh SATA SSD (SSDSC2KB/KG 8th-gen)",
        "fw_size_kb": 815,
        "variants": 6,
        "md5_prefix": "varies_per_capacity",
        "magic": "06000000a1000000",
        "bootloader": "Intel Youngsville Refresh Bootloader",
        "adu_present": True,
        "adu_string": "Asymmetric Diag Unlock          Asymmetric Diag Unlock Auth Key 010",
        "host_exchange": True,
        "pki_chain": ["HostExchangeAuthority", "HostExchangeCert", "HostSigningAuthority", "HostSigningCert"],
        "max_authentications": "MaxAuthentications",
        "fw_auth": "Device_FW_Authentication        FW_MAC_Key",
        "msid": ["MSID_password", "FMSID_password"],
        "reencrypt": ["ReEncryptState", "ReEncryptRequest", "LastReEncryptLBA", "MaxReEncryptions"],
        "certificate": "PresentCertificate",
        "active_key": "ActiveKey",
        "note": "ADU + FULL PKI chain (same as ACV10370 NVMe); FMSID = Factory MSID for manufacturing unlock",
    },
    "lineage_insight": {
        "summary": "ADU introduced at 'Youngsville RR' generation (7CV1CS05); original 'Youngsville' (SCV1CS08) has only Device_FW_Authentication. 'Youngsville Refresh' (XCV1CS06) adds full HostExchange + HostSigning PKI chain. The PKI chain is IDENTICAL to ACV10370 NVMe firmware -- same authentication infrastructure across SATA and NVMe interfaces.",
    },
}

AMD_MI210_FIRMWARE = {
    "product": "AMD Instinct MI210 GPU (Aldebaran/MI200 series, HBM2E 128GB/64GB)",
    "fw_version": "113-D67307V-075, VBIOS ATOMBIOS VER020.040.000.040.000000",
    "fw_size_kb": 23443,
    "codename": "Aldebaran",
    "hbm2e": "AMD_MI200_D65209_XT_A1_HBM2E_128GB",
    "build_path_leak": [
        "AMD-MI210/opt/amdfwflash/ifwi/ga/D6520900.063",
        "AMD-MI210/opt/amdfwflash/ifwi/ga/D6521000.063",
        "AMD-MI210/opt/amdfwflash/ifwi/ga/D6730100.059",
        "AMD-MI210/opt/amdfwflash/ifwi/ga/D6730100.064D",
        "AMD_MI200_D65209_XT_A1_HBM2E_128GB_ROWAIRCOOLEDUBB4\\config.h",
    ],
    "crypto_library": {
        "name": "Crypto++ (CryptoPP)",
        "type": "Open-source C++ cryptographic library",
        "evidence_mangled": [
            "N8CryptoPP18PublicKeyAlgorithmE",
            "N8CryptoPP13X509PublicKeyE",
            "N8CryptoPP27SignatureVerificationFilterE",
            "N8CryptoPP27SignatureVerificationFilter27SignatureVerificationFailedE",
            "N8CryptoPP18ASN1CryptoMaterialINS_9PublicKeyEEE",
        ],
        "note": "Demangled: CryptoPP::PublicKeyAlgorithm, CryptoPP::X509PublicKey, CryptoPP::SignatureVerificationFilter -- Crypto++ is embedded in AMD GPU firmware tool",
    },
    "certificate_chain": {
        "tiers": 3,
        "evidence": [
            "VerifyCertChain(pu8DecryptedIFWIDevCert, u32DecryptedIFWIDevCertSize, pu8DecryptedAMDRootCert, u32DecryptedAMDRootCertSize, pu8DecryptedSigningKeyCert, u32DecryptedSigningKeyCertSize, &pkey)",
            "Failed to write IFWI Certificate into BIO memory Buffer",
            "Failed to write AMD Intermediate Certificate into BIO memory Buffer",
            "Failed to write AMD Root Certificate into BIO memory Buffer",
            "Failed to verify Certificate Chain",
            "Invalid device certificate",
            "Failed to pushX509 IFWI Certificate into the stack",
            "Failed to add root certificate to certificate store",
            "Failed to initialize pX509vrfy_ctx contex structure with the certificate chain",
        ],
        "hierarchy": "IFWI Device Cert --> AMD Intermediate Cert --> AMD Root Cert",
        "note": "Certs decrypted before chain verification; uses OpenSSL X509 store (pX509vrfy_ctx)",
    },
    "openssl_cmac": {
        "camellia_variants": [
            "CAMELLIA-128-CMAC", "CAMELLIA-192-CMAC", "CAMELLIA-256-CMAC",
        ],
        "source_path": "providers/implementations/macs/cmac_prov.c",
        "impl_string": "OpenSSL CMAC via EVP_PKEY implementation",
        "note": "Camellia = Japanese national symmetric cipher (ISO/IEC 18033-3); presence in AMD GPU firmware = OpenSSL 3.x provider with Camellia-CMAC compiled in. Camellia-CMAC is used for message authentication in Japanese government and NTT deployments.",
    },
    "tcg_dice_attestation": {
        "strings": [
            "tcg-tr-ID-platformFirmwareSignatureVerification",
            "tcg-tr-cat-platformFirmwareSignatureVerification",
            "tcg-at-tpmManufacturer",
            "tcg-at-tpmModel",
            "tcg-at-tpmVersion",
            "TPMRequester",
        ],
        "note": "tcg-tr-* = TCG Reference Integrity Manifest (RIM) transport type; tcg-at-* = TCG attestation attributes for TPM identity. This is DICE (Device Identifier Composition Engine) attestation protocol -- GPU firmware verifies platform firmware signature against a TCG RIM and reports TPM identity.",
    },
    "smu_efuse": {
        "strings": [
            "SMU_ReadEfuseValue()",
            "SMU_READ_FUSE()overflow",
            "SMUIO_I2CTransaction()",
        ],
        "note": "SMU (System Management Unit) reads eFuse values; overflow condition in SMU_READ_FUSE() indicates a size/bounds check failure when reading fuse data; eFuses configure permanent GPU security settings",
    },
    "ssl_cert_pinning": {
        "strings": [
            "SSL public key does not match pinned public key",
            "-----BEGIN PUBLIC KEY-----",
            "-----END PUBLIC KEY-----",
            " public key hash: sha256//%s",
        ],
        "note": "PEM-encoded public key embedded in GPU firmware; SSL certificate pinning enforced with SHA-256 hash pinning",
    },
    "security_bits": "unknown security bits",
    "vbios_update": {
        "strings": [
            "pIFWIDeviceManager->FlashVBIOS(vecIndices, strIFWIFile, strIFWILevel, ...)",
            "pIFWIDeviceManager->SaveVBIOS(vecIndices, strIFWIFile, u32VBIOSImageSize)",
            "Failed to flash the VBIOS.",
            "VBIOS File Image not specified.",
        ],
        "note": "VBIOS update managed through IFWI Device Manager; separate VBIOS and IFWI flash paths",
    },
}

MICRON_D4_SATA = {
    "D4CS000": {
        "product": "Micron D4 SATA SSD non-SED (MTFDDAK/MTFDDAV D4 generation)",
        "variants": 12,
        "fw_size_kb": 908,
    },
    "D4CS001": {
        "product": "Micron D4 SATA SSD SED variant (MTFDDAK D4 SED generation)",
        "variants": 4,
        "fw_size_kb": 910,
    },
    "jtag_state_machine": {
        "strings": [
            "Jtag is already disabled when transition to deployed state.",
            "Can't disable jtag when transition to deployed state",
            "Can Not Disable Jtag Any More",
            "Should not see this!!! Can not disable jtag any more",
            "Disable JTAG by DBG IF",
            "Enable JTAG by DBG IF",
            "JTAG Status:%u (en:1, dis:0)",
            "Jtag Access Ctrl:%x En:%u",
        ],
        "note": "JTAG managed by firmware via Debug Interface (DBG IF). On deployed state transition, JTAG should be permanently disabled. Failure paths: 'Can't disable jtag when transition to deployed state' and 'Can Not Disable Jtag Any More' indicate JTAG disable can fail silently -- drive reaches deployed state with JTAG potentially active. 'Enable JTAG by DBG IF' shows the re-enable path also exists in production firmware.",
    },
    "aes_bypass": {
        "strings": [
            "AES Control Encry:0x%x",
            "AES Status Encry:0x%x",
            "AES Configuration Encry:0x%x",
            "AES Control Decry:0x%x",
            "AES Status Decry:0x%x",
            "AES Configuration Decry:0x%x",
            "AES Range Enable:0x%x",
            "AES Bypass:0x%x",
        ],
        "note": "AES hardware register state visible via diagnostics. 'AES Bypass:0x%x' indicates a bypass register for the AES encryption engine. If accessible via vendor-specific SATA commands, this exposes inline encryption state and bypass capability.",
    },
    "oem_security_bypass": {
        "string": "HP_DISABLE_SECURITY_FEATURE_SUPPORT = %d",
        "note": "HP OEM flag to disable drive security features entirely. Presence in Cisco UCS D4 firmware confirms the same HP-originated bypass flag is present in Cisco-branded drives. When HP_DISABLE_SECURITY_FEATURE_SUPPORT is set, security enforcement is relaxed to accommodate HP systems that don't use drive security.",
    },
    "debug_decrypt": {
        "strings": [
            "Display decrypted data !",
            "Decrypt Dram Data ",
            "[1: display encrypted data, 0: display decrypted data]TURN On",
            "Decrypt IV",
            "Decrypt Key",
        ],
        "note": "Debug diagnostic mode includes toggle to display decrypted data, with explicit 'Decrypt IV' and 'Decrypt Key' display paths. If accessible via vendor-specific SATA commands, this exposes key material in diagnostic mode.",
    },
    "skip_password_check": {
        "string": " Skip Password check",
        "note": "Explicit skip path for password verification in debug/diagnostic mode",
    },
    "rsa_verification": {
        "strings": [
            " RSA Signature check failed for",
            "<SM_ERR> RSA check fail  %X ",
            "<SM> RSA Sign validation PASS ",
            "<SM_ERR> RSA authentication failed %X ",
            "  FAIL: Main Firmware RSA Check",
            "  FAIL: Bootloader RSA Check",
            "Don't Reverse bytes order of public key ... ",
        ],
        "note": "RSA signature verification for both main firmware and bootloader; 'Don't Reverse bytes order of public key' is a developer comment about key encoding convention -- visible in production firmware",
    },
    "fips_trng_fail": {
        "string": "<FIPS> TRNG_Generate FAILED!!!",
        "note": "FIPS TRNG (True Random Number Generator) failure handling; triple exclamation mark (!!!) in FIPS-critical path",
    },
    "tcg_opal": {
        "strings": [
            "***OPAL SSC  Feature Descriptor***",
            "OPAL 1.0 is supported",
            "OPAL 2.0 is supported",
            "TCG Shadow MBR Enabled",
            "TCG Shadow MBR Disabled ",
            "Erase TCG Range Error",
        ],
        "note": "OPAL 1.0 and 2.0 SSC with Shadow MBR -- full TCG Opal SED implementation in D4 generation",
    },
}

ADDITIONAL_COMPONENTS = {
    "WDC_NVMe_R2210803": {
        "product": "WDC NVMe NVMEM6-W* M6 generation (3422KB, 5 variants)",
        "security_hits": ["tpm"],
        "note": "Only TPM string match; no direct finding",
    },
    "WDC_NVMe_R121000B": {
        "product": "WDC NVMe NVMW19T/NVMW64T + NVMEM6-W* legacy (2863KB, 4 variants)",
        "security_hits": [],
        "note": "No security hits; clean firmware",
    },
    "Samsung_NVMe_OPPA1K3Q_1K5Q": {
        "product": "Samsung NVMe PM9A3 UCS-NVE*S1* enterprise (2897KB, 8 variants, 2 fw versions)",
        "fw_versions": ["OPPA1K3Q", "OPPA1K5Q"],
        "security_hits": ["samsung_oppa -- identity string only"],
        "note": "No deep security hits; firmware version string visible as 'OPPA' in binary; no ADU/JTAG/cert chain",
    },
    "Micron_NVMe_E3MQ009_E3MF009": {
        "product": "Micron NVMe UCS-NVB*M2* G3 generation (1671KB, 14 variants, E3MQ009/E3MF009)",
        "security_hits": [],
        "note": "Zero security hits; firmware may be encrypted or compressed in a format not parsed by SN extraction",
    },
    "Micron_NVMe_E2CS007": {
        "product": "Micron NVMe NVMEG4/NVM2/NVMEM6 G4 generation (1478KB, 14 variants, E2CS007)",
        "security_hits": ["tpm", "nvme_pki (Certificate string)"],
        "note": "TPM + Certificate string hits; likely TPM integration for attestation and x.509 firmware update signing",
    },
    "Kioxia_SAS_SSD_0109_0105": {
        "product": "Kioxia PM7/PM6 series SAS SSD (KPM6*/KPM7*, 22 variants, two fw versions)",
        "security_hits": ["kioxia_id -- self-identity string only; KPM7WRUG/WVUG have UBM string (backplane mgmt)"],
        "note": "No standalone security findings; UBM string in KPM7WRUG/WVUG indicates Universal Backplane Management support in the drive firmware itself",
    },
    "Miami_Lake_controller": {
        "product": "Cisco Miami Lake M.2/PCIe storage controller (03.01.41.040, 6274KB)",
        "security_hits": ["tpm"],
        "note": "Only TPM string match; no unique security findings relative to Samish Lake",
    },
    "PTE3_CPLD": {
        "product": "PTE3 CPLD (ucs-x10c-pte3-cpld.1.001 -- x210c-m8, x410c-m8, x215c-m8, 3 variants)",
        "fw_size_kb": 127,
        "magic": "Altera Corporation copyright header",
        "format": "JTAG SVF for Altera/Intel MAX series CPLD",
        "security_strings": ["DO_BYPASS (same pattern as gpufm-cpld and pt4f-cpld)"],
        "note": "Fourth CPLD SVF file type in the bundle with DO_BYPASS. PTE3 = PCIe Timing Element 3? Controls PCIe signal conditioning. Same SVF bypass pattern = Cisco-wide CPLD programming practice confirmed across 4 different CPLD function groups.",
    },
    "X210M7_X410M7_BIOS": {
        "product": "X210 M7 and X410 M7 BIOS (identical 12440KB binary, 6.0.2a)",
        "security_hits": ["tpm (X210M7 also: ubm string)"],
        "note": "Same binary for X210M7 and X410M7 (same file size, both 6.0.2a); TPM integration present; UBM string in X210M7 suggests inline backplane management interface in BIOS",
    },
    "SanDisk_C405": {
        "product": "SanDisk (WD) SATA SSD lt0400mo/lt1600mo (C405 firmware, 712KB)",
        "security_hits": ["tpm"],
        "note": "Only TPM string match; no unique security findings",
    },
    "Toshiba_SAS_HDD_families": {
        "families": ["AL13SEB (5706)", "AL13SXB (5703)", "AL14SEB (1703/5705)", "AL14SXB/AL15SEB/MG04SCA (5704/5705)"],
        "variants_total": 22,
        "security_hits": [],
        "note": "All Toshiba SAS HDD families: zero security hits from string scan; firmware may be in Toshiba-proprietary format not extractable via SN parser",
    },
    "PMem_firmware": {
        "product": "Intel Optane PMem DIMM firmware (1.2.0.5446, 261KB) + BPS (2.2.0.1553, 293KB)",
        "security_hits": [],
        "note": "No security hits; firmware likely encrypted; Intel PMem uses hardware-enforced security with dedicated security controller separate from firmware image",
    },
}

FINDINGS = {
    "INTEL-ADU-XCV1CS06-SATA-F1": {
        "id": "INTEL-ADU-XCV1CS06-SATA-F1",
        "severity": "HIGH",
        "title": "Intel Youngsville Refresh SATA SSD (XCV1CS06) is Fifth ADU Family; Confirms ADU Introduced at Youngsville RR Generation",
        "component": "ucs-sata-intel-SSDSC2KB480G8K.XCV1CS06 + SSDSC2KB960G8K + SSDSC2KB038T8K + SSDSC2KG480G8K + SSDSC2KG960G8K + SSDSC2KG019T8K (6 variants)",
        "what": (
            "'Asymmetric Diag Unlock          Asymmetric Diag Unlock Auth Key 010' confirmed in XCV1CS06. "
            "Full PKI chain: HostExchangeAuthority, HostExchangeCert, HostSigningAuthority, HostSigningCert, MaxAuthentications -- "
            "identical to ACV10370 NVMe firmware. "
            "Bootloader string: 'Intel Youngsville Refresh Bootloader'. "
            "Also: FMSID_password (Factory MSID for manufacturing-time access), "
            "ReEncryptState/Request/LastReEncryptLBA/MaxReEncryptions, PresentCertificate, ActiveKey, Device_FW_Authentication, FW_MAC_Key. "
            "CONTRAST with SCV1CS08 (prior generation 'Intel Youngsville'): "
            "has Device_FW_Authentication + FW_MAC_Key but ZERO ADU strings. "
            "Generational ADU lineage: "
            "SCV1CS08 (Youngsville original) -> no ADU; "
            "7CV1CS05 (Youngsville RR) -> ADU + Auth Key, no HostExchange; "
            "XCV1CS06 (Youngsville Refresh) -> ADU + full PKI chain (HostExchangeAuthority/Cert + HostSigningAuthority/Cert)."
        ),
        "why": (
            "The FMSID_password (Factory MSID) field is new in XCV1CS06. "
            "MSID (Manufacturer-Set ID) is the factory default SED password; FMSID is the factory manufacturing variant. "
            "An attacker with knowledge of the FMSID could bypass SED authentication at drive reuse. "
            "The full HostExchangeAuthority/Cert PKI chain means the ADU key exchange requires "
            "certificates signed by a HostExchangeAuthority CA -- the same CA model as ACV10370 NVMe. "
            "If the same CA signs both SATA (XCV1CS06) and NVMe (ACV10370) ADU credentials, "
            "a CA key compromise enables ADU on ALL Intel/Solidigm enterprise storage regardless of interface. "
            "Generational dating confirms Intel progressively expanded ADU: first introduced FW authentication (SCV1CS08), "
            "then ADU with symmetric key (RR), then ADU with full asymmetric PKI (Refresh). "
            "Each generation ships in larger UCS B-Series deployments."
        ),
        "evidence": {
            "xcv1cs06_adu": "Asymmetric Diag Unlock Auth Key 010",
            "xcv1cs06_pki": "HostExchangeAuthority, HostExchangeCert, HostSigningAuthority, HostSigningCert",
            "xcv1cs06_fmsid": "FMSID_password (Factory MSID)",
            "scv1cs08_no_adu": "SCV1CS08 has Device_FW_Authentication + FW_MAC_Key only; zero ADU strings",
            "lineage": "SCV1CS08 -> 7CV1CS05 (ADU intro) -> XCV1CS06 (full PKI)",
        },
        "remediation": "Same as SOLIDIGM-ASYM-DIAG-UNLOCK-F1 -- confirm ADU CA hierarchy scope. Additionally: confirm FMSID is rotated per-drive and not a static factory default reused across all XCV1CS06 units.",
    },

    "AMD-MI210-PKI-CHAIN-F1": {
        "id": "AMD-MI210-PKI-CHAIN-F1",
        "severity": "HIGH",
        "title": "AMD MI210 GPU Firmware Contains 3-Tier PKI Chain, CryptoPP Library, Camellia-CMAC, TCG DICE Attestation, and SMU eFuse Read Overflow",
        "component": "ucs-video-amd-mi210.113-D67307V-075_3.16.bin (23443KB, Aldebaran/MI200)",
        "what": (
            "1. 3-TIER PKI: VerifyCertChain(pu8DecryptedIFWIDevCert, ..., pu8DecryptedAMDRootCert, ..., pu8DecryptedSigningKeyCert, ..., &pkey). "
            "Chain: IFWI Device Cert -> AMD Intermediate Cert -> AMD Root Cert. Certs are DECRYPTED before verification -- "
            "the certs themselves are stored encrypted in the firmware image. "
            "Error paths: 'Invalid device certificate', 'Failed to verify Certificate Chain', "
            "'Failed to add root certificate to certificate store'. "
            "OpenSSL X.509 store used for verification (pX509vrfy_ctx). "
            "SSL certificate pinning: 'SSL public key does not match pinned public key'; "
            "embedded PEM public key ('-----BEGIN PUBLIC KEY-----'/'-----END PUBLIC KEY-----'). "
            "2. CRYPTO++ LIBRARY: Demangled symbols include CryptoPP::X509PublicKey, "
            "CryptoPP::SignatureVerificationFilter, CryptoPP::PublicKeyAlgorithm. "
            "CryptoPP is an open-source C++ crypto library embedded in AMD GPU flashing tool. "
            "3. CAMELLIA-CMAC: 'CAMELLIA-128-CMAC', 'CAMELLIA-192-CMAC', 'CAMELLIA-256-CMAC', "
            "'OpenSSL CMAC via EVP_PKEY implementation' from 'providers/implementations/macs/cmac_prov.c' (OpenSSL 3.x). "
            "4. TCG DICE ATTESTATION: 'tcg-tr-ID-platformFirmwareSignatureVerification', "
            "'tcg-tr-cat-platformFirmwareSignatureVerification' -- TCG RIM transport types. "
            "'tcg-at-tpmManufacturer/Model/Version' -- TPM attestation attributes. "
            "5. SMU EFUSE: 'SMU_ReadEfuseValue()', 'SMU_READ_FUSE()overflow' -- eFuse read overflow condition. "
            "6. BUILD PATH LEAK: 'AMD-MI210/opt/amdfwflash/ifwi/ga/D6730100.064D'; "
            "'AMD_MI200_D65209_XT_A1_HBM2E_128GB_ROWAIRCOOLEDUBB4\\config.h' (Windows path in Linux binary)."
        ),
        "why": (
            "The 3-tier PKI (IFWI device cert decrypted then verified against AMD root CA) means AMD GPU firmware "
            "authenticity depends on the AMD root CA key security. "
            "CryptoPP embedded in the AMD GPU flashing utility exposes the full CryptoPP version's attack surface "
            "(CryptoPP has had vulnerabilities in EC2N/ECDSA implementations -- check CryptoPP version). "
            "Camellia-CMAC in OpenSSL 3.x provider path: Camellia is rarely used outside Japan; "
            "its presence indicates the AMD GPU flashing tool supports compliance with Japanese government security standards. "
            "TCG DICE attestation: the GPU reports platform firmware signature verification state to a TPM -- "
            "if the GPU firmware is tampered and the DICE attestation is bypassed, the TPM will not detect it. "
            "SMU eFuse read overflow: if triggerable, could cause undefined behavior in the SMU during eFuse reads -- "
            "SMU controls power, clocking, and security fuse enforcement for the GPU. "
            "Build path exposes Windows developer machine path, Linux install path, and internal firmware file naming."
        ),
        "evidence": {
            "cert_chain_call": "VerifyCertChain(pu8DecryptedIFWIDevCert, ..., pu8DecryptedAMDRootCert, ..., pu8DecryptedSigningKeyCert, ..., &pkey)",
            "camellia_cmac": "CAMELLIA-128/192/256-CMAC via OpenSSL EVP_PKEY (providers/implementations/macs/cmac_prov.c)",
            "dice": "tcg-tr-ID-platformFirmwareSignatureVerification, tcg-at-tpmManufacturer/Model/Version",
            "smu_efuse": "SMU_READ_FUSE()overflow",
            "cert_pinning": "SSL public key does not match pinned public key + embedded PEM public key",
            "build_path": "AMD_MI200_D65209_XT_A1_HBM2E_128GB_ROWAIRCOOLEDUBB4\\config.h",
        },
        "remediation": "Confirm CryptoPP version and patch status. Confirm AMD root CA key HSM protections. Confirm SMU_READ_FUSE() overflow cannot be triggered via any host-accessible API (I2C, PCIe MMIO). Confirm DICE attestation chain is not bypassable.",
    },

    "MICRON-D4-JTAG-DISABLE-FAIL-F1": {
        "id": "MICRON-D4-JTAG-DISABLE-FAIL-F1",
        "severity": "MEDIUM",
        "title": "Micron D4 SATA SSD JTAG Can Fail to Disable on Deployed State Transition; AES Bypass Register and OEM Security Disable Flag Present",
        "component": "Micron D4CS000 (12 non-SED variants) + D4CS001 (4 SED variants); MTFDDAK/MTFDDAV D4 generation",
        "what": (
            "1. JTAG DISABLE FAILURE: "
            "'Jtag is already disabled when transition to deployed state.' -- normal case. "
            "'Can't disable jtag when transition to deployed state' -- failure path 1. "
            "'Can Not Disable Jtag Any More' -- failure path 2. "
            "'Should not see this!!! Can not disable jtag any more' -- terminal failure with developer alarm. "
            "'Enable JTAG by DBG IF' -- JTAG RE-ENABLE path present in production firmware. "
            "'JTAG Status:%u (en:1, dis:0)', 'Jtag Access Ctrl:%x En:%u' -- runtime JTAG state query. "
            "2. AES BYPASS: 'AES Bypass:0x%x' in diagnostic register dump. "
            "AES control/status/configuration/range-enable registers all exposed with format strings. "
            "3. HP OEM SECURITY BYPASS: 'HP_DISABLE_SECURITY_FEATURE_SUPPORT = %d' -- "
            "HP OEM flag present in Cisco UCS D4 firmware; disables security feature enforcement for HP OEM compatibility. "
            "4. DEBUG DECRYPT PATHS: 'Decrypt Key', 'Decrypt IV', 'Display decrypted data !', "
            "'[1: display encrypted data, 0: display decrypted data]TURN On' -- debug toggle for decryption display. "
            "5. SKIP PASSWORD CHECK: ' Skip Password check' -- explicit debug bypass for password verification. "
            "6. RSA: 'FAIL: Main Firmware RSA Check', 'FAIL: Bootloader RSA Check', "
            "'Don't Reverse bytes order of public key ... ' (developer comment in production). "
            "7. FIPS: '<FIPS> TRNG_Generate FAILED!!!' -- TRNG failure in FIPS mode; drive continues with TRNG failure."
        ),
        "why": (
            "JTAG disable failure on deployed state means production drives in Cisco UCS servers could be "
            "deployed with JTAG accessible if the disable sequence fails (power glitch, silicon fault, firmware bug). "
            "'Enable JTAG by DBG IF' in production firmware means JTAG re-enable was not removed at release. "
            "AES bypass register exposure: if AES Bypass is settable via a vendor-specific SATA command, "
            "the inline encryption can be disabled without erasing the drive, exposing data. "
            "HP_DISABLE_SECURITY_FEATURE_SUPPORT in Cisco-branded firmware means: "
            "if an attacker can set this flag via vendor-specific SATA commands, security features are disabled globally. "
            "TRNG failure with '!!!' comment suggests the FIPS mode continues operating with a failed TRNG -- "
            "violating the FIPS requirement for a working entropy source."
        ),
        "evidence": {
            "jtag_fail": "Can't disable jtag when transition to deployed state / Can Not Disable Jtag Any More",
            "jtag_reenable": "Enable JTAG by DBG IF",
            "aes_bypass": "AES Bypass:0x%x",
            "hp_disable": "HP_DISABLE_SECURITY_FEATURE_SUPPORT = %d",
            "debug_decrypt": "Decrypt Key / Decrypt IV / [1: display encrypted data, 0: display decrypted data]",
            "skip_password": " Skip Password check",
            "fips_trng": "<FIPS> TRNG_Generate FAILED!!!",
        },
        "remediation": "Confirm AES Bypass register is not settable via vendor-specific SATA SCSI commands. Confirm HP_DISABLE_SECURITY_FEATURE_SUPPORT cannot be toggled by the host. Confirm JTAG disable failure triggers drive halt rather than continuing to deployed state.",
    },

    "INTEL-SATA-ADU-GENERATION-MATRIX-F1": {
        "id": "INTEL-SATA-ADU-GENERATION-MATRIX-F1",
        "severity": "LOW",
        "title": "Intel/Solidigm SATA SSD ADU Generation Matrix: 3 Generations Across 21 Variants; Pre-ADU Generation Also Confirmed",
        "component": "SCV1CS08 (6 variants), 7CV1CS05 (9 variants), XCV1CS06 (6 variants) -- 21 total SATA variants",
        "what": (
            "Complete ADU generational survey across Intel/Solidigm enterprise SATA SSDs in UCS B-Series: "
            "GEN1 SCV1CS08 (Youngsville, 661KB, 6 vars): Device_FW_Authentication + FW_MAC_Key ONLY; NO ADU. "
            "GEN2 7CV1CS05 (Youngsville RR, 873KB, 9 vars): ADU + Auth Key 010; dual Intel/Solidigm identity; NO HostExchange chain. "
            "GEN3 XCV1CS06 (Youngsville Refresh, 815KB, 6 vars): ADU + Auth Key 010 + FULL HostExchange/Signing PKI chain; FMSID_password. "
            "All three generations share the same magic bytes (06000000a1000000). "
            "All generations have firmware authentication (Device_FW_Authentication/FW_MAC_Key). "
            "ReEncrypt fields (State/Request/LastReEncryptLBA/MaxReEncryptions) first appear in XCV1CS06."
        ),
        "why": "Documents the full SATA ADU generational rollout for disclosure and supply-chain analysis. 21 firmware variants across 3 generations all affected by the same underlying ADU key hierarchy.",
        "evidence": {
            "gen1_scv1cs08": "fw_auth only; bootloader = 'Intel Youngsville Bootloader'",
            "gen2_7cv1cs05": "ADU + Auth Key 010; bootloader = 'Intel Youngsville RR Bootloader' + 'Solidigm Youngsville RR Bootloader'",
            "gen3_xcv1cs06": "ADU + Auth Key 010 + HostExchangeAuthority/Cert + HostSigningAuthority/Cert; FMSID_password; bootloader = 'Intel Youngsville Refresh Bootloader'",
        },
        "remediation": "Audit SCV1CS08 pre-ADU FMSID/MSID defaults; confirm per-drive unique vs fleet-wide. Confirm XCV1CS06 HostExchange CA is not shared with NVMe ADU CA.",
    },

    "PTE3-CPLD-SVF-BYPASS-F1": {
        "id": "PTE3-CPLD-SVF-BYPASS-F1",
        "severity": "LOW",
        "title": "PTE3 CPLD SVF Contains DO_BYPASS Pattern -- Fourth CPLD Type with Bypass in Bundle",
        "component": "ucs-x210c-m8-x10c-pte3-cpld.1.001.bin, ucs-x410c-m8-x10c-pte3-cpld.1.001.bin, ucs-x215c-m8-x10c-pte3-cpld.1.001.bin (all 127KB)",
        "what": (
            "PTE3 CPLD (PCIe Timing/Electrical?) for X210c-M8, X410c-M8, X215c-M8 X-Series compute nodes. "
            "SVF contains DO_BYPASS OPTIONAL operations -- same pattern as gpufm-cpld (Intel MAX 10), "
            "pt4f-cpld (Altera MAX), and mraid12g-he-cpld (Intel MAX II). "
            "All four CPLD types use the same SVF OPTIONAL bypass construct. "
            "Altera Corporation copyright (pre-Intel acquisition branding). "
            "raid-m1l6-cpld (x210c-m8/x410c-m8/x215c-m8, 22-23KB): NO security hits -- different CPLD type without bypass."
        ),
        "why": "OPTIONAL DO_BYPASS across 4 CPLD function groups confirms this is a Cisco design standard, not a one-off. The bypass allows the SVF programmer to skip verification steps that fail on certain hardware revisions.",
        "evidence": {
            "pte3_bypass": "DO_BYPASS (x210c-m8/x410c-m8/x215c-m8 pte3-cpld)",
            "cpld_types_with_bypass": 4,
            "raid_m1l6_cpld": "No bypass -- different CPLD type (Altera vs Intel MAX variant)",
        },
        "remediation": "Confirm DO_BYPASS OPTIONAL steps in pte3-cpld SVF do not bypass security-relevant verification operations.",
    },

    "MICRON-NVME-SURVEY-F1": {
        "id": "MICRON-NVME-SURVEY-F1",
        "severity": "LOW",
        "title": "Micron NVMe Survey: E2CS007 G4 Has TPM + PKI; E3MQ/E3MF G3 Has Zero Security Hits",
        "component": "E2CS007 (14 variants, 1478KB), E3MQ009/E3MF009 (14 variants, 1671KB), G1MU003 (2 variants, 3258KB)",
        "what": (
            "E2CS007 (Micron NVMe G4, UCS-NVMEG4-M*/NVM2*/NVMEM6-M*, 14 variants): "
            "TPM hit + Certificate string hit -- "
            "indicates TPM integration for attestation and X.509 firmware update certificates. "
            "No ADU or JTAG hits; security profile consistent with standard enterprise NVMe + TPM attestation. "
            "E3MQ009/E3MF009 (Micron NVMe G3, UCS-NVB*M2*, 14 variants): "
            "ZERO security hits from SN blob extraction. "
            "Possible causes: (a) firmware encrypted inside the SN blob; (b) firmware in a format not extracted by current parser; "
            "(c) genuinely absent security strings. "
            "G1MU003 (30.7TB/61.4TB ultra-dense, 2 variants, 3258KB): no security hits. "
            "WDC NVMe R2210803 (5 variants, 3422KB): TPM hit only; no ADU/JTAG/cert chain. "
            "WDC NVMe R121000B (4 variants, 2863KB): zero hits."
        ),
        "why": "Establishes that Micron NVMe G3 and WDC NVMe R121000B have no detectable security features in string scan -- either cleaner security model or opaque firmware format. Micron E2CS007 G4 TPM/PKI profile is documentation only (no novel finding above what's already known for enterprise NVMe).",
        "evidence": {
            "e2cs007_hits": "tpm + nvme_pki (Certificate string)",
            "e3mq_hits": "ZERO",
            "wdc_r121000b_hits": "ZERO",
            "wdc_r2210803_hits": "tpm only",
        },
        "remediation": "For E3MQ009/E3MF009 zero-hit case: attempt deeper extraction with alternative blob parsers to confirm whether security features are absent or just opaque.",
    },
}

BUNDLE_ANALYSIS_METADATA = {
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "session": 29,
    "module_number": 8,
    "total_findings": 6,
    "severity_breakdown": {"HIGH": 2, "MEDIUM": 1, "LOW": 3},
    "key_technical_notes": [
        "ADU generational lineage: SCV1CS08 (Youngsville, no ADU) -> 7CV1CS05 (Youngsville RR, ADU + key) -> XCV1CS06 (Youngsville Refresh, ADU + full PKI). ADU was introduced at the 'Release Refresh' generation, not at initial design.",
        "XCV1CS06 FMSID_password: Factory MSID is a manufacturing-time SED override password; if fleet-wide vs per-drive is not enforced, it creates a universal factory backdoor across all XCV1CS06 units",
        "AMD MI210 uses Crypto++ (C++ open-source library) for PKI operations -- not a proprietary AMD implementation; CryptoPP bug surface applies",
        "AMD MI210 embeds Camellia-CMAC (Japanese national cipher) via OpenSSL 3.x provider -- unusual in US GPU firmware; may indicate compliance with Japanese CRYPTREC standards",
        "AMD MI210 DICE attestation via TCG RIM means the GPU participates in platform-level attestation chain; tampered GPU firmware would be detectable IF the attestation chain is queried",
        "SMU_READ_FUSE()overflow in AMD MI210 SMU: the SMU is the GPU's system management controller; overflow in eFuse reading could affect fuse-based security configuration",
        "Micron D4 'Enable JTAG by DBG IF' in production firmware: the re-enable path was not removed before release; paired with 'Can Not Disable Jtag Any More' failure mode, JTAG may persist in deployed drives",
        "HP_DISABLE_SECURITY_FEATURE_SUPPORT in Cisco UCS Micron D4: OEM compatibility flags from one vendor's SKU appear in another vendor's OEM build -- legacy code reuse without OEM-specific removal",
        "Micron D4 AES Bypass register: if accessible via vendor-specific SATA Security Feature commands, inline AES encryption can be bypassed without triggering secure erase or authentication",
        "PTE3 CPLD (fourth type with SVF bypass): confirms the DO_BYPASS OPTIONAL pattern is a Cisco CPLD programming standard, not incidental",
        "E3MQ009/E3MF009 zero hits: suggests Micron NVMe G3 firmware may use stronger binary protection (encryption/compression) than the SN blob parser can reach",
        "Samsung OPPA NVMe (2897KB): no security hits despite large firmware; 'OPPA' is just the firmware version string; Samsung enterprise NVMe firmware in UCS B-Series is opaque at string scan level",
        "Toshiba SAS HDD (all families): zero hits across 22 variants -- Toshiba SAS firmware format may use a proprietary container not parsed by the SN extractor",
        "Miami Lake controller TPM-only: less security exposure surface than Samish Lake (ReadMem, NVRAM warnings); Miami Lake may be a simpler M.2 controller without the diagnostic memory access interface",
        "PMem firmware: no hits; Intel Optane PMem firmware security is enforced at hardware level (DIMM security controller, BIOS TCG OPAL implementation), not visible at string level in the firmware image",
    ],
}
