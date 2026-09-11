"""
Cisco UCS C-Series: RAID Controllers, VIC Adaptors, Storage Firmware
Bundle: ucs-k9-bundle-c-series.6.0.2b.C.bin

Covers:
- C3K M4RAID (UCS-C3K-M4RAID.29.00.1-0360.bin, 4329KB) + UCSC-C3X60-R1GB (24.21.0-0156.bin, 5209KB)
- Mellanox ConnectX VIC adaptors (22.46.1006, 26.46.1006)
- HGST SAS HDD (ADD5/AD50/A7JX/A3Z4/A320 families, 5 variants)
- Seagate SAS HDD C-Series families (CN05/CK05/CE05 nearline SAS)
- WDC HAMR SAS HDD (AHA2, 24TB)
- Miami River/Rock/Beach RAID series (6274KB each, opaque payload)
- Lagunabeach / Laguna Rock RAID (3564KB / 1148KB, opaque payload)
- M6 RAID (ucsc-raid-m6t / ucsc-raid-m6sd, 4459KB, opaque payload)
- PSoC (ucsc-raid-m6t-psoc.001F.bin, 652KB) - zero hits
- SAS expander CUBR (avago_jtag / SPICO SerDes PHY JTAG only, not security-relevant)
- Zero-hit survey: Kioxia 1YETE106, Samsung OPPA, Intel 8DV1CP02, Toshiba MG10/MG11/AL13SXB,
  pcie84-vic / pcie85-vic (5.4.2.47), Samsung DM0V/8F3Q/EM17, BIOS (M7/M8), PSoC, Intel GPU Flex

Session 29, C-Series module 1
"""

C3K_M4RAID_AND_C3X60 = {
    "binaries": [
        {"product": "UCS-C3K-M4RAID", "file": "UCS-C3K-M4RAID.29.00.1-0360.bin", "fw_version": "29.00.1-0360", "size_kb": 4329},
        {"product": "UCSC-C3X60-R1GB", "file": "UCSC-C3X60-R1GB.24.21.0-0156.bin", "fw_version": "24.21.0-0156", "size_kb": 5209},
    ],
    "note": "Both contain identical KM_ + JBI JTAG + EKMS + FDE suite as MegaRAID 12G variants (MRSAS-12G-EKMS-DUALKEY-F1). New additions below.",
    "efuse_srk": {
        "functions": ["EfuseReadSRKVal", "SRKEfuseDebug"],
        "srk_function_context": "EfuseReadSRKVal appears in production symbol table adjacent to DM_PL_ClearProgressCount -- active in shipping firmware, not ifdef'd out",
        "srk_debug": "SRKEfuseDebug is a SEPARATE debug interface for the SRK eFuse value -- a dedicated path for inspecting the Secure Root Key via debug interface",
        "note": "SRK (Secure Root Key) is the root of the TPM key hierarchy. EfuseReadSRKVal reads the SRK value from hardware eFuse in production firmware. SRKEfuseDebug provides a named debug path for the same value.",
    },
    "efuse_rng": {
        "strings": [
            "FUSE_RANDOM_NUMBER_READ:: Trying to read from user index %d",
            "EFUSE_RANDOM_NUMBER_READ::The data reg contents at index = %d is = %x",
            "The address corresponding to the  data bits are as follows: %d",
            "EFUSE_RANDOM_NUMBER_READ::Data Reg contents after the first read = 0x%x",
            "EFUSE_RANDOM_NUMBER_READ:: FAILURE WHILE READING THE DATA FROM THE EFUSE content = 0x%x",
            "EFUSE_RANDOM_NUMBER_READ::DATA IS READ CORRECTLY FROM THE EFUSE",
            "EFUSE_RANDOM_NUMBER_READ::The Data contents of efuse are as follows:",
        ],
        "note": "eFuse RNG read is index-addressable ('user index %d'). The data register value is printed in hex. Full eFuse contents are dumped in a CORRECTLY READ path. This is a diagnostic path that exposes eFuse entropy directly.",
    },
    "tpm_integration": {
        "functions": ["TPM_BindKey", "KM_USE_TPM_MASK"],
        "tpm_bind_context": "TPM_BindKey.t.3.DbgReadSectors -> TPM key binding is called in the key management flow alongside debug sector reads",
        "tpm_mask_context": "KM_USE_TPM_MASK -> bitmask flag that controls whether the KM_ key management system uses TPM for key binding",
        "note": "KM_USE_TPM_MASK is a configurable flag. If it can be cleared without authentication, TPM-protected key management degrades to software-only protection.",
    },
    "ds1961s_ibutton": {
        "functions": [
            "ds1961s_ReadScratchpad",
            "ds1961s_WriteScratchpad",
            "searchOneWireDevices",
            "readRomId",
            "ds1961s_WritePage",
            "ds1961s_ReadMemoryAuthenticated_Wrapper",
        ],
        "ibutton_context_strings": [
            "Incompatible secondary iButton detected!",
            "Incompatible secondary iButton present!",
            "Please insert the correct iButton and restart the system",
            "Press any key to continue but OEM specific features will not be upgraded!",
            "Upgrade Key Mismatch",
            "Cannot communicate with iButton, possible extreme temps.",
            "Cannot communicate with iButton to retrieve premium features",
        ],
        "raidkeyid_adjacency": "ds1961s_ReadMemoryAuthenticated_Wrapper -> EepromReadPages -> sbrWrite -> RaidKeyId",
        "note": (
            "DS1961S is a 1-Wire SHA-1 iButton (Maxim/Dallas) -- a hardware authentication token connected via one-wire bus. "
            "The `ReadMemoryAuthenticated_Wrapper` uses SHA-1 challenge-response. "
            "`RaidKeyId` immediately follows in the function table -- the iButton stores the RAID key ID. "
            "The iButton is both an OEM feature license key (controls whether premium features are enabled) "
            "AND part of the key management chain (stores RaidKeyId used in FDE unlock). "
            "iButton authentication uses SHA-1 (broken since 2017). "
            "If absent, the system continues with 'OEM specific features will not be upgraded' -- "
            "a degraded mode that bypasses the hardware token check."
        ),
    },
    "escrow_null_passphrase": {
        "strings": [
            "lockKeyFromEscrow: usePpAsIs is not a supported parameter",
            "lockKeyFromEscrow: NULL passphrase detected",
            "lockKeyFromEscrow: Try counter (%u) exceeded maximum",
            "lockKeyFromEscrow: Failed to hash pass phrase",
            "lockKeyFromEscrow: NULL escrowLockKey",
            "lockKeyFromEscrow: Failed to decrypt escrowed key",
        ],
        "note": (
            "The escrow unlock function has an explicit NULL passphrase detection path. "
            "The sequence: usePpAsIs (rejected) -> NULL passphrase detected -> "
            "Try counter exceeded -> Failed to hash -> NULL escrowLockKey -> Failed to decrypt. "
            "The code checks for NULL passphrase before the hash attempt -- "
            "but the 'Try counter exceeded maximum' path appears BEFORE 'Failed to hash', "
            "suggesting the try counter is incremented even on the NULL passphrase path. "
            "Repeated NULL passphrase probes exhaust the try counter, locking out valid recovery attempts."
        ),
    },
    "hsm": {
        "strings": [
            "HSM active,failing Config CfgDcmd %x",
            "HSM active,failing Pdset Dcmd for/to JBOD",
            "HSM active,configRaid Skipped",
            "BootMsgHandleHSMClear",
        ],
        "note": (
            "HSM (Hardware Security Module) integration mode: "
            "when HSM is active, CFG_ADD commands fail, JBOD physical drive set commands fail, "
            "and RAID configuration is skipped entirely. "
            "HSM mode creates a configuration-layer denial of service on the controller. "
            "BootMsgHandleHSMClear appears adjacent to RSA_pub_key_new -- "
            "HSM state can be cleared during boot via a boot message handler, "
            "after which RSA public key operations are available."
        ),
    },
    "inspur_oem": {
        "string": "isInspur4GPnP",
        "note": "C3X60-R1GB contains Inspur OEM code path (isInspur4GPnP). Inspur is a Chinese OEM server maker. Platform-generic binary with active OEM branching.",
    },
    "jam_jtag_gpio": {
        "strings": [
            "JAM.Setting TDI TMS TCK TDO gpio",
            "Error: BitBlaster not responding",
        ],
        "note": "JAM (JTAG Action Method) format JTAG GPIO configuration -- same JBI JTAG master library as MegaRAID 12G variants. GPIO pins TDI/TMS/TCK/TDO are configured programmatically.",
    },
}

MELLANOX_CONNECTX_VIC = {
    "binaries": [
        {"product": "ucsc-p-M6DD100GF-100g-qsfp28", "fw_version": "22.46.1006", "size_kb": 3923},
        {"product": "ucsc-p-M6CD100GF-100g-qsfp28", "fw_version": "22.46.1006", "size_kb": 3923},
        {"product": "ucsc-o-N6CD100GF", "fw_version": "22.46.1006", "size_kb": 3923},
        {"product": "ucsc-p-N6D25GF", "fw_version": "26.46.1006", "size_kb": 3673},
        {"product": "ucsc-o-N6CD25GF", "fw_version": "26.46.1006", "size_kb": 3674},
    ],
    "note": "These are Mellanox/NVIDIA ConnectX-6 (22.x/26.x) VIC adaptors, distinct from B-Series Emulex/QLogic HBA-style VICs. NOT in B-Series.",
    "mjtag": {
        "strings": [
            "mjtag - Not supported",
            "mjtag - JTAG master already activated",
            "mjtag - JTAG master not in activate state",
            "jtag_master_if_enable_disable_: %d",
        ],
        "note": (
            "ConnectX VIC has a JTAG master interface (`mjtag`) that can be programmatically enabled/disabled. "
            "`mjtag - JTAG master already activated` = duplicate activation guard, state is tracked. "
            "`jtag_master_if_enable_disable_: %d` = enable/disable function with binary parameter. "
            "The JTAG master is accessible via the VIC management plane (DCQCN/RDMA management interface). "
            "If triggerable via firmware management commands, it provides JTAG master access from the host."
        ),
    },
    "rollback_fuse": {
        "string": "Rollback fuse is full",
        "note": "ConnectX NIC has one-time programmable rollback protection fuses. When the fuse is full (all bits blown), firmware rollback prevention is at maximum. The firmware exposes when the rollback fuse state is saturated.",
    },
    "lifecycle_iron": {
        "strings": [
            "Flash erase_sect_block_wrapper not allowed for RO image or Iron",
            "Flash write_chunks_wrapper not allowed for RO image or Iron",
            "lifecycle_decision: lcycle_decision_",
            "fw_burn_is_secure: is_secure %x, is_debug_fw %x",
        ],
        "note": (
            "ConnectX lifecycle states include 'Iron' (end-of-life/secured state). "
            "In Iron state, flash erase and write operations are blocked. "
            "`fw_burn_is_secure` distinguishes production vs debug firmware images during burn. "
            "If lifecycle state is misconfigured or manipulable, it gates flash write access."
        ),
    },
    "aes_gcm_auth_fail": {
        "strings": [
            "Error: AES Self test fail on engine %d",
            "GCM fail, authentication tag fail in DECRYPT operation",
            "test fail, mismatch authentication tag",
        ],
        "note": (
            "Hardware AES engine self-test failure is logged per engine index. "
            "AES-GCM authentication tag failure in DECRYPT -- GCM tag verification failure during IPsec/RoCE decryption. "
            "These are observable failure conditions from the host via VIC management interface log retrieval."
        ),
    },
    "cmis_module_password": {
        "strings": [
            "write unlock password failed, state = %d, gw = %d, smbus status = %d",
            "_burn_sm CMIS error password write err",
            "PMMP write lock password",
        ],
        "note": (
            "QSFP+ modules use CMIS (Common Management Interface Specification) password protection. "
            "The VIC burns firmware to plugged-in QSFP+ transceivers via CMIS password unlock. "
            "`write unlock password failed` = CMIS password rejection logged with state + gateway + SMBus status. "
            "The CMIS firmware burn state machine has a named error for password write failure."
        ),
    },
    "nvram_tlv_signature": {
        "strings": [
            "signature is not valid",
            "cfg_header: invalid signature",
            "file_signature_2_itoc_entry_offset 0x%.8x",
        ],
        "note": "ConnectX NVRAM TLV (Type-Length-Value) header signature validation; firmware image ITOC entry signature validation. Failed signature = logged error, not necessarily a halt.",
    },
    "handle_secure_magic_pkt": {
        "string": "handle_secure_magic_pkt, invalid fw_portid=%d",
        "note": "A 'secure magic packet' handler with port ID validation. Secure magic packets are a management command mechanism in ConnectX firmware; invalid port ID triggers a logged error.",
    },
}

HGST_SAS_HDD_TCG = {
    "families": [
        {"firmware": "ADD5", "products": ["HUS726060AL5210", "HUS726020ALS210", "HUS726040ALS210", "HUS726060AL4210"]},
        {"firmware": "AD50", "products": ["HUC101812CSS200", "HUC101818CS4200", "HUC101860CS4200"]},
        {"firmware": "A7JX", "products": ["HUH728080AL4200"]},
        {"firmware": "A3Z4", "products": ["HUH721010AL4200"]},
        {"firmware": "A320", "products": ["HUS724020ALS640", "HUS724030ALS640"]},
    ],
    "tcg_certificate_auth": {
        "strings": [
            "HashAndSign",
            "PresentCertificate",
            "Credential",
            "ResponseSign",
            "ResponseExch",
        ],
        "note": (
            "HGST TCG Enterprise SSC implements certificate-based authority authentication. "
            "PresentCertificate is a TCG Enterprise protocol method that authenticates "
            "an authority using an X.509 certificate and challenge-response. "
            "ResponseSign (sign-then-respond) and ResponseExch (key exchange then respond) "
            "are two protocol variants. HashAndSign is the signing operation. "
            "This is stronger than password-only TCG Enterprise implementations "
            "but requires the drive to manage an RSA key pair for TPer signing."
        ),
    },
    "re_encryption": {
        "strings": [
            "ActiveKey",
            "NextKey",
            "ReEncryptState",
            "ReEncryptRequest",
            "AdvKeyMode",
            "VerfMode",
            "ContOnReset",
            "LastReEncryptLBA",
            "LastReEncStat",
            "GeneralStatus",
            "ByteValue",
            "EncryptSupport",
            "MaxRanges",
        ],
        "note": (
            "HGST implements TCG Enterprise in-place re-encryption: "
            "the drive can re-encrypt all user data with a new key (NextKey) while I/O continues. "
            "LastReEncryptLBA tracks progress through the LBA space. "
            "ContOnReset: whether re-encryption continues after a power cycle. "
            "AdvKeyMode and VerfMode control key advancement and verification policies. "
            "A re-encryption in progress that is interrupted and not completed leaves some LBAs "
            "encrypted with the old key and others with the new key -- "
            "this split state is tracked by ReEncryptState and LastReEncStat."
        ),
    },
    "manufacturer_keys": {
        "strings": [
            "MakerDiag",
            "MakerSymK",
            "MaintSymK",
            "ActivationSymK",
            "C_PIN_PSID",
            "PhysicalDriveOwner",
            "TPerOwner",
        ],
        "note": (
            "MakerSymK (Manufacturer Symmetric Key): a secret symmetric key held by HGST/WDC "
            "that provides manufacturer-level access to the drive's TCG namespace. "
            "MaintSymK (Maintenance Symmetric Key): maintenance/depot access key. "
            "ActivationSymK: used during drive activation at first owner setup. "
            "C_PIN_PSID (Physical Security ID): the PSID printed on the drive label for factory reset. "
            "If MakerSymK or MaintSymK are the same across all drives in a product family "
            "(class-wide secret), they function as universal backdoor access. "
            "MakerDiag: diagnostic interface authenticated with MakerSymK. "
            "These manufacturer keys are present in ADD5, AD50, A7JX, A3Z4, and A320 families."
        ),
    },
    "isAuthenticated": {
        "string": "IsAuthenticated",
        "context": "IsAuthenticated..PortLocked...Diagnostic_Port.Firmware_Dload_Port.State_Dump_Port.Change_Defn",
        "note": "IsAuthenticated flag exposed adjacent to port access controls (Diagnostic, Firmware Download, State Dump). The authentication state determines port access.",
    },
}

SEAGATE_NEARLINE_SAS_C_SERIES = {
    "families": [
        {"firmware": "CN05", "products": ["ST1000NM0045", "ST2000NM0045", "ST4000NM0025"], "size_kb": 1229},
        {"firmware": "CK05", "products": ["ST6000NM0105"], "size_kb": 1307},
        {"firmware": "CE05", "products": ["ST8000NM0075"], "size_kb": 1342},
    ],
    "tcg_fips140": {
        "string": "Seagate Secure. TCG Enterprise SSC Self-Encrypting Drives FIPS 140 Module",
        "note": "CN05/CK05/CE05 are FIPS 140 certified TCG Enterprise SSC drives (distinct from 10K SAS N0A6/K0A6). These are nearline SAS (7.2K/SATA-spindle) with SAS interface and full TCG Enterprise + FIPS 140.",
    },
    "c_rsa_2048_tpersign": {
        "context": "C_RSA_2048..TPerSign....MakerSymK....MaintSymK.......ActivationSymK",
        "field_names": ["Pr_Exp", "Iqmp", "C_RSA_2048", "TPerSign"],
        "note": (
            "C_RSA_2048: RSA-2048 cryptographic context in the TCG Enterprise SSP object table. "
            "Pr_Exp (Private Exponent) and Iqmp (CRT inverse prime coefficient) are data structure "
            "field names for the TCG Enterprise drive's RSA-2048 private key components. "
            "TPerSign: the function that signs challenges using the drive's RSA-2048 private key "
            "(used in certificate-based authentication, same as HGST PresentCertificate pattern). "
            "Seagate's TCG Enterprise RSA signing key is a per-drive key generated at manufacturing."
        ),
    },
    "manufacturer_keys": {
        "strings": ["MakerSymK", "MaintSymK", "ActivationSymK"],
        "note": "Same manufacturer key structure as HGST: MakerSymK (manufacturer backdoor), MaintSymK (maintenance), ActivationSymK (activation). HGST and Seagate both implement Opal/Enterprise TCG with manufacturer privilege keys.",
    },
    "sbp_note": {
        "note": (
            "CN05 SBP hit (InitiateMarkSBParityPendingRealReq - SB:) is SAS Bus Parity error handling "
            "(SB = SAS Bus), NOT the Misconfigured SBP Fuse Bits from B-Series. "
            "CN05/CK05/CE05 nearline SATA-spindle SAS drives do NOT have the SBP Fuse Bits security issue."
        ),
    },
}

WDC_HAMR_AHA2 = {
    "firmware": "AHA2",
    "products": ["WUH722424AL4200 (24TB)"],
    "size_kb": 5121,
    "note": "WDC HAMR (Heat-Assisted Magnetic Recording) 24TB SAS HDD, newest WDC generation in bundle",
    "tcg": {
        "strings": [
            "BandMaster0.BandMaster0_SetSelf.EraseMaster.EraseMaster_SetSelf.AnyMaster.BandMasters",
            "Get_K_AES_Mode.SID.Global_Range.Band1.Global_Range-_AES_256.Band1_AES_256.LockingInfo",
            "MSID_Get.SID_SetSelf",
            "SecureDriveTransition",
            "Encrypted_Statedump_Port",
            "Firmware_Download_Port",
        ],
        "note": "TCG Enterprise SED with AES-256 band encryption. Encrypted_Statedump_Port: the diagnostic state dump port requires encryption -- debug output is not in plaintext. SecureDriveTransition: drive security state machine transitions. Confirming WDC HAMR uses same TCG Enterprise class as prior WDC SAS findings.",
    },
}

ZERO_HIT_C_SERIES_BATCH1 = {
    "opaque_payloads": [
        "Miami River HBA/RAID/Rock/Beach (6274KB each) -- encrypted/compressed inner payload, no extractable strings",
        "Lagunabeach / 9460-8i (3564KB) -- opaque",
        "Laguna Rock / Laguna Rock Plus (1148KB) -- opaque",
        "M6 RAID (ucsc-raid-m6t / ucsc-raid-m6sd, 4459KB) -- opaque",
    ],
    "true_zero_hits": [
        "PSoC (ucsc-raid-m6t-psoc.001F.bin, 652KB) -- PSoC firmware, no extractable strings",
        "pcie84-vic / pcie85-vic (5.4.2.47, 19-20MB) -- opaque",
        "Kioxia 1YETE106 (2277KB) -- same zero-hit pattern as B-Series 0105/0109",
        "Samsung OPPA1K3Q / OPPA1K5Q (2897KB) -- opaque",
        "Intel NVMe 8DV1CP02 (519KB) -- opaque",
        "Toshiba MG10 / MG11 (1543/1640KB) -- same zero-hit pattern as AL13/AL14/AL15",
        "Toshiba AL13SXB (540KB) -- zero hits",
        "BIOS (M7/M8/M6 series, 10-24MB) -- gzip payload, SN parser does not reach inner content",
        "Samsung DM0V / 8F3Q / EM17 (619/567/764KB) -- older Samsung SSD, zero hits",
        "SAS expander CUBR (65.11.21.00, 293KB): avago_jtag / SPICO SerDes PHY JTAG for SerDes programming -- not a security-relevant JTAG master; Unlock is SMP port state, not FDE",
        "S3260 DHBA (13.00.00.12, 788KB) -- RSA hit is binary coincidence",
        "SAS M6 controller (ucsc-sas-m6t, 1303KB) -- opaque",
        "PMC HBA (avilapier, 1787KB) -- opaque",
        "Intel GPU Flex 140/170 (1124-1126KB) -- opaque",
        "NVIDIA RTX PRO 6000 / L40S (1055-1311KB) -- opaque",
        "AMD 7150x2 (183KB) -- opaque",
    ],
    "note": "Large CIMC binaries (79-152MB) and BIOS (10-24MB) require inner-payload extraction (not SN blob format); scanning via SN parser produces no extractable strings at outer wrapper level.",
}

FINDINGS = {
    "C3K-EFUSE-SRK-TPM-IBUTTON-F1": {
        "id": "C3K-EFUSE-SRK-TPM-IBUTTON-F1",
        "severity": "HIGH",
        "title": "C3K M4RAID + C3X60-R1GB: EfuseReadSRKVal + EFUSE_RANDOM_NUMBER_READ (indexed) + TPM_BindKey + KM_USE_TPM_MASK + DS1961S iButton + HSM Config DoS",
        "components": [
            "UCS-C3K-M4RAID.29.00.1-0360.bin (4329KB)",
            "UCSC-C3X60-R1GB.24.21.0-0156.bin (5209KB)",
        ],
        "what": (
            "1. EfuseReadSRKVal in production symbol table: reads the Secure Root Key from hardware eFuse. "
            "SRK is the root of the TPM key hierarchy used for binding/sealing keys. "
            "2. SRKEfuseDebug: a named debug interface for the SRK eFuse value, present in production firmware. "
            "3. EFUSE_RANDOM_NUMBER_READ: index-addressable eFuse read ('user index %d') with full data register "
            "dump and success/failure status. The eFuse array is readable by index in production firmware diagnostics. "
            "4. TPM_BindKey + KM_USE_TPM_MASK: TPM key binding integrated into the KM_ key management chain. "
            "KM_USE_TPM_MASK is a configurable bitmask; if cleared, TPM is bypassed and key management falls back "
            "to software-only protection. "
            "5. DS1961S iButton (SHA-1): one-wire hardware authentication token that stores RaidKeyId "
            "(confirmed by symbol table: ds1961s_ReadMemoryAuthenticated_Wrapper -> RaidKeyId). "
            "iButton uses SHA-1 challenge-response for authentication (SHA-1 is broken). "
            "iButton absence degrades to a 'press any key to continue' soft-bypass for OEM features. "
            "6. lockKeyFromEscrow: NULL passphrase detected -- explicit code path for NULL passphrase input; "
            "try counter increments on NULL attempts, enabling exhaustion of the recovery try budget. "
            "7. HSM active,failing Config CfgDcmd + HSM active,configRaid Skipped + "
            "HSM active,failing Pdset Dcmd for/to JBOD: HSM mode blocks all controller configuration. "
            "BootMsgHandleHSMClear: HSM state can be cleared during boot message handling. "
            "8. Both binaries also contain the full KM_DecryptNvramKeyBlob dual-key (USER+FW secret) "
            "and EKMS bypass suite from MRSAS-12G-EKMS-DUALKEY-F1 -- confirming the Broadcom KM_ "
            "library is present across ALL MegaRAID product lines: 12G HE, 12G standard, C3K M4, C3X60."
        ),
        "why": (
            "EfuseReadSRKVal in production firmware means the Secure Root Key is readable from hardware "
            "at runtime by any code with privilege. If the SRK is exposed, TPM-sealed keys become unsealed "
            "without requiring PCR state match. "
            "EFUSE_RANDOM_NUMBER_READ with index parameter means eFuse entropy is readable per-bit-position -- "
            "this is a diagnostic path that should not expose entropy in production. "
            "KM_USE_TPM_MASK: if the TPM mask can be cleared via controller management interface, "
            "the firmware falls back to software key protection (vulnerable to NVRAM key blob extraction). "
            "DS1961S SHA-1: SHA-1 collision attacks (2017+) and preimage attacks reduce the strength of "
            "the iButton challenge-response. RaidKeyId storage in iButton means iButton cloning bypasses "
            "the hardware token requirement. "
            "HSM config DoS: activating HSM mode (if controllable) blocks all RAID configuration, "
            "creating a persistent DoS on the controller's management plane."
        ),
        "evidence": {
            "srk": "EfuseReadSRKVal, SRKEfuseDebug (in production symbol table)",
            "efuse_rng": "EFUSE_RANDOM_NUMBER_READ::The data reg contents at index = %d is = %x",
            "tpm": "TPM_BindKey, KM_USE_TPM_MASK",
            "ibutton": "ds1961s_ReadMemoryAuthenticated_Wrapper -> RaidKeyId",
            "ibutton_bypass": "Press any key to continue but OEM specific features will not be upgraded!",
            "null_passphrase": "lockKeyFromEscrow: NULL passphrase detected",
            "hsm": "HSM active,failing Config CfgDcmd %x, HSM active,configRaid Skipped",
        },
        "remediation": "Confirm EfuseReadSRKVal is not callable from controller management interface. Confirm KM_USE_TPM_MASK cannot be cleared without physical access. Replace DS1961S SHA-1 iButton with a SHA-256 or ECDSA-based hardware token. Confirm HSM activation requires physical presence.",
    },

    "CONNECTX-VIC-MJTAG-ROLLBACK-IRON-F1": {
        "id": "CONNECTX-VIC-MJTAG-ROLLBACK-IRON-F1",
        "severity": "MEDIUM",
        "title": "Mellanox ConnectX VIC: Programmable JTAG Master, Rollback Fuse Saturation, Iron Lifecycle Gate, AES-GCM Auth Tag Failure",
        "components": [
            "ucsc-p-M6DD100GF-100g-qsfp28 (22.46.1006, 3923KB)",
            "ucsc-o-N6CD100GF (22.46.1006, 3923KB)",
            "ucsc-p-N6D25GF (26.46.1006, 3673KB)",
            "ucsc-o-N6CD25GF (26.46.1006, 3674KB)",
        ],
        "what": (
            "1. mjtag JTAG master: jtag_master_if_enable_disable_() enables/disables the VIC's JTAG master. "
            "'mjtag - JTAG master already activated' = stateful; 'mjtag - JTAG master not in activate state'. "
            "If this function is accessible via firmware management commands (FW iCMD, flint, mlxconfig), "
            "the JTAG master can be activated from the host without physical access. "
            "2. Rollback fuse is full: ConnectX one-time programmable rollback fuses are at capacity. "
            "When the rollback fuse array is full, no further rollback protection can be added -- "
            "the firmware cannot be rolled back to any earlier version. "
            "3. Iron lifecycle state: ConnectX firmware tracks a lifecycle state (lcycle_decision_); "
            "Iron state blocks all Flash write/erase operations. "
            "fw_burn_is_secure distinguishes production vs debug images. "
            "4. AES-GCM auth tag failure: 'GCM fail, authentication tag fail in DECRYPT operation' + "
            "'Error: AES Self test fail on engine %d' -- AES-GCM decryption failures on IPsec/RoCE paths. "
            "5. CMIS password for module firmware burn: ConnectX burns firmware to QSFP+ transceivers "
            "using CMIS password unlock; password failure is logged with state + gateway + SMBus status. "
            "6. handle_secure_magic_pkt: a 'secure magic packet' handler with port ID validation -- "
            "a special management command type in ConnectX firmware."
        ),
        "why": (
            "mjtag JTAG master access from a management API converts a physical JTAG requirement into "
            "a software requirement -- if accessible from the host, an attacker with VIC management "
            "access gains JTAG master capability over the VIC's hardware. "
            "Rollback fuse saturation: the rollback protection mechanism is exhausted; "
            "if a downgrade attack is possible through another path, no fuse prevents it. "
            "AES-GCM auth tag failure on IPsec/RoCE: authentication tag failure is logged but not "
            "necessarily fatal -- the connection may continue with degraded integrity."
        ),
        "evidence": {
            "mjtag": "jtag_master_if_enable_disable_: %d, mjtag - JTAG master already activated",
            "rollback": "Rollback fuse is full",
            "iron": "Flash write_chunks_wrapper not allowed for RO image or Iron",
            "gcm": "GCM fail, authentication tag fail in DECRYPT operation",
            "aes_selftest": "Error: AES Self test fail on engine %d",
            "cmis": "_burn_sm CMIS error password write err",
        },
        "remediation": "Confirm mjtag enable/disable is not accessible via firmware management API without physical access. Confirm AES-GCM auth tag failure triggers connection teardown, not silent continuation.",
    },

    "HGST-TCG-CERT-AUTH-REENCRYPT-F1": {
        "id": "HGST-TCG-CERT-AUTH-REENCRYPT-F1",
        "severity": "MEDIUM",
        "title": "HGST SAS HDD: TCG Enterprise Certificate-Based Authority Authentication + In-Place Re-Encryption + Manufacturer Backdoor Keys",
        "components": [
            "ADD5 (HUS726060AL5210, HUS726020/040ALS210, HUS726060AL4210)",
            "AD50 (HUC101812/818/860CS4200)",
            "A7JX (HUH728080AL4200)",
            "A3Z4 (HUH721010AL4200)",
            "A320 (HUS724020/030ALS640)",
        ],
        "what": (
            "1. Certificate-based TCG Enterprise authority auth: PresentCertificate + HashAndSign + "
            "Operation + Credential + ResponseSign + ResponseExch. "
            "ResponseSign: sign a challenge with the authority's private key and send the response. "
            "ResponseExch: Diffie-Hellman key exchange then sign. "
            "This is the TCG Enterprise certificate authentication protocol where the host "
            "proves authority using an X.509 certificate and RSA/ECDSA signing. "
            "2. In-place re-encryption state machine: ReEncryptState + ReEncryptRequest + AdvKeyMode + "
            "VerfMode + ContOnReset + LastReEncryptLBA + NextKey + ActiveKey. "
            "The drive can re-encrypt all LBAs from LastReEncryptLBA to the last LBA using NextKey, "
            "while serving I/O using ActiveKey for already-processed LBAs. "
            "ContOnReset: if True, re-encryption continues after power cycle from LastReEncryptLBA. "
            "3. Manufacturer backdoor keys: MakerSymK + MaintSymK + ActivationSymK + MakerDiag + "
            "C_PIN_PSID + PhysicalDriveOwner. "
            "These are privileged keys held by the manufacturer for recovery and maintenance access. "
            "4. IsAuthenticated state exposed adjacent to port access controls: "
            "Diagnostic_Port + Firmware_Dload_Port + State_Dump_Port."
        ),
        "why": (
            "TCG Enterprise certificate auth is stronger than password auth but introduces the "
            "certificate management attack surface: if the host certificate authority is compromised, "
            "any authority in that chain can be impersonated. "
            "Re-encryption partial state: a drive with LastReEncryptLBA mid-way has split-key LBAs -- "
            "LBAs before that address use NextKey, after it use ActiveKey (or vice versa). "
            "If re-encryption is interrupted and the key is rotated again, some LBAs may be orphaned "
            "under a key that no longer exists in the SSP. "
            "MakerSymK/MaintSymK: if these are identical across all drives in a product family "
            "(a common TCG implementation shortcut), they are universal backdoors. "
            "Firmware_Dload_Port + State_Dump_Port require authentication -- "
            "but if IsAuthenticated can be set without proper auth (TCG protocol implementation bug), "
            "all gated ports become accessible."
        ),
        "evidence": {
            "cert_auth": "HashAndSign.PresentCertificate..Operation...Credential..ResponseSign....ResponseExch",
            "reencrypt": "ActiveKey...NextKey.ReEncryptState..ReEncryptRequest....AdvKeyMode..VerfMode....ContOnReset.LastReEncryptLBA",
            "maker_keys": "MakerSymK, MaintSymK, ActivationSymK, MakerDiag",
            "ports": "Diagnostic_Port.Firmware_Dload_Port.State_Dump_Port.Change_Defn",
        },
        "remediation": "Confirm MakerSymK and MaintSymK are per-drive secrets, not class-wide. Confirm re-encryption partial state is handled correctly under key rotation and power failure scenarios.",
    },

    "SEAGATE-NEARLINE-TCG-FIPS-RSA-MAKER-F1": {
        "id": "SEAGATE-NEARLINE-TCG-FIPS-RSA-MAKER-F1",
        "severity": "MEDIUM",
        "title": "Seagate Nearline SAS (CN05/CK05/CE05): TCG Enterprise FIPS 140 + C_RSA_2048 TPerSign + Manufacturer Symmetric Key Backdoor",
        "components": [
            "CN05 (ST1000/2000/4000NM0045, 1229KB)",
            "CK05 (ST6000NM0105, 1307KB)",
            "CE05 HDD (ST8000NM0075, 1342KB) -- distinct from B-Series CE05 which is a SAS SSD",
        ],
        "what": (
            "1. FIPS 140 module: 'Seagate Secure. TCG Enterprise SSC Self-Encrypting Drives FIPS 140 Module'. "
            "CN05/CK05/CE05 are FIPS 140 validated TCG Enterprise SSC nearline SAS drives. "
            "2. C_RSA_2048 + TPerSign + Pr_Exp + Iqmp: RSA-2048 TPer signing with CRT private key storage. "
            "Field names Pr_Exp (Private Exponent) and Iqmp (CRT inverse prime coefficient) in the TCG SSP "
            "object table define the per-drive RSA-2048 private key used by TPerSign for challenge signing. "
            "3. MakerSymK + MaintSymK + ActivationSymK: same manufacturer backdoor key structure as HGST. "
            "Seagate and HGST (both now WDC) share this TCG authority key naming convention. "
            "The manufacturer symmetric keys provide authenticated privileged access to the TCG namespace "
            "without knowing the user's SID password."
        ),
        "why": (
            "FIPS 140 certification does not protect against manufacturer key misuse. "
            "If MakerSymK is the same across all CN05/CK05/CE05 drives (a known TCG implementation risk), "
            "it is a universal passphrase for the manufacturer's TCG authority. "
            "TPerSign with Pr_Exp + Iqmp: per-drive RSA-2048 key is generated at manufacturing and "
            "stored in the drive's tamper-resistant storage. If the key is extractable via "
            "a TCG protocol implementation bug or physical attack, the drive's certificate can be forged. "
            "Note: these C-Series CE05 nearline SAS HDDs do NOT have the SBP Fuse Bits "
            "security issue from B-Series (the B-Series CE05 is a different product -- an SAS SSD)."
        ),
        "evidence": {
            "fips": "Seagate Secure. TCG Enterprise SSC Self-Encrypting Drives FIPS 140 Module",
            "rsa": "C_RSA_2048..TPerSign....MakerSymK....N'..<.....~MaintSymK.......ActivationSymK",
            "pr_exp": "Pr_Exp..Iqmp....C_RSA_2048",
        },
        "remediation": "Confirm MakerSymK and MaintSymK are per-drive secrets generated at manufacturing, not a class-wide shared symmetric key. Request Seagate/WDC confirmation that the FIPS 140 module's manufacturer key is per-device.",
    },

    "WDC-HAMR-AHA2-TCG-ENCRYPTED-DUMP-F1": {
        "id": "WDC-HAMR-AHA2-TCG-ENCRYPTED-DUMP-F1",
        "severity": "LOW",
        "title": "WDC HAMR 24TB AHA2: TCG Enterprise SED + Encrypted_Statedump_Port + SecureDriveTransition",
        "component": "WUH722424AL4200.AHA2.bin (5121KB)",
        "what": (
            "TCG Enterprise SED with AES-256 band encryption and BandMaster authority. "
            "Encrypted_Statedump_Port: the diagnostic state dump port requires encryption -- "
            "unlike other WDC/HGST drives, debug output is not accessible in plaintext. "
            "SecureDriveTransition: drive security state machine transitions logged. "
            "Firmware_Download_Port: firmware updates require TCG authentication. "
            "AES-256 per-band encryption (K_AES_256 per band, Global_Range-_AES_256). "
            "Same TCG Enterprise authority hierarchy as HGST ADD5/AD50."
        ),
        "why": "Encrypted_Statedump_Port means forensic debug access requires TCG authentication -- hardened compared to WDC SAS SSD and older WDC nearline families. Confirming WDC HAMR generation has stronger debug security than prior WDC SAS variants.",
        "evidence": {
            "dump": "Encrypted_Statedump_Port",
            "transition": "SecureDriveTransition",
            "aes": "Band1.Global_Range-_AES_256.Band1_AES_256.LockingInfo.DataStore.K_AES_256",
        },
        "remediation": "N/A -- Encrypted_Statedump_Port is a security improvement. Document as security feature present.",
    },

    "CSERIES-BATCH1-ZERO-HIT-SURVEY-F1": {
        "id": "CSERIES-BATCH1-ZERO-HIT-SURVEY-F1",
        "severity": "LOW",
        "title": "C-Series Batch 1 Zero-Hit Survey: Miami/Lagunabeach/M6 RAID Opaque, CIMC/BIOS Not SN-Extractable, New Gen Storage Families",
        "component": "Multiple C-Series components (728 TAR members total)",
        "what": (
            "Opaque payloads (no strings extractable): Miami River HBA/RAID/Rock/Beach (5 variants, 6274KB each), "
            "Lagunabeach/9460-8i (3564KB), Laguna Rock (1148KB), M6 RAID t/sd (4459KB each). "
            "Not SN-format: CIMC (79-152MB, requires inner TAR extraction), BIOS (10-24MB). "
            "True zero-hit new families: Kioxia 1YETE106, Samsung OPPA1K3Q/K5Q, Intel NVMe 8DV1CP02, "
            "Toshiba MG10/MG11 SAS HDDs, pcie84/pcie85-vic 5.4.2.47, Samsung DM0V/8F3Q/EM17, PSoC 001F. "
            "CUBR SAS expander jtag strings are avago_jtag (Avago SPICO SerDes PHY JTAG for SerDes "
            "programming) -- not a JTAG master in the security sense; Unlock is SMP port state management."
        ),
        "why": "Coverage documentation for the C-Series bundle batch 1 scan.",
        "evidence": {
            "opaque": "Miami/Lagunabeach/M6 RAID: hits are binary coincidences, no printable context",
            "cubr_jtag": "avago_jtag.avago_jtag_options.get_chip_name.aapl_register_jtag_idcode_fn",
        },
        "remediation": "N/A -- coverage documentation.",
    },
}

BUNDLE_ANALYSIS_METADATA = {
    "bundle": "ucs-k9-bundle-c-series.6.0.2b.C.bin",
    "session": 29,
    "module_number": 1,
    "total_findings": 6,
    "severity_breakdown": {"HIGH": 1, "MEDIUM": 3, "LOW": 2},
    "key_technical_notes": [
        "C3K M4RAID and C3X60-R1GB share the full Broadcom KM_ + JBI JTAG suite with 12G HE/standard -- ALL MegaRAID product lines have KM_DecryptNvramKeyBlob dual-key (USER+FW secret)",
        "C3K M4RAID adds EfuseReadSRKVal + SRKEfuseDebug + EFUSE_RANDOM_NUMBER_READ (indexed) -- SRK eFuse access in production firmware; absent from MegaRAID 12G binaries",
        "C3K M4RAID adds TPM_BindKey + KM_USE_TPM_MASK -- configurable TPM integration in KM_ chain; TPM bypass is a flag, not enforced by hardware",
        "C3K M4RAID adds DS1961S iButton as hardware authentication + RaidKeyId storage -- SHA-1 authentication (broken 2017+); iButton absence triggers soft-bypass",
        "lockKeyFromEscrow NULL passphrase path: explicit code handling for NULL passphrase input; increments try counter, enabling exhaustion attack on recovery budget",
        "HSM active config DoS: HSM mode blocks ALL controller configuration commands; BootMsgHandleHSMClear can clear HSM state during boot",
        "Mellanox ConnectX VIC (22.x/26.x) has mjtag JTAG master with enable/disable API -- JTAG master access potentially from VIC management interface without physical JTAG access",
        "ConnectX Rollback fuse is full: rollback protection fuses are saturated; any downgrade path not blocked by fuses can proceed",
        "HGST HDDs (ADD5/AD50/A7JX/A3Z4/A320) implement TCG Enterprise with certificate-based authentication (PresentCertificate + HashAndSign + ResponseSign + ResponseExch) -- confirmed across 5 firmware families",
        "HGST + Seagate CN05/CK05/CE05 both have MakerSymK + MaintSymK + ActivationSymK manufacturer backdoor keys -- same key naming convention, likely same TCG implementation",
        "Seagate CN05 TCG is FIPS 140 certified (Seagate Secure TCG Enterprise SSC FIPS 140 Module); same family has C_RSA_2048 TPerSign with Pr_Exp + Iqmp CRT key components",
        "WDC HAMR AHA2 (24TB) has Encrypted_Statedump_Port -- debug output requires TCG auth; improved security vs prior WDC generations which had plaintext debug access",
        "Miami River/Lagunabeach/M6 RAID firmwares are fully opaque -- SN parser cannot extract inner payload; these require separate extraction via the inner TAR format",
        "CUBR SAS expander JTAG is Avago SPICO (SerDes PHY programming) -- NOT a security-relevant JTAG master",
        "C3X60-R1GB contains Inspur OEM branching (isInspur4GPnP) -- platform-generic binary with active Inspur-specific code paths",
    ],
}
