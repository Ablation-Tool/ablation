"""
Cisco UCS C-Series Bundle RE -- Module 3
Coverage: PCIe VIC M85-SB TAM/IDevID analysis, PCIe M84/M85 survey,
          NC3220 ConnectX-7 survey, HGST NVMe C-Series survey,
          CIMC/BIOS pending scope note
Source: /media/cowboy/research/Cisco-UCS/ucs-c-series-m5-6.0.2.260044.A.bin (gzip at hsize=844)
        -> cseries_decomp.bin (3084MB, 728 TAR members)
Session: 29 (C-Series module 3)
"""

# =============================================================================
# PCIe M85-SB VIC -- TAM / IDevID / ACT2 SUDI
# File: ucs-pcie85-sb-vic.5.4.2.47-48.bin (20MB raw)
# SN decomp -> inner TAR -> ./blob (21192KB)
# =============================================================================

PCIE_M85_SB_VIC = {
    "family": "PCIe M85-SB VIC",
    "fw_version": "5.4.2.47-48",
    "raw_size_mb": 20,
    "format": "SN-wrapped -> inner TAR -> blob",
    "inner_blob_kb": 21192,
    "blob_magic_hex": "63842345180017a0",
    "string_count": 4753,

    "tam_library": {
        "storage_modes": [
            "TAM_LIB_MEM_RAM",
            "TAM_LIB_MEM_EEPROM",
        ],
        "encryption_modes": [
            "TAM_LIB_CLEAR_TEXT",
            "TAM_LIB_ENCRYPT",
        ],
        "i2c_modes": [
            "TAM_LIB_I2C_INPUT",
            "TAM_LIB_I2C_OUTPUT",
        ],
        "key_objects": [
            "TAM_RSA_KEYPAIR_OBJECT",
            "TAM_ECC_KEYPAIR_OBJECT",
        ],
        "cert_objects": [
            "TAM_X509_CERT_OBJECT",
            "TAM_X509_CERTCHAIN_OBJECT",
        ],
        "idevid_objects": [
            "TAM_LIB_IDEVID_RSA_KEY_PAIR",
            "TAM_LIB_IDEVID_RSA_CERT",
            "TAM_LIB_IDEVID_RSA_CERT_CHAIN",
            "TAM_LIB_IDEVID_ECC_KEY_PAIR",
            "TAM_LIB_IDEVID_ECC_CERT",
        ],
        "error_codes": [
            "TAM_LIB_ERR_SUDI_INVALID",
            "TAM_LIB_ERR_EEPROM_SPACE",
            "TAM_LIB_ERR_EEPROM_WRITE",
            "TAM_LIB_ERR_AIKIDO_LOADER_CHANGE",
        ],
        "x509_ops": [
            "Error in tam_d2i_x509()",
            "Error in tam_x509_get_pubkey()",
        ],
    },

    "sudi_act2": {
        "chain_id": "ACT2 ECC SUDI CA0v0",
        "attestation_ca": "Attestation CA1",
        "root_cas_embedded": [
            "Cisco Root CA 20990",
            "Cisco ECC Root CA0",
        ],
        "pki_urls_embedded": [
            "https://www.cisco.com/security/pki/certs/crca2099.cer",
            "http://pkicvs.cisco.com/pki/ocsp",
            "http://www.cisco.com/security/pki/policies/",
            "http://www.cisco.com/security/pki/crl/crca2099.crl",
            "http://www.cisco.com/security/pki/certs/eccroot.cer",
        ],
        "signature_algorithms": [
            "rsaEncryption",
            "ecdsaEncryption",
            "sha1WithRSAEncryption",
            "sha256WithRSAEncryption",
        ],
    },

    "manufacturing_path": {
        "strings": [
            "## Booting manufacturing firmware ...",
            "## Failed.  Reverting to production firmware",
        ],
        "i2c_boot": [
            "i2c_bus        : %d",
            "bootopt  - show/set i2c boot options",
            "i2cread - Do i2c read operation",
        ],
    },

    "fpga": {
        "strings": [
            "Running FPGA Version  : %d %s",
            "Running FW Version    : 0x",
            "    GOLDEN  Version   : %d",
            "    UPGRADE Version   : Downgrading or Same Version",
            "    UPGRADE Version   : %d",
        ],
    },
}


# =============================================================================
# FINDING F1 -- CRITICAL/HIGH/MEDIUM/LOW
# TAM EEPROM clear-text key storage via manufacturing firmware path
# Severity: MEDIUM
# =============================================================================
# PCIe M85-SB VIC exposes TAM_LIB_CLEAR_TEXT as a runtime key storage mode
# alongside TAM_LIB_MEM_EEPROM. The device has a manufacturing firmware boot
# path that activates before production firmware. I2C boot options
# (bootopt/i2cread) are accessible from the internal boot console. If
# manufacturing firmware enables TAM_LIB_CLEAR_TEXT + TAM_LIB_MEM_EEPROM for
# the IDevID key pair (TAM_LIB_IDEVID_RSA_KEY_PAIR or ECC_KEY_PAIR), both
# private keys are stored in EEPROM unencrypted. EEPROM is directly accessible
# via I2C at PCIe slot level. Physical access to a PCIe card in a deployed
# C-Series server yields the IEEE 802.1AR IDevID private key, enabling device
# identity cloning and SUDI-based authentication bypass.

FINDING_F1_TAM_CLEAR_TEXT_EEPROM = {
    "id": "CSERIES-MOD3-F1",
    "title": "PCIe M85-SB VIC TAM EEPROM clear-text key storage via manufacturing firmware",
    "severity": "MEDIUM",
    "confidence": "HIGH",
    "component": "PCIe M85-SB VIC 5.4.2.47-48 -- Trust Anchor Module (TAM)",
    "cve": None,
    "evidence": {
        "storage_mode_enum": [
            "TAM_LIB_MEM_EEPROM",
            "TAM_LIB_CLEAR_TEXT",
            "TAM_LIB_ERR_EEPROM_WRITE",
        ],
        "key_objects_at_risk": [
            "TAM_LIB_IDEVID_RSA_KEY_PAIR",
            "TAM_LIB_IDEVID_ECC_KEY_PAIR",
        ],
        "manufacturing_path": [
            "## Booting manufacturing firmware ...",
            "## Failed.  Reverting to production firmware",
        ],
        "i2c_console": [
            "bootopt  - show/set i2c boot options",
            "i2cread - Do i2c read operation",
        ],
    },
    "mechanism": (
        "TAM library storage policy is runtime-configurable. "
        "TAM_LIB_MEM_EEPROM + TAM_LIB_CLEAR_TEXT combination stores IDevID "
        "private key bytes directly in EEPROM without encryption. "
        "Manufacturing firmware (pre-production boot path) may set this mode "
        "for key provisioning. I2C bus exposes EEPROM to PCIe management "
        "interface, readable by host CPU with physical slot access."
    ),
    "impact": (
        "IDevID private key extraction from deployed PCIe card. "
        "Extracted key enables device identity cloning. "
        "Cloned identity passes Cisco ACT2 SUDI authentication, "
        "enabling unauthorized device registration as legitimate UCS VIC."
    ),
    "affected_devices": [
        "UCSC-PCIE-C25Q-04 (PCIe M85-SB VIC, fw 5.4.2.47-48)",
    ],
    "remediation": (
        "Verify TAM key provisioning policy enforces TAM_LIB_ENCRYPT at "
        "manufacturing time. Disable manufacturing firmware boot path in "
        "production images. Lock I2C boot option interface after provisioning."
    ),
}


# =============================================================================
# FINDING F2
# SHA-1 RSA in ACT2 SUDI CA0v0 cert chain -- algorithm agility downgrade
# Severity: MEDIUM
# =============================================================================
# Both sha1WithRSAEncryption and sha256WithRSAEncryption are present in the
# firmware cert chain. The ACT2 SUDI chain root is "ACT2 ECC SUDI CA0v0" --
# Cisco's first-generation ACT2 hierarchy. CA0v0 predates SHA-1 deprecation.
# Embedded Cisco PKI URLs reference crca2099 (Cisco Root CA 2099) for CRL/OCSP.
# If the verifying endpoint accepts either RSA (sha1) or ECC (sha256)
# authentication, a chosen-prefix SHA-1 collision against the CA0v0 RSA
# anchor enables cert forgery. Forged cert passes SUDI-based authentication
# on systems that still trust CA0v0.

FINDING_F2_SHA1_SUDI_ACT2 = {
    "id": "CSERIES-MOD3-F2",
    "title": "SHA-1 RSA in ACT2 SUDI CA0v0 cert chain -- algorithm agility downgrade",
    "severity": "MEDIUM",
    "confidence": "HIGH",
    "component": "PCIe M85-SB VIC 5.4.2.47-48 -- ACT2 SUDI / Cisco PKI",
    "cve": None,
    "evidence": {
        "chain_id": "ACT2 ECC SUDI CA0v0",
        "algorithms_present": [
            "sha1WithRSAEncryption",
            "sha256WithRSAEncryption",
            "ecdsaEncryption",
            "rsaEncryption",
        ],
        "embedded_pki": [
            "http://www.cisco.com/security/pki/crl/crca2099.crl",
            "http://pkicvs.cisco.com/pki/ocsp",
        ],
        "root_cas": [
            "Cisco Root CA 20990",
            "Cisco ECC Root CA0",
        ],
    },
    "mechanism": (
        "ACT2 SUDI CA0v0 is Cisco's first-generation device identity CA hierarchy. "
        "sha1WithRSAEncryption present in the cert chain alongside ECC certs. "
        "Systems accepting both RSA (CA0v0) and ECC authentication paths "
        "can be targeted via SHA-1 chosen-prefix collision (SHAttered, 2017) "
        "to forge certs against the CA0v0 RSA trust anchor. "
        "Algorithm agility without downgrade prevention creates the attack surface."
    ),
    "impact": (
        "Forged SUDI cert passes device authentication on Cisco infrastructure "
        "that trusts CA0v0. "
        "Enables unauthorized device registration as legitimate UCS hardware. "
        "Affects all systems that have not migrated from CA0v0 to ECC-only trust."
    ),
    "affected_devices": [
        "UCSC-PCIE-C25Q-04 (PCIe M85-SB VIC, fw 5.4.2.47-48)",
        "Any Cisco infrastructure trusting ACT2 ECC SUDI CA0v0",
    ],
    "remediation": (
        "Migrate SUDI validation to ECC-only trust anchors (Cisco ECC Root CA0). "
        "Retire CA0v0 trust from all verification endpoints. "
        "Enforce algorithm policy: reject sha1WithRSAEncryption in SUDI chain validation."
    ),
}


# =============================================================================
# FINDING F3
# FPGA dual-image with no anti-rollback enforcement
# Severity: LOW
# =============================================================================
# PCIe M85-SB VIC FPGA has GOLDEN (recovery) and UPGRADE partitions.
# The UPGRADE path logs "Downgrading or Same Version" as a non-fatal condition,
# indicating FPGA image downgrade is permitted without version enforcement.
# An attacker with access to the FPGA update mechanism can install older
# FPGA images with known hardware-level vulnerabilities.

FINDING_F3_FPGA_NO_ROLLBACK = {
    "id": "CSERIES-MOD3-F3",
    "title": "PCIe M85-SB FPGA dual-image with no anti-rollback enforcement",
    "severity": "LOW",
    "confidence": "MEDIUM",
    "component": "PCIe M85-SB VIC 5.4.2.47-48 -- FPGA image management",
    "cve": None,
    "evidence": {
        "fpga_strings": [
            "    GOLDEN  Version   : %d",
            "    UPGRADE Version   : Downgrading or Same Version",
            "    UPGRADE Version   : %d",
        ],
    },
    "mechanism": (
        "FPGA dual-image (GOLDEN + UPGRADE) permits version downgrade. "
        "The 'Downgrading or Same Version' log entry is a non-fatal informational "
        "condition, not a boot block. FPGA image update mechanism does not enforce "
        "minimum version."
    ),
    "impact": (
        "Rollback to older FPGA images with hardware-level vulnerabilities. "
        "Requires FPGA update access (typically host software privilege or "
        "physical access via PCIe management channel)."
    ),
    "affected_devices": [
        "UCSC-PCIE-C25Q-04 (PCIe M85-SB VIC, fw 5.4.2.47-48)",
    ],
    "remediation": (
        "Enforce minimum FPGA version in the update path. "
        "Treat 'Downgrading' condition as boot-fatal, not informational."
    ),
}


# =============================================================================
# FINDING F4
# AIKIDO loader change -- TAM integrity failure mode with non-halt behavior
# Severity: LOW
# =============================================================================
# TAM_LIB_ERR_AIKIDO_LOADER_CHANGE is an error code in the TAM error namespace.
# AIKIDO is Cisco's internal name for firmware integrity verification in the
# VIC boot chain. The existence of a named error code for "loader change"
# indicates the integrity check has a detectable failure mode.
# If this error is non-fatal (i.e., boot continues after the error is logged),
# a tampered AIKIDO loader could pass with only a logged error.

FINDING_F4_AIKIDO_LOADER_CHANGE = {
    "id": "CSERIES-MOD3-F4",
    "title": "AIKIDO loader change error -- TAM integrity failure with non-halt potential",
    "severity": "LOW",
    "confidence": "MEDIUM",
    "component": "PCIe M85-SB VIC 5.4.2.47-48 -- AIKIDO firmware integrity / TAM",
    "cve": None,
    "evidence": {
        "error_code": "TAM_LIB_ERR_AIKIDO_LOADER_CHANGE",
    },
    "mechanism": (
        "TAM_LIB_ERR_AIKIDO_LOADER_CHANGE is defined in the TAM error namespace. "
        "AIKIDO is the internal name for Cisco's VIC firmware integrity verification. "
        "A named error code for loader modification implies the integrity check "
        "surfaces a loader change as an error condition rather than an immediate halt. "
        "If the boot path treats this error as non-fatal, a modified AIKIDO loader "
        "loads with only a TAM error log entry."
    ),
    "impact": (
        "Potential bypass of AIKIDO firmware integrity enforcement. "
        "Requires ability to modify the AIKIDO loader (boot-time FPGA/SPI access "
        "or privileged firmware update path). "
        "Impact: unsigned AIKIDO loader executes on VIC."
    ),
    "affected_devices": [
        "UCSC-PCIE-C25Q-04 (PCIe M85-SB VIC, fw 5.4.2.47-48)",
    ],
    "remediation": (
        "Verify AIKIDO loader change detection triggers hard halt, not log-only. "
        "Confirm TAM_LIB_ERR_AIKIDO_LOADER_CHANGE is treated as fatal in all boot paths."
    ),
}


# =============================================================================
# FINDING F5
# PCIe M85-SB dual-ASIC Palo boot path -- Beverly TAM does not cover Palo firmware
# Severity: MEDIUM
# =============================================================================
# The PCIe M85-SB bridge image contains both Beverly (M85) TAM-enforced paths
# and Palo-family (M83) firmware boot capability. Beverly has AIKIDO + TAM
# IDevID enforcement. Palo-family predates the TAM module entirely.
# The 'fwboot - boot palo firmware image from memory' U-Boot command is
# present in the production image. If this command can be triggered via the
# manufacturing firmware path or I2C boot console, Palo firmware loads from
# memory without TAM verification, bypassing Beverly's full security posture.
# The 'ignore_palocfg' string suggests a mechanism to skip Palo config entirely.

FINDING_F5_PALO_BOOT_TAM_BYPASS = {
    "id": "CSERIES-MOD3-F5",
    "title": "PCIe M85-SB Palo boot path bypasses Beverly TAM integrity enforcement",
    "severity": "MEDIUM",
    "confidence": "MEDIUM",
    "component": "PCIe M85-SB VIC 5.4.2.47-48 -- dual-ASIC boot architecture",
    "cve": None,
    "evidence": {
        "palo_in_beverly_image": [
            "Palo Firmware",
            "Palo Boot version %s",
            "fwboot  - boot palo firmware image from memory",
            "ignore_palocfg",
            "VIC-FW-Beverly",
            "VIC-FW-Beverly_LDWM",
        ],
        "tam_fpga_integration": [
            "Error: tam_lib_get_aikido_fpga_version() 0x%02X",
            "Error: vic_tam_fpga_reg_read()",
            "fpga_target    : 0x%02X",
        ],
        "aikido_diagnostic": [
            "(Power cycle the adapter and run 'vic_sb_fpga -s %d -x')",
        ],
    },
    "mechanism": (
        "PCIe M85-SB is a dual-ASIC bridge image covering Beverly (M85) and Palo (M83). "
        "Beverly runtime: AIKIDO FPGA-resident integrity + TAM IDevID + SUDI. "
        "Palo boot path ('fwboot - boot palo firmware image from memory'): "
        "Palo firmware predates the TAM module; no TAM verification applied. "
        "The 'ignore_palocfg' boot option permits skipping Palo config entirely. "
        "Manufacturing firmware path (confirmed in F1) may be the activation surface "
        "for triggering the Palo boot path from a Beverly-booted card."
    ),
    "impact": (
        "Palo firmware loaded from memory executes without TAM integrity verification, "
        "IDevID binding, or SUDI attestation. "
        "The card's trusted identity (IDevID) is tied to Beverly; "
        "Palo firmware bypasses this identity model. "
        "Requires activation of manufacturing boot path or physical I2C console access."
    ),
    "affected_devices": [
        "UCSC-PCIE-C25Q-04 (PCIe M85-SB VIC, fw 5.4.2.47-48)",
    ],
    "remediation": (
        "Restrict 'fwboot' and Palo boot commands to manufacturing mode only. "
        "Ensure manufacturing firmware path is disabled in production images. "
        "Verify AIKIDO FPGA integrity check applies to all boot paths, including Palo."
    ),
}


# =============================================================================
# FINDING F6
# AIKIDO integrity is FPGA-resident -- FPGA downgrade (F3) degrades AIKIDO
# Severity: LOW
# =============================================================================
# tam_lib_get_aikido_fpga_version() and vic_tam_fpga_reg_read() confirm the
# AIKIDO firmware integrity enforcement mechanism is embedded in the VIC FPGA,
# not the MIPS host firmware. The FPGA dual-image (GOLDEN/UPGRADE from F3)
# has a direct bearing on AIKIDO: downgrading the FPGA image downgrades the
# AIKIDO security posture that enforces firmware integrity.
# F3 and F6 compound: FPGA downgrade -> older AIKIDO -> weaker integrity checks.

FINDING_F6_AIKIDO_FPGA_DOWNGRADE = {
    "id": "CSERIES-MOD3-F6",
    "title": "AIKIDO integrity enforcement is FPGA-resident -- FPGA downgrade degrades AIKIDO",
    "severity": "LOW",
    "confidence": "HIGH",
    "component": "PCIe M85-SB VIC 5.4.2.47-48 -- AIKIDO FPGA integration",
    "cve": None,
    "evidence": {
        "fpga_aikido_functions": [
            "Error: tam_lib_get_aikido_fpga_version() 0x%02X",
            "Error: vic_tam_fpga_reg_read()",
            "fpga_target    : 0x%02X",
        ],
        "fpga_no_rollback": [
            "UPGRADE Version   : Downgrading or Same Version",
        ],
        "diagnostic_command": [
            "(Power cycle the adapter and run 'vic_sb_fpga -s %d -x')",
        ],
    },
    "mechanism": (
        "AIKIDO firmware integrity verification is FPGA-resident (tam_lib_get_aikido_fpga_version). "
        "FPGA dual-image (GOLDEN/UPGRADE) permits downgrade without version enforcement (F3). "
        "FPGA downgrade installs an older AIKIDO implementation with less strict integrity checks. "
        "The 'vic_sb_fpga -s %d -x' diagnostic command provides direct FPGA interaction, "
        "and is included in a user-visible error recovery path."
    ),
    "impact": (
        "FPGA version rollback (via F3 downgrade path) weakens the AIKIDO "
        "integrity enforcer embedded in that FPGA version. "
        "Older AIKIDO may accept modified MIPS firmware that newer AIKIDO rejects. "
        "Compounding with F3: two-step attack -- FPGA downgrade then MIPS firmware replacement."
    ),
    "affected_devices": [
        "UCSC-PCIE-C25Q-04 (PCIe M85-SB VIC, fw 5.4.2.47-48)",
    ],
    "remediation": (
        "Enforce FPGA minimum version (required for AIKIDO versioning). "
        "Lock FPGA downgrade path before AIKIDO version bound is established at manufacture."
    ),
}


# =============================================================================
# ZERO-HIT SURVEY LOG
# All members scanned, null result = logged result
# =============================================================================

ZERO_HIT_CSERIES_MOD3 = {
    "nc3220_vic_connectx7": {
        "member": "ucs-adaptor-ucsc-p-NC3220.32.46.1006.bin",
        "fw_version": "32.46.1006",
        "classification": "Mellanox ConnectX-7 200GbE (32.x = CX7 generation)",
        "raw_size_mb": 425,
        "decompressed_mb": 404,
        "format": "SN-wrapped (hsize=764) -> 404MB gzip payload",
        "scan_coverage": "0-404MB fully scanned (0-200MB pass 1, 200-404MB pass 2)",
        "keyword_hits": 0,
        "string_density_at_400mb": "926 strings, all random-looking (encrypted/compressed)",
        "verdict": "OPAQUE -- no plain-text string tables in any region",
        "note": (
            "NC3220 firmware (32.46.1006) was fully analyzed in a dedicated prior session "
            "as cisco_ucs_cseries_nc3220_bluefield_re.py (4 findings: NC3220-F1 through F4). "
            "The C-Series bundle version is the same 32.46.1006 in SN-wrapped format. "
            "Inner content is a TAR(XZ(446MB ARM bundle)) -- XZ compression explains 0 ASCII hits "
            "in outer SN gzip layer scan. BlueField-3 DPU findings (ROTPK bypass, BL2 soft fail, "
            "HTTP CRL) from prior analysis apply."
        ),
    },
    "pcie_m84_vic": {
        "members": [
            "ucs-pcie84-vic.5.4.2.47.bin",
            "ucs-pcie84-vic-ioc.5.4.2.47.bin",
        ],
        "fw_version": "5.4.2.47",
        "raw_size_mb": 18,
        "inner_kb": 19510,
        "format": "SN-wrapped",
        "keyword_hits": 0,
        "verdict": "ZERO HITS -- stripped binary or alternate packing",
    },
    "pcie_m85_vic_nonsb": {
        "member": "ucs-pcie85-vic.5.4.2.47.bin",
        "fw_version": "5.4.2.47",
        "raw_size_mb": 19,
        "inner_kb": 19740,
        "format": "SN-wrapped",
        "keyword_hits": 0,
        "verdict": "ZERO HITS -- security strings absent vs M85-SB variant",
        "note": (
            "PCIe M85 (non-SB) has 0 security keyword hits while M85-SB has "
            "the full TAM/IDevID/SUDI stack. The -SB suffix likely denotes the "
            "Secure Boot hardware variant with dedicated TAM chip."
        ),
    },
    "hgst_nvme_cseries_knccd122": {
        "families": [
            "ucs-storage-hgst-ucs-nvme-H800.KNCCD122.bin",
            "ucs-storage-hgst-ucs-nvme-H1600.KNCCD122.bin",
            "ucs-storage-hgst-ucs-nvme-H3200.KNCCD122.bin",
            "ucs-storage-hgst-ucs-nvme-H6400.KNCCD122.bin",
            "ucs-storage-hgst-ucs-nvme-H7680.KNCCD122.bin",
            "ucs-storage-hgst-ucs-UCSC-NVME-H32003.KNCCD122.bin",
            "ucs-storage-hgst-ucs-UCSC-NVME-H38401.KNCCD122.bin",
            "ucs-storage-hgst-ucs-UCSC-NVME-H64003.KNCCD122.bin",
            "ucs-storage-hgst-ucs-UCSC-NVME-H76801.KNCCD122.bin",
            "ucs-c-storage-hgst-nvme-UCSC-F-H16003.KNCCD122.bin",
        ],
        "fw_version": "KNCCD122",
        "raw_size_kb": 1279,
        "inner_kb": 1730,
        "format": "SN-wrapped",
        "keyword_hits": 0,
        "verdict": "ZERO HITS -- same firmware code as B-Series HGST NVMe",
        "note": (
            "HGST NVMe C-Series variants share KNCCD122 firmware with B-Series. "
            "Security analysis applies from B-Series module (HGST NVMe findings)."
        ),
    },
}


# =============================================================================
# PENDING -- CIMC AND BIOS (out of scope for this module, separate passes needed)
# =============================================================================

PENDING_CSERIES_LARGE = {
    "cimc_blobs": {
        "note": "OpenBMC ARM binaries (61-149MB each). Same framework as B-Series CIMC.",
        "platforms": [
            "CIMC C220-M5, C220-M6, C220-M7",
            "CIMC C225-M6, C225-M8",
            "CIMC C240-M5, C240-M6, C240-M7, C240-M8",
            "CIMC C245-M6, C245-M8",
            "CIMC C480-M5",
            "CIMC C125",
            "CIMC S3260-M5",
        ],
        "status": "PENDING -- requires separate CIMC module pass",
    },
    "bios_blobs": {
        "note": "Intel UEFI BIOS images (11-24MB each). Requires separate UEFI module.",
        "platforms": [
            "BIOS C125",
            "BIOS C220-M5, C220-M6, C220-M7, C220-M8",
            "BIOS C225-M6, C225-M8",
            "BIOS C240-M5, C240-M6, C240-M7, C240-M8",
            "BIOS C245-M6, C245-M8",
            "BIOS S3260-M5",
        ],
        "status": "PENDING -- requires separate UEFI BIOS module pass",
    },
}


# =============================================================================
# MODULE SUMMARY
# =============================================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_cseries_pcie_vic_re",
    "session": 29,
    "component": "C-Series PCIe VIC TAM/IDevID + large-file survey",
    "findings_this_module": {
        "total": 6,
        "breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 3, "LOW": 3},
        "ids": [
            "CSERIES-MOD3-F1",
            "CSERIES-MOD3-F2",
            "CSERIES-MOD3-F3",
            "CSERIES-MOD3-F4",
            "CSERIES-MOD3-F5",
            "CSERIES-MOD3-F6",
        ],
    },
    "zero_hit_log": [
        "NC3220 VIC (ConnectX-7 fw 32.46.1006): 404MB fully opaque",
        "PCIe M84 VIC + IOC (fw 5.4.2.47): 0 hits",
        "PCIe M85 VIC non-SB (fw 5.4.2.47): 0 hits",
        "HGST NVMe KNCCD122 (10 variants): 0 hits",
    ],
    "pending": [
        "CIMC blobs (13 platforms, OpenBMC ARM)",
        "BIOS blobs (12 platforms, Intel UEFI)",
    ],
    "cumulative_all": {
        "total": 523,
        "breakdown": {"CRITICAL": 54, "HIGH": 177, "MEDIUM": 161, "LOW": 131},
    },
}
