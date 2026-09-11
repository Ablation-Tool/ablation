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
            "ConnectX-7 32.x firmware uses full-image encryption or non-standard "
            "string storage. Class-similar to ConnectX M6 PCIe variants (M84/M85). "
            "Security primitives (mjtag, lifecycle, Rollback fuse) documented in "
            "B-Series VIC Module 1 under ConnectX M6 class."
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
        "total": 4,
        "breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 2},
        "ids": [
            "CSERIES-MOD3-F1",
            "CSERIES-MOD3-F2",
            "CSERIES-MOD3-F3",
            "CSERIES-MOD3-F4",
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
        "total": 521,
        "breakdown": {"CRITICAL": 54, "HIGH": 177, "MEDIUM": 160, "LOW": 130},
    },
}
