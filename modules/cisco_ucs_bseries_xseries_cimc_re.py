"""
Cisco UCS B-Series / X-Series CIMC RE Module 1
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin
Targets: ucs-x410-m7-cimc, ucs-x215-m8-cimc, ucs-BXSeriesM6, ucs-intel-blade-m8-cimc
Version: 6.0(2.260040), built Feb 14-19 2026

8 findings: 0C/0H/3M/5L
Cumulative: 559 [54C+182H+170M+153L]
"""

# ============================================================
# TARGET MAP
# ============================================================

TARGET_MAP = {
    "ucs-x410-m7-cimc.6.0.2.260040.bin": {
        "platform": "UCS X410C M7",
        "blob_size_mb": 65,
        "bmc_asic": "Aspeed AST2600",
        "uboot_version": "U-Boot SPL 2019.04",
        "uboot_build": "Dec 06 2023 14:05:48 +0000",
        "cimc_build": "Sat Feb 14 14:45:51 2026",
        "swid": "swid-blade-controller-elma-sapphirerapids",
        "codenames": ["XSeriesM7", "everett", "elma", "mandalorian"],
        "cpu_gen": "Intel Sapphire Rapids (4th Gen Xeon Scalable)",
        "secureboot_mode": "secureboot=2",
    },
    "ucs-x215-m8-cimc.6.0.2.260040.bin": {
        "platform": "UCS X215C M8",
        "blob_size_mb": 65,
        "bmc_asic": "Aspeed AST2600",
        "uboot_version": "U-Boot SPL 2019.04",
        "uboot_build": "Dec 06 2023 14:05:48 +0000",
        "cimc_build": "Sat Feb 14 12:54:01 2026",
        "swid": "swid-blade-controller-mandalorian",
        "codenames": ["XSeriesM7", "everett", "elma", "mandalorian"],
        "note": "IDENTICAL BLOB to X410 M7 -- same binary, different SWID header",
        "secureboot_mode": "secureboot=2",
    },
    "ucs-BXSeriesM6.6.0.2.260040.bin": {
        "platform": "UCS BX-Series M6",
        "blob_size_mb": 52,
        "bmc_asic": "Nuvoton/ServerEngines Pilot4 (PILOT_ORION variant)",
        "uboot_version": "U-Boot 2012.10",
        "uboot_build": "Feb 19 2026 07:48:53",
        "cimc_build": "Thu Feb 19 07:53:38 2026",
        "swid": "swid-blade-controller-wilbur-icelake",
        "codenames": ["BXSeriesM6", "wilbur"],
        "cpu_gen": "Intel Ice Lake (3rd Gen Xeon Scalable)",
        "secureboot_mode": "secureboot=1",
    },
    "ucs-intel-blade-m8-cimc.6.0.2.260040.bin": {
        "platform": "UCS Intel Blade M8",
        "blob_size_mb": 85,
        "bmc_asic": "Aspeed AST2600",
        "uboot_version": "U-Boot SPL 2019.04",
        "uboot_build": "Dec 14 2023 00:12:24 +0000",
        "cimc_build": "Sat Feb 14 17:26:30 2026",
        "swid": "swid-blade-controller-intel-m8",
        "codenames": ["XSeriesM8", "godfather", "gladiator"],
        "multi_platform_blob": True,
        "secureboot_mode": "secureboot=2",
    },
}

# ============================================================
# CPK PACKAGE MANIFEST
# ============================================================

CPK_PACKAGE_MANIFEST = {
    "format": "JSON dict: '<name>-<ver>-<build_git_hash>.<build_num>.cpk': {'sha': '<hash>'}",
    "build_git_hash": "17633db507e81f789359828008cf046045bfa5a1",
    "sha_all_packages": "4a28187af3c665e9ee943d46242004d287ba2c41",
    "sha_is_build_commit": True,
    "finding": "ALL packages across ALL platforms share IDENTICAL sha value; sha is NOT per-package content hash",
    "packages": {
        "bash": "4.4",
        "bash_semver2": "1.0.3",
        "busybox": "1.36.0",
        "Python": "3.9.7",
        "nginx": "1.18.0",
        "libfastjson": "0.99.8",
        "memtester": "4.6.0",
        "miitool": "1.9.1.1",
        "rng_tools": "5",
        "cisco_internal": [
            "secure_boot_monitor-1.0.0",
            "secure_action-1.0.0",
            "secure_suite-1.0.0",
            "will_boot2-1.0.0",
            "UcsHealth-1.0.0",
            "mezz_ctrl-1.0.0",
            "host_reset_monitor-1.0.0",
            "power_fault_monitor-1.0.0",
            "qpi_logger-1.0.0",
            "blade_power-1.0.0",
            "blade_bonding-1.0.0",
            "blade_mezz_fru_cache-1.0.0",
            "bt_server-1.0.0",
            "BIOSPostCodeDecoder-1.0.0",
            "cdrutil-1.0.0",
            "crond-1.0.0",
            "I2cAccess-1.0.0",
            "I2cBusScan-1.0.0",
            "Peci-1.0.0",
            "MrT-1.0.0",
            "ipmi_query-1.0.0",
            "blade_nmi-1.0.0",
            "dr_bmc_nvlog-1.0.0",
            "fru-1.0.0",
            "x509_cert_gen-1.0.0",
            "ptpd-1.0.0",
            "locate_led_button-1.0.0",
            "reboot-1.0.0",
            "uuid_bios-1.0.0",
            "uspm_app-1.0.0",
        ],
    },
    "identical_across": ["x410m7", "x215m8", "bxm6", "intelblade_m8"],
}

# ============================================================
# SECURE BOOT KEY HIERARCHY (X-Series, AST2600)
# ============================================================

SECURE_BOOT_XSERIES = {
    "bmc": "Aspeed AST2600",
    "format": "BIS (Boot Image Secure) format with versioned update path",
    "key_types": [
        "RSA-public as SOC public key (AST2600 root of trust)",
        "RSA-private as SOC private key",
        "RSA-public as OEM DSS public keys in Mode 2",
        "RSA-public as OEM DSS public keys in Mode 2 (big endian)",
        "RSA-public as AES key decryption key",
        "RSA-public as AES key decryption key (big endian)",
        "RSA-private as AES key decryption key",
    ],
    "cmdline_format": (
        "console=ttyS4,115200n8 root=/dev/ram rw rdinit=/sbin/init "
        "image=partition%d secureboot=2 rng_core.default_quality=1000 "
        "%s signature=%s ;bootm 0x%08x%s"
    ),
    "signature_in_cmdline": True,
    "key_erasure_options": [
        "Do not erase signature data after secure boot check",
        "Erase signature data after secure boot check",
        "Do not erase RSA public key after secure boot check",
        "Erase RSA public key after secure boot check",
    ],
    "panic_on_taint": "0x42A0 (PROPRIETARY_MODULE|UNSIGNED_MODULE|AUTOLOADED_UNSIGNED); nousertaint",
    "otp_bist": "ASPEED DRAM BIST, Enable/Disable OTP Memory BIST Mode",
}

# ============================================================
# BX-SERIES BOOT CONFIGURATION
# ============================================================

BX_SERIES_BOOT = {
    "bmc": "Pilot4 ASIC (PILOT_ORION variant)",
    "uboot_boot_paths": {
        "norboot": "NOR flash -> 0xE2100000 -> 0x3000000 (kernel), 0xE2600000 -> 0x2A00000 (dtb), 0xE2620000 -> 0x2000000 (ramdisk)",
        "qspiboot": "QSPI flash sf probe/read -> 0x3000000/0x2A00000/0x2000000",
        "emmcboot": "MMC dev 2 fatload -> 0x81000000 (kernel), 0x81A00000 (ramdisk)",
        "sdboot": "MMC dev 0 (SD card) fatload -> 0x81000000/0x81A00000",
        "nandboot": "NAND flash read -> 0x3000000/0x2A00000/0x2000000",
        "jtagboot": "TFTP -> 0x3000000 (kernel), 0x2A00000 (dtb), 0x2000000 (ramdisk) -> bootm",
    },
    "bootcmd": "bootm 0x100000 0x400000",
    "bootdelay": 3,
    "secureboot_cmdline": "secureboot=1 panic_on_taint=0x42A0,nousertaint",
    "fpga_boot_image": "bootImgFPGASecure-BXSeriesM6 / bootImgFPGASecure-wilbur",
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "BSERIES-F1",
        "severity": "MEDIUM",
        "title": "BX_SERIES_M6_UBOOT_2012_10_WITH_JTAGBOOT_TFTP_PATH",
        "platforms": ["BXSeriesM6 (wilbur)"],
        "detail": (
            "BX-Series M6 CIMC uses U-Boot 2012.10 (built Feb 19 2026), a bootloader from October 2012 "
            "still in production firmware 12+ years after release. "
            "Current stable is ~2024.x. U-Boot 2012.x predates HTTPS, ECC keys, "
            "and numerous memory corruption fixes in the bootloader. "
            "The U-Boot environment includes a JTAG/TFTP boot path:\n"
            "  jtagboot=echo TFTPing Linux to RAM...;"
            "tftp 0x3000000 ${kernel_image};"
            "tftp 0x2A00000 ${devicetree_image};"
            "tftp 0x2000000 ${ramdisk_image};"
            "bootm 0x3000000 0x2000000 0x2A00000\n"
            "bootdelay=3 provides a 3-second window to interrupt U-Boot auto-boot. "
            "If an attacker can reach the BMC serial console or interrupt the boot sequence "
            "via physical JTAG, arbitrary kernel+ramdisk+devicetree can be loaded via TFTP "
            "to hardcoded addresses (0x3000000, 0x2A00000, 0x2000000) bypassing Cisco's "
            "secureboot=1 kernel argument (set only after U-Boot-level validation). "
            "BMC: Pilot4 ASIC (PILOT_ORION); firmware built same day as CIMC (Feb 19 2026)."
        ),
    },
    {
        "id": "BSERIES-F2",
        "severity": "MEDIUM",
        "title": "INTEL_BLADE_M8_CIMC_DEV_KEY_INSTALL_IN_PRODUCTION_FIRMWARE",
        "platforms": ["Intel Blade M8 (godfather, gladiator)"],
        "detail": (
            "Intel Blade M8 CIMC firmware (ucs-intel-blade-m8-cimc.6.0.2.260040.bin) "
            "contains 'CIMC_DEV_Key_Install' and 'DEV_Key_Install' strings "
            "three times each (lines 56/68, 535/547, 689/701 of strings output). "
            "This string triple occurrence matches the three platforms in the blob: "
            "XSeriesM8, godfather, gladiator. "
            "CIMC_DEV_Key_Install appears adjacent to: "
            "'mfg-only=N' (manufacturing mode disabled flag), "
            "AST2600 SDRAM/H2X probe strings, and the signature verification error table. "
            "The string is present in a region preceding signature verification error codes:\n"
            "  Signature Not Present\n"
            "  Signature Section Not Present\n"
            "  General Failure in Signature Verification\n"
            "This positions CIMC_DEV_Key_Install as a state label or function in the "
            "CIMC signing framework, not a debug artifact. "
            "mfg-only=N being a runtime-configurable field suggests the manufacturing mode "
            "switch and DEV key install path are gated by this flag -- "
            "if mfg-only can be set to Y through a CIMC interface, the dev key path becomes active."
        ),
    },
    {
        "id": "BSERIES-F3",
        "severity": "MEDIUM",
        "title": "XSERIES_AST2600_RSA_SIGNATURE_PASSED_IN_KERNEL_CMDLINE",
        "platforms": ["X410C M7 (elma/everett/mandalorian)", "X215C M8", "Intel Blade M8 (godfather/gladiator)"],
        "detail": (
            "X-Series blades with AST2600 BMC pass the firmware verification signature "
            "directly in the Linux kernel cmdline:\n"
            "  console=ttyS4,115200n8 root=/dev/ram rw rdinit=/sbin/init "
            "image=partition%d secureboot=2 rng_core.default_quality=1000 %s signature=%s\n"
            "The signature value is passed as a kernel parameter rather than being verified "
            "entirely within U-Boot or the BIS framework. "
            "If the U-Boot environment or SPL can be modified (via flash write, JTAG, or "
            "U-Boot console interrupt on an SPL build without console lockout), "
            "the signature field can be altered. "
            "Additional exposure: the firmware exposes a binary choice -- "
            "'Erase RSA public key after secure boot check' vs "
            "'Do not erase RSA public key after secure boot check' -- "
            "indicating the OTP-provisioned RSA public key can be erased post-verification, "
            "making the check non-repeatable on subsequent boots. "
            "BIS format: versioned (Current BIS version is %d.%d; "
            "update path: Updating BIS image from %d.%d to %d.%d). "
            "OTP BIST mode: 'Enable OTP Memory BIST Mode' / 'Disable OTP Memory BIST Mode' "
            "present in AST2600 component (OTP physical attack surface)."
        ),
    },
    {
        "id": "BSERIES-F4",
        "severity": "LOW",
        "title": "CPK_MANIFEST_SHA_IS_BUILD_COMMIT_NOT_PER_PACKAGE_CONTENT_HASH",
        "platforms": ["all: X410C M7, X215C M8, BX-Series M6, Intel Blade M8"],
        "detail": (
            "The CPK package manifest embedded in all CIMC images lists a 'sha' field "
            "for each package. All packages -- bash, busybox, Python, nginx, and all Cisco "
            "internals -- share the IDENTICAL sha value: 4a28187af3c665e9ee943d46242004d287ba2c41. "
            "The sha is not computed per-package (bash-4.4 and nginx-1.18.0 cannot produce "
            "the same content hash). The value matches the build commit tag suffix "
            "17633db507e81f789359828008cf046045bfa5a1 pattern -- it is likely the sha of "
            "a build artifact or repository state, not a per-package integrity check. "
            "Consequence: a modified CIMC package (e.g., nginx with a backdoor) would "
            "produce an identical manifest sha as the legitimate package -- "
            "the manifest sha field provides no package-level integrity verification. "
            "All four platforms (X410 M7, X215 M8, BX-Series M6, Intel Blade M8) "
            "ship the identical package manifest with the same build tag."
        ),
    },
    {
        "id": "BSERIES-F5",
        "severity": "LOW",
        "title": "OUTDATED_EMBEDDED_PACKAGES_ACROSS_ALL_BLADE_CIMC",
        "platforms": ["all: X410C M7, X215C M8, BX-Series M6, Intel Blade M8"],
        "detail": (
            "All blade CIMC images (version 6.0.2.260040, built Feb 2026) embed "
            "identical outdated package versions:\n"
            "  nginx 1.18.0 (released Aug 2020; 5+ years old; multiple CVEs including "
            "CVE-2021-23017 (CRITICAL: off-by-one in resolver), CVE-2022-41742, "
            "CVE-2023-44487 (HTTP/2 Rapid Reset), CVE-2024-7347)\n"
            "  bash 4.4 (released Sep 2016; 9 years old; CVE-2019-18276 privilege escalation)\n"
            "  Python 3.9.7 (released Sep 2021; multiple CVEs in 3.9.x series)\n"
            "  libfastjson 0.99.8 (2018-era; potential heap issues)\n"
            "These packages run as the CIMC management OS on the AST2600/Pilot4 BMC. "
            "nginx likely serves the CIMC web interface. "
            "An attacker with network access to the CIMC management interface "
            "can exploit nginx CVEs without requiring physical access."
        ),
    },
    {
        "id": "BSERIES-F6",
        "severity": "LOW",
        "title": "X410C_M7_AND_X215C_M8_SHIP_IDENTICAL_FIRMWARE_BLOB_LABELED_XSERIESM7",
        "platforms": ["X410C M7", "X215C M8"],
        "detail": (
            "ucs-x410-m7-cimc.6.0.2.260040.bin (57MB) and ucs-x215-m8-cimc.6.0.2.260040.bin (57MB) "
            "decompress to 65MB blobs with identical content except their outer SN wrapper. "
            "Both blobs are labeled 'XSeriesM7' internally with the same three codenames: "
            "everett, elma, mandalorian. The X215C M8 SWID tag 'swid-blade-controller-mandalorian' "
            "maps the X215C M8 to the 'mandalorian' platform variant. "
            "CIMC build times differ by ~2 hours (X410: 14:45:51; X215: 12:54:01, same date) "
            "suggesting parallel builds of the same source. "
            "Cross-platform vulnerability: any CIMC exploit against X410C M7 applies equally "
            "to X215C M8 without additional porting. "
            "Same pattern observed in FI bundles (6400/6500/6600/X-Direct identical) and "
            "C-Series CIMC (5 blades identical; see cisco_ucs_cseries_s3260_cimc_re.py)."
        ),
    },
    {
        "id": "BSERIES-F7",
        "severity": "LOW",
        "title": "SWID_CODENAME_CPU_GEN_MATRIX_XSERIES_BLADE_CONTROLLERS",
        "detail": (
            "imghdr.bin SWID tags and string analysis across all 4 CIMC images expose "
            "internal codenames and Intel CPU generation bindings:\n"
            "  X410C M7: swid-blade-controller-elma-sapphirerapids "
            "(elma = internal name; Sapphire Rapids = Intel 4th Gen Xeon Scalable)\n"
            "  X215C M8: swid-blade-controller-mandalorian "
            "(mandalorian = internal name; CPU gen not disclosed in SWID)\n"
            "  BX-Series M6: swid-blade-controller-wilbur-icelake "
            "(wilbur = internal name; Ice Lake = Intel 3rd Gen Xeon Scalable)\n"
            "  Intel Blade M8: swid-blade-controller-intel-m8 "
            "(no specific codename; three platform names: XSeriesM8/godfather/gladiator)\n"
            "Additional U-Boot image labels for X410 M7: everett (AST2600 board variant), "
            "elma (primary X410 variant), mandalorian (X215 variant in same blob). "
            "CPU generation disclosure enables precise vulnerability scoping against "
            "Sapphire Rapids or Ice Lake CPU-level vulnerabilities."
        ),
    },
    {
        "id": "BSERIES-F8",
        "severity": "LOW",
        "title": "INTEL_BLADE_M8_SINGLE_BLOB_THREE_PLATFORM_CODENAMES_GODFATHER_GLADIATOR",
        "detail": (
            "ucs-intel-blade-m8-cimc.6.0.2.260040.bin (73MB) contains U-Boot images, "
            "flash filesystems, SSP images, and OS tarballs for THREE distinct platforms:\n"
            "  XSeriesM8 (primary product name)\n"
            "  godfather (internal codename)\n"
            "  gladiator (internal codename)\n"
            "Intel Blade M8 uses AST2600 BMC with U-Boot SPL 2019.04 (Dec 14 2023), "
            "same base as X410 M7/X215 M8. It is the largest blob (85MB decompressed) "
            "carrying the most packages (adds: Python-3.9.7, MrT-1.0.0, BIOSPostCodeDecoder-1.0.0 "
            "vs standard set). 'godfather' and 'gladiator' are distinct hardware variants "
            "with separate SPL/BIS/boot/SSP/flashfs/cloudimgfs/sie/opkg images each -- "
            "suggesting at least 3 shipping SKUs of Intel Blade M8. "
            "Cross-variant vulnerability: an exploit against any of the three sub-platforms "
            "applies across all three."
        ),
    },
]

MODULE_SUMMARY = {
    "module": "cisco_ucs_bseries_xseries_cimc_re",
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "targets": list(TARGET_MAP.keys()),
    "findings": [f["title"] for f in FINDINGS],
    "finding_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 3, "LOW": 5},
    "cumulative_counts": {"CRITICAL": 54, "HIGH": 182, "MEDIUM": 170, "LOW": 153},
    "cumulative_total": 559,
    "codenames_discovered": {
        "X410C M7": ["everett", "elma"],
        "X215C M8": ["mandalorian"],
        "BX-Series M6": ["wilbur"],
        "Intel Blade M8": ["godfather", "gladiator"],
    },
    "bmc_versions": {
        "AST2600 (X-Series, Intel Blade M8)": "U-Boot SPL 2019.04 (Dec 2023)",
        "Pilot4/ORION (BX-Series M6)": "U-Boot 2012.10 (built Feb 2026)",
    },
}
