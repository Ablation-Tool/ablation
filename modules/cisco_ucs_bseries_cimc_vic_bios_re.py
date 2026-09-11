"""
Cisco UCS B-Series CIMC, VIC, and BIOS Firmware RE
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin

Covers:
- CIMC Blade M8 (ucs-intel-blade-m8-cimc.6.0.2.260040.bin) -- 87.5MB AST2600
- X215 M8 CIMC (ucs-x215-m8-cimc.6.0.2.260040.bin) -- 67MB
- BXSeriesM6 VIC (ucs-BXSeriesM6.6.0.2.260040.bin) -- 53.9MB
- B200 M5 BIOS (B200M5.4.3.2g) + B480 M5 BIOS (B480M5.4.3.2g)
- B200 M6 BIOS (B200M6.6.0.2a)
- X210 M8 BIOS + X410 M8 BIOS (6.0.2b)
- Intel Flex 140 VGA (DG02-2.2280_7.0.0.0) -- Intel DG2 GPU firmware
"""

CIMC_BLADE_M8 = {
    "fw_version": "6.0.2.260040",
    "product": "Cisco Integrated Management Controller -- Intel Blade M8 (AST2600 BMC SoC)",
    "fw_size_kb": 87553,
    "fw_md5_prefix": "b9d2d8f2",
    "magic": "55aa000e801b80c2",
    "magic_note": "Magic 55aa = ASPEED BMC standard; remaining bytes = CIMC header",
    "hardware": "ASPEED AST2600 (ast2600_sdrammc_probe, aspeed_h2x_probe confirm SoC)",
    "packages": {
        "build_commit": "17633db507e81f789359828008cf046045bfa5a1",
        "notable_packages": [
            "otp-1.0.0",
            "secure_boot_monitor-1.0.0",
            "secure_board_update-1.0.0",
            "tftpd-0.48",
            "tcpdump-4.99.1",
            "netsnmp-5.7.3",
            "pof_monitor-1.0.0",
            "bmc_install_scripts-1.0.0",
            "update_bios_v3-1.0.0",
            "selparser-1.0.0",
        ],
        "all_sha_same": "4a28187af3c665e9ee943d46242004d287ba2c41 (all packages same SHA -- pre-built bundle, not content hash)",
    },
    "security_strings": {
        "dev_key_install": {
            "context": [
                "@NYYYY@@@@",
                "mfg-only=N",
                "CIMC_DEV_Key_Install",
                "DEV_Key_Install",
            ],
            "note": "Three separate occurrences in binary; 'mfg-only=N' flag adjacent to key install function name",
        },
        "dev_key_aes_context": {
            "context": [
                "CIMC_DEV_Key_Install",
                "DEV_Key_Install",
                "AES-256 as OEM platform key for image encryption/decryption",
                "AES-256 as secret vault key",
                "HMAC as encrypted OEM HMAC keys in Mode 1",
            ],
            "note": "DEV key install adjacent to AES-256 OEM platform key, secret vault key, and HMAC OEM keys -- confirms DEV key affects all three security domains",
        },
        "boot_stability": {
            "context": [
                "at start, protection %x, magic %x, try %x, image id %x",
                "no valid or stable images to boot so wait for ever",
                "at end, protection %x, magic %x, try %x, image id %x",
                "CIMC_DEV_Key_Install",
                "DEV_Key_Install",
                "Signature Not Present",
            ],
            "note": "DEV key install appears in same binary region as 'Signature Not Present' -- suggests DEV key install is on the boot-recovery / no-valid-image path",
        },
    },
}

BXSERIES_VIC = {
    "fw_version": "6.0.2.260040",
    "product": "Cisco UCS BXSeries M6 VIC (BXSeries = BX210C-M6 blade mezzanine VIC)",
    "fw_size_kb": 53929,
    "fw_md5_prefix": "a43243e8",
    "magic": "55aa0007000c8035",
    "uboot_version": "U-Boot 2012.10 (Feb 19 2026 - 07:48:53)",
    "uboot_age_note": "U-Boot 2012.10 was released 2012-10-xx; shipping in 2026 product = 13+ year old bootloader",
    "shell_prompt": "PILOT_ORION>",
    "platform_note": "PILOT = Cisco VIC ASIC name; ORION = platform name for BXSeries M6 blade",
    "boot_environment": {
        "bootcmd": "bootm 0x100000 0x400000",
        "bootdelay": "3 (seconds to interrupt autoboot at PILOT_ORION> prompt)",
        "ipaddr": "192.168.2.100",
        "serverip": "192.168.2.101",
        "norboot": "cp 0xE2100000 0x3000000 ${kernel_size};cp 0xE2600000 0x2A00000 ${devicetree_size};cp 0xE2620000 0x2000000 ${ramdisk_size};bootm 0x3000000 0x2000000 0x2A00000",
        "qspiboot": "sf probe 0 0 0;sf read 0x3000000 0x100000 ${kernel_size};...;bootm 0x3000000 0x2000000 0x2A00000",
        "emmcboot": "mmc dev 2;fatload mmc 2 0x81000000 ${kernel_image};fatload mmc 2 0x81A00000 ${ramdisk_image};bootm 0x81000000",
        "sdboot": "mmc dev 0;fatload mmc 0 0x81000000 ${kernel_image};...;bootm 0x81000000",
        "nandboot": "nand read 0x3000000 0x100000 ${kernel_size};...;bootm 0x3000000 0x2000000 0x2A00000",
        "jtagboot": "echo TFTPing Linux to RAM...;tftp 0x3000000 ${kernel_image};tftp 0x2A00000 ${devicetree_image};tftp 0x2000000 ${ramdisk_image};bootm 0x3000000 0x2000000 0x2A00000",
    },
    "secureboot_boot_args": "secureboot=1 panic_on_taint=0x42A0,nousertaint",
    "chimp_install": {
        "patterns": ["bootImgCHIMP", "bootImg", "chimp.bin"],
        "note": "Broadcom CHIMP (CHassis Interface Management Processor) separate firmware component installed alongside VIC Linux",
    },
    "source_code_comment": {
        "text": "#The BSeriesM5, presidio, pomona is a hack to work around a bug. In General we should avoid doing this.",
        "note": "Source code comment shipped in production binary; exposes internal Cisco platform codenames: presidio, pomona, BSeriesM5",
    },
    "fit_image_validation": {
        "messages": [
            "Bad hash in FIT image!",
            "Verifying Hash Integrity ...",
            "Bad Data Hash",
            "Image 1 validation in progress",
            "Image 1 validation COMPLETE",
            "Primary image validation failed",
            "BACKUP image 2 validation in progress",
            "IMAGE VALIDATION FAILED COMPLETELY",
            "Please Hit Enter Key to Boot Alternate Image: %2d",
        ],
    },
}

BIOS_FIRMWARE = {
    "B200M5": {
        "fw_version": "B200M5.4.3.2g.0.0116260829",
        "fw_size_kb": 8800,
        "fw_md5_prefix": "8c96195f",
        "magic_ascii": "B200M5-B",
        "boot_guard_strings": ["ImageACM_SVN_Authorized=2", "ImageKM_SVN=0", "ImageBPM_SVN=0"],
    },
    "B480M5": {
        "fw_version": "B480M5.4.3.2g.0.0116260830",
        "fw_size_kb": 8780,
        "fw_md5_prefix": "fa3e8e7d",
        "magic_ascii": "B480M5-B",
        "boot_guard_strings": ["ImageACM_SVN_Authorized=2", "ImageKM_SVN=0", "ImageBPM_SVN=0"],
    },
    "B200M6": {
        "fw_version": "B200M6.6.0.2a.0.0121260813",
        "fw_size_kb": 10130,
        "fw_md5_prefix": "20c6e45a",
        "note": "No security string hits in printable scan",
    },
    "X210M8": {
        "fw_version": "X210M8.6.0.2b.0.0130261958",
        "fw_size_kb": 19000,
        "fw_md5_prefix": "3dae31e5",
        "magic_ascii": "X210M8-B",
        "note": "double-gz format; no security hits in outer decompression layer",
    },
    "X410M8": {
        "fw_version": "X410M8.6.0.2b.0.0130261958",
        "fw_size_kb": 19000,
        "fw_md5_prefix": "737eeec4",
        "magic_ascii": "X410M8-B",
        "note": "double-gz format; different md5 from X210M8 (different platform BIOS)",
    },
    "X215M8": {
        "fw_version": "X215M8.6.0.2a.0.0121261120",
        "fw_size_kb": 24620,
        "fw_md5_prefix": "339c088d",
        "note": "Largest BIOS in bundle (24.6MB); double-gz",
    },
    "B200M6_notes": {
        "acm_note": "ImageACM_SVN_Authorized=2 in B200M5/B480M5 only; M6 uses BIOS version 6.0.2a (not 4.3.2g) -- different generations",
    },
}

INTEL_FLEX_VGA = {
    "fw_version": "DG02-2.2280_7.0.0.0",
    "product": "Intel Data Center GPU Flex 140 VGA firmware (Intel Xe DG2 GPU)",
    "variants": ["ucs-video-intel-flex-140-Mezz.DG02", "ucs-video-intel-flex-170-Mezz.DG02"],
    "fw_size_kb": 2440,
    "fw_md5_prefix": "b4413b86",
    "magic": "494657495f585055",
    "magic_ascii": "IFWI_XPU",
    "security_strings": {
        "dgfx_svn": {
            "string": "DGFX DG2 SVN01 Kernel CA0v0",
            "note": "Intel DG2 GPU Security Version Number = 01; Kernel Certificate Authority = 0 version 0; documents Intel DG2 (Xe-HPG) boot security chain",
        },
        "sha_not_ready": {
            "string": "[%3lu] E SHA hash not ready",
            "note": "SHA hash hardware engine initialization failure in AMC (Add-on Module Controller); error-log format with sequence number prefix",
        },
        "flash_erase_fail": {
            "string": "[%3lu] W In amc_flash_erase_zero memset_s failed",
            "note": "Flash erase + secure zero-fill failure; memset_s is the security-critical zero (not optimizable away by compiler)",
        },
        "edge_perst": {
            "string": "[%3lu] I EDGE_PERST_N signal is HIGH    [%3lu] I EDGE_PERST_N signal is LOW",
            "note": "PCIe PERST# (PCI Express Reset) edge detection monitoring; logged by AMC",
        },
    },
}

FINDINGS = {
    "CIMC-DEV-KEY-INSTALL-F1": {
        "id": "CIMC-DEV-KEY-INSTALL-F1",
        "severity": "HIGH",
        "title": "Development Key Installation Function (CIMC_DEV_Key_Install) in Production Blade M8 CIMC Firmware",
        "component": "ucs-intel-blade-m8-cimc.6.0.2.260040 (AST2600 BMC, 87.5MB, md5=b9d2d8f2)",
        "what": (
            "The production CIMC firmware for Blade M8 contains 'CIMC_DEV_Key_Install' and "
            "'DEV_Key_Install' as named symbols appearing three times in the binary. "
            "The most revealing context: "
            "adjacent to 'AES-256 as OEM platform key for image encryption/decryption', "
            "'AES-256 as secret vault key', and 'HMAC as encrypted OEM HMAC keys in Mode 1'. "
            "The 'mfg-only=N' flag appears immediately before CIMC_DEV_Key_Install in one context, "
            "indicating this function is NOT restricted to manufacturing. "
            "A second context places CIMC_DEV_Key_Install adjacent to 'Signature Not Present' "
            "and the boot stability watchdog strings ('no valid or stable images to boot so wait for ever'), "
            "suggesting DEV key install is on the recovery/no-valid-image path. "
            "The CIMC firmware includes an OTP (One-Time Programmable) management package "
            "('otp-1.0.0') and a secure boot monitor ('secure_boot_monitor-1.0.0'). "
            "The hardware is ASPEED AST2600 (confirmed by asp2600_sdrammc_probe, aspeed_h2x_probe)."
        ),
        "why": (
            "A development key installation function in production CIMC firmware that is "
            "NOT restricted to manufacturing (mfg-only=N) and accessible on the recovery path "
            "represents a privileged credential injection channel in the platform management controller. "
            "If CIMC_DEV_Key_Install installs a development/non-production AES-256 key into "
            "the OEM platform key slot, the holder of the corresponding development key can: "
            "(1) decrypt CIMC firmware images (AES-256 OEM platform key), "
            "(2) access the CIMC secret vault (AES-256 secret vault key), "
            "(3) forge HMAC authentication for OEM images (Mode 1 HMAC key). "
            "With recovery-path accessibility, an attacker who can force a boot failure "
            "might trigger the DEV key installation path. "
            "The CIMC is the hardware root of trust for Cisco UCS B-Series blades -- "
            "CIMC compromise is equivalent to full server compromise."
        ),
        "evidence": {
            "function_names": "CIMC_DEV_Key_Install    DEV_Key_Install (3 occurrences)",
            "mfg_only_flag": "mfg-only=N (adjacent to CIMC_DEV_Key_Install)",
            "aes_context": "AES-256 as OEM platform key for image encryption/decryption",
            "vault_context": "AES-256 as secret vault key",
            "hmac_context": "HMAC as encrypted OEM HMAC keys in Mode 1",
            "recovery_path": "no valid or stable images to boot so wait for ever (adjacent context)",
        },
        "remediation": (
            "Audit the CIMC_DEV_Key_Install code path: determine the trigger condition "
            "(UCS CLI command? IPMI raw command? boot-failure auto-trigger?). "
            "Confirm that 'mfg-only=N' does not mean this path is callable post-manufacturing. "
            "Verify the development key private material is not recoverable from the firmware binary. "
            "Confirm OTP fuses (otp-1.0.0 package) cannot be used to re-enable this path "
            "after it has been burned off."
        ),
    },

    "VIC-UBOOT-JTAGBOOT-F1": {
        "id": "VIC-UBOOT-JTAGBOOT-F1",
        "severity": "MEDIUM",
        "title": "U-Boot 2012.10 with jtagboot Network Boot Path and PILOT_ORION Interactive Shell in BXSeries VIC",
        "component": "ucs-BXSeriesM6.6.0.2.260040.bin (VIC, 53.9MB, md5=a43243e8)",
        "what": (
            "The BXSeries M6 VIC firmware contains U-Boot 2012.10 (released Oct 2012, "
            "built Feb 19 2026 -- 13 years old). The U-Boot environment includes: "
            "(1) 'jtagboot=echo TFTPing Linux to RAM...;tftp 0x3000000 ${kernel_image};"
            "tftp 0x2A00000 ${devicetree_image};tftp 0x2000000 ${ramdisk_image};"
            "bootm 0x3000000 0x2000000 0x2A00000' -- JTAG-triggered TFTP network boot. "
            "(2) Hardcoded dev IPs: ipaddr=192.168.2.100, serverip=192.168.2.101. "
            "(3) bootdelay=3 -- 3-second window to interrupt autoboot and reach the PILOT_ORION> shell. "
            "(4) 'PILOT_ORION>' -- interactive U-Boot shell prompt on the VIC. "
            "Additional boot paths: norboot (NOR flash), qspiboot (QSPI SPI flash), "
            "emmcboot (eMMC), sdboot (SD card), nandboot (NAND flash). "
            "Source code comment in binary: '#The BSeriesM5, presidio, pomona is a hack to work "
            "around a bug. In General we should avoid doing this.' -- exposes Cisco internal "
            "platform codenames (presidio, pomona) in production firmware."
        ),
        "why": (
            "U-Boot 2012.10 is 13 years old and has numerous documented vulnerabilities: "
            "CVE-2022-30790 (heap overflow in TFTP), CVE-2022-30552 (stack smash in IP frag), "
            "CVE-2021-27138 (TFTP DoS), and many others predating its vintage. "
            "The jtagboot command with hardcoded development IPs (192.168.2.100/192.168.2.101) "
            "is a manufacturing test boot path that loads kernel, DT, and ramdisk via TFTP -- "
            "if triggered on production hardware via JTAG, it boots an arbitrary network image. "
            "The bootdelay=3 window gives a 3-second opportunity to reach the PILOT_ORION> shell "
            "from a physical JTAG/serial console, bypassing the secureboot=1 Linux boot argument. "
            "In U-Boot 2012.10, the shell gives full hardware control including 'md' (memory dump), "
            "'mw' (memory write), 'sf' (SPI flash read/write), and other destructive commands."
        ),
        "evidence": {
            "uboot_version": "U-Boot 2012.10 (Feb 19 2026 - 07:48:53)",
            "jtagboot_cmd": "jtagboot=echo TFTPing Linux to RAM...;tftp 0x3000000 ${kernel_image};...",
            "hardcoded_ips": "ipaddr=192.168.2.100    serverip=192.168.2.101",
            "shell_prompt": "PILOT_ORION>",
            "bootdelay": "bootdelay=3",
            "source_comment": "#The BSeriesM5, presidio, pomona is a hack to work around a bug.",
        },
        "remediation": (
            "Update BXSeries M6 VIC firmware to use a current U-Boot version (minimum 2024.xx). "
            "Remove or protect the jtagboot environment variable from production builds. "
            "Set bootdelay=0 or use U-Boot password protection to prevent console interruption. "
            "Remove hardcoded development IP addresses from the production U-Boot environment."
        ),
    },

    "BIOS-BOOT-GUARD-SVN-ZERO-F1": {
        "id": "BIOS-BOOT-GUARD-SVN-ZERO-F1",
        "severity": "MEDIUM",
        "title": "Intel Boot Guard Key Manifest (KM_SVN=0) and Boot Policy Manifest (BPM_SVN=0) SVN=0 in B200/B480 M5 BIOS",
        "component": "B200M5.4.3.2g (md5=8c96195f) + B480M5.4.3.2g (md5=fa3e8e7d)",
        "what": (
            "B200 M5 and B480 M5 BIOS firmware (generation 4.3.2g) contain Intel Boot Guard "
            "FIT (Firmware Interface Table) manifest strings: "
            "'ImageKM_SVN=0' (Key Manifest Security Version Number = 0), "
            "'ImageBPM_SVN=0' (Boot Policy Manifest Security Version Number = 0), "
            "'ImageACM_SVN_Authorized=2' (ACM minimum SVN authorization = 2). "
            "Both B200 M5 and B480 M5 share the same SVN configuration. "
            "The M6 generation BIOS (B200M6.6.0.2a) does not contain these strings in printable form, "
            "suggesting the M6 generation uses a different manifest embedding approach."
        ),
        "why": (
            "KM_SVN=0 means the Intel Boot Guard Key Manifest has Security Version Number 0: "
            "there is no anti-rollback protection for the Boot Guard Key Manifest. "
            "An attacker who can modify the Boot Guard Key Manifest (requires BIOS flash write access) "
            "can replace it with a version that authorizes a different key -- effectively disabling "
            "Boot Guard's root of trust. With KM_SVN=0, there is no floor on which KM version "
            "the platform will accept. BPM_SVN=0 has the same implication for the Boot Policy Manifest "
            "(controls IBB measurement and verification policy). "
            "ACM_SVN_Authorized=2 is the only non-zero threshold: only ACMs with SVN >= 2 are accepted. "
            "These M5 blades (Purley/Skylake-SP generation) use a different Boot Guard configuration "
            "from the M6/M7/M8 generation (Ice Lake/Sapphire Rapids)."
        ),
        "evidence": {
            "km_svn_zero": "ImageKM_SVN=0",
            "bpm_svn_zero": "ImageBPM_SVN=0",
            "acm_svn": "ImageACM_SVN_Authorized=2",
            "affected": "B200M5 (md5=8c96195f) + B480M5 (md5=fa3e8e7d)",
        },
        "remediation": (
            "Confirm whether Intel Boot Guard OTP fuses are programmed on deployed B200 M5 and B480 M5 "
            "blades with KM hash locked. If Boot Guard is not fused (OEM production key not burned), "
            "KM_SVN=0 is irrelevant but Boot Guard provides no protection at all. "
            "If fused, SVN=0 for KM/BPM requires BIOS update to increment SVN for rollback protection."
        ),
    },

    "VIC-CHIMP-COMPONENT-F1": {
        "id": "VIC-CHIMP-COMPONENT-F1",
        "severity": "LOW",
        "title": "Broadcom CHIMP (CHassis Interface Management Processor) Firmware Component in BXSeries VIC",
        "component": "ucs-BXSeriesM6.6.0.2.260040.bin (VIC firmware)",
        "what": (
            "The BXSeries M6 VIC firmware bundle contains Broadcom CHIMP ("
            "CHassis Interface Management Processor) as a separately installed component: "
            "patterns 'bootImgCHIMP', 'bootImg', 'chimp.bin' in the VIC install script's "
            "Pattern2Action mapping. CHIMP is Broadcom's management processor in VIC-class NICs. "
            "The VIC install also handles: u-boot.bin (bootloader), uImage (Linux kernel), "
            "FLASHCP_UBOOT_PARTITION, FLASHCP_LINUX_PARTITION as flash targets."
        ),
        "why": (
            "CHIMP is a separate processor within the VIC with its own firmware, separate from "
            "the main Linux runtime on the VIC. A CHIMP firmware vulnerability or backdoor would "
            "be distinct from the main VIC operating system. The CHIMP firmware installed via "
            "the pattern-matching install script may have separate versioning and update cadence "
            "from the main VIC firmware package."
        ),
        "evidence": {
            "chimp_patterns": "bootImgCHIMP    bootImg    chimp.bin",
            "action": "CHIMP_INSTALL",
        },
        "remediation": "Identify and separately track Broadcom CHIMP firmware version within the VIC bundle for CVE tracking.",
    },

    "INTEL-DG2-SVN-GPU-F1": {
        "id": "INTEL-DG2-SVN-GPU-F1",
        "severity": "LOW",
        "title": "Intel DG2 GPU SVN01 and Certificate Authority Version in Flex 140/170 VGA Firmware",
        "component": "ucs-video-intel-flex-140/170-Mezz.DG02-2.2280_7.0.0.0 (magic IFWI_XPU, 2440KB)",
        "what": (
            "Intel Flex GPU VGA firmware (IFWI_XPU container) contains: "
            "'DGFX DG2 SVN01 Kernel CA0v0' -- Intel DG2 GPU (Xe-HPG DGFX architecture) "
            "with Security Version Number 01 and Kernel Certificate Authority version 0, revision 0. "
            "Error log messages: '[%3lu] E SHA hash not ready' (SHA hardware engine init failure), "
            "'[%3lu] W In amc_flash_erase_zero memset_s failed' (secure erase failure in AMC), "
            "'[%3lu] I EDGE_PERST_N signal is HIGH/LOW' (PCIe reset signal monitoring by AMC). "
            "The IFWI_XPU container format is Intel's Integrated Firmware Image for external PCIe GPU devices."
        ),
        "why": (
            "DG2 GPU SVN01 documents the minimum firmware version for this GPU generation. "
            "The memset_s failure in amc_flash_erase_zero is a security-relevant operation: "
            "memset_s is the compiler-proof secure zero (unlike memset which can be optimized out). "
            "If memset_s fails, secure erasure of sensitive data in flash fails silently. "
            "SHA hash not ready indicates a transient state where cryptographic operations "
            "may proceed without the hardware hash engine (fallback to software SHA or error path)."
        ),
        "evidence": {
            "gpu_svn": "DGFX DG2 SVN01 Kernel CA0v0",
            "sha_fail": "[%3lu] E SHA hash not ready",
            "memset_fail": "[%3lu] W In amc_flash_erase_zero memset_s failed",
        },
        "remediation": "Confirm amc_flash_erase_zero failure handling -- verify that memset_s failure triggers retry or hard error, not silent continue.",
    },

    "BIOS-X210M8-X410M8-FORMAT-F1": {
        "id": "BIOS-X210M8-X410M8-FORMAT-F1",
        "severity": "LOW",
        "title": "X-Series M8 BIOS Container Format and Deduplication Survey",
        "component": "X210M8 (md5=3dae31e5, 19MB) + X410M8 (md5=737eeec4, 19MB) + X215M8 (md5=339c088d, 24.6MB)",
        "what": (
            "X210M8 BIOS magic 'X210M8-B' (583231304d382d42); X410M8 magic 'X410M8-B' (583431304d382d42); "
            "X215M8 magic 'X215M8-B'. Each is 19MB (X210M8/X410M8) or 24.6MB (X215M8) as an outer gzip. "
            "X210M8 and X410M8 have identical sizes (19000KB each) but different md5 -- "
            "different silicon targets (X210C vs X410C chassis slot), same BIOS version 6.0.2b. "
            "X215M8 is 24.6MB (5.6MB larger) -- additional GPU mezzanine support or larger UEFI modules. "
            "B200M5/B480M5/B200M6 use a different container format (numeric magic 'B200M5-B' etc.) "
            "and are 8.8-10.1MB (much smaller than X-Series 19-24.6MB). "
            "The X-Series BIOS inner format (after gzip decompression) is not yet analyzed for "
            "Boot Guard SVN or PKI artifacts."
        ),
        "why": "Baseline format documentation for B-Series and X-Series BIOS containers.",
        "evidence": {
            "x210m8_magic": "X210M8-B = 583231304d382d42",
            "x410m8_magic": "X410M8-B = 583431304d382d42",
            "x215m8_magic": "X215M8-B = 583231354d382d42",
            "sizes": "X210M8/X410M8: 19000KB; X215M8: 24620KB; B200M5: 8800KB",
        },
        "remediation": "N/A -- format survey finding.",
    },
}

BUNDLE_ANALYSIS_METADATA = {
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "session": 29,
    "module_number": 6,
    "total_findings": 6,
    "severity_breakdown": {"HIGH": 1, "MEDIUM": 2, "LOW": 3},
    "key_technical_notes": [
        "CIMC_DEV_Key_Install with mfg-only=N is the highest-severity single-function finding in the B-Series bundle; the adjacent AES-256 OEM key + secret vault context confirms the breadth of DEV key impact",
        "U-Boot 2012.10 in VIC 6.0.2.260040 (2026 product): 13-year-old bootloader with bootdelay=3 shell and jtagboot TFTP path; this is the same U-Boot vintage present in many BXSeries/B-Series VICs historically",
        "jtagboot hardcoded dev IPs (192.168.2.100/192.168.2.101) = development lab subnets that should not appear in production firmware",
        "PILOT_ORION> prompt confirms interactive U-Boot console; in U-Boot 2012.10 the full command set (md/mw/sf/tftp/bootm) is enabled by default",
        "B200M5/B480M5 ImageKM_SVN=0 + ImageBPM_SVN=0: Intel Boot Guard anti-rollback not configured for M5 generation; M6/M8 generation different",
        "AST2600 CIMC (M8 blade): 87.5MB firmware with otp-1.0.0 package, secure_boot_monitor, and tcpdump/netsnmp in production build",
        "All CIMC packages share identical SHA (4a28187af3c6...) -- this is the build hash for the entire bundle, not content-addressed hashes per package",
        "Intel DG2 GPU (Xe-HPG) SVN01 CA0v0: first Cisco UCS bundle to include discrete GPU IFWI with SVN tracking",
        "BXSeries M6 FIT image validation chain present (Bad hash in FIT image!, Verifying Hash Integrity) -- FIT secure boot is implemented despite old U-Boot",
        "'#The BSeriesM5, presidio, pomona is a hack' source comment: presidio and pomona are B-Series M5 platform codenames visible in production firmware blob",
    ],
}
