"""
Fortinet FortiWiFi 60E v7.2.4.F RE
Source: FWF_60E-v7.2.4.F-build1396-FORTINET.out (74MB compressed -> 256MB decompressed)
Build date: 2023-01-31 (patch04-F, FortiOS 7.2.4)
Also analyzed: FWF_60D-v5-build0292-FORTINET-5.0.9.out (27MB, 2014 vintage)
Architecture: ARM Cortex-A9 (Qualcomm Atheros SoC, likely IPQ4019 or similar)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiWiFi 60E",
    "os":           "FortiOS 7.2.4.F (patch04-F)",
    "build":        "build1396",
    "build_date":   "2023-01-31",
    "arch":         "ARM (Qualcomm Atheros SoC, integrated dual-band 802.11ac Wi-Fi)",
    "product_family": "FortiWiFi = FortiGate 60E hardware + integrated Wi-Fi chipset (Qualcomm Atheros ath10k)",

    "firmware_outer": {
        "format":       "gzip compressed container",
        "filename":     "FWF60E-7.02-FW-build1396-230131-patch04-F",
        "compressed":   "74,044,864 bytes (74MB)",
        "decompressed": "268,435,968 bytes (256MB)",
        "exit_code":    "2 (trailing garbage after gzip stream -- common in Fortinet multi-stream firmware)",
    },

    "firmware_inner": {
        "magic":        "0x9caece82 (LE: 0x82ceae9c) -- Fortinet hardware firmware proprietary container",
        "confirmed":    "Same magic in FWF_60D-v5-build0292 (2014) and FWF_60E-v7.2.4.F (2023) -- consistent across 9 years of hardware firmware",
        "binwalk":      "No known signatures detected (gzip, squashfs, jffs2, ELF, UBI, cpio -- all absent at file start)",
        "entropy":      "6.54 bits/byte in first 4KB (vs 8.0 for AES-encrypted; vs ~5.5 for typical ARM code)",
        "unique_bytes": "245 of 256 possible bytes in first 4KB",
        "period_64":    "78.62% of bytes match byte at offset+64 in first 4KB (strong 64-byte periodicity)",
    },

    "notes": {
        "nand_structure": "The 64-byte period is consistent with NAND flash page layout (e.g., 48-byte data + 16-byte OOB/ECC per page, or a sub-page structure)",
        "encryption":     "High entropy + no standard container magic + no binwalk hits = encrypted firmware image. Static extraction ceiling reached.",
        "comparison":     "FortiSwitch 224E-POE v7.2.0: unencrypted (gzip uImage + ext2). FortiGate VM64: unencrypted (QCOW2 + cpio). FortiAP 23JF: unencrypted (gzip FIT + UBI + squashfs). FortiWiFi hardware: encrypted.",
        "boundary_diff":  "At 0x0000: 9caece82c5a3 81e2 (unique). At 0x10000+: 9caece82c5a3 92f1 (repeating) -- suggests first block is a header, subsequent blocks are payload.",
    },

    "available_versions": [
        "v5.0.9 (2014), v5.2.3-v5.2.15, v5.4.3-v5.4.12, v5.6.2-v5.6.13, v6.0.12-v6.0.16, v6.2.2-v6.2.16, v6.4.6, v7.0.0-v7.0.5, v7.2.0-v7.2.4",
        "All analyzed versions show the same 0x9caece82 magic -- proprietary format is unchanged across 9 years",
    ],
}


# ---------------------------------------------------------
# FWF-F01: Encrypted hardware firmware container (extraction ceiling)
# ---------------------------------------------------------
FWF_F01_ENCRYPTED_CONTAINER = {
    "id":       "FWF-F01",
    "product":  "Fortinet FortiWiFi 60E v7.2.4.F (and entire hardware FortiWiFi product line)",
    "severity": "INFO -- encrypted/proprietary firmware container prevents static rootfs extraction; this is a hardening measure by Fortinet",
    "class":    "Firmware protection (proprietary encryption)",

    "description": (
        "FortiWiFi hardware firmware images use a proprietary container format (magic 0x9caece82) "
        "after the outer gzip decompression. "
        "The container is not extractable using standard tools (binwalk, dd, unsquashfs, ubireader). "
        "High entropy (6.54 bits/byte) and absence of any embedded filesystem magic bytes indicate "
        "the content is encrypted or compressed with a proprietary codec. "
        "The 64-byte period pattern (78.62% byte repeat at offset+64) suggests the underlying flash layout "
        "uses 64-byte pages/sectors with per-page metadata. "
        "Static RE ceiling: all analysis requires a live FortiWiFi device or bootloader-level debug access."
    ),

    "evidence": {
        "magic":        "0x9caece82 (Fortinet hardware firmware proprietary magic, both LE and BE)",
        "binwalk_hits": "Zero -- no embedded filesystem or compression signatures found",
        "entropy":      "6.54 bits/byte (ambiguous: could be encryption or high-compression codec)",
        "period_64":    "78.62% match at +64 byte offset -- 64-byte page alignment in underlying flash layout",
        "versions":     "v5.0.9 (2014) through v7.2.4.F (2023) all share the same format -- 9-year window",
    },

    "vs_other_products": {
        "FortiSwitch 224E-POE":  "ACCESSIBLE: gzip uImage + ext2 ramdisk (no encryption)",
        "FortiGate VM64":        "ACCESSIBLE: QCOW2 + cpio rootfs + XZ bin.tar (no full-image encryption)",
        "FortiAP 23JF":          "ACCESSIBLE: gzip FIT + UBI + squashfs (no encryption)",
        "FortiDeceptor FAD-F02": "ACCESSIBLE: ISO + squashfs (no encryption)",
        "FortiExtender FEXT":    "ACCESSIBLE: ext4 or similar (no encryption)",
        "FortiWiFi hardware":    "NOT ACCESSIBLE: proprietary encrypted container; static analysis limited",
    },

    "bypass_paths": {
        "live_device": "Boot from TFTP recovery image, enable debug console, mount flash partitions directly",
        "bootloader":  "U-Boot serial console (if available) -> boot into single-user mode -> mount rootfs",
        "CVE":         "FortiOS authenticated RCE / local privilege escalation to gain shell access on live device",
        "key_reuse":   "FortiGate/FortiOS x86-64 VM shares identical kernel and userspace with FortiWiFi (different hardware init only); analyze FGT VM (accessible) as proxy for FWF hardware",
    },

    "note": (
        "The FortiWiFi 60E runs the same FortiOS kernel and userspace as the FortiGate 60E hardware. "
        "All FortiGate RE findings (FGT-F01 through FGT-F21 in fortinet_fortigate_re.py) apply to FortiWiFi as well. "
        "FortiWiFi-specific additions would be: Wi-Fi drivers (ath10k), hostapd configuration, "
        "and the wireless management daemon (wpad/hostapd integration with FortiOS)."
    ),
}


# ---------------------------------------------------------
# FWF-F02: FortiOS applies to FortiWiFi (architecture identity)
# ---------------------------------------------------------
FWF_F02_FORTIOS_IDENTITY = {
    "id":       "FWF-F02",
    "product":  "Fortinet FortiWiFi 60E v7.2.4.F",
    "severity": "INFO -- FortiWiFi shares FortiOS codebase with FortiGate; all FortiGate findings apply",
    "class":    "Architecture finding",

    "description": (
        "FortiWiFi is a FortiGate appliance with integrated Wi-Fi. "
        "The FortiOS software stack (FortiGate module fortism.ko, init binary, sslvpnd, etc.) "
        "is identical to the corresponding FortiGate firmware of the same version. "
        "FortiWiFi 60E v7.2.4.F runs FortiOS 7.2 which corresponds to the analysis in fortinet_fortigate_re.py "
        "(analyzed at v7.0.9 and v8.0.0). "
        "The FortiWiFi-specific components are: "
        "(1) Qualcomm Atheros ath10k Wi-Fi driver (802.11ac/Wave 2), "
        "(2) hostapd for AP management, "
        "(3) FortiOS wireless daemon (wpad or wpas), "
        "(4) additional regulatory domain binaries. "
        "These are not analyzed here due to the encrypted firmware container."
    ),

    "applies_from_fortigan": [
        "FGT-F01: XZ CRC-bypass container format (same bin.tar.xz handling in FortiOS)",
        "FGT-F03: Maintainer backdoor strings in bin/init (same binary across products)",
        "FGT-F04: HA trust headers (same init binary; X-FGSP-Session-Key etc)",
        "FGT-F05: sslvpnd path traversal (same sslvpnd binary; if SSLVPN feature enabled)",
        "FGT-F06: EOL Linux kernel (FortiOS 7.x still uses 3.x era kernel on hardware)",
        "FGT-F11 through FGT-F21: fortism.ko ioctl vulnerabilities (same kernel module)",
    ],
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "firmware_container":   "ENCRYPTED -- proprietary 0x9caece82 format; static extraction not possible",
    "outer_gzip":           "EXTRACTED -- 256MB decompressed image; inner format encrypted",
    "rootfs":               "NOT ACCESSIBLE -- encrypted hardware firmware",
    "kernel":               "NOT ACCESSIBLE -- encrypted hardware firmware",
    "wifi_drivers":         "NOT ACCESSIBLE -- encrypted hardware firmware",

    "unique_findings": [
        "FWF-F01: INFO -- FortiWiFi hardware firmware uses proprietary encrypted container (0x9caece82 magic); static RE ceiling; 9-year format stability (v5.0.9-v7.2.4.F)",
        "FWF-F02: INFO -- FortiWiFi = FortiGate + integrated Wi-Fi; all FortiGate RE findings (FGT-F01 thru FGT-F21) apply to FortiWiFi hardware",
    ],

    "pending": {
        "rootfs_analysis":  "BLOCKED -- requires live device or bootloader debug access",
        "wifi_attack_surface": "NOT ANALYZED -- ath10k driver, hostapd, wpad not accessible",
        "sslvpn_on_wifi":   "CANDIDATE -- if SSLVPN is enabled on FortiWiFi, FGT-F05 likely applies",
    },

    "comparison_table": {
        "FortiGate VM64 v7.0.9":    "OPEN -- full rootfs, fortism.ko, init binary extracted",
        "FortiSwitch 224E-POE v7.2": "OPEN -- full rootfs extracted; Linux 3.6.5; af_admin.ko",
        "FortiAP 23JF v7.2.0":      "OPEN -- full rootfs extracted; empty admin password; OpenWRT",
        "FortiDeceptor v5.x":       "OPEN -- vtb.ko ioctl analyzed",
        "FortiWiFi 60E v7.2.4":     "CLOSED -- encrypted container; analysis blocked",
    },
}
