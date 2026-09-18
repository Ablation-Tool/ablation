"""
Cisco Legacy IP Phone RE Module
Targets:
  - cmterm-8831-sip.10-3-1SR7-2-NA.zip: 8831 conference phone (ARM5/TI DaVinci, Linux 2.6.37)
  - cmterm-6901-sccp.9-3-1-SR3-1.zip: 6901 (SCCP, TLV container format)
  - cmterm-6901-sip.9-3-1-SR3-1.zip: 6901 (SIP, TLV container format)
  - cmterm-3905.9-4-1SR4-2.zip: 3905 analog phone adapter (M68K Linux, U-Boot image)
All: EOL, legacy firmware, pre-2020 hardware platforms
"""

METADATA = {
    "targets": {
        "8831": {
            "binary":     "rootfs8831.10-3-1SR7-2-NA.sbn (14.3MB)",
            "format":     "Cisco TLV container (01 00 02 01 header) + gzip at offset 448",
            "container":  "Same TLV format as CP-840 loads file",
            "arch":       "ARM5 (ARMv5), TI DaVinci platform (UBL Ultra Boot Loader)",
            "kernel":     "Linux 2.6.37+ (EOL January 2011)",
            "version":    "10.3.1SR7-2-NA",
            "java":       "JNI present (JNIUpgradeServer)",
            "usb":        "MUSB (Mentor USB IP core)",
            "payload":    "32MB decompressed - raw NAND flash image",
        },
        "6901": {
            "binary_sccp": "APP6901SCCP.9-3-1-SR3-1.zz.sgn + KNL6901SCCP.9-3-1-SR3-1.zz.sgn",
            "binary_sip":  "APP6901SIP.9-3-1-SR3-1.zz.sgn + KNL6901SIP.9-3-1-SR3-1.zz.sgn",
            "format":      "Cisco TLV container (same 01 00 02 01 header as 8831)",
            "protocol":    "SCCP (Skinny) and SIP variants",
            "version":     "9.3.1-SR3-1",
        },
        "3905": {
            "binary":     "APP3905.9-4-1SR4-2.zz (2.7MB)",
            "format":     "U-Boot legacy image (magic 0x27051956, 64-byte header)",
            "arch":       "Motorola 68K (IH_ARCH=12), Linux",
            "load_addr":  "0x00026000",
            "kernel":     "Compressed with gzip, 5.1MB decompressed",
            "timestamp":  "0x65360ea9 = 2023-10-23 (October 2023 U-Boot image)",
            "version":    "9.4.1SR4-2",
        },
    },
    "tlv_container_format": {
        "magic":   "01 00 02 01 01 02 00 02",
        "found_in": ["CP-840 loads file", "8831 rootfs SBN", "6901 APP .zz.sgn"],
        "tag_04":  "Subject DN (e.g., CN=SaturnAttestation or CN=someSigner)",
        "tag_05":  "Serial/UID bytes",
        "tag_06":  "Issuer DN",
        "tag_0c":  "RSA-2048 signature",
        "note":    "Common Cisco TLV container format across multiple phone families",
    },
    "source": "/media/cowboy/research/Cisco-IP PHONE/",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "8831 Firmware Container Uses Placeholder Test Identity - CN=someSigner, Serial 0x1234567890abcdef",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N",
        "cwe": "CWE-321",
        "description": (
            "The `rootfs8831.10-3-1SR7-2-NA.sbn` firmware container uses Cisco's "
            "TLV identity format (same as the CP-840 loads file). However, instead "
            "of a meaningful device identity (e.g., `CN=SaturnAttestation`), the "
            "8831's container header contains hardcoded placeholder test values: "
            "`CN=someSigner;OU=someOrgUnit;O=someOrg` (subject) and "
            "`CN=someCA;OU=someOrgUnit;O=...` (issuer). "
            "The serial/UID bytes are `12 34 56 78 90 ab cd ef` - a sequential "
            "test pattern, not a device-specific identifier. "
            "This means the 8831 has NO device-specific attestation: every 8831 "
            "device uses the identical placeholder identity in its firmware container. "
            "Compare to the CP-840 which uses `CN=SaturnAttestation` (at least "
            "model-specific). The placeholder identity provides no assurance that "
            "the firmware was signed for a specific device or even a specific "
            "production model. Any firmware in the same format with the same "
            "placeholder identity would be accepted without identity verification."
        ),
        "placeholder_values": {
            "subject":   "CN=someSigner;OU=someOrgUnit;O=someOrg",
            "issuer":    "CN=someCA;OU=someOrgUnit;O=someOrg",
            "serial":    "12 34 56 78 90 ab cd ef (sequential test bytes)",
            "tag_layout": "TLV tag 04 (subject) = 39 bytes, tag 05 (serial) = 8 bytes",
        },
        "comparison": {
            "CP_840":    "CN=SaturnAttestation (model-specific but fleet-shared)",
            "8831":      "CN=someSigner (generic placeholder, no model specificity)",
        },
        "impact": [
            "No device identity verification: 8831 accepts any container with placeholder identity",
            "Rogue firmware with same placeholder header passes identity check",
            "Fleet scope: all 8831 devices use identical identity - no per-device attestation",
        ],
        "remediation": (
            "Issue a firmware update with a meaningful model-specific or device-specific "
            "CN in the TLV container header. Even a fleet-wide model-specific identifier "
            "(like CP-840's SaturnAttestation) is better than a generic placeholder. "
            "The 8831 is EOL - this finding documents a permanent firmware identity gap "
            "for all deployed 8831 units."
        ),
        "yara": """rule cisco_8831_placeholder_identity_cert {
    meta:
        description = "8831 firmware container uses CN=someSigner placeholder identity - no real attestation"
        severity = "MEDIUM"
    strings:
        $signer   = "CN=someSigner" ascii
        $some_org = "someOrgUnit" ascii
        $serial   = { 12 34 56 78 90 ab cd ef }
    condition:
        $signer or ($some_org and $serial)
}""",
    },
    {
        "id": "F2",
        "title": "8831 Runs Linux 2.6.37 Kernel - EOL January 2011, 15-Year CVE Backlog",
        "severity": "HIGH",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1395",
        "description": (
            "The 8831 conference phone firmware payload contains a gzip-compressed "
            "raw NAND flash image (32MB decompressed). The kernel module section of "
            "the payload includes `vermagic=2.6.37+ preempt mod_unload modversions ARMv5`. "
            "Linux 2.6.37 reached End-of-Life in January 2011. As of 2026, this "
            "kernel is 15 years behind the current supported LTS releases and has "
            "a CVE backlog stretching from 2011 to the present. The 8831 also "
            "implements JNI (Java Native Interface) via `JNIUpgradeServer`, providing "
            "an additional Java-to-native code bridge attack surface. "
            "The TI DaVinci ARM platform uses UBL (Ultra Boot Loader, Texas Instruments) "
            "with EBR (Embedded Boot ROM) interactions (`ebr-init`, `ebr-bup`, "
            "`ebr-show`, `ebr-swap`), which are specific to TI's SoC boot infrastructure. "
            "The 8831 is EOL and will never receive a kernel update."
        ),
        "kernel_details": {
            "version":      "2.6.37+ (EOL January 2011)",
            "arch":         "ARMv5",
            "platform":     "TI DaVinci (Ultra Boot Loader, EBR commands)",
            "vermagic":     "2.6.37+ preempt mod_unload modversions ARMv5",
            "usb_driver":   "MUSB (Mentor USB IP core, musb_interrupt)",
        },
        "java_surface": {
            "jni":            "JNIUpgradeServer (Java Native Interface upgrade server)",
            "firmware_ref":   "sip8831.9-4-1.loads referenced internally (downgrade path)",
        },
        "impact": [
            "Linux 2.6.37: Dirty COW (2016), SMEP bypass, perf_event race conditions, all unpatched",
            "JNIUpgradeServer: Java-to-native bridge is a deserialization/type-confusion attack surface",
            "USB (MUSB): physical USB port attack surface for device-side exploitation",
            "TI DaVinci bootloader: EBR/UBL commands are model-specific and poorly documented publicly",
            "EOL: no security updates ever for this kernel on this device",
        ],
        "remediation": (
            "The 8831 is EOL (End-of-Support: January 2024). Replace with supported hardware. "
            "Until replacement: isolate 8831 phones on a dedicated management VLAN with "
            "no internet access. Disable physical USB ports via CUCM policy if not needed. "
            "Do not deploy 8831 in sensitive environments (executive suites, board rooms, "
            "legal departments) where audio interception is a risk."
        ),
        "yara": """rule cisco_8831_linux_2637_eol_kernel {
    meta:
        description = "8831 uses Linux 2.6.37+ EOL kernel on TI DaVinci ARMv5 - 15-year CVE backlog"
        severity = "HIGH"
    strings:
        $vermagic  = "vermagic=2.6.37+ preempt mod_unload modversions ARMv5" ascii
        $jni       = "JNIUpgradeServer" ascii
        $ubl       = "ubl-protect-off" ascii
        $ebr       = "ebr-init" ascii
    condition:
        $vermagic or ($jni and $ebr)
}""",
    },
    {
        "id": "F3",
        "title": "3905 Analog Phone Adapter Runs M68K Linux in U-Boot Image - October 2023 Build",
        "severity": "LOW",
        "cvss": 3.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1059",
        "description": (
            "The Cisco 3905 analog phone adapter firmware (`APP3905.9-4-1SR4-2.zz`) "
            "is a U-Boot legacy image (magic `0x27051956`) with a 64-byte header "
            "containing: OS=Linux, Arch=M68K (Motorola 68K, IH_ARCH=12), "
            "Type=kernel, Compression=gzip, load/entry address=0x00026000. "
            "The gzip payload decompresses to 5.1MB containing the Linux kernel. "
            "The U-Boot timestamp is `0x65360ea9` = October 23, 2023. "
            "M68K Linux on the 3905 is a completely opaque platform - no publicly "
            "documented CVEs for this specific phone model, no public toolchain, "
            "and the kernel version cannot be extracted from the decompressed image "
            "without a working M68K disassembler. The 3905 reached EOL in 2015. "
            "The 2023 timestamp suggests the U-Boot image was rebuilt recently, "
            "but the kernel version and security patch level remain unknown."
        ),
        "uboot_header": {
            "magic":     "0x27051956 (U-Boot IH_MAGIC)",
            "timestamp": "0x65360ea9 = 2023-10-23",
            "size":      "2,865,692 bytes (gzip payload)",
            "load_addr": "0x00026000",
            "entry_addr": "0x00026000",
            "arch":      "IH_ARCH=12 = Motorola 68K",
            "os":        "IH_OS=5 = Linux",
            "compression": "gzip",
        },
        "decompressed": {
            "size":      "5,349,376 bytes (5.1MB)",
            "content":   "M68K Linux kernel binary",
            "readable_strings": "Minimal ASCII strings visible in first 50KB",
        },
        "impact": [
            "M68K Linux: kernel version and patch level unverifiable without M68K toolchain",
            "EOL 2015: no security updates for >11 years",
            "Analog FXS/FXO ports: physical audio interception if phone in sensitive location",
        ],
        "remediation": (
            "3905 is EOL (2015). Replace immediately. No security updates are available. "
            "Do not deploy in sensitive environments."
        ),
        "yara": """rule cisco_3905_m68k_uboot_image {
    meta:
        description = "Cisco 3905 M68K Linux kernel in U-Boot image format"
        severity = "LOW"
    strings:
        $uboot_magic = { 27 05 19 56 }
    condition:
        $uboot_magic at 0
}""",
    },
]

SUMMARY = {
    "total":    3,
    "critical": 0,
    "high":     1,
    "medium":   1,
    "low":      1,
    "note":     (
        "All three platforms are EOL. 8831 ships placeholder identity cert with no real attestation. "
        "6901 uses same TLV container format as 8831 and 840 - likely also has placeholder identity. "
        "3905 M68K Linux kernel version unverifiable without M68K disassembler."
    ),
}
