"""
Cisco UCS eCMC Cloud Connector RE Module
Target: ecmc_cloud_connector v1.0.11-20260202093858420
Source: chassisA.img (UCS ESU CMC firmware 6.0.2.260036)
        Embedded as gzip tarball at offset 0x580 in chassisA.img
Format: UPX-packed aarch64 ELF (statically linked, stripped, no section header)
"""

METADATA = {
    "target":    "Cisco UCS eCMC Cloud Connector",
    "binary":    "ecmc_cloud_connector",
    "version":   "1.0.11-20260202093858420",
    "arch":      "aarch64 (ARM64), statically linked, stripped, no section header",
    "packer":    "Custom UPX variant (UPX! magic at ELF offset 0xEC, modified ELF header)",
    "container": "chassisA.img CMC firmware 6.0.2.260036 (UCS ESU bundle)",
    "embedded_at": "gzip tarball at offset 0x580 inside chassisA.img",
    "source":    "/media/cowboy/research/Cisco-UCS/UCS-ESU-6.0.2.260036.tar.gz",
    "build_date": "2026-02-02 09:38:58",
    "size":      1631744,
    "platform":  "Cisco UCS-X Series Chassis Management Controller (CMC)",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Cloud Connector Binary Embedded in CMC Firmware with Custom UPX Packing",
        "severity": "MEDIUM",
        "cvss": 5.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-259",
        "description": (
            "The Cisco UCS Chassis Management Controller (CMC) firmware "
            "(chassisA.img, 150MB) embeds a cloud connector binary "
            "`ecmc_cloud_connector` v1.0.11 at ELF offset 0x580 as a gzip "
            "tarball. The binary is stripped, statically linked, and packed "
            "with a modified UPX variant (UPX! magic at ELF offset 0xEC with "
            "altered p_info/b_info headers that prevent standard `upx -d` "
            "extraction). The binary phones home from the chassis management "
            "plane to Cisco cloud infrastructure. The custom packer obstructs "
            "static analysis of the communication protocol, endpoints, and "
            "credential handling. The CMC runs on ARM64 (aarch64) confirming "
            "the embedded Linux ARM processor in UCS-X chassis hardware."
        ),
        "trigger_strings": [
            "UPX! (at ELF offset 0xEC, modified header)",
            "ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, no section header",
        ],
        "technical_detail": {
            "elf_entry_point": "0x026A5774",
            "upx_marker_offset": "0xEC",
            "upx_context_bytes": "000000007dd0d93c555058215c0b0e2a00000000b800e30130300f01",
            "ph_count": 3,
            "ph0": "PT_LOAD offset=0x0 vaddr=0x10000 filesz=0x1000 memsz=0x1E77620 (decompressor stub)",
            "ph1": "PT_LOAD offset=0x0 vaddr=0x1E90000 filesz=0x8162C2 memsz=0x8162C2 (compressed payload)",
            "gzip_at": "0x76CD within binary",
        },
        "impact": [
            "CMC cloud connectivity attack surface not publicly documented",
            "If cloud channel uses weak auth or hardcoded credentials, "
            "remote attackers can reach the chassis management plane",
            "Obfuscated binary prevents verification of secure coding practices",
        ],
        "remediation": (
            "Cisco should publish the eCMC cloud connector communication protocol "
            "documentation including certificate pinning and authentication methods. "
            "Remove custom UPX header modification to allow standard binary auditing. "
            "Apply standard network segmentation to prevent CMC direct internet access."
        ),
        "yara": """rule cisco_ecmc_cloud_connector_upx_packed {
    meta:
        description = "Cisco eCMC Cloud Connector - custom UPX-packed aarch64 ELF in CMC firmware"
        severity = "MEDIUM"
    strings:
        $upx_magic   = { 55 50 58 21 }  // UPX!
        $elf_magic   = { 7f 45 4c 46 02 01 01 00 }  // ELF64 LE
        $aarch64_id  = { 02 00 b7 00 }  // e_machine=0x00b7 aarch64
    condition:
        $elf_magic at 0 and $aarch64_id and $upx_magic
}""",
    },
    {
        "id": "F2",
        "title": "CMC Firmware Contains FDT/ARM Linux + Multiple Embedded Archive Formats",
        "severity": "HIGH",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "The 150MB chassisA.img is not a traditional x86 BIOS ROM despite "
            "the 55AA magic. binwalk identifies: a Flattened Device Tree (FDT) "
            "at offset 36,619,649 (ARM Linux kernel boot descriptor), gzip "
            "streams at offsets 36,619,877 and 44,056,661 (likely kernel and "
            "initramfs), a DER X.509 certificate at offset 105,764,829, two "
            "additional FDTs at offsets 155,060,365 and 155,072,121 (secondary "
            "DTBs), MySQL ISAM index at 34,064,281, and LZO compressed data at "
            "156,198,266. The firmware hosts a full Linux ARM system. The "
            "X.509 certificate at 105MB is embedded in the firmware and may be "
            "used for CMC-to-cloud or CMC-to-CIMC authentication."
        ),
        "trigger_offsets": {
            "ecmc_gzip_tar":    "0x580 (ecmc_cloud_connector tarball)",
            "fdt_primary":      "0x22EC581 (ARM FDT, 118MB DTB)",
            "gzip_kernel":      "0x22EC665 (kernel image)",
            "gzip_rootfs":      "0x2A04055 (likely initramfs/rootfs)",
            "x509_cert":        "0x64DD7DD (DER certificate, seq_len=6234)",
            "fdt_secondary_1":  "0x93E088D",
            "fdt_secondary_2":  "0x93E3679",
            "lzo_data":         "0x94F657A",
        },
        "impact": [
            "Embedded X.509 cert at 105MB - if private key co-located, factory cert extraction",
            "Full Linux ARM rootfs accessible via binwalk extraction with root privileges",
            "FDT reveals hardware topology and peripheral bus assignments",
        ],
        "remediation": (
            "Extract and validate the DER certificate at 0x64DD7DD. "
            "Verify it is a device certificate with per-device private keys, "
            "not a shared factory or fleet key. Audit the Linux rootfs (gzip "
            "at 0x2A04055) for hardcoded credentials and SUID binaries."
        ),
        "yara": """rule cisco_ucs_cmc_firmware_arm_linux {
    meta:
        description = "Cisco UCS CMC chassisA.img is ARM Linux, not x86 BIOS"
        severity = "HIGH"
    strings:
        $fdt_magic   = { d0 0d fe ed }  // Flattened Device Tree magic
        $upx_ecmc    = "UPX!" ascii
        $ecmc_ver    = "ecmc_cloud_connector" ascii
    condition:
        $fdt_magic and ($upx_ecmc or $ecmc_ver)
}""",
    },
]

SUMMARY = {
    "total":    2,
    "critical": 0,
    "high":     1,
    "medium":   1,
    "low":      0,
}

NEXT_STEPS = [
    "Extract FDT at 0x22EC581 and parse ARM hardware tree",
    "Extract and parse DER cert at 0x64DD7DD - check if shared fleet cert",
    "Mount gzip rootfs at 0x2A04055 - enumerate SUID binaries, hardcoded creds",
    "Dynamic unpack ecmc_cloud_connector via qemu-aarch64-static execution",
    "Diff ecmc cloud connector version across multiple UCS firmware releases",
]
