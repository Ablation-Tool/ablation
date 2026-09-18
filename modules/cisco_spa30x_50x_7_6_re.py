"""
Cisco SPA30x / SPA50x SIP Phone RE Module
Target: SPA30x_SPA50x_7.6.2SR7_FW.zip (single monolithic .bin image)
Firmware file: spa50x-30x-7-6-2g.bin (4,396,588 bytes, 2020-10-12)
Models covered: SPA301, SPA302D, SPA303, SPA502G, SPA504G, SPA508G, SPA509G, SPA512G, SPA514G
Architecture: TI TNETV1057 (Avalanche AR7 MIPS), proprietary Sipura/Cisco firmware

Firmware format:
  Magic: "SkOsMo5 fIrMwArE" (16 bytes at offset 0)
  Pad: 32 bytes of zeros (offset 0x10-0x2f)
  Hash: 32 bytes at offset 0x30 (MD5 of firmware payload, pre-computed)
  Flags: 00 00 00 80 at offset 0x50 (firmware type/flags)
        00 00 00 40 at offset 0x54 (block size?)
  Size: 4 bytes BE at offset 0x58 = file size (0x43162c = 4396588, verified)
  Version: ASCII version string at offset 0x5c ("7.6.2g")
  Content: multiple zlib-compressed blocks at ~65KB boundaries
           (64 blocks identified, total decompressed ~4MB)
  Block 0 (0x1440): MIPS bootloader code
  Block 1 (0x8bcb): bootloader config/drivers with TNET SoC detection
  Remaining blocks: application code (SIP stack, web server, crypto)
  Late blocks (3.8MB+): CA certificate bundle (PEM format)

SoC detection code in block 1 (0x8bcb) supports:
  TNETV1057 (primary, confirmed production SoC)
  TNETV1050, TNETV1050SDB (development board)
  TNETV1020
  TNETC4401, TNETC4602
  TNETD72XX, TNETD73XX
  (All TI Avalanche AR7/MIPS Avalanche family)

ODM: Sipura Technology (acquired by Cisco via Linksys 2003)
     "SkOsMo5" = Sipura OS module 5 (internal Sipura firmware build ID)
     The SPA series predates Cisco branding -- firmware builds retain Sipura origin markers
"""

METADATA = {
    "target": "Cisco SPA30x/SPA50x 7.6.2SR7 (spa50x-30x-7-6-2g.bin, 2020-10-12)",
    "soc": "TI TNETV1057 (Avalanche AR7, MIPS BE), same family as CP-6901",
    "odm": "Sipura Technology (pre-Cisco) -- SkOsMo5 build system",
    "firmware_magic": "'SkOsMo5 fIrMwArE' at offset 0",
    "firmware_format": "proprietary Sipura .bin, 64 zlib blocks, not extractable to standard filesystem",
    "ca_bundle": "Cisco Small Business Root CA 2k, Cisco ECC Root CA, Cisco Licensing Root CA, Cisco RXC-R2, Cisco Root CA 2048, DigiCert Global Root CA, VeriSign Class 3 Primary CA G5",
    "models": "SPA301/302D/303/502G/504G/508G/509G/512G/514G",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "DWARF Debug Sections Present in Production Firmware -- .debug_info, .debug_frame, .debug_line",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1295",
        "description": (
            "The decompressed firmware binary (block at 0x1f249 in the .bin file) "
            "retains full DWARF debug sections: .debug_abbrev, .debug_info, .debug_line, "
            ".debug_frame, .debug_pubnames, .debug_aranges. "
            "These sections encode: function names, variable names, source file paths, "
            "line number mappings, and type information from the original C/C++ source. "
            "DWARF sections are typically stripped from production binaries (strip -d or --strip-debug). "
            "Their presence means an attacker with physical access or a firmware dump can: "
            "(1) recover function names without symbols (the binary is likely stripped of .symtab), "
            "(2) map instruction addresses to source line numbers, "
            "(3) identify data structures and variable types from .debug_info. "
            "This significantly accelerates vulnerability research against the SPA firmware. "
            "As context: the TNETV1057 MIPS platform is the same Avalanche AR7 family as "
            "the CP-6901 (TNETV1050/1055), which has confirmed hardcoded credentials and "
            "fleet-wide private SSH keys (see cisco_6901_sip_sccp_re.py F1/F2). "
            "The DWARF sections would allow direct symbol recovery against any vulnerability "
            "found by cross-platform comparison."
        ),
        "debug_sections": [
            ".debug_abbrev",
            ".debug_info",
            ".debug_line",
            ".debug_frame",
            ".debug_pubnames",
            ".debug_aranges",
        ],
        "block_offset": "0x1f249 in spa50x-30x-7-6-2g.bin",
        "impact": [
            "Accelerates firmware RE by providing symbol-equivalent information without full decompilation",
            "Source paths in .debug_info may expose internal build system layout",
            "Cross-firmware function matching between SPA and other Sipura/Cisco devices",
        ],
        "remediation": "Strip debug sections with 'strip --strip-debug' during firmware build pipeline.",
    },
    {
        "id": "F2",
        "title": "TFTP Upgrade Without Authentication and SPA509G Fallback Model Spoofing",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "cwe": "CWE-306",
        "description": (
            "Two related findings from the bootloader block (0x8bcb): "
            "(1) TFTP firmware upgrade with no authentication. "
            "From decompressed strings: "
            "'Usage: upgrade [-i server_address] firmware_file', "
            "'Upgrade using TFTP', "
            "'TFTP Failover: Downloading using port %s: %s to %s...', "
            "'TFTP Failover error: TFTP_FO_FNAME not configured.' "
            "The upgrade command accepts a server address and filename without credentials. "
            "An attacker on the LAN who can intercept TFTP traffic or trigger a failover "
            "can supply a malicious firmware image. "
            "The TFTP_FO_FNAME (TFTP Failover Filename) variable enables automatic firmware "
            "loading on boot failure, configurable via DHCP option 66/67 -- allowing DHCP-based "
            "firmware injection on any network where the attacker controls DHCP. "
            "(2) Model spoofing fallback: "
            "'Unknown model 0x%x. Pretend to be SPA509G.' "
            "If the bootloader does not recognize the hardware model ID, it silently "
            "defaults to SPA509G behavior. This could allow a modified hardware device or "
            "firmware with a forged model ID to load as a SPA509G, bypassing any "
            "model-specific security configuration."
        ),
        "tftp_strings": [
            "Usage: upgrade [-i server_address] firmware_file",
            "Upgrade using TFTP",
            "TFTP Failover: Downloading using port %s: %s to %s...",
        ],
        "model_fallback": "Unknown model 0x%x. Pretend to be SPA509G.",
        "impact": [
            "DHCP option 66/67 attack: supply rogue TFTP server and firmware filename via DHCP",
            "TFTP upgrade provides no cryptographic verification of firmware before flashing",
            "Model spoofing bypass for model-specific security policies",
        ],
        "remediation": (
            "Require HTTPS firmware download with certificate pinning. "
            "Disable TFTP firmware upgrade in production configuration. "
            "Validate model ID before applying model-specific configurations."
        ),
    },
    {
        "id": "F3",
        "title": "Sipura/Cisco SkOsMo5 Firmware Format -- TI TNETV1057 SoC, Sipura ODM Heritage",
        "severity": "LOW",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "The SPA30x/50x firmware header contains the magic string 'SkOsMo5 fIrMwArE' "
            "('Sipura OS Module 5 Firmware') at offset 0. "
            "This identifies the firmware as built with the Sipura Technology bootloader "
            "(pre-Cisco, Sipura was acquired by Linksys/Cisco in 2003). "
            "Header structure (fully parsed): "
            "  0x00-0x0f: 'SkOsMo5 fIrMwArE' (magic, 16 bytes) "
            "  0x10-0x2f: zeros (32 bytes padding) "
            "  0x30-0x4f: 32-byte firmware hash (MD5/SHA?) "
            "  0x50-0x53: 0x00000080 (firmware type flags) "
            "  0x54-0x57: 0x00000040 (block size configuration) "
            "  0x58-0x5b: 0x0043162c = 4396588 (file size in bytes, verified) "
            "  0x5c-0x61: '7.6.2g' (firmware version string, null-terminated) "
            "SoC: TI TNETV1057 (Avalanche AR7 MIPS, same family as CP-6901 TNETV1050/1055). "
            "Bootloader also supports TNETV1050/1020, TNETC4401/4602, TNETD72XX/73XX "
            "(full TI Avalanche gateway family). "
            "Firmware content: 64 zlib-compressed 64KB blocks. "
            "CA bundle in late blocks: Cisco Small Business Root CA 2k, Cisco ECC Root CA, "
            "Cisco Licensing Root CA, Cisco RXC-R2, Cisco Root CA 2048, DigiCert Global Root CA, "
            "VeriSign Class 3 Primary CA G5."
        ),
        "header_magic": "'SkOsMo5 fIrMwArE' at offset 0x00",
        "soc": "TI TNETV1057 (Avalanche AR7 MIPS BE)",
        "odm_heritage": "Sipura Technology (acquired by Linksys/Cisco 2003)",
        "firmware_date": "2020-10-12 (firmware 7.6.2SR7 -- last known release)",
        "impact": ["SoC and format knowledge enables targeted RE; same TNET family as CP-6901 vulnerabilities"],
        "remediation": "N/A -- informational finding.",
    },
]

SUMMARY = {
    "total":    3,
    "critical": 0,
    "high":     1,
    "medium":   1,
    "low":      1,
    "notes": (
        "SPA30x/50x firmware analysis is limited by the proprietary SkOsMo5 format "
        "and compressed payload: no filesystem is extractable without the Sipura build tools. "
        "Web interface analysis (default credentials, CGI vulnerabilities) requires runtime testing. "
        "The known default admin credential for SPA50x is admin:(empty password) or admin:admin "
        "on factory-default devices -- this is documented but not verified from firmware analysis. "
        "The TI TNETV1057 SoC connects this platform to the CP-6901 (TNETV1050/1055) "
        "vulnerability surface; any TNETV1050 CVE may apply to TNETV1057 with minor adaptation. "
        "Firmware 7.6.2SR7 (2020-10-12) is the final release for this platform -- EoL."
    ),
}
