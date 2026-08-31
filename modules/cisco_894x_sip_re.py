"""
Cisco IP Phone 894x SIP firmware reverse engineering module.
Firmware: SIP 9.4.2SR2-2 (cmterm-894x-sip.9-4-2SR2-2.zip — 11-file SGN set)
Platform: ARM926EJ-S (ARMv5TEJ), Linux, glibc 4.3.2 (WRL), OpenSSL 1.1.0-fips-dev
JFFS2 filesystem extracted from concatenated stripped SGN files
"""

FIRMWARE = {
    "model":      "Cisco IP Phone 894x SIP",
    "version":    "9.4.2SR2-2",
    "arch":       "ARM926EJ-S (ARMv5TEJ, 32-bit LE)",
    "build_env":  "Wind River Linux Sourcery G++ 4.3-85",
    "openssl":    "1.1.0-fips-dev (SONAME libssl.so.1.0.0/libcrypto.so.1.0.0 — ABI-compat naming retained)",
    "container":  "Cisco SGN format (same Cisco TLV signature as SBN, .sgn extension)",
    "jffs2_offset_in_concatenated": 0x206e38,
    "jffs2_first_inode": "bcm-debug-info (Broadcom SoC)",
    "file_count": 11,
    "sig_strip_per_file": 512,
    "bin1_size": 3145116,
    "bin10_size": 3145120,
    "bin11_size": 2371948,
    "concatenated_size": 0x2040388,
    "kernel_gzip_offset": 0x3c44,
}

EXTRACTION = {
    "sig_format": (
        "Cisco TLV signature: 01 00 02 01 01 02 00 02 01 9c 03 00 5b 04 00 27 CN=someSigner... "
        "Same format as 8941 SBN. .sgn extension is a rename — structure identical."
    ),
    "file_count_delta": (
        "11 files vs 10 in 8941 9.3.4-17. New file: BOOT894x.0-0-2-0.bin.sgn (111,552 bytes). "
        "This bootloader component is absent in 8941."
    ),
    "bin1_bin2_size_delta": (
        "bin1.sgn: 3,145,116 bytes (4 bytes less than 8941 3,145,120). "
        "Small size difference — likely version metadata change in Cisco TLV header."
    ),
}

# ---- Security library inventory ----

PHN_SURFACE_894x = {
    "libsecurity_so":   "usr/lib/libsecurity.so (ARM926EJ-S, stripped, 61,368 bytes)",
    "libseccommon_so":  "usr/lib/libseccommon.so (ARM926EJ-S, stripped, 28,504 bytes — OpenSSL 1.1.0-fips-dev wrapper)",
    "libssl_so":        "usr/lib/libssl.so.1.0.0 (353,732 bytes)",
    "libcrypto_so":     "usr/lib/libcrypto.so.1.0.0 (1,970,316 bytes)",
    "libtvs_so":        "usr/lib/libtvs.so (34,948 bytes)",
    "libcapf_so":       "usr/lib/libcapf.so (62,464 bytes)",
    "libsrtp_so":       "usr/lib/libsrtp.so (72,768 bytes)",
    "libsecdApi_so":    "lib/libsecdApi.so",
    "libvpnApi_so":     "lib/libvpnApi.so",
    "libvpnPlatform_so":"lib/libvpnPlatform.so",
    "libsipcc_so":      "lib/libsipcc.so",
    "no_cisco_seclib":  "No cisco_seclib/ subdirectory (8941 had this; 894x integrates libs flat in usr/lib/)",
    "openssl_note": (
        "OpenSSL SONAME is 1.0.0 (libssl.so.1.0.0) but actual version string is "
        "'OpenSSL 1.1.0-fips-dev' with date 'reproducible build, date unspecified'. "
        "Cisco forked OpenSSL 1.1.0-dev FIPS branch; maintained 1.0.0 SONAME for ABI compat. "
        "Date scrubbed for reproducible builds."
    ),
}

# ---- PHN-F02 TOFU: CONFIRMED UNPATCHED in 894x 9.4.2SR2-2 ----

PHN_F02_STATUS_894x = {
    "finding_id":   "PHN-F02",
    "base_finding": "8941 SIP 9.3.4-17 libsecurity.so TOFU leap-of-faith CTL/ITL acceptance",
    "status_894x":  "CONFIRMED PRESENT — string 'Using leap of faith to accept TL file' in 894x libsecurity.so",
    "confirmed_string": " Using leap of faith to accept TL file ",
    "implication": (
        "9.4.2SR2-2 did NOT patch PHN-F02. TOFU CTL/ITL bootstrap acceptance persists "
        "across the 8941→894x generation. Factory-reset phones remain exploitable via "
        "DHCP option 150 / TFTP redirect → malicious ITLFile.tlv."
    ),
}

# ---- PHN-F03 SRST bypass: CONFIRMED UNPATCHED in 894x 9.4.2SR2-2 ----

PHN_F03_STATUS_894x = {
    "finding_id":   "PHN-F03",
    "base_finding": "8941 libsecurity.so TVS bypass for SRST/TVS role certs",
    "status_894x":  "CONFIRMED PRESENT — 'not using TVS for cert validation - role is TVS or SRST' in 894x libsecurity.so",
    "confirmed_string": "not using TVS for cert validation - role is TVS or SRST",
}

# ---- PHN-F04 TVS-absent bypass: CONFIRMED UNPATCHED in 894x 9.4.2SR2-2 ----

PHN_F04_STATUS_894x = {
    "finding_id":   "PHN-F04",
    "base_finding": "8941 libsecurity.so TVS-absent bypass (no revocation check when TVS not in ITL)",
    "status_894x":  "CONFIRMED PRESENT — both 'Not using TVS - TVS not in Trust list' and 'VALIDATE CERT - TVS not enabled'",
    "confirmed_strings": [
        "Not using TVS - TVS not in Trust list",
        "VALIDATE CERT - TVS not enabled",
        "Failed to validate cert using TVS",
        "Failed to get signer using TVS",
    ],
}

# ---- PHN-F05 OpenSSL: PATCHED in 894x 9.4.2SR2-2 ----

PHN_F05_STATUS_894x = {
    "finding_id":   "PHN-F05",
    "base_finding": "8941 SIP 9.3.4-17 OpenSSL 0.9.8k CVE-2009-3555 TLS renegotiation injection",
    "status_894x":  "PATCHED — OpenSSL upgraded to 1.1.0-fips-dev from 0.9.8k",
    "old_version":  "8941 9.3.4-17: OpenSSL 0.9.8k 25 Mar 2009",
    "new_version":  "894x 9.4.2SR2-2: OpenSSL 1.1.0-fips-dev (reproducible build, date unspecified)",
    "impact_of_patch": (
        "CVE-2009-3555 TLS renegotiation injection is patched. "
        "RFC 5746 renegotiation_info extension present in 1.1.0. "
        "TLS 1.2 now available (1.1.0 default). "
        "SSLv2 removed in 1.1.0."
    ),
    "residual_surface": (
        "OpenSSL 1.1.0-fips-dev is a development snapshot — not a stable 1.1.0 release. "
        "FIPS module constraints may create operational bypasses. "
        "libssl.so.1.0.0 SONAME vs actual 1.1.0 version creates version-detection confusion "
        "for any scanner that relies on SO naming rather than version strings."
    ),
}

# ---- CTL/ITL trust infrastructure (8941 comparison) ----

CTL_ITL_894x = {
    "confirmed_strings_in_libsecurity": [
        "Could not load CTL File from persistent memory.",
        "Could not load ITL File from persistent memory.",
        "Could not load configuration trust items from persistent memory.",
        "/CTLFile.tlv", "/CTLFile.bak", "/ITLFile.tlv", "/ITLFile.bak",
        "CTL: Failed to update configuration list.",
        "Using TVS for cert validation",
        "Using TVS to get signer",
        "CTL: Found identical existing certificate; no update made.",
        "validateSignedCTL",
        "updateMasterCTLTable",
        "CTL_ParseCTLToTable",
        "parseCTLRecord",
    ],
    "note": (
        "CTL/ITL trust list handling in 894x libsecurity.so is string-identical to 8941 9.3.4-17. "
        "Same code path; same leap-of-faith logic."
    ),
}

# ---- 894x vs 8941 comparison ----

COMPARISON_894x_vs_8941 = {
    "8941_sip_9_3_4_17": {
        "openssl":    "0.9.8k 25 Mar 2009 (CVE-2009-3555 VULNERABLE)",
        "build_env":  "Wind River Linux Sourcery G++ 4.3-85",
        "bin_ext":    ".sbn",
        "files":      10,
        "cisco_seclib_dir": "yes (cisco_seclib/ subdirectory in JFFS2)",
    },
    "894x_sip_9_4_2SR2_2": {
        "openssl":    "1.1.0-fips-dev (CVE-2009-3555 PATCHED)",
        "build_env":  "Wind River Linux Sourcery G++ 4.3-85 (same toolchain)",
        "bin_ext":    ".sgn (rename of .sbn — same Cisco TLV format)",
        "files":      11,
        "cisco_seclib_dir": "no (libs flat in usr/lib/)",
        "new_file":   "BOOT894x.0-0-2-0.bin.sgn (111,552 bytes bootloader)",
    },
    "unchanged": [
        "PHN-F02 TOFU leap-of-faith CTL/ITL acceptance",
        "PHN-F03 SRST role TVS bypass",
        "PHN-F04 TVS-absent bypass",
        "Build toolchain (Wind River Linux Sourcery G++ 4.3-85)",
        "Architecture (ARM926EJ-S ARMv5TEJ)",
        "Security function names and log strings",
    ],
    "changed": [
        "OpenSSL 0.9.8k → 1.1.0-fips-dev (PHN-F05 patched)",
        "Extension: .sbn → .sgn",
        "File count: 10 → 11 (new BOOT binary)",
        "Library layout: cisco_seclib/ dir → flat usr/lib/",
        "SO naming: libssl.so.7 / libcrypto.so.0.9.8g → libssl.so.1.0.0 / libcrypto.so.1.0.0",
    ],
    "assessment": (
        "894x 9.4.2SR2-2 is essentially a point release of 8941 with OpenSSL updated and a new "
        "boot component added. The core trust anchor mechanisms (PHN-F02/F03/F04) are carried "
        "forward unchanged. The 9.4.2SR2 designation confirms this is a security release — "
        "the SR indicates 'Special Release' for security fixes — yet the critical TOFU bypass "
        "was not addressed."
    ),
}

# ---- PHN-CHAIN-894x: Updated attack chain ----

PHN_CHAIN_894x = {
    "scenario": "Unauthenticated remote MITM on 894x SIP phone — 8941 chain applies directly",
    "unchanged_from_8941": [
        "PHN-F02 TOFU: factory-reset → DHCP 150 → malicious ITLFile.tlv → attacker CA installed",
        "PHN-F04 TVS: no TVS in attacker ITL → cert validation is direct-list only → MITM",
        "Call hijack via CUCM registration redirect",
    ],
    "eliminated": [
        "PHN-F05 TLS renegotiation injection (CVE-2009-3555 patched in OpenSSL 1.1.0-fips-dev)",
    ],
    "gate": "Factory reset OR DHCP/TFTP control over network segment (unchanged)",
    "delta": (
        "F05 elimination reduces the MITM → SIP injection chain. "
        "Attacker must rely on DNS/DHCP/TFTP-level redirect rather than TLS injection. "
        "Core trust anchor compromise path (F02→F04) is unaffected."
    ),
}

# ---- New boot component analysis ----

BOOT894x_ANALYSIS = {
    "file":    "BOOT894x.0-0-2-0.bin.sgn",
    "size":    111552,
    "format":  "Cisco TLV signature format (same as SIP binaries)",
    "version": "0.0.2.0",
    "purpose": "Bootloader component absent in 8941 9.3.4-17 — first appearance in 894x",
    "surface": (
        "Cisco ROMMON/bootloader components are a known attack surface for persistent rootkits. "
        "A compromised BOOT binary survives IOS re-flash. Requires physical/console access or "
        "flash write primitives from OS level. Not further analyzed in this pass."
    ),
}
