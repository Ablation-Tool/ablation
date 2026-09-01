"""
Cisco IP Phone 894x SCCP firmware reverse engineering module.
Firmware: SCCP 9.4.2SR2-2 (cmterm-894x-sccp.9-4-2SR2-2.zip — 11-file SGN set)
Platform: ARM926EJ-S (ARMv5TEJ), Linux, Wind River Linux 3.0, OpenSSL 1.1.0-fips-dev
JFFS2 offset: 0x222000 (vs SIP 0x206e38 — SCCP concat is 28.5MB vs SIP 33.8MB)
Key finding: libsecurity.so binary-identical to 894x SIP — PHN-F02/F03/F04 confirmed in SCCP.
New finding PHN-F11: dropbear 0.51 SSH with no auth restrictions; /etc/passwd is PNG.
"""

FIRMWARE = {
    "model":       "Cisco IP Phone 894x SCCP",
    "version":     "9.4.2SR2-2",
    "arch":        "ARM926EJ-S (ARMv5TEJ, 32-bit LE)",
    "build_env":   "Wind River Linux 3.0 GA, arm11_le-glibc_small toolchain",
    "build_path":  "/home/gumbo/pj/branches/942/gumbo/src/OnePhone/build-output/SCCP894x.9-4-2SR2-2/GUMBO/",
    "openssl":     "1.1.0-fips-dev (PHN-F05 patched vs 8941 0.9.8k)",
    "container":   "Cisco SGN format (same as SIP .sgn — 512-byte Cisco TLV strip)",
    "jffs2_offset_in_concatenated": 0x222000,
    "file_count":  11,
    "sig_strip_per_file": 512,
    "concat_size": 0x1b35a34,
    "protocol":    "SCCP (Skinny Client Control Protocol)",
    "jffs2_delta_from_sip": (
        "SCCP concat 28,531,252 bytes vs SIP 33,817,480 bytes — 5.3MB smaller. "
        "JFFS2 at 0x222000 (SCCP) vs 0x206e38 (SIP). "
        "SIP has libsipcc.so + libccserv.so + libdba.so + libmsiApi.so (SIP protocol stack); "
        "SCCP omits these — SCCP stack is embedded directly in phone firmware blobs."
    ),
}

# ---- Security library comparison: 894x SCCP vs 894x SIP ----

LIBRARY_COMPARISON_894x_SCCP_vs_SIP = {
    "libsecurity_so": {
        "sccp_sha256": "061dcc3215bc37fc05801b8b85795614888320c35993e781c5803e60ffeafbb8",
        "sip_sha256":  "061dcc3215bc37fc05801b8b85795614888320c35993e781c5803e60ffeafbb8",
        "result": "IDENTICAL",
        "implication": "PHN-F02/F03/F04 present in SCCP 9.4.2SR2-2 by binary identity",
    },
    "libseccommon_so": {"result": "IDENTICAL", "implication": "OpenSSL 1.1.0-fips-dev same (PHN-F05 patched)"},
    "libssl_so_1_0_0": {"result": "IDENTICAL"},
    "libcrypto_so_1_0_0": {
        "sccp_size": 1970316, "sip_size": 1970316,
        "result": "DIFFERS — same size, different binary",
        "note": (
            "libcrypto.so.1.0.0 differs between SCCP and SIP 894x. "
            "Same size (1,970,316 bytes) but different SHA256. "
            "Both versions are OpenSSL 1.1.0-fips-dev per libseccommon.so (which is identical). "
            "Difference likely SCCP-specific FIPS crypto configuration or build flags."
        ),
    },
    "libtvs_so":  {"result": "IDENTICAL"},
    "libcapf_so": {"result": "IDENTICAL", "note": "Unlike 8941 where libcapf.so differed, 894x libcapf.so is same"},
    "libsrtp_so": {"result": "IDENTICAL"},
    "sip_only_libs": ["libsipcc.so", "libccserv.so", "libdba.so", "libmsiApi.so"],
}

# ---- PHN findings in 894x SCCP ----

PHN_F02_STATUS_894x_SCCP = {
    "finding_id": "PHN-F02",
    "status_894x_sccp": "CONFIRMED PRESENT — binary-identical libsecurity.so to 894x SIP",
    "sha256": "061dcc3215bc37fc05801b8b85795614888320c35993e781c5803e60ffeafbb8",
    "confirmed_string": " Using leap of faith to accept TL file ",
}

PHN_F03_STATUS_894x_SCCP = {
    "finding_id": "PHN-F03",
    "status_894x_sccp": "CONFIRMED PRESENT — binary-identical libsecurity.so",
    "confirmed_string": "not using TVS for cert validation - role is TVS or SRST",
}

PHN_F04_STATUS_894x_SCCP = {
    "finding_id": "PHN-F04",
    "status_894x_sccp": "CONFIRMED PRESENT — binary-identical libsecurity.so",
    "confirmed_strings": ["Not using TVS - TVS not in Trust list", "VALIDATE CERT - TVS not enabled"],
}

PHN_F05_STATUS_894x_SCCP = {
    "finding_id": "PHN-F05",
    "status_894x_sccp": "PATCHED — OpenSSL 1.1.0-fips-dev (same as 894x SIP; same libseccommon.so binary)",
}

# ---- PHN-F11: Dropbear SSH 0.51 with no auth restrictions ----

PHN_F11_DROPBEAR_SSH = {
    "id":     "PHN-F11",
    "title":  "Dropbear SSH 0.51 (2008-era) starts with no auth restrictions",
    "binary": "/usr/sbin/dropbear (549,851 bytes, ARM EABI5)",
    "version": "SSH-2.0-dropbear_0.51",
    "debug_info": "WITH debug_info, not stripped (SCCP) vs stripped (SIP) — different SHA256",
    "init_invocation": "/usr/sbin/dropbear & (no -w, no -g flags)",
    "auth_flags": {
        "-w (Disallow root logins)": "NOT USED — root login enabled",
        "-g (Disable password logins for root)": "NOT USED — root password auth enabled",
    },
    "passwd_file": (
        "/etc/passwd in JFFS2 is a 38x65 PNG image — not a real password file. "
        "Authentication data lives in nvdata partition (mounted at boot from UBIFS or JFFS2 at /nvdata). "
        "Factory reset clears nvdata → no password set → dropbear rejects blank passwords ('user has blank password, rejected'). "
        "BUT: if nvdata is not cleared, whatever password was set persists."
    ),
    "root_gumbo_account": (
        "Dropbear contains the string 'root-gumbo' near pty_allocate code. "
        "Format string '%s-gumbo' precedes it. "
        "This is a Cisco-patched dropbear modification that appends '-gumbo' to logged usernames. "
        "It is not a separate account — it is a log/audit annotation. "
        "Authentication targets are whatever users exist in the nvdata passwd store."
    ),
    "dropbear_0_51_cves": [
        "CVE-2007-1099: remote code execution in pubkey auth (pre-0.50)",
        "CVE-2012-0920: heap use-after-free in SSH client (0.52 fix)",
        "Dropbear 0.51 is pre-CVE-2012-0920 — use-after-free present",
        "libtomcrypt/libtommath (embedded) — vintage 2008 — multiple known math library issues",
    ],
    "chain": (
        "Network access → dropbear TCP 22 → "
        "password auth attempt against nvdata user store → "
        "if default/weak password (or blank accepted pre-check): shell on phone as root → "
        "libsecurity.so access → ITL/CTL manipulation → PHN-F02 re-trigger or trust anchor substitution"
    ),
    "severity": "HIGH — direct network-accessible attack surface; auth depends on nvdata content",
    "build_path_leak": "/home/gumbo/pj/branches/942/gumbo/src/OnePhone/build-output/SCCP894x.9-4-2SR2-2/GUMBO/dropbear-0.51",
}

# ---- Filesystem structure: PNG-as-system-file anti-forensics ----

PNG_SYSTEM_FILE_PATTERN = {
    "files_affected": ["/etc/passwd", "/etc/group", "/etc/passwd~", "/etc/group~",
                       "/etc/cfg_global.sh", "/etc/dropbear.sh", "/etc/dropbear_start.sh"],
    "behavior": (
        "JFFS2 stores small PNG images at paths that correspond to critical system files. "
        "cat /etc/passwd → PNG binary data. "
        "Text content (actual script or config) is appended AFTER the PNG IEND marker. "
        "Shell scripts stored this way work because sh/bash ignores binary prefix if "
        "the file is sourced with '. /etc/script.sh' or sourced from another script that reads "
        "the portion after IEND. jefferson extracts the full content including the PNG header."
    ),
    "forensic_impact": (
        "Standard forensic tools that identify files by magic bytes will classify "
        "/etc/passwd and /etc/group as PNG images, not credential files. "
        "This could cause automated forensics tools to skip them. "
        "Manual analysis required to extract the post-IEND content."
    ),
    "passwd_content": "PNG data only (38x65, RGBA) — no text after IEND — auth is fully in nvdata partition",
}

# ---- nvdata partition: runtime-mounted auth store ----

NVDATA_AUTH_STORE = {
    "path": "/nvdata",
    "mount_init": "/etc/init.d/nvdata (UBIFS ubi1:nvdata or JFFS2 mtdblock)",
    "secure_data_path": "/nvdata/SecureData (CRC-protected, same PHN-F10 pattern as 8941 SCCP)",
    "auth_significance": (
        "User accounts and passwords for dropbear SSH are in the nvdata partition. "
        "Not in static JFFS2. "
        "Factory reset → nvdata cleared → blank password → dropbear rejects. "
        "Shipped/deployed phones with nvdata populated are the risk surface."
    ),
    "telnetd_present": "/usr/sbin/telnetd present but init.d/apps has it commented out",
}

# ---- 894x SCCP vs 8941 SCCP comparison ----

SCCP_894x_vs_8941_COMPARISON = {
    "libsecurity_so": {
        "8941_sccp": "SHA256 61315c88... (OpenSSL 0.9.8k, PHN-F05 VULNERABLE)",
        "894x_sccp": "SHA256 061dcc32... (OpenSSL 1.1.0-fips-dev, PHN-F05 PATCHED)",
        "delta": "Different build, same function signatures (PHN-F02/F03/F04 strings identical in both)",
    },
    "libplatform_so": {
        "8941_sccp": "105,237 bytes — large SCCP CPR layer with nvdata CRC wipe (PHN-F10)",
        "894x_sccp": "NOT YET COMPARED — needs explicit analysis",
    },
    "shared": [
        "PHN-F02/F03/F04 TOFU + SRST + TVS-absent bypass strings (confirmed in both)",
        "SDES-SRTP (no DTLS-SRTP)",
        "DHCP option 150 / TFTP provisioning path",
        "nvdata secure store path",
    ],
    "894x_additions": [
        "Dropbear SSH 0.51 with no auth restrictions (PHN-F11)",
        "PNG-as-system-file pattern for /etc/passwd",
        "libcrypto.so.1.0.0 differs between SCCP and SIP (new in 894x)",
    ],
}
