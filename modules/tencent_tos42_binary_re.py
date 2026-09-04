"""
TencentOS Server 4.2 Binary RE Module
Binaries: sshd, ssh-agent, libssl.so.3 (from TOS 4.2 qcow2, date: 20241018)
Source: /dev/nbd14 mount of TOS 4.2 qcow2 TencentOS-Server-GenericCloud-4.2-20241018.1.x86_64
Method: String scan + ELF dynsym + binary comparison with TOS 4.4/4.6
Analysis date: 2026-09-04

TOS 4.2 spans 5 GenericCloud qcow2 builds (2024-05-15 through 2024-10-18).
This module covers the latest (20241018).

KEY DIFFERENCE FROM TOS 4.4/4.6: sshd is OpenSSH_9.3 (without p2 suffix) — a different
build artifact. kex-strict string at file_offset 0x9f244 vs 0xa1244 in TOS 4.4/4.6.
The PKCS#11 "not allowed" wording matches TOS 4.4 (OpenSSH 9.x terminology).

FINDINGS SUMMARY:
  TOS42-F01 (HIGH/7.3)   CVE-2023-48795 PATCHED — kex-strict at 0x9f244 in OpenSSH_9.3
  TOS42-F02 (HIGH/7.3)   CVE-2023-38408 PATCHED — "not allowed" wording in ssh-agent
  TOS42-F03 (INFO)        sshd OpenSSH_9.3 (no p2 suffix) — different build from TOS 4.4/4.6
  TOS42-F04 (INFO)        TLCP full API present in libssl.so.3 (10 TLCP symbols, 23 cert symbols)
  TOS42-F05 (INFO)        SM4-GCM(128) present in libssl.so.3
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS42-F01: CVE-2023-48795 Terrapin — PATCHED
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_48795_TOS42 = {
    "finding_id": "TOS42-F01",
    "severity": "HIGH (patched)",
    "status": "PATCHED",
    "binary": "sshd",
    "openssh_version": "OpenSSH_9.3",
    "kex_strict_string": "PRESENT",
    "kex_strict_file_offset": 0x9f244,
    "note": (
        "kex-strict offset differs from TOS 4.4/4.6 (0xa1244) because TOS 4.2 "
        "ships a different sshd build (OpenSSH_9.3 vs 9.3p2). "
        "Different build, same security feature."
    ),
    "comparison": {
        "TOS_4.2": {"version": "OpenSSH_9.3",   "size_kb": 971, "kex_strict_offset": 0x9f244},
        "TOS_4.4": {"version": "OpenSSH_9.3p2", "size_kb": 983, "kex_strict_offset": 0xa1244},
        "TOS_4.6": {"version": "OpenSSH_9.3p2", "size_kb": 983, "kex_strict_offset": 0xa1244},
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS42-F02: CVE-2023-38408 PKCS#11 — PATCHED
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_38408_TOS42 = {
    "finding_id": "TOS42-F02",
    "severity": "HIGH (patched)",
    "status": "PATCHED",
    "binary": "ssh-agent",
    "string_confirmed": {
        "file_offset": 0x28798,
        "value": 'refusing PKCS#11 provider "%.100s": not allowed',
    },
    "wording": "not allowed (consistent with TOS 4.4 — OpenSSH 9.x API naming)",
    "binary_comparison": {
        "TOS_4.2_size_kb": 309,
        "TOS_4.4_size_kb": 314,
        "identical": False,
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS42-F03: OpenSSH_9.3 vs 9.3p2 (different build)
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_VERSION_NOTE = {
    "finding_id": "TOS42-F03",
    "severity": "INFO",
    "title": "TOS 4.2 ships OpenSSH_9.3 (not p2) — different from TOS 4.4/4.6",
    "tos42_version": "OpenSSH_9.3",
    "tos44_version": "OpenSSH_9.3p2",
    "tos46_version": "OpenSSH_9.3p2",
    "size_difference": "TOS 4.2 sshd: 971KB vs TOS 4.4/4.6: 983KB",
    "binary_identity": {
        "tos42_vs_tos44": False,
        "tos42_vs_tos46": False,
        "tos44_vs_tos46": True,  # 4.4 and 4.6 are identical
    },
    "note": (
        "OpenSSH 9.3p2 was released 2023-08-20 to fix CVE-2023-38408. "
        "OpenSSH 9.3 (no p suffix) is the same code but packaged differently. "
        "The 'p' suffix in OpenSSH indicates portable version number (not a security revision). "
        "Both versions have the Terrapin fix (kex-strict) — Terrapin was disclosed Nov 2023, "
        "after 9.3, and was backported to existing versions."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS42-F04/F05: TLCP and SM4-GCM in libssl.so.3
# ──────────────────────────────────────────────────────────────────────────────

TOS42_LIBSSL_ANALYSIS = {
    "finding_id": "TOS42-F04",
    "libssl_size_kb": 803,
    "tlcp_symbols_count": 10,    # symbols with 'tlcp' in name
    "cert_symbols_count": 23,    # symbols with 'certificate' in name
    "api_present": [
        "TLCP_method",
        "TLCP_server_method",
        "TLCP_client_method",
        "SSL_is_tlcp",
        "SSL_CTX_enable_tlcp",
        "SM4-GCM(128)",
    ],
    "libssl_comparison": {
        "TOS_4.2_size_kb": 803,
        "TOS_4.4_size_kb": 803,
        "identical": False,  # different build, same feature set
    },
    "sm4_gcm": {
        "finding_id": "TOS42-F05",
        "string_found": "SM4-GCM(128) present in libssl.so.3",
        "note": "RFC 8998 SM4-GCM TLS 1.3 cipher suite available in TOS 4.2",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# TOS 4.2 QCOW2 BUILD INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

TOS42_BUILD_INVENTORY = {
    "builds": [
        "TencentOS-Server-GenericCloud-4.2-20240515.0.x86_64.qcow2",
        "TencentOS-Server-GenericCloud-4.2-20240619.0.x86_64.qcow2",
        "TencentOS-Server-GenericCloud-4.2-20240729.2.x86_64.qcow2",
        "TencentOS-Server-GenericCloud-4.2-20240902.0.x86_64.qcow2",
        "TencentOS-Server-GenericCloud-4.2-20241018.1.x86_64.qcow2",  # analyzed
    ],
    "analyzed_build": "20241018 (latest)",
}

# ──────────────────────────────────────────────────────────────────────────────
# FULL CROSS-VERSION CVE POSTURE TABLE (all analyzed versions)
# ──────────────────────────────────────────────────────────────────────────────

FULL_VERSION_CVE_TABLE = {
    "versions_analyzed": ["3.1", "3.3", "4.2", "4.4", "4.6"],
    "CVE_2023_38408_PKCS11": {
        "TOS_3.1 (openssh-8.0p1-13)": "OPEN",
        "TOS_3.3 (openssh-8.0p1-25)": "PATCHED ('not whitelisted')",
        "TOS_4.2 (openssh-9.3)":      "PATCHED ('not allowed')",
        "TOS_4.4 (openssh-9.3p2)":    "PATCHED ('not allowed')",
        "TOS_4.6 (openssh-9.3p2)":    "PATCHED ('not allowed')",
    },
    "CVE_2023_48795_Terrapin": {
        "TOS_3.1 (openssh-8.0p1-13)": "OPEN",
        "TOS_3.3 (openssh-8.0p1-25)": "PATCHED (kex-strict confirmed)",
        "TOS_4.2 (openssh-9.3)":      "PATCHED (kex-strict at 0x9f244)",
        "TOS_4.4 (openssh-9.3p2)":    "PATCHED (kex-strict at 0xa1244)",
        "TOS_4.6 (openssh-9.3p2)":    "PATCHED (identical to TOS 4.4)",
    },
    "CVE_2023_4911_Looney_Tunables": {
        "TOS_3.1 (glibc-2.28-189.5)": "OPEN (predates CVE, no update channel)",
        "TOS_3.3":                     "UNKNOWN (not analyzed)",
        "TOS_4.2":                     "UNKNOWN (glibc not extracted)",
        "TOS_4.4":                     "UNKNOWN (glibc not extracted)",
        "TOS_4.6 (glibc-2.38-49)":    "PATCHED (from SRPM analysis)",
    },
    "TLCP_implementation": {
        "TOS_3.1":                     "ABSENT (pre-dates TLCP patch 2024-04-15)",
        "TOS_3.3 (libssl.so.1.1)":     "PRESENT (3 method exports, 14 internal fns)",
        "TOS_4.2 (libssl.so.3)":       "PRESENT (full API, 10+ TLCP symbols)",
        "TOS_4.4 (libssl.so.3)":       "PRESENT (18 TLCP symbols, full CRUD API)",
        "TOS_4.6 (libssl.so.3)":       "PRESENT (identical to TOS 4.4)",
    },
    "compat_openssl10_CVE_2022_0778": {
        "TOS_3.1":                     "PATCHED (-4 counter, May 2022, terminal)",
        "TOS_3.3+":                    "UNKNOWN (not analyzed)",
    },
}
