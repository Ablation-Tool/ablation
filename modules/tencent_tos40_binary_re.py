"""
TencentOS Server 4.0 Binary RE Module
Binaries: ssh-agent, libssl.so.3.0.12, libssh.so.4.9.5
Source: tencentos-server-4.0-x86_64.tar (Docker container layer, build 20240311)
Method: layer.tar extraction + string scan + ELF dynsym
Analysis date: 2026-09-04

TOS 4.0 ships as a container image (Docker layer tarball) rather than a qcow2.
The sshd binary is absent from the container layer (server-only sshd package not
included in the container base). Analysis uses ssh-agent and libssl/libssh.

KEY FINDING: TOS 4.0 libssl (OpenSSL 3.0.12-3.tl4) has NO TLCP/SM symbols.
The TLCP patch (wynnfeng@tencent.com, 2024-04-15) was added between TOS 4.0 and 4.4.
libssl grows from 660KB (TOS 4.0) to 803KB (TOS 4.4/4.6) when the TLCP patch is applied.

FINDINGS SUMMARY:
  TOS40-F01 (HIGH, patched)  CVE-2023-38408 PATCHED — "provider not allowed" in ssh-agent
  TOS40-F02 (HIGH, patched)  CVE-2023-48795 PATCHED — kex-strict in libssh 0.10.5
  TOS40-F03 (MEDIUM/5.9)    TLCP ABSENT — libssl 3.0.12-3.tl4 has no GM/T 0024-2014 support
  TOS40-F04 (INFO)           OpenSSH 9.3p2-8.tl4 — same major version as TOS 4.4/4.6
  TOS40-F05 (INFO)           libssh 0.10.5 — identical version to TOS 4.2/4.6
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS40-F01: CVE-2023-38408 PKCS#11 — PATCHED
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_38408_TOS40 = {
    "finding_id": "TOS40-F01",
    "severity": "HIGH (patched)",
    "status": "PATCHED",
    "binary": "ssh-agent",
    "openssh_package": "openssh-9.3p2-8.tl4",
    "confirmed_strings": [
        'Refusing add key: provider %s not allowed',
        'refusing PKCS#11 add of "%.100s": provider not allowed',
    ],
    "wording": "not allowed (consistent with TOS 4.2/4.4/4.6 — OpenSSH 9.x naming)",
    "note": (
        "TOS 4.0 ships OpenSSH 9.3p2-8.tl4 which includes the full pkcs11 "
        "permitted_providers fix. Both the primary and fallback error strings confirmed. "
        "Package counter -8 (vs -2 in TOS 4.4 for the equivalent package) suggests "
        "TOS 4.0 received additional patches in the base openssh package."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS40-F02: CVE-2023-48795 Terrapin — PATCHED (via libssh)
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_48795_TOS40 = {
    "finding_id": "TOS40-F02",
    "severity": "HIGH (patched)",
    "status": "PATCHED",
    "binary": "libssh.so.4.9.5",
    "libssh_version": "0.10.5",
    "kex_strict_strings_confirmed": [
        "kex-strict-c-v00@openssh.com",
        ",kex-strict-s-v00@openssh.com",
        "Client supports strict kex, enabling.",
    ],
    "note": (
        "libssh 0.10.5 with kex-strict confirmed in TOS 4.0. "
        "Same version as TOS 4.2/4.6 libssh (0.10.5). "
        "sshd binary unavailable in container layer (not included in base container image). "
        "sshd CVE status inferred from OpenSSH package version (9.3p2 confirmed patched "
        "in TOS 4.2/4.4/4.6 where the binary is available)."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS40-F03: TLCP ABSENT in libssl 3.0.12
# ──────────────────────────────────────────────────────────────────────────────

TLCP_ABSENT_TOS40 = {
    "finding_id": "TOS40-F03",
    "severity": "MEDIUM",
    "cvss_v3": 5.9,
    "title": "TOS 4.0 libssl has no TLCP (GM/T 0024-2014) support",
    "binary": "libssl.so.3.0.12",
    "openssl_package": "openssl-3.0.12-3.tl4",
    "file_size_kb": 660,
    "tlcp_exported_symbols": 0,
    "sm_cipher_exported_symbols": 0,
    "evidence": [
        "nm -D libssl.so.3.0.12: 0 symbols matching TLCP or tlcp",
        "String scan: 0 strings containing TLCP, tlcp, SM4, SM2 in libssl",
        "No ssl_method_st for TLCP method code 0x101",
    ],
    "comparison_with_tos44": {
        "TOS_4.0_libssl_size_kb": 660,
        "TOS_4.4_libssl_size_kb": 803,
        "size_delta_kb": 143,
        "delta_explanation": (
            "~143KB added between TOS 4.0 and TOS 4.4 is attributable to the "
            "TLCP patch set (openssl-3.0.12-support-tlcp.patch, ~600+ LOC, "
            "authored by wynnfeng@tencent.com, 2024-04-15). "
            "TOS 4.4 ships openssl-3.0.12-3.tl4 vs TOS 4.0's same base package, "
            "but TOS 4.4 adds the tencent-tlcp patch group in the SRPM."
        ),
    },
    "attack_surface": (
        "Applications on TOS 4.0 that require TLCP for China GM/T 0024-2014 "
        "compliance (banking, government, regulated sectors) will fail to "
        "negotiate TLCP and silently fall back to standard TLS or fail entirely. "
        "No runtime error is generated — the SSL_CTX_enable_tlcp() symbol does "
        "not exist in this build, so calls to it fail at link/dlsym time."
    ),
    "tlcp_introduction_version": "TOS 4.4 (confirmed — 18 TLCP symbols, full API)",
    "ref_module": "tencent_tos44_binary_re.py",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS40-F04/F05: OpenSSH and libssh versions
# ──────────────────────────────────────────────────────────────────────────────

TOS40_VERSION_INVENTORY = {
    "openssh": {
        "finding_id": "TOS40-F04",
        "package": "openssh-9.3p2-8.tl4",
        "version": "OpenSSH_9.3p2",
        "binary_available": "ssh-agent (302KB, Feb 17 2024)",
        "sshd_available": False,
        "note": "Package counter -8 vs TOS 4.4's -2; TOS 4.0 base received more patches",
    },
    "libssh": {
        "finding_id": "TOS40-F05",
        "package": "libssh-0.10.5",
        "binary": "libssh.so.4.9.5",
        "source_ref": "libssh-0.10.5/src/packet_crypt.c",
        "identical_version_in": ["TOS 4.2", "TOS 4.6"],
    },
    "libssl": {
        "binary": "libssl.so.3.0.12",
        "package": "openssl-3.0.12-3.tl4",
        "size_kb": 660,
        "tlcp": False,
        "openssl_string": "3.0.12-3.tl4.x86_64.debug",
        "build_date": "2024-03-11",
    },
    "libcrypto": {
        "binary": "libcrypto.so.3.0.12",
        "package": "openssl-3.0.12-3.tl4",
        "build_date": "2024-03-11",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# TLCP INTRODUCTION TIMELINE (cross-version)
# ──────────────────────────────────────────────────────────────────────────────

TLCP_INTRODUCTION_TIMELINE = {
    "title": "TLCP (GM/T 0024-2014) availability across TOS versions",
    "TOS_3.1": "ABSENT — OpenSSL 1.1.1k, predates TLCP patch",
    "TOS_3.3": "PRESENT (limited) — libssl.so.1.1, 3 method exports, 14 internal fns, no enable/disable API",
    "TOS_4.0": "ABSENT — OpenSSL 3.0.12-3.tl4, no TLCP patch applied",
    "TOS_4.2": "PRESENT (full API) — libssl.so.3, 10+ TLCP symbols",
    "TOS_4.4": "PRESENT (full API) — libssl.so.3, 18 TLCP symbols, cert CRUD API",
    "TOS_4.6": "PRESENT (full API) — libssl.so.3, 18 TLCP symbols, identical to TOS 4.4",
    "patch_author": "wynnfeng@tencent.com",
    "patch_date_confirmed": "2024-04-15 (from TOS 4.6 SRPM analysis)",
    "note": (
        "TOS 3.3 has TLCP in OpenSSL 1.1.1 codebase (different patch line from 3.0.x). "
        "TOS 4.0 shows OpenSSL 3.0.x was initially shipped without TLCP. "
        "TOS 4.2 received the first 3.0.x TLCP patch, TOS 4.4/4.6 finalized the API. "
        "The gap between TOS 4.0 (TLCP absent) and TOS 4.2 (TLCP present) locates "
        "the patch introduction window to the 4.0→4.2 update cycle."
    ),
    "ref_modules": [
        "tencent_tos33_libssl_tlcp_re.py",
        "tencent_tos44_binary_re.py",
        "tencent_tos46_libssl_tlcp_binary_re.py",
        "tencent_tos46_baseos_source_re.py",
    ],
}
