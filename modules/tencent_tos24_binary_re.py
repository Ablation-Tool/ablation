"""
TencentOS Server 2.4 Binary RE Module
Binaries: sshd (837KB), ssh-agent (374KB), libssl.so.1.0.2k (460KB)
Source: TencentOS-Server-2.4-TK4-x86_64-minimal-20260725.1.iso (2026-07-25 build)
        openssh-7.4p1-23.tl2.7.x86_64.rpm, openssl-libs-1.0.2k-26.tl2.2.x86_64.rpm
Method: ISO mount → rpm2cpio extraction → string scan
Analysis date: 2026-09-04

TOS 2.4 is based on CentOS 7 (RHEL7) with custom Tencent kernel (TK4).
The 2026-07-25 ISO shows TOS 2.4 is still actively maintained (latest ISO 6 weeks pre-analysis).
OpenSSH 7.4p1 base is from December 2016; TencentOS applies security backports
through the -NNN.tl2 counter system rather than upgrading the upstream version.

KEY FINDINGS:
- OpenSSH 7.4p1 with both CVE-2023-38408 and CVE-2023-48795 backported (~7yr old base)
- OpenSSL 1.0.2k (2017 release) with 26 rebuild cycles — FIPS-capable, no TLCP
- openssl098e also present (0.9.8e — 2008 era, for legacy application compat)

FINDINGS SUMMARY:
  TOS24-F01 (HIGH, patched)  CVE-2023-38408 PATCHED — "not whitelisted" in ssh-agent (backport)
  TOS24-F02 (HIGH, patched)  CVE-2023-48795 PATCHED — kex-strict in sshd (backport)
  TOS24-F03 (INFO)           OpenSSL 1.0.2k-fips EoL base, 26 tl2 rebuild cycles
  TOS24-F04 (INFO)           TLCP absent — OpenSSL 1.0.2k predates the TLCP patch line
  TOS24-F05 (HIGH)           openssl098e-0.9.8e compat library: EoL since 2015 (OpenSSL project)
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS24-F01: CVE-2023-38408 PKCS#11 — PATCHED (backport to 7.4p1)
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_38408_TOS24 = {
    "finding_id": "TOS24-F01",
    "severity": "HIGH (patched)",
    "status": "PATCHED",
    "binary": "ssh-agent",
    "openssh_package": "openssh-7.4p1-23.tl2.7",
    "openssh_banner": "OpenSSH_7.4p1-RHEL7-7.4p1-23",
    "confirmed_strings": [
        '[-P pkcs11_whitelist] [-t life] [command [arg ...]]',
        'refusing PKCS#11 add of "%.100s": provider not whitelisted',
    ],
    "wording": "not whitelisted (pre-rename API — same as TOS 3.3 OpenSSH 8.0p1)",
    "api_flag_name": "pkcs11_whitelist",
    "note": (
        "CVE-2023-38408 was fixed upstream in OpenSSH 9.3p2 (Aug 2023) with the "
        "full permitted_providers mechanism. For legacy versions, the fix was "
        "backported as the pkcs11_whitelist flag using 'not whitelisted' wording. "
        "TOS 2.4 backported this into the 7.4p1 codebase — roughly 7 years behind "
        "the original release (2016 → 2023). The backport appears in revision -23.tl2.7."
    ),
    "api_evolution": {
        "TOS_2.4 (7.4p1-23)": "pkcs11_whitelist flag, 'not whitelisted' message",
        "TOS_3.3 (8.0p1-25)": "pkcs11_whitelist flag, 'not whitelisted' message",
        "TOS_4.2+ (9.3+)":    "permitted_providers flag, 'not allowed' message",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS24-F02: CVE-2023-48795 Terrapin — PATCHED (backport to 7.4p1)
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_48795_TOS24 = {
    "finding_id": "TOS24-F02",
    "severity": "HIGH (patched)",
    "status": "PATCHED",
    "binary": "sshd",
    "openssh_package": "openssh-7.4p1-23.tl2.7",
    "binary_size_kb": 837,
    "kex_strict_strings_confirmed": [
        "kex-strict-s-v00@openssh.com",
        "kex-strict-c-v00@openssh.com",
    ],
    "note": (
        "Terrapin (CVE-2023-48795) was disclosed Dec 2023 and required a new SSH "
        "extension (kex-strict). Upstream fix required either OpenSSH 9.5+ or a "
        "dedicated backport. TOS 2.4 backported kex-strict into OpenSSH 7.4p1 — "
        "a 7-year-old codebase. Both client and server kex-strict extension strings "
        "confirmed present in the 2026-07-25 ISO build."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS24-F03: OpenSSL 1.0.2k EoL — 26 tl2 rebuild cycles
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_102K_TOS24 = {
    "finding_id": "TOS24-F03",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "title": "TOS 2.4 ships EoL OpenSSL 1.0.2k with extensive backport history",
    "binary": "libssl.so.1.0.2k",
    "package": "openssl-1.0.2k-26.tl2.2",
    "openssl_version_string": "SSLv3 part of OpenSSL 1.0.2k-fips  26 Jan 2017",
    "file_size_kb": 460,
    "build_date": "2024-12-31",
    "openssl_upstream_eol": "2020-01-01",
    "tencent_last_rebuild": "26.tl2.2 (counter shows 26+ rebuild cycles)",
    "tlcp_present": False,
    "sm_ciphers_present": False,
    "note": (
        "OpenSSL 1.0.2k official EoL was 2020-01-01. TencentOS maintains their own "
        "1.0.2k fork with -26.tl2 counter reflecting 26+ revision cycles. "
        "The build date of Dec 31 2024 shows the library receives active maintenance. "
        "Without access to the SRPM, the exact CVEs covered by these 26 revisions "
        "is unknown; the binary predates standard CVE-2022-0778 through CVE-2023-x "
        "but whether those are patched requires SRPM analysis."
    ),
    "exposure_assessment": (
        "TOS 2.4 is CentOS 7 based (EoL June 2024). Applications using libssl.so.1.0.2k "
        "on TOS 2.4 systems carry inherent EoL-library risk. The 26 rebuild cycles "
        "suggest Tencent actively backports CVEs, but the exact coverage is unknown "
        "without SRPM inspection."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS24-F04: TLCP absent in TOS 2.4
# ──────────────────────────────────────────────────────────────────────────────

TLCP_ABSENT_TOS24 = {
    "finding_id": "TOS24-F04",
    "severity": "INFO",
    "status": "TLCP ABSENT",
    "openssl_version": "1.0.2k",
    "note": (
        "TLCP (GM/T 0024-2014) is absent in TOS 2.4. The TLCP patch was implemented "
        "for OpenSSL 1.1.1 and 3.0.x lines, not 1.0.2. "
        "TOS 2.4 running on CentOS 7 infrastructure would require OpenSSL 1.1.1+ "
        "or 3.0.x with TLCP patches to support China GM/T 0024-2014 compliance."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS24-F05: openssl098e legacy compat library
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_098E_TOS24 = {
    "finding_id": "TOS24-F05",
    "severity": "HIGH",
    "title": "TOS 2.4 ISO includes openssl098e-0.9.8e compat library",
    "package": "openssl098e-0.9.8e-29.tl2.4",
    "openssl_version": "0.9.8e",
    "upstream_eol": "2015-12-31",
    "tencent_counter": "29.tl2.4",
    "note": (
        "OpenSSL 0.9.8e was released March 2007. Upstream EoL December 2015. "
        "The -29.tl2.4 counter shows 29+ rebuild cycles. "
        "This is an even older generation than 1.0.2k and would carry all "
        "post-2015 OpenSSL vulnerabilities. Exposure depends on whether "
        "any applications link against libssl.so.0.9.8."
    ),
    "exposure_chain": (
        "Applications on TOS 2.4 linking against openssl098e (libssl.so.8) are "
        "exposed to all unpatched post-2015 OpenSSL 0.9.8 CVEs. "
        "Identify affected applications with: ldd /usr/*/bin/* | grep 'ssl.so.8'"
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# CROSS-VERSION CVE POSTURE (complete table)
# ──────────────────────────────────────────────────────────────────────────────

FULL_CROSS_VERSION_TABLE = {
    "CVE_2023_38408_PKCS11": {
        "TOS_2.4 (openssh-7.4p1-23)": "PATCHED ('not whitelisted' — backport to 7.4p1)",
        "TOS_3.1 (openssh-8.0p1-13)": "OPEN (predates fix; SRPM confirmed, binary inaccessible)",
        "TOS_3.3 (openssh-8.0p1-25)": "PATCHED ('not whitelisted' — OpenSSH 8.x API)",
        "TOS_4.0 (openssh-9.3p2-8)":  "PATCHED ('not allowed')",
        "TOS_4.2 (openssh-9.3)":      "PATCHED ('not allowed')",
        "TOS_4.4 (openssh-9.3p2)":    "PATCHED ('not allowed')",
        "TOS_4.6 (openssh-9.3p2)":    "PATCHED ('not allowed' — identical to TOS 4.4)",
    },
    "CVE_2023_48795_Terrapin": {
        "TOS_2.4 (openssh-7.4p1-23)": "PATCHED (kex-strict backported to 7.4p1)",
        "TOS_3.1 (openssh-8.0p1-13)": "OPEN (predates fix; SRPM confirmed, binary inaccessible)",
        "TOS_3.3 (openssh-8.0p1-25)": "PATCHED (kex-strict confirmed)",
        "TOS_4.0 (openssh-9.3p2-8)":  "PATCHED (inferred from 9.3p2 + kex-strict in libssh)",
        "TOS_4.2 (openssh-9.3)":      "PATCHED (kex-strict at file_offset 0x9f244)",
        "TOS_4.4 (openssh-9.3p2)":    "PATCHED (kex-strict at 0xa1244)",
        "TOS_4.6 (openssh-9.3p2)":    "PATCHED (identical binary to TOS 4.4)",
    },
    "TLCP_GM_T_0024": {
        "TOS_2.4 (openssl-1.0.2k)":   "ABSENT (1.0.2k predates TLCP patch line)",
        "TOS_3.1 (openssl-1.1.1k)":   "ABSENT (predates 2024-04-15 Tencent TLCP patch)",
        "TOS_3.3 (openssl-1.1.1w)":   "PRESENT (limited — 3 method exports, no enable/disable API)",
        "TOS_4.0 (openssl-3.0.12-3)": "ABSENT (3.0.x pre-TLCP patch era)",
        "TOS_4.2 (openssl-3.0.12+)":  "PRESENT (full API — 10+ TLCP symbols)",
        "TOS_4.4 (openssl-3.0.12+)":  "PRESENT (full API — 18 TLCP symbols)",
        "TOS_4.6 (openssl-3.0.12+)":  "PRESENT (identical to TOS 4.4)",
    },
    "OpenSSL_version": {
        "TOS_2.4":  "1.0.2k-26.tl2.2 (EoL 2020, 26 Tencent rebuild cycles, FIPS)",
        "TOS_3.1":  "1.1.1k (terminal Jun 2022 — see tencent_tos31_core_security_lifecycle_re.py)",
        "TOS_3.3":  "1.1.1w+ (base unclear, TLCP patched)",
        "TOS_4.0":  "3.0.12-3.tl4 (no TLCP, 660KB)",
        "TOS_4.2":  "3.0.12+ tl4 (TLCP full API, 803KB)",
        "TOS_4.4":  "3.0.12+ tl4 (TLCP full API, 803KB, cert CRUD)",
        "TOS_4.6":  "3.0.12+ tl4 (identical to TOS 4.4)",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# TOS 2.4 BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

TOS24_BINARY_INVENTORY = {
    "source_iso": "TencentOS-Server-2.4-TK4-x86_64-minimal-20260725.1.iso",
    "build_date": "2026-07-25",
    "sshd": {
        "package": "openssh-server-7.4p1-23.tl2.7",
        "size_kb": 837,
        "version_string": "OpenSSH_7.4p1-RHEL7-7.4p1-23",
    },
    "ssh_agent": {
        "package": "openssh-clients-7.4p1-23.tl2.7",
        "size_kb": 374,
    },
    "libssl": {
        "package": "openssl-libs-1.0.2k-26.tl2.2",
        "filename": "libssl.so.1.0.2k",
        "size_kb": 460,
        "version_string": "OpenSSL 1.0.2k-fips  26 Jan 2017",
        "build_date": "2024-12-31",
    },
    "libcrypto": {
        "package": "openssl-libs-1.0.2k-26.tl2.2",
        "filename": "libcrypto.so.1.0.2k",
    },
    "openssl098e": {
        "package": "openssl098e-0.9.8e-29.tl2.4",
        "filename": "libssl.so.0.9.8",
        "upstream_eol": "2015-12-31",
    },
}
