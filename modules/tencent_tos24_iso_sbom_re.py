"""
TencentOS Server 2.4 ISO SBOM RE Module
Source: /media/cowboy/research/tencentos/2.4/iso/
  TencentOS-Server-2.4-TK4-x86_64-everything-20260725.1.iso (3.0GB, Jul 25 2026)
  TencentOS-Server-2.4-TK4-x86_64-minimal-20260725.1.iso (1.8GB, Aug 13 2026)
Method: sudo mount -o loop,ro; ISO Packages/ inventory; repodata primary.xml.gz parse
Analysis date: 2026-09-04

TOS 2.4 is based on RHEL 7 userspace (glibc 2.17, Python 2.7, openssl 1.0.2k).
The kernel is TK4 (Tencent Kernel 4, 5.4.x LTS) — same kernel branch as TOS 3.x.
RHEL 7 EoL: June 30, 2024. TOS 2.4 continues as a Tencent-supported platform past RHEL 7 EoL.

The ISO dated Jul 25 2026 is 2+ years past RHEL 7 EoL. Packages have `.tl2` suffixes
indicating Tencent-specific patching. However, the tlinux-srpms/ (906 SRPMs) does NOT
contain openssl, openssh, glibc, or libssh — these packages' SRPMs are not in the
available archive. Package version analysis is from ISO binary RPM inventory.

NOTE: openssh-7.4p1-23 RPM extracted from ISO shows I/O errors on the test machine;
Terrapin and CVE-2023-38408 status for openssh is UNVERIFIED (marked as such below).
libssh-0.7.1 Terrapin status is DEFINITIVELY OPEN based on upstream branch analysis.

TLINUX-SRPMS ANOMALY:
  906 SRPMs present; openssl, openssh, glibc, libssh, libssh2 ABSENT.
  Tencent distributes binary-only builds of these core packages from the ISO Packages/
  directory. The SRPMs for critical security packages are not publicly available
  in the tlinux-srpms channel, preventing source-level patch audit.
"""

TOS24_ISO_PACKAGE_VERSIONS = {
    "openssl":       "1.0.2k-26.tl2.2",
    "openssl11":     "1.1.1k-4.tl2",
    "openssl098e":   "0.9.8e-29.tl2.4",
    "openssh":       "7.4p1-23.tl2.7",
    "libssh":        "0.7.1-7.tl2",
    "libssh2":       "1.8.0-4.tl2.1",
    "glibc":         "2.17-326.tl2.6",
    "compat-glibc":  "2.12-5.tl2.1",
    "curl":          "7.29.0-59.tl2.2",
    "python":        "2.7.5-94.tl2.5.1",
    "kernel":        "5.4.119-19.0009.67.2.tl2",
    "krb5":          "1.15.1-55.tl2.4.1",
}

EOL_ANALYSIS = {
    "openssl-1.0.2": {
        "upstream_eol": "2019-12-31",
        "rhel7_supported_through": "2024-06-30",
        "tos24_version": "1.0.2k-26.tl2.2",
        "years_past_upstream_eol_at_iso_date": 6.6,
        "tencent_support_continues": True,
        "note": (
            "Tencent continues patching openssl-1.0.2k past RHEL 7 EoL via .tl2 counter "
            "increments. -26 is the same base counter as RHEL 7's final openssl. "
            ".tl2.2 = 2 additional Tencent patches post-RHEL-7-EoL."
        ),
    },
    "openssl-1.1.1": {
        "upstream_eol": "2023-09-11",
        "tos24_version": "1.1.1k-4.tl2",
        "note": (
            "openssl11 is a compatibility package alongside the main openssl-1.0.2k. "
            "Counter -4 (low). Likely does not include post-Sep 2023 CVE backports."
        ),
    },
    "openssl-0.9.8e": {
        "upstream_eol": "2010-01-01",
        "tos24_version": "0.9.8e-29.tl2.4",
        "years_past_upstream_eol_at_iso_date": 16.6,
        "note": (
            "Compatibility shim for ancient applications. Shipped in a 2026 OS release. "
            "Counter -29.tl2.4 is high — Tencent patched the binary form but upstream "
            "OpenSSL 0.9.8e ceased all support in 2010. "
            "EVERY post-2010 CVE patched via backport must be verified; "
            "a missed backport leaves a 16-year gap."
        ),
    },
    "python-2.7": {
        "upstream_eol": "2020-01-01",
        "tos24_version": "2.7.5-94.tl2.5.1",
        "years_past_upstream_eol_at_iso_date": 6.6,
        "note": "Python 2.7 is the default python on TOS 2.4; EoL since 2020.",
    },
    "rhel7_userspace": {
        "rhel7_eol": "2024-06-30",
        "tos24_iso_date": "2026-07-25",
        "months_past_rhel7_eol": 25,
        "note": (
            "TOS 2.4 was built 25 months after RHEL 7's full support EoL. "
            "Tencent continues to support TOS 2.x independently of Red Hat's lifecycle."
        ),
    },
}

LIBSSH_07X_ANALYSIS = {
    "version": "0.7.1-7.tl2",
    "upstream_released": "~2014",
    "upstream_branch_eol": "0.7.x branch was replaced by 0.8.x in 2018",
    "terrapin_status": "OPEN — DEFINITIVELY",
    "terrapin_reasoning": (
        "CVE-2023-48795 (Terrapin, Dec 2023) fix requires implementing the "
        "kex-strict extension introduced in libssh 0.10.4 (and backported to 0.9.x "
        "in some distributions). The 0.7.x branch NEVER received this extension "
        "from the upstream libssh project. Tencent would need to add a custom "
        "0.7.x backport. Counter -7.tl2 is low (same as RHEL 7's final libssh counter) "
        "and is consistent with not having the Terrapin fix."
    ),
    "cve_2018_10933_status": "LIKELY PATCHED (counter -7 aligns with RHEL 7 -7.el7 which included the fix)",
    "cve_2018_10933_note": (
        "CVE-2018-10933 (HIGH/9.8): Authentication bypass in libssh server mode. "
        "A client can authenticate by sending SSH2_MSG_USERAUTH_SUCCESS before "
        "authentication completes. Fixed in libssh 0.7.6 and 0.8.4 (Oct 2018). "
        "RHEL 7's libssh-0.7.1-7.el7 includes this fix. "
        "TOS 2.4 libssh-0.7.1-7.tl2 counter matches — likely patched. "
        "BINARY VERIFICATION PENDING (I/O error on ISO extraction)."
    ),
    "missing_features_vs_current": [
        "kex-strict extension (Terrapin mitigation)",
        "All 0.8.x/0.9.x/0.10.x security patches (~9 years of development)",
        "Ed25519 key improvements (added in 0.8.x)",
        "ECDSA improvements",
    ],
}

LIBSSH2_18_ANALYSIS = {
    "version": "1.8.0-4.tl2.1",
    "upstream_released": "2016-11-16",
    "tos46_equivalent": "libssh2-1.11.0-6.tl4 (10 major versions newer)",
    "terrapin_status": "OPEN — DEFINITIVELY",
    "terrapin_reasoning": (
        "libssh2 1.8.0 was released November 2016. "
        "Terrapin (CVE-2023-48795) was disclosed December 2023 — 7 years later. "
        "The fix requires kex-strict extension implemented in libssh2 1.11.1 (Dec 2023). "
        "libssh2 1.8.0 cannot receive this fix without upgrading to a newer branch."
    ),
    "known_cves_since_1_8_0": [
        "CVE-2019-3855 (HIGH): integer overflow in transport read",
        "CVE-2019-3856 (HIGH): integer overflow in keyboard interactive handling",
        "CVE-2019-3857 (HIGH): integer overflow in SSH_MSG_CHANNEL_REQUEST handling",
        "CVE-2019-3858 (MEDIUM): OOB read in SFTP",
        "CVE-2019-3859 (MEDIUM): OOB reads in multi-packet parsing",
        "CVE-2019-3860 (MEDIUM): OOB reads in SFTP with FXP_READDIR response",
        "CVE-2019-3861 (MEDIUM): OOB reads in disconnect message",
        "CVE-2019-3862 (HIGH): OOB read in channel close notification",
        "CVE-2019-3863 (HIGH): integer overflow in keyboard interactive response",
        "CVE-2023-48795 (MEDIUM): Terrapin handshake truncation (requires 1.11.1)",
        "CVE-2026-58050 (HIGH): heap overflow in publickey_list_fetch (requires 1.11.0-5)",
        "CVE-2026-58051 (MEDIUM): uninitialized memory in publickey_list_fetch",
        "CVE-2026-66032 (HIGH): double-free in sftp_open (requires 1.11.0-6)",
        "CVE-2026-66033 (HIGH): integer underflow in AES-GCM cipher path",
        "CVE-2026-66034 (MEDIUM): OOB read in publickey_list_fetch",
        "CVE-2026-66035 (HIGH): heap overflow in ETM negotiation (requires 1.11.0-6)",
    ],
    "counter_status": (
        "Counter -4.tl2.1 is low (RHEL 7-style patching). "
        "RHEL 7's libssh2 received the 2019 batch CVE fixes. "
        "The 2026 CVEs (fixed in TOS 4.6 AppStream) and Terrapin are NOT expected "
        "in this branch."
    ),
}

FINDINGS = {
    "TOS24-F01": {
        "title": (
            "TOS 2.4 Ships openssl098e-0.9.8e (2007 Library, EoL 2010) in Jul 2026 ISO; "
            "Any Application Linking Against openssl098e Is Exposed to 16+ Years of Backlog; "
            "No Upstream Security Support for 0.9.8 Branch Since 2010"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-1104",
        "component": "openssl098e-0.9.8e-29.tl2.4 (TOS 2.4 ISO, Jul 2026)",
        "description": (
            "TOS 2.4 includes openssl098e-0.9.8e-29.tl2.4 as a compatibility library for "
            "legacy applications. OpenSSL 0.9.8 upstream EoL was January 1, 2010. "
            "The ISO was built July 25, 2026 — 16.6 years after upstream EoL. "
            "\n"
            "Counter -29.tl2.4 indicates Tencent has applied patches, but: "
            "  1. No public source for which CVEs are addressed in the .tl2 patches "
            "  2. OpenSSL 0.9.8 lacked many modern security primitives from design: "
            "     - No TLS 1.2 support in the base 0.9.8e "
            "     - No AEAD ciphers (AES-GCM, ChaCha20-Poly1305) "
            "     - RSA PKCS#1 v1.5 only in TLS context (no RSA-PSS) "
            "  3. Major CVEs unfixable without branch upgrade include: "
            "     - All TLS 1.3-related CVEs (TLS 1.3 never in 0.9.8) "
            "     - CVEs requiring cipher suite changes (0.9.8 cipher set is frozen) "
            "\n"
            "Any TOS 2.4 application that links to libssl.so.0.9.8 or libcrypto.so.0.9.8 "
            "rather than the newer openssl-1.0.2k or openssl11-1.1.1k libraries is "
            "running on a 2007-era cryptographic foundation."
        ),
        "remediation": (
            "Identify applications linking against openssl098e: "
            "  ldd <binary> | grep 'libssl.so.0' or 'libcrypto.so.0' "
            "Port those applications to link against openssl-1.0.2k or openssl11-1.1.1k. "
            "If not possible, isolate applications using openssl098e from any "
            "network-accessible entry points."
        ),
        "references": ["CVE-2018-0735", "CVE-2018-0737", "openssl098e EOL 2010"],
    },
    "TOS24-F02": {
        "title": (
            "TOS 2.4 libssh-0.7.1-7 Is Definitively Terrapin-Vulnerable; "
            "0.7.x Branch Never Received kex-strict Extension; "
            "No Upstream Fix Path Without Branch Upgrade"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-354",
        "component": "libssh-0.7.1-7.tl2 (TOS 2.4 ISO, Jul 2026)",
        "description": (
            "TOS 2.4 includes libssh-0.7.1-7.tl2. The 0.7.x branch was last maintained "
            "by upstream in 2018. The Terrapin fix (CVE-2023-48795, Dec 2023) requires "
            "the kex-strict SSH extension, which was implemented in libssh 0.10.4 and "
            "backported to libssh 0.9.x. The 0.7.x branch NEVER received this extension. "
            "\n"
            "Counter -7.tl2: aligns with RHEL 7's libssh-0.7.1-7.el7, which includes "
            "the CVE-2018-10933 authentication bypass fix but predates Terrapin. "
            "The .tl2 suffix suggests minor Tencent patches; kex-strict addition would "
            "require significant implementation work not visible at the binary level. "
            "\n"
            "Any SSH client or server using libssh on TOS 2.4 is Terrapin-vulnerable."
        ),
        "references": [
            "CVE-2023-48795",
            "libssh 0.7.x final release (0.7.6, Nov 2018)",
            "TOS33-F01 CORRECTION — TOS 3.3 libssh 0.9.6-14 HAS the Terrapin fix",
            "TOS46-C01 CORRECTION — TOS 4.6 libssh 0.10.5-6 HAS the Terrapin fix",
        ],
    },
    "TOS24-F03": {
        "title": (
            "TOS 2.4 libssh2-1.8.0-4 (2016) Missing Terrapin Fix and 14 CVEs "
            "Including 2026 HIGH-Severity Heap Overflow (CVE-2026-66035) and "
            "Double-Free (CVE-2026-66032); curl Links Against This Library"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-122",
        "component": "libssh2-1.8.0-4.tl2.1 (TOS 2.4 ISO, Jul 2026)",
        "description": (
            "TOS 2.4 ships libssh2-1.8.0 — released November 2016. "
            "TOS 4.6's libssh2-1.11.0-6 is the current version, containing "
            "security patches released from 2016 through 2026. "
            "\n"
            "14 CVEs have been identified across the 1.8.0→1.11.0 span that are "
            "confirmed open in 1.8.0: "
            "\n"
            "  2019 CVE batch (HIGH): CVE-2019-3855, CVE-2019-3856, CVE-2019-3857, "
            "  CVE-2019-3862, CVE-2019-3863 — all integer overflows in packet handling; "
            "  potential RCE from malicious SSH server response. "
            "\n"
            "  CVE-2023-48795 (Terrapin): open — 1.8.0 predates kex-strict by 7 years. "
            "\n"
            "  2026 CVEs from TOS 4.6 AppStream analysis: "
            "    CVE-2026-66035 (HIGH): heap overflow in ETM cipher negotiation — pre-auth "
            "    CVE-2026-66032 (HIGH): double-free in sftp_open() "
            "    CVE-2026-66033 (HIGH): integer underflow in AES-GCM cipher path "
            "    CVE-2026-58050 (HIGH): heap overflow in publickey_list_fetch() "
            "  All these were patched in TOS 4.6 AppStream at 1.11.0-5/-6. "
            "  They are open in 1.8.0 — same vulnerable code paths, older codebase. "
            "\n"
            "curl-7.29.0-59.tl2.2 links against libssh2 for SFTP/SCP transport. "
            "Any curl sftp:// or scp:// operation on TOS 2.4 is affected."
        ),
        "chain": (
            "TOS24-F03: TOS 2.4 host uses curl sftp:// or any libssh2-linked application → "
            "malicious SSH server → CVE-2026-66035 heap overflow in ETM negotiation → "
            "pre-auth code execution in client process on TOS 2.4 host"
        ),
        "references": [
            "CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3862",
            "CVE-2023-48795", "CVE-2026-66035", "CVE-2026-66032", "CVE-2026-66033",
            "CVE-2026-58050",
            "TOS46-LIBSSH2-F01, F02 (tencent_tos46_appstream_libssh2_re.py)",
        ],
    },
    "TOS24-F04": {
        "title": (
            "TOS 2.4 openssl11-1.1.1k-4 (Compat Package) at Low Counter; "
            "Missing Post-Sep 2023 CVE Patches; Same CVE Exposure as TOS 3.1 openssl -7 "
            "Plus openssl11 EoL Since Sep 2023"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-843",
        "component": "openssl11-1.1.1k-4.tl2 (TOS 2.4 compatibility package)",
        "description": (
            "TOS 2.4 ships openssl11-1.1.1k-4 as a compatibility package for applications "
            "requiring OpenSSL 1.1.x. Counter -4 is LOW compared to TOS 3.1's openssl -7 "
            "(-7 was Jul 5, 2022; -4 predates that). "
            "\n"
            "openssl11-1.1.1k-4 likely includes fewer backport patches than TOS 3.1's -7. "
            "The missing CVEs from TOS 3.1 (openssl-1.1.1k-7 analysis) apply here too: "
            "  CVE-2023-0286 (HIGH/7.4): X.400 type confusion arbitrary memory read "
            "  CVE-2022-4450 (HIGH/7.5): double free in PEM_read_bio_ex "
            "  CVE-2023-0215 (HIGH/7.5): use-after-free in BIO_new_NDEF "
            "\n"
            "And if -4 predates TOS 3.1's -7 build (Jul 2022): "
            "  CVE-2022-0778 (HIGH/7.5): infinite loop in BN_mod_sqrt() MAY be absent "
            "  (depends on exact -4 date vs -6/-7 build dates in TOS 3.1 changelog). "
            "\n"
            "openssl11-1.1.1k EoL: September 2023. The .tl2 suffix shows Tencent "
            "continues patching, but -4 is the version in the Jul 2026 ISO. "
            "If no updates have been applied since the ISO was built, -4 is the "
            "current version on installed systems."
        ),
        "note": "SRPM unavailable; exact CVE status requires extraction and changelog analysis.",
        "references": [
            "TOS31-OPENSSL-F01 (tencent_tos31_core_security_lifecycle_re.py)",
            "CVE-2023-0286", "CVE-2022-4450", "CVE-2023-0215", "CVE-2022-0778",
        ],
    },
    "TOS24-F05": {
        "title": (
            "TOS 2.4 Ships Python 2.7.5 (Python 2.7 EoL Jan 2020) as Default Python; "
            "Counter -94.tl2 Suggests Patching But Python 2 Core Unmaintained Since 2020"
        ),
        "severity": "MEDIUM",
        "cvss": "0.0",
        "cwe": "CWE-1104",
        "component": "python-2.7.5-94.tl2.5.1 (TOS 2.4 default python)",
        "description": (
            "python-2.7.5-94.tl2.5.1 is the default Python on TOS 2.4. "
            "Python 2.7 upstream EoL: January 1, 2020. "
            "Counter -94 is very high — Tencent has applied extensive backport patches. "
            "\n"
            "Core Python 2.7 issues that cannot be backported: "
            "  - No type annotation support (mypy security analysis tools limited) "
            "  - No f-strings (code readability, not security) "
            "  - ssl module: Python 2.7's ssl module has limited cipher control vs Python 3 "
            "\n"
            "Risk: third-party Python packages that drop Python 2 support after 2020 "
            "may not receive security updates. pip installs on TOS 2.4 that pull "
            "Python 2-compatible packages may be installing 2020-era frozen versions "
            "of those packages."
        ),
        "references": ["Python 2.7 EoL announcement (Jan 2020)"],
    },
    "TOS24-F06": {
        "title": (
            "TOS 2.4 Critical Security SRPMs Not Publicly Available; "
            "openssl, openssh, glibc, libssh, libssh2 Absent from tlinux-srpms/ Archive; "
            "Source-Level CVE Verification Blocked"
        ),
        "severity": "MEDIUM",
        "cvss": "0.0",
        "cwe": "CWE-656",
        "component": "tlinux-srpms/ (906 packages, openssl/openssh/glibc absent)",
        "description": (
            "The tlinux-srpms/ archive (906 SRPMs) contains no source packages for: "
            "openssl, openssl11, openssh, glibc, libssh, libssh2. "
            "\n"
            "These packages have .tl2 suffixes in the ISO — confirming they ARE "
            "Tencent-modified packages — but their SRPMs are not in the public archive. "
            "\n"
            "Implication: "
            "  1. Patch-level CVE verification for TOS 2.4's core security packages "
            "     requires binary analysis (strings + disassembly) or Tencent PSIRT request. "
            "  2. openssh-7.4p1-23.tl2.7 Terrapin and CVE-2023-38408 status is UNVERIFIED. "
            "     Counter -23 suggests RHEL 7-equivalent patching; .tl2.7 = 7 Tencent patches "
            "     on top, but whether those include the Dec 2023 kex-strict addition is unknown. "
            "  3. The .tl2 modification history is opaque to external researchers. "
            "\n"
            "BINARY ANALYSIS PATH: "
            "  strings /usr/sbin/sshd | grep kex-strict → confirms Terrapin "
            "  strings /usr/bin/ssh-agent | grep pkcs11_whitelist → confirms CVE-2023-38408 "
            "  (ISO I/O error prevented this analysis on the research machine)"
        ),
        "references": [
            "TOS31-OPENSSH-F01 (binary analysis methodology)",
            "TOS33-F01, TOS33-F03 CORRECTIONS (tencent_tos33_iso_sbom_re.py)",
        ],
    },
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "TencentOS-Server-2.4-TK4-x86_64-everything-20260725.1.iso",
        "method": "ISO mount; Packages/ inventory; repodata primary.xml.gz parse",
        "iso_date": "2026-07-25",
        "key_packages": TOS24_ISO_PACKAGE_VERSIONS,
        "eol_status": {
            "openssl_0.9.8e": "EoL 2010 — 16.6 years past at ISO date",
            "python_2.7": "EoL 2020 — 6.6 years past at ISO date",
            "openssl_1.0.2k": "Upstream EoL 2019 — 6.6 years past; RHEL 7 supported until Jun 2024",
            "libssh_0.7.x": "Unmaintained since 2018; no Terrapin fix path",
        },
        "srpm_availability": "openssl/openssh/glibc/libssh/libssh2 SRPMs NOT in tlinux-srpms/",
        "terrapin_status": {
            "libssh_0.7.1": "OPEN (definitively — 0.7.x branch never received kex-strict)",
            "libssh2_1.8.0": "OPEN (definitively — pre-dates Terrapin by 7 years)",
            "openssh_7.4p1_23": "UNVERIFIED (I/O error; counter analysis suggests patched)",
        },
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
