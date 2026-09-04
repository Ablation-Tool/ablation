"""
TencentOS Server 4.6 AppStream libssh2 SRPM RE Module
Source: /media/cowboy/research/tencentos/4.6/AppStream-source/libssh2-1.11.0-6.tl4.src.rpm
Method: rpm2cpio | cpio -idmv; patch file enumeration; spec changelog parsing
Analysis date: 2026-09-04

libssh2 is a DIFFERENT library from libssh:
  libssh (OpenCloudOS BaseOS): server + client SSH implementation, used by git-over-SSH
  libssh2 (OpenCloudOS AppStream): C-only client library, used by curl, PHP, Python paramiko

TOS 4.6 AppStream ships libssh2-1.11.0 (August 2023 upstream release).
The Terrapin fix (CVE-2023-48795) was introduced in libssh2 1.11.1 (December 2023).
TOS 4.6 AppStream is still on 1.11.0 across all release counters; 1.11.1 was never adopted.

6 new 2026 CVEs were discovered in libssh2 during this analysis — all are patched
in AppStream via SRPM backport at -5 (Jun 2026) and -6 (Jul 2026).
The Terrapin CVE-2023-48795 was NOT backported and remains OPEN in all libssh2 counters.

PkgAgent Robot <pkgagent@opencloudos.tech> authored both security releases.
This is the same AI-mediated patch pipeline as the BaseOS openssh/libssh security releases.
"""

LIBSSH2_SRPM_TIMELINE = {
    "1.11.0-1.tl4": {
        "date": "2023-08-08",
        "author": "OpenCloudOS <opencloudos@opencloudos.org>",
        "notes": "Initial 1.11.0 build for TOS 4.x",
        "cve_patches": [],
        "terrapin_fix": False,
    },
    "1.11.0-2.tl4": {
        "date": "2023-09-08",
        "author": "OpenCloudOS <opencloudos@opencloudos.org>",
        "notes": "Rebuild for OpenCloudOS Stream 23.09",
        "cve_patches": [],
        "terrapin_fix": False,
    },
    "1.11.0-3.tl4": {
        "date": "2024-08-16",
        "author": "OpenCloudOS <opencloudos@opencloudos.org>",
        "notes": "Rebuild for loongarch architecture",
        "cve_patches": [],
        "terrapin_fix": False,
    },
    "1.11.0-4.tl4": {
        "date": "2024-09-26",
        "author": "OpenCloudOS <opencloudos@opencloudos.org>",
        "notes": "Rebuilt for BaseOS/AppStream clarification; test patches only",
        "cve_patches": [],
        "non_security_patches": [
            "ssh-rsa-test.patch",
            "strict-modes.patch",
        ],
        "note_strict_modes": (
            "strict-modes.patch adds '-o StrictModes no' to sshd invocation in the test suite. "
            "It is a test helper, NOT a kex-strict/Terrapin fix. The name is misleading."
        ),
        "terrapin_fix": False,
        "appstream_version_in_tos46_iso": True,
    },
    "1.11.0-5.tl4": {
        "date": "2026-06-29",
        "author": "PkgAgent Robot <pkgagent@opencloudos.tech>",
        "notes": "Security release; 2 CVE patches added",
        "cve_patches": [
            "CVE-2026-58050.patch",
            "CVE-2026-58051.patch",
        ],
        "terrapin_fix": False,
    },
    "1.11.0-6.tl4": {
        "date": "2026-07-27",
        "author": "PkgAgent Robot <pkgagent@opencloudos.tech>",
        "notes": "Security release; 4 CVE patches added",
        "cve_patches": [
            "CVE-2026-66034.patch",
            "CVE-2026-66032.patch",
            "CVE-2026-66033.patch",
            "CVE-2026-66035.patch",
        ],
        "terrapin_fix": False,
        "appstream_version_latest_confirmed": True,
    },
}

LIBSSH2_VERSION_TO_DEPLOYMENT = {
    "1.11.0-4": {
        "present_in": ["TOS 4.6 ISO (Apr 2026)"],
        "open_cves": [
            "CVE-2023-48795 (Terrapin)",
            "CVE-2026-58050", "CVE-2026-58051",
            "CVE-2026-66032", "CVE-2026-66033", "CVE-2026-66034", "CVE-2026-66035",
        ],
    },
    "1.11.0-5": {
        "present_in": ["update channel (Jun 2026)"],
        "fixed_vs_4": ["CVE-2026-58050", "CVE-2026-58051"],
        "open_cves": [
            "CVE-2023-48795 (Terrapin)",
            "CVE-2026-66032", "CVE-2026-66033", "CVE-2026-66034", "CVE-2026-66035",
        ],
    },
    "1.11.0-6": {
        "present_in": ["update channel (Jul 2026)"],
        "fixed_vs_5": [
            "CVE-2026-66032", "CVE-2026-66033", "CVE-2026-66034", "CVE-2026-66035",
        ],
        "open_cves": ["CVE-2023-48795 (Terrapin) — never backported in any 1.11.0 counter"],
    },
}

LIBSSH2_CVE_CATALOG_2026 = {
    "CVE-2026-58050": {
        "component": "libssh2_publickey_list_fetch()",
        "class": "heap buffer overflow",
        "severity": "HIGH",
        "fixed_at": "1.11.0-5",
        "description": (
            "Heap buffer overflow in libssh2_publickey_list_fetch(). "
            "A malicious SSH server response can trigger out-of-bounds writes "
            "in the public key list parsing routine."
        ),
        "attack_vector": "malicious SSH server response",
        "impact": "potential RCE in SSH client process",
    },
    "CVE-2026-58051": {
        "component": "libssh2_publickey_list_fetch()",
        "class": "uninitialized memory read",
        "severity": "MEDIUM",
        "fixed_at": "1.11.0-5",
        "description": (
            "Uninitialized memory in libssh2_publickey_list_fetch(). "
            "Stack or heap memory bytes can be returned to the caller "
            "and potentially leak sensitive data (key material, crypto state)."
        ),
        "attack_vector": "malicious SSH server response",
        "impact": "information disclosure (key material leak)",
    },
    "CVE-2026-66034": {
        "component": "libssh2_publickey_list_fetch()",
        "class": "out-of-bounds read",
        "severity": "MEDIUM",
        "fixed_at": "1.11.0-6",
        "description": (
            "OOB read in libssh2_publickey_list_fetch(). "
            "Malformed server-side public key list response causes the parser "
            "to read past allocated buffer bounds."
        ),
        "attack_vector": "malicious SSH server response",
        "impact": "crash (DoS) or information disclosure",
    },
    "CVE-2026-66032": {
        "component": "sftp_open()",
        "class": "double-free",
        "severity": "HIGH",
        "fixed_at": "1.11.0-6",
        "description": (
            "Double-free in sftp_open(). Error path in the SFTP open operation "
            "frees a structure twice under specific error conditions. "
            "Exploitable as a heap corruption primitive."
        ),
        "attack_vector": "malicious SFTP server response or client error path",
        "impact": "memory corruption, potential RCE if heap layout is controlled",
    },
    "CVE-2026-66033": {
        "component": "ssh2_cipher_crypt() with AES-GCM",
        "class": "integer underflow",
        "severity": "HIGH",
        "fixed_at": "1.11.0-6",
        "description": (
            "Integer underflow in ssh2_cipher_crypt() when AES-GCM mode is in use. "
            "A carefully crafted sequence can underflow the length field passed to "
            "the AES-GCM decryption routine, producing a negative length interpreted "
            "as a very large unsigned value. May bypass MAC validation or trigger OOB reads."
        ),
        "attack_vector": "malicious SSH server controlling the session cipher stream",
        "impact": "crypto bypass or memory corruption",
        "note": "AES-GCM is a commonly preferred cipher; this is a hot path",
    },
    "CVE-2026-66035": {
        "component": "ETM cipher negotiation",
        "class": "heap overflow",
        "severity": "HIGH",
        "fixed_at": "1.11.0-6",
        "description": (
            "Heap overflow in ETM (Encrypt-then-MAC) cipher negotiation. "
            "Shares the attack surface class with Terrapin (CVE-2023-48795). "
            "Oversized ETM negotiation field causes a heap buffer write overflow. "
            "Triggerable before authentication completes."
        ),
        "attack_vector": "pre-auth; malicious SSH server response during negotiation",
        "impact": "heap corruption, potential unauthenticated RCE",
        "note": "Pre-auth attack surface — no credential required to trigger",
    },
    "CVE-2023-48795": {
        "component": "SSH handshake (kex-strict extension)",
        "class": "MitM handshake truncation (Terrapin)",
        "severity": "MEDIUM",
        "fixed_at": "libssh2 1.11.1 (upstream) — NEVER BACKPORTED TO TOS 4.x AppStream",
        "description": (
            "Terrapin: SSH sequence number manipulation via MitM allows truncation "
            "of the SSH handshake, potentially downgrading extensions negotiated "
            "in the pre-authentication phase (e.g. disabling ext-info, disabling "
            "kex-strict in clients that support it). "
            "\n"
            "libssh2 status in TOS 4.6: "
            "  1.11.0 was released Aug 2023, BEFORE Terrapin disclosure (Dec 2023). "
            "  1.11.1 (Dec 2023) introduced kex-strict support and is the upstream fix. "
            "  TOS 4.6 AppStream remains at 1.11.0. No CVE-2023-48795.patch was added "
            "  in ANY counter from -1 through -6. "
            "\n"
            "Note: libssh (BaseOS) DID receive the backport at 0.10.5-6. "
            "libssh2 (AppStream) did NOT."
        ),
        "open_in_all_tos46_appstream_counters": True,
        "references": [
            "libssh2 1.11.1 release (Dec 2023) — upstream fix",
            "TOS46-C01 CORRECTION (tencent_tos46_components_re.py) — libssh (BaseOS) IS fixed",
            "TOS46-SRPM-F01 (tencent_tos46_srpm_re.py) — libssh counter-to-deployment map",
        ],
    },
}

PKGAGENT_PIPELINE = {
    "attribution": "PkgAgent Robot <pkgagent@opencloudos.tech>",
    "observed_in": [
        "libssh2-1.11.0-5.tl4 changelog (Jun 29 2026)",
        "libssh2-1.11.0-6.tl4 changelog (Jul 27 2026)",
    ],
    "also_attributed_in": [
        "libssh 0.10.5-7.tl4 (BaseOS, CVE-2026-0964)",
        "libssh 0.10.5-8.tl4 (BaseOS, CVE-2026-59843)",
        "openssh 9.3p2-16.tl4 (BaseOS, CVE-2025-26465, CVE-2026-35385, CVE-2026-35414)",
    ],
    "same_pipeline_as": "DeepSeek V4 (PkgAgent/deepseek-v4 in patch Subject headers, BaseOS)",
    "note": (
        "PkgAgent Robot is Tencent's AI-mediated patch adaptation pipeline for OpenCloudOS. "
        "The AppStream and BaseOS security releases in 2026 are authored by this agent, "
        "not by human packagers. The AI adapts upstream CVE patches to the TencentOS "
        "packaging environment. See TOS46-SRPM-F07 in tencent_tos46_srpm_re.py for risk analysis."
    ),
}

FINDINGS = {
    "TOS46-LIBSSH2-F01": {
        "title": (
            "libssh2 1.11.0 in TOS 4.6 AppStream Predates Terrapin Fix; "
            "CVE-2023-48795 Never Backported to Any 1.11.0 Counter (-1 through -6); "
            "curl/PHP/paramiko SSH Sessions on TOS 4.6 Are Terrapin-Vulnerable"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-354",
        "component": "libssh2-1.11.0.tl4 (all counters, TOS 4.6 AppStream)",
        "description": (
            "libssh2 1.11.0 (Aug 2023) predates the Terrapin CVE-2023-48795 disclosure (Dec 2023). "
            "The fix shipped in libssh2 1.11.1 (Dec 2023) which TOS 4.6 AppStream never adopted. "
            "\n"
            "SRPM audit of libssh2-1.11.0-1.tl4 through -6.tl4: "
            "  No CVE-2023-48795.patch in any counter. "
            "  The strict-modes.patch in -4 is a test helper, not a kex-strict fix. "
            "\n"
            "Consumer library impact: "
            "  curl uses libssh2 for SSH (scp://, sftp://) transport "
            "  PHP uses libssh2 via php-pecl-ssh2 "
            "  Python paramiko (used extensively in automation) uses its own SSH impl, "
            "  but scripts that call libssh2 directly are affected "
            "  libgit2 with SSH transport may use libssh2 depending on build flags "
            "\n"
            "Contrast: libssh (BaseOS) was patched at 0.10.5-6 (Apr 2026). "
            "libssh2 (AppStream) was never patched for Terrapin — the two libraries "
            "are developed independently and patched on different schedules. "
            "\n"
            "Any TOS 4.6 system using curl over SFTP or SCP to an attacker-controlled "
            "or compromised server is vulnerable to Terrapin handshake truncation."
        ),
        "chain": (
            "TOS46-LIBSSH2-F01: TOS 4.6 host uses curl sftp:// or scp:// → "
            "libssh2 1.11.0 (no kex-strict) negotiates SSH with MitM in path → "
            "CVE-2023-48795: Terrapin handshake truncation applied → "
            "pre-auth extensions (ext-info, newkeys reorder) stripped from negotiation → "
            "downgraded session used for subsequent data transfer or auth"
        ),
        "remediation": (
            "Apply libssh2 1.11.0-5.tl4 or -6.tl4 from the update channel. "
            "Note: these do NOT fix Terrapin. "
            "Full Terrapin fix requires upgrading to libssh2 1.11.1 or requesting Tencent "
            "backport CVE-2023-48795 to the 1.11.0 package (as was done for libssh in BaseOS)."
        ),
        "references": [
            "CVE-2023-48795",
            "libssh2 1.11.1 release notes (Dec 2023)",
            "TOS46-C01 CORRECTION (tencent_tos46_components_re.py) — libssh BaseOS IS patched",
            "TOS46-SRPM-F01 (tencent_tos46_srpm_re.py) — libssh (BaseOS) counter-to-deployment",
        ],
    },
    "TOS46-LIBSSH2-F02": {
        "title": (
            "TOS 4.6 ISO (Apr 2026) Ships libssh2 1.11.0-4; "
            "6 New 2026 CVEs Open at Install (Heap Overflow, Double-Free, Integer Underflow); "
            "All Fixed After Jun/Jul 2026 via Update Channel at -5 and -6"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-122",
        "component": "libssh2-1.11.0-4.tl4 (TOS 4.6 ISO level, Sep 2024)",
        "description": (
            "TOS 4.6 ISO (Apr 2026) installs libssh2 from AppStream at counter -4 (Sep 2024). "
            "At this level, 6 CVEs discovered in 2026 are unpatched: "
            "\n"
            "  CVE-2026-58050 (FIXED AT -5): heap buffer overflow in publickey_list_fetch() "
            "  CVE-2026-58051 (FIXED AT -5): uninitialized memory in publickey_list_fetch() "
            "  CVE-2026-66034 (FIXED AT -6): OOB read in publickey_list_fetch() "
            "  CVE-2026-66032 (FIXED AT -6): double-free in sftp_open() "
            "  CVE-2026-66033 (FIXED AT -6): integer underflow in AES-GCM cipher path "
            "  CVE-2026-66035 (FIXED AT -6): heap overflow in ETM cipher negotiation (pre-auth) "
            "\n"
            "Most severe in the set: "
            "  CVE-2026-66035 (heap overflow in ETM negotiation) — pre-auth attack; "
            "    a malicious SSH server can trigger this before any credentials are exchanged. "
            "    Class: same attack surface as Terrapin (negotiation-phase). "
            "  CVE-2026-66032 (double-free in sftp_open()) — heap corruption primitive; "
            "    controllable allocation layout makes this a feasible RCE path. "
            "  CVE-2026-66033 (integer underflow, AES-GCM) — affects the default "
            "    cipher negotiated by modern SSH connections on any TOS 4.6 client. "
            "\n"
            "Any TOS 4.6 fresh install (from ISO) that does NOT run dnf update after "
            "install is vulnerable to all 6 CVEs on any SSH operation using libssh2 "
            "(curl sftp/scp, any application linking libssh2)."
        ),
        "chain": (
            "TOS46-LIBSSH2-F02: Fresh TOS 4.6 install (no dnf update) → "
            "libssh2 1.11.0-4 in libssh2 consumer applications → "
            "[a] curl sftp:// to malicious server → CVE-2026-66035 heap overflow pre-auth → "
            "    code execution in curl process → "
            "[b] curl sftp:// → sftp_open() error path → CVE-2026-66032 double-free → "
            "    heap corruption → "
            "[c] any SSH connection with AES-GCM → CVE-2026-66033 underflow → "
            "    decryption bypass or memory corruption"
        ),
        "remediation": "dnf update libssh2 (applies -6 from update channel, fixes all 6 CVEs).",
        "references": [
            "CVE-2026-58050", "CVE-2026-58051",
            "CVE-2026-66034", "CVE-2026-66032", "CVE-2026-66033", "CVE-2026-66035",
            "TOS46-LIBSSH2-F01 — Terrapin ALSO open at this version",
        ],
    },
    "TOS46-LIBSSH2-F03": {
        "title": (
            "PkgAgent Robot Authors All TOS 4.6 AppStream libssh2 Security Releases; "
            "AI-Mediated Patch Adaptation Confirmed Across Both BaseOS and AppStream; "
            "Same Pipeline Risk as TOS46-SRPM-F07"
        ),
        "severity": "MEDIUM",
        "cvss": "0.0",
        "cwe": "CWE-1071",
        "component": "libssh2 AppStream packaging pipeline",
        "description": (
            "PkgAgent Robot <pkgagent@opencloudos.tech> is the listed author for "
            "libssh2-1.11.0-5.tl4 (Jun 29 2026) and -6.tl4 (Jul 27 2026). "
            "\n"
            "This is the same PkgAgent pipeline attributed to DeepSeek V4 in BaseOS "
            "openssh and libssh security releases. The AI agent adapts upstream CVE patches "
            "to the OpenCloudOS packaging environment for both BaseOS and AppStream components. "
            "\n"
            "Coverage gap: the PkgAgent pipeline patched 6 new 2026 CVEs in libssh2 "
            "but did NOT backport CVE-2023-48795 (Terrapin), despite that CVE predating "
            "the 2026 releases by 30 months. This is evidence of the pipeline's scope: "
            "it responds to new disclosures but does not systematically audit for "
            "older unpatched CVEs in frozen upstream versions. "
            "\n"
            "For details on the AI-mediation risk model, see TOS46-SRPM-F07 in "
            "tencent_tos46_srpm_re.py."
        ),
        "references": [
            "TOS46-SRPM-F07 (tencent_tos46_srpm_re.py) — DeepSeek V4 risk analysis",
            "libssh2-1.11.0-5.tl4 spec changelog (PkgAgent Robot, Jun 2026)",
            "libssh2-1.11.0-6.tl4 spec changelog (PkgAgent Robot, Jul 2026)",
        ],
    },
    "TOS46-LIBSSH2-F04": {
        "title": (
            "libssh (BaseOS) and libssh2 (AppStream) Have Divergent Terrapin Patch Status on TOS 4.6; "
            "libssh 0.10.5-6 Patched (CVE-2023-48795.patch Present); "
            "libssh2 1.11.0-6 NOT Patched (No CVE-2023-48795 Backport)"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-1104",
        "component": "libssh2 vs libssh Terrapin patch divergence (TOS 4.6)",
        "description": (
            "TOS 4.6 has an asymmetric Terrapin patch status: "
            "\n"
            "  libssh (BaseOS): 0.10.5-6.tl4 — CVE-2023-48795.patch PRESENT (Apr 2026) "
            "  libssh2 (AppStream): 1.11.0-6.tl4 — NO CVE-2023-48795.patch "
            "\n"
            "This divergence creates a split security posture: "
            "  Git-over-SSH using libssh (BaseOS) → Terrapin-protected "
            "  curl SFTP/SCP using libssh2 (AppStream) → Terrapin-vulnerable "
            "\n"
            "The operational split matters because: "
            "  - System automation scripts that use curl for sftp:// remain vulnerable "
            "  - CI/CD pipelines deploying artifacts via sftp remain vulnerable "
            "  - Any application using the libssh2 C library directly remains vulnerable "
            "\n"
            "Both libraries are present on a typical TOS 4.6 installation. "
            "A defender checking 'is Terrapin patched on this host' that only checks "
            "libssh (BaseOS) will incorrectly conclude the host is clean."
        ),
        "references": [
            "TOS46-C01 CORRECTION (tencent_tos46_components_re.py) — libssh BaseOS fix confirmed",
            "TOS46-LIBSSH2-F01 — libssh2 AppStream unfixed",
            "CVE-2023-48795",
        ],
    },
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "libssh2-1.11.0-6.tl4.src.rpm (TOS 4.6 AppStream-source)",
        "method": "rpm2cpio | cpio; patch file enumeration; spec changelog parsing",
        "library": "libssh2 (separate from libssh; used by curl, PHP SSH, automation)",
        "version": "1.11.0 (all counters -1 through -6)",
        "upstream_terrapin_fix": "libssh2 1.11.1 (Dec 2023) — NEVER adopted by TOS 4.6",
        "cve_2023_48795": "OPEN in all 1.11.0 counters — no backport",
        "new_2026_cves_patched_at_5": ["CVE-2026-58050", "CVE-2026-58051"],
        "new_2026_cves_patched_at_6": [
            "CVE-2026-66034", "CVE-2026-66032",
            "CVE-2026-66033", "CVE-2026-66035",
        ],
        "pkgagent_authored": True,
        "divergence": {
            "libssh_baseOS": "0.10.5-6 — Terrapin PATCHED",
            "libssh2_appstream": "1.11.0-6 — Terrapin OPEN",
        },
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
