"""
TencentOS Server 3.3 ISO SBOM RE Module
Sources: SPDX JSON ISO SBOMs from /media/cowboy/research/tencentos/sbom/ISOs/
  TencentOS-Server-3.3-20240624.0-TK4-x86_64-minimal.iso.spdx.json  (Jun 2024)
  TencentOS-Server-3.3-20240829.1-TK4-x86_64-minimal.iso.spdx.json  (Aug 2024)
  TencentOS-Server-3.3-20241220.2-TK4-x86_64-minimal.iso.spdx.json  (Dec 2024)
  TencentOS-Server-3.3-20250320.0-5.4.241-x86_64-minimal.iso.spdx.json  (Mar 2025)
  TencentOS-Server-3.3-20250512.1-5.4.241-x86_64-minimal.iso.spdx.json  (May 2025)
  TencentOS-Server-3.3-20250808.2-5.4.241-x86_64-minimal.iso.spdx.json  (Aug 2025)
Method: pkg:rpm purl extraction from SPDX packages[] array
Analysis date: 2026-09-04

TencentOS 3.3 is the RHEL 8-derived line using Tencent's TK4 kernel (5.4.x downstream).
It is the most recent TOS 3.x release; 3.3 Aug 2025 is the latest available SBOM snapshot.

Key structural observation: TOS 3.3 launched (Jun 2024) with kernel 5.4.119-19 —
the EXACT same kernel version as TOS 2.4 (Sep 2022). This indicates TOS 3.3 did not
start from a fresh RHEL 8-equivalent kernel baseline; it inherited the TOS 2.4 kernel
build pipeline. The Dec 2024 builds upgraded to 5.4.241-24.

RHEL 8 base packages (glibc 2.28, openssh 8.0p1, openssl 1.1.1) are frozen across
ALL six TOS 3.3 builds spanning Jun 2024 to Aug 2025.
"""

COMPONENT_VERSIONS_BY_BUILD = {
    "20240624_TK4": {
        "kernel":       "5.4.119-19",
        "openssh":      "8.0p1-24",
        "libssh":       "0.9.6-14",
        "openssl-libs": "1.1.1k-12",
        "glibc":        "2.28-251",
        "sudo":         "1.9.5p2-1",
        "pam":          "1.3.1-33",
        "systemd":      "239-82",
        "bash":         "4.4.20-5",
        "xz":           "5.2.4-4",
    },
    "20240829_TK4": {
        "kernel":       "5.4.119-19",
        "openssh":      "8.0p1-25",
        "libssh":       "0.9.6-14",
        "openssl-libs": "1.1.1k-12",
        "glibc":        "2.28-251",
        "sudo":         "1.9.5p2-1",
        "pam":          "1.3.1-34",
        "systemd":      "239-82",
        "bash":         "4.4.20-5",
        "xz":           "5.2.4-4",
    },
    "20241220_TK4": {
        "kernel":       "5.4.241-24",
        "openssh":      "8.0p1-25",
        "libssh":       "0.9.6-14",
        "openssl-libs": "1.1.1k-14",
        "glibc":        "2.28-251",
        "sudo":         "1.9.5p2-1",
        "pam":          "1.3.1-36",
        "systemd":      "239-82",
        "bash":         "4.4.20-5",
        "xz":           "5.2.4-4",
    },
    "20250320_5.4.241": {
        "kernel":       "5.4.241-24",
        "openssh":      "8.0p1-25",
        "libssh":       "0.9.6-14",
        "openssl-libs": "1.1.1k-14",
        "glibc":        "2.28-251",
        "sudo":         "1.9.5p2-1",
        "pam":          "1.3.1-36",
        "systemd":      "239-82",
        "bash":         "4.4.20-5",
        "xz":           "5.2.4-4",
    },
    "20250512_5.4.241": {
        "kernel":       "5.4.241-24",
        "openssh":      "8.0p1-25",
        "libssh":       "0.9.6-14",
        "openssl-libs": "1.1.1k-14",
        "glibc":        "2.28-251",
        "sudo":         "1.9.5p2-1",
        "pam":          "1.3.1-36",
        "systemd":      "239-82",
        "bash":         "4.4.20-5",
        "xz":           "5.2.4-4",
    },
    "20250808_5.4.241": {
        "kernel":       "5.4.241-24",
        "openssh":      "8.0p1-25",
        "libssh":       "0.9.6-14",
        "openssl-libs": "1.1.1k-14",
        "glibc":        "2.28-251",
        "sudo":         "1.9.5p2-1",
        "pam":          "1.3.1-37",
        "systemd":      "239-82",
        "bash":         "4.4.20-5",
        "xz":           "5.2.4-4",
    },
}

KERNEL_LINEAGE = {
    "TOS_2.4_sep_2022":           "5.4.119-19",
    "TOS_3.3_launch_jun_2024":    "5.4.119-19",
    "TOS_3.3_aug_2024":           "5.4.119-19",
    "TOS_3.3_dec_2024_upgraded":  "5.4.241-24",
    "TOS_3.3_aug_2025":           "5.4.241-24",
    "note": (
        "TOS 3.3 launched (Jun 2024) with the same 5.4.119-19 kernel as TOS 2.4 (Sep 2022). "
        "This is not a RHEL 8 kernel (RHEL 8 uses 4.18.x). "
        "TOS 3.3 uses Tencent's own 5.4.x downstream (TK4), inherited from TOS 2.4. "
        "The Dec 2024 upgrade to 5.4.241 was a 122-version catch-up in one batch. "
        "After Dec 2024, 5.4.241-24 is frozen through Aug 2025."
    ),
}

FINDINGS = {
    "TOS33-F01": {
        "title": (
            "CORRECTED: libssh 0.9.6-14 CVE-2023-48795 Terrapin Fix IS Backported by Tencent; "
            "Binary Strings Confirm kex-strict Extension Present in TOS 3.3 Aug 2025 qcow2; "
            "SBOM-Only Inference (0.9.6 < 0.9.8) Was Wrong — Release Counter -14 Includes Backport"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "status": "CORRECTED — prior MEDIUM finding was wrong",
        "component": "libssh-0.9.6-14 (TOS 3.3 qcow2, Aug 2025)",
        "description": (
            "ORIGINAL FINDING (now corrected): TOS33-F01 previously asserted libssh 0.9.6-14 "
            "was Terrapin-vulnerable because 0.9.6 < 0.9.8 (upstream fix version). "
            "\n"
            "CORRECTION via binary analysis of TOS 3.3 Aug 2025 qcow2 "
            "(mounted at /dev/nbd1p2, libssh.so.4.8.7): "
            "  strings libssh.so.4.8.7 | grep kex-strict: "
            "    kex-strict-c-v00@openssh.com  <- CLIENT-SIDE strict-kex marker "
            "    kex-strict-s-v00@openssh.com  <- SERVER-SIDE strict-kex marker "
            "    Client supports strict kex, enabling. "
            "    Server supports strict kex, enabling. "
            "\n"
            "These are the exact strings introduced by the CVE-2023-48795 Terrapin fix. "
            "Their presence confirms that Tencent backported the fix into 0.9.6-14 — "
            "the release counter -14 accumulates CVE backports applied to the 0.9.6 base "
            "rather than tracking upstream release versions. "
            "\n"
            "This is consistent with Tencent's pattern on both series: "
            "  0.9.6-14 (TOS 3.3): Terrapin fix backported into 0.9.6 package "
            "  0.10.5-6 (TOS 4.4/4.6): Terrapin fix backported into 0.10.5 package "
            "  0.10.5-3 (TOS 4.0/4.2): Terrapin fix NOT present (see TOS40-F01 / TOS42-F01) "
            "\n"
            "The earlier analysis treated -14 as just a packaging counter. It is a security "
            "patch counter: each increment represents CVE backports applied to the frozen "
            "upstream version. Binary string verification is the correct method; SBOM "
            "version comparison alone cannot distinguish patched from unpatched at this counter level."
        ),
        "verification_method": (
            "TOS 3.3 Aug 2025 qcow2 mounted via qemu-nbd /dev/nbd1; "
            "strings /mnt/tos33/usr/lib64/libssh.so.4.8.7 | grep -E 'kex-strict'; "
            "Result: 4 matching strings including both c-v00 and s-v00 extension markers."
        ),
        "references": [
            "CVE-2023-48795",
            "TOS46-SRPM-F01 (tencent_tos46_srpm_re.py) — 0.10.5 SRPM patch file confirmation",
            "TOS40-F01 (tencent_tos40_container_re.py) — -3 remains open",
            "TOS42-F01 (tencent_tos42_iso_sbom_re.py) — -3 remains open across 7 builds",
        ],
    },
    "TOS33-F02": {
        "title": (
            "OpenSSL 1.1.1k EOL September 2023; TOS 3.3 Aug 2025 Still Ships 1.1.1k-14; "
            "24 Months Post-EOL with No Upstream Patch Path; "
            "Same Finding as TOS 3.1 (tencent_tos31_srpm_re.py TOS31-SRPM-F01) Extended to 3.3"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-1104",
        "component": "openssl-libs-1.1.1k-14 (TOS 3.3 Aug 2025, Dec 2024); 1.1.1k-12 (Jun-Aug 2024)",
        "description": (
            "OpenSSL 1.1.1 reached end-of-life September 11, 2023. "
            "No upstream security patches are released for 1.1.1 after this date. "
            "\n"
            "TOS 3.3 progression: "
            "  Jun 2024: 1.1.1k-12 — 9 months post-EOL "
            "  Aug 2024: 1.1.1k-12 — 11 months post-EOL "
            "  Dec 2024: 1.1.1k-14 — 15 months post-EOL "
            "  Mar 2025: 1.1.1k-14 — 18 months post-EOL "
            "  May 2025: 1.1.1k-14 — 20 months post-EOL "
            "  Aug 2025: 1.1.1k-14 — 24 months post-EOL "
            "\n"
            "The release counter advanced from -12 to -14 across the 3.3 series. "
            "This represents Tencent-internal backports or packaging changes, NOT upstream "
            "OpenSSL patches (none exist post-EOL for 1.1.1). "
            "\n"
            "CVEs filed against OpenSSL 1.3.x and 3.0.x post-September 2023 have no "
            "backport path to 1.1.1k. The cumulative exposure grows with each month post-EOL. "
            "\n"
            "This finding is the 3.3-confirmed extension of TOS31-SRPM-F01: TOS 3.1 was "
            "already on 1.1.1k-7; the 3.3 series did not upgrade the branch, it advanced "
            "the release counter only."
        ),
        "chain": (
            "TOS33-F02: Any OpenSSL-consuming service on TOS 3.3 (HTTPS, LDAPS, git TLS) → "
            "post-EOL CVE with no TOS backport → exploitation depending on specific CVE; "
            "example: BN_mod_sqrt infinite loop (CVE-2022-0778) → DoS on certificate parsing"
        ),
        "remediation": "Upgrade to TOS 4.x (OpenSSL 3.0.x, supported). No patch path in 1.1.1.",
        "references": ["OpenSSL 1.1.1 EOL announcement", "TOS31-SRPM-F01 (tencent_tos31_srpm_re.py)"],
    },
    "TOS33-F03": {
        "title": (
            "CORRECTED: openssh 8.0p1-25 CVE-2023-38408 PKCS#11 Whitelist IS Backported; "
            "ssh-agent Binary Confirms -P pkcs11_whitelist Flag and Refusal Logic Present; "
            "Upstream Fix Mechanism from 8.9p1 Backported Into TOS 3.3 8.0p1-25"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "status": "CORRECTED — prior HIGH/9.8 finding was wrong",
        "component": "openssh-8.0p1-25 (TOS 3.3 Aug 2025 qcow2)",
        "description": (
            "ORIGINAL FINDING (now corrected): TOS33-F03 previously asserted TOS 3.3 openssh "
            "8.0p1-25 was vulnerable to CVE-2023-38408 (agent forwarding PKCS#11 RCE) because "
            "8.0p1 < 8.9p1 (upstream fix version). "
            "\n"
            "CORRECTION via binary analysis of TOS 3.3 Aug 2025 qcow2 "
            "(mounted at /dev/nbd1p2, ssh-agent binary): "
            "  strings /usr/bin/ssh-agent | grep -E 'pkcs11|whitelist|refusing': "
            "    [-P pkcs11_whitelist]          <- CLI flag present "
            "    failing PKCS#11 provider ... realpath: %s "
            "    refusing PKCS#11 provider %.100s: not whitelisted  <- enforcement present "
            "    Allow use of key %s? "
            "\n"
            "The -P pkcs11_whitelist flag is the specific mechanism OpenSSH 8.9p1 introduced "
            "to fix CVE-2023-38408: restrict PKCS#11 library loading to an allowlist. "
            "The refusal string 'not whitelisted' confirms the enforcement path is active "
            "in the TOS 3.3 build. Tencent backported this fix into 8.0p1-25. "
            "\n"
            "Additionally, Terrapin fix strings confirmed in TOS 3.3 sshd: "
            "  kex-strict-s-v00@openssh.com present in /usr/sbin/sshd "
            "\n"
            "Pattern: like libssh, Tencent backports CVE fixes into frozen upstream versions "
            "rather than upgrading to the upstream fix release. The -25 counter accumulates "
            "security patches applied to the 8.0p1 base. Binary analysis is required to "
            "determine actual patch status; version-number comparison alone is insufficient."
        ),
        "verification_method": (
            "TOS 3.3 Aug 2025 qcow2 mounted via qemu-nbd /dev/nbd1; "
            "strings /mnt/tos33/usr/bin/ssh-agent | grep -iE 'pkcs11|whitelist|refusing'; "
            "strings /mnt/tos33/usr/sbin/sshd | grep kex-strict; "
            "Both return positive results confirming backported fixes."
        ),
        "remaining_concern": (
            "OpenSSH 8.0p1 base is still a 2019-era codebase. While CVE-2023-38408 appears "
            "patched, the full set of CVEs between 8.0p1 and 8.9p1 has not been verified "
            "by binary inspection. There may be additional backports or gaps. "
            "Comprehensive assessment requires enumerating all openssh CVEs in the 8.0-8.9 "
            "range and checking each via binary string or behavioral probe."
        ),
        "references": [
            "CVE-2023-38408",
            "openssh 8.9p1 release notes (PKCS#11 allowlist introduced)",
            "TOS33-F01 CORRECTION (same backport pattern in libssh)",
        ],
    },
    "TOS33-F04": {
        "title": (
            "TOS 3.3 Launched (Jun 2024) with kernel 5.4.119-19 — Same as TOS 2.4 (Sep 2022); "
            "Two-Year-Old Kernel at Launch; Upgraded to 5.4.241-24 in Dec 2024 Batch; "
            "5.4.241-24 Frozen from Dec 2024 Through Aug 2025"
        ),
        "severity": "MEDIUM",
        "cvss": "6.7",
        "cwe": "CWE-1104",
        "component": "kernel-5.4.119-19 (Jun-Aug 2024); kernel-5.4.241-24 (Dec 2024 - Aug 2025)",
        "description": (
            "TOS 3.3 launched in June 2024 with kernel 5.4.119-19. "
            "This is the exact same kernel version present in TOS 2.4 Sep 2022 builds — "
            "meaning TOS 3.3 did not bring a fresher kernel to the 3.x series at launch; "
            "it inherited the same frozen TK4 5.4.119 from the TOS 2.4 pipeline. "
            "\n"
            "5.4.119 was a stable upstream release from 2021. Between 5.4.119 and the "
            "Dec 2024 upgrade to 5.4.241, there are 122 upstream stable releases with "
            "accumulated CVE patches. "
            "\n"
            "Timeline: "
            "  Jun 2024: 5.4.119-19 — launched 2.5 years behind upstream "
            "  Aug 2024: 5.4.119-19 — unchanged "
            "  Dec 2024: 5.4.241-24 — 122-version catch-up in one batch "
            "  Mar-Aug 2025: 5.4.241-24 — frozen again at the new level "
            "\n"
            "For the Jun-Aug 2024 window (TOS 3.3 first two stable builds), any kernel LPE "
            "fixed in 5.4.120-5.4.241 was open — 122 kernel stable releases worth of patches."
        ),
        "chain": (
            "TOS33-F04 (Jun-Aug 2024 window): local access on fresh TOS 3.3 install → "
            "kernel 5.4.119 (122 versions behind) → "
            "kernel LPE via any vuln fixed in 5.4.120-5.4.241 → "
            "root; container escape"
        ),
        "references": ["kernel 5.4 LTS stable changelog",
                       "tencent_tos24_iso_sbom_re.py TOS24-F03 (same base kernel)"],
    },
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "SPDX ISO SBOMs, TOS 3.3 TK4 x86_64 minimal (6 builds, Jun 2024 - Aug 2025)",
        "method": "pkg:rpm purl extraction from packages[] array",
        "libssh_status": "0.9.6-14 — Terrapin fix CONFIRMED BACKPORTED via binary string analysis (kex-strict strings present)",
        "openssl_eol": "1.1.1k, EOL Sep 2023 — still shipped Aug 2025 (24 months post-EOL)",
        "openssh_status": "8.0p1-25 — CVE-2023-38408 PKCS#11 whitelist CONFIRMED BACKPORTED via binary string analysis",
        "kernel_progression": "5.4.119-19 (launch) -> 5.4.241-24 (Dec 2024 upgrade)",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
