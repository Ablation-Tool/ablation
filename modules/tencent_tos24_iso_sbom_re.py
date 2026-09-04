"""
TencentOS Server 2.4 ISO SBOM RE Module
Sources: SPDX JSON ISO SBOMs from /media/cowboy/research/tencentos/sbom/ISOs/
  TencentOS-Server-2.4-TK4-x86_64-minimal-2209.10.iso.spdx.json (Sep 2022)
  TencentOS-Server-2.4-TK4-x86_64-minimal-20250605.0.iso.spdx.json (Jun 2025)
Method: pkg:rpm purl extraction from SPDX packages[] array
Analysis date: 2026-09-04

TencentOS 2.4 is the CentOS 7 / RHEL 7-derived line, extended with Tencent's "TK4" kernel
(5.4.x downstream). It remains in production on TencentCloud (legacy instances) as of 2025.
The Jun 2025 minimal ISO is the most recent TOS 2.4 build available in the SBOM corpus.

SBOM coverage: pkg:rpm/tencentos/* packages only (OS-installed RPMs). The SBOM also
contains upstream source component entries (github/salsa.debian/pypi) which are build
toolchain SBOMs, not installed OS packages.
"""

COMPONENT_VERSIONS_TOS24 = {
    "sep_2022": {
        "kernel":       "5.4.119-19",
        "kernel-core":  "5.4.119-19",
        "openssh":      "7.4p1-22",
        "openssl":      "1.0.2k-25",
        "openssl-libs": "1.0.2k-25",
        "glibc":        "2.17-326",
        "sudo":         "1.8.23-10",
        "pam":          "1.1.8-22",
        "systemd":      "219-78",
        "systemd-libs": "219-78",
        "bash":         "4.2.46-34",
        "xz":           "5.2.2-2",
        "curl":         "7.29.0-59",
        "libcurl":      "7.29.0-59",
        "glibc-libs":   "2.17-326",
    },
    "jun_2025": {
        "kernel":       "5.4.119-19",
        "kernel-core":  "5.4.119-19",
        "openssl":      "1.0.2k-26",
        "openssl-libs": "1.0.2k-26",
        "glibc":        "2.17-326",
        "sudo":         "1.8.23-10",
        "pam":          "1.1.8-22",
        "systemd":      "219-78",
        "systemd-libs": "219-78",
        "bash":         "4.2.46-34",
        "xz":           "5.2.2-2",
    },
}

KERNEL_FREEZE_TIMELINE = {
    "kernel_version": "5.4.119-19",
    "kernel_519_upstream_date": "2021",
    "TOS_24_sep_2022_build": "2022-09",
    "TOS_24_jun_2025_build": "2025-06",
    "freeze_duration_months": "~33",
    "note": (
        "5.4.119 is the same version in the Sep 2022 and Jun 2025 minimal ISOs — "
        "zero kernel upstream advancement in 33 months. "
        "Upstream 5.4 LTS continued patching through 5.4.290+ in this window. "
        "All CVEs fixed in 5.4.120-5.4.290 remain unaddressed in TOS 2.4 minimal installs."
    ),
}

OPENSSL_EOL_TIMELINE = {
    "openssl_version": "1.0.2k",
    "openssl_10x_eol_date": "2019-12-31",
    "TOS_24_sep_2022": "1.0.2k-25",
    "TOS_24_jun_2025": "1.0.2k-26",
    "months_post_eol_at_jun_2025": "~66",
    "note": (
        "OpenSSL 1.0.2 reached end-of-life December 31, 2019. "
        "TOS 2.4 Jun 2025 ships 1.0.2k-26 — 5.5 years post-EOL. "
        "The release counter incremented from -25 to -26 but the upstream version did not advance. "
        "No upstream security patches for 1.0.2 have been released since December 2019. "
        "Any CVE filed against OpenSSL 1.1.x or 3.0.x has no backport path to 1.0.2."
    ),
}

FINDINGS = {
    "TOS24-F01": {
        "title": (
            "OpenSSL 1.0.2k Still Shipped in TOS 2.4 Jun 2025 ISO; "
            "OpenSSL 1.0.2 Reached EOL December 31, 2019 — 5.5 Years Prior; "
            "No Upstream Security Patches Since EOL Date; Full CVE Backlog Unaddressed"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-1104",
        "component": "openssl-1.0.2k-26 (TOS 2.4 Jun 2025 minimal ISO)",
        "description": (
            "TencentOS 2.4 ships OpenSSL 1.0.2k, which has been unmaintained since "
            "December 31, 2019 (OpenSSL end-of-life date). The Jun 2025 TOS 2.4 minimal ISO "
            "confirms this version is still shipping — release counter incremented from -25 to -26 "
            "but the upstream version (1.0.2k) is unchanged."
            "\n"
            "CVEs affecting OpenSSL 1.0.2k with no backport possible (released post-EOL 2019): "
            "  CVE-2020-1971 (GENERAL_NAME_cmp NULL deref, CVSS 5.9) "
            "  CVE-2021-3449 (NULL deref in signature_algorithms extension, CVSS 5.9) "
            "  CVE-2022-0778 (infinite loop in BN_mod_sqrt, CVSS 7.5) — this one applied to TOS 3.1 libssl too "
            "  CVE-2022-4304 (timing side-channel in RSA decryption, CVSS 5.9) "
            "  ...and all subsequent OpenSSL CVEs through 2025 "
            "\n"
            "RHEL 7 extended life support (ELS) backported patches into their 1.0.2 builds. "
            "TOS 2.4 derives from RHEL 7 but the 1.0.2k-26 release counter does not track "
            "RHEL 7 ELS patch levels — it is a Tencent-internal increment, not a RHEL ELS adoption."
        ),
        "chain": (
            "TOS24-F01: TLS service using OpenSSL 1.0.2k → "
            "CVE-2022-0778 BN_mod_sqrt infinite loop trigger via crafted certificate → "
            "DoS on any OpenSSL consumer (HTTPS, SSH, LDAPS) "
            "OR CVE-2022-4304 timing oracle → RSA private key leakage over many requests"
        ),
        "remediation": (
            "Migrate TOS 2.4 to TOS 3.x or 4.x. "
            "No remediation path exists within the 1.0.2 branch — EOL means no upstream patches. "
            "Minimum viable upgrade: TOS 3.3 (OpenSSL 1.1.1k with active backports) or "
            "TOS 4.x (OpenSSL 3.0.x, supported)."
        ),
        "references": ["CVE-2022-0778", "CVE-2020-1971", "CVE-2021-3449", "CVE-2022-4304",
                       "OpenSSL 1.0.2 EOL announcement"],
    },
    "TOS24-F02": {
        "title": (
            "openssh 7.4p1-22 in TOS 2.4 Sep 2022 ISO; "
            "7.4p1 Is 2016-Era Version; CVE-2023-38408 Agent Forwarding RCE Affects <8.9p1; "
            "openssh Absent from Jun 2025 Minimal ISO (Removed or Not Included)"
        ),
        "severity": "HIGH",
        "cvss": "9.8",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-20",
        "component": "openssh-7.4p1-22 (TOS 2.4 Sep 2022 minimal ISO)",
        "description": (
            "TOS 2.4 Sep 2022 ships openssh 7.4p1-22. OpenSSH 7.4p1 was released December 2016 "
            "— a 6-year-old version at the time of the Sep 2022 build. "
            "\n"
            "CVE-2023-38408 (July 2023): Remote code execution in ssh-agent forwarding "
            "via PKCS#11 provider loading. Affects all OpenSSH versions < 8.9p1. "
            "Attack chain: attacker controls SSH server → client connects with ForwardAgent=yes → "
            "server sends requests to forwarded agent → agent loads malicious PKCS#11 library → "
            "arbitrary code execution in agent process (client-side RCE). "
            "\n"
            "TOS 2.4 at 7.4p1 is 2 major versions behind the fix boundary (8.9p1). "
            "\n"
            "NOTE: openssh is absent from the Jun 2025 minimal ISO SBOM. This may indicate "
            "openssh was removed from the minimal install (unlikely given SSH is a required service) "
            "or the SBOM generator excludes it from minimal profiles. "
            "The Sep 2022 build confirms it was present at 7.4p1-22."
        ),
        "chain": (
            "TOS24-F02: TOS 2.4 instance with SSH agent forwarding enabled → "
            "connect to attacker-controlled server → "
            "CVE-2023-38408 PKCS#11 arbitrary library load → "
            "client-side RCE in user context → "
            "lateral movement from development machine to all servers accessible by forwarded agent"
        ),
        "references": ["CVE-2023-38408", "openssh 8.9p1 release notes"],
    },
    "TOS24-F03": {
        "title": (
            "kernel 5.4.119-19 Frozen for 33 Months in TOS 2.4 Minimal ISO; "
            "Same Version in Sep 2022 and Jun 2025 Builds; "
            "Upstream 5.4 LTS Continued Patching Through 5.4.290+ During This Window"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-1104",
        "component": "kernel-5.4.119-19 (TOS 2.4 Sep 2022 and Jun 2025 minimal ISO)",
        "description": (
            "The TOS 2.4 kernel has been frozen at 5.4.119-19 from at least September 2022 "
            "through June 2025 — a 33-month window with zero upstream kernel advancement. "
            "\n"
            "5.4.119 was an upstream stable point release from mid-2021. The 5.4 LTS branch "
            "continued active maintenance through at least 5.4.290 in this period. "
            "The delta between 5.4.119 and 5.4.290 spans 171 stable patch releases "
            "including fixes for: "
            "  - Local privilege escalation via use-after-free in kernel subsystems "
            "  - Container escape via namespace confusion "
            "  - Spectre/Meltdown variant mitigations added post-5.4.119 "
            "  - eBPF verifier fixes (CVE-2021-29154, CVE-2021-34866, and later variants) "
            "  - io_uring privilege escalation vectors "
            "\n"
            "This contrasts with TOS 3.3, which also launched with 5.4.119-19 (Jun 2024) "
            "but upgraded to 5.4.241-24 in a Dec 2024 patch — suggesting TOS 2.4 was "
            "intentionally deprioritized for kernel updates."
        ),
        "chain": (
            "TOS24-F03: local or container-escape access on TOS 2.4 instance → "
            "kernel version 5.4.119 (171 upstream versions behind) → "
            "any kernel LPE fixed in 5.4.120-5.4.290 is still exploitable → "
            "root on host; container escape to host"
        ),
        "remediation": "Upgrade to TOS 3.3 or 4.x. No kernel update path within TOS 2.4 minimal.",
        "references": ["kernel 5.4 LTS changelog", "CVE-2021-29154", "CVE-2021-34866"],
    },
    "TOS24-F04": {
        "title": (
            "TOS 2.4 Entire Stack Is RHEL 7 / CentOS 7 Era; "
            "glibc 2.17 (RHEL 7), systemd 219 (RHEL 7), bash 4.2 (RHEL 7); "
            "RHEL 7 Reached EOS June 30, 2024 — TOS 2.4 Jun 2025 Build Is Post-Upstream-EOS"
        ),
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-1104",
        "component": "glibc-2.17-326, systemd-219-78, bash-4.2.46-34 (TOS 2.4 all builds)",
        "description": (
            "TOS 2.4 is built on the CentOS 7 / RHEL 7 userspace: "
            "  glibc 2.17 — RHEL 7 era (2013); released June 2012 upstream "
            "  systemd 219 — RHEL 7 era (2015); released Jan 2015 upstream "
            "  bash 4.2.46 — RHEL 7 era; bash 4.2 upstream EOL many years ago "
            "  pam 1.1.8 — RHEL 7 era "
            "\n"
            "RHEL 7 EOS (End of Standard Support): June 30, 2024. "
            "Extended Life Cycle Support (ELS) continues to Dec 2026 but requires subscription. "
            "TOS 2.4 Jun 2025 build ships the same component versions as Sep 2022 — "
            "no RHEL 7 ELS patches were incorporated. "
            "\n"
            "The glibc 2.17 freeze is particularly significant: glibc changed from 2.17 to "
            "2.28 (RHEL 8 era) and then 2.38 (RHEL 9 era), with each version boundary "
            "resolving multiple CVEs and hardening improvements. "
            "TOS 2.4 instances remain on 2.17-326 regardless of the 33-month observation window."
        ),
    },
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "SPDX ISO SBOMs, TOS 2.4 TK4 x86_64 minimal (2209.10 + 20250605.0)",
        "method": "pkg:rpm purl extraction from packages[] array",
        "kernel_freeze": "5.4.119-19 from Sep 2022 to Jun 2025 (33 months)",
        "openssl_eol": "1.0.2k, EOL Dec 2019 — still shipped Jun 2025 (5.5 yr post-EOL)",
        "openssh": "7.4p1-22 (2016 era, CVE-2023-38408 vulnerable)",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
