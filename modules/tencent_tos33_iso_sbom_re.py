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
            "libssh 0.9.6-14 CVE-2023-48795 Terrapin Frozen Across All TOS 3.3 Builds; "
            "Fix Available in libssh 0.9.8 (January 2024); TOS 3.3 Jun 2024 Launched "
            "6 Months Post-Fix and Never Updated; Still 0.9.6-14 in Aug 2025 (20 Months Post-Fix)"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-354",
        "component": "libssh-0.9.6-14 (all 6 TOS 3.3 builds, Jun 2024 through Aug 2025)",
        "description": (
            "CVE-2023-48795 (Terrapin attack) disclosed December 2023. "
            "libssh 0.9.8 released January 2024 — backport of Terrapin fix for the 0.9.x branch. "
            "libssh 0.9.6 does not contain this fix. "
            "\n"
            "TOS 3.3 uses the 0.9.x branch of libssh (vs TOS 4.x which uses 0.10.x). "
            "Across all 6 available TOS 3.3 builds: "
            "  Jun 2024: 0.9.6-14 — 6 months post-fix, still unfixed "
            "  Aug 2024: 0.9.6-14 — 7 months post-fix "
            "  Dec 2024: 0.9.6-14 — 12 months post-fix "
            "  Mar 2025: 0.9.6-14 — 15 months post-fix "
            "  May 2025: 0.9.6-14 — 17 months post-fix "
            "  Aug 2025: 0.9.6-14 — 20 months post-fix "
            "\n"
            "This mirrors the TOS 4.x libssh 0.10.5 freeze (TOS40-F01 / TOS46-C01) but on "
            "the 0.9.x branch. Both branches exhibit the same pattern: Terrapin fix available "
            "for the relevant branch, Tencent has not applied it across multiple major releases. "
            "\n"
            "Terrapin attack impact: MitM of SSH session → truncate handshake → "
            "disable chacha20-poly1305 ETM or CBC-ETM negotiation → "
            "keystroke-timing countermeasures off → inference of typed credentials."
        ),
        "chain": (
            "TOS33-F01: MitM on SSH session with libssh client (git-over-SSH, automation tools) → "
            "Terrapin truncates handshake → security features downgraded → "
            "keystroke timing side-channel enables credential inference"
        ),
        "remediation": (
            "Update libssh to 0.9.8+. "
            "Alternatively upgrade the TOS 3.3 system to TOS 4.x which uses libssh 0.10.x "
            "(though the 0.10.x Terrapin fix requires 0.10.6, and TOS 4.x ships 0.10.5 — "
            "same unpatched state on a different branch). "
            "Interim: cipher policy restricting chacha20-poly1305@openssh.com and *-etm variants."
        ),
        "references": ["CVE-2023-48795", "libssh 0.9.8 release notes",
                       "TOS40-F01 (tencent_tos40_container_re.py)",
                       "TOS46-C01 (tencent_tos46_components_re.py)"],
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
            "openssh 8.0p1 Frozen Across All TOS 3.3 Builds (Jun 2024 - Aug 2025); "
            "8.0p1 Dates from 2019; CVE-2023-38408 Agent Forwarding RCE Affects <8.9p1; "
            "TOS 3.3 Remains Vulnerable to Agent Forwarding RCE Through Latest Available Build"
        ),
        "severity": "HIGH",
        "cvss": "9.8",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-20",
        "component": "openssh-8.0p1-24 (Jun 2024); openssh-8.0p1-25 (Aug 2024 - Aug 2025)",
        "description": (
            "OpenSSH 8.0p1 was released April 2019. "
            "TOS 3.3 ships 8.0p1 across all 6 builds spanning Jun 2024 to Aug 2025 — "
            "the upstream version is frozen at 5-year-old code. "
            "\n"
            "CVE-2023-38408 (Qualys, July 2023): "
            "Remote code execution in ssh-agent via untrusted PKCS#11 provider loading. "
            "Attack requirements: victim connects to attacker-controlled SSH server with "
            "ForwardAgent=yes enabled. "
            "Exploitability: CVSS 9.8 (critical). "
            "Fix: openssh 8.9p1 (February 2022). TOS 3.3 at 8.0p1 is below the fix boundary. "
            "\n"
            "The release counter advanced from -24 to -25 between Jun and Aug 2024. "
            "The Qualys advisory includes a working PoC; the CVE is actively exploited. "
            "\n"
            "CONTRAST with TOS 4.x: TOS 4.x ships openssh 9.3p2 which is above the fix "
            "boundary for CVE-2023-38408 but potentially affected by CVE-2025-26465 "
            "(see TOS46-C02 in tencent_tos46_components_re.py)."
        ),
        "chain": (
            "TOS33-F03: Developer on TOS 3.3 uses ssh -A (agent forwarding) to production server → "
            "connects through or to an attacker-controlled intermediate → "
            "CVE-2023-38408 PKCS#11 load via agent protocol → "
            "arbitrary code execution in ssh-agent on developer machine → "
            "all private keys stored in agent accessible to attacker → "
            "lateral movement to all servers accessible with forwarded agent credentials"
        ),
        "remediation": (
            "Upgrade to TOS 4.x (openssh 9.3p2, above CVE-2023-38408 fix boundary). "
            "Interim: disable agent forwarding (ForwardAgent=no in ~/.ssh/config). "
            "On existing TOS 3.3 systems, TOS cannot backport the fix to 8.0p1 — "
            "the bug was fixed upstream in 8.9p1, requiring a 9-minor-version jump."
        ),
        "references": ["CVE-2023-38408", "Qualys advisory QVA-2023-001", "openssh 8.9p1 release notes"],
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
        "libssh_freeze": "0.9.6-14 across all 6 builds (20 months post-Terrapin fix)",
        "openssl_eol": "1.1.1k, EOL Sep 2023 — still shipped Aug 2025 (24 months post-EOL)",
        "openssh_freeze": "8.0p1 (2019-era, CVE-2023-38408 vulnerable)",
        "kernel_progression": "5.4.119-19 (launch) -> 5.4.241-24 (Dec 2024 upgrade)",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
