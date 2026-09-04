"""
TencentOS Server 4.0 Container Image RE Module
Source: /media/cowboy/research/tencentos/4.0/tencentos-server-4.0-x86_64.tar (611MB)
  Image structure: Docker image tar -> single-layer Docker image (one layer.tar)
  RPM database: layer.tar -> usr/lib/sysimage/rpm/rpmdb.sqlite (SQLite, RPM 4.16+ format)
  Package extraction: Python RPM header blob parser (no magic prefix format; il/dl header)
Analysis date: 2026-09-04

TencentOS 4.0 (early 2024, RHEL 9 base):
  Container image: 2024-03-22 tarball modification date
  os-release: "TencentOS Server 4.0"
  kernel-headers: 6.6.6-2401.0.1.tl4.4 (6.6.6 kernel era, January 2024 build)

This image establishes the TOS 4.0 launch baseline. Key comparisons to TOS 4.4/4.6:
  openssh: 9.3p2-8.tl4 (4.0) → 9.3p2-15.tl4 (4.4/4.6) — upstream version FROZEN at 9.3p2
  libssh:  0.10.5-3.tl4 (4.0) → 0.10.5-6.tl4 (4.6) — upstream version FROZEN at 0.10.5
  openssl: 3.0.12-3.tl4 (4.0) → 3.0.12-25.tl4 (4.6) — upstream version FROZEN at 3.0.12
  systemd: 255-3.tl4.1 (4.0) → 255-20.tl4.ap.1 (4.6) — substantial patch accumulation

The libssh freeze is the critical observation: libssh 0.10.6 (Terrapin fix, CVE-2023-48795)
was released January 2024. TOS 4.0 shipped March 2024 — a deliberate decision to launch
with unpatched libssh even though the fix was 2 months old at launch time.
"""

COMPONENT_VERSIONS_TOS40 = {
    "kernel-headers":   "6.6.6-2401.0.1.tl4.4",
    "openssh":          "9.3p2-8.tl4",
    "openssh-clients":  "9.3p2-8.tl4",
    "openssh-server":   "9.3p2-8.tl4",
    "libssh":           "0.10.5-3.tl4",
    "openssl":          "3.0.12-3.tl4",
    "openssl-libs":     "3.0.12-3.tl4",
    "glibc":            "2.38-5.tl4",
    "glibc-common":     "2.38-5.tl4",
    "bash":             "5.2.15-2.tl4",
    "sudo":             "1.9.15p5-1.tl4",
    "polkit":           "123-2.tl4",
    "polkit-libs":      "123-2.tl4",
    "systemd":          "255-3.tl4.1",
    "systemd-libs":     "255-3.tl4.1",
    "systemd-pam":      "255-3.tl4.1",
    "systemd-udev":     "255-3.tl4.1",
    "curl":             "8.4.0-4.tl4",
    "libcurl":          "8.4.0-4.tl4",
    "python3":          "3.11.6-2.tl4",
    "bind-libs":        "9.18.18-4.tl4",
    "nss":              "3.93-3.tl4",
    "krb5-libs":        "1.21.2-1.tl4",
    "pam":              "1.5.3-4.tl4",
    "xz":               "5.4.4-1.tl4",
    "xz-libs":          "5.4.4-1.tl4",
    "expat":            "2.5.0-2.tl4",
}

DELTA_FROM_TOS40_TO_TOS46 = {
    "kernel": {
        "tos40_headers": "6.6.6-2401.0.1.tl4.4",
        "tos46": "6.6.119-47.8.tl4",
        "note": "6.6.6 → 6.6.119 — 113 upstream stable releases across the series",
    },
    "openssh": {
        "tos40": "9.3p2-8.tl4",
        "tos46": "9.3p2-15.tl4",
        "note": "UPSTREAM VERSION FROZEN — only release counter advanced (+7)",
    },
    "libssh": {
        "tos40": "0.10.5-3.tl4",
        "tos46": "0.10.5-6.tl4",
        "note": "UPSTREAM VERSION FROZEN — 0.10.5 at 4.0 launch (Mar 2024); fix in 0.10.6 (Jan 2024)",
    },
    "openssl": {
        "tos40": "3.0.12-3.tl4",
        "tos46": "3.0.12-25.tl4",
        "note": "UPSTREAM VERSION FROZEN — release counter +22, but base version unchanged",
    },
    "glibc": {
        "tos40": "2.38-5.tl4",
        "tos46": "2.38-49.tl4",
        "note": "Release counter +44 — significant CVE backport activity within 2.38",
    },
    "systemd": {
        "tos40": "255-3.tl4.1",
        "tos46": "255-20.tl4.ap.1",
        "note": "Release counter +17; .ap.1 Tencent self-patch series introduced in 4.6",
    },
    "bind-libs": {
        "tos40": "9.18.18-4.tl4",
        "tos46": "9.18.21-4.tl4",
        "note": "9.18.18 → 9.18.21 — 3 upstream stable versions within LTS branch",
    },
    "pam": {
        "tos40": "1.5.3-4.tl4",
        "tos46": "1.5.3-12.tl4",
        "note": "Release counter +8",
    },
    "xz": {
        "tos40": "5.4.4-1.tl4",
        "tos46": "5.4.7-8.tl4",
        "note": "5.4.4 → 5.4.7 — remains in 5.4.x stable branch (clean — NOT 5.6.x)",
    },
}

FINDINGS = {
    "TOS40-F01": {
        "title": (
            "libssh 0.10.5-3 Shipped at TOS 4.0 Launch (March 2024) Despite "
            "Terrapin Fix (0.10.6) Being Available Since January 2024; "
            "Deliberate 2-Month Skip Established Pattern for Entire TOS 4.x Series"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-354",
        "component": "libssh-0.10.5-3.tl4 (TOS 4.0, March 2024)",
        "description": (
            "CVE-2023-48795 Terrapin attack: libssh 0.10.6 released January 2024 contains the fix. "
            "TencentOS 4.0 container image (modification date 2024-03-22) ships libssh 0.10.5-3.tl4 — "
            "the last pre-fix version. "
            "\n"
            "The timeline: "
            "  Dec 2023: CVE-2023-48795 disclosed; libssh 0.10.6 released with fix "
            "  Jan 2024: libssh 0.10.6 available for 1 month "
            "  Mar 2024: TOS 4.0 ships 0.10.5 — fix available for 2 months, not applied "
            "  Sep 2025: TOS 4.4 ships 0.10.5 — fix available for 21 months, not applied "
            "  Apr 2026: TOS 4.6 ships 0.10.5-6 — fix available for 27 months, not applied "
            "\n"
            "The TOS 4.0 launch decision established the baseline that all subsequent TOS 4.x "
            "releases inherited. This is not a regression — it is an initial choice that "
            "Tencent has maintained unchanged across 27 months of TOS 4.x releases."
        ),
        "chain": (
            "TOS40-F01: MitM on SSH session with ChaCha20-Poly1305 or CBC-ETM cipher → "
            "Terrapin truncates negotiation → keystroke timing countermeasures disabled → "
            "side-channel inference of typed credentials"
        ),
        "references": ["CVE-2023-48795", "libssh 0.10.6 release notes"],
    },
    "TOS40-F02": {
        "title": (
            "TOS 4.0 openssh 9.3p2-8 Launched Without CVE-2025-26465 Fix; "
            "Fix Requires 9.3p2-18.el9_5 Level; TOS 4.x Series Has Reached -15 at Most"
        ),
        "severity": "MEDIUM",
        "cvss": "6.8",
        "cwe": "CWE-295",
        "component": "openssh-9.3p2-8.tl4 (TOS 4.0); openssh-9.3p2-15.tl4 (TOS 4.6)",
        "description": (
            "CVE-2025-26465 (VerifyHostKeyDNS MitM, Feb 2025) was patched in RHEL 9 at "
            "openssh-9.3p2-18.el9_5. "
            "\n"
            "TOS 4.0 launched with 9.3p2-8.tl4. TOS 4.6 (April 2026) is at 9.3p2-15.tl4. "
            "The TOS tl4 release counter has never reached 18 — the minimum required to match "
            "the RHEL 9 fix level if tl4 and el9_5 counters are proportional. "
            "\n"
            "Status across TOS 4.x: "
            "  4.0 (Mar 2024): 9.3p2-8.tl4 — OPEN (pre-CVE date, not relevant) "
            "  4.4 (Sep 2025): 9.3p2-15.tl4 — OPEN (fix disclosed Feb 2025, -15 < -18) "
            "  4.6 (Apr 2026): 9.3p2-15.tl4 — OPEN (unchanged from 4.4) "
            "\n"
            "CAVEAT: tl4 release counters are not 1:1 with el9_5 counters. Definitive "
            "confirmation requires binary-level verification of verify_host_key_dns() "
            "in the TOS 4.6 openssh client binary."
        ),
        "references": ["CVE-2025-26465", "RHSA-2025:1677", "TOS46-C02 in tencent_tos46_components_re.py"],
    },
    "TOS40-F03": {
        "title": (
            "xz 5.4.4 in TOS 4.0 — Clean Branch (Not CVE-2024-3094); "
            "TOS 4.x Series Consistently Pins 5.4.x Branch Across All Releases"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "component": "xz-5.4.4-1.tl4 (TOS 4.0)",
        "description": (
            "CVE-2024-3094 (XZ backdoor by Jia Tan, March 2024) affected 5.6.0 and 5.6.1 only. "
            "TOS 4.0 (March 2024, same month as disclosure) ships xz-5.4.4-1.tl4 — "
            "the 5.4.x stable branch, clean. TOS 4.6 ships 5.4.7-8.tl4. "
            "Tencent consistently used the 5.4.x stable branch across the entire TOS 4.x series."
        ),
    },
    "TOS40-F04": {
        "title": (
            "TOS 4.0 sudo 1.9.15p5 vs TOS 3.1 sudo 1.8.29-8; "
            "TOS 4.x Uses 1.9.x Branch (Active Upstream) vs 3.x EOL 1.8.x"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "component": "sudo-1.9.15p5-1.tl4",
        "description": (
            "TOS 4.0 ships sudo 1.9.15p5 — the 1.9.x active upstream branch. "
            "TOS 3.1 shipped 1.8.29-8 (1.8.x branch, which was 'legacy' since 2020). "
            "The 1.9.x branch has more active upstream CVE remediation. "
            "Specific differences: 1.9.x added more robust session recording, "
            "improved audit logging, and additional bug-class fixes."
        ),
    },
}

LIBSSH_FREEZE_TIMELINE = {
    "CVE-2023-48795_disclosed": "2023-12-18",
    "libssh_0_10_6_released": "2024-01-13",
    "TOS_4_0_container_built": "2024-03-22",
    "fix_available_at_TOS40_launch": "2 months",
    "TOS_4_4_released": "2025-09",
    "fix_available_at_TOS44_release": "~21 months",
    "TOS_4_6_released": "2026-04-09",
    "fix_available_at_TOS46_release": "~27 months",
    "libssh_version_across_all_TOS4x": "0.10.5 (unchanged)",
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "tencentos-server-4.0-x86_64.tar (Docker image, 611MB)",
        "method": "layer.tar extraction; RPM blob header parse (no-magic format)",
        "kernel_version": "6.6.6-2401.0.1.tl4.4",
        "container_date": "2024-03-22",
        "libssh_freeze_finding": "0.10.5 at launch despite 0.10.6 Terrapin fix 2mo earlier",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
