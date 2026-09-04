"""
TencentOS Server 4.2 ISO SBOM RE Module
Sources: SPDX JSON ISO SBOMs from /media/cowboy/research/tencentos/sbom/ISOs/
  TencentOS-Server-4.2-20240515.0-x86_64-minimal.iso.spdx.json  (May 2024)
  TencentOS-Server-4.2-20240619.0-x86_64-minimal.iso.spdx.json  (Jun 2024)
  TencentOS-Server-4.2-20240729.2-x86_64-minimal.iso.spdx.json  (Jul 2024)
  TencentOS-Server-4.2-20240902.0-x86_64-minimal.iso.spdx.json  (Sep 2024)
  TencentOS-Server-4.2-20241018.1-x86_64-minimal.iso.spdx.json  (Oct 2024)
  TencentOS-Server-4.2-20241126.1-x86_64-minimal.iso.spdx.json  (Nov 2024)
Method: pkg:rpm purl extraction from SPDX packages[] array
Analysis date: 2026-09-04

TencentOS 4.2 is the RHEL 9-derived line, placed between 4.0 (Mar 2024) and 4.4 (Sep 2025).
6 monthly builds available from May to November 2024.

Key observation: libssh is frozen at 0.10.5-3 across all 6 TOS 4.2 builds —
the same version as TOS 4.0 (Mar 2024). The Terrapin fix (libssh 0.10.6, Jan 2024)
was never applied in TOS 4.x across the entire 4.0 → 4.2 → 4.4 → 4.6 lifecycle.

The kernel IS updated regularly in TOS 4.2 (6.6.30 → 6.6.58 across 6 months),
contrasting with the 3.x kernel freeze pattern. Only crypto components freeze.
"""

COMPONENT_VERSIONS_BY_BUILD = {
    "20240515": {
        "kernel":       "6.6.30-4",
        "openssh":      "9.3p2-8",
        "libssh":       "0.10.5-3",
        "openssl-libs": "3.0.12-3",
        "glibc":        "2.38-11",
        "sudo":         "1.9.15p5-1",
        "pam":          "1.5.3-4",
        "systemd":      "255-4",
        "bash":         "5.2.15-2",
        "xz":           "5.4.4-1",
        "curl":         "8.4.0-8",
        "libcurl":      "8.4.0-8",
    },
    "20240619": {
        "kernel":       "6.6.30-5",
        "openssh":      "9.3p2-8",
        "libssh":       "0.10.5-3",
        "openssl-libs": "3.0.12-7",
        "glibc":        "2.38-13",
        "sudo":         "1.9.15p5-1",
        "pam":          "1.5.3-4",
        "systemd":      "255-4",
        "bash":         "5.2.15-2",
        "xz":           "5.4.4-1",
    },
    "20240729": {
        "kernel":       "6.6.30-5",
        "openssh":      "9.3p2-13",
        "libssh":       "0.10.5-3",
        "openssl-libs": "3.0.12-8",
        "glibc":        "2.38-13",
        "sudo":         "1.9.15p5-1",
        "pam":          "1.5.3-4",
        "systemd":      "255-4",
        "bash":         "5.2.15-2",
        "xz":           "5.4.4-1",
    },
    "20240902": {
        "kernel":       "6.6.34-9",
        "openssh":      "9.3p2-13",
        "libssh":       "0.10.5-3",
        "openssl-libs": "3.0.12-8",
        "glibc":        "2.38-13",
        "sudo":         "1.9.15p5-1",
        "pam":          "1.5.3-4",
        "systemd":      "255-4",
        "bash":         "5.2.15-2",
        "xz":           "5.4.4-1",
    },
    "20241018": {
        "kernel":       "6.6.47-12",
        "openssh":      "9.3p2-13",
        "libssh":       "0.10.5-3",
        "openssl-libs": "3.0.12-14",
        "glibc":        "2.38-13",
        "sudo":         "1.9.15p5-1",
        "pam":          "1.5.3-4",
        "systemd":      "255-4",
        "bash":         "5.2.15-2",
        "xz":           "5.4.4-1",
    },
    "20241126": {
        "kernel":       "6.6.58-15",
        "openssh":      "9.3p2-13",
        "libssh":       "0.10.5-3",
        "openssl-libs": "3.0.12-14",
        "glibc":        "2.38-23",
        "sudo":         "1.9.15p5-1",
        "pam":          "1.5.3-4",
        "systemd":      "255-4",
        "bash":         "5.2.15-2",
        "xz":           "5.4.4-1",
    },
}

LIBSSH_FREEZE_CONTEXT = {
    "CVE_2023_48795_disclosed":     "2023-12-18",
    "libssh_0_10_6_released":       "2024-01-13",
    "TOS_4_0_launched":             "2024-03-22",
    "TOS_4_2_first_build":          "2024-05-15",
    "TOS_4_2_last_available_build": "2024-11-26",
    "TOS_4_4_released":             "2025-09",
    "TOS_4_6_released":             "2026-04-09",
    "libssh_version_all_TOS_42":    "0.10.5-3",
    "fix_available_at_TOS42_launch": "4 months",
    "note": (
        "TOS 4.2 launched in May 2024 — 4 months after the Terrapin fix in libssh 0.10.6. "
        "The decision at TOS 4.0 launch (March 2024, 2 months post-fix) to ship 0.10.5 "
        "was carried forward unchanged through all 6 TOS 4.2 builds. "
        "The 4.2 series ends November 2024 with libssh still at 0.10.5-3 — the same "
        "release count as TOS 4.0. Not a single build in the 4.2 series received the fix."
    ),
}

KERNEL_UPDATE_PATTERN = {
    "20240515": "6.6.30-4",
    "20240619": "6.6.30-5",
    "20240729": "6.6.30-5",
    "20240902": "6.6.34-9",
    "20241018": "6.6.47-12",
    "20241126": "6.6.58-15",
    "note": (
        "The kernel IS updated in TOS 4.2: 6.6.30 (May 2024) → 6.6.58 (Nov 2024), "
        "a 28-minor-version advancement in 6 months. "
        "This is the inverse of the TOS 3.x pattern where the kernel froze and "
        "only userspace components got periodic counter bumps. "
        "TOS 4.x updates kernel routinely; TOS 4.x's stable freeze is in libssh/openssh "
        "upstream versions, not the kernel."
    ),
}

FINDINGS = {
    "TOS42-F01": {
        "title": (
            "libssh 0.10.5-3 Frozen Across All 6 TOS 4.2 Builds (May-Nov 2024); "
            "Terrapin Fix (libssh 0.10.6) Was Available 4 Months Before First TOS 4.2 Build; "
            "Confirms Cross-Series Pattern: TOS 4.0, 4.2, 4.4, 4.6 All Ship 0.10.5"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-354",
        "component": "libssh-0.10.5-3 (all 6 TOS 4.2 builds, May-Nov 2024)",
        "description": (
            "libssh 0.10.6 was released January 13, 2024 with the CVE-2023-48795 Terrapin fix. "
            "TOS 4.2 launched May 15, 2024 — 4 months after the fix was available. "
            "Across all 6 TOS 4.2 builds (May through November 2024), libssh remains at 0.10.5-3. "
            "\n"
            "The full TOS 4.x libssh freeze: "
            "  TOS 4.0 (Mar 2024): 0.10.5-3 — 2 months post-fix "
            "  TOS 4.2 (May-Nov 2024): 0.10.5-3 — 4-10 months post-fix "
            "  TOS 4.4 (Sep 2025): 0.10.5-6 — 20 months post-fix "
            "  TOS 4.6 (Apr 2026): 0.10.5-6 — 27 months post-fix "
            "\n"
            "The release counter did NOT advance at all in TOS 4.2 (-3 throughout), "
            "whereas it later advanced to -6 in 4.4/4.6. This means not even "
            "Tencent-internal patches were applied to libssh during the entire 4.2 series. "
            "\n"
            "Cross-series comparison: TOS 3.3 ships libssh 0.9.x (0.9.6-14, also frozen), "
            "TOS 4.x ships 0.10.x (0.10.5-3/-6, also frozen). "
            "Both branches carry the Terrapin vulnerability across their entire respective series."
        ),
        "chain": (
            "TOS42-F01: MitM SSH session with libssh client ��� Terrapin → "
            "chacha20-poly1305 or CBC-ETM session truncated → keystroke timing open → "
            "credential inference from timing side-channel"
        ),
        "references": [
            "CVE-2023-48795",
            "TOS40-F01 (tencent_tos40_container_re.py)",
            "TOS46-C01 (tencent_tos46_components_re.py)",
            "TOS33-F01 (tencent_tos33_iso_sbom_re.py)",
        ],
    },
    "TOS42-F02": {
        "title": (
            "TOS 4.2 Kernel Updated Actively (6.6.30 → 6.6.58 Across 6 Months); "
            "Inverse of TOS 3.x Kernel Freeze; Confirms TOS 4.x Policy: Kernel Updated, "
            "libssh/openssh Upstream Versions Frozen"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "component": "kernel-6.6.30-4 (May 2024) through kernel-6.6.58-15 (Nov 2024)",
        "description": (
            "TOS 4.2 kernel progression across 6 builds: "
            "  May 2024: 6.6.30-4 "
            "  Jun 2024: 6.6.30-5 (minor) "
            "  Jul 2024: 6.6.30-5 (unchanged) "
            "  Sep 2024: 6.6.34-9 (3 minor versions forward) "
            "  Oct 2024: 6.6.47-12 (13 minor versions forward) "
            "  Nov 2024: 6.6.58-15 (11 minor versions forward) "
            "\n"
            "The 6.6 LTS branch is actively maintained; TOS 4.2 tracks it regularly. "
            "This is the inverse of TOS 3.x where the 5.4.x kernel was frozen 33 months "
            "(TOS 2.4: TOS24-F03) or launched 2.5 years behind (TOS 3.3: TOS33-F04). "
            "\n"
            "The TOS 4.x update posture: kernel = updated; crypto libs (libssh, openssh) = "
            "upstream version frozen with only release counter increments. "
            "This is a consistent cross-series policy choice, not an oversight."
        ),
        "references": [
            "TOS24-F03 (tencent_tos24_iso_sbom_re.py)",
            "TOS33-F04 (tencent_tos33_iso_sbom_re.py)",
        ],
    },
    "TOS42-F03": {
        "title": (
            "openssh 9.3p2-8 at TOS 4.2 Launch (May 2024); Advances to 9.3p2-13 by Jul 2024; "
            "Upstream Version Frozen at 9.3p2 Across All 4.2 Builds; "
            "CVE-2025-26465 (VerifyHostKeyDNS MitM) Disclosed Feb 2025 — After 4.2 Series"
        ),
        "severity": "LOW",
        "cvss": "4.3",
        "cwe": "CWE-295",
        "component": "openssh-9.3p2-8 (May-Jun 2024); openssh-9.3p2-13 (Jul-Nov 2024)",
        "description": (
            "TOS 4.2 openssh release counter advances: 9.3p2-8 (May-Jun) → 9.3p2-13 (Jul-Nov). "
            "Upstream version stays at 9.3p2 — the RHEL 9 baseline version. "
            "\n"
            "CVE-2025-26465 (VerifyHostKeyDNS MitM, February 2025) was disclosed after the "
            "last TOS 4.2 build (November 2024). The 4.2 series predates this CVE entirely. "
            "However: TOS 4.4 (September 2025) and TOS 4.6 (April 2026) also ship 9.3p2-15 "
            "which is below the RHEL 9 fix level of 9.3p2-18.el9_5 (see TOS46-C02). "
            "\n"
            "The release counter advance from -8 to -13 in 4.2 represents RHEL 9 security "
            "backports incorporated by Tencent. The counter progression in 4.2 "
            "(max -13) is below TOS 4.4/4.6 (-15), confirming TOS 4.4 included additional patches. "
            "\n"
            "Key gap: in the 4.2 series, openssh upstream version = 9.3p2 throughout. "
            "The upstream security fix cadence (9.4p1, 9.5p1, 9.6p1, 9.7p1, 9.8p1) was "
            "not adopted; all of those fixes had to be backported manually into the 9.3p2 tree."
        ),
        "references": [
            "CVE-2025-26465",
            "TOS46-C02 (tencent_tos46_components_re.py)",
        ],
    },
}

CROSS_SERIES_LIBSSH_SUMMARY = {
    "TOS_3_3_branch": {
        "version": "0.9.6",
        "fix_version": "0.9.8",
        "freeze_start": "2024-06 (TOS 3.3 launch)",
        "freeze_end": "2025-08 (last known build)",
        "months_frozen": 14,
        "fix_was_available": "2024-01 (6 months before launch)",
    },
    "TOS_4_x_branch": {
        "version": "0.10.5",
        "fix_version": "0.10.6",
        "freeze_start": "2024-03 (TOS 4.0 launch)",
        "freeze_end": "2026-04 (TOS 4.6, last known build)",
        "months_frozen": 25,
        "fix_was_available": "2024-01 (2 months before TOS 4.0 launch)",
    },
    "note": (
        "TencentOS maintains two parallel libssh branches: 0.9.x (TOS 3.x) and 0.10.x (TOS 4.x). "
        "Both branches have an available Terrapin fix (0.9.8 for 0.9.x; 0.10.6 for 0.10.x). "
        "Neither branch received the fix across any TOS release. "
        "This is not an oversight on one branch — it is a platform-wide pattern."
    ),
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "SPDX ISO SBOMs, TOS 4.2 x86_64 minimal (6 builds, May-Nov 2024)",
        "method": "pkg:rpm purl extraction from packages[] array",
        "libssh_freeze": "0.10.5-3 across all 6 builds (fix available 4 months pre-launch)",
        "kernel_updated": "6.6.30 -> 6.6.58 across 6 months (active update policy)",
        "openssh_upstream": "9.3p2 frozen (release counter -8 -> -13)",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
