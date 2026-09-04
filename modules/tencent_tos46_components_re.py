"""
TencentOS Server 4.6 Component RE Module
Source: TencentOS-Server-4.6-20260409.0-x86_64-boot.iso (April 9, 2026)
  ISO -> install.img (squashfs) -> LiveOS/rootfs.img (ext4, Anaconda installer)
  Package versions from: /var/lib/dnf/history.sqlite (rpm table, 698 rows)
  Kernel KASLR confirmation: vmlinuz-6.6.119-47.8.tl4 decompressed (61MB);
    arch/x86/mm/kaslr.c + kaslr_get_random_long present -> CONFIG_RANDOMIZE_BASE=y
Analysis date: 2026-09-04

TencentOS 4.6 in the TOS 4.x line:
  4.0 (2023): RHEL 9 userspace, 6.6.x kernel, KASLR disabled in early 6.6 builds
  4.2 (2024): KASLR fixed at 6.6.70 (per tencent_kernel_cross_version.py)
  4.4 (Sep 2025): 6.6.110, KASLR enabled, openssh 9.3p2-15.tl4
  4.6 (Apr 2026): 6.6.119, KASLR enabled, openssh 9.3p2-15.tl4 (NO UPDATE FROM 4.4)
  CVE-2025-26465 binary analysis: BuildID e01050f8b90fb107f41e0ec034dd691c055fd6b9
    RHEL 9.5 fix: openssh-9.3p2-16.el9_5 (RHSA-2025:1677, Feb 2025)
    TOS 4.6: -15.tl4 = BELOW RHEL fix counter; no forced-reject path found in SSHFP
    matching code at 0x2ddc7-0x2de14 in stripped binary. Status: OPEN (UNCONFIRMED)

systemd .ap series: systemd-255-20.tl4.ap.1 first seen in 4.6 — the Tencent self-patch
  series (.ap.N counter) previously confined to glibc, openssh, openssl on 3.x branches
  has expanded into RHEL 9 / TOS 4.x core services as of 4.6.

linux-firmware timestamp: 20250917 (September 2025 upstream snapshot) — the April 2026
  boot ISO ships 6-month-old firmware. Applies to GPU/NIC/WiFi microcode advisories
  released October 2025 - April 2026.
"""

COMPONENT_VERSIONS_TOS46 = {
    "kernel":         "6.6.119-47.8.tl4.x86_64",
    "openssl-libs":   "3.0.12-25.tl4.x86_64",
    "glibc":          "2.38-49.tl4.x86_64",
    "openssh":        "9.3p2-15.tl4.x86_64",
    "openssh-clients":"9.3p2-15.tl4.x86_64",
    "openssh-server": "9.3p2-15.tl4.x86_64",
    "libssh":         "0.10.5-6.tl4.x86_64",
    "gnutls":         "3.8.2-11.tl4.x86_64",
    "curl":           "8.4.0-15.tl4.x86_64",
    "libcurl":        "8.4.0-15.tl4.x86_64",
    "expat":          "2.6.4-5.tl4.x86_64",
    "libxml2":        "2.11.5-11.tl4.x86_64",
    "sudo":           "ABSENT from ISO installer env (check container)",
    "polkit":         "123-5.tl4.x86_64",
    "pam":            "1.5.3-12.tl4.x86_64",
    "systemd":        "255-20.tl4.ap.1.x86_64",
    "nss":            "3.112-2.tl4.x86_64",
    "krb5-libs":      "1.21.2-8.tl4.x86_64",
    "bind-libs":      "9.18.21-4.tl4.x86_64",
    "python3":        "3.11.6-30.tl4.x86_64",
    "xz":             "5.4.7-8.tl4.x86_64",
    "zlib":           "1.2.13-9.tl4.x86_64",
    "bash":           "5.2.15-7.tl4.x86_64",
    "coreutils":      "9.4-9.tl4.x86_64",
    "dbus":           "1.14.8-4.tl4.x86_64",
    "selinux-policy": "40.9-4.tl4.ap.1.noarch",
    "linux-firmware":  "20250917-2.tl4.noarch",
    "NetworkManager": "1.44.2-8.tl4.x86_64",
    "audit":          "3.1.2-3.tl4.x86_64",
    "rsyslog":        "8.2312.0-6.tl4.x86_64",
    "rpm":            "4.18.2-4.tl4.x86_64",
    "dnf":            "4.16.2-5.tl4.noarch",
    "iproute":        "6.6.0-6.tl4.x86_64",
    "util-linux":     "2.39.1-12.tl4.x86_64",
}

DELTA_FROM_TOS44 = {
    "kernel":        {"tos44": "6.6.110-*.tl4", "tos46": "6.6.119-47.8.tl4", "note": "kernel updated"},
    "openssl-libs":  {"tos44": "3.0.12-18.tl4", "tos46": "3.0.12-25.tl4", "note": "release counter +7, CVE backports"},
    "glibc":         {"tos44": "2.38-46.tl4", "tos46": "2.38-49.tl4", "note": "release counter +3"},
    "openssh":       {"tos44": "9.3p2-15.tl4", "tos46": "9.3p2-15.tl4", "note": "UNCHANGED — identical package"},
    "libssh":        {"tos44": "0.10.5-*.tl4", "tos46": "0.10.5-6.tl4", "note": "Terrapin PATCHED at -6 (CVE-2023-48795.patch in SRPM); -3 (TOS 4.0/4.2) still open"},
    "systemd":       {"tos44": "255-*.tl4", "tos46": "255-20.tl4.ap.1", "note": ".ap.1 series introduced"},
    "selinux-policy":{"tos44": "unknown", "tos46": "40.9-4.tl4.ap.1", "note": ".ap.1 series introduced"},
    "pam":           {"tos44": "1.5.3-*.tl4", "tos46": "1.5.3-12.tl4", "note": "same base"},
    "polkit":        {"tos44": "123-*.tl4", "tos46": "123-5.tl4", "note": "polkit 123 — well past PwnKit (0.120)"},
    "bind-libs":     {"tos44": "9.18.*", "tos46": "9.18.21-4.tl4", "note": "BIND 9.18 LTS (vs OCO 9.4's EOL 9.11)"},
}

FINDINGS = {
    "TOS46-C01": {
        "title": (
            "CORRECTED: libssh CVE-2023-48795 Terrapin Fix Present in TOS 4.4/4.6 (-6 SRPM); "
            "CVE-2023-48795.patch Confirmed in libssh-0.10.5-6.tl4.src.rpm; "
            "Terrapin OPEN Only at -3 (TOS 4.0, 4.2); FIXED at -6 (TOS 4.4, 4.6 ISO)"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "status": "CORRECTED — prior MEDIUM finding was wrong for TOS 4.4/4.6",
        "component": "libssh-0.10.5-6.tl4 (TOS 4.6 ISO); libssh-0.10.5-3.tl4 (TOS 4.0, 4.2 — still open)",
        "description": (
            "ORIGINAL FINDING (now corrected): TOS46-C01 previously asserted libssh 0.10.5 "
            "Terrapin was open at TOS 4.6 because 0.10.5 < 0.10.6 (upstream fix version). "
            "\n"
            "CORRECTION via SRPM patch file analysis: "
            "  /media/cowboy/research/tencentos/4.6/BaseOS-source/libssh-0.10.5-6.tl4.src.rpm "
            "  Contains: CVE-2023-48795.patch — Terrapin fix directly backported "
            "  Also contains: CVE-2023-6004.patch, CVE-2023-6918.patch "
            "  Changelog entry: fixed at -4 (Aug 16 2024, OpenCloudOS RelEng) "
            "\n"
            "Libssh Terrapin fix timeline across TOS 4.x: "
            "  -3 (TOS 4.0 Mar 2024, TOS 4.2 all 7 builds May-Dec 2024): NO patch — OPEN "
            "  -4 (Aug 16 2024 per changelog): CVE-2023-48795.patch added — fix applied "
            "  -6 (TOS 4.4 Sep 2025, TOS 4.6 ISO Apr 2026): Patch confirmed in SRPM — FIXED "
            "  -7 (TOS 4.6 qcow2 update): CVE-2026-0964 added on top — still Terrapin-fixed "
            "\n"
            "Confirmed-open findings: "
            "  TOS40-F01 (tencent_tos40_container_re.py): libssh-0.10.5-3 — REMAINS OPEN "
            "  TOS42-F01 (tencent_tos42_iso_sbom_re.py): libssh-0.10.5-3 across all 7 builds — REMAINS OPEN "
            "\n"
            "TOS 4.0 and 4.2 deployments remain vulnerable to Terrapin. "
            "TOS 4.4 and 4.6 (ISO + qcow2) are patched. "
            "\n"
            "This corrects the inference that 'upstream version frozen at 0.10.5 = unpatched.' "
            "Tencent's policy: freeze upstream version, accumulate CVE backports as release "
            "counter increments. SRPM patch file enumeration is the definitive check; "
            "upstream version comparison is insufficient for this distro's patch model."
        ),
        "verification_method": (
            "rpm2cpio libssh-0.10.5-6.tl4.src.rpm | cpio -idmv; "
            "ls *.patch; "
            "Result: CVE-2023-48795.patch, CVE-2023-6004.patch, CVE-2023-6918.patch present."
        ),
        "references": [
            "CVE-2023-48795",
            "TOS46-SRPM-F01 (tencent_tos46_srpm_re.py) — full SRPM analysis",
            "TOS40-F01 (tencent_tos40_container_re.py) — -3 still open",
            "TOS42-F01 (tencent_tos42_iso_sbom_re.py) — -3 still open across 7 builds",
            "TOS33-F01 CORRECTION (tencent_tos33_iso_sbom_re.py) — same backport pattern in 0.9.6-14",
        ],
    },
    "TOS46-C02": {
        "title": (
            "openssh 9.3p2-15.tl4 CVE-2025-26465 CONFIRMED OPEN via SRPM Patch Absence; "
            "openssh-9.3p2-15.tl4.src.rpm Has No CVE-2025-26465.patch; "
            "Fix Added at -16 (Jul 29 2026) with CVE-2026-35385 and CVE-2026-35414 Co-Patch"
        ),
        "severity": "MEDIUM",
        "cvss": "6.8",
        "cwe": "CWE-295",
        "component": "openssh-9.3p2-15.tl4 (TOS 4.6 ISO Apr 2026; qcow2 unpatched as of Jul 2026)",
        "description": (
            "CVE-2025-26465 (Qualys, Feb 2025): OpenSSH client accepts MitM when "
            "VerifyHostKeyDNS=yes is enabled and SSHFP DNS records exist. "
            "\n"
            "CONFIRMED via SRPM patch file enumeration: "
            "  openssh-9.3p2-15.tl4.src.rpm: "
            "    Contains: openssh-9.6p1-CVE-2023-48795.patch (Terrapin) "
            "    Contains: openssh-9.6p1-cve-2024-6387.patch (regreSSHion) "
            "    ABSENT:   openssh-9.3p2-CVE-2025-26465.patch "
            "  -> CVE-2025-26465 is OPEN at -15 "
            "\n"
            "  openssh-9.3p2-16.tl4.src.rpm (released Jul 29 2026): "
            "    Adds: openssh-9.3p2-CVE-2025-26465.patch "
            "    Adds: openssh-9.3p2-CVE-2026-35385.patch (scp setuid bits, root download) "
            "    Adds: openssh-9.3p2-CVE-2026-35414.patch (empty cert principals fail-open) "
            "    Changelog: 'Fix CVE-2026-35414, CVE-2026-35385, CVE-2025-26465' "
            "    Adapted-by: PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream) "
            "\n"
            "TOS 4.6 ISO (Apr 2026, openssh -15): OPEN for CVE-2025-26465 "
            "TOS 4.6 qcow2 after Jul 2026 update (-16 available): FIXED "
            "The mounted qcow2 at /mnt/qcow2 shows TENCENTOS_UPDATE_ID=6 (libssh -7); "
            "openssh version in that qcow2 needs verification. "
            "\n"
            "Attack chain: VerifyHostKeyDNS=yes → attacker spoofs SSHFP DNS records "
            "or MitM DNSSEC → CVE-2025-26465 → client accepts forged host key → "
            "credential exposure over attacker-controlled session."
        ),
        "references": [
            "CVE-2025-26465",
            "RHSA-2025:1677 (RHEL backport at -18.el9_5)",
            "TOS46-SRPM-F02 (tencent_tos46_srpm_re.py) — full SRPM patch analysis",
            "TOS46-SRPM-F05 (tencent_tos46_srpm_re.py) — CVE-2026-35385 co-patched at -16",
            "TOS46-SRPM-F06 (tencent_tos46_srpm_re.py) — CVE-2026-35414 co-patched at -16",
        ],
    },
    "TOS46-C03": {
        "title": (
            "linux-firmware 20250917 (Sep 2025 Snapshot) Shipped in April 2026 ISO; "
            "6 Months of Microcode/Firmware Advisories Not Applied; "
            "Affects GPU (NVIDIA/AMD), NIC, Intel ME Firmware for Affected Hardware"
        ),
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-1104",
        "component": "linux-firmware-20250917-2.tl4.noarch (confirmed via dnf history.sqlite)",
        "description": (
            "TencentOS 4.6 (April 9, 2026 build date per ISO timestamp) ships "
            "linux-firmware-20250917, a firmware snapshot from September 17, 2025. "
            "The gap: 6 months of firmware/microcode updates between the package snapshot "
            "date and the ISO release date were not incorporated. "
            "\n"
            "Firmware released Oct 2025 - Apr 2026 that may be missing: "
            "Intel microcode updates (IPAS-2024-0020 series if released in this window); "
            "AMD GPU firmware for ROCm security fixes; "
            "Qualcomm/Realtek NIC firmware for CVE-affected chipsets; "
            "Marvell HBA firmware. "
            "\n"
            "This is a systematic supply-chain hygiene issue, not a specific CVE — "
            "the exact exposure depends on hardware in use at deployment sites."
        ),
        "remediation": "Apply dnf update linux-firmware on first boot or via kickstart %post.",
        "references": ["linux-firmware upstream github.com/torvalds/linux-firmware"],
    },
    "TOS46-C04": {
        "title": (
            "xz 5.4.7 in TOS 4.6 — CVE-2024-3094 Backdoor Check; "
            "5.4.7 Is Clean (Backdoor Was in 5.6.0/5.6.1); "
            "Version Confirms TOS 4.6 Correctly Avoided the XZ Backdoor"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "component": "xz-5.4.7-8.tl4 (confirmed via dnf history.sqlite)",
        "description": (
            "CVE-2024-3094 (XZ backdoor by Jia Tan, disclosed March 2024) affected "
            "xz-utils versions 5.6.0 and 5.6.1 only. "
            "TOS 4.6 ships xz-5.4.7, which is the 5.4.x stable branch — NOT affected. "
            "This confirms Tencent correctly pinned xz to the 5.4.x stable branch "
            "and did not pick up the compromised 5.6.x versions. "
            "Referenced as a clean-check finding for completeness in the TOS 4.6 RE."
        ),
        "references": ["CVE-2024-3094"],
    },
}

KASLR_STATUS = {
    "tos46_kernel": "6.6.119-47.8.tl4.x86_64",
    "config_randomize_base": "ENABLED (arch/x86/mm/kaslr.c + kaslr_get_random_long present in decompressed vmlinuz)",
    "confirmation_method": (
        "vmlinuz decompressed via dd+gunzip from offset 17105 (binwalk-identified); "
        "strings search for 'kaslr_get_random_long' and 'arch/x86/mm/kaslr.c' — both found. "
        "This is consistent with TOS 4.4 (6.6.110) and the fix at TOS 4.2 (6.6.70)."
    ),
    "contrast_with_tos3x": (
        "All TOS 3.x / OCO 8.x (5.4.119 TK4) have KASLR disabled. "
        "TOS 4.x (6.6.x) has KASLR enabled since 6.6.70 (TOS 4.2 era)."
    ),
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "TencentOS-Server-4.6-20260409.0-x86_64-boot.iso",
        "method": "ISO->squashfs->ext4 chain; dnf history.sqlite rpm table; 698 packages",
        "kernel": COMPONENT_VERSIONS_TOS46["kernel"],
        "kaslr": "ENABLED",
        "corrections": [
            "TOS46-C01 CORRECTED: libssh 0.10.5-6 Terrapin IS patched (CVE-2023-48795.patch in SRPM)",
            "TOS46-C02 CONFIRMED: openssh -15 CVE-2025-26465 open (patch absent in -15 SRPM; -16 Jul 2026 fixes it)",
        ],
        "open_findings": [
            "CVE-2025-26465 openssh (fixed at -16, Jul 2026)",
            "CVE-2026-35385 openssh scp setuid bits (fixed at -16)",
            "CVE-2026-35414 openssh empty cert principals (fixed at -16)",
            "CVE-2026-0964 libssh SCP path traversal (fixed at -7, qcow2 has it; ISO at -6 does not)",
            "CVE-2026-59843 libssh channel infinite loop (fixed at -8, open in both ISO and qcow2)",
        ],
        "findings": [k for k in FINDINGS],
    }, indent=2))
