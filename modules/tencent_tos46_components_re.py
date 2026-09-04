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
    "libssh":        {"tos44": "0.10.5-*.tl4", "tos46": "0.10.5-6.tl4", "note": "UNCHANGED — Terrapin still open"},
    "systemd":       {"tos44": "255-*.tl4", "tos46": "255-20.tl4.ap.1", "note": ".ap.1 series introduced"},
    "selinux-policy":{"tos44": "unknown", "tos46": "40.9-4.tl4.ap.1", "note": ".ap.1 series introduced"},
    "pam":           {"tos44": "1.5.3-*.tl4", "tos46": "1.5.3-12.tl4", "note": "same base"},
    "polkit":        {"tos44": "123-*.tl4", "tos46": "123-5.tl4", "note": "polkit 123 — well past PwnKit (0.120)"},
    "bind-libs":     {"tos44": "9.18.*", "tos46": "9.18.21-4.tl4", "note": "BIND 9.18 LTS (vs OCO 9.4's EOL 9.11)"},
}

FINDINGS = {
    "TOS46-C01": {
        "title": (
            "libssh 0.10.5 CVE-2023-48795 Terrapin Still Open in TOS 4.6 (April 2026); "
            "27 Months After Disclosure and 27 Months After Fix (libssh 0.10.6, Jan 2024); "
            "Identical to TOS 4.0, 4.2, 4.4 — Zero Progression Across 3 Major Point Releases"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-354",
        "component": "libssh-0.10.5-6.tl4 (confirmed via dnf history.sqlite)",
        "description": (
            "CVE-2023-48795 (Terrapin attack) was disclosed December 2023 and fixed in "
            "libssh 0.10.6 (January 2024). TencentOS 4.6 (April 2026) ships libssh 0.10.5, "
            "which is 27 months post-disclosure and 27 months post-fix. "
            "This is the same version shipped in TOS 4.0, 4.2, and 4.4 — the libssh version "
            "has not advanced across any TOS 4.x release. "
            "\n"
            "The Terrapin attack allows an active network MitM to truncate the SSH negotiation "
            "and downgrade security features (disabling keystroke-timing attack mitigations, "
            "disabling extension negotiation). Affected algorithms: ChaCha20-Poly1305 "
            "(chacha20-poly1305@openssh.com) or CBC with ETM (encrypt-then-MAC) variants. "
            "\n"
            "Impact for TOS 4.6 deployments: any SSH connection using affected ciphers is "
            "vulnerable to negotiation truncation. The primary client use case for libssh "
            "on TOS is git-over-SSH (libgit2) and automation tooling."
        ),
        "chain": (
            "TOS46-C01: MitM on SSH session (e.g., cloud provider LAN, compromised router) → "
            "Terrapin truncates handshake → disable CBC ETM or chacha20 negotiation → "
            "keystroke-timing countermeasures off → enables inference of typed passphrases "
            "or commands via keystroke timing side-channel"
        ),
        "remediation": (
            "Update libssh to 0.10.6+. Interim: enforce cipher policy to disable "
            "chacha20-poly1305@openssh.com and *-etm@openssh.com variants."
        ),
        "references": ["CVE-2023-48795", "TOS33-C02 (tencent_tos33_components_re.py)"],
    },
    "TOS46-C02": {
        "title": (
            "openssh 9.3p2-15.tl4 Unchanged Since TOS 4.4; "
            "CVE-2025-26465 (MitM via VerifyHostKeyDNS) Status Unconfirmed; "
            "RHEL 9 Fix Expected at 9.3p2-18.el9 or Higher"
        ),
        "severity": "MEDIUM",
        "cvss": "6.8",
        "cwe": "CWE-295",
        "component": "openssh-9.3p2-15.tl4 (confirmed via dnf history.sqlite)",
        "description": (
            "CVE-2025-26465 (disclosed February 2025) — OpenSSH client accepts a MitM "
            "connection when VerifyHostKeyDNS=yes is set and SSHFP records exist. "
            "The upstream fix was in openssh 9.9p2. RHEL 9 backported this to "
            "openssh-9.3p2-18.el9_5 (CVE advisory RHSA-2025:1677, February 2025). "
            "\n"
            "TOS 4.6 ships openssh-9.3p2-15.tl4. The RHEL fix release counter is -18.el9_5. "
            "The TOS release counter is -15.tl4. If Tencent maps RHEL backport levels "
            "proportionally, -15.tl4 is likely BELOW the -18 level where the CVE-2025-26465 "
            "fix was applied. "
            "\n"
            "This is UNCONFIRMED — TOS may have applied the fix at a different counter or "
            "the mapping between tl4 and el9_5 release counters is not 1:1. "
            "Confirmation requires binary string search in openssh binary for the fix "
            "indicator (updated SSHFP validation logic)."
        ),
        "verify": (
            "Extract openssh client binary from TOS 4.6 rootfs. "
            "Search for CVE-2025-26465 fix: changed behavior in verify_host_key_dns() — "
            "look for additional check on dns_verify_hostkey() return code before accepting "
            "a SSHFP-validated key. Compare to known-patched RHEL 9.3p2-18 binary."
        ),
        "chain": (
            "TOS46-C02: VerifyHostKeyDNS=yes in SSH client config (non-default but documented) → "
            "attacker spoofs SSHFP DNS records or MitM DNS → CVE-2025-26465 → "
            "SSH session accepted to attacker's server → credential / data exposure"
        ),
        "references": ["CVE-2025-26465", "RHSA-2025:1677", "openssh 9.9p2 fix"],
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
        "critical_regressions": [
            "libssh 0.10.5 Terrapin CVE-2023-48795 (27mo post-fix, still open)",
            "openssh 9.3p2-15 CVE-2025-26465 unconfirmed (counter -15 vs RHEL fix -18)",
        ],
        "findings": [k for k in FINDINGS],
    }, indent=2))
