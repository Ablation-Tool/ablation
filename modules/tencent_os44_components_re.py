"""
TencentOS 4.4 Component RE Module
Source: TencentOS-Server-GenericCloud-4.4-20260126.0.x86_64.qcow2 (January 26, 2026)
        Mounted via qemu-nbd; RPM SQLite rpmdb.sqlite decoded (419 packages)
OS: TencentOS Server 4.4 (TENCENTOS_UPDATE_ID=4, platform:tl4)
Kernel: 6.6.110-42.4.tl4.x86_64 (KASLR ENABLED — confirmed via CONFIG_RANDOMIZE_BASE=y)
Lineage: RHEL 9 (glibc 2.38, systemd 255, OpenSSL 3.0.12, Python 3.11)
Analysis date: 2026-09-04

Kernel config confirmed (from /boot/config-6.6.110-42.4.tl4.x86_64):
  CONFIG_RANDOMIZE_BASE=y        — KASLR ENABLED (fixed in 4.4; was disabled through 4.2)
  # CONFIG_FORTIFY_SOURCE is not set   — persistent gap (same as all 2.4–4.2)
  # CONFIG_HARDENED_USERCOPY is not set — persistent gap
  # CONFIG_MODULE_SIG_FORCE is not set — optional enforcement
  # CONFIG_SLAB_FREELIST_RANDOM is not set — persistent gap
  # CONFIG_SLAB_FREELIST_HARDENED is not set — persistent gap
  CONFIG_IMA_DEFAULT_HASH="sha1"  — SHA1, collision-vulnerable (same as 3.3)
  CONFIG_BPF_KPROBE_OVERRIDE=y    — BPF function override enabled

System.map: _text = 0xffffffff81000000 (compile-time base; runtime randomized by KASLR)

Component versions (Jan 2026 image):
  kernel:    6.6.110-42.4.tl4
  openssl:   3.0.12-18.tl4.4     (CVE-2024-13176 ECDSA timing patched; pre-4.6's -27)
  openssh:   9.3p2-15.tl4        (CVE-2025-26465 VerifyHostKeyDNS MitM — fixed at -16)
  glibc:     2.38-46.tl4         (active backporting; vs 4.2's -25)
  curl:      8.4.0-14.tl4        (vs 4.2's -9; multiple CVE patches applied)
  sudo:      1.9.15p5-5.tl4      (SUID confirmed; vs 4.2's -1)
  systemd:   255-14.tl4.ap.6     (vs 4.2's 255-13)
  expat:     2.6.4-4.tl4         (vs 4.2's 2.6.4-1)
  gnutls:    3.8.2-11.tl4        (vs 4.2's 3.8.2-6)
  polkit:    123-5.tl4           (pkexec SUID confirmed)
  python3:   3.11.6-28.tl4       (vs 4.2's 3.11.6-14)
  cloud-init: 23.2.1-12.tl4

Comparison to 4.2 (Dec 2024) and 4.6 (Aug 2026):
  openssh:   4.2=-15, 4.4=-15 (same!), 4.6=-16 (CVE-2025-26465 fixed)
  openssl:   4.2=-15, 4.4=-18.tl4.4, 4.6=-27 (3 years of patches ahead)
  glibc:     4.2=-25, 4.4=-46, 4.6=-49.tl4.2

Primary finding: openssh 9.3p2-15 in 4.4 is the same as 4.2; CVE-2025-26465 NOT patched.
"""

COMPONENT_VERSIONS = {
    "kernel":     "6.6.110-42.4.tl4",
    "openssl":    "3.0.12-18.tl4.4",
    "openssh":    "9.3p2-15.tl4",
    "glibc":      "2.38-46.tl4",
    "curl":       "8.4.0-14.tl4",
    "sudo":       "1.9.15p5-5.tl4",
    "systemd":    "255-14.tl4.ap.6",
    "expat":      "2.6.4-4.tl4",
    "gnutls":     "3.8.2-11.tl4",
    "polkit":     "123-5.tl4",
    "python3":    "3.11.6-28.tl4",
    "cloud_init": "23.2.1-12.tl4",
}

KERNEL_CONFIG = {
    "RANDOMIZE_BASE": True,    # KASLR enabled — confirmed
    "FORTIFY_SOURCE": False,   # absent — persistent gap
    "HARDENED_USERCOPY": False,
    "MODULE_SIG": True,
    "MODULE_SIG_FORCE": False,
    "SLAB_FREELIST_RANDOM": False,
    "SLAB_FREELIST_HARDENED": False,
    "IMA": True,
    "IMA_DEFAULT_HASH": "sha1",
    "BPF_KPROBE_OVERRIDE": True,
}

FINDINGS = {
    "TOS44-C01": {
        "title": (
            "openssh 9.3p2-15 Present in TencentOS 4.4 January 2026 — "
            "CVE-2025-26465 VerifyHostKeyDNS MitM Not Patched (Fixed at -16); "
            "Attacker Can Impersonate Any SSH Server When VerifyHostKeyDNS=yes"
        ),
        "severity": "HIGH",
        "cvss": "6.8",
        "cwe": "CWE-297",
        "component": "openssh-9.3p2-15.tl4 (same as TencentOS 4.2 Dec 2024 image)",
        "description": (
            "CVE-2025-26465: when OpenSSH client is configured with VerifyHostKeyDNS=yes, "
            "a network attacker can present a crafted SSHFP DNS record to satisfy the "
            "host key verification check with an untrusted key. The fix (introduced upstream "
            "and backported to 9.3p2-16.tl4 in TencentOS 4.6) adds a warning/rejection "
            "path when VerifyHostKeyDNS returns a match against a non-trusted key. "
            "TencentOS 4.4 ships -15, one release before the fix. "
            "VerifyHostKeyDNS is not the default, but cloud automation tooling commonly "
            "sets it for hostname-based SSH fingerprint verification."
        ),
        "binary_evidence": (
            "strings /usr/bin/ssh confirms 'found %d secure fingerprints in DNS' and "
            "'found %d insecure fingerprints in DNS' — VerifyHostKeyDNS code paths present. "
            "Lack of the rejection logic for untrusted keys is the unfixed condition."
        ),
        "chain": (
            "TOS44-C01: attacker MitM on DNS → responds to SSHFP query with attacker's key → "
            "client with VerifyHostKeyDNS=yes accepts attacker's host key → SSH session MitM; "
            "Applicable to any TencentOS 4.4 host using VerifyHostKeyDNS (common in Tencent Cloud VMs)"
        ),
        "remediation": "Update openssh to 9.3p2-16.tl4+ (available in 4.6 branch). Set VerifyHostKeyDNS=no until patched.",
        "references": ["CVE-2025-26465", "TCS46-P03 (tencent_os46_components_re.py)"],
    },
    "TOS44-C02": {
        "title": (
            "FORTIFY_SOURCE and HARDENED_USERCOPY Absent in 6.6.110-42.4 — "
            "Persistent Hardening Gap Continues Into 4.4 Despite KASLR Fix; "
            "Same Configuration as All Pre-4.4 Versions for These Mitigations"
        ),
        "severity": "HIGH",
        "cvss": "7.0",
        "cwe": "CWE-120",
        "component": "config-6.6.110-42.4.tl4.x86_64: # CONFIG_FORTIFY_SOURCE is not set",
        "description": (
            "TencentOS 4.4 enabled KASLR (CONFIG_RANDOMIZE_BASE=y) but left FORTIFY_SOURCE "
            "and HARDENED_USERCOPY disabled — the same persistent gap documented in "
            "TOSXK-F03 (tencent_kernel_cross_version.py) across 2.4, 3.3, and 4.2. "
            "FORTIFY_SOURCE adds compile-time and runtime bounds checking on libc string/memory "
            "functions; HARDENED_USERCOPY adds range validation on user-to-kernel copy operations. "
            "Without these, any buffer overflow in the kernel has no inline detection. "
            "With KASLR now enabled, exploitation requires an additional ASLR bypass step, "
            "but FORTIFY_SOURCE absence removes the detection layer that would trip on overflow "
            "before the attacker reaches the return address."
        ),
        "chain": (
            "TOS44-C02 + any kernel buffer overflow CVE on 6.6.110: "
            "overflow → no detection → controlled corruption; "
            "attacker must defeat KASLR (new requirement vs 4.2) but has no secondary mitigation; "
            "SLAB_FREELIST_RANDOM also absent — heap spray easier without randomized slab layout"
        ),
        "remediation": "Enable CONFIG_FORTIFY_SOURCE=y, CONFIG_HARDENED_USERCOPY=y, CONFIG_SLAB_FREELIST_RANDOM=y in next kernel build.",
        "references": ["TOSXK-F03 (tencent_kernel_cross_version.py)", "CWE-120"],
    },
    "TOS44-C03": {
        "title": (
            "IMA Configured with SHA1 Default Hash in 6.6.110 — "
            "CONFIG_IMA_DEFAULT_HASH='sha1'; SHA1 Collision-Vulnerable; "
            "Same SHA1 Configuration as TencentOS 3.3 (5.4.241)"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-327",
        "component": "config-6.6.110-42.4.tl4.x86_64: CONFIG_IMA_DEFAULT_HASH='sha1'",
        "description": (
            "TencentOS 4.4 enables IMA with SHA1 as the default hash algorithm — "
            "identical to TencentOS 3.3 (TOS33K-F03). SHA1 chosen-prefix collisions "
            "are achievable (SHAttered 2017) for well-funded adversaries, allowing "
            "IMA measurement forgery: craft a malicious file that produces the same SHA1 "
            "as a trusted file, bypassing IMA appraisal. "
            "TencentOS 4.6 configuration was not checked for SHA1 → SHA256 upgrade; "
            "4.4 confirms SHA1 is still the default as of kernel 6.6.110."
        ),
        "remediation": "Set CONFIG_IMA_DEFAULT_HASH='sha256' (or sha384/sha512). Rebuild kernel or apply sysctl override.",
        "references": ["TOS33K-F03 (tencent_tos33_kernel_re.py)", "CVE-2022-21449 parallel (SHA1 dual-broken)", "SHAttered 2017"],
    },
}

DELTA_FROM_42_DEC2024 = {
    "KASLR": "ENABLED in 4.4 (was DISABLED in 4.2 through 6.6.58)",
    "openssh": "9.3p2-15 (same as 4.2-15; CVE-2025-26465 still open — fixed at -16 in 4.6)",
    "openssl": "3.0.12-18.tl4.4 (was -15 in 4.2; CVE-2024-13176 ECDSA timing patched at -17)",
    "glibc": "2.38-46.tl4 (was -25 in 4.2; active backporting)",
    "gnutls": "3.8.2-11 (was -6 in 4.2; 5 additional release counters of patches)",
    "FORTIFY_SOURCE": "STILL ABSENT (same as 4.2)",
    "HARDENED_USERCOPY": "STILL ABSENT (same as 4.2)",
}

SUID_BINARIES = {
    "/usr/bin/sudo":   "219144 bytes, 1.9.15p5-5.tl4; no CVE-2021-3156 (1.9.x is clean)",
    "/usr/bin/pkexec": "31992 bytes, polkit 123-5.tl4; no CVE-2021-4034 (polkit 0.120+ baseline)",
}


def probe():
    return {
        "critical": [],
        "high": ["TOS44-C01", "TOS44-C02"],
        "medium": ["TOS44-C03"],
        "low": [],
    }


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "kernel": "6.6.110-42.4.tl4",
        "kaslr": True,
        "findings": list(FINDINGS.keys()),
        "delta_from_42": DELTA_FROM_42_DEC2024,
    }, indent=2))
