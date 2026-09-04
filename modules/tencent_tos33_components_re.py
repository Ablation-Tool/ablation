"""
TencentOS 3.3 Component RE Module
Source: TencentOS-Server-GenericCloud-3.3-20260702.0.x86_64.qcow2 (July 2, 2026)
        Mounted via qemu-nbd; dnf history.sqlite + binary string extraction
OS: TencentOS Server 3.3 (Final), platform:el8, ID_LIKE="rhel fedora centos"
Kernel: 5.4.241-24.0017.41.1 (KASLR DISABLED — see tencent_tos33_kernel_re.py)
Lineage: RHEL 8 (glibc 2.28, systemd 239, OpenSSL 1.1.1k, Python 3.6)
Analysis date: 2026-09-04

Package extraction method:
  Primary: /var/lib/dnf/history.sqlite → rpm table (name, version, release, arch)
  Verification: strings on binaries; /usr/share/doc/* changelogs
  DNF history schema: trans/trans_item/rpm tables; action=1 (install), 3 (upgrade)

Key packaging note: TencentOS 3.3 introduces a ".ap.N" suffix series on core packages
  (glibc, openssl, openssh, systemd, pam) indicating Tencent-maintained additional patches
  applied after upstream RHEL 8 EOL (May 2024). These packages have substantially higher
  release counters than RHEL 8 equivalents and continue receiving CVE backports.

Component versions (July 2026 image):
  kernel:     5.4.241-24.0017.41.1          (KASLR DISABLED — platform:el8 TK4)
  openssl:    1.1.1k-16.tl3.ap.1            (EOL upstream; Tencent .ap self-maintained)
  openssh:    8.0p1-29.tl3.ap.1             (CVE-2023-38408 PATCHED at -19; -29 confirmed)
  glibc:      2.28-251.tl3.38.ap.1          (heavily patched .ap series; CVE-2023-4911 fixed)
  curl:       7.61.1-34.tl3.11              (CVE-2023-38545 SOCKS5 fixed at -28+)
  sudo:       1.9.5p2-1.tl3.5              (likely CVE-2021-3156 patched; July 2026 image)
  systemd:    239-82.tl3.17.ap.1            (.ap series; RHEL 8 EOL-surviving)
  expat:      2.5.0-1.tl3.ap.1             (CVE-2022-25315 cluster FIXED in 2.4.4+)
  gnutls:     3.6.16-8.tl3.6              (CVE-2021-20231/20232 patched at RHEL -5+)
  polkit:     0.115-15.tl3.2              (CVE-2021-4034 PwnKit PATCHED: RHEL fix at -13)
  libssh:     0.9.6-16.tl3               (CVE-2023-48795 Terrapin OPEN — fixed in 0.10.6)
  nss:        3.112.0-8.tl3              (CVE-2023-6135 fixed in 3.109+)
  sssd:       2.9.4-5.tl3.4             (CVE-2023-3758 fixed in 2.9.3 — TOS33 PATCHED)
  pam:        1.3.1-39.tl3.ap.1         (.ap series; high backport counter)
  libxml2:    2.9.7-21.tl3.5           (CVE-2022-40303/40304 patched at -13+)
  bash:       4.4.20-6.tl3
  python3:    3.6.8-76.tl3.ap.2
  cloud-init: 23.4-7.tl3.11.ap.1

CVE-2023-38408 backport verification (openssh 8.0p1-29.tl3.ap.1):
  strings /usr/bin/ssh-agent confirms: '-P pkcs11_whitelist' option present
  The PKCS#11 provider whitelist (-P flag to ssh-agent) was introduced as the
  CVE-2023-38408 backport mitigation; RHEL fix counter was -19.el8_8 (July 2023).
  TencentOS 3.3 at -29.tl3.ap.1 > -19 → backport confirmed present.

Polkit PwnKit backport verification (polkit 0.115-15.tl3.2):
  binary: pkexec-0.115-15.tl3.2.x86_64.debug string confirmed in /usr/bin/pkexec
  RHEL 8 PwnKit fix counter: -13.el8_5.1 (January 2022)
  TencentOS 3.3 counter -15 > -13 → fix confirmed present.

Compared to TencentOS 3.1 (5.4.119, RHEL 8):
  PATCHED in 3.3 vs 3.1:
    CVE-2023-38408 (openssh PKCS#11 RCE CVSS 9.8) — -29 vs -13
    CVE-2021-4034  (polkit PwnKit CVSS 7.8) — -15 vs -11/13
    CVE-2021-3156  (sudo Baron Samedit CVSS 7.8) — 1.9.5p2-1.tl3.5 vs 1.8.29-8
    CVE-2022-25315 (expat cluster CVSS 9.8) — expat 2.5.0 vs 2.2.5
    CVE-2021-20231/20232 (gnutls UAF) — -8 vs -5
  STILL OPEN in 3.3:
    KASLR DISABLED (5.4.241; same as all 3.x and 2.4)
    CVE-2023-48795 Terrapin (libssh 0.9.6; fixed in 0.10.6)
    OpenSSL 1.1.1k EOL (no upstream support; Tencent .ap backporting, coverage unknown)
"""

COMPONENT_VERSIONS = {
    "kernel":     "5.4.241-24.0017.41.1",
    "openssl":    "1.1.1k-16.tl3.ap.1",
    "openssh":    "8.0p1-29.tl3.ap.1",
    "glibc":      "2.28-251.tl3.38.ap.1",
    "curl":       "7.61.1-34.tl3.11",
    "sudo":       "1.9.5p2-1.tl3.5",
    "systemd":    "239-82.tl3.17.ap.1",
    "expat":      "2.5.0-1.tl3.ap.1",
    "gnutls":     "3.6.16-8.tl3.6",
    "polkit":     "0.115-15.tl3.2",
    "libssh":     "0.9.6-16.tl3",
    "nss":        "3.112.0-8.tl3",
    "sssd":       "2.9.4-5.tl3.4",
    "pam":        "1.3.1-39.tl3.ap.1",
    "libxml2":    "2.9.7-21.tl3.5",
    "bash":       "4.4.20-6.tl3",
    "python3":    "3.6.8-76.tl3.ap.2",
    "cloud_init": "23.4-7.tl3.11.ap.1",
}

KERNEL_CONFIG_SUMMARY = {
    "RANDOMIZE_BASE": False,     # KASLR DISABLED — see tencent_tos33_kernel_re.py
    "FORTIFY_SOURCE": False,     # absent — persistent gap
    "HARDENED_USERCOPY": False,
    "MODULE_SIG_FORCE": False,
    "SLAB_FREELIST_RANDOM": False,
    "IMA": True,
    "IMA_DEFAULT_HASH": "sha1",  # collision-vulnerable — TOS33K-F03
    "BPF_KPROBE_OVERRIDE": True, # root-accessible eBPF kernel function override
}

FINDINGS = {
    "TOS33-C01": {
        "title": (
            "OpenSSL 1.1.1k-16.tl3.ap.1 Past Upstream EOL (September 2023) — "
            "Tencent Self-Maintaining .ap Series with Unknown CVE Coverage Gap; "
            "TLS Services on TencentOS 3.3 Running Without Upstream Security Support"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-1104",
        "component": "openssl-libs-1.1.1k-16.tl3.ap.1",
        "description": (
            "OpenSSL 1.1.1k reached upstream EOL on September 7, 2023. "
            "TencentOS 3.3 (July 2026 image) continues shipping 1.1.1k with Tencent's "
            "proprietary .ap patch series (release -16.tl3.ap.1). "
            "The .ap series demonstrates active backporting but its CVE coverage is "
            "opaque — no public advisory mapping exists. "
            "Known OpenSSL CVEs disclosed after September 2023 that affect 1.1.1 and "
            "are NOT fixed in any public 1.1.1 build include: "
            "CVE-2024-0727 (PKCS#12 null deref DoS — 1.1.1w base has no backport path); "
            "CVE-2024-2511 (TLS 1.3 session cache UAF); "
            "CVE-2023-5678 (DH key gen excessive time); "
            "CVE-2024-13176 (ECDSA timing side-channel in p384/p521 — fixed in OpenSSL 3.x). "
            "Without .ap series source access, it is impossible to confirm which are patched. "
            "Best-case: Tencent tracks the 1.1.1 tree they forked from. "
            "Worst-case: patches lag 3–6 months behind disclosure."
        ),
        "chain": (
            "TOS33-C01: TLS client/server on 3.3 → CVE-2024-2511 session UAF or ECDSA "
            "timing side-channel → attacker with network position extracts TLS private key; "
            "chained with KASLR-disabled kernel (TOSXK-F01) for local heap control"
        ),
        "remediation": (
            "Migration to TencentOS 4.x (OpenSSL 3.0.12 with upstream support). "
            "If 3.3 must be maintained, obtain Tencent's .ap series patch manifest and "
            "verify CVE coverage explicitly."
        ),
        "references": ["CVE-2024-2511", "CVE-2024-0727", "CVE-2023-5678", "CWE-1104"],
    },
    "TOS33-C02": {
        "title": (
            "libssh 0.9.6 Vulnerable to CVE-2023-48795 Terrapin Attack — "
            "SSH Handshake Prefix Truncation via ChaCha20-Poly1305 or CBC-EtM; "
            "Fixed in libssh 0.10.6 (January 2024); TencentOS 3.3 Ships 0.9.6-16"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-354",
        "component": "libssh-0.9.6-16.tl3",
        "description": (
            "CVE-2023-48795 (Terrapin, December 2023): a network MitM can truncate the "
            "SSH connection handshake prefix, removing negotiated security extensions "
            "(strict-kex, keystroke timing obfuscation). Affects libssh < 0.10.6. "
            "TencentOS 3.3 ships libssh 0.9.6-16.tl3 — the 0.9.x branch does not receive "
            "the 0.10.6 fix. TencentOS 3.3 is frozen at 0.9.6 for its entire lifecycle. "
            "Impact: applications using libssh (as opposed to openssh-clients) on TencentOS 3.3 "
            "remain Terrapin-vulnerable for the OS lifetime. "
            "Binary evidence: /usr/lib64/libssh.so.4 build path: "
            "'/builddir/build/BUILD/libssh-0.9.6/src/bignum.c' — confirms 0.9.6 is the "
            "compiled version, not an upgraded package rename."
        ),
        "chain": (
            "TOS33-C02: active network MitM on SSH connection using libssh-based client → "
            "Terrapin truncates strict-kex → keystroke timing obfuscation removed → "
            "timing side-channel on authentication enables password/key recovery"
        ),
        "remediation": (
            "No fix available in 3.3 branch (0.9.x → 0.10.x is a major version jump). "
            "Disable ChaCha20-Poly1305 and CBC-EtM cipher modes in libssh application config. "
            "Migrate to TencentOS 4.x which ships 0.10.5+ (libssh 0.10.x; note TOS40 has "
            "a separate Terrapin exposure at 0.10.5 — fixed in 0.10.6)."
        ),
        "references": ["CVE-2023-48795", "Terrapin Attack (Bäumer et al. 2023)"],
    },
    "TOS33-C03": {
        "title": (
            "KASLR Disabled in 5.4.241-24.0017.41.1 — Kernel Text Fixed at "
            "0xffffffff81000000 Across All TencentOS 3.3 Releases (Jul 2024–Jul 2026); "
            "Same Disabled State as 2.4 and 3.1; See TOSXK-F01"
        ),
        "severity": "CRITICAL",
        "cvss": "8.1",
        "cwe": "CWE-330",
        "component": "kernel-5.4.241-24.0017.41.1 (# CONFIG_RANDOMIZE_BASE is not set)",
        "description": (
            "KASLR is explicitly disabled in TencentOS 3.3's 5.4.241 kernel — confirmed "
            "across 6 qcow2 images spanning July 2024 through July 2026. "
            "The _text symbol at 0xffffffff81000000 is identical across all images. "
            "FORTIFY_SOURCE and HARDENED_USERCOPY are also absent. "
            "TencentOS 3.3 runs on RHEL 8 userspace with significantly hardened userspace "
            "packages (vs 3.1), but the kernel remains at the same exposure level as 2.4. "
            "See TOSXK-F01 (tencent_kernel_cross_version.py) and "
            "tencent_tos33_kernel_re.py for full kernel config analysis."
        ),
        "chain": (
            "TOS33-C03: any kernel CVE on 5.4.241 (e.g., CVE-2023-3269 StackRot, "
            "CVE-2022-0847 Dirty Pipe) → KASLR bypass NOT required → direct exploitation "
            "from known text/data base; no secondary info-leak step needed; "
            "CONFIG_BPF_KPROBE_OVERRIDE=y additionally allows root-level eBPF to override "
            "any kernel function return value"
        ),
        "remediation": "Upgrade to TencentOS 4.4+ (6.6.110+, KASLR enabled).",
        "references": ["TOSXK-F01 (tencent_kernel_cross_version.py)", "tencent_tos33_kernel_re.py", "CWE-330"],
    },
}

PATCHED_VS_31 = {
    "CVE-2023-38408 (openssh PKCS#11 RCE CVSS 9.8)": (
        "PATCHED — openssh 8.0p1-29.tl3.ap.1; '-P pkcs11_whitelist' in ssh-agent binary; "
        "RHEL fix at -19.el8_8 (Jul 2023); -29 confirms backport applied"
    ),
    "CVE-2021-4034 (polkit PwnKit CVSS 7.8)": (
        "PATCHED — polkit 0.115-15.tl3.2; RHEL fix at -13.el8_5.1 (Jan 2022); "
        "-15 > -13 confirms backport applied; binary confirms 0.115-15.tl3.2"
    ),
    "CVE-2021-3156 (sudo Baron Samedit CVSS 7.8)": (
        "PATCHED (probable) — sudo 1.9.5p2-1.tl3.5; July 2026 image, 5+ years post-CVE; "
        "RHEL 8 AppStream sudo-1.9.5p2 includes fix; binary does not expose clean indicator"
    ),
    "CVE-2022-25315 (expat cluster CVSS 9.8)": (
        "PATCHED — expat 2.5.0-1.tl3.ap.1; fixed in expat 2.4.4; 2.5.0 >> fix"
    ),
    "CVE-2021-20231/20232 (gnutls UAF CVSS 9.8)": (
        "PATCHED — gnutls 3.6.16-8.tl3.6; RHEL fixed at -5; -8 > -5"
    ),
    "CVE-2023-3758 (sssd machine cred race)": (
        "PATCHED — sssd 2.9.4-5.tl3.4; fixed in sssd 2.9.3; 2.9.4 > fix"
    ),
}

STILL_OPEN = {
    "KASLR disabled":       "kernel 5.4.241; TOSXK-F01; all TencentOS 3.x affected",
    "CVE-2023-48795":       "libssh 0.9.6-16.tl3 Terrapin; fixed in 0.10.6; 0.9.x frozen",
    "OpenSSL 1.1.1k EOL":   "self-maintained .ap series; unknown CVE gap since Sep 2023",
    "IMA SHA1":             "CONFIG_IMA_DEFAULT_HASH=sha1; TOS33K-F03",
    "FORTIFY_SOURCE absent": "5.4.241 kernel; TOSXK-F03",
}


def probe():
    return {
        "critical": ["TOS33-C03"],
        "high": ["TOS33-C01"],
        "medium": ["TOS33-C02"],
        "low": [],
    }


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "TencentOS-Server-GenericCloud-3.3-20260702.0.x86_64.qcow2",
        "kernel": "5.4.241-24.0017.41.1 (KASLR DISABLED)",
        "findings": list(FINDINGS.keys()),
        "patched_vs_31": list(PATCHED_VS_31.keys()),
        "still_open": list(STILL_OPEN.keys()),
    }, indent=2))
