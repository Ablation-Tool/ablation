"""
OpenCloudOS 8.10 / 9.4 Component RE Module
Source: SPDX SBOMs from /media/cowboy/research/tencentos/sbom/
  OCO-8.10: OpenCloudOS-Container-Minimal-8.10-20241213.0.x86_64.tar.xz.spdx.json (Dec 2024)
  OCO-9.4:  OpenCloudOS-GenericCloud-9.4-20250904.0.x86_64.qcow2.spdx.json (Sep 2025)
Analysis date: 2026-09-04

SBOM format note: OpenCloudOS SBOMs use SPDX format with upstream git source references,
not installed RPM versions with dist tags. Version data is from upstream project sources.
Precise build/patch level (release counter, backport presence) cannot be confirmed without
container image extraction. CVE analysis is conservative: unpatched unless confirmed patched.

OpenCloudOS project context:
  OpenCloudOS is a Linux OS community founded by Tencent, Kingsoft, ARM, OPPO, and others.
  It shares lineage with TencentOS Server (same kernel base: TencentLinux TK4 5.4.119).
  OCO 8.10 = RHEL 8 userspace equivalent; OCO 9.4 = RHEL 9 userspace equivalent.
  Both use the OpenCloudOS Kernel from https://gitee.com/OpenCloudOS/OpenCloudOS-Kernel

Critical finding: OCO 9.4 kernel is 5.4.119 (tencent/tencentos-kernel: 5.4.119)
  Source: OCO 9.4 SBOM packages entry 'tencent/tencentos-kernel: 5.4.119'
  This is the TencentLinux Kernel 4.0 (TK4) — the same kernel as TencentOS 2.4 (2020).
  KASLR is DISABLED in all 5.4.119 TK4 builds (confirmed across TencentOS 2.4, 3.1, OpenCloudOS).
  OCO 9.4 (September 2025) ships RHEL 9-equivalent userspace on a 2020-era kernel
  with KASLR disabled and no FORTIFY_SOURCE. The userspace security improvements
  (glibc 2.38, OpenSSL 3.x, openssh 9.7) are undermined by the frozen kernel.

OCO 8.10 version profile (SBOM upstream references, Dec 2024):
  openssl:  1.1.1k         (EOL Sep 2023 upstream; OpenCloudOS may self-maintain)
  glibc:    2.28           (RHEL 8 baseline)
  openssh:  8.0/8.0p1      (CVE-2023-38408 PKCS#11 RCE — depends on build release counter)
  gnutls:   3.6.16         (CVE-2021-20231/20232 UAF — depends on release counter)
  curl:     7.61.1         (CVE-2023-38545 SOCKS5 — depends on release counter)
  expat:    2.2.5          (CVE-2022-25315 cluster CVSS 9.8 — unpatched at 2.2.5 base)
  systemd:  239.50         (vs TencentOS 3.3's 239-82 — lower release counter)
  sudo:     1.9.5p2        (Baron Samedit CVE-2021-3156 — depends on backport)
  kernel:   5.4.119        (KASLR DISABLED; same as TencentOS 2.4/3.1/OpenCloudOS)

OCO 9.4 version profile (SBOM upstream references, Sep 2025):
  kernel:   5.4.119        (CONFIRMED: tencent/tencentos-kernel SBOM entry; KASLR disabled)
  openssl:  3.0.12 + 3.1.2 (3.1.x EOL Nov 11, 2023 — 3.1.2 is EOL if shipped)
  glibc:    2.38           (RHEL 9 baseline; Looney Tunables patched at 2.38-3+)
  openssh:  9.7 / 9.3p2   (9.7 = newer than TOS46's 9.3p2-16; CVE-2025-26465 status unclear)
  gnutls:   3.8.2          (same as TOS44; CVE-2021-20231/20232 patched)
  libssh:   0.10.5         (CVE-2023-48795 Terrapin — fixed in 0.10.6)
  curl:     8.4.0          (CVE-2023-38545 patched at 8.4.0 base)
  bind9:    9.11.37        (bind 9.11 EOL → should be 9.16+ or 9.18+)
  pam:      1.5.3          (same as TOS44)
  expat:    2.6.4          (RHEL 9 series; clean for 2.x CVE cluster)
"""

COMPONENT_VERSIONS_OCO_810 = {
    "openssl":    "1.1.1k",
    "glibc":      "2.28",
    "openssh":    "8.0p1",
    "gnutls":     "3.6.16",
    "curl":       "7.61.1",
    "expat":      "2.2.5",
    "systemd":    "239.50",
    "sudo":       "1.9.5p2",
    "pam":        "1.3.1",
    "kernel":     "5.4.119 (TK4, KASLR disabled)",
}

COMPONENT_VERSIONS_OCO_94 = {
    "kernel":    "5.4.119 (TK4; tencent/tencentos-kernel SBOM confirmed; KASLR disabled)",
    "openssl":   "3.0.12 + 3.1.2 (3.1.x branch EOL Nov 2023)",
    "glibc":     "2.38",
    "openssh":   "9.7 / 9.3p2",
    "gnutls":    "3.8.2",
    "libssh":    "0.10.5",
    "curl":      "8.4.0",
    "bind9":     "9.11.37",
    "pam":       "1.5.3",
    "expat":     "2.6.4",
}

FINDINGS = {
    "OCO-C01": {
        "title": (
            "OpenCloudOS 9.4 (Sep 2025) Runs 5.4.119 TK4 Kernel — "
            "RHEL 9 Userspace (glibc 2.38, OpenSSL 3.x) on 2020-Era Kernel with KASLR Disabled; "
            "Same Kernel Attack Surface as TencentOS 2.4 (2020)"
        ),
        "severity": "CRITICAL",
        "cvss": "8.1",
        "cwe": "CWE-330",
        "component": (
            "tencent/tencentos-kernel: 5.4.119 (from OCO 9.4 SPDX SBOM); "
            "CONFIG_RANDOMIZE_BASE not set in all known TK4 5.4.119 builds"
        ),
        "description": (
            "OpenCloudOS 9.4 (September 2025) includes `tencent/tencentos-kernel: 5.4.119` "
            "as a SBOM package reference. This is the TencentLinux Kernel 4.0 (TK4), confirmed "
            "in TencentOS 2.4 (2020), TencentOS 3.1 (2021), and documented in "
            "tencent_opencloudos_kernel_re.py. "
            "All known TK4 5.4.119 builds have KASLR explicitly disabled "
            "(# CONFIG_RANDOMIZE_BASE is not set). "
            "OpenCloudOS 9.4 presents a mixed security posture: "
            "RHEL 9-level userspace (glibc 2.38 with Looney Tunables patched, OpenSSL 3.x, "
            "openssh 9.x) BUT the kernel lacks KASLR, FORTIFY_SOURCE, HARDENED_USERCOPY, and "
            "carries the ttools world-writable ptrace bypass device (/dev/ttools 0666). "
            "Any kernel CVE on 5.4.119 (a 2020 kernel now 5+ years old at OCO 9.4's release) "
            "is directly exploitable without an ASLR bypass prerequisite. "
            "CVE count for 5.4.119 at Sep 2025: hundreds of kernel CVEs disclosed since 2020."
        ),
        "chain": (
            "OCO-C01: any 5.4.119 kernel CVE (e.g., StackRot CVE-2023-3269, Dirty Pipe "
            "CVE-2022-0847, netfilter CVE-2023-32233) → text/data base at 0xffffffff81000000 "
            "→ direct exploitation without KASLR bypass; "
            "ttools /dev/ttools 0666 → malware self-protects from forensic analysis; "
            "ptrace_pre_hook at known VA → kernel write primitive → ptrace redirect (see TTLS-F03)"
        ),
        "remediation": (
            "Upgrade OpenCloudOS 9.x to a kernel >= 6.6 with CONFIG_RANDOMIZE_BASE=y. "
            "The TK4 5.4.119 kernel is unsuitable for a 2025 OS release given its age "
            "and the accumulated CVE backlog. Enable FORTIFY_SOURCE and HARDENED_USERCOPY."
        ),
        "references": [
            "tencent_opencloudos_kernel_re.py",
            "tencent_kernel_cross_version.py TOSXK-F01",
            "tencent_ttools_kernel_re.py TTLS-F03",
            "CWE-330",
        ],
    },
    "OCO-C02": {
        "title": (
            "OpenCloudOS 8.10 expat 2.2.5 — CVE-2022-25315 Cluster CVSS 9.8 Unpatched; "
            "Integer Overflow in expat 2.2.5 Base (Fixed in 2.4.4); "
            "All Components Parsing XML on OCO 8.10 Exposed"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-190",
        "component": "expat-2.2.5 (OCO 8.10; SBOM source: expat/expat: 2.2.5)",
        "description": (
            "OpenCloudOS 8.10 ships expat 2.2.5, which is in the affected range for "
            "CVE-2022-25315 (storeAtts integer overflow CVSS 9.8), CVE-2022-25235 "
            "(UTF-8 encoding validation bypass), CVE-2022-25236 (namespace separator bypass). "
            "These were fixed in expat 2.4.4 (February 2022). "
            "The OCO 8.10 SBOM shows two expat versions: 2.2.5 AND 2.6.2 — suggesting "
            "a higher version may be installed alongside (or as a replacement). "
            "If 2.2.5 is the installed libexpat (not 2.6.2), the full CVE cluster applies. "
            "Context: TencentOS 3.1 (same RHEL 8 lineage) shipped expat-2.2.5-9.tl3.1 which "
            "had CVE backports; OCO 8.10's packaging status is unknown from SBOM alone."
        ),
        "chain": (
            "OCO-C02: attacker-supplied XML via any expat consumer (rpm, systemd, curl, dbus) → "
            "CVE-2022-25315 integer overflow → heap overflow → arbitrary code exec in parser process"
        ),
        "remediation": "Verify installed expat version. If 2.2.5 base without backports, update.",
        "references": ["CVE-2022-25315", "CVE-2022-25235", "CVE-2022-25236"],
    },
    "OCO-C03": {
        "title": (
            "OpenCloudOS 9.4 libssh 0.10.5 — CVE-2023-48795 Terrapin Attack Open; "
            "Identical Exposure to TencentOS 4.0 (TOS40-C02); "
            "Fixed in libssh 0.10.6 (January 2024)"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-354",
        "component": "libssh-0.10.5 (OCO 9.4; SBOM source: projects/libssh: 0.10.5)",
        "description": (
            "OCO 9.4 ships libssh 0.10.5, vulnerable to CVE-2023-48795 (Terrapin). "
            "See TOS40-C02 (tencent_os40_components_re.py) for full analysis — identical exposure. "
            "OpenCloudOS 9.4 is released in September 2025, 20 months after the Terrapin "
            "disclosure (December 2023) and 20 months after the fix (libssh 0.10.6, January 2024). "
            "The lack of 0.10.6 update in a Sep 2025 release represents an active decision "
            "to ship a known-vulnerable libssh version."
        ),
        "remediation": "Update libssh to 0.10.6+ or enforce cipher policy excluding ChaCha20-Poly1305.",
        "references": ["CVE-2023-48795", "TOS40-C02 (tencent_os40_components_re.py)"],
    },
    "OCO-C04": {
        "title": (
            "OpenCloudOS 9.4 bind9 9.11.37 — EOL Branch; "
            "ISC BIND 9.11 End-of-Life May 2021; "
            "Multiple CVEs Disclosed After EOL Without Upstream Backport Path"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-1104",
        "component": "bind9-9.11.37 (OCO 9.4; SBOM source: isc-projects/bind9: 9.11.37)",
        "description": (
            "ISC BIND 9.11 reached End-of-Life in May 2021. "
            "OCO 9.4 (September 2025) ships bind9 9.11.37 — a version 4+ years past its EOL date. "
            "BIND CVEs disclosed after May 2021 that affect the 9.11 branch and have no "
            "upstream backport: "
            "CVE-2022-3094 (SERVFAIL loop DoS); "
            "CVE-2023-3341 (assertion failure on zone transfer); "
            "CVE-2023-4236 (RRSIG cache DoS); "
            "CVE-2024-1975 (DNSSEC SIG(0) assertion DoS). "
            "Without upstream patches, OpenCloudOS 9.4's BIND server-facing exposure is "
            "unmitigated for all post-EOL CVEs. "
            "RHEL 9 typically ships BIND 9.16 (LTS) or 9.18 (stable). "
            "OCO's use of 9.11 is a significant EOL deviation even for a RHEL 9 derivative."
        ),
        "chain": (
            "OCO-C04: exposed BIND on OCO 9.4 → CVE-2023-3341 assertion failure via zone transfer "
            "→ named process crash → DNS denial of service; "
            "or CVE-2024-1975 DNSSEC SIGZERO processing → cache poisoning window"
        ),
        "remediation": "Upgrade to BIND 9.18 (current stable) or 9.16 (LTS, EOL Jun 2023) minimum.",
        "references": ["CVE-2022-3094", "CVE-2023-3341", "CVE-2024-1975", "ISC BIND 9.11 EOL May 2021"],
    },
}

COMPARISON = {
    "oco_810_vs_tos31": {
        "kernel":    "5.4.119 (identical — same TK4 base; KASLR disabled)",
        "openssl":   "1.1.1k (OCO 8.10 = TOS31 base; backport level unknown)",
        "openssh":   "8.0p1 (OCO 8.10 = TOS31; CVE-2023-38408 status depends on release counter)",
        "expat":     "2.2.5 (OCO 8.10 base = TOS31; TOS31 had CVE backports to -9.tl3.1)",
        "systemd":   "239.50 (OCO 8.10) vs 239-58.tl3 (TOS31 base) — slightly lower counter",
    },
    "oco_94_vs_tos44": {
        "kernel":    "5.4.119 TK4 (OCO 9.4) vs 6.6.110 (TOS44) — OCO has OLDER kernel, KASLR disabled",
        "openssl":   "3.x (OCO 9.4) vs 3.0.12-18 (TOS44) — similar base",
        "openssh":   "9.7 (OCO 9.4 SBOM) vs 9.3p2-15 (TOS44) — OCO may have newer upstream base",
        "libssh":    "0.10.5 (both OCO 9.4 and TOS40 — same Terrapin exposure)",
        "glibc":     "2.38 (OCO 9.4) vs 2.38-46 (TOS44) — same base",
    },
}


def probe():
    return {
        "critical": ["OCO-C01", "OCO-C02"],
        "high": ["OCO-C04"],
        "medium": ["OCO-C03"],
    }


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "oco_810_source": "OpenCloudOS-Container-Minimal-8.10-20241213.0.x86_64",
        "oco_94_source":  "OpenCloudOS-GenericCloud-9.4-20250904.0.x86_64",
        "critical_finding": "OCO 9.4 kernel=5.4.119 TK4 (KASLR disabled) on RHEL9 userspace",
        "findings": list(FINDINGS.keys()),
    }, indent=2))
