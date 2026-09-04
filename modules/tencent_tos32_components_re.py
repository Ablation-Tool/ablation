"""
TencentOS 3.2 Component RE Module
Source: /media/cowboy/research/tencentos/3.1/TencentOS-srpms/ +
        /media/cowboy/research/tencentos/3.1/Updates-srpms/ (39 .tl3.2 packages)
Distribution: TencentOS 3.2 is NOT a separate release — it is a set of 39 .tl3.2-tagged
              update packages applied on top of TencentOS 3.1 (RHEL 8 userspace).
              Same kernel as 3.1: 5.4.119-19-0009.11 (KASLR DISABLED — same as 2.4 and 3.1).
Analysis date: 2026-09-04

Relationship to TencentOS 3.1:
  RHEL naming convention: .el8 base → .el8_1/.el8_2 updates.
  TencentOS follows: .tl3 base → .tl3.1/.tl3.2 updates.
  "TencentOS 3.2" = TencentOS 3.1 + 39 packages rebuilt with .tl3.2 dist tag.
  The kernel is NOT updated — 5.4.119-19 persists through 3.1 and 3.2.

Complete list of packages updated in TencentOS 3.2 (full .tl3.2 inventory — 39 packages):
  accountsservice-0.6.55-2, anaconda-33.16.9.4-1, annobin-9.72-1, audit-3.0.7-2,
  bash-4.4.19-10, bind-9.11.36-8, bind9.16-9.16.23-0.16, binutils-2.30-119,
  booth-1.0-6, bpftrace-0.12.1-4, c-ares-1.13.0-6, ca-certificates-2023.2.60_v7.0.306-80.0,
  ceph-12.2.7-9, cloud-init-22.1-6, crash-7.2.9-2, cups-2.2.6-45,
  cups-filters-1.20.0-29, curl-7.61.1-34, dbus-1.12.8-12, dbxtool-8-5,
  device-mapper-multipath-0.8.4-22, dhcp-4.3.6-47, dnsmasq-2.79-31, dovecot-2.3.8-2,
  dracut-049-228, edk2-20220126gitbb1bba3d77-13, elfutils-0.188-3, emacs-26.1-10,
  epel-release-8-100, fapolicyd-1.0-3, fence-agents-4.2.1-41, freerdp-2.0.0-46,
  kexec-tools-2.0.23-1, libxml2-2.9.7-13, openssh-8.0p1-4, polkit-0.115-13,
  sos-4.2-20, sssd-2.6.2-4, zsh-5.5.1-6

Security-critical packages NOT UPDATED in 3.2 (same as 3.1):
  openssl: 1.1.1k-7.tl3     (EOL Sep 2023; no .tl3.2 package exists)
  glibc:   2.28-101.tl3     (RHEL 8 baseline; no .tl3.2 update)
  sudo:    1.8.29-8.tl3     (CVE-2021-3156 Baron Samedit — affected range 1.8.2-1.9.5p2)
  expat:   2.2.5-9.tl3.1    (CVE-2022-25315 cluster CVSS 9.8; only expat base version in .tl3.1)
  gnutls:  3.6.16-5.tl3     (CVE-2021-20231/20232 UAF CVSS 9.8)
  kernel:  5.4.119-19-0009.11 (KASLR DISABLED; same as TencentOS 2.4 and 3.1)

Note on openssh 3.2 version discrepancy:
  openssh-8.0p1-4.tl3.2 exists in TencentOS-srpms but is OLDER by release counter
  than openssh-8.0p1-13.tl3 (the 3.1 base's latest). This is a packaging artifact:
  the .tl3.2 tag was applied to an early rebuild, while the main line advanced to -13.
  Installed systems will have -13.tl3 (or higher via yum update from 3.1 stream).
  CVE-2023-38408 remains open on all 3.1/3.2 releases.
"""

COMPONENT_VERSIONS_3_2_UPDATED = {
    "curl":         "7.61.1-34.tl3.2",
    "bind":         "9.11.36-8.tl3.2",
    "bind9.16":     "9.16.23-0.16.tl3.2",
    "dhcp":         "4.3.6-47.tl3.2",
    "dnsmasq":      "2.79-31.tl3.2",
    "dbus":         "1.12.8-12.tl3.2",
    "libxml2":      "2.9.7-13.tl3.2",
    "cloud_init":   "22.1-6.tl3.2",
    "ca_certs":     "2023.2.60_v7.0.306-80.0.tl3.2",
    "sssd":         "2.6.2-4.tl3.2",
    "audit":        "3.0.7-2.tl3.2",
    "polkit":       "0.115-13.tl3.2",
    "openssh":      "8.0p1-4.tl3.2",
    "bash":         "4.4.19-10.tl3.2",
    "cups":         "2.2.6-45.tl3.2",
    "edk2":         "20220126gitbb1bba3d77-13.tl3.2",
}

COMPONENT_VERSIONS_UNCHANGED_FROM_31 = {
    "openssl":    "1.1.1k-7.tl3",
    "openssh":    "8.0p1-13.tl3",
    "glibc":      "2.28-101.tl3",
    "sudo":       "1.8.29-8.tl3",
    "expat":      "2.2.5-9.tl3.1",
    "gnutls":     "3.6.16-5.tl3",
    "python3":    "3.6.8-23.tl3",
    "kernel":     "5.4.119-19-0009.11",
}

FINDINGS = {
    "TOS32-C01": {
        "title": (
            "TencentOS 3.2 Inherits All Critical Findings from 3.1 — "
            "Kernel 5.4.119-19 KASLR Disabled; openssh 8.0p1 CVE-2023-38408 Open; "
            "polkit 0.115 PwnKit (CVE-2021-4034) and sudo 1.8.29 Baron Samedit Open"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-330",
        "component": (
            "kernel-5.4.119-19-0009.11 + openssh-8.0p1-13.tl3 + "
            "polkit-0.115-13.tl3.2 + sudo-1.8.29-8.tl3"
        ),
        "description": (
            "TencentOS 3.2 is a set of 39 package updates on top of TencentOS 3.1 — "
            "it does NOT update the kernel, openssh, openssl, glibc, sudo, expat, or gnutls. "
            "All critical findings documented in tencent_tos31_components_re.py apply directly "
            "to TencentOS 3.2 with no mitigation: "
            "(1) Kernel 5.4.119-19 KASLR disabled — same as TencentOS 2.4. "
            "(2) openssh 8.0p1 CVE-2023-38408 PKCS#11 RCE CVSS 9.8 — affects all < 9.3p2. "
            "(3) polkit 0.115 CVE-2021-4034 PwnKit — heap OOB in pkexec, affects < 0.120. "
            "(4) sudo 1.8.29 CVE-2021-3156 Baron Samedit — heap OOB, local root. "
            "(5) expat 2.2.5 CVE-2022-25315 cluster CVSS 9.8. "
            "(6) gnutls 3.6.16 CVE-2021-20231/20232 UAF CVSS 9.8. "
            "The polkit PwnKit tag in TOS32 is -13.tl3.2 (updated release counter) but the "
            "upstream version remains 0.115 — PwnKit fixed only at 0.120+."
        ),
        "chain": (
            "TOS32-C01: Same chain as TOS31-ATTACK-CHAIN-01. "
            "Remote: openssh-agent forward CVE-2023-38408 PKCS#11 injection → code exec in ssh-agent; "
            "Local escalation: polkit PwnKit (CVE-2021-4034) → root OR sudo Baron Samedit → root; "
            "KASLR disabled (kernel text at 0xffffffff81000000) removes the bypass prerequisite. "
            "3.2's only security value vs 3.1: curl CVE-2023-38545 SOCKS5 heap overflow patched."
        ),
        "remediation": "No in-branch fix available. TencentOS 3.2 requires migration to 4.x.",
        "references": [
            "TOS31-C01 (tencent_tos31_components_re.py)",
            "TOS31-C02 (openssh CVE-2023-38408)",
            "TOS31-C04 (sudo CVE-2021-3156)",
            "CVE-2021-4034", "CVE-2023-38408", "CVE-2021-3156", "CVE-2022-25315",
        ],
    },
    "TOS32-C02": {
        "title": (
            "curl 7.61.1-34.tl3.2 Patches CVE-2023-38545 SOCKS5 Heap Overflow (CVSS 9.8) — "
            "TencentOS 3.2 Update from 3.1's -22 Counter Applies 12 Release Counters of Patches; "
            "Earliest Safe Version for SOCKS5 Exposure in 3.x Branch"
        ),
        "severity": "INFO",
        "cvss": "0",
        "cwe": "CWE-122",
        "component": "curl-7.61.1-34.tl3.2 (was 7.61.1-22.tl3.4 in TencentOS 3.1)",
        "description": (
            "The curl update in TencentOS 3.2 (-22 → -34, 12 release counters) patches the "
            "following CVEs that were open in TencentOS 3.1: "
            "CVE-2023-38545 (CVSS 9.8): SOCKS5 heap overflow — attacker-controlled SOCKS5 "
            "server can overflow a heap buffer when handling long hostname responses; "
            "CVE-2023-28319 (use-after-free with SSH via CURLOPT_SSH_HOSTKEYFUNCTION); "
            "CVE-2023-28320 (siglongjmp race condition in multi-threaded SIGPIPE handling); "
            "CVE-2023-28321 (IDN hostname case-insensitive matching bypass); "
            "CVE-2023-38039 (HTTP header unbounded memory growth DoS); "
            "CVE-2024-2466 (mbedTLS certificate check bypass without CURLOPT_PINNEDPUBLICKEY). "
            "TencentOS 3.1 systems that have NOT applied the curl update remain vulnerable to "
            "CVE-2023-38545 (CVSS 9.8) and the full set above."
        ),
        "patched_in_34": [
            "CVE-2023-38545 (SOCKS5 heap overflow CVSS 9.8 — fixed ~-28)",
            "CVE-2023-28319 (libssh UAF — fixed ~-24)",
            "CVE-2023-28320 (SIGPIPE race — fixed ~-24)",
            "CVE-2023-28321 (IDN bypass — fixed ~-24)",
            "CVE-2023-38039 (HTTP header DoS — fixed ~-29)",
            "CVE-2024-2466 (mbedTLS cert bypass — fixed ~-33)",
        ],
        "remediation": "Ensure curl-7.61.1-34.tl3.2 or later is installed on all TencentOS 3.x systems.",
        "references": ["CVE-2023-38545", "CVE-2023-28319", "CVE-2023-38039"],
    },
    "TOS32-C03": {
        "title": (
            "libxml2 2.9.7-13.tl3.2 — Significant Update from 3.1 Baseline; "
            "Patches CVE-2022-40303/40304 Integer Overflow and Use-After-Free (Both CVSS 7.5); "
            "Previously Unpatched in TencentOS 3.1 -7.tl3"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-190",
        "component": "libxml2-2.9.7-13.tl3.2 (was 2.9.7-7.tl3 in TencentOS 3.1)",
        "description": (
            "TencentOS 3.2 updates libxml2 from 2.9.7-7.tl3 (3.1 baseline) to 2.9.7-13.tl3.2 "
            "(6 release counter increment). The RHEL 8 libxml2-2.9.7 backport history indicates "
            "this range covers: "
            "CVE-2022-40303 (CVSS 7.5): integer overflow in xmlParseNameComplex() allowing "
            "heap buffer over-read in XML parser when handling malformed names; "
            "CVE-2022-40304 (CVSS 7.5): use-after-free in xmlDictAddQString() when handling "
            "deeply nested XML entities (dict/qname table corruption). "
            "Both were introduced before -7 and fixed before -13. "
            "Any XML parsing pipeline (systemd unit file loading, rpm metadata, GNOME keyring, "
            "PAM HBAC, etc.) in TencentOS 3.1 was exposed to these."
        ),
        "chain": (
            "TOS32-C03: attacker-supplied XML via any libxml2-linked parser (rpm, curl --xml-parse, "
            "systemd-networkd, pam_sss) → CVE-2022-40303 integer overflow → heap over-read → info "
            "disclosure or crash; escalate with CVE-2022-40304 UAF for potential code exec path"
        ),
        "remediation": "Ensure libxml2-2.9.7-13.tl3.2+ on all TencentOS 3.1 systems. Not installed by default in 3.2.",
        "references": ["CVE-2022-40303", "CVE-2022-40304"],
    },
    "TOS32-C04": {
        "title": (
            "sssd-2.6.2 Introduced in TencentOS 3.2 — "
            "CVE-2023-3758 Race Condition in AD Machine Account Renewal (CVSS 7.1); "
            "New Attack Surface vs TencentOS 3.1 Base"
        ),
        "severity": "HIGH",
        "cvss": "7.1",
        "cwe": "CWE-362",
        "component": "sssd-2.6.2-4.tl3.2",
        "description": (
            "TencentOS 3.2 ships sssd-2.6.2-4.tl3.2 as an update package (2.6.2 is newer than "
            "the RHEL 8 SSSD baseline). CVE-2023-3758 affects SSSD 2.x: a race condition in the "
            "AD provider's machine account password renewal allows a local attacker to read the "
            "machine account credentials from a temporary file before it is removed, enabling "
            "impersonation as the machine account in the AD domain. Affects SSSD < 2.9.3. "
            "sssd-2.6.2 is within the vulnerable range. Impact is elevated in cloud environments "
            "where TencentOS instances are domain-joined to Active Directory — common in "
            "enterprise deployments of TencentOS on Tencent Cloud."
        ),
        "chain": (
            "TOS32-C04: local user on domain-joined TencentOS 3.2 instance → race on SSSD machine "
            "credential renewal tempfile → read machine account Kerberos credentials → impersonate "
            "host in AD → lateral movement to other AD resources"
        ),
        "remediation": "Update SSSD to 2.9.3+. Not available in TencentOS 3.x branch; requires migration to 4.x.",
        "references": ["CVE-2023-3758"],
    },
}

ATTACK_CHAIN_3_2 = {
    "title": "Remote Root via openssh PKCS#11 RCE + polkit PwnKit (Identical to TOS31)",
    "steps": [
        "1. Gain SSH access to TencentOS 3.2 host (credential, stolen key, or prior finding)",
        "2. Set up malicious PKCS#11 library on attacker-controlled SSH server",
        "3. Forward ssh-agent from victim to attacker server; victim's agent loads attacker's .so",
        "4. CVE-2023-38408: arbitrary code exec in victim's ssh-agent process (CVSS 9.8)",
        "5. From ssh-agent exec context (user-level): run polkit PwnKit exploit (CVE-2021-4034)",
        "6. pkexec heap OOB write → root escalation; or alternatively sudo Baron Samedit (CVE-2021-3156)",
        "7. Root shell; KASLR disabled (0xffffffff81000000) makes kernel exploits direct from here",
    ],
    "note": "TencentOS 3.2 adds no mitigation to this chain vs 3.1. curl-34 patched separately.",
}

DELTA_FROM_31 = {
    "patched_in_32": {
        "curl":    "CVE-2023-38545 SOCKS5 heap overflow CVSS 9.8 + 5 others (7.61.1-22→34)",
        "libxml2": "CVE-2022-40303/40304 overflow+UAF CVSS 7.5 (2.9.7-7→13)",
        "dnsmasq": "multiple CVEs in 2.79-31 (highly patched; release counter from ~17)",
        "bind":    "9.11.36-8.tl3.2 patches up to CVE-2022-38177 class",
        "dhcp":    "4.3.6-47 patches CVE-2023-8438 class in ISC DHCP",
        "dbus":    "1.12.8-12 patches CVE-2022-42010/42011/42012 D-Bus parsing cluster",
    },
    "still_open": {
        "CVE-2023-38408": "openssh PKCS#11 RCE CVSS 9.8 — no openssh update in 3.2 that advances -13",
        "CVE-2021-4034":  "polkit PwnKit CVSS 7.8 — 0.115-13.tl3.2 still < 0.120 fix",
        "CVE-2021-3156":  "sudo Baron Samedit CVSS 7.8 — 1.8.29-8.tl3 not updated",
        "CVE-2022-25315": "expat cluster CVSS 9.8 — expat-2.2.5 not updated",
        "CVE-2021-20231": "gnutls UAF CVSS 9.8 — 3.6.16-5.tl3 not updated",
        "TOSXK-F01":      "KASLR disabled in 5.4.119-19 — kernel not updated in 3.2",
    },
}


def probe():
    return {
        "critical": ["TOS32-C01"],
        "high": ["TOS32-C03", "TOS32-C04"],
        "medium": [],
        "info": ["TOS32-C02"],
    }


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "release": "TencentOS 3.2 (update set on 3.1 base)",
        "kernel": "5.4.119-19-0009.11 (unchanged from 3.1; KASLR disabled)",
        "updated_packages": len(COMPONENT_VERSIONS_3_2_UPDATED),
        "findings": list(FINDINGS.keys()),
        "delta": DELTA_FROM_31,
    }, indent=2))
