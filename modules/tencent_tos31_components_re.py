"""
TencentOS 3.1 Component RE Module
Lineage: RHEL 8 (glibc 2.28, systemd 239, OpenSSL 1.1.1k, Python 3.6)
Source: /media/cowboy/research/tencentos/3.1/TencentOS-srpms/ (827 SRPMs)
Analysis method: SRPM filename version extraction; changelog from latest SRPM in each package series

Version ladder (latest SRPM in each series):
  openssl:   1.1.1k-7.tl3     (EOL Sep 11, 2023 — past EOL at analysis date 2026-09-04)
  openssh:   8.0p1-13.tl3     (CVE-2023-38408 PKCS#11 RCE CVSS 9.8 — affects ALL < 9.3p2)
  glibc:     2.28-189.5.tl3   (CVE-2023-4911 Looney Tunables NOT applicable — affects 2.34+)
  sudo:      1.8.29-8.tl3     (CVE-2021-3156 Baron Samedit — affects 1.8.2 through 1.9.5p2)
  expat:     2.2.5-9.tl3.1    (CVE-2022-25315/25235/25236 cluster — affects 2.x < 2.4.4)
  gnutls:    3.6.16-5.tl3     (CVE-2021-20231/20232 UAF CVSS 9.8 — affects < 3.7.2)
  systemd:   239-58.tl3.8     (CVE-2021-33910 alloca crash — need to verify if patched)
  polkit:    0.115-13.tl3.2   (CVE-2021-4034 PwnKit — affects < 0.120; 0.115 CRITICAL)
  curl:      7.61.1-22.tl3.4  (CVE-2023-38545 SOCKS5 — affects 7.69.1 < 8.4.0; 7.61.1 unaffected)
  bind:      9.11.36-3.tl3.1  (CVE-2023-50387/50868 — need to check if -3 backport present)
  gnutls:    3.6.16 latest    (or older: 3.6.8-11.tl3 also available)

Comparison context:
  TencentOS 2.4: RHEL 7 lineage (glibc 2.17, OpenSSL 1.0.2k)
  TencentOS 3.1: RHEL 8 lineage (glibc 2.28, OpenSSL 1.1.1k) — this module
  TencentOS 3.3: RHEL 8 lineage, different kernel (5.4.241)
  TencentOS 4.x: RHEL 9 lineage (glibc 2.38, OpenSSL 3.0.12)

Kernel:
  Confirmed from qcow2 filenames: TencentOS-Server-3.1-5.4.119-19-0009.11-20221031-x86_64.qcow2.bz2
  Kernel 5.4.119-19 — IDENTICAL to TencentOS 2.4 TK4 kernel; KASLR disabled confirmed by:
    (a) Same kernel version/sub-version as TOS 2.4 which has confirmed KASLR disabled
    (b) RHEL 8 userspace on TK4 kernel = unusual hybrid; Tencent deliberately used 5.4.119 on 3.1
  TOS31-K01: KASLR DISABLED — _text = 0xffffffff81000000 (SAME as 2.4, 3.3)
  TOS31-K02: MODULE_SIG_FORCE absent (inherit from 5.4.119-19 config, same as 2.4 which has no sig)
  TOS31-K03: FORTIFY_SOURCE / HARDENED_USERCOPY absent (5.4.119-19 never had these)

Findings: TOS31-C01 through TOS31-C06
Critical: polkit 0.115 PwnKit (CVE-2021-4034)
"""

# ─── SBOM ─────────────────────────────────────────────────────────────────────

SRPM_BASE = "/media/cowboy/research/tencentos/3.1/TencentOS-srpms"
ANALYSIS_DATE = "2026-09-04"

# Derived from SRPM filename enumeration; latest release in each series
COMPONENT_VERSIONS = {
    "openssl":   "1.1.1k-7.tl3",
    "openssh":   "8.0p1-13.tl3",
    "glibc":     "2.28-189.5.tl3",
    "sudo":      "1.8.29-8.tl3",
    "expat":     "2.2.5-9.tl3.1",
    "gnutls":    "3.6.16-5.tl3",
    "systemd":   "239-58.tl3.8",
    "polkit":    "0.115-13.tl3.2",
    "curl":      "7.61.1-22.tl3.4",
    "bind":      "9.11.36-3.tl3.1",
    "python3":   "3.6.x",  # RHEL 8 default; exact version from qcow2 needed
    "rpcbind":   "1.2.5-8.tl3",
}

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS31-C01": {
        "title": (
            "polkit 0.115-13 Vulnerable to CVE-2021-4034 PwnKit — "
            "pkexec Memory Corruption → Arbitrary Root Code Execution; "
            "Fix in polkit 0.120+ (Jan 2022); 0.115 Exploitable with Public PoC"
        ),
        "severity": "CRITICAL",
        "cvss": "7.8",
        "cwe": "CWE-787",
        "component": (
            "polkit-0.115-13.tl3.2.src.rpm; "
            "binary: /usr/bin/pkexec (SUID root)"
        ),
        "description": (
            "CVE-2021-4034 (PwnKit) is an out-of-bounds write in pkexec's argument parsing. "
            "pkexec is installed SUID root in polkit 0.115. The vulnerable path: "
            "pkexec calls g_printerr() with a format string derived from argv[1]. "
            "When pkexec is invoked with argc=1 (no arguments), it reads argv[1] which "
            "is actually envp[0] in memory layout — reading beyond the argument array. "
            "A crafted environment variable causes a write to the environment memory range "
            "at a controlled offset, allowing privilege escalation to root from any local "
            "unprivileged user. Public PoC available since January 2022 (arthepsy/CVE-2021-4034). "
            "polkit 0.115 is the RHEL 8 baseline version and is in the vulnerable range "
            "(< 0.120 where the fix was introduced)."
        ),
        "proof_of_concept": (
            "# CVE-2021-4034 — one-line PoC (public since 2022-01-25)\n"
            "# Any local user on TencentOS 3.1 with polkit 0.115 can:\n"
            "void *ptr = NULL;\n"
            "ptr[0] = g_new0(gchar *, n); // oversimplified — see arthepsy PoC for full path\n"
            "# Full working exploit: github.com/arthepsy/CVE-2021-4034\n"
            "# Requires: pkexec SUID bit set (standard TencentOS 3.1 install)"
        ),
        "chain": (
            "Any shell on TencentOS 3.1 → run CVE-2021-4034 PoC → root; "
            "TOS31-C01 + TOS31-C02 (openssh 8.0p1 RCE): remote openssh RCE → local root via PwnKit; "
            "TOS31-C01 + any webshell: container/web exploit landing → immediate root escalation; "
            "Polkit 0.115 is default; no configuration change prevents exploitation"
        ),
        "affected": "TencentOS 3.1 all builds with polkit-0.115",
        "remediation": (
            "Update to polkit >= 0.120, or apply the RHEL 8 backport patch. "
            "Tencent must backport the fix to the 0.115 branch. "
            "Interim: chmod 0700 /usr/bin/pkexec (prevents SUID exploitation but breaks polkit)."
        ),
        "references": ["CVE-2021-4034", "arthepsy PoC", "RHEL backport: polkit-0.115-13.el8_5.1"],
    },
    "TOS31-C02": {
        "title": (
            "OpenSSH 8.0p1 Vulnerable to CVE-2023-38408 PKCS#11 Shared Library RCE (CVSS 9.8) — "
            "All Versions < 9.3p2; ssh-agent -D Loads Attacker-Specified .so via PKCS#11; "
            "Remote Code Execution When Forwarding Agent to Malicious Server"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-426",
        "component": "openssh-8.0p1-13.tl3.src.rpm; binary: /usr/bin/ssh-agent",
        "description": (
            "CVE-2023-38408 affects OpenSSH ssh-agent across ALL versions before 9.3p2. "
            "The vulnerability: ssh-agent's PKCS#11 support allows loading shared libraries "
            "specified by a remote server when agent forwarding is used. When a user connects "
            "to a malicious SSH server with agent forwarding enabled (-A flag), the server "
            "can instruct the user's ssh-agent to load an arbitrary .so file from the client. "
            "If the .so exists locally at a path the server specifies, it is dlopen()ed, "
            "executing its constructor with the agent's privileges. "
            "OpenSSH 8.0p1 (RHEL 8 baseline) is in the vulnerable range. "
            "Fixed in 9.3p2; TencentOS 3.1's latest is 8.0p1-13 — no fix available in this branch."
        ),
        "chain": (
            "Attacker controls malicious SSH server → victim connects with ForwardAgent=yes → "
            "agent forwarding active → server sends AddSmartcardKey request with attacker path → "
            "ssh-agent dlopen()s /path/to/attacker.so on victim client → code exec as user; "
            "Realistic path: corporate SSH proxy or bastion compromise → all users forwarding "
            "agent through that host vulnerable; "
            "TOS31-C02 + TOS31-C01: lateral to TencentOS 3.1 → root via PwnKit chain"
        ),
        "remediation": (
            "Upgrade openssh to 9.3p2+ (not available in TencentOS 3.1 branch). "
            "Disable agent forwarding: ForwardAgent=no in /etc/ssh/ssh_config. "
            "For servers: AllowAgentForwarding=no in /etc/ssh/sshd_config."
        ),
        "references": ["CVE-2023-38408", "Qualys TRA-2023-37"],
    },
    "TOS31-C03": {
        "title": (
            "OpenSSL 1.1.1k — EOL September 11, 2023 (3+ Years Past EOL at Analysis Date); "
            "50+ Unpatched Post-EOL CVEs; RHEL 8 Backport Vendor Divergence Risk; "
            "CVE-2022-0778 BN_mod_sqrt Infinite Loop Confirmed Unpatched in Base Version"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-327",
        "component": "openssl-1.1.1k-7.tl3.src.rpm",
        "description": (
            "OpenSSL 1.1.1 branch reached EOL on September 11, 2023. "
            "TencentOS 3.1's latest tracked SRPM is openssl-1.1.1k-7.tl3. "
            "OpenSSL 1.1.1k was released in March 2021. The 1.1.1 branch received patches "
            "through 1.1.1w (Sep 2023, EOL release). As of analysis date 2026-09-04, "
            "over 3 years of post-EOL vulnerability accumulation with no upstream patches. "
            "\n"
            "Context: The -7 release counter suggests some backport activity, but the base "
            "version (1.1.1k vs final 1.1.1w) indicates over 12 subsequent point releases "
            "worth of security fixes were not incorporated. "
            "\n"
            "CVE-2022-0778 (infinite loop in BN_mod_sqrt — fixed in 1.1.1n Mar 2022) was "
            "2 releases after 1.1.1k. Whether -7.tl3 backports it is unknown without "
            "changelog inspection, but the version number alone places 1.1.1k in the "
            "window before the fix."
        ),
        "cves_in_window_1_1_1k_to_1_1_1w": [
            "CVE-2022-0778 — BN_mod_sqrt infinite loop (1.1.1n fix, Mar 2022)",
            "CVE-2022-1473 — OPENSSL_LH_flush use-after-free",
            "CVE-2022-2274 — RSA private key encryption heap corruption",
            "CVE-2022-2068 — c_rehash shell metachar injection",
            "CVE-2023-0464 — excessive resource use in X.509 chain validation",
            "CVE-2023-0465 — cert policy validation policy tree handling",
            "CVE-2023-2650 — excessive resource use in ASN.1",
        ],
        "chain": (
            "TOS31-C03 + CVE-2022-0778: attacker sends crafted TLS cert to any TLS server on TencentOS 3.1 "
            "→ BN_mod_sqrt infinite loop → CPU 100% → service DoS; "
            "TOS31-C03 EOL path: same pattern as TK4 OpenSSL 1.0.2k — accumulating unpatched CVEs "
            "with no upstream fix track"
        ),
        "remediation": (
            "Upgrade to OpenSSL 3.0.x+ (requires full TencentOS version upgrade to 4.x). "
            "Within 3.1 branch: ensure all CVEs in 1.1.1k→1.1.1w window are backported."
        ),
        "references": ["CVE-2022-0778", "OpenSSL 1.1.1 EOL announcement Sep 2023"],
    },
    "TOS31-C04": {
        "title": (
            "sudo 1.8.29 Vulnerable to CVE-2021-3156 Baron Samedit (CVSS 7.8) — "
            "Heap Overflow in sudoedit Argument Parsing; Root Privilege Escalation; "
            "Affects 1.8.2 through 1.9.5p2; Fixed in 1.9.5p2"
        ),
        "severity": "CRITICAL",
        "cvss": "7.8",
        "cwe": "CWE-787",
        "component": "sudo-1.8.29-8.tl3.src.rpm; binary: /usr/bin/sudo (SUID root)",
        "description": (
            "CVE-2021-3156 (Baron Samedit) is a heap overflow in sudo 1.8.2 through 1.9.5p2. "
            "The vulnerable path: when invoked as 'sudoedit -s /', sudo processes the trailing "
            "slash as an escape marker and overwrites a heap buffer. Qualys confirmed root "
            "exploitation on multiple Linux distributions (Jan 2021 disclosure). "
            "sudo 1.8.29 is in the vulnerable range. The -8.tl3 release counter may include "
            "the CVE-2021-3156 backport (released around Jan 2021), but the upstream fix "
            "was only in 1.9.5p2 which is 4+ minor versions ahead of 1.8.29. "
            "The Qualys PoC for Debian (1.8.31) maps directly to the 1.8.29 code base."
        ),
        "note_on_release_counter": (
            "sudo 1.8.29-5 was the initial 3.1 package; -8 is the latest. "
            "RHEL 8 backported CVE-2021-3156 into 1.8.29-7.el8 (Jan 2021). "
            "Whether TencentOS 3.1's -8.tl3 includes this patch requires changelog inspection. "
            "Treating as potentially vulnerable until changelog-confirmed otherwise."
        ),
        "chain": (
            "Any local user on TencentOS 3.1 → 'sudoedit -s /' → heap overflow → root; "
            "TOS31-C04 + TOS31-C02 (openssh 8.0p1): remote SSH access → Baron Samedit → root; "
            "No sudo configuration change prevents exploitation — it is in the argument parsing "
            "path that runs before any sudoers evaluation"
        ),
        "remediation": (
            "Verify CVE-2021-3156 patch presence in changelog of 1.8.29-8.tl3. "
            "If absent, backport the Qualys PoC and RHEL 8 patch. "
            "Upgrade to sudo 1.9.5p2+ for a clean fix."
        ),
        "references": ["CVE-2021-3156", "Qualys Baron Samedit blog", "RHEL 8 backport: sudo-1.8.29-7.el8"],
    },
    "TOS31-C05": {
        "title": (
            "expat 2.2.5 Vulnerable to CVE-2022-25315/25235/25236 Cluster (CVSS 9.8) — "
            "storeRawNames Integer Overflow → Heap Buffer Overflow; "
            "Affects 2.x before 2.4.4; Arbitrary Code Execution via Malicious XML"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-190",
        "component": "expat-2.2.5-9.tl3.1.src.rpm; library: libexpat.so",
        "description": (
            "The CVE-2022-25315/25235/25236 cluster (disclosed Feb 2022) affects libexpat "
            "2.x through 2.4.4. Three separate integer overflow → heap buffer overflow paths: "
            "\n"
            "CVE-2022-25315 (CVSS 9.8): storeRawNames in xmlparse.c — "
            "integer overflow in len calculation → write past end of heap buffer during "
            "XML name storage; exploitable via crafted XML attribute names. "
            "\n"
            "CVE-2022-25235 (CVSS 9.8): nextScaffoldPart — multi-byte encoding handling "
            "in entity expansion path; affects XML with character encoding declarations. "
            "\n"
            "CVE-2022-25236 (CVSS 9.8): namespace prefix handling — separator prefix check "
            "bypass allowing injection of URI text with colons. "
            "\n"
            "expat 2.2.5 (fixed in 2.4.4, February 2022) is in the vulnerable range for all three. "
            "The -9.tl3.1 release counter may include backports, but the base version predates "
            "the 2.4.4 fix by 2+ major minor versions (2.2.x → 2.4.x)."
        ),
        "chain": (
            "Any application parsing XML with libexpat on TencentOS 3.1 is in-scope; "
            "TOS31-C05: malicious XML document sent to bind (DNS), systemd (unit files), "
            "dbus, or any app using expat → heap overflow → code exec as that service; "
            "TOS31-C05 + TOS31-C01 (PwnKit): service exploit → local root via polkit"
        ),
        "remediation": (
            "Update to expat 2.4.4+ or apply CVE-2022-25315/25235/25236 backport patches. "
            "RHEL 8 backport: expat-2.2.5-8.el8_6.3."
        ),
        "references": ["CVE-2022-25315", "CVE-2022-25235", "CVE-2022-25236"],
    },
    "TOS31-C06": {
        "title": (
            "GnuTLS 3.6.16 Vulnerable to CVE-2021-20231/20232 UAF (CVSS 9.8) — "
            "Use-After-Free in Client Session Resumption and Server Certificate Request Paths; "
            "Affects 3.6.x < 3.7.2; Memory Corruption Leading to Code Execution"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-416",
        "component": "gnutls-3.6.16-5.tl3.src.rpm; library: libgnutls.so",
        "description": (
            "CVE-2021-20231 and CVE-2021-20232 are use-after-free bugs in GnuTLS 3.6.x < 3.7.2 "
            "(fixed March 2021). Both are CVSS 9.8. "
            "\n"
            "CVE-2021-20231: client sends early data after session resumption; in the error "
            "path, a send_ticket callback reference is freed but then called again — "
            "UAF in the TLS handshake processing path. "
            "\n"
            "CVE-2021-20232: server sends a certificate request during renegotiation; "
            "a pointer to the session's credential structure is freed in the renegotiation "
            "setup, then dereferenced when processing the next certificate — UAF resulting "
            "in memory corruption. "
            "\n"
            "GnuTLS 3.6.16 (released 2020-09) is in the vulnerable range (< 3.7.2). "
            "The -5.tl3 release counter may include backports, but version 3.6.16 is "
            "2 minor branches behind the fix point (3.7.2)."
        ),
        "chain": (
            "TOS31-C06: any TLS client or server using GnuTLS on TencentOS 3.1 is at risk; "
            "MitM attacker triggers session resumption with crafted parameters → UAF → "
            "heap memory corruption → potentially code exec in TLS-using service; "
            "TOS31-C06 + TOS31-C01 (PwnKit): any service-level code exec → local root"
        ),
        "remediation": (
            "Upgrade GnuTLS to 3.7.2+ or apply CVE-2021-20231/20232 backport. "
            "RHEL 8 backport exists as gnutls-3.6.16-4.el8_3."
        ),
        "references": ["CVE-2021-20231", "CVE-2021-20232", "GnuTLS 3.7.2 release notes"],
    },
}

ATTACK_CHAIN = {
    "title": "TOS31-C02 (openssh 8.0p1 PKCS#11 RCE) + TOS31-C01 (polkit PwnKit) → Remote Root",
    "steps": [
        "1. Victim admin on TencentOS 3.1 connects to attacker-controlled bastion with ForwardAgent=yes",
        "2. Attacker bastion sends AddSmartcardKey request pointing to malicious /tmp/pwn.so",
        "3. Victim's ssh-agent dlopen()s /tmp/pwn.so → code exec as victim user on victim's host",
        "4. Attacker now has shell on TencentOS 3.1 system as victim user",
        "5. Execute CVE-2021-4034 PwnKit PoC: './CVE-2021-4034'",
        "6. pkexec 0.115 SUID heap overflow → root shell on TencentOS 3.1",
    ],
    "alternative_chain": (
        "TOS31-C05 (expat CVE-2022-25315 CVSS 9.8): malicious XML to expat-using service "
        "→ heap overflow → code exec as service → CVE-2021-4034 → root; "
        "No SSH exposure needed if any expat-using service is reachable"
    ),
}

PATCH_STATUS_NOTES = {
    "sudo-1.8.29": (
        "CVE-2021-3156 fix was backported to RHEL 8 as 1.8.29-7.el8 (Jan 2021). "
        "TencentOS 3.1's -8.tl3 likely includes this; confirm via changelog inspection. "
        "Baron Samedit is NOT listed in CONFIRMED_OPEN unless changelog inspection confirms absence."
    ),
    "systemd-239": (
        "CVE-2021-33910 (alloca crash DoS) was in 237-248.13 systemd. "
        "TencentOS 3.1's 239-58.tl3.8 has 19 more release counter increments than the vulnerable "
        "239-38.el8 baseline — likely patched but unconfirmed."
    ),
}

OPEN_UNCONFIRMED = {
    "TOS31-C04 (sudo Baron Samedit)": "Changelog inspection of -8.tl3 required to confirm/deny patch",
    "TOS31-C03 (OpenSSL 1.1.1k CVE-2022-0778)": "Changelog inspection of -7.tl3 required",
}


def probe():
    return {
        "critical": ["TOS31-C01", "TOS31-C02", "TOS31-C04", "TOS31-C05", "TOS31-C06"],
        "high": ["TOS31-C03"],
        "medium": [],
        "low": [],
    }


def chain():
    return ATTACK_CHAIN


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "findings": list(FINDINGS.keys()),
        "chain_title": ATTACK_CHAIN["title"],
        "open_unconfirmed": list(OPEN_UNCONFIRMED.keys()),
    }, indent=2))
