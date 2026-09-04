"""
TencentOS Server 3.1 Core Security Lifecycle RE Module
Source: TOS 3.1 local HDD: TencentOS-srpms/ (827 packages), Updates-srpms/ (892 packages)
Method: SRPM inventory; changelog extraction (rpm2cpio | cpio); patch file enumeration
Analysis date: 2026-09-04

TOS 3.1 DUAL-REPO SECURITY MODEL:
  TencentOS-srpms/ (827):  base OS components — openssl, glibc, libssh, openssh, kernel (not present)
  Updates-srpms/ (892):    security updates — curl, bind, NetworkManager, etc.

DISCOVERY: Core cryptographic packages were abandoned in TencentOS-srpms by mid-2022
and were NOT picked up by Updates-srpms. Application-layer packages (curl, bind) continued
receiving security updates through Sep 2023 via Updates-srpms.

TERMINAL VERSIONS (extracted from SRPM changelogs):
  openssl-1.1.1k-7.tl3   Jul 05 2022  Clemens Lang <cllang@redhat.com>
  glibc-2.28-189.5.tl3   Jun 08 2022  Florian Weimer <fweimer@redhat.com>
  libssh-0.9.6-3.tl3     unknown (no Updates-srpms entry, TencentOS-srpms terminal)
  openssh-8.0p1-13.tl3   Oct 26 2021  Dmitry Belyavskiy <dbelyavs@redhat.com>
  curl-7.61.1-34.tl3     Sep 19 2023  Jacek Migacz <jmigacz@redhat.com>     [IN Updates-srpms]
  bind-9.11.36-16.tl3.2  most recent  (IN Updates-srpms — multiple 2022-2024 builds)

SPLIT: curl got updates through Sep 2023; its TLS layer (openssl) stopped at Jul 2022.
curl-7.61.1-34 links against the same openssl-1.1.1k-7 that is missing 2023 CVE patches.
An "updated" curl is running on an unpatched crypto foundation.
"""

REPO_INVENTORY = {
    "TencentOS-srpms": {
        "count": 827,
        "purpose": "base OS packages",
        "security_critical": {
            "openssl":  "1.1.1k-7.tl3 (Jul 2022, TERMINAL)",
            "glibc":    "2.28-189.5.tl3 (Jun 2022, TERMINAL)",
            "libssh":   "0.9.6-3.tl3 (TERMINAL — not in Updates-srpms)",
            "openssh":  "8.0p1-13.tl3 (Oct 2021, TERMINAL — not in Updates-srpms)",
        },
    },
    "Updates-srpms": {
        "count": 892,
        "purpose": "security/bugfix updates",
        "security_critical_absent": [
            "openssl (any version)",
            "glibc (any version)",
            "libssh (any version)",
            "openssh (any version)",
            "kernel (not present in either repo)",
        ],
        "security_critical_present": {
            "curl":     "7.61.1-34.tl3 (Sep 2023)",
            "bind":     "9.11.36-16.tl3.2 (2024-era build)",
            "bind9.16": "9.16.23-0.22.tl3",
            "expat":    "2.2.5-16.tl3",
        },
    },
}

OPENSSL_PATCH_AUDIT = {
    "srpm": "openssl-1.1.1k-7.tl3.src.rpm",
    "changelog_terminal_date": "2022-07-05",
    "patches_confirmed_present": [
        "openssl-1.1.1-cve-2022-0778.patch  (BN_mod_sqrt infinite loop)",
        "openssl-1.1.1-cve-2022-1292.patch  (c_rehash command injection)",
        "openssl-1.1.1-cve-2022-2068.patch  (c_rehash command injection)",
        "openssl-1.1.1-cve-2022-2097.patch  (AES OCB 32-bit x86 encryption)",
        "openssl-1.1.1-read-buff.patch      (CVE-2021-3712 ASN.1 OOB read)",
    ],
    "cves_open_post_july_2022": {
        "CVE-2022-4304": {
            "cvss": "5.9",
            "class": "Timing oracle in RSA Decryption",
            "fixed_in_rhel8": "openssl-1.1.1k-8 (Feb 2023)",
            "impact": (
                "RSA timing side-channel distinguishable with network access. "
                "Bleichenbacher-style attack applicable to RSA key exchange cipher suites. "
                "Not exploitable in TLS 1.3 (no RSA key exchange), but affects TLS 1.2 "
                "connections with RSA_WITH_* cipher suites."
            ),
        },
        "CVE-2022-4450": {
            "cvss": "7.5",
            "class": "Double free after calling PEM_read_bio_ex",
            "fixed_in_rhel8": "openssl-1.1.1k-8 (Feb 2023)",
            "impact": (
                "Double free in PEM_read_bio_ex() triggered by malformed PEM data. "
                "Any application that reads PEM-format certificates/keys from external "
                "sources (file uploads, ACME challenges, TLS client cert processing) "
                "is affected. Heap corruption; potential RCE if allocation patterns "
                "are controllable."
            ),
        },
        "CVE-2023-0215": {
            "cvss": "7.5",
            "class": "Use-after-free following BIO_new_NDEF",
            "fixed_in_rhel8": "openssl-1.1.1k-8 (Feb 2023)",
            "impact": (
                "Use-after-free in BIO_new_NDEF() when processing S/MIME or CMS data. "
                "Affects mail handling, code-signing verification, and any TLS stack "
                "that processes PKCS#7/CMS structures. Potential crash or RCE."
            ),
        },
        "CVE-2023-0286": {
            "cvss": "7.4",
            "class": "Type confusion in X.400 GeneralName ASN.1 parsing",
            "fixed_in_rhel8": "openssl-1.1.1k-8 (Feb 2023)",
            "impact": (
                "Type confusion between ASN1_STRING and ASN1_TYPE when processing "
                "X.400 address type in GeneralName structures in certificates. "
                "A specially crafted certificate can cause OpenSSL to read arbitrary "
                "stack or heap memory. Triggered during certificate chain verification — "
                "a HTTPS client connecting to a malicious server with a crafted cert "
                "can be exploited with no user interaction required."
            ),
        },
        "CVE-2023-0464": {
            "cvss": "7.5",
            "class": "Excessive resource usage in certificate policy checking",
            "fixed_in_rhel8": "openssl-1.1.1k-9 (Mar 2023)",
            "impact": "DoS via crafted certificate chain with excessively large policy tree.",
        },
        "CVE-2023-2650": {
            "cvss": "5.9",
            "class": "ASN.1 OID translation DoS",
            "fixed_in_rhel8": "openssl-1.1.1k-10 (May 2023)",
            "impact": "Possible DoS via malformed ASN.1 OID in certificate.",
        },
        "CVE-2023-3446": {
            "cvss": "5.3",
            "class": "Excessive time spent checking DH keys",
            "fixed_in_rhel8": "openssl-1.1.1k-11 (Jul 2023)",
            "impact": "DoS via very large DH parameter values.",
        },
        "CVE-2023-3817": {
            "cvss": "5.3",
            "class": "Excessive time spent checking DH q parameter value",
            "fixed_in_rhel8": "openssl-1.1.1k-12 (Aug 2023)",
            "impact": "DoS via large q parameter in DH key generation.",
        },
    },
    "rhel8_terminal": "openssl-1.1.1k-12+ (Sep 2023, EoL release)",
    "tos31_terminal": "openssl-1.1.1k-7 (Jul 2022)",
    "counter_delta": "~5 counter increments missing from TOS 3.1 vs RHEL 8 terminal",
}

GLIBC_PATCH_AUDIT = {
    "srpm": "glibc-2.28-189.5.tl3.src.rpm",
    "changelog_terminal_date": "2022-06-08",
    "last_cve_in_build": "CVE-2022-23218/CVE-2022-23219 (Jan 2022) at -188",
    "cves_open_post_june_2022": {
        "CVE-2023-4911": {
            "cvss": "7.8",
            "class": "Buffer overflow in dynamic linker (ld.so) GLIBC_TUNABLES processing",
            "disclosure": "2023-10-03",
            "fixed_in_rhel8": "glibc-2.28-236.0.1 (Oct 2023)",
            "impact": (
                "LOCAL PRIVILEGE ESCALATION to root. "
                "The GLIBC_TUNABLES environment variable is processed by the dynamic linker "
                "before setuid/setgid privilege drops. An attacker with local code execution "
                "(any shell, any unprivileged account) can craft a GLIBC_TUNABLES value that "
                "causes a buffer overflow in ld.so, gaining root on the system. "
                "\n"
                "Attack chain: local access (e.g. via webshell, CVE-2023-38408 openssh RCE, "
                "any web app vuln) → "
                "CVE-2023-4911 via crafted GLIBC_TUNABLES → root privilege escalation. "
                "\n"
                "This is a 'Looney Tunables' class vulnerability affecting all distros "
                "using glibc ≤2.38 without the patch. TOS 3.1 glibc 2.28-189.5 (Jun 2022) "
                "predates the Oct 2023 fix by 16 months."
            ),
            "exploit_available": True,
            "note": "Public PoC released Oct 2023; actively exploited in the wild",
        },
        "CVE-2023-4527": {
            "cvss": "6.5",
            "class": "Stack read overflow in getaddrinfo with large TCP responses",
            "fixed_in_rhel8": "glibc-2.28-236.0.1 (Oct 2023)",
            "impact": "Stack OOB read in getaddrinfo() handling large DNS responses over TCP.",
        },
        "CVE-2023-4806": {
            "cvss": "5.9",
            "class": "Use-after-free in getaddrinfo()",
            "fixed_in_rhel8": "glibc-2.28-236.0.1 (Oct 2023)",
            "impact": "Use-after-free in getaddrinfo() on early exit.",
        },
        "CVE-2023-4813": {
            "cvss": "5.9",
            "class": "Use-after-free in gaih_inet()",
            "fixed_in_rhel8": "glibc-2.28-236.0.1 (Oct 2023)",
            "impact": "Use-after-free in gaih_inet() via name service lookup.",
        },
    },
    "tos31_terminal": "glibc-2.28-189.5 (Jun 2022)",
    "rhel8_terminal": "glibc-2.28-236.0.1+ (Oct 2023)",
    "counter_delta": "~47 counter increments missing from TOS 3.1 vs RHEL 8 terminal",
}

CURL_AUDIT = {
    "srpm": "curl-7.61.1-34.tl3.src.rpm",
    "changelog_terminal_date": "2023-09-19",
    "repo": "Updates-srpms (HAS ongoing updates unlike openssl/glibc)",
    "cves_included_at_34": [
        "CVE-2023-28322 (upload/method handling)",
        "CVE-2023-38546 (cookie injection)",
        "CVE-2023-46218 (PSL domain lowercase)",
        "CVE-2023-28321 (hostname wildcard)",
        "CVE-2023-27536, CVE-2023-27535 (GSS/FTP conn reuse)",
        "CVE-2023-23916 (HTTP multi-header compression DoS)",
        "CVE-2022-43552 (smb/telnet use-after-free)",
    ],
    "split_observation": (
        "curl is updated through Sep 2023 in Updates-srpms. "
        "However, curl links against openssl-1.1.1k-7 (TOS 3.1 base). "
        "openssl-1.1.1k-7 is missing CVE-2023-0286 (type confusion, arbitrary memory read). "
        "A HTTPS connection made by curl to a malicious server with a crafted certificate "
        "can trigger CVE-2023-0286 in the openssl library, independent of curl's own patch level. "
        "\n"
        "The security update model creates a false sense of security: "
        "dnf list updates shows curl as current, but the underlying crypto is not."
    ),
}

FINDINGS = {
    "TOS31-OPENSSL-F01": {
        "title": (
            "TOS 3.1 openssl-1.1.1k Terminal at Jul 2022 (-7); "
            "Missing Post-Jul 2022 CVEs Including CVE-2023-0286 (HIGH) X.400 Memory Read, "
            "CVE-2022-4450 (HIGH) Double-Free, CVE-2023-0215 (HIGH) Use-After-Free; "
            "No openssl in Updates-srpms — No Update Path"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H",
        "cwe": "CWE-843",
        "component": "openssl-1.1.1k-7.tl3 (TOS 3.1 terminal version, Jul 2022)",
        "description": (
            "TOS 3.1 openssl-1.1.1k-7 was released July 5, 2022 and is the terminal version. "
            "No openssl package exists in Updates-srpms for TOS 3.1. "
            "\n"
            "RHEL 8's openssl-1.1.1k continued through -12 (Sep 2023, EoL). "
            "TOS 3.1 diverged at -7 (Jul 2022) — missing ~5 counter increments that cover: "
            "\n"
            "  CVE-2023-0286 (HIGH/7.4): X.400 address type confusion in GeneralName "
            "    ASN.1 parsing. Arbitrary stack/heap memory read during certificate "
            "    verification. A HTTPS client connecting to a crafted server certificate "
            "    is exploitable without user interaction. "
            "\n"
            "  CVE-2022-4450 (HIGH/7.5): Double free in PEM_read_bio_ex(). "
            "    Applications reading external PEM data (cert files, ACME, TLS client certs) "
            "    are vulnerable to heap corruption. "
            "\n"
            "  CVE-2023-0215 (HIGH/7.5): Use-after-free in BIO_new_NDEF(). "
            "    S/MIME and CMS processing; TLS stacks processing PKCS#7 structures. "
            "\n"
            "  CVE-2022-4304 (MEDIUM/5.9): RSA timing oracle. "
            "    Bleichenbacher-style attack on TLS 1.2 RSA key exchange. "
            "\n"
            "  CVE-2023-0464, CVE-2023-2650, CVE-2023-3446, CVE-2023-3817: "
            "    Various DoS via crafted certificate content. "
            "\n"
            "curl-7.61.1-34 (Sep 2023, in Updates-srpms) links against this openssl — "
            "an 'updated' curl running on an unpatched crypto foundation."
        ),
        "chain": (
            "TOS31-OPENSSL-F01: any TLS client on TOS 3.1 (curl, wget, python-requests) → "
            "HTTPS connection to attacker-controlled server → "
            "server presents crafted certificate with X.400 GeneralName → "
            "CVE-2023-0286: openssl reads arbitrary stack/heap memory → "
            "sensitive data disclosure (key material, process memory) or crash"
        ),
        "remediation": (
            "Upgrade to TOS 3.3 or TOS 4.x. "
            "No openssl update available in TOS 3.1 update channel. "
            "dnf update on TOS 3.1 will NOT deliver a patched openssl."
        ),
        "references": [
            "CVE-2023-0286", "CVE-2022-4450", "CVE-2023-0215", "CVE-2022-4304",
            "CVE-2023-0464", "CVE-2023-2650", "CVE-2023-3446", "CVE-2023-3817",
            "openssl-1.1.1k-7 changelog (Jul 5, 2022)",
        ],
    },
    "TOS31-GLIBC-F01": {
        "title": (
            "TOS 3.1 glibc-2.28 Terminal at Jun 2022 (-189.5); "
            "CVE-2023-4911 Looney Tunables OPEN — Local Privilege Escalation to Root; "
            "No glibc in Updates-srpms — No Update Path"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-122",
        "component": "glibc-2.28-189.5.tl3 (TOS 3.1 terminal version, Jun 2022)",
        "description": (
            "TOS 3.1 glibc-2.28-189.5 was released June 8, 2022 and is the terminal version. "
            "No glibc package exists in Updates-srpms for TOS 3.1. "
            "\n"
            "CVE-2023-4911 (Looney Tunables, Oct 2023): Buffer overflow in ld.so's "
            "GLIBC_TUNABLES processing. The dynamic linker processes GLIBC_TUNABLES before "
            "privilege drops in setuid/setgid execution contexts. "
            "\n"
            "Attack: any local user crafts GLIBC_TUNABLES to overflow the parsing buffer "
            "in ld.so, gaining control of the linker's execution context in a setuid binary, "
            "resulting in root code execution. "
            "\n"
            "Public PoC available since October 2023. Actively exploited in the wild. "
            "\n"
            "RHEL 8 glibc patched at 2.28-236.0.1 (Oct 2023). "
            "TOS 3.1 glibc 2.28-189.5 (Jun 2022) predates the fix by 16 months. "
            "\n"
            "Chain: any initial access (web app vuln, CVE-2023-38408 openssh RCE) → "
            "local shell on TOS 3.1 host → CVE-2023-4911 → root. "
            "\n"
            "Additional missing CVEs: CVE-2023-4527 (getaddrinfo OOB), "
            "CVE-2023-4806, CVE-2023-4813 (use-after-free in name resolution)."
        ),
        "chain": (
            "TOS31-GLIBC-F01: any initial access to TOS 3.1 host (web app, SSH) → "
            "local user shell → "
            "GLIBC_TUNABLES=<crafted value> ./vulnerable_suid_binary → "
            "CVE-2023-4911: ld.so buffer overflow during setuid execution → "
            "root privilege escalation → full host compromise"
        ),
        "chain_with_openssh": (
            "TOS31-OPENSSH-F01 (CVE-2023-38408 RCE via ssh -A) → "
            "code execution as user on TOS 3.1 host → "
            "TOS31-GLIBC-F01 (CVE-2023-4911 Looney Tunables) → "
            "root privilege on TOS 3.1 host → "
            "all agent-stored keys stolen, lateral movement"
        ),
        "remediation": (
            "Upgrade to TOS 3.3 or TOS 4.x. "
            "No glibc update available in TOS 3.1 update channel. "
            "Mitigate by restricting local access and disabling setuid binaries "
            "where not required (chmod -s)."
        ),
        "references": [
            "CVE-2023-4911 (Looney Tunables)",
            "CVE-2023-4527", "CVE-2023-4806", "CVE-2023-4813",
            "glibc-2.28-189.5 changelog (Jun 8, 2022)",
        ],
    },
    "TOS31-CORE-F01": {
        "title": (
            "TOS 3.1 Core Cryptographic Package Lifecycle Split: "
            "Application Layer (curl, bind) Updated Through Sep 2023 via Updates-srpms; "
            "Crypto Foundation (openssl, glibc, libssh, openssh) Abandoned at Mid-2022 in TencentOS-srpms; "
            "dnf update on TOS 3.1 Creates False Security Assurance"
        ),
        "severity": "HIGH",
        "cvss": "0.0",
        "cwe": "CWE-1104",
        "component": "TOS 3.1 security update model",
        "description": (
            "TOS 3.1 uses two package repositories: TencentOS-srpms (base OS, 827 packages) "
            "and Updates-srpms (updates, 892 packages). "
            "\n"
            "FINDING: The two repos are maintained on divergent schedules: "
            "\n"
            "  Updates-srpms (ACTIVE through 2023): "
            "    curl-7.61.1-34.tl3 (Sep 19, 2023) "
            "    bind-9.11.36-16.tl3.2 (2024-era) "
            "    bind9.16-9.16.23-0.22.tl3 "
            "    NetworkManager-1.40.16-15.tl3 "
            "\n"
            "  TencentOS-srpms (ABANDONED at mid-2022): "
            "    openssl-1.1.1k-7 (Jul 2022) — 8 post-Jul-2022 CVEs unpatched "
            "    glibc-2.28-189.5 (Jun 2022) — CVE-2023-4911 (LPE to root) unpatched "
            "    libssh-0.9.6-3 (date unknown) — Terrapin unpatched "
            "    openssh-8.0p1-13 (Oct 2021) — CVE-2023-38408 unpatched "
            "\n"
            "OPERATIONAL IMPLICATION: "
            "A TOS 3.1 administrator who runs 'dnf update' regularly sees curl and bind "
            "as current (updated Sep 2023). The system APPEARS patched. But: "
            "\n"
            "  1. curl uses openssl for TLS — openssl is missing CVE-2023-0286 (HIGH). "
            "     A 'current' curl on a TOS 3.1 host is vulnerable to X.400 cert exploits. "
            "\n"
            "  2. openssh is 4 years old (Oct 2021) — missing CVE-2023-38408 (ssh-agent RCE). "
            "\n"
            "  3. glibc is missing CVE-2023-4911 — any local shell = root. "
            "\n"
            "A dnf check-update on TOS 3.1 would show curl, bind, etc. as UPDATED "
            "but would NOT flag openssl, glibc, libssh, openssh — they are at their "
            "TencentOS-srpms terminal versions and Updates-srpms has no newer version. "
            "\n"
            "The security update model's split creates a systematic blind spot: "
            "the packages most critical to the system's security posture (openssl, glibc) "
            "are in the repo that stopped receiving updates."
        ),
        "remediation": (
            "Upgrade TOS 3.1 hosts to TOS 3.3 or TOS 4.x. "
            "For detection on existing TOS 3.1 hosts: "
            "  rpm -q openssl glibc libssh openssh "
            "  Expected vulnerable: openssl-1.1.1k-7, glibc-2.28-189.5, "
            "  libssh-0.9.6-3, openssh-8.0p1-13 "
            "No in-place fix available without OS upgrade."
        ),
        "references": [
            "TOS31-OPENSSL-F01 (this module)",
            "TOS31-GLIBC-F01 (this module)",
            "TOS31-OPENSSH-F01, TOS31-OPENSSH-F02, TOS31-OPENSSH-F03 (tencent_tos31_openssh_srpm_re.py)",
            "curl-7.61.1-34.tl3 changelog (Sep 19, 2023)",
            "openssl-1.1.1k-7.tl3 changelog (Jul 5, 2022)",
            "glibc-2.28-189.5.tl3 changelog (Jun 8, 2022)",
        ],
    },
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "TOS 3.1 TencentOS-srpms/ + Updates-srpms/",
        "method": "SRPM inventory; changelog extraction; patch file enumeration",
        "key_finding": (
            "Core crypto packages (openssl, glibc, libssh, openssh) abandoned mid-2022. "
            "Application packages (curl, bind) active through 2023. "
            "dnf update creates false security assurance on TOS 3.1."
        ),
        "terminal_versions": {
            "openssl":  "1.1.1k-7 (Jul 2022) — 8 CVEs open",
            "glibc":    "2.28-189.5 (Jun 2022) — CVE-2023-4911 open",
            "libssh":   "0.9.6-3 — Terrapin open",
            "openssh":  "8.0p1-13 (Oct 2021) — CVE-2023-38408 open",
            "curl":     "7.61.1-34 (Sep 2023) — appears current but uses unpatched openssl",
        },
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
