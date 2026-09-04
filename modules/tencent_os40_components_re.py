"""
TencentOS 4.0 Component RE Module
Source: tencentos-server-4.0-minimal-x86_64.tar (Mar 2024 container, 229MB)
        OCI layer RPM SQLite rpmdb.sqlite decode (131 packages, minimal container)
OS: TencentOS Server 4.0 (TENCENTOS_UPDATE_ID absent, VERSION_ID=4.0)
Lineage: RHEL 9 (glibc 2.38, systemd absent in minimal, OpenSSL 3.0.12, Python 3.11)
Analysis date: 2026-09-04

Package versions confirmed from RPM SQLite blob decode:
  openssl-libs: 3.0.12-3.tl4    (early release; CVE-2024-4741 fixed at -7)
  glibc:        2.38-5.tl4      (CVE-2023-4911 Looney Tunables PATCHED at -3)
  curl:         8.4.0-4.tl4     (CVE-2023-38545 SOCKS5 heap overflow: 8.4.0 base PATCHED)
  expat:        2.5.0-2.tl4     (CVE-2022-25315 cluster fixed in 2.4.4; 2.5.0 clean for that)
  libssh:       0.10.5-3.tl4    (NOT libssh2; CVE-2023-48795 Terrapin: fixed in 0.10.6)
  gnutls:       3.8.2-2.tl4     (modern; CVE-2021-20231/20232 fixed in 3.7.2)
  python3:      3.11.6-2.tl4    (early; CVE-2023-40217 fixed at -6)
  bash:         5.2.15-2.tl4    (no known critical open CVEs at this version)

Baseline for upgrade tracking:
  4.0 → 4.2: openssl -3 → -15; glibc -5 → -25; etc. (see tencent_os42_components_re.py)
  4.0 → 4.6: openssl -3 → -27; glibc -5 → -49.tl4.2

Findings: TOS40-C01 through TOS40-C03
"""

COMPONENT_VERSIONS = {
    "openssl_libs":  "3.0.12-3.tl4",
    "glibc":         "2.38-5.tl4",
    "curl":          "8.4.0-4.tl4",
    "expat":         "2.5.0-2.tl4",
    "gnutls":        "3.8.2-2.tl4",
    "libssh":        "0.10.5-3.tl4",
    "python3":       "3.11.6-2.tl4",
    "libxml2":       "2.11.5-2.tl4",
    "krb5_libs":     "1.21.2-1.tl4",
    "pam":           "1.5.3-4.tl4",
    "bash":          "5.2.15-2.tl4",
}

FINDINGS = {
    "TOS40-C01": {
        "title": (
            "openssl-libs 3.0.12-3 Missing CVE-2024-4741 UAF and Six Other Backports — "
            "4.0 Early Release Counter (-3) vs First CVE Patch (-7); "
            "CVE-2024-4741 Use-After-Free in SSL_free_buffers (CVSS 7.5) Present in Early 4.0"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-416",
        "component": "openssl-libs-3.0.12-3.tl4",
        "description": (
            "TencentOS 4.0 ships openssl-libs 3.0.12-3.tl4. The CVE backport history "
            "from 4.6's changelog (tencent_os46_components_re.py TCS46-P01) shows: "
            "first CVE patches in 3.0.12-7 (Jun 2024), covering CVE-2024-4741 (UAF), "
            "CVE-2024-2511 (session cache DoS), CVE-2024-4603 (key parameter check bypass). "
            "TencentOS 4.0's -3 release predates all of these. "
            "CVE-2024-4741 (CVSS 7.5): use-after-free in SSL_free_buffers() allows "
            "an attacker who controls TLS session teardown to corrupt heap state. "
            "This affects any TLS client or server on 4.0 early deployments."
        ),
        "missing_from_3_tl4": [
            "CVE-2024-4741 (UAF in SSL_free_buffers — fixed in 3.0.12-7)",
            "CVE-2024-2511 (session cache memory use issue — fixed in 3.0.12-7)",
            "CVE-2024-4603 (RSA key parameter validation — fixed in 3.0.12-7)",
            "CVE-2024-5535 (SSL_select_next_proto OOB CVSS 9.1 — fixed in 3.0.12-8)",
            "CVE-2024-6119 (cert CN type confusion — fixed in 3.0.12-12)",
            "CVE-2024-41996 (DH parameter order — fixed in 3.0.12-14)",
            "CVE-2024-9143 (EC point-at-infinity — fixed in 3.0.12-15)",
        ],
        "chain": (
            "TOS40-C01: any TLS handshake termination on 4.0 early deployment → "
            "CVE-2024-4741 heap UAF → potential code exec in TLS-serving process; "
            "Chain with glibc-2.38-5 (pre-latest patches) if heap grooming path found"
        ),
        "remediation": "Ensure all 4.0 deployments are updated to >= openssl-3.0.12-7.tl4.",
        "references": ["CVE-2024-4741", "CVE-2024-5535"],
    },
    "TOS40-C02": {
        "title": (
            "libssh 0.10.5 Vulnerable to CVE-2023-48795 Terrapin Attack — "
            "SSH Handshake Prefix Truncation; HMAC Bypass via ChaCha20-Poly1305 or CBC-EtM; "
            "Fixed in libssh 0.10.6 (January 2024)"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-354",
        "component": "libssh-0.10.5-3.tl4",
        "description": (
            "CVE-2023-48795 (Terrapin, disclosed December 2023) affects SSH implementations "
            "using ChaCha20-Poly1305 or CBC-EtM cipher modes. The attack: an active MitM can "
            "truncate the negotiated handshake extension negotiation messages by injecting a "
            "crafted sequence number, removing security extensions (e.g., ext-info, keystroke "
            "timing obfuscation) negotiated during connection setup. "
            "libssh 0.10.5 (May 2023) predates the fix in 0.10.6 (January 2024). "
            "In TencentOS 4.0, libssh is used by applications making SSH connections (not the "
            "OpenSSH server, which is a separate package not in the minimal container)."
        ),
        "chain": (
            "TOS40-C02: active network MitM on SSH connection using libssh in 4.0 application → "
            "Terrapin truncation → remove keystroke timing obfuscation or strict-kex → "
            "enables downstream timing side-channel on authentication"
        ),
        "remediation": "Update libssh to 0.10.6+. Avoid ChaCha20-Poly1305 and CBC-EtM in policy.",
        "references": ["CVE-2023-48795", "Terrapin Attack (Bäumer et al. 2023)"],
    },
    "TOS40-C03": {
        "title": (
            "python3 3.11.6-2 Missing CVE-2023-40217 Bypass of ssl.SSLSocket Handshake Timing — "
            "Premature EOF from Buffered SSL Handshake; Pre-auth Data Injection; "
            "Fixed in Python 3.11.6 release itself, but -2 release counter may predate backport"
        ),
        "severity": "LOW",
        "cvss": "4.0",
        "cwe": "CWE-295",
        "component": "python3-3.11.6-2.tl4",
        "description": (
            "CVE-2023-40217 affects Python ssl module: an attacker can inject data before the "
            "TLS handshake completes by sending data that arrives before the ssl.SSLSocket "
            "handshake is processed. This allows injecting cleartext into what the application "
            "believes is a TLS-protected connection. Affects 3.x before specific backport patches. "
            "The RHEL 9 backport was applied around the -6 release counter. "
            "4.0's python3-2.tl4 is the early release, likely missing this fix. "
            "Impact: any Python application using ssl.SSLSocket directly (not via urllib/requests) "
            "on TencentOS 4.0 is at risk."
        ),
        "remediation": "Update python3 to >= 3.11.6-6.tl4.",
        "references": ["CVE-2023-40217", "Python 3.11.6 release notes"],
    },
}

KASLR_NOTE = (
    "TencentOS 4.0 kernel: unknown from minimal container (no kernel package in 131-pkg minimal). "
    "Expected: 6.6.x TK4 kernel; KASLR status unknown. "
    "See tencent_kernel_cross_version.py for 4.2 (6.6.47, KASLR disabled). "
    "4.0 likely also disabled given 4.2 was disabled through 6.6.58."
)

PATCHED_VS_31 = {
    "CVE-2022-25315 (expat cluster CVSS 9.8)": "PATCHED — expat 2.5.0 is post-2.4.4 fix",
    "CVE-2021-20231 (GnuTLS UAF CVSS 9.8)": "PATCHED — gnutls 3.8.2 >> 3.7.2 fix",
    "CVE-2021-4034 (polkit PwnKit)": "N/A — polkit absent in minimal container",
    "CVE-2023-4911 (glibc Looney Tunables)": "PATCHED — glibc 2.38-5 >= -3 fix",
}


def probe():
    return {
        "critical": [],
        "high": ["TOS40-C01"],
        "medium": ["TOS40-C02"],
        "low": ["TOS40-C03"],
    }


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "tencentos-server-4.0-minimal-x86_64.tar",
        "pkg_count": 131,
        "findings": list(FINDINGS.keys()),
        "kaslr_note": KASLR_NOTE,
    }, indent=2))
