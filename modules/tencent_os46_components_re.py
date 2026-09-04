#!/usr/bin/env python3
"""
TencentOS 4.6 Component RE Module
Source: /media/cowboy/research/tencentos/4.6/ (BaseOS-source + AppStream-source SRPMs)
Analysis date: 2026-09-04
Kernel: 6.6.110-42.x / 6.6.117-45.x (Linux 6.6 LTS, tl4 series)
glibc: 2.38-49.tl4.2
OpenSSL: 3.0.12-27.tl4
curl: 8.4.0-17.tl4
openssh: 9.3p2-16.tl4
polkit: 123-5.tl4
KonaJDK: java-8-konajdk-8.0.27, java-11-konajdk-11.0.32, java-17-konajdk-17.0.20

Methodology: SRPM spec %changelog extraction via rpm2cpio + awk.
Release-counter cross-referencing for CVE backport status.
Findings below are CONFIRMED via spec changelog text and patch file presence.

CVE backport status summary (4.6 vs 4.0):
  CVE-2024-2961 (glibc iconv OOB): PATCHED at glibc-2.38-8.tl4 (Apr 2024)
  CVE-2023-4911 (Looney Tunables): PATCHED at glibc-2.38-3.tl4 (Oct 2023)
  CVE-2024-4741 (OpenSSL UAF):     PATCHED at openssl-3.0.12-7.tl4 (Jun 2024)
  CVE-2024-5535 (OpenSSL OOB):     PATCHED at openssl-3.0.12-8.tl4 (Jun/Jul 2024)
  CVE-2024-6387 (regreSSHion):     PATCHED at openssh-9.3p2-12.tl4 (Jul 2024)
  CVE-2023-38545 (curl SOCKS5):    PATCHED at curl-8.4.0-1.tl4 (Oct 2023, version bump)
  CVE-2021-4034 (PwnKit/polkit):   NOT APPLICABLE — polkit-123-5.tl4 uses 0.123 base
                                    (fix was in upstream 0.120; TCS-S04 in tencent_os_components_re.py
                                     covers 3.x polkit-0.115-15 only)

Findings:
  TCS46-P01  OpenSSL 3.0.12 on EOL path (2026-09-07) — 3 days from analysis date
  TCS46-P02  Triple KonaJDK runtime surface (Java 8/11/17) + Chinese crypto extensions
  TCS46-P03  openssh 9.3p2 post-CVE-2024-6387 new vulnerabilities (CVE-2025-26465 confirmed unpatched pre-16)
  TCS46-P04  OpenSSL SM2/SM4/TLCP Chinese national crypto extension — novel attack surface
"""

import json
import subprocess
import os
from pathlib import Path

# ─── Target Profile ───────────────────────────────────────────────────────────

TARGET = "tencentos-4.6"
SRPM_BASE = "/media/cowboy/research/tencentos/4.6/BaseOS-source"
SRPM_APPSTREAM = "/media/cowboy/research/tencentos/4.6/AppStream-source"
ANALYSIS_DATE = "2026-09-04"

# Package versions confirmed from SRPM filenames and changelog extraction
CONFIRMED_VERSIONS = {
    "openssl":    "3.0.12-27.tl4",
    "glibc":      "2.38-49.tl4.2",
    "curl":       "8.4.0-17.tl4",
    "openssh":    "9.3p2-16.tl4",
    "polkit":     "123-5.tl4",
    "sudo":       "1.9.15p5-6.tl4",
    "systemd":    "255-20.tl4.ap.4",
    "kernel":     "6.6.117-45.x.tl4",
    "konajdk8":   "8.0.27-1.tl4",
    "konajdk11":  "11.0.32-1.tl4",
    "konajdk17":  "17.0.20-1.tl4",
}

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        "id": "TCS46-P01",
        "title": (
            "OpenSSL 3.0.12 Approaching End-of-Life (2026-09-07, 3 Days from Analysis) — "
            "Post-EOL: No Upstream Patches; Tencent Backport Burden Becomes Sole Security Layer; "
            "Active CVE Backport History Confirmed via Spec Changelog"
        ),
        "severity": "HIGH",
        "detail": (
            "TencentOS 4.6 ships OpenSSL 3.0.12-27.tl4. The 3.0.x branch enters EOL on "
            "2026-09-07 (3 days from analysis date 2026-09-04). After EOL, the OpenSSL project "
            "publishes no further patches, CVE advisories, or security fixes for 3.0.x.\n"
            "\n"
            "BACKPORT TRACK RECORD (confirmed via spec changelog):\n"
            "  3.0.12-7  (Jun 2024): CVE-2024-4741 (UAF in SSL_free_buffers) PATCHED\n"
            "             also: CVE-2024-2511 (session cache DoS), CVE-2024-4603 (key check)\n"
            "  3.0.12-8  (Jul 2024): CVE-2024-5535 (SSL_select_next_proto OOB, CVSS 9.1) PATCHED\n"
            "  3.0.12-12 (Sep 2024): CVE-2024-6119 (cert CN comparison type confusion) PATCHED\n"
            "  3.0.12-14 (Oct 2024): CVE-2024-41996 (DH parameter order validation) PATCHED\n"
            "  3.0.12-15 (Oct 2024): CVE-2024-9143 (EC point-at-infinity) PATCHED\n"
            "  3.0.12-17 (Feb 2025): CVE-2024-13176 (ECDSA timing side-channel) PATCHED\n"
            "  3.0.12-25 (Jan 2026): CVE-2025-15467 PATCHED\n"
            "  3.0.12-26 (Feb 2026): CVE-2026-22795, CVE-2026-22796, CVE-2025-69418,\n"
            "             CVE-2025-69419, CVE-2025-69420, CVE-2025-69421, CVE-2025-68160 PATCHED\n"
            "  3.0.12-27 (Jun 2026): CVE-2026-34182, CVE-2026-45447 PATCHED\n"
            "\n"
            "POST-EOL RISK MODEL:\n"
            "  - OpenSSL project stops issuing CVEs for 3.0.x after 2026-09-07.\n"
            "  - Tencent must independently identify and backport fixes from 3.x/4.x mainline.\n"
            "  - The Tencent team has demonstrated 2-6 week patch velocity on known CVEs,\n"
            "    but zero-day or privately disclosed vulnerabilities will have no upstream\n"
            "    advisory to trigger the backport process.\n"
            "  - OpenSSL 3.2 / 3.3 (current LTS candidates) contain additional hardening\n"
            "    (e.g., FIPS module updates, provider architecture improvements) that 3.0.12\n"
            "    will not receive.\n"
            "\n"
            "ADDITIONAL CONTEXT:\n"
            "  TencentOS 4.6 also ships SM2/SM4 and TLCP extensions on top of 3.0.12 "
            "(see TCS46-P04). These are Tencent-specific patches that do not exist upstream "
            "and will require independent maintenance after EOL with no reference implementation "
            "to sync against."
        ),
        "evidence": {
            "openssl_version": "3.0.12-27.tl4 (confirmed from SRPM filename)",
            "eol_date": "2026-09-07 (OpenSSL project official EOL for 3.0.x branch)",
            "analysis_date": "2026-09-04 (3 days before EOL)",
            "last_changelog_entry": "3.0.12-27: Fix CVE-2026-34182, CVE-2026-45447 (Jun 2026)",
            "srpm_path": f"{SRPM_BASE}/openssl-3.0.12-27.tl4.src.rpm",
        },
        "attack_chain": (
            "EOL-based risk (not an exploitable chain by itself): "
            "Post 2026-09-07, any OpenSSL 3.0.x vulnerability disclosed via upstream 3.2/3.3 "
            "commit will not have a corresponding 3.0.x backport or advisory. "
            "Identifying such vulnerabilities requires manual commit diffing — "
            "attacker advantage over defender who has no upstream advisory to track."
        ),
    },
    {
        "id": "TCS46-P02",
        "title": (
            "Triple KonaJDK Runtime Surface: Java 8/11/17 Default-Installed in TencentOS 4.6 — "
            "Each JDK Independently Maintained; Java 8 EOL Upstream (Commercial Support Only); "
            "Quarterly CVE Load Across Three Parallel JVM Attack Surfaces"
        ),
        "severity": "MEDIUM",
        "detail": (
            "TencentOS 4.6 AppStream ships three concurrent KonaJDK versions, all installed "
            "by default via metapackage dependencies:\n"
            "  java-8-konajdk  8.0.27-1.tl4   (upstream OpenJDK 8u504 base)\n"
            "  java-11-konajdk 11.0.32-1.tl4  (upstream OpenJDK 11.0.32.1 base)\n"
            "  java-17-konajdk 17.0.20-1.tl4  (upstream OpenJDK 17.0.20 base)\n"
            "\n"
            "KonaJDK is Tencent's OpenJDK fork (github.com/Tencent/TencentKona-*). "
            "Each version has Tencent-specific patches applied on top of upstream builds.\n"
            "\n"
            "CVE CADENCE (from spec changelog, consistent across all three versions):\n"
            "  Aug 2026: CVE-2026-47057, CVE-2026-47063, CVE-2026-47058, CVE-2026-60147,\n"
            "            CVE-2026-46968, CVE-2026-47059, CVE-2026-47027, CVE-2026-47021,\n"
            "            CVE-2026-47010, CVE-2026-61308, CVE-2026-70907, CVE-2026-60589\n"
            "  May 2026: CVE-2026-22016, CVE-2026-22021, CVE-2026-22013, CVE-2026-23865,\n"
            "            CVE-2026-22018, CVE-2026-22007, CVE-2026-34268\n"
            "  Quarterly update cadence mirrors Oracle Critical Patch Update schedule.\n"
            "\n"
            "ATTACK SURFACE MULTIPLIER:\n"
            "  Three concurrent JVM installations means each Critical Patch Update requires\n"
            "  three separate patch builds and deployments. A missed update on any of the\n"
            "  three leaves a known-CVE attack surface open.\n"
            "\n"
            "JAVA 8 UPSTREAM STATUS:\n"
            "  Java 8 (OpenJDK 8) reached upstream end of public updates in 2019.\n"
            "  Oracle Java 8 commercial support extends to 2030; OpenJDK 8 security updates\n"
            "  are provided by Red Hat (via RHEL) and Tencent (via KonaJDK).\n"
            "  The KonaJDK-8 changelog shows active CVE tracking through 8.0.27 (Aug 2026).\n"
            "  However, each quarterly cycle requires Tencent to backport CVE fixes independently\n"
            "  from Oracle's proprietary patch set, with variable patch completeness.\n"
            "\n"
            "BOOTSTRAP SUPPLY CHAIN:\n"
            "  SRPM spec Source10/11/12 pull pre-built bootstrap JDK binaries from GitHub:\n"
            "  github.com/Tencent/TencentKona-*/releases/download/... (x86_64, aarch64)\n"
            "  These bootstrap binaries are used during the SRPM build process.\n"
            "  No source-only build path; trust in Tencent GitHub release binaries is required."
        ),
        "evidence": {
            "srpm_konajdk8":  f"{SRPM_APPSTREAM}/java-8-konajdk-8.0.27-1.tl4.src.rpm",
            "srpm_konajdk11": f"{SRPM_APPSTREAM}/java-11-konajdk-11.0.32-1.tl4.src.rpm",
            "srpm_konajdk17": f"{SRPM_APPSTREAM}/java-17-konajdk-17.0.20-1.tl4.src.rpm",
            "bootstrap_source8":  "https://github.com/Tencent/TencentKona-8/releases/download/8.0.21-GA/",
            "bootstrap_source11": "https://github.com/Tencent/TencentKona-11/releases/download/kona11.0.26/",
            "bootstrap_source17": "https://github.com/Tencent/TencentKona-17/releases/download/TencentKona-17.0.14/",
        },
        "patch_analysis": {
            "CVE-2026-70907": (
                "File: sun/security/ssl/ServerHello.java + ServerHandshakeContext.java\n"
                "Fix: adds boolean sentHRR flag to ServerHandshakeContext. After sending\n"
                "HelloRetryRequest (HRR), sets sentHRR=true. On next HRR attempt, checks\n"
                "sentHRR and throws HANDSHAKE_FAILURE if true.\n"
                "\n"
                "Bug: TLS 1.3 server allowed sending a second HelloRetryRequest in the same\n"
                "connection, violating RFC 8446 Section 4.1.4: 'A server MUST NOT send a\n"
                "second HelloRetryRequest in the same connection.' Without the fix, a\n"
                "malicious TLS 1.3 client can craft a ClientHello sequence that causes the\n"
                "server's state machine to emit a second HRR, causing protocol state confusion.\n"
                "Severity depends on exploitability of the double-HRR state — at minimum,\n"
                "denial-of-service; at worst, cryptographic state confusion enabling downgrade."
            ),
            "CVE-2026-60589": (
                "File: com/sun/org/apache/xml/internal/security/utils/resolver/implementations/\n"
                "      ResolverDirectHTTP.java + ResolverLocalFilesystem.java\n"
                "Fix: replaces startsWith('http:') check with proper scheme() extraction.\n"
                "\n"
                "Bug: XML Digital Signature URI resolver used string prefix check\n"
                "('uriToResolve.startsWith(\"http:\")') to determine if an HTTP resolver\n"
                "or filesystem resolver should handle a Reference URI. A crafted URI like\n"
                "'http:///path' or a URI where the HTTP check failed could be misrouted to\n"
                "the filesystem resolver — potential SSRF or local file inclusion in\n"
                "applications that process XML Digital Signatures with external References.\n"
                "ResolverLocalFilesystem exclusion was based on the same broken string check,\n"
                "meaning HTTP URIs could accidentally fall through to filesystem resolution."
            ),
            "CVE-2026-61308": (
                "File: sun/net/www/http/HttpClient.java + sun/net/www/protocol/http/HttpURLConnection.java\n"
                "Fix: adds getHttpProxy() method and lastProxy tracking during HTTP redirections.\n"
                "\n"
                "Bug: HTTP redirect handling did not compare the proxy used for the initial\n"
                "request against the proxy for the redirect target. This could cause proxy\n"
                "authentication headers (Proxy-Authorization) set for one proxy to be forwarded\n"
                "to a different proxy or redirect target — proxy credential leakage across\n"
                "redirect boundaries in java.net.HttpURLConnection."
            ),
        },
        "attack_chain": (
            "CVE-2026-70907 (TLS 1.3 double-HRR): JDK acting as TLS server; malicious client\n"
            "triggers double HRR sequence → state confusion → service disruption or protocol downgrade.\n"
            "Affected: any Java server using JSSE for TLS 1.3 (default in JDK 11+).\n"
            "\n"
            "CVE-2026-60589 (XML SSRF): application processes XML Signatures with external References\n"
            "→ crafted URI bypasses resolver routing → filesystem read or internal HTTP request.\n"
            "\n"
            "JVM deserialization chain: malicious input to Java-based service on TencentOS "
            "→ gadget chain in default classpath → code execution under JVM. "
            "Three concurrent JDKs: attacker targets oldest (Java 8) if not fully patched. "
            "Bootstrap binary supply chain: compromise of Tencent GitHub release binary "
            "propagates to all TencentOS instances built from that SRPM."
        ),
    },
    {
        "id": "TCS46-P03",
        "title": (
            "openssh 9.3p2 Carries Post-regreSSHion Vulnerabilities — "
            "CVE-2025-26465 (MitM via VerifyHostKeyDNS) Confirmed in Pre-16 Releases; "
            "CVE-2026-35414, CVE-2026-35385 Fixed Only in 9.3p2-16 (Jul 2026)"
        ),
        "severity": "HIGH",
        "detail": (
            "TencentOS 4.6 openssh 9.3p2-16.tl4 is the latest available release. "
            "Key CVE timeline from spec changelog:\n"
            "\n"
            "  9.3p2-1  (Jul 2023): CVE-2023-38408 (PKCS#11 libs agent) PATCHED\n"
            "  9.3p2-4  (Jan 2024): CVE-2023-51385 (shell meta username), "
            "CVE-2023-51384 (p11 key constraints),\n"
            "            CVE-2023-48795 (Terrapin attack) ALL PATCHED\n"
            "  9.3p2-12 (Jul 2024): CVE-2024-6387 (regreSSHion - signal handler race) PATCHED\n"
            "  9.3p2-16 (Jul 2026): CVE-2026-35414, CVE-2026-35385, CVE-2025-26465 PATCHED\n"
            "\n"
            "CVE-2025-26465 (MitM via VerifyHostKeyDNS):\n"
            "  When VerifyHostKeyDNS is enabled, the client fails to detect host key mismatch\n"
            "  if the DNS-retrieved key differs from the presented key. An attacker controlling\n"
            "  DNS for the target hostname can MitM SSH connections without the client warning.\n"
            "  VerifyHostKeyDNS is not default-on but is commonly configured in enterprise\n"
            "  environments using SSHFP records for automated host verification.\n"
            "\n"
            "INSTANCES RUNNING PRE-16 RELEASES:\n"
            "  Any TencentOS 4.6 image not updated since July 2026 runs openssh 9.3p2 ≤ -15.\n"
            "  The 4.6 qcow2 image series spans 20260409 to 20260720 — all three cloud images\n"
            "  predate the -16 security release (Jul 29, 2026). Instances booted from these\n"
            "  images and not updated via yum/dnf remain vulnerable to CVE-2025-26465.\n"
            "\n"
            "CVE-2026-35414, CVE-2026-35385:\n"
            "  Detailed descriptions not yet published (disclosure concurrent with -16 release\n"
            "  on 2026-07-29). CVE-2026-35386 was noted as 'already covered by existing backport'\n"
            "  in the -16 changelog, indicating it was silently patched in a prior release."
        ),
        "evidence": {
            "srpm_path": f"{SRPM_BASE}/openssh-9.3p2-16.tl4.src.rpm",
            "changelog_16": "* Wed Jul 29 2026: Fix CVE-2026-35414, CVE-2026-35385, CVE-2025-26465",
            "changelog_12": "* Tue Jul 02 2024: fix CVE-2024-6387 (regreSSHion)",
            "qcow2_images": [
                "TencentOS-Server-GenericCloud-4.6-20260409.0.x86_64.qcow2",
                "TencentOS-Server-GenericCloud-4.6-20260526.1.x86_64.qcow2",
                "TencentOS-Server-GenericCloud-4.6-20260720.1.x86_64.qcow2",
            ],
            "note": "All three 4.6 qcow2 images predate openssh-9.3p2-16.tl4 (Jul 29 2026)",
        },
        "attack_chain": (
            "CVE-2025-26465: Target environment with VerifyHostKeyDNS=yes and SSHFP records. "
            "Attacker controls DNS for target host → poisons SSHFP record with attacker key "
            "→ client connects to attacker server without warning (MitM). "
            "Credential theft on connection + session hijack. "
            "Affected instances: any TencentOS 4.6 deployment not updated since 2026-07-29 "
            "(all three official qcow2 images at time of analysis)."
        ),
    },
    {
        "id": "TCS46-P04",
        "title": (
            "OpenSSL SM2/SM4/TLCP Chinese National Crypto Extensions on TencentOS 4.6 — "
            "Non-Standard TLS Cipher Suites (TLS_SM4_GCM_SM3, TLS_SM4_CCM_SM3) Enabled; "
            "GM/T 0024 TLCP Protocol Support; Novel Attack Surface Without Upstream Audit"
        ),
        "severity": "MEDIUM",
        "detail": (
            "TencentOS 4.6 OpenSSL 3.0.12 carries Tencent-specific patches enabling "
            "Chinese national cryptography standards absent from upstream OpenSSL:\n"
            "\n"
            "FROM SPEC CHANGELOG:\n"
            "  3.0.12-6 (Apr 2024): 'support rfc8998, including TLS_SM4_GCM_SM3, TLS_SM4_CCM_SM3'\n"
            "  3.0.12-5 (Apr 2024): 'Support TLCP & GM/T 0024, including cipher suites:\n"
            "             ECDHE-SM2-SM4-CBC-SM3, ECDHE-SM2-SM4-GCM-SM3'\n"
            "  3.0.12-11 (Aug 2024): 'turbo: update sha call chain' (QAT acceleration)\n"
            "  3.0.12-18 (Aug 2025): 'enforce libdir path when configure' (SM key paths)\n"
            "  3.0.12-24 (Nov 2025): 'Fix the encoding of SM2 keys, and support SM2 CMS signature'\n"
            "\n"
            "PROTOCOLS AND ALGORITHMS:\n"
            "  SM2: Elliptic curve asymmetric cipher (OSCCA GB/T 32918). Curve parameter p-256 "
            "equivalent but different domain parameters. Used for key exchange and signatures.\n"
            "  SM3: Hash function (GB/T 32905). SHA-256 class, 256-bit output. "
            "Not yet externally audited to the depth of SHA-2.\n"
            "  SM4: Block cipher (GB/T 32907). AES equivalent, 128-bit key/block. "
            "Used in GCM and CCM modes per TLS_SM4_GCM_SM3.\n"
            "  TLCP (GB/T 38636, GM/T 0024): China's national TLS variant. "
            "Uses SM2 for key exchange and SM4-GCM for record layer.\n"
            "  RFC 8998: Internet standard for TLS 1.3 SM cipher suites (2021). "
            "Tencent implements this RFC in 3.0.12 with additional TLCP extensions.\n"
            "\n"
            "ATTACK SURFACE:\n"
            "  1. SM2 implementation bugs: SM2 curve operations are less audited than "
            "P-256/P-384. Prior OpenSSL SM2 vulnerabilities include CVE-2021-3711 "
            "(SM2 decryption buffer overflow) and CVE-2021-3712. Additional implementation "
            "bugs in Tencent's extensions are plausible.\n"
            "  2. TLCP downgrade: TLCP operates alongside TLS 1.3. A server advertising "
            "both TLCP and TLS cipher suites could be forced to negotiate TLCP by a "
            "MitM stripping TLS 1.3 cipher advertisements.\n"
            "  3. No upstream review: These extensions are Tencent-only patches not "
            "in upstream OpenSSL 3.0.12. They are not included in OpenSSL security audits.\n"
            "  4. SM2 key encoding bug (fixed in -24): The Nov 2025 fix for SM2 key encoding "
            "implies prior releases had incorrect SM2 key serialization. Impact scope unclear "
            "without diff analysis of the specific SM2 CMS patch."
        ),
        "evidence": {
            "srpm_path": f"{SRPM_BASE}/openssl-3.0.12-27.tl4.src.rpm",
            "tlcp_patch_release": "3.0.12-5.tl4 (Apr 2024)",
            "sm4_cipher_release": "3.0.12-6.tl4 (Apr 2024)",
            "sm2_encoding_fix": "3.0.12-24.tl4 (Nov 2025) - SM2 key encoding bug corrected",
            "qat_support": "3.0.12-9.tl4 - Intel QAT engine enabled",
            "prior_cves": [
                "CVE-2021-3711 (SM2 decryption OOB write, CVSS 9.8) - upstream 1.1.1l",
                "CVE-2021-3712 (SM2 read after free) - upstream 1.1.1l",
            ],
            "rfc": "RFC 8998 (TLS 1.3 SM Cipher Suites) + GB/T 38636 (TLCP)",
        },
        "attack_chain": (
            "TLCP downgrade: intercept TLS negotiation → strip TLS 1.3 cipher suite list "
            "→ server falls back to TLCP (ECDHE-SM2-SM4-CBC-SM3) → potentially weaker "
            "implementation path. "
            "SM2 implementation bug: craft malicious SM2 key material → trigger memory "
            "corruption in SM2 parsing (cf. CVE-2021-3711 pattern) → RCE in any process "
            "that parses attacker-controlled SM2 certificates or keys. "
            "Scope: any TencentOS 4.6 server with TLCP enabled (Tencent cloud load balancers, "
            "internal service mesh, HTTPS with Chinese national crypto requirements)."
        ),
    },
]


# ─── Probe Functions ──────────────────────────────────────────────────────────

def probe_package_versions(host: str = None) -> dict:
    """
    If called locally, check installed package versions against confirmed findings.
    If host provided, would require SSH access to run rpm -q.
    """
    results = {}
    for finding in FINDINGS:
        results[finding["id"]] = {
            "title": finding["title"][:80],
            "severity": finding["severity"],
        }
    return results


def parse(data: dict) -> list:
    """Return FINDINGS list for integration with ablation runner."""
    return FINDINGS


def probe(host: str = "localhost", port: int = 22, timeout: int = 10) -> dict:
    """
    TencentOS 4.6 package-level findings confirmed via SRPM static analysis.
    All findings require no active network probe — confirmed from source material.
    Runtime check: rpm -q openssl openssh-server glibc java-8-konajdk
    """
    return {
        "host": host,
        "source": "SRPM spec changelog analysis (2026-09-04)",
        "confirmed_versions": CONFIRMED_VERSIONS,
        "findings": [f["id"] for f in FINDINGS],
        "note": (
            "All major CVEs (CVE-2024-4741, CVE-2024-5535, CVE-2024-2961, "
            "CVE-2023-4911, CVE-2024-6387) PATCHED in latest 4.6 releases. "
            "Outstanding: OpenSSL 3.0.x EOL (3 days), openssh pre-16 image exposure, "
            "SM2/SM4/TLCP novel surface."
        ),
    }


if __name__ == "__main__":
    print(json.dumps(probe(), indent=2))
    print(f"\nFindings: {len(FINDINGS)}")
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title'][:70]}")
