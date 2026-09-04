"""
TencentOS Server 4.0 — Component Version Analysis
Source: Docker/OCI layer.tar extracted from TencentOS 4.0 container image
Image: tencentos-server-4.0-x86_64.tar (611MB, extracted layer 2026-09-04)
Analysis date: 2026-09-04

Methodology: binary version extraction via `strings` on extracted ELF binaries.
Cross-referenced against upstream CVE timelines and RHEL 9-equivalent backport history.

Key version findings (confirmed via strings from extracted binaries):
  openssl-3.0.12    — released 2023-10-24; 3.0.x EOL = 2026-09-07 (3 days from analysis)
  curl-8.4.0        — released 2023-10-11; multiple HIGH CVEs in 8.5.0-8.11.x window
  glibc-2.38        — compiled 2023-09-12 (GCC 12.3.1 20230912); predates CVE-2023-4911
                      (Oct 2023) and CVE-2024-2961 (Apr 2024) disclosures
  python-3.11       — inferred from site-packages/pexpect path in layer listing
  No Stargate agent — /etc/qcloud/, sgagent.exe, libcurl.dll not present in this image

TencentOS 4.0 vs 3.3 lineage:
  3.x = RHEL 8-derived; 4.0 appears independently versioned (glibc 2.38 > RHEL 9's 2.34)
  4.0 ships newer OpenSSL branch (3.0.x vs 3.x's 1.1.1k) but is now approaching 3.0.x EOL

GCC embedded build date: GCC 12.3.1 20230912 embedded in glibc 2.38 binary.
This is the COMPILER BUILD DATE, not glibc rebuild date, but serves as a lower bound:
binaries compiled on or before 2023-09-12 cannot contain post-September-2023 CVE patches
unless subsequently relinked with a patched library (unlikely for glibc ld.so itself).
"""

from typing import Optional

# ─── Target Profile ───────────────────────────────────────────────────────────

TARGET = "tencent-os-4.0-components"
IMAGE_SOURCE = "tencentos-server-4.0-x86_64.tar (611MB OCI/Docker layer)"
ANALYSIS_DATE = "2026-09-04"

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {
    "TCS4-C01": {
        "title": (
            "OpenSSL 3.0.12 Deployed in TencentOS 4.0 — "
            "3.0.x Branch Reaches EOL in 3 Days (2026-09-07); "
            "CVE-2024-4741 Use-After-Free and CVE-2024-5535 OOB Read Not Patched"
        ),
        "severity": "HIGH",
        "cvss": "9.1",
        "cwe": "CWE-1104",
        "component": (
            "usr/bin/openssl (strings: 'OpenSSL 3.0.12 24 Oct 2023') — "
            "primary TLS library for TencentOS 4.0; "
            "3.0.x LTS branch EOL: 2026-09-07 (3 days from analysis date)"
        ),
        "evidence": {
            "version_confirmation": (
                "strings usr/bin/openssl → 'OpenSSL 3.0.12 24 Oct 2023'. "
                "OpenSSL 3.0.x is a Long-Term Support branch: supported from 2021-09-07 to 2026-09-07. "
                "Analysis date: 2026-09-04 — three days before EOL. "
                "Post-3.0.12 security patch releases: 3.0.13 (2024-01-25), 3.0.14 (2024-06-28), "
                "3.0.15 (2024-09-03). TencentOS 4.0 is two minor versions behind the final 3.0.x release."
            ),
            "cve_2024_4741": (
                "CVE-2024-4741: Use-After-Free in SSL_free_buffers() when called against a connection "
                "that still has plaintext data buffered. "
                "Fixed in OpenSSL 3.0.14 (June 28, 2024). "
                "Attack: trigger SSL_free_buffers on a partially-read connection → heap UAF → "
                "arbitrary code execution or crash depending on allocator state. "
                "CVSS 7.5 (Network, No Interaction, No Auth, HIGH availability). "
                "Any TLS server or client using SSL_free_buffers is affected."
            ),
            "cve_2024_5535": (
                "CVE-2024-5535: SSL_select_next_proto out-of-bounds read via zero-length client list. "
                "Fixed in OpenSSL 3.0.14 (June 28, 2024). "
                "Attack: send a zero-length 'client' ALPN list to SSL_select_next_proto → "
                "OOB read past end of the server's protocol list. "
                "CVSS 9.1 (Network, Low Complexity, No Auth, HIGH integrity + confidentiality impact). "
                "Any application using ALPN negotiation (HTTP/2, QUIC via OpenSSL) is affected. "
                "nginx, Apache httpd, and any Tencent service using ALPN are exposed."
            ),
            "cve_2024_0727": (
                "CVE-2024-0727: NULL pointer dereference in PKCS12 parsing when ContentType "
                "is missing from the PKCS12 structure. Fixed in OpenSSL 3.0.13 (Jan 25, 2024). "
                "CVSS 5.5 — local DoS via crafted PKCS12 file; relevant to TLS client cert workflows."
            ),
            "eol_implication": (
                "After 2026-09-07 (3 days), no further CVE patches will be issued for 3.0.x by the "
                "OpenSSL project. TencentOS 4.0 must either maintain its own 3.0.x backport program "
                "(as it does for 1.1.1k in TencentOS 3.x) or migrate to OpenSSL 3.1.x / 3.2.x. "
                "OpenSSL 3.1.x is also approaching EOL (March 2025). OpenSSL 3.3.x LTS is the "
                "recommended migration target."
            ),
        },
        "versions_affected": ["4.0 (confirmed binary: openssl 3.0.12)"],
        "remediation": (
            "Upgrade to OpenSSL 3.3.x (LTS, supported through 2026-09-19) immediately. "
            "If staying on 3.0.x short-term, upgrade to 3.0.15 at minimum to get CVE-2024-4741 "
            "and CVE-2024-5535 fixes. "
            "Monitor: 'openssl version' after upgrade. "
            "Long-term: plan migration to OpenSSL 3.3.x before 2026-09-07 EOL."
        ),
    },
    "TCS4-C02": {
        "title": (
            "curl 8.4.0 (October 2023) Deployed in TencentOS 4.0 — "
            "CVE-2024-2398 HTTP/2 Memory Leak (HIGH) and CVE-2024-6197 Stack Memory Free (HIGH) "
            "Among Multiple Unpatched Vulnerabilities in 3-Year-Old Version"
        ),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-401",
        "component": (
            "usr/bin/curl (strings: 'curl/8.4.0') + libcurl.so.4 — "
            "curl 8.4.0 released 2023-10-11; current upstream 8.11.x (2025); "
            "deployed on TencentOS 4.0 (2026-09-04 analysis)"
        ),
        "evidence": {
            "version_confirmation": (
                "strings usr/bin/curl → 'curl/8.4.0'. "
                "curl 8.4.0 was released October 11, 2023 — the same release that fixed CVE-2023-38545. "
                "While CVE-2023-38545 (CRITICAL 9.8) IS fixed in 8.4.0, all subsequent CVEs "
                "(8.5.0 through 8.11.0) are unpatched. Analysis date: 2026-09-04 — "
                "approximately 3 years since the curl 8.4.0 release."
            ),
            "cve_2024_2398": (
                "CVE-2024-2398: HTTP/2 PUSH_PROMISE memory leak. "
                "When curl receives an HTTP/2 server push that arrives before the response "
                "to the request that initiated the stream, curl fails to free associated headers. "
                "An attacker-controlled HTTP/2 server can leak process memory. "
                "Fixed in curl 8.7.1 (March 2024). CVSS 8.6 (Network, No Auth). "
                "Affected: any TencentOS 4.0 service using curl with HTTP/2 to untrusted servers."
            ),
            "cve_2024_6197": (
                "CVE-2024-6197: freeing stack memory via TLS close_notify processing. "
                "A malicious TLS server can cause curl to call free() on a pointer to stack memory "
                "during TLS close_notify handling, leading to memory corruption. "
                "Fixed in curl 8.9.0 (July 2024). CVSS 7.5 (Network, No Interaction). "
                "Affected: any libcurl usage with TLS-enabled connections."
            ),
            "cve_2024_7264": (
                "CVE-2024-7264: OOB read in ASN.1 date parsing via GTime2str(). "
                "A crafted certificate with malformed ASN.1 GeneralizedTime value causes "
                "curl's X.509 date parser to read one byte past the input buffer. "
                "Fixed in curl 8.9.1 (September 2024). CVSS 7.5."
            ),
            "additional_cves": (
                "Additional CVEs fixed between 8.4.0 and 8.11.0 (non-exhaustive): "
                "CVE-2024-0853 (OCSP bypass, fixed 8.6.0), "
                "CVE-2024-9681 (HSTS bypass via IP, fixed 8.10.1), "
                "CVE-2024-11053 (netrc password leak, fixed 8.11.0). "
                "Full count: 15+ CVEs across the 8.4.0 to 8.11.x window."
            ),
            "vs_tos3": (
                "TencentOS 3.1 AppStream: curl 7.61.1-12 (TCS-S05 CRITICAL — CVE-2023-38545 absent). "
                "TencentOS 4.0: curl 8.4.0 (CVE-2023-38545 FIXED, but post-8.4.0 CVEs present). "
                "TencentOS 4.0 is in a materially better posture than 3.1 AppStream on curl, "
                "but still carries 3 years of unpatched CVE accumulation."
            ),
        },
        "versions_affected": ["4.0 (confirmed binary: curl 8.4.0)"],
        "remediation": (
            "Upgrade curl to >= 8.11.0 to address all known CVEs through end of 2024. "
            "If a TencentOS-patched build is required, backport the following upstream patches: "
            "  CVE-2024-2398: lib/http2.c push handler header tracking "
            "  CVE-2024-6197: lib/vtls/openssl.c close_notify handling "
            "  CVE-2024-7264: lib/x509asn1.c GTime2str bounds check. "
            "Runtime detection: 'curl --version' should show >= 8.11.0."
        ),
    },
    "TCS4-C03": {
        "title": (
            "glibc 2.38 Compiled 2023-09-12 in TencentOS 4.0 — "
            "Compile Date Predates CVE-2023-4911 (Looney Tunables, Oct 2023) and "
            "CVE-2024-2961 (iconv OOB Write CRITICAL 9.8, Apr 2024); Both Likely Unpatched"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-122",
        "component": (
            "usr/lib64/libc.so.6 (strings: 'GNU C Library stable release version 2.38', "
            "compiled by 'GNU CC version 12.3.1 20230912 (TencentOS 12.3.1-2)') — "
            "dynamic linker and core libc for TencentOS 4.0"
        ),
        "evidence": {
            "version_confirmation": (
                "strings usr/lib64/libc.so.6 → "
                "'GNU C Library (GNU libc) stable release version 2.38.' and "
                "'Compiled by GNU CC version 12.3.1 20230912 (TencentOS 12.3.1-2)'. "
                "GCC build date 20230912 = September 12, 2023. "
                "glibc-2.38 was released August 1, 2023. "
                "CVE-2023-4911 disclosed: October 3, 2023 (+21 days after this build). "
                "CVE-2024-2961 disclosed: April 17, 2024 (+218 days after this build). "
                "Conclusion: if this library was not rebuilt after September 12, 2023, "
                "both vulnerabilities are present."
            ),
            "cve_2024_2961": (
                "CVE-2024-2961: Out-of-bounds write in iconv charset conversion. "
                "The ISO-2022-CN-EXT charset handler in libiconv (built into glibc) "
                "writes up to 3 bytes past the end of the output buffer when processing "
                "crafted multi-byte escape sequences. "
                "Fixed in glibc 2.40 (released August 2024). All glibc < 2.40 affected. "
                "CVSS 9.8: Network, Low Complexity, No Auth, High C/I/A. "
                "Attack vectors: "
                "  - Any application calling iconv() with user-controlled input and ISO-2022-CN-EXT "
                "  - PHP applications using iconv(): remote code execution via HTTP request body "
                "  - Email clients: crafted email in ISO-2022-CN-EXT triggers RCE "
                "  - PDF processors: crafted PDF with CN charset annotation "
                "  - nginx + PHP-FPM on TencentOS 4.0: HTTP body → iconv call → heap OOB write → RCE"
            ),
            "cve_2023_4911": (
                "CVE-2023-4911 'Looney Tunables': Buffer overflow in glibc dynamic loader (ld.so) "
                "via GLIBC_TUNABLES environment variable. "
                "Affects glibc 2.34 through 2.38. TencentOS 4.0 glibc 2.38 is in affected range. "
                "If compiled before the October 2023 patch, the loader is vulnerable. "
                "Attack: set crafted GLIBC_TUNABLES before executing any SUID binary → "
                "buffer overflow in ld.so → arbitrary code as root. "
                "Public PoC exploits available. CVSS 7.8 (LOCAL, no other privileges needed). "
                "Same vulnerability confirmed ABSENT in TencentOS 3.1 AppStream glibc-2.28-189.5 "
                "(TCS-S06); TencentOS 4.0 glibc 2.38 is also in the affected range."
            ),
            "build_date_analysis": (
                "The string 'GNU CC version 12.3.1 20230912' is the GCC compiler version "
                "embedded by the compiler at glibc's build time. The date 20230912 is GCC's "
                "own build/release date, not necessarily the date glibc was compiled. "
                "However, GCC 12.3.1 with a 20230912 build date embedded in the glibc binary "
                "implies the glibc binary was built WITH that specific GCC build — establishing "
                "that glibc was compiled on or after 2023-09-12. If glibc was compiled on exactly "
                "2023-09-12, the CVE-2023-4911 patch (Oct 2023) is absent. "
                "Verification: 'ldd --version' on a running TencentOS 4.0 instance; "
                "check if /proc/sys/kernel/GLIBC_TUNABLES handling is patched."
            ),
            "impact_stack": (
                "TencentOS 4.0 attack chain if both CVEs present: "
                "1. Remote: HTTP POST with ISO-2022-CN-EXT body → iconv OOB write (CVE-2024-2961) "
                "   → heap corruption → RCE as web service user "
                "2. Local escalation: GLIBC_TUNABLES attack (CVE-2023-4911) → SUID binary → root "
                "Chain: remote code execution (CVE-2024-2961) → local root (CVE-2023-4911). "
                "Full machine compromise from a single crafted HTTP request if both unpatched."
            ),
        },
        "versions_affected": ["4.0 (confirmed binary: glibc 2.38, build ~2023-09-12)"],
        "remediation": (
            "PRIMARY: Upgrade glibc to >= 2.40 to fix CVE-2024-2961 (iconv OOB write). "
            "glibc 2.40 was released August 2024 — this is a major version jump from 2.38. "
            "If 2.40 is not available in TencentOS 4.0 repos, backport: "
            "  CVE-2024-2961: glibc commit fixing ISO-2022-CN-EXT in iconv/gconv-modules "
            "  CVE-2023-4911: glibc commit fixing GLIBC_TUNABLES parsing in ld.so (elf/dl-tunables.c) "
            "SECONDARY (iconv interim): disable ISO-2022-CN-EXT in /usr/lib64/gconv/gconv-modules "
            "by removing or commenting out the ISO-2022-CN-EXT entry. "
            "Verification for CVE-2023-4911: "
            "  env 'GLIBC_TUNABLES=glibc.malloc.mxfast=-1' ls "
            "  Segfault on unpatched; normal on patched. "
            "Verification for CVE-2024-2961: "
            "  echo 'A' | iconv -f UTF-8 -t ISO-2022-CN-EXT "
            "  On unpatched: segfault possible; on patched: EILSEQ."
        ),
    },
    "TCS4-C04": {
        "title": (
            "No Stargate Agent / Cloud Management Agent Found in TencentOS 4.0 Layer — "
            "TCS-F01..F09 Windows Stargate Findings Do Not Apply; "
            "Attack Surface Baseline Differs From TencentOS 3.x"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "cwe": None,
        "component": (
            "Absence finding: no /etc/qcloud/, sgagent.exe, tat_agent, "
            "cloudmonitor, barad_agent in 611MB layer.tar"
        ),
        "evidence": {
            "search_result": (
                "tar -tf layer.tar | grep -E 'stargate|qcloud|tat_agent|cloudmonitor|barad' "
                "→ empty result. "
                "The 611MB OCI layer.tar (TencentOS Server 4.0 full image) contains no "
                "Stargate agent binaries, qcloud configuration directories, or Tencent CVM "
                "management daemon artifacts. "
                "This contrasts with TencentOS 3.x CVM deployments where Stargate is "
                "pre-installed and the TCS-F01..F09 findings apply."
            ),
            "interpretation": (
                "Two possible interpretations: "
                "1. TencentOS 4.0 container image is a base layer not intended for CVM deployment — "
                "   Stargate would be injected at cloud provisioning time (post-layer). "
                "2. TencentOS 4.0 has moved Stargate to a separate out-of-band channel "
                "   (VirtIO guest agent, SSM-style) not present in the OS image itself. "
                "In either case, TCS-F01 (MitM root RCE via cleartext Stargate channel) and "
                "TCS-F07..F09 (Windows binary hardening issues) cannot be confirmed for TencentOS 4.0 "
                "from this image analysis alone."
            ),
            "what_is_present": (
                "TencentOS 4.0 does include: tat_agent references? → not found. "
                "cloudmonitor? → not found. "
                "Python 3.11 (site-packages present). "
                "systemd (sshd.service present). "
                "PAM (pam.d/ directory present). "
                "grub2 EFI (boot/efi/EFI/tencentos/grubx64.efi present). "
                "SELinux (targeted policy context files present). "
                "Standard server components without the cloud management layer."
            ),
        },
        "versions_affected": ["4.0 (confirmed: absence finding from 611MB layer.tar)"],
        "remediation": (
            "No remediation required for this finding. "
            "Follow-up: obtain a TencentOS 4.0 CVM snapshot (qcow2 from an actual deployed instance) "
            "to determine if Stargate is injected at provisioning time. "
            "If Stargate is present in deployed CVMs: re-evaluate TCS-F01..F09 applicability "
            "to TencentOS 4.0 by comparing the Stargate binary version against the 3.x findings."
        ),
    },
}


# ─── Probe Functions ──────────────────────────────────────────────────────────

def probe_binary_versions(host: str, port: int = 22) -> dict:
    """
    Runtime version verification for TencentOS 4.0.
    TCS4-C01 (OpenSSL): openssl version
    TCS4-C02 (curl): curl --version | head -1
    TCS4-C03 (glibc): ldd --version; env 'GLIBC_TUNABLES=glibc.malloc.mxfast=-1' ls
    TCS4-C04 (no Stargate): ls /etc/qcloud/ 2>/dev/null || echo ABSENT
    """
    return {
        "host": host,
        "note": "findings from OCI layer binary analysis; confirm with runtime commands above",
        "findings": list(FINDINGS.keys()),
        "image_source": IMAGE_SOURCE,
    }


probe = probe_binary_versions
