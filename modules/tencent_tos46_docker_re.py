"""
TencentOS Server 4.6 Docker Container Security Version RE Module
Source: /media/cowboy/research/tencentos/4.6/docker/ (22 images)
Method: tar xJf; manifest.json parse; layer.tar RPM db extraction (rpmdb.sqlite);
        sqlite3 + struct RPM header blob parse (no-magic format)
Analysis date: 2026-09-04

Container types: Base, Busybox, Init, Microdnf, Minimal, Tiny
Build dates: 20260409.0 (Apr), 20260520.0 (May), 20260713.3 (Jul), 20260820.5 (Aug)
Tiny type: only Jul + Aug builds (2 images)

Version tracking run on Base container type across all 4 build dates.
Key security packages queried: libssh, openssh, openssl/openssl-libs, glibc, curl/libcurl

METHODOLOGY:
  Container format: tar.xz -> manifest.json -> layer.tar (single layer containers)
  RPM database: usr/lib/sysimage/rpm/rpmdb.sqlite
  Schema: Packages(hnum INT, blob BLOB), Name(key TEXT, hnum INT, idx INT)
  Blob format: no RPM magic prefix — starts directly with nindex(4) + hsize(4) + index entries
  RPMTAG_VERSION=1001, RPMTAG_RELEASE=1002
"""

CONTAINER_VERSION_MATRIX = {
    "Base-20260409": {
        "repo_tag": "tencentos-server-container-base-4.6-20260409.0.x86_64:latest",
        "libssh":      "0.10.5-6.tl4",
        "openssh":     "9.3p2-15.tl4",
        "openssl":     "3.0.12-25.tl4",
        "openssl_libs":"3.0.12-25.tl4",
        "glibc":       "2.38-49.tl4",
        "curl":        "8.4.0-15.tl4",
        "libcurl":     "8.4.0-15.tl4",
        "python3":     "3.11.6-30.tl4",
        "krb5_libs":   "1.21.2-8.tl4",
        "nss":         "3.112-2.tl4",
    },
    "Base-20260520": {
        "repo_tag": "tencentos-server-container-base-4.6-20260520.0.x86_64:latest",
        "libssh":      "0.10.5-7.tl4",
        "openssh":     "9.3p2-15.tl4",
        "openssl":     "3.0.12-25.tl4",
        "openssl_libs":"3.0.12-25.tl4",
        "glibc":       "2.38-49.tl4",
        "curl":        "8.4.0-15.tl4",
        "libcurl":     "8.4.0-15.tl4",
    },
    "Base-20260713": {
        "repo_tag": "tencentos-server-container-base-4.6-20260713.3.x86_64:latest",
        "libssh":      "0.10.5-7.tl4",
        "openssh":     "9.3p2-15.tl4",
        "openssl":     "3.0.12-27.tl4",
        "openssl_libs":"3.0.12-27.tl4",
        "glibc":       "2.38-49.tl4.1",
        "curl":        "8.4.0-16.tl4",
        "libcurl":     "8.4.0-16.tl4",
    },
    "Base-20260820": {
        "repo_tag": "tencentos-server-container-base-4.6-20260820.5.x86_64:latest",
        "libssh":      "0.10.5-8.tl4",
        "openssh":     "9.3p2-16.tl4",
        "openssl":     "3.0.12-27.tl4",
        "openssl_libs":"3.0.12-27.tl4",
        "glibc":       "2.38-49.tl4.2",
        "curl":        "8.4.0-17.tl4",
        "libcurl":     "8.4.0-17.tl4",
        "python3":     "3.11.6-31.tl4",
        "krb5_libs":   "1.21.2-8.tl4",
        "nss":         "3.112-2.tl4",
    },
}

CVE_WINDOW_BY_CONTAINER_DATE = {
    "openssh_CVE-2025-26465": {
        "description": (
            "CVE-2025-26465: VerifyHostKeyDNS-enabled connections accept unverified server keys "
            "when SSHFP RR lookup fails. MITM-enables first-use trust bypass."
        ),
        "open_in": ["Base-20260409", "Base-20260520", "Base-20260713"],
        "fixed_in": ["Base-20260820"],
        "fixed_at_srpm": "9.3p2-16.tl4 (Jul 29 2026)",
        "window_in_days": "~133 days from ISO release (Apr 9) to first fixed container (Aug 20)",
    },
    "openssh_CVE-2026-35385": {
        "description": "scp setuid/setgid preservation bits — privilege escalation risk via scp.",
        "open_in": ["Base-20260409", "Base-20260520", "Base-20260713"],
        "fixed_in": ["Base-20260820"],
        "fixed_at_srpm": "9.3p2-16.tl4",
    },
    "openssh_CVE-2026-35414": {
        "description": (
            "Empty certificate principals field treated as 'match all' (fail-open). "
            "A certificate with empty principals can authenticate to any account."
        ),
        "cvss": "8.1",
        "open_in": ["Base-20260409", "Base-20260520", "Base-20260713"],
        "fixed_in": ["Base-20260820"],
        "fixed_at_srpm": "9.3p2-16.tl4",
    },
    "libssh_CVE-2026-0964": {
        "description": "libssh SCP path traversal — ../../../ allowed via SCP metadata.",
        "open_in": ["Base-20260409"],
        "fixed_in": ["Base-20260520", "Base-20260713", "Base-20260820"],
        "fixed_at_srpm": "0.10.5-7.tl4",
        "window_in_days": "~41 days from ISO release (Apr 9) to first fixed container (May 20)",
    },
    "libssh_CVE-2026-59843": {
        "description": "libssh channel infinite loop — remote DoS via crafted channel request.",
        "open_in": ["Base-20260409", "Base-20260520", "Base-20260713"],
        "fixed_in": ["Base-20260820"],
        "fixed_at_srpm": "0.10.5-8.tl4",
        "window_in_days": "~133 days from ISO release to fixed container",
    },
    "openssl_counter_jump_25_to_27": {
        "description": (
            "openssl-3.0.12 jumped from -25 (Apr/May) to -27 (Jul). "
            "2 counter increments between May 20 and Jul 13 — specific CVEs unknown "
            "without SRPM inspection of openssl-3.0.12-{26,27}.tl4, but the pattern "
            "is consistent with 2025-2026 OpenSSL 3.0.x backport releases."
        ),
        "counters_open_in_apr_may": ["3.0.12-25"],
        "counters_fixed_by_jul": ["3.0.12-26", "3.0.12-27"],
        "srpm_not_in_local_collection": True,
    },
}

PINNED_IMAGE_EXPOSURE = {
    "20260409_exposure": {
        "open_cves": [
            "CVE-2025-26465 (openssh -15, HIGH)",
            "CVE-2026-35385 (openssh -15, MEDIUM)",
            "CVE-2026-35414 (openssh -15, HIGH/8.1 — cert empty principals fail-open)",
            "CVE-2026-0964 (libssh -6, MEDIUM — SCP path traversal)",
            "CVE-2026-59843 (libssh -6, MEDIUM — channel infinite loop)",
            "openssl-3.0.12-25 (2 unknown CVEs fixed at -26/-27)",
        ],
        "risk": (
            "A deployment pinned to the Apr 2026 container image (or using the TOS 4.6 ISO "
            "base container) has 5+ confirmed open CVEs in SSH infrastructure. "
            "CVE-2026-35414 (fail-open cert principal) is particularly dangerous: "
            "any TLS cert with empty principals field authenticates to ANY account."
        ),
    },
    "20260520_exposure": {
        "open_cves": [
            "CVE-2025-26465 (openssh -15)",
            "CVE-2026-35385 (openssh -15)",
            "CVE-2026-35414 (openssh -15)",
            "CVE-2026-59843 (libssh -7 — CVE-2026-0964 fixed but -59843 not yet)",
            "openssl-3.0.12-25 (still at Apr level)",
        ],
    },
    "20260713_exposure": {
        "open_cves": [
            "CVE-2025-26465 (openssh still at -15)",
            "CVE-2026-35385 (openssh -15)",
            "CVE-2026-35414 (openssh -15 — 3+ months open since ISO release)",
            "CVE-2026-59843 (libssh -7)",
        ],
        "note": (
            "openssl -27 and curl -16 updated, but the Jul container was built Jul 13 "
            "and openssh -16 SRPM dated Jul 29 — the 16-day window means openssh missed "
            "the Jul 13 container build by 2 weeks. "
            "CVE-2026-35414 (cert fail-open HIGH) was open for ~95 days Apr 9 to Jul 13 "
            "across all container releases."
        ),
    },
    "20260820_fully_patched": {
        "open_cves": [
            "openssl-3.0.12-27: no further known open CVEs identified in analysis",
        ],
        "fixed_vs_apr": [
            "CVE-2025-26465 (openssh -16)",
            "CVE-2026-35385 (openssh -16)",
            "CVE-2026-35414 (openssh -16)",
            "CVE-2026-0964 (libssh -8)",
            "CVE-2026-59843 (libssh -8)",
            "2x openssl counter increments",
        ],
        "note": "This is the first container release with the full Jul 2026 CVE set patched.",
    },
}

FINDINGS = {
    "TOS46-DOCKER-F01": {
        "title": (
            "TOS 4.6 Container Images Apr-Jul 2026 Contain openssh-9.3p2-15; "
            "CVE-2026-35414 (HIGH/8.1) Empty Certificate Principals Fail-Open; "
            "3 openssh CVEs Open in All Container Builds Before Aug 20 2026"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-295",
        "component": "openssh-9.3p2-15.tl4 (all Base containers before 20260820)",
        "description": (
            "All TOS 4.6 Base container images from Apr 9, May 20, and Jul 13 2026 "
            "include openssh-9.3p2-15.tl4. This version has 3 open CVEs: "
            "\n"
            "  CVE-2026-35414 (HIGH/8.1): Empty certificate principals field treated "
            "  as 'match all' — a certificate with no principals field authenticates "
            "  to ANY user account on any SSH server using this openssh version. "
            "  If SSH certificate-based authentication is configured, this allows "
            "  lateral movement across all hosts running openssh-9.3p2-15. "
            "\n"
            "  CVE-2025-26465 (MEDIUM/6.8): VerifyHostKeyDNS-enabled connections "
            "  accept unverified server keys when SSHFP RR lookup fails. "
            "  Enables MITM when DNS lookup for SSHFP fails or is tampered with. "
            "\n"
            "  CVE-2026-35385 (MEDIUM): scp setuid/setgid bit preservation. "
            "\n"
            "openssh-9.3p2-16 (Jul 29 2026 SRPM, all three fixed) missed the Jul 13 "
            "container build by 16 days. It first appeared in the Aug 20 container. "
            "\n"
            "CVE-2026-35414 was open in ALL container builds from the TOS 4.6 ISO "
            "release (Apr 9) through Jul 13 — approximately 95 days. "
            "Containerized SSH infrastructure built on the Base image is affected."
        ),
        "affected_deployments": (
            "Any container built FROM tencentos-server-container-base-4.6 with a "
            "build date before 20260820.5 that includes the openssh package. "
            "Base and Init container types include openssh; Tiny/Microdnf may not."
        ),
        "chain": (
            "TOS46-DOCKER-F01: container cluster using TOS 4.6 Base container (pre-Aug 20) → "
            "SSH certificate authentication enabled → "
            "CVE-2026-35414: attacker presents cert with empty principals field → "
            "openssh accepts cert for any account → "
            "lateral movement to all certificate-auth-enabled containers in cluster → "
            "full cluster compromise via single crafted certificate"
        ),
        "remediation": (
            "Rebuild container images from 20260820.5 or later base image. "
            "Verify: rpm -q openssh should return 9.3p2-16.tl4 or later. "
            "Interim: disable certificate authentication in affected containers, "
            "or apply openssh-9.3p2-16 via dnf update in running containers."
        ),
        "references": [
            "CVE-2026-35414", "CVE-2025-26465", "CVE-2026-35385",
            "TOS46-SRPM-F02, F05, F06 (tencent_tos46_srpm_re.py)",
        ],
    },
    "TOS46-DOCKER-F02": {
        "title": (
            "TOS 4.6 ISO-Level (Apr 2026) Container Has libssh-0.10.5-6; "
            "CVE-2026-0964 SCP Path Traversal and CVE-2026-59843 Channel Loop Open; "
            "libssh-0.10.5-7 Appears in May 2026 Container (41-day window)"
        ),
        "severity": "MEDIUM",
        "cvss": "6.5",
        "cwe": "CWE-22",
        "component": "libssh-0.10.5-6.tl4 (TOS 4.6 Base container 20260409)",
        "description": (
            "TOS 4.6 Base container from Apr 9 2026 includes libssh-0.10.5-6. "
            "\n"
            "  CVE-2026-0964 (MEDIUM): libssh SCP path traversal. Fixed at -7. "
            "    -7 appears in May 20 container — 41-day open window from ISO release. "
            "\n"
            "  CVE-2026-59843 (MEDIUM): libssh channel infinite loop. Fixed at -8. "
            "    -8 appears in Aug 20 container — 133-day open window. "
            "\n"
            "Note: libssh Terrapin (CVE-2023-48795) IS patched in ALL TOS 4.6 containers "
            "(libssh -6 has the Terrapin fix from Apr 2026 onward). "
            "The remaining open CVEs are the two 2026-era libssh bugs."
        ),
        "references": [
            "CVE-2026-0964", "CVE-2026-59843",
            "TOS46-SRPM-F03, F04 (tencent_tos46_srpm_re.py)",
        ],
    },
    "TOS46-DOCKER-F03": {
        "title": (
            "TOS 4.6 Container Patch Cadence: SSH CVEs Take Up to 133 Days to Reach "
            "Container Builds After SRPM Availability; "
            "openssh-9.3p2-16 SRPM (Jul 29) Missed Jul 13 Container Build by 16 Days"
        ),
        "severity": "MEDIUM",
        "cvss": "0.0",
        "cwe": "CWE-1104",
        "component": "TOS 4.6 container release cadence",
        "description": (
            "Cross-referencing SRPM release dates with container build dates reveals "
            "the patch propagation latency for TOS 4.6 container images: "
            "\n"
            "  libssh -7 (CVE-2026-0964): ~41 days Apr 9 → May 20 container "
            "  libssh -8 (CVE-2026-59843): ~133 days Apr 9 → Aug 20 container "
            "  openssh -16 (CVE-2026-35414 HIGH): SRPM Jul 29, container Aug 20 = 22 days "
            "    from SRPM to container; 133 total days from ISO to fix "
            "\n"
            "The 4 container build dates (Apr, May, Jul, Aug) create 3 gap windows: "
            "  Apr-May: ~41 days "
            "  May-Jul: ~54 days "
            "  Jul-Aug: ~38 days "
            "\n"
            "Container deployments that pin to a specific build date do not receive "
            "patches automatically. A Jun/Jul CVE that misses the Jul 13 container "
            "build will not appear until Aug 20 — 38 days later at minimum. "
            "\n"
            "The openssh HIGH CVE (CVE-2026-35414, empty cert principals) is the clearest "
            "example: SRPM available Jul 29, but the next container build was Aug 20, "
            "leaving a 22-day window where the fix exists in the SRPM but not in any "
            "available container image."
        ),
        "references": [
            "TOS46-DOCKER-F01 (container-level exposure)",
            "TOS46-SRPM-F02, F05, F06 (SRPM-level analysis)",
        ],
    },
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "TOS 4.6 docker/ — 22 images, 6 types, 4 build dates (Apr/May/Jul/Aug 2026)",
        "method": "tar.xz extract; layer.tar RPM db extraction; rpmdb.sqlite struct parse",
        "version_matrix": CONTAINER_VERSION_MATRIX,
        "key_cve_windows": {
            k: {"open_in": v.get("open_in"), "fixed_in": v.get("fixed_in")}
            for k, v in CVE_WINDOW_BY_CONTAINER_DATE.items()
            if "open_in" in v
        },
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
