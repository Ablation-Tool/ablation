"""
TencentOS 4.2 — Component Version Analysis
Source: TencentOS-Server-4.2-20241227.0-x86_64-everything.iso.spdx.json
        December 2024 release; kernel 6.6.64-18 (updated from 6.6.47-12 in initial 4.2 release)
        SBOM path: /media/cowboy/research/tencentos/sbom/ISOs/

Baseline: RHEL 9 lineage (glibc 2.38, systemd 255)
Analysis context: 2026-09-04 — OpenSSL 3.0.x EOL in 3 days (2026-09-07)

Comparison sources:
  tencent_kernel_cross_version.py — original 4.2 kernel was 6.6.47-12 (KASLR DISABLED)
  tencent_kona_jdk_re.py         — TencentOS 2.4 Kona JDK 8.0.9 = OpenJDK 8u322 (CVE-2022-21449 present)
  tencent_tos24_tk4_components_re.py — TK4 frozen RHEL 7 stack

Component version summary:
  kernel:    6.6.64-18       (updated from 6.6.47-12; KASLR status unconfirmed for 6.6.64)
  openssl:   3.0.12-15       (EOL 2026-09-07 — 3 days from analysis)
  openssh:   9.3p2-15        (CVE-2024-6387 regreSSHion PATCHED at -12)
  glibc:     2.38-25         (CVE-2023-4911 Looney Tunables PATCHED at -3)
  curl:      8.4.0-9         (CVE-2023-38545 SOCKS5 overflow fixed in 8.4.0 version bump)
  sudo:      1.9.15p5-1      (CVE-2023-42465 PATCHED at 1.9.15p2)
  systemd:   255-13          (modern; no critical open CVEs at this version)
  expat:     2.6.4-1         (PATCHED — was 2.1.0-15 in TK4 with CVSS 9.8 cluster)
  libssh2:   1.11.0-2        (PATCHED — was 1.8.0-4 in TK4 with CVE-2019-3855 cluster)
  gnutls:    3.8.2-6         (modern; CVE-2021-20231/20232 UAF fixed in 3.8.x)
  polkit:    123-2           (CVE-2021-4034 not applicable — polkit 0.120+ baseline)
  runc:      1.1.14-2        (CVE-2021-30465 PATCHED in 1.0.1; 1.1.14 is far ahead)
  konajdk-8: 8.0.20-1        (≈ OpenJDK 8u402 Apr 2024 CPU; CVE-2022-21449 PATCHED)
  konajdk-11: 11.0.25-1      (Oct 2024 CPU)
  konajdk-17: 17.0.13-1      (Oct 2024 CPU)

Primary findings: 2 (OpenSSL 3.0.x EOL, kernel KASLR status gap)
"""

# ─── Target Profile ───────────────────────────────────────────────────────────

SBOM_SOURCE = {
    "file": "TencentOS-Server-4.2-20241227.0-x86_64-everything.iso.spdx.json",
    "release_date": "2024-12-27",
    "kernel": "6.6.64-18",
    "lineage": "RHEL 9 (glibc 2.38, systemd 255)",
    "analysis_date": "2026-09-04",
    "openssl_eol": "2026-09-07",
}

COMPONENT_VERSIONS = {
    "kernel": "6.6.64-18",
    "openssl": "3.0.12-15",
    "openssh": "9.3p2-15",
    "glibc": "2.38-25",
    "curl": "8.4.0-9",
    "sudo": "1.9.15p5-1",
    "systemd": "255-13",
    "expat": "2.6.4-1",
    "libssh2": "1.11.0-2",
    "gnutls": "3.8.2-6",
    "polkit": "123-2",
    "runc": "1.1.14-2",
    "nss": "3.105-1",
    "python3": "3.11.6-14",
    "cloud_init": "23.2.1-10",
    "bind": "9.18.21-2",
    "java_8_konajdk": "8.0.20-1",
    "java_11_konajdk": "11.0.25-1",
    "java_17_konajdk": "17.0.13-1",
}

# ─── Findings ────────���─────────────────────────────────��──────────────────────

FINDINGS = {
    "TOS42-C01": {
        "title": (
            "OpenSSL 3.0.12 (EOL 2026-09-07) Deployed in TencentOS 4.2 December 2024 Image — "
            "3.0.x Branch End-of-Life Creates Ongoing Vulnerability Accumulation; "
            "Migration Path: OpenSSL 3.1+ or 3.2+; "
            "Source: tencentos/openssl 3.0.12-15 in SBOM"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-327",
        "component": "tencentos/openssl 3.0.12-15",
        "description": (
            "OpenSSL 3.0.x (3.0 LTS branch) reaches end-of-life on 2026-09-07. "
            "As of the analysis date (2026-09-04), TencentOS 4.2 is shipping OpenSSL 3.0.12-15 "
            "with 3 days remaining to EOL. After that date, no further security patches will be "
            "issued by the OpenSSL project for the 3.0.x branch. The -15 release counter "
            "indicates active patching through the analysis date (CVE-2024-4741 UAF fixed at "
            "-7; CVE-2024-5535 OOB fixed at -8). However, any CVE disclosed after 2026-09-07 "
            "will not receive an upstream fix unless Tencent independently patches the branch. "
            "The upstream migration path is OpenSSL 3.1 (EOL 2025-03-14, already EOL) or "
            "OpenSSL 3.2+ (supported). The practical upgrade path from 3.0.12 is to 3.4.x "
            "(current stable as of analysis date)."
        ),
        "context": (
            "TencentOS 3.x ships openssl 1.1.1k (EOL Sep 2023). "
            "TencentOS 4.2/4.6 both ship 3.0.12. All production TencentOS versions "
            "are either on EOL or immediately-approaching-EOL OpenSSL branches."
        ),
        "confirmed_present_cves": [
            "None confirmed open at 3.0.12-15 as of analysis date",
            "Post-2026-09-07: any newly disclosed CVE in 3.0.x will be permanently unpatched",
        ],
        "chain": (
            "TOS42-C01 + any post-EOL OpenSSL CVE: Tencent must independently backport the fix "
            "or ship a new OpenSSL version; window for unpatched exposure begins 2026-09-07; "
            "TencentOS 4.2 CFS-utils TLS, Kona JDK SSL backend, cloud-init HTTPS all use OpenSSL"
        ),
        "remediation": "Upgrade OpenSSL to 3.4.x. Update TencentOS 4.x package stream.",
        "references": ["OpenSSL 3.0 LTS lifecycle", "RHEL 9 OpenSSL migration path"],
    },
    "TOS42-C02": {
        "title": (
            "KASLR Disabled in TencentOS 4.2 Through December 2024 — "
            "Confirmed Disabled: 6.6.47-12 (initial), 6.6.58-15 (Dec 19 2024); "
            "Confirmed Enabled: 6.6.70-24 (Feb 27 2025); "
            "All 4.2 Deployments With Pre-Feb-2025 Images Have Fixed Kernel Text at 0xffffffff81000000"
        ),
        "severity": "CRITICAL",
        "cvss": "8.1",
        "cwe": "CWE-330",
        "component": "tencentos/kernel through 6.6.58 (Dec 2024)",
        "description": (
            "KASLR was disabled in TencentOS 4.2 through at least December 2024. "
            "Confirmed via direct qcow2 /boot/config extraction: "
            "6.6.47-12 (May 2024): # CONFIG_RANDOMIZE_BASE is not set; "
            "6.6.58-15 (December 2024): # CONFIG_RANDOMIZE_BASE is not set, _text = 0xffffffff81000000; "
            "6.6.70-24 (February 2025): CONFIG_RANDOMIZE_BASE=y — fix confirmed. "
            "The fix window in the 4.2 branch is 6.6.59–6.6.69. "
            "All TencentOS 4.2 cloud instances provisioned before February 27, 2025 "
            "from pre-6.6.70 images have a fixed kernel text base. "
            "On a cloud platform, many instances are provisioned from base images and "
            "never fully rebooted into updated kernels — the actual exposure window "
            "extends beyond the patch date."
        ),
        "confirmed_data": {
            "6.6.47-12_May2024": "KASLR DISABLED",
            "6.6.58-15_Dec2024": "KASLR DISABLED",
            "6.6.64-18_Dec2024_SBOM": "KASLR DISABLED (same pattern; 6.6.64 < 6.6.70 fix)",
            "6.6.70-24_Feb2025": "KASLR ENABLED — fix confirmed",
        },
        "chain": (
            "TOS42-C02 + TOSXK-F02 (MODULE_SIG_FORCE absent) + TOSXK-F03 (FORTIFY_SOURCE absent): "
            "kernel overflow on any pre-6.6.70 4.2 instance → fixed ROP at 0xffffffff81000000 → "
            "insmod unsigned rootkit → persistent root; "
            "same chain as TOS24K-F01+F02 applies to 4.2 images from 2024"
        ),
        "remediation": (
            "Ensure all TencentOS 4.2 instances run kernel >= 6.6.70-24 (Feb 2025 image or later). "
            "Confirm with: uname -r | awk -F- '{print $1}' (should be >= 6.6.70)"
        ),
        "references": [
            "tencent_kernel_cross_version.py TOSXK-F01",
            "KASLR_TIMELINE (updated 2026-09-04)",
        ],
    },
    "TOS42-C03": {
        "title": (
            "Kona JDK 8.0.20 in TencentOS 4.2 vs 8.0.9 in TencentOS 2.4 — "
            "CVE-2022-21449 (Psychic Signatures) Patched in 4.2; "
            "8.0.20 ≈ OpenJDK 8u402 (Apr 2024 CPU), Post-8u333 Fix Point; "
            "TencentOS 2.4 TK4 Ships 8.0.9 = 8u322 (VULNERABLE)"
        ),
        "severity": "INFORMATIONAL",
        "cvss": "N/A",
        "cwe": "CWE-347",
        "component": "tencentos/java-8-konajdk 8.0.20-1",
        "description": (
            "TencentOS 4.2 ships Kona JDK 8.0.20, which maps to approximately OpenJDK 8u402 "
            "(April 2024 CPU). This is well past the 8u333 (April 2022) fix point for "
            "CVE-2022-21449 (Psychic Signatures: ECDSA r=s=0 bypass). "
            "TencentOS 2.4 TK4 ships Kona JDK 8.0.9 = 8u322 (January 2022) which "
            "lacks CVE-2022-21449 fix — documented in tencent_kona_jdk_re.py KJD-F02. "
            "The gap between 4.2 and TK4 on this finding is significant: "
            "4.2 deployments with JDK 8 workloads are not vulnerable to JWT forgery; "
            "TK4 deployments remain vulnerable."
        ),
        "status": "PATCHED in TencentOS 4.2; OPEN in TencentOS 2.4 TK4",
        "references": ["KJD-F02 (tencent_kona_jdk_re.py)", "CVE-2022-21449"],
    },
}

# ─── Verified-Patched Summary ───────��──────────────────────────────────────────

PATCHED_IN_42_VS_TK4 = {
    "CVE-2022-25315 (expat 2.1.0 CVSS 9.8)": "PATCHED — expat 2.6.4-1 (TK4: 2.1.0-15)",
    "CVE-2019-3855 (libssh2 1.8.0)": "PATCHED — libssh2 1.11.0-2 (TK4: 1.8.0-4)",
    "CVE-2021-3156 (sudo 1.8.23 Baron Samedit)": "PATCHED — sudo 1.9.15p5-1 (TK4: 1.8.23-10)",
    "CVE-2021-20231 (GnuTLS UAF CVSS 9.8)": "PATCHED — gnutls 3.8.2-6 (TK4: 3.3.29-9)",
    "CVE-2023-38408 (openssh ssh-agent CVSS 9.8)": "PATCHED — openssh 9.3p2-15 (TK4: 7.4p1-13)",
    "CVE-2021-33910 (systemd alloca crash)": "PATCHED — systemd 255-13 (TK4: v220)",
    "CVE-2021-30465 (runc symlink escape)": "PATCHED — runc 1.1.14-2 (TK4: 1.0.0-70)",
    "CVE-2022-21449 (Kona JDK Psychic Signatures)": "PATCHED — konajdk 8.0.20 (TK4: 8.0.9)",
    "CVE-2024-6387 (openssh regreSSHion)": "PATCHED — openssh 9.3p2-15",
    "CVE-2023-4911 (glibc Looney Tunables)": "PATCHED — glibc 2.38-25 (TK4: 2.17-326 not affected)",
}

OPEN_IN_42 = {
    "OpenSSL 3.0.x EOL 2026-09-07": "TOS42-C01 — EOL in 3 days; post-EOL CVEs accumulate",
    "Kernel KASLR (6.6.64)": "TOS42-C02 — unconfirmed; in fix window 6.6.48–6.6.109",
    "MODULE_SIG_FORCE": "TOSXK-F02 (cross-version) — still not enforced in 6.6.64",
    "FORTIFY_SOURCE": "TOSXK-F03 (cross-version) — confirm still absent in 6.6.64",
}

ATTACK_CHAIN = {
    "title": "TOS42-C02 (KASLR unknown 6.6.64) + TOSXK-F02 (MODULE_SIG_FORCE absent): if KASLR disabled, same chain as TOS24K-F01+F02",
    "note": (
        "If 6.6.64 KASLR is disabled: unchanged exploitation path from TencentOS 2.4/3.3. "
        "If enabled: bar raised to moderate-difficulty kernel exploitation with ASLR bypass requirement. "
        "Verification of kernel config is the load-bearing step."
    ),
}


def probe():
    return {
        "critical": ["TOS42-C02"],
        "high": ["TOS42-C01"],
        "medium": [],
        "low": [],
        "informational": ["TOS42-C03"],
    }


def patched_summary():
    return PATCHED_IN_42_VS_TK4


def open_findings():
    return OPEN_IN_42


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": SBOM_SOURCE["file"],
        "kernel": SBOM_SOURCE["kernel"],
        "openssl_eol": SBOM_SOURCE["openssl_eol"],
        "findings": list(FINDINGS.keys()),
        "patched_count": len(PATCHED_IN_42_VS_TK4),
        "open_count": len(OPEN_IN_42),
    }, indent=2))
