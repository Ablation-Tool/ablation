"""
TencentOS Server 3.1 AppStream compat-openssl10 SRPM RE Module
Source: /media/cowboy/research/tencentos/3.1/TencentOS-AppStream-srpms/
        compat-openssl10-1.0.2o-4.tl3.src.rpm (terminal version)
Method: rpm2cpio | cpio -idmv; spec/patch enumeration
Analysis date: 2026-09-04

compat-openssl10 is an OpenSSL 1.0.2 compatibility shim for applications
that link against the legacy libcrypto.so.10 / libssl.so.10 ABI.
OpenSSL 1.0.2 reached End of Life on 2020-01-01.

SRPM inventory in TencentOS-AppStream-srpms/:
  compat-openssl10-1.0.2o-3.tl3.src.rpm   (Aug 2018 — compat cnf file setup)
  compat-openssl10-1.0.2o-4.tl3.src.rpm   (May 2022 — CVE-2022-0778 backport, TERMINAL)

FINDINGS SUMMARY:
  TOS31-COMPAT-F01 (HIGH/7.5)   CVE-2022-0778 PATCHED (counter -4, May 2022)
  TOS31-COMPAT-F02 (CRITICAL)   All post-May-2022 OpenSSL 1.0.2 CVEs OPEN — EoL library
  TOS31-COMPAT-F03 (HIGH)       compat-openssl10 provides EoL libssl.so.10 + libcrypto.so.10
  TOS31-COMPAT-F04 (INFO)       50 patches total; only 1 security CVE (0778); rest infrastructure
"""

# ─────────────────────────────────────���────────────────────────────────────────
# FINDING TOS31-COMPAT-F01: CVE-2022-0778 PATCHED
# ──────────────────────────────────────────────────────────────────────────────

CVE_2022_0778_STATUS = {
    "finding_id": "TOS31-COMPAT-F01",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cve": "CVE-2022-0778",
    "title": "OpenSSL BN_mod_sqrt() infinite loop in certificate parsing",
    "description": (
        "A crafted certificate with a non-prime p value triggers an infinite loop "
        "in BN_mod_sqrt() during X.509 certificate chain validation. "
        "Affects applications calling X509_verify_cert() with attacker-controlled certs. "
        "Remote DoS via crafted TLS certificate."
    ),
    "status": "PATCHED in compat-openssl10-1.0.2o-4.tl3",
    "patch_file": "openssl-1.0.2o-cve-2022-0778.patch",
    "patch_date": "2022-05-04",
    "patch_author": "Clemens Lang <cllang@redhat.com>",
    "patch_upstream": "Tomas Mraz <tomas@openssl.org> (2022-02-28)",
    "patch_location": "crypto/bn/bn_sqrt.c lines 14, 302-326",
    "fix_description": (
        "Adds non-prime check before entering Tonelli-Shanks iteration. "
        "Adds loop counter limit in the BN_mod_sqrt() algorithm to prevent infinite loop. "
        "Returns error if p is not prime (previously produced incorrect result silently)."
    ),
    "srpm_counter": "-4",
    "terminal_version": True,
}

# ──────────────���──────────��────────────────────────────────────────────────────
# FINDING TOS31-COMPAT-F02: Post-2022 OpenSSL 1.0.2 CVEs OPEN
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL102_EOL_CVE_EXPOSURE = {
    "finding_id": "TOS31-COMPAT-F02",
    "severity": "CRITICAL",
    "title": "OpenSSL 1.0.2 EoL — all CVEs after May 2022 unpatched in compat library",
    "openssl_102_eol_date": "2020-01-01",
    "last_security_patch_in_tencent_version": "CVE-2022-0778 (May 2022)",
    "known_unpatched_cves": [
        {
            "cve": "CVE-2022-2068",
            "severity": "CRITICAL/9.8",
            "title": "c_rehash script injection via shell metacharacters",
            "disclosed": "2022-06-21",
            "affects_library": True,
            "note": "Affects c_rehash script; low direct impact on library users",
        },
        {
            "cve": "CVE-2022-2274",
            "severity": "CRITICAL/9.8",
            "title": "RSA off-by-one memory corruption (heap overflow in RSA decryption)",
            "disclosed": "2022-07-05",
            "affects_library": True,
            "note": "Affects X86_64 assembly RSA implementation; memory corruption",
        },
        {
            "cve": "CVE-2022-4304",
            "severity": "MEDIUM/5.9",
            "title": "RSA decryption timing oracle (Bleichenbacher-style)",
            "disclosed": "2023-02-07",
            "affects_library": True,
        },
        {
            "cve": "CVE-2023-0215",
            "severity": "HIGH/7.5",
            "title": "UAF in BIO_new_NDEF() X.509 streaming functions",
            "disclosed": "2023-02-07",
            "affects_library": True,
        },
        {
            "cve": "CVE-2023-0286",
            "severity": "HIGH/7.4",
            "title": "X.400 GeneralName type confusion (ASN.1 parsing)",
            "disclosed": "2023-02-07",
            "affects_library": True,
        },
        {
            "cve": "CVE-2023-2650",
            "severity": "HIGH/7.5",
            "title": "Possible DoS via crafted ANS.1 object identifiers",
            "disclosed": "2023-05-30",
            "affects_library": True,
        },
    ],
    "attack_chain": (
        "Application on TOS 3.1 links against compat-openssl10 (libssl.so.10) "
        "and handles untrusted X.509 certificates (TLS client or cert verification). "
        "Attacker presents crafted cert triggering CVE-2022-2274 (heap overflow in RSA decryption) "
        "or CVE-2023-0286 (ASN.1 type confusion) → remote code execution in the application process. "
        "Attack is passive (attacker controls a TLS server or cert signing path)."
    ),
    "exposure_qualifier": (
        "Exposure depends on which applications link against libssl.so.10/libcrypto.so.10. "
        "Enumerate with: ldd /usr/*/bin/* /usr/*/sbin/* | grep 'ssl.so.10\\|crypto.so.10'. "
        "If no applications link against it, risk is theoretical."
    ),
}

# ─────────────────────────────────���────────────────────────────────────────────
# FINDING TOS31-COMPAT-F03: EoL library provided in AppStream
# ─────────────────────────────────���────────────────────────────────────────────

COMPAT_OPENSSL10_LIBRARY_FINDING = {
    "finding_id": "TOS31-COMPAT-F03",
    "severity": "HIGH",
    "title": "TOS 3.1 AppStream ships EoL OpenSSL 1.0.2 compatibility library",
    "library_names": ["libssl.so.10", "libcrypto.so.10"],
    "base_version": "1.0.2o (April 2018 release)",
    "eos_date": "2020-01-01",
    "tencent_terminal_counter": "-4.tl3 (May 2022)",
    "note": (
        "compat-openssl10 is intended to provide backward compatibility only. "
        "It should not be the primary OpenSSL in use — TOS 3.1 main OpenSSL is "
        "openssl-1.1.1 (in base OS). Any application requiring 1.0.x ABI should "
        "be migrated or rebuilt against 1.1.x."
    ),
    "comparison_to_tos46": (
        "TOS 4.6 ships compat-openssl10 too, but with actively maintained 1.0.2 fork patches. "
        "TOS 3.1 version (-4.tl3) is terminal with no further security updates."
    ),
}

# ────────────────────────────────────────────���─────────────────────────────────
# FINDING TOS31-COMPAT-F04: Patch inventory
# ──────────────────────────────────────────────────────────────────────────────

PATCH_INVENTORY = {
    "total_patches": 50,
    "security_cve_patches": 1,
    "security_patches": {
        "Patch83": "openssl-1.0.2o-cve-2022-0778.patch — BN_mod_sqrt infinite loop fix",
    },
    "infrastructure_patches": (
        "49 patches for build system, FIPS compat, algorithm documentation, "
        "system cipher list defaults, x509 conformance, ipv6 support, "
        "compatibility symbols, engine dir, etc. No security CVEs."
    ),
    "notable_non_security_patches": [
        "openssl-1.0.2a-fips-ctor.patch — FIPS module constructor",
        "openssl-1.0.2a-fips-ec.patch — FIPS EC support",
        "openssl-1.0.2a-defaults.patch — system-wide default cipher list",
        "openssl-1.0.2o-system-cipherlist.patch — system cipherlist override",
    ],
    "changelog_summary": {
        "1.0.2o-4 (2022-05-04)": "CVE-2022-0778: Infinite loop in BN_mod_sqrt()",
        "1.0.2o-3 (2018-08-03)": "Provide compat openssl10.cnf (non-security)",
        "1.0.2o-1 (2018-04-05)": "1.0.2o upstream release (upstream security fixes)",
    },
}

# ────────────────────────────────────────────────────────────────────���─────────
# COMPARISON: TOS 3.1 compat-openssl10 vs main openssl
# ────────────────���─────────────────────────────────────────────────��───────────

TOS31_OPENSSL_ECOSYSTEM = {
    "main_openssl": {
        "package": "openssl-1.1.1k (or similar in TOS 3.1 base)",
        "path": "TencentOS-BaseOS-srpms",
        "status": "terminal Jun 2022 (see tencent_tos31_core_security_lifecycle_re.py)",
    },
    "compat_openssl10": {
        "package": "compat-openssl10-1.0.2o-4.tl3",
        "path": "TencentOS-AppStream-srpms",
        "status": "terminal May 2022",
        "last_security_patch": "CVE-2022-0778",
    },
    "combined_exposure": (
        "Both main (1.1.1) and compat (1.0.2) OpenSSL in TOS 3.1 have no security "
        "updates published after May/Jun 2022. All CVEs disclosed since then remain "
        "unpatched in both libraries. TOS 3.1 is fully terminal from an OpenSSL perspective."
    ),
}
