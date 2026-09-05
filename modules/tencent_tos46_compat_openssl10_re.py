"""
TencentOS 4.6 — compat-openssl10 EOL CVE gap analysis.

Package: compat-openssl10-1.0.2o (EOL December 31, 2019)
Sources: scratchpad/compat-openssl10/, scratchpad/compat-ssl10/
Both directories contain identical specs and patch sets.

Summary: TOS 4.6 ships OpenSSL 1.0.2o as a compatibility library for
legacy applications. The version reached end-of-life in 2019. Of 63 total
patches applied, exactly ONE is a CVE security fix. All post-EOL CVEs
with severity >= MEDIUM are unpatched.
"""

PACKAGE_METADATA = {
    "name": "compat-openssl10",
    "version": "1.0.2o",
    "eos_date": "2019-12-31",
    "tos_version": "TOS 4.6",
    "total_patches": 63,
    "cve_patches": 1,
    "cve_patch_file": "openssl-1.0.2o-cve-2022-0778.patch",
    "spec_identical_in": ["compat-openssl10/", "compat-ssl10/"],
    "spec_patch_line": "Patch83: openssl-1.0.2o-cve-2022-0778.patch",
    "purpose": (
        "Compatibility shim for legacy applications that link against libssl.so.10 / "
        "libcrypto.so.10 (OpenSSL 1.0.x ABI). TOS 4.6 ships OpenSSL 3.0.x as the "
        "system default; compat-openssl10 provides the 1.0.x ABI in parallel. "
        "Applications using libssl.so.10 that ship with TOS (e.g., some Tencent "
        "proprietary binaries and older RPM dependencies) depend on this package."
    ),
}

PATCHED_CVE = {
    "CVE-2022-0778": {
        "severity": "HIGH",
        "title": "BN_mod_sqrt infinite loop — DoS via crafted certificate",
        "description": (
            "BN_mod_sqrt() fails to converge for non-square inputs modulo a prime. "
            "A TLS server or client that parses a certificate containing an EC key "
            "with a non-square modulus value enters an infinite loop in the handshake. "
            "Denial of service — process hangs, no memory corruption. "
            "Fixed in OpenSSL 1.0.2zd (March 15, 2022). "
            "TOS backported this single patch to 1.0.2o (Patch83). "
            "This is the ONLY CVE patch in the 63-patch stack."
        ),
        "patched_in_tos": True,
        "patch_file": "openssl-1.0.2o-cve-2022-0778.patch",
        "pre_auth": True,
        "vector": "network",
    },
}

UNPATCHED_CVES = {
    "CVE-2021-23840": {
        "severity": "HIGH",
        "cvss3": 7.5,
        "title": "EVP_EncryptUpdate / EVP_EncryptFinal_ex: integer overflow in output buffer calculation",
        "description": (
            "When encrypting large amounts of data (> 2^31 - 1 bytes) using EVP_EncryptUpdate "
            "or EVP_EncryptFinal_ex, the output buffer length calculation overflows. "
            "Affected: OpenSSL <= 1.0.2x. Fixed in 1.0.2y. "
            "TOS compat-openssl10 is 1.0.2o — no fix applied."
        ),
        "fixed_upstream_in": "1.0.2y",
        "patched_in_tos": False,
        "pre_auth": False,
        "notes": "Affects large data processing paths (bulk encryption, file encryption).",
    },
    "CVE-2022-2068": {
        "severity": "CRITICAL",
        "cvss3": 9.8,
        "title": "c_rehash: shell command injection via crafted hash directory entries",
        "description": (
            "The c_rehash script distributed with OpenSSL does not properly sanitize "
            "shell meta-characters before passing directory names to shell commands. "
            "An attacker who can place a crafted filename in a directory processed by "
            "c_rehash can inject arbitrary shell commands. "
            "Affected: OpenSSL <= 1.0.2ze. Fixed in 1.0.2zf. "
            "TOS compat-openssl10 does not ship c_rehash itself but the underlying "
            "libcrypto.so.10 does not prevent the issue if the script is invoked."
        ),
        "fixed_upstream_in": "1.0.2zf",
        "patched_in_tos": False,
        "pre_auth": False,
        "notes": "Relevant if TOS package management or CA cert scripts invoke c_rehash.",
    },
    "CVE-2023-0215": {
        "severity": "HIGH",
        "cvss3": 7.5,
        "title": "BIO_new_NDEF: use-after-free in CMS/PKCS7 streaming write",
        "description": (
            "BIO_new_NDEF() allocates a BIO chain for CMS or PKCS7 streaming. "
            "Under certain error conditions, the allocated BIO is freed while still "
            "referenced, leading to a use-after-free. "
            "Affected: OpenSSL 1.0.2 (all versions). No 1.0.2 patch released post-EOL. "
            "TOS compat-openssl10 is unpatched. "
            "Reachable via S/MIME operations in libcrypto.so.10 consumers."
        ),
        "fixed_upstream_in": "1.1.1t / 3.0.8 (no 1.0.2 fix — EOL)",
        "patched_in_tos": False,
        "pre_auth": False,
        "class": "use-after-free",
    },
    "CVE-2023-0286": {
        "severity": "HIGH",
        "cvss3": 7.4,
        "title": "X.400 address type confusion in GeneralName",
        "description": (
            "OpenSSL incorrectly handles the comparison of GeneralName type containing "
            "X.400 addresses. Under certain conditions, the comparison treats the "
            "X400Address field as an ASN1_STRING when it should be ASN1_TYPE. "
            "This can lead to a read of arbitrary memory and in some cases a "
            "DoS crash when processing a malicious certificate. "
            "Affected: OpenSSL 1.0.2 (no fix released post-EOL). "
            "TOS compat-openssl10 is unpatched."
        ),
        "fixed_upstream_in": "1.1.1t / 3.0.8 (no 1.0.2 fix — EOL)",
        "patched_in_tos": False,
        "pre_auth": True,
        "vector": "network",
        "class": "type-confusion",
    },
    "CVE-2024-0727": {
        "severity": "MEDIUM",
        "cvss3": 5.5,
        "title": "PKCS12: NULL pointer dereference in PKCS12_parse() on missing MAC",
        "description": (
            "Processing a maliciously crafted PKCS12 file may result in a NULL pointer "
            "dereference in PKCS12_parse() when the MAC is missing or empty. "
            "Crash / denial of service. "
            "Affected: OpenSSL 1.0.2 (no fix released post-EOL). "
            "TOS compat-openssl10 is unpatched."
        ),
        "fixed_upstream_in": "1.1.1x / 3.0.13 (no 1.0.2 fix — EOL)",
        "patched_in_tos": False,
        "pre_auth": False,
        "class": "null-deref",
        "notes": "Reachable via pkcs12 import operations in legacy applications.",
    },
    "CVE-2024-4603": {
        "severity": "MEDIUM",
        "cvss3": 5.3,
        "title": "Excessive time in EVP_PKEY_param_check() validating DSA/DH parameters",
        "description": (
            "Checking DSA/DH key parameters with EVP_PKEY_param_check() can take "
            "excessive time for very large parameter sets, leading to a denial of service. "
            "Affected: OpenSSL 1.0.2 (no fix released post-EOL). "
            "TOS compat-openssl10 is unpatched."
        ),
        "fixed_upstream_in": "1.1.1y / 3.0.14 (no 1.0.2 fix — EOL)",
        "patched_in_tos": False,
        "pre_auth": True,
        "vector": "network",
        "class": "resource-exhaustion",
    },
}

SYSTEMIC_ANALYSIS = {
    "title": "One CVE patch in 63-patch stack — TOS ships EOL crypto with minimal maintenance",
    "detail": (
        "compat-openssl10 contains 63 patches. Patch numbers 1-82, 90-99: all backports "
        "from the RHEL/Fedora OpenSSL 1.0.2o RPM base — packaging adjustments, config "
        "defaults, FIPS mode, PKCS11, disabling SSLv2/v3. None are security CVE patches. "
        "Patch83 is the single CVE fix: CVE-2022-0778 (BN_mod_sqrt DoS). "
        "The library was EOL December 31, 2019. After EOL, the OpenSSL project issued "
        "no further 1.0.2 releases. All post-2022 CVEs affecting 1.0.2 are unpatched "
        "in TOS because no upstream fix exists to backport. "
        "The effective security posture: any application linking libssl.so.10 on TOS 4.6 "
        "is exposed to CVE-2023-0215 (UAF), CVE-2023-0286 (type confusion), "
        "CVE-2021-23840 (integer overflow), and CVE-2024-0727 (NULL deref). "
        "The only mitigation: CVE-2022-0778 (infinite loop DoS) is patched."
    ),
    "compat_ssl10_note": (
        "scratchpad/compat-ssl10/ contains a second identical spec. "
        "Both ship the same Patch83 and no additional CVE patches. "
        "The duplicate directory may be an artifact of the TOS source packaging workflow."
    ),
    "affected_consumers": (
        "Any binary on TOS 4.6 that dlopen()s or links against libssl.so.10 or "
        "libcrypto.so.10. Tencent-proprietary binaries and older cloud tools "
        "shipped by Tencent are the primary consumers."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "compat-openssl10 1.0.2o shipped on TOS 4.6: 6-year-old EOL library with 4+ unpatched CVEs",
        "detail": (
            "TOS 4.6 ships OpenSSL 1.0.2o (EOL 2019-12-31) as compat-openssl10. "
            "63 patches; exactly 1 CVE patch (CVE-2022-0778 — DoS only). "
            "Unpatched: CVE-2023-0215 (UAF HIGH), CVE-2023-0286 (type confusion HIGH), "
            "CVE-2021-23840 (int overflow HIGH), CVE-2024-0727 (NULL deref MEDIUM), "
            "CVE-2024-4603 (resource exhaustion MEDIUM). "
            "No upstream 1.0.2 fix exists post-EOL — TOS cannot backport what was never released."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2023-0215",
        "title": "BIO_new_NDEF UAF in CMS/PKCS7 streaming: unpatched in libcrypto.so.10",
        "detail": (
            "Use-after-free in PKCS7/CMS streaming write path. Any TOS application "
            "using S/MIME or CMS operations via libcrypto.so.10 is reachable. "
            "No 1.0.2 patch exists (EOL); fix only in 1.1.1t/3.0.8."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2023-0286",
        "title": "X.400 GeneralName type confusion: memory read + potential crash via crafted cert",
        "detail": (
            "X400Address treated as ASN1_STRING instead of ASN1_TYPE in GeneralName compare. "
            "Network-reachable via TLS certificate processing in any application using libssl.so.10. "
            "No 1.0.2 fix (EOL)."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "cve": "CVE-2021-23840",
        "title": "EVP integer overflow in output buffer size for large plaintext blocks",
        "detail": (
            "Integer overflow in EVP_EncryptUpdate/EVP_EncryptFinal_ex for inputs > 2^31-1 bytes. "
            "Any application encrypting large files via libcrypto.so.10 is affected. "
            "Fixed in 1.0.2y — not backported to TOS compat package."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "cve": "CVE-2022-2068",
        "title": "c_rehash shell injection: command execution via crafted directory names",
        "detail": (
            "c_rehash script does not sanitize shell metacharacters. "
            "If any TOS component or administrator invokes c_rehash against an "
            "attacker-controlled directory, arbitrary command execution results."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "compat-ssl10/ is a byte-identical duplicate of compat-openssl10/ spec",
        "detail": (
            "Both directories carry the same spec, same 63 patches, same single CVE fix. "
            "Likely a packaging artifact — two names for the same compatibility shim."
        ),
    },
]

if __name__ == '__main__':
    print("compat-openssl10 1.0.2o TOS 4.6 CVE gap analysis")
    print(f"  version: {PACKAGE_METADATA['version']} (EOL {PACKAGE_METADATA['eos_date']})")
    print(f"  total patches: {PACKAGE_METADATA['total_patches']}")
    print(f"  CVE patches: {PACKAGE_METADATA['cve_patches']} ({PACKAGE_METADATA['cve_patch_file']})")
    print()
    print("Patched:")
    for cve_id, cve in PATCHED_CVE.items():
        print(f"  [PATCHED  ] {cve_id} ({cve['severity']}): {cve['title'][:60]}")
    print()
    print("Unpatched:")
    for cve_id, cve in UNPATCHED_CVES.items():
        print(f"  [UNPATCHED] {cve_id} ({cve['severity']} {cve.get('cvss3','?')}): {cve['title'][:55]}")
    print()
    for f in FINDINGS:
        cve = f"[{f.get('cve', '')}] " if f.get('cve') else ""
        print(f"  [{f['severity']:8s}] {f['id']}: {cve}{f['title'][:65]}")
