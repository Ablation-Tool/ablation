"""
TencentOS 4.6 — httpd and 389-ds-base RE.

httpd: 2.4.66, 2.4.68 (two version increments in srpm_work)
389-ds-base: 1.4.3.39-8 (latest of 12 version builds in srpm_work)

Method: spec changelog CVE enumeration + patch file analysis for security-relevant patches.

TOS uses version upgrades to fix httpd CVEs (no individual CVE backports).
389-ds-base uses individual CVE patch files (3 CVE patches in .39-8).
"""

HTTPD = {
    "package": "httpd",
    "versions_in_srpm_work": ["2.4.66-1.tl4", "2.4.68-1.tl4"],
    "tos_specific_patches": {
        "Patch0001": {
            "file": "httpd-2.4.48-r1842929+.patch",
            "description": "Apache r1842929: fix SNI hostname matching edge case.",
            "class": "bug-fix",
        },
        "Patch0002": {
            "file": "httpd-2.4.43-enable-sslv3.patch",
            "description": (
                "SSLv3 handling: modifies ssl_engine_config.c and ssl_engine_init.c. "
                "Two changes: "
                "(1) 'SSLProtocol all' keyword explicitly EXCLUDES SSLv3 "
                "(removes SSL_PROTOCOL_SSLV3 from the 'all' bitmask). "
                "(2) Adds ssl_set_ctx_protocol_option() that emits a WARNING log "
                "if SSLv3 is explicitly enabled while OpenSSL disables it by default. "
                "Direction: protective — SSLv3 is removed from 'all', explicit SSLv3 "
                "use generates a visible warning log entry."
            ),
            "class": "ssl-hardening",
            "security_direction": "protective",
        },
        "Patch3000-3011": "Build/config: apxs, deplibs, systemd integration, cache, icons, logging",
        "Patch_sslprotdefault": {
            "file": "httpd-2.4.43-sslprotdefault.patch",
            "description": (
                "Changes modssl_ctx_init() default from SSL_PROTOCOL_DEFAULT to SSL_PROTOCOL_NONE. "
                "Forces explicit protocol configuration — no protocol is enabled by default. "
                "Prevents accidental weak protocol enablement from the default context."
            ),
            "class": "ssl-hardening",
            "security_direction": "protective",
        },
    },
    "cve_history": {
        "2.4.68": [
            "CVE-2026-29167", "CVE-2026-29170", "CVE-2026-34355", "CVE-2026-34356",
            "CVE-2026-42535", "CVE-2026-42536", "CVE-2026-43951", "CVE-2026-44119",
            "CVE-2026-44185", "CVE-2026-44186", "CVE-2026-44631", "CVE-2026-48913",
            "CVE-2026-49975",
        ],
        "2.4.67": [
            "CVE-2026-24072", "CVE-2026-23918", "CVE-2026-28780", "CVE-2026-29168",
        ],
        "2.4.66": [
            "CVE-2025-55753", "CVE-2025-58098", "CVE-2025-59775",
            "CVE-2025-65082", "CVE-2025-66200", "CVE-2025-54090",
        ],
        "2.4.64": [
            "CVE-2025-53020", "CVE-2024-43204", "CVE-2024-47252",
            "CVE-2024-42516", "CVE-2025-23048", "CVE-2025-49630", "CVE-2025-49812",
        ],
        "pre-2.4.64": [
            "CVE-2024-36387",                       # mod_http2 DoS
            "CVE-2024-38472",                       # SSRF via UNC paths (Windows only — n/a)
            "CVE-2024-38473",                       # mod_proxy URL encoding flaw
            "CVE-2024-38474",                       # mod_rewrite backreference injection
            "CVE-2024-38475",                       # mod_rewrite bypass
            "CVE-2024-38476",                       # Potential RCE via backend response
            "CVE-2024-38477",                       # mod_proxy null ptr via crafted response
            "CVE-2024-39573",                       # mod_rewrite substitution bypass
            "CVE-2023-38709",                       # HTTP response splitting
            "CVE-2024-27316",                       # mod_http2 CONTINUATION DoS
            "CVE-2024-24795",                       # HTTP response splitting in multiple modules
            "CVE-2023-31122",                       # mod_macro UAF on reconfig
            "CVE-2023-45802",                       # mod_http2 RST_STREAM DoS
            "CVE-2023-43622",                       # mod_http2 DoS via concurrent streams
        ],
    },
    "patching_strategy": (
        "TOS ships httpd at upstream release versions to get CVE fixes. "
        "No individual CVE backports found. TOS-specific patches are build and config adjustments. "
        "Two TOS patches harden SSL: SSLv3 excluded from 'all', default protocol set to NONE."
    ),
    "total_cves_fixed": 40,
}

DS_389 = {
    "package": "389-ds-base",
    "version": "1.4.3.39",
    "release": "8.module+el8.10.0+688+93972b36",
    "builds_in_srpm_work": 12,
    "earliest": "1.4.2.4-8.module_el8.2.0+366+71e3276f",
    "latest": "1.4.3.39-8.module+el8.10.0+688+93972b36",
    "note": (
        "389-ds-base 1.4.x is the LDAP directory server (used by FreeIPA and standalone). "
        "TOS ships it for enterprise LDAP. Multiple build snapshots in srpm_work "
        "represent the TOS package update history. Analysis targets the latest (1.4.3.39-8)."
    ),
    "cve_patches": {
        "CVE-2024-2199": {
            "patch": "0006-CVE-2024-2199.patch",
            "author": "James Chapman <jachapma@redhat.com>",
            "title": "Non-UTF8 userPassword DoS — crash on invalid password value in modify",
            "severity": "MEDIUM",
            "description": (
                "A modify request setting userPassword to an invalid non-UTF8 value "
                "causes the server to crash when pw_encodevals_ext() encounters the value. "
                "Affected file: ldap/servers/slapd/modify.c — op_shared_modify(). "
                "The encode step fails but doesn't safely return LDAP_UNWILLING_TO_PERFORM; "
                "instead it logs incorrectly and continues into an error state. "
                "Fix: add explicit error log message referencing UTF8 requirement; "
                "ensure LDAP_UNWILLING_TO_PERFORM is sent and valuearray is freed. "
                "Also adds SLAPI_MODIFY_MODS update via slapi_pblock_set() before the "
                "no-mods-check (prevents a related crash when smods is empty after filter). "
                "Authenticated user can crash 389-ds by attempting to set a non-UTF8 password."
            ),
            "pre_auth": False,
            "class": "logic-error + crash",
        },
        "CVE-2024-3657": {
            "patch": "0007-CVE-2024-3657.patch",
            "author": "Pierre Rogier <progier@redhat.com>",
            "title": "Large LDAP filter: index.c buffer size underestimate — heap overflow",
            "severity": "HIGH",
            "description": (
                "index.c:index_add_mods() converts berval values to ASCII for indexing. "
                "The buffer size calculation for the encoded representation did not account "
                "for the expansion factor of non-printable and special characters "
                "(which expand to 2-3 bytes: \\xx for control chars, \\ for backslash/quote). "
                "A large LDAP search filter containing many chars that require multi-byte "
                "encoding overflows the allocated buffer. "
                "Fix: add encode_size[256] lookup table mapping each byte value to its "
                "encoded size (1, 2, or 3 bytes). Pre-compute the required buffer size "
                "before allocating: "
                "0x00-0x1F and 0x7F-0xFF → 3 bytes (\\xx format); "
                "0x22 (quote) and 0x5C (backslash) → 2 bytes; "
                "all other printable ASCII → 1 byte. "
                "Large filter from an authenticated user → heap overflow in slapd. "
                "Potential code execution; demonstrated as DoS."
            ),
            "pre_auth": False,
            "class": "heap-overflow",
        },
        "CVE-2024-5953": {
            "patch": "0012-Security-fix-for-CVE-2024-5953.patch",
            "author": "Pierre Rogier <progier@redhat.com>",
            "title": "Malformed userPassword hash: DoS via incoherent hash size in bind",
            "severity": "MEDIUM",
            "description": (
                "When 389-ds processes a BIND request, it reads the stored userPassword "
                "hash and passes it to the appropriate hash-check function. "
                "A malformed hash with an incoherent size field (e.g., larger than the "
                "actual hash data) causes a buffer overread in the hash verification "
                "path (md5_pwd.c, pbkdf2_pwd.c). "
                "Fix: validate hash size coherence before attempting hash processing; "
                "if hash size is invalid, immediately fail the bind rather than reading "
                "beyond the hash boundary. "
                "An admin who stores a malformed hash (or an attacker who can write to "
                "userPassword with a crafted hash string) can trigger server crash on "
                "the next bind attempt for that account."
            ),
            "pre_auth": True,
            "class": "memory-overread + crash",
        },
        "CVE-2024-1062": {
            "patch": None,
            "title": "Heap overflow in log_entry_attr: value > 256 chars",
            "severity": "MEDIUM",
            "description": (
                "Heap overflow when logging an entry attribute value longer than 256 characters. "
                "Documented in spec changelog (RHEL-23209) but patch file not present in srpm_work. "
                "Fixed in 1.4.3.39-8."
            ),
            "pre_auth": False,
            "class": "heap-overflow",
        },
    },
}

SHADOW_UTILS = {
    "package": "shadow-utils",
    "version": "4.14.3",
    "release": "5.tl4",
    "tos_patches": {
        "Patch5000": {
            "file": "add-sm3-support.patch",
            "description": (
                "Adds SM3 hash algorithm support to shadow-utils password storage. "
                "SM3 is the Chinese national cryptographic hash standard (GB/T 32905-2016). "
                "Enables systems using SM3-based authentication infrastructure to "
                "store passwords using SM3 as the hash algorithm in /etc/shadow. "
                "Only TOS-specific patch; no CVE patches in this version."
            ),
            "class": "feature",
            "security_relevant": True,
            "notes": (
                "SM3 support enables non-standard password hashing. "
                "If SM3 is used as the hash scheme on a system that also needs interoperability "
                "with standard Linux tooling (PAM, nsswitch, etc.), the SM3 hash scheme identifier "
                "must be handled consistently across all password-checking paths."
            ),
        },
    },
    "cves": None,
    "no_cve_patches": True,
}

PASSWD = {
    "package": "passwd",
    "version": "0.80",
    "release": "6.tl4",
    "tos_patches": None,
    "stock_upstream_patches": [
        "passwd-0.80.autotoolized.tar.bz2 — base source",
        "passwd-0.80-manpage.patch — manpage fixes",
        "passwd-0.80-S-output.patch — -S flag output format fix",
    ],
    "cves": None,
    "no_cve_patches": True,
    "note": "No TOS-specific security patches. Standard upstream passwd 0.80.",
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2024-3657",
        "package": "389-ds-base-1.4.3.39",
        "title": "Large LDAP filter: berval encode_size not accounted → heap overflow in index.c",
        "detail": (
            "index.c buffer for berval-to-ASCII didn't account for multi-byte escaping. "
            "Non-printable chars (\\xx) expand 3x, quote/backslash 2x. "
            "Large filter with special chars overflows allocation. Authenticated. "
            "Fix: encode_size[256] pre-compute lookup table before alloc."
        ),
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "cve": "CVE-2024-5953",
        "package": "389-ds-base-1.4.3.39",
        "title": "389-ds BIND: malformed userPassword hash size → server DoS (pre-auth)",
        "detail": (
            "md5_pwd.c + pbkdf2_pwd.c: hash size not validated before processing. "
            "Crafted hash with oversized hash_len field → buffer overread → crash. "
            "Pre-auth: any bind attempt against the crafted account triggers it."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "cve": "CVE-2024-2199",
        "package": "389-ds-base-1.4.3.39",
        "title": "389-ds modify: non-UTF8 userPassword crashes server — authenticated",
        "detail": (
            "modify.c:op_shared_modify(): pw_encodevals_ext fails on non-UTF8 password. "
            "Server crashes instead of returning LDAP_UNWILLING_TO_PERFORM. "
            "Authenticated user with write access to userPassword."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "cve": None,
        "package": "httpd-2.4.68",
        "title": "httpd: 40+ CVEs fixed via version upgrades across TOS 4.6 lifecycle",
        "detail": (
            "TOS ships httpd at upstream release versions. No backport strategy. "
            "2.4.68 (latest in srpm_work) covers CVEs through 2026-49975. "
            "TOS-specific patches harden SSL: SSLv3 excluded from 'all'; default protocol = NONE."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "cve": None,
        "package": "shadow-utils-4.14.3",
        "title": "shadow-utils: SM3 hash support added (Patch5000) — Chinese national hash",
        "detail": (
            "add-sm3-support.patch adds SM3 (GB/T 32905-2016) as a password hash option. "
            "No CVE patches. SM3 hash identifier consistency across PAM stack not verified."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "cve": None,
        "package": "httpd-2.4.68",
        "title": "httpd Patch0002: SSLv3 excluded from 'all' + explicit enable emits warning",
        "detail": (
            "Patch0002 (httpd-2.4.43-enable-sslv3.patch): protective direction. "
            "SSLv3 removed from SSL_PROTOCOL_ALL bitmask. Explicit SSLv3 config logs APLOGNO(02904) WARNING. "
            "Patch_sslprotdefault: mctx->protocol init from SSL_PROTOCOL_DEFAULT → SSL_PROTOCOL_NONE."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 httpd + 389-ds-base RE")
    print()
    print(f"httpd {HTTPD['versions_in_srpm_work']} — {HTTPD['total_cves_fixed']} CVEs via version upgrades")
    total_ds_cves = len(DS_389["cve_patches"])
    print(f"389-ds-base {DS_389['version']}-{DS_389['release']} — {total_ds_cves} CVE patches + 12 build snapshots")
    print(f"shadow-utils {SHADOW_UTILS['version']} — SM3 support only, no CVE patches")
    print(f"passwd {PASSWD['version']} — no TOS-specific patches")
    print()
    for f in FINDINGS:
        cve = f"[{f['cve']}] " if f.get('cve') else ""
        pkg = f"[{f.get('package', '')}] " if f.get('package') else ""
        print(f"  [{f['severity']:6s}] {f['id']}: {cve}{pkg}{f['title'][:55]}")
