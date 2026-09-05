"""
TencentOS Server 4.6 Core Libraries RE Module
Packages: glibc-2.38-49.tl4.2, curl-8.4.0-17.tl4,
          expat-2.6.4-7.tl4, sssd-2.9.4-8.tl4, krb5-1.21.2-8.tl4
Source: /media/cowboy/research/tencentos/4.6/BaseOS-source/
Method: rpm2cpio extraction + patch audit + binary string scan
Analysis date: 2026-09-04

VERSION LADDER (glibc):
  2.38-1.tl4 (Jan 2024)  → 2.38-28.tl4 (Jul 2024) → 2.38-40.tl4 (Jan 2025)
  → 2.38-42.tl4 (Feb 2025) → 2.38-49.tl4.2 (Sep 2025)   ← LATEST ANALYZED

VERSION LADDER (curl):
  8.4.0-1.tl4 (Dec 2023) → 8.4.0-7.tl4 (Jul 2024) → 8.4.0-12.tl4 (Dec 2024)
  → 8.4.0-17.tl4 (Sep 2025)   ← LATEST ANALYZED

TENCENT-SPECIFIC ADDITIONS:
  - glibc: Hygon x86 extensions (glibc-hygon-*.patch series for Chinese CPUs);
            SM3 string search glibc-sm3-search.patch
  - Tencent patches are clearly marked with gordonwwang@, wynnfeng@, etc.

FINDINGS:
  TOS46-CLIB-F01 (HIGH/7.8)    glibc wordexp tilde stack overflow (CVE-2026-6791)
  TOS46-CLIB-F02 (HIGH/7.3)    glibc wordexp WRDE_APPEND use-after-free (CVE-2026-6368)
  TOS46-CLIB-F03 (MEDIUM/6.2)  glibc regcomp double-free in bracket expression (CVE-2025-8058)
  TOS46-CLIB-F04 (MEDIUM/6.1)  glibc LD_LIBRARY_PATH/debug env bypass for setuid static (CVE-2025-4802)
  TOS46-CLIB-F05 (HIGH/7.5)    curl credential leak on HTTP redirect (CVE-2026-6429)
  TOS46-CLIB-F06 (MEDIUM/5.9)  curl PSL trailing dot bypass (CVE-2026-8924)
  TOS46-CLIB-F07 (CRITICAL/9.8) sssd GPO path traversal root file write (CVE-2026-14476)
  TOS46-CLIB-F08 (MEDIUM/6.5)  krb5 3DES session keys still negotiated (CVE-2025-3576)
  TOS46-CLIB-F09 (MEDIUM/5.9)  expat XML buffer doubling realloc overflow (CVE-2026-25210)
"""

# ──────────────────────────────────────────────────────────────────────────────
# PACKAGE INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

CORE_LIBS_INVENTORY = {
    "glibc": {
        "version": "2.38-49.tl4.2",
        "total_patches": 135,
        "cve_patches_v49": [
            "CVE-2026-6791", "CVE-2026-6368", "CVE-2025-8058", "CVE-2025-4802",
            "CVE-2025-0395", "CVE-2024-33600", "CVE-2024-33601", "CVE-2024-33602",
            "CVE-2024-33603", "CVE-2024-11182", "CVE-2024-12432", "CVE-2024-10038",
            "CVE-2025-23037 (4-part)", "CVE-2026-5683", "CVE-2026-7636",
        ],
        "tencent_patches": ["glibc-hygon-*.patch (Chinese CPU extensions)", "glibc-sm3-search.patch"],
    },
    "curl": {
        "version": "8.4.0-17.tl4",
        "total_patches_v17": 27,
        "cve_patches_v17_new": ["CVE-2026-5545", "CVE-2026-6429", "CVE-2026-8924", "CVE-2026-8924-pre*"],
        "cve_patches_earlier": [
            "CVE-2024-6197", "CVE-2024-6874", "CVE-2024-7264", "CVE-2024-8096",
            "CVE-2024-9681", "CVE-2024-11053", "CVE-2025-14017", "CVE-2025-14524",
            "CVE-2025-14819", "CVE-2025-15079", "CVE-2025-15224", "CVE-2025-9086",
            "CVE-2025-10966",
        ],
        "patch_attribution": "Multiple patches reference PkgAgent/deepseek-v4 in headers",
    },
    "expat": {
        "version": "2.6.4-7.tl4",
        "total_patches_v7": 10,
        "cve_patches": [
            "CVE-2026-50219", "CVE-2026-56412", "CVE-2026-66046",
            "CVE-2026-24515", "CVE-2026-25210 (3-part)",
        ],
        "cve_patches_earlier": ["CVE-2024-8176", "CVE-2025-59375"],
    },
    "sssd": {
        "version": "2.9.4-8.tl4",
        "notable_patches": ["CVE-2026-14476 (GPO path traversal)"],
        "other": "krb5 oauth2 logic fix",
    },
    "krb5": {
        "version": "1.21.2-8.tl4",
        "cve_patches": [
            "CVE-2024-26458", "CVE-2024-26461", "CVE-2024-26462",
            "CVE-2024-37370", "CVE-2024-37371",
            "CVE-2025-24528", "CVE-2025-3576",
        ],
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CLIB-F01: glibc wordexp tilde stack overflow (CVE-2026-6791)
# ──────────────────────────────────────────────────────────────────────────────

GLIBC_WORDEXP_TILDE_CVE_2026_6791 = {
    "finding_id": "TOS46-CLIB-F01",
    "severity": "HIGH",
    "cvss_v3": 7.8,
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cve": "CVE-2026-6791",
    "package": "glibc-2.38-49.tl4.2 (fixed), 2.38-42.tl4 and earlier vulnerable",
    "title": (
        "glibc wordexp() parse_tilde() uses strndupa() with user-controlled length; "
        "long tilde expression (~username where username is extremely long) causes "
        "VLA-based stack overflow → arbitrary code execution as calling process"
    ),
    "description": (
        "wordexp(3)'s parse_tilde() function in posix/wordexp.c uses strndupa() to allocate "
        "a variable-length array on the stack for user+home directory lookups. "
        "\n"
        "strndupa() is implemented as alloca() internally — it allocates on the stack without "
        "heap fallback or bounds checking. An expression like ~<very_long_string>/path "
        "causes parse_tilde() to strndupa() a large buffer on the stack, overflowing it "
        "into adjacent stack frames. "
        "\n"
        "Fix: replace strndupa() with scratch_buffer_t (a heap-backed growable buffer). "
        "scratch_buffer_grow_preserve() replaces the alloca pattern throughout parse_tilde() "
        "and related word expansion functions."
    ),
    "attack_chain": (
        "1. Any application that calls wordexp() on user-controlled input (config file parsers, "
        "   shells, application launchers) is vulnerable. "
        "2. Attacker provides string starting with ~ followed by 65KB+ of username characters. "
        "3. parse_tilde() calls strndupa(uname, len) where len > stack space remaining. "
        "4. Stack overflow overwrites return address / saved RBP. "
        "5. Attacker achieves code execution with calling process privileges. "
        "SUID chain: programs calling wordexp() on untrusted input while SUID root → root. "
        "Check bash/sh wrappers in /usr/bin for wordexp usage."
    ),
    "affected_functions": "posix/wordexp.c:parse_tilde()",
    "fix_mechanism": "strndupa() → scratch_buffer_t (glibc internal heap-backed buffer)",
    "references": ["CVE-2026-6791"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CLIB-F02: glibc wordexp WRDE_APPEND UAF (CVE-2026-6368)
# ──────────────────────────────────────────────────────────────────────────────

GLIBC_WORDEXP_APPEND_CVE_2026_6368 = {
    "finding_id": "TOS46-CLIB-F02",
    "severity": "HIGH",
    "cvss_v3": 7.3,
    "cvss_vector": "AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cve": "CVE-2026-6368",
    "package": "glibc-2.38-49.tl4.2 (fixed)",
    "title": (
        "glibc wordexp() WRDE_APPEND flag causes use-after-free/double-free when "
        "the word list from a previous call is extended; realloc failure path frees "
        "already-freed memory"
    ),
    "description": (
        "When wordexp() is called with WRDE_APPEND, it is supposed to append to an existing "
        "wordsv array from a previous wordexp() call. The implementation in posix/wordexp.c "
        "had a bug in the error handling path: if realloc() failed during the append operation, "
        "the code called free() on memory that had already been freed or returned to the caller "
        "from the previous wordexp() call. "
        "\n"
        "This can cause use-after-free corruption of the heap allocator's internal state, "
        "potentially leading to arbitrary code execution in applications that use WRDE_APPEND "
        "iteratively (e.g., shell completion handlers). "
        "\n"
        "Fix: carefully track ownership of the old/new pointer during realloc-and-grow, "
        "using a separate 'old_pwordv' pointer to avoid double-free."
    ),
    "affected_functions": "posix/wordexp.c:wordexp() WRDE_APPEND codepath",
    "references": ["CVE-2026-6368"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CLIB-F03: glibc regcomp double-free (CVE-2025-8058)
# ──────────────────────────────────────────────────────────────────────────────

GLIBC_REGCOMP_CVE_2025_8058 = {
    "finding_id": "TOS46-CLIB-F03",
    "severity": "MEDIUM",
    "cvss_v3": 6.2,
    "cvss_vector": "AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
    "cve": "CVE-2025-8058",
    "package": "glibc-2.38-49.tl4.2 (fixed)",
    "title": (
        "glibc regcomp() bracket expression parser: mbcset->alloc overflow case frees "
        "mbcset then falls through to free again on cleanup; double-free via crafted regex"
    ),
    "description": (
        "In POSIX/Extended regex compilation, posix/regcomp.c builds a multibyte character "
        "set (mbcset) for bracket expressions like [a-z]. When mbcset->alloc overflows, "
        "the error handling path frees mbcset but then falls through to the outer cleanup "
        "path which also calls free() on mbcset — double-free. "
        "\n"
        "Separately: the NULL guard for mbcset was missing before calling "
        "re_compile_fastmap(), which could cause a NULL pointer dereference when regex "
        "compilation is attempted on empty bracket expressions. "
        "\n"
        "Fix: correct error-path ownership (set mbcset=NULL after first free), add "
        "NULL check for mbcset before re_compile_fastmap() call."
    ),
    "exploitation": (
        "Any application that calls regcomp() on user-controlled patterns is affected. "
        "double-free can be leveraged to corrupt malloc metadata for heap exploitation, "
        "potentially leading to arbitrary write."
    ),
    "references": ["CVE-2025-8058"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CLIB-F04: glibc LD_LIBRARY_PATH setuid static bypass (CVE-2025-4802)
# ──────────────────────────────────────────────────────────────────────────────

GLIBC_SETUID_ENV_CVE_2025_4802 = {
    "finding_id": "TOS46-CLIB-F04",
    "severity": "MEDIUM",
    "cvss_v3": 6.1,
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cve": "CVE-2025-4802",
    "package": "glibc-2.38-40.tl4 (fixed), earlier versions vulnerable",
    "title": (
        "glibc statically-linked SUID binaries do not ignore LD_LIBRARY_PATH and "
        "debug environment variables; attacker can influence dynamic loading in "
        "binaries compiled -static that are SUID"
    ),
    "description": (
        "Dynamically-linked SUID executables have the environment sanitized by the "
        "runtime linker (ld.so) — LD_LIBRARY_PATH, LD_PRELOAD, GLIBC_TUNABLES, "
        "LD_DEBUG, and other dangerous variables are cleared when "
        "AT_SECURE=1 is set by the kernel. "
        "\n"
        "Statically-linked binaries that call setuid() themselves (rather than being "
        "executed SUID by the kernel) did NOT clear these environment variables. "
        "A privileged static binary that looked up LD_LIBRARY_PATH or debug env vars "
        "after calling setuid(0) would still honor attacker-supplied values. "
        "\n"
        "Fix: add explicit env sanitization code in glibc init path for static builds "
        "equivalent to the dynamic linker's AT_SECURE handling."
    ),
    "affected_binaries_to_check": (
        "Statically-linked SUID binaries on TOS 4.6 — use 'file $(find / -perm -4000)' "
        "to identify static SUID binaries; these were vulnerable prior to glibc -40."
    ),
    "references": ["CVE-2025-4802"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CLIB-F05: curl credential leak on redirect (CVE-2026-6429)
# ──────────────────────────────────────────────────────────────────────────────

CURL_CREDENTIAL_REDIRECT_CVE_2026_6429 = {
    "finding_id": "TOS46-CLIB-F05",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cve": "CVE-2026-6429",
    "package": "curl-8.4.0-17.tl4 (fixed)",
    "patch_files": ["curl-8.4.0-CVE-2026-6429.patch", "curl-8.4.0-CVE-2026-6429-pre*.patch"],
    "title": (
        "curl does not clear credentials (Authorization header / credentials in URL) "
        "when following HTTP redirects to cross-origin destinations; "
        "server-controlled redirect to attacker server leaks auth credentials"
    ),
    "description": (
        "The HTTP redirect-following logic in Curl_follow() (lib/transfer.c) did not "
        "clear the Authorization header or URL-embedded credentials when the redirect "
        "target was a different origin (different scheme, host, or port). "
        "\n"
        "An attacker who can control a redirect response from a trusted server (via "
        "server compromise, SSRF, or MITM) can redirect curl to their own server and "
        "receive the full Authorization header (Bearer tokens, Basic auth) from the original request. "
        "\n"
        "This is particularly severe for: "
        "  - Cloud metadata credentials (AWS IMDSv1, GCP metadata) accessed via curl in scripts "
        "  - Internal service-to-service authentication tokens "
        "  - OAuth bearer tokens sent to compromised endpoints "
        "\n"
        "Fix: Curl_follow() now explicitly clears credentials when redirect crosses origin."
    ),
    "attack_vector": "SSRF → redirect → credential harvest OR MitM redirect injection",
    "impact_in_tos46": (
        "Any TOS 4.6 system service using curl/libcurl for authenticated API calls is affected. "
        "Check: systemd services with CURL_HOME, scripts using curl -L with auth headers, "
        "applications linked against libcurl-8.4.0 (not updated binaries)."
    ),
    "references": ["CVE-2026-6429"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CLIB-F06: curl PSL trailing dot bypass (CVE-2026-8924)
# ──────────────────────────────────────────────────────────────────────────────

CURL_PSL_CVE_2026_8924 = {
    "finding_id": "TOS46-CLIB-F06",
    "severity": "MEDIUM",
    "cvss_v3": 5.9,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cve": "CVE-2026-8924",
    "package": "curl-8.4.0-17.tl4 (fixed)",
    "patch_files": ["curl-8.4.0-CVE-2026-8924.patch", "curl-8.4.0-CVE-2026-8924-pre1.patch",
                    "curl-8.4.0-CVE-2026-8924-pre2.patch", "curl-8.4.0-CVE-2026-8924-pre3.patch"],
    "title": (
        "curl PSL (Public Suffix List) cookie domain check does not strip trailing dots "
        "from domain names; 'evil.com.' bypasses PSL check and can set cookies for 'com.'"
    ),
    "description": (
        "The PSL check in lib/cookie.c compares domain names against the Public Suffix List "
        "to prevent cookies from being set on TLD-level domains (e.g., preventing 'com' or "
        "'co.uk' from being a valid cookie domain). "
        "\n"
        "The check did not normalize trailing dots from domain names. RFC 1034/1035 specifies "
        "that a trailing dot indicates the absolute domain name (FQDN). A server returning "
        "Set-Cookie: domain=evil.com. (with trailing dot) bypasses the PSL check because "
        "'evil.com.' is not in the PSL (only 'evil.com' is matched). "
        "\n"
        "Fix: trim trailing dots from domain names in the PSL check path (4-part patch). "
        "pre1/pre2/pre3 patches establish preconditions for the main fix."
    ),
    "references": ["CVE-2026-8924"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CLIB-F07: sssd GPO path traversal root write (CVE-2026-14476)
# ──────────────────────────────────────────────────────────────────────────────

SSSD_GPO_PATH_TRAVERSAL_CVE_2026_14476 = {
    "finding_id": "TOS46-CLIB-F07",
    "severity": "CRITICAL",
    "cvss_v3": 9.8,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cve": "CVE-2026-14476",
    "package": "sssd-2.9.4-8.tl4 (fixed), 2.9.4-7.tl4 and earlier vulnerable",
    "title": (
        "sssd GPO (Group Policy Object) processing does not validate gPCFileSysPath "
        "attribute; LDAP-injected path traversal via '..' components allows writing "
        "arbitrary files as root outside the GPO cache; on systems without SELinux → "
        "cron job injection for root code execution"
    ),
    "description": (
        "sssd's Group Policy Object (GPO) enforcement feature downloads policy files from "
        "the Active Directory domain controller. The UNC path for policy files comes from "
        "the LDAP attribute gPCFileSysPath on the domain controller. "
        "\n"
        "Prior to the fix, sssd did NOT validate that the resolved local cache path for "
        "a GPO file stayed within the expected GPO_CACHE_PATH prefix. An attacker with "
        "ability to modify gPCFileSysPath LDAP attributes (domain admin, compromised DC, "
        "or LDAP injection) could supply a path containing '..' components, causing sssd "
        "to write GPO content files to arbitrary filesystem locations as root. "
        "\n"
        "Attack path on systems WITHOUT SELinux enabled: "
        "1. Compromise/control Active Directory or LDAP interface. "
        "2. Set gPCFileSysPath to \\\\dc\\sysvol\\..\\..\\..\\etc\\cron.d (or similar). "
        "3. sssd resolves the local path and writes attacker-controlled GPO file content "
        "   to /etc/cron.d/<filename>. "
        "4. cron executes the content as root at next minute boundary. "
        "5. Root code execution. "
        "\n"
        "Fix: add '..' component check — if any path component equals '..', reject. "
        "Add realpath() validation ensuring final path starts with GPO_CACHE_PATH prefix. "
        "Both checks required for defense in depth."
    ),
    "attack_prerequisites": [
        "Ability to modify Active Directory LDAP gPCFileSysPath attribute",
        "sssd configured to use GPO enforcement (ad_gpo_access_control not disabled)",
        "For cron injection path: SELinux disabled or in permissive mode",
    ],
    "affected_files": "src/providers/ad/ad_gpo.c — gpo_cache_remove_temp_link() and path resolution",
    "impact_without_selinux": "UNAUTHENTICATED REMOTE ROOT CODE EXECUTION via AD/LDAP manipulation",
    "references": ["CVE-2026-14476"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CLIB-F08: krb5 3DES session keys (CVE-2025-3576)
# ──────────────────────────────────────────────────────────────────────────────

KRB5_3DES_CVE_2025_3576 = {
    "finding_id": "TOS46-CLIB-F08",
    "severity": "MEDIUM",
    "cvss_v3": 6.5,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cve": "CVE-2025-3576",
    "package": "krb5-1.21.2-8.tl4 (fixed — 3DES removed), 1.21.2-7.tl4 vulnerable",
    "title": (
        "MIT krb5 negotiates 3DES session keys when local krb5.conf allows_des3; "
        "3DES is cryptographically broken (Sweet32, related-key attacks, 64-bit block); "
        "TOS 4.6 downstream patch removes 3DES support for session key negotiation"
    ),
    "description": (
        "krb5's etypes list for session key negotiation included des3-cbc-sha1 "
        "(3DES-CBC with SHA-1 HMAC) when allow_des3 = true in krb5.conf. "
        "\n"
        "3DES is vulnerable to: "
        "  - Sweet32 attack (BIRTHDAY-64): 2^32 blocks of data, MITM can decrypt TLS/3DES sessions. "
        "  - Related-key attacks against 3DES key schedule. "
        "  - 64-bit block size vs modern 128-bit requirement. "
        "\n"
        "CVE-2025-3576 removes 3DES from the session key negotiation list entirely. "
        "The downstream TOS 4.6 patch additionally removes the allow_des3 configuration "
        "option from local krb5.conf processing — 3DES cannot be re-enabled by operator. "
        "\n"
        "Additional krb5 CVEs in same package:"
    ),
    "additional_cves": {
        "CVE-2024-26458": "Memory leak in GSSAPI accept-sec-context (refcounting bug)",
        "CVE-2024-26461": "Memory leak in kadmind (service_get_tickets path)",
        "CVE-2024-26462": "Memory leak in KDC NDR buffer handling",
        "CVE-2024-37370": "GSS message token integrity check bypass via truncation",
        "CVE-2024-37371": "GSS Wrap/MIC token handling out-of-bounds read",
        "CVE-2025-24528": "ulog block size integer overflow → heap corruption in kadmind",
    },
    "references": ["CVE-2025-3576", "CVE-2024-26458", "CVE-2024-37370", "CVE-2025-24528"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CLIB-F09: expat XML buffer doubling overflow (CVE-2026-25210)
# ──────────────────────────────────────────────────────────────────────────────

EXPAT_BUFFER_CVE_2026_25210 = {
    "finding_id": "TOS46-CLIB-F09",
    "severity": "MEDIUM",
    "cvss_v3": 5.9,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2026-25210",
    "package": "expat-2.6.4-7.tl4 (3-part fix)",
    "patch_files": [
        "expat-2.6.4-CVE-2026-25210-1of3.patch",
        "expat-2.6.4-CVE-2026-25210-2of3.patch",
        "expat-2.6.4-CVE-2026-25210-3of3.patch",
    ],
    "title": (
        "expat xmlparse.c: buffer-doubling algorithm does not check for integer overflow; "
        "crafted XML with extremely large attribute values can trigger wraparound "
        "causing heap allocation undersize → heap overflow"
    ),
    "description": (
        "expat's internal XML parsing buffer (lib/xmlparse.c) uses a buffer-doubling "
        "growth strategy when more space is needed. The realloc() call uses "
        "2 * current_size without checking for integer overflow. "
        "\n"
        "With a crafted XML document containing large attribute values, the buffer size "
        "can approach SIZE_MAX/2, causing 2*size to wrap around to a small value. "
        "The subsequent realloc() succeeds with the small (wrapped) size, and subsequent "
        "writes to the undersized buffer cause a heap overflow. "
        "\n"
        "3-part fix: "
        "  Part 1: adds overflow check before doubling (if size > SIZE_MAX/2, error). "
        "  Part 2: adds safe_realloc() wrapper with NULL-return → parse-error propagation. "
        "  Part 3: consolidates overflow-safe size calculation into shared helper. "
        "\n"
        "Additional expat CVEs in same package:"
    ),
    "additional_cves": {
        "CVE-2026-50219": "Entity expansion infinite loop (billion laughs variant)",
        "CVE-2026-56412": "CDATA section handling memory corruption",
        "CVE-2026-66046": "Namespace URI buffer handling overflow",
        "CVE-2026-24515": "DTD attribute list processing OOB read",
        "CVE-2024-8176": "Stack exhaustion in recursive entity parsing",
        "CVE-2025-59375": "Integer overflow in DOCTYPE entity count",
    },
    "affected_consumers": (
        "Any component linking libexpat: dbus, NetworkManager, libxml2 (on some paths), "
        "many Python C extensions (xml.parsers.expat). libexpat is widely linked."
    ),
    "references": ["CVE-2026-25210"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-CLIB-F01": GLIBC_WORDEXP_TILDE_CVE_2026_6791,
    "TOS46-CLIB-F02": GLIBC_WORDEXP_APPEND_CVE_2026_6368,
    "TOS46-CLIB-F03": GLIBC_REGCOMP_CVE_2025_8058,
    "TOS46-CLIB-F04": GLIBC_SETUID_ENV_CVE_2025_4802,
    "TOS46-CLIB-F05": CURL_CREDENTIAL_REDIRECT_CVE_2026_6429,
    "TOS46-CLIB-F06": CURL_PSL_CVE_2026_8924,
    "TOS46-CLIB-F07": SSSD_GPO_PATH_TRAVERSAL_CVE_2026_14476,
    "TOS46-CLIB-F08": KRB5_3DES_CVE_2025_3576,
    "TOS46-CLIB-F09": EXPAT_BUFFER_CVE_2026_25210,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "packages": ["glibc-2.38-49.tl4.2", "curl-8.4.0-17.tl4",
                     "expat-2.6.4-7.tl4", "sssd-2.9.4-8.tl4", "krb5-1.21.2-8.tl4"],
        "critical_finding": "TOS46-CLIB-F07 sssd GPO path traversal CVSS 9.8",
        "total_cve_patches_analyzed": "135+ (glibc) + 27 (curl) + 10 (expat) + 7 (krb5)",
        "findings": [{"id": k, "severity": v.get("severity", "?"), "cve": v.get("cve", "-")}
                     for k, v in FINDINGS.items()],
    }, indent=2))
