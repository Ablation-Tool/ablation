"""
TencentOS 4.6 — 389-ds-base binary RE (libback-ldbm.so + libpwdstorage-plugin.so).

Binaries analyzed:
  ds_work/usr/sbin/ns-slapd           — 473KB stripped PIE (thin loader, 179 functions)
  ds_work/usr/lib64/dirsrv/plugins/libback-ldbm.so  — 765KB stripped SO (LDBM backend, 731 funcs)
  ds_work/usr/lib64/dirsrv/plugins/libpwdstorage-plugin.so — 42KB stripped SO (63 funcs)

Method: endbr64-based function detection → capstone disassembly → BERT semantic sweep
(sentence-transformers/all-MiniLM-L6-v2) → 6-query profile per library.

Build: 2024-09-10 (BuildID sha1 confirmed)
Version: 389-ds-base 1.4.3.39 (TOS 4.6)

Key results:
  CVE-2024-3657 fix: PRESENT — encode_size[] table at ldbm offset 0x93240
  CVE-2024-5953 fix: PRESENT — pbkdf2 size check at 0x6305 (cmp eax, 0x144; ja error)
  Additional HIGH-confidence patterns: none found beyond patched CVEs
"""

BINARY_INVENTORY = {
    "ns-slapd": {
        "path": "ds_work/usr/sbin/ns-slapd",
        "size": 473488,
        "type": "PIE executable",
        "stripped": True,
        "build_id": "57d9263b6074825f80ec2ac9c272181cd6af8cec",
        "text_section": {"foff": 0x12da0, "va": 0x12da0, "size": 143225},
        "functions_detected": 179,
        "note": (
            "Thin launcher/framework binary. Most LDAP engine code is in plugin .so files. "
            "Only 179 functions vs 731 in libback-ldbm.so. "
            "Notable function: 0x26600 — attribute name registration for 'unhashed#user#password' "
            "(case-insensitive attribute name comparator, not password logic itself)."
        ),
    },
    "libback-ldbm.so": {
        "path": "ds_work/usr/lib64/dirsrv/plugins/libback-ldbm.so",
        "size": 765504,
        "type": "shared object",
        "stripped": True,
        "build_id": "5631762e595121366e0e417988abb2f50243af10",
        "text_size": 451618,
        "functions_detected": 731,
        "key_functions": {
            "0x29500": "filter_candidates_ext — LDAP filter dispatch, 392-byte stack frame",
            "0x63160": "sort_candidates — VLV sort with 'Sorting done' log string",
            "0x32fa0": "index_read_ext_allids — allids threshold index read path",
            "0x65da0": "vlv_filter_candidates — Virtual List View filter",
        },
        "encode_size_table": {
            "offset": 0x93240,
            "size": 256,
            "description": "encode_size[256] lookup table for CVE-2024-3657 fix",
            "values": {
                "0x00-0x1F": 3,   # control chars → \\xx (3 bytes)
                "0x20-0x21": 1,   # space, ! → literal (1 byte)
                "0x22": 2,        # double quote → \\22 (2 bytes)
                "0x23-0x5B": 1,   # printable → literal
                "0x5C": 2,        # backslash → \\\\ (2 bytes)
                "0x5D-0x7E": 1,   # printable → literal
                "0x7F-0xFF": 3,   # non-ASCII → \\xx (3 bytes)
            },
            "verification": "table[0x22]=2, table[0x5c]=2, table[0x41]=1, table[0x80]=3 — matches patch exactly",
        },
    },
    "libpwdstorage-plugin.so": {
        "path": "ds_work/usr/lib64/dirsrv/plugins/libpwdstorage-plugin.so",
        "size": 42008,
        "type": "shared object",
        "stripped": True,
        "build_id": "e19c99035822bb7d80f65f717413c4a167bb8140",
        "text_size": 13465,
        "functions_detected": 63,
        "key_functions": {
            "0x3647": "md5_check area — 'MD5 password hash', 'Could not base64 encode hashed value'",
            "0x3680": "md5_hash_generate — stack frame 0x88, digest operations, '{MD5}' prefix",
            "0x6250": "pbkdf2_init — reads nsslapd-pluginEnabled config",
            "0x6260": "pbkdf2_check — CVE-2024-5953 fix: hash size validation at 0x6305",
            "0x54f0": "sha512_check — SHA512 password scheme handler",
            "0x65a0": "gost_yescrypt_check — 'Unable to use gost_yescrypt_pw_enc, xcrypt is not available'",
        },
    },
}

CVE_BINARY_VERIFICATION = {
    "CVE-2024-3657": {
        "status": "PATCHED — CONFIRMED at binary level",
        "binary": "libback-ldbm.so",
        "evidence": (
            "encode_size[256] table present at offset 0x93240 in libback-ldbm.so. "
            "Table values match CVE-2024-3657 patch exactly: "
            "control chars (0x00-0x1F) and high-byte (0x7F-0xFF) → 3; "
            "quote (0x22) and backslash (0x5C) → 2; all other printable → 1. "
            "Table is used in the berval-to-ASCII encoding path in index.c to "
            "pre-compute buffer size before allocation, preventing the heap overflow."
        ),
        "patch_author": "Pierre Rogier (Red Hat)",
    },
    "CVE-2024-5953": {
        "status": "PATCHED — CONFIRMED at binary level",
        "binary": "libpwdstorage-plugin.so",
        "evidence": (
            "pbkdf2_check function at 0x6260: at offset 0x6305, instruction "
            "'cmp eax, 0x144; ja 0x6397' validates the decoded hash length "
            "against 0x144 (324 bytes) before processing. "
            "The 0x6397 error path logs 'PBKDF2_SHA256' at warn level and returns 1 (failure). "
            "This prevents the out-of-bounds read when hash size field is incoherent. "
            "Truncated string in binary 'Unable to base64 decode dbpwd value. (hashed value is too lo' "
            "completes as 'hashed value is too long' — matches the new error message in the patch."
        ),
        "patch_author": "Pierre Rogier (Red Hat)",
    },
    "CVE-2024-2199": {
        "status": "PATCHED — INFERRED (patch in spec, binary logic consistent)",
        "binary": "ns-slapd (modify.c logic in ns-slapd proper)",
        "evidence": (
            "The ns-slapd binary is too thin (179 functions) to contain the full modify.c logic; "
            "most modify processing is in libslapd.so (not extracted). "
            "Binary string 'check value is utf8 string' not found in ns-slapd binary — "
            "this string is part of the CVE-2024-2199 fix error message, expected in libslapd.so. "
            "Patch presence inferred from spec version (1.4.3.39-8 applies Patch06)."
        ),
    },
}

FILTER_CANDIDATES_ANALYSIS = {
    "function": "filter_candidates_ext",
    "va": 0x29500,
    "stack_frame_bytes": 392,
    "dispatch_pattern": (
        "Function dispatches on LDAP filter type via: "
        "lea rsi, [rip+0x68144] (loads 'filter_candidates_ext' for logging); "
        "cmp edx, 0x22; ja 0x29bd0 — handles filter types 0x87 through 0xa9 "
        "(all standard LDAP filter types: EQ/SUB/GE/LE/PRESENT/APPROX/AND/OR/NOT). "
        "Jump table at 0x29bd0 dispatches 35 type cases."
    ),
    "recursion_note": (
        "Function consumes 392+ bytes of stack per call frame. "
        "For AND/OR filter types, 389-ds evaluates subfilters by calling back into "
        "the filter evaluation engine. A deeply nested AND/OR filter "
        "(e.g., 10,000 levels deep) would consume ~4MB of stack, "
        "approaching the default 8MB thread stack limit. "
        "389-ds 1.4.3.x implemented filter subexpression limiting upstream (ndn_ht_t limits), "
        "but binary-level recursion depth guard not confirmed in this function's assembly. "
        "BERT sweep score 0.371 — insufficient confidence for a standalone finding."
    ),
    "verdict": "INCONCLUSIVE — depth limit not confirmed at binary level",
}

PWDSTORAGE_SCHEMES = {
    "confirmed_in_binary": [
        "MD5 ({MD5} prefix, md5_hash_generate @ 0x3680)",
        "PBKDF2_SHA256 (pbkdf2_check @ 0x6260)",
        "SHA512 (sha512_check @ 0x54f0)",
        "GOST_YESCRYPT (gost_yescrypt_check @ 0x65a0 — xcrypt optional)",
        "SSHA, SHA1, SHA256 (string evidence in pwdstorage plugin)",
    ],
    "note": (
        "MD5 password scheme still present and callable. "
        "If a legacy account uses {MD5} hashing, the scheme is handled. "
        "MD5 is not secure for password storage (preimage attacks). "
        "Admins must explicitly migrate to PBKDF2_SHA256 or SHA512."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "CVE-2024-3657 fix BINARY-CONFIRMED: encode_size[256] at ldbm:0x93240",
        "detail": (
            "encode_size[] lookup table present in libback-ldbm.so at offset 0x93240. "
            "Values: 3 for control/high-byte chars, 2 for quote/backslash, 1 for printable. "
            "Matches Pierre Rogier (Red Hat) patch exactly. Buffer overflow prevented."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "CVE-2024-5953 fix BINARY-CONFIRMED: pbkdf2 size check at 0x6305",
        "detail": (
            "libpwdstorage-plugin.so pbkdf2_check @ 0x6305: 'cmp eax, 0x144; ja error'. "
            "Hash length validated ≤ 324 before processing. "
            "Error path at 0x6397 logs PBKDF2_SHA256 at warning level, returns 1 (failure). "
            "Pre-auth DoS vector closed."
        ),
    },
    {
        "id": "F3",
        "severity": "LOW",
        "title": "MD5 password scheme present: legacy accounts vulnerable to preimage attack",
        "detail": (
            "libpwdstorage-plugin.so contains MD5 password scheme ('{MD5}' prefix). "
            "Accounts with {MD5}-hashed passwords are vulnerable to preimage attacks. "
            "No runtime enforcement prevents new accounts from using MD5. "
            "Admin action required: migrate all {MD5} accounts to PBKDF2_SHA256."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "filter_candidates_ext: 392-byte stack frame, recursion depth not binary-confirmed",
        "detail": (
            "filter_candidates_ext @ 0x29500: large per-frame stack allocation. "
            "Nested AND/OR filter evaluation pattern detected. "
            "Recursion depth guard not confirmed at binary level (BERT score 0.371 — low confidence). "
            "389-ds 1.4.3.x has upstream ndn_ht_t limits; binary verification inconclusive."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "ns-slapd: thin 179-function binary — LDAP engine in plugins, not executable",
        "detail": (
            "ns-slapd is a 473KB launcher with 179 endbr64-detected functions. "
            "Core LDAP processing: libback-ldbm.so (731 funcs), libpwdstorage-plugin.so (63 funcs), "
            "and other plugin .so files. Binary RE must target plugins, not the main executable."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 389-ds binary RE")
    print(f"  ns-slapd: {BINARY_INVENTORY['ns-slapd']['functions_detected']} funcs")
    print(f"  libback-ldbm.so: {BINARY_INVENTORY['libback-ldbm.so']['functions_detected']} funcs")
    print(f"  libpwdstorage-plugin.so: {BINARY_INVENTORY['libpwdstorage-plugin.so']['functions_detected']} funcs")
    print()
    print("CVE binary verification:")
    for cve, v in CVE_BINARY_VERIFICATION.items():
        print(f"  {cve}: {v['status']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
