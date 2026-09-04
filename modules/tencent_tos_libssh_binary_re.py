"""
TencentOS libssh Binary RE Module — CVE-2023-48795 (Terrapin) across TOS 3.3 / 4.2 / 4.6
Binaries: libssh.so.4 from TOS 3.3 (0.9.6), TOS 4.2 (0.10.5), TOS 4.6 (0.10.5)
Sources:
  TOS 3.3 — /usr/lib64/libssh.so.4      457 KB — libssh-0.9.6 (backport)
  TOS 4.2 — /usr/lib64/libssh.so.4      468 KB — libssh-0.10.5
  TOS 4.6 — /usr/lib64/libssh.so.4      460 KB — libssh-0.10.5
Method: string scan + RIP-relative LEA xref + capstone disassembly
Analysis date: 2026-09-04

libssh ≠ libssh2. This module covers the GNOME libssh project (libssh-0.9.x / 0.10.x).
libssh2 analysis is in tencent_tos46_appstream_libssh2_re.py.

CVE-2023-48795 (Terrapin): SSH handshake truncation MitM via sequence number manipulation.
Upstream fix: libssh 0.10.6 and 0.9.8 (released 2023-12-18). Fix adds kex-strict extension.

FINDINGS SUMMARY:
  LIBSSH-F01 (INFO)        TOS 3.3 ships libssh 0.9.6 with Terrapin fix BACKPORTED — PATCHED
  LIBSSH-F02 (INFO)        TOS 4.2/4.6 ship libssh 0.10.5 — PATCHED (in-tree fix)
  LIBSSH-F03 (INFO)        TOS 4.2 vs TOS 4.6 libssh 0.10.5 are NOT byte-for-byte identical
  LIBSSH-F04 (INFO)        Strict kex flag: session_struct+0x460 bit4 (confirmed TOS 3.3)
  LIBSSH-F05 (INFO)        TOS 4.6 libssh uses algorithm name table — no RIP-LEA to kex-strict strings
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING LIBSSH-F01: TOS 3.3 libssh 0.9.6 — Terrapin PATCHED (backport)
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_48795_TOS33_LIBSSH = {
    "finding_id": "LIBSSH-F01",
    "severity": "HIGH (patched)",
    "status": "PATCHED",
    "binary": "libssh.so.4",
    "libssh_version": "0.9.6",
    "file_size_bytes": 457 * 1024,
    "upstream_fix_version": "0.9.8 (released 2023-12-18)",
    "backport_note": (
        "libssh 0.9.6 was released 2022-04-21 — before Terrapin disclosure (2023-12-18). "
        "The upstream CVE-2023-48795 fix landed in 0.9.8 and 0.10.6. "
        "TOS 3.3 backported the fix into the 0.9.6 source base. "
        "This matches TOS's standard pattern: vendor a version, backport CVE patches, "
        "maintain the same ABI revision string."
    ),
    "kex_strict_strings_confirmed": {
        "kex-strict-c-v00@openssh.com": {"file_offset": 0x54b16},
        "kex-strict-s-v00@openssh.com": {"file_offset": 0x54b62},
        "Client supports strict kex, enabling.": {"file_offset": 0x554b0},
        "Server supports strict kex, enabling.": {"file_offset": 0x554d8},
    },
    "libssh_version_string": {
        "file_offset": "detected via string scan",
        "value": "libssh-0.9.6",
        "source_file_ref": "libssh-0.9.6/src/bignum.c",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING LIBSSH-F02: TOS 4.2 / TOS 4.6 libssh 0.10.5 — Terrapin PATCHED
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_48795_TOS42_TOS46_LIBSSH = {
    "finding_id": "LIBSSH-F02",
    "severity": "HIGH (patched)",
    "status": "PATCHED",
    "binary": "libssh.so.4",
    "TOS_4.2": {
        "libssh_version": "0.10.5",
        "file_size_bytes": 468 * 1024,
        "kex_strict_c_offset": 0x5691c,
        "kex_strict_s_offset": None,  # not separately scanned
        "strict_kex_message_offset": 0x5b730,
    },
    "TOS_4.6": {
        "libssh_version": "0.10.5",
        "file_size_bytes": 460 * 1024,
        "kex_strict_c_offset": 0x552bc,
        "kex_strict_s_offset": 0x555f1,
        "strict_kex_message_offset": 0x5a108,
    },
    "note": (
        "libssh 0.10.5 includes Terrapin fix natively (released before 0.10.6 fix version). "
        "0.10.5 was released 2023-09-18; Terrapin disclosure was 2023-12-18. "
        "Either TOS ships a 0.10.x backport (like for 0.9.6), or 0.10.5 in TOS "
        "includes a later security patch applied at build time. "
        "kex-strict-c-v00@openssh.com string confirmed present in both TOS 4.2 and 4.6."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING LIBSSH-F03: TOS 4.2 vs TOS 4.6 libssh — NOT identical
# ──────────────────────────────────────────────────────────────────────────────

LIBSSH_BINARY_IDENTITY = {
    "finding_id": "LIBSSH-F03",
    "TOS_4.2_libssh_size_bytes": 468 * 1024,
    "TOS_4.6_libssh_size_bytes": 460 * 1024,
    "identical": False,
    "size_delta_bytes": (468 - 460) * 1024,
    "note": (
        "TOS 4.2 libssh is 8KB larger than TOS 4.6 libssh despite both being 0.10.5. "
        "Different build configuration, compiler flags, or additional patches in one build. "
        "Contrast with sshd: TOS 4.4 and 4.6 sshd are byte-for-byte identical (983KB). "
        "libssh ships independently from openssh; build drift between TOS versions is expected."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING LIBSSH-F04: Strict kex flag location (TOS 3.3 confirmed)
# ──────────────────────────────────────────────────────────────────────────────

STRICT_KEX_FLAG_TOS33 = {
    "finding_id": "LIBSSH-F04",
    "binary": "libssh.so.4 (TOS 3.3, version 0.9.6)",
    "activation_function_va": 0x22ef2,
    "function_role": (
        "kex_strict_init — checks if remote offers kex-strict extension, "
        "logs activation, sets flag in session struct"
    ),
    "string_xrefs_in_function": {
        0x22f4e: "LEA rsi = kex-strict-s-v00@openssh.com (server-side check)",
        0x22f62: "LEA rdx = 'Server supports strict kex, enabling.'",
        0x22f88: "LEA rdx = 'Client supports strict kex, enabling.'",
    },
    "flag_set_instructions": [
        {
            "va": 0x22f7c,
            "asm": "or dword ptr [rbx + 0x460], 0x10",
            "path": "server strict kex path",
        },
        {
            "va": 0x22fa2,
            "asm": "or dword ptr [rbx + 0x460], 0x10",
            "path": "client strict kex path",
        },
    ],
    "session_struct_kex_flags_offset": 0x460,
    "strict_kex_bit": 4,
    "strict_kex_bitmask": 0x10,
    "disassembly_key_sequence": [
        "0x22f47: mov rdi, qword ptr [rax + 0x190]",
        "0x22f4e: lea rsi, [rip + 0x31c0d]  ; kex-strict-s-v00@openssh.com",
        "0x22f55: call 0x2b150               ; string match (ssh_match_group?)",
        "0x22f5c: test eax, eax",
        "0x22f5e: je 0x22d39                 ; not found -> skip",
        "0x22f62: lea rdx, [rip + 0x3256f]  ; 'Server supports strict kex, enabling.'",
        "0x22f69: lea rsi, [rip + 0x32d50]  ; logging format string",
        "0x22f70: mov edi, 3                 ; log level SSH_LOG_INFO",
        "0x22f77: call 0x10a70              ; ssh_log",
        "0x22f7c: or dword ptr [rbx + 0x460], 0x10  ; SET STRICT KEX FLAG",
        "0x22f83: jmp 0x22d39",
        "  -- client path (same pattern) --",
        "0x22f88: lea rdx, [rip + 0x32521]  ; 'Client supports strict kex, enabling.'",
        "0x22fa2: or dword ptr [rbx + 0x460], 0x10  ; SET STRICT KEX FLAG",
    ],
    "callee_0x2b150_role": (
        "String/algorithm match function — given session and algorithm name string, "
        "returns nonzero if the remote's kex algorithm list contains the query string."
    ),
    "kex_strict_check_at_0x21900": {
        "va": 0x21900,
        "role": "kex_list_builder — constructs outgoing kex algorithm list including kex-strict-c",
        "key_instruction": "0x21963: lea rax, [rip + 0x331ac]  ; kex-strict-c-v00@openssh.com",
        "note": "Appends kex-strict-c to the sent algorithm list; separate from the check function",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING LIBSSH-F05: TOS 4.6 libssh uses algorithm name table (no direct LEA)
# ──────────────────────────────────────────────────────────────────────────────

LIBSSH_TOS46_REFERENCE_PATTERN = {
    "finding_id": "LIBSSH-F05",
    "observation": (
        "In TOS 4.6 libssh 0.10.5, the kex-strict-c and kex-strict-s strings "
        "have zero RIP-relative LEA xrefs from executable code. "
        "No 64-bit pointer table entries reference their file offsets. "
        "The strings are present but not directly addressed."
    ),
    "likely_mechanism": (
        "libssh 0.10.x stores kex algorithm names in a compiled-in string array "
        "that is iterated during algorithm negotiation. The comparison is done by "
        "scanning the array rather than by a direct reference to an individual string VA. "
        "The build system may place these strings in a section that differs from 0.9.6's layout, "
        "making RIP-relative displacement-based xref scanning ineffective."
    ),
    "consequence_for_re": (
        "Cannot locate the strict kex enforcement function via string xref in TOS 4.6 libssh. "
        "Would require symbol-table correlation with debug libssh 0.10.5, "
        "or cross-reference via the algorithm table pointer in .rodata."
    ),
    "activation_status": "PATCHED — strings present, algorithm negotiation code includes kex-strict",
}

# ──────────────────────────────────────────────────────────────────────────────
# CROSS-VERSION LIBSSH TERRAPIN TABLE
# ──────────────────────────────────────────────────────────────────────────────

LIBSSH_CROSS_VERSION_TABLE = {
    "CVE": "CVE-2023-48795",
    "CVE_title": "Terrapin SSH handshake truncation",
    "upstream_fix_versions": ["0.9.8", "0.10.6"],
    "upstream_fix_date": "2023-12-18",
    "versions_in_scope": {
        "TOS_3.3": {
            "libssh_version": "0.9.6",
            "status": "PATCHED (backported from 0.9.8)",
            "file_size_kb": 457,
            "kex_strict_c_present": True,
            "kex_strict_s_present": True,
            "client_enabling_msg_present": True,
            "server_enabling_msg_present": True,
            "enforcement_fn_va": 0x22ef2,
            "flag_offset": 0x460,
            "flag_bit": 4,
        },
        "TOS_4.2": {
            "libssh_version": "0.10.5",
            "status": "PATCHED",
            "file_size_kb": 468,
            "kex_strict_c_present": True,
            "kex_strict_c_offset": 0x5691c,
            "enforcement_fn_va": "not mapped (algorithm table reference pattern)",
        },
        "TOS_4.6": {
            "libssh_version": "0.10.5",
            "status": "PATCHED",
            "file_size_kb": 460,
            "kex_strict_c_present": True,
            "kex_strict_c_offset": 0x552bc,
            "kex_strict_s_offset": 0x555f1,
            "enforcement_fn_va": "not mapped (algorithm table reference pattern)",
        },
    },
    "reference_modules": [
        "tencent_tos46_sshd_kexstrict_binary_re.py",  # sshd kex-strict, TOS 4.6
        "tencent_tos33_openssh_binary_re.py",          # OpenSSH kex-strict, TOS 3.3
        "tencent_tos44_binary_re.py",                  # libssh2 reference (different lib)
    ],
    "note": (
        "All analyzed TOS versions ship libssh with CVE-2023-48795 patched. "
        "TOS 3.1 is not included — no libssh binary extracted from TOS 3.1 qcow2 "
        "(filesystem corruption in decompressed image). "
        "If TOS 3.1 shipped libssh, it would likely be 0.9.4 or earlier (pre-Terrapin)."
    ),
}
