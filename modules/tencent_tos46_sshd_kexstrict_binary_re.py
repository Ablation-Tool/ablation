"""
TencentOS Server 4.6 sshd Kex-Strict Binary RE Module
Binary: sshd (from TOS 4.6 qcow2 /usr/sbin/sshd)
        openssh-9.3p1 (or equivalent) build included in TOS 4.6
Source: /dev/nbd10 mount of TOS 4.6 qcow2
Method: String cross-reference scan -> function boundary detection -> capstone disassembly
Analysis date: 2026-09-04

CVE-2023-48795 (Terrapin): SSH handshake sequence number manipulation via MitM.
Fix: kex-strict extension (kex-strict-s-v00@openssh.com / kex-strict-c-v00@openssh.com).
     Both sides advertise support; if both present, strict sequencing enforced.

FINDINGS SUMMARY:
  TOS46-SSHD-F01 (HIGH/7.3)  CVE-2023-48795 PATCHED — kex-strict string confirmed in sshd binary
  TOS46-SSHD-F02 (INFO)       kex-strict string at file_offset 0xa1244
  TOS46-SSHD-F03 (INFO)       kex-strict registered at VA 0x7b9f0; activation at VA 0x19177
  TOS46-SSHD-F04 (INFO)       kex-strict flag stored at kex_struct+0x4c = 1 when active
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSHD-F01: CVE-2023-48795 Terrapin — PATCHED
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_48795_TOS46 = {
    "binary": "sshd",
    "version": "TOS 4.6 (openssh-9.x equivalent build)",
    "status": "PATCHED",
    "string_evidence": {
        "string": "kex-strict-s-v00@openssh.com",
        "file_offset": 0xa1244,
        "binary_value": b"kex-strict-s-v00@openssh.com",
    },
    "tos31_comparison": {
        "version": "openssh-8.0p1-13.tl3",
        "status": "OPEN — kex-strict strings absent from TOS 3.1 binary/SRPM",
    },
    "tos33_comparison": {
        "version": "openssh-8.0p1-25.tl3",
        "status": "PATCHED — kex-strict strings confirmed in TOS 3.3 sshd",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSHD-F02/F03: kex-strict string cross-references
# ──────────────────────────────────────────────────────────────────────────────
# String "kex-strict-s-v00@openssh.com" at file_offset 0xa1244
# Cross-references found at: 0x19177, 0x19527, 0x7b9f0

KEX_STRICT_STRING_XREFS = {
    "string_offset": 0xa1244,
    "string_value": "kex-strict-s-v00@openssh.com",
    "xref_count": 3,
    "xrefs": {
        0x19177: {
            "context_fn_start": 0x1912a,
            "role": "kex_proposals_populate() — adds kex-strict to server's kex proposal",
            "instruction": "lea rsi, [rip + 0x880c6]  ; -> 0xa1244",
            "follows": "jmp 0x18e6d  ; continues to build kex name list",
            "note": "Second argument (rsi) for kex name string — included in server hello proposal",
        },
        0x19527: {
            "context_fn_start": 0x19327,
            "role": "kex_proposal_check() or kex_names_valid() — validation function",
            "instruction": "lea rsi, [rip + ...]  ; -> 0xa1244 (within proposal check context)",
        },
        0x7b9f0: {
            "context_fn_start": 0x7b9f0,
            "role": "kex_strict_activate() — activates strict mode when peer supports it",
            "instruction": "lea rsi, [rip + 0x2584d]  ; -> 0xa1244",
            "follows": "call 0x9b1d0  ; match_pattern() — checks if client offered kex-strict",
            "activation_flag": {
                "offset_in_kex_struct": 0x4c,
                "value": 1,
                "instruction": "mov dword ptr [rax + 0x4c], 1  ; kex->flags |= STRICT",
                "va": 0x7ba56,
            },
            "note": (
                "If call 0x9b1d0 (match_pattern) returns non-NULL (client supports kex-strict), "
                "then: sets kex_struct+0x4c = 1 to enable strict sequence checking. "
                "This is the activation point for the Terrapin defense."
            ),
        },
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSHD-F04: kex_struct layout (kex-strict flag offset)
# ──────────────────────────────────────────────────────────────────────────────

KEX_STRUCT_LAYOUT_PARTIAL = {
    "finding_id": "TOS46-SSHD-F04",
    "note": "Partial layout derived from kex-strict activation code at VA 0x7b9f0",
    "confirmed_fields": {
        0x4c: {
            "name": "strict_kex_flag",
            "type": "int32",
            "value_when_active": 1,
            "set_by": "VA 0x7ba56: mov dword ptr [rax + 0x4c], 1",
        },
        0xb0: {
            "name": "unknown_kex_field",
            "notes": "mov qword ptr [rcx + 0xb0], rdx at VA 0x7b9d0",
        },
    },
    "activation_disasm": {
        # From fn starting at 0x7b9f0 (kex-strict activation)
        0x7b9f0: "lea        rsi, [rip + 0x2584d]  ; -> 0xa1244 (kex-strict-s-v00@...)",
        0x7b9f7: "movd       dword ptr [rsp + 0x10], xmm0",
        0x7b9fd: "call       0x9b1d0                ; match_pattern(kex-strict-s string, client_proposal)",
        0x7ba02: "movd       xmm0, dword ptr [rsp + 0x10]",
        0x7ba08: "test       rax, rax",
        0x7ba0b: "mov        rdi, rax",
        0x7ba0e: "je         0x7bf2b",              # client doesn't support kex-strict: skip
        # activation path (client supports kex-strict):
        0x7ba14: "movd       dword ptr [rsp + 0x38], xmm0",
        0x7ba1a: "call       0x114a0",              # free match result
        0x7ba4c: "mov        ecx, 1",
        0x7ba56: "mov        dword ptr [rax + 0x4c], 1",  # kex->flags = STRICT_KEX
        0x7ba7a: "test       r15d, r15d",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# ABLATION SEMANTIC SWEEP RESULTS (sshd 556 functions)
# ──────────────────────────────────────────────────────────────────────────────

ABLATION_SWEEP_TOS46_SSHD = {
    "total_functions_extracted": 556,
    "prologue_method": "push rbp / endbr64+push rbp scan",
    "bert_model": "sentence-transformers/all-MiniLM-L6-v2",
    "query_profiles": [
        "SSH_KEX | calls: match_pattern | kex: strict sequence enforcement for Terrapin prevention",
        "SSH_KEX_STRICT | vuln: sequence number manipulation MitM prevention via strict kex extension",
    ],
    "top_candidates": [
        {
            "va": 0x1409d,
            "similarity": 0.2398,
            "label": "kex proposal building top candidate",
        },
    ],
    "confirmed_kex_strict_fns": {
        "proposal_add": 0x19177,
        "activation_check": 0x7b9f0,
    },
    "xref_method": "string cross-reference scan for 0xa1244 (kex-strict-s-v00@openssh.com)",
}

# ──────────────────────────────────────────────────────────────────────────────
# BINARY METADATA
# ──────────────────────────────────────────────────────────────────────────────

SSHD_TOS46_METADATA = {
    "path": "scratchpad/tos46-bins/sshd",
    "source": "TOS 4.6 qcow2 /usr/sbin/sshd",
    "size_bytes": 984 * 1024,   # ~984KB
    "stripped": True,
    "pie": True,
    "nx": True,
    "canary": True,
    "relro": "partial",
    "symbols": "PLT only (no internal symbols)",
    "va_equals_file_offset": True,  # confirmed for this binary
    "kex_strict_string_file_offset": 0xa1244,
}
