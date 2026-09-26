"""
FortiGate 7000F -- FortiOS 8.0.0 build 0167 -- libips.so.new + libav.so.new RE
Binary: /home/cowboy/ablation/fortigate-work/extract/datafs/lib/libips.so.new (SHA256: fdfaceccdc740d82...)
Session: targets/fortinet/SESSION_fgt7kf.md (last updated: session 8, 2026-09-25)

Findings: C14 ELIMINATED, C16 ELIMINATED, C17 CONFIRMED HIGH, C18 CANDIDATE LOW,
          C19 CANDIDATE LOW, FGT7K-4 CONFIRMED HIGH.
Source reconstructed from pyc + session notes (original source lost after session 7).
"""

FINDINGS = {
    "C14_libips_indirect_guard_underflow": {
        "binary": "libips.so.new",
        "func_va": 0x29fa90,
        "func_name": "ips_indirect_guard_handler",
        "description": (
            "func=0x29fa90 loads a 16-bit length field from offset 0x20 of an inbound struct "
            "(movzx eax, word ptr [rdi+0x20]), subtracts 16 to strip a fixed header "
            "(lea r12d, [rax-0x10]), then passes the result to 0x9efa8 after a "
            "movzx r15d, r12w truncation. If the field value is < 16, r12d underflows "
            "to a large positive value (e.g., 65520 when field=0). Guard at 0x29fab6 "
            "checks ecx vs (rdx_low16 + r12w)."
        ),
        "code_trace": (
            "0x29faa4: movzx eax, word ptr [rdi+0x20]   wire LENGTH (< 16 triggers underflow)\n"
            "0x29faa8: lea r12d, [rax-0x10]             r12d = LENGTH-16 (underflows)\n"
            "0x29faac: movzx eax, dx                    eax = rdx low 16 = 0xcf00\n"
            "0x29faaf: movzx r15d, r12w                 r15d = 65520 when LENGTH < 16\n"
            "0x29fab3: add eax, r15d                    eax = 0xcf00 + 65520 = 118512\n"
            "0x29fab6: cmp ecx, eax                     GUARD: ecx >= 118512?\n"
            "0x29fab8: jb 29fb30                        fail if not"
        ),
        "status": "ELIMINATED",
        "elimination_reason": (
            "Guard at 0x29fab6 (cmp ecx, eax; jb exit) requires ecx >= 118512. "
            "Full caller trace (session 8, 2026-09-25): only dispatch site is 0xef9ec "
            "in function 0xef210, via call [r15+0x38] where r15 loaded from global 0x11b32f8. "
            "ecx at 0xef9ec derives from call 0x17a140 (time-of-day calc, ceiling 86400) "
            "via call 0x663cd0 fast path, OR from allocator 0x103b90 via not-found path. "
            "86400 < 118512 -- guard cannot pass from any normal call path. "
            "ecx is NOT wire-controlled. ELIMINATED."
        ),
        "caller_trace": {
            "dispatch_site": "0xef9ec in function 0xef210",
            "dispatch_pattern": "call qword ptr [r15+0x38] where r15 = [0x11b32f8]",
            "ecx_source_1": "call 0x17a140 (time-of-day calc) -- ecx bounded by 0x15180=86400",
            "ecx_source_2": "call 0x663cd0 fast path -- ecx unchanged from 0x17a140",
            "ecx_source_3": "call 0x663cd0 not-found path -> call 0x663bf0 (allocator) -- not wire-controlled",
            "guard_threshold": 118512,
            "max_observed_ecx": 86400,
            "verdict": "guard cannot pass",
        },
        "dispatch_tables": [
            {"va": 0x11a1218, "index": 4, "stride": 8},
            {"va": 0x96350, "stride": 24, "offset_in_entry": 8},
        ],
    },

    "C17_dcerpc_zero_length_infinite_loop": {
        "binary": "libips.so.new",
        "func_va": 0x20dd40,
        "func_name": "ips_dcerpc_decode",
        "description": (
            "DCE/RPC decoder at 0x20dd40 contains an unbounded TLV-advance loop. "
            "At 0x20ed40, loads 16-bit record length from word ptr [rbx] into eax "
            "with zero extension, then add rbx, rax to advance. No floor check. "
            "Zero length + non-type-1 type byte creates infinite loop."
        ),
        "code_trace": (
            "0x20ed40: movzx eax, word ptr [rbx]  ; 16-bit length from wire\n"
            "0x20ed43: add rbx, rax                ; advance (NO floor check)\n"
            "0x20ed46: cmp rbx, r15               ; check new_pos < end_ptr\n"
            "0x20ed49: jb 0x20eaf0                 ; if in-bounds, continue\n"
            "0x20eaf0: cmp byte ptr [rbx+2], 1    ; check record type\n"
            "0x20eaf4: jne 0x20ed40               ; if type != 1, loop back"
        ),
        "trigger": "DCE/RPC fragment with record_length=0x0000 AND type_byte != 0x01",
        "status": "CONFIRMED HIGH",
        "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
        "cwe": "CWE-835 (Loop with Unreachable Exit Condition)",
        "pre_auth": True,
        "callers": [0x20f813, 0x215d15, 0x2193b0, 0x21de55, 0x21e825],
        "disclosure_id": "FGT7K-C17",
    },

    "C19_lha_huffman_bit_count_underflow": {
        "binary": "libav.so.new",
        "func_vas": [0x1ed150, 0x1ed4a0, 0x1edb80, 0x1edf20],
        "description": (
            "4 LHA Huffman mode handlers (modes 0-3) subtract 0xc or 0x8 from a "
            "wire-controlled Huffman table byte, then truncate via movzx dil,dil. "
            "If byte < 12 (or 8), dil wraps to 244/248 and is passed to bit_read "
            "as bits_count. bit_read has internal bounds check (no OOB read), but "
            "244-bit consumption corrupts the decoder bit-buffer for all subsequent "
            "symbol reads. Return value discarded -- DoS only."
        ),
        "code_trace": (
            "0x1ed1e2: movzx edi, byte ptr [rbp+rax+0x3e60]  ; Huffman table byte\n"
            "0x1ed1ea: sub edi, 0xc                           ; UNDERFLOW if byte < 12\n"
            "0x1ed1ed: movzx edi, dil                         ; truncate -> 244\n"
            "0x1ed1f1: call 0x1edfe0                          ; bit_read(struct, 244)\n"
            "0x1ed1f6: mov eax, ebx                           ; return value DISCARDED"
        ),
        "trigger": "LHA archive with Huffman table entry < 12 in pre-auth AV scan path",
        "status": "CANDIDATE LOW",
        "pre_auth": True,
        "note": "DoS-only confirmed: bit_read return discarded, bit_read has internal bounds check",
        "disclosure_id": "FGT7K-C19",
    },

    "FGT7K_4_chm_itsp_imul_overflow": {
        "binary": "libav.so.new",
        "func_va": 0x197dd0,
        "description": (
            "CHM ITSP header parser at 0x197dd0: imul esi, DWORD PTR [rdi+0x28c] "
            "multiplies wire-controlled ITSP block_size (ctx+0x288) by block_count "
            "(ctx+0x28c) as 32-bit. When block_size=0x10000 and block_count=0x10000, "
            "esi = 0x100000000 mod 2^32 = 0. Overflow creates zero-size scan window, "
            "causing AV to skip embedded CHM content entirely (scanner bypass)."
        ),
        "code_trace": (
            # Caller (0x1981b0) wire-control path:\n"
            "0x198240: add rbx, r14           ; rbx = CHM data ptr + ITSF->ITSP offset\n"
            "0x198243: cmp [rbx], 'ITSP'      ; signature check\n"
            "0x19824e: add rbx, 0x54          ; skip 84-byte ITSP header\n"
            "0x198266: mov edx, [rbx-0x44]    ; [ITSP+0x10] = block_size -- WIRE (CHM file)\n"
            "0x198269: mov [r12+0x288], edx   ; ctx->block_size = wire value\n"
            "0x198271: mov edx, [rbx-0x28]    ; [ITSP+0x2c] = block_count -- WIRE (CHM file)\n"
            "0x198274: mov [r12+0x28c], edx   ; ctx->block_count = wire value\n"
            # FGT7K-4 overflow site (0x197dd0):\n"
            "0x197def: mov esi, [rdi+0x288]   ; ITSP block_size (wire, no bounds)\n"
            "0x197df5: imul esi, [rdi+0x28c]  ; *= block_count (wire) -- 32-BIT OVERFLOW\n"
            "0x197e04: mov r15, r8             ; r8 = [rdi+0x20] = scan window base ptr\n"
            "0x197e0a: add r15, rsi            ; end_ptr = base + 0 (when overflow)\n"
            "0x197e0d: jb 0x197e15             ; carry check -- NOT set: +0 has no carry\n"
            "0x197e0f: cmp [rbx+8], r15        ; container_end >= base: trivially true\n"
            "0x197e13: jae 0x197e30            ; proceeds; scan window length = 0\n"
            "0x197eb3: sub rdx, rsi            ; chunk_len = end_ptr - chunk_start = 0\n"
            "0x197eb6: call 0x197d60           ; directory parser called with len=0 -> no entries"
        ),
        "wire_source": (
            "block_size = [ITSP_ptr+0x10], block_count = [ITSP_ptr+0x2c]. "
            "Both read from CHM file ITSP header with no range check. "
            "Standard CHM ITSP spec: block_size at +0x10, num_blocks at +0x2c."
        ),
        "trigger": "CHM file with ITSP block_size=0x10000 and block_count=0x10000",
        "status": "CONFIRMED HIGH",
        "confirmation_session": 9,
        "confirmation_date": "2026-09-26",
        "cvss": "8.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N)",
        "cwe": "CWE-190 (Integer Overflow), CWE-693 (Protection Mechanism Failure)",
        "yara_bytes": ["0f af b7 8c 02 00 00", "49 01 f7 72 06"],
        "disclosure_id": "FGT7K-4",
        "disclosure_doc": "/home/cowboy/Documents/fortinet-disclosure/fgt7kf_psirt_disclosure.tex",
    },
}

ELIMINATED = {
    "C14_libips_indirect_guard_underflow": "guard requires ecx >= 118512; all callers bounded by 86400 (time calc). Session 8, 2026-09-25.",
    "C15_ips_match_all_candidates": "r8+0x66 is compiled IPS candidate rule data, not network-controlled. Zero-advance null-guard at 0x1bdf51-0x1bdf59.",
    "C16_diameter_avp_zero_length": "FALSE POSITIVE -- bytes at 0x17b84c mismatch documented assembly. bswap+shr pattern absent from entire binary.",
    "C18_libav_zero_advance": "dead code (0 callers)",
    "BMP_imul_comparison_only": "0x1516a7-0x1516b2 Width*Height*BitCount imul -- result compared vs edi only, never passed to alloc/copy. Session 9, 2026-09-25.",
    "PNG_64bit_imul": "0x151ae4,0x151af0 imul rbp,r12/rdx -- 64-bit operands, no 32-bit overflow. Session 9, 2026-09-25.",
    "MP4_size_capped": "0x152143 cmova rdx,rax caps size at 0x80 before arithmetic. Session 9, 2026-09-25.",
    "C19_upgrade_denied": "After bit_read(struct,244) at 0x1ed1f1: mov eax,ebx; pop; ret -- return value discarded, no array index use. C19 stays CANDIDATE LOW. Session 9, 2026-09-25.",
    "PDF_chain_no_overflow": (
        "0x3dfd60 realloc size = (ctx[0x57c]+16)*48 -- ctx[0x57c] is internal capacity counter, not wire data. "
        "0x3e2928 fixed ecx=0x78. ctx fields [0x570-0x594] are internal bookkeeping. "
        "Chain 0x3d6030->0x3d9050->0x3d7720->0x3da9a0->0x3dfd60 all internal. Session 9, 2026-09-25."
    ),
    "C21_ips_rule_bit_index_no_upper_bound": (
        "Actual site 0x193ccb (not 0x122da0 -- placeholder address in session notes) in func 0x192680. "
        "movzx ecx, [rdi+0x3c] loads a rule group bit index from compiled IPS candidate struct "
        "(rsi+0x108 array, same class as C15). Accessed as bitmask index [r13+rax*4] via shr/5 pattern. "
        "Not wire-controlled. Callers: 0xef210, 0xf4ea0. Session 9, 2026-09-25."
    ),
}


def print_findings():
    print("=== FortiGate 7000F libips/libav Findings ===")
    for k, v in FINDINGS.items():
        status = v.get("status", "?")
        cvss = v.get("cvss", "")
        print(f"  {k}: {status} {cvss}")
    print()
    print("=== Eliminated ===")
    for k, v in ELIMINATED.items():
        print(f"  {k}: {v}")
