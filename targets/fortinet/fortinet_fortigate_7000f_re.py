"""
FortiGate 7000F -- FortiOS 8.0.0 build 0167 -- libips.so.new + libav.so.new RE
Binaries:
  /home/cowboy/ablation/fortigate-work/extract/datafs/lib/libips.so.new (SHA256: fdfaceccdc740d82...)
  /home/cowboy/ablation/fortigate-work/extract/datafs/lib/libav.so.new
Session: targets/fortinet/SESSION_fgt7kf.md (last updated: session 9, 2026-09-26)

Findings:
  FGT7K-1  CONFIRMED HIGH    libips  DCE/RPC zero-length loop
  FGT7K-2  CONFIRMED CRIT    libips  Static RC4 key (STUB -- lost in pyc reconstruction, see .tex)
  FGT7K-3  ELIMINATED        libips  IPS option field underflow (guard cannot pass)
  FGT7K-4  CONFIRMED HIGH    libav   CHM ITSP 32-bit imul overflow (scanner bypass)
  FGT7K-5  CANDIDATE LOW     libav   LHA Huffman bit-count underflow (DoS only)

Source reconstructed from pyc + session notes (original source lost after session 7).
FGT7K-2 detail lost in reconstruction -- canonical record in disclosure .tex only.
"""

FINDINGS = {
    "FGT7K_1_libips_dcerpc_zero_length_loop": {
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
        "disclosure_id": "FGT7K-1",
        "disclosure_doc": "/home/cowboy/Documents/fortinet-disclosure/fgt7kf_psirt_disclosure.tex",
    },

    "FGT7K_2_libips_static_rc4_key": {
        "binary": "libips.so.new",
        "status": "CONFIRMED CRITICAL",
        "cvss": "9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
        "cwe": "CWE-321 (Use of Hard-coded Cryptographic Key)",
        "description": (
            "STUB -- detail lost in pyc reconstruction after session 7. "
            "Firmware container uses a static RC4 key in the RSA signature block, "
            "allowing pre-auth firmware decryption. Full record in disclosure .tex only."
        ),
        "disclosure_id": "FGT7K-2",
        "disclosure_doc": "/home/cowboy/Documents/fortinet-disclosure/fgt7kf_psirt_disclosure.tex",
        "reconstruction_note": "Recover from .tex section FGT7K-2 if full RE detail needed.",
    },

    "FGT7K_4_libav_chm_itsp_imul_overflow": {
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
            "-- Caller (0x1981b0) wire-control path --\n"
            "0x198240: add rbx, r14           ; rbx = CHM data ptr + ITSF->ITSP offset\n"
            "0x198243: cmp [rbx], 'ITSP'      ; signature check\n"
            "0x19824e: add rbx, 0x54          ; skip 84-byte ITSP header\n"
            "0x198266: mov edx, [rbx-0x44]    ; [ITSP+0x10] = block_size -- WIRE (CHM file)\n"
            "0x198269: mov [r12+0x288], edx   ; ctx->block_size = wire value\n"
            "0x198271: mov edx, [rbx-0x28]    ; [ITSP+0x2c] = block_count -- WIRE (CHM file)\n"
            "0x198274: mov [r12+0x28c], edx   ; ctx->block_count = wire value\n"
            "-- Overflow site (0x197dd0) --\n"
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

    "FGT7K_5_libav_lha_huffman_underflow": {
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
        "disclosure_id": "FGT7K-5",
    },
}

ELIMINATED = {
    "FGT7K_3_libips_option_underflow": (
        "func=0x29fa90: movzx eax,[rdi+0x20] / lea r12d,[rax-0x10] / movzx r15d,r12w. "
        "Guard at 0x29fab6 (cmp ecx,eax; jb exit) requires ecx >= 118512. "
        "Full caller trace (session 8): only dispatch site 0xef9ec in 0xef210; "
        "ecx bounded by 86400 (time-of-day calc, ceiling via cmovle). "
        "Guard cannot pass from any call path. (disclosure_id: FGT7K-3)"
    ),
    "libips_match_rule_candidates": (
        "r8+0x66 is compiled IPS candidate rule data, not network-controlled. "
        "Zero-advance null-guard at 0x1bdf51-0x1bdf59."
    ),
    "libips_diameter_avp_false_positive": (
        "FALSE POSITIVE -- bytes at 0x17b84c mismatch documented assembly. "
        "bswap+shr pattern absent from entire binary."
    ),
    "libav_zero_advance_dead_code": "dead code (0 callers)",
    "libav_bmp_imul_comparison_only": (
        "0x1516a7-0x1516b2 Width*Height*BitCount imul -- result compared vs edi only, "
        "never passed to alloc/copy. Session 9, 2026-09-25."
    ),
    "libav_png_64bit_imul": (
        "0x151ae4,0x151af0 imul rbp,r12/rdx -- 64-bit operands, no 32-bit overflow. "
        "Session 9, 2026-09-25."
    ),
    "libav_mp4_size_capped": (
        "0x152143 cmova rdx,rax caps size at 0x80 before arithmetic. Session 9, 2026-09-25."
    ),
    "libav_lha_upgrade_denied": (
        "After bit_read(struct,244) at 0x1ed1f1: mov eax,ebx; pop; ret -- return value "
        "discarded, no array index use. FGT7K-5 stays CANDIDATE LOW. Session 9, 2026-09-25."
    ),
    "libav_pdf_chain_no_overflow": (
        "0x3dfd60 realloc size = (ctx[0x57c]+16)*48 -- ctx[0x57c] is internal capacity "
        "counter, not wire data. 0x3e2928 fixed ecx=0x78. ctx fields [0x570-0x594] are "
        "internal bookkeeping. Chain 0x3d6030->0x3d9050->0x3d7720->0x3da9a0->0x3dfd60 "
        "all internal. Session 9, 2026-09-25."
    ),
    "libips_rule_bit_index_no_upper_bound": (
        "Actual site 0x193ccb in func 0x192680. movzx ecx,[rdi+0x3c] loads a rule group "
        "bit index from compiled IPS candidate struct (rsi+0x108 array). Accessed as "
        "bitmask index [r13+rax*4] via shr/5 pattern. Not wire-controlled. "
        "Callers: 0xef210, 0xf4ea0. Session 9, 2026-09-25."
    ),
}


def print_findings():
    print("=== FortiGate 7000F libips/libav Findings ===")
    for k, v in FINDINGS.items():
        status = v.get("status", "?")
        cvss = v.get("cvss", "")
        did = v.get("disclosure_id", "")
        print(f"  {did:10s} {status:20s} {k}")
    print()
    print("=== Eliminated ===")
    for k, v in ELIMINATED.items():
        print(f"  {k}: {v[:80]}...")
