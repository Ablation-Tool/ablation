"""
Fortinet binary semantic sweep - same methodology as LINA analysis.
Extracts functions via capstone, encodes with BinFuse+all-MiniLM-L6-v2,
runs multiple vulnerability query profiles, returns ranked candidates.
"""

import sys
import os
import re
import struct
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from modules.semantic_search import describe_function, normalize_asm

import capstone
from sentence_transformers import SentenceTransformer


LIBAV  = "/tmp/claude-1000/-home-cowboy/e43dec39-d499-4594-8156-93bb60757ab9/scratchpad/fgt7412-data/lib/libav.so.new"
LIBIPS = "/tmp/claude-1000/-home-cowboy/e43dec39-d499-4594-8156-93bb60757ab9/scratchpad/fgt7412-data/lib/libips.so.new"

PLT_RE = re.compile(r"@plt$")

VULN_PROFILES = [
    ("memcpy_packet_len",
     "AV_PARSER | role=buffer_copy | calls: memcpy | "
     "vuln: memcpy called with length from packet data or untrusted field without upper bound check"),

    ("strcpy_fixed_dst",
     "AV_PARSER | role=string_copy | calls: strcpy strcat sprintf | "
     "vuln: strcpy or sprintf into fixed-size stack or heap buffer without length check"),

    ("integer_overflow_alloc",
     "AV_SCANNER | role=allocation | calls: malloc realloc calloc | "
     "vuln: integer multiplication or addition before malloc without overflow check"),

    ("format_string",
     "LOGGER | role=logging_error | calls: printf fprintf sprintf snprintf | "
     "vuln: format string argument from untrusted packet field passed to printf family"),

    ("use_after_free",
     "OBJECT_MANAGER | role=lifetime | calls: free | "
     "vuln: pointer used after free, heap object freed then accessed in same function"),

    ("fidsdb_parser_overflow",
     "FIDSDB_PARSER | role=binary_format | calls: memcpy atoi strtol | "
     "vuln: binary signature database parser reads 16-bit length field and copies without bounds check"),

    ("system_popen_injection",
     "COMMAND_EXEC | role=shell | calls: system popen execve | "
     "vuln: system or popen called with string built from untrusted input without sanitization"),

    ("luajit_string_unbox",
     "LUA_BINDING | role=ffi_bridge | calls: lua_tolstring luaL_checkstring | "
     "vuln: LuaJIT NaN-unboxed string passed to C function without null terminator or length check"),

    ("decompression_bomb",
     "DECOMPRESSOR | role=inflate | calls: inflate zlib_inflate lz4_decompress | "
     "vuln: output buffer size not checked against decompression output; missing avail_out bound"),

    ("network_packet_parse",
     "NETWORK_HANDLER | role=packet_parser | calls: memcpy memmove recv read | "
     "vuln: length from packet header used in memory operation without validation against packet bounds"),
]

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
TOP_N = 8
MAX_INSNS = 400


def build_caller_set(data: bytes, text_off: int, text_va: int, text_sz: int) -> set:
    """
    Scan .text for call rel32 (e8) and jmp rel32 (e9) instructions.
    Returns set of intra-section target VAs that are explicitly branched to.
    Used as one acceptance criterion for function start candidates.
    """
    targets = set()
    blob = data[text_off:text_off + text_sz]
    for i in range(len(blob) - 5):
        if blob[i] in (0xe8, 0xe9):
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            target_va = text_va + i + 5 + rel
            if text_va <= target_va < text_va + text_sz:
                targets.add(target_va)
    return targets


def find_functions(data: bytes, base_va: int, text_off: int, text_va: int, text_sz: int):
    """
    Find x86-64 function prologues: PUSH RBP / ENDBR64+PUSH RBP / SUB RSP.

    Three-condition acceptance filter to eliminate mid-instruction false starts:
      1. VA appears as a call/jmp rel32 target in .text  (direct caller exists)
      2. Byte immediately before VA is a known function boundary marker
         (ret/leave/retf/hlt/int3/nop)
      3. VA is 16-byte aligned  (compiler function alignment)

    A candidate is accepted if ANY condition is true.
    """
    blob = data[text_off:text_off + text_sz]
    ENDBR64 = bytes([0xf3, 0x0f, 0x1e, 0xfa])

    # Bytes that legitimately terminate a function and precede the next start
    BOUNDARY_BYTES = frozenset([0xc3, 0xc9, 0xcb, 0xf4, 0xcc, 0x90])

    caller_set = build_caller_set(data, text_off, text_va, text_sz)

    raw = []
    i = 0
    while i < len(blob) - 4:
        b = blob[i]
        if b == 0x55:
            raw.append(text_va + i)
        elif blob[i:i+4] == ENDBR64 and i + 4 < len(blob) and blob[i+4] == 0x55:
            raw.append(text_va + i)
        elif b == 0x48 and i + 3 < len(blob) and blob[i+1] == 0x83 and blob[i+2] == 0xec:
            raw.append(text_va + i)
        i += 1

    funcs = []
    excluded = 0
    for va in sorted(set(raw)):
        # Condition 1: has a direct caller
        if va in caller_set:
            funcs.append(va)
            continue
        # Condition 2: preceded by a function-boundary byte
        off = text_off + (va - text_va)
        if off > text_off and data[off - 1] in BOUNDARY_BYTES:
            funcs.append(va)
            continue
        # Condition 3: 16-byte aligned (compiler function alignment)
        if va & 0xF == 0:
            funcs.append(va)
            continue
        excluded += 1

    print(f"  Prologue filter: {len(set(raw))} raw -> {len(funcs)} accepted "
          f"({excluded} excluded: misaligned, no caller, no boundary)")
    return funcs


def disasm_function(data: bytes, va: int, text_va: int, text_off: int, text_sz: int, md):
    """Disassemble up to MAX_INSNS from va; stop at ret/retn."""
    off = text_off + (va - text_va)
    if off < 0 or off >= text_off + text_sz:
        return [], []

    insns = []
    calls = []
    for insn in md.disasm(data[off:off + MAX_INSNS * 15], va):
        insns.append(f"{insn.mnemonic} {insn.op_str}".strip())
        if insn.mnemonic in ("call", "callq"):
            op = insn.op_str.strip()
            if "0x" in op:
                try:
                    calls.append(hex(int(op, 16)))
                except ValueError:
                    calls.append(op)
            else:
                calls.append(op)
        if insn.mnemonic in ("ret", "retn", "retq"):
            break
        if len(insns) >= MAX_INSNS:
            break
    return insns, calls


def load_elf_text(path: str):
    """Parse ELF, return (data, text_offset, text_va, text_size, base_va, plt_names)."""
    with open(path, "rb") as f:
        data = f.read()

    # ELF64 header
    e_phoff   = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum   = struct.unpack_from("<H", data, 0x38)[0]
    e_shoff   = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
    e_shnum   = struct.unpack_from("<H", data, 0x3c)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3e)[0]

    # Find base VA (lowest LOAD segment)
    base_va = 0xffffffffffffffff
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_vaddr = struct.unpack_from("<Q", data, off + 0x10)[0]
        if p_type == 1 and p_vaddr < base_va:  # PT_LOAD
            base_va = p_vaddr

    # Section headers
    shstr_sh_off = e_shoff + e_shstrndx * e_shentsize
    shstr_offset = struct.unpack_from("<Q", data, shstr_sh_off + 0x18)[0]

    text_off = text_va = text_sz = 0
    plt_off = plt_va = plt_sz = 0
    relplt_off = relplt_sz = 0
    dynsym_off = dynsym_sz = 0
    dynstr_off = dynstr_sz = 0

    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        sh_name_off = struct.unpack_from("<I", data, sh)[0]
        try:
            name_end = data.index(b"\x00", shstr_offset + sh_name_off)
            name = data[shstr_offset + sh_name_off:name_end].decode("ascii", errors="replace")
        except Exception:
            name = ""
        sh_offset = struct.unpack_from("<Q", data, sh + 0x18)[0]
        sh_size   = struct.unpack_from("<Q", data, sh + 0x20)[0]
        sh_addr   = struct.unpack_from("<Q", data, sh + 0x10)[0]

        if name == ".text":
            text_off, text_va, text_sz = sh_offset, sh_addr, sh_size
        elif name == ".plt":
            plt_off, plt_va, plt_sz = sh_offset, sh_addr, sh_size
        elif name in (".rela.plt", ".rel.plt"):
            relplt_off, relplt_sz = sh_offset, sh_size
        elif name == ".dynsym":
            dynsym_off, dynsym_sz = sh_offset, sh_size
        elif name == ".dynstr":
            dynstr_off, dynstr_sz = sh_offset, sh_size

    # Build PLT address -> name map
    plt_names = {}
    if relplt_off and dynsym_off and dynstr_off:
        # Rela entries: 24 bytes each [r_offset(8), r_info(8), r_addend(8)]
        n_rela = relplt_sz // 24
        for j in range(n_rela):
            r = relplt_off + j * 24
            r_offset = struct.unpack_from("<Q", data, r)[0]
            r_info   = struct.unpack_from("<Q", data, r + 8)[0]
            sym_idx  = r_info >> 32
            sym_off  = dynsym_off + sym_idx * 24  # Elf64_Sym = 24 bytes
            st_name  = struct.unpack_from("<I", data, sym_off)[0]
            try:
                n_end = data.index(b"\x00", dynstr_off + st_name)
                sym_name = data[dynstr_off + st_name:n_end].decode("ascii", errors="replace")
            except Exception:
                sym_name = f"sym_{sym_idx}"
            # PLT entry is at plt_va + 0x10 + j*0x10 (standard x86-64 PLT layout)
            plt_entry_va = plt_va + 0x10 + j * 0x10
            plt_names[plt_entry_va] = sym_name

    return data, text_off, text_va, text_sz, base_va, plt_names


def sweep(binary_path: str, label: str):
    print(f"\n{'='*60}")
    print(f"SWEEP: {label}")
    print(f"Binary: {binary_path}")
    print(f"{'='*60}")

    data, text_off, text_va, text_sz, base_va, plt_names = load_elf_text(binary_path)
    print(f".text: VA=0x{text_va:x} off=0x{text_off:x} sz={text_sz//1024}KB")
    print(f"PLT entries: {len(plt_names)}")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False

    func_vas = find_functions(data, base_va, text_off, text_va, text_sz)
    print(f"Function prologues found: {len(func_vas)}")

    # Disassemble and build descriptions
    descs = []
    metas = []
    n_skip_short = n_skip_ud2 = 0
    for va in func_vas:
        insns, raw_calls = disasm_function(data, va, text_va, text_off, text_sz, md)
        if len(insns) < 4:
            n_skip_short += 1
            continue
        # Skip C++ exception landing pads: ud2 (0f 0b) signals __terminate / unreachable
        if any(i.startswith("ud2") for i in insns):
            n_skip_ud2 += 1
            continue
        # Resolve PLT calls to names
        call_names = []
        for c in raw_calls:
            try:
                cva = int(c, 16)
                call_names.append(plt_names.get(cva, c))
            except ValueError:
                call_names.append(c)

        desc = describe_function(
            name=f"sub_{va:x}",
            role="unknown",
            call_targets=call_names,
            strings=[],
            vuln_notes="",
            asm_lines=insns[:80],
        )
        descs.append(desc)
        metas.append({"va": va, "calls": call_names, "n_insns": len(insns)})

    print(f"Functions encoded: {len(descs)} "
          f"(skipped: {n_skip_short} too-short, {n_skip_ud2} exception-handlers)")

    print(f"Encoding {len(descs)} functions with {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME, device="cpu")
    corpus_vecs = model.encode(descs, normalize_embeddings=True, batch_size=64, show_progress_bar=True)

    print(f"\nVulnerability sweep results:")
    results = {}
    for profile_name, query in VULN_PROFILES:
        qvec = model.encode(query, normalize_embeddings=True)
        scores = corpus_vecs @ qvec
        top_idx = np.argsort(scores)[::-1][:TOP_N]
        hits = []
        for idx in top_idx:
            m = metas[idx]
            score = float(scores[idx])
            if score < 0.3:
                break
            hits.append({
                "va": hex(m["va"]),
                "score": round(score, 3),
                "n_insns": m["n_insns"],
                "calls": m["calls"][:8],
            })
        results[profile_name] = hits
        print(f"\n[{profile_name}]")
        for h in hits[:4]:
            print(f"  0x{int(h['va'],16):x}  score={h['score']}  calls={h['calls'][:5]}")

    return results, metas, descs, corpus_vecs, model


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "libav"
    if target == "libav":
        sweep(LIBAV, "FGT7412 libav.so.new (AV engine)")
    elif target == "libips":
        sweep(LIBIPS, "FGT7412 libips.so.new (IPS+LuaJIT engine)")
    else:
        print(f"Unknown target: {target}")
        sys.exit(1)
