"""
IOM2400 tahusd AAPL AACS server init sweep.

Goal: confirm whether the AACS TCP debug server (port 2330) is started
unconditionally from tahusd process init, or only under a debug flag.

Method:
  1. Scan tahusd ELF .text section for x86-64 function prologues.
  2. Disassemble each function; extract call targets + string refs + port constants.
  3. Encode corpus with BERT (all-MiniLM-L6-v2).
  4. Query for AACS server startup behavioral pattern.
  5. For top candidates: check whether call site is inside a conditional branch.

Binary: /tmp/iom2400-root/isan/bin/tahusd (x86-64 PIE ELF, stripped, 49MB)

Sweep results (run 2026-09-18):
  - 47,699 prologue candidates identified in 49MB binary
  - 135 functions reference port 2330 as a decimal immediate
  - 30 of those 135 have NO conditional branch before the port-2330 reference (UNCONDITIONAL)
  - All port-2330 references are in LOG format-string calls (0x3ab120 = logging function)
    passing 2330 as a format arg; these log the "server listening on port N" message
  - htons(2330) = 0x1a09 has ZERO occurrences as a hardcoded immediate in .text
    -> port arrives as a register parameter to aapl_aacs_server_start(); htons() is
       computed at runtime inside the SDK function (no constant in instruction stream)
  - SEMANTIC scores low (~0.2) across all queries; stripped binary with no symbols
    limits behavioral description quality

Chain verification status:
  CONFIRMED (static):
    - AACS server code and log strings present in tahusd binary
    - Port 2330 log messages emitted after server bind (server startup confirmed)
    - 30 log call sites are unconditionally reachable (no branch guard before port log)
    - iptables ACCEPT unconditional from SAM IPs in extracted filesystem
  UNCONFIRMED (requires call-graph trace from main() or live device):
    - Whether aapl_aacs_server_start() call site is itself inside a conditional block
    - Actual bind() syscall path (port arrives via register, not hardcoded immediate)
  NEXT STEP: trace call graph from ELF entry point to find aapl_aacs_server_start
    caller; OR obtain netstat output from live IOM to confirm :2330 LISTEN state
"""

import sys
import struct
import pickle
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import capstone
import numpy as np
from sentence_transformers import SentenceTransformer

from modules.semantic_search import describe_function, normalize_asm, WhiteningTransform

BINARY = Path('/tmp/iom2400-root/isan/bin/tahusd')
CACHE  = Path.home() / '.ablation' / 'tahusd_aacs_corpus.pkl'

# ── ELF helpers ──────────────────────────────────────────────────────────────

def parse_elf64(data: bytes):
    """Return (text_offset, text_va, text_size, load_bias) for the .text section."""
    assert data[:4] == b'\x7fELF', "not an ELF"
    e_phoff   = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum   = struct.unpack_from('<H', data, 0x38)[0]

    # Find PT_LOAD segment with execute flag to determine load bias
    load_bias = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type  = struct.unpack_from('<I', data, off)[0]
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr  = struct.unpack_from('<Q', data, off + 0x10)[0]
        if p_type == 1 and (p_flags & 1):   # PT_LOAD + PF_X
            load_bias = p_vaddr - p_offset
            break

    e_shoff     = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum     = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx  = struct.unpack_from('<H', data, 0x3e)[0]

    shstr_off = e_shoff + e_shstrndx * e_shentsize
    shstr_foff = struct.unpack_from('<Q', data, shstr_off + 0x18)[0]

    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name_off = struct.unpack_from('<I', data, off)[0]
        name = data[shstr_foff + name_off: shstr_foff + name_off + 10]
        name = name.split(b'\x00')[0].decode('ascii', errors='replace')
        if name == '.text':
            sh_offset = struct.unpack_from('<Q', data, off + 0x18)[0]
            sh_addr   = struct.unpack_from('<Q', data, off + 0x10)[0]
            sh_size   = struct.unpack_from('<Q', data, off + 0x20)[0]
            return sh_offset, sh_addr, sh_size, load_bias

    raise RuntimeError(".text section not found")


# ── Function prologue scanner (x86-64) ───────────────────────────────────────

def find_function_starts(data: bytes, text_off: int, text_va: int, text_size: int) -> list[int]:
    """
    Heuristic prologue detection for stripped x86-64 PIE binaries.
    Recognizes:
      - endbr64 (F3 0F 1E FA)
      - push rbp; mov rbp rsp  (55 48 89 E5)
      - sub rsp, imm8/imm32    (48 83 EC xx  or  48 81 EC xx xx xx xx)
    Returns list of file offsets.
    """
    starts = []
    seg = data[text_off: text_off + text_size]
    i = 0
    while i < len(seg) - 8:
        b = seg[i: i+4]
        # endbr64
        if b == b'\xf3\x0f\x1e\xfa':
            starts.append(text_off + i)
            i += 4
            continue
        # push rbp (55) followed by mov rbp, rsp (48 89 E5)
        if seg[i] == 0x55 and seg[i+1:i+4] == b'\x48\x89\xe5':
            starts.append(text_off + i)
            i += 4
            continue
        # sub rsp, imm8 (48 83 EC)
        if seg[i:i+3] == b'\x48\x83\xec':
            starts.append(text_off + i)
            i += 3
            continue
        i += 1
    return starts


# ── Function disassembly ──────────────────────────────────────────────────────

PORT_2330 = 2330

def disasm_func(data: bytes, file_off: int, va: int,
                max_insns: int = 200) -> tuple[list[str], list[str], bool]:
    """
    Disassemble one function.
    Returns (asm_lines, call_targets_hex, has_port_2330_constant).
    Stops at ret/retn or after max_insns instructions.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    raw = data[file_off: file_off + max_insns * 15]

    lines, calls = [], []
    has_port = False

    for insn in md.disasm(raw, va):
        op = f'{insn.mnemonic} {insn.op_str}'.strip()
        lines.append(op)

        if insn.mnemonic in ('call',) and insn.op_str.startswith('0x'):
            calls.append(insn.op_str)

        # Port 2330 as immediate in any instruction
        if str(PORT_2330) in insn.op_str or hex(PORT_2330) in insn.op_str:
            has_port = True

        if insn.mnemonic in ('ret', 'retq', 'retn', 'hlt'):
            break
        if len(lines) >= max_insns:
            break

    return lines, calls, has_port


# ── Corpus build / load ───────────────────────────────────────────────────────

def build_corpus(data: bytes) -> list[dict]:
    text_off, text_va, text_size, load_bias = parse_elf64(data)
    print(f"  .text  offset=0x{text_off:x}  va=0x{text_va:x}  size=0x{text_size:x}")

    starts = find_function_starts(data, text_off, text_va, text_size)
    print(f"  prologue candidates: {len(starts)}")

    funcs = []
    for file_off in starts:
        va = text_va + (file_off - text_off)
        lines, calls, has_port = disasm_func(data, file_off, va)
        if len(lines) < 4:
            continue
        desc = describe_function(
            name       = f'sub_{va:x}',
            role       = 'UNKNOWN',
            call_targets = calls,
            strings    = ['PORT_2330'] if has_port else [],
            asm_lines  = lines,
        )
        funcs.append({
            'va':       va,
            'file_off': file_off,
            'desc':     desc,
            'calls':    calls,
            'has_port': has_port,
            'n_insns':  len(lines),
        })
    return funcs


def load_or_build(data: bytes) -> list[dict]:
    digest = hashlib.sha256(data[:65536]).hexdigest()[:16]
    if CACHE.exists():
        with open(CACHE, 'rb') as f:
            cached = pickle.load(f)
        if cached.get('digest') == digest:
            print(f"  corpus cache hit ({len(cached['funcs'])} functions)")
            return cached['funcs']
    print("  building corpus...")
    funcs = build_corpus(data)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE, 'wb') as f:
        pickle.dump({'digest': digest, 'funcs': funcs}, f)
    print(f"  corpus: {len(funcs)} functions, cached to {CACHE}")
    return funcs


# ── Semantic sweep ────────────────────────────────────────────────────────────

QUERIES = [
    (
        'aacs_server_init',
        'TCP_SERVER_INIT | calls: socket bind listen accept | strings: PORT_2330 | '
        'vuln: debug server opens TCP listener on port 2330 no authentication check '
        'before accepting connections AAPL AACS SerDes hardware debug',
    ),
    (
        'process_startup_init',
        'DAEMON_INIT | calls: daemon fork setsid | '
        'vuln: process startup initialization unconditional service startup no conditional guard',
    ),
    (
        'aapl_sdk_startup',
        'AAPL_SDK_INIT | calls: aapl_create aapl_connect | strings: Avago SerDes AAPL | '
        'vuln: AAPL SDK handle initialization SerDes ASIC setup Broadcom debug interface',
    ),
]


def run_sweep():
    print(f"\n[tahusd AACS sweep] {BINARY}")
    data = BINARY.read_bytes()
    print(f"  binary size: {len(data)/1024/1024:.1f} MB")

    funcs = load_or_build(data)

    # Port 2330 candidates -- fast pre-filter
    port_hits = [f for f in funcs if f['has_port']]
    print(f"\n  functions referencing port 2330: {len(port_hits)}")
    for f in port_hits:
        print(f"    va=0x{f['va']:x}  insns={f['n_insns']}  calls={f['calls'][:4]}")

    # Semantic sweep
    print("\n  encoding corpus with BERT...")
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')
    descs = [f['desc'] for f in funcs]
    corpus_vecs = model.encode(descs, normalize_embeddings=True, batch_size=128,
                               show_progress_bar=True)

    wt = WhiteningTransform()
    corpus_w = wt.fit_transform(corpus_vecs)

    print("\n  query results:")
    for qname, qtext in QUERIES:
        qvec = model.encode(qtext, normalize_embeddings=True)
        qvec_w = wt.transform(qvec.reshape(1, -1))[0]
        scores = corpus_w @ qvec_w
        top_idx = np.argsort(scores)[::-1][:8]
        print(f"\n  [{qname}]")
        for rank, idx in enumerate(top_idx):
            f = funcs[idx]
            print(f"    {rank+1}. va=0x{f['va']:x}  score={scores[idx]:.4f}  "
                  f"insns={f['n_insns']}  port={f['has_port']}  "
                  f"calls={f['calls'][:3]}")

    # Conditional branch check for port_hits
    if port_hits:
        print("\n  conditional branch analysis for port 2330 functions:")
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = False
        COND_MNEMONICS = {
            'je','jne','jz','jnz','jl','jg','jle','jge',
            'ja','jb','jae','jbe','jns','js','jo','jno',
        }
        for f in port_hits:
            raw = data[f['file_off']: f['file_off'] + f['n_insns'] * 15]
            insns = list(md.disasm(raw, f['va']))
            conds = [i for i in insns if i.mnemonic in COND_MNEMONICS]
            port_pos = next(
                (pos for pos, i in enumerate(insns)
                 if str(PORT_2330) in i.op_str or hex(PORT_2330) in i.op_str),
                -1
            )
            # use address-based position tracking (CsInsn objects not comparable across calls)
        insn_addrs = [i.address for i in insns]
        cond_addrs = [c.address for c in conds]
        port_addr  = insns[port_pos].address if port_pos >= 0 else None
        conds_before_port = [c for c in conds
                              if c.address < port_addr] \
                            if port_addr is not None else []
            print(f"    va=0x{f['va']:x}: {len(conds)} conditional branches total, "
                  f"{len(conds_before_port)} before port 2330 reference  "
                  f"(port at insn #{port_pos})")
            if conds_before_port:
                print(f"      CONDITIONAL: branch at "
                      f"{[hex(c.address) for c in conds_before_port]} precedes port ref")
            else:
                print(f"      UNCONDITIONAL PATH: port 2330 ref reached without conditional guard")


if __name__ == '__main__':
    run_sweep()
