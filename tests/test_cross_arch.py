"""
Cross-architecture homolog search for attr_list_add_impl.

Tests three ISA boundaries:
  i386   → x86-64 seed (ASA 9.2.4, 2015-era 32-bit codebase)
  ARM64  → x86-64 seed (FTD 10.0.0, Firepower 200 series)
  ARM64  → x86-64 seed (FTD 7.6.2, Firepower 1200 series)

For same-arch: Jaccard ≥ 0.15 + semantic ≥ 0.75 = HIGH confidence.
For cross-arch: semantic ≥ 0.85 = HIGH-equivalent (Jaccard is ISA-specific).
"""

import sys, time, struct
import capstone
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.version_delta import FuncFeatures, FuncMatcher
from modules.semantic_search import SemanticSearcher

LINA_914   = '/path/to/binary'
SEED_VA    = 0xc563d0
SEED_NAME  = 'attr_list_add_impl'
DB         = '~/.ablation/func_id.db'

LINA_904        = '/path/to/research/binary'
LINA_924        = '/path/to/research/binary'
LINA_917_K8     = '/path/to/research/binary'
LINA_917_32     = '/path/to/research/binary'
LINA_917_23_K8  = '/path/to/research/binary'
LINA_FTD10      = '/path/to/research/binary'
LINA_1200       = '/path/to/research/binary'

CROSS_ARCH_SEM_THRESHOLD = 0.85

# ── x86-64 seed extraction ────────────────────────────────────────────────────

def extract_func_x64(data, va):
    raw = data[va:va + 4096]
    md  = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines, calls = [], []
    for insn in md.disasm(raw, va):
        op = f'{insn.mnemonic} {insn.op_str}'.strip()
        lines.append(op)
        if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
            calls.append(insn.op_str)
        if insn.mnemonic in ('ret', 'retq', 'retn'):
            break
        if insn.mnemonic in ('jmp', 'jmpq'):
            try:
                if abs(int(insn.op_str, 16) - va) > 0x20000:
                    break
            except ValueError:
                break
    return lines, calls


# ── i386 prologue scanner ─────────────────────────────────────────────────────
# 32-bit calling convention: ebp frame, arguments on stack.
# Mnemonic vocabulary overlaps with x86-64 but lacks rax/rdi/etc;
# Jaccard is non-zero cross-width (~0.13) unlike cross-ISA (~0.01).

_PROLOGUES_I386 = [b'\x55\x89\xe5', b'\x55\x83\xec', b'\x55\x56', b'\x55\x53', b'\x55\x57']
_MIN_INSTRS_I386 = 5
_MAX_BYTES_I386  = 4096


def i386_prologue_scan(data: bytes) -> list[FuncFeatures]:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    seen: set[int] = set()
    for pat in _PROLOGUES_I386:
        off = 0
        while True:
            pos = data.find(pat, off)
            if pos < 0:
                break
            seen.add(pos)
            off = pos + 1
    feats = []
    for offset in sorted(seen):
        raw = data[offset:offset + _MAX_BYTES_I386]
        lines, calls = [], []
        for insn in md.disasm(raw, offset):
            op = f'{insn.mnemonic} {insn.op_str}'.strip()
            lines.append(op)
            if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
                calls.append(insn.op_str)
            if insn.mnemonic in ('ret', 'retl'):
                break
            if insn.mnemonic == 'jmp':
                try:
                    if abs(int(insn.op_str, 16) - offset) > 0x10000:
                        break
                except ValueError:
                    break
        if len(lines) >= _MIN_INSTRS_I386:
            feats.append(FuncFeatures.from_disasm_lines(offset, hex(offset), lines, calls))
    return feats


# ── AArch64 prologue scanner ─────────────────────────────────────────────────
# All AArch64 instructions are 4 bytes LE. Primary prologue:
#   stp x29, x30, [sp, #-N]!  → bytes[0]=0xfd, bytes[1]=0x7b, bytes[3]=0xa9
# Secondary: paciasp (ARMv8.3+ pointer auth)  → 5f 23 03 d5

_PACIASP = b'\x5f\x23\x03\xd5'
_MIN_INSTRS_A64 = 6
_MAX_BYTES_A64  = 4096


def _is_stp_x29_x30_pre(word: int) -> bool:
    b = word.to_bytes(4, 'little')
    return b[0] == 0xfd and b[1] == 0x7b and b[3] == 0xa9


def arm64_prologue_scan(data: bytes) -> list[FuncFeatures]:
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False
    seen: set[int] = set()
    n = len(data) - 4
    for offset in range(0, n, 4):
        word = struct.unpack_from('<I', data, offset)[0]
        if _is_stp_x29_x30_pre(word) or data[offset:offset + 4] == _PACIASP:
            seen.add(offset)
    feats = []
    for offset in sorted(seen):
        raw = data[offset:offset + _MAX_BYTES_A64]
        lines, calls = [], []
        for insn in md.disasm(raw, offset):
            op = f'{insn.mnemonic} {insn.op_str}'.strip()
            lines.append(op)
            if insn.mnemonic in ('bl', 'blr') and insn.op_str.startswith('#0x'):
                calls.append(insn.op_str[1:])
            if insn.mnemonic == 'ret':
                break
            if insn.mnemonic == 'b' and not insn.op_str.startswith('.'):
                try:
                    dest = int(insn.op_str.lstrip('#'), 16)
                    if abs(dest - offset) > 0x40000:
                        break
                except ValueError:
                    break
        if len(lines) >= _MIN_INSTRS_A64:
            feats.append(FuncFeatures.from_disasm_lines(offset, hex(offset), lines, calls))
    return feats


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ss      = SemanticSearcher(DB)
    ss.build_corpus()
    matcher = FuncMatcher(semantic_searcher=ss)

    with open(LINA_914, 'rb') as f:
        data914 = f.read()
    asm_seed, callee_vas = extract_func_x64(data914, SEED_VA)
    seed = FuncFeatures.from_disasm_lines(SEED_VA, SEED_NAME, asm_seed, callee_vas)
    print(f'Seed (x86-64 ASA 9.14): {SEED_NAME}  instrs={seed.n_instrs}\n')

    targets = [
        # i386 Era 1 — oldest known: 9.0.4.42 (jac=0.1471, MEDIUM, sem=0.9211)
        ('ASA 9.0.4.42 (i386)',      LINA_904,        i386_prologue_scan,  'i386→x86-64'),
        ('ASA 9.1.7 k8 (i386)',      LINA_917_K8,     i386_prologue_scan,  'i386→x86-64'),
        ('ASA 9.1.7 32bit (i386)',   LINA_917_32,     i386_prologue_scan,  'i386→x86-64'),
        ('ASA 9.1.7.23 k8 (i386)',   LINA_917_23_K8,  i386_prologue_scan,  'i386→x86-64'),
        ('ASA 9.2.4 (i386)',         LINA_924,         i386_prologue_scan,  'i386→x86-64'),
        ('FTD 10.0.0 (AArch64)',     LINA_FTD10,       arm64_prologue_scan, 'AArch64→x86-64'),
        ('FTD 1200 7.6.2 (AArch64)', LINA_1200,        arm64_prologue_scan, 'AArch64→x86-64'),
    ]

    import os
    print(f'{"Target":<30} {"ISA":>15} {"N":>7} {"Scan":>6}  {"VA":>12}  {"Jac":>6}  {"Sem":>6}  {"XConf":<8}  Patched')
    print('-' * 110)

    for label, path, scanner, isa_label in targets:
        if not os.path.exists(path):
            print(f'{label:<30}  PATH MISSING: {path}')
            continue
        with open(path, 'rb') as f:
            data = f.read()
        t0 = time.time()
        feats = scanner(data)
        scan_s = time.time() - t0
        match = matcher.find_homolog(seed, feats)
        match_s = time.time() - scan_s - t0

        if match is None:
            print(f'{label:<30} {isa_label:>15} {len(feats):>7} {scan_s:>5.0f}s  {"NO MATCH":>12}')
        else:
            xconf = 'HIGH' if match.semantic_score >= CROSS_ARCH_SEM_THRESHOLD else 'MEDIUM'
            print(f'{label:<30} {isa_label:>15} {len(feats):>7} {scan_s:>5.0f}s  '
                  f'{hex(match.va):>12}  {match.jaccard:.4f}  {match.semantic_score:.4f}  '
                  f'{xconf:<8}  {"YES" if match.delta.is_patched else "NO"}')
            if xconf == 'HIGH':
                print(f'  CROSS-ARCH HIT (sem={match.semantic_score:.4f} >= {CROSS_ARCH_SEM_THRESHOLD})')


if __name__ == '__main__':
    main()
