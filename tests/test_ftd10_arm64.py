"""
FTD 10.0.0 (ARM AArch64) — semantic homolog search for attr_list_add_impl.

FTD 10.0.0 lina is AArch64, not x86-64. The x86-64 prologue scanner and
mnemonic Jaccard layer don't apply cross-architecture. This test uses:
  - ARM64 prologue scanner (stp x29, x30, [sp, #N]! + paciasp patterns)
  - Capstone CS_ARCH_ARM64 for disassembly
  - MPNet semantic embedding as the primary similarity signal
  - Jaccard computed from AArch64 mnemonics (still valid within-arch)

The seed (attr_list_add_impl) is from x86-64 lina 9.14. Its text description
("implements attribute list management with conditional branching...") is
architecture-neutral — MPNet will score an AArch64 homolog on meaning, not
on shared instruction bytes.
"""

import sys
import time
import struct
import capstone
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.version_delta import FuncFeatures, FuncMatcher
from modules.semantic_search import SemanticSearcher

# ── paths ─────────────────────────────────────────────────────────────────────

LINA_914_X64  = '/path/to/binary'
LINA_1000_A64 = '/path/to/research/binary'
SEED_VA       = 0xc563d0
SEED_NAME     = 'attr_list_add_impl'
DB            = '~/.ablation/func_id.db'

# ── AArch64 prologue scanner ──────────────────────────────────────────────────

# All AArch64 instructions are exactly 4 bytes, little-endian.
# Primary prologue: stp x29, x30, [sp, #-N]!
#   Encoding: bytes[0]=0xfd, bytes[1]=0x7b, bytes[3]=0xa9 (byte[2] varies by offset)
# Secondary: paciasp (pointer authentication, ARMv8.3+)
#   Encoding: 5f 23 03 d5
# Tertiary: stp x29, x30, [sp, #-N]! without pointer auth (subset of primary)

_PACIASP = b'\x5f\x23\x03\xd5'
_MIN_INSTRS_A64 = 6
_MAX_BYTES_A64  = 4096


def _is_stp_x29_x30_pre(word: int) -> bool:
    """True if the 32-bit LE word is stp x29, x30, [sp, #N]! (pre-indexed)."""
    # Encoding: opc=10 V=0 L=0, pre-index, Rt=x29(0x1d), Rt2=x30(0x1e), Rn=sp(0x1f)
    # High byte: 0xa9 (64-bit STP pre-indexed base)
    # byte[1] = 0x7b (Rt2[4:0]=0x1e<<1 | Rn high bits ... actually simpler to mask)
    # Mask: byte[0]==0xfd, byte[1]==0x7b, byte[3]==0xa9
    b = word.to_bytes(4, 'little')
    return b[0] == 0xfd and b[1] == 0x7b and b[3] == 0xa9


def arm64_prologue_scan(data: bytes) -> list[FuncFeatures]:
    """Scan an AArch64 ELF binary for function prologues."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False
    seen: set[int] = set()

    # Scan at 4-byte aligned positions
    n = len(data) - 4
    for offset in range(0, n, 4):
        word = struct.unpack_from('<I', data, offset)[0]
        if _is_stp_x29_x30_pre(word):
            seen.add(offset)
        elif data[offset:offset+4] == _PACIASP:
            # paciasp at boundary — the stp usually follows within 1-2 instructions
            seen.add(offset)

    feats = []
    for offset in sorted(seen):
        raw = data[offset: offset + _MAX_BYTES_A64]
        lines, calls = [], []
        for insn in md.disasm(raw, offset):
            op = f'{insn.mnemonic} {insn.op_str}'.strip()
            lines.append(op)
            if insn.mnemonic in ('bl', 'blr') and insn.op_str.startswith('#0x'):
                calls.append(insn.op_str[1:])  # strip '#' prefix
            if insn.mnemonic == 'ret':
                break
            if insn.mnemonic == 'b' and not insn.op_str.startswith('.'):
                # unconditional branch out of function
                try:
                    dest = int(insn.op_str.lstrip('#'), 16)
                    if abs(dest - offset) > 0x40000:
                        break
                except ValueError:
                    break
        if len(lines) >= _MIN_INSTRS_A64:
            feats.append(FuncFeatures.from_disasm_lines(offset, hex(offset), lines, calls))
    return feats


# ── x86-64 seed extraction (same as other tests) ─────────────────────────────

_PROLOGUES_X64 = [b'\x55\x48\x89\xe5', b'\xf3\x0f\x1e\xfa\x55', b'\x55\x41']
_MAX_BYTES_X64 = 4096


def _extract_func_x64(data: bytes, offset: int) -> tuple[list[str], list[str]]:
    raw = data[offset: offset + _MAX_BYTES_X64]
    md  = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines, calls = [], []
    for insn in md.disasm(raw, offset):
        op = f'{insn.mnemonic} {insn.op_str}'.strip()
        lines.append(op)
        if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
            calls.append(insn.op_str)
        if insn.mnemonic in ('ret', 'retq', 'retn'):
            break
        if insn.mnemonic in ('jmp', 'jmpq'):
            try:
                if abs(int(insn.op_str, 16) - offset) > 0x20000:
                    break
            except ValueError:
                break
    return lines, calls


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ss      = SemanticSearcher(DB)
    ss.build_corpus()
    matcher = FuncMatcher(semantic_searcher=ss)

    with open(LINA_914_X64, 'rb') as f:
        data914 = f.read()
    asm_seed, callee_vas = _extract_func_x64(data914, SEED_VA)
    seed = FuncFeatures.from_disasm_lines(SEED_VA, SEED_NAME, asm_seed, callee_vas)
    print(f'Seed (x86-64): {SEED_NAME}  instrs={seed.n_instrs}')

    print(f'\nScanning FTD 10.0.0 lina (AArch64, 85 MB)...')
    with open(LINA_1000_A64, 'rb') as f:
        data1000 = f.read()
    t0 = time.time()
    feats = arm64_prologue_scan(data1000)
    scan_s = time.time() - t0
    print(f'  {len(feats)} functions in {scan_s:.1f}s')

    t0 = time.time()
    match = matcher.find_homolog(seed, feats)
    match_s = time.time() - t0
    print(f'  match in {match_s:.1f}s')

    # Cross-architecture confidence: bypass Jaccard floor (always near-zero across ISAs).
    # Semantic >= 0.85 from a validated seed is HIGH-equivalent for cross-arch matching.
    CROSS_ARCH_SEM_THRESHOLD = 0.85

    if match is None:
        print('\nResult: NO MATCH')
        print('  Cross-architecture semantic gap: the function is either absent,')
        print('  renamed, or the AArch64 description diverged too much from x86-64.')
    else:
        cross_arch_conf = 'HIGH' if match.semantic_score >= CROSS_ARCH_SEM_THRESHOLD else 'MEDIUM'
        print(f'\nResult:')
        print(f'  VA               : {hex(match.va)}')
        print(f'  jaccard          : {match.jaccard:.4f}  (expected ~0 cross-arch)')
        print(f'  semantic         : {match.semantic_score:.4f}')
        print(f'  confidence       : {match.confidence}  (same-arch Jaccard gate)')
        print(f'  cross_arch_conf  : {cross_arch_conf}  (semantic >= {CROSS_ARCH_SEM_THRESHOLD})')
        print(f'  is_patched       : {match.delta.is_patched}')
        if match.delta.added:   print(f'  added            : {match.delta.added[:5]}')
        if match.delta.removed: print(f'  removed          : {match.delta.removed[:5]}')
        print()
        if cross_arch_conf == 'HIGH':
            print(f'  CROSS-ARCH HIT: function found across ISA boundary (sem={match.semantic_score:.4f} >= {CROSS_ARCH_SEM_THRESHOLD})')


if __name__ == '__main__':
    main()
