#!/usr/bin/env python3
"""
skydio_dataflow_trace.py — Register dataflow tracer for ARM64 stripped binaries

Given a VA inside a function body (no prologue needed), finds the parent function,
disassembles it fully, and traces a target register through all def/use chains.

Primary use: trace x1 (malformed length) through 0x16ddba0's parent function to
determine if it reaches a memory copy operation (F2 negative-length bypass audit).

Usage:
  python3 modules/skydio_dataflow_trace.py --va 0x16ddba0 --reg x1
  python3 modules/skydio_dataflow_trace.py --va 0x16ddba0 --reg x1 --full
"""
import sys
import struct
import argparse
import re
from pathlib import Path

import capstone
from capstone import arm64_const

BINARY = "/media/cowboy/research/Skydio/intel-vdt/re-material/libflyby_jni.so"

# ARM64 prologue patterns (detect function entry)
PROLOGUE_STP_FP_LR = 0xA9BF7BFD   # stp x29, x30, [sp, #-N]!  mask=0xFFE07FFF
PROLOGUE_STP_MASK  = 0xFFE07FFF
PROLOGUE_STP2      = 0xA9007BFD    # stp x29, x30, [sp, N]      mask=0xFFC07FFF
PROLOGUE_STP2_MASK = 0xFFC07FFF
PROLOGUE_SUB_SP    = 0xD10003FF    # sub sp, sp, #imm            mask=0xFFC003FF
PROLOGUE_SUB_MASK  = 0xFFC003FF
PROLOGUE_STP_SP    = 0xA9BF7BE0    # stp x0, ... [sp, #-N]! (other pairs)
PROLOGUE_STP_SP_MASK = 0xFFE07FE0

# Memory copy/move indicators in mnemonic
COPY_MNEMONICS = {'bl', 'blr', 'str', 'strb', 'strh', 'stp', 'stlr', 'stlrb', 'stlrh', 'stlxr', 'stxr'}
CALL_MNEMONICS = {'bl', 'blr'}

# Register normalization: w-regs alias to x-regs
def norm_reg(r: str) -> str:
    r = r.lower().strip().rstrip(',')
    if r.startswith('w') and r[1:].isdigit():
        return 'x' + r[1:]
    return r

# Parse one instruction's register reads and writes
def get_defs_uses(insn) -> tuple[set, set]:
    """Return (defined_regs, used_regs) for an instruction."""
    defs, uses = set(), set()
    parts = insn.op_str.replace('[', '').replace(']', '').replace('!', '').split(',')
    mnem = insn.mnemonic.lower()

    if not parts or not parts[0].strip():
        return defs, uses

    first = norm_reg(parts[0])
    rest = [norm_reg(p) for p in parts[1:] if p.strip()]

    # Data transfer: first operand is def, rest are uses
    if mnem in ('mov', 'movz', 'movk', 'movn', 'fmov'):
        if first.startswith('x') or first.startswith('s') or first.startswith('d') or first.startswith('v'):
            defs.add(first)
        for r in rest:
            if r.startswith('x') or r.startswith('w'):
                uses.add(r)

    elif mnem.startswith('ldr') or mnem.startswith('ldp') or mnem in ('ldar', 'ldxr', 'ldaxr'):
        # ldr xN, [xM, #off]  -> def=xN, use=xM
        # ldp xN, xM, [xK]   -> def=xN,xM, use=xK
        for i, r in enumerate(parts):
            r = norm_reg(r)
            if r.startswith('x') or r.startswith('w'):
                if i == 0 or (mnem.startswith('ldp') and i == 1):
                    defs.add(r)
                else:
                    uses.add(r)

    elif mnem.startswith('str') or mnem.startswith('stp') or mnem in ('stlr', 'stlrb', 'stxr'):
        # str xN, [xM, #off]  -> use=xN,xM
        for r in parts:
            r = norm_reg(r)
            if r.startswith('x') or r.startswith('w'):
                uses.add(r)

    elif mnem in ('add', 'sub', 'and', 'orr', 'eor', 'asr', 'lsl', 'lsr', 'mul', 'umulh',
                  'subs', 'adds', 'ands', 'bics', 'bic', 'orn', 'adc', 'sbc', 'msb', 'madd',
                  'sbfx', 'ubfx', 'sbfiz', 'ubfiz', 'extr', 'csel', 'csinc', 'csinv', 'csneg',
                  'tst', 'cmp', 'cmn'):
        if first.startswith('x') or first.startswith('w'):
            if mnem not in ('tst', 'cmp', 'cmn'):
                defs.add(first)
            else:
                uses.add(first)
        for r in rest:
            if r.startswith('x') or r.startswith('w'):
                uses.add(r)

    elif mnem in ('bl', 'blr', 'br', 'b', 'bx'):
        # Calls clobber x0-x15, x30 per ABI
        for r in ('x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15','x30'):
            defs.add(r)
        # Uses are the argument regs at point of call (we handle separately)
        if mnem in ('blr', 'br'):
            for r in parts:
                r = norm_reg(r)
                if r.startswith('x'):
                    uses.add(r)

    elif mnem.startswith('sxt') or mnem.startswith('uxt'):
        if first.startswith('x') or first.startswith('w'):
            defs.add(first)
        for r in rest:
            if r.startswith('x') or r.startswith('w'):
                uses.add(r)

    return defs, uses


def load_binary(path: str):
    with open(path, 'rb') as f:
        return f.read()


def get_load_segments(data: bytes) -> list:
    """Return list of (va_start, va_end, file_offset) for all PT_LOAD R-X segments."""
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        if p_type == 1 and (p_flags & 1):  # PT_LOAD with exec bit
            segs.append((p_vaddr, p_vaddr + p_filesz, p_offset))
    return segs


def va_to_fileoff(segs: list, va: int) -> int:
    """Convert virtual address to file offset using PT_LOAD segments."""
    for va_start, va_end, foff_base in segs:
        if va_start <= va < va_end:
            return foff_base + (va - va_start)
    raise ValueError(f"VA 0x{va:x} not in any executable segment")


def read_at_va(data: bytes, segs: list, va: int, n: int) -> bytes:
    foff = va_to_fileoff(segs, va)
    return data[foff:foff + n]


def get_text_section(data: bytes):
    """Legacy: return (text_data, text_va, text_foff) for the primary code segment."""
    segs = get_load_segments(data)
    if not segs:
        raise RuntimeError("No executable PT_LOAD segments")
    # Return the largest executable segment
    segs_sorted = sorted(segs, key=lambda s: s[1] - s[0], reverse=True)
    va_start, va_end, foff_base = segs_sorted[0]
    return data[foff_base:foff_base + (va_end - va_start)], va_start, foff_base


def is_prologue(word: int) -> bool:
    if (word & PROLOGUE_STP_MASK) == PROLOGUE_STP_FP_LR:
        return True
    if (word & PROLOGUE_STP2_MASK) == PROLOGUE_STP2:
        return True
    if (word & PROLOGUE_SUB_MASK) == PROLOGUE_SUB_SP:
        return True
    return False


def find_parent_function(data: bytes, segs: list, va: int, max_scan: int = 0x8000) -> int:
    """Scan backwards from va to find the nearest function prologue."""
    scan_start = max(va - max_scan, 0)
    for candidate in range(va, scan_start, -4):
        try:
            raw = read_at_va(data, segs, candidate, 4)
        except ValueError:
            break
        word = struct.unpack_from('<I', raw)[0]
        if is_prologue(word):
            return candidate
    return va  # fallback: assume va IS the start


def disasm_function(data: bytes, segs: list, func_va: int, max_insns: int = 800) -> list:
    """Disassemble from func_va until ret or max_insns."""
    try:
        code = read_at_va(data, segs, func_va, max_insns * 4)
    except ValueError:
        return []
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    insns = []
    for insn in md.disasm(code, func_va):
        insns.append(insn)
        if insn.mnemonic == 'ret' and len(insns) > 8:
            break
        if len(insns) >= max_insns:
            break
    return insns


def trace_register(insns: list, target_reg: str, target_va: int) -> list:
    """
    Trace target_reg through instructions.
    Returns list of (insn, event_type, detail) for all def/use events.
    event_type: 'DEF' | 'USE' | 'CALL_ARG' | 'KILL' | 'STORE' | 'TAINT_CALL'
    """
    target = norm_reg(target_reg)
    # Track taint set: registers that hold value derived from target
    tainted = {target}
    events = []
    found_va = False

    for insn in insns:
        va = insn.address
        mnem = insn.mnemonic.lower()
        op_str = insn.op_str

        # Track only from our target VA onwards (the join point)
        # but trace the FULL function to understand all paths
        defs, uses = get_defs_uses(insn)
        tainted_used = tainted & uses
        tainted_defined = tainted & defs

        # Check for direct register use (unaliased)
        parts_raw = [p.strip().lower() for p in re.split(r'[,\[\]!]', op_str) if p.strip()]

        # CALL: check if any tainted reg is in argument position (x0-x7)
        if mnem in CALL_MNEMONICS:
            tainted_args = tainted & {'x0','x1','x2','x3','x4','x5','x6','x7'}
            if tainted_args:
                # Resolve call target
                call_target = op_str.strip()
                events.append((va, 'TAINT_CALL',
                    f"{mnem} {call_target}  [tainted args: {sorted(tainted_args)}]"))
            # ABI: x0-x15 killed after call (but x19-x28 preserved)
            killed = tainted & {'x0','x1','x2','x3','x4','x5','x6','x7',
                                 'x8','x9','x10','x11','x12','x13','x14','x15','x30'}
            if killed:
                events.append((va, 'KILL', f"ABI clobber after call: {sorted(killed)}"))
            tainted -= killed

        # STORE: tainted value written to memory
        elif mnem.startswith('str') or mnem.startswith('stp'):
            if tainted_used:
                events.append((va, 'STORE',
                    f"{mnem} {op_str}  [tainted: {sorted(tainted_used)}]"))

        # DEF: tainted value propagated to new register
        if tainted_used and defs:
            new_defs = defs - CALL_MNEMONICS  # don't add function names
            for r in new_defs:
                if r not in ('x29', 'x30', 'sp', 'xzr'):
                    tainted.add(r)
                    events.append((va, 'DEF',
                        f"{mnem} {op_str}  [{target} -> {r}]"))

        # KILL: register in taint set overwritten by non-tainted source
        kills = tainted_defined - (tainted & uses) - {target}
        # A def that isn't also a use kills the taint in that reg
        real_kills = set()
        for r in defs:
            if r in tainted and r not in uses and r not in {target}:
                real_kills.add(r)
        if real_kills:
            tainted -= real_kills

        # Direct USE (read) of tainted register
        if tainted_used and mnem not in CALL_MNEMONICS and mnem not in ('str','stp','strb','strh'):
            events.append((va, 'USE',
                f"{mnem} {op_str}  [tainted: {sorted(tainted_used)}]"))

    return events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=BINARY)
    parser.add_argument('--va', type=lambda x: int(x, 16), default=0x16ddba0,
                        help='VA inside target function (default: 0x16ddba0)')
    parser.add_argument('--reg', default='x1',
                        help='Register to trace (default: x1)')
    parser.add_argument('--full', action='store_true',
                        help='Print full disassembly alongside trace')
    parser.add_argument('--max-insns', type=int, default=600)
    args = parser.parse_args()

    print(f"[*] Skydio libflyby_jni.so — Dataflow Trace")
    print(f"[*] Target VA: 0x{args.va:x}  Register: {args.reg}\n")

    data = load_binary(args.binary)
    segs = get_load_segments(data)
    for va_s, va_e, foff in segs:
        print(f"[*] R-X segment: VA=0x{va_s:x}-0x{va_e:x}  ({(va_e-va_s)//1024}KB)")

    # Find parent function
    func_va = find_parent_function(data, segs, args.va)
    print(f"[*] Parent function: 0x{func_va:x}  (delta: {args.va - func_va} bytes from entry)")

    # Disassemble function
    insns = disasm_function(data, segs, func_va, args.max_insns)
    print(f"[*] Disassembled {len(insns)} instructions\n")

    # Trace register
    events = trace_register(insns, args.reg, args.va)

    if args.full:
        print("=== FULL DISASSEMBLY ===")
        for insn in insns:
            print(f"  0x{insn.address:08x}:  {insn.mnemonic:<8} {insn.op_str}")
        print()

    print(f"=== DATAFLOW TRACE: {args.reg} from 0x{func_va:x} ===")
    print(f"{'VA':<14} {'Event':<12} Details")
    print("-" * 80)

    taint_calls = [e for e in events if e[1] == 'TAINT_CALL']
    stores = [e for e in events if e[1] == 'STORE']

    for va, etype, detail in events:
        marker = " <===" if etype in ('TAINT_CALL', 'STORE') else ""
        print(f"  0x{va:08x}   {etype:<12} {detail}{marker}")

    print()
    print("=== SUMMARY ===")
    print(f"  Tainted calls ({len(taint_calls)}):")
    for va, _, detail in taint_calls:
        print(f"    0x{va:08x}  {detail}")
    print(f"\n  Tainted stores ({len(stores)}):")
    for va, _, detail in stores:
        print(f"    0x{va:08x}  {detail}")

    if not taint_calls and not stores:
        print("  [*] No tainted calls or memory writes found.")
        print("  [*] x1 (malformed length) does not reach a copy operation in this function.")
    else:
        print("\n  [!!!] Tainted value reaches memory or call -- review above for overflow candidate")


if __name__ == '__main__':
    main()
