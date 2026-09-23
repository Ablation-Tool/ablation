#!/usr/bin/env python3
"""
callsite_tracer.py — Trace argument registers at BL call sites for stripped ARM64 binaries.

Given a target function VA and a list of call-site PCs, backward-slices each
argument register (x0–x7) at each call site to determine its symbolic value.

Primary use: confirm that 0x2ec280 (gILinkKey list-insertion) receives
struct_base = GOT[0x3ce188] (gILinkKey - 0x48) as x0 at call sites
0x2e90cc and 0x2eac04.

GOT catalogue (libwechatnetwork.so, WeChat 8.0.56 ARM64):
  GOT[0x3cd9d8]  R_AARCH64_GLOB_DAT  mmtls::gILinkKey (+0)
  GOT[0x3ce188]  R_AARCH64_RELATIVE  struct_base = gILinkKey - 0x48

Usage:
  python3 callsite_tracer.py [--so PATH] [--target VA] [--callsite VA] [--depth N]

  # Confirm 0x2ec280 receives struct_base at both known callers:
  python3 callsite_tracer.py \\
      --target 0x2ec280 \\
      --callsite 0x2e90cc --callsite 0x2eac04
"""

import struct, sys, argparse
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

import lief
import capstone
from capstone import arm64 as A64

# ─── capstone ────────────────────────────────────────────────────────────────

_MD = capstone.Cs(capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
_MD.detail = True
_MD.skipdata = True

def _rn(insn, reg_id: int) -> str:
    if not reg_id:
        return 'xzr'
    n = insn.reg_name(reg_id)
    if n.startswith('w') and n[1:].isdigit():
        n = 'x' + n[1:]
    return n

# ─── symbolic value domain ───────────────────────────────────────────────────
# Minimal: Const, Global(name, delta), Add(base, imm), Unknown

@dataclass(frozen=True)
class Const:
    v: int
    def __str__(self): return f'0x{self.v:x}'

@dataclass(frozen=True)
class Global:
    name: str
    delta: int = 0
    def __str__(self):
        s = f'+0x{self.delta:x}' if self.delta > 0 else (f'-0x{-self.delta:x}' if self.delta < 0 else '')
        return f'Global({self.name}{s})'

@dataclass(frozen=True)
class Add:
    base: Any
    imm: int
    def __str__(self): return f'({self.base} + 0x{self.imm:x})'

@dataclass(frozen=True)
class Unknown:
    reg: str
    pc: int
    def __str__(self): return f'Unknown({self.reg}@0x{self.pc:x})'

# ─── GOT catalogue ───────────────────────────────────────────────────────────

_GOT: Dict[Tuple[int, int], Global] = {
    (0x3cd000, 0x9d8): Global('mmtls::gILinkKey', 0),
    (0x3ce000, 0x188): Global('mmtls::gILinkKey', -0x48),  # struct_base
}

# ─── binary helpers ───────────────────────────────────────────────────────────

def _load(so_path: str):
    binary = lief.parse(so_path)
    raw = Path(so_path).read_bytes()
    return binary, raw

def _va_to_raw(binary, va: int) -> Optional[int]:
    for seg in binary.segments:
        if seg.type != lief.ELF.Segment.TYPE.LOAD:
            continue
        b = seg.virtual_address
        if b <= va < b + seg.virtual_size:
            return seg.file_offset + (va - b)
    return None

def _read_u32(raw: bytes, off: int) -> int:
    return struct.unpack_from('<I', raw, off)[0]

def _decode_adrp(word: int, pc: int) -> Optional[int]:
    if (word & 0x9F000000) != 0x90000000:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)
    return (pc & ~0xFFF) + imm

def _fn_start(raw: bytes, binary, callsite_va: int, scan_back: int = 4096) -> int:
    """Heuristic: scan backward for STP x29, x30, [sp, #-k]! prologue."""
    off = _va_to_raw(binary, callsite_va)
    if off is None:
        return callsite_va - scan_back
    scan_start = max(0, off - scan_back)
    for i in range(0, off - scan_start, 4):
        file_off = scan_start + i
        w = struct.unpack_from('<I', raw, file_off)[0]
        va = callsite_va - (off - file_off)
        # STP x29, x30, [sp, #-k]!: bits[31:22]=0x2A6/0x2A7, Rt1=bits[4:0]=29
        top = (w >> 22) & 0x3FF
        rt1 = w & 0x1F
        if top in (0x2A6, 0x2A7) and rt1 == 29:
            last_prologue = va
    try:
        return last_prologue
    except NameError:
        return callsite_va - 0x200

# ─── backward slicer ─────────────────────────────────────────────────────────

_CALLER_SAVED: Set[str] = {f'x{i}' for i in range(19)} | {'x30'}

@dataclass(frozen=True)
class Arg:
    idx: int
    delta: int = 0
    def __str__(self):
        s = f'+0x{self.delta:x}' if self.delta > 0 else (f'-0x{-self.delta:x}' if self.delta < 0 else '')
        return f'Arg({self.idx}){s}'

def backward_slice(raw: bytes, binary, callsite_va: int,
                   arg_regs: List[str], max_depth: int = 128) -> Dict[str, Any]:
    """
    Forward-simulate from enclosing function start to callsite_va.
    Seeds x0..x7 as Arg(0)..Arg(7) to track argument threading.
    Returns {reg_name: symbolic_value} at the callsite.
    """
    fn_start = _fn_start(raw, binary, callsite_va)
    fn_off = _va_to_raw(binary, fn_start)
    if fn_off is None:
        return {r: Unknown(r, callsite_va) for r in arg_regs}

    cs_off = _va_to_raw(binary, callsite_va)
    if cs_off is None:
        return {r: Unknown(r, callsite_va) for r in arg_regs}

    chunk_size = cs_off - fn_off + 4
    chunk = raw[fn_off: fn_off + chunk_size]
    insns = list(_MD.disasm(chunk, fn_start))

    cs_idx = None
    for i, ins in enumerate(insns):
        if ins.address == callsite_va:
            cs_idx = i
            break
    if cs_idx is None:
        return {r: Unknown(r, callsite_va) for r in arg_regs}

    # Seed arg registers as Arg(i) symbolic values
    adrp_pages: Dict[str, int] = {}
    state: Dict[str, Any] = {f'x{i}': Arg(i) for i in range(8)}

    for i in range(cs_idx):  # stop BEFORE the callsite BL
        ins = insns[i]
        ops = ins.operands
        if not ops:
            continue

        if ins.id == A64.ARM64_INS_ADRP and ops:
            rd = _rn(ins, ops[0].reg)
            page = _decode_adrp(_read_u32(raw, fn_off + (ins.address - fn_start)), ins.address)
            if page is not None:
                adrp_pages[rd] = page
                state[rd] = Const(page)

        elif ins.id == A64.ARM64_INS_ADD and len(ops) >= 3:
            rd = _rn(ins, ops[0].reg)
            rn_str = _rn(ins, ops[1].reg) if ops[1].type == A64.ARM64_OP_REG else None
            if rn_str and ops[2].type == A64.ARM64_OP_IMM:
                imm = ops[2].imm
                base_val = state.get(rn_str)
                if isinstance(base_val, Const) and rn_str in adrp_pages:
                    state[rd] = Const((adrp_pages[rn_str] + imm) & 0xFFFFFFFFFFFFFFFF)
                elif isinstance(base_val, Arg):
                    state[rd] = Arg(base_val.idx, base_val.delta + imm)
                elif isinstance(base_val, Global):
                    state[rd] = Global(base_val.name, base_val.delta + imm)
                elif base_val is not None:
                    state[rd] = Add(base_val, imm)
                else:
                    state[rd] = Unknown(rd, ins.address)

        elif ins.id == A64.ARM64_INS_LDR and len(ops) >= 2:
            rd = _rn(ins, ops[0].reg)
            mem = ops[1] if ops[1].type == A64.ARM64_OP_MEM else None
            if mem:
                base_rn = _rn(ins, mem.mem.base) if mem.mem.base else None
                disp = mem.mem.disp
                if base_rn and base_rn in adrp_pages:
                    page = adrp_pages[base_rn]
                    slot = (page + disp) & 0xFFFFFFFFFFFFFFFF
                    slot_page = slot & ~0xFFF
                    slot_off = slot & 0xFFF
                    key = (slot_page, slot_off)
                    if key in _GOT:
                        state[rd] = _GOT[key]
                    else:
                        state[rd] = Unknown(rd, ins.address)
                else:
                    state[rd] = Unknown(rd, ins.address)

        elif ins.id in (A64.ARM64_INS_MOV, A64.ARM64_INS_MOVZ) and len(ops) >= 2:
            rd = _rn(ins, ops[0].reg)
            if ops[1].type == A64.ARM64_OP_IMM:
                state[rd] = Const(ops[1].imm)
            elif ops[1].type == A64.ARM64_OP_REG:
                src = _rn(ins, ops[1].reg)
                state[rd] = state.get(src, Unknown(src, ins.address))
        elif ins.id in (A64.ARM64_INS_LDP,) and len(ops) >= 3:
            # LDP xA, xB, [xBase, #disp] — track both destinations as Unknown from mem
            rd1 = _rn(ins, ops[0].reg)
            rd2 = _rn(ins, ops[1].reg)
            state[rd1] = Unknown(rd1, ins.address)
            state[rd2] = Unknown(rd2, ins.address)

        elif ins.id == A64.ARM64_INS_BL:
            # Clobber caller-saved
            for r in _CALLER_SAVED:
                if r in state:
                    del state[r]
            if i < cs_idx:
                adrp_pages.clear()

    result = {}
    for r in arg_regs:
        result[r] = state.get(r, Unknown(r, callsite_va))
    return result

# ─── main ─────────────────────────────────────────────────────────────────────

DEFAULT_SO = '/media/cowboy/research/wechat-re/native-libs/lib/arm64-v8a/libwechatnetwork.so'
DEFAULT_TARGET = 0x2ec280
DEFAULT_CALLSITES = [0x2e90cc, 0x2eac04]
DEFAULT_ARGS = ['x0', 'x1', 'x2', 'x3']

def main():
    ap = argparse.ArgumentParser(description='ARM64 call-site argument tracer')
    ap.add_argument('--so', default=DEFAULT_SO)
    ap.add_argument('--target', type=lambda x: int(x, 0), default=DEFAULT_TARGET,
                    metavar='VA', help='target function VA')
    ap.add_argument('--callsite', type=lambda x: int(x, 0), action='append',
                    dest='callsites', metavar='VA', help='call site PC (repeatable)')
    ap.add_argument('--args', default=','.join(DEFAULT_ARGS),
                    help='comma-separated arg regs to trace (default: x0,x1,x2,x3)')
    ap.add_argument('--depth', type=int, default=128, help='max backward scan depth')
    args = ap.parse_args()

    callsites = args.callsites if args.callsites else DEFAULT_CALLSITES
    arg_regs = [r.strip() for r in args.args.split(',')]

    binary, raw = _load(args.so)

    print(f'CALLSITE TRACER — fn@0x{args.target:x}')
    print(f'  binary: {Path(args.so).name}')
    print(f'  call sites: {[hex(c) for c in callsites]}')
    print(f'  tracing: {arg_regs}')
    print()

    confirmed_struct_base = []
    confirmed_gilink_key = []

    for cs_va in callsites:
        result = backward_slice(raw, binary, cs_va, arg_regs, args.depth)
        print(f'Call site 0x{cs_va:x}:')
        for reg, val in result.items():
            marker = ''
            if isinstance(val, Global):
                if val.name == 'mmtls::gILinkKey' and val.delta == -0x48:
                    marker = '  ← STRUCT_BASE (gILinkKey-0x48) ✓'
                    confirmed_struct_base.append(cs_va)
                elif val.name == 'mmtls::gILinkKey' and val.delta == 0:
                    marker = '  ← &gILinkKey directly'
                    confirmed_gilink_key.append(cs_va)
            print(f'  {reg:4s} = {val}{marker}')
        print()

    print('─' * 60)
    print(f'fn@0x{args.target:x} receives struct_base (gILinkKey-0x48) as x0:')
    if confirmed_struct_base:
        print(f'  CONFIRMED at {len(confirmed_struct_base)}/{len(callsites)} call sites:')
        for cs in confirmed_struct_base:
            print(f'    0x{cs:x}')
    else:
        print('  NOT CONFIRMED — x0 value unknown or different global at all traced sites')
    if confirmed_gilink_key:
        print(f'\n  NOTE: {len(confirmed_gilink_key)} site(s) pass &gILinkKey directly (delta=0):')
        for cs in confirmed_gilink_key:
            print(f'    0x{cs:x}')

if __name__ == '__main__':
    main()
