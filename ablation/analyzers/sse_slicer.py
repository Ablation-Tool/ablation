#!/usr/bin/env python3
"""
sse_slicer.py — EmTaint-inspired SSE (Structured Symbolic Expression) backward slicer
for ARM64 stripped binaries. Finds all STR instructions whose effective address
(base + offset) computes to a target BSS address.

Algorithm (from: "EmTaint: Towards Precise Taint Analysis via Structured Symbolic
Expressions", EmTaint SSE approach, adapted for stripped ARM64 static analysis):

  SSE(reg) is a tree:
    Const(v)            — known constant (page addr, immediate)
    Add(sse, imm)       — sse + imm
    Mem(sse, imm)       — load from *(sse + imm)  [pointer dereference]
    Unknown(reg, pc)    — unresolved

  For each STR xT, [xN, #off] in .text:
    sse = slice_backward(xN, from STR site)
    ea  = eval(sse) + off
    if ea == TARGET:  → WRITER FOUND (exact)
    if contains_Mem(sse) and could_be_target(sse, off): → POSSIBLE WRITER

Usage:
  python3 sse_slicer.py \
    --binary libwechatnetwork.so \
    --target 0x3d4648 \
    --size 72 \
    [--text-start 0xdd130] [--text-size 0x2de650]

Paper basis:
  EmTaint: Towards Precise Taint Analysis via Structured Symbolic Expressions
  ("Finding Taint-Style Vulnerabilities in Linux-based Embedded Firmware with...")
  SSE builds a provenance tree for each variable; two SSEs alias iff they evaluate
  to the same address under any concrete memory state.

  iResolveX: Multi-Layered Indirect Call Resolution via Static Reasoning
  Inter-procedural backward analysis crossing call boundaries via ABI register
  save conventions (x19-x28 callee-saved on ARM64).
"""

import struct, sys, argparse
from pathlib import Path
from typing import Optional, Tuple, Dict, List

# ── SSE node types ────────────────────────────────────────────────────────────

class SSE:
    pass

class Const(SSE):
    def __init__(self, v: int):
        self.v = v & 0xFFFFFFFFFFFFFFFF
    def __repr__(self):
        return "Const(0x%x)" % self.v
    def eval(self, mem=None) -> Optional[int]:
        return self.v

class Add(SSE):
    def __init__(self, base: SSE, imm: int):
        self.base = base
        self.imm = imm & 0xFFFFFFFFFFFFFFFF
    def __repr__(self):
        return "Add(%r, 0x%x)" % (self.base, self.imm)
    def eval(self, mem=None) -> Optional[int]:
        b = self.base.eval(mem)
        return (b + self.imm) & 0xFFFFFFFFFFFFFFFF if b is not None else None

class Sub(SSE):
    def __init__(self, base: SSE, imm: int):
        self.base = base
        self.imm = imm & 0xFFFFFFFFFFFFFFFF
    def __repr__(self):
        return "Sub(%r, 0x%x)" % (self.base, self.imm)
    def eval(self, mem=None) -> Optional[int]:
        b = self.base.eval(mem)
        return (b - self.imm) & 0xFFFFFFFFFFFFFFFF if b is not None else None

class Mem(SSE):
    def __init__(self, base: SSE, imm: int):
        self.base = base
        self.imm = imm & 0xFFFFFFFFFFFFFFFF
    def __repr__(self):
        return "Mem(%r, 0x%x)" % (self.base, self.imm)
    def eval(self, mem=None) -> Optional[int]:
        if mem is None: return None
        addr = self.base.eval(mem)
        if addr is None: return None
        loaded_addr = (addr + self.imm) & 0xFFFFFFFFFFFFFFFF
        return mem.get(loaded_addr)

class Unknown(SSE):
    def __init__(self, reg: int, pc: int):
        self.reg = reg
        self.pc = pc
    def __repr__(self):
        return "Unknown(x%d@0x%x)" % (self.reg, self.pc)
    def eval(self, mem=None) -> Optional[int]:
        return None

def sse_has_mem(sse: SSE) -> bool:
    if isinstance(sse, Mem): return True
    if isinstance(sse, (Add, Sub)): return sse_has_mem(sse.base)
    return False

# ── ARM64 instruction decoders ────────────────────────────────────────────────

def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]

def u64(data: bytes, off: int) -> int:
    return struct.unpack_from('<Q', data, off)[0]

def decode_adrp(pc: int, w: int) -> Optional[Tuple[int, int]]:
    """Return (page, rd) or None."""
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000: imm -= 0x200000
    return (pc & ~0xFFF) + (imm << 12), w & 0x1F

def decode_add_imm(w: int) -> Optional[Tuple[int, int, int]]:
    """ADD rd, rn, #imm — return (rd, rn, imm) or None."""
    if (w & 0xFF000000) != 0x91000000:
        return None
    rd = w & 0x1F
    rn = (w >> 5) & 0x1F
    imm = (w >> 10) & 0xFFF
    sh = (w >> 22) & 1
    if sh: imm <<= 12
    return rd, rn, imm

def decode_sub_imm(w: int) -> Optional[Tuple[int, int, int]]:
    """SUB rd, rn, #imm — return (rd, rn, imm) or None."""
    if (w & 0xFF000000) != 0xD1000000:
        return None
    rd = w & 0x1F
    rn = (w >> 5) & 0x1F
    imm = (w >> 10) & 0xFFF
    sh = (w >> 22) & 1
    if sh: imm <<= 12
    return rd, rn, imm

def decode_ldr64(w: int) -> Optional[Tuple[int, int, int]]:
    """LDR Xt, [Xn, #imm] — return (rt, rn, imm) or None."""
    if (w & 0xFFC00000) != 0xF9400000:
        return None
    rt = w & 0x1F
    rn = (w >> 5) & 0x1F
    imm = ((w >> 10) & 0xFFF) * 8
    return rt, rn, imm

def decode_str64(w: int) -> Optional[Tuple[int, int, int]]:
    """STR Xt, [Xn, #imm] — return (rt, rn, imm) or None."""
    if (w & 0xFFC00000) != 0xF9000000:
        return None
    rt = w & 0x1F
    rn = (w >> 5) & 0x1F
    imm = ((w >> 10) & 0xFFF) * 8
    return rt, rn, imm

def decode_str_stp(w: int):
    """STP Xt1, Xt2, [Xn, #simm7*8] — return (rt1, rt2, rn, off) or None."""
    if (w & 0xFFC00000) != 0xA9000000:
        return None
    rt1 = w & 0x1F
    rn  = (w >> 5) & 0x1F
    rt2 = (w >> 10) & 0x1F
    imm7 = (w >> 15) & 0x7F
    if imm7 & 0x40: imm7 -= 0x80
    return rt1, rt2, rn, imm7 * 8

def decode_mov(w: int) -> Optional[Tuple[int, int]]:
    """MOV rd, rn (ORR rd, xzr, rn) — return (rd, rn) or None."""
    # MOV Xd, Xm: encoding = ORR Xd, XZR, Xm shifted #0
    if (w & 0xFFE0FFE0) == 0xAA0003E0:
        rd = w & 0x1F
        rm = (w >> 16) & 0x1F
        return rd, rm
    return None

def is_bl(w: int) -> bool:
    return (w & 0xFC000000) == 0x94000000

def is_blr(w: int) -> bool:
    return (w & 0xFFFFFC1F) == 0xD63F0000

def is_adrp(w: int) -> bool:
    return (w & 0x9F000000) == 0x90000000

# ── Intra-procedural prologue finder ─────────────────────────────────────────

def find_fn_start(data: bytes, addr: int, text_start: int, max_lb: int = 65536) -> int:
    for off in range(addr - 4, max(text_start, addr - max_lb), -4):
        if off < 0: break
        w = u32(data, off)
        if (w & 0xFFC07FFF) == 0xA9807BFD:  # STP X29,X30,[SP,#-x]!
            return off
        if w in (0xD503233F, 0xD503237F, 0xD503201F):  # PACIASP/NOP hints
            nw = u32(data, off + 4)
            if (nw & 0xFFC07FFF) == 0xA9807BFD:
                return off
    return max(text_start, addr - max_lb)

# ── Backward SSE slicer ───────────────────────────────────────────────────────

def backward_sse(data: bytes, target_reg: int, from_pc: int,
                 text_start: int, text_end: int,
                 max_depth: int = 128,
                 callee_saved: bool = False) -> SSE:
    """
    Walk backward from from_pc (exclusive) to find the SSE for target_reg.
    Stops at function boundary or max_depth instructions.

    ARM64 ABI:
      Caller-saved (clobbered by BL): x0-x18
      Callee-saved (survive BL):      x19-x28, x29 (fp), x30 (lr)
    """
    fn_start = find_fn_start(data, from_pc, text_start)

    cur_reg = target_reg
    cur_sse: SSE = Unknown(target_reg, from_pc)
    depth = 0

    pos = from_pc - 4  # start one instruction before target

    while pos >= fn_start and depth < max_depth:
        if pos + 4 > len(data): break
        w = u32(data, pos)

        # ADRP defines cur_reg → stop
        if is_adrp(w):
            res = decode_adrp(pos, w)
            if res and res[1] == cur_reg:
                cur_sse = Const(res[0])
                break

        # ADD rd, rn, #imm
        res = decode_add_imm(w)
        if res:
            rd, rn, imm = res
            if rd == cur_reg:
                if rn == cur_reg:
                    # ADD xD, xD, #imm → wrap in Add
                    cur_sse = Add(cur_sse, imm)
                else:
                    # ADD xD, xN, #imm where xN != xD → recurse for xN
                    inner = backward_sse(data, rn, pos, text_start, text_end,
                                         max_depth - depth, callee_saved)
                    cur_sse = Add(inner, imm)
                    break

        # SUB rd, rn, #imm
        res = decode_sub_imm(w)
        if res:
            rd, rn, imm = res
            if rd == cur_reg:
                inner = backward_sse(data, rn, pos, text_start, text_end,
                                      max_depth - depth, callee_saved)
                cur_sse = Sub(inner, imm)
                break

        # LDR Xt, [Xn, #imm] defines cur_reg
        res = decode_ldr64(w)
        if res:
            rt, rn, imm = res
            if rt == cur_reg:
                # Memory load — SSE = Mem(sse_of_rn, imm)
                inner = backward_sse(data, rn, pos, text_start, text_end,
                                      max_depth - depth, callee_saved)
                cur_sse = Mem(inner, imm)
                break

        # MOV defines cur_reg
        res = decode_mov(w)
        if res:
            rd, rm = res
            if rd == cur_reg:
                inner = backward_sse(data, rm, pos, text_start, text_end,
                                      max_depth - depth, callee_saved)
                cur_sse = inner
                break

        # BL/BLR: invalidates caller-saved (x0-x18)
        if (is_bl(w) or is_blr(w)) and cur_reg < 19:
            # cur_reg could be x0-x18 return value from this call
            # treat as return value — unknown
            cur_sse = Unknown(cur_reg, pos)
            break

        # Another ADRP to a DIFFERENT register: harmless, skip
        # ADRP to cur_reg handled above already

        pos -= 4
        depth += 1

    return cur_sse


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan(binary: Path, target: int, target_size: int,
         text_start: int, text_size: int,
         verbose: bool = False):
    data = binary.read_bytes()
    text_end = text_start + text_size

    TARGET_END = target + target_size

    print("[sse-slicer] Target: 0x%x..0x%x (size=%d)" % (target, TARGET_END, target_size))
    print("[sse-slicer] .text: 0x%x..0x%x" % (text_start, text_end))
    print()

    exact_writers = []
    mem_writers   = []

    n_str = 0
    for off in range(text_start, text_end, 4):
        if off + 4 > len(data): break
        w = u32(data, off)

        # STR Xt, [Xn, #imm]
        res = decode_str64(w)
        if res:
            rt, rn, imm = res
            if rn == 31: continue  # SP-relative: not BSS
            n_str += 1

            sse = backward_sse(data, rn, off, text_start, text_end)
            ea_sse = Add(sse, imm) if imm else sse
            ea_val = ea_sse.eval()

            if ea_val is not None:
                if target <= ea_val < TARGET_END:
                    exact_writers.append((off, rt, rn, imm, ea_val, ea_sse))
                    print("*** EXACT WRITER: 0x%x: STR x%d,[x%d,#0x%x]  EA=0x%x (gILinkKey+0x%x)"
                          % (off, rt, rn, imm, ea_val, ea_val - target))
                    print("    SSE(%s):" % ('x%d' % rn), sse)
            else:
                # EA has Mem nodes — mark as POSSIBLE
                if sse_has_mem(sse):
                    mem_writers.append((off, rt, rn, imm, ea_sse))
                    if verbose:
                        print("? POSSIBLE: 0x%x: STR x%d,[x%d,#0x%x]" % (off, rt, rn, imm))
                        print("    SSE:", sse)

        # STP Xt1, Xt2, [Xn, #simm7*8]
        res2 = decode_str_stp(w)
        if res2:
            rt1, rt2, rn, stp_off = res2
            if rn == 31: continue
            n_str += 1

            sse = backward_sse(data, rn, off, text_start, text_end)

            # STP writes two consecutive 8-byte slots
            for field_off, field_rt in ((stp_off, rt1), (stp_off + 8, rt2)):
                ea_sse = Add(sse, field_off) if field_off else sse
                ea_val = ea_sse.eval()
                if ea_val is not None:
                    if target <= ea_val < TARGET_END:
                        exact_writers.append((off, field_rt, rn, field_off, ea_val, ea_sse))
                        print("*** EXACT WRITER (STP): 0x%x: STP x%d,x%d,[x%d,#0x%x]  field=x%d EA=0x%x (gILinkKey+0x%x)"
                              % (off, rt1, rt2, rn, stp_off, field_rt, ea_val, ea_val - target))
                        print("    SSE(%s):" % ('x%d' % rn), sse)

    print()
    print("=" * 60)
    print("SUMMARY")
    print("  STR/STP instructions scanned: %d" % n_str)
    print("  EXACT writers to target:      %d" % len(exact_writers))
    print("  POSSIBLE (Mem-path) writers:  %d" % len(mem_writers))

    if mem_writers and not verbose:
        print("  (run with --verbose to see all POSSIBLE writers)")

    return exact_writers, mem_writers


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--binary', required=True)
    ap.add_argument('--target', default='0x3d4648', type=lambda x: int(x, 16))
    ap.add_argument('--size', default=72, type=int)
    ap.add_argument('--text-start', default='0xdd130', type=lambda x: int(x, 16))
    ap.add_argument('--text-size', default='0x2de650', type=lambda x: int(x, 16))
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    scan(Path(args.binary), args.target, args.size,
         args.text_start, args.text_size, args.verbose)
