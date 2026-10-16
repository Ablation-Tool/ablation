#!/usr/bin/env python3
"""
arm64_global_tracker.py — Global-symbol-aware SSE forward/backward slicer for ARM64.

Extends sse_slicer.py with a new symbolic domain tier that recognises GOT slots for
named global variables and propagates them through arithmetic, yielding stores like:

    WRITE  mmtls::gILinkKey  +0x08  at  0x303cbc  (STP x8,x8,[x20,#72])

Architecture
────────────
SSE domain (ordered by precision):

  Const(v)                  — concrete constant (page addr, immediate)
  Global(name)              — concrete address resolved via GOT GLOB_DAT/RELATIVE
  GlobAdd(name, imm)        — Global + imm  (field access into a global object)
  Add(sse, imm)             — generic addition
  Mem(sse, imm)             — pointer load *(sse+imm)
  Unknown(reg, pc)          — unresolvable

GOT catalogue (libwechatnetwork.so, WeChat 8.0.56 ARM64):
  GOT slot VA   Type               Addend / Symbol        Alias
  0x3cd9d8      R_AARCH64_GLOB_DAT mmtls::gILinkKey       GILINK_KEY
  0x3ce1b8      R_AARCH64_RELATIVE 0x3d4690               GILINK_KEY+72  (past-the-end)
  0x3ce188      R_AARCH64_RELATIVE 0x3d4600               STRUCT_BASE    (gILinkKey - 0x48)

When the slicer encounters:
  ADRP xN, PAGE  + LDR xM, [xN, #off]  where PAGE+off == known GOT slot:
    → return Global(alias)

  ADD xD, xN, #imm where SSE(xN) == Global(STRUCT_BASE):
    if imm == 0x48 → return Global("mmtls::gILinkKey")   (identity: struct_base+0x48 == gILinkKey)

  Store [Global(X) + off] → record as write to X at byte-offset off.

Paper basis:
  User extension of EmTaint SSE (see sse_slicer.py).
  Symbolic global tracking inspired by:
    "StateLifter: Recovering Program State Machines from Binary Executables"
    (semantic annotation of global state via relocation metadata).
  Inter-procedural tracking modelled on iResolveX callee-saved register propagation.

Usage (standalone):
  python3 arm64_global_tracker.py \
      --binary libwechatnetwork.so

Output:
  Per-global table of (pc, instruction, field_offset, size) write records.
"""

import struct, sys, argparse
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any

# ─────────────────────────────────────────────────────────────────────────────
# GOT catalogue: (GOT_VA, symbol_name, base_offset)
# base_offset = how many bytes from the named symbol does this slot point to?
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (got_page, got_offset_in_page, symbol_name, delta_from_symbol)
# Access pattern: ADRP x?, got_page; LDR x?, [x?, #got_offset_in_page]
GOT_CATALOGUE = [
    # GLOB_DAT: direct symbol pointer — loads &gILinkKey
    (0x3cd000, 0x9d8,  "mmtls::gILinkKey",  0),
    # RELATIVE: struct_base = gILinkKey - 0x48 — pointer to containing struct
    # ADD [struct_base_ptr + 0x48] == gILinkKey, so delta=-0x48 here
    (0x3ce000, 0x188,  "mmtls::gILinkKey",  -0x48),
    # NOTE: GOT[0x3ce1b8] = 0x3d4690 is the NEXT BSS object after gILinkKey,
    # NOT a field of gILinkKey. Excluded from catalogue to avoid false positives.
]

# Build lookup: (page, off_in_page) → (symbol, delta)
_GOT_LOOKUP: Dict[Tuple[int,int], Tuple[str,int]] = {
    (p, o): (sym, d) for p, o, sym, d in GOT_CATALOGUE
}


# ─────────────────────────────────────────────────────────────────────────────
# SSE node hierarchy (extended with Global / GlobAdd)
# ─────────────────────────────────────────────────────────────────────────────

class SSE:
    def eval(self) -> Optional[int]:
        return None
    def contains_mem(self) -> bool:
        return False
    def contains_global(self) -> bool:
        return False

class Const(SSE):
    def __init__(self, v: int):
        self.v = v & 0xFFFFFFFFFFFFFFFF
    def __repr__(self): return f"Const(0x{self.v:x})"
    def eval(self): return self.v

class Global(SSE):
    """Symbolic address: the runtime address of a named global variable."""
    def __init__(self, name: str, delta: int = 0):
        self.name = name      # canonical symbol name
        self.delta = delta    # bytes from symbol base that this pointer is at
    def __repr__(self):
        suffix = (f"+0x{self.delta:x}" if self.delta > 0 else
                  f"-0x{-self.delta:x}" if self.delta < 0 else "")
        return f"Global({self.name}{suffix})"
    def contains_global(self): return True

class GlobAdd(SSE):
    """Global(name) + additional immediate offset."""
    def __init__(self, name: str, base_delta: int, extra: int):
        self.name = name
        self.total = base_delta + extra   # total offset from symbol base
    def __repr__(self):
        suffix = (f"+0x{self.total:x}" if self.total >= 0 else f"-0x{-self.total:x}")
        return f"GlobAdd({self.name}{suffix})"
    def contains_global(self): return True

class Add(SSE):
    def __init__(self, base: SSE, imm: int):
        self.base, self.imm = base, imm & 0xFFFFFFFFFFFFFFFF
    def __repr__(self): return f"Add({self.base!r}, 0x{self.imm:x})"
    def eval(self):
        b = self.base.eval()
        return (b + self.imm) & 0xFFFFFFFFFFFFFFFF if b is not None else None
    def contains_mem(self): return self.base.contains_mem()
    def contains_global(self): return self.base.contains_global()

class Mem(SSE):
    def __init__(self, base: SSE, imm: int):
        self.base, self.imm = base, imm & 0xFFFFFFFFFFFFFFFF
    def __repr__(self): return f"Mem({self.base!r}, 0x{self.imm:x})"
    def contains_mem(self): return True
    def contains_global(self): return self.base.contains_global()

class Unknown(SSE):
    def __init__(self, reg: int, pc: int):
        self.reg, self.pc = reg, pc
    def __repr__(self): return f"Unknown(x{self.reg}@0x{self.pc:x})"


def _global_from_got(page: int, offset: int) -> Optional[SSE]:
    """
    If (page, offset) matches a known GOT entry, return the appropriate Global SSE node.
    page   = ADRP result (page-aligned VA)
    offset = byte offset within that page (LDR unsigned imm)
    """
    key = (page, offset)
    if key in _GOT_LOOKUP:
        sym, delta = _GOT_LOOKUP[key]
        return Global(sym, delta)
    return None

def _global_add(base: SSE, imm: int) -> SSE:
    """
    Fold ADD(Global/GlobAdd, imm) → resolved Global/GlobAdd node.
    Special case: Global("mmtls::gILinkKey", -0x48) + 0x48 = Global("mmtls::gILinkKey", 0)
    """
    if isinstance(base, Global):
        new_delta = base.delta + imm
        # identity: check if new_delta == 0
        return Global(base.name, new_delta)
    if isinstance(base, GlobAdd):
        return GlobAdd(base.name, 0, base.total + imm)
    return Add(base, imm)


# ─────────────────────────────────────────────────────────────────────────────
# Instruction decoders
# ─────────────────────────────────────────────────────────────────────────────

def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]

def decode_adrp(pc: int, w: int) -> Optional[Tuple[int, int]]:
    if (w & 0x9F000000) != 0x90000000: return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000: imm -= 0x200000
    return (pc & ~0xFFF) + (imm << 12), w & 0x1F

def decode_add_imm(w: int) -> Optional[Tuple[int, int, int]]:
    if (w & 0xFF000000) != 0x91000000: return None
    rd, rn = w & 0x1F, (w >> 5) & 0x1F
    imm = (w >> 10) & 0xFFF
    if (w >> 22) & 1: imm <<= 12
    return rd, rn, imm

def decode_sub_imm(w: int) -> Optional[Tuple[int, int, int]]:
    if (w & 0xFF000000) != 0xD1000000: return None
    rd, rn = w & 0x1F, (w >> 5) & 0x1F
    imm = (w >> 10) & 0xFFF
    if (w >> 22) & 1: imm <<= 12
    return rd, rn, imm

def decode_ldr64(w: int) -> Optional[Tuple[int, int, int]]:
    if (w & 0xFFC00000) != 0xF9400000: return None
    return w & 0x1F, (w >> 5) & 0x1F, ((w >> 10) & 0xFFF) * 8

def decode_str64(w: int) -> Optional[Tuple[int, int, int]]:
    if (w & 0xFFC00000) != 0xF9000000: return None
    return w & 0x1F, (w >> 5) & 0x1F, ((w >> 10) & 0xFFF) * 8

def decode_stp(w: int) -> Optional[Tuple[int, int, int, int]]:
    if (w & 0xFFC00000) != 0xA9000000: return None
    rt1, rn, rt2 = w & 0x1F, (w >> 5) & 0x1F, (w >> 10) & 0x1F
    imm7 = (w >> 15) & 0x7F
    if imm7 & 0x40: imm7 -= 0x80
    return rt1, rt2, rn, imm7 * 8

def decode_stur64(w: int) -> Optional[Tuple[int, int, int]]:
    # STUR Xt, [Xn, #simm9]
    if (w & 0xFFE00C00) != 0xF8000000: return None
    rt, rn = w & 0x1F, (w >> 5) & 0x1F
    imm9 = (w >> 12) & 0x1FF
    if imm9 & 0x100: imm9 -= 0x200
    return rt, rn, imm9

def decode_mov(w: int) -> Optional[Tuple[int, int]]:
    if (w & 0xFFE0FFE0) == 0xAA0003E0:
        return w & 0x1F, (w >> 16) & 0x1F
    return None

def is_bl(w: int) -> bool:  return (w >> 26) == 0b100101
def is_blr(w: int) -> bool: return (w & 0xFFFFFC1F) == 0xD63F0000
def is_adrp(w: int) -> bool: return (w & 0x9F000000) == 0x90000000


# ─────────────────────────────────────────────────────────────────────────────
# Function boundary finder
# ─────────────────────────────────────────────────────────────────────────────

def find_fn_start(data: bytes, addr: int, text_start: int) -> int:
    for off in range(addr - 4, max(text_start, addr - 65536), -4):
        if off < 0: break
        w = u32(data, off)
        # STP X29,X30,[SP,#-N]!
        if (w & 0xFFC07FFF) == 0xA9807BFD:
            return off
    return max(text_start, addr - 65536)


# ─────────────────────────────────────────────────────────────────────────────
# Global-aware backward SSE slicer
# ─────────────────────────────────────────────────────────────────────────────

def backward_sse(data: bytes, target_reg: int, from_pc: int,
                 text_start: int, text_end: int,
                 max_depth: int = 150) -> SSE:
    """
    Walk backward from from_pc to resolve SSE for target_reg.
    Recognises GOT loads as Global(symbol) nodes.
    """
    fn_start = find_fn_start(data, from_pc, text_start)
    cur_reg  = target_reg
    cur_sse: SSE = Unknown(target_reg, from_pc)
    depth    = 0
    pos      = from_pc - 4

    while pos >= fn_start and depth < max_depth:
        if pos + 4 > len(data): break
        w = u32(data, pos)

        # ADRP: defines cur_reg with page constant
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
                    cur_sse = _global_add(cur_sse, imm) if cur_sse.contains_global() \
                              else Add(cur_sse, imm)
                else:
                    inner = backward_sse(data, rn, pos, text_start, text_end, max_depth - depth)
                    cur_sse = _global_add(inner, imm)
                break

        # SUB rd, rn, #imm
        res = decode_sub_imm(w)
        if res:
            rd, rn, imm = res
            if rd == cur_reg:
                inner = backward_sse(data, rn, pos, text_start, text_end, max_depth - depth)
                cur_sse = Add(inner, -imm & 0xFFFFFFFFFFFFFFFF)
                break

        # LDR Xt, [Xn, #imm]  — check for GOT catalogue match
        res = decode_ldr64(w)
        if res:
            rt, rn, imm = res
            if rt == cur_reg:
                inner = backward_sse(data, rn, pos, text_start, text_end, max_depth - depth)
                # GOT slot recognition
                if isinstance(inner, Const):
                    g = _global_from_got(inner.v, imm)
                    if g is not None:
                        cur_sse = g
                        break
                cur_sse = Mem(inner, imm)
                break

        # MOV rd, rm
        res = decode_mov(w)
        if res:
            rd, rm = res
            if rd == cur_reg:
                cur_sse = backward_sse(data, rm, pos, text_start, text_end, max_depth - depth)
                break

        # BL/BLR: invalidates x0-x18
        if (is_bl(w) or is_blr(w)) and cur_reg < 19:
            cur_sse = Unknown(cur_reg, pos)
            break

        pos -= 4
        depth += 1

    return cur_sse


# ─────────────────────────────────────────────────────────────────────────────
# Write record
# ─────────────────────────────────────────────────────────────────────────────

class WriteRecord:
    def __init__(self, pc: int, insn: str, symbol: str, field_off: int, size: int, base_sse: SSE):
        self.pc        = pc
        self.insn      = insn
        self.symbol    = symbol
        self.field_off = field_off   # byte offset from symbol base
        self.size      = size        # 8 for STR, 8+8=16 for STP pair
        self.base_sse  = base_sse

    def __repr__(self):
        return (f"WriteRecord(pc=0x{self.pc:x}, symbol={self.symbol}, "
                f"field=+0x{self.field_off:x}, size={self.size}, "
                f"insn={self.insn}, sse={self.base_sse!r})")


def _extract_global_write(sse: SSE, field_off: int) -> Optional[Tuple[str, int]]:
    """
    If sse (the base register) + field_off ultimately points into a known global,
    return (symbol_name, total_byte_offset_from_symbol) or None.
    """
    # Direct Global node
    if isinstance(sse, Global):
        return sse.name, sse.delta + field_off
    if isinstance(sse, GlobAdd):
        return sse.name, sse.total + field_off
    # Add(Global(...), X) should already be folded by _global_add
    if isinstance(sse, Add):
        inner = sse.base
        if isinstance(inner, Global):
            total_off = inner.delta + (sse.imm & 0x7FFFFFFFFFFFFFFF) + field_off
            # handle negative imm stored as large uint
            if sse.imm > (1 << 63):
                total_off = inner.delta - (2**64 - sse.imm) + field_off
            return inner.name, total_off
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main scan
# ─────────────────────────────────────────────────────────────────────────────

def scan(binary: Path, text_start: int, text_size: int, verbose: bool = False
         ) -> List[WriteRecord]:
    data      = binary.read_bytes()
    text_end  = text_start + text_size
    records: List[WriteRecord] = []

    for off in range(text_start, text_end, 4):
        if off + 4 > len(data): break
        w = u32(data, off)

        # STR Xt, [Xn, #imm]
        res = decode_str64(w)
        if res:
            _rt, rn, imm = res
            if rn == 31: continue
            sse = backward_sse(data, rn, off, text_start, text_end)
            hit = _extract_global_write(sse, imm)
            if hit:
                sym, foff = hit
                records.append(WriteRecord(off, f"STR x{_rt},[x{rn},#0x{imm:x}]", sym, foff, 8, sse))

        # STUR Xt, [Xn, #simm9]
        res = decode_stur64(w)
        if res:
            _rt, rn, simm = res
            if rn == 31: continue
            sse = backward_sse(data, rn, off, text_start, text_end)
            imm = simm if simm >= 0 else simm  # signed
            hit = _extract_global_write(sse, imm)
            if hit:
                sym, foff = hit
                records.append(WriteRecord(off, f"STUR x{_rt},[x{rn},#0x{simm:x}]", sym, foff, 8, sse))

        # STP Xt1, Xt2, [Xn, #simm7*8]
        res2 = decode_stp(w)
        if res2:
            rt1, rt2, rn, stp_off = res2
            if rn == 31: continue
            sse = backward_sse(data, rn, off, text_start, text_end)
            for field_off_adj, _src in ((stp_off, rt1), (stp_off + 8, rt2)):
                hit = _extract_global_write(sse, field_off_adj)
                if hit:
                    sym, foff = hit
                    records.append(WriteRecord(
                        off, f"STP x{rt1},x{rt2},[x{rn},#0x{stp_off:x}] slot=x{_src}",
                        sym, foff, 8, sse))

    return records


def report(records: List[WriteRecord]) -> None:
    if not records:
        print("[global-tracker] 0 global writes found.")
        return

    from collections import defaultdict
    by_sym: Dict[str, List[WriteRecord]] = defaultdict(list)
    for r in records:
        by_sym[r.symbol].append(r)

    for sym, recs in sorted(by_sym.items()):
        print(f"\n{'='*60}")
        print(f"GLOBAL: {sym}  ({len(recs)} writes)")
        print(f"{'='*60}")
        for r in sorted(recs, key=lambda x: x.field_off):
            print(f"  pc=0x{r.pc:x}  field=+0x{r.field_off:x}  {r.insn}")
            print(f"        base_sse={r.base_sse!r}")


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--binary', default='/path/to/libwechatnetwork.so')
    ap.add_argument('--text-start', default='0xdd130', type=lambda x: int(x, 16))
    ap.add_argument('--text-size',  default='0x2de650', type=lambda x: int(x, 16))
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    print(f"[global-tracker] Scanning {args.binary}")
    print(f"[global-tracker] .text 0x{args.text_start:x}..0x{args.text_start+args.text_size:x}")
    print(f"[global-tracker] GOT catalogue: {len(GOT_CATALOGUE)} entries")
    for p, o, sym, d in GOT_CATALOGUE:
        dsuf = f"+0x{d:x}" if d >= 0 else f"-0x{-d:x}"
        print(f"   GOT[0x{p+o:x}] -> {sym}{dsuf}")
    print()

    recs = scan(Path(args.binary), args.text_start, args.text_size, args.verbose)
    report(recs)
    print(f"\n[global-tracker] Total global write records: {len(recs)}")
