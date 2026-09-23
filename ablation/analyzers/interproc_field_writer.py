#!/usr/bin/env python3
"""
interproc_field_writer.py — ablation module
Demand-driven inter-procedural field-writer finder for stripped ARM64 binaries.

Finds all functions that write to a specific field of a known global symbol,
even when the struct pointer is forwarded through multiple call frames as a
function argument. Crosses BL boundaries using per-function summaries keyed
to the ARM64 calling convention (x0-x7 args, x0 return, x19-x28 callee-saved).

Algorithm (summary-based, demand-driven IFDS-style inter-procedural dataflow):
  Phase 1 — Build per-function summaries (lazy, on-demand):
      abstract domain: Arg(i) | GlobalVal(name,delta) | Add(base,imm) | None
      record:  global_field_writes  — writes to known GOT-loaded globals
               global_to_callee     — pass global as callee arg
               arg_field_writes     — writes to [Arg(i) + offset]
               arg_to_callee        — forward Arg(i) to callee arg position j

  Phase 2 — Seed discovery:
      Scan .text for ADRP+LDR pairs loading gILinkKey GOT entries.
      Walk backward ~512 bytes to find enclosing function prologue (STP x29,x30).

  Phase 3 — Worklist propagation:
      Worklist items: (fn_va, tracking_mode, key)
        mode='global'  → function directly holds the target GlobalVal in a register
        mode='arg'     → function receives target via argument register idx=key
      At each function: report any writes; enqueue callees that receive the tracked ptr.

References:
  - Summary-based IFDS (Reps, Horwitz, Sagiv 1995)
  - Interprocedural slicing (Horwitz, Reps, Binkley 1992)
  - "Static Analysis of Executables for Automatic Struct Field Recovery" (Egele, NDSS 2017)
  - iResolveX callee-saved register propagation (intra-proc basis for inter-proc bridge)

Binary hardcoded: libwechatnetwork.so (WeChat 8.0.56 ARM64)
  .text VA == file offset
  GOT[0x3cd9d8] = R_AARCH64_GLOB_DAT → mmtls::gILinkKey (VA 0x3d4648, size 72)
  GOT[0x3ce188] = R_AARCH64_RELATIVE addend=0x3d4600 → struct_base (gILinkKey - 0x48)
"""

import struct
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import capstone
    import capstone.arm64
except ImportError:
    print("[!] pip install capstone", file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Abstract value domain
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Arg:
    """Abstract function argument in register x{idx}."""
    idx: int
    def __repr__(self): return f"Arg({self.idx})"

@dataclass(frozen=True)
class GlobalVal:
    """Known global variable loaded from GOT; delta = bytes from symbol base."""
    name: str
    delta: int = 0
    def __repr__(self):
        sign = '+' if self.delta >= 0 else '-'
        return f"Global({self.name!r} {sign} {abs(self.delta):#x})"

@dataclass(frozen=True)
class Add:
    """base + imm where base is Arg or GlobalVal."""
    base: Any
    imm: int
    def __repr__(self): return f"({self.base} + {self.imm:#x})"


def _add(base: Any, imm: int) -> Any:
    if base is None or imm == 0 and not isinstance(base, type(None)):
        if imm == 0:
            return base
    if base is None:
        return None
    if isinstance(base, Add):
        return _add(base.base, base.imm + imm)
    if isinstance(base, GlobalVal):
        return GlobalVal(base.name, base.delta + imm)
    if isinstance(base, Arg):
        return Add(base, imm) if imm != 0 else base
    return None


def _resolve(val: Any) -> Optional[Tuple[str, Any, int]]:
    """
    Returns (kind, key, offset):
      kind='global' → key=name, offset=bytes from symbol base
      kind='arg'    → key=arg_idx, offset=bytes from arg pointer
    Returns None if unresolvable.
    """
    if isinstance(val, GlobalVal):
        return ('global', val.name, val.delta)
    if isinstance(val, Arg):
        return ('arg', val.idx, 0)
    if isinstance(val, Add):
        b = val.base
        if isinstance(b, GlobalVal):
            return ('global', b.name, b.delta + val.imm)
        if isinstance(b, Arg):
            return ('arg', b.idx, val.imm)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# GOT catalogue
# ─────────────────────────────────────────────────────────────────────────────

# (ADRP_page, LDR_offset_in_page) → GlobalVal
_GOT: Dict[Tuple[int, int], GlobalVal] = {
    (0x3cd000, 0x9d8): GlobalVal("mmtls::gILinkKey", 0),    # R_AARCH64_GLOB_DAT
    (0x3ce000, 0x188): GlobalVal("mmtls::gILinkKey", -0x48), # R_AARCH64_RELATIVE; struct_base
}


def _got_lookup(page: int, off: int) -> Optional[GlobalVal]:
    return _GOT.get((page, off))


# ─────────────────────────────────────────────────────────────────────────────
# Per-function summary
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FuncSummary:
    addr: int
    # Writes to a known global: (global_name, effective_field_offset, store_pc, store_bytes)
    global_field_writes: List[Tuple[str, int, int, int]] = field(default_factory=list)
    # Global forwarded as callee arg: (callee_va, global_name, callee_arg_idx, call_pc)
    global_to_callee: List[Tuple[int, str, int, int]] = field(default_factory=list)
    # Writes to an arg pointer field: (arg_idx, field_offset, store_pc, store_bytes)
    arg_field_writes: List[Tuple[int, int, int, int]] = field(default_factory=list)
    # Arg forwarded to callee arg: (callee_va, caller_arg_idx, callee_arg_idx, call_pc)
    arg_to_callee: List[Tuple[int, int, int, int]] = field(default_factory=list)
    # All direct callee addresses seen in BL instructions
    direct_callees: Set[int] = field(default_factory=set)
    # How many instructions were analysed
    insns_scanned: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Binary wrapper
# ─────────────────────────────────────────────────────────────────────────────

class Binary:
    TEXT_VA   = 0xdd130
    TEXT_SIZE = 0x2de650
    TEXT_END  = TEXT_VA + TEXT_SIZE
    GOT_VA    = 0x3cd9c8
    GOT_FO    = GOT_VA - 0x1000
    GOT_SIZE  = 0x2fc0

    # PLT lazy-resolver stubs — BL to these are external and untraceable
    PLT_STUBS: Set[int] = {0x3bb780}

    def __init__(self, path: str):
        self.data = Path(path).read_bytes()
        self._md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        self._md.detail = True

    def in_text(self, va: int) -> bool:
        return self.TEXT_VA <= va < self.TEXT_END

    def read32(self, va: int) -> Optional[int]:
        if not self.in_text(va) or va + 4 > len(self.data):
            return None
        return struct.unpack_from('<I', self.data, va)[0]

    def disasm(self, va: int, max_bytes: int):
        if not self.in_text(va):
            return
        chunk = self.data[va : va + max_bytes]
        yield from self._md.disasm(chunk, va)

    def _decode_adrp(self, w: int, pc: int) -> Optional[int]:
        if (w & 0x9F000000) != 0x90000000:
            return None
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= (1 << 33)
        return (pc & ~0xFFF) + imm

    def find_function_start(self, va: int, search_back: int = 512) -> int:
        """
        Walk backwards from va looking for STP x29,x30,[sp,#-k]! (function prologue).
        Returns best-guess function entry, or va itself if not found.
        """
        probe = (va & ~3) - 4
        limit = max(self.TEXT_VA, va - search_back)
        while probe >= limit:
            w = self.read32(probe)
            if w is not None:
                # STP x29,x30,[sp,#-k]! = 0xA9?x7BFD  (various k)
                # More precisely: bits[31:23]=0b1010 1001 1, rd=x29(29), r2=x30(30), rn=sp
                # Mask: 0xFFC07FFF, value: 0xA9807BFD
                # Looser: top byte 0xA9 or 0xAD (pre-index variants), rd=x29
                top = (w >> 20) & 0xFFF
                if top in (0xA98, 0xA9C, 0xA99, 0xA9D, 0xAD8, 0xADC):
                    # Check Rt field = 29 (x29)
                    if (w & 0x1F) == 29:
                        return probe
                # SUB sp, sp, #imm (another prologue style)
                # D100?3FF = sub sp, sp, #imm
                if (w & 0xFFC003FF) == 0xD10003FF:
                    return probe
            probe -= 4
        return va

    def scan_got_loads(self, target_gv: GlobalVal) -> List[Tuple[int, int]]:
        """
        Scan .text for ADRP+LDR pairs that load a specific GlobalVal from GOT.
        Returns list of (load_pc, fn_start_va).
        """
        results = []
        # Build reverse GOT lookup for this specific GlobalVal
        target_slots = {(p, o) for (p, o), gv in _GOT.items()
                        if gv.name == target_gv.name}

        va = self.TEXT_VA
        end = self.TEXT_END
        adrp_page: Dict[int, Tuple[int, int]] = {}  # reg_idx -> (page, adrp_pc)

        while va < end:
            w = self.read32(va)
            if w is None:
                va += 4
                continue

            # Detect ADRP
            page = self._decode_adrp(w, va)
            if page is not None:
                rd = w & 0x1F
                adrp_page[rd] = (page, va)
                va += 4
                continue

            # Detect LDR x?, [x?, #off]  (64-bit load, unsigned offset)
            # Encoding: 1111 1001 01xx xxxx xxxx xxxx xxxx xxxx
            if (w & 0xFFC00000) == 0xF9400000:
                rn = (w >> 5) & 0x1F
                rd = w & 0x1F
                imm12 = (w >> 10) & 0xFFF
                off = imm12 << 3  # scale=8 for 64-bit
                if rn in adrp_page:
                    pg, adrp_pc = adrp_page[rn]
                    if (pg, off) in target_slots:
                        fn_start = self.find_function_start(va)
                        results.append((va, fn_start))
                    del adrp_page[rn]
                va += 4
                continue

            # Any instruction that writes to a reg clears its ADRP page
            # Simplification: clear on any non-ADRP/LDR write to rn
            rd_generic = w & 0x1F
            if rd_generic in adrp_page:
                adrp_page.pop(rd_generic, None)

            va += 4

        return results


# ─────────────────────────────────────────────────────────────────────────────
# Per-function intra-procedural summary builder
# ─────────────────────────────────────────────────────────────────────────────

# ARM64 argument register names in order
_ARG_REGS = [f'x{i}' for i in range(8)]

# Caller-saved register names: x0-x18, x30
_CALLER_SAVED_NAMES = {f'x{i}' for i in range(19)} | {'x30'}

# W-register name → canonical X-register name (w0 → x0, etc.)
def _canon(name: str) -> str:
    """Canonicalize register name to x-form for state dict keys."""
    if name.startswith('w') and name[1:].isdigit():
        return 'x' + name[1:]
    return name


def _reg_name(insn, reg_id: int) -> str:
    """Get canonical register name string from capstone register ID."""
    name = insn.reg_name(reg_id) if reg_id else 'xzr'
    return _canon(name)


def _mem_base_name(insn, reg_id: int) -> Optional[str]:
    """Return canonical base register name for a memory operand, or None for sp/xzr."""
    if not reg_id:
        return None
    name = _canon(insn.reg_name(reg_id))
    if name in ('xzr', 'sp'):
        return None
    return name


def build_summary(binary: Binary, fn_va: int, max_insns: int = 3000) -> FuncSummary:
    """
    Single-pass intra-procedural analysis of function at fn_va.
    Produces a FuncSummary recording arg/global field writes and arg flows.

    State dict uses canonical register name strings ('x0'..'x30') as keys.
    Capstone register IDs are NOT 0-31; always use reg_name() conversion.
    """
    summary = FuncSummary(addr=fn_va)

    # Register state: 'xN' -> abstract value | None (unknown)
    state: Dict[str, Any] = {f'x{i}': Arg(i) for i in range(8)}
    # x8-x18: caller-saved, unknown initially (not in state)
    # x19-x28: callee-saved; unknown until assigned

    # Pending ADRP pages: reg_name -> page_va
    adrp_pages: Dict[str, int] = {}

    count = 0
    for insn in binary.disasm(fn_va, max_insns * 4):
        count += 1
        if count > max_insns:
            break

        mn  = insn.mnemonic
        pc  = insn.address
        ops = insn.operands if hasattr(insn, 'operands') and insn.operands else []

        # ── RET: end of function ──────────────────────────────────────────
        if mn == 'ret':
            break

        # ── ADRP ──────────────────────────────────────────────────────────
        if mn == 'adrp' and ops:
            w = binary.read32(pc)
            if w:
                page = binary._decode_adrp(w, pc)
                rd = _reg_name(insn, ops[0].reg)
                if page is not None:
                    adrp_pages[rd] = page
                state[rd] = None
            continue

        # ── LDR (from memory) ─────────────────────────────────────────────
        if mn == 'ldr' and ops and len(ops) >= 2:
            rd  = _reg_name(insn, ops[0].reg)
            op1 = ops[1]
            if op1.type == capstone.arm64.ARM64_OP_MEM:
                rn  = _mem_base_name(insn, op1.mem.base)
                off = op1.mem.disp
                if rn and rn in adrp_pages:
                    page = adrp_pages.pop(rn)
                    gv   = _got_lookup(page, off)
                    state[rd] = gv      # GlobalVal or None
                else:
                    state[rd] = None    # dereference → lose precise value
            else:
                state[rd] = None
            adrp_pages.pop(rd, None)
            continue

        # ── ADD ───────────────────────────────────────────────────────────
        if mn == 'add' and ops and len(ops) >= 3:
            rd = _reg_name(insn, ops[0].reg)
            rn = _reg_name(insn, ops[1].reg)
            if ops[2].type == capstone.arm64.ARM64_OP_IMM:
                imm = ops[2].imm
                if rn in adrp_pages:
                    adrp_pages.pop(rn)
                    state[rd] = None    # ADRP+ADD non-GOT: address unknown
                else:
                    state[rd] = _add(state.get(rn), imm)
            else:
                state[rd] = None        # reg+reg: lose track
            adrp_pages.pop(rd, None)
            continue

        # ── SUB ───────────────────────────────────────────────────────────
        if mn == 'sub' and ops and len(ops) >= 3:
            rd = _reg_name(insn, ops[0].reg)
            rn = _reg_name(insn, ops[1].reg)
            if ops[2].type == capstone.arm64.ARM64_OP_IMM:
                state[rd] = _add(state.get(rn), -ops[2].imm)
            else:
                state[rd] = None
            adrp_pages.pop(rd, None)
            continue

        # ── MOV / aliases ─────────────────────────────────────────────────
        if mn in ('mov', 'movz', 'movk', 'movn') and ops and len(ops) >= 2:
            rd = _reg_name(insn, ops[0].reg)
            if ops[1].type == capstone.arm64.ARM64_OP_REG:
                rs       = _reg_name(insn, ops[1].reg)
                state[rd] = state.get(rs)
            else:
                state[rd] = None
            adrp_pages.pop(rd, None)
            continue

        # ── ORR (MOV alias: ORR rd, xzr, rs) ─────────────────────────────
        if mn == 'orr' and ops and len(ops) >= 3:
            rd = _reg_name(insn, ops[0].reg)
            if ops[1].type == capstone.arm64.ARM64_OP_REG:
                rn_name = _reg_name(insn, ops[1].reg)
                if rn_name in ('xzr', 'wzr', 'x31') and ops[2].type == capstone.arm64.ARM64_OP_REG:
                    rs = _reg_name(insn, ops[2].reg)
                    state[rd] = state.get(rs)
                else:
                    state[rd] = None
            else:
                state[rd] = None
            adrp_pages.pop(rd, None)
            continue

        # ── STR / STRB / STRH ────────────────────────────────────────────
        if mn in ('str', 'strb', 'strh') and ops and len(ops) >= 2:
            sz  = {'str': 8, 'strb': 1, 'strh': 2}[mn]
            op1 = ops[1]
            if op1.type == capstone.arm64.ARM64_OP_MEM:
                rn  = _mem_base_name(insn, op1.mem.base)
                off = op1.mem.disp
                _record_store(summary, state.get(rn) if rn else None, off, sz, pc)
            continue

        # ── STP ───────────────────────────────────────────────────────────
        if mn == 'stp' and ops and len(ops) >= 3:
            op2 = ops[2]
            if op2.type == capstone.arm64.ARM64_OP_MEM:
                rn       = _mem_base_name(insn, op2.mem.base)
                off      = op2.mem.disp
                base_val = state.get(rn) if rn else None
                _record_store(summary, base_val, off,     8, pc)
                _record_store(summary, base_val, off + 8, 8, pc)
            continue

        # ── STUR / STURB / STURH ─────────────────────────────────────────
        if mn in ('stur', 'sturb', 'sturh') and ops and len(ops) >= 2:
            sz  = {'stur': 8, 'sturb': 1, 'sturh': 2}[mn]
            op1 = ops[1]
            if op1.type == capstone.arm64.ARM64_OP_MEM:
                rn  = _mem_base_name(insn, op1.mem.base)
                off = op1.mem.disp
                _record_store(summary, state.get(rn) if rn else None, off, sz, pc)
            continue

        # ── BL (direct call) ─────────────────────────────────────────────
        if mn == 'bl' and ops:
            op0 = ops[0]
            if op0.type == capstone.arm64.ARM64_OP_IMM:
                callee_va = op0.imm
                summary.direct_callees.add(callee_va)

                # Record how args / globals flow into callee arg positions x0..x7
                for ci, xname in enumerate(_ARG_REGS):
                    rv = state.get(xname)
                    if rv is None:
                        continue
                    info = _resolve(rv)
                    if info is None:
                        continue
                    kind, key, off = info
                    if kind == 'global':
                        summary.global_to_callee.append((callee_va, key, ci, pc))
                    elif kind == 'arg':
                        summary.arg_to_callee.append((callee_va, key, ci, pc))

                # Clobber caller-saved registers x0-x18, x30
                for rname in _CALLER_SAVED_NAMES:
                    state[rname] = None
                adrp_pages.clear()
            continue

        # ── Default: clobber written destination register ─────────────────
        if ops and ops[0].type == capstone.arm64.ARM64_OP_REG:
            rd = _reg_name(insn, ops[0].reg)
            if rd not in ('xzr', 'sp') and mn not in (
                'str','strb','strh','stp','stur','sturb','sturh','bl','ret'
            ):
                state[rd] = None
                adrp_pages.pop(rd, None)

    summary.insns_scanned = count
    return summary


def _record_store(summary: FuncSummary, base_val: Any, off: int, sz: int, pc: int):
    info = _resolve(base_val)
    if info is None:
        return
    kind, key, base_off = info
    total = base_off + off
    if kind == 'global':
        summary.global_field_writes.append((key, total, pc, sz))
    elif kind == 'arg':
        summary.arg_field_writes.append((key, total, pc, sz))


# ─────────────────────────────────────────────────────────────────────────────
# Inter-procedural worklist driver
# ─────────────────────────────────────────────────────────────────────────────

def find_field_writers(
    binary: Binary,
    target_name: str,
    target_offset: int = -1,   # -1 = any offset
    seed_fn_addrs: Optional[List[int]] = None,
    max_depth: int = 8,
    verbose: bool = False,
) -> List[Dict]:
    """
    Demand-driven inter-procedural search for all write sites of
    `target_name` field `target_offset`.

    Returns list of dicts with keys: fn, pc, field_offset, store_bytes, via, depth.
    """
    target_gv = GlobalVal(target_name, 0)

    # Lazy summary cache
    _summaries: Dict[int, FuncSummary] = {}

    def get_summary(va: int) -> FuncSummary:
        if va not in _summaries:
            if verbose:
                print(f"  [sum] building summary for {va:#010x}")
            _summaries[va] = build_summary(binary, va)
        return _summaries[va]

    # ── Seed discovery ────────────────────────────────────────────────────
    if seed_fn_addrs is None:
        hits = binary.scan_got_loads(target_gv)
        seed_fn_addrs = list({fn for (_, fn) in hits})
        if verbose:
            print(f"[seed] Found {len(hits)} GOT load sites → {len(seed_fn_addrs)} seed functions")
            for load_pc, fn in hits:
                print(f"       GOT load @ {load_pc:#010x}  fn_start={fn:#010x}")

    findings: List[Dict] = []
    # Worklist: (fn_va, mode, key, depth)
    #   mode='global' key=global_name  → fn directly holds the GlobalVal
    #   mode='arg'    key=arg_idx      → fn receives target as arg[key]
    Worklist = List[Tuple[int, str, Any, int]]
    worklist: Worklist = []
    # Visited set to prevent cycles: (fn_va, mode, key)
    visited: Set[Tuple[int, str, Any]] = set()

    def enqueue(fn_va: int, mode: str, key: Any, depth: int):
        item = (fn_va, mode, key)
        if item in visited:
            return
        if depth > max_depth:
            if verbose:
                print(f"  [skip] depth limit at {fn_va:#010x}")
            return
        if fn_va in binary.PLT_STUBS:
            return
        if not binary.in_text(fn_va):
            return
        visited.add(item)
        worklist.append((fn_va, mode, key, depth))

    # Seed entries: functions that directly reference the global
    for fn_va in seed_fn_addrs:
        enqueue(fn_va, 'global', target_name, 0)

    # ── Worklist loop ─────────────────────────────────────────────────────
    while worklist:
        fn_va, mode, key, depth = worklist.pop()
        s = get_summary(fn_va)

        if mode == 'global':
            gname = key
            # Report any direct global field writes
            for (wname, woff, wpc, wsz) in s.global_field_writes:
                if wname == gname:
                    if target_offset < 0 or woff == target_offset:
                        findings.append({
                            'fn':           fn_va,
                            'pc':           wpc,
                            'field_offset': woff,
                            'store_bytes':  wsz,
                            'via':          'direct_global',
                            'depth':        depth,
                        })
            # Propagate: global forwarded to a callee as arg
            for (callee_va, wname, callee_ai, call_pc) in s.global_to_callee:
                if wname == gname:
                    enqueue(callee_va, 'arg', callee_ai, depth + 1)

        elif mode == 'arg':
            caller_ai = key
            # Report any arg-relative field writes for this arg idx
            for (ai, woff, wpc, wsz) in s.arg_field_writes:
                if ai == caller_ai:
                    if target_offset < 0 or woff == target_offset:
                        findings.append({
                            'fn':           fn_va,
                            'pc':           wpc,
                            'field_offset': woff,
                            'store_bytes':  wsz,
                            'via':          f'arg{caller_ai}',
                            'depth':        depth,
                        })
            # Propagate: arg forwarded to callee
            for (callee_va, c_ai, callee_ai, call_pc) in s.arg_to_callee:
                if c_ai == caller_ai:
                    enqueue(callee_va, 'arg', callee_ai, depth + 1)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Demand-driven inter-procedural field-writer finder (ARM64)")
    ap.add_argument('--binary', required=True)
    ap.add_argument('--global', dest='glob', default='mmtls::gILinkKey',
                    help='Target global symbol name')
    ap.add_argument('--offset', type=lambda x: int(x, 0), default=-1,
                    help='Field offset to search for (-1 = any)')
    ap.add_argument('--depth', type=int, default=8,
                    help='Max inter-procedural depth')
    ap.add_argument('--seed', type=lambda x: int(x, 0), action='append', dest='seeds',
                    help='Seed function VA (can repeat; auto-discovered if omitted)')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    print(f"[*] Loading {args.binary}")
    binary = Binary(args.binary)
    off_str = f"{args.offset:#x}" if args.offset >= 0 else 'any'
    print(f"[*] Target: {args.glob!r}  offset={off_str}")

    findings = find_field_writers(
        binary,
        target_name=args.glob,
        target_offset=args.offset,
        seed_fn_addrs=args.seeds,
        max_depth=args.depth,
        verbose=args.verbose,
    )

    print(f"\n[*] {len(findings)} write(s) found\n")
    if not findings:
        print("    (none)")
        return

    # Group by field_offset
    from collections import defaultdict
    by_off: Dict[int, list] = defaultdict(list)
    for f in findings:
        by_off[f['field_offset']].append(f)

    for off in sorted(by_off):
        entries = by_off[off]
        print(f"  field +{off:#06x}  ({len(entries)} write(s)):")
        for e in sorted(entries, key=lambda x: x['pc']):
            print(f"    pc={e['pc']:#010x}  fn={e['fn']:#010x}  "
                  f"sz={e['store_bytes']}B  via={e['via']}  depth={e['depth']}")

    print(f"\n[*] Summary: {len(findings)} total writes across {len(by_off)} field offsets")
    print(f"    Offsets: {[f'+{o:#x}' for o in sorted(by_off)]}")


if __name__ == '__main__':
    main()
