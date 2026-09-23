#!/usr/bin/env python3
"""
vtable_resolver.py — Static vtable reconstruction and BLR resolution for stripped ARM64.

Implements iResolveX-style indirect call resolution (Paper 23: "iResolveX: Resolving
Indirect Calls in Stripped Binaries via Learning-Augmented Static Reasoning"):
  Phase 1 — Candidate vtable extraction from .rodata (runs of ≥N code pointers)
  Phase 2 — Constructor vptr detection (ADRP+ADD+STR pattern → object type assignment)
  Phase 3 — BLR site detection (LDR vptr / LDR slot / BLR sequence)
  Phase 4 — Resolution: map each BLR@slot-k to target set from matching vtable regions

Binary hardcoded default: libwechatnetwork.so (WeChat 8.0.56 ARM64)
  .text   VA 0x000dd130  size 0x002de650
  .rodata VA 0x00032bf0  size 0x00064470

Primary target: BLR at ~0x112050 (fn 0x111f98) — passes &gILinkKey as x1 via unresolved
indirect call. Resolution goal: find vtable + slot for this dispatch.
"""

import argparse
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import capstone
    try:
        import capstone.arm64 as arm64_const
        _ARCH_AARCH64 = capstone.CS_ARCH_ARM64
    except AttributeError:
        import capstone.aarch64 as arm64_const
        _ARCH_AARCH64 = capstone.CS_ARCH_AARCH64
except ImportError:
    print("[!] pip install capstone", file=sys.stderr)
    sys.exit(1)

try:
    import lief
except ImportError:
    print("[!] pip install lief", file=sys.stderr)
    sys.exit(1)

DEFAULT_SO = "/media/cowboy/research/wechat-re/native-libs/lib/arm64-v8a/libwechatnetwork.so"

# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VtableRegion:
    va: int
    slots: List[int]  # code VAs at each slot index

    def __len__(self): return len(self.slots)
    def target_at(self, slot_idx: int) -> Optional[int]:
        return self.slots[slot_idx] if slot_idx < len(self.slots) else None


@dataclass
class CtorVptrInit:
    init_pc: int       # instruction address of STR xV, [x0, #vptr_off]
    vtable_va: int     # address of the vtable in .rodata
    vptr_off: int      # offset into object where vptr is stored (usually 0)


@dataclass
class BLRSite:
    blr_pc: int
    vptr_load_pc: int
    slot_offset: int   # byte offset into vtable (k from LDR xN, [xM, #k])
    resolved_targets: List[int] = field(default_factory=list)
    narrowed: bool = False   # True if narrowed by constructor type info


# ─────────────────────────────────────────────────────────────────────────────
# Capstone helpers — string-based register names, never & 0x1F
# ─────────────────────────────────────────────────────────────────────────────

def _canon(name: str) -> str:
    """Canonicalize w-register names to x-register names."""
    if name.startswith('w') and name[1:].isdigit():
        return 'x' + name[1:]
    return name

def _reg(insn, op) -> str:
    return _canon(insn.reg_name(op.reg))

def _mem_base(insn, op) -> Optional[str]:
    if op.mem.base == 0:
        return None
    name = _canon(insn.reg_name(op.mem.base))
    return None if name in ('xzr', 'sp') else name

def _mem_disp(op) -> int:
    return op.mem.disp


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Vtable candidate extraction via R_AARCH64_RELATIVE relocations
#
# Android ARM64 shared libraries store vtable function pointers as RELATIVE
# relocations in .data.rel.ro (applied at load time: *slot = base + addend).
# The pre-load raw data holds 0 or a stub; the addend carries the target.
# We reconstruct virtual vtables from the relocation table directly.
# ─────────────────────────────────────────────────────────────────────────────

def extract_vtable_regions(binary: lief.ELF.Binary, text_va: int, text_size: int,
                           drelro_va: int, drelro_size: int,
                           min_slots: int = 3) -> List[VtableRegion]:
    text_end = text_va + text_size
    drelro_end = drelro_va + drelro_size

    reloc_map: Dict[int, int] = {}
    for rel in binary.relocations:
        addend = rel.addend if hasattr(rel, 'addend') else 0
        rva = rel.address
        if text_va <= addend < text_end and drelro_va <= rva < drelro_end:
            reloc_map[rva] = addend

    sorted_rvas = sorted(reloc_map.keys())
    if not sorted_rvas:
        return []

    results: List[VtableRegion] = []
    current: List[int] = [sorted_rvas[0]]
    for rva in sorted_rvas[1:]:
        if rva == current[-1] + 8:
            current.append(rva)
        else:
            if len(current) >= min_slots:
                base_va = current[0]
                results.append(VtableRegion(
                    va=base_va,
                    slots=[reloc_map[r] for r in current],
                ))
            current = [rva]
    if len(current) >= min_slots:
        base_va = current[0]
        results.append(VtableRegion(
            va=base_va,
            slots=[reloc_map[r] for r in current],
        ))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Constructor vptr detection
# Pattern: ADRP xV, rodata_page  +  ADD xV, xV, #lo12  +  STR xV, [x0, #off]
# ─────────────────────────────────────────────────────────────────────────────

def detect_ctor_vptr_inits(text_data: bytes, text_va: int, text_size: int,
                            vtable_vas: Set[int],
                            drelro_va: int = 0, drelro_size: int = 0) -> List[CtorVptrInit]:
    cs = capstone.Cs(_ARCH_AARCH64, capstone.CS_MODE_ARM)
    cs.detail = True

    insns = list(cs.disasm(text_data[:text_size], text_va))

    results: List[CtorVptrInit] = []
    n = len(insns)

    # adrp_pages[reg_name] = page_va held by reg at current instruction
    adrp_pages: Dict[str, int] = {}
    # pending_adrp_add[reg_name] = resolved rodata VA (after ADRP+ADD)
    pending_va: Dict[str, int] = {}

    for idx, insn in enumerate(insns):
        mnem = insn.mnemonic

        if mnem == 'adrp':
            ops = insn.operands
            if len(ops) == 2:
                dst = _reg(insn, ops[0])
                page = ops[1].imm & 0xFFFFFFFFFFFFFFFF
                adrp_pages[dst] = page
                pending_va.pop(dst, None)

        elif mnem == 'add' and len(insn.operands) == 3:
            ops = insn.operands
            dst = _reg(insn, ops[0])
            src = _reg(insn, ops[1])
            if (ops[2].type == capstone.arm64.ARM64_OP_IMM and
                    src in adrp_pages):
                imm = ops[2].imm
                addr = adrp_pages[src] + imm
                pending_va[dst] = addr
                if dst != src:
                    adrp_pages.pop(dst, None)

        elif mnem in ('str', 'stur') and len(insn.operands) >= 2:
            ops = insn.operands
            if ops[0].type == capstone.arm64.ARM64_OP_REG:
                src_reg = _reg(insn, ops[0])
                if src_reg in pending_va:
                    vtbl_addr = pending_va[src_reg]
                    if vtbl_addr in vtable_vas:
                        mem_op = ops[1]
                        base = _mem_base(insn, mem_op)
                        disp = _mem_disp(mem_op)
                        if base is not None:
                            results.append(CtorVptrInit(
                                init_pc=insn.address,
                                vtable_va=vtbl_addr,
                                vptr_off=disp,
                            ))

        # clobbers: clear state for any written-to regs not from ADRP
        if mnem not in ('adrp', 'add'):
            for ops in insn.operands:
                if (ops.type == capstone.arm64.ARM64_OP_REG and
                        ops.access & capstone.CS_AC_WRITE):
                    rname = _reg(insn, ops)
                    adrp_pages.pop(rname, None)
                    pending_va.pop(rname, None)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: BLR site detection
# Pattern within a ~8-instruction window before BLR xN:
#   LDR xV, [x0, #vptr_off]     ← vptr load
#   LDR xN, [xV, #k]            ← vtable slot load
#   BLR xN
# ─────────────────────────────────────────────────────────────────────────────

WINDOW = 10  # instructions to look back before BLR

def detect_blr_sites(text_data: bytes, text_va: int, text_size: int) -> List[BLRSite]:
    cs = capstone.Cs(_ARCH_AARCH64, capstone.CS_MODE_ARM)
    cs.detail = True

    insns = list(cs.disasm(text_data[:text_size], text_va))
    results: List[BLRSite] = []

    for idx, insn in enumerate(insns):
        if insn.mnemonic != 'blr':
            continue
        ops = insn.operands
        if not ops:
            continue
        blr_reg = _reg(insn, ops[0])

        # scan backward for slot load: LDR blr_reg, [vtbl_reg, #k]
        slot_load_pc: Optional[int] = None
        slot_offset: Optional[int] = None
        vtbl_reg: Optional[str] = None
        vptr_load_pc: Optional[int] = None

        window_start = max(0, idx - WINDOW)
        for j in range(idx - 1, window_start - 1, -1):
            prev = insns[j]
            if prev.mnemonic not in ('ldr', 'ldur'):
                continue
            pops = prev.operands
            if len(pops) < 2:
                continue
            dst = _reg(prev, pops[0])
            if dst != blr_reg:
                continue
            if pops[1].type != capstone.arm64.ARM64_OP_MEM:
                continue
            base = _mem_base(prev, pops[1])
            disp = _mem_disp(pops[1])
            if base is None or disp < 0:
                continue
            slot_load_pc = prev.address
            slot_offset = disp
            vtbl_reg = base
            break

        if vtbl_reg is None:
            continue

        # scan backward for vptr load: LDR vtbl_reg, [this_reg, #vptr_off]
        for j in range(idx - 1, window_start - 1, -1):
            prev = insns[j]
            if prev.mnemonic not in ('ldr', 'ldur'):
                continue
            pops = prev.operands
            if len(pops) < 2:
                continue
            dst = _reg(prev, pops[0])
            if dst != vtbl_reg:
                continue
            if pops[1].type != capstone.arm64.ARM64_OP_MEM:
                continue
            base = _mem_base(prev, pops[1])
            if base is None:
                continue
            vptr_load_pc = prev.address
            break

        results.append(BLRSite(
            blr_pc=insn.address,
            vptr_load_pc=vptr_load_pc or slot_load_pc,
            slot_offset=slot_offset,
        ))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4: Resolution — map each BLR to target set
# ─────────────────────────────────────────────────────────────────────────────

def resolve_blr_sites(blr_sites: List[BLRSite], vtable_regions: List[VtableRegion],
                      ctor_inits: List[CtorVptrInit]) -> None:
    # Map vtable_va → VtableRegion for fast lookup
    vt_map: Dict[int, VtableRegion] = {vt.va: vt for vt in vtable_regions}

    # Conservative resolution: all vtables that have the slot
    for site in blr_sites:
        slot_idx = site.slot_offset // 8
        targets: List[int] = []
        for vt in vtable_regions:
            t = vt.target_at(slot_idx)
            if t is not None:
                targets.append(t)
        site.resolved_targets = sorted(set(targets))


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="ARM64 vtable resolver (iResolveX-style)")
    ap.add_argument('--so', default=DEFAULT_SO)
    ap.add_argument('--show-vtables', action='store_true')
    ap.add_argument('--blr-pc', type=lambda x: int(x, 0), default=0x112050)
    ap.add_argument('--min-vtable-size', type=int, default=3)
    ap.add_argument('--max-blr-candidates', type=int, default=50,
                    help='Suppress BLR sites with more than N targets (noisy; 0=show all)')
    args = ap.parse_args()

    raw = Path(args.so).read_bytes()
    binary = lief.parse(args.so)
    if binary is None:
        print(f"[!] Failed to parse {args.so}", file=sys.stderr)
        sys.exit(1)

    def _section(name: str):
        for s in binary.sections:
            if s.name == name:
                return s
        return None

    text_sec   = _section('.text')
    rodata_sec = _section('.rodata')

    if text_sec is None or rodata_sec is None:
        print("[!] Could not locate .text or .rodata", file=sys.stderr)
        sys.exit(1)

    text_va   = text_sec.virtual_address
    text_size = text_sec.size
    rodata_va = rodata_sec.virtual_address
    rodata_sz = rodata_sec.size

    # VA == file offset in this binary (no load bias)
    text_data   = raw[text_va   : text_va   + text_size]
    rodata_data = raw[rodata_va : rodata_va + rodata_sz]

    drelro_sec = _section('.data.rel.ro')
    if drelro_sec is None:
        print("[!] Could not locate .data.rel.ro", file=sys.stderr)
        sys.exit(1)
    drelro_va = drelro_sec.virtual_address
    drelro_sz = drelro_sec.size

    print(f"[vtable-resolver] {args.so}")
    print(f"  .text        VA=0x{text_va:08x}  size=0x{text_size:x}")
    print(f"  .rodata      VA=0x{rodata_va:08x}  size=0x{rodata_sz:x}")
    print(f"  .data.rel.ro VA=0x{drelro_va:08x}  size=0x{drelro_sz:x}")
    print()

    # Phase 1
    vtable_regions = extract_vtable_regions(
        binary, text_va, text_size, drelro_va, drelro_sz, args.min_vtable_size)
    print(f"VTABLE REGIONS: {len(vtable_regions)} found (min_slots={args.min_vtable_size})")

    vtable_vas: Set[int] = {vt.va for vt in vtable_regions}

    if args.show_vtables:
        for vt in vtable_regions:
            print(f"  VT@0x{vt.va:08x}  [{len(vt.slots)} slots]  "
                  f"targets: {[f'0x{t:08x}' for t in vt.slots[:4]]}"
                  f"{'...' if len(vt.slots) > 4 else ''}")
    print()

    # Phase 2
    ctor_inits = detect_ctor_vptr_inits(
        text_data, text_va, text_size, vtable_vas, drelro_va, drelro_sz)
    print(f"CTOR VPTR INITS: {len(ctor_inits)} found")
    for ci in ctor_inits[:20]:
        print(f"  pc=0x{ci.init_pc:08x}  vtable=0x{ci.vtable_va:08x}  vptr_off={ci.vptr_off}")
    if len(ctor_inits) > 20:
        print(f"  ... ({len(ctor_inits) - 20} more)")
    print()

    # Phase 3
    blr_sites = detect_blr_sites(text_data, text_va, text_size)
    print(f"BLR SITES: {len(blr_sites)} found")

    # Phase 4
    resolve_blr_sites(blr_sites, vtable_regions, ctor_inits)

    # Print non-noisy sites
    limit = args.max_blr_candidates
    shown = 0
    for site in blr_sites:
        nc = len(site.resolved_targets)
        if limit > 0 and nc > limit:
            continue
        tgts = [f'0x{t:08x}' for t in site.resolved_targets[:6]]
        tstr = '[' + ', '.join(tgts) + (', ...' if nc > 6 else '') + ']'
        print(f"  0x{site.blr_pc:08x}  slot=+0x{site.slot_offset:02x}  "
              f"targets={tstr}  ({nc} candidates)")
        shown += 1
        if shown >= 50:
            print(f"  ... (showing 50 of {len(blr_sites)}, use --max-blr-candidates 0 for all)")
            break
    print()

    # Target BLR
    target = next((s for s in blr_sites if s.blr_pc == args.blr_pc), None)
    if target is None:
        # search near target
        near = sorted(blr_sites, key=lambda s: abs(s.blr_pc - args.blr_pc))
        if near:
            target = near[0]
            print(f"TARGET BLR 0x{args.blr_pc:08x}: not found exactly; "
                  f"nearest is 0x{target.blr_pc:08x} (delta={abs(target.blr_pc - args.blr_pc)})")
        else:
            print(f"TARGET BLR 0x{args.blr_pc:08x}: no BLR sites found at all")
            return
    else:
        print(f"TARGET BLR 0x{args.blr_pc:08x}:")

    print(f"  slot        = +0x{target.slot_offset:02x}  (slot_index={target.slot_offset // 8})")
    print(f"  vptr_load   = 0x{target.vptr_load_pc:08x}")
    print(f"  candidates  = {len(target.resolved_targets)}")
    for t in target.resolved_targets[:20]:
        print(f"    0x{t:08x}")
    if len(target.resolved_targets) > 20:
        print(f"    ... ({len(target.resolved_targets) - 20} more)")

    # Narrow using ctor info: find vtables that are stored as vptr at any
    # construction site, then filter to those whose slot_index is in range
    slot_idx = target.slot_offset // 8
    known_vtable_vas = {ci.vtable_va for ci in ctor_inits}
    narrowed = []
    for vt in vtable_regions:
        if vt.va not in known_vtable_vas:
            continue
        t = vt.target_at(slot_idx)
        if t is not None:
            narrowed.append((vt.va, t))

    if narrowed:
        print(f"\n  NARROWED (ctor-linked vtables only): {len(narrowed)} candidates")
        for vt_va, tgt in narrowed[:20]:
            print(f"    vtable=0x{vt_va:08x}  target=0x{tgt:08x}")
    else:
        print(f"\n  NARROWED: 0 (no ctor inits link to vtable covering slot {slot_idx})")


if __name__ == '__main__':
    main()
