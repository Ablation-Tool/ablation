"""
intoverflow_scanner_arm32.py -- ARM32 integer overflow scanner for allocation sizing.

Detects MUL/UMULL/SMULL instructions whose operands are wire-controlled (traced
to recv/read sources) and whose result flows into an allocation (malloc/calloc/
realloc) without an intervening bounds check.

Architecture:
  1. Scan .text for MUL/UMULL/SMULL/UMLAL/SMLAL instructions.
  2. For each candidate, extract the multiplication site and operand registers.
  3. Use ReachingDefsAnalysis (dataflow_engine) to find definition sites.
  4. Check if any definition site is in a recv/read-calling function (wire-source).
  5. Check if the multiply result (or any register derived from it) reaches a
     malloc/calloc/realloc call without a CMP-based upper-bound check.

This is the ARM32 equivalent of the x86-64 IMUL-from-memory scan that confirmed
the Leptonica Pta and JPEG2000 vulnerabilities in libav.so.new.

Usage:
    from ablation.analyzers.intoverflow_scanner_arm32 import ARM32IntOverflowScanner

    scanner = ARM32IntOverflowScanner.from_context(ctx)
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
from capstone import arm as C_ARM

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False

from ablation.analyzers.dataflow_engine import (
    make_arch, CFGBuilder, ReachingDefsAnalysis, ConstPropAnalysis
)


# ── data classes ─────────────────────────────────────────────────────────────

@dataclass
class IntOverflowFinding32:
    func_va: int
    mul_va: int
    mnemonic: str
    operand_regs: List[str]
    alloc_va: int
    alloc_sym: str
    wire_evidence: str       # what makes operand wire-controlled
    bounds_checked: bool     # True if a CMP guard was detected

    def __str__(self) -> str:
        regs = ', '.join(self.operand_regs)
        checked = " [GUARDED]" if self.bounds_checked else " [UNGUARDED]"
        return (f"INT_OVERFLOW  func=0x{self.func_va:x}  mul@0x{self.mul_va:x}"
                f"  {self.mnemonic}({regs}) -> {self.alloc_sym}@0x{self.alloc_va:x}"
                f"  wire=[{self.wire_evidence}]{checked}")


# ── multiply mnemonics of interest ────────────────────────────────────────────

_MUL_MNEMS = frozenset(['mul', 'muls', 'mla', 'mlas',
                        'umull', 'umulls', 'umlal', 'umlals',
                        'smull', 'smulls', 'smlal', 'smlals'])

_ALLOC_SYMS = frozenset(['malloc', 'calloc', 'realloc',
                         'kmalloc', 'vmalloc', 'kzalloc',
                         '__kmalloc'])

_WIRE_SOURCES = frozenset(['recv', 'recvfrom', 'recvmsg', 'read',
                            'fread', 'pread', 'pread64',
                            'ngx_recv', 'ngx_recv_chain',
                            'SSL_read', 'BIO_read'])


# ── scanner ───────────────────────────────────────────────────────────────────

class ARM32IntOverflowScanner:
    """
    Scans an ARM32 binary for integer overflow in allocation sizing.

    Call flow: scan() -> _find_mul_sites() -> _check_operand_sources() ->
               _find_downstream_alloc() -> IntOverflowFinding32
    """

    def __init__(self, data: bytes, base: int, plt: Dict[int, str],
                 func_starts: List[int], thumb_funcs: Optional[Set[int]] = None):
        self._data = data
        self._base = base
        self._plt = plt
        self._func_starts = func_starts
        self._thumb_funcs: Set[int] = set(thumb_funcs) if thumb_funcs else set()
        self._arch = make_arch('arm32')
        self._cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self._cs.detail = True
        self._cs.skipdata = True
        self._cs_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self._cs_thumb.detail = True
        self._cs_thumb.skipdata = True

    @classmethod
    def from_context(cls, ctx) -> 'ARM32IntOverflowScanner':
        data = Path(ctx.path).read_bytes()
        return cls(data, ctx.base_va, ctx.plt, ctx.func_starts,
                   thumb_funcs=getattr(ctx, 'thumb_funcs', None))

    @classmethod
    def from_path(cls, path: str) -> 'ARM32IntOverflowScanner':
        data = Path(path).read_bytes()
        base = 0
        plt: Dict[int, str] = {}
        func_starts: List[int] = []

        if _LIEF_OK:
            try:
                binary = lief.parse(data)
                if isinstance(binary, lief.ELF.Binary):
                    base = binary.imagebase
                    # PLT from .rel.plt
                    sym_names: List[str] = []
                    try:
                        rel_plt = binary.get_section('.rel.plt')
                        if rel_plt:
                            rel_data = bytes(rel_plt.content)
                            for off in range(0, len(rel_data) - 7, 8):
                                r_offset, r_info = struct.unpack_from('<II', rel_data, off)
                                sym_idx = r_info >> 8
                                try:
                                    sym = binary.dynamic_symbols[sym_idx]
                                    sym_names.append(sym.name or '')
                                except Exception:
                                    sym_names.append('')
                    except Exception:
                        pass
                    if sym_names:
                        plt_sec = binary.get_section('.plt')
                        if plt_sec:
                            plt_va = int(plt_sec.virtual_address)
                            for i, name in enumerate(sym_names):
                                if name:
                                    plt[plt_va + 20 + i * 12] = name
                    # func_starts from exports + eh_frame
                    starts: Set[int] = set()
                    try:
                        for sym in binary.exported_functions:
                            if sym.name and sym.value:
                                starts.add(sym.value)
                    except Exception:
                        pass
                    try:
                        from elftools.elf.elffile import ELFFile
                        from elftools.dwarf.callframe import FDE
                        with open(path, 'rb') as fh:
                            elf = ELFFile(fh)
                            if elf.has_dwarf_info():
                                di = elf.get_dwarf_info()
                                if di.has_EH_CFI():
                                    for e in di.EH_CFI_entries():
                                        if isinstance(e, FDE) and e['initial_location'] > 0:
                                            starts.add(e['initial_location'])
                    except Exception:
                        pass
                    func_starts = sorted(starts)
            except Exception:
                pass

        return cls(data, base, plt, func_starts)

    def _cs_for(self, func_va: int) -> capstone.Cs:
        return self._cs_thumb if func_va in self._thumb_funcs else self._cs

    def func_containing(self, va: int) -> Optional[int]:
        import bisect
        idx = bisect.bisect_right(self._func_starts, va) - 1
        return self._func_starts[idx] if idx >= 0 else None

    def scan(self, max_funcs: int = 10000) -> List[IntOverflowFinding32]:
        findings: List[IntOverflowFinding32] = []
        funcs = self._func_starts[:max_funcs]
        if not funcs:
            return findings

        # Precompute: which functions call wire-source symbols?
        wire_funcs = self._find_wire_source_callers()
        # Precompute: which functions call allocators, and at which VA?
        alloc_sites = self._find_alloc_sites()

        for func_va in funcs:
            mul_sites = list(self._find_mul_sites_in_func(func_va))
            if not mul_sites:
                continue

            for mul_va, mnemonic, op_regs in mul_sites:
                # Check if any operand register has definitions from wire-source functions
                evidence = self._check_operand_wire(func_va, mul_va, op_regs, wire_funcs)
                if not evidence:
                    continue

                # Check for downstream allocation
                alloc_va, alloc_sym = self._find_downstream_alloc(
                    func_va, mul_va, alloc_sites
                )
                if not alloc_va:
                    continue

                # Check for CMP-based guard between mul_va and alloc_va
                guarded = self._has_bounds_check(func_va, mul_va, alloc_va)

                findings.append(IntOverflowFinding32(
                    func_va=func_va,
                    mul_va=mul_va,
                    mnemonic=mnemonic,
                    operand_regs=op_regs,
                    alloc_va=alloc_va,
                    alloc_sym=alloc_sym,
                    wire_evidence=evidence,
                    bounds_checked=guarded,
                ))

        return findings

    def _find_mul_sites_in_func(
        self, func_va: int, max_bytes: int = 4096
    ) -> List[Tuple[int, str, List[str]]]:
        """Yield (mul_va, mnemonic, [operand_regs]) for MUL-family insns."""
        off = func_va - self._base
        if off < 0 or off + max_bytes > len(self._data):
            return
        chunk = self._data[off: off + max_bytes]
        for insn in self._cs_for(func_va).disasm(chunk, func_va):
            mn = insn.mnemonic.lower()
            if mn not in _MUL_MNEMS:
                continue
            op_regs = []
            try:
                for op in insn.operands:
                    if op.type == C_ARM.ARM_OP_REG:
                        op_regs.append(insn.reg_name(op.reg).lower())
            except Exception:
                pass
            # For MUL: rd = rm * rs (ops[0]=rd, ops[1]=rm, ops[2]=rs)
            # For UMULL: rdhi:rdlo = rm * rs (ops[0]=rdlo, ops[1]=rdhi, ops[2]=rm, ops[3]=rs)
            # We want the source operands (not the destination)
            if mn in ('mul', 'muls') and len(op_regs) >= 3:
                yield (insn.address, mn, op_regs[1:3])
            elif mn in ('mla', 'mlas') and len(op_regs) >= 4:
                yield (insn.address, mn, op_regs[1:3])
            elif mn in ('umull', 'umulls', 'smull', 'smulls') and len(op_regs) >= 4:
                yield (insn.address, mn, op_regs[2:4])
            elif mn in ('umlal', 'umlals', 'smlal', 'smlals') and len(op_regs) >= 4:
                yield (insn.address, mn, op_regs[2:4])
            elif op_regs:
                yield (insn.address, mn, op_regs[1:] if len(op_regs) > 1 else op_regs)

    def _find_wire_source_callers(self) -> Set[int]:
        """Return set of function VAs that directly call wire-source symbols."""
        wire_funcs: Set[int] = set()
        plt_by_sym = {sym: va for va, sym in self._plt.items()}
        for func_va in self._func_starts:
            off = func_va - self._base
            if off < 0:
                continue
            chunk = self._data[off: off + 4096]
            for insn in self._cs_for(func_va).disasm(chunk, func_va):
                mn = insn.mnemonic.lower()
                if not (mn.startswith('bl') and not mn.startswith('blx_r')):
                    continue
                try:
                    for op in insn.operands:
                        if op.type == C_ARM.ARM_OP_IMM:
                            sym = self._plt.get(op.imm)
                            if sym and sym in _WIRE_SOURCES:
                                wire_funcs.add(func_va)
                except Exception:
                    pass
                if func_va in wire_funcs:
                    break
        return wire_funcs

    def _find_alloc_sites(self) -> Dict[int, Tuple[int, str]]:
        """Return {func_va: (call_va, alloc_sym)} for functions that call allocators."""
        alloc: Dict[int, Tuple[int, str]] = {}
        for func_va in self._func_starts:
            off = func_va - self._base
            if off < 0:
                continue
            chunk = self._data[off: off + 4096]
            for insn in self._cs_for(func_va).disasm(chunk, func_va):
                mn = insn.mnemonic.lower()
                if not mn.startswith('bl'):
                    continue
                try:
                    for op in insn.operands:
                        if op.type == C_ARM.ARM_OP_IMM:
                            sym = self._plt.get(op.imm)
                            if sym and sym in _ALLOC_SYMS:
                                if func_va not in alloc:
                                    alloc[func_va] = (insn.address, sym)
                except Exception:
                    pass
        return alloc

    def _check_operand_wire(
        self,
        func_va: int,
        mul_va: int,
        op_regs: List[str],
        wire_funcs: Set[int],
    ) -> str:
        """
        Check if any operand register at mul_va has a definition from a call
        to a wire-source function. Returns evidence string or '' if not wire-controlled.
        """
        try:
            rd = ReachingDefsAnalysis(self._data, self._base, arch='arm32')
            mfp_o, _ = rd.solve(func_va)
        except Exception:
            return ''

        # Find block label containing mul_va
        block_label = None
        try:
            cfg_b = CFGBuilder(self._arch, self._data, self._base)
            cfg = cfg_b.build(func_va)
            for lbl, blk in cfg.blocks.items():
                for ins in blk.insns:
                    if ins.address == mul_va:
                        block_label = lbl
                        break
                if block_label is not None:
                    break
        except Exception:
            return ''

        if block_label is None:
            return ''

        for reg in op_regs:
            defs = rd.ud_chain(mfp_o, reg, block_label)
            for def_addr in defs:
                if def_addr is None:
                    continue
                # Check if this definition is a call to a wire source
                off = def_addr - self._base
                if off < 0 or off + 4 > len(self._data):
                    continue
                word = struct.unpack_from('<I', self._data, off)[0]
                # Is this a BL instruction (byte[3] == 0xEB)?
                if (word >> 24) != 0xEB:
                    continue
                imm24 = word & 0xFFFFFF
                if imm24 & 0x800000:
                    imm24 |= 0xFF000000
                imm_s = int(imm24) if imm24 < 0x80000000 else int(imm24) - 0x100000000
                target = def_addr + 8 + imm_s * 4
                sym = self._plt.get(target)
                if sym and sym in _WIRE_SOURCES:
                    return f"{reg} <- {sym}() at 0x{def_addr:x}"
                # Check if target is a wire-calling function
                if target in wire_funcs:
                    return f"{reg} <- wire-caller@0x{target:x} at 0x{def_addr:x}"

        return ''

    def _find_downstream_alloc(
        self,
        func_va: int,
        mul_va: int,
        alloc_sites: Dict[int, Tuple[int, str]],
    ) -> Tuple[int, str]:
        """Return (alloc_call_va, sym) if an alloc call follows mul_va in this function."""
        if func_va not in alloc_sites:
            return (0, '')
        alloc_va, sym = alloc_sites[func_va]
        if alloc_va > mul_va:
            return (alloc_va, sym)
        return (0, '')

    def _has_bounds_check(self, func_va: int, mul_va: int, alloc_va: int) -> bool:
        """Check for a CMP instruction between mul_va and alloc_va."""
        off = mul_va - self._base
        if off < 0:
            return False
        scan_len = max(alloc_va - mul_va + 4, 64)
        chunk = self._data[off: off + scan_len]
        func_va = self.func_containing(mul_va) or mul_va
        for insn in self._cs_for(func_va).disasm(chunk, mul_va):
            if insn.address >= alloc_va:
                break
            mn = insn.mnemonic.lower()
            if mn.startswith(('cmp', 'tst', 'cmn')):
                return True
        return False

    def report(self, findings: List[IntOverflowFinding32]) -> str:
        if not findings:
            return "No ARM32 integer overflow candidates."
        unguarded = [f for f in findings if not f.bounds_checked]
        lines = [
            f"ARM32 Integer Overflow Scan: {len(findings)} candidate(s)"
            f" ({len(unguarded)} unguarded)",
            "=" * 70,
        ]
        for f in findings:
            lines.append(str(f))
        return "\n".join(lines)
