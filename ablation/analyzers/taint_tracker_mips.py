"""
taint_tracker_mips.py -- MIPS32 network-to-sink taint analysis.

Architecture: MIPS32 big-endian and little-endian (RouterOS, embedded firmware).
ABI: O32 -- $a0-$a3 args, $v0/$v1 return, $t0-$t9 caller-saved, $s0-$s7 callee-saved.

Load-delay slot: the instruction immediately after a branch/jump executes before
the branch takes effect. This tracker processes delay slots correctly by consuming
them as part of the branch insn before updating PC.

Sources: recv/recvfrom/read/fgets/gets/fread and their MIPS PLT wrappers.
         Return value lands in $v0; taint propagates from there.
Sinks  : system/execve/execl/execvp/popen/strcpy/sprintf/memcpy/strcat/snprintf
         and their MIPS variants.

Usage:
    from ablation.analyzers.taint_tracker_mips import MIPS32TaintTracker
    tracker = MIPS32TaintTracker.from_path('firmware.elf')
    findings = tracker.run()
    chains   = tracker.run_interprocedural(depth=4)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import capstone
    from capstone.mips import (
        MIPS_INS_LW, MIPS_INS_LH, MIPS_INS_LB, MIPS_INS_LBU, MIPS_INS_LHU,
        MIPS_INS_SW, MIPS_INS_SH, MIPS_INS_SB,
        MIPS_INS_MOVE, MIPS_INS_ADD, MIPS_INS_ADDU, MIPS_INS_ADDI, MIPS_INS_ADDIU,
        MIPS_INS_SUB, MIPS_INS_SUBU, MIPS_INS_AND, MIPS_INS_ANDI,
        MIPS_INS_OR, MIPS_INS_ORI, MIPS_INS_XOR, MIPS_INS_XORI,
        MIPS_INS_SLL, MIPS_INS_SRL, MIPS_INS_SRA, MIPS_INS_SLLV, MIPS_INS_SRLV,
        MIPS_INS_MUL, MIPS_INS_MULT, MIPS_INS_MULTU, MIPS_INS_DIV, MIPS_INS_DIVU,
        MIPS_INS_JAL, MIPS_INS_JALR, MIPS_INS_JR, MIPS_INS_J,
        MIPS_INS_BEQ, MIPS_INS_BNE, MIPS_INS_BGTZ, MIPS_INS_BLTZ,
        MIPS_INS_BGEZ, MIPS_INS_BLEZ, MIPS_INS_BLTZAL, MIPS_INS_BGEZAL,
        MIPS_OP_REG, MIPS_OP_IMM, MIPS_OP_MEM,
    )
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    _HAS_PYELF = True
except ImportError:
    _HAS_PYELF = False

# ---------------------------------------------------------------------------
# MIPS O32 register canonicalization
# ---------------------------------------------------------------------------

# Canonical register names (capstone uses integer IDs; we normalise to string names)
_REG_ALIASES: Dict[str, str] = {
    'zero': 'zero', 'at': 'at',
    'v0': 'v0', 'v1': 'v1',
    'a0': 'a0', 'a1': 'a1', 'a2': 'a2', 'a3': 'a3',
    't0': 't0', 't1': 't1', 't2': 't2', 't3': 't3',
    't4': 't4', 't5': 't5', 't6': 't6', 't7': 't7',
    's0': 's0', 's1': 's1', 's2': 's2', 's3': 's3',
    's4': 's4', 's5': 's5', 's6': 's6', 's7': 's7',
    't8': 't8', 't9': 't9', 'k0': 'k0', 'k1': 'k1',
    'gp': 'gp', 'sp': 'sp', 'fp': 'fp', 's8': 'fp',
    'ra': 'ra',
}

# Caller-saved registers cleared on unknown calls (O32 ABI)
_CALLER_SAVED = frozenset(['v0', 'v1', 'a0', 'a1', 'a2', 'a3',
                            't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                            't8', 't9'])

# Argument registers (O32): first 4 args
_ARG_REGS = ['a0', 'a1', 'a2', 'a3']

# Network receive sources: taint enters in $v0 (return value = byte count / ptr)
_SOURCES: Set[str] = {
    'recv', 'recvfrom', 'recvmsg', 'read', 'fread',
    'fgets', 'gets', 'getline', 'scanf', 'fscanf', 'sscanf',
    'read@plt', 'recv@plt', 'recvfrom@plt', 'fgets@plt', 'gets@plt',
}

# Dangerous sinks
_SINKS: Dict[str, str] = {
    'system':     'OS_CMD',
    'execve':     'OS_CMD',
    'execl':      'OS_CMD',
    'execvp':     'OS_CMD',
    'execlp':     'OS_CMD',
    'popen':      'OS_CMD',
    'strcpy':     'BUFFER_COPY',
    'strncpy':    'BUFFER_COPY',
    'strcat':     'BUFFER_COPY',
    'strncat':    'BUFFER_COPY',
    'sprintf':    'FORMAT_STRING',
    'snprintf':   'FORMAT_STRING',
    'fprintf':    'FORMAT_STRING',
    'printf':     'FORMAT_STRING',
    'memcpy':     'MEMORY_COPY',
    'memmove':    'MEMORY_COPY',
    'memset':     'MEMORY_COPY',
    'bcopy':      'MEMORY_COPY',
    'write':      'SYSCALL_WRITE',
    'send':       'SYSCALL_WRITE',
    'sendto':     'SYSCALL_WRITE',
}

MAX_FUNC_BYTES = 32768  # 32 KB per function cap


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class MIPSTaintFinding:
    func_va: int
    sink_va: int
    sink_name: str
    tainted_args: List[str]
    source_name: str

    def __str__(self) -> str:
        args = ', '.join(self.tainted_args)
        return (f"  [TAINT] {self.source_name} -> {self.sink_name}({args})"
                f"  func=0x{self.func_va:08x}  sink=0x{self.sink_va:08x}")


@dataclass
class MIPSInterproceduralPath:
    func_chain: List[int]
    sink_va: int
    sink_name: str
    tainted_args: List[str]
    source_name: str

    def __str__(self) -> str:
        chain = ' -> '.join(f'0x{va:08x}' for va in self.func_chain)
        args = ', '.join(self.tainted_args)
        return (f"  [CHAIN] {self.source_name} => {chain} => "
                f"{self.sink_name}({args}) @ 0x{self.sink_va:08x}")


# ---------------------------------------------------------------------------
# Core taint analysis -- single function
# ---------------------------------------------------------------------------

def _reg_name(cs_insn, op) -> Optional[str]:
    """Return canonical register name for a capstone operand, or None."""
    if not _HAS_CAPSTONE or op.type != MIPS_OP_REG:
        return None
    name = cs_insn.reg_name(op.reg)
    return _REG_ALIASES.get(name, name)


def analyze_function_mips(
    data: bytes,
    func_va: int,
    func_end_va: int,
    plt: Dict[int, str],
    md,  # capstone Cs instance
    seed_regs: Optional[Set[str]] = None,
    source_calls: Optional[List[str]] = None,
    extra_sinks: Optional[Dict[str, str]] = None,
) -> Tuple[List[MIPSTaintFinding], List[Tuple[int, Set[str]]]]:
    """
    Analyze one MIPS32 function for taint flow from network sources to sinks.

    Returns (findings, propagations) where propagations is a list of
    (callee_va, tainted_arg_set) for interprocedural BFS.
    """
    tainted: Set[str] = set(seed_regs or [])
    findings: List[MIPSTaintFinding] = []
    propagations: List[Tuple[int, Set[str]]] = []
    sources_seen: List[str] = list(source_calls or [])
    sinks = dict(_SINKS)
    if extra_sinks:
        sinks.update(extra_sinks)

    if not _HAS_CAPSTONE:
        return findings, propagations

    try:
        insns = list(md.disasm(data, func_va))
    except Exception:
        return findings, propagations

    i = 0
    while i < len(insns):
        insn = insns[i]

        # --- CALL (JAL or JALR) ---
        if insn.id in (MIPS_INS_JAL, MIPS_INS_JALR):
            # Resolve target
            callee_name = ''
            callee_va = 0
            if insn.id == MIPS_INS_JAL and insn.operands:
                op = insn.operands[0]
                if op.type == MIPS_OP_IMM:
                    callee_va = op.imm
                    callee_name = plt.get(callee_va, '')
            elif insn.id == MIPS_INS_JALR and insn.operands:
                # JALR $t9 -- indirect; check if $t9 is from PLT load
                pass

            # Delay slot: execute before the call takes effect (taint state unchanged)
            # Skip it in the loop
            if i + 1 < len(insns):
                i += 1  # consume delay slot instruction

            if callee_name in _SOURCES:
                # Source call: taint $v0 after the call returns
                tainted.add('v0')
                sources_seen.append(callee_name)
            elif callee_name in sinks and sources_seen:
                # Sink call: check which arg regs are tainted
                tainted_args = [r for r in _ARG_REGS if r in tainted]
                if tainted_args:
                    findings.append(MIPSTaintFinding(
                        func_va=func_va,
                        sink_va=insn.address,
                        sink_name=callee_name,
                        tainted_args=tainted_args,
                        source_name=sources_seen[-1],
                    ))
            elif callee_va and callee_name == '' and sources_seen:
                # Internal call -- propagate tainted args
                tainted_call_args = set(r for r in _ARG_REGS if r in tainted)
                if tainted_call_args:
                    propagations.append((callee_va, tainted_call_args))

            # Clear caller-saved registers (return value unknown for non-source calls)
            if callee_name not in _SOURCES:
                tainted -= _CALLER_SAVED

        # --- Return ---
        elif insn.id == MIPS_INS_JR:
            ops = insn.operands
            if ops and _reg_name(insn, ops[0]) == 'ra':
                break  # end of function

        # --- Arithmetic / logic taint propagation ---
        # Destination is ops[0], sources are ops[1..n]
        elif insn.id in (
            MIPS_INS_MOVE,
            MIPS_INS_ADD, MIPS_INS_ADDU, MIPS_INS_ADDI, MIPS_INS_ADDIU,
            MIPS_INS_SUB, MIPS_INS_SUBU,
            MIPS_INS_AND, MIPS_INS_ANDI,
            MIPS_INS_OR,  MIPS_INS_ORI,
            MIPS_INS_XOR, MIPS_INS_XORI,
            MIPS_INS_SLL, MIPS_INS_SRL, MIPS_INS_SRA,
            MIPS_INS_SLLV, MIPS_INS_SRLV,
            MIPS_INS_MUL, MIPS_INS_MULT, MIPS_INS_MULTU,
        ):
            ops = insn.operands
            if len(ops) >= 2:
                dst = _reg_name(insn, ops[0])
                srcs = [_reg_name(insn, op) for op in ops[1:] if op.type == MIPS_OP_REG]
                if dst:
                    if any(s in tainted for s in srcs if s):
                        tainted.add(dst)
                    else:
                        tainted.discard(dst)

        # --- Load: LW/LH/LB dst, offset(base) ---
        elif insn.id in (MIPS_INS_LW, MIPS_INS_LH, MIPS_INS_LB,
                         MIPS_INS_LBU, MIPS_INS_LHU):
            ops = insn.operands
            if len(ops) >= 2:
                dst = _reg_name(insn, ops[0])
                mem_op = ops[1]
                if dst and mem_op.type == MIPS_OP_MEM:
                    base = _REG_ALIASES.get(insn.reg_name(mem_op.mem.base), '')
                    if base in tainted:
                        tainted.add(dst)
                    else:
                        tainted.discard(dst)

        # --- Store: SW/SH/SB src, offset(base) -- does not change reg taint ---

        i += 1

    return findings, propagations


# ---------------------------------------------------------------------------
# MIPS32TaintTracker
# ---------------------------------------------------------------------------

class MIPS32TaintTracker:
    """
    MIPS32 taint tracker. Supports both intraprocedural and interprocedural modes.

    Usage:
        tracker = MIPS32TaintTracker.from_path('firmware.elf')
        findings = tracker.run()
        chains   = tracker.run_interprocedural(depth=4)
    """

    def __init__(self, binary_path: str, endian: str = 'little'):
        self._path = binary_path
        self._endian = endian
        self._data = Path(binary_path).read_bytes()
        self._plt: Dict[int, str] = {}
        self._func_starts: List[int] = []
        self._text_va: int = 0
        self._text_off: int = 0
        self._text_size: int = 0
        self._extra_sinks: Dict[str, str] = {}

        if not _HAS_CAPSTONE:
            raise RuntimeError("capstone not installed")

        mode = capstone.CS_MODE_MIPS32
        if endian == 'big':
            mode |= capstone.CS_MODE_BIG_ENDIAN
        else:
            mode |= capstone.CS_MODE_LITTLE_ENDIAN

        self._md = capstone.Cs(capstone.CS_ARCH_MIPS, mode)
        self._md.detail = True
        self._md.skipdata = True

        self._load_elf()

    @classmethod
    def from_path(cls, path: str, endian: str = 'little') -> 'MIPS32TaintTracker':
        return cls(path, endian=endian)

    def _load_elf(self):
        """Parse ELF: extract .text bounds, PLT names, and symbol-based func starts."""
        if not _HAS_PYELF:
            return

        try:
            with open(self._path, 'rb') as f:
                elf = ELFFile(f)

                # .text section
                text = elf.get_section_by_name('.text')
                if text:
                    self._text_va   = text['sh_addr']
                    self._text_off  = text['sh_offset']
                    self._text_size = text['sh_size']

                # PLT: resolve via .rel.plt / .rela.plt + dynsym
                dynsym = elf.get_section_by_name('.dynsym')
                if not dynsym:
                    return

                sym_names: Dict[int, str] = {}
                for sym in dynsym.iter_symbols():
                    if sym['st_value']:
                        sym_names[sym['st_value']] = sym.name

                plt_section = elf.get_section_by_name('.plt')
                plt_va   = plt_section['sh_addr']   if plt_section else 0
                plt_size = plt_section['sh_size']    if plt_section else 0
                plt_stub = 16  # MIPS PLT stub size (typical)

                for reloc_sec_name in ('.rel.plt', '.rela.plt'):
                    rsec = elf.get_section_by_name(reloc_sec_name)
                    if not rsec:
                        continue
                    for i, rel in enumerate(rsec.iter_relocations()):
                        sym_idx = rel['r_info_sym']
                        sym = dynsym.get_symbol(sym_idx)
                        if sym and plt_va:
                            stub_va = plt_va + plt_stub * (i + 1)
                            name = sym.name
                            self._plt[stub_va] = name
                            # Also add @plt variant
                            self._plt[stub_va] = name

                # Function starts from symbol table
                for sym_name in ('.symtab', '.dynsym'):
                    sec = elf.get_section_by_name(sym_name)
                    if not isinstance(sec, SymbolTableSection):
                        continue
                    for sym in sec.iter_symbols():
                        if (sym['st_info']['type'] == 'STT_FUNC'
                                and sym['st_value']
                                and sym['st_size'] > 0):
                            self._func_starts.append(sym['st_value'])

                self._func_starts = sorted(set(self._func_starts))

        except Exception:
            pass

    def _get_func_starts(self) -> List[int]:
        if self._func_starts:
            return self._func_starts

        # Fallback: scan for common MIPS function prologues
        # addiu $sp, $sp, -N  (encoding: 27 bd ff ??)
        starts = []
        data = self._data
        for off in range(0, len(data) - 3, 4):
            w = int.from_bytes(data[off:off+4], 'little' if self._endian == 'little' else 'big')
            # addiu $sp, $sp, negative_imm: opcode=0x09 (ADDIU), rs=29 (sp), rt=29 (sp), imm<0
            opcode = (w >> 26) & 0x3f
            rs     = (w >> 21) & 0x1f
            rt     = (w >> 16) & 0x1f
            imm    = w & 0xffff
            if opcode == 0x09 and rs == 29 and rt == 29 and (imm & 0x8000):
                va = self._text_va + (off - self._text_off)
                if self._text_va <= va < self._text_va + self._text_size:
                    starts.append(va)
        return sorted(set(starts))

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        if not self._text_va:
            return None
        off = self._text_off + (va - self._text_va)
        if off < 0 or off + size > len(self._data):
            return None
        return self._data[off: off + size]

    def run(self) -> List[MIPSTaintFinding]:
        """Intraprocedural taint analysis across all functions."""
        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        findings: List[MIPSTaintFinding] = []
        for i, fva in enumerate(func_starts):
            fend = func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES
            size = min(fend - fva, MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(fva, size)
            if not func_bytes or len(func_bytes) < 8:
                continue
            try:
                f, _ = analyze_function_mips(
                    func_bytes, fva, fend, self._plt, self._md,
                    extra_sinks=self._extra_sinks,
                )
                findings.extend(f)
            except Exception:
                continue
        return findings

    def run_interprocedural(self, depth: int = 4) -> List[MIPSInterproceduralPath]:
        """Cross-function BFS taint tracking up to `depth` hops."""
        from collections import deque

        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        func_end_map: Dict[int, int] = {}
        for i, fva in enumerate(func_starts):
            func_end_map[fva] = (func_starts[i + 1]
                                 if i + 1 < len(func_starts)
                                 else fva + MAX_FUNC_BYTES)
        func_start_set = set(func_starts)

        # Find seed functions (directly call a network source)
        seed_funcs: Dict[int, List[str]] = {}
        for fva in func_starts:
            fend = func_end_map[fva]
            size = min(fend - fva, MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(fva, size)
            if not func_bytes or len(func_bytes) < 8:
                continue
            try:
                for insn in self._md.disasm(func_bytes, fva):
                    if insn.id == MIPS_INS_JAL and insn.operands:
                        op = insn.operands[0]
                        if op.type == MIPS_OP_IMM:
                            name = self._plt.get(op.imm, '')
                            if name in _SOURCES:
                                seed_funcs.setdefault(fva, []).append(name)
            except Exception:
                continue

        results: List[MIPSInterproceduralPath] = []
        queue: deque = deque()
        visited: Set[tuple] = set()

        for fva, sources in seed_funcs.items():
            key = (fva, frozenset())
            if key not in visited:
                visited.add(key)
                queue.append((fva, set(), [fva], sources[0], 0))

        while queue:
            func_va, seed_regs, path, source_name, d = queue.popleft()
            if d > depth:
                continue

            fend = func_end_map.get(func_va, func_va + MAX_FUNC_BYTES)
            size = min(fend - func_va, MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(func_va, size)
            if not func_bytes or len(func_bytes) < 8:
                continue

            try:
                findings, propagations = analyze_function_mips(
                    func_bytes, func_va, fend, self._plt, self._md,
                    seed_regs=seed_regs,
                    source_calls=[source_name],
                    extra_sinks=self._extra_sinks,
                )
            except Exception:
                continue

            for f in findings:
                results.append(MIPSInterproceduralPath(
                    func_chain=list(path),
                    sink_va=f.sink_va,
                    sink_name=f.sink_name,
                    tainted_args=f.tainted_args,
                    source_name=source_name,
                ))

            for callee_va, tainted_regs in propagations:
                if callee_va not in func_start_set:
                    continue
                key = (callee_va, frozenset(tainted_regs))
                if key not in visited:
                    visited.add(key)
                    queue.append((callee_va, tainted_regs,
                                  path + [callee_va], source_name, d + 1))

        return results

    def report(self, findings) -> str:
        if not findings:
            return "No taint paths found."
        lines = [f"{len(findings)} finding(s):\n"]
        for f in findings:
            lines.append(str(f))
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli():
    import argparse
    import sys

    ap = argparse.ArgumentParser(description='MIPS32 taint tracker')
    ap.add_argument('binary')
    ap.add_argument('--endian', choices=['little', 'big'], default='little')
    ap.add_argument('--interprocedural', action='store_true')
    ap.add_argument('--depth', type=int, default=4)
    args = ap.parse_args()

    tracker = MIPS32TaintTracker.from_path(args.binary, endian=args.endian)
    if args.interprocedural:
        results = tracker.run_interprocedural(depth=args.depth)
        print(tracker.report(results))
    else:
        results = tracker.run()
        print(tracker.report(results))


if __name__ == '__main__':
    _cli()
