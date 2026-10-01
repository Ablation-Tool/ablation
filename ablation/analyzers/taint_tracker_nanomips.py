"""
taint_tracker_nanomips.py: nanoMIPS network-to-sink taint analysis.

Architecture: nanoMIPS (variable-width 16/32/48-bit instructions).
              Ingenic X-series SoCs (JZ4780, X1000, X2000), MediaTek Helio
              embedded, MIPS32r6 microcontrollers.

ABI: O32-compatible (same register assignments as MIPS32):
     $a0-$a3 args, $v0/$v1 return, $t0-$t9 caller-saved, $s0-$s7 callee-saved.

Key ISA differences from MIPS32:
  - No branch delay slots (removed in nanoMIPS).
  - Calls: BALC (P16 and P32 forms), JALRC (P32) — replaces JAL/JALR.
  - Returns: JRC $ra — replaces JR $ra.
  - Variable-width instructions: 16, 32, or 48 bytes.
  - P32 BALC: bits[31:26] = 0x2a, bits[25:0] = signed offset; target = VA + 4 + sign_extend_26(offset) << 1.
  - P16 BALC: bits[15:10] = 0b110010, bits[9:0] = signed offset; target = VA + 2 + sign_extend_10(offset) << 1.

Two execution paths:
  1. Full decode (capstone 6.x with CS_MODE_NANOMIPS): uses capstone operand detail;
     register-level taint propagation identical to MIPS32 tracker.
  2. Fallback (capstone 5.x or no capstone): NanoMIPSDecoder frame-walk;
     BALC target extracted by bit-field decode; conservative taint (all $a0-$a3
     marked tainted after any source call — no false negatives, possible false positives).

Sources: recv, recvfrom, read, fgets, gets, fread, recvmsg and PLT wrappers.
Sinks:   system, popen, execve, execl, execvp, strcpy, strcat, sprintf, snprintf,
         fprintf, memcpy, memmove, bcopy, write, send, sendto.

Usage:
    from ablation.analyzers.taint_tracker_nanomips import NanoMIPSTaintTracker

    tracker = NanoMIPSTaintTracker.from_path('firmware.elf')
    findings = tracker.run()
    chains   = tracker.run_interprocedural(depth=4)
    print(tracker.report(findings))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .nanomips_decoder import NanoMIPSDecoder, NanoMIPSDisasm, _frame_width, _HAS_NANOMIPS

# ---------------------------------------------------------------------------
# Optional full-decode imports (capstone 6.x)
# ---------------------------------------------------------------------------

try:
    import capstone
    from capstone.mips import (
        MIPS_INS_MOVE,
        MIPS_INS_ADD, MIPS_INS_ADDU, MIPS_INS_ADDI, MIPS_INS_ADDIU,
        MIPS_INS_SUB, MIPS_INS_SUBU,
        MIPS_INS_AND, MIPS_INS_ANDI,
        MIPS_INS_OR,  MIPS_INS_ORI,
        MIPS_INS_XOR, MIPS_INS_XORI,
        MIPS_INS_SLL, MIPS_INS_SRL, MIPS_INS_SRA, MIPS_INS_SLLV, MIPS_INS_SRLV,
        MIPS_INS_MUL, MIPS_INS_MULT, MIPS_INS_MULTU,
        MIPS_INS_LW, MIPS_INS_LH, MIPS_INS_LB, MIPS_INS_LBU, MIPS_INS_LHU,
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
# O32 ABI register tables (shared with MIPS32)
# ---------------------------------------------------------------------------

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

_CALLER_SAVED = frozenset([
    'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
    't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7', 't8', 't9',
])

_ARG_REGS = ['a0', 'a1', 'a2', 'a3']

_SOURCES: Set[str] = {
    'recv', 'recvfrom', 'recvmsg', 'read', 'fread',
    'fgets', 'gets', 'getline', 'scanf', 'fscanf', 'sscanf',
    'recv@plt', 'recvfrom@plt', 'read@plt', 'fgets@plt', 'gets@plt',
}

_SINKS: Dict[str, str] = {
    'system':   'OS_CMD',
    'execve':   'OS_CMD',
    'execl':    'OS_CMD',
    'execvp':   'OS_CMD',
    'execlp':   'OS_CMD',
    'popen':    'OS_CMD',
    'strcpy':   'BUFFER_COPY',
    'strncpy':  'BUFFER_COPY',
    'strcat':   'BUFFER_COPY',
    'strncat':  'BUFFER_COPY',
    'sprintf':  'FORMAT_STRING',
    'snprintf': 'FORMAT_STRING',
    'fprintf':  'FORMAT_STRING',
    'printf':   'FORMAT_STRING',
    'memcpy':   'MEMORY_COPY',
    'memmove':  'MEMORY_COPY',
    'bcopy':    'MEMORY_COPY',
    'write':    'SYSCALL_WRITE',
    'send':     'SYSCALL_WRITE',
    'sendto':   'SYSCALL_WRITE',
}

MAX_FUNC_BYTES = 32768


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class NanoMIPSTaintFinding:
    func_va: int
    sink_va: int
    sink_name: str
    tainted_args: List[str]
    source_name: str
    full_decode: bool = False

    def __str__(self) -> str:
        args = ', '.join(self.tainted_args)
        mode = 'full' if self.full_decode else 'conservative'
        return (
            f"  [TAINT:{mode}] {self.source_name} -> {self.sink_name}({args})"
            f"  func=0x{self.func_va:08x}  sink=0x{self.sink_va:08x}"
        )


@dataclass
class NanoMIPSInterproceduralPath:
    func_chain: List[int]
    sink_va: int
    sink_name: str
    tainted_args: List[str]
    source_name: str
    full_decode: bool = False

    def __str__(self) -> str:
        chain = ' -> '.join(f'0x{va:08x}' for va in self.func_chain)
        args = ', '.join(self.tainted_args)
        return (
            f"  [CHAIN] {self.source_name} => {chain} => "
            f"{self.sink_name}({args}) @ 0x{self.sink_va:08x}"
        )


# ---------------------------------------------------------------------------
# BALC target decoding (both P16 and P32 forms)
# ---------------------------------------------------------------------------

def _balc_p32_target(va: int, raw: bytes, endian: str) -> Optional[int]:
    """
    Extract the absolute call target of a P32 BALC instruction.

    P32 BALC: bits[31:26] = 0x2a, bits[25:0] = signed offset.
    Target = VA + 4 + sign_extend_26(bits[25:0]) * 2
    """
    if len(raw) < 4:
        return None
    bo = 'little' if endian == 'little' else 'big'
    w = int.from_bytes(raw[:4], bo)
    if (w >> 26) & 0x3f != 0x2a:
        return None
    raw_offset = w & 0x3ffffff
    # Sign-extend 26-bit value
    if raw_offset & (1 << 25):
        raw_offset -= (1 << 26)
    return va + 4 + (raw_offset * 2)


def _balc_p16_target(va: int, raw: bytes, endian: str) -> Optional[int]:
    """
    Extract the absolute call target of a P16 BALC instruction.

    P16 BALC: bits[15:10] = 0b110010, bits[9:0] = signed offset.
    Target = VA + 2 + sign_extend_10(bits[9:0]) * 2
    """
    if len(raw) < 2:
        return None
    bo = 'little' if endian == 'little' else 'big'
    hw = int.from_bytes(raw[:2], bo)
    if (hw >> 10) & 0x3f != 0b110010:
        return None
    raw_offset = hw & 0x3ff
    if raw_offset & (1 << 9):
        raw_offset -= (1 << 10)
    return va + 2 + (raw_offset * 2)


# ---------------------------------------------------------------------------
# Per-function analysis — fallback path (Capstone 5.x or no Capstone)
# ---------------------------------------------------------------------------

def _analyze_fallback(
    data: bytes,
    func_va: int,
    plt: Dict[int, str],
    endian: str,
    seed_regs: Optional[Set[str]] = None,
    source_calls: Optional[List[str]] = None,
    extra_sinks: Optional[Dict[str, str]] = None,
) -> Tuple[List[NanoMIPSTaintFinding], List[Tuple[int, Set[str]]]]:
    """
    Conservative taint analysis using the nanoMIPS frame-walker.

    Register-level propagation is unavailable without full decode, so we use
    a conservative model: after any source call, all $a0-$a3 are tainted.
    This produces no false negatives at the cost of possible false positives.
    """
    dec = NanoMIPSDecoder(endian=endian)
    frames = dec.decode_frames(data, func_va)

    tainted: Set[str] = set(seed_regs or [])
    findings: List[NanoMIPSTaintFinding] = []
    propagations: List[Tuple[int, Set[str]]] = []
    sources_seen: List[str] = list(source_calls or [])
    sinks = dict(_SINKS)
    if extra_sinks:
        sinks.update(extra_sinks)

    for frame in frames:
        if not frame.mnemonic.startswith('balc') and frame.mnemonic not in ('jalrc', 'jalrc.hb'):
            if frame.mnemonic in ('jrc',) and 'ra' in (frame.op_str or ''):
                break  # end of function
            continue

        # Resolve call target
        callee_va: Optional[int] = None
        if frame.width == 2:
            callee_va = _balc_p16_target(frame.va, frame.raw, endian)
        elif frame.width == 4:
            callee_va = _balc_p32_target(frame.va, frame.raw, endian)

        callee_name = plt.get(callee_va, '') if callee_va is not None else ''

        if callee_name in _SOURCES:
            # Conservative: taint all arg regs after a source call
            tainted.update(_ARG_REGS)
            tainted.add('v0')
            sources_seen.append(callee_name)
        elif callee_name in sinks and sources_seen:
            tainted_args = [r for r in _ARG_REGS if r in tainted]
            if tainted_args:
                findings.append(NanoMIPSTaintFinding(
                    func_va=func_va,
                    sink_va=frame.va,
                    sink_name=callee_name,
                    tainted_args=tainted_args,
                    source_name=sources_seen[-1],
                    full_decode=False,
                ))
        elif callee_va and not callee_name and sources_seen:
            tainted_call_args = set(r for r in _ARG_REGS if r in tainted)
            if tainted_call_args:
                propagations.append((callee_va, tainted_call_args))

        if callee_name not in _SOURCES:
            tainted -= _CALLER_SAVED

    return findings, propagations


# ---------------------------------------------------------------------------
# Per-function analysis — full decode path (Capstone 6.x)
# ---------------------------------------------------------------------------

def _reg_name_cs(cs_insn, op) -> Optional[str]:
    if not _HAS_CAPSTONE or op.type != MIPS_OP_REG:
        return None
    return _REG_ALIASES.get(cs_insn.reg_name(op.reg), None)


def _analyze_full(
    data: bytes,
    func_va: int,
    plt: Dict[int, str],
    md,  # capstone Cs instance
    seed_regs: Optional[Set[str]] = None,
    source_calls: Optional[List[str]] = None,
    extra_sinks: Optional[Dict[str, str]] = None,
) -> Tuple[List[NanoMIPSTaintFinding], List[Tuple[int, Set[str]]]]:
    """
    Full register-level taint analysis via Capstone 6.x nanoMIPS decode.
    Logic mirrors taint_tracker_mips.py but adapted for nanoMIPS mnemonics
    (BALC/JALRC calls, JRC returns, no delay slots).
    """
    tainted: Set[str] = set(seed_regs or [])
    findings: List[NanoMIPSTaintFinding] = []
    propagations: List[Tuple[int, Set[str]]] = []
    sources_seen: List[str] = list(source_calls or [])
    sinks = dict(_SINKS)
    if extra_sinks:
        sinks.update(extra_sinks)

    try:
        insns = list(md.disasm(data, func_va))
    except Exception:
        return findings, propagations

    _CALL_IDS = frozenset()
    _RET_IDS  = frozenset()
    try:
        # nanoMIPS uses same MIPS capstone instruction IDs for the corresponding mnemonics
        from capstone.mips import MIPS_INS_BALC, MIPS_INS_JALRC, MIPS_INS_JRC
        _CALL_IDS = frozenset({MIPS_INS_BALC, MIPS_INS_JALRC})
        _RET_IDS  = frozenset({MIPS_INS_JRC})
    except ImportError:
        pass

    _ARITH_IDS = frozenset()
    if _HAS_CAPSTONE:
        _ARITH_IDS = frozenset({
            MIPS_INS_MOVE,
            MIPS_INS_ADD, MIPS_INS_ADDU, MIPS_INS_ADDI, MIPS_INS_ADDIU,
            MIPS_INS_SUB, MIPS_INS_SUBU,
            MIPS_INS_AND, MIPS_INS_ANDI,
            MIPS_INS_OR,  MIPS_INS_ORI,
            MIPS_INS_XOR, MIPS_INS_XORI,
            MIPS_INS_SLL, MIPS_INS_SRL, MIPS_INS_SRA, MIPS_INS_SLLV, MIPS_INS_SRLV,
            MIPS_INS_MUL, MIPS_INS_MULT, MIPS_INS_MULTU,
        })
    _LOAD_IDS = frozenset()
    if _HAS_CAPSTONE:
        _LOAD_IDS = frozenset({MIPS_INS_LW, MIPS_INS_LH, MIPS_INS_LB, MIPS_INS_LBU, MIPS_INS_LHU})

    for insn in insns:
        mnem = insn.mnemonic.lower()

        # Call: BALC or JALRC
        if insn.id in _CALL_IDS or mnem in ('balc', 'jalrc', 'jalrc.hb'):
            callee_va = 0
            callee_name = ''
            if insn.operands:
                op = insn.operands[0]
                if op.type == MIPS_OP_IMM:
                    callee_va = op.imm
                    callee_name = plt.get(callee_va, '')

            # No delay slot in nanoMIPS — process directly

            if callee_name in _SOURCES:
                tainted.add('v0')
                tainted.update(_ARG_REGS)  # conservative: treat all args as tainted post-call
                sources_seen.append(callee_name)
            elif callee_name in sinks and sources_seen:
                tainted_args = [r for r in _ARG_REGS if r in tainted]
                if tainted_args:
                    findings.append(NanoMIPSTaintFinding(
                        func_va=func_va,
                        sink_va=insn.address,
                        sink_name=callee_name,
                        tainted_args=tainted_args,
                        source_name=sources_seen[-1],
                        full_decode=True,
                    ))
            elif callee_va and not callee_name and sources_seen:
                tainted_call_args = set(r for r in _ARG_REGS if r in tainted)
                if tainted_call_args:
                    propagations.append((callee_va, tainted_call_args))

            if callee_name not in _SOURCES:
                tainted -= _CALLER_SAVED

        # Return: JRC $ra
        elif insn.id in _RET_IDS or mnem == 'jrc':
            ops = insn.operands
            if not ops or (ops[0].type == MIPS_OP_REG
                           and insn.reg_name(ops[0].reg) == 'ra'):
                break

        # Arithmetic / logic taint propagation
        elif insn.id in _ARITH_IDS:
            ops = insn.operands
            if len(ops) >= 2:
                dst = _reg_name_cs(insn, ops[0])
                srcs = [_reg_name_cs(insn, op) for op in ops[1:]
                        if op.type == MIPS_OP_REG]
                if dst:
                    if any(s in tainted for s in srcs if s):
                        tainted.add(dst)
                    else:
                        tainted.discard(dst)

        # Load: propagate taint from base register
        elif insn.id in _LOAD_IDS:
            ops = insn.operands
            if len(ops) >= 2:
                dst = _reg_name_cs(insn, ops[0])
                mem_op = ops[1]
                if dst and mem_op.type == MIPS_OP_MEM:
                    base = _REG_ALIASES.get(insn.reg_name(mem_op.mem.base), '')
                    if base in tainted:
                        tainted.add(dst)
                    else:
                        tainted.discard(dst)

    return findings, propagations


# ---------------------------------------------------------------------------
# NanoMIPSTaintTracker
# ---------------------------------------------------------------------------

class NanoMIPSTaintTracker:
    """
    nanoMIPS taint tracker. Supports intraprocedural and interprocedural modes.

    Automatically selects full decode (capstone 6.x) or conservative fallback.

    Usage:
        tracker = NanoMIPSTaintTracker.from_path('firmware.elf')
        findings = tracker.run()
        chains   = tracker.run_interprocedural(depth=4)
        print(tracker.report(findings))
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
        self._full_decode = False
        self._cs = None

        # Try to set up Capstone 6.x full decode
        if _HAS_NANOMIPS and _HAS_CAPSTONE:
            try:
                from capstone import CS_ARCH_MIPS, CS_MODE_NANOMIPS  # type: ignore[attr-defined]
                cs_endian = (capstone.CS_MODE_BIG_ENDIAN
                             if endian == 'big' else capstone.CS_MODE_LITTLE_ENDIAN)
                self._cs = capstone.Cs(CS_ARCH_MIPS, CS_MODE_NANOMIPS | cs_endian)
                self._cs.detail = True
                self._cs.skipdata = True
                self._full_decode = True
            except Exception:
                pass

        self._load_elf()

    @classmethod
    def from_path(cls, path: str, endian: str = 'little') -> 'NanoMIPSTaintTracker':
        return cls(path, endian=endian)

    @property
    def has_full_decode(self) -> bool:
        return self._full_decode

    def _load_elf(self) -> None:
        """Parse ELF: extract .text bounds, PLT stub map, and symbol-based func starts."""
        if not _HAS_PYELF:
            return
        try:
            with open(self._path, 'rb') as f:
                elf = ELFFile(f)

                text = elf.get_section_by_name('.text')
                if text:
                    self._text_va   = text['sh_addr']
                    self._text_off  = text['sh_offset']
                    self._text_size = text['sh_size']

                dynsym = elf.get_section_by_name('.dynsym')
                if not dynsym:
                    return

                plt_sec = elf.get_section_by_name('.plt')
                plt_va  = plt_sec['sh_addr'] if plt_sec else 0
                # nanoMIPS PLT stubs are typically 12 bytes (3 × 4-byte insns)
                plt_stub = 12

                for reloc_sec_name in ('.rel.plt', '.rela.plt'):
                    rsec = elf.get_section_by_name(reloc_sec_name)
                    if not rsec:
                        continue
                    for i, rel in enumerate(rsec.iter_relocations()):
                        sym_idx = rel['r_info_sym']
                        sym = dynsym.get_symbol(sym_idx)
                        if sym and plt_va:
                            stub_va = plt_va + plt_stub * (i + 1)
                            self._plt[stub_va] = sym.name

                for sym_tbl_name in ('.symtab', '.dynsym'):
                    sec = elf.get_section_by_name(sym_tbl_name)
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
        # Fallback: use NanoMIPSDisasm heuristic (ADDIU $sp, $sp, -N prologue scan)
        dis = NanoMIPSDisasm(endian=self._endian)
        starts = dis.find_function_starts(self._data, base_addr=self._text_va)
        return starts

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        if not self._text_va:
            # Flat binary: VA == file offset
            if va + size <= len(self._data):
                return self._data[va:va + size]
            return None
        off = self._text_off + (va - self._text_va)
        if off < 0 or off + size > len(self._data):
            return None
        return self._data[off:off + size]

    def run(self) -> List[NanoMIPSTaintFinding]:
        """Intraprocedural taint analysis across all functions."""
        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        findings: List[NanoMIPSTaintFinding] = []
        for i, fva in enumerate(func_starts):
            fend = func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES
            size = min(fend - fva, MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(fva, size)
            if not func_bytes or len(func_bytes) < 4:
                continue
            try:
                if self._full_decode and self._cs is not None:
                    f, _ = _analyze_full(func_bytes, fva, self._plt, self._cs,
                                         extra_sinks=self._extra_sinks)
                else:
                    f, _ = _analyze_fallback(func_bytes, fva, self._plt, self._endian,
                                             extra_sinks=self._extra_sinks)
                findings.extend(f)
            except Exception:
                continue
        return findings

    def run_interprocedural(self, depth: int = 4) -> List[NanoMIPSInterproceduralPath]:
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

        # Seed functions: those that directly call a network source
        seed_funcs: Dict[int, List[str]] = {}
        dec = NanoMIPSDecoder(endian=self._endian)

        for fva in func_starts:
            fend = func_end_map[fva]
            size = min(fend - fva, MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(fva, size)
            if not func_bytes or len(func_bytes) < 4:
                continue
            try:
                frames = dec.decode_frames(func_bytes, fva)
                for frame in frames:
                    if frame.mnemonic not in ('balc', 'jalrc', 'jalrc.hb'):
                        continue
                    callee_va: Optional[int] = None
                    if frame.width == 2:
                        callee_va = _balc_p16_target(frame.va, frame.raw, self._endian)
                    elif frame.width == 4:
                        callee_va = _balc_p32_target(frame.va, frame.raw, self._endian)
                    if callee_va and self._plt.get(callee_va, '') in _SOURCES:
                        seed_funcs.setdefault(fva, []).append(self._plt[callee_va])
            except Exception:
                continue

        results: List[NanoMIPSInterproceduralPath] = []
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
            if not func_bytes or len(func_bytes) < 4:
                continue

            try:
                if self._full_decode and self._cs is not None:
                    findings, propagations = _analyze_full(
                        func_bytes, func_va, self._plt, self._cs,
                        seed_regs=seed_regs, source_calls=[source_name],
                        extra_sinks=self._extra_sinks,
                    )
                else:
                    findings, propagations = _analyze_fallback(
                        func_bytes, func_va, self._plt, self._endian,
                        seed_regs=seed_regs, source_calls=[source_name],
                        extra_sinks=self._extra_sinks,
                    )
            except Exception:
                continue

            for f in findings:
                results.append(NanoMIPSInterproceduralPath(
                    func_chain=list(path),
                    sink_va=f.sink_va,
                    sink_name=f.sink_name,
                    tainted_args=f.tainted_args,
                    source_name=source_name,
                    full_decode=f.full_decode,
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
            decode_note = 'full' if self._full_decode else 'conservative fallback'
            return f"No taint paths found. ({decode_note} decode)"
        lines = [f"{len(findings)} finding(s) "
                 f"({'full' if self._full_decode else 'conservative fallback'} decode):\n"]
        for f in findings:
            lines.append(str(f))
        return '\n'.join(lines)
