"""
taint_tracker_v850.py: Renesas V850 data-flow taint tracker.

Tracks attacker-controlled data from network/IO sources to dangerous sinks
in V850 ELF binaries. Uses the pure-Python V850Decoder (no capstone needed).

ABI: V850 EABI (GCC default)
  r6-r9:  argument registers (a0-a3) -- 4 regs only
  r10:    return value, caller-saved
  r11-r19: caller-saved temporaries
  r20-r29: callee-saved
  r30:    ep (element pointer), callee-saved
  r31:    lp (link pointer = return address)

Sources: recv/recvfrom/read/fgets/gets/fread (return value in r10)
Sinks:   system/execve/execl/execvp/popen/strcpy/sprintf/snprintf/memcpy/strcat

Targets: Renesas RH850/G3M, RH850/G3MH (automotive ECU, AUTOSAR),
         V850E2R (industrial controller), V850E3V5 (dual-core ASIL-D),
         NEC V850ES/SJ3 (power systems, white goods).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .v850_decoder import V850Decoder, V850Frame

# ---------------------------------------------------------------------------
# ABI constants
# ---------------------------------------------------------------------------

# Argument registers: r6-r9 (only 4, unlike most other ABIs)
_ARG_REGS: List[str] = ['r6', 'r7', 'r8', 'r9']

# Return value register
_RET_REG: str = 'r10'

# Caller-saved (clobbered by callees): r6-r19 + r10 + r1 (assembler temp)
_CALLER_SAVED: frozenset = frozenset([
    'r1', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10',
    'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19',
])

# Callee-saved: r20-r30 + r2 (tp) + r3 (gp) -- preserved across calls
_CALLEE_SAVED: frozenset = frozenset([
    'r2', 'r3', 'r4',
    'r20', 'r21', 'r22', 'r23', 'r24', 'r25', 'r26', 'r27',
    'r28', 'r29', 'r30',
])

# Sources: functions whose return value (r10) we trust as attacker-controlled
_SOURCE_NAMES: frozenset = frozenset({
    'recv', 'recvfrom', 'recvmsg', 'read', 'fread',
    'fgets', 'gets', 'getchar', 'fgetc',
})

# Sinks: dangerous functions; tainted r6 (first arg) = finding
_SINK_NAMES: frozenset = frozenset({
    'system', 'execve', 'execl', 'execvp', 'execle', 'execvpe', 'popen',
    'strcpy', 'strcat', 'sprintf', 'vsprintf', 'snprintf', 'vsnprintf',
    'memcpy', 'memmove', 'gets',
})

# PLT tolerance: how far past a jarl target we accept as "same call"
_PLT_TOL = 16


# ---------------------------------------------------------------------------
# Finding record
# ---------------------------------------------------------------------------

@dataclass
class TaintFindingV850:
    func_va:      int
    func_name:    str
    sink_va:      int
    sink_name:    str
    tainted_args: List[str]
    source_name:  str
    severity:     str = 'HIGH'

    def __str__(self) -> str:
        args = ', '.join(self.tainted_args)
        return (f'[{self.severity}] 0x{self.func_va:x} ({self.func_name}): '
                f'tainted {{{args}}} -> {self.sink_name} @ 0x{self.sink_va:x} '
                f'(source: {self.source_name})')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _name_at(symbols: Dict[int, str], va: int, tol: int = _PLT_TOL) -> Optional[str]:
    if va in symbols:
        return symbols[va]
    for off in range(0, tol + 1, 2):
        if va + off in symbols:
            return symbols[va + off]
        if va - off in symbols:
            return symbols[va - off]
    return None


def _load_elf(path: str):
    """Return (data, base_va, text_start, text_end, symbols, endian)."""
    try:
        import lief
        elf = lief.parse(path)
        if elf is None:
            raise ValueError(f"lief: cannot parse {path}")
        endian = 'little' if elf.header.identity_data == lief.ELF.ELF_DATA.LSB else 'big'
        data = Path(path).read_bytes()
        text = elf.get_section('.text')
        if text:
            text_start = text.virtual_address
            text_end   = text_start + text.size
            base_va    = text.virtual_address - text.offset
        else:
            base_va    = 0
            text_start = 0
            text_end   = len(data)
        syms: Dict[int, str] = {}
        for sym in elf.symbols:
            if sym.name and sym.value:
                syms[sym.value] = sym.name
        return data, base_va, text_start, text_end, syms, endian
    except ImportError:
        pass

    # pyelftools fallback
    from elftools.elf.elffile import ELFFile
    data = Path(path).read_bytes()
    ef = ELFFile(open(path, 'rb'))
    endian = 'little' if ef.little_endian else 'big'
    text_sh = ef.get_section_by_name('.text')
    if text_sh:
        text_start = text_sh['sh_addr']
        text_end   = text_start + text_sh['sh_size']
        base_va    = text_sh['sh_addr'] - text_sh['sh_offset']
    else:
        base_va = text_start = text_end = 0
        text_end = len(data)
    syms: Dict[int, str] = {}
    for sec in ef.iter_sections():
        if sec.name in ('.symtab', '.dynsym'):
            for sym in sec.iter_symbols():
                if sym.name and sym['st_value']:
                    syms[sym['st_value']] = sym.name
    return data, base_va, text_start, text_end, syms, endian


# ---------------------------------------------------------------------------
# Taint engine
# ---------------------------------------------------------------------------

class V850TaintTracker:
    """
    Intraprocedural + interprocedural taint tracker for V850 ELF binaries.

    Taint model:
      - Sources: return value of recv/read/fgets/etc. lands in r10
      - After a source call, r10 is tainted; caller copies to r6-r9 for next call
      - Sinks: if r6 (or r7-r9 for multi-arg sinks) is tainted at a sink JARL, report it
      - Callee-saved registers (r20-r30) are preserved across calls
      - Caller-saved registers (r6-r19) are clobbered after any call

    Instruction coverage:
      - JARL lp / JR: call / branch (from decoder)
      - JMP [lp]: return
      - MOV reg1, reg2: copy propagation (op6=0x00, Format I)
      - MOVEA imm16, reg1, reg2: immediate-to-reg (clears taint)
      - MOVHI imm16, reg1, reg2: immediate-to-reg (clears taint)
      - ADD/SUB/MUL/DIVH: arithmetic propagates taint from operands
      - SLD.W/SLD.H/SLD.B: load clears taint (memory not tracked)
      - ST.W/ST.H/ST.B: store (no effect on register taint)
    """

    def __init__(self, data: bytes, base_va: int, text_start: int, text_end: int,
                 symbols: Dict[int, str], endian: str = 'little'):
        self._data       = data
        self._base_va    = base_va
        self._text_start = text_start
        self._text_end   = text_end
        self._syms       = symbols
        self._dec        = V850Decoder(endian=endian)
        self._frames_by_va: Optional[Dict[int, V850Frame]] = None

    @classmethod
    def from_path(cls, path: str) -> 'V850TaintTracker':
        data, base_va, text_start, text_end, syms, endian = _load_elf(path)
        return cls(data, base_va, text_start, text_end, syms, endian)

    # ---- frame cache -------------------------------------------------------

    def _ensure_frames(self) -> Dict[int, V850Frame]:
        if self._frames_by_va is not None:
            return self._frames_by_va
        offset = self._text_start - self._base_va
        length = self._text_end - self._text_start
        snippet = self._data[offset:offset + length]
        frames = self._dec.decode_frames(snippet, self._text_start)
        self._frames_by_va = {f.va: f for f in frames}
        return self._frames_by_va

    # ---- function-start heuristic -----------------------------------------

    def _get_func_starts(self) -> List[int]:
        """PREPARE instruction marks a function start in V850 GCC output."""
        fv = self._ensure_frames()
        # Collect PREPARE positions and any ELF symbol addresses in text range
        starts: Set[int] = set()
        for va, f in fv.items():
            if f.mnemonic == 'prepare':
                starts.add(va)
        for va, nm in self._syms.items():
            if self._text_start <= va < self._text_end:
                starts.add(va)
        if not starts:
            starts.add(self._text_start)
        return sorted(starts)

    # ---- taint execution model ---------------------------------------------

    def _exec_insn(self, frame: V850Frame, taint: Set[str]) -> Set[str]:
        """Update taint set based on V850 instruction semantics."""
        hw0 = frame.hw0
        op6 = (hw0 >> 5) & 0x3F
        reg2_idx = hw0 & 0x1F
        reg1_idx = (hw0 >> 11) & 0x1F
        dst = f'r{reg2_idx}'
        src = f'r{reg1_idx}'

        # Format I: MOV reg1, reg2 (op6=0x00, reg2 is destination)
        if op6 == 0x00:
            if src in taint:
                taint.add(dst)
            elif dst in taint:
                taint.discard(dst)
            return taint

        # Format II: immediate operations (op6 in 0x08-0x0F): clears taint on dst
        # Includes: MOVEA/MOVHI/ADDI/ORI/ANDI/XORI pattern
        if 0x08 <= op6 <= 0x0F:
            taint.discard(dst)
            return taint

        # Format I arithmetic (op6 in 0x01-0x07): ADD/SUB/MULH/DIVH/CMP/SATADD
        if 0x01 <= op6 <= 0x07:
            if src in taint:
                taint.add(dst)
            return taint

        # Format IX load instructions (op6 >= 0x30 range, various SLD/SLD.W)
        # Loads from memory clear taint (memory not tracked)
        # op6 in 0x18-0x1B are short load (SLD.B/SLD.H/SLD.W/SLD.BU/SLD.HU)
        if op6 in (0x18, 0x19, 0x1A, 0x1B):
            taint.discard(dst)
            return taint

        # 32-bit load patterns (op6 >= 0x20): all loads from memory clear dst taint
        if op6 >= 0x20:
            # Loads: LD.B/LD.H/LD.W/LD.BU/LD.HU
            # Store: ST.B/ST.H/ST.W -- no register destination, skip
            # JARL/JR: handled by call/ret logic in caller, not here
            # PREPARE/DISPOSE: not register ops
            mnem = frame.mnemonic
            if mnem.startswith('ld.') or mnem.startswith('sld.'):
                taint.discard(dst)
            # arithmetic 32-bit extended: taint propagates
            # (op6=0x3C/0x3D mul/div families) -- leave taint unchanged

        return taint

    # ---- intraprocedural scan ---------------------------------------------

    def _scan_func(self, func_va: int, func_end: int,
                   initial_taint: Optional[Set[str]] = None
                   ) -> List[TaintFindingV850]:
        fv = self._ensure_frames()
        taint: Set[str] = set(initial_taint) if initial_taint else set()
        findings: List[TaintFindingV850] = []
        func_name = self._syms.get(func_va, f'fn_0x{func_va:x}')

        va = func_va
        while va < func_end:
            frame = fv.get(va)
            if frame is None:
                va += 2
                continue

            # ---- call instruction ----------------------------------------
            if frame.is_call and frame.target:
                callee_name = _name_at(self._syms, frame.target)

                if callee_name in _SOURCE_NAMES:
                    # Clobber caller-saved, mark r10 tainted after source call
                    taint -= _CALLER_SAVED
                    taint.add(_RET_REG)

                elif callee_name in _SINK_NAMES:
                    # Report if any arg register is tainted
                    tainted_args = [r for r in _ARG_REGS if r in taint]
                    if tainted_args:
                        sev = 'CRITICAL' if callee_name in (
                            'system', 'execve', 'execl', 'execvp', 'popen') else 'HIGH'
                        source = (next((r for r in _ARG_REGS if r in taint), 'r10'))
                        findings.append(TaintFindingV850(
                            func_va=func_va, func_name=func_name,
                            sink_va=va, sink_name=callee_name,
                            tainted_args=tainted_args,
                            source_name=source, severity=sev,
                        ))
                    # Clobber caller-saved after sink call
                    taint -= _CALLER_SAVED

                else:
                    # Unknown callee: clobber caller-saved, r10 unknown
                    taint -= _CALLER_SAVED

            elif frame.is_ret:
                break

            else:
                taint = self._exec_insn(frame, taint)

            va += frame.width

        return findings

    # ---- public API -------------------------------------------------------

    def run(self) -> List[TaintFindingV850]:
        """Intraprocedural scan: each function scanned independently."""
        starts = self._get_func_starts()
        starts_set = set(starts)
        findings: List[TaintFindingV850] = []
        for i, fva in enumerate(starts):
            fend = starts[i + 1] if i + 1 < len(starts) else self._text_end
            findings.extend(self._scan_func(fva, fend))
        return findings

    def run_interprocedural(self, depth: int = 4) -> List[TaintFindingV850]:
        """
        Interprocedural BFS: follow tainted r6-r9 from callers into callees.

        When a call site has tainted argument registers, re-scan the callee
        with those registers pre-tainted (simulating passed taint).
        BFS depth limits transitive propagation.
        """
        starts    = self._get_func_starts()
        starts_set = set(starts)
        func_end: Dict[int, int] = {}
        for i, fva in enumerate(starts):
            func_end[fva] = starts[i + 1] if i + 1 < len(starts) else self._text_end

        findings:  List[TaintFindingV850] = []
        queue:     List[Tuple[int, int, Set[str]]] = []  # (func_va, depth, initial_taint)
        visited:   Dict[Tuple[int, ...], int]      = {}  # (func_va, *sorted_taint) -> depth

        # Seed: scan all functions, collect calls where r10 is tainted at call site
        for fva in starts:
            queue.append((fva, depth, set()))

        while queue:
            fva, d, init_taint = queue.pop(0)
            key = (fva,) + tuple(sorted(init_taint))
            if visited.get(key, -1) >= d:
                continue
            visited[key] = d

            fend = func_end.get(fva, self._text_end)
            fv   = self._ensure_frames()
            taint: Set[str] = set(init_taint)
            func_name = self._syms.get(fva, f'fn_0x{fva:x}')
            va   = fva

            while va < fend:
                frame = fv.get(va)
                if frame is None:
                    va += 2
                    continue

                if frame.is_call and frame.target:
                    callee_va   = frame.target
                    callee_name = _name_at(self._syms, callee_va)

                    if callee_name in _SOURCE_NAMES:
                        taint -= _CALLER_SAVED
                        taint.add(_RET_REG)

                    elif callee_name in _SINK_NAMES:
                        tainted_args = [r for r in _ARG_REGS if r in taint]
                        if tainted_args:
                            sev = 'CRITICAL' if callee_name in (
                                'system', 'execve', 'execl', 'execvp', 'popen') else 'HIGH'
                            source = tainted_args[0]
                            findings.append(TaintFindingV850(
                                func_va=fva, func_name=func_name,
                                sink_va=va, sink_name=callee_name,
                                tainted_args=tainted_args,
                                source_name=source, severity=sev,
                            ))
                        taint -= _CALLER_SAVED

                    else:
                        # BFS: if arg regs are tainted, schedule callee
                        if d > 0:
                            tainted_args_into = [r for r in _ARG_REGS if r in taint]
                            if tainted_args_into:
                                # Map r6-r9 -> callee's r6-r9 (same registers, V850 EABI)
                                callee_init = {r for r in tainted_args_into}
                                # Look for callee in starts
                                c_va = callee_va
                                # Tolerate PLT stub offset
                                for off in range(0, _PLT_TOL + 1, 2):
                                    if c_va + off in func_end:
                                        c_va = c_va + off
                                        break
                                    if c_va - off in func_end and c_va - off >= 0:
                                        c_va = c_va - off
                                        break
                                if c_va in func_end:
                                    queue.append((c_va, d - 1, callee_init))
                        taint -= _CALLER_SAVED

                elif frame.is_ret:
                    break
                else:
                    taint = self._exec_insn(frame, taint)

                va += frame.width

        # Deduplicate
        seen: Set[Tuple] = set()
        unique: List[TaintFindingV850] = []
        for f in findings:
            key = (f.func_va, f.sink_va, f.sink_name)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def report(self, findings: List[TaintFindingV850]) -> str:
        if not findings:
            return "V850 taint: no findings."
        lines = [f"V850 taint: {len(findings)} finding(s)\n"]
        for f in sorted(findings, key=lambda x: (x.func_va, x.sink_va)):
            lines.append(str(f))
        return '\n'.join(lines)
