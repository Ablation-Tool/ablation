"""
taint_tracker_arc.py: Synopsys DesignWare ARC network-to-sink taint analysis.

Architecture: ARC 700 / ARC HS (ARC EM, HS3x, HS4x, HS5x).
ABI: ARC Linux ABI (GNU toolchain convention):
     r0-r7  argument registers (8 integer args), r0 return value.
     r0-r12 caller-saved (volatile). r13-r25 callee-saved.
     r26 = GP (global pointer), r27 = FP, r28 = SP, r31 = BLINK (LR).
     No branch delay slots.

Prologue: push_s blink        [save return address, compact 16-bit]
          push_s fp           [save frame pointer]
          sub sp, sp, N       [allocate stack frame]
Return:   j_s [blink]         [compact 16-bit return]
          OR j [blink]        [32-bit return]
Call:     bl <target>         [direct call, 25-bit offset]
          jl [reg]            [indirect call via register]

Note: capstone 5.x has no CS_ARCH_ARC. This tracker uses a pure-Python ARC
instruction walker (arc_decoder.ARCDecoder) for control-flow classification
and lief/pyelftools for PLT/symbol extraction. Full instruction-level decode
will be available when capstone 6.x adds ARC support.

Sources: recv/recvfrom/read/fgets/gets/fread -- return value in r0.
Sinks  : system/execve/execl/execvp/popen/strcpy/sprintf/memcpy/strcat/snprintf.

Targets: Synopsys DesignWare ARC EM (IoT/MCU), ARC HS38/HS48 (SMP Linux),
         ARC 770D (multimedia/storage), smart TV SoCs (Marvell, Sigma Designs),
         automotive SoCs, Seagate/Western Digital storage controllers.

Usage:
    from ablation.analyzers.taint_tracker_arc import ARCTaintTracker
    tracker = ARCTaintTracker.from_path('arc_binary')
    findings = tracker.run()
    chains   = tracker.run_interprocedural(depth=4)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from .arc_decoder import ARCDecoder, _BL_MASK, _BL_MATCH, _J_MASK, _J_MATCH, _bl_target

try:
    import lief as _lief
    _HAS_LIEF = True
except ImportError:
    _HAS_LIEF = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    _HAS_PYELF = True
except ImportError:
    _HAS_PYELF = False


# ---------------------------------------------------------------------------
# ARC Linux ABI register model
# ---------------------------------------------------------------------------
#
# r0        : return value + arg 0 (volatile)
# r1-r7     : arg 1-7 (volatile)
# r8-r12    : volatile (scratch, not argument regs in the 8-reg model)
# r13-r25   : callee-saved
# r26       : GP (global pointer) -- callee-saved
# r27       : FP (frame pointer) -- callee-saved
# r28       : SP (stack pointer) -- never tainted
# r29       : ILINK1 (interrupt link 1)
# r30       : ILINK2 / scratch
# r31       : BLINK (branch link = return address)
# ---------------------------------------------------------------------------

_ARG_REGS: List[str] = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7']

_CALLER_SAVED: frozenset = frozenset([
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11', 'r12',
])

_CALLEE_SAVED: frozenset = frozenset([
    'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20',
    'r21', 'r22', 'r23', 'r24', 'r25',
    'r26', 'r27', 'r28',
])

_SOURCES: Set[str] = {
    'recv', 'recvfrom', 'recvmsg', 'read', 'pread',
    'fread', 'fgets', 'gets', 'getenv',
    'recv@plt', 'read@plt', 'fgets@plt', 'recvfrom@plt',
}

_DEFAULT_SINKS: Dict[str, List[int]] = {
    'system':    [0],
    'execv':     [0],
    'execvp':    [0],
    'execve':    [0],
    'popen':     [0],
    'strcpy':    [1],
    'strcat':    [1],
    'sprintf':   [1],
    'snprintf':  [2],
    'memcpy':    [2],
    'memmove':   [2],
    'malloc':    [0],
    'calloc':    [0, 1],
    'realloc':   [1],
}

MAX_FUNC_BYTES = 0x8000


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class TaintFindingARC:
    binary: str
    func_va: int
    func_name: str
    sink_va: int
    sink_name: str
    tainted_args: List[int]
    source_name: str

    def __str__(self) -> str:
        args_str = ', '.join(f'r{i}' for i in self.tainted_args)
        return (f'[ARC-TAINT] {self.func_name} (0x{self.func_va:x})'
                f' -> {self.sink_name}({args_str}) @ 0x{self.sink_va:x}'
                f'  [src: {self.source_name}]')


# ---------------------------------------------------------------------------
# ARCTaintTracker
# ---------------------------------------------------------------------------

class ARCTaintTracker:
    """
    Source-to-sink static taint tracker for ARC ELF binaries.

    ABI: ARC Linux ABI (GNU toolchain). r0-r7 args, r0 return.
    No capstone required -- uses pure-Python ARC instruction walker.

    Usage:
        tracker = ARCTaintTracker.from_path('arc_binary')         # LE default
        findings = tracker.run()
        chains   = tracker.run_interprocedural(depth=4)

    Custom sinks:
        tracker = ARCTaintTracker.from_path('fw', custom_sinks={'arc_exec': [0]})

    From BinaryContext:
        tracker = ARCTaintTracker.from_context(ctx)
    """

    def __init__(
        self,
        binary_path: str,
        ctx=None,
        custom_sinks: Optional[Dict[str, List[int]]] = None,
        endian: str = 'little',
    ):
        self.binary_path = binary_path
        self._ctx = ctx
        self._sinks = dict(_DEFAULT_SINKS)
        if custom_sinks:
            self._sinks.update(custom_sinks)

        self._data = Path(binary_path).read_bytes()
        self._endian = endian
        self._dec = ARCDecoder(endian=endian)
        self._plt: Dict[int, str] = {}
        self._plt_by_name: Dict[str, int] = {}
        self._func_starts: List[int] = []
        self._text_va: int = 0
        self._text_off: int = 0
        self._text_size: int = 0

        self._load_elf()

    @classmethod
    def from_path(cls, path: str, endian: str = 'little', **kwargs) -> 'ARCTaintTracker':
        return cls(path, endian=endian, **kwargs)

    @classmethod
    def from_context(cls, ctx, endian: str = 'little', **kwargs) -> 'ARCTaintTracker':
        return cls(ctx.binary_path, ctx=ctx, endian=endian, **kwargs)

    # ------------------------------------------------------------------
    # ELF loading
    # ------------------------------------------------------------------

    def _load_elf(self) -> None:
        if _HAS_LIEF:
            self._load_lief()
        elif _HAS_PYELF:
            self._load_pyelf()

    def _load_lief(self) -> None:
        try:
            binary = _lief.parse(self.binary_path)
            if not binary:
                return
            for sym in binary.pltgot_relocations:
                if sym.symbol and sym.symbol.name:
                    self._plt[sym.address] = sym.symbol.name
                    self._plt_by_name[sym.symbol.name] = sym.address
            for sym in binary.plt_relocations:
                if sym.symbol and sym.symbol.name:
                    self._plt[sym.address] = sym.symbol.name
                    self._plt_by_name[sym.symbol.name] = sym.address
            starts: Set[int] = set()
            for sym in binary.static_symbols:
                if sym.type == _lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                    starts.add(sym.value)
            for sym in binary.dynamic_symbols:
                if sym.type == _lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                    starts.add(sym.value)
            self._func_starts = sorted(starts)
            for seg in binary.segments:
                if seg.type == _lief.ELF.SEGMENT_TYPES.LOAD and seg.flags & 0x1:
                    self._text_va   = seg.virtual_address
                    self._text_off  = seg.file_offset
                    self._text_size = seg.physical_size
                    break
        except Exception:
            pass

    def _load_pyelf(self) -> None:
        try:
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                text = elf.get_section_by_name('.text')
                if text:
                    self._text_va   = text['sh_addr']
                    self._text_off  = text['sh_offset']
                    self._text_size = text['sh_size']
                dynsym = elf.get_section_by_name('.dynsym')
                if dynsym:
                    plt_sec = elf.get_section_by_name('.plt')
                    plt_va  = plt_sec['sh_addr'] if plt_sec else 0
                    for relname in ('.rela.plt', '.rel.plt'):
                        rsec = elf.get_section_by_name(relname)
                        if not rsec:
                            continue
                        for idx, rel in enumerate(rsec.iter_relocations()):
                            sym = dynsym.get_symbol(rel['r_info_sym'])
                            if sym and plt_va:
                                # ARC PLT stubs are typically 12 or 16 bytes
                                entry_va = plt_va + 12 * (idx + 1)
                                self._plt[entry_va] = sym.name
                                self._plt_by_name[sym.name] = entry_va
                for sname in ('.symtab', '.dynsym'):
                    sec = elf.get_section_by_name(sname)
                    if not isinstance(sec, SymbolTableSection):
                        continue
                    for sym in sec.iter_symbols():
                        if (sym['st_info']['type'] == 'STT_FUNC'
                                and sym['st_value'] and sym['st_size'] > 0):
                            self._func_starts.append(sym['st_value'])
                self._func_starts = sorted(set(self._func_starts))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_func_starts(self) -> List[int]:
        if self._ctx is not None:
            return self._ctx.func_starts
        if self._func_starts:
            return self._func_starts
        # Prologue scan: push_s blink (16-bit compact, hw0 & 0xFF80 == 0xC180)
        # and sub sp,sp,N (32-bit, various encodings) as a secondary signal.
        # Primary: look for 16-bit compact prologue at 2-byte aligned addresses
        # following a ret instruction or gap.
        starts: List[int] = []
        bo = 'little' if self._endian == 'little' else 'big'
        prev_ret = True
        off = 0
        while off < len(self._data) - 1:
            hw0 = int.from_bytes(self._data[off:off+2], bo)
            op5 = (hw0 >> 11) & 0x1f
            width = 2 if op5 >= 0x18 else 4
            if prev_ret:
                # push_s blink pattern (op5 == 0x18 = push group)
                if op5 == 0x18:
                    if self._text_va and self._text_off:
                        va = self._text_va + (off - self._text_off)
                        if self._text_va <= va < self._text_va + self._text_size:
                            starts.append(va)
                    else:
                        starts.append(off)
            # detect return (j_s [blink] pattern)
            if op5 == 0x1f and (hw0 & 0x001F) == 0x001F:
                prev_ret = True
            elif width == 4 and off + 4 <= len(self._data):
                hw1 = int.from_bytes(self._data[off+2:off+4], bo)
                if ((hw0 & _J_MASK) == _J_MATCH
                        and (hw1 & 0x003F) == 0x001F):
                    prev_ret = True
                else:
                    prev_ret = False
            else:
                prev_ret = False
            off += width
        return sorted(set(starts))

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        if not self._text_va:
            return None
        off = self._text_off + (va - self._text_va)
        if off < 0 or off + size > len(self._data):
            return None
        return self._data[off: off + size]

    def _func_name(self, va: int) -> str:
        if self._ctx is not None:
            return self._ctx.name(va)
        return self._plt.get(va, f'0x{va:x}')

    def _plt_name_for_target(self, target_va: int) -> str:
        """
        Resolve a BL target VA to a PLT function name.

        Accepts exact match or target within +/-8 bytes of a PLT stub entry
        (to absorb small offset errors in the _bl_target computation).
        """
        name = self._plt.get(target_va, '')
        if name:
            return name
        for plt_va, plt_name in self._plt.items():
            if abs(target_va - plt_va) <= 8:
                return plt_name
        return ''

    # ------------------------------------------------------------------
    # Taint analysis (function-level, register-call model)
    # ------------------------------------------------------------------

    def _analyze_function(
        self,
        func_va: int,
        func_end_va: int,
        func_bytes: bytes,
        seed_arg_indices: List[int],
    ) -> List[TaintFindingARC]:
        tainted: Dict[str, bool] = {}
        for i in seed_arg_indices:
            if i < len(_ARG_REGS):
                tainted[_ARG_REGS[i]] = True

        findings: List[TaintFindingARC] = []
        func_name = self._func_name(func_va)

        for frame in self._dec.decode_frames(func_bytes, func_va):
            if frame.is_call and frame.target:
                target_name = self._plt_name_for_target(frame.target)

                if target_name in _SOURCES:
                    tainted['r0'] = True

                elif target_name in self._sinks:
                    hit_args = []
                    for ai, areg in enumerate(_ARG_REGS):
                        if ai in self._sinks.get(target_name, []) and tainted.get(areg):
                            hit_args.append(ai)
                    if hit_args:
                        findings.append(TaintFindingARC(
                            binary=self.binary_path,
                            func_va=func_va,
                            func_name=func_name,
                            sink_va=frame.va,
                            sink_name=target_name,
                            tainted_args=hit_args,
                            source_name='recv/arg',
                        ))

                # Clobber caller-saved after call
                for r in _CALLER_SAVED - {'r0'}:
                    tainted[r] = False
                if target_name not in _SOURCES:
                    tainted['r0'] = False

            elif frame.is_ret:
                break

        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_on_function(self, func_va: int, func_end_va: int = 0) -> List[TaintFindingARC]:
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 4:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, [])

    def run_on_function_seeded(
        self, func_va: int, seed_arg_indices: List[int], func_end_va: int = 0
    ) -> List[TaintFindingARC]:
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 4:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, seed_arg_indices)

    def run(self) -> List[TaintFindingARC]:
        func_starts = self._get_func_starts()
        findings: List[TaintFindingARC] = []
        func_end_map = {
            fva: (func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES)
            for i, fva in enumerate(func_starts)
        }
        for fva, fend in func_end_map.items():
            size = min(fend - fva, MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(fva, size)
            if not func_bytes or len(func_bytes) < 4:
                continue
            try:
                findings.extend(self._analyze_function(fva, fend, func_bytes, []))
            except Exception:
                continue
        return findings

    def run_interprocedural(self, depth: int = 4) -> List[TaintFindingARC]:
        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        func_start_set = set(func_starts)
        func_end_map: Dict[int, int] = {
            fva: (func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES)
            for i, fva in enumerate(func_starts)
        }

        # Seed: functions that directly call a network source via BL
        seed_funcs: Dict[int, str] = {}
        for fva in func_starts:
            fend = func_end_map[fva]
            func_bytes = self._va_to_slice(fva, min(fend - fva, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 4:
                continue
            try:
                for frame in self._dec.decode_frames(func_bytes, fva):
                    if frame.is_call and frame.target:
                        name = self._plt_name_for_target(frame.target)
                        if name in _SOURCES:
                            seed_funcs[fva] = name
                            break
            except Exception:
                continue

        results: List[TaintFindingARC] = []
        queue: deque = deque()
        visited: Set[tuple] = set()

        for fva, src_name in seed_funcs.items():
            key = (fva, frozenset())
            if key not in visited:
                visited.add(key)
                queue.append((fva, [], 0, src_name))

        while queue:
            func_va, seed_arg_indices, depth_cur, source_name = queue.popleft()
            if depth_cur > depth:
                continue

            fend = func_end_map.get(func_va, func_va + MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(func_va, min(fend - func_va, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 4:
                continue

            try:
                findings = self._analyze_function(func_va, fend, func_bytes, seed_arg_indices)
            except Exception:
                continue

            results.extend(findings)

            # Propagate tainted args into callees
            try:
                tainted: Dict[str, bool] = {_ARG_REGS[i]: True for i in seed_arg_indices
                                             if i < len(_ARG_REGS)}
                for frame in self._dec.decode_frames(func_bytes, func_va):
                    if frame.is_call and frame.target:
                        callee_va = frame.target
                        if callee_va in func_start_set:
                            tainted_passed = [
                                ai for ai, ar in enumerate(_ARG_REGS)
                                if tainted.get(ar)
                            ]
                            if tainted_passed:
                                key = (callee_va, frozenset(tainted_passed))
                                if key not in visited:
                                    visited.add(key)
                                    queue.append((callee_va, tainted_passed,
                                                  depth_cur + 1, source_name))
                        for r in _CALLER_SAVED:
                            tainted[r] = False
                    elif frame.is_ret:
                        break
            except Exception:
                pass

        return results

    def report(self, findings: List[TaintFindingARC]) -> str:
        if not findings:
            return f'[arc_taint] No findings in {self.binary_path}'
        lines = [f'[arc_taint] {self.binary_path}: {len(findings)} finding(s)']
        for f in findings:
            lines.append(f'  {f}')
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='ARC taint tracker')
    ap.add_argument('binary')
    ap.add_argument('--be', action='store_true', help='big-endian (default: little-endian)')
    ap.add_argument('--interprocedural', action='store_true')
    ap.add_argument('--depth', type=int, default=4)
    args = ap.parse_args()

    tracker = ARCTaintTracker.from_path(args.binary, endian='big' if args.be else 'little')
    if args.interprocedural:
        results = tracker.run_interprocedural(depth=args.depth)
    else:
        results = tracker.run()
    print(tracker.report(results))


if __name__ == '__main__':
    _cli()
