"""
taint_tracker_rh850.py: GHS CC-RH / IAR RH850 ABI taint tracker.

Extends V850TaintTracker with three additions that the V850 tracker lacks:

  1. from_bytes / scan_function — flat ROM support for ECU firmware dumps
     (V850TaintTracker requires a well-formed ELF; automotive RH850 ROMs
     frequently ship without ELF headers).

  2. double_is_32bit flag — GHS CC-RH / IAR RH850 default is double=32-bit
     (§2.7 of GHS-RE-REFERENCE.md). A 32-bit double occupies ONE arg register
     (R6 or R7 or R8 or R9), not a pair. V850TaintTracker models the GCC ABI
     where double=64-bit and occupies a register pair (R6:R7). Without this
     flag, callers with double arguments show wrong register consumption:
     what looks like "R7 is second half of a double" is actually an independent
     scalar argument.

  3. GHS old-style symbol normalisation — GHS MULTI uses GCC 2.9.x mangling:
     constructors are ``Foo__ct``, destructors ``Foo__dt``, vtables ``__vtbl``.
     V850TaintTracker's source/sink resolver does not strip Renesas assembler
     underscore prefixes or recognise __ct / __dt patterns, so GHS-compiled
     constructor calls appear as anonymous call sites and are not matched
     against sink tables.

ABI: GHS CC-RH / IAR RH850 (GHS-RE-REFERENCE.md §2.2-2.4)
  Arg registers:   R6, R7, R8, R9
  Return register: R10 (scalar / pointer 32-bit), R10:R11 (64-bit)
  Link register:   R31 = LP
  Stack pointer:   R3 = SP
  Caller-saved:    R1, R6-R19, LP
  Callee-saved:    R2, R4 (GP), R5 (TP), R20-R29, EP (R30)

double type note (§2.7):
  Default: double = 32 bits (IEC 60559 single). Set double_is_32bit=False
  if the firmware was compiled with --double=64 (uncommon in ECU targets).

Targets: Denso RH850/G3M, Bosch GS327, Renesas R-Car E2 (R-Car D3/M3/H3 ECU).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, FrozenSet, List, Optional, Set, Tuple

from .isa_v850 import ARG_REGS, CALLER_SAVED, RET_REGS, Variant
from .taint_tracker_v850 import (
    CLEAN, Taint, TaintFindingV850, TaintEngine, V850TaintTracker,
    _load_elf, _name_at, _PLT_TOL, _SOURCE_NAMES, _SINK_NAMES,
)

Labels = FrozenSet[str]
EMPTY: Labels = frozenset()

_GHS_CRITICAL_SINKS = frozenset({
    'system', 'execve', 'execl', 'execvp', 'popen',
})


# ---------------------------------------------------------------------------
# GHS symbol normaliser
# ---------------------------------------------------------------------------

def _ghs_strip_underscore(name: str) -> str:
    """Renesas assembler prepends '_' to every C symbol (§2.10). Strip it."""
    return name[1:] if name.startswith('_') and not name.startswith('__') else name


def _ghs_c_name(name: str) -> str:
    """
    Return the C-level name for a GHS MULTI mangled symbol.

    Handles old GCC 2.9.x patterns:
    - ``Foo__ctXXX``  → ``Foo``  (constructor)
    - ``Foo__dtXXX``  → ``Foo``  (destructor)
    - ``__vtblFoo``   → ``Foo``  (vtable; rarely a call target)
    - ``_foo``        → ``foo``  (Renesas assembler leading underscore)
    - anything else   → unchanged

    Used to match source/sink names against C-level function names.
    """
    n = _ghs_strip_underscore(name)
    # Old-style constructor: Foo__ctN or Foo__ct (no trailing type code)
    ct_idx = n.find('__ct')
    if ct_idx > 0:
        return n[:ct_idx]
    # Old-style destructor
    dt_idx = n.find('__dt')
    if dt_idx > 0:
        return n[:dt_idx]
    # vtable pointer symbol
    if n.startswith('__vtbl'):
        return n[6:]
    return n


def _ghs_name_in(name: str, name_set: FrozenSet[str]) -> bool:
    """True if `name` or its GHS-normalised C name is in `name_set`."""
    return name in name_set or _ghs_c_name(name) in name_set


# ---------------------------------------------------------------------------
# TaintFindingRH850
# ---------------------------------------------------------------------------

@dataclass
class TaintFindingRH850:
    """Taint finding from RH850 source-to-sink scan."""
    func_va:         int
    func_name:       str
    sink_va:         int
    sink_name:       str
    tainted_args:    List[str]
    source_name:     str
    severity:        str = 'HIGH'
    double_is_32bit: bool = True  # GHS CC-RH default

    @classmethod
    def from_v850(cls, f: TaintFindingV850,
                  double_is_32bit: bool = True) -> 'TaintFindingRH850':
        return cls(
            func_va=f.func_va, func_name=f.func_name,
            sink_va=f.sink_va, sink_name=f.sink_name,
            tainted_args=list(f.tainted_args),
            source_name=f.source_name, severity=f.severity,
            double_is_32bit=double_is_32bit,
        )

    def __str__(self) -> str:
        args = ', '.join(self.tainted_args)
        dbl  = ' [double=32b]' if self.double_is_32bit else ' [double=64b]'
        return (
            f'[{self.severity}] 0x{self.func_va:x} ({self.func_name}): '
            f'tainted {{{args}}} -> {self.sink_name} @ 0x{self.sink_va:x} '
            f'(source: {self.source_name}){dbl}'
        )


# ---------------------------------------------------------------------------
# RH850TaintTracker
# ---------------------------------------------------------------------------

class RH850TaintTracker(V850TaintTracker):
    """
    GHS CC-RH / IAR RH850 ABI taint tracker.

    Extends V850TaintTracker with flat-ROM support, GHS double=32-bit ABI
    modelling, and GHS old-style symbol normalisation.

    Flat ROM usage (ECU firmware dump)::

        tracker = RH850TaintTracker.from_bytes(data, base_va=0x0)
        findings = tracker.scan_function(func_va, func_end,
                                         init_labels={'can_payload'})
        print(tracker.report(findings))

    ELF usage::

        tracker = RH850TaintTracker.from_path('firmware.elf')
        findings = tracker.run()
        chains   = tracker.run_interprocedural(depth=4)
    """

    def __init__(
        self,
        data:            bytes,
        base_va:         int,
        text_start:      int,
        text_end:        int,
        symbols:         Dict[int, str],
        endian:          str  = 'little',
        double_is_32bit: bool = True,
    ) -> None:
        super().__init__(
            data, base_va, text_start, text_end, symbols, endian,
            variant=Variant.RH850,
        )
        self._double_is_32bit = double_is_32bit

    # -- constructors ---------------------------------------------------------

    @classmethod
    def from_path(cls, path: str,                   # type: ignore[override]
                  double_is_32bit: bool = True) -> 'RH850TaintTracker':
        """Create from an RH850 ELF binary (requires lief or pyelftools)."""
        data, base_va, text_start, text_end, syms, endian = _load_elf(path)
        return cls(data, base_va, text_start, text_end, syms, endian,
                   double_is_32bit)

    @classmethod
    def from_bytes(cls, data: bytes, base_va: int = 0x0,
                   double_is_32bit: bool = True) -> 'RH850TaintTracker':
        """
        Create from a flat ROM dump.

        ``base_va`` is the load address of the first byte.  Caller must supply
        function boundaries to ``scan_function``; the ``run()`` API works only
        when symbols are present.
        """
        return cls(data, base_va, base_va, base_va + len(data), {},
                   'little', double_is_32bit)

    # -- flat-ROM API ---------------------------------------------------------

    def scan_function(
        self,
        func_va:     int,
        func_end:    int,
        init_labels: Optional[Set[str]] = None,
        func_name:   Optional[str]      = None,
    ) -> List[TaintFindingRH850]:
        """
        Scan one function for taint flows from seeded arg registers to sinks.

        Seeds R6-R9 with every label in ``init_labels`` at function entry.
        Returns findings for this function only; does not follow calls.
        """
        if func_name and func_va not in self._syms:
            self._syms[func_va] = func_name

        raw = self._scan_func_binary(func_va, func_end, init_labels)
        return [TaintFindingRH850.from_v850(f, self._double_is_32bit)
                for f in raw]

    # -- run overrides (wrap TaintFindingV850 → TaintFindingRH850) ------------

    def run(self) -> List[TaintFindingRH850]:  # type: ignore[override]
        """Intraprocedural scan of all ELF symbol-known functions."""
        raw = super().run()
        return [TaintFindingRH850.from_v850(f, self._double_is_32bit)
                for f in raw]

    def run_interprocedural(self,              # type: ignore[override]
                            depth: int = 4) -> List[TaintFindingRH850]:
        """
        Interprocedural BFS scan.  Follows tainted R6-R9 into callees.
        Uses GHS symbol normalisation at every call site.
        Uses deque for O(1) BFS (fixes O(N) list.pop(0) in V850TaintTracker).
        Mirror changes to V850TaintTracker.run_interprocedural — call-site logic must stay in sync.
        """
        starts   = self._get_func_starts()
        fv       = self._ensure_frames()
        func_end: Dict[int, int] = {
            fva: (starts[i + 1] if i + 1 < len(starts) else self._text_end)
            for i, fva in enumerate(starts)
        }

        findings: List[TaintFindingRH850] = []
        queue:    Deque[Tuple[int, int, Set[str]]] = deque(
            (fva, depth, set()) for fva in starts
        )
        visited: Dict[Tuple, int] = {}

        while queue:
            fva, d, init_labels = queue.popleft()
            key = (fva,) + tuple(sorted(init_labels))
            if visited.get(key, -1) >= d:
                continue
            visited[key] = d
            fend      = func_end.get(fva, self._text_end)
            func_name = self._syms.get(fva, f'fn_0x{fva:x}')

            eng = TaintEngine(self._variant)
            for r in ARG_REGS:
                for lbl in init_labels:
                    eng.taint_register(r, lbl)

            va = fva
            while va < fend:
                frame = fv.get(va)
                if frame is None:
                    va += 2
                    continue

                if frame.is_call and frame.target:
                    callee_va   = frame.target
                    raw_name    = _name_at(self._syms, callee_va)
                    callee_name = _ghs_c_name(raw_name) if raw_name else ''
                    st = eng.state

                    if _ghs_name_in(raw_name or '', _SOURCE_NAMES):
                        for r in CALLER_SAVED:
                            st.set(r, CLEAN)
                        for r in RET_REGS:
                            st.set(r, Taint(frozenset({callee_name or raw_name or 'source'}), None))

                    elif _ghs_name_in(raw_name or '', _SINK_NAMES):
                        tainted_args = [r for r in ARG_REGS if st.get(r).tainted]
                        if tainted_args:
                            labels = frozenset().union(*(st.get(r).labels for r in tainted_args))
                            sev = 'CRITICAL' if callee_name in _GHS_CRITICAL_SINKS else 'HIGH'
                            findings.append(TaintFindingRH850(
                                func_va=fva, func_name=func_name,
                                sink_va=va, sink_name=callee_name or raw_name or '?',
                                tainted_args=tainted_args,
                                source_name=next(iter(sorted(labels)), 'unknown'),
                                severity=sev,
                                double_is_32bit=self._double_is_32bit,
                            ))
                        for r in CALLER_SAVED:
                            st.set(r, CLEAN)

                    else:
                        # Enqueue callee if taint flows into it
                        if d > 0:
                            tainted_into = [r for r in ARG_REGS if st.get(r).tainted]
                            if tainted_into:
                                lbs = set().union(*(st.get(r).labels for r in tainted_into))
                                c_va = callee_va
                                # snap to nearest known function start
                                for off in range(0, _PLT_TOL + 1, 2):
                                    if c_va + off in func_end:
                                        c_va += off; break
                                    if c_va - off in func_end and c_va - off >= 0:
                                        c_va -= off; break
                                if c_va in func_end:
                                    queue.append((c_va, d - 1, lbs))
                        for r in CALLER_SAVED:
                            st.set(r, CLEAN)

                else:
                    eng.step(frame)

                va += frame.width

        return _dedup_rh850(findings)

    def report(self, findings: List[TaintFindingRH850]) -> str:
        if not findings:
            return 'RH850 taint: no findings.'
        lines = [f'RH850 taint: {len(findings)} finding(s)  '
                 f'[double={"32b" if self._double_is_32bit else "64b"}]\n']
        for f in sorted(findings, key=lambda x: (x.func_va, x.sink_va)):
            lines.append(str(f))
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dedup_rh850(findings: List[TaintFindingRH850]) -> List[TaintFindingRH850]:
    seen: Set[Tuple] = set()
    out:  List[TaintFindingRH850] = []
    for f in findings:
        k = (f.func_va, f.sink_va, f.sink_name)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
