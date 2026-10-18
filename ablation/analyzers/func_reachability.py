"""
func_reachability.py: determine whether a function is reachable at runtime.

An ARG_PROPAGATED finding in an unreachable function cannot be exploited.
This module filters dead code to reduce false positives from SinkArgClassifier.

Two orthogonal checks:
  1. call_edges — does the function appear as a destination in BinaryContext.call_edges?
     A function with no call edges has no direct callers known to the disassembler.
  2. binary_refs — are there any references to the function VA as a 32/64-bit word
     in executable or initialized-data sections (as opposed to DWARF debug sections)?
     A function with only .debug_* references is dead code — debug sections are not
     mapped into the process address space at runtime.

Verdicts (per function VA):
  REACHABLE         — at least one call edge exists → normal ARG_PROPAGATED path
  REACHABLE_VIA_PTR — no call edges but function VA appears in exec/data section
                      (function pointer table, virtual dispatch table, etc.)
  UNREACHABLE_DEBUG — no call edges; VA appears only in .debug_* sections
                      (dead code; debug symbol table reference only)
  UNREACHABLE_NOREF — no call edges; no references anywhere in binary

Engagement gap this fills:
  IBM.RecoveryRMd (CSM SAM 2.2.0.1): func@0x839c14f contained an ARG_PROPAGATED
  system() site that was manually investigated before discovering the function had
  no runtime callers. References to 0x839c14f existed only in .debug_pubnames
  (file offsets 0x3020c, 0x11eb730). Manual verification took ~20 minutes.
  This module would have flagged UNREACHABLE_DEBUG instantly.

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.func_reachability import FuncReachabilityAnalyzer

    ctx = BinaryContext.load_or_build('/path/to/target')
    rz = FuncReachabilityAnalyzer.from_context(ctx)

    result = rz.check(0x839c14f)
    print(result.verdict, result.reason)

    # Batch-filter ARG_PROPAGATED findings
    from ablation.analyzers.sink_arg_classifier import ARG_PROPAGATED
    findings = clf.classify_all()
    filtered = rz.filter_unreachable(findings)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# Section name prefixes that are DWARF debug sections (not loaded at runtime).
_DEBUG_PREFIXES = (
    '.debug_', '__debug_', '.zdebug_',
)

# Section names that contain VA references but cannot call functions.
# Symbol/string tables: reference every exported symbol's VA for the linker/debugger
# but do not represent function pointer calls.  A VA appearing only in these
# sections means the function is dead code in an executable context.
_NON_CALL_SECTIONS: frozenset = frozenset({
    '.dynsym', '.symtab',           # symbol tables
    '.dynstr', '.strtab',           # string tables
    '.gnu.hash', '.gnu_hash', '.hash',  # hash tables
    '.note.gnu.build-id', '.note.ABI-tag', '.comment',
    '.gnu_debuglink', '.gnu_debugdata',
})

# Section names that are runtime-loadable executable or initialized data.
_RUNTIME_SECTIONS = frozenset({
    '.text', '.init', '.fini', '.plt', '.plt.got', '.plt.sec',
    '.data', '.data.rel.ro', '.rodata', '.rodata1', '.got', '.got.plt',
    '.bss', '.tbss', '.init_array', '.fini_array', '.ctors', '.dtors',
    '.eh_frame', '.eh_frame_hdr',
})


def _is_non_call_section(name: str) -> bool:
    """True for sections that reference VAs symbolically but cannot call functions."""
    if any(name.startswith(p) for p in _DEBUG_PREFIXES):
        return True
    return name in _NON_CALL_SECTIONS


# Keep for callers that use the old name
def _is_debug_section(name: str) -> bool:
    return _is_non_call_section(name)


@dataclass
class VaRef:
    """One reference to a function VA found in the binary."""
    file_offset: int
    section:     str   # section name, or '' if not in any section
    va:          int   # VA of the reference site (file_offset → VA)


@dataclass
class ReachabilityResult:
    """Reachability verdict for one function."""
    func_va:  int
    verdict:  str             # REACHABLE | REACHABLE_VIA_PTR | UNREACHABLE_DEBUG | UNREACHABLE_NOREF
    callers:  List[int] = field(default_factory=list)   # call-edge caller VAs
    refs:     List[VaRef] = field(default_factory=list) # VA references found

    @property
    def is_reachable(self) -> bool:
        return self.verdict in ('REACHABLE', 'REACHABLE_VIA_PTR')

    @property
    def reason(self) -> str:
        if self.verdict == 'REACHABLE':
            return f'{len(self.callers)} call edge(s)'
        if self.verdict == 'REACHABLE_VIA_PTR':
            secs = ', '.join(sorted({r.section for r in self.refs}))
            return f'no call edges but VA in runtime section(s): {secs}'
        if self.verdict == 'UNREACHABLE_DEBUG':
            secs = ', '.join(sorted({r.section for r in self.refs if r.section})) or '(no named section)'
            return f'no call edges; VA only in non-callable section(s): {secs} → dead code'
        return 'no call edges; no VA references in binary'


class FuncReachabilityAnalyzer:
    """
    Determine whether functions are reachable at runtime.

    Combines BinaryContext call-graph edges with a full-binary VA scan to
    distinguish genuinely dead functions from those reached via function pointers.
    """

    def __init__(self, ctx) -> None:
        self._ctx   = ctx
        self._data: bytes = Path(ctx.path).read_bytes()
        self._bin   = None
        self._ptr_size: int = 8   # default x86_64; overridden by arch
        self._sections: List[Tuple[str, int, int]] = []  # (name, file_off, file_end)
        if _LIEF_OK:
            self._bin = _lief.parse(ctx.path)
            self._init_sections()
            # Detect pointer size from ELF class
            try:
                elf_class = str(self._bin.header.identity_class)
                if '32' in elf_class:
                    self._ptr_size = 4
            except Exception:
                pass
        # Infer from ctx.arch too (more reliable than ELF header parse)
        arch = getattr(ctx, 'arch', '') or ''
        if '32' in arch or arch in ('x86_32', 'ppc32', 'arm32', 'mips32', 's390x_32'):
            self._ptr_size = 4

    def _init_sections(self) -> None:
        if self._bin is None:
            return
        try:
            for sec in self._bin.sections:
                try:
                    off = int(self._bin.virtual_address_to_offset(sec.virtual_address))
                    self._sections.append((sec.name, off, off + int(sec.size)))
                except Exception:
                    pass
        except Exception:
            pass

    @classmethod
    def from_context(cls, ctx) -> 'FuncReachabilityAnalyzer':
        return cls(ctx)

    # ── core API ──────────────────────────────────────────────────────────────

    def check(self, func_va: int) -> ReachabilityResult:
        """Return the reachability verdict for one function VA."""
        # Check 1: call edges
        callers = [src for src, dst, _n in self._ctx.call_edges if dst == func_va]
        if callers:
            return ReachabilityResult(func_va=func_va, verdict='REACHABLE', callers=callers)

        # Check 2: binary VA scan
        refs = self._find_refs(func_va)
        if not refs:
            return ReachabilityResult(func_va=func_va, verdict='UNREACHABLE_NOREF')

        # A ref is "callable" only if it's in a known runtime code/data section.
        # Unknown section (empty name) and symbol/debug tables are not callable.
        callable_refs = [r for r in refs if r.section in _RUNTIME_SECTIONS]
        if not callable_refs:
            return ReachabilityResult(func_va=func_va, verdict='UNREACHABLE_DEBUG', refs=refs)

        return ReachabilityResult(func_va=func_va, verdict='REACHABLE_VIA_PTR', refs=callable_refs)

    def check_all(self, func_vas: List[int]) -> Dict[int, ReachabilityResult]:
        """Batch check; returns {func_va: result}."""
        return {va: self.check(va) for va in func_vas}

    def filter_unreachable(self, findings: list) -> list:
        """
        Remove findings whose containing function is unreachable (dead code).

        Each item in `findings` must have a `func_va` attribute.
        Returns a new list containing only reachable findings.
        """
        seen_vas: Dict[int, ReachabilityResult] = {}
        kept = []
        for f in findings:
            va = getattr(f, 'func_va', None)
            if va is None:
                kept.append(f)
                continue
            if va not in seen_vas:
                seen_vas[va] = self.check(va)
            if seen_vas[va].is_reachable:
                kept.append(f)
        return kept

    def report(self, results: Dict[int, ReachabilityResult]) -> str:
        lines = ['FuncReachabilityAnalyzer results:']
        for va, r in sorted(results.items()):
            lines.append(f'  0x{va:x}  {r.verdict:22s}  {r.reason}')
        return '\n'.join(lines)

    # ── internal ──────────────────────────────────────────────────────────────

    def _find_refs(self, func_va: int) -> List[VaRef]:
        """Scan binary for func_va as a little-endian 32 or 64-bit word."""
        refs: List[VaRef] = []
        fmt = '<I' if self._ptr_size == 4 else '<Q'
        needle = struct.pack(fmt, func_va)
        pos = 0
        while True:
            idx = self._data.find(needle, pos)
            if idx == -1:
                break
            sec_name = self._section_for_offset(idx)
            refs.append(VaRef(file_offset=idx, section=sec_name, va=func_va))
            pos = idx + 1
        return refs

    def _section_for_offset(self, file_off: int) -> str:
        """Return the section name containing file_off, or ''."""
        for name, sec_off, sec_end in self._sections:
            if sec_off <= file_off < sec_end:
                return name
        return ''
