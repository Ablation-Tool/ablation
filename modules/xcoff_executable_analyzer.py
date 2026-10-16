"""XCOFF32/64 executable RE surface analyzer.

Wraps the xcoff_parser core module and exposes the AIX binary RE surface in
the same interface pattern as other ablation analyzers.

Why this exists
---------------
1. xcoff_parser.parse() returns an XcoffBinary dataclass. In session work,
   callers repeatedly extracted exports, imports, and function starts from
   the raw dataclass. A thin analyzer layer with convenience methods
   (exports_table, imports_by_lib, func_starts, section_at_va) avoids
   repetitive boilerplate in every AIX session script.
2. The XCOFF32 main symtab (_parse_symtab32_exe) uses absolute VAs, while
   XCOFF32 relocatable .o files use section-relative offsets. Without the
   analyzer layer this distinction must be remembered by every caller.
   xcoff_executable_analyzer always returns absolute code VAs regardless of
   file type.
3. The analyzer integrates with BinaryContext via from_context, which gives
   access to the same ctx.path interface used by all other analyzers in the
   tool-selection pipeline.

Usage::

    from ablation.analyzers.xcoff_executable_analyzer import XCOFFExecutableAnalyzer

    a = XCOFFExecutableAnalyzer.from_path('/path/to/ioscli')
    print(a.arch)
    for name, code_va in sorted(a.exports_table().items()):
        print(f'{name}  {code_va:#010x}')
    for lib, names in a.imports_by_lib().items():
        print(f'{lib}: {names}')
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_MAX_XCOFF_BYTES = 256 * 1024 * 1024


class XCOFFExecutableAnalyzer:
    """RE surface view of an XCOFF32 or XCOFF64 AIX binary.

    Args:
        path: Path to the XCOFF32 or XCOFF64 binary.
    """

    def __init__(self, path: str | Path):
        self._path = str(path)
        self._binary = None

    def _load(self):
        if self._binary is not None:
            return
        bin_size = os.path.getsize(self._path)
        if bin_size > _MAX_XCOFF_BYTES:
            raise ValueError(
                f'{self._path}: file size {bin_size} exceeds {_MAX_XCOFF_BYTES} byte limit')
        from ablation.core.xcoff_parser import parse
        self._binary = parse(self._path)

    @classmethod
    def from_path(cls, path: str | Path) -> 'XCOFFExecutableAnalyzer':
        """Construct and load the binary immediately."""
        a = cls(path)
        a._load()
        return a

    @classmethod
    def from_context(cls, ctx) -> 'XCOFFExecutableAnalyzer':
        return cls.from_path(ctx.path)

    @property
    def arch(self) -> str:
        """'ppc32' or 'ppc64'."""
        self._load()
        return self._binary.arch

    @property
    def entry(self) -> int:
        self._load()
        return self._binary.entry

    def exports_table(self) -> Dict[str, int]:
        """Return a dict mapping export name to code VA.

        For ppc32 executables, code_va is the resolved text-section address
        (after descriptor resolution). For ppc32 .o files, code_va is the
        section-relative offset.
        """
        self._load()
        result = {}
        for sym in self._binary.exports:
            if sym.code_va:
                result[sym.name] = sym.code_va
            elif sym.va:
                result[sym.name] = sym.va
        return result

    def imports_by_lib(self) -> Dict[str, List[str]]:
        """Return a dict mapping library name to list of imported symbol names."""
        self._load()
        result: Dict[str, List[str]] = {}
        for sym in self._binary.imports:
            result.setdefault(sym.lib or '<unknown>', []).append(sym.name)
        return result

    def func_starts(self) -> List[Tuple[str, int]]:
        """Return list of (name, code_va) sorted by code_va."""
        table = self.exports_table()
        return sorted(table.items(), key=lambda kv: kv[1])

    def section_at_va(self, va: int):
        """Return the XcoffSection covering va, or None."""
        self._load()
        for sec in self._binary.sections:
            if sec.vaddr <= va < sec.vaddr + sec.size:
                return sec
        return None

    def summary(self) -> str:
        self._load()
        b = self._binary
        n_exp = len(b.exports)
        n_imp = len(b.imports)
        n_sec = len(b.sections)
        sec_names = ' '.join(s.name for s in b.sections)
        return (
            f'XCOFFExecutableAnalyzer  path={self._path}\n'
            f'  arch={b.arch}  entry={b.entry:#010x}'
            f'  toc={b.toc_va:#010x}\n'
            f'  sections={n_sec} [{sec_names}]\n'
            f'  exports={n_exp}  imports={n_imp}'
        )
