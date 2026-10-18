"""
pe_sink_classifier.py — Windows PE exec-class IAT import scanner.

Gap filled vs SinkArgClassifier:
  SinkArgClassifier.classify_all() accesses binary.dynamic_symb (ELF-only
  attribute). When called on a PE32/PE64 binary it raises:
    AttributeError: 'lief._lief.PE.Binary' object has no attribute 'dynamic_symb'
  This crash surfaces in IBM-RE analysis on DS6000, Misc, Pacbase, ISPF-Tools,
  EGL-VSE, RapidRestore, and other Windows-only directories.

  PE binaries do NOT use ELF PLT/JUMP_SLOT — they use the IAT (import address
  table). Windows exec-class equivalents of POSIX system/popen/exec* are:
    CreateProcessA/W, ShellExecuteA/W/Ex, WinExec, system, _popen, _wsystem.

  This module scans the IAT for exec-class API imports and reports which DLL
  provides each, classified by attack-surface category.

  Windows exec-class imports do not correspond to POSIX attack paths (no shell
  injection, no argument-from-network paths without full x86 analysis). The
  output of this classifier is per-file import presence — whether these APIs
  are imported at all — which is the correct Ablation finding for Windows PE
  binaries in a cross-platform collection analysis.

Windows exec-class categories:
  PROCESS_CREATION  — CreateProcessA/W, CreateProcessAsUserA/W
  SHELL_EXECUTE     — ShellExecuteA/W, ShellExecuteExA/W
  LEGACY_EXEC       — WinExec
  MSVCRT_SYSTEM     — system, _wsystem
  MSVCRT_POPEN      — _popen, _wpopen
  SERVICE_INSTALL   — CreateServiceA/W (privilege boundary, not process exec)

Usage:
    from ablation.analyzers.pe_sink_classifier import PESinkClassifier

    clf = PESinkClassifier.from_path('/path/to/target.exe')
    results = clf.classify_all()
    print(clf.report(results))

    # Check import presence summary:
    summary = clf.summary()  # dict: category -> [import_names]

    # With existing BinaryContext (arch check only):
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/target.exe')
    clf = PESinkClassifier.from_context(ctx)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# ── Exec-class import catalog ─────────────────────────────────────────────────
# Map canonical import name (lowercase) → (display_name, category, dll)
_EXEC_CLASS_IMPORTS: Dict[str, tuple] = {
    # Process creation (kernel32)
    'createprocessa':         ('CreateProcessA',      'PROCESS_CREATION', 'KERNEL32.dll'),
    'createprocessw':         ('CreateProcessW',      'PROCESS_CREATION', 'KERNEL32.dll'),
    'createprocessasusera':   ('CreateProcessAsUserA','PROCESS_CREATION', 'ADVAPI32.dll'),
    'createprocessasuserw':   ('CreateProcessAsUserW','PROCESS_CREATION', 'ADVAPI32.dll'),
    # Shell execute (shell32)
    'shellexecutea':          ('ShellExecuteA',       'SHELL_EXECUTE',    'SHELL32.dll'),
    'shellexecutew':          ('ShellExecuteW',       'SHELL_EXECUTE',    'SHELL32.dll'),
    'shellexecuteexa':        ('ShellExecuteExA',     'SHELL_EXECUTE',    'SHELL32.dll'),
    'shellexecuteexw':        ('ShellExecuteExW',     'SHELL_EXECUTE',    'SHELL32.dll'),
    # Legacy exec (kernel32)
    'winexec':                ('WinExec',             'LEGACY_EXEC',      'KERNEL32.dll'),
    # MSVCRT system-family
    'system':                 ('system',              'MSVCRT_SYSTEM',    'msvcrt.dll'),
    '_wsystem':               ('_wsystem',            'MSVCRT_SYSTEM',    'msvcrt.dll'),
    # MSVCRT popen-family
    '_popen':                 ('_popen',              'MSVCRT_POPEN',     'msvcrt.dll'),
    '_wpopen':                ('_wpopen',             'MSVCRT_POPEN',     'msvcrt.dll'),
    # Service installation (privilege boundary)
    'createservicea':         ('CreateServiceA',      'SERVICE_INSTALL',  'ADVAPI32.dll'),
    'createservicew':         ('CreateServiceW',      'SERVICE_INSTALL',  'ADVAPI32.dll'),
}


@dataclass
class PESinkFinding:
    """One exec-class import found in a PE binary's IAT."""
    import_name: str          # canonical name as stored in IAT
    category:    str          # PROCESS_CREATION / SHELL_EXECUTE / etc.
    dll_name:    str          # originating DLL as listed in IAT
    binary_path: str          # path to the PE binary

    def fmt(self) -> str:
        return (
            f'[{self.category:18s}] {self.import_name:28s}'
            f'  (from {self.dll_name})  {Path(self.binary_path).name}'
        )


class PESinkClassifier:
    """
    Scan Windows PE binaries for exec-class IAT imports.

    Fills the gap where SinkArgClassifier crashes on PE binaries with
    'AttributeError: lief._lief.PE.Binary has no attribute dynamic_symb'.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._bin  = None
        if _LIEF_OK:
            parsed = _lief.parse(path)
            if parsed is not None and isinstance(parsed, _lief.PE.Binary):
                self._bin = parsed

    @classmethod
    def from_path(cls, path: str) -> 'PESinkClassifier':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'PESinkClassifier':
        return cls(ctx.path)

    def is_pe(self) -> bool:
        return self._bin is not None

    def classify_all(self) -> List[PESinkFinding]:
        """Return a finding for every exec-class API imported by this PE binary."""
        if not self._bin:
            return []
        findings: List[PESinkFinding] = []
        for imp_module in self._bin.imports:
            dll = imp_module.name
            for entry in imp_module.entries:
                name = entry.name or ''
                key  = name.lower()
                if key in _EXEC_CLASS_IMPORTS:
                    _, category, _ = _EXEC_CLASS_IMPORTS[key]
                    findings.append(PESinkFinding(
                        import_name=name,
                        category=category,
                        dll_name=dll,
                        binary_path=self._path,
                    ))
        return findings

    def summary(self) -> Dict[str, List[str]]:
        """Return {category: [import_name, ...]} dict for all exec-class imports."""
        out: Dict[str, List[str]] = {}
        for f in self.classify_all():
            out.setdefault(f.category, []).append(f.import_name)
        return out

    def report(self, results: Optional[List[PESinkFinding]] = None) -> str:
        if results is None:
            results = self.classify_all()
        if not self._bin:
            return f'PESinkClassifier: not a PE binary: {self._path}\n'
        if not results:
            return f'PESinkClassifier: no exec-class imports found in {Path(self._path).name}\n'
        lines = [
            'PESinkClassifier Results',
            '=' * 60,
            f'Binary: {self._path}',
            '',
        ]
        by_cat: Dict[str, List[PESinkFinding]] = {}
        for r in results:
            by_cat.setdefault(r.category, []).append(r)
        for cat in sorted(by_cat):
            lines.append(f'  {cat}:')
            for r in by_cat[cat]:
                lines.append(f'    {r.import_name}  (from {r.dll_name})')
        return '\n'.join(lines) + '\n'


def scan_directory(
    dirpath: str,
    extensions: tuple = ('.exe', '.dll', '.ocx', '.sys'),
) -> Dict[str, List[PESinkFinding]]:
    """
    Scan all PE files in dirpath for exec-class imports.

    Returns {filepath: [findings]} — only files with at least one finding.
    """
    results: Dict[str, List[PESinkFinding]] = {}
    root = Path(dirpath)
    for ext in extensions:
        for p in root.rglob(f'*{ext}'):
            clf = PESinkClassifier.from_path(str(p))
            if not clf.is_pe():
                continue
            findings = clf.classify_all()
            if findings:
                results[str(p)] = findings
    return results


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: python3 -m ablation.analyzers.pe_sink_classifier <path>')
        sys.exit(1)
    clf = PESinkClassifier.from_path(sys.argv[1])
    if not clf.is_pe():
        print(f'Not a PE binary: {sys.argv[1]}')
        sys.exit(1)
    results = clf.classify_all()
    print(clf.report(results))
