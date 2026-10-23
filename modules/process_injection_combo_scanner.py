"""
process_injection_combo_scanner.py: Process injection combination detector.

Detects the canonical Windows process injection triad:
  VirtualAllocEx + WriteProcessMemory + CreateRemoteThread

or the NT-native variant:
  NtAllocateVirtualMemory + NtWriteVirtualMemory + NtCreateThreadEx

When all three APIs from either group appear as imports in the same binary,
the binary has the full toolkit for injecting code into a foreign process.
This is ATT&CK T1055 (Process Injection) at the binary level.

Single API co-occurrence is high confidence; this scanner flags the triad
presence even at PLT import level, before any function-level call-graph
analysis. Use SinkPropagator for deeper chain analysis.

Usage:
    scanner = ProcessInjectionComboScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = ProcessInjectionComboScanner.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ── API groups defining injection capability ───────────────────────────────────

_INJECTION_COMBOS: list[dict] = [
    {
        'name': 'Classic DLL Injection',
        'attck': 'T1055.001',
        'apis': {
            'alloc':  frozenset({'VirtualAllocEx', 'VirtualAlloc'}),
            'write':  frozenset({'WriteProcessMemory'}),
            'execute': frozenset({'CreateRemoteThread', 'CreateRemoteThreadEx',
                                  'RtlCreateUserThread', 'NtCreateThreadEx'}),
        },
    },
    {
        'name': 'PE Injection / Shellcode',
        'attck': 'T1055.002',
        'apis': {
            'alloc':  frozenset({'VirtualAllocEx'}),
            'write':  frozenset({'WriteProcessMemory'}),
            'execute': frozenset({'SetThreadContext', 'ResumeThread'}),
        },
    },
    {
        'name': 'NT Native Injection',
        'attck': 'T1055',
        'apis': {
            'alloc':  frozenset({'NtAllocateVirtualMemory', 'ZwAllocateVirtualMemory'}),
            'write':  frozenset({'NtWriteVirtualMemory', 'ZwWriteVirtualMemory'}),
            'execute': frozenset({'NtCreateThreadEx', 'ZwCreateThreadEx',
                                  'RtlCreateUserThread'}),
        },
    },
    {
        'name': 'Process Hollowing',
        'attck': 'T1055.012',
        'apis': {
            'create': frozenset({'CreateProcessA', 'CreateProcessW',
                                 'CreateProcessInternalA', 'CreateProcessInternalW'}),
            'suspend': frozenset({'SuspendThread', 'NtSuspendThread'}),
            'write':  frozenset({'WriteProcessMemory', 'NtWriteVirtualMemory'}),
        },
    },
]


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class InjectionFinding:
    technique:    str          # technique name
    attck_id:     str          # ATT&CK T-ID
    matched_apis: list[str]    # which specific APIs were found
    severity:     str = 'HIGH'

    def fmt(self) -> str:
        apis = ', '.join(self.matched_apis)
        return (f"  {self.severity:6s}  [{self.attck_id}]  {self.technique}\n"
                f"         imports: {apis}")


# ── Scanner ────────────────────────────────────────────────────────────────────

class ProcessInjectionComboScanner:
    """Detect process injection API triads in binary PLT imports."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'ProcessInjectionComboScanner':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _load_ctx(self):
        if self._ctx is not None:
            return self._ctx
        from ablation.analyzers.binary_context import BinaryContext
        self._ctx = BinaryContext.load_or_build(self._path)
        return self._ctx

    def _get_import_names(self, ctx) -> frozenset:
        """Return frozenset of all PLT/import symbol base names."""
        names: set[str] = set()
        for _, name in ctx.plt.items():
            base = name.split('@')[0].lstrip('_')
            names.add(base)
        return frozenset(names)

    def scan(self) -> List[InjectionFinding]:
        ctx = self._load_ctx()
        imports = self._get_import_names(ctx)
        findings: list[InjectionFinding] = []

        for combo in _INJECTION_COMBOS:
            matched: list[str] = []
            all_groups_hit = True
            for group_name, api_set in combo['apis'].items():
                hits = sorted(imports & api_set)
                if not hits:
                    all_groups_hit = False
                    break
                matched.extend(hits)
            if all_groups_hit:
                findings.append(InjectionFinding(
                    technique=combo['name'],
                    attck_id=combo['attck'],
                    matched_apis=matched,
                ))

        return findings

    def report(self, findings: Optional[List[InjectionFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'ProcessInjectionComboScanner: no injection API triads in {self._path}'
        lines = [f'ProcessInjectionComboScanner: {len(findings)} injection technique(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
