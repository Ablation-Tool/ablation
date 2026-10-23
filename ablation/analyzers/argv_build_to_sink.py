"""
argv_build_to_sink.py: Detect malloc→strcat(argv[i] loop)→system/popen injection pattern.

Why this exists
---------------
Gap discovered during HMC ldapsearch + chhmc analysis (sessions 46+53, 2026-10-23):
  ldapsearch (SETUID hscroot-gated): malloc(N) → for(i; i<argc; i++) strcat(buf, argv[i])
    → system(buf).  SAC returns UNKNOWN because the strcat source is dynamic (argv[i]).
    TaintTracker also needs a configured sink.  The malloc→strcat-loop→system idiom
    is so common (10+ binaries in the HMC corpus alone) that a dedicated classifier
    is justified.

  chhmc / lshmc (HMCMGMT-CMD-001 LOW): same pattern, partial accumulation.

  The classifier also detects the access-gate (getuid(), getpwuid(), strcmp to a role
  name) and scores severity accordingly.

The pattern
-----------
  Within a single function:
    1. call malloc/calloc/alloca  — allocate a command buffer
    2. (optional) strcpy/strncpy initial command template into buffer
    3. loop: call strcat(buf, argv[i])  — where i is a loop counter ← argv[argc]
    4. call system(buf) / popen(buf) / execvp(buf)  — command execution sink

  Gate scoring (determines severity):
    - No gate: HIGH
    - Gate = getuid()==0 or strcmp(uname,"root"): MEDIUM (root-only; still internal
      privilege boundary)
    - Gate = strcmp(uname, role_name): MEDIUM/LOW (role check; inject via role account)

Usage
-----
    from ablation.analyzers.argv_build_to_sink import ArgvBuildToSinkClassifier
    results = ArgvBuildToSinkClassifier.from_path('/path/to/binary').scan()
    for r in results:
        print(r)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import capstone

from ablation.analyzers.binary_context import BinaryContext

_ALLOC_FUNCS  = {'malloc', 'calloc', 'alloca', '__builtin_alloca'}
_STRCAT_FUNCS = {'strcat', 'strncat', 'sprintf', 'snprintf'}
_COPY_FUNCS   = {'strcpy', 'strncpy', 'memcpy', 'snprintf', 'sprintf'}
_SINK_FUNCS   = {'system', 'popen', 'execvp', 'execve', 'execv'}
_GATE_FUNCS   = {'getuid', 'geteuid', 'getpwuid', 'getpwnam', 'strcmp', 'strcasecmp'}


@dataclass
class ArgvBuildFinding:
    func_va: int
    alloc_va: Optional[int]        # malloc/calloc call VA (None if stack buf)
    strcat_vas: List[int]          # VA of each strcat(buf, argv[i]) in loop
    sink_va: int
    sink_name: str                 # 'system', 'popen', 'execvp', etc.
    gate_funcs: List[str]          # gate functions seen in same function (can confirm gating)
    gate_strings: List[str]        # string args to strcmp/getpwnam (e.g., "hscroot", "root")
    no_gate: bool                  # True if no gate detected before sink
    verdict: str                   # 'CONFIRMED' or 'PLAUSIBLE'
    severity: str                  # 'HIGH' / 'MEDIUM' / 'LOW'
    note: str

    def __str__(self) -> str:
        gate_info = (
            f"gate={self.gate_strings!r}" if self.gate_strings else
            ("no-gate" if self.no_gate else "gate-present")
        )
        return (
            f"ArgvBuildFinding({self.verdict}/{self.severity}): "
            f"func@{hex(self.func_va)} | "
            f"alloc@{hex(self.alloc_va) if self.alloc_va else 'stack'} → "
            f"strcat×{len(self.strcat_vas)} → "
            f"{self.sink_name}@{hex(self.sink_va)} [{gate_info}]"
        )


class ArgvBuildToSinkClassifier:
    """
    Classifies command-injection patterns where argv[i] is accumulated
    into a buffer via strcat/sprintf loop and then passed to a shell sink.

    SAC returns UNKNOWN for these because the strcat source is dynamic.
    This classifier provides a targeted analysis that SAC cannot.
    """

    def __init__(self, ctx: BinaryContext) -> None:
        self._ctx  = ctx
        self._data = open(ctx.path, 'rb').read()
        self._base = ctx.base_va
        self._plt: Dict[str, int] = {
            name: va for va, name in ctx.plt.items()
            if name in (
                *_ALLOC_FUNCS, *_STRCAT_FUNCS, *_SINK_FUNCS, *_GATE_FUNCS
            )
        }

    @classmethod
    def from_path(cls, path: str) -> ArgvBuildToSinkClassifier:
        return cls(BinaryContext.load_or_build(path))

    @classmethod
    def from_context(cls, ctx: BinaryContext) -> ArgvBuildToSinkClassifier:
        return cls(ctx)

    def _plt_name(self, va: int) -> Optional[str]:
        for name, plt_va in self._plt.items():
            if plt_va == va:
                return name
        return None

    def _disasm_func(self, func_va: int, max_bytes: int = 4096) -> List:
        arch = self._ctx.arch
        if arch == 'x86_64':
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
        elif arch == 'x86':
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
        else:
            return []
        off = func_va - self._base
        if off < 0 or off >= len(self._data):
            return []
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True
        return list(md.disasm(self._data[off:off + max_bytes], func_va))

    def _resolve_call(self, insn) -> Optional[int]:
        try:
            return int(insn.op_str.strip(), 16)
        except ValueError:
            return None

    def _rodata_str_at(self, va: int, maxlen: int = 64) -> Optional[str]:
        off = va - self._base
        if off < 0 or off + maxlen > len(self._data):
            return None
        try:
            end = self._data.index(b'\x00', off, off + maxlen)
            return self._data[off:end].decode('ascii')
        except (ValueError, UnicodeDecodeError):
            return None

    def _extract_string_arg(self, insns: List, call_idx: int, arg_reg: str = 'edi') -> Optional[str]:
        """Extract RODATA string argument to current call (edi/rdi for first arg)."""
        for i in range(call_idx - 1, max(call_idx - 20, -1), -1):
            pi = insns[i]
            if pi.mnemonic not in ('lea', 'mov'):
                continue
            parts = [p.strip() for p in pi.op_str.split(',')]
            if len(parts) != 2:
                continue
            dst, src = parts
            if dst not in (arg_reg, arg_reg.replace('e', 'r')):
                continue
            try:
                if 'rip' in src:
                    rip_next = insns[i + 1].address if i + 1 < len(insns) else pi.address + 7
                    offset_str = src.split('+')[-1].strip().rstrip(']').strip()
                    val = rip_next + int(offset_str, 16)
                else:
                    val = int(src.lstrip('#'), 16)
                s = self._rodata_str_at(val)
                if s:
                    return s
            except (ValueError, IndexError):
                pass
        return None

    def _second_arg_from_argv(self, insns: List, call_idx: int) -> bool:
        """
        Return True if the second argument to strcat/strncat appears to come
        from argv (indicated by: lea/mov esi/rsi from a memory load whose base
        is likely the argv array — [rbp+rax*8+offset] or [rbp+N+rax*8]).
        """
        for i in range(call_idx - 1, max(call_idx - 15, -1), -1):
            pi = insns[i]
            if pi.mnemonic not in ('lea', 'mov'):
                continue
            parts = [p.strip() for p in pi.op_str.split(',')]
            if len(parts) != 2:
                continue
            dst, src = parts
            if dst not in ('esi', 'rsi', 'edx', 'rdx'):
                continue
            # Patterns: mov rsi, [rbp+rax*8+N] or mov rsi, [rbp+N] where N is small
            if '[' in src and ('*8' in src or ('rbp' in src and '+' in src)):
                return True
            # Also accept indirect argv[i]: mov rsi, [rax] where rax was loaded from argv
            if '[' in src and 'rax' in src:
                return True
        return False

    def _scan_func(self, func_va: int) -> List[ArgvBuildFinding]:
        insns = self._disasm_func(func_va)
        if not insns:
            return []

        alloc_va: Optional[int] = None
        strcat_vas: List[int]  = []
        gate_funcs: List[str]  = []
        gate_strings: List[str] = []
        findings: List[ArgvBuildFinding] = []

        for i, insn in enumerate(insns):
            if insn.mnemonic != 'call':
                continue
            target = self._resolve_call(insn)
            if target is None:
                continue
            name = self._plt_name(target)
            if name is None:
                continue

            if name in _ALLOC_FUNCS:
                alloc_va = insn.address

            elif name in _STRCAT_FUNCS:
                if self._second_arg_from_argv(insns, i):
                    strcat_vas.append(insn.address)
                else:
                    # partial — still record, may confirm via other means
                    strcat_vas.append(insn.address)

            elif name in _GATE_FUNCS:
                gate_funcs.append(name)
                if name in ('strcmp', 'strcasecmp', 'getpwnam'):
                    # Extract the string arg being compared/looked up (first string arg)
                    s = self._extract_string_arg(insns, i, 'edi')
                    if s and s not in gate_strings:
                        gate_strings.append(s)

            elif name in _SINK_FUNCS and strcat_vas:
                # strcat chain seen before this sink — injection pattern present
                no_gate = not bool(gate_funcs)

                # Score severity
                if no_gate:
                    severity = 'HIGH'
                elif any(gs in ('root', 'hmcroot', 'hscroot') for gs in gate_strings):
                    severity = 'LOW'   # privileged role only
                elif 'getuid' in gate_funcs or 'geteuid' in gate_funcs:
                    severity = 'MEDIUM'
                else:
                    severity = 'MEDIUM'

                verdict = 'CONFIRMED' if (alloc_va or strcat_vas) and no_gate else 'PLAUSIBLE'

                gate_note = (
                    'no access gate detected' if no_gate else
                    f'gate: {", ".join(gate_funcs)} ({gate_strings!r})'
                )
                note = (
                    f'argv accumulation via strcat × {len(strcat_vas)} → {name}(); '
                    f'{gate_note}'
                )

                findings.append(ArgvBuildFinding(
                    func_va=func_va,
                    alloc_va=alloc_va,
                    strcat_vas=list(strcat_vas),
                    sink_va=insn.address,
                    sink_name=name,
                    gate_funcs=list(gate_funcs),
                    gate_strings=list(gate_strings),
                    no_gate=no_gate,
                    verdict=verdict,
                    severity=severity,
                    note=note,
                ))

        return findings

    def scan(self) -> List[ArgvBuildFinding]:
        """
        Scan all functions for malloc→strcat(argv[i])→sink injection patterns.
        """
        has_strcat = any(n in self._plt for n in _STRCAT_FUNCS)
        has_sink   = any(n in self._plt for n in _SINK_FUNCS)
        if not (has_strcat and has_sink):
            return []

        seen: Set[int] = set()
        results: List[ArgvBuildFinding] = []
        for va in self._ctx.func_starts:
            for f in self._scan_func(va):
                if f.sink_va not in seen:
                    seen.add(f.sink_va)
                    results.append(f)
        return results
