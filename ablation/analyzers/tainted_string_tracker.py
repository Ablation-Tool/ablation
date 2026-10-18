"""
tainted_string_tracker.py: upgrade SAC SNPRINTF_RODATA verdicts where format args are tainted.

Why this exists:
  SinkArgClassifier classifies `system(buf)` as SNPRINTF_RODATA when it finds that
  `buf` was written by `snprintf(buf, n, fmt, ...)` with a RODATA constant format.
  That classification is correct about the format — but it says nothing about the
  format arguments. The pattern:

      snprintf(cmd, sizeof(cmd), "%s %s", argv[1], argv[2]);
      system(cmd);

  ...produces SNPRINTF_RODATA even though cmd contains argv[1] and argv[2].

  TaintedStringTracker finds the snprintf call that produced each SNPRINTF_RODATA
  buffer, classifies the format arguments (rcx, r8, r9 for x86_64; stack for i386),
  and upgrades the verdict to ARG_PROPAGATED when any format arg is tainted.

  Gap ID: SAC-FORMAT-001

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
    from ablation.analyzers.tainted_string_tracker import TaintedStringTracker

    ctx = BinaryContext.load_or_build('/path/to/binary')
    sac = SinkArgClassifier.from_context(ctx)
    results = sac.classify_all()

    tst = TaintedStringTracker.from_context(ctx)
    upgraded = tst.upgrade_snprintf_rodata(results)
    for u in upgraded:
        print(u)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass
class TaintedFormatResult:
    """An upgraded verdict: SAC said SNPRINTF_RODATA but format args are tainted."""
    sink_va: int           # VA of the system()/exec() call site
    sink_name: str         # 'system', 'popen', etc.
    snprintf_va: int       # VA of the snprintf that built the buffer
    tainted_args: List[str]   # which format arg registers were tainted (e.g. ['rcx'])
    arg_evidence: str      # human-readable backward trace

    @property
    def verdict(self) -> str:
        return 'ARG_PROPAGATED'

    def __str__(self) -> str:
        return (
            f'{self.sink_va:#010x} → {self.sink_name}()  '
            f'[upgraded: SNPRINTF_RODATA → ARG_PROPAGATED]  '
            f'snprintf at {self.snprintf_va:#x}, tainted args: {self.tainted_args}  '
            f'// {self.arg_evidence}'
        )


# ── Architecture-specific format arg registers ────────────────────────────────

# x86_64 SysV ABI: snprintf(rdi, rsi, rdx=fmt, rcx, r8, r9, ...)
_FMT_ARGS_X86_64 = ['rcx', 'r8', 'r9']
# i386 cdecl: snprintf(esp+0, esp+4, esp+8=fmt, esp+12, ...)
# For i386 we classify the stack push pattern, not register names
_FMT_ARGS_X86_32 = ['stack+12', 'stack+16', 'stack+20']


# ── Core classifier ───────────────────────────────────────────────────────────

def _classify_reg_at_call_x86_64(data: bytes, base_va: int, call_va: int, reg: str) -> Tuple[str, str]:
    """
    Backward-scan from `call_va` to classify what is in `reg` at the CALL.
    Mirrors the logic in SinkArgClassifier's _classify_arg0 but for arbitrary reg.
    Returns (verdict, evidence): RODATA_CONST / ARG_PROPAGATED / UNKNOWN
    """
    try:
        import capstone
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
    except ImportError:
        return 'UNKNOWN', 'capstone not available'

    call_off = call_va - base_va
    window_start = max(0, call_off - 512)
    window = data[window_start:call_off + 5]
    insns = list(cs.disasm(window, base_va + window_start))

    for i in range(len(insns) - 1, -1, -1):
        ins = insns[i]
        mnem = ins.mnemonic
        op = ins.op_str

        # MOV reg, src
        if mnem in ('mov', 'movq', 'movzx', 'movsx', 'movsxd') and op.startswith(reg + ','):
            src = op.split(',', 1)[1].strip()
            if src.startswith('0x') or src.lstrip('-').isdigit():
                return 'RODATA_CONST', f'mov {reg}, {src} (immediate) at {ins.address:#x}'
            if 'rip' in src:
                return 'RODATA_CONST', f'mov {reg}, [rip+...] (.rodata) at {ins.address:#x}'
            if 'rbp' in src and '-' in src:
                return 'ARG_PROPAGATED', f'mov {reg}, [rbp-...] (local/arg from frame) at {ins.address:#x}'
            if 'rsp' in src:
                return 'ARG_PROPAGATED', f'mov {reg}, [rsp+...] (stack) at {ins.address:#x}'
            # register-register copy: mark as UNKNOWN (would need deeper trace)
            return 'UNKNOWN', f'mov {reg}, {src} at {ins.address:#x}'

        # LEA reg, [...]
        if mnem == 'lea' and op.startswith(reg + ','):
            src = op.split(',', 1)[1].strip()
            if 'rip' in src:
                return 'RODATA_CONST', f'lea {reg}, [rip+...] (.rodata string) at {ins.address:#x}'
            if 'rbp' in src:
                return 'ARG_PROPAGATED', f'lea {reg}, [rbp...] (stack buf from frame) at {ins.address:#x}'
            if 'rsp' in src:
                return 'ARG_PROPAGATED', f'lea {reg}, [rsp...] (stack buf) at {ins.address:#x}'
            return 'UNKNOWN', f'lea {reg}, {src} at {ins.address:#x}'

        # XOR reg, reg (zeroing)
        if mnem == 'xor' and op.startswith(reg + ',') and reg in op.split(',', 1)[1]:
            return 'RODATA_CONST', f'xor {reg},{reg} (zeroed) at {ins.address:#x}'

    return 'UNKNOWN', f'{reg} source not found in window before {call_va:#x}'


def _find_preceding_call(data: bytes, base_va: int, search_end: int, target_va: int,
                         window_bytes: int = 1024) -> Optional[int]:
    """
    Scan backward from search_end for a CALL rel32 (0xe8) that calls target_va.
    Returns the VA of the call instruction, or None.
    """
    end_off = search_end - base_va
    start_off = max(0, end_off - window_bytes)
    for off in range(end_off - 5, start_off - 1, -1):
        if data[off] == 0xe8:
            rel32 = struct.unpack_from('<i', data, off + 1)[0]
            dest = (base_va + off + 5) + rel32
            if dest == target_va:
                return base_va + off
    return None


# ── Main class ────────────────────────────────────────────────────────────────

class TaintedStringTracker:
    """
    Upgrades SAC SNPRINTF_RODATA verdicts when snprintf format arguments are tainted.
    """

    def __init__(self, ctx) -> None:
        self._ctx = ctx
        self._data: bytes = Path(ctx.path).read_bytes()
        self._base_va: int = ctx.base_va
        self._arch: str = getattr(ctx, 'arch', 'x86_64')
        self._snprintf_va: Optional[int] = self._resolve_snprintf()

    @classmethod
    def from_context(cls, ctx) -> 'TaintedStringTracker':
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'TaintedStringTracker':
        from ablation.analyzers.binary_context import BinaryContext
        return cls(BinaryContext.load_or_build(path))

    def upgrade_snprintf_rodata(self, sac_results) -> List[TaintedFormatResult]:
        """
        Accepts a list of SAC result objects (anything with .verdict and .call_va).
        Returns a list of TaintedFormatResult for each SNPRINTF_RODATA verdict
        where at least one format argument is ARG_PROPAGATED.
        """
        if self._snprintf_va is None:
            return []

        upgraded: List[TaintedFormatResult] = []
        for r in sac_results:
            verdict = getattr(r, 'verdict', None)
            if verdict != 'SNPRINTF_RODATA':
                continue
            call_va = getattr(r, 'call_va', None) or getattr(r, 'address', None)
            if call_va is None:
                continue
            sink_name = getattr(r, 'sink', '') or getattr(r, 'sink_name', 'unknown')

            snprintf_call_va = _find_preceding_call(
                self._data, self._base_va, call_va, self._snprintf_va
            )
            if snprintf_call_va is None:
                continue

            tainted, evidence_parts = self._classify_format_args(snprintf_call_va)
            if tainted:
                upgraded.append(TaintedFormatResult(
                    sink_va=call_va,
                    sink_name=str(sink_name),
                    snprintf_va=snprintf_call_va,
                    tainted_args=tainted,
                    arg_evidence='; '.join(evidence_parts),
                ))

        return upgraded

    def report(self, results: List[TaintedFormatResult]) -> str:
        if not results:
            return 'TaintedStringTracker: 0 SNPRINTF_RODATA upgrades.\n'
        lines = [f'TaintedStringTracker: {len(results)} upgrade(s)']
        for r in sorted(results, key=lambda x: x.sink_va):
            lines.append(f'  {r}')
        return '\n'.join(lines) + '\n'

    # ── internals ─────────────────────────────────────────────────────────────

    def _resolve_snprintf(self) -> Optional[int]:
        """Find snprintf's VA from BinaryContext PLT."""
        plt: Dict[int, str] = getattr(self._ctx, 'plt', {})
        for va, name in plt.items():
            if name.split('@')[0].strip() in ('snprintf', '__snprintf_chk'):
                return va
        return None

    def _classify_format_args(self, snprintf_call_va: int) -> Tuple[List[str], List[str]]:
        """
        Classify the format arguments of the snprintf call at snprintf_call_va.
        Returns (tainted_arg_names, evidence_list).
        """
        tainted: List[str] = []
        evidence: List[str] = []

        if self._arch == 'x86_64':
            for reg in _FMT_ARGS_X86_64:
                verdict, ev = _classify_reg_at_call_x86_64(
                    self._data, self._base_va, snprintf_call_va, reg
                )
                if verdict == 'ARG_PROPAGATED':
                    tainted.append(reg)
                    evidence.append(ev)
        # i386 and other arches: not yet implemented; return empty (no false positives)

        return tainted, evidence
