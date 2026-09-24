"""
func_profiler.py: Single-call complete function analysis block.

Combines BinaryContext (strings/PLT), RegAnnotator (arg values), and sink
detection into one compact report. Replaces the 4-call manual sequence:
callees_of -> dump_text -> annotate_calls -> string lookup.

Usage:
    fp = FuncProfiler.from_path('/path/to/binary')
    print(fp.profile(va=0x1000, end_va=0x1200).fmt())

    # With target-specific sinks:
    fp = FuncProfiler.from_path(binary, custom_sinks={'exec_handler': [2]})
    print(fp.profile(va=0x1000, end_va=0x1200).fmt())

Example output:
    [FUNC 0x1000..0x1200]  357B  11 calls  4 strings  2 SINKS

    STRINGS:
      0x8000  '/bin/target-binary'
      0x1a5f10  '--output-path'
      0x1a5f28  '/var/private/test-path'
      0x1a5e00  'help'

    CALLS:
      0x1050  strcmp(rdi='help', rsi=[arg1_entry+0x0])
      0x10c0  exec_by_pipe(rsi=0x3, rdx=0)
      0x1090  strcmp(rsi='--output-path')
      0x1058  strcmp(rsi='/var/private/test-path')
      0x106d  printf(rdi='--output-path must be %s', rsi='/var/private/test-path')
      0x1100  exec_handler(rdi='/bin/target-binary', rsi=arg0_entry, rdx=arg1_entry)  *** SINK ***
      0x1180  exec_handler(rdi='/bin/target-binary', rsi=arg0_entry, rdx=arg1_entry)  *** SINK ***
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .binary_context import BinaryContext
from .reg_annotator import RegAnnotator, CallSite, RegVal, _ARG_REGS
from .arm32_reg_annotator import ARM32RegAnnotator

# Known dangerous sinks: symbol name -> reason tag
_DEFAULT_SINKS: Dict[str, str] = {
    # memory corruption
    'strcpy':   'buffer-overflow',
    'strcat':   'buffer-overflow',
    'stpcpy':   'buffer-overflow',
    'wcscpy':   'buffer-overflow',
    'sprintf':  'buffer-overflow',
    'vsprintf': 'buffer-overflow',
    'gets':     'buffer-overflow',
    # command execution
    'system':   'cmd-exec',
    'popen':    'cmd-exec',
    'execv':    'cmd-exec',
    'execve':   'cmd-exec',
    'execvp':   'cmd-exec',
    'execl':    'cmd-exec',
    'execlp':   'cmd-exec',
    'execvpe':  'cmd-exec',
    'exec_handler': 'cmd-exec',
    # Tcl injection
    'Tcl_Eval':          'tcl-inject',
    'Tcl_EvalEx':        'tcl-inject',
    'Tcl_EvalObjEx':     'tcl-inject',
    'Tcl_GlobalEval':    'tcl-inject',
    'Tcl_GlobalEvalObj': 'tcl-inject',
    # format string
    'printf':   'fmt-string',
    'fprintf':  'fmt-string',
    'syslog':   'fmt-string',
    # filesystem
    'unlink':   'filesystem',
    'rename':   'filesystem',
    'fopen':    'filesystem',
    'open':     'filesystem',
}


@dataclass
class ProfiledCall:
    site: CallSite
    sink_tag: str = ""

    @property
    def is_sink(self) -> bool:
        return bool(self.sink_tag)

    def fmt(self, arg_regs=None) -> str:
        regs = arg_regs or _ARG_REGS
        parts = []
        for reg in regs:
            v = self.site.args.get(reg)
            if not v or v.kind == 'unknown':
                continue
            # Skip ret() values for non-sink calls: they add noise without insight
            if v.kind == 'ret' and not self.is_sink:
                continue
            parts.append(f"{reg}={v.display()}")
        args_str = ', '.join(parts)
        name = self.site.target_name or f"0x{self.site.target_va:x}"
        line = f"  0x{self.site.site_va:x}  {name}({args_str})"
        if self.is_sink:
            line += f"  *** SINK ({self.sink_tag}) ***"
        return line


@dataclass
class FuncProfile:
    va: int
    end_va: int
    size: int
    strings: List[Tuple[int, str]]
    calls: List[ProfiledCall]
    binary_name: str = ""

    @property
    def sink_calls(self) -> List[ProfiledCall]:
        return [c for c in self.calls if c.is_sink]

    def fmt(self, show_unknown_only_if_sink: bool = True) -> str:
        n_sinks = len(self.sink_calls)
        header = (
            f"[FUNC 0x{self.va:x}..0x{self.end_va:x}]"
            f"  {self.size}B"
            f"  {len(self.calls)} calls"
            f"  {len(self.strings)} strings"
        )
        if n_sinks:
            header += f"  {n_sinks} SINK{'S' if n_sinks > 1 else ''}"
        if self.binary_name:
            header = f"[{self.binary_name}] " + header

        lines = [header]

        if self.strings:
            lines.append("")
            lines.append("  STRINGS:")
            for va, s in self.strings:
                preview = s[:60] + "..." if len(s) > 60 else s
                lines.append(f"    0x{va:x}  '{preview}'")

        if self.calls:
            lines.append("")
            lines.append("  CALLS:")
            for pc in self.calls:
                # Filter: show all args if sink, otherwise show only non-unknown
                lines.append(pc.fmt())

        return "\n".join(lines)

    def has_sink(self, name: str) -> bool:
        return any(c.site.target_name == name for c in self.sink_calls)


class FuncProfiler:
    """
    Complete function profile in a single call.

    Combines RegAnnotator (arg values at call sites) + BinaryContext
    (string table for cross-referencing addresses) + sink detection.
    """

    def __init__(
        self,
        binary_path: str,
        ctx: Optional[BinaryContext] = None,
        custom_sinks: Optional[Dict[str, str]] = None,
    ):
        self.path = binary_path
        self._ctx = ctx or BinaryContext.load_or_build(binary_path)
        if self._ctx.arch == 'arm32':
            self._ra = ARM32RegAnnotator.from_context(self._ctx)
        else:
            self._ra = RegAnnotator.from_path(binary_path)
        self._sinks: Dict[str, str] = {**_DEFAULT_SINKS}
        if custom_sinks:
            self._sinks.update(custom_sinks)

    @classmethod
    def from_path(
        cls,
        binary_path: str,
        custom_sinks: Optional[Dict[str, str]] = None,
    ) -> "FuncProfiler":
        return cls(binary_path, custom_sinks=custom_sinks)

    @classmethod
    def from_context(
        cls,
        ctx: BinaryContext,
        custom_sinks: Optional[Dict[str, str]] = None,
    ) -> "FuncProfiler":
        return cls(ctx.path, ctx=ctx, custom_sinks=custom_sinks)

    # ── query API ─────────────────────────────────────────────────────────────

    def profile(
        self,
        va: int,
        end_va: int = 0,
        window: int = 2048,
        seed_args: bool = True,
    ) -> FuncProfile:
        """
        Build a complete function profile.

        va:       function start VA
        end_va:   function end VA (0 = use next func_start from BinaryContext)
        window:   fallback window if end_va not determinable
        seed_args: pre-seed entry arg registers (rdi=arg0, rsi=arg1, ...)
        """
        if end_va == 0:
            end_va = self._estimate_end(va, window)

        result = self._ra.annotate_calls(va, end_va, window=window, seed_args=seed_args)

        # Collect strings referenced in this function's region
        strings = self._collect_strings(va, end_va, result)

        # Build profiled calls with sink detection
        calls: List[ProfiledCall] = []
        for cs in result.calls:
            tag = self._sinks.get(cs.target_name, "")
            calls.append(ProfiledCall(site=cs, sink_tag=tag))

        binary_name = Path(self.path).name
        return FuncProfile(
            va=va,
            end_va=end_va,
            size=end_va - va,
            strings=strings,
            calls=calls,
            binary_name=binary_name,
        )

    def profile_many(
        self,
        vas: List[int],
        window: int = 2048,
    ) -> List[FuncProfile]:
        """Profile multiple functions, returning list in same order."""
        return [self.profile(va, window=window) for va in vas]

    def sinks_in_region(self, va: int, end_va: int = 0, window: int = 4096) -> List[ProfiledCall]:
        """Return only sink calls in a function region. Quick triage."""
        p = self.profile(va, end_va, window)
        return p.sink_calls

    # ── helpers ───────────────────────────────────────────────────────────────

    def _estimate_end(self, va: int, window: int) -> int:
        """Use BinaryContext func_starts to find next function boundary."""
        starts = self._ctx.func_starts
        if not starts:
            return va + window
        import bisect
        idx = bisect.bisect_right(starts, va)
        if idx < len(starts):
            next_start = starts[idx]
            gap = next_start - va
            if 16 <= gap <= window:
                return next_start
        return va + window

    def _collect_strings(
        self,
        func_va: int,
        func_end_va: int,
        result,
    ) -> List[Tuple[int, str]]:
        """
        Collect all .rodata strings referenced in this function.

        Two sources:
        1. RegAnnotator found a RegVal.string -> its VA is in the trace
        2. BinaryContext.strings_near the function's VA range
        """
        seen: Set[int] = set()
        strings: List[Tuple[int, str]] = []

        # From RegAnnotator traces: extract string VAs
        for call in result.calls:
            for rv in call.args.values():
                self._collect_rv_strings(rv, seen, strings)

        # From BinaryContext: scan for string references in a larger radius
        # to catch strings in the region not caught by reg trace
        mid = (func_va + func_end_va) // 2
        radius = max((func_end_va - func_va) * 2, 512)
        for sva, s in self._ctx.strings_near(mid, radius=radius):
            if sva not in seen:
                seen.add(sva)
                strings.append((sva, s))

        return sorted(strings, key=lambda x: x[0])

    def _collect_rv_strings(
        self,
        rv: RegVal,
        seen: Set[int],
        out: List[Tuple[int, str]],
        depth: int = 0,
    ) -> None:
        if depth > 4 or rv is None:
            return
        if rv.kind == 'string':
            # Try to find the VA for this string
            for va, s in self._ctx.strings.items():
                if s == rv.str_val and va not in seen:
                    seen.add(va)
                    out.append((va, s))
                    break
        if rv.kind == 'copy' and rv.chain:
            self._collect_rv_strings(rv.chain, seen, out, depth + 1)
