"""
signal_handler_race_scanner.py: Async-signal-safety violation detector.

Finds signal handlers registered via signal()/sigaction() that call
non-async-signal-safe functions. POSIX defines a fixed set of async-signal-safe
functions (POSIX.1-2017 §2.4.3). Calling any other function from a signal
handler is undefined behavior and a race condition: if the signal fires while
the main thread is inside malloc(), a second malloc() call from the handler
can corrupt the allocator's internal state.

Common culprits found in firmware:
  malloc, free, realloc, calloc  -- allocator is not reentrant
  printf, fprintf, sprintf       -- stdio uses non-reentrant locks
  syslog                         -- calls malloc internally
  exit, _exit                    -- only _exit is signal-safe; exit is not

Detection strategy:
  1. Find all signal()/sigaction() call sites and extract the handler VA.
  2. Build the call graph from each handler.
  3. Report any PLT call to a non-async-signal-safe function reachable from
     the handler (direct call or one level of call chain).

Usage:
    scanner = SignalHandlerRaceScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = SignalHandlerRaceScanner.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ── Unsafe functions ───────────────────────────────────────────────────────────

# These are NOT in the POSIX async-signal-safe list (POSIX.1-2017 §2.4.3)
_UNSAFE_FUNCTIONS: frozenset = frozenset({
    # Memory allocation
    'malloc', 'free', 'realloc', 'calloc', 'valloc', 'pvalloc',
    'aligned_alloc', 'posix_memalign',
    # stdio (all non-reentrant)
    'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf',
    'vsprintf', 'vsnprintf', 'puts', 'fputs', 'fputc', 'putchar',
    'fgets', 'fread', 'fwrite', 'fopen', 'fclose', 'fflush',
    'scanf', 'fscanf', 'sscanf', 'perror',
    # Logging
    'syslog', 'openlog', 'closelog',
    # Process/thread
    'exit', 'atexit', 'on_exit', 'pthread_create', 'pthread_mutex_lock',
    'pthread_mutex_unlock', 'pthread_cond_wait', 'pthread_cond_signal',
    # Dynamic loading
    'dlopen', 'dlsym', 'dlclose',
    # String/locale (uses malloc)
    'strdup', 'strndup', 'setlocale', 'nl_langinfo',
    # Misc
    'tmpfile', 'tmpnam', 'mktemp', 'getenv', 'putenv', 'setenv', 'unsetenv',
    'strerror', 'strsignal',
})

# Functions that register signal handlers
_SIGNAL_REGISTRARS: frozenset = frozenset({
    'signal', 'sigaction', 'bsd_signal', 'sysv_signal',
})


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class SignalRaceFinding:
    handler_va:    int         # VA of the signal handler function
    handler_name:  str         # name if available
    register_va:   int         # VA of the signal()/sigaction() call
    unsafe_calls:  list[str]   # list of unsafe functions called from handler
    call_depth:    int         # 0 = direct call, 1 = one level of indirection

    def fmt(self) -> str:
        unsafe_str = ', '.join(self.unsafe_calls)
        depth_note = 'direct' if self.call_depth == 0 else f'via call chain (depth {self.call_depth})'
        return (f"  HIGH    [SIGNAL_RACE]  {self.handler_name}\n"
                f"         registered at 0x{self.register_va:x}\n"
                f"         unsafe calls ({depth_note}): {unsafe_str}")


# ── Scanner ────────────────────────────────────────────────────────────────────

class SignalHandlerRaceScanner:
    """Detect async-signal-safety violations in signal handler functions."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'SignalHandlerRaceScanner':
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

    def _plt_va_map(self, ctx) -> dict[int, str]:
        """Return {plt_va: function_name} for all PLT entries."""
        result: dict[int, str] = {}
        for name, va in ctx.plt_entries():
            base = name.split('@')[0].lstrip('_')
            result[va] = base
        return result

    def _call_targets(self, ctx, func_va: int, plt_map: dict[int, str]) -> list[tuple[int, str]]:
        """Return list of (call_va, callee_name_or_va) for calls in func_va."""
        results: list[tuple[int, str]] = []
        for insn in ctx.disasm_func(func_va):
            mn = insn.mnemonic.lower()
            if mn not in ('call', 'bl', 'blx', 'jalr', 'jal'):
                continue
            target = _extract_call_target(insn)
            if target == 0:
                continue
            name = plt_map.get(target, ctx.name(target))
            results.append((insn.address, name))
        return results

    def _extract_handler_va(self, ctx, signal_call_va: int) -> int:
        """Try to extract the handler VA from the instruction before a signal() call."""
        insns = list(ctx.disasm_func_containing(signal_call_va))
        if not insns:
            return 0
        # Walk backwards from the signal() call looking for the handler arg load
        # signal(signum, handler): handler is the second arg (rsi/x1/a1)
        for insn in reversed(insns):
            if insn.address >= signal_call_va:
                continue
            mn = insn.mnemonic.lower()
            op = insn.op_str.lower()
            # x86-64: lea rsi, [rip+offset] or mov rsi, <immediate>
            if mn in ('lea', 'mov') and op.startswith('rsi'):
                target = _extract_imm_or_rip(insn)
                if target:
                    return target
            # ARM64: adrp + add x1,...  or mov x1,...
            if mn in ('adrp', 'mov') and op.startswith('x1'):
                target = _extract_imm_or_rip(insn)
                if target:
                    return target
            break  # only look at the immediately preceding instruction
        return 0

    def scan(self) -> List[SignalRaceFinding]:
        ctx = self._load_ctx()
        plt_map = self._plt_va_map(ctx)

        # Find all signal() / sigaction() PLT VAs
        registrar_vas: set[int] = set()
        for va, name in plt_map.items():
            if name in _SIGNAL_REGISTRARS:
                registrar_vas.add(va)
        if not registrar_vas:
            return []

        findings: list[SignalRaceFinding] = []

        for func_va in ctx.func_starts:
            calls = self._call_targets(ctx, func_va, plt_map)
            for call_va, callee_name in calls:
                # Find registrar calls
                callee_va = _name_to_plt_va(callee_name, plt_map)
                if callee_va not in registrar_vas:
                    continue

                # This function calls signal()/sigaction() — extract handler
                handler_va = self._extract_handler_va(ctx, call_va)
                if handler_va == 0:
                    continue
                if handler_va not in ctx.func_starts:
                    continue

                # Check direct unsafe calls from handler
                handler_calls = self._call_targets(ctx, handler_va, plt_map)
                unsafe_direct = [
                    name for _, name in handler_calls
                    if name in _UNSAFE_FUNCTIONS
                ]

                # Check one level of indirect calls
                unsafe_indirect: list[str] = []
                for _, callee in handler_calls:
                    callee_inner_va = ctx.name_to_va(callee) if hasattr(ctx, 'name_to_va') else 0
                    if callee_inner_va and callee_inner_va in ctx.func_starts:
                        inner_calls = self._call_targets(ctx, callee_inner_va, plt_map)
                        for _, inner_name in inner_calls:
                            if inner_name in _UNSAFE_FUNCTIONS and inner_name not in unsafe_direct:
                                unsafe_indirect.append(inner_name)

                all_unsafe = unsafe_direct + unsafe_indirect
                if not all_unsafe:
                    continue

                depth = 0 if unsafe_direct else 1
                findings.append(SignalRaceFinding(
                    handler_va=handler_va,
                    handler_name=ctx.name(handler_va),
                    register_va=call_va,
                    unsafe_calls=list(dict.fromkeys(all_unsafe)),  # deduplicate preserving order
                    call_depth=depth,
                ))

        return findings

    def report(self, findings: Optional[List[SignalRaceFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'SignalHandlerRaceScanner: no async-signal-safety violations in {self._path}'
        lines = [f'SignalHandlerRaceScanner: {len(findings)} violation(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_call_target(insn) -> int:
    try:
        op = insn.op_str.strip()
        if op.startswith('0x') or op.startswith('#0x'):
            return int(op.lstrip('#'), 16)
        return int(op, 16)
    except (ValueError, AttributeError):
        return 0


def _extract_imm_or_rip(insn) -> int:
    try:
        op = insn.op_str
        parts = op.split(',', 1)
        val_part = parts[1].strip() if len(parts) > 1 else parts[0].strip()
        val_part = val_part.strip('[]').strip()
        if '0x' in val_part.lower():
            for tok in val_part.split():
                if '0x' in tok.lower():
                    return int(tok.replace('+', '').replace('-', ''), 16)
    except Exception:
        pass
    return 0


def _name_to_plt_va(name: str, plt_map: dict[int, str]) -> int:
    for va, n in plt_map.items():
        if n == name:
            return va
    return 0
