# SignalHandlerRaceScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Detect async-signal-safety violations in signal handlers.** POSIX defines a fixed set of async-signal-safe functions (POSIX.1-2017 §2.4.3). Calling any other function from a signal handler is undefined behavior: if the signal fires while the main thread is inside `malloc()`, a recursive `malloc()` call from the handler corrupts the allocator's internal state. `TaintTracker` traces user-controlled data to exec sinks. No prior Ablation module tracked whether signal-registered functions called non-reentrant library functions. `SignalHandlerRaceScanner` finds `signal()`/`sigaction()` registrations, extracts the handler function, and checks whether the handler calls any of 57 known-unsafe functions directly or one call level deep.

## Usage

```python
from ablation.analyzers.signal_handler_race_scanner import SignalHandlerRaceScanner

scanner = SignalHandlerRaceScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = SignalHandlerRaceScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: SignalRaceFinding

| Field | Type | Description |
|-------|------|-------------|
| `handler_va` | int | VA of the signal handler function |
| `handler_name` | str | Demangled name or `sub_VA` if stripped |
| `register_va` | int | VA of the `signal()`/`sigaction()` call instruction |
| `unsafe_calls` | list[str] | Non-async-signal-safe functions reachable from the handler |
| `call_depth` | int | 0 for direct calls, 1 for calls through one intermediate function |

## Unsafe function set

57 functions tracked including:

- **Allocators:** `malloc`, `free`, `realloc`, `calloc`, `aligned_alloc`
- **stdio:** `printf`, `fprintf`, `sprintf`, `fopen`, `fclose`, `fflush`, `puts`, `perror`
- **Logging:** `syslog`, `openlog`, `closelog`
- **Process/thread:** `exit`, `pthread_create`, `pthread_mutex_lock`, `pthread_cond_wait`
- **Dynamic loading:** `dlopen`, `dlsym`, `dlclose`
- **String/env:** `strdup`, `getenv`, `setenv`, `strerror`

Note: `_exit` is async-signal-safe and is not flagged.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** verify each finding with `WindowAnalyzer.dump_text(handler_va)`. Confirm that the unsafe function is genuinely called, then check whether a signal mask blocks the relevant signal during the unsafe call in the main thread. If no mask is set, the race is exploitable.

## See also

- [BinaryContext](binary-context.md): function and PLT maps
- [SinkPropagator](sink-propagator.md): transitive call chain analysis
- [TaintTracker](taint-analysis.md): trace user input to exec sinks
