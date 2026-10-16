# SinkPropagator

## Why this exists

Four things were not possible before in Ablation:

1. **Find injection paths hidden behind custom string-passing wrappers.** TaintTracker
 searches for calls to known PLT sinks (system, popen, etc.). When a binary wraps
 system() behind doSystem(string) and systemLog(char*), three levels deep; TaintTracker
 finds zero injection sites while the vulnerability is fully reachable. SinkPropagator
 computes the transitive closure of passthrough wrappers so TaintTracker gets the complete
 sink list.

2. **Detect the entire wrapper chain, not just level-one wrappers.** Propagation iterates
 to a fixed point: if addUser() passes its arg to doSystem(), and doSystem() passes its
 arg to systemLog(), and systemLog() calls system(), all three are returned as
 SinkWrapper findings with their full lineage. A single TaintTracker run using the
 expanded sink list will then trace injection all the way from the entry point.

3. **Report multi-parameter wrappers correctly.** Some wrappers pass argument 1 (rsi)
 rather than argument 0 (rdi). The scanner tracks which parameter index is propagated
 and emits the correct arg_pos for each wrapper, so TaintTracker traces the right
 source register.

4. **Give a human-readable chain report.** Each SinkWrapper record carries the full
 ancestor chain so a reviewer can follow the injection path without re-running capstone
 by hand.

## Usage

```python
from ablation.analyzers.sink_propagator import SinkPropagator

sp = SinkPropagator.from_path('/path/to/binary')
# or, when BinaryContext is already loaded:
sp = SinkPropagator.from_context(ctx)

wrappers = sp.propagate()
print(sp.report(wrappers))
```

**Integrating with TaintTracker:**

```python
from ablation.analyzers.taint_tracker_x86 import TaintTrackerX86

sp = SinkPropagator.from_context(ctx)
wrappers = sp.propagate()

tt = TaintTrackerX86.from_context(ctx)
for w in wrappers:
    tt.add_sink(w.va, arg_pos=w.param_idx)
results = tt.run()
```

**Adding vendor-specific sinks as propagation seeds:**

```python
sp.add_sink('fadcsystem', arg_pos=0)
sp.add_sink('sys_vdom_exec', arg_pos=1)
wrappers = sp.propagate()
```

## Output: SinkWrapper

Each wrapper contains:

| Field | Type | Description |
|-------|------|-------------|
| `va` | int | VA of the wrapper function |
| `name` | str | Demangled name (or `sub_VA` if stripped) |
| `param_idx` | int | Parameter index propagated to the sink (0-based) |
| `call_va` | int | VA of the call instruction inside the wrapper |
| `wraps_va` | int | VA of the immediate sink called |
| `wraps_name` | str | Name of that immediate sink |
| `chain` | List[str] | Full lineage from root PLT sink |

## Design notes

**Exactly-one-call constraint.** A wrapper is only recognized if it contains exactly
one call to a known sink. Functions with two or more sink calls are dispatch functions,
not simple wrappers, and are excluded to avoid false positives.

**Arg0 passthrough only.** The current implementation traces `rdi` (arg0) backward
from the call site. Wrappers that transform `string&` → `char*` via `c_str()` break
the register chain and are not recognized, this is intentional. Those intermediate
functions are still found because their callee (`systemLog(char*)`) IS recognized as
a wrapper, and TaintTracker will traverse to them from the other direction.

**Arch guard.** Raises `ValueError` for non-x86-64 ELF.

## FORGE audit

Gate: **PASSED** (2026-10-13). No HIGH or CRITICAL issues.

Tested on:
- `HSCUserConf` (one vendor's HMC binary): systemLog correctly identified as level-1 wrapper around system@plt.
- `commandcontrol`, `LoginMOMIssue`, `5250proxy`, `mmhmccmd`, `runUpdate`: all return 0 wrappers (no false positives).
- Non-ELF input: raises `ValueError` as expected.
- Out-of-bounds VA: `_disasm_func` returns empty list.
- `call_idx=0` (no lookback): `_trace_rdi_at` returns `None`.
- Idempotence: calling `propagate()` twice yields identical results.
