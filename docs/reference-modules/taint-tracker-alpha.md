# AlphaTaintTracker

## Why this exists

1. The existing `taint_tracker_*.py` family uses linear backward scans within a
   single basic block window. Taint does **not** cross basic block boundaries.

2. A register tainted on ONE path reaching a CFG merge point is not propagated
   to the merged state — there are no phi-node semantics at join points.

3. `BSR_RETVAL` terminates trace_arg at a call boundary. The callee is not
   entered, so return-value taint from wrapper functions is never discovered.

`AlphaTaintTracker` fixes all three gaps using forward CFG-fixpoint propagation.

## Constructor

```python
AlphaTaintTracker(
    data:       bytes,
    base:       int,
    sections:   Dict,
    gp_value:   Optional[int],
    sym_table:  Dict[int, str],   # VA → symbol name
)
```

Or from path:

```python
tracker = AlphaTaintTracker.from_path('/path/to/binary')
```

`from_path` uses `AlphaEcoffScanner._load()` to get data/gp/sections and
`_sym_table()` (if available) for symbol names.

## `scan_function(func_va, init_taint=None, callee_results=None, max_insns=4096)`

Scans a single function using CFG-fixpoint forward taint propagation:

1. Builds `cfg = AlphaCFGBuilder.build(func_va)`.
2. Seeds entry block with `init_taint` (default: r16–r21 all tainted with
   `TaintLabel('arg_N')` — conservative for library functions).
3. Worklist fixpoint: propagates `AlphaTaintState` forward along CFG edges.
   At join points, states are merged via `join()` (union of labels per register).
4. After fixpoint: sweeps for BSR calls to exec-class sinks where argument
   registers (r16–r21) are tainted.

**Exec-class sinks:** `system`, `popen`, `execl`, `execle`, `execlp`, `execv`,
`execve`, `execvp`, `execvpe`.

Returns `List[AlphaTaintFinding]`.

## `run_interprocedural(depth=3, max_insns=4096)`

Scans all functions in the binary, iterating up to `depth` times to propagate
callee return-value taint through wrapper chains:

```
iteration 0: scan all functions with no callee knowledge
iteration 1: for any function that called a sink with tainted args,
             mark its return value (r0) as tainted in callee_results
iteration 2: re-scan functions that call the above wrappers
...
```

Returns deduplicated `List[AlphaTaintFinding]` across all iterations.

## `AlphaTaintFinding`

```python
@dataclass
class AlphaTaintFinding:
    func_va:      int
    func_name:    str
    sink_va:      int
    sink_name:    str             # 'system', 'popen', etc.
    tainted_args: List[str]       # e.g. ['r16', 'r17']
    labels:       FrozenSet[TaintLabel]
    severity:     str = 'HIGH'
```

```python
str(finding)
# [HIGH] 0x120001234 (process_cmd): tainted {r16} -> system @ 0x120001278
# (labels: {arg_0})
```

## `AlphaTaintState`

```python
@dataclass
class AlphaTaintState:
    regs: Dict[str, FrozenSet[TaintLabel]]

state.get('r16')           # frozenset of TaintLabel
state.is_tainted('r16')   # bool
state.taint('r16', TaintLabel('argv'))
state.join(other_state)    # returns new merged state
```

## Transfer function

The internal `_transfer(va, word, state, callee_results)` function handles:

| Instruction | Taint effect |
|:---|:---|
| `LDA/LDAH` | ra → CLEAN (constant or address computation) |
| `LDQ/LDL` | ra ← labels of rb (the address base register) |
| `STQ/STL` | no register written; taint not propagated to memory model |
| `BSR` | ra ← callee_results.get(target_va, CLEAN); clobbers r0–r8 |
| `JSR/JMP` | r0 ← tainted if rb is tainted (indirect call — conservative) |
| `RET` | no register written |
| Integer ops | rc ← union(labels(rb), labels(lit_or_rb2)) |
| `BR/Bcc` | no register written |

Memory taint is not tracked (only register taint). This is intentional —
exec-class sinks in Alpha AXP firmware overwhelmingly take register arguments.

## Comparison with linear-scan trackers

| Property | `trace_arg()` / linear scan | `AlphaTaintTracker` |
|:---|:---|:---|
| Crosses basic blocks | No | Yes (worklist fixpoint) |
| Join at merge points | No | Yes (union of labels) |
| Callee return value | BSR_RETVAL (stops) | Models via `callee_results` |
| Memory taint | No | No |
| Speed | Fast (~1ms) | ~5–50ms per function |
