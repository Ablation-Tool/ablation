# PathSolver

**File:** `modules/path_solver.py`

## Why this exists

Bounded symbolic execution with Z3 path constraint solving for x86-64. Pipeline position: `cfg_builder → taint_tracker (finds sink VA) → path_solver (finds input)`. Enumerates all simple CFG paths from entry block to target block (DFS, bounded by `max_path_blocks`), symbolically executes each path (register expressions as Z3 BitVec), and asks Z3 to produce concrete register values at function entry that satisfy all constraints. Supports struct-aware memory seeding (`MemoryConstraint`) for constraining field-offset reads on a known struct pointer.

## Key API

```python
from modules.path_solver import PathSolver, PathResult, MemoryConstraint, solve_for_sink

# Full run: returns all paths solved (up to max_paths)
ps = PathSolver(data, func_va, func_end_va, plt, cfg, md,
                max_path_blocks=40, max_paths=50, z3_timeout_ms=5000)
results = ps.solve(target_va=0x5747a)
for r in results:
    if r.sat:
        print(r.model)  # {reg_name: int}

# Quick first-SAT
first = ps.solve_first_sat(target_va=0x5747a)

# One-call wrapper
first = solve_for_sink(data, func_va, func_end_va, plt, cfg, md, target_va=0x5747a)

# Struct seeding: constrain memory reads at (base_reg, byte_offset)
seed = {
    ("rbx", 0x2b): MemoryConstraint("attr_type", width=8, lo=0, hi=255),
    ("rbx", 0x2c): MemoryConstraint("attr_len",  width=8, lo=4, hi=255),
    ("rbx", 0x2e): MemoryConstraint("vendor_id", width=32, exact=311),
}
ps = PathSolver(data, func_va, func_end_va, plt, cfg, md, struct_seed=seed)
```

## FORGE audit

Gate: **PASSED**. No file reads. No network I/O. No subprocess. No lief.parse(). No bare `except:`. Z3 solver bounded by `z3_timeout_ms` (default 5000 ms). Path enumeration bounded by `max_path_blocks` (40) and `max_paths` (50). Operates entirely on in-memory CFG and register state.

---

## How it works

Provides the session state, indexing, and utility functions that other Ablation modules depend on. The implementation details vary by class; see the class-level docstrings and the relevant workflow docs for specifics.

---

## Usage

See **Key API** above. The full pipeline usage:

```python
from modules.path_solver import PathSolver, MemoryConstraint, solve_for_sink
from ablation.analyzers.binary_context import BinaryContext
import capstone, lief

ctx = BinaryContext.load_or_build('/path/to/target.elf')

# Get data + capstone handle for the function
elf = lief.parse('/path/to/target.elf')
text_sec = elf.get_section('.text')
data = bytes(text_sec.content)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# Build CFG from taint tracker result, then solve
# func_va and target_va come from TaintTracker findings
ps = PathSolver(data, func_va=0x12000, func_end_va=0x12800,
                plt={}, cfg=cfg, md=md)
results = ps.solve(target_va=0x12340)
for r in results:
    if r.sat:
        print(r)   # [SAT] path=0x12000 -> 0x12200 -> 0x12340 model=(rdi=0x41414141)
```

---

## Example output

```
[SAT] path=0x12000 -> 0x12200 -> 0x12340 clauses=37 model=(rdi=0x41414141, rsi=0x0)
[UNSAT] path=0x12000 -> 0x12100 -> 0x12340 clauses=22
[timeout] path=0x12000 -> 0x12180 -> 0x12340 clauses=51
```

---

## False positives

**Z3 `UNSAT` on a real path** — the symbolic executor uses bounded BitVec arithmetic; path constraints from loop-carried values or indirect memory reads may be over-constrained, producing `UNSAT` on a path that is actually reachable. Increase `max_path_blocks` or add struct seeding for struct-pointer reads to give Z3 more context.

**`sat=True` on an infeasible path** — under-constrained memory reads (fields Z3 leaves unconstrained) may produce concrete models that satisfy the formula but are not actually reachable in the program. Always confirm the `model` values make semantic sense for the vulnerability class (e.g., an overlong length field should be larger than the allocation size).

---

## Pipeline position

**Before this module:** `TaintTracker` (provides `sink_va`) and `cfg_builder` or `analysis_arm64.build_cfg()` (provides `cfg`).

**After this module:** A `PathResult` with `sat=True` confirms the finding is reachable. Register the finding with `FindingRegistry.register()` and write to `re/<vendor>/<target>_re.py`.

---

## Reading output

`PathSolver.solve(target_va)` returns `List[PathResult]`:

| Attribute | Content |
|:---|:---|
| `sat` | `True` if Z3 found a satisfying assignment |
| `path` | `List[int]` — basic block VAs on the solved path |
| `model` | `Dict[str, int]` — concrete register values at function entry (only when `sat=True`) |
| `clauses` | Number of Z3 clauses added during path constraint solving |
| `note` | `'timeout'`, `'unsat'`, or empty string |
| `seeded_fields` | `List[str]` — struct field names from `MemoryConstraint` that constrained this path |
| `model` | `Dict[str, int]` — concrete register values at function entry that satisfy the path |
| `clauses` | Number of Z3 clauses added during solving |
| `note` | Reason string if `sat=False` (e.g., `'timeout'`, `'unsat'`) |
| `seeded_fields` | `List[str]` — struct field names that were used to constrain the path |

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
