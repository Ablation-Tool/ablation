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

```python
from ablation.analyzers.path_solver import PathSolver

results = PathSolver.from_context(ctx).run()
for r in results:
    print(r)
```

---

## Example output

```
# Output varies by module. See Usage section for representative examples.
```

---

## False positives

Core infrastructure modules do not emit security findings directly. False positives in downstream scanners are addressed at the scanner level, not here.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to build the analysis session.

**After this module:** Results feed directly into the analysis pipeline: `SemanticSearcher`, `TaintTracker`, or output modules depending on the task.

---

## Reading findings

| Field | Content |
|:---|:---|
| `result` | Module-specific output; see the class docstring for the exact type |

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
