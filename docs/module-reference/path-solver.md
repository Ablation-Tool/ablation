# PathSolver

**File:** `modules/path_solver.py`

## Why this exists

Bounded symbolic execution with Z3 path constraint solving for x86-64. Pipeline position: `cfg_builder → taint_tracker (finds sink VA) → path_solver (finds input)`. Enumerates all simple CFG paths from entry block to target block, symbolically executes each path, and asks Z3 to produce concrete register values at function entry that satisfy all constraints.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No file reads. No HTTP reads. No subprocess. No lief.parse(). Operates entirely on in-memory CFG and register state.
