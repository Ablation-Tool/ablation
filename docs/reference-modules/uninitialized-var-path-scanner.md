# UninitializedVarPathScanner

## Why this module exists

Two gaps motivated this module:

1. No Ablation tool detected uninitialized stack variables on error paths. The pattern is common in stripped firmware where cleanup epilogues are shared by multiple predecessors, some of which jump past the initialization. This is distinct from `DeadSecurityCheckScanner` (unreachable checks) and `TruncationAtSinkScanner` (narrowing at assignment).
2. `CFGBuilder` provides predecessor maps but no consumer existed for the specific case where a merge-point block loads a stack slot that not all predecessors write to.

## UninitializedVarPathScanner.scan()

Iterates all functions via `ctx.func_starts`. For each function, builds a basic-block map and predecessor map, then finds merge-point blocks (two or more predecessors) that load stack slots not written by all incoming predecessors.

Returns a list of `UninitFinding` objects. Each finding identifies one merge block and one predecessor that does not store to the loaded slot.

```python
from modules.uninitialized_var_path_scanner import UninitializedVarPathScanner
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = UninitializedVarPathScanner.from_context(ctx)
findings = scanner.scan()
print(scanner.report(findings))
```

## UninitFinding fields

| Field | Type | Description |
| ----- | ---- | ----------- |
| `func_va` | int | VA of the containing function |
| `func_name` | str | Function name from BinaryContext, or sub_VA |
| `merge_va` | int | VA of the merge block (the epilogue or join point) |
| `slot` | str | Stack slot key such as `rbp-0x8` or `rsp+0x10` |
| `uninit_edge` | int | VA of one predecessor block that does not write to the slot |
| `confidence` | str | HIGH if no predecessor writes the slot; MEDIUM if some do |

## Confidence

HIGH means no predecessor block at the merge point stores to the slot before entering. MEDIUM means at least one predecessor writes the slot but at least one does not. The variable is initialized on some paths but not all.

## Architecture coverage

Stack slot detection covers x86-64, x86-32, ARM64, and ARM32. MIPS32 is partially covered. RISC-V and PPC are not covered.

## Limitations

The predecessor analysis is immediate-predecessor only. A store in a grandparent block that feeds all paths through a common intermediate block is not propagated forward and may produce a false positive finding. Verify each finding with `PathSolver.solve_path()` before reporting.

The instruction-level block splitting uses capstone-derived branch targets. Indirect branches such as computed jumps and tail calls produce incomplete CFGs that can cause false positives at merge points that are not true epilogues.

## Triage workflow

```python
# Confirm a finding before reporting
from modules.path_solver import chain_depth_weight

for f in findings:
    # Verify the uninit path is feasible
    # Then register and score
    weight = chain_depth_weight([f], path_length=2)
    print(f"{f.func_name}  slot={f.slot}  weight={weight:.1f}")
```

Do not report findings directly from this scanner without manual verification. The false-positive rate is higher than register-based analysis because stack slot tracking does not distinguish aliased slots or pointer-tracked storage.
