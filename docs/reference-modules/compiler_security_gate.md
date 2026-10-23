# compiler_security_gate

Post-linker binary security gate. Runs Ablation's full vulnerability detector
suite on a freshly compiled binary (the output of `ld`) before it ships.

## Why post-linker matters

Traditional compiler security tools (LLVM sanitizers, `-fstack-protector`) run
**before** optimization on the IR. Optimization passes can then remove bounds
checks the sanitizer already approved, or introduce new unsafe code paths. The
gate runs on the final binary, after all optimization passes, so it sees what
actually ships, not what the compiler intended to ship.

## Architecture support

| Architecture | Taint tracker | Extra scanners |
|---|---|---|
| x86_64 | ✓ | format string, heap, length underflow |
| arm32 | ✓ |: |
| arm64 | ✓ |: |
| mips32 / mips64 | ✓ |: |
| ppc32 / ppc64 | ✓ |: |
| riscv32 / riscv64 | ✓ |: |
| loongarch64 | ✓ |: |

## DAG Adapter integration

Each taint finding is documented as a `SemanticBlock` using the `encoding_dag`
module's producer-consumer model:

```
TAINT_SOURCE (recv) → TAINT_CARRY (rdi) → TAINT_SINK (system, arg0)
```

The `DataflowEdge` entries make the path traversable with `SemanticBlock.dag_nodes()`,
giving any DAG-aware analysis the exact producer-consumer chain without walking
raw bytes or guessing at basic block boundaries.

## Usage

### Build system Makefile

```makefile
.PHONY: security-check
security-check: $(TARGET)
	python -m ablation.analyzers.compiler_security_gate $(TARGET)
	@echo "Security gate passed"

# Block on any finding severity:
security-check-strict: $(TARGET)
	python -m ablation.analyzers.compiler_security_gate $(TARGET) --strict
```

### Python API

```python
from ablation.analyzers.compiler_security_gate import CompilerSecurityGate

# Basic scan
gate = CompilerSecurityGate.from_path('./build/target')
findings = gate.scan()
print(gate.report(findings))

# With existing BinaryContext (avoids cache rebuild):
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('./build/target')
gate = CompilerSecurityGate.from_context(ctx)
findings = gate.scan()

# Filter to blocking findings only
blocking = [f for f in findings if f.severity in ('CRITICAL', 'HIGH')]

# Walk the taint DAG for a finding
for f in findings:
    if f.taint_dag is not None:
        for node in f.taint_dag.dag_nodes():
            print(node)
```

### CI integration

```yaml
# GitHub Actions
- name: Security gate
  run: |
    python -m ablation.analyzers.compiler_security_gate ./build/target
```

## Finding severities

| Severity | Meaning |
|---|---|
| CRITICAL | Taint reaches command injection sink system, execve, popen, Tcl_Eval, … |
| HIGH | Memory corruption: taint reaches strcpy/memcpy/sprintf size, or format string without literal, or unguarded length underflow |
| MEDIUM | Taint reaches controlled allocation size malloc/calloc |
| LOW | All other taint paths |

## Classes

### `GateFinding`

```python
@dataclass
class GateFinding:
    func_va: int
    site_va: int
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW
    category: str            # TAINT_FLOW / FORMAT_STRING / HEAP / LENGTH_UNDERFLOW
    description: str
    detector: str
    taint_dag: Optional[SemanticBlock]
```

### `CompilerSecurityGate`

```python
gate = CompilerSecurityGate.from_path(path)
gate = CompilerSecurityGate.from_context(ctx)

findings = gate.scan()          # List[GateFinding], sorted by severity
report   = gate.report()        # str, human-readable
exit_code = gate.check()        # int: 0=clean, 1=HIGH/CRITICAL found
exit_code = gate.check(strict=True)  # 1 on any finding
```

## Exit codes (CLI)

| Code | Meaning |
|---|---|
| 0 | No blocking findings |
| 1 | One or more HIGH or CRITICAL findings (or any finding with `--strict`) |

## Notes

- The gate shares BinaryContext's cache (`~/.ablation/cache/`). If the binary
 was already analyzed in the same session, rebuilding takes ~100ms.
- x86_64 only: `FormatStringScanner`, `HeapVulnScanner`, `LengthUnderflowScanner`.
 For other architectures, only the taint tracker runs.
- The `taint_dag` field is `None` for non-taint findings format string, heap, underflow.

---

## Why this exists

Prior to this module, compiler_security_gate required manual work outside the Ablation pipeline. This module integrates the capability directly so findings feed the shared `PatternLibrary` and `FindingRegistry` without a separate toolchain.

---

## How it works

`CompilerSecurityGate.from_path(path)` accepts a binary path and optionally a pre-built `BinaryContext`. Internally it runs `SinkArgClassifier` to classify all exec-sink call sites RODATA_CONST / ARG_PROPAGATED / UNKNOWN, then runs `TaintTracker` on ARG_PROPAGATED and UNKNOWN sites. `_taint_dag()` reconstructs a simplified taint chain from the raw taint results. `_normalize_taint()` converts each raw finding to a `GateFinding` with severity based on the sink name. Results are sorted by severity then virtual address.

---

## Pipeline position

**Before:** Requires a binary with a populated PLT map. `BinaryContext.load_or_build()` first if you want cached results.

**After:** Pass gate findings to `FindingRegistry`. Each `GateFinding` carries a `taint_chain` field ready for RE write-up.

---

## Reading findings

`CompilerSecurityGate.from_context(ctx).scan()` returns `List[GateFinding]`:

| Attribute | Content |
|:---|:---|
| `func_va` | Start VA of the function containing the finding |
| `site_va` | VA of the specific instruction or call site flagged |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `category` | `TAINT_FLOW` / `FORMAT_STRING` / `HEAP` / `LENGTH_UNDERFLOW` |
| `description` | One-line description of what was detected |
| `detector` | Name of the sub-scanner that produced this finding |
| `taint_dag` | `Optional[SemanticBlock]`: DAG adapter block for walking the taint path; `None` for non-taint findings format string, heap, underflow |

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
