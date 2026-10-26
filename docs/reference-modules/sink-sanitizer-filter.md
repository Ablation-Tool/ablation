# SinkSanitizerFilter

## Why this exists

2 gaps that made ARG_PROPAGATED triage the dominant manual cost of every x86-64
engagement TG-FAD-2:

1. **SinkArgClassifier and SanitizerDetector produced independent, unconnected
 output.** SinkArgClassifier identified exec-sink call sites where the argument
 comes from a caller-supplied register ARG_PROPAGATED. SanitizerDetector
 identified functions that enforce shell-safe allowlists. Neither knew about
 the other. The analyst had to disassemble each ARG_PROPAGATED site manually,
 find the sanitizer call, check that it gated the exec path, and confirm the
 same variable was validated, 30–60 minutes per site on a stripped binary.
 On FortiADC authd 221 functions this was 5 sites to triage manually.

2. **No automated guard verification.** Even when a sanitizer was obviously
 present in the function, confirming that a conditional branch on its return
 value actually blocked the exec path (vs. the sanitizer being called for
 logging only, with execution continuing unconditionally) required manual trace
 through the control flow.

Both gaps are closed by this module. It connects the two existing analyzers,
disassembles each ARG_PROPAGATED function, verifies the sanitizer-and-guard
pattern, and performs an arg-identity check (same register source at both call
sites) to rule out coincidental rdi sharing.

---

## What it does

`SinkSanitizerFilter` post-processes `List[SinkClassification]` output from
`SinkArgClassifier.classify_all()`.  For each `ARG_PROPAGATED` entry it runs
three checks on the containing function's disassembly:

| Check | What it verifies |
|---|---|
| **Sanitizer present** | A `SanitizerDetector`-identified `SHELL_SAFE` function is called within `_SANITIZER_SCAN_WINDOW` (256) instructions before the exec call |
| **Guard present** | Within `_GUARD_SCAN_WINDOW` (12) instructions after the sanitizer call: `test eax, eax` (or `cmp`) followed by a conditional jump: execution is blocked when the sanitizer rejects |
| **Arg identity** | `rdi` at the sanitizer call site and `rdi` at the exec call site both trace backward to the same source register same variable, not coincidental rdi sharing |

Sites passing all three are reclassified to `SANITIZER_VALIDATED` (severity
lowered from HIGH to LOW). Partial matches are left `ARG_PROPAGATED`.

### Arg-identity trace

`_trace_first_arg_sourceinsns, call_idx` scans backward from `call_idx` up
to 80 instructions looking for the instruction that last wrote to `rdi`:

- `mov rdi, rX` where `rX` is non-volatile r12–r15, rbx, rbp: follows one
 level backward to find what set rX.
- `mov rdi, [rX + N]`: returns `rX` as a proxy (struct-field load; matching
 base register is sufficient for the typical firmware save-restore pattern).
- `lea rdi, [rsp/rbp + N]`: returns `'STACK'` stack buffer address.
- Call instruction encountered before a setter: returns `None` (rdi was
 clobbered by the callee; source is unknown).
- No setter found within window: returns the current target register (rdi if
 never changed, the function's first argument passed through unchanged).

---

## Usage

```python
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
from ablation.analyzers.sink_sanitizer_filter import SinkSanitizerFilter

clf = SinkArgClassifier.from_path('/path/to/binary')
results = clf.classify_all()

flt = SinkSanitizerFilter.from_path('/path/to/binary')
results = flt.apply(results)

print(flt.report(results))

# Only exploit candidates
hot = [r for r in results
       if r.verdict not in ('RODATA_CONST', 'SNPRINTF_RODATA', 'SANITIZER_VALIDATED')]

# With BinaryContext (avoids rebuilding corpus twice):
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
clf = SinkArgClassifier.from_context(ctx)
flt = SinkSanitizerFilter.from_context(ctx)
results = flt.apply(clf.classify_all())
```

---

## API

### `SinkSanitizerFilter.from_pathpath: str → SinkSanitizerFilter`

Loads the binary, runs `SanitizerDetector.detect()`, builds the function-start
list. Run once; `apply()` is then cheap for any classification list.

### `SinkSanitizerFilter.from_context(ctx) → SinkSanitizerFilter`

Same as `from_path` but reuses an existing `BinaryContext` (shares function
starts; avoids rebuilding).

### `SinkSanitizerFilter.applyclassifications → List[SinkClassification]`

Main entry point. Returns a new list. `ARG_PROPAGATED` entries that pass all
three checks are replaced with a copy whose `verdict = 'SANITIZER_VALIDATED'`
and `severity = 'LOW'`. Non-`ARG_PROPAGATED` entries are returned unchanged
no side effects on the input list.

### `SinkSanitizerFilter.reportclassifications → str`

Prints two sections: SANITIZER_VALIDATED sites downgraded and ARG_PROPAGATED
sites remaining still require manual triage.

### `SANITIZER_VALIDATED = 'SANITIZER_VALIDATED'`

Module-level constant for verdict comparisons.

---

## Limitations

- **x86-64 only.** Arg-identity trace uses x86-64 register families and
 calling convention rdi as arg0. For PPC64, ARM64, or MIPS targets, use
 architecture-specific taint trackers.
- **Single-function scope.** Only scans within the function containing the
 exec call site. Sanitizer calls in caller functions interprocedural guards
 are not detected, use `TaintTracker.run_interprocedural()` for those.
- **Linear scan, not CFG.** The backward scan does not follow conditional
 branches. A sanitizer on an alternate path (not always executed before the
 exec call) could produce a false negative, but that pattern is also
 architecturally unsafe, so not downgrading it is the correct conservative choice.
- **Memory-dereference identity.** `mov rdi, [r14+0x10]` and `mov rdi, [r14+0x18]`
 both trace to `'r14'`, different struct fields sharing the same base register
 will match. False positives from this are extremely rare in practice (different
 string fields of the same struct would rarely both be passed to exec sinks in
 the same function).

---

## How it works

`applyclassifications` takes the `List[SinkClassification]` from `SinkArgClassifier.classify_all()` and disassembles each calling function. For each site, it performs an arg-identity trace backwards from the sink call to find a `call` to a shell-safe validator that writes the same argument register. If the validator is confirmed shell-safe (via `SanitizerDetector`) and the argument is the same value passed to the sink, the site's verdict is reclassified to `SANITIZER_VALIDATED` with severity lowered to `LOW`. No func_starts iteration: only the functions identified by the incoming classifications are disassembled.

---

## Example output

```
# Classifications in; same-length list out. Changed sites show updated verdict:
SinkClassification  call_va=0x00401f44  sink=system  arg=0  func=handle_request
  verdict: ARG_PROPAGATED → SANITIZER_VALIDATED  (validator: validate_input at 0x00401e80)
  severity: HIGH → LOW

SinkClassification  call_va=0x004023a0  sink=system  arg=0  func=run_command
  verdict: ARG_PROPAGATED  (no sanitizer found)
  severity: HIGH
```

---

## False positives

A function with multiple paths where the sanitizer is only on one branch produces a SANITIZER_VALIDATED verdict even if the other path is exploitable. The arg-identity trace is linear and does not build a CFG. For HIGH-risk sinks, verify the sanitizer is on all paths before marking as validated.

---

## Pipeline position

**Before this module:** `SinkArgClassifier.classify_all()`, this filter consumes its output directly. `BinaryContext.load_or_build()` and `SanitizerDetector` must also be built.

**After this module:** Pass remaining `ARG_PROPAGATED` / `UNKNOWN` sites to `FuncReachabilityAnalyzer` (eliminate dead-code findings), then `NetworkSinkFinder` (networked binaries), then `TaintTracker`. The `SANITIZER_VALIDATED` sites are excluded from taint analysis.

---

## Reading output

`SinkSanitizerFilter.from_path(path).applyclassifications` accepts and returns `List[SinkClassification]`: the same type as `SinkArgClassifier.classify_all()`. Sites where a shell-safe sanitizer guards the argument are reclassified to `verdict='SANITIZER_VALIDATED'` with `severity='LOW'`. All other sites pass through unchanged.

| Attribute | Content |
|:---|:---|
| `sink_name` | Name of the exec-class sink function |
| `arg_pos` | 0-indexed argument position |
| `func_va` | VA of the calling function |
| `call_va` | VA of the call instruction |
| `verdict` | Original verdict or `'SANITIZER_VALIDATED'` if a shell-safe guard was confirmed |
| `detail` | Trace description: updated to name the sanitizer if reclassified |
| `severity` | `'LOW'` for SANITIZER_VALIDATED and RODATA_CONST; `'HIGH'` for ARG_PROPAGATED |

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
