# SscanfSinkClassifier

`ablation/analyzers/sscanf_sink_classifier.py`

## Why this exists

Three gaps in the existing x86-64 sink analysis chain:

1. **SinkArgClassifier does not analyze sscanf-family sinks.** It classifies the command string argument at exec-class sinks (system/popen/execve). It does not classify the format string at sscanf/scanf/fscanf, the vuln class where `sscanf(input, "%s", buf)` overflows `buf` when `input` is attacker-controlled.

2. **sscanf format strings require a different analysis target.** For exec-class sinks, the question is "where did the command string come from?" For sscanf, the question is "does the format string allow writing past the destination buffer?" These require tracing different argument registers and a second-pass scan of the resolved bytes.

3. **Four sscanf callers in libwmshared.so (session 18) required full manual disassembly.** The most interesting one (0x2c3550) used a dynamically-constructed format `%46s %lu %d` built via `snprintf`. This module would have auto-classified it as DYNAMIC_FMT, reducing work to: confirm snprintf format template is constant. The remaining three would have been classified by register trace without manual capstone trace.

## Entry points

```python
from ablation.analyzers.sscanf_sink_classifier import SscanfSinkClassifier

# From path
clf = SscanfSinkClassifier.from_path('/path/to/binary')
results = clf.classify_all()
flagged = [r for r in results if r.needs_investigation]
print(clf.report(results))

# With existing BinaryContext (avoids redundant LIEF parse)
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build(path)
clf = SscanfSinkClassifier.from_context(ctx)
```

## Verdicts

| Verdict | Severity | Meaning |
|---------|----------|---------|
| `RODATA_SAFE` | LOW | Format in `.rodata`, no unbounded `%s`. ELIMINATED. |
| `RODATA_UNSAFE` | HIGH | Format in `.rodata`, has unbounded `%s` (e.g., `"%s %d"`). |
| `DYNAMIC_FMT` | MEDIUM | Runtime-built via snprintf. Verify format template is constant. |
| `ARG_PROPAGATED` | HIGH | Format came from a caller argument. Format injection risk. |
| `UNKNOWN` | MEDIUM | Provenance not resolved in 40-instruction window. |

## Default sinks

| Sink | Format arg |
|------|-----------|
| `sscanf(str, fmt,...)` | rsi (arg 1) |
| `vsscanf(str, fmt, ap)` | rsi (arg 1) |
| `__isoc99_sscanf(str, fmt,...)` | rsi (arg 1) |
| `scanf(fmt,...)` | rdi (arg 0) |
| `__isoc99_scanf(fmt,...)` | rdi (arg 0) |
| `fscanf(file, fmt,...)` | rsi (arg 1) |
| `__isoc99_fscanf(file, fmt,...)` | rsi (arg 1) |

## Format string analysis (`_has_unbounded_s`)

Parses the resolved `.rodata` format string byte-by-byte to detect `%s` without an explicit width specifier. Handles:

- `%s` → UNSAFE (no width)
- `%20s` → SAFE (explicit width 20)
- `%05s` → SAFE (`0` consumed as flag, `5` is width)
- `%*s` → SAFE (assignment-suppressed: no buffer write)
- `%%` → SAFE (escaped percent, not a specifier)
- `%ls`, `%hs` → UNSAFE (length modifier, no width)

Known limitation: `%[...]` character-class specifiers without a width are also unbounded but are not detected. Only `%s` conversion is checked.

## DYNAMIC_FMT detection

When the format register traces to a stack slot that was previously written by a snprintf call, the verdict is DYNAMIC_FMT. The format string itself cannot be verified statically.

Workflow for DYNAMIC_FMT sites:
1. Find the snprintf call in the disassembly
2. Trace the snprintf format argument (rdx for snprintf, r8 for `__snprintf_chk`)
3. If that format is RODATA_CONST → the runtime format has bounded `%s` from a constant template (safe)
4. If that format is ARG_PROPAGATED → format injection risk

## Workflow position

After `SinkArgClassifier.classify_all()`, run `SscanfSinkClassifier.classify_all()` on the same binary:

```python
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
from ablation.analyzers.sscanf_sink_classifier import SscanfSinkClassifier

# Shell exec sinks
shell_results = SinkArgClassifier.from_context(ctx).classify_all()

# sscanf format string sinks
fmt_results = SscanfSinkClassifier.from_context(ctx).classify_all()
flagged_fmt = [r for r in fmt_results if r.needs_investigation]
```

## FORGE audit

gate_passed=True. 1 MEDIUM finding (dead-sink filter when `_plt_caller_counts` empty, fixed before recording).

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Usage

```python
from ablation.analyzers.sscanf_sink_classifier import SscanfSinkClassifier

results = SscanfSinkClassifier.from_context(ctx).run()
for r in results:
    print(r)
```

---

## Example output

```
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `finding_type` | Scanner-specific category label |
| `va` | Virtual address of the call site or instruction in the binary |
| `func_va` | Virtual address of the containing function |
| `detail` | What was found and the specific condition that triggered it |
| `sink_name` | Name of the dangerous function reached (if applicable) |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
