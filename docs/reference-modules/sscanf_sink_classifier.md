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
