# SnprintfVariableFilter

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [Class and method reference](#class-and-method-reference)
- [Usage](#usage)
- [Example output](#example-output)
- [False positives](#false-positives)
- [Pipeline position](#pipeline-position)
- [Reading findings](#reading-findings)
- [See also](#see-also)

---

## Why this exists

`SinkArgClassifier` (SAC) verdicts `SNPRINTF_RODATA` when the format string passed to `snprintf`/`__snprintf_chk` is in `.rodata`. That verdict is correct — the format string literal is hardcoded. But it is **insufficient** to rule out injection.

A format string like:

```c
snprintf(cmd, sizeof(cmd), "/bin/netstat -rn -4 | /bin/grep -w -F '%s'", gateway_ip);
popen(cmd, "r");
```

has its format string in `.rodata`, so SAC says `SNPRINTF_RODATA` — but the `%s` consumes a caller-supplied string argument. If `gateway_ip` is attacker-controlled, the resulting `cmd` is injectable.

Three gaps this fills:

1. **SNPRINTF_RODATA underreporting** — SAC correctly classifies the format string provenance but does not inspect the format string content. This filter does.
2. **Severity signal** — after upgrading to `SNPRINTF_RODATA_VARIABLE`, the severity is set to `HIGH`, matching what a taint analysis would conclude for an externally-controlled `%s` argument.
3. **`%n` detection** — a `%n` specifier in a format string that reaches `snprintf` is a write primitive. SAC does not detect this; this filter does.

---

## How it works

`SnprintfVariableFilter.apply()` iterates over a list of `SinkClassification` results from SAC. For each `SNPRINTF_RODATA` result:

1. Extract the format string VA from the `detail` field using three strategies:
   - **Strategy 1**: detail already contains a decoded string literal (`fmt='...'`).
   - **Strategy 2**: (currently falls through — rip-relative displacement without call-site VA cannot reconstruct absolute VA from detail alone).
   - **Strategy 3**: scan the detail for any hex address with 5+ digits, read bytes from that offset in the binary, and check if it looks like a format string (`%` present, null-terminated, ≥ 2 bytes).
2. If a format string is found, run `_VARIABLE_SPEC_RE` against it.
3. On a match, shallow-copy the `SinkClassification`, set `verdict = SNPRINTF_RODATA_VARIABLE`, `severity = 'HIGH'`, and append the decoded format string to `detail`.

### Specifiers flagged

| Specifier | Reason |
|-----------|--------|
| `%s`, `%S` | String argument — shell metacharacter injection vector |
| `%n`, `%N` | Write-to-pointer — memory safety |
| `%*s` (star width) | Argument-controlled width — indirect control |

### Specifiers NOT flagged

`%d`, `%i`, `%u`, `%x`, `%o`, `%f`, `%g`, `%e`, `%c`, `%p` — numeric/pointer arguments. No string content injectable via these.

---

## Class and method reference

### `SnprintfVariableFilter`

```python
class SnprintfVariableFilter:
    from_context(ctx) -> SnprintfVariableFilter
    SnprintfVariableFilter(binary_path: str)
```

#### `apply(results: List[SinkClassification]) -> List[SinkClassification]`

Return a new list. `SNPRINTF_RODATA` entries with injectable specifiers are replaced by shallow copies with `verdict=SNPRINTF_RODATA_VARIABLE` and `severity=HIGH`. All other entries pass through unchanged. Input list is not modified.

#### `fmt_string_at(va: int) -> Optional[bytes]`

Read a null-terminated format string from `va` in the binary. Returns `None` if `va` is out of range or no null terminator is found.

#### `has_variable_specifier(fmt_bytes: bytes) -> bool`

Return `True` if `fmt_bytes` contains a variable-injection specifier (`%s`, `%S`, `%n`, `%N`, or star-width variants).

### `SNPRINTF_RODATA_VARIABLE`

The new verdict string: `'SNPRINTF_RODATA_VARIABLE'`. Import it to filter results:

```python
from ablation.analyzers.snprintf_variable_filter import SNPRINTF_RODATA_VARIABLE
```

---

## Usage

```python
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
from ablation.analyzers.snprintf_variable_filter import (
    SnprintfVariableFilter, SNPRINTF_RODATA_VARIABLE
)

sac     = SinkArgClassifier.from_context(ctx)
results = sac.classify_all()

filt    = SnprintfVariableFilter.from_context(ctx)
results = filt.apply(results)

for r in results:
    if r.verdict == SNPRINTF_RODATA_VARIABLE:
        print(f"{r.func_va:#x}  {r.sink_name}  {r.detail}")
```

---

## Example output

Before filtering (SAC output):

```
popen @ 0x001591f0  SNPRINTF_RODATA  fmt=LEA [rip+0x3a1c0] in .rodata
```

After filtering:

```
popen @ 0x001591f0  SNPRINTF_RODATA_VARIABLE  HIGH
  fmt=LEA [rip+0x3a1c0] in .rodata
  fmt=b"/bin/netstat -rn -4 | /bin/grep -w -F '%s'"
```

---

## False positives

**Format strings that look like function calls.** A format string containing `%s` where the `%s` argument is always a compile-time constant (e.g., error strings from a table) will be flagged even though no runtime injection is possible. To rule these out, check the `%s` argument source via `TaintTracker` or `SinkArgClassifier` on the snprintf call itself.

**Strategy 3 VA collision.** If the detail string contains a hex number that happens to match a `.rodata` offset containing a coincidental `%` byte, the filter will read that as a format string and flag it. This is rare (requires an `%` byte at a known-looking VA). Strategy 1 (embedded string) takes precedence and is exact.

---

## Pipeline position

```
BinaryContext → SinkArgClassifier.classify_all()
    → SnprintfVariableFilter.apply()    ← here
    → filter(verdict == SNPRINTF_RODATA_VARIABLE)
    → TaintTracker (on the %s argument of the snprintf call)
```

Apply immediately after `SAC.classify_all()`, before any triage. The upgraded verdict ensures `SNPRINTF_RODATA_VARIABLE` findings are not silently deprioritized against `ARG_PROPAGATED` findings.

---

## Reading findings

A `SNPRINTF_RODATA_VARIABLE` result means:

- The shell command skeleton is in `.rodata` (hardcoded) — the programmer did restrict the command structure.
- **But** at least one `%s` (or `%n`) argument slot exists — the value filling that slot may come from an external source.
- **Next step**: run `SinkArgClassifier` on the **snprintf call** (not the popen call) to classify the `%s` argument. If it is `ARG_PROPAGATED`, trace it with `TaintTracker` from the function's entry point.
- The `detail` field now includes the decoded format string — use it to understand which argument position(s) are injectable.

---

## See also

- `SinkArgClassifier` — produces the `SNPRINTF_RODATA` results this filter post-processes
- `TaintTracker` — trace the `%s` argument source to its origin
- `CrossBinaryExportDetector` — identify zero-caller functions that receive external arguments at their entry point

[↑ Back to top](#snprintf-variable-filter)
