# TaintedStringTracker

Upgrade `SNPRINTF_RODATA` verdicts from `SinkArgClassifier` to `ARG_PROPAGATED` when the `snprintf` format arguments, not the format string: carry attacker-controlled input.

---

## Why this exists

1. **`SNPRINTF_RODATA` is incomplete, not safe.** `SinkArgClassifier` classifies `system(buf)` as `SNPRINTF_RODATA` when `buf` was written by `snprintfbuf, n, fmt, ...` with a `.rodata` constant format. That is correct about the format, but says nothing about the `%s` arguments. The pattern:
   ```c
   snprintf(cmd, sizeof(cmd), "%s %s", argv[1], argv[2]);
   system(cmd);
   ```
 produces `SNPRINTF_RODATA`. The format is indeed a `.rodata` literal. But `cmd` contains `argv[1]` and `argv[2]`, making this a confirmed command injection path. Without this module, the finding is classified at MEDIUM and deprioritized.

2. **The gap is real.** Gap ID `SAC-FORMAT-001`. `SNPRINTF_RODATA` verdicts in firmware binaries frequently use format strings like `"/bin/tool %s"` or `"cmd %s %s"` with user-supplied format arguments. The format is fixed; the injection path is through the `%s` slots.

---

## How it works

```
upgrade_snprintf_rodata(sac_results)
         │
         ├── Filter: only SNPRINTF_RODATA verdicts
         │
         ├── For each SNPRINTF_RODATA finding at call_va:
         │   ├── _find_preceding_call(data, base_va, call_va, snprintf_va)
         │   │   └── Scan backward for CALL rel32 (0xe8) that calls snprintf PLT VA
         │   │
         │   └── _classify_format_args(snprintf_call_va)
         │       ├── x86_64: classify rcx, r8, r9 (format arg registers 3,4,5)
         │       │   └── For each reg: backward trace from snprintf CALL
         │       │       ├── MOV/LEA [rip+...] → RODATA_CONST (safe)
         │       │       ├── MOV/LEA [rbp-...] or [rsp+...] → ARG_PROPAGATED
         │       │       └── Immediate → RODATA_CONST
         │       └── → tainted_args list if any arg is ARG_PROPAGATED
         │
         └── Yield TaintedFormatResult for each upgraded finding
```

x86_64 `snprintf` argument positions (SysV ABI):

| Argument | Register | Role |
|:---|:---|:---|
| 0 | `rdi` | `buf` destination buffer: tracked by SAC |
| 1 | `rsi` | `n` (size) |
| 2 | `rdx` | `fmt` (format string: SAC verifies this is `.rodata`) |
| 3 | `rcx` | First format arg: **this module classifies** |
| 4 | `r8` | Second format arg: **this module classifies** |
| 5 | `r9` | Third format arg: **this module classifies** |

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
from ablation.analyzers.tainted_string_tracker import TaintedStringTracker

ctx = BinaryContext.load_or_build('/path/to/binary')
sac = SinkArgClassifier.from_context(ctx)
results = sac.classify_all()

tst = TaintedStringTracker.from_context(ctx)
upgraded = tst.upgrade_snprintf_rodata(results)
print(tst.report(upgraded))
```

**Typical output:**
```
TaintedStringTracker: 2 upgrade(s)
  0x22d456 → system()  [upgraded: SNPRINTF_RODATA → ARG_PROPAGATED]
    snprintf at 0x22d3a0, tainted args: ['rcx']
    // mov rcx, [rbp-0x10] (local/arg from frame) at 0x22d388

  0x22e100 → popen()  [upgraded: SNPRINTF_RODATA → ARG_PROPAGATED]
    snprintf at 0x22e010, tainted args: ['rcx', 'r8']
    // mov rcx, [rsp+0x30] (stack) at 0x22dfec
    // lea r8, [rbp-0x20] (stack buf from frame) at 0x22dff8
```

**Full pipeline: SAC + upgrade + taint:**
```python
from ablation.analyzers.sink_arg_classifier import SNPRINTF_RODATA, ARG_PROPAGATED
from ablation.analyzers.taint_tracker import TaintTracker

sac_results = sac.classify_all()
upgraded = tst.upgrade_snprintf_rodata(sac_results)

# Taint-trace both original ARG_PROPAGATED and newly upgraded sites
to_trace = (
    [r for r in sac_results if r.verdict == ARG_PROPAGATED]
    + upgraded
)
tt = TaintTracker(ctx.path)
for r in to_trace:
    func_va = getattr(r, 'func_va', None) or r.sink_va
    print(f'Tracing 0x{func_va:x}')
    sinks = tt.trace_function(func_va, tainted_args=['rdi', 'rsi', 'rdx', 'rcx'])
    for s in sinks:
        print(f'  {s.sink_type} at 0x{s.address:x}: {s.instruction}')
```

---

## Result fields (TaintedFormatResult)

| Field | Type | Content |
|:---|:---|:---|
| `sink_va` | `int` | VA of the `system()` / `popen()` call site |
| `sink_name` | `str` | Name of the exec sink |
| `snprintf_va` | `int` | VA of the `snprintf` that built the buffer |
| `tainted_args` | `list[str]` | Register names classified as `ARG_PROPAGATED` (e.g. `['rcx', 'r8']`) |
| `arg_evidence` | `str` | Human-readable backward trace for each tainted arg |
| `verdict` | `str` | Always `'ARG_PROPAGATED'` |

---

## Limitations

**x86_64 only.** i386 and PPC architectures are not yet implemented. Calls to `upgrade_snprintf_rodata()` on non-x86_64 binaries return an empty list rather than a wrong result.

**One-level snprintf search.** The module scans backward up to 1024 bytes from the exec sink call for a preceding CALL to the `snprintf` PLT entry. If the `snprintf` call is more than ~200 instructions before the sink, it will not be found.

**Three format arg positions.** Only `rcx`, `r8`, `r9` positions 3–5 are classified. Format strings with more than three `%s` substitutions using stack-passed arguments are not traced.

---

## Pipeline position

**Before:** `SinkArgClassifier.classify_all()`: produces the `SNPRINTF_RODATA` verdicts to upgrade.

**After:** Treat upgraded `TaintedFormatResult` objects the same as `ARG_PROPAGATED` findings from SAC. Continue through the post-SAC filter chain: `SnprintfVariableFilter` → `SinkSanitizerFilter` → `FuncReachabilityAnalyzer` → `NetworkSinkFinder` (networked binaries), then `TaintTracker`.

---

## See also

- [Sink Arg Classifier](sink-arg-classifier.md): produces the SNPRINTF_RODATA inputs this module upgrades
- [Taint Analysis](taint-analysis.md): receives the upgraded ARG_PROPAGATED findings
- [Format String Scanner](format-string-scanner.md): separate scanner for printf-class vulnerabilities
