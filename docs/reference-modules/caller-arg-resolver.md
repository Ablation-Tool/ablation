# CallerArgResolver

Trace one hop up the call chain from a `SinkArgClassifier` `ARG_PROPAGATED` finding to classify what each caller actually passes for the propagated argument: determining whether the propagated argument is attacker-controlled or internally fixed.

---

## Why this exists

1. **ARG_PROPAGATED means the argument came from outside the function, not that it is exploitable.** When `SinkArgClassifier` reports `ARG_PROPAGATED` for `system(arg0)` at `func@0x805842b`, it means the argument to `system()` traces back to an entry argument of `func`. That argument may be user-supplied, or it may be a hardcoded constant passed by every caller. Without examining the call sites, both cases look identical.

2. **Manual caller examination is slow.** IBM CSM `samlicm`: `lum_add_nodelocked` (`func@0x805842b`) has an `ARG_PROPAGATED` `system()` site where `arg_pos=9` traces to `[ebp+0x2c]`. Manual disassembly of all three callers revealed:
   - `netls_add_nodelocked` (`0x80526b6`): passes `push 0` → `system(NULL)`: shell probe, not exploitable
   - `installTryBuyLicense` (`0x804d3ba`): passes `push 0` → `system(NULL)`, not exploitable
   - `netls_add_nodelocked_from_certificate` (`0x80774a4`): passes `&[ebp-0x7b8]`: a stack buffer containing certificate data → **exploitable path**

   Manual investigation took ~40 minutes. This module classifies all three in seconds and flags only the certificate path for further review.

3. **i386 cdecl caller classification is mechanical.** Arguments are pushed right-to-left before the call instruction. The last push before `call func_va` is `arg0`, the second-to-last is `arg1`, and so on. This is deterministic enough to automate.

---

## How it works

```
resolve(func_va=0x805842b, func_arg_pos=9)
         │
         ├── Find all call sites to func_va in BinaryContext.call_edges
         │
         └── For each caller at caller_site_va:
             ├── Disassemble up to _LOOKBACK=80 instructions backward
             ├── Count pushes backward from the call (adjusting for
             │   'add esp, N' cleanup after inner calls)
             ├── When push count == func_arg_pos, classify the push source:
             │   ├── push 0                → CONST_NULL
             │   ├── push imm32 (≠0)       → CONST_NONZERO
             │   ├── lea/mov + push from .rodata → CONST_NONZERO
             │   ├── push [ebp+N] N>0      → ARG_PROPAGATED
             │   ├── push [ebp-N] or lea [ebp-N] → STACK_LOCAL
             │   └── other                 → UNKNOWN
             └── → CallerResult per call site
```

**Stack adjustment for inner calls:** If the function being analyzed calls other functions with cleanup (`add esp, N`), those adjustments affect the effective push count. The analyzer tracks cumulative `add esp` values between inner-call cleanup and the target push to maintain an accurate argument position count.

---

## Verdicts

| Verdict | Meaning | Action |
|:---|:---|:---|
| `CONST_NULL` | `push 0`: `system(NULL)` shell probe | Discard: shell probe tests if a shell is available, not exploitable |
| `CONST_NONZERO` | `push imm32 ≠ 0` or LEA from `.rodata` | Verify: static string to `system()` is benign unless the string is mutable |
| `ARG_PROPAGATED` | `push [ebp+N]`: value from caller's caller | Continue: trace one more level up or confirm with TaintTracker |
| `STACK_LOCAL` | `push [ebp-N]` or `lea [ebp-N]` | Investigate: stack buffer: check if its content is user-controlled snprintf pattern |
| `UNKNOWN` | Push source not resolved within lookback | Manual trace required |

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.caller_arg_resolver import CallerArgResolver

ctx = BinaryContext.load_or_build('/path/to/samlicm')
resolver = CallerArgResolver.from_context(ctx)

# Resolve what callers pass for arg_pos 9 of lum_add_nodelocked
report = resolver.resolve(func_va=0x805842b, func_arg_pos=9)
print(resolver.fmt_report(report))
```

**Typical output:**
```
CallerArgResolver: lum_add_nodelocked (0x805842b) arg_pos=9 — 3 call site(s)

  0x80526b6  CONST_NULL        push 0 (system(NULL) — shell probe)
  0x804d3ba  CONST_NULL        push 0 (system(NULL) — shell probe)
  0x80774a4  STACK_LOCAL       push [ebp-0x7b8] (cert buffer on frame)

  2 CONST_NULL  1 STACK_LOCAL
  → STACK_LOCAL at 0x80774a4 warrants further investigation
```

**Integration with SAC pipeline:**
```python
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier, ARG_PROPAGATED

sac = SinkArgClassifier.from_context(ctx)
findings = [r for r in sac.classify_all() if r.verdict == ARG_PROPAGATED]

for f in findings:
    # Parse func_arg_pos from SAC detail string e.g. '[ebp+0x2c]'
    report = resolver.resolve_from_classification(f)
    if report:
        print(resolver.fmt_report(report))
```

`resolve_from_classification()` parses the `[ebp+N]` offset from the SAC `detail` field automatically.

---

## Result fields

The `resolve()` method returns a report object. Each call site produces a `CallerResult`:

| Field | Type | Content |
|:---|:---|:---|
| `caller_va` | `int` | VA of the calling function |
| `call_site_va` | `int` | VA of the specific `call func_va` instruction |
| `verdict` | `str` | One of the five verdicts above |
| `detail` | `str` | Human-readable push source trace |

---

## Limitations

**i386 cdecl only.** x86_64, PPC, ARM, and MIPS calling conventions are not supported. The module raises if called on a non-i386 binary.

**One hop only.** The module resolves one level up the call chain. If `ARG_PROPAGATED` is returned for a caller, repeat `resolve()` on that caller function and the original argument position.

**`add esp` cleanup is approximate.** The cleanup tracking handles the common `add esp, N` idiom after inner calls, but complex stack frames with multiple cleanup paths can produce inaccurate argument position counts.

---

## Pipeline position

**Before:** `SinkArgClassifier.classify_all()`: produces the `ARG_PROPAGATED` findings to resolve.

**After:** `STACK_LOCAL` and `ARG_PROPAGATED` results from this module feed into `TaintedStringTracker` (for `STACK_LOCAL` with snprintf pattern) or another `CallerArgResolver.resolve()` call (for `ARG_PROPAGATED`).

---

## See also

- [Sink Arg Classifier](sink-arg-classifier.md): produces the ARG_PROPAGATED inputs to this module
- [Func Reachability](func-reachability.md): filter dead code before running caller resolution
- [Tainted String Tracker](tainted-string-tracker.md): upgrade SNPRINTF_RODATA when stack buffer is tainted
- [Taint Analysis](taint-analysis.md): full interprocedural trace for confirmed paths
