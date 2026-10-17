# sanitizer_detector: Shell Sanitization Auditor

## Why this exists

1. **Gap: SanitizerDetector was x86-64 only.** The existing auto-detection relied on
   `movzx`-in-loop + inline `cmp` patterns — valid for Fortinet-style pure byte-validator
 functions but completely missed IBM LoadLeveler's pattern: a 280-instruction class
 method that calls `string::find(0x20)` via `li r3, 0x20; bl string_func` on PPC64.

2. **Gap: no targeted function-level audit.** The detector scanned entire binaries for
 validator-shaped functions. There was no way to ask "given I know this function is
 called before a popen(), does it actually check for shell metacharacters?"

3. **Gap: indirect validators weren't covered.** When a validator calls `strchr` or
   `string::find` with an ASCII immediate as the char argument, the character is checked
 indirectly. The original detector's hard gate (`n_calls > 0 → None`) rejected all
 such functions.

## Two tools in one module

### `SanitizerDetector` (x86-64 auto-detection, unchanged)

Scans all functions in a stripped x86-64 ELF for inline byte-validator loops:
- `movzx eX, byte ptr [...]` inside a backward edge
- Range comparisons with `ja`/`jb` against ASCII immediates
- Dual return (0/1) paths
- No external calls (pure classifier)

```python
from ablation.analyzers.sanitizer_detector import SanitizerDetector
det = SanitizerDetector.from_path('/path/to/binary')
profiles = det.detect()
for p in profiles:
    if p.shell_safe:
        print(f'{p.func_va:#x}: SHELL_SAFE — {p.detail}')
```

### `audit_coverage` / `SanitizerDetector.coverage` (arch-agnostic targeted audit)

Given a *specific* function VA, extracts all ASCII character values from:
1. **Call-arg pattern**: `li`/`mov`-immediate with ASCII value appearing within
   `call_window` instructions before a call/branch.
 *Covers:* `li r3, 0x20; bl string::find()`, IBM LoadLeveler style.
2. **Inline-compare pattern**: any compare/test instruction with an ASCII immediate.
 *Covers:* `cmpwi r0, 0x2d; bne`, both PPC64 and x86.

Reports `chars_checked ∩ SHELL_METACHARACTERS` and which metachars are missing.

```python
from capstone import CS_ARCH_PPC, CS_MODE_64, CS_MODE_BIG_ENDIAN
from ablation.analyzers.sanitizer_detector import audit_coverage

r = audit_coverage(
    '/path/to/target.so',
    0x1234f0,
    CS_ARCH_PPC,
    CS_MODE_64 | CS_MODE_BIG_ENDIAN,
)
print(r.fmt())
# → 0x1234f0  SPACE_ONLY  checked=["' '"]  missing_shell=['"', '$', '&', ';', ...]
```

Or via the classmethod:

```python
r = SanitizerDetector.coverage(
    0x1234f0, CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN,
    binary_path='/path/to/target.so',
)
```

## `SanitizerCoverageReport` verdicts

| Verdict | Meaning |
|--------------|---------|
| `SHELL_SAFE` | Every `SHELL_METACHARACTERS` entry is explicitly tested: injection structurally blocked |
| `PARTIAL` | Some metachars tested, others missing (e.g. rejects `|` but allows `;`) |
| `SPACE_ONLY` | Only space (0x20) found in the metachar intersection: common in class-method validators that check for spaces but not injection chars; all other metachars bypass |
| `NO_CHECKS` | No shell metacharacter appears anywhere in the function: no sanitization at all |
| `UNKNOWN` | Disassembly failed or function not found |

## Integration with SinkArgClassifier workflow

After `SinkArgClassifier` returns `ARG_PROPAGATED`:

```python
# 1. Find the function called just before the sink (the "validator")
# 2. Audit its coverage:
r = audit_coverage(binary, validator_va, arch_cs, mode_cs)
if r.verdict in ('NO_CHECKS', 'SPACE_ONLY'):
    # No shell safety — finding is CONFIRMED
elif r.verdict == 'SHELL_SAFE':
    # Argument sanitized — eliminate or downgrade the finding
elif r.verdict == 'PARTIAL':
    # Check which metachars are missing; finding may still be valid
```

## Limitations

- Tab (0x09) and newline (0x0a) are not detected: values below 0x20 are excluded
 from the scan range to avoid false positives from numeric constants (offsets,
 counts, shift amounts that happen to be < 0x20).
- Functions that sanitize via table lookup (`ldrb + tbl` on ARM, `movzx + test [rbx+rax]`
 on x86) are not detected by this method, use `SanitizerDetector.detect()` instead.
- Only `call_window=6` instructions before each call are inspected; deeply pipelined
 character argument setup may be missed.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Usage

```python
from ablation.analyzers.sanitizer_detector import SanitizerDetector

detector = SanitizerDetector.from_context(ctx)
profiles = detector.detect(min_score=3)
for p in profiles:
    print(p)
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

## Reading output

`SanitizerDetector.from_context(ctx).detect(min_score=3)` returns `List[SanitizerProfile]`:

| Attribute | Content |
|:---|:---|
| `func_va` | VA of the detected sanitizer function |
| `score` | Detection confidence score (0–10) |
| `allowed_bytes` | `FrozenSet[int]` — reconstructed allowed charset byte values |
| `blocked_bytes` | `FrozenSet[int]` — reconstructed blocked charset byte values |
| `shell_safe` | `True` if `allowed_bytes` contains no shell metacharacters |
| `verdict` | `'SHELL_SAFE'` / `'SHELL_UNSAFE'` / `'PARTIAL'` / `'UNKNOWN'` |
| `comparison_imms` | `List[int]` — raw comparison immediates observed |
| `n_byte_loads` | Number of single-byte load instructions found |
| `n_comparisons` | Number of comparison instructions found |
| `detail` | Human-readable description |

Pass matching `SanitizerProfile` objects to `SinkSanitizerFilter` to downgrade `ARG_PROPAGATED` verdicts.

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
