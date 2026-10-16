# sanitizer_detector — Shell Sanitization Auditor

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
   *Covers:* `li r3, 0x20; bl string::find()` — IBM LoadLeveler style.
2. **Inline-compare pattern**: any compare/test instruction with an ASCII immediate.
   *Covers:* `cmpwi r0, 0x2d; bne` — both PPC64 and x86.

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

| Verdict      | Meaning |
|--------------|---------|
| `SHELL_SAFE` | Every `SHELL_METACHARACTERS` entry is explicitly tested — injection structurally blocked |
| `PARTIAL`    | Some metachars tested, others missing (e.g. rejects `|` but allows `;`) |
| `SPACE_ONLY` | Only space (0x20) found in the metachar intersection — common in class-method validators that check for spaces but not injection chars; all other metachars bypass |
| `NO_CHECKS`  | No shell metacharacter appears anywhere in the function — no sanitization at all |
| `UNKNOWN`    | Disassembly failed or function not found |

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
  on x86) are not detected by this method — use `SanitizerDetector.detect()` instead.
- Only `call_window=6` instructions before each call are inspected; deeply pipelined
  character argument setup may be missed.
