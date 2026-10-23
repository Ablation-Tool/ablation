# NonConstantTimeComparatorScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Detect timing-unsafe comparisons in security-critical contexts.** `strcmp()` and `memcmp()` return on the first differing byte. Against a timing oracle, this lets an attacker recover a secret one byte at a time. No prior Ablation module checked whether comparison functions near security-sensitive rodata strings or in security-named functions are timing-safe. `NonConstantTimeComparatorScanner` finds `strcmp`/`memcmp` call sites in functions whose names contain security keywords, or with security-sensitive strings in the surrounding rodata window, and flags them as HIGH or MEDIUM depending on confidence.

## Usage

```python
from modules.non_constant_time_comparator_scanner import NonConstantTimeComparatorScanner

scanner = NonConstantTimeComparatorScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = NonConstantTimeComparatorScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: CTFinding

| Field | Type | Description |
|-------|------|-------------|
| `func_va` | int | VA of the containing function |
| `func_name` | str | Function name or `sub_VA` |
| `call_va` | int | VA of the comparison call instruction |
| `cmp_func` | str | `strcmp`, `memcmp`, `strncmp`, etc. |
| `context_hint` | str | Why this was flagged |
| `severity` | str | `HIGH` for security-named functions; `MEDIUM` for rodata keyword match |

## Detection logic

1. Find all PLT imports in `_EARLY_EXIT_CMPS`: `strcmp`, `strncmp`, `strcasecmp`, `strncasecmp`, `memcmp`, `bcmp`, `wmemcmp`.
2. For each call site in each function:
   - **HIGH:** the containing function name matches `check`, `verify`, `validate`, `compare`, `auth`, `login`, `password`, `token`, `hmac`, `mac`, or `sign`.
   - **MEDIUM:** the 256-byte rodata window around the call site matches `passw`, `secret`, `token`, `hmac`, `mac`, `sig`, `auth`, `key`, `nonce`, `cert`, `pin`, `otp`, or `bearer`.
   - **MEDIUM:** no constant-time alternative is imported at all in the binary.

## Constant-time alternatives checked

`CRYPTO_memcmp`, `timingsafe_bcmp`, `timingsafe_memcmp`, `crypto_memcmp`, `safe_memcmp`, `consttime_memequal`, `secure_compare`.

If any of these are present in the PLT, a rodata-window match is still flagged MEDIUM.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** for each HIGH finding, use `TaintTracker` to verify that one argument of the comparison comes from attacker-controlled input and the other from a stored secret. If both conditions hold, the finding is exploitable as a timing side-channel.

## See also

- [DeprecatedCryptoScanner](deprecated-crypto-scanner.md): detect MD5/SHA-1 in same crypto context
- [TaintTracker](taint-analysis.md): argument provenance tracing
- [SinkArgClassifier](sink-arg-classifier.md): classify argument types at call sites
