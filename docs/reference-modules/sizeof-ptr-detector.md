# SizeofPtrDetector

## Why this exists

One thing was not possible before in Ablation:

1. **Detect `sizeof(pointer)` literal constants feeding copy and fill sinks.** `sizeof(ptr)` compiles to the integer literal 4 or 8. When this literal feeds `memcpy()` or `memset()`, the result is a partial copy or partial clear of the actual buffer. This produces security bugs: partial zeroing leaves secrets intact, partial copy of a credential copies only the first 8 bytes. `SizeofPtrDetector` walks backwards from each copy/fill sink and flags cases where the length argument is loaded as an immediate 4 or 8.

## Usage

```python
from modules.sizeof_ptr_detector import SizeofPtrDetector

detector = SizeofPtrDetector('/path/to/binary')
findings = detector.scan()
print(detector.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
detector = SizeofPtrDetector.from_context(ctx)
findings = detector.scan()
```

## Output: SizeofPtrFinding

| Field | Type | Description |
|-------|------|-------------|
| `func_va` | int | VA of the containing function |
| `func_name` | str | Function name or `sub_VA` |
| `call_va` | int | VA of the sink call |
| `sink` | str | Sink name such as `memcpy` or `memset` |
| `ptr_size` | int | The literal: 4 or 8 |
| `load_insn` | str | The MOV/LDR that loaded the literal |
| `load_va` | int | VA of that instruction |
| `severity` | str | `MEDIUM` for copy sinks; `LOW` for fill sinks |

## Covered sinks

Copy sinks: `memcpy`, `memmove`, `memcpy_s`, `wmemcpy`, `read`, `recv`, `recvfrom`.

Fill sinks: `memset`, `bzero`, `explicit_bzero`, `memset_explicit`, `SecureZeroMemory`, `RtlSecureZeroMemory`.

## False positives

Not every length-4 or length-8 is a bug. A `memcpy` of exactly one pointer is intentional. Common legitimate patterns:

- `memcpy(&dst_ptr, &src_ptr, sizeof(void*))`: pointer copy, intentional.
- `memset(&int_field, 0, 4)`: zeroing a 4-byte integer field.

Verify each finding by examining what the destination buffer is. If the destination is a `char buf[128]` or heap allocation larger than 8 bytes, the finding is real.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## See also

- [SignedLengthArgScanner](signed-length-arg-scanner.md): signed/unsigned confusion at length args
- [TruncationAtSinkScanner](truncation-at-sink-scanner.md): wide-to-narrow length truncation
- [TaintTracker](taint-analysis.md): confirm destination buffer provenance
