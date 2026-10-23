# TruncationAtSinkScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Detect wide-to-narrow length truncation before allocation and I/O sinks.** `SignedLengthArgScanner` catches signed/unsigned confusion. `LengthUnderflow` catches arithmetic underflow. Neither catches the Ariane 5 pattern: a 32-bit network-received value is truncated to 16 bits by an `AND 0xFFFF` or `MOVZX` before feeding `malloc()`, producing a tiny allocation that a subsequent `memcpy()` using the original 32-bit value overflows. `TruncationAtSinkScanner` walks backwards from each allocation and I/O sink call looking for `AND` instructions with 8- or 16-bit masks, `MOVZX`, and ARM `UXTH`/`UXTB` instructions targeting the length register.

## Usage

```python
from modules.truncation_at_sink_scanner import TruncationAtSinkScanner

scanner = TruncationAtSinkScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = TruncationAtSinkScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: TruncationFinding

| Field | Type | Description |
|-------|------|-------------|
| `func_va` | int | VA of the containing function |
| `func_name` | str | Function name or `sub_VA` |
| `call_va` | int | VA of the sink call instruction |
| `sink` | str | Sink function name such as `malloc` or `memcpy` |
| `trunc_width` | int | Truncated bit width: 8, 16, or 24 |
| `trunc_insn` | str | The truncating instruction text |
| `trunc_va` | int | VA of the truncating instruction |
| `severity` | str | `HIGH` for allocation sinks; `MEDIUM` for I/O sinks |

## Truncation patterns detected

| Pattern | Width | Architecture |
|---------|-------|-------------|
| `AND reg, 0xFF` | 8 bits | x86-64, ARM |
| `AND reg, 0xFFFF` | 16 bits | x86-64, ARM |
| `MOVZX reg, word ptr` | 16 bits | x86-64 |
| `MOVZX reg, byte ptr` | 8 bits | x86-64 |
| `UXTH reg, reg` | 16 bits | ARM32/64 |
| `UXTB reg, reg` | 8 bits | ARM32/64 |

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** confirm the truncated allocation is followed by a `memcpy()`/`read()` using the original untruncated length. Use `PathSolver` to verify the path from input to truncation to allocation to overflow is feasible.

## See also

- [SignedLengthArgScanner](signed-length-arg-scanner.md): signed/unsigned confusion at length args
- [LengthUnderflow](length-underflow.md): arithmetic underflow at length args
- [PathSolver](path-solver.md): path feasibility from input to sink
