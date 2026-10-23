# SignedLengthArgScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Detect signed-to-unsigned type confusion at length arguments.** `TaintTracker` follows attacker-controlled data to exec sinks. `SinkArgClassifier` classifies argument provenance. Neither checks the arithmetic type of the length argument. A signed `int` passed as a `size_t` to `malloc()` or `read()` wraps on negative values: `read(fd, buf, -1)` becomes `read(fd, buf, 0xffffffffffffffff)` on 64-bit targets, writing past the buffer end. `SignedLengthArgScanner` walks backwards from each length-sink call site looking for `MOVSX`/`MOVSXD`/`SXTW` sign-extension instructions or signed arithmetic (`IMUL`/`IDIV`) targeting the length register.

## Usage

```python
from modules.signed_length_arg_scanner import SignedLengthArgScanner

scanner = SignedLengthArgScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = SignedLengthArgScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: SignedLengthFinding

| Field | Type | Description |
|-------|------|-------------|
| `func_va` | int | VA of the containing function |
| `func_name` | str | Function name or `sub_VA` |
| `call_va` | int | VA of the sink call instruction |
| `sink` | str | Sink function name such as `malloc`, `read`, `memcpy` |
| `length_arg` | int | Argument index of the length parameter |
| `sign_insn` | str | The sign-extending or signed-arithmetic instruction found |
| `sign_va` | int | VA of that instruction |
| `severity` | str | `HIGH` for direct sign extension; `MEDIUM` for signed arithmetic |

## Covered sinks

21 sinks across allocation, I/O, and memory operations:

`malloc`, `calloc`, `realloc`, `alloca`, `read`, `recv`, `recvfrom`, `recvmsg`, `fread`, `write`, `send`, `memcpy`, `memmove`, `memset`, `snprintf`, `strncat`, `strncpy`, `mmap`, `VirtualAlloc`, `VirtualAllocEx`, `HeapAlloc`.

## Detection logic

Within a 20-instruction window before each sink call, walks backwards from the call looking for instructions that write to the length register and are one of:

- **HIGH:** `movsx`, `movsxd` (x86-64), `sbfx`, `sxtw`, `sxtb`, `sxth` (ARM64), `seb`, `seh` (MIPS): direct sign extension.
- **MEDIUM:** `imul`, `idiv` (x86), `smull`, `sdiv` (ARM): signed arithmetic whose result feeds the length.

Architecture support: x86-64 and ARM64. MIPS sign-extension mnemonics included.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** for HIGH findings, use `TaintTracker` to confirm whether the sign-extended value originates from a network or user-controlled source. If yes, the finding is a concrete integer overflow leading to heap or stack overflow.

## See also

- [LengthUnderflow](length-underflow.md): arithmetic underflow at length arguments
- [TaintTracker](taint-analysis.md): source-to-sink argument provenance
- [SinkArgClassifier](sink-arg-classifier.md): call-site argument classification
