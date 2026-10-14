# Length Underflow Scanner

**File:** `ablation/analyzers/length_underflow.py`

Detects integer underflow in protocol parsers where a user-supplied length field has a fixed header size subtracted, wraps on uint16 truncation, and reaches a downstream allocation or copy without a prior bounds check. Generalizes across DNS, GRE, PPTP, SCTP, and Diameter parsers.

---

## Why this exists

Three gaps existed before this module:

1. **Protocol parser underflow was a blind spot for taint trackers.** Standard taint analysis follows input data to sinks. The underflow pattern involves arithmetic on a *length value* — a secondary data flow that taint trackers miss when they only trace the buffer content.

2. **Generic integer overflow scanners miss the truncation step.** The C12-class bug requires three specific steps in sequence: subtract a fixed constant, truncate to uint16, then call a function with the result. Scanners that look for overflow arithmetic alone generate too many false positives to be actionable.

3. **Cross-protocol applicability was unproven.** The pattern was known for specific protocols but not validated across an arbitrary x86-64 ELF corpus. The scanner confirms it applies to any parser that strips a fixed header from a user-supplied length field, regardless of protocol.

---

## Detected pattern

The scanner finds this exact instruction sequence in x86-64 `.text`, without a preceding bounds check:

```
lea  -N(%reg), %dest     ; subtract fixed header size N (4–256 bytes)
  OR  sub $N, %reg
movzwl %?x, %dest        ; truncate to uint16 (wraps if input_len < N)
call <target>            ; pass wrapped value as function argument
```

**Without** an intervening `cmp`/`test` on the subtraction result in the prior 25 instructions.

**Example from a confirmed protocol parser:**
```
0x1000: cmp  $0xf, %r12d         ; checks BUFFER SPACE, not chunk_length
0x1010: lea  -0x10(%r9), %edx    ; chunk_length - 16
0x1018: movzwl %dx, %edx         ; uint16 truncation: 3 - 16 = 65523
0x101c: call proto_parse_field   ; called with rdx = 65523 → OOB read
```

Input lengths 1 through N-1 wrap to 65537-N through 65535 after the uint16 truncation.

---

## Usage

```python
from ablation.analyzers.length_underflow import LengthUnderflowScanner

# From binary path
scanner = LengthUnderflowScanner('/path/to/binary')
findings = scanner.scan()

# Unguarded findings only (likely true positives)
for f in findings:
    if not f.guarded:
        print(f.fmt())

# Reuse an existing BinaryContext (avoids LIEF rebuild)
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = LengthUnderflowScanner.from_context(ctx)
findings = scanner.scan()

# All findings including guarded (for manual triage)
for f in findings:
    guard_tag = "GUARDED" if f.guarded else "UNGUARDED"
    print(f"[{guard_tag}] 0x{f.sub_va:x}  -0x{f.header_size:x}  trunc@0x{f.trunc_va:x}  call@0x{f.call_va:x}")
```

---

## Finding fields (`UnderflowFinding`)

| Field | Description |
|---|---|
| `sub_va` | VA of the `lea -N(%reg)` or `sub $N` instruction |
| `header_size` | The subtracted constant N (4–256 bytes) |
| `sub_reg` | Register holding the result after subtraction |
| `trunc_va` | VA of the `movzwl`/`movzbl` truncation instruction |
| `call_va` | VA of the `call` instruction that receives the wrapped value |
| `callee` | Name of the called function (from PLT), if resolved |
| `func_va` | VA of the enclosing function |
| `guarded` | `True` if a `cmp`/`test` on the subtraction result appears within 25 prior instructions |
| `description` | Human-readable summary of the wrapping path |

---

## Guard detection

The scanner looks back 25 instructions from the subtraction site for any `cmp` or `test` instruction that references the subtraction result register. A guard present marks `guarded=True` — these findings require manual confirmation that the guard covers the right range before the subtraction.

Unguarded findings require no manual confirmation of guard presence: the path to the sink runs without any length check.

---

## Protocol coverage

The header size range [4, 256] covers:

| Protocol | Fixed header |
|---|---|
| DNS | 12 bytes |
| GRE | 4 bytes |
| PPTP | 8 bytes |
| SCTP | 12 bytes |
| Diameter | 20 bytes |
| Custom TLV | 4–16 bytes |

Any protocol parser that reads a user-supplied length field and subtracts a fixed overhead falls within this detection range.
