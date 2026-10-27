# SinkArgClassifierARM64

**Module**: `ablation/analyzers/sink_arg_classifier_arm64.py`
**Gap**: ARM64-SAC-GAP-001

---

## Why this exists

1. `SinkArgClassifier` (x86-64) uses x86-64 register IDs (rdi=7, rsi=6, rdx=4). AArch64 binaries never produce those IDs — every call site returned `UNKNOWN`.
2. No AArch64-specific SAC existed despite `taint_tracker_arm64.py` being present. The gap was the argument-provenance classifier, not the taint tracker.
3. facility ATLAS GEP ships `versalTcpIpbusShim` (AArch64, stripped), which is the primary network-to-/dev/mem bridge. Without this module, its sink call sites could not be classified.

---

## Calling convention

AArch64 AAPCS64: first eight integer/pointer arguments in **x0–x7**.

| Arg position | Register | Capstone ID |
|-------------|----------|-------------|
| 0 | x0 | 218 |
| 1 | x1 | 219 |
| 2 | x2 | 220 |
| 3 | x3 | 221 |
| 4–7 | x4–x7 | 222–225 |

---

## String address load patterns traced

### 1. ADRP + ADD (most common PIC pattern)

```asm
adrp  x0, 0x401000      ; page_va = 0x401000
add   x0, x0, #0x38     ; string_va = 0x401038
```

Both instructions write to the same register. The backward trace detects `ADD xR, xR, #off` and looks back ≤6 instructions for `ADRP xR, page_va`.

### 2. ADRP + LDR (GOT-indirect)

```asm
adrp  x0, 0x480000      ; GOT page
ldr   x0, [x0, #0x10]   ; load pointer from GOT slot 0x480010
```

The loaded pointer (read from the file image at the GOT VA) is checked against `.rodata`.

### 3. ADR (short-range PC-relative)

```asm
adr   x0, 0x1040        ; direct address, within ±1MB
```

Target VA checked against `.rodata` → RODATA_CONST.

### 4. LDR literal pool (IMM operand)

```asm
ldr   x0, #0x4008       ; load 8 bytes from address 0x4008 (pool entry)
```

Capstone reports a single `ARM64_OP_IMM` operand with the absolute pool VA. Reads 8 bytes at that VA; checks the loaded pointer.

### 5. MOV / ORR xR, xzr, xY

```asm
mov   x0, x1             ; register copy (AAPCS64 alias for ORR x0, xzr, x1)
```

Recurses on source register xY. Recursion capped at depth 1.

### 6. MOVZ / MOVK

```asm
movz  x0, #0             ; NULL → RODATA_CONST
movz  x0, #0x4, lsl #48  ; MOVZ+MOVK pair → RODATA_CONST (compile-time constant)
```

### 7. LDR [sp, #N] / [x29, #N]

Stack slot. Two sub-cases:
- **SNPRINTF_RODATA**: look back for `BL snprintf_va`; trace x2 (fmt). If RODATA_CONST → SNPRINTF_RODATA.
- **ARG_PROPAGATED**: look for `STR xR, [sp/x29, #N]` in the first 24 instructions of the function (prologue arg save).
- Else → UNKNOWN.

### 8. LDR [xY, #N] where xY ∉ {sp, x29}

Struct/heap field dereference. If base register xY ∈ entry regs (x0-x7) → ARG_PROPAGATED. Else UNKNOWN.

---

## Store mnemonic exclusion

`_writes_reg()` explicitly excludes store mnemonics (`str`, `stur`, `strb`, `stp`, etc.). This fixes a subtle bug in the ARM32 module where `STR x0, [sp, #8]` (which stores x0 to memory, not the other way around) would be misidentified as a write to x0, causing premature UNKNOWN returns.

---

## Constructor patterns

```python
# From BinaryContext (preferred — avoids double-parse)
from ablation.analyzers.sink_arg_classifier_arm64 import SinkArgClassifierARM64
clf = SinkArgClassifierARM64.from_context(ctx)

# Via arch-aware dispatch (auto-detects AArch64 from ELF header)
from ablation.analyzers.sink_arg_classifier import sac_for_path, sac_for_context
clf = sac_for_path('/path/to/arm64_binary')          # calls from_context internally
clf = sac_for_context(ctx)                           # dispatches on ctx.arch == 'arm64'

# Add vendor-specific sinks
clf.add_sink('ioctl_write_reg', arg_pos=2)           # third argument = x2

# Classify
results = clf.classify_all()
print(clf.report(results))

# Filter to non-safe
risky = [r for r in results if r.verdict not in ('RODATA_CONST',)]
```

---

## Verdicts

| Verdict | Meaning | Next step |
|---------|---------|-----------|
| `RODATA_CONST` | Hardcoded string in .rodata. No injection. | Eliminate. |
| `SNPRINTF_RODATA` | Stack buffer from `snprintf` with fixed format string. | Check %s args with SnprintfVariableFilter. |
| `ARG_PROPAGATED` | Came from a caller-supplied x0-x7. Trace callers. | TaintTracker. |
| `UNKNOWN` | Not resolved in 80-insn window. | Manual WindowAnalyzer. |

---

## Known limitations

- Indirect calls via `blr xN` (e.g., function pointer dispatch) are not matched. Only direct `BL target_va` call sites are classified.
- Inline assembly that moves a string address through a callee-saved register (x19–x28) across a function call boundary is not traced.
- W-register variants (w0–w7) of argument registers are not currently tracked — these carry 32-bit integers, not pointers, so missing them has low practical impact.

[↑ Back to INDEX](../INDEX.md)
