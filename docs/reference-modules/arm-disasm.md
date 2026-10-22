# ARM Disassembler

**File:** `modules/arm_disasm.py`

## Why this exists

Pure-Python ARM32 disassembler. Decodes the fixed 4-byte ARM instruction set (data processing, load/store, branch, multiply, coprocessor) with no external library dependency. Used as the disassembly layer by `arm_symbolic.py` for path-insensitive symbolic execution on ARM32 targets where Capstone is unavailable or where a lightweight dependency-free decoder is required.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.

---

## How it works

`ArmDisasm` decodes ARMv7 32-bit fixed-width instructions in pure Python with no external disassembly libraries. It classifies each instruction word by bits [27:25] into one of five groups — Data Processing (AND/ADD/SUB/MOV/…), Load/Store (LDR/STR/LDRB/…), Branch (B/BL/BX/BLX), Multiply (MUL/MLA/UMULL/…), and Status Register Access (MRS/MSR) — then extracts condition code [31:28] and instruction-specific fields to build the decoded instruction. Called by `ARM32TaintTracker` when Capstone is unavailable.

---

## Usage

```python
from modules.arm_disasm import ARMDisassembler

with open('/path/to/arm32_firmware.bin', 'rb') as fh:
    data = fh.read()

disasm = ARMDisassembler(data, base_addr=0x10000)
insns = disasm.disassemble(start=0x10000, count=100)
for insn in insns:
    print(insn)
```

---

## Example output

```
# ArmInstruction.__str__() output:
push     {r4, r5, r6, lr}
ldr      r3, [r7, #0]
add      r2, r0, r1
bne      0x400120
bl       0x4012a0
pop      {r4, r5, r6, pc}
```

---

## False positives

**Non-Thumb2 encoding.** `ArmDisassembler` decodes ARMv7 fixed-width 32-bit instructions (A32 encoding only). It does not decode Thumb-16 or Thumb-32 instructions. If the binary contains Thumb code regions, Capstone with `CS_MODE_THUMB` should be used instead.

---

## Pipeline position

**Before this module:** Confirm the target is an ARM32 ELF with A32 encoding. Check `ctx.arch` is `ARM` and not `THUMB`.

**After this module:** Pass the decoded instruction list to `ARM32TaintTracker` or use individual `ArmInstruction` objects in custom analysis.

---

## Reading output

`ARMDisassembler.from_bytes(data, base=0).disassemble()` returns `List[ARMInstruction]`:

| Attribute | Content |
|:---|:---|
| `address` | Virtual address of the instruction |
| `encoding` | Raw 32-bit instruction encoding |
| `mnemonic` | Instruction mnemonic string (e.g., `'ldr'`, `'bl'`, `'mov'`) |
| `operands` | Decoded operands as a string (e.g., `'r0, [r1, #4]'`) |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
