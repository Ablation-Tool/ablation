# ECU SH-2A Decoder

Pure-Python instruction decoder for Renesas SH-2A (SH7058/SH7059) ECU firmware.
Capstone 5.0.7 has no SH-2A support; this module fills that gap.

---

## Why this exists

Three things weren't possible before in Ablation:

**1. Decoding SH-2A ECU firmware at all.** Capstone 5.0.7 does not implement the SH-2A
ISA. Honda CBR250RR, Subaru SH7058S, and similar Renesas-based ECUs are opaque without
a decoder — no function starts, no call graph, no disassembly.

**2. Distinguishing 16-bit SH-2 base instructions from 32-bit SH-2A extensions.**
SH-2A adds 32-bit instruction variants (MOVI20, MOVI20S, MOV with 12-bit displacement,
BIT operations) that share the base instruction word space. Length discrimination from
the first halfword is required before decoding can begin.

**3. Finding function starts in SH-2A firmware without symbols.** SH-2A uses a fixed
prologue convention: `STS.L PR, @-R15` (0x4F22) for stack-saving functions and
`STS PR, Rn` for leaf functions. A prologue scanner gives function boundaries for
stripped ROMs.

---

## Module

**File:** `ablation/analyzers/ecu_sh2a_decoder.py`

**ISA coverage:**

| Class | Instruction | Encoding |
|---|---|---|
| Prologue/epilogue | STS.L PR, @-R15 | 0x4F22 |
| Prologue (leaf) | STS PR, Rn | (hw & 0xF0FF) == 0x002A |
| Stack | MOV.L Rm, @-R15 | (hw & 0xFF0F) == 0x2F06 |
| Stack | MOV.L @R15+, Rn | (hw & 0xF0FF) == 0x60F6 |
| Return | RTS / RTS/N | 0x000B / 0x0063 |
| Call | BSR disp12 | (hw & 0xF000) == 0xB000 |
| Call | JSR @Rn | (hw & 0xF0FF) == 0x400B |
| Branch | BRA disp12 | (hw & 0xF000) == 0xA000 |
| Branch | BT/BF/BT.S/BF.S | 0x8900/8B00/8D00/8F00 |
| Load | MOV.L @(d,PC), Rn | (hw & 0xF000) == 0xD000 |
| Load | MOV.W @(d,PC), Rn | (hw & 0xF000) == 0x9000 |
| SH-2A 32-bit | MOVI20 / MOVI20S | (hw & 0xF0FF) == 0x00E5/E7 |
| SH-2A 32-bit | MOV @(d12,Rm), R0 family | (hw & 0xF00F) == 0x3001 |
| SH-2A 32-bit | BCLR/BSET/BST etc. | (hw & 0xF00F) == 0x3009 |

---

## Usage

```python
from ablation.analyzers.ecu_sh2a_decoder import EcuSH2aDecoder

# From file path
dec = EcuSH2aDecoder.from_path('/path/to/honda_cbr250rr.bin', base_va=0x400000)

# From bytes
dec = EcuSH2aDecoder.from_bytes(rom_bytes, base_va=0)

# Disassemble a range (offsets into the data buffer, not VAs)
insns = dec.disassemble(start=0x0, end=0x1000)
for i in insns:
    print(i)  # 0x00400000  [SH16]  sts.l            R15

# Get function starts (virtual addresses)
starts = dec.function_starts()

# Decode one instruction
insn = dec.decode_one(offset=0x0)
print(insn.mnemonic, insn.insn_type, insn.rd, insn.rs)
```

---

## SH-2A length discrimination

From Renesas SH-2A Hardware Manual Rev.2.00:

```
32-bit if first halfword matches any of:
  (hw & 0xF00F) == 0x3001   MOV with 12-bit displacement
  (hw & 0xF00F) == 0x3009   BIT operation
  (hw & 0xF0FF) == 0x00E5   MOVI20
  (hw & 0xF0FF) == 0x00E7   MOVI20S
All other first halfwords → 16-bit SH-2 instruction
```

---

## API reference

### `EcuSH2aDecoder`

**`__init__(data, base_va=0)`** — accepts `bytes`, `str` path, or `Path`.

**`from_path(path, base_va=0)`** / **`from_bytes(data, base_va=0)`** — convenience wrappers.

**`insn_length(offset)`** → `int` — 2 or 4 (0 at EOF).

**`decode_one(offset)`** → `SH2aInsn | None` — decode one instruction; None at EOF.

**`disassemble(start=0, end=None)`** → `List[SH2aInsn]` — all instructions in byte range.

**`function_starts()`** → `List[int]` — sorted VAs of detected function prologues.

### `SH2aInsn` dataclass

| Field | Type | Description |
|---|---|---|
| `offset` | `int` | Virtual address of instruction |
| `is_32bit` | `bool` | True for 32-bit SH-2A variant |
| `mnemonic` | `str` | Instruction mnemonic |
| `insn_type` | `str` | CALL / BRANCH / RETURN / LOAD / STORE / LR_SAVE / LR_RESTORE / MISC |
| `raw` | `bytes` | 2 or 4 raw bytes |
| `target` | `int?` | Computed branch/call target VA |
| `rd` | `int?` | Destination register index |
| `rs` | `int?` | Source register index |
| `imm` | `int?` | Immediate operand (signed) |

---

## Validated on

- Honda CBR250RR (SH7058, ECU 38770-K87-J01) — function_starts matches symbol table

---

## Gaps and limitations

- Instruction coverage is prologue/branch/load/store focused; arithmetic (ADD, SUB, MUL,
  logical) and FPU instructions fall through to the generic fallback mnemonic
- `disassemble()` does not enforce 2-byte alignment; callers must pass aligned start offsets
- SH-2A DSP extensions not covered
