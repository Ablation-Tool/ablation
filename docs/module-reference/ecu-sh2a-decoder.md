# EcuSH2aDecoder

**File:** `ablation/analyzers/ecu_sh2a_decoder.py`

---

## Why this exists

3 things that were not possible before in Ablation:

**1. No SH-2A instruction decoding.** Capstone 5.0.7 does not support the Renesas SH-2A ISA
(SH7058/SH7059), used in Honda and Subaru ECUs.  Before this module, any attempt to
`BinaryContext.load_or_build()` on a Subaru SH7058S or Honda CBR250RR ROM had no way to
identify instruction boundaries, preventing WindowAnalyzer, SemanticSearcher, or manual
capstone trace from working at all.  `EcuSH2aDecoder` implements the full SH-2A decoder in
pure Python, giving Ablation complete instruction-level access to those binaries.

**2. No 32-bit SH-2A instruction length discrimination.** SH-2A introduces a set of 32-bit
instructions into a base ISA where all instructions are 16-bit.  Without knowing the exact
first-halfword patterns that indicate a 32-bit instruction, any linear sweep will misalign
and all downstream analysis is garbage.  The module encodes the four correct discriminator
masks from the Renesas SH2A Hardware Manual Rev.2.00 and applies them in `insn_length()` so
every caller gets 2 or 4, never wrong.

**3. No function_starts() for SH-2A flat ROM.** SH-2A ECU ROMs have no ELF headers and no
symbol tables.  Seeding BinaryContext, TaintTracker, or the manual RE workflow requires a
list of function entry points.  `function_starts()` scans the entire ROM for the two SH-2A
prologue conventions (stack-saving and register-saving leaf functions) in a single O(N) pass
and returns all probable entry VAs without requiring a prior disassembly walk.

---

## SH-2A instruction width discrimination

SH-2A first-halfword patterns that indicate a **32-bit** instruction:

| Pattern | Instruction family |
|---|---|
| `(hw & 0xF00F) == 0x3001` | MOV.B/W/L with 12-bit displacement |
| `(hw & 0xF00F) == 0x3009` | BCLR.B/BSET.B/BST.B/BLD.B bit operations |
| `(hw & 0xF00F) == 0x0005` | MOVI20 — `0000 nnnn iiii 0101 \| imm16` |
| `(hw & 0xF00F) == 0x0007` | MOVI20S — `0000 nnnn iiii 0111 \| imm16` |

All other first halfwords → 16-bit SH-2 instruction.

**Why `0xF00F` not `0xF0FF` for MOVI20/MOWI20S:** MOVI20 encodes as
`0000 nnnn iiii 0101` where `nnnn` = Rn (varies, bits 11:8) and `iiii` = imm[19:16]
(varies, bits 7:4).  Using `0xF0FF` as the mask keeps bits[7:4] and would only match
MOWI20 instructions where `imm[19:16] == 0xE`, missing all other immediates.  The correct
mask `0xF00F` keeps only bits[15:12] (must be 0x0) and bits[3:0] (must be 0x5), which is
the actual fixed discriminator.

---

## Function prologue forms

### Stack-saving functions (primary)

```
STS.L PR, @-R15    =  0x4F22
```

Saves the procedure register (return address) to the stack.  This is the universal
SH-2/SH-2A prologue for any non-leaf function.  `function_starts()` detects this at every
even offset.

### Register-saving leaf functions (secondary)

```
STS PR, Rn    =  (hw & 0xF0FF) == 0x002A  (any Rn in 0-15)
```

Saves PR to a GPR instead of the stack; common in leaf functions with short call chains.
A `STS PR, Rn` immediately following `STS.L PR, @-R15` is suppressed — it is the second
instruction of a non-leaf function, not a new function start.

---

## Usage

```python
from ablation.analyzers.ecu_sh2a_decoder import EcuSH2aDecoder

# From file path
dec = EcuSH2aDecoder.from_path("subaru_sh7058s.bin", base_va=0)

# From raw bytes
dec = EcuSH2aDecoder.from_bytes(rom_bytes, base_va=0)

# function_starts() — pure pattern scan, no Capstone required
starts = dec.function_starts()
print(f"{len(starts)} probable functions")

# disassemble() — pure Python, no Capstone required
insns = dec.disassemble(start=0x400, end=0x2000)
for i in insns:
    if i.insn_type in ("CALL", "RETURN"):
        print(i)

# decode single instruction
insn = dec.decode_one(0x400)
print(insn.mnemonic, insn.is_32bit)

# length of instruction at offset
length = dec.insn_length(0x400)  # 2 or 4
```

### Constructor parameters

| Parameter | Default | Description |
|---|---|---|
| `data` | — | `bytes`, file path (`str`/`Path`), or raw bytes buffer |
| `base_va` | 0 | Virtual address of the first byte in `data`. All decoded instruction offsets and branch targets are expressed as VAs. |

---

## SH2aInsn fields

```python
@dataclass
class SH2aInsn:
    offset:    int         # instruction VA (base_va + byte offset)
    is_32bit:  bool        # True for 32-bit SH-2A instructions
    mnemonic:  str         # instruction mnemonic, e.g. "rts", "bsr", "movi20"
    insn_type: str         # see table below
    raw:       bytes       # raw instruction bytes (2 or 4)
    target:    int | None  # branch/call target VA when statically resolvable
    rd:        int | None  # destination register (0-15)
    rs:        int | None  # source register (0-15)
    imm:       int | None  # immediate value (signed)
```

`insn_type` values:

| Type | Instructions |
|---|---|
| `RETURN` | `rts`, `rts/n` |
| `BRANCH` | `bra`, `bt`, `bf`, `bt/s`, `bf/s` |
| `CALL` | `bsr`, `jsr` |
| `LR_SAVE` | `sts.l pr, @-r15` (stack), `sts pr, Rn` (register) |
| `LR_RESTORE` | `lds.l @r15+, pr`, `lds Rn, pr` |
| `LOAD` | `mov.l @(disp,pc)`, `mov.w @(disp,pc)`, `mov.l @r15+,Rn` |
| `STORE` | `mov.l Rm, @-r15` |
| `MISC` | All others (mov, add, cmp, movi20, etc.) |

---

## Branch target computation

SH-2/SH-2A has a **delay slot** (one instruction after every branch executes before
the branch takes effect).  The PC seen by the branch displacement computation is
`instruction_VA + 4` (not +2):

```
BSR/BRA disp12:  target = VA + 4 + sign_extend(disp12) * 2
BT/BF/BT.S/BF.S disp8:  target = VA + 4 + sign_extend(disp8) * 2
```

`JSR @Rn` and `JMP @Rn` are indirect — target is a runtime register value, returned
as `target = None`.

---

## 32-bit instruction coverage

| Mnemonic | Encoding | Decoded |
|---|---|---|
| `movi20` | `(hw & 0xF00F) == 0x0005` | rd, imm (signed 20-bit) |
| `movi20s` | `(hw & 0xF00F) == 0x0007` | rd, imm (shifted 20-bit) |
| `mov.b/w/l @(d12,Rm),R0` | `(hw & 0xF00F) == 0x3001` + sub_op | LOAD + disp12 |
| `mov.b/w/l R0,@(d12,Rn)` | `(hw & 0xF00F) == 0x3001` + sub_op | STORE + disp12 |
| `bclr.b/bset.b/bst.b/bld.b` | `(hw & 0xF00F) == 0x3009` | MISC |

---

## Limitations

- No SH-2A FPU instructions decoded (not present in ECU firmware; decoded as MISC).
- `BRAF Rn` / `BSRF Rn` (indirect relative branch/subroutine): decoded as MISC with no
  target (register-indirect, not statically resolvable).
- Unvalidated on real Honda or Subaru ROM — all encoding derived from Renesas SH2A Hardware
  Manual Rev.2.00.  A real corpus run is required before treating function_starts() output
  as ground truth for these targets.
- `function_starts()` does not walk call graph from reset vector.
  `FlatBinaryFuncStartScanner` adds that capability once built.
