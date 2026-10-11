# ecu-c28x-decoder

## Why this exists

4 things that weren't possible before in Ablation:

1. **No C28x disassembler existed in any supported toolchain.** Capstone 5.x has no
   TMS320C28x support. Ghidra and Radare2 support C28x, but Ablation cannot invoke them
   from Python without a subprocess dependency. The F28x-series MCUs (F28335, F28P55x,
   F2837x, F2838x) used in EV/HEV traction-inverter controllers and motor-drive ECUs were
   entirely opaque to Ablation's control-flow passes.

2. **The two C28x calling conventions could not be distinguished.** `LC/LRET` (return
   address on the software stack, 8-cycle return) and `LCR/LRETR` (return address in the
   RPC register, 4-cycle return) each require different stack-unwinding logic. Without a
   decoder, Ablation could not decide which convention a given function uses, making CFG
   construction impossible.

3. **`FFC XAR7, 22bit` — a third calling convention — was unknown to Ablation.** FFC
   (Fast Function Call) stores the return address in the XAR7 register rather than the
   stack or RPC. It is used in performance-sensitive inner loops and is not identified by
   any stack-frame analysis tool that assumes only CALL/RET pairs.

4. **Word-addressed branching could not be modeled.** C28x program memory is word-addressed.
   PC-relative branch offsets are signed 16-bit word counts, not byte counts. Applying
   byte-count displacement arithmetic produces wrong target addresses for every C28x branch.

---

## What it does

`EcuC28xDecoder` decodes TMS320C28x instructions from a raw byte buffer using the
encodings in SPRU430F (TMS320C28x CPU and Instruction Set Reference Guide, April 2015).
It identifies control-flow instructions (branches, calls, returns), computes branch targets
in word-addresses, and provides a `function_starts()` method that returns probable function
entry points from direct call targets.

Primary consumer: C28x firmware analysis in the auto-ECU corpus and any TI F28x target
where `TiCoffLoader` has extracted a code section.

---

## Usage

```python
from ablation.analyzers.ecu_c28x_decoder import EcuC28xDecoder

# Decode from raw bytes (base_va is a word address, default 0)
dec = EcuC28xDecoder(code_bytes, base_va=0x3F8000)

# Decode a range (byte offsets into the buffer)
insns = dec.disassemble(start=0, end=len(code_bytes))
for insn in insns:
    print(insn)

# Decode one instruction
insn = dec.decode_one(byte_off=0)

# Get length of instruction at a byte offset
length = dec.insn_length(byte_off=0)   # 2 or 4

# Collect direct call targets as candidate function entry points
starts = dec.function_starts()   # list of word VAs, sorted
```

`from_path()` and `from_bytes()` are convenience constructors. `from_path()` raises
`FileNotFoundError` or `OSError` on missing/unreadable files (caller catches).

---

## C28xInsn fields

| Field | Type | Meaning |
|---|---|---|
| `word_va` | `int` | Word-address VA of the instruction |
| `is_32bit` | `bool` | True when this is a 2-word (32-bit) instruction |
| `mnemonic` | `str` | Instruction mnemonic string |
| `insn_type` | `str` | `BRANCH`, `CALL`, `RETURN`, `LOOP`, or `MISC` |
| `raw` | `bytes` | 2 or 4 raw bytes (little-endian word order) |
| `target` | `int | None` | Word-address target VA (branches/calls with static target) |
| `cond` | `str | None` | Condition code name for B/BF/BAR; None = unconditional |
| `imm` | `int | None` | Immediate value (INTR interrupt number, IACK mask, etc.) |

---

## Instruction encoding reference

All encodings from SPRU430F. `w1` = first instruction word, `w2` = second word (for
32-bit instructions). Little-endian byte order: bytes 0-1 = w1, bytes 2-3 = w2.

### Branch instructions (32-bit, 2 words)

| Instruction | w1 pattern | w2 | Notes |
|---|---|---|---|
| `B COND, #offset` | `0xFFE0 \| cond` | signed offset16 | Cond branch; UNC=unconditional |
| `BF COND, #offset` | `0x56C0 \| cond` | signed offset16 | Branch Fast (4 cycles) |
| `BANZ #off, ARn--` | `0x0008 \| n` | signed offset16 | Branch if ARn != 0, decrement |
| `BAR #off, ARn, ARm, EQ` | `0x8F80 \| (n<<3) \| m` | signed offset16 | |
| `BAR #off, ARn, ARm, NEQ` | `0x8FC0 \| (n<<3) \| m` | signed offset16 | |
| `LB 22bit` | `0x0040 \| addr[21:16]` | `addr[15:0]` | Long branch, absolute word addr |

### Call instructions (32-bit, 2 words)

| Instruction | w1 pattern | w2 | Notes |
|---|---|---|---|
| `LC 22bit` | `0x0080 \| addr[21:16]` | `addr[15:0]` | Long call (return on stack) |
| `FFC XAR7, 22bit` | `0x00C0 \| addr[21:16]` | `addr[15:0]` | Fast call (return in XAR7) |
| `LCR #22bit` | `0x7640 \| addr[21:16]` | `addr[15:0]` | Long call using RPC register |

22-bit extraction: `addr22 = ((w1 & 0x3F) << 16) | w2`

### Indirect branches and calls (16-bit, 1 word)

| Instruction | Encoding | insn_type |
|---|---|---|
| `LB *XAR7` | `0x7620` | BRANCH |
| `LC *XAR7` | `0x7604` | CALL |
| `LCR *XARn` | `0x3E60 \| n` | CALL |

### Return instructions (16-bit, 1 word)

| Instruction | Encoding | Notes |
|---|---|---|
| `LRET` | `0x7614` | Long Return from stack (pairs with LC) |
| `LRETE` | `0x7610` | Long Return + enable interrupts |
| `LRETR` | `0x0006` | Long Return from RPC register (pairs with LCR) |
| `IRET` | `0x7602` | Interrupt Return |

### Condition codes (COND field, 4 bits)

```
0x0=NEQ  0x1=EQ   0x2=GT   0x3=GEQ
0x4=LT   0x5=LEQ  0x6=HI   0x7=HIS
0x8=LO   0x9=LOS  0xA=NOV  0xB=OV
0xC=NTC  0xD=TC   0xE=NBIO 0xF=UNC
```

### Branch target computation

For 2-word (32-bit) instructions: `target_word_va = word_va + 2 + signed_offset`

For absolute 22-bit instructions: `target_word_va = addr22`

---

## Word addressing vs byte offsets

C28x program memory is word-addressed. The `base_va` parameter is a **word address**
(the program address of the first instruction word in the buffer). All `word_va` and
`target` fields in `C28xInsn` are word addresses.

The `disassemble(start, end)` and `decode_one(byte_off)` methods take **byte offsets**
into the raw data buffer (not word addresses). Conversion: `byte_off = (word_va - base_va) * 2`.

---

## Reference

SPRU430F — TMS320C28x CPU and Instruction Set Reference Guide, April 2015.
Per-instruction encoding pages used: 163 (B), 167 (BF), 162 (BANZ), 162 (BAR),
197 (FFC), 217 (LB 22bit), 216 (LB *XAR7), 219 (LC 22bit), 218 (LC *XAR7),
220 (LCR #22bit), 221 (LCR *XARn), 213 (INTR), 207 (IACK), 227 (LRET),
228 (LRETE), 229 (LRETR), 214 (IRET), 222-225 (LOOPNZ/LOOPZ).
