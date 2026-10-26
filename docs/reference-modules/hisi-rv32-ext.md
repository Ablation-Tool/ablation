# HiSiliconRV32ExtDecoder

Correct-size disassembly for HiSilicon WS63 / Hi3863 / BS21 (Hi2821) NearLink SoC
firmware and all other HiSilicon bare-metal RISC-V targets using the proprietary
`riscv31` core with HCC Huawei Custom C ISA extensions.

---

## What this is <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon's WS63, Hi3863, and BS21 NearLink SoCs use an RV32GC core with six proprietary opcode spaces. Capstone 5.x does not recognize any of them. When Capstone encounters a HiSilicon custom instruction, it reads the wrong number of bytes and misaligns every decode that follows in the function. The 48-bit `l.li` instruction is the most dangerous case: a single occurrence shifts all subsequent decodes by two bytes with no error or warning.

`HiSiliconRV32ExtDecoder` intercepts all six custom opcode spaces before Capstone processes them, so instruction boundaries stay correct through the full function.

---

## Where it's used <sup>[↑](#hisiliconrv32extdecoder)</sup>

- **HiSilicon WS63 / Hi3863**: NearLink WS63E development kit firmware, BearPi-HH-NB3 LiteOS images
- **HiSilicon BS21 / Hi2821**: NearLink BS21E firmware, BearPi-HH-NB3 SLE images
- Any HiSilicon bare-metal RV32GC firmware compiled for the `riscv31` + HCC extension core

---

## Safe usage <sup>[↑](#hisiliconrv32extdecoder)</sup>

**Pass `ext_decoder=dec` to `RISCV32TaintTracker.from_path()`.** Constructing the tracker without the ext_decoder falls back to plain Capstone. Every custom instruction then misaligns subsequent decodes and the taint analysis runs on wrong instruction boundaries.

**Use `conservative=True` for any binary with unknown `0x7b` custom-3 semantics.** The decoder knows the encoding but not the semantics of the roughly 9,000 custom-3 variants in WS63 firmware. Conservative mode propagates taint from rs1 and rs2 to rd so no taint path is silently dropped.

**Run `dec.opcode_report()` before taint analysis.** If the report shows `l.li` instances, confirm the lifter walks past them correctly. Each `l.li` is 6 bytes and a plain Capstone pass produces wrong boundaries at every occurrence.

**Verify the target is a HiSilicon RV32 binary.** A standard RISC-V binary works correctly with this decoder but wastes the interception logic. An ARM or x86 binary produces nonsense and no error.

---

## The problem: six custom opcode spaces <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon's `riscv31` core extends base RV32GC with six custom opcode spaces plus
two 16-bit compressed extensions:

| Opcode | Space | Instructions | Size |
|--------|-----------|--------------|------|
| `0x0b` | custom-0 | `ldmia`, `stmia`: multi-register load/store | 4 B |
| `0x1b` | OP-IMM-32 | `addshf`, `subshf`, `orshf`, `xorshf`, `andshf` | 4 B |
| `0x1f` | reserved | `l.li`: 48-bit long load-immediate | **6 B** |
| `0x3b` | OP-32 | `beqi`, `bnei`, `bgei`, `blti`, `bgeui`, `bltui` | 4 B |
| `0x5b` | custom-2 | `muliadd` | 4 B |
| `0x7b` | custom-3 | R-type dispatch/context broad multi-op | 4 B |
| (16-bit) | RVC Q1 | `uxtb`, `uxth`: zero-extend to 8/16 bits | 2 B |

Capstone 5.x mishandles all six:

- `0x0b/0x5b/0x3b/0x1b`: decoded as a 2-byte `.byte` pair, then the trailing
 2 bytes are misinterpreted as a valid RVC instruction. 2-byte cascade misalignment.
- `0x7b`: same 2-byte misalignment (Capstone occasionally decodes `0x7b` R-type as
  `c.fsdsp`, consuming 2 bytes).
- `0x1f`: decoded as a 4-byte instruction (bits[1:0]=11 is satisfied), leaving
 2 unaccounted bytes that corrupt the next instruction boundary.
- `uxtb`/`uxth`: occupy the RVC C.FLD/C.FSD compressed D-float space, which
 Capstone would decode as float load/store on targets without the D extension.

`l.li` is architecturally the most dangerous: every occurrence silently shifts
the decoder 2 bytes behind the true instruction stream for the rest of the function.

## What this module provides <sup>[↑](#hisiliconrv32extdecoder)</sup>

`HiSiliconRV32ExtDecoder` is a drop-in replacement for `capstone.Cs` with the
same `disasm_lite()` signature. It detects all five custom opcode bytes before
forwarding to Capstone, consuming the correct number of bytes for each.

Push/pop/popret are **not** handled here; they are 16-bit RVC instructions in
Quadrant-0 custom slots bits[15:13]=100, bits[1:0]=00 per
`riscv_push_pop_extension.rst`. Capstone's skipdata mode handles them adequately
for taint purposes.

## Instruction encodings <sup>[↑](#hisiliconrv32extdecoder)</sup>

### 0x0b: `ldmia` / `stmia` 4 bytes, multi-register <sup>[↑](#hisiliconrv32extdecoder)</sup>

Multi-register load/store with banked register lists. HiSilicon equivalent of ARM's
`ldmia`/`stmia` prologue/epilogue patterns.

```
bits[6:0]   = 0x0b
bits[12]    = 0 → ldmia,  1 → stmia
bits[14:13] = funct3[2:1] (funct3≥2 = reserved/prefd, skip)
bits[19:15] = base register
bits[31]    = bank selector  (0 = bank-0 callee-saved, 1 = bank-1 caller-saved)
bits[30:7]  = register bitmap  (slot positions → actual registers via table below)
```

**Slot-bit mapping** (`_LDMSTM_SLOT_BIT[i]` → bit position in the 32-bit word):

| Slot | Bit | Bank-0 reg | Bank-1 reg |
|------|-----|-----------|-----------|
| 0 | 30 | x27 (s11) | x31 (t6) |
| 1 | 29 | x26 (s10) | x30 (t5) |
| 2 | 28 | x25 (s9) | x29 (t4) |
| 3 | 27 | x24 (s8) | x28 (t3) |
| 4 | 26 | x23 (s7) | x17 (a7) |
| 5 | 25 | x22 (s6) | x16 (a6) |
| 6 | 24 | x21 (s5) | x15 (a5) |
| 7 | 23 | x20 (s4) | x14 (a4) |
| 8 | 22 | x19 (s3) | x13 (a3) |
| 9 | 21 | x18 (s2) | x12 (a2) |
| 10 | 20 | x11 (a1) | x11 (a1) |
| 11 | 11 | x10 (a0) | x10 (a0) |
| 12 | 10 | x9 (s1) | x7 (t2) |
| 13 | 9 | x8 (s0) | x6 (t1) |
| 14 | 8 | x2 (sp) | x5 (t0) |
| 15 | 7 | x1 (ra) | x1 (ra) |

**Critical decoder rule:** bit7 (`_LDMSTM_SLOT_BIT[15]` = ra slot) is a valid register
bitmap bit, not the `rd` lsb used by standard 32-bit R-type encoding. Do **not**
gate dispatch on `(b0 & 0x80) == 0`; any ldmia/stmia saving ra will have bit7 set.
Example: `ldmia {ra},(sp)` = `0x0001008b` → b0=0x8b, bit7=1.

**Taint semantics:** `ldmia` loads from untracked memory → each loaded register is
untainted. `stmia` stores registers to memory; destination memory not tracked.

Verified from `trans_xlinx.c.inc` (QEMU xlinx extension implementation,
`/media/cowboy/research/hisilicon-ws63-re/online/zip_extract/`).

### 16-bit: `uxtb rd', imm` / `uxth rd'` (2 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

Zero-extend-to-8 and zero-extend-to-16 in the compressed instruction space.

```
Encoding mask:  insn & 0xFC5F == 0x9C01
Bit 5:          0 → uxtb,  1 → uxth
Bits[9:7]:      rd' offset (0–7 → register x8..x15 = a0..a5,s0,s1)
```

Decoded as:
```
rd = 8 + ((insn >> 7) & 0x7)
mnem = 'uxth' if (insn & 0x20) else 'uxtb'
```

These occupy the RVC C.FLD/C.FSD compressed D-float space. Capstone would mis-decode
them as float load/store on RV32 targets without the D extension; they must be
intercepted before Capstone sees them.

**Taint semantics:** Both `uxtb` and `uxth` bound the register to ≤255 / ≤65535
respectively, a bounding operation that clears taint, equivalent to `andi rd, rd, 0xFF`.

Verified from `trans_xlinx.c.inc` mask `(insn & 0xFC5F) == 0x9C01`.

### 0x1f: `l.li rd, imm32` (6 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
bytes[0:4] (LE uint32):  { imm[15:0] :: funct3=0 :: rd[4:0] :: 0x1f }
bytes[4:6] (LE uint16):  imm[31:16]
```

Verified: `l.li a0, 0x12345678` → `1f 05 78 56 34 12`
- Word = 0x5678051F: bits[11:7]=10(a0), bits[31:16]=0x5678
- HWord = 0x1234: imm[31:16]=0x1234 → full imm=0x12345678 ✓

### 0x1b: `addshf/subshf/orshf/xorshf/andshf` (4 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
bits[31:25] = {shift_type[1:0], shamt[4:0]}   (sll=00, srl=01, sra=10, ror=11)
bits[24:20] = rs2   (base register)
bits[19:15] = rs1   (register to shift)
bits[14:12] = funct3  (0=add, 1=sub, 2=or, 3=xor, 4=and)
bits[11:7]  = rd
bits[6:0]   = 0x1b
Semantics: rd = rs2 base_op shift_type(rs1, shamt)
```

Verified: `addshf a0,a1,a2,sll,3` → `0x06C5851B` rd=a0, rs1=a1, rs2=a2, shamt=3 ✓

Source: `riscv_preshifted_arithmetic.rst` riscvarchive/riscv-code-size-reduction

### 0x5b: `muliadd rd, rs1, rs2, uimm` (4 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
bits[31:25] = uimm[7:1]   (uimm[0]=0 always; unsigned 7-bit × 2)
bits[24:20] = rs2          (register to multiply)
bits[19:15] = rs1          (base register)
bits[14:12] = funct3
bits[11:7]  = rd
bits[6:0]   = 0x5b
Semantics: rd = rs1 + (rs2 * zero_ext(uimm))
```

Verified: `muliadd a0,a1,a2,4` → `0x04C5955B` rd=a0, rs1=a1, rs2=a2, uimm=4 ✓

Note: spec (`riscv_muladd_extension.rst`) assigns this to custom-1 (0x2b), but
HiSilicon silicon uses custom-2 (0x5b). `ldmia`/`stmia` were incorrectly attributed
to `0x5b` in prior versions; ground truth from `trans_xlinx.c.inc` places them at `0x0b`.

### 0x3b: `beqi/bnei/bgei/blti/bgeui/bltui` (4 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
bits[31:24] = cmpimm[7:0]    (8-bit signed comparison immediate)
bits[23:20] = offset[9:6]    (PC-relative branch offset, upper 4 bits)
bits[19:15] = rs1
bits[14:12] = funct3          (0=beqi, 1=bnei, 2=bgei, 3=blti, 4=bgeui, 5=bltui)
bits[11:7]  = offset[5:1]    (branch offset, lower 5 bits; bit0=0)
bits[6:0]   = 0x3b
```

Verified: `beqi a0,7,.` → `0x0705003B` cmpimm=7, rs1=a0, offset=0 ✓

Note: spec assigns to custom-0 (0x0b); HiSilicon silicon uses `0x3b` for branches and `0x0b` for ldmia/stmia.

### 0x7b: custom-3 R-type (4 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
image  = {funct7[6:0]} :: {rs2[4:0]} :: {rs1[4:0]} :: {funct3[2:0]} :: {rd[4:0]} :: 0x7b
syntax = "hisi.{funct3}.{funct7:02x}  {rd}, {rs1}, {rs2}"
```

~9000 occurrences, ~8900 unique encodings in WS63-liteos-app. Semantics unknown;
conservative taint: rs1,rs2 → rd when `HiSiliconRV32ExtDecoder(conservative=True)`.

## Usage <sup>[↑](#hisiliconrv32extdecoder)</sup>

```python
from ablation.analyzers.hisi_rv32_ext import HiSiliconRV32ExtDecoder
from ablation.analyzers.taint_tracker_riscv32 import RISCV32TaintTracker

dec = HiSiliconRV32ExtDecoder()

# HiSiliconRV32ExtDecoder
for addr, sz, mnem, ops in dec.disasm_lite(code_bytes, base_va):
    print(f"0x{addr:08x}  {sz}  {mnem}  {ops}")

# HiSiliconRV32ExtDecoder
for insn in dec.scan_all_custom(code_bytes, base_va):
    print(insn.mnemonic, insn.taint_sources, '->', insn.taint_dest)

# HiSiliconRV32ExtDecoder
print(dec.opcode_report(code_bytes, base_va))

# HiSiliconRV32ExtDecoder
tracker = RISCV32TaintTracker.from_path(elf_path, ext_decoder=dec)
findings = tracker.run_interprocedural()
```

## Taint semantics <sup>[↑](#hisiliconrv32extdecoder)</sup>

| Space | Default taint | `conservative=True` |
|-------|--------------|---------------------|
| 0x0b (ldmia) | clears taint on each loaded reg memory not tracked | same |
| 0x0b (stmia) | no taint propagation to memory | same |
| 0x1b (addshf) | rs1,rs2 → rd | same |
| 0x1f (l.li) | constant → rd no reg src | same |
| 0x3b branches | none branch only | same |
| 0x5b (muliadd) | rs1,rs2 → rd | same |
| 0x7b custom-3 | opaque no propagation | rs1,rs2 → rd |
| uxtb / uxth | clears taint bounds value ≤255/≤65535 | same |

## References <sup>[↑](#hisiliconrv32extdecoder)</sup>

- `fbb_ws63/src/drivers/chips/ws63/arch/riscv/riscv31/` (HiSilicon SDK)
- `riscv-code-size-reduction/existing_extensions/Huawei Custom Extension/` (GitHub)
- Perotti et al., CARRV 2020: "HW/SW approaches for RISC-V code size reduction"
- `tools_isa/poc_hisi_asm_map.py` + HiSilicon-patched GCC 7.3.0 empirical ground truth
- RI5CY User Manual PULP Platform, April 2019: base Xpulp encoding reference
- `trans_xlinx.c.inc`: QEMU xlinx extension RISC-V translator; canonical ground truth
 for `0x0b` ldmia/stmia slot_bit/slot_reg tables and uxtb/uxth 16-bit mask;
 archived at `/media/cowboy/research/hisilicon-ws63-re/online/zip_extract/`
- `HiMCUGenInstrInfo.td`: vendor LLVM fork Apache-2.0, © HiSilicon 2024; defines
 GROUP1 16-bit compressed: `c.neg/c.sbz/c.shz/c.swz/c.xori`; does NOT define
 ldmia/stmia/uxtb/uxth those are in the QEMU C back-end only

## Targets <sup>[↑](#hisiliconrv32extdecoder)</sup>

- HiSilicon WS63 / Hi3863 NearLink WS63E kit, BearPi-HH-NB3 LiteOS firmware
- HiSilicon BS21 / Hi2821 NearLink BS21E, BearPi-HH-NB3 SLE firmware
- Any HiSilicon bare-metal RV32GC firmware using the `riscv31` + HCC extensions

---

## Why this exists <sup>[↑](#hisiliconrv32extdecoder)</sup>

Prior to this module, hisilicon rv32 extension decoder required manual work outside the Ablation pipeline. This module integrates the capability directly so findings feed the shared `PatternLibrary` and `FindingRegistry` without a separate toolchain.

---

## How it works <sup>[↑](#hisiliconrv32extdecoder)</sup>

Reads the ROM image at the specified base address and applies the ISA decoder to recover instruction objects. Function boundaries are identified from preamble/epilogue patterns specific to the target compiler and ABI. Security-relevant patterns UDS handler tables, seed/key routines, calibration write paths are identified by combining structural matching with known compiler output signatures. Decoded results are stored in a `BinaryContext`-compatible format for downstream analysis.

---

## Example output <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
[CRITICAL] WEAK_SEED   UDS 0x27 0x01 at ROM:0x8004A0
  detail: seed is timestamp-derived (LSB of timer register)
  algorithm: linear congruential; key derivable in < 2^16 guesses

[HIGH] UNPROTECTED_WRITE   calibration region at ROM:0x810000
  detail: no write-protect fuse check before accepting 0x34 WriteDataByIdentifier
```

---

## False positives <sup>[↑](#hisiliconrv32extdecoder)</sup>

Calibration data regions contain byte sequences that decode as valid instructions in some ISAs. Confirm candidate function VAs against the ROM layout from `ECURomLayoutAnalyzer` before treating them as code. Security Access sequences in boot ROM are expected and not findings unless the seed/key algorithm is cryptographically weak.

---

## Pipeline position <sup>[↑](#hisiliconrv32extdecoder)</sup>

**Before this module:** `ECUArchDetector` to identify the processor family and confirm this decoder applies to the target ROM.

**After this module:** Feed decoded instructions to the appropriate taint tracker RH850, TriCore, SH-2A, or C28x for vulnerability analysis.

---

## Reading output <sup>[↑](#hisiliconrv32extdecoder)</sup>

`HiSiRV32Ext(ctx).scan_custom3code, base_va` returns `List[HisiInsn]`:

| Attribute | Content |
|:---|:---|
| `address` | VA of the instruction |
| `size` | Instruction size in bytes 4 for custom-3 encoding |
| `mnemonic` | Decoded mnemonic string for example `'hisi.conv2d'`, `'hisi.matmul'` |
| `op_str` | Decoded operand string |
| `rd` / `rs1` / `rs2` | Destination and source register indices |
| `funct3` / `funct7` | Function code fields from the 32-bit custom-3 encoding |

Use `scan_all_custom()` to scan all HiSilicon custom opcode spaces in one pass.

---

## See also <sup>[↑](#hisiliconrv32extdecoder)</sup>

- [ECUArchDetector](ecu-arch-detector.md): identify processor family before choosing a decoder
- [ECURomLayoutAnalyzer](ecu-rom-layout-analyzer.md): map ROM sections before decoding
- [ECUSecurityAccessScanner](ecu-security-access-scanner.md): find UDS 0x27 bypass vectors in decoded code
