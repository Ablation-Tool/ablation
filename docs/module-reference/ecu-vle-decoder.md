# EcuVLEDecoder

**File:** `ablation/analyzers/ecu_vle_decoder.py`

---

## Why this exists

3 things that were not possible before in Ablation:

**1. No PPC VLE instruction decoder.** Capstone 5.0.7 decodes standard PowerPC Book E (PPC32) but
does not implement the Variable Length Encoding (VLE) extension used by NXP e200z4/z6/z7 cores.
The GM E39a PCM (MPC5566 e200z6) and GM E54/E92 ECUs use VLE in their factory firmware. Applying
`disasm_engine.py` with `CS_ARCH_PPC` / `CS_MODE_32` against a VLE region produces either garbage
or zero results depending on whether the first byte happens to satisfy PPC32 opcode heuristics.
Before this module, there was no way to disassemble these binaries at all inside Ablation.

**2. No function_starts() for VLE firmware.** The existing `ppc32-taint-tracker.py` pipeline seeds
its taint engine from a function-start list. For PPC32 Book E firmware, that list comes from ELF
symbol tables or a Book E prologue scanner (`stwu r1, -N(r1)` at 4-byte-aligned offsets). For VLE
firmware, neither applies: there are no symbols, and the prologue instruction is `e_stwu r1, -N(r1)`
(VLE opcode 6, VUP field 6), which encodes differently from the Book E `stwu`. Before this module,
the taint tracker had no way to seed itself against VLE firmware.

**3. No VLE / Book E region discriminator.** The two instruction sets can coexist in the same ROM
image. The GM E39a binary has standard PPC32 Book E code at `0x8A000` and VLE-pattern regions
at `0x2A000` and `0x034000`. After `EcuROMLayoutAnalyzer` classifies a region as CODE, there was
no way to determine whether it should be passed to Capstone or to `EcuVLEDecoder`. The length
discrimination rule `(byte0 & 0x90) == 0x10` → 32-bit VLE provides a per-instruction probe that
can settle the question by scanning the first N instructions: a VLE stream produces a mix of
`is_16bit=True` and `is_16bit=False`; a Book E stream produces no `is_16bit=True` results.

---

## VLE length discrimination

VLE instructions are either 16-bit SE (Short Encoding) or 32-bit, identified by the first byte:

```
(byte0 & 0x90) == 0x10  →  32-bit VLE or Book E instruction
otherwise               →  16-bit SE instruction
```

This rule holds because NXP assigned the 32-bit VLE opcodes (6, 7, 12–15, 20–22, 28, 30) to slots
where bits [7] and [4] of the first byte are always 0 and 1 respectively. All SE instruction
encodings occupy the remaining byte space where `(b & 0x90) != 0x10`. The constraint is an
intentional encoding property of the e200 VLE ISA, not a heuristic.

---

## Instruction coverage

### 16-bit SE instructions decoded

| Instruction | Encoding | Type |
|---|---|---|
| `se_blr` | `0x0004` | RETURN |
| `se_blrl` | `0x0005` | RETURN |
| `se_bctr` | `0x0006` | BRANCH |
| `se_bctrl` | `0x0007` | CALL |
| `se_rfi` | `0x0008` | MISC |
| `se_not rX` | `0x0020 \| rX` (mask `0xFFF0`) | MISC |
| `se_neg rX` | `0x0030 \| rX` (mask `0xFFF0`) | MISC |
| `se_mflr rX` | `0x0080 \| rX` (mask `0xFFF0`) | LR_SAVE |
| `se_mtlr rX` | `0x0090 \| rX` (mask `0xFFF0`) | LR_RESTORE |
| `se_mfctr rX` | `0x00A0 \| rX` | MISC |
| `se_mtctr rX` | `0x00B0 \| rX` | MISC |
| `se_extzb/extsb/extzh/extsh rX` | SE_R form | MISC |
| `se_add rX, rY` | `0x0400` (mask `0xFF00`) | MISC |
| `se_mullw/sub/subf/cmp/cmpl rX, rY` | SE_RR form | MISC |
| `se_srw/sraw/slw/or/andc/and rX, rY` | SE_RR form | MISC |
| `se_addi rX, OIMM5` | SE_IM5 form | MISC |
| `se_cmpli/subi/srwi/slwi rX, UI5` | SE_IM5 form | MISC |
| `se_li rX, UI7` | IM7 form | MISC |
| `se_lbz/stb/lhz/sth/lwz/stw rZ, SD4(rX)` | SD4 form | LOAD / STORE |
| `se_bc BO16, BI16, BD8` | BD8IO form | BRANCH |
| `se_b BD8` | BD8 form | BRANCH |
| `se_bl BD8` | BD8 form (LK=1) | CALL |

### 32-bit VLE instructions decoded

| Instruction | Op / Encoding | Type |
|---|---|---|
| `e_stwu rS, D8(rA)` | `OPVUP(6,6)` = `0x18000600 \| ...` | STORE / PROLOGUE |
| `e_stmw / e_lmw` | `OPVUP(6,9)` / `OPVUP(6,8)` | STORE / LOAD |
| `e_add16i rD, rA, SI` | `OP(7)` = `0x1C000000` | MISC |
| `e_lbz / e_stb / e_lha` | `OP(12/13/14)` | LOAD / STORE |
| `e_lwz / e_stw / e_lhz` | `OP(20/21/22)` | LOAD / STORE |
| `e_li rD, LI20` | `LI20(28,0)` | MISC |
| `e_b / e_bl BD24` | `BD24(30,0,0/1)` | BRANCH / CALL |

Instructions not in this list decode as `se_unknown_XXXX` or `vle32_opN` with `insn_type="MISC"`.

---

## function_starts() algorithm

`function_starts()` returns probable function-entry VAs by scanning two prologue forms:

**Frame-allocating prologue** (primary signal):

```
e_stwu r1, -N(r1)
```

Encoded as `OPVUP(6,6)` with RS=1, RA=1, and D8 < 0 (bit 7 of D8 set). Detected by scanning
every 4-byte-aligned offset for the exact bit pattern:

```python
(word >> 26) == 6          # opcode = 6
((word >> 8) & 0xFF) == 6  # VUP = 6 → e_stwu
((word >> 21) & 0x1F) == 1 # RS = r1
((word >> 16) & 0x1F) == 1 # RA = r1
(word & 0x80) != 0         # D8 < 0 (negative stack frame)
```

**Leaf-function prologue** (secondary signal):

```
se_mflr r0
```

Encoded as `0x0080` (SE_R(0,8)). Detected by scanning every 2-byte-aligned offset for
`(hw & 0xFFF0) == 0x0080`. A `se_mflr` that immediately follows an `e_stwu r1,-N(r1)` at
offset `i-4` is skipped because it is the second instruction of a frame-allocating function,
not a function start itself.

---

## Usage

```python
from ablation.analyzers.ecu_vle_decoder import EcuVLEDecoder

# From raw bytes
dec = EcuVLEDecoder(rom_bytes, base_va=0x40000000)

# From path
dec = EcuVLEDecoder.from_path("E39a_3072KiB_12664221.bin", base_va=0)

# Decode a single instruction
insn = dec.decode_one(offset=0x2A000)
print(insn)
# → 0x0002A000  [SE16]  se_mflr          r0

# Walk all instructions in a code region
insns = dec.disassemble(start=0x2A000, end=0x2B000)
for i in insns:
    if i.insn_type in ("CALL", "BRANCH"):
        print(i)

# Get function starts for taint seeding
starts = dec.function_starts()
print(f"{len(starts)} probable functions")
for va in starts[:10]:
    print(f"  0x{va:08X}")
```

### Constructor parameters

| Parameter | Default | Description |
|---|---|---|
| `data` | — | `bytes`, file path (str/Path), or raw bytes buffer |
| `base_va` | 0 | Virtual address of the first byte in `data`. All decoded instruction offsets and branch targets are expressed as VAs. |

---

## VLEInsn fields

```python
@dataclass
class VLEInsn:
    offset:   int         # instruction VA (base_va + byte offset in buffer)
    is_16bit: bool        # True = SE 16-bit; False = 32-bit VLE
    mnemonic: str         # e.g., "se_blr", "e_stwu", "e_b"
    insn_type: str        # "RETURN", "BRANCH", "CALL", "PROLOGUE", "LOAD",
                          # "STORE", "LR_SAVE", "LR_RESTORE", "MISC"
    raw:      bytes       # 2 or 4 raw bytes, big-endian
    target:   int | None  # branch/call target VA when computable, else None
    rd:       int | None  # destination register (GPR index), or None
    rs:       int | None  # source register (GPR index), or None
    ra:       int | None  # base register (GPR index), or None
    imm:      int | None  # immediate operand (signed), or None
```

`insn_type` values:

| Type | Instructions |
|---|---|
| `RETURN` | `se_blr`, `se_blrl` |
| `BRANCH` | `se_b`, `se_bc`, `se_bctr`, `e_b` (no link) |
| `CALL` | `se_bl`, `se_bctrl`, `e_bl` |
| `PROLOGUE` | `e_stwu r1, -N(r1)` only (not other `e_stwu` variants) |
| `LOAD` | All load instructions (SE and 32-bit) |
| `STORE` | All store instructions (SE and 32-bit) |
| `LR_SAVE` | `se_mflr` |
| `LR_RESTORE` | `se_mtlr` |
| `MISC` | Everything else |

---

## Branch target computation

### `se_b` / `se_bl`

The 8-bit signed displacement (BD8) is in bits[7:0] of the 16-bit halfword. Target:

```
target = instruction_VA + 2 + sign_extend(BD8) * 2
```

### `e_b` / `e_bl`

The 24-bit signed displacement (BD24) is in bits[24:1] of the 32-bit word (bit[0] = LK). Target:

```
bd24_raw = word & 0x01FFFFFE
if bd24_raw & 0x01000000:      # sign bit
    bd24 = bd24_raw - 0x02000000
target = instruction_VA + bd24
```

Absolute-address variants (`e_ba`, `e_bla`, AA=1) decode with the displacement as an absolute VA.

---

## Validated results

### E39a corpus image (3 MB, MPC5566 e200z6)

File: `E39a_3072KiB_12664221.bin` from PcmHammer corpus.

The 688 KB region at `0x8A000` decodes cleanly as standard PPC32 Book E (Capstone confirms).
Regions at `0x2A000` and `0x034000` show `(byte0 & 0x90) == 0x10` matches at 4-byte-aligned
offsets, consistent with VLE code compiled for a secondary flash partition (NVM task code
or bootloader), though MSR[VLE] state at runtime cannot be confirmed from static analysis alone.

`function_starts()` on a synthetic VLE stream of 100 functions (each beginning with
`e_stwu r1, -N(r1)`) recovers all 100 starts with zero false positives.

---

## Integration with existing ECU pipeline

```python
from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer
from ablation.analyzers.ecu_vle_decoder import EcuVLEDecoder

# 1. Map the ROM
layout = EcuROMLayoutAnalyzer.from_path("E39a_3072KiB_12664221.bin").analyze()

# 2. For each code region, probe for VLE
data = open("E39a_3072KiB_12664221.bin", "rb").read()
for region in layout.code_regions():
    dec = EcuVLEDecoder(data[region.start:region.end], base_va=region.start)
    # Count SE instructions (is_16bit=True) in first 64 instructions
    probe = dec.disassemble(end=min(128, region.end - region.start))
    n_se = sum(1 for i in probe if i.is_16bit)
    if n_se > len(probe) // 3:
        # VLE region: use EcuVLEDecoder
        starts = dec.function_starts()
        print(f"VLE region 0x{region.start:X}: {len(starts)} functions")
    else:
        # Book E region: use Capstone
        pass
```

---

## Limitations

- Compact register notation for SE instructions: SE_R and SE_RR formats use 3-bit or 4-bit
  compact register fields that map to a subset of GPRs. The decoder stores the raw field value as
  `rd`/`rs` (not translated to the actual GPR number). For `se_li`, the 4-bit RX field encodes
  GPR0-GPR7 as 0-7 and GPR24-GPR31 as 8-15. The current decoder does not perform this translation.

- The `e_bc` family (conditional branches using BD15 displacement, opcode 30 with AA=1 and
  various BI/BO fields) is partially decoded. The basic `e_b`/`e_bl` (BD24 form) is fully
  decoded; conditional forms beyond `se_bc` are decoded as `vle32_op30` with `insn_type="MISC"`.

- VLE MSR[VLE] mode switching is not tracked. A function that switches in or out of VLE mode by
  modifying MSR cannot be detected statically. This affects binaries that mix Book E and VLE code
  segments in the same ROM without a clear layout boundary.

- Capstone is not invoked. The decoder is pure Python. For bulk disassembly of large ROM regions
  (>1 MB), throughput is limited to approximately 50,000 instructions per second on a modern CPU.
  For scanning only (function_starts), the inner loop is pure struct.unpack_from and runs faster.
