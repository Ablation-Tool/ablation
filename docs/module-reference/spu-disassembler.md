# SPU Disassembler

Cell BE Synergistic Processing Unit (SPU) instruction decoder. Handles all confirmed SPU ISA instruction formats from a 32-bit big-endian instruction stream.

## Import

```python
from ablation.analyzers.spu_disassembler import (
    decode_spu_word,
    disassemble_spu_text,
    extract_spu_text_from_elf,
    dump_spu_elf,
    frequency_report,
    SPUInstruction,
)
```

## Core API

### `decode_spu_word(addr, word) → SPUInstruction`

Decode a single 32-bit big-endian SPU instruction word.

```python
insn = decode_spu_word(0x3050, 0x4206d803)
print(insn.asm())   # "ila	$3, 0xdb0"
print(insn.fmt)     # "ri18"
print(insn.mnemonic) # "ila"
```

### `disassemble_spu_text(data, base_vaddr, limit) → Iterator[SPUInstruction]`

Iterate over instructions in a raw text section (bytes).

```python
for insn in disassemble_spu_text(text_bytes, base_vaddr=0x3000):
    print(insn.asm())
```

### `extract_spu_text_from_elf(elf_data) → (text_bytes, base_vaddr, entry_vaddr)`

Extract the executable PT_LOAD segment from an SPU ELF (machine type 0x17).

```python
raw = open("crysis2_spu_0.elf", "rb").read()
text, base, entry = extract_spu_text_from_elf(raw)
```

### `dump_spu_elf(path, start_va, end_va, limit) → str`

Disassemble an SPU ELF to a string. `start_va`/`end_va` filter to a VA range.

```python
print(dump_spu_elf("/tmp/crysis2_spu_0.elf", start_va=0x3050, limit=64))
```

### `frequency_report(data, base_vaddr) → str`

Coverage analysis: mnemonic frequency table + unknown opcode gaps.

```python
text, base, _ = extract_spu_text_from_elf(raw)
print(frequency_report(text, base))
```

## Instruction Format Hierarchy

| Format | Opcode bits | Field extraction |
|--------|-------------|-----------------|
| RRR    | top 4 (0xA-0xF) | selb/shufb/fma/fnms/fms/mpya |
| RI18   | bits 31-25 (7-bit) | I18 = `(w>>7)&0x3FFFF`, rT = `w&0x7F` |
| RI16   | bits 31-23 (9-bit) | I16 = signed `(w>>7)&0xFFFF`, rT = `w&0x7F` |
| RI10   | bits 31-24 (8-bit) | I10 = signed `(w>>14)&0x3FF`, rA = `(w>>7)&0x7F`, rT = `w&0x7F` |
| RR/RI7 | bits 31-21 (11-bit) | rB = `(w>>14)&0x7F`, rA = `(w>>7)&0x7F`, rT = `w&0x7F` |

RI16 is checked before RI10 — this matters because lqr/stqr/il/ilhu/iohl use 9-bit opcodes that overlap with 8-bit RI10 space.

## Confirmed Opcode Coverage

Empirically confirmed from:
- IBM Cell SDK `addmat` example (not-stripped SPU ELF, 1128 instructions)
- Crysis 2 PS3 SPU0 ELF (38,556 instructions, physics/rendering)

Key confirmations:

| Opcode | Mnemonic | Confirmation |
|--------|----------|-------------|
| op11=0x001 | `lnop` | 941 hits Crysis2, pipeline odd-slot NOP |
| op11=0x201 | `nop` | 1072 hits Crysis2, pipeline even-slot NOP |
| op11=0x204 | `cbd` | 2467 hits Crysis2 (was top unknown) |
| op11=0x209 | `cwx` | 0x413fff88 in addmat |
| op11=0x1C0 | `fa`  | was "op8=0x38 (2167 hits)" top unknown |
| op11=0x1DC | `csflt` | 1590 hits Crysis2 (was "op11=0x1dc" unknown) |
| op11=0x1DD | `cuflt` | convert unsigned int to float (RI7 scale7; adjacent to csflt) |
| op11=0x2AE | `cfltu` | convert float to unsigned int (RI7 scale7; 211 hits Crysis2) |
| op11=0x2B6 | `cflts` | convert float to signed int (RI7 scale7; 244 hits Crysis2) |
| op11=0x0A0 | `frds`  | float round double to single (tentative; after csflt, 282 hits) |
| op11=0x0A1 | `fesd`  | float extend single to double (tentative; rA=rT-1 pattern, 192 hits) |
| op11=0x0C1 | `addx`  | add extended with carry (tentative; tree-reduction, 344 hits) |
| op11=0x0D3 | `mpys`  | multiply and shift right (tentative; in shufb sequences, 224 hits) |
| op11=0x19D | `rotqbyx` | rotate quadword by bytes indexed (tentative; rB=$81 fixed, 402 hits) |
| op11=0x1A8 | `fence` | data sync barrier (word=0x35000000, rT=rA=rB=$0 always, 210 hits) |
| op11=0x1A9 | `fence2` | float-pipe drain/sync (rT=$0 always, follows csflt, 127 hits) |
| op11=0x2C0 | `cg`   | carry generate (tentative; precedes cgx in multi-precision chain) |
| op11=0x2E0 | `cgx`  | carry generate extended (tentative; cg→cgx→addx triple) |
| op9=0x043  | `il rt, s16` | sequential immediates 0x4010→0x4015 in addmat |
| op9=0x047  | `ilhu rt, u16` | address-formation pairs in addmat |
| op9=0x067  | `stqr rt, s16` | 402 hits Crysis2, forward PC-relative offsets |
| op9=0x07D  | `stqr rt, s16` | register saves in function prologues |
| op9=0x07F  | `lqr rt, s16`  | large-neg PC-relative offsets to static data |
| op9=0x098  | `stqr rt, s16` | alt encoding (0x4c002b60 confirmed) |

## Coverage (Crysis 2 SPU0 — 38,556 instructions)

| Version | Known | Coverage |
|---------|-------|----------|
| v0 (initial) | ~33,000 | ~85% |
| v1 (after addmat ground-truth) | ~36,100 | 93.8% |
| v2 (RI16/RI10 gap fills) | ~36,600 | 95.0% |

## Added in v2

| Op | Mnemonic | Evidence |
|----|----------|----------|
| op9=0x09A | lqr | RI16; produces values consumed by addx (146 hits) |
| op9=0x09B | lqr | RI16; parallel to 0x09A with large I16 (145 hits) |
| op9=0x0FE | lqr | RI16; loads pointer into $0 before cbd (43 hits) |
| op8=0x79  | ceqbi | RI10; fills gap between cgtbi(0x78)/cgthi(0x7A) in compare-byte chain (136 hits) |

## Remaining Gaps (top unknowns after v2)

| Op | Hits | Notes |
|----|------|-------|
| op11=0x1d6 | 108 | always same rA/rB as preceding fm; float domain |
| op8=0x83 (0x418–0x41f) | ~250 total | RI10 group; 8 op11 variants; mixed contexts |
| op11=0x2a5 | 84 | op8=0x54; rB=$0 always |
| op11=0x008 | 58 | inline constant data (0x01010101 pattern) embedded in text |
| op11=0x1b4 | 50 | rB=$0 always, follows andbi, before shufb |

## Embedded SPU ELF Extraction from PPU ELFs

Crysis 2 PS3 PPU ELF contains 23 embedded SPU ELFs (raw ELF data, machine type 0x17 = SPU):

```python
import struct

def find_spu_elfs(ppu_elf_data):
    results = []
    off = 0
    while True:
        idx = ppu_elf_data.find(b'\x7fELF', off)
        if idx == -1:
            break
        try:
            if struct.unpack_from(">H", ppu_elf_data, idx+18)[0] == 0x17:
                results.append(idx)
        except Exception:
            pass
        off = idx + 1
    return results
```
