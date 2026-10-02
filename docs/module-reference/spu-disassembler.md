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
| op9=0x043  | `il rt, s16` | sequential immediates 0x4010→0x4015 in addmat |
| op9=0x047  | `ilhu rt, u16` | address-formation pairs in addmat |
| op9=0x07D  | `stqr rt, s16` | register saves in function prologues |
| op9=0x07F  | `lqr rt, s16`  | large-neg PC-relative offsets to static data |
| op9=0x098  | `stqr rt, s16` | alt encoding (0x4c002b60 confirmed) |

## Coverage Gaps (Crysis 2 SPU0, as of initial module version)

| Op | Hits | Notes |
|----|------|-------|
| op11=0x19d | 402 | unknown |
| op11=0x0c1 | 344 | unknown |
| op11=0x0a0 | 282 | unknown |
| op11=0x2b6 | 244 | unknown |
| op11=0x0d3 | 224 | unknown |
| op11=0x2ae | 211 | unknown |
| op11=0x1a8 | 210 | pipeline NOP variant (appears at function boundaries) |
| op11=0x0a1 | 192 | unknown |

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
