# HiSilicon RV32 Extension Decoder

Correct-size disassembly for HiSilicon WS63 / Hi3863 NearLink SoC firmware and
other HiSilicon bare-metal RISC-V targets that use the proprietary custom-3 ISA
extension (opcode `0x7b`).

## The problem

Capstone 5.x's `skipdata` mode emits each custom-3 instruction as a 2-byte
`.byte` pair, then misinterprets the following 2 bytes as a valid compressed
instruction. The error cascades through the rest of the function: every
subsequent instruction is decoded 2 bytes behind the true boundary. Prologue
scanning, call-target resolution, and taint tracking all break downstream.

## What this module provides

`HiSiliconRV32ExtDecoder` is a drop-in replacement for `capstone.Cs` whose
`disasm_lite()` method has the same signature but handles custom-3 correctly.

It walks the byte stream. When it finds `0x7b` at a 2-byte-aligned position it
consumes 4 bytes and decodes them as a standard R-type instruction using
HiSilicon's observed field layout. Everything else is forwarded to the real
Capstone instance.

## Field encoding (nML grammar, single AND rule)

```
image  = {funct7[6:0]} :: {rs2[4:0]} :: {rs1[4:0]} :: {funct3[2:0]} :: {rd[4:0]} :: 0b1111011
syntax = "hisi.{funct3}.{funct7:02x}  {rd}, {rs1}, {rs2}"
action = unknown (no public ISA docs); conservative taint: rs1,rs2 → rd
```

The funct3 and funct7 fields follow standard RISC-V R-type layout (RISC-V ISA
Spec, Unprivileged §2.6 — "Custom" opcode space). With ~9000 instruction
occurrences across ~8900 unique encodings in the WS63 firmware, this is a broad
multi-operation extension, not a narrow accelerator.

## Usage

```python
from ablation.analyzers.hisi_rv32_ext import HiSiliconRV32ExtDecoder
from ablation.analyzers.taint_tracker_riscv32 import RISCV32TaintTracker

# Standalone: drop-in for capstone.Cs
dec = HiSiliconRV32ExtDecoder()
for addr, sz, mnem, ops in dec.disasm_lite(code_bytes, base_va):
    print(f"0x{addr:08x}  {sz}  {mnem}  {ops}")

# Taint tracking on HiSilicon firmware
tracker = RISCV32TaintTracker.from_path(elf_path, ext_decoder=dec)
findings = tracker.run_interprocedural()
```

## Output format

Custom-3 instructions appear as:

```
0x002d346a  4  hisi.6.44  t5, s9, a1
0x002d3496  4  hisi.6.44  t5, s3, a0
0x002d351a  4  hisi.5.22  t5, s4, a1
```

Standard RISC-V instructions appear exactly as Capstone would decode them.

## Taint semantics

By default `conservative=False`: custom-3 instructions are treated as opaque
(no taint propagation). Set `conservative=True` to propagate taint from
`rs1` and `rs2` into `rd` — appropriate when you suspect custom-3 carries
copy-like semantics (e.g. `memcpy`, `strncpy`).

```python
dec = HiSiliconRV32ExtDecoder(conservative=True)
```

## Targets

- HiSilicon WS63 / Hi3863 (NearLink BearPi-HH-NB3 AT firmware)
- Any HiSilicon bare-metal RV32GC firmware using the `0x7b` custom opcode space
