# Decompiler Docs Template Pass

Template: `taint-tracker-alpha.md`. Applied: title = class name, indented TOC,
back-to-top `<sup>[↑](#anchor)</sup>` on every heading, zero em dashes,
clean numbered "Why this exists" bullets (no embedded-sentence bold).

## Status

### Already done
- [x] `taint-tracker-alpha.md` (Alpha AXP)
- [x] `x86.md` (x86-32/64)
- [x] `binary-lifter.md` (ARM + ARC + most ISAs)

### Remaining (22 docs)

| Doc | Title fix | Em dashes | Bold bullets | TOC | Back-to-top |
|:----|:---------:|:---------:|:------------:|:---:|:-----------:|
| `mips.md` | yes | 6 | 3 | has | - |
| `nanomips.md` | yes | 1 | 0 | has | - |
| `ppc32-taint-tracker.md` | ok | 0 | 3 | has | - |
| `ecu-vle-decoder.md` | ok | 0 | 0 | has | - |
| `ppc476-lifter.md` | yes | 1 | 0 | has | - |
| `xcoff32-decompiler.md` | ok | 0 | 0 | MISSING | - |
| `risc-v.md` | yes | 2 | 3 | has | - |
| `hisi-rv32-ext.md` | yes | 0 | 0 | has | - |
| `loongarch64.md` | yes | 2 | 0 | has | - |
| `isa-8051.md` | yes | 0 | 4 | has | - |
| `v850-rh850.md` | yes | 2 | 3 | has | - |
| `binary-lifter-sh2a.md` | yes | 0 | 0 | has | - |
| `m68k-cpu32-decoding.md` | yes | 0 | 3 | has | - |
| `m88k-decoder.md` | yes | 1 | 8 | has | - |
| `tricore-taint-tracker.md` | ok | 0 | 0 | has | - |
| `ti-c28x-decoding.md` | yes | 0 | 3 | has | - |
| `c166-c167-decoding.md` | yes | 0 | 3 | has | - |
| `dex.md` | yes | 1 | 3 | has | - |
| `micropython.md` | yes | 0 | 3 | has | - |
| `beam.md` | yes | 0 | 0 | has | - |
| `java-re.md` | yes | 0 | 0 | has | - |
| `pyc-bytecode-scanner.md` | yes | 0 | 3 | has | - |

## Per-doc title mapping

| Doc | Current title | Target |
|:----|:-------------|:-------|
| `mips.md` | MIPS ISA Support | MIPSTaintTracker |
| `nanomips.md` | nanoMIPS Taint Analysis | NanoMIPSTaintTracker |
| `ppc476-lifter.md` | Ppc32Lifter: IBM PPC476 backend | Ppc476Lifter |
| `risc-v.md` | RISC-V ISA Support | RISCVTaintTracker |
| `hisi-rv32-ext.md` | HiSilicon RV32 Extension Decoder | HiSiliconRV32Decoder |
| `loongarch64.md` | LoongArch64 Analysis Stack | LoongArch64TaintTracker |
| `isa-8051.md` | isa-8051 | ISA8051Decoder |
| `v850-rh850.md` | V850/RH850 ISA Support | V850TaintTracker |
| `binary-lifter-sh2a.md` | BinaryLifter: SH-2A backend | BinaryLifterSH2A |
| `m68k-cpu32-decoding.md` | M68K/CPU32 Decoding | M68KDecoder |
| `m88k-decoder.md` | M88K BCS COFF Support MC88100 / Motorola 88000 | M88KDecoder |
| `ti-c28x-decoding.md` | TI C28x DSP/MCU Decoding | TIC28xDecoder |
| `c166-c167-decoding.md` | C166/C167 ECU Decoding | C166Decoder |
| `dex.md` | Android DEX Security Analysis | DEXAnalyzer |
| `micropython.md` | MicroPython Analysis | MicroPythonLifter |
| `beam.md` | Erlang / BEAM Analysis | BEAMAnalyzer |
| `java-re.md` | Java RE | JavaREAnalyzer |
| `pyc-bytecode-scanner.md` | PYC Bytecode Scanner | PYCBytecodeScanner |
