# Motorola 88000 / BCS COFF Analysis

Decode Motorola 88000 (M88K) binaries — identifying `RISC.88000` architecture COFF containers, disassembling M88K instructions, and providing function start discovery for taint analysis of legacy Motorola 88000 firmware targets including NeXT workstations, early Motorola embedded platforms, and HP-UX systems that used the M88K processor.

---

## Why this exists

1. **Capstone does not support the Motorola 88000 ISA.** The M88K is a pure RISC architecture used in NeXT workstations (NeXTSTEP on M88K), early Motorola embedded platforms, and HP-UX installations prior to the transition to PA-RISC. Without `insn_m88k.py`/`isa_m88k.py`, M88K firmware cannot be disassembled by any existing tool in the pipeline.

2. **M88K COFF BCS (Binary Compatibility Standard) containers** use the `RISC.88000` magic identifier in the COFF header's optional machine type field. `isa_m88k.py` parses BCS COFF to extract code sections and determine the base address for disassembly. This is the entry point for M88K firmware analysis without a full RE platform.

3. **M88K uses a fixed 32-bit instruction width with a pure RISC encoding** — all instructions are 4 bytes, big-endian, with a 6-bit opcode field and distinct register encoding for 3-operand, immediate, and branch forms. The fixed width makes sequential disassembly reliable; `InsnM88K` provides the security-relevant subset (loads, stores, branches, and arithmetic) needed for taint analysis.

---

## How it works

```mermaid
flowchart TD
    A["ISAM88K.from_path(path)  (BCS COFF loader)"] --> B["Parse COFF header:\n  machine = RISC.88000\n  Extract code sections (.text)\n  base_address from optional header\n  → code_bytes, base_va"]
    B --> C["InsnM88K.decode(word) → Optional[InsnM88K]\n  Decode 32-bit big-endian instruction:\n    6-bit opcode field → mnemonic\n    Register fields: D, S1, S2\n    Immediate: 16-bit for loads/stores/branches\n  Security-relevant subset:\n    ld/st (loads/stores)\n    jsr/jsr.n (subroutine call)\n    jmp/jmp.n (indirect branch)\n    br/br.n (direct branch)\n    addu/subu/mulu (arithmetic)"]
    C --> D["function_starts() → List[int]\n  Scan for M88K function prologue:\n    subu r31, r31, N  (frame allocation)\n    st r1, r31, N     (LR save)\n  Return sorted start addresses"]
```

---

## Usage

```python
from ablation.analyzers.isa_m88k import ISAM88K
from ablation.analyzers.insn_m88k import InsnM88K

isa = ISAM88K.from_path('/path/to/next_firmware.coff')
code_bytes, base_va = isa.code_section()

starts = isa.function_starts()
print(f"Found {len(starts)} M88K functions")

# Decode a range
offset = starts[0] - base_va
for i in range(0, 40, 4):
    word = int.from_bytes(code_bytes[offset+i:offset+i+4], 'big')
    insn = InsnM88K.decode(word)
    if insn:
        print(f"  {base_va + offset + i:#x}: {insn.mnemonic} {insn.op_str}")
```

---

## Example output

The following illustrates M88K decoding output format. Actual addresses are binary-specific.

```
ISAM88K: next_firmware.coff

Machine: RISC.88000
Code section: <N> bytes at base_va=<va>

function_starts(): <F> M88K functions

Disassembly at <va>:
  <va>: subu  r31, r31, 0x20   ; frame alloc
  <va>: st    r1, r31, 0x1c    ; LR save
  <va>: jsr   r10              ; indirect call
```

---

## False positives

**`function_starts()` heuristic is based on `subu r31, r31, N` + `st r1, r31, N` prologue** — leaf functions that do not save LR are not detected. The function start list is a lower bound; supplement with call-graph reachability from detected starts.

**M88K `jsr.n` (delayed branch) includes a delay slot instruction** — the instruction following `jsr.n` executes before the branch takes effect. `InsnM88K` decodes `jsr.n` as a call but does not automatically consume the delay slot. Callers must skip one instruction after a `jsr.n` to maintain correct sequential decode.

---

## Pipeline position

Run M88K analysis on any BCS COFF firmware binary confirmed to use the M88K architecture. Function starts feed `TaintTracker`-equivalent analysis using the same source/sink model — porting to M88K ABI (r2–r9 argument registers) is required for full taint analysis.

---

## See also

- [Flat ROM Function Discovery](flat-rom-function-discovery.md) — `EcuArchDetector` for architecture identification before M88K-specific analysis
- [M68K CPU32 Decoding](m68k-cpu32-decoding.md) — Motorola M68K equivalent (different architecture family)
