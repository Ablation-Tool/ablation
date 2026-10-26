# EcuC28xDecoder

Decode Texas Instruments TMS320C28x firmware: implementing the 16-bit word-addressed ISA from SPRU430F in pure Python Capstone has no C28x support: distinguishing 16-bit single-word from 32-bit dual-word instructions for F28x-series MCUs F28P55x, F28335, F2837x, F2838x used in EV/HEV traction inverter control units and motor-drive ECUs.

---

## Why this exists <sup>[↑](#ecuc28xdecoder)</sup>

1. Capstone 5.x has no C28x support. The TMS320C28x is TI's primary 32-bit fixed-point DSP/MCU core for real-time control applications. EV/HEV traction inverter firmware compiled with `cl2000` or `c29clang` is C28x firmware. Without `ecu_c28x_decoder.py`, this entire class of automotive and industrial firmware cannot be disassembled by any existing pipeline tool.

2. C28x uses 16-bit program words with word addressing: each address refers to one 16-bit word, not one byte. This is structurally different from byte-addressed ISAs and requires the decoder to translate word addresses to byte offsets before reading instruction words. `EcuC28xDecoder` handles this transparently via the `base_va` parameter.

3. C28x instruction width is determined by the first word's opcode field. 16-bit instructions use opcodes that fit in a single word; 32-bit instructions use an extended encoding. `EcuC28xDecoder.insn_length(byte_off)` reads the first word and returns either 2 or 4 bytes, enabling O(1) sequential decode.

---

## How it works <sup>[↑](#ecuc28xdecoder)</sup>

```mermaid
flowchart TD
    A(["EcuC28xDecoder.from_path(path, base_va=0)\n  or .from_bytes(data, base_va=0)"]):::input --> B["insn_length(byte_off) → int\n  Read first 16-bit word (LE) at byte_off\n  Decode opcode field (bits[15:8] or bits[15:10])\n  1-word instruction → return 2 (bytes)\n  2-word instruction → return 4 (bytes)"]:::primary
    B:::primary --> C["decode_one(byte_off) → Optional[C28xInsn]\n  Decode 1 or 2-word instruction\n  Security-relevant subset:\n    LCR/LRETR: subroutine calls and returns\n    MOVL/MOVB: 32-bit/8-bit moves (data transfer)\n    ADDB/SUBBL: arithmetic with immediate\n    B/BF: branch instructions\n  C28xInsn: address, mnemonic, op_str, size, words"]:::secondary
    C:::secondary --> D(["disassemble(start_va, end_va) → Iterator[C28xInsn]"]):::output
    C:::secondary --> E(["function_starts() → List[int]\n  Scan for C28x function prologue:\n    PUSH RB (push return block) + PUSH AR1H:AR0H\n  Return sorted start addresses"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

---

## Usage <sup>[↑](#ecuc28xdecoder)</sup>

```python
from ablation.analyzers.ecu_c28x_decoder import EcuC28xDecoder

decoder = EcuC28xDecoder.from_path('/path/to/ti_f28335_inverter.bin', base_va=0x3E8000)

starts = decoder.function_starts()
print(f"Found {len(starts)} C28x functions")

for insn in decoder.disassemble(starts[0], starts[0] + 0x40):
    print(f"  {insn.address:#x} ({insn.size}B): {insn.mnemonic} {insn.op_str}")
```

---

## Example output <sup>[↑](#ecuc28xdecoder)</sup>

The following illustrates C28x disassembly output format. Actual addresses are firmware-specific.

```
EcuC28xDecoder: ti_f28335_inverter.bin  (base_va=0x3e8000)

function_starts(): <N> C28x functions

Disassembly at 0x3e8000:
  0x3e8000 (2B): PUSH  RB
  0x3e8002 (4B): MOVL  XAR4, #0x1234  (32-bit 2-word)
  0x3e8006 (2B): ADDB  ACC, #10
  0x3e8008 (4B): LCR   <target>
```

---

## False positives <sup>[↑](#ecuc28xdecoder)</sup>

**`function_starts()` heuristic requires `PUSH RB` prologue**: functions that do not save the return block leaf functions or interrupt service routines are not detected. Supplement with ELF symbol table entries from `TiCoffLoader` if available, or with call-graph reachability from detected starts.

**Word-addressed instruction decoding at incorrect byte offsets**: C28x word addresses must be even byte offsets. Passing an odd byte offset to `decode_one()` produces incorrect decoding. `function_starts()` seeds use valid even offsets; callers must ensure alignment when using `decode_one()` directly.

---

## Pipeline position <sup>[↑](#ecuc28xdecoder)</sup>

Run `EcuC28xDecoder` on any TI F28x-series firmware after `EcuArchDetector` confirms C28x architecture. Function starts seed C28x-specific taint analysis. Pair with `TiCoffLoader` for symbol names when the firmware was compiled with debug symbols.

---

## Reading output <sup>[↑](#ecuc28xdecoder)</sup>

`EcuC28xDecoder.disassemblestart=0, end=None` returns `List[C28xInsn]`:

| Attribute | Content |
|:---|:---|
| `word_va` | Word-address VA of the instruction |
| `is_32bit` | `True` when the instruction occupies two 16-bit words |
| `mnemonic` | Instruction mnemonic for example `'MOV'`, `'LCR'`, `'ADDB'` |
| `insn_type` | `'BRANCH'` / `'CALL'` / `'RETURN'` / `'LOOP'` / `'MISC'` |
| `raw` | `bytes`: 2 or 4 raw bytes little-endian |
| `target` | Word-address branch/call target VA, or `None` |
| `cond` | Condition name for `B`/`BF` instructions, or `None` for unconditional |
| `imm` | Immediate operand value, or `None` |

`EcuC28xDecoder.function_starts()` returns `List[int]`: probable function-start word-VAs collected from direct call targets `LC`, `LCR`, `FFC` instructions.

---

## See also <sup>[↑](#ecuc28xdecoder)</sup>

- [TI COFF Archive Loading](ti-coff-archive-loading.md): `TiCoffLoader` for symbol names in COFF2-format C28x firmware
- [TI Neural Network Artifact Detection](ti-neural-network-artifacts.md): `TiNNCScanner` for detecting TVM inference modules in C28x firmware
- [Flat ROM Function Discovery](flat-rom-function-discovery.md): `EcuArchDetector` for architecture identification
