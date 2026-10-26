# M88kDecoder

Parse and disassemble Motorola MC88100 BCS COFF executables.

**Modules:** 
- `ablation.core.coff_m88k_parser` file parser 
- `ablation.analyzers.isa_m88k` ISA + ABI constants 
- `ablation.analyzers.insn_m88k` instruction decoder 

---

## What this is <sup>[↑](#m88kdecoder)</sup>

Motorola MC88100 is a RISC processor from the late 1980s used in Motorola 88000 workstations and legacy industrial systems. MC88100 BCS COFF executables are still in the wild. Capstone 5.x removed its incomplete 88K stub. GNU binutils dropped 88K support around 2020. `M88kDecoder` and `coff_m88k_parser` are the only current Python tools for this ISA. They parse the 88K BCS COFF format correctly where standard parsers corrupt section headers, decode all MC88100 instruction classes, and recover function boundaries from call sites in stripped binaries.

---

## Where it's used <sup>[↑](#m88kdecoder)</sup>

- Motorola 88000 workstation binaries
- Legacy industrial systems running MC88100 firmware
- Any BCS COFF binary with magic number `0x016D`

---

## Safe usage <sup>[↑](#m88kdecoder)</sup>

**Parse with `coff_m88k_parser.parse()` before passing to `M88kDecoder`.** Standard COFF parsers use 40-byte section headers. The 88K BCS COFF uses 44-byte section headers with 4-byte `nreloc` and `nlnno` fields. A standard parser corrupts all section names and virtual addresses from the first section onward.

**Seed analysis from `function_starts()`.** The BCS COFF is typically stripped. `function_starts()` recovers function boundaries from BSR/BSR.N call sites in `.text`. Without seeds, the taint tracker has no entry points.

**Do not interpret triadic op placeholder output as findings.** Triadic ops (0x3A-0x3C) decode as placeholder mnemonics because the shift, rotate, multiply, and divide function codes are not decoded. A triadic placeholder in a taint path is not a confirmed finding.

**Use `string_refs()` separately from taint analysis.** `string_refs()` scans for `OR.U + OR` constant-load pairs that point into `.data`. These are format string and constant references, not taint sources.

---

## Why this exists <sup>[↑](#m88kdecoder)</sup>

Four things were not possible before in Ablation:

1. M88K BCS COFF files were completely unreadable. LIEF does not support
 COFF and does not recognise magic 0x016D; all existing COFF parsers assume
 2-byte `s_nreloc`/`s_nlnno` fields standard, but the 88K BCS variant
 promotes those fields to 4-byte longs, making every section header 44 bytes
 instead of 40. Parsing with the wrong stride corrupts all section names and
 virtual addresses from section 1 onwards. `coff_m88k_parser.parse()` is the
 first Python parser that handles this correctly.

2. No M88K disassembler survives in the Python ecosystem. Capstone 5.x
 removed its incomplete 88K stub. GNU binutils dropped 88K support circa
 2020. Radare2 has no M88K plugin. `M88kDecoder` provides a pure-Python decoder for all MC88100 instruction classes: immediate, load/store, branch, conditional branch, register-to-register, and triadic ops.

3. Function start detection on a dead ISA with no symbols is not possible without a custom scanner. The BCS COFF
 symbol table is typically stripped. `function_starts()` recovers function
 boundaries by scanning all BSR/BSR.N call sites in .text, validated at 126
 unique function entries on the moto_gen binary.

4. Data reference recovery without Capstone required a purpose-built scanner. `string_refs()` scans for
 consecutive OR.U + OR instruction pairs (the canonical 88K 32-bit constant
 load idiom) where the computed VA falls in .data, validated at 73 string
 and format-string references on the same binary.

---

## Supported ISA subset <sup>[↑](#m88kdecoder)</sup>

All MC88100 instruction classes decoded:

| Class | Opcodes | Notes |
|---|---|---|
| Immediate | 0x10–0x1F | ADDU, OR, OR.U, AND, XOR, LDA.H, LDA.W |
| Load/store | 0x00–0x0F, 0x20–0x2F, 0x34–0x38 | All width/signedness variants |
| Branch | 0x30–0x33 | BR, BR.N, BSR 26-bit PC-relative × 4, BSR.N |
| Conditional | 0x25, 0x29, 0x2D | BCND / BCND.N 16-bit PC-relative × 4 |
| CTL JMP/JSR/MOV | 0x3D | bits 15:14 select JMP (11), JSR (10), MOV (00/01) |
| Triadic integer | 0x3A–0x3C | partial: function code field not decoded |
| Unknown | all others | decoded as `???XX`, no exception |

Triadic ops (0x3A–0x3C) emit placeholder mnemonics; the full MC88100 PRM
function-code table shift, rotate, multiply, divide, … is the next
extension point.

---

## ABI BCS / Binary Compatibility Standard <sup>[↑](#m88kdecoder)</sup>

| Register | Role |
|---|---|
| r0 | Zero hardwired |
| r1 | Link register BSR saves PC+4 here |
| r2–r9 | Arguments / return values caller-saved |
| r10–r13 | Additional return / scratch caller-saved |
| r14–r25 | Callee-saved |
| r26–r29 | Caller-saved temporaries |
| r30 | Frame pointer callee-saved |
| r31 | Stack pointer |

---

## Quick start <sup>[↑](#m88kdecoder)</sup>

```python
from ablation.core.coff_m88k_parser import parse
from ablation.analyzers.insn_m88k import M88kDecoder

binary = parse('/path/to/target.coff')
dec = M88kDecoder(binary)

# M88kDecoder
for insn in dec.disassemble_va(binary.entry, max_insns=40):
    print(insn)

# M88kDecoder
for va in sorted(dec.function_starts()):
    print(f'func_{va:08x}')

# M88kDecoder
for code_va, data_va in sorted(dec.string_refs().items()):
    print(f'{code_va:#010x} -> {data_va:#010x}')
```

---

## Key findings from first target <sup>[↑](#m88kdecoder)</sup>

The modules were developed against and validated on:

- **Binary**: Lotus 1-2-3 `moto_gen` license key generator (54,608 bytes,
 88K BCS COFF, January 1993, for DG AViiON / DG/UX Unix systems)
- **Architecture gap discovered**: section headers are 44 bytes in 88K BCS
 COFF, not 40, because `s_nreloc` and `s_nlnno` are `unsigned long` 4 bytes each
- **Results**: 73 data refs, 126 function entries, complete key generation
 algorithm reversed (XOR encoding with ASCII offsets 0x30/0x37/0x57/0x61,
 three `%02x%02x` pairs → 12-char activation key)

See `re/lotus/moto_gen_re.py` for the full findings module.

---

## Extension points <sup>[↑](#m88kdecoder)</sup>

1. Triadic ops (0x3A–0x3C): expand `TRIADIC_OPS` in `isa_m88k.py` with
 the full function-code table from the MC88100 PRM shift, rotate, cmp, …
2. DataExplorer AViiON corpus: larger 88K target set for validating coverage
 of additional instruction encodings
3. **CFG builder** (`cfg_m88k.py`): block-level control flow graph using the
 existing `function_starts()` + branch target detection; follow `cfg_ppc.py`
 as the template
4. BinaryLifter integration: add `arch='m88k'` to `BinaryLifter`'s ISA
 dispatch table once a CFG builder exists

---

## How it works <sup>[↑](#m88kdecoder)</sup>

`CoffM88kParser.parse(path)` reads a Motorola 88000 BCS COFF executable (COFF magic 0x016D). LIEF and Capstone have no 88000 support; this pure-Python parser extracts section headers, section data, symbol table, and string table from the COFF layout. Returns an `M88kBinary` with section data bytes and a PLT-like import table derived from the COFF symbol table. Consumed by `M88KDisassembler` and `M88KTaintTracker`.

---

## Usage <sup>[↑](#m88kdecoder)</sup>

```python
from ablation.core.coff_m88k_parser import parse
from ablation.analyzers.insn_m88k import M88kDecoder

binary = parse('/path/to/target.coff')
decoder = M88kDecoder(binary)

for insn in decoder.disassemble_bytes(binary.text.data, base_va=binary.text.vaddr):
    print(insn)
```

---

## Example output <sup>[↑](#m88kdecoder)</sup>

```
# M88kDecoder
>>> b = parse('netmgr88k')
>>> hex(b.entry_va)
'0x8000c'
>>> b.sections[0].name
'.text'
>>> len(b.symbols)
184
>>> b.plt['printf']
0x8000c0
```

---

## False positives <sup>[↑](#m88kdecoder)</sup>

**Symbol table coverage.** `coff_m88k_parser` reads `C_EXT` and `C_WEAKEXT` COFF symbol entries. Static functions not exported have `C_STAT` type and are excluded from `b.plt`. Use prologue pattern scanning on `b.sections[0].data` to find static function starts.

---

## Pipeline position <sup>[↑](#m88kdecoder)</sup>

**Before this module:** Confirm the binary has COFF magic 0x016D (`file -b target` shows `mc68k COFF` or `m88k COFF`).

**After this module:** Pass `M88kBinary.sections[0].data` and the PLT to `M88KTaintTracker` for source-to-sink analysis.

---

## Reading output <sup>[↑](#m88kdecoder)</sup>

`parse(path)` returns an `M88kCoffBinary`.

| Field | Type | Content |
|:---|:---|:---|
| `path` | `str` | Path to the analyzed binary |
| `entry` | `int` | Program entry point VA |
| `text_start` | `int` | `.text` section base VA |
| `data_start` | `int` | `.data` section base VA |
| `sections` | `List[Section]` | All parsed sections |

Each `Section`: `name, vaddr, size, flags, data`; properties `is_text, is_data, va_end`; methods `read_word(va)`, `read_bytesva, n`, `contains_va(va)`.

Helper methods on `M88kCoffBinary`: `section(name)`, `text` property, `data` property, `va_to_bytesva, n`, `words_atva, count`.

---

## See also <sup>[↑](#m88kdecoder)</sup>

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
