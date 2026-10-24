# TclProDecoder

## Why this exists

Two gaps drove this module:

1. **TCLPRO-GAP-001 — Installer and appliance logic locked in bytecodes.**  BitRock installers, network appliance management interfaces (Cisco, Juniper, Huawei), and some IoT firmware distribute Tcl logic as TclPro 1.x compiled bytecodes (`.tbc` / in-memory blobs named `TclPro ByteCode`).  Ablation had no way to recover the plaintext Tcl commands, variable names, or control flow — making it impossible to audit what these runtimes do: install hooks, network callbacks, `exec` sink usage, registry modification.

2. **TCLPRO-GAP-002 — tbcload.so reverse-engineered encoding not captured.**  During IDA Pro 9.4 SP1 crack analysis, `tbcload.so` was disassembled to confirm the `char - 0x21` encoding and the TclPro ByteCode 1.3 header format.  Without capturing these findings as a reusable module, future targets with TclPro bytecodes would require re-RE of tbcload.

---

## Constructor patterns

```python
from ablation.analyzers.tclpro_decoder import TclProDecoder

# From raw bytes (e.g. a blob extracted by MetaKitParser)
dec = TclProDecoder.from_bytes(bytecode_blob)

# Find all TclPro ByteCode streams in an arbitrary binary blob
decoders = TclProDecoder.find_all_in_blob(binary_data)

# From a BinaryContext (scans the binary file for all bytecode streams)
decoders = TclProDecoder.from_context(ctx)
```

---

## Key methods

| Method | Returns | Notes |
|--------|---------|-------|
| `.valid` | `bool` | True if parsed without errors |
| `.version` | `str` | e.g. `'1.3/8.3'` (fmt.tcl_minor/bc_major.bc_minor) |
| `.header` | `TclProHeader` | Parsed header fields |
| `.get_strings()` | `List[str]` | All string literals from the literal table |
| `.get_integers()` | `List[int]` | All integer literals |
| `.disassemble()` | `List[TclProInstruction]` | Full instruction list |
| `.has_eval_stk()` | `bool` | True if `EVAL_STK` opcode present (high risk: dynamic eval) |
| `.security_strings()` | `List[str]` | Strings matching exec/network/install patterns |
| `.find_strings_matching(pattern)` | `List[str]` | Regex search over literal table |
| `.report()` | `str` | One-line summary |
| `.dump()` | `str` | Full disassembly with literal annotations |

---

## TclPro ByteCode 1.x format

**Header line (ASCII):**
```
TclPro ByteCode <fmt_ver> <byte_order> <tcl_maj>.<tcl_min> <bc_maj>.<bc_min>\n
```
Example: `TclPro ByteCode 1 0 1.3 8.3\n`

**Parameter line:**
```
<nprocs> <ncmds> <nbytes> <nsrcbytes> <nfwdrefs>\n
```
`nbytes` = number of encoded body characters.

**Body encoding (confirmed from tbcload.so `.rodata` + disassembly):**
```
decoded_byte = char - 0x21     (values 0-93: single char '!' to '~')
if char == '~' (0x7E): next char decoded_byte = (next_char - 0x21) + 94
```
Confirmed: tbcload.so `.rodata` has **no lookup table** — this is a computed transform.  The `__ctype_b_loc` import in tbcload.so is used only for whitespace skipping in the header parser, not the body.

**Literal table (after body):**
```
<nliterals>\n
[type\n [length\n] value\n] * nliterals
```
Type codes: `i` = integer, `x` = external string, `d` = double.

---

## Bytecode versions

| `fmt_ver` | `tcl_minor` | `bc_major.bc_minor` | Used in |
|-----------|------------|---------------------|---------|
| 1 | 3 | 8.3 | BitRock Linux/Windows installers |
| 1 | 7 | 8.5 | BitRock macOS installers |

tbcload.so compiled against Tcl 8.5a7 handles both 8.3 and 8.5 bytecodes.

---

## Security screening

```python
dec = TclProDecoder.from_bytes(blob)
if dec.has_eval_stk():
    print('WARNING: EVAL_STK present — dynamic code evaluation')
for s in dec.security_strings():
    print(f'SECURITY: {repr(s)}')

# Screen for network callbacks
for s in dec.find_strings_matching(r'http://|https://|socket|ftp://'):
    print(f'NETWORK: {repr(s)}')
```

`EVAL_STK` (`0x08`) is the highest-risk opcode: it evaluates an arbitrary Tcl string at runtime, bypassing the literal table.  Any bytecode containing it requires manual inspection.

---

## Next tools in chain

After extracting Tcl strings, feed identified shell exec sinks into `SemanticSearcher` and `SinkArgClassifier` for the `.so` binaries that implement them (e.g. lzmadec.so, cookfs.so from `MetaKitParser.find_embedded_elfs()`).

```python
# Full workflow: MetaKit → TclProDecoder → BinaryContext
from ablation.analyzers.metakit_parser import MetaKitParser
from ablation.analyzers.tclpro_decoder import TclProDecoder

parser = MetaKitParser.from_path('/path/to/installer.run')
for label, blob in parser.find_tcl_scripts().items():
    if blob.startswith(b'TclPro ByteCode'):
        dec = TclProDecoder.from_bytes(blob)
        if dec.security_strings() or dec.has_eval_stk():
            print(f'\n[{label}] {dec.report()}')
            print(dec.dump())
```
