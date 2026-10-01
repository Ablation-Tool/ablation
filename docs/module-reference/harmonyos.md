# HarmonyOS / ArkTS Analysis

Zero-dependency parser for HarmonyOS Ark Bytecode (ABC) files and HAP application
packages. Covers all ABC versions from v9 through v13+, including the v12.0.6.0
literal-array header boundary.

---

## ABCParser

**File:** `ablation/analyzers/abc_parser.py`

Parses the binary ABC format defined by ArkCompiler's `libpandafile`. ABC files
appear in HarmonyOS as:

- `modules.abc` — compiled ArkTS module (inside a HAP)
- `*.abc` — individual class or utility files
- Obfuscated HAP bundles (e.g. WeChat HarmonyOS port)

### Construction

```python
from ablation.analyzers.abc_parser import ABCParser

with ABCParser.from_path('/path/to/modules.abc') as p:
    print(p.summary())
```

`from_path()` reads the entire file into memory. The context manager is a no-op
exit (no file handles kept open); it exists for symmetry with other Ablation parsers.

### Header

```python
hdr = p.header
print(hdr.version)           # (12, 0, 6, 0)
print(hdr.num_classes)       # 39
print(hdr.num_literalarrays) # 644 (v12); 0 for v13+ (index-only)
p.is_valid()                 # True if magic matches and size >= 60
```

The header is 60 bytes: `magic(8) + checksum(4) + version(4) + 11 × u32`.
`has_literal_in_header()` returns True for versions ≤ 12.0.6.0.

### Class Names

```python
for eid, name in p.iter_class_names():
    print(hex(eid), name)
# 0x2f12  Lcn.icheny.wechat/entry/ets/component/ListChatContentLeftItem;
```

Class entity IDs are file offsets. The class name IS the first field of the
class body (MUTF-8 string), so the entity ID also doubles as the string offset.

### Method Iteration

```python
for method in p.iter_methods():
    code = p.get_code(method)
    if code:
        print(method.fqn, code.code_size, 'bytes')
```

`iter_methods()` walks all class bodies. Each `MethodInfo` carries:

| Field | Type | Meaning |
|---|---|---|
| `entity_id` | `int` | File offset of method item |
| `class_name` | `str` | Decoded class name |
| `method_name` | `str` | Decoded method name |
| `access_flags` | `int` | ULEB128-decoded flags |
| `code_off` | `int` | File offset of CodeItem (0 if none) |
| `fqn` | `str` | `ClassName.methodName` |
| `is_native` | `bool` | `ACC_NATIVE` set (0x100) |
| `is_abstract` | `bool` | `ACC_ABSTRACT` set (0x400) |
| `has_code` | `bool` | `code_off > 60` |

Note: in dynamic ABC (ECMAScript/ArkTS runtime dialect), `ACC_NATIVE` does **not**
mean JNI/FFI. All methods in this dialect carry bytecode. Use `napi_boundary.py`
(forthcoming) to identify actual NAPI bridge methods.

**Coverage:** `iter_methods()` enumerates class-body methods only (explicitly
declared methods). Anonymous functions and closures stored in literal arrays are
not covered; those require literal-array walking and appear in the IndexHeader's
`method_idx` but not in class bodies.

### Code Items

```python
code = p.get_code(method)      # returns CodeItem or None
code = p.get_code(0x23222)     # also accepts raw code_off

code.register_count    # total vregisters allocated
code.parameter_count   # argument count
code.code_size         # bytecode byte count
code.exception_handler_count
code.bytecode          # bytes
```

CodeItem binary layout (all ULEB128, confirmed from ArkCompiler ark-rs):

```
register_count(uleb) + parameter_count(uleb) + code_size(uleb)
  + exception_handler_count(uleb) + bytecode[code_size]
  + exception_handler_records[exception_handler_count]
```

This differs from the static ABC format (which uses fixed u16/u32 fields).

### Security Queries

```python
# Methods with ACC_NATIVE flag set
native = p.find_native_methods()

# Methods by name substring
hits = p.find_methods_by_name('loadLibrary')

# Methods in a specific class
hits = p.find_methods_in_class('com/example/CryptoHelper')

# String refs in bytecode (best-effort u32 pointer scan)
hits = p.find_string_refs_in_code('password')
# returns [(MethodInfo, matched_string), ...]

# Class info (metadata only, no method walk)
for ci in p.iter_class_info():
    print(ci.name, ci.num_fields, ci.num_methods)
```

### Summary

```python
p.summary()
# {
#   'format': 'ABC',
#   'version': '12.0.6.0',
#   'file_size': 356808,
#   'num_classes': 39,
#   'num_literalarrays': 644,
#   'num_methods_total': 867,
#   'num_methods_with_code': 867,
#   'num_native_methods': 145,
#   'num_index_regions': 1,
# }
```

### String Resolution

```python
# Resolve an lda.str operand index to the actual string value.
# N is the 16-bit operand from the instruction — it is an INDEX
# into IndexHeader.class_idx[], not a raw file offset.
s = p.resolve_class_idx(n, region=0)    # returns "" if out of range
```

This method is used internally by `ARKDisasm.find_string_loads()` and exists
as a public API for callers that want to resolve operands without a full
disassembly pass.

---

## ARKDisasm

**File:** `ablation/analyzers/abc_disasm.py`

Disassembler for the ARK Bytecode ISA. Wraps an `ABCParser` and consumes
`CodeItem` objects to produce `ARKInstruction` sequences. The full ISA table
(324 opcodes, ArkCompiler v13.0.0.0) is embedded in the module — no external
`isa.json` file required at runtime.

### Construction

```python
from ablation.analyzers.abc_disasm import ARKDisasm
from ablation.analyzers.abc_parser import ABCParser

parser = ABCParser.from_path('/path/to/modules.abc')
dis = ARKDisasm(parser)
```

### Instruction iteration

```python
code = parser.get_code(method)
for insn in dis.iter_insns(code):
    print(f'+{insn.offset:04x}  {insn.mnemonic:20s}  {insn.operands}')
```

`ARKInstruction` fields:

| Field | Type | Meaning |
|---|---|---|
| `offset` | `int` | Byte offset within bytecode |
| `mnemonic` | `str` | Instruction mnemonic (e.g. `lda.str`) |
| `size` | `int` | Instruction size in bytes (1–5) |
| `raw` | `bytes` | Raw bytes |
| `operands` | `list` | Decoded operand values |

Unknown opcodes are emitted as single-byte `.data` instructions so that
`iter_insns` always advances and alignment is preserved.

Convenience accessor: `insn.string_id` returns the 16-bit entity ID operand
if the instruction is `lda.str`, else `None`.

### Disassembly text

```python
# Single method — smali-style with inline string annotations
text = dis.disasm_method(method, code)
# Example output:
# func_main_0  (10 regs, 3 args, 129 bytes)
# +0000  ldai      0
# +000e  lda.str   0x21  # "L@system.curves;"
```

`disasm_method(method, code)` resolves `lda.str` operands via
`ABCParser.resolve_class_idx()` and appends the string as a `# "..."` comment.

```python
# All methods in the file
for text in dis.disasm_all():
    print(text)
```

### Security queries

```python
# Call sites
for insn in dis.find_calls(code):
    print(f'+{insn.offset:04x}  {insn.mnemonic}')

# String loads — resolved to actual string value
for insn, s in dis.find_string_loads(code):
    print(f'+{insn.offset:04x}  {repr(s)}')
```

`find_string_loads()` resolves each `lda.str N` operand through
`IndexHeader.class_idx[N]` → entity_id → string bytes. The raw 16-bit operand
is NOT a file offset; it is an index into the current index region.

### ISA table design

The embedded `_OPCODE_TABLE` is keyed by `(prefix_byte | None, opcode_byte)`.
Four prefix groups:

| Prefix | Byte | Examples |
|---|---|---|
| `callruntime` | `0xfb` | `callruntime.notifyconcurrentresult` |
| `deprecated` | `0xfc` | `deprecated.lda.str` |
| `wide` | `0xfd` | `wide.createobjectwithexcludedkeys` |
| `throw` | `0xfe` | `throw.ifdefinednotundefined` |
| (none) | — | everything else |

The ISA uses parallel arrays: `opcode_idx[i] ↔ format[i]`. Iterating format
strings naively against all opcodes creates 138 false collisions (e.g.
`getiterator` appears at both opcode 103 with format `op_imm_8` and opcode 171
with format `op_imm_16`). The table is built by pairing arrays at the same
index, yielding 324 clean entries.

---

## Format Notes

### ABC Dialects

Two dialects exist:

- **Dynamic** (ECMAScript/ArkTS runtime): `access_flags` is ULEB128;
  `code_size` is ULEB128. Used in all HAP/APP bundles.
- **Static** (older compiler): `access_flags` is u32. The parser assumes
  dynamic dialect, which is backwards-compatible for flags ≤ 0x7F.

### Version Boundary

Version `[12,0,6,0]` is `LAST_CONTAINS_LITERAL_IN_HEADER_VERSION`. Files
at or below this version embed `num_literalarrays` and `literalarray_idx_off`
in the fixed 60-byte header. v13+ stores literal arrays in the index section only.

### String Encoding

Strings use MUTF-8: `uleb128(utf16_len) + bytes[utf16_len>>1] + 0x00`.
`char_count = utf16_len >> 1`. `is_ascii = utf16_len & 1`.
U+0000 is encoded as `C0 80` (not a real null).

### Class Body Layout

```
inline_name_string (MUTF-8)
u32 reserved
uleb128 access_flags
uleb128 num_fields
uleb128 num_methods
ClassTaggedValues (terminated by tag=0)
Field12 items × num_fields
Method items × num_methods
```

### Method Item Layout

```
u16 class_idx
u16 proto_idx   (0xffff = no prototype, common in dynamic ABC)
u32 name_off    (file offset of method name string)
uleb128 access_flags
MethodTaggedValues (terminated by tag=0)
```

Key `MethodTag` values: `CODE=1` (u32 code_off), `SOURCE_LANG=2` (u8),
`DEBUG_INFO=5` (u32).
