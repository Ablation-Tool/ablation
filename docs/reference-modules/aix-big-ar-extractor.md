# AixBigArExtractor

## Why this exists

Three things were not possible before in Ablation:

1. **Extract XCOFF members from AIX big archives.** GNU `ar` reports "file format not recognized" for `<bigaf>` files. AIX ships all system libraries (`libc.a`, `libm.a`, `libpthreads.a`, `libbsd.a`) as big archives. Without extraction, the XCOFF32/XCOFF64 object files inside are inaccessible to `BinaryContext` or `xcoff_parser`.

2. **Handle AIX 5.x and above library archives.** The `<bigaf>` format is distinct from the old small archive (`<aiaff>`) used on AIX 4.2 and earlier. Modern AIX ships all 32-bit and 64-bit variants of each function as members inside a single `<bigaf>`, with `_64.o` suffix members holding the 64-bit XCOFF64 code.

3. **Filter XCOFF members from metadata entries.** `<bigaf>` archives contain special members (member table, global symbol table) that are not object files. The module's `xcoff_members()` method skips these using magic-byte validation (`0x01DF` = XCOFF32, `0x01F7` = XCOFF64).

## Format notes

`<bigaf>` (AIX big archive) layout:

- Magic: `<bigaf>\n` (8 bytes, `0x3c 0x62 0x69 0x67 0x61 0x66 0x3e 0x0a`)
- Global header (128 bytes total): 8-byte magic + six 20-char text decimal fields
 - `fl_fstmoff`: offset of first member (128 for non-empty archives)
 - `fl_lstmoff`: offset of last member
 - `fl_memoff`, `fl_gstoff`, `fl_gst64off`: member table + symbol tables
- Member header at each member offset:
 - 112-byte fixed section (6 text-decimal fields + 1 text-octal mode field + 4-char namlen)
 - `ar_namlen` bytes of member name (not null-terminated)
 - 1 null pad byte if `ar_namlen` is odd
 - 2-byte `ar_fmag` = `` `\n `` (`0x60 0x0a`) consistency trailer
 - `ar_size` bytes of member data
 - 1 pad byte if `ar_size` is odd (to align next member to 2-byte boundary)

Members are a doubly-linked list via `ar_nxtoff` / `ar_prvoff` (text-decimal file offsets).

## Constructor patterns

```python
from ablation.analyzers.aix_big_ar_extractor import AixBigArExtractor

# One-shot: get all members as dict
members = AixBigArExtractor.from_path('/path/to/libc.a')
# -> {'frexp.o': b'\x01\xdf...', 'ldexp.o': b'\x01\xdf...', ...}

# Iterator: process large archives without loading all into memory
ext = AixBigArExtractor('/path/to/libc.a')
for name, data in ext.extract():
    print(name, len(data))

# XCOFF-only: skip metadata members
for name, data in ext.xcoff_members():
    # data[:2] is guaranteed 0x01DF or 0x01F7
    ...

# Single member by name
frexp_bytes = ext.get_member('frexp.o')

# Just names
print(ext.list_members())
```

## Key methods

| Method | Purpose |
|--------|---------|
| `from_path(path)` → `Dict[str, bytes]` | One-shot extract all members |
| `extract()` → `Iterator[(name, bytes)]` | All members (including metadata) |
| `xcoff_members()` → `Iterator[(name, bytes)]` | XCOFF32/64 only |
| `list_members()` → `List[str]` | Names only |
| `get_member(name)` → `bytes` | Single member, raises KeyError if absent |

---

## How it works

`AixBigArExtractor.__init__()` reads the entire archive into memory and validates the `<bigaf>\n` magic. `extract()` reads the two text-decimal offsets from the 128-byte global header (`fl_fstmoff`, `fl_lstmoff`), then walks the member doubly-linked list via `ar_nxtoff` at each member header. For each member, it parses the 112-byte fixed header, extracts the `ar_namlen`-byte name field, verifies the 2-byte `ar_fmag` consistency trailer (`\x60\x0a`), and yields `(name, member_bytes)`. The metadata-only members (empty name, `/`, `//`): the member table and global symbol tables: are skipped. `xcoff_members()` filters the output of `extract()` by checking that the first 2 bytes of each member are `\x01\xdf` (XCOFF32) or `\x01\xf7` (XCOFF64). If a member header is corrupt at any point, the walk stops cleanly via the `except` guard rather than raising.

---

## Usage

```python
from ablation.analyzers.aix_big_ar_extractor import AixBigArExtractor

members = AixBigArExtractor.from_path('/path/to/libc.a')
for name, data in members.items():
    print(f"  {name}: {len(data)} bytes")
```

---

## Example output

```python
>>> ext = AixBigArExtractor('/aix/usr/lib/libc.a')
>>> ext.list_members()
['crypt.o', 'frexp.o', 'ldexp.o', 'modf.o', 'frexp_64.o', 'ldexp_64.o', 'modf_64.o', ...]

>>> for name, data in ext.xcoff_members():
...     magic = '0x01df' if data[:2] == b'\x01\xdf' else '0x01f7'
...     print(f"  {name}: {len(data)} bytes  magic={magic}")
  crypt.o: 4096 bytes  magic=0x01df
  frexp.o: 2048 bytes  magic=0x01df
  frexp_64.o: 2560 bytes  magic=0x01f7
```

---

## False positives

Extraction either succeeds or raises an exception, there are no false positives in the traditional sense. Check for incomplete downloads (`.aria2` sidecar present) before analysis: partial images produce truncated or zero-filled partitions that pass validation but contain no useful data.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to identify the outer binary format and confirm the container is present.

**After this module:** Feed extracted partition bytes to `BinaryContext.load_or_build()` or the appropriate ISA taint tracker for each extracted payload.

---

## Reading output

`AixBigArExtractor.extract()` yields `Tuple[str, bytes]`: `(member_name, member_bytes)`. `from_path()` returns `Dict[str, bytes]`. `xcoff_members()` yields only members whose first 2 bytes match an XCOFF magic.

| Value | Content |
|:---|:---|
| `member_name` | Archive member name (e.g., `frexp.o`, `frexp_64.o`) |
| `member_bytes` | Raw bytes of the XCOFF object file |
| First 2 bytes `\x01\xdf` | XCOFF32: 32-bit PowerPC object code |
| First 2 bytes `\x01\xf7` | XCOFF64: 64-bit PowerPC object code |

---

## See also

- [BinaryContext](binary-context.md): load extracted payloads for analysis
- [FirmwareContainers](firmware-containers.md): higher-level firmware partition walker
- [EntropyMapper](entropy-mapper.md): locate encrypted or compressed regions before extraction
