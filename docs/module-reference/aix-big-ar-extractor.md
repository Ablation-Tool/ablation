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
