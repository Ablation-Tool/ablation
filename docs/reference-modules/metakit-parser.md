# MetaKitParser

## Why this exists

Three gaps drove this module:

1. **MK4-GAP-001 — TclKit binary locator missing.**  Ablation had no way to find MetaKit VFS databases appended to TclKit installer binaries.  BitRock InstallBuilder (Cisco, Juniper, enterprise appliance vendors) embed all installer Tcl scripts and runtime libraries in a MetaKit VFS appended directly to the ELF/PE stub.  Without a locator, every file in the VFS — including the file manifest, Tcl actions scripts, and embedded .so extensions — is invisible.

2. **MK4-GAP-002 — File manifest not parseable.**  The first blob in a BitRock MetaKit VFS is the complete file manifest: every installed path, permission, mtime, and LZMA chunk offset.  This is the entry point for understanding what a software package actually installs.

3. **MK4-GAP-003 — Embedded ELF blobs not enumerable.**  BitRock MetaKit VFS blobs include Tcl extension .so files (tbcload, lzmadec, cookfs, thread, itcl, libtcl, libtk).  These binaries contain the decompression logic for the main LZMA payload.  Without MetaKit extraction, they are inaccessible for further BinaryContext analysis.

Confirmed against IDA Pro 9.4 SP1 Linux x64 installer (583 MB).

---

## Constructor patterns

```python
from ablation.analyzers.metakit_parser import MetaKitParser

# From a file path (reads the file internally)
parser = MetaKitParser.from_path('/path/to/installer.run')

# From an existing BinaryContext
ctx = BinaryContext.load_or_build('/path/to/installer.run')
parser = MetaKitParser.from_context(ctx)

# Static: find MetaKit in a bytes blob (returns (mk_start, mk_end_exclusive) or None)
result = MetaKitParser.find_mk4_in_data(data)
```

---

## Key methods

| Method | Returns | Notes |
|--------|---------|-------|
| `.found` | `bool` | True if a valid MetaKit VFS was located |
| `.mk_start` | `int` | Byte offset of JL magic in the binary |
| `.mk_size` | `int` | MetaKit data size (excluding 16-byte descriptor) |
| `.schema` | `str` | MetaKit schema string (e.g. `dirs[name:S,...]`) |
| `.iter_files()` | iterator of `(label, bytes)` | Each zlib blob decompressed |
| `.get_file(index)` | `bytes` or `None` | Blob by index |
| `.get_manifest()` | `bytes` or `None` | First large text blob (BitRock file manifest) |
| `.find_embedded_elfs()` | `{label: bytes}` | All ELF blobs — feed to `BinaryContext` |
| `.find_tcl_scripts()` | `{label: bytes}` | `.tcl` and TclPro ByteCode blobs |
| `.report()` | `str` | One-line summary (blob count, ELF count, sizes) |

---

## MetaKit 4 format

A MetaKit database appended to a TclKit binary ends with a 16-byte big-endian descriptor:

```
[a: 0x80000000][b: MK_size][c: 0x80??????][d: ???]
```

- `a` must equal `0x80000000`
- `(c >> 24)` must equal `0x80`
- MetaKit data starts at: `file_end - 16 - b`
- Starts with `JL\x1a\x00` magic

**BitRock Windows installers** embed a `bitrock-lzma-4.0` marker in the last 32KB of the file.  If the marker is at index `i` in the last 32KB window, an extra offset `off = 32768 - i` is subtracted from `b` to locate the MetaKit start.

**BitRock file manifest** (first large blob): format is Tcl list syntax:
```
path {file mode mtime ? {{chunk_offset chunk_size}...}}
```
Each entry names a file in the LZMA payload with its compressed chunk locations.

---

## Confirmed offsets (IDA Pro 9.4 SP1 reference)

| Variant | MetaKit start | MetaKit size |
|---------|--------------|-------------|
| Linux x64 | `0x22850239` | ~3.95 MB |
| Linux ARM64 | `0x203df011` | ~3.53 MB |
| Windows x64 | `0x25b23303` | ~3.43 MB (bitrock-lzma-4.0 off=13243) |
| macOS x64 | separate `osx-x86_64.dat` | 3,164,778 bytes |

**Schema:** `dirs[name:S,parent:I,files[name:S,size:I,date:I,contents:B]]`

---

## Next tools in chain

```python
# Extract and analyze each embedded ELF
for label, elf_bytes in parser.find_embedded_elfs().items():
    with open(f'/tmp/{label}.elf', 'wb') as fh:
        fh.write(elf_bytes)
    ctx2 = BinaryContext.load_or_build(f'/tmp/{label}.elf')
    print(ctx2.summary())

# Decode TclPro ByteCode scripts from MetaKit
from ablation.analyzers.tclpro_decoder import TclProDecoder
for label, blob in parser.find_tcl_scripts().items():
    if blob.startswith(b'TclPro ByteCode'):
        dec = TclProDecoder.from_bytes(blob)
        print(label, dec.report())
        for s in dec.security_strings():
            print(f'  SECURITY: {repr(s)}')
```
