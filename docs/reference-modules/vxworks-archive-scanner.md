# VxWorksArchiveScanner

## Why this exists

Three things were not possible before in Ablation:

1. **Scan VxWorks static archives for frame-overflow patterns without extracting object files manually.** VxWorks network stack components such as `libwmNet.a` and `libNetBuf.a` are distributed as GNU `ar` archives. `BinaryContext` builds a context per-binary; there was no way to sweep all object files in an archive for a specific sink pattern without manually running `ar x` and repeating the analysis for each `.o`. The VxWorks sessock and solidDB VxWorks analyses both required manually expanding archives.

2. **Resolve callee names across `.o` ELF relocation tables.** In relocatable `.o` files, `bl` instructions carry an offset of 0; the actual callee is stored in `.rela.text` R_PPC_REL24 entries. Capstone decodes `bl 0x0` for every call site. Without relocation resolution, finding `strcpy` calls required manually cross-referencing the symbol table, an error-prone process that slowed VxWorks analysis significantly.

3. **Detect stack frame overflows.** `SinkArgClassifier` and `TaintTracker` work on single functions in a loaded binary. The VxWorks archive scanner adds frame-size awareness: it reads the `stwu r1, -N(r1)` prologue to determine the stack frame size, then reports `strcpy` and `strcat` call sites where the frame is small enough to be overflowed by a typical receive buffer. This is the pattern class that produced SDB-NET-001 and related VxWorks findings.

## Pattern detected

For each object file in the archive:

1. Locate each `stwu r1, -N(r1)` instruction stack frame allocation where `frame_min <= N <= frame_max`.
2. Within the same function, find any `bl` that resolves via R_PPC_REL24 to `strcpy` or `strcat`.
3. Report the object file, function name, frame size, and call VA.

## Usage

```python
from modules.vxworks_archive_scanner import VxWorksArchiveScanner

scanner = VxWorksArchiveScanner('/path/to/libwmNet.a')
findings = scanner.scan_strcpy_in_frame(frame_min=0x80, frame_max=0x300)
print(VxWorksArchiveScanner.report(findings))

# Narrow to specific object files
scanner = VxWorksArchiveScanner('/path/to/libwmNet.a',
                                targets=['sockLib.o', 'tcpLib.o'])
```

## Key API

| Symbol | Description |
|--------|-------------|
| `VxWorksArchiveScanner(archive_path, targets=None)` | Constructor; `targets` filters to named object files |
| `VxWorksArchiveScanner.scan_strcpy_in_frameframe_min, frame_max` | Returns `list[ArchiveSite]` |
| `VxWorksArchiveScanner.reportfindings` | Human-readable summary string |
| `ArchiveSite.obj_file` | Object file name within the archive |
| `ArchiveSite.func_name` | Function name (from ELF `.symtab`) |
| `ArchiveSite.func_va` | Function start VA section-relative |
| `ArchiveSite.call_va` | VA of the `bl strcpy/strcat` instruction |
| `ArchiveSite.frame_size` | Stack frame size N (bytes) |
| `ArchiveSite.callee_name` | Resolved callee name (`strcpy` or `strcat`) |

## Implementation notes

- Uses `ar p <archive> <member>` via subprocess to extract each object file in memory.
- Resolves callee names via `.rela.text` R_PPC_REL24 relocations (type `0x0a`).
- `_find_frame_size()` scans for `stwu r1, -N(r1)` encoded as opcode 37, rS=r1, rA=r1 in the first 20 instructions of the function.

## Limits

| Constant | Value | Purpose |
|----------|-------|---------|
| `_MAX_ARCHIVE_BYTES` | 128 MB | `os.path.getsize()` guard in `__init__` before archive scan |
| `_MAX_MEMBER_BYTES` | 16 MB | Cap on bytes returned by `ar p` per extracted `.o` member |

## FORGE audit

Gate: **PASSED**. Two fixes applied:

| Fix | Location | Description |
|---|---|---|
| CWE-770: unbounded archive read | `__init__` | `_MAX_ARCHIVE_BYTES=128MB` via `os.path.getsize()` guard before archive scan |
| CWE-770: unbounded member read | `_extract_member` | `_MAX_MEMBER_BYTES=16MB` cap on bytes returned by `ar p` per `.o` member |
| CWE-20: unguarded `shstrtab.index()` | `sh_name()` inner function in `_parse_elf32_ppc` | `shstrtab.index(b'\x00', name_off)` raised `ValueError` on malformed ELF; now wrapped in `try/except (ValueError, IndexError)` returning `''`: matches the identical guard in the `.symtab` str_data loop |

No HIGH or CRITICAL findings remain.

---

## How it works

Reads the binary header to validate the container magic, walks the partition or directory table, and yields the raw bytes of each embedded payload. Format detection runs on the first 512 bytes of each partition to classify the content as ELF, SquashFS, ext4, JFFS2, or unknown before extraction begins. Checksum validation CRC32 or SHA256 depending on container format runs on the extracted bytes and raises `ExtractionError` if the digest does not match the stored value.

---

## Example output

```
Extracted 4 partitions from firmware.bin:
  [0] boot      512 KB  ELF (ARM64)
  [1] rootfs    18 MB   SquashFS
  [2] data      4 MB    ext4
  [3] config    128 KB  JFFS2
Written to /tmp/extracted/
```

---

## False positives

Extraction either succeeds or raises an exception, there are no false positives in the traditional sense. Check for incomplete downloads (`.aria2` sidecar present) before analysis: partial images produce truncated or zero-filled partitions that pass validation but contain no useful data.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to identify the outer binary format and confirm the container is present.

**After this module:** Feed extracted partition bytes to `BinaryContext.load_or_build()` or the appropriate ISA taint tracker for each extracted payload.

---

## Reading findings

`VxWorksArchiveScanner.from_path(path).scan()` returns `List[ArchiveSite]`:

| Attribute | Content |
|:---|:---|
| `obj_file` | Member name of the `.o` archive member containing the finding |
| `func_name` | Enclosing function symbol name if resolved |
| `func_va` | Function start offset in `.text` |
| `call_va` | Offset of the `bl` branch-and-link instruction |
| `frame_size` | Stack frame size allocated at function entry |
| `callee_name` | Target symbol name from `.rela.text` or hex address if unresolved |

---

## See also

- [BinaryContext](binary-context.md): load extracted payloads for analysis
- [FirmwareContainers](firmware-containers.md): higher-level firmware partition walker
- [EntropyMapper](entropy-mapper.md): locate encrypted or compressed regions before extraction
