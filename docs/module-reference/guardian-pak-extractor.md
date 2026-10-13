# GuardianPakExtractor

## Why this exists

4 things that weren't possible before in Ablation:

1. **Extract files from Tandem Guardian PAK archives.** Guardian PAK is not a ZIP file despite the `.ZIP` extension used for patch distribution. `unzip`, `file`, `binwalk`, and every other standard archive tool reject these files. The only documented extractor (`UNPAK`) requires a live Tandem NSK system. Without this module, every Guardian PAK is a sealed black box.

2. **Provide the prerequisite for any RE work on Guardian-native code.** Guardian PAK archives are the only publicly accessible corpus of Tandem NonStop binaries. The platform's source code, ABI, and file-format specs are covered by NDA; no public documentation or disassembler plugin exists for any of the common RE tools. This extractor is the unlocking step for all Guardian RE in Ablation.

3. **Handle content-based record detection.** The Guardian BACKUP tape format (which wraps the PAK contents) uses 2-byte type codes per record, but these codes are NOT stable across archive runs — confirmed: the tape-label code is `0x6891` in one PTF archive and `0x1F1A` in another for the same logical record class. Any type-code-based parser silently misidentifies records on the second archive it encounters. This module detects record class by content signature and record size, making it correct across archive variants.

4. **Preserve Guardian three-component filenames.** Guardian files live in a `$VOLUME.SUBVOLUME.FILENAME` three-field namespace (each component up to 8 characters) with no POSIX equivalent. No standard tool maps these to a safe filesystem path without truncation or silent collision. This module parses the 24-byte padded-field structure at offset `0x2E` in file header records and maps it to a clean directory hierarchy.

## Format notes

**PAK container structure:**

```
magic       8 bytes   b'PAK \x00\x01\x00\x00'
subtype     2 bytes   (typically 0x000A)

Chunk stream:
  chunk_size  2 bytes   big-endian; 0xFFFF = group separator (skip)
  zlib_data   chunk_size bytes
  padding     0-1 bytes (1 if chunk_size is odd, for 2-byte alignment)

Archive terminator: FF FF FF FF  (two consecutive group separators)
```

**Guardian BACKUP tape records (decompressed chunk contents):**

```
Record detection is content-based — type codes are not stable across archives:

  Tape label    200-byte chunk containing b'Tandem Archive Tape'
  File catalog  222-byte chunk containing b'File Backup'
  File header   358-byte chunk with b'$' at offset 0x2E (Guardian path start)
  Data block    any other chunk following a file header (~28 KB typical)
```

**Guardian path layout (offset 0x2E in 358-byte file header):**

```
bytes[0:8]   volume    space-padded, e.g. b'$DEV2   '
bytes[8:16]  subvolume space-padded, e.g. b'ZMQP001E'
bytes[16:24] filename  space-padded, e.g. b'ALTMQFLS'
```

**Confirmed architecture:** Tandem Himalaya K-series = MIPS32 big-endian. Verified by Capstone decode of extracted binaries from two NSK PTF archives.

## Usage

```python
from ablation.core.guardian_pak_extractor import iter_files, extract_to, GuardianFile
from pathlib import Path

# Iterate files without writing to disk
data = Path('patch.zip').read_bytes()
for f in iter_files(data):
    print(f'{f.path}  {len(f.data)} bytes  arch={f.arch}')

# Extract to a directory hierarchy ($VOL/SUBVOL/FILENAME)
extracted = extract_to(data, Path('/tmp/guardian_out'))
for f in extracted:
    print(f'{f.path}  →  {f.volume.lstrip("$")}/{f.subvolume}/{f.filename}')

# Access file contents directly
for f in iter_files(data):
    if f.filename == 'MQMSVR':
        mips_code = f.data  # raw MIPS32be binary
```

## Key API

| Symbol | Description |
|--------|-------------|
| `GUARDIAN_PAK_MAGIC` | `b'PAK '` — first 4 bytes of any valid PAK archive |
| `GuardianFile` | Dataclass: `path`, `volume`, `subvolume`, `filename`, `data`, `arch` (`"mips32be"`) |
| `iter_chunks(data)` | Decompress and yield raw Guardian BACKUP record bytes; raises `ValueError` on bad magic; skips corrupt chunks silently |
| `iter_files(data)` | Yield `GuardianFile` per file; accumulates consecutive data chunks; flushes on tape_label/file_catalog boundaries |
| `extract_to(data, dest)` | Extract all files to `dest/$VOL/SUBVOL/FILENAME` hierarchy; returns `List[GuardianFile]`; skips files with empty filename |
| `_parse_guardian_path(record)` | `(volume, subvolume, filename)` from 358-byte file header; fallback scans for `$` if not at offset `0x2E` |

## FORGE audit

Gate: **PASSED** (0 HIGH, 0 CRITICAL).

- 1 MEDIUM (FORGE §3): `zlib.decompress()` has no `max_length` — a crafted PAK could cause OOM via zlib bomb. Acceptable for trusted RE corpus use; callers consuming untrusted PAK files should pre-screen decompressed size.
- 1 LOW (FORGE §6): the docstring listed specific record type code values (`0x6891`, `0xDF3B`, `0x0F02`) as if they were authoritative. Fixed before commit: docstring now explicitly states codes are not stable and documents the content-detection approach instead.
- 1 LOW (FORGE §2): the `< 4` chunk size guard in `iter_files` discarded legitimate small data chunks (e.g., 3-byte or 1-byte payloads). Fixed before commit: guard changed to skip only truly empty blocks (`if not chunk`).

Confirmed on two NSK middleware PTF archives (66 files / ~130 MB and 83 files / ~139 MB decompressed).
