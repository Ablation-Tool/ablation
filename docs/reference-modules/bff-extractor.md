# BffExtractor

## Why this exists

Four things were not possible before in Ablation:

1. **Extract files from AIX backup-by-name (BFF) archives.** GNU `tar`, `ar`, `file`, and `binwalk` all fail on BFF: `tar` does not recognise the format, `ar` errors on the magic bytes, and `binwalk` extracts raw byte-offset slices that are not the actual archived files. Before this module, every AIX OS package was opaque to the analysis chain.

2. **Make XCOFF binaries reachable.** XCOFF binaries inside BFF archives are invisible to LIEF, which returns `None` for XCOFF inputs. Without a BFF extractor, the XCOFF binaries could not be extracted, so `xcoff_parser` and `BinaryContext._build_xcoff` had nothing to parse.

3. **Handle AIX kernel extensions, shared objects, and loadable modules.** AIX 4.3.3 and 5.x ship all kernel networking drivers (`netintf`, `afinet`, `striped`) and loadable modules inside BFF containers. These are primary RE targets for the AIX network server analysis.

4. **Resolve the mixed-endian BFF layout.** BFF archives from an AIX/PowerPC (big-endian) platform store all integer fields in little-endian byte order. COFF/XCOFF tools that assume big-endian for all fields misread sizes and fail to locate data. This module handles the LE integer layout explicitly.

## Format notes

BFF layout:
- Magic: `0x09 0x00` at byte 0 of the archive
- Volume header: 72 bytes (fixed)
- Per-entry block (variable):
 - Extended stat: 56 bytes (timestamps, device/inode; all LE)
 - File size: 4 bytes LE (0 for directories)
 - Zero field: 4 bytes
 - Name: null-terminated, padded to next 8-byte boundary
 - Stat summary: 40 bytes (uid at +0, gid at +4, mode at +12; all LE)
 - Data: `<size>` bytes, padded to next 8-byte boundary

The name and data fields both use `_pad8(n) = (n + 7) & ~7` padding.

Confirmed on: `bos.net.tcp.server.4.3.3.84.bff` (86 entries: 36 XCOFF32, 44 other, 6 directories).

## Usage

```python
from ablation.core.bff_extractor import iter_entries, extract_to
from pathlib import Path

data = Path('bos.net.tcp.server.4.3.3.84.bff').read_bytes()

# Iterate entries
for entry in iter_entries(data):
    if not entry.is_dir:
        print(f'{entry.rel_path}  {len(entry.data)} bytes  mode={entry.mode:#o}')

# Extract all to a directory
extracted = extract_to(data, Path('/tmp/bff_out'))
print(f'{len(extracted)} entries extracted')

# Feed XCOFF entries directly to xcoff_parser
from ablation.core.xcoff_parser import parse as xcoff_parse
for entry in iter_entries(data):
    if entry.data[:2] in (b'\x01\xdf', b'\x01\xef'):
        binary = xcoff_parse(entry.rel_path, entry.data)
        print(f'{entry.rel_path}: {binary.arch}, {len(binary.exports)} exports')
```

## Key API

| Symbol | Description |
|--------|-------------|
| `BFF_MAGIC` | `b'\x09\x00'` |
| `BffEntry` | dataclass: `name, data, mode, uid, gid, mtime` |
| `BffEntry.is_dir` | True if `mode & S_IFMT == S_IFDIR` |
| `BffEntry.is_reg` | True if `mode & S_IFMT == S_IFREG` |
| `BffEntry.rel_path` | Name with leading `./` stripped |
| `iter_entries(data)` | Generator yielding `BffEntry` per archive entry |
| `extract_to(data, dest)` | Write all entries to `dest`; returns list of extracted entries |

## FORGE audit

Gate: **PASSED** (0 HIGH, 0 CRITICAL). 1 LOW finding: path traversal in `extract_to` for crafted `../` entry names (mitigated by trusted-input use case; tracked for future sanitization).
