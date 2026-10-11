# appledouble-extractor

## Why this exists

Three things that were not possible before in Ablation:

1. **Tool_Chest compiled Mac Classic binaries were unreadable.** `unar -forks visible` extracts `.rsrc` files in AppleDouble format: the 26-byte AppleDouble header is prepended to the resource fork data. Every attempt to parse these `.rsrc` files as raw resource forks produced garbage. 533 of 894 Tool_Chest archives contain compiled Mac Classic binaries; all were blocked.

2. **No scriptable resource fork extraction pipeline.** Each session required a manual byte-offset calculation to skip to the actual resource fork data: error-prone, not reproducible, and blocking all Tool_Chest network-stack analysis.

3. **Entry enumeration was opaque.** AppleDouble files contain Finder info, file dates, real name, and other metadata entries alongside the resource fork. Without a parser, these entries were invisible and could not be cross-referenced with findings.

The module is needed because `unar` is the only reliable Linux tool for Mac archive extraction (BinHex/Stuffit pipelines), and it always emits AppleDouble wrappers on systems without a HFS+ filesystem driver.

## What it does

Parses the AppleDouble container header (magic `0x00051607`, RFC 1740 / Apple II File Type Note $E0/$E1 format), enumerates all entry descriptors, and returns raw bytes for any entry: primarily the resource fork (entry ID 2).

AppleDouble format layout:
```
+00  uint32  magic         0x00051607
+04  uint32  version       0x00020000 (v2) or 0x00010000 (v1)
+08  char[16] home_fs      NUL-padded filesystem name string
+24  uint16  entry_count
+26  entries (12 bytes each):
     +00  uint32  entry_id
     +04  uint32  offset    (absolute from file start)
     +08  uint32  length
```

Entry IDs: 1=data_fork, 2=resource_fork, 3=real_name, 4=comment, 5=icon_bw, 6=icon_color, 7=file_dates, 8=finder_info, 9=macintosh_info, 10=file_dates_new.

## Usage

```python
from ablation.analyzers.appledouble_extractor import AppleDoubleExtractor

# Single file: raw resource fork bytes
raw = AppleDoubleExtractor.from_path('/path/to/file.rsrc').resource_fork()

# Introspect all entries
ext = AppleDoubleExtractor.from_bytes(data)
print(ext.report())
for entry in ext.entries:
    print(f"id={entry.entry_id} {entry.name} offset=0x{entry.offset:x} len={entry.length}")

# Get the resource fork entry descriptor without extracting bytes
rf_entry = ext.resource_fork_entry()   # AppleDoubleEntry | None

# Batch extraction
paths = ['/tool_chest/foo.rsrc', '/tool_chest/bar.rsrc']
results = AppleDoubleExtractor.batch_extract_resource_forks(paths)
# {path_str: bytes | None}

# Check file type before parsing
if AppleDoubleExtractor.is_appledouble(data):
    ...
```

## Notes

- Offset in each entry is absolute from the start of the AppleDouble file (not from the end of the header). This is the most common off-by-one mistake when parsing manually.
- AppleSingle (magic `0x00051600`) is rejected with a descriptive error: it embeds both forks inline and requires a different parser.
- `batch_extract_resource_forks` returns `None` for paths that fail to parse (truncated, wrong magic, missing resource fork entry) rather than raising.
- `real_name()` decodes the entry using `mac_roman` with error replacement: correct for all Mac OS 8/9 era filenames.
