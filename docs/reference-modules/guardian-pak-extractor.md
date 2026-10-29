# Guardian PAK Extraction

`GuardianPakExtractor` functionality in `ablation.core.guardian_pak_extractor` recovers files from Tandem NonStop Guardian PAK archives. It provides in-memory iteration and optional disk extraction without a NonStop system or a ZIP-compatible tool.

---

## Why this exists

Guardian patches may use a `.ZIP` suffix while containing none of the ZIP structure expected by `unzip` or `binwalk`. The payload combines a proprietary PAK chunk stream with Guardian BACKUP tape records. Without a reader for both layers, the executable contents remain inaccessible.

The extractor also addresses two details that a one-off decompressor can get wrong. BACKUP record type codes vary between archives, so content signatures are more reliable than a fixed type table. Guardian filenames contain three components, so preserving volume, subvolume, and filename separately avoids flattening the namespace.

This is an ingestion component, not a NonStop decompiler. Recovered Himalaya K-series files are labeled `mips32be` so they can enter an appropriate MIPS analysis workflow.

---

## How extraction works

1. Require the `PAK ` magic and walk the big-endian compressed-chunk lengths after the header and subtype field.
2. Decompress each recognized zlib chunk and skip `0xFFFF` group separators and alignment padding.
3. Identify tape-label, file-catalog, and file-header records using fixed sizes and content signatures.
4. Parse the 24-byte path field at offset `0x2E` in a file header, with a bounded fallback search for `$`.
5. Accumulate following data records until another file or catalog boundary, then yield a `GuardianFile`.

The observed layout is:

```text
PAK header + subtype
  -> repeated zlib chunks
  -> Guardian BACKUP records
  -> file header: $VOLUME + SUBVOLUME + FILENAME
  -> consecutive file-data records
  -> GuardianFile(path, components, data, arch='mips32be')
```

Content-based record detection works across the reviewed archive variants because it does not assign permanent meaning to their unstable two-byte type codes. It remains an empirical format model rather than a vendor conformance proof.

---

## Iterate without writing files

```python
from pathlib import Path
from ablation.core.guardian_pak_extractor import iter_files

raw = Path('/path/to/patch.zip').read_bytes()
for item in iter_files(raw):
    print(f'{item.path}  {len(item.data)} bytes  arch={item.arch}')
    if item.filename == 'MQMSVR':
        mips_code = item.data
```

`GuardianFile` exposes `path`, `volume`, `subvolume`, `filename`, `data`, and `arch`. In-memory iteration is the preferred first step for unfamiliar or untrusted archives.

`iter_chunks()` is the lower-level zlib/record iterator. Invalid outer magic raises `ValueError`; corrupt compressed chunks are skipped. `extract_to(data, Path(destination))` writes recovered files into volume/subvolume directories and returns the corresponding `GuardianFile` objects.

---

## What this adds for the user

The reader turns a vendor-specific archive into named byte payloads suitable for inventory and MIPS analysis. It replaces a live-platform extraction dependency with a small Python API that can be reused by a batch sweep or a later Guardian-aware loader.

The parser can evolve independently as more record layouts are validated. A future bounded extraction interface could wrap it, but such an interface must add hostile-input limits rather than presenting current iteration as a containment boundary.

---

## Safety and limitations

- `zlib.decompress()` and per-file accumulation have no global expanded-output budget. Apply process resource limits and pre-screen untrusted archives before iteration.
- Corrupt compressed chunks are skipped, so a nonempty result does not prove that every archive member was recovered.
- `extract_to()` derives directories from archive metadata but is not a general hostile-path containment proof. Validate names and destination containment before using it on untrusted input.
- The `mips32be` label reflects the validated Himalaya K-series artifacts. Confirm architecture independently for a new payload family.
- No cryptographic signature, package authenticity, runtime authorization, or deployment relevance is established by successful extraction.

---

## See also

- [Legacy Binary Formats](motorola-88000-bcs-coff.md): how Guardian and MC88100 ingestion relate
- [MIPS Decompilation & Taint Analysis](mips.md): subsequent analysis for recovered MIPS payloads
- [Nested Archive Scanner](nested-archive-scanner.md): other archive-handling paths with different safety models
