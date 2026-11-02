# Streaming Xilinx WDB Event Recovery

`xilinx_wdb.py` decodes Xilinx WDB 01 waveform containers through a bounded memory map and streaming event iterator. It supports the older two-section RTTI/`WDB.Event` layout found in the 2017 Endeavour archive and event-only decoding of the newer three-section layout.

For the newer embedded `Xilinx ISim DBG 006` name/type profile, a separately pinned MIT-licensed reader is preserved under `analysis/tools/vivado-wdb/`. The two paths deliberately do not share unsupported naming assumptions.

## Why this exists

The Endeavour waveform is 35 MB and not SQLite. Initially it could only be identified and hashed. Its older container layout differs from the newer profile: the third header pointer is zero and the modern embedded debug database is absent. Forcing the newer reader produced a structural error rather than useful evidence.

The streaming decoder provides three benefits:

1. **Actual event access.** It recovers timestamps, root indices, storage identifiers, and binary payloads from zlib-compressed event pages.
2. **Bounded resource use.** Millions of records need not be retained in Python objects; filtered exports and summaries stream through the file.
3. **Honest metadata boundaries.** Legacy events remain unnamed instead of receiving guessed signal names or incompatible type assignments.

## Accepted profiles

### Legacy two-section

Required properties:

- `Xilinx WAVE DATABASE 01` signature;
- RTTI and `WDB.Event` pointers at `0x48` and `0x50`;
- zero third pointer at `0x58`;
- exactly those two unique ascending sections;
- valid event index pages and compressed records.

The Endeavour WDB has 21 roots and 10,759,544 records, with event times from 0 to 10,030,000,000 ps.

### Three-section event-only

The header contains unique ascending RTTI, DBG, and `WDB.Event` sections. Event records are decoded with the same bounds, but the module does not implement the modern DBG name/type mapping. Use the pinned full converter when that mapping is required and its profile matches.

## Event layout

Index pages are `0x4C0` bytes and contain:

- next-page pointer;
- up to 100 compressed payload pointers and sizes;
- valid payload count.

Each decompressed chunk has a 20-byte header followed by fixed 16-byte event headers and variable payloads. The decoder validates pointer ranges, page cycles, record counts, payload lengths, zlib completion, and zero trailing bytes.

Each exported event contains:

- `root_index` and hexadecimal `storage_id`;
- integer timestamp and picoseconds for the characterized profile;
- full payload length and bounded hexadecimal payload;
- chunk serial and record slot.

No signal name is emitted when the embedded metadata cannot establish one.

## Python API

```python
from ablation.analyzers.xilinx_wdb import WdbReader

path = '/media/cowboy/research/CERN/analysis/wdb/endeavour_tb_behav.wdb'
with WdbReader(path) as reader:
    summary = reader.summary()
    exported = reader.export_jsonl(
        '/media/cowboy/research/CERN/analysis/wdb/legacy-events.jsonl',
        max_events=16,
        payload_limit=64,
    )

print(summary['events'])
print(summary['first_time'], summary['last_time'])
print(exported['complete_within_limit'])
```

The reader is a context manager and closes its memory map and input stream on exit. Calling `events()` yields one `WdbEvent` at a time. `summary()` accumulates only bounded root and stream statistics.

## CLI

```bash
python3 -m ablation.analyzers.xilinx_wdb \
  /media/cowboy/research/CERN/analysis/wdb/endeavour_tb_behav.wdb \
  --events-output /media/cowboy/research/CERN/analysis/wdb/legacy-events.jsonl \
  --summary-output /media/cowboy/research/CERN/analysis/wdb/legacy-summary.json \
  --max-events 16
```

Use repeated `--root N` options to filter roots and `--payload-limit N` to bound each payload preview. Full payload length is preserved even when preview bytes are truncated.

JSONL export writes a temporary file and atomically renames it only after successful completion. A decoding error does not leave a successful-looking partial output.

## Resource limits

Defaults include:

- 4 GiB input address limit;
- 50 million events;
- 100,000 storage streams;
- 100,000 pages per chain;
- 64 MiB decompressed data per chunk;
- 1 MiB per event payload;
- 100,000 exported events and 64 preview bytes per event.

Exceeding a limit raises `WdbDecodeError` or `ValueError`. Time filters, root filters, and summary stream limits are validated before export.

## Modern profile reader and provenance

The full reference implementation and MIT license were pinned at commit `419f78bad3e8286a70574a685acf1043e33105c5`:

- source: https://github.com/Ross0907/Vivado-WDB-Waveform-Converter
- local copy: `analysis/tools/vivado-wdb/`
- Ablation license copy: `ablation/data/vivado_wdb_upstream_LICENSE.txt`

It documents its observed 2026.1 profile and rejects ambiguous mappings. The streaming legacy module is an independently bounded implementation of the event layout, with attribution for the format evidence.

## Verification

`tests/test_xilinx_wdb.py` constructs a valid two-section container and tests summary counts, filtered JSONL, invalid signatures, out-of-range pointers, bad zlib streams, page cycles, event limits, and atomic output. The integration test decodes the complete Endeavour file and checks its exact root, event, and timestamp totals.

## Limitations

- Legacy root/storage IDs do not prove HDL names, widths, or types.
- Event timestamps are profile ticks; picosecond interpretation is limited to the characterized XSim files.
- Chunk order across independent roots is not globally sorted.
- A successful event decode does not prove an archived transaction passed; correlate it with HDL and protocol evidence.
- Three-section support is event-only, not a replacement for the modern DBG mapper.

See [known anomalies](../reference-anomalies/xilinx-wdb.md) and the [CERN workflow](../workflows/cern-reverse-engineering-toolchain.md).
