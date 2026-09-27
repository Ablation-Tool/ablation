# Firmware Container Modules

Parsers for binary firmware container formats and video container forensics.

---

## FirmwareContainer

**File:** `ablation/analyzers/firmware_container.py`

Parses partitioned firmware images that use a plaintext header and a fixed-record partition
table. No encryption or compression at the container level; individual partitions may be
gzip, ext2/3/4, xz, ELF, cpio, or other formats detected automatically.

This module handles any firmware container with the following structure:

- 8-byte magic prefix identifying the container version
- Fixed-width header fields: firmware version, vendor string, product string, language
- Partition table starting at offset 0x54 — fixed 296-byte records

### Partition record layout

```
+0x00  version  char[16]    partition version string
+0x10  name     char[16]    partition name (e.g. "kernel", "bin")
+0x20  offset   uint32 LE   byte offset from container start
+0x24  size     uint32 LE   partition size in bytes
+0x28  destpath char[64]    flash destination path
+0x68  pad      byte[184]   zeros
```

### Payload detection

Each partition's payload type is detected from its leading bytes:

| Type | Detection |
|---|---|
| `gzip` | `\x1f\x8b` at offset 0 |
| `xz` | `\xfd7zXZ` at offset 0 |
| `zstd` | `\x28\xb5\x2f\xfd` at offset 0 |
| `lz4` | `\x02\x21\x4c\x18` at offset 0 |
| `lzo` | `\x89\x4c\x5a\x4f` at offset 0 |
| `cpio_newc` | `070701` at offset 0 |
| `cpio_odc` | `070707` at offset 0 |
| `elf` | `\x7fELF` at offset 0 |
| `pe` | `MZ` at offset 0 |
| `ext2/3/4` | superblock magic `\x53\xef` at offset 0x438 |
| `unknown` | none of the above matched |

Note: bzImage kernels match `pe` (MZ setup stub at offset 0) — this is expected.

### Usage

```python
from ablation.analyzers.firmware_container import FirmwareContainer

fw = FirmwareContainer.from_path('/path/to/firmware.BIN')

# Print partition table
fw.dump_partitions()

# Inspect partitions
for p in fw.partitions:
    print(p.name, p.payload_type, hex(p.offset), p.size)

# Read raw bytes for a partition
raw = fw.read_partition('bin')

# Extract one partition
fw.extract('kernel', '/tmp/kernel.bin')

# Extract all partitions
fw.extract_all('/tmp/parts/')
```

### CLI

```
python3 -m ablation.analyzers.firmware_container <image.BIN>
python3 -m ablation.analyzers.firmware_container <image.BIN> extract <outdir>
```

### API reference

| Method | Returns | Description |
|---|---|---|
| `FirmwareContainer.from_path(path)` | `FirmwareContainer` | Load and parse image |
| `.dump_partitions()` | None | Print formatted partition table |
| `.get_partition(name)` | `FirmwarePartition \| None` | Find partition by name |
| `.read_partition(name)` | `bytes` | Raw bytes for named partition |
| `.extract(name, out_path)` | `Path` | Write partition to file |
| `.extract_all(out_dir)` | `list[Path]` | Extract all partitions |

### FirmwarePartition fields

| Field | Type | Description |
|---|---|---|
| `index` | int | Position in partition table |
| `name` | str | Partition name |
| `version` | str | Partition version string |
| `offset` | int | Byte offset in container |
| `size` | int | Partition size in bytes |
| `destpath` | str | Flash destination path |
| `payload_type` | str | Detected payload type |

---

## VideoContainerAnalyzer

**File:** `ablation/analyzers/video_container.py`

Forensic scanner for MP4/MOV, MKV/WebM, and AVI container files. Detects structural
anomalies that indicate polyglot files, appended payloads, or malformed containers used
to exploit media parsers.

### Checks performed

**Polyglot detection** — scans the first 8 bytes for multiple valid magic signatures
(e.g., ZIP + MP4, ELF + MP4). A dual-magic file is a polyglot and warrants manual
inspection.

**Trailer data (appended payload)** — computes the declared container end from the
top-level atom/chunk structure and compares against the file size. Bytes after the
declared end are reported with their length and a hex preview.

**Atom/box size overflow (MP4/MOV)** — checks each top-level atom for declared sizes
that exceed the remaining file. An overflowing atom typically crashes or exploits a
vulnerable media parser.

**EBML length abuse (MKV/WebM)** — checks for EBML unknown-length elements outside of
`Cluster` scope, where they are not valid. Parsers that accept them may process
attacker-controlled data.

**RIFF chunk miscount (AVI)** — verifies that the sum of chunk sizes in the LIST/movi
hierarchy matches the declared `movi` size.

### Usage

```python
from ablation.analyzers.video_container import VideoContainerAnalyzer

analyzer = VideoContainerAnalyzer.from_path('/path/to/sample.mp4')
findings = analyzer.scan()
print(analyzer.report(findings))
```

### API reference

| Method | Returns | Description |
|---|---|---|
| `VideoContainerAnalyzer.from_path(path)` | `VideoContainerAnalyzer` | Load file, detect format |
| `.scan()` | `list[VideoFinding]` | Run all checks, return findings |
| `.report(findings)` | `str` | Human-readable report |

### VideoFinding fields

| Field | Type | Description |
|---|---|---|
| `check` | str | Check name (e.g. `polyglot`, `trailer_data`) |
| `severity` | str | `HIGH`, `MEDIUM`, or `INFO` |
| `detail` | str | Human-readable description |
| `offset` | int \| None | File offset where anomaly was found |
