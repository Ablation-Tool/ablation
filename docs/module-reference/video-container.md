# VideoContainerAnalyzer

**File:** `modules/video_container.py`

## Why this exists

Four gaps existed before this module:

1. **Video files as dropper delivery vectors were not analyzed.** Polyglot files embedding ELF, PE, Mach-O, or archive payloads inside MP4/MKV/AVI containers bypass naive file-type checks. No automated detector existed in the Ablation pipeline.

2. **Binary magic scanning inside container atoms was absent.** ELF or ZIP content embedded inside a `udta`, `free`, or MKV Void element is invisible to signature-based scanners that check only the file header. `_scan_for_embedded_magic` recursively checks atom payloads.

3. **DRM component fingerprinting was not available.** Identifying Widevine, PlayReady, FairPlay, Adobe Primetime, and Nagra protection system UUIDs inside `pssh` boxes required manual parsing of the ISOBMFF atom tree.

4. **Entropy anomaly detection in non-compressed regions was absent.** Encrypted or compressed payloads hiding inside `free`, `skip`, or `uuid` atoms have anomalously high entropy. High-entropy fraction detection flags these regions.

---

## Scope

967-line pure in-memory analysis module. Reads file once (capped at 256 MB), then all analysis operates on the in-memory `bytes` object. No network I/O, no subprocess, no lief. Supports:

- **MP4/MOV (ISOBMFF)**: Full atom tree walk, DRM atom detection (pssh/encv/enca/sinf/tenc), oversized metadata atoms, embedded binary scan in unknown/metadata atoms, entropy anomaly in non-video atoms
- **MKV/WebM (EBML)**: EBML element tree walk, ContentEncodings DRM detection, attachment FileData binary scan, oversized Void element detection with entropy check
- **AVI (RIFF)**: RIFF chunk walk, JUNK/IDIT/ISFT chunk binary scan, oversized JUNK chunk entropy check, size overrun detection

All formats: polyglot detection (prepended magic before container, appended data past declared container end).

---

## Key API

```python
from modules.video_container import VideoContainerAnalyzer, VideoFinding

# Load and scan
analyzer = VideoContainerAnalyzer.from_path('/path/to/file.mp4')
findings = analyzer.scan()       # list[VideoFinding], severity-sorted CRITICAL→LOW
print(analyzer.report(findings))

# Filter by category
polyglots = [f for f in findings if f.category == 'POLYGLOT']
drm       = [f for f in findings if f.category == 'DRM']
embedded  = [f for f in findings if f.category == 'EMBEDDED_BINARY']
```

`VideoFinding` fields: `offset` (file offset), `severity` (CRITICAL/HIGH/MEDIUM/LOW), `category`, `description`, `detail`.

Finding categories:

| Category | Description |
|---|---|
| `POLYGLOT` | Data outside declared container boundaries (prepended or appended) |
| `EMBEDDED_BINARY` | Known binary magic (ELF, PE, ZIP, Mach-O, etc.) inside an atom/element/chunk |
| `ANOMALOUS_STRUCTURE` | Malformed sizes, atoms extending past file boundary |
| `DRM` | Encrypted track or protection metadata (pssh, encv, enca, ContentEncodings) |
| `METADATA_ANOMALY` | Oversized metadata container (udta/free/skip/uuid/Void/JUNK) |
| `UNKNOWN_TYPE` | Non-printable or unrecognized atom type / EBML element ID |
| `ENTROPY_ANOMALY` | High-entropy region in non-compressed atom (possible encrypted payload) |

---

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_CONTAINER_BYTES` | 256 MB | File read cap in `from_path()` |
| `_MIN_ATOM_SCAN_SIZE` | 8 B | Minimum atom payload size for embedded magic scan |
| `_ENTROPY_ENCRYPTED_THRESHOLD` | 7.2 bits | Shannon entropy threshold for "high entropy" window |
| `_ENTROPY_WINDOW_SIZE` | 4096 B | Sliding window size for entropy analysis |
| `_ENTROPY_HIGH_FRACTION` | 0.60 | Fraction of high-entropy windows to trigger finding |

---

## FORGE audit

Gate: **PASSED**. No code changes needed.

- `from_path()`: `p.stat().st_size` check against `_MAX_CONTAINER_BYTES` before `p.read_bytes()`. Raises `ValueError` on oversized files (documented precondition).
- No file reads inside `scan()` or any analysis method — all work on `self._data` loaded once.
- No bare `except:`. No try/except inside any parser function — bounds checks prevent exceptions.
- Recursion bounded: `max_depth=8` (MP4), `max_depth=6` (EBML/RIFF).
- Division guard: `return high / total if total else 0.0` in `_high_entropy_fraction`.
- EBML element sizes: master element recursion only when `esize < 4 MB`; MP4 container atom recursion only when `data_size < 8 MB`.
- No lief.parse(). No network I/O. No subprocess.
