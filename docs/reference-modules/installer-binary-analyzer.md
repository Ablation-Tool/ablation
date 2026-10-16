# InstallerBinaryAnalyzer

## Why this exists

Three things were not possible before in Ablation:

1. **Enumerate PE binaries embedded in self-extracting installers.** BitRock/Bitnami, NSIS, and Inno Setup installers compress their payload into a single EXE stub. Before this module, finding the actual flasher DLLs and drivers inside an installer required extracting it externally with 7z or innounp and guessing which output files mattered. This module automates that step in-process, returning `CarvedBinary` objects ready for pe_sweep or taint analysis.

2. **Handle UPX-wrapped installer stubs.** The TI CC3xxx RadioTool and RTI SDK BitRock installers are double-packed: the BitRock PE stub is further compressed with UPX before distribution. Standard lief/Capstone analysis fails on packed data. This module detects UPX sections and calls `upx -d` to unpack before BitRock extraction, so the analysis pipeline sees clean code.

3. **Recover filename hints for carved PEs.** When a firmware flasher includes multiple DLLs and drivers in one payload, knowing which carved PE is the flasher core vs. a supporting library matters. This module scans the 200 bytes before each `MZ` header in the decompressed payload for null-terminated strings containing `.` separators and reports the best candidate as `name_hint`.

## Format notes

### BitRock LZMA-4.0 layout

```
[PE sections ...] [overlay at max_raw] [PKCS7 signature]

Overlay:
  [4-byte LE]  record_size  (e.g. 0x0e = 14)
  [bytes]      section name: record_size - 4 bytes, null-terminated; e.g. '.eh_frame\0'
  [1 byte]     compression type  (0xFF = LZMA)
  [LZMA_ALONE stream]
  [bitrock-lzma-4.0 marker]
  [PKCS7 digital signature]
```

Confirmed on:

- TI CC3xxx RadioTool 1.0.3.19 (UPX outer + BitRock inner)
- TI CC3xxx RadioTool 1.2 (UPX + BitRock)
- RTI SDK v2.00.01.15 (UPX + BitRock)

When `comp_type != 0xFF`, the module falls back to a brute-force probe across the first 64 overlay bytes, scanning for valid LZMA_ALONE properties bytes and known dictionary sizes. This handles variants where the record format differs.

### PE carving from decompressed payload

Carving walks the decompressed buffer for `MZ` at 2-byte boundaries, validates `PE\x00\x00` at `e_lfanew`, cross-checks section table for plausible `raw_off + raw_size` values, and rejects entries with `num_sections > 96`. The arch code is mapped from the COFF `Machine` field.

## Usage

```python
from modules.installer_binary_analyzer import InstallerBinaryAnalyzer

# Analyze an installer
result = InstallerBinaryAnalyzer.from_path('/path/to/setup.exe').analyze()
print(InstallerBinaryAnalyzer.report(result))

# Extract to files for further analysis
paths = InstallerBinaryAnalyzer.extract_to_dir(result, '/tmp/extracted/')
for name, path in paths.items():
    print(f"  {name}: {path}")

# Access decompressed payload directly
if hasattr(result, '_dec'):
    payload_bytes = result._dec  # full decompressed BitRock payload
```

## Result fields

| Field | Type | Meaning |
|---|---|---|
| `installer_type` | str | `'bitrock-lzma-4.0'`, `'nsis'`, `'inno'`, `'unknown'` |
| `upx_unpacked` | bool | True if UPX was detected and removed |
| `payload_size` | int | Decompressed payload size in bytes |
| `binaries` | List[CarvedBinary] | Carved PE objects from payload |
| `errors` | List[str] | Non-fatal errors: upx missing, overlay parse fail |

Each `CarvedBinary`:

| Field | Type | Meaning |
|---|---|---|
| `offset` | int | Byte offset in decompressed payload |
| `arch` | str | `'i386'`, `'x64'`, `'ARM'`, `'ARM64'`, `'PPC32'`, or `'0x<machine>'` |
| `size` | int | Approximate size from last section end |
| `data` | bytes | Raw PE bytes |
| `name_hint` | str | Best-effort filename from preceding bytes in payload |

## Limitations

- NSIS and Inno Setup extraction is detection-only. Pass to `7z e` or `innoextract` for actual extraction.
- BitRock payloads that use compression types other than `0xFF` (LZMA) are handled by the brute-force probe; exotic dict sizes may not be covered.
- UPX unpacking requires `upx` on PATH. If absent, `result.errors` contains a message and the packed data is analyzed as-is.
- `extract_to_dir` uses file size to choose `.exe` vs `.dll` extension when `name_hint` has no extension. This heuristic is imprecise.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `_MAX_INSTALLER_BYTES=256MB`; `os.path.getsize()` guard in both the extraction path and the direct-read path.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Example output

```
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `finding_type` | Scanner-specific category label |
| `va` | Virtual address of the call site or instruction in the binary |
| `func_va` | Virtual address of the containing function |
| `detail` | What was found and the specific condition that triggered it |
| `sink_name` | Name of the dangerous function reached (if applicable) |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
