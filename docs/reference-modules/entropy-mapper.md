# Entropy Mapper

**File:** `ablation/analyzers/entropy_mapper.py`

Maps a firmware binary by Shannon entropy before any analysis begins, classifying every region as encrypted, executable, sparse, or padding. Sections approaching H=8.0 bits/byte hold encrypted or compressed data; analysis effort concentrates on decrypted plaintext regions first.

---

## Why this exists

Three gaps existed before this module:

1. **Pre-analysis classification was manual.** Without an entropy map, identifying which sections of a flat firmware image were AES-encrypted versus plaintext code required inspecting sections individually. A 200 MB image took hours to orient.

2. **XOR-key boundary detection had no systematic method.** Locating the offset where an XOR-encrypted payload begins required manual offset guessing. The mapper's `scan_xor_key_boundary()` finds it automatically by detecting a sudden entropy spike.

3. **No reusable entropy output fed into taint setup.** Taint trackers need to start at plaintext code boundaries, not inside compressed sections. The `encrypted_ranges()` and `code_ranges()` methods expose those boundaries for downstream callers.

---

## Classification thresholds

| Class | Entropy range | Typical content |
|---|---|---|
| `ENCRYPTED` | H ≥ 7.2 | AES ciphertext, LZMA/squashfs, XOR-keystream output |
| `CODE` | 4.5 ≤ H < 7.2 | x86-64 or ARM64 `.text`, mixed executable regions |
| `SPARSE` | 1.5 ≤ H < 4.5 | ASCII strings, `.rodata`, sparse headers |
| `PADDING` | H < 1.5 | Null fill, `.bss`, zero-initialized regions |

---

## Detection algorithm

`EntropyMapper` slides a window of `window_size` bytes (default 256) across the binary at `step_size` intervals. For each window it computes Shannon entropy:

```
H = -Σ p_i * log2(p_i)   for every non-zero byte frequency p_i
```

Consecutive windows with the same class merge into an `EntropyRegion`. Entropy transitions larger than `threshold` bits/byte mark section boundaries.

When `numpy` is installed the mapper uses a vectorized path; it falls back to pure Python without it.

---

## Usage

```python
from ablation.analyzers.entropy_mapper import EntropyMapper

# One-shot classification
result = EntropyMapper.classify_file('/path/to/firmware.raw')
print(result.summary())

for region in result.regions:
    print(region.fmt())

# XOR-key boundary detection
mapper = EntropyMapper('/path/to/firmware.raw')
xor_start = mapper.scan_xor_key_boundary()
if xor_start is not None:
    print(f"XOR payload starts at 0x{xor_start:x}")

# Extract plaintext ranges for downstream analysis
for start, end in result.code_ranges():
    print(f"plaintext code: 0x{start:x} – 0x{end:x}")

# Finer resolution (step smaller than window)
result = EntropyMapper.classify_file('/path/to/firmware.raw', window_size=256, step_size=64)
transitions = result.find_transitions(threshold=0.5)
for t in transitions:
    print(f"0x{t.offset:x}: {t.from_cls} → {t.to_cls}  Δ={t.delta:.2f}")
```

---

## Result fields

### `EntropyRegion`

| Field | Description |
|---|---|
| `offset_start` | Byte offset where this region begins |
| `offset_end` | Byte offset where this region ends (exclusive) |
| `cls` | `ENCRYPTED` / `CODE` / `SPARSE` / `PADDING` |
| `avg_entropy` | Mean entropy across all windows in this region |
| `min_entropy` | Minimum window entropy in the region |
| `max_entropy` | Maximum window entropy in the region |
| `size` | `offset_end - offset_start` in bytes |

### `EntropyTransition`

| Field | Description |
|---|---|
| `offset` | Byte offset of the entropy change |
| `from_cls` | Class of the preceding region |
| `to_cls` | Class of the following region |
| `from_entropy` | Entropy of the window before the transition |
| `to_entropy` | Entropy of the window after the transition |
| `delta` | Absolute entropy change: `|to_entropy - from_entropy|` |

---

## Integration with firmware extraction

Run `EntropyMapper` before `FortiOSHardwareExtractor` or any taint tracker. The encrypted ranges identify partitions that need decryption before analysis proceeds. The code ranges provide the plaintext `.text` boundaries where taint sources start.

```python
from ablation.analyzers.entropy_mapper import EntropyMapper
from ablation.analyzers.fortios_firmware_extractor import FortiOSHardwareExtractor

result = EntropyMapper.classify_file('/path/to/firmware.bin')
enc_ranges = result.encrypted_ranges()
# Confirm the encrypted ranges match the expected inner partition offsets
# before decryption begins
for start, end in enc_ranges:
    print(f"encrypted: 0x{start:08x}–0x{end:08x}  ({(end-start)//1024} KB)")
```

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

## Reading output

`EntropyMapper(path).scan()` returns an `EntropyMapResult`:

| Attribute | Content |
|:---|:---|
| `path` | Path to the analyzed file |
| `file_size` | Total file size in bytes |
| `window_size` | Entropy window size used |
| `step_size` | Step size between windows |
| `windows` | `List[EntropyWindow]` — per-window entropy values |
| `regions` | `List[EntropyRegion]` — contiguous runs of the same entropy class |

Each `EntropyRegion`:

| Attribute | Content |
|:---|:---|
| `offset_start` / `offset_end` | Byte range (exclusive end) |
| `cls` | `'ENCRYPTED'` / `'CODE'` / `'SPARSE'` / `'PADDING'` |
| `avg_entropy` | Mean Shannon entropy (bits/byte) across windows in this region |
| `min_entropy` / `max_entropy` | Min/max entropy in the region |
| `size` | Property: `offset_end - offset_start` |

Call `result.find_transitions(threshold=0.5)` to get `List[EntropyTransition]` at region boundaries.

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
