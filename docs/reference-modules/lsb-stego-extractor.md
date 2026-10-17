# BMP LSB Key Extractor

**File:** `ablation/analyzers/lsb_stego_extractor.py`

Recovers cryptographic key material hidden in BMP pixel LSBs using a Shamir-style Lagrange polynomial secret-sharing scheme. Firmware and APK packages that conceal keys in image assets are handled without prior knowledge of the encoding.

Built from two confirmed findings where FortiAnalyzer and FortiManager embedded per-session key components in bundled BMP images. No other public scanner detected the class.

---

## Why this exists

Three things were not possible before this module:

1. **LSB steganography in firmware was undetected.** Binaries that load a BMP asset and recover key material from its pixel stream left no obvious string or API footprint. The pattern, seed hash → pixel offset → LSB channel → Lagrange reconstruction: the pattern appeared in stripped ARM32 `.so` libraries with no prior public analysis.

2. **Lagrange interpolation over multi-prime CRT was manual.** Reconstructing the secret required identifying the coordinate pairs in the LSB channel, building the polynomial, and running exact rational arithmetic. This module automates the full pipeline with a stdlib-only implementation (no sympy).

3. **The byte-order and sign-handling were undocumented.** The key output uses `imath mp_int_to_binary` semantics: little-endian, with a non-standard reverse-TC transformation for negative polynomial values. Without this module, matching the output of the producing library required per-engagement trial and error.

---

## Encoding scheme

The firmware encodes key material in a BMP file as follows:

1. Hash a seed string to a pixel offset in the BMP.
2. Read `type_count` and `n_groups` from the LSB channel at that offset.
3. Build `type_count × n_groups` coordinate pairs (x, y) from consecutive LSB-encoded hex fields.
4. For each of `type_count` key components: run Lagrange interpolation at x=0 over `n_pts = n_groups // type_count` points, using multi-prime CRT for exact integer arithmetic.
5. Output each component as a hex string in little-endian byte order, with the reverse-TC transformation applied to negative values.

---

## Usage

```python
from ablation.analyzers.lsb_stego_extractor import BmpKeyExtractor

ext = BmpKeyExtractor('/path/to/asset.bmp')
result = ext.extract('MySeedString')

# Full concatenated key
print(result.raw_key_hex)

# Individual components
for i, component in enumerate(result.components):
    print(f"component {i}: {component}")

# Verify against known key material
assert result.raw_key_hex == expected_hex, "Key extraction mismatch"
```

---

## Result fields (`KeyExtractionResult`)

| Field | Description |
|---|---|
| `raw_key_hex` | Concatenated hex string of all key components |
| `components` | `list[str]`: individual key component hex strings |
| `type_count` | Number of key components encoded |
| `n_groups` | Number of coordinate-pair groups |
| `coord_pairs` | `list[CoordPair]`: raw (x, y) coordinate pairs read from the LSB channel |
| `seed` | Seed string used to locate the pixel offset |
| `pixel_offset` | Byte offset in the BMP pixel data where the encoding begins |

---

## Algorithm details

### Pixel offset from seed

The seed string is hashed (SHA-256) and reduced modulo the BMP pixel data length, aligned to a 4-byte boundary. This gives a deterministic starting offset.

### Lagrange interpolation

For each key component, the extractor takes `n_pts` coordinate pairs and evaluates:

```
f(0) = Σ y_i * Π (0 - x_j) / (x_i - x_j)   for j ≠ i
```

The interpolation runs over exact rational arithmetic using multi-prime CRT to avoid floating-point error. The prime set (8 primes at 63 bits each) is sufficient for the key sizes observed in the Fortinet firmware corpus.

### Output encoding

Positive polynomial values encode as standard little-endian bytes. 
Negative values apply a reverse two's-complement transformation matching the `imath mp_int_to_binary` path in the producing library.

---

## Known targets

- FortiAnalyzer 7.x (ARM32 management daemon): two CRITICAL findings
- FortiManager 7.x (ARM32 policy daemon): one CRITICAL finding

Key material recovered: per-session encryption keys stored in BMP assets bundled with the application package. No other scanner in the Ablation corpus detected this class before this module was built.

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

`PrimeCoordExtractor(bmp_path).extract(seed, n_primes=8)` returns a `StegoKeyResult`:

| Attribute | Content |
|:---|:---|
| `seed` | The seed string used for extraction |
| `type_count` | Number of distinct component types extracted |
| `n_groups` | Number of coordinate groups |
| `n_pts` | Total number of points read |
| `components` | `List[str]` — each component as a hex string |
| `raw_key_hex` | Hex string of all components concatenated |

Use `result.fmt()` for a human-readable multi-line summary including per-component hex excerpts.

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
