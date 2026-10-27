# EntropyAnalyzer

## Why this exists

Two things were not possible before in Ablation:

1. **Warn before running taint analysis on packed firmware.** `SemanticSearcher` and `TaintTracker` produce poor results on packed or encrypted ELF sections because the code visible to the disassembler is compressed data, not instructions. Without a pre-analysis entropy check, an analyst can spend time on a target that returns no findings. This does not mean the binary is clean: the real code is hidden inside a packed segment. `EntropyAnalyzer` runs in seconds at the start of a session and surfaces this condition before any expensive analysis begins.

2. **Identify obfuscated data regions for targeted unpacking.** High-entropy sections at non-standard addresses, or sections with entropy above 7.5 that are not `.rodata` or `.data.rel.ro`, are candidates for runtime decompression or XOR decryption. Knowing which specific VA range to focus on reduces unpacking effort from a full-image scan to a targeted extract.

## Usage

```python
from ablation.analyzers.entropy_analyzer import EntropyAnalyzer

scanner = EntropyAnalyzer('/path/to/firmware.elf')
if scanner.is_likely_packed():
    print('WARNING: packed sections detected. Unpack before analysis.')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/firmware.elf')
scanner = EntropyAnalyzer.from_context(ctx)
findings = scanner.scan()
```

To see all sections including normal ones:

```python
all_sections = scanner.scan_all()
```

## Output: EntropyFinding

Each finding contains:

| Field | Type | Description |
|-------|------|-------------|
| `section_name` | str | ELF section name |
| `va` | int | Virtual address of section start |
| `size` | int | Section size in bytes |
| `entropy` | float | Shannon entropy 0.0 to 8.0 |
| `verdict` | str | `PACKED`, `HIGH_ENTROPY`, or `NORMAL` |

## Entropy ranges

| Range | Verdict | Meaning |
|-------|---------|---------|
| 7.0 – 8.0 | `PACKED` | Likely packed, compressed, or encrypted. Analysis unreliable. |
| 6.5 – 7.0 | `HIGH_ENTROPY` | Dense code, crypto constants, or compressed data. Review before trusting analysis. |
| 0.0 – 6.5 | `NORMAL` | Standard compiled code or data. Analysis proceeds normally. |

Sections smaller than 256 bytes are excluded: short sections produce noisy entropy values.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on:
- All-zero buffer: H=0.0 correctly.
- Full 256-byte range: H=8.0 correctly.
- Random 4096 bytes: H > 7.0, verdict `PACKED`.
- ASCII text: H < 5.0, not included in `scan()` output.

## Pipeline position

**Before this module:** nothing. Run `EntropyAnalyzer` as the first step after `BinaryContext.load_or_build()`.

**After this module:** if `is_likely_packed()` returns `True`, unpack or decrypt the flagged sections before running `SemanticSearcher`, `TaintTracker`, or `SinkArgClassifier`. If all sections are normal, proceed with standard analysis.

## See also

- [BinaryContext](binary-context.md): binary loading and section metadata
- [SemanticSearcher](semantic-code-search.md): query-based search that requires decompressed code
- [ELFInternalsAndHardening](elf-internals-and-hardening.md): ELF structural anomaly detection
