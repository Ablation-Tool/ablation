# ELFAnomalyScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Detect ELF structural anomalies that indicate packing, manual construction, or shellcode injection.** `BuildIntegrityAnalyzer` checks hardening flags. `EntropyAnalyzer` checks section entropy. Neither checks whether the ELF structure itself is internally consistent. `ELFAnomalyScanner` runs six structural checks using LIEF and flags properties that no legitimate compiler produces: sections extending past end-of-file, entry points outside any mapped segment, zero-size executable PT_LOAD segments, overlapping sections, multiple PT_INTERP segments, and extreme section-to-segment count ratios.

## Usage

```python
from modules.elf_anomaly_scanner import ELFAnomalyScanner

scanner = ELFAnomalyScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = ELFAnomalyScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: ELFAnomalyFinding

| Field | Type | Description |
|-------|------|-------------|
| `check` | str | Check name (see table below) |
| `detail` | str | Human-readable description with addresses |
| `severity` | str | `HIGH`, `MEDIUM`, or `LOW` |

## Checks performed

| Check | Severity | What it detects |
|-------|----------|-----------------|
| `section_past_eof` | HIGH | `sh_offset + sh_size > filesize` — section claims to extend beyond the file |
| `zero_size_exec_load` | HIGH | PT_LOAD+X with `p_filesz == 0` — executable segment with no file backing (shellcode pattern) |
| `ep_outside_load` | HIGH | Entry point VA is not inside any PT_LOAD segment — binary will fault at startup normally |
| `multiple_pt_interp` | MEDIUM | More than one PT_INTERP segment — seen in custom loaders |
| `overlapping_sections` | MEDIUM | Two sections whose file ranges overlap each other |
| `section_segment_mismatch` | LOW | Section count is more than 10x the segment count or vice versa |

## Notes

Non-ELF inputs (PE, raw shellcode, `/dev/null`) return an empty finding list immediately after the magic byte check.

LIEF may silently normalize some malformed ELF inputs before presenting them to the checks. If a binary fails the magic check but you expect ELF anomalies, read the raw bytes directly rather than via LIEF.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on a real ELF (Python interpreter): returns findings without crashing.

## See also

- [AntiAnalysisStringDetector](anti-analysis-string-detector.md): tool-name checklists in rodata
- [EntropyAnalyzer](entropy-analyzer.md): packed section detection via Shannon entropy
- [BuildIntegrityAnalyzer](build-integrity-analyzer.md): PIE, stack canary, NX, RELRO
