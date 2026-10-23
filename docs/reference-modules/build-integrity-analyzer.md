# BuildIntegrityAnalyzer

## Why this exists

One thing was not possible before in Ablation:

1. **Report build hardening as structured findings with severity.** `BinaryContext` exposes raw ELF metadata. No prior module translated ELF segment flags and dynamic entries into a scored hardening report. `BuildIntegrityAnalyzer` checks PIE, stack canary, NX, RELRO, and FORTIFY_SOURCE for ELF binaries, and ASLR, DEP, and CFG for PE binaries, then assigns HIGH/MEDIUM/LOW severity to each absent feature.

## Usage

```python
from modules.build_integrity_analyzer import BuildIntegrityAnalyzer

analyzer = BuildIntegrityAnalyzer('/path/to/binary')
findings = analyzer.scan()
print(analyzer.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
analyzer = BuildIntegrityAnalyzer.from_context(ctx)
findings = analyzer.scan()
```

## Output: HardeningFinding

| Field | Type | Description |
|-------|------|-------------|
| `feature` | str | Feature name such as `PIE`, `Stack canary`, `Full RELRO` |
| `status` | str | `PRESENT`, `ABSENT`, or `PARTIAL` |
| `severity` | str | `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `note` | str | Evidence or explanation |

## ELF checks

| Feature | Detection method | Absent severity |
|---------|-----------------|----------------|
| PIE | `ELF header e_type == ET_DYN` | HIGH |
| Stack canary | `__stack_chk_fail` in PLT | HIGH |
| NX | `PT_GNU_STACK` execute bit clear | HIGH |
| Full RELRO | `PT_GNU_RELRO` + `BIND_NOW` | MEDIUM |
| Partial RELRO | `PT_GNU_RELRO` without `BIND_NOW` | MEDIUM |
| FORTIFY_SOURCE | `__*_chk` variants in PLT | LOW |

## PE checks

| Feature | Detection method | Absent severity |
|---------|-----------------|----------------|
| ASLR | `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` | HIGH |
| DEP/NX | `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` | HIGH |
| CFG | `IMAGE_DLLCHARACTERISTICS_GUARD_CF` | MEDIUM |

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** absent `Stack canary` makes `TaintTracker` stack-overflow findings exploitable without needing to bypass a canary. Absent `Full RELRO` makes GOT overwrites viable for any write primitive. Use these results to prioritize which findings need full exploit chains.

## See also

- [BuildProvenanceExtractor](build-provenance-extractor.md): compiler toolchain recovery
- [SBOMExtractor](sbom-extractor.md): library version detection
- [TaintTracker](taint-analysis.md): stack-overflow trace analysis
