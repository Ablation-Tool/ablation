# BuildProvenanceExtractor

## Why this exists

One thing was not possible before in Ablation:

1. **Extract compiler, linker, and libc provenance from stripped binaries.** Firmware images often have no version strings, but the compiler always writes provenance into the binary even in release builds. `SBOMExtractor` sweeps for library version strings. No prior module focused on build toolchain provenance: GCC/Clang version from `.comment`, linker from its own version string, build-ID from `.note.gnu.build-id`, and libc from the dynamic linker path. `BuildProvenanceExtractor` collects these into a structured result. The build-ID alone lets you fetch the matching debuginfo package from a distribution's dbgsym repository, recovering function names for a nominally stripped binary.

## Usage

```python
from modules.build_provenance_extractor import BuildProvenanceExtractor

extractor = BuildProvenanceExtractor('/path/to/binary')
result = extractor.extract()
print(extractor.report(result))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
extractor = BuildProvenanceExtractor.from_context(ctx)
result = extractor.extract()
```

## Output: BuildProvenanceResult

| Field | Type | Description |
|-------|------|-------------|
| `compiler` | str | Compiler name and version, e.g. `GCC 12.2.0` |
| `compiler_detail` | str | Distro-specific compiler build tag |
| `linker` | str | Linker name and version, e.g. `GNU ld 2.40` |
| `build_id` | str | GNU build-ID hash (hex) |
| `libc` | str | `glibc`, `musl`, `uclibc`, or `Android` |
| `dynlinker` | str | Full dynamic linker path |
| `target_arch` | str | `x86_64`, `aarch64`, `mips`, etc. |
| `build_timestamp` | str | PE header timestamp (Unix seconds) if present |

## Detection sources

**Compiler:** 6 patterns covering GCC, Clang, ICC, MSVC, ARM Compiler, IAR.

**Linker:** 4 patterns covering GNU ld, LLD, gold, mold.

**Libc:** dynamic linker path matched against `ld-linux`, `ld-musl`, `ld-uClibc`, `/system/bin/linker` (Android).

**Build-ID:** `.note.gnu.build-id` SHA-1 or MD5 hash.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on:
- Synthetic ELF with `GCC: (Debian 12.2.0-14) 12.2.0` in data: `compiler='GCC 12.2.0'`, `arch='x86_64'`, `libc='glibc'` all extracted correctly.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** use `build_id` with `debuginfod-find debuginfo <build_id>` to fetch matching debug symbols. Feed `compiler` into `SBOMExtractor` as a toolchain component entry.

## See also

- [BuildIntegrityAnalyzer](build-integrity-analyzer.md): hardening flag analysis
- [SBOMExtractor](sbom-extractor.md): library and toolchain SBOM
- [BinaryContext](binary-context.md): ELF metadata access
