# PPC32 Function Discovery

## Overview

Discovers function entry points in PowerPC 32-bit big-endian binaries, including stripped binaries with no section headers.

**Target use case**: AIX diagnostics, VxWorks firmware, embedded PowerPC systems where `.eh_frame` and symbol tables are absent.

## How it works

Three-pass discovery:

1. **Entry point** — from ELF header
2. **Branch targets** — scan for `bl` (branch-and-link) and `bla` (branch-and-link-absolute) instructions
3. **Prologue patterns** — standard PowerPC function prologues:
   - `mflr r0; stw r0, X(r1); stwu r1, -Y(r1)` (full prologue)
   - `stwu r1, -<frame>(r1)` (leaf/frameless functions)

## Why not XRefGraph?

XRefGraph currently only supports x86-64, ARM32, and ARM64. PowerPC e_machine (20) defaults to x86-64, producing incorrect results.

## Usage

```python
from ablation.analyzers.ppc32_func_discovery import PPC32FuncDiscovery

disc = PPC32FuncDiscovery.from_path('/path/to/ppc32.elf')
func_starts = disc.discover()

print(disc.report(func_starts))
```

### CLI

```bash
python3 -m ablation.analyzers.ppc32_func_discovery <elf_file>
```

## API

### Class: `PPC32FuncDiscovery`

#### `from_path(path: str) -> PPC32FuncDiscovery`

Load from ELF file. Reads the main LOAD segment containing the entry point directly from file offset (bypasses lief's section-header dependency).

#### `discover() -> Set[int]`

Returns set of function start VAs.

#### `report(func_starts: Set[int]) -> str`

Generates human-readable discovery report.

### Function: `discover_ppc32_functions(elf_path: str) -> Set[int]`

Convenience wrapper — one-call discovery.

## Limitations

- **Big-endian only** — little-endian PPC (PlayStation 3) not tested
- **32-bit only** — use `taint_tracker_ppc64.py` prologue patterns for 64-bit
- **ELF only** — XCOFF (AIX native format) requires separate parser

## Tested on

- IBM AIX 7.2.0.0 Diagnostics (cd7200_bootfile.exe): 18,919 functions discovered
- PowerPC ELF with no section headers

## Integration with other ablation tools

Pass discovered function starts to:
- `PPC32TaintTracker.from_path()` — already has built-in prologue discovery
- `XRefGraph.build(func_starts=...)` — when PPC32 support is added

## Future work

1. Add PPC32 arch detection to `xref_graph.py` (e_machine == 20)
2. Integrate this discovery into `XRefGraph._build_call_graph()`
3. Add XCOFF format support for native AIX binaries

## References

- PowerPC ISA: Branch instructions (BO/BI encoding)
- AIX ABI: Standard prologue/epilogue conventions
- IBM CHRP boot specification
