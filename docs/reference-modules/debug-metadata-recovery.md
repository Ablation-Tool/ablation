# Debug Metadata Recovery

Recover function boundaries, names, and type information from `.eh_frame` CFI records, DWARF `.debug_info`, and Linux BTF `.BTF`/`.BTF.ext` sections in ELF binaries — providing precise `(start, end)` function intervals and names even when `.symtab` is stripped, for LoongArch64 and all other ELF targets.

---

## Why this exists

1. **Stripped ELF binaries drop `.symtab` but typically retain `.eh_frame` CFI records emitted by GCC/Clang for C++ exception unwinding — these records contain precise function start VAs as FDE (Frame Description Entry) entries.** `DwarfLoongArch64.function_starts_from_eh_frame()` extracts all FDE start addresses, providing function boundaries without the noise of prologue-scan heuristics. On a typical stripped firmware binary, `.eh_frame` yields function start accuracy of 99%+ versus prologue scan's ~85%.

2. **`.debug_info` sections (present in `-g` builds) provide `(name, low_pc, high_pc)` triples via `DW_TAG_subprogram`** — `high_pc` eliminates the "next-function-start" approximation that `.eh_frame` alone requires. When `.debug_info` is present (common in development firmware images or partial debug builds), `DwarfLoongArch64.function_intervals_from_dwarf()` yields precise function end addresses, enabling accurate function-size calculations and loop detection.

3. **Linux kernel modules stripped of `.symtab` often retain `.BTF` and `.BTF.ext` sections** — BTF maps section offsets to function names even without symbol tables, enabling name recovery for kernel modules and eBPF programs where DWARF is absent. `DwarfLoongArch64.names_from_btf()` parses the BTF string and type sections without external dependencies (pure struct parsing, no libbpf required).

---

## How it works

```mermaid
flowchart TD
    A["DwarfLoongArch64(elf_path)"] --> B["function_starts_from_eh_frame() → Set[int]\n  Parse .eh_frame with pyelftools CIE/FDE decoder\n  Extract pc_begin from each FDE\n  Best-effort: returns empty set if section absent"]
    A --> C["function_intervals_from_dwarf() → List[Tuple[int,int,str]]\n  Parse .debug_info DW_TAG_subprogram\n  Extract (low_pc, high_pc, name)\n  Requires -g build; returns [] if .debug_info absent"]
    A --> D["names_from_btf() → Dict[int,str]\n  Parse .BTF type section (BTF_KIND_FUNC)\n  Parse .BTF.ext for func_info VA→name mapping\n  Pure struct parsing, no libbpf\n  Returns {} if .BTF absent"]
    B --> E["inject_into_context(ctx) → int\n  Add all recovered starts to BinaryContext.func_starts\n  Returns: count of new starts added"]
    C --> E
    D --> F["ctx.set_name(va, name, source='dwarf') for DWARF names\n  ctx.set_name(va, name, source='btf') for BTF names"]

    G["I386AbsoluteXrefScanner\n  (i386 ELF32 string reference recovery)"] --> H["scan_full() → XrefResult\n  Scan .text for 4-byte LE values matching known string VAs\n  Attribute hits to enclosing function\n  ELF32 only — PE32 not supported"]
    H --> I["inject(ctx) → int\n  Add discovered xrefs to BinaryContext\n  Returns: count of new xrefs added"]
```

---

## Usage

```python
from ablation.analyzers.dwarf_loongarch64 import DwarfLoongArch64
from ablation.analyzers.i386_absolute_xref_scanner import I386AbsoluteXrefScanner
from ablation.analyzers.binary_context import BinaryContext

# ── ELF64 debug metadata (eh_frame / DWARF / BTF) ──────────────────────────
ctx = BinaryContext.load_or_build('/path/to/target.elf')
dwarf = DwarfLoongArch64('/path/to/target.elf')

n_starts = dwarf.inject_into_context(ctx)
print(f"Added {n_starts} function starts from eh_frame/DWARF")

# Recover names from BTF (kernel modules)
btf_names = dwarf.names_from_btf()
for va, name in btf_names.items():
    ctx.set_name(va, name, source='btf')

# Recover debug intervals if available
intervals = dwarf.function_intervals_from_dwarf()
for low_pc, high_pc, name in intervals:
    ctx.set_name(low_pc, name, source='dwarf')

# ── i386 string xref recovery ──────────────────────────────────────────────
ctx32 = BinaryContext.load_or_build('/path/to/target32.elf')
xref_scanner = I386AbsoluteXrefScanner.from_context(ctx32)
result = xref_scanner.scan_full()
n_xrefs = xref_scanner.inject(ctx32)
print(f"Added {n_xrefs} i386 string xrefs")
print(result.report())
```

---

## Example output

The following illustrates the recovery output format. Actual counts and names are binary-specific.

```
DwarfLoongArch64 (.eh_frame):
  FDE entries found: <N>
  Function starts added to context: <M>  (net new)

DwarfLoongArch64 (.BTF):
  BTF functions found: <N>
  Names set in context: <N>

I386AbsoluteXrefScanner:
  Strings in .rodata: <N>
  Xrefs found: <M>  (vs <K> from RIP-relative scanner)
  Xrefs added to context: <M>
```

---

## False positives

**`.eh_frame` FDE start addresses include exception landing pads that are not function entry points.** These appear as spurious starts within function bodies. Filter by checking whether the FDE start is within an existing known-function interval (i.e., it would overlap a function already in `ctx.func_starts`).

**`I386AbsoluteXrefScanner` may report false positives for 4-byte LE values in the code stream that coincidentally match a string VA but are operands to instructions where the value is not a pointer.** The false-positive rate is low for typical binaries but increases when `.rodata` is small and the VA space is densely populated.

---

## Pipeline position

Run debug metadata recovery immediately after `BinaryContext.load_or_build()` on any target binary — before `CorpusBuilder`, `SemanticSearcher`, or taint analysis. Better function boundaries and more string xrefs improve all downstream analyses. The `inject_into_context()` methods modify the context in place.

---

## Reading output

`ARM32FunctionScanner.inject_into_context(ctx)` modifies `ctx.func_starts` in place and returns:

| Field | Content |
|:---|:---|
| `added` | Count of new function starts added to `ctx` |
| `existing` | Count of function starts already in `ctx` (from symbols or prior analysis) |

`I386AbsoluteXrefScanner.inject_into_context(ctx)` modifies `ctx.xrefs` in place and returns:

| Field | Content |
|:---|:---|
| `xrefs_added` | Count of new cross-references added |

---

## See also

- [ARM32 Allocation Arithmetic Overflow](arm32-allocation-arithmetic-overflow.md) — `ARM32FunctionScanner` prologue scan for ARM32 stripped binaries
- [Function Corpus Builder](function-corpus-builder.md) — uses function starts recovered here for corpus population
- [PPC32/PPC476 Dedicated Lifting](ppc32-ppc476-dedicated-lifting.md) — PPC64 ELFv1 resolver that also patches BinaryContext
