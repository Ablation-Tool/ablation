# i386 Stripped Static Binary Function Discovery

Discover function starts in stripped statically-linked i386 ELF binaries: where neither `.symtab` nor `.dynsym` are populated: using primary `push ebp; mov ebp, esp` prologue pattern scan and a `call`-target fallback for `-fomit-frame-pointer` compiled functions.

---

## Why this exists

1. **`lief` populates `BinaryContext.func_starts` only from `.symtab` / `.dynsym` symbol table entries.** Statically linked stripped i386 ELF binaries common in legacy network firmware, VxWorks images, and old Linux daemons compiled with `strip --strip-all` have neither table populated. Without `func_starts`, `SemanticSearcher`, `TaintTracker`, and `SinkArgClassifier` cannot run.

2. **The primary CDECL prologue `55 89 e5`: `push ebp; mov ebp, esp` is present in ~95% of GCC-compiled i386 functions**, it is the most reliable function start indicator in stripped i386 binaries. `StaticELF32FuncStartScanner.scan()` finds all occurrences of this byte sequence in executable segments (`PT_LOAD + PF_X`) as the primary method.

3. **`inject(ctx)` patches the discovered starts directly into `BinaryContext.func_starts`**: after injection, the full Ablation analysis pipeline runs normally on the previously unanalyzable stripped binary. `scan_full()` returns a `ScanResult` with primary/secondary/call-target counts for diagnostic purposes.

---

## How it works

```mermaid
flowchart TD
    A(["StaticELF32FuncStartScanner.from_path(elf_path)\n  or .from_context(ctx)"]):::input --> B["scan() → List[int]\n  For each PT_LOAD + PF_X segment:\n    Primary scan: 55 89 e5 (push ebp; mov ebp, esp)\n      ~95% of CDECL functions\n    Secondary scan: 55 57 56 (push ebp; push edi; push esi)\n      callee-save without frame setup\n    Call-target fallback: scan for CALL rel32 (0xe8)\n      Collect all call targets not already in starts\n  Return sorted unique start addresses"]:::primary
    B:::primary --> C(["scan_full() → ScanResult\n  primary_count: int\n  secondary_count: int\n  call_target_count: int\n  starts: List[int]\n  report() → str"]):::output
    B:::primary --> D(["inject(ctx: BinaryContext) → int\n  ctx.func_starts.extend(scan())\n  ctx.func_starts.sort() + dedup\n  Returns: count of new starts added"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from ablation.analyzers.static_elf32_func_start_scanner import StaticELF32FuncStartScanner
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/stripped_i386_binary')

if not ctx.func_starts:
    print("No function starts from ELF symbols — running prologue scan")
    scanner = StaticELF32FuncStartScanner.from_context(ctx)
    n_injected = scanner.inject(ctx)
    print(f"Injected {n_injected} function starts")

    # Diagnostic breakdown
    result = scanner.scan_full()
    print(result.report())

# Now SemanticSearcher and TaintTracker work normally
from ablation.analyzers.semantic_search import SemanticSearcher
searcher = SemanticSearcher.from_context(ctx)
searcher.build_corpus()
```

---

## Example output

The following illustrates the function start discovery output format. Actual counts are binary-specific.

```
StaticELF32FuncStartScanner: stripped_i386_binary  (i386, stripped, static)

func_starts before injection: 0  (no .symtab/.dynsym)

Scan results:
  Primary   (55 89 e5):   <A> functions
  Secondary (55 57 56):   <B> functions
  Call-target fallback:   <C> functions

Total injected: <N>  (deduplicated)

func_starts after injection: <N>
```

---

## False positives

**Prologue byte patterns in data sections**: the byte sequence `55 89 e5` can appear in data constants by coincidence. `StaticELF32FuncStartScanner` scans only `PT_LOAD + PF_X` executable segments, which reduces but does not eliminate data false positives. Functions starting at misidentified addresses will produce garbled `FuncProfiler` output, these are detectable because they decode as invalid instruction sequences.

**Call-target fallback may identify data pointers as function starts**: a `call` instruction with a 32-bit relative offset into a non-code region. Use `scan_full()` to check call-target counts; a suspiciously high count relative to primary+secondary counts suggests data-region pollution.

---

## Pipeline position

Run `StaticELF32FuncStartScanner.inject()` immediately after `BinaryContext.load_or_build()` when `ctx.func_starts` is empty on a known stripped static i386 binary. This step is a prerequisite for all subsequent analysis.

---

## Reading output

`StaticELF32FuncStartScanner.scan()` returns `List[int]`: sorted VA list of discovered function entry points.

`StaticELF32FuncStartScanner.scan_full()` returns a `ScanResult`:

| Attribute | Content |
|:---|:---|
| `path` | Path to the scanned binary |
| `starts` | `List[int]`: sorted function entry VAs |
| `patterns_used` | `List[str]`: prologue pattern names that produced matches |
| `segment_count` | Number of executable segments scanned |

`StaticELF32FuncStartScanner.inject(ctx)` calls `scan()` and writes the starts directly to `ctx.func_starts`, returning the count injected. Only runs when `ctx.func_starts` is empty, it does not overwrite existing `eh_frame` data.

---

## See also

- [Persistent Analysis Context](persistent-analysis-context.md): `BinaryContext.func_starts` that this scanner populates
- [Debug Metadata Recovery](debug-metadata-recovery.md): `I386AbsoluteXrefScanner` for ELF32 absolute cross-reference injection
- [Generic Vulnerability Profile Sweeps](generic-vulnerability-profile-sweeps.md): `SemanticSearcher` that requires `func_starts`
