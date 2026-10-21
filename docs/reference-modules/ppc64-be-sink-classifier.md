# Ppc64BeSinkClassifier

## Why this exists

3 gaps that blocked automated sink classification on PPC64 big-endian ELFv1 binaries
(IBM POWER Linux, LoadLeveler):

1. **SinkArgClassifier is x86-only.** `SinkArgClassifier.classify_all()` scans for
   `insn.mnemonic.lower() == 'call'` to find call sites.  On PPC64, the branch-with-link
 instruction is `bl`, not `call`. For any IBM POWER Linux binary the result is zero
 classifications, every strcpyx/sprintf/memcpy call site is invisibly missed.
 LL-008, LL-010, LL-011, LL-012, and LL-013 (IBM LoadLeveler) were all found by manual
 disassembly precisely because no automated per-site classifier existed.

2. **IBM C++ string allocator pattern is pervasive and mistaken for a dangerous copy.**
 IBM LoadLeveler calls `strcpyx(ibm_str_obj, int_size)` as a string heap allocator, r4
 is an integer size (or zero), not a source pointer. Without automation, every strcpyx
 call site must be manually inspected to distinguish `strcpyx(sp+N, argv_str)` (overflow)
 from `strcpyx(ibm_obj, 0x98)` (allocator, safe). The IBM allocator pattern appears 12+
 times in every LoadLeveler binary.

3. **IBM string object pass-through (mr r3, rX) hides stack-buffer destinations.**
 When r3 is set via `mr r3, rX`, the destination is often an IBM string object held in a
 saved non-volatile register (rX = r27/r28/r31, etc.). This looks identical to
   `addi r31, r1, N; mr r3, r31` (stack buffer destination) in a single-instruction view.
 Distinguishing the two requires a backward register trace through the mr chain.

---

## What it does

`Ppc64BeSinkClassifier` scans a PPC64 BE ELFv1 binary for BL calls to registered sink
stubs (strcpyx, strcatx, sprintf, memcpy, etc.), disassembles the preceding 12 instructions
at each call site, and classifies r3 (destination) and r4 (source) using these categories:

| Class | Meaning | Risk |
|---|---|---|
| `STACK_DEST` | r3 = addi r1, N: raw stack buffer address | DANGEROUS if src=ARG_PROPAGATED |
| `ARG_PROPAGATED` | r4 from ld 0(arg_reg) or ld N(arg_reg): user-controlled pointer | DANGEROUS if dest=STACK_DEST |
| `RODATA_TOC` | r4 = ld N(r2): static string from TOC | SAFE |
| `IMM_SIZE` | r3 = li rX, N (N < 0x2000): IBM string allocator size | SAFE (allocator) |
| `IMM` | li with large value | SAFE |
| `IBM_OBJECT` | r3 via mr from a callee-saved non-volatile: IBM string object | Context-dependent |
| `MR_FROM` | Intermediate: mr chain followed backward automatically | — |
| `UNKNOWN` | Cannot determine within lookback window | Needs manual trace |

Sites where `dest_class == 'STACK_DEST'` and `src_class == 'ARG_PROPAGATED'` are flagged
as `interesting = True`, the exact signature of LL-008/010/011/012/013.

---

## Usage

```python
from ablation.analyzers.ppc64_be_sink_classifier import Ppc64BeSinkClassifier

# From file path:
clf = Ppc64BeSinkClassifier.from_path('/path/to/ppc64be.elf')
results = clf.classify_all()
print(clf.report(results))

# Filter to dangerous candidates only:
dangerous = [r for r in results if r.interesting]

# With an existing BinaryContext (avoids ELF re-parse):
clf = Ppc64BeSinkClassifier.from_context(ctx)

# Classify a single sink:
sites = clf.classify_sink('strcpyx')

# Add a custom IBM sink:
clf.add_sink('IBM_sprintf', dest_pos=1, src_pos=2)
```

### Ppc64SinkSite fields

| Field | Type | Description |
|---|---|---|
| `va` | `int` | VA of the BL instruction |
| `sink_name` | `str` | e.g. `'strcpyx'` |
| `stub_va` | `int` | VA of the glink PLT stub for this sink |
| `dest_class` | `str` | r3 classification |
| `src_class` | `str` | r4 classification |
| `dest_detail` | `str` | Human-readable r3 context (e.g. `'sp+0x70'`) |
| `src_detail` | `str` | Human-readable r4 context (e.g. `'ld 0(r25) [arg reg]'`) |
| `interesting` | `bool` | `True` when dest=STACK_DEST and src=ARG_PROPAGATED |

---

## Architecture notes

**Lookback window:** 12 instructions before the BL (48 bytes) for r3/r4 register tracing.
Sufficient for IBM LoadLeveler patterns where argv-derived loads are 2-5 instructions
before strcpyx. Increase `_WINDOW` if deeper chains are needed.

**Prologue scan for NONVOL_DEREF demotion:** When a base register is a non-volatile
(r14-r31), the classifier scans the enclosing function's prologue to determine whether
that non-volatile was saved from a function argument. Function entry is found by
scanning raw bytes backward for `mflr r0` (7c 08 02 a6), bounded to 512 instructions.
`ld r4, 0(r25)` where `mr r25, r3` appears before `stdu` classifies ARG_PROPAGATED.
`ld r4, 0x250(r9)` from a C++ exception-object non-volatile classifies UNKNOWN.

**mr chain following:** When r3 or r4 is set by `mr rD, rS`, the classifier automatically
traces backward to find how rS was set. This handles the `addi r31,r1,0x70; mr r3,r31`
pattern (STACK_DEST) and the `mr r3,r28` IBM string object pattern (IBM_OBJECT or
UNKNOWN depending on r28's origin).

**TOC-relative loads:** `ld rX, N(r2)` where r2 is the TOC pointer loads a global
pointer from the TOC. These are classified RODATA_TOC for r4 (static source, safe)
but as UNKNOWN/ARG_PROPAGATED for r4 when the global itself is a user-controlled pointer
(e.g. a global job-list pointer). Manual verification needed when src=ARG_PROPAGATED
and the load is from a non-r1 non-r2 non-arg register.

**IBM string allocator detection:** `li r3, N` where N < 0x2000 is the IBM string
allocator pattern (`strcpyx(new_str, capacity)`). Classified IMM_SIZE, safe.

**PPC64 arg registers:** r3-r10 per ELFv1 ABI. r3 = first arg (dest for str*), r4 =
second arg (src), r5 = third arg (size for snprintf/memcpy).

---

## Depends on

- `Ppc64ElfV1Resolver`: for glink stub map and BL caller enumeration
- `capstone` (`CS_ARCH_PPC`, `CS_MODE_64 | CS_MODE_BIG_ENDIAN`): for per-site disassembly

## When to use

- Any PPC64 BE ELFv1 binary where `SinkArgClassifier.classify_all()` returns 0 results.
- IBM LoadLeveler, IBM GPFS, IBM AIX POWER Linux userspace binaries.
- After `Ppc64ElfV1Resolver.patch_context(ctx)` to ensure ctx.plt is populated, or as a
 standalone (it resolves the binary independently via `Ppc64ElfV1Resolver.from_path()`).
- Replaces SinkArgClassifier entirely for PPC64 BE targets: do not run both.

---

## How it works

`PPC64BESinkClassifier.classify_all()` classifies PPC64 big-endian ELFv1 sink call sites as `RODATA_CONST`, `SNPRINTF_RODATA`, `ARG_PROPAGATED`, or `UNKNOWN` — the same classification set as `SinkArgClassifier` (x86-only). On PPC64 BE, function calls use `bl` (branch-link) with the callee VA as a direct immediate, not an x86 `call` relocation. This classifier scans for `bl` instructions to PLT-resolved sinks, back-traces the argument registers (r3–r10, PPC64 ELFv1 ABI), and classifies whether the argument register holds a RODATA pointer, a format string, or a propagated function argument.

---

## Example output

```
Resolved 847 PLT entries
Recovered 312 function starts from .eh_frame
Named 28 functions from DWARF remnants

va=0x401200  name=verify_admin_token  confidence=HIGH
va=0x4015C0  name=process_http_request  confidence=HIGH
va=0x403A00  name=''  confidence=MEDIUM  (stripped)
```

---

## False positives

Symbol resolution errors produce phantom function boundaries. Verify any candidate VA against `ctx.func_starts` before analysis. Compiler-synthesized stubs (PLT entries, thunks) appear as functions in some loaders — `BinaryContext` filters known stub patterns but custom thunks may slip through.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for symbol and import resolution. For stripped binaries, run `SemanticSearcher` first to identify candidate function VAs.

**After this module:** Pass resolved call edges and function VAs to `TaintTracker` or `SinkArgClassifier`.

---

## Reading findings

`Ppc64BeSinkClassifier.from_path(path).classify_all()` returns `List[Ppc64SinkSite]`.

| Field | Type | Content |
|:---|:---|:---|
| `va` | `int` | VA of the BL instruction |
| `sink_name` | `str` | Sink function name (e.g., `strcpyx`, `sprintf`) |
| `stub_va` | `int` | VA of the glink PLT stub |
| `dest_class` | `str` | r3 (destination) classification: `STACK_DEST` / `IMM_SIZE` / `IBM_OBJECT` / `UNKNOWN` |
| `src_class` | `str` | r4 (source) classification: `RODATA_TOC` / `ARG_PROPAGATED` / `IMM` / `UNKNOWN` |
| `dest_detail` | `str` | Human-readable r3 context (e.g., `sp+0x70`) |
| `src_detail` | `str` | Human-readable r4 context (e.g., `ld 0(r25) [arg r3]`) |
| `fmt_class` | `str` | Format-string classification for sprintf/snprintf only; `CATGETS_RETURN` or empty |
| `fmt_detail` | `str` | Human-readable format-string source context |
| `interesting` | `bool` | `True` when dest=`STACK_DEST`, src=`ARG_PROPAGATED`, fmt_class != `CATGETS_RETURN` |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
