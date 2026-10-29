# WindowAnalyzer

**File:** `ablation/analyzers/window_analyzer.py`

Disassembles a configurable byte window centered on any virtual address and annotates each instruction with its PLT call target and `.rodata` string reference. One call returns a formatted text block that an LLM can pattern-match in a single pass.

Supports x86_64, x86_32, ARM32, ARM64, PPC32, PPC64, and PPC64LE (ELFv2).

---

## Why this exists

Three things were not possible before this module:

1. **Per-instruction disassembly fragmented LLM context across dozens of round trips.** Each call returned one instruction so a 1536-byte window required 100 to 200 calls before any analysis could begin.

2. **Call targets in stripped binaries appeared as hex addresses.** The module resolves PLT stubs at load time so `call 0x3000` becomes `call 0x3000 ; PLT -> malloc` without a second lookup.

3. **Function boundaries were invisible inside a window.** The module marks `endbr64` patterns on x86_64 and push-LR prologues on ARM so the LLM knows where functions start without running a separate boundary detector.

---

## Usage

```python
from ablation.analyzers.window_analyzer import WindowAnalyzer

wa = WindowAnalyzer.from_path('/path/to/binary')

# Annotated instruction list
lines = wa.dump(va=0x41366, window=1536)

# Formatted text block
text = wa.dump_text(va=0x41366, window=1536)

# Include context before the target VA
text = wa.dump_text(va=0x41366, window=1536, align_back=256)

# Find function start candidates in the window
starts = wa.find_func_starts(va=0x41366, window=1536)

# All call sites in the window
calls = wa.calls_in_window(va=0x41366, window=1536)
# returns list of (call_site_va, target_va, label)
```

Output format per instruction:

```
0x41366: call     0x3000          ; PLT -> malloc
0x41371: lea      rdi, [rip+0x..] ; "error loading cli context"
0x41290: endbr64                  ; [FUNC_START]
```

---

## PPC64LE ELFv2 PLT resolution

On PPC64LE ELFv2 binaries the PLT section is NOBITS at runtime. Callers branch to stubs embedded in `.text`. Each stub follows this four-instruction pattern:

```
std  r2, 0x18(r1)    ; save TOC pointer
ld   r12, OFF(r2)    ; load function pointer from GOT via TOC-relative offset
mtctr r12            ; move pointer to CTR
bctr                 ; branch
```

`WindowAnalyzer` detects this pattern by scanning `.text` for `ld r12, OFF(r2)` preceded by `std r2, 0x18(r1)`. It computes the GOT slot address as `TOC_BASE + displacement` where `TOC_BASE = .got_va + 0x8000` per the ELFv2 ABI. It then matches the GOT slot against the relocation table to recover the symbol name.

The arch is detected from the ELF header: `e_machine == 21` EM_PPC64 with `EI_DATA == 1` little-endian maps to `ppc64le`. `EI_DATA == 2` big-endian maps to `ppc64` and uses the existing BSS PLT resolver.

**Known limitation.** The `std r2 + ld r12` pattern could appear in non-stub code that saves the TOC and loads a function pointer from the GOT. The GOT-slot-to-symbol gate limits false positives because the slot must match a known relocation entry.

**Known limitation.** `bctrl` indirect calls are not annotated in `dump()` output. Direct `bl` calls to stub VAs are annotated.

---

## Annotation rules

| Instruction | Annotation |
|---|---|
| `call` / `bl` to a known PLT stub VA | `PLT -> symbol_name` |
| `call` / `bl` to a known string VA | `-> "string content"` |
| `lea` / `mov` with `[rip+disp]` pointing to a string | `"string content"` |
| `endbr64` (x86_64) | `[FUNC_START]` |
| `push` / `stp` saving `lr` or `x29` (ARM) | `[FUNC_START?]` |

---

## Supported architectures

| `_elf_arch` value | ELF `e_machine` | Capstone mode |
|---|---|---|
| `x86_64` | 62 EM_X86_64 or default | CS_ARCH_X86 + CS_MODE_64 |
| `x86_32` | 3 (EM_386) | CS_ARCH_X86 + CS_MODE_32 |
| `arm64` | 183 EM_AARCH64 | CS_ARCH_ARM64 + CS_MODE_ARM |
| `arm32` | 40 (EM_ARM) | CS_ARCH_ARM + CS_MODE_ARM |
| `ppc32` | 20 (EM_PPC) | CS_ARCH_PPC + CS_MODE_32 + CS_MODE_BIG_ENDIAN |
| `ppc64` | 21 EM_PPC64, big-endian | CS_ARCH_PPC + CS_MODE_64 + CS_MODE_BIG_ENDIAN |
| `ppc64le` | 21 EM_PPC64, little-endian | CS_ARCH_PPC + CS_MODE_64 + CS_MODE_LITTLE_ENDIAN |

---

## Legacy ARM32 and bFLT support

Legacy 32-bit ARM uses `.rel.plt` with 8-byte relocation records. The ARM resolver maps those records to the 20-byte PLT resolver followed by 12-byte stubs. A `JUMP_SLOT` fallback covers images without a normal PLT layout. A1676 now recovers all 39 of its PLT symbols.

`calls_in_window()` collects direct calls while disassembling instead of trying to parse formatted text. This is what makes ARM `bl` operands usable: the C111C comparison call at `0x1788` and A1676's `0x10980 -> 0x10D38` call are returned with their actual targets. Register-indirect destinations are not invented.

ARM32 literal loads can annotate strings by computing the PC-relative literal address, reading a bounded 32-bit pointer, and checking it against the string map. ARM32 `skipdata` allows a window to continue through inline literal pools, but valid-looking data can still be decoded as instructions and needs review.

The address map comes from `pyelftools` rather than repeated LIEF parsing or section access. This removes the legacy A1676 crash while retaining bounds checks. LIEF remains available for symbol and relocation extraction.

For a relocated bFLT image, construct `BfltBinaryContext` first and call `WindowAnalyzer.from_bflt(ctx)`. The window then uses the adapter's text bounds, strings, and load base instead of treating bFLT as ELF. Relocated strings can differ from their stored file targets, so link-time and runtime evidence should not be conflated.

---

## Assumptions and failure modes

**Assumption: lief is installed.** Without lief, PLT and string maps are empty so instructions disassemble without annotations. Capstone is still used for disassembly.

**Assumption: ELFv2 TOC_BASE follows the ABI convention.** `TOC_BASE =.got_va + 0x8000`. Vendor-modified firmware that deviates from the ABI will produce incorrect GOT slot addresses and miss PLT entries.

**Assumption: `.rela.plt` or relocation entries are present.** Stripped binaries with no dynamic symbol information produce empty PLT maps.

**Scan bound.** The PPC64LE `.text` scanner iterates every word in `.text`. On a binary with a 10 MB `.text` section this is approximately 2.5 million iterations. This is a one-time build cost at `WindowAnalyzer.from_path()` time.

---

## FORGE status

Gate: **PASS**. No CRITICAL or HIGH findings. Legacy ARM PLT recovery, typed direct calls, bounded literal annotation, and bFLT-backed windows are covered. Register-indirect targets such as `bctrl` remain unresolved rather than being assigned invented destinations.

---

## How it works

`WindowAnalyzer.dump_textva, window` extracts `window` bytes centered on `va`, disassembles the range with Capstone x86-64 or ARM64 based on binary architecture, resolves PLT call targets to their names, and annotates `.rodata` string references inline. Returns a list of annotated disassembly lines for LLM or manual analysis. Not a scanner: produces no findings.

---

## Example output

```
0x00401f20 <handle_request+0x20>:
  push   rbp
  mov    rbp, rsp
  sub    rsp, 0x110
  mov    rdi, QWORD PTR [rbp-0x108]   ; arg_0
  call   0x4030a0 <recv@plt>           ; recv(sock, buf, len, flags)
  test   rax, rax
  js     0x401f48
  lea    rdi, [rip+0x20840]            ; "User: %s\n"  (.rodata:0x6040e0)
  call   0x4031b0 <printf@plt>
```

---

## False positives

Not applicable: `WindowAnalyzer` is a display tool, not a scanner. It produces disassembly context for human/LLM review, not structured findings.

---

## Pipeline position

**Before this module:** `SemanticSearcher.query()` and `FuncProfiler.profile()` to identify a candidate VA. `SinkArgClassifier` and `TaintTracker` should be exhausted first: use `WindowAnalyzer` only when automated tools have no configured sink for the pattern.

**After this module:** Manual or LLM analysis of the disassembly window. Identify the taint path and feed back into `TaintTracker` by configuring the new sink pattern.

---

## Reading output

`WindowAnalyzer.from_bflt(ctx).dump_text(va, window=1536, align_back=0)` returns a formatted string block: a disassembly listing with annotations from a relocated bFLT context. `WindowAnalyzer.from_path(path)` handles ELF input. There is no typed finding dataclass; output is text for manual analysis.

Use the helper methods to extract structured data from the window:

| Method | Returns |
|:---|:---|
| `find_func_startsva, window` | `List[int]`: VAs of `[FUNC_START]` entries in the window |
| `calls_in_windowva, window` | `List[Tuple[int, int, str]]`: `call_site_va, target_va, label` for each call |
| `dumpva, window, align_back` | `List[str]`: individual annotated disassembly lines |

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
