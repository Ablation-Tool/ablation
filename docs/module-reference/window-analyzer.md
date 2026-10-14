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

The arch is detected from the ELF header: `e_machine == 21` (EM_PPC64) with `EI_DATA == 1` (little-endian) maps to `ppc64le`. `EI_DATA == 2` (big-endian) maps to `ppc64` and uses the existing BSS PLT resolver.

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
| `x86_64` | 62 (EM_X86_64) or default | CS_ARCH_X86 + CS_MODE_64 |
| `x86_32` | 3 (EM_386) | CS_ARCH_X86 + CS_MODE_32 |
| `arm64` | 183 (EM_AARCH64) | CS_ARCH_ARM64 + CS_MODE_ARM |
| `arm32` | 40 (EM_ARM) | CS_ARCH_ARM + CS_MODE_ARM |
| `ppc32` | 20 (EM_PPC) | CS_ARCH_PPC + CS_MODE_32 + CS_MODE_BIG_ENDIAN |
| `ppc64` | 21 (EM_PPC64), big-endian | CS_ARCH_PPC + CS_MODE_64 + CS_MODE_BIG_ENDIAN |
| `ppc64le` | 21 (EM_PPC64), little-endian | CS_ARCH_PPC + CS_MODE_64 + CS_MODE_LITTLE_ENDIAN |

---

## Assumptions and failure modes

**Assumption: lief is installed.** Without lief, PLT and string maps are empty so instructions disassemble without annotations. Capstone is still used for disassembly.

**Assumption: ELFv2 TOC_BASE follows the ABI convention.** `TOC_BASE = .got_va + 0x8000`. Vendor-modified firmware that deviates from the ABI will produce incorrect GOT slot addresses and miss PLT entries.

**Assumption: `.rela.plt` or relocation entries are present.** Stripped binaries with no dynamic symbol information produce empty PLT maps.

**Scan bound.** The PPC64LE `.text` scanner iterates every word in `.text`. On a binary with a 10 MB `.text` section this is approximately 2.5 million iterations. This is a one-time build cost at `WindowAnalyzer.from_path()` time.

---

## FORGE status

Gate: **PASS**. No CRITICAL or HIGH findings. Three open items tracked for follow-up:

1. Move `_STD_R2_SAVE` to module level alongside `_ENDBR64`.
2. Add `bctrl` to `call_mnems` for `ppc64le` in `dump()`.
3. Add a `_MAX_TEXT_SCAN_WORDS` guard to `_build_plt_ppc64le_elfv2`.
