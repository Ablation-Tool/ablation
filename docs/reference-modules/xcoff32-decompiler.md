# Xcoff32Decompiler

**Module:** `ablation.analyzers.xcoff32_decompiler`  
**Class:** `Xcoff32Decompiler`

- [What this is](#what-this-is)
- [Where it's used](#where-its-used)
- [Safe usage](#safe-usage)
- [Why this exists](#why-this-exists)
- [Usage](#usage)
- [AIX PPC32 calling convention](#aix-ppc32-calling-convention)
- [Function descriptor format](#function-descriptor-format)
- [Instruction coverage](#instruction-coverage)
- [Limitations](#limitations)

---

## What this is <sup>[↑](#xcoff32decompiler)</sup>

`Xcoff32Decompiler` converts AIX PPC32 XCOFF32 functions to C-like pseudocode. It resolves AIX function descriptors before disassembly, names TOC-relative operands from the symbol map, and emits output through the standard `from_context(ctx)` interface. No Ghidra. No LIEF.

---

## Where it's used <sup>[↑](#xcoff32decompiler)</sup>

- AIX base executables extracted from `.bff` installp archives `automountd`, `rlogind`, `ksh93`
- Stripped XCOFF32 binaries where the only function names come from `.symtab` rather than a `.loader` section
- Any PPC32 BE XCOFF32 binary where you need readable pseudocode, not a raw instruction listing

---

## Safe usage <sup>[↑](#xcoff32decompiler)</sup>

**Pass a code VA, not a descriptor VA.** `XcoffBinary.exports` keys are descriptor VAs in `.data`. Call `Xcoff32Decompiler.from_context(ctx)` and let it resolve the descriptor, then call `decompile(code_va)` with the resolved entry point. Passing a descriptor VA to `decompile()` disassembles `.data` bytes as instructions and produces garbage output.

**`decompile()` is a linear walk.** It does not reconstruct a CFG. Conditional branches emit `if (cond) goto loc_N;` labels. For functions with complex control flow, increase `n_insn` and follow the `goto` targets manually. Do not interpret the pseudocode as structured C: the function may have multiple exit paths.

**TOC resolution requires a non-zero `toc_va`.** `from_context()` derives `toc_va` from the first function descriptor's second word. If the binary has no exported functions with valid descriptors, `toc_va` defaults to 0 and all `lwz rN, off(r2)` loads appear as `TOC+off` rather than symbol names. Run `XcoffSymtabParser` first to populate function names, which helps `from_context()` locate a valid descriptor.

**`r2` is the TOC pointer, not a general-purpose register.** `lwz rN, off(r2)` loads a global symbol address. The decompiler annotates these as `sym_name; // TOC+off`. Do not treat a TOC load as attacker-controlled input unless you have traced a write to that TOC slot.

**Callee-save suppression is a heuristic.** `stw rN, off(r1)` for `N >= 14` is silently suppressed as a prologue callee-save. If the function actually stores a meaningful value from `r14-r31` into the stack frame, that store disappears from the pseudocode. Confirm any stack slot whose name starts with `local_` against the raw disassembly when a finding depends on that value.

**Floating-point register values do not propagate.** FPR operands print as `fN` literals throughout. The decompiler tracks GPR state but not FPR state. Any dataflow through `f0-f31` appears as bare register names rather than derived expressions.

---

## Why this exists <sup>[↑](#xcoff32decompiler)</sup>

Three gaps in the existing toolchain make PPC32 AIX RE slower than it should be.

**1. Ghidra cannot resolve AIX function descriptors.**  
Every exported PPC32 AIX function has a two-word descriptor in `.data`: the first word is the `.text` entry point, the second is the TOC base. Ghidra treats the descriptor region as data and misses the real entry point entirely. The function's name appears in the symbol table attached to the descriptor VA, so Ghidra labels the descriptor, not the code. `Xcoff32Decompiler.from_context()` reads `descriptor[0]` to get the code VA before Capstone runs.

**2. Ghidra does not name TOC-relative operands.**  
AIX PPC32 code loads nearly every global symbol via `lwz rN, off(r2)`. Without a resolved TOC map, each load appears as a raw numeric offset. `_resolve_toc(offset)` maps `r2 + off` to a symbol name using the same name table that `BinaryContext` maintains, so calls through descriptors appear as `r3 = malloc(...)` rather than `r3 = *(toc+0x48)`.

**3. No existing ablation decompiler targets XCOFF32.**  
`Ppc476Decompiler` uses LIEF for ELF loading and targets IBM Book E embedded cores. It does not parse XCOFF32 headers, does not understand AIX descriptors, and does not handle the AIX calling convention where `r2` is the TOC pointer rather than a scratch register. `Xcoff32Decompiler` parses the XCOFF32 file header directly and handles the full AIX PPC32 calling convention.

---

## Usage <sup>[↑](#xcoff32decompiler)</sup>

```python
from ablation.analyzers.xcoff32_decompiler import Xcoff32Decompiler
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/automountd')

# from_context() resolves all descriptors and derives toc_va automatically.
dec = Xcoff32Decompiler.from_context(ctx)

# Decompile one function by its code VA (not the descriptor VA).
print(dec.decompile(0x10001234, n_insn=200))

# Decompile all named exports.
for code_va in dec.exports:
    print(dec.decompile(code_va))
```

**Output format:**

```
// Xcoff32Decompiler: is_nonzero @ 0x10001000  (toc=0x200c0000)
auto is_nonzero(auto arg0, auto arg1, auto arg2, auto arg3) {
  // frame: sp -= 32
  if (arg0 == 0) goto loc_0x10001018;
  r3 = 1;
  goto loc_0x10001020;
loc_0x10001018:
  r3 = 0;
loc_0x10001020:
  return r3;
}
```

---

## AIX PPC32 calling convention <sup>[↑](#xcoff32decompiler)</sup>

```
r1    stack pointer (grows down; stwu r1,-N(r1) allocates)
r2    TOC pointer (constant for the duration of each function)
r3    first argument / return value
r4-r10  remaining arguments
r11   environment pointer for nested functions; scratch otherwise
r12   scratch; used by PLT resolvers
r13-r31 callee-saved
LR    return address (saved by mflr at prologue, restored by mtlr at epilogue)
CTR   computed branch target (loaded by mtctr, jumped by bctr)
```

---

## Function descriptor format <sup>[↑](#xcoff32decompiler)</sup>

Each exported symbol name in the symbol table points to a descriptor in `.data`, not directly to `.text`.

```
descriptor_va:           (this is the VA in XcoffBinary.exports)
  +0  uint32_t  code_va  <- actual .text entry point
  +4  uint32_t  toc_va   <- r2 value for this function
  +8  uint32_t  env_va   <- environment pointer (0 for normal functions)
```

`from_context()` reads `data_data[descriptor_va - data_va]` to extract `code_va` and uses the first valid `toc_va` as the module-wide TOC base.

---

## Instruction coverage <sup>[↑](#xcoff32decompiler)</sup>

| Family | Instructions handled |
|--------|----------------------|
| Frame | `stwu sp`, `addi sp`; callee-save suppress `stmw`, `lmw`, `stw/lwz rN>=14` |
| Load | `lwz/lhz/lha/lbz/lfs/lfd` + indexed `lwzx/lhzx/lbzx` + update `lwzu/lhzu/lbzu` + `ld/lwa` |
| Store | `stw/sth/stb/stfs/stfd` + indexed `stwx/sthx/stbx` + update `stwu/sthu/stbu` + `std/stdx` |
| Arithmetic | `add/subf/mullw/divw/divwu` + carry `addc/adde` + high-word `mulhw/mulhwu` |
| Logic | `and/or/xor/nand/nor/andc/orc/eqv` + immediate `andi./ori/xori/andis./oris/xoris` |
| Shift/rotate | `slw/srw/sraw/srawi` + `rlwinm` (with `slwi`/`srwi` alias detection) + `rlwimi/rotlwi` |
| Immediate | `li`, `lis` (2-arg), `addis` (3-arg; treated as `lis` when `rA=0`), `addi/la` |
| Unary | `neg/extsb/extsh/extsw/cntlzw/popcntw` |
| Compare | `cmpwi/cmplwi/cmpw/cmplw` and 64-bit forms; updates CR state for the following branch |
| Branch | `b/bl/blr/bctr/bctrl` + all conditional `b*` via `_CRState.decode()` |
| Float | `fadd/fsub/fmul/fdiv/fmadd` single and double variants + `fcmpu/fcmpo` |
| SPR | `mfspr/mtspr` LR=8, CTR=9, XER=1; `mflr/mtlr` suppressed; `mtctr` absorbed into `bctr` |
| Syscall | `sc` emits `syscall(r0=N)` |
| Altivec | passes through as `// [va] vmx_insn ops` |

---

## Limitations <sup>[↑](#xcoff32decompiler)</sup>

XCOFF64 is not supported. `from_context()` raises if the binary magic is `0x01f7`. Use `XcoffSymtabParser` for XCOFF64 name resolution and disassemble with a separate tool.

Indirect calls through an unresolved CTR emit `r3 = (*ctr)(...)`. This happens when the function pointer was loaded via a chain the decompiler did not track, typically a nested TOC load or a function pointer passed as an argument.

The decompiler produces a linear walk, not a CFG. It does not follow both sides of a branch or detect loop back-edges beyond a simple VA comparison. For functions with deeply nested branches, multiple `goto` chains appear in the output. Restructuring into `if/else` or `while` requires manual reading of the label graph.
