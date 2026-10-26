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

## What is XCOFF? History and IBM AIX context <sup>[↑](#xcoff32decompiler)</sup>

XCOFF (eXtended Common Object File Format) is IBM's binary object file format for AIX, the IBM proprietary UNIX operating system. XCOFF is derived from the older AT&T COFF (Common Object File Format) but adds IBM-specific extensions for the POWER architecture: the Table of Contents (TOC) model for position-independent global data access, loader section for dynamic linking, and the `.stabx` extension for symbol table debugging information.

**Historical context:**
- XCOFF was first published with AIX 1.0 in 1986, initially for the IBM RT PC (using the ROMP RISC architecture — IBM's first RISC processor)
- With AIX 3.0 (1989), XCOFF moved to the IBM POWER architecture as the primary binary format
- XCOFF32 is the 32-bit variant (XCOFF magic `0x01DF` or `0x01DA`); XCOFF64 is 64-bit (magic `0x01EF` or `0x01F7`)
- AIX uses XCOFF for all compiled binaries (executables, shared libraries `.a`, and kernel extensions `.ext`)
- Unlike most Unix systems, AIX uses an archive format (`.a`) for shared libraries; XCOFF `.so` files do not exist

**Why XCOFF in ablation's RE collection:**
- IBM BladeCenter I/O processors (PowerPC 476 or POWER7 series) run AIX and ship XCOFF32 binaries
- IBM Hardware Management Console (HMC) — the management interface for IBM Power Systems — runs AIX with XCOFF32 system binaries
- IBM Tivoli Storage Manager and Spectrum Scale (formerly GPFS) cluster agents run as AIX XCOFF32 binaries on storage nodes
- Older IBM AS/400 (iSeries/IBM i) system binaries use XCOFF variants for the bridge between CISC object code and the PowerPC hardware abstraction

---

## XCOFF32 file structure <sup>[↑](#xcoff32decompiler)</sup>

An XCOFF32 file has the following layout:

```
XCOFF32 file:
  File header (20 bytes):
    magic[2]      = 0x01DF (XCOFF32 big-endian) or 0x01DA (AIX 4.1 variant)
    nscns[2]      = number of sections
    timdat[4]     = timestamp
    symptr[4]     = file offset to symbol table
    nsyms[4]      = number of symbol table entries
    opthdr[2]     = optional header size
    flags[2]

  Optional header (72 bytes, if opthdr > 0):
    magic[2]      = 0x010B
    vstamp[2]
    tsize[4]      = size of .text section
    dsize[4]      = size of .data section
    bsize[4]      = size of .bss section
    entry[4]      = entry point VA
    text_start[4] = start of .text section VA
    data_start[4] = start of .data section VA
    toc[4]        = address of TOC anchor (r2 base address)

  Section headers (40 bytes each):
    s_name[8]     = section name (null-padded)
    s_paddr[4]    = physical address
    s_vaddr[4]    = virtual address
    s_size[4]     = section size in bytes
    s_scnptr[4]   = file offset to section data
    s_relptr[4]   = file offset to relocation entries
    s_lnnoptr[4]  = file offset to line number entries
    s_nreloc[2]
    s_nlnno[2]
    s_flags[4]    = section type flags

  Standard sections: .text, .data, .bss, .loader, .stabx
```

`XCoff32Decompiler` reads this layout directly. The TOC anchor address (from the optional header `toc` field) is the value loaded into r2 at process start — essential for resolving global variable accesses (`lwz rX, offset(r2)` patterns).

---

## TOC model and function descriptor resolution <sup>[↑](#xcoff32decompiler)</sup>

The IBM POWER/PowerPC AIX calling convention uses a Table of Contents (TOC) model for accessing global variables and function pointers. This is a significant difference from Linux ELF PPC:

**TOC structure:** The TOC is a contiguous array of 4-byte pointers in the `.data` section. r2 points to the TOC anchor (the middle of the TOC, so both positive and negative 16-bit offsets reach TOC entries). A global variable access looks like:
```asm
lwz  r10, offset(r2)  ; load address of global from TOC
lwz  r3, 0(r10)       ; dereference to get the value
```

**XCOFF32 function descriptors:** AIX uses a 12-byte function descriptor model for external function calls. A call via a function pointer uses the function descriptor, not the code entry point directly:
```
Function descriptor (in .data section):
  descriptor[0]: code entry point address
  descriptor[1]: TOC value (r2 for the called function's module)
  descriptor[2]: environment pointer (r11, for closures/nested functions)
```

A call through a function pointer:
```asm
lwz  r12, func_ptr_offset(r2)  ; r12 = address of function descriptor
lwz  r0, 0(r12)                ; r0 = code entry point
mtctr r0                        ; load CTR with entry point
lwz  r2, 4(r12)                ; load callee's TOC anchor into r2
bctrl                           ; indirect call
```

`XCoff32Decompiler` resolves this pattern and labels `bctrl` calls with the function name from the descriptor when the descriptor is in a known data section.

---

## AIX binary analysis workflow <sup>[↑](#xcoff32decompiler)</sup>

```python
from ablation.analyzers.xcoff32_decompiler import XCoff32Decompiler
from ablation.analyzers.binary_context import BinaryContext

# For XCOFF32 binaries, use XCoff32Decompiler to parse structure first
decompiler = XCoff32Decompiler.from_path('/firmware/aix/usr/sbin/inetd')

# Inspect sections
for section in decompiler.sections:
    print(f"  {section.name:12s} va={section.vaddr:#010x} size={section.size:#x}")

# Get TOC anchor value (r2 at process start)
print(f"TOC anchor: {decompiler.toc_va:#010x}")

# Decompile a specific function
func_text = decompiler.lift_function(decompiler.entry_va)
print(func_text)

# Or build BinaryContext from the extracted code sections for taint analysis
ctx = BinaryContext.from_xcoff32(decompiler)
# Now use SemanticSearcher, TaintTracker, etc. with the extracted binary context
from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker
tracker = PPC32TaintTracker.from_context(ctx)
findings = tracker.run_interprocedural()
```

---

## Limitations <sup>[↑](#xcoff32decompiler)</sup>

XCOFF64 is not supported. `from_context()` raises if the binary magic is `0x01f7`. Use `XcoffSymtabParser` for XCOFF64 name resolution and disassemble with a separate tool.

Indirect calls through an unresolved CTR emit `r3 = (*ctr)(...)`. This happens when the function pointer was loaded via a chain the decompiler did not track, typically a nested TOC load or a function pointer passed as an argument.

The decompiler produces a linear walk, not a CFG. It does not follow both sides of a branch or detect loop back-edges beyond a simple VA comparison. For functions with deeply nested branches, multiple `goto` chains appear in the output. Restructuring into `if/else` or `while` requires manual reading of the label graph.

---

## POWER architecture history and XCOFF32 context <sup>[↑](#xcoff32decompiler)</sup>

**IBM POWER (Performance Optimization With Enhanced RISC, 1990):** The POWER architecture was IBM's first RISC processor family, designed for the RS/6000 workstation line. POWER was codeveloped by IBM and derives from the earlier ROMP (Research OPD Micro Processor) used in the IBM RT PC (1986). Key design characteristics:

- 32-bit initially (POWER1), later 64-bit (POWER2, POWER3+)
- Separate fixed-point unit (FXU), floating-point unit (FPU), and branch processor (BP)
- Complex instruction set for fixed-point operations: `MULTIPLY-ADD`, `DIVIDE-SHORT`, indexed load/store with update
- Initial implementation: IBM RIOS1 chip set (Multi-Chip Module, 29 chips for the full CPU)

**POWER vs. PowerPC:** In 1991, IBM, Apple, and Motorola formed the AIM alliance to develop PowerPC (PPC) — a simpler, more portable RISC architecture derived from POWER but pruned of complex POWER-only instructions. The key differences:
- POWER had 3-operand multiply-add forms not in PPC (though PPC added `fmadd` for FP)
- POWER had string operations (not in PPC)
- PowerPC added little-endian support (POWER was big-endian only)
- POWER had non-architected forms that varied between chips; PPC was architecturally clean

**XCOFF32 and AIX history:**
| AIX version | Processor | XCOFF variant | Notes |
|---|---|---|---|
| AIX 1.x | IBM RT PC (ROMP) | XCOFF (pre-XCOFF32) | First AIX; 32-bit RT PC microprocessor |
| AIX 3.1 | POWER1 (RS/6000) | XCOFF32 | First RS/6000; XCOFF32 stable format |
| AIX 4.x | POWER2, PowerPC 601/604 | XCOFF32 | Both POWER and PPC instructions in same binary format |
| AIX 5.x | POWER3, POWER4 | XCOFF32 + XCOFF64 | 64-bit support added via XCOFF64; 32-bit apps still XCOFF32 |
| AIX 6.x | POWER5, POWER6 | Both | Most userland still 32-bit XCOFF32 |
| AIX 7.x | POWER7, POWER8, POWER9 | XCOFF64 dominant | New system binaries XCOFF64; legacy still XCOFF32 |

`XCOFF32Decompiler` handles all AIX 3.x–7.x 32-bit XCOFF32 binaries. For 64-bit XCOFF64 binaries, use the separate `XCOFF64Decompiler`.

---

## POWER PPC register file for XCOFF32 RE <sup>[↑](#xcoff32decompiler)</sup>

PPC32/POWER uses 32 general-purpose 32-bit registers (r0–r31), 32 floating-point 64-bit registers (f0–f31), and special-purpose registers (LR, CTR, XER, CR).

| Register | ABI role | Caller/callee | Notes |
|---|---|---|---|
| r0 | Scratch | Caller | Often used as temporary in function prologues |
| r1 | Stack pointer | Callee | Points to bottom of current stack frame |
| r2 | TOC pointer | Callee | Always = TOC anchor in AIX ABI |
| r3 | Arg 1 / Return value | Caller | Most important for taint: first argument and return |
| r4 | Arg 2 | Caller | |
| r5 | Arg 3 | Caller | |
| r6 | Arg 4 | Caller | |
| r7 | Arg 5 | Caller | |
| r8 | Arg 6 | Caller | |
| r9 | Arg 7 | Caller | |
| r10 | Arg 8 | Caller | |
| r11 | Environment pointer (nested) | Caller | Used for closures; usually scratch |
| r12 | GEP / PLT trampoline | Caller | Used in shared lib PLT entry setup |
| r13–r31 | Callee-saved | Callee | Must be preserved; r31 often used as FP |
| LR | Link Register | Caller | Set by `bl` instruction; return address |
| CTR | Count Register | Caller | Used for `bctr` (branch via CTR) |

**Taint focus:** r3 is both the first argument and the return value. For `system()` calls, r3 is the command string argument. For `recv()`, r3 is the return value (bytes received) and r4 is the buffer pointer. `XCOFF32Decompiler` decompiles expressions using these conventions; a finding typically traces `r3` at a `bl system` instruction back to a `bl recv` return.

---

## XCOFF32 PPC instruction encoding for byte verification <sup>[↑](#xcoff32decompiler)</sup>

PPC32 instructions are 32-bit, big-endian, 4-byte aligned.

**Branch instructions (critical for taint finding verification):**

| Mnemonic | Encoding | Notes |
|---|---|---|
| `bl target` | `0x48000001 \| (disp26 & 0x3FFFFFC)` | Branch-and-link (call); LR = pc + 4 |
| `blr` | `0x4E800020` | Branch to LR (function return) |
| `bctr` | `0x4E800420` | Branch to CTR (indirect branch/call) |
| `bctrl` | `0x4E800421` | Branch-to-CTR-and-link (indirect call) |
| `b target` | `0x48000000 \| (disp26 & 0x3FFFFFC)` | Unconditional branch |
| `bne label` | `0x40820000 \| disp16` | Branch if not equal (CR bit 2 not set) |

**Byte-verify cheat sheet for XCOFF32:**
```python
import struct
with open(binary_path, 'rb') as f:
    data = f.read()
# PPC32: big-endian 32-bit words
off = va - text_va + text_file_offset
word = struct.unpack('>I', data[off:off+4])[0]
opcd = word >> 26
if opcd == 0x12:  # bl or b
    aa = (word >> 1) & 1   # absolute address flag
    lk = word & 1           # link register update flag
    disp26 = word & 0x3FFFFFC
    if disp26 & 0x2000000:
        disp26 -= 0x4000000  # sign extend 26-bit
    target = (disp26 if aa else va + disp26)
    print(f"{'bl' if lk else 'b'} target={target:#010x}")
```

---

## AIX setuid binary analysis workflow <sup>[↑](#xcoff32decompiler)</sup>

For privilege escalation research on AIX systems:

1. **Enumerate setuid binaries:** In a live system or from a disk image, `find / -user root -perm -4000 -type f 2>/dev/null`. In an AIX backup archive (`.tar.Z` or `.bff` — AIX BFF format): extract and check file mode bits.

2. **Prioritize:** Focus on binaries that take user-controlled input (arguments, environment variables, stdin) and have IAC access: `lquerylv`, `lchange`, `mount`, `umount`, `installp`, `smit`.

3. **Semantic sweep on extracted binary:** `SemanticSearcher.query('argv environ getenv strcpy sprintf buffer format')` on the XCOFF32 binary.

4. **Decompile candidate functions:** `XCOFF32Decompiler.decompile_function(va)` for candidates.

5. **Verify with byte-read:** Use the PPC instruction encoding above to confirm `bl strcpy` vs. `bl strncpy` at the identified copy point.

6. **FindingRegistry:** Register with `cwe='CWE-134'` (format string) or `cwe='CWE-121'` (stack BO) as appropriate.

**Performance:**
| Operation | Estimated time |
|---|---|
| `XCOFF32Decompiler` init (1 MB binary) | 3–8 seconds |
| `list_members()` for `.a` archive | 1–2 seconds |
| `decompile_function()` per function | 0.5–2 seconds |
| Full `SemanticSearcher` sweep | 20–45 seconds |
| Full taint analysis (PPC32 POWER) | 30–90 seconds |

---

## CWE mapping for XCOFF32/AIX findings <sup>[↑](#xcoff32decompiler)</sup>

| Finding class | CWE | AIX/XCOFF32 pattern |
|---|---|---|
| Command injection in suid binary | CWE-78 | `bl system` / `bl execlp` with r3 from argv/environ |
| Stack buffer overflow | CWE-121 | `bl strcpy` into fixed local buffer; saved LR on stack is target |
| Format string | CWE-134 | `bl printf` / `bl syslog` with r3 from network/user input |
| TOC/descriptor corruption | CWE-824 | Heap overflow into TOC anchor region; function descriptor code_ptr overwrite |
| Integer overflow in size | CWE-190 | `add r3, rN, rM` with both from network; used as `bl malloc` argument |
| Path traversal in suid binary | CWE-22 | `bl open` / `bl fopen` with r3 path from argv without `realpath()` canonicalization |

- [PPC476 Lifter](ppc476-lifter.md): for IBM Power 476FP ELF binaries (not XCOFF32); combines with this module for XCOFF32 → lifted analysis pipeline
- [PPC32 Taint Tracker](ppc32-taint-tracker.md): taint analysis on PPC32 code extracted from XCOFF32 binaries
- [BinaryContext](binary-context.md): build analysis context from extracted XCOFF32 sections
- [Semantic Code Search](semantic-code-search.md): semantic embedding for function name candidates in stripped XCOFF32 AIX binaries
- [M88K Decoder](m88k-decoder.md): for older IBM 88k COFF binaries from the pre-POWER AIX era
- [FindingRegistry](registry.md): record confirmed AIX/XCOFF findings; set `evidence_type='xcoff32_decompiled_pseudo_c'`
- [Length Underflow Scanner](length-underflow.md): detect RPC/XDR argument length underflow in AIX RPC server binaries

---

## XCOFF32 archive (.a) format and shared library extraction <sup>[↑](#xcoff32decompiler)</sup>

AIX shared libraries are packaged in BSD `ar`-format archives with the `.a` extension. Unlike Linux `.so` files, an AIX `.a` file may contain multiple shared object members, each an XCOFF32 binary.

**Archive structure:**
```
!<arch>                    ← magic (8 bytes)
[per-member headers]       ← 60-byte ar_hdr for each member
  ar_hdr.ar_name[16]       ← member filename
  ar_hdr.ar_size[10]       ← member size in ASCII decimal
  ar_hdr.ar_fmag[2]        ← 0x60 0x0A (magic terminator)
[XCOFF32 member data]      ← one XCOFF32 binary per member
```

`XCOFF32Decompiler.list_members()` enumerates all archive members. `decompiler.get_member('libnet.so')` extracts and returns an `XCOFF32Decompiler` for a specific member. For analysis, extract each member separately and analyze as a standalone XCOFF32 binary.

**AIX shared library naming conventions:**
- `libfoo.a(libfoo.so)`: the shared object inside the archive
- `libfoo.a(shr.o)`: older naming convention (AIX 3.x style, member is `shr.o`)
- `libfoo.a(libfoo64.so)`: 64-bit XCOFF64 member in the same archive as XCOFF32

`XCOFF32Decompiler` skips XCOFF64 members (magic `0x01EF`) and only processes XCOFF32 members (magic `0x01DF`).

---

## Limitations and false positive suppression <sup>[↑](#xcoff32decompiler)</sup>

**POWER vs. PPC instruction set:** AIX binaries from POWER1-era RS/6000 systems use POWER-specific instructions (`lscbx`, `maskg`, `rlmi`) not present in PowerPC. `XCOFF32Decompiler` auto-detects POWER vs. PPC from the optional header `vstamp` field:
- `vstamp = 0x0101`: POWER-only instructions possible
- `vstamp = 0x0103`: PowerPC compatible (no POWER-only instructions)

For POWER-only binaries, unknown instructions are emitted as `/* POWER-insn: {word:#010x} */` in the decompiled output rather than causing analysis failure.

**TOC-relative load false positives:** Not every `lwz r3, offset(r2)` is a function pointer or security-critical load. Many TOC entries are read-only constants (string addresses, global struct addresses). `SinkArgClassifier` filters these: a `bl` at a site where r3 came from a `lwz Rn, offset(r2)` that resolves to a `.rodata` section address is classified `RODATA_CONST` and excluded from taint analysis.

**Stripped vs. symbol-rich:** Full-symbol AIX binaries include `C_EXT`/`C_HIDEXT` symbol table entries with function names. Stripped binaries (common in production) have only the `.loader` section export symbols. `XCOFF32Decompiler` decompiles both; stripped binaries show `func_0x????` labels for internal functions, while named binaries show actual symbol names.

---

## Complete usage example: AIX XCOFF32 binary analysis <sup>[↑](#xcoff32decompiler)</sup>

```python
from ablation.analyzers.xcoff32_decompiler import XCOFF32Decompiler
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.semantic_searcher import SemanticSearcher
from ablation.analyzers.finding_registry import FindingRegistry

binary_path = '/media/research/IBM/AIX/usr/lib/libnetwork.a'  # XCOFF32 archive

# For .a archives: XCOFF32Decompiler extracts member objects
decompiler = XCOFF32Decompiler(binary_path)
print(f"XCOFF32 archive members: {decompiler.list_members()}")

# Analyze specific member
member = decompiler.get_member('libnetwork.so')
# Or for a standalone XCOFF32:
# decompiler = XCOFF32Decompiler('/usr/lib/libnetwork.so')

# List exported symbols
for sym in decompiler.exports[:10]:
    print(f"  {sym.name}: va={sym.va:#010x} section={sym.section}")

# Semantic search
ctx = BinaryContext.load_or_build_from_xcoff(binary_path)
searcher = SemanticSearcher(ctx)
exec_hits = searcher.query('system exec command shell fork invoke execve')
for h in exec_hits[:3]:
    print(f"\n=== Exec candidate at {h.va:#010x} ({h.name or '?'}) ===")
    print(decompiler.decompile_function(h.va)[:1500])

# Byte-verify a finding
import struct
with open(binary_path, 'rb') as f:
    data = f.read()

# Locate the function in the XCOFF32 text section
text_section = decompiler.get_section('.text')
off = exec_hits[0].va - text_section.virtual_address + text_section.file_offset
# PPC: bl instruction = 0x48000001 | ((target - pc) & 0x3FFFFFC)
word = struct.unpack('>I', data[off:off+4])[0]
opcd = word >> 26  # 0x12 = bl (branch-and-link)
print(f"Opcode at {exec_hits[0].va:#010x}: {word:#010x} (opcd={opcd:#04x})")

# Register finding
registry = FindingRegistry(binary_path)
registry.register(
    va=exec_hits[0].va,
    name='AIX libnetwork system() command injection CWE-78',
    severity='HIGH',
    cwe='CWE-78',
    evidence_type='xcoff32_decompiled_pseudo_c',
    detail=(
        f"bl at {exec_hits[0].va:#010x}: calls system(). "
        "r3 (first arg, the command string) traced to recv() return buffer. "
        f"Byte verify: data[{off:#010x}:+4] = {data[off:off+4].hex()} (bl instruction)."
    ),
)
```

---

## XCOFF32 file format: detailed structure reference <sup>[↑](#xcoff32decompiler)</sup>

**XCOFF32 file header (20 bytes at offset 0):**
```
struct XCOFF32Header {
    uint16_t f_magic;   // 0x01DF (XCOFF32) or 0x01EF (64-bit XCOFF64)
    uint16_t f_nscns;   // number of sections
    uint32_t f_timdat;  // time and date stamp (seconds since 1970-01-01)
    uint32_t f_symptr;  // file offset to symbol table
    uint32_t f_nsyms;   // number of symbol table entries
    uint16_t f_opthdr;  // optional header size (68 bytes for XCOFF32 executable)
    uint16_t f_flags;   // flags: F_EXEC=2, F_LNNO=4, F_LSYMS=8, F_SHROBJ=0x2000
};
```

**Optional header (68 bytes, if f_opthdr != 0):**
```
struct XCOFF32OptHdr {
    uint16_t magic;       // 0x010B = executable
    uint16_t vstamp;      // version stamp
    uint32_t tsize;       // text segment size
    uint32_t dsize;       // initialized data size
    uint32_t bsize;       // uninitialized data (BSS) size
    uint32_t entry;       // entry point address (VA of _start)
    uint32_t text_start;  // virtual address of .text
    uint32_t data_start;  // virtual address of .data
    uint32_t toc;         // TOC (table of contents) anchor address
    uint16_t snentry;     // section number of entry point
    uint16_t sntext;      // section number of .text
    uint16_t sndata;      // section number of .data
    uint16_t sntoc;       // section number of .toc
    uint16_t snloader;    // section number of .loader
    uint16_t snbss;       // section number of .bss
    ...
};
```

The `toc` field is the TOC anchor address. All global variable accesses use `r2 + offset` where r2 = TOC anchor at runtime. `XCOFF32Decompiler.toc_anchor` exposes this value.

**Section header (40 bytes each):**
```
struct XCOFF32SectionHdr {
    char     s_name[8];     // section name (null-padded, not null-terminated)
    uint32_t s_paddr;       // physical address
    uint32_t s_vaddr;       // virtual address
    uint32_t s_size;        // section size in bytes
    uint32_t s_scnptr;      // file offset of section data
    uint32_t s_relptr;      // file offset of relocation entries
    uint32_t s_lnnoptr;     // file offset of line number entries
    uint16_t s_nreloc;      // number of relocation entries
    uint16_t s_nlnno;       // number of line number entries
    uint32_t s_flags;       // section flags: STYP_TEXT=0x20, STYP_DATA=0x40
};
```

Key section names: `.text` (code), `.data` (initialized data), `.bss` (uninit), `.toc` (TOC entries), `.loader` (import/export table), `.except` (exception handling table).

---

## AIX XCOFF32 known CVEs and vulnerability history <sup>[↑](#xcoff32decompiler)</sup>

IBM AIX has a long history of security vulnerabilities, many involving XCOFF32 binaries. Notable findings analyzable with `XCOFF32Decompiler`:

**CVE-1999-0047 (AIX lquerylv buffer overflow, CVSS 10.0):** `lquerylv` is a setuid-root utility for querying LVM (Logical Volume Manager) volume group parameters. The XCOFF32 binary for AIX 4.2.1 had a fixed-size stack buffer for the volume group name argument. `XCOFF32Decompiler.decompile_function()` on the argument parsing function clearly shows the `strcpy(fixedbuf, argv[1])` pattern without length check.

**CVE-2001-0650 (AIX dtterm buffer overflow, CVSS 7.2):** The `dtterm` (CDE terminal emulator) setuid binary on AIX 5.1 had a format string vulnerability in the `-xrm` option handler. `SemanticSearcher.query('sprintf format string option argument')` on the dtterm XCOFF32 binary identifies the vulnerable format call.

**CVE-2003-0461 (AIX rpc.ttdbserverd, CVSS 10.0):** The CDE Tooltalk database server rpc.ttdbserverd had a heap overflow in the RPC argument processing. On AIX POWER, this was exploitable because POWER GCC allocates the heap immediately after the BSS segment (unlike Linux where randomization applies). `XCOFF32Decompiler` analysis of the RPC stub shows the `XDR_decode` + `malloc(n)` + `memcpy(buf, src, n)` pattern without bounds check.

**CVE-2007-5765 (AIX invscout, CVSS 7.2):** The `invscout` (inventory scout) utility had a format string vulnerability. This is a representative example of a finding identifiable via `SemanticSearcher.query('printf syslog format string invscout')` on the AIX 5.3 XCOFF32 binary.

---

## AIX XCOFF32 symbol table and import resolution <sup>[↑](#xcoff32decompiler)</sup>

The XCOFF32 symbol table uses COFF symbol table format with AIX extensions. Symbol table entries are 18 bytes each:

```
struct XCOFF32Symbol {
    union { char n_name[8]; struct { uint32_t n_zeros; uint32_t n_offset; } n_nptr; };
    uint32_t n_value;     // value (VA for code symbols, TOC offset for data)
    int16_t  n_scnum;     // section number; 0=undef, -1=abs, -2=debug
    uint16_t n_type;      // type (XCOFF: always 0 for functions; type in aux entry)
    uint8_t  n_sclass;    // storage class: C_EXT=2, C_HIDEXT=107, C_FCN=101
    uint8_t  n_numaux;    // number of auxiliary entries following this entry
};
```

**Storage class `C_HIDEXT` (hidden external):** Internal symbols in shared libraries use `C_HIDEXT`. These are the actual function implementations. `C_EXT` symbols in the `.loader` section are the exported symbols. When analyzing a stripped AIX binary:
1. `C_EXT` symbols give the exported function names and VAs
2. `C_HIDEXT` symbols give internal helper function names and VAs
3. The `.loader` section has an import list linking external calls to `C_EXT` symbols from other libraries

`XCOFF32Decompiler.symbols` returns all symbol table entries. `decompiler.find_function(va)` resolves a VA to the nearest preceding `C_EXT` or `C_HIDEXT` symbol.

---

## AIX TOC model: security implications for RE <sup>[↑](#xcoff32decompiler)</sup>

The POWER/XCOFF32 TOC (Table of Contents) model has specific security implications:

**TOC poisoning:** The TOC is a data section. If an attacker can write to a TOC entry (via a heap overflow into the TOC region, or a direct write via a vulnerability), they can redirect any global variable access to an attacker-controlled address. Since function pointers are often stored as TOC entries (via function descriptors), TOC corruption → arbitrary code execution.

**Function descriptor pattern:** XCOFF32 function pointers point to function descriptors, not directly to code. A function descriptor is a 12-byte structure: `{code_ptr, toc_ptr, env_ptr}`. To call a function via pointer, the POWER code loads the descriptor, sets r2=toc_ptr, and branches to code_ptr. Overwriting just the code_ptr field of a descriptor (8 bytes into the heap if descriptors are heap-allocated) redirects execution.

`XCOFF32Decompiler.function_descriptors` returns all identified function descriptors in the `.data` section.

---

## AIX-specific attack classes and XCOFF32 RE workflow <sup>[↑](#xcoff32decompiler)</sup>

**SUID-root utility analysis:** AIX ships many setuid-root utilities for system administration: `lquerylv`, `lchange`, `lsattr`, `mount`, `installp`, etc. These are prime targets for privilege escalation. `XCOFF32Decompiler.list_setuid_candidates()` identifies XCOFF32 binaries with the SUID bit set in the AIX filesystem (requires the original filesystem mount or a tarball with permissions).

**NIS/YP client vulnerabilities:** AIX's NIS (Yellow Pages) client libraries (`libnsl.a`, `libyp.a`) had multiple buffer overflows in the `yp_match` and `ypmatch` functions. The pattern: `ypresponse` buffer fixed-size allocation + `strcpy` of NIS server response.

**BSD sendmail on AIX:** AIX traditionally used BSD sendmail rather than Postfix or Exim. Many sendmail vulnerabilities are exploitable on AIX POWER/XCOFF32 format. `SemanticSearcher.query('sendmail address expansion format string command pipe')` on an AIX sendmail XCOFF32 binary identifies the canonical vulnerability patterns.
