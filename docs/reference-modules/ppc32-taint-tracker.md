# PPC32TaintTracker

  - [What is PowerPC?](#what-is-powerpc)
    - [Register file and calling conventions](#register-file-and-calling-conventions)
    - [Instruction encoding and branch model](#instruction-encoding-and-branch-model)
    - [Big-endian vs. little-endian PowerPC](#big-endian-vs-little-endian-powerpc)
    - [PPC-64 and server variants](#ppc-64-and-server-variants)
    - [RE implications](#re-implications)
  - [What this is](#what-this-is)
  - [Where it's used](#wheres-its-used)
  - [Safe usage](#safe-usage)
  - [Usage](#usage)
  - [ABI model](#abi-model)
  - [GOT2 PIC support](#got2-pic-support-huawei--embedded-linux)
  - [Sources and sinks](#sources-and-sinks)
  - [Taint propagation](#taint-propagation)
  - [Interprocedural depth](#interprocedural-depth)
  - [Known limitations](#known-limitations)
  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)

**File:** `ablation/analyzers/taint_tracker_ppc32.py`

---

## What is PowerPC? <sup>[↑](#ppc32tainttracker)</sup>

PowerPC (Performance Optimization With Enhanced RISC Performance Chip) is a RISC processor architecture created in 1991 by the AIM alliance: Apple, IBM, and Motorola. It descends directly from IBM's POWER (Performance Optimization With Enhanced RISC) architecture developed in the late 1980s. The PowerPC specification was first published in 1993; Motorola's PowerPC 601 and IBM's RS64 were the first implementations. Apple used PowerPC in the Macintosh line from 1994 until the Intel transition in 2006. IBM's PowerPC cores powered the Nintendo GameCube, Wii, Wii U, Xbox 360, and PlayStation 3.

In embedded networking and industrial contexts, PowerPC became the dominant architecture for Cisco routers throughout the 1990s and 2000s. The Cisco 7200 series used IDT R4700 (MIPS) but the 7600 and Catalyst 6000 series, plus IOS-XR on CRS and ASR platforms, ran on PowerPC. Freescale (spun off from Motorola in 2004, acquired by NXP in 2015) produced PowerPC SoCs (MPC8xx, MPC82xx, MPC85xx, QorIQ P/T/B series) that powered the majority of embedded networking hardware from 2000 through 2018. Huawei's Versatile Routing Platform (VRP) boot ROMs and management plane code ran on PPC32 big-endian.

The current server-side successor is IBM POWER10, used in OpenPOWER servers. The embedded successor is NXP's QorIQ (still PPC architecture) and the automotive-grade e200 core series (PPC Book E, used in automotive ECUs: see `ecu-vle-decoder.md` for VLE). PowerPC remains in production in aerospace (Freescale's radiation-hardened MPC5200), industrial control systems, and legacy networking infrastructure.

### Register file and calling conventions <sup>[↑](#ppc32tainttracker)</sup>

PowerPC defines 32 general-purpose 32-bit registers (64-bit in PPC-64). The SysV PPC-32 ABI (used by Linux, VxWorks on MPC8xx) and the EABI (used by bare-metal Freescale firmware) share the same general structure:

| Register(s) | Convention |
|---|---|
| `r0` | Volatile. Used as a scratch by function prologues/epilogues. In system calls: holds syscall number. |
| `r1` | Stack pointer. Grows downward. The first word at `r1` is the back-chain pointer to the caller's stack frame. |
| `r2` | Table of Contents (TOC) pointer in PPC-64 ELF v1/v2. In PPC-32: sometimes used for GOT, sometimes small data area. |
| `r3–r10` | Function arguments (r3–r10) and return values (r3, r4 for 64-bit returns). Network recv() stores byte count in r3. |
| `r11–r12` | Volatile scratch. `r12` is used for global entry point in PPC-64 ELFv2. |
| `r13` | Small data area pointer (SDA) in EABI; thread pointer in Linux PPC-32. |
| `r14–r31` | Non-volatile. Callee must save and restore. Freed pointers moved here survive CALL boundaries. |

Special registers: `LR` (Link Register) holds the return address set by `BL` (branch-and-link). `CTR` (Count Register) holds the loop counter for `BDNZ` and the target for `BCTRL` indirect calls. `CR` (Condition Register) is split into eight 4-bit fields (`cr0–cr7`). `XER` holds carry, overflow, and byte-count for string operations.

### Instruction encoding and branch model <sup>[↑](#ppc32tainttracker)</sup>

All PowerPC instructions are 32 bits wide, fixed-width, no variable-length prefix. The opcode occupies bits [31:26] (big-endian bit numbering where bit 0 is the MSB). The primary opcode determines the instruction class; most arithmetic/logical instructions use a 6-bit primary opcode with a 10-bit extended opcode in bits [10:1].

Branches use a different model than x86: `B` (branch) and `BL` (branch-and-link) use a 26-bit PC-relative offset. Conditional branches (`BC`, `BCL`) use a 14-bit offset and test a specific bit in the Condition Register. Indirect branches (`BCLR`, `BCTR`, `BLRL`, `BCTRL`) branch to the address in `LR` or `CTR`. The absence of a CALL instruction: `BL` saves the return address in `LR`, not on the stack: means function prologues must explicitly push `LR` with `MFLR r0; STW r0, offset(r1)` if the function makes any calls.

**Back-chain pointer**: Unlike x86 where the return address is pushed to the stack, PPC uses a linked-list stack frame structure. Every frame starts with a back-chain word at `r1+0` pointing to the caller's frame. The saved LR is at `r1+4` in PPC-32 (or `r1+8` in PPC-64). Stack overflow exploits on PPC target the saved LR at a predictable offset.

### Big-endian vs. little-endian PowerPC <sup>[↑](#ppc32tainttracker)</sup>

Original PowerPC is big-endian only: Apple, Cisco IOS, AIX, VxWorks on embedded networking hardware. IBM POWER and PowerPC server Linux run big-endian for compatibility with historical IBM software.

PowerPC little-endian (PPCEL) was introduced for Book E embedded cores (Freescale MPC85xx) and became the dominant mode for embedded Linux after GCC added `-mlittle-endian` support. Modern NXP QorIQ Linux runs little-endian. Sony PlayStation 3's PPU (POWER-based) is big-endian but SPUs can run either way.

IBM POWER8 and later support a "little-endian mode" where the hardware stores bytes in LE order but instructions remain 32-bit-wide big-endian encoded. This "LE instruction" mode is what modern OpenPOWER Linux uses. The Ablation PPC-32 tracker reads endianness from the ELF `e_data` field; the disassembler handles byte-swapping of the 32-bit instruction word before decoding.

### PPC-64 and server variants <sup>[↑](#ppc32tainttracker)</sup>

POWER64 (IBM RS64 and POWER3) introduced 64-bit addressing in 1998. PPC-64 ELFv1 (the original Linux ABI) uses a "function descriptor" model where a function pointer is a pointer to a 3-word struct containing the entry point address, TOC pointer, and environment pointer. PPC-64 ELFv2 (Linux since 2014) eliminated descriptors: function pointers are direct entry point addresses.

The Cisco CRS and ASR platforms run IOS-XR on PPC-64 big-endian with custom kernel modifications. The `PPC64TaintTracker` (separate from `PPC32TaintTracker`) handles the wider register file and ELFv2 calling convention.

### RE implications <sup>[↑](#ppc32tainttracker)</sup>

**Network entry points in IOS**: Cisco IOS `ip_input()` and `tcp_input()` receive packet data into Cisco Buffer structures. The buffer data pointer and length are in the first two fields of the `struct iovec`-equivalent at `r3` on entry. Taint both the length field (potential size confusion) and the data pointer (potential format string or command injection).

**GOT2 and PIC code**: Embedded Linux PPC-32 firmware compiled with `-fPIC` uses a per-function GOT anchor at `r30` (`.got2` section). Each function computes `r30 = _GLOBAL_OFFSET_TABLE_ + offset` using a `ADDIS; ADDI` pair at the prologue. Indirect calls go through `LWZ r12, symbol@got(r30); MTCTR r12; BCTRL`. The tracker resolves these via the PLT symbols in `BinaryContext`.

**Stack smashing**: Because the return address is in `LR` stored at a fixed offset from `r1`, and because PPC stacks have a predictable back-chain structure, buffer overflows that reach the saved LR overwrite it reliably. The saved LR offset is `frame_size + 4` from the function's local frame base.

Interprocedural taint analysis for 32-bit PowerPC big-endian and little-endian.
Traces network-sourced data from read/recv/pread/fgets to command-execution sinks and memory-corruption sinks.

Targets: Cisco 7200/3700 IOS big-endian, Huawei S6720/S6720EI boot ROM (big-endian
GOT2 PIC), MikroTik RB600 big-endian, VxWorks embedded big-endian, POWER LE
Linux userspace little-endian, older Fortinet hardware big-endian.

---

## What this is <sup>[↑](#ppc32tainttracker)</sup>

32-bit PowerPC firmware appears across router IOS images, embedded bootloaders, and VxWorks targets. These binaries use GOT2 position-independent code where r30 holds a per-function GOT2 anchor computed at runtime. Standard PLT resolution fails on these because LIEF discards Huawei vendor relocation types. `PPC32TaintTracker` resolves PLT stubs directly from raw ELF dynamic symbol entries when LIEF returns zero relocations, so taint paths through the network stack resolve correctly on both standard and vendor ELF formats.

---

## Where it's used <sup>[↑](#ppc32tainttracker)</sup>

- **Cisco IOS 7200 / 3700**: big-endian PPC32 router firmware
- **Huawei S6720 / S6720EI**: big-endian GOT2 PIC bootloaders
- **MikroTik RB600**: big-endian embedded Linux on PPC32
- **VxWorks embedded**: big-endian PPC32 RTOS firmware
- **POWER LE Linux userspace**: little-endian PPC32 shared libraries

---

## Safe usage <sup>[↑](#ppc32tainttracker)</sup>

**Pass `endian='little'` for POWER LE Linux binaries.** The default is big-endian. A wrong endian setting decodes every instruction incorrectly with no error.

**Verify GOT2 resolution if r30-relative calls are not matching sinks.** For GOT2 PIC binaries, check `tracker._func_r30` is populated. If `_func_r30` is empty, the `bcl`/`mflr r30` prologue was not found and external calls will not resolve.

**Check `tracker._plt` after construction for Huawei targets.** LIEF discards Huawei vendor relocation type `0x40000054` and returns zero PLT entries. The tracker falls back to raw dynsym loading, but confirm `_plt` is non-empty before analyzing a Huawei binary.

**Expect taint on r3 only for buffer-based sources.** `readfd, buf, n` writes data into the buffer argument and returns a byte count in r3. The tracker taints r3 from the return value, not the buffer contents. A finding requires the byte count to reach a sink register. Use `SinkArgClassifier` when taint returns no findings on a binary you expect to be vulnerable.

---

## Usage <sup>[↑](#ppc32tainttracker)</sup>

```python
from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker

tracker = PPC32TaintTracker.from_path('/path/to/bootload', endian='big')
findings = tracker.run_interprocedural(depth=4)
for f in findings:
    print(f)
```

`endian` defaults to `'big'`. Pass `'little'` for POWER LE Linux userspace binaries.

---

## ABI model <sup>[↑](#ppc32tainttracker)</sup>

PPC32 System V / EABI:

| Register | Role |
|---|---|
| r0 | Volatile scratch (holds LR in prologue: `mflr r0`) |
| r1 | Stack pointer never tainted |
| r2 | Small data anchor / TOC EABI/POWER, never tainted |
| r3–r10 | Integer argument registers; r3 = return value |
| r13–r31 | Callee-saved |
| r30 | PIC base register in GOT2 PIC binaries |

External calls always use `bctrl` branch via CTR with the target loaded from
GOT2: `lwz rX, N(r30)` / `mtctr rX` / `[crclr cr1eq]` / `bctrl`.

---

## GOT2 PIC support Huawei / embedded Linux <sup>[↑](#ppc32tainttracker)</sup>

PPC32 GOT2 PIC binaries reserve r30 as the per-compilation-unit GOT2 anchor.
Each function prologue captures the PC using a `bcl 20,31,$+4` / `mflr r30`
sequence and then adds a linker-computed offset:

```
bcl  20,31,$+4      ; LR ← bcl_addr + 4  (= mflr_addr)
mflr r30            ; r30 ← LR  (= mflr_addr)
addis r30, r30, HI  ; r30 += sign_extend(HI) << 16
addi  r30, r30, LO  ; r30 += sign_extend(LO)
```

`lr_val` for the base computation is the address of the `mflr` instruction itself.
Different compilation units use different HI/LO constants, so r30 is a per-function
value. The tracker pre-computes r30 for every function in `_func_r30`.

GOT2 entries that point to PLT stubs are indexed in `_got2_va_to_name`. At each
`bctrl` site the tracker computes `got2_va = r30 + disp` and resolves the name.

### LIEF limitation on Huawei PPC32 <sup>[↑](#ppc32tainttracker)</sup>

Huawei bootloaders use vendor-specific ELF relocation type `0x40000054`, which
LIEF reports as invalid and discards. This causes LIEF to return 0 JUMP_SLOT
relocations.

The tracker calls `_load_plt_from_dynsym_raw()` to load SHN_UNDEF dynamic
symbols with non-zero `st_value` directly from the raw ELF section headers.
These are the true PLT stub VAs. This fallback runs **only when LIEF populated
zero PLT entries** (`if not self._plt:`), which is always the case for Huawei
binaries with the vendor reloc type.

On SYSV PIC binaries IBM HPS, glibc `.so`, LIEF correctly populates `_plt`
from `.rela.plt` R_PPC_JMP_SLOT entries. The guard prevents
`_load_plt_from_dynsym_raw()` from running on these binaries; undefined
symbols in SYSV PIC have `st_value=0` and adding them would corrupt the PLT map.

### GCC `crclr cr1eq` between mtctr and bctrl <sup>[↑](#ppc32tainttracker)</sup>

GCC PPC32 emits `crclr cr1eq` (or `creqv`) between `mtctr rX` and `bctrl` as
a variadic calling convention indicator. The 2-instruction look-back pattern
`prev2=lwz, prev1=mtctr` breaks when this extra instruction is present.

The resolver handles this: when `prev1` is not `PPC_INS_MTCTR` but `prev2` is,
and `prev3` (the instruction 3 before `bctrl`) is `PPC_INS_LWZ`, the window
shifts one slot back to recover the `lwz+mtctr` pair.

### Prologue window <sup>[↑](#ppc32tainttracker)</sup>

PPC32 prologues save LR (`mflr r0`), spill callee-saved registers (`stmw r30`
or individual `stw r30`/`stw r31`), and set up the frame pointer before the
`bcl`/`mflr r30` pair. The `bcl` sits at instruction index 7+ on a typical
function, so a 64-byte 16-instruction window is used.

---

## Sources and sinks <sup>[↑](#ppc32tainttracker)</sup>

**Sources** mark r3 tainted after call:
`recv`, `recvfrom`, `recvmsg`, `read`, `pread`, `fread`, `fgets`, `gets`, `getenv`
and their `@plt` aliases.

**Note on buffer-based sources**: `readfd, buf, n` and `pread`/`recv` write
into the buffer argument r4 before the call. The return value in r3 is a byte
count. Register-level taint tracks r3; actual buffer contents flow through memory
and are not tracked. Findings require the return value to reach a sink register
without intermediate clobbering, which is uncommon. Use `SinkArgClassifier` for
broader argument-provenance classification when taint finds nothing.

**Sinks** fire when the listed arg register is tainted:

| Sink | Tainted arg | Notes |
|---|---|---|
| `system`, `popen` | r3 | command string |
| `execl`, `execle`, `execlp` | r3 | path |
| `execv`, `execvp`, `execve` | r3 | path |
| `strcpy`, `strcat` | r4 | src |
| `strcpy_s`, `strcat_s` | r5 | src Huawei secure variants |
| `sprintf` | r4 | fmt |
| `sprintf_s` | r5 | fmt |
| `snprintf` | r5 | fmt |
| `snprintf_s` | r6 | fmt |
| `memcpy`, `memmove` | r5 | count |
| `memcpy_s` | r6 | src |
| `malloc`, `calloc`, `realloc` | r3/r4 | size |

---

## Taint propagation <sup>[↑](#ppc32tainttracker)</sup>

Register taint propagates through arithmetic ops, logic ops, register moves, and `lwz` pointer dereferences from tainted base registers. `li`/`lis` immediate loads and `mflr` clear
destination taint. Loads from a non-tainted base register also clear destination
taint (the destination is being overwritten with an untainted value; prior taint
does not survive the overwrite).

Stack-level taint (tainted value stored via `stw` and later re-loaded via `lwz`)
is not tracked. Binaries that route all network data through stack buffers before
passing them to sinks will show 0 findings; use `SinkArgClassifier` for those.

---

## Interprocedural depth <sup>[↑](#ppc32tainttracker)</sup>

`run_interprocedural(depth=4)` seeds from functions that call a source, then
follows tainted arguments through direct BL calls up to `depth` hops. GOT2
indirect calls (`bctrl`) to unresolved internal function-pointer entries are
treated as clobbering r3–r10.

---

## Known limitations <sup>[↑](#ppc32tainttracker)</sup>

1. Memory taint: stack buffers are not modelled. Any flow that routes tainted
 data through a local buffer before the sink call is invisible to the tracker.

2. Unresolved GOT2 entries: only PLT stubs SHN_UNDEF dynsym entries are
 in `_got2_va_to_name`. GOT2 entries pointing to internal function pointers or
 data constants appear as `??` and clobber r3.

3. LIEF relocation bug Huawei-specific: LIEF silently discards relocations
 with vendor-specific types. `_load_plt_from_dynsym_raw()` works around this
 for Huawei GOT2-PIC binaries (triggered by `if not self._plt:` guard).
 SYSV PIC binaries (glibc `.so`) are not affected; LIEF handles their
 standard R_PPC_JMP_SLOT relocations correctly.

---

## Why this exists <sup>[↑](#ppc32tainttracker)</sup>

Prior to this module, ppc32tainttracker required manual work outside the Ablation pipeline. This module integrates the capability directly so findings feed the shared `PatternLibrary` and `FindingRegistry` without a separate toolchain.

---

## How it works <sup>[↑](#ppc32tainttracker)</sup>

Seeds the worklist with every call site of each configured source function. For each seeded location, a linear Capstone disassembly pass applies the taint lattice rules instruction by instruction, propagating taint through register moves, arithmetic, and memory operations. When a call instruction targets a PLT stub that resolves to a sink function and the relevant argument register is tainted, a `TaintFinding` is emitted. Internal calls push a new entry onto the worklist so taint follows the call graph interprocedurally up to `max_depth` levels.

---

## Example output <sup>[↑](#ppc32tainttracker)</sup>

```
[CRITICAL] system() at 0x4023A0
  source:   recv() at 0x401F00
  arg:      rdi (arg 0)
  chain:    recv→rdi → strcpy buf → system rdi
  path:     [0x401F00, 0x4020C0, 0x4023A0]
  severity: CRITICAL (exec sink, externally controlled argument)
```

---

## False positives <sup>[↑](#ppc32tainttracker)</sup>

The most common false positive is taint surviving a zero-clear instruction `xor rax, rax`. The `CLR` rule in the taint lattice clears taint unconditionally on self-XOR, but some architectures use different clearing idioms. Use `SinkArgClassifier` to pre-filter `RODATA_CONST` call sites before running the taint tracker, these are not findings regardless of register state.

---

## Pipeline position <sup>[↑](#ppc32tainttracker)</sup>

**Before this module:** `BinaryContext.load_or_build()`, then `SinkArgClassifier.classify_all()` to eliminate `RODATA_CONST` call sites. Only pass `ARG_PROPAGATED` and `UNKNOWN` sinks to the taint tracker.

**After this module:** `PathSolver` to confirm path feasibility. `FindingRegistry.register()` to record confirmed findings.

---

## Reading findings <sup>[↑](#ppc32tainttracker)</sup>

| Field | Content |
|:---|:---|
| `sink_name` | Name of the dangerous function reached |
| `sink_va` | Virtual address of the call site |
| `source_name` | Name of the taint source for example `recv`, `read` |
| `arg_index` | Which argument to the sink carries taint 0-indexed |
| `chain` | `[va, register, operation]` steps from source to sink |
| `path` | `[caller_va, ...]` function VAs traversed interprocedurally |
| `severity` | `CRITICAL` for exec sinks, `HIGH` for memory sinks |

---

## PowerPC prologue and epilogue patterns <sup>[↑](#ppc32tainttracker)</sup>

Function prologues and epilogues are consistent across PowerPC32 SysV ABI and are used by the taint tracker for function boundary detection:

**SysV ABI prologue (big-endian Cisco IOS style):**
```ppc
mflr     r0              # move LR to r0 (LR cannot be stored directly)
stw      r0, -4(r1)     # store r0 (saved LR) at stack[sp-4]
stwu     r1, -N(r1)     # decrement stack pointer by N (framesize), write back
stw      r31, N-4(r1)   # save callee-saved r31 (frame pointer or local)
stw      r30, N-8(r1)   # save callee-saved r30 (if needed)
```
Identifying characteristic: `MFLR r0` (op=31, XO=339 = MFSPR, SPR=8 = LR) within the first three instructions.

**SysV ABI epilogue:**
```ppc
lwz      r0, N+4(r1)    # reload saved LR
addi     r1, r1, N      # restore stack pointer (or `lwz r1, 0(r1)` via back chain)
mtlr     r0              # restore LR
blr                      # return (branch to LR)
```

**EABI prologue (embedded, Linux on MPC5xx/QorIQ):**
```ppc
mflr     r0
stw      r0, 4(r1)      # EABI: saved LR at [sp+4], not [sp-4]
stwu     r1, -N(r1)
```
The EABI saves LR at `[original_sp + 4]` (i.e., `[new_sp + N + 4]` after `stwu`), unlike SysV which saves at `[original_sp - 4]` (i.e., `[new_sp + N - 4]`). The taint tracker distinguishes these by the offset sign relative to r1 before and after `stwu`.

**Back chain pointer:** POWER ABI mandates that `0(r1)` always contains the previous stack frame's `r1` (the back chain pointer). `stwu r1, -N(r1)` is an update-indexed store that atomically decrements `r1` and stores the old value at `[new_r1]`. A stack overflow that corrupts the back chain pointer at `0(r1)` does not directly control the return address, but breaks stack unwinding and can facilitate other exploits.

---

## PPC64 and ELFv1 vs ELFv2 function descriptors <sup>[↑](#ppc32tainttracker)</sup>

PowerPC 64-bit introduces a significant complication: the ELFv1 ABI (used on AIX and old Linux on POWER) uses "function descriptors." A function pointer is not the address of the first instruction: it is the address of a 3-word descriptor:
```
descriptor[0]: actual code address (entry point)
descriptor[1]: TOC base (.got equivalent for POWER64)
descriptor[2]: environment pointer (closure, or NULL for normal functions)
```

When `BL target` is assembled with a function pointer value, the linker generates a PLT stub that loads `descriptor[0]` into CTR, loads `descriptor[1]` into `r2` (the TOC pointer), and then executes `BCTRL`. This is why `BL functionpointer` in AIX binaries is actually an indirect call through a descriptor.

ELFv2 (introduced for Linux on POWER8 in 2013) eliminates function descriptors. Function pointers are actual code addresses. Calls through function pointers are direct `BCTRL` after loading the address into CTR, setting `r12` to the callee address (for `r2` setup at callee entry).

The taint tracker targets PPC32 (always SysV OEA, no descriptors) by default. For PPC64 AIX targets (ELFv1), use `PPC64ELFv1TaintTracker` from `xcoff32-decompiler.md`.

---

## GOT/PIC addressing in PowerPC <sup>[↑](#ppc32tainttracker)</sup>

Position-independent PowerPC32 code uses `r30` (or another designated register) as a "base register" containing the address of the `.got2` section (analogous to `$gp` in MIPS). The PIC setup sequence in function prologues:

```ppc
bcl      20, 31, .L1    # branch-to-LR-like trick: BL to next instruction sets LR
.L1:
mflr     r30             # r30 = address of .L1 (current PC)
addis    r30, r30, ha16(_GLOBAL_OFFSET_TABLE_ - .L1)
addi     r30, r30, lo16(_GLOBAL_OFFSET_TABLE_ - .L1)
# r30 now = GOT base
```

External symbol references then use:
```ppc
lwz      r3, GOT_OFFSET(r30)   # load symbol address from GOT
mtctr    r3
bctrl                           # call via CTR
```

`BCL 20, 31, .L1` (op=16, BO=20, BI=31, LK=1) is a conditional branch that is always taken (BO=20 = branch unconditionally) and sets LR. The taint tracker recognizes this pattern and does not model `r30` as tainted from LR after this sequence.

---

## PowerPC instruction encoding reference <sup>[↑](#ppc32tainttracker)</sup>

PowerPC uses a fixed 32-bit instruction encoding. The primary formats:

**I-form (branch):**
```
 31    26 25                 2  1  0
[  op   ][      LI (24-bit)  ][AA][LK]
   6-bit          24             1   1
```
`BL target` → op=0x12, LK=1 (sets LR). `B target` → op=0x12, LK=0. `BLA target` → AA=1 (absolute address).

**B-form (conditional branch):**
```
 31    26 25   21 20   16 15            2  1  0
[  op   ][ BO  ][ BI   ][   BD (14-bit) ][AA][LK]
   6-bit    5      5           14            1   1
```
`BEQ label` → op=0x10, BO=0xC, BI=2 (eq bit of CR0). `BDNZ label` → BO=0x10 (CTR-- != 0).

Security-critical encodings for sink confirmation:
- `BL target26` (op=0x12, LK=1): direct call. Byte-verify: `word >> 26 == 0x12` and `word & 1 == 1`.
- `BCTRL` (op=19, XO=528, LK=1): indirect call via CTR. PLT stub tail call or function pointer dispatch.
- `STW r0, saved_lr(r1)` after `MFLR r0` → saved LR on stack. A buffer overflow reaching `saved_lr` controls the return address.

---

## PowerPC SoC variants and firmware targets <sup>[↑](#ppc32tainttracker)</sup>

**Cisco IOS (Classic, PPC):** PowerPC 603/604e based Cisco 7200, 7500, 12000 series routers. Monolithic binary with no dynamic linking. All system calls go through Cisco's internal kernel abstraction layer. Boot flash contains the IOS image at a fixed offset; RAM base is at `0x80000000`.

**IBM POWER (AIX, 32-bit):** IBM RS/6000, pSeries. XCOFF binary format. PowerPC 32-bit big-endian. Distinct from Cisco IOS: dynamic linking via XCOFF import/export symbols, different ABI for function pointers (function descriptor at `.opd` section). See `xcoff32-decompiler.md` and `re/ibm/` targets.

**Freescale/NXP QorIQ (e500/e6500):** Used in Cisco ISR G2 and Juniper MX80. Book E architecture (different privilege instructions from classic PowerPC OEA). `AltiVec` absent on Book E cores.

**Automotive ECU (VLE):** Variable-Length Encoding extension for Freescale MPC5xx/MPC56xx. See `ecu-vle-decoder.md`.

---

## Usage: full PowerPC firmware scan workflow <sup>[↑](#ppc32tainttracker)</sup>

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.sink_arg_classifier_ppc32 import SinkArgClassifierPPC32BE
from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker

ctx = BinaryContext.load_or_build('/firmware/ios_c7200.bin', arch='ppc32be')
classifier = SinkArgClassifierPPC32BE.from_context(ctx)
work = [s for s in classifier.classify_all()
        if s.classification in ('ARG_PROPAGATED', 'UNKNOWN')]
findings = PPC32TaintTracker.from_context(ctx).scan(sink_sites=work)

# Byte-verify: BL = op 0x12 with LK=1
data = open(ctx.binary_path, 'rb').read()
for f in findings:
    off = f.sink_va - ctx.base
    word = int.from_bytes(data[off:off+4], 'big')
    op = word >> 26
    assert op in (0x12, 0x13), f"Not a branch at {f.sink_va:#x}"
    ctx.set_name(f.sink_va, f"sink_{f.sink_name}", source="confirmed")
    print(f"[{f.severity}] {f.sink_name} @ {f.sink_va:#x}: r{3+f.arg_index} tainted from {f.source_name}")
```

---

## See also <sup>[↑](#ppc32tainttracker)</sup>

- [TaintAnalysis](taint-analysis.md): multi-architecture taint tracking reference
- [SinkArgClassifier](sink-arg-classifier.md): pre-filter RODATA_CONST sinks before taint
- [PathSolver](path-solver.md): confirm path feasibility after a taint hit
- [SinkPropagator](sink-propagator.md): extend sink coverage across wrappers
- [MIPS Taint Tracker](mips.md): equivalent for MIPS firmware; compare branch-and-link models
- [PPC476 Lifter](ppc476-lifter.md): IBM PowerPC 476 variant used in IBM BladeCenter targets
- [XCOFF32 Decompiler](xcoff32-decompiler.md): AIX/POWER XCOFF binary format parsing
- [ECU VLE Decoder](ecu-vle-decoder.md): Variable-Length Encoding extension for automotive PowerPC
- [RISC-V Taint Tracker](risc-v.md): RISC-V equivalent; no delay slots, no LR register, similar calling convention structure
- [Length Underflow Scanner](length-underflow.md): header-subtraction integer underflow in PowerPC networking code; combines with taint tracker when the length value flows from a network read
- [IPReg Annotator](ipreg-annotator.md): resolve indirect BCTRL calls through function pointer tables in PowerPC firmware before running taint tracker

---

## PowerPC taint tracker architecture <sup>[↑](#ppc32tainttracker)</sup>

`PPC32TaintTracker` implements the following taint model specific to the PowerPC32 register architecture:

**Register set tracked:** All 32 GPRs (`r0`–`r31`), plus the Link Register (LR), Count Register (CTR), and Condition Register (CR) as a single aggregate. The Floating-Point Registers (`f0`–`f31`) and AltiVec/VMX registers (`v0`–`v31`) are not tracked: firmware rarely passes user-controlled data through FP or SIMD registers to security-sensitive sinks.

**Taint sources:** `recv()`/`recvfrom()` → `r3` (return value = bytes received, `r4` contains buffer address). The buffer at `r4` is marked tainted. `fgets()` → `r3` (buffer pointer). `read()` → `r4` is the buffer. `sscanf()` writes tainted values into pointer arguments (`r4`, `r5`, ...).

**Call convention:** Arguments in `r3`–`r10`. Return value in `r3` (and `r4` for 64-bit on 32-bit ABI). When the taint tracker encounters a `BL` instruction with tainted `r3`–`r10` registers, it marks the called function as receiving tainted input and recursively traces the callee.

**Callee-saved registers:** `r14`–`r31` (SysV: `r13`–`r31` on embedded, `r14`–`r31` on big-endian Linux). The tracker preserves caller taint through call boundaries: a callee must restore callee-saved registers before `BLR`, so taint in `r15` before a call is still in `r15` after the call.

**Volatile registers cleared:** `r0`, `r3`–`r12`, `LR`, `CTR`, `CR` fields 0–1 are volatile across calls. The tracker clears their taint marks after each `BL`/`BCTRL`/`BLR` instruction, unless the return value (`r3`) is itself tainted (i.e., the called function returns user data).

---

## False positives <sup>[↑](#ppc32tainttracker)</sup>

**`r3` carries function return values from non-network sources.** In PowerPC, `r3` is both the first argument register and the return value register. A sequence like `BL strlen; CMPLWI r3, 0x100; BGT overflow_handler` uses `r3` as a length check, not a tainted value. The taint tracker marks `r3` as potentially tainted only when the preceding call is a known network source (`recv`, `fgets`, etc.) or a call chain traced through tainted arguments.

**`BCL 20, 31, .L1` is not a tainted indirect call.** This PIC setup pattern loads the current PC into LR via the branch-and-link mechanism. The taint tracker recognizes this specific form (BO=20, BI=31, LK=1, branch target = next instruction offset = +4) and does not propagate taint to LR from the PIC setup sequence.

**`MTCTR r12; BCTRL` in ELFv2 PLT stubs is not attacker-controlled.** ELFv2 requires `r12` = callee address on entry, so PLT stubs set `r12` from the GOT entry. The GOT value comes from the dynamic linker's relocation, not from user input. This pattern produces `BCTRL` with `r12` looking "externally loaded" but not tainted.

**AltiVec `STVX`/`LVX` stores and loads near buffers.** Some PowerPC networking code uses AltiVec for bulk memory copy (`STVX` + `LVX` in a loop). The taint tracker does not track AltiVec registers, so a tainted buffer copied via AltiVec may not be tracked. Manual review is required when `LVXL`/`STVXL` instructions appear near tainted memory ranges.

**`LMW r14, 0(r1)` restores multiple callee-saved registers.** The `LMW` (Load Multiple Word) instruction loads `r14`–`r31` from consecutive memory starting at the epilogue restore address. A stack overflow large enough to overwrite all 18 callee-saved register slots would taint them all via `LMW`. The taint tracker models `LMW` as a load of all targeted registers from the memory range.

---

## Pipeline position (expanded) <sup>[↑](#ppc32tainttracker)</sup>

**Firmware extraction for PowerPC targets:**
```bash
# Cisco IOS: extract from monolithic binary
# The IOS image starts with a compressed payload after a small decompressor stub
# Use binwalk to find the compressed segment
binwalk -e ios_c7200.bin
find _ios_c7200.bin.extracted/ -type f -name '*.elf' -o -name '*.bin' | head -5

# For AIX XCOFF: use xcoff32-decompiler.py to parse symbol table
python3 -m ablation.analyzers.xcoff32_decompiler /mnt/aix/usr/sbin/inetd
```

**Pre-scan checklist:**
1. Confirm endianness: PowerPC firmware is almost always big-endian (ELF `e_ident[EI_DATA]` = 2). Embedded Linux on NXP QorIQ may be little-endian (ELF `e_ident[EI_DATA]` = 1, `e_machine` = `EM_PPC` = 0x14).
2. Check for VLE flag: ELF section headers may have `SHF_PPC_VLE` (0x10000000) set. If present, use `ecu-vle-decoder.md` instead of `PPC32TaintTracker`.
3. Identify ABI: look for `MFLR r0; STW r0, -4(r1)` (SysV) vs `MFLR r0; STW r0, 4(r1)` (EABI) in the first 10 instructions of any function.
4. Identify PIC vs non-PIC: search for `BCL 20, 31, .L1; MFLR r30/r31` pattern in function prologues.

**After PPC32TaintTracker:** Confirmed findings go in `re/<vendor>/<target>_re.py`. Byte-verify the `BL` or `BCTRL` at `sink_va` before registering. For Cisco IOS targets: note that there is no PLT (monolithic binary), so all calls are direct `BL`; there is no `BCTRL` unless through a function pointer table.

**Estimated scan times (empirical):**
- Single function (avg 200 instructions): < 50 ms
- Full Cisco IOS 7200 binary (~885 functions): ~40 seconds with SemanticSearcher pre-filter + SinkArgClassifier + TaintTracker
- Full scan without pre-filter: ~8 minutes (not recommended: too many false positives from `RODATA_CONST` sinks)

**Important: Cisco IOS has no `system()` in the traditional sense.** Cisco IOS Classic does not expose a POSIX shell to the management plane. Command injection in Cisco IOS must reach a Cisco-internal "exec parser" function (identifiable by calling convention: the command string is in `r3`, parsed via Cisco's TCL-like parser). `SemanticSearcher.query("exec parser command string")` identifies these call sites. Standard `SinkArgClassifier` sink names (`system`, `popen`, `execv`) do not apply to Cisco IOS Classic. Use the Cisco-specific sink list from `re/cisco/sink_list_ios.py` in the findings module.

**PowerPC big-endian quick identification (ELF header parse):**
```python
with open('/path/to/binary', 'rb') as f:
    e_ident = f.read(16)
    ei_class = e_ident[4]    # 1 = 32-bit, 2 = 64-bit
    ei_data  = e_ident[5]    # 1 = little-endian, 2 = big-endian
    f.seek(18)
    e_machine = int.from_bytes(f.read(2), 'big' if ei_data == 2 else 'little')
    # EM_PPC = 0x0014 (PowerPC 32-bit)
    # EM_PPC64 = 0x0015 (PowerPC 64-bit)
    print(f"{'PPC32' if e_machine == 0x14 else 'PPC64'} {'BE' if ei_data == 2 else 'LE'}")
    # VLE check: scan section headers for SHF_PPC_VLE flag (0x10000000) on any section
    # If SHF_PPC_VLE is set: use ecu-vle-decoder.md workflow instead of PPC32TaintTracker
    # Mixed-VLE binaries (some sections VLE, others not) require per-section decoder switching
```
