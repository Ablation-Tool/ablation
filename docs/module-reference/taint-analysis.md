# Taint Analysis

Interprocedural data-flow tracking from network entry points to security-sensitive sinks. The tracker follows tainted data across function call boundaries, resolving PLT stubs to import names at every hop. Covers 14 architectures under one API.

---

## Why this exists

Three things were not possible before the taint stack existed in Ablation:

**1. Cross-architecture vulnerability scanning without a commercial disassembler.**
IDA Pro and Binary Ninja can taint-track x86-64 with plugins, but neither has first-class support for LoongArch64, nanoMIPS, V850, or ARC. Every target on a new architecture required writing a fresh one-off taint model in a disassembler scripting API, losing the work at the end of the engagement. Ablation's taint stack covers 14 architectures under one API: `TrackerClass.from_path(elf).run_interprocedural()` runs on any supported target. Every confirmed finding feeds back into the shared PatternLibrary.

**2. Interprocedural traces that cross PLT boundaries.**
Single-function taint analysis stops at every `call strcpy` or `call malloc`. The PLT entry is a stub, not real code, so a single-function analysis sees the call and stops. Ablation's interprocedural engine walks the call graph, resolves each PLT stub to its import name, and continues through calling functions. A taint path that crosses three callers and ends in a `strcpy` in a helper function surfaces as one finding with the complete call trace.

**3. Stack slot tracking across architecture ABI differences.**
x86-64, ARM64, MIPS32, PPC32, and LoongArch64 all pass function arguments differently: register counts, callee-save conventions, stack frame layout. A generic tracker that ignores ABI details produces false positives on any architecture that does not match its assumptions. Each tracker in Ablation models the target ABI precisely: register width, argument registers, caller-saved vs callee-saved sets, stack growth direction.

---

## How it works

### Full pipeline

```
  network-facing binary (ELF or Mach-O)
          |
          v
  ┌────────────────────────────────────────────────────────────┐
  │  TrackerClass.from_path(elf)                               │
  │    BinaryContext.load_or_build()                           │
  │      plt dict:    {stub_VA -> import_name}                 │
  │      func_starts: sorted list of function entry VAs        │
  │      call_edges:  [(caller_va, callee_va, label)]          │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              v
  ┌────────────────────────────────────────────────────────────┐
  │  run_interprocedural()                                     │
  │                                                            │
  │  for each known source (recv, read, fgets, ...):           │
  │    find all callers of that source in call_edges           │
  │    seed worklist: [(caller_va, depth=0, taint_state={})]   │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              v
  ┌────────────────────────────────────────────────────────────┐
  │  Intra-function taint pass (one function per iteration)    │
  │                                                            │
  │  Capstone linear disassembly of function body              │
  │  for each instruction, apply the taint policy:             │
  │                                                            │
  │    XFER  (mov/ldr/str)  dst ← src_taint                    │
  │    ALU   (add/sub/and)  dst ← op1_taint | op2_taint        │
  │    CLR   (xor r, r)     dst ← {}        (clears taint)     │
  │    LEA                  dst ← base_taint | index_taint      │
  │    CALL  (source fn)    return_reg ← {source_label}        │
  │    CALL  (sink fn)      if arg_reg tainted → emit finding  │
  │    CALL  (other fn)     caller-saved regs ← {}; callee-saved kept │
  │                                                            │
  │  Stack slot model:                                         │
  │    "mov [rbp-8], rdi" where rdi is tainted:                │
  │      slot_map[rbp-8] = tainted                             │
  │    "mov rdi, [rbp-8]" before a sink call:                  │
  │      rdi ← slot_map[rbp-8].taint                           │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              | tainted argument found at call site
                              v
  ┌────────────────────────────────────────────────────────────┐
  │  PLT stub resolution                                       │
  │                                                            │
  │  is callee_va in plt_section_range?                        │
  │    yes → import_name = plt[callee_va]                      │
  │           import_name in sink_table?                       │
  │             yes → emit TaintFinding                        │
  │             no  → propagate taint through return value     │
  │    no  → push (callee_va, depth+1) onto worklist           │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              | taint escapes via return or output pointer arg
                              v
  ┌────────────────────────────────────────────────────────────┐
  │  Caller propagation                                        │
  │                                                            │
  │  return register carries taint back into the caller frame  │
  │  output pointer arguments (e.g., dst buf in arg[1])        │
  │    propagate taint to the pointed-to memory region         │
  │  continue DFS until call graph exhausted or max_depth hit  │
  └────────────────────────────────────────────────────────────┘
```

### The taint lattice

All trackers implement the libdft taint policy (Andriesse, "Practical Binary Analysis", ch. 11) adapted for static analysis. The policy defines a two-element lattice over each register and memory location. A location is either clean (`{}`) or tainted (`{source_label}`). The label tracks which source the taint originated from, so multi-source binaries produce separate findings per source.

```
  Taint lattice for a single location L:
    clean   = {}
    tainted = {source_label}

  Meet operator (join at merge points in CFG):
    {} | {} = {}
    {A} | {} = {A}
    {A} | {A} = {A}
    {A} | {B} = {A, B}   (both sources taint this location)

  Instruction class     Propagation rule
  ─────────────────────────────────────────────────────────────────
  XFER  (mov/ldr/str)   dst_taint = src_taint
  ALU   (add/sub/and)   dst_taint = taint(op1) | taint(op2)
  CLR   (xor r, r)      dst_taint = {}
  LEA                   dst_taint = taint(base) | taint(index)
  CALL  (source fn)     return register = {source_label}
  CALL  (sink fn)       finding if relevant arg register is tainted
  CALL  (other fn)      caller-saved registers = {}; callee-saved preserved
```

The `|` operator is set union. In a single-source binary it reduces to boolean OR, but the label set preserves provenance: `{recv, fgets}` means the location carries taint from both sources independently. A sink finding with two labels means two independent code paths reach the same dangerous call.

The `CLR` rule is the most important false-positive filter. `xor rax, rax` on x86-64 unconditionally zeroes `rax` regardless of its tainted state. Without this rule, taint would survive zero-initialization sequences and produce false positives on every stack frame that homes a tainted register before clearing it.

### PLT resolution in depth

The ELF Procedure Linkage Table is a region of stub functions. Each stub on x86-64 is 16 bytes:

```
  PLT stub for 'strcpy' at 0x403020:
    0x403020:  jmp QWORD PTR [rip+0x20ba9a]   <- GOT entry (lazy-resolved)
    0x403026:  push 0x3                         <- relocation index
    0x40302b:  jmp 0x4030b0                     <- dynamic linker resolver

  ELF relocation table (.rela.plt):
    offset=0x603020, sym='strcpy', type=R_X86_64_JUMP_SLOT

  At static analysis time, GOT[strcpy] has not been resolved.
  The tracker identifies stubs by VA range and maps each to its symbol name
  via the relocation table directly, without needing the GOT to be resolved.
```

When the interprocedural walk hits a call to any VA within the `.plt` section range, it looks up the import name and checks it against the sink table immediately. The actual GOT resolution that happens at runtime is irrelevant.

On PPC32 with GOT2 PIC, call sequences go through a `.got2` trampoline. `PPC32GOT2Resolver` unwraps these before the interprocedural walk begins so call edges in the call graph already point to import names, not trampoline VAs.

### Stack slot tracking by architecture

Stack slot tracking extends the register taint model to memory. When a tainted register is stored to a stack-relative address, that slot address is added to the slot map. When any register is loaded from a tracked slot, the taint transfers to the destination register.

```
  x86-64 stack frame model:
    rbp - 8:   first local variable (rbp-relative, stable offset)
    rsp - 8:   also valid (rsp-relative with push/pop delta tracking)

    push/pop tracking: each push decrements rsp by 8; each pop increments it.
    The tracker adjusts all rsp-relative slot addresses by the running delta
    so that "mov [rsp-8], rdi" before a push and "mov rdi, [rsp+0]" after the
    push refer to the same slot.

  ARM64 stack frame model:
    sp + 0:   x0 home slot (AArch64 PCS allows but does not require homing)
    sp + 8:   x1 home slot
    x29:      frame pointer (= sp at function entry in AAPCS64)
    x30:      link register (lr) — callee-saved, cleared of taint on return

  MIPS32 stack frame model (O32 ABI):
    $sp + 0:  $a0 home slot  (O32 requires homing ALL four arg regs)
    $sp + 4:  $a1 home slot
    $sp + 8:  $a2 home slot
    $sp + 12: $a3 home slot
    $fp:      frame pointer when the compiler allocates a variable-size frame

    The mandatory homing is why naive trackers fail on MIPS32: they see a store
    of a tainted $a0 to [$sp+0] at function entry and then a reload from [$sp+0]
    before a call, treating it as a stack-to-stack taint path rather than recognizing
    the home store and reload as the same data.

  PPC32 stack frame model:
    r1 + 8:   saved LR
    r1 + 24:  $r3 (first arg) home slot
    r1 + 28:  $r4 home slot
    r30:      GOT2 base register in PIC code; carries no taint semantics

  LoongArch64 stack frame model (LP64 ABI):
    $sp + 0:   $a0 home slot
    $fp:       frame pointer ($fp = $r22)
    $ra:       return address ($r1) — callee-saved
```

---

## Architecture coverage

| Architecture | Tracker class | Notes |
|---|---|---|
| x86-64 | `TaintTracker` | Full: RIP-relative strings, stack delta, SIMD clear |
| x86-32 | `X86_32TaintTracker` | CDECL32; PIC and non-PIC PLT |
| ARM64 | `ARM64TaintTracker` | `from_path_full` injects eh_frame func starts |
| ARM32 | `ARM32TaintTracker` | `thumb=True` for Thumb2 binaries |
| MIPS32 | `MIPS32TaintTracker` | `endian='big'` for big-endian RouterOS |
| MIPS64 | `MIPS64TaintTracker` | `endian='big'` for IOS/OCTEON |
| nanoMIPS | `NanoMIPSTaintTracker` | Two-path: Capstone 6.x or conservative fallback |
| PPC32 | `PPC32TaintTracker` | `endian='big'`; GOT2-PIC call resolution |
| PPC64 | `PPC64TaintTracker` | IBM POWER, AIX; `endian='big'` |
| LoongArch64 | `LoongArch64TaintTracker` | Pure Python; Capstone has no LA64 support |
| RISC-V 32 | `RISCV32TaintTracker` | HiSilicon WS63 extension via `ext_decoder=` |
| RISC-V 64 | `RISCV64TaintTracker` | SiFive, VisionFive 2 |
| ARC | `ARCTaintTracker` | Marvell, Seagate; check `ARCDecoder().has_full_decode` |
| V850 | `V850TaintTracker` | RH850/G3M ECU; endian auto-detected |

---

## Sources and sinks

| Category | Functions |
|---|---|
| Sources | `recv`, `recvfrom`, `recvmsg`, `read`, `fgets`, `gets`, `fread` and vendor wrappers |
| Exec sinks | `system`, `popen`, `execve`, `execl`, `execvp`, `execvpe` |
| Memory sinks | `strcpy`, `strcat`, `sprintf`, `snprintf`, `vsprintf`, `memcpy`, `memmove`, `bcopy` |
| Scripting sinks | `Tcl_Eval`, `lua_dostring`, `fm_exec_cli` |

Custom sinks are added per engagement via `custom_sinks={'my_exec': {0: 0}}` where the dict value is `{arg_position: min_tainted_length}` (0-indexed).

Vendor-specific sinks load via `VendorProfile`:

```python
from ablation.analyzers.vendor_profile import VendorProfile
profile = VendorProfile.from_vendor('fortinet')
profile.apply_to(tracker)
```

---

## Usage

All trackers share the same interface:

```python
from ablation.analyzers.taint_tracker_arm64 import ARM64TaintTracker

findings = ARM64TaintTracker.from_path_full('/path/to/bmcfirmware').run_interprocedural()
for f in findings:
    print(f)
```

For x86-64 with a pre-built context:

```python
from ablation.analyzers.xref_graph import XRefGraph
from ablation.analyzers.taint_tracker_x86 import TaintTracker

xg = XRefGraph.from_path(binary)
xg.build()

tracker = TaintTracker(binary, xref=xg, custom_sinks={'my_sink': {0: 0}})
findings = tracker.run_interprocedural()
```

---

## Reading findings

Each `TaintFinding` includes:

| Field | Content |
|---|---|
| `sink_name` | Name of the dangerous function reached |
| `sink_va` | VA of the call site in the binary |
| `source_name` | Name of the taint source (e.g., `recv`) |
| `arg_index` | Which argument to the sink is tainted (0-indexed) |
| `chain` | List of `(va, register, operation)` steps from source to sink |
| `path` | List of caller function VAs traversed interprocedurally |

A finding with `path=[0x1000, 0x2000, 0x3000]` means taint entered at `0x1000`, passed through `0x2000`, and reached the sink call in `0x3000`.
