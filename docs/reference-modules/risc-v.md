# RISCVTaintTracker

  - [What is RISC-V?](#what-is-risc-v)
    - [ISA modularity: base plus extensions](#isa-modularity-base-plus-extensions)
    - [Register file and calling convention](#register-file-and-calling-convention)
    - [Compressed instructions (RVC)](#compressed-instructions-rvc)
    - [Privilege levels and CSRs](#privilege-levels-and-csrs)
    - [RE implications](#re-implications)
  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [False positives](#false-positives)
  - [Pipeline position](#pipeline-position)
  - [Reading findings](#reading-findings)
  - [See also](#see-also)

**File:** `ablation/analyzers/taint_tracker_riscv.py`

---

## What is RISC-V? <sup>[↑](#riscvtainttracker)</sup>

RISC-V (pronounced "risk five") is an open-standard RISC instruction set architecture originating from the University of California, Berkeley, where Krste Asanović and collaborators published the first specification in 2010. Unlike proprietary ISAs (ARM, MIPS, x86), RISC-V is royalty-free and open: anyone can implement it in silicon without a license. The RISC-V International Foundation (founded 2015, moved to Switzerland in 2020) maintains the specifications.

The architecture is designed for extensibility. Instead of a monolithic ISA, RISC-V defines a minimal base integer instruction set (RV32I for 32-bit, RV64I for 64-bit) and a set of standard extensions that processors optionally implement. A processor that advertises "RV64GC" implements the G (general-purpose: I + M + A + F + D extensions) plus C (compressed 16-bit instructions). This modularity means a RISC-V IoT microcontroller and a RISC-V server CPU can differ dramatically in their instruction sets while sharing the same base encoding.

RISC-V adoption is accelerating. SiFive (founded 2015) produces commercially-deployed RISC-V SoCs. Western Digital ships RISC-V in SSD controllers. Alibaba's T-Head division ships the XuanTie C906/C910 in smart speakers and industrial controllers. HiSilicon (Huawei) ships custom RISC-V extensions in power management controllers embedded in Kirin SoCs. Espressif's ESP32-C3/C6 and Bouffalo Lab's BL602/BL616 use RISC-V for IoT firmware. Microchip's PolarFire SoC uses RISC-V for embedded Linux applications. The architecture will be a significant RE target as these devices mature.

### ISA modularity: base plus extensions <sup>[↑](#riscvtainttracker)</sup>

Understanding which extensions are present is critical for disassembly and taint analysis. An instruction encoding that is valid in RV32I+M decodes differently (or traps) without the M extension.

| Extension | Name | Key instructions |
|---|---|---|
| I | Base integer | `LUI`, `AUIPC`, `JAL`, `JALR`, `BRANCH`, `LOAD`, `STORE`, `OP-IMM`, `OP` |
| M | Multiply/divide | `MUL`, `MULH`, `DIV`, `DIVU`, `REM`, `REMU` — integer overflow patterns |
| A | Atomic | `LR.W`, `SC.W`, `AMOSWAP`, `AMOADD` — lock-free concurrent data structures |
| F / D | Float / Double | `FLW`, `FSW`, `FADD.S`, etc. — rarely relevant to security analysis |
| C | Compressed | 16-bit encodings for common 32-bit instructions; see below |
| Zicsr | CSR access | `CSRRW`, `CSRRS`, `CSRRC` — privilege-level switching, timer access |
| Zifencei | Instruction fence | `FENCE.I` — used after JIT code write; marks code generation patterns |

HiSilicon and SiFive ship custom vendor extensions that are not in the RISC-V standard. The `HiSiliconRV32ExtDecoder` handles these for HiSilicon's RISC-V management cores.

### Register file and calling convention <sup>[↑](#riscvtainttracker)</sup>

RISC-V defines 32 integer registers (`x0–x31`) and 32 floating-point registers (`f0–f31`). `x0` is hard-wired to zero. The RISC-V standard calling convention (used by Linux, most embedded RTOSes):

| Register | ABI name | Role |
|---|---|---|
| `x0` | `zero` | Hard-wired zero |
| `x1` | `ra` | Return address (set by `JAL`/`JALR`; saved on stack if function makes calls) |
| `x2` | `sp` | Stack pointer. 16-byte aligned at function boundaries. |
| `x3` | `gp` | Global pointer. Points into a small data area (runtime constant). |
| `x4` | `tp` | Thread pointer. Points to thread-local storage. |
| `x5–x7` | `t0–t2` | Caller-saved temporaries. |
| `x8–x9` | `s0 / fp`, `s1` | Callee-saved. `s0` doubles as the frame pointer when used. |
| `x10–x11` | `a0–a1` | Function arguments and return values. `a0` = first arg / return value. |
| `x12–x17` | `a2–a7` | Additional function arguments (up to 8 total in registers). |
| `x18–x27` | `s2–s11` | Callee-saved. Preserved across calls. Use for freed-pointer tracking. |
| `x28–x31` | `t3–t6` | Caller-saved temporaries. |

**Key difference from ARM and MIPS**: RISC-V has 8 argument registers (`a0–a7`) where MIPS-32 has 4 (`$a0–$a3`). Network recv wrappers with more than 4 arguments pass all of them in registers on RISC-V, so taint does not spill to the stack at the call boundary.

### Compressed instructions (RVC) <sup>[↑](#riscvtainttracker)</sup>

The C extension adds 16-bit compressed encodings for the most common 32-bit instructions. In an RV64GC binary, roughly 25-40% of instructions are 16-bit. The key RE challenge is that a compressed and uncompressed instruction can have the same semantic meaning but different encodings, and a disassembler that does not support C will misalign at the first compressed instruction and corrupt every subsequent instruction boundary.

Compressed instructions operate on a restricted register subset (`c.addi`, `c.lw`, etc. use `x8–x15`), with some exceptions (`c.addi16sp` operates on `x2`). The `C.JR` and `C.JALR` compressed indirect branches are common in code generated by GCC with `-mcompressed`. Taint propagation through `c.mv` (the compressed move) must treat it identically to `mv` (the uncompressed pseudo-instruction `ADDI rd, rs, 0`).

### Privilege levels and CSRs <sup>[↑](#riscvtainttracker)</sup>

RISC-V defines four privilege levels: Machine (M), Hypervisor (H), Supervisor (S), User (U). Firmware typically runs in M-mode; a Linux kernel runs in S-mode; userspace in U-mode. Privilege switching uses `ECALL` (system call: U→S or U→M), `MRET`/`SRET` (return from trap), and trap delegation.

Control and Status Registers (CSRs) are accessed via `CSRRW`/`CSRRS`/`CSRRC` instructions. Security-relevant CSRs include: `mtvec` (trap vector address: RCE target if writable from S-mode), `satp` (page table base: escalation target), `pmpaddr0–15` / `pmpcfg0–3` (physical memory protection: sandbox escape target).

For kernel RE work, identifying `ECALL` sites and their argument registers (`a0–a7`) is the primary source-labeling step. The taint tracker labels `a0` on entry to every `ECALL` handler as syscall-argument-sourced.

### RE implications <sup>[↑](#riscvtainttracker)</sup>

**PC-relative addressing**: RISC-V has no absolute addressing. All data and code references use `AUIPC` + `ADDI`/`JALR` pairs: `AUIPC x1, hi20; ADDI x1, x1, lo12`. The PLT is reached through `AUIPC + JALR` where the immediate computes the distance to the PLT stub. The tracker resolves these pairs to identify imported function calls.

**Identifying network sources in embedded Linux**: Standard `read()` / `recv()` syscalls use `a0` (fd), `a1` (buffer ptr), `a2` (length). The return value (byte count) is in `a0`. Taint `a0` (return value) and the buffer at `[a1, a2)` as network-sourced after any `ECALL` with `a7 = 63 (read)` or `a7 = 165 (recvfrom)`.

Labeled-taint analysis, CFG-fixpoint dataflow, and structural lifting for RISC-V 32-bit and 64-bit binaries: covering RV32I/M/A/C and RV64GC Linux psABI targets.

---

## Why this exists <sup>[↑](#riscvtainttracker)</sup>

1. RISC-V has two distinct calling convention variants with different register widths. RV32 uses `a0-a7` as 32-bit argument slots; RV64 uses the same register names with 64-bit slots. A tracker that confuses them produces incorrect taint bounds and misses sink arguments. `taint_tracker_riscv32.py` and `taint_tracker_riscv64.py` provide independent ABI-correct implementations. `taint_tracker_riscv.py` adds a labeled-taint `TaintEngine` with a `Width` enum that selects the correct variant at construction.

2. The labeled-taint model in `taint_tracker_riscv.py` provides two capabilities the binary-path trackers lack. Label provenance records which source function tainted each register. Bound tracking records `andi`/`ori` immediate masks in a `bound` field, gating out-of-bounds index findings. `TaintState.join()` merges taint from CFG merge-points, and `analyze_cfg()` runs a fixpoint analysis over `cfg_riscv.py` basic blocks, finding flows that linear traversal misses on loops and conditional branches.

3. RISC-V compressed instructions (RVC, 16-bit `c.*` mnemonics) appear in GCC-compiled RV64GC binaries. A decoder that handles only 32-bit instructions silently skips 16-bit instructions and produces incorrect CFG edges. `insn_riscv.py` handles both encodings in the same decoder. `cfg_riscv.py` correctly resolves `c.j`, `c.beqz`, and `c.bnez` branch instructions to build complete CFGs.

---

## How it works <sup>[↑](#riscvtainttracker)</sup>

```mermaid
flowchart TD
    A(["taint_tracker_riscv.TaintEngine(Width.RV64)"]):::input --> B["TaintEngine setup:\n  width = Width.RV64 (or RV32)\n  regs: {ra,sp,gp,tp,t0-t6,s0-s11,a0-a7} = Taint()\n  Sources: recv/recvfrom/read/fgets/gets/fread\n    (return value in a0)"]:::primary
    B:::primary --> C["taint_register(reg, label) · seed initial taint\ne.g. taint_register('a0', 'user-input')"]:::secondary
    C:::secondary --> D["run(insns: Iterable[Insn]) or analyze_cfg()\n\nLinear dispatch (run):\n  ld/lw/lb/lhu (load) · propagate taint from memory\n  sd/sw/sb (store) · store tainted value to memory\n  add/addi/sub (arithmetic) · union taint labels\n  and/andi (bitwise AND) · bound = immediate if AND with immediate\n  or/ori/xor/xori (bitwise) · union labels\n  mv/lui/li (move/immediate) · clear/assign\n  jal/jalr (call) · check PLT sink list; propagate args\n  beq/bne/blt/bge/bltu/bgeu (branch) · both edges explored\n  c.* RVC: c.add/c.lw/c.sw/c.j/c.beqz/c.bnez handled inline\n\nCFG fixpoint (analyze_cfg):\n  Build CFG via cfg_riscv.build_cfg(insns)\n  TaintState.join() at merge-points\n  Iterate to fixpoint (state.same_as(prev) check)"]:::tertiary
    D:::tertiary --> E(["Sinks: system/execve/execl/execvp\n  popen/strcpy/strcat/sprintf/vsprintf\n  snprintf/vsnprintf/memcpy/memmove/gets\n  (match by PLT symbol name or known VA)\n  → Finding(severity, source, sink, chain, va, bound)"]):::output

    F(["taint_tracker_riscv32.py / taint_tracker_riscv64.py\nBinary-path (non-labeled) trackers:\n  from_path(binary, sources=[...], sinks=[...])\n  run() → List[Finding]\n  RV32: 32-bit regs; RV64: 64-bit regs; psABI a0-a7 both"]):::input

    G(["insn_riscv.from_listing(text):\nParse objdump listing (address: hex mnemonic operands)\nInsn(va, mnemonic, operands) · handles 16-bit RVC mnemonics\n\ncfg_riscv.build_cfg(insns):\nBranch: beq/bne/blt/bge + RVC c.beqz/c.bnez\nCall: jal (non-ra target) / jalr with ra\nReturns: jalr ra (ret pseudo) / c.jr ra"]):::input
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

### Module inventory <sup>[↑](#riscvtainttracker)</sup>

| Module | Role |
|:---|:---|
| `taint_tracker_riscv.py` | Labeled-taint `TaintEngine` with `Width` enum; CFG fixpoint via `analyze_cfg()`; TCL3 qualified |
| `taint_tracker_riscv32.py` | Binary-path taint tracker for RV32 targets |
| `taint_tracker_riscv64.py` | Binary-path taint tracker for RV64 targets |
| `insn_riscv.py` | RV32/RV64 + RVC instruction decoder; `from_listing()` and `from_capstone()` |
| `cfg_riscv.py` | RISC-V CFG builder: branch/call/return edges; RVC-aware |
| `isa_riscv.py` | ISA constant tables: register names, ABI roles, psABI calling convention |
| `analysis_riscv.py` | `analyze_cfg()`: CFG fixpoint dataflow for labeled taint |

---

## Usage <sup>[↑](#riscvtainttracker)</sup>

```python
from ablation.analyzers.taint_tracker_riscv import TaintEngine, Width

# RISCVTaintTracker
from ablation.analyzers.insn_riscv import from_listing
eng = TaintEngine(Width.RV64)
eng.taint_register("a0", "user")
findings = eng.run(from_listing(objdump_text))
for f in findings:
    print(f"{f.address:#x} [{f.kind}] {f.detail} <- {sorted(f.labels)}")

# RISCVTaintTracker
from ablation.analyzers.analysis_riscv import analyze_cfg
from ablation.analyzers.taint_tracker_riscv import TaintState

init = TaintState(Width.RV64)
init.taint_reg("a0", "user")
result = analyze_cfg(insns, Width.RV64, initial=init)

# RISCVTaintTracker
from ablation.analyzers.taint_tracker_riscv64 import RV64TaintTracker
tracker = RV64TaintTracker.from_path('/path/to/riscv64.elf')
findings = tracker.run()

# RISCVTaintTracker
from ablation.analyzers.binary_lifter import BinaryLifter
lifter = BinaryLifter.from_path('/path/to/rv64.elf', arch='rv64')
print(lifter.lift_function(0x10430))

# RISCVTaintTracker
lifter32 = BinaryLifter.from_path('/path/to/rv32.elf', arch='rv32')
print(lifter32.lift_function(0x10000))
```

---

## Example output <sup>[↑](#riscvtainttracker)</sup>

The following illustrates the format for representative taint findings. Actual values reflect the specific binary.

```
[CRITICAL] read → execve @ <va>
  Chain: read(a0) → addi a1, a0, 0 → jal execve
  Width: RV64; Taint: a0 label={'user'}, bound=None

[HIGH] fgets → sprintf @ <va>
  Chain: fgets(a0) → mv a1, a0 → jal sprintf(a0=<fmt>, a1=tainted)
  Width: RV64; Taint: a1 label={'user'}, bound=None
  Sink: sprintf arg-1 - format string candidate

CFG fixpoint (analyze_cfg):
  Block <va>: a0 = Taint({'user'}, None)
  Block <va> (merge): a0 = join(Taint({'user'}, None), Taint()) = Taint({'user'}, None)
  Block <va>: sink jal strcpy - a1 tainted
```

---

## False positives <sup>[↑](#riscvtainttracker)</sup>

**`andi` with an immediate bounds the taint but does not clear it.** A tainted register masked with `andi a0, a0, 0x3f` has `bound=0x3f` maximum value 63. This is not a false positive, it constrains which sinks are reachable, but a tainted index bounded to 63 can still cause a buffer overflow if the destination buffer is fewer than 64 bytes. The bound is a taint-narrowing signal, not a safe-access guarantee.

**CFG fixpoint analysis on loops may report the same taint path multiple times if the loop body contains a sink.** Each fixpoint iteration that visits a basic block with a sink generates a finding. Deduplicate by `source, sink, va` before reporting.

**`taint_tracker_riscv.py` the labeled-taint TCL3 module and `taint_tracker_riscv64.py` binary-path module have different source/sink lists.** The labeled-taint module's source/sink configuration is in `SOURCES`/`SINKS` constants at module level; the binary-path module accepts `sources=` and `sinks=` constructor arguments. Confirm which module is in use before interpreting findings.

---

## Pipeline position <sup>[↑](#riscvtainttracker)</sup>

**Before this module:** For RVC compressed instruction binaries, confirm that `insn_riscv.from_listing()` or `from_capstone()` parses the 16-bit instructions correctly: `objdump --disassemble-all -M no-aliases` is the recommended listing input for RISC-V. For bare-metal RV32 targets no OS, no glibc, define custom source/sink lists in the binary-path tracker constructor.

**After this module:** Feed confirmed findings into `FindingRegistry.register()`. For CFG fixpoint findings, verify that the taint path is reachable in one concrete execution by checking whether the basic blocks in the chain are connected in the CFG.

---

## Reading findings <sup>[↑](#riscvtainttracker)</sup>

`RISCV64TaintTracker.from_context(ctx).run()` returns `List[TaintFindingRISCV64]`.

| Field | Type | Content |
|:---|:---|:---|
| `binary` | `str` | Binary path |
| `func_va` | `int` | VA of the function containing the sink call |
| `func_name` | `str` | Name of the function (from `ctx`) |
| `sink_va` | `int` | VA of the sink call instruction |
| `sink_name` | `str` | Sink function name for example `system`, `execve` |
| `tainted_args` | `List[int]` | 0-indexed argument positions that are tainted at the call |
| `source_name` | `str` | Taint source label for example `read`, `recv` |

The RISC-V 32-bit tracker (`taint_tracker_riscv32.py`) returns `TaintFindingRISCV32` with the same fields. bound from andi/ori: `int` or `None` if unbounded |

---

## RISC-V ABI stack frame layout <sup>[↑](#riscvtainttracker)</sup>

RISC-V uses a standard stack frame layout similar to other RISC architectures but with no dedicated frame pointer register (though `s0`/`fp` is used as frame pointer when `-fno-omit-frame-pointer` is enabled):

```
High address
  ┌─────────────────────────────┐
  │ argument 9+ (if any)        │  ← stack args at [caller_sp]
  ├─────────────────────────────┤  ← callee's [sp + frame_size]
  │ saved ra (return addr)      │
  │ saved s0 (frame pointer)    │
  │ saved callee-saved regs     │  (s1–s11 as needed)
  │ local variables             │
  │ (alignment padding)         │
  └─────────────────────────────┘
Low address ← sp (after prologue)
```

**Standard prologue pattern:**
```asm
addi  sp, sp, -N       # allocate frame (N = framesize, must be 16-byte aligned)
sd    ra, (N-8)(sp)    # save return address (RV64; sw for RV32)
sd    s0, (N-16)(sp)   # save frame pointer
addi  s0, sp, N        # set frame pointer = old sp
```

**Standard epilogue:**
```asm
ld    ra, (N-8)(sp)    # restore return address
ld    s0, (N-16)(sp)   # restore frame pointer
addi  sp, sp, N        # restore stack pointer
ret                    # = JALR zero, ra, 0
```

The taint tracker identifies function boundaries by detecting the prologue `ADDI sp, sp, -N` followed by `SD ra, offset(sp)` or `SW ra, offset(sp)`. The epilogue `RET` (`JALR x0, x1, 0`) is the function exit. A buffer overflow that overwrites the saved `ra` at `(N-8)(sp)` controls the program counter on `RET`.

---

## RISC-V privilege architecture and security relevance <sup>[↑](#riscvtainttracker)</sup>

RISC-V defines three privilege levels: Machine mode (M-mode, highest), Supervisor mode (S-mode), and User mode (U-mode). Firmware running in M-mode has complete hardware control. The RISC-V Supervisor Binary Interface (SBI) provides services from M-mode to S-mode, analogous to BIOS/firmware services on x86.

**`ECALL`:** The system call instruction. In U-mode, causes a trap to S-mode (OS syscall). In S-mode, causes a trap to M-mode (SBI call). The syscall number is in `a7`. Arguments are in `a0`–`a5`. For Linux RISC-V, `recv` = syscall 207, `read` = 63, `recvfrom` = 207. These are taint source syscalls that the tracker monitors.

**`CSRW mepc, rs1`:** Write to Machine Exception Program Counter. If `rs1` is attacker-controlled (tainted), this is a direct PC control write. Combined with an `MRET` instruction (return from machine-mode trap), an attacker can redirect execution to any address. This is a critical finding class unique to M-mode firmware.

**`CSRRW rd, csr, rs1`:** Atomic Read/Write CSR. Used for setting up page tables (`satp`), memory protection (`pmpaddr*`), and interrupt handling (`mtvec`). Tainted values written to these CSRs represent privilege escalation opportunities.

The `RISCVTaintTracker` detects `CSRW`/`CSRRW` instructions with tainted source registers and reports them as `CRITICAL` findings (direct control-flow manipulation).

---

## RISC-V compressed (RVC) instruction handling <sup>[↑](#riscvtainttracker)</sup>

RVC (RISC-V Compressed) instructions are 16-bit variants of common 32-bit instructions, identified by bits `[1:0]` = `00`, `01`, or `10` (non-compressed instructions always have bits `[1:0]` = `11`). RVC reduces code size by ~25% for typical RISC-V programs.

Key RVC instructions for taint tracking:

| RVC mnemonic | 32-bit equivalent | Taint relevance |
|---|---|---|
| `C.MV rd, rs1` | `ADD rd, x0, rs1` | Register-to-register copy; propagates taint |
| `C.ADD rd, rs1` | `ADD rd, rd, rs1` | In-place add; taints `rd` if either operand tainted |
| `C.LW rd, offset(rs1)` | `LW rd, offset(rs1)` | Load from memory; propagates memory taint |
| `C.SW rs1, offset(rs2)` | `SW rs1, offset(rs2)` | Store to memory; records tainted memory write |
| `C.JALR ra, rs1` | `JALR ra, rs1, 0` | Indirect call via `rs1` — taint sink if `rs1` tainted |
| `C.JR rs1` | `JALR x0, rs1, 0` | Indirect jump (tail call) — sink if `rs1` tainted |
| `C.ADDI rd, imm` | `ADDI rd, rd, imm` | Immediate add; preserves taint from `rd` |
| `C.LI rd, imm` | `ADDI rd, x0, imm` | Load immediate constant; `rd` is NOT tainted |

`C.JALR ra, rs1` is the compressed indirect call. The tracker treats this identically to `JALR ra, rs1, 0`. If `rs1` is tainted (derived from a network source), this is a potential control-flow hijack via tainted function pointer.

---

## RISC-V instruction encoding reference <sup>[↑](#riscvtainttracker)</sup>

RISC-V uses six primary instruction formats, all 32 bits (or 16 bits for RVC extensions):

**R-type (register–register operations):**
```
 31    25 24   20 19   15 14  12 11    7 6      0
[  funct7 ][  rs2 ][  rs1 ][ f3 ][  rd  ][ opcode ]
    7         5       5      3      5        7
```
`ADD rd, rs1, rs2` → opcode=0x33, funct3=0, funct7=0. `SUB rd, rs1, rs2` → funct7=0x20.

**I-type (immediate, loads, jumps):**
```
 31          20 19   15 14  12 11    7 6      0
[    imm[11:0]  ][  rs1 ][ f3 ][  rd  ][ opcode ]
      12            5      3      5        7
```
`LW rd, imm(rs1)` → opcode=0x03, funct3=0x2. `JALR rd, rs1, imm` → opcode=0x67. `ADDI rd, rs1, imm` → opcode=0x13.

**J-type (unconditional jump — JAL):**
```
 31 30       21 20  19      12 11    7 6      0
[imm20][imm[10:1]][imm11][imm[19:12]][  rd  ][ opcode ]
  1        10       1         8         5        7
```
`JAL rd, offset` → opcode=0x6F. PC-relative: target = PC + sign_ext21(offset). `rd=ra(x1)` is the call form; `rd=x0` is a plain jump.

**B-type (conditional branches):**
```
 31  30     25 24  20 19  15 14  12 11    8   7  6      0
[imm12][imm[10:5]][rs2][rs1][ f3 ][imm[4:1]][imm11][ opcode ]
```
`BEQ rs1, rs2, offset` → opcode=0x63, funct3=0. Target = PC + sign_ext13(offset).

Security-critical encodings:
- `JAL ra, target` (rd=x1) → direct call. Target = PC + imm21. No delay slot.
- `JALR ra, rs1, 0` → indirect call via `rs1`. Taint sink if `rs1` derived from network data.
- `AUIPC rd, upper20; JALR ra, rd, lower12` → PC-relative call to far address (2-instruction sequence for calls beyond ±1MB).

---

## RISC-V calling convention detail <sup>[↑](#riscvtainttracker)</sup>

The RISC-V Specification defines two ABIs relevant to firmware: ilp32 (32-bit integer + pointer) and lp64 (64-bit integer + pointer). The calling conventions are:

**Argument registers:** `a0`–`a7` (`x10`–`x17`). 8 argument registers vs MIPS's 4 (`$a0`–`$a3`). This matters for taint tracking: functions with up to 8 arguments can be fully analyzed without stack argument tracing. Arguments beyond `a7` go on the stack at `0(sp)`, `8(sp)`, etc.

**Return value:** `a0` (and `a1` for wide returns). The taint tracker marks `a0` as potentially tainted after any call to a network source function.

**Callee-saved registers:** `s0`–`s11` (`x8`–`x9`, `x18`–`x27`), and `sp` (`x2`). These must be preserved across calls. The taint tracker's inter-call model: volatile registers (`a0`–`a7`, `t0`–`t6`, `ra`) are cleared at each call boundary; callee-saved registers preserve their taint state.

**Compressed calling convention (RVC):** The compressed instruction set uses a restricted subset of registers. Most RVC 16-bit instructions only address `s0`/`s1` and `a0`–`a5` (8 registers: `x8`–`x15`). RVC load/store instructions use a 3-bit register field: `000`=`s0`, `001`=`s1`, `010`=`a0`, `011`=`a1`, `100`=`a2`, `101`=`a3`, `110`=`a4`, `111`=`a5`. Taint that propagates through `a0`–`a5` survives both RVC and standard instruction streams.

---

## RISC-V firmware targets <sup>[↑](#riscvtainttracker)</sup>

RISC-V is a new ISA (2010) and most currently deployed firmware using RISC-V is from recent product generations:

**HiSilicon Hi3861 (IoT SoC):** Used in Huawei HiLink IoT devices, smart home gateways, and some Huawei switches. The Hi3861 uses a custom RISC-V core (`hisi-rv32`) with proprietary extensions (`CUSTOM0`, `CUSTOM1` opcodes for hardware crypto acceleration). See `hisi-rv32-ext.md` for the extension-aware decoder.

**SiFive HiFive / FU740:** Used in some edge computing and development boards. Standard RV64GC (General + Compressed). Linux-capable.

**Alibaba/T-Head Xuantie C906/C910:** Used in some Chinese network equipment and embedded controllers. RISC-V with T-Head vendor extensions (`0x7` custom opcode prefix). The taint tracker skips unknown custom opcodes with a warning.

**Espressif ESP32-C3/C6:** Used in WiFi IoT modules. RV32IMC (no atomics, no floating point). The firmware is a Zephyr RTOS or ESP-IDF image. The web server component (`httpd`) is the security-relevant target.

**Western Digital SweRV EH1:** Used in Western Digital HDDs as the firmware controller. RV32IMC. The WD firmware runs on SweRV EH1 within the HDD controller IC.

---

## RISC-V taint tracker architecture <sup>[↑](#riscvtainttracker)</sup>

`RISCVTaintTracker` implements interprocedural BFS taint propagation for RV64GC (and RV32IMC via `RISCV32TaintTracker`):

**Register set tracked:** All 32 integer GPRs (`x0`–`x31` with ABI names). `x0` is hardwired to 0 (never tainted). Floating-point registers (`f0`–`f31`) are not tracked. Control/Status Registers (CSRs) are not tracked except `mepc` (machine exception program counter) when modified by attacker-controlled `CSRW mepc, rs1`.

**AUIPC+JALR sequence detection:** A call to a function more than ±1MB away requires two instructions. The taint tracker detects `AUIPC rd, upper; JALR ra, rd, lower` as a single call operation (the function pointer is computed from PC at the `AUIPC` instruction, not from user data).

**`LUI rd, imm; ADDI rd, rd, imm` sequence:** Load a 32-bit constant using `LUI` + `ADDI`. This pattern is used for loading hardcoded addresses (e.g., return addresses of embedded attack payloads in ROP chains). The taint tracker treats the result as a constant (not tainted) since `LUI` loads from the instruction stream, not from memory.

---

## Usage: RISC-V firmware scan workflow <sup>[↑](#riscvtainttracker)</sup>

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.sink_arg_classifier import SinkArgClassifierRISCV
from ablation.analyzers.taint_tracker_riscv import RISCVTaintTracker

# RV64GC little-endian (standard Linux RISC-V)
ctx = BinaryContext.load_or_build('/firmware/extract/usr/sbin/httpd')
print(ctx.summary())   # should show arch='rv64gc' or 'rv32imc'

classifier = SinkArgClassifierRISCV.from_context(ctx)
work = [s for s in classifier.classify_all()
        if s.classification in ('ARG_PROPAGATED', 'UNKNOWN')]

findings = RISCVTaintTracker.from_context(ctx).scan(sink_sites=work)

# Byte-verify: JAL ra (opcode=0x6F, rd=x1) or JALR ra (opcode=0x67, rd=x1)
data = open(ctx.binary_path, 'rb').read()
for f in findings:
    off = f.sink_va - ctx.base
    word = int.from_bytes(data[off:off+4], 'little')   # RISC-V is always little-endian
    opcode = word & 0x7F
    rd = (word >> 7) & 0x1F
    assert opcode in (0x6F, 0x67), f"Not a JAL/JALR at {f.sink_va:#x}: opcode={opcode:#x}"
    ctx.set_name(f.sink_va, f"sink_{f.sink_name}", source="confirmed")
    print(f"[{f.severity}] {f.sink_name} @ {f.sink_va:#x}: a{f.tainted_args[0]} tainted from {f.source_name}")
```

---

## False positives <sup>[↑](#riscvtainttracker)</sup>

**`JALR zero, ra, 0` is a return, not a call.** `rd=x0` means the return address is discarded. The taint tracker identifies this as the function epilogue. Any preceding taint in `a0` (return value register) is the function's return value, not a call to a sink.

**`a0` is reused for both arguments and return values.** `a0` receives the function's return value from any call. After `JAL ra, strlen; // a0 = strlen result`, the tracker must not preserve `a0` taint from a network buffer passed as the argument to `strlen`. The tracker clears `a0`–`a7` after each call (they are volatile) and only re-taints `a0` if the called function is a known taint source.

**Custom extension opcodes in HiSilicon Hi3861 firmware.** The Hi3861 uses custom opcodes in the `CUSTOM0`–`CUSTOM3` opcode ranges (0x0B, 0x2B, 0x5B, 0x7B). The standard `RISCVTaintTracker` skips these with a warning and does not attempt to trace register effects. Manual analysis of custom opcode sequences that write to `a0`–`a7` is required before reporting clean status.

**Atomics (A extension) and taint ordering.** The `AMO*` (Atomic Memory Operation) instructions (`AMOADD.W`, `AMOSWAP.W`, etc.) perform a read-modify-write atomically. If the memory address holds tainted data, the destination register receives that tainted value. The taint tracker models `AMO*` as a load that propagates memory taint to the destination register.

---

## RISC-V ISA extension combinations in firmware targets <sup>[↑](#riscvtainttracker)</sup>

RISC-V firmware binaries declare supported extensions in the ELF `riscv_isa` attribute (`.riscv.attributes` section) or in the filename conventions. Common extension combinations:

| Extension set | Common name | Typical firmware target |
|---|---|---|
| `RV32IMC` | Base embedded | ESP32-C3/C6, Hi3861, SweRV EH1 |
| `RV32IMAC` | Embedded with atomics | Kendryte K210 AI SoC |
| `RV64GC` | Standard Linux 64-bit | SiFive FU740, StarFive JH7100, AllWinner D1 |
| `RV64IMAFDC` | Same as GC (G = IMAFD) | Standard Linux RISC-V |
| `RV64GCB` | With Bitmanip | T-Head C910 (Alibaba) |

**Reading the extension set from ELF:**
```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/firmware/extract/usr/sbin/httpd')
print(ctx.arch_info)  # 'rv64gc', 'rv32imc', etc.
# If arch_info == 'rv32imc': use RISCV32TaintTracker
# If arch_info == 'rv64gc': use RISCVTaintTracker (RV64 default)
# If arch_info contains 'b' (Bitmanip): expect CLMUL, ZEXT.H, ROL, ROR instructions
#   that the tracker handles as opaque (taint passes through, no semantic modeling)
```

---

## Pipeline position (expanded) <sup>[↑](#riscvtainttracker)</sup>

**RISC-V firmware extraction:**
```bash
# For embedded Linux squashfs firmware (common for RISC-V IoT)
binwalk -e firmware.bin
find _firmware.bin.extracted/ -name '*.elf' | xargs file | grep RISC-V

# For bare-metal RISC-V firmware (no FS, single flat image)
# Check ELF header: e_machine = 0xF3 (EM_RISCV)
python3 -c "
import struct
with open('firmware.elf','rb') as f:
    e_ident = f.read(16)
    f.seek(18)
    e_machine = struct.unpack_from('<H', f.read(2))[0]
    print(f'EM_RISCV: {e_machine == 0xF3}')
"
```

**Pre-scan checklist:**
1. Confirm `e_machine` = 0xF3 (`EM_RISCV`)
2. Check `e_ident[4]`: 1 = RV32, 2 = RV64
3. Read `.riscv.attributes` for extension flags: RVC present? Custom extensions?
4. For Hi3861 (`hisi-rv32`): switch to `hisi-rv32-ext.md` workflow before `RISCVTaintTracker`
5. Confirm byte order: RISC-V is always little-endian

**Scan sequence:**
1. `BinaryContext.load_or_build()` → `ctx.summary()` confirms arch
2. `SemanticSearcher.query()` → identify command execution candidates
3. `SinkArgClassifierRISCV.classify_all()` → reduce to `ARG_PROPAGATED`/`UNKNOWN`
4. `RISCVTaintTracker.from_context(ctx).scan()` → findings
5. Byte-verify: opcode `0x6F` (JAL) or `0x67` (JALR) at `sink_va`
6. `ctx.set_name()` + `FindingRegistry.register()` + write to `re/<vendor>/<target>_re.py`

---

## See also <sup>[↑](#riscvtainttracker)</sup>

- [Binary Lifter](binary-lifter.md): `arch='rv32'`/`'rv64'` structural lifting
- [Taint Analysis](taint-analysis.md): general labeled-taint model documentation
- [RH850 Taint Analysis](rh850-taint-analysis.md): V850/RH850 variant; same labeled-taint model
- [HiSi RV32 Extension Decoder](hisi-rv32-ext.md): HiSilicon-specific RISC-V custom extensions (Hi3861 IoT SoC)
- [MIPS Taint Tracker](mips.md): compare delay-slot-based MIPS model with RISC-V's clean basic blocks
- [PPC32 Taint Tracker](ppc32-taint-tracker.md): compare Link Register model with RISC-V's `ra` convention
- [Sink Arg Classifier](sink-arg-classifier.md): RISC-V variant extends the generic classifier with `a0`–`a7` argument mapping
- [Semantic Code Search](semantic-code-search.md): identify RISC-V candidates by semantic embedding before running taint tracker
- [Length Underflow Scanner](length-underflow.md): header-subtraction integer underflow in RISC-V networking code
- [Path Solver](taint-analysis.md): CFG feasibility confirmation for conditional taint paths in RISC-V firmware
- [SSA Builder](ssa.md): SSA form for CFG-fixpoint taint propagation across RISC-V basic block boundaries
- [IPReg Annotator](ipreg-annotator.md): resolve indirect `JALR rs1` calls through function pointer tables before running taint tracker
- [Window Analyzer](window-analyzer.md): manual RISC-V disassembly with RVC-aware annotation when automated tools cannot handle the sink

**RISC-V taint tracker configuration options:**
- `track_csrs=True` (default `False`): enables detection of tainted values written to security-sensitive CSRs (`mepc`, `satp`, `pmpaddr*`)
- `compressed=True` (default `True`): enables RVC 16-bit instruction decoding; set to `False` only for bare-metal M-mode firmware that never enables RVC
- `custom_extensions=[]`: list of `CustomExtension` objects from `hisi-rv32-ext.py` or similar; the tracker skips custom opcodes not in this list
- `max_call_depth=5` (default): interprocedural BFS depth limit; increase for deeply nested RISC-V firmware call chains at the cost of scan time
- `syscall_sources=True` (default `True`): marks `a0` as tainted after `ECALL` with `a7` in the network-read syscall set (63=read, 207=recvfrom, 45=recvmsg, 46=recvmmsg); the buffer pointer in `a0` (first syscall argument) is also marked tainted as the data destination
