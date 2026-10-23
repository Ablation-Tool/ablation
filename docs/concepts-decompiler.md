# Decompiler and IR Lifter Concepts

**Scope:** conceptual reference for all Ablation users 
**Applies to:** `BinaryLifter`, `Ppc32Lifter`, `Ppc476Decompiler`, `ABCDecompiler`, `BEAMLifter`, `DEXLifter`, `MpyLifter`

---

## What this covers

Ablation spans three levels of abstraction for binary analysis. This document defines the levels, explains where each Ablation tool fits, and provides concrete examples of the transformations involved. Understanding the distinction between an **IR lifter** and a **decompiler** prevents misreading tool output and sets correct expectations about what each component can and cannot recover.

---

## Definitions

### Decompiler

**Goal:** Machine code → high-level source code or source-like code.

- **Input:** Native machine code x86, ARM, PPC, etc. in a binary or executable. Also applicable to bytecode (JVM, Dalvik, MicroPython).
- **Output:** A high-level language representation: something that looks like C, C++, or pseudo-C.
- **What it does:**
 - Disassembles machine code to assembly.
 - Recovers control flow basic blocks, functions, loops, conditionals.
 - Constructs an intermediate representation (IR) internally.
 - Performs high-level analyses and transformations: data-flow analysis, type/variable recovery, control flow structuring.
 - Pretty-prints the IR to C-like code.

A decompiler usually *includes* a lifter internally to get to its IR, but its primary purpose is to give you readable high-level code, not just an IR.

### IR Lifter

**Goal:** Machine code → intermediate representation (IR) for analysis or transformation.

> An **IR lifter** is a semantic translation engine that takes architecture-specific machine instructions and produces a precise, architecture-neutral intermediate representation. It makes all register, memory, and control-flow effects explicit, organizes them into a control-flow graph, and serves as the foundation upon which program analysis, verification, binary rewriting, and decompilation are built.

- **Input:** Machine code or assembly for a specific architecture.
- **Output:** Architecture-neutral IR LLVM IR, VEX, BIL, REIL, or similar CFG of basic blocks.
- **What it does:**
 - Decodes instructions and translates each one's semantics into IR operations.
 - Makes side-effects explicit: register updates, memory writes, flags, control flow.
 - Builds a control-flow graph of IR basic blocks.
 - Does *not* reconstruct `for`/`while`/`if` constructs, named variables, or types.

An IR lifter is not a decompiler by itself. It is the bridge between "whatever CPU this binary runs on" and higher-level tools that want a uniform view of program behavior.

### Lifter (generic)

"Lifter" is used broadly to mean any component that moves a lower-level representation to a higher-level one:
- **IR lifter** (precise): assembly → IR.
- **Bytecode lifter:** bytecode → IR or high-level AST.
- Informally, sometimes the front end of a decompiler machine code → decompiler IR.

In binary analysis frameworks angr, BAP, etc. "lifter" almost always means IR lifter.

---

---

## The pipeline and the cut line

Every binary analysis tool that produces human-readable output operates on this stack:

```
(High)   ┌──────────────────────────────┐
         │  Decompiled high-level code  │  ← C-like: variables, types, if/for/while
         └─────────────▲────────────────┘
                       │
                       │  (Decompiler logic: CFG structuring,
                       │   SSA, type/variable recovery)
   ─────────────── CUT HERE ────────────────────────────────────
                       │
                       │  (IR lifter)
                       │
         ┌─────────────▼────────────────┐
         │  Intermediate Representation │  ← IR CFG: loads/stores, branches, temps
         └─────────────▲────────────────┘
                       │
                       │  (Disassembler / decoder)
                       │
         ┌─────────────▼────────────────┐
         │   Machine code / Assembly    │  ← Real instructions, registers, flags
(Low)    └──────────────────────────────┘
```

- **IR lifter's job:** Assembly → IR below the cut line.
- **Decompiler's job:** IR → High-level code above the cut line.

A decompiler is: **disassembler + IR lifter + analysis passes + pretty-printer**. An IR lifter is only the middle step. A decompiler always includes a lifter internally; a lifter by itself does not produce decompiled output.

---

## Stage 1: Machine Code and Assembly

What the binary contains. Raw bytes decoded as instructions.

```asm
; x86-64 example — sum_positive
push   rbp
mov    rbp, rsp
sub    rsp, 16
mov    DWORD PTR [rbp-4], 0    ; sum = 0
mov    DWORD PTR [rbp-8], 0    ; i = 0
loop_start:
  mov    eax, DWORD PTR [rbp-8] ; eax = i
  cmp    eax, esi               ; compare i, n
  jge    loop_end               ; if i >= n → exit
  mov    rdx, QWORD PTR [rbp+16]
  mov    eax, DWORD PTR [rbp-8]
  cdqe
  mov    ecx, DWORD PTR [rdx+rax*4]
  cmp    ecx, 0
  jle    skip_add
  mov    eax, DWORD PTR [rbp-4]
  add    eax, ecx
  mov    DWORD PTR [rbp-4], eax
skip_add:
  add    DWORD PTR [rbp-8], 1
  jmp    loop_start
loop_end:
  mov    eax, DWORD PTR [rbp-4]
  leave
  ret
```

At this stage: instructions, registers, raw stack offsets (`[rbp-4]`), unstructured jumps. No `for`, no `if`, no named variables.

---

## Stage 2: Intermediate Representation (IR)

The IR lifter translates each machine instruction into IR operations organized into basic blocks with explicit control-flow edges. The result is architecture-neutral and explicit about every load, store, and branch.

```text
function sum_positive(a_arg: ptr<i32>, n_arg: i32) -> i32 {

entry:
  sum_0 = 0:i32
  STORE(MEM[frame + (-4)], sum_0)
  i_0 = 0:i32
  STORE(MEM[frame + (-8)], i_0)
  GOTO loop_start

loop_start:
  i_1    = LOAD(MEM[frame + (-8)])
  t_cmp0 = i_1 - n_arg
  IF (i_1 >= n_arg) GOTO loop_end ELSE GOTO loop_body

loop_body:
  t_i64 = i64_extend(i_1)
  t_addr = a_arg + (t_i64 * 4)
  v = LOAD(MEM[t_addr])
  t_cmp1 = v - 0:i32
  IF (v <= 0) GOTO skip_add ELSE GOTO add_block

add_block:
  sum_1 = LOAD(MEM[frame + (-4)])
  sum_2 = sum_1 + v
  STORE(MEM[frame + (-4)], sum_2)
  GOTO inc_i

skip_add:
  GOTO inc_i

inc_i:
  t_i2 = i_1 + 1:i32
  STORE(MEM[frame + (-8)], t_i2)
  GOTO loop_start

loop_end:
  sum_final = LOAD(MEM[frame + (-4)])
  RETURN sum_final
}
```

IR CFG as a diagram:

```
       [entry]
         |
         v
    [loop_start] <-----------+
     /         \             |
   yes           no          |
   v              v          |
[loop_body]   [loop_end]    |
   |                        |
   +--> [add_block] ──+      |
   +--> [skip_add]  ──+      |
                  [inc_i] ---+
```

At this stage: values are explicit temporaries (`t0`, `t1`, …), memory is explicit (`LOAD`/`STORE`), control flow is a graph, but loops and conditionals are still *implicit* in the CFG, not yet `for`/`if` constructs.

### What the IR lifter produces and stops at

The lifter stops here. It does not:
- Invent `for`/`while` constructs.
- Assign names (`sum`, `i`) to stack slots.
- Infer types (`int`, `char *`).

### Core lifter responsibilities

1. **Instruction semantics:** translate each opcode into IR ops, `add eax, ecx` → `t2 = t0 + t1`.
2. **Make side-effects explicit:** flags, register writes, memory writes all become IR statements.
3. **Build CFG:** identify basic block boundaries at labels and jumps; connect blocks with IR branches (`IF... GOTO`).

---

## Stage 3: Decompiled High-Level Code

The decompiler takes the IR and:
- Recognizes loops from back-edges in the CFG.
- Recognizes if/else patterns from branch pairs.
- Converts SSA phi nodes into loop variables.
- Renames stack slots to named variables.
- Infers types.

```c
int sum_positive(int *a, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] > 0) {
            sum += a[i];
        }
    }
    return sum;
}
```

What changed between Stage 2 and Stage 3:
- **Jumps → structured control flow:** `loop_start` + conditional back-edge → `for`.
- **Stack slots → named variables:** `MEM[frame-4]` → `sum`, `MEM[frame-8]` → `i`.
- **Phi nodes removed:** `sum_0`, `sum_1`, `sum_2`, `sum_final` collapse into `sum`.

### Concrete difference at the loop boundary

```
[Stage 2 — IR, lifter output]            [Stage 3 — C, decompiler output]
─────────────────────────────────────    ──────────────────────────────────
loop_start:                              for (int i = 0; i < n; i++) {
  i_1    = LOAD(MEM[frame - 8])              if (a[i] > 0) {
  t_cmp0 = i_1 - n_arg                           sum += a[i];
  IF (i_1 >= n_arg) GOTO loop_end          }
  ELSE GOTO loop_body               →  }
```

The IR expresses the *what* loads, compare, conditional branch. The decompiler recovers the *shape* loop, condition, increment.

---

## Side-by-side: same function, three views

```
[Stage 1] Assembly          [Stage 2] IR (lifter)               [Stage 3] Decompiled C
─────────────────────────   ─────────────────────────────────   ─────────────────────────
push rbp                    entry:                              int sum_positive(int *a,
mov rbp, rsp                  sum_0 = 0:i32                                    int n) {
sub rsp, 16                   STORE(MEM[frame-4], sum_0)          int sum = 0;
mov [rbp-4], 0                i_0 = 0:i32                         for (int i = 0;
mov [rbp-8], 0                STORE(MEM[frame-8], i_0)                 i < n; i++) {
                              GOTO loop_start                       int v = a[i];
loop_start:                 loop_start:                             if (v > 0) {
  cmp eax, esi                i_1 = LOAD(MEM[frame-8])                 sum += v;
  jge loop_end                IF (i_1 >= n_arg) GOTO loop_end     }
  ...                         ELSE GOTO loop_body               }
  jmp loop_start            ...                                   return sum;
                                                                }
loop_end:
  mov eax, [rbp-4]
  ret
```

---

## Simple example: add_to_y

A minimal function that adds x to a global y, shown at all three stages.

**Stage 1, Assembly (x86-64):**
```asm
; Raw bytes: 55 48 89 E5 89 7D FC 8B 45 FC 01 45 F8 8B 45 F8 5D C3
push   rbp
mov    rbp, rsp
mov    DWORD PTR [rbp-0x4], edi      ; int x (argument)
mov    eax, DWORD PTR [rbp-0x4]
add    DWORD PTR [rbp-0x8], eax      ; y += x
mov    eax, DWORD PTR [rbp-0x8]
pop    rbp
ret
```

**Stage 2, IR lifter output:**
```text
func add_to_y(arg0: i32) -> i32 {
entry:
  t0 = arg0                     ; from edi
  t1 = load &y                  ; read y
  t2 = t1 + t0                  ; y + x
  store &y, t2                  ; write back y
  t3 = load &y
  return t3
}
```

**Stage 3, Decompiled C:**
```c
int add_to_y(int x) {
    y = y + x;
    return y;
}
```

---

## IR lifter: detailed responsibilities

### Position in the toolchain

```
Raw bytes  →  Disassembly  →  IR Lifter  →  IR  →  Analysis / Decompilation
(binary)       (assembly)       (this)        (CFG, SSA, etc.)
```

### Core responsibilities

**1. Instruction-by-instruction semantics.** For each architecture instruction, the lifter encodes a semantic rule:
- `ADD reg, reg` → new value = old value + source; flags updated.
- `CMP reg, imm` → no register change; flags set based on reg − imm.
- `JZ target` → if zero flag is set, control flow goes to `target`.

The IR makes each of these effects explicit so analysis tools don't have to decode CPU semantics themselves.

**2. Normalization and abstraction.** Architecture quirks are hidden behind a uniform IR model:
- All registers become IR variables/temporaries.
- Memory is exposed through uniform `LOAD`/`STORE` operations.
- Flags become explicit comparisons or flag variables.

Higher-level components don't need to know about x86's `EFLAGS` vs ARM's `CPSR`; they see "if (x == 0) then branch."

**3. Building basic blocks and CFG.** The lifter:
- Splits lifted code into basic blocks straight-line sequences with one entry, one exit.
- Connects blocks based on direct jumps, conditional branches, calls, and returns.

Output is not just linear IR, it is a **graph structure** that models all possible execution paths.

### Example: instruction-level translation

Assembly:
```asm
mov    DWORD PTR [rbp-4], 0   ; sum = 0
```
Lifted IR:
```text
t0 = 0:i32
STORE(MEM[rsp_frame + (-4)], t0)
```

Assembly:
```asm
mov    eax, DWORD PTR [rbp-8]   ; eax = i
cmp    eax, esi                  ; compare i, n
jge    loop_end
```
Lifted IR:
```text
t2 = LOAD(MEM[rsp_frame + (-8)])   ; i
t3 = n_arg                         ; was in esi
t4 = t2 - t3
SETFLAGS(t4)
IF (t2 >= t3) GOTO loop_end ELSE GOTO next_block
```

Assembly:
```asm
mov    ecx, DWORD PTR [rdx+rax*4]   ; ecx = a[i]
cmp    ecx, 0
jle    skip_add
```
Lifted IR:
```text
t5 = a_arg
t6 = i64_extend(t2)
t7 = t5 + (t6 * 4)
t8 = LOAD(MEM[t7])
IF (t8 <= 0) GOTO skip_add ELSE GOTO add_block
```

### Design goals

1. **Semantically faithful**, accurately models what machine code does, instruction by instruction. Small inaccuracies break symbolic execution and taint analysis.
2. **Architecture-neutral**, the same IR framework is usable for x86, ARM, MIPS, PPC. Only the lifting rules differ; consumers of IR remain unchanged.
3. **Explicit and analyzable**, hidden side effects implicit flag updates, implicit stack pointer changes become explicit IR operations; control flow is explicit in branches and block edges.
4. **Amenable to further transformation**, easy to convert to SSA form; easy to apply standard compiler analyses data-flow, taint tracking, symbolic execution, binary rewriting.

### What an IR lifter is NOT

- **Not a decompiler.** It does not produce human-readable C/C++ code. It does not infer types, structure loops, or rename variables.
- **Not a disassembler.** A disassembler maps bytes → assembly mnemonics. A lifter maps assembly → IR semantics.
- **Not visible to end-users** of GUI tools like IDA or Ghidra: it is an internal engine component.

### Typical use cases

1. **Program analysis frameworks**, angr (VEX IR), BAP (BIL), Binary Ninja BNIL/LLIL/MLIL, Miasm, REIL.
2. **Decompilers**, most decompilers use IR as a stepping stone; the decompiler front end is disassembler + IR lifter.
3. **Binary rewriting / instrumentation**, insert logging or security checks by reasoning about IR structure.
4. **Verification and security analysis**, symbolic execution, taint analysis, and model checking all operate on IR graphs rather than CPU-specific artifacts.

### Intuitive analogy

An IR lifter is a **universal translator**: different CPUs "speak" different machine languages x86, ARM, PPC, RISC-V. The IR is a common language. The lifter translates each CPU's dialect into that common language, preserving all meaning. Higher-level tools analyzers, decompilers, optimizers only need to know the IR, not every CPU dialect.

---

## One-sentence contrast

- **IR lifter:** "Given this architecture's instructions, tell me *exactly* what they do in a uniform IR form."
- **Decompiler:** "Given this uniform IR, recover the *human-level structure* types, variables, loops, if/else and print it as source-like code."

---

## Zoom-in: from IR to decompiled output, step by step

This walks the exact transition from IR lifter output to final C code. Each step is strictly decompiler work, the lifter is done.

### Starting point: IR lifter output

```text
entry:
  sum_0 = 0:i32
  STORE(MEM[frame - 4], sum_0)
  i_0   = 0:i32
  STORE(MEM[frame - 8], i_0)
  GOTO loop_cond

loop_cond:
  i_1    = LOAD(MEM[frame - 8])
  t_cmp0 = i_1 - n_arg
  IF (i_1 >= n_arg) GOTO loop_end ELSE GOTO loop_body

loop_body:
  v_0    = LOAD(MEM[a_arg + i64_extend(i_1) * 4])
  t_cmp1 = v_0 - 0:i32
  IF (v_0 <= 0) GOTO skip_add ELSE GOTO do_add

do_add:
  sum_1  = LOAD(MEM[frame - 4])
  sum_2  = sum_1 + v_0
  STORE(MEM[frame - 4], sum_2)
  GOTO inc_i

skip_add:
  GOTO inc_i

inc_i:
  i_3    = LOAD(MEM[frame - 8])
  i_4    = i_3 + 1
  STORE(MEM[frame - 8], i_4)
  GOTO loop_cond

loop_end:
  sum_final = LOAD(MEM[frame - 4])
  RETURN sum_final
```

No `while`, no `if`, just blocks, `IF`/`GOTO`, and loads/stores. The **decompiler starts here**.

### Step 1 decompiler: build SSA

Convert memory slots to SSA variables with phi nodes at merge points:

```text
loop_cond:
  i_phi   = phi(i_0, i_4)          ; from entry or from inc_i
  sum_phi = phi(sum_0, sum_2)      ; from entry or from do_add
  cond0   = (i_phi < n_arg)
  if cond0 then goto loop_body else goto loop_end
```

`MEM[frame-4]` and `MEM[frame-8]` become named SSA variables. Phi nodes represent merge points that the lifter does not model.

### Step 2 decompiler: recognize loop

`loop_cond` has a back-edge from `inc_i` → pattern: "condition block with back-edge" = **`while` loop**:

```c
while (i_phi < n_arg) {
    ...
}
```

### Step 3 decompiler: recognize if

Inside the loop, `loop_body` branches to `do_add` or `inc_i` based on `cond1`. Both converge at `inc_i` → pattern: "branch then converge" = **`if` statement**:

```c
if (v_0 > 0) {
    sum_phi = sum_phi + v_0;
}
```

### Step 4 decompiler: eliminate phi nodes

```text
i_phi = phi(i_0, i_4)
i_4   = i_phi + 1
```
→
```c
int i = 0;
...
i = i + 1;
```

Phi nodes collapse into a single named variable updated in the loop.

### Step 5 decompiler: type inference and renaming

Usage patterns reveal types: `a_arg` is `int *` indexed with stride 4, `n_arg` is `int`. Stack slots become `sum` and `i`.

### Final output

```c
int sum_positive(int *a, int n) {
    int sum = 0;
    int i = 0;
    while (i < n) {
        int v = a[i];
        if (v > 0) {
            sum += v;
        }
        i++;
    }
    return sum;
}
```

### The exact dividing line

```
[IR lifter output]                      [Decompiler output]
────────────────────────────────────    ──────────────────────────────────
loop_cond:                              while (i < n) {
  i_1    = LOAD(MEM[frame - 8])    →       ...
  t_cmp0 = i_1 - n_arg             →   }
  IF (i_1 >= n_arg) GOTO loop_end
  ELSE GOTO loop_body
```

Below the line: `LOAD`, `IF`, `GOTO`, raw memory slots. 
Above the line: `while (i < n)` with a declared `int i`.

---

## Ablation: where each tool fits

| Tool | Stage | Output | Notes |
|---|---|---|---|
| `WindowAnalyzer` | 1 | Raw disassembly | No register tracking |
| `BinaryLifter` all ISA backends | 2 → ~3 | Register-tracked pseudo-C per function | Includes NativeVal register state; CFG not fully reconstructed; completeness varies by ISA |
| `Ppc32Lifter` | 2 → ~3 | Register-tracked pseudo-C, PPC32 BE | Linear walk only; no loop structuring |
| `Ppc476Decompiler` | 2 → 3 | Named locals, type annotations, condition expressions, CFG back-edge detection | Closest to a full decompiler for PPC476 Book E targets |
| `ABCDecompiler` | 2 → 3 | Source-like output | Bytecode input |
| `BEAMLifter` | 2 | IR-level pseudo output | Erlang BEAM bytecode; stays at IR, no structuring |
| `DEXLifter` | 2 → ~3 | Source-like output | Dalvik bytecode |
| `MpyLifter` | 2 → ~3 | Source-like output | MicroPython bytecode |
| `JavaModuleAnalyzer` |: | Parser/scanner | Not a lifter or decompiler; operates on class metadata |

**Key nuance:** "Register-tracked pseudo-C" from `BinaryLifter` backends is not the same as full decompilation. The backends produce output closer to Stage 2 with some Stage 3 features resolved calls, constant folding but without loop structuring, phi-node elimination, or type inference across call boundaries. Presence of `NativeVal` register tracking is a prerequisite for decompiler-quality output, not proof of it.

---

## Encyclopedia comparison: IR Lifter vs Decompiler indirect calls

Focusing on indirect calls, the clearest case where the pipeline cut-line matters:

| Aspect | IR Lifter | Decompiler |
|---|---|---|
| Input | Decoded machine instructions (`mov`, `push`, `call eax`, …) | IR lifter output: explicit `CALL_INDIRECT addr`, stack ops, etc. |
| View of callee | **Address in a register/memory** (`t_fp`), opaque | **Function pointer variable** (`fp`), possibly typed (`int (*)(int)`) |
| Representation of call | `CALL_INDIRECT t_fp` + explicit stack/PC manipulation | High-level call expression: `fp(y)` |
| Argument handling | Explicit `STOREMEM[esp - 4], arg` + `CALL_INDIRECT` | Abstract arguments: list `[y]` in AST `Call(function=fp, args=[y])` |
| Return value | Modeled as `eax` or similar, then `STORE` to a local | Modeled as `RETVAL(fp)` → assigned to `z` in high-level code |
| Control flow | Basic blocks with `CALL_INDIRECT` and `RETURN`/PC updates | Structured control flow: functions, returns, and call expressions |
| Type information | None or minimal raw word sizes | Inferred types: `int (*fp)(int)`, `int y`, `int z`, `int return` |
| Naming of entities | Temporaries: `t_fp`, `t_y`, `t_ret`, stack slots `[ebp+8]` | Symbolic names: `fp`, `y`, `z`, `call_through_ptr` |
| Primary goal | Precisely encode instruction semantics in a common IR | Recover human-understandable program structure and source-like code |
| Output example | See low-level IR listing above | `int z = fp(y);` |

---

## Why Ablation does not use Ghidra

Ghidra's decompiler is a full Stage 1 → Stage 3 pipeline and would produce higher-quality structuring for complex functions. Ablation excludes it because:
1. The RE workflow targets automated, reproducible pipeline runs, Ghidra requires a GUI or headless scripting setup that couples poorly with the `BinaryContext` + `SemanticSearcher` + `SinkArgClassifier` pipeline.
2. Ablation's goal is vulnerability analysis, not reverse engineering for comprehension. For that goal, knowing that `system(arg0)` is called with a propagated function argument is more actionable than a pretty-printed for loop.
3. The `Ppc476Decompiler` and similar modules close the gap for the specific ISAs where automated sink tracing needs full argument recovery.

---

## Complete tool and ISA reference

### Named entry-point tools

These are imported and called directly. They are not `arch=` strings passed to `BinaryLifter`.

| Tool | Import | Stage | Input | Notes |
|---|---|---|---|---|
| `BinaryLifter` | `ablation.analyzers.binary_lifter` | 2 → ~3 | Native binary or bytecode | Multi-ISA dispatch via `arch=`; see table below |
| `Ppc476Decompiler` | `ablation.analyzers.ppc476_lifter` | 2 → 3 | PPC476 Book E flat ROM or ELF | Full loop structuring, type annotations, named locals; closest to a full decompiler |
| `ABCDecompiler` | `ablation.analyzers.abc_decompiler` | 2 → 3 | ActionScript bytecode (.abc) | Source-like output from Flash/AIR bytecode |
| `BEAMLifter` | `ablation.analyzers.beam_context` | 2 | Erlang/Elixir.beam | IR-level pseudo output; also exposed via `BinaryLifter(arch='beam')` |
| `DEXLifter` | (via `android.md`) | 2 → ~3 | Dalvik/ART.dex | Source-like output for Android native analysis |
| `MpyLifter` | `ablation.analyzers.mpy_lifter` | 2 → ~3 | MicroPython.mpy v6 | Lifts ESP32/STM32/CC13xx firmware; flags dangerous imports |

---

### BinaryLifter: `arch=` strings and completeness tiers

Pass `arch=` to `BinaryLifter.from_path()` or `BinaryLifter.from_context()`.

**Tier definitions:**
- **Full**: CFG construction, per-register NativeVal state machine, taint annotations, typed expressions
- **Structural**: per-register state machine seeded from ABI; calls/returns/branches emitted as C; other instructions emitted as `// mnemonic` comments
- **Structural + Structurizer**: same as structural, then Structurizer converts the goto-CFG to if/while/for pseudo-C
- **Tool-dependent**: structural output, but requires a GNU cross-toolchain objdump in PATH; returns an explanatory comment if the tool is absent
- **Module summary**: no VA space; returns exports, dangerous imports, and atoms

#### Native CPUs

| ISA | `arch=` strings | Tier | ABI / return reg |
|---|---|---|---|
| ARM64 | `arm64` | Full | AAPCS64; x0 |
| x86-64 | `x86_64`, `x86-64`, `amd64` | Full | SysV AMD64; rax |
| x86-32 | `x86_32`, `i386`, `i686` | Structural | CDECL stack args; eax |
| ARM32 | `arm32`, `arm` | Structural | AAPCS; r0-r3 args, r0 return |
| Thumb / Thumb-2 | `thumb`, `thumb2` | Structural | AAPCS Thumb mode |
| MIPS-32 BE | `mips32`, `mips`, `mipsbe` | Structural | o32; $a0-$a3, $v0 return |
| MIPS-32 LE | `mips32el`, `mipsel` | Structural | o32 little-endian |
| MIPS-64 BE | `mips64`, `mipsn64` | Structural | n64; $a0-$a7, $v0 return |
| MIPS-64 LE | `mips64el` | Structural | n64 little-endian |
| nanoMIPS | `nanomips` | Structural linear walk, no CFG | o32 ABI |
| PPC-32 | `ppc32`, `ppc`, `powerpc` | Structural | SysV32; r3-r10 args, r3 return |
| PPC-64 | `ppc64`, `powerpc64` | Structural | ELFv2; r3-r10 args, r3 return |
| RISC-V 32 | `rv32`, `riscv32` | Structural | psABI; a0-a7 args, a0 return |
| RISC-V 64 | `rv64`, `riscv64` | Structural | psABI; a0-a7 args, a0 return |
| ARC EM/HS | `arc`, `arcem`, `archs` | Tool-dependent | requires `arc-elf32-objdump` in PATH |
| LoongArch64 | `la64`, `loongarch64` | Structural | lp64; $a0-$a7, $a0 return |
| BEAM Erlang/Elixir | `beam`, `erlang`, `elixir` | Module summary | no VA space; pass `va=0` |

#### Automotive ECUs (via BinaryLifter)

| ISA | `arch=` strings | Tier | Notes |
|---|---|---|---|
| SH-2A | `sh2a`, `sh2` | Structural + Structurizer | Flat ROM support (VA == file offset when no ELF section map); linear fallback on structurizer failure |
| V850-32 | `v850`, `v850e2` | Tool-dependent | requires `v850-elf-objdump` in PATH |
| RH850 | `rh850` | Tool-dependent | requires `v850-elf-objdump` in PATH |

#### Automotive ECUs (dedicated decoder classes, not BinaryLifter `arch=` strings)

These ISAs have their own decoder and taint tracker. They do not go through `BinaryLifter`.

| ISA | Decoder / entry point | Notes |
|---|---|---|
| PPC476 Book E | `Ppc476Decompiler` | Full decompiler; loops, types, named locals |
| PowerPC VLE | `VLEDecoder` / `ecu_vle_decoder` | Mixed 16/32-bit NXP automotive instructions |
| M68K / CPU32 | `EcuM68kDecoder` / `ecu_m68k_decoder` | GM/Motorola ECUs |
| MC88100 | `M88kDecoder` / `m88k_decoder` | Motorola 88000 |
| TriCore TC1.6x | `TaintTrackerTricore` | GHS EABI + IAR EABI; used via taint tracker |
| TMS320C28x | `EcuC28xDecoder` / `ecu_c28x_decoder` | TI DSP; word-addressed |
| Intel 8051 | (via `isa-8051.md`) | MCS-51 microcontrollers |
| HiSilicon RV32 | (via `hisi-rv32-ext.md`) | RV32 with custom bound-clearing instructions |

#### VM runtimes (standalone tools, not BinaryLifter `arch=` strings)

| Runtime | Entry-point tool | `arch=` in BinaryLifter |
|---|---|---|
| Dalvik / ART | `DEXLifter` |: |
| ArkTS (HarmonyOS) | (via `harmonyos.md`) |: |
| MicroPython.mpy v6 | `MpyLifter` |: |
| Erlang / Elixir BEAM | `BEAMLifter` | also `beam`, `erlang`, `elixir` |

---

## ExprLifter: design architecture from IBM production systems

This section documents design patterns extracted from three IBM production tools: HATS 7.5, XLC/OMR for s390x, and VisualAge CPP iDebug. These patterns directly inform how Ablation's planned `ExprLifter` module should be implemented.

---

### HATS v75: BMSParser: binary translator for COBOL field operations

**HATS Host Access Transformation Services 7.5** added `com.ibm.etools.bms.parser` as a standalone component. It is absent from v71. Its core is `BMSParser.jj`: a JavaCC grammar 1760 lines that translates COBOL BMS macro definitions into EMF model objects.

BMS Basic Mapping Support defines 3270 screens using COBOL assembler-like macros:

```
MAPSET    DFHMSD TYPE=&SYSPARM,MODE=INOUT,LANG=COBOL,TIOAPFX=YES
MAP1      DFHMDI SIZE=(24,80),LINE=1,COLUMN=1
FIELD1    DFHMDF POS=(3,10),LENGTH=20,ATTRB=(UNPROT,NORM)
          DFHMSD TYPE=FINAL
          END
```

The parser builds a hierarchy: `BMSFile` → `BMSMapset` → `BMSMap` → `BMSField`. Each node is created by an EMF factory: `factory.createBMSField()`, `factory.createBMSMap()`, etc.

The critical structural pattern: per-operand sub-dispatch within a production rule:

```java
// BMSParser.jj
void field_keyword() : {} {
    field_attrb()     // ATTRB=(PROT,BRT)
  | field_pos()       // POS=(3,10)
  | field_length()    // LENGTH=20
  | field_color()     // COLOR=RED
  | field_initial()   // INITIAL='default'
  // ... 15 more sub-rules
}

void field_attrb_value(BMSAttributesType attrb) : {} {
    "PROT"   { attrb.setWriteable(BMSWriteableType.PROTECTED_LITERAL);}
  | "UNPROT" { attrb.setWriteable(BMSWriteableType.UNPROTECTED_LITERAL);}
  | "BRT"    { attrb.setDisplayable(BMSDisplayableType.BRIGHT_LITERAL);}
  | "NORM"   { attrb.setDisplayable(BMSDisplayableType.NORMAL_LITERAL);}
  // ...
}
```

This is a two-level dispatch: `field_keyword()` routes to the right attribute handler; each attribute handler dispatches on attribute values. The factory constructs the output object in phases: `createBMSField()` first, then each attribute sub-rule sets one property.

**Key distinction from AbstractRenderingRulesEngine:** the BMS parser has per-operand sub-dispatch *within* a rule. AbstractRenderingRulesEngine fires one rule per screen region. The BMS parser fires one sub-rule per operand token within a field declaration. Together they define two levels of dispatch: field-level which rule handles this instruction and operand-level how to lift each operand.

**v71 vs v75:** v71 has no `bms.parser` JAR. BMS field translation was embedded in the v71 core. v75 refactored it into an explicit JavaCC grammar, making the translation structure machine-readable.

**Ablation ExprLifter mapping:**

```python
# BMSParser.jj factory.createBMSField()  ≡  ExprNode.add() / ExprNode.load()
# field_keyword() per-operand dispatch   ≡  separate operand lifting within LiftRule.recognise()
# field_attrb setWriteable/setDisplay    ≡  ExprNode.ctype, ExprNode.tainted flags

# Example: a LiftRule that lifts a load-and-add pair, handling each operand separately
def recognise_load_add(insns):
    if len(insns) < 2: return None, 0
    load, add = insns[0], insns[1]
    if load.mnemonic != 'ld' or add.mnemonic != 'add': return None, 0
    addr  = _lift_operand(load.operands[0])   # per-operand sub-dispatch
    base  = _lift_operand(add.operands[1])    # per-operand sub-dispatch
    return ExprNode.add(ExprNode.load(addr), base), 2
```

---

### HATS: the pattern-recognition and rewrite engine

**HATS Host Access Transformation Services 7.5** transforms IBM 3270 terminal screen fields into web UI components. Its `AbstractRenderingRulesEngine.processScreen()` implements a greedy consumption model that maps directly to an instruction-level rewrite engine.

The algorithm from `AbstractRenderingRulesEngine` bytecode hsrendering.jar:

```
1. Build ConsumableFieldList from HsrScreen  (≡ ConsumableInsnList from basic block)
2. Get Iterator over IRenderingRuleSet rules  (≡ iterate LiftRules in priority order)
3. While unmatched fields remain AND rules remain:
   a. Get next rule (IRenderingRule)
   b. Skip if rule.isEnabled() is false
   c. PatternComponent.newInstance(rule.componentClassName, classLoader, screen, fieldList)
      (≡ factory-instantiate the pattern component by class name)
   d. component.recognize(region, settings) → ComponentElement[]
      (≡ try rule.pattern.match(window) → IRNode[] if matched, None if not)
   e. If matched: consume matched fields, emit ComponentElement[]
      (≡ consume matched instructions, emit IR nodes)
4. Consumed fields are gone; remaining unmatched fields fall through to default
```

**Key constraints visible in the bytecode:**
- The loop exits when `consumedCount >= fieldList.size()`: all fields consumed, OR the rule iterator is exhausted. This is greedy: the first rule that matches a region wins.
- `PatternComponent.newInstance()` instantiates by class name string: the component class is stored in `RenderingRule.componentClassName`, not hardcoded. This is the extensible factory pattern.
- `ComponentElement[]` (plural): one rule match can produce multiple IR nodes.

**Ablation ExprLifter mapping:**

```python
@dataclass
class LiftRule:
    name: str                # rule identifier
    pattern: InsnPattern     # window matcher: InsnPattern.match(insns) -> Optional[List[IRNode]]
    node_class: str          # 'ablation.ir.Add', 'ablation.ir.Load', etc.
    enabled: bool = True

class ExprLifter:
    def lift(self, insns: List[Insn]) -> List[IRNode]:
        """Greedy consumption: lift each instruction window to IR."""
        consumable = ConsumableInsnList(insns)
        nodes = []
        while not consumable.empty():
            for rule in self._rules:
                if not rule.enabled:
                    continue
                window = consumable.peek(rule.pattern.width)
                matched = rule.pattern.match(window)
                if matched:
                    consumable.consume(rule.pattern.width)
                    nodes.extend(matched)
                    break
            else:
                # No rule matched: emit fallback node for head instruction
                nodes.append(IRNode.opaque(consumable.pop()))
        return nodes
```

---

### XLC/OMR: value numbering and per-opcode simplifier dispatch

**WCodeDriver** IBM XL C++ for s390x, 26MB, unstripped uses the Eclipse OMR JIT framework. Its exported symbols reveal the optimizer pass structure. All passes are confirmed by `c++filt` demangled symbol names.

**Value numbering** (`TR_ValueNumberInfo`, 37 exported functions):

| Symbol | Purpose |
|:---|:---|
| `TR_ValueNumberInfo::initializeNodeTR::Node*, int&` | Assign initial value number to a new node |
| `TR_ValueNumberInfo::congruentNodesTR::Node*, TR::Node*` | Structural equality check: same opcode + same child value numbers |
| `TR_ValueNumberInfo::canShareValueNumberTR::Node*` | CSE eligibility guard: no side effects, no volatile loads |
| `TR_ValueNumberInfo::setValueNumberTR::Node*, TR::Node*` | Assign target's value number to source |
| `TR_ValueNumberInfo::changeValueNumberTR::Node*, int` | Update value number after transformation |
| `TR_ValueNumberInfo::getValueNumberTR::Node*` | Query current value number |

The OMR approach is hash-congruence: two nodes are congruent if they have the same opcode and their children have the same value numbers. `canShareValueNumber()` gates CSE eligibility before `congruentNodes()` runs. This separates the "are they the same expression" check from the "can we share them" check, because aliasing, volatility, and exception ordering make some structurally-equal nodes unsafe to reuse.

**Reaching definitions and dominators: WCodeDriver does not use phi-SSA:**

WCodeDriver uses **GEN/KILL bit-vector reaching definitions** (`TR_UseDefInfo`), not classical phi-SSA. From diagnostic strings in the binary:

- `"Gen and kill sets for block_%d:"`: per-block GEN/KILL computation
- `"completed reaching definition analysis for use/def"`: forward dataflow result
- `"interrupted in backward bit vector analysis"`: liveness computed backward

`TR_UseDefInfo::buildUseDefs()` builds use-def chains via forward dataflow. `TR_Liveness` computes live variable sets via backward dataflow. Both are standard bit-vector analyses. No phi nodes are inserted.

`TR_Dominators::findDominators()` uses the **Lengauer-Tarjan** algorithm. The three auxiliary functions confirm this:

| Function | Lengauer-Tarjan role |
|:---|:---|
| `TR_Dominators::compress(int)` | Path compression on the dominator forest |
| `TR_Dominators::eval(int)` | Evaluate semi-dominator of a DFS ancestor |
| `TR_Dominators::linkint, int` | Link child to parent in the dominator forest |

No other dominator algorithm uses this exact `compress/eval/link` triad. Lengauer-Tarjan runs in O(n α(n)) and is the standard choice for JIT compilers where dominator computation happens at compile time per-function.

**Why reaching definitions rather than phi-SSA:** XLC/OMR processes s390x code that already has physical register assignments from the machine ABI. Phi nodes represent merge points for virtual variables; physical registers have explicit use-def chains. Reaching definitions directly express which assignment reaches which use, without requiring a rename pass. The `TR_ValueNumberInfo` hash-congruence works over this representation because it doesn't need phi merge points: structural equality of expression trees is sufficient.

**Per-opcode simplifier dispatch** (`TR_Simplifier`, 1116 exported functions):

Every IR opcode has a dedicated simplifier function. Function signature pattern: `xyzSimplifierTR::Node*, TR::Block*, TR_Simplifier*`. Examples confirmed in symbol table:

- `sdivSimplifier`: signed division constant folding x/1 → x, x/pow2 → shift
- `i2sSimplifier`: integer-to-short sign extension elimination
- `arraycopybndchkSimplifier`: bounds check removal for provably-safe array copies

**Ablation ExprLifter mapping:**

```python
# Per-opcode dispatch table (one entry per IR opcode)
_SIMPLIFIERS: Dict[str, Callable[['IRNode'], 'IRNode']] = {
    'Add':  simplify_add,    # constant folding, neutral element elimination
    'Mul':  simplify_mul,    # 0/1 elimination, power-of-two → shift
    'Div':  simplify_div,    # constant folding, div-by-power-of-2
    'I2S':  simplify_i2s,    # extend then narrow → narrow directly
    'Load': simplify_load,   # known-address constant load
    # ...
}

class ValueNumberTable:
    """Hash-congruence value numbering over IR nodes."""
    def get_or_assign(self, node: IRNode) -> int:
        if not node.can_share():       # ≡ TR_ValueNumberInfo::canShareValueNumber
            return self._fresh()
        key = self._congruence_key(node)  # ≡ TR_ValueNumberInfo::congruentNodes
        if key not in self._table:
            self._table[key] = self._fresh()
        return self._table[key]

    def _congruence_key(self, node: IRNode):
        # Opcode + child value numbers — the OMR congruence definition
        child_vnums = tuple(self.get_or_assign(c) for c in node.children)
        return (node.opcode, child_vnums)
```

---

### VisualAge CPP EPDC: IR node type hierarchy

**VisualAge CPP iDebug 8.5.7** uses EPDC Engine Protocol for Debug Communication to stream type information between the Java debugger frontend and the C++ backend. The wire protocol uses `EStdTreeNode` as a flat discriminated record; the model layer uses polymorphic subclasses.

**Type hierarchy from `com/ibm/debug/model` class names** jdebug_sui.exe strings:

| Wire type | Model class | IR analogy |
|:---|:---|:---|
| `EStdTreeNode` | `MonitoredExpressionTreeNode` | `IRNode` base class |
| `EStdExpression2` | `MonitoredExpression` | typed expression with value |
| scalar | `ScalarMonitoredExpressionTreeNode` | `IntNode`, `FloatNode` |
| pointer | `PointerMonitoredExpressionTreeNode` | `PtrNode` |
| array | `ArrayMonitoredExpressionTreeNode` | `ArrayNode` |
| struct | `StructMonitoredExpressionTreeNode` | `StructNode` |
| aggregate | `AggregateMonitoredExpressionTreeNode` | `AggNode` |
| class | `ClassMonitoredExpressionTreeNode` | `ObjNode` |

**Key design from EPDC constructor signatures:**

```java
// Deserialization: wire node + parent expression → model node
new MonitoredExpressionTreeNode(EStdTreeNode wire, MonitoredExpression parent)

// Full expression deserialization: wire + type info → typed node
new MonitoredExpression(EStdExpression2 wire, int typeId, short typeFlags,
                        int repType, boolean hasChildren, boolean isModifiable,
                        Client client, ...)
```

The separation of `EStdTreeNode` flat wire format from `MonitoredExpressionTreeNode` (model) means the deserializer reads the type discriminator byte, then calls the appropriate subclass constructor. This is a type-tagged union on the wire, polymorphic on the model side.

**Ablation ExprLifter mapping:**

```python
# Wire format: flat discriminated record
@dataclass
class IRNodeWire:
    opcode: int          # type discriminator
    operands: bytes      # raw operand bytes

# Model: polymorphic nodes
class IRNode:
    @staticmethod
    def from_wire(wire: IRNodeWire) -> 'IRNode':
        """Factory: reads type discriminator, returns appropriate subclass."""
        cls = _NODE_CLASS_BY_OPCODE[wire.opcode]  # dispatch table
        return cls._from_wire(wire)

class IntNode(IRNode):  ...   # scalar integer expression
class PtrNode(IRNode):  ...   # pointer expression
class LoadNode(IRNode): ...   # memory load
class AddNode(IRNode):  ...   # addition
```

The VisualAge pattern confirms: keep the wire format flat type-tagged record and the model layer polymorphic. Never merge both into a single class hierarchy: the wire format must be stable across versions while the model layer evolves.

---

### RAA Rational Application Architect, not acquired

IBM Rational Application Architect contains `com.ibm.raa.core.decompiler.*` implementing Sharir's interval analysis for control-flow structuring if/while/for recovery from CFG. This is the reference for a future **Structurizer** module.

RAA is absent from this collection. The DHE mirror (`public.dhe.ibm.com`) has no RAA directory. The collection's Rational subdirectories contain Apex, DOORS, Rose, and RoseRT, not Application Architect.

**Decision:** ExprLifter operates at expression level single instruction → IR node. It does not perform CFG-level structuring. Sharir's interval analysis is needed for a future Structurizer, not ExprLifter. ExprLifter is not blocked by the absence of RAA.

---

### IBM Dynamite JIT (PowerVM LX86): x86→POWER binary translator

**PowerVM LX86** (`powervm-lx86`, stripped PPC64 ELF) is IBM's x86-Linux binary translator: the evolution of WABI. It runs x86 ELF binaries on POWER via dynamic binary translation. The binary retains full build-time source paths, exposing the complete JIT architecture.

**Source tree reconstructed from debug paths:**

```
src/
├── irConstructor/
│   ├── common/
│   │   ├── GenericExpressionInterface.cc      — abstract Expression* factory API
│   │   └── GenericExpressionInterfaceIRMkI.cc — Mark I IR implementation
│   ├── Sx86-autogen/                          — AUTO-GENERATED from FADE tables
│   │   ├── X86FadeIRDelegate.cc               — x86 integer IR construction
│   │   ├── X86FadeIRDelegate_FP.cc            — x86 FP IR construction
│   │   └── X86FadeIRDelegateSystem.cc         — x86 syscall IR construction
│   └── Sx86/
│       ├── X86DataManagement.cc               — load/store with sign extension
│       ├── X86IRConstructorContext.cc         — per-instruction conversion context
│       ├── NevisFlagManagement.cc             — x86 EFLAGS computation
│       └── X86LazyFlags.cc                   — lazy flag evaluation
└── codeGenerator/
    ├── common/
    │   ├── RegisterAllocator.cc               — target register allocation
    │   └── TraversalOrdering.cc               — node traversal order for emission
    ├── Sx86-Tppc/
    │   ├── BackEnd_X86Atomic.cc               — x86 atomic → POWER lock instructions
    │   ├── BackEnd_X86FloatingPoint.cc        — x86 FP → POWER VMX/FPU
    │   └── Bgenerate.cc                       — main x86→POWER backend driver
    └── Tppc/
        ├── BackEnd.cc                         — POWER instruction emitter
        ├── nodeGenerates.cc                   — per-node 32-bit POWER emission
        └── nodeGenerates64.cc                 — per-node 64-bit POWER emission
```

**IR data types from mangled symbol names:**

| Type | Role |
|:---|:---|
| `Expression*` | IR expression node (equivalent to `ExprNode`) |
| `BasicBlock*` | Basic block container |
| `IR*` | Per-block IR; passed to factory methods |
| `AbstractOperation*` | IR operation statement-level node |
| `Tlabel` | Branch target label |
| `TRegID` / `ARegID` | Target (POWER) / abstract register IDs |
| `TCAccessedVariable` | Shared variable between x86 subject and POWER target |

**Three-stage translation pipeline:**

```
1. Decode:    FADE tables → X86FadeIRDelegate (auto-generated per opcode)
2. Lift:      X86FadeIRDelegate calls GenericExpressionInterface factory methods
              → Expression* IR tree per basic block
3. Emit:      nodeGenerates.cc walks Expression* tree → POWER instructions
```

**Key Expression factory methods from symbol strings:**

```cpp
// X86DataManagement — load/store with type and sign extension
Expression* load(Expression* addr, RegisterID dst, X86SizeType sz, X86SignExtension sext);
void        store(Expression* addr, RegisterID src, Expression* val, X86SizeType sz);

// GenericExpressionInterface — binary arithmetic
static Expression* sub64(IR*, Expression*, Expression*);

// GenericExpressionInterfaceIRMkI — higher-level builders
static Expression*        byteSwapDouble(IR*, Expression*);
static Expression*        byteSwapSingle(IR*, Expression*);
static AbstractOperation* createLabelVersionOfBranch(IR*, AbstractOperation*, Tlabel, bool);
```

**FADE decoder: table-driven autogeneration of IR lifting code**

The `Sx86-autogen/` directory is auto-generated: the FADE Fast Architecture Decoder Engine tables describe x86 instruction encodings. The autogen step creates `X86FadeIRDelegate.cc`, which calls the appropriate `GenericExpressionInterface` factory method for each x86 opcode. This is the same pattern as HATS BMS parser's JavaCC grammar: machine-readable tables auto-generate the per-opcode translation code.

**Lazy flag evaluation** (`X86LazyFlags.cc`)

x86 EFLAGS CF, ZF, SF, OF, PF are computed lazily: they are only evaluated when the translated code reads a flag register. This avoids emitting POWER condition-register update code for every arithmetic instruction when the flags are rarely consumed. The IR keeps flags as separate `Expression*` nodes; `NevisFlagManagement.cc` generates the flag expression when a conditional branch reads CF/ZF/etc.

**Ablation ExprLifter mapping:**

```
FADE tables → X86FadeIRDelegate    ≡    ExprLifter.rules (LiftRule per opcode)
GenericExpressionInterface.load()  ≡    ExprNode.load()
GenericExpressionInterfaceIRMkI    ≡    ExprNode (concrete implementation)
nodeGenerates.cc per-node dispatch ≡    ExprSimplifier._SIMPLIFIERS[op] dispatch
TCAccessedVariable                 ≡    ValueNumberer (shared variable ≡ CSE'd expression)
X86LazyFlags                       ≡    ExprNode.tainted flag (propagated lazily)
```

The two-interface split (`GenericExpressionInterface` abstract + `IRMkI` concrete) confirms the VisualAge EPDC wire/model split appears independently in IBM's JIT framework, it is a stable IBM IR design pattern.

---

### Summary: IBM patterns for ExprLifter

| Concern | IBM source | Pattern |
|:---|:---|:---|
| Field-level rule dispatch | HATS v75 `AbstractRenderingRulesEngine` | Greedy consumption: `ConsumableInsnList` + priority-ordered rules + per-rule `recognise()` |
| Operand-level sub-dispatch | HATS v75 `BMSParser.jj` | Per-operand sub-rules within a production: `field_keyword()` → 20 attribute handlers |
| Table-driven autogen lifting | PowerVM LX86 `X86FadeIRDelegate` (FADE) | Machine-readable decoder tables auto-generate per-opcode IR construction delegates |
| Expression factory interface | PowerVM LX86 `GenericExpressionInterface` | Abstract factory API + concrete `IRMkI` implementation: same wire/model split as VisualAge |
| Per-node POWER emission | PowerVM LX86 `nodeGenerates.cc` | Per-node dispatch table for code generation: mirrors `_SIMPLIFIERS[op]` |
| Lazy flag computation | PowerVM LX86 `X86LazyFlags.cc` | Flags as deferred `Expression*` nodes; computed only on conditional branch |
| Expression simplification | XLC/OMR `TR_Simplifier` 1116 functions | Per-opcode dispatch table: `_SIMPLIFIERS[opcode](node)` |
| Value numbering / CSE | XLC/OMR `TR_ValueNumberInfo` | Hash-congruence: `opcode, child_vnums` key + `canShareValueNumber()` eligibility guard |
| Dominator computation | XLC/OMR `TR_Dominators` | Lengauer-Tarjan O(n α(n)): `compress/eval/link` |
| Dataflow representation | XLC/OMR `TR_UseDefInfo` | GEN/KILL bit-vector reaching definitions; no phi nodes |
| IR node hierarchy | VisualAge EPDC model layer | Flat wire format (`EStdTreeNode`) + polymorphic model (`ScalarNode`, `PtrNode`, …) |
| CFG structuring | RAA `com.ibm.raa.core.decompiler` | **Not acquired**: Sharir interval analysis deferred to Structurizer module |

---

## Further reading

- `docs/guide-re-workflow.md`: how these stages map to the analysis pipeline
- `docs/guide-tool-selection.md`: which tool to use for which task
- `docs/reference-modules/binary-lifter.md`: BinaryLifter ISA backend reference
- `docs/reference-modules/ppc476-lifter.md`: Ppc32Lifter for IBM PPC476 targets
