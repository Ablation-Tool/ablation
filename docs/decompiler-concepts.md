# Decompiler and IR Lifter Concepts

**Scope:** conceptual reference for all Ablation users  
**Applies to:** `BinaryLifter`, `Ppc32Lifter`, `Ppc476Decompiler`, `ABCDecompiler`, `BEAMLifter`, `DEXLifter`, `MpyLifter`

---

## What this covers

Ablation spans three levels of abstraction for binary analysis. This document defines the levels, explains where each Ablation tool fits, and provides concrete examples of the transformations involved. Understanding the distinction between an **IR lifter** and a **decompiler** prevents misreading tool output and sets correct expectations about what each component can and cannot recover.

---

## Definitions

### Decompiler

**Goal:** Machine code → high-level source code (or source-like code).

- **Input:** Native machine code (x86, ARM, PPC, etc.) in a binary or executable. Also applicable to bytecode (JVM, Dalvik, MicroPython).
- **Output:** A high-level language representation — something that looks like C, C++, or pseudo-C.
- **What it does:**
  - Disassembles machine code to assembly.
  - Recovers control flow (basic blocks, functions, loops, conditionals).
  - Constructs an intermediate representation (IR) internally.
  - Performs high-level analyses and transformations: data-flow analysis, type/variable recovery, control flow structuring.
  - Pretty-prints the IR to C-like code.

A decompiler usually *includes* a lifter internally (to get to its IR), but its primary purpose is to give you readable high-level code, not just an IR.

### IR Lifter

**Goal:** Machine code → intermediate representation (IR) for analysis or transformation.

> An **IR lifter** is a semantic translation engine that takes architecture-specific machine instructions and produces a precise, architecture-neutral intermediate representation. It makes all register, memory, and control-flow effects explicit, organizes them into a control-flow graph, and serves as the foundation upon which program analysis, verification, binary rewriting, and decompilation are built.

- **Input:** Machine code or assembly for a specific architecture.
- **Output:** Architecture-neutral IR (LLVM IR, VEX, BIL, REIL, or similar CFG of basic blocks).
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
- Informally, sometimes the front end of a decompiler (machine code → decompiler IR).

In binary analysis frameworks (angr, BAP, etc.) "lifter" almost always means IR lifter.

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

- **IR lifter's job:** Assembly → IR (below the cut line).
- **Decompiler's job:** IR → High-level code (above the cut line).

A decompiler is: **disassembler + IR lifter + analysis passes + pretty-printer**. An IR lifter is only the middle step. A decompiler always includes a lifter internally; a lifter by itself does not produce decompiled output.

---

## Stage 1 — Machine Code / Assembly

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

## Stage 2 — Intermediate Representation (IR)

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

At this stage: values are explicit temporaries (`t0`, `t1`, …), memory is explicit (`LOAD`/`STORE`), control flow is a graph, but loops and conditionals are still *implicit* in the CFG — not yet `for`/`if` constructs.

### What the IR lifter produces (and stops at)

The lifter stops here. It does not:
- Invent `for`/`while` constructs.
- Assign names (`sum`, `i`) to stack slots.
- Infer types (`int`, `char *`).

### Core lifter responsibilities

1. **Instruction semantics:** translate each opcode into IR ops — `add eax, ecx` → `t2 = t0 + t1`.
2. **Make side-effects explicit:** flags, register writes, memory writes all become IR statements.
3. **Build CFG:** identify basic block boundaries at labels and jumps; connect blocks with IR branches (`IF ... GOTO`).

---

## Stage 3 — Decompiled High-Level Code

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

The IR expresses the *what* (loads, compare, conditional branch). The decompiler recovers the *shape* (loop, condition, increment).

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

**Stage 1 — Assembly (x86-64):**
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

**Stage 2 — IR (lifter output):**
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

**Stage 3 — Decompiled C:**
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
- `CMP reg, imm` → no register change; flags set based on (reg − imm).
- `JZ target` → if zero flag is set, control flow goes to `target`.

The IR makes each of these effects explicit so analysis tools don't have to decode CPU semantics themselves.

**2. Normalization and abstraction.** Architecture quirks are hidden behind a uniform IR model:
- All registers become IR variables/temporaries.
- Memory is exposed through uniform `LOAD`/`STORE` operations.
- Flags become explicit comparisons or flag variables.

Higher-level components don't need to know about x86's `EFLAGS` vs ARM's `CPSR`; they see "if (x == 0) then branch."

**3. Building basic blocks and CFG.** The lifter:
- Splits lifted code into basic blocks (straight-line sequences with one entry, one exit).
- Connects blocks based on direct jumps, conditional branches, calls, and returns.

Output is not just linear IR — it is a **graph structure** that models all possible execution paths.

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

1. **Semantically faithful** — accurately models what machine code does, instruction by instruction. Small inaccuracies break symbolic execution and taint analysis.
2. **Architecture-neutral** — the same IR framework is usable for x86, ARM, MIPS, PPC. Only the lifting rules differ; consumers of IR remain unchanged.
3. **Explicit and analyzable** — hidden side effects (implicit flag updates, implicit stack pointer changes) become explicit IR operations; control flow is explicit in branches and block edges.
4. **Amenable to further transformation** — easy to convert to SSA form; easy to apply standard compiler analyses (data-flow, taint tracking, symbolic execution, binary rewriting).

### What an IR lifter is NOT

- **Not a decompiler.** It does not produce human-readable C/C++ code. It does not infer types, structure loops, or rename variables.
- **Not a disassembler.** A disassembler maps bytes → assembly mnemonics. A lifter maps assembly → IR semantics.
- **Not visible to end-users** of GUI tools like IDA or Ghidra — it is an internal engine component.

### Typical use cases

1. **Program analysis frameworks** — angr (VEX IR), BAP (BIL), Binary Ninja (BNIL/LLIL/MLIL), Miasm, REIL.
2. **Decompilers** — most decompilers use IR as a stepping stone; the decompiler front end is disassembler + IR lifter.
3. **Binary rewriting / instrumentation** — insert logging or security checks by reasoning about IR structure.
4. **Verification and security analysis** — symbolic execution, taint analysis, and model checking all operate on IR graphs rather than CPU-specific artifacts.

### Intuitive analogy

An IR lifter is a **universal translator**: different CPUs "speak" different machine languages (x86, ARM, PPC, RISC-V). The IR is a common language. The lifter translates each CPU's dialect into that common language, preserving all meaning. Higher-level tools (analyzers, decompilers, optimizers) only need to know the IR — not every CPU dialect.

---

## One-sentence contrast

- **IR lifter:** "Given this architecture's instructions, tell me *exactly* what they do in a uniform IR form."
- **Decompiler:** "Given this uniform IR, recover the *human-level structure* (types, variables, loops, if/else) and print it as source-like code."

---

## Zoom-in: from IR to decompiled output, step by step

This walks the exact transition from IR lifter output to final C code. Each step is strictly decompiler work — the lifter is done.

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

### Step 1 (decompiler): build SSA

Convert memory slots to SSA variables with phi nodes at merge points:

```text
loop_cond:
  i_phi   = phi(i_0, i_4)          ; from entry or from inc_i
  sum_phi = phi(sum_0, sum_2)      ; from entry or from do_add
  cond0   = (i_phi < n_arg)
  if cond0 then goto loop_body else goto loop_end
```

`MEM[frame-4]` and `MEM[frame-8]` become named SSA variables. Phi nodes represent merge points that the lifter does not model.

### Step 2 (decompiler): recognize loop

`loop_cond` has a back-edge from `inc_i` → pattern: "condition block with back-edge" = **`while` loop**:

```c
while (i_phi < n_arg) {
    ...
}
```

### Step 3 (decompiler): recognize if

Inside the loop, `loop_body` branches to `do_add` or `inc_i` based on `cond1`. Both converge at `inc_i` → pattern: "branch then converge" = **`if` statement**:

```c
if (v_0 > 0) {
    sum_phi = sum_phi + v_0;
}
```

### Step 4 (decompiler): eliminate phi nodes

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

### Step 5 (decompiler): type inference and renaming

Usage patterns reveal types: `a_arg` is `int *` (indexed with stride 4), `n_arg` is `int`. Stack slots become `sum` and `i`.

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
| `BinaryLifter` (all ISA backends) | 2 → ~3 | Register-tracked pseudo-C per function | Includes NativeVal register state; CFG not fully reconstructed; completeness varies by ISA |
| `Ppc32Lifter` | 2 → ~3 | Register-tracked pseudo-C, PPC32 BE | Linear walk only; no loop structuring |
| `Ppc476Decompiler` | 2 → 3 | Named locals, type annotations, condition expressions, CFG back-edge detection | Closest to a full decompiler for PPC476 Book E targets |
| `ABCDecompiler` | 2 → 3 | Source-like output | Bytecode input |
| `BEAMLifter` | 2 | IR-level pseudo output | Erlang BEAM bytecode; stays at IR, no structuring |
| `DEXLifter` | 2 → ~3 | Source-like output | Dalvik bytecode |
| `MpyLifter` | 2 → ~3 | Source-like output | MicroPython bytecode |
| `JavaModuleAnalyzer` | — | Parser/scanner | Not a lifter or decompiler; operates on class metadata |

**Key nuance:** "Register-tracked pseudo-C" from `BinaryLifter` backends is not the same as full decompilation. The backends produce output closer to Stage 2 with some Stage 3 features (resolved calls, constant folding) but without loop structuring, phi-node elimination, or type inference across call boundaries. Presence of `NativeVal` register tracking is a prerequisite for decompiler-quality output, not proof of it.

---

## Why Ablation does not use Ghidra

Ghidra's decompiler is a full Stage 1 → Stage 3 pipeline and would produce higher-quality structuring for complex functions. Ablation excludes it because:
1. The RE workflow targets automated, reproducible pipeline runs — Ghidra requires a GUI or headless scripting setup that couples poorly with the `BinaryContext` + `SemanticSearcher` + `SinkArgClassifier` pipeline.
2. Ablation's goal is vulnerability analysis, not reverse engineering for comprehension. For that goal, knowing that `system(arg0)` is called with a propagated function argument is more actionable than a pretty-printed for loop.
3. The `Ppc476Decompiler` and similar modules close the gap for the specific ISAs where automated sink tracing needs full argument recovery.

---

## Further reading

- `docs/re-workflow.md` — how these stages map to the analysis pipeline
- `docs/tool-selection-guide.md` — which tool to use for which task
- `docs/module-reference/binary-lifter.md` — BinaryLifter ISA backend reference
- `docs/module-reference/ppc476-lifter.md` — Ppc32Lifter for IBM PPC476 targets
