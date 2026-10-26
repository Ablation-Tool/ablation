# AlphaTaintTracker

## What Alpha AXP is

**Alpha AXP** (also written Alpha or DEC Alpha) is a 64-bit RISC processor architecture designed by Digital Equipment Corporation (DEC) and released in 1992. It was DEC's attempt to replace their aging 32-bit VAX line with something fast enough to last twenty years. The architecture was pure 64-bit from day one — no 32-bit compatibility mode, no segmentation, no x87 float stack. Every instruction is 32 bits wide, every register is 64 bits wide, and the load/store model is strict (no memory-to-memory operations).

Alpha was used in DEC workstations and servers running **Tru64 UNIX** (originally called OSF/1) and **OpenVMS**. IBM AIX and several other commercial UNIX systems ran on Alpha hardware. Later, Linux was ported to Alpha and saw production use into the 2000s.

DEC was acquired by Compaq in 1998. Compaq was acquired by HP in 2002. HP EOL'd Alpha in 2007. The result is a large installed base of Alpha firmware, server software, and embedded code that is still running today — on real hardware in some cases, and far more commonly in emulated environments used to host legacy applications.

**Why Alpha binaries show up in RE work:** industrial control systems, telecoms infrastructure, financial backend systems, and military/government installations ran Tru64 or OpenVMS for decades and many never migrated off. When you're doing RE on legacy infrastructure or doing firmware analysis on hardware that predates ARM-everywhere, you encounter Alpha. It is also common in IBM research/academic code distributions and in archived OS source trees.

### Chip generations

The three variants in the ablation corpus represent the three major commercial generations:

| Chip | Codename | Year | Key changes |
|:--|:--|:--|:--|
| **21064** | EV4 | 1992 | First Alpha. 200 MHz. 2-issue in-order pipeline. On-die 8 KB I-cache + 8 KB D-cache. 64-bit integer, 64-bit IEEE 754 FP. |
| **21164** | EV5 | 1995 | 4-issue in-order. 96 KB L2 on-die. Added the `AMASK`/`IMPLVER` extension model. Up to 333 MHz. |
| **21264** | EV6 | 1998 | Out-of-order execution (first Alpha with OoO). 2 MB L2 external. Up to 667 MHz. Added BWX (byte/word extension — prior Alphas had no byte-granular load/store). |

From a binary analysis standpoint the differences rarely matter — the instruction encoding and calling convention are the same across all three. The exception is **BWX** (`LDBU`/`LDWU`/`STB`/`STW` opcodes): binaries compiled for 21064 avoid byte/word memory operations and use masks instead; 21264 binaries may use them freely. The taint tracker handles all three transparently.

### Binary formats: ECOFF vs ELF

Alpha binaries come in two formats:

**ECOFF** (Extended COFF) is the native Tru64/OSF/1 format. It stores the **GP (global pointer) value** in the optional header — a literal integer that tells the dynamic linker what value to load into r29 before calling any function. Every `LDQ Ra, disp(gp)` instruction is a GOT dereference: `Ra ← *GOT[gp + disp]`. Without the correct GP value you cannot resolve what string a `system()` argument points to. `AlphaEcoffScanner._load()` reads GP from the ECOFF header automatically.

**ELF** is used for Linux Alpha and cross-compiled targets. GP is not stored in the header; it must be recovered from the `.got` section or from `_gp` symbol. The tracker falls back to heuristic GP recovery for ELF (see Limitations).

---

## Taint tracking vs. decompilation — what each one does

Ablation has two separate pipelines for Alpha AXP. They answer different questions.

**The decompiler pipeline** (`AlphaIRLifter` → `SSABuilder` → `PseudoCEmitter`) answers: *what does this function compute?* It lifts raw Alpha instructions to an architecture-neutral IR, builds SSA form, recovers struct field access patterns, and emits pseudo-C. Use it when you need to understand a function's logic.

**The taint tracker** (`AlphaTaintTracker`) answers: *does attacker-controlled data reach a dangerous function call?* It does not try to understand what the code computes — it only asks whether a register holding user-controlled data is passed as the first argument to `system()`, `execv()`, `popen()`, or similar exec-class sinks. This is the vulnerability scanner path.

The two pipelines are independent but complementary. A typical workflow:

```
1. AlphaEcoffScanner.scan()          → find all BSR calls to exec-class sinks (fast)
2. AlphaEcoffScanner.trace_arg()     → single-block backward trace on each call site
3. AlphaTaintTracker.scan_function() → full CFG-fixpoint trace for calls trace_arg can't resolve
4. AlphaCFGBuilder.trace_return_value() → recover what string a tainted return value points to
5. AlphaIRLifter / PseudoCEmitter    → read the code around a confirmed finding to understand context
```

Steps 1–2 classify the easy cases (hardcoded strings, GP-relative constants). Steps 3–4 handle the hard cases (values assembled across multiple basic blocks or passed through wrappers). Step 5 is confirmation and write-up.

**Taint** means: this register may contain a value that an attacker can influence. The tracker seeds entry registers as tainted (all of r16–r21 = the six argument registers) and forwards that label through the function. If a tainted register is passed to `system()`, that is a finding. The label doesn't say what the attacker can do — only that the data came from an attacker-influenced source. Whether it's actually exploitable requires the manual step (step 5).

---

## Why AlphaTaintTracker exists (gaps in the linear scanner)

The existing `taint_tracker_*.py` family — and `AlphaEcoffScanner.trace_arg()` — does **linear backward scans within a single basic-block window**. That is fast and sufficient for the common case (a string constant loaded two instructions before the call). Three concrete gaps motivated a CFG-aware replacement:

1. **No cross-block propagation.** Taint does not follow edges across basic block boundaries. A value set in block A that flows to block B via a conditional branch is invisible to block B's analysis.

2. **No phi-node merging at join points.** When two paths converge (e.g. after an if/else), the taint from either predecessor is not merged into the successor's state. A register tainted on *one* incoming path is treated as clean after the join.

3. **BSR_RETVAL terminates the trace.** `trace_arg()` stops when the target register is the return value of a prior call. The callee is not entered, so exec findings inside wrapper chains (`foo() → bar() → system()`) are missed.

`AlphaTaintTracker` fixes all three by using **forward CFG-fixpoint propagation** built on `AlphaCFGBuilder`:

- `AlphaTaintState` is threaded forward along CFG edges via a worklist algorithm.
- At merge points (join nodes), incoming states from all predecessors are **unioned** — any predecessor that taints a register taints the merged result (conservative/sound).
- BSR results are modelled: if a callee itself reaches a sink with tainted args, its return value (r0) is conservatively tainted in subsequent scans.

---

## Alpha AXP architecture background

Understanding the tracker requires knowing the Alpha register file and calling convention.

### Integer register file

| Register(s) | ABI name | Role |
|:--|:--|:--|
| r0 | v0 | Return value (integer / address) |
| r1–r8 | t0–t7 | Caller-save temporaries |
| r9–r14 | s0–s5 | Callee-save |
| r15 | s6 / fp | Frame pointer (callee-save) |
| r16–r21 | a0–a5 | Function arguments (caller-save) |
| r22–r25 | t8–t11 | More caller-save temporaries |
| r26 | ra | Return address (written by BSR) |
| r27 | pv / t12 | Procedure value — used for position-independent code; clobbered by calls |
| r28 | at | Assembler temporary (caller-save) |
| r29 | gp | Global pointer — base for all GP-relative loads (GOT accesses) |
| r30 | sp | Stack pointer |
| r31 | zero | Hardwired zero |

The tracker initialises r16–r21 as tainted (`arg_0`–`arg_5`) for library-function scanning. When scanning a specific call site you typically seed only the registers you care about.

### Instruction encoding

All Alpha instructions are 32 bits wide, aligned on 4-byte boundaries.

```
 31     26 25  21 20  16 15         0
 ┌────────┬──────┬──────┬──────────────┐
 │ opcode │  Ra  │  Rb  │  disp16      │  memory / branch format
 └────────┴──────┴──────┴──────────────┘

 31     26 25  21 20  16 15 13 12 4      0
 ┌────────┬──────┬──────┬───┬──┬──────────┐
 │ opcode │  Ra  │  Rb  │ fn│lit│   Rc    │  operate format (integer ops)
 └────────┴──────┴──────┴───┴──┴──────────┘
```

Key opcodes for taint analysis:

| Opcode (hex) | Mnemonic | Notes |
|:--|:--|:--|
| 0x08 | LDA | Load address: Ra ← Rb + sext(disp16). Used for constant loads and address arithmetic. |
| 0x09 | LDAH | Load address high: Ra ← Rb + sext(disp16)<<16. Often paired with LDA to build a 32-bit address. |
| 0x28 | LDL | Load 32-bit longword from memory. |
| 0x29 | LDQ | Load 64-bit quadword from memory. Most pointer loads are LDQ. |
| 0x2C | STL | Store 32-bit longword. No register is written. |
| 0x2D | STQ | Store 64-bit quadword. No register is written. |
| 0x10–0x17 | INTA/INTL/INTS/INTM | Integer arithmetic (ADD, SUB, MUL, logical, shift). rc = f(ra, rb_or_lit). |
| 0x11, fn=0x20 | BIS | Bitwise OR — the `MOV Ra, Rb` pseudo-op is `BIS Ra, $31, Rc`. |
| 0x30 | BR | Unconditional branch. Ra (usually r31) written with next-PC for computed gotos. |
| 0x34 | BSR | Branch and store return: Ra ← PC+4; branches to disp21 target. The **call** instruction. |
| 0x1A, hint=0 | JMP | Indirect jump. |
| 0x1A, hint=1 | JSR | Indirect subroutine call. |
| 0x1A, hint=2 | RET | Return: indirect branch through ra (usually r26). |
| 0x38–0x3F | BLBS/BEQ/BLT/BLE/BLBC/BNE/BGE/BGT | Conditional branches. |

### BSR target encoding

BSR uses a 21-bit PC-relative displacement in **instruction units** (each unit = 4 bytes):

```
target_va = (BSR_va + 4) + sign_extend_21(disp21) * 4
```

The transfer function and `_resolve_bsr_target()` both use this formula.

### ECOFF / ELF and the GP register

Tru64 / OSF/1 binaries are **ECOFF** (alpha-specific). ELF binaries exist for Linux Alpha and some cross-compiled targets. Key difference for analysis:

- **ECOFF**: GP value is stored in the ECOFF optional header (`aouthdr.gp_value`). `AlphaEcoffScanner._load()` extracts it from the header and passes it to the tracker. All `LDQ Ra, disp(gp)` instructions are GOT-relative accesses: `*GOT[gp + disp]`.
- **ELF**: GP points to the `.got` section base. Parser falls back to heuristic if no `.got` is found.

Without a correct GP value, `LDA/LDAH/LDQ` address resolution fails silently — strings appear as raw VAs rather than resolved values.

---

## Module relationships

```
AlphaTaintTracker
    ├── AlphaCFGBuilder           (alpha_cfg.py)
    │   └── builds per-function BasicBlock CFGs
    ├── AlphaEcoffScanner         (insn_alpha.py)
    │   ├── _load()  → (data, gp_value, sections)
    │   ├── scan()   → List[AlphaExecFinding]    (call-site scan, no taint)
    │   └── trace_arg()                          (single-block backward trace)
    └── _transfer()               (taint_tracker_alpha.py)
        └── per-instruction state update
```

`AlphaEcoffScanner.scan()` + `trace_arg()` are the **fast first pass** (BSR call-site discovery + single-block backward trace). Use them to find candidate call sites quickly. Use `AlphaTaintTracker` when those candidates have taint paths that cross basic blocks or call boundaries.

---

## Constructor

```python
AlphaTaintTracker(
    data:       bytes,
    base:       int,             # load base VA (lowest section VA)
    sections:   Dict,            # name → _Section from AlphaEcoffScanner._load()
    gp_value:   Optional[int],   # GP register value from ECOFF header
    sym_table:  Dict[int, str],  # VA → symbol name (for finding names and sink detection)
)
```

**Or from a path (recommended):**

```python
tracker = AlphaTaintTracker.from_path('/path/to/binary')
```

`from_path()` calls `AlphaEcoffScanner._load()` to get `(data, gp_value, sections)` and `_sym_table()` for symbol names. If the file is not valid ECOFF/ELF, it falls back to raw bytes with `base=0` and an empty symbol table — sink detection by name will not work in that mode.

---

## `scan_function(func_va, init_taint=None, callee_results=None, max_insns=4096)`

Scans a single function for exec-class sink calls with tainted arguments.

**Algorithm:**

1. Calls `AlphaCFGBuilder.build(func_va, max_insns)` to recover the function's basic-block CFG.
2. Seeds the entry block's state with `init_taint`. Default: r16–r21 all tainted with `TaintLabel('arg_N')` — conservative for library functions where all arguments are suspect.
3. Runs **worklist fixpoint**:
   - Dequeues a block VA; copies its entry state.
   - Runs `_transfer(va, insn, state, callee_results)` over every instruction in the block.
   - Propagates the resulting exit state to each successor via `join()` (label-set union per register).
   - If the successor's stored state changed, re-enqueues it. Continues until the worklist is empty.
4. **Finding sweep**: re-executes transfer over each block, checking every BSR instruction. If the BSR target is a known exec-class sink and any of r16–r21 are tainted at that point, emits an `AlphaTaintFinding`.

**Parameters:**

| Parameter | Default | Meaning |
|:--|:--|:--|
| `init_taint` | r16–r21 each tainted with `arg_N` | Entry register state. Override when you know which args are clean. |
| `callee_results` | `{}` | Map from callee VA → taint labels for its return value (r0). Built by `run_interprocedural()`. |
| `max_insns` | 4096 | Instruction limit passed to `AlphaCFGBuilder.build()`. Prevents infinite loops on pathological functions. |

Returns `List[AlphaTaintFinding]`.

---

## `run_interprocedural(depth=3, max_insns=4096)`

Scans the entire binary across up to `depth` fixpoint iterations to discover taint paths through wrapper chains.

**Algorithm:**

```
iteration 0:  scan every function with callee_results = {}
              → finds direct exec calls with tainted args
              → marks those functions' return values as tainted in callee_results

iteration 1:  re-scan functions that call one of the tainted functions from iter 0
              → now the callee's return value (r0) propagates the taint label
              → finds indirect exec paths through one wrapper level

iteration 2:  same, now two wrapper levels deep
...
```

Deduplicates by `(func_va, sink_va)` across iterations. Stops early if no new findings.

Function discovery uses the symbol table when available. If the binary is stripped, falls back to `_heuristic_func_list()` which scans for BSR targets in `.text`.

Returns deduplicated `List[AlphaTaintFinding]`.

---

## `AlphaTaintFinding`

```python
@dataclass
class AlphaTaintFinding:
    func_va:      int                    # VA of the containing function
    func_name:    str                    # symbol name or 'sub_<va>'
    sink_va:      int                    # VA of the BSR instruction calling the sink
    sink_name:    str                    # 'system', 'execv', 'popen', etc.
    tainted_args: List[str]              # e.g. ['r16', 'r17'] — the tainted argument regs
    labels:       FrozenSet[TaintLabel]  # union of all taint labels on tainted_args
    severity:     str = 'HIGH'
```

```python
str(finding)
# [HIGH] 0x120001234 (process_cmd): tainted {r16} -> system @ 0x120001278
# (labels: {arg_0})
```

**Exec-class sinks detected:**

```
system  popen  execl  execle  execlp  execv  execve  execvp  execvpe
system_r  bsd_system
```

Sink matching strips leading underscores and `@version` suffixes to handle OSF/1 symbol decorations.

---

## `AlphaTaintState`

Represents the register taint map at a point in the program.

```python
@dataclass
class AlphaTaintState:
    regs: Dict[str, FrozenSet[TaintLabel]]   # reg name → set of labels; absent = CLEAN
```

```python
state.get('r16')              # frozenset of TaintLabel (empty = CLEAN)
state.is_tainted('r16')       # bool
state.set('r16', frozenset([TaintLabel('argv')]))
state.taint('r16', TaintLabel('argv'))  # adds a label, preserving existing ones
state.join(other)             # returns new merged state (union of labels per reg)
state.equals(other)           # True if identical taint maps
state.tainted_arg_regs()      # ['r16', 'r17', ...] — subset of r16–r21 that are tainted
state.copy()                  # deep copy
```

`CLEAN` is the empty frozenset `frozenset()`. An absent register and an explicitly-clean register are equivalent.

---

## `TaintLabel`

```python
@dataclass(frozen=True)
class TaintLabel:
    name: str   # e.g. 'arg_0', 'argv', 'env', 'network', 'callee_retval:0x12345678'
```

A label is a symbolic tag that identifies the *source* of a taint. Labels are preserved through register moves, arithmetic, and loads (when the address register is tainted). You can seed with any names you find meaningful:

```python
init = {
    'r16': frozenset([TaintLabel('argv')]),
    'r17': frozenset([TaintLabel('env')]),
}
findings = tracker.scan_function(func_va, init_taint=init)
```

`run_interprocedural()` generates `callee_retval:0x<va>` labels internally when it marks a function's return value as tainted.

---

## Transfer function

`_transfer(insn_va, word, state, callee_results)` updates `state` in-place for one instruction. The table covers every Alpha opcode the tracker handles explicitly; all others default to **CLEAN write to Ra** (conservative — treats the result as untainted).

| Opcode | Instruction | Taint effect |
|:--|:--|:--|
| 0x08 | `LDA Ra, d(Rb)` | Ra ← **CLEAN** — constant or address arithmetic. If you need to track the resulting address itself, taint at the load that dereferences it. |
| 0x09 | `LDAH Ra, d(Rb)` | Ra ← **CLEAN** — same rationale. |
| 0x28 | `LDL Ra, d(Rb)` | Ra ← **labels(Rb)**. Memory is not modelled; taint propagates from the address register. |
| 0x29 | `LDQ Ra, d(Rb)` | Ra ← **labels(Rb)**. Same. |
| 0x2C | `STL Ra, d(Rb)` | **No register written.** Store is a side effect; taint is not propagated to a memory model. |
| 0x2D | `STQ Ra, d(Rb)` | **No register written.** Same. |
| 0x34 | `BSR Ra, target` | Ra ← **callee_results.get(target, CLEAN)**. Then clobbers caller-save regs (r0–r8, r23–r28) to CLEAN, *except* Ra. |
| 0x1A hint≠2 | `JMP/JSR Rb` | Indirect call: if Rb is tainted, r0 ← `TaintLabel('indirect_call_retval')`. Caller-saves clobbered. |
| 0x1A hint=2 | `RET` | No register written. |
| 0x30 | `BR Ra, target` | Ra ← **CLEAN** (link-register write; used for computed gotos, not call linkage in practice). |
| 0x31–0x3F | `BEQ/BNE/BLT/...` | **No register written.** Branch condition only. |
| 0x10–0x17 | Integer ops (ADDQ, SUBQ, MULQ, AND, OR, XOR, SLL, SRL, SRA, ...) | `rc ← labels(rb) ∪ labels(rb_or_lit)`. If the instruction uses a literal (bit 12 set), only Rb contributes. |
| All others | Unknown | Ra ← **CLEAN** (conservative). |

**What memory taint means here:** The tracker does not maintain a per-address memory map. When a load (`LDQ Ra, d(Rb)`) fires, the taint on `Ra` comes from `Rb` (the *address register*), not from whatever value was stored at that address. This means:

- A pointer to tainted data: `LDQ Ra, 0(Rb)` where Rb is tainted → Ra is tainted. ✓
- A clean pointer into a tainted buffer: `LDQ Ra, 0(Rb)` where Rb is clean → Ra is clean, even if the buffer contains user-controlled data. This is a **known limitation** — see below.

---

## `AlphaCFGBuilder`

`AlphaCFGBuilder(data, sections, gp_value)` constructs per-function CFGs. Used internally by `AlphaTaintTracker`.

### `build(func_va, max_insns=4096) → CFG`

Builds the CFG via a recursive-descent worklist starting at `func_va`. Each time it encounters a branch:

- **Conditional branch (BEQ/BNE/etc.)**: two successors — fall-through and taken target.
- **BR**: one successor — the branch target. Ra is marked CLEAN.
- **BSR**: does **not** create a CFG edge; treated as a sequential instruction (call-and-continue). The callee is NOT inlined.
- **JMP/JSR** (hint 0/1): indirect — block exits with `is_jmp=True`, no successors recorded.
- **RET** (hint 2): block exits with `is_ret=True`, no successors.

Returns a `CFG` with `blocks: Dict[int, BasicBlock]` and `entry: int`.

### `BasicBlock`

```python
@dataclass
class BasicBlock:
    start_va:  int
    end_va:    int                    # VA of the last instruction in the block
    insns:     List[Tuple[int, int]]  # [(va, insn_word), ...]
    succs:     List[int]              # successor BB entry VAs
    preds:     List[int]              # predecessor BB entry VAs
    is_ret:    bool                   # True if block ends with RET
    is_jmp:    bool                   # True if block ends with indirect JMP (target unknown)
```

### `trace_return_value(cfg, ret_reg=0, window=32) → List[ReturnTrace]`

For each `is_ret` block in `cfg`, scans backward through the block's last `window` instructions to identify what value is in `ret_reg` (default r0, the return value) at the RET. Returns one `ReturnTrace` per exit block.

`ReturnTrace.insn_type` values and their meaning:

| insn_type | Meaning |
|:--|:--|
| `LDA_CONST` | r0 is a small integer constant (e.g. error code). |
| `LDA_GP` | r0 is an address computed as `gp + disp` — usually a `.rodata` string pointer. `.interp` field contains the resolved string. |
| `LDAH_GP` | Same but using `LDAH` (16-bit shifted displacement). |
| `LDQ_GP` | r0 is loaded from GOT: `*GOT[gp + disp]`. `.value` is the GOT-slot value at load time. |
| `BIS_MOV` | r0 ← another register (MOV pseudo-op). One level of register aliasing is resolved. |
| `BSR_RETVAL` | r0 is the return value of a nested BSR call. `.value` is the callee VA. |
| `UNKNOWN` | r0 origin not determined within the window. |

---

## `AlphaEcoffScanner`

`AlphaEcoffScanner` (in `insn_alpha.py`) is the **fast first-pass** tool. Use it before `AlphaTaintTracker` to quickly locate call sites and do single-block argument traces.

```python
from ablation.analyzers.insn_alpha import AlphaEcoffScanner

scanner = AlphaEcoffScanner.from_path('/path/to/binary')
# or: AlphaEcoffScanner.from_context(ctx)

findings = scanner.scan()          # all BSR calls to exec-class sinks
summary  = scanner.scan_summary()  # {sink_name: count}

# For a specific call site:
trace = scanner.trace_arg(caller_va=0x120001234, reg=16, window=32)
print(trace)
```

`trace_arg()` does a **single-block backward trace** from the BSR at `caller_va`. It returns an `AlphaArgTrace` whose `.insn_type` matches the `ReturnTrace` type vocabulary above. Use it to quickly classify a finding as RODATA_CONST, GP_RELATIVE, etc., without the full CFG machinery.

---

## Worked example

```python
from ablation.analyzers.taint_tracker_alpha import AlphaTaintTracker, TaintLabel

# Step 1: load from ECOFF binary
tracker = AlphaTaintTracker.from_path('/media/cowboy/research/IBMaix/usr/bin/ftpd')

# Step 2: scan one function (e.g. 0x1200012a0 = do_command)
findings = tracker.scan_function(0x1200012a0)
for f in findings:
    print(f)
# [HIGH] 0x1200012a0 (do_command): tainted {r16} -> system @ 0x1200014bc
# (labels: {arg_0})

# Step 3: trace the arg at the call site with the linear scanner
from ablation.analyzers.insn_alpha import AlphaEcoffScanner
scanner = AlphaEcoffScanner.from_path('/media/cowboy/research/IBMaix/usr/bin/ftpd')
trace = scanner.trace_arg(0x1200014bc, reg=16)
print(trace.insn_type, trace.interp)
# LDQ_GP   LDQ r16, -48($gp) GOT[0x1400104a0] = 0x1200038c0

# Step 4: full binary scan (interprocedural)
all_findings = tracker.run_interprocedural(depth=3)
print(f'{len(all_findings)} findings across binary')
```

---

## Limitations

1. **Memory taint is not modelled.** If user-controlled data is written to a local stack buffer and then loaded into an argument register via `LDQ Ra, offset(sp)`, the taint on `Ra` depends on whether `sp` itself is tainted (it isn't, normally). Stack-allocated command buffers built with `strcpy` / `snprintf` will be missed unless you seed `sp` as tainted, which produces massive over-approximation.

2. **One-level BIS/MOV alias in `trace_return_value()`.** The backward scan through a RET block only resolves one MOV chain. If r0 ← r5 ← r3 ← BSR, the second alias is not traced.

3. **Indirect call targets are UNKNOWN.** JSR/JMP with an indirect target does not create a CFG edge; if the tainted pointer is itself a function pointer to a sink, the finding is missed.

4. **No floating-point registers.** Alpha has a separate FP register file (f0–f31). Exec-class sinks use integer registers only, so this is rarely a gap in practice.

5. **BSR displacement computation.** Alpha BSR uses a 21-bit signed displacement in *instruction units*. The `_resolve_bsr_target()` formula is `(va + 4) + hint * 4` where `hint` is the 14-bit *hint* field from the instruction word — not the full 21-bit branch displacement. This is correct for direct BSR (where hint carries the low 14 bits of the displacement), but may diverge from actual targets in position-independent code.

6. **Stripped binaries fall back to heuristic function discovery.** `_heuristic_func_list()` only finds BSR targets, not all functions — prologue patterns are not used. Some functions will be missed.

7. **ECOFF only for `from_path()`.** The ELF fallback in `from_path()` does not attempt to resolve GP from `.dynamic` or `.got`. GP will be `None`, making all GP-relative address resolutions fail.

---

## Comparison with existing trackers

| Property | `trace_arg()` (linear backward) | `AlphaTaintTracker` (CFG fixpoint) |
|:--|:--|:--|
| Crosses basic block boundaries | No — single-block window | Yes — worklist over entire CFG |
| Join at merge points | No — no phi merging | Yes — state union at each join node |
| Callee return-value taint | Stops at `BSR_RETVAL` | Modelled via `callee_results` dict |
| Interprocedural depth | 0 (no cross-function) | Up to `depth` (default 3) iterations |
| Memory taint | No | No |
| Speed | ~1 ms per call site | 5–50 ms per function |
| False negatives | Higher (misses cross-block paths) | Lower (conservative union at joins) |
| False positives | Lower (narrower scope) | Higher (conservative — any tainted predecessor taints join) |

**Workflow:** use `AlphaEcoffScanner.scan()` + `trace_arg()` for initial call-site discovery and quick RODATA_CONST classification. Escalate to `AlphaTaintTracker.scan_function()` only for findings where `trace_arg()` returns `BSR_RETVAL` or `UNKNOWN` and the function is non-trivial (multiple blocks).
