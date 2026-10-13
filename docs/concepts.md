# Program Analysis Concepts

Reference for the core program analysis techniques used throughout Ablation.

---

## Slicing and copy propagation

### Program slicing

A program slice is the subset of statements that affect, or are affected by, a specific variable at a specific point.

A **backward slice** starts from a variable of interest (the slicing criterion) and walks backward through control and data flow to find every statement that could have contributed to its value. A **forward slice** walks forward to find every statement that the variable could influence.

```python
x = recv(fd, buf, n)   # source
y = x + 1              # included in backward slice of z
z = y * 2              # slicing criterion
w = 7                  # not included: z does not depend on w
system(cmd)            # not included: different variable
```

`TaintTracker.run_interprocedural()` computes a forward slice from a taint source. It tracks which registers and memory locations are reachable from `recv` and checks whether any path reaches a sink. The analysis is register-level rather than statement-level, but the logic is the same.

### Copy propagation

Copy propagation replaces a use of a variable with the value it was copied from, when the source has not changed in between.

```
r3 = recv(...)    # r3 tainted
r5 = r3           # copy: r5 is tainted
system(r5)        # finding: r5 == r3 == tainted
```

Without copy propagation, a taint tracker watching only `r3` misses the sink because `system` receives `r5`.

Every `mov rd, rs` propagates taint from `rs` to `rd`. The taint set is the transitive closure of all copies from the original source register.

**Where copy propagation stops:** address constants are excluded. In LoongArch64, `lu12i.w` and `pcaddi` load address values, not data values, so they are treated as taint-clearing. The HiSilicon `uxtb` and `uxth` instructions bound a register to 255 or 65535 respectively, so they also clear taint because a bounded value cannot carry an exploitable path across that boundary.

---

## Taint analysis vs symbolic execution

### Taint analysis

Taint analysis tracks which values are attacker-controlled. Each register and memory location gets a label: tainted or clean. Rules propagate the label through arithmetic.

```
r3 = recv(...)          # r3 = TAINTED
r4 = r3 + 1            # r4 = TAINTED
r5 = 0xFF              # r5 = CLEAN
r6 = r3 & r5           # r6 = TAINTED
strcpy(dst, r6)         # FINDING: tainted arg at memory sink
```

Taint analysis answers: can attacker data reach this sink? It does not answer whether the attacker can actually trigger that path, or what value would be needed.

Fast. Scales to full binaries. Produces false positives when taint flows through bounds checks that the analyzer does not model as sanitizers.

### Symbolic execution

Symbolic execution replaces concrete values with symbolic expressions and tracks constraints. Instead of tainted or not, it carries the full formula for what a register could hold.

```
r3 = recv(...)          # r3 = α  (fresh symbol)
r4 = r3 + 1            # r4 = α + 1
if (r4 > 255): exit     # path constraint: α ≤ 254
strcpy(dst, r4)         # reachable when α = any value ≤ 254
```

At the sink a constraint solver (Z3, STP) checks whether a concrete value of α satisfies all path constraints. If yes, the path is feasible and a concrete input exists.

Symbolic execution answers: is this path actually reachable and what input triggers it? It does not scale to full binaries because branches multiply the number of paths that must be explored.

### How Ablation uses both

| | Taint | Symbolic |
|---|---|---|
| Tracks | "could attacker data reach here?" | "what values can this expression take?" |
| Answer | Yes/No + chain | Feasibility + concrete witness |
| Cost | O(program size) | O(2^branches) worst case |
| False positives | Yes | No |
| Ablation role | `TaintTracker` — find candidates | `PathSolver` — confirm one candidate |

`TaintTracker.run_interprocedural()` is cheap enough to run on a whole binary and produces a short candidate list. `PathSolver.solve_path()` is expensive and runs only on one confirmed candidate. Running symbolic execution first would hit path explosion almost immediately on real firmware.

---

## Data flow analysis vs control flow analysis

### Control flow analysis

Control flow analysis maps the structure of execution: which instructions can run after which others, which branches exist, and which functions call which.

The output is a Control Flow Graph (CFG). Nodes are basic blocks (straight-line sequences with no branches). Edges are possible transfers of control.

```
       [entry: r3 = recv(...)]
              |
        [r3 > 0?]
       /         \
  [yes: process]  [no: return -1]
       |
  [strcpy(dst, r3)]
       |
     [exit]
```

Control flow analysis answers: can this sink ever be reached? Are there loops? What are the dominators? Control flow analysis says nothing about what the values are.

In Ablation, `cfg_loongarch64`, `cfg_riscv`, and the other CFG builders are control flow analysis. They classify instructions as leaders, terminators, or interior instructions and connect them into blocks.

### Data flow analysis

Data flow analysis maps how values move through the program. It uses the CFG as the substrate and propagates facts along edges until a fixed point is reached.

```
Block 1:  r3 = recv(...)   OUT: {r3 = TAINTED}
Block 2:  r4 = r3 + 1     IN: {r3 = TAINTED}  OUT: {r3, r4 = TAINTED}
Block 3:  strcpy(dst, r4)  IN: {r4 = TAINTED}  FINDING
```

Classic data flow problems:

| Problem | Question | Direction |
|---|---|---|
| Reaching definitions | Which assignment of X reaches this use? | Forward |
| Live variables | Is X still needed after this point? | Backward |
| Taint analysis | Does attacker data reach this point? | Forward |
| Constant propagation | Does this register always hold the same constant? | Forward |

In Ablation, `analysis_loongarch64` runs a flow-sensitive fixpoint over the CFG blocks. It is data flow analysis built on top of the CFG that `cfg_loongarch64` produced.

### The relationship

Control flow analysis must run before data flow analysis. The CFG is the graph. Data flow analysis computes facts on it.

Control flow analysis answers: can execution get there?  
Data flow analysis answers: what is true when execution gets there?

---

## Intraprocedural vs interprocedural analysis

### Intraprocedural analysis

Intraprocedural analysis examines one function at a time. Calls to other functions are treated as black boxes. The analyzer assumes the worst (or the best, depending on the goal) and continues past each call site.

The CFG stays within one function's boundaries. Fast. Scales to any binary. Misses paths where taint passes through a callee and comes back.

**In Ablation:** `RH850TaintTracker.run()` and `scan_function()` calls are intraprocedural.

### Interprocedural analysis

Interprocedural analysis follows execution across function call boundaries. When a call is encountered, the analyzer descends into the callee, propagates facts through it, and carries results back to the caller.

```python
def sanitize(data):
    return data          # interprocedural sees: returns tainted input unchanged

def process_input(data):
    x = sanitize(data)   # descend into sanitize: x is still TAINTED
    strcpy(dst, x)       # FINDING
```

The analysis builds a call graph and propagates facts along its edges. It finds paths that cross multiple function boundaries. Each callee's analysis feeds back into the caller so the cost grows with call graph depth.

**In Ablation:** `TaintTracker.run_interprocedural(depth=N)` — BFS over the call graph up to N frames deep.

### Context sensitivity

The same function can be called from multiple sites with different taint states. A context-insensitive interprocedural analysis merges all call sites: if any produces taint, all do. This causes false positives. A context-sensitive analysis tracks each call site separately at much higher cost.

Ablation's `run_interprocedural()` is context-insensitive. It computes one taint summary per function and reuses it at every call site. This is the right tradeoff for stripped firmware where the call graph itself is uncertain.

| | Intraprocedural | Interprocedural |
|---|---|---|
| Scope | One function | Whole program up to depth limit |
| Call sites | Opaque | Transparent |
| Cost | O(function size) | O(call graph × depth) |
| False negatives | Higher | Lower |
| When to use | Large binary triage | Confirmed candidate |

The `depth=` parameter bounds cost. At `depth=1` the behavior approximates intraprocedural: a taint source in function A only reaches sinks also in function A. At `depth=4` (the default) the analysis follows chains like `recv → parse_header → copy_field → strcpy`.

---

## Static vs dynamic analysis

### Static analysis

Static analysis examines a program without running it. It reads the binary or source, builds models of behavior, and draws conclusions from those models alone.

Everything Ablation does is static analysis. The binary never executes.

Strengths:
- Every code path is visible in principle, including error paths and rarely-triggered branches
- Safe: no risk of triggering the vulnerability on a live system
- Works on firmware that cannot execute (no hardware, wrong OS, missing dependencies)
- Reproducible: the same binary produces the same results every run

Weaknesses:
- Conservative assumptions produce false positives to avoid false negatives
- External calls are opaque: `recv()` is a black box so the analyzer must assume what it returns
- Runtime values are invisible: loop counts, heap layout, JIT-compiled code, and dynamically loaded libraries cannot be observed
- Obfuscation and self-modifying code defeat it

### Dynamic analysis

Dynamic analysis examines a program by running it and observing what actually happens. It instruments execution and records concrete behavior.

Examples: fuzzing (AFL, libFuzzer), dynamic taint tracking (Valgrind, DynamoRIO), debugger tracing, syscall recording (strace), emulation (QEMU with instrumentation).

Strengths:
- Only sees real behavior: no false positives on paths that never execute
- Captures runtime values, heap state, JIT output, and dynamically loaded code
- Finds bugs that static analysis cannot model (race conditions, timing side-channels)

Weaknesses:
- Coverage problem: only exercises paths that test inputs trigger
- Requires execution: needs hardware, OS, firmware dependencies, or an accurate emulator
- Misses paths that are never triggered: a bug behind a rarely-hit branch may never appear

### How they complement each other

| | Static | Dynamic |
|---|---|---|
| Runs the binary? | No | Yes |
| Coverage | All paths in principle | Only executed paths |
| False positives | Yes | No (what ran, ran) |
| False negatives | Yes (conservative assumptions) | Yes (untriggered paths) |
| Runtime values | Unknown | Exact |
| Needs hardware/OS | No | Usually |

Static analysis finds the candidate: a taint path from `recv` to `strcpy` that looks exploitable. Dynamic analysis confirms it: run the binary under instrumentation with a crafted input and observe whether the overflow fires.

The Ablation pipeline ends at `PathSolver`, which is still static. It uses a constraint solver to check feasibility rather than executing the binary. A full confirmation loop hands `PathSolver`'s output to a fuzzer or emulator that drives the actual execution to the sink.

The `SinkArgClassifier` step (between `FuncProfiler` and `TaintTracker` in the pipeline) narrows the static/dynamic gap. It does one more static pass to eliminate sinks where the dangerous argument is provably a compile-time constant (RODATA_CONST). This removes false positives before the expensive interprocedural pass runs, without needing to execute the binary.
