# CFG Analysis Engine (analysis_arc, analysis_x86, analysis_ppc)

Path-insensitive, flow-sensitive dataflow analysis over architecture-specific CFGs. Three modules: `analysis_arc.py`, `analysis_x86.py`, `analysis_ppc.py`. Entry point is `analyze_cfg(insns, mode, initial)` in each.

---

## Why this exists

1. **Taint trackers and CFG builders are separate layers that need a coordinator.** `cfg_arc` builds the CFG from instruction stream; `taint_tracker_arc_labeled` propagates taint state. Without an analysis engine to run the MFP (meet over all paths) worklist iteration, callers would have to implement the fixed-point loop themselves — and get the loop-head handling wrong.

2. **Loop heads need special treatment.** Naive worklist iteration over cyclic CFGs may not converge if loop-back edges re-inject tainted state at loop heads without a convergence check. `analyze_cfg` identifies loop heads with an iterative DFS (`_loop_heads()`) and applies the join-then-propagate order that guarantees termination in `max_iterations` steps.

3. **All three arches use the same MFP algorithm.** `analysis_arc`, `analysis_x86`, and `analysis_ppc` are structurally identical — they differ only in which arch-specific CFG builder, ISA model, and taint tracker they import. A single doc covers all three.

---

## Modules

| Module | Arch | Imports |
|:---|:---|:---|
| `analysis_arc.py` | ARC EM/HS | `cfg_arc`, `isa_arc`, `taint_tracker_arc_labeled` |
| `analysis_x86.py` | x86 / x86-64 | `cfg_x86`, `isa_x86`, `taint_tracker_x86_labeled` |
| `analysis_ppc.py` | PPC32 / PPC64 | `cfg_ppc`, `isa_ppc`, `taint_tracker_ppc_labeled` |

---

## Usage

```python
from ablation.analyzers.analysis_arc import analyze_cfg
from ablation.analyzers.taint_tracker_arc_labeled import TaintState
from ablation.analyzers.isa_arc import Mode
from ablation.analyzers.insn_arc import from_listing

init = TaintState()
init.regs["r0"] = Taint(frozenset({"user"}), None)

result = analyze_cfg(list(from_listing(disasm_text)), Mode.HS, initial=init)
for f in result.findings:
    print(f)
```

```python
# x86-64 variant
from ablation.analyzers.analysis_x86 import analyze_cfg
from ablation.analyzers.taint_tracker_x86_labeled import TaintState
from ablation.analyzers.isa_x86 import Mode

init = TaintState(Mode.X64)
init.taint_reg("rdi", "user")
result = analyze_cfg(insns, Mode.X64, initial=init)
```

---

## CFGResult fields

| Field | Type | Content |
|:---|:---|:---|
| `cfg` | `CFG` | Built CFG (basic blocks, successors) |
| `findings` | `List[Finding]` | Taint-sink findings from this analysis run |
| `entry_states` | `Dict[int, TaintState]` | Taint state at entry to each basic block |
| `exit_states` | `Dict[int, TaintState]` | Taint state at exit from each basic block |
| `iterations` | `int` | Number of MFP worklist iterations to convergence |
| `unknown` | `Set[str]` | Register names the taint tracker could not resolve |
| `unreachable` | `List[int]` | Basic block IDs that were never reached |

---

## Convergence

The MFP worklist runs up to `max_iterations=10_000` iterations. Loop heads are identified first by iterative DFS (no recursion — `_loop_heads()` uses an explicit stack). For CFGs without unbounded taint explosion (typical of stripped firmware functions), convergence occurs in under 50 iterations.

---

## When to use directly

For most binary RE workflows, use the arch-specific TaintTracker (`TaintTracker.from_path()`) which internally calls `analyze_cfg`. Use `analyze_cfg` directly when:
- You have a hand-written listing (captured from objdump output or manual disassembly)
- You need to inspect per-block entry/exit taint states for debugging
- You need the `CFG` object itself for structure analysis

---

## See also

- [ISA Models](isa-models.md) — ABI constants and `canon_reg()` used internally
- [Insn Models](insn-models.md) — `Insn` dataclass consumed as input
- [Taint Analysis](taint-analysis.md) — higher-level `TaintTracker.from_path()` API
