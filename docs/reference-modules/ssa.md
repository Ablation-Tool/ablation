<a id="ssabuilder"></a>
# Static Single Assignment

  - [What is Static Single Assignment form?](#what-is-static-single-assignment-form)
  - [Why this exists](#why-this-exists)
  - [Constructor](#constructor)
  - [build() → SSAForm](#build--ssaform)
  - [SSAForm methods](#ssaform-methods)
  - [SSAName](#ssaname)
  - [Typical usage for DX-001 class findings](#typical-usage-for-dx-001-class-findings)
  - [Known limitations](#known-limitations)

**File:** `ablation/analyzers/ssa.py`

---

## What is Static Single Assignment form? <sup>[↑](#ssabuilder)</sup>

Static Single Assignment (SSA) form is a property of an intermediate representation in which every variable is defined exactly once. When a source-level variable is assigned in two branches of an `if` statement, SSA creates two distinct versions of that variable (for example `r0_1` on the true branch and `r0_2` on the false branch) and inserts a "phi function" at the merge point that selects between them based on which branch was taken. The phi function carries no runtime cost: it is a representation artifact that makes the control-flow-sensitive reaching definition explicit.

The algorithm for computing SSA was published by Cytron et al. in 1991 ("Efficiently computing static single assignment form and the control dependence graph"). It works in two passes over the control flow graph. The first pass places phi functions at "dominance frontier" join points: the set of blocks where a definition on one path meets an alternative definition on another path, specifically the minimal set that makes every use dominated by exactly one definition. The second pass renames all uses and definitions to add version numbers using a depth-first traversal of the dominator tree.

Ablation uses `SSABuilder` because linear-scan taint trackers (the `TaintTracker` family) cannot follow a register value across basic-block boundaries. When `rax` holds a tainted length in block A, flows through a conditional branch, and reaches a `malloc` call in block C, a linear scan of block C alone does not see the taint origin. SSA's reaching-definition query resolves this: `SSAForm.reaching_def('rax', malloc_va)` returns the single SSA name that reaches the malloc call site, and `SSAForm.defs_of(name)` returns the instruction that defined it. This closes the "DX-001 class" gap where taint across basic blocks required manual trace.

## Why this exists <sup>[↑](#ssabuilder)</sup>

1. `trace_arg()` stops with `BSR_RETVAL` when the target register was set by a
   prior call. It cannot follow the taint across a basic block boundary because
   it does a linear backward scan within a single block window.

2. `SinkArgClassifier` stops at `ARG_PROPAGATED`: it knows the argument came
   from outside the block, but cannot say which instruction in which predecessor
   block defined it.

3. For multi-block functions on Alpha AXP and x86-64, the correct answer to
   "what value is in r0 at this RET?" requires traversing the dominator tree and
   tracking phi functions at merge points. This is exactly what SSA provides.

## Constructor <sup>[↑](#ssabuilder)</sup>

```text
SSABuilder(cfg: CFG, arch: ArchConfig)
```

- `cfg`: `dataflow_engine.CFG` produced by `CFGBuilder.build()`.
- `arch`: any `ArchConfig` (or `RawArchConfig`) implementing `dest_reg()`,
  `all_regs()`, `is_call()`, `call_clobbers()`.

```python
from ablation.analyzers.dataflow_engine import CFGBuilder, make_arch
from ablation.analyzers.ssa import SSABuilder

arch = make_arch('alpha')
cfg  = CFGBuilder(arch, data, base).build(func_va)
ssa  = SSABuilder(cfg, arch).build()
```

## `build()` → `SSAForm` <sup>[↑](#ssabuilder)</sup>

Runs three phases (Cytron et al. 1991):

1. **Def-site collection**: scans each `BasicBlock` via `arch.dest_reg()` and
   `arch.call_clobbers()` to record which blocks define each register.

2. **Phi insertion**: computes iterated dominance frontiers (from
   `DomTree.dom_frontier()`). Inserts a phi node at every block in `DF+(def_site)`
   for each register that is defined in multiple blocks.

3. **Variable renaming**: DFS over the dominator tree with per-register version
   stacks. Assigns a fresh version at each definition; fills phi arguments by
   looking up the current version on entry to each successor.

## `SSAForm` methods <sup>[↑](#ssabuilder)</sup>

```text
ssa.reaching_def(reg: str, use_va: int) -> Optional[SSAName]
```
Returns the SSA name of `reg` at the point just before the instruction at
`use_va`. This is the correct replacement for `trace_arg()` for cross-block
queries.

```text
ssa.defs_of(name: SSAName) -> List[int]
```
Returns all instruction VAs (and phi-node block VAs) that define `name`.

```text
ssa.uses_of(name: SSAName) -> List[int]
```
Returns all instruction VAs where `name` is in scope as a potential use.

```text
ssa.report() -> str
```
Human-readable phi summary: block VA, phi result, and incoming pairs of
predecessor VA and SSA name.

## `SSAName` <sup>[↑](#ssabuilder)</sup>

```python
@dataclass(frozen=True)
class SSAName:
    reg: str     # e.g. 'r0'
    ver: int     # version (0 = entry/undefined, 1+ = defined)

str(SSAName('r0', 3))  # → 'r0_3'
```

## Typical usage for DX-001 class findings <sup>[↑](#ssabuilder)</sup>

```python
from ablation.analyzers.insn_alpha import AlphaEcoffScanner
from ablation.analyzers.alpha_cfg import AlphaCFGBuilder
from ablation.analyzers.arch_configs_raw import AlphaAXPConfig
from ablation.analyzers.dataflow_engine import CFGBuilder
from ablation.analyzers.ssa import SSABuilder

scanner = AlphaEcoffScanner('/tmp/dxexec')
data, gp, sections = scanner._load()

# Build SSA for the system() wrapper
arch = AlphaAXPConfig()
cfg  = CFGBuilder(arch, data, 0).build(0x120184f00)
ssa  = SSABuilder(cfg, arch).build()

# What is r0 at each RET instruction?
for va, block in cfg.blocks.items():
    if block.is_ret:
        for insn in block.insns:
            if arch.is_return(insn):
                name = ssa.reaching_def('r0', insn.address)
                print(f'  RET 0x{insn.address:x}: r0 = {name}')
                print(f'  defined at: {[hex(v) for v in ssa.defs_of(name)]}')
```

## Role in the analysis workflow

SSA is a small semantic foundation used when a linear scan is not enough. It lets a reviewer ask which definition reaches a use across branches instead of manually reconstructing every predecessor. That can improve taint queries, return-value analysis, and pseudo-C generation while leaving the underlying CFG and instruction evidence available for verification.

It is not a standalone decompiler or a proof that every merged value is feasible. Architecture adapters and CFG recovery can improve independently, and the same SSA layer can be reused when those inputs change. Correct dominance and successor relationships are therefore prerequisites for the precision this component provides.

## Known limitations <sup>[↑](#ssabuilder)</sup>

- Version 0 (`r0_0`) means "defined before the function entry": i.e., a
  function argument or an uninitialized register. Treat it as an external source.
- The renaming pass uses a recursive DFS. For very deep dominator trees
  (pathological loops with hundreds of nested levels) this can hit Python's
  default recursion limit. Increase with `sys.setrecursionlimit()` if needed.
- Phi arguments are filled based on CFG successor edges. If the CFG has
  unreachable blocks (blocks with no predecessors except the entry), their
  phi args may contain only version-0 names.
