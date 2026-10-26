# SSABuilder

## Why this exists <sup>[↑](#ssabuilder)</sup>

1. `trace_arg()` stops with `BSR_RETVAL` when the target register was set by a
   prior call. It cannot follow the taint across a basic block boundary because
   it does a linear backward scan within a single block window.

2. `SinkArgClassifier` stops at `ARG_PROPAGATED` — it knows the argument came
   from outside the block, but cannot say which instruction in which predecessor
   block defined it.

3. For multi-block functions on Alpha AXP and x86-64, the correct answer to
   "what value is in r0 at this RET?" requires traversing the dominator tree and
   tracking phi functions at merge points. This is exactly what SSA provides.

## Constructor <sup>[↑](#ssabuilder)</sup>

```python
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

1. **Def-site collection** — scans each `BasicBlock` via `arch.dest_reg()` and
   `arch.call_clobbers()` to record which blocks define each register.

2. **Phi insertion** — computes iterated dominance frontiers (from
   `DomTree.dom_frontier()`). Inserts a phi node at every block in `DF+(def_site)`
   for each register that is defined in multiple blocks.

3. **Variable renaming** — DFS over the dominator tree with per-register version
   stacks. Assigns a fresh version at each definition; fills phi arguments by
   looking up the current version on entry to each successor.

## `SSAForm` methods <sup>[↑](#ssabuilder)</sup>

```python
ssa.reaching_def(reg: str, use_va: int) -> Optional[SSAName]
```
Returns the SSA name of `reg` at the point just before the instruction at
`use_va`. This is the correct replacement for `trace_arg()` for cross-block
queries.

```python
ssa.defs_of(name: SSAName) -> List[int]
```
Returns all instruction VAs (and phi-node block VAs) that define `name`.

```python
ssa.uses_of(name: SSAName) -> List[int]
```
Returns all instruction VAs where `name` is in scope as a potential use.

```python
ssa.report() -> str
```
Human-readable phi summary: block VA, phi result, incoming (pred_va, SSA_name)
pairs.

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

## Known limitations <sup>[↑](#ssabuilder)</sup>

- Version 0 (`r0_0`) means "defined before the function entry" — i.e., a
  function argument or an uninitialized register. Treat it as an external source.
- The renaming pass uses a recursive DFS. For very deep dominator trees
  (pathological loops with hundreds of nested levels) this can hit Python's
  default recursion limit. Increase with `sys.setrecursionlimit()` if needed.
- Phi arguments are filled based on CFG successor edges. If the CFG has
  unreachable blocks (blocks with no predecessors except the entry), their
  phi args may contain only version-0 names.
