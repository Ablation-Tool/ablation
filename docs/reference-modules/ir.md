# IR node hierarchy, IRLifters, PseudoCEmitter

## Why this exists

1. `binary_lifter.py` builds strings via `NativeVal` objects — it cannot be
   post-processed for type recovery, constant folding, or struct-field
   annotation because there is no node tree to traverse.

2. `taint_tracker_*.py` operates on raw instructions. Neither can represent
   cross-block flow because there is no IR to attach it to.

3. A frozen dataclass IR is structurally hashable — useful for value numbering,
   CSE, and def-use edges keyed by expression identity.

## IR node hierarchy

All nodes are `@dataclass(frozen=True)`. Structural equality and `hash()` are
free — two nodes with identical fields are equal.

```
IRNode (frozen base)
  ├─ IRConst(value, width=64)          literal integer
  ├─ IRReg(name, ver=0)                register (SSA name via ver)
  ├─ IRPhi(reg, args: Tuple[IRNode])   phi node
  ├─ IRLoad(addr: IRNode, width=64)    memory read
  ├─ IRStore(addr, val, width=64)      memory write (statement)
  ├─ IRBinop(op, lhs, rhs)             +  -  *  /  &  |  ^  <<  >>  u>>
  ├─ IRCmp(op, lhs, rhs)               ==  !=  <  <=  >  >=  u<  u>
  ├─ IRCall(target, args, ret_reg)     function call
  ├─ IRBranch(cond, taken, fallthrough) conditional/unconditional branch
  ├─ IRReturn(val)                     function return
  └─ IRAssign(dest: IRReg, rhs)        register assignment (statement)
```

## Blocks and function graph

```python
@dataclass
class IRBlock:
    start_va: int
    stmts:    List[IRNode]   # IRAssign, IRStore, IRBranch, IRReturn, IRCall
    succs:    List[int]
    preds:    List[int]
    is_ret:   bool = False

@dataclass
class IRIG:
    blocks: Dict[int, IRBlock]
    entry:  int
    arch:   str
```

## Lifters

### `AlphaIRLifter`

```python
AlphaIRLifter(data: bytes, sections: Dict, gp_value: Optional[int])
```

Lifts Alpha AXP basic blocks (from `AlphaCFGBuilder`) to `IRBlock`. Covers:
- `LDA/LDAH` → `IRConst` or `IRBinop('+', base, const)` assignments
- `LDQ/LDL` → `IRLoad`
- `STQ/STL` → `IRStore`
- `BSR` → `IRCall(IRConst(target_va), ...)`
- `JSR/JMP` → `IRCall(IRReg(target_reg), ...)`
- `RET` → `IRReturn(IRReg('r0'))`
- `BR` → `IRBranch(cond=None, taken=...)`
- Conditional branches → `IRBranch(IRCmp(op, reg, 0), taken, fallthrough)`
- Integer arithmetic (0x10–0x12) → `IRBinop`

Unrecognised instructions → `IRAssign(dest, IRConst(0))`.

### `X86_64IRLifter`

```python
X86_64IRLifter()
```

Lifts x86-64 basic blocks (from `CFGBuilder` with `X86_64Config`) to `IRBlock`.
Covers MOV, LEA, ADD/SUB/AND/OR/XOR/SHL/SAR/SHR, CALL, RET, JMP, Jcc.
Register canonicalisation: `eax/ax/al/ah → rax`, etc.

### `IRLifter.lift_cfg(cfg) → IRIG`

Common method on both lifters. Lifts every `BasicBlock` in the CFG and wires
successor/predecessor edges from the original CFG.

## `PseudoCEmitter`

```python
PseudoCEmitter(
    irig:    IRIG,
    names:   Optional[Dict[int, str]] = None,   # VA → function name
    structs: Optional[List[StructDef]] = None,  # from StructLayoutAnalyzer
)
```

Emits human-readable pseudo-C in topological block order.

```python
emitter = PseudoCEmitter(irig, names={0x120123456: 'system'}, structs=structs)
print(emitter.emit())
```

Output example:
```
// IRIG arch=alpha_axp
BB_0x120001000:
  r0 = ctx->command;
  system(r0);
  return r0;
```

Without `structs=`:
```
BB_0x120001000:
  r0 = *(r1 + 0x18);
  sub_120123456(r0);
```

## Usage

```python
from ablation.analyzers.insn_alpha import AlphaEcoffScanner
from ablation.analyzers.alpha_cfg import AlphaCFGBuilder
from ablation.analyzers.ir import AlphaIRLifter, PseudoCEmitter
from ablation.analyzers.struct_layout import StructLayoutAnalyzer

scanner = AlphaEcoffScanner('/path/to/binary')
data, gp, sections = scanner._load()
builder = AlphaCFGBuilder(data, sections, gp)

cfg     = builder.build(func_va)
lifter  = AlphaIRLifter(data=data, sections=sections, gp_value=gp)
irig    = lifter.lift_cfg(cfg)
structs = StructLayoutAnalyzer(irig).analyze()

print(PseudoCEmitter(irig, structs=structs).emit())
```

Or via `BinaryLifter`:

```python
from ablation.analyzers.binary_lifter import BinaryLifter
print(BinaryLifter('/path/to/binary', arch='alpha').lift_function_ir(func_va))
```
