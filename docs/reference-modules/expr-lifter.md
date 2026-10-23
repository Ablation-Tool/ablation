# ExprLifter

Arch-neutral expression simplification, value numbering, and rule-based IR lifting.

---

## Why this exists

1. BinaryLifter and ppc476_decompiler produce stringly-typed IR (C expression
   strings). No shared layer applies constant folding, algebraic simplification,
   or common subexpression elimination before output reaches the user. Complex
   lifted output like `uint32_targ0 + 0 + 0` passes through unchanged.
2. SinkArgClassifier tracks argument provenance at the instruction level.
   Alias chains like `t0 = arg0 + 8; t1 = t0 - 8` are not simplified before
   sink classification. ExprLifter collapses `arg0 + 8 - 8` to `arg0` first.
3. No shared infrastructure exists for per-opcode simplifiers and
   hash-congruence value numbering. Each arch decompiler reimplements ad-hoc
   constant folding separately.

---

## Design sources

Three IBM production systems analyzed from extracted binaries. See
`docs/concepts-decompiler.md` ExprLifter section for algorithm details.

| Component | IBM source | Algorithm |
|:---|:---|:---|
| `ExprSimplifier` | XLC/OMR WCodeDriver `TR_Simplifier` 1116 per-opcode functions | Per-opcode dispatch table: `_SIMPLIFIERS[op](node)` |
| `ValueNumberer` | XLC/OMR `TR_ValueNumberInfo` | Hash-congruence: `op, ctype, child_vnums` key + `canShareValueNumber()` gate |
| `LiftRule` / `ConsumableInsnList` | HATS 7.5 `AbstractRenderingRulesEngine` | Greedy consumption: priority-ordered rules + `PatternComponent.newInstance()` factory |
| `ExprNode` hierarchy | VisualAge EPDC model layer | Flat frozen dataclass + type annotations |

---

## ExprNode

```python
from ablation.analyzers.expr_lifter import ExprNode

# Convenience constructors
c  = ExprNode.const(42, 'uint32_t')
a0 = ExprNode.arg(0)
t  = ExprNode.temp('t0')
s  = ExprNode.sym('strcpy')

add  = ExprNode.add(a0, c)
mul  = ExprNode.mul(a0, ExprNode.const(4))
load = ExprNode.load(a0, 'uint8_t')
call = ExprNode.call(s, [a0, ExprNode.arg(1)])

# Print as C expression
print(add.to_c())   # (arg0 + 0x2a)
print(mul.to_c())   # (arg0 * 4)
print(load.to_c())  # *(uint8_t*)arg0
```

`ExprNode` is a frozen dataclass: immutable, hashable, structurally comparable
with `==`. Two nodes with the same opcode, children, and type are equal and
share the same hash.

### Supported opcodes

| Category | Opcodes |
|:---|:---|
| Leaf | `const`, `arg`, `temp`, `sym` |
| Arithmetic | `add`, `sub`, `mul`, `div` |
| Bitwise | `and_`, `or_`, `xor`, `shl`, `shr`, `neg`, `not_` |
| Type | `cast` |
| Memory | `load`, `store` |
| Control | `call` |

### Predicates

| Predicate | Returns True when |
|:---|:---|
| `is_const()` | node is a constant |
| `is_zero()` | constant with value 0 |
| `is_one()` | constant with value 1 |
| `is_leaf()` | node has no children |
| `can_share()` | node is CSE-eligible no load/store/call, recursively |

---

## ExprSimplifier

```python
from ablation.analyzers.expr_lifter import simplify

# Constant folding
n = ExprNode.add(ExprNode.const(3), ExprNode.const(5))
assert simplify(n) == ExprNode.const(8)

# Identity elimination
n = ExprNode.mul(ExprNode.arg(0), ExprNode.const(1))
assert simplify(n) == ExprNode.arg(0)

# Strength reduction: multiply by power of 2 → shift
n = ExprNode.mul(ExprNode.arg(0), ExprNode.const(4))
assert simplify(n) == ExprNode.shl(ExprNode.arg(0), ExprNode.const(2))

# Nested constant folding
n = ExprNode.add(ExprNode.add(ExprNode.arg(0), ExprNode.const(5)), ExprNode.const(3))
assert simplify(n) == ExprNode.add(ExprNode.arg(0), ExprNode.const(8))

# Cast truncation
n = ExprNode.cast(ExprNode.const(0x1FF), 'uint8_t')
assert simplify(n) == ExprNode.const(0xFF, 'uint8_t')
```

`simplify()` applies transformations bottom-up: children are simplified before
the opcode simplifier runs, so transformations compose automatically.

### Simplifications by opcode

| Opcode | Rules applied |
|:---|:---|
| `add` | 0+x→x, x+0→x, const fold, (x+c1)+c2→x+(c1+c2) |
| `sub` | x-0→x, x-x→0, const fold |
| `mul` | 0*x→0, x*1→x, const fold, x*2^N→x<<N |
| `div` | x/1→x, const fold, x/2^N→x>>N unsigned |
| `and_` | 0&x→0, x&x→x, const fold |
| `or_` | 0|x→x, x|x→x, const fold |
| `xor` | 0^x→x, x^x→0, const fold |
| `shl`/`shr` | x<<0→x, 0<<n→0, const fold |
| `neg` | const fold, neg(neg(x))→x |
| `not_` | const fold, not_(not_(x))→x |
| `cast` | same-type→no-op, const truncation, cast-chain collapse |

---

## ValueNumberer

```python
from ablation.analyzers.expr_lifter import ValueNumberer, ExprNode

vn = ValueNumberer()

e1 = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))
e2 = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))  # structurally equal

# Congruent nodes get the same value number
assert vn.number(e1) == vn.number(e2)

# Loads always get fresh numbers (aliasing)
l1 = ExprNode.load(ExprNode.arg(0))
l2 = ExprNode.load(ExprNode.arg(0))
assert vn.number(l1) != vn.number(l2)

# Identify duplicates in a block
nodes = [e1, e2, ExprNode.arg(2)]
pairs = vn.cse_pairs(nodes)
# pairs = {vn_for_e1: e1} — one repeated expression
```

`ValueNumberer` implements XLC/OMR `TR_ValueNumberInfo` hash-congruence:
two nodes are congruent when they have the same opcode, same ctype, same
constant/name, and their children have the same value numbers recursively.
`can_share()` gates CSE eligibility: loads, stores, and calls always get
fresh numbers regardless of structural equality.

### Methods

| Method | Returns | Description |
|:---|:---|:---|
| `number(node)` | `int` | Value number for node; assigns fresh if new |
| `cse_pairs(nodes)` | `Dict[int, ExprNode]` | `{vn: canonical_node}` for expressions with count > 1 |
| `reset()` | `None` | Clear table; call between functions |

---

## LiftRule and ConsumableInsnList

```python
from ablation.analyzers.expr_lifter import LiftRule, ConsumableInsnList, ExprNode

# Define a rule that recognises an 'add' instruction
def recognise_add(insns):
    if insns and insns[0].mnemonic.startswith('add'):
        return ExprNode.add(ExprNode.arg(0), ExprNode.arg(1)), 1
    return None, 0

rule = LiftRule(name='add', recognise=recognise_add)

# Manually use ConsumableInsnList
consumable = ConsumableInsnList(insns)
while not consumable.empty():
    window = consumable.peek(4)
    node, n = rule.recognise(window)
    if node:
        consumable.consume(n)
```

`recognise` receives a window of up to 16 instructions (list). It returns
`(ExprNode, n_consumed)` on match or `(None, 0)` on no-match.

The `ConsumableInsnList.peek(n)` is non-destructive. `consume(n)` advances
the position. `pop()` consumes and returns the head instruction.

---

## ExprLifter

```python
from ablation.analyzers.expr_lifter import ExprLifter, ExprNode

lifter = ExprLifter()

# Simplify a single node
n = ExprNode.add(ExprNode.mul(ExprNode.arg(0), ExprNode.const(4)), ExprNode.const(0))
print(lifter.simplify(n).to_c())   # (arg0 << 2)

# Simplify a list
nodes = [ExprNode.add(ExprNode.const(0), ExprNode.arg(i)) for i in range(3)]
simplified = lifter.simplify_all(nodes)
# [arg0, arg1, arg2]

# CSE: identify repeated subexpressions
expr = ExprNode.add(ExprNode.arg(0), ExprNode.arg(1))
_, pairs = lifter.apply_cse([expr, expr, ExprNode.arg(2)])
# pairs has one entry: the repeated add expression

# Rule-based lifting
lifter_with_rules = ExprLifter(rules=[rule])
result = lifter_with_rules.lift(insns)

# Reset value numbering between functions
lifter.reset()
```

### Constructor

```python
ExprLifter(rules=None, value_numbering=True)
```

| Parameter | Default | Description |
|:---|:---|:---|
| `rules` | `[]` | List of `LiftRule` objects for instruction-to-IR lifting |
| `value_numbering` | `True` | Apply `ValueNumberer` after simplification in `lift()` |

### Methods

| Method | Returns | Description |
|:---|:---|:---|
| `simplify(node)` | `ExprNode` | Bottom-up simplification of one node |
| `simplify_all(nodes)` | `List[ExprNode]` | Simplify a list of nodes |
| `apply_cse(nodes)` | `(List[ExprNode], Dict[int, ExprNode])` | Simplify + identify CSE pairs |
| `lift(insns)` | `List[ExprNode]` | Rule-based lift of instruction list |
| `reset()` | `None` | Reset value numbering state |

---

## Integration with existing decompilers

**From `ppc476_decompiler._Val`:**

```python
from ablation.analyzers.ppc476_decompiler import Ppc476Decompiler
from ablation.analyzers.expr_lifter import ExprNode, ExprLifter

lifter = ExprLifter()

# Convert _Val to ExprNode before sink classification
def val_to_expr(v) -> ExprNode:
    if v.kind == 'const':
        return ExprNode.const(int(v.text, 0))
    if v.kind == 'arg':
        n = int(v.text.replace('arg', ''))
        return ExprNode.arg(n, v.type_, tainted=True)
    return ExprNode.temp(v.text, v.type_)

expr = val_to_expr(some_val)
simplified = lifter.simplify(expr)
print(simplified.to_c())
```

**From `BinaryLifter` NativeVal:**

`BinaryLifter` outputs `NativeVal` objects per-register. Promote a `NativeVal`
to `ExprNode`, simplify, then use `to_c()` as the expression text.

---

## Pipeline position

**Before this module:** `BinaryLifter`, `ppc476_decompiler`, any arch lifter
producing register-tracked expression strings.

**After this module:** `SinkArgClassifier` or `TaintTracker`: pass the
simplified `ExprNode.to_c()` as the expression string. CSE results help
identify which function argument a sink expression aliases.

---

## FORGE audit

2 LOW findings: see FORGE cache. Gate passed.

| Finding | Severity | Mitigation |
|:---|:---|:---|
| `ValueNumberer._table` unbounded growth | LOW | Call `ExprLifter.reset()` between functions. |
| `simplify()` recursion depth | LOW | Not reachable from real instruction sequences; Python default ~1000 level limit. |

---

## See also

- [Decompiler and IR Lifter Concepts](../concepts-decompiler.md): ExprLifter design architecture section
- [BinaryLifter](binary-lifter.md): upstream lifter producing NativeVal register state
- [PPC476 Lifter](ppc476-lifter.md): arch-specific decompiler; ExprLifter targets its `_Val` expressions
- [Structurizer](structurizer.md): downstream CFG structuring pass
