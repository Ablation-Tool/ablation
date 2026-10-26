# ExprLifter

Arch-neutral expression simplification, value numbering, and rule-based IR lifting. Converts machine instructions into typed `ExprNode` trees, collapses compiler-generated synonyms via per-opcode simplification rules, identifies common subexpressions through hash-congruence value numbering, and provides a greedy rule-engine for pattern-based instruction-to-IR lifting.

- [What is expression lifting and value numbering?](#what-is-expression-lifting-and-value-numbering)
  - [The problem: machine instructions are not expressions](#the-problem-machine-instructions-are-not-expressions)
  - [Expression lifting](#expression-lifting)
  - [Algebraic simplification and strength reduction](#algebraic-simplification-and-strength-reduction)
  - [Value numbering](#value-numbering)
  - [Common subexpression elimination](#common-subexpression-elimination)
  - [Why this matters for decompilation and taint analysis](#why-this-matters-for-decompilation-and-taint-analysis)
- [Why this exists](#why-this-exists)
- [Design sources](#design-sources)
- [Module relationships](#module-relationships)
- [API reference](#api-reference)
  - [`ExprNode`](#exprnode)
  - [`ExprSimplifier`](#exprsimplifier)
  - [`ValueNumberer`](#valuenumberer)
  - [`LiftRule` and `ConsumableInsnList`](#liftrule-and-consumableinsnlist)
  - [`ExprLifter`](#exprlifter-class)
- [Usage](#usage)
- [Integration with existing decompilers](#integration-with-existing-decompilers)
- [FORGE audit](#forge-audit)
- [Limitations](#limitations)
- [Pipeline position](#pipeline-position)
- [See also](#see-also)

---

## What is expression lifting and value numbering? <sup>[↑](#exprlifter)</sup>

### The problem: machine instructions are not expressions <sup>[↑](#exprlifter)</sup>

A machine instruction like `add rax, 0x8` is an imperative side-effecting operation: it reads `rax`, adds 8, and writes the result back to `rax`. This encoding is chosen by the ISA for compactness and hardware simplicity, not for analysis friendliness. Two structurally different instruction sequences can compute identical values:

```
; Sequence A                  ; Sequence B (compiler generated synonym)
mov  r1, r0                   lea  r1, [r0 + 8]
add  r1, 8
```

Both sequences place `r0 + 8` in `r1`. A taint tracker operating at the instruction level sees two different patterns. A simplifier operating on expression trees sees one canonical form: `add(arg0, const(8))`.

### Expression lifting <sup>[↑](#exprlifter)</sup>

**Expression lifting** converts an imperative instruction into a typed expression tree — an intermediate representation (IR) node that captures what value the instruction computes, independent of how the ISA encodes the computation. The lifted form records:

- The operation (add, mul, load, cast, call)
- The operand types and widths (uint32_t, uint64_t)
- The taint status of each operand (attacker-controlled or not)
- The tree structure (children are sub-expressions, not registers)

An `ExprNode` in `ExprLifter` is a frozen, hashable dataclass. Two nodes that compute the same value with the same types and the same child structure are `==` and share the same hash. This structural equality is the foundation value numbering builds on.

### Algebraic simplification and strength reduction <sup>[↑](#exprlifter)</sup>

Compilers emit redundant operations. A variable indexed from the base of an array may appear in the binary as `add(mul(i, stride), base)` with a subsequent `sub(..., 0)` when the compiler fails to eliminate the zero subtraction. An optimizing compiler may convert `mul(x, 4)` to `shl(x, 2)` but an unoptimized or cross-compiled binary may leave the multiplication intact.

**Per-opcode simplification** applies canonical transformation rules bottom-up over the expression tree:

- Identity elimination: `x + 0 → x`, `x * 1 → x`, `x - 0 → x`
- Constant folding: `const(3) + const(5) → const(8)`
- Strength reduction: `x * 2^N → x << N`, `x / 2^N → x >> N` (unsigned)
- Nested constant folding: `(x + 5) + 3 → x + 8`
- Double-negation: `neg(neg(x)) → x`, `not_(not_(x)) → x`
- Cast chain collapse: `cast(cast(x, uint32_t), uint32_t) → x`

These transformations are sourced from XLC/OMR's `TR_Simplifier`, which implements 1116 per-opcode simplification functions for IBM's production C/C++ compiler.

### Value numbering <sup>[↑](#exprlifter)</sup>

**Value numbering** assigns a canonical integer identifier (the value number) to every expression in a block so that two expressions producing the same value share the same identifier. It was formalized by Rosen, Wegman, and Zadeck (1988) for global value numbering (GVN) over SSA form. The hash-congruence variant used here (from XLC/OMR `TR_ValueNumberInfo`) works over expression trees without requiring SSA:

> Two nodes are **congruent** if they have the same opcode, the same `ctype`, the same constant value or name (for leaf nodes), and their children have the same value numbers recursively.

This reduces to a hash-table lookup: the key is `(op, ctype, const_val, name, child_vnums...)`. If the key is already in the table, the node gets that existing value number. Otherwise it gets a fresh one.

The `can_share()` gate (mirroring `TR_ValueNumberInfo::canShareValueNumber`) excludes loads, stores, and calls from structural congruence: two `load(addr)` nodes with the same address may read different values due to aliasing, so they always get fresh value numbers.

### Common subexpression elimination <sup>[↑](#exprlifter)</sup>

**CSE** (Common Subexpression Elimination) identifies expressions that are computed more than once in a basic block and can be factored into a single computation. `ValueNumberer.cse_pairs(nodes)` returns a dict mapping value numbers to their canonical expression for all value numbers that appear more than once. The caller replaces each occurrence with a reference to the single canonical computation.

CSE over typed expression trees is more precise than CSE over raw register values because it survives register renames (e.g. the compiler moves a value between `r0` and `r1` between two uses) and still recognizes the two computations as identical.

### Why this matters for decompilation and taint analysis <sup>[↑](#exprlifter)</sup>

Without simplification and value numbering, taint analysis sees a cloud of instruction-level operations where semantically identical expressions appear in multiple forms. `SinkArgClassifier` classifies sink arguments; if the argument reaching a `system()` call is `sub(add(arg0, 8), 8)` in one path and `arg0` in another (both semantically equal), the classifier sees two different forms and may miss one as not tainted. `ExprLifter.simplify()` collapses both to `arg0` first, so `SinkArgClassifier` sees one canonical form.

---

## Why this exists <sup>[↑](#exprlifter)</sup>

1. `BinaryLifter` and `ppc476_decompiler` produce stringly-typed IR (C expression strings). No shared layer applies constant folding, algebraic simplification, or common subexpression elimination before output reaches the user. Complex lifted output like `(uint32_t)arg0 + 0 + 0` passes through unchanged.

2. `SinkArgClassifier` tracks argument provenance at the instruction level. Alias chains like `t0 = arg0 + 8; t1 = t0 - 8` are not simplified before sink classification. `ExprLifter` collapses `(arg0 + 8) - 8` to `arg0` first, eliminating the false non-taint verdict.

3. No shared infrastructure exists for per-opcode simplifiers and hash-congruence value numbering. Each arch decompiler reimplements ad-hoc constant folding separately. `ExprSimplifier` and `ValueNumberer` provide a single implementation used across all arch decompilers.

---

## Design sources <sup>[↑](#exprlifter)</sup>

Three IBM production systems analyzed from extracted binaries. See `docs/concepts-decompiler.md` ExprLifter section for algorithm details.

| Component | IBM source | Algorithm |
|:---|:---|:---|
| `ExprSimplifier` | XLC/OMR WCodeDriver `TR_Simplifier` — 1116 per-opcode functions | Per-opcode dispatch table: `_SIMPLIFIERS[op](node)` |
| `ValueNumberer` | XLC/OMR `TR_ValueNumberInfo` | Hash-congruence: `(op, ctype, child_vnums)` key + `canShareValueNumber()` gate |
| `LiftRule` / `ConsumableInsnList` | HATS 7.5 `AbstractRenderingRulesEngine` | Greedy consumption: priority-ordered rules + `PatternComponent.newInstance()` factory |
| `ExprNode` hierarchy | VisualAge EPDC model layer | Flat frozen dataclass + type annotations |

---

## Module relationships <sup>[↑](#exprlifter)</sup>

```
ExprLifter
  └── ExprSimplifier     (per-opcode dispatch table)
  └── ValueNumberer      (hash-congruence table)
  └── LiftRule list      (caller-supplied rule engine)
  └── ConsumableInsnList (greedy instruction consumer)
```

**Upstream (produces inputs to ExprLifter):**
- [BinaryLifter](binary-lifter.md): produces `NativeVal` register state; promote to `ExprNode` before simplification
- [PPC476 Lifter](ppc476-lifter.md): produces `_Val` expression strings; convert via `val_to_expr()` pattern

**Downstream (consumes ExprLifter output):**
- [SinkArgClassifier](sink-arg-classifier.md): pass `simplified_node.to_c()` as the expression string for classification
- [TaintTracker](taint-tracker-alpha.md): simplified + CSE-reduced `ExprNode` trees expose canonical taint flow
- [Structurizer](structurizer.md): downstream CFG structuring pass

---

## API reference <sup>[↑](#exprlifter)</sup>

### `ExprNode` <sup>[↑](#exprlifter)</sup>

**File:** `ablation/analyzers/expr_lifter.py`

```python
from ablation.analyzers.expr_lifter import ExprNode
```

`ExprNode` is a frozen dataclass: immutable, hashable, and structurally comparable with `==`. Two nodes with the same opcode, children, and type are equal and share the same hash.

**Raw fields** (set via convenience constructors, not directly):

| Field | Type | Description |
|:---|:---|:---|
| `op` | `str` | Opcode string (e.g. `'add'`, `'load'`, `'const'`) |
| `children` | `Tuple[ExprNode, ...]` | Child sub-expressions (empty for leaf nodes) |
| `ctype` | `str` | C width annotation (default `'uint64_t'`) |
| `const_val` | `Optional[int]` | Integer value for `const` nodes; `None` otherwise |
| `name` | `Optional[str]` | Identifier for `arg`, `temp`, `sym` nodes; `None` otherwise |
| `tainted` | `bool` | Attacker-controlled flag; propagated through arithmetic |

**Convenience constructors:**

```python
c  = ExprNode.const(42, 'uint32_t')
a0 = ExprNode.arg(0)                      # arg0, uint64_t, tainted=False
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

**Supported opcodes:**

| Category | Opcodes |
|:---|:---|
| Leaf | `const`, `arg`, `temp`, `sym` |
| Arithmetic | `add`, `sub`, `mul`, `div` |
| Bitwise | `and_`, `or_`, `xor`, `shl`, `shr`, `neg`, `not_` |
| Type | `cast` |
| Memory | `load`, `store` |
| Control | `call` |

**Predicates:**

| Predicate | Returns True when |
|:---|:---|
| `is_const()` | node is a constant |
| `is_zero()` | constant with value 0 |
| `is_one()` | constant with value 1 |
| `is_leaf()` | node has no children |
| `can_share()` | CSE-eligible: no `load`/`store`/`call` anywhere in the subtree |

### `ExprSimplifier` <sup>[↑](#exprlifter)</sup>

```python
from ablation.analyzers.expr_lifter import simplify
```

`simplify(node)` applies transformations bottom-up: children are simplified before the opcode simplifier runs, so transformations compose automatically.

```python
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

**Simplifications by opcode:**

| Opcode | Rules applied |
|:---|:---|
| `add` | `0+x→x`, `x+0→x`, const fold, `(x+c1)+c2→x+(c1+c2)` |
| `sub` | `x-0→x`, `x-x→0`, const fold |
| `mul` | `0*x→0`, `x*1→x`, const fold, `x*2^N→x<<N` |
| `div` | `x/1→x`, const fold, `x/2^N→x>>N` (unsigned) |
| `and_` | `0&x→0`, `x&x→x`, const fold |
| `or_` | `0|x→x`, `x|x→x`, const fold |
| `xor` | `0^x→x`, `x^x→0`, const fold |
| `shl`/`shr` | `x<<0→x`, `0<<n→0`, const fold |
| `neg` | const fold, `neg(neg(x))→x` |
| `not_` | const fold, `not_(not_(x))→x` |
| `cast` | same-type no-op, const truncation, cast-chain collapse |

### `ValueNumberer` <sup>[↑](#exprlifter)</sup>

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

**Methods:**

| Method | Returns | Description |
|:---|:---|:---|
| `number(node)` | `int` | Value number for node; assigns a fresh integer if new |
| `cse_pairs(nodes)` | `Dict[int, ExprNode]` | `{vn: canonical_node}` for value numbers appearing more than once |
| `reset()` | `None` | Clear the table; call between functions |

### `LiftRule` and `ConsumableInsnList` <sup>[↑](#exprlifter)</sup>

```python
from ablation.analyzers.expr_lifter import LiftRule, ConsumableInsnList, ExprNode

# Define a rule that recognises a two-register add instruction
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

`recognise` receives a window of up to 16 instructions. It returns `(ExprNode, n_consumed)` on match or `(None, 0)` on no-match. `ConsumableInsnList.peek(n)` is non-destructive; `consume(n)` advances the position; `pop()` consumes and returns the head instruction.

### `ExprLifter` class <sup>[↑](#exprlifter)</sup>

```python
from ablation.analyzers.expr_lifter import ExprLifter, ExprNode

lifter = ExprLifter()
```

**Constructor:**

```python
ExprLifter(rules=None, value_numbering=True)
```

| Parameter | Default | Description |
|:---|:---|:---|
| `rules` | `[]` | List of `LiftRule` objects for instruction-to-IR lifting |
| `value_numbering` | `True` | Apply `ValueNumberer` after simplification in `lift()` |

**Methods:**

| Method | Returns | Description |
|:---|:---|:---|
| `simplify(node)` | `ExprNode` | Bottom-up simplification of one node |
| `simplify_all(nodes)` | `List[ExprNode]` | Simplify a list of nodes |
| `apply_cse(nodes)` | `(List[ExprNode], Dict[int, ExprNode])` | Simplify then identify CSE pairs |
| `lift(insns)` | `List[ExprNode]` | Rule-based lift of an instruction list |
| `reset()` | `None` | Reset value numbering state between functions |

---

## Usage <sup>[↑](#exprlifter)</sup>

```python
from ablation.analyzers.expr_lifter import ExprLifter, ExprNode

lifter = ExprLifter()

# Simplify a single node
n = ExprNode.add(ExprNode.mul(ExprNode.arg(0), ExprNode.const(4)), ExprNode.const(0))
print(lifter.simplify(n).to_c())   # (arg0 << 2)

# Simplify a list of nodes
nodes = [ExprNode.add(ExprNode.const(0), ExprNode.arg(i)) for i in range(3)]
simplified = lifter.simplify_all(nodes)
# [arg0, arg1, arg2]  (x + 0 → x for each)

# Identify repeated subexpressions
expr = ExprNode.add(ExprNode.arg(0), ExprNode.arg(1))
_, pairs = lifter.apply_cse([expr, expr, ExprNode.arg(2)])
# pairs has one entry: the repeated add expression

# Rule-based lifting from instruction list
lifter_with_rules = ExprLifter(rules=[rule])
result = lifter_with_rules.lift(insns)

# Reset value numbering between functions
lifter.reset()
```

---

## Integration with existing decompilers <sup>[↑](#exprlifter)</sup>

**From `ppc476_decompiler._Val`:**

```python
from ablation.analyzers.ppc476_decompiler import Ppc476Decompiler
from ablation.analyzers.expr_lifter import ExprNode, ExprLifter

lifter = ExprLifter()

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

**From `BinaryLifter` `NativeVal`:**

`BinaryLifter` outputs `NativeVal` objects per-register. Promote a `NativeVal` to `ExprNode`, simplify, then use `to_c()` as the expression text. `tainted=True` should be set on nodes derived from attacker-controlled registers (`x0`–`x7` from network input, etc.).

---

## FORGE audit <sup>[↑](#exprlifter)</sup>

Gate: **PASSED**. 2 LOW findings.

| Finding | Severity | Mitigation |
|:---|:---|:---|
| `ValueNumberer._table` unbounded growth | LOW | Call `ExprLifter.reset()` between functions |
| `simplify()` recursion depth | LOW | Not reachable from real instruction sequences; Python default ~1000 level limit |

---

## Limitations <sup>[↑](#exprlifter)</sup>

1. Value numbering is intraprocedural. `ValueNumberer` assigns numbers within one call to `apply_cse()` or `lift()`. Expressions whose canonical forms are established in one function are not recognized as congruent to identical forms in a different function. Call `reset()` between functions to avoid cross-function table pollution.

2. Load aliasing is conservatively treated as always fresh. Two `load(addr)` nodes with structurally equal `addr` trees get different value numbers because the memory state may have changed between the two loads. This is sound but may miss CSE opportunities in loop bodies where the address is provably stable.

3. Rule-based lifting requires caller-supplied rules. `ExprLifter.lift()` does nothing without a `rules` list. No arch-specific rules are bundled in `ExprLifter` itself; the arch lifters (`BinaryLifter`, `Ppc476Decompiler`) supply them.

4. `simplify()` is not aware of signedness. The strength reduction `x / 2^N → x >> N` applies unsigned right shift. Signed division by a power of two requires arithmetic shift right with a rounding correction; the simplifier does not detect this case and skips the reduction when signedness is ambiguous.

5. The `tainted` flag is not propagated through `cast` and `load`. A `cast(tainted_node, uint32_t)` drops the taint flag on the outer cast node (it inherits from the child only through the child node itself, not through the wrapper). Callers should check `node.tainted or any(c.tainted for c in node.children)` for full subtree taint coverage.

---

## Pipeline position <sup>[↑](#exprlifter)</sup>

Before this module: `BinaryLifter`, `ppc476_decompiler`, or any arch lifter producing register-tracked expression strings. Convert their output to `ExprNode` trees before calling `simplify()`.

After this module: `SinkArgClassifier` or `TaintTracker`. Pass the simplified `ExprNode.to_c()` as the expression string for classification. CSE results identify which function argument a sink expression aliases.

---

## See also <sup>[↑](#exprlifter)</sup>

- [Decompiler and IR Lifter Concepts](../concepts-decompiler.md): ExprLifter design architecture section — algorithm details from HATS, XLC/OMR, and VisualAge EPDC
- [BinaryLifter](binary-lifter.md): upstream arch-neutral lifter producing `NativeVal` register state
- [PPC476 Lifter](ppc476-lifter.md): arch-specific decompiler; `ExprLifter` targets its `_Val` expressions
- [SinkArgClassifier](sink-arg-classifier.md): downstream consumer of simplified `ExprNode.to_c()` strings
- [Structurizer](structurizer.md): downstream CFG structuring pass
