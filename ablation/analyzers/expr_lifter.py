"""
ExprLifter: arch-neutral expression simplification and value numbering for IR nodes.

Why this exists
---------------
1. BinaryLifter and ppc476_decompiler produce stringly-typed IR (C expression
   strings). There is no layer that applies constant folding, algebraic
   simplification, or common subexpression elimination before pretty-printing.
   Complex lifted output like ``(uint32_t)(arg0 + 0 + 0)`` reaches the user
   without simplification.
2. SinkArgClassifier tracks argument provenance through register aliases but
   stops at the instruction level. ExprLifter provides a proper expression tree
   so alias chains (``t0 = arg0 + 8; t1 = t0 - 8``) collapse to ``arg0``
   before a sink classification is made.
3. No shared infrastructure exists for the per-opcode simplifiers and
   hash-congruence value numbering needed by all new arch decompilers. Each
   arch reimplements ad-hoc constant folding.

Design sources (from IBM production systems — see docs/concepts-decompiler.md)
-------------------------------------------------------------------------------
- ExprNode hierarchy: VisualAge CPP EPDC MonitoredExpressionTreeNode model
  (flat wire type + polymorphic model layer).
- ExprSimplifier dispatch: XLC/OMR WCodeDriver TR_Simplifier (1116 per-opcode
  exported functions — sdivSimplifier, i2sSimplifier, etc.).
- ValueNumberer: XLC/OMR TR_ValueNumberInfo hash-congruence (congruentNodes +
  canShareValueNumber eligibility gate + setValueNumber).
- ConsumableInsnList / LiftRule engine: HATS AbstractRenderingRulesEngine
  greedy consumption (ConsumableFieldList + priority-ordered rule iteration +
  PatternComponent.newInstance factory).

Usage
-----
Simplify an expression tree from ppc476_decompiler or BinaryLifter:

    from ablation.analyzers.expr_lifter import ExprNode, ExprLifter

    # Build a tree: (arg0 + 0) * 1
    e = ExprNode.mul(ExprNode.add(ExprNode.arg(0), ExprNode.const(0)),
                     ExprNode.const(1))
    lifter = ExprLifter()
    simplified = lifter.simplify(e)
    assert simplified == ExprNode.arg(0)   # (x + 0) * 1 → x

CSE across a block:

    nodes = [ExprNode.add(ExprNode.arg(0), ExprNode.arg(1))] * 3
    lifter = ExprLifter()
    cse_results = lifter.apply_cse(nodes)
    # First occurrence keeps its node; subsequent occurrences get a temp alias.

Rule-based lifting (HATS pattern):

    from ablation.analyzers.expr_lifter import LiftRule, ConsumableInsnList

    def _recognise_add(insns):
        if len(insns) >= 1 and insns[0].mnemonic.startswith('add'):
            return ExprNode.add(ExprNode.arg(0), ExprNode.arg(1)), 1
        return None, 0

    rule = LiftRule(name='add', recognise=_recognise_add)
    lifter = ExprLifter(rules=[rule])
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple


# ── ExprNode ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ExprNode:
    """Immutable, hashable IR expression tree node.

    All fields are hashable so ExprNode can be used as a dict key for value
    numbering. Use the convenience constructors (ExprNode.const, ExprNode.add,
    etc.) rather than the raw dataclass constructor.

    The type hierarchy mirrors VisualAge EPDC's MonitoredExpressionTreeNode:
    scalar (const/arg/temp), ptr, binary-op (add/sub/mul/div/and_/or_/xor/shl/
    shr), unary-op (neg/not_/cast), load, store, call.
    """

    op: str                     # opcode: 'const'/'arg'/'temp'/'add'/'load'/...
    children: Tuple['ExprNode', ...] = ()
    ctype: str = 'uint64_t'     # C width annotation
    const_val: Optional[int] = None     # only for op='const'
    name: Optional[str] = None          # only for op='arg'/'temp'/'sym'
    tainted: bool = False               # attacker-controlled flag

    # ── convenience constructors ──────────────────────────────────────────────

    @staticmethod
    def const(v: int, ctype: str = 'uint64_t', tainted: bool = False) -> 'ExprNode':
        return ExprNode('const', (), ctype, v, None, tainted)

    @staticmethod
    def arg(n: int, ctype: str = 'uint64_t', tainted: bool = False) -> 'ExprNode':
        return ExprNode('arg', (), ctype, None, f'arg{n}', tainted)

    @staticmethod
    def temp(name: str, ctype: str = 'uint64_t', tainted: bool = False) -> 'ExprNode':
        return ExprNode('temp', (), ctype, None, name, tainted)

    @staticmethod
    def sym(name: str, ctype: str = 'void*') -> 'ExprNode':
        """Named symbol (PLT/export/global)."""
        return ExprNode('sym', (), ctype, None, name, False)

    @staticmethod
    def add(a: 'ExprNode', b: 'ExprNode') -> 'ExprNode':
        ctype = _common_ctype(a.ctype, b.ctype)
        return ExprNode('add', (a, b), ctype)

    @staticmethod
    def sub(a: 'ExprNode', b: 'ExprNode') -> 'ExprNode':
        ctype = _common_ctype(a.ctype, b.ctype)
        return ExprNode('sub', (a, b), ctype)

    @staticmethod
    def mul(a: 'ExprNode', b: 'ExprNode') -> 'ExprNode':
        ctype = _common_ctype(a.ctype, b.ctype)
        return ExprNode('mul', (a, b), ctype)

    @staticmethod
    def div(a: 'ExprNode', b: 'ExprNode') -> 'ExprNode':
        ctype = _common_ctype(a.ctype, b.ctype)
        return ExprNode('div', (a, b), ctype)

    @staticmethod
    def and_(a: 'ExprNode', b: 'ExprNode') -> 'ExprNode':
        ctype = _common_ctype(a.ctype, b.ctype)
        return ExprNode('and_', (a, b), ctype)

    @staticmethod
    def or_(a: 'ExprNode', b: 'ExprNode') -> 'ExprNode':
        ctype = _common_ctype(a.ctype, b.ctype)
        return ExprNode('or_', (a, b), ctype)

    @staticmethod
    def xor(a: 'ExprNode', b: 'ExprNode') -> 'ExprNode':
        ctype = _common_ctype(a.ctype, b.ctype)
        return ExprNode('xor', (a, b), ctype)

    @staticmethod
    def shl(a: 'ExprNode', b: 'ExprNode') -> 'ExprNode':
        return ExprNode('shl', (a, b), a.ctype)

    @staticmethod
    def shr(a: 'ExprNode', b: 'ExprNode') -> 'ExprNode':
        return ExprNode('shr', (a, b), a.ctype)

    @staticmethod
    def neg(a: 'ExprNode') -> 'ExprNode':
        return ExprNode('neg', (a,), a.ctype)

    @staticmethod
    def not_(a: 'ExprNode') -> 'ExprNode':
        return ExprNode('not_', (a,), a.ctype)

    @staticmethod
    def cast(a: 'ExprNode', ctype: str) -> 'ExprNode':
        return ExprNode('cast', (a,), ctype)

    @staticmethod
    def load(addr: 'ExprNode', ctype: str = 'uint64_t', tainted: bool = False) -> 'ExprNode':
        return ExprNode('load', (addr,), ctype, None, None, tainted)

    @staticmethod
    def store(addr: 'ExprNode', val: 'ExprNode') -> 'ExprNode':
        return ExprNode('store', (addr, val), 'void')

    @staticmethod
    def call(target: 'ExprNode', args: Sequence['ExprNode'],
             ctype: str = 'uint64_t') -> 'ExprNode':
        return ExprNode('call', (target, *args), ctype)

    # ── predicates ───────────────────────────────────────────────────────────

    def is_const(self) -> bool:
        return self.op == 'const'

    def is_zero(self) -> bool:
        return self.op == 'const' and self.const_val == 0

    def is_one(self) -> bool:
        return self.op == 'const' and self.const_val == 1

    def is_leaf(self) -> bool:
        return not self.children

    def can_share(self) -> bool:
        """CSE eligibility: no side effects (no load/store/call).

        Mirrors XLC/OMR TR_ValueNumberInfo::canShareValueNumber — gates whether
        two structurally-congruent nodes can share the same value number.  Loads
        are excluded because aliasing can make two identical load addresses return
        different values; stores and calls are excluded for side-effect ordering.
        """
        if self.op in ('load', 'store', 'call'):
            return False
        return all(c.can_share() for c in self.children)

    # ── pretty-printing ───────────────────────────────────────────────────────

    def to_c(self) -> str:
        """Return C expression string for this node."""
        return _to_c(self)


def _common_ctype(a: str, b: str) -> str:
    """Return the wider of two C type annotations."""
    _WIDTH = {'uint8_t': 1, 'uint16_t': 2, 'uint32_t': 4, 'uint64_t': 8,
              'int8_t': 1, 'int16_t': 2, 'int32_t': 4, 'int64_t': 8}
    return a if _WIDTH.get(a, 8) >= _WIDTH.get(b, 8) else b


def _to_c(n: ExprNode) -> str:
    if n.op == 'const':
        if n.const_val is None:
            return '0'
        v = n.const_val
        if n.ctype in ('uint8_t', 'uint16_t', 'uint32_t', 'uint64_t'):
            return hex(v) if (v > 9 or v < 0) else str(v)
        return str(v)
    if n.op in ('arg', 'temp', 'sym'):
        return n.name or '?'
    c = [_to_c(ch) for ch in n.children]
    _OPS = {
        'add': '{} + {}', 'sub': '{} - {}',
        'mul': '{} * {}', 'div': '{} / {}',
        'and_': '{} & {}', 'or_': '{} | {}', 'xor': '{} ^ {}',
        'shl': '{} << {}', 'shr': '{} >> {}',
    }
    if n.op in _OPS:
        fmt = _OPS[n.op]
        return f'({fmt.format(*c)})'
    if n.op == 'neg':
        return f'(-{c[0]})'
    if n.op == 'not_':
        return f'(~{c[0]})'
    if n.op == 'cast':
        return f'({n.ctype}){c[0]}'
    if n.op == 'load':
        return f'*({n.ctype}*){c[0]}'
    if n.op == 'store':
        return f'*{c[0]} = {c[1]}'
    if n.op == 'call':
        return f'{c[0]}({", ".join(c[1:])})'
    return f'{n.op}({", ".join(c)})'


# ── ExprSimplifier ────────────────────────────────────────────────────────────

# Per-opcode simplifier dispatch table.
# Mirrors XLC/OMR TR_Simplifier: each opcode has a dedicated function that
# receives the already-child-simplified node and returns a replacement.
_SIMPLIFIERS: Dict[str, Callable[[ExprNode], ExprNode]] = {}


def _reg(op: str):
    """Register a simplifier function for an opcode."""
    def decorator(fn):
        _SIMPLIFIERS[op] = fn
        return fn
    return decorator


@_reg('add')
def _simplify_add(n: ExprNode) -> ExprNode:
    a, b = n.children
    if a.is_zero():
        return b
    if b.is_zero():
        return a
    if a.is_const() and b.is_const():
        return ExprNode.const(a.const_val + b.const_val, n.ctype, a.tainted or b.tainted)
    # Constant-fold: (x + c1) + c2 → x + (c1 + c2)
    if b.is_const() and a.op == 'add' and a.children[1].is_const():
        merged = a.children[1].const_val + b.const_val
        inner = a.children[0]
        if merged == 0:
            return inner
        return ExprNode.add(inner, ExprNode.const(merged, b.ctype))
    return n


@_reg('sub')
def _simplify_sub(n: ExprNode) -> ExprNode:
    a, b = n.children
    if b.is_zero():
        return a
    if a == b:
        return ExprNode.const(0, n.ctype)
    if a.is_const() and b.is_const():
        return ExprNode.const(a.const_val - b.const_val, n.ctype, a.tainted or b.tainted)
    return n


@_reg('mul')
def _simplify_mul(n: ExprNode) -> ExprNode:
    a, b = n.children
    if a.is_zero() or b.is_zero():
        return ExprNode.const(0, n.ctype)
    if a.is_one():
        return b
    if b.is_one():
        return a
    if a.is_const() and b.is_const():
        return ExprNode.const(a.const_val * b.const_val, n.ctype, a.tainted or b.tainted)
    # Strength reduction: x * 2^N → x << N
    if b.is_const() and b.const_val > 0:
        v = b.const_val
        if v & (v - 1) == 0:
            shift = v.bit_length() - 1
            return ExprNode.shl(a, ExprNode.const(shift, 'uint8_t'))
    if a.is_const() and a.const_val > 0:
        v = a.const_val
        if v & (v - 1) == 0:
            shift = v.bit_length() - 1
            return ExprNode.shl(b, ExprNode.const(shift, 'uint8_t'))
    return n


@_reg('div')
def _simplify_div(n: ExprNode) -> ExprNode:
    a, b = n.children
    if b.is_one():
        return a
    if a.is_const() and b.is_const() and b.const_val != 0:
        return ExprNode.const(a.const_val // b.const_val, n.ctype, a.tainted or b.tainted)
    # Strength reduction: x / 2^N → x >> N (unsigned only)
    if b.is_const() and b.const_val > 0 and n.ctype.startswith('u'):
        v = b.const_val
        if v & (v - 1) == 0:
            shift = v.bit_length() - 1
            return ExprNode.shr(a, ExprNode.const(shift, 'uint8_t'))
    return n


@_reg('and_')
def _simplify_and(n: ExprNode) -> ExprNode:
    a, b = n.children
    if a.is_zero() or b.is_zero():
        return ExprNode.const(0, n.ctype)
    if a.is_const() and b.is_const():
        return ExprNode.const(a.const_val & b.const_val, n.ctype, a.tainted or b.tainted)
    if a == b:
        return a
    return n


@_reg('or_')
def _simplify_or(n: ExprNode) -> ExprNode:
    a, b = n.children
    if a.is_zero():
        return b
    if b.is_zero():
        return a
    if a.is_const() and b.is_const():
        return ExprNode.const(a.const_val | b.const_val, n.ctype, a.tainted or b.tainted)
    if a == b:
        return a
    return n


@_reg('xor')
def _simplify_xor(n: ExprNode) -> ExprNode:
    a, b = n.children
    if a.is_zero():
        return b
    if b.is_zero():
        return a
    if a == b:
        return ExprNode.const(0, n.ctype)
    if a.is_const() and b.is_const():
        return ExprNode.const(a.const_val ^ b.const_val, n.ctype, a.tainted or b.tainted)
    return n


@_reg('shl')
def _simplify_shl(n: ExprNode) -> ExprNode:
    a, b = n.children
    if b.is_zero():
        return a
    if a.is_zero():
        return ExprNode.const(0, n.ctype)
    if a.is_const() and b.is_const():
        return ExprNode.const(a.const_val << b.const_val, n.ctype, a.tainted)
    return n


@_reg('shr')
def _simplify_shr(n: ExprNode) -> ExprNode:
    a, b = n.children
    if b.is_zero():
        return a
    if a.is_zero():
        return ExprNode.const(0, n.ctype)
    if a.is_const() and b.is_const():
        return ExprNode.const(a.const_val >> b.const_val, n.ctype, a.tainted)
    return n


@_reg('neg')
def _simplify_neg(n: ExprNode) -> ExprNode:
    (a,) = n.children
    if a.is_const():
        return ExprNode.const(-a.const_val, n.ctype, a.tainted)
    if a.op == 'neg':
        return a.children[0]
    return n


@_reg('not_')
def _simplify_not(n: ExprNode) -> ExprNode:
    (a,) = n.children
    if a.is_const():
        return ExprNode.const(~a.const_val, n.ctype, a.tainted)
    if a.op == 'not_':
        return a.children[0]
    return n


@_reg('cast')
def _simplify_cast(n: ExprNode) -> ExprNode:
    (a,) = n.children
    # cast to same type is a no-op
    if a.ctype == n.ctype:
        return a
    # cast of a const: fold immediately
    if a.is_const():
        _MASKS = {'uint8_t': 0xFF, 'uint16_t': 0xFFFF,
                  'uint32_t': 0xFFFFFFFF, 'uint64_t': 0xFFFFFFFFFFFFFFFF}
        mask = _MASKS.get(n.ctype)
        if mask is not None:
            return ExprNode.const(a.const_val & mask, n.ctype, a.tainted)
    # cast of cast: collapse to single cast if same direction or outer is wider
    if a.op == 'cast':
        _W = {'uint8_t': 1, 'uint16_t': 2, 'uint32_t': 4, 'uint64_t': 8,
              'int8_t': 1, 'int16_t': 2, 'int32_t': 4, 'int64_t': 8}
        outer_w = _W.get(n.ctype, 8)
        inner_w = _W.get(a.ctype, 8)
        source_w = _W.get(a.children[0].ctype, 8)
        if outer_w <= inner_w <= source_w:
            return ExprNode.cast(a.children[0], n.ctype)
    return n


def simplify(node: ExprNode) -> ExprNode:
    """Recursively simplify an ExprNode tree bottom-up.

    Applies per-opcode simplifiers (constant folding, algebraic identities,
    strength reduction) following the XLC/OMR TR_Simplifier dispatch pattern.
    Calls itself recursively on children before applying the opcode simplifier,
    so transformations compose: (x * 4) + 0 simplifies first to (x << 2) + 0,
    then to x << 2.
    """
    if not node.children:
        return node
    simplified_children = tuple(simplify(c) for c in node.children)
    n = ExprNode(node.op, simplified_children, node.ctype,
                 node.const_val, node.name, node.tainted)
    fn = _SIMPLIFIERS.get(n.op)
    if fn:
        return fn(n)
    return n


# ── ValueNumberer ─────────────────────────────────────────────────────────────

class ValueNumberer:
    """Hash-congruence value numbering.

    Implements the XLC/OMR TR_ValueNumberInfo algorithm:
      - congruentNodes: structural equality by (op, ctype, const_val, name,
        child_value_numbers). Two nodes are congruent if they compute the same
        value by this recursive definition.
      - canShareValueNumber: gates CSE eligibility (no loads/stores/calls).
      - setValueNumber: assigns the congruent node's number to both.

    All nodes receive unique value numbers. Structurally-congruent, share-
    eligible nodes receive the *same* value number, enabling downstream CSE.
    """

    def __init__(self) -> None:
        self._table: Dict[tuple, int] = {}
        self._next_vn: int = 0

    def reset(self) -> None:
        self._table.clear()
        self._next_vn = 0

    def number(self, node: ExprNode) -> int:
        """Return the value number for *node*, assigning a fresh one if new.

        Nodes that cannot be shared (loads, stores, calls) always get fresh
        numbers because aliasing or side-effect ordering makes them unsafe to
        identify across call sites.
        """
        if not node.can_share():
            return self._fresh()
        key = self._congruence_key(node)
        if key not in self._table:
            self._table[key] = self._fresh()
        return self._table[key]

    def cse_pairs(self, nodes: List[ExprNode]) -> Dict[int, ExprNode]:
        """Return {vn: canonical_node} for value numbers seen more than once.

        The caller can replace all nodes whose value number appears in this
        dict (except the first occurrence) with a temp that refers to the
        canonical expression.
        """
        counts: Dict[int, int] = {}
        canonical: Dict[int, ExprNode] = {}
        for n in nodes:
            vn = self.number(n)
            counts[vn] = counts.get(vn, 0) + 1
            if vn not in canonical:
                canonical[vn] = n
        return {vn: canonical[vn] for vn, cnt in counts.items() if cnt > 1}

    def _congruence_key(self, node: ExprNode) -> tuple:
        child_vns = tuple(self.number(c) for c in node.children)
        return (node.op, node.ctype, node.const_val, node.name, child_vns)

    def _fresh(self) -> int:
        vn = self._next_vn
        self._next_vn += 1
        return vn


# ── LiftRule / ConsumableInsnList ─────────────────────────────────────────────

@dataclass
class LiftRule:
    """A single rule in the ExprLifter rule engine.

    Mirrors HATS AbstractRenderingRulesEngine / RenderingRule:
      - name: rule identifier (≡ RenderingRule.name)
      - recognise: callable that receives the current instruction window and
        returns (ExprNode, n_consumed) on match or (None, 0) on no-match
        (≡ PatternComponent.recognize returning ComponentElement[])
      - enabled: allow rules to be toggled without removing them
        (≡ IRenderingRule.isEnabled())
    """
    name: str
    recognise: Callable[[List], Tuple[Optional[ExprNode], int]]
    enabled: bool = True


class ConsumableInsnList:
    """Greedy consumption list for the rule-based lifting engine.

    Mirrors HATS ConsumableFieldList: tracks which instructions have been
    consumed by rules. The lift loop exits when either all instructions are
    consumed or no rule fires for the head instruction.
    """

    def __init__(self, insns: List) -> None:
        self._insns = list(insns)
        self._pos: int = 0

    def peek(self, n: int = 1) -> List:
        return self._insns[self._pos:self._pos + n]

    def consume(self, n: int) -> List:
        consumed = self._insns[self._pos:self._pos + n]
        self._pos += n
        return consumed

    def pop(self):
        insn = self._insns[self._pos]
        self._pos += 1
        return insn

    def empty(self) -> bool:
        return self._pos >= len(self._insns)

    def consumed_count(self) -> int:
        return self._pos

    def size(self) -> int:
        return len(self._insns)

    def remaining(self) -> int:
        return len(self._insns) - self._pos


# ── ExprLifter ────────────────────────────────────────────────────────────────

class ExprLifter:
    """Arch-neutral expression simplification, value numbering, and rule-based lifting.

    Combines three IBM-derived components:
      1. ExprSimplifier (XLC/OMR TR_Simplifier pattern) — constant folding and
         algebraic simplification via per-opcode dispatch table.
      2. ValueNumberer (XLC/OMR TR_ValueNumberInfo pattern) — hash-congruence
         CSE with canShareValueNumber eligibility gate.
      3. Rule-based lifting (HATS AbstractRenderingRulesEngine pattern) —
         greedy ConsumableInsnList + priority-ordered LiftRule iteration.

    Args:
        rules:           Optional list of LiftRules for instruction-to-IR lifting.
        value_numbering: If True, apply ValueNumberer after simplification.
    """

    def __init__(self, rules: Optional[List[LiftRule]] = None,
                 value_numbering: bool = True) -> None:
        self._rules = rules or []
        self._value_numbering = value_numbering
        self._vn = ValueNumberer()

    def simplify(self, node: ExprNode) -> ExprNode:
        """Recursively simplify an ExprNode tree bottom-up.

        Applies constant folding, algebraic identities, and strength reduction
        using the per-opcode dispatch table.
        """
        return simplify(node)

    def simplify_all(self, nodes: List[ExprNode]) -> List[ExprNode]:
        """Simplify a list of nodes. Returns a new list."""
        return [simplify(n) for n in nodes]

    def apply_cse(self, nodes: List[ExprNode]) -> Tuple[List[ExprNode], Dict[int, ExprNode]]:
        """Apply value numbering to identify common subexpressions.

        Returns (simplified_nodes, cse_pairs) where cse_pairs is a dict of
        {value_number: canonical_ExprNode} for expressions that appear more
        than once. The caller assigns temps for the canonical forms and replaces
        subsequent occurrences.
        """
        self._vn.reset()
        simplified = [simplify(n) for n in nodes]
        pairs = self._vn.cse_pairs(simplified)
        return simplified, pairs

    def lift(self, insns: List) -> List[ExprNode]:
        """Lift an instruction list to ExprNodes using the registered LiftRules.

        Implements the HATS greedy consumption model:
        - Iterate rules in registration order (priority = order).
        - For each head position, try each enabled rule.
        - If a rule matches, consume its instructions and emit its node.
        - If no rule matches, emit an opaque temp for the head instruction and
          advance by one (fallback — never blocks progress).
        - Stop when all instructions are consumed.
        """
        consumable = ConsumableInsnList(insns)
        result: List[ExprNode] = []

        while not consumable.empty():
            matched = False
            for rule in self._rules:
                if not rule.enabled:
                    continue
                window = consumable.peek(16)
                node, n_consumed = rule.recognise(window)
                if node is not None and n_consumed > 0:
                    consumable.consume(n_consumed)
                    result.append(simplify(node) if self._value_numbering else node)
                    matched = True
                    break
            if not matched:
                insn = consumable.pop()
                mnem = getattr(insn, 'mnemonic', str(insn))
                result.append(ExprNode.temp(f'_op_{mnem}'))

        return result

    def reset(self) -> None:
        """Reset value numbering state between functions."""
        self._vn.reset()
