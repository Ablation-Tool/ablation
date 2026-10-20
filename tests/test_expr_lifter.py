"""Tests for expr_lifter: ExprNode, ExprSimplifier, ValueNumberer, ExprLifter.

Covers:
  - ExprNode construction, equality, hashability
  - to_c() pretty-printing
  - can_share() CSE eligibility
  - simplify(): constant folding, algebraic identities, strength reduction,
    nested constant fold, cast fold, cast collapse
  - ValueNumberer: basic numbering, congruence assignment, cse_pairs
  - ConsumableInsnList: peek/consume/pop/empty
  - ExprLifter.lift(): greedy consumption, rule matching, fallback
  - ExprLifter.apply_cse(): identify duplicate subexpressions
  - ExprLifter.simplify_all(): batch simplification
"""

import pytest
from ablation.analyzers.expr_lifter import (
    ExprNode, ExprLifter, LiftRule, ConsumableInsnList,
    ValueNumberer, simplify,
)


# ── ExprNode ───────────────────────────────────────────────────────────────────

class TestExprNodeConstruction:
    def test_const(self):
        n = ExprNode.const(42)
        assert n.op == 'const'
        assert n.const_val == 42
        assert n.ctype == 'uint64_t'
        assert not n.tainted

    def test_arg(self):
        n = ExprNode.arg(0)
        assert n.op == 'arg'
        assert n.name == 'arg0'

    def test_temp(self):
        n = ExprNode.temp('t0')
        assert n.op == 'temp'
        assert n.name == 't0'

    def test_sym(self):
        n = ExprNode.sym('recv')
        assert n.op == 'sym'
        assert n.name == 'recv'

    def test_add_inherits_wider_type(self):
        a = ExprNode.const(1, 'uint32_t')
        b = ExprNode.const(2, 'uint64_t')
        n = ExprNode.add(a, b)
        assert n.ctype == 'uint64_t'

    def test_frozen_hashable(self):
        a = ExprNode.const(5)
        b = ExprNode.const(5)
        assert a == b
        assert hash(a) == hash(b)
        s = {a, b}
        assert len(s) == 1

    def test_children_tuple(self):
        n = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))
        assert isinstance(n.children, tuple)


class TestExprNodePredicates:
    def test_is_const(self):
        assert ExprNode.const(0).is_const()
        assert not ExprNode.arg(0).is_const()

    def test_is_zero(self):
        assert ExprNode.const(0).is_zero()
        assert not ExprNode.const(1).is_zero()
        assert not ExprNode.arg(0).is_zero()

    def test_is_one(self):
        assert ExprNode.const(1).is_one()
        assert not ExprNode.const(0).is_one()

    def test_is_leaf(self):
        assert ExprNode.const(1).is_leaf()
        assert ExprNode.arg(0).is_leaf()
        assert not ExprNode.add(ExprNode.const(1), ExprNode.const(2)).is_leaf()

    def test_can_share_pure(self):
        n = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))
        assert n.can_share()

    def test_can_share_load_false(self):
        addr = ExprNode.arg(0)
        n = ExprNode.load(addr)
        assert not n.can_share()

    def test_can_share_store_false(self):
        n = ExprNode.store(ExprNode.arg(0), ExprNode.const(1))
        assert not n.can_share()

    def test_can_share_call_false(self):
        n = ExprNode.call(ExprNode.sym('recv'), [ExprNode.arg(0)])
        assert not n.can_share()

    def test_can_share_nested_load_false(self):
        # add(load(x), y) — contains a load so not shareable
        addr = ExprNode.arg(0)
        n = ExprNode.add(ExprNode.load(addr), ExprNode.const(1))
        assert not n.can_share()


class TestExprNodeToC:
    def test_const_small(self):
        assert ExprNode.const(5).to_c() == '5'

    def test_const_large(self):
        assert ExprNode.const(0x100).to_c() == '0x100'

    def test_arg(self):
        assert ExprNode.arg(2).to_c() == 'arg2'

    def test_temp(self):
        assert ExprNode.temp('t1').to_c() == 't1'

    def test_add(self):
        n = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))
        assert n.to_c() == '(arg0 + 1)'

    def test_neg(self):
        n = ExprNode.neg(ExprNode.arg(0))
        assert n.to_c() == '(-arg0)'

    def test_cast(self):
        n = ExprNode.cast(ExprNode.arg(0), 'uint32_t')
        assert n.to_c() == '(uint32_t)arg0'

    def test_load(self):
        n = ExprNode.load(ExprNode.arg(0), 'uint8_t')
        assert n.to_c() == '*(uint8_t*)arg0'

    def test_call(self):
        n = ExprNode.call(ExprNode.sym('strcpy'), [ExprNode.arg(0), ExprNode.arg(1)])
        assert n.to_c() == 'strcpy(arg0, arg1)'


# ── ExprSimplifier ─────────────────────────────────────────────────────────────

class TestSimplifyAdd:
    def test_zero_left(self):
        n = ExprNode.add(ExprNode.const(0), ExprNode.arg(0))
        assert simplify(n) == ExprNode.arg(0)

    def test_zero_right(self):
        n = ExprNode.add(ExprNode.arg(0), ExprNode.const(0))
        assert simplify(n) == ExprNode.arg(0)

    def test_const_fold(self):
        n = ExprNode.add(ExprNode.const(3), ExprNode.const(5))
        assert simplify(n) == ExprNode.const(8, 'uint64_t')

    def test_nested_const_fold(self):
        # (arg0 + 5) + 3 → arg0 + 8
        inner = ExprNode.add(ExprNode.arg(0), ExprNode.const(5))
        outer = ExprNode.add(inner, ExprNode.const(3))
        s = simplify(outer)
        assert s == ExprNode.add(ExprNode.arg(0), ExprNode.const(8))

    def test_nested_sum_zero(self):
        # (arg0 + 5) + (-5) → arg0
        inner = ExprNode.add(ExprNode.arg(0), ExprNode.const(5))
        outer = ExprNode.add(inner, ExprNode.const(-5))
        s = simplify(outer)
        assert s == ExprNode.arg(0)


class TestSimplifySub:
    def test_zero_right(self):
        n = ExprNode.sub(ExprNode.arg(0), ExprNode.const(0))
        assert simplify(n) == ExprNode.arg(0)

    def test_self_sub(self):
        arg = ExprNode.arg(0)
        n = ExprNode.sub(arg, arg)
        assert simplify(n) == ExprNode.const(0)

    def test_const_fold(self):
        n = ExprNode.sub(ExprNode.const(10), ExprNode.const(3))
        assert simplify(n).const_val == 7


class TestSimplifyMul:
    def test_zero(self):
        n = ExprNode.mul(ExprNode.arg(0), ExprNode.const(0))
        assert simplify(n).is_zero()

    def test_one_right(self):
        n = ExprNode.mul(ExprNode.arg(0), ExprNode.const(1))
        assert simplify(n) == ExprNode.arg(0)

    def test_one_left(self):
        n = ExprNode.mul(ExprNode.const(1), ExprNode.arg(0))
        assert simplify(n) == ExprNode.arg(0)

    def test_strength_reduction_4(self):
        n = ExprNode.mul(ExprNode.arg(0), ExprNode.const(4))
        s = simplify(n)
        assert s.op == 'shl'
        assert s.children[1].const_val == 2

    def test_strength_reduction_8(self):
        n = ExprNode.mul(ExprNode.const(8), ExprNode.arg(0))
        s = simplify(n)
        assert s.op == 'shl'
        assert s.children[1].const_val == 3

    def test_const_fold(self):
        n = ExprNode.mul(ExprNode.const(6), ExprNode.const(7))
        assert simplify(n).const_val == 42


class TestSimplifyDiv:
    def test_one(self):
        n = ExprNode.div(ExprNode.arg(0), ExprNode.const(1))
        assert simplify(n) == ExprNode.arg(0)

    def test_strength_reduction_unsigned(self):
        a = ExprNode.arg(0, ctype='uint32_t')
        n = ExprNode.div(a, ExprNode.const(8))
        s = simplify(n)
        assert s.op == 'shr'
        assert s.children[1].const_val == 3

    def test_const_fold(self):
        n = ExprNode.div(ExprNode.const(24), ExprNode.const(4))
        assert simplify(n).const_val == 6


class TestSimplifyBitwise:
    def test_and_zero(self):
        n = ExprNode.and_(ExprNode.arg(0), ExprNode.const(0))
        assert simplify(n).is_zero()

    def test_and_self(self):
        arg = ExprNode.arg(0)
        n = ExprNode.and_(arg, arg)
        assert simplify(n) == arg

    def test_or_zero_left(self):
        n = ExprNode.or_(ExprNode.const(0), ExprNode.arg(0))
        assert simplify(n) == ExprNode.arg(0)

    def test_xor_self(self):
        arg = ExprNode.arg(0)
        n = ExprNode.xor(arg, arg)
        assert simplify(n).is_zero()

    def test_shl_zero_shift(self):
        n = ExprNode.shl(ExprNode.arg(0), ExprNode.const(0))
        assert simplify(n) == ExprNode.arg(0)

    def test_shr_zero_shift(self):
        n = ExprNode.shr(ExprNode.arg(0), ExprNode.const(0))
        assert simplify(n) == ExprNode.arg(0)


class TestSimplifyUnary:
    def test_neg_const(self):
        n = ExprNode.neg(ExprNode.const(5))
        assert simplify(n).const_val == -5

    def test_double_neg(self):
        inner = ExprNode.neg(ExprNode.arg(0))
        outer = ExprNode.neg(inner)
        assert simplify(outer) == ExprNode.arg(0)

    def test_not_const(self):
        n = ExprNode.not_(ExprNode.const(0xFF))
        assert simplify(n).const_val == ~0xFF

    def test_double_not(self):
        inner = ExprNode.not_(ExprNode.arg(0))
        outer = ExprNode.not_(inner)
        assert simplify(outer) == ExprNode.arg(0)


class TestSimplifyCast:
    def test_cast_same_type(self):
        n = ExprNode.cast(ExprNode.arg(0, 'uint32_t'), 'uint32_t')
        assert simplify(n) == ExprNode.arg(0, 'uint32_t')

    def test_cast_const_truncate(self):
        n = ExprNode.cast(ExprNode.const(0x1FF), 'uint8_t')
        assert simplify(n).const_val == 0xFF

    def test_cast_chain_collapse(self):
        # cast(cast(x:u64, u32), u8) → cast(x:u64, u8)
        x = ExprNode.arg(0, 'uint64_t')
        inner = ExprNode.cast(x, 'uint32_t')
        outer = ExprNode.cast(inner, 'uint8_t')
        s = simplify(outer)
        assert s.op == 'cast'
        assert s.ctype == 'uint8_t'
        assert s.children[0] == x


class TestSimplifyCompose:
    def test_mul_then_add_zero(self):
        # (arg0 * 4) + 0 → arg0 << 2
        n = ExprNode.add(
            ExprNode.mul(ExprNode.arg(0), ExprNode.const(4)),
            ExprNode.const(0))
        s = simplify(n)
        assert s.op == 'shl'
        assert s.children[1].const_val == 2

    def test_nested_const_chain(self):
        # (1 + 2) * 4 → 12
        n = ExprNode.mul(
            ExprNode.add(ExprNode.const(1), ExprNode.const(2)),
            ExprNode.const(4))
        s = simplify(n)
        assert s.is_const()
        assert s.const_val == 12


# ── ValueNumberer ──────────────────────────────────────────────────────────────

class TestValueNumberer:
    def test_fresh_per_node(self):
        vn = ValueNumberer()
        a = ExprNode.arg(0)
        b = ExprNode.arg(1)
        vn_a = vn.number(a)
        vn_b = vn.number(b)
        assert vn_a != vn_b

    def test_congruent_same_number(self):
        vn = ValueNumberer()
        a1 = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))
        a2 = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))
        assert a1 == a2  # frozen dataclass equality
        assert vn.number(a1) == vn.number(a2)

    def test_non_congruent_different_number(self):
        vn = ValueNumberer()
        a1 = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))
        a2 = ExprNode.add(ExprNode.arg(0), ExprNode.const(2))
        assert vn.number(a1) != vn.number(a2)

    def test_load_always_fresh(self):
        vn = ValueNumberer()
        addr = ExprNode.arg(0)
        l1 = ExprNode.load(addr)
        l2 = ExprNode.load(addr)
        assert vn.number(l1) != vn.number(l2)

    def test_cse_pairs_identifies_duplicates(self):
        vn = ValueNumberer()
        expr = ExprNode.add(ExprNode.arg(0), ExprNode.arg(1))
        nodes = [expr, expr, ExprNode.arg(2)]
        pairs = vn.cse_pairs(nodes)
        assert len(pairs) == 1
        vn_key = list(pairs.keys())[0]
        assert pairs[vn_key] == expr

    def test_cse_pairs_no_duplicates(self):
        vn = ValueNumberer()
        nodes = [ExprNode.arg(i) for i in range(4)]
        pairs = vn.cse_pairs(nodes)
        assert len(pairs) == 0

    def test_reset_clears_table(self):
        vn = ValueNumberer()
        expr = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))
        vn1 = vn.number(expr)
        vn.reset()
        vn2 = vn.number(expr)
        # After reset, the new number may differ but should still be consistent
        assert vn.number(expr) == vn2


# ── ConsumableInsnList ─────────────────────────────────────────────────────────

class _FakeInsn:
    def __init__(self, mnemonic: str):
        self.mnemonic = mnemonic


class TestConsumableInsnList:
    def _make(self, mnemonics):
        return ConsumableInsnList([_FakeInsn(m) for m in mnemonics])

    def test_peek(self):
        c = self._make(['add', 'sub', 'mul'])
        w = c.peek(2)
        assert [i.mnemonic for i in w] == ['add', 'sub']
        assert c.consumed_count() == 0

    def test_consume(self):
        c = self._make(['add', 'sub', 'mul'])
        c.consume(2)
        assert c.consumed_count() == 2
        assert not c.empty()

    def test_pop(self):
        c = self._make(['add', 'sub'])
        i = c.pop()
        assert i.mnemonic == 'add'
        assert c.consumed_count() == 1

    def test_empty(self):
        c = self._make(['add'])
        assert not c.empty()
        c.consume(1)
        assert c.empty()

    def test_size_remaining(self):
        c = self._make(['a', 'b', 'c'])
        assert c.size() == 3
        assert c.remaining() == 3
        c.consume(1)
        assert c.remaining() == 2

    def test_peek_beyond_end(self):
        c = self._make(['a', 'b'])
        w = c.peek(10)
        assert len(w) == 2


# ── ExprLifter ────────────────────────────────────────────────────────────────

class TestExprLifterSimplify:
    def test_simplify_single(self):
        lifter = ExprLifter()
        n = ExprNode.add(ExprNode.const(0), ExprNode.arg(0))
        assert lifter.simplify(n) == ExprNode.arg(0)

    def test_simplify_all(self):
        lifter = ExprLifter()
        nodes = [
            ExprNode.add(ExprNode.const(0), ExprNode.arg(0)),
            ExprNode.mul(ExprNode.arg(1), ExprNode.const(1)),
        ]
        result = lifter.simplify_all(nodes)
        assert result[0] == ExprNode.arg(0)
        assert result[1] == ExprNode.arg(1)


class TestExprLifterCSE:
    def test_apply_cse_finds_duplicates(self):
        lifter = ExprLifter()
        expr = ExprNode.add(ExprNode.arg(0), ExprNode.arg(1))
        nodes = [expr, expr, ExprNode.arg(2)]
        simplified, pairs = lifter.apply_cse(nodes)
        assert len(pairs) == 1

    def test_apply_cse_no_duplicates(self):
        lifter = ExprLifter()
        nodes = [ExprNode.arg(i) for i in range(4)]
        _, pairs = lifter.apply_cse(nodes)
        assert len(pairs) == 0


class TestExprLifterLift:
    def _make_insn(self, mnemonic):
        return _FakeInsn(mnemonic)

    def test_lift_with_matching_rule(self):
        def recognise_add(insns):
            if insns and insns[0].mnemonic == 'add':
                return ExprNode.add(ExprNode.arg(0), ExprNode.arg(1)), 1
            return None, 0

        rule = LiftRule(name='add', recognise=recognise_add)
        lifter = ExprLifter(rules=[rule])
        insns = [self._make_insn('add'), self._make_insn('add')]
        result = lifter.lift(insns)
        assert len(result) == 2
        assert all(n.op == 'add' for n in result)

    def test_lift_fallback_for_unmatched(self):
        lifter = ExprLifter(rules=[])
        insns = [self._make_insn('nop')]
        result = lifter.lift(insns)
        assert len(result) == 1
        assert result[0].op == 'temp'

    def test_lift_disabled_rule_not_applied(self):
        def recognise_add(insns):
            if insns and insns[0].mnemonic == 'add':
                return ExprNode.const(99), 1
            return None, 0

        rule = LiftRule(name='add', recognise=recognise_add, enabled=False)
        lifter = ExprLifter(rules=[rule])
        insns = [self._make_insn('add')]
        result = lifter.lift(insns)
        # disabled rule — fallback temp emitted
        assert result[0].op == 'temp'

    def test_lift_rule_priority(self):
        # Two rules match 'add'; first one wins.
        def rule1(insns):
            if insns and insns[0].mnemonic == 'add':
                return ExprNode.const(1), 1
            return None, 0

        def rule2(insns):
            if insns and insns[0].mnemonic == 'add':
                return ExprNode.const(2), 1
            return None, 0

        lifter = ExprLifter(rules=[LiftRule('r1', rule1), LiftRule('r2', rule2)])
        insns = [self._make_insn('add')]
        result = lifter.lift(insns)
        assert result[0].const_val == 1  # first rule wins

    def test_lift_consumes_multiple_insns(self):
        def recognise_pair(insns):
            if len(insns) >= 2 and insns[0].mnemonic == 'mov' and insns[1].mnemonic == 'add':
                return ExprNode.add(ExprNode.arg(0), ExprNode.arg(1)), 2
            return None, 0

        rule = LiftRule(name='mov_add', recognise=recognise_pair)
        lifter = ExprLifter(rules=[rule])
        insns = [self._make_insn('mov'), self._make_insn('add')]
        result = lifter.lift(insns)
        assert len(result) == 1  # two insns consumed into one node
        assert result[0].op == 'add'

    def test_lift_empty(self):
        lifter = ExprLifter()
        assert lifter.lift([]) == []

    def test_reset(self):
        lifter = ExprLifter()
        expr = ExprNode.add(ExprNode.arg(0), ExprNode.const(1))
        lifter.apply_cse([expr, expr])
        lifter.reset()
        # After reset, numbering starts fresh — no assertion needed, just no crash
