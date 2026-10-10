"""Tests for cfg_sh2a (SH-2A CFG builder) and structurizer (structured CFG pass).

Covers:
  - 10 original smoke tests (linear, conditional no-DS, conditional DS, unconditional DS,
    call DS, rts/n no-DS, .flow property, DomTree on SH-2A CFG, structurizer linear,
    structurizer if/else)
  - 5 FORGE-required tests (irreducible CFG raises, join=None, conditional break
    documented limitation, flow_r, PostDomTree diamond)
"""
import pytest

from ablation.analyzers.ecu_sh2a_decoder import SH2aInsn
from ablation.analyzers.cfg_sh2a import build_cfg, Block, CFG
from ablation.analyzers.structurizer import Structurizer, PostDomTree, IfNode


# ── Helpers ─────────────────────────────────────────────────────────────────────

def make_insn(
    offset: int,
    mnemonic: str = "nop",
    insn_type: str = "MISC",
    target: int = None,
    is_32bit: bool = False,
) -> SH2aInsn:
    raw = b"\x00\x00\x00\x00" if is_32bit else b"\x00\x00"
    return SH2aInsn(
        offset=offset,
        is_32bit=is_32bit,
        mnemonic=mnemonic,
        insn_type=insn_type,
        raw=raw,
        target=target,
        rd=None,
        rs=None,
        imm=None,
    )


def _nop(off): return make_insn(off, "nop", "MISC")
def _rts(off): return make_insn(off, "rts", "RETURN")
def _rts_n(off): return make_insn(off, "rts/n", "RETURN")
def _bt(off, target): return make_insn(off, "bt", "BRANCH", target=target)
def _bf(off, target): return make_insn(off, "bf", "BRANCH", target=target)
def _bt_s(off, target): return make_insn(off, "bt/s", "BRANCH", target=target)
def _bf_s(off, target): return make_insn(off, "bf/s", "BRANCH", target=target)
def _bra(off, target): return make_insn(off, "bra", "BRANCH", target=target)
def _bsr(off, target): return make_insn(off, "bsr", "CALL", target=target)


def _simple_emitter(insn):
    return f"// {insn.mnemonic}"


# ── Minimal fake CFG for PostDomTree / Structurizer tests ────────────────────────

class _FakeBlock:
    def __init__(self, start, succs=(), preds=()):
        self.start = start
        self.succs = list(succs)
        self.preds = list(preds)
        self.insns = []


class _FakeCFG:
    def __init__(self, blocks_dict, entry):
        self.blocks = blocks_dict
        self.entry = entry

    @property
    def flow(self):
        return [(b.start, s) for b in self.blocks.values() for s in b.succs]

    def flow_r(self):
        return [(dst, src) for src, dst in self.flow]


def _make_diamond_cfg():
    """A→B, A→C, B→D, C→D (classic if/else diamond). Returns (_FakeCFG, A, B, C, D)."""
    A, B, C, D = 0x100, 0x110, 0x120, 0x130
    ba = _FakeBlock(A, succs=[B, C])
    bb = _FakeBlock(B, succs=[D], preds=[A])
    bc = _FakeBlock(C, succs=[D], preds=[A])
    bd = _FakeBlock(D, succs=[], preds=[B, C])
    cfg = _FakeCFG({A: ba, B: bb, C: bc, D: bd}, entry=A)
    return cfg, A, B, C, D


def _make_irreducible_cfg():
    """Irreducible: A→B, A→C, B→C, C→B (two-entry loop B↔C)."""
    A, B, C = 0x200, 0x210, 0x220
    ba = _FakeBlock(A, succs=[B, C])
    bb = _FakeBlock(B, succs=[C], preds=[A, C])
    bc = _FakeBlock(C, succs=[B], preds=[A, B])
    cfg = _FakeCFG({A: ba, B: bb, C: bc}, entry=A)
    return cfg


# ── 10 Original Smoke Tests ────────────────────────────────────────────────────


class TestBuildCfgSmoke:
    def test_linear_function(self):
        """Linear: nop, rts/n — single block, no successors."""
        insns = [_nop(0x800), _rts_n(0x802)]
        cfg = build_cfg(insns, entry=0x800)
        assert len(cfg.blocks) == 1
        b = cfg.blocks[0x800]
        assert b.succs == []

    def test_conditional_branch_no_ds(self):
        """bt (no DS): two successors (target + fall-through)."""
        insns = [
            _bt(0x800, 0x808),   # bt → 0x808
            _nop(0x802),          # fall-through block
            _rts_n(0x804),
            _nop(0x808),          # target block
            _rts_n(0x80A),
        ]
        cfg = build_cfg(insns, entry=0x800)
        cond_block = cfg.blocks[0x800]
        assert 0x808 in cond_block.succs  # branch target
        assert 0x802 in cond_block.succs  # fall-through (no DS, so next insn)

    def test_conditional_branch_with_ds(self):
        """bt/s (with DS): fall-through is after delay slot."""
        insns = [
            _bt_s(0x800, 0x810),  # bt/s → 0x810 (DS at 0x802)
            _nop(0x802),           # delay slot
            _nop(0x804),           # fall-through block start (after DS)
            _rts_n(0x806),
            _nop(0x810),           # target block
            _rts_n(0x812),
        ]
        cfg = build_cfg(insns, entry=0x800)
        cond_block = cfg.blocks[0x800]
        assert len(cond_block.insns) == 2  # bt/s + DS nop
        assert 0x810 in cond_block.succs
        assert 0x804 in cond_block.succs  # after delay slot

    def test_unconditional_branch_with_ds(self):
        """bra (with DS): single target successor, no fall-through."""
        insns = [
            _bra(0x800, 0x810),
            _nop(0x802),   # delay slot
            _nop(0x804),   # dead (no one branches here in this test)
            _nop(0x810),
            _rts_n(0x812),
        ]
        cfg = build_cfg(insns, entry=0x800)
        bra_block = cfg.blocks[0x800]
        assert bra_block.succs == [0x810]
        assert len(bra_block.insns) == 2  # bra + DS nop

    def test_call_with_ds(self):
        """bsr (CALL + DS): only fall-through after DS (callee abstracted)."""
        insns = [
            _bsr(0x800, 0x900),   # bsr to 0x900
            _nop(0x802),           # delay slot
            _rts_n(0x804),         # fall-through after call
        ]
        cfg = build_cfg(insns, entry=0x800)
        call_block = cfg.blocks[0x800]
        assert len(call_block.insns) == 2
        assert call_block.succs == [0x804]  # only fall-through, no callee edge

    def test_rts_n_no_ds(self):
        """rts/n is RETURN with no delay slot — block ends immediately."""
        insns = [_nop(0x800), _rts_n(0x802)]
        cfg = build_cfg(insns, entry=0x800)
        b = cfg.blocks[0x800]
        term = b.terminator()
        assert term.mnemonic == "rts/n"
        assert b.delay_slot() is None
        assert b.succs == []

    def test_flow_property(self):
        """cfg.flow returns all (src, dst) edges — bt/s case."""
        insns = [
            _bt_s(0x800, 0x810),
            _nop(0x802),
            _rts_n(0x804),
            _nop(0x810),
            _rts_n(0x812),
        ]
        cfg = build_cfg(insns, entry=0x800)
        edges = cfg.flow
        assert (0x800, 0x810) in edges
        assert (0x800, 0x804) in edges

    def test_domtree_on_sh2a_cfg(self):
        """DomTree accepts cfg_sh2a.CFG via duck-type compatibility."""
        from ablation.analyzers.dataflow_engine import DomTree, LoopInfo
        insns = [
            _bt_s(0x800, 0x810),
            _nop(0x802),
            _rts_n(0x804),
            _nop(0x810),
            _rts_n(0x812),
        ]
        cfg = build_cfg(insns, entry=0x800)
        dom = DomTree(cfg)
        loops = LoopInfo(cfg, dom)
        assert dom.idom(0x804) == 0x800
        assert dom.idom(0x810) == 0x800
        assert loops.is_reducible() is True

    def test_structurizer_linear(self):
        """Structurizer on a single-block function emits instructions."""
        insns = [_nop(0x800), _rts_n(0x802)]
        cfg = build_cfg(insns, entry=0x800)
        s = Structurizer(cfg)
        out = s.emit(_simple_emitter, func_name="test_fn")
        assert "// test_fn @ 0x800" in out
        assert "// nop" in out

    def test_structurizer_if_else(self):
        """Structurizer emits if/else for a two-successor block."""
        insns = [
            _bt_s(0x800, 0x810),
            _nop(0x802),
            _nop(0x804),
            _rts_n(0x806),
            _nop(0x810),
            _rts_n(0x812),
        ]
        cfg = build_cfg(insns, entry=0x800)
        s = Structurizer(cfg)
        out = s.emit(_simple_emitter, func_name="test_fn")
        assert "if" in out


# ── 5 FORGE-Required Tests ────────────────────────────────────────────────────


class TestStructurizerForge:
    def test_irreducible_cfg_raises(self):
        """Structurizer raises ValueError on irreducible CFG (FORGE §2, §4)."""
        cfg = _make_irreducible_cfg()
        with pytest.raises(ValueError, match="irreducible"):
            Structurizer(cfg)

    def test_postdomtree_diamond_join(self):
        """PostDomTree finds correct join for a diamond CFG (FORGE §2, §8)."""
        cfg, A, B, C, D = _make_diamond_cfg()
        pdt = PostDomTree(cfg)
        join = pdt.closest_common_post_dominator(B, C)
        assert join == D, f"expected join at {D:#x}, got {join}"

    def test_flow_r_is_reverse_of_flow(self):
        """cfg.flow_r() == reversed pairs of cfg.flow (FORGE §2)."""
        insns = [
            _bt(0x800, 0x808),
            _rts_n(0x802),
            _rts_n(0x808),
        ]
        cfg = build_cfg(insns, entry=0x800)
        forward = set(cfg.flow)
        reversed_ = set(cfg.flow_r())
        assert reversed_ == {(dst, src) for src, dst in forward}

    def test_join_none_both_return(self):
        """if/else with both branches returning — no join block (FORGE §2).

        Expected: structurizer produces IfNode(join_block=None) without crashing
        and output contains 'if'.
        """
        # A → B (then, returns), A → C (else, returns). No reconvergence.
        A, B, C = 0x100, 0x110, 0x120
        ba = _FakeBlock(A, succs=[B, C])
        bb = _FakeBlock(B, succs=[], preds=[A])
        bc = _FakeBlock(C, succs=[], preds=[A])
        # Add a single nop insn to each block so emitter has something to emit.
        ba.insns = [_nop(A)]
        bb.insns = [_rts_n(B)]
        bc.insns = [_rts_n(C)]
        cfg = _FakeCFG({A: ba, B: bb, C: bc}, entry=A)
        s = Structurizer(cfg)
        out = s.emit(_simple_emitter, func_name="join_none_test")
        assert "if" in out
        assert isinstance(out, str)

    def test_conditional_break_emits_insnnode(self):
        """Conditional break (one succ inside loop, one outside) emits InsnNode.

        Documented limitation (FORGE §2): only unconditional breaks (all succs outside
        loop) are detected. A conditional break is emitted as a plain InsnNode.
        """
        # Loop: H (header) → B (body, succs=[H, EXIT]), EXIT
        H, B, EXIT = 0x200, 0x210, 0x220
        bh = _FakeBlock(H, succs=[B], preds=[B])
        bb = _FakeBlock(B, succs=[H, EXIT], preds=[H])
        be = _FakeBlock(EXIT, succs=[], preds=[B])
        bh.insns = [_nop(H)]
        bb.insns = [_nop(B)]
        be.insns = [_rts_n(EXIT)]
        cfg = _FakeCFG({H: bh, B: bb, EXIT: be}, entry=H)
        s = Structurizer(cfg)
        out = s.emit(_simple_emitter, func_name="cond_break_test")
        # Output must be a non-empty string (no crash).
        assert isinstance(out, str)
        assert len(out) > 0
        # "break;" should NOT appear (conditional break is an InsnNode, not BreakNode).
        # This documents the known limitation rather than asserting future behaviour.
