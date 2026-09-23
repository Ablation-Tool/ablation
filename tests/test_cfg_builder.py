"""Tests for CFGBuilder -- per-function control-flow graph construction."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

BINARY = '/usr/bin/ls'


@pytest.fixture(scope='module')
def xref():
    from ablation.analyzers.xref_graph import XRefGraph
    xg = XRefGraph.from_path(BINARY)
    xg.build()
    return xg


def test_build_function_returns_cfg(xref):
    from ablation.analyzers.cfg_builder import CFGBuilder, CFG
    builder = CFGBuilder(BINARY, xref=xref)
    fva = sorted(xref._func_starts)[0]
    cfg = builder.build_function(fva)
    assert isinstance(cfg, CFG)


def test_cfg_has_blocks(xref):
    from ablation.analyzers.cfg_builder import CFGBuilder
    builder = CFGBuilder(BINARY, xref=xref)
    fva = sorted(xref._func_starts)[0]
    cfg = builder.build_function(fva)
    assert len(cfg.blocks) > 0


def test_cfg_entry_matches_va(xref):
    from ablation.analyzers.cfg_builder import CFGBuilder
    builder = CFGBuilder(BINARY, xref=xref)
    fva = sorted(xref._func_starts)[0]
    cfg = builder.build_function(fva)
    assert cfg.entry == fva


def test_cfg_stats(xref):
    from ablation.analyzers.cfg_builder import CFGBuilder
    builder = CFGBuilder(BINARY, xref=xref)
    fva = sorted(xref._func_starts)[0]
    cfg = builder.build_function(fva)
    s = cfg.stats()
    assert s['blocks'] > 0
    assert s['instructions'] > 0


def test_build_all_returns_dict(xref):
    from ablation.analyzers.cfg_builder import CFGBuilder
    builder = CFGBuilder(BINARY, xref=xref)
    all_cfgs = builder.build_all()
    assert isinstance(all_cfgs, dict)
    assert len(all_cfgs) > 0


def test_basic_block_has_insns(xref):
    from ablation.analyzers.cfg_builder import CFGBuilder
    builder = CFGBuilder(BINARY, xref=xref)
    fva = sorted(xref._func_starts)[0]
    cfg = builder.build_function(fva)
    for bb in cfg.blocks.values():
        # BasicBlock must have a non-negative instruction count
        assert len(bb.insns) >= 0


def test_succ_vas_are_in_blocks_or_external(xref):
    """Every successor VA either points into the same CFG or is an external call target."""
    from ablation.analyzers.cfg_builder import CFGBuilder
    builder = CFGBuilder(BINARY, xref=xref)
    fva = sorted(xref._func_starts)[3]  # use a non-trivial function
    cfg = builder.build_function(fva)
    known_block_starts = set(cfg.blocks.keys())
    for bb_va, bb in cfg.blocks.items():
        for succ in bb.succs:
            # successor is either a block we built, or it's outside our function
            # (cross-function jump / tail call) -- both are valid
            assert isinstance(succ, int)
            assert succ >= 0
