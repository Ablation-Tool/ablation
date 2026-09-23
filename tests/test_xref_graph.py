"""Tests for XRefGraph -- call graph and string cross-reference scanning."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

BINARY = '/usr/bin/ls'


def test_build_returns_stats():
    from ablation.analyzers.xref_graph import XRefGraph
    xg = XRefGraph.from_path(BINARY)
    xg.build()
    stats = xg.stats()
    assert stats['functions'] > 0
    assert stats['plt_entries'] > 0


def test_func_starts_populated():
    from ablation.analyzers.xref_graph import XRefGraph
    xg = XRefGraph.from_path(BINARY)
    xg.build()
    assert len(xg._func_starts) > 0


def test_plt_maps_to_names():
    from ablation.analyzers.xref_graph import XRefGraph
    xg = XRefGraph.from_path(BINARY)
    xg.build()
    # PLT should have at least some named entries (libc imports)
    named = {va: name for va, name in xg._plt.items() if name}
    assert len(named) > 0


def test_call_edges_exist():
    from ablation.analyzers.xref_graph import XRefGraph
    xg = XRefGraph.from_path(BINARY)
    xg.build()
    assert xg.stats()['call_edges'] > 0


def test_string_xrefs_indexed():
    from ablation.analyzers.xref_graph import XRefGraph
    xg = XRefGraph.from_path(BINARY)
    xg.build()
    assert xg.stats()['funcs_with_string_refs'] > 0
