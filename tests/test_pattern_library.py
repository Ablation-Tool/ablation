"""Tests for PatternLibrary -- pattern registration, sweep, and formatting."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_default_patterns_loaded():
    from ablation.analyzers.pattern_library import PatternLibrary
    pl = PatternLibrary()
    assert len(pl._patterns) > 0


def test_add_pattern():
    from ablation.analyzers.pattern_library import PatternLibrary
    pl = PatternLibrary()
    before = len(pl._patterns)
    pl.add("test pattern for buffer overflow detection", tag="buffer-overflow")
    assert len(pl._patterns) > before


def test_pattern_has_tag():
    from ablation.analyzers.pattern_library import PatternLibrary
    pl = PatternLibrary()
    for p in pl._patterns:
        assert hasattr(p, 'query')
        assert hasattr(p, 'tag')
        assert isinstance(p.query, str)
        assert len(p.query) > 0


def test_sweep_with_mock_searcher():
    """Sweep should return a dict keyed by query string."""
    from ablation.analyzers.pattern_library import PatternLibrary

    class MockSearcher:
        def query(self, description, top_k=5):
            return []  # no results -- just tests control flow

    pl = PatternLibrary()
    results = pl.sweep(MockSearcher(), top_k=3, min_score=0.30)
    assert isinstance(results, dict)
    # Should have one entry per pattern
    assert len(results) == len(pl._patterns)


def test_fmt_sweep_returns_string():
    from ablation.analyzers.pattern_library import PatternLibrary, SweepResult
    pl = PatternLibrary()
    fake_results = {
        "test query": SweepResult(
            pattern="test query",
            tag="buffer-overflow",
            hits=[(0x1000, 0.45), (0x2000, 0.38)],
        )
    }
    s = pl.fmt_sweep(fake_results, binary_name='test.so')
    assert isinstance(s, str)
    assert '0x1000' in s


def test_sweep_filters_by_min_score():
    from ablation.analyzers.pattern_library import PatternLibrary

    class MockSearcher:
        def query(self, description, top_k=5):
            from ablation.analyzers.semantic_search import SimilarFunction
            return [
                SimilarFunction(name='fn_low', role='', confidence='', va=0x1000, score=0.20),
                SimilarFunction(name='fn_high', role='', confidence='', va=0x2000, score=0.50),
            ]

    pl = PatternLibrary()
    results = pl.sweep(MockSearcher(), top_k=5, min_score=0.35)
    for query, sr in results.items():
        for va, score in sr.hits:
            assert score >= 0.35
