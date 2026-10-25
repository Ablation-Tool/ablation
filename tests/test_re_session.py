"""Tests for RESession automatic write-back."""
import datetime
import json
from unittest.mock import MagicMock, patch

import pytest

from ablation.analyzers.knowledge_graph import KnowledgeGraph
from ablation.analyzers.re_session import RESession, _extract_sink_arg, _extract_list


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def graph(tmp_path):
    g = KnowledgeGraph.open(str(tmp_path / 'test.db'))
    yield g
    g.close()


@pytest.fixture
def ctx():
    c = MagicMock()
    c.path = '/fake/binary'
    c.binary_path = '/fake/binary'
    return c


def _make_session(ctx, graph):
    return RESession(ctx, arch='ppc32', session_id='session://test', graph=graph)


# ── Extractor unit tests ──────────────────────────────────────────────────────

class _FakeResult:
    def __init__(self, verdict):
        self.verdict = verdict


def test_extract_sink_arg_empty():
    candidates, confirmed, fp_rate = _extract_sink_arg([])
    assert candidates == 0
    assert confirmed == 0
    assert fp_rate == 0.0


def test_extract_sink_arg_all_fp():
    results = [_FakeResult('RODATA_CONST')] * 4
    candidates, confirmed, fp_rate = _extract_sink_arg(results)
    assert candidates == 0
    assert fp_rate == 1.0


def test_extract_sink_arg_mixed():
    results = [
        _FakeResult('RODATA_CONST'),
        _FakeResult('ARG_PROPAGATED'),
        _FakeResult('UNKNOWN'),
        _FakeResult('UNICODE_WRAPPER'),
    ]
    candidates, _, fp_rate = _extract_sink_arg(results)
    assert candidates == 2   # ARG_PROPAGATED + UNKNOWN
    assert fp_rate == 0.5    # 2 FP out of 4 total


def test_extract_list_counts_length():
    assert _extract_list([1, 2, 3]) == (3, 0, 0.0)


def test_extract_list_non_iterable():
    assert _extract_list(42) == (1, 0, 0.0)


# ── RESession.run() ───────────────────────────────────────────────────────────

class _FakeTool:
    """Mock tool with from_context and a run() method."""
    @classmethod
    def from_context(cls, ctx):
        instance = cls()
        return instance

    def run(self):
        return ['finding_a', 'finding_b']


def test_run_returns_result_unchanged(ctx, graph):
    with _make_session(ctx, graph) as s:
        result = s.run(_FakeTool)
    assert result == ['finding_a', 'finding_b']


def test_run_records_analysis_event(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)
        assert graph.node_count('AnalysisEvent') == 1


def test_run_records_correct_candidates(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)
        row = graph._con.execute(
            "SELECT props FROM nodes WHERE type='AnalysisEvent'"
        ).fetchone()
        props = json.loads(row['props'])
        assert props['candidates'] == 2
        assert props['arch'] == 'ppc32'
        assert props['module'] == '_FakeTool'


def test_run_multiple_tools_records_multiple_events(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)
        s.run(_FakeTool)
        assert graph.node_count('AnalysisEvent') == 2


def test_run_passes_method_kwargs(ctx, graph):
    class _KwargedTool:
        @classmethod
        def from_context(cls, ctx):
            return cls()

        def query(self, description, top_k=5):
            return list(range(top_k))

    with _make_session(ctx, graph) as s:
        result = s.run(_KwargedTool, method='query', description='overflow', top_k=3)
    assert result == [0, 1, 2]


def test_run_records_root_cause(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool, root_cause='XCOFF_no_plt')
        row = graph._con.execute(
            "SELECT props FROM nodes WHERE type='AnalysisEvent'"
        ).fetchone()
        props = json.loads(row['props'])
        assert props['root_cause'] == 'XCOFF_no_plt'


# ── SinkArgClassifier routing ─────────────────────────────────────────────────

def test_run_routes_sink_arg_classifier(ctx, graph):
    class SinkArgClassifier:
        @classmethod
        def from_context(cls, ctx):
            return cls()

        def classify_all(self):
            return [
                _FakeResult('RODATA_CONST'),
                _FakeResult('ARG_PROPAGATED'),
                _FakeResult('UNKNOWN'),
            ]

    with _make_session(ctx, graph) as s:
        s.run(SinkArgClassifier)
        row = graph._con.execute(
            "SELECT props FROM nodes WHERE type='AnalysisEvent'"
        ).fetchone()
        props = json.loads(row['props'])
        assert props['candidates'] == 2
        assert round(props['fp_rate'], 3) == round(1/3, 3)


# ── last_event_id / event_ids ─────────────────────────────────────────────────

def test_last_event_id_none_before_run(ctx, graph):
    s = _make_session(ctx, graph)
    assert s.last_event_id() is None
    s.close()


def test_last_event_id_after_run(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)
        eid = s.last_event_id()
    assert eid is not None
    assert eid.startswith('event://')


def test_event_ids_accumulate(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)
        s.run(_FakeTool)
        ids = s.event_ids()
    assert len(ids) == 2
    assert ids[0] != ids[1]


# ── update_confirmed ──────────────────────────────────────────────────────────

def test_update_confirmed_refines_fp_rate(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)   # candidates=2, fp_rate=0.0
        eid = s.last_event_id()
        s.update_confirmed(eid, confirmed=1)
        row = graph._con.execute(
            "SELECT props FROM nodes WHERE id=?", (eid,)
        ).fetchone()
        props = json.loads(row['props'])
        assert props['confirmed'] == 1
        # fp_rate = (2 - 1) / 2 = 0.5
        assert props['fp_rate'] == 0.5


def test_update_confirmed_unknown_event_logs_warning(ctx, graph, caplog):
    import logging
    with caplog.at_level(logging.WARNING, logger='ablation.analyzers.re_session'):
        with _make_session(ctx, graph) as s:
            s.update_confirmed('event://nonexistent', confirmed=1)
    assert 'not in this session' in caplog.text


# ── close_session ────────────────────────────────────────────────────────────

def test_close_session_returns_none_with_no_runs(ctx, graph):
    with _make_session(ctx, graph) as s:
        result = s.close_session()
    assert result is None


def test_close_session_creates_hyperedge(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)
        chain_id = s.close_session()
        assert chain_id is not None
        assert chain_id.startswith('chain://')
        assert graph.hyperedge_count('SessionToolChain') == 1


def test_close_session_members_include_arch_and_module(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)
        chain_id = s.close_session()
        members = graph.get_hyperedge_members(chain_id)
    roles = {m['role'] for m in members}
    assert 'arch' in roles
    assert 'module' in roles
    assert 'session' in roles


def test_close_session_includes_findings(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)
        chain_id = s.close_session(finding_ids=['finding://test-001'])
        members = graph.get_hyperedge_members(chain_id)
    finding_members = [m for m in members if m['role'] == 'finding']
    assert len(finding_members) == 1
    assert finding_members[0]['node_id'] == 'finding://test-001'


def test_close_session_deduplicates_modules(ctx, graph):
    with _make_session(ctx, graph) as s:
        s.run(_FakeTool)
        s.run(_FakeTool)  # same class name — should appear only once as module member
        chain_id = s.close_session()
        members = graph.get_hyperedge_members(chain_id)
    module_members = [m for m in members if m['role'] == 'module']
    assert len(module_members) == 1


# ── Context manager ───────────────────────────────────────────────────────────

def test_context_manager_closes_graph(ctx, tmp_path):
    g = KnowledgeGraph.open(str(tmp_path / 'test.db'))
    with RESession(ctx, arch='arm64', session_id='session://x', graph=g):
        pass
    # After __exit__, connection should be closed; further execute raises.
    with pytest.raises(Exception):
        g._con.execute("SELECT 1")


# ── Intent parameter ──────────────────────────────────────────────────────────

def test_invalid_intent_raises(ctx, graph):
    with pytest.raises(ValueError, match="intent must be one of"):
        RESession(ctx, arch='ppc32', session_id='session://x', graph=graph, intent='bad')


def test_session_intent_stored_in_event(ctx, graph):
    with RESession(ctx, arch='ppc32', session_id='session://x', graph=graph, intent='confirm') as s:
        s.run(_FakeTool)
        row = graph._con.execute(
            "SELECT props FROM nodes WHERE type='AnalysisEvent'"
        ).fetchone()
        props = json.loads(row['props'])
        assert props['intent'] == 'confirm'


def test_session_event_has_timestamp(ctx, graph):
    with RESession(ctx, arch='ppc32', session_id='session://x', graph=graph) as s:
        s.run(_FakeTool)
        row = graph._con.execute(
            "SELECT props FROM nodes WHERE type='AnalysisEvent'"
        ).fetchone()
        props = json.loads(row['props'])
        assert 'timestamp' in props
        dt = datetime.datetime.fromisoformat(props['timestamp'])
        assert dt.year >= 2024
