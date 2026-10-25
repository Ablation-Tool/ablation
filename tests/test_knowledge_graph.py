"""Tests for KnowledgeGraph — schema, write API, query API, access_level filtering."""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ablation.analyzers.knowledge_graph import KnowledgeGraph


@pytest.fixture
def g(tmp_path):
    """Open a fresh in-memory graph for each test."""
    db = str(tmp_path / 'test_kg.db')
    kg = KnowledgeGraph.open(db)
    yield kg
    kg.close()


# ── Schema ────────────────────────────────────────────────────────────────────

def test_schema_creates_tables(g):
    tables = {
        r[0] for r in g._con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert 'nodes' in tables
    assert 'edges' in tables
    assert 'hyperedges' in tables
    assert 'hyperedge_members' in tables


def test_empty_graph_returns_zero_counts(g):
    assert g.node_count() == 0
    assert g.edge_count() == 0


# ── add_node ──────────────────────────────────────────────────────────────────

def test_add_node_stores_and_retrieves(g):
    g.add_node('Module', 'module://BinaryContext', {
        'name': 'BinaryContext', 'workflow_stage': 'triage',
    })
    assert g.node_count('Module') == 1


def test_add_node_idempotent(g):
    g.add_node('Module', 'module://BinaryContext', {'name': 'BinaryContext'})
    g.add_node('Module', 'module://BinaryContext', {'name': 'BinaryContext-v2'})
    assert g.node_count('Module') == 1

    row = g._con.execute(
        "SELECT props FROM nodes WHERE id='module://BinaryContext'"
    ).fetchone()
    props = json.loads(row['props'])
    assert props['name'] == 'BinaryContext-v2'


def test_add_multiple_node_types(g):
    g.add_node('Module', 'module://X', {'name': 'X'})
    g.add_node('Architecture', 'arch://ppc32', {'name': 'ppc32'})
    g.add_node('KnownGap', 'gap://PPC32_PLT', {'description': 'PLT missing', 'arch': 'ppc32'})
    assert g.node_count() == 3
    assert g.node_count('Module') == 1
    assert g.node_count('Architecture') == 1


# ── add_edge ──────────────────────────────────────────────────────────────────

def test_add_edge_idempotent(g):
    g.add_node('Module', 'module://A', {})
    g.add_node('Architecture', 'arch://ppc32', {})
    g.add_edge('module://A', 'arch://ppc32', 'SUPPORTS')
    g.add_edge('module://A', 'arch://ppc32', 'SUPPORTS')
    assert g.edge_count('SUPPORTS') == 1


def test_add_edge_with_props(g):
    g.add_node('Module', 'module://A', {})
    g.add_node('Module', 'module://B', {})
    g.add_edge('module://A', 'module://B', 'REQUIRES', {'order': 1})
    row = g._con.execute(
        "SELECT props FROM edges WHERE src='module://A' AND dst='module://B'"
    ).fetchone()
    assert json.loads(row['props'])['order'] == 1


# ── add_analysis_event / add_run ──────────────────────────────────────────────

def test_add_analysis_event_returns_event_id(g):
    eid = g.add_analysis_event(
        session_id='session://test',
        module='SinkArgClassifier',
        arch='ppc32',
        candidates=5,
        confirmed=0,
        fp_rate=1.0,
        root_cause='FCode_not_C_stack',
    )
    assert eid.startswith('event://')
    assert g.node_count('AnalysisEvent') == 1


def test_add_run_wraps_add_analysis_event(g):
    eid = g.add_run(
        'SemanticSearcher', '/fw/test.bin', 'arm64',
        {'candidates': 3, 'confirmed': 1, 'fp_rate': 0.0, 'root_cause': ''},
    )
    assert eid.startswith('event://')
    row = g._con.execute(
        "SELECT props FROM nodes WHERE type='AnalysisEvent'"
    ).fetchone()
    p = json.loads(row['props'])
    assert p['module'] == 'SemanticSearcher'
    assert p['arch'] == 'arm64'
    assert p['fp_rate'] == 0.0


def test_add_run_coerces_types(g):
    g.add_run('Mod', '/bin', 'x86_64', {
        'candidates': '7', 'confirmed': '2', 'fp_rate': '0.5',
    })
    row = g._con.execute(
        "SELECT props FROM nodes WHERE type='AnalysisEvent'"
    ).fetchone()
    p = json.loads(row['props'])
    assert isinstance(p['candidates'], int)
    assert isinstance(p['fp_rate'], float)


# ── record_finding ────────────────────────────────────────────────────────────

def test_record_finding_creates_node_and_edge(g):
    g.add_node('Session', 'session://test', {})
    g.record_finding(
        finding_id='finding://TEST-001',
        cwe='CWE-121',
        va=0x1234,
        status='CONFIRMED',
        byte_verified=True,
        disclosure_status='public',
        session_id='session://test',
    )
    assert g.node_count('Finding') == 1
    assert g.edge_count('FOUND_IN') == 1


def test_record_finding_pre_disclosure_default_access(g):
    g.add_node('Session', 'session://s1', {})
    g.record_finding(
        finding_id='finding://PRE-001',
        cwe='CWE-122',
        va=0xABCD,
        status='PLAUSIBLE',
        byte_verified=False,
        disclosure_status='pre-disclosure',
        session_id='session://s1',
    )
    row = g._con.execute(
        "SELECT props FROM nodes WHERE id='finding://PRE-001'"
    ).fetchone()
    p = json.loads(row['props'])
    assert p['disclosure_status'] == 'pre-disclosure'
    assert p['access_level'] == 'public'  # default; caller-overridable


# ── get_context_for_binary ────────────────────────────────────────────────────

def test_get_context_empty_graph_returns_fallback(g):
    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
    assert 'No graph context' in ctx


def test_get_context_returns_matching_modules(g):
    g.add_node('Architecture', 'arch://ppc32', {'name': 'ppc32'})
    g.add_node('Module', 'module://SinkArgClassifier', {
        'name': 'SinkArgClassifier',
        'workflow_stage': 'classify',
        'entry_point': 'SinkArgClassifier.from_context(ctx).classify_all()',
        'limitations': '',
    })
    g.add_edge('module://SinkArgClassifier', 'arch://ppc32', 'SUPPORTS')

    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
    assert 'SinkArgClassifier' in ctx
    assert 'classify' in ctx


def test_get_context_includes_known_gaps(g):
    g.add_node('KnownGap', 'gap://PPC32_PLT', {
        'description': 'PPC32 PLT unresolvable',
        'arch': 'ppc32',
        'workaround': 'BinaryContext exports',
        'module_needed': 'PPC32ExternalCallResolver',
    })
    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
    assert 'PPC32 PLT' in ctx
    assert 'BinaryContext exports' in ctx


def test_get_context_includes_prior_sessions(g):
    g.add_node('Session', 'session://ibm-iplrom', {
        'arch': 'ppc32', 'date': '2026-10-15',
        'verdict': 'COMPLETE', 'tool_sequence': [],
    })
    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
    assert 'COMPLETE' in ctx


def test_get_context_vuln_class_filter(g):
    g.add_node('Architecture', 'arch://arm64', {'name': 'arm64'})
    g.add_node('VulnClass', 'vuln://stack_overflow', {'name': 'stack_overflow'})
    g.add_node('Module', 'module://TaintTracker', {
        'name': 'TaintTracker', 'workflow_stage': 'taint',
    })
    g.add_edge('module://TaintTracker', 'vuln://stack_overflow', 'DETECTS')
    g.add_edge('module://TaintTracker', 'arch://arm64', 'SUPPORTS')

    ctx = g.get_context_for_binary(arch='arm64', fmt='elf64', vuln_class='stack_overflow')
    assert 'TaintTracker' in ctx


# ── get_recommendations_for_task ──────────────────────────────────────────────

def test_recommendations_sorted_by_workflow_stage(g):
    g.add_node('Architecture', 'arch://ppc32', {'name': 'ppc32'})
    for name, stage in [
        ('TaintTracker', 'taint'), ('BinaryContext', 'triage'), ('FuncProfiler', 'profile'),
    ]:
        g.add_node('Module', f"module://{name}", {'name': name, 'workflow_stage': stage})
        g.add_edge(f"module://{name}", 'arch://ppc32', 'SUPPORTS')

    rec = g.get_recommendations_for_task('find stack overflows', arch='ppc32')
    idx_triage = rec.index('BinaryContext')
    idx_profile = rec.index('FuncProfiler')
    idx_taint = rec.index('TaintTracker')
    assert idx_triage < idx_profile < idx_taint


# ── get_gap_candidates ────────────────────────────────────────────────────────

def test_get_gap_candidates_empty(g):
    assert g.get_gap_candidates() == []


def test_get_gap_candidates_below_threshold(g):
    for _ in range(3):
        g.add_run('Mod', '/bin', 'ppc32',
                  {'fp_rate': 0.9, 'candidates': 1, 'confirmed': 0})
    # min_events=5, only 3 events → no candidates
    assert g.get_gap_candidates(min_events=5) == []


def test_get_gap_candidates_above_threshold(g):
    for _ in range(6):
        g.add_run('BadModule', '/fw.bin', 'mips32',
                  {'fp_rate': 0.8, 'candidates': 4, 'confirmed': 0,
                   'root_cause': 'no_plt'})
    candidates = g.get_gap_candidates(fp_threshold=0.3, min_events=5)
    assert len(candidates) == 1
    c = candidates[0]
    assert c['module'] == 'BadModule'
    assert c['arch'] == 'mips32'
    assert c['avg_fp_rate'] == pytest.approx(0.8)
    assert 'no_plt' in c['root_causes']


def test_get_gap_candidates_sorted_by_fp_rate(g):
    for _ in range(6):
        g.add_run('ModA', '/a', 'ppc32', {'fp_rate': 0.9})
    for _ in range(6):
        g.add_run('ModB', '/b', 'ppc32', {'fp_rate': 0.4})
    candidates = g.get_gap_candidates(fp_threshold=0.3, min_events=5)
    assert candidates[0]['module'] == 'ModA'
    assert candidates[1]['module'] == 'ModB'


# ── Hyperedge API ─────────────────────────────────────────────────────────────

def test_add_hyperedge_creates_edge_and_members(g):
    g.add_hyperedge(
        'SessionToolChain', 'chain://test',
        member_ids=['session://s1', 'arch://ppc32', 'module://SinkArgClassifier'],
        roles=['session', 'arch', 'module'],
        props={'session_id': 'session://s1', 'arch': 'ppc32'},
    )
    assert g.hyperedge_count('SessionToolChain') == 1
    members = g.get_hyperedge_members('chain://test')
    assert len(members) == 3
    roles = {m['role'] for m in members}
    assert roles == {'session', 'arch', 'module'}


def test_add_hyperedge_default_role(g):
    g.add_hyperedge('TestEdge', 'chain://x', member_ids=['node://a', 'node://b'])
    members = g.get_hyperedge_members('chain://x')
    assert all(m['role'] == 'member' for m in members)


def test_add_hyperedge_role_length_mismatch_raises(g):
    with pytest.raises(ValueError):
        g.add_hyperedge('T', 'chain://bad',
                        member_ids=['a', 'b'], roles=['r1'])


def test_add_hyperedge_idempotent(g):
    g.add_hyperedge('T', 'chain://dup', member_ids=['node://x'], roles=['m'])
    g.add_hyperedge('T', 'chain://dup', member_ids=['node://x'], roles=['m'])
    assert g.hyperedge_count() == 1


def test_get_hyperedges_for_node_finds_by_member(g):
    g.add_hyperedge('SessionToolChain', 'chain://c1',
                    member_ids=['arch://ppc32', 'module://SinkArgClassifier'],
                    roles=['arch', 'module'])
    g.add_hyperedge('SessionToolChain', 'chain://c2',
                    member_ids=['arch://arm64'],
                    roles=['arch'])
    results = g.get_hyperedges_for_node('arch://ppc32')
    assert len(results) == 1
    assert results[0]['id'] == 'chain://c1'


def test_get_hyperedges_for_node_edge_type_filter(g):
    g.add_hyperedge('TypeA', 'chain://a', member_ids=['node://x'], roles=['m'])
    g.add_hyperedge('TypeB', 'chain://b', member_ids=['node://x'], roles=['m'])
    assert len(g.get_hyperedges_for_node('node://x', edge_type='TypeA')) == 1
    assert len(g.get_hyperedges_for_node('node://x', edge_type='TypeB')) == 1
    assert len(g.get_hyperedges_for_node('node://x')) == 2


def test_get_context_includes_tool_chains(g):
    g.add_hyperedge(
        'SessionToolChain', 'chain://ibm-iplrom',
        member_ids=['session://ibm-iplrom', 'arch://ppc32',
                    'module://SinkArgClassifier', 'finding://IBM-001'],
        roles=['session', 'arch', 'module', 'finding'],
        props={'session_id': 'session://ibm-iplrom', 'arch': 'ppc32',
               'tool_count': 1, 'confirmed_count': 1},
    )
    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
    assert 'TOOL CHAINS' in ctx
    assert 'SinkArgClassifier' in ctx
    assert 'confirmed=1' in ctx


# ── Context manager ───────────────────────────────────────────────────────────

def test_context_manager_closes_connection(tmp_path):
    db = str(tmp_path / 'cm_test.db')
    with KnowledgeGraph.open(db) as kg:
        kg.add_node('Module', 'module://X', {'name': 'X'})
        assert kg.node_count() == 1
    # Connection closed — accessing it should raise
    with pytest.raises(Exception):
        kg._con.execute("SELECT 1")
