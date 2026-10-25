"""Tests for KnowledgeGraph — schema, write API, query API, access_level filtering."""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import datetime

from ablation.analyzers.knowledge_graph import ContextCoverage, KnowledgeGraph, VALID_INTENTS


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


# ── Arch-family fallback ──────────────────────────────────────────────────────

def _add_module_for_arch(g, arch, name='TestModule'):
    g.add_node('Architecture', f'arch://{arch}', {'name': arch})
    g.add_node('Module', f'module://{name}', {'name': name, 'workflow_stage': 'triage'})
    g.add_edge(f'module://{name}', f'arch://{arch}', 'SUPPORTS')


def test_arch_family_fallback_uses_related_arch(g):
    _add_module_for_arch(g, 'powerpc', 'TestModule')
    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
    assert 'TestModule' in ctx


def test_arch_family_fallback_notes_substitution(g):
    _add_module_for_arch(g, 'powerpc', 'TestModule')
    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
    assert 'NOTE' in ctx
    assert 'ppc32' in ctx
    assert 'powerpc' in ctx


def test_arch_family_no_fallback_when_primary_has_modules(g):
    _add_module_for_arch(g, 'ppc32', 'PrimaryModule')
    _add_module_for_arch(g, 'powerpc', 'FamilyModule')
    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
    assert 'PrimaryModule' in ctx
    assert 'FamilyModule' not in ctx
    assert 'NOTE' not in ctx


def test_arch_family_unknown_arch_no_crash(g):
    ctx = g.get_context_for_binary(arch='riscv64', fmt='elf64')
    assert 'No graph context' in ctx


def test_arch_family_fallback_reflected_in_coverage(g):
    _add_module_for_arch(g, 'aarch64', 'ARM64Module')
    _, cov = g.get_context_with_coverage(arch='arm64', fmt='elf64')
    assert cov.arch_family_used is True
    assert cov.arch == 'aarch64'
    assert cov.module_count == 1


# ── ContextCoverage and get_context_with_coverage ────────────────────────────

def test_get_context_with_coverage_returns_tuple(g):
    result = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    assert isinstance(result, tuple)
    assert len(result) == 2
    ctx, cov = result
    assert isinstance(ctx, str)
    assert isinstance(cov, ContextCoverage)


def test_coverage_score_zero_empty_graph(g):
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    assert cov.coverage_score == 0.0
    assert cov.module_count == 0
    assert cov.session_count == 0
    assert cov.chain_count == 0


def test_coverage_score_with_modules(g):
    _add_module_for_arch(g, 'ppc32', 'ModA')
    _add_module_for_arch(g, 'ppc32', 'ModB')
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    # 0.5 * min(2/3, 1.0) = 0.333
    assert cov.coverage_score == pytest.approx(0.333, abs=0.001)
    assert cov.module_count == 2


def test_coverage_score_full(g):
    for name in ['ModA', 'ModB', 'ModC']:
        _add_module_for_arch(g, 'ppc32', name)
    for i in range(2):
        g.add_node('Session', f'session://s{i}', {'arch': 'ppc32', 'date': f'2026-01-0{i+1}', 'verdict': 'COMPLETE'})
    g.add_hyperedge('SessionToolChain', 'chain://c1',
                    member_ids=['session://s0', 'arch://ppc32', 'module://ModA'],
                    roles=['session', 'arch', 'module'],
                    props={'session_id': 'session://s0', 'arch': 'ppc32'})
    g.add_hyperedge('SessionToolChain', 'chain://c2',
                    member_ids=['session://s1', 'arch://ppc32', 'module://ModB'],
                    roles=['session', 'arch', 'module'],
                    props={'session_id': 'session://s1', 'arch': 'ppc32'})
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    assert cov.coverage_score == pytest.approx(1.0, abs=0.001)


def test_coverage_sufficient_default_threshold(g):
    _add_module_for_arch(g, 'ppc32', 'ModA')
    _add_module_for_arch(g, 'ppc32', 'ModB')
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    assert cov.sufficient()  # 0.333 >= 0.3


def test_coverage_not_sufficient_empty(g):
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    assert not cov.sufficient()


def test_coverage_str_contains_score(g):
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    s = str(cov)
    assert 'coverage=' in s
    assert 'modules=' in s
    assert 'sessions=' in s


def test_coverage_str_notes_family_fallback(g):
    _add_module_for_arch(g, 'powerpc', 'TestModule')
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    assert 'arch-family fallback' in str(cov)


def test_coverage_gaps_not_counted_in_score(g):
    g.add_node('KnownGap', 'gap://ppc32-plt', {'description': 'PLT missing', 'arch': 'ppc32'})
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    assert cov.gap_count == 1
    assert cov.coverage_score == 0.0  # gaps do not raise score


# ── Context manager ───────────────────────────────────────────────────────────

def test_context_manager_closes_connection(tmp_path):
    db = str(tmp_path / 'cm_test.db')
    with KnowledgeGraph.open(db) as kg:
        kg.add_node('Module', 'module://X', {'name': 'X'})
        assert kg.node_count() == 1
    # Connection closed — accessing it should raise
    with pytest.raises(Exception):
        kg._con.execute("SELECT 1")


# ── Intent routing ────────────────────────────────────────────────────────────

def test_invalid_intent_raises_value_error(g):
    with pytest.raises(ValueError, match="intent must be one of"):
        g.get_context_for_binary(arch='ppc32', fmt='xcoff32', intent='bad_intent')


def test_valid_intents_set():
    assert VALID_INTENTS == frozenset({'sweep', 'confirm', 'version_diff'})


def test_context_sweep_is_default(g):
    _add_module_for_arch(g, 'ppc32', 'ModA')
    ctx_default, cov_default = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
    ctx_sweep, cov_sweep = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32', intent='sweep')
    assert ctx_default == ctx_sweep
    assert cov_default.intent == 'sweep'


def test_coverage_intent_field(g):
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32', intent='confirm')
    assert cov.intent == 'confirm'


def test_context_non_sweep_adds_intent_header(g):
    _add_module_for_arch(g, 'ppc32', 'ModA')  # must have content for lines to render
    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32', intent='confirm')
    assert '[INTENT: confirm]' in ctx


def test_context_confirm_filters_sessions_without_verdict(g):
    g.add_node('Session', 'session://s1', {'arch': 'ppc32', 'date': '2026-01-01', 'verdict': 'CONFIRMED'})
    g.add_node('Session', 'session://s2', {'arch': 'ppc32', 'date': '2026-01-02', 'verdict': ''})
    _add_module_for_arch(g, 'ppc32', 'ModA')
    ctx, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32', intent='confirm')
    assert 'session://s1' in ctx
    assert 'session://s2' not in ctx
    assert cov.session_count == 1


def test_context_version_diff_excludes_gaps_and_sessions(g):
    _add_module_for_arch(g, 'ppc32', 'ModA')
    g.add_node('KnownGap', 'gap://ppc32-plt', {'description': 'PLT gap', 'arch': 'ppc32'})
    g.add_node('Session', 'session://s1', {'arch': 'ppc32', 'date': '2026-01-01', 'verdict': 'CONFIRMED'})
    ctx, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32', intent='version_diff')
    assert '[KNOWN GAPS' not in ctx
    assert '[PRIOR SESSIONS' not in ctx
    assert cov.gap_count == 0
    assert cov.session_count == 0


def test_coverage_str_includes_intent(g):
    _, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32', intent='version_diff')
    assert 'intent=version_diff' in str(cov)


# ── Timestamp and SUPERSEDES ──────────────────────────────────────────────────

def test_analysis_event_has_timestamp(g):
    g.add_run(
        module_name='TestModule',
        binary_path='/fake/binary',
        arch='ppc32',
        results={'session_id': 'session://t1', 'candidates': 2, 'confirmed': 0,
                 'fp_rate': 0.5, 'root_cause': ''},
    )
    row = g._con.execute("SELECT props FROM nodes WHERE type='AnalysisEvent'").fetchone()
    props = json.loads(row['props'])
    assert 'timestamp' in props
    # Timestamp should be parseable ISO8601
    dt = datetime.datetime.fromisoformat(props['timestamp'])
    assert dt.year >= 2024


def test_analysis_event_stores_intent(g):
    g.add_analysis_event(
        session_id='session://t1', module='TestModule', arch='ppc32',
        candidates=1, confirmed=0, fp_rate=0.5, root_cause='', intent='confirm',
    )
    row = g._con.execute("SELECT props FROM nodes WHERE type='AnalysisEvent'").fetchone()
    props = json.loads(row['props'])
    assert props['intent'] == 'confirm'


def test_add_gap_node_creates_known_gap(g):
    g.add_gap_node(
        gap_id='gap://ppc32/xcoff_no_plt',
        arch='ppc32',
        description='XCOFF binaries have no PLT; SinkArgClassifier misclassifies sinks',
        root_cause='XCOFF_no_plt',
        module_needed='SinkArgClassifierXCOFF',
    )
    assert g.node_count('KnownGap') == 1
    row = g._con.execute("SELECT props FROM nodes WHERE type='KnownGap'").fetchone()
    props = json.loads(row['props'])
    assert props['arch'] == 'ppc32'
    assert props['root_cause'] == 'XCOFF_no_plt'


def test_add_gap_node_adds_supersedes_edges(g):
    # Create two AnalysisEvent nodes first
    g.add_analysis_event(
        session_id='session://x', module='SinkArgClassifier', arch='ppc32',
        candidates=0, confirmed=0, fp_rate=0.9, root_cause='XCOFF_no_plt',
    )
    eid = g._con.execute(
        "SELECT id FROM nodes WHERE type='AnalysisEvent'"
    ).fetchone()['id']

    g.add_gap_node(
        gap_id='gap://ppc32/xcoff_no_plt',
        arch='ppc32',
        description='XCOFF PLT gap',
        root_cause='XCOFF_no_plt',
        supersedes_event_ids=[eid],
    )
    edge = g._con.execute(
        "SELECT * FROM edges WHERE src='gap://ppc32/xcoff_no_plt' AND type='SUPERSEDES'"
    ).fetchone()
    assert edge is not None
    assert edge['dst'] == eid


def test_gap_candidates_excludes_superseded_events(g):
    # Insert 5 high-fp events for SinkArgClassifier/ppc32 with a known root_cause.
    for i in range(5):
        eid = g.add_analysis_event(
            session_id=f'session://s{i}', module='SinkArgClassifier', arch='ppc32',
            candidates=0, confirmed=0, fp_rate=0.9, root_cause='XCOFF_no_plt',
        )
    # Document the gap — its SUPERSEDES edges cover these events.
    all_eids = [
        r['id'] for r in g._con.execute(
            "SELECT id FROM nodes WHERE type='AnalysisEvent'"
        ).fetchall()
    ]
    g.add_gap_node(
        gap_id='gap://ppc32/xcoff_no_plt',
        arch='ppc32',
        description='XCOFF PLT gap',
        root_cause='XCOFF_no_plt',
        supersedes_event_ids=all_eids,
    )
    candidates = g.get_gap_candidates(fp_threshold=0.3, min_events=3)
    # All events superseded; should return no candidates.
    assert candidates == []


def test_gap_candidates_excludes_documented_root_cause(g):
    # Insert 5 high-fp events with a root_cause that matches a KnownGap.
    for i in range(5):
        g.add_analysis_event(
            session_id=f'session://s{i}', module='SinkArgClassifier', arch='ppc32',
            candidates=0, confirmed=0, fp_rate=0.85, root_cause='XCOFF_no_plt',
        )
    # KnownGap without explicit SUPERSEDES edges — root_cause matching filter only.
    g.add_gap_node(
        gap_id='gap://ppc32/xcoff_no_plt',
        arch='ppc32',
        description='XCOFF PLT gap',
        root_cause='XCOFF_no_plt',
    )
    candidates = g.get_gap_candidates(fp_threshold=0.3, min_events=3)
    assert candidates == []
