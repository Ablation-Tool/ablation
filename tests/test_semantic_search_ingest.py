"""Tests for SemanticSearcher.ingest_binary and from_context auto-ingest."""

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ablation.analyzers.semantic_search import SemanticSearcher


def _make_schema(con):
    con.executescript("""
        CREATE TABLE IF NOT EXISTS binaries (
            id INTEGER PRIMARY KEY,
            sha256 TEXT NOT NULL UNIQUE,
            path_hint TEXT NOT NULL DEFAULT '',
            product TEXT NOT NULL DEFAULT '',
            arch TEXT NOT NULL DEFAULT 'x86-64',
            version TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            added_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE IF NOT EXISTS functions (
            id INTEGER PRIMARY KEY,
            binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
            va INTEGER NOT NULL,
            name TEXT NOT NULL,
            demangled TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'UNKNOWN',
            confidence TEXT NOT NULL DEFAULT 'CANDIDATE'
                CHECK(confidence IN ('CONFIRMED','ANGR_INFERRED','CANDIDATE')),
            sig_bytes TEXT NOT NULL DEFAULT '',
            sig_mask TEXT NOT NULL DEFAULT '',
            sig_len INTEGER NOT NULL DEFAULT 0,
            call_targets TEXT NOT NULL DEFAULT '[]',
            callers TEXT NOT NULL DEFAULT '[]',
            string_xrefs TEXT NOT NULL DEFAULT '[]',
            struct_accesses TEXT NOT NULL DEFAULT '[]',
            notes TEXT NOT NULL DEFAULT '',
            version_str TEXT NOT NULL DEFAULT '',
            UNIQUE(binary_id, va)
        );
    """)
    con.commit()


def _fake_ctx(sha256='aabbccdd' * 8, names=None, callees=None):
    ctx = MagicMock()
    ctx.sha256 = sha256
    ctx.arch = 'x86-64'
    names = {0x1000: 'func_a', 0x2000: 'func_b', 0x3000: 'func_c'} if names is None else names
    ctx.names_map.return_value = names
    callees = callees or {}
    ctx.callees_of.side_effect = lambda va: callees.get(va, [])
    return ctx


@pytest.fixture
def tmp_db(tmp_path):
    db = tmp_path / 'func_id.db'
    con = sqlite3.connect(str(db))
    _make_schema(con)
    con.close()
    return db


def test_ingest_registers_binary(tmp_db):
    ctx = _fake_ctx()
    with patch('ablation.analyzers.semantic_search._DEFAULT_DB', tmp_db):
        binary_id, live_addrs = SemanticSearcher.ingest_binary(ctx, product='test', version='1.0')

    con = sqlite3.connect(str(tmp_db))
    row = con.execute('SELECT sha256, product, version FROM binaries WHERE id=?', (binary_id,)).fetchone()
    con.close()

    assert row is not None
    assert row[0] == ctx.sha256
    assert row[1] == 'test'
    assert row[2] == '1.0'


def test_ingest_inserts_functions(tmp_db):
    names = {0x1000: 'alpha', 0x2000: 'beta', 0x3000: 'gamma'}
    callees = {0x1000: [(0x2000, 'beta'), (0x3000, 'gamma')]}
    ctx = _fake_ctx(names=names, callees=callees)

    with patch('ablation.analyzers.semantic_search._DEFAULT_DB', tmp_db):
        binary_id, live_addrs = SemanticSearcher.ingest_binary(ctx)

    assert live_addrs == {0x1000, 0x2000, 0x3000}

    con = sqlite3.connect(str(tmp_db))
    rows = con.execute(
        "SELECT va, name, confidence, call_targets FROM functions WHERE binary_id=?",
        (binary_id,)
    ).fetchall()
    con.close()

    assert len(rows) == 3
    by_va = {r[0]: r for r in rows}
    assert by_va[0x1000][1] == 'alpha'
    assert by_va[0x1000][2] == 'CONFIRMED'
    assert json.loads(by_va[0x1000][3]) == [0x2000, 0x3000]
    assert json.loads(by_va[0x2000][3]) == []


def test_ingest_is_idempotent(tmp_db):
    ctx = _fake_ctx()
    with patch('ablation.analyzers.semantic_search._DEFAULT_DB', tmp_db):
        id1, addrs1 = SemanticSearcher.ingest_binary(ctx)
        id2, addrs2 = SemanticSearcher.ingest_binary(ctx)

    assert id1 == id2
    assert addrs1 == addrs2

    con = sqlite3.connect(str(tmp_db))
    n_binaries = con.execute("SELECT COUNT(*) FROM binaries").fetchone()[0]
    n_funcs = con.execute("SELECT COUNT(*) FROM functions WHERE binary_id=?", (id1,)).fetchone()[0]
    con.close()

    assert n_binaries == 1
    assert n_funcs == 3


def test_ingest_empty_names_warns(tmp_db):
    ctx = _fake_ctx(names={})
    with patch('ablation.analyzers.semantic_search._DEFAULT_DB', tmp_db):
        import warnings
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            binary_id, live_addrs = SemanticSearcher.ingest_binary(ctx)

    assert live_addrs == set()
    assert any('no named functions' in str(w.message) for w in caught)


def test_from_context_auto_ingest(tmp_db):
    names = {0x1000: 'do_thing', 0x2000: 'helper'}
    ctx = _fake_ctx(names=names)

    build_corpus_calls = []

    with patch('ablation.analyzers.semantic_search._DEFAULT_DB', tmp_db):
        ss = SemanticSearcher(str(tmp_db))
        with patch.object(SemanticSearcher, 'build_corpus', lambda self, **kw: build_corpus_calls.append(kw) or 2):
            result = SemanticSearcher.from_context(ctx)

    assert result._binary_id is not None
    assert result._live_addrs == {0x1000, 0x2000}
    assert len(build_corpus_calls) == 1

    con = sqlite3.connect(str(tmp_db))
    n = con.execute("SELECT COUNT(*) FROM binaries WHERE sha256=?", (ctx.sha256,)).fetchone()[0]
    con.close()
    assert n == 1


def test_from_context_existing_binary_skips_ingest(tmp_db):
    names = {0x1000: 'do_thing'}
    ctx = _fake_ctx(names=names)

    with patch('ablation.analyzers.semantic_search._DEFAULT_DB', tmp_db):
        SemanticSearcher.ingest_binary(ctx)

    ingest_called = []
    with patch('ablation.analyzers.semantic_search._DEFAULT_DB', tmp_db):
        with patch.object(SemanticSearcher, 'ingest_binary', side_effect=lambda *a, **kw: ingest_called.append(1) or (1, {0x1000})):
            with patch.object(SemanticSearcher, 'build_corpus', lambda self, **kw: 1):
                SemanticSearcher.from_context(ctx)

    assert ingest_called == [], "ingest_binary should not be called for an already-registered binary"


def test_callees_capped_at_32(tmp_db):
    many_callees = [(0x1000 + i, f'f{i}') for i in range(50)]
    names = {0x5000: 'big_caller'}
    ctx = _fake_ctx(names=names, callees={0x5000: many_callees})

    with patch('ablation.analyzers.semantic_search._DEFAULT_DB', tmp_db):
        SemanticSearcher.ingest_binary(ctx)

    con = sqlite3.connect(str(tmp_db))
    call_targets_json = con.execute(
        "SELECT call_targets FROM functions WHERE va=0x5000"
    ).fetchone()[0]
    con.close()

    assert len(json.loads(call_targets_json)) == 32
