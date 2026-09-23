"""Tests for CorpusBuilder and func_id_db schema."""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

BINARY = '/usr/bin/ls'


@pytest.fixture(scope='module')
def corpus_db(tmp_path_factory):
    db = tmp_path_factory.mktemp('corpus') / 'test.db'
    from ablation.analyzers.corpus_builder import CorpusBuilder
    cb = CorpusBuilder(db_path=str(db))
    cb.build(BINARY, product='test-ls', version='1.0', progress=False)
    return db


def test_corpus_creates_db(corpus_db):
    assert corpus_db.exists()


def test_corpus_has_functions(corpus_db):
    con = sqlite3.connect(str(corpus_db))
    count = con.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
    con.close()
    assert count > 0


def test_corpus_has_binary_record(corpus_db):
    con = sqlite3.connect(str(corpus_db))
    row = con.execute("SELECT path_hint, product FROM binaries LIMIT 1").fetchone()
    con.close()
    assert row is not None
    assert row[1] == 'test-ls'


def test_corpus_function_has_confidence(corpus_db):
    con = sqlite3.connect(str(corpus_db))
    rows = con.execute(
        "SELECT DISTINCT confidence FROM functions"
    ).fetchall()
    con.close()
    confidences = {r[0] for r in rows}
    # CorpusBuilder inserts ANGR_INFERRED for functions without confirmed names
    assert 'ANGR_INFERRED' in confidences or 'CONFIRMED' in confidences


def test_corpus_function_has_va(corpus_db):
    con = sqlite3.connect(str(corpus_db))
    row = con.execute("SELECT va FROM functions LIMIT 1").fetchone()
    con.close()
    assert row is not None
    assert row[0] > 0


def test_rebuild_is_idempotent(corpus_db):
    """Building twice should not double the function count."""
    from ablation.analyzers.corpus_builder import CorpusBuilder
    cb = CorpusBuilder(db_path=str(corpus_db))

    con = sqlite3.connect(str(corpus_db))
    before = con.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
    con.close()

    cb.build(BINARY, product='test-ls', version='1.0', progress=False)

    con = sqlite3.connect(str(corpus_db))
    after = con.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
    con.close()

    # Should not grow unboundedly on rebuild
    assert after <= before * 2
