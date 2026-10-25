"""
Tests for ArchiveContext.

Fixture: tests/fixtures/ppc32_relo/test_archive.a
  Contains: rpc0http.o and sessock.o

Known facts:
  - rpc0http.o imports strcpy, rpc_ses_read
  - rpc_http_svc_get calls both strcpy and rpc_ses_read
  - sessock.o does NOT import strcpy
  - co_reference_scan('rpc_ses_read', 'strcpy') must return ('rpc0http.o', 'rpc_http_svc_get')
"""

from __future__ import annotations

import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent / 'fixtures' / 'ppc32_relo'
ARCHIVE  = FIXTURES / 'test_archive.a'


def _skip_if_missing(path: Path):
    return pytest.mark.skipif(not path.exists(), reason=f'fixture missing: {path}')


@pytest.fixture(scope='session')
def arc():
    from ablation.analyzers.archive_context import ArchiveContext
    return ArchiveContext.from_path(str(ARCHIVE))


# ── basic index ───────────────────────────────────────────────────────────────

@_skip_if_missing(ARCHIVE)
def test_archive_has_two_members(arc):
    assert len(arc.members()) == 2


@_skip_if_missing(ARCHIVE)
def test_archive_members_include_rpc_http(arc):
    assert 'rpc0http.o' in arc.members()


@_skip_if_missing(ARCHIVE)
def test_archive_members_include_sessock(arc):
    assert 'sessock.o' in arc.members()


@_skip_if_missing(ARCHIVE)
def test_summary_contains_count(arc):
    s = arc.summary()
    assert '2' in s


# ── member access ────────────────────────────────────────────────────────────

@_skip_if_missing(ARCHIVE)
def test_get_rpc_http_returns_context(arc):
    ctx = arc.get('rpc0http.o')
    assert ctx is not None
    assert 'rpc_http_svc_get' in ctx.function_names()


@_skip_if_missing(ARCHIVE)
def test_get_unknown_returns_none(arc):
    ctx = arc.get('__not_in_archive__.o')
    assert ctx is None


@_skip_if_missing(ARCHIVE)
def test_get_is_cached(arc):
    ctx1 = arc.get('rpc0http.o')
    ctx2 = arc.get('rpc0http.o')
    assert ctx1 is ctx2   # same object — lazy cache


# ── co_reference_scan ─────────────────────────────────────────────────────────

@_skip_if_missing(ARCHIVE)
def test_co_reference_scan_finds_rpc_http_svc_get(arc):
    results = arc.co_reference_scan('rpc_ses_read', 'strcpy')
    assert ('rpc0http.o', 'rpc_http_svc_get') in results, \
        f'Expected rpc0http.o::rpc_http_svc_get in: {results}'


@_skip_if_missing(ARCHIVE)
def test_co_reference_scan_no_match_for_missing_sym(arc):
    results = arc.co_reference_scan('__nonexistent_sym_a__', '__nonexistent_sym_b__')
    assert results == []


@_skip_if_missing(ARCHIVE)
def test_co_reference_scan_sessock_excluded(arc):
    results = arc.co_reference_scan('rpc_ses_read', 'strcpy')
    obj_names = {obj for obj, fn in results}
    assert 'sessock.o' not in obj_names   # sessock doesn't import both


# ── find_callers ─────────────────────────────────────────────────────────────

@_skip_if_missing(ARCHIVE)
def test_find_callers_strcpy_includes_rpc_http(arc):
    results = arc.find_callers('strcpy')
    assert ('rpc0http.o', 'rpc_http_svc_get') in results


@_skip_if_missing(ARCHIVE)
def test_find_callers_nonexistent_returns_empty(arc):
    results = arc.find_callers('__not_a_real_symbol__')
    assert results == []


# ── find_definitions ─────────────────────────────────────────────────────────

@_skip_if_missing(ARCHIVE)
def test_find_definitions_rpc_http_svc_get(arc):
    results = arc.find_definitions('rpc_http_svc_get')
    assert len(results) >= 1
    obj_names = {obj for obj, sym in results}
    assert 'rpc0http.o' in obj_names


# ── imports / exports via archive methods ────────────────────────────────────

@_skip_if_missing(ARCHIVE)
def test_imports_of_includes_strcpy(arc):
    imports = arc.imports_of('rpc0http.o')
    assert 'strcpy' in imports


@_skip_if_missing(ARCHIVE)
def test_exports_of_unknown_returns_empty(arc):
    exports = arc.exports_of('__not_in_archive__.o')
    assert exports == []


# ── robustness: non-archive input ────────────────────────────────────────────

def test_non_archive_returns_empty_members():
    from ablation.analyzers.archive_context import ArchiveContext
    arc = ArchiveContext(b'this is not an ar archive')
    assert arc.members() == []


def test_empty_archive_returns_empty_members():
    from ablation.analyzers.archive_context import ArchiveContext
    arc = ArchiveContext(b'')
    assert arc.members() == []
