"""
Tests for ReloObjectContext.

Fixtures: tests/fixtures/ppc32_relo/rpc0http.o (known-positive PPC32 BE .o)
          tests/fixtures/ppc32_relo/sessock.o   (known-good, multi-function)

Known-positive expectations (confirmed against raw binary by byte-verification
during SDB-VXW-HTTP-001 analysis):
  rpc0http.o::rpc_http_svc_get imports: strcpy, rpc_ses_read, getword
  sessock.o functions include: sessock_accept, sessock_read (or similar)
"""

from __future__ import annotations

import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent / 'fixtures' / 'ppc32_relo'
RPC_HTTP = FIXTURES / 'rpc0http.o'
SESSOCK  = FIXTURES / 'sessock.o'


def _skip_if_missing(path: Path):
    return pytest.mark.skipif(not path.exists(), reason=f'fixture missing: {path}')


# ── import guard ───────────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def roc():
    from ablation.analyzers.relo_object_context import ReloObjectContext
    return ReloObjectContext


# ── basic parsing ──────────────────────────────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_rpc_http_parses(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    assert 'rpc_http_svc_get' in ctx.function_names()


@_skip_if_missing(RPC_HTTP)
def test_rpc_http_summary_contains_ppc32(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    s = ctx.summary()
    assert 'PPC32' in s
    assert 'BE' in s


@_skip_if_missing(RPC_HTTP)
def test_rpc_http_has_functions(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    funcs = ctx.functions()
    assert len(funcs) >= 2   # at least rpc_http_svc_get + getword


@_skip_if_missing(RPC_HTTP)
def test_rpc_http_function_offsets_nonnegative(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    for fn in ctx.functions():
        assert fn.offset >= 0
        assert fn.size > 0


# ── known-positive: call graph ─────────────────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_rpc_http_svc_get_imports_strcpy(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    calls = ctx.calls_in('rpc_http_svc_get')
    sym_names = {c.sym_name for c in calls}
    assert 'strcpy' in sym_names, f'strcpy not in calls: {sorted(sym_names)}'


@_skip_if_missing(RPC_HTTP)
def test_rpc_http_svc_get_imports_rpc_ses_read(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    calls = ctx.calls_in('rpc_http_svc_get')
    sym_names = {c.sym_name for c in calls}
    assert 'rpc_ses_read' in sym_names, f'rpc_ses_read not in calls: {sorted(sym_names)}'


@_skip_if_missing(RPC_HTTP)
def test_rpc_http_svc_get_calls_getword(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    calls = ctx.calls_in('rpc_http_svc_get')
    sym_names = {c.sym_name for c in calls}
    assert 'getword' in sym_names, f'getword not in calls: {sorted(sym_names)}'


@_skip_if_missing(RPC_HTTP)
def test_functions_calling_strcpy_includes_rpc_http(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    callers = ctx.functions_calling('strcpy')
    assert 'rpc_http_svc_get' in callers


# ── imports / exports ──────────────────────────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_rpc_http_imports_includes_strcpy(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    assert 'strcpy' in ctx.imports()


@_skip_if_missing(RPC_HTTP)
def test_has_import_strcpy(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    assert ctx.has_import('strcpy')
    assert not ctx.has_import('__nonexistent_sym__')


# ── getword: local function (STB_LOCAL STT_FUNC) ──────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_getword_appears_as_function(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    fn_names = ctx.function_names()
    assert 'getword' in fn_names, f'getword not in functions: {fn_names}'


@_skip_if_missing(RPC_HTTP)
def test_getword_binding_is_local(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    funcs = {f.name: f for f in ctx.functions()}
    assert funcs['getword'].binding == 'local'


# ── text_bytes ────────────────────────────────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_text_bytes_nonempty(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    raw, off = ctx.text_bytes('rpc_http_svc_get')
    assert len(raw) > 100   # rpc_http_svc_get is 1244 bytes
    assert off >= 0


@_skip_if_missing(RPC_HTTP)
def test_text_bytes_unknown_raises(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    with pytest.raises(KeyError):
        ctx.text_bytes('__nonexistent__')


# ── rela_map ──────────────────────────────────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_rela_map_nonempty(roc):
    ctx = roc.from_path(str(RPC_HTTP))
    assert len(ctx.rela_map()) > 0


# ── sessock.o: multi-function object ─────────────────────────────────────────

@_skip_if_missing(SESSOCK)
def test_sessock_has_multiple_functions(roc):
    ctx = roc.from_path(str(SESSOCK))
    assert len(ctx.functions()) >= 2


@_skip_if_missing(SESSOCK)
def test_sessock_summary(roc):
    ctx = roc.from_path(str(SESSOCK))
    s = ctx.summary()
    assert 'PPC32' in s


# ── robustness: non-ELF input ─────────────────────────────────────────────────

def test_non_elf_returns_empty_context(roc):
    ctx = roc(b'this is not elf data at all xxxxxx', '<test>')
    assert ctx.functions() == []
    assert ctx.imports() == []


def test_truncated_elf_returns_empty(roc):
    ctx = roc(b'\x7fELF', '<test>')
    assert ctx.functions() == []


def test_empty_bytes_returns_empty(roc):
    ctx = roc(b'', '<test>')
    assert ctx.functions() == []
