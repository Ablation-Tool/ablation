"""Tests for BinaryContext -- ELF parsing, string extraction, import resolution."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

BINARY = '/usr/bin/ls'


def test_load_or_build():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(BINARY)
    assert ctx is not None


def test_has_func_starts():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(BINARY)
    assert len(ctx.func_starts) > 0


def test_has_strings():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(BINARY)
    assert len(ctx.strings) > 0


def test_has_plt_entries():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(BINARY)
    # /usr/bin/ls imports standard library functions
    assert len(ctx.plt) > 0


def test_summary_returns_string():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(BINARY)
    s = ctx.summary()
    assert isinstance(s, str)
    assert 'func_starts' in s


def test_sha256_is_hex():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(BINARY)
    assert len(ctx.sha256) >= 8
    int(ctx.sha256[:8], 16)  # must be valid hex


@pytest.mark.integration
def test_ppc64le_plt_stubs():
    """_extract_plt_ppc64le decodes stub VAs and symbol names from a ppc64le ELF V2."""
    import os
    lib = '/tmp/at_rpms/runtime/opt/at17.0/lib64/libpaf-dsc.so.0.0.3'
    if not os.path.exists(lib):
        pytest.skip('AT17 runtime fixture not extracted at /tmp/at_rpms/')
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(lib)
    syms = set(ctx.plt.values())
    # 18 PLT entries known from manual analysis; spot-check 5 key ones
    for expected in ('strncpy', 'open', 'read', 'malloc', 'pthread_once'):
        assert expected in syms, f'Expected {expected!r} in ppc64le PLT, got {sorted(syms)}'
    # All stub VAs must be plausible code addresses (non-zero, within .text/.init range)
    for va in ctx.plt:
        assert 0xa00 <= va < 0x2000, f'PLT stub VA {va:#x} outside plausible code range'


def test_cache_hit_is_fast(tmp_path):
    """Second load_or_build call should use cache and be much faster."""
    import time
    from ablation.analyzers.binary_context import BinaryContext
    t0 = time.perf_counter()
    BinaryContext.load_or_build(BINARY)
    t1 = time.perf_counter()
    BinaryContext.load_or_build(BINARY)
    t2 = time.perf_counter()
    # Second call should not be significantly slower than first (cache hit)
    assert (t2 - t1) <= (t1 - t0) + 1.0  # generous bound -- just not hanging
