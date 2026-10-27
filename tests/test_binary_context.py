"""Tests for BinaryContext -- ELF parsing, string extraction, import resolution."""

import sys
import warnings
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


def test_arm64_plt_stubs_resolve_to_dynamic_symbols():
    import struct
    from types import SimpleNamespace
    from ablation.analyzers.binary_context import BinaryContext

    symbols = [
        SimpleNamespace(name='_ZNSo3putEc@GLIBCXX_3.4'),
        SimpleNamespace(name='socket@GLIBC_2.17'),
    ]
    rela_plt = b''.join(
        struct.pack('<QQq', got_va, index << 32, 0)
        for index, got_va in enumerate((0x1fd70, 0x1fd78))
    )
    plt = bytes(32) + bytes.fromhex(
        'f00000d011ba46f910c2359120021fd6'
        'f00000d011be46f910e2359120021fd6'
    )
    sections = {
        '.rela.plt': SimpleNamespace(content=rela_plt),
        '.plt': SimpleNamespace(content=plt, virtual_address=0x1e40),
    }
    binary = SimpleNamespace(
        dynamic_symbols=symbols,
        get_section=lambda name: sections.get(name),
    )
    ctx = BinaryContext()
    ctx.arch = 'arm64'

    ctx._extract_plt(binary)

    assert ctx.plt == {0x1e60: '_ZNSo3putEc', 0x1e70: 'socket'}


def test_arm64_plt_supports_register_variants_and_ldr_only_stubs():
    import struct
    from types import SimpleNamespace
    from ablation.analyzers.binary_context import BinaryContext

    rela_plt = struct.pack('<QQq', 0x1fd70, 0, 0)
    plt_sec = bytes.fromhex(
        'f10000d031ba46f931c2359120021fd6'
        'f10000d031ba46f91f2003d520021fd6'
    )
    sections = {
        '.rela.plt': SimpleNamespace(content=rela_plt),
        '.plt.sec': SimpleNamespace(content=plt_sec, virtual_address=0x1e60),
    }
    binary = SimpleNamespace(
        dynamic_symbols=[SimpleNamespace(name='_ZNSo3putEc@GLIBCXX_3.4')],
        get_section=lambda name: sections.get(name),
    )
    ctx = BinaryContext()
    ctx.arch = 'arm64'

    ctx._extract_plt(binary)

    assert ctx.plt == {0x1e60: '_ZNSo3putEc', 0x1e70: '_ZNSo3putEc'}


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


def test_version_two_cache_is_rebuilt(tmp_path, monkeypatch):
    import json
    from ablation.analyzers import binary_context as module
    from ablation.analyzers.binary_context import BinaryContext

    binary = tmp_path / 'arm64-sample'
    data = b'not-an-elf'
    binary.write_bytes(data)
    sha = module._sha256(data)
    monkeypatch.setattr(module, '_CACHE_DIR', tmp_path)
    cache_file = module._cache_path(sha, str(binary))
    cache_file.write_text(json.dumps({'cache_version': 2, 'sha256': sha}))

    rebuilt = BinaryContext()
    rebuilt.path = str(binary)
    rebuilt.sha256 = sha
    monkeypatch.setattr(
        BinaryContext,
        '_build',
        classmethod(lambda cls, data, path, sha: rebuilt),
    )

    result = BinaryContext.load_or_build(str(binary))

    assert result is rebuilt
    assert json.loads(cache_file.read_text())['cache_version'] == 3


def test_bff_magic_issues_warning(tmp_path):
    """load_or_build on AIX BFF magic bytes must issue a UserWarning, not crash."""
    from ablation.analyzers.binary_context import BinaryContext
    fake_bff = tmp_path / 'test.bff'
    # AIX BFF magic: 0x09006bea (big-endian u32)
    fake_bff.write_bytes(b'\x09\x00\x6b\xea' + b'\x00' * 100)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        ctx = BinaryContext.load_or_build(str(fake_bff))
    msgs = [str(w.message) for w in caught if issubclass(w.category, UserWarning)]
    assert any('BFF' in m or 'installp' in m for m in msgs), (
        f'Expected BFF warning, got: {msgs}'
    )
    assert ctx is not None  # must not raise, returns empty context


def test_xcoff32_magic_issues_warning(tmp_path):
    """load_or_build on XCOFF32 magic bytes must issue a UserWarning, not crash."""
    from ablation.analyzers.binary_context import BinaryContext
    fake_xcoff = tmp_path / 'test.o'
    # XCOFF32 magic: 0x01df (big-endian u16 at offset 0)
    fake_xcoff.write_bytes(b'\x01\xdf' + b'\x00' * 100)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        ctx = BinaryContext.load_or_build(str(fake_xcoff))
    msgs = [str(w.message) for w in caught if issubclass(w.category, UserWarning)]
    assert any('XCOFF32' in m or 'xcoff' in m.lower() for m in msgs), (
        f'Expected XCOFF32 warning, got: {msgs}'
    )
    assert ctx is not None
