"""
Tests for DeprecatedFuncScanner.
"""
import struct
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import capstone
import pytest

from ablation.analyzers.deprecated_func_scanner import (
    DeprecatedFuncScanner,
    DeprecatedHit,
    _DANGEROUS,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _e8_call(from_va: int, to_va: int) -> bytes:
    """Encode a CALL rel32 at from_va targeting to_va."""
    rel = to_va - (from_va + 5)
    return b'\xe8' + struct.pack('<i', rel)


def _build_mock_ctx(
    *,
    plt: dict,
    exports: dict,
    func_starts: list,
    call_edges: list,
    path: str,
):
    ctx = MagicMock()
    ctx.plt = plt
    ctx.exports = exports
    ctx.func_starts = func_starts
    ctx.call_edges = call_edges
    ctx.base_va = 0x400000
    ctx.path = path
    ctx.name = MagicMock(return_value='')
    return ctx


# ── Unit tests: _DANGEROUS coverage ───────────────────────────────────────────

class TestDangerousFunctions:
    def test_gets_present(self):
        assert 'gets' in _DANGEROUS

    def test_mktemp_present(self):
        assert 'mktemp' in _DANGEROUS

    def test_tmpnam_present(self):
        assert 'tmpnam' in _DANGEROUS

    def test_getwd_present(self):
        assert 'getwd' in _DANGEROUS

    def test_overflow_flag_gets(self):
        assert _DANGEROUS['gets']['overflow'] is True

    def test_overflow_flag_mktemp(self):
        assert _DANGEROUS['mktemp']['overflow'] is False

    def test_cwe_gets_includes_121(self):
        assert 'CWE-121' in _DANGEROUS['gets']['cwe']

    def test_cwe_mktemp_includes_377(self):
        assert 'CWE-377' in _DANGEROUS['mktemp']['cwe']


# ── Unit tests: DeprecatedHit.fmt ──────────────────────────────────────────────

class TestDeprecatedHitFmt:
    def _hit(self, **kw):
        defaults = dict(
            va=0x404666, func_va=0x40464e, func_name='readStdin',
            plt_name='gets', cwe='CWE-242/CWE-121',
            reason='reads stdin with no bounds check',
        )
        defaults.update(kw)
        return DeprecatedHit(**defaults)

    def test_fmt_basic(self):
        h = self._hit()
        s = h.fmt()
        assert '0x404666' in s
        assert 'gets' in s
        assert 'readStdin' in s

    def test_fmt_with_buf_size(self):
        h = self._hit(buf_size=0x2020, frame_size=0x2040, overflow_offset=0x2028)
        s = h.fmt()
        assert '0x2020' in s
        assert '0x2028' in s

    def test_fmt_unknown_buf_no_overflow_line(self):
        h = self._hit(buf_size=-1, overflow_offset=-1)
        s = h.fmt()
        assert 'overflow_offset' not in s

    def test_fmt_callers_listed(self):
        h = self._hit(callers=['handleResponse', 'dispMsgReadInput'])
        assert 'handleResponse' in h.fmt()
        assert 'dispMsgReadInput' in h.fmt()

    def test_fmt_no_func_name_uses_va(self):
        h = self._hit(func_name='', func_va=0x40464e)
        assert '0x40464e' in h.fmt()


# ── Integration: scan on a real tiny ELF ──────────────────────────────────────

def _make_minimal_elf_with_gets(tmp_path: Path) -> Path:
    """
    Build a minimal x86-64 ELF (not truly runnable) that encodes:
      - A PLT stub for gets at 0x401060
      - A function at 0x404650 that does:
          push rbp; mov rbp, rsp; sub rsp, 0x50
          lea rdi, [rbp-0x40]
          call 0x401060  (gets)
          leave; ret
    We use BinaryContext's raw disassembly path, not the ELF loader.
    This approach builds the raw bytes and patches the BinaryContext mock.
    """
    code_bytes = bytearray()
    FUNC_VA = 0x404650
    GETS_PLT = 0x401060

    # push rbp (1B) + mov rbp, rsp (3B) + sub rsp, 0x50 (4B)
    prologue = bytes.fromhex('55') + bytes.fromhex('4889E5') + bytes.fromhex('4883EC50')
    # lea rdi, [rbp-0x40]: 48 8D 7D C0
    lea_rdi = bytes.fromhex('488D7DC0')
    # call rel32 to GETS_PLT
    call_gets = _e8_call(FUNC_VA + len(prologue) + len(lea_rdi), GETS_PLT)
    # leave (1B) + ret (1B)
    epilogue = bytes.fromhex('C9C3')

    func_code = prologue + lea_rdi + call_gets + epilogue
    return func_code, FUNC_VA, GETS_PLT


class TestScanWithMock:
    def test_no_dangerous_plt_returns_empty(self, tmp_path):
        code = bytes(32)
        f = tmp_path / 'dummy.bin'
        f.write_bytes(code)
        ctx = _build_mock_ctx(
            plt={0x401030: 'printf', 0x401040: 'strlen'},
            exports={},
            func_starts=[0x400000],
            call_edges=[],
            path=str(f),
        )
        scanner = DeprecatedFuncScanner(ctx)
        assert scanner.scan() == []

    def test_gets_in_plt_but_no_call_returns_empty(self, tmp_path):
        # gets is in PLT but no code calls it
        code = b'\x55\x48\x89\xe5\x48\x83\xec\x10\xc9\xc3'  # push rbp ... ret
        f = tmp_path / 'dummy.bin'
        f.write_bytes(code)
        BASE = 0x400000
        ctx = _build_mock_ctx(
            plt={0x401060: 'gets'},
            exports={},
            func_starts=[BASE],
            call_edges=[],
            path=str(f),
        )
        scanner = DeprecatedFuncScanner(ctx)
        hits = scanner.scan()
        assert hits == []

    def test_gets_call_produces_hit(self, tmp_path):
        func_code, FUNC_VA, GETS_PLT = _make_minimal_elf_with_gets(tmp_path)
        # Pad to reach FUNC_VA relative to base 0x400000
        BASE = 0x400000
        offset = FUNC_VA - BASE
        raw = b'\x00' * offset + func_code
        f = tmp_path / 'real.bin'
        f.write_bytes(raw)

        ctx = _build_mock_ctx(
            plt={GETS_PLT: 'gets'},
            exports={},
            func_starts=[FUNC_VA],
            call_edges=[],
            path=str(f),
        )
        scanner = DeprecatedFuncScanner(ctx)
        hits = scanner.scan()
        assert len(hits) == 1
        h = hits[0]
        assert h.plt_name == 'gets'
        assert h.func_va == FUNC_VA
        assert h.cwe == 'CWE-242/CWE-121'

    def test_gets_call_buf_size_from_lea_rdi(self, tmp_path):
        func_code, FUNC_VA, GETS_PLT = _make_minimal_elf_with_gets(tmp_path)
        BASE = 0x400000
        raw = b'\x00' * (FUNC_VA - BASE) + func_code
        f = tmp_path / 'real.bin'
        f.write_bytes(raw)

        ctx = _build_mock_ctx(
            plt={GETS_PLT: 'gets'},
            exports={},
            func_starts=[FUNC_VA],
            call_edges=[],
            path=str(f),
        )
        scanner = DeprecatedFuncScanner(ctx)
        hits = scanner.scan()
        assert len(hits) == 1
        # lea rdi, [rbp-0x40] -> buf_size = 0x40
        assert hits[0].buf_size == 0x40
        # overflow_offset = 0x40 + 8 = 0x48
        assert hits[0].overflow_offset == 0x48

    def test_overflow_flag_false_no_buf_calc(self, tmp_path):
        # mktemp call — should not attempt buffer size calculation
        BASE = 0x400000
        FUNC_VA = BASE + 0x100
        MKTEMP_PLT = BASE + 0x060
        # function that calls mktemp (simplified: push rbp; call mktemp; ret)
        prologue = bytes.fromhex('554889E5')
        call_mk = _e8_call(FUNC_VA + len(prologue), MKTEMP_PLT)
        code = prologue + call_mk + bytes.fromhex('C3')
        raw = b'\x00' * 0x100 + code
        f = tmp_path / 'mktemp.bin'
        f.write_bytes(raw)

        ctx = _build_mock_ctx(
            plt={MKTEMP_PLT: 'mktemp'},
            exports={},
            func_starts=[FUNC_VA],
            call_edges=[],
            path=str(f),
        )
        scanner = DeprecatedFuncScanner(ctx)
        hits = scanner.scan()
        assert len(hits) == 1
        assert hits[0].plt_name == 'mktemp'
        assert hits[0].buf_size == -1
        assert hits[0].overflow_offset == -1

    def test_dedup_same_call_va_not_double_reported(self, tmp_path):
        func_code, FUNC_VA, GETS_PLT = _make_minimal_elf_with_gets(tmp_path)
        BASE = 0x400000
        raw = b'\x00' * (FUNC_VA - BASE) + func_code
        f = tmp_path / 'dup.bin'
        f.write_bytes(raw)

        # Two func_starts that both claim the same range -> dedup should fire
        ctx = _build_mock_ctx(
            plt={GETS_PLT: 'gets'},
            exports={},
            func_starts=[FUNC_VA, FUNC_VA + 4],  # second is inside the first
            call_edges=[],
            path=str(f),
        )
        scanner = DeprecatedFuncScanner(ctx)
        hits = scanner.scan()
        # Call at FUNC_VA + <offset> should only appear once
        call_vas = [h.va for h in hits]
        assert len(call_vas) == len(set(call_vas)), "duplicate call VAs reported"

    def test_callers_populated_from_call_edges(self, tmp_path):
        func_code, FUNC_VA, GETS_PLT = _make_minimal_elf_with_gets(tmp_path)
        BASE = 0x400000
        raw = b'\x00' * (FUNC_VA - BASE) + func_code
        f = tmp_path / 'callers.bin'
        f.write_bytes(raw)

        CALLER_VA = 0x403000
        ctx = _build_mock_ctx(
            plt={GETS_PLT: 'gets'},
            exports={CALLER_VA: 'mainFunc'},
            func_starts=[FUNC_VA],
            call_edges=[(CALLER_VA, FUNC_VA, 'readStdin')],
            path=str(f),
        )
        ctx.name = MagicMock(return_value='')
        scanner = DeprecatedFuncScanner(ctx)
        hits = scanner.scan()
        assert len(hits) == 1
        assert 'mainFunc' in hits[0].callers


# ── Unit tests: report output ─────────────────────────────────────────────────

class TestReport:
    def test_empty_hits(self):
        ctx = MagicMock()
        ctx.plt = {}
        ctx.exports = {}
        ctx.func_starts = []
        ctx.call_edges = []
        ctx.base_va = 0x400000
        ctx.path = '/dev/null'
        ctx.name = MagicMock(return_value='')
        scanner = DeprecatedFuncScanner(ctx)
        r = scanner.report([])
        assert 'no dangerous' in r.lower()

    def test_report_count_line(self):
        hits = [
            DeprecatedHit(va=0x100, func_va=0x200, func_name='f1',
                          plt_name='gets', cwe='CWE-242/CWE-121',
                          reason='test'),
            DeprecatedHit(va=0x110, func_va=0x200, func_name='f1',
                          plt_name='mktemp', cwe='CWE-242/CWE-377',
                          reason='test2'),
        ]
        ctx = MagicMock()
        ctx.plt = {}
        ctx.exports = {}
        ctx.func_starts = []
        ctx.call_edges = []
        ctx.base_va = 0x400000
        ctx.path = '/dev/null'
        ctx.name = MagicMock(return_value='')
        scanner = DeprecatedFuncScanner(ctx)
        r = scanner.report(hits)
        assert '2 finding' in r
