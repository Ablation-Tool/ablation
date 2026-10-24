"""Tests for PthreadOnceDetector.

Known-positive: IBM Storage Defender Sentinel dispatch (non-PIE ET_EXEC, 183MB) —
func@0x7781ac confirmed as LAZY_INIT in session 12 (calls pthread_once@GLIBC_2.34,
always returns 0; previously misidentified as an auth check).

Known-negative: a minimal ELF with no pthread_once import → no results.
"""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

DISPATCH = '/tmp/ds_re/cyberv_extracted/opt/ie/bin/dispatch'


def _dispatch_available():
    return Path(DISPATCH).exists()


class TestPthreadOnceDetectorSynthetic:
    def test_no_results_on_missing_plt(self, tmp_path):
        """A minimal ELF with no dynamic section returns an empty result list."""
        from ablation.analyzers.pthread_once_detector import PthreadOnceDetector
        # Write a trivial 64-byte (almost) valid ELF with no .rela.plt
        data = b'\x7fELF' + b'\x02\x01\x01' + b'\x00' * 9 + b'\x00' * 48
        elf  = tmp_path / 'stub.elf'
        elf.write_bytes(data)
        det = PthreadOnceDetector.from_path(str(elf))
        assert det.detect() == []

    def test_verdicts_are_known_values(self, tmp_path):
        from ablation.analyzers.pthread_once_detector import (
            PthreadOnceDetector, LAZY_INIT, POSSIBLE_AUTH, UNKNOWN
        )
        assert LAZY_INIT     == 'LAZY_INIT'
        assert POSSIBLE_AUTH == 'POSSIBLE_AUTH'
        assert UNKNOWN       == 'UNKNOWN'

    def test_report_no_results(self, tmp_path):
        from ablation.analyzers.pthread_once_detector import PthreadOnceDetector
        rep = PthreadOnceDetector.report([])
        assert 'no pthread_once' in rep

    def test_from_context_equivalent_to_from_path(self, tmp_path):
        from ablation.analyzers.pthread_once_detector import PthreadOnceDetector

        class FakeCtx:
            binary_path = None
            path = None

        elf = tmp_path / 'stub.elf'
        elf.write_bytes(b'\x7fELF' + b'\x00' * 60)
        FakeCtx.binary_path = str(elf)
        FakeCtx.path        = str(elf)
        d1 = PthreadOnceDetector.from_path(str(elf))
        d2 = PthreadOnceDetector.from_context(FakeCtx)
        assert d1.detect() == d2.detect()


@pytest.mark.skipif(not _dispatch_available(), reason='dispatch binary not extracted')
class TestPthreadOnceDetectorDispatch:
    def test_finds_at_least_one_lazy_init(self):
        from ablation.analyzers.pthread_once_detector import PthreadOnceDetector, LAZY_INIT
        det     = PthreadOnceDetector.from_path(DISPATCH)
        results = det.detect()
        lazy = [r for r in results if r.verdict == LAZY_INIT]
        assert lazy, 'expected at least one LAZY_INIT in dispatch'

    def test_session12_func_7781ac_is_lazy_init(self):
        """
        func@0x7781ac confirmed LAZY_INIT in session 12: pthread_once, always returns 0.
        This test locks that finding in the test suite.
        """
        from ablation.analyzers.pthread_once_detector import PthreadOnceDetector, LAZY_INIT
        det     = PthreadOnceDetector.from_path(DISPATCH)
        results = det.detect()
        match = [r for r in results if r.func_va == 0x7781ac]
        assert match, (
            'func@0x7781ac (session 12 lazy init) not found in PthreadOnceDetector results'
        )
        assert match[0].verdict == LAZY_INIT, (
            f'func@0x7781ac expected LAZY_INIT, got {match[0].verdict}'
        )
        assert match[0].returns_zero, 'func@0x7781ac should have returns_zero=True'

    def test_session12_func_7781ac_has_single_call(self):
        from ablation.analyzers.pthread_once_detector import PthreadOnceDetector
        det     = PthreadOnceDetector.from_path(DISPATCH)
        results = det.detect()
        match = [r for r in results if r.func_va == 0x7781ac]
        assert match
        assert match[0].call_count <= 1, (
            f'func@0x7781ac expected <=1 calls, got {match[0].call_count}'
        )

    def test_report_format_includes_lazy_init_section(self):
        from ablation.analyzers.pthread_once_detector import PthreadOnceDetector, LAZY_INIT
        det     = PthreadOnceDetector.from_path(DISPATCH)
        results = det.detect()
        rep = PthreadOnceDetector.report(results)
        if any(r.verdict == LAZY_INIT for r in results):
            assert 'LAZY_INIT' in rep
