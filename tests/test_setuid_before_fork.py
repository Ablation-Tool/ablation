"""Tests for SetuidBeforeForkAnalyzer.

Known-positive: HMC asmmenu (V10 + V11) — SETUID root binary that calls
setuid(0) before fork()+execv('/opt/hsc/bin/launchASM').
Known-negative: /usr/bin/ls — no setuid/fork/exec in same function chain.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

V10 = '/tmp/hmc-svrmgmt/usr/hmcrbin/asmmenu'
V11 = '/tmp/hmc_v11r1/hmc.svrmgmt/usr/hmcrbin/asmmenu'


def _has_binaries():
    return Path(V10).exists() and Path(V11).exists()


@pytest.mark.skipif(not _has_binaries(), reason='HMC asmmenu binaries not extracted')
class TestSetuidBeforeForkPositive:
    def test_v10_single_finding(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        results = SetuidBeforeForkAnalyzer.from_path(V10).scan()
        assert len(results) == 1, f'expected 1, got {len(results)}: {results}'

    def test_v10_confirmed_verdict(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        r = SetuidBeforeForkAnalyzer.from_path(V10).scan()[0]
        assert r.verdict == 'CONFIRMED'

    def test_v10_setuid_arg_zero(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        r = SetuidBeforeForkAnalyzer.from_path(V10).scan()[0]
        assert r.setuid_arg == 0

    def test_v10_exec_path_resolved(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        r = SetuidBeforeForkAnalyzer.from_path(V10).scan()[0]
        assert r.exec_path == '/opt/hsc/bin/launchASM'

    def test_v10_func_va_correct(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        r = SetuidBeforeForkAnalyzer.from_path(V10).scan()[0]
        assert r.func_va == 0x401260

    def test_v10_chain_vas_correct(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        r = SetuidBeforeForkAnalyzer.from_path(V10).scan()[0]
        assert r.setuid_va == 0x401278
        assert r.fork_va == 0x40127d
        assert r.exec_va == 0x4012be

    def test_v11_single_finding(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        results = SetuidBeforeForkAnalyzer.from_path(V11).scan()
        assert len(results) == 1, f'expected 1, got {len(results)}: {results}'

    def test_v11_confirmed_verdict(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        r = SetuidBeforeForkAnalyzer.from_path(V11).scan()[0]
        assert r.verdict == 'CONFIRMED'

    def test_v11_exec_path_resolved(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        r = SetuidBeforeForkAnalyzer.from_path(V11).scan()[0]
        assert r.exec_path == '/opt/hsc/bin/launchASM'

    def test_v11_func_va_correct(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        r = SetuidBeforeForkAnalyzer.from_path(V11).scan()[0]
        assert r.func_va == 0x400af0

    def test_v11_chain_vas_correct(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        r = SetuidBeforeForkAnalyzer.from_path(V11).scan()[0]
        assert r.setuid_va == 0x400b08
        assert r.fork_va == 0x400b0d
        assert r.exec_va == 0x400b4e


class TestSetuidBeforeForkNegative:
    def test_ls_no_findings(self):
        from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
        results = SetuidBeforeForkAnalyzer.from_path('/usr/bin/ls').scan()
        assert results == []
