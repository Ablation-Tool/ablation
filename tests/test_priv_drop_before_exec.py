"""Tests for PrivilegeDropBeforeExecAnalyzer.

Known-positive: HMC rnvi — SETUID root vi wrapper that calls
  setreuid(-1, getuid()) before execv('/bin/vi'), dropping root before exec.
  VAs byte-verified in session 53 (2026-10-23):
    getuid@0x401104, setreuid(-1,getuid())@0x40161f, execv@0x40181a

Known-negative: /usr/bin/ls — no getuid+setreuid+exec chain.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

RNVI = '/tmp/hmc_v11r1/hmc.mgmt/opt/hsc/bin/rnvi'


def _has_binary():
    return Path(RNVI).exists()


@pytest.mark.skipif(not _has_binary(), reason='HMC rnvi binary not extracted')
class TestPrivDropPositive:
    def test_rnvi_single_finding(self):
        from ablation.analyzers.priv_drop_before_exec import PrivilegeDropBeforeExecAnalyzer
        results = PrivilegeDropBeforeExecAnalyzer.from_path(RNVI).scan()
        assert len(results) >= 1, f'expected >=1, got {len(results)}: {results}'

    def test_rnvi_verdict_not_exploitable(self):
        from ablation.analyzers.priv_drop_before_exec import PrivilegeDropBeforeExecAnalyzer
        results = PrivilegeDropBeforeExecAnalyzer.from_path(RNVI).scan()
        # At least one NOT_EXPLOITABLE finding expected (the main priv-drop)
        verdicts = [r.verdict for r in results]
        assert 'NOT_EXPLOITABLE' in verdicts, f'expected NOT_EXPLOITABLE, got {verdicts}'

    def test_rnvi_drop_name_setreuid(self):
        from ablation.analyzers.priv_drop_before_exec import PrivilegeDropBeforeExecAnalyzer
        results = PrivilegeDropBeforeExecAnalyzer.from_path(RNVI).scan()
        not_exp = [r for r in results if r.verdict == 'NOT_EXPLOITABLE']
        assert not_exp, 'no NOT_EXPLOITABLE finding'
        assert not_exp[0].drop_name == 'setreuid'

    def test_rnvi_getuid_va(self):
        from ablation.analyzers.priv_drop_before_exec import PrivilegeDropBeforeExecAnalyzer
        results = PrivilegeDropBeforeExecAnalyzer.from_path(RNVI).scan()
        not_exp = [r for r in results if r.verdict == 'NOT_EXPLOITABLE']
        # geteuid@0x40110c is the last uid call before setreuid (getuid@0x401104 precedes it)
        assert not_exp[0].getuid_va == 0x40110c

    def test_rnvi_drop_va(self):
        from ablation.analyzers.priv_drop_before_exec import PrivilegeDropBeforeExecAnalyzer
        results = PrivilegeDropBeforeExecAnalyzer.from_path(RNVI).scan()
        not_exp = [r for r in results if r.verdict == 'NOT_EXPLOITABLE']
        # 0x401624 = call setreuid (the call instruction); 0x40161f = preceding mov edi,-1
        assert not_exp[0].drop_va == 0x401624

    def test_rnvi_exec_va(self):
        from ablation.analyzers.priv_drop_before_exec import PrivilegeDropBeforeExecAnalyzer
        results = PrivilegeDropBeforeExecAnalyzer.from_path(RNVI).scan()
        not_exp = [r for r in results if r.verdict == 'NOT_EXPLOITABLE']
        assert not_exp[0].exec_va == 0x40181a

    def test_rnvi_no_reescalation(self):
        from ablation.analyzers.priv_drop_before_exec import PrivilegeDropBeforeExecAnalyzer
        results = PrivilegeDropBeforeExecAnalyzer.from_path(RNVI).scan()
        not_exp = [r for r in results if r.verdict == 'NOT_EXPLOITABLE']
        assert not not_exp[0].reescalation


class TestPrivDropNegative:
    def test_ls_no_findings(self):
        from ablation.analyzers.priv_drop_before_exec import PrivilegeDropBeforeExecAnalyzer
        results = PrivilegeDropBeforeExecAnalyzer.from_path('/usr/bin/ls').scan()
        assert results == []
