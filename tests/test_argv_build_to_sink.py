"""Tests for ArgvBuildToSinkClassifier.

Known-positive: HMC ldapsearch — SETUID binary with argv accumulation via
  strcat(buf, argv[i]) loop → system(buf), gated by GetRole=="hscroot".
  VAs byte-verified in session 53 (2026-10-23):
    strcat@0x400d86, system@0x400de6, strcmp gate with "hscroot"@0x4010e5

Known-positive (no gate): HMC chhmc — argv[1] directly strcat'd → system()
  with no role check (HMC restricted shell only, HMCMGMT-CMD-001 LOW).
  strcat@0x400897, system@0x400945

Known-negative: /usr/bin/ls — no strcat→system chain.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

LDAPSEARCH = '/tmp/hmc_v11r1/hmc.mgmt/usr/hmcrbin/ldapsearch'
CHHMC      = '/tmp/hmc_v11r1/hmc.mgmt/opt/hsc/bin/chhmc'


def _has_ldapsearch():
    return Path(LDAPSEARCH).exists()


def _has_chhmc():
    return Path(CHHMC).exists()


@pytest.mark.skipif(not _has_ldapsearch(), reason='HMC ldapsearch binary not extracted')
class TestArgvBuildPositiveLdapsearch:
    def test_ldapsearch_finds_pattern(self):
        from ablation.analyzers.argv_build_to_sink import ArgvBuildToSinkClassifier
        results = ArgvBuildToSinkClassifier.from_path(LDAPSEARCH).scan()
        assert len(results) >= 1, f'expected >=1, got {results}'

    def test_ldapsearch_sink_system(self):
        from ablation.analyzers.argv_build_to_sink import ArgvBuildToSinkClassifier
        results = ArgvBuildToSinkClassifier.from_path(LDAPSEARCH).scan()
        sinks = [r.sink_name for r in results]
        assert 'system' in sinks

    def test_ldapsearch_sink_va(self):
        from ablation.analyzers.argv_build_to_sink import ArgvBuildToSinkClassifier
        results = ArgvBuildToSinkClassifier.from_path(LDAPSEARCH).scan()
        sys_findings = [r for r in results if r.sink_name == 'system']
        sink_vas = [r.sink_va for r in sys_findings]
        assert 0x400de6 in sink_vas, f'expected system@0x400de6 in {[hex(v) for v in sink_vas]}'

    def test_ldapsearch_gate_detected(self):
        from ablation.analyzers.argv_build_to_sink import ArgvBuildToSinkClassifier
        results = ArgvBuildToSinkClassifier.from_path(LDAPSEARCH).scan()
        # Gate is detected via getpwnam("root") call — 'root' in gate_strings confirms
        # privilege restriction is present (hscroot strcmp at 0x4010e5 may appear as second arg)
        gate_strings = []
        gate_funcs = []
        for r in results:
            gate_strings.extend(r.gate_strings)
            gate_funcs.extend(r.gate_funcs)
        assert gate_strings or gate_funcs, f'expected gate, got strings={gate_strings} funcs={gate_funcs}'
        # Any root-or-role string confirms access restriction
        role_strings = {'root', 'hscroot', 'hmcroot'}
        assert role_strings & set(gate_strings), f'expected role gate string, got {gate_strings}'

    def test_ldapsearch_severity_low(self):
        from ablation.analyzers.argv_build_to_sink import ArgvBuildToSinkClassifier
        results = ArgvBuildToSinkClassifier.from_path(LDAPSEARCH).scan()
        sys_findings = [r for r in results if r.sink_name == 'system']
        severities = {r.severity for r in sys_findings}
        assert 'LOW' in severities, f'expected LOW severity for hscroot-gated finding, got {severities}'


@pytest.mark.skipif(not _has_chhmc(), reason='HMC chhmc binary not extracted')
class TestArgvBuildPositiveChhmc:
    def test_chhmc_finds_pattern(self):
        from ablation.analyzers.argv_build_to_sink import ArgvBuildToSinkClassifier
        results = ArgvBuildToSinkClassifier.from_path(CHHMC).scan()
        assert len(results) >= 1, f'expected >=1, got {results}'

    def test_chhmc_sink_va(self):
        from ablation.analyzers.argv_build_to_sink import ArgvBuildToSinkClassifier
        results = ArgvBuildToSinkClassifier.from_path(CHHMC).scan()
        sys_findings = [r for r in results if r.sink_name == 'system']
        sink_vas = [r.sink_va for r in sys_findings]
        assert 0x400945 in sink_vas, f'expected system@0x400945 in {[hex(v) for v in sink_vas]}'


class TestArgvBuildNegative:
    def test_ls_no_findings(self):
        from ablation.analyzers.argv_build_to_sink import ArgvBuildToSinkClassifier
        results = ArgvBuildToSinkClassifier.from_path('/usr/bin/ls').scan()
        assert results == []
