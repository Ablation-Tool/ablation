"""Tests for SetuidObfuscatedExecDetector.

Known-positive: HMC hscdc — SETUID root binary with hex+XOR decode + getpwnam("root")
  → setuid(pw_uid) → fork() → execvp(decoded_command).
  VAs byte-verified in session 53 (2026-10-23) on V11R2M1120 binary:
    hscdc V11R2: getpwnam called before setuid@0x4013ef, fork@0x401407, execvp@0x40144c
    The getpwnam arg is "root" — ensures setuid(0) by invariant.

Known-negative: /usr/bin/ls — no getpwnam/setuid/fork/exec chain.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

HSCDC_V11 = '/tmp/hmc_rpms/hmc.common/opt/hsc/bin/hscdc'


def _has_binary():
    return Path(HSCDC_V11).exists()


@pytest.mark.skipif(not _has_binary(), reason='HMC hscdc binary not extracted')
class TestObfuscatedExecPositive:
    def test_hscdc_finds_pattern(self):
        from ablation.analyzers.setuid_obfuscated_exec import SetuidObfuscatedExecDetector
        results = SetuidObfuscatedExecDetector.from_path(HSCDC_V11).scan()
        assert len(results) >= 1, f'expected >=1, got {len(results)}: {results}'

    def test_hscdc_verdict_confirmed_or_plausible(self):
        from ablation.analyzers.setuid_obfuscated_exec import SetuidObfuscatedExecDetector
        results = SetuidObfuscatedExecDetector.from_path(HSCDC_V11).scan()
        verdicts = {r.verdict for r in results}
        assert verdicts & {'CONFIRMED', 'PLAUSIBLE'}, f'unexpected verdicts: {verdicts}'

    def test_hscdc_getpwnam_arg_root(self):
        from ablation.analyzers.setuid_obfuscated_exec import SetuidObfuscatedExecDetector
        results = SetuidObfuscatedExecDetector.from_path(HSCDC_V11).scan()
        args = [r.getpwnam_arg for r in results]
        assert 'root' in args, f'expected "root" arg, got {args}'

    def test_hscdc_severity_high(self):
        from ablation.analyzers.setuid_obfuscated_exec import SetuidObfuscatedExecDetector
        results = SetuidObfuscatedExecDetector.from_path(HSCDC_V11).scan()
        severities = {r.severity for r in results}
        assert 'HIGH' in severities

    def test_hscdc_setuid_va(self):
        from ablation.analyzers.setuid_obfuscated_exec import SetuidObfuscatedExecDetector
        results = SetuidObfuscatedExecDetector.from_path(HSCDC_V11).scan()
        suid_vas = [r.setuid_va for r in results]
        assert 0x4013ef in suid_vas, f'expected setuid@0x4013ef in {[hex(v) for v in suid_vas]}'

    def test_hscdc_fork_va(self):
        from ablation.analyzers.setuid_obfuscated_exec import SetuidObfuscatedExecDetector
        results = SetuidObfuscatedExecDetector.from_path(HSCDC_V11).scan()
        fork_vas = [r.fork_va for r in results]
        assert 0x401407 in fork_vas, f'expected fork@0x401407 in {[hex(v) for v in fork_vas]}'

    def test_hscdc_exec_va(self):
        from ablation.analyzers.setuid_obfuscated_exec import SetuidObfuscatedExecDetector
        results = SetuidObfuscatedExecDetector.from_path(HSCDC_V11).scan()
        exec_vas = [r.exec_va for r in results]
        assert 0x40144c in exec_vas, f'expected execvp@0x40144c in {[hex(v) for v in exec_vas]}'


class TestObfuscatedExecNegative:
    def test_ls_no_findings(self):
        from ablation.analyzers.setuid_obfuscated_exec import SetuidObfuscatedExecDetector
        results = SetuidObfuscatedExecDetector.from_path('/usr/bin/ls').scan()
        assert results == []
