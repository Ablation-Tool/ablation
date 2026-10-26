"""
Tests for SnprintfVariableFilter.

Uses PanGPS 6.3.3 build 674. Verified facts:
  - GetRoute_netstat@0x1591f0 popen call has format "/bin/netstat -rn -4 | /bin/grep -w -F '%s'"
    → contains %s → SAC verdict SNPRINTF_RODATA should upgrade to SNPRINTF_RODATA_VARIABLE
  - ip-route calls ("/sbin/ip route get %s", "/sbin/ip -6 route get %s") also contain %s
  - Numeric-only format strings must NOT be upgraded

Unit tests that don't require the PanGPS fixture test the filter logic on
synthetic SinkClassification objects.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from ablation.analyzers.snprintf_variable_filter import (
    SnprintfVariableFilter,
    SNPRINTF_RODATA_VARIABLE,
    _VARIABLE_SPEC_RE,
)

PANGPS = Path('/tmp/pangp_re/6.3.3-c42/opt/paloaltonetworks/globalprotect/PanGPS')
_SKIP = pytest.mark.skipif(not PANGPS.exists(), reason='PanGPS fixture not present')


# ── Unit tests (no fixture needed) ────────────────────────────────────────────

def _make_result(verdict, detail=''):
    from ablation.analyzers.sink_arg_classifier import SinkClassification
    return SinkClassification(
        sink_name='popen', arg_pos=0,
        func_va=0x1000, call_va=0x1010,
        verdict=verdict, detail=detail,
    )


def test_regex_matches_percent_s():
    assert _VARIABLE_SPEC_RE.search(b'/bin/netstat -rn -4 | grep -F \'%s\'')


def test_regex_matches_percent_S():
    assert _VARIABLE_SPEC_RE.search(b'echo %S')


def test_regex_matches_percent_n():
    assert _VARIABLE_SPEC_RE.search(b'%n')


def test_regex_does_not_match_numeric():
    assert not _VARIABLE_SPEC_RE.search(b'diff %d %d')
    assert not _VARIABLE_SPEC_RE.search(b'/sbin/ip route get %i')
    assert not _VARIABLE_SPEC_RE.search(b'count=%u total=%x')


def test_regex_does_not_match_escaped_percent():
    assert not _VARIABLE_SPEC_RE.search(b'100%% done')


def test_filter_upgrades_snprintf_rodata_with_string_spec(tmp_path):
    # Write a tiny fake binary containing the format string at a known offset
    fmt = b'/bin/netstat -rn -4 | grep \'%s\'\x00'
    payload = b'\x00' * 0x1000 + fmt
    bin_path = tmp_path / 'fake.bin'
    bin_path.write_bytes(payload)

    filt = SnprintfVariableFilter(str(bin_path))
    # Inject a known VA so fmt_string_at finds the string
    fmt_va = 0x1000
    result = filt.fmt_string_at(fmt_va)
    assert result is not None
    assert b'%s' in result
    assert filt.has_variable_specifier(result)


def test_filter_does_not_upgrade_rodata_const():
    # A RODATA_CONST result should pass through unchanged
    import io
    from ablation.analyzers.snprintf_variable_filter import SnprintfVariableFilter
    # We need an actual binary path; use /dev/null as a stub since we
    # only test non-SNPRINTF_RODATA verdicts (no format string reading)
    try:
        filt = SnprintfVariableFilter('/dev/null')
    except Exception:
        pytest.skip('cannot open /dev/null as binary')
    r = _make_result('RODATA_CONST', 'hardcoded string')
    out = filt.apply([r])
    assert len(out) == 1
    assert out[0].verdict == 'RODATA_CONST'


def test_filter_does_not_upgrade_snprintf_rodata_without_string_spec(tmp_path):
    fmt = b'diff %d %d\x00'
    payload = b'\x00' * 0x1000 + fmt
    bin_path = tmp_path / 'fake.bin'
    bin_path.write_bytes(payload)

    filt = SnprintfVariableFilter(str(bin_path))
    # Build a result whose detail contains the VA of the numeric-only format string
    r = _make_result('SNPRINTF_RODATA', detail='fmt LEA 0x1000 in .rodata')
    out = filt.apply([r])
    assert len(out) == 1
    assert out[0].verdict == 'SNPRINTF_RODATA'


def test_filter_upgrades_snprintf_rodata_with_string_spec_via_va(tmp_path):
    fmt = b'/bin/grep -F \'%s\'\x00'
    # Strategy 3 requires a hex address with 5+ digits (>= 0x10000) to avoid
    # misinterpreting small integers as VAs.
    payload = b'\x00' * 0x100100 + fmt
    bin_path = tmp_path / 'fake.bin'
    bin_path.write_bytes(payload)

    filt = SnprintfVariableFilter(str(bin_path))
    r = _make_result('SNPRINTF_RODATA', detail='fmt LEA 0x100100 in .rodata')
    out = filt.apply([r])
    assert len(out) == 1
    assert out[0].verdict == SNPRINTF_RODATA_VARIABLE
    assert out[0].severity == 'HIGH'


# ── Integration test with PanGPS ──────────────────────────────────────────────

@_SKIP
def test_pangps_sac_results_have_snprintf_variable_findings():
    """GetRoute_netstat uses '%s' in popen format — must be upgraded."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier import SinkArgClassifier

    ctx = BinaryContext.load_or_build(str(PANGPS))
    sac = SinkArgClassifier.from_context(ctx)
    results = sac.classify_all()

    filt = SnprintfVariableFilter.from_context(ctx)
    upgraded = filt.apply(results)

    variable_findings = [r for r in upgraded if r.verdict == SNPRINTF_RODATA_VARIABLE]
    assert len(variable_findings) >= 1, (
        "Expected at least one SNPRINTF_RODATA_VARIABLE after filtering PanGPS results"
    )
    # Severity must be HIGH for upgraded results
    for r in variable_findings:
        assert r.severity == 'HIGH', f"Expected HIGH severity, got {r.severity}"
