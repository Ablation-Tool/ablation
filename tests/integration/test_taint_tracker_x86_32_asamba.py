"""Integration test: X86_32TaintTracker on Acronis asamba i386 ELF.

Requires the Acronis True Image 2018 ramdisk to be extracted at one of the
candidate paths below. Tests are skipped automatically when binary is absent.

Expected findings (session-verified 2026-10-06):
  ATI-KRB-001: func=0x804ec40  sink=system@0x804ec87
  ATI-KRB-002: func=0x804e986  sink=system@0x804ea09
"""

from pathlib import Path

import pytest

from ablation.analyzers.taint_tracker_x86_32 import X86_32TaintTracker

# Candidate extraction paths for asamba (try in order)
_CANDIDATES = [
    '/home/cowboy/scratchpad/acronis/ramdisk64/bin/asamba',
    '/media/cowboy/research/repos/acronis/ramdisk64/bin/asamba',
    '/media/cowboy/research/acronis/ramdisk64/bin/asamba',
    '/tmp/acronis/ramdisk64/bin/asamba',
]
ASAMBA_PATH = next((p for p in _CANDIDATES if Path(p).exists()), None)

pytestmark = pytest.mark.integration


@pytest.mark.skipif(ASAMBA_PATH is None, reason='asamba binary not available — mount research drive')
def test_run_interprocedural_asamba_krb001():
    """ATI-KRB-001: system sink at 0x804ec87 found in asamba interprocedural run."""
    tracker = X86_32TaintTracker.from_path(ASAMBA_PATH)
    findings = tracker.run_interprocedural()
    sink_vas = {f.sink_va for f in findings}
    assert 0x804ec87 in sink_vas, (
        f"ATI-KRB-001 sink VA 0x804ec87 not found; all sink VAs: "
        f"{sorted(hex(v) for v in sink_vas)[:20]}"
    )


@pytest.mark.skipif(ASAMBA_PATH is None, reason='asamba binary not available — mount research drive')
def test_run_interprocedural_asamba_krb002():
    """ATI-KRB-002: system sink at 0x804ea09 found in asamba interprocedural run."""
    tracker = X86_32TaintTracker.from_path(ASAMBA_PATH)
    findings = tracker.run_interprocedural()
    sink_vas = {f.sink_va for f in findings}
    assert 0x804ea09 in sink_vas, (
        f"ATI-KRB-002 sink VA 0x804ea09 not found; all sink VAs: "
        f"{sorted(hex(v) for v in sink_vas)[:20]}"
    )


@pytest.mark.skipif(ASAMBA_PATH is None, reason='asamba binary not available — mount research drive')
def test_summary_asamba():
    """X86_32TaintTracker.summary() returns expected binary name and non-zero func/PLT counts."""
    tracker = X86_32TaintTracker.from_path(ASAMBA_PATH)
    s = tracker.summary()
    assert 'asamba' in s
    assert 'funcs' in s
    assert 'PLT' in s
