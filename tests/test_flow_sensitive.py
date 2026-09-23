"""
Tests for flow-sensitive taint analysis, PLT.sec resolution, and callee augmentation.

Compiles a small C binary with gcc, then verifies:
  1. PLT.sec stubs resolve to named symbols via XRefGraph._plt
  2. XRefGraph._func_starts includes callee VAs not found by prologue scan
  3. Flow-sensitive analysis detects read->memcpy across basic blocks
  4. TaintFinding.source_calls populated correctly even when source and sink
     are in different basic blocks
"""

import os
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

# ── compile test binary ───────────────────────────────────────────────────────

C_SRC = r"""
#include <unistd.h>
#include <string.h>

static volatile char sink_buf[512];

/*
 * Cross-block case: read() in block A, conditional branch, memcpy() in block B.
 * Use volatile output + -fno-builtin so gcc emits both PLT calls.
 */
__attribute__((noinline))
void process_input(char *output) {
    char buf[256];
    ssize_t n = read(0, buf, sizeof(buf));
    if (n > 0) {
        memcpy(output, buf, (size_t)n);
    }
}

/*
 * Single-block case: read() and memcpy() in the same basic block (no branch).
 * Used for linear taint regression test.
 */
__attribute__((noinline))
void simple_input(char *output, size_t maxlen) {
    char tmp[256];
    ssize_t n = read(0, tmp, maxlen < sizeof(tmp) ? maxlen : sizeof(tmp));
    memcpy(output, tmp, (size_t)(n < 0 ? 0 : n));
}

int main(void) {
    process_input((char *)sink_buf);
    simple_input((char *)sink_buf + 256, 64);
    return 0;
}
"""


@pytest.fixture(scope="module")
def test_binary():
    """Compile C source and return path to ELF binary. Deleted after module."""
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as csrc:
        csrc.write(C_SRC.encode())
        csrc_path = csrc.name

    bin_path = csrc_path.replace(".c", "_bin")
    try:
        result = subprocess.run(
            # -fno-builtin: prevent gcc from inlining memcpy/read as builtins
            ["gcc", "-O1", "-g0", "-fno-builtin", "-o", bin_path, csrc_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            pytest.skip(f"gcc failed: {result.stderr}")
        yield bin_path
    finally:
        for p in (csrc_path, bin_path):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


# ── helpers ───────────────────────────────────────────────────────────────────

def _build_xref(binary_path: str):
    from ablation.analyzers.xref_graph import XRefGraph
    xg = XRefGraph.from_path(binary_path)
    xg.build()
    return xg


# ── PLT.sec resolution ───────────────────────────────────────────────────────

def test_plt_sec_resolves_read(test_binary):
    """XRefGraph._plt must contain 'read' at a .plt.sec stub VA."""
    xg = _build_xref(test_binary)
    names = set(xg._plt.values())
    assert "read" in names, f"'read' not in PLT names: {sorted(names)}"


def test_plt_sec_resolves_memcpy(test_binary):
    """XRefGraph._plt must contain 'memcpy' at a .plt.sec stub VA."""
    xg = _build_xref(test_binary)
    names = set(xg._plt.values())
    assert "memcpy" in names, f"'memcpy' not in PLT names: {sorted(names)}"


def test_plt_stub_vas_are_in_plt_sec(test_binary):
    """PLT VAs for read/memcpy must be in .plt.sec range (not only .plt range)."""
    import lief
    binary = lief.parse(test_binary)
    plt_sec = binary.get_section(".plt.sec")
    assert plt_sec is not None, ".plt.sec section absent"

    sec_start = plt_sec.virtual_address
    sec_end = sec_start + plt_sec.size

    from ablation.analyzers.xref_graph import XRefGraph
    xg = XRefGraph.from_path(test_binary)
    xg.build()

    # At least one named entry must fall inside .plt.sec
    plt_sec_entries = {va: name for va, name in xg._plt.items()
                       if sec_start <= va < sec_end}
    assert plt_sec_entries, f"No PLT entries inside .plt.sec range [{sec_start:#x}, {sec_end:#x})"


# ── callee augmentation ───────────────────────────────────────────────────────

def test_callee_augmentation_adds_targets(test_binary):
    """_func_starts must include all callee VAs after build()."""
    from ablation.analyzers.xref_graph import XRefGraph
    xg = XRefGraph.from_path(test_binary)
    xg.build()

    plt_vas = set(xg._plt.keys())
    for caller_va, callee_set in xg._callees.items():
        for callee_va in callee_set:
            if callee_va in plt_vas:
                continue
            assert callee_va in xg._func_starts, (
                f"callee {callee_va:#x} called from {caller_va:#x} not in _func_starts"
            )


# ── flow-sensitive taint (cross-block source attribution) ─────────────────────

def _run_flow_sensitive(binary_path: str):
    """Return (findings, chains) from TaintTracker.run_flow_sensitive()."""
    from ablation.analyzers.xref_graph import XRefGraph
    from ablation.analyzers.taint_tracker_x86 import TaintTracker

    xg = XRefGraph.from_path(binary_path)
    xg.build()
    tracker = TaintTracker(binary_path, xref=xg)
    return tracker.run_flow_sensitive(min_func_size=10)


def test_flow_sensitive_detects_read_memcpy(test_binary):
    """Flow-sensitive analysis must detect read->memcpy taint path."""
    findings, _ = _run_flow_sensitive(test_binary)
    memcpy_findings = [f for f in findings if f.sink_name == "memcpy"]
    assert memcpy_findings, (
        f"No memcpy finding. All findings: {findings}"
    )


def test_flow_sensitive_tainted_arg_is_size(test_binary):
    """memcpy finding must flag arg2 (size, rdx) as tainted."""
    findings, _ = _run_flow_sensitive(test_binary)
    memcpy_findings = [f for f in findings if f.sink_name == "memcpy"]
    assert memcpy_findings, "No memcpy finding"
    f = memcpy_findings[0]
    assert 2 in f.tainted_args, f"Expected arg2 tainted; got tainted_args={f.tainted_args}"


def test_flow_sensitive_source_attribution_cross_block(test_binary):
    """
    source_calls must include 'read' even though read() and memcpy() are in
    different basic blocks (conditional branch between them).

    This validates the accumulated_sources fix: predecessor block's source calls
    propagate forward to successor blocks via the taint_out update path.
    """
    findings, _ = _run_flow_sensitive(test_binary)
    memcpy_findings = [f for f in findings if f.sink_name == "memcpy"]
    assert memcpy_findings, "No memcpy finding"
    f = memcpy_findings[0]
    assert "read" in f.source_calls, (
        f"Expected 'read' in source_calls; got {f.source_calls}. "
        "Cross-block source attribution is broken."
    )


# ── linear taint baseline (regression) ───────────────────────────────────────

def test_linear_taint_still_finds_memcpy(test_binary):
    """
    Linear (non-flow-sensitive) analysis must detect read->memcpy.

    Uses simple_input() which has read() and memcpy() in the SAME basic block
    (no conditional branch between them) -- linear scan can reach the sink
    without CFG traversal. The cross-block case (process_input) is intentionally
    not tested here: linear analysis stops at 'ret' and misses code reachable
    only via other paths.
    """
    from ablation.analyzers.xref_graph import XRefGraph
    from ablation.analyzers.taint_tracker_x86 import TaintTracker

    xg = XRefGraph.from_path(test_binary)
    xg.build()
    tracker = TaintTracker(test_binary, xref=xg)
    findings = tracker.run(min_func_size=10)
    memcpy_findings = [f for f in findings if f.sink_name == "memcpy"]
    assert memcpy_findings, (
        f"Linear taint regression: no memcpy finding. All findings: {findings}"
    )


if __name__ == "__main__":
    import subprocess, sys
    sys.exit(subprocess.run(["python3", "-m", "pytest", __file__, "-v"]).returncode)
