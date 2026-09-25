"""
Tests for run_interprocedural() with CFG-based seed detection.

Key scenario: read() sits behind an early-return branch, making it unreachable
by linear disassembly that stops at the first 'ret'. The CFG-based seed scan
must find it and produce a 2-hop taint chain:
  conditional_recv -> process_buf -> memcpy

Verifies:
  1. conditional_recv is identified as a seed (read() is in non-first block)
  2. Full 2-hop chain is reported with correct sink and source attribution
  3. tainted_args reflects the propagated size argument
"""

import os
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

# ── compile a binary whose network source is in a non-first basic block ───────

C_SRC = r"""
#include <unistd.h>
#include <string.h>

/*
 * Global sink keeps the memcpy call alive even under -O1.
 * Without it, gcc eliminates process_buf because its local dst has no
 * observable side effects.
 */
volatile char g_sink[512];

/*
 * Callee: receives tainted buffer + length, copies into global sink.
 * memcpy with tainted len is the expected taint sink.
 */
__attribute__((noinline))
void process_buf(char *buf, size_t len) {
    memcpy((char *)g_sink, buf, len);
}

/*
 * Seed function: read() is in the SECOND basic block, gated behind an early
 * return.  Linear disassembly stopping at the first 'ret' never reaches
 * read().  CFG-based scan walks all blocks and finds it.
 *
 * Control flow:
 *   block_A: if (fd < 0) goto ret_early
 *   block_B: n = read(fd, buf, sizeof(buf))   <-- source call here
 *   block_C: if (n > 0) call process_buf(buf, n)
 *   block_D: return
 *   ret_early: return
 */
__attribute__((noinline))
void conditional_recv(int fd) {
    if (fd < 0) return;           /* early return -- first basic block ends here */
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n > 0)
        process_buf(buf, (size_t)n);
}

int main(void) {
    conditional_recv(0);
    return 0;
}
"""


@pytest.fixture(scope="module")
def interproc_binary():
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as csrc:
        csrc.write(C_SRC.encode())
        csrc_path = csrc.name

    bin_path = csrc_path.replace(".c", "_bin")
    try:
        result = subprocess.run(
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


def _run_interproc(binary_path: str):
    from ablation.analyzers.xref_graph import XRefGraph
    from ablation.analyzers.taint_tracker_x86 import TaintTracker

    xg = XRefGraph.from_path(binary_path)
    xg.build()
    tracker = TaintTracker(binary_path, xref=xg)
    return tracker.run_interprocedural(depth=4, min_func_size=10)


def test_interproc_finds_memcpy_sink(interproc_binary):
    """run_interprocedural must report a chain ending at memcpy or __memcpy_chk."""
    paths = _run_interproc(interproc_binary)
    memcpy_paths = [p for p in paths if p.sink_name in ("memcpy", "__memcpy_chk")]
    assert memcpy_paths, (
        f"No interprocedural memcpy finding. All paths: {paths}"
    )


def test_interproc_chain_length(interproc_binary):
    """Chain must include at least 2 functions (conditional_recv + process_buf)."""
    paths = _run_interproc(interproc_binary)
    memcpy_paths = [p for p in paths if p.sink_name in ("memcpy", "__memcpy_chk")]
    assert memcpy_paths, "No memcpy path"
    assert any(len(p.func_chain) >= 2 for p in memcpy_paths), (
        f"Expected chain length >= 2; got chains: {[p.func_chain for p in memcpy_paths]}"
    )


def test_interproc_source_is_read(interproc_binary):
    """Source name on the memcpy chain must be 'read'."""
    paths = _run_interproc(interproc_binary)
    memcpy_paths = [p for p in paths if p.sink_name in ("memcpy", "__memcpy_chk")]
    assert memcpy_paths, "No memcpy path"
    sources = {p.source_name for p in memcpy_paths}
    assert "read" in sources, f"Expected source 'read'; got {sources}"


def test_interproc_tainted_arg_is_size(interproc_binary):
    """memcpy finding must flag arg2 (size/rdx) as tainted."""
    paths = _run_interproc(interproc_binary)
    memcpy_paths = [p for p in paths if p.sink_name in ("memcpy", "__memcpy_chk")]
    assert memcpy_paths, "No memcpy path"
    assert any(2 in p.tainted_args for p in memcpy_paths), (
        f"Expected arg2 tainted; got tainted_args={[p.tainted_args for p in memcpy_paths]}"
    )


if __name__ == "__main__":
    import subprocess, sys
    sys.exit(subprocess.run(["python3", "-m", "pytest", __file__, "-v"]).returncode)
