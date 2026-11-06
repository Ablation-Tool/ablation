"""
Tests for the HDL simulator runner (ablation.integrations.hdl_sim).

No real simulator is required: bundles are stub shell scripts that echo their
arguments. Covers the noexec-mount relocation (copy + chmod) and the exact
analyze/elaborate/run command construction, plus failure propagation.
"""

import os
import stat

import pytest

from ablation.integrations.hdl_sim import (
    GHDLRunner,
    IverilogRunner,
    SimulationError,
    relocate_bundle,
)


def _stub(path, script="#!/bin/sh\necho \"$@\"\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(script)
    # Deliberately non-executable, as on a noexec research mount.
    path.chmod(0o644)
    return path


def _ghdl_bundle(tmp_path, script="#!/bin/sh\necho \"$@\"\n"):
    root = tmp_path / "bundle"
    _stub(root / "usr" / "bin" / "ghdl-mcode", script)
    return root


def test_relocate_bundle_copies_and_chmods(tmp_path):
    src = _ghdl_bundle(tmp_path)
    dst = relocate_bundle(src, tmp_path / "work" / "ghdl")
    binary = dst / "usr" / "bin" / "ghdl-mcode"
    assert binary.is_file()
    assert binary.stat().st_mode & stat.S_IXUSR
    # Reuse is idempotent.
    assert relocate_bundle(src, dst) == dst


def test_relocate_bundle_missing_source(tmp_path):
    with pytest.raises(FileNotFoundError):
        relocate_bundle(tmp_path / "nope", tmp_path / "out")


def test_ghdl_full_flow(tmp_path):
    bundle = relocate_bundle(_ghdl_bundle(tmp_path), tmp_path / "ghdl")
    runner = GHDLRunner(bundle, tmp_path / "build")
    result = runner.analyze(["decoder.vhd", "decoder_tb.vhd"])
    assert result.argv[1:3] == ["-a", "--std=08"]
    assert result.argv[3:] == ["decoder.vhd", "decoder_tb.vhd"]
    assert "-a --std=08 decoder.vhd decoder_tb.vhd" in result.output
    runner.elaborate("decoder_tb")
    log = tmp_path / "build" / "sim.log"
    result = runner.run("decoder_tb", stop_time="5us", assert_level="error", log=log)
    assert "-r --std=08 decoder_tb --stop-time=5us --assert-level=error" in result.output
    assert log.read_text() == result.output


def test_ghdl_failure_raises_with_output(tmp_path):
    bundle = relocate_bundle(
        _ghdl_bundle(tmp_path, script="#!/bin/sh\necho compile error\necho \"$@\"\nexit 1\n"),
        tmp_path / "ghdl",
    )
    runner = GHDLRunner(bundle, tmp_path / "build")
    with pytest.raises(SimulationError) as excinfo:
        runner.analyze(["broken.vhd"])
    assert "compile error" in excinfo.value.output


def test_ghdl_missing_binary(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    with pytest.raises(FileNotFoundError):
        GHDLRunner(root, tmp_path / "build")


def test_iverilog_flow(tmp_path):
    root = tmp_path / "ivl-bundle"
    _stub(root / "usr" / "bin" / "iverilog")
    _stub(root / "usr" / "bin" / "vvp")
    bundle = relocate_bundle(root, tmp_path / "ivl")
    runner = IverilogRunner(bundle, tmp_path / "build")
    runner.compile(["tb.sv"], output="sim.vvp", top="tb")
    vvp_path = tmp_path / "build" / "sim.vvp"
    vvp_path.write_text("stub")
    result = runner.run("sim.vvp")
    assert "-M" in result.argv
    assert result.argv[-1] == "sim.vvp"
