"""
hdl_sim.py — GHDL / Icarus Verilog runner for firmware-analysis sandboxes.

The CERN (and similar) research collections live on noexec mounts: bundled
simulator binaries exist in the collection but cannot be executed in place.
Every analysis script used to re-implement the same workaround — copy the
bundle to an executable filesystem, chmod the binaries, then invoke the tool.
This module centralizes that relocation plus the analyze/elaborate/run
invocations, with captured logs and explicit failure reporting.

No simulator is required at import time. Paths are explicit; nothing is
downloaded and no system package manager is touched.

Usage:
    tools = relocate_bundle('/media/research/tools/ghdl-5.0.1/root',
                            '/tmp/fpga-work/ghdl')
    ghdl = GHDLRunner(tools, '/tmp/fpga-work/build')
    ghdl.analyze(['decoder.vhd', 'decoder_tb.vhd'])
    ghdl.elaborate('decoder_tb')
    result = ghdl.run('decoder_tb', stop_time='5us', log='sim.log')
    print(result.output)
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Union

PathLike = Union[str, Path]


class SimulationError(RuntimeError):
    """A simulator invocation failed; carries the captured output."""

    def __init__(self, message: str, output: str = "") -> None:
        super().__init__(message)
        self.output = output


@dataclass
class SimResult:
    argv: List[str]
    returncode: int
    output: str


def relocate_bundle(source: PathLike, destination: PathLike,
                    executable_globs: Sequence[str] = ("usr/bin/*", "bin/*")) -> Path:
    """Copy a bundled tool tree to an executable filesystem.

    Returns the destination root. Existing destinations are reused (delete
    first to refresh). Binaries matching executable_globs get the owner
    execute bit, which noexec source mounts typically strip or forbid.
    """
    src = Path(source)
    dst = Path(destination)
    if not src.is_dir():
        raise FileNotFoundError(f"tool bundle not found: {src}")
    if not dst.exists():
        shutil.copytree(src, dst)
    for pattern in executable_globs:
        for binary in dst.glob(pattern):
            if binary.is_file():
                binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return dst


def _invoke(argv: Sequence[str], cwd: Path, log: Optional[PathLike],
            timeout: Optional[int]) -> SimResult:
    proc = subprocess.run(
        list(argv), cwd=str(cwd), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=timeout,
    )
    result = SimResult(argv=list(argv), returncode=proc.returncode, output=proc.stdout)
    if log is not None:
        Path(log).write_text(proc.stdout, encoding="utf-8")
    if proc.returncode != 0:
        raise SimulationError(f"command failed ({proc.returncode}): {' '.join(argv)}",
                              output=proc.stdout)
    return result


class GHDLRunner:
    """GHDL mcode runner operating inside a dedicated build directory."""

    def __init__(self, bundle_root: PathLike, build_dir: PathLike,
                 std: str = "08", timeout: Optional[int] = 60) -> None:
        self.binary = Path(bundle_root) / "usr" / "bin" / "ghdl-mcode"
        if not self.binary.is_file():
            # Some bundles ship the driver as plain 'ghdl'.
            alternate = Path(bundle_root) / "usr" / "bin" / "ghdl"
            if alternate.is_file():
                self.binary = alternate
        if not self.binary.is_file():
            raise FileNotFoundError(f"ghdl-mcode not found under {bundle_root}")
        self.build_dir = Path(build_dir)
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.std = std
        self.timeout = timeout

    def _ghdl(self, args: Sequence[str], log: Optional[PathLike] = None) -> SimResult:
        return _invoke([str(self.binary), *args], cwd=self.build_dir, log=log,
                       timeout=self.timeout)

    def analyze(self, sources: Sequence[PathLike]) -> SimResult:
        return self._ghdl(["-a", f"--std={self.std}", *[str(s) for s in sources]])

    def elaborate(self, unit: str) -> SimResult:
        return self._ghdl(["-e", f"--std={self.std}", unit])

    def run(self, unit: str, stop_time: Optional[str] = None,
            assert_level: Optional[str] = None,
            log: Optional[PathLike] = None, extra_args: Sequence[str] = ()) -> SimResult:
        args = ["-r", f"--std={self.std}", unit]
        if stop_time:
            args.append(f"--stop-time={stop_time}")
        if assert_level:
            args.append(f"--assert-level={assert_level}")
        args.extend(extra_args)
        return self._ghdl(args, log=log)


class IverilogRunner:
    """Icarus Verilog runner (iverilog compile + vvp execution)."""

    def __init__(self, bundle_root: PathLike, build_dir: PathLike,
                 timeout: Optional[int] = 60) -> None:
        root = Path(bundle_root)
        self.compiler = root / "usr" / "bin" / "iverilog"
        self.runtime = root / "usr" / "bin" / "vvp"
        for binary in (self.compiler, self.runtime):
            if not binary.is_file():
                raise FileNotFoundError(f"simulator binary not found: {binary}")
        self.build_dir = Path(build_dir)
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        # Icarus needs its library trees; the bundle layout supplies them via
        # -B and the vvp module path relative to the copied root.
        self.root = root

    def compile(self, sources: Sequence[PathLike], output: str = "sim.vvp",
                top: Optional[str] = None, log: Optional[PathLike] = None) -> Path:
        argv = [str(self.compiler), "-B", str(self.root / "usr" / "lib" / "ivl"),
                "-o", output]
        if top:
            argv.extend(["-s", top])
        argv.extend(str(s) for s in sources)
        _invoke(argv, cwd=self.build_dir, log=log, timeout=self.timeout)
        return self.build_dir / output

    def run(self, vvp_file: PathLike, log: Optional[PathLike] = None,
            extra_args: Sequence[str] = ()) -> SimResult:
        argv = [str(self.runtime), "-M", str(self.root / "usr" / "lib" / "ivl"),
                str(vvp_file), *extra_args]
        return _invoke(argv, cwd=self.build_dir, log=log, timeout=self.timeout)
