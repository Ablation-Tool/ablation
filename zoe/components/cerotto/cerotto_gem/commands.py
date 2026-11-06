"""Bounded native CEROTTO command execution for the desktop workbench."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
from typing import Any


MAX_COMMAND_OUTPUT = 1024 * 1024


class CommandError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    document: dict[str, Any]
    stdout: str
    stderr: str
    duration_ms: int


class CommandRunner:
    def __init__(self, binary: str | Path):
        self.binary = Path(binary).expanduser().resolve()
        if not self.binary.is_file():
            raise ValueError(f"CEROTTO binary not found: {self.binary}")
        self._processes: set[subprocess.Popen] = set()
        self._lock = threading.Lock()
        self._cancelled = False

    def cancel_all(self) -> None:
        self._cancelled = True
        with self._lock:
            processes = list(self._processes)
        for process in processes:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def run_json(self, arguments: list[str], timeout: int = 60, accepted: tuple[int, ...] = (0,),
                 allow_empty: bool = False) -> CommandResult:
        if self._cancelled:
            raise CommandError("native command execution is closing")
        if not arguments or any(not isinstance(argument, str) or not argument for argument in arguments):
            raise ValueError("native command arguments must be nonempty strings")
        started = time.monotonic()
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.Popen(
                    [str(self.binary), *arguments], stdout=stdout, stderr=stderr,
                    start_new_session=True,
                )
            except OSError as exc:
                raise CommandError(f"could not start CEROTTO: {exc}") from exc
            with self._lock:
                self._processes.add(process)
            try:
                try:
                    returncode = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise CommandError(f"CEROTTO command timed out after {timeout} seconds") from exc
            finally:
                with self._lock:
                    self._processes.discard(process)
            stdout.seek(0)
            raw_output = stdout.read(MAX_COMMAND_OUTPUT + 1)
            stderr.seek(0)
            raw_errors = stderr.read(MAX_COMMAND_OUTPUT + 1)
        if len(raw_output) > MAX_COMMAND_OUTPUT or len(raw_errors) > MAX_COMMAND_OUTPUT:
            raise CommandError("CEROTTO command output exceeds the configured limit")
        output = raw_output.decode("utf-8", errors="replace")
        errors = raw_errors.decode("utf-8", errors="replace")
        if returncode not in accepted:
            raise CommandError(f"CEROTTO exited with status {returncode}: {errors[:2000]}")
        if allow_empty and not output.strip():
            document = {}
        else:
            try:
                document = json.loads(output)
            except json.JSONDecodeError as exc:
                raise CommandError(f"CEROTTO returned invalid JSON: {errors[:500] or output[:500]}") from exc
            if not isinstance(document, dict):
                raise CommandError("CEROTTO returned a non-object JSON result")
        return CommandResult(returncode, document, output, errors, round((time.monotonic() - started) * 1000))

    def guard(self, database: Path, case_id: str, proposal: Path, output: Path) -> CommandResult:
        if output.exists():
            raise CommandError(f"guard result already exists: {output}")
        return self.run_json([
            "guard", "--db", str(database), "--case", case_id,
            "--input", str(proposal), "--output", str(output),
        ], accepted=(0, 1, 3))

    def verify(self, database: Path, case_id: str) -> CommandResult:
        return self.run_json(["verify", "--db", str(database), "--case", case_id], accepted=(0, 1))

    def report(self, database: Path, case_id: str, conversation_id: str, output: Path,
               reviewer: str = "CEROTTO GEM User") -> None:
        result = self.run_json([
            "report", "--db", str(database), "--case", case_id,
            "--conversation", conversation_id, "--format", "json",
            "--reviewer", reviewer, "--review-status", "reviewed", "--output", str(output),
        ], allow_empty=True)
        if result.returncode != 0 or not output.is_file():
            raise CommandError("CEROTTO did not create the requested report")
