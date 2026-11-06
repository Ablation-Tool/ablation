"""Command-line launcher for the CEROTTO GEM desktop workbench."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import sys

from .commands import CommandRunner
from .model import CaseModel, MAX_CASE_EVENTS


ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="cerotto-gem")
    result.add_argument("--db", required=True, type=Path)
    result.add_argument("--case", required=True)
    result.add_argument("--conversation", required=True)
    result.add_argument("--binary", type=Path, default=ROOT / "build" / "cerotto")
    result.add_argument("--limit", type=int, default=MAX_CASE_EVENTS)
    result.add_argument("--agent-command", help="optional interactive agent command, parsed without a shell")
    result.add_argument("--workspace", type=Path)
    result.add_argument("--self-test", action="store_true", help="exercise the native workbench and exit")
    result.add_argument("--screenshot", type=Path, help="save a PNG during --self-test")
    return result


def load_application_class():
    try:
        from .gui import CerottoGemApplication
        return CerottoGemApplication
    except ImportError as first:
        distribution = Path("/usr/lib/python3/dist-packages")
        if distribution.is_dir():
            sys.path.append(str(distribution))
            try:
                from .gui import CerottoGemApplication
                return CerottoGemApplication
            except ImportError as second:
                raise RuntimeError(f"GTK3/PyGObject is unavailable: {second}") from second
        raise RuntimeError(f"GTK3/PyGObject is unavailable: {first}") from first


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.screenshot and not args.self_test:
        parser().error("--screenshot requires --self-test")
    try:
        agent_command = shlex.split(args.agent_command) if args.agent_command else None
        if agent_command is not None and (not agent_command or any(not item for item in agent_command)):
            raise ValueError("agent command must contain nonempty arguments")
        workspace = args.workspace.expanduser().resolve() if args.workspace else args.db.expanduser().resolve().parent
        if not workspace.is_dir():
            raise ValueError("agent workspace is not a directory")
        if args.screenshot and not args.screenshot.parent.is_dir():
            raise ValueError("screenshot directory does not exist")
        model = CaseModel(args.db, args.case, args.conversation, args.limit)
        model.load()
        commands = CommandRunner(args.binary)
        application_class = load_application_class()
        application = application_class(model, commands, agent_command, workspace)
        if args.self_test:
            from gi.repository import GLib
            GLib.timeout_add(1000, lambda: application.window.self_test(args.screenshot))
        return application.run([sys.executable])
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"cerotto-gem: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
