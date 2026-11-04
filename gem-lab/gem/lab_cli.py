import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .events import Session
from metrix.agent import parse_agent_command
from .launcher import default_agent, default_workspace, session_for_target, show_launch_error


def session_path(value):
    return Path(value).expanduser().resolve()


def command_launch(args):
    try:
        args.workspace = str(default_workspace())
        if not args.no_agent and not args.agent_command and not args.agent:
            args.agent = default_agent() or None
        target = command_desktop(args)
        if not isinstance(target, Path):
            return target
        args.target = str(target)
        args.session = str(session_for_target(target))
        return command_desktop(args)
    except Exception as error:
        show_launch_error(str(error))
        return 1


def command_desktop(args):
    command = parse_agent_command(args.agent_command or args.agent) if args.agent_command or args.agent else None
    workspace = session_path(args.workspace) if getattr(args, "workspace", None) else default_workspace()
    target = session_path(args.target) if getattr(args, "target", None) else None
    session = session_path(args.session) if target is not None else None
    if args.toolkit != "tk":
        system_packages = Path("/usr/lib/python3/dist-packages")
        if system_packages.is_dir() and str(system_packages) not in sys.path:
            sys.path.append(str(system_packages))
        try:
            from .gtk_app import run_desktop
            return run_desktop(target, session, command, workspace)
        except (ImportError, ValueError) as error:
            if args.toolkit == "gtk":
                raise ValueError(f"GTK/VTE interface is unavailable: {error}. Install python3-gi, python3-cairo, python3-gi-cairo, gir1.2-gtk-3.0, and gir1.2-vte-2.91") from error
            print(f"GTK interface unavailable ({error}); using Tkinter", file=sys.stderr)
    from .app import run_desktop
    return run_desktop(target, session, command, workspace)


def command_emit(args):
    session = Session(session_path(args.session))
    event = session.emit(
        args.id, args.parent, args.type, args.label, args.status,
        args.source, args.evidence, args.note, args.scope,
    )
    print(json.dumps(event, indent=2, ensure_ascii=False))
    return 0


def command_emit_many(args):
    session = Session(session_path(args.session))
    if args.file == "-":
        specifications = json.load(sys.stdin)
    else:
        specifications = json.loads(Path(args.file).read_text(encoding="utf-8"))
    if not isinstance(specifications, list) or not all(isinstance(item, dict) for item in specifications):
        raise ValueError("emit-many input must be a JSON array of event objects")
    events = session.emit_many(specifications)
    print(json.dumps(events, indent=2, ensure_ascii=False))
    return 0


def command_state(args):
    session = Session(session_path(args.session))
    print(json.dumps(session.current_state(), indent=2, ensure_ascii=False))
    return 0


def command_begin(args):
    session = Session(session_path(args.session))
    state = session.begin_selected_work(args.expected_id, args.expected_revision, args.note)
    print(json.dumps(state, indent=2, ensure_ascii=False))
    return 0


def command_tree(args):
    session = Session(session_path(args.session))
    events = session.events()
    if args.json:
        print(json.dumps(events, indent=2, ensure_ascii=False))
        return 0
    children = {}
    for event in events:
        children.setdefault(event["parent_id"], []).append(event)
    pending = [(None, 0)]
    while pending:
        parent_id, depth = pending.pop()
        descendants = children.get(parent_id, [])
        for event in descendants:
            print(f"{'  ' * depth}{event['label']} [{event['status']}] ({event['id']})")
        for event in reversed(descendants):
            pending.append((event["id"], depth + 1))
    return 0


def command_review(args):
    session = Session(session_path(args.session))
    event = session.events_by_id().get(args.id)
    if event is None:
        raise ValueError(f"node does not exist: {args.id}")
    updated = session.emit(
        event["id"], event["parent_id"], event["type"], event["label"],
        args.status, "human", event["evidence"], args.note or event["note"], event.get("scope"),
    )
    print(json.dumps(updated, indent=2, ensure_ascii=False))
    return 0


def add_session(parser):
    parser.add_argument("--session", "-s", default="gem-session", help="Session directory (default: gem-session)")


def add_desktop_options(command):
    command.add_argument("--toolkit", choices=["auto", "gtk", "tk"], default="auto", help="Native interface toolkit (default: auto)")
    agents = command.add_mutually_exclusive_group()
    agents.add_argument("--agent", help="Interactive agent CLI executable to embed, such as kimi, claude, or codex")
    agents.add_argument("--agent-command", help="Interactive CLI command to run inside the embedded terminal")
    agents.add_argument("--no-agent", action="store_true", help="Open the Lab without an embedded interactive CLI")


def build_parser():
    parser = argparse.ArgumentParser(prog="gem", description="GEM (Graphics Environment Manager) investigation workspace")
    parser.add_argument("--version", action="version", version=f"GEM {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("desktop", help="Open the native Lab workspace with an optional embedded interactive CLI")
    command.add_argument("target", help="Binary file or material directory for this investigation")
    add_session(command)
    command.add_argument("--workspace", help="Interactive CLI working directory (default: gem-lab root)")
    add_desktop_options(command)
    command.set_defaults(function=command_desktop)
    command = commands.add_parser("launch", help="Open GEM and choose an investigation target inside the application")
    add_desktop_options(command)
    command.set_defaults(function=command_launch)
    command = commands.add_parser("emit", help="Append or update an investigation node")
    add_session(command)
    command.add_argument("--id", required=True)
    command.add_argument("--parent")
    command.add_argument("--type", required=True, choices=["artifact", "function", "evidence", "observation", "hypothesis", "finding", "note"])
    command.add_argument("--label", required=True)
    command.add_argument("--status", default="not_started", choices=["not_started", "in_progress", "partial", "blocked", "reviewed", "complete_scoped", "rejected", "not_applicable"])
    command.add_argument("--source", default="agent", choices=["system", "agent", "tool", "human"])
    command.add_argument("--evidence", default="")
    command.add_argument("--note", default="")
    command.add_argument("--scope")
    command.set_defaults(function=command_emit)
    command = commands.add_parser("emit-many", help="Append a JSON array of discoveries with one disk sync")
    add_session(command)
    command.add_argument("--file", required=True, help="JSON array file, or - to read stdin")
    command.set_defaults(function=command_emit_many)
    command = commands.add_parser("state", help="Print the currently selected investigation node")
    add_session(command)
    command.set_defaults(function=command_state)
    command = commands.add_parser("begin", help="Begin work only if the selected node and revision are unchanged")
    add_session(command)
    command.add_argument("--expected-id", required=True, help="selected_id returned by gem state")
    command.add_argument("--expected-revision", required=True, type=int, help="revision returned by gem state")
    command.add_argument("--note", help="Optional work note; existing notes are preserved by default")
    command.set_defaults(function=command_begin)
    command = commands.add_parser("tree", help="Print the current investigation tree")
    add_session(command)
    command.add_argument("--json", action="store_true")
    command.set_defaults(function=command_tree)
    command = commands.add_parser("review", help="Record a human status update for a node")
    add_session(command)
    command.add_argument("id")
    command.add_argument("--status", required=True, choices=["partial", "blocked", "reviewed", "rejected"])
    command.add_argument("--note")
    command.set_defaults(function=command_review)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.function(args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
