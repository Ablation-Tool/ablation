import argparse
import csv
import json
from pathlib import Path
import sys

from . import __version__
from .agent import AgentBridge, kimi_command, parse_agent_command
from .inventory import load_records, scan, write_scan
from .render import load_summary, render
from .server import serve


QUERY_FIELDS = [
    "id", "path", "format", "architecture", "endianness", "artifact_class",
    "size_bytes", "sha256", "status", "analysis_status", "scan_error",
]


def output_path(value):
    return Path(value).expanduser().resolve()


def command_scan(args):
    records, summary = scan(args.directory, args.output)
    output = output_path(args.output)
    write_scan(output, records, summary)
    destination = render(output)
    print(json.dumps({**summary, "matrix": str(destination)}, indent=2, ensure_ascii=False))
    return 0


def command_summary(args):
    summary = load_summary(output_path(args.output))
    if args.text:
        print(f"METRIX {summary['tool_version']} — {summary['artifacts']} artifacts")
        print(f"Root: {summary['root']}")
        print(f"Files: {summary['regular_files']} ({summary['hashed_files']} hashed, {summary['total_file_bytes']} bytes)")
        print(f"Directories: {summary['directories']}; symlinks: {summary['symlinks']}; errors: {summary['errors']}")
        for title, key in (("Formats", "formats"), ("Architectures", "architectures"), ("Statuses", "statuses")):
            print(f"{title}:")
            for value, count in summary[key].items():
                print(f"  {value}: {count}")
    else:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def matches(record, args):
    for field in ("format", "architecture", "artifact_class", "status", "analysis_status"):
        value = getattr(args, field)
        if value is not None and record.get(field) != value:
            return False
    haystack = json.dumps(record, ensure_ascii=False, sort_keys=True).casefold()
    return all(term.casefold() in haystack for term in args.contains)


def command_query(args):
    total = 0
    shown = 0
    writer = None
    if args.tsv:
        writer = csv.DictWriter(sys.stdout, fieldnames=QUERY_FIELDS, delimiter="\t", lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
    for record in load_records(output_path(args.output)):
        if not matches(record, args):
            continue
        total += 1
        if args.limit and shown >= args.limit:
            continue
        shown += 1
        if writer:
            writer.writerow(record)
        else:
            print(json.dumps(record, ensure_ascii=False, sort_keys=True))
    print(f"{total} matches; showing {shown}.", file=sys.stderr)
    return 0


def command_show(args):
    records = list(load_records(output_path(args.output)))
    exact = [record for record in records if args.identifier in (record.get("id"), record.get("path"), record.get("sha256"))]
    candidates = exact or [record for record in records if (record.get("id") or "").startswith(args.identifier) or (record.get("sha256") or "").startswith(args.identifier)]
    if not candidates:
        raise ValueError(f"artifact not found: {args.identifier}")
    if len(candidates) != 1:
        paths = ", ".join(record["path"] for record in candidates[:10])
        raise ValueError(f"artifact identifier is ambiguous ({len(candidates)} matches): {paths}")
    print(json.dumps(candidates[0], indent=2, ensure_ascii=False, sort_keys=True))
    return 0


def command_render(args):
    destination = render(output_path(args.output))
    print(json.dumps({"matrix": str(destination)}, indent=2))
    return 0


def command_gui(args):
    output = output_path(args.output)
    workspace = output_path(args.workspace) if args.workspace else output
    command = parse_agent_command(args.agent_command) if args.agent_command else kimi_command() if args.agent == "kimi" else None
    bridge = AgentBridge(command, output, workspace, args.agent_timeout)
    return serve(output, args.host, args.port, bridge, not args.no_browser)


def command_desktop(args):
    from .desktop import run_desktop
    command = parse_agent_command(args.agent_command) if args.agent_command else ["kimi"] if args.agent == "kimi" else None
    workspace = output_path(args.workspace) if args.workspace else None
    return run_desktop(output_path(args.output), command, workspace)


def add_output(parser):
    parser.add_argument("--output", "-o", default="metrix-output", help="METRIX output directory (default: metrix-output)")


def build_parser():
    parser = argparse.ArgumentParser(prog="metrix", description="Evidence-first inventory and navigation for reverse-engineering corpora")
    parser.add_argument("--version", action="version", version=f"METRIX {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("scan", help="Inventory a directory and generate JSONL, summary, and HTML")
    command.add_argument("directory", type=Path)
    add_output(command)
    command.set_defaults(function=command_scan)
    command = commands.add_parser("summary", help="Print corpus totals and filter counts")
    add_output(command)
    command.add_argument("--text", action="store_true", help="Use human-readable text instead of JSON")
    command.set_defaults(function=command_summary)
    command = commands.add_parser("query", help="Filter artifact records; emits JSONL by default")
    add_output(command)
    command.add_argument("--format")
    command.add_argument("--architecture")
    command.add_argument("--kind", "--artifact-class", dest="artifact_class", help="Artifact class, such as executable, library, archive, or source")
    command.add_argument("--status")
    command.add_argument("--analysis-status")
    command.add_argument("--contains", action="append", default=[], help="Case-insensitive text term; repeat to require multiple terms")
    command.add_argument("--limit", type=int, default=50, help="Maximum records; 0 means unlimited (default: 50)")
    command.add_argument("--tsv", action="store_true", help="Emit TSV instead of JSONL")
    command.set_defaults(function=command_query)
    command = commands.add_parser("show", help="Show one artifact by ID, path, or unique hash prefix")
    command.add_argument("identifier")
    add_output(command)
    command.set_defaults(function=command_show)
    command = commands.add_parser("render", help="Regenerate matrix.html from existing output records")
    add_output(command)
    command.set_defaults(function=command_render)
    command = commands.add_parser("gui", help="Serve the local dashboard and optional external-agent bridge")
    add_output(command)
    command.add_argument("--host", default="127.0.0.1", help="Loopback host only (default: 127.0.0.1)")
    command.add_argument("--port", type=int, default=0, help="Loopback port; 0 chooses a free port (default: 0)")
    command.add_argument("--workspace", help="External agent working directory (default: METRIX output directory)")
    agents = command.add_mutually_exclusive_group()
    agents.add_argument("--agent", choices=["kimi"], help="Use an installed agent CLI preset")
    agents.add_argument("--agent-command", help="External CLI command; {prompt} is replaced, otherwise the prompt uses stdin")
    command.add_argument("--agent-timeout", type=int, default=180, help="Agent timeout in seconds (default: 180)")
    command.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    command.set_defaults(function=command_gui)
    command = commands.add_parser("desktop", help="Open the native dashboard with an optional embedded interactive CLI")
    add_output(command)
    command.add_argument("--workspace", help="Interactive CLI working directory (default: METRIX output directory)")
    agents = command.add_mutually_exclusive_group()
    agents.add_argument("--agent", choices=["kimi"], help="Start the interactive Kimi CLI in the embedded terminal")
    agents.add_argument("--agent-command", help="Interactive CLI command to run inside the embedded terminal")
    command.set_defaults(function=command_desktop)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "limit", 0) < 0:
        parser.error("--limit must be nonnegative")
    if getattr(args, "port", 0) < 0 or getattr(args, "port", 0) > 65535:
        parser.error("--port must be between 0 and 65535")
    if getattr(args, "agent_timeout", 1) < 1:
        parser.error("--agent-timeout must be positive")
    try:
        return args.function(args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, csv.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
