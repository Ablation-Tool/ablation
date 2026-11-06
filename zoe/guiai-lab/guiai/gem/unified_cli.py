from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .unified import ComponentRegistry, IDENTITY


def parser():
    result = argparse.ArgumentParser(prog="zoe", description=IDENTITY)
    commands = result.add_subparsers(dest="command")
    for name in ("list", "components"):
        commands.add_parser(name, help="list every registered engine and GEM source")
    launch = commands.add_parser("launch", help="launch an explicit engine or GEM command")
    launch.add_argument("--detach", action="store_true", help="start the component without waiting for it")
    launch.add_argument("component", help="component identifier from `zoe list`")
    launch.add_argument("arguments", nargs=argparse.REMAINDER, help="component arguments after `--`")
    manifest = commands.add_parser("manifest", help="write a no-overwrite unified component manifest")
    manifest.add_argument("--output", required=True, help="new JSON manifest path")
    knowledge = commands.add_parser("knowledge", help="save the unified source and trust-context graph")
    knowledge.add_argument("--output", required=True, help="new JSON knowledge-memory path")
    show = commands.add_parser("show", help="inspect a component without launching a process")
    show.add_argument("component", help="component identifier from `zoe list`")
    return result


def main(argv=None):
    arguments = parser().parse_args(argv)
    registry = ComponentRegistry()
    try:
        if arguments.command in {"list", "components"}:
            for component in registry.manifest()["components"]:
                source = component["source"]
                status = "present" if source["source_present"] else "missing"
                print(f"{component['identifier']:10} {status:8} {source['mode']:9} {component['summary']}")
            return 0
        if arguments.command == "manifest":
            output = registry.write_manifest(arguments.output)
            print(json.dumps({"identity": IDENTITY, "output": str(output), "bytes": output.stat().st_size}, indent=2, sort_keys=True))
            return 0
        if arguments.command == "knowledge":
            output = registry.knowledge.save(arguments.output)
            print(json.dumps({"identity": IDENTITY, "output": str(output), "bytes": output.stat().st_size, "events": len(registry.knowledge.events)}, indent=2, sort_keys=True))
            return 0
        if arguments.command == "show":
            registry.component(arguments.component)
            row = next(item for item in registry.manifest()["components"] if item["identifier"] == arguments.component)
            print(json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if arguments.command == "launch":
            forwarded = list(arguments.arguments)
            if forwarded and forwarded[0] == "--":
                forwarded.pop(0)
            result = registry.launch(arguments.component, forwarded or None, detach=arguments.detach)
            if arguments.detach:
                print(json.dumps({"component": arguments.component, "pid": result.pid, "started": True, "readiness_verified": False}, indent=2, sort_keys=True))
                return 0
            return result.returncode
        from .atlas_view import launch_atlas
        launch_atlas("unified")
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(f"zoe: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
