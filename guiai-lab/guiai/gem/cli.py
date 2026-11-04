from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .agent import DEFAULT_AGENT_COMMAND, solve
from .geometry import VerificationReport, verify
from .model import Scene, demo_scene
from .render import write_png, write_svg
from .runner import export_run, replay, verify_vdi, write_failed_run
from .vdi import write_metafile
from .volume import DEFAULT_THRESHOLDS, measure_artifact, write_report


def _parser():
    parser = argparse.ArgumentParser(prog="gem", description="Executable Spatial IR, GEM VDI, and deterministic geometry verification")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    demo = commands.add_parser("demo", help="export the verified house example")
    demo.add_argument("--output", required=True, help="new or empty run directory")

    verify_parser = commands.add_parser("verify", help="verify a Spatial IR scene")
    verify_parser.add_argument("scene", help="scene JSON path")
    verify_parser.add_argument("--vdi", action="store_true", help="also recover and verify a GEM metafile")
    verify_parser.add_argument("--json", action="store_true", help="emit machine-readable reports")

    render = commands.add_parser("render", help="render a scene to SVG, PNG, or GEM VDI")
    render.add_argument("scene", help="scene JSON path")
    render.add_argument("--output", required=True, help="output artifact path")
    render.add_argument("--format", choices=("svg", "png", "gem"), help="default: infer from output suffix")
    render.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")

    replay_parser = commands.add_parser("replay", help="recompute verification from run artifacts")
    replay_parser.add_argument("run", help="GEM run directory")
    replay_parser.add_argument("--json", action="store_true", help="emit the complete recomputed report")

    agent = commands.add_parser("solve", help="generate, verify, and repair a scene with an external agent")
    agent.add_argument("request", help="natural-language drawing request")
    agent.add_argument("--output", required=True, help="new or empty run directory")
    agent.add_argument("--agent-command", default=DEFAULT_AGENT_COMMAND, help="command template; {prompt} is replaced, otherwise prompt uses stdin")
    agent.add_argument("--attempts", type=int, default=3, help="total generation/repair attempts, from 1 to 10")
    agent.add_argument("--timeout", type=float, default=120, help="timeout for each agent process in seconds")
    agent.add_argument("--constraints", help="JSON file containing required constraint objects")
    agent.add_argument("--cwd", help="working directory for the external agent")

    volume = commands.add_parser("volume", help="measure accessible volume and optional accessible momentum")
    volume.add_argument("probabilities", help="NPZ file containing a full-vocabulary probability vector")
    volume.add_argument("--key", default="probabilities", help="NPZ key for the current distribution")
    volume.add_argument("--previous", help="earlier NPZ distribution used to compute momentum")
    volume.add_argument("--previous-key", help="NPZ key for the earlier distribution; default: current key")
    volume.add_argument("--tau", action="append", type=float, help="probability threshold; repeat for a sweep")
    volume.add_argument("--min-volume", type=int, default=1, help="target band lower bound")
    volume.add_argument("--max-volume", type=int, default=4, help="target band upper bound")
    volume.add_argument("--output", required=True, help="new evidence JSON path")
    return parser


def _print_report(report):
    print(VerificationReport(report["scene_id"], report["results"]).text())


def main(argv=None):
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "volume":
            report = measure_artifact(
                arguments.probabilities,
                key=arguments.key,
                previous_path=arguments.previous,
                previous_key=arguments.previous_key,
                thresholds=arguments.tau or DEFAULT_THRESHOLDS,
                minimum=arguments.min_volume,
                maximum=arguments.max_volume,
            )
            output = write_report(report, arguments.output)
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            print(f"Evidence: {output}")
            return 0
        if arguments.command == "demo":
            result = export_run(demo_scene(), arguments.output, trajectory=[{
                "sequence": 1, "kind": "builtin_demo", "outcome": "exported",
            }])
            _print_report(result.source.to_dict())
            print(f"VDI: {'PASS' if result.vdi.passed else 'FAIL'}")
            for profile, report in result.devices.items():
                print(f"{profile}: {'PASS' if report['passed'] else 'FAIL'}")
            print(f"Run: {result.path}")
            return 0 if result.passed else 1
        if arguments.command == "verify":
            scene = Scene.load(arguments.scene)
            source = verify(scene)
            documents = {"source": source.to_dict()}
            if arguments.vdi:
                documents["vdi"] = verify_vdi(scene).to_dict()
            if arguments.json:
                print(json.dumps(documents, indent=2, sort_keys=True))
            else:
                _print_report(documents["source"])
                if "vdi" in documents:
                    print()
                    _print_report(documents["vdi"])
            return 0 if all(report["passed"] for report in documents.values()) else 1
        if arguments.command == "render":
            scene = Scene.load(arguments.scene)
            output = Path(arguments.output)
            kind = arguments.format or output.suffix.lower().lstrip(".")
            if kind == "svg":
                write_svg(scene, output, arguments.width)
            elif kind == "png":
                write_png(scene, output, arguments.width)
            elif kind == "gem":
                write_metafile(scene, output)
            else:
                raise ValueError("output format must be svg, png, or gem")
            print(f"{kind}: {output} ({output.stat().st_size} bytes)")
            return 0
        if arguments.command == "replay":
            result = replay(arguments.run)
            if arguments.json:
                print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            else:
                _print_report(result.source)
                _print_report(result.vdi)
                for profile, report in result.devices.items():
                    print(f"{profile}: {'PASS' if report['passed'] else 'FAIL'} · source+VDI+invariants")
                print(f"Recorded reports match: {result.matches_recorded}")
            return 0 if result.passed and result.matches_recorded else 1
        if arguments.command == "solve":
            constraints = []
            if arguments.constraints:
                constraints = json.loads(Path(arguments.constraints).read_text(encoding="utf-8"))
                if not isinstance(constraints, list):
                    raise ValueError("constraint file must contain a JSON array")
            result = solve(
                arguments.request, arguments.agent_command, constraints,
                max_attempts=arguments.attempts, timeout=arguments.timeout, cwd=arguments.cwd,
            )
            if result.scene is None:
                path = write_failed_run(arguments.output, result.trajectory, result.error or "no valid scene returned")
                print(f"No valid Spatial IR scene after {result.attempts} attempts. Trajectory: {path}", file=sys.stderr)
                return 1
            run = export_run(result.scene, arguments.output, trajectory=result.trajectory)
            _print_report(run.source.to_dict())
            print(f"Attempts: {result.attempts}")
            print(f"Source+VDI+devices: {'PASS' if run.passed else 'FAIL'}")
            print(f"Run: {run.path}")
            return 0 if run.passed else 1
    except (OSError, RuntimeError, ValueError) as error:
        print(f"gem: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
