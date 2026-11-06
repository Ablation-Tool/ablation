from __future__ import annotations

import argparse
import json
import os
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

    module_choices = ("unified", "brain", "field", "cognitive", "qualia", "procrustes", "ellipses", "parabola", "circle", "clock", "graph", "volume", "onset", "horizon", "research", "dorothy", "dorothy-jenga", "dorothy-stack", "dorothy-rings")
    atlas = commands.add_parser("atlas", help="open the native geometry atlas or export one module")
    atlas.add_argument("--module", choices=module_choices, default="procrustes")
    atlas.add_argument("--output", help="export the default scene to .svg, .png, or .gem instead of opening GTK")
    atlas.add_argument("--format", choices=("svg", "png", "gem"), help="default: infer from output suffix")
    atlas.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")
    master = commands.add_parser("master", aliases=["brain", "zoe"], help="open Zoe / MASTER GEM with the BRAIN orchestrator")
    master.add_argument("--module", choices=module_choices, default="brain")
    master.add_argument("--research-root", help="next-token-predictability repository; default: MASTER_GEM_RESEARCH_ROOT")
    master.add_argument("--output", help="export the default scene to .svg, .png, or .gem instead of opening GTK")
    master.add_argument("--format", choices=("svg", "png", "gem"), help="default: infer from output suffix")
    master.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")
    qualia = commands.add_parser("qualia", help="run the Accessible Q-Volume toy demonstration and save JSON evidence")
    qualia.add_argument("--tau", action="append", type=float, help="additional q-arrow threshold; repeat to override the default 0.20 and 0.30")
    qualia.add_argument("--output", required=True, help="new JSON evidence path")
    dorothy = commands.add_parser("dorothy", help="Dorothy: render Allen CCFv3 structure meshes, or fetch the vendored atlas data")
    dorothy.add_argument("--fetch", action="store_true", help="download and hash the structure graph and PLY meshes into the local cache")
    dorothy.add_argument("--data-root", help="atlas cache directory; default: DOROTHY_CCF_ROOT or ~/.cache/dorothy/ccf_2017")
    dorothy.add_argument("--structures", help="comma-separated CCF structure IDs; default: the vendored 12-region set")
    dorothy.add_argument("--yaw", type=float, default=None, help="orbit yaw in degrees; default: per-view")
    dorothy.add_argument("--pitch", type=float, default=None, help="orbit pitch in degrees; default: per-view")
    dorothy.add_argument("--distance", type=float, help="camera distance in CCF units; default: fit the visible structures")
    dorothy.add_argument("--fov", type=float, default=35.0, help="vertical field of view in degrees")
    dorothy.add_argument("--shade-levels", type=int, default=16, help="flat-shading quantization per structure, 2-64")
    dorothy.add_argument("--output", help="export .svg, .png, or .gem instead of opening the native atlas")
    dorothy.add_argument("--format", choices=("svg", "png", "gem"), help="default: infer from output suffix")
    dorothy.add_argument("--width", type=int, default=1600, help="SVG/PNG width in pixels")
    dorothy.add_argument("--view", choices=("brain", "jenga", "stack", "rings"), default="brain", help="visualization variant")
    dorothy.add_argument("--layout", choices=("tower", "exploded", "pull"), default="tower", help="Jenga layout")
    dorothy.add_argument("--structure", type=int, help="structure ID: Jenga pull block or Rings center")
    dorothy.add_argument("--slices", type=int, default=8, help="Stack slab count, 2-32")
    dorothy.add_argument("--depth", type=int, default=3, help="Rings descendant depth, 1-5")
    notebook = commands.add_parser("notebook", help="verify, save, or render a Zoe Bayesian field notebook")
    notebook.add_argument("input", nargs="?", help="saved notebook JSON; omit to use the worked GEM example")
    notebook.add_argument("--output", required=True, help="new .json, .svg, .png, or .gem output path")
    notebook.add_argument("--format", choices=("json", "svg", "png", "gem"), help="default: infer from output suffix")
    notebook.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")
    cognitive = commands.add_parser("cognitive", help="save, verify, or render Zoe's bounded Cognitive Field")
    cognitive.add_argument("input", nargs="?", help="saved Cognitive Field JSON; omit to use the worked example")
    cognitive.add_argument("--output", required=True, help="new .json, .svg, .png, or .gem output path")
    cognitive.add_argument("--format", choices=("json", "svg", "png", "gem"), help="default: infer from output suffix")
    cognitive.add_argument("--width", type=int, default=1400, help="SVG/PNG width in pixels")
    return parser


def _print_report(report):
    print(VerificationReport(report["scene_id"], report["results"]).text())


def main(argv=None):
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "qualia":
            import math
            from .qualia import accessible_sweep, accessible_q_toy, q_arrow_annotation, reconstruct_filtration
            toy = accessible_q_toy()
            thresholds = arguments.tau or [0.20, 0.30]
            toy["arrows"] = [q_arrow_annotation(toy["before"], toy["after"], tau) for tau in thresholds]
            for name in ("before", "after"):
                levels = [level["tau"] for level in toy[f"{name}_sweep"]] + thresholds
                toy[f"{name}_sweep"] = accessible_sweep(toy[name], levels)
            deltas = [row["delta_accessible_q_volume"] for row in toy["arrows"]]
            arithmetic_passed = (
                (thresholds != [0.20, 0.30] or (
                    deltas == [-1, 3]
                    and toy["arrows"][0]["exited"] == ["11"]
                    and toy["arrows"][1]["entered"] == ["00", "01", "10"]
                ))
                and all(
                    row["delta_accessible_q_volume"] == sum(p > row["tau"] for p in toy["after"].values()) - sum(p > row["tau"] for p in toy["before"].values())
                    and row["entered"] == sorted(state for state, probability in toy["after"].items() if probability > row["tau"] and toy["before"][state] <= row["tau"])
                    and row["exited"] == sorted(state for state, probability in toy["before"].items() if probability > row["tau"] and toy["after"][state] <= row["tau"])
                    and math.isclose(row["ei_bits"], math.log2(4 / 3))
                    for row in toy["arrows"]
                )
                and next(level for level in toy["after_sweep"] if level["tau"] == 1 / 3)["states"] == []
                and toy["two_way"]["past"]["accessible_q_volume"] == 3
                and toy["two_way"]["future"]["accessible_volume"] == 3
            )
            if not arithmetic_passed:
                raise RuntimeError("Accessible Q-Volume toy arithmetic did not match its checked contract")
            report = {
                "schema_version": 1,
                "instrument": "Accessible Q-Volume toy demonstration",
                "source": "Balduzzi & Tononi (2009), Qualia: The Geometry of Integrated Information",
                "original_equation_credit": "Nicholas Michael Kloster, March 6, 2026",
                "extension_status": "proposed formal construction; toy arithmetic verified, not an empirically validated IIT implementation",
                "complete_filtration_identity": "rho(z) = sup{tau : z is in QB_tau}, with sup(empty) = 0; this is the continuous labeled-filtration identity",
                "finite_sweep_is_approximate": True,
                "phi_computed": False,
                "gamma_calculator": False,
                "consciousness_measured": False,
                "checks": {"arithmetic": "passed", "strict_threshold_equality": "passed", "two_way_record": "passed"},
                "sampled_reconstruction": {name: reconstruct_filtration(toy[f"{name}_sweep"]) for name in ("before", "after")},
                "toy": toy,
            }
            output = Path(arguments.output)
            if output.suffix.lower() != ".json":
                raise ValueError("qualia evidence output must use .json")
            with output.open("x", encoding="utf-8") as handle:
                json.dump(report, handle, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
                handle.write("\n")
            print(json.dumps({"instrument": report["instrument"], "output": str(output), "bytes": output.stat().st_size, "deltas": deltas, "ei_bits": toy["arrows"][0]["ei_bits"], "checks": report["checks"]}, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if arguments.command == "cognitive":
            from .cognitive import CognitiveField, export_cognitive
            field = CognitiveField.load(arguments.input) if arguments.input else CognitiveField.demo()
            output, report = export_cognitive(field, arguments.output, arguments.format, arguments.width)
            print(json.dumps({"instrument": "Zoe Cognitive Field", "events": len(field.events), "active": len(field.working), "evicted": len(field.evicted), "declarative": len(field.declarative), "review_required": len(field.performance), "executed": False, "output": str(output), "bytes": output.stat().st_size, "verified": "verification" in report}, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if arguments.command == "notebook":
            from .field import FieldNotebook, field_scene
            notebook = FieldNotebook.load(arguments.input) if arguments.input else FieldNotebook.demo()
            output = Path(arguments.output)
            kind = arguments.format or output.suffix.lower().lstrip(".")
            if kind == "json":
                notebook.save(output)
            else:
                scene, _ = field_scene(notebook)
                if kind == "svg":
                    write_svg(scene, output, arguments.width)
                elif kind == "png":
                    write_png(scene, output, arguments.width)
                elif kind == "gem":
                    write_metafile(scene, output)
                else:
                    raise ValueError("notebook output format must be json, svg, png, or gem")
            print(json.dumps({"instrument": "Zoe Bayesian field notebook", "events": len(notebook.events), "questions": len(notebook.questions), "claims": len(notebook.claims), "measurements": len(notebook.measurements), "output": str(output), "bytes": output.stat().st_size}, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if arguments.command == "dorothy":
            from . import dorothy_data
            from .dorothy import dorothy_scene
            if arguments.data_root:
                os.environ["DOROTHY_CCF_ROOT"] = str(arguments.data_root)
            if arguments.fetch:
                ids = dorothy_data.parse_structure_ids(arguments.structures) if arguments.structures else dorothy_data.DEFAULT_STRUCTURE_IDS
                manifest = dorothy_data.fetch(arguments.data_root, ids)
                print(json.dumps({
                    "atlas": manifest["atlas"],
                    "citation": manifest["citation"],
                    "root": str(dorothy_data.default_root()),
                    "structures": [{"id": record["id"], "acronym": record["acronym"], "bytes": record["bytes"], "sha256": record["sha256"]} for record in manifest["structures"]],
                }, ensure_ascii=False, indent=2, sort_keys=True))
                return 0
            if not arguments.output:
                from .atlas_view import launch_atlas
                launch_atlas("dorothy" if arguments.view == "brain" else f"dorothy-{arguments.view}")
                return 0
            if arguments.view == "jenga":
                from .dorothy_jenga import default_jenga_document
                scene, report = default_jenga_document(
                    arguments.data_root, layout=arguments.layout, selected=arguments.structure,
                    yaw=arguments.yaw, pitch=arguments.pitch, fov=arguments.fov,
                )
            elif arguments.view == "stack":
                from .dorothy_stack import default_stack_document
                scene, report = default_stack_document(
                    arguments.data_root, slices=arguments.slices,
                    yaw=arguments.yaw, pitch=arguments.pitch, fov=arguments.fov,
                )
            elif arguments.view == "rings":
                from .dorothy_rings import default_rings_document
                scene, report = default_rings_document(
                    arguments.data_root, center=arguments.structure or 997, max_depth=arguments.depth,
                )
            else:
                records = dorothy_data.load_structures(arguments.data_root, arguments.structures)
                scene, report = dorothy_scene(
                    records, yaw=215.0 if arguments.yaw is None else arguments.yaw,
                    pitch=-18.0 if arguments.pitch is None else arguments.pitch,
                    distance=arguments.distance, fov=arguments.fov, shade_levels=arguments.shade_levels,
                )
            output = Path(arguments.output)
            kind = arguments.format or output.suffix.lower().lstrip(".")
            if kind == "svg":
                write_svg(scene, output, arguments.width)
            elif kind == "png":
                write_png(scene, output, arguments.width)
            elif kind == "gem":
                write_metafile(scene, output)
            else:
                raise ValueError("Dorothy output format must be svg, png, or gem")
            print(json.dumps({"module": "dorothy", "output": str(output), "bytes": output.stat().st_size, "measurement": report}, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if arguments.command in {"atlas", "master", "brain", "zoe"}:
            research_root = getattr(arguments, "research_root", None) or os.environ.get("MASTER_GEM_RESEARCH_ROOT")
            if arguments.output:
                from .atlas import default_document
                scene, report = default_document(arguments.module, research_root=research_root)
                output = Path(arguments.output)
                kind = arguments.format or output.suffix.lower().lstrip(".")
                if kind == "svg":
                    write_svg(scene, output, arguments.width)
                elif kind == "png":
                    write_png(scene, output, arguments.width)
                elif kind == "gem":
                    write_metafile(scene, output)
                else:
                    raise ValueError("atlas output format must be svg, png, or gem")
                print(json.dumps({"module": arguments.module, "output": str(output), "bytes": output.stat().st_size, "measurement": report}, ensure_ascii=False, indent=2, sort_keys=True))
            else:
                from .atlas_view import launch_atlas
                launch_atlas(arguments.module, research_root=research_root)
            return 0
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
    except (OSError, ImportError, RuntimeError, ValueError) as error:
        print(f"gem: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
