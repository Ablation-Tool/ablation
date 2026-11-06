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


def _parser():
    parser = argparse.ArgumentParser(
        prog="gem",
        description="GEM (Graphics Environment Manager): Lab, Spatial IR, VDI, and deterministic verification",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    os_command = commands.add_parser("os", help="open the mirrored GEM brain, manual library, or field notebook")
    os_command.add_argument("--module", choices=("mirror", "library", "field"), default="mirror")
    os_command.add_argument("--output", help="export the default scene to .svg, .png, or .gem instead of opening GTK")
    os_command.add_argument("--format", choices=("svg", "png", "gem"), help="default: infer from output suffix")
    os_command.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")

    workbench = commands.add_parser("workbench", help="list, run, and verify the unified GEM mathematical catalog")
    workbench_commands = workbench.add_subparsers(dest="workbench_command", required=True)
    workbench_commands.add_parser("list", help="list every equation and its evidence boundary")
    workbench_run = workbench_commands.add_parser("run", help="evaluate an equation with a JSON object of named inputs")
    workbench_run.add_argument("equation", help="equation identifier from workbench list")
    workbench_run.add_argument("--input", required=True, help="JSON object containing equation inputs")
    workbench_run.add_argument("--output", help="new JSON output path; omit to print the result")
    workbench_check = workbench_commands.add_parser("check", help="verify every registered algorithm against independent expected results")
    workbench_check.add_argument("--output", help="new JSON evidence path; omit to print the full report")

    library = commands.add_parser("library", help="index and search local GEM manuals without executing their content")
    library_commands = library.add_subparsers(dest="library_command", required=True)
    library_index = library_commands.add_parser("index", help="build a new local full-text index")
    library_index.add_argument("--root", action="append", required=True, help="manual file or directory; repeat for multiple roots")
    library_index.add_argument("--database", required=True, help="new SQLite index path; existing files are not overwritten")
    library_stats = library_commands.add_parser("stats", help="show index coverage and extraction limits")
    library_stats.add_argument("--database", required=True)
    library_search = library_commands.add_parser("search", help="search indexed manual pages")
    library_search.add_argument("--database", required=True)
    library_search.add_argument("--query", required=True)
    library_search.add_argument("--limit", type=int, default=8)
    library_open = library_commands.add_parser("open", help="open a source document with the desktop opener")
    library_open.add_argument("--database", required=True)
    library_open.add_argument("--document", required=True)

    notebook = commands.add_parser("notebook", help="verify, save, or render the GEM Bayesian field notebook")
    notebook.add_argument("input", nargs="?", help="saved notebook JSON; omit to use the worked GEM example")
    notebook.add_argument("--output", required=True, help="new .json, .svg, .png, or .gem output path")
    notebook.add_argument("--format", choices=("json", "svg", "png", "gem"), help="default: infer from output suffix")
    notebook.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")

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

    hourglass = commands.add_parser("hourglass", help="export Zoe's GEM/Artline Accessible Q-Volume hourglass")
    hourglass.add_argument("--output", required=True, help="output artifact path")
    hourglass.add_argument("--format", choices=("svg", "png", "gem"), help="default: infer from output suffix")
    hourglass.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")

    eye = commands.add_parser("eye", help="inspect synthetic stereo depth, parallax, and depth of field")
    eye.add_argument("--focus", type=float, default=1.6, help="focus distance in meters, 0.5-10")
    eye.add_argument("--aperture", type=float, default=4.0, help="f-number, 1-64")
    eye.add_argument("--baseline", type=float, default=.065, help="stereo baseline in meters, 0.02-0.25")
    eye.add_argument("--output", help="export .json, .svg, .png, or .gem instead of opening the native instrument")
    eye.add_argument("--format", choices=("json", "svg", "png", "gem"), help="default: infer from output suffix")
    eye.add_argument("--width", type=int, default=1920, help="SVG/PNG width in pixels")

    halo = commands.add_parser("halo", help="compare independent pose searches from two synthetic projections")
    halo.add_argument("--metric", choices=("both", "l2", "walsh"), default="both", help="similarity metric; never averaged")
    halo.add_argument("--angle", type=float, default=65, help="parallax view angle in degrees, 1-89")
    halo.add_argument("--noise", type=float, default=0.0, help="observation noise standard deviation, 0-0.05")
    halo.add_argument("--seed", type=int, default=7, help="deterministic seed, 0-999999")
    halo.add_argument("--output", help="export .json, .svg, .png, or .gem instead of opening the native instrument")
    halo.add_argument("--format", choices=("json", "svg", "png", "gem"), help="default: infer from output suffix")
    halo.add_argument("--width", type=int, default=1920, help="SVG/PNG width in pixels")

    tetris = commands.add_parser("tetris", help="play and measure a bounded deterministic Tetris probability field")
    tetris.add_argument("--seed", type=int, default=7, help="deterministic unsigned 64-bit seed")
    tetris.add_argument("--randomizer", choices=("bag", "uniform"), default="bag", help="piece distribution model")
    tetris.add_argument("--horizon", type=int, default=1, choices=(1, 2, 3), help="joint outcome horizon, 1-3 pieces")
    tetris.add_argument("--output", help="export .json, .svg, .png, or .gem instead of opening the native instrument")
    tetris.add_argument("--format", choices=("json", "svg", "png", "gem"), help="default: infer from output suffix")
    tetris.add_argument("--width", type=int, default=1920, help="SVG/PNG width in pixels")

    feed = commands.add_parser("feed", help="evaluate simple black-box models of binary like/not-like observations")
    feed.add_argument("input", help="chronological JSON booleans or objects with outcome like/not_like")
    feed.add_argument("--alpha", type=float, default=.5, help="symmetric Dirichlet smoothing strength, greater than zero")
    feed.add_argument("--train", type=int, default=24, help="initial chronological training observations, at least 8")
    feed.add_argument("--test", type=int, default=8, help="observations per later held-out window, at least 1")
    feed.add_argument("--output", help="new JSON evidence path; existing files are not overwritten")

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

    lab = commands.add_parser("lab", help="open GEM Lab as an application inside the GEM environment")
    lab.add_argument("target", help="binary file or material directory")
    lab.add_argument("--session", required=True, help="investigation session directory")
    lab.add_argument("--workspace", help="embedded agent working directory")
    lab.add_argument("--toolkit", choices=("auto", "gtk", "tk"), default="auto")
    agents = lab.add_mutually_exclusive_group()
    agents.add_argument("--agent", help="interactive agent executable")
    agents.add_argument("--agent-command", help="complete interactive agent command")
    agents.add_argument("--no-agent", action="store_true", help="open the Lab without an embedded agent")

    state = commands.add_parser("lab-state", help="inspect unified investigation and derived spatial objects")
    state.add_argument("--session", required=True, help="investigation session directory")

    predict = commands.add_parser("predict", help="measure next-token accessible volume for the selected Lab context")
    predict.add_argument("--session", required=True, help="investigation session directory")
    predict.add_argument("--model-dir", help="local distilgpt2 model cache (default: per-user GEM data directory)")
    predict.add_argument("--thresholds", default="0.02,0.05,0.10,0.15,0.30,0.50", help="comma-separated probability thresholds")
    predict.add_argument("--actual-token-id", type=int, help="optional observed token for correctness and calibration scoring")
    predict.add_argument("--json", action="store_true", help="print the complete measurement report")

    steer = commands.add_parser("steer", help="recommend a cautious next action from the current prediction and its trend")
    steer.add_argument("--session", required=True, help="investigation session directory")
    steer.add_argument("--model-dir", help="local distilgpt2 model cache (default: per-user GEM data directory)")
    steer.add_argument("--thresholds", default="0.02,0.05,0.10,0.15,0.30,0.50", help="comma-separated probability thresholds")
    steer.add_argument("--json", action="store_true", help="print the complete measurement and advisory report")

    volume = commands.add_parser("volume", help="measure and feed back a saved full-vocabulary NPZ distribution")
    volume.add_argument("distribution", help="NPZ containing probabilities and optional input_ids")
    volume.add_argument("--session", help="optional investigation session for separate evidence")
    volume.add_argument("--previous", help="earlier NPZ distribution; default: latest feedback artifact when available")
    volume.add_argument("--key", default="probabilities", help="NPZ key for the current distribution")
    volume.add_argument("--previous-key", help="NPZ key for the earlier distribution; default: current key")
    volume.add_argument("--thresholds", default="0.02,0.05,0.10,0.15,0.30,0.50", help="comma-separated probability thresholds")
    volume.add_argument("--min-volume", type=int, default=1, help="target volume lower bound")
    volume.add_argument("--max-volume", type=int, default=4, help="target volume upper bound")
    volume.add_argument("--actual-token-id", type=int, help="optional observed token for correctness and calibration scoring")
    volume.add_argument("--horizon", type=int, default=1, help="number of tokens in each joint continuation (default: 1)")
    volume.add_argument("--vocabulary-size", type=int, help="token vocabulary size for a flat joint distribution")
    volume.add_argument("--model-id", help="model identifier override for research artifacts")
    volume.add_argument("--output", help="additional new JSON report path; existing files are never overwritten")
    volume.add_argument("--json", action="store_true", help="print the complete measurement and advisory report")

    tournament = commands.add_parser("tournament", help="attack fixed and adaptive equations plus context variants without changing policy")
    tournament.add_argument("--session", required=True, help="investigation session directory")
    tournament.add_argument("--model-dir", help="local distilgpt2 model cache (default: per-user GEM data directory)")
    tournament.add_argument("--thresholds", default="0.02,0.05,0.10,0.15,0.30,0.50", help="comma-separated probability thresholds")
    tournament.add_argument("--json", action="store_true", help="print the complete tournament report")

    landmarks = commands.add_parser("landmarks", help="fit a Procrustes similarity and export replayable landmark evidence")
    landmarks.add_argument("correspondences", help="JSON document containing a correspondences array")
    landmarks.add_argument("--session", required=True, help="investigation session directory")
    landmarks.add_argument("--allow-reflection", action="store_true", help="permit orientation-reversing orthogonal alignment")
    landmarks.add_argument("--json", action="store_true", help="print the complete alignment report")

    guard = commands.add_parser("guard", help="bind a forecast to a proposal, then review or explicitly approve it")
    guard.add_argument("proposal", help="JSON proposal containing a supported command")
    guard.add_argument("--action-id", required=True, help="unique bounded action identifier")
    guard.add_argument("--session", required=True, help="investigation session directory")
    guard.add_argument("--distribution", help="optional NPZ forecast; default: live local model prediction")
    guard.add_argument("--key", default="probabilities", help="NPZ key for the forecast distribution")
    guard.add_argument("--model-dir", help="local distilgpt2 model cache for live prediction")
    guard.add_argument("--thresholds", default="0.02,0.05,0.10,0.15,0.30,0.50", help="comma-separated probability thresholds")
    guard.add_argument("--horizon", type=int, default=1, help="joint forecast horizon (default: 1)")
    guard.add_argument("--vocabulary-size", type=int, help="token vocabulary size for a flat joint distribution")
    guard.add_argument("--model-id", help="model identifier override for research artifacts")
    guard.add_argument("--approve", action="store_true", help="execute a valid proposal; without this flag it is review-only")
    guard.add_argument("--json", action="store_true", help="print the complete guard report")

    generate = commands.add_parser("generate", help="generate hypotheses and review every proposal without executing them")
    generate.add_argument("--session", required=True, help="investigation session directory")
    generate.add_argument("--distribution", help="optional NPZ forecast; default: live local model prediction")
    generate.add_argument("--key", default="probabilities", help="NPZ key for the forecast distribution")
    generate.add_argument("--model-dir", help="local distilgpt2 model cache for live prediction")
    generate.add_argument("--thresholds", default="0.02,0.05,0.10,0.15,0.30,0.50", help="comma-separated probability thresholds")
    generate.add_argument("--horizon", type=int, default=1, help="joint forecast horizon (default: 1)")
    generate.add_argument("--vocabulary-size", type=int, help="token vocabulary size for a flat joint distribution")
    generate.add_argument("--model-id", help="model identifier override for research artifacts")
    generate.add_argument("--generator-command", help="external JSON generator; {prompt} is replaced or prompt uses stdin")
    generate.add_argument("--count", type=int, default=4, help="maximum hypotheses to generate, from 1 to 8")
    generate.add_argument("--timeout", type=float, default=120, help="external generator timeout in seconds")
    generate.add_argument("--json", action="store_true", help="print the complete generation report")

    calibrate = commands.add_parser("calibrate", help="evaluate confidence and correctness from labeled forecast reports")
    calibrate.add_argument("reports", nargs="+", help="measurement JSON reports containing outcome objects")
    calibrate.add_argument("--bins", type=int, default=10, help="calibration bin count from 1 to 100")
    calibrate.add_argument("--output", help="new calibration JSON path; existing files are never overwritten")
    calibrate.add_argument("--json", action="store_true", help="print the complete calibration report")

    estimate = commands.add_parser("estimate", help="apply an explicit linear state-space model to observations")
    estimate.add_argument("model", help="JSON state-space model and observations")
    estimate.add_argument("--output", help="new estimation JSON path; existing files are never overwritten")
    estimate.add_argument("--json", action="store_true", help="print the complete estimation report")

    launch = commands.add_parser("launch", help="open GEM and choose a target inside the application")
    launch.add_argument("--toolkit", choices=("auto", "gtk", "tk"), default="auto")
    launch_agents = launch.add_mutually_exclusive_group()
    launch_agents.add_argument("--agent", help="interactive agent executable")
    launch_agents.add_argument("--agent-command", help="complete interactive agent command")
    launch_agents.add_argument("--no-agent", action="store_true")

    for name in ("state", "tree", "begin", "emit", "emit-many", "review"):
        command = commands.add_parser(name, help=f"{name} investigation state through the shared Lab protocol")
        command.add_argument("--session", default="gem-session")

    tree = commands.choices["tree"]
    tree.add_argument("--json", action="store_true")
    begin = commands.choices["begin"]
    begin.add_argument("--expected-id", required=True)
    begin.add_argument("--expected-revision", required=True, type=int)
    begin.add_argument("--note")
    emit = commands.choices["emit"]
    emit.add_argument("--id", required=True)
    emit.add_argument("--parent")
    emit.add_argument("--type", required=True, choices=("artifact", "function", "evidence", "observation", "hypothesis", "finding", "note"))
    emit.add_argument("--label", required=True)
    emit.add_argument("--status", default="not_started", choices=("not_started", "in_progress", "partial", "blocked", "reviewed", "complete_scoped", "rejected", "not_applicable"))
    emit.add_argument("--source", default="agent", choices=("system", "agent", "tool", "human"))
    emit.add_argument("--evidence", default="")
    emit.add_argument("--note", default="")
    emit.add_argument("--scope")
    commands.choices["emit-many"].add_argument("--file", required=True)
    review = commands.choices["review"]
    review.add_argument("id")
    review.add_argument("--status", required=True, choices=("partial", "blocked", "reviewed", "rejected"))
    review.add_argument("--note")
    return parser


def _print_report(report):
    print(VerificationReport(report["scene_id"], report["results"]).text())


def _measure_from_arguments(host, session, arguments):
    if arguments.distribution:
        from .volume import VolumeBridge

        return VolumeBridge(session).observe(
            arguments.distribution,
            thresholds=arguments.thresholds,
            key=arguments.key,
            horizon=arguments.horizon,
            vocabulary_size=arguments.vocabulary_size,
            model_id=arguments.model_id,
        ).report
    return host.measure_prediction(
        model_dir=arguments.model_dir, thresholds=arguments.thresholds,
    ).report


def _emit_json(document, output=None):
    text = json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(text, end="")
        return None
    path = Path(output)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(text)
    return path


def main(argv=None):
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "eye":
            from .eye import EyeModel, eye_scene
            model = EyeModel(focus=arguments.focus, fstop=arguments.aperture, baseline=arguments.baseline)
            scene, report = eye_scene(model)
            if not arguments.output:
                from .eye_view import launch_eye
                launch_eye(model)
                return 0
            output = Path(arguments.output)
            kind = arguments.format or output.suffix.lower().lstrip(".")
            if kind == "json":
                _emit_json(report, output)
            elif kind == "svg":
                write_svg(scene, output, arguments.width)
            elif kind == "png":
                write_png(scene, output, arguments.width)
            elif kind == "gem":
                write_metafile(scene, output)
            else:
                raise ValueError("eye output format must be json, svg, png, or gem")
            _emit_json({"instrument": report["instrument"], "output": str(output), "bytes": output.stat().st_size, "summary": report["summary"], "actual_camera_used": False, "executed": False})
            return 0
        if arguments.command == "halo":
            from .halo import experiment, halo_scene
            report = experiment(metric=arguments.metric, view_angle=arguments.angle, noise=arguments.noise, seed=arguments.seed)
            if not arguments.output:
                from .halo_view import launch_halo
                launch_halo(metric=arguments.metric, view_angle=arguments.angle, noise=arguments.noise, seed=arguments.seed)
                return 0
            scene, _ = halo_scene(report)
            output = Path(arguments.output)
            kind = arguments.format or output.suffix.lower().lstrip(".")
            if kind == "json":
                _emit_json(report, output)
            elif kind == "svg":
                write_svg(scene, output, arguments.width)
            elif kind == "png":
                write_png(scene, output, arguments.width)
            elif kind == "gem":
                write_metafile(scene, output)
            else:
                raise ValueError("halo output format must be json, svg, png, or gem")
            _emit_json({"instrument": report["instrument"], "output": str(output), "bytes": output.stat().st_size, "summary": report["summary"], "autonomous_action": False})
            return 0
        if arguments.command == "tetris":
            from .tetris import TetrisGame, tetris_report, tetris_scene
            game = TetrisGame(seed=arguments.seed, randomizer=arguments.randomizer)
            if not arguments.output:
                from .tetris_view import launch_tetris
                launch_tetris(game)
                return 0
            report = tetris_report(game, horizon=arguments.horizon)
            scene, _ = tetris_scene(report)
            output = Path(arguments.output)
            kind = arguments.format or output.suffix.lower().lstrip(".")
            if kind == "json":
                _emit_json(report, output)
            elif kind == "svg":
                write_svg(scene, output, arguments.width)
            elif kind == "png":
                write_png(scene, output, arguments.width)
            elif kind == "gem":
                write_metafile(scene, output)
            else:
                raise ValueError("tetris output format must be json, svg, png, or gem")
            _emit_json({"instrument": report["instrument"], "output": str(output), "bytes": output.stat().st_size, "summary": report["summary"], "autonomous_action": False})
            return 0
        if arguments.command == "feed":
            from .cognition import unique_object
            from .feed import evaluate_feed
            source = Path(arguments.input).expanduser().resolve(strict=True)
            if source.stat().st_size > 1024 * 1024:
                raise ValueError("feed observation input exceeds the 1 MiB limit")
            events = json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
            report = evaluate_feed(events, alpha=arguments.alpha, trial_train=arguments.train, trial_test=arguments.test)
            _emit_json(report, arguments.output)
            return 0
        if arguments.command == "os":
            if arguments.output:
                from .mirror import os_document
                from os import environ
                scene, report = os_document(arguments.module, environ.get("GEM_LIBRARY"))
                output = Path(arguments.output)
                kind = arguments.format or output.suffix.lower().lstrip(".")
                if kind == "svg":
                    write_svg(scene, output, arguments.width)
                elif kind == "png":
                    write_png(scene, output, arguments.width)
                elif kind == "gem":
                    write_metafile(scene, output)
                else:
                    raise ValueError("os output format must be svg, png, or gem")
                _emit_json({"module": arguments.module, "output": str(output), "bytes": output.stat().st_size, "measurement": report})
            else:
                from .mirror_view import launch_os
                launch_os(arguments.module)
            return 0
        if arguments.command == "library":
            from .authorization import launch_explicit
            from .library import ManualLibrary
            from subprocess import DEVNULL
            if arguments.library_command == "index":
                library = ManualLibrary.index(arguments.root, arguments.database)
                _emit_json(library.summary())
                return 0
            library = ManualLibrary(arguments.database)
            if arguments.library_command == "stats":
                _emit_json(library.summary())
                return 0
            if arguments.library_command == "search":
                _emit_json({"query": arguments.query, "results": library.search(arguments.query, arguments.limit), "executed": False})
                return 0
            document = Path(arguments.document).expanduser()
            if not document.is_file() or document.is_symlink():
                raise ValueError("document must be an existing regular, non-symlink file")
            launch_explicit(["/usr/bin/xdg-open", str(document)], approved=True, stdout=DEVNULL, stderr=DEVNULL, start_new_session=True)
            _emit_json({"document": str(document), "opened": True, "approved_by": "explicit_user_action"})
            return 0
        if arguments.command == "workbench":
            from .workbench import Workbench
            workbench = Workbench()
            if arguments.workbench_command == "list":
                _emit_json({"algorithm_count": len(workbench.catalog()), "algorithms": workbench.catalog(), "executed": False})
                return 0
            if arguments.workbench_command == "check":
                report = workbench.verify()
                output = _emit_json(report, arguments.output)
                if output is not None:
                    print(json.dumps({"output": str(output), "algorithm_count": report["algorithm_count"], "passed": report["passed"], "failed": report["failed"]}, indent=2))
                return 0 if report["failed"] == 0 else 1
            inputs = json.loads(Path(arguments.input).read_text(encoding="utf-8"))
            if not isinstance(inputs, dict):
                raise ValueError("workbench input must be a JSON object of named arguments")
            outcome = workbench.evaluate(arguments.equation, **inputs)
            output = _emit_json(outcome, arguments.output)
            if output is not None:
                print(json.dumps({"equation": arguments.equation, "output": str(output), "executed": False}, indent=2))
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
            _emit_json({"instrument": "GEM Bayesian field notebook", "events": len(notebook.events), "questions": len(notebook.questions), "claims": len(notebook.claims), "measurements": len(notebook.measurements), "output": str(output), "bytes": output.stat().st_size})
            return 0
        if arguments.command == "volume":
            from gem.events import Session
            from .volume import VolumeBridge, write_report

            session = Session(arguments.session) if arguments.session else None
            result = VolumeBridge(session).observe(
                arguments.distribution,
                previous=arguments.previous,
                thresholds=arguments.thresholds,
                key=arguments.key,
                previous_key=arguments.previous_key,
                minimum=arguments.min_volume,
                maximum=arguments.max_volume,
                actual_token_id=arguments.actual_token_id,
                horizon=arguments.horizon,
                vocabulary_size=arguments.vocabulary_size,
                model_id=arguments.model_id,
            )
            if arguments.output:
                output = write_report(result.report, arguments.output)
                print(f"Report: {output}")
            if arguments.json:
                print(json.dumps(result.report, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                for measurement in result.report["threshold_sweep"]:
                    print(
                        f"τ={measurement['tau']:.2f} A(S)={measurement['accessible_volume']} "
                        f"complement={measurement['complement_volume']}"
                    )
                print(f"Advisory: {result.report['advisory']['label']}")
                if "outcome" in result.report:
                    outcome = result.report["outcome"]
                    print(f"Outcome: correct={outcome['correct']}; log_loss={outcome['log_loss']:.6f}")
                print(f"Run: {result.path}")
                if result.evidence is not None:
                    print(f"Evidence: {result.evidence['id']}")
            return 0
        if arguments.command == "calibrate":
            from .cognition import unique_object
            from .evaluation import calibration_metrics
            from .volume import write_report

            records = []
            for name in arguments.reports:
                path = Path(name).expanduser().resolve(strict=True)
                if path.stat().st_size > 1024 * 1024:
                    raise ValueError(f"calibration report exceeds the 1 MiB limit: {path}")
                document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
                if isinstance(document, list):
                    records.extend(document)
                elif isinstance(document, dict) and isinstance(document.get("results"), list):
                    records.extend(document["results"])
                elif isinstance(document, dict):
                    records.append(document)
                else:
                    raise ValueError(f"calibration input must be a report or a results array: {path}")
            report = calibration_metrics(records, bins=arguments.bins)
            if arguments.output:
                output = write_report(report, arguments.output)
                print(f"Report: {output}")
            if arguments.json:
                print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                print(f"Cases: {report['cases']}; accuracy={report['accuracy']:.6f}")
                print(f"Expected calibration error: {report['expected_calibration_error']:.6f}")
                print(f"AUROC correctness: {report['auroc_correctness']}")
                print(f"AUPRC correctness: {report['auprc_correctness']}")
            return 0
        if arguments.command == "estimate":
            from .cognition import unique_object
            from .estimation import linear_filter
            from .measurement import document_sha256
            from .volume import write_report

            model_path = Path(arguments.model).expanduser().resolve(strict=True)
            if model_path.stat().st_size > 1024 * 1024:
                raise ValueError("estimation model exceeds the 1 MiB limit")
            document = json.loads(model_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
            if not isinstance(document, dict):
                raise ValueError("estimation input must contain a state-space object")
            results = linear_filter(
                document["observations"],
                document["process_matrix"],
                document["process_covariance"],
                document["observation_matrix"],
                document["observation_covariance"],
                document["initial_state"],
                document["initial_covariance"],
                control_matrix=document.get("control_matrix"),
                controls=document.get("controls"),
            )
            report = {
                "schema_version": 1,
                "instrument": "explicit linear state-space estimation",
                "observation_count": len(results),
                "steps": results,
                "final_state": results[-1]["state"],
                "final_covariance": results[-1]["covariance"],
                "model_sha256": document_sha256(document),
                "scope": [
                    "The caller supplies the state-space model and covariances; GEM does not infer or validate system dynamics.",
                    "Filtering changes an estimate, not an action authorization or a correctness guarantee.",
                ],
            }
            if arguments.output:
                output = write_report(report, arguments.output)
                print(f"Report: {output}")
            if arguments.json:
                print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                print(f"Observations: {len(results)}")
                print(f"Final state: {report['final_state']}")
                print(f"Final covariance: {report['final_covariance']}")
            return 0
        if arguments.command == "generate":
            from gem.events import Session
            from .generation import AgentProposalGenerator
            from .host import GemLabHost

            session = Session(arguments.session)
            host = GemLabHost(session)
            measurement = _measure_from_arguments(host, session, arguments)
            generator = AgentProposalGenerator(
                arguments.generator_command, timeout=arguments.timeout,
            ) if arguments.generator_command else None
            result = host.generate_proposals(
                measurement, count=arguments.count, generator=generator,
            )
            report = result.report
            if arguments.json:
                print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                print(
                    f"Generated {len(report['candidates'])} candidates: "
                    f"{report['reviewable']} reviewable, {report['denied']} denied, "
                    f"{report['duplicates']} duplicates."
                )
                for candidate in report["candidates"]:
                    print(f"{candidate['action_id'] or 'duplicate'}: {candidate['status']} · {candidate['statement']}")
                print("No candidate was executed or marked as verified.")
                print(f"Run: {result.path}")
                print(f"Hypothesis: {result.evidence['id']}")
            return 0
        if arguments.command == "guard":
            from gem.events import Session
            from .cognition import unique_object
            from .host import GemLabHost

            proposal_path = Path(arguments.proposal).expanduser().resolve(strict=True)
            if proposal_path.stat().st_size > 1024 * 1024:
                raise ValueError("proposal JSON exceeds the 1 MiB limit")
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
            if not isinstance(proposal, dict):
                raise ValueError("proposal JSON must contain an object")
            session = Session(arguments.session)
            host = GemLabHost(session)
            measurement = _measure_from_arguments(host, session, arguments)
            result = host.review_proposal(
                proposal, measurement, arguments.action_id, approve=arguments.approve,
            )
            report = result.report
            if arguments.json:
                print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                print(f"Decision: {report['decision']}")
                print(f"Reason: {report['reason']}")
                print(f"Executed: {report['executed']}")
                print(f"Succeeded: {report['succeeded']}")
                print(f"Run: {result.path}")
                print(f"Evidence: {result.evidence['id']}")
            return 0 if report["decision"] == "review" or report["succeeded"] else 2
        if arguments.command == "landmarks":
            from gem.events import Session
            from .host import GemLabHost

            document = json.loads(Path(arguments.correspondences).read_text(encoding="utf-8"))
            pairs = document.get("correspondences") if isinstance(document, dict) else None
            if not isinstance(pairs, list):
                raise ValueError("correspondence JSON must contain a correspondences array")
            source = [pair["source"] for pair in pairs]
            target = [pair["target"] for pair in pairs]
            result = GemLabHost(Session(arguments.session)).align_landmarks(
                source, target, allow_reflection=arguments.allow_reflection,
            )
            if arguments.json:
                print(json.dumps(result.report, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                alignment = result.alignment
                print(f"Scale: {alignment.scale:.10f}")
                print(f"Angle: {alignment.angle_degrees:.6f}°")
                print(f"RMS: {alignment.rms:.6g}")
                print(f"Determinant: {alignment.determinant:.1f}")
                print(f"Run: {result.path}")
                print(f"Evidence: {result.evidence['id']}")
            return 0
        if arguments.command == "lab-state":
            from gem.events import Session
            from .host import GemLabHost

            snapshot = GemLabHost(Session(arguments.session)).snapshot()
            print(json.dumps(snapshot, indent=2, ensure_ascii=False, sort_keys=True))
            return 0
        if arguments.command == "predict":
            from gem.events import Session
            from .host import GemLabHost

            result = GemLabHost(Session(arguments.session)).measure_prediction(
                model_dir=arguments.model_dir, thresholds=arguments.thresholds,
                actual_token_id=arguments.actual_token_id,
            )
            if arguments.json:
                print(json.dumps(result.report, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                for measurement in result.report["threshold_sweep"]:
                    print(
                        f"τ={measurement['tau']:.2f} "
                        f"A(S)={measurement['accessible_volume']} "
                        f"normalized={measurement['normalized_accessible_volume']:.8f}"
                    )
            if not arguments.json:
                print(f"Run: {result.path}")
                print(f"Evidence: {result.evidence['id']}")
            return 0
        if arguments.command == "steer":
            from gem.events import Session
            from .host import GemLabHost

            result = GemLabHost(Session(arguments.session)).advise_next_action(
                model_dir=arguments.model_dir, thresholds=arguments.thresholds,
            )
            advisory = result.report["advisory"]
            if arguments.json:
                print(json.dumps(result.report, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                print(f"Advisory: {advisory['label']}")
                print(advisory["summary"])
                for reason in advisory["reasons"]:
                    print(f"Reason: {reason}")
                print("Allowed action categories: " + ", ".join(advisory["allowed_actions"]))
                print("Autonomous execution and permission escalation are not authorized.")
            if not arguments.json:
                print(f"Run: {result.path}")
                print(f"Evidence: {result.evidence['id']}")
            return 0
        if arguments.command == "tournament":
            from gem.events import Session
            from .host import GemLabHost

            result = GemLabHost(Session(arguments.session)).run_equation_tournament(
                model_dir=arguments.model_dir, thresholds=arguments.thresholds,
            )
            tournament = result.report["tournament"]
            if arguments.json:
                print(json.dumps(result.report, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                print(f"Equation tournament: {tournament['advisory_flip_count']} advisory flips")
                for variant in tournament["variants"]:
                    largest = variant["largest_disagreement"]
                    print(
                        f"{variant['name']}: fixed={variant['fixed_advisory_mode']} "
                        f"flips={variant['advisory_flip_count']} "
                        f"largest A(0.05) delta={largest['fixed_005_delta']} "
                        f"(alpha={largest['alpha']}, beta={largest['beta']})"
                    )
                print("Sensitivity only; no equation winner is inferred without verified outcomes.")
                print(f"Run: {result.path}")
                print(f"Evidence: {result.evidence['id']}")
            return 0
        if arguments.command == "lab":
            from gem.lab_cli import main as gem_main

            command = [
                "desktop", arguments.target, "--session", arguments.session,
                "--toolkit", arguments.toolkit,
            ]
            if arguments.workspace:
                command.extend(["--workspace", arguments.workspace])
            if arguments.agent_command:
                command.extend(["--agent-command", arguments.agent_command])
            elif arguments.agent:
                command.extend(["--agent", arguments.agent])
            elif arguments.no_agent:
                command.append("--no-agent")
            return gem_main(command)
        if arguments.command == "launch":
            from gem.lab_cli import main as gem_main

            command = ["launch", "--toolkit", arguments.toolkit]
            if arguments.agent_command:
                command.extend(["--agent-command", arguments.agent_command])
            elif arguments.agent:
                command.extend(["--agent", arguments.agent])
            elif arguments.no_agent:
                command.append("--no-agent")
            return gem_main(command)
        if arguments.command in {"state", "tree", "begin", "emit", "emit-many", "review"}:
            from gem.lab_cli import main as gem_main

            command = [arguments.command, "--session", arguments.session]
            if arguments.command == "tree" and arguments.json:
                command.append("--json")
            elif arguments.command == "begin":
                command.extend([
                    "--expected-id", arguments.expected_id,
                    "--expected-revision", str(arguments.expected_revision),
                ])
                if arguments.note is not None:
                    command.extend(["--note", arguments.note])
            elif arguments.command == "emit":
                command.extend(["--id", arguments.id, "--type", arguments.type, "--label", arguments.label])
                for name in ("parent", "status", "source", "evidence", "note", "scope"):
                    value = getattr(arguments, name)
                    if value is not None:
                        command.extend([f"--{name}", str(value)])
            elif arguments.command == "emit-many":
                command.extend(["--file", arguments.file])
            elif arguments.command == "review":
                command.extend([arguments.id, "--status", arguments.status])
                if arguments.note is not None:
                    command.extend(["--note", arguments.note])
            return gem_main(command)
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
        if arguments.command == "hourglass":
            from .hourglass import hourglass_scene

            scene, report = hourglass_scene()
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
            print(json.dumps({
                "module": "hourglass",
                "format": kind,
                "output": str(output),
                "bytes": output.stat().st_size,
                "measurement": report,
            }, indent=2, ensure_ascii=False, sort_keys=True))
            return 0
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
