from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .atlas import default_document
from .field import FieldNotebook, field_scene
from .render import write_png, write_svg
from .vdi import write_metafile


def parser():
    result = argparse.ArgumentParser(prog="brain-gem", description="Zoe Bayesian field notebook and chambered memory")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("field", "zoe", "master", "brain", "atlas"):
        command = commands.add_parser(name, help="open the native Bayesian field notebook or export a scene")
        command.add_argument("--module", default="field", choices=("field", "brain", "horizon", "research", "procrustes", "ellipses", "parabola", "circle", "clock", "graph", "volume", "onset"))
        command.add_argument("--research-root", help="optional next-token-predictability research repository")
        command.add_argument("--output", help="export the scene to .svg, .png, or .gem instead of opening GTK")
        command.add_argument("--format", choices=("svg", "png", "gem"), help="default: infer from output suffix")
        command.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")
    notebook = commands.add_parser("notebook", help="save, verify, or render unified notebook memory")
    notebook.add_argument("input", nargs="?", help="saved notebook JSON; omit for the worked GEM example")
    notebook.add_argument("--output", required=True, help="new .json, .svg, .png, or .gem output path")
    notebook.add_argument("--format", choices=("json", "svg", "png", "gem"), help="default: infer from output suffix")
    notebook.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")
    return result


def main(argv=None):
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "notebook":
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
        if arguments.output:
            scene, report = default_document(arguments.module, research_root=arguments.research_root)
            output = Path(arguments.output)
            kind = arguments.format or output.suffix.lower().lstrip(".")
            if kind == "svg":
                write_svg(scene, output, arguments.width)
            elif kind == "png":
                write_png(scene, output, arguments.width)
            elif kind == "gem":
                write_metafile(scene, output)
            else:
                raise ValueError("scene output format must be svg, png, or gem")
            print(json.dumps({"module": arguments.module, "output": str(output), "bytes": output.stat().st_size, "measurement": report}, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            from .atlas_view import launch_atlas
            launch_atlas(arguments.module, research_root=arguments.research_root)
        return 0
    except (OSError, ImportError, RuntimeError, ValueError) as error:
        print(f"brain-gem: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
