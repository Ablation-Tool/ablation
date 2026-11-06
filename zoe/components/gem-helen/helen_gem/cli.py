from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .core import MODULES, default_document
from .render import write_png, write_scene_json, write_svg


def parser():
    result = argparse.ArgumentParser(prog="gem-helen", description="GEM HELEN: optimized native geometry and forecast laboratory")
    result.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    result.add_argument("--module", choices=tuple(MODULES), default="procrustes")
    result.add_argument("--output", help="export the default scene to .svg, .png, or .json instead of opening GTK")
    result.add_argument("--format", choices=("svg", "png", "json"), help="default: infer from output suffix")
    result.add_argument("--width", type=int, default=1200, help="SVG/PNG width in pixels")
    return result


def main(argv=None):
    arguments = parser().parse_args(argv)
    try:
        if arguments.output:
            scene, report = default_document(arguments.module)
            output = Path(arguments.output).expanduser().resolve()
            if output.exists():
                raise FileExistsError(f"output already exists: {output}")
            kind = arguments.format or output.suffix.lower().lstrip(".")
            if kind == "svg":
                write_svg(scene, output, arguments.width)
            elif kind == "png":
                write_png(scene, output, arguments.width)
            elif kind == "json":
                write_scene_json(scene, output)
            else:
                raise ValueError("output format must be svg, png, or json")
            print(json.dumps({"application": "GEM HELEN", "module": arguments.module, "scene_digest": scene.digest(), "output": str(output), "bytes": output.stat().st_size, "measurement": report}, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        from .ui import launch_helen
        launch_helen(arguments.module)
        return 0
    except (OSError, ImportError, RuntimeError, ValueError) as error:
        print(f"gem-helen: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
