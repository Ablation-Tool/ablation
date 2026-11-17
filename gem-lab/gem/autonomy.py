from __future__ import annotations

import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv) or ["run"]
    workspace = ROOT.parent
    zoe_root = Path(os.environ.get("ZOE_ROOT", workspace / "zoe")).expanduser().resolve()
    engine_root = Path(os.environ.get("ZOE_AUTONOMY_ROOT", workspace / "Zoe-Autonomy")).expanduser().resolve()
    source = engine_root / "src"
    if not (zoe_root / "guiai-lab").is_dir() or not (source / "zoe_autonomy" / "cli.py").is_file():
        raise ValueError("Zoe One requires Zoe and Zoe-Autonomy checkouts or ZOE_ROOT and ZOE_AUTONOMY_ROOT")
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    os.environ["ZOE_ROOT"] = str(zoe_root)
    if "--zoe-root" not in arguments:
        arguments = ["--zoe-root", str(zoe_root), *arguments]
    native = zoe_root / "guiai-lab"
    if str(native) not in sys.path:
        sys.path.insert(0, str(native))
    from zoe_autonomy.cli import main as autonomy_main

    return autonomy_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
