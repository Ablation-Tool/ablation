import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig


ROOT = Path(__file__).resolve().parents[1]
ZOE_ROOT = ROOT / "zoe"


def test_ablation_is_the_zoe_host_component():
    sys.path.insert(0, str(ZOE_ROOT / "guiai-lab"))
    from guiai.gem.unified import ComponentRegistry

    registry = ComponentRegistry(ZOE_ROOT)
    for identifier in ("ablation", "gem-lab"):
        source = registry.source(identifier)
        assert source["mode"] == "host"
        assert source["path"] == ROOT
        assert source["available"] is True
    manifest = registry.manifest()
    assert manifest["identity"] == "ZOE is allgems"
    assert len(manifest["components"]) == 11
    assert all(row["source"]["source_present"] for row in manifest["components"])


def test_zoe_cli_uses_host_ablation_and_nested_sources():
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ZOE_ROOT / "guiai-lab")
    environment["ZOE_ROOT"] = str(ZOE_ROOT)
    environment["ZOE_PYTHON"] = sys.executable
    environment["ZOE_PYTHON_DEPENDENCIES"] = sysconfig.get_paths()["purelib"]
    result = subprocess.run(
        [sys.executable, "-m", "guiai.gem.unified_cli", "list"],
        cwd=ROOT, env=environment, check=True, capture_output=True, text=True,
    )
    rows = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(rows) == 11
    assert sum("host" in line for line in rows) == 2
    assert all("present" in line for line in rows)
    launch = subprocess.run(
        [sys.executable, "-m", "guiai.gem.unified_cli", "launch", "ablation", "--", "--help"],
        cwd=ROOT, env=environment, capture_output=True, text=True,
    )
    assert launch.returncode == 0, launch.stdout + launch.stderr
    assert "usage:" in launch.stdout
    source_record = json.loads((ZOE_ROOT / "ZOE-SOURCE.json").read_text(encoding="utf-8"))
    assert source_record["revision"] == "8ac90bb7364d27eb4814498c93a2b7c00ef109f6"
