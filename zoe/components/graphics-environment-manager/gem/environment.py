import os
from pathlib import Path
import shlex
import subprocess
import sys


def configure_environment(session):
    values = {
        "SESSION": str(session.root),
        "STATE": str(session.state_path),
        "EVENTS": str(session.events_path),
        "TARGET": session.target,
        "TARGET_KIND": session.target_kind,
        "ROOT_ID": session.root_id,
    }
    os.environ.update({f"GEM_{key}": value for key, value in values.items()})
    os.environ.update({
        "GEM_CLI": str(session.cli_path),
        "ABLATION_CLI": os.environ.get("ABLATION_CLI", "ablation"),
    })
    if session.target_kind == "file":
        os.environ["ABLATION_BINARY"] = session.target
    else:
        os.environ.pop("ABLATION_BINARY", None)
    path = os.environ.get("PATH", "")
    for directory in (str(Path(sys.executable).parent), str(session.cli_path.parent)):
        if directory not in path.split(os.pathsep):
            path = directory + (os.pathsep + path if path else "")
    os.environ["PATH"] = path


def agent_environment(session, workspace, metrix_root):
    configure_environment(session)
    os.environ["GEM_WORKSPACE"] = str(workspace)
    environment = os.environ.copy()
    package_root = str(Path(metrix_root).resolve())
    environment.update({
        "TERM": "xterm-256color",
        "COLORTERM": "truecolor",
        "METRIX_OUTPUT": str(session.root),
        "METRIX_WORKSPACE": str(workspace),
        "METRIX_CLI": subprocess.list2cmdline([sys.executable, "-m", "metrix"]) if os.name == "nt" else shlex.join([sys.executable, "-m", "metrix"]),
        "PYTHONPATH": package_root + (os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""),
    })
    return [f"{key}={value}" for key, value in environment.items()]
