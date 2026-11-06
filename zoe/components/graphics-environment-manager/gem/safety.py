import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys

from .launcher import user_data_root


APT_GTK = "sudo apt install python3-venv python3-tk python3-gi python3-cairo python3-gi-cairo gir1.2-gtk-3.0 gir1.2-vte-2.91"


def command_text(arguments):
    if os.name != "nt":
        return shlex.join(arguments)
    quoted = []
    for argument in arguments:
        value = subprocess.list2cmdline([argument])
        if any(character in argument for character in "<>|&^") and not value.startswith('"'):
            value = f'"{value}"'
        quoted.append(value)
    return " ".join(quoted)


def safety_colors(light_background, palette="system", accent=None):
    if palette == "colorblind":
        if light_background:
            colors = {"pass": "#0072b2", "review": "#a94e00", "accent": "#6a51a3"}
        else:
            colors = {"pass": "#56b4e9", "review": "#e69f00", "accent": "#cc79a7"}
    elif palette == "high-contrast":
        if light_background:
            colors = {"pass": "#006400", "review": "#8b0000", "accent": "#000080"}
        else:
            colors = {"pass": "#00ff66", "review": "#ff6e6e", "accent": "#8ab4ff"}
    elif light_background:
        colors = {"pass": "#1a7f37", "review": "#9a6700", "accent": "#1867c0"}
    else:
        colors = {"pass": "#3fb950", "review": "#d29922", "accent": "#58a6ff"}
    if palette == "system" and accent:
        colors["accent"] = accent
    return colors


def evaluate_safety(agent_command=None):
    checks = []
    remediations = []

    def add(name, ok, detail, required=True, action=None, command=None):
        checks.append({"name": name, "ok": bool(ok), "required": required, "detail": detail})
        if not ok and action:
            remediations.append({"action": action, "command": command})

    supported = os.name == "nt" or sys.platform == "darwin" or sys.platform.startswith("linux")
    add("Operating system", supported, f"Detected {sys.platform}; supported targets are Linux, Windows, and macOS")
    python_ok = sys.version_info >= (3, 10) and (os.name != "nt" or sys.version_info[:2] == (3, 11))
    architecture_ok = os.name != "nt" or sys.maxsize > 2**32
    add(
        "Python runtime",
        python_ok and architecture_ok,
        f"Running Python {sys.version.split()[0]} ({sys.maxsize.bit_length() + 1}-bit); Linux/macOS require 3.10+, native Windows requires 3.11 x64",
        action="Install the supported Python runtime from https://www.python.org/downloads/ and reinstall GEM",
    )
    tkinter_ok = importlib.util.find_spec("tkinter") is not None
    add(
        "Tkinter",
        tkinter_ok,
        "Tkinter is available" if tkinter_ok else "Tkinter is missing",
        action="Install a Python distribution with Tkinter support",
        command=APT_GTK if sys.platform.startswith("linux") else None,
    )
    for module, requirement in (("pyte", "pyte>=0.8.1,<1"), ("tkinterdnd2", "tkinterdnd2==0.7.0")):
        available = importlib.util.find_spec(module) is not None
        add(
            module,
            available,
            f"{module} is available" if available else f"{module} is missing; embedded terminal/drop support is incomplete",
            action=f"Install the declared dependency {requirement}",
            command=command_text([sys.executable, "-m", "pip", "install", requirement]),
        )
    if os.name == "nt":
        terminal_ok = importlib.util.find_spec("winpty") is not None
        terminal_detail = "pywinpty ConPTY support is available" if terminal_ok else "pywinpty is missing"
        terminal_requirement = "pywinpty>=2,<3"
    else:
        terminal_ok = importlib.util.find_spec("pty") is not None
        terminal_detail = "POSIX PTY support is available" if terminal_ok else "POSIX PTY support is missing"
        terminal_requirement = None
    add(
        "Embedded terminal",
        terminal_ok,
        terminal_detail,
        action="Install the platform terminal dependency" if terminal_requirement else "Repair the Python platform runtime",
        command=command_text([sys.executable, "-m", "pip", "install", terminal_requirement]) if terminal_requirement else None,
    )
    if sys.platform.startswith("linux"):
        try:
            import gi
            gi.require_version("Gtk", "3.0")
            gi.require_version("Vte", "2.91")
            from gi.repository import Gtk, Vte
            import gi._gi_cairo
            gtk_ok = all((Gtk, Vte, gi._gi_cairo))
        except (ImportError, ValueError) as error:
            gtk_ok = False
            gtk_error = str(error)
        else:
            gtk_error = "GTK, VTE, and Cairo are available"
        add(
            "Native Linux GTK/VTE",
            gtk_ok,
            gtk_error,
            required=False,
            action="Install native GTK/VTE dependencies, or explicitly use --toolkit tk",
            command=APT_GTK,
        )
    if agent_command:
        executable = agent_command[0]
        agent_path = shutil.which(executable)
        add(
            "AI agent",
            agent_path is not None,
            f"Agent executable resolved: {agent_path}" if agent_path else f"Agent executable was not found: {executable}",
            action="Install or authenticate the intended AI agent separately; do not substitute another agent",
        )
    else:
        checks.append({"name": "AI agent", "ok": True, "required": False, "detail": "No embedded AI agent is configured; local audit remains available"})
    data_root = user_data_root()
    existing = data_root
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    writable = existing.is_dir() and os.access(existing, os.W_OK)
    add("GEM data directory", writable, f"{data_root} (nearest existing directory: {existing})")

    blocking = [check for check in checks if check["required"] and not check["ok"]]
    advisory = [check for check in checks if not check["required"] and not check["ok"]]
    if blocking:
        summary = f"{len(blocking)} required item{'s' if len(blocking) != 1 else ''} need attention"
    elif advisory:
        summary = "Required checks passed; optional native GTK/VTE support needs attention"
    else:
        summary = "Safety Check + OS Compliance passed"
    details = "\n".join(
        f"[{'PASS' if check['ok'] else 'REVIEW'}] {check['name']}: {check['detail']}" for check in checks
    )
    if remediations:
        details += "\n\nProposed actions (no action has been taken):\n" + "\n".join(
            f"- {item['action']}" + (f"\n  {item['command']}" if item["command"] else "") for item in remediations
        )
    return {
        "checks": checks,
        "details": details,
        "remediations": remediations,
        "summary": summary,
        "ready": not blocking,
    }


def agent_request(report, domain="Safety Check + OS Compliance"):
    if report["remediations"]:
        instruction = (
            "The user clicked Allow Permission for only the exact remediation actions in this report. "
            "Restate them, then run each listed command at most once in the embedded terminal and report the results. "
            "Do not substitute commands, broaden scope, or perform additional downloads, installs, privilege changes, "
            "or configuration changes without a new explicit user confirmation. Actions without a command require user guidance only."
        )
    else:
        instruction = (
            "The user authorized only a read-only AI review of this report. Explain any findings. Do not install, "
            "download, change permissions or configuration, or execute investigation artifacts."
        )
    return f"{domain} requested by the user. " + json.dumps(
        {"instruction": instruction, "audit": report}, ensure_ascii=True, separators=(",", ":"),
    )
