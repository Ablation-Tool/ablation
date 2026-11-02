#!/bin/bash
set -euo pipefail

SOURCE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c 'import sys; assert sys.version_info >= (3, 10); import tkinter' 2>/dev/null; then
    echo "Python 3.10 or newer with Tkinter is required. Install your distribution's Python and Tk packages, then retry." >&2
    exit 1
fi

cd "$SOURCE"
"$PYTHON" -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install --no-index --find-links "$SOURCE/vendor" "$SOURCE/guiai_lab-0.1.0-py3-none-any.whl"
python -m guiai --help >/dev/null

if [[ "${SKIP_TESTS:-0}" != "1" && -f "$SOURCE/native_stress.py" ]]; then
    python "$SOURCE/native_stress.py"
fi

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
APPLICATIONS="$DATA_HOME/applications"
ICON_DIRECTORY="$DATA_HOME/icons/hicolor/512x512/apps"
DESKTOP_ENTRY="$APPLICATIONS/re.guiai.workbench.desktop"
install -d "$APPLICATIONS" "$ICON_DIRECTORY"
install -m 0644 "$SOURCE/ablation-guiai-logo.png" "$ICON_DIRECTORY/ablation-guiai.png"
export SOURCE APPLICATIONS
python - <<'PY'
import os
from pathlib import Path
import tempfile

package_source = Path(os.environ["SOURCE"])
install_source = Path(os.environ.get("GUIAI_INSTALL_DESTINATION", package_source))
applications = Path(os.environ["APPLICATIONS"])
executable = str(install_source / ".venv" / "bin" / "guiai")
if "\n" in executable or "\r" in executable:
    raise ValueError("The installation path contains an unsupported line break")
quoted = '"' + executable.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$") + '"'
template = (package_source / "re.guiai.workbench.desktop.in").read_text(encoding="utf-8")
if template.count("@GUIAI_EXECUTABLE@") != 1:
    raise ValueError("The desktop-entry template is invalid")
contents = template.replace("@GUIAI_EXECUTABLE@", quoted)
descriptor, temporary = tempfile.mkstemp(prefix=".ablation-", dir=applications)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, applications / "re.guiai.workbench.desktop")
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$DESKTOP_ENTRY"
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPLICATIONS"
fi

if [[ "${NO_DESKTOP_SHORTCUT:-0}" != "1" ]]; then
    DESKTOP_DIR=""
    if command -v xdg-user-dir >/dev/null 2>&1; then
        DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
    fi
    DESKTOP_DIR="${DESKTOP_DIR:-$HOME/Desktop}"
    if [[ "$DESKTOP_DIR" == "$HOME" ]]; then
        echo "Desktop shortcuts are disabled by the desktop configuration; the application-menu icon is installed." >&2
    else
        install -d "$DESKTOP_DIR"
        SHORTCUT="$DESKTOP_DIR/Ablation.desktop"
        if [[ -e "$SHORTCUT" ]] && ! cmp -s "$DESKTOP_ENTRY" "$SHORTCUT"; then
            echo "Keeping the customized Desktop launcher at $SHORTCUT" >&2
        else
            install -m 0755 "$DESKTOP_ENTRY" "$SHORTCUT"
            if command -v gio >/dev/null 2>&1; then
                if ! gio set "$SHORTCUT" metadata::trusted true; then
                    echo "The shortcut was installed, but GNOME trusted-launcher metadata could not be set." >&2
                fi
            else
                echo "The shortcut was installed without GNOME trusted-launcher metadata because gio is unavailable." >&2
            fi
            echo "Desktop shortcut: $SHORTCUT"
        fi
    fi
fi

cat <<'EOF'
GUIAI is installed. Linux supports native GTK/VTE when its system packages are available, with Tk as a fallback.
The application-menu icon opens a native target chooser.

Start it with:
  . .venv/bin/activate
  guiai desktop /path/to/target --session /path/to/session --agent kimi

Replace kimi with claude, codex, or another installed agent executable.
For GTK/VTE dependencies, see guiai-lab/README.md in the Ablation repository.
EOF
