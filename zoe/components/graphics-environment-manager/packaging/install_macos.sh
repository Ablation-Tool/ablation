#!/bin/bash
set -euo pipefail

SOURCE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c 'import sys; assert sys.version_info >= (3, 10); import tkinter' 2>/dev/null; then
    echo "Python 3.10 or newer with Tkinter is required. Install it from https://www.python.org/downloads/macos/ and retry." >&2
    exit 1
fi

cd "$SOURCE"
"$PYTHON" -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --find-links "$SOURCE/vendor" "$SOURCE/graphics_environment_manager-0.3.0-py3-none-any.whl[predict]"
python -m gem --help >/dev/null
python "$SOURCE/create_macos_app.py" "$SOURCE"

if [[ "${SKIP_TESTS:-0}" != "1" && -f "$SOURCE/macos_stress.py" ]]; then
    python "$SOURCE/macos_stress.py"
fi

if [[ "${NO_DESKTOP_SHORTCUT:-0}" != "1" ]]; then
    DESKTOP_DIR="$(python -c 'from pathlib import Path; print(Path.home() / "Desktop")')"
    mkdir -p "$DESKTOP_DIR"
    SHORTCUT="$DESKTOP_DIR/GEM.app"
    if [[ -e "$SHORTCUT" && ! -L "$SHORTCUT" ]]; then
        echo "Refusing to replace an existing non-symlink at $SHORTCUT" >&2
        exit 1
    fi
    ln -sfn "$SOURCE/GEM.app" "$SHORTCUT"
    if [[ "$(readlink "$SHORTCUT")" != "$SOURCE/GEM.app" ]]; then
        echo "The Ablation Desktop alias failed validation." >&2
        exit 1
    fi
    echo "Desktop alias: $SHORTCUT"
fi

printf '\nApplication: %s\n' "$SOURCE/GEM.app"
cat <<'EOF'
Open GEM.app and choose Open binary or Open directory in GEM.

Start it with:
  . .venv/bin/activate
  gem lab /path/to/target --session /path/to/session --toolkit tk --agent kimi

Replace kimi with claude, codex, or another installed agent executable.
EOF
