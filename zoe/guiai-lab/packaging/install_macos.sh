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
python -m pip install --no-index --find-links "$SOURCE/vendor" "$SOURCE/guiai_lab-0.1.0-py3-none-any.whl"
python -m guiai --help >/dev/null
python "$SOURCE/create_macos_app.py" "$SOURCE"

if [[ "${SKIP_TESTS:-0}" != "1" && -f "$SOURCE/macos_stress.py" ]]; then
    python "$SOURCE/macos_stress.py"
fi

printf '\nApplication: %s\n' "$SOURCE/Ablation.app"
cat <<'EOF'
Open Ablation.app to choose a target, project directory, and optional AI Agent.

Start it with:
  . .venv/bin/activate
  guiai desktop /path/to/target --session /path/to/session --toolkit tk --agent kimi

Replace kimi with claude, codex, or another installed agent executable.
EOF
