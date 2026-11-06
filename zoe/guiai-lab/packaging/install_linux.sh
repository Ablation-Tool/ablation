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

cat <<'EOF'
GUIAI is installed. Linux supports native GTK/VTE when its system packages are available, with Tk as a fallback.

Start it with:
  . .venv/bin/activate
  guiai desktop /path/to/target --session /path/to/session --agent kimi

Replace kimi with claude, codex, or another installed agent executable.
For GTK/VTE dependencies, see guiai-lab/README.md in the Ablation repository.
EOF
