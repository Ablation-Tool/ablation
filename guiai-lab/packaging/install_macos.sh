#!/bin/bash
set -euo pipefail

SOURCE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c 'import sys; assert sys.version_info >= (3, 10); import tkinter' 2>/dev/null; then
    echo "Python 3.10 or newer with Tkinter is required. Install it from https://www.python.org/downloads/macos/ and retry." >&2
    exit 1
fi

if [[ ! -f "$SOURCE/ablation-guiai.icns" ]]; then
    echo "The package is incomplete: ablation-guiai.icns is missing." >&2
    exit 1
fi

cd "$SOURCE"
"$PYTHON" -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --find-links "$SOURCE/vendor" "$SOURCE/guiai_lab-0.1.0-py3-none-any.whl"

if [[ "${SKIP_TESTS:-0}" != "1" && -f "$SOURCE/macos_stress.py" ]]; then
    python "$SOURCE/macos_stress.py"
fi

APP_ROOT="${GUIAI_APPLICATION_ROOT:-$HOME/Applications}"
APP_BUNDLE="$APP_ROOT/Ablation.app"
export SOURCE APP_BUNDLE
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
python - <<'PY'
import os
from pathlib import Path
import plistlib
import shlex
import shutil

package_source = Path(os.environ["SOURCE"])
install_source = Path(os.environ.get("GUIAI_INSTALL_DESTINATION", package_source))
bundle = Path(os.environ["APP_BUNDLE"])
executable = bundle / "Contents" / "MacOS" / "Ablation"
command = shlex.join([str(install_source / ".venv" / "bin" / "python"), "-m", "guiai", "launch", "--toolkit", "tk"])
temporary = executable.with_suffix(".tmp")
temporary.write_text(f"#!/bin/sh\nexec {command}\n", encoding="utf-8")
temporary.chmod(0o755)
temporary.replace(executable)
shutil.copy2(package_source / "ablation-guiai.icns", bundle / "Contents" / "Resources" / "Ablation.icns")
plist_path = bundle / "Contents" / "Info.plist"
temporary_plist = plist_path.with_suffix(".tmp")
with temporary_plist.open("wb") as stream:
    plistlib.dump({
        "CFBundleDisplayName": "Ablation",
        "CFBundleExecutable": "Ablation",
        "CFBundleIconFile": "Ablation",
        "CFBundleIdentifier": "re.guiai.workbench",
        "CFBundleName": "Ablation",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "0.1.0",
        "CFBundleVersion": "1",
    }, stream, sort_keys=True)
temporary_plist.replace(plist_path)
with plist_path.open("rb") as stream:
    plist = plistlib.load(stream)
assert plist["CFBundleExecutable"] == "Ablation"
assert plist["CFBundleIconFile"] == "Ablation"
PY
bash -n "$APP_BUNDLE/Contents/MacOS/Ablation"
if [[ "$(uname -s)" == "Darwin" ]] && command -v plutil >/dev/null 2>&1; then
    plutil -lint "$APP_BUNDLE/Contents/Info.plist"
fi

if [[ "${NO_DESKTOP_SHORTCUT:-0}" != "1" ]]; then
    DESKTOP_DIR="$(python -c 'from pathlib import Path; print(Path.home() / "Desktop")')"
    mkdir -p "$DESKTOP_DIR"
    SHORTCUT="$DESKTOP_DIR/Ablation.app"
    if [[ -e "$SHORTCUT" && ! -L "$SHORTCUT" ]]; then
        echo "Refusing to replace an existing non-symlink at $SHORTCUT" >&2
        exit 1
    fi
    ln -sfn "$APP_BUNDLE" "$SHORTCUT"
    if [[ "$(readlink "$SHORTCUT")" != "$APP_BUNDLE" ]]; then
        echo "The Ablation Desktop alias failed validation." >&2
        exit 1
    fi
    echo "Desktop alias: $SHORTCUT"
fi

cat <<EOF
GUIAI is installed. macOS uses the Tk interface.
Application bundle: $APP_BUNDLE

Open Ablation from the Desktop alias, or start it with:
  . .venv/bin/activate
  guiai desktop /path/to/target --session /path/to/session --toolkit tk --agent kimi

Replace kimi with claude, codex, or another installed agent executable.
EOF
