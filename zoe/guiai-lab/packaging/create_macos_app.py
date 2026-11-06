from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile


LAUNCHER = '''#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../Resources" && pwd)"
exec "$ROOT/.venv/bin/python" -m guiai.macos_launcher "$@"
'''


def create_icon(source, resources):
    if sys.platform != "darwin":
        raise RuntimeError("The native macOS icon must be built on macOS with sips and iconutil.")
    with tempfile.TemporaryDirectory(prefix="guiai-iconset-") as temporary:
        iconset = Path(temporary) / "Ablation.iconset"
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            for scale in (1, 2):
                suffix = "@2x" if scale == 2 else ""
                output = iconset / f"icon_{size}x{size}{suffix}.png"
                subprocess.run([
                    "sips", "-z", str(size * scale), str(size * scale), str(source), "--out", str(output),
                ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([
            "iconutil", "-c", "icns", str(iconset), "-o", str(resources / "Ablation.icns"),
        ], check=True)


def repair_launchers(environment):
    for script in (environment / "bin").iterdir():
        if not script.is_file() or script.is_symlink():
            continue
        with script.open("rb") as stream:
            first = stream.readline(4096)
            remainder = stream.read()
        if not first.startswith(b"#!") or b"python" not in first.lower() or not first.endswith(b"\n"):
            continue
        script.write_bytes(
            b'#!/bin/sh\n""":"\nexec "$(dirname "$0")/python" "$0" "$@"\n":"""\n' + remainder
        )


def create_app(source):
    source = Path(source).resolve()
    environment = source / ".venv"
    icon = source / "vendor" / "ablation-guiai-logo.png"
    if not (environment / "bin" / "python").is_file() or not icon.is_file():
        raise RuntimeError("The offline Python environment or branding asset is missing.")
    destination = source / "Ablation.app"
    if destination.exists():
        raise RuntimeError(f"Application already exists: {destination}. Choose a new package directory instead of overwriting it.")
    with tempfile.TemporaryDirectory(prefix=".ablation-app-", dir=source) as temporary:
        contents = Path(temporary) / "Ablation.app" / "Contents"
        resources = contents / "Resources"
        resources.mkdir(parents=True)
        shutil.copytree(environment, resources / ".venv")
        repair_launchers(resources / ".venv")
        launcher = contents / "MacOS" / "Ablation"
        launcher.parent.mkdir()
        launcher.write_text(LAUNCHER, encoding="utf-8")
        launcher.chmod(0o755)
        metadata = {
            "CFBundleName": "Ablation",
            "CFBundleDisplayName": "Ablation",
            "CFBundleIdentifier": "re.ablation.guiai",
            "CFBundleExecutable": "Ablation",
            "CFBundlePackageType": "APPL",
            "CFBundleIconFile": "Ablation.icns",
            "CFBundleShortVersionString": "0.1.0",
            "CFBundleVersion": "0.1.0",
            "LSApplicationCategoryType": "public.app-category.developer-tools",
            "NSHighResolutionCapable": True,
        }
        with (contents / "Info.plist").open("wb") as stream:
            plistlib.dump(metadata, stream, sort_keys=True)
        create_icon(icon, resources)
        (contents.parent).rename(destination)
    return destination


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python create_macos_app.py EXTRACTED_PACKAGE_DIRECTORY")
    destination = create_app(sys.argv[1])
    print(f"Created {destination}")


if __name__ == "__main__":
    main()
