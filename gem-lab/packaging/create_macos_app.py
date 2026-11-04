from pathlib import Path
import plistlib
import shutil
import sys
import tempfile


LAUNCHER = '''#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../Resources" && pwd)"
exec "$ROOT/.venv/bin/python" -m gem.macos_launcher "$@"
'''


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
    icon = source / "vendor" / "gem-woven-diamond.icns"
    if not (environment / "bin" / "python").is_file() or not icon.is_file():
        raise RuntimeError("The offline Python environment or branding asset is missing.")
    destination = source / "GEM.app"
    if destination.exists():
        raise RuntimeError(f"Application already exists: {destination}. Choose a new package directory instead of overwriting it.")
    with tempfile.TemporaryDirectory(prefix=".ablation-app-", dir=source) as temporary:
        contents = Path(temporary) / "GEM.app" / "Contents"
        resources = contents / "Resources"
        resources.mkdir(parents=True)
        shutil.copytree(environment, resources / ".venv")
        repair_launchers(resources / ".venv")
        launcher = contents / "MacOS" / "GEM"
        launcher.parent.mkdir()
        launcher.write_text(LAUNCHER, encoding="utf-8")
        launcher.chmod(0o755)
        metadata = {
            "CFBundleName": "GEM",
            "CFBundleDisplayName": "GEM",
            "CFBundleIdentifier": "re.ablation.gem",
            "CFBundleExecutable": "GEM",
            "CFBundlePackageType": "APPL",
            "CFBundleIconFile": "GEM.icns",
            "CFBundleShortVersionString": "0.1.0",
            "CFBundleVersion": "0.1.0",
            "LSApplicationCategoryType": "public.app-category.developer-tools",
            "NSHighResolutionCapable": True,
        }
        with (contents / "Info.plist").open("wb") as stream:
            plistlib.dump(metadata, stream, sort_keys=True)
        shutil.copy2(icon, resources / "GEM.icns")
        (contents.parent).rename(destination)
    return destination


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python create_macos_app.py EXTRACTED_PACKAGE_DIRECTORY")
    destination = create_app(sys.argv[1])
    print(f"Created {destination}")


if __name__ == "__main__":
    main()
