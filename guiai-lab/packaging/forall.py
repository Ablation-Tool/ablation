#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import quote
from urllib.request import Request, urlopen
from zipfile import ZipFile


BASE_URL = "https://github.com/Ablation-Tool/ablation/releases/latest/download"


def platform_package(system=None, machine=None):
    system = (system or sys.platform).lower()
    machine = (machine or platform.machine()).lower()
    if system == "darwin":
        return "GUIAI-macOS.zip", "install_macos.sh"
    if system == "win32":
        if machine not in {"amd64", "x86_64"}:
            raise RuntimeError("Native Windows currently requires an x64 Python and Windows installation.")
        return "GUIAI-Windows-Native.zip", "Install-WindowsNative.ps1"
    if system.startswith("linux"):
        return "GUIAI-Linux.zip", "install_linux.sh"
    raise RuntimeError(f"Unsupported operating system: {system}. Use the platform installation guide.")


def download(url, destination):
    request = Request(url, headers={"User-Agent": "Ablation-GUIAI-Installer/1"})
    with urlopen(request, timeout=60) as response, open(destination, "xb") as stream:
        shutil.copyfileobj(response, stream)


def release_checksums(text):
    checksums = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            raise RuntimeError("The release checksum file is malformed.")
        digest, name = fields
        name = name.lstrip("*")
        if len(digest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in digest):
            raise RuntimeError("The release checksum file contains an invalid SHA256 digest.")
        if name in checksums:
            raise RuntimeError(f"The release contains duplicate checksums for {name}.")
        checksums[name] = digest.lower()
    return checksums


def verify_archive(archive, checksums):
    if archive.name not in checksums:
        raise RuntimeError(f"The release does not provide a checksum for {archive.name}.")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if not hmac.compare_digest(digest, checksums[archive.name]):
        raise RuntimeError(f"Checksum verification failed for {archive.name}; nothing was installed.")


def extract_archive(archive, destination):
    with ZipFile(archive) as bundle:
        for member in bundle.infolist():
            path = PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts or not path.parts or "\\" in member.filename or (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise RuntimeError(f"Unsafe archive member: {member.filename}")
        if "install_macos.sh" not in bundle.namelist() and "install_linux.sh" not in bundle.namelist() and "Install-WindowsNative.ps1" not in bundle.namelist():
            raise RuntimeError("The downloaded package does not contain a supported installer.")
        bundle.extractall(destination)


def install_package(source, installer, skip_tests):
    if sys.platform == "win32":
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            raise RuntimeError("Windows PowerShell is required to complete the installation.")
        command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(source / installer)]
        if skip_tests:
            command.append("-SkipTests")
    else:
        command = ["bash", str(source / installer)]
        environment = os.environ.copy()
        if skip_tests:
            environment["SKIP_TESTS"] = "1"
        subprocess.run(command, cwd=source, env=environment, check=True)
        return
    subprocess.run(command, cwd=source, check=True)


def default_destination():
    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "Ablation" / "GUIAI"


def parse_arguments(arguments=None):
    parser = argparse.ArgumentParser(description="Download and install the verified native GUIAI package for this computer.")
    parser.add_argument("--directory", type=Path, default=default_destination(), help="new installation directory (must not exist)")
    parser.add_argument("--skip-tests", action="store_true", help="skip native validation (not recommended)")
    parser.add_argument("--base-url", default=BASE_URL, help=argparse.SUPPRESS)
    return parser.parse_args(arguments)


def main(arguments=None):
    args = parse_arguments(arguments)
    if sys.version_info < (3, 10):
        raise RuntimeError("Python 3.10 or newer is required; native Windows requires Python 3.11 x64.")
    destination = args.directory.expanduser().resolve()
    if destination.exists():
        raise RuntimeError(f"Installation directory already exists: {destination}. Choose an empty --directory; existing files were not changed.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    asset, installer = platform_package()
    with tempfile.TemporaryDirectory(prefix="guiai-forall-", dir=destination.parent) as temporary:
        downloads = Path(temporary)
        base = args.base_url.rstrip("/") + "/"
        download(base + "SHA256SUMS.txt", downloads / "SHA256SUMS.txt")
        checksums = release_checksums((downloads / "SHA256SUMS.txt").read_text(encoding="utf-8-sig"))
        archive = downloads / asset
        download(base + quote(asset), archive)
        verify_archive(archive, checksums)
        staging = downloads / "install"
        extract_archive(archive, staging)
        install_package(staging, installer, args.skip_tests)
        (staging / ".guiai-install.json").write_text(json.dumps({
            "package": asset,
            "sha256": checksums[asset],
            "source": args.base_url,
        }, indent=2) + "\n", encoding="utf-8")
        try:
            staging.rename(destination)
        except OSError as error:
            raise RuntimeError(f"Unable to move the completed installation into {destination}: {error}") from error
    executable = destination / ".venv" / ("Scripts/guiai.exe" if sys.platform == "win32" else "bin/guiai")
    print(f"\nGUIAI is installed in {destination}")
    if sys.platform == "darwin":
        print(f"Application: {destination / 'Ablation.app'}")
    print("Launch it with your installed AI Agent:")
    print(f'  "{executable}" desktop TARGET --session SESSION --toolkit tk --agent kimi')
    if not sys.platform.startswith("linux"):
        print("Replace kimi with claude, codex, or another installed agent executable.")
    else:
        print("Remove --toolkit tk to use native GTK/VTE when its Linux system packages are installed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Installation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
