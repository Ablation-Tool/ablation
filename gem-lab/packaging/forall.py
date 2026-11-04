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
import venv
from zipfile import BadZipFile, ZipFile


BASE_URL = "https://github.com/Ablation-Tool/ablation/releases/latest/download"


def platform_package(system=None, machine=None):
    system = (system or sys.platform).lower()
    machine = (machine or platform.machine()).lower()
    if system == "darwin":
        return "GEM-macOS.zip", "install_macos.sh"
    if system == "win32":
        if machine not in {"amd64", "x86_64"}:
            raise RuntimeError("Native Windows currently requires an x64 Python and Windows installation.")
        return "GEM-Windows-Native.zip", "Install-WindowsNative.ps1"
    if system.startswith("linux"):
        return "GEM-Linux.zip", "install_linux.sh"
    raise RuntimeError(f"Unsupported operating system: {system}. Use the platform installation guide.")


def download(url, destination):
    request = Request(url, headers={"User-Agent": "Ablation-GEM-Installer/1"})
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


def install_package(source, installer, skip_tests, no_desktop_shortcut, destination):
    environment = os.environ.copy()
    environment["GEM_INSTALL_DESTINATION"] = str(destination)
    if skip_tests:
        environment["SKIP_TESTS"] = "1"
    if no_desktop_shortcut:
        environment["NO_DESKTOP_SHORTCUT"] = "1"
    if sys.platform == "win32":
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            raise RuntimeError("Windows PowerShell is required to complete the installation.")
        command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(source / installer)]
        if skip_tests:
            command.append("-SkipTests")
        if no_desktop_shortcut:
            command.append("-NoDesktopShortcut")
    else:
        command = ["bash", str(source / installer)]
    subprocess.run(command, cwd=source, env=environment, check=True)


def ablation_package(checksums):
    matches = [
        name for name in checksums
        if name.startswith("ablation_tool-") and name.endswith("-py3-none-any.whl")
    ]
    if len(matches) != 1:
        raise RuntimeError("The release must provide exactly one standard Ablation CLI wheel.")
    return matches[0]


def install_ablation(source, archive):
    environment = source / ".venv"
    venv.EnvBuilder(
        with_pip=True, system_site_packages=sys.platform.startswith("linux"),
    ).create(environment)
    executable = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    subprocess.run(
        [str(executable), "-m", "pip", "install", str(archive)],
        cwd=source, check=True, timeout=600,
    )


def verify_installed_cli(source, include_ablation):
    names = ["gem"] + (["ablation"] if include_ablation else [])
    for name in names:
        executable = source / ".venv" / (
            f"Scripts/{name}.exe" if sys.platform == "win32" else f"bin/{name}"
        )
        subprocess.run(
            [str(executable), "--help"], cwd=source,
            stdout=subprocess.DEVNULL, check=True, timeout=60,
        )
    gem = source / ".venv" / ("Scripts/gem.exe" if sys.platform == "win32" else "bin/gem")
    subprocess.run(
        [str(gem), "launch", "--help"], cwd=source,
        stdout=subprocess.DEVNULL, check=True, timeout=60,
    )
    if include_ablation and sys.platform == "darwin":
        bundled = source / "GEM.app" / "Contents" / "Resources" / ".venv" / "bin" / "ablation"
        subprocess.run(
            [str(bundled), "--help"], cwd=source,
            stdout=subprocess.DEVNULL, check=True, timeout=60,
        )


def default_destination():
    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "Ablation" / "GEM"


def parse_arguments(arguments=None):
    parser = argparse.ArgumentParser(description="Download and install the standard Ablation CLI and native GEM workbench.")
    parser.add_argument("--gui-only", action="store_true", help="install only GEM, without the standard Ablation CLI")
    parser.add_argument("--directory", type=Path, default=default_destination(), help="new installation directory (must not exist)")
    parser.add_argument("--skip-tests", action="store_true", help="skip native validation (not recommended)")
    parser.add_argument("--no-desktop-shortcut", action="store_true", help="install without creating a Desktop shortcut")
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
    with tempfile.TemporaryDirectory(prefix="gem-forall-", dir=destination.parent) as temporary:
        downloads = Path(temporary)
        base = args.base_url.rstrip("/") + "/"
        download(base + "SHA256SUMS.txt", downloads / "SHA256SUMS.txt")
        checksums = release_checksums((downloads / "SHA256SUMS.txt").read_text(encoding="utf-8-sig"))
        archive = downloads / asset
        download(base + quote(asset), archive)
        verify_archive(archive, checksums)
        ablation_asset = None
        if not args.gui_only:
            ablation_asset = ablation_package(checksums)
            full_archive = downloads / ablation_asset
            download(base + quote(ablation_asset), full_archive)
            verify_archive(full_archive, checksums)
        created = False
        try:
            destination.mkdir()
            created = True
            extract_archive(archive, destination)
            if not args.gui_only:
                install_ablation(destination, full_archive)
            install_package(destination, installer, args.skip_tests, args.no_desktop_shortcut, destination)
            verify_installed_cli(destination, not args.gui_only)
            (destination / ".gem-install.json").write_text(json.dumps({
                "package": asset,
                "sha256": checksums[asset],
                "ablation_package": ablation_asset,
                "ablation_sha256": checksums.get(ablation_asset),
                "source": args.base_url,
            }, indent=2) + "\n", encoding="utf-8")
        except BaseException as error:
            raise RuntimeError(
                f"Installation did not complete; the new partial installation is retained at {destination}: {error}",
            ) from error
    executable = destination / ".venv" / ("Scripts/gem.exe" if sys.platform == "win32" else "bin/gem")
    installed = "GEM is" if args.gui_only else "Ablation CLI and GEM are"
    print(f"\n{installed} installed in {destination}")
    if not args.no_desktop_shortcut:
        print("Open GEM from its Desktop icon and choose Open binary or Open directory in GEM.")
    if sys.platform == "darwin":
        print(f"Application: {destination / 'GEM.app'}")
    print("Launch it with your installed AI Agent:")
    toolkit = "" if sys.platform.startswith("linux") else " --toolkit tk"
    print(f'  "{executable}" lab TARGET --session SESSION{toolkit} --agent kimi')
    if not sys.platform.startswith("linux"):
        print("Replace kimi with claude, codex, or another installed agent executable.")
    else:
        print("Linux uses native GTK/VTE by default when its system packages are installed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, BadZipFile, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"Installation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
