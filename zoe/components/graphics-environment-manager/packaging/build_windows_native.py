from pathlib import Path
import shutil
import subprocess
import sys
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "windows-native"
WHEEL_NAME = "graphics_environment_manager-0.3.0-py3-none-any.whl"


def main():
    if DIST.exists():
        shutil.rmtree(DIST)
    vendor = DIST / "vendor"
    vendor.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "build", "--wheel", "--outdir", str(DIST)], cwd=ROOT, check=True)
    subprocess.run([
        sys.executable, "-m", "pip", "download", "--only-binary=:all:",
        "--platform", "win_amd64", "--python-version", "311",
        "--implementation", "cp", "--abi", "cp311",
        "--dest", str(vendor), "pyte>=0.8.1,<1", "wcwidth==0.2.14", "pywinpty>=2,<3", "tkinterdnd2==0.7.0",
        "numpy>=2.3.5,<3", "onnxruntime>=1.31.1,<2", "tokenizers>=0.23.3,<1", "huggingface-hub>=1.33.0,<2",
    ], check=True)
    for name in ("Install-WindowsNative.ps1", "README.md"):
        shutil.copy(ROOT / "packaging" / name, DIST / name)
    shutil.copy(ROOT / "stress" / "windows_stress.py", DIST / "windows_stress.py")
    shutil.copy(ROOT / "gem" / "assets" / "gem2red.ico", DIST / "ablation-gem.ico")
    destination = ROOT / "dist" / "GEM-Windows-Native.zip"
    with ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(DIST.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(DIST))
    with ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("Windows package ZIP validation failed")
    print(destination)


if __name__ == "__main__":
    main()
