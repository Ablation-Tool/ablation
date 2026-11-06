from pathlib import Path
import shutil
import subprocess
import sys
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "linux"
WHEEL_NAME = "graphics_environment_manager-0.3.0-py3-none-any.whl"


def main():
    if DIST.exists():
        shutil.rmtree(DIST)
    vendor = DIST / "vendor"
    vendor.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "build", "--wheel", "--outdir", str(DIST)], cwd=ROOT, check=True)
    subprocess.run([
        sys.executable, "-m", "pip", "download", "--only-binary=:all:",
        "--dest", str(vendor), "pyte>=0.8.1,<1", "wcwidth==0.2.14", "tkinterdnd2==0.7.0",
        "numpy>=2.3.5,<3", "onnxruntime>=1.31.1,<2", "tokenizers>=0.23.3,<1", "huggingface-hub>=1.33.0,<2",
    ], check=True)
    for name in ("install_linux.sh", "README.md"):
        shutil.copy(ROOT / "packaging" / name, DIST / name)
    shutil.copy(ROOT / "stress" / "native_stress.py", DIST / "native_stress.py")
    shutil.copy(ROOT / "gem" / "assets" / "gem2red.png", DIST / "ablation-gem-logo.png")
    shutil.copy(ROOT / "packaging" / "re.gem.workbench.desktop.in", DIST / "re.gem.workbench.desktop.in")
    (DIST / "install_linux.sh").chmod(0o755)
    destination = ROOT / "dist" / "GEM-Linux.zip"
    with ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(DIST.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(DIST))
    with ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("Linux package ZIP validation failed")
    print(destination)


if __name__ == "__main__":
    main()
