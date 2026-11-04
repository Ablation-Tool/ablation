from pathlib import Path
import shutil
import subprocess
import sys
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "macos"
WHEEL_NAME = "gem_lab-0.1.0-py3-none-any.whl"


def main():
    if DIST.exists():
        shutil.rmtree(DIST)
    vendor = DIST / "vendor"
    vendor.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "build", "--wheel", "--outdir", str(DIST)], cwd=ROOT, check=True)
    subprocess.run([
        sys.executable, "-m", "pip", "download", "--only-binary=:all:",
        "--dest", str(vendor), "pyte>=0.8.1,<1", "wcwidth==0.2.14", "tkinterdnd2==0.7.0",
    ], check=True)
    for name in ("install_macos.sh", "create_macos_app.py", "README.md"):
        shutil.copy(ROOT / "packaging" / name, DIST / name)
    shutil.copy(ROOT / "gem" / "icons" / "gem-woven-diamond.png", vendor / "gem-woven-diamond.png")
    shutil.copy(ROOT / "stress" / "macos_stress.py", DIST / "macos_stress.py")
    shutil.copy(ROOT / "gem" / "icons" / "gem-woven-diamond.icns", vendor / "gem-woven-diamond.icns")
    shutil.copy(ROOT / "gem" / "icons" / "gem-woven-diamond.icns", DIST / "gem-woven-diamond.icns")
    (DIST / "install_macos.sh").chmod(0o755)
    destination = ROOT / "dist" / "GEM-macOS.zip"
    with ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(DIST.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(DIST))
    with ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("macOS package ZIP validation failed")
    print(destination)


if __name__ == "__main__":
    main()
