#!/bin/bash
# Build standalone executable

echo "[*] Building Internal RE standalone executable..."

# Install PyInstaller if needed
if ! pip show pyinstaller > /dev/null 2>&1; then
    echo "[*] Installing PyInstaller..."
    pip install pyinstaller > /dev/null 2>&1
fi

# Create single-file executable
echo "[*] Creating single-file binary..."
pyinstaller --onefile \
    --name ablation \
    --hidden-import capstone \
    --add-data "core:core" \
    --add-data "modules:modules" \
    --strip \
    main.py

if [ -f dist/ablation ]; then
    echo "[+] Build complete: dist/ablation"
    ls -lh dist/ablation
    echo ""
    echo "Deploy with:"
    echo "  scp dist/ablation target:/tmp/scanner"
    echo "  ssh target '/tmp/scanner'"
else
    echo "[-] Build failed"
    exit 1
fi
