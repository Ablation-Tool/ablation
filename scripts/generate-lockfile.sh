#!/usr/bin/env bash
# generate-lockfile.sh — pin all runtime dependencies with cryptographic hashes
#
# Closes DPR-001 (ABLATION-STANDARDS.md §4): produces requirements-hashed.txt
# with --require-hashes so pip refuses any package whose hash doesn't match.
#
# Requires: pip install pip-tools (included in requirements-dev.txt)
#
# Usage:
#   scripts/generate-lockfile.sh           # regenerate requirements-hashed.txt
#
# The output file is checked into the repo and used for reproducible installs:
#   pip install --require-hashes -r requirements-hashed.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HASHED="${REPO_ROOT}/requirements-hashed.txt"

echo "[generate-lockfile] compiling ${HASHED}"
pip-compile \
    --generate-hashes \
    --output-file="${HASHED}" \
    "${REPO_ROOT}/requirements.txt"

echo "[generate-lockfile] lockfile written: ${HASHED}"
echo "[generate-lockfile] install with: pip install --require-hashes -r requirements-hashed.txt"
