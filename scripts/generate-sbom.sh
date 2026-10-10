#!/usr/bin/env bash
# generate-sbom.sh — produce SPDX-compatible SBOM for Ablation
#
# Closes ESF-SBOM (ABLATION-STANDARDS.md §4) and satisfies DoWI 8430.01 §2.8.k
# (SBOM mandatory for custom and COTS software).
#
# Requires: pip install pip-licenses (included in requirements-dev.txt)
#
# Usage:
#   scripts/generate-sbom.sh              # writes docs/sbom/ablation-sbom.json
#   scripts/generate-sbom.sh --csv        # also writes docs/sbom/ablation-sbom.csv
#   SBOM_OUT=path/to/out.json scripts/generate-sbom.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SBOM_DIR="${REPO_ROOT}/docs/sbom"
SBOM_JSON="${SBOM_OUT:-${SBOM_DIR}/ablation-sbom.json}"

mkdir -p "${SBOM_DIR}"

echo "[generate-sbom] writing SPDX JSON → ${SBOM_JSON}"
pip-licenses \
    --format=json \
    --with-urls \
    --with-description \
    --with-license-file \
    --output-file="${SBOM_JSON}"

echo "[generate-sbom] SBOM written: ${SBOM_JSON}"

if [[ "${1:-}" == "--csv" ]]; then
    SBOM_CSV="${SBOM_DIR}/ablation-sbom.csv"
    echo "[generate-sbom] writing CSV → ${SBOM_CSV}"
    pip-licenses \
        --format=csv \
        --with-urls \
        --output-file="${SBOM_CSV}"
    echo "[generate-sbom] CSV written: ${SBOM_CSV}"
fi
