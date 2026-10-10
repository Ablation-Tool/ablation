#!/usr/bin/env bash
# monitor-supply-chain.sh — automated supply chain CVE monitoring
#
# Closes DOWI-SUPPLY (ABLATION-STANDARDS.md §10, DoWI 8430.01 §3.5.h):
# automated monitoring for new CVEs in Ablation's dependency supply chain.
#
# Requires: pip install pip-audit (included in requirements-dev.txt)
#
# Usage:
#   scripts/monitor-supply-chain.sh               # scan and report
#   scripts/monitor-supply-chain.sh --ci          # exit 1 if any CVEs found (CI mode)
#
# Recommended: run weekly via cron or CI schedule job
#   0 9 * * 1 /home/cowboy/ablation/scripts/monitor-supply-chain.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REQUIREMENTS="${REPO_ROOT}/requirements.txt"
REPORT_DIR="${REPO_ROOT}/docs/supply-chain-reports"
REPORT="${REPORT_DIR}/supply-chain-audit-$(date +%Y-%m-%d).json"
CI_MODE="${1:-}"

mkdir -p "$REPORT_DIR"

if ! command -v pip-audit &>/dev/null; then
    echo "[monitor-supply-chain] ERROR: pip-audit not installed"
    echo "[monitor-supply-chain] Install: pip install -r ${REPO_ROOT}/requirements-dev.txt"
    exit 2
fi

echo "[monitor-supply-chain] starting supply chain audit — $(date)"
echo "[monitor-supply-chain] requirements: $REQUIREMENTS"
echo "[monitor-supply-chain] report: $REPORT"

pip-audit \
    --requirement "$REQUIREMENTS" \
    --format=json \
    --output="$REPORT" \
    --desc on \
    || true

VULN_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open('$REPORT'))
    n = sum(len(dep.get('vulns', [])) for dep in d.get('dependencies', []))
    print(n)
except Exception as e:
    print('?')
" 2>/dev/null || echo "?")

echo "[monitor-supply-chain] vulnerabilities found: $VULN_COUNT"

if [[ "$VULN_COUNT" != "0" && "$VULN_COUNT" != "?" ]]; then
    echo "[monitor-supply-chain] ATTENTION: $VULN_COUNT CVE(s) detected"
    echo "[monitor-supply-chain] Review: $REPORT"
    echo "[monitor-supply-chain] Remediate: bump affected package in requirements.txt and re-run audit-deps.sh"
    if [[ "$CI_MODE" == "--ci" ]]; then
        exit 1
    fi
fi

if [[ "$VULN_COUNT" == "0" ]]; then
    echo "[monitor-supply-chain] supply chain clean as of $(date)"
fi

echo "[monitor-supply-chain] archive: ls $REPORT_DIR"
