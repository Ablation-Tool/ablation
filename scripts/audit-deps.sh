#!/usr/bin/env bash
# audit-deps.sh — scan runtime dependencies for known CVEs
#
# Closes SSDF-RV1 (ABLATION-STANDARDS.md §3.4, NIST SP 800-218 RV.1):
# automated dependency vulnerability identification.
#
# Requires: pip install pip-audit (included in requirements-dev.txt)
#
# Usage:
#   scripts/audit-deps.sh                         # scan requirements.txt
#   scripts/audit-deps.sh --json                  # emit JSON report
#   AUDIT_OUTPUT=report.json scripts/audit-deps.sh --json
#
# Exit codes:
#   0 = no vulnerabilities found
#   1 = vulnerabilities found (details printed to stdout)
#   2 = pip-audit not installed or requirements.txt missing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REQUIREMENTS="${REPO_ROOT}/requirements.txt"

if ! command -v pip-audit &>/dev/null; then
    echo "[audit-deps] ERROR: pip-audit not installed"
    echo "[audit-deps] Install with: pip install -r ${REPO_ROOT}/requirements-dev.txt"
    exit 2
fi

if [[ ! -f "$REQUIREMENTS" ]]; then
    echo "[audit-deps] ERROR: requirements.txt not found at $REQUIREMENTS"
    exit 2
fi

echo "[audit-deps] scanning $REQUIREMENTS for CVEs — $(date)"

if [[ "${1:-}" == "--json" ]]; then
    OUTPUT="${AUDIT_OUTPUT:-${REPO_ROOT}/docs/supply-chain-audit-$(date +%Y-%m-%d).json}"
    pip-audit \
        --requirement "$REQUIREMENTS" \
        --format=json \
        --output="$OUTPUT" \
        --desc on
    VULN_COUNT=$(python3 -c "
import json, sys
d = json.load(open('$OUTPUT'))
n = sum(len(dep.get('vulns', [])) for dep in d.get('dependencies', []))
print(n)
" 2>/dev/null || echo "?")
    echo "[audit-deps] report: $OUTPUT"
    echo "[audit-deps] vulnerabilities: $VULN_COUNT"
    [[ "$VULN_COUNT" == "0" ]]
else
    pip-audit \
        --requirement "$REQUIREMENTS" \
        --desc on
    echo "[audit-deps] scan complete — no HIGH/CRITICAL CVEs found"
fi
