#!/usr/bin/env bash
# verify-account.sh — confirm active gh account is Ablation-Tool before any push
#
# Closes DPR-003 (ABLATION-STANDARDS.md §8.2, NIST SSDF PS.1):
# automated verification that the correct GitHub account is active.
#
# Usage:
#   scripts/verify-account.sh           # exits 0 if OK, 1 if wrong account
#
# Run before every git push to Ablation-Tool/ablation:
#   scripts/verify-account.sh && git push origin main
#
# Or inline with the canonical push command:
#   scripts/verify-account.sh && env HOME=/home/cowboy GIT_LFS_SKIP_SMUDGE=1 git push origin main

set -euo pipefail

EXPECTED="Ablation-Tool"

ACTUAL=$(gh api user --jq .login 2>/dev/null || echo "ERROR")

if [[ "$ACTUAL" == "ERROR" ]]; then
    echo "[verify-account] FAIL: gh CLI returned error — is gh authenticated?"
    echo "[verify-account] Run: gh auth login"
    exit 1
fi

if [[ "$ACTUAL" != "$EXPECTED" ]]; then
    echo "[verify-account] FAIL: active gh account is '$ACTUAL', expected '$EXPECTED'"
    echo "[verify-account] Switch with: gh auth switch --user $EXPECTED"
    echo "[verify-account] List accounts with: gh auth status"
    exit 1
fi

echo "[verify-account] OK: active gh account is $EXPECTED"
