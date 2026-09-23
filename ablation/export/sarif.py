"""
SARIF 2.1.0 export for Ablation sweep results and confirmed findings.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard consumed
by GitHub Code Scanning, VS Code, and most modern SAST platforms.

Usage:
    from ablation.export.sarif import sweep_to_sarif
    sarif = sweep_to_sarif(sweep_results, binary_path='/path/to/firmware.so')
    Path('results.sarif').write_text(json.dumps(sarif, indent=2))

GitHub Code Scanning upload:
    ablation sweep firmware.so --sarif results.sarif
    gh api repos/<owner>/<repo>/code-scanning/sarifs \\
        -f commit_sha=$(git rev-parse HEAD) \\
        -f ref=refs/heads/main \\
        -f sarif=$(gzip -c results.sarif | base64 -w0) \\
        -f tool_name=ablation

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

import importlib.metadata
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import pathname2url

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

try:
    _VERSION = importlib.metadata.version("ablation")
except Exception:
    _VERSION = "0.0.0"


def _rule_id(tag: str, query: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", query.lower())[:60].strip("-")
    return f"{tag}/{slug}" if tag else slug


def _artifact_uri(binary_path: str) -> str:
    return Path(binary_path).as_uri()


def sweep_to_sarif(
    sweep_results: Dict[str, Any],
    binary_path: str,
    min_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Convert PatternLibrary.sweep() results to a SARIF 2.1.0 document.

    sweep_results: dict returned by PatternLibrary.sweep()
    binary_path:   path to the analyzed binary (used as artifact URI)
    min_score:     only include hits at or above this score
    """
    rules: List[Dict] = []
    results: List[Dict] = []
    seen_rule_ids: set = set()

    for query, sr in sweep_results.items():
        rule_id = _rule_id(sr.tag, query)

        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f"{sr.tag.title().replace('-', '')}Pattern",
                "shortDescription": {"text": query},
                "fullDescription": {"text": f"[{sr.tag}] {query}"},
                "defaultConfiguration": {"level": "warning"},
                "properties": {"tags": [sr.tag] if sr.tag else []},
            })

        for va, score in sr.hits:
            if score < min_score:
                continue
            results.append({
                "ruleId": rule_id,
                "level": "warning",
                "message": {
                    "text": f"{query} (score={score:.3f})",
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _artifact_uri(binary_path)},
                        "address": {
                            "absoluteAddress": va,
                            "name": f"0x{va:x}",
                        },
                    },
                }],
                "properties": {
                    "score": score,
                    "va": f"0x{va:x}",
                    "tag": sr.tag,
                },
            })

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Ablation",
                    "version": _VERSION,
                    "informationUri": "https://github.com/Ablation-Tool/ablation",
                    "rules": rules,
                }
            },
            "artifacts": [{
                "location": {"uri": _artifact_uri(binary_path)},
                "roles": ["analysisTarget"],
            }],
            "results": results,
        }],
    }


def findings_to_sarif(
    findings: List[Dict[str, Any]],
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convert FindingRegistry.list_findings() output to SARIF 2.1.0.

    findings:    list of dicts from FindingRegistry.list_findings()
    binary_path: optional binary associated with the findings
    """
    rules: List[Dict] = []
    results: List[Dict] = []
    seen_cwes: set = set()

    for f in findings:
        cwe = f.get("cwe") or "unknown"
        rule_id = f"ablation/{cwe}"

        if rule_id not in seen_cwes:
            seen_cwes.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": cwe.replace("-", ""),
                "shortDescription": {"text": f"CWE class: {cwe}"},
                "defaultConfiguration": {
                    "level": _severity_to_sarif(f.get("severity", "medium")),
                },
            })

        loc: Dict[str, Any]
        if binary_path:
            loc = {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(binary_path)},
                }
            }
        else:
            loc = {"logicalLocations": [{"name": f.get("product", "unknown")}]}

        results.append({
            "ruleId": rule_id,
            "level": _severity_to_sarif(f.get("severity", "medium")),
            "message": {"text": f.get("title", "")},
            "locations": [loc],
            "properties": {
                "vendor": f.get("vendor"),
                "product": f.get("product"),
                "severity": f.get("severity"),
                "created_at": f.get("created_at"),
            },
        })

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Ablation",
                    "version": _VERSION,
                    "informationUri": "https://github.com/Ablation-Tool/ablation",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def _severity_to_sarif(severity: str) -> str:
    m = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }
    return m.get((severity or "").lower(), "warning")
