"""Flat JSON export for Ablation sweep results and confirmed findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def sweep_to_json(
    sweep_results: Dict[str, Any],
    binary_path: str,
    min_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Convert PatternLibrary.sweep() results to a flat JSON structure.

    Output schema:
    {
      "binary": "<path>",
      "findings": [
        {
          "tag": "memory-safety",
          "pattern": "function reads untrusted length ...",
          "hits": [{"va": "0x1234", "score": 0.42}, ...]
        }
      ]
    }
    """
    findings = []
    for query, sr in sweep_results.items():
        hits = [
            {"va": f"0x{va:x}", "score": round(score, 4)}
            for va, score in sr.hits
            if score >= min_score
        ]
        if hits:
            findings.append({
                "tag": sr.tag,
                "pattern": query,
                "hits": hits,
            })

    return {
        "binary": str(Path(binary_path).resolve()),
        "findings": findings,
        "total_hits": sum(len(f["hits"]) for f in findings),
    }


def findings_to_json(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Convert FindingRegistry.list_findings() to JSON."""
    return {
        "findings": findings,
        "total": len(findings),
    }


def write_json(data: Dict[str, Any], path: str, indent: int = 2) -> None:
    Path(path).write_text(json.dumps(data, indent=indent))


def write_sarif(data: Dict[str, Any], path: str, indent: int = 2) -> None:
    Path(path).write_text(json.dumps(data, indent=indent))
