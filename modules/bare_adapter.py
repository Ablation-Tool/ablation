"""
BARE adapter — converts ablation vuln findings to findings.json and pipes
through the BARE binary to get ranked Metasploit modules.

BARE binary: github.com/sshpie/BARE  (installed at ~/.local/bin/bare)
Corpus:      3,904 Metasploit modules encoded at compile time.

AI/ML-specific findings (HPKE, STRAP, RADIUS dialects) will typically
trigger BARE's no_high_confidence_match sentinel — this is expected.
Classic overflow/memcpy primitives will surface usable MSF modules.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .llm_analyst import AnalysisResult

_BARE_BIN = shutil.which('bare') or str(Path.home() / '.local/bin/bare')


def _bare_available() -> bool:
    return Path(_BARE_BIN).exists()


def _confidence_to_severity(confidence: float) -> str:
    if confidence >= 0.9:
        return 'critical'
    if confidence >= 0.7:
        return 'high'
    if confidence >= 0.5:
        return 'medium'
    return 'low'


def findings_from_results(
    results: 'list[AnalysisResult]',
    binary_path: str = '',
) -> dict:
    """Convert llm_analyst AnalysisResults to BARE findings.json dict.

    Only includes results with vuln_notes (clean functions produce no finding).
    """
    findings = []
    for r in results:
        if not r.vuln_notes:
            continue

        desc_parts = [f"{r.name} role={r.role}"]
        desc_parts.append(r.vuln_notes[:400])
        if r.rationale:
            desc_parts.append(r.rationale[:300])

        findings.append({
            'id': f"{Path(binary_path).name}:{hex(r.func_addr)}",
            'title': f"{r.name} ({r.role})",
            'description': ' | '.join(desc_parts),
            'target': binary_path,
            'severity': _confidence_to_severity(r.confidence),
        })

    return {
        'version': 1,
        'source': 'ablation',
        'findings': findings,
    }


def run_bare(findings: dict, timeout: int = 60) -> dict:
    """Write *findings* to a temp file, invoke BARE, return parsed output."""
    if not _bare_available():
        raise FileNotFoundError(
            f"bare binary not found. Install from github.com/sshpie/BARE or "
            f"check {_BARE_BIN}"
        )

    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.json', delete=False
    ) as f:
        json.dump(findings, f)
        tmp_path = f.name

    try:
        result = subprocess.run(
            [_BARE_BIN, tmp_path],
            capture_output=True,
            timeout=timeout,
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    if result.returncode != 0:
        stderr = result.stderr.decode(errors='replace')
        raise RuntimeError(f"bare exited {result.returncode}: {stderr}")

    return json.loads(result.stdout)


def rank_modules(
    results: 'list[AnalysisResult]',
    binary_path: str = '',
) -> dict | None:
    """End-to-end: AnalysisResults → BARE output dict.

    Returns None if no results have vuln_notes.
    Findings with no_high_confidence_match=true are expected for
    AI/ML-specific primitives (HPKE, STRAP, RADIUS custom dialects).
    """
    findings = findings_from_results(results, binary_path)
    if not findings['findings']:
        return None
    return run_bare(findings)


def format_bare_output(bare_result: dict, min_score: float = 0.3) -> str:
    """Human-readable ranked module summary from BARE output."""
    lines = [f"BARE — corpus {bare_result['corpus']['size']} modules"]
    for finding in bare_result.get('findings', []):
        lines.append(f"\n  {finding['title']} [{finding.get('severity', '?')}]")
        if finding.get('no_high_confidence_match'):
            lines.append(
                f"    no MSF coverage (top score: "
                f"{finding.get('top_score_seen', 0):.3f})"
            )
            continue
        for m in finding.get('matches', []):
            if m['score'] < min_score:
                break
            lines.append(
                f"    #{m['rank']:2d}  {m['score']:.3f}  "
                f"{m['category']:12s}  {m['module']}"
            )
    return '\n'.join(lines)
