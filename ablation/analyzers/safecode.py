"""
safecode.py — SAFECODE: unified production readiness and source security auditor.

Two modes, one output type:

    SAFECODE.audit_module(path)   — production readiness audit for a single module.
                                     10-section LLM audit + DEV & TEST ORCHESTRATION
                                     PLAN. Use before git add on any new ablation module.

    SAFECODE.audit_source(path)   — source security audit for any codebase, any size,
                                     any owner. SourceContext → SourceEntryClassifier →
                                     SourceSinkScanner → SourceAuditCompressor. Returns
                                     ranked priority read list + sink findings.

    SAFECODE.pre_commit_gate(staged) — runs audit_module on each staged .py file;
                                        combined report, gate_passed=False on any HIGH.

Usage:
    from ablation.analyzers.safecode import SAFECODE

    # Pre-commit: audit a new module before git add
    report = SAFECODE.audit_module('/home/cowboy/ablation/ablation/analyzers/new_module.py')
    print(report.report())
    if not report.gate_passed:
        raise SystemExit("SAFECODE BLOCKED: HIGH findings present — fix before committing")

    # Source audit: any codebase, any size
    report = SAFECODE.audit_source('/tmp/target-repo')
    print(report.report())

    # Pre-commit gate (staged files from git)
    import subprocess
    staged = subprocess.check_output(
        ['git', 'diff', '--cached', '--name-only'], cwd='/home/cowboy/ablation'
    ).decode().splitlines()
    report = SAFECODE.pre_commit_gate(staged, repo_root='/home/cowboy/ablation')
    raise SystemExit(0 if report.gate_passed else 1)

CLI:
    python3 -m ablation.analyzers.safecode module /path/to/module.py
    python3 -m ablation.analyzers.safecode source /path/to/repo
    python3 -m ablation.analyzers.safecode gate --repo /home/cowboy/ablation
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import anthropic as _anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _anthropic = None       # type: ignore
    _ANTHROPIC_AVAILABLE = False

try:
    from .source_ingestion import SourceContext
    from .source_entry_classifier import SourceEntryClassifier
    from .source_sink_scanner import SourceSinkScanner
    from .source_audit_compressor import SourceAuditCompressor
except ImportError:
    from source_ingestion import SourceContext                      # type: ignore
    from source_entry_classifier import SourceEntryClassifier      # type: ignore
    from source_sink_scanner import SourceSinkScanner              # type: ignore
    from source_audit_compressor import SourceAuditCompressor      # type: ignore


_DEFAULT_MODEL = 'claude-sonnet-5'

# System prompt search order: package data first, external drive fallback.
_PROMPT_CANDIDATES = [
    Path(__file__).parent.parent / 'data' / 'safecode_system.md',
    Path('/media/cowboy/research/repos/Downloads/Ablation-SAFE CODE.md'),
]

_PROMPT_FALLBACK = """\
You are a senior production readiness reviewer. Audit the provided code.
Respond with exactly these 10 sections in this order:
1. Scope & Assumptions
2. Functional Correctness Assessment
3. Operational Safety & Failure Modes
4. Reliability & Resilience Issues
5. Performance & Resource Use Considerations
6. Maintainability & Operability Observations
7. Data Integrity & Consistency Risks
8. Testing & Verification Suggestions
9. Prioritized Production Readiness Checklist
10. Residual Risk & Limitations
For each finding in sections 2-4 and 7 include: Title, Severity (High/Medium/Low),
Location, Description, Recommendation.
"""


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class SafecodeFinding:
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str       # section name or sink category
    title: str
    location: str       # file:line or function name
    description: str
    recommendation: str
    source: str         # "module_audit" or "source_audit"
    cwe: str = ""


@dataclass
class SafecodeReport:
    path: str
    mode: str           # "module" or "source"
    findings: list[SafecodeFinding] = field(default_factory=list)
    summary: str = ""
    raw_text: str = ""  # full LLM output (module mode) or compressor report (source mode)

    @property
    def gate_passed(self) -> bool:
        return not any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

    def highs(self) -> list[SafecodeFinding]:
        return [f for f in self.findings if f.severity in ("CRITICAL", "HIGH")]

    def report(self) -> str:
        n_crit   = sum(1 for f in self.findings if f.severity == "CRITICAL")
        n_high   = sum(1 for f in self.findings if f.severity == "HIGH")
        n_medium = sum(1 for f in self.findings if f.severity == "MEDIUM")
        n_low    = sum(1 for f in self.findings if f.severity == "LOW")
        n_info   = sum(1 for f in self.findings if f.severity == "INFO")

        lines = [
            f"SAFECODE [{self.mode.upper()}] — {self.path}",
            f"Gate: {'PASSED' if self.gate_passed else 'BLOCKED'}",
            f"Findings: {len(self.findings)}  "
            f"({n_crit} CRITICAL  {n_high} HIGH  {n_medium} MEDIUM  "
            f"{n_low} LOW  {n_info} INFO)",
            "",
        ]
        for f in self.findings:
            lines.append(f"  [{f.severity}] {f.title}")
            lines.append(f"    location   : {f.location}")
            lines.append(f"    category   : {f.category}")
            if f.cwe:
                lines.append(f"    cwe        : {f.cwe}")
            lines.append(f"    description: {f.description}")
            if f.recommendation:
                lines.append(f"    action     : {f.recommendation}")
            lines.append("")
        if self.summary:
            lines += ["", f"Summary:", f"  {self.summary}"]
        return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _load_system_prompt() -> str:
    for candidate in _PROMPT_CANDIDATES:
        if candidate.exists():
            return candidate.read_text(encoding='utf-8')
    return _PROMPT_FALLBACK


def _parse_json_findings(raw: str, source: str) -> list[SafecodeFinding]:
    """Extract findings from the SAFECODE_JSON line appended by the LLM."""
    m = re.search(r'SAFECODE_JSON:\s*(\[.*?\])\s*$', raw, re.DOTALL | re.MULTILINE)
    if not m:
        return _parse_prose_findings(raw, source)
    try:
        items = json.loads(m.group(1))
        findings = []
        for item in items:
            if not isinstance(item, dict):
                continue
            findings.append(SafecodeFinding(
                severity=str(item.get('severity', 'INFO')).upper(),
                category=str(item.get('category', 'module_audit')),
                title=str(item.get('title', '')),
                location=str(item.get('location', '')),
                description=str(item.get('description', '')),
                recommendation=str(item.get('recommendation', '')),
                source=source,
                cwe=str(item.get('cwe', '')),
            ))
        return findings
    except (json.JSONDecodeError, TypeError):
        return _parse_prose_findings(raw, source)


def _parse_prose_findings(raw: str, source: str) -> list[SafecodeFinding]:
    """Fallback: extract findings from free-text 10-section prose output."""
    findings: list[SafecodeFinding] = []
    # Match blocks that have a title line followed by a Severity: label nearby.
    block_re = re.compile(
        r'\*{0,2}(?P<title>[^\n*]{5,80}?)\*{0,2}\n'
        r'(?:.*?\n){0,6}'
        r'[*\s]*(?:Severity|Type)\s*:\s*(?P<sev>Critical|High|Medium|Low|Issue|Risk)\b',
        re.IGNORECASE,
    )
    sev_map = {'ISSUE': 'MEDIUM', 'RISK': 'MEDIUM'}
    seen: set[str] = set()
    for m in block_re.finditer(raw):
        title = m.group('title').strip(' .*')
        if not title or title in seen:
            continue
        seen.add(title)
        sev_raw = m.group('sev').upper()
        sev = sev_map.get(sev_raw, sev_raw)
        findings.append(SafecodeFinding(
            severity=sev,
            category='module_audit',
            title=title,
            location='',
            description='',
            recommendation='',
            source=source,
        ))
    return findings


def _extract_summary(raw: str) -> str:
    """Pull the first substantive line from Section 10 as the report summary."""
    m = re.search(
        r'10\.\s+Residual Risk[^\n]*\n((?:.|\n){20,300}?)(?:\n\n|\Z)',
        raw, re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()[:300]
    return ""


# ── Main class ────────────────────────────────────────────────────────────────

class SAFECODE:
    """
    Unified production readiness and source security auditor.

    All methods are classmethods; no instantiation needed.
    """

    @classmethod
    def audit_module(
        cls,
        path: str,
        model: str = _DEFAULT_MODEL,
    ) -> SafecodeReport:
        """
        Run the 10-section SAFE CODE production audit on a single source file.

        Sends the file to Claude with the SAFE CODE system prompt and requests
        a structured JSON findings array appended after the prose sections.
        Returns a SafecodeReport; gate_passed=False if any HIGH/CRITICAL finding.
        """
        source_path = Path(path)
        if not source_path.exists():
            raise FileNotFoundError(f"safecode.audit_module: file not found: {path}")

        code = source_path.read_text(encoding='utf-8', errors='replace')
        system = _load_system_prompt()

        user_msg = (
            f"Audit this file: {source_path.name}\n\n"
            f"```\n{code}\n```\n\n"
            "After completing all 10 sections and the DEV & TEST ORCHESTRATION PLAN, "
            "append exactly one final line in this format (no line break inside the JSON):\n"
            "SAFECODE_JSON: [{\"severity\": \"HIGH\", \"category\": \"functional_correctness\", "
            "\"title\": \"...\", \"location\": \"...\", \"description\": \"...\", "
            "\"recommendation\": \"...\", \"cwe\": \"\"}]\n"
            "Include one object per finding from sections 2, 3, 4, and 7. "
            "Severity must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO."
        )

        if not _ANTHROPIC_AVAILABLE:
            raise ImportError(
                "safecode.audit_module requires anthropic. "
                "Install it with: pip install 'ablation[llm]'"
            )
        client = _anthropic.Anthropic()
        resp = client.messages.create(
            model=model,
            max_tokens=8192,
            system=system,
            messages=[{"role": "user", "content": user_msg}],
        )

        raw = resp.content[0].text
        findings = _parse_json_findings(raw, source="module_audit")

        return SafecodeReport(
            path=str(source_path),
            mode="module",
            findings=findings,
            summary=_extract_summary(raw),
            raw_text=raw,
        )

    @classmethod
    def audit_source(cls, path: str) -> SafecodeReport:
        """
        Run the source security audit pipeline on any codebase.

        Runs SourceContext → SourceEntryClassifier → SourceSinkScanner →
        SourceAuditCompressor. Returns sink findings (HIGH/MEDIUM/LOW), unauth
        route findings (MEDIUM), and priority read recommendations (INFO).

        Does not call the LLM — the pipeline is pure static analysis.
        The priority_reads in the report are the files that warrant LLM-assisted
        manual reads in the subsequent session phase.
        """
        repo_path = Path(path)
        if not repo_path.exists():
            raise FileNotFoundError(f"safecode.audit_source: path not found: {path}")

        ctx = SourceContext.from_path(str(repo_path))
        findings: list[SafecodeFinding] = []

        # Phase 1: entry classifier — NONE auth routes are highest-leverage attack surface.
        clf = SourceEntryClassifier.from_context(ctx)
        routes = clf.classify()
        for r in routes:
            if r.auth_level == "NONE" and not r.is_low_value:
                findings.append(SafecodeFinding(
                    severity="MEDIUM",
                    category="attack_surface",
                    title=f"Unauthenticated route: {r.rel_path}",
                    location=r.rel_path,
                    description=(
                        f"No authentication signal found ({r.matched_signal}). "
                        f"Input reaching a dangerous sink from this route is a full-chain finding."
                    ),
                    recommendation="Verify this route does not expose sensitive operations without auth.",
                    source="source_audit",
                ))

        # Phase 2: sink scanner — dangerous patterns across the entire codebase.
        scanner = SourceSinkScanner.from_context(ctx)
        sink_hits = scanner.scan()
        for sh in sink_hits:
            findings.append(SafecodeFinding(
                severity=sh.severity,
                category=sh.category,
                title=sh.description,
                location=f"{sh.rel_path}:{sh.line}",
                description=sh.line_text.strip(),
                recommendation=(
                    f"Trace {sh.cwe} pattern; verify all inputs are sanitized before this call."
                    + (" (guarded — severity already reduced)" if sh.guarded else "")
                ),
                source="source_audit",
                cwe=sh.cwe,
            ))

        # Phase 3: compressor — profiles 8+ need individual reads; surface as INFO.
        compressor = SourceAuditCompressor.from_context(ctx)
        buckets = compressor.compress()
        for bucket in SourceAuditCompressor.priority_reads(buckets):
            for fp in bucket.files:
                findings.append(SafecodeFinding(
                    severity="INFO",
                    category="priority_read",
                    title=f"Priority read: {fp.rel_path}",
                    location=fp.rel_path,
                    description=(
                        f"profile={fp.profile_str} signals={fp.signals} — {bucket.audit_action}"
                    ),
                    recommendation="Read this file individually; trace signals to their data origin.",
                    source="source_audit",
                ))

        ratio = SourceAuditCompressor.compression_ratio(buckets)
        total_files = sum(len(b.files) for b in buckets.values())
        summary = (
            f"{ctx.summary()} | "
            f"sink_hits={len(sink_hits)} | "
            f"unauth_routes={sum(1 for r in routes if r.auth_level == 'NONE' and not r.is_low_value)} | "
            f"priority_reads={sum(len(b.files) for b in SourceAuditCompressor.priority_reads(buckets))} | "
            f"compression={ratio:.1%} ({total_files} files)"
        )

        return SafecodeReport(
            path=str(repo_path),
            mode="source",
            findings=findings,
            summary=summary,
            raw_text=SourceAuditCompressor.report(buckets),
        )

    @classmethod
    def pre_commit_gate(
        cls,
        staged_files: list[str],
        repo_root: str = ".",
        model: str = _DEFAULT_MODEL,
    ) -> SafecodeReport:
        """
        Run audit_module on each staged Python file.

        Returns a combined SafecodeReport. gate_passed=False if any file has a
        HIGH or CRITICAL finding. Designed for use as a git pre-commit hook.

        Only audits .py files — non-Python staged files are skipped silently.
        One LLM call per file; keep staged batches small.
        """
        root = Path(repo_root)
        py_files = [
            f for f in staged_files
            if f.endswith('.py') and (root / f).exists()
        ]

        all_findings: list[SafecodeFinding] = []
        for rel_path in py_files:
            sub = cls.audit_module(str(root / rel_path), model=model)
            all_findings.extend(sub.findings)

        return SafecodeReport(
            path=str(root),
            mode="module",
            findings=all_findings,
            summary=f"pre_commit_gate: {len(py_files)} files audited, {len(all_findings)} findings",
        )


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog='safecode',
        description='SAFECODE: production readiness + source security auditor',
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    m = sub.add_parser('module', help='audit a single Python module (LLM)')
    m.add_argument('path', help='path to the .py file to audit')
    m.add_argument('--model', default=_DEFAULT_MODEL)

    s = sub.add_parser('source', help='audit a source codebase (pipeline, no LLM)')
    s.add_argument('path', help='path to the repository root')

    g = sub.add_parser('gate', help='pre-commit gate on staged .py files')
    g.add_argument('--repo', default='.', help='git repository root')
    g.add_argument('--model', default=_DEFAULT_MODEL)

    args = parser.parse_args()

    if args.cmd == 'module':
        report = SAFECODE.audit_module(args.path, model=args.model)
        print(report.report())
        if not report.gate_passed:
            print("\nSAFECODE BLOCKED — fix HIGH/CRITICAL findings before committing.")
            sys.exit(1)

    elif args.cmd == 'source':
        report = SAFECODE.audit_source(args.path)
        print(report.report())

    elif args.cmd == 'gate':
        try:
            staged = subprocess.check_output(
                ['git', 'diff', '--cached', '--name-only'],
                cwd=args.repo,
            ).decode().splitlines()
        except subprocess.CalledProcessError as e:
            print(f"safecode gate: git error: {e}", file=sys.stderr)
            sys.exit(2)

        if not staged:
            print("safecode gate: no staged files.")
            sys.exit(0)

        report = SAFECODE.pre_commit_gate(staged, repo_root=args.repo, model=args.model)
        print(report.report())
        sys.exit(0 if report.gate_passed else 1)


if __name__ == '__main__':
    _cli()
