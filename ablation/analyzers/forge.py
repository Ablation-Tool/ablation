"""
forge.py — FORGE: module development, validation, and local storage for Ablation.

FORGE is the quality gate for any Python module built on Ablation — native or local.
Before code commits or registers to the local store, FORGE runs the full
Ablation-SAFE CODE.md 10-section production readiness audit via Claude and produces
a DEV & TEST ORCHESTRATION PLAN from the findings.

Three entry points:

    FORGE.audit_module(path)     — 10-section LLM audit on a single .py file.
                                    Returns ForgeReport; gate_passed=False on
                                    any HIGH or CRITICAL finding.

    FORGE.audit_source(path)     — source security audit on any codebase.
                                    SourceContext → SourceEntryClassifier →
                                    SourceSinkScanner → SourceAuditCompressor.
                                    No LLM required. Returns ranked findings.

    FORGE.register(path)         — validate a module with audit_module, then
                                    copy it to ~/.ablation/local_modules/ so it
                                    loads automatically in future sessions.
                                    Blocks if gate_passed is False.

Local module store:

    ~/.ablation/local_modules/   — user-owned modules. Separate from native
                                    Ablation modules. Never overwritten by
                                    Ablation updates. Loaded at session start
                                    via FORGE.load_local_modules().

Usage:
    from ablation.analyzers.forge import FORGE

    # Audit a module before committing (required by Ablation-SAFE CODE.md SOP)
    report = FORGE.audit_module('/home/cowboy/ablation/ablation/analyzers/new_module.py')
    print(report.report())
    if not report.gate_passed:
        raise SystemExit("FORGE BLOCKED: fix HIGH/CRITICAL findings before committing")

    # Register a local module (validates + stores)
    report = FORGE.register('~/my_work/my_scanner.py')

    # Load all local modules at session start
    FORGE.load_local_modules()

    # Source audit: any codebase, no LLM
    report = FORGE.audit_source('/tmp/target-repo')
    print(report.report())

CLI:
    python3 -m ablation.analyzers.forge module /path/to/module.py
    python3 -m ablation.analyzers.forge source /path/to/repo
    python3 -m ablation.analyzers.forge register /path/to/module.py
    python3 -m ablation.analyzers.forge list
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
import warnings

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

_LOCAL_MODULES_DIR = Path.home() / '.ablation' / 'local_modules'

# SOP system prompt search order: package data first, external drive fallback.
_PROMPT_CANDIDATES = [
    Path(__file__).parent.parent / 'data' / 'forge_system.md',
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
For each finding in sections 2-4 and 7 include:
Title, Severity (CRITICAL/HIGH/MEDIUM/LOW), Location, Description, Recommendation.
After section 10 append:
FORGE_JSON: [{"severity":"HIGH","category":"...","title":"...","location":"...",
"description":"...","recommendation":"...","cwe":""}]
"""


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class ForgeFinding:
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str       # section name or sink category
    title: str
    location: str       # file:line or function name
    description: str
    recommendation: str
    source: str         # "module_audit" or "source_audit"
    cwe: str = ""


@dataclass
class ForgeReport:
    path: str
    mode: str           # "module" or "source"
    findings: list[ForgeFinding] = field(default_factory=list)
    summary: str = ""
    raw_text: str = ""  # full LLM output (module) or compressor report (source)

    @property
    def gate_passed(self) -> bool:
        return not any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

    def highs(self) -> list[ForgeFinding]:
        return [f for f in self.findings if f.severity in ("CRITICAL", "HIGH")]

    def report(self) -> str:
        n_crit   = sum(1 for f in self.findings if f.severity == "CRITICAL")
        n_high   = sum(1 for f in self.findings if f.severity == "HIGH")
        n_medium = sum(1 for f in self.findings if f.severity == "MEDIUM")
        n_low    = sum(1 for f in self.findings if f.severity == "LOW")
        n_info   = sum(1 for f in self.findings if f.severity == "INFO")

        lines = [
            f"FORGE [{self.mode.upper()}] — {self.path}",
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
            lines += ["", "Summary:", f"  {self.summary}"]
        return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _load_system_prompt() -> str:
    for candidate in _PROMPT_CANDIDATES:
        if candidate.exists():
            return candidate.read_text(encoding='utf-8')
    warnings.warn(
        "FORGE: forge_system.md not found in package data or on external drive. "
        "Using minimal fallback prompt — DEV & TEST ORCHESTRATION PLAN will be absent. "
        "Run: cp '/media/cowboy/research/repos/Downloads/Ablation-SAFE CODE.md' "
        f"{_PROMPT_CANDIDATES[0]}",
        stacklevel=3,
    )
    return _PROMPT_FALLBACK


def _parse_json_findings(raw: str, source: str) -> list[ForgeFinding]:
    m = re.search(r'FORGE_JSON:\s*(\[.*?\])\s*$', raw, re.DOTALL | re.MULTILINE)
    if not m:
        return _parse_prose_findings(raw, source)
    try:
        items = json.loads(m.group(1))
        findings = []
        for item in items:
            if not isinstance(item, dict):
                continue
            findings.append(ForgeFinding(
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


def _parse_prose_findings(raw: str, source: str) -> list[ForgeFinding]:
    findings: list[ForgeFinding] = []
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
        findings.append(ForgeFinding(
            severity=sev_map.get(sev_raw, sev_raw),
            category='module_audit',
            title=title,
            location='',
            description='',
            recommendation='',
            source=source,
        ))
    return findings


def _extract_summary(raw: str) -> str:
    m = re.search(
        r'10\.\s+Residual Risk[^\n]*\n((?:.|\n){20,300}?)(?:\n\n|\Z)',
        raw, re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()[:300]
    return ""


# ── Main class ────────────────────────────────────────────────────────────────

class FORGE:
    """
    Module development, validation, and local storage for Ablation.

    All methods are classmethods; no instantiation needed.
    """

    # ── Audit ─────────────────────────────────────────────────────────────────

    @classmethod
    def audit_module(
        cls,
        path: str,
        model: str = _DEFAULT_MODEL,
    ) -> ForgeReport:
        """
        Run the Ablation-SAFE CODE.md 10-section production audit on a single file.

        Required before git add on any new or modified Ablation module.
        Required before FORGE.register() on any local module.
        Returns ForgeReport; gate_passed=False blocks on any HIGH/CRITICAL finding.
        Requires ablation[llm] (pip install 'ablation[llm]').
        """
        if not _ANTHROPIC_AVAILABLE:
            raise ImportError(
                "FORGE.audit_module requires anthropic. "
                "Install with: pip install 'ablation[llm]'"
            )

        source_path = Path(path).expanduser().resolve()
        if not source_path.exists():
            raise FileNotFoundError(f"FORGE.audit_module: file not found: {path}")

        code = source_path.read_text(encoding='utf-8', errors='replace')
        system = _load_system_prompt()

        user_msg = (
            f"Audit this file: {source_path.name}\n\n"
            f"```\n{code}\n```\n\n"
            "After completing all 10 sections and the DEV & TEST ORCHESTRATION PLAN, "
            "append exactly one final line in this format (no line break inside the JSON):\n"
            "FORGE_JSON: [{\"severity\": \"HIGH\", \"category\": \"functional_correctness\", "
            "\"title\": \"...\", \"location\": \"...\", \"description\": \"...\", "
            "\"recommendation\": \"...\", \"cwe\": \"\"}]\n"
            "Include one object per finding from sections 2, 3, 4, and 7. "
            "Severity must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO."
        )

        client = _anthropic.Anthropic(timeout=120.0)
        resp = client.messages.create(
            model=model,
            max_tokens=16384,
            system=system,
            messages=[{"role": "user", "content": user_msg}],
        )

        raw = resp.content[0].text if resp.content else ""
        if not raw:
            warnings.warn(
                "FORGE.audit_module: LLM returned empty content — audit incomplete, "
                "gate result may be unreliable. Check model availability and token limits.",
                stacklevel=2,
            )
        findings = _parse_json_findings(raw, source="module_audit")

        return ForgeReport(
            path=str(source_path),
            mode="module",
            findings=findings,
            summary=_extract_summary(raw),
            raw_text=raw,
        )

    @classmethod
    def audit_source(cls, path: str) -> ForgeReport:
        """
        Run the source security audit pipeline on any codebase.

        SourceContext → SourceEntryClassifier → SourceSinkScanner →
        SourceAuditCompressor. No LLM. Works on any language, any size.

        Returns ForgeReport with:
          - sink findings (CRITICAL/HIGH/MEDIUM/LOW)
          - unauthenticated route findings (MEDIUM)
          - priority read recommendations (INFO) — the files worth reading manually
        """
        repo_path = Path(path).expanduser().resolve()
        if not repo_path.exists():
            raise FileNotFoundError(f"FORGE.audit_source: path not found: {path}")

        ctx = SourceContext.from_path(str(repo_path))
        findings: list[ForgeFinding] = []

        # Phase 1: unauthenticated routes — full-chain attack surface.
        clf = SourceEntryClassifier.from_context(ctx)
        routes = clf.classify()
        for r in routes:
            if r.auth_level == "NONE" and not r.is_low_value:
                findings.append(ForgeFinding(
                    severity="MEDIUM",
                    category="attack_surface",
                    title=f"Unauthenticated route: {r.rel_path}",
                    location=r.rel_path,
                    description=(
                        f"No authentication signal found ({r.matched_signal}). "
                        "Input reaching a dangerous sink from here is a full-chain finding."
                    ),
                    recommendation="Verify this route does not expose sensitive operations without auth.",
                    source="source_audit",
                ))

        # Phase 2: sink scanner — dangerous patterns across the entire codebase.
        scanner = SourceSinkScanner.from_context(ctx)
        sink_hits = scanner.scan()
        for sh in sink_hits:
            findings.append(ForgeFinding(
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
                findings.append(ForgeFinding(
                    severity="INFO",
                    category="priority_read",
                    title=f"Priority read: {fp.rel_path}",
                    location=fp.rel_path,
                    description=f"profile={fp.profile_str} signals={fp.signals} — {bucket.audit_action}",
                    recommendation="Read individually; trace signals to their data origin.",
                    source="source_audit",
                ))

        ratio = SourceAuditCompressor.compression_ratio(buckets)
        total = sum(len(b.files) for b in buckets.values())
        n_unauth = sum(1 for r in routes if r.auth_level == "NONE" and not r.is_low_value)
        n_reads  = sum(len(b.files) for b in SourceAuditCompressor.priority_reads(buckets))

        summary = (
            f"{ctx.summary()} | "
            f"sinks={len(sink_hits)} | unauth_routes={n_unauth} | "
            f"priority_reads={n_reads} | compression={ratio:.1%} ({total} files)"
        )

        return ForgeReport(
            path=str(repo_path),
            mode="source",
            findings=findings,
            summary=summary,
            raw_text=SourceAuditCompressor.report(buckets),
        )

    # ── Local module store ────────────────────────────────────────────────────

    @classmethod
    def register(
        cls,
        path: str,
        model: str = _DEFAULT_MODEL,
        force: bool = False,
    ) -> ForgeReport:
        """
        Validate a module with audit_module, then copy it to ~/.ablation/local_modules/.

        Blocks registration if the audit gate fails (any HIGH/CRITICAL finding).
        Pass force=True to register despite findings (not recommended).

        The module loads automatically in future sessions via load_local_modules().
        """
        source_path = Path(path).expanduser().resolve()
        if not source_path.exists():
            raise FileNotFoundError(f"FORGE.register: file not found: {path}")
        if not source_path.suffix == '.py':
            raise ValueError(f"FORGE.register: only .py files can be registered: {path}")

        report = cls.audit_module(str(source_path), model=model)

        if not report.gate_passed and not force:
            raise RuntimeError(
                f"FORGE.register: gate failed for {source_path.name} — "
                f"{len(report.highs())} HIGH/CRITICAL finding(s). "
                "Fix all findings before registering. Use force=True to override."
            )

        _LOCAL_MODULES_DIR.mkdir(parents=True, exist_ok=True)
        dest = _LOCAL_MODULES_DIR / source_path.name
        if dest.exists():
            warnings.warn(
                f"FORGE.register: overwriting existing local module {dest.name}",
                stacklevel=2,
            )
        shutil.copy2(source_path, dest)
        if dest.stat().st_size != source_path.stat().st_size:
            raise RuntimeError(
                f"FORGE.register: copy size mismatch for {dest} "
                f"({dest.stat().st_size} != {source_path.stat().st_size}) — "
                "file may be corrupt"
            )

        return report

    @classmethod
    def load_local_modules(cls) -> list[str]:
        """
        Import all .py files from ~/.ablation/local_modules/ into the current session.

        Returns a list of successfully loaded module names.
        Call once at session start after importing ablation.
        """
        if not _LOCAL_MODULES_DIR.exists():
            return []

        loaded: list[str] = []
        for module_file in sorted(_LOCAL_MODULES_DIR.glob('*.py')):
            if module_file.name.startswith('_'):
                continue
            module_name = f"ablation_local.{module_file.stem}"
            try:
                if module_name in sys.modules:
                    loaded.append(module_file.stem)
                    continue
                spec = importlib.util.spec_from_file_location(module_name, module_file)
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = mod
                spec.loader.exec_module(mod)
                loaded.append(module_file.stem)
            except Exception as e:
                print(f"FORGE: failed to load local module {module_file.name}: {e}",
                      file=sys.stderr)

        return loaded

    @classmethod
    def list_local_modules(cls) -> list[str]:
        """List all .py files registered in ~/.ablation/local_modules/."""
        if not _LOCAL_MODULES_DIR.exists():
            return []
        return sorted(p.stem for p in _LOCAL_MODULES_DIR.glob('*.py')
                      if not p.name.startswith('_'))


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog='forge',
        description='FORGE: module validation and local storage for Ablation',
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    m = sub.add_parser('module', help='audit a single .py file (LLM)')
    m.add_argument('path', help='path to the .py file to audit')
    m.add_argument('--model', default=_DEFAULT_MODEL)

    s = sub.add_parser('source', help='audit a source codebase (pipeline, no LLM)')
    s.add_argument('path', help='path to the repository root')

    r = sub.add_parser('register', help='validate and register a local module')
    r.add_argument('path', help='path to the .py file to register')
    r.add_argument('--model', default=_DEFAULT_MODEL)
    r.add_argument('--force', action='store_true',
                   help='register even if gate fails (not recommended)')

    sub.add_parser('list', help='list registered local modules')

    args = parser.parse_args()

    if args.cmd == 'module':
        report = FORGE.audit_module(args.path, model=args.model)
        print(report.report())
        sys.exit(0 if report.gate_passed else 1)

    elif args.cmd == 'source':
        report = FORGE.audit_source(args.path)
        print(report.report())

    elif args.cmd == 'register':
        try:
            report = FORGE.register(args.path, model=args.model, force=args.force)
            print(report.report())
            dest = _LOCAL_MODULES_DIR / Path(args.path).name
            print(f"\nRegistered: {dest}")
        except RuntimeError as e:
            print(f"FORGE: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.cmd == 'list':
        modules = FORGE.list_local_modules()
        if not modules:
            print("No local modules registered.")
        else:
            print(f"Local modules ({len(modules)}) in {_LOCAL_MODULES_DIR}:")
            for name in modules:
                print(f"  {name}")


if __name__ == '__main__':
    _cli()
