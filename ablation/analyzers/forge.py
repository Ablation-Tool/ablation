"""
forge.py — FORGE: module development, validation, and local storage for Ablation.

FORGE is the quality gate for any Python module built on Ablation — native or local.
Before code commits or registers to the local store, FORGE requires the full
Ablation-SAFE CODE.md 10-section production readiness audit with a DEV & TEST
ORCHESTRATION PLAN. The audit is performed inline by Claude Code reading the file
directly — no subprocess, no Anthropic API key.

Three entry points:

    FORGE.audit_module(path)     — check cache for a prior SAFE CODE audit result.
                                    Returns ForgeReport on hit; raises
                                    ForgeAuditRequired on miss. Perform the audit
                                    inline, then call FORGE.record_result().

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

import hashlib
import importlib.util
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
import warnings

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


# ── Result cache ─────────────────────────────────────────────────────────────

_CACHE_PATH = Path.home() / '.ablation' / 'forge_cache.json'


class _ForgeCache:
    """
    Persistent cache for FORGE module audit results.

    Key: sha256(system_prompt)[:16] + ":" + sha256(file_bytes)[:16]
    Any change to the SOP file or the module source invalidates the entry.
    raw_text is not cached (too large); all other ForgeReport fields are.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            if _CACHE_PATH.exists():
                self._data = json.loads(_CACHE_PATH.read_text(encoding='utf-8'))
        except Exception:
            self._data = {}

    @staticmethod
    def _key(system: str, file_path: str) -> str:
        sys_h = hashlib.sha256(system.encode()).hexdigest()[:16]
        file_h = hashlib.sha256(Path(file_path).read_bytes()).hexdigest()[:16]
        return f"{sys_h}:{file_h}"

    def get(self, system: str, file_path: str) -> 'ForgeReport | None':
        self._ensure_loaded()
        entry = self._data.get(self._key(system, file_path))
        if not entry:
            return None
        try:
            findings = [ForgeFinding(**f) for f in entry['findings']]
            return ForgeReport(
                path=entry['path'],
                mode=entry['mode'],
                findings=findings,
                summary=entry.get('summary', ''),
                raw_text='',
            )
        except Exception:
            return None

    def put(self, system: str, report: 'ForgeReport') -> None:
        self._ensure_loaded()
        key = self._key(system, report.path)
        self._data[key] = {
            'path': report.path,
            'mode': report.mode,
            'findings': [
                {
                    'severity': f.severity, 'category': f.category,
                    'title': f.title, 'location': f.location,
                    'description': f.description, 'recommendation': f.recommendation,
                    'source': f.source, 'cwe': f.cwe,
                }
                for f in report.findings
            ],
            'summary': report.summary,
        }
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CACHE_PATH.with_suffix('.tmp')
        try:
            tmp.write_text(json.dumps(self._data, indent=2), encoding='utf-8')
            tmp.replace(_CACHE_PATH)
        except Exception:
            pass


_forge_cache = _ForgeCache()


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



# ── Exceptions ───────────────────────────────────────────────────────────────

class ForgeAuditRequired(Exception):
    """Raised by audit_module() when no cached result exists.

    Perform the SAFE CODE 10-section audit inline as Claude Code, then call
    FORGE.record_result() to store it. Future audit_module() calls will
    return the cached result instantly.
    """


# ── Main class ────────────────────────────────────────────────────────────────

class FORGE:
    """
    Module development, validation, and local storage for Ablation.

    All methods are classmethods; no instantiation needed.
    """

    # ── Audit ─────────────────────────────────────────────────────────────────

    @classmethod
    def audit_module(cls, path: str) -> ForgeReport:
        """
        Return a cached FORGE audit for a module, or raise ForgeAuditRequired.

        On a cache hit, returns the ForgeReport immediately — no subprocess, no LLM call.
        On a cache miss, raises ForgeAuditRequired with instructions.

        The audit is always done inline: read the file in the Claude Code session,
        apply the SAFE CODE 10-section review, then call FORGE.record_result() to
        cache the result. Future calls return instantly from cache.
        """
        source_path = Path(path).expanduser().resolve()
        if not source_path.exists():
            raise FileNotFoundError(f"FORGE.audit_module: file not found: {path}")

        system = _load_system_prompt()
        cached = _forge_cache.get(system, str(source_path))
        if cached is not None:
            return cached

        raise ForgeAuditRequired(
            f"No cached audit for {source_path.name}. "
            f"Read the file and perform the SAFE CODE 10-section audit inline as Claude Code, "
            f"then call:\n"
            f"  FORGE.record_result('{source_path}', findings, summary)"
        )

    @classmethod
    def record_result(
        cls,
        path: str,
        findings: 'list[ForgeFinding] | list[dict]',
        summary: str = '',
        raw_text: str = '',
    ) -> ForgeReport:
        """
        Store the result of an inline SAFE CODE audit performed by Claude Code.

        Call this after reading a module and completing the 10-section review inline.
        Populates the cache so future audit_module() calls return instantly.

        findings can be a list of ForgeFinding objects or a list of dicts with keys:
        severity, category, title, location, description, recommendation, source, cwe.
        """
        source_path = Path(path).expanduser().resolve()
        if not source_path.exists():
            raise FileNotFoundError(f"FORGE.record_result: file not found: {path}")

        system = _load_system_prompt()
        normalized: list[ForgeFinding] = []
        for f in findings:
            if isinstance(f, ForgeFinding):
                normalized.append(f)
            elif isinstance(f, dict):
                normalized.append(ForgeFinding(
                    severity=str(f.get('severity', 'INFO')).upper(),
                    category=str(f.get('category', 'module_audit')),
                    title=str(f.get('title', '')),
                    location=str(f.get('location', '')),
                    description=str(f.get('description', '')),
                    recommendation=str(f.get('recommendation', '')),
                    source=str(f.get('source', 'module_audit')),
                    cwe=str(f.get('cwe', '')),
                ))

        report = ForgeReport(
            path=str(source_path),
            mode='module',
            findings=normalized,
            summary=summary,
            raw_text=raw_text,
        )
        _forge_cache.put(system, report)
        return report

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
    def register(cls, path: str, force: bool = False) -> ForgeReport:
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

        try:
            report = cls.audit_module(str(source_path))
        except ForgeAuditRequired as e:
            raise ForgeAuditRequired(
                f"FORGE.register: no cached audit for {source_path.name}. "
                f"Run FORGE.audit_module() inline first, then call FORGE.record_result() "
                f"to cache the result before registering.\n{e}"
            ) from None

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

    m = sub.add_parser('module', help='audit a single .py file')
    m.add_argument('path', help='path to the .py file to audit')

    s = sub.add_parser('source', help='audit a source codebase (pipeline, no LLM)')
    s.add_argument('path', help='path to the repository root')

    r = sub.add_parser('register', help='validate and register a local module')
    r.add_argument('path', help='path to the .py file to register')
    r.add_argument('--force', action='store_true',
                   help='register even if gate fails (not recommended)')

    sub.add_parser('list', help='list registered local modules')

    args = parser.parse_args()

    if args.cmd == 'module':
        try:
            report = FORGE.audit_module(args.path)
        except ForgeAuditRequired as e:
            print(f"FORGE: audit required\n{e}", file=sys.stderr)
            print(
                "\nHow to proceed:\n"
                "  1. Open this file in your Claude Code session.\n"
                "  2. Read it and perform the SAFE CODE 10-section audit inline.\n"
                "  3. Call FORGE.record_result(path, findings, summary) to cache.\n"
                "  4. Re-run this command — it will return instantly from cache.",
                file=sys.stderr,
            )
            sys.exit(2)
        print(report.report())
        sys.exit(0 if report.gate_passed else 1)

    elif args.cmd == 'source':
        report = FORGE.audit_source(args.path)
        print(report.report())

    elif args.cmd == 'register':
        try:
            report = FORGE.register(args.path, force=args.force)
            print(report.report())
            dest = _LOCAL_MODULES_DIR / Path(args.path).name
            print(f"\nRegistered: {dest}")
        except ForgeAuditRequired as e:
            print(f"FORGE: {e}", file=sys.stderr)
            sys.exit(2)
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
