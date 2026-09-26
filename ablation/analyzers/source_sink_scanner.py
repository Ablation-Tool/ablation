"""
source_sink_scanner.py: dangerous sink detection for source RE.

Finds dangerous code patterns across a repository: code eval, subprocess
execution, SSRF, path traversal, and unguarded internal endpoints. Each sink
class maps to a CWE and severity. A guard-condition detector narrows findings
by identifying env-var or conditional gates around sinks (reducing HIGH → MEDIUM
for gated sinks, as in LFG-CODEEVAL-1 where vm.runInContext was gated by
LANGFUSE_CODE_EVAL_DISPATCHER=insecure-local).

Analogous to dangerous_callers.py / format_string_scanner.py in binary RE.

Usage:
    from ablation.analyzers.source_ingestion import SourceContext
    from ablation.analyzers.source_sink_scanner import SourceSinkScanner

    ctx = SourceContext.from_path("/tmp/langfuse")
    scanner = SourceSinkScanner.from_context(ctx)
    findings = scanner.scan()
    print(scanner.report(findings))

    # Filter by severity
    highs = [f for f in findings if f.severity == "HIGH"]

CLI:
    python3 -m ablation.analyzers.source_sink_scanner /tmp/langfuse
    python3 -m ablation.analyzers.source_sink_scanner /tmp/langfuse --severity HIGH
"""

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from .source_ingestion import SourceContext
except ImportError:
    from source_ingestion import SourceContext

# ── sink definitions ─────────────────────────────────────────────────────────
# Each SinkDef describes a pattern class.
# pattern     : regex that matches the dangerous call or usage
# cwe         : CWE class
# severity    : baseline severity before guard reduction
# category    : short tag for grouping
# description : one-line human label

@dataclass(frozen=True)
class SinkDef:
    pattern: re.Pattern
    cwe: str
    severity: str
    category: str
    description: str


_SINK_DEFS: list[SinkDef] = [
    # ── Code evaluation ───────────────────────────────────────────────────────
    SinkDef(re.compile(r"\bvm\.runIn(New)?Context\b"),
            "CWE-94", "HIGH", "code-eval", "Node.js vm.runInContext (not a sandbox)"),
    SinkDef(re.compile(r"\bvm\.runInThisContext\b"),
            "CWE-94", "HIGH", "code-eval", "Node.js vm.runInThisContext"),
    SinkDef(re.compile(r"\bnew\s+Function\s*\("),
            "CWE-94", "HIGH", "code-eval", "new Function() constructor"),
    SinkDef(re.compile(r"(?<![.\w])eval\s*\("),
            "CWE-94", "HIGH", "code-eval", "eval() call"),
    SinkDef(re.compile(r"\bexec\s*\(\s*[`'\"].*\$\{"),
            "CWE-78", "HIGH", "code-eval", "exec() with template-literal interpolation"),
    SinkDef(re.compile(r"\bFunction\s*\(\s*['\"`]return\s+process"),
            "CWE-94", "CRITICAL", "code-eval", "vm escape: Function('return process')()"),

    # ── Subprocess / OS command ───────────────────────────────────────────────
    SinkDef(re.compile(r"\bspawn\s*\(\s*['\"`]?sh\b"),
            "CWE-78", "HIGH", "subprocess", "spawn('sh', ...) — shell interpreter"),
    SinkDef(re.compile(r"\bspawn\s*\(\s*['\"`](?!sh\b)[a-zA-Z]"),
            "CWE-78", "MEDIUM", "subprocess", "spawn() with static command"),
    SinkDef(re.compile(r"\bexecSync\s*\(|\bexecFile\s*\("),
            "CWE-78", "MEDIUM", "subprocess", "execSync / execFile"),
    SinkDef(re.compile(r"\bos\.system\s*\(|\bsubprocess\.run\s*\(.*shell\s*=\s*True"),
            "CWE-78", "HIGH", "subprocess", "Python shell=True subprocess"),
    SinkDef(re.compile(r"\bCommand::new\s*\("),
            "CWE-78", "MEDIUM", "subprocess", "Rust std::process::Command"),

    # ── SSRF / internal fetch ─────────────────────────────────────────────────
    SinkDef(re.compile(r"fetch\s*\(\s*['\"`][^'\"`]*localhost"),
            "CWE-918", "MEDIUM", "ssrf", "fetch to localhost (internal service)"),
    SinkDef(re.compile(r"fetch\s*\(\s*['\"`][^'\"`]*127\.0\.0\.1"),
            "CWE-918", "MEDIUM", "ssrf", "fetch to 127.0.0.1 (loopback)"),
    SinkDef(re.compile(r"fetch\s*\(\s*['\"`][^'\"`]*:\s*5000"),
            "CWE-918", "HIGH", "ssrf", "fetch to :5000 (sandbox server port)"),
    SinkDef(re.compile(r"fetch\s*\(\s*['\"`][^'\"`]*172\.(1[6-9]|2[0-9]|3[0-1])\."),
            "CWE-918", "MEDIUM", "ssrf", "fetch to RFC1918 172.16-31.x.x range"),
    SinkDef(re.compile(r"\b(axios|got|request)\s*\.\s*(get|post)\s*\(\s*.*\$\{"),
            "CWE-918", "MEDIUM", "ssrf", "HTTP client call with interpolated URL"),

    # ── Path traversal ────────────────────────────────────────────────────────
    SinkDef(re.compile(r"path\.join\s*\([^)]*req\.(body|query|params)"),
            "CWE-22", "HIGH", "path-traversal", "path.join with request input"),
    SinkDef(re.compile(r"fs\.(readFile|writeFile|unlink|mkdir)\s*\([^)]*req\.(body|query|params)"),
            "CWE-22", "HIGH", "path-traversal", "fs operation with request input"),
    SinkDef(re.compile(r"open\s*\([^)]*request\.(body|args|form|files)"),
            "CWE-22", "HIGH", "path-traversal", "Python file open with request input"),

    # ── Prototype pollution / object injection ────────────────────────────────
    SinkDef(re.compile(r"Object\.assign\s*\(\s*(req|request)\.(body|query)"),
            "CWE-1321", "MEDIUM", "prototype-pollution", "Object.assign from request body"),
    SinkDef(re.compile(r"\[.*req\.(body|query)\[.*\]\s*\]\s*="),
            "CWE-1321", "MEDIUM", "prototype-pollution", "computed property assignment from request"),

    # ── Deserialisation ───────────────────────────────────────────────────────
    SinkDef(re.compile(r"\bpickle\.loads?\s*\("),
            "CWE-502", "HIGH", "deserialisation", "Python pickle.load (RCE-capable deserialization)"),
    SinkDef(re.compile(r"\byaml\.load\s*\([^,)]+\)(?!\s*,\s*Loader)"),
            "CWE-502", "MEDIUM", "deserialisation", "PyYAML yaml.load without Loader (unsafe)"),
    SinkDef(re.compile(r"\beval\s*\(.*JSON"),
            "CWE-502", "MEDIUM", "deserialisation", "eval(JSON...) instead of JSON.parse"),

    # ── SQL / NoSQL injection ─────────────────────────────────────────────────
    SinkDef(re.compile(r"Prisma\.raw\s*\("),
            "CWE-89", "MEDIUM", "sqli", "Prisma.raw() — verify parameterization"),
    SinkDef(re.compile(r"queryRaw\s*\(\s*['\"`][^'\"`]*\$\{"),
            "CWE-89", "HIGH", "sqli", "Prisma queryRaw with string interpolation"),
    SinkDef(re.compile(r"\.query\s*\(\s*['\"`][^'\"`]*\+"),
            "CWE-89", "HIGH", "sqli", "DB query with string concatenation"),

    # ── Redirect / open redirect ──────────────────────────────────────────────
    SinkDef(re.compile(r"res\.redirect\s*\([^)]*req\.(query|body|params)"),
            "CWE-601", "MEDIUM", "open-redirect", "res.redirect with request input"),
    SinkDef(re.compile(r"callbackUrl\s*=\s*req\.(query|body)"),
            "CWE-601", "MEDIUM", "open-redirect", "callbackUrl from request input"),
]

# ── guard condition patterns ──────────────────────────────────────────────────
# If a sink is surrounded by one of these, reduce severity by one level.
_GUARD_PATTERNS: list[re.Pattern] = [
    re.compile(r'env\.\w+\s*===?\s*["\'][^"\']+["\']'),      # env.FOO === 'value'
    re.compile(r'process\.env\.\w+\s*===?\s*["\']'),          # process.env.FOO === '...'
    re.compile(r'NODE_ENV\s*===?\s*["\']development'),         # NODE_ENV === 'development'
    re.compile(r'if\s*\(\s*!?\s*\w+Enabled\s*\)'),            # if (!featureEnabled)
    re.compile(r'LANGFUSE_\w+\s*===?\s*["\']'),               # LANGFUSE_* config gate
]

_SEVERITY_DOWNGRADE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO"}


def _reduce_severity(severity: str, guarded: bool) -> str:
    if guarded:
        return _SEVERITY_DOWNGRADE.get(severity, severity)
    return severity


@dataclass
class SinkHit:
    """One detected dangerous sink location."""
    path: Path
    rel_path: str
    line: int
    line_text: str
    category: str
    cwe: str
    severity: str          # after guard reduction
    base_severity: str     # before guard reduction
    description: str
    guarded: bool          # True if a guard condition was detected nearby
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "path": self.rel_path,
            "line": self.line,
            "category": self.category,
            "cwe": self.cwe,
            "severity": self.severity,
            "guarded": self.guarded,
            "description": self.description,
            "match": self.line_text.strip(),
        }


class SourceSinkScanner:
    """
    Scans source files for dangerous sinks.

    Each match is checked for nearby guard conditions; guarded sinks have
    their severity downgraded by one level.
    """

    CONTEXT_LINES = 6   # lines above/below match to check for guards

    def __init__(self, ctx: SourceContext):
        self.ctx = ctx

    @classmethod
    def from_context(cls, ctx: SourceContext) -> "SourceSinkScanner":
        return cls(ctx)

    def _check_guards(self, lines: list[str], match_idx: int) -> bool:
        window_start = max(0, match_idx - self.CONTEXT_LINES)
        window_end = min(len(lines), match_idx + self.CONTEXT_LINES + 1)
        window = "\n".join(lines[window_start:window_end])
        return any(p.search(window) for p in _GUARD_PATTERNS)

    def _scan_file(self, path: Path) -> list[SinkHit]:
        text = self.ctx.read(path)
        if not text:
            return []
        lines = text.splitlines()
        hits: list[SinkHit] = []
        rel = self.ctx.rel(path)

        is_test = any(frag in rel for frag in (".test.", ".spec.", "__tests__", ".servertest.", ".clienttest.", ".gatewaye2e."))
        seen: set[tuple[int, str]] = set()  # deduplicate (line, category)

        for sink in _SINK_DEFS:
            for i, line in enumerate(lines):
                if not sink.pattern.search(line):
                    continue
                key = (i, sink.category)
                if key in seen:
                    continue
                seen.add(key)

                guarded = self._check_guards(lines, i)
                severity = _reduce_severity(sink.severity, guarded)
                if is_test:
                    severity = _reduce_severity(severity, True)

                before = lines[max(0, i - 3): i]
                after = lines[i + 1: i + 4]

                hits.append(SinkHit(
                    path=path,
                    rel_path=rel,
                    line=i + 1,
                    line_text=line,
                    category=sink.category,
                    cwe=sink.cwe,
                    severity=severity,
                    base_severity=sink.severity,
                    description=sink.description,
                    guarded=guarded,
                    context_before=before,
                    context_after=after,
                ))
        return hits

    def scan(self, files: Optional[list[Path]] = None) -> list[SinkHit]:
        """
        Scan files for dangerous sinks.

        If files is None, scans all source files in ctx.
        Returns hits sorted by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO).
        """
        targets = files if files is not None else self.ctx.all_files
        all_hits: list[SinkHit] = []
        for f in targets:
            all_hits.extend(self._scan_file(f))

        _rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_hits.sort(key=lambda h: (_rank.get(h.severity, 5), h.rel_path, h.line))
        return all_hits

    @staticmethod
    def report(findings: list[SinkHit], severity_filter: Optional[str] = None) -> str:
        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        lines = ["Sink Scanner Results", "=" * 60]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            n = counts.get(sev, 0)
            if n:
                lines.append(f"  {sev:<10} {n}")
        lines.append("")

        current_sev = None
        for h in findings:
            if h.severity != current_sev:
                current_sev = h.severity
                lines.append(f"── {h.severity} ─────────────────────────────────")
            guard_tag = " [guarded]" if h.guarded else ""
            lines.append(f"  {h.rel_path}:{h.line}  {h.cwe}  {h.description}{guard_tag}")
            lines.append(f"    {h.line_text.strip()}")
        return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse
    ap = argparse.ArgumentParser(prog="source_sink_scanner", description="Scan repo for dangerous sinks")
    ap.add_argument("path", help="Repo path")
    ap.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    help="Filter to one severity level")
    ap.add_argument("--category", help="Filter to one category (code-eval, subprocess, ssrf, ...)")
    args = ap.parse_args()

    ctx = SourceContext.from_path(args.path)
    scanner = SourceSinkScanner.from_context(ctx)
    findings = scanner.scan()

    if args.category:
        findings = [f for f in findings if f.category == args.category]

    print(scanner.report(findings, severity_filter=args.severity))


if __name__ == "__main__":
    _cli()
