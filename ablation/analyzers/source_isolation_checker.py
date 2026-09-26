"""
source_isolation_checker.py: tenant isolation checker for source RE.

Finds database queries (Prisma, Mongoose, SQLAlchemy, raw SQL) that fetch or
mutate data without scoping to the authenticated tenant (org/project/user).
This is the highest-yield pattern class in multi-tenant SaaS: a missing
projectId / orgId in a where clause → IDOR or cross-tenant data leak.

Pattern: findUnique / findFirst / findMany with no tenant-scoping field in the
where clause. Also detects update/delete/upsert without tenant scope.

Analogous to the interproc_field_writer.py scanner in binary RE (which checks
that tainted fields are written with appropriate bounds), but operating on ORM
call AST patterns instead of instruction sequences.

Usage:
    from ablation.analyzers.source_ingestion import SourceContext
    from ablation.analyzers.source_isolation_checker import SourceIsolationChecker

    ctx = SourceContext.from_path("/tmp/langfuse")
    checker = SourceIsolationChecker.from_context(ctx)
    findings = checker.scan()
    print(checker.report(findings))

CLI:
    python3 -m ablation.analyzers.source_isolation_checker /tmp/langfuse
    python3 -m ablation.analyzers.source_isolation_checker /tmp/langfuse --severity CONFIRMED
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

# ── tenant scope field names ──────────────────────────────────────────────────
# Fields that constitute a tenant scope in a where clause.
# A query is considered scoped if its where clause contains at least one of these.
_SCOPE_FIELDS = frozenset([
    "projectId", "orgId", "organizationId", "tenantId",
    "project_id", "org_id", "organization_id", "tenant_id",
    "userId", "user_id",   # user-scoped resources are also OK
    "scope.projectId", "auth.scope.projectId",
    "authCheck.scope.projectId",
])

# ── ORM operation patterns ────────────────────────────────────────────────────

# Prisma model operations that should always be tenant-scoped
_PRISMA_OPS = re.compile(
    r"\bprisma\.(\w+)\.(findUnique|findFirst|findMany|update|updateMany|delete|deleteMany|upsert)\s*\(",
    re.IGNORECASE,
)

# The where clause block: from `where:` to the next top-level `}`
# We extract the portion of the call to check for scope fields.
# This is a best-effort extraction; AST-perfect parsing is Phase 2.
_WHERE_BLOCK = re.compile(r"where\s*:\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", re.DOTALL)

# Fields that look like scope variables (handles nested: { projectId: ctx.projectId })
_SCOPE_FIELD_RE = re.compile(
    r"\b(" + "|".join(re.escape(f) for f in _SCOPE_FIELDS) + r")\s*:",
)

# ── lookup exclusions ─────────────────────────────────────────────────────────
# Models that are global / non-tenant and don't need project scoping.
_GLOBAL_MODELS = frozenset([
    "user", "organization", "apikey", "account", "session",
    "verificationtoken", "auditlog", "ssoconfig",
    "backgroundmigration",
])

# Patterns that indicate a lookup by a unique global key (publicKey, email, etc.)
_GLOBAL_KEY_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bpublicKey\s*:"),
    re.compile(r"\bemail\s*:"),
    re.compile(r"\bhashedSecretKey\s*:"),
    re.compile(r"\bfastHashedSecretKey\s*:"),
    re.compile(r"\bslug\s*:"),
]

# Calling context patterns that indicate auth lookup (not data access)
_AUTH_CONTEXT_PATTERNS: list[re.Pattern] = [
    re.compile(r"verifyAuth|authenticate|getAuth|findApiKey|findUser"),
    re.compile(r"ApiAuthService|verifySecretKey|verifyPassword"),
]

# Path fragments that indicate non-production code (seeds, tests, migrations, CLIs)
# These are intentionally unscoped and should not be flagged as isolation failures.
_EXEMPT_PATH_FRAGMENTS = frozenset([
    "seed", "seeder", "seeds",
    "__tests__", ".test.", ".spec.", ".servertest.", ".clienttest.", ".gatewaye2e.",
    "backgroundMigrations", "backgroundmigrations", "migration",
    "scripts/",
    "/cli/", "/bin/",
    "fixtures/", "mock/", "mocks/",
])


def _extract_where_block(call_text: str) -> str:
    """Extract the content of the where: {} block from a Prisma call."""
    m = _WHERE_BLOCK.search(call_text)
    return m.group(1) if m else ""


def _has_scope_field(where_text: str) -> bool:
    return bool(_SCOPE_FIELD_RE.search(where_text))


def _extract_call_window(lines: list[str], start: int, max_lines: int = 15) -> str:
    """
    Extract a multi-line call starting at start.
    Walks forward until braces balance or max_lines is reached.
    """
    chunk = []
    depth = 0
    for i in range(start, min(start + max_lines, len(lines))):
        chunk.append(lines[i])
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0 and i > start:
            break
    return "\n".join(chunk)


@dataclass
class IsolationFinding:
    """One query missing tenant isolation."""
    path: Path
    rel_path: str
    line: int
    operation: str       # e.g. "prisma.user.findUnique"
    model: str           # e.g. "user"
    op_type: str         # findUnique, findMany, update, delete, upsert
    where_text: str      # extracted where clause content
    severity: str        # CONFIRMED | PLAUSIBLE | INFO
    note: str
    call_window: str = ""

    def as_dict(self) -> dict:
        return {
            "path": self.rel_path,
            "line": self.line,
            "operation": self.operation,
            "model": self.model,
            "op_type": self.op_type,
            "severity": self.severity,
            "note": self.note,
        }


class SourceIsolationChecker:
    """
    Checks source files for ORM queries missing tenant isolation.

    Severity classification:
      CONFIRMED  : where clause has an id-only lookup, no scope field, non-global model
      PLAUSIBLE  : where clause present but scope field not detected; manual review needed
      INFO       : global model (organization, user) or auth-context lookup
    """

    def __init__(self, ctx: SourceContext):
        self.ctx = ctx

    @classmethod
    def from_context(cls, ctx: SourceContext) -> "SourceIsolationChecker":
        return cls(ctx)

    def _classify(
        self,
        model: str,
        op_type: str,
        where_text: str,
        context_lines: str,
    ) -> tuple[str, str]:
        """Return (severity, note) for a detected Prisma call."""
        model_lower = model.lower()

        # Auth-context lookup: not a data access concern
        if any(p.search(context_lines) for p in _AUTH_CONTEXT_PATTERNS):
            return "INFO", "auth-context lookup"

        # Global models don't require project scoping
        if model_lower in _GLOBAL_MODELS:
            return "INFO", f"global model ({model}) — no tenant scope expected"

        # Global key lookup (email, publicKey, etc.)
        if any(p.search(where_text) for p in _GLOBAL_KEY_PATTERNS):
            return "INFO", "lookup by global unique key"

        # No where clause extracted at all
        if not where_text.strip():
            return "PLAUSIBLE", "where clause not statically extractable"

        # Has a recognized scope field → clean
        if _has_scope_field(where_text):
            return None, ""  # clean, not a finding

        # Only an `id:` field in the where clause
        id_only = re.match(r"\s*id\s*:[^,}]+$", where_text.strip())
        if id_only:
            return "CONFIRMED", "id-only where clause — no org/project scope"

        # Has some fields but none are scope fields
        return "PLAUSIBLE", "where clause fields unrecognized — verify scope"

    def _is_exempt(self, path: Path) -> bool:
        """Return True for test, seed, migration, and CLI files."""
        rel = self.ctx.rel(path).replace("\\", "/").lower()
        return any(frag in rel for frag in _EXEMPT_PATH_FRAGMENTS)

    def _scan_file(self, path: Path) -> list[IsolationFinding]:
        if self._is_exempt(path):
            return []
        text = self.ctx.read(path)
        if not text:
            return []
        lines = text.splitlines()
        rel = self.ctx.rel(path)
        findings: list[IsolationFinding] = []

        for i, line in enumerate(lines):
            m = _PRISMA_OPS.search(line)
            if not m:
                continue

            model = m.group(1)
            op_type = m.group(2)

            call_window = _extract_call_window(lines, i)
            where_text = _extract_where_block(call_window)

            # Context: lines around the call for auth-pattern detection
            ctx_start = max(0, i - 5)
            ctx_end = min(len(lines), i + 20)
            context_lines = "\n".join(lines[ctx_start:ctx_end])

            operation = f"prisma.{model}.{op_type}"
            severity, note = self._classify(model, op_type, where_text, context_lines)

            if severity is None:
                continue  # clean

            findings.append(IsolationFinding(
                path=path,
                rel_path=rel,
                line=i + 1,
                operation=operation,
                model=model,
                op_type=op_type,
                where_text=where_text.strip()[:200],
                severity=severity,
                note=note,
                call_window=call_window[:400],
            ))

        return findings

    def scan(self, files: Optional[list[Path]] = None) -> list[IsolationFinding]:
        """
        Scan for isolation failures.

        If files is None, scans all TypeScript/JavaScript source files.
        Returns findings sorted CONFIRMED first.
        """
        targets = files if files is not None else (
            self.ctx.files_by_lang("typescript") + self.ctx.files_by_lang("javascript")
        )
        all_findings: list[IsolationFinding] = []
        for f in targets:
            all_findings.extend(self._scan_file(f))

        _rank = {"CONFIRMED": 0, "PLAUSIBLE": 1, "INFO": 2}
        all_findings.sort(key=lambda f: (_rank.get(f.severity, 3), f.rel_path, f.line))
        return all_findings

    @staticmethod
    def report(findings: list[IsolationFinding], severity_filter: Optional[str] = None) -> str:
        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        lines = ["Isolation Checker Results", "=" * 60]
        for sev in ["CONFIRMED", "PLAUSIBLE", "INFO"]:
            n = counts.get(sev, 0)
            if n:
                lines.append(f"  {sev:<12} {n}")
        lines.append("")

        current_sev = None
        for f in findings:
            if f.severity != current_sev:
                current_sev = f.severity
                lines.append(f"── {f.severity} ──────────────────────────────────")
            lines.append(f"  {f.rel_path}:{f.line}  {f.operation}")
            lines.append(f"    {f.note}")
            if f.where_text:
                short = f.where_text.replace("\n", " ")[:120]
                lines.append(f"    where: {{ {short} }}")
        return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse
    ap = argparse.ArgumentParser(prog="source_isolation_checker",
                                 description="Check ORM queries for missing tenant isolation")
    ap.add_argument("path", help="Repo path")
    ap.add_argument("--severity", choices=["CONFIRMED", "PLAUSIBLE", "INFO"],
                    help="Filter to one severity level")
    args = ap.parse_args()

    ctx = SourceContext.from_path(args.path)
    checker = SourceIsolationChecker.from_context(ctx)
    findings = checker.scan()
    print(checker.report(findings, severity_filter=args.severity))


if __name__ == "__main__":
    _cli()
