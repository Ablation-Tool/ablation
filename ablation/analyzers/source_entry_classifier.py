"""
source_entry_classifier.py: HTTP route auth-wrapper classification for source RE.

Classifies every API route file by its authentication level, producing a fast
surface map before any deep reading. Analogous to the binary export-table scan +
function-prologue pattern match that precedes taint analysis.

Auth levels (ordered weakest → strongest):
    NONE        : no auth check found
    API_KEY     : API key / Basic auth required
    SESSION     : user session (cookie/JWT) required
    INTERNAL    : service-to-service HMAC / admin key
    ADMIN       : global admin credential

Usage:
    from ablation.analyzers.source_ingestion import SourceContext
    from ablation.analyzers.source_entry_classifier import SourceEntryClassifier

    ctx = SourceContext.from_path("/tmp/langfuse")
    clf = SourceEntryClassifier.from_context(ctx)
    results = clf.classify()
    print(clf.report(results))

    # Get only unauthenticated routes
    unauth = [r for r in results if r.auth_level == "NONE"]

CLI:
    python3 -m ablation.analyzers.source_entry_classifier /tmp/langfuse
    python3 -m ablation.analyzers.source_entry_classifier /tmp/langfuse --level NONE
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

# Auth levels: string constants used throughout
AUTH_NONE     = "NONE"
AUTH_API_KEY  = "API_KEY"
AUTH_SESSION  = "SESSION"
AUTH_INTERNAL = "INTERNAL"
AUTH_ADMIN    = "ADMIN"

# Ordered weakest → strongest for ranking
_AUTH_RANK = {AUTH_NONE: 0, AUTH_API_KEY: 1, AUTH_SESSION: 2, AUTH_INTERNAL: 3, AUTH_ADMIN: 4}

# Patterns per auth level. Each entry: (auth_level, compiled_regex, note).
# First match wins; patterns are checked in order ADMIN → INTERNAL → SESSION → API_KEY → NONE.
_AUTH_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # ADMIN ── global admin credential gates
    (AUTH_ADMIN, re.compile(r"\bADMIN_API_KEY\b"), "ADMIN_API_KEY env check"),
    (AUTH_ADMIN, re.compile(r"\bisAdminApiKeyAuth\b"), "admin API key auth"),
    (AUTH_ADMIN, re.compile(r"\bwithGatewayResolveSignatureVerification\b"), "HMAC gateway resolve"),
    (AUTH_ADMIN, re.compile(r"\bwithGatewayModelsSignatureVerification\b"), "HMAC gateway models"),

    # INTERNAL ── service-to-service auth (HMAC, internal tokens)
    (AUTH_INTERNAL, re.compile(r"\bverifyGatewayRequestSignature\b"), "gateway HMAC verify"),
    (AUTH_INTERNAL, re.compile(r"\bwithGateway\w*SignatureVerification\b"), "gateway signature"),
    (AUTH_INTERNAL, re.compile(r"\blangfuse-gateway-authorization\b"), "gateway auth header"),
    (AUTH_INTERNAL, re.compile(r"\bX-aws-proxy-auth\b"), "AWS proxy token"),

    # SESSION ── user session / cookie / NextAuth
    (AUTH_SESSION, re.compile(r"\bgetServerSession\b|\bgetSession\b|\bgetServerAuthSession\w*\b"), "NextAuth session"),
    (AUTH_SESSION, re.compile(r"\bprotectedProcedure\b|\bprotectedProject\w+Procedure\b"), "tRPC protected procedure"),
    (AUTH_SESSION, re.compile(r"\bsessionMiddleware\b|\bwithSession\b"), "session middleware"),
    (AUTH_SESSION, re.compile(r"\brequireSession\b|\bensureAuth\b"), "session guard"),
    (AUTH_SESSION, re.compile(r"@(login_required|requires_auth)\b"), "Python auth decorator"),

    # API_KEY ── API key / Basic auth / Bearer token
    (AUTH_API_KEY, re.compile(r"\bshadowAuth\b|\benforceAuth\b"), "shadowAuth / enforceAuth"),
    (AUTH_API_KEY, re.compile(r"\bcreateAuthedProjectAPIRoute\b"), "createAuthedProjectAPIRoute"),
    (AUTH_API_KEY, re.compile(r"\bverifyAuthHeaderAndReturnScope\b"), "verifyAuthHeader"),
    (AUTH_API_KEY, re.compile(r"\bApiAuthService\b"), "ApiAuthService"),
    (AUTH_API_KEY, re.compile(r"\bwithMiddlewares\b.*action\s*:"), "withMiddlewares + action"),
    (AUTH_API_KEY, re.compile(r"\bBasicAuth\b|\bBearerAuth\b"), "Basic/Bearer auth"),
    (AUTH_API_KEY, re.compile(r"Authorization.*Bearer|Bearer.*Authorization"), "Bearer header check"),
    (AUTH_API_KEY, re.compile(r"@require_http_methods|api_key_required"), "Python API key decorator"),
    # Webhook signature verification (Stripe, ClickHouse billing, etc.)
    (AUTH_API_KEY, re.compile(r"\bwebhook.*secret\b|\bstripe\.webhooks\.constructEvent\b", re.IGNORECASE), "webhook secret verify"),
    (AUTH_API_KEY, re.compile(r"\btimingSafeEqual\b"), "timing-safe bearer verify"),
    (AUTH_API_KEY, re.compile(r"\bauthorizeRequestOrThrow\b|\bauthorizeRequest\b"), "authorizeRequest guard"),
    # INTERNAL service-to-service bearer keys (not user auth)
    (AUTH_INTERNAL, re.compile(r"CLICKHOUSE_BILLING_METRICS_API_KEY|BILLING_METRICS_API_KEY"), "billing metrics API key"),
    (AUTH_INTERNAL, re.compile(r"\bSTRIPE_WEBHOOK_SECRET\b|\bchbWebhookHandler\b|\bstripeWebhookHandler\b"), "Stripe/CHB webhook handler"),
]

# Signals that a file is a config/health/docs endpoint (lowers NONE severity)
_LOW_VALUE_SIGNALS: list[re.Pattern] = [
    re.compile(r"\bhealth\b|\bready\b|\bping\b", re.IGNORECASE),
    re.compile(r"\bversion\b|\binfo\b|\bstatus\b", re.IGNORECASE),
    re.compile(r"openapi|swagger|docs\.ts", re.IGNORECASE),
]


@dataclass
class RouteClassification:
    """Classification result for one route file."""
    path: Path
    rel_path: str
    auth_level: str        # AUTH_* constant
    matched_signal: str    # which pattern triggered (or "no auth signal found")
    is_low_value: bool     # health/docs/config endpoint
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "path": self.rel_path,
            "auth_level": self.auth_level,
            "signal": self.matched_signal,
            "low_value": self.is_low_value,
        }


class SourceEntryClassifier:
    """
    Classifies API route files by authentication level.

    Produces a surface map of the attack entry points, ranked weakest → strongest.
    """

    def __init__(self, ctx: SourceContext):
        self.ctx = ctx

    @classmethod
    def from_context(cls, ctx: SourceContext) -> "SourceEntryClassifier":
        return cls(ctx)

    _IMPORT_FROM = re.compile(
        r"""(?:import\s+\S+\s+from|import\s*\{[^}]*\}\s*from)\s+['"]([^'"]+)['"]""",
        re.MULTILINE,
    )

    def _resolve_import(self, from_path: Path, import_str: str) -> Optional[Path]:
        """Resolve a relative or @-aliased import string to an absolute path."""
        # Relative import
        if import_str.startswith("."):
            base = from_path.parent
            for ext in ("", ".ts", ".tsx", "/index.ts", "/index.tsx", ".js", "/index.js"):
                candidate = (base / (import_str + ext)).resolve()
                if candidate.exists():
                    return candidate
            return None

        # Next.js @/ alias — maps to the nearest package root (directory containing src/)
        if import_str.startswith("@/"):
            tail = import_str[2:]  # strip @/
            # Walk up from from_path to find a directory containing src/
            check = from_path.parent
            for _ in range(8):
                candidate_base = check / tail
                for ext in ("", ".ts", ".tsx", "/index.ts", "/index.tsx", ".js", "/index.js"):
                    candidate = Path(str(candidate_base) + ext)
                    if candidate.exists():
                        return candidate
                if (check / "package.json").exists():
                    break
                check = check.parent
            return None

        return None  # external package

    def _classify_text(self, text: str) -> tuple[str, str]:
        """Return (auth_level, matched_signal) for a block of source text."""
        auth_level = AUTH_NONE
        matched_signal = "no auth signal found"
        for level, pattern, note in _AUTH_PATTERNS:
            if pattern.search(text):
                if _AUTH_RANK[level] > _AUTH_RANK[auth_level]:
                    auth_level = level
                    matched_signal = note
        return auth_level, matched_signal

    def _classify_file(self, path: Path) -> RouteClassification:
        text = self.ctx.read(path)
        rel = self.ctx.rel(path)

        auth_level, matched_signal = self._classify_text(text or "")

        # If no auth found in route file, follow one level of imports.
        # Many Next.js route files are pure shims that re-export a handler.
        if auth_level == AUTH_NONE and text:
            for m in self._IMPORT_FROM.finditer(text):
                import_path = self._resolve_import(path, m.group(1))
                if import_path is None:
                    continue
                imported_text = self.ctx.read(import_path)
                if not imported_text:
                    continue
                imp_level, imp_signal = self._classify_text(imported_text)
                if _AUTH_RANK[imp_level] > _AUTH_RANK[auth_level]:
                    auth_level = imp_level
                    matched_signal = f"{imp_signal} (via {self.ctx.rel(import_path)})"
                if auth_level != AUTH_NONE:
                    break  # stop once we find any auth signal

        is_low_value = any(p.search(text or "") or p.search(rel) for p in _LOW_VALUE_SIGNALS)

        return RouteClassification(
            path=path,
            rel_path=rel,
            auth_level=auth_level,
            matched_signal=matched_signal,
            is_low_value=is_low_value,
        )

    def classify(self, files: Optional[list[Path]] = None) -> list[RouteClassification]:
        """
        Classify route files by auth level.

        If files is None, classifies all detected route files from SourceContext.
        Returns results sorted weakest-auth-first (NONE before API_KEY etc.).
        """
        targets = files if files is not None else self.ctx.route_files
        results = [self._classify_file(f) for f in targets]
        results.sort(key=lambda r: (_AUTH_RANK[r.auth_level], r.rel_path))
        return results

    def classify_all_source(self) -> list[RouteClassification]:
        """Classify all source files, not just detected route files."""
        return self.classify(files=self.ctx.all_files)

    @staticmethod
    def report(results: list[RouteClassification], filter_level: Optional[str] = None) -> str:
        if filter_level:
            results = [r for r in results if r.auth_level == filter_level]

        counts: dict[str, int] = {}
        for r in results:
            counts[r.auth_level] = counts.get(r.auth_level, 0) + 1

        lines = ["Route Auth Surface Map", "=" * 60]
        lines.append(f"{'Level':<12} {'Count':>5}")
        lines.append("-" * 18)
        for level in [AUTH_NONE, AUTH_API_KEY, AUTH_SESSION, AUTH_INTERNAL, AUTH_ADMIN]:
            n = counts.get(level, 0)
            if n:
                lines.append(f"{level:<12} {n:>5}")
        lines.append("")

        current_level = None
        for r in results:
            if r.auth_level != current_level:
                current_level = r.auth_level
                lines.append(f"── {r.auth_level} ──────────────────────────────")
            flag = " [low-value]" if r.is_low_value else ""
            lines.append(f"  {r.rel_path:<60} [{r.matched_signal}]{flag}")

        return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse
    ap = argparse.ArgumentParser(prog="source_entry_classifier", description="Classify API route auth levels")
    ap.add_argument("path", help="Repo path")
    ap.add_argument("--level", choices=[AUTH_NONE, AUTH_API_KEY, AUTH_SESSION, AUTH_INTERNAL, AUTH_ADMIN],
                    help="Filter to one auth level")
    ap.add_argument("--all-files", action="store_true", help="Classify all source files, not just route files")
    args = ap.parse_args()

    ctx = SourceContext.from_path(args.path)
    clf = SourceEntryClassifier.from_context(ctx)
    results = clf.classify_all_source() if args.all_files else clf.classify()
    print(clf.report(results, filter_level=args.level))


if __name__ == "__main__":
    _cli()
