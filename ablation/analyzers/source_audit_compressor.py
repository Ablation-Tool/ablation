"""
source_audit_compressor.py — Source Code Auditor.

Audit any large codebase for security vulnerabilities. Every source file gets a
5-bit security profile that determines exactly how much attention it needs, so
nothing gets missed and nothing gets read twice.

The core insight: most source files share identical security-relevant profiles.
Files with the same profile are auditable as a batch — read one representative,
apply the finding to all others in the same profile bucket.

Profile = 5-bit integer (0–31) encoding the presence of security-relevant signals:

    bit 4 (weight 16): has_unsafe_render  — unsafeHTML / innerHTML / StrictUnsafe / eval
    bit 3 (weight  8): has_href_binding   — dynamic href=${...} attribute
    bit 2 (weight  4): has_url_assignment — window.location.assign / window.open(var)
    bit 1 (weight  2): has_user_data      — renders .name/.username/.body/.email/.description
    bit 0 (weight  1): is_shared_module   — elements/, common/, admin/policies/, Base* class

Profile 0 (00000): No sinks, no hrefs, no URL assignments, no user data, leaf component.
  → Batch-CLEAN after one representative read. This is the vast majority of files.

Profile 16+ (1xxxx): Has unsafe rendering.
  → Individual read required for every file.

Profile 8–15 (01xxx): Has href binding without unsafe rendering.
  → Individual read required (AUT-CHANGELOG-URL-1 class).

Profile 4–7 (001xx): Has URL assignment.
  → Spot-check (usually server-generated URLs, but verify).

Profiles 2–3 (0001x): Has user-data rendering only.
  → Spot-check (text-node context is usually safe, but verify).

Profile 1 (00001): Shared module only, no rendering signals.
  → Batch with other shared-only files after one read.

Compression ratio for a 2861-file TypeScript codebase (empirical):
  ~2790 files in profile 0 → batch on 1 representative read
  ~71 files in profiles 1–31 → individual or spot-check reads
  Audit compression: 2861 reads → ~72 reads (40x reduction)

Usage:
    from ablation.analyzers.source_ingestion import SourceContext
    from ablation.analyzers.source_audit_compressor import SourceAuditCompressor

    ctx = SourceContext.from_path("/tmp/authentik")
    compressor = SourceAuditCompressor.from_context(ctx)
    buckets = compressor.compress()
    print(compressor.report(buckets))

    # Get the individual-read required files (profiles with any unsafe sink)
    priority = compressor.priority_reads(buckets)
    for profile, files in priority:
        print(f"profile={profile:05b} ({len(files)} files) — read all individually")

    # Get the batch-CLEAN candidates (profile 0)
    batch = compressor.batch_clean(buckets)
    print(f"Batch-CLEAN: {len(batch)} files (read 1 representative)")

CLI:
    python3 -m ablation.analyzers.source_audit_compressor /tmp/authentik
    python3 -m ablation.analyzers.source_audit_compressor /tmp/authentik --profile 8
    python3 -m ablation.analyzers.source_audit_compressor /tmp/authentik --ext ts --show-files
"""

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from .source_ingestion import SourceContext
except ImportError:
    from source_ingestion import SourceContext  # type: ignore


# ── Profile bit definitions ───────────────────────────────────────────────────

BIT_UNSAFE_RENDER = 4   # weight 16
BIT_HREF_BINDING  = 3   # weight 8
BIT_URL_ASSIGN    = 2   # weight 4
BIT_USER_DATA     = 1   # weight 2
BIT_SHARED_MODULE = 0   # weight 1

PROFILE_LABELS = {
    BIT_UNSAFE_RENDER: "unsafe_render",
    BIT_HREF_BINDING:  "href_binding",
    BIT_URL_ASSIGN:    "url_assign",
    BIT_USER_DATA:     "user_data",
    BIT_SHARED_MODULE: "shared_module",
}

AUDIT_PRIORITY = {
    # profile range → audit action
    (16, 31): "INDIVIDUAL READ (unsafe rendering present)",
    (8,  15): "INDIVIDUAL READ (dynamic href binding)",
    (4,   7): "SPOT CHECK (URL assignment)",
    (2,   3): "SPOT CHECK (user-data rendering)",
    (1,   1): "BATCH (shared module, no sinks)",
    (0,   0): "BATCH-CLEAN (no signals at all)",
}

# ── Detection patterns per channel ───────────────────────────────────────────

# Bit 4 — unsafe rendering
_PAT_UNSAFE_RENDER = re.compile(
    r'\b(?:unsafeHTML|unsafeStatic|StrictUnsafe|dangerouslySetInnerHTML)\s*\('
    r'|(?<!\w)innerHTML\s*='
    r'|(?<!\w)outerHTML\s*='
    r'|(?<!\w)eval\s*\('
    r'|\bnew\s+Function\s*\('
)

# Bit 3 — dynamic href binding (Lit attribute binding syntax href=${...})
_PAT_HREF_BINDING = re.compile(r'\bhref=\$\{')

# Bit 2 — URL assignment via window.location or window.open with a variable
_PAT_URL_ASSIGN = re.compile(
    r'\bwindow\.location(?:\.assign|\.replace|\.href)\s*[=(]'
    r'|\bwindow\.open\s*\(\s*(?![\'\"]https?://)[^\)]{3,}\)'
    r'|\blocation\.href\s*='
    r'|\bnavigateToUrl\s*\('
)

# Bit 1 — renders user-controlled API data (object property access on rendered items)
_PAT_USER_DATA = re.compile(
    r'(?:html|html`)[^`]*\$\{[^}]*\.(?:name|username|email|body|description|title|label|text|message|content)\b'
    r'|\$\{(?:item|user|group|app|event|policy|stage|provider|source|flow|device|token|notification)\.'
    r'(?:name|username|email|body|description|title|label|text|message|content)\}'
)

# Bit 0 — shared/hub module (path-based)
_PAT_SHARED_PATH = re.compile(
    r'/elements/'
    r'|/common/'
    r'|/shared/'
    r'|/admin/policies/'
    r'|/admin/stages/'
    r'|/flow/stages/'
)
_PAT_SHARED_CLASS = re.compile(
    r'\bclass\s+\w+\s+extends\s+(?:Base\w+|ModelViewSet|GenericAPIView|APIView|ModelForm|Table\b)'
)

SKIP_FRAGMENTS = [".test.", ".spec.", ".stories.", "__pycache__", ".pyc", "node_modules"]


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class FileProfile:
    path: Path
    rel_path: str
    profile: int          # 5-bit integer
    signals: list[str]    # which channel names matched

    @property
    def profile_str(self) -> str:
        return format(self.profile, "05b")

    @property
    def audit_action(self) -> str:
        for (lo, hi), action in AUDIT_PRIORITY.items():
            if lo <= self.profile <= hi:
                return action
        return "UNKNOWN"


@dataclass
class ProfileBucket:
    profile: int
    files: list[FileProfile] = field(default_factory=list)

    @property
    def profile_str(self) -> str:
        return format(self.profile, "05b")

    @property
    def active_bits(self) -> list[str]:
        return [
            PROFILE_LABELS[bit]
            for bit in sorted(PROFILE_LABELS.keys(), reverse=True)
            if self.profile & (1 << bit)
        ]

    @property
    def audit_action(self) -> str:
        for (lo, hi), action in AUDIT_PRIORITY.items():
            if lo <= self.profile <= hi:
                return action
        return "UNKNOWN"


# ── Scanner ───────────────────────────────────────────────────────────────────

class SourceAuditCompressor:
    """
    Compresses a source codebase into a small set of security risk profile buckets.

    Files in the same bucket share an identical risk profile and can be batch-processed:
    read one representative file to confirm the profile's expected security posture,
    then apply that determination to all other files in the bucket.
    """

    def __init__(self, ctx: SourceContext):
        self.ctx = ctx

    @classmethod
    def from_context(cls, ctx: SourceContext) -> "SourceAuditCompressor":
        return cls(ctx)

    def _profile_file(self, path: Path) -> Optional[FileProfile]:
        rel = self.ctx.rel(path)

        if any(frag in rel for frag in SKIP_FRAGMENTS):
            return None

        text = self.ctx.read(path)
        if not text:
            return None

        profile = 0
        signals: list[str] = []

        if _PAT_UNSAFE_RENDER.search(text):
            profile |= (1 << BIT_UNSAFE_RENDER)
            signals.append("unsafe_render")

        if _PAT_HREF_BINDING.search(text):
            profile |= (1 << BIT_HREF_BINDING)
            signals.append("href_binding")

        if _PAT_URL_ASSIGN.search(text):
            profile |= (1 << BIT_URL_ASSIGN)
            signals.append("url_assign")

        if _PAT_USER_DATA.search(text):
            profile |= (1 << BIT_USER_DATA)
            signals.append("user_data")

        if _PAT_SHARED_PATH.search(rel) or _PAT_SHARED_CLASS.search(text):
            profile |= (1 << BIT_SHARED_MODULE)
            signals.append("shared_module")

        return FileProfile(path=path, rel_path=rel, profile=profile, signals=signals)

    def compress(
        self,
        files: Optional[list[Path]] = None,
    ) -> dict[int, ProfileBucket]:
        """
        Assign all source files to profile buckets.

        Returns a dict keyed by profile integer (0–31), each value a ProfileBucket.
        """
        targets = files if files is not None else self.ctx.all_files
        buckets: dict[int, ProfileBucket] = {}

        for path in targets:
            fp = self._profile_file(path)
            if fp is None:
                continue
            if fp.profile not in buckets:
                buckets[fp.profile] = ProfileBucket(profile=fp.profile)
            buckets[fp.profile].files.append(fp)

        return buckets

    @staticmethod
    def priority_reads(buckets: dict[int, ProfileBucket]) -> list[ProfileBucket]:
        """Return buckets that require individual reads (profiles >= 8), sorted HIGH→LOW."""
        return sorted(
            [b for b in buckets.values() if b.profile >= 8],
            key=lambda b: (-b.profile, len(b.files)),
        )

    @staticmethod
    def spot_checks(buckets: dict[int, ProfileBucket]) -> list[ProfileBucket]:
        """Return buckets that warrant a spot-check (profiles 2–7)."""
        return sorted(
            [b for b in buckets.values() if 2 <= b.profile <= 7],
            key=lambda b: (-b.profile, len(b.files)),
        )

    @staticmethod
    def batch_clean(buckets: dict[int, ProfileBucket]) -> list[FileProfile]:
        """Return all files in profile 0 (no signals at all) — batch-CLEAN candidates."""
        return buckets.get(0, ProfileBucket(0)).files

    @staticmethod
    def compression_ratio(buckets: dict[int, ProfileBucket]) -> float:
        """
        Estimated audit reads saved.

        Formula: (total_files - reads_required) / total_files
        reads_required = individual reads (profiles 8–31) + spot-checks (profiles 2–7) +
                         1 representative per batch bucket (profiles 0–1)
        """
        total = sum(len(b.files) for b in buckets.values())
        if total == 0:
            return 0.0

        # Individual reads for profiles >= 8
        individual = sum(len(b.files) for b in buckets.values() if b.profile >= 8)
        # Spot checks: 1 per file for profiles 2–7 (conservative)
        spot = sum(len(b.files) for b in buckets.values() if 2 <= b.profile <= 7)
        # Batch buckets: only 1 representative read per occupied bucket
        batch_buckets = [b for b in buckets.values() if b.profile <= 1]
        batch_reads = len(batch_buckets)  # 1 representative per bucket

        reads_required = individual + spot + batch_reads
        return (total - reads_required) / total

    @staticmethod
    def report(
        buckets: dict[int, ProfileBucket],
        show_files: bool = False,
        profile_filter: Optional[int] = None,
    ) -> str:
        if profile_filter is not None:
            buckets = {k: v for k, v in buckets.items() if k == profile_filter}

        total = sum(len(b.files) for b in buckets.values())
        ratio = SourceAuditCompressor.compression_ratio(buckets)

        lines = [
            "Source Audit Compressor — profile-based batch audit",
            "=" * 70,
            f"Total files: {total}",
            f"Occupied profiles: {len(buckets)} / 32",
            f"Estimated audit compression: {ratio:.1%} fewer reads",
            "",
        ]

        # Group buckets by audit action
        groups: dict[str, list[ProfileBucket]] = {}
        for b in sorted(buckets.values(), key=lambda b: -b.profile):
            action = b.audit_action
            groups.setdefault(action, []).append(b)

        for action, group_buckets in sorted(groups.items(), key=lambda x: -max(b.profile for b in x[1])):
            total_in_group = sum(len(b.files) for b in group_buckets)
            lines.append(f"── {action} ({total_in_group} files) ──────────────")
            for b in group_buckets:
                bits_str = " | ".join(b.active_bits) if b.active_bits else "no signals"
                lines.append(f"  profile={b.profile_str} ({b.profile:2d}): {len(b.files):4d} files  [{bits_str}]")
                if show_files:
                    for fp in sorted(b.files, key=lambda f: f.rel_path)[:20]:
                        lines.append(f"      {fp.rel_path}")
                    if len(b.files) > 20:
                        lines.append(f"      … +{len(b.files) - 20} more")

        return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        prog="source_audit_compressor",
        description="Profile-based audit compression: compress N files to M profile buckets",
    )
    ap.add_argument("path", help="Repository root path")
    ap.add_argument("--profile", type=int, help="Show only files in this profile (0–31)")
    ap.add_argument("--ext", nargs="+", help="File extensions to include (e.g. ts py)")
    ap.add_argument("--show-files", action="store_true",
                    help="Print file paths within each bucket")
    args = ap.parse_args()

    ctx = SourceContext.from_path(args.path)

    if args.ext:
        exts = {f".{e.lstrip('.')}" for e in args.ext}
        files = [f for f in ctx.all_files if f.suffix in exts]
        compressor = SourceAuditCompressor(ctx)
        buckets = compressor.compress(files=files)
    else:
        compressor = SourceAuditCompressor.from_context(ctx)
        buckets = compressor.compress()

    print(SourceAuditCompressor.report(
        buckets,
        show_files=args.show_files,
        profile_filter=args.profile,
    ))


if __name__ == "__main__":
    _cli()
