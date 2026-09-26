"""
source_arch_risk.py: "safe now catastrophic later" architectural risk scanner.

Detects files that combine unsafe rendering primitives with extensible type
dispatchers, string-based component selectors, or shared-module context.

The risk model: a file is low-risk if it only has one tag category. It becomes
high-risk when unsafe rendering lives in the same file as a type-dispatch switch
or string-based selector, because those are the exact patterns developers extend
by adding new cases — without realising each new case is a new rendering path
that may bypass shared sanitization.

Tag categories:
    unsafe_render  — StrictUnsafe, unsafeHTML, innerHTML, eval, dangerouslySetInnerHTML
    type_dispatch  — switch/if on *Type, *Action, *Policy, *Component, *Kind
    string_selector — hardcoded element-name string property, template-literal tag name
    registry_lookup — customElements.get(), componentRegistry[], createElement(variable)
    shared_module  — file in elements/, common/, admin/policies/; class extends Base*/ViewSet

Risk score = count of distinct categories present. HIGH_CONFIDENCE when a known
dangerous combo appears (unsafe_render + type_dispatch, unsafe_render + string_selector, etc.)

Usage:
    from ablation.analyzers.source_ingestion import SourceContext
    from ablation.analyzers.source_arch_risk import SourceArchRiskScanner

    ctx = SourceContext.from_path("/tmp/authentik")
    scanner = SourceArchRiskScanner.from_context(ctx)
    findings = scanner.scan()
    print(scanner.report(findings, min_score=2))

    # Only unsafe_render findings in shared modules
    high = [f for f in findings if f.score >= 3 or f.high_confidence]

CLI:
    python3 -m ablation.analyzers.source_arch_risk /tmp/authentik
    python3 -m ablation.analyzers.source_arch_risk /tmp/authentik --min-score 2
    python3 -m ablation.analyzers.source_arch_risk /tmp/authentik --tag unsafe_render
    python3 -m ablation.analyzers.source_arch_risk /tmp/authentik --ext ts py
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


# ── Tag pattern definitions ───────────────────────────────────────────────────

_TAG_PATTERNS: dict[str, list[tuple[str, re.Pattern]]] = {
    "unsafe_render": [
        ("StrictUnsafe()", re.compile(r"\bStrictUnsafe\s*\(")),
        ("unsafeHTML()", re.compile(r"\bunsafeHTML\s*\(")),
        ("unsafeStatic()", re.compile(r"\bunsafeStatic\s*\(")),
        ("dangerouslySetInnerHTML", re.compile(r"\bdangerouslySetInnerHTML\b")),
        ("innerHTML =", re.compile(r"\binnerHTML\s*=")),
        ("outerHTML =", re.compile(r"\bouterHTML\s*=")),
        ("document.write()", re.compile(r"\bdocument\.write\s*\(")),
        ("eval()", re.compile(r"(?<!\w)eval\s*\(")),
        ("new Function()", re.compile(r"\bnew\s+Function\s*\(")),
    ],
    "type_dispatch": [
        ("switch(*type)", re.compile(r"switch\s*\(\s*\w*[tT]ype\w*\s*\)")),
        ("switch(*action)", re.compile(r"switch\s*\(\s*\w*[aA]ction\w*\s*\)")),
        ("switch(*component)", re.compile(r"switch\s*\(\s*\w*[cC]omponent\w*\s*\)")),
        ("switch(*policy)", re.compile(r"switch\s*\(\s*\w*[pP]olicy\w*\s*\)")),
        ("switch(*stage)", re.compile(r"switch\s*\(\s*\w*[sS]tage\w*\s*\)")),
        ("switch(*kind)", re.compile(r"switch\s*\(\s*\w*[kK]ind\w*\s*\)")),
        ("switch(*widget)", re.compile(r"switch\s*\(\s*\w*[wW]idget\w*\s*\)")),
        ("if(.*policyType)", re.compile(r"if\s*\(.*\bpolicyType\b")),
        ("if(.*actionType)", re.compile(r"if\s*\(.*\bactionType\b")),
        ("if(.*component ===)", re.compile(r"if\s*\(.*\bcomponent\b.*===\s*[\"']")),
    ],
    "string_selector": [
        ("hardcoded ak-* string to property",
         re.compile(r'\b\w+\s*=\s*["\'](?:ak|pf|policy|form|stage|provider)[\w-]+["\']')),
        ("this.*Form/Component/Renderer property",
         re.compile(r'\bthis\.\w*(?:[Ff]orm|[Cc]omponent|[Rr]enderer|[Ss]elector|[Hh]andler)\b')),
        ("template literal element tag name",
         re.compile(r'`(?:ak|policy|form|binding|stage|provider|component)-\$\{')),
        ("StrictUnsafe on property value",
         re.compile(r'\bStrictUnsafe\s*\(\s*(?:this\.\w+|\w+\.\w+)\s*\)')),
    ],
    "registry_lookup": [
        ("customElements.get()", re.compile(r"\bcustomElements\.get\s*\(")),
        ("componentRegistry[...]", re.compile(r"\bcomponentRegistry\s*\[")),
        ("createElement(variable)", re.compile(
            r"\bcreateElement\s*\(\s*(?!(?:'[a-z]|\"[a-z]))[^\)\"']{2,}\)"
        )),
        ("named tag map (providerToTag / formMap / etc.)",
         re.compile(r'\b(?:providerToTag|componentMap|formMap|rendererMap|UNSAFE_TAGS|stageMap)\b')),
    ],
    "shared_module": [
        # path-based: evaluated against rel_path, not file content
        ("in elements/", re.compile(r"/elements/")),
        ("in admin/policies/", re.compile(r"/admin/policies/")),
        ("in admin/stages/", re.compile(r"/admin/stages/")),
        ("in common/", re.compile(r"/(?:common|shared|base)/")),
        ("in flow/stages/", re.compile(r"/flow/stages/")),
        # content-based
        ("class extends Base*/ViewSet/ModelForm",
         re.compile(r'\bclass\s+\w+\s+extends\s+(?:Base\w+|ModelViewSet|GenericAPIView|APIView|ModelForm|Table\b)')),
    ],
}

# Combos that are definitively high-confidence risk
_HIGH_CONFIDENCE_COMBOS: list[frozenset[str]] = [
    frozenset({"unsafe_render", "type_dispatch", "shared_module"}),
    frozenset({"unsafe_render", "string_selector"}),
    frozenset({"unsafe_render", "registry_lookup"}),
    frozenset({"string_selector", "type_dispatch", "shared_module"}),
    frozenset({"registry_lookup", "type_dispatch"}),
]

# Path fragments that identify test/storybook files to skip
_SKIP_FRAGMENTS = [".test.", ".spec.", ".stories.", "__pycache__", ".pyc", "node_modules"]


@dataclass
class ArchRiskFinding:
    """Single-file architectural risk result."""
    path: Path
    rel_path: str
    tags: dict[str, list[str]] = field(default_factory=dict)
    high_confidence: bool = False

    @property
    def score(self) -> int:
        return len(self.tags)

    @property
    def risk_label(self) -> str:
        if self.score >= 3 or self.high_confidence:
            return "HIGH"
        if self.score == 2:
            return "MEDIUM"
        return "LOW"

    def as_dict(self) -> dict:
        return {
            "path": self.rel_path,
            "score": self.score,
            "risk": self.risk_label,
            "high_confidence": self.high_confidence,
            "tags": {t: sigs[:3] for t, sigs in self.tags.items()},
        }


class SourceArchRiskScanner:
    """
    Architectural risk scanner for source codebases.

    Identifies files that are architecturally primed to become dangerous
    if extended naturally — the "safe now catastrophic later" class.
    """

    def __init__(self, ctx: SourceContext):
        self.ctx = ctx

    @classmethod
    def from_context(cls, ctx: SourceContext) -> "SourceArchRiskScanner":
        return cls(ctx)

    def _classify_file(self, path: Path) -> Optional[ArchRiskFinding]:
        rel = self.ctx.rel(path)

        if any(frag in rel for frag in _SKIP_FRAGMENTS):
            return None

        text = self.ctx.read(path)
        if not text:
            return None

        finding = ArchRiskFinding(path=path, rel_path=rel)

        for tag, patterns in _TAG_PATTERNS.items():
            matched: list[str] = []
            for signal_name, pattern in patterns:
                # path-based signals match against rel_path
                target = rel if "in " in signal_name and "/" in signal_name else text
                if pattern.search(target):
                    matched.append(signal_name)
            if matched:
                finding.tags[tag] = matched

        if not finding.tags:
            return None

        tag_set = frozenset(finding.tags.keys())
        finding.high_confidence = any(combo <= tag_set for combo in _HIGH_CONFIDENCE_COMBOS)

        return finding

    def scan(self, files: Optional[list[Path]] = None) -> list[ArchRiskFinding]:
        """
        Scan files for architectural risk patterns.

        If files is None, scans all source files in the context.
        Returns results sorted HIGH → MEDIUM → LOW, then by path.
        """
        targets = files if files is not None else self.ctx.all_files
        findings = []
        for f in targets:
            result = self._classify_file(f)
            if result:
                findings.append(result)

        findings.sort(key=lambda f: (-f.score, -int(f.high_confidence), f.rel_path))
        return findings

    @staticmethod
    def report(
        findings: list[ArchRiskFinding],
        min_score: int = 1,
        tag_filter: Optional[str] = None,
    ) -> str:
        if tag_filter:
            findings = [f for f in findings if tag_filter in f.tags]
        findings = [f for f in findings if f.score >= min_score]

        counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f.risk_label] += 1

        lines = [
            "Source Architectural Risk Scan — 'safe now catastrophic later'",
            "=" * 70,
        ]
        for label in ("HIGH", "MEDIUM", "LOW"):
            if counts[label]:
                lines.append(f"  {label:<8}: {counts[label]} files")
        lines.append("")

        current_risk = None
        for f in findings:
            if f.risk_label != current_risk:
                current_risk = f.risk_label
                lines.append(f"── {current_risk} ──────────────────────────────")
            hc = " ★" if f.high_confidence else ""
            lines.append(f"  {f.rel_path}{hc}")
            for tag, signals in f.tags.items():
                lines.append(f"    [{tag}]  {'; '.join(signals[:2])}")

        return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        prog="source_arch_risk",
        description="Detect 'safe now catastrophic later' architectural risk patterns",
    )
    ap.add_argument("path", help="Repository root path")
    ap.add_argument("--min-score", type=int, default=1,
                    help="Minimum tag-category count (1=LOW, 2=MEDIUM, 3+=HIGH; default: 1)")
    ap.add_argument("--tag", choices=list(_TAG_PATTERNS.keys()),
                    help="Filter to files with this specific tag category")
    ap.add_argument("--ext", nargs="+",
                    help="File extensions to include (e.g. ts py; default: all source)")
    args = ap.parse_args()

    ctx = SourceContext.from_path(args.path)

    if args.ext:
        exts = {f".{e.lstrip('.')}" for e in args.ext}
        files = [f for f in ctx.all_files if f.suffix in exts]
        scanner = SourceArchRiskScanner(ctx)
        findings = scanner.scan(files=files)
    else:
        scanner = SourceArchRiskScanner.from_context(ctx)
        findings = scanner.scan()

    print(SourceArchRiskScanner.report(findings, min_score=args.min_score, tag_filter=args.tag))
    flagged = len([f for f in findings if f.score >= args.min_score])
    if args.tag:
        flagged = len([f for f in findings if args.tag in f.tags and f.score >= args.min_score])
    print(f"\nTotal files flagged: {flagged}")


if __name__ == "__main__":
    _cli()
