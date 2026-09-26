"""
architectural_risk_scanner.py — "safe now catastrophic later" pattern detector.

Scans a TypeScript/JavaScript/Python codebase for files that combine:
  - Unsafe rendering primitives (StrictUnsafe, unsafeHTML, innerHTML, eval)
  - Type-based dispatchers (switch/if on policyType, actionType, etc.)
  - String-based component selectors (hardcoded element names fed to dynamic lookup)
  - Registry/dynamic component lookup (customElements.get, componentRegistry[])
  - Shared/base module context (files in base/, common/, admin/policies/ etc.)

Risk score = number of distinct tag categories present in the same file.
A file tagged unsafe_render + type_dispatch + shared_module = HIGH risk (score 3).

Usage:
    python3 targets/authentik/architectural_risk_scanner.py /tmp/authentik
    python3 targets/authentik/architectural_risk_scanner.py /tmp/authentik --min-score 2
    python3 targets/authentik/architectural_risk_scanner.py /tmp/authentik --tag unsafe_render
    python3 targets/authentik/architectural_risk_scanner.py /tmp/authentik --ext ts py

Source: adapted from debug-script.txt heuristics 1-5.
"""

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Pattern definitions ──────────────────────────────────────────────────────

TAG_PATTERNS: dict[str, list[tuple[str, re.Pattern]]] = {
    "unsafe_render": [
        ("StrictUnsafe()", re.compile(r"\bStrictUnsafe\s*\(")),
        ("unsafeHTML()", re.compile(r"\bunsafeHTML\s*\(")),
        ("unsafeStatic()", re.compile(r"\bunsafeStatic\s*\(")),
        ("dangerouslySetInnerHTML", re.compile(r"\bdangerouslySetInnerHTML\b")),
        ("innerHTML =", re.compile(r"\binnerHTML\s*=")),
        ("outerHTML =", re.compile(r"\bouterHTML\s*=")),
        ("document.write()", re.compile(r"\bdocument\.write\s*\(")),
        ("eval()", re.compile(r"\beval\s*\(")),
        ("new Function(", re.compile(r"\bnew\s+Function\s*\(")),
    ],
    "type_dispatch": [
        ("switch(type)", re.compile(r"switch\s*\(\s*\w*[tT]ype\w*\s*\)")),
        ("switch(action)", re.compile(r"switch\s*\(\s*\w*[aA]ction\w*\s*\)")),
        ("switch(component)", re.compile(r"switch\s*\(\s*\w*[cC]omponent\w*\s*\)")),
        ("switch(policy)", re.compile(r"switch\s*\(\s*\w*[pP]olicy\w*\s*\)")),
        ("switch(widget)", re.compile(r"switch\s*\(\s*\w*[wW]idget\w*\s*\)")),
        ("switch(stage)", re.compile(r"switch\s*\(\s*\w*[sS]tage\w*\s*\)")),
        ("switch(kind)", re.compile(r"switch\s*\(\s*\w*[kK]ind\w*\s*\)")),
        ("if(.*policyType)", re.compile(r"if\s*\(.*\bpolicyType\b")),
        ("if(.*actionType)", re.compile(r"if\s*\(.*\bactionType\b")),
        ("if(.*component)", re.compile(r"if\s*\(.*\bcomponent\b.*===\s*[\"']")),
    ],
    "string_selector": [
        ("hardcoded ak- string assigned to property",
         re.compile(r'\b\w+\s*=\s*["\']ak-[\w-]+["\']')),
        ("this.bindingEditForm / this.*Form / this.*Component as string selector",
         re.compile(r'\bthis\.\w*(?:EditForm|bindingForm|componentName|formName|renderer)\b')),
        ("template literal element name",
         re.compile(r'`(?:ak|policy|form|binding|stage|provider)-\$\{[^`]+\}`')),
        ("StrictUnsafe used on a property",
         re.compile(r'\bStrictUnsafe\s*\(\s*(?:this\.\w+|\w+\.\w+)\s*\)')),
    ],
    "registry_lookup": [
        ("customElements.get()", re.compile(r"\bcustomElements\.get\s*\(")),
        ("customElements.define()", re.compile(r"\bcustomElements\.define\s*\(")),
        ("componentRegistry[", re.compile(r"\bcomponentRegistry\s*\[")),
        ("createElement(this.*)", re.compile(r"\bcreateElement\s*\(\s*this\.\w+")),
        ("document.createElement(variable)", re.compile(
            r"\bdocument\.createElement\s*\(\s*(?!\"[a-z])[^\)\"]+\)"
        )),
        ("UNSAFE tag map / provider map", re.compile(
            r'\b(?:UNSAFE_TAGS|providerToTag|componentMap|formMap|rendererMap)\b'
        )),
    ],
    "shared_module": [
        ("file in elements/", re.compile(r"/elements/")),
        ("file in admin/policies/", re.compile(r"/admin/policies/")),
        ("file in admin/stages/", re.compile(r"/admin/stages/")),
        ("file in common/", re.compile(r"/common/")),
        ("file in flow/stages/", re.compile(r"/flow/stages/")),
        ("class name Base*/Abstract*/Generic*/List*/Table*/Form*",
         re.compile(r'\bclass\s+(?:Base|Abstract|Generic|Common|Shared)\w+')),
        ("extends Base*/ModelForm/Table/ViewSet",
         re.compile(r'\bextends\s+(?:Base\w+|ModelForm|Table|Table|ViewSet|APIView|GenericAPIView)')),
    ],
}

# Tags that indicate higher confidence when combined
HIGH_CONFIDENCE_COMBOS: list[frozenset[str]] = [
    frozenset({"unsafe_render", "type_dispatch", "shared_module"}),
    frozenset({"unsafe_render", "string_selector"}),
    frozenset({"unsafe_render", "registry_lookup"}),
    frozenset({"string_selector", "type_dispatch", "shared_module"}),
]

SKIP_PATTERNS = [".test.", ".spec.", ".stories.", "__pycache__", ".pyc"]
DEFAULT_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".py"}


@dataclass
class FileFinding:
    path: Path
    rel_path: str
    tags: dict[str, list[str]] = field(default_factory=dict)
    high_confidence: bool = False

    @property
    def score(self) -> int:
        return len(self.tags)

    @property
    def all_signals(self) -> list[str]:
        signals = []
        for tag_signals in self.tags.values():
            signals.extend(tag_signals)
        return signals


def scan_file(path: Path, repo_root: Path, extensions: set[str]) -> Optional[FileFinding]:
    if path.suffix not in extensions:
        return None
    rel = str(path.relative_to(repo_root))
    if any(skip in rel for skip in SKIP_PATTERNS):
        return None

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None

    finding = FileFinding(path=path, rel_path=rel)

    for tag, patterns in TAG_PATTERNS.items():
        matched_signals = []
        for signal_name, pattern in patterns:
            # For path-based patterns, match against rel_path
            if "file in " in signal_name:
                if pattern.search(rel):
                    matched_signals.append(signal_name)
            else:
                if pattern.search(text):
                    matched_signals.append(signal_name)
        if matched_signals:
            finding.tags[tag] = matched_signals

    if not finding.tags:
        return None

    tag_set = frozenset(finding.tags.keys())
    finding.high_confidence = any(combo <= tag_set for combo in HIGH_CONFIDENCE_COMBOS)

    return finding


def scan(repo_root: Path, extensions: set[str]) -> list[FileFinding]:
    findings = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        result = scan_file(path, repo_root, extensions)
        if result and result.score >= 1:
            findings.append(result)
    findings.sort(key=lambda f: (-f.score, -int(f.high_confidence), f.rel_path))
    return findings


def report(
    findings: list[FileFinding],
    min_score: int = 1,
    tag_filter: Optional[str] = None,
) -> str:
    if tag_filter:
        findings = [f for f in findings if tag_filter in f.tags]
    findings = [f for f in findings if f.score >= min_score]

    counts: dict[int, int] = {}
    for f in findings:
        counts[f.score] = counts.get(f.score, 0) + 1

    lines = [
        "Architectural Risk Scanner — 'safe now catastrophic later' findings",
        "=" * 70,
        f"{'Score':<8} {'Files':>6}",
        "-" * 16,
    ]
    for score in sorted(counts.keys(), reverse=True):
        label = "HIGH" if score >= 3 else "MEDIUM" if score == 2 else "LOW"
        lines.append(f"score={score:<2} [{label:6}]  {counts[score]:>4} files")
    lines.append("")

    current_score = None
    for f in findings:
        if f.score != current_score:
            current_score = f.score
            label = "HIGH" if current_score >= 3 else "MEDIUM" if current_score == 2 else "LOW"
            lines.append(f"── score={current_score} [{label}] ──────────────────────────────")
        hc = " ★HIGH_CONFIDENCE" if f.high_confidence else ""
        lines.append(f"  {f.rel_path}{hc}")
        for tag, signals in f.tags.items():
            lines.append(f"    [{tag}]")
            for sig in signals[:3]:
                lines.append(f"      • {sig}")
            if len(signals) > 3:
                lines.append(f"      … +{len(signals) - 3} more")
    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────────────

def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        prog="architectural_risk_scanner",
        description="Detect 'safe now catastrophic later' architectural patterns",
    )
    ap.add_argument("path", help="Repo root path")
    ap.add_argument("--min-score", type=int, default=1, help="Minimum tag score to report (default: 1)")
    ap.add_argument("--tag", help="Filter to files with a specific tag category")
    ap.add_argument("--ext", nargs="+", help="File extensions to scan (default: ts tsx js jsx py)")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: {root} does not exist", file=sys.stderr)
        sys.exit(1)

    extensions = {f".{e.lstrip('.')}" for e in args.ext} if args.ext else DEFAULT_EXTENSIONS
    findings = scan(root, extensions)
    print(report(findings, min_score=args.min_score, tag_filter=args.tag))
    print(f"\nTotal files flagged: {len([f for f in findings if f.score >= args.min_score])}")


if __name__ == "__main__":
    _cli()
