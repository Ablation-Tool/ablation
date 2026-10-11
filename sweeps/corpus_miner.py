"""
sweeps/corpus_miner.py — Cross-target finding corpus miner.

Reads all *_re.py modules under ~/ablation/re/, extracts CONFIRMED findings,
normalizes CWE tags, and produces:

  1. CorpusEntry list  — structured record per confirmed finding
  2. CWE frequency table  — how often each vuln class appears across targets
  3. Coverage gaps  — high-frequency CWEs with no ablation scanner
  4. Cross-target patterns  — same CWE in 3+ vendors → strong module candidates

This closes the ablation flywheel: confirmed findings feed back into tooling
priorities rather than living only in per-target RE notes.

Usage:
    python3 sweeps/corpus_miner.py
    python3 sweeps/corpus_miner.py --re-dir /path/to/alt/re --min-count 3
    python3 sweeps/corpus_miner.py --json  # machine-readable output
"""

from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

# ── CWE normalization ─────────────────────────────────────────────────────────

_CWE_RE = re.compile(r'\bCWE-?(\d+)\b', re.IGNORECASE)
_TITLE_CWE_MAP: List[tuple] = [
    # (regex pattern, CWE) — ordered most-specific first
    (re.compile(r'\bsql\b.*inject|inject.*\bsql\b', re.I),                 'CWE-89'),
    (re.compile(r'\blua\b.*inject|inject.*\blua\b', re.I),                 'CWE-94'),
    (re.compile(r'\bcommand inject|\bos.system\b|\bpopen\b|\bexec.*inject', re.I), 'CWE-78'),
    (re.compile(r'\bos command|\bshell inject|system\s*\(', re.I),         'CWE-78'),
    (re.compile(r'\bformat string\b', re.I),                               'CWE-134'),
    (re.compile(r'\bpath traversal|directory traversal', re.I),            'CWE-22'),
    (re.compile(r'\bopen redirect|url redirect', re.I),                    'CWE-601'),
    (re.compile(r'\bheap overflow|heap.*overfl', re.I),                    'CWE-122'),
    (re.compile(r'\bstack overflow|stack.*overfl|stack.*smash', re.I),     'CWE-121'),
    (re.compile(r'\bbuffer overfl|out.of.bounds write', re.I),             'CWE-120'),
    (re.compile(r'\binteger overflow|int.*overfl', re.I),                  'CWE-190'),
    (re.compile(r'\buse.after.free\b', re.I),                              'CWE-416'),
    (re.compile(r'\bhardcoded.*key|hardcoded.*secret|hardcoded.*password', re.I), 'CWE-321'),
    (re.compile(r'\bhardcoded.*cred|default.*cred|default.*password', re.I), 'CWE-798'),
    (re.compile(r'\bshared.*private key|shared.*rsa|rsa.*shared', re.I),   'CWE-321'),
    (re.compile(r'\bshared.*cert|shared.*fgt\.key|shared.*pem\b', re.I),   'CWE-321'),
    (re.compile(r'\bcert.*bypass|tls.*bypass|ssl.*bypass|certificate.*bypass', re.I), 'CWE-295'),
    (re.compile(r'\btls.*skip|ssl.*skip|verify.*ssl.*false|cert.*none', re.I), 'CWE-295'),
    (re.compile(r'\bauth.*bypass|bypass.*auth|missing.*auth|unauthenticated', re.I), 'CWE-287'),
    (re.compile(r'\bmissing.*authentication\b', re.I),                     'CWE-306'),
    (re.compile(r'\bcleartext|plain.*text.*password|unencrypted.*cred', re.I), 'CWE-319'),
    (re.compile(r'\bweak.*hash|md5.*password|sha1.*password', re.I),       'CWE-328'),
    (re.compile(r'\buntrusted.*search|rpath\b|ld_preload', re.I),          'CWE-426'),
    (re.compile(r'\bsignature.*bypass|signature.*skip|verify.*sig.*false', re.I), 'CWE-347'),
    (re.compile(r'\bxxe\b|xml.*entity', re.I),                             'CWE-611'),
    (re.compile(r'\bssrf\b|server.side.*request', re.I),                   'CWE-918'),
    (re.compile(r'\bxss\b|cross.site.*script|html.*inject', re.I),         'CWE-79'),
    (re.compile(r'\bxmpp|chat.*inject', re.I),                             'CWE-74'),
    (re.compile(r'\bprompt inject|llm.*inject|mcp.*inject', re.I),         'CWE-77'),
    (re.compile(r'\bbind.*0\.0\.0\.0|listen.*any.*interface', re.I),       'CWE-668'),
    (re.compile(r'\bexec.*allowed|allowed.*exec|exec.*method', re.I),      'CWE-284'),
    (re.compile(r'\binformation.*leak|info.*leak|memory.*leak', re.I),     'CWE-200'),
    (re.compile(r'\brace condition\b', re.I),                              'CWE-362'),
    (re.compile(r'\bnull.*deref|null pointer', re.I),                      'CWE-476'),
]


def _normalize_cwe(raw) -> tuple[str, bool]:
    """Return (cwe_string, inferred_from_title) for a raw CWE value."""
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not raw:
        return ('unknown', False)
    s = str(raw).strip()
    # Already normalized: 'CWE-78'
    m = _CWE_RE.search(s)
    if m:
        return (f'CWE-{m.group(1)}', False)
    # Bare integer: '78' or '121'
    if s.isdigit():
        return (f'CWE-{s}', False)
    return ('unknown', False)


def _infer_cwe_from_title(title: str) -> str:
    for pat, cwe in _TITLE_CWE_MAP:
        if pat.search(title):
            return cwe
    return 'unknown'


# ── coverage map (CWE → ablation module(s)) ──────────────────────────────────

_CWE_COVERAGE: Dict[str, Optional[str]] = {
    'CWE-78':  'TaintTracker (x86/ARM32/ARM64/PPC32/PPC64/MIPS64/LA64/RISCV32/RISCV64/ARC), SinkArgClassifier, SourceSinkScanner',
    'CWE-77':  'TaintTracker (all arches), SinkArgClassifier',
    'CWE-74':  'LuaInjectionAnalyzer (Lua inject), SourceSinkScanner',
    'CWE-94':  'LuaInjectionAnalyzer, SourceSinkScanner',
    'CWE-79':  None,   # XSS — no binary-level scanner; JS sanitizer gap
    'CWE-89':  'SourceSinkScanner (sql_inject), SourceTaintTracker',
    'CWE-22':  'SourceSinkScanner (path_traversal)',
    'CWE-601': 'SourceSinkScanner (open_redirect)',
    'CWE-134': 'SourceSinkScanner (format_string), SinkArgClassifier',
    'CWE-122': 'LA64HeapVulnScanner, ARM32IntOverflowScanner (boundary check)',
    'CWE-121': 'ARM32IntOverflowScanner',
    'CWE-120': 'ARM32IntOverflowScanner',
    'CWE-119': 'ARM32IntOverflowScanner',
    'CWE-190': 'ARM32IntOverflowScanner, LA64MaxNotMinScanner',
    'CWE-193': 'ARM32IntOverflowScanner',
    'CWE-416': None,   # use-after-free — no dedicated UAF scanner
    'CWE-321': None,   # hardcoded crypto key — SemanticSearcher profiles only (no structured scan)
    'CWE-798': None,   # hardcoded credentials — SemanticSearcher profiles only
    'CWE-295': None,   # cert validation bypass — no dedicated scanner
    'CWE-287': None,   # improper authentication — SourceIsolationChecker (partial)
    'CWE-306': 'MCPToolTaintScanner, SourceIsolationChecker',
    'CWE-284': 'MCPToolTaintScanner',
    'CWE-668': 'MCPToolTaintScanner',
    'CWE-319': None,   # cleartext transmission — no dedicated scanner
    'CWE-328': None,   # weak hash — no dedicated scanner
    'CWE-347': None,   # improper signature verification — no dedicated scanner
    'CWE-610': None,   # externally controlled reference — no dedicated scanner
    'CWE-494': None,   # download without integrity check — no dedicated scanner
    'CWE-426': None,   # untrusted search path — no dedicated scanner
    'CWE-611': None,   # XXE — no dedicated scanner
    'CWE-918': None,   # SSRF — no dedicated scanner
    'CWE-200': None,   # info disclosure — no dedicated scanner
    'CWE-362': None,   # race condition — no dedicated scanner
    'CWE-476': None,   # null deref — no dedicated scanner
    'CWE-908': None,   # use of uninit memory — no dedicated scanner
}

# CWE descriptions for report readability
_CWE_NAMES: Dict[str, str] = {
    'CWE-78':  'OS Command Injection',
    'CWE-77':  'Command Injection',
    'CWE-74':  'Injection (general)',
    'CWE-94':  'Code Injection',
    'CWE-79':  'XSS',
    'CWE-89':  'SQL Injection',
    'CWE-22':  'Path Traversal',
    'CWE-601': 'Open Redirect',
    'CWE-134': 'Format String',
    'CWE-122': 'Heap Buffer Overflow',
    'CWE-121': 'Stack Buffer Overflow',
    'CWE-120': 'Buffer Copy without Size Check',
    'CWE-119': 'Improper Memory Operation',
    'CWE-190': 'Integer Overflow',
    'CWE-193': 'Off-by-One',
    'CWE-416': 'Use-After-Free',
    'CWE-321': 'Hardcoded Crypto Key',
    'CWE-798': 'Hardcoded Credentials',
    'CWE-295': 'Certificate Validation Bypass',
    'CWE-287': 'Improper Authentication',
    'CWE-306': 'Missing Authentication',
    'CWE-284': 'Improper Access Control',
    'CWE-668': 'Exposure to Wrong Sphere',
    'CWE-319': 'Cleartext Transmission',
    'CWE-328': 'Weak Hash',
    'CWE-347': 'Signature Verification Bypass',
    'CWE-610': 'Externally Controlled Reference',
    'CWE-494': 'Download Without Integrity Check',
    'CWE-426': 'Untrusted Search Path',
    'CWE-611': 'XXE',
    'CWE-918': 'SSRF',
    'CWE-200': 'Information Disclosure',
    'CWE-362': 'Race Condition',
    'CWE-476': 'Null Dereference',
    'CWE-908': 'Use of Uninitialized Memory',
}

# ── dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class CorpusEntry:
    finding_id: str
    vendor: str
    module_file: str
    cwe: str
    cwe_inferred: bool
    severity: str
    title: str

@dataclass
class CoverageGap:
    cwe: str
    cwe_name: str
    count: int
    vendors: List[str]
    scanner: Optional[str]   # None = no scanner at all
    priority: str            # HIGH / MEDIUM / LOW

@dataclass
class CrossTargetPattern:
    cwe: str
    cwe_name: str
    vendor_count: int
    vendors: List[str]
    finding_count: int
    example_titles: List[str]

# ── extraction ────────────────────────────────────────────────────────────────

def _vendor_from_path(path: Path) -> str:
    """Return vendor name (directory right under re/ in the path)."""
    parts = path.parts
    try:
        re_idx = [i for i, p in enumerate(parts) if p == 're'][-1]
        return parts[re_idx + 1] if re_idx + 1 < len(parts) else 'unknown'
    except (IndexError, ValueError):
        return 'unknown'


def _extract_file(path: Path) -> List[CorpusEntry]:
    """Extract all CONFIRMED entries from a single *_re.py file."""
    try:
        src = path.read_text(encoding='utf-8', errors='replace')
        tree = ast.parse(src)
    except Exception:
        return []

    vendor = _vendor_from_path(path)
    results: List[CorpusEntry] = []

    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if 'FINDINGS' not in targets:
            continue
        if not isinstance(node.value, ast.Dict):
            continue

        for key, val in zip(node.value.keys, node.value.values):
            try:
                fid = ast.literal_eval(key)
            except Exception:
                continue
            if not isinstance(val, ast.Dict):
                continue

            fdata: Dict = {}
            for k, v in zip(val.keys, val.values):
                try:
                    fdata[ast.literal_eval(k)] = ast.literal_eval(v)
                except Exception:
                    pass

            if fdata.get('status') != 'CONFIRMED':
                continue

            title = str(fdata.get('title', ''))
            severity = str(fdata.get('severity', 'unknown')).upper()

            cwe_raw = fdata.get('cwe')
            if cwe_raw is not None:
                cwe, inferred = _normalize_cwe(cwe_raw)
            else:
                cwe = _infer_cwe_from_title(title)
                inferred = cwe != 'unknown'

            results.append(CorpusEntry(
                finding_id=str(fid),
                vendor=vendor,
                module_file=path.name,
                cwe=cwe,
                cwe_inferred=inferred,
                severity=severity,
                title=title[:100],
            ))

    return results


# ── main class ────────────────────────────────────────────────────────────────

class FindingCorpusMiner:
    """Mine confirmed findings from all *_re.py modules in re/."""

    RE_DIR: Path = Path.home() / 'ablation' / 're'

    def __init__(self, re_dir: Optional[Path] = None) -> None:
        self._re_dir = Path(re_dir) if re_dir else self.RE_DIR

    def extract(self) -> List[CorpusEntry]:
        """Return all CONFIRMED findings across all RE modules."""
        results: List[CorpusEntry] = []
        for path in sorted(self._re_dir.rglob('*_re.py')):
            results.extend(_extract_file(path))
        return results

    @staticmethod
    def coverage_gaps(
        entries: List[CorpusEntry],
        min_count: int = 2,
    ) -> List[CoverageGap]:
        """Return CWEs with ≥ min_count findings ordered by priority."""
        cwe_vendors: Dict[str, set] = defaultdict(set)
        cwe_count: Counter = Counter()
        for e in entries:
            if e.cwe == 'unknown':
                continue
            cwe_count[e.cwe] += 1
            cwe_vendors[e.cwe].add(e.vendor)

        gaps: List[CoverageGap] = []
        for cwe, count in cwe_count.most_common():
            if count < min_count:
                continue
            scanner = _CWE_COVERAGE.get(cwe)
            vendors = sorted(cwe_vendors[cwe])
            vendor_count = len(vendors)
            # Priority: no scanner + many vendors → HIGH
            if scanner is None and vendor_count >= 3:
                priority = 'HIGH'
            elif scanner is None and count >= 3:
                priority = 'HIGH'
            elif scanner is None:
                priority = 'MEDIUM'
            else:
                priority = 'COVERED'
            gaps.append(CoverageGap(
                cwe=cwe,
                cwe_name=_CWE_NAMES.get(cwe, ''),
                count=count,
                vendors=vendors,
                scanner=scanner,
                priority=priority,
            ))
        return gaps

    @staticmethod
    def cross_target_patterns(
        entries: List[CorpusEntry],
        min_vendors: int = 2,
    ) -> List[CrossTargetPattern]:
        """Return CWEs found in ≥ min_vendors distinct vendors, sorted by vendor count."""
        cwe_data: Dict[str, Dict] = defaultdict(lambda: {
            'vendors': set(), 'count': 0, 'titles': []
        })
        for e in entries:
            if e.cwe == 'unknown':
                continue
            cwe_data[e.cwe]['vendors'].add(e.vendor)
            cwe_data[e.cwe]['count'] += 1
            if len(cwe_data[e.cwe]['titles']) < 3:
                cwe_data[e.cwe]['titles'].append(e.title[:70])

        patterns = [
            CrossTargetPattern(
                cwe=cwe,
                cwe_name=_CWE_NAMES.get(cwe, ''),
                vendor_count=len(d['vendors']),
                vendors=sorted(d['vendors']),
                finding_count=d['count'],
                example_titles=d['titles'],
            )
            for cwe, d in cwe_data.items()
            if len(d['vendors']) >= min_vendors
        ]
        return sorted(patterns, key=lambda p: (-p.vendor_count, -p.finding_count))

    @staticmethod
    def render_report(
        entries: List[CorpusEntry],
        gaps: List[CoverageGap],
        patterns: List[CrossTargetPattern],
    ) -> str:
        lines: List[str] = []

        # ── Summary ──────────────────────────────────────────────────────────
        sev_counts = Counter(e.severity for e in entries)
        vendor_counts = Counter(e.vendor for e in entries)
        inferred = sum(1 for e in entries if e.cwe_inferred)
        unknown = sum(1 for e in entries if e.cwe == 'unknown')

        lines += [
            '# Ablation Finding Corpus — Cross-Target Analysis',
            '',
            f'**Total confirmed findings**: {len(entries)}  ',
            f'**Vendors / targets**: {len(vendor_counts)}  ',
            f'**CWE coverage**: {len(entries) - unknown}/{len(entries)} have CWE '
            f'({inferred} inferred from title)',
            '',
            '## Severity Distribution',
            '',
        ]
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'INFO']:
            if sev in sev_counts:
                bar = '█' * min(sev_counts[sev], 40)
                lines.append(f'  {sev:<15} {sev_counts[sev]:3d}  {bar}')
        lines.append('')

        # ── By vendor ────────────────────────────────────────────────────────
        lines += ['## Findings by Vendor (top 15)', '']
        for vendor, count in vendor_counts.most_common(15):
            bar = '█' * min(count, 40)
            lines.append(f'  {vendor:<20} {count:3d}  {bar}')
        lines.append('')

        # ── CWE frequency ────────────────────────────────────────────────────
        lines += ['## CWE Frequency (covered / gap)', '']
        lines.append(f'  {"CWE":<12} {"Name":<35} {"N":>4}  {"Vendors":>7}  Status')
        lines.append('  ' + '-' * 80)
        for gap in sorted(gaps, key=lambda g: -g.count):
            status = f'COVERED ({gap.scanner[:30]}...)' if gap.scanner else f'GAP [{gap.priority}]'
            lines.append(
                f'  {gap.cwe:<12} {gap.cwe_name:<35} {gap.count:4d}  '
                f'{len(gap.vendors):7d}  {status}'
            )
        lines.append('')

        # ── Top gaps ─────────────────────────────────────────────────────────
        top_gaps = [g for g in gaps if g.scanner is None]
        if top_gaps:
            lines += ['## Coverage Gaps (no ablation scanner)', '']
            lines.append(f'  {"CWE":<12} {"Name":<35} {"N":>4}  {"Vendors":>7}  Priority')
            lines.append('  ' + '-' * 80)
            for g in sorted(top_gaps, key=lambda g: -(g.count * len(g.vendors))):
                lines.append(
                    f'  {g.cwe:<12} {g.cwe_name:<35} {g.count:4d}  '
                    f'{len(g.vendors):7d}  {g.priority}'
                )
                lines.append(f'    vendors: {", ".join(g.vendors)}')
            lines.append('')

        # ── Cross-target patterns ─────────────────────────────────────────────
        if patterns:
            lines += ['## Cross-Target Patterns (same CWE, multiple vendors)', '']
            for p in patterns[:15]:
                scanner = _CWE_COVERAGE.get(p.cwe)
                covered = 'COVERED' if scanner else 'NO SCANNER ← module candidate'
                lines.append(
                    f'  {p.cwe} ({p.cwe_name}) — {p.vendor_count} vendors, '
                    f'{p.finding_count} findings — {covered}'
                )
                lines.append(f'    vendors: {", ".join(p.vendors)}')
                for t in p.example_titles:
                    lines.append(f'    · {t}')
                lines.append('')

        return '\n'.join(lines) + '\n'


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='Mine cross-target finding patterns from RE corpus')
    ap.add_argument('--re-dir', default='', help='Override re/ directory path')
    ap.add_argument('--min-count', type=int, default=2,
                    help='Minimum finding count to include in gap analysis (default 2)')
    ap.add_argument('--min-vendors', type=int, default=2,
                    help='Minimum vendor count for cross-target patterns (default 2)')
    ap.add_argument('--json', action='store_true', help='Output machine-readable JSON')
    ap.add_argument('--out', default='', help='Write report to this file (default: stdout)')
    args = ap.parse_args()

    re_dir = Path(args.re_dir) if args.re_dir else None
    miner = FindingCorpusMiner(re_dir=re_dir)

    print('[*] Extracting findings from RE corpus...', file=sys.stderr)
    entries = miner.extract()
    print(f'[*] {len(entries)} confirmed findings extracted', file=sys.stderr)

    gaps = miner.coverage_gaps(entries, min_count=args.min_count)
    patterns = miner.cross_target_patterns(entries, min_vendors=args.min_vendors)

    if args.json:
        output = json.dumps({
            'entries': [asdict(e) for e in entries],
            'gaps': [asdict(g) for g in gaps],
            'patterns': [asdict(p) for p in patterns],
        }, indent=2)
    else:
        output = FindingCorpusMiner.render_report(entries, gaps, patterns)

    if args.out:
        Path(args.out).write_text(output)
        print(f'[*] Report written to {args.out}', file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
