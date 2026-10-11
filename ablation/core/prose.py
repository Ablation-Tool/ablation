"""
prose.py: White-bronco prose linter for Ablation documentation.

Checks text for violations of the white-bronco writing style:
no em dashes, no parenthetical feature lists, no filler words, no AI copy.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


# ── Issue type ─────────────────────────────────────────────────────────────────

@dataclass
class ProseIssue:
    rule:       str   # em_dash | parenthetical | filler | ai_copy
    line:       int   # 1-indexed
    col:        int   # 1-indexed
    text:       str   # matched text
    suggestion: str   # what to write instead


# ── Rules ──────────────────────────────────────────────────────────────────────

_EM_DASH = re.compile(r'—')

_PARENS_LIST = re.compile(r'\([^)]{0,120},[^)]{0,120}\)')

_FILLER_PATTERNS: list[tuple[str, str]] = [
    (r'\bcomprehensive\b',             'drop it'),
    (r'\bpowerful\b',                  'drop it'),
    (r'\brobust\b',                    'drop it'),
    (r'\bseamless(?:ly)?\b',           'drop it'),
    (r'\bstreamline[sd]?\b',           'say what it does instead'),
    (r'\bleverage[sd]?\b',             'use "use"'),
    (r'\butilize[sd]?\b',              'use "use"'),
    (r'\bin\s+order\s+to\s+ensure\b',   'use "so" or be specific'),
    (r'\bfully\s+\w+',                 'drop "fully"'),
    (r'\bin\s+order\s+to\b',           'use "to"'),
    (r'\bas\s+a\s+result\s+of\b',      'use "because"'),
    (r'\bit\s+is\s+worth\s+noting\b',  'say it directly'),
    (r"\bit'?s\s+worth\s+noting\b",    'say it directly'),
    (r'\bplease\s+note\b',             'say it directly'),
    (r'\bnote\s+that\b',               'say it directly'),
    (r'\bstate-of-the-art\b',          'drop it'),
    (r'\bcutting[- ]edge\b',           'drop it'),
]

_AI_COPY_PATTERNS: list[tuple[str, str]] = [
    (r'\bdelve\s+into\b',                      'use "examine" or "look at"'),
    (r'\bin\s+the\s+realm\s+of\b',             'be specific'),
    (r'\bgame[- ]changer\b',                   'say what changed'),
    (r'\binnovative\s+solution\b',             'say what it does'),
    (r'\bat\s+the\s+end\s+of\s+the\s+day\b',  'drop it'),
    (r'\bmoving\s+forward\b',                  'drop it'),
]

_FILLER_RE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.IGNORECASE), s) for p, s in _FILLER_PATTERNS
]
_AI_COPY_RE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.IGNORECASE), s) for p, s in _AI_COPY_PATTERNS
]


# ── Core checker ───────────────────────────────────────────────────────────────

def _scan_line(lineno: int, line: str) -> Iterator[ProseIssue]:
    for m in _EM_DASH.finditer(line):
        yield ProseIssue('em_dash', lineno, m.start() + 1, m.group(),
                         'use a period or "because"')
    for m in _PARENS_LIST.finditer(line):
        yield ProseIssue('parenthetical', lineno, m.start() + 1, m.group(),
                         'inline the items or use a list')
    for pattern, suggestion in _FILLER_RE:
        for m in pattern.finditer(line):
            yield ProseIssue('filler', lineno, m.start() + 1, m.group(), suggestion)
    for pattern, suggestion in _AI_COPY_RE:
        for m in pattern.finditer(line):
            yield ProseIssue('ai_copy', lineno, m.start() + 1, m.group(), suggestion)


def check(text: str) -> list[ProseIssue]:
    """Check a string for white-bronco violations."""
    issues: list[ProseIssue] = []
    for i, line in enumerate(text.splitlines(), start=1):
        issues.extend(_scan_line(i, line))
    return issues


def check_file(path: str) -> list[ProseIssue]:
    """Check a file for white-bronco violations."""
    return check(Path(path).read_text(encoding='utf-8'))


# ── Report ─────────────────────────────────────────────────────────────────────

def report(issues: list[ProseIssue], path: str = '') -> str:
    """Format issues as a colored report."""
    from ablation.core.render import (
        RED, ORANGE, YELLOW, GREEN, GRAY, BOLD, DIM, RESET, section,
    )

    if not issues:
        label = f'{path}  ' if path else ''
        return GREEN + f'{label}No white-bronco violations found.' + RESET

    _RULE_COLOR = {
        'em_dash':       ORANGE,
        'parenthetical': ORANGE,
        'filler':        YELLOW,
        'ai_copy':       RED,
    }

    lines: list[str] = []
    if path:
        lines.append(section(f'prose  {path}', GRAY))
        lines.append('')

    for issue in issues:
        c   = _RULE_COLOR.get(issue.rule, GRAY)
        loc = DIM + f'line {issue.line}:{issue.col}' + RESET
        tag = c + f'[{issue.rule}]' + RESET
        txt = BOLD + f'"{issue.text}"' + RESET
        sug = DIM + f'→ {issue.suggestion}' + RESET
        lines.append(f'  {loc}  {tag}  {txt}  {sug}')

    lines.append('')
    n = len(issues)
    lines.append(DIM + f'{n} violation{"s" if n != 1 else ""} found.' + RESET)
    return '\n'.join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────────

def _main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        prog='python3 -m ablation.core.prose',
        description='White-bronco prose linter',
    )
    parser.add_argument('paths', nargs='+', metavar='FILE',
                        help='Files to check; use - for stdin')
    args = parser.parse_args()

    total = 0
    for p in args.paths:
        if p == '-':
            issues = check(sys.stdin.read())
            label  = '<stdin>'
        else:
            issues = check_file(p)
            label  = p
        print(report(issues, label))
        total += len(issues)

    sys.exit(1 if total else 0)


if __name__ == '__main__':
    _main()
