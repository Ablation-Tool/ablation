"""
advisor.py — On-demand RE/security code reviewer via the claude CLI.

Provides a single review(content, context) call that sends code or a diff to
claude-opus-4-7 with a binary-RE-specific system prompt and returns structured
findings. No ANTHROPIC_API_KEY required — uses claudeAiOauth from the CLI.

Usage:
    from ablation.analyzers.advisor import Advisor
    a = Advisor()
    result = a.review(open('my_module.py').read())
    for f in result.findings:
        print(f.severity, f.location, f.description)
    print(result.summary)
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass, field

_DEFAULT_MODEL = 'claude-sonnet-4-6'

_SYSTEM_PROMPT = (
    'You are a senior binary RE and security code reviewer for Ablation, '
    'a Python firmware RE toolkit (angr/capstone/LIEF/Unicorn). '
    'Review the provided code or diff. Be terse and direct — only report real issues, '
    'not style preferences or non-issues. '
    'Each finding on its own line: SEVERITY [location] description. '
    'Location is file:line or function name. '
    'Severity levels: CRIT / HIGH / MED / LOW / INFO. '
    'Finish with one plain summary sentence on its own line.'
)

_DISALLOWED_TOOLS = 'Bash,Edit,Write,MultiEdit,WebSearch,WebFetch,Workflow,Agent,Task'


# ── Result types ───────────────────────────────────────────────────────────────

@dataclass
class ReviewFinding:
    severity:    str
    location:    str
    description: str


@dataclass
class ReviewResult:
    findings: list[ReviewFinding]
    summary:  str
    raw:      str
    model:    str


# ── Advisor ────────────────────────────────────────────────────────────────────

class Advisor:
    """
    Single-call code reviewer using the claude CLI.

    Uses the same subprocess + tempdir isolation pattern as llm_analyst.
    Works with claudeAiOauth (no ANTHROPIC_API_KEY needed).
    """

    def __init__(self, model: str = _DEFAULT_MODEL):
        self._model = model

    def review(self, content: str, context: str = '') -> ReviewResult:
        """
        Review code or a diff.

        Args:
            content: The code or diff text to review.
            context: Optional one-line description of what this is / what to focus on.

        Returns:
            ReviewResult with parsed findings, summary, and raw text.

        Raises:
            RuntimeError: if the claude CLI returns a non-zero exit or is_error=true.
        """
        prompt = f'{context.strip()}\n\n{content}' if context.strip() else content
        raw = self._call_claude_cli(prompt)
        return self._parse_review(raw)

    # ── CLI call ──────────────────────────────────────────────────────────────

    def _call_claude_cli(self, prompt: str) -> str:
        cmd = [
            'claude', '-p', '-',
            '--model', self._model,
            '--output-format', 'json',
            '--system-prompt', _SYSTEM_PROMPT,
            '--disallowedTools', _DISALLOWED_TOOLS,
        ]

        with tempfile.TemporaryDirectory() as cwd:
            proc = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=cwd,
            )

        if proc.returncode != 0:
            raise RuntimeError(
                f'claude CLI exit {proc.returncode}: '
                f'{(proc.stderr or proc.stdout)[:300]}'
            )

        try:
            events = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return proc.stdout.strip()

        result_event = next(
            (e for e in events if e.get('type') == 'result'),
            None,
        )
        if result_event is None:
            raise RuntimeError(f'no result event in output: {proc.stdout[:300]}')

        if result_event.get('is_error'):
            raise RuntimeError(
                f'claude CLI error: {result_event.get("result", "")[:300]}'
            )

        return result_event.get('result', '').strip()

    # ── response parsing ──────────────────────────────────────────────────────

    def _parse_review(self, text: str) -> ReviewResult:
        """
        Extract structured findings from the reviewer's text response.

        Findings pattern: SEVERITY [location] description
        Summary: last non-finding, non-empty line.
        """
        _FINDING_RE = re.compile(
            r'^(CRIT|HIGH|MED|LOW|INFO)\s+\[([^\]]+)\]\s+(.+)$'
        )
        findings: list[ReviewFinding] = []
        summary  = ''

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _FINDING_RE.match(line)
            if m:
                findings.append(ReviewFinding(
                    severity=m.group(1),
                    location=m.group(2),
                    description=m.group(3),
                ))
            else:
                summary = line

        return ReviewResult(
            findings=findings,
            summary=summary,
            raw=text,
            model=self._model,
        )
