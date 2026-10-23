"""
agent_observability_audit.py: Agent observability and audit trail auditor.

Detects agentic LLM runtime binaries that lack the logging and observability
functions needed to reconstruct what actions the agent took. Without audit
trails, post-incident analysis of an LLM agent that ran a malicious tool call
is impossible: there is no record of what the model decided, what tool it
invoked, or what the tool returned.

Observable patterns required in a well-instrumented agent:
  - Structured logging before and after each tool call (log4c, syslog, write
    to a log file, emit to a metrics endpoint)
  - Tool call result recording (the output of each tool call stored)
  - HITL (human-in-the-loop) confirmation: functions named confirm, approve,
    checkpoint, or review that interrupt the agentic loop
  - Error path logging: error/exception handling that emits to a log sink

What this module checks:
  1. Is any logging sink present (syslog, openlog, syslog_r, log4c_init,
     zlog_init, write-to-log-path patterns)?
  2. Is any HITL pattern present (function names: confirm, approve, review,
     checkpoint, interrupt, pause)?
  3. Is any audit/trace sink present (audit_open, audit_log, AUDIT_USER_MSG)?
  4. Reports each absent category as a separate finding.

Usage:
    auditor = AgentObservabilityAudit('/path/to/binary')
    findings = auditor.scan()
    print(auditor.report(findings))
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


# Logging/audit PLT functions
_LOG_SINKS: frozenset = frozenset({
    'syslog', 'vsyslog', 'openlog', 'closelog',
    'log4c_init', 'log4c_fini',
    'zlog_init', 'zlog_finish',
    'fprintf',   # often used for stderr logging
    'audit_open', 'audit_log_user_message', 'audit_log_acct_message',
    'sd_journal_print', 'sd_journal_send',
})

# LLM agent context indicators: binary is an agent runtime
_AGENT_INDICATORS: list[bytes] = [
    b'tool_call',
    b'tool_result',
    b'function_call',
    b'function_result',
    b'"role":"assistant"',
    b'"role": "assistant"',
    b'agent_loop',
    b'agentic',
    b'run_agent',
    b'agent_step',
]

# HITL function name patterns
_HITL_PAT = re.compile(
    r'(confirm|approve|checkpoint|interrupt_agent|pause_agent|review_action|'
    r'request_approval|human_review|hitl|human.in.the.loop)',
    re.I,
)

# Observability categories
_OBS_CATEGORIES = {
    'structured_logging': 'No structured logging sink found (syslog, log4c, sd_journal, audit_log)',
    'hitl_checkpoint':    'No HITL confirmation function found (confirm, approve, checkpoint, review)',
    'audit_trail':        'No kernel audit trail sink found (audit_open, audit_log_user_message)',
}


@dataclass
class ObservabilityFinding:
    category:  str     # observability category absent
    detail:    str     # why it was determined absent
    severity:  str

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [NO_OBSERVABILITY]  {self.category}\n"
                f"         {self.detail}")


class AgentObservabilityAudit:
    """Detect absent audit trail components in LLM agent runtimes."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'AgentObservabilityAudit':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _load_ctx(self):
        if self._ctx is not None:
            return self._ctx
        from ablation.analyzers.binary_context import BinaryContext
        self._ctx = BinaryContext.load_or_build(self._path)
        return self._ctx

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def scan(self) -> List[ObservabilityFinding]:
        raw = self._read_raw()
        if not raw:
            return []

        # Gate: is this an agent runtime binary?
        is_agent = any(ind in raw for ind in _AGENT_INDICATORS)
        if not is_agent:
            return []

        ctx = self._load_ctx()
        plt_names = frozenset(n.split('@')[0].lstrip('_') for _, n in ctx.plt.items())
        func_names = [ctx.name(va) for va in ctx.func_starts]

        findings: list[ObservabilityFinding] = []

        # Check 1: structured logging sinks
        log_imports = sorted(plt_names & _LOG_SINKS)
        has_logging = bool(log_imports)
        if not has_logging:
            findings.append(ObservabilityFinding(
                'structured_logging',
                _OBS_CATEGORIES['structured_logging'],
                'HIGH',
            ))

        # Check 2: HITL confirmation
        hitl_funcs = [n for n in func_names if _HITL_PAT.search(n)]
        if not hitl_funcs:
            findings.append(ObservabilityFinding(
                'hitl_checkpoint',
                _OBS_CATEGORIES['hitl_checkpoint'],
                'HIGH',
            ))

        # Check 3: kernel audit trail
        audit_imports = sorted(plt_names & {'audit_open', 'audit_log_user_message',
                                            'audit_log_acct_message', 'audit_log_semanage_message'})
        if not audit_imports:
            findings.append(ObservabilityFinding(
                'audit_trail',
                _OBS_CATEGORIES['audit_trail'],
                'MEDIUM',
            ))

        return findings

    def report(self, findings: Optional[List[ObservabilityFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'AgentObservabilityAudit: all observability checks passed in {self._path}'
        lines = [f'AgentObservabilityAudit: {len(findings)} absent component(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
