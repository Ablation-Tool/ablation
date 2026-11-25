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
from typing import Iterable, List, Optional


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
            with open(self._path, 'rb') as fh:
                return fh.read()
        except OSError:
            return b''

    @classmethod
    def scan_bytes(
        cls,
        raw: bytes,
        plt_names: Iterable[str],
        func_names: Iterable[str],
    ) -> List[ObservabilityFinding]:
        """Audit an in-memory agent runtime buffer given PLT imports and function names."""
        if not raw:
            return []
        if not any(ind in raw for ind in _AGENT_INDICATORS):
            return []

        norm_plt = frozenset(n.split('@')[0].lstrip('_') for n in plt_names)
        funcs = list(func_names)
        findings: list[ObservabilityFinding] = []

        if not (norm_plt & _LOG_SINKS):
            findings.append(ObservabilityFinding(
                'structured_logging',
                _OBS_CATEGORIES['structured_logging'],
                'HIGH',
            ))

        if not any(_HITL_PAT.search(n) for n in funcs):
            findings.append(ObservabilityFinding(
                'hitl_checkpoint',
                _OBS_CATEGORIES['hitl_checkpoint'],
                'HIGH',
            ))

        audit_sinks = {
            'audit_open', 'audit_log_user_message',
            'audit_log_acct_message', 'audit_log_semanage_message',
        }
        if not (norm_plt & audit_sinks):
            findings.append(ObservabilityFinding(
                'audit_trail',
                _OBS_CATEGORIES['audit_trail'],
                'MEDIUM',
            ))

        return findings

    def scan(self) -> List[ObservabilityFinding]:
        raw = self._read_raw()
        if not raw:
            return []
        if not any(ind in raw for ind in _AGENT_INDICATORS):
            return []
        ctx = self._load_ctx()
        plt_names = [n for _, n in ctx.plt.items()]
        func_names = [ctx.name(va) for va in ctx.func_starts]
        return self.scan_bytes(raw, plt_names, func_names)

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
