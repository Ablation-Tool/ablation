"""
agent_authority_audit.py: Agent authority (capability) scope auditor.

For AI agent binaries: maps imported functions into capability categories
(file I/O, network, process execution, credential access, system config)
and reports the total capability scope. Highlights authority surplus:
capabilities imported but unlikely to be needed for the agent's stated
function (inferred from API hostname patterns).

Principle: an agent that calls api.openai.com should not also import
system(), execve(), or write to /etc/passwd. If it does, the imported
authority is wider than the task requires, creating confused-deputy risk.

Detection strategy:
  1. Map all PLT imports to capability categories.
  2. Detect agent type from string patterns (AI agent, web agent, CLI agent).
  3. Compute expected vs. actual capability set.
  4. Flag capabilities that are unexpected for the detected agent type.

Usage:
    auditor = AgentAuthorityAudit('/path/to/binary')
    findings = auditor.scan()
    print(auditor.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    auditor = AgentAuthorityAudit.from_context(ctx)
    findings = auditor.scan()
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ── Capability categories ──────────────────────────────────────────────────────

_CAPABILITY_MAP: dict[str, frozenset] = {
    'process_execution': frozenset({
        'system', 'execve', 'execl', 'execvp', 'execvpe', 'execle',
        'popen', 'posix_spawn', 'posix_spawnp',
        'CreateProcessA', 'CreateProcessW', 'ShellExecuteA', 'ShellExecuteW',
        'WinExec',
    }),
    'file_write': frozenset({
        'fwrite', 'fputs', 'write', 'pwrite', 'pwrite64',
        'rename', 'unlink', 'remove', 'truncate', 'ftruncate',
        'chmod', 'chown', 'mkdir', 'rmdir',
        'WriteFile', 'DeleteFileA', 'DeleteFileW',
    }),
    'network_raw': frozenset({
        'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv',
        'sendto', 'recvfrom', 'setsockopt', 'getsockopt',
        'WSASocket', 'WSAConnect',
    }),
    'credential_access': frozenset({
        'getpwnam', 'getpwuid', 'shadow', 'pam_authenticate',
        'CryptAcquireContextA', 'CryptGenRandom',
        'SecretServiceGet', 'keyctl',
    }),
    'system_config': frozenset({
        'setuid', 'setgid', 'seteuid', 'setegid',
        'chroot', 'mount', 'umount', 'ioctl',
        'sysctl', 'prctl', 'ptrace',
        'AdjustTokenPrivileges', 'SetTokenInformation',
    }),
    'memory_injection': frozenset({
        'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
        'NtWriteVirtualMemory', 'NtCreateThreadEx',
        'mmap', 'mprotect',
    }),
    'persistence': frozenset({
        'RegSetValueExA', 'RegSetValueExW',
        'RegCreateKeyExA', 'RegCreateKeyExW',
        'WritePrivateProfileStringA',
        'crontab', 'systemctl', 'launchctl',
    }),
}

# Which capabilities are acceptable for an AI agent (LLM API caller)
_EXPECTED_FOR_AI_AGENT: frozenset = frozenset({
    'network_raw',   # needs HTTP to reach AI API
})

_HIGH_RISK_ALWAYS: frozenset = frozenset({
    'process_execution', 'memory_injection', 'persistence',
    'system_config', 'credential_access',
})

# Agent type detection patterns
_AGENT_TYPE_PATTERNS: dict[str, list[re.Pattern]] = {
    'ai_agent': [
        re.compile(rb'api\.openai\.com', re.I),
        re.compile(rb'api\.anthropic\.com', re.I),
        re.compile(rb'ChatCompletion', re.I),
        re.compile(rb'messages\.create', re.I),
        re.compile(rb'GenerateContent', re.I),
    ],
    'web_agent': [
        re.compile(rb'selenium', re.I),
        re.compile(rb'playwright', re.I),
        re.compile(rb'puppeteer', re.I),
        re.compile(rb'webdriver', re.I),
    ],
    'cli_agent': [
        re.compile(rb'subprocess\.run', re.I),
        re.compile(rb'bash -c', re.I),
        re.compile(rb'/bin/sh', re.I),
    ],
}


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class AuthorityFinding:
    agent_type:          str         # detected agent type or 'unknown'
    excess_capabilities: list[str]   # capabilities not expected for this agent type
    all_capabilities:    list[str]   # all detected capability categories
    severity:            str         # HIGH / MEDIUM

    def fmt(self) -> str:
        excess = ', '.join(self.excess_capabilities) or 'none'
        all_caps = ', '.join(self.all_capabilities) or 'none'
        return (f"  {self.severity:6s}  [AGENT_AUTHORITY_SURPLUS]  agent_type={self.agent_type}\n"
                f"         all capabilities: {all_caps}\n"
                f"         excess (unexpected): {excess}")


# ── Auditor ────────────────────────────────────────────────────────────────────

class AgentAuthorityAudit:
    """Audit agent capability scope for authority surplus."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'AgentAuthorityAudit':
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

    def _plt_names(self) -> frozenset:
        try:
            ctx = self._load_ctx()
            return frozenset(
                n.split('@')[0].lstrip('_')
                for _, n in ctx.plt.items()
            )
        except Exception:
            return frozenset()

    def _detect_agent_type(self, raw: bytes) -> str:
        for agent_type, patterns in _AGENT_TYPE_PATTERNS.items():
            if any(p.search(raw) for p in patterns):
                return agent_type
        return 'unknown'

    def _detect_capabilities(self, plt_names: frozenset) -> list[str]:
        found: list[str] = []
        for category, api_set in _CAPABILITY_MAP.items():
            if plt_names & api_set:
                found.append(category)
        return found

    def scan(self) -> List[AuthorityFinding]:
        raw = self._read_raw()
        if not raw:
            return []

        plt_names = self._plt_names()
        agent_type = self._detect_agent_type(raw)
        if agent_type == 'unknown':
            return []  # not an agent binary

        capabilities = self._detect_capabilities(plt_names)
        if not capabilities:
            return []

        expected = _EXPECTED_FOR_AI_AGENT if agent_type == 'ai_agent' else frozenset()
        excess = [c for c in capabilities if c not in expected]
        if not excess:
            return []

        high_risk = [c for c in excess if c in _HIGH_RISK_ALWAYS]
        severity = 'HIGH' if high_risk else 'MEDIUM'

        return [AuthorityFinding(
            agent_type=agent_type,
            excess_capabilities=excess,
            all_capabilities=capabilities,
            severity=severity,
        )]

    def report(self, findings: Optional[List[AuthorityFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'AgentAuthorityAudit: no authority surplus detected in {self._path}'
        lines = [f'AgentAuthorityAudit: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
