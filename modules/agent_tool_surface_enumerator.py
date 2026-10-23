"""
agent_tool_surface_enumerator.py: Agent tool-surface enumerator.

Extracts tool/function definitions from JSON schema strings embedded in a
binary. When an LLM agent registers its available tools, those definitions
appear as JSON objects containing "name", "description", and "parameters"
keys. This module finds those schema blobs and enumerates the tool surface
exposed to the LLM: what the agent can do, what inputs each tool accepts,
and whether any tool bypasses security boundaries (shell exec, file write,
network send).

Detection:
  1. Find all candidate JSON blobs (between { and matching }) in rodata.
  2. Filter for objects containing at minimum "name" and either "description"
     or "parameters" keys.
  3. Extract tool names and flag any that map to dangerous capabilities:
       - Shell execution: run, exec, bash, shell, command, execute
       - File operations: write_file, create_file, edit_file, delete_file
       - Network: fetch, http_request, send_request, web_search (some risk)
       - Code execution: python, javascript, eval, run_code
       - System: spawn_process, kill_process, list_processes
  4. Emit a finding per dangerous tool with the capability class.

Usage:
    enumerator = AgentToolSurfaceEnumerator('/path/to/binary')
    findings = enumerator.scan()
    print(enumerator.report(findings))
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


# Patterns for tool definition JSON blobs in rodata
_TOOL_JSON_PAT = re.compile(
    rb'"name"\s*:\s*"([^"]{1,80})".*?"(?:description|parameters)"\s*:',
    re.DOTALL,
)

# High-risk tool name patterns per capability class
_HIGH_RISK_TOOLS: dict[str, list[re.Pattern]] = {
    'shell_execution': [
        re.compile(r'(run|exec|bash|shell|command|execute|cmd|terminal)', re.I),
    ],
    'code_execution': [
        re.compile(r'(python|javascript|eval|run_code|execute_code|repl)', re.I),
    ],
    'file_write': [
        re.compile(r'(write_file|create_file|edit_file|delete_file|overwrite|patch_file)', re.I),
    ],
    'process_control': [
        re.compile(r'(spawn_process|kill_process|list_processes|start_service)', re.I),
    ],
    'network_request': [
        re.compile(r'(http_request|fetch_url|send_request|post_to|make_request)', re.I),
    ],
    'credential_access': [
        re.compile(r'(get_secret|read_credential|get_api_key|retrieve_token|keychain)', re.I),
    ],
}

# Medium risk: useful but should be reviewed
_MEDIUM_RISK_TOOLS: dict[str, list[re.Pattern]] = {
    'web_search': [
        re.compile(r'(web_search|search_web|google|bing_search|duckduckgo)', re.I),
    ],
    'file_read': [
        re.compile(r'(read_file|open_file|get_file|load_file|file_contents)', re.I),
    ],
}


@dataclass
class ToolSurfaceFinding:
    tool_name:    str
    capability:   str     # capability class
    severity:     str     # HIGH / MEDIUM

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [TOOL_SURFACE]  {self.tool_name}\n"
                f"         capability: {self.capability}")


class AgentToolSurfaceEnumerator:
    """Extract and classify agent tool definitions from binary rodata."""

    def __init__(self, path: str) -> None:
        self._path = path

    @classmethod
    def from_context(cls, ctx) -> 'AgentToolSurfaceEnumerator':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        return obj

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def _classify_tool(self, name: str) -> tuple[str, str]:
        for cap, patterns in _HIGH_RISK_TOOLS.items():
            for pat in patterns:
                if pat.search(name):
                    return cap, 'HIGH'
        for cap, patterns in _MEDIUM_RISK_TOOLS.items():
            for pat in patterns:
                if pat.search(name):
                    return cap, 'MEDIUM'
        return '', ''

    def scan(self) -> List[ToolSurfaceFinding]:
        raw = self._read_raw()
        if not raw:
            return []

        findings: list[ToolSurfaceFinding] = []
        seen: set[str] = set()

        for match in _TOOL_JSON_PAT.finditer(raw):
            try:
                tool_name = match.group(1).decode('utf-8', errors='replace').strip()
            except (IndexError, AttributeError):
                continue

            if tool_name in seen:
                continue
            seen.add(tool_name)

            capability, severity = self._classify_tool(tool_name)
            if not capability:
                continue

            findings.append(ToolSurfaceFinding(
                tool_name=tool_name,
                capability=capability,
                severity=severity,
            ))

        return findings

    def report(self, findings: Optional[List[ToolSurfaceFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'AgentToolSurfaceEnumerator: no dangerous tool definitions in {self._path}'
        lines = [f'AgentToolSurfaceEnumerator: {len(findings)} tool(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
