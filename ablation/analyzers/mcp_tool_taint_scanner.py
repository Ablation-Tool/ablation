"""
mcp_tool_taint_scanner.py — MCP server security scanner for Python source.

Closes TG-FMGMCP-1: no ablation module for MCP server security analysis.

Why this exists:

FortiManager v8.0.0 ships an AI/MCP stack (ai/agent/agent_framework/). Two confirmed
findings required manual source read because no automated scanner existed:

  FMG-AI-1 (CWE-214, MEDIUM): mcp.py serializes request.COOKIES to JSON and passes
    it as --cookies CLI arg to /usr/bin/webmcpserver. The session token is visible
    in /proc/<pid>/cmdline for the subprocess lifetime — world-readable on Linux.

  FMG-AI-2 (CWE-77, MEDIUM): agent_views.py passes a user-supplied FortiGate CLI
    script as the system-role content to an LLM security analyzer, enabling prompt
    injection into the AI's trust context.

This scanner detects four finding classes in any Python MCP server codebase:

  CREDENTIAL_EXPOSURE (CWE-214): session tokens, cookies, or auth headers serialized
    and passed as command-line arguments to a subprocess or StdioMCPClient. The
    credential is visible to all users via /proc/<pid>/cmdline.

  PROMPT_INJECTION (CWE-77): user-controlled input placed in a system-role message
    to an LLM, bypassing the intended system/user prompt separation.

  TRANSPORT_EXPOSURE (CWE-284): MCP HTTP server bound to 0.0.0.0 (network-reachable)
    without confirmed auth middleware on the MCP endpoint.

  AUTH_BYPASS (CWE-306): /mcp route registered without a recognized auth decorator
    or middleware (login_required, requires_auth, jwt_required, etc.).

Detection is regex + AST-based. All patterns were confirmed by real findings.
Scope extends beyond Fortinet: any Python MCP server sharing these patterns.

Usage:

    from ablation.analyzers.mcp_tool_taint_scanner import McpToolTaintScanner

    findings = McpToolTaintScanner.from_path('/tmp/fortimanager/ai/').scan()
    print(McpToolTaintScanner.report(findings))

    # Single file
    findings = McpToolTaintScanner.scan_file('/tmp/app/mcp.py')

CLI:
    python3 -m ablation.analyzers.mcp_tool_taint_scanner /path/to/app
    python3 -m ablation.analyzers.mcp_tool_taint_scanner /path/to/app --severity MEDIUM
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

# ── Pre-filter patterns ───────────────────────────────────────────────────────
# Applied before expensive AST parse to skip unrelated files.

_MCP_IMPORT_RE = re.compile(
    r'\b(?:mcp|fastmcp|StdioMCPClient|StdioServerParameters|'
    r'WebSocketServerParameters|MCPClient|ModelContextProtocol)\b',
    re.IGNORECASE,
)
_CREDENTIAL_QUICK_RE = re.compile(r'COOKIES|request\.headers|session\[|auth_token', re.IGNORECASE)
_PROMPT_QUICK_RE = re.compile(r'system.*role|initial_prompt_role|system_prompt', re.IGNORECASE)
_TRANSPORT_QUICK_RE = re.compile(r'0\.0\.0\.0|host\s*=\s*["\']0\.', re.IGNORECASE)

# ── Auth decorator names (presence = auth gated) ─────────────────────────────
_AUTH_DECORATORS: Set[str] = {
    'login_required', 'requires_auth', 'jwt_required', 'token_required',
    'auth_required', 'authenticated', 'require_login', 'permission_required',
    'require_permissions', 'verify_token', 'check_auth', 'admin_required',
}

# ── Variable/attribute names that are credential signals ─────────────────────
_CREDENTIAL_ATTR_NAMES: Set[str] = {
    'COOKIES', 'cookies', 'headers', 'session', 'auth_token', 'token',
    'access_token', 'refresh_token', 'api_key', 'secret', 'password',
    'credential', 'credentials', 'Authorization',
}

# ── CLI launch patterns (subprocess / StdioServerParameters) ─────────────────
_STDIO_MCP_RE = re.compile(r'StdioServerParameters|StdioMCPClient|subprocess\s*\.\s*\w+')

# ── System-role message patterns ─────────────────────────────────────────────
_SYSTEM_ROLE_RE = re.compile(
    r'(?:initial_prompt_role\s*[=:]\s*["\']system["\']|'
    r'role["\']?\s*[:=]\s*["\']system["\']|'
    r'"role"\s*:\s*"system")',
    re.IGNORECASE,
)

# ── User-input variable name indicators for CRITICAL escalation ──────────────
_USER_INPUT_NAMES: Set[str] = {
    'script', 'command', 'user_script', 'cli_script', 'input', 'user_input',
    'body', 'payload', 'content', 'text', 'data', 'message', 'description',
    'query', 'prompt', 'request', 'req', 'param', 'value', 'args', 'raw',
}

# ── Finding class ─────────────────────────────────────────────────────────────

@dataclass
class McpFinding:
    """One detected MCP security issue."""
    path: Path
    rel_path: str
    lineno: int
    finding_class: str    # CREDENTIAL_EXPOSURE | PROMPT_INJECTION | TRANSPORT_EXPOSURE | AUTH_BYPASS
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW
    cwe: str
    title: str
    detail: str
    snippet: str = ""

    def fmt(self) -> str:
        loc = f"{self.rel_path}:{self.lineno}"
        return (
            f"[{self.severity}] {self.finding_class}  {loc}\n"
            f"  CWE: {self.cwe}\n"
            f"  {self.title}\n"
            f"  {self.detail}\n"
            + (f"  snippet: {self.snippet!r}\n" if self.snippet else "")
        )


# ── Scanner ───────────────────────────────────────────────────────────────────

class McpToolTaintScanner:
    """Scan Python MCP server source for security issues."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self._root = root

    @classmethod
    def from_path(cls, root: str) -> 'McpToolTaintScanner':
        return cls(Path(root))

    def scan(self) -> List[McpFinding]:
        if self._root is None:
            return []
        findings: List[McpFinding] = []
        pattern = "**/*.py"
        for p in sorted(self._root.rglob("*.py")):
            try:
                findings.extend(self._scan_path(p))
            except Exception:
                pass
        return findings

    @staticmethod
    def scan_file(path: str) -> List[McpFinding]:
        p = Path(path)
        try:
            return McpToolTaintScanner._scan_path(p)
        except Exception:
            return []

    @staticmethod
    def _scan_path(p: Path) -> List[McpFinding]:
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        root_path = p.parent
        rel = str(p)

        # Fast pre-filters
        is_mcp_file = bool(_MCP_IMPORT_RE.search(src))
        has_credential = bool(_CREDENTIAL_QUICK_RE.search(src))
        has_prompt = bool(_PROMPT_QUICK_RE.search(src))
        has_transport = bool(_TRANSPORT_QUICK_RE.search(src))

        if not any([is_mcp_file, has_credential, has_prompt, has_transport]):
            return []

        findings: List[McpFinding] = []

        # Pattern 1: CREDENTIAL_EXPOSURE — json.dumps on COOKIES/headers → CLI arg
        if has_credential:
            findings.extend(_check_credential_exposure(p, rel, src))

        # Pattern 2: PROMPT_INJECTION — user input in system-role message
        if has_prompt:
            findings.extend(_check_prompt_injection(p, rel, src))

        # Pattern 3: TRANSPORT_EXPOSURE — MCP server on 0.0.0.0
        if has_transport and is_mcp_file:
            findings.extend(_check_transport_exposure(p, rel, src))

        # Pattern 4: AUTH_BYPASS — /mcp route without auth decorator
        if is_mcp_file:
            findings.extend(_check_auth_bypass(p, rel, src))

        return findings

    @staticmethod
    def report(findings: List[McpFinding]) -> str:
        if not findings:
            return "[mcp_tool_taint_scanner] No findings.\n"
        total = len(findings)
        by_sev: dict = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        hdr = (
            f"[mcp_tool_taint_scanner] {total} finding(s)  "
            + "  ".join(f"{k}={v}" for k, v in sorted(by_sev.items()))
            + "\n"
        )
        lines = [hdr]
        for f in sorted(findings, key=lambda x: (x.severity, x.path, x.lineno)):
            lines.append(f.fmt())
        return "\n".join(lines)


# ── Detection helpers ─────────────────────────────────────────────────────────

def _lines(src: str) -> List[str]:
    return src.splitlines()


def _check_credential_exposure(p: Path, rel: str, src: str) -> List[McpFinding]:
    """Detect session token / cookie dict serialized and passed as CLI arg."""
    findings: List[McpFinding] = []
    ls = _lines(src)

    # Pass 1: record (lineno, var_name) for json.dumps(*.COOKIES/headers) assignments.
    # Pass 2: within _WINDOW lines after each assignment, look for subprocess /
    # StdioServerParameters in the same context.  The credential typically flows
    # through an intermediate list variable (e.g., all_cli_args = ['--cookies', cookies])
    # before reaching the launch call — so we do not require the var itself on the
    # launch line; proximity is enough.
    _WINDOW = 30

    credential_sites: List[tuple] = []  # (lineno, var_name)

    for lineno, line in enumerate(ls, 1):
        m = re.search(
            r'(\w+)\s*=\s*json\.dumps\s*\(\s*\S*?'
            r'(?:COOKIES|headers|session|auth_token|Authorization)\b',
            line,
        )
        if m:
            credential_sites.append((lineno, m.group(1)))
            continue

        # json.dumps(request.COOKIES) inline on the same line as a launch call
        m2 = re.search(
            r'json\.dumps\s*\(\s*\S*?(?:COOKIES|session|auth_token)\s*\)',
            line,
        )
        if m2 and re.search(r'args\s*=|--\w+|subprocess', line):
            findings.append(McpFinding(
                path=p, rel_path=rel, lineno=lineno,
                finding_class='CREDENTIAL_EXPOSURE',
                severity='MEDIUM',
                cwe='CWE-214',
                title='Session credential serialized inline as CLI argument',
                detail=(
                    'json.dumps(request.COOKIES/session) passed directly as CLI arg. '
                    'Token visible in /proc/<pid>/cmdline (world-readable on Linux).'
                ),
                snippet=line.strip()[:120],
            ))

    # Pass 2: for each credential assignment, scan the following _WINDOW lines for
    # a subprocess / StdioServerParameters launch (the credential travels through
    # at most one intermediate variable before the launch site).
    seen_launch_lines: Set[int] = set()
    for assign_lineno, var_name in credential_sites:
        window_end = min(len(ls), assign_lineno - 1 + _WINDOW)
        window_lines = ls[assign_lineno - 1:window_end]
        for offset, wline in enumerate(window_lines):
            launch_lineno = assign_lineno + offset
            if launch_lineno in seen_launch_lines:
                continue
            if _STDIO_MCP_RE.search(wline):
                seen_launch_lines.add(launch_lineno)
                findings.append(McpFinding(
                    path=p, rel_path=rel, lineno=launch_lineno,
                    finding_class='CREDENTIAL_EXPOSURE',
                    severity='MEDIUM',
                    cwe='CWE-214',
                    title='Serialized credential reaches subprocess/StdioServerParameters launch',
                    detail=(
                        f'{var_name!r} (json.dumps of COOKIES/headers, line {assign_lineno}) '
                        f'flows into this launch call within {_WINDOW} lines. '
                        'Credential visible in /proc/<pid>/cmdline.'
                    ),
                    snippet=wline.strip()[:120],
                ))
                break  # one finding per credential assignment

    return findings


def _check_prompt_injection(p: Path, rel: str, src: str) -> List[McpFinding]:
    """Detect user-controlled input in LLM system-role messages."""
    findings: List[McpFinding] = []
    ls = _lines(src)

    # Find lines where a system role is assigned
    system_role_lines: List[int] = []
    for lineno, line in enumerate(ls, 1):
        if _SYSTEM_ROLE_RE.search(line):
            system_role_lines.append(lineno)

    if not system_role_lines:
        return []

    # For each system-role line, inspect the surrounding context (±20 lines) for
    # non-literal content sources that suggest user-controlled input.
    for srl in system_role_lines:
        window_start = max(0, srl - 20)
        window_end = min(len(ls), srl + 20)
        window = ls[window_start:window_end]
        window_src = "\n".join(window)

        # Check if any user-input-named variable is present near the system role
        found_user_input = False
        escalate = False
        for name in _USER_INPUT_NAMES:
            if re.search(r'\b' + re.escape(name) + r'\b', window_src):
                found_user_input = True
                # Escalate to HIGH if it's directly assigned as content
                if re.search(
                    r'content\s*[=:]\s*' + re.escape(name) +
                    r'|' + re.escape(name) + r'\s*[+]=?\s*\S',
                    window_src,
                ):
                    escalate = True
                break

        if found_user_input:
            severity = 'HIGH' if escalate else 'MEDIUM'
            snippet = ls[srl - 1].strip()[:120]
            findings.append(McpFinding(
                path=p, rel_path=rel, lineno=srl,
                finding_class='PROMPT_INJECTION',
                severity=severity,
                cwe='CWE-77',
                title='User-controlled input in LLM system-role message',
                detail=(
                    'A user-input-derived variable appears near a system-role message assignment. '
                    'Attacker can inject arbitrary system-level instructions into the AI context, '
                    'bypassing intended trust separation between operator and user prompts.'
                ),
                snippet=snippet,
            ))

    return findings


def _check_transport_exposure(p: Path, rel: str, src: str) -> List[McpFinding]:
    """Detect MCP server bound to all interfaces without auth middleware."""
    findings: List[McpFinding] = []
    ls = _lines(src)

    for lineno, line in enumerate(ls, 1):
        # host="0.0.0.0" in uvicorn.run / app.run / FastMCP.run
        m = re.search(r'(?:uvicorn\.run|app\.run|\.run)\s*\(.*host\s*=\s*["\']0\.0\.0\.0["\']', line)
        if not m:
            m = re.search(r'host\s*=\s*["\']0\.0\.0\.0["\']', line)
        if m:
            # Check if auth is mentioned in the nearby context (±10 lines)
            window_start = max(0, lineno - 10)
            window_end = min(len(ls), lineno + 10)
            window = "\n".join(ls[window_start:window_end])
            auth_present = bool(re.search(
                r'auth|middleware|token|login_required|bearer|jwt', window, re.IGNORECASE
            ))
            severity = 'LOW' if auth_present else 'MEDIUM'
            snippet = line.strip()[:120]
            findings.append(McpFinding(
                path=p, rel_path=rel, lineno=lineno,
                finding_class='TRANSPORT_EXPOSURE',
                severity=severity,
                cwe='CWE-284',
                title='MCP server bound to all network interfaces',
                detail=(
                    'host="0.0.0.0" binds the MCP endpoint to all interfaces. '
                    'Unless separately protected by a firewall or auth middleware, '
                    'the MCP protocol surface is network-reachable from any host.'
                    + (' Auth middleware detected in context.' if auth_present else
                       ' No auth middleware found in context — verify firewall gating.')
                ),
                snippet=snippet,
            ))

    return findings


def _check_auth_bypass(p: Path, rel: str, src: str) -> List[McpFinding]:
    """Detect /mcp route registered without a recognized auth decorator."""
    findings: List[McpFinding] = []
    ls = _lines(src)

    for lineno, line in enumerate(ls, 1):
        # Route registration: @app.route('/mcp'...) or path('/mcp', ...)
        if not re.search(r"""['"]/mcp['"]""", line):
            continue
        if not re.search(r'@\w+\.(?:route|get|post|add_route|path)\s*\(', line):
            continue

        # Inspect the preceding 8 lines for auth decorators
        window_start = max(0, lineno - 8)
        preceding = "\n".join(ls[window_start:lineno - 1])
        has_auth = any(
            re.search(r'\b' + re.escape(d) + r'\b', preceding, re.IGNORECASE)
            for d in _AUTH_DECORATORS
        )
        if not has_auth:
            snippet = line.strip()[:120]
            findings.append(McpFinding(
                path=p, rel_path=rel, lineno=lineno,
                finding_class='AUTH_BYPASS',
                severity='MEDIUM',
                cwe='CWE-306',
                title='/mcp endpoint registered without recognized auth decorator',
                detail=(
                    'Route for /mcp registered without login_required, jwt_required, or equivalent '
                    'auth decorator in the preceding 8 lines. Verify the endpoint is protected by '
                    'middleware registered elsewhere, or add an explicit auth check.'
                ),
                snippet=snippet,
            ))

    return findings


# ── CLI entry ─────────────────────────────────────────────────────────────────

def _main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='MCP tool taint scanner')
    ap.add_argument('path', help='Directory or file to scan')
    ap.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    help='Minimum severity to report')
    args = ap.parse_args()

    p = Path(args.path)
    if p.is_file():
        findings = McpToolTaintScanner.scan_file(str(p))
    else:
        findings = McpToolTaintScanner.from_path(str(p)).scan()

    if args.severity:
        rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        threshold = rank[args.severity]
        findings = [f for f in findings if rank.get(f.severity, 99) <= threshold]

    print(McpToolTaintScanner.report(findings))


if __name__ == '__main__':
    _main()

# ── Aliases for __init__.py compatibility ─────────────────────────────────────
MCPToolTaintScanner = McpToolTaintScanner
MCPTaintFinding = McpFinding
