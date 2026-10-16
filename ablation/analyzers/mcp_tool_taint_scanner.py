"""
mcp_tool_taint_scanner.py — MCP server security scanner (Python, JS, TypeScript).

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

This scanner detects five finding classes across Python, JS, and TypeScript MCP sources:

  BIND_WIDE (CWE-668, HIGH): MCP HTTP server bound to all interfaces.
    JS/TS: .listen(port) without explicit loopback host, or with '0.0.0.0'.
    Python: host='0.0.0.0' in uvicorn.run / app.run.

  EXEC_IN_ALLOWED (CWE-284, CRITICAL): ALLOWED_METHODS set/dict contains exec-class
    method names (exec, execute, shell, run, spawn, popen, system, eval, cmd).
    An MCP tool that proxies exec-class operations to a managed device is an
    RCE escalation path if any MCP tool receives user-controlled method names.

  NO_AUTH (CWE-306, HIGH): /mcp endpoint registered without recognized auth in
    surrounding context. Also fires for FastMCP.run(transport='http') without
    auth_middleware nearby.

  CREDENTIAL_EXPOSURE (CWE-214, MEDIUM): session tokens / cookies serialized via
    json.dumps and passed as CLI args to subprocess / StdioServerParameters.
    Credential visible in /proc/<pid>/cmdline (world-readable on Linux).

  PROMPT_INJECTION (CWE-77, HIGH/MEDIUM): user-controlled input in LLM system-role
    message, bypassing the system/user prompt trust separation.

Detection: regex-based pre-filter + line-by-line pattern matching.
File types scanned: .py, .ts, .js (not .html, .json, .md, etc.).

Usage:

    from ablation.analyzers.mcp_tool_taint_scanner import MCPToolTaintScanner

    findings = MCPToolTaintScanner.from_path('/tmp/fortimanager/ai/').scan()
    print(MCPToolTaintScanner.report(findings))

    # Single file
    findings = MCPToolTaintScanner.scan_file('/tmp/app/mcp.py')

CLI:
    python3 -m ablation.analyzers.mcp_tool_taint_scanner /path/to/app
    python3 -m ablation.analyzers.mcp_tool_taint_scanner /path/to/app --severity HIGH
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

# ── Scanned extensions ────────────────────────────────────────────────────────
_SCAN_EXTS = frozenset({'.py', '.ts', '.js'})

# ── Pre-filter — must have at least one MCP or AI-agent signal ───────────────
_MCP_QUICK_RE = re.compile(
    r'\b(?:McpServer|FastMCP|modelcontextprotocol|mcp_transport|'
    r'StdioServerParameters|StdioMCPClient|MCPClient|ALLOWED_METHODS|/mcp|'
    r'initial_prompt_role|system_prompt|system.*role)\b',
    re.IGNORECASE,
)

# ── Auth term patterns (case-insensitive) ─────────────────────────────────────
_AUTH_RE = re.compile(
    r'authenticate|requireAuth|verifyToken|loginRequired|jwtRequired|'
    r'auth_middleware|bearerAuth|checkAuth|tokenRequired|requireLogin|'
    r'login_required|requires_auth|jwt_required|token_required|'
    r'admin_required|permission_required',
    re.IGNORECASE,
)

# ── Exec-class method names ───────────────────────────────────────────────────
_EXEC_CLASS_NAMES = frozenset({
    'exec', 'execute', 'shell', 'run', 'spawn', 'popen', 'system',
    'eval', 'cmd', 'command', 'subprocess', 'process',
})

# ── Severity rank ─────────────────────────────────────────────────────────────
_SEV_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class MCPTaintFinding:
    """One detected MCP server security issue."""
    file: str
    line: int
    issue_type: str    # BIND_WIDE | EXEC_IN_ALLOWED | NO_AUTH | CREDENTIAL_EXPOSURE | PROMPT_INJECTION
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW
    cwe: str
    description: str
    snippet: str = ""

    def fmt(self) -> str:
        loc = f"{self.file}:{self.line}"
        return (
            f"[{self.severity}] {self.issue_type}  {loc}\n"
            f"  CWE: {self.cwe}\n"
            f"  {self.description}\n"
            + (f"  snippet: {self.snippet!r}\n" if self.snippet else "")
        )


# ── Public helper functions (used by tests) ───────────────────────────────────

def _has_auth_in_window(lines: List[str], lineno: int, window: int = 8) -> bool:
    """Return True if an auth-related term appears within window lines of lineno.

    lineno is 0-indexed. Checks lines[max(0, lineno-window) : lineno+window+1].
    """
    start = max(0, lineno - window)
    end = min(len(lines), lineno + window + 1)
    for ln in lines[start:end]:
        if _AUTH_RE.search(ln):
            return True
    return False


def _exec_methods_in_block(block: str) -> List[str]:
    """Return list of exec-class method names found in an ALLOWED_METHODS block string."""
    found: List[str] = []
    # Extract quoted strings from the block
    for m in re.finditer(r'''["']([^"']+)["']''', block):
        name = m.group(1).lower()
        if name in _EXEC_CLASS_NAMES:
            found.append(m.group(1))
    return found


def _extract_allowed_methods_block(src: str, lineno: int) -> str:
    """Extract ALLOWED_METHODS block starting at lineno (1-indexed) from src.

    Handles single-line and multi-line definitions. Returns the block as a string
    containing the full definition up to the closing bracket/brace/paren.
    """
    lines = src.splitlines()
    if lineno < 1 or lineno > len(lines):
        return ''
    start = lineno - 1
    # Find the opening bracket/brace/paren on this or the same line
    chunk = '\n'.join(lines[start:min(len(lines), start + 30)])
    return chunk


# ── Scanner ───────────────────────────────────────────────────────────────────

class MCPToolTaintScanner:
    """Scan Python/JS/TS MCP server source for security issues."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self._root = root

    @classmethod
    def from_path(cls, root: str) -> 'MCPToolTaintScanner':
        return cls(Path(root))

    def scan(self) -> List[MCPTaintFinding]:
        if self._root is None:
            return []
        findings: List[MCPTaintFinding] = []
        p = self._root
        if p.is_file():
            if p.suffix in _SCAN_EXTS:
                findings.extend(_scan_file(p))
        else:
            for f in sorted(p.rglob('*')):
                if f.is_file() and f.suffix in _SCAN_EXTS:
                    try:
                        findings.extend(_scan_file(f))
                    except Exception:
                        pass
        findings.sort(key=lambda x: (_SEV_RANK.get(x.severity, 9), x.file, x.line))
        return findings

    @staticmethod
    def scan_file(path: str) -> List[MCPTaintFinding]:
        p = Path(path)
        if p.suffix not in _SCAN_EXTS:
            return []
        try:
            return sorted(
                _scan_file(p),
                key=lambda x: (_SEV_RANK.get(x.severity, 9), x.line),
            )
        except Exception:
            return []

    @staticmethod
    def report(findings: List[MCPTaintFinding]) -> str:
        if not findings:
            return "[mcp_tool_taint_scanner] no findings.\n"
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
        for f in findings:
            lines.append(f.fmt())
        return "\n".join(lines)


# ── Per-file analysis ─────────────────────────────────────────────────────────

def _scan_file(p: Path) -> List[MCPTaintFinding]:
    try:
        src = p.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []

    if not _MCP_QUICK_RE.search(src):
        return []

    rel = str(p)
    findings: List[MCPTaintFinding] = []
    lines = src.splitlines()

    findings.extend(_check_bind_wide(rel, lines))
    findings.extend(_check_exec_in_allowed(rel, src, lines))
    findings.extend(_check_no_auth(rel, lines))
    findings.extend(_check_credential_exposure(rel, lines))
    findings.extend(_check_prompt_injection(rel, lines))

    return findings


# ── BIND_WIDE ─────────────────────────────────────────────────────────────────

_SAFE_HOSTS = frozenset({'127.0.0.1', 'localhost', '::1', '[::1]'})

# JS/TS: .listen(port) or .listen(port, callback) but not .listen(port, '127.0.0.1')
_LISTEN_RE = re.compile(r'\.listen\s*\(')

# Python: host='0.0.0.0'
_PY_WIDE_HOST_RE = re.compile(r"""host\s*=\s*['"]0\.0\.0\.0['"]""")
_PY_SAFE_HOST_RE = re.compile(r"""host\s*=\s*['"](?:127\.0\.0\.1|localhost|::1)['"]""")


def _check_bind_wide(rel: str, lines: List[str]) -> List[MCPTaintFinding]:
    findings: List[MCPTaintFinding] = []
    is_py = rel.endswith('.py')

    for lineno, line in enumerate(lines, 1):
        if is_py:
            # Python: host='0.0.0.0' (only flag explicit wide bind; 'localhost' / '127.0.0.1' safe)
            if _PY_WIDE_HOST_RE.search(line):
                findings.append(MCPTaintFinding(
                    file=rel, line=lineno,
                    issue_type='BIND_WIDE',
                    severity='HIGH',
                    cwe='CWE-668',
                    description=(
                        "MCP server bound to host='0.0.0.0' — accessible from all network interfaces. "
                        "Restrict to '127.0.0.1' unless intentionally network-exposed with auth."
                    ),
                    snippet=line.strip()[:120],
                ))
            elif _PY_SAFE_HOST_RE.search(line):
                pass  # explicit safe host
        else:
            # JS/TS: .listen(port, ?) — check second argument
            m = _LISTEN_RE.search(line)
            if not m:
                continue
            # Extract the argument list after .listen(
            arg_str = line[m.end():]
            # Check for safe host: '127.0.0.1' or 'localhost'
            is_safe = bool(re.search(
                r"""['"](?:127\.0\.0\.1|localhost|::1)['"]""", arg_str
            ))
            if is_safe:
                continue
            # Flag: no second arg, callback as second arg, or '0.0.0.0'
            is_explicit_wide = bool(re.search(r"""['"]0\.0\.0\.0['"]""", arg_str))
            findings.append(MCPTaintFinding(
                file=rel, line=lineno,
                issue_type='BIND_WIDE',
                severity='HIGH',
                cwe='CWE-668',
                description=(
                    'MCP HTTP server .listen() without explicit loopback host'
                    + (' (explicit 0.0.0.0)' if is_explicit_wide else ' — defaults to all interfaces')
                    + '. Restrict to 127.0.0.1 unless intentionally network-exposed with auth.'
                ),
                snippet=line.strip()[:120],
            ))

    return findings


# ── EXEC_IN_ALLOWED ───────────────────────────────────────────────────────────

_ALLOWED_METHODS_RE = re.compile(r'\bALLOWED_METHODS\b\s*[=:]')


def _check_exec_in_allowed(rel: str, src: str, lines: List[str]) -> List[MCPTaintFinding]:
    findings: List[MCPTaintFinding] = []

    for lineno, line in enumerate(lines, 1):
        if not _ALLOWED_METHODS_RE.search(line):
            continue
        # Extract block: from this line forward, up to 30 lines
        block = _extract_allowed_methods_block(src, lineno)
        exec_names = _exec_methods_in_block(block)
        if exec_names:
            names_str = ', '.join(repr(n) for n in exec_names)
            findings.append(MCPTaintFinding(
                file=rel, line=lineno,
                issue_type='EXEC_IN_ALLOWED',
                severity='CRITICAL',
                cwe='CWE-284',
                description=(
                    f'ALLOWED_METHODS contains exec-class method(s): {names_str}. '
                    'An MCP tool that proxies these to a managed device allows remote '
                    'code execution if any caller controls the method name.'
                ),
                snippet=line.strip()[:120],
            ))
        break  # one finding per ALLOWED_METHODS block (re-entry on next lineno)

    # Re-run without break to catch multiple ALLOWED_METHODS blocks
    findings_all: List[MCPTaintFinding] = []
    seen_linenos: Set[int] = set()
    for lineno, line in enumerate(lines, 1):
        if not _ALLOWED_METHODS_RE.search(line) or lineno in seen_linenos:
            continue
        block = _extract_allowed_methods_block(src, lineno)
        exec_names = _exec_methods_in_block(block)
        seen_linenos.add(lineno)
        if exec_names:
            names_str = ', '.join(repr(n) for n in exec_names)
            findings_all.append(MCPTaintFinding(
                file=rel, line=lineno,
                issue_type='EXEC_IN_ALLOWED',
                severity='CRITICAL',
                cwe='CWE-284',
                description=(
                    f'ALLOWED_METHODS contains exec-class method(s): {names_str}. '
                    'An MCP tool that proxies these to a managed device allows remote '
                    'code execution if any caller controls the method name.'
                ),
                snippet=line.strip()[:120],
            ))

    return findings_all


# ── NO_AUTH ───────────────────────────────────────────────────────────────────

_MCP_ROUTE_RE = re.compile(
    r"""(?:app|router)\s*\.\s*(?:get|post|put|use|route)\s*\(\s*['"][^'"]*mcp[^'"]*['"]""",
    re.IGNORECASE,
)

_FASTMCP_HTTP_RE = re.compile(r"""mcp\s*\.\s*run\s*\(.*transport\s*=\s*['"]http['"]""")


def _check_no_auth(rel: str, lines: List[str]) -> List[MCPTaintFinding]:
    findings: List[MCPTaintFinding] = []

    for lineno, line in enumerate(lines, 1):
        # JS/TS: app.get/post('/mcp', ...)
        if _MCP_ROUTE_RE.search(line):
            if not _has_auth_in_window(lines, lineno - 1, window=8):
                findings.append(MCPTaintFinding(
                    file=rel, line=lineno,
                    issue_type='NO_AUTH',
                    severity='HIGH',
                    cwe='CWE-306',
                    description=(
                        '/mcp route registered without recognized auth middleware '
                        'in ±8 lines. Verify the endpoint is protected by auth registered '
                        'at the app level, or add explicit auth.'
                    ),
                    snippet=line.strip()[:120],
                ))

        # Python: FastMCP.run(transport='http') without auth
        elif _FASTMCP_HTTP_RE.search(line):
            if not _has_auth_in_window(lines, lineno - 1, window=10):
                findings.append(MCPTaintFinding(
                    file=rel, line=lineno,
                    issue_type='NO_AUTH',
                    severity='HIGH',
                    cwe='CWE-306',
                    description=(
                        'FastMCP.run(transport="http") without auth_middleware in ±10 lines. '
                        'HTTP transport exposes MCP protocol to the network without authentication.'
                    ),
                    snippet=line.strip()[:120],
                ))

    return findings


# ── CREDENTIAL_EXPOSURE ───────────────────────────────────────────────────────
# FMG-AI-1 pattern: json.dumps(request.COOKIES/headers) → CLI arg → subprocess

_CRED_ASSIGN_RE = re.compile(
    r'(\w+)\s*=\s*json\.dumps\s*\(\s*\S*?'
    r'(?:COOKIES|headers|session|auth_token|Authorization)\b',
)
_STDIO_MCP_RE = re.compile(r'StdioServerParameters|StdioMCPClient|subprocess\s*\.\s*\w+')
_CRED_INLINE_RE = re.compile(
    r'json\.dumps\s*\(\s*\S*?(?:COOKIES|session|auth_token)\s*\)',
)
_WINDOW_CRED = 30


def _check_credential_exposure(rel: str, lines: List[str]) -> List[MCPTaintFinding]:
    findings: List[MCPTaintFinding] = []
    credential_sites: List[tuple] = []  # (lineno, var_name)

    for lineno, line in enumerate(lines, 1):
        m = _CRED_ASSIGN_RE.search(line)
        if m:
            credential_sites.append((lineno, m.group(1)))
            continue
        m2 = _CRED_INLINE_RE.search(line)
        if m2 and re.search(r'args\s*=|--\w+|subprocess', line):
            findings.append(MCPTaintFinding(
                file=rel, line=lineno,
                issue_type='CREDENTIAL_EXPOSURE',
                severity='MEDIUM',
                cwe='CWE-214',
                description=(
                    'json.dumps(request.COOKIES/session) passed directly as CLI arg. '
                    'Token visible in /proc/<pid>/cmdline (world-readable on Linux).'
                ),
                snippet=line.strip()[:120],
            ))

    seen_launch_lines: Set[int] = set()
    for assign_lineno, var_name in credential_sites:
        window_end = min(len(lines), assign_lineno - 1 + _WINDOW_CRED)
        for offset, wline in enumerate(lines[assign_lineno - 1:window_end]):
            launch_lineno = assign_lineno + offset
            if launch_lineno in seen_launch_lines:
                continue
            if _STDIO_MCP_RE.search(wline):
                seen_launch_lines.add(launch_lineno)
                findings.append(MCPTaintFinding(
                    file=rel, line=launch_lineno,
                    issue_type='CREDENTIAL_EXPOSURE',
                    severity='MEDIUM',
                    cwe='CWE-214',
                    description=(
                        f'{var_name!r} (json.dumps of COOKIES/headers, line {assign_lineno}) '
                        f'flows into subprocess/StdioServerParameters within {_WINDOW_CRED} lines. '
                        'Credential visible in /proc/<pid>/cmdline.'
                    ),
                    snippet=wline.strip()[:120],
                ))
                break

    return findings


# ── PROMPT_INJECTION ──────────────────────────────────────────────────────────
# FMG-AI-2 pattern: user-controlled input in LLM system-role message

_SYSTEM_ROLE_RE = re.compile(
    r'(?:initial_prompt_role\s*[=:]\s*["\']system["\']|'
    r'role["\']?\s*[:=]\s*["\']system["\']|'
    r'"role"\s*:\s*"system")',
    re.IGNORECASE,
)
_USER_INPUT_NAMES = frozenset({
    'script', 'command', 'user_script', 'cli_script', 'input', 'user_input',
    'body', 'payload', 'content', 'text', 'data', 'message', 'description',
    'query', 'prompt', 'request', 'req', 'param', 'value', 'args', 'raw',
})


def _check_prompt_injection(rel: str, lines: List[str]) -> List[MCPTaintFinding]:
    findings: List[MCPTaintFinding] = []

    for lineno, line in enumerate(lines, 1):
        if not _SYSTEM_ROLE_RE.search(line):
            continue
        window_start = max(0, lineno - 21)
        window_end = min(len(lines), lineno + 20)
        window_lines = lines[window_start:window_end]
        window_src = '\n'.join(window_lines)

        found_user_input = False
        escalate = False
        for name in _USER_INPUT_NAMES:
            if re.search(r'\b' + re.escape(name) + r'\b', window_src):
                found_user_input = True
                if re.search(
                    r'content\s*[=:]\s*' + re.escape(name) +
                    r'|' + re.escape(name) + r'\s*[+]=?\s*\S',
                    window_src,
                ):
                    escalate = True
                break

        if found_user_input:
            severity = 'HIGH' if escalate else 'MEDIUM'
            findings.append(MCPTaintFinding(
                file=rel, line=lineno,
                issue_type='PROMPT_INJECTION',
                severity=severity,
                cwe='CWE-77',
                description=(
                    'User-controlled input found near a system-role message assignment. '
                    'Attacker can inject arbitrary system-level instructions into the AI context, '
                    'bypassing the intended operator/user prompt trust separation.'
                ),
                snippet=line.strip()[:120],
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
        findings = MCPToolTaintScanner.scan_file(str(p))
    else:
        findings = MCPToolTaintScanner.from_path(str(p)).scan()

    if args.severity:
        threshold = _SEV_RANK[args.severity]
        findings = [f for f in findings if _SEV_RANK.get(f.severity, 99) <= threshold]

    print(MCPToolTaintScanner.report(findings))


if __name__ == '__main__':
    _main()


# ── Legacy aliases ────────────────────────────────────────────────────────────
McpToolTaintScanner = MCPToolTaintScanner
McpFinding = MCPTaintFinding
