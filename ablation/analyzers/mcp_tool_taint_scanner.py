"""
ablation/analyzers/mcp_tool_taint_scanner.py — MCP server security scanner.

Detects three confirmed dangerous patterns in MCP server source code
(TypeScript/JavaScript/Python):

  BIND_WIDE    — HTTP transport bound to 0.0.0.0 (or no explicit host, which
                 defaults to 0.0.0.0 in Node.js). Any host on the network can
                 submit tool calls.  CWE-668.  Severity HIGH.

  EXEC_IN_ALLOWED — exec-class method ('exec', 'execute', 'run', 'shell', 'eval')
                 present in ALLOWED_METHODS / allowed_methods set/constant. LLM
                 can invoke arbitrary execution via prompt injection.  CWE-284.
                 Severity CRITICAL.

  NO_AUTH      — /mcp endpoint or MCP HTTP transport defined without a visible
                 authentication middleware or auth dependency.  CWE-306.
                 Severity HIGH.

These patterns were confirmed in FortiManager fortimanager-code-mode-mcp
(FMGMCP-1 HIGH: BIND_WIDE + NO_AUTH, FMGMCP-2 CRITICAL: EXEC_IN_ALLOWED).

Usage:
    from ablation.analyzers.mcp_tool_taint_scanner import MCPToolTaintScanner
    results = MCPToolTaintScanner.from_path('/path/to/mcp-server').scan()
    print(MCPToolTaintScanner.report(results))
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

# ── constants ─────────────────────────────────────────────────────────────────

_EXEC_CLASS: Set[str] = frozenset({'exec', 'execute', 'run', 'shell', 'eval', 'spawn'})

_AUTH_TERMS: Set[str] = frozenset({
    'authenticate', 'verifytoken', 'checkauth', 'requireauth', 'isauthenticated',
    'bearerauth', 'apikey', 'api_key', 'authmiddleware', 'auth_middleware',
    'authorization', 'verify_token', 'check_auth', 'require_auth', 'is_authenticated',
})

_EXTENSIONS: Set[str] = frozenset({'.ts', '.js', '.py'})
_MAX_FILES_WARN: int = 10_000

# Pre-filter: only scan files that contain at least one of these patterns
_PREFILTER_RE = re.compile(
    r'ALLOWED_METHODS|McpServer|FastMCP|mcp_transport|streamableHttp|'
    r'\.listen\s*\(|/mcp["\'\s/]|mcp_http',
    re.IGNORECASE,
)

# ── detection regexes ─────────────────────────────────────────────────────────

# BIND_WIDE: Node.js .listen(port) without a host string argument
# Matches: .listen(8000), .listen(config.port), .listen(config.mcpHttpPort, () => {
# Does NOT match: .listen(8000, '127.0.0.1', ...) — has string host
_LISTEN_RE = re.compile(r'\.listen\s*\(([^)]*)\)')
_SAFE_BIND_RE = re.compile(r'["\'](?:127\.0\.0\.1|localhost|::1)["\']')

# Python BIND_WIDE: host='0.0.0.0' or host="0.0.0.0"
_PY_BIND_WIDE_RE = re.compile(r'\bhost\s*=\s*["\']0\.0\.0\.0["\']')

# EXEC_IN_ALLOWED: ALLOWED_METHODS constant contains exec-class method
# Captures the method name from a quoted string inside an ALLOWED_METHODS assignment
_ALLOWED_METHODS_LINE_RE = re.compile(r'\bALLOWED_METHODS\b', re.IGNORECASE)
_QUOTED_METHOD_RE = re.compile(r'''['"]([a-zA-Z_]\w*)['"]''')

# /mcp route definition (TypeScript/JS Express-style)
_MCP_ROUTE_RE = re.compile(r'''['"]/mcp['"]''')
_AUTH_LINE_RE = re.compile(r'\b(?:' + '|'.join(_AUTH_TERMS) + r')\b', re.IGNORECASE)

# FastMCP HTTP transport (Python): only flag when 'http' appears in the run() call args,
# or when uvicorn.run() is used (always HTTP). stdio-only mcp.run() is safe.
_FASTMCP_HTTP_RE = re.compile(
    r"mcp\.run\s*\([^)]*['\"]http['\"]|uvicorn\.run\s*\(",
    re.IGNORECASE,
)

# ── dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class MCPTaintFinding:
    path: Path
    rel_path: str
    cwe: str
    severity: str
    issue_type: str       # BIND_WIDE | EXEC_IN_ALLOWED | NO_AUTH
    line: int
    line_text: str
    description: str = ""

# ── helpers ───────────────────────────────────────────────────────────────────

def _severity_order(f: MCPTaintFinding) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 5)


def _has_auth_in_window(lines: List[str], center: int, window: int = 15) -> bool:
    start = max(0, center - window)
    end = min(len(lines), center + window + 1)
    for ln in lines[start:end]:
        if _AUTH_LINE_RE.search(ln):
            return True
    return False


def _exec_methods_in_block(block_text: str) -> List[str]:
    """Return exec-class method names found as quoted strings in block_text."""
    return [m for m in _QUOTED_METHOD_RE.findall(block_text) if m in _EXEC_CLASS]


def _extract_allowed_methods_block(lines: List[str], start_idx: int) -> str:
    """Return the text of the ALLOWED_METHODS assignment block starting at start_idx."""
    block: List[str] = []
    depth = 0
    for ln in lines[start_idx:start_idx + 30]:
        block.append(ln)
        depth += ln.count('(') + ln.count('[') + ln.count('{')
        depth -= ln.count(')') + ln.count(']') + ln.count('}')
        if depth <= 0 and len(block) > 1:
            break
    return '\n'.join(block)

# ── per-file scanner ──────────────────────────────────────────────────────────

def _scan_ts_js(path: Path, rel_path: str, lines: List[str]) -> List[MCPTaintFinding]:
    findings: List[MCPTaintFinding] = []
    full_text = '\n'.join(lines)

    # BIND_WIDE: .listen() without safe host
    for m in _LISTEN_RE.finditer(full_text):
        args = m.group(1)
        # If args contain a safe bind address, skip
        if _SAFE_BIND_RE.search(args):
            continue
        # If args contain '0.0.0.0', definitely vulnerable
        # If args contain a string that's not a safe address → flag
        # If args contain only non-string tokens (port var, callback) → flag
        lineno = full_text[:m.start()].count('\n') + 1
        findings.append(MCPTaintFinding(
            path=path, rel_path=rel_path,
            cwe='CWE-668', severity='HIGH', issue_type='BIND_WIDE',
            line=lineno, line_text=lines[lineno - 1].strip(),
            description=(
                f'.listen() has no explicit safe host (127.0.0.1/localhost); '
                f'Node.js defaults to 0.0.0.0. Args: {args.strip()[:80]}'
            ),
        ))

    # EXEC_IN_ALLOWED: ALLOWED_METHODS contains exec-class method
    for i, ln in enumerate(lines):
        if not _ALLOWED_METHODS_LINE_RE.search(ln):
            continue
        block = _extract_allowed_methods_block(lines, i)
        exec_found = _exec_methods_in_block(block)
        if exec_found:
            findings.append(MCPTaintFinding(
                path=path, rel_path=rel_path,
                cwe='CWE-284', severity='CRITICAL', issue_type='EXEC_IN_ALLOWED',
                line=i + 1, line_text=ln.strip(),
                description=(
                    f'ALLOWED_METHODS contains exec-class method(s): '
                    f'{", ".join(exec_found)}. LLM prompt injection can invoke these.'
                ),
            ))
            break  # one finding per ALLOWED_METHODS block per file

    # NO_AUTH: /mcp route defined without auth middleware nearby
    for i, ln in enumerate(lines):
        if not _MCP_ROUTE_RE.search(ln):
            continue
        if not _has_auth_in_window(lines, i):
            findings.append(MCPTaintFinding(
                path=path, rel_path=rel_path,
                cwe='CWE-306', severity='HIGH', issue_type='NO_AUTH',
                line=i + 1, line_text=ln.strip(),
                description=(
                    f'/mcp endpoint defined at line {i + 1} with no auth '
                    f'middleware found within 15 lines.'
                ),
            ))

    return findings


def _scan_python(path: Path, rel_path: str, lines: List[str]) -> List[MCPTaintFinding]:
    findings: List[MCPTaintFinding] = []
    full_text = '\n'.join(lines)

    # BIND_WIDE: host='0.0.0.0'
    for m in _PY_BIND_WIDE_RE.finditer(full_text):
        lineno = full_text[:m.start()].count('\n') + 1
        findings.append(MCPTaintFinding(
            path=path, rel_path=rel_path,
            cwe='CWE-668', severity='HIGH', issue_type='BIND_WIDE',
            line=lineno, line_text=lines[lineno - 1].strip(),
            description="Server binds to 0.0.0.0 — reachable from any network interface.",
        ))

    # EXEC_IN_ALLOWED: ALLOWED_METHODS set contains exec-class method
    for i, ln in enumerate(lines):
        if not _ALLOWED_METHODS_LINE_RE.search(ln):
            continue
        block = _extract_allowed_methods_block(lines, i)
        exec_found = _exec_methods_in_block(block)
        if exec_found:
            findings.append(MCPTaintFinding(
                path=path, rel_path=rel_path,
                cwe='CWE-284', severity='CRITICAL', issue_type='EXEC_IN_ALLOWED',
                line=i + 1, line_text=ln.strip(),
                description=(
                    f'ALLOWED_METHODS contains exec-class method(s): '
                    f'{", ".join(exec_found)}. LLM prompt injection can invoke these.'
                ),
            ))
            break

    # NO_AUTH: FastMCP HTTP transport without auth
    for i, ln in enumerate(lines):
        if not _FASTMCP_HTTP_RE.search(ln):
            continue
        if not _has_auth_in_window(lines, i):
            findings.append(MCPTaintFinding(
                path=path, rel_path=rel_path,
                cwe='CWE-306', severity='HIGH', issue_type='NO_AUTH',
                line=i + 1, line_text=ln.strip(),
                description=(
                    f'MCP HTTP transport started without visible auth at line {i + 1}.'
                ),
            ))

    return findings

# ── main class ────────────────────────────────────────────────────────────────

class MCPToolTaintScanner:
    """Scan MCP server source trees for BIND_WIDE, EXEC_IN_ALLOWED, and NO_AUTH patterns."""

    MAX_FILES_WARN = _MAX_FILES_WARN

    def __init__(
        self,
        root: Path,
        rel_base: Optional[Path] = None,
        max_files: Optional[int] = None,
    ) -> None:
        self._root = root
        self._rel_base = rel_base or root
        self._max_files = max_files

    @classmethod
    def from_path(cls, path, max_files: Optional[int] = None) -> "MCPToolTaintScanner":
        p = Path(path)
        if p.is_file():
            return cls(root=p.parent, rel_base=p.parent, max_files=max_files)
        return cls(root=p, rel_base=p, max_files=max_files)

    def _should_scan(self, text: str) -> bool:
        return bool(_PREFILTER_RE.search(text))

    def _scan_file(self, path: Path) -> List[MCPTaintFinding]:
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError as e:
            warnings.warn(f"MCPToolTaintScanner: cannot read {path}: {e}")
            return []
        if not self._should_scan(text):
            return []
        lines = text.splitlines()
        rel = str(path.relative_to(self._rel_base))
        ext = path.suffix.lower()
        if ext in ('.ts', '.js'):
            return _scan_ts_js(path, rel, lines)
        if ext == '.py':
            return _scan_python(path, rel, lines)
        return []

    def scan(self) -> List[MCPTaintFinding]:
        """Scan all .ts/.js/.py files under root. Returns findings sorted CRITICAL first."""
        all_findings: List[MCPTaintFinding] = []
        files = [
            p for p in self._root.rglob('*')
            if p.is_file() and p.suffix.lower() in _EXTENSIONS
        ]
        if len(files) > self.MAX_FILES_WARN:
            warnings.warn(
                f"MCPToolTaintScanner: {len(files)} files in {self._root} — "
                f"consider narrowing the scan root"
            )
        if self._max_files and len(files) > self._max_files:
            warnings.warn(
                f"MCPToolTaintScanner: truncating to {self._max_files} files"
            )
            files = files[:self._max_files]
        for f in files:
            all_findings.extend(self._scan_file(f))
        return sorted(all_findings, key=_severity_order)

    @staticmethod
    def report(findings: List[MCPTaintFinding]) -> str:
        if not findings:
            return "MCPToolTaintScanner: no findings\n"
        lines = [
            f"MCPToolTaintScanner: {len(findings)} finding(s)\n",
            f"{'SEV':<10} {'TYPE':<20} {'FILE:LINE':<45} DESCRIPTION",
            '-' * 100,
        ]
        for f in findings:
            loc = f"{f.rel_path}:{f.line}"
            lines.append(
                f"{f.severity:<10} {f.issue_type:<20} {loc:<45} {f.description[:60]}"
            )
        return '\n'.join(lines) + '\n'


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> None:
    import argparse, sys
    ap = argparse.ArgumentParser(
        description='Scan MCP server code for security issues'
    )
    ap.add_argument('path', help='Directory or file to scan')
    ap.add_argument('--severity', default='',
                    help='Filter to this severity or higher (CRITICAL/HIGH/MEDIUM)')
    args = ap.parse_args()
    findings = MCPToolTaintScanner.from_path(args.path).scan()
    if args.severity:
        order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        threshold = order.index(args.severity.upper()) if args.severity.upper() in order else 99
        findings = [f for f in findings if order.index(f.severity) <= threshold]
    print(MCPToolTaintScanner.report(findings))
    sys.exit(1 if findings else 0)


if __name__ == '__main__':
    _cli()
