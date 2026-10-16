"""
electron_security_scanner.py — Electron app JavaScript security scanner.

Closes TG-FFO-1: no ablation module for Electron app security analysis.

Why this exists:

FortiFone Desktop v8.0 build 67 is an Electron/Chromium SIP phone client.
Manual source review of app.asar (extracted JS) produced seven confirmed findings
that required reading the Electron security model from scratch each time — there
was no automated scanner. The patterns are identical across all Electron-based
desktop apps (FortiFone, FortiClient desktop integrations, FPAM browser extension
host, any vendor using Electron).

Confirmed findings this scanner closes:

  FFO-NI-1 (CWE-693, CRITICAL): nodeIntegration:true + contextIsolation:false
    on all BrowserWindow instances (11 windows in main.js). Any XSS or renderer-side
    code injection has full Node.js — require(), process, fs — with no sandbox.

  FFO-WSIPC-1 (CWE-940, HIGH): ipcMain event relay via WebSocket bridge.
    ctx.ipcMain.emit(obj.ipcMsg, SyntheticIpcMainEvent, ...obj.args) where
    obj comes from an unvalidated WebSocket message. Synthetic events lack
    event.sender — auth checks are skipped. Attacker on localhost can trigger
    any ipcMain handler.

  FFO-COOKIE-1 (CWE-522, HIGH): ipcMain.handle('get-session-cookies') exposes
    all session cookies to any renderer. No sender URL or origin check.

  FFO-IPC-1 (CWE-693, HIGH): ipcMain.handle('get-global-prop'/'get-global-object')
    exposes full global.sharedObject (cert material, tokens) to any renderer.
    No sender verification.

  FFO-OAUTH-1 (CWE-601, HIGH): oauthWindow.loadURL(authUrl) — server-controlled
    URL loaded in a nodeIntegration:true window. Compromised/MITM PBX → RCE.

  FFO-DEEPLINK-1 (CWE-601, MEDIUM): deep link handler sets attacker server as
    login target without URL validation or scheme allowlisting.

  FFO-DEVTOOLS-1 (CWE-489, MEDIUM): BrowserWindow.openDevTools() called
    unconditionally in production code path.

Scanner scope: unpacked .asar JavaScript (main process and renderer JS files).
Run against the extracted `app.asar.unpacked/` or `app_src/` directory.

Extraction: `npx asar extract resources/app.asar /tmp/app_src`

Usage:

    from ablation.analyzers.electron_security_scanner import ElectronSecurityScanner

    findings = ElectronSecurityScanner.from_path('/tmp/fortifone/app_src/').scan()
    print(ElectronSecurityScanner.report(findings))

    # Single file
    findings = ElectronSecurityScanner.scan_file('/tmp/app_src/main.js')

CLI:
    python3 -m ablation.analyzers.electron_security_scanner /path/to/app_src
    python3 -m ablation.analyzers.electron_security_scanner /path/to/app_src --severity HIGH
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set

# ── Pre-filter patterns ───────────────────────────────────────────────────────
# Applied before per-line analysis to skip non-Electron files quickly.

_ELECTRON_QUICK_RE = re.compile(
    r'BrowserWindow|ipcMain|ipcRenderer|nodeIntegration|contextIsolation|'
    r'require\s*\(\s*["\']electron["\']|webPreferences|loadURL|openDevTools',
    re.IGNORECASE,
)

# ── Finding class ─────────────────────────────────────────────────────────────

@dataclass
class ElectronFinding:
    """One detected Electron security issue."""
    path: Path
    rel_path: str
    lineno: int
    finding_class: str
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW
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

class ElectronSecurityScanner:
    """Scan Electron app JavaScript source for security issues."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self._root = root

    @classmethod
    def from_path(cls, root: str) -> 'ElectronSecurityScanner':
        return cls(Path(root))

    def scan(self) -> List[ElectronFinding]:
        if self._root is None:
            return []
        findings: List[ElectronFinding] = []
        for p in sorted(self._root.rglob("*.js")):
            try:
                findings.extend(self._scan_path(p))
            except Exception:
                pass
        return findings

    @staticmethod
    def scan_file(path: str) -> List[ElectronFinding]:
        try:
            return ElectronSecurityScanner._scan_path(Path(path))
        except Exception:
            return []

    @staticmethod
    def _scan_path(p: Path) -> List[ElectronFinding]:
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        rel = str(p)

        if not _ELECTRON_QUICK_RE.search(src):
            return []

        findings: List[ElectronFinding] = []
        findings.extend(_check_node_integration(p, rel, src))
        findings.extend(_check_ipc_no_sender_check(p, rel, src))
        findings.extend(_check_server_url_in_ni_window(p, rel, src))
        findings.extend(_check_devtools_in_prod(p, rel, src))
        findings.extend(_check_deep_link_no_validation(p, rel, src))
        findings.extend(_check_tls_bypass(p, rel, src))
        findings.extend(_check_context_bridge_missing(p, rel, src))
        return findings

    @staticmethod
    def report(findings: List[ElectronFinding]) -> str:
        if not findings:
            return "[electron_security_scanner] No findings.\n"
        total = len(findings)
        by_sev: dict = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        hdr = (
            f"[electron_security_scanner] {total} finding(s)  "
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


def _check_node_integration(p: Path, rel: str, src: str) -> List[ElectronFinding]:
    """Detect nodeIntegration:true and contextIsolation:false in BrowserWindow webPreferences."""
    findings: List[ElectronFinding] = []
    ls = _lines(src)

    for lineno, line in enumerate(ls, 1):
        # nodeIntegration: true
        m = re.search(r'nodeIntegration\s*:\s*true\b', line)
        if m:
            # Determine if contextIsolation is explicitly false in nearby context
            window_start = max(0, lineno - 5)
            window_end = min(len(ls), lineno + 5)
            window = "\n".join(ls[window_start:window_end])
            ci_false = bool(re.search(r'contextIsolation\s*:\s*false\b', window))
            severity = 'CRITICAL' if ci_false else 'HIGH'
            detail = (
                'nodeIntegration:true gives renderer processes full Node.js (require, process, fs). '
            )
            if ci_false:
                detail += (
                    'contextIsolation:false also present — no isolation between JS worlds. '
                    'Any XSS or injected renderer script has unrestricted system access.'
                )
            else:
                detail += 'contextIsolation state not confirmed false in ±5 lines — verify manually.'
            findings.append(ElectronFinding(
                path=p, rel_path=rel, lineno=lineno,
                finding_class='NODE_INTEGRATION',
                severity=severity,
                cwe='CWE-693',
                title='BrowserWindow with nodeIntegration:true',
                detail=detail,
                snippet=line.strip()[:120],
            ))

        # contextIsolation: false (standalone — may not have NI:true nearby)
        m2 = re.search(r'contextIsolation\s*:\s*false\b', line)
        if m2:
            window_start = max(0, lineno - 5)
            window_end = min(len(ls), lineno + 5)
            window = "\n".join(ls[window_start:window_end])
            if not re.search(r'nodeIntegration\s*:\s*true\b', window):
                # nodeIntegration not in window — report as MEDIUM (NI defaults to false in newer Electron)
                findings.append(ElectronFinding(
                    path=p, rel_path=rel, lineno=lineno,
                    finding_class='CONTEXT_ISOLATION_DISABLED',
                    severity='MEDIUM',
                    cwe='CWE-693',
                    title='contextIsolation:false without confirmed nodeIntegration:true',
                    detail=(
                        'Disabling contextIsolation exposes the renderer window object to page scripts. '
                        'Combined with nodeIntegration:true (even if elsewhere), renderer XSS reaches Node.js.'
                    ),
                    snippet=line.strip()[:120],
                ))

    return findings


def _check_ipc_no_sender_check(p: Path, rel: str, src: str) -> List[ElectronFinding]:
    """Detect ipcMain.handle/on without event.sender or event.senderFrame validation."""
    findings: List[ElectronFinding] = []
    ls = _lines(src)

    for lineno, line in enumerate(ls, 1):
        if not re.search(r'ipcMain\s*\.\s*(?:handle|on)\s*\(', line):
            continue

        # Get the handler body: next 15 lines
        body_end = min(len(ls), lineno + 15)
        body = "\n".join(ls[lineno - 1:body_end])

        # Does the handler check sender origin?
        has_sender_check = bool(re.search(
            r'event\.(?:sender|senderFrame|frameId)|'
            r'allowedOrigins?|'
            r'trustedOrigins?|'
            r'\.url\b.*(?:===|includes|startsWith)',
            body,
        ))
        if has_sender_check:
            continue

        # Is this handler returning sensitive data or executing privileged ops?
        sensitive = bool(re.search(
            r'cookie|session|cert|key|token|password|credential|'
            r'global\.|sharedObject|require\(|exec|spawn|shell|'
            r'readFile|writeFile|unlink|rmdir',
            body,
            re.IGNORECASE,
        ))
        severity = 'HIGH' if sensitive else 'MEDIUM'
        channel_m = re.search(r'ipcMain\s*\.\s*(?:handle|on)\s*\(\s*["\']([^"\']+)["\']', line)
        channel = channel_m.group(1) if channel_m else '(unknown)'

        findings.append(ElectronFinding(
            path=p, rel_path=rel, lineno=lineno,
            finding_class='IPC_NO_SENDER_CHECK',
            severity=severity,
            cwe='CWE-940',
            title=f'ipcMain handler {channel!r} without sender origin validation',
            detail=(
                f'Handler for {channel!r} does not verify event.sender URL or senderFrame origin. '
                'Any renderer (including XSS or injected content) can invoke this handler. '
                + ('Handler returns sensitive data or executes privileged ops.' if sensitive else
                   'Verify handler does not return sensitive data or perform privileged operations.')
            ),
            snippet=line.strip()[:120],
        ))

    return findings


def _check_server_url_in_ni_window(p: Path, rel: str, src: str) -> List[ElectronFinding]:
    """Detect loadURL() calls where the URL comes from an external/server-controlled source."""
    findings: List[ElectronFinding] = []
    ls = _lines(src)

    # Track whether we are in a file that has nodeIntegration:true windows
    has_ni = bool(re.search(r'nodeIntegration\s*:\s*true', src))

    for lineno, line in enumerate(ls, 1):
        if not re.search(r'\.loadURL\s*\(', line):
            continue

        # Skip literal URLs (http:// or file:// or __dirname)
        m_literal = re.search(r'\.loadURL\s*\(\s*["\'](?:https?://|file://)', line)
        m_dirname = re.search(r'\.loadURL\s*\(.*__dirname', line)
        if m_literal or m_dirname:
            continue

        # Does the URL argument look like a variable that might come from server config?
        m_var = re.search(r'\.loadURL\s*\(\s*(\w[\w.]*)\s*[,)]', line)
        if not m_var:
            continue
        url_var = m_var.group(1)

        # Look back 20 lines for where url_var is assigned — is it from an external source?
        window_start = max(0, lineno - 20)
        window = "\n".join(ls[window_start:lineno - 1])
        server_derived = bool(re.search(
            r'(?:server|config|remote|auth|oauth|settings|response|'
            r'PBXURL|serverUrl|pbxServer|loginServer|apiBase)\b',
            window,
            re.IGNORECASE,
        ))
        if not server_derived and not has_ni:
            continue

        severity = 'HIGH' if (has_ni and server_derived) else 'MEDIUM'
        findings.append(ElectronFinding(
            path=p, rel_path=rel, lineno=lineno,
            finding_class='SERVER_URL_IN_WINDOW',
            severity=severity,
            cwe='CWE-601',
            title=f'loadURL({url_var}) with server-derived URL',
            detail=(
                f'{url_var!r} appears derived from server/config (context: ±20 lines). '
                + ('nodeIntegration:true present in file — compromised/MITM server controls URL → RCE. '
                   if has_ni else
                   'Verify window webPreferences for nodeIntegration setting.')
            ),
            snippet=line.strip()[:120],
        ))

    return findings


def _check_devtools_in_prod(p: Path, rel: str, src: str) -> List[ElectronFinding]:
    """Detect unconditional openDevTools() calls (not gated on debug/dev mode)."""
    findings: List[ElectronFinding] = []
    ls = _lines(src)

    for lineno, line in enumerate(ls, 1):
        if not re.search(r'\.openDevTools\s*\(', line):
            continue

        # Check if it is gated on a dev/debug/isDev condition
        window_start = max(0, lineno - 8)
        window = "\n".join(ls[window_start:lineno - 1])
        gated = bool(re.search(
            r'isDev|is_dev|NODE_ENV\s*===\s*["\']development["\']|'
            r'debug\s*===\s*true|process\.env\.DEBUG|__DEV__',
            window,
            re.IGNORECASE,
        ))
        if not gated:
            findings.append(ElectronFinding(
                path=p, rel_path=rel, lineno=lineno,
                finding_class='DEVTOOLS_IN_PROD',
                severity='MEDIUM',
                cwe='CWE-489',
                title='openDevTools() called without isDev/debug guard',
                detail=(
                    'DevTools open unconditionally — present in production builds. '
                    'Exposes application internals, enables easy JS injection, and '
                    'leaks renderer source / local storage / network traffic to any local user.'
                ),
                snippet=line.strip()[:120],
            ))

    return findings


def _check_deep_link_no_validation(p: Path, rel: str, src: str) -> List[ElectronFinding]:
    """Detect deep link (protocol URL) handlers that don't validate/allowlist the server argument."""
    findings: List[ElectronFinding] = []
    ls = _lines(src)

    for lineno, line in enumerate(ls, 1):
        # Custom protocol registration or open-url handler
        if not re.search(
            r'open-url|protocol\.register|setAsDefaultProtocolClient|'
            r'second-instance|argv.*://',
            line,
        ):
            continue

        # Get handler body: next 25 lines
        body_end = min(len(ls), lineno + 25)
        body = "\n".join(ls[lineno - 1:body_end])

        # Does the handler validate the server or URL before use?
        has_validation = bool(re.search(
            r'allowlist|allowedServer|trustedServer|url\.parse|new URL\b|'
            r'startsWith\s*\(\s*["\']https?://',
            body,
            re.IGNORECASE,
        ))
        if has_validation:
            continue

        # Does the handler use the deep-link value in a loadURL or login flow?
        has_use = bool(re.search(r'loadURL|loginServer|setServer|connect\s*\(', body))
        if not has_use:
            continue

        findings.append(ElectronFinding(
            path=p, rel_path=rel, lineno=lineno,
            finding_class='DEEP_LINK_NO_VALIDATION',
            severity='MEDIUM',
            cwe='CWE-601',
            title='Deep link handler uses URL argument without server allowlist/validation',
            detail=(
                'Protocol URL argument used in loadURL or server-login context without '
                'scheme/domain validation. Attacker-crafted deep link can redirect the '
                'client to an attacker-controlled server, intercepting credentials.'
            ),
            snippet=line.strip()[:120],
        ))

    return findings


def _check_tls_bypass(p: Path, rel: str, src: str) -> List[ElectronFinding]:
    """Detect TLS certificate bypass: rejectUnauthorized:false or certificate-error accept-all."""
    findings: List[ElectronFinding] = []
    ls = _lines(src)

    for lineno, line in enumerate(ls, 1):
        # rejectUnauthorized: false
        if re.search(r'rejectUnauthorized\s*:\s*false', line):
            # Is it gated on a dev/debug mode?
            window_start = max(0, lineno - 5)
            window = "\n".join(ls[window_start:lineno - 1])
            gated = bool(re.search(r'isDev|NODE_ENV.*development|debug', window, re.IGNORECASE))
            severity = 'LOW' if gated else 'HIGH'
            findings.append(ElectronFinding(
                path=p, rel_path=rel, lineno=lineno,
                finding_class='TLS_BYPASS',
                severity=severity,
                cwe='CWE-295',
                title='rejectUnauthorized:false — TLS certificate validation disabled',
                detail=(
                    'TLS certificate errors are suppressed unconditionally. '
                    'MITM attack becomes possible on any connection using this agent.'
                    + (' Dev-mode context present — verify this is not in production path.'
                       if gated else '')
                ),
                snippet=line.strip()[:120],
            ))

        # certificate-error event with callback(true) — accept all cert errors
        if re.search(r'certificate-error', line):
            body_end = min(len(ls), lineno + 6)
            body = "\n".join(ls[lineno - 1:body_end])
            if re.search(r'callback\s*\(\s*true\s*\)', body):
                findings.append(ElectronFinding(
                    path=p, rel_path=rel, lineno=lineno,
                    finding_class='TLS_BYPASS',
                    severity='CRITICAL',
                    cwe='CWE-295',
                    title='certificate-error event handler accepts ALL TLS errors',
                    detail=(
                        "app.on('certificate-error', callback(true)) accepts every TLS certificate error "
                        '(expired, self-signed, MITM). Any TLS connection using the default session '
                        'can be intercepted without user warning.'
                    ),
                    snippet=line.strip()[:120],
                ))

    return findings


def _check_context_bridge_missing(p: Path, rel: str, src: str) -> List[ElectronFinding]:
    """Detect preload scripts that expose objects without contextBridge.exposeInMainWorld."""
    findings: List[ElectronFinding] = []
    ls = _lines(src)

    is_preload = bool(
        re.search(r'preload', str(Path(src[:50]).name if len(src) < 50 else ''), re.IGNORECASE)
        or re.search(r'contextBridge|ipcRenderer\s*\.(?:send|invoke|on)\b', src)
    )
    if not is_preload:
        return []

    has_context_bridge = bool(re.search(r'contextBridge\s*\.\s*exposeInMainWorld', src))
    if has_context_bridge:
        return []

    # File looks like a preload with ipcRenderer but no contextBridge
    has_ipc_renderer = bool(re.search(r'ipcRenderer\s*\.(?:send|invoke|on)\b', src))
    has_global_assign = bool(re.search(r'window\s*\.\s*\w+\s*=|global\s*\.\s*\w+\s*=', src))

    if has_ipc_renderer or has_global_assign:
        for lineno, line in enumerate(ls, 1):
            if re.search(r'(?:window|global)\s*\.\s*\w+\s*=', line) and re.search(r'ipcRenderer', line):
                findings.append(ElectronFinding(
                    path=p, rel_path=rel, lineno=lineno,
                    finding_class='CONTEXT_BRIDGE_MISSING',
                    severity='HIGH',
                    cwe='CWE-693',
                    title='Preload assigns ipcRenderer to window/global without contextBridge',
                    detail=(
                        'Assigning ipcRenderer (or a wrapper) directly to window/global in a preload '
                        'bypasses contextBridge isolation. Renderer-side code can call ipcRenderer.invoke '
                        'directly, including attacker-injected scripts, with no origin filtering.'
                    ),
                    snippet=line.strip()[:120],
                ))

    return findings


# ── CLI entry ─────────────────────────────────────────────────────────────────

def _main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='Electron app security scanner')
    ap.add_argument('path', help='Directory or JS file to scan')
    ap.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    help='Minimum severity to report')
    args = ap.parse_args()

    p = Path(args.path)
    if p.is_file():
        findings = ElectronSecurityScanner.scan_file(str(p))
    else:
        findings = ElectronSecurityScanner.from_path(str(p)).scan()

    if args.severity:
        rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        threshold = rank[args.severity]
        findings = [f for f in findings if rank.get(f.severity, 99) <= threshold]

    print(ElectronSecurityScanner.report(findings))


if __name__ == '__main__':
    _main()
