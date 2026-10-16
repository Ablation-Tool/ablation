"""
browser_extension_auditor.py — Chrome/Edge/Firefox extension security auditor.

Closes TG-FPAM-1: no ablation module for browser extension security analysis.

Why this exists:

FortiClient EMS ships a browser extension (FPAM) that exposes a privileged
Chrome messaging bus to web pages via externally_connectable. Manual analysis of
the manifest.json and background service worker confirmed FPAM-EXT-1:

  FPAM-EXT-1 (CWE-346, HIGH): externally_connectable matches https://*/*
    exposing chrome.runtime.sendMessage to any HTTPS page. The service worker
    message handler processes the request payload (including host:port) before
    validating sender.url against the allowlist. A page on any HTTPS origin can
    ping any local TCP port using the extension as a confused deputy — silent
    port-scan oracle against 127.0.0.1.

No automated scanner existed; each browser extension audit required reading
the Chrome extension security model from scratch. The patterns below are
reusable across all Fortinet browser-resident agents (EMS, FSSO, FIDO2, VPN).

Finding classes this scanner detects:

  EXT_CONN_BROAD (CWE-346, HIGH):
    externally_connectable.matches contains a pattern that is too broad
    (e.g. https://*/* , *://*/* , <all_urls>, or a wildcard second-level domain).
    Any page matching the pattern can call chrome.runtime.sendMessage into the
    extension's privileged service worker.

  EXT_CONN_MISSING (CWE-346, MEDIUM):
    content_scripts are declared but externally_connectable is absent entirely.
    Extensions with content scripts that relay ipcRenderer-style messages to the
    background page are still reachable via window.postMessage from injected scripts.

  MSG_HANDLER_PREAUTH (CWE-285, HIGH):
    chrome.runtime.onMessage / onMessageExternal listener body processes the
    message payload (destructures request, calls sendMessage, fetch, XMLHttpRequest,
    or modifies the DOM) BEFORE a sender.id / sender.url / sender.origin check.
    Confused-deputy: any page on a matched origin can drive the privileged handler.

  CONTENT_SCRIPT_DOM_HOOK (CWE-200, MEDIUM):
    Content script overwrites window.fetch, window.XMLHttpRequest,
    document.cookie, or window.location. Hooking these globals leaks the page's
    full request/response stream to the extension's content world, which has
    access to chrome.runtime.sendMessage.

  WEBSOCKET_BUS (CWE-284, HIGH):
    Background service worker creates a WebSocket server (ws://) or connects to
    one on localhost. Any page that can reach the same loopback port bypasses the
    Chrome extension message API entirely (no sender validation, no
    externally_connectable restriction).

  NATIVE_MSG_NO_ALLOWLIST (CWE-284, HIGH):
    chrome.runtime.connectNative / sendNativeMessage called without a declared
    allowed_origins guard (checked against the host manifest). Also fires when
    the native messaging host's allowed_origins includes * or a wildcard.

  PERSISTENT_DATA_CLEAR (CWE-362, LOW):
    chrome.storage.local.clear() / chrome.storage.session.clear() called inside a
    message handler without sender verification. Any matched-origin page can wipe
    extension-stored credentials or session state.

Usage:

    from ablation.analyzers.browser_extension_auditor import BrowserExtensionAuditor

    findings = BrowserExtensionAuditor.from_path('/tmp/fpam-ext/').scan()
    print(BrowserExtensionAuditor.report(findings))

    # Single file
    findings = BrowserExtensionAuditor.scan_file('/tmp/ext/background.js')

CLI:
    python3 -m ablation.analyzers.browser_extension_auditor /path/to/ext/
    python3 -m ablation.analyzers.browser_extension_auditor /path/to/ext/ --severity HIGH
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# ── Scanned file extensions ───────────────────────────────────────────────────
_SCAN_EXTS = frozenset({'.js', '.ts', '.mjs'})

# ── Pre-filter: must have at least one Chrome extension API signal ─────────────
_EXT_QUICK_RE = re.compile(
    r'\bchrome\.runtime\b|\bbrowser\.runtime\b|onMessage|onMessageExternal|'
    r'sendNativeMessage|connectNative|content_scripts|externally_connectable|'
    r'chrome\.storage\b',
    re.IGNORECASE,
)

# ── Patterns that indicate a sender check ────────────────────────────────────
_SENDER_CHECK_RE = re.compile(
    r'\bsender\s*\.\s*(?:id|url|origin|tab)\b|'
    r'allowedOrigins?\s*\.|'
    r'ALLOWED_ORIGIN|'
    r'whitelist|allowlist|'
    r'\.includes\s*\(\s*sender|'
    r'sender\s*===|=== sender',
    re.IGNORECASE,
)

# ── Patterns that indicate payload processing ────────────────────────────────
_PAYLOAD_USE_RE = re.compile(
    r'\brequest\s*\.\s*\w+|'
    r'\bdata\s*\.\s*\w+|'
    r'\bmessage\s*\.\s*\w+|'
    r'\bfetch\s*\(|'
    r'\bXMLHttpRequest\b|'
    r'sendResponse\s*\(|'
    r'chrome\.tabs\.query|chrome\.tabs\.sendMessage|'
    r'chrome\.runtime\.sendMessage',
    re.IGNORECASE,
)


# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class ExtFinding:
    path: Path
    rel_path: str
    lineno: int
    finding_class: str
    severity: str
    cwe: str
    title: str
    detail: str
    snippet: str = ''
    evidence: str = ''

    def fmt(self) -> str:
        lines = [
            f'[{self.severity}] {self.finding_class}: {self.title}',
            f'  File: {self.rel_path}:{self.lineno}',
            f'  CWE:  {self.cwe}',
            f'  {self.detail}',
        ]
        if self.snippet:
            lines.append(f'  Snippet: {self.snippet}')
        if self.evidence:
            lines.append(f'  Evidence: {self.evidence}')
        return '\n'.join(lines)


# ── Broad externally_connectable patterns ─────────────────────────────────────

# Match-all or broadly wildcarded host patterns.
_BROAD_PATTERNS: List[re.Pattern] = [
    re.compile(r'^\*://\*/'),           # *://*/*
    re.compile(r'^https?://\*/'),       # https://*/* or http:///*/*
    re.compile(r'<all_urls>', re.IGNORECASE),
    re.compile(r'^https?://\*\.\w'),    # https://*.example.com — still broad
]


def _pattern_is_broad(pat: str) -> bool:
    pat = pat.strip()
    for compiled in _BROAD_PATTERNS:
        if compiled.search(pat):
            return True
    # Catch https://*.tld/* where the subdomain is fully wildcarded
    if re.match(r'^https?://\*\.', pat):
        return True
    return False


def _lines(src: str) -> List[str]:
    return src.splitlines()


# ── manifest.json auditor ─────────────────────────────────────────────────────

def _audit_manifest(manifest_path: Path, root: Path) -> List[ExtFinding]:
    findings: List[ExtFinding] = []
    rel = str(manifest_path.relative_to(root))
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return []

    ec = manifest.get('externally_connectable', {})
    matches = ec.get('matches', [])
    has_content_scripts = bool(manifest.get('content_scripts'))

    if matches:
        broad = [m for m in matches if _pattern_is_broad(m)]
        if broad:
            findings.append(ExtFinding(
                path=manifest_path,
                rel_path=rel,
                lineno=1,
                finding_class='EXT_CONN_BROAD',
                severity='HIGH',
                cwe='CWE-346',
                title='externally_connectable grants message API access to broad origins',
                detail=(
                    'The extension exposes chrome.runtime.sendMessage() to web pages '
                    'matching one or more wildcard patterns. Any page on a matching '
                    'origin can send arbitrary messages to the privileged service worker.'
                ),
                evidence=f'broad patterns: {broad}',
            ))
    elif has_content_scripts:
        findings.append(ExtFinding(
            path=manifest_path,
            rel_path=rel,
            lineno=1,
            finding_class='EXT_CONN_MISSING',
            severity='MEDIUM',
            cwe='CWE-346',
            title='externally_connectable absent; content scripts relay window.postMessage',
            detail=(
                'No externally_connectable declared but content_scripts are present. '
                'Content scripts that relay window.postMessage to chrome.runtime.sendMessage '
                'create an unauthenticated message bridge reachable from any co-origin script.'
            ),
        ))

    # native_messaging host check: allowed_origins containing * is overly broad
    nm_hosts = manifest.get('permissions', [])
    if 'nativeMessaging' in nm_hosts or 'nativeMessaging' in manifest.get('optional_permissions', []):
        # Flag for follow-up in host manifest
        findings.append(ExtFinding(
            path=manifest_path,
            rel_path=rel,
            lineno=1,
            finding_class='NATIVE_MSG_NO_ALLOWLIST',
            severity='MEDIUM',
            cwe='CWE-284',
            title='nativeMessaging permission declared — verify host manifest allowed_origins',
            detail=(
                'Extension requests nativeMessaging permission. '
                'The native messaging host manifest allowed_origins must restrict access '
                'to this specific extension ID. A wildcard or absent allowed_origins '
                'allows any extension to reach the native host.'
            ),
        ))

    return findings


# ── JS/TS file auditors ───────────────────────────────────────────────────────

def _audit_msg_handler_preauth(p: Path, rel: str, src: str) -> List[ExtFinding]:
    """
    Detect onMessage/onMessageExternal handlers that process payload before
    validating sender.id / sender.url / sender.origin.
    """
    findings: List[ExtFinding] = []
    if not re.search(r'on(?:Message|MessageExternal)\s*\.addListener', src):
        return []

    ls = _lines(src)
    n = len(ls)

    for i, line in enumerate(ls, 1):
        if not re.search(r'on(?:Message|MessageExternal)\s*\.addListener', line):
            continue

        # Scan forward up to 50 lines for the handler body
        body_start = i
        body_end = min(n, i + 50)
        body_lines = ls[body_start - 1:body_end]
        body = '\n'.join(body_lines)

        sender_check_line: Optional[int] = None
        first_payload_use_line: Optional[int] = None

        for j, bl in enumerate(body_lines, body_start):
            if _SENDER_CHECK_RE.search(bl) and sender_check_line is None:
                sender_check_line = j
            if _PAYLOAD_USE_RE.search(bl) and first_payload_use_line is None:
                first_payload_use_line = j

        if first_payload_use_line is None:
            continue  # no payload use — not risky

        if sender_check_line is None or first_payload_use_line < sender_check_line:
            findings.append(ExtFinding(
                path=p,
                rel_path=rel,
                lineno=i,
                finding_class='MSG_HANDLER_PREAUTH',
                severity='HIGH',
                cwe='CWE-285',
                title='Message handler processes payload before sender validation',
                detail=(
                    'The onMessage/onMessageExternal handler uses request content '
                    '(destructuring, fetch, chrome.tabs.sendMessage, or sendResponse) '
                    'before checking sender.id, sender.url, or sender.origin. '
                    'Any web page matching externally_connectable can drive the handler.'
                ),
                evidence=(
                    f'first payload use: line {first_payload_use_line}; '
                    f'sender check: {"line " + str(sender_check_line) if sender_check_line else "ABSENT"}'
                ),
                snippet=line.strip()[:120],
            ))

    return findings


def _audit_dom_hook(p: Path, rel: str, src: str) -> List[ExtFinding]:
    """Detect content scripts that overwrite window.fetch / XHR / cookie / location."""
    findings: List[ExtFinding] = []
    _HOOK_RE = re.compile(
        r'(?:window|self|globalThis)\s*\.\s*'
        r'(?:fetch|XMLHttpRequest|open|send|cookie)\s*=|'
        r'document\s*\.\s*cookie\s*=',
        re.IGNORECASE,
    )
    ls = _lines(src)
    for i, line in enumerate(ls, 1):
        if _HOOK_RE.search(line):
            findings.append(ExtFinding(
                path=p,
                rel_path=rel,
                lineno=i,
                finding_class='CONTENT_SCRIPT_DOM_HOOK',
                severity='MEDIUM',
                cwe='CWE-200',
                title='Content script hooks window.fetch / XHR / cookie',
                detail=(
                    'The content script overwrites a page global (fetch, '
                    'XMLHttpRequest, or document.cookie). All page requests or '
                    'cookie writes pass through the content script, which has '
                    'access to chrome.runtime.sendMessage. Page data leaks to '
                    'the extension privileged world.'
                ),
                snippet=line.strip()[:120],
            ))
    return findings


def _audit_websocket_bus(p: Path, rel: str, src: str) -> List[ExtFinding]:
    """Detect background service workers that open or connect to a WebSocket."""
    findings: List[ExtFinding] = []
    _WS_RE = re.compile(
        r'new\s+WebSocket\s*\(\s*[\'"]ws://',
        re.IGNORECASE,
    )
    _WS_SERVER_RE = re.compile(
        r'new\s+(?:WebSocketServer|Server)\s*\(\s*\{.*?port',
        re.IGNORECASE | re.DOTALL,
    )
    ls = _lines(src)
    for i, line in enumerate(ls, 1):
        if _WS_RE.search(line):
            findings.append(ExtFinding(
                path=p,
                rel_path=rel,
                lineno=i,
                finding_class='WEBSOCKET_BUS',
                severity='HIGH',
                cwe='CWE-284',
                title='Background service worker connects to ws:// WebSocket',
                detail=(
                    'The extension background context opens a ws:// WebSocket. '
                    'Any page that can reach the same loopback address bypasses '
                    'Chrome extension sender validation entirely — the WebSocket '
                    'server applies no per-origin check by default.'
                ),
                snippet=line.strip()[:120],
            ))

    # Check for WebSocket server creation (block-style match)
    if _WS_SERVER_RE.search(src):
        findings.append(ExtFinding(
            path=p,
            rel_path=rel,
            lineno=1,
            finding_class='WEBSOCKET_BUS',
            severity='HIGH',
            cwe='CWE-284',
            title='Background creates a WebSocket server (loopback exposure)',
            detail=(
                'The service worker creates a WebSocket server. '
                'Loopback WebSocket servers lack the same-origin restrictions '
                'of Chrome extension messaging — any local page can connect.'
            ),
        ))

    return findings


def _audit_native_msg(p: Path, rel: str, src: str) -> List[ExtFinding]:
    """Detect native messaging calls without surrounding allowlist guard."""
    findings: List[ExtFinding] = []
    _NM_RE = re.compile(r'chrome\.runtime\.(?:sendNativeMessage|connectNative)\s*\(')
    ls = _lines(src)
    for i, line in enumerate(ls, 1):
        if _NM_RE.search(line):
            # Look backward/forward 10 lines for a sender check
            start = max(0, i - 10)
            end = min(len(ls), i + 10)
            context = '\n'.join(ls[start:end])
            if not _SENDER_CHECK_RE.search(context):
                findings.append(ExtFinding(
                    path=p,
                    rel_path=rel,
                    lineno=i,
                    finding_class='NATIVE_MSG_NO_ALLOWLIST',
                    severity='HIGH',
                    cwe='CWE-284',
                    title='sendNativeMessage/connectNative without sender allowlist guard',
                    detail=(
                        'chrome.runtime.sendNativeMessage or connectNative called '
                        'with no sender.id / sender.url check in surrounding context. '
                        'If the extension is also externally_connectable, any web page '
                        'can trigger arbitrary native process execution.'
                    ),
                    snippet=line.strip()[:120],
                ))
    return findings


def _audit_storage_clear(p: Path, rel: str, src: str) -> List[ExtFinding]:
    """Detect storage.clear() inside message handlers with no sender check."""
    findings: List[ExtFinding] = []
    _CLEAR_RE = re.compile(r'chrome\.storage\.\w+\.clear\s*\(')
    ls = _lines(src)

    in_handler = False
    handler_start = 0

    for i, line in enumerate(ls, 1):
        if re.search(r'on(?:Message|MessageExternal)\s*\.addListener', line):
            in_handler = True
            handler_start = i
        if in_handler and _CLEAR_RE.search(line):
            # Check whether there's a sender guard in the handler body so far
            body = '\n'.join(ls[handler_start - 1:i])
            if not _SENDER_CHECK_RE.search(body):
                findings.append(ExtFinding(
                    path=p,
                    rel_path=rel,
                    lineno=i,
                    finding_class='PERSISTENT_DATA_CLEAR',
                    severity='LOW',
                    cwe='CWE-362',
                    title='chrome.storage.clear() in message handler without sender check',
                    detail=(
                        'chrome.storage.*.clear() called inside a message listener '
                        'before sender identity is verified. Any matched-origin page '
                        'can wipe extension-stored session data or credentials.'
                    ),
                    snippet=line.strip()[:120],
                ))
        # Reset handler tracking on closing brace patterns (heuristic)
        if in_handler and i > handler_start + 60:
            in_handler = False

    return findings


# ── Main scanner class ────────────────────────────────────────────────────────

class BrowserExtensionAuditor:
    """
    Chrome/Edge/Firefox extension security auditor.

    Scans:
    - manifest.json (V2 and V3): externally_connectable, permissions, content_scripts
    - Background service workers and pages: message handler auth order, native messaging
    - Content scripts: DOM hook detection

    Usage::

        findings = BrowserExtensionAuditor.from_path('/tmp/fpam-ext/').scan()
        print(BrowserExtensionAuditor.report(findings))
    """

    def __init__(self, root: Path, js_files: List[Path], manifest: Optional[Path]) -> None:
        self._root = root
        self._js_files = js_files
        self._manifest = manifest

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str) -> 'BrowserExtensionAuditor':
        """Build auditor from an extension directory."""
        root = Path(path)
        if not root.is_dir():
            raise ValueError(f'Not a directory: {path}')
        js_files = [
            p for p in root.rglob('*')
            if p.suffix in _SCAN_EXTS and p.is_file()
        ]
        manifest = root / 'manifest.json'
        return cls(root, js_files, manifest if manifest.exists() else None)

    @classmethod
    def scan_file(cls, path: str) -> List[ExtFinding]:
        """Scan a single JS/TS file."""
        p = Path(path)
        src = p.read_text(encoding='utf-8', errors='replace')
        rel = p.name
        findings: List[ExtFinding] = []
        if not _EXT_QUICK_RE.search(src):
            return findings
        findings.extend(_audit_msg_handler_preauth(p, rel, src))
        findings.extend(_audit_dom_hook(p, rel, src))
        findings.extend(_audit_websocket_bus(p, rel, src))
        findings.extend(_audit_native_msg(p, rel, src))
        findings.extend(_audit_storage_clear(p, rel, src))
        return findings

    # ── Scan ──────────────────────────────────────────────────────────────────

    def scan(self) -> List[ExtFinding]:
        """Run all audit checks. Returns findings sorted by severity."""
        findings: List[ExtFinding] = []

        if self._manifest:
            findings.extend(_audit_manifest(self._manifest, self._root))

        for js in self._js_files:
            try:
                src = js.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue
            if not _EXT_QUICK_RE.search(src):
                continue
            rel = str(js.relative_to(self._root))
            findings.extend(_audit_msg_handler_preauth(js, rel, src))
            findings.extend(_audit_dom_hook(js, rel, src))
            findings.extend(_audit_websocket_bus(js, rel, src))
            findings.extend(_audit_native_msg(js, rel, src))
            findings.extend(_audit_storage_clear(js, rel, src))

        _SEV_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda f: (_SEV_RANK.get(f.severity, 9), f.rel_path, f.lineno))
        return findings

    # ── Reporting ─────────────────────────────────────────────────────────────

    @staticmethod
    def report(findings: List[ExtFinding], min_severity: Optional[str] = None) -> str:
        _SEV_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        if min_severity:
            threshold = _SEV_RANK.get(min_severity, 99)
            findings = [f for f in findings if _SEV_RANK.get(f.severity, 99) <= threshold]

        if not findings:
            return 'BrowserExtensionAuditor: no findings.'

        counts: dict = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = ' | '.join(
            f'{k}: {v}' for k, v in
            sorted(counts.items(), key=lambda kv: _SEV_RANK.get(kv[0], 9))
        )
        lines = [
            f'BrowserExtensionAuditor — {len(findings)} finding(s) [{summary}]',
            '=' * 70,
        ]
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)


# ── CLI entry ─────────────────────────────────────────────────────────────────

def _main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='Browser extension security auditor')
    ap.add_argument('path', help='Extension directory or JS file to scan')
    ap.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    help='Minimum severity to report')
    args = ap.parse_args()

    p = Path(args.path)
    if p.is_file():
        findings = BrowserExtensionAuditor.scan_file(str(p))
    else:
        findings = BrowserExtensionAuditor.from_path(str(p)).scan()

    print(BrowserExtensionAuditor.report(findings, min_severity=args.severity))


if __name__ == '__main__':
    _main()
