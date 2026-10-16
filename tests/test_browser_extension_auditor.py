"""
Tests for BrowserExtensionAuditor — browser extension security scanner.

Each test is named after the finding class it exercises.
All tests use in-memory fixtures (no real extension required).
"""

import json
import tempfile
from pathlib import Path

import pytest

from ablation.analyzers.browser_extension_auditor import (
    BrowserExtensionAuditor,
    _audit_manifest,
    _audit_msg_handler_preauth,
    _audit_dom_hook,
    _audit_websocket_bus,
    _audit_native_msg,
    _audit_storage_clear,
    _pattern_is_broad,
    ExtFinding,
)


# ── Helper ────────────────────────────────────────────────────────────────────

def _write_ext(tmp: Path, manifest_dict: dict, js_files: dict[str, str] | None = None) -> Path:
    """Create a minimal extension directory for auditing."""
    ext = tmp / 'ext'
    ext.mkdir(exist_ok=True)
    (ext / 'manifest.json').write_text(json.dumps(manifest_dict), encoding='utf-8')
    for name, src in (js_files or {}).items():
        f = ext / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(src, encoding='utf-8')
    return ext


# ── _pattern_is_broad ─────────────────────────────────────────────────────────

@pytest.mark.parametrize('pat,expected', [
    ('*://*/*', True),
    ('https://*/*', True),
    ('http://*/*', True),
    ('<all_urls>', True),
    ('https://*.example.com/*', True),
    ('https://sso.corp.com/*', False),
    ('https://ems.fortinet.com/auth/*', False),
    ('http://localhost/*', False),
])
def test_pattern_is_broad(pat, expected):
    assert _pattern_is_broad(pat) is expected


# ── EXT_CONN_BROAD ────────────────────────────────────────────────────────────

def test_ext_conn_broad_fires_on_wildcard():
    with tempfile.TemporaryDirectory() as tmp:
        ext = _write_ext(Path(tmp), {
            'manifest_version': 3,
            'name': 'TestExt',
            'version': '1.0',
            'externally_connectable': {'matches': ['https://*/*']},
        })
        findings = _audit_manifest(ext / 'manifest.json', ext)
    assert any(f.finding_class == 'EXT_CONN_BROAD' for f in findings)
    assert any(f.severity == 'HIGH' for f in findings if f.finding_class == 'EXT_CONN_BROAD')


def test_ext_conn_broad_does_not_fire_on_specific_origin():
    with tempfile.TemporaryDirectory() as tmp:
        ext = _write_ext(Path(tmp), {
            'manifest_version': 3,
            'name': 'TestExt',
            'version': '1.0',
            'externally_connectable': {'matches': ['https://ems.corp.com/*']},
        })
        findings = _audit_manifest(ext / 'manifest.json', ext)
    broad = [f for f in findings if f.finding_class == 'EXT_CONN_BROAD']
    assert not broad


# ── EXT_CONN_MISSING ─────────────────────────────────────────────────────────

def test_ext_conn_missing_fires_when_content_scripts_present():
    with tempfile.TemporaryDirectory() as tmp:
        ext = _write_ext(Path(tmp), {
            'manifest_version': 3,
            'name': 'TestExt',
            'version': '1.0',
            'content_scripts': [{'matches': ['<all_urls>'], 'js': ['content.js']}],
        })
        findings = _audit_manifest(ext / 'manifest.json', ext)
    assert any(f.finding_class == 'EXT_CONN_MISSING' for f in findings)


def test_ext_conn_missing_does_not_fire_without_content_scripts():
    with tempfile.TemporaryDirectory() as tmp:
        ext = _write_ext(Path(tmp), {
            'manifest_version': 3,
            'name': 'TestExt',
            'version': '1.0',
        })
        findings = _audit_manifest(ext / 'manifest.json', ext)
    assert not any(f.finding_class == 'EXT_CONN_MISSING' for f in findings)


# ── MSG_HANDLER_PREAUTH ───────────────────────────────────────────────────────

_PREAUTH_HANDLER_SRC = """\
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    const host = request.host;
    fetch('http://' + host).then(r => sendResponse(r.status));
    if (sender.url !== 'https://allowed.com') return;
});
"""

_SAFE_HANDLER_SRC = """\
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (sender.url !== 'https://allowed.com') return;
    const host = request.host;
    fetch('http://' + host).then(r => sendResponse(r.status));
});
"""

_EXTERNAL_PREAUTH_SRC = """\
chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {
    const action = request.action;
    chrome.tabs.query({}, function(tabs) { sendResponse(tabs); });
});
"""


def test_msg_handler_preauth_fires_payload_before_check():
    p = Path('/fake/background.js')
    findings = _audit_msg_handler_preauth(p, 'background.js', _PREAUTH_HANDLER_SRC)
    assert any(f.finding_class == 'MSG_HANDLER_PREAUTH' for f in findings)


def test_msg_handler_preauth_clean_when_check_first():
    p = Path('/fake/background.js')
    findings = _audit_msg_handler_preauth(p, 'background.js', _SAFE_HANDLER_SRC)
    assert not any(f.finding_class == 'MSG_HANDLER_PREAUTH' for f in findings)


def test_msg_handler_preauth_fires_on_message_external():
    p = Path('/fake/background.js')
    findings = _audit_msg_handler_preauth(p, 'background.js', _EXTERNAL_PREAUTH_SRC)
    assert any(f.finding_class == 'MSG_HANDLER_PREAUTH' for f in findings)


def test_msg_handler_preauth_absent_sender_check():
    src = """\
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    sendResponse({data: request.payload});
});
"""
    p = Path('/fake/background.js')
    findings = _audit_msg_handler_preauth(p, 'background.js', src)
    assert any(f.finding_class == 'MSG_HANDLER_PREAUTH' for f in findings)
    finding = next(f for f in findings if f.finding_class == 'MSG_HANDLER_PREAUTH')
    assert 'ABSENT' in finding.evidence


# ── CONTENT_SCRIPT_DOM_HOOK ───────────────────────────────────────────────────

@pytest.mark.parametrize('src,should_fire', [
    ('window.fetch = function(url, opts) { return originalFetch(url, opts); };', True),
    ('window.XMLHttpRequest = function() {};', True),
    ('document.cookie = "session=" + token;', True),
    ('const result = await fetch(url);', False),
    ('chrome.runtime.sendMessage({action: "log", url});', False),
])
def test_content_script_dom_hook(src, should_fire):
    p = Path('/fake/content.js')
    findings = _audit_dom_hook(p, 'content.js', src)
    fired = any(f.finding_class == 'CONTENT_SCRIPT_DOM_HOOK' for f in findings)
    assert fired is should_fire


# ── WEBSOCKET_BUS ─────────────────────────────────────────────────────────────

def test_websocket_bus_fires_on_ws_connect():
    src = "const ws = new WebSocket('ws://127.0.0.1:4433/ext');"
    p = Path('/fake/background.js')
    findings = _audit_websocket_bus(p, 'background.js', src)
    assert any(f.finding_class == 'WEBSOCKET_BUS' for f in findings)


def test_websocket_bus_does_not_fire_on_wss():
    src = "const ws = new WebSocket('wss://secure.example.com/ws');"
    p = Path('/fake/background.js')
    findings = _audit_websocket_bus(p, 'background.js', src)
    assert not any(f.finding_class == 'WEBSOCKET_BUS' for f in findings)


# ── NATIVE_MSG_NO_ALLOWLIST ───────────────────────────────────────────────────

def test_native_msg_no_allowlist_fires_without_sender_check():
    src = """\
function handleMsg(request, sender, sendResponse) {
    chrome.runtime.sendNativeMessage('com.fortinet.ems', request, sendResponse);
}
"""
    p = Path('/fake/background.js')
    findings = _audit_native_msg(p, 'background.js', src)
    assert any(f.finding_class == 'NATIVE_MSG_NO_ALLOWLIST' for f in findings)


def test_native_msg_no_allowlist_clean_with_sender_check():
    src = """\
function handleMsg(request, sender, sendResponse) {
    if (sender.id !== 'knownExtId') return;
    chrome.runtime.sendNativeMessage('com.fortinet.ems', request, sendResponse);
}
"""
    p = Path('/fake/background.js')
    findings = _audit_native_msg(p, 'background.js', src)
    assert not any(f.finding_class == 'NATIVE_MSG_NO_ALLOWLIST' for f in findings)


# ── PERSISTENT_DATA_CLEAR ────────────────────────────────────────────────────

def test_storage_clear_fires_without_sender_check():
    src = """\
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'logout') {
        chrome.storage.local.clear();
    }
});
"""
    p = Path('/fake/background.js')
    findings = _audit_storage_clear(p, 'background.js', src)
    assert any(f.finding_class == 'PERSISTENT_DATA_CLEAR' for f in findings)


def test_storage_clear_clean_with_sender_check():
    src = """\
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (sender.url !== 'https://ems.corp.com/') return;
    if (request.action === 'logout') {
        chrome.storage.local.clear();
    }
});
"""
    p = Path('/fake/background.js')
    findings = _audit_storage_clear(p, 'background.js', src)
    assert not any(f.finding_class == 'PERSISTENT_DATA_CLEAR' for f in findings)


# ── Integration: from_path / report ──────────────────────────────────────────

def test_from_path_end_to_end():
    manifest = {
        'manifest_version': 3,
        'name': 'TestExt',
        'version': '1.0',
        'externally_connectable': {'matches': ['https://*/*']},
        'background': {'service_worker': 'background.js'},
    }
    bg_js = """\
chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {
    const ws = new WebSocket('ws://127.0.0.1:5555/bus');
    const host = request.host;
    fetch('http://' + host).then(r => sendResponse(r.status));
    if (sender.url.startsWith('https://')) sendResponse({ok: true});
});
"""
    content_js = (
        "window.fetch = function(url) {"
        "  return realFetch(url).then(r => chrome.runtime.sendMessage({url, status: r.status}));"
        "};"
    )

    with tempfile.TemporaryDirectory() as tmp:
        ext = _write_ext(Path(tmp), manifest, {'background.js': bg_js, 'content.js': content_js})
        auditor = BrowserExtensionAuditor.from_path(str(ext))
        findings = auditor.scan()

    classes = {f.finding_class for f in findings}
    assert 'EXT_CONN_BROAD' in classes
    assert 'MSG_HANDLER_PREAUTH' in classes
    assert 'WEBSOCKET_BUS' in classes
    assert 'CONTENT_SCRIPT_DOM_HOOK' in classes


def test_report_contains_severity_summary():
    src = "chrome.runtime.onMessage.addListener(function(r,s,rs){ fetch(r.url); });"
    p = Path('/fake/bg.js')
    findings = _audit_msg_handler_preauth(p, 'bg.js', src)
    findings += _audit_websocket_bus(p, 'bg.js', "new WebSocket('ws://127.0.0.1/x');")
    text = BrowserExtensionAuditor.report(findings)
    assert 'HIGH' in text
    assert 'BrowserExtensionAuditor' in text


def test_report_min_severity_filters():
    manifest = {
        'manifest_version': 3,
        'name': 'T',
        'version': '1.0',
        'content_scripts': [{'matches': ['<all_urls>'], 'js': ['c.js']}],
    }
    with tempfile.TemporaryDirectory() as tmp:
        ext = _write_ext(Path(tmp), manifest)
        findings = _audit_manifest(ext / 'manifest.json', ext)
    # EXT_CONN_MISSING is MEDIUM
    medium_findings = [f for f in findings if f.finding_class == 'EXT_CONN_MISSING']
    assert medium_findings
    text = BrowserExtensionAuditor.report(findings, min_severity='HIGH')
    # MEDIUM findings should be filtered out
    for f in medium_findings:
        assert f.finding_class not in text or 'MEDIUM' not in text.split(f.finding_class)[0]


def test_scan_file_single_js():
    with tempfile.TemporaryDirectory() as tmp:
        js = Path(tmp) / 'bg.js'
        js.write_text(
            "chrome.runtime.onMessage.addListener(function(req,sender,resp){ fetch(req.url); });",
            encoding='utf-8',
        )
        findings = BrowserExtensionAuditor.scan_file(str(js))
    assert any(f.finding_class == 'MSG_HANDLER_PREAUTH' for f in findings)


def test_empty_extension_no_crash():
    with tempfile.TemporaryDirectory() as tmp:
        ext = Path(tmp) / 'empty'
        ext.mkdir()
        (ext / 'manifest.json').write_text('{}')
        findings = BrowserExtensionAuditor.from_path(str(ext)).scan()
    assert isinstance(findings, list)
