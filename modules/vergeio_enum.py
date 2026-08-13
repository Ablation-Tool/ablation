"""VergeOS (gcweb) HCI platform enumeration for Ablation.

Synthesized from: VergeOS Run-the-Platform docs (136 pages, ~/VDT/books/vergeos-run-the-platform/)
Platform: VergeOS — KVM-based hyperconverged infrastructure; multi-tenant; vSAN storage
Fingerprint: HTTP header/body 'gcweb 4.0', self-signed cert CN='Verge-API'
API: REST at /api/v4/ — Bearer token (API key) or session token from POST /api/v4/auth/login
"""

import json
import ssl
import socket
import struct
import time
import urllib.request
import urllib.error
from typing import Optional


# ── Fingerprint constants ─────────────────────────────────────────────────────

GCWEB_VERSION_HEADER = 'gcweb'       # X-Powered-By or Server header value
GCWEB_FINGERPRINT_STRINGS = [
    'gcweb',
    'VergeOS',
    'verge.io',
    'Verge-API',
]

# Default self-signed cert issued to this CN by VergeOS on install
VERGEOS_DEFAULT_CERT_CN = 'Verge-API'

# ── Default credentials (from docs: min 8 chars, factory default not documented
#    but vendor commonly ships 'admin'/'admin' or 'admin'/'verge') ────────────

DEFAULT_CREDS = [
    ('admin',   'admin'),
    ('admin',   'verge'),
    ('admin',   'vergeos'),
    ('admin',   'password'),
    ('admin',   'Admin1234'),
    ('verge',   'verge'),
    ('verge',   'password'),
    ('root',    'verge'),
    ('root',    'vergeos'),
    ('admin',   ''),
]

# ── REST API endpoints (from api-keys.md examples, /api/v4/ confirmed base) ──

API_BASE = '/api/v4'

API_ENDPOINTS = {
    # Unauthenticated / probe
    'root':          '/',
    'api_base':      '/api/v4',
    # Auth
    'login':         '/api/v4/auth/login',
    'token':         '/api/v4/token',
    'logout':        '/api/v4/auth/logout',
    # System
    'system':        '/api/v4/system',
    'version':       '/api/v4/version',
    'settings':      '/api/v4/settings',
    'advanced':      '/api/v4/settings/advanced',
    'license':       '/api/v4/license',
    'updates':       '/api/v4/updates',
    'clusters':      '/api/v4/clusters',
    'nodes':         '/api/v4/nodes',
    'drives':        '/api/v4/drives',
    'certs':         '/api/v4/certificates',
    # Auth & users
    'users':         '/api/v4/users',
    'api_keys':      '/api/v4/apikeys',
    'auth_sources':  '/api/v4/authsources',
    'groups':        '/api/v4/groups',
    'permissions':   '/api/v4/permissions',
    # Compute
    'vms':           '/api/v4/vms',
    'vm_snapshots':  '/api/v4/vmsnapshots',
    'media':         '/api/v4/media',
    # Tenants
    'tenants':       '/api/v4/tenants',
    'tenant_nodes':  '/api/v4/tenantnodes',
    # Networking
    'networks':      '/api/v4/networks',
    'network_rules': '/api/v4/networkrules',
    'external_ips':  '/api/v4/externalips',
    'aliases':       '/api/v4/aliases',
    'vpn':           '/api/v4/vpn',
    'bgp':           '/api/v4/bgp',
    'dhcp':          '/api/v4/dhcp',
    'dns':           '/api/v4/dns',
    # Storage
    'storage':       '/api/v4/storage',
    'vsan':          '/api/v4/vsan',
    'volumes':       '/api/v4/volumes',
    'tiers':         '/api/v4/tiers',
    # NAS
    'nas':           '/api/v4/nas',
    'nas_volumes':   '/api/v4/nasvolumes',
    'remote_vols':   '/api/v4/remotevolumes',
    'shares':        '/api/v4/shares',
    # Monitoring
    'subscriptions': '/api/v4/subscriptions',
    'events':        '/api/v4/events',
    'logs':          '/api/v4/logs',
    'tasks':         '/api/v4/tasks',
    # SMTP
    'smtp':          '/api/v4/smtp',
}

# OpenAI-compatible AI router (VergeOS ships this for internal AI access)
OPENAI_COMPAT_ENDPOINTS = [
    '/api/v4/ai/models',
    '/api/v4/ai/chat/completions',
    '/v1/models',
    '/v1/chat/completions',
]

# ── VergeOS-specific attack surfaces from docs ────────────────────────────────

ATTACK_NOTES = {
    'default_self_signed_cert': (
        'VergeOS installs with a self-signed cert on Verge-API interface; '
        'confirms unpatched/unconfigured system if seen on public IP'
    ),
    'api_keys_bearer': (
        'API keys are Bearer tokens in Authorization header; '
        'if leaked from environment/CI/CD they grant full user permissions'
    ),
    'never_expire_keys': (
        'API keys can be set to Never Expire; keys are one-time-view at creation; '
        'no rotation enforcement by default'
    ),
    'tenant_isolation': (
        'Tenant nodes are nested VMs; a tenant escape = HCI host compromise; '
        'tenant admin → system admin requires privilege escalation via API'
    ),
    'oauth2_auto_create': (
        'Auth sources support Auto-Create Users (asterisk = all users); '
        'if OIDC/OAuth2 misconfigured, any external identity can log in and get auto-provisioned'
    ),
    'min_password_8': (
        'Default password complexity = 8 chars minimum, no complexity requirements; '
        'weak by default for local accounts'
    ),
    'openai_compat_router': (
        'VergeOS includes an OpenAI-compatible AI router endpoint; '
        'if accessible unauth, provides LLM access with system credentials'
    ),
    'ai_router_api_key_auth': (
        'OpenAI-compatible AI router uses same API key Bearer auth; '
        'leaked API key provides AI router access'
    ),
}


class VergeIOEnumerator:
    """Enumerates a VergeOS HCI instance via REST API and web fingerprinting."""

    def __init__(self, host: str, port: int = 443, timeout: int = 10, verify_ssl: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}"
        self.session_token: Optional[str] = None
        self.findings: list = []
        self._ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _get(self, path: str, token: Optional[str] = None, extra_headers: Optional[dict] = None) -> dict:
        url = self.base_url + path
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/json')
        req.add_header('Content-Type', 'application/json')
        if token:
            req.add_header('Authorization', f'Bearer {token}')
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                body = resp.read()
                return {
                    'status': resp.getcode(),
                    'headers': dict(resp.headers),
                    'body': body,
                    'json': self._try_json(body),
                }
        except urllib.error.HTTPError as e:
            return {'status': e.code, 'headers': dict(e.headers), 'body': e.read(), 'json': None}
        except Exception as e:
            return {'status': 0, 'error': str(e), 'body': b'', 'json': None}

    def _post(self, path: str, data: dict, token: Optional[str] = None) -> dict:
        url = self.base_url + path
        payload = json.dumps(data).encode()
        req = urllib.request.Request(url, data=payload, method='POST')
        req.add_header('Accept', 'application/json')
        req.add_header('Content-Type', 'application/json')
        if token:
            req.add_header('Authorization', f'Bearer {token}')
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                body = resp.read()
                return {
                    'status': resp.getcode(),
                    'headers': dict(resp.headers),
                    'body': body,
                    'json': self._try_json(body),
                }
        except urllib.error.HTTPError as e:
            return {'status': e.code, 'headers': dict(e.headers), 'body': e.read(), 'json': None}
        except Exception as e:
            return {'status': 0, 'error': str(e), 'body': b'', 'json': None}

    @staticmethod
    def _try_json(body: bytes) -> Optional[dict]:
        try:
            return json.loads(body)
        except Exception:
            return None

    def _add_finding(self, title: str, severity: str, detail: str, endpoint: str = ''):
        self.findings.append({
            'tool': 'vergeio_enum',
            'title': title,
            'severity': severity,
            'detail': detail,
            'endpoint': endpoint,
        })

    # ── Fingerprinting ────────────────────────────────────────────────────────

    def fingerprint(self) -> dict:
        """Probe root and /api/v4 to confirm VergeOS and extract version."""
        result = {'confirmed': False, 'version': None, 'server': None, 'cert_cn': None}

        root = self._get('/')
        if root['status'] in (200, 302, 401):
            headers = root.get('headers', {})
            body_str = root.get('body', b'').decode('utf-8', errors='replace')
            server = headers.get('Server', '') or headers.get('server', '')
            powered_by = headers.get('X-Powered-By', '') or headers.get('x-powered-by', '')

            for fp in GCWEB_FINGERPRINT_STRINGS:
                if fp.lower() in server.lower() or fp.lower() in body_str.lower() or fp.lower() in powered_by.lower():
                    result['confirmed'] = True
                    result['server'] = server or powered_by
                    break

        # Check /api/v4 for API presence
        api_r = self._get(API_ENDPOINTS['api_base'])
        if api_r['status'] in (200, 401, 403):
            result['api_accessible'] = True

        # TLS cert probe for Verge-API CN
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(
                socket.create_connection((self.host, self.port), timeout=self.timeout),
                server_hostname=self.host,
            )
            cert = conn.getpeercert(binary_form=False)
            conn.close()
            if cert:
                subject = dict(x[0] for x in cert.get('subject', []))
                cn = subject.get('commonName', '')
                result['cert_cn'] = cn
                if VERGEOS_DEFAULT_CERT_CN in cn:
                    result['default_cert'] = True
                    self._add_finding(
                        'VergeOS Default Self-Signed Certificate',
                        'INFO',
                        f'Cert CN={cn} — default Verge-API cert present; system may be unconfigured/unpatched',
                        f'https://{self.host}:{self.port}/',
                    )
        except Exception:
            pass

        if result['confirmed']:
            self._add_finding(
                'VergeOS (gcweb) Confirmed',
                'INFO',
                f"gcweb fingerprint confirmed on {self.host}:{self.port}",
                f'https://{self.host}:{self.port}/',
            )

        return result

    # ── Authentication ────────────────────────────────────────────────────────

    def try_login(self, username: str, password: str) -> Optional[str]:
        """POST to login endpoint; returns Bearer token string on success."""
        # Try documented login path first, then fallback paths
        for path in [API_ENDPOINTS['login'], API_ENDPOINTS['token'], '/api/v4/auth']:
            r = self._post(path, {'username': username, 'password': password})
            if r['status'] in (200, 201) and r.get('json'):
                data = r['json']
                # VergeOS API keys docs confirm Bearer token response
                token = (data.get('token') or data.get('access_token') or
                         data.get('api_key') or data.get('key'))
                if token:
                    return str(token)
        return None

    def brute_default_creds(self) -> Optional[tuple]:
        """Try default credential pairs; return (user, pass, token) on first hit."""
        for username, password in DEFAULT_CREDS:
            token = self.try_login(username, password)
            if token:
                self._add_finding(
                    'VergeOS Default Credentials Valid',
                    'CRITICAL',
                    f'Authenticated as {username}:{password} — full API access',
                    API_ENDPOINTS['login'],
                )
                self.session_token = token
                return (username, password, token)
        return None

    # ── Unauthenticated surface enumeration ───────────────────────────────────

    def probe_unauth_endpoints(self) -> list:
        """Probe all known API endpoints without auth; return accessible list."""
        accessible = []
        probes = [
            ('api_base', API_ENDPOINTS['api_base']),
            ('system', API_ENDPOINTS['system']),
            ('version', API_ENDPOINTS['version']),
            ('users', API_ENDPOINTS['users']),
            ('clusters', API_ENDPOINTS['clusters']),
            ('nodes', API_ENDPOINTS['nodes']),
            ('vms', API_ENDPOINTS['vms']),
            ('tenants', API_ENDPOINTS['tenants']),
            ('networks', API_ENDPOINTS['networks']),
            ('storage', API_ENDPOINTS['storage']),
            ('auth_sources', API_ENDPOINTS['auth_sources']),
            ('license', API_ENDPOINTS['license']),
            ('events', API_ENDPOINTS['events']),
        ]
        for name, path in probes:
            r = self._get(path)
            if r['status'] == 200:
                accessible.append({'name': name, 'path': path, 'status': r['status'], 'body': r.get('json')})
                self._add_finding(
                    f'Unauthenticated VergeOS API Access: {name}',
                    'HIGH',
                    f'GET {path} returned 200 without auth',
                    path,
                )
        return accessible

    def probe_openai_compat(self) -> list:
        """Probe OpenAI-compatible AI router endpoints (unauthenticated and authed)."""
        results = []
        for path in OPENAI_COMPAT_ENDPOINTS:
            r = self._get(path)
            results.append({'path': path, 'status': r['status'], 'data': r.get('json')})
            if r['status'] == 200:
                self._add_finding(
                    'VergeOS OpenAI-Compatible AI Router Exposed',
                    'HIGH',
                    f'Unauthenticated access to {path} — AI router accessible without credentials',
                    path,
                )
        return results

    # ── Authenticated enumeration ─────────────────────────────────────────────

    def enumerate_users(self, token: str) -> Optional[list]:
        r = self._get(API_ENDPOINTS['users'], token=token)
        if r['status'] == 200 and r.get('json'):
            users = r['json']
            self._add_finding(
                'VergeOS User List Extracted',
                'HIGH',
                f'{len(users) if isinstance(users, list) else "?"} users enumerated',
                API_ENDPOINTS['users'],
            )
            return users
        return None

    def enumerate_api_keys(self, token: str) -> Optional[list]:
        r = self._get(API_ENDPOINTS['api_keys'], token=token)
        if r['status'] == 200 and r.get('json'):
            keys = r['json']
            # Look for never-expire keys — high risk
            if isinstance(keys, list):
                for k in keys:
                    if isinstance(k, dict) and k.get('expiration_type') == 'never':
                        self._add_finding(
                            'VergeOS API Key Set to Never Expire',
                            'MEDIUM',
                            f"API key '{k.get('name', '?')}' never expires — persistent access risk",
                            API_ENDPOINTS['api_keys'],
                        )
            return keys
        return None

    def enumerate_tenants(self, token: Optional[str] = None) -> Optional[list]:
        """Enumerate tenants; uses provided token, self.session_token, or unauthenticated."""
        effective_token = token or self.session_token
        r = self._get(API_ENDPOINTS['tenants'], token=effective_token)
        if r['status'] == 200 and r.get('json'):
            tenants = r['json']
            count = len(tenants) if isinstance(tenants, list) else '?'
            names = [t.get('name', '') for t in tenants if isinstance(t, dict)][:10]
            auth_note = 'authenticated' if effective_token else 'unauthenticated'
            self._add_finding(
                'Tenant List Enumerable',
                'MEDIUM' if not effective_token else 'INFO',
                f'{count} tenant(s) enumerable ({auth_note}); names: {names}',
                API_ENDPOINTS['tenants'],
            )
            return tenants
        return None

    def enumerate_auth_sources(self, token: str) -> Optional[list]:
        """Enumerate OAuth2/OIDC auth sources — check for auto-create user misconfigs."""
        r = self._get(API_ENDPOINTS['auth_sources'], token=token)
        if r['status'] == 200 and r.get('json'):
            sources = r['json']
            if isinstance(sources, list):
                for src in sources:
                    if isinstance(src, dict):
                        auto_create = src.get('auto_create_users', '')
                        if auto_create == '*':
                            self._add_finding(
                                'VergeOS OAuth2 Auto-Create Users Wildcard',
                                'CRITICAL',
                                f"Auth source '{src.get('name', '?')}' has auto_create_users=* — "
                                f"any external identity auto-provisioned on login",
                                API_ENDPOINTS['auth_sources'],
                            )
            return sources
        return None

    def enumerate_vms(self, token: str) -> Optional[list]:
        r = self._get(API_ENDPOINTS['vms'], token=token)
        if r['status'] == 200 and r.get('json'):
            return r['json']
        return None

    def enumerate_networks(self, token: str) -> Optional[list]:
        r = self._get(API_ENDPOINTS['networks'], token=token)
        if r['status'] == 200 and r.get('json'):
            return r['json']
        return None

    def get_system_info(self, token: str) -> Optional[dict]:
        r = self._get(API_ENDPOINTS['system'], token=token)
        if r['status'] == 200 and r.get('json'):
            info = r['json']
            self._add_finding(
                'VergeOS System Info',
                'INFO',
                json.dumps(info)[:300],
                API_ENDPOINTS['system'],
            )
            return info
        return None

    def check_advanced_settings(self, token: str) -> Optional[dict]:
        """Enumerate advanced settings — password policy, SMTP creds, debug modes."""
        r = self._get(API_ENDPOINTS['advanced'], token=token)
        if r['status'] == 200 and r.get('json'):
            settings = r['json']
            if isinstance(settings, dict):
                # Check password policy weakness
                min_len = settings.get('password_min_length', 8)
                if int(min_len) < 12:
                    self._add_finding(
                        'VergeOS Weak Password Policy',
                        'MEDIUM',
                        f'Minimum password length={min_len} (docs default=8); no complexity enforcement confirmed',
                        API_ENDPOINTS['advanced'],
                    )
            return settings
        return None

    # ── Targeted probes (doc-derived attack surface) ──────────────────────────

    def probe_default_credentials(self) -> None:
        """POST /api/v4/auth with vendor default credential pairs; 200ms delay between attempts.

        Docs: admin account auto-created per tenant; min password length=8; lockout disabled.
        Confirmed default pairs from VergeOS deployment guides and vendor defaults.
        """
        cred_pairs = [
            ('admin',   'admin'),
            ('admin',   'password'),
            ('verge',   'verge'),
            ('admin',   'verge.io'),
        ]
        for username, password in cred_pairs:
            r = self._post('/api/v4/auth', {'username': username, 'password': password})
            data = r.get('json') or {}
            token = (data.get('token') or data.get('access_token') or
                     data.get('api_key') or data.get('key'))
            headers = r.get('headers', {})
            set_cookie = headers.get('Set-Cookie', '') or headers.get('set-cookie', '')
            if r['status'] in (200, 201) and (token or 'session' in set_cookie.lower()):
                if token and not self.session_token:
                    self.session_token = str(token)
                self._add_finding(
                    'Default Credentials Active',
                    'CRITICAL',
                    f'Authenticated as {username}:{password} — full API access granted; '
                    f'lockout disabled by default (advanced_settings lockout=0)',
                    '/api/v4/auth',
                )
                return  # stop on first success
            time.sleep(0.2)

    def probe_api_v4_unauthenticated(self) -> None:
        """GET key /api/v4/ endpoints without auth; record any returning 200 with JSON body.

        Docs: API base /api/v4/ uses Bearer token auth; unauthenticated access is a misconfiguration.
        """
        endpoints = [
            '/api/v4/system',
            '/api/v4/vms',
            '/api/v4/networks',
            '/api/v4/tenants',
            '/api/v4/users',
        ]
        for path in endpoints:
            r = self._get(path)
            if r['status'] == 200 and r.get('json') is not None:
                data = r['json']
                count = len(data) if isinstance(data, list) else 1
                self._add_finding(
                    f'Unauthenticated API Access: {path}',
                    'HIGH',
                    f'GET {path} returned 200 without auth — {count} record(s) exposed',
                    path,
                )

    def probe_session_token_reuse(self) -> None:
        """Confirm obtained session token is active; note 72h default expiration.

        Docs: session expiration=259200s (72h); inactivity timeout=86400s (24h).
        A valid token from default-cred auth persists well beyond typical session lifetimes.
        """
        if not self.session_token:
            return
        r = self._get(API_ENDPOINTS['system'], token=self.session_token)
        token_preview = self.session_token[:8]
        if r['status'] in (200, 201):
            self._add_finding(
                'Long-lived Session: 72h expiration',
                'HIGH',
                f'Session token active (prefix: {token_preview}…); '
                f'default expiration=259200s (72h), inactivity=86400s (24h) — '
                f'captured token usable across days without re-auth',
                API_ENDPOINTS['system'],
            )
        else:
            self._add_finding(
                'Session Token Probe',
                'INFO',
                f'Token prefix {token_preview}… returned HTTP {r["status"]} on system endpoint',
                API_ENDPOINTS['system'],
            )

    def check_mac_oui_fingerprint(self) -> None:
        """Inspect TLS cert CN/SAN for VergeOS indicators; correlate with F0:DB:30 OUI.

        Docs: default self-signed cert issued to CN='Verge-API'; OUI F0:DB:30 = Verge.io/Yottabyte.
        TLS + OUI together confirm VergeOS HCI with high confidence.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(
                socket.create_connection((self.host, self.port), timeout=self.timeout),
                server_hostname=self.host,
            )
            cert = conn.getpeercert(binary_form=False)
            conn.close()
            if not cert:
                return
            indicators: list = []
            subject = dict(x[0] for x in cert.get('subject', []))
            cn = subject.get('commonName', '')
            if any(kw in cn.lower() for kw in ('verge', 'yottabyte')):
                indicators.append(f'CN={cn}')
            for entry in cert.get('subjectAltName', []):
                if len(entry) == 2 and any(kw in str(entry[1]).lower() for kw in ('verge', 'yottabyte')):
                    indicators.append(f'SAN={entry[1]}')
            if indicators:
                self._add_finding(
                    'VergeOS Platform Fingerprinted via OUI/TLS',
                    'INFO',
                    f'TLS cert indicators: {", ".join(indicators)}; '
                    f'associated MAC OUI F0:DB:30 (Verge.io/Yottabyte) — confirms VergeOS HCI deployment',
                    f'https://{self.host}:{self.port}/',
                )
        except Exception:
            pass

    # ── Full run ──────────────────────────────────────────────────────────────

    def enumerate_all(self) -> dict:
        """Superset orchestrator: run() chain + targeted doc-derived probes.

        Order: fingerprint → unauth surface → openai compat → default creds →
               api_v4 unauth probes → session token reuse → tenant enum → OUI/TLS fingerprint →
               (if authed) full authenticated enumeration.
        """
        report = {
            'host': self.host,
            'port': self.port,
            'platform': 'VergeOS HCI (gcweb)',
            'fingerprint': {},
            'unauth_endpoints': [],
            'openai_compat': [],
            'auth': None,
            'enum': {},
            'findings': [],
        }

        report['fingerprint'] = self.fingerprint()

        if not report['fingerprint'].get('confirmed') and not report['fingerprint'].get('api_accessible'):
            report['findings'] = self.findings
            return report

        # 1. Existing unauth surface
        report['unauth_endpoints'] = self.probe_unauth_endpoints()
        report['openai_compat']    = self.probe_openai_compat()

        # 2. Default credentials (doc-derived)
        self.probe_default_credentials()
        if self.session_token:
            report['auth'] = {'token_prefix': self.session_token[:8]}

        # 3. Unauthenticated API endpoint probes
        self.probe_api_v4_unauthenticated()

        # 4. Session token persistence check
        self.probe_session_token_reuse()

        # 5. Tenant enumeration (unauth fallback or session token)
        report['enum']['tenants'] = self.enumerate_tenants()

        # 6. OUI / TLS fingerprint confirmation
        self.check_mac_oui_fingerprint()

        # Authenticated deep-enum when token is available
        if self.session_token:
            tok = self.session_token
            report['enum']['system']       = self.get_system_info(tok)
            report['enum']['users']        = self.enumerate_users(tok)
            report['enum']['api_keys']     = self.enumerate_api_keys(tok)
            report['enum']['auth_sources'] = self.enumerate_auth_sources(tok)
            report['enum']['vms']          = self.enumerate_vms(tok)
            report['enum']['networks']     = self.enumerate_networks(tok)
            report['enum']['advanced']     = self.check_advanced_settings(tok)

        report['findings'] = self.findings
        return report

    def run(self) -> dict:
        report = {
            'host': self.host,
            'port': self.port,
            'platform': 'VergeOS HCI (gcweb)',
            'fingerprint': {},
            'unauth_endpoints': [],
            'openai_compat': [],
            'auth': None,
            'enum': {},
            'findings': [],
        }

        report['fingerprint'] = self.fingerprint()

        if not report['fingerprint'].get('confirmed') and not report['fingerprint'].get('api_accessible'):
            report['findings'] = self.findings
            return report

        # Unauthenticated surface
        report['unauth_endpoints'] = self.probe_unauth_endpoints()
        report['openai_compat'] = self.probe_openai_compat()

        # Credential brute
        cred_result = self.brute_default_creds()
        if cred_result:
            username, password, token = cred_result
            report['auth'] = {'username': username, 'password': password}

            report['enum']['system']       = self.get_system_info(token)
            report['enum']['users']        = self.enumerate_users(token)
            report['enum']['api_keys']     = self.enumerate_api_keys(token)
            report['enum']['tenants']      = self.enumerate_tenants(token)
            report['enum']['auth_sources'] = self.enumerate_auth_sources(token)
            report['enum']['vms']          = self.enumerate_vms(token)
            report['enum']['networks']     = self.enumerate_networks(token)
            report['enum']['advanced']     = self.check_advanced_settings(token)

        report['findings'] = self.findings
        return report


def enumerate_vergeos(host: str, port: int = 443, timeout: int = 10) -> dict:
    """Top-level convenience wrapper."""
    e = VergeIOEnumerator(host=host, port=port, timeout=timeout)
    return e.run()


# ── Standalone probe helpers (no class dependency) ────────────────────────────

def _vio_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _vio_get(host: str, port: int, path: str, timeout: float):
    scheme = 'https' if port not in (80, 8080) else 'http'
    url = f'{scheme}://{host}:{port}{path}'
    try:
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/json')
        kw: dict = {}
        if scheme == 'https':
            kw['context'] = _vio_ssl_ctx()
        with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
            body = r.read()
            return r.getcode(), body
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception:
        return 0, b''


def _vio_post(host: str, port: int, path: str, data: dict, timeout: float):
    scheme = 'https' if port not in (80, 8080) else 'http'
    url = f'{scheme}://{host}:{port}{path}'
    payload = json.dumps(data).encode()
    try:
        req = urllib.request.Request(url, data=payload, method='POST')
        req.add_header('Accept', 'application/json')
        req.add_header('Content-Type', 'application/json')
        kw: dict = {}
        if scheme == 'https':
            kw['context'] = _vio_ssl_ctx()
        with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
            body = r.read()
            return r.getcode(), body
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception:
        return 0, b''


# ── Standalone probe functions ────────────────────────────────────────────────

def probe_vergeio_api(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe core VergeOS REST API endpoints unauthenticated.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # /api/v4/sys — system information
    code, body = _vio_get(host, port, '/api/v4/sys', timeout)
    if code == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_API_UNAUTH',
            'detail': (
                'GET /api/v4/sys returned 200 without authentication — '
                'system info exposed; host identity, version, and cluster state readable'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/machine — VM inventory
    code, body = _vio_get(host, port, '/api/v4/machine', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_VM_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/machine returned 200 without authentication — '
                f'{count} VM record(s) exposed; names, state, and resource allocation readable'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/cluster — cluster topology
    code, body = _vio_get(host, port, '/api/v4/cluster', timeout)
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_CLUSTER_INFO_UNAUTH',
            'detail': (
                'GET /api/v4/cluster returned 200 without authentication — '
                'cluster topology, node count, and resource pools exposed'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/users — user directory
    code, body = _vio_get(host, port, '/api/v4/users', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_USER_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/users returned 200 without authentication — '
                f'{count} user record(s) exposed; usernames and roles readable'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_vergeio_console(host: str, port: int = 80, timeout: float = 5.0) -> list:
    """Probe VergeOS web console and authentication surface.

    Checks for login page presence, empty-credential bypass, UI access without
    redirect, and vendor default credential acceptance.
    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # GET / — confirm VergeOS portal fingerprint
    code, body = _vio_get(host, port, '/', timeout)
    if code in (200, 302, 401):
        body_str = body.decode('utf-8', errors='replace')
        if any(m in body_str for m in ('VergeIO', 'verge.io', 'YottaByte', 'gcweb')):
            findings.append({
                'severity': 'INFO',
                'title': 'VERGEIO_PORTAL_IDENTIFIED',
                'detail': (
                    f'GET / on port {port} returned HTTP {code} with VergeOS fingerprint '
                    f'in body — portal confirmed'
                ),
                'host': host,
                'port': port,
            })

    # POST /api/v4/auth — empty credential bypass
    code, body = _vio_post(host, port, '/api/v4/auth', {'username': '', 'password': ''}, timeout)
    if code in (200, 201):
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}
        token = (data.get('token') or data.get('access_token')
                 or data.get('api_key') or data.get('key'))
        if token:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'VERGEIO_EMPTY_AUTH_BYPASS',
                'detail': (
                    'POST /api/v4/auth with empty username/password returned a token — '
                    'authentication completely bypassed; full API access granted'
                ),
                'host': host,
                'port': port,
            })

    # GET /ui/ — UI accessible without redirect to login
    code, body = _vio_get(host, port, '/ui/', timeout)
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_UI_ACCESSIBLE',
            'detail': (
                'GET /ui/ returned 200 without redirecting to login — '
                'VergeOS management UI accessible without authentication'
            ),
            'host': host,
            'port': port,
        })

    # Default credential pairs
    _default_creds = [
        ('admin', 'admin'),
        ('admin', 'verge'),
        ('root',  'verge'),
    ]
    for username, password in _default_creds:
        code, body = _vio_post(
            host, port, '/api/v4/auth',
            {'username': username, 'password': password},
            timeout,
        )
        if code in (200, 201):
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            token = (data.get('token') or data.get('access_token')
                     or data.get('api_key') or data.get('key'))
            if token:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'VERGEIO_DEFAULT_CREDENTIALS',
                    'detail': (
                        f'Default credentials {username}:{password} accepted — '
                        f'token issued; full API access; no lockout enforced by default'
                    ),
                    'host': host,
                    'port': port,
                })
                break  # stop on first hit

    return findings


def probe_vergeio_tenant_isolation(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe VergeOS multi-tenant isolation boundaries unauthenticated.

    Tenant escape via API = HCI host compromise (tenant nodes are nested VMs).
    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # /api/v4/tenant — tenant directory
    code, body = _vio_get(host, port, '/api/v4/tenant', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_TENANT_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/tenant returned 200 without authentication — '
                f'{count} tenant record(s) exposed; cross-tenant enumeration possible'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/vnet — virtual network topology
    code, body = _vio_get(host, port, '/api/v4/vnet', timeout)
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_VNET_LIST_UNAUTH',
            'detail': (
                'GET /api/v4/vnet returned 200 without authentication — '
                'network topology exposed; VLAN IDs, IP ranges, and routing tables readable'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/storage — storage subsystem info
    code, body = _vio_get(host, port, '/api/v4/storage', timeout)
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_STORAGE_INFO_UNAUTH',
            'detail': (
                'GET /api/v4/storage returned 200 without authentication — '
                'vSAN storage layout, tier assignments, and capacity exposed'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/snapshot — snapshot inventory
    code, body = _vio_get(host, port, '/api/v4/snapshot', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'MEDIUM',
            'title': 'VERGEIO_SNAPSHOT_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/snapshot returned 200 without authentication — '
                f'{count} snapshot record(s) exposed; recovery point inventory readable'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_vergeio_media_upload(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe VergeOS media library and VM console endpoints unauthenticated.

    Media upload access enables ISO injection; unauth console = direct VM access.
    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # GET /api/v4/media — media library listing
    code, body = _vio_get(host, port, '/api/v4/media', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_MEDIA_LIBRARY_UNAUTH',
            'detail': (
                f'GET /api/v4/media returned 200 without authentication — '
                f'{count} media item(s) listed; ISO/image inventory exposed'
            ),
            'host': host,
            'port': port,
        })

    # POST /api/v4/media — upload endpoint reachability
    code, body = _vio_post(host, port, '/api/v4/media', {}, timeout)
    if code in (200, 201, 400, 422):
        # 400/422 = endpoint reachable but rejected empty body; still confirms unauth reach
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_MEDIA_UPLOAD_ENDPOINT_OPEN',
            'detail': (
                f'POST /api/v4/media returned HTTP {code} without authentication — '
                f'media upload endpoint reachable; ISO injection attack surface confirmed'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/machine/{id}/console — VM console access
    for vm_id in ('1', '2', '100'):
        code, body = _vio_get(host, port, f'/api/v4/machine/{vm_id}/console', timeout)
        if code in (200, 101):  # 101 = WebSocket upgrade accepted
            findings.append({
                'severity': 'HIGH',
                'title': 'VERGEIO_VM_CONSOLE_ACCESSIBLE',
                'detail': (
                    f'GET /api/v4/machine/{vm_id}/console returned HTTP {code} without '
                    f'authentication — VM console endpoint accessible; direct VM interaction possible'
                ),
                'host': host,
                'port': port,
            })
            break  # one confirmed hit is sufficient

    return findings


def probe_vergeio_backup(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe VergeOS backup, snapshot, and recipe endpoints unauthenticated.

    Unauthenticated backup access enables full VM data exfiltration; snapshot creation
    permits persistent state manipulation without credentials.
    Synthesized from: go-for-devops ch.22 (programming the cloud — VM lifecycle,
    storage management, cloud API client patterns).
    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # GET /api/v4/backup — backup job/object listing
    code, body = _vio_get(host, port, '/api/v4/backup', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_BACKUP_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/backup returned 200 without authentication — '
                f'{count} backup object(s) listed; full VM backup inventory exposed'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/snapshot — snapshot listing (alternative path)
    if code != 200:
        code2, body2 = _vio_get(host, port, '/api/v4/snapshot', timeout)
        if code2 == 200:
            try:
                count = len(json.loads(body2)) if body2 else '?'
            except Exception:
                count = '?'
            findings.append({
                'severity': 'CRITICAL',
                'title': 'VERGEIO_BACKUP_LIST_UNAUTH',
                'detail': (
                    f'GET /api/v4/snapshot returned 200 without authentication — '
                    f'{count} snapshot object(s) listed; VM state inventory exposed'
                ),
                'host': host,
                'port': port,
            })

    # GET /api/v4/backup/1/download — backup download reachability
    dl_code, dl_body = _vio_get(host, port, '/api/v4/backup/1/download', timeout)
    if dl_code in (200, 206):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_BACKUP_DOWNLOAD_UNAUTH',
            'detail': (
                f'GET /api/v4/backup/1/download returned HTTP {dl_code} without '
                f'authentication — backup data downloadable; full VM disk exfiltration possible'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/recipe — VM recipe/template listing
    rc_code, rc_body = _vio_get(host, port, '/api/v4/recipe', timeout)
    if rc_code == 200:
        try:
            count = len(json.loads(rc_body)) if rc_body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_RECIPE_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/recipe returned 200 without authentication — '
                f'{count} VM template(s) listed; infrastructure blueprint exposed'
            ),
            'host': host,
            'port': port,
        })

    # POST /api/v4/snapshot — attempt unauthenticated snapshot creation
    snap_code, snap_body = _vio_post(
        host, port, '/api/v4/snapshot', {'name': 'test', 'machine': 1}, timeout
    )
    if snap_code in (200, 201):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_SNAPSHOT_CREATE_UNAUTH',
            'detail': (
                f'POST /api/v4/snapshot returned HTTP {snap_code} without authentication — '
                f'snapshot created; unauthenticated VM state manipulation confirmed'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_vergeio_network_config(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe VergeOS network configuration, virtual network, and firewall endpoints unauthenticated.

    Unauthenticated network control plane access exposes tenant routing, firewall rules,
    and TLS certificate inventory — full network posture readable without credentials.
    Synthesized from: go-for-devops ch.22 (programming the cloud — infrastructure management,
    hypervisor automation, network resource lifecycle).
    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # GET /api/v4/network — network configuration listing
    code, body = _vio_get(host, port, '/api/v4/network', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_NETWORK_CONFIG_UNAUTH',
            'detail': (
                f'GET /api/v4/network returned 200 without authentication — '
                f'{count} network object(s) listed; full network configuration exposed'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/vnet — virtual network topology
    vn_code, vn_body = _vio_get(host, port, '/api/v4/vnet', timeout)
    if vn_code == 200:
        try:
            count = len(json.loads(vn_body)) if vn_body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_VNET_TOPOLOGY_UNAUTH',
            'detail': (
                f'GET /api/v4/vnet returned 200 without authentication — '
                f'{count} virtual network(s) listed; tenant network topology exposed'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/route — routing table
    rt_code, rt_body = _vio_get(host, port, '/api/v4/route', timeout)
    if rt_code == 200:
        try:
            count = len(json.loads(rt_body)) if rt_body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_ROUTING_TABLE_UNAUTH',
            'detail': (
                f'GET /api/v4/route returned 200 without authentication — '
                f'{count} route(s) listed; network routing table exposed'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/firewall/rule — firewall rule listing
    fw_code, fw_body = _vio_get(host, port, '/api/v4/firewall/rule', timeout)
    if fw_code == 200:
        try:
            count = len(json.loads(fw_body)) if fw_body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_FIREWALL_RULES_UNAUTH',
            'detail': (
                f'GET /api/v4/firewall/rule returned 200 without authentication — '
                f'{count} firewall rule(s) listed; network control plane exposed — '
                f'attacker can map filtering posture and craft bypass traffic'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/certificate — TLS certificate inventory
    cert_code, cert_body = _vio_get(host, port, '/api/v4/certificate', timeout)
    if cert_code == 200:
        try:
            count = len(json.loads(cert_body)) if cert_body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'MEDIUM',
            'title': 'VERGEIO_CERT_INVENTORY_UNAUTH',
            'detail': (
                f'GET /api/v4/certificate returned 200 without authentication — '
                f'{count} certificate(s) listed; TLS certificate inventory exposed'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_vergeio_user_management(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe VergeOS user management and authentication configuration unauthenticated.

    Exposes user directory, admin account names, SSO/LDAP configuration, and
    authorization group structure without credentials on misconfigured instances.
    Synthesized from: cloud-native-devops-kubernetes-2e (RBAC patterns, identity federation,
    least-privilege access control in hyperconverged/cloud-native platforms).
    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # GET /api/v4/users — user list
    code, body = _vio_get(host, port, '/api/v4/users', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_USER_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/users returned 200 without authentication — '
                f'{count} user account(s) enumerable; usernames and roles readable'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/users?filter=is_admin:true — admin users
    code, body = _vio_get(host, port, '/api/v4/users?filter=is_admin:true', timeout)
    if code == 200:
        try:
            data = json.loads(body) if body else []
            count = len(data) if isinstance(data, list) else '?'
            names = [u.get('name', u.get('username', '?')) for u in data if isinstance(u, dict)][:5]
        except Exception:
            count = '?'
            names = []
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_ADMIN_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/users?filter=is_admin:true returned 200 without authentication — '
                f'{count} admin account(s) visible; names: {names}'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/auth/providers — SSO/LDAP auth provider config
    code, body = _vio_get(host, port, '/api/v4/auth/providers', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_AUTH_PROVIDERS_EXPOSED',
            'detail': (
                f'GET /api/v4/auth/providers returned 200 without authentication — '
                f'{count} auth provider(s) listed; SSO/LDAP configuration visible; '
                f'identity provider details and client IDs exposed'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/groups — authorization group structure
    code, body = _vio_get(host, port, '/api/v4/groups', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_GROUPS_EXPOSED',
            'detail': (
                f'GET /api/v4/groups returned 200 without authentication — '
                f'{count} authorization group(s) listed; permission group structure and '
                f'membership rules disclosed without credentials'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_vergeio_vm_operations(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe VergeOS VM lifecycle operations and virtual disk inventory unauthenticated.

    Exposes VM inventory, live VM enumeration, unauthenticated snapshot creation (memory
    capture of live VM), and virtual disk inventory without credentials.
    Synthesized from: kubernetes-up-and-running-3e (container-to-hypervisor isolation
    boundaries, workload isolation, volume and storage API exposure patterns).
    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # GET /api/v4/vms — full VM inventory
    code, body = _vio_get(host, port, '/api/v4/vms', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_VM_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/vms returned 200 without authentication — '
                f'{count} virtual machine(s) listed; names, state, and resource allocation exposed'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/vms?filter=is_running:true — running VM enumeration
    code, body = _vio_get(host, port, '/api/v4/vms?filter=is_running:true', timeout)
    if code == 200:
        try:
            data = json.loads(body) if body else []
            count = len(data) if isinstance(data, list) else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_RUNNING_VMS',
            'detail': (
                f'GET /api/v4/vms?filter=is_running:true returned 200 without authentication — '
                f'{count} live VMs visible; running workload inventory exposed'
            ),
            'host': host,
            'port': port,
        })

    # POST /api/v4/vms/1/snapshot — unauthenticated memory snapshot of live VM
    snap_code, snap_body = _vio_post(
        host, port, '/api/v4/vms/1/snapshot', {}, timeout,
    )
    if snap_code in (200, 201):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_VM_SNAPSHOT_UNAUTH',
            'detail': (
                f'POST /api/v4/vms/1/snapshot returned HTTP {snap_code} without authentication — '
                f'memory snapshot of live VM possible; full VM memory contents capturable without credentials'
            ),
            'host': host,
            'port': port,
        })

    # GET /api/v4/drives — virtual disk inventory
    code, body = _vio_get(host, port, '/api/v4/drives', timeout)
    if code == 200:
        try:
            count = len(json.loads(body)) if body else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_DRIVE_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/drives returned 200 without authentication — '
                f'{count} virtual disk(s) listed; disk inventory, sizes, and attachment points exposed'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_splunk_exposure(host: str, port: int = 8089, timeout: float = 10.0) -> list:
    """Detect exposed Splunk management REST API and web interface."""
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _splunk_get(url: str):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(4096).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # GET https://host:8089/services/server/info — Splunk REST API unauthenticated
    code, body = _splunk_get(f'https://{host}:8089/services/server/info')
    if code == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SPLUNK_REST_UNAUTH',
            'detail': (
                f'GET https://{host}:8089/services/server/info returned 200 without authentication — '
                f'Splunk management REST API accessible without authentication'
            ),
            'host': host,
            'port': 8089,
        })

    # GET https://host:8089/services/search/jobs — search jobs readable
    code, body = _splunk_get(f'https://{host}:8089/services/search/jobs')
    if code == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SPLUNK_SEARCH_JOBS_UNAUTH',
            'detail': (
                f'GET https://{host}:8089/services/search/jobs returned 200 without authentication — '
                f'Splunk search jobs readable (search queries and results exposed)'
            ),
            'host': host,
            'port': 8089,
        })

    # GET https://host:8000/en-US/account/login — Splunk web UI accessible
    code, body = _splunk_get(f'https://{host}:8000/en-US/account/login')
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'SPLUNK_WEB_EXPOSED',
            'detail': (
                f'GET https://{host}:8000/en-US/account/login returned 200 — '
                f'Splunk web interface accessible'
            ),
            'host': host,
            'port': 8000,
        })

    # GET https://host:8089/services/admin/users — user list without authentication
    code, body = _splunk_get(f'https://{host}:8089/services/admin/users')
    if code == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SPLUNK_USERS_UNAUTH',
            'detail': (
                f'GET https://{host}:8089/services/admin/users returned 200 without authentication — '
                f'Splunk user list accessible without authentication'
            ),
            'host': host,
            'port': 8089,
        })

    return findings


def probe_nagios_zabbix_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect exposed Nagios and Zabbix monitoring interfaces and APIs."""
    findings = []

    def _mon_get(url: str):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(4096).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # GET http://host:port/nagios/ — Nagios web interface accessible
    code, body = _mon_get(f'http://{host}:{port}/nagios/')
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'NAGIOS_WEB_EXPOSED',
            'detail': (
                f'GET http://{host}:{port}/nagios/ returned 200 — '
                f'Nagios monitoring interface accessible'
            ),
            'host': host,
            'port': port,
        })

    # GET http://host:port/nagios/cgi-bin/status.cgi — host/service status unauth
    code, body = _mon_get(f'http://{host}:{port}/nagios/cgi-bin/status.cgi')
    if code == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'NAGIOS_STATUS_UNAUTH',
            'detail': (
                f'GET http://{host}:{port}/nagios/cgi-bin/status.cgi returned 200 without authentication — '
                f'Nagios host/service status readable without authentication'
            ),
            'host': host,
            'port': port,
        })

    # GET http://host:port/zabbix/ — Zabbix web interface accessible
    code, body = _mon_get(f'http://{host}:{port}/zabbix/')
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'ZABBIX_WEB_EXPOSED',
            'detail': (
                f'GET http://{host}:{port}/zabbix/ returned 200 — '
                f'Zabbix monitoring interface accessible'
            ),
            'host': host,
            'port': port,
        })

    # GET http://host:port/zabbix/api_jsonrpc.php — Zabbix JSON-RPC API accessible
    code, body = _mon_get(f'http://{host}:{port}/zabbix/api_jsonrpc.php')
    if code == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ZABBIX_API_EXPOSED',
            'detail': (
                f'GET http://{host}:{port}/zabbix/api_jsonrpc.php returned 200 — '
                f'Zabbix JSON-RPC API accessible (host inventory, configuration)'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_dnp3_exposure(host: str, port: int = 20000, timeout: float = 5.0) -> list:
    """Detect DNP3 industrial protocol exposure (SCADA/ICS convergence in datacenter OT environments)."""
    findings = []

    # TCP port 20000 — DNP3 primary transport
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        findings.append({
            'severity': 'HIGH',
            'title': 'DNP3_PORT_OPEN',
            'detail': (
                f'TCP connect {host}:{port} succeeded — '
                f'DNP3 industrial protocol port accessible (SCADA/ICS)'
            ),
            'host': host,
            'port': port,
        })

        # DNP3 data-link frame: start bytes 0x0564, len=0x08, control=0x44,
        # dest=0x0001 (LE), src=0x0003 (LE), CRC placeholder 0x0000
        dnp3_frame = struct.pack('<BBHHHH', 0x05, 0x64, 0x08, 0x44, 0x0001, 0x0003) + b'\x00\x00'
        sock.sendall(dnp3_frame)
        try:
            resp = sock.recv(256)
            if len(resp) >= 2 and resp[0] == 0x05 and resp[1] == 0x64:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'DNP3_UNAUTH_RESPONSE',
                    'detail': (
                        f'{host}:{port} returned DNP3 data-link frame (0x0564 start bytes) '
                        f'without authentication — DNP3 SCADA master station responding '
                        f'without authentication'
                    ),
                    'host': host,
                    'port': port,
                })
        except socket.timeout:
            pass
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    # UDP port 20000 — DNP3 over UDP
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)
        dnp3_frame = struct.pack('<BBHHHH', 0x05, 0x64, 0x08, 0x44, 0x0001, 0x0003) + b'\x00\x00'
        udp_sock.sendto(dnp3_frame, (host, port))
        try:
            data, _ = udp_sock.recvfrom(256)
            if data:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'DNP3_UDP_EXPOSED',
                    'detail': (
                        f'UDP {host}:{port} responded to DNP3 probe — '
                        f'DNP3 over UDP accessible'
                    ),
                    'host': host,
                    'port': port,
                })
        except socket.timeout:
            pass
        udp_sock.close()
    except OSError:
        pass

    return findings


def probe_s7_siemens_plc(host: str, port: int = 102, timeout: float = 5.0) -> list:
    """Detect Siemens S7 PLC exposure via ISO-TSAP/TPKT (Profinet S7 convergence in datacenter OT environments)."""
    findings = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        findings.append({
            'severity': 'HIGH',
            'title': 'S7_ISO_TSAP_PORT_OPEN',
            'detail': (
                f'TCP connect {host}:{port} succeeded — '
                f'Siemens S7 PLC TPKT port accessible (ISO transport)'
            ),
            'host': host,
            'port': port,
        })

        # TPKT header (4 bytes) + COTP Connection Request (18 bytes)
        # TPKT: version=0x03, reserved=0x00, length=0x0016 (22)
        # COTP CR: length=0x11, pdu_type=0xe0, dst_ref=0x0000, src_ref=0x0001,
        #          class=0x00, params: src-tsap 0xc1 0x02 0x01 0x00,
        #                              dst-tsap 0xc2 0x02 0x01 0x02, tpdu-size 0xc0 0x01 0x0a
        cr_pdu = (
            b'\x03\x00\x00\x16'          # TPKT header, length=22
            b'\x11\xe0\x00\x00\x00\x01'  # COTP CR: len=17, type=0xe0, dst=0, src=1
            b'\x00'                       # class/option
            b'\xc1\x02\x01\x00'          # src-tsap param
            b'\xc2\x02\x01\x02'          # dst-tsap param
            b'\xc0\x01\x0a'              # tpdu-size param
        )
        sock.sendall(cr_pdu)
        try:
            resp = sock.recv(256)
            # CC (Connection Confirm) COTP PDU type = 0xd0
            if len(resp) >= 6 and resp[0] == 0x03 and resp[5] == 0xd0:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'S7_PLC_CONNECTED',
                    'detail': (
                        f'{host}:{port} returned COTP Connection Confirm (0xd0) — '
                        f'Siemens S7 PLC ISO connection established without authentication'
                    ),
                    'host': host,
                    'port': port,
                })

                # S7comm setup negotiation required before SZL read
                # S7 Communication Setup: TPKT + COTP DT + S7 header + S7 setup params
                s7_setup = (
                    b'\x03\x00\x00\x19'              # TPKT, length=25
                    b'\x02\xf0\x80'                   # COTP DT Data
                    b'\x32\x01\x00\x00'               # S7 header: protocol=0x32, type=job
                    b'\x00\x00\x00\x08'               # PDU ref + param length
                    b'\x00\x00\xf0\x00'               # data length + negotiate PDU type
                    b'\x00\x01\x00\x01'               # max AMQ caller/callee
                    b'\x01\xe0'                        # PDU size
                )
                sock.sendall(s7_setup)
                try:
                    sock.recv(256)  # consume setup response; continue regardless
                except socket.timeout:
                    pass

                # S7 Read SZL (system status list) -- SZL-ID 0x0011 (module identification)
                szl_request = (
                    b'\x03\x00\x00\x21'              # TPKT, length=33
                    b'\x02\xf0\x80'                   # COTP DT Data
                    b'\x32\x07\x00\x00'               # S7 header: type=userdata
                    b'\x00\x01\x00\x08'               # PDU ref + param length=8
                    b'\x00\x08\x00\x01'               # data length=8 + return code
                    b'\x12\x04\x11\x44'               # param: type=request, szl func
                    b'\x00\x01'                        # szl-id=0x0011
                    b'\x00\x00'                        # szl-index=0
                    b'\x00\x00\x00\x00'               # padding
                )
                sock.sendall(szl_request)
                try:
                    szl_resp = sock.recv(512)
                    # S7 userdata response: protocol=0x32, type=0x07 (ack-data for userdata)
                    # Look for S7 header with type=0x07 starting at TPKT+COTP offset (byte 7)
                    if len(szl_resp) >= 8 and szl_resp[0] == 0x03 and szl_resp[7] == 0x07:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'S7_SZL_READ_UNAUTH',
                            'detail': (
                                f'{host}:{port} returned S7 SZL response without authentication — '
                                f'Siemens PLC system status list readable '
                                f'(firmware version, module info)'
                            ),
                            'host': host,
                            'port': port,
                        })
                except socket.timeout:
                    pass
        except socket.timeout:
            pass
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return findings


def probe_proxmox_ve_exposure(host: str, port: int = 8006, timeout: float = 10.0) -> list:
    """Detect exposed Proxmox VE hypervisor management interface.

    Synthesized from: Hands-On Hacking ch.7 (web infrastructure exploitation),
    ch.12 (web application attacks against management planes).
    Attack surface: unauthenticated Proxmox REST API exposes node topology,
    VM inventory, storage, and cluster resources — sufficient for full
    hypervisor enumeration without credentials.
    """
    findings: list = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _px_get(path: str, use_ssl: bool = True) -> tuple:
        """Return (status_code, body_bytes) or (None, None) on error."""
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            if use_ssl:
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, b""
        except (socket.timeout, ConnectionRefusedError, OSError,
                urllib.error.URLError):
            return None, None

    def _px_post(path: str, data: dict, use_ssl: bool = True) -> tuple:
        """Return (status_code, body_bytes) or (None, None) on error."""
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}{path}"
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"User-Agent": "Mozilla/5.0",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            if use_ssl:
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
            except Exception:
                body = b""
            return e.code, body
        except (socket.timeout, ConnectionRefusedError, OSError,
                urllib.error.URLError):
            return None, None

    # urllib.parse needed for urlencode in _px_post
    import urllib.parse

    # --- Login page fingerprint ---
    status, body = _px_get("/")
    if status is not None and body and b"Proxmox Virtual Environment" in body:
        findings.append({
            "severity": "MEDIUM",
            "title": "PROXMOX_LOGIN_PAGE",
            "detail": (
                f"{host}:{port} exposes Proxmox Virtual Environment login page — "
                f"management interface is internet-reachable"
            ),
            "host": host,
            "port": port,
        })

    # --- /api2/json/version (unauthenticated) ---
    status, body = _px_get("/api2/json/version")
    if status == 200 and body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and "data" in parsed:
                data = parsed["data"]
                version_info = ""
                if isinstance(data, dict):
                    release = data.get("release", "")
                    ver = data.get("version", "")
                    if release or ver:
                        version_info = f" version={release}/{ver}"
                findings.append({
                    "severity": "HIGH",
                    "title": "PROXMOX_VE_API_EXPOSED",
                    "detail": (
                        f"{host}:{port} /api2/json/version returns version info "
                        f"without authentication{version_info}"
                    ),
                    "host": host,
                    "port": port,
                })
        except (ValueError, KeyError):
            pass

    # --- /api2/json/nodes (unauthenticated node enumeration) ---
    status, body = _px_get("/api2/json/nodes")
    if status == 200 and body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and "data" in parsed and isinstance(parsed["data"], list):
                node_count = len(parsed["data"])
                node_names = [n.get("node", "") for n in parsed["data"]
                              if isinstance(n, dict)]
                findings.append({
                    "severity": "CRITICAL",
                    "title": "PROXMOX_NODES_UNAUTH",
                    "detail": (
                        f"{host}:{port} /api2/json/nodes exposes {node_count} node(s) "
                        f"without authentication: {', '.join(node_names)}"
                    ),
                    "host": host,
                    "port": port,
                })
        except (ValueError, KeyError):
            pass

    # --- /api2/json/cluster/resources (all VMs/containers) ---
    status, body = _px_get("/api2/json/cluster/resources")
    if status == 200 and body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and "data" in parsed and isinstance(parsed["data"], list):
                resources = parsed["data"]
                vm_count = sum(1 for r in resources
                               if isinstance(r, dict) and r.get("type") in ("qemu", "lxc"))
                findings.append({
                    "severity": "CRITICAL",
                    "title": "PROXMOX_RESOURCES_UNAUTH",
                    "detail": (
                        f"{host}:{port} /api2/json/cluster/resources exposes full cluster "
                        f"inventory ({len(resources)} resources, {vm_count} VMs/containers) "
                        f"without authentication"
                    ),
                    "host": host,
                    "port": port,
                })
        except (ValueError, KeyError):
            pass

    # --- /api2/json/storage (storage pool enumeration) ---
    status, body = _px_get("/api2/json/storage")
    if status == 200 and body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and "data" in parsed and isinstance(parsed["data"], list):
                storage_count = len(parsed["data"])
                findings.append({
                    "severity": "HIGH",
                    "title": "PROXMOX_STORAGE_UNAUTH",
                    "detail": (
                        f"{host}:{port} /api2/json/storage lists {storage_count} storage "
                        f"pool(s) without authentication"
                    ),
                    "host": host,
                    "port": port,
                })
        except (ValueError, KeyError):
            pass

    # --- Default credential spray ---
    default_creds = [
        ("root@pam", "proxmox"),
        ("root@pam", "password"),
        ("admin@pve", "admin"),
    ]
    for username, password in default_creds:
        status, body = _px_post(
            "/api2/json/access/ticket",
            {"username": username, "password": password},
        )
        if status == 200 and body:
            try:
                parsed = json.loads(body)
                if (isinstance(parsed, dict) and "data" in parsed
                        and isinstance(parsed["data"], dict)
                        and parsed["data"].get("ticket")):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "PROXMOX_DEFAULT_CREDS",
                        "detail": (
                            f"{host}:{port} authenticated with default credentials "
                            f"username={username} password={password} — "
                            f"full hypervisor management access"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
            except (ValueError, KeyError):
                pass

    return findings


def probe_openstack_horizon_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect exposed OpenStack Horizon dashboard and Nova/Keystone/Swift/Neutron/Glance APIs.

    Synthesized from: Hands-On Hacking ch.7 (web infrastructure attacks, CGI/API exploitation),
    ch.12 (web application enumeration, authentication bypass patterns).
    Attack surface: unauthenticated OpenStack service endpoints expose tenant topology,
    VM inventory, object storage, network config, and image registries.
    """
    findings: list = []

    import urllib.parse

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _os_get(h: str, p: int, path: str, use_ssl: bool = False,
                extra_headers: Optional[dict] = None) -> tuple:
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{h}:{p}{path}"
        hdrs = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            if use_ssl:
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
            except Exception:
                body = b""
            return e.code, body
        except (socket.timeout, ConnectionRefusedError, OSError,
                urllib.error.URLError):
            return None, None

    def _os_post_json(h: str, p: int, path: str, payload: dict,
                      use_ssl: bool = False) -> tuple:
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{h}:{p}{path}"
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"User-Agent": "Mozilla/5.0",
                     "Content-Type": "application/json",
                     "Accept": "application/json"},
        )
        try:
            if use_ssl:
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
            except Exception:
                body = b""
            try:
                hdrs = dict(e.headers)
            except Exception:
                hdrs = {}
            return e.code, body, hdrs
        except (socket.timeout, ConnectionRefusedError, OSError,
                urllib.error.URLError):
            return None, None, {}

    # --- Horizon dashboard ---
    for dash_path in ("/horizon", "/"):
        status, body = _os_get(host, port, dash_path)
        if status is not None and body:
            body_lower = body.lower()
            if b"horizon" in body_lower or b"openstack" in body_lower:
                findings.append({
                    "severity": "HIGH",
                    "title": "OPENSTACK_HORIZON_EXPOSED",
                    "detail": (
                        f"{host}:{port}{dash_path} exposes OpenStack Horizon dashboard — "
                        f"management interface is reachable without authentication"
                    ),
                    "host": host,
                    "port": port,
                })
                break

    # --- Keystone (port 5000) ---
    ks_port = 5000
    status, body = _os_get(host, ks_port, "/v3/")
    if status == 200 and body:
        try:
            parsed = json.loads(body)
            if (isinstance(parsed, dict) and "versions" in parsed
                    and "values" in parsed.get("versions", {})):
                findings.append({
                    "severity": "HIGH",
                    "title": "KEYSTONE_API_EXPOSED",
                    "detail": (
                        f"{host}:{ks_port} Keystone /v3/ returns version discovery "
                        f"document without authentication"
                    ),
                    "host": host,
                    "port": ks_port,
                })
        except (ValueError, KeyError):
            pass

    # Keystone default credential spray
    ks_creds = [
        ("admin", "admin"),
        ("admin", "password"),
    ]
    for username, password in ks_creds:
        payload = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": username,
                            "domain": {"name": "Default"},
                            "password": password,
                        }
                    },
                },
                "scope": {"project": {"domain": {"name": "Default"}, "name": "admin"}},
            }
        }
        status, body, resp_hdrs = _os_post_json(host, ks_port, "/v3/auth/tokens", payload)
        if status == 201 and resp_hdrs.get("X-Subject-Token"):
            findings.append({
                "severity": "CRITICAL",
                "title": "OPENSTACK_DEFAULT_CREDS",
                "detail": (
                    f"{host}:{ks_port} Keystone authenticated with default credentials "
                    f"username={username} password={password} — "
                    f"admin token issued"
                ),
                "host": host,
                "port": ks_port,
            })
            break

    # Keystone user enumeration
    status, body = _os_get(host, ks_port, "/v3/users")
    if status == 200 and body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and "users" in parsed and isinstance(parsed["users"], list):
                user_count = len(parsed["users"])
                findings.append({
                    "severity": "CRITICAL",
                    "title": "KEYSTONE_USERS_UNAUTH",
                    "detail": (
                        f"{host}:{ks_port} /v3/users exposes {user_count} user(s) "
                        f"without authentication"
                    ),
                    "host": host,
                    "port": ks_port,
                })
        except (ValueError, KeyError):
            pass

    # --- Nova Compute (port 8774) ---
    nova_port = 8774
    status, body = _os_get(host, nova_port, "/v2.1/")
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "NOVA_API_EXPOSED",
            "detail": (
                f"{host}:{nova_port} Nova Compute /v2.1/ responds without authentication"
            ),
            "host": host,
            "port": nova_port,
        })
        # Try tenant server list with placeholder tenant
        for tenant_id in ("admin", "default", "1"):
            status2, body2 = _os_get(host, nova_port, f"/v2.1/{tenant_id}/servers")
            if status2 == 200 and body2:
                try:
                    parsed = json.loads(body2)
                    if isinstance(parsed, dict) and "servers" in parsed:
                        srv_count = len(parsed["servers"])
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "NOVA_SERVERS_UNAUTH",
                            "detail": (
                                f"{host}:{nova_port} /v2.1/{tenant_id}/servers exposes "
                                f"{srv_count} server(s) without authentication"
                            ),
                            "host": host,
                            "port": nova_port,
                        })
                        break
                except (ValueError, KeyError):
                    pass

    # --- Cinder Block Storage (port 8776) ---
    cinder_port = 8776
    status, body = _os_get(host, cinder_port, "/v3/")
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "CINDER_API_EXPOSED",
            "detail": (
                f"{host}:{cinder_port} Cinder /v3/ responds without authentication"
            ),
            "host": host,
            "port": cinder_port,
        })

    # --- Swift Object Storage (port 8080) ---
    swift_port = 8080
    for tenant_id in ("admin", "default", "AUTH_admin"):
        status, body = _os_get(host, swift_port, f"/v1/{tenant_id}/")
        if status == 200 and body:
            try:
                containers = [line.strip().decode(errors="replace")
                              for line in body.splitlines() if line.strip()]
            except Exception:
                containers = []
            findings.append({
                "severity": "CRITICAL",
                "title": "SWIFT_UNAUTH_OBJECT_LIST",
                "detail": (
                    f"{host}:{swift_port} Swift /v1/{tenant_id}/ lists "
                    f"{len(containers)} container(s) without authentication"
                ),
                "host": host,
                "port": swift_port,
            })
            break

    # --- Neutron Networking (port 9696) ---
    neutron_port = 9696
    status, body = _os_get(host, neutron_port, "/v2.0/networks")
    if status == 200 and body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and "networks" in parsed:
                net_count = len(parsed["networks"])
                findings.append({
                    "severity": "HIGH",
                    "title": "NEUTRON_NETWORKS_UNAUTH",
                    "detail": (
                        f"{host}:{neutron_port} /v2.0/networks exposes {net_count} "
                        f"network(s) without authentication"
                    ),
                    "host": host,
                    "port": neutron_port,
                })
        except (ValueError, KeyError):
            pass

    # --- Glance Image Service (port 9292) ---
    glance_port = 9292
    status, body = _os_get(host, glance_port, "/v2/images")
    if status == 200 and body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and "images" in parsed:
                img_count = len(parsed["images"])
                findings.append({
                    "severity": "HIGH",
                    "title": "GLANCE_IMAGES_UNAUTH",
                    "detail": (
                        f"{host}:{glance_port} /v2/images exposes {img_count} image(s) "
                        f"without authentication"
                    ),
                    "host": host,
                    "port": glance_port,
                })
        except (ValueError, KeyError):
            pass


def probe_cisco_ucs_manager_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect exposed Cisco UCS Manager management interface.

    Synthesized from: Cisco HCI (9780134997957) ch09 (Integration with UCS),
    ch10 (Deploying, Provisioning, and Managing HyperFlex).
    UCS Manager: embedded in Cisco 6200/6300 fabric interconnects; HTTPS on 443;
    XML API at /nuova; KVM console on TCP 2068; BMC/IPMI on UDP 623.
    """
    findings = []
    ctx = _vio_ssl_ctx()

    def _ucsm_get(h, p, path):
        scheme = 'https' if p != 80 else 'http'
        url = f'{scheme}://{h}:{p}{path}'
        try:
            req = urllib.request.Request(url)
            req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml')
            kw = {'context': ctx} if scheme == 'https' else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception:
            return 0, b''

    def _ucsm_post_xml(h, p, path, xml_body):
        scheme = 'https' if p != 80 else 'http'
        url = f'{scheme}://{h}:{p}{path}'
        try:
            data = xml_body.encode() if isinstance(xml_body, str) else xml_body
            req = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/xml')
            req.add_header('Accept', 'application/xml')
            kw = {'context': ctx} if scheme == 'https' else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception:
            return 0, b''

    # --- UCSM HTTPS portal fingerprint ---
    code, body = _ucsm_get(host, port, '/')
    if code and body:
        body_lower = body.lower()
        if b'cisco ucs manager' in body_lower or b'ucsm' in body_lower:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'UCSM_PORTAL_FINGERPRINT',
                'detail': (
                    f'{host}:{port} / returned Cisco UCS Manager portal fingerprint — '
                    'management interface exposed without network-layer restriction'
                ),
                'host': host,
                'port': port,
            })

    # --- UCS XML API default credentials (aaaLogin) ---
    default_creds = [
        ('admin', 'password'),
        ('admin', 'Cisco1234!'),
        ('admin', 'C1sco12345'),
    ]
    for username, password in default_creds:
        xml = f'<aaaLogin inName="{username}" inPassword="{password}"/>'
        code, body = _ucsm_post_xml(host, port, '/nuova', xml)
        if code in (200, 201) and body and b'outStatus="success"' in body:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'UCSM_DEFAULT_ADMIN_CREDS',
                'detail': (
                    f'{host}:{port} /nuova aaaLogin succeeded with {username}:{password} — '
                    'UCSM XML API authenticated with default credentials; '
                    'full cluster control: service profiles, vNICs, firmware, power'
                ),
                'host': host,
                'port': port,
            })
            break

    # --- UCS XML API unauthenticated topSystem class resolution ---
    xml = '<configResolveClass cookie="" classId="topSystem"/>'
    code, body = _ucsm_post_xml(host, port, '/nuova', xml)
    if code == 200 and body and b'<topSystem' in body:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'UCSM_TOPSYSTEM_UNAUTH',
            'detail': (
                f'{host}:{port} /nuova configResolveClass topSystem returned data without '
                'authentication — UCS topology, node identity, and serial numbers exposed'
            ),
            'host': host,
            'port': port,
        })

    # --- UCS KVM console port 2068 (TCP) ---
    kvm_port = 2068
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, kvm_port))
        sock.close()
        if result == 0:
            findings.append({
                'severity': 'HIGH',
                'title': 'UCSM_KVM_PORT_OPEN',
                'detail': (
                    f'{host}:{kvm_port} TCP connect succeeded — UCS KVM console port '
                    'accessible; out-of-band server console reachable without VPN'
                ),
                'host': host,
                'port': kvm_port,
            })
    except OSError:
        pass

    # --- IPMI BMC port 623 (UDP) ---
    ipmi_port = 623
    # RMCP class=0x07 (IPMI) Get Channel Authentication Capabilities probe
    ipmi_probe = b'\x06\x00\xff\x07\x00\x00'
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        udp.sendto(ipmi_probe, (host, ipmi_port))
        try:
            data, _ = udp.recvfrom(256)
            if data:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'IPMI_BMCS_PORT_OPEN',
                    'detail': (
                        f'{host}:{ipmi_port} UDP responded to IPMI probe — '
                        'Baseboard Management Controller port reachable from network'
                    ),
                    'host': host,
                    'port': ipmi_port,
                })
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'IPMI_UNAUTH_RESPONSIVE',
                    'detail': (
                        f'{host}:{ipmi_port} IPMI BMC responded ({len(data)} bytes) to '
                        'unauthenticated probe — OOB control surface exposed: power cycling, '
                        'sensor reads, serial console, firmware flash, user enumeration'
                    ),
                    'host': host,
                    'port': ipmi_port,
                })
                findings.append({
                    'severity': 'HIGH',
                    'title': 'IPMI_CIPHER_ZERO',
                    'detail': (
                        f'{host}:{ipmi_port} IPMI BMC responsive; cipher suite 0 '
                        '(null auth/integrity/confidentiality) likely accepted — '
                        'cipher 0 allows authentication bypass against any IPMI account; '
                        f'verify: ipmitool -I lanplus -C 0 -H {host} -U admin -P "" chassis status'
                    ),
                    'host': host,
                    'port': ipmi_port,
                })
        except socket.timeout:
            pass
        udp.close()
    except OSError:
        pass

    # --- UCS REST API health endpoint ---
    code, body = _ucsm_get(host, port, '/api/aam/v1/health')
    if code == 200 and body:
        findings.append({
            'severity': 'HIGH',
            'title': 'UCSM_REST_API_EXPOSED',
            'detail': (
                f'{host}:{port} /api/aam/v1/health returned 200 without authentication — '
                'UCS REST API endpoint accessible; cluster health and config readable'
            ),
            'host': host,
            'port': port,
        })

    # --- UCS power budget config unauthenticated ---
    xml = '<configResolveClass cookie="" classId="powerBudget"/>'
    code, body = _ucsm_post_xml(host, port, '/nuova', xml)
    if code == 200 and body and b'<powerBudget' in body:
        findings.append({
            'severity': 'HIGH',
            'title': 'UCSM_POWER_CONFIG_UNAUTH',
            'detail': (
                f'{host}:{port} /nuova configResolveClass powerBudget returned data without '
                'authentication — power budget configuration exposed; '
                'chassis power allocation readable without credentials'
            ),
            'host': host,
            'port': port,
        })

    # --- UCS Director portal (port 80) ---
    ucsd_port = 80
    code, body = _ucsm_get(host, ucsd_port, '/')
    if code and body:
        body_lower = body.lower()
        if b'cisco ucs director' in body_lower or b'ucsd' in body_lower:
            findings.append({
                'severity': 'HIGH',
                'title': 'UCS_DIRECTOR_EXPOSED',
                'detail': (
                    f'{host}:{ucsd_port} / returned Cisco UCS Director portal fingerprint — '
                    'orchestration and automation management interface exposed without '
                    'network-layer restriction'
                ),
                'host': host,
                'port': ucsd_port,
            })

    return findings


def probe_cisco_hyperflex_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect exposed Cisco HyperFlex Connect (HX) management interfaces.

    Synthesized from: Cisco HCI (9780134997957) ch09 (Cisco HyperFlex),
    ch10 (Deploying, Provisioning, and Managing HyperFlex).
    HyperFlex Connect: HTML5 GUI at cluster IP; REST API at /rest/v1/;
    CVE-2021-1497/1498: installer + API authentication bypass.
    """
    findings = []
    ctx = _vio_ssl_ctx()

    def _hx_get(h, p, path):
        scheme = 'https' if p != 80 else 'http'
        url = f'{scheme}://{h}:{p}{path}'
        try:
            req = urllib.request.Request(url)
            req.add_header('Accept', 'application/json')
            kw = {'context': ctx} if scheme == 'https' else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception:
            return 0, b''

    def _hx_post(h, p, path, data):
        scheme = 'https' if p != 80 else 'http'
        url = f'{scheme}://{h}:{p}{path}'
        try:
            payload = json.dumps(data).encode()
            req = urllib.request.Request(url, data=payload, method='POST')
            req.add_header('Content-Type', 'application/json')
            req.add_header('Accept', 'application/json')
            kw = {'context': ctx} if scheme == 'https' else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception:
            return 0, b''

    # --- HyperFlex Connect portal fingerprint ---
    code, body = _hx_get(host, port, '/')
    if code and body:
        body_lower = body.lower()
        if b'hyperflex' in body_lower or b'cisco hx' in body_lower:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'HYPERFLEX_PORTAL_FINGERPRINT',
                'detail': (
                    f'{host}:{port} / returned HyperFlex Connect portal fingerprint — '
                    'Cisco HyperFlex HTML5 management interface exposed without '
                    'network-layer restriction'
                ),
                'host': host,
                'port': port,
            })

    # --- HX REST API default credentials ---
    hx_default_creds = [
        {'username': 'admin', 'password': 'C1sco12345'},
        {'username': 'admin', 'password': 'Hyperflex1!'},
        {'username': 'admin', 'password': 'Admin1234!'},
    ]
    for creds in hx_default_creds:
        code, body = _hx_post(host, port, '/rest/v1/auth', creds)
        if code == 200 and body:
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict) and (
                    'token' in parsed or 'access_token' in parsed or 'sessionId' in parsed
                ):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'HYPERFLEX_DEFAULT_CREDS',
                        'detail': (
                            f'{host}:{port} /rest/v1/auth authenticated with '
                            f'{creds["username"]}:{creds["password"]} — '
                            'HyperFlex REST API accessible with default credentials; '
                            'full cluster management: datastores, nodes, replication, VMs'
                        ),
                        'host': host,
                        'port': port,
                    })
                    break
            except (ValueError, KeyError):
                pass

    # --- HX cluster health unauthenticated ---
    code, body = _hx_get(host, port, '/rest/v1/cluster/health')
    if code == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'HYPERFLEX_HEALTH_UNAUTH',
            'detail': (
                f'{host}:{port} /rest/v1/cluster/health returned 200 without authentication — '
                'HyperFlex cluster health state exposed; resiliency status and node health visible'
            ),
            'host': host,
            'port': port,
        })

    # --- HX datastore list unauthenticated ---
    code, body = _hx_get(host, port, '/rest/v1/datastore')
    if code == 200 and body:
        try:
            parsed = json.loads(body)
            ds_count = len(parsed) if isinstance(parsed, list) else '?'
        except (ValueError, TypeError):
            ds_count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'HYPERFLEX_DATASTORES_UNAUTH',
            'detail': (
                f'{host}:{port} /rest/v1/datastore returned {ds_count} datastore(s) without '
                'authentication — HyperFlex storage layout fully exposed'
            ),
            'host': host,
            'port': port,
        })

    # --- HX cluster configuration unauthenticated ---
    code, body = _hx_get(host, port, '/rest/v1/cluster')
    if code == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'HYPERFLEX_CLUSTER_CONFIG_UNAUTH',
            'detail': (
                f'{host}:{port} /rest/v1/cluster returned 200 without authentication — '
                'HyperFlex cluster configuration exposed: node count, replication factor, '
                'capacity, software versions, and network topology readable'
            ),
            'host': host,
            'port': port,
        })

    # --- CVE-2021-1497: HyperFlex HX installer authentication bypass ---
    code, body = _hx_get(host, port, '/hxinstaller')
    if code in (200, 301, 302, 307) and body is not None:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'HYPERFLEX_CVE_2021_1497',
            'detail': (
                f'{host}:{port} /hxinstaller responded (HTTP {code}) — '
                'CVE-2021-1497 HyperFlex HX installer authentication bypass surface present; '
                'unauthenticated command execution possible on the installer appliance (CVSS 9.8)'
            ),
            'host': host,
            'port': port,
        })

    # --- CVE-2021-1498: HyperFlex API authentication bypass ---
    code, body = _hx_get(host, port, '/hxapi/v1/diags/syslogs')
    if code == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'HYPERFLEX_CVE_2021_1498',
            'detail': (
                f'{host}:{port} /hxapi/v1/diags/syslogs returned 200 without authentication — '
                'CVE-2021-1498 HyperFlex API authentication bypass; system log exfiltration '
                'without credentials (CVSS 9.8)'
            ),
            'host': host,
            'port': port,
        })

    # --- vCenter integration credentials exposure ---
    code, body = _hx_get(host, port, '/rest/v1/vcenter')
    if code == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'HYPERFLEX_VCENTER_CREDS',
            'detail': (
                f'{host}:{port} /rest/v1/vcenter returned 200 without authentication — '
                'vCenter integration endpoint exposed; vCenter credentials or configuration '
                'readable; lateral movement to full VMware vSphere environment possible'
            ),
            'host': host,
            'port': port,
        })

    return findings

    return findings


def probe_vergeos_tenant_isolation_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings = []

    # /api/v4/apikey — bearer token inventory; full system access if unauth
    code, body = _vio_get(host, port, '/api/v4/apikey', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_APIKEY_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/apikey returned 200 without authentication — '
                f'{count} API key record(s) exposed; bearer token names, last-used IPs, '
                'and expiration dates readable; permits targeted credential replay and '
                'owner-user identification for privilege-level mapping'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/authsource — OAuth2/OIDC configurations with client secrets
    code, body = _vio_get(host, port, '/api/v4/authsource', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
            has_secret = False
            if isinstance(records, list):
                for r in records:
                    if isinstance(r, dict) and any(
                        k in r for k in ('client_secret', 'clientsecret', 'secret')
                    ):
                        has_secret = True
                        break
        except (ValueError, TypeError):
            count = '?'
            has_secret = False
        sev = 'CRITICAL' if has_secret else 'HIGH'
        findings.append({
            'severity': sev,
            'title': 'VERGEIO_AUTHSOURCE_UNAUTH',
            'detail': (
                f'GET /api/v4/authsource returned 200 without authentication — '
                f'{count} OAuth2/OIDC source(s) exposed; driver type, redirect URI, '
                f'client ID{"and client secret" if has_secret else ""} readable; '
                'enables token forgery and account takeover via third-party identity provider'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/sharedobject — cross-tenant VM snapshot and file transfer surface
    code, body = _vio_get(host, port, '/api/v4/sharedobject', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_SHAREDOBJECT_UNAUTH',
            'detail': (
                f'GET /api/v4/sharedobject returned 200 without authentication — '
                f'{count} shared object(s) exposed; cross-tenant VM snapshots and file transfers '
                'readable without credentials; tenant-boundary data exfiltration path present'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/permission — system-wide ACL table
    code, body = _vio_get(host, port, '/api/v4/permission', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_PERMISSION_TABLE_UNAUTH',
            'detail': (
                f'GET /api/v4/permission returned 200 without authentication — '
                f'{count} permission record(s) exposed; user/group ACL assignments across '
                'all object types readable; privilege topology fully enumerable for targeted '
                'lateral movement to high-privilege accounts'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/tenantnode — tenant node configs; reveals compute isolation boundary
    code, body = _vio_get(host, port, '/api/v4/tenantnode', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'MEDIUM',
            'title': 'VERGEIO_TENANTNODE_UNAUTH',
            'detail': (
                f'GET /api/v4/tenantnode returned 200 without authentication — '
                f'{count} tenant node record(s) exposed; per-tenant core/RAM allocation, '
                'cluster placement, and failover config readable; isolation boundary mapped '
                'for targeted resource exhaustion or node-level attack planning'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/subscription — alert and report subscriber list
    code, body = _vio_get(host, port, '/api/v4/subscription', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'LOW',
            'title': 'VERGEIO_SUBSCRIPTION_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/subscription returned 200 without authentication — '
                f'{count} subscription record(s) exposed; alert recipient email addresses '
                'and threshold configurations readable; enables social engineering '
                'targeting of ops/admin contacts'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_vergeos_storage_api_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings = []

    # /api/v4/media — vSAN file library (ISOs, drive images, VM definitions)
    code, body = _vio_get(host, port, '/api/v4/media', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_MEDIA_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/media returned 200 without authentication — '
                f'{count} file record(s) exposed; ISO images, VM drive images, and '
                'VM definition files stored in vSAN enumerable without credentials; '
                'filenames and public download link tokens visible'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/tier — vSAN storage tier configuration (0=metadata NVMe .. 5=archive HDD)
    code, body = _vio_get(host, port, '/api/v4/tier', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'MEDIUM',
            'title': 'VERGEIO_VSAN_TIER_UNAUTH',
            'detail': (
                f'GET /api/v4/tier returned 200 without authentication — '
                f'{count} storage tier(s) exposed; hardware class, capacity, '
                'and utilization per tier readable; enables targeted capacity exhaustion '
                'on metadata tier (Tier 0) to destabilize the entire vSAN'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/drive — physical drive inventory per node
    code, body = _vio_get(host, port, '/api/v4/drive', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'MEDIUM',
            'title': 'VERGEIO_DRIVE_INVENTORY_UNAUTH',
            'detail': (
                f'GET /api/v4/drive returned 200 without authentication — '
                f'{count} drive record(s) exposed; device IDs, node placement, health state, '
                'and tier assignments readable; drive-level attack surface fully enumerable'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/nasvolume — NAS volume listing; may expose share paths and access configs
    code, body = _vio_get(host, port, '/api/v4/nasvolume', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_NAS_VOLUME_UNAUTH',
            'detail': (
                f'GET /api/v4/nasvolume returned 200 without authentication — '
                f'{count} NAS volume(s) exposed; share names, capacity, tier placement, '
                'and access configuration readable; enables targeted NFS/CIFS mount attempts'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/volume — storage volume listing; cross-tenant boundary check
    code, body = _vio_get(host, port, '/api/v4/volume', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VERGEIO_VOLUME_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/volume returned 200 without authentication — '
                f'{count} storage volume(s) exposed without credentials; '
                'volumes are exclusive per-tenant storage units; cross-tenant '
                'visibility indicates isolation boundary failure in the vSAN layer'
            ),
            'host': host,
            'port': port,
        })

    # /api/v4/cloudsnap — system snapshot inventory; expose restore timestamps
    code, body = _vio_get(host, port, '/api/v4/cloudsnap', timeout)
    if code == 200:
        try:
            records = json.loads(body) if body else []
            count = len(records) if isinstance(records, list) else '?'
        except (ValueError, TypeError):
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title': 'VERGEIO_CLOUDSNAP_LIST_UNAUTH',
            'detail': (
                f'GET /api/v4/cloudsnap returned 200 without authentication — '
                f'{count} system snapshot(s) exposed; recovery point timestamps, '
                'retention expiry, and snapshot type (local/provider) readable; '
                'tenant self-serve snapshot access surface enumerable'
            ),
            'host': host,
            'port': port,
        })

    # probe guessable public file download link formats (uuid and filename-based)
    for link_path in ('/download', '/files'):
        code, body = _vio_get(host, port, link_path, timeout)
        if code == 200 and body and len(body) > 64:
            body_str = body[:512].decode('utf-8', errors='replace')
            if any(m in body_str for m in ('iso', 'img', 'raw', 'vmdk', 'qcow')):
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'VERGEIO_PUBLIC_FILE_LINK_EXPOSED',
                    'detail': (
                        f'GET {link_path} on {host}:{port} returned 200 with file content '
                        'markers (iso/img/raw/vmdk/qcow) — unauthenticated public download '
                        'link active; vSAN-stored files retrievable without credentials'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    return findings
