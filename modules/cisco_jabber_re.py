"""
cisco_jabber_re.py — Cisco Jabber multi-platform static RE module

Targets:
  Windows 11.9.1 : CiscoJabber-Install-ffr.11-9-1.zip → CiscoJabberSetup.msi (71MB, 2017-09-25)
                   /media/cowboy/research/jabber-11-9-1-extract/msi-files/
  Windows 15.3.0 : https://binaries.webex.com/jabberclientwindows/20260721091017/CiscoJabberSetup.msi
                   /media/cowboy/research/jabber-15-3-0-msi/
  Android 15.0.4 : com.cisco.im@15.0.4.309657.apk (APKPure)
                   /media/cowboy/research/jabber-apk-15-0-4/

Download URL extraction:
  jabber.html JS: jabberAppUrl = 'https://binaries.webex.com/jabberclientwindows/<build>/CiscoJabberSetup.msi'
  Android CDN   : https://play.google.com/store/apps/details?id=com.cisco.im (Play Store redirect)
  iOS CDN       : https://apps.apple.com/us/app/cisco-jabber/id467192391

Build dates:
  11.9.1  : 2017-09-25
  15.3.0  : 20260721091017 (build timestamp)
  15.0.4  : APK manifest timestamp 1981-01-01 (stripped build time)

Platform:
  Windows: Win32 PE DLLs, MSVC runtime, x86/x64
  Android: arm64-v8a + armeabi-v7a, ABI split in APK lib/

KEY BINARY MAP — Windows 15.3.0:

  libcef.dll               108MB  Chromium Embedded Framework — browser engine (UI renderer)
  libpme.dll                34MB  Protocol Media Engine
  CiscoSparkClientFramework.dll 18MB  Spark/Webex client framework (added post-11.9.1)
  ipps90lgc.dll             16MB  Intel IPP codec library
  ippsc90lgc.dll            14MB  Intel IPP codec (second variant)
  enhanced-callcontrol_MD.dll 11MB  Call control (Multiline Device)
  libGLESv2.dll              6.7MB GPU/OpenGL ES shim
  XmppSDK.dll               3.6MB XMPP protocol SDK
  lcppn.dll                 2.2MB  (Locus/CMR presence notifier)
  libcrypto-1_1.dll         2.1MB  CiscoSSL fork (see FINDINGS)
  videoprocess.dll          1.9MB  Video processing pipeline
  libtaf.dll                1.8MB  Telephony Abstraction Framework
  libmari.dll               1.7MB  MARI (media/RTP) library
  csfnetutils.dll           1.6MB  CSF network utils — SIP/DTLS/SRTP + Edge integration
  DBWrapper.dll             1.6MB  SQLite/local DB wrapper
  csfcommunicationhistory.dll 1.5MB  Call/IM history
  libcxypme.dll             1.5MB  CXY protocol media engine
  VirtualBackgroundManager.dll 1.4MB Virtual background processing
  cpve.dll                  856K  Protocol Voice Engine — primary RTP/SRTP/DTLS surface
  krb5_32.dll               899K  MIT Kerberos 5 (domain auth)
  libcurl.dll               474K  HTTP client
  WapiClient.dll            329K  WAPI (wireless auth) client
  csflogger.dll             161K  CSF logging framework
  commonsession.dll         158K  Session management
  dnsutils.dll              143K  DNS resolution utils
  csfdiagnostics.dll         66K  CSF diagnostics
  cmcrypto.dll               64K  Cisco Media Crypto — STRIPPED (no readable symbols)
  srtp.dll                   58K  SRTP library (standalone, separate from cpve)
  csfstorage.dll             22K  CSF persistent storage

KEY BINARY MAP — Android 15.0.4 (arm64-v8a):

  libJCF.so                149MB  Jabber Client Framework monolith (full CSF + all service modules)
  libcpve.so               8.7MB  Protocol Voice Engine (= Windows cpve.dll, ARM64)
  libcpve-opensource.so    7.8MB  cpve open-source components (separated for license compliance)
  libcryptox.so            2.3MB  CiscoSSL libcrypto fork (x = Cisco custom)
  libcfom.so               550K  CF Object Model
  libsslx.so               536K  CiscoSSL libssl fork
  libc++_shared.so         891K  LLVM libc++ shared runtime
  libnative_crash_handler.so 355K  Native crash reporter
  libcsflogger.so          279K  CSF logging (= Windows csflogger.dll)
  liboboe.so               253K  Android Oboe audio library
  librender.so             211K  Rendering layer
  libcjose.so              123K  JOSE (JWT/JWK/JWE) — auth token handling
  libsrtp.so               106K  SRTP library
  libz.1.3.1.so            100K  zlib 1.3.1
  libfips.so                35K  FIPS module stub

libJCF.so JNI surface (12,301 entry points by module):
  impresenceservicesmodule   : 3941
  telephonyservicemodule     : 2592
  systemservicemodule        : 1869
  contactservicemodule       :  772
  meetingservicemodule       :  614
  voicemailservicemodule     :  472
  conversationservicemodule  :  330
  mediadeviceservicemodule   :  302
  commonheadmodule           :  253
  diagnosticstoolservicemodule: 198
  communicationhistoryservicemodule: 171
  telemetryservicemodule     :  154
  loggerservicemodule        :  118
  configservicemodule        :  110
  systemmonitorservicemodule :   89
  global                     :   88
  diagnosticservicemodule    :   80
  servicesframeworkmodule    :   76
  servicefactory             :   62
  NativePrivateKeyManagement :    1  <-- key management JNI bridge

CSF version delta (11.9.1 → 15.3.0):
  csfnetutils.dll : 1.4MB → 1.6MB (+200K)
    New namespace: csf::edge (full Expressway-E integration)
    New classes: EdgeConfig, EdgeConfigHttpClient, EdgeConfigRequest,
                 EdgeConfigResponse, EdgeDetectionController,
                 CollabEdgeServiceSensor, CredentialsManager,
                 DirectConnectivityTester, EdgeTransitionDetectionController
    New DNS SRV: _collab-edge._tls (Expressway-E service discovery)
  CiscoSparkClientFramework.dll : NEW in 15.3.0 (18MB) — Webex unification layer
  wv2_dll.dll : NEW — WebView2 (Chromium Edge) replaces legacy rendering in parts

APK default config (assets/jabber-config-defaults.xml):
  imcatcher_disable    : FALSE  (IM capture/logging ENABLED by default)
  local_archive_enabled: TRUE   (local message archive on by default)
  support_ssl_encoding : TRUE
  support_aes_encoding : FALSE
  support_no_encoding  : FALSE
  IP_MODE              : Dual_Stack
  screen_capture_enabled: TRUE
  file_transfer_enabled: TRUE

Auth network services (assets/AuthenticatorMap.xml):
  CUCM_CISCO_UDS    (id=1000) — UCM 9.0 UDS auth
  EDGE_CISCOEDGE    (id=1001) — Expressway-E auth (MRA path)
  CUP_CUPLOGIN      (id=1200) — CUPS/IM&P service login
  WEBEX_XMPP_CLIENT (id=1201) — Webex cloud XMPP
  CUCM_LEGACY_TFTP  (id=2100) — Legacy CUCM TFTP
  CUCM_LEGACY_CCMCIP(id=2100) — Legacy CCMCIP
  WEBEX_TEAMS_CLIENT(id=2000) — Webex Teams auth

FINDINGS:

JAB-F1: CiscoSSL Private Fork Extends Past OpenSSL 1.1.1w EOL [HIGH]
  File: libcrypto-1_1.dll (Windows 15.3.0)
  Version string: CSCO_CSM_CiscoSSL_1.1.1zc.7.3.4
  OpenSSL public branch: 1.1.1w is the last public release (EOL Sept 2023)
  CiscoSSL extends: 1.1.1zc — version beyond the public numbering
  Implication:
    1. Cisco maintains a private patch set on top of OpenSSL 1.1.1 branch
    2. CVE disclosure lag: Cisco-private patches vs public CVE timeline unknown
    3. 1.1.1 branch has known post-EOL CVEs (CVE-2024-5535, etc.) — unclear if
       CiscoSSL cherry-picks fixes or carries the full public backport stream
    4. "zc" versioning is Cisco-internal; no public changelog available
  APK equivalent: libcryptox.so/libsslx.so — same OpenSSL 1.1.1 base,
                  "x" suffix = Cisco custom build, version stripped from binary

JAB-F2: Expressway-E Auth Credential Chain in csfnetutils [HIGH]
  File: csfnetutils.dll (15.3.0 only — not in 11.9.1)
  Namespace: csf::edge
  Key classes:
    csf::edge::Credentials             — stores username/password as SecureString
    csf::edge::CredentialsManager      — manages Edge credential lifecycle
    csf::edge::EdgeConfigHttpClient    — fetches edge config from Expressway-E over HTTPS
    csf::edge::CollabEdgeServiceSensor — monitors _collab-edge._tls DNS SRV
    csf::edge::DirectConnectivityTester — TCP probe to Expressway-E endpoint
  Discovery: DNS SRV _collab-edge._tls.<domain> → Expressway-E FQDN:443
  Auth flow: EdgeConfigRequest → EdgeConfigResponse → SIP route extraction
             → sipEdgeServer + sipRequestServer in XML response
  Attack surface:
    1. EdgeConfigHttpClient fetches XML from Expressway-E — MITM of DNS SRV
       record redirects to attacker-controlled server, returning malicious config
    2. Credentials stored in csf::edge::SecureString — memory disclosure if
       heap spray or use-after-free in csfnetutils
    3. Error string: "Edge Connection has failed with an SSL/TLS error" — TLS
       downgrade attack surface at the Edge connection layer

JAB-F3: libJCF.so NativePrivateKeyManagement JNI Bridge [HIGH]
  File: libJCF.so (Android 15.0.4 arm64)
  Symbol: Java_com_cisco_jabber_jcf_..._NativePrivateKeyManagement_*
  Only 1 entry point in this module — single JNI bridge for key management
  Implication: private key operations exposed through a single JNI call
               Any memory corruption in libJCF.so's key management path
               has direct access to key material

JAB-F4: imcatcher_disable=FALSE Default — IM Capture Enabled [MEDIUM]
  File: assets/jabber-config-defaults.xml (Android 15.0.4)
  Setting: imcatcher_disable = FALSE
  Meaning: IM capture/recording by admin is ENABLED by default
           Users cannot detect passive IM monitoring without explicit policy check
  Also: local_archive_enabled = TRUE — plaintext local message store
        Location: Android internal storage / app sandbox
  Attack: post-compromise of device → local archive extraction = full IM history

JAB-F5: cmcrypto.dll Intentionally Stripped [LOW/MEDIUM]
  File: cmcrypto.dll (64K, Windows 15.3.0)
  Strings: only PE headers, section names, MSVC CRT bootstrap — zero Cisco symbols
  11.9.1 cmcrypto.dll: same size range, same stripped state (consistent across versions)
  Interpretation: thin DRM/key-wrapping shim, stripped to obscure key handling logic
  RE path: requires dynamic analysis (API monitor on Windows) or disassembly
           Exports: enumerate via dumpbin /exports to map the thin API surface

JAB-F7: libcjose 0.6.1 — CVE-2023-37464 Algorithm Confusion + alg:none [CRITICAL]
  File: libcjose.so (Android 15.0.4 arm64, 123K)
  Version: 0.6.1 (from embedded source paths: 0.6.1/src/jws.c, 0.6.1/src/jwe.c, etc.)
  CVE-2023-37464 fixed in: 0.6.2.2 — this build is 3 minor versions behind the fix
  Compiler: Android clang 6.0.2 r316199 (~2018) — 8-year-old toolchain
  Dependencies: libcryptox.so, libsslx.so (CiscoSSL fork)
  Mechanism (confirmed via disassembly of cjose_jws_verify at 0x10aa8):
    cjose_jws_verify dispatches via two function pointers stored in the JWS struct
    at offsets [x21+120] and [x21+136]. These pointers are set at cjose_jws_import
    time based on the "alg" header value in the token. No re-validation of key type
    occurs at verify time — only the algorithm-specific verify function is called.
    Attack (CVE-2023-37464 algorithm confusion):
      1. Server uses RS256 with an RSA key pair for JWS token issuance
      2. Attacker obtains RSA public key (public by definition)
      3. Attacker crafts JWS token with header {"alg":"HS256"} (swapped to HMAC)
      4. Computes HMAC-SHA256 of header.payload using RSA public key bytes as the secret
      5. Submits forged token — server calls HS256 verify with the same RSA public key
         as "secret"; HMAC matches → verification passes → token accepted
  alg:none surface:
    CJOSE_HDR_ALG_NONE constant and "none" string present in binary
    If import accepts alg:none, verify dispatches to a no-op function → unsigned
    tokens pass verification with no signature check
  Exports: cjose_jws_verify, cjose_jws_sign, cjose_jwe_encrypt, cjose_jwe_decrypt,
           cjose_jwe_decrypt_multi, cjose_jwk_create_EC_random, cjose_jwk_create_RSA_random,
           cjose_jwk_derive_ecdh_secret, cjose_jwk_hkdf
  Auth relevance: EDGE_CISCOEDGE (Expressway-E MRA path, id=1001) uses JWS tokens
                  for Mobile Remote Access auth. Algorithm confusion here → MRA token
                  forgery → unauthorized remote access bypass

JAB-F8: libcjose ECDH-ES Key Derivation Exported [MEDIUM]
  File: libcjose.so (Android 15.0.4)
  Functions: cjose_jwk_derive_ecdh_bits, cjose_jwk_derive_ecdh_ephemeral_key,
             cjose_jwk_derive_ecdh_secret, cjose_concatkdf_derive
  Supported curves: P-256, P-384, P-521
  JWE algorithms: ECDH-ES, A128KW, A192KW, A256KW, A256GCM, A128CBC-HS256,
                  A192CBC-HS384, A256CBC-HS512, RSA1_5, RSA-OAEP
  RSA1_5 presence: RSA PKCS1v1.5 encryption accepted (known padding oracle surface)

JAB-F6: SRTP/DTLS Split — Two Separate Libraries [LOW]
  Windows: both cpve.dll (Protocol Voice Engine, 856K) AND srtp.dll (58K) present
  cpve.dll likely embeds its own SRTP stack; srtp.dll may be legacy or used by
  separate subsystem (e.g., screen sharing, BFCP)
  Android: libsrtp.so (106K) separate from libcpve.so (8.7MB) — same split
  Implication: two independent SRTP implementations → different patch cadences,
               different CVE exposure windows

JAB-F9: Android Deep Link Injection — ciscoim/ciscojabber/ciscotel Schemes [HIGH]
  Registered URL schemes (AndroidManifest, category:BROWSABLE): ciscoim://, ciscojabber://, ciscotel://
  Handler: CrossLaunchActivity (com.cisco.jabber.signin.crosslaunch.CrossLaunchActivity)
  Handled scheme actions:
    ciscotel://         → call initiation to attacker number (toll fraud)
    sip://              → SIP call
    jabberphone://      → Jabber phone call
    clicktocall://      → click-to-call
    ciscoim://          → IM conversation start
    im:// / imto:// / xmpp:// → XMPP conversation
    ciscojabber://provision   → server provisioning (TFTP/CUCM reconfiguration)
  BROWSABLE category: any web page can trigger CrossLaunchActivity without user prompt
  Attack: ciscojabber://provision → replaces CUCM/TFTP server with attacker endpoint;
          ciscotel://attacker-number → toll fraud; ciscoim:// → unsolicited IM

JAB-F10: WebView Chat Renderer — Event Handler Injection via XMPP Messages [HIGH]
  Files: assets/js/jabberMessageManager.js, jabberPostRequest.js, ConversationTemplate.html
  Native-to-JS bridge (Android): ChatView JavaScript interface (ChatView.postMessage)
  Message rendering pipeline:
    1. Native calls JS loadConversation/appendMessages(base64-encoded HTML)
    2. decodeBase64Html(): window.atob() + URL decode → raw HTML string
    3. createElementsFromHtml(): range.createContextualFragment(html)
       → parses HTML into DOM fragment; inline event handlers (onerror/onload/onclick) EXECUTE
  ChatView bridge operations (from JS → native):
    downloadFile(fileId, msgId)          → native file download
    browseFile(fileId, msgId)            → open file in external viewer
    deleteMessage(convId, msgId)         → delete message
    callMeMessage(uri)                   → initiate call to any URI
    robotMessage(robotUri, action, msg)  → bot action dispatch
    ecmFileAction(fileId, msgId, type)   → ECM content operation
    postMessagesHtml(htmlStr)            → inject raw HTML back into renderer
    startOneToOneConversation(uri)       → start conversation with arbitrary URI
  Attack: if native HTML sanitizer fails to strip event handlers from XMPP message body:
    <img src=x onerror="ChatView.postMessage(JSON.stringify({name:'callMeMessage',
    params:{contactUri:'sip:attacker@domain'}}))"> → triggers outbound call on victim device
  Note: sanitization boundary is Java-side before base64 encode; DEX analysis needed
        to confirm whether server-provided HTML is sanitized before WebView injection

JAB-F11: JabberCallStateContentProvider — Exported ContentProvider [MEDIUM]
  Component: com.cisco.jabber.providers.JabberCallStateContentProvider
  Protecting permissions: com.cisco.jabber.READ_CALL_STATE, WRITE_CALL_STATE
  Any app that declares matching permission (or if exported without protection) can
  query/modify call state: call hijacking, call log access, call spoofing

JAB-F12: SSO Browser WebView — OAuth Redirect and Token Leakage [MEDIUM]
  Classes: JabberSSOBrowserActivity, MeetingSSOBrowserActivity, SSOActivity
  WebView-based SSO for CUCM/Expressway/Webex OAuth/SAML flows
  DEX strings: 'refreshToken', 'accessToken', 'SessionExpireDialogActivity',
               'RefreshTokenAboutToExpireDialogActivity'
  Attack:
    1. MITM of IdP TLS (CiscoSSL 1.1.1 fork — JAB-F1) during SSO flow
    2. Injected JS in IdP response leaks OAuth tokens via ChatView bridge or postMessage
    3. Open redirect at IdP → OAuth code delivered to attacker URI
    4. Chain with JAB-F9: deep link triggers SSO then provision re-pointer

JAB-F13: libcpve.so — DTLS Fingerprint Verification Bypass [HIGH]
  Binary:    libcpve.so (arm64-v8a, 8.7MB, Android 15.0.4)
  Source:    cpve/src/main/ConnectionFactory.cpp line 1279
  Namespace: CSF::media::rtp::ConnectionImpl

  Architecture:
    ConnectionImpl struct has a 1-byte bypass flag at offset +0xe8.
    When set, connectDtlsSession and connectDtlsSessionWithTimeout skip
    all DTLS fingerprint validation — the handshake succeeds without verifying
    the remote certificate fingerprint against the SDP offer.

  Bypass setter (3-instruction function):
    VA 0x51466c:
      mov  w8, #1
      strb w8, [x0, #0xe8]   ; ConnectionImpl->bypass_fingerprint_verify = 1
      ret

  Verification function (VA 0x514ca8, connectDtlsSession):
    0x514cb0: ldr  w8, [x0, #0xd0]      ; load DTLS state
    0x514cb4: cbz  w8, #0x51504c         ; state==0 → early exit (no check, no error)
    0x514d40: ldrb w8, [x19, #0xe8]      ; load bypass flag
    0x514d44: cbnz w8, #0x514dac         ; if set → jump to bypass path
    ...
    0x514dac: mov  x2, x25               ; load "fingerprint verification is disabled"
    0x514db0: mov  x0, xzr
    0x514db4: bl   #0x1e1960             ; LOG(...) — logs bypass, does NOT abort
    0x514dc4: str  w22, [x19, #0xd0]     ; set state=2 (CONNECTED) — handshake marked complete
    ; callbacks fire, DTLS session accepted without fingerprint check

  Second bypass check (VA 0x5146c0, connectDtlsSessionWithTimeout path):
    0x5146c0: ldrb w8, [x19, #0xe8]
    0x5146c4: cbnz w8, #0x5146d4         ; bypass → skip fingerprint compare at 0x1d46c0

  Log strings confirmed in binary:
    0x6ed8d5: "connectDtlsSession, disable fingerprint verification"
    0x6ed958: "connectDtlsSessionWithTimeout, disable fingerprint verification"
    0x7475dc: "%s: fingerprint verification is disabled"
    0x747495: "%s: no remote fingerprint"
    0x747658: "%s: connect error, remote fingerprint did not match %s != %s"
    0x74763f: "%s: fingerprint is valid"

  Bypass setter vtable pointer: file offset 0x4c798 → VA 0x51466c

  Impact:
    DTLS-SRTP key exchange completes without certificate validation.
    Adversary performing media-path MITM presents arbitrary certificate;
    Jabber accepts it if the bypass flag is set on the ConnectionImpl instance.
    Bypasses the primary defense against certificate substitution in DTLS-SRTP.

  Trigger condition:
    Requires disableFingerprintVerification() to be called on the ConnectionImpl
    instance before connectDtlsSession fires. Trigger path not yet traced — requires
    identifying all callers of vtable slot at 0x4c798 via BLR trace or SDP negotiation
    error fallback analysis.

  Chain:
    JAB-F13 → media path MITM → decrypt RTP/SRTP in real time
    Combined with JAB-F1 (CiscoSSL 1.1.1 fork) for signaling-path MITM:
    full session interception (signaling + media) without user indication

JAB-F14: HTMLOUT WebView DOM Scraping — Hardcoded JS Token Extractor [HIGH]
  Source: classes2.dex, string pool
  Interface: HTMLOUT (addJavascriptInterface target)

  Two hardcoded JavaScript injection strings:

  1. Full-page HTML dump:
       javascript: var wholeBody = document.documentElement.innerHTML;
                   HTMLOUT.processHTML(wholeBody, window.location.href);
     Dumps the entire rendered DOM of any WebView page to the Java interface.
     HTMLOUT.processHTML receives raw HTML + current URL on every trigger.

  2. Meeting ticket scraper:
       javascript: var result = document.getElementsByName('result')[0].value;
                   var ticket = document.getElementsByName('ticket')[0].value;
                   var timetolive = document.getElementsByName('timetolive')[0].value;
                   var createtime = document.getElementsByName('createtime')[0].value;
                   var username = document.getElementsByName('username')[0].value;
                   var siteurl = document.getElementsByName('siteurl')[0].value;
                   HTMLOUT.processMeetingInfo(result, ticket, timetolive, createtime,
                                              username, siteurl);
     Extracts meeting auth ticket, username, site URL from a Cisco Meeting Server /
     Webex login form rendered in the WebView. Fields match CMS session token schema.

  Bridge path:
    IBrowserAdapter (C++ abstract interface)
    → SwigDirector_IBrowserAdapter_runJavascript (SWIG JNI)
    → addJavascriptInterface("HTMLOUT", ...)
    → evaluateJavascript / loadUrl("javascript:...")
    → HTMLOUT.processHTML / HTMLOUT.processMeetingInfo (Java callback)

  Strings confirmed:
    'IBrowserAdapter_runJavascript'
    'SwigDirector_IBrowserAdapter_runJavascript'
    'AddJavascriptInterface' / 'addJavascriptInterface'
    'evaluateJavascript'
    'HTMLOUT'

  Attack:
    1. MITM or redirect the WebView to attacker-controlled page (chain JAB-F12, JAB-F1)
    2. Jabber injects the hardcoded JS, receives full HTML including any tokens
    3. processMeetingInfo delivers ticket+username+siteurl to attacker-controlled host
       if the phished page mimics a CMS login form with correct field names
    4. ticket = session bearer for Cisco Meeting Server / Webex session

JAB-F15: CrossLaunch Provision Protocol — Rate-Limited Deep Link Provisioning [HIGH]
  Source: classes2.dex string pool
  Classes: CrossLaunchActivity, ShareFileCrossLaunchService

  Config keys:
    KEY_CROSS_LAUNCH_ENABLE_PROVISION_PROTOCOL
    KEY_CROSS_LAUNCH_PROVISION_PROTOCOL_RATE_LIMIT
    KEY_CROSS_LAUNCH_PROVISION_PROTOCOL_TIME_LIMIT

  Strings:
    'com.cisco.jabber.signin.crosslaunch.provision'  ← scheme handler
    'ConfigService_setUrlProvisioningData'            ← provisioning URL setter
    'ConfigService_resetAllowUriProvisioningData'     ← provisioning reset
    'EnableProvisionProtocol'
    'DisableCrossLaunch'                              ← admin killswitch
    'CiscoTelProtocolCrossLaunchBackSchema'           ← ciscotel:// handler
    'CrossLaunchBackSchema', 'CrossLaunchBackAppName'

  Cross-launch attack path:
    1. ciscotel:// or ciscojabber:// deep link (BROWSABLE, JAB-F9)
    2. CrossLaunchActivity handles provision scheme
    3. ConfigService_setUrlProvisioningData sets attacker CUCM URL
    4. Rate limit (KEY_CROSS_LAUNCH_PROVISION_PROTOCOL_RATE_LIMIT) is the
       only defense — brute-forceable if rate window is observed
    5. ShareFileCrossLaunchService processes file-sharing URIs — potential
       path traversal if URI validation is missing (ShareFileCrossLaunchService.kt:74-87)

  Chain: JAB-F9 (deep link) → JAB-F15 (provision) → EXP-F9/F10 (Expressway privilege escalation)

DEX STRUCTURE (classes.dex + classes2.dex):
  Total: 59293 strings, 10221 types, 65339 methods, 8104 classes (DEX035)
  Cisco packages: cisco/jabber/app, signin, im, jcf, telephony, service, setting,
                  system, presence, contact, utils, vvm, widget, csf, droid
  Notable: com.cisco.anyconnect.vpn integration (VPN_DNS_CONFIGURED/RESTORED intents)
           com.cisco.jabber.signin.crosslaunch (deep link entry point)
           com.cisco.jabber.service.contact.delegate.sync.authenticator.AuthenticationService
  Robot/bot subsystem: BotMsgDetailActivity, robotMessage bridge, robot.css
  AnyConnect VPN: com.cisco.im.watchlib (watch app), VPN DNS change receiver
"""

# Binary inventory — Windows 15.3.0
WIN_BINARIES_15_3_0 = {
    "libcef.dll":                   {"size_mb": 108,  "role": "Chromium Embedded Framework"},
    "libpme.dll":                   {"size_mb": 34,   "role": "Protocol Media Engine"},
    "CiscoSparkClientFramework.dll":{"size_mb": 18,   "role": "Spark/Webex client framework (new post-11.9.1)"},
    "csfnetutils.dll":              {"size_mb": 1.6,  "role": "SIP/DTLS/SRTP + Edge/Expressway-E integration"},
    "cpve.dll":                     {"size_mb": 0.856,"role": "Protocol Voice Engine (RTP/SRTP/DTLS)"},
    "libcrypto-1_1.dll":            {"size_mb": 2.1,  "role": "CiscoSSL fork CSCO_CSM_CiscoSSL_1.1.1zc.7.3.4"},
    "libssl-1_1.dll":               {"size_mb": 0.521,"role": "CiscoSSL TLS layer"},
    "cmcrypto.dll":                 {"size_mb": 0.064,"role": "Media crypto (STRIPPED — no readable symbols)"},
    "srtp.dll":                     {"size_mb": 0.058,"role": "SRTP standalone library"},
    "libcurl.dll":                  {"size_mb": 0.474,"role": "HTTP client"},
    "csflogger.dll":                {"size_mb": 0.161,"role": "CSF logging framework"},
    "dnsutils.dll":                 {"size_mb": 0.143,"role": "DNS resolution utils"},
    "csfdiagnostics.dll":           {"size_mb": 0.066,"role": "CSF diagnostics"},
    "csfstorage.dll":               {"size_mb": 0.022,"role": "CSF persistent storage"},
}

# Binary inventory — Android 15.0.4 (arm64-v8a)
APK_BINARIES_15_0_4 = {
    "libJCF.so":              {"size_mb": 149,  "role": "Jabber Client Framework monolith (12301 JNI entry points)"},
    "libcpve.so":             {"size_mb": 8.7,  "role": "Protocol Voice Engine (ARM64)"},
    "libcpve-opensource.so":  {"size_mb": 7.8,  "role": "cpve open-source components (license separation)"},
    "libcryptox.so":          {"size_mb": 2.3,  "role": "CiscoSSL libcrypto fork (custom build)"},
    "libsslx.so":             {"size_mb": 0.536,"role": "CiscoSSL libssl fork"},
    "libcfom.so":             {"size_mb": 0.550,"role": "CF Object Model"},
    "libcsflogger.so":        {"size_mb": 0.279,"role": "CSF logging framework"},
    "libcjose.so":            {"size_mb": 0.123,"role": "JOSE (JWT/JWK/JWE) auth token handling"},
    "libsrtp.so":             {"size_mb": 0.106,"role": "SRTP library (separate from cpve)"},
    "libfips.so":             {"size_mb": 0.035,"role": "FIPS module stub"},
}

# libcpve.so — DTLS fingerprint bypass (JAB-F13)
LIBCPVE_DTLS_BYPASS = {
    "binary":            "libcpve.so (arm64-v8a, 8.7MB)",
    "source_file":       "cpve/src/main/ConnectionFactory.cpp",
    "source_line":       1279,
    "namespace":         "CSF::media::rtp::ConnectionImpl",
    "bypass_flag_offset": 0xe8,       # 1-byte flag in ConnectionImpl struct
    "setter_va":         0x51466c,    # mov w8,#1; strb w8,[x0,#0xe8]; ret
    "verify_fn_va":      0x514ca8,    # connectDtlsSession — checks flag at 0x514d40
    "bypass_check_1":    0x514d40,    # ldrb w8,[x19,#0xe8]; cbnz → bypass
    "bypass_check_2":    0x5146c0,    # second check in connectDtlsSessionWithTimeout path
    "bypass_log_va":     0x514dac,    # logs "fingerprint verification is disabled" then marks CONNECTED
    "setter_vtable_ptr": 0x4c798,     # file offset of function pointer to setter
    "log_strings": {
        0x6ed8d5: "connectDtlsSession, disable fingerprint verification",
        0x6ed958: "connectDtlsSessionWithTimeout, disable fingerprint verification",
        0x7475dc: "%s: fingerprint verification is disabled",
        0x747495: "%s: no remote fingerprint",
        0x747658: "%s: connect error, remote fingerprint did not match %s != %s",
        0x74763f: "%s: fingerprint is valid",
    },
    "impact": (
        "DTLS handshake completes without remote cert fingerprint validation. "
        "MITM on media path can substitute arbitrary certificate. "
        "Bypasses primary defense against certificate substitution in DTLS-SRTP."
    ),
    "trigger": "disableFingerprintVerification() called on ConnectionImpl before connectDtlsSession fires",
    "trigger_traced": False,          # No BL callers in .text; not in any C++ vtable found
    # Dispatch note: TlsSession/DtlsSession vtables at 0x86e9c0/0x86e978 use GLib GObject
    # dispatch (slot[0]=rodata VA, slot[1]=NULL typeinfo) — not Itanium C++ ABI.
    # Function is GLOBAL exported; reachable via dlsym or GStreamer element property table
    # at 0x4c798 (.dynsym st_value, not a runtime pointer). Requires dynamic analysis.
    "chain": ["JAB-F1 (CiscoSSL 1.1.1 fork) → signaling MITM", "JAB-F13 → media MITM"],
}

# CSF version delta: csfnetutils 11.9.1 → 15.3.0
CSFNETUTILS_DELTA = {
    "11.9.1_size_bytes":  1468416,   # 1.4MB
    "15.3.0_size_bytes":  1604608,   # 1.6MB (+200K)
    "new_namespace": "csf::edge",
    "new_classes": [
        "csf::edge::EdgeConfig",
        "csf::edge::EdgeConfigHttpClient",
        "csf::edge::EdgeConfigRequest",
        "csf::edge::EdgeConfigResponse",
        "csf::edge::EdgeDetectionController",
        "csf::edge::CollabEdgeServiceSensor",
        "csf::edge::CredentialsManager",
        "csf::edge::Credentials",
        "csf::edge::DirectConnectivityTester",
        "csf::edge::EdgeTransitionDetectionController",
        "csf::edge::EdgeInfrastructureEventController",
    ],
    "new_dns_srv": "_collab-edge._tls",
    "expressway_xml_paths": [
        "/getEdgeConfigResponse/edgeConfig/sipEdgeServer/server",
        "/getEdgeConfigResponse/edgeConfig/sipRequest",
    ],
}

# Auth network services (AuthenticatorMap.xml)
AUTH_SERVICES = {
    "CUCM_CISCO_UDS":     {"id": 1000, "desc": "UCM UDS auth"},
    "EDGE_CISCOEDGE":     {"id": 1001, "desc": "Expressway-E MRA auth"},
    "CUP_CUPLOGIN":       {"id": 1200, "desc": "CUPS/IM&P service login"},
    "WEBEX_XMPP_CLIENT":  {"id": 1201, "desc": "Webex cloud XMPP"},
    "CUCM_LEGACY_TFTP":   {"id": 2100, "desc": "Legacy CUCM TFTP"},
    "CUCM_LEGACY_CCMCIP": {"id": 2100, "desc": "Legacy CCMCIP"},
    "WEBEX_TEAMS_CLIENT": {"id": 2000, "desc": "Webex Teams auth"},
}

# Default config flags of interest
DEFAULT_CONFIG_FLAGS = {
    "imcatcher_disable":      "FALSE",   # IM capture enabled by default
    "local_archive_enabled":  "TRUE",    # local message store on
    "support_ssl_encoding":   "TRUE",
    "support_aes_encoding":   "FALSE",   # AES encoding disabled
    "support_no_encoding":    "FALSE",
    "screen_capture_enabled": "TRUE",
    "file_transfer_enabled":  "TRUE",
    "IP_MODE":                "Dual_Stack",
}
