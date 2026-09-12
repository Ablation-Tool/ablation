"""
Fortinet FortiFone Softclient for Desktop v8.0.0 (build 67) RE
Source: FortiFone_linux_v8.0_b67.deb (106MB amd64 Electron app)
Package: fortifone 8.0.0~b67~1784584593~GA-0067
Install path: /opt/FortiFone/
Depends: libgtk-3-0, libnss3, libxss1, Electron runtime
Extracted: dpkg-deb -x -> opt/FortiFone/resources/app.asar -> npx asar extract
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":          "Fortinet FortiFone Softclient for Desktop",
    "version":          "8.0.0 build 67",
    "build_date_epoch": "1784584593 (approx July 2026)",
    "format":           "Electron amd64 .deb (Chromium runtime + Node.js)",
    "install_path":     "/opt/FortiFone/",
    "resources_path":   "/opt/FortiFone/resources/",
    "app_bundle":       "/opt/FortiFone/resources/app.asar (165MB)",
    "app_extracted":    "asar archive -> JS bundles + node_modules (fully accessible)",
    "architecture":     "x86-64 (Electron 32+ runtime)",
    "vendor_email":     "ljwang@fortinet.com (developer cert OU=FortiFone Team)",

    "key_files_in_package": {
        "server.key":               "/opt/FortiFone/resources/server.key -- RSA-2048 private key",
        "server.crt":               "/opt/FortiFone/resources/server.crt -- self-signed X.509 cert",
        "fortifone_desktop_c2_v0.bin": "/opt/FortiFone/resources/fortifone_desktop_1_c2_v0.bin -- password-protected PKCS#12",
        "app.asar":                 "/opt/FortiFone/resources/app.asar -- full JS source",
    },

    "local_server": {
        "bind":     "localhost:23586",
        "protocol": "HTTPS + WebSocket upgrade",
        "tls_cert": "self-signed CN=localhost issued by Fortinet Inc. OU=FortiFone Team",
        "valid":    "2025-08-18 to 2035-08-16",
        "fingerprint": "8E:42:8D:C4:69:59:FA:AB:D4:0C:92:3E:5F:4F:30:E1:0E:8D:9E:16",
    },
}


# ---------------------------------------------------------
# FFF-F01: Hardcoded TLS private key shipped in all installations
# ---------------------------------------------------------
FFF_F01_HARDCODED_TLS_KEY = {
    "id":       "FFF-F01",
    "product":  "Fortinet FortiFone 8.0.0 (all Linux installations)",
    "severity": "MEDIUM -- key is used only for localhost server; real TLS PKI impact is limited, but impersonation and inspection of local HTTPS traffic is enabled",
    "class":    "Hardcoded cryptographic key (CWE-321)",
    "cwe":      "CWE-321 (Use of Hard-coded Cryptographic Key)",

    "description": (
        "FortiFone 8.0.0 .deb ships a 2048-bit RSA TLS private key (server.key) and self-signed "
        "certificate (server.crt) under /opt/FortiFone/resources/. "
        "These are identical across ALL installations. The key is loaded at startup by "
        "fvLocalHttpsServer.js to create an HTTPS server at localhost:23586. "
        "The private key is world-readable (rw-rw-r--) in the installed package. "
        "Signed by an internal Fortinet developer identity (emailAddress=ljwang@fortinet.com), not a CA."
    ),

    "key_details": {
        "algorithm":     "RSA-2048",
        "subject":       "C=CA, ST=Ontario, L=Ottawa, O=Fortinet Inc., OU=FortiFone Team, CN=localhost",
        "issuer":        "Self-signed",
        "valid_from":    "2025-08-18T18:46:14Z",
        "valid_to":      "2035-08-16T18:46:14Z",
        "fingerprint":   "8E:42:8D:C4:69:59:FA:AB:D4:0C:92:3E:5F:4F:30:E1:0E:8D:9E:16",
        "file_perms":    "rw-rw-r-- (world-readable)",
        "source_code":   "fvLocalHttpsServer.js:17 -- fs.readFileSync(path.join(app.getAppPath(), '../../resources/server.key'))",
    },

    "impact": (
        "Any local process that reads /opt/FortiFone/resources/server.key can impersonate "
        "the FortiFone local server to any other local process that trusts the shared certificate. "
        "Combined with FFF-F02, enables a malicious local process to position itself as a "
        "man-in-the-middle on the Teams integration WebSocket channel and intercept/inject IPC messages."
    ),

    "remediation": "Generate a per-installation keypair at first run (node crypto.generateKeyPairSync). Store in OS keychain or protected app data directory, not in the world-readable package installation path.",
}


# ---------------------------------------------------------
# FFF-F02: Unauthenticated WebSocket IPC bridge exposes credential theft and call fraud
# ---------------------------------------------------------
FFF_F02_UNAUTH_WEBSOCKET_IPC = {
    "id":       "FFF-F02",
    "product":  "Fortinet FortiFone 8.0.0 (Teams integration or HEADLESS mode)",
    "severity": "HIGH -- unauthenticated local WebSocket enables SIP/JWT credential theft and arbitrary call initiation without user interaction",
    "class":    "Missing Authentication for Critical Function (CWE-306)",
    "cwe":      "CWE-306 (Missing Authentication for Critical Function)",

    "description": (
        "FortiFone exposes an unauthenticated HTTPS/WebSocket server at wss://localhost:23586/headless "
        "for Microsoft Teams integration and HEADLESS mode. "
        "The WebSocket has no authentication layer. Any process on localhost can connect and: "
        "(1) extract SIP PINs, JWT session tokens, UC refresh tokens, and PBX server addresses "
        "by sending {req: 'fvUserAccount'}; "
        "(2) initiate arbitrary phone calls by sending {ipcMsg: 'user_make_call', args: [...]}; "
        "(3) delete user accounts, stop call service, or inject any other registered ipcMain message. "
        "The server is active when the user enables Teams integration OR when FortiFone runs in HEADLESS mode."
    ),

    "activation_conditions": {
        "teams_integration": "User enables 'Enable Teams Integration' preference -> server starts at :23586",
        "headless_mode":     "FortiFone launched with HEADLESS app_gui_mode (e.g. Teams headless deployment)",
        "note":              "Server does NOT start in default GUI mode without Teams integration enabled",
    },

    "server_details": {
        "bind":       "localhost:23586 (increments on EADDRINUSE)",
        "tls":        "Hardcoded server.key/server.crt (see FFF-F01)",
        "http_route": "GET /trust -> 200 {message: 'Connection trusted.'}",
        "ws_route":   "GET /headless (WebSocket upgrade)",
        "source":     "fortivoiceShared/fvLocalHttpsServer.js + fvHeadlessWebSocketServer.js",
    },

    "credential_theft_path": {
        "request":    '{"req": "fvUserAccount"}',
        "response":   "Full account object including cfg_data AND secure_data",
        "secure_data_fields": {
            "pin":              "User PIN (credential for FortiFone account login)",
            "sip_pin":          "SIP authentication PIN",
            "uc_refresh_token": "Fortinet UC platform JWT refresh token",
            "jwt.token":        "Active JWT session token",
            "session_magic":    "Session integrity token",
        },
        "code":       "fvUserData.js:1509-1514 -- getData() returns { cfg_data: this.data, secure_data: this.secure_data }",
    },

    "ipc_injection_path": {
        "mechanism":  "Any JSON message with {ipcMsg: <handler_name>, args: [...]} emits to Electron ipcMain",
        "code":       "fvHeadlessWebSocketServer.js:130-131 -- ctx.ipcMain.emit(obj.ipcMsg, new SyntheticIpcMainEvent('Web'), ...obj.args)",
        "operations": {
            "user_make_call":         "Initiate outbound SIP call to any number without user interaction",
            "user_init_headless_account": "Configure/overwrite account settings",
            "user_stop_call_service": "Terminate active call service (DoS)",
            "user_delete_account":    "Delete user account configuration",
            "save_password":          "Trigger password manager write IPC (main.js:3682)",
            "get_password":           "Trigger password manager read IPC (main.js:3688)",
        },
        "no_allowlist": "No restriction on which ipcMsg values are accepted -- any registered ipcMain handler is reachable",
    },

    "info_broadcast": {
        "description": "On new connection, server pushes last known IPC state to client. IPC_OF_INTEREST events are forwarded to ALL connected clients in real-time.",
        "events_forwarded": [
            "main_sip_account_info (extension, display_name, sip_server)",
            "main_httpsession_status (login success/failure + JWT token + server address)",
            "main_phone_info",
            "main_session_status",
            "main_audio_device_status",
            "main_rtc_configuration (ICE servers, STUN/TURN config)",
            "main_account_status",
        ],
    },

    "attack_scenario": {
        "attacker":  "Any local process or user (no elevated privileges required)",
        "step_1":    "Connect to wss://localhost:23586/headless (ignore TLS cert warning -- self-signed)",
        "step_2":    'Send {"req": "fvUserAccount"} -- receive SIP PIN, JWT tokens, PBX server address',
        "step_3":    'Send {"ipcMsg": "user_make_call", "args": [{"account_id": 1, "callee": "+19000000000"}]} -- FortiFone dials a premium number',
        "privilege":  "None -- any process running as the logged-in user",
        "prerequisite": "FortiFone running with Teams integration enabled or in HEADLESS mode",
    },

    "remediation": (
        "Require a per-session HMAC token (generated at startup, stored in OS keychain, distributed "
        "to the Teams extension via a secure handshake) on every WebSocket message. "
        "Add an allowlist of permitted ipcMsg values at the WebSocket handler. "
        "Restrict fvUserAccount response to exclude secure_data -- return only display-safe fields. "
        "Bind to a named pipe instead of a TCP port to eliminate cross-process access."
    ),
}


# ---------------------------------------------------------
# FFF-F03: PKCS12 bundle with unknown password shipped in package
# ---------------------------------------------------------
FFF_F03_PKCS12_BUNDLE = {
    "id":       "FFF-F03",
    "product":  "Fortinet FortiFone 8.0.0",
    "severity": "INFO -- purpose not yet determined; PKCS12 is password-protected so impact is bounded by password strength",
    "class":    "Sensitive file in distribution package",

    "description": (
        "A PKCS#12 certificate bundle (fortifone_desktop_1_c2_v0.bin, 5.2KB) is shipped in the package "
        "under /opt/FortiFone/resources/. "
        "The file is password-protected (MAC: sha256, 2048 iterations). "
        "Its purpose is not determined by static analysis -- 'c2' naming convention suggests "
        "it may be a code-signing or CA certificate bundle. Common Fortinet passwords were tested "
        "without success. JavaScript source references to this filename were not found in the extracted "
        "ASAR bundle, suggesting it may be loaded by native code or by a bundled shell script."
    ),

    "file_details": {
        "path":      "/opt/FortiFone/resources/fortifone_desktop_1_c2_v0.bin",
        "size":      "5200 bytes (5.2KB)",
        "magic":     "30 82 14 7f (DER SEQUENCE -- PKCS#12 PFX)",
        "mac_algo":  "SHA-256",
        "mac_iter":  "2048",
        "passwords_tried": ["(empty)", "fortinet", "FortiFone", "Fortinet123", "admin", "S3crtMsG", "password", "1234"],
    },

    "pending": "Password recovery via hashcat (extract MAC from DER, convert to pfx2john, crack with rockyou + Fortinet-specific rules)",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "asar_extracted":  "COMPLETE -- 165MB app.asar -> JS source fully readable",
    "server_key":      "COMPLETE -- FFF-F01 confirmed; 2048-bit RSA private key shipped identical in all installs",
    "websocket_auth":  "COMPLETE -- FFF-F02 confirmed; no authentication; getData() leaks secure_data",
    "pkcs12_bin":      "PARTIAL -- FFF-F03; purpose and password unknown; pending hashcat",
    "ipc_surface":     "COMPLETE -- all ipcMain handlers reachable via WebSocket ipcMsg injection",
    "sip_stack":       "NOT ANALYZED -- bundle-pbx.js / bundle-assistant.js SIP protocol implementation",
    "update_mechanism": "NOT ANALYZED -- electron-builder update flow",

    "unique_findings": [
        "FFF-F01: RSA-2048 private key identical across all FortiFone 8.0 installations (world-readable in /opt)",
        "FFF-F02: Unauthenticated wss://localhost:23586/headless -> SIP PIN + JWT token theft + call fraud (Teams/HEADLESS mode)",
        "FFF-F03: PKCS#12 bundle (purpose unknown) shipped in distribution package",
        "getData() returns full secure_data including sip_pin, uc_refresh_token, jwt.token to any connected WebSocket client",
        "No allowlist on ipcMsg -> any Electron ipcMain handler accessible remotely from localhost",
    ],
}
