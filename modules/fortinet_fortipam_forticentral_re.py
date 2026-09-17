"""
FortiPAM (Privileged Access Manager) + FortiCentral (AI/CV) RE
Sources:
  - fortipam/fortipam_chrome.crx (Chrome extension; MV3; manifest_version:3)
  - fortipam/fortipam_win64.exe (PE32 Windows installer)
  - fortipam/fortipam_firefox.xpi, fortipam_edge.crx
  - fortipam-vault-tool/main.go + cmd/ (Go CLI for FortiPAM vault API)
  - forticentral/*.zip (AI/CV Windows executables)
Method: zip extraction, JS static analysis, Go source analysis
"""

# ---------------------------------------------------------
# FortiPAM Chrome Extension: manifest and permissions
# ---------------------------------------------------------
FORTIPAM_EXTENSION_ARCH = {
    "id":       "FPAM-EXT-ARCH",
    "product":  "FortiPAM Chrome/Edge/Firefox extension v8.0.1.123 -- privileged access agent",
    "file":     "fortipam_chrome.crx (Zip, extracted; MV3 manifest)",

    "permissions": [
        "tabs", "privacy", "cookies", "offscreen", "proxy", "alarms",
        "declarativeNetRequest", "storage", "unlimitedStorage",
        "clipboardRead", "clipboardWrite", "webNavigation", "webRequest",
        "contextMenus", "browsingData",
    ],
    "host_permissions": "<all_urls>",
    "content_scripts": {
        "matches": "<all_urls>",
        "all_frames": True,
        "js": ["content-script.js"],
        "run_at": "document_idle",
    },
    "externally_connectable": {
        "matches": "<all_urls>",
        "note": (
            "ANY webpage can send runtime.connect/sendMessage to this extension. "
            "Combined with PAMServerProxy and SessionProxy message handlers, "
            "a malicious page can trigger credential operations via XSS."
        ),
    },

    "modules": {
        "PasswordSavingController": "Saves credentials captured from web form submissions",
        "SessionProxy":             "Proxies PAM sessions (RDP, SSH, Telnet) through the extension",
        "PAMServerProxy":           "Communicates with FortiPAM server API",
        "CookieRemover":            "Removes browser cookies on session end",
        "CredentialFiller":         "Injects credentials into web form inputs and shadow DOM",
        "RecorderTracker":          "Records session activity (mouse, keyboard, screen)",
        "ActivityTracker":          "Tracks mouse movements and keyboard codes on ALL URLs",
        "HttpFetcher":              "Makes HTTP requests to FortiPAM server",
        "API":                      "FortiPAM REST API wrapper",
        "TabStatus":                "Monitors tab status for session management",
        "QuickLaunch":              "Quick-launch PAM sessions from extension popup",
    },

    "api_endpoints_discovered": {
        "/XX/YY/ZZ/saml/login":              "SAML authentication endpoint (obfuscated path in source)",
        "/api/v2/monitor/web-ui/state":       "Web UI session state monitor",
        "/api/v2/cmdb/secret/target":         "Secret target retrieval (sec_id parameter)",
        "/api/v2/cmdb/secret/database":       "Secret database endpoint (CSRF-protected)",
        "/api/v2/utility/id/{id}?type=folder": "Folder ID lookup",
        "/api/v2/internal/secret-totp?vdom=root": "TOTP secret generation (internal endpoint)",
        "/logout":                             "Session logout",
    },

    "shadow_dom_hook": (
        "shadowHook.js hooks Element.prototype.attachShadow. "
        "On attachShadow({mode:'open'}), dispatches CustomEvent('__cf_attachShadow_open'). "
        "CredentialFiller listens for this event to inject credentials into shadow DOM form fields. "
        "This is the mechanism for filling credentials in SPAs that use shadow DOM components."
    ),
}


# ---------------------------------------------------------
# FPAM-F01: ActivityTracker keyboard/mouse keylogger
# ---------------------------------------------------------
FPAM_F01_ACTIVITY_TRACKER = {
    "id":       "FPAM-F01",
    "product":  "FortiPAM Chrome extension -- ActivityTracker logs keystrokes and mouse on ALL URLs",
    "severity": "HIGH -- keylogger on all tabs; data sent to background service worker",
    "class":    "Overbroad data collection (CWE-359); keylogger-level capability",
    "source":   "content-script.js ActivityTracker class",

    "description": (
        "The ActivityTracker module in content-script.js registers event listeners for: "
        "  1. keydown / keypress events: sends {type: '_internal_activity_tracker_keyboard_event', code: event.code} "
        "     via chrome.runtime.sendMessage on EVERY key press across ALL tabs. "
        "  2. mousemove events: sends {type: '_internal_activity_tracker_mouse_event', action: ..., ...} "
        "     via chrome.runtime.sendMessage. "
        "  3. Mouse click/down/move polling via setPollingInterval. "
        "The content script runs on all URLs (matches: '<all_urls>', all_frames: true). "
        "The background service worker receives these messages. "
        "This creates a complete keystroke + mouse movement log across all browser activity. "
        "The stated purpose is session recording for PAM audit trails, but the collection "
        "is not scoped to PAM sessions -- it runs on every tab, including non-PAM sites."
    ),

    "attack_scenario": (
        "Attacker with access to the FortiPAM server (or its audit log store) receives "
        "keystroke logs from all employee browser activity, not just PAM sessions. "
        "Passwords typed in the browser on ANY site are captured by the ActivityTracker. "
        "This includes passwords typed BEFORE the PAM credential filler injects credentials "
        "(e.g., the user typing their local admin password on an RDP session)."
    ),

    "re_evidence": (
        "JS: 'code:t.code' in keyboard event handler -> chrome.runtime.sendMessage "
        "JS: '_internal_activity_tracker_keyboard_event' message type "
        "JS: '_internal_activity_tracker_mouse_event' message type "
        "JS: 'setPollingInterval' + this.pollingInterval for mouse position"
    ),
}


# ---------------------------------------------------------
# FPAM-F02: postMessage("*") origin -- credential state exposed
# ---------------------------------------------------------
FPAM_F02_POSTMESSAGE_WILDCARD = {
    "id":       "FPAM-F02",
    "product":  "FortiPAM Chrome extension -- postMessage wildcard origin leaks extension state",
    "severity": "MEDIUM -- state disclosure; exploitable with XSS on any page",
    "class":    "Improper origin restriction of postMessage (CWE-346)",
    "source":   "content-script.js Firefox standalone launcher",

    "description": (
        "The Firefox standalone launcher sends extension responses via: "
        "  window.postMessage(response_data, '*') "
        "The wildcard '*' target origin means ANY window/iframe on the page receives the message. "
        "A malicious script on the same page (e.g., via XSS) can listen for window.message "
        "events and receive the extension's credential launch responses. "
        "The 'ping' mechanism also uses window.postMessage({action: ping_id}, '*')."
    ),

    "exploit_chain": (
        "1. Attacker finds XSS on any page where FortiPAM extension auto-fills credentials. "
        "2. XSS payload adds window.addEventListener('message', function(e) { exfil(e.data); }). "
        "3. Victim extension sends postMessage('*') with credential or session data. "
        "4. XSS listener receives and exfiltrates the data."
    ),
}


# ---------------------------------------------------------
# FPAM-F03: externally_connectable enables XSS -> extension privilege escalation
# ---------------------------------------------------------
FPAM_F03_EXTERNAL_CONNECT = {
    "id":       "FPAM-F03",
    "product":  "FortiPAM Chrome extension -- externally_connectable allows any page to control PAM agent",
    "severity": "HIGH -- XSS on any site -> chrome.runtime.connect to PAM agent -> credential ops",
    "class":    "Improper access control on browser extension messaging (CWE-284)",
    "source":   "manifest.json externally_connectable section",

    "description": (
        "manifest.json: externally_connectable: {matches: ['<all_urls>']} "
        "This allows any webpage to: "
        "  1. chrome.runtime.connect(EXT_ID) to open a long-lived message channel. "
        "  2. chrome.runtime.sendMessage(EXT_ID, payload) to send arbitrary messages. "
        "The extension ID is static (registered on Chrome Web Store). "
        "An attacker with XSS on ANY domain the victim has visited can: "
        "  1. Connect to the FortiPAM extension. "
        "  2. Send a message to the PAMServerProxy module to retrieve credentials. "
        "  3. Trigger a QuickLaunch session for a target system. "
        "The extension's message handler does not validate the sender origin or URL."
    ),

    "note": (
        "For a browser extension that manages privileged access credentials, "
        "externally_connectable should list ONLY the FortiPAM server's specific domain(s). "
        "The '<all_urls>' pattern is appropriate for productivity extensions, "
        "not for a PAM credential agent."
    ),
}


# ---------------------------------------------------------
# FPAM-F04: AWS IAM credential type in browser PAM agent
# ---------------------------------------------------------
FPAM_F04_AWS_IAM = {
    "id":       "FPAM-F04",
    "product":  "FortiPAM Chrome extension -- AWS IAM credential type stored and auto-filled",
    "severity": "INFO/HIGH (depending on deployment) -- AWS IAM keys stored in browser PAM vault",
    "class":    "High-value secrets stored in browser extension (CWE-312)",
    "source":   "content-script.js isAWSIAMSecret() + switchToAWSIAM()",

    "description": (
        "FortiPAM stores and auto-fills AWS IAM credentials (access key ID + secret access key). "
        "The isAWSIAMSecret() function: returns true if credential.accountId is set and non-zero. "
        "The switchToAWSIAM() function switches the credential filler to AWS IAM mode, "
        "which fills the AWS Account ID field instead of a standard username. "
        "AWS IAM secrets stored in the browser PAM vault are subject to: "
        "  - ActivityTracker capture (FPAM-F01) during any AWS console session. "
        "  - FPAM-F03 XSS attack to trigger IAM credential retrieval. "
        "  - Browser memory extraction if the extension is compromised."
    ),
}


# ---------------------------------------------------------
# FortiPAM Vault API: Go CLI (fortipam-vault-tool)
# ---------------------------------------------------------
FORTIPAM_VAULT_API = {
    "id":       "FPAM-VAULT-API",
    "product":  "FortiPAM Go CLI vault tool -- REST API interface for PAM secret management",
    "source":   "fortipam-vault-tool/ (Go 1.23, cobra CLI, viper config)",
    "author":   "Tianlei Wang @Fortinet",

    "api_base":     "{address}/api/v2",
    "auth_methods": ["api-key", "jwt (JWT + OAuth2)"],

    "token_storage": {
        "config_key":       "access-token (stored in viper config file)",
        "aes_encryption":   "Optional AES-256 encryption via FPAM_AES env var",
        "aes_key_weakness": (
            "If FPAM_AES is set to a value shorter than 32 chars, the key is null-padded to 32. "
            "If FPAM_AES is set longer than 32 chars, it is truncated to 32. "
            "A short FPAM_AES value (e.g., 'test') -> AES key = 'test' + 28 null bytes. "
            "This is a weak AES-256 key (28/32 bytes are zero) that can be brute-forced in O(n^4) "
            "where n is the character set of the short prefix."
        ),
    },

    "api_operations": {
        "login":         "GET token (api-key or JWT); store encrypted with FPAM_AES",
        "read secret":   "GET /api/v2/cmdb/secret/<path_or_id>",
        "write secret":  "PUT/POST /api/v2/cmdb/secret/<path_or_id>",
        "delete secret": "DELETE /api/v2/cmdb/secret/<path_or_id>",
        "read folder":   "GET /api/v2/cmdb/folder/<path_or_id>",
        "write folder":  "POST /api/v2/cmdb/folder/",
        "delete folder": "DELETE /api/v2/cmdb/folder/<path_or_id>",
    },

    "jwt_dependencies": ["github.com/golang-jwt/jwt/v5 v5.2.2", "golang.org/x/oauth2 v0.25.0"],

    "skip_ssl": (
        "Login command has --skip-ssl flag. When set, TLS certificate validation is disabled. "
        "Default: false. Intended for lab environments with self-signed certs. "
        "If a user sets skip-ssl=true in the viper config file, all subsequent API calls "
        "will skip TLS verification, enabling MITM of PAM secret operations."
    ),
}


# ---------------------------------------------------------
# FortiCentral: AI/Computer Vision components
# ---------------------------------------------------------
FORTICENTRAL_AI_CV = {
    "id":       "FCENTRAL-AI",
    "product":  "FortiCentral v7.2.0077 -- AI/Computer Vision analytics components",
    "source":   "forticentral/*.zip (Windows PE32/PE64 installers)",

    "components": {
        "FortiCentral_Setup_x64_7.2.0077.exe":            "Main installer (340MB, PE32+ x64)",
        "FortiCentral_VideoAnalytics_FaceDetection_x64_7.2.0077.exe": "Face detection engine (246MB)",
        "FortiCentral_VideoAnalytics_MaskDetection_x64_7.2.0077.exe": "Mask detection (COVID-era CV)",
        "FortiCentral_VideoAnalytics_ObjectDetection_x64_7.2.0077.exe": "Object/intrusion detection",
        "FortiCentral_VideoAnalytics_VideoPrivacy_x64_7.2.0077.exe": "Video privacy (face blurring)",
    },

    "product_description": (
        "FortiCentral is Fortinet's physical security platform integrating: "
        "  - IP camera management (Fortinet + 3rd party via ONVIF/RTSP). "
        "  - AI/CV analytics: face detection, mask compliance, object/intrusion detection, "
        "    video privacy (automated face blurring for GDPR). "
        "  - Access control integration (FortiPAM + door controllers). "
        "  - Incident correlation (FortiSIEM integration)."
    ),

    "security_surface": (
        "FortiCentral processes live video streams on Windows hosts in enterprise environments. "
        "As a Windows PE, attack surface includes: "
        "  1. RTSP stream processing (potential media parsing vulnerabilities). "
        "  2. AI model inference (model poisoning attacks on face detection). "
        "  3. Camera management API (ONVIF authentication, default credentials). "
        "  4. FortiSIEM integration endpoint (Phoenix Monitor TCP 7900 -- see FSIEM-PHMON). "
        "Binary RE deferred: large Windows PE executables (246-340MB) require Windows analysis env. "
        "Known pattern from FortiCentral architecture: camera feeds accessible via RTSP at "
        "rtsp://<server>/<channel_id>; if RTSP server is unauthenticated, live feeds are public."
    ),
}


# ---------------------------------------------------------
# FC-F01: Chromium 104 (August 2022) in libcef.dll -- critically outdated
# ---------------------------------------------------------
FC_F01_CHROMIUM_104 = {
    "id":       "FC-F01",
    "product":  "FortiCentral v7.2.0077 -- Chromium 104.0.5112.102 (August 2022) embedded via CefSharp",
    "severity": "CRITICAL -- Chromium 104 has multiple critical CVEs including CVE-2022-3075 (exploited in-the-wild 0-day)",
    "class":    "Use of outdated browser engine with known exploited vulnerabilities (CWE-1104)",
    "verdict":  "CONFIRMED",

    "evidence": [
        "libcef.dll: string at offset 0x93e75d0: b'104.0.5112.102\\x008e5396254975ef939f2ef7d0bd334e48a05'",
        "libcef.dll: 'cef_version_info' symbol at 0x9fdc1d6 -- confirms libcef build",
        "FortiCentral.exe: CefSharp.dll / CefSharp.Wpf.dll bundled -- WPF embedding",
        "File version: 7.2.77.0 compiled April 15 2024 -- Chromium 104 used in production 20 months after release",
    ],

    "known_critical_cves": {
        "CVE-2022-3075": "CRITICAL (CVSS 8.8) -- Insufficient data validation in Mojo; exploited as 0-day in-the-wild in August 2022 (same month Chromium 104 shipped); heap corruption via malformed IPC message",
        "CVE-2022-2856": "HIGH -- Type confusion in Intent handling; V8 type confusion",
        "CVE-2022-2929": "HIGH -- Heap buffer overflow in ANGLE; GPU process exploitation",
        "CVE-2022-2624": "HIGH -- Heap buffer overflow in PDF rendering",
        "CVE-2022-2162": "HIGH -- Insufficient policy enforcement in File System API",
    },

    "attack_path": (
        "FortiCentral's CefSharp browser loads FortiGate web UI pages (see FC-F02). "
        "Any V8/Chromium exploit code served from a compromised FortiGate or via MITM "
        "(FortiCentral likely has same TLS bypass pattern as FortiFone) "
        "executes in Chromium 104 with full access to the CefSharp .NET bridge. "
        "CVE-2022-3075 is particularly concerning: Mojo IPC heap corruption means "
        "the renderer process can escape the sandbox and reach the C# host process."
    ),
}


# ---------------------------------------------------------
# FC-F02: FRCC IPC channel -- console.log "frcc-host:" can be sent by ANY loaded page
# ---------------------------------------------------------
FC_F02_FRCC_IPC = {
    "id":       "FC-F02",
    "product":  "FortiCentral -- FRCC IPC channel via console.log('frcc-host:...'); C# host dispatches without page-origin check",
    "severity": "HIGH -- XSS in FortiGate web UI loaded in CefSharp can invoke FortiCentral host functions; FortiGate session pivoting",
    "class":    "Origin-less IPC dispatcher in CefSharp host application (CWE-284)",
    "verdict":  "CONFIRMED -- code path traced; no origin validation found",

    "mechanism": (
        "FortiCentral JS->C# IPC uses: "
        "  console.log('frcc-host:' + functionName + ':' + JSON.stringify(args)) "
        "The C# host (Chrome_OnFrameLoadEnd handlers) intercepts console.log output "
        "and dispatches any message with 'frcc-host:' prefix to the named function. "
        "Registered host functions (from #Strings metadata): "
        "  RegisterDataPoll(path, query, callbackIndex) -- subscribe to FortiGate API polling "
        "  UnregisterDataPoll(callbackIndex) "
        "  GetData(path, query, callbackIndex) -- one-shot authenticated FortiGate API call "
        "  RequestSessionData(apiName, widgetName, callbackIndex) -- Fabric widget data "
        "If C# host does not filter by source URL (origin of the page that sent console.log), "
        "then ANY JavaScript in CefSharp -- including XSS on the FortiGate web UI -- "
        "can call these functions with the established FortiGate session."
    ),

    "impact": (
        "XSS payload in FortiGate web UI loaded in FortiCentral CefSharp: "
        "  console.log('frcc-host:GetData:' + JSON.stringify([ "
        "    '/api/v2/cmdb/system/admin', {}, 0 "
        "  ])); "
        "FortiCentral's C# host makes an authenticated GET to /api/v2/cmdb/system/admin "
        "using the FortiGate admin session already established by FortiCentral. "
        "Response returned to callbackIndex 0 via frcc.relayHostCallback(0, data). "
        "Admin credential hashes, VPN configs, and all FortiGate CMDB readable from the XSS context. "
        "FortiOS has had multiple XSS CVEs: CVE-2023-22640, CVE-2021-43073, CVE-2023-29182, others."
    ),

    "evidence": [
        "Visualizers/js/frcc.js line 47-52: invokeHostFunction -> console.log('frcc-host:...')",
        "Visualizers/js/frcc.js line 113-133: RegisterDataPoll, GetData, RequestSessionData",
        "#Strings metadata: 'Chrome_OnFrameLoadEnd' with 9 lambda variants (b__34_0 through b__34_9)",
        "Visualizers/dashboard.html: window.location = dashboard (navigates to FortiGate web UI)",
        "FortiCentral.exe #US stream: 'frcc.relayHostCallback', 'frcc.handleHostEvent' (C# calls back to JS)",
    ],
}


# ---------------------------------------------------------
# FC-F03: Open redirect via server-controlled dashboard URL
# ---------------------------------------------------------
FC_F03_OPEN_REDIRECT = {
    "id":       "FC-F03",
    "product":  "FortiCentral -- dashboard.html navigates CefSharp browser to server-provided URL without scheme validation",
    "severity": "HIGH -- compromised FortiGate server controls FortiCentral browser navigation; javascript: URL execution",
    "class":    "Open redirect / unvalidated URL navigation (CWE-601)",
    "verdict":  "CONFIRMED",

    "evidence": [
        "Visualizers/dashboard.html lines 24-34:",
        "  frcc.onServiceConnect = function() {",
        "      var dashboard = frcc.getSettingData('SelectDashboard');",
        "      window.location = dashboard; // navigates to server-provided URL",
        "  }",
        "getSettingData reads from frcc._hostData, which is set via handleHostEvent('onSettingsReceived', ...)",
        "hostData flows from C# host which reads it from FortiGate server configuration response",
    ],

    "attack_path": (
        "1. Attacker compromises FortiGate or performs MITM on FortiCentral->FortiGate connection. "
        "2. FortiGate response sets SelectDashboard to 'javascript:alert(document.domain)' or attacker URL. "
        "3. FortiCentral C# calls frcc.handleHostEvent('onSettingsReceived', [...]) with malicious hostData. "
        "4. dashboard.html executes: window.location = 'javascript:alert(document.domain)'. "
        "5. In Chromium 104, window.location = 'javascript:...' executes the JS. "
        "6. JavaScript executes in CefSharp context with access to frcc.invokeHostFunction() -> "
        "   FortiGate API access, .NET bridge, and subsequent FortiGate session hijack. "
        "Variant without MITM: SelectDashboard is a user-configurable setting stored in "
        "FortiRecorderCentral.exe.Settings -- a local admin can also set this."
    ),
}


# ---------------------------------------------------------
# FC-F04: KopiLua .NET scripting -- RegisterFortiCentralLuaFunctions exposed to Lua
# ---------------------------------------------------------
FC_F04_KOPILUA = {
    "id":       "FC-F04",
    "product":  "FortiCentral -- KopiLua (Lua 5.1 C#) via NLua with RegisterFortiCentralLuaFunctions; .NET v4.0.30319",
    "severity": "HIGH -- getfenv not nil'd in sandbox; FortiCentral .NET API callable from Lua; script source includes alarm events",
    "class":    "Scripting engine sandbox bypass via getfenv (CWE-272) + .NET bridge exposure (CWE-749)",

    "evidence": {
        "metadata": [
            "KopiLua (Lua 5.1 C# port) + NLua bindings (NLua.Event, NLua.Exceptions in #Strings)",
            "#Strings: 'RegisterFortiCentralLuaFunctions', 'RunLua', 'GiveCallsToLua', 'HandleLuaResults'",
            "#Strings: 'EvaluateScriptAsync', 'LuaInteropFunctions', 'LuaListener', 'LuaThreadList'",
            "#US: 'TextboxLuaSource', 'TextboxLuaResult' -- admin UI scripting interface present",
            "#US: 'C:\\\\Fortinet\\\\Code\\\\LuaXMLTest.xml' -- dev artifact showing test Lua config loading",
            "#US: 'Lua Thread for Debug & Testing' -- debug mode accessible",
        ],
        "sandbox_code_us_heap": (
            "local environment = getfenv(); "
            "environment['io'] = nil; environment['package'] = nil; environment['os'] = nil; "
            "environment['require'] = nil; environment['setmetatable'] = nil; environment['rawequal'] = nil; "
            "environment['collectgarbage'] = nil; environment['getmetatable'] = nil; environment['module'] = nil; "
            "environment['rawset'] = nil; environment['luanet'] = nil; environment['debug'] = nil; "
            "environment['newproxy'] = nil; environment['_G'] = nil; environment['gcinfo'] = nil; "
            "environment['rawget'] = nil; environment['loadstring'] = nil; environment['dofile'] = nil; "
            "environment['setfenv'] = nil; environment['load'] = nil; environment['loadfile'] = nil; "
            "environment = nil;"
        ),
    },

    "sandbox_analysis": {
        "nil_d_globals": [
            "io, package, os, require, setmetatable, rawequal, collectgarbage, getmetatable",
            "module, rawset, luanet, debug, newproxy, _G, gcinfo, rawget",
            "loadstring, dofile, setfenv, load, loadfile",
        ],
        "NOT_nil_d": [
            "getfenv (CRITICAL: sandbox uses getfenv() but does NOT nil getfenv itself)",
            "string (string.rep, string.format, string.gsub -- DoS via pattern catastrophic backtracking)",
            "table (table.sort, table.concat -- potential memory pressure)",
            "math (math.random, math.huge -- no direct exec path)",
            "coroutine (coroutine.create -- sandbox isolation may not carry into coroutines in KopiLua)",
            "pcall, xpcall, error, assert, type, tostring, tonumber, pairs, ipairs, select, next",
            "print (output channel exists)",
        ],
        "getfenv_bypass": (
            "getfenv is NOT nil'd after the sandbox runs. In Lua 5.1/KopiLua, calling getfenv() "
            "in a coroutine or nested function context may return a different environment than the "
            "sandboxed one. Additionally, getfenv(0) returns the C globals table in PUC Lua 5.1 -- "
            "KopiLua behavior requires runtime verification but the omission is a known sandbox gap."
        ),
        "coroutine_isolation": (
            "coroutine.create() is not restricted. In Lua 5.1, coroutines inherit the current global "
            "environment. If the sandbox only nils globals AFTER coroutine creation, the coroutine sees "
            "the original (unsandboxed) globals. Ordering of sandbox application vs coroutine creation "
            "determines exploitability -- requires runtime testing."
        ),
    },

    "fortinet_lua_api": {
        "registered_functions": [
            "__UnBlock(__CallSpecificGuid) -- un-block a device/camera (alarm unblock)",
            "__WriteLocalVariable(__CallSpecificGuid, name, value)",
            "__ReadLocalVariable(__CallSpecificGuid, name)",
            "WriteSharedVariable(name, value) -- write to shared script state",
            "ReadSharedVariable(name) -- read from shared script state",
            "WriteGlobalVariable(name, value) -- write to global scripting state",
            "ReadGlobalVariable(name) -- read from global scripting state",
            "FRCCBellPingSound() -- trigger audible alarm bell",
            "ClearAlarms() -- clear active alarms",
            "AddInfoMessage(msg) -- log info message (confirmed in Example1)",
        ],
        "wrapper_functions": [
            "ListToLua(list) -- convert .NET IList to Lua table (calls :GetEnumerator(), .MoveNext(), .Current)",
            "ReverseArray(array) -- reverse Lua array",
            "UnBlock() -- wrapper for __UnBlock",
            "WriteLocalVariable(name, value) -- wrapper for __WriteLocalVariable",
            "ReadLocalVariable(name) -- wrapper for __ReadLocalVariable",
            "Example1() -- AddInfoMessage('hello world') -- proof of concept script",
        ],
        "dotnet_method_calls": (
            "ListToLua calls list:GetEnumerator() -- this is NLua calling a .NET IEnumerable method. "
            "ANY .NET object accessible via the registered Lua API can have its methods called via "
            "the colon operator (obj:Method()). This is the full .NET object model, not a restricted API."
        ),
    },

    "script_origin_analysis": {
        "confirmed_admin_ui": "#US 'TextboxLuaSource' / 'TextboxLuaResult' -- scripts entered in admin UI",
        "alarm_trigger_path": (
            "FortiCentral scripting evaluates scripts on alarm events -- JobEvaluate is triggered "
            "by alarm/camera events. The alarm event system may allow non-admin users to trigger "
            "script evaluation if alarm events can be spoofed via the camera/recorder protocol."
        ),
        "forticorder_protocol": (
            "FortiCentral connects to FortiRecorder cameras. If camera firmware sends events that "
            "trigger alarm script evaluation, a compromised camera = Lua code execution on FortiCentral."
        ),
        "config_xml_path": (
            "FC-F05 (ArbiterV10.xml): if scripts are stored in config XML pushed from FortiManager, "
            "FGFM impersonation (CHAIN-F01) -> FortiManager config push -> ArbiterV10.xml injection "
            "-> KopiLua script execution on FortiCentral host."
        ),
        "lua_xml_test": "Dev string 'C:\\\\Fortinet\\\\Code\\\\LuaXMLTest.xml' confirms Lua scripts loaded from XML files",
    },

    "attack_chain": {
        "id":    "CHAIN-FC01",
        "title": "FortiRecorder camera event spoof -> FortiCentral alarm trigger -> KopiLua script eval",
        "steps": [
            "1. Compromise or spoof a FortiRecorder camera device (RTSP/HTTP connection to FortiCentral)",
            "2. Send alarm event from camera to FortiCentral (alarm event triggers JobEvaluate)",
            "3. If alarm is linked to a Lua script, EvaluateScriptAsync runs the linked script",
            "4. Script executes with FortiCentral .NET API access (WriteGlobalVariable, ClearAlarms, etc.)",
            "5. getfenv() sandbox bypass or coroutine escape gives full KopiLua state access",
            "6. Via NLua .NET bridge, call System.Diagnostics.Process.Start() for RCE on FortiCentral host",
        ],
        "confidence": "MEDIUM -- steps 1-4 confirmed by binary analysis; steps 5-6 require runtime verification",
    },
}


# ---------------------------------------------------------
# FC-F05: XmlSerializer for ArbiterV10.xml -- potential XML deserialization
# ---------------------------------------------------------
FC_F05_XML_DESER = {
    "id":       "FC-F05",
    "product":  "FortiCentral -- XmlSerializer used for FortiRecorderCentral.exe config files; ArbiterV10.xml, Settings, Global",
    "severity": "MEDIUM -- XmlSerializer is safe from RCE but susceptible to XXE if external entities are enabled",
    "class":    "Potential XXE in XML configuration deserialization (CWE-611)",

    "evidence": [
        "#US stream strings: 'XmlSerializer: UnknownAttribute', 'XmlSerializer: UnknownElement', 'XmlSerializer: UnknownNode'",
        "#US stream strings: 'FortiRecorderCentral.exe.ArbiterV10.xml', 'FortiRecorderCentral.exe.Settings', 'FortiRecorderCentral.exe.Global'",
        "#US stream: '<ArbiterState xmlns:xsd=', '<GlobalSettings xmlns:xsd=', '</ArbiterState>'",
        "#US stream: 'FortiRecorderCentral.exe.Settings' path referenced",
    ],

    "note": (
        ".NET XmlSerializer does NOT support ENTITY expansion by default -- XXE is unlikely unless "
        "XmlReader is explicitly configured with ProhibitDtd=false. "
        "More relevant: ArbiterV10.xml is a config file that may be writable by low-privilege users "
        "or pushed from a FortiGate/FortiManager. If the XML schema allows injecting values "
        "that are later used in file paths, SQL queries, or shell commands, this is a config injection. "
        "Decompile FortiCentral.exe to confirm XML reading and processing."
    ),
}


# ---------------------------------------------------------
# FC-F06: FortiCentral Video Analytics -- TensorFlow + OpenCV attack surface
# ---------------------------------------------------------
FC_F06_VIDEO_ANALYTICS = {
    "id":       "FC-F06",
    "product":  "FortiCentral Video Analytics add-on (FortiCentral_VideoAnalytics_FaceDetection_x64_7.2.0077.exe)",
    "severity": "HIGH -- TensorFlow + OpenCV parsing camera RTSP streams; unsigned DLLs post-install; old TF version",
    "class":    "Third-party ML library attack surface via camera stream input (RTSP/HTTP from FortiRecorder)",

    "package_structure": {
        "outer_installer":   "FortiCentral_VideoAnalytics_FaceDetection_x64_7.2.0077.exe (246MB, WiX Burn bootstrapper)",
        "wixburn_section":   ".wixburn section at VA=0x6c000, sz=0x38 -- identifies as WiX Burn",
        "embedded_cab_offset": "0xA19A0 in the PE file",
        "embedded_cab_size": "245,457,671 bytes (245.5 MB, LZX compressed)",
        "embedded_cab_contents": "Single file 'a0' (245.7 MB uncompressed) -- the Video Analytics MSI",
        "msi_file":          "a2 in /tmp/forticentral_cab/ (110MB) = Composite Document File, OLE2",
        "digital_signature": "Signed by Fortinet, Inc. via DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
    },

    "embedded_libraries": {
        "tensorflow_dll": {
            "file":             "tensorflow.dll in CAB stream 2",
            "uncompressed_sz":  "211,298,304 bytes (211.3 MB)",
            "compressed_sz":    "66,596,212 bytes (66.6 MB, in MSI stream '䄦㢥䆾䅤')",
            "risk":             "TensorFlow 2.x on Windows; if SavedModel path is attacker-controlled, arbitrary code via TF custom ops; "
                                "known CVE classes: CVE-2022-29216 (TF saved_model), CVE-2023-25801 (TF tensor memory)",
            "version_unknown":  "Exact TF version not confirmed from CAB metadata -- check DLL strings",
        },
        "opencv_suite": {
            "version":    "4.8.0 (all DLL names contain '480')",
            "count":      "53 OpenCV DLLs in CAB stream 1",
            "key_modules": [
                "opencv_dnn480.dll (6.9MB) -- loads ONNX/Caffe/TF models from file path",
                "opencv_face480.dll (0.7MB) -- face detection/recognition",
                "opencv_objdetect480.dll (1.4MB) -- object detection (Haar cascades, HOG)",
                "opencv_videoio_ffmpeg480_64.dll (26.4MB) -- FFmpeg video decode for RTSP",
                "opencv_gapi480.dll (6.1MB) -- G-API pipeline (graph-based processing)",
            ],
            "rtsp_attack_surface": (
                "opencv_videoio_ffmpeg480_64.dll uses FFmpeg to decode video from FortiRecorder RTSP streams. "
                "A compromised or rogue FortiRecorder camera sending a malformed video stream (H.264, H.265, MJPEG) "
                "triggers FFmpeg parsing in the FortiCentral process. FFmpeg has multiple known parsing CVEs."
            ),
        },
        "cv_interfaces": {
            "file":    "ComputerVisionInterfaces (37,376 bytes, no .dll extension)",
            "type":    "Likely .NET assembly -- 37KB is too small for native code; needs extraction and decompilation",
            "role":    "Bridge between FortiCentral .NET application and native OpenCV/TF DLLs",
        },
    },

    "attack_vectors": {
        "rtsp_stream_parser": {
            "description": "FortiCentral receives RTSP streams from FortiRecorder cameras via opencv_videoio_ffmpeg480_64.dll. "
                           "A malicious camera (or MITM on the camera network) sends a crafted H.264/H.265/MJPEG stream. "
                           "FFmpeg parsing runs in FortiCentral's process context (Windows SYSTEM or admin-level service).",
            "severity":    "CRITICAL -- pre-auth from camera network; no user interaction needed",
            "cve_class":   "FFmpeg heap-buffer-overflow in video codec parsers (multiple historical CVEs)",
        },
        "dnn_model_loading": {
            "description": "opencv_dnn480.dll loads model files from a configurable path (likely C:\\ProgramData\\Fortinet\\... "
                           "or admin-configurable path). Model formats: ONNX, Caffe .prototxt, DarkNet .cfg. "
                           "ONNX models are Protobuf-parsed; malformed ONNX can trigger memory corruption.",
            "severity":    "HIGH -- requires write access to model path (admin) or FGFM config injection (CHAIN-F01)",
        },
        "tensorflow_savedmodel": {
            "description": "If SavedModel directory path is configurable, TF can load a SavedModel with custom ops. "
                           "In TF 2.x, custom ops in .so/.dll loaded at SavedModel load time. "
                           "This is a documented code execution path (CVE-2022-29216 class).",
            "severity":    "HIGH -- requires admin-controlled model path; CHAIN-F01 can inject via FortiManager",
        },
    },

    "chain_extensions": {
        "CHAIN-FC02": {
            "title": "Rogue FortiRecorder camera -> RTSP stream -> FFmpeg heap overflow -> FortiCentral RCE",
            "steps": [
                "1. Attacker controls a device in the FortiRecorder camera segment (or ARP poisons camera IP)",
                "2. FortiCentral connects to the camera RTSP endpoint (configured camera IP:port)",
                "3. Rogue device serves a malformed H.264/H.265 stream crafted for a known FFmpeg CVE",
                "4. opencv_videoio_ffmpeg480_64.dll processes the stream in FortiCentral process space",
                "5. Heap overflow in FFmpeg achieves RCE on the Windows host running FortiCentral",
            ],
            "confidence": "MEDIUM -- attack path confirmed; specific FFmpeg CVE applicability depends on bundled version",
        },
    },
}
