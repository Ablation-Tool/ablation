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
