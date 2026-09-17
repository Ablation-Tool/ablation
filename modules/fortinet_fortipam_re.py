"""
Fortinet FortiPAM Privileged Access Agent -- Chrome Browser Extension RE
Source: fortipam-chrome-extension.crx (CRX3, v8.0.1.123, 32 files, 1.1MB extracted)
Platform: Chrome MV3 extension; service_worker.js (423KB), content-script.js (62KB),
          offscreen.js (362KB), shadowHook.js (356 bytes)
Extracted: struct.unpack CRX3 header (1308 bytes), ZIP at offset 0x528
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet Privileged Access Agent (Chrome Extension)",
    "package_id":   "com.fortinet.fortipam (Chrome Web Store)",
    "version":      "8.0.1.123",
    "manifest_ver": "3 (MV3)",
    "crx_format":   "CRX3; header size 1308 bytes; ZIP at offset 0x528",
    "update_url":   "https://clients2.google.com/service/update2/crx",

    "key_files": {
        "service_worker.js":  "423KB; MV3 background service worker; main extension logic",
        "content-script.js":  "62KB; injected into all frames of all URLs",
        "shadowHook.js":      "356 bytes; hooks Element.prototype.attachShadow for shadow DOM injection",
        "offscreen.js":       "362KB; offscreen document worker (DOM/clipboard access in MV3)",
        "manifest.json":      "MV3; externally_connectable: <all_urls>; host_permissions: <all_urls>",
    },

    "permissions": [
        "tabs", "privacy", "cookies", "offscreen", "proxy", "alarms",
        "declarativeNetRequest", "storage", "unlimitedStorage",
        "clipboardRead", "clipboardWrite", "webNavigation", "webRequest",
        "contextMenus", "browsingData",
    ],

    "externally_connectable": "<all_urls>",
    "content_scripts_match":  "<all_urls>; all_frames: true; run_at: document_idle",

    "ipc": {
        "local_ws":    "ws://127.0.0.1:7715 (nanomsg protocol: bus.sp.nanomsg.org); PAM native agent channel",
        "http_watch":  "http://*/launcher (webRequest.onBeforeRequest; any HTTP host; requestBody=JSON)",
    },
}


# ---------------------------------------------------------
# FPE-F1: External message handler with hostname whitelist validation
# ---------------------------------------------------------
FPE_F01_EXTERNAL_MESSAGE_HANDLER = {
    "id":       "FPE-F01",
    "product":  "Fortinet Privileged Access Agent Chrome Extension v8.0.1.123",
    "severity": "INFO -- externally_connectable: <all_urls> allows any website to probe extension presence and initiate auth",
    "class":    "Overly broad externally_connectable scope (Chrome Extension API misuse)",

    "description": (
        "The extension sets externally_connectable.matches to <all_urls>, allowing any "
        "web page to call chrome.runtime.sendMessage() to the extension. "
        "The onMessageExternal handler (service_worker.js) implements a whitelist check: "
        "it extracts the sender hostname via new URL(t.url).hostname and checks if it is "
        "in the PAMHostnameList (stored in chrome.storage.local). "
        "However, any page can send a ping message (e.ping === ct) without authentication "
        "and receive a {action: ct} response -- this allows enumeration of extension presence. "
        "JWT validation is present but optional: the branch "
        "'[SV] Chromium: skipping server verification (enabled=false)' shows that when "
        "server verification is disabled, the hostname whitelist is the only protection "
        "before the extension launches a privileged access session."
    ),

    "evidence": {
        "handler":          "onMessageExternalHandler(e,t,n) in service_worker.js at offset 373620",
        "whitelist_check":  "const i=await this.getPAMHostnameList(); if(!i.includes(new URL(r).hostname)) return n(K)",
        "ping_bypass":      "if(e.ping===ct)return void n({action:ct}) -- no whitelist check for ping",
        "jwt_optional":     "Tt(e.accesstoken) check; if false and a==false: 'skipping server verification'",
        "catch_behavior":   "catch(e){ return void n(K) } -- fail-closed; TypeError on null list returns K",
    },

    "impact": (
        "Extension presence on user's browser is detectable by any website. "
        "If PAMHostnameList is misconfigured to include broad patterns or if JWT validation "
        "is disabled, a whitelisted host can trigger credential injection sessions. "
        "Extension holds cookies, proxy control, browsingData erasure, and clipboard "
        "access -- compromise of the extension context is high impact."
    ),

    "pending": "Enumerate PAMHostnameList population path -- find where new hostnames are added to the whitelist.",
}


# ---------------------------------------------------------
# FPE-F2: Local WebSocket on port 7715 (nanomsg bus protocol)
# ---------------------------------------------------------
FPE_F02_LOCAL_WEBSOCKET_7715 = {
    "id":       "FPE-F02",
    "product":  "Fortinet Privileged Access Agent Chrome Extension v8.0.1.123",
    "severity": "INFO -- local-only WebSocket; credentials flow through ws://127.0.0.1:7715",
    "class":    "Local IPC channel for credential transit",

    "description": (
        "service_worker.js initWS() opens ws://127.0.0.1:7715 with "
        "nanomsg bus protocol (subprotocol: bus.sp.nanomsg.org). "
        "This socket connects to the FortiPAM native app installed on the machine. "
        "Credential objects (isValidSessionInfo checks: id, secretUrl, credential.username, "
        "credential.password) are passed through this channel between the browser extension "
        "and the native PAM agent. "
        "The nanomsg bus pattern means any local process that connects to port 7715 "
        "with the correct subprotocol joins the bus and receives all messages."
    ),

    "evidence": {
        "initWS":           "ws://127.0.0.1:7715 subprotocol bus.sp.nanomsg.org in service_worker.js",
        "isValidSessionInfo": "checks id, secretUrl, credential.username, credential.password non-null",
        "port":             "7715 TCP loopback",
        "protocol_name":    "bus.sp.nanomsg.org (nanomsg message bus; any peer can join)",
    },

    "impact": (
        "A local malicious process can connect to ws://127.0.0.1:7715 with subprotocol "
        "bus.sp.nanomsg.org and intercept credential payloads passed between the "
        "FortiPAM native agent and the browser extension. "
        "nanomsg bus topology delivers messages to all connected peers -- "
        "a passive listener receives credentials without authentication."
    ),

    "pending": (
        "Capture live traffic on port 7715 during a PAM session. "
        "Reverse the nanomsg message format to extract credential structure. "
        "Check if port 7715 binding allows non-localhost connections."
    ),
}


# ---------------------------------------------------------
# FPE-F3: shadowHook.js -- shadow DOM attachment notification
# ---------------------------------------------------------
FPE_F03_SHADOW_HOOK = {
    "id":       "FPE-F03",
    "product":  "Fortinet Privileged Access Agent Chrome Extension v8.0.1.123",
    "severity": "INFO -- standard password manager shadow DOM injection technique",
    "class":    "Shadow DOM interception (architectural documentation)",

    "description": (
        "shadowHook.js (356 bytes, web_accessible_resources) hooks "
        "Element.prototype.attachShadow to dispatch a CustomEvent '__cf_attachShadow_open' "
        "with bubbles:true, composed:true when a shadow root with mode:'open' is created. "
        "The __cfHooked marker prevents double-hooking. "
        "The content-script.js presumably listens for these events to detect shadow DOM "
        "credential forms and inject autofill. "
        "This is a standard architecture for modern password managers/PAM agents. "
        "The script is loaded via chrome.tabs.executeScript or as web_accessible_resource "
        "injected by the content script."
    ),

    "evidence": {
        "shadow_hook":      "Element.prototype.attachShadow hooked in shadowHook.js",
        "event_name":       "__cf_attachShadow_open (CustomEvent; bubbles=true, composed=true)",
        "guard":            "__cfHooked marker on Element.prototype.attachShadow to prevent re-hook",
        "web_accessible":   "Listed in manifest web_accessible_resources['shadowHook.js']",
    },

    "impact": (
        "Any page with a shadow DOM form that uses mode:'open' will trigger this event. "
        "If content-script.js fills credentials into shadow DOM forms, "
        "a malicious page could create a shadow DOM with a fake credential form "
        "to receive the injected credentials. "
        "Depends on whether the content script validates that the shadow host is a "
        "legitimate PAM target before injecting."
    ),

    "pending": "Read content-script.js handler for __cf_attachShadow_open to verify target validation.",
}


# ---------------------------------------------------------
# FPE-F4: HTTP launcher intercept (http://*/launcher)
# ---------------------------------------------------------
FPE_F04_HTTP_LAUNCHER_INTERCEPT = {
    "id":       "FPE-F04",
    "product":  "Fortinet Privileged Access Agent Chrome Extension v8.0.1.123",
    "severity": "INFO -- launcher IPC mechanism; cleartext HTTP body parsed",
    "class":    "HTTP-based local IPC trigger",

    "description": (
        "The extension registers a webRequest.onBeforeRequest listener for "
        "url pattern 'http://*/launcher' (any HTTP host, any port, path /launcher). "
        "handleOnBeforeRequest decodes the request body as UTF-8 JSON and checks "
        "isFortiPAMLauncherRequest(e). If valid AND e.type==='ftc', it sets "
        "this.prepForLaunch=Date.now()+5000 (5-second launch window) and calls saveToHistory(e). "
        "The 'ftc' type appears to be a FortiClient-originated launcher request. "
        "This does NOT modify the PAMHostnameList whitelist."
    ),

    "evidence": {
        "url_filter":       "http://*/launcher (any host; cleartext HTTP)",
        "handler":          "handleOnBeforeRequest in service_worker.js",
        "type_check":       "'ftc'===e.type (FortiClient launcher type)",
        "side_effect":      "prepForLaunch=Date.now()+5000; saveToHistory(e)",
        "no_whitelist_mod": "confirmed -- does not call setPAMHostnameList",
    },

    "impact": (
        "If an attacker can cause the browser to make a cleartext HTTP request to "
        "any host at path /launcher with a JSON body that passes isFortiPAMLauncherRequest, "
        "they can trigger the 5-second prepForLaunch window. "
        "The actual exploit depends on what prepForLaunch enables -- likely a timing gate "
        "for an incoming external message."
    ),

    "pending": "Reverse isFortiPAMLauncherRequest validation and what prepForLaunch gates.",
}


# ---------------------------------------------------------
# FPE-F05: Arbitrary domain fetch from extension (SSRF-like) via launch message
# ---------------------------------------------------------
FPE_F05_DOMAIN_SSRF = {
    "id":       "FPE-F05",
    "product":  "Fortinet Privileged Access Agent Chrome Extension v8.0.1.123",
    "severity": "MEDIUM -- extension makes outbound requests to attacker-controlled domain",
    "class":    "Server-Side Request Forgery from browser extension context",

    "description": (
        "The onMessageExternalHandler accepts a 'domain' field in the launch message. "
        "If the sender hostname passes the PAMHostnameList check (whitelist) and either "
        "JWT is valid or server verification is bypassed via trusted list, the extension "
        "calls launchStandaloneSession(e,n). "
        "launchStandaloneSession calls api.sendInfoRequest(e), which constructs a URL: "
        "new URL(o?`${t}:${o}`:t) (domain + port) with pathname '/pam/info'. "
        "The extension then calls delegateFetch to this constructed URL with: "
        "  Authorization: Bearer <message.accesstoken> "
        "  X-User-Agent: MV3 Extension v8.0.1.123/<browser> <version>;<OS> <arch> "
        "The accesstoken header value comes from the launch message, not stored credentials. "
        "However, the extension has <all_urls> host_permissions, so it can reach any URL "
        "including intranet addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x, localhost). "
        "An attacker with control over a PAM-whitelisted hostname can direct the extension "
        "to probe any IP/port accessible from the user's browser."
    ),

    "trigger": {
        "condition_1": "Sender hostname in PAMHostnameList (chrome.storage.local)",
        "condition_2a": "JWT validation enabled: valid JWT required (sign key from PAM server)",
        "condition_2b": "JWT disabled: hostname in trusted list OR user approves server verification modal",
        "action":       "chrome.runtime.sendMessage(EXT_ID, {action:'launcher', domain:'attacker.com:8443', sec_id:'1', launcher:'1'})",
    },

    "evidence": {
        "action_constant":   "T = 'launcher' at service_worker.js offset 294964",
        "valid_check":       "validStandaloneChromium(e): (!isWSConnected() || e.type==='extension') && e.action===T",
        "sendInfoRequest":   "new URL(domain+port) with pathname='/pam/info'; adds sec_id and launcher as searchParams",
        "makeHeaders":       "Authorization: Bearer ${message.accesstoken}; X-User-Agent: extension version",
        "host_permissions":  "<all_urls>; extension can reach any URL from user's browser",
    },

    "attack_chain": (
        "1. Compromise or MITM a FortiPAM server hostname in the whitelist. "
        "2. Serve a page that calls chrome.runtime.sendMessage(EXT_ID, "
        "   {action:'launcher', domain:'192.168.1.1:22', sec_id:'1', launcher:'1', accesstoken:''}) "
        "3. Extension makes GET https://192.168.1.1:22/pam/info?sec_id=1&launcher=1 from user browser. "
        "4. Response status/error reveals port state (port scan from victim browser). "
        "5. With valid JWT (from compromised PAM server): iterate over intranet addresses. "
        "Amplification: extension's trusted origin list persists -- one-time user approval enables "
        "repeat access without further interaction."
    ),

    "scope_note": (
        "Credential leakage: NO -- Authorization header carries the caller-provided accesstoken "
        "only; no stored PAM credentials are sent to the attacker-controlled domain. "
        "Primary impact: intranet port scanning / service enumeration from victim browser context."
    ),
}

FPE_F01_UPDATES = {
    "jwt_validation_reversals_2026_09_16": {
        "T_constant":      "T = 'launcher' (sw.js offset 294964) -- e.action === 'launcher' required",
        "Tt_function":     "Tt(e.accesstoken): truthy check -- returns true if accesstoken is provided",
        "kt_function":     "kt(accesstoken): JWT decode+verify; returns {valid, claims} object",
        "Ct_function":     "Ct(claims, msg): validates JWT claims against message fields",
        "trusted_list_Ue": "Ue() reads chrome.storage.local[ne] (persistent cross-session trusted hosts)",
        "Oe_function":     "Oe(hostname) adds host to trusted list -- triggers after user approves modal",
        "ping_ct":         "ct = 'ping' (sw.js offset 327814) -- responds to any caller, no whitelist",
    },
}


# ---------------------------------------------------------
# Pending findings
# ---------------------------------------------------------
pending_findings = [
    "PAMHostnameList population path: find where new PAM server hostnames are added to "
    "chrome.storage.local -- specifically the code path "
    "n?n.includes(e)||(n.push(e),setPAMHostnameList(n)):setPAMHostnameList([e]); "
    "determine if launcher flow or external message can add attacker hostname; "
    "source: service_worker.js setPAMHostnameList call sites; 2026-09-16",

    "content-script.js shadow DOM autofill validation: read __cf_attachShadow_open "
    "listener to determine if target host is validated before credential injection; "
    "if no validation, malicious page can receive PAM credentials via fake shadow DOM; "
    "source: content-script.js 62KB; 2026-09-16",

    "offscreen.js purpose: 362KB is large for an offscreen document; "
    "likely handles clipboard access (clipboardRead/Write permission); "
    "check if credentials are routed through clipboard; "
    "source: offscreen.js + offscreen.html; 2026-09-16",

    "nanomsg port 7715 message format: capture live session traffic on ws://127.0.0.1:7715; "
    "determine if any authentication gates the bus; "
    "source: service_worker.js initWS(); 2026-09-16",

    "JWT validation implementation: reverse kt() (JWT decode) and Ct() (claims validate) "
    "to determine if JWT signature is verified or only decoded; "
    "source: service_worker.js Tt/kt/Ct functions; 2026-09-16",
]
