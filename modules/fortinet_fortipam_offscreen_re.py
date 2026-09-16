"""
Fortinet FortiPAM Chrome Extension offscreen.js RE
Source: /tmp/fortipam-crx/offscreen.js (362KB, single-line minified; CRX v8.0.1.123)
Companion to: fortinet_fortipam_re.py (service_worker.js) and fortinet_fortipam_content_script_re.py
"""

# ---------------------------------------------------------
# Architecture -- offscreen.js roles
# ---------------------------------------------------------
ARCHITECTURE = {
    "file":     "offscreen.js (362,867 bytes, single-line minified)",
    "purpose":  (
        "Chrome MV3 Offscreen Document. Runs as a persistent hidden page with full DOM access "
        "but no UI. Used by the extension for two things: "
        "(1) Proxy fetch requests from the service worker (SW cannot use fetch with credentials:include "
        "    for same-origin requests to PAM server; offscreen document can). "
        "(2) Session state management: SessionManager, TOTP polling, recording upload, proxy config."
    ),
    "classes": {
        "SessionManager (Ae)": (
            "Singleton. Central orchestrator. Manages all active PAM sessions as a tree of "
            "SessionTab nodes keyed by session ID. Tracks tabs, domains, TOTP timers, "
            "recording metadata, proxy state. "
            "Handles all _internal_* message types from content scripts and service worker."
        ),
        "API (_e)": (
            "FortiPAM REST API client. All PAM API calls go through delegateFetch(). "
            "In offscreen context: uses fetch() directly with credentials:include. "
            "In SW context: delegates to offscreen via _internal_fetch message."
        ),
        "CookieRemover (De)": (
            "Session cleanup: removes cookies, cache, browsing data on session end. "
            "Supports SSO domain tracking (removes cookies from known SSO domains)."
        ),
        "SessionProxy": "Manages Chrome proxy settings for PAM proxy-mode sessions (PAC script).",
        "SessionTab (ke)": (
            "Node in the session tab tree. Tracks: tabId, parent, children, sessionInfo, "
            "click timestamps, keypress timestamps + codes, mouse position/style, URL. "
            "Root node holds sessionInfo (including credentials). Children inherit via getRoot()."
        ),
    },
    "message_types_handled": {
        "_internal_session_info_query":              "Return sessionInfo (with credentials) to content script",
        "_internal_activity_tracker_mouse_query":    "Return isSession/allowCopy/pollingInterval to content script",
        "_internal_activity_tracker_mouse_event":    "Record mouse move/click/style from content script",
        "_internal_activity_tracker_keyboard_event": "Record keypress code from content script",
        "_internal_terminate_session":               "Close all session tabs",
        "_internal_fetch":                           "Execute fetch() on behalf of service worker",
    },
}


# ---------------------------------------------------------
# FPO-OF-F01: Incomplete credential wipe on session end
# ---------------------------------------------------------
FPO_OF_F01_INCOMPLETE_CRED_WIPE = {
    "id":       "FPO-OF-F01",
    "product":  "FortiPAM Chrome Extension offscreen.js (SessionTab.removeCred)",
    "severity": "MEDIUM -- credential.username and credential.password nulled but dynamicFill NOT cleared",
    "class":    "Incomplete credential cleanup (CWE-459)",

    "description": (
        "SessionTab.removeCred() nullifies credential.username and credential.password "
        "on the root SessionTab node's sessionInfo: "
        "  this.sessionInfo.credential.username = null; "
        "  this.sessionInfo.credential.password = null. "
        "It does NOT clear sessionInfo.credential.dynamicFill. "
        "dynamicFill is the array that the CredentialFiller (content-script.js) reads "
        "when responding to _internal_session_info_query. "
        "If removeCred() is called at session end but dynamicFill survives, "
        "a subsequent _internal_session_info_query on the same tab could return credentials "
        "from a prior session until the SessionTab node is fully garbage-collected."
    ),

    "vulnerable_code": (
        "removeCred(){this.isRoot()?"
        "(this.sessionInfo.credential.username=null,this.sessionInfo.credential.password=null)"
        ":this.parent.removeCred()}"
    ),

    "dynamicFill_not_cleared": (
        "sessionInfo.credential.dynamicFill survives removeCred(). "
        "dynamicFill contains: [{type:'password', value:'<plaintext>'}, {type:'username', value:'<plaintext>'}]. "
        "Full session cleanup (handleSessionEnd) eventually calls removeSessionFromInternalRecord "
        "which does `delete this.record[sessionId]` -- but this is a JS delete on the record object, "
        "not a secure wipe. The underlying sessionInfo object may remain in memory until GC."
    ),

    "note": (
        "In practice, the session ends when the session tab is closed, which triggers "
        "onRemovedHandler -> handleSessionEnd -> removeSessionFromInternalRecord. "
        "The window between removeCred() call and full deletion is likely short. "
        "More impactful: dynamicFill is NEVER securely overwritten (zeroed) before deletion."
    ),
}


# ---------------------------------------------------------
# FPO-OF-F02: TOTP code fetched and stored plaintext in SW/offscreen memory
# ---------------------------------------------------------
FPO_OF_F02_TOTP_PLAINTEXT_IN_MEMORY = {
    "id":       "FPO-OF-F02",
    "product":  "FortiPAM Chrome Extension offscreen.js (SessionManager.checkTOTP / API.getTOTP)",
    "severity": "MEDIUM -- TOTP code fetched from server and stored plaintext in extension memory",
    "class":    "Sensitive data in memory (CWE-316)",

    "description": (
        "When a PAM session has a TOTP-type credential (hasTOTP returns true), "
        "SessionManager.startTOTPCheck() begins polling checkTOTP() on expiry. "
        "checkTOTP() calls api.getTOTP(sessionInfo), which POST to "
        "  /api/v2/internal/secret-totp?vdom=root "
        "  with body {\"secret-id\": \"<id_from_dynamicFill>\"}. "
        "On success, the TOTP code is stored: "
        "  o.value = n.results.TOTP; o.expiry = n.results.expiry; o.tokenRetrieved = Date.now(). "
        "Here `o` is the dynamicFill entry for type='token'. "
        "The TOTP code lives in the extension's in-memory session record until the next refresh. "
        "Any vulnerability allowing read of the SW/offscreen's memory state could expose current TOTP codes."
    ),

    "api_endpoint": "POST /api/v2/internal/secret-totp?vdom=root",
    "request_body": '{"secret-id": "<secret_id_from_dynamicFill>"}',
    "response_stored": "n.results.TOTP (plaintext TOTP code), n.results.expiry (seconds until rotation)",

    "secret_id_exposure": (
        "The 'secret-id' sent in the POST body comes from "
        "e.credential.dynamicFill.find(e=>'token'===e.type)['secret-id']. "
        "This identifier is also present in the _internal_session_info_query response "
        "that the content script receives (the full sessionInfo is returned). "
        "An XSS on a PAM-managed host receiving the sessionInfo response gets the secret-id "
        "and can call the /api/v2/internal/secret-totp endpoint directly to fetch TOTP codes."
    ),
}


# ---------------------------------------------------------
# FPO-OF-F03: delegateFetch -- offscreen as privileged fetch proxy
# ---------------------------------------------------------
FPO_OF_F03_OFFSCREEN_FETCH_PROXY = {
    "id":       "FPO-OF-F03",
    "product":  "FortiPAM Chrome Extension offscreen.js (FetchHandler.handleFetch)",
    "severity": "HIGH -- offscreen document executes arbitrary fetch() on behalf of service worker; credentials:include",
    "class":    "Privileged fetch proxy without URL validation (CWE-441)",

    "description": (
        "The FetchHandler class in offscreen.js listens for _internal_fetch messages: "
        "  onMessageHandler: if '_internal_fetch' === type -> handleFetch(e, n, retry). "
        "handleFetch executes: "
        "  const {resource, options} = message; "
        "  const resp = await fetch(resource, options); "
        "  n({ok: resp.ok, data: await resp.text(), status: resp.status, redirected: resp.redirected}). "
        "The `resource` URL and `options` (method, credentials, headers, body) are taken directly "
        "from the message without URL validation. "
        "The offscreen document runs in the extension origin (chrome-extension://<id>/) "
        "and can make cross-origin requests with credentials:include, bypassing SameSite=Strict cookies "
        "if the target is the PAM server. "
        "This is intentional but means a compromised service worker can exfiltrate any "
        "PAM API response to an arbitrary URL."
    ),

    "message_format": {
        "_internal_fetch": {
            "type":     "_internal_fetch",
            "resource": "<URL to fetch>",
            "options":  "{method, credentials: 'include'|'omit', headers: {...}}",
            "data":     "<optional body -- base64 for blob/arraybuffer, string otherwise>",
            "dataType": "'blob'|'arraybuffer'|<other>",
            "retry":    "boolean (triggers exponential retry on failure)",
        },
    },

    "response_format": {
        "_internal_fetch_resp": {
            "ok":         "boolean",
            "data":       "response text",
            "status":     "HTTP status code",
            "redirected": "boolean",
        },
    },

    "credentials_include_note": (
        "The fetch options use credentials:'include' (constant W='include') or 'omit' (constant Y='omit'). "
        "For all PAM API calls, credentials='include' is used, meaning all browser cookies "
        "for the PAM domain are sent with each fetch. "
        "This allows the offscreen document to make authenticated API calls without "
        "explicitly handling session tokens."
    ),

    "csrf_auto_fetch": (
        "API.getCSRFToken(pamUrl) calls chrome.cookies.getAll({domain: pamUrl, name: 'ccsrftoken'}) "
        "and returns the cookie value. This CSRF token is then added to the X-Csrftoken header "
        "on all state-changing API calls (POST/PUT/DELETE). "
        "The extension fetches the CSRF token automatically from the cookie store -- "
        "the caller does not need to know the token value."
    ),
}


# ---------------------------------------------------------
# FPO-OF-F04: Session recording upload -- video chunked to server
# ---------------------------------------------------------
FPO_OF_F04_SESSION_RECORDING = {
    "id":       "FPO-OF-F04",
    "product":  "FortiPAM Chrome Extension offscreen.js (API: session recording)",
    "severity": "INFO -- intended feature; session video streams to uploadUrl from sessionInfo",
    "class":    "Session recording design",

    "description": (
        "FortiPAM records PAM sessions as video. The recording stream is uploaded chunk-by-chunk. "
        "sendLiveStreamCluster(blob, sessionInfo, chunkNum): "
        "  POST <sessionInfo.recording.uploadUrl> "
        "  with headers {Content-Type: 'video/webm; codecs=vp8', Content-Disposition: 'filename=chunk_NNNNNN.chk'} "
        "  body: binary blob chunk. "
        "The uploadUrl comes from sessionInfo which originates from the FortiPAM server "
        "during session initialization. "
        "sendInitHeader(), sendUpdatedLiveStreamHeader(), sendUpdatedRecordingHeader() manage "
        "the init/finalization of the recording stream."
    ),

    "recording_upload_apis": {
        "POST sendInitHeader":                  "Upload recording init header (binary, Content-Disposition: init.hdr)",
        "POST sendLiveStreamCluster":           "Upload video chunk (webm, Content-Disposition: chunk_NNNNNN.chk)",
        "POST sendUpdatedLiveStreamHeader":     "Finalize live stream (X-Complete: true)",
        "POST sendRecordingChunk":              "Upload recording chunk (Content-Range via X-Range)",
        "POST sendUpdatedRecordingHeader":      "PATCH recording header (PATCH method, X-Complete: true)",
        "POST sendMetaData":                    "Upload session metadata JSON (key events, clicks, timestamps)",
    },

    "metadata_content": (
        "makeMetaData() structures: {Name, Version, CreateDate, Description, Event-N: {timestamp, key_event_totals, mice_event_totals, keys_pressed}}. "
        "keys_pressed contains translated key codes (e.g., 'A', 'Enter', 'Space') with timing. "
        "This metadata is sent alongside the video recording. "
        "NOTE: keys_pressed uses the v={} map to translate e.code to VirtualKey-style names "
        "(e.g., KeyA -> 'A', ShiftLeft -> 'LShiftKey'). This is NOT character values but "
        "physical key names with timestamps."
    ),
}


# ---------------------------------------------------------
# FPO-OF-F05: Session tab domain tracking -- auto-association attack surface
# ---------------------------------------------------------
FPO_OF_F05_DOMAIN_TRACKING = {
    "id":       "FPO-OF-F05",
    "product":  "FortiPAM Chrome Extension offscreen.js (SessionManager domain tracking)",
    "severity": "LOW -- session domain tracking auto-associates navigated URLs; expandable via SSO domains",
    "class":    "Session scope expansion via URL tracking (CWE-284)",

    "description": (
        "SessionManager tracks all domains navigated to during a PAM session via domainRecord. "
        "addHostToSessionHostTracker(sessionId, url) extracts hostname from URL and adds to domainRecord[sessionId]. "
        "checkIfShouldTrack(url, tabId) checks if the URL hostname is in any domainRecord -- "
        "if so, the tab is automatically added to that session (setTabAsSessionAndReload). "
        "Additionally, getKnownSSO(secretUrl) returns associated SSO domains from a hardcoded list b[]. "
        "On session end, CookieRemover removes cookies from all tracked domains AND SSO domains."
    ),

    "sso_domain_list": (
        "The constant b[] is a hardcoded list of known SSO domain groups. "
        "If a PAM secretUrl matches one of these groups, ALL domains in the group "
        "are added to the session's domain scope and have their cookies removed on session end. "
        "This list includes known IdP providers (Okta, Azure AD patterns, etc.) "
        "that FortiPAM treats as part of the same SSO session."
    ),

    "auto_association_risk": (
        "If an attacker can navigate a non-session tab to a URL whose hostname is already "
        "in domainRecord (i.e., a URL visited during a PAM session), "
        "that tab would be automatically added to the PAM session and receive "
        "sendReloadMessageToContentScript -- triggering the content script to reload "
        "and potentially re-query session credentials. "
        "This requires being able to navigate a browser tab to a known PAM session domain."
    ),
}


# ---------------------------------------------------------
# FPO-OF-F06: createSecret includes plaintext credentials in POST body
# ---------------------------------------------------------
FPO_OF_F06_CREATESECRET_PLAINTEXT = {
    "id":       "FPO-OF-F06",
    "product":  "FortiPAM Chrome Extension offscreen.js (API.createSecret)",
    "severity": "MEDIUM -- quick-create stores observed credentials to PAM server; weak default '******'",
    "class":    "Credential exposure in API call (CWE-522)",

    "description": (
        "API.createSecret() is a 'Quick Create' feature: when the extension observes a user "
        "entering credentials into a form on a non-PAM-managed site, it can create a new PAM secret "
        "with those credentials. "
        "The POST body to /api/v2/cmdb/secret/database includes: "
        "  field: [{name:'Username', value: r?.username || 'user_name'}, "
        "          {name:'Password', value: r?.password || '******'}]. "
        "If r.password is falsy (empty string, null, undefined), the literal string '******' "
        "is stored as the password. "
        "A PAM admin reviewing the credential store would see six asterisks as the stored value "
        "and might assume the password is correct when it is actually the placeholder."
    ),

    "api_endpoint":  "POST /api/v2/cmdb/secret/database",
    "weak_default":  "Password field defaults to '******' (literal string) if observed value is falsy",
    "note": (
        "The createTarget() call also uses Q = '/api/v2/cmdb/secret/target' "
        "with access:'everyone' and web-proxy-status:'enable' as defaults. "
        "A quick-created secret is world-accessible to all PAM users by default."
    ),
}


# ---------------------------------------------------------
# FPO-OF-F07: API endpoint inventory from offscreen.js
# ---------------------------------------------------------
FPO_OF_F07_API_ENDPOINT_INVENTORY = {
    "id":       "FPO-OF-F07",
    "product":  "FortiPAM REST API surface (extracted from offscreen.js API class)",
    "severity": "INFO -- complete API endpoint map for authenticated access",
    "class":    "API surface documentation",

    "endpoints": {
        "GET  /api/v2/monitor/web-ui/state":          "getPAMState -- current UI state",
        "GET  /api/v2/utility/id/<name>?type=folder": "getFolderId -- folder ID lookup",
        "GET  /api/v2/cmdb/secret/target/<name>":     "doesTargetExist -- target lookup",
        "GET  /api/v2/cmdb/secret/target":            "getTargetList -- all targets (POST with json_filter)",
        "POST /api/v2/cmdb/secret/database":          "createSecret -- create credential record",
        "POST /api/v2/cmdb/secret/target":            "createTarget -- create connection target",
        "POST /api/v2/internal/secret-totp?vdom=root": "getTOTP -- fetch current TOTP code by secret-id",
        "GET  <secretUrl>/logout?":                   "sendPAMLogout -- logout from target service",
        "GET  <pacScriptUrl>":                        "getPacScript -- fetch PAC file for proxy mode",
        "POST <uploadUrl> (init.hdr)":                "sendInitHeader -- start recording upload",
        "POST <uploadUrl> (chunk_N.chk)":             "sendLiveStreamCluster -- upload video chunk",
        "POST <uploadUrl> (metadata)":                "sendMetaData -- upload session key/click events",
        "POST <pam/info>":                            "sendInfoRequest -- report session info (sec_id, launcher, accesstoken)",
        "POST <ftc_uri>":                             "sendFortiVRSLauncherRequest -- VRS launcher request",
        "POST <saml_url>":                            "sendSAMLLoginRequest -- SAML assertion POST",
    },

    "csrf_header":    "X-Csrftoken: <value from ccsrftoken cookie>",
    "auth_header":    "X-Requested-With: XMLHttpRequest (on all API calls)",
    "content_type":   "Content-Type: application/json (most), video/webm... (recording)",

    "totp_secret_id_note": (
        "The /api/v2/internal/secret-totp endpoint accepts a 'secret-id' value. "
        "This secret-id is present in the sessionInfo returned to content scripts. "
        "An attacker with the secret-id (via XSS -> ArrowDown fill -> sessionInfo exfil) "
        "can call this endpoint directly from the PAM-managed host browser context "
        "with credentials:include to get fresh TOTP codes."
    ),
}
