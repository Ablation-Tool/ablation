"""
Fortinet FortiPAM Chrome Extension content-script.js RE
Source: /tmp/fortipam-crx/content-script.js (62KB, single-line minified; CRX v8.0.1.123)
Companion to: fortinet_fortipam_re.py (service_worker.js, shadowHook.js)
"""

# ---------------------------------------------------------
# Architecture summary
# ---------------------------------------------------------
ARCHITECTURE = {
    "file":     "content-script.js (62,535 bytes, single-line minified)",
    "runs_on":  "<all_urls> -- all pages, including non-PAM pages",
    "classes":  {
        "U (ActivityTracker)": (
            "Tracks mouse/keyboard activity on active PAM sessions. "
            "Blocks clipboard copy/cut on protected pages. "
            "Sends mouse position + keyboard key codes to service worker."
        ),
        "Wt (CredentialFiller)": (
            "Singleton. Fills PAM credentials into web form inputs. "
            "Activated only on pages where service worker returns isSession:true. "
            "Reads credentials from service worker (_internal_session_info_query). "
            "Shows floating modal 'Fill Credentials' near focused inputs."
        ),
    },
    "message_types": {
        "_internal_activity_tracker_mouse_query":    "Check if current page is a PAM session (ActivityTracker)",
        "_internal_activity_tracker_mouse_response": "Response: {isSession, isWebApp, allowCopy, pollingInterval}",
        "_internal_activity_tracker_keyboard_event": "Report keydown code to service worker (code only, not value)",
        "_internal_session_info_query":              "Get full session info + credentials (CredentialFiller)",
        "_internal_overlay_shutdown":                "Shutdown overlay with countdown message",
    },
}


# ---------------------------------------------------------
# FPE-CS-F01: shouldTrackThisPage -- host validation delegation
# ---------------------------------------------------------
FPE_CS_F01_HOST_VALIDATION = {
    "id":       "FPE-CS-F01",
    "product":  "FortiPAM Chrome Extension content-script.js",
    "severity": "INFO -- host validation delegated to service worker; content-script is fail-closed",
    "class":    "Authentication design",

    "description": (
        "The content script does NOT independently validate the current page hostname. "
        "It delegates to the service worker via sendMessage(_internal_session_info_query). "
        "If the service worker returns isSession:false (or throws), the content script "
        "does NOT activate credential filling. "
        "shouldTrackThisPage(isSession): return isSession && window.top === window.self "
        "(also checks: not in iframe). "
        "querySessionInfoFromSW() catch block returns {isSession:false} -- fail-closed. "
        "The service worker's PAMHostnameList is the only hostname gating mechanism."
    ),

    "code": {
        "shouldTrackThisPage": "return t && window?.top === window?.self",
        "querySessionInfoFromSW_fallback": "catch(t){return{type:'_internal_activity_tracker_mouse_response',isSession:false}}",
        "credential_filler_init": "catch(t){return !1}  // getSessionInfo falls back to false",
    },

    "security_note": (
        "The service worker's PAMHostnameList validation (confirmed fail-closed in prior analysis) "
        "is the load-bearing security boundary. "
        "Content script trusts the service worker's response completely. "
        "chrome.runtime.sendMessage from content script is extension-internal; "
        "web page JS cannot intercept or spoof this message."
    ),
}


# ---------------------------------------------------------
# FPE-CS-F02: Credential plaintext in preparedInputs + DOM
# ---------------------------------------------------------
FPE_CS_F02_PLAINTEXT_CREDENTIAL_IN_DOM = {
    "id":       "FPE-CS-F02",
    "product":  "FortiPAM Chrome Extension content-script.js",
    "severity": "MEDIUM -- plaintext credentials stored in content script memory and written to DOM input.value",
    "class":    "Credential exposure in shared DOM (CWE-522)",

    "description": (
        "After _internal_session_info_query returns sessionInfo.credential.dynamicFill, "
        "the CredentialFiller stores each credential entry in preparedInputs: "
        "preparedInputs.push({input, value: entry.value, type, mask}). "
        "The value field contains the PLAINTEXT credential (password, username, token). "
        "When fillInputUsingEntry() is called, inputToField(entry.value, inputElement) "
        "types the credential character-by-character into the DOM input field. "
        "After filling, the input element's .value property contains the plaintext credential. "
        "Any JavaScript running on the page can read input.value at this point."
    ),

    "credential_flow": [
        "1. SW returns sessionInfo.credential.dynamicFill = [{type:'password', value:'<plaintext>', mask:true}, ...]",
        "2. Wt.getInputWithDynamicFill(entry) finds matching DOM input elements",
        "3. preparedInputs.push({input: domElement, value: plaintext_cred, type, mask})",
        "4. User focuses input -> 'Fill Credentials' modal appears",
        "5. fillInput() -> fillInputWithPreparedValue() -> fillInputUsingEntry(input, entry)",
        "6. inputToField(entry.value, input): simulates keystrokes at 300/length ms intervals",
        "7. Wt.changeInputValue(input, partial_value) -> input.value = partial_value; dispatchEvent(Input); dispatchEvent(Change)",
        "8. Final: input.value = full_plaintext_credential (readable by page JS)",
    ],

    "note": (
        "This is inherent to browser-based credential filling -- "
        "the filled value is always readable by page JS via DOM. "
        "The 'mask: true' attribute only controls display (type='password' attribute), "
        "not JavaScript access. "
        "The character-by-character typing (inputToField delay loop) means the credential "
        "is ALSO readable during typing via oninput handler."
    ),
}


# ---------------------------------------------------------
# FPE-CS-F03: ArrowDown keydown synthesis bypasses user-click requirement
# ---------------------------------------------------------
FPE_CS_F03_ARROWDOWN_SYNTHESIS = {
    "id":       "FPE-CS-F03",
    "product":  "FortiPAM Chrome Extension content-script.js",
    "severity": "HIGH -- synthesized ArrowDown event on prepared input fills credentials without user modal click",
    "class":    "Missing isTrusted check on keyboard event triggers credential fill (CWE-807)",

    "description": (
        "inputKeyDownHandler does not check event.isTrusted: "
        "'ArrowDown'===t.key && this.fillInput(). "
        "Page JavaScript can dispatch a synthesized KeyboardEvent with key='ArrowDown' "
        "on a prepared input element. "
        "The extension's inputKeyDownHandler will fire and call fillInput() -> "
        "fillInputWithPreparedValue() -> fillInputUsingEntry() -> inputToField(credential). "
        "The credential is written to input.value without the user clicking 'Fill Credentials'. "
        "Prerequisite: page must be on PAMHostnameList AND have an active PAM session "
        "(only then does the extension prepare inputs for filling). "
        "Exploitable via XSS on any PAM-managed target host."
    ),

    "vulnerable_code": "'ArrowDown'===t.key&&this.fillInput()",
    "no_trusted_check": "event.isTrusted is never checked in inputKeyDownHandler",

    "exploit": {
        "scenario": "XSS on PAM-managed host while PAM session is active",
        "steps": [
            "1. XSS executes on PAM-managed host (in PAMHostnameList, active session)",
            "2. Extension's CredentialFiller is active; preparedInputs populated with credentials",
            "3. XSS: const input = document.querySelector('input[type=password]') (or scan for prepared inputs)",
            "4. XSS: input.focus()  // triggers inputFocusHandler; sets this.focusedInput",
            "5. XSS: input.dispatchEvent(new KeyboardEvent('keydown', {key:'ArrowDown', bubbles:true}))",
            "6. inputKeyDownHandler fires: 'ArrowDown'===t.key -> fillInput() called",
            "7. fillInputWithPreparedValue() -> inputToField(preparedInputs[match].value, input)",
            "8. Credential typed char-by-char into input; XSS reads input.value = plaintext cred",
        ],
        "result": "PAM-managed service credential exfiltrated without user click",
        "limitations": [
            "Requires XSS on PAM-managed host (not pre-auth)",
            "Requires active PAM session (user must have authenticated to FortiPAM)",
            "Extension must have already prepared the input (may require brief wait after page load)",
        ],
    },

    "fix": "Add event.isTrusted check: 'ArrowDown'===t.key && t.isTrusted && this.fillInput()",
}


# ---------------------------------------------------------
# FPE-CS-F04: Shadow DOM confused deputy via listenForHookEvents
# ---------------------------------------------------------
FPE_CS_F04_SHADOW_DOM_CONFUSED_DEPUTY = {
    "id":       "FPE-CS-F04",
    "product":  "FortiPAM Chrome Extension content-script.js",
    "severity": "MEDIUM -- shadow DOM confused deputy; attacker-controlled shadow root gets observed by credential filler",
    "class":    "Confused deputy via shadow DOM event (CWE-441)",

    "description": (
        "listenForHookEvents() adds document.addEventListener('__cf_attachShadow_open', handler, capture=true). "
        "Handler: const e = t.target.shadowRoot; e && this.observeRoot(e). "
        "When shadowHook.js hooks Element.prototype.attachShadow, calling attachShadow({mode:'open'}) "
        "on ANY element fires __cf_attachShadow_open. "
        "Page JavaScript on a PAM-managed host can: "
        "(1) create an element; "
        "(2) call el.attachShadow({mode:'open'}); "
        "(3) put fake password/username inputs inside the shadow root; "
        "(4) shadowHook.js fires __cf_attachShadow_open automatically; "
        "(5) content script calls observeRoot(el.shadowRoot); "
        "(6) extension scans fake shadow root for password inputs; "
        "(7) extension prepares fake inputs for credential filling. "
        "Combined with FPE-CS-F03 (ArrowDown synthesis), credentials can be filled into "
        "attacker-controlled shadow DOM inputs and read back."
    ),

    "vulnerable_code": (
        "listenForHookEvents(){"
        "const t=t=>{const e=t.target.shadowRoot;e&&this.observeRoot(e)};"
        "document.addEventListener(D,t,!0)}"
    ),

    "attack_chain_with_f03": [
        "1. XSS on PAM-managed host",
        "2. XSS: const div=document.createElement('div'); document.body.appendChild(div)",
        "3. XSS: const shadow=div.attachShadow({mode:'open'})",
        "   -> shadowHook.js fires '__cf_attachShadow_open' on div",
        "   -> CredentialFiller.listenForHookEvents handler: observeRoot(div.shadowRoot)",
        "4. XSS (BEFORE or AFTER step 3): shadow.innerHTML='<input type=password name=password>'",
        "5. Extension scans shadow root, finds password input, adds to preparedInputs",
        "6. XSS: shadow.querySelector('input').focus()",
        "7. XSS: shadow.querySelector('input').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true}))",
        "8. Extension fills PAM credential into attacker's shadow DOM input",
        "9. XSS reads shadow.querySelector('input').value = plaintext PAM credential",
    ],

    "note": (
        "The observeRoot() function uses a MutationObserver to watch for new inputs. "
        "The shadow root needs to have password inputs in it when scanned, OR the observer "
        "will pick them up when they're added via MutationObserver. "
        "The extension uses class + id + name + type + autocomplete attributes to match "
        "inputs to dynamicFill entries -- the attacker's shadow DOM input just needs a "
        "matching attribute (e.g., type=password or name=password)."
    ),
}


# ---------------------------------------------------------
# FPE-CS-F05: Activity tracker -- keystroke reporting to service worker
# ---------------------------------------------------------
FPE_CS_F05_ACTIVITY_TRACKER = {
    "id":       "FPE-CS-F05",
    "product":  "FortiPAM Chrome Extension content-script.js (ActivityTracker class U)",
    "severity": "INFO -- intended feature; keycode (not value) reported to service worker",
    "class":    "Activity monitoring design",

    "description": (
        "The ActivityTracker (class U) registers keyboard event listeners on PAM session pages. "
        "On keydown: chrome.runtime.sendMessage({type:'_internal_activity_tracker_keyboard_event', code:t.code}). "
        "t.code is the physical key code (e.g., 'KeyA', 'ShiftLeft') -- NOT the character value. "
        "This means PAM can detect user activity (is the session idle?) without reading keypress content. "
        "Clipboard: copy and cut events are blocked (preventDefault + stopPropagation) on PAM session pages "
        "unless allowCopy is true (set by service worker in the session info response)."
    ),

    "clipboard_block": (
        "registerCopyListener: window.addEventListener('copy', e=>{e.preventDefault();e.stopPropagation()}, capture=true). "
        "registerCutListener: same for 'cut'. "
        "This prevents users from copying credentials from PAM-managed web apps to clipboard."
    ),

    "note": "The code field does not reveal what the user typed, only which physical key was pressed. Intended for session activity/idle detection.",
}


# ---------------------------------------------------------
# FPE-CS-F06: _internal_get_credential_from_page -- bidirectional credential harvest
# ---------------------------------------------------------
FPE_CS_F06_CREDENTIAL_HARVEST_FROM_PAGE = {
    "id":       "FPE-CS-F06",
    "product":  "FortiPAM Chrome Extension content-script.js",
    "severity": "MEDIUM -- service worker can harvest credentials from any open tab's password fields",
    "class":    "Overly broad credential read access (CWE-522 + CWE-732)",

    "description": (
        "The content script's onMessageHandler accepts '_internal_get_credential_from_page' "
        "from the service worker (extension-internal; not web-page-triggerable). "
        "Handler calls getCredentialsFromPage(callback): "
        "queries document.querySelectorAll('[type=password]').filter(t=>t.value?.length>0), "
        "takes the last non-empty password field, reads its plaintext .value, "
        "finds the nearest username field via findNearestUsernameInput(lastPwdInput), "
        "and returns {username: usernameInput.value, password: lastPwdInput.value}. "
        "The service worker sends this message via chrome.tabs.sendMessage(tabId, msg) -- "
        "it can target ANY tab where the content script is active (all URLs). "
        "The 'quickCreateAction' feature legitimately uses this: when a user asks the extension "
        "to save a new PAM secret for the current page, it reads existing credentials. "
        "A logic bug in service_worker.js could cause this to run on the wrong tab, "
        "harvesting credentials from any page with filled password fields."
    ),

    "evidence": {
        "handler":  "_internal_get_credential_from_page at content-script.js offset 60084",
        "query":    "document.querySelectorAll('[type=\"password\"]').filter(t=>t.value?.length>0)",
        "returns":  "{type:'_internal_get_credential_from_page_response', username: str, password: str}",
        "caller":   "askContentScriptForCredentials(tab) in service_worker.js at offset 330380",
        "scope":    "content script is registered on <all_urls>; message can target any tab",
    },

    "attack_scenario": (
        "1. Service worker has logic bug: sends _internal_get_credential_from_page to active tab "
        "instead of PAM-specific tab (e.g., tab selection race condition). "
        "2. Active tab is a banking site with filled password field. "
        "3. Content script returns {password: '<bank_password>'}. "
        "4. Service worker sends this to the PAM server API (createWebAccountSecretForUrl). "
        "Alternatively: XSS on the FortiPAM web UI triggers quickCreateAction "
        "via the extension's external message handler, targeting any tab ID."
    ),

    "note": (
        "This is intentional design (PAM secret creation flow). "
        "The risk is amplified by the <all_urls> content script scope -- "
        "no page is excluded from credential read access."
    ),
}


# ---------------------------------------------------------
# FPE-CS-F07: _internal_fill_specific_field_with_value -- arbitrary DOM injection
# ---------------------------------------------------------
FPE_CS_F07_ARBITRARY_DOM_FILL = {
    "id":       "FPE-CS-F07",
    "product":  "FortiPAM Chrome Extension content-script.js",
    "severity": "LOW -- arbitrary DOM field injection via service worker; no direct web-page trigger",
    "class":    "DOM injection via extension IPC (design-level attack surface)",

    "description": (
        "The content script's onMessageHandler accepts '_internal_fill_specific_field_with_value' "
        "from the service worker. "
        "Handler: const {selector, value} = t; this.fillSpecificFieldWithValue(selector, value). "
        "The selector is a CSS selector string; value is the string to inject. "
        "fillSpecificFieldWithValue() calls document.querySelector(selector) or similar, "
        "then sets the matched element's .value to the provided string and dispatches "
        "input/change events. "
        "This allows the service worker to inject any string into any CSS-selector-matched "
        "DOM element on any page where the content script runs. "
        "Web pages cannot trigger this directly (extension-internal message only). "
        "A compromised service worker or logic error in session injection could cause "
        "credential values to be written to wrong DOM elements on any page."
    ),

    "evidence": {
        "handler":   "_internal_fill_specific_field_with_value at content-script.js offset 60372",
        "payload":   "{type:'_internal_fill_specific_field_with_value', selector: str, value: str}",
        "no_origin": "origin of calling tab is not checked by content script; trusts service worker",
    },

    "note": "Exploitable only via service worker compromise or logic error; not a web-page-reachable surface.",
}


# ---------------------------------------------------------
# Finding index
# ---------------------------------------------------------
unique_findings = [
    "FPE-CS-F01", "FPE-CS-F02", "FPE-CS-F03",
    "FPE-CS-F04", "FPE-CS-F05", "FPE-CS-F06", "FPE-CS-F07",
]
