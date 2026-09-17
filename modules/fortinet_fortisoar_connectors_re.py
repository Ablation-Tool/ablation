"""
FortiSOAR Fortinet connector Python source RE
Sources:
  - repo.fortisoar.fortinet.com/connectors/x86_64/ (public RPM repo, no auth)
  - cyops-connector-fortinet-fortipam-1.0.0-10924.el9.x86_64.rpm
  - cyops-connector-fortinet-fortisiem-6.2.0-11459.el9.x86_64.rpm
  - cyops-connector-fortinet-fortimanager-json-rpc-1.1.0-10282.el9.x86_64.rpm
Products: FortiSOAR SOAR platform; FortiPAM 1.0.0; FortiSIEM 6.2.0; FortiManager JSON-RPC 1.1.0
"""

# ---------------------------------------------------------
# Connector repo -- product context
# ---------------------------------------------------------
FORTISOAR_CONNECTOR_REPO = {
    "id":      "FSOAR-CON",
    "product": "FortiSOAR Fortinet connector suite (cyops-connector-fortinet-*)",
    "source":  "repo.fortisoar.fortinet.com/connectors/x86_64/ (public, no auth)",
    "version": "fortipam 1.0.0 / fortisiem 6.2.0 / fortimanager-json-rpc 1.1.0",
    "purpose": "SOAR playbook integration layer between FortiSOAR and Fortinet product APIs",

    "repo_structure": (
        "Apache directory listing at repo.fortisoar.fortinet.com. "
        "Root: 28 FortiSOAR version dirs + connectors/, content-hub/, fortisoar/, patches/. "
        "connectors/x86_64/: 1000+ cyops-connector-*.rpm packages (no auth). "
        "RPM inner structure: rpm2cpio | cpio -id -> "
        "opt/cyops-connector-<name>/fortinet-<name>.tgz -> Python connector source."
    ),

    "connector_layout": {
        "fortipam":             "operation.py, connector.py, info.json, playbooks/playbooks.json",
        "fortisiem":            "schema.py, constants.py, utils.py, forticloud_auth.py, forticloud_token.py, "
                                "watch_list_actions.py, resource_list_actions.py, lookup_table_actions.py, "
                                "compatible_v751_actions.py, attributes_list.py",
        "fortimanager-json-rpc": "operations.py, connector.py, generic_json_rpc.py, __init__.py",
    },
}

# ---------------------------------------------------------
# FortiPAM connector -- API surface
# ---------------------------------------------------------
FORTIPAM_CONNECTOR_API = {
    "id":      "FSOAR-CON-FPAM",
    "product": "FortiSOAR FortiPAM connector v1.0.0",
    "source":  "operation.py",

    "auth_method":  "Bearer token in Authorization header: 'Authorization: Bearer {api_key}'",
    "base_url":     "https://{address}:{port}",

    "api_endpoints": {
        "get_all_users":          "GET  /api/v2/cmdb/system/admin",
        "get_user_details":       "GET  /api/v2/cmdb/system/admin/{name}",
        "update_user":            "PUT  /api/v2/cmdb/system/admin/{name}",
        "delete_user":            "DELETE /api/v2/cmdb/system/admin/{name}?vdom=root",
        "execute_an_api_request": "ANY  {user-supplied endpoint}",
    },

    "api_base_note": (
        "FortiPAM uses /api/v2/cmdb/system/admin -- the standard FortiOS CMDB REST API. "
        "This confirms FortiPAM is built on FortiOS; its management API is the same class "
        "of surface as FortiGate. Full FortiOS CMDB attack surface applies."
    ),

    "cmdb_admin_response_fields": [
        "name", "password", "history0..history19", "shared-key",
        "ssh-public-key1", "ssh-public-key2", "ssh-public-key3",
        "fortitoken", "two-factor", "two-factor-authentication",
        "trusthost1..trusthost10", "vdom", "accprofile",
    ],
}

# ---------------------------------------------------------
# FORTISOAR-CON-F01: FortiPAM unconstrained API proxy
# ---------------------------------------------------------
FORTISOAR_CON_F01_FORTIPAM_API_PROXY = {
    "id":       "FORTISOAR-CON-F01",
    "product":  "FortiSOAR -- FortiPAM connector execute_an_api_request",
    "severity": "MEDIUM -- unconstrained API proxy; any SOAR playbook reaches any FortiPAM API path",
    "class":    "Unconstrained proxy / SSRF-adjacent (CWE-918)",
    "source":   "operation.py:159-168",

    "description": (
        "execute_an_api_request() accepts three playbook-controlled parameters with no allowlist: "
        "  endpoint: str  -- any URL path on the FortiPAM server "
        "  method:   str  -- any HTTP verb (GET/POST/PUT/PATCH/DELETE) "
        "  payload:  dict -- arbitrary JSON body "
        "The stored Bearer api_key is appended to every request. "
        "A SOAR playbook (including attacker-injected via alert-ingestion) can direct the connector "
        "to any FortiPAM REST endpoint: /api/v2/cmdb/system/admin, /api/v2/cmdb/vpn.ssl/, "
        "/api/v2/cmdb/firewall/, /api/v2/monitor/, etc. "
        "Scope is bounded only by the API key's FortiPAM permission profile."
    ),

    "code_evidence": (
        "def execute_an_api_request(config, params):\n"
        "    endpoint = params.get('endpoint')\n"
        "    http_method = params.get('method')\n"
        "    query_parameters = params.get('query_params') if params.get('query_params') else {}\n"
        "    payload = params.get('payload') if params.get('payload') else {}\n"
        "    response = _api_request(config, endpoint, parameters=query_parameters,\n"
        "                            method=http_method, body=payload)\n"
        "    return response"
    ),

    "impact": (
        "Playbook injections via compromised FortiSOAR alert ingestion or playbook tampering "
        "can issue arbitrary authenticated API calls to FortiPAM. "
        "If FortiPAM API key has write permissions: admin user creation, policy modification, "
        "VPN config changes. "
        "If FortiPAM API key has read permissions: full admin user list including credential hashes."
    ),

    "remediation": "Allowlist valid endpoint patterns; validate method against a fixed set; "
                   "scope API key to minimum required permissions.",
}

# ---------------------------------------------------------
# FORTISOAR-CON-F02: CMDB admin response leaks credential hashes
# ---------------------------------------------------------
FORTISOAR_CON_F02_CMDB_CREDENTIAL_FIELDS = {
    "id":       "FORTISOAR-CON-F02",
    "product":  "FortiSOAR -- FortiPAM connector CMDB admin API response",
    "severity": "MEDIUM -- admin user list exposes password hashes, 2FA keys, SSH public keys",
    "class":    "Sensitive data exposure in API response (CWE-200)",
    "source":   "info.json output_schema for get_all_users / get_user_details",

    "description": (
        "GET /api/v2/cmdb/system/admin returns the full admin user record. "
        "The documented output schema includes: "
        "  password        -- admin password (FortiOS returns ENC(xxx) encoded hash) "
        "  history0..19    -- previous 20 password hashes (password reuse detection data) "
        "  shared-key      -- 2FA TOTP shared secret (base32 seed for TOTP) "
        "  fortitoken      -- hardware/software FortiToken serial "
        "  ssh-public-key1/2/3 -- SSH public keys for the admin "
        "  trusthost1..10  -- allowed source IP ranges for the admin "
        "Any SOAR integration with a read-level FortiPAM API key receives all of these. "
        "If FortiSOAR is compromised, attacker retrieves all admin password hashes and 2FA seeds."
    ),

    "impact": (
        "ENC(xxx) password hashes are FortiOS-specific encoding; the underlying hash is SHA-1 or MD5 "
        "depending on firmware version. Offline cracking feasible for weak passwords. "
        "2FA shared-key exposure allows TOTP code generation without hardware token. "
        "Combined with valid username: full authentication bypass of FortiPAM admin console."
    ),

    "remediation": "FortiSOAR API key for FortiPAM should be scoped to specific operations only. "
                   "Monitor CMDB admin endpoint access in FortiPAM audit logs.",
}

# ---------------------------------------------------------
# FORTISOAR-CON-F03: FortiSIEM debug log credential leak
# ---------------------------------------------------------
FORTISOAR_CON_F03_FORTISIEM_DEBUG_CREDLEAK = {
    "id":       "FORTISOAR-CON-F03",
    "product":  "FortiSOAR -- FortiSIEM connector OAuth2 credential logging",
    "severity": "LOW -- credentials in debug logs; requires log access",
    "class":    "Sensitive data in debug output (CWE-312)",
    "source":   "forticloud_auth.py:87",

    "description": (
        "acquire_token() logs the full OAuth2 token request payload at DEBUG level: "
        "  data = { "
        "    'username': config.get('username'), "
        "    'password': config.get('password'), "
        "    'client_id': config.get('client_id'), "
        "    'grant_type': 'password' "
        "  } "
        "  logger.debug('Payload: {0}'.format(data)) "
        "If FortiSOAR debug logging is enabled (development/troubleshooting), "
        "the FortiSIEM username and plaintext password are written to connector log files. "
        "FortiSOAR connector logs are stored on the FortiSOAR appliance filesystem."
    ),

    "code_evidence": (
        "# forticloud_auth.py:87\n"
        "logger.debug('Payload: {0}'.format(data))\n"
        "# data = {'username': ..., 'password': ..., 'client_id': ..., 'grant_type': 'password'}"
    ),

    "impact": "Anyone with FortiSOAR filesystem access or log aggregation access "
              "reads the FortiSIEM service account password in plaintext during debug mode.",

    "remediation": "Redact password from log payload before debug logging. "
                   "Log only grant_type and client_id.",
}

# ---------------------------------------------------------
# FORTISOAR-CON-F04: FortiManager JSON-RPC unconstrained freeform proxy
# ---------------------------------------------------------
FORTISOAR_CON_F04_FMG_FREEFORM_PROXY = {
    "id":       "FORTISOAR-CON-F04",
    "product":  "FortiSOAR -- FortiManager JSON-RPC connector json_rpc_freeform",
    "severity": "MEDIUM -- unconstrained JSON-RPC proxy to FortiManager; full API surface reachable",
    "class":    "Unconstrained proxy (CWE-918)",
    "source":   "operations.py:69-75, generic_json_rpc.py:181-205",

    "description": (
        "json_rpc_freeform() calls perform_rpc_action('free_form', config, params) where: "
        "  params['method'] -- raw JSON-RPC method string (no allowlist) "
        "  params['data']   -- full JSON-RPC payload as list of objects "
        "The underlying pyFMG free_form() call passes these directly to the FortiManager API. "
        "If workspaces are enabled (fmg._lock_ctx.uses_workspace), the connector automatically "
        "locks the ADOM extracted from the first URL in the data list before executing. "
        "No method allowlist. No URL path restrictions. "
        "Full FortiManager JSON-RPC surface reachable: "
        "  add, set, get, execute, delete, replace, move, clone, update "
        "  against any /adom/{adom}/* path."
    ),

    "code_evidence": (
        "# generic_json_rpc.py:193-198\n"
        "if action == 'free_form':\n"
        "    method = params.get('method')\n"
        "    status, action_response = action_func(method, **data)\n"
        "# data constructed from params['data'] -- user-controlled JSON list"
    ),

    "impact": (
        "SOAR playbook tampering or injection allows arbitrary FortiManager API calls: "
        "policy push to managed FortiGates, device provisioning, configuration replacement, "
        "ADOM policy modification. FortiManager manages 100s-1000s of FortiGate devices; "
        "a single compromised SOAR connector reaches all managed devices."
    ),

    "remediation": "Restrict free_form to allowlisted methods and URL path prefixes. "
                   "Audit SOAR playbooks that use json_rpc_freeform.",
}

# ---------------------------------------------------------
# FORTISOAR-CON-F05: FortiManager ADOM lock starvation
# ---------------------------------------------------------
FORTISOAR_CON_F05_FMG_LOCK_STARVATION = {
    "id":       "FORTISOAR-CON-F05",
    "product":  "FortiSOAR -- FortiManager JSON-RPC connector ADOM lock retry",
    "severity": "LOW -- lock contention DoS; requires ability to trigger many concurrent connector ops",
    "class":    "Resource exhaustion via lock starvation (CWE-400)",
    "source":   "generic_json_rpc.py:19, 124-151",

    "description": (
        "lock_adom() retries up to MAX_RETRY_LIMIT=1500 times with random sleep(randint(1,10)) "
        "between attempts. Upper bound per contention cycle: 1500 * 10 = 15,000 seconds (~4.2 hours). "
        "If an attacker can trigger many concurrent SOAR playbook executions that each attempt "
        "to lock the same ADOM, the retry loop ties up connector worker threads for hours. "
        "Each blocked worker holds a FortiManager session object (pyFMG context manager). "
        "FortiManager has a session limit; exhausting it locks out legitimate management."
    ),

    "code_evidence": (
        "MAX_RETRY_LIMIT = 1500\n"
        "for attempt in range(MAX_RETRY_LIMIT):\n"
        "    status, _ = fmg.lock_adom(adom)\n"
        "    if status == 0: return True\n"
        "    sleep_time = random.randint(1, 10)\n"
        "    time.sleep(sleep_time)"
    ),

    "impact": "SOAR connector worker thread exhaustion; FortiManager session exhaustion; "
              "management lockout during active incident response.",

    "remediation": "Add a shorter per-lock timeout; implement exponential backoff with a hard ceiling; "
                   "cap MAX_RETRY_LIMIT to ~30 with a 300-second total timeout.",
}

# ---------------------------------------------------------
# FORTISOAR-CON-F06: FortiSIEM OAuth2 refresh token persistence
# ---------------------------------------------------------
FORTISOAR_CON_F06_FORTISIEM_TOKEN_PERSISTENCE = {
    "id":       "FORTISOAR-CON-F06",
    "product":  "FortiSOAR -- FortiSIEM connector OAuth2 token storage",
    "severity": "LOW -- refresh token persisted in FortiSOAR config DB",
    "class":    "Persistent credential storage (CWE-522)",
    "source":   "forticloud_auth.py:54-58, 119-124",

    "description": (
        "generate_or_validate_token() stores access_token, refresh_token, and expiresOn "
        "back into the FortiSOAR connector config via update_connnector_config(). "
        "Refresh tokens for FortiCloud OAuth2 typically have 30-day TTL. "
        "If FortiSOAR database is compromised, the attacker obtains a live refresh token "
        "valid for another 30 days and can generate fresh access tokens without credentials. "
        "FortiCloud token endpoint: customerapiauth.fortinet.com/api/v1/oauth/token/ "
        "Grant type: refresh_token with client_id."
    ),

    "cloud_auth_endpoints": {
        "oauth_token":     "https://customerapiauth.fortinet.com/api/v1/oauth/token/",
        "fsoc_token":      "/api/auth/cloud/long-lived/token",
        "fsoc_refresh":    "/api/auth/cloud/long-lived/refresh-token",
    },

    "impact": "FortiSOAR DB compromise -> live FortiCloud refresh token -> "
              "FortiSIEM API access for up to 30 days without re-authentication.",

    "remediation": "Do not persist refresh tokens in the SOAR connector config DB. "
                   "Use short-lived credentials or a secrets vault integration.",
}

# ---------------------------------------------------------
# Connector repo public exposure -- architecture note
# ---------------------------------------------------------
FORTISOAR_CON_REPO_NOTE = {
    "id":    "FSOAR-CON-REPO",
    "note":  (
        "repo.fortisoar.fortinet.com is a public Apache directory listing. "
        "All Fortinet SOAR connector Python source code is downloadable without authentication. "
        "RPM structure: rpm2cpio | cpio -> opt/cyops-connector-fortinet-<name>/<name>.tgz -> Python. "
        "140+ Fortinet-product-specific connectors confirmed at time of enumeration. "
        "This is intentional (public connector repository); source exposure is by design."
    ),
}

unique_findings = [
    "FORTISOAR-CON-F01",
    "FORTISOAR-CON-F02",
    "FORTISOAR-CON-F03",
    "FORTISOAR-CON-F04",
    "FORTISOAR-CON-F05",
    "FORTISOAR-CON-F06",
]
