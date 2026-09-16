"""
Fortinet Ansible collection httpapi plugins RE
Sources:
  - ansible-collections/fortios/httpapi_fortios.py
  - ansible-collections/fortimanager/httpapi_fortimanager.py
  - ansible-collections/fortimanager/napi.py
Products: FortiOS, FortiManager (via Ansible Automation Platform / AWX)
"""

# ---------------------------------------------------------
# Architecture summary
# ---------------------------------------------------------
ARCHITECTURE = {
    "fortios_httpapi": {
        "file":   "ansible-collections/fortios/httpapi_fortios.py",
        "class":  "HttpApi (Ansible httpapi plugin)",
        "auth":   "access_token (Bearer) or username+password (form POST or JSON API)",
        "target": "FortiOS REST API (/api/v2/cmdb, /api/v2/monitor, /api/v2/authentication)",
        "session": "_session_key stored on object; _admin_password cached for X-Admin-Passwd",
    },
    "fortimanager_httpapi": {
        "file":   "ansible-collections/fortimanager/httpapi_fortimanager.py",
        "class":  "HttpApi (Ansible httpapi plugin)",
        "auth":   "username+password JSON RPC; Bearer token; forticloud_access_token",
        "target": "FortiManager JSON RPC (/jsonrpc, sys/login/user)",
        "session": "_sid (session token); passwd in JSON login body",
    },
    "fortimanager_napi": {
        "file":   "ansible-collections/fortimanager/napi.py",
        "class":  "NAPIManager",
        "role":   "Task orchestration: maps Ansible module params -> FortiManager API calls",
        "key_methods": ["process_crud", "process_exec", "process_task", "get_mvalue"],
    },
}


# ---------------------------------------------------------
# FANSIBLE-F01: FortiOS httpapi -- plaintext password cached in X-Admin-Passwd header per-request
# ---------------------------------------------------------
FANSIBLE_F01_XADMINPASSWD_HEADER = {
    "id":       "FANSIBLE-F01",
    "product":  "FortiOS via Ansible httpapi collection (ansible-collections/fortios)",
    "severity": "MEDIUM -- admin password cached on httpapi object; sent in X-Admin-Passwd header on confirmation-required requests",
    "class":    "Sensitive credential in HTTP header; long-lived credential cache (CWE-312, CWE-598)",

    "description": (
        "httpapi_fortios.py login(): self._admin_password = password (line 170). "
        "Comment: 'Cache password for features that need per-request confirmation headers.' "
        "send_request() (line 368): "
        "if 'X-Admin-Passwd' in headers and headers.get('X-Admin-Passwd') is True: "
        "    self._admin_password = self._conn.get_option('password') [fallback] "
        "    headers['X-Admin-Passwd'] = str(self._admin_password). "
        "The plaintext admin password is sent in the X-Admin-Passwd HTTP header on every request "
        "that requires admin confirmation (since FortiOS 7.6.5 for admin-related APIs). "
        "Exposure scenarios: "
        "(1) If Ansible is configured with ansible_httpapi_use_ssl=false, the header is sent in cleartext. "
        "(2) HTTP proxy logs that capture headers record the password. "
        "(3) Ansible debug logging at verbosity -vvvv logs request headers including X-Admin-Passwd. "
        "Separate from the session token -- this is the raw admin password, not a derived credential."
    ),

    "cache_lifecycle": (
        "login() -> self._admin_password = password. "
        "Object lifetime: for the duration of the Ansible play. "
        "Ansible connections are reused across tasks within a play -- the password persists "
        "in the httpapi object's memory for the entire play duration, "
        "not just for the login request."
    ),

    "line_references": "httpapi_fortios.py:170 (cache), :368-378 (header injection)",
}


# ---------------------------------------------------------
# FANSIBLE-F02: FortiManager httpapi -- passwd in JSON RPC body + log redaction after-the-fact
# ---------------------------------------------------------
FANSIBLE_F02_FMG_PASSWD_JSON = {
    "id":       "FANSIBLE-F02",
    "product":  "FortiManager via Ansible httpapi collection (ansible-collections/fortimanager)",
    "severity": "MEDIUM -- login() embeds passwd in JSON RPC body; log_request() redacts after construction",
    "class":    "Credential in plaintext JSON body; post-hoc log redaction (CWE-312)",

    "description": (
        "httpapi_fortimanager.py login(): "
        "'data': {'passwd': to_text(password), 'user': to_text(username)} "
        "-> send_request('exec', [{url: 'sys/login/user', data: {passwd: ..., user: ...}}]). "
        "This is the same pattern as FFAZ-F01 (FortiAnalyzer Go SDK) and the "
        "FortiManager JSON RPC spec: plaintext password in JSON body to /jsonrpc. "
        "log_request() (line 89-90) modifies params[0]['data']['passwd'] = '******' before logging -- "
        "this redaction happens in the logging path only. "
        "The actual request body sent to the wire contains the plaintext password. "
        "If the logging code runs before the send (which it does here), "
        "the redaction mutates the same dict object that is serialized for the request -- "
        "this means the request could be sent with '******' instead of the real password "
        "if the dict is shared by reference and log_request is called before send. "
        "Needs verification in the send path to confirm whether mutation affects the wire payload."
    ),

    "log_redaction_race": (
        "log_request() mutates params[0]['data']['passwd'] = '******'. "
        "If params is the same dict passed to send_request, the mutation may corrupt the login payload. "
        "This is a subtle bug in the defensive coding: the redaction for logging may break authentication "
        "if the params dict is shared by reference between log_request and the JSON serializer."
    ),

    "line_references": "httpapi_fortimanager.py:151 (passwd in body), :89-90 (log redaction)",
}


# ---------------------------------------------------------
# FANSIBLE-F03: FortiManager napi -- bypass_validation disables all Ansible schema validation
# ---------------------------------------------------------
FANSIBLE_F03_BYPASS_VALIDATION = {
    "id":       "FANSIBLE-F03",
    "product":  "FortiManager via Ansible napi (ansible-collections/fortimanager)",
    "severity": "MEDIUM -- bypass_validation=true removes all Ansible-layer schema validation; arbitrary params reach FortiManager API",
    "class":    "Validation bypass by design; attack surface expansion (CWE-20)",

    "description": (
        "napi.py get_bypass(params): returns True if params['bypass_validation'] is truthy. "
        "check_parameter_bypass(): if is_bypass: replace full schema with {type: dict} or {type: list}. "
        "When bypass_validation=true in an Ansible task, the FortiManager module "
        "accepts any key-value pairs without validating them against the module's JSON schema. "
        "All params pass through to the FortiManager API call without Ansible-layer checks. "
        "This is documented as a feature (escape hatch for schema mismatches), "
        "but creates a validation bypass path that: "
        "(1) Allows typos and invalid params to reach FortiManager silently. "
        "(2) If FortiManager's own API validation has gaps, allows injection of unexpected parameters. "
        "(3) In CI/CD pipelines where Ansible playbooks are auto-generated, "
        "bypass_validation=true in a template enables arbitrary FortiManager API calls "
        "without the Ansible schema acting as a filter."
    ),

    "bypass_example": (
        "- fortinet.fortimanager.fmgr_dvmdb_device:\n"
        "    bypass_validation: true\n"
        "    dvmdb_device:\n"
        "      arbitrary_key: arbitrary_value  # no schema check"
    ),
}


# ---------------------------------------------------------
# FANSIBLE-F04: FortiManager napi -- eval() on complex: prefixed module_primary_key
# ---------------------------------------------------------
FANSIBLE_F04_EVAL_COMPLEX_KEY = {
    "id":       "FANSIBLE-F04",
    "product":  "FortiManager via Ansible napi (ansible-collections/fortimanager)",
    "severity": "LOW -- eval() on complex:-prefixed module_primary_key; supply chain concern if schema files modified",
    "class":    "Code execution via eval() on schema-level string; supply chain risk (CWE-95)",

    "description": (
        "napi.py get_mvalue() (line 559-562): "
        "if self.module_primary_key.startswith('complex:'): "
        "    mvalue_exec_string = self.module_primary_key[len('complex:'):] "
        "    mvalue_exec_string = mvalue_exec_string.replace('{{module}}', 'self.module.params[self.module_level2_name]') "
        "    mvalue = eval(mvalue_exec_string). "
        "module_primary_key is a schema-level constant defined in the Fortinet Ansible collection's "
        "module definitions, not directly controlled by playbook authors. "
        "The eval() executes Python code built from the schema file. "
        "Supply chain risk: if an attacker compromises the Fortinet Ansible collection "
        "(e.g., via a malicious release to Ansible Galaxy), a modified module schema "
        "with a 'complex:__import__(\"os\").system(...)' primary_key would execute arbitrary code "
        "on the Ansible controller during any play using that module. "
        "Not directly exploitable by a playbook author in normal usage."
    ),

    "trigger_condition": (
        "module_primary_key starts with 'complex:' -> rest of string is eval()'d Python. "
        "In current collection schemas, complex: keys are legitimate Python expressions "
        "like 'complex:self.module.params[self.module_level2_name][\"name\"]'. "
        "Attacker must control schema files on the Ansible controller file system."
    ),

    "line_references": "napi.py:559-562",
}


# ---------------------------------------------------------
# Cross-tool systemic analysis
# ---------------------------------------------------------
FORTINET_ANSIBLE_SYSTEMIC = {
    "id":       "FANSIBLE-SYSTEMIC",
    "product":  "Fortinet Ansible collections (FortiOS + FortiManager)",
    "severity": "MEDIUM -- Ansible control node becomes privileged long-lived client for all Fortinet products",
    "class":    "Systemic: Ansible controller credential exposure pattern",

    "pattern": (
        "The Ansible httpapi plugins cache credentials (session tokens, raw passwords) "
        "in the httpapi connection object for the duration of a play. "
        "Ansible connections are forked from the controller process -- credentials are in process memory. "
        "The controller runs all plays: a malicious playbook imported alongside legitimate ones "
        "(supply chain via Ansible Galaxy or AWX project import) can access the connection object "
        "and read cached credentials. "
        "The FortiOS X-Admin-Passwd header (FANSIBLE-F01) compounds this: "
        "the raw admin password is sent repeatedly across HTTP/HTTPS connections, "
        "not just at login time."
    ),

    "password_in_json_pattern": (
        "FortiManager JSON RPC requires plaintext passwd in sys/login/user body. "
        "This is a FortiManager API design choice -- not fixable at the Ansible layer "
        "without Fortinet changing the API. "
        "Third instance documented (FFAZ-F01, FANSIBLE-F02, and original FMG spec). "
        "Pattern: ALL FortiManager JSON RPC integrations (Go SDK, Ansible, FortiSOAR connector) "
        "must send the plaintext password in the JSON body."
    ),
}
