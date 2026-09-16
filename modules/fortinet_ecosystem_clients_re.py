"""
FortiOS/FortiManager ecosystem clients RE: Terraform provider, JSON-RPC connector,
n8n FortiSIEM node, ssl_vpn_brute, FortiOS backup encryption (systemic)
Sources:
  - connector-fortinet-fortimanager-json-rpc/ (generic_json_rpc.py, operations.py)
  - terraform-provider-fortios/sdk/ (auth.go, config.go, request.go, fortios/client.go)
  - npm-packages/extracted/n8n-nodes-fortisiem-0.3.1/ (GenericFunctions.js)
Products: FortiManager, FortiOS, FortiSIEM
"""

# ---------------------------------------------------------
# FortiManager JSON-RPC connector (FortiSOAR) -- RE findings
# ---------------------------------------------------------
FMG_JSONRPC_CONNECTOR = {
    "id":       "FFMG-JSONRPC",
    "product":  "FortiManager via FortiSOAR JSON-RPC connector (connector-fortinet-fortimanager-json-rpc)",
    "source":   "connector-fortinet-fortimanager-json-rpc/fortinet-fortimanager-json-rpc/generic_json_rpc.py",
    "library":  "pyFMG (FortiManager Python library)",
}

FFMG_JSONRPC_F01_FREE_FORM = {
    "id":       "FFMG-JSONRPC-F01",
    "product":  "FortiManager JSON-RPC connector -- free_form action",
    "severity": "MEDIUM -- free_form exposes raw FortiManager JSON-RPC API with no URL restriction",
    "class":    "Unconstrained API proxy; arbitrary FortiManager URL + data forwarded (CWE-20)",

    "description": (
        "perform_rpc_action('free_form', config, params): "
        "  method = params.get('method') -> any FortiManager JSON-RPC method. "
        "  data['data'] -> list of {url, data} dicts forwarded to fmg.free_form(method, **data). "
        "  url is extracted from data['data'][0]['url'] for ADOM lock purposes. "
        "The free_form action is a raw JSON-RPC passthrough -- no allow-list on URLs or methods. "
        "An operator with FortiSOAR write access can send arbitrary exec/set/add/delete "
        "FortiManager JSON-RPC calls to the connected FortiManager instance "
        "without FortiSOAR enforcing any schema or safety checks. "
        "Risk: privilege escalation from FortiSOAR operator -> FortiManager admin-equivalent via free_form."
    ),

    "adom_lock_note": (
        "free_form with workspace-enabled FortiManager triggers ADOM lock. "
        "Lock retry loop: MAX_RETRY_LIMIT=1500 with random 1-10 second sleep. "
        "Maximum wait: 1500 * 10 = 15000 seconds (~4 hours). "
        "A failing lock on a large ADOM could leave the connector stuck for hours, "
        "blocking all other FortiManager operations from the same connection pool."
    ),
}

FFMG_JSONRPC_F02_SSL = {
    "id":       "FFMG-JSONRPC-F02",
    "product":  "FortiManager JSON-RPC connector -- TLS warning suppression in tests",
    "severity": "LOW -- production defaults to verify_ssl=True; test suite defaults to False",
    "class":    "Test suite insecure default (CWE-295) -- credential transmission during CI/CD",

    "description": (
        "Production: verify_ssl = config.get('verify_ssl', True). Default is True. "
        "FortiManager() call: disable_request_warnings=True -- suppresses urllib3 InsecureRequestWarning globally. "
        "Test suite (run_tests.py, test_concurrent, test_sequential): "
        "  'verify_ssl': os.getenv('VERIFY_SSL', 'False').lower() in ('true', '1', 't'). "
        "  Default VERIFY_SSL env = 'False' -> verify_ssl=False in all test runs. "
        "Test-suite credentials (FORTIOS_FMG_HOSTNAME, FORTIOS_FMG_USERNAME, FORTIOS_FMG_PASSWORD) "
        "are transmitted over unverified TLS if VERIFY_SSL is not explicitly set. "
        "disable_request_warnings=True: no user-visible warning when InsecureSkipVerify is in effect."
    ),
}


# ---------------------------------------------------------
# Terraform provider FortiOS -- RE findings
# ---------------------------------------------------------
TERRAFORM_FORTIOS = {
    "id":       "FTERRAFORM",
    "product":  "Fortinet Terraform provider for FortiOS (terraform-provider-fortios)",
    "source":   "terraform-provider-fortios/sdk/ + fortios/client.go",
    "language": "Go",
}

FTERRAFORM_TLS_DESIGN = {
    "id":       "FTERRAFORM-TLS",
    "product":  "Terraform provider FortiOS -- TLS verification",
    "severity": "INFORMATIONAL -- well-designed; forces CA bundle or explicit insecure flag",
    "class":    "Security-conscious design (no finding); documented for ecosystem comparison",

    "description": (
        "client.go line 236: if c.Insecure == nil -> default Insecure=false (secure). "
        "line 244: if InsecureSkipVerify==false && CABundle=='' && CABundleContent=='': "
        "  return error 'CA Bundle should be set when insecure is false'. "
        "The provider REQUIRES a CA bundle when InsecureSkipVerify=false. "
        "This is a deliberate enforcement: no silent insecure connections. "
        "Contrast: PyFortiAPI, fortigate_api both default to verify=False. "
        "Terraform: correct by default + enforced CA bundle = most secure Fortinet client surveyed."
    ),

    "env_vars": {
        "FORTIOS_ACCESS_TOKEN":    "API token",
        "FORTIOS_ACCESS_HOSTNAME": "target hostname",
        "FORTIOS_ACCESS_USERNAME": "username (fallback)",
        "FORTIOS_ACCESS_PASSWORD": "password (fallback)",
        "FORTIOS_CA_CABUNDLE":     "CA bundle file path",
        "FORTIOS_INSECURE":        "'true' enables InsecureSkipVerify; default false",
        "FORTIOS_FMG_INSECURE":    "FortiManager-specific insecure flag",
        "HTTPS_PROXY":             "HTTP proxy (logged as WARNING if not set)",
    },

    "auth_flow": (
        "1. Bearer token (Authorization: Bearer {token}) if FORTIOS_ACCESS_TOKEN set. "
        "2. LoginToken(): POST /logincheck with username+password -> get CSRF token. "
        "3. LoginSession(): fallback if token login fails -> session cookie. "
        "Login per request: token/session obtained and then logged out after each request. "
        "No long-lived session cache -- reduces risk of session fixation from the client side."
    ),
}


# ---------------------------------------------------------
# n8n FortiSIEM node -- RE findings
# ---------------------------------------------------------
N8N_FORTISIEM = {
    "id":       "FN8N-FORTISIEM",
    "product":  "FortiSIEM via n8n workflow automation (n8n-nodes-fortisiem-0.3.1)",
    "source":   "npm-packages/extracted/n8n-nodes-fortisiem-0.3.1/dist/nodes/FortiSiem/GenericFunctions.js",
    "language": "TypeScript/JavaScript (n8n community node)",
}

FN8N_FORTISIEM_F01_TOKEN_CACHE = {
    "id":       "FN8N-FORTISIEM-F01",
    "product":  "n8n FortiSIEM node -- in-process token cache",
    "severity": "LOW -- token cache persists for process lifetime; no per-tenant isolation",
    "class":    "Credential cache lifetime issue; process-global Map (CWE-312)",

    "description": (
        "const tokenCache = new Map() -- module-level singleton. "
        "Cache key: 'baseUrl::clientId'. "
        "Token cached until expiresAt > Date.now() (typically expiresIn - 60 seconds). "
        "Risk: in a multi-tenant n8n deployment, tokens from different users "
        "sharing the same baseUrl+clientId combination are cached across tenant boundaries. "
        "The cache is never invalidated on connection error or credential rotation. "
        "If credentials are rotated (clientSecret changed), the cached token remains valid "
        "until natural expiry -- old token continues to be used."
    ),

    "oauth_endpoint": "/phoenix/rest/pub/security/oauth/token (client_credentials grant)",
    "ssl_note": "skipSslCertificateValidation: credentials.allowUnauthorizedCerts -- user-configurable; no forced default",
}


# ---------------------------------------------------------
# Fortinet ecosystem TLS verification comparison table
# ---------------------------------------------------------
FORTINET_ECOSYSTEM_TLS_COMPARISON = {
    "id":       "FECO-TLS-SYSTEMIC",
    "product":  "Fortinet ecosystem clients (comparative analysis)",
    "severity": "HIGH -- majority of third-party Fortinet clients default to insecure TLS",

    "client_tls_defaults": {
        "fortiosapi (Python)":                 "verify=True (default); best-in-class; mkey URL-encoded",
        "Terraform provider (Go)":             "InsecureSkipVerify=false (default); forces CABundle; best-in-class",
        "FortiManager JSON-RPC connector":     "verify_ssl=True (production default); disable_request_warnings=True",
        "n8n FortiSIEM node":                  "allowUnauthorizedCerts user-configurable; no forced default",
        "PyFortiAPI (PyPI)":                   "verify=False (DEFAULT); process-wide urllib3 warning suppression at login",
        "fortigate_api (PyPI)":                "bool(None)=False (DEFAULT); module-level warning suppression at import",
        "Ansible fortios httpapi":             "verify=True (Ansible default); but X-Admin-Passwd header exposure",
        "Ansible fortimanager httpapi":        "verify=True (Ansible default); plaintext passwd in JSON body",
    },

    "pattern": (
        "Three distinct tiers observed: "
        "Tier 1 (secure): fortiosapi, Terraform -- verify-by-default + CABundle enforcement. "
        "Tier 2 (configurable): FortiManager JSON-RPC connector, n8n -- verify-by-default in production, "
        "  but disable in tests or via user config. "
        "Tier 3 (insecure by default): PyFortiAPI, fortigate_api -- verify=False as default; "
        "  process-wide warning suppression masks the exposure. "
        "Tier 3 clients in production environments transmit FortiOS credentials over unauthenticated TLS "
        "to any host the library connects to (including SSRF targets). "
        "The SSRF impact is multiplicative: "
        "  FortiNDR Cloud SSRF (FFNDR-F01) + PyFortiAPI verify=False -> IBToken + FortiOS password in one request "
        "  to any attacker-controlled URL."
    ),
}
