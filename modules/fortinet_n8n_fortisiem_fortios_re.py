"""
Fortinet n8n-nodes-fortisiem + n8n-nodes-fortios RE
Sources:
  - npm-packages/extracted/n8n-nodes-fortisiem-0.3.1/dist/nodes/FortiSiem/
  - npm-packages/extracted/n8n-nodes-fortios-1.0.0/dist/nodes/FortiOs/
Products: FortiSIEM (via n8n), FortiOS (via n8n)
"""

# ---------------------------------------------------------
# Architecture summary
# ---------------------------------------------------------
ARCHITECTURE = {
    "n8n_fortisiem": {
        "package":   "n8n-nodes-fortisiem v0.3.1",
        "auth":      "basicAuth (username:password -> Basic header) or accessToken (client_id+client_secret -> Bearer)",
        "token_endpoint": "POST /phoenix/rest/pub/security/oauth/token (client_credentials grant)",
        "token_cache":    "module-level Map keyed by baseUrl::clientId; TTL = expires_in - 60s",
        "resources": ["discovery", "event", "incident", "osquery", "agent", "case",
                      "cmdbQuery", "context", "device", "deviceMaintenance", "health",
                      "lookupTable", "organization", "reputation", "watchlist", "worker"],
        "ssl_bypass": "allowUnauthorizedCerts -> skipSslCertificateValidation",
    },
    "n8n_fortios": {
        "package":   "n8n-nodes-fortios v1.0.0",
        "auth":      "tokenQuery (access_token=<token> in query string) or tokenBearer (Authorization: Bearer)",
        "resources": ["systemAdmin", "systemInterface", "systemDns", "firewallPolicy",
                      "firewallAddress", "firewallVip", "firewallIppool", "routerStatic",
                      "routerBgp", "routerPolicy", "antivirusProfile", "ipsSensor",
                      "webfilterProfile", "applicationList"],
        "ssl_bypass": "allowUnauthorizedCerts -> rejectUnauthorized=false",
    },
}


# ---------------------------------------------------------
# FFSN-F01: FortiSIEM n8n -- token cached in module-level Map; process-lifetime exposure
# ---------------------------------------------------------
FFSN_F01_TOKEN_CACHE = {
    "id":       "FFSN-F01",
    "product":  "FortiSIEM via n8n-nodes-fortisiem v0.3.1",
    "severity": "MEDIUM -- OAuth access token cached plaintext in module-level Map; process-lifetime",
    "class":    "Credential caching in long-lived process memory (CWE-316)",

    "description": (
        "getAccessToken() stores the OAuth bearer token in a module-level Map: "
        "tokenCache.set(cacheKey, {token: <bearer_token>, expiresAt: now + (expires_in - 60) * 1000}). "
        "cacheKey = baseUrl + '::' + clientId. "
        "The Map is process-global: any code running in the same n8n worker can access it. "
        "A malicious n8n community node can require() the GenericFunctions module and read tokenCache. "
        "On retry (401 response): old token deleted, new token fetched and re-cached. "
        "The token is a FortiSIEM Super/Global access token granting full API access, "
        "including event query, Osquery execution on all agents, and discovery credential management."
    ),

    "cache_structure": {
        "location": "const tokenCache = new Map(); (module-level, GenericFunctions.js)",
        "key":      "normalizeBaseUrl(baseUrl) + '::' + credentials.clientId",
        "value":    "{token: <oauth_bearer_token>, expiresAt: <timestamp>}",
        "lifetime": "until expires_in expires or process restart",
    },
}


# ---------------------------------------------------------
# FFSN-F02: FortiSIEM n8n -- submitArchiveQuery sends user-controlled XML to FortiSIEM
# ---------------------------------------------------------
FFSN_F02_ARCHIVE_XML = {
    "id":       "FFSN-F02",
    "product":  "FortiSIEM via n8n-nodes-fortisiem v0.3.1",
    "severity": "MEDIUM -- submitArchiveQuery sends user-controlled XML body to /phoenix/rest/query/archive; no sanitization",
    "class":    "Unsanitized XML body; potential XXE in FortiSIEM archive query parser (CWE-611)",

    "description": (
        "The event.submitArchiveQuery operation: "
        "const reportXml = this.getNodeParameter('reportXml', i); "
        "fortiSiemApiRequest('POST', '/phoenix/rest/query/archive', {body: reportXml, contentType: 'text/xml'}). "
        "The reportXml string is sent directly to FortiSIEM with no sanitization. "
        "If FortiSIEM's archive query XML parser does not disable external entity resolution, "
        "an XXE payload in reportXml reads local files from the FortiSIEM server: "
        "<?xml version='1.0'?><!DOCTYPE a [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>"
        "<reportDef><attribute>&x;</attribute></reportDef>. "
        "FortiSIEM is a Java application; Java XML parsers historically enabled XXE by default. "
        "The archive query XML format is documented and well-understood; this is an accessible attack path."
    ),

    "vulnerable_code": (
        "const reportXml = this.getNodeParameter('reportXml', i); "
        "return fortiSiemApiRequest('POST', '/phoenix/rest/query/archive', {body: reportXml, contentType: 'text/xml'})"
    ),

    "xxe_payload": (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<!DOCTYPE a [<!ENTITY x SYSTEM 'file:///etc/shadow'>]>"
        "<Reports><selectClause>&x;</selectClause></Reports>"
    ),

    "impact": (
        "If XXE is active: local file read from FortiSIEM super-server "
        "(/etc/shadow, FortiSIEM credential files, SSH keys, config files). "
        "Requires authenticated FortiSIEM access (n8n credential)."
    ),
}


# ---------------------------------------------------------
# FFSN-F03: FortiSIEM n8n -- Osquery SQL execution on all agents
# ---------------------------------------------------------
FFSN_F03_OSQUERY = {
    "id":       "FFSN-F03",
    "product":  "FortiSIEM via n8n-nodes-fortisiem v0.3.1",
    "severity": "HIGH -- Osquery run operation executes SQL on all agents; no query sanitization",
    "class":    "Arbitrary Osquery execution on managed endpoints (CWE-94)",

    "description": (
        "The osquery.run operation: "
        "body = {query: this.getNodeParameter('query', i), agentIds: [...], hostNames: [...]}; "
        "fortiSiemApiRequest('POST', '/phoenix/rest/pub/osquery/run', {body, contentType: 'application/json'}). "
        "The query field is user-controlled Osquery SQL with no validation. "
        "Osquery supports virtual tables that can execute OS commands or read sensitive data: "
        "  SELECT * FROM processes; -- lists all processes on each agent "
        "  SELECT * FROM users; -- local user accounts + password hashes (shadow_users table on Linux) "
        "  SELECT * FROM etc_hosts; -- /etc/hosts "
        "  SELECT * FROM startup_items; -- persistence mechanisms "
        "  SELECT * FROM file WHERE path LIKE '/etc/%%'; -- filesystem enumeration "
        "  SELECT * FROM shadow; -- requires root; returns hashed passwords "
        "The agentIds and hostNames fields target the query to specific agents. "
        "Omitting both targets ALL agents managed by FortiSIEM. "
        "An n8n workflow operator with FortiSIEM credentials can enumerate all managed endpoints, "
        "extract process lists, user accounts, and sensitive file contents at scale."
    ),

    "sensitive_osquery_tables": [
        "shadow (Linux) -- /etc/shadow hashes; requires root agent",
        "users -- local user account metadata",
        "groups -- group membership",
        "processes -- running process list (command line args, environment if filtered)",
        "startup_items -- persistence (LaunchDaemons, systemd units, cron)",
        "certificates -- installed TLS certificates (may include private keys on some platforms)",
        "listening_ports -- open sockets + bound process",
    ],

    "api_endpoint": "POST /phoenix/rest/pub/osquery/run",
    "result_endpoint": "GET /phoenix/rest/pub/osquery/result",
}


# ---------------------------------------------------------
# FFSN-F04: FortiSIEM n8n -- updateCredential sends user-controlled XML; credential injection
# ---------------------------------------------------------
FFSN_F04_UPDATE_CREDENTIAL = {
    "id":       "FFSN-F04",
    "product":  "FortiSIEM via n8n-nodes-fortisiem v0.3.1",
    "severity": "HIGH -- updateCredential allows injecting/overwriting device credentials in FortiSIEM",
    "class":    "Device credential injection via unauthenticated XML (CWE-285)",

    "description": (
        "The discovery.updateCredential operation: "
        "const body = this.getNodeParameter('credentialXml', i); "
        "fortiSiemApiRequest('PUT', '/phoenix/rest/deviceMon/updateCredential', {body, contentType: 'text/xml'}). "
        "The credentialXml string is sent directly to FortiSIEM. "
        "FortiSIEM uses this endpoint to define credentials (SNMP community strings, WMI credentials, "
        "SSH credentials, API keys) for devices it monitors. "
        "An n8n workflow operator can use this to: "
        "  (1) Inject rogue SNMP credentials that redirect monitoring data to attacker-controlled server "
        "  (2) Overwrite existing SSH credentials used by FortiSIEM to connect to managed devices "
        "  (3) Add attacker-controlled IP ranges to credential mappings, "
        "      causing FortiSIEM to authenticate to attacker's devices. "
        "The credential XML format is documented in FortiSIEM API; no additional authorization gate exists."
    ),

    "api_endpoint": "PUT /phoenix/rest/deviceMon/updateCredential",
    "credential_format": (
        "<accessMethods>"
        "<accessMethod>"
        "<name>ROGUE-SSH</name>"
        "<accessProtocol>SSH</accessProtocol>"
        "<pwdType>Manual</pwdType>"
        "<userName>admin</userName>"
        "<password>attacker_controlled</password>"
        "<ipRanges><ipRange>0.0.0.0/0</ipRange></ipRanges>"
        "</accessMethod>"
        "</accessMethods>"
    ),
}


# ---------------------------------------------------------
# FFSN-F05: FortiSIEM n8n -- ClickHouse SQL via advanced event query (super/global users)
# ---------------------------------------------------------
FFSN_F05_CLICKHOUSE_SQL = {
    "id":       "FFSN-F05",
    "product":  "FortiSIEM via n8n-nodes-fortisiem v0.3.1",
    "severity": "MEDIUM -- advanced ClickHouse SQL accepted for super/global users; arbitrary SQL in event database",
    "class":    "Arbitrary SQL against FortiSIEM event database (CWE-89 risk surface)",

    "description": (
        "The event.submitQuery operation: "
        "body = this.getNodeParameter('queryJson', i); "
        "fortiSiemApiRequest('POST', '/phoenix/rest/pub/v2/query/eventQuery', {body, contentType: 'application/json'}). "
        "The queryJson is passed as-is. The EventDescription notes: "
        "'advanced object with a ClickHouse SQL string (Super/Global users only)'. "
        "n8n workflow operators configured with Super/Global credentials can execute "
        "arbitrary ClickHouse SQL against the FortiSIEM event database: "
        "  {\"advanced\": {\"query\": \"SELECT * FROM phEvtTbl LIMIT 1000\"}} "
        "ClickHouse SQL injection risk depends on whether FortiSIEM parameterizes the query "
        "before passing it to ClickHouse. If not parameterized, FortiSIEM-side SQLi is possible. "
        "At minimum: access to all stored security events, incidents, and monitoring data."
    ),

    "api_endpoint": "POST /phoenix/rest/pub/v2/query/eventQuery",
    "advanced_query_format": '{"advanced": {"query": "<ClickHouse SQL>"}}',
}


# ---------------------------------------------------------
# FFOS-F01: FortiOS n8n -- tokenQuery mode puts API token in URL query string
# ---------------------------------------------------------
FFOS_F01_TOKEN_IN_URL = {
    "id":       "FFOS-F01",
    "product":  "FortiOS via n8n-nodes-fortios v1.0.0",
    "severity": "MEDIUM -- tokenQuery auth mode appends access_token to URL; token logged in HTTP access logs",
    "class":    "Sensitive credential in URL query string (CWE-598)",

    "description": (
        "apiRequest.js: if (authMethod === 'tokenQuery') { queryParams.access_token = apiToken; } "
        "The FortiOS REST API token is appended as ?access_token=<token> to every API request URL. "
        "HTTP server access logs on FortiOS, intermediate proxies, and load balancers log request URLs. "
        "The access_token appears in: "
        "  (1) FortiOS /var/log/httpd.log (if enabled) "
        "  (2) Upstream proxy access logs "
        "  (3) n8n debug logs (the logger logs request URLs in debug mode) "
        "The alternative tokenBearer mode uses Authorization: Bearer header "
        "which is NOT logged in standard access log formats."
    ),

    "vulnerable_code": (
        "if (authMethod === 'tokenQuery') { queryParams.access_token = apiToken; } "
        "// Results in: https://<fortigate>/api/v2/cmdb/system/admin?access_token=<token>&vdom=root"
    ),

    "default_value": (
        "authMethod defaults to 'tokenQuery' (not tokenBearer). "
        "Users who accept the default put their API token in every request URL."
    ),

    "fix": "Default to tokenBearer; deprecate or remove tokenQuery option.",
}


# ---------------------------------------------------------
# FFOS-F02: FortiOS n8n -- systemAdmin.create defaults accprofile to super_admin
# ---------------------------------------------------------
FFOS_F02_ADMIN_CREATE_SUPER_ADMIN_DEFAULT = {
    "id":       "FFOS-F02",
    "product":  "FortiOS via n8n-nodes-fortios v1.0.0",
    "severity": "HIGH -- systemAdmin.create defaults accprofile to super_admin; new admins get full access without explicit choice",
    "class":    "Insecure default: admin creation defaults to maximum privilege (CWE-276)",

    "description": (
        "systemAdmin.methods.js create(): "
        "accprofile: additionalFields.accprofile || 'super_admin'. "
        "If the n8n workflow operator does not explicitly set accprofile in additionalFields, "
        "every admin account created via this node gets accprofile=super_admin. "
        "super_admin is the highest FortiOS privilege level -- full read/write/execute on all objects. "
        "Combined with FFOS-F01 (token in URL, logged), an attacker who reads logs "
        "can use the logged token to create their own super_admin account. "
        "The trusthost fields (trusthost1, trusthost2, trusthost3) are optional -- "
        "if omitted, the new super_admin account is accessible from any source IP."
    ),

    "vulnerable_code": (
        "const body = { name, password, accprofile: additionalFields.accprofile || 'super_admin' }; "
        "// if additionalFields.accprofile not set -> super_admin"
    ),

    "impact": (
        "An n8n workflow that auto-provisions FortiOS admin accounts (e.g., for ITSM integration) "
        "creates super_admin accounts by default. "
        "Combined with trusthost omission: any IP can authenticate as the provisioned admin. "
        "One workflow automation mistake = unrestricted super_admin on all provisioned FortiGates."
    ),

    "parallel_to_terraform": (
        "This is the same pattern as FTFP-F02 (Terraform provider). "
        "Both the Terraform provider and this n8n node default new API user/admin accounts "
        "to the maximum privilege profile without requiring explicit user choice."
    ),
}


# ---------------------------------------------------------
# Cross-tool systemic analysis
# ---------------------------------------------------------
FORTISIEM_FORTIOS_N8N_SYSTEMIC = {
    "id":       "FN8N-SYSTEMIC",
    "product":  "FortiSIEM + FortiOS via n8n integrations",
    "severity": "HIGH -- n8n workflow automation exposes FortiSIEM and FortiOS attack surfaces to workflow operators",
    "class":    "Systemic: automation layer reduces security boundary to workflow operator access level",

    "pattern": (
        "Both n8n Fortinet integrations follow the same insecure pattern: "
        "(1) Credentials cached in module-level process memory (tokenCache / sessionCache). "
        "(2) User-controlled data (XML, SQL, API paths) sent to product APIs without sanitization. "
        "(3) Default privilege escalation (super_admin). "
        "(4) Token in URL logs (FortiOS tokenQuery default). "
        "The common thread: the n8n worker process becomes a privileged client for all connected "
        "Fortinet products. Any code running in the n8n worker (malicious community node, "
        "workflow credential exfiltration, XSS in n8n UI) gains access to all cached tokens/sessions."
    ),

    "n8n_worker_trust_model": (
        "n8n community nodes run in the same Node.js process as all credentials and cached tokens. "
        "n8n's sandboxing for community nodes is opt-in and not enforced by default. "
        "A malicious community node published to npm can iterate module.cache and read all "
        "sessionCache / tokenCache entries across all installed Fortinet node packages."
    ),
}
