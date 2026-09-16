"""
Fortinet REST API surface -- derived from public SDK and Terraform provider source
Sources:
  forti-sdk-go      github.com/fortinetdev/forti-sdk-go (Go; FortiOS/FMG/FAZ SDK)
  terraform-provider-fortios  github.com/fortinetdev/terraform-provider-fortios (1128 resource files)
  fortiosapi        github.com/fortinet-solutions-cse/fortiosapi (Python client)
  fortipam-vault-tool  github.com/fortinetdev/fortipam-vault-tool (Go; FortiPAM+Vault integration)
  forticonverter-tools  github.com/fortinet/forticonverter-tools (Python; Meraki/Zscaler config extract)
  ips-bph-framework    github.com/fortinet/ips-bph-framework (Python; Fortinet malware analysis)
Cloned to: /home/cowboy/Downloads/fortinet/
"""

# ---------------------------------------------------------
# FortiOS REST API auth surface
# ---------------------------------------------------------
FORTIOS_API_AUTH = {
    "session_login": {
        "endpoint":  "POST /logincheck",
        "params":    "username=<url-encoded>&secretkey=<url-encoded>&ajax=1",
        "note":      "Password field is named 'secretkey' not 'password'; ajax=1 returns ASCII '1'/'0' instead of redirect",
        "csrf":      "CSRFTOKEN cookie updated after login; required for subsequent write operations",
        "session":   "Cookie-based persistent session; fortiosapi.py uses requests.session()",
    },
    "token_auth": {
        "method":    "URL query parameter: ?access_token=<token>&vdom=<vdom>",
        "note":      "access_token appears in server access logs, proxy logs, HTTP Referer headers",
        "sdk_path":  "forti-sdk-go/fortios/request/request.go buildURL()",
        "severity":  "Token disclosure via URL logging (CWE-598)",
    },
    "token_env":   "FORTIOS_ACCESS_TOKEN env var (forti-sdk-go GetEnvToken)",
    "insecure_env": "FORTIOS_INSECURE=true disables TLS cert verification",
    "api_base":    "/api/v2/cmdb/<path>/<name>",
    "schema_url":  "/api/v2/cmdb/<path>/<name>?action=schema (returns field definitions)",
}


# ---------------------------------------------------------
# FAPI-F1: access_token in URL query string (forti-sdk-go)
# ---------------------------------------------------------
FAPI_F01_TOKEN_IN_URL = {
    "id":       "FAPI-F01",
    "product":  "FortiOS REST API (forti-sdk-go; terraform-provider-fortios)",
    "severity": "MEDIUM -- API token exposed in URL; logged by default in any HTTP server, proxy, or CDN",
    "class":    "Sensitive data in URL (CWE-598; OWASP A02)",

    "description": (
        "forti-sdk-go constructs all API requests with the access_token as a URL query parameter. "
        "Every API call produces a URL like: "
        "https://<fortigate>/api/v2/cmdb/system/admin?vdom=root&access_token=<token>. "
        "This token is logged in: FortiGate HTTPS server access logs, "
        "any HTTP proxy (corporate proxy, WAF, CDN), "
        "HTTP Referer headers when the API is called from a browser context, "
        "terraform state files (which include the constructed URLs). "
        "Terraform provider for FortiOS uses this SDK -- all terraform apply/plan operations "
        "for FortiOS expose the access token in URL-form."
    ),

    "evidence": {
        "sdk_file":   "forti-sdk-go/fortios/request/request.go",
        "functions":  "buildURL(), buildURLWithoutVdom(), buildURL3()",
        "pattern":    "u += 'access_token='; u += r.Config.Auth.Token",
        "env_var":    "FORTIOS_ACCESS_TOKEN -- token sourced from environment or provider config",
    },

    "impact": (
        "If FortiGate logs are accessible to a lower-privileged admin or are forwarded to a SIEM "
        "that multiple teams access, the access token in logs grants API-level admin access. "
        "Tokens do not expire by session -- they are static API keys until manually rotated."
    ),

    "remediation": "FortiOS API should support Authorization: Bearer header; SDK should use it instead of URL parameter.",
}


# ---------------------------------------------------------
# FAPI-F2: FortiOS admin wildcard + disallowed_login_methods denylist
# ---------------------------------------------------------
FAPI_F02_ADMIN_WILDCARD = {
    "id":       "FAPI-F02",
    "product":  "FortiOS system_admin API (terraform-provider-fortios)",
    "severity": "HIGH -- wildcard admin + remote_auth enables any RADIUS/LDAP user to become admin",
    "class":    "Overly permissive admin configuration (CWE-269; misconfiguration)",

    "description": (
        "The FortiOS system_admin object has a 'wildcard' field (API: system/admin). "
        "When wildcard='enable', the admin account's username acts as a wildcard match for "
        "remote authentication (RADIUS/LDAP). "
        "Combined with remote_auth='enable' and remote_group pointing to a broad LDAP group, "
        "this allows any member of the remote group to authenticate as this admin. "
        "The disallowed_login_methods field is a denylist (not allowlist) -- "
        "omitting it permits all login methods. "
        "The accprofile field determines permissions -- 'super_admin' grants full control."
    ),

    "evidence": {
        "api_endpoint":          "PUT /api/v2/cmdb/system/admin/<name>",
        "wildcard_field":        "wildcard: enable|disable (Optional, Computed -- default not enforced by API schema)",
        "disallowed_methods":    "disallowed-login-methods: denylist (not allowlist)",
        "remote_auth_field":     "remote-auth: enable|disable; remote-group: LDAP/RADIUS group name",
        "accprofile_field":      "accprofile: 0-35 char string; 'super_admin' = full access",
        "trusthost_fields":      "trusthost1-10: IP ranges that can use this admin account (bypass = 0.0.0.0/0 or empty)",
        "source_file":           "terraform-provider-fortios/fortios/resource_system_admin.go",
    },

    "impact": (
        "Wildcard admin with remote_auth enabled and trusthost set to 0.0.0.0/0 "
        "allows any user who can authenticate against the RADIUS/LDAP server "
        "to gain admin access to the FortiGate. "
        "This is a common misconfiguration in enterprise deployments that integrate "
        "FortiGate with LDAP/RADIUS for admin auth convenience."
    ),

    "remediation": "Use allowlist login methods, specific trusthost ranges, non-wildcard admin accounts, and least-privilege accprofile.",
}


# ---------------------------------------------------------
# FAPI-F3: FortiPAM internal secret checkout -- potential IDOR
# ---------------------------------------------------------
FAPI_F03_FORTIPAM_SECRET_IDOR = {
    "id":       "FAPI-F03",
    "product":  "FortiPAM REST API v1.1.0 (fortipam-vault-tool)",
    "severity": "HIGH (unverified) -- integer secret-id in checkout body; IDOR if server-side authz not enforced per-secret",
    "class":    "Insecure Direct Object Reference (CWE-639; unverified)",

    "description": (
        "POST /internal/secret-checkout accepts body {\"secret-id\": <int32>}. "
        "The only required parameter is a simple sequential integer secret ID. "
        "The /internal/ path prefix suggests this is the Vault integration endpoint "
        "that may have a different authorization model than the standard UI path. "
        "If the server-side authorization check verifies only that the JWT token is valid "
        "(for any PAM user) without checking whether that user has permission to access "
        "the specific secret-id, an authenticated PAM user can enumerate all secrets by "
        "iterating secret-id from 1 to N. "
        "The Body1 (checkin/update) model has per-secret user-permission and "
        "group-permission fields, confirming per-secret ACLs exist -- "
        "the question is whether /internal/ enforces them."
    ),

    "evidence": {
        "endpoint":        "POST /internal/secret-checkout",
        "body":            '{"secret-id": <int32>} -- only parameter',
        "int_id_concern":  "Sequential integer ID enables enumeration by iteration",
        "jwt_auth":        "POST /auth/jwt/login body: {\"jwt\": \"<token>\"} -> FortiPAM auth token",
        "internal_prefix": "/internal/ suggests vault-integration internal API path",
        "permission_model": "Body1 has user-permission and group-permission sub-arrays (server-side ACL)",
        "source_files":    "fortipam-vault-tool/api/api_secret_checkout.go, model_body_2.go",
    },

    "impact": (
        "If /internal/secret-checkout bypasses per-secret ACLs, any service account "
        "with a valid Vault JWT (which FortiPAM accepts via /auth/jwt/login) "
        "can checkout ALL secrets in the PAM vault -- SSH keys, Windows credentials, "
        "database passwords, etc. -- without individual secret permission."
    ),

    "reproduction": (
        "1. Obtain a valid Vault JWT token accepted by FortiPAM. "
        "2. POST /auth/jwt/login with {\"jwt\": token} -> get FortiPAM auth token. "
        "3. POST /internal/secret-checkout with {\"secret-id\": 1} through N. "
        "4. Observe whether secrets outside user permission are returned."
    ),

    "remediation": "Enforce per-secret ACL check on /internal/ API path, not just JWT authentication.",
}


# ---------------------------------------------------------
# FAPI-F4: FortiOS login endpoint parameter enumeration
# ---------------------------------------------------------
FAPI_F04_LOGINCHECK_PARAMS = {
    "id":       "FAPI-F04",
    "product":  "FortiOS web admin interface (fortiosapi Python client)",
    "severity": "INFO -- non-obvious login parameter names; useful for brute-force tooling",
    "class":    "Authentication endpoint documentation",

    "description": (
        "FortiOS web admin login uses POST /logincheck with form-encoded parameters. "
        "The password field name is 'secretkey' (not 'password' or 'pass'). "
        "Generic brute-force tools that try standard password field names will fail. "
        "ajax=1 parameter changes response format from HTTP redirect to ASCII '1' (success) or '0' (failure). "
        "Successful login sets a CSRFTOKEN cookie that must be included in all write operations "
        "as X-CSRFTOKEN header (standard Django-style CSRF pattern). "
        "Response character at index [0] being '1' is the programmatic success check."
    ),

    "evidence": {
        "url":          "POST /logincheck",
        "body":         "username=<url-encoded>&secretkey=<url-encoded>&ajax=1",
        "success_check": "res.content.decode('ascii')[0] == '1'",
        "csrf_update":  "update_cookie() called after successful login",
        "source_file":  "fortiosapi/fortiosapi/fortiosapi.py, login() method",
    },

    "enumeration_note": (
        "The ajax=1 flag enables binary success/failure detection without parsing HTML. "
        "Brute-force: POST /logincheck with username=admin&secretkey=<guess>&ajax=1; "
        "check response[0]=='1'. No CSRF required for /logincheck itself."
    ),
}


# ---------------------------------------------------------
# FAPI-F5: FortiOS API endpoint catalog (from 1128 terraform resources)
# ---------------------------------------------------------
FAPI_F05_API_ENDPOINT_CATALOG = {
    "id":       "FAPI-F05",
    "product":  "FortiOS REST API (terraform-provider-fortios 1128 resource files)",
    "severity": "INFO -- complete FortiOS REST API surface map",
    "class":    "Attack surface documentation",

    "api_base":    "/api/v2/cmdb/",
    "source":      "terraform-provider-fortios/fortios/resource_*.go (1128 files)",

    "high_value_endpoints": {
        "system/admin":                   "Admin user CRUD (password, trusthost, wildcard, accprofile)",
        "system/global":                  "Global admin settings (ssl versions, lockout, timeout, SSH/telnet enable)",
        "system/interface":               "Network interface config (IP, management access)",
        "system/password-policy":         "Password policy configuration",
        "system/saml":                    "SAML SSO configuration",
        "vpn/ssl/settings":               "SSL-VPN settings (auth timeout, realm, auth rules)",
        "vpn/ssl/web/portal":             "SSL-VPN web portal config",
        "vpn/ipsec/phase1-interface":     "IPsec VPN phase 1 (pre-shared key, auth method)",
        "authentication/scheme":          "Authentication scheme (RADIUS, LDAP, SAML)",
        "authentication/rule":            "Authentication rules (match criteria, auth scheme)",
        "user/radius":                    "RADIUS server config (server, secret, NAS IP)",
        "user/ldap":                      "LDAP server config (server, DN, bind type, password)",
        "user/saml":                      "SAML IdP config (cert, entity-id, SLO URL)",
        "certificate/local":              "Local cert management (private key upload)",
        "certificate/ca":                 "CA cert management",
        "firewall/policy":                "Firewall policy CRUD (allow/deny rules)",
        "firewall/vip":                   "Virtual IP (port forwarding, NAT)",
        "credentialstore/domaincontroller": "Domain controller credential store",
    },

    "admin_ssl_settings": {
        "admin_https_ssl_versions":        "TLS version allowlist (can enable TLS 1.0/1.1)",
        "admin_https_ssl_ciphersuites":    "Admin HTTPS cipher suite config",
        "admin_https_ssl_banned_ciphers":  "Cipher denylist (not allowlist)",
        "admin_ssh_v1":                    "SSH v1 enable (legacy insecure protocol)",
        "admin_telnet":                    "Telnet admin access (plaintext)",
        "admin_ssh_password":              "SSH password auth for admin (vs key-only)",
        "admin_restrict_local":            "Local admin console restriction",
        "admin_lockout_threshold":         "Lockout trigger threshold (failed login count)",
        "admin_lockout_duration":          "Lockout duration (seconds)",
    },
}


# ---------------------------------------------------------
# FAPI-F6: ips-bph-framework -- Fortinet malware analysis pipeline
# ---------------------------------------------------------
FAPI_F06_BPH_FRAMEWORK = {
    "id":       "FAPI-F06",
    "product":  "Fortinet IPS BPH Framework (ips-bph-framework; internal malware analysis)",
    "severity": "INFO -- internal tooling; reveals Fortinet threat research pipeline architecture",
    "class":    "Internal tool documentation",

    "description": (
        "Fortinet's internal malware analysis framework (published 2019, Apache 2.0). "
        "Architecture: BphVmControl connects to a VirtualBox VM manager server "
        "via TCP socket (BPH_VIRTUALBOX_SERVER_IP, BPH_VIRTUALBOX_SERVER_PORT). "
        "Protocol: pipe-delimited ASCII -- action|vm_id|snapshot_id|network_id. "
        "Server responds with 'OK'. No authentication on the control socket. "
        "VMs run malware samples in isolated network environments. "
        "Plugin system: tools include AutoIt, ProcMon, CaptureBat, OllyDbg, Floss, "
        "NetworkTrafficView, PE-ID, PEiD, Depends, BinText. "
        "Fortinet uses this to automate malware behavior analysis at scale."
    ),

    "evidence": {
        "vm_control":  "bph/core/vm.py BphVmControl; TCP socket to VM manager; plaintext pipe protocol",
        "plugins":     "scripts/examples/tools/ and scripts/examples/malware/",
        "vm_protocol": "action|vm_id|snapshot_id|network_id (pipe-delimited ASCII; no auth)",
        "presented_at": "BlackHat 2019 (referenced in README)",
    },

    "notes": (
        "The plaintext unauthenticated VM control socket is internal only. "
        "The framework reveals that Fortinet's malware analysis VMs run Windows "
        "(AutoIt-based tools, PE analysis tools -- Windows-native). "
        "Any pipe character in filenames/paths passed to the VM control would be "
        "interpreted as field delimiter (injection risk in the internal pipeline)."
    ),
}


# ---------------------------------------------------------
# Pending findings
# ---------------------------------------------------------
pending_findings = [
    "FAPI-F03 verification: test /internal/secret-checkout with a Vault JWT that has "
    "limited permissions -- confirm whether per-secret ACL is enforced; "
    "requires FortiPAM v1.1.0 instance; 2026-09-16",

    "FortiOS /logincheck CSRF bypass: verify whether /logincheck requires CSRF token "
    "for POST (it shouldn't, but the ajax=1 parameter behavior should be tested); "
    "source: fortiosapi/fortiosapi/fortiosapi.py login(); 2026-09-16",

    "FortiOS access_token logging: verify that access_token in URL is logged in "
    "FortiGate event logs (system/fortianalyzer config, local logging); "
    "cross-reference with actual FMG log format; 2026-09-16",

    "terraform-provider-fortios: audit resource_system_admin.go for dangerous "
    "default values in Optional/Computed fields (wildcard, remote_auth defaults); "
    "source: terraform-provider-fortios/fortios/resource_system_admin.go; 2026-09-16",

    "forticonverter-tools credential handling: fcon_meraki_backup.py passes Meraki "
    "API key as CLI argument (visible in process table); "
    "fcon_zscaler_backup.py -- check if Zscaler credentials are similarly exposed; "
    "source: forticonverter-tools/; 2026-09-16",

    "FortiOS admin SSH v1 and telnet: check whether admin_ssh_v1 and admin_telnet "
    "defaults are enable or disable in factory config; "
    "cross-reference with fgfmsd factory config extraction; 2026-09-16",
]
