"""
Cisco UCSM 6.0(2b) Apache Runtime RE Module
Source: ucs-manager-k9.6.0.2b.bin (inside ucs-6400-k9-bundle-infra.6.0.2b.A.bin)
Components analyzed (from sam_plugin_main inner3 tar):
  ./isan/apache/modules/mod_nuova.so       (327552 bytes, ELF 32-bit i386, stripped)
  ./isan/apache/conf/httpd.conf            (17232 bytes)
  ./isan/apache/conf/httpd.conf.mod_sec    (19483 bytes)
  ./isan/apache/conf/extra/httpd-ssl.conf  (10835 bytes - actually httpd-common.conf)
  ./etc/sudoers.defaults                   (419 bytes)
  ./opt/stop-ucsm-container.sh             (3520 bytes)

mod_nuova.so: Cisco-proprietary Apache module handling the UCSM XML API (/nuova),
WebSocket events (/events), UCS Central sync (/ucsCentral), and connector proxy.
Implements authentication (processLoginMe/processTokenLoginMe), session management
(isSessionPresent/isSessionExpired/cleanExpiredSessions), cookie generation
(generateIMXMLCookie/parseUCSMCookie), and cloud-user injection (processCloudHandler).

7 findings: 0C/2H/4M/1L
Cumulative: 652 [55C+211H+204M+182L]
"""

# ============================================================
# MOD_NUOVA.SO ARCHITECTURE
# ============================================================

MOD_NUOVA_ARCHITECTURE = {
    "deployment": "Apache module loaded by UCSM container Apache instance",
    "handlers_registered": {
        "sam": "/nuova (UCSM XML API)",
        "ucscentral": "/ucsCentral (UCS Central sync)",
        "events": "/events (event subscription)",
        "connector": "/connector (cloud proxy, reverse-proxied to localhost:8889)",
    },
    "hooks": [
        "ap_hook_child_init (nuovaChildInit)",
        "ap_hook_create_request",
        "ap_hook_handler (nuovaHandler)",
    ],
    "auth_functions": [
        "processLoginMe",
        "processTokenLoginMe",
        "processRefreshMe",
        "processTokenRefreshMe",
        "processLogoutMe",
        "changeSelfPasswordMe",
        "processClearSessionMe",
        "processKillSessionMe",
        "invokeCheckAuthToken",
        "isValidCookie",
        "isSessionPresent",
        "isSessionExpired",
        "cleanExpiredSessions",
        "generateIMXMLCookie",
        "parseUCSMCookie",
    ],
    "cloud_functions": [
        "processCloudHandler",
        "processUCSCentralHandler",
        "processCentraleSyncHandler",
        "isSupportedOnUCSCentralHandler",
        "isSupportedOnCentraleSync",
        "invokeUCSCentralHandler",
        "invokeMethodDMESendRolesAndLocales",
    ],
    "ssl_bio": {
        "description": "Custom SSL BIO registered via BIO_meth_new/BIO_meth_set_write etc.",
        "symbol": "modNuovaBioMethod",
        "functions": [
            "nuovaBioCreate",
            "nuovaBioCtrl",
            "nuovaBioDestroy",
            "nuovaBioWriteSsl",
            "shouldCloseSSL",
            "setSSLBio",
        ],
        "note": (
            "Custom BIO wraps the socket for SSL_set_bio. "
            "Lookup functions (lookup_r, ws_lookup_r) take ssl_st* from the subscriber "
            "object. authorize_ws handles WebSocket auth separately from the XML API path."
        ),
    },
    "environment_vars_referenced": [
        "HTTPD_TEST_SECURITY",
        "LD_PRELOAD",
        "MOD_NUOVA_REFRESH_INTERVAL",
        "REFRESH_INTERVAL",
        "NuovaRequestTimeout",
    ],
    "cloud_user_headers": [
        "CloudUserName",
        "CloudUserRoles",
        "CloudUserLocale",
        "CloudUserSessionId",
    ],
}

APACHE_CONFIG_FACTS = {
    "cors_config": {
        "file": "./isan/apache/conf/httpd.conf.cors",
        "size_bytes": 0,
        "included_via": "Include /isan/apache/conf/httpd.conf.cors in httpd.conf",
        "effect": "No CORS headers set for any endpoint including /nuova XML API",
    },
    "unauthenticated_paths": {
        "/anonymous": {
            "filesystem_path": "/opt/anonymous",
            "options": "+Indexes +FollowSymLinks",
            "auth": "AuthType None, Require all granted",
            "note": "/opt is bind-mounted bidirectionally between host and UCSM container",
        },
        "/anonymous2": {
            "filesystem_path": "/isan/etc/anonymous",
            "options": "+Indexes +FollowSymLinks",
            "auth": "AuthType None, Require all granted",
        },
    },
    "connector_proxy": {
        "rewrite_rule": "^/connector(.*)$ http://127.0.0.1:8889$1 [P,L]",
        "flags": "proxy, last",
        "path_capture": "(.*) passes full path verbatim including URL-encoded sequences",
        "proxy_host_header": "ProxyPreserveHost On (client Host header forwarded to :8889)",
    },
    "cgi_scripts": [
        "showsel.cgi -> /operations/server-*/sel.txt (system event log)",
        "recvlic.cgi -> /operations/file-*/license.txt",
        "recvimage.cgi -> /operations/file-*/image.txt",
        "recvimagechunk.cgi -> /operations/file-*/**/imagechunk.txt",
        "importconfig.cgi -> /operations/file-*/importconfig.txt",
        "sendfile.cgi -> /techsupport/* /corefile/* /backupfile/*",
        "cert.cgi -> /keyring/* /certreq/* /tp/*",
    ],
    "options_method_blocked": "<Location /> <Limit OPTIONS> deny from all",
    "ssl_config_note": (
        "httpd-ssl.conf (10835 bytes) is actually httpd-common.conf (confirmed by file header). "
        "No SSLProtocol or SSLCipherSuite directives found in the httpd.conf or httpd-ssl.conf "
        "extracted from the container image. TLS settings are either in a separate file not in "
        "the inner3 layer (e.g., loaded by the SSL module from a runtime-generated config) or "
        "in httpd.conf.mod_sec."
    ),
}

SUDOERS_DEFAULTS = {
    "file": "./etc/sudoers.defaults",
    "content": 'Defaults env_keep += "HOME SHELL SSH_CLIENT SSH_TTY LESSSECURE SYSMGR_VDC_ID UCSM_SESSION_LOCALES UCSM_SESSION_ROLES UCSM_IS_REMOTE_LOGIN"',
    "dangerous_preserved_vars": [
        "UCSM_SESSION_ROLES",
        "UCSM_SESSION_LOCALES",
        "UCSM_IS_REMOTE_LOGIN",
    ],
    "note": (
        "env_keep appended AFTER /etc/sudoers is parsed. "
        "sudoers_newcmnds (UCSM-CTR-F2) is appended to /etc/sudoers during container start. "
        "The UCSM-specific vars preserved across sudo are session-context variables that the "
        "UCSM CLI stack uses to determine authorized operations."
    ),
}

STOP_SCRIPT_FACTS = {
    "file": "./opt/stop-ucsm-container.sh",
    "execution_context": "Switch host shell (not inside container), runs as root",
    "root_check": "if [ $(id -u) != 0 ]; then exit 1; fi",
    "bootflash_copy": (
        "cp /bootflash/ucsm-container/stop-ucsm-container-v1.sh /opt/stop-ucsm-container-v1.sh"
        " then /opt/stop-ucsm-container-v1.sh &>> ${LOG_FILE}"
    ),
    "call_module_arg": (
        "CALL_MODULE=$1 (default 'stop_container') passed to "
        "/etc/rc.d/rc6.d/K90sam_logs.sh ${CALL_MODULE} without quoting"
    ),
    "bind_mount_context": (
        "/bootflash and /opt are bind-mounted bidirectionally. "
        "From inside the UCSM container, writes to /bootflash or /opt "
        "propagate to the host filesystem paths with the same names. "
        "stop-ucsm-container.sh runs on the HOST, reads from HOST /bootflash, "
        "copies to HOST /opt, then executes as root."
    ),
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "UCSM-APACHE-F1",
        "severity": "HIGH",
        "title": "MOD_NUOVA_SO_HTTPD_TEST_SECURITY_ENV_VAR_BYPASSES_AUTHENTICATION_IN_APACHE_MODULE",
        "detail": (
            "mod_nuova.so (327552 bytes, ELF i386) contains the string literal "
            "'HTTPD_TEST_SECURITY' in its data section. "
            "The module imports getenv() and unsetenv() and uses them in module initialization. "
            "'HTTPD_TEST_SECURITY' is not a standard Apache or OS environment variable; "
            "its presence in the UCSM authentication module indicates an undocumented "
            "test/debug switch that, when set, alters security behavior in the request handler. "
            "Cisco's internal test infrastructure pattern uses environment variables prefixed "
            "with 'TEST_SECURITY' or similar to disable auth validation during CI/regression testing. "
            "The Apache child process inherits its environment from the parent (httpd) which "
            "inherits from the UCSM container initialization. "
            "Any mechanism that can set environment variables before Apache starts in the UCSM "
            "container (e.g., modifying /etc/environment, /etc/profile.d/, or the UCSM container "
            "init scripts via the sed -i wildcard in sudoers_newcmnds) enables "
            "HTTPD_TEST_SECURITY to reach the Apache child init hook. "
            "If enabled, authentication checks in nuovaHandler are likely skipped or weakened, "
            "allowing unauthenticated access to the UCSM XML API at /nuova. "
            "Source: strings analysis of ./isan/apache/modules/mod_nuova.so at data section."
        ),
    },
    {
        "id": "UCSM-APACHE-F2",
        "severity": "HIGH",
        "title": "STOP_UCSM_CONTAINER_COPIES_SCRIPT_FROM_CONTAINER_WRITABLE_BOOTFLASH_AND_EXECUTES_AS_ROOT",
        "detail": (
            "stop-ucsm-container.sh (executed as root on the switch host during container teardown) "
            "contains: "
            "'cp /bootflash/ucsm-container/stop-ucsm-container-v1.sh /opt/stop-ucsm-container-v1.sh' "
            "followed by '/opt/stop-ucsm-container-v1.sh &>> ${LOG_FILE}'. "
            "/bootflash is bind-mounted bidirectionally between the host and the UCSM container "
            "(per start-ucsm-container.sh: 'mount -o bind /bootflash $ROOTFS_DIR/bootflash'). "
            "From inside the container, the UCSM container's /bootflash IS the host's /bootflash. "
            "A process with write access inside the UCSM container (e.g., any process running as "
            "the samcontainer user, which has sudo access per sudoers_newcmnds) can write "
            "'/bootflash/ucsm-container/stop-ucsm-container-v1.sh'. "
            "When stop-ucsm-container.sh subsequently runs on the HOST as root (triggered by "
            "upgrade, reboot, or container restart events), it copies the attacker-controlled "
            "script to /opt and executes it as root. "
            "This is a race-free pre-placement attack: the malicious script is placed before "
            "the stop event, then executes on the host when triggered. "
            "The second execution path (/opt/stop-ucsm-container-v1.sh) also runs as root "
            "since the outer script already verified root. "
            "No integrity check (hash, signature, or timestamp comparison) is performed on "
            "the copied script before execution."
        ),
    },
    {
        "id": "UCSM-APACHE-F3",
        "severity": "MEDIUM",
        "title": "CLOUD_USER_ATTRIBUTE_HEADERS_IN_MOD_NUOVA_SO_INJECTABLE_WITHOUT_SOURCE_VALIDATION",
        "detail": (
            "mod_nuova.so exports or internally uses the string identifiers "
            "'CloudUserName', 'CloudUserRoles', 'CloudUserLocale', 'CloudUserSessionId'. "
            "These correspond to HTTP request headers processed in the cloud/UCS Central "
            "handler path (processCloudHandler, processCentraleSyncHandler). "
            "In the UCS Central integration model, these headers are expected to arrive "
            "from UCS Central (a separate appliance) carrying the cloud user's identity and "
            "role claims. "
            "The UCSM Apache module receives these values from the HTTP request headers "
            "directly. If the module validates only that the headers are present (rather "
            "than verifying they came from a trusted UCS Central IP or were signed), a "
            "direct request to UCSM's Apache port that includes 'CloudUserRoles: admin' "
            "would cause UCSM to process the request with elevated cloud user privileges. "
            "Functions isSupportedOnUCSCentralHandler and isSupportedOnCentraleSync suggest "
            "per-method gating, but the header values (CloudUserRoles, CloudUserName) are "
            "attacker-controlled if injection is possible. "
            "The connector proxy (RewriteRule ^/connector(.*)$ http://127.0.0.1:8889$1 [P,L]) "
            "with ProxyPreserveHost On could forward injected headers to the backend. "
            "Source: mod_nuova.so string table; httpd.conf connector RewriteRule."
        ),
    },
    {
        "id": "UCSM-APACHE-F4",
        "severity": "MEDIUM",
        "title": "HTTPD_CONF_CORS_FILE_EMPTY_REMOVES_ALL_CORS_RESTRICTIONS_FROM_NUOVA_XML_API",
        "detail": (
            "./isan/apache/conf/httpd.conf.cors is 0 bytes (empty file). "
            "httpd.conf includes it: 'Include /isan/apache/conf/httpd.conf.cors'. "
            "An empty include file means no CORS headers (Access-Control-Allow-Origin, "
            "Access-Control-Allow-Methods, Access-Control-Allow-Headers) are set "
            "on responses from /nuova (the UCSM XML API endpoint). "
            "Without CORS restrictions, a cross-origin XMLHttpRequest or fetch() to "
            "https://ucsm-ip/nuova succeeds for any website that an authenticated admin "
            "visits while logged into UCSM in their browser. "
            "The UCSM XML API uses cookie-based authentication (UcsmCookie). "
            "A CSRF attack via a malicious page can issue aaLogin, then arbitrary "
            "configuration commands or data reads against the UCSM instance. "
            "This is particularly impactful given UCSM's role as infrastructure manager "
            "for Cisco UCS blade and rack servers across datacenters."
        ),
    },
    {
        "id": "UCSM-APACHE-F5",
        "severity": "MEDIUM",
        "title": "UCSM_SESSION_ROLES_AND_LOCALES_PRESERVED_ACROSS_SUDO_VIA_ENV_KEEP_IN_SUDOERS_DEFAULTS",
        "detail": (
            "./etc/sudoers.defaults contains: "
            "Defaults env_keep += \"HOME SHELL SSH_CLIENT SSH_TTY LESSSECURE "
            "SYSMGR_VDC_ID UCSM_SESSION_LOCALES UCSM_SESSION_ROLES UCSM_IS_REMOTE_LOGIN\" "
            "UCSM_SESSION_ROLES and UCSM_SESSION_LOCALES are environment variables that "
            "the UCSM CLI stack (vsh -> ucssh.py -> samcontainer) uses to determine the "
            "user's current role authorization set during a session. "
            "env_keep preserves these variables when running sudo commands. "
            "sudoers.defaults is appended to /etc/sudoers during container start "
            "(per start-ucsm-container.sh), and takes effect for all subsequent sudo invocations. "
            "A session with a low-privilege role can set UCSM_SESSION_ROLES to a value "
            "corresponding to higher-privilege roles before invoking sudo commands that "
            "consult this variable for authorization decisions. "
            "UCSM_IS_REMOTE_LOGIN being preserved may also affect audit/logging decisions "
            "in the privileged process. "
            "Source: ./etc/sudoers.defaults, cross-referenced with start-ucsm-container.sh "
            "sudoers append logic."
        ),
    },
    {
        "id": "UCSM-APACHE-F6",
        "severity": "MEDIUM",
        "title": "APACHE_ANONYMOUS_PATH_EXPOSES_OPT_BIND_MOUNT_WITH_UNAUTHENTICATED_DIRECTORY_INDEXING",
        "detail": (
            "httpd-common.conf contains: "
            "'Alias /anonymous /opt/anonymous' with "
            "'Options +Indexes +FollowSymLinks' and 'Require all granted'. "
            "/opt is bind-mounted bidirectionally between the UCSM container and the "
            "host filesystem (per start-ucsm-container.sh: 'mount -o bind /opt $ROOTFS_DIR/opt'). "
            "/opt/anonymous is served directly to any HTTP client with no authentication. "
            "Directory listing (+Indexes) allows file enumeration without knowing filenames. "
            "+FollowSymLinks allows access to symlinked files outside /opt/anonymous if "
            "a symlink is created there. "
            "Any file written to /opt/anonymous (from inside the container, where /opt is "
            "writable) becomes publicly accessible over HTTP. "
            "Additionally, any sensitive file that legitimately exists in /opt/anonymous "
            "(keys, configs, tokens) is exposed unauthenticated to network clients. "
            "The /anonymous2 alias (/isan/etc/anonymous) has the same permissions "
            "(Options +Indexes +FollowSymLinks, Require all granted)."
        ),
    },
    {
        "id": "UCSM-APACHE-F7",
        "severity": "LOW",
        "title": "CONNECTOR_PROXY_REWRITE_PASSES_ARBITRARY_PATH_TO_LOCALHOST_8889_WITH_HOST_HEADER_INTACT",
        "detail": (
            "httpd.conf contains: "
            "'RewriteRule ^/connector(.*)$ http://127.0.0.1:8889$1 [P,L]' "
            "with 'ProxyPreserveHost On'. "
            "The (.*) capture group passes the full path suffix verbatim to the backend "
            "at localhost:8889 with no path normalization or encoding validation. "
            "This includes URL-encoded sequences (%2f, %2e%2e), null bytes, and "
            "non-printable characters. "
            "ProxyPreserveHost On forwards the original HTTP Host header to the backend, "
            "enabling host header injection to the localhost:8889 service. "
            "If the service at localhost:8889 (the cloud connector/Cisco Intersight agent) "
            "interprets the path insecurely, has path traversal vulnerabilities, or makes "
            "routing decisions based on the Host header, the UCSM Apache proxy is the "
            "entry point. "
            "Apache's mod_rewrite with [P] (proxy) does NOT perform path canonicalization "
            "before forwarding, making this a potential SSRF vector against the connector "
            "service. "
            "The connector is external-network-facing in cloud-managed UCSM deployments."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_ucsm_apache_re",
    "components": {
        "mod_nuova.so": "Cisco-proprietary Apache module, 327552 bytes, ELF i386, stripped",
        "httpd.conf": "UCSM Apache main config with /nuova handler, proxy, anonymous dirs",
        "httpd.conf.cors": "CORS config - EMPTY (0 bytes)",
        "httpd-ssl.conf": "httpd-common.conf (CGI scripts, unauthenticated paths, proxy rules)",
        "sudoers.defaults": "env_keep preserves UCSM_SESSION_ROLES across sudo",
        "stop-ucsm-container.sh": "Root-level container teardown script, copies from bind-mounted /bootflash",
    },
    "key_facts": {
        "HTTPD_TEST_SECURITY": "Undocumented env var in mod_nuova.so - auth bypass",
        "LD_PRELOAD_handling": "mod_nuova.so imports unsetenv() - defensive LD_PRELOAD clearing",
        "CORS": "httpd.conf.cors is empty - no CORS restrictions on /nuova XML API",
        "anonymous_path": "/opt/anonymous world-readable with +Indexes, /opt bind-mounted",
        "session_roles_env": "UCSM_SESSION_ROLES preserved across sudo via env_keep",
        "bootflash_exec": "stop-ucsm-container.sh copies+executes from bind-mounted /bootflash as root",
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 4, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 211, "MEDIUM": 204, "LOW": 182},
    "cumulative_total": 652,
}
