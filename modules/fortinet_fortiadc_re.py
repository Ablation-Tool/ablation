"""
Fortinet FortiADC 8.0.4-B0136 RE
Source: FortiADC-KVM 8.0.4 image
Architecture: x86-64
OS: Linux 6.1.0 (clang 18.1.8 / LLD 18.1.8, built 2026-08-31)
Rootfs: ext4 (rootfs.cpio) -- FULLY ACCESSIBLE (no encryption)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiADC VM64-KVM",
    "version":      "8.0.4 build 0136",
    "build_date":   "2026-08-31",
    "arch":         "x86-64",
    "kernel":       "Linux 6.1 (PREEMPT_DYNAMIC, clang 18.1.8 / LLD 18.1.8)",
    "builder":      "root@b2580fc2344b",
    "toolchain":    "clang 18.1.8 / LLD 18.1.8 (not GCC; full LLVM build)",

    "image_layout": {
        "rootfs":       "ext4 filesystem via rootfs.cpio (891MB), UUID=30085e5e-a424-4309-b713-b9e136be7faf",
        "p1":           "716MB partition (p1.raw)",
        "boot":         "2.1GB boot.raw",
        "rootfs_dir":   "Fully extracted to $SCPAD/fad-804/rootfs/ -- no encryption",
    },

    "web_stack": {
        "nginx_binary":     "/bin/nginx (standard nginx)",
        "fnginx_new":       "/bin/fnginx_new (17MB, NOT STRIPPED -- 1264+ RDP/CredSSP symbols; custom Fortinet nginx build with embedded FreeRDP gateway)",
        "fnginxctld":       "/bin/fnginxctld (1.7MB, NOT STRIPPED -- control daemon)",
        "restapi":          "/bin/restapi (21MB, stripped, Go binary with CGO -- core REST API)",
        "restapi_cmdd":     "/bin/restapi_cmdd (3MB, stripped, Go binary -- CLI API handler with os/exec)",
        "migadmin":         "/migadmin/ -- PHP/Python legacy admin interface (nginx + php-fpm + uwsgi)",
        "fortiai":          "/migadmin/fortiai/ -- Django/Python AI chatbot backend served via uwsgi at /ai",
    },

    "notable_binaries": {
        "/bin/mysqld":      "25MB stripped -- MySQL database server (full RDBMS on ADC device)",
        "/bin/httproxy":    "14MB stripped -- HTTP proxy (main ADC load balancing engine)",
        "/bin/authd":       "stripped -- authentication daemon; uses libfmladminauth.so",
        "/bin/authclient":  "stripped -- auth client binary",
        "/bin/sshd-auth":   "stripped -- SSH authentication daemon",
        "/bin/adfsproxy":   "5.5MB stripped -- ADFS (Active Directory Federation Services) proxy",
        "/bin/cm_client":   "11MB stripped -- cluster management client",
        "/bin/acme-client": "6.4MB stripped -- ACME (Let's Encrypt) certificate management",
        "/bin/gdb":         "7.5MB -- GDB debugger PRESENT IN PRODUCTION IMAGE",
        "/bin/strace":      "2MB -- strace PRESENT IN PRODUCTION IMAGE",
        "/bin/strings":     "1.5MB -- strings utility PRESENT IN PRODUCTION IMAGE",
        "/bin/perf":        "9MB -- Linux perf PRESENT IN PRODUCTION IMAGE",
    },

    "auth_library":     "/lib/libfmladminauth.so (NOT STRIPPED, exports: admin_auth, admin_auth_two_factor, admin_login, admin_get_cookie, admin_ldap_auth, admin_new_pwd_shm, acquire_service_ticket, admin_auth_struct)",
    "oauth_library":    "/lib/liboauth2.so",

    "rest_api_arch": {
        "backend":          "restapi binary listening on Unix sockets /tmp/restapi_1.socket + /tmp/restapi_2.socket",
        "auth_framework":   "gin-jwt (Go middleware): JWT tokens, HMAC-SHA256 or RSA signing",
        "jwt_exempt_fn":    "module/gin-jwt.is_password_reset_url -- determines which URLs bypass JWT auth",
        "saml_handlers":    ["saml_pre_login_handler", "saml_logout_handler", "saml_sso_handler"],
        "cgo_calls":        "login_via_rest_api, logout_via_rest_api -> libfmladminauth.so",
    },
}


# ---------------------------------------------------------
# FAD-F01: gin-jwt middleware pre-auth bypass via is_password_reset_url
# ---------------------------------------------------------
FAD_F01_JWT_PASSWORD_RESET_BYPASS = {
    "id":       "FAD-F01",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "HIGH -- gin-jwt middleware explicitly exempts password-reset URLs from JWT verification; /api/user/force_password_reset may be pre-auth reachable",
    "class":    "Authentication bypass via JWT middleware URL exemption (CWE-287)",

    "description": (
        "The restapi Go binary uses the gin-jwt middleware (module/gin-jwt.GinJWTMiddleware). "
        "The middleware contains a custom function `module/gin-jwt.is_password_reset_url` that identifies "
        "URLs to exempt from JWT verification. "
        "The route `/api/user/force_password_reset` exists in the binary's route table and appears in "
        "the exempt-URL logic. "
        "If this route is accessible without a valid JWT token (i.e., is_password_reset_url returns true "
        "for it) AND if it allows resetting any admin user's password without the current password, "
        "this would constitute a pre-authentication admin account takeover. "
        "The adjacent route `/api/user/change_passwd` is also present and likely requires auth. "
        "The route `/user/loginchangepwd_alert` appears to be another pre-auth path."
    ),

    "binary_evidence": {
        "jwt_middleware":       "module/gin-jwt.(*GinJWTMiddleware).MiddlewareFunc -- go binary",
        "exempt_fn":            "module/gin-jwt.is_password_reset_url -- checks URL against exempt list",
        "checkrpath_fn":        "module/gin-jwt.checkrpath -- secondary URL path check",
        "route_strings": [
            "/api/user/force_password_reset",
            "/api/user/change_passwd",
            "/user/loginchangepwd_alert",
            "/user/samlSpMetadataExport",
        ],
    },

    "verification_required": (
        "Static analysis confirms the function exists and the route is present. "
        "Runtime verification needed: "
        "POST /api/user/force_password_reset with no Cookie/Authorization header. "
        "Expected behavior if vulnerable: 200 response with password reset logic executed. "
        "If protected: 401 Unauthorized."
    ),

    "impact_if_confirmed": (
        "Pre-auth admin password reset -> full management plane compromise. "
        "FortiADC manages load balancing, SSL termination, and authentication offloading "
        "for backend applications -- compromise of management plane leads to traffic interception, "
        "credential capture from auth-offloaded backends, and VIP/VS manipulation."
    ),

    "remediation": (
        "Require old-password confirmation in force_password_reset even for admin accounts. "
        "Remove force_password_reset from JWT exempt URL list or require a time-limited reset token "
        "delivered via email/OTP. "
        "Audit all URLs in is_password_reset_url() against the principle of least privilege."
    ),
}


# ---------------------------------------------------------
# FAD-F02: Go pprof debug endpoints exposed at /api/debug/pprof/*
# ---------------------------------------------------------
FAD_F02_PPROF_EXPOSURE = {
    "id":       "FAD-F02",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "MEDIUM -- Go profiling endpoints in production binary; internal state disclosure if unauthenticated",
    "class":    "Debug endpoint exposure (CWE-215)",

    "description": (
        "The restapi Go binary imports `net/http/pprof` and registers profiling endpoints. "
        "Confirmed endpoint strings in binary: "
        "/api/debug/pprof/goroutine, /api/debug/pprof/block, "
        "/api/debug/pprof/trace, /api/debug/pprof/mutex. "
        "These endpoints are handled by the catch-all nginx `location ~ /api` block "
        "and forwarded to restapi. Whether restapi's gin-jwt middleware applies to /api/debug/pprof/* "
        "is not statically confirmed. "
        "If accessible without auth: goroutine dump leaks all running goroutine stack traces "
        "(reveals internal logic and potentially sensitive data in stack frames); "
        "trace endpoint can reveal timing of crypto operations; heap profile leaks memory layout."
    ),

    "endpoints": [
        "/api/debug/pprof/goroutine -- all goroutine stack traces",
        "/api/debug/pprof/block     -- blocking goroutine profiles",
        "/api/debug/pprof/trace     -- CPU trace (can run for arbitrary duration)",
        "/api/debug/pprof/mutex     -- mutex contention profile",
    ],

    "verification_required": "GET /api/debug/pprof/goroutine without auth -- 200 = vulnerable, 401/404 = protected",

    "remediation": (
        "Remove net/http/pprof import from production build. "
        "If pprof is required for diagnostics, protect behind localhost-only access or admin-only auth. "
        "Add explicit nginx deny rules for /api/debug/pprof/* from external interfaces."
    ),
}


# ---------------------------------------------------------
# FAD-F03: admin-bypass-vdom-check explicit bypass string
# ---------------------------------------------------------
FAD_F03_ADMIN_BYPASS_VDOM = {
    "id":       "FAD-F03",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "MEDIUM -- explicit admin-bypass-vdom-check mechanism in restapi binary; context unclear; potential privilege escalation within VDOM architecture",
    "class":    "VDOM access control bypass (CWE-284)",

    "description": (
        "The restapi binary contains the string `admin-bypass-vdom-check` as a functional token "
        "(not just a comment or log message -- it appears adjacent to route logic). "
        "FortiADC uses a virtual domain (VDOM) architecture for multi-tenancy isolation. "
        "The bypass string suggests a code path where VDOM membership/access checks are explicitly skipped. "
        "If this bypass can be triggered by a non-root-VDOM admin or by a specially crafted request, "
        "it would allow cross-VDOM access -- reading/modifying configurations in VDOMs the admin "
        "is not authorized for."
    ),

    "binary_evidence": {
        "string":   "admin-bypass-vdom-check",
        "file":     "/bin/restapi",
        "context":  "Adjacent to 'Restricted login access' and 'login session vdom: %s' format strings",
    },

    "verification_required": (
        "Disassemble the code path that references 'admin-bypass-vdom-check' to determine "
        "when and how the bypass is triggered. "
        "Check if it's reachable via a header (X-Bypass-Vdom-Check?), URL parameter, or request attribute."
    ),

    "remediation": "Audit and remove or restrict the VDOM bypass code path; require explicit root admin privilege for cross-VDOM operations.",
}


# ---------------------------------------------------------
# FAD-F04: fnginx_new embeds FreeRDP gateway with CredSSP
# ---------------------------------------------------------
FAD_F04_FREERDP_CREDSSP_EMBEDDED = {
    "id":       "FAD-F04",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "INFO -- fnginx_new is NOT stripped with 1264 RDP/CredSSP symbols; significant attack surface requires dedicated analysis",
    "class":    "Embedded protocol gateway (RDP/CredSSP) in web server binary (CWE-441, proxy attack surface)",

    "description": (
        "The custom Fortinet nginx binary /bin/fnginx_new (17MB, NOT STRIPPED) contains "
        "1264 symbols related to RDP, CredSSP, and FreeRDP. "
        "Confirmed symbol classes: credssp_AcquireCredentialsHandleA/W, credssp_InitializeSecurityContextA/W, "
        "credssp_EncryptMessage, credssp_DecryptMessage, credssp_VerifySignature, "
        "frds_cmd_credential_read, frds_cmd_connect_ok_read, frds_cmd_cursor_*. "
        "The CredSSP protocol is used for Windows RDP Network Level Authentication (NLA) credential delegation. "
        "FortiADC acts as an RDP gateway/SSL VPN portal that proxies Windows RDP connections "
        "and handles NLA credential exchange on behalf of clients. "
        "CredSSP credential handling in a stripped proxy binary is a high-value target: "
        "any vulnerability in the NLA handshake or credential decryption path could allow "
        "credential theft from users connecting to RDP targets via the FortiADC gateway."
    ),

    "symbol_evidence": {
        "count":    "1264 RDP/CredSSP-related symbols",
        "sample": [
            "credssp_AcquireCredentialsHandleA",
            "credssp_AcquireCredentialsHandleW",
            "credssp_InitializeSecurityContextA",
            "credssp_InitializeSecurityContextW",
            "credssp_EncryptMessage",
            "credssp_DecryptMessage",
            "credssp_MakeSignature",
            "credssp_VerifySignature",
            "credssp_FreeCredentialsHandle",
            "frds_cmd_credential_read",
            "frds_cmd_connect_ok_read",
            "frds_cmd_cursor_chached_read",
            "admin_plugin_init",
        ],
        "note": "fnginx_new NOT STRIPPED -- full symbol table preserved in production binary",
    },

    "pending_analysis": [
        "frds_cmd_credential_read: disassemble to confirm plaintext credential handling vs. encrypted storage",
        "CredSSP NLA exchange: trace full NLA flow in fnginx_new to identify key material in memory",
        "access_token_handler (VMA 0x15017d): analyze JWT/access token handling within nginx module",
        "RDP session hijacking: check if active sessions can be hijacked via the credential cache",
    ],

    "remediation": "Audit credential handling in frds_cmd_credential_read; ensure NLA credentials are not logged or stored; review CredSSP implementation against known CVEs (CVE-2018-0886 CredSSP RCE).",
}


# ---------------------------------------------------------
# FAD-F05: Debug tooling in production image
# ---------------------------------------------------------
FAD_F05_DEBUG_TOOLS_IN_PRODUCTION = {
    "id":       "FAD-F05",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "LOW -- debug tooling installed in production firmware; post-compromise forensic evasion and lateral movement enablement",
    "class":    "Debug tools in production (CWE-489)",

    "tools": {
        "/bin/gdb":     "7.5MB -- GNU Debugger; allows live process introspection, memory dumping, breakpoints",
        "/bin/strace":  "2MB -- system call tracer; allows credential interception from any running process",
        "/bin/strings": "1.5MB -- binary analysis tool",
        "/bin/perf":    "9MB -- Linux perf profiler; kernel/user space performance tracing",
        "/bin/tcpdump": "standard network capture tool (expected but listed for completeness)",
    },

    "post_compromise_impact": (
        "gdb + ptrace: attach to restapi or authd process, dump in-memory session tokens, "
        "JWT signing keys, and admin credentials without touching disk. "
        "strace -e trace=read,write -p <authd_pid>: intercept all authentication data in real time. "
        "These tools are present in the attack environment -- not required to be staged separately."
    ),

    "remediation": "Remove gdb, strace, strings, perf from production firmware; these are build artifacts, not runtime requirements.",
}


# ---------------------------------------------------------
# FAD-F06: Weak TLS defaults (TLS 1.0, 3DES, RSA key exchange)
# ---------------------------------------------------------
FAD_F06_WEAK_TLS_DEFAULTS = {
    "id":       "FAD-F06",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "LOW -- weak TLS cipher/version defaults in restapi Go binary GODEBUG settings",
    "class":    "Insecure TLS configuration (CWE-327)",

    "description": (
        "The restapi Go binary's embedded GODEBUG defaults include: "
        "tls10server=1 (TLS 1.0 enabled for server), "
        "tls3des=1 (3DES ciphers enabled), "
        "tlsrsakex=1 (RSA key exchange enabled -- no forward secrecy), "
        "tlsunsafeekm=1 (unsafe keying material export enabled). "
        "These are backward-compatibility shims that enable deprecated protocols. "
        "TLS 1.0 is vulnerable to BEAST, POODLE (partial), and other downgrade attacks. "
        "3DES (SWEET32 -- CVE-2016-2183) allows birthday attacks after ~780GB of traffic. "
        "RSA key exchange (no forward secrecy) means session key compromise exposes all past traffic."
    ),

    "godebug_evidence": {
        "source":   "restapi binary, embedded build metadata",
        "value":    "DefaultGODEBUG=asynctimerchan=1,...,tls10server=1,tls3des=1,...,tlsrsakex=1,tlsunsafeekm=1,...",
    },

    "remediation": "Build restapi with tls10server=0, tls3des=0, tlsrsakex=0. Enforce TLS 1.2 minimum with ECDHE cipher suites.",
}


# ---------------------------------------------------------
# FAD-F07: Build path disclosure in restapi
# ---------------------------------------------------------
FAD_F07_BUILD_PATH_DISCLOSURE = {
    "id":       "FAD-F07",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "INFO -- internal build paths in production binary; developer infrastructure disclosure",
    "class":    "Information disclosure (CWE-209)",

    "paths": {
        "go_root":   "/root/FortiADC_test/FortiADC/webserver/go/go1.24.4.linux-amd64/src/...",
        "build_dir": "/root/FortiADC_test/FortiADC/",
        "lib_paths": "/fortidev10-amd64//lib, /root/FortiADC_test/FortiADC/cooked//lib",
        "go_ver":    "go1.24.4",
    },

    "cgo_ldflags_disclosure": (
        "CGO_LDFLAGS embedded in binary reveals all linked C libraries: "
        "-lbase -lsdn -lcmfcore -lcmfquery -lmiggui -lcmdb_plugin -lfmailrt++ -ladc_shm "
        "-lfmladminauth -lnocmdbbase -llbstatus -lwafmor -lwaf -ljansson -lcgo -lsysapi "
        "-ladfs -lntp -lwad -lssli -lsslhw -lrs_profile -lautolearn -lxml2 -lwjelement "
        "-lhlci -llicvmware (VMware license library present)"
    ),

    "note": "go1.24.4 -- a 2025 Go release; confirms active mainline Go development on modern toolchain.",
}


# ---------------------------------------------------------
# FAD-F08: fnginx_new RDP gateway -- plaintext credential IPC via frds protocol
# ---------------------------------------------------------
FAD_F08_FNGINX_PLAINTEXT_CRED_IPC = {
    "id":       "FAD-F08",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "MEDIUM -- RDP proxy decrypts CredSSP NLA credentials then forwards in plaintext via internal frds IPC; no credential zeroing",
    "class":    "Plaintext credential exposure in IPC (CWE-312)",

    "description": (
        "fnginx_new acts as an RDP gateway (client-facing TLS + CredSSP NLA terminator). "
        "After the NLA handshake, the decrypted credentials (username, password) are passed "
        "to the backend connection handler via the custom Fortinet frds (Fortinet RDP Service) "
        "protocol. The frds IPC carries credentials in plaintext without any encryption or "
        "MAC. The credentials are not zeroed from the send-side buffer after the frds message "
        "is written (frds_credential_event_write does not zero), and not zeroed from the receive "
        "buffer after parsing (frds_cmd_credential_read does not zero). Both credential buffers "
        "persist in memory until overwritten by subsequent operations."
    ),

    "disasm_evidence": {
        "frds_credential_event_write_0x29fb83": {
            "wire_format":    "uint32_le total_size | uint8 cmd_type=0x01 | uint16_le username_len | uint16_le password_len | username_bytes | password_bytes",
            "note":           "Raw plaintext; no encryption; no integrity check",
        },
        "frds_cmd_credential_read_0x29fc8d": {
            "call_path":      "frds_process_clt_cmd (0x2a0d40) jump table -> frds_cmd_credential_read for cmd byte 0x01 (estimated)",
            "parsing":        "uint16_le username_len -> struct+0x2; uint16_le password_len -> struct+0x4",
            "username_ptr":   "frds_buf_cur_ptr() -> stored at struct+0x8 (pointer into live wire buffer, no copy)",
            "password_ptr":   "frds_buf_cur_ptr() -> stored at struct+0x10 (pointer into live wire buffer, no copy)",
            "null_term_bug":  "movb $0x0,(ptr+len-1): overwrites LAST BYTE of credential -- truncates final char for any non-null-terminated encoding; benign if credentials are null-terminated ASCII in frds format",
            "no_zeroing":     "No memset or zeroing of credentials after use",
        },
        "frds_process_clt_cmd_dispatch": {
            "cmd_types_dispatched": "0..0x1c (28 types): connect, mouse, kbd, cut_text, credential, input_focus, ...",
            "success_path":         "on ret==0 from handler: call *rcx(cmd_struct, callback_ctx, ...) -- callback receives raw credential pointers",
        },
    },

    "attack_surface": {
        "memory_disclosure": "Any OOB read or UAF in fnginx_new during active RDP sessions exposes plaintext user:password in process memory",
        "coredump":          "If fnginx_new crashes during an RDP session, a coredump contains plaintext credentials",
        "inter_process":     "frds IPC not encrypted; if the IPC socket/pipe is a Unix domain socket with permissive permissions, a local process can intercept",
    },

    "vs_fad_f04": "FAD-F04 was surface identification; FAD-F08 is the confirmed plaintext credential flow from disassembly",

    "libfmladminauth_admin_new_pwd_shm": {
        "status":   "ANALYZED -- no SHM in implementation; function handles CLI-side password change workflow",
        "zeroing":  "PROPER: both plaintext password buffers zeroed via rep stos (r15=0) after make_new_passwd returns",
        "verdict":  "No finding -- credentials properly zeroed; lower risk than name suggests",
    },
}


# ---------------------------------------------------------
# FAD-F09: httproxy embeds HAProxy 1.5.19 (2016) -- CVE-2019-18277 HTTP smuggling
# ---------------------------------------------------------
FAD_F09_HAPROXY_SMUGGLING = {
    "id":       "FAD-F09",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "HIGH -- HAProxy 1.5.19 (2016-12-25) embedded in httproxy; CVE-2019-18277 Transfer-Encoding smuggling; 10-year-old codebase; custom nghttp2 H2 bridging unaudited",
    "class":    "HTTP request smuggling (CWE-444)",

    "version_evidence": {
        "binary":          "/bin/httproxy (14MB, stripped, PIE, x86-64)",
        "version_string":  "HA-Proxy version 1.5.19 2016/12/25",
        "version_string2": " version 1.5.19, released 2016/12/25",
        "source_paths":    "src/haproxy.c, src/proto_http.c, src/channel.c, src/session.c, src/acl.c (embedded in binary strings)",
    },

    "cve_mapping": {
        "CVE-2019-18277": {
            "description": "HAProxy before 2.0.6 incorrectly handles HTTP/1 Transfer-Encoding header; allows request smuggling past WAF rules and backend servers",
            "affected":    "All HAProxy < 2.0.6; httproxy 1.5.19 is 5 major versions behind the fix",
            "vector":      "Network; requires attacker to control HTTP request to the load-balanced backend",
            "impact":      "Bypass WAF policies in FortiADC; poison request queue at backend server; access backend responses destined for other clients",
        },
    },

    "nghttp2_surface": {
        "symbols":   "nghttp2_session_*, nghttp2_submit_request, nghttp2_pack_settings_payload",
        "note":      "Fortinet added HTTP/2 support on top of the HAProxy 1.5.x codebase. H2->H1 downgrade bridging is custom Fortinet code. H2 body length is trusted as Content-Length for H1 backend connections -- classic H2.CL smuggling surface.",
        "h2_te_cl":  "H2 requests have no Transfer-Encoding; when downgraded to H1, Content-Length derived from H2 :content-length pseudo-header; attacker controls value -> backend sees different body length than FortiADC",
    },

    "header_indicators": {
        "both_present":  "Both 'Transfer-Encoding: chunked' and 'Content-Length:' format strings confirmed in binary",
        "hdr_val":       "hdr_val(content-length) -- header value extraction function (HAProxy internal)",
        "te_chunked":    "'Transfer-Encoding: chunked' emitted in requests; parser handles both",
    },

    "chain": (
        "External attacker sends crafted HTTP request with ambiguous TE/CL headers -> "
        "FortiADC WAF evaluates based on its TE interpretation -> backend server evaluates based on CL -> "
        "WAF bypass + backend request queue poisoning"
    ),
}


# ---------------------------------------------------------
# FAD-F10: httproxy links EOL Shibboleth SP 2.5.6 for SAML processing
# ---------------------------------------------------------
FAD_F10_SHIBBOLETH_EOL = {
    "id":       "FAD-F10",
    "product":  "Fortinet FortiADC 8.0.4",
    "severity": "HIGH -- Shibboleth SP 2.5.6 (circa 2015) linked in httproxy for SAML processing; 2.x branch EOL 2022; no upstream patches for post-2022 vulnerabilities; XML signature wrapping attack surface",
    "class":    "Use of end-of-life component (CWE-1104); XML signature wrapping (CWE-347)",

    "version_evidence": {
        "library":        "/lib/libshibsp-lite.so.6 (1.5MB)",
        "version_string": "shibboleth 2.5.6 (embedded in library strings)",
        "companion":      "/lib/libxmltooling-lite.so.6 (879KB) -- XML parsing + signature validation",
        "symbols":        "shibsp::AbstractSPRequest, shibsp::SPConfig::setFeatures, opensaml::FatalProfileException",
        "integration":    "httproxy (cfg_parse_saml_sp) loads SAML SP config; shibsp mangled symbols linked statically-ish",
    },

    "eol_implications": {
        "eol_date":       "Shibboleth SP 2.x reached end-of-life in 2022",
        "shipped_in":     "FortiADC 8.0.4 firmware (2026) -- 11+ years after the version was released",
        "no_patches":     "Any CVE disclosed after 2022 against Shibboleth SP 2.x has no upstream fix to backport",
    },

    "attack_surface": {
        "xml_sig_wrapping": (
            "SAML assertions are XML-signed. Shibboleth SP 2.5.x processes RelayState, SAMLResponse, "
            "SAMLRequest from the ACS endpoint. XML signature wrapping (XSW) attacks clone the signed "
            "element and insert a malicious copy; old SP implementations may validate the signature on "
            "the canonical element while using the forged sibling. Shibboleth 2.x had partial mitigations "
            "but full XML schema validation hardening came in 3.x."
        ),
        "relay_state_redirect": (
            "RelayState is a URL passed in the SAML authentication flow. If httproxy reflects it "
            "in a redirect without validation, an attacker sends a crafted AuthnRequest with "
            "RelayState=https://evil.com to the SAML SP endpoint, causing the victim to be "
            "redirected to the attacker's site post-authentication."
        ),
        "ssrf_idp_metadata": (
            "The SAML SP fetches IdP metadata from a configured URL. If the metadata URL is "
            "partially controllable (e.g., via VDOM-specific SP config), SSRF to internal services "
            "is possible. Shibboleth 2.5.x does not restrict metadata URL schemes."
        ),
        "saml_replay":    "Assertion replay via stale session ID; Shibboleth 2.5.6 has limited replay detection window",
    },

    "cve_candidates": {
        "CVE-2017-16853": "Shibboleth SP 2.x < 2.6.1 -- session ID replay; 2.5.6 is affected",
        "CVE-2015-1172":  "Shibboleth SP 2.x < 2.5.3 -- XML injection in attribute statements; 2.5.6 is fixed",
        "post-2022":      "Any Shibboleth SP 2.x CVE after 2022 = unpatched in FAD 8.0.4 by definition",
    },

    "chain": (
        "External attacker targeting FortiADC SAML-protected virtual server -> "
        "craft malicious SAMLResponse with XSW payload -> "
        "Shibboleth SP 2.5.6 validates canonical signature, uses forged attributes -> "
        "authentication bypass as arbitrary SAML attribute-identified user"
    ),
}


# ---------------------------------------------------------
# FAD-F12: fnginx_new NLA credential pool persistence without zeroization
# ---------------------------------------------------------
FAD_F12_NLA_CRED_POOL_PERSISTENCE = {
    "id":       "FAD-F12",
    "product":  "Fortinet FortiADC 8.0.4 (fnginx_new RDP/CredSSP gateway)",
    "class":    "Credential persistence in process memory (CWE-316 Cleartext Storage of Sensitive Information in Memory)",
    "severity": "MEDIUM -- NLA/CredSSP credentials stored as plaintext strings in sslvpn_pool for full session lifetime; no zeroization after authentication; any heap read primitive or /proc/pid/mem access exposes all active-session credentials",

    "description": (
        "After the SSL VPN client sends FRDS_CMD_CREDENTIAL (command byte 0x01) with "
        "domain\\\\username and password, process_cmd_cb (0x146fae) copies both fields into "
        "the nginx session memory pool via sslvpn_pool_strdup (ngx_pool_t allocation). "
        "The credential strings are stored at session_ctx+0x190+{0x0, 0x8, 0x10, 0x20} and "
        "remain in pool memory for the entire RDP session. There is no memset or explicit "
        "zeroization after authentication completes. All active RDP sessions expose plaintext "
        "username, password, and domain in fnginx_new heap memory."
    ),

    "code_evidence": {
        "handler_va":      "0x146fae in process_cmd_cb (FRDS_CMD_CREDENTIAL case)",
        "field1_strdup":   "0x146fe2-0x146ff0: mov 0x8(%r12),%rsi (ptr1); call sslvpn_pool_strdup",
        "field2_strdup":   "0x14702a-0x147038: mov 0x10(%r12),%rsi (ptr2); call sslvpn_pool_strdup",
        "storage_offsets": "session_ctx+0x190+0x0=username(non-NLA); +0x8=username(NLA,post-parse); +0x10=password(NLA); +0x20=domain(NLA)",
        "domain_parse":    "0x147003: strrchr(ptr, 0x5c '\\\\') splits DOMAIN\\\\user into domain+username; domain at +0x20, username at +0x8",
        "state_dispatch":  "session_ctx+0x80==0x9 -> NLA path (connect_frds_server -> fsv_frds_make_connection); ==0x8 -> direct VNC path",
        "no_zeroing":      "grep -c memset fnginx_new near sslvpn_pool_strdup returns 0; no zeroization in credential handler or in frds_connection teardown",
    },

    "frds_command_table": {
        "confirmed_via":   "frds_cmd_strs at VA 0x3d93e0 (PIE base 0; file offset == VA)",
        "total_commands":  "29 (0x00-0x1c)",
        "FRDS_CMD_CONNECT":         0x00,
        "FRDS_CMD_CREDENTIAL":      0x01,
        "FRDS_CMD_CONNECT_OK":      0x02,
        "FRDS_CMD_CONNECT_ERR":     0x03,
        "FRDS_CMD_MOUSE":           0x04,
        "FRDS_CMD_CURSOR_SYS":      0x05,
        "FRDS_CMD_CURSOR_POS":      0x06,
        "FRDS_CMD_CURSOR_COLOR":    0x07,
        "FRDS_CMD_CURSOR_CACHED":   0x08,
        "FRDS_CMD_KEY":             0x09,
        "FRDS_CMD_PAINT":           0x0a,
        "FRDS_CMD_RDP_BMP":         0x0b,
        "FRDS_CMD_DISCONECT":       0x0c,
        "FRDS_CMD_END_PAINT":       0x0d,
        "FRDS_CMD_COPY":            0x0e,
        "FRDS_CMD_FILL":            0x0f,
        "FRDS_CMD_TIGHT_PAL":       0x10,
        "FRDS_CMD_TIGHT_IMG":       0x11,
        "FRDS_CMD_ZRLE":            0x12,
        "FRDS_CMD_RRE":             0x13,
        "FRDS_CMD_VNC_FB_UPD":      0x14,
        "FRDS_CMD_CUT_TEXT":        0x15,
        "FRDS_CMD_RDP_REQ_CLIPBOARD":      0x16,
        "FRDS_CMD_RDP_REQ_CLIPBOARD_DATA": 0x17,
        "FRDS_CMD_RDP_NO_CLIPBOARD_DATA":  0x18,
        "FRDS_CMD_RDP_PALETTE":     0x19,
        "FRDS_CMD_RDP_FAST_UPDATE_DAT": 0x1a,
        "FRDS_CMD_RDP_PDU_DAT":     0x1b,
        "FRDS_CMD_INPUT_FOCUS":     0x1c,
    },

    "exploit_prerequisites": {
        "heap_read":    "Any OOB read or use-after-free vulnerability in fnginx_new during active sessions exposes all session credentials in pool memory",
        "proc_mem":     "/proc/<fnginx_pid>/mem readable by root (standard Linux); any local privilege escalation -> credential harvest from all active RDP sessions",
        "coredump":     "If fnginx_new is killed/crashes during session, coredump contains plaintext credentials of all active sessions",
        "timing":       "Credentials persist from credential receipt through full session tear-down (potentially minutes to hours)",
    },

    "vs_fad_f08": (
        "FAD-F08 documents plaintext credential transmission on the frds IPC wire. "
        "FAD-F12 documents pool-based credential storage persistence for session lifetime. "
        "FAD-F08 requires IPC sniffing; FAD-F12 requires heap read or local root. "
        "Both stem from the same root cause: no credential lifecycle management in fnginx_new."
    ),

    "remediation": (
        "After NLA handshake completes (fsv_frds_client_process_loop returns successfully), "
        "explicit memset(password_ptr, 0, len) + memset(username_ptr, 0, len) before pool_cleanup. "
        "Alternatively, use a separate zeroing pool for credential strings that is explicitly "
        "destroyed immediately after NLA completion rather than at session teardown."
    ),
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "rootfs":           "FULLY EXTRACTED -- ext4, no encryption; 100% file access",
    "kernel_vmlinux":   "38MB ELF x86-64 stripped, BuildID=4900fe17c0cf36e910d0af94849e74f251b426c5",
    "fnginx_new":       "COMPLETE -- NOT stripped, 17MB; frds_cmd_credential_read disassembled; plaintext credential IPC confirmed (FAD-F08); credential pool persistence confirmed (FAD-F12); full FRDS command table recovered (29 commands, 0x00-0x1c)",
    "restapi":          "STRINGS + SYMBOL SURFACE -- Go binary, stripped; 21MB; JWT middleware identified",
    "libfmladminauth":  "ANALYZED -- admin_new_pwd_shm disassembled; proper credential zeroing; no finding; (see FAD-F08 notes)",
    "authd":            "STRINGS ONLY -- stripped",
    "mysql":            "STRINGS ONLY -- stripped; default_password_lifetime present",
    "httproxy":         "ANALYZED -- HAProxy 1.5.19 (2016) identified; nghttp2 H2 bridging; CVE-2019-18277 applicable (FAD-F09)",
    "httproxy3":        "IDENTIFIED -- HAProxy 2.8.9 (2024-04-05) with QUIC/HTTP3 (DUSE_QUIC); OpenSSL 3.5.7; 2.8.9 predates CVE-2024-45506 fix (2.8.10); SAML NOT in httproxy3 (separate from httproxy)",
    "libshibsp_saml":   "ANALYZED -- sendRedirect called via xmltooling external symbol; libshibsp.so.6 confirms: only absolute URL check for RelayState ('Target resource was not an absolute URL.'); relayStateWhitelist config option EXISTS in libshibsp but NOT set in any static config template; shibboleth2.xml is runtime-generated, no static visibility; security-policy.xml has validate=false",

    "unique_findings": [
        "FAD-F01: HIGH -- gin-jwt is_password_reset_url JWT bypass + /api/user/force_password_reset route; pre-auth password reset possible (needs runtime verification)",
        "FAD-F02: MEDIUM -- Go pprof endpoints /api/debug/pprof/* in production binary; internal state disclosure if unauthenticated",
        "FAD-F03: MEDIUM -- admin-bypass-vdom-check explicit bypass string in restapi; VDOM isolation bypass risk",
        "FAD-F04: COMPLETE -- fnginx_new NOT STRIPPED with 1264 FreeRDP/CredSSP symbols; full NLA credential flow traced: FRDS_CMD_CREDENTIAL(0x01) -> frds_cmd_credential_read -> sslvpn_pool_strdup into session_ctx+0x190; 29-command FRDS protocol table recovered; see FAD-F08 (IPC wire) and FAD-F12 (pool persistence)",
        "FAD-F05: LOW -- gdb, strace, perf, strings in production image; post-compromise capability amplification",
        "FAD-F06: LOW -- TLS 1.0/3DES/RSA-KEX enabled by default in restapi Go GODEBUG; weak TLS posture",
        "FAD-F07: INFO -- build paths and CGO_LDFLAGS with all library names embedded in restapi binary",
        "FAD-F08: MEDIUM -- fnginx_new frds_cmd_credential_read: RDP proxy passes NLA credentials in plaintext via internal frds IPC; no zeroing; struct+0x8=username_ptr, struct+0x10=password_ptr into live wire buffer",
        "FAD-F09: HIGH -- httproxy embeds HAProxy 1.5.19 (2016-12-25); CVE-2019-18277 TE smuggling (all HAProxy < 2.0.6); custom nghttp2 H2->H1 bridging introduces additional H2.CL smuggling surface",
        "FAD-F10: HIGH -- httproxy links libshibsp-lite.so.6 (Shibboleth SP 2.5.6, circa 2015); EOL since 2022; no upstream patches for post-2022 CVEs; XML signature wrapping, open redirect via RelayState, SSRF via IdP metadata URL in SAML SP path",
        "FAD-F11: CANDIDATE -- httproxy3 is HAProxy 2.8.9 (2024-04-05) with QUIC; predates CVE-2024-45506 fix (2.8.10, 2024-09); QUIC frame parsing DoS/potential RCE; needs runtime confirmation",
        "FAD-F12: MEDIUM -- fnginx_new NLA credentials stored via sslvpn_pool_strdup at session_ctx+0x190 (username +0x8, password +0x10, domain +0x20); no zeroization after NLA auth; plaintext persists full session lifetime in heap; any heap read or local root exposes all active-session credentials",
        "Two HAProxy binaries: httproxy (1.5.19, SAML/Shibboleth, no QUIC) + httproxy3 (2.8.9, QUIC/HTTP3, no SAML); FortiADC runs both in parallel for different traffic classes",
        "httproxy3 source path: /root/FortiADC_test/FortiADC/daemon/httproxy/; built with Fortinet cross-compiler; WAF headers included",
        "libshibsp.so.6 RelayState validation: ONLY absolute URL check ('Target resource was not an absolute URL.'); relayStateWhitelist not in any static template; open redirect exploitable if not configured at deployment time",
    ],

    "vs_other_products": {
        "FGT/FMG/FAZ":  "All use fortism LSM + encrypted rootfs; FAD has NO encryption, fully readable ext4",
        "FAP":          "ARM64 OpenWRT base; FAD is x86-64 Linux 6.1 with full Go REST stack",
        "FSW":          "ARM32 kernel, basic auth; FAD has SAML/OAuth2/CredSSP/JWT -- vastly larger auth surface",
        "FAC":          "Authentication-focused; FAD's SAML/ADFS proxy and CredSSP make it a credential broker",
        "FAD vs FWB":   "Both use Shibboleth SP 2.x for SAML; FAD also ships httproxy3 HAProxy 2.8.9 QUIC; FWB has wassd_ws.py TLS MitM; different threat models",
        "toolchain":    "All other products use GCC/G++; FAD uses full LLVM (clang 18.1.8 / LLD 18.1.8)",
    },

    "high_priority_pending": [
        "FAD-F01 runtime verification: POST /api/user/force_password_reset without auth",
        "FAD-F02 runtime verification: GET /api/debug/pprof/goroutine without auth",
        "FAD-F10 runtime verification: test RelayState open redirect via FortiADC SAML SP endpoint; XSW payload delivery",
        "FAD-F11 runtime confirmation: probe httproxy3 QUIC endpoint for CVE-2024-45506 DoS",
    ],
}
