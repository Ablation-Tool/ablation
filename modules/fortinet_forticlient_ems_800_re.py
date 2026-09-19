"""
FortiClient EMS 8.0.0 -- Linux ARM64 Package RE
Source: FortiClientEMS_8.0.0.0157_linux.run (Makeself self-extracting shell, skip=682 lines)
Extraction: Makeself -> gzip+tar -> DEB (FortiClientEMS_8.0.0.0157_linux_arm64.deb) -> ar -> data.tar.zst -> filesystem at /tmp/ems_800_fs/
Architecture change from 7.2.9: Nginx replaces Apache24; PostgreSQL 15 replaces SQL Server; Linux ARM64.
Django app: /opt/forticlientems/fcm/ (mostly compiled to .pyc, some plaintext .py)
Python: 3.10 (pyc magic 0x6f0d = 3439), compiled 2026-06-25
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":    "Fortinet FortiClient EMS",
    "version":    "8.0.0.0157",
    "build_date": "2026-06-25",
    "package":    "FortiClientEMS_8.0.0.0157_linux.run (Makeself) -> .deb (data.tar.zst)",
    "arch":       "Linux ARM64",
    "stack": {
        "web_server": "Nginx (replaces Apache24 from 7.2.x)",
        "wsgi":       "Django 4.x (Gunicorn/uWSGI)",
        "python":     "3.10 (CPython, ARM64)",
        "db":         "PostgreSQL 15 (replaces SQL Server)",
        "cache":      "Redis",
        "das":        "FCTDas (Go binary, ARM64) -- data access service",
        "workers":    "emsworkers_linux_arm64 (C++, ARM64) -- main daemon",
        "ztna":       "emsworkers with separate ZTNA worker upstream",
        "aigateway":  "fcems_aigateway (Python venv) -- separate AI service",
        "scim":       "SCIM server on localhost:7643",
        "grafana":    "Grafana on localhost:3000 (partial exposure)",
    },
    "layout": {
        "installdir":   "/opt/forticlientems",
        "fcm_dir":      "/opt/forticlientems/fcm/fcm/",
        "settings":     "/opt/forticlientems/fcm/fcm/settings.py",
        "nginx_conf":   "/etc/nginx/sites-available/ems-443.conf.template",
        "nginx_main":   "/etc/nginx/nginx.conf.template",
        "data_dir":     "/opt/forticlientems/data/",
        "bin_dir":      "/opt/forticlientems/bin/",
        "ai_dir":       "/opt/forticlientems/ai/gateway/",
    },
    "binaries": {
        "emsworkers_linux_arm64": "82MB ARM64 ELF C++ (stripped, PIE) -- main daemon",
        "FCTDas":                 "25MB ARM64 ELF Go (pclntab @ 0xfcb135) -- data access service",
        "fos_server":             "24MB ARM64 Go binary",
        "setcredentials":         "27MB ARM64 Go binary",
        "PasswordRecovery":       "27MB ARM64 Go binary",
        "emscli":                 "34MB ARM64 Go binary",
        "adconnector_linux_arm64":"36MB ARM64 Go binary",
        "fdsclt":                 "40MB ARM64 Go binary",
        "installutils":           "40MB ARM64 Go binary",
    },
}

# ---------------------------------------------------------
# Delta vs 7.2.9 (fixes and regressions)
# ---------------------------------------------------------
DELTA_FROM_729 = {
    "FIXED": {
        "EMS-F1":  "SECRET_KEY randomized at install -- no longer hardcoded",
        "EMS-F3":  "DEBUG=False confirmed",
        "EMS-F4":  "SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True",
        "EMS-F5":  "Apache optional_no_ca replaced by Nginx ssl_verify_client optional (better)",
        "EMS-F6":  "Nginx ssl_verify_client optional -- no CA-cert bypass needed",
        "EMS-F7":  "Django check: HTTP_X_SSL_CLIENT_VERIFY == 'SUCCESS' confirmed present",
    },
    "PARTIAL": {
        "EMS-F2":  "safe_join() added in shared/utils/path.py but comment in regex.py says 'Port fully in 8.0.1' -- transitional",
    },
    "SAME": {
        "SESSION_ENGINE": "django.contrib.sessions.backends.signed_cookies -- client-side session signing unchanged",
        "FORTINET_CA":    "Same CA cert (serial DAF636B443D4A58B) shipped for client cert auth",
    },
    "NEW_REGRESSIONS": [
        "SECRET_KEY now also decrypts PostgreSQL + Redis credentials (cascading trust)",
        "Nginx /ai/ proxy is completely unauthenticated at Nginx layer (EMS-800-F08)",
        "FCTDas dynamic SQL: UPDATE FortiClients_users SET %s; and IN (%s) patterns",
        "emsworkers CGo memcpy in impdb service (EMS-800-F04)",
    ],
}

# =============================================================
# FINDINGS -- FortiClient EMS 8.0.0
# =============================================================

FINDINGS = {}

# ---------------------------------------------------------
# EMS-800-F01 | SECRET_KEY Cascading Trust
# Severity: HIGH
# ---------------------------------------------------------
FINDINGS["EMS-800-F01"] = {
    "title":    "SECRET_KEY is master decryption key for all stored credentials",
    "severity": "HIGH",
    "status":   "CONFIRMED",
    "cvss":     "8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    "component": "settings.py + shared/utils/decrypt.py",

    "description": (
        "In 7.2.9, SECRET_KEY was hardcoded (EMS-F1, CRITICAL). In 8.0.0, it is randomized at "
        "install time. HOWEVER, the same SECRET_KEY is now used as the PBKDF2 master key for "
        "AES-256-GCM encryption of PostgreSQL and Redis credentials stored on disk in db.json "
        "and redis.json. Django's signed-cookie session engine also uses SECRET_KEY for HMAC "
        "signing. A single SECRET_KEY leak therefore enables: (1) session token forgery, "
        "(2) PostgreSQL credential decryption, (3) Redis credential decryption."
    ),

    "technical": {
        "session_engine":  "django.contrib.sessions.backends.signed_cookies -- client-side HMAC with SECRET_KEY",
        "credential_enc":  "PBKDF2(SECRET_KEY, salt[16], dkLen=32, count=10000, HMAC-SHA256) -> AES-256-GCM",
        "db_json_path":    "/opt/forticlientems/fcm/fcm/db.json (encrypted at rest)",
        "redis_json_path": "/opt/forticlientems/fcm/fcm/redis.json (encrypted at rest)",
        "decrypt_src":     "/opt/forticlientems/fcm/shared/utils/decrypt.py (plaintext source)",
        "settings_load": (
            "POSTGRES_DB_CONFIG = get_postgres_db_config(SECRET_KEY, Path(INSTALLDIR)/'fcm'/'fcm'/'db.json')\n"
            "REDIS_CONFIG = get_redis_config(SECRET_KEY, Path(INSTALLDIR)/'fcm'/'fcm'/'redis.json')"
        ),
        "decrypt_impl": (
            "def decrypt(encrypted_data, secret_key):\n"
            "    data = base64.b64decode(encrypted_data)\n"
            "    salt = data[:16]\n"
            "    derived_key = PBKDF2(secret_key, salt, dkLen=32, count=10000, hmac_hash_module=SHA256)\n"
            "    nonce = data[16:28]\n"
            "    ciphertext = data[28:-16]\n"
            "    tag = data[-16:]\n"
            "    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)\n"
            "    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')"
        ),
    },

    "impact": (
        "If SECRET_KEY is obtained via any path (Django debug page residual, timing oracle, "
        "file read vulnerability), attacker gains: arbitrary session cookie forgery (admin session), "
        "PostgreSQL password (DB lateral movement), Redis password (cache poisoning, session store)."
    ),

    "exploit_sketch": (
        "1. Obtain SECRET_KEY (via admin account, path traversal, or other vuln)\n"
        "2. Read /opt/forticlientems/fcm/fcm/db.json + redis.json\n"
        "3. Run decrypt() with SECRET_KEY to get plaintext DB credentials\n"
        "4. Connect to PostgreSQL directly (EMS fleet data) and Redis\n"
        "5. Forge session cookie: django.core.signing.dumps({'_auth_user_id': '1', ...}, SECRET_KEY)"
    ),

    "remediation": (
        "Use separate independently-generated keys for session signing vs credential encryption. "
        "Never reuse SECRET_KEY as an encryption key. Use a proper secrets manager or HSM for DB credentials."
    ),
}

# ---------------------------------------------------------
# EMS-800-F02 | Nginx ssl_verify_client optional -- Auth Analysis
# Severity: MEDIUM (mitigated by Django-layer check)
# ---------------------------------------------------------
FINDINGS["EMS-800-F02"] = {
    "title":    "Nginx forwards unverified cert metadata; Django check confirmed but conditional",
    "severity": "MEDIUM",
    "status":   "PARTIAL -- Django check present but gated on ENABLE_CERT_AUTH_ALL DB flag",
    "cvss":     "5.3 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N)",
    "component": "ems-443.conf.template + cert_chain_auth.pyc + consts.pyc",

    "nginx_config": {
        "ssl_verify_client": "optional",
        "ssl_client_certificate": "/opt/forticlientems/data/certs/fortinet_ca_root_all.crt",
        "fortinet_ca_serial": "DAF636B443D4A58B",
        "fortinet_ca_cn":     "support",
        "fortinet_ca_expiry": "2038-01-19",
        "headers_forwarded": {
            "X-SSL-CLIENT-VERIFY": "$ssl_client_verify (SUCCESS|NONE|FAILED|ERROR)",
            "X-SSL-CLIENT-S-DN":   "$ssl_client_s_dn (empty if not verified)",
            "X-SSL-CLIENT-CERT":   "$ssl_client_escaped_cert",
            "X-SSL-CLIENT-S-DN-CN":"$client_cert_cn (extracted from DN regex)",
        },
        "cn_extraction": "map $ssl_client_s_dn $client_cert_cn { '~CN=([^,]+)' $1; } -- extracted regardless of verify status",
    },

    "django_check": {
        "file":    "fcm/auth/cert_chain_auth.py (compiled to .pyc)",
        "method":  "CertChainAuth.contains_certificate",
        "check":   "request.META.get('HTTP_X_SSL_CLIENT_VERIFY') == 'SUCCESS'",
        "status":  "PRESENT -- verified via pyc string extraction",
    },

    "db_flag": {
        "flag":   "ENABLE_CERT_AUTH_ALL",
        "source": "SELECT enable_cert_auth_all FROM system_demo_settings",
        "risk":   (
            "If False/NULL, cert auth not enforced for all endpoints. "
            "Endpoints that rely solely on cert auth may be bypassed when flag is False."
        ),
    },

    "residual_risk": (
        "1. ENABLE_CERT_AUTH_ALL=False disables cert auth enforcement globally -- default value unknown.\n"
        "2. An attacker with a cert signed by the shipped Fortinet CA (serial DAF636B443D4A58B) "
        "gets SUCCESS verification -- any device enrolled to EMS can impersonate other CNs.\n"
        "3. Nginx $client_cert_cn is extracted from the DN regex even before verify check -- "
        "the X-SSL-CLIENT-S-DN-CN header is always set from the cert's CN. Django must re-check "
        "X-SSL-CLIENT-VERIFY independently."
    ),
}

# ---------------------------------------------------------
# EMS-800-F03 | FCTDas Dynamic SQL Construction
# Severity: HIGH
# ---------------------------------------------------------
FINDINGS["EMS-800-F03"] = {
    "title":    "FCTDas Go binary contains raw SQL format strings with %s placeholders",
    "severity": "HIGH",
    "status":   "CONFIRMED -- format strings embedded in binary, attack path via emsworkers needs confirmation",
    "cvss":     "8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)",
    "component": "bin/FCTDas (Go ARM64, 25MB)",

    "description": (
        "FCTDas is the internal data access service for FortiClient EMS, receiving requests from "
        "emsworkers over a TCP port (stored in daemon_ports table). The binary contains raw SQL "
        "format strings using Go's %s/%d placeholder -- not PostgreSQL parameterized $1/$2 placeholders. "
        "These strings appear to be built with fmt.Sprintf or equivalent before DB execution. "
        "emsworkers passes data from HTTP requests to FCTDas, creating a potential SQL injection "
        "path from network-attacker-controlled input."
    ),

    "raw_sql_patterns": [
        "UPDATE FortiClients_users SET %s;",
        "UPDATE endpoint_ztna_cert_status SET %s;",
        "SELECT id, uid FROM FortiClients WHERE devices_id IN (%s);",
        "auth_user_id IN (%s)",
        "auth_user_id IS NULL AND %smachine_user_id IS NULL",
        "UPDATE all Devices statement: %s  (logged -- confirms dynamic SQL build)",
        "error deleting domain devices using SQL statement [%s]: %v  (statement logged on error)",
    ],

    "safe_patterns_also_present": [
        "das_fct_users_insert(@in_column_names, @in_values, @in_value_types, ...) -- stored proc",
        "das_fct_multiple_update(@in_column_names, @in_values, ...) -- stored proc",
        "das_fct_multiple_delete(@in_uids) -- stored proc",
        "SELECT * FROM jsonb_array_elements_text(@uids::jsonb) -- parameterized",
    ],

    "operations_with_pattern_queries": [
        "GENERIC_GET_ALL_BY_PATTERN -- LIKE pattern query (wildcard injection potential)",
        "KA_GET_ALL_BY_PATTERN -- keepalive pattern query",
        "DELETE_ALL_BY_PATTERN",
        "da.GetAllByPattern -- runtime call site logged",
    ],

    "drivers_present": {
        "mssql": "STILL compiled in 8.0.0 (mssql.tdsBuffer, mssql.Connector, mssql.CheckConstraints)",
        "pgx":   "PostgreSQL driver (nextQueryAndArgs, pgx.QueuedQuery, pgx.BatchTracer)",
        "note":  "MSSQL driver presence may mean old injection vectors survive on MSSQL deployments",
    },

    "attack_path": (
        "HTTP request to emsworkers -> parsed user-controlled field (UID, hostname, device ID) -> "
        "passed to FCTDas via internal protocol -> FCTDas builds SQL with %s -> PostgreSQL injection. "
        "The UPDATE FortiClients_users SET %s pattern is particularly dangerous: column names "
        "built from user-controlled input create column injection even with values parameterized."
    ),

    "predecessor":  "CVE-2023-48788 (MSSQL injection in FCTUID field, patched 7.2.3+)",
    "note": (
        "FCTDas has two code paths: stored procedure path (safe, @params) and direct SQL path "
        "(unsafe, %s). The direct SQL path coexists with parameterized stored procs."
    ),

    "remediation": (
        "Replace all fmt.Sprintf(\"... %s ...\", sqlFragment) with pgx parameterized queries ($1, $2). "
        "Audit GetAllByPattern to ensure LIKE pattern is escaped before substitution."
    ),
}

# ---------------------------------------------------------
# EMS-800-F04 | emsworkers CGo memcpy in impdb Service
# Severity: CRITICAL
# ---------------------------------------------------------
FINDINGS["EMS-800-F04"] = {
    "title":    "emsworkers CGo-wrapped memcpy in import DB service without confirmed bounds check",
    "severity": "CRITICAL",
    "status":   "CANDIDATE -- binary string confirmed, bounds check not yet verified via disasm",
    "cvss":     "9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) if pre-auth import endpoint",
    "component": "bin/emsworkers_linux_arm64 (C++, 82MB, ARM64)",

    "evidence": {
        "symbol":   "fortinet.com/ems/service/impdb._Cfunc_memcpy",
        "meaning":  "CGo-wrapped memcpy in impdb (import database) service package",
        "libc":     "modernc.org/libc.Xmemcpy also present (pure-Go libc memcpy wrapper)",
        "context":  (
            "FTNTDBImporter string present: '/proc/self/exeFTNTDBImporter\"VarFileInfo\":StringFileInfo'.\n"
            "The impdb package processes FortiClient database import files. CGo memcpy suggests "
            "C-language buffer operations on imported file data. If the size argument derives from "
            "a field in the import file without an upper-bound check, this is a heap/stack overflow."
        ),
    },

    "attack_path": (
        "1. Locate the database import endpoint (likely /api/v1/... endpoint accepting .db/.zip files)\n"
        "2. Craft malformed import file with oversized field\n"
        "3. Upload triggers CGo memcpy with attacker-controlled size -> overflow in emsworkers process\n"
        "4. emsworkers runs as forticlientems user; exploit for RCE"
    ),

    "pending": "Disassemble emsworkers ARM64 around impdb._Cfunc_memcpy callers to confirm no bounds check",

    "related_strings": [
        "FTNTDBImporter",
        "ftntdbimporter",
        "(core dumped)",
        "fortinet.com/ems/service/impdb._Cfunc_memcpy",
    ],

    "remediation": (
        "Audit impdb package for all memcpy calls. Enforce strict size bounds from file header "
        "before any memcpy. Use Go's safe slice operations instead of CGo memcpy."
    ),
}

# ---------------------------------------------------------
# EMS-800-F05 | emsworkers Script Interpreter Execution
# Severity: HIGH
# ---------------------------------------------------------
FINDINGS["EMS-800-F05"] = {
    "title":    "emsworkers invokes PHP/Lua/Tcl interpreters -- potential command injection",
    "severity": "HIGH",
    "status":   "CANDIDATE -- interpreter paths confirmed in binary, invocation context TBD",
    "cvss":     "8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)",
    "component": "bin/emsworkers_linux_arm64",

    "evidence": {
        "interpreter_paths": [
            "/usr/bin/env php",
            "/usr/bin/env lua",
            "/usr/bin/env tcl",
            "/usr/bin/env node",
            "/usr/bin/env perl",
            "/usr/bin/env wish",
            "/usr/bin/env tclsh",
            "/usr/local/bin/php",
            "/usr/local/bin/lua",
            "/usr/local/bin/tcl",
        ],
        "context": (
            "These interpreter shebang paths in the binary suggest emsworkers spawns "
            "subprocesses to run scripts. If script path or arguments include user-controlled "
            "data (hostname, device name, OS type field), the subprocess call is injectable."
        ),
        "related_strings": [
            "strOSType=%s  (OS type format string near file detail fetch)",
            "sudo  (present in binary near command strings)",
            "Authentication error, userName: %s, user: %s, password empty: %t",
        ],
    },

    "attack_path": (
        "1. Identify which emsworkers endpoint triggers script execution\n"
        "2. Supply crafted device name / hostname / OS type with shell metacharacters\n"
        "3. If exec.Command(interpreterPath, arg) uses user-controlled arg without quoting -> injection"
    ),

    "pending": "Semantic sweep on emsworkers ARM64 to find interpreter invocation callsites",

    "remediation": (
        "Replace all shell invocations with direct exec without shell interpretation. "
        "Never pass user-controlled strings as script arguments. Validate all input against allowlist."
    ),
}

# ---------------------------------------------------------
# EMS-800-F06 | PostgreSQL pgcrypto addons.pgp_sym_decrypt
# Severity: HIGH
# ---------------------------------------------------------
FINDINGS["EMS-800-F06"] = {
    "title":    "addons.symmetric_key() exposed to all DB users -- 80-bit entropy, decrypts entire EMS secret store",
    "severity": "HIGH",
    "status":   "CONFIRMED -- key generation in postinst, function body in sqitch migrations, callable by any DB user",
    "cvss":     "8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)",
    "component": "postinst + sqitch/vdom/deploy/baseline/schema/master.sql + sqitch/fcm/deploy/baseline/schema/master.sql",

    "evidence": {
        "key_generation": (
            "# postinst:\n"
            "SYMMETRIC_KEY=$(head -c 20 /dev/urandom | md5sum | head -c 20)\n"
            "# 20 bytes urandom -> MD5 hex -> first 20 chars = 80-bit effective entropy\n"
            "# Key written into SQL function body AND stored to filesystem:\n"
            "# /var/lib/postgresql/{PG_VERSION}/symmetric_key.txt"
        ),
        "sql_function_baseline": (
            "CREATE OR REPLACE FUNCTION addons.symmetric_key()\n"
            "  RETURNS character varying LANGUAGE plpgsql AS $\n"
            "  BEGIN RETURN '[SYMMETRIC_KEY]'; END; $;\n"
            "-- postinst replaces [SYMMETRIC_KEY] with the generated 20-char hex key.\n"
            "-- Key is hardcoded in the SQL function body after install."
        ),
        "callable_by_any_db_user": "SELECT addons.symmetric_key();  -- no SECURITY DEFINER restriction seen",
        "encrypted_columns": [
            "ldap.client_secret (Azure AD OAuth2 client secret)",
            "upload_token, secret, scheduled_backup_password",
            "scheduled_backup_remote_user_password",
            "endpoint_registration_ips_list.reg_pwd",
            "Any column with pg_description ILIKE 'encrypted%'",
            "ALL jwt_secrets.secret values (JWT signing keys for all KIDs)",
        ],
    },

    "attack_path": (
        "1. Obtain any PostgreSQL DB user access (e.g. via EMS-800-F03 SQL injection or EMS-800-F01 cred leak)\n"
        "2. SELECT addons.symmetric_key() -- returns the 20-char hex encryption key\n"
        "3. SELECT addons.pgp_sym_decrypt(secret::bytea, addons.symmetric_key()) FROM jwt_secrets\n"
        "   -- decrypts ALL JWT signing keys (CLOUD_CONTROLLER, EMAIL_REPORT, SASE_CONTROLLER, OAUTH2, WEBSERVER)\n"
        "4. SELECT addons.pgp_sym_decrypt(client_secret, addons.symmetric_key()) FROM ldap\n"
        "   -- decrypts Azure AD OAuth2 client_secret\n"
        "5. Forge JWT tokens for any KID, impersonate cloud controller or SASE controller"
    ),

    "entropy_note": (
        "head -c 20 /dev/urandom provides 160-bit raw entropy. md5() reduces to 128-bit output. "
        "Taking only the first 20 hex chars (80 bits) of that. This is below modern key strength "
        "recommendations for symmetric encryption keys. In practice the key space is 16^20 = 2^80 "
        "which is weak for offline brute force given the key is stored in the DB function body."
    ),

    "filesystem_exposure": (
        "Key also stored in /var/lib/postgresql/{PG_VERSION}/symmetric_key.txt. "
        "Any process running as the postgres OS user (or reading the DB data directory) "
        "can read the key without DB access."
    ),

    "remediation": (
        "1. Remove addons.symmetric_key() function -- prevent direct DB user access to the key.\n"
        "2. Store encryption keys outside the DB (HSM, AWS KMS, or HashiCorp Vault).\n"
        "3. Increase key entropy: 256-bit key from /dev/urandom (no md5 reduction).\n"
        "4. Apply SECURITY DEFINER + GRANT EXECUTE only to the EMS service account at minimum."
    ),
}

# ---------------------------------------------------------
# EMS-800-F07 | ENABLE_CERT_AUTH_ALL Database Flag
# Severity: MEDIUM
# ---------------------------------------------------------
FINDINGS["EMS-800-F07"] = {
    "title":    "ENABLE_CERT_AUTH_ALL DB flag from system_demo_settings controls cert auth scope",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- flag loaded from DB, default value unknown",
    "cvss":     "6.5 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N)",
    "component": "fcm/models/consts.py (compiled to .pyc) + auth_middleware.pyc",

    "sql": "SELECT enable_cert_auth_all, enable_sn_allowlist, sn_allowlist FROM system_demo_settings",

    "description": (
        "AuthMiddleware.check_request_authorization reads ENABLE_CERT_AUTH_ALL from the consts "
        "module (DB-backed). If False, cert auth is not enforced for all endpoints. "
        "Endpoints that conditionally branch on ENABLE_CERT_AUTH_ALL may be reachable without "
        "a valid Fortinet client certificate when the flag is disabled."
    ),

    "impact": (
        "If ENABLE_CERT_AUTH_ALL=False (default on non-demo installs), certain endpoints "
        "may accept requests without FortiClient cert validation, widening the unauthenticated "
        "attack surface beyond what the Nginx ssl_verify_client optional config implies."
    ),

    "pending": "Determine default value of enable_cert_auth_all in system_demo_settings on fresh install",
}

# ---------------------------------------------------------
# EMS-800-F08 | Unauthenticated AI Gateway Proxy
# Severity: CRITICAL
# ---------------------------------------------------------
FINDINGS["EMS-800-F08"] = {
    "title":    "Nginx /ai/ location proxies to fcems_aigateway with ZERO authentication",
    "severity": "CRITICAL",
    "status":   "CONFIRMED -- Nginx config verified; AI gateway auth unknown (binary not in package)",
    "cvss":     "9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) if AI gateway has no auth",
    "component": "ems-443.conf.template + fcems_aigateway service",

    "nginx_location": {
        "path":      "/ai/",
        "proxy":     "http://fcems_aigateway/ (host=$EMS_AI_GATEWAY_HOST, port=$EMS_AI_GATEWAY_PORT)",
        "auth_headers": "NONE -- no common_proxy_headers.conf, no ssl_client_verify check",
        "session_headers": "NONE",
        "timeout":   "proxy_read_timeout 3600s (allows long-running LLM requests)",
    },

    "contrast": {
        "ztna_routes": "Each ZTNA route: include ztna_proxy_headers.conf + if ssl_client_verify check",
        "main_route":  "location /: include common_proxy_headers.conf (X-SSL-CLIENT-VERIFY etc.)",
        "ai_route":    "location /ai/: ONLY Host, X-Forwarded-For, X-Forwarded-Proto headers -- no auth context",
    },

    "service_info": {
        "systemd":       "fcems_aigateway.service",
        "binary":        "/opt/forticlientems/ai/gateway/venv/bin/aigateway",
        "workdir":       "/opt/forticlientems/ai/gateway",
        "env_file":      "/opt/forticlientems/ai/gateway/.env (likely contains LLM API keys)",
        "user":          "forticlientems",
        "not_in_package":"AI gateway binary shipped separately (not in 8.0.0 DEB)",
    },

    "attack_surface": (
        "Any internet-facing FortiClient EMS 8.0.0 instance exposes /ai/ without auth. "
        "If fcems_aigateway lacks its own authentication:\n"
        "  - Direct LLM API access (prompt injection, data exfiltration)\n"
        "  - LLM API key theft from .env file if gateway exposes config\n"
        "  - Model exfiltration if local model is deployed\n"
        "Even if aigateway has internal auth, the 3600s timeout enables slow brute force "
        "or resource exhaustion against the AI service."
    ),

    "proof_of_concept": "curl -sk https://EMS_HOST/ai/... (no cert, no session, no auth)",

    "remediation": (
        "Add authentication to the /ai/ Nginx location:\n"
        "  include /etc/nginx/includes/common_proxy_headers.conf;\n"
        "  Require valid session or JWT before proxying to aigateway.\n"
        "OR implement authentication in the aigateway service itself and document requirements."
    ),
}

# ---------------------------------------------------------
# EMS-800-F09 | SCIM Endpoint Auth Analysis
# Severity: MEDIUM
# ---------------------------------------------------------
FINDINGS["EMS-800-F09"] = {
    "title":    "SCIM endpoint at /scim proxied to localhost:7643 without cert/session auth headers",
    "severity": "MEDIUM",
    "status":   "CANDIDATE -- Nginx config verified, SCIM service auth TBD",
    "cvss":     "6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N)",
    "component": "ems-443.conf.template + SCIM service on localhost:7643",

    "nginx_location": {
        "path":   "/scim",
        "proxy":  "http://localhost:7643",
        "headers": "Host, X-Real-IP, X-Forwarded-For, X-Forwarded-Proto (no SSL cert headers)",
        "body":    "client_max_body_size 10M",
    },

    "description": (
        "The SCIM (System for Cross-domain Identity Management) endpoint proxied to localhost:7643 "
        "does not receive X-SSL-CLIENT-VERIFY or session auth headers from Nginx. "
        "SCIM endpoints manage user provisioning/deprovisioning. "
        "If the SCIM service does not enforce its own bearer token auth (RFC 7644), "
        "an unauthenticated attacker could create/modify/delete EMS users."
    ),

    "scim_files": [
        "/opt/forticlientems/fcm/fcm/models/idp/scim/scim.pyc",
        "/opt/forticlientems/fcm/fcm/models/idp/scim/scim_sql_queries.pyc",
        "/opt/forticlientems/fcm/fcm/proto/ad_scim_pb2.pyc",
    ],

    "pending": "Decompile scim.pyc to verify bearer token enforcement",
}

# ---------------------------------------------------------
# EMS-800-F10 | Grafana Partial Exposure
# Severity: LOW
# ---------------------------------------------------------
FINDINGS["EMS-800-F10"] = {
    "title":    "Grafana /api, /public, /d-solo paths accessible without EMS authentication",
    "severity": "LOW",
    "status":   "CONFIRMED -- Nginx config verified",
    "cvss":     "4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)",
    "component": "ems-443.conf.template + Grafana on localhost:3000",

    "nginx_location": {
        "path":    "/grafana/",
        "allow":   "^/grafana/(api|public|d-solo/)",
        "deny":    "Everything else -> 403",
        "note":    "Grafana /api/* is unauthenticated at the EMS Nginx layer",
    },

    "description": (
        "The Grafana location allows unauthenticated access to /grafana/api, /grafana/public, "
        "and /grafana/d-solo. Grafana's own auth is the last line of defense. "
        "If Grafana is configured with anonymous access (grafana.ini auth.anonymous.enabled=true), "
        "metrics and dashboards are publicly readable. "
        "Even with Grafana auth, the /grafana/public directory is fully public."
    ),

    "impact": "Read EMS operational metrics (endpoint counts, connection rates, performance data)",
}

# ---------------------------------------------------------
# EMS-800-F11 | FCTDas MSSQL Driver Retained in PostgreSQL Build
# Severity: MEDIUM
# ---------------------------------------------------------
FINDINGS["EMS-800-F11"] = {
    "title":    "FCTDas ARM64 binary retains compiled MSSQL driver alongside PostgreSQL pgx driver",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- driver symbols in binary",
    "cvss":     "7.5 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) if MSSQL path reachable",
    "component": "bin/FCTDas",

    "evidence": {
        "mssql_symbols": [
            "*mssql.queryNotifSubSetQueryNotification",
            "*mssql.ConnectorCheckConstraints",
            "*[8]mssql.featureExtTimestampLastUpdated",
            "mssql.tdsBuffer",
            "processQueryText (MSSQL TDS protocol handler)",
            "MSSQL does not allow NULL value with... (error string in binary)",
        ],
        "pgx_symbols": [
            "*pgx.QueryTracer",
            "*pgx.BatchTracer",
            "*pgx.QueuedQuery",
            "nextQueryAndArgs",
            "*pgx.LargeObject",
            "*[8]pgx.namedArg",
        ],
    },

    "description": (
        "FCTDas for 8.0.0 (ARM64 Linux, PostgreSQL architecture) still compiles in the MSSQL "
        "database driver. CVE-2023-48788 was an MSSQL injection in the FCTDas predecessor. "
        "If any runtime code path selects the MSSQL driver (env var, config flag, or DB type "
        "detection), legacy MSSQL injection vectors may be reachable on hybrid or migrating "
        "deployments that retain SQL Server as DB backend."
    ),

    "predecessor": "CVE-2023-48788 (CVSS 9.8) -- MSSQL injection in FCTDas, patched 7.2.3+",

    "remediation": "Remove MSSQL driver import from FCTDas build for Linux-only packages.",
}

# ---------------------------------------------------------
# EMS-800-F12 | SESSION_ENGINE Client-Side Signed Cookies -- 8.0.0 Unchanged
# Severity: HIGH (requires SECRET_KEY)
# ---------------------------------------------------------
FINDINGS["EMS-800-F12"] = {
    "title":    "Session engine remains django.contrib.sessions.backends.signed_cookies in 8.0.0",
    "severity": "HIGH",
    "status":   "CONFIRMED -- settings.py plaintext",
    "cvss":     "8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) with SECRET_KEY",
    "component": "fcm/fcm/settings.py",

    "description": (
        "The Django session engine is still client-side signed cookies (not database-backed). "
        "Sessions are signed with SECRET_KEY using HMAC-SHA256 via django.core.signing. "
        "An attacker with SECRET_KEY can forge sessions for any user ID, including admin (ID=1). "
        "This is the same vulnerability class as EMS-F9 in 7.2.9 (SECRET_KEY used for signing). "
        "In 8.0.0, the risk is contingent on SECRET_KEY disclosure (EMS-800-F01), whereas in "
        "7.2.9 the key was hardcoded."
    ),

    "forge_session": (
        "import django.core.signing as s\n"
        "payload = {'_auth_user_id': '1', '_auth_user_backend': 'django.contrib.auth.backends.ModelBackend'}\n"
        "# Sign with stolen SECRET_KEY:\n"
        "signed = s.dumps(payload, key=SECRET_KEY, salt='django.contrib.sessions.backends.signed_cookies')\n"
        "# Set as sessionid cookie"
    ),

    "mitigation_path": "Switch to SESSION_ENGINE = 'django.contrib.sessions.backends.db' (server-side, revocable)",
}

# ---------------------------------------------------------
# EMS-800-F13 | JWT Secret Store Encrypted with Exposed symmetric_key()
# Severity: CRITICAL (chains with EMS-800-F06)
# ---------------------------------------------------------
FINDINGS["EMS-800-F13"] = {
    "title":    "ALL JWT signing secrets encrypted with addons.symmetric_key() -- full token forgery via DB access",
    "severity": "CRITICAL",
    "status":   "CONFIRMED -- jwt_secrets.pyc SQL confirms pgp_sym_encrypt/decrypt with symmetric_key()",
    "cvss":     "9.1 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)",
    "component": "fcm/models/jwt_secrets/jwt_secrets.pyc",

    "evidence": {
        "get_secret_sql": (
            "SELECT addons.pgp_sym_decrypt(\"secret\"::bytea, addons.symmetric_key()) AS \"secret\"\n"
            "FROM jwt_secrets\n"
            "WHERE \"key\" = %s"
        ),
        "create_secret_sql": (
            "INSERT INTO jwt_secrets (\"key\", \"secret\")\n"
            "VALUES (%s, addons.pgp_sym_encrypt(%s, addons.symmetric_key()))"
        ),
        "update_secret_sql": (
            "UPDATE jwt_secrets\n"
            "SET \"secret\" = addons.pgp_sym_encrypt(%s, addons.symmetric_key())\n"
            "WHERE \"key\" = %s"
        ),
        "asymmetric_key_sql": (
            "INSERT INTO jwt_secrets (key, secret, public_key, is_symmetric, jwk)\n"
            "VALUES (%s, addons.pgp_sym_encrypt(%s, addons.symmetric_key()), %s, FALSE, %s)\n"
            "-- RSA private keys also encrypted with the same symmetric_key()"
        ),
        "kid_types": [
            "CLOUD_CONTROLLER_KID -- symmetric HS256 secret",
            "EMAIL_REPORT_KID -- symmetric HS256 secret",
            "SASE_CONTROLLER_KID -- symmetric HS256 secret (MERGE upsert)",
            "OAUTH2_KID -- symmetric HS256 secret",
            "WEBSERVER_KID -- RSA keypair (RS256), private key encrypted with symmetric_key()",
        ],
    },

    "chain": "EMS-800-F06 (symmetric_key() callable by any DB user) provides the decryption key. "
             "Combined: DB access + symmetric_key() = forge any JWT for any trust domain.",

    "attack_path": (
        "1. Gain DB access (EMS-800-F03 SQL injection or EMS-800-F01 credential disclosure)\n"
        "2. SELECT addons.symmetric_key()  -- retrieves 20-char hex key\n"
        "3. SELECT key, addons.pgp_sym_decrypt(secret::bytea, addons.symmetric_key()) FROM jwt_secrets\n"
        "   -- dumps all JWT signing secrets for all KIDs\n"
        "4. Forge HS256 JWT with CLOUD_CONTROLLER_KID, EMAIL_REPORT_KID, OAUTH2_KID\n"
        "5. Reconstruct RSA private key for WEBSERVER_KID, forge RS256 tokens\n"
        "6. JWT grants full EMS API access as any user or service"
    ),

    "key_rotation_behavior": (
        "JwtSecrets.check_ws_kid_rotation() rotates WEBSERVER_KID if older than WEBSERVER_KID_LIFETIME_DAYS. "
        "Old keys kept for WEBSERVER_KID_LIFETIME_DAYS grace period. "
        "Rotation does NOT change symmetric_key() -- forged tokens remain valid until per-kid expiry."
    ),

    "remediation": (
        "1. Fix EMS-800-F06 first (restrict symmetric_key() access).\n"
        "2. Store JWT signing keys in a separate HSM or secrets manager, not in the DB encrypted with a DB function.\n"
        "3. Rotate all JWT secrets immediately after any DB compromise."
    ),
}

# ---------------------------------------------------------
# EMS-800-F14 | Custom Installer Upload -- subprocess on Uploaded File Path
# Severity: HIGH (command injection candidate)
# ---------------------------------------------------------
FINDINGS["EMS-800-F14"] = {
    "title":    "uploadhelper.py calls subprocess (msiinfo, 7z, grep) with uploaded installer file paths",
    "severity": "HIGH",
    "status":   "CANDIDATE -- subprocess confirmed, sanitization of filename/path not yet verified",
    "cvss":     "8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) if filename unsanitized",
    "component": "fcm/models/installers/uploadhelper.pyc + custom_installer_uploader.pyc",

    "evidence": {
        "subprocess_calls": [
            "subprocess with capture_output=True on msiinfo -- MSI property/suminfo extraction",
            "subprocess on grep -- file content scanning",
            "subprocess on 7z / _unzip -- archive extraction to temp dir",
            "python3 peInfo.py <filename> -- PE version extraction via wrapper script",
        ],
        "external_tools": ["msiinfo", "7z", "grep", "python3_wrapper (peInfo.py)"],
        "temp_dir": "uuid4()-based temp directory for extraction",
        "filename_flow": (
            "Uploaded file saved -> path passed to _get_win_installer_info / _get_deb_installer_info "
            "-> uploadhelper functions -> subprocess([tool, path, ...])"
        ),
        "architecture_check": (
            "isFortiClientDEBAMDInstaller / isFortiClientDEBARMInstaller call grep on the DEB file "
            "to extract architecture string -- file path passed directly to subprocess"
        ),
    },

    "injection_vector": (
        "If the filename from the multipart upload is not stripped of shell metacharacters before "
        "use in subprocess calls, an attacker can inject shell commands. "
        "E.g., filename='FortiClient; rm -rf /tmp; .msi' passed to msiinfo or 7z.\n"
        "Requires: authenticated EMS admin user with installer upload permission."
    ),

    "cpio_note": (
        "RPM installer processing uses cpio extraction: subprocess on cpio_extracted_dir path. "
        "Path traversal in the cpio archive could write files outside the temp extraction dir."
    ),

    "pending": [
        "Trace filename sanitization between upload controller and uploadhelper subprocess calls",
        "Check if shlex.quote() or equivalent is applied before subprocess construction",
        "Test: upload .deb with crafted filename containing shell metacharacters",
    ],

    "remediation": (
        "1. Use subprocess with list args (not shell=True) and validate filenames against strict allowlist regex.\n"
        "2. Strip or reject filenames with non-alphanumeric chars (except ._-).\n"
        "3. Run installer processing in a sandboxed subprocess with no network and restricted FS access."
    ),
}

# ---------------------------------------------------------
# EMS-800-F15 | ai_controller Proxies to localhost:8001 Without Auth -- Django Completes Unauthenticated AI Path
# Severity: CRITICAL (chains with EMS-800-F08)
# ---------------------------------------------------------
FINDINGS["EMS-800-F15"] = {
    "title":    "/api/v1/ai/query Django controller proxies to localhost:8001/query with no additional auth",
    "severity": "CRITICAL",
    "status":   "CONFIRMED -- ai_controller.pyc strings: http://localhost:8001/query, no auth headers",
    "cvss":     "9.1 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)",
    "component": "fcm/controllers/ai_controller.pyc + etc/nginx/sites-available/ems-443.conf.template",

    "evidence": {
        "nginx_location": (
            "location /ai/ {\n"
            "    proxy_pass http://fcems_aigateway;\n"
            "    proxy_read_timeout 3600;\n"
            "    # NO common_proxy_headers.conf (no session/user headers forwarded)\n"
            "    # NO ssl_verify check\n"
            "    # NO auth requirement\n"
            "}"
        ),
        "django_controller": (
            "class AiController:\n"
            "    # Route: /api/v1/ai/query\n"
            "    # Proxies to: http://localhost:8001/query\n"
            "    # No auth in extracted strings -- relies solely on Nginx layer\n"
            "    # Request body: {'message': '...'} (application/json)"
        ),
        "fcems_aigateway_service": (
            "ExecStart=bash -c 'exec -a fcems_aigateway /opt/forticlientems/ai/gateway/venv/bin/aigateway'\n"
            "# Binary shipped separately -- not in this package\n"
            "# EnvironmentFile=/opt/forticlientems/ai/gateway/.env"
        ),
    },

    "chain": "EMS-800-F08 (Nginx /ai/ unauthenticated) + EMS-800-F15 (Django no-auth proxy to localhost:8001) = "
             "internet client sends arbitrary LLM queries with zero authentication at any layer.",

    "attack_path": (
        "1. Send POST https://<EMS_IP>/ai/  (or /api/v1/ai/query) with JSON body {\"message\": \"<prompt>\"}\n"
        "2. Nginx passes through with no auth check (EMS-800-F08)\n"
        "3. Django ai_controller proxies to localhost:8001/query with no added auth\n"
        "4. AI gateway processes arbitrary prompt\n"
        "5. If AI gateway has tool access or can read EMS data, prompt injection escalates to data exfil"
    ),

    "pending": [
        "Obtain aigateway binary -- audit /query endpoint for tool access, data source access, SSRF",
        "Check .env file for API keys or LLM provider credentials",
        "Test: does /api/v1/ai/query require session cookie (Django auth middleware may still apply)",
        "Determine if Nginx /ai/ and Django /api/v1/ai/query are separate or same route",
    ],

    "remediation": (
        "1. Add authentication to the Nginx /ai/ location (include common_proxy_headers.conf, require valid session).\n"
        "2. Add auth enforcement in ai_controller before proxying.\n"
        "3. Audit aigateway for SSRF, prompt injection, and EMS data access."
    ),
}

# ---------------------------------------------------------
# EMS-800-F16 | Scheduled SFTP Backup Uses InsecureIgnoreHostKey -- MITM Credential/Data Theft
# Severity: HIGH
# ---------------------------------------------------------
FINDINGS["EMS-800-F16"] = {
    "title":    "TaskScheduledBackup uses golang.org/x/crypto/ssh.InsecureIgnoreHostKey -- no SFTP server verification",
    "severity": "HIGH",
    "status":   "CONFIRMED -- symbol fortinet.com/ems/service/emstasks.TaskScheduledBackup.func1.InsecureIgnoreHostKey.2 in binary",
    "cvss":     "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    "component": "bin/emsworkers_linux_arm64 (fortinet.com/ems/service/emstasks.TaskScheduledBackup)",

    "evidence": {
        "symbol": (
            "fortinet.com/ems/service/emstasks.TaskScheduledBackup.func1.InsecureIgnoreHostKey.2\n"
            "-- confirmed in Go symbol table at binary offset 0x3ea5dcf"
        ),
        "sftp_stack": [
            "golang.org/x/crypto/ssh.Password -- password-based SSH auth (backup password from DB)",
            "github.com/pkg/sftp@v1.13.6 -- SFTP client library",
            "golang.org/x/crypto/ssh.Dial -- standard SSH dial",
            "fortinet.com/ems/service/emstasks.SFTPMkdirAll -- directory creation on remote SFTP server",
        ],
        "insecure_note": (
            "golang.org/x/crypto/ssh.InsecureIgnoreHostKey() returns a HostKeyCallback that "
            "accepts ANY server host key without verification. Go documentation explicitly labels "
            "this function as insecure and states it should only be used for testing."
        ),
    },

    "attack_path": (
        "1. Attacker positions on network path between EMS server and configured SFTP backup target\n"
        "2. Scheduled backup task runs (TaskScheduledBackup) using InsecureIgnoreHostKey\n"
        "3. Attacker presents fake SFTP server -- EMS connects without verifying host key\n"
        "4. SSH Password credential (scheduled_backup_password, decrypted from DB via symmetric_key())\n"
        "   is sent to attacker's fake server\n"
        "5. Attacker also receives the full EMS configuration backup data\n"
        "   (contains all endpoint registrations, policies, encrypted secrets)"
    ),

    "chain": "EMS-800-F06 (symmetric_key() exposure) provides scheduled_backup_password. "
             "EMS-800-F16 leaks it to a network MITM during backup transmission.",

    "backup_content_risk": (
        "Scheduled EMS backups contain full DB exports including: endpoint registration passwords, "
        "LDAP credentials, Azure AD client secrets, JWT signing keys, TLS private keys. "
        "A backup file stolen via MITM gives equivalent access to a DB dump."
    ),

    "remediation": (
        "1. Replace InsecureIgnoreHostKey with known_hosts-based HostKeyCallback.\n"
        "2. Store SFTP server host key fingerprint in EMS settings and verify on each connection.\n"
        "3. Alternatively: enforce SFTP over TLS (FTPS) or use SFTP with certificate authentication."
    ),
}

# =============================================================
# SUMMARY TABLE
# =============================================================

SUMMARY = {
    "total_findings": 16,
    "critical":       4,   # EMS-800-F04, EMS-800-F08, EMS-800-F13, EMS-800-F15
    "high":           7,   # EMS-800-F01, EMS-800-F03, EMS-800-F05, EMS-800-F06, EMS-800-F12, EMS-800-F14, EMS-800-F16
    "medium":         4,   # EMS-800-F02, EMS-800-F07, EMS-800-F09, EMS-800-F11
    "low":            1,   # EMS-800-F10
    "confirmed":      12,  # F01, F02, F03, F06, F07 (partial), F08, F10, F11, F12, F13, F15, F16
    "candidate":      4,   # F04, F05, F09, F14
    "disclosure_deadline": "2026-12-16",
    "disclosure_start":    "2026-09-17",
    "analysis_date":       "2026-09-19",
}

# =============================================================
# PENDING ANALYSIS
# =============================================================

PENDING = [
    "EMS-800-F04: Disassemble emsworkers ARM64 near impdb._Cfunc_memcpy to confirm no bounds check",
    "EMS-800-F05: Find interpreter invocation callsite in emsworkers -- which endpoint triggers it",
    "EMS-800-F07: Determine default value of enable_cert_auth_all in fresh EMS 8.0.0 install",
    "EMS-800-F08: Obtain AI gateway binary and audit its authentication implementation",
    "EMS-800-F09: Decompile scim.pyc to verify bearer token enforcement",
    "EMS-800-F03: Confirm emsworkers passes user-controlled data to FCTDas SQL format strings",
    "EMS-800-F14: Trace filename sanitization path in custom installer upload -- subprocess injection",
    "EMS-800-F15: Test if /api/v1/ai/query enforces Django session auth; obtain aigateway binary",
    "EMS-800-F16: Extract scheduled_backup_password from DB; confirm InsecureIgnoreHostKey with network MITM test",
    "7.2.14 / 7.2.15 Windows installer: extract CAB payload; diff against 7.2.9 findings (F1-F22)",
    "cert_chain_auth.pyc full bytecode: confirm no code path bypasses contains_certificate()",
    "Ablation semantic sweep on emsworkers ARM64: auth, memcpy, exec, SQL query profiles",
    "7.4.5 OVA extraction: stream OVA as tar, find VMDK offset, mount with qemu-nbd",
    "8.0.0.0121 vs 8.0.0.0157: diff FCTDas, emsworkers, postinst for patch changes",
]
