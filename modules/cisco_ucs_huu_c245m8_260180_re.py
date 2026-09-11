"""
Cisco UCS HUU C245 M8 6.0.2.260180 Delta RE Module
ISO: ucs-c245m8-huu-6.0.2.260180.iso
Platform: Cisco UCS C245 M8 (CIMC 6.0(2.260096), BIOS C245M8.6.0.2c, HSU 6.0.2.260180)
Focus: Redfish stack (nginx/Gunicorn) -- hsu.tgz.enc decrypted with known key zfguijkophju@*%1]

6 findings: 1C/2H/2M/1L
Cumulative: 600 [55C+192H+182M+171L]
"""

# ============================================================
# TARGET
# ============================================================

TARGET = {
    "iso": "ucs-c245m8-huu-6.0.2.260180.iso",
    "cimc": "6.0(2.260096)",
    "bios": "C245M8.6.0.2c.0.0527260120",
    "hsu_version": "6.0.2.260180",
    "container_squashfs_built": "2026-08-11 15:46:14",
    "rootfs_img_built": "2018-03-09 06:34:56",
    "hsu_tgz_enc": "/root/hsu.tgz.enc (31MB, built 2026-08-11)",
    "decrypt_key": "zfguijkophju@*%1] (same key as all prior C245/C220/XE130C M8 HUU versions)",
    "redfish_stack": "nginx/Gunicorn (Flask), HTTP only",
    "gunicorn_bind": "127.0.0.1:8000",
    "nginx_bind": "0.0.0.0:80",
}

# ============================================================
# REDFISH STACK ARCHITECTURE
# ============================================================

NGINX_TEMPLATE = {
    "source_path": "/root/hsu/nginx.conf (inside hsu.tgz.enc)",
    "runtime_path": "/root/hsu/logs/huu-nginx.conf (generated at startup by init-huu.sh)",
    "user_directive": "user root;",
    "listen": "<NGINX_IP>:<NGINX_PORT> default_server (default: 0.0.0.0:80)",
    "tls_status": "FULLY COMMENTED OUT -- port 443 server block present but all lines prefixed #",
    "access_log": "access_log off;",
    "proxy_rules": {
        "/redfish|/huu|/sdu|/scu": "proxy_pass http://<GUNICORN_IP>:<GUNICORN_PORT>",
        "/uilog": "proxy_pass http://<GUNICORN_IP>:<GUNICORN_LOGGER_PORT>",
        "/hsu/*": "rewrite hsu/(.*)$ /$1 then re-proxy to nginx itself",
    },
    "no_auth": True,
    "start_mechanism": "init-huu.sh start_nginx() -- sed-substitutes template vars, runs nginx -c logs/huu-nginx.conf",
}

GUNICORN_APP = {
    "wsgi": "hsu_wsgi.py -> app.py (Flask)",
    "bind": "127.0.0.1:8000",
    "workers": 1,
    "timeout_seconds": 940,
    "blueprints": ["RedfishApp", "HuuApp", "InventoryApp (conditional)", "ConfigApp (conditional)", "SduApp (conditional)"],
    "auth_middleware": None,
    "before_request_hooks": None,
    "auth_imports": "none (no flask_login, flask_httpauth, HTTPBasicAuth in any app file)",
    "health_check": "wget -q -O - 127.0.0.1:8000/redfish/v1 (no credentials -- confirms /redfish/v1 is unauth)",
}

REDFISH_ENDPOINTS = {
    "GET /redfish/v1/Oem/GetBmcToHostScpCredentials": {
        "class": "UCSBmcToHostScpCredentials",
        "auth": None,
        "action": "reads /tmp/huu.cred; returns {Username, Password} as JSON 200",
        "credential_source": "/tmp/huu.cred (created by init.sh create_user())",
    },
    "POST /redfish/v1/Systems/<serial>/Actions/ComputerSystem.Reset": {
        "class": "Reset",
        "auth": "serial number path param match only",
        "reset_types": "GracefulRestart, ForceRestart, ForceOff, GracefulShutdown, On",
    },
    "POST /redfish/v1/Systems/<serial>/Actions/Oem/ComputerSystem.MountISO": {
        "class": "MountISO",
        "auth": "serial number path param match only",
        "action": "mounts virtual media ISO via async task",
    },
    "POST /redfish/v1/Systems/<serial>/Actions/Oem/ComputerSystem.EnableBackend": {
        "class": "EnableBackend",
        "auth": "serial number path param match only",
        "action": "enables HUU backend for spin/letter builds",
    },
    "GET /redfish/v1/Oem/TaskSummary": {"auth": None},
    "GET /redfish/v1/Oem/LastTaskSummary": {"auth": None},
    "GET /redfish/v1/Oem/LaunchMode": {"auth": None},
    "GET /redfish/v1/Oem/NIStatus": {"auth": None},
    "GET /redfish/v1/Oem/SystemEventLogs": {"auth": None},
    "POST /redfish/v1/Systems/<serial>/Actions/Oem/ComputerSystem.TechSupport": {
        "auth": "serial number path param match only",
        "action": "generates and returns tech support bundle as file download",
    },
}

HUU_CRED_GENERATION = {
    "function": "create_user() in /initramfs/etc/init.sh",
    "username": "huu_user",
    "password_cmd": "date +%s%N | md5sum | cut -c1-12",
    "password_format": "first 12 hex chars of MD5(nanosecond Unix timestamp at user creation time)",
    "storage": "/tmp/huu.cred as 'huu_user:PASSWORD' plaintext",
    "purpose": "BMC-to-host SCP operations; also used for telnet login to HUU chroot",
    "exposure_path": "GET /redfish/v1/Oem/GetBmcToHostScpCredentials (no auth)",
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "HCMD-F1",
        "severity": "CRITICAL",
        "title": "UNAUTH_REDFISH_OEM_ENDPOINT_EXPOSES_HUU_USER_CREDENTIALS_IN_PLAINTEXT",
        "detail": (
            "GET /redfish/v1/Oem/GetBmcToHostScpCredentials (RedfishApp.py:281-303) "
            "returns the HUU user credentials from /tmp/huu.cred as a 200 JSON response "
            "with no authentication: {Username: 'huu_user', Password: '<12-char-md5>'}. "
            "No auth in nginx (no auth_basic, no proxy auth header injection). "
            "No auth in Flask (no before_request hook, no @requires_auth, no flask_login, "
            "no flask_httpauth import anywhere in any .py file in the HSU app). "
            "The credential file /tmp/huu.cred is created by init.sh create_user() at HUU startup: "
            "USERNAME=huu_user; PASSWORD=$(date +%s%N | md5sum | cut -c1-12). "
            "huu_user is created in the HUU chroot (useradd + chpasswd) and used by the BMC "
            "for SCP file transfer to/from the HUU host environment. "
            "Transport is HTTP only (TLS commented out -- see HCMD-F3); "
            "credentials are exposed both unauthenticated AND in cleartext on the wire. "
            "Confirmed: health check in start_gunicorn() -- "
            "'wget -q -O - 127.0.0.1:8000/redfish/v1' with no credentials -- returns 200, "
            "confirming the Redfish root is also accessible without authentication."
        ),
    },
    {
        "id": "HCMD-F2",
        "severity": "HIGH",
        "title": "NGINX_REDFISH_PROXY_PROCESSES_RUN_AS_ROOT",
        "detail": (
            "The nginx template shipped inside hsu.tgz.enc (decryptable with hardcoded key) "
            "has 'user root;' as the worker process directive. "
            "init-huu.sh start_nginx() copies this template to logs/huu-nginx.conf, "
            "substitutes placeholder values (<WORKBASE>, <NGINX_IP>, etc.), and starts nginx with: "
            "'nginx -c ${LOGS_DIR}/huu-nginx.conf'. "
            "All nginx worker processes that proxy the Redfish API run as root. "
            "The system nginx.conf (in /etc/nginx/nginx.conf) has 'user www;' but is NOT used "
            "at runtime -- only the template-generated config is loaded. "
            "Any nginx-layer vulnerability (buffer overflow, request smuggling, "
            "log injection to file nginx writes) executes as root."
        ),
    },
    {
        "id": "HCMD-F3",
        "severity": "HIGH",
        "title": "HUU_REDFISH_STACK_HTTP_ONLY_TLS_ENTIRELY_COMMENTED_OUT",
        "detail": (
            "The nginx template has a TLS server block (port 443, ssl http2) that is entirely "
            "commented out. Every line in the block is prefixed with '#'. "
            "The active server block listens only on <NGINX_IP>:<NGINX_PORT> (default 0.0.0.0:80). "
            "No ssl_certificate or ssl_certificate_key directive is active. "
            "All Redfish API traffic -- including /redfish/v1/Oem/GetBmcToHostScpCredentials "
            "responses, firmware update task commands, host reset commands, "
            "system inventory reads, and tech support bundle downloads -- "
            "travels over HTTP in cleartext. "
            "A network-adjacent attacker on the CIMC/IPMI management VLAN can intercept "
            "all HUU API traffic with a passive capture."
        ),
    },
    {
        "id": "HCMD-F4",
        "severity": "MEDIUM",
        "title": "REDFISH_HOST_RESET_ISO_MOUNT_ENABLE_BACKEND_REQUIRE_ONLY_SERIAL_NUMBER",
        "detail": (
            "Three operational endpoints require only a valid serial number in the URL path, "
            "with no authentication token or session: "
            "POST /redfish/v1/Systems/<serial>/Actions/ComputerSystem.Reset "
            "(host power control: GracefulRestart/ForceRestart/ForceOff/GracefulShutdown/On), "
            "POST /redfish/v1/Systems/<serial>/Actions/Oem/ComputerSystem.MountISO "
            "(virtual media ISO mount via async task), "
            "POST /redfish/v1/Systems/<serial>/Actions/Oem/ComputerSystem.EnableBackend "
            "(enables HUU backend for spin/letter firmware builds). "
            "Each handler's only validation: "
            "'if redfish_api.server_prop[Serial Number] != system_id.strip(): return 400'. "
            "The server serial number is readable from IPMI FRU without credentials "
            "('ipmitool fru' returns board/chassis serial) and from CIMC XML API. "
            "A network-adjacent attacker who knows the server serial number can "
            "reset the host, mount a custom ISO image, or enable the firmware update backend "
            "without any credentials."
        ),
    },
    {
        "id": "HCMD-F5",
        "severity": "MEDIUM",
        "title": "NGINX_HTTP_ACCESS_LOGGING_DISABLED_BY_DEFAULT_IN_PRODUCTION_TEMPLATE",
        "detail": (
            "The production nginx template has 'access_log off;' in the http{} block. "
            "A commented-out line says: "
            "'# Uncomment this below line to get http request logs.' "
            "No HTTP request audit trail exists for any Redfish API activity when nginx starts "
            "with the default template. Gunicorn werkzeug logging is enabled at DEBUG level "
            "(app.py: logging.getLogger('werkzeug').setLevel(logging.DEBUG)) but this is "
            "written to HUU's internal log files, not a standard syslog or SIEM-accessible path. "
            "Result: no accessible record of Redfish API calls, including credential harvest "
            "via HCMD-F1 or unauthenticated host reset via HCMD-F4."
        ),
    },
    {
        "id": "HCMD-F6",
        "severity": "LOW",
        "title": "HUU_USER_PASSWORD_DERIVED_FROM_NANOSECOND_TIMESTAMP_MD5_PREFIX",
        "detail": (
            "init.sh create_user(): PASSWORD=$(date +%s%N | md5sum | cut -c1-12). "
            "The password is the first 12 hex chars of MD5(nanosecond-precision Unix timestamp). "
            "The timestamp is taken at the moment create_user() executes, "
            "which is inside setup_rootfs() -- called as a background job from main(), "
            "approximately 30-60 seconds after HUU boot. "
            "HUU boot time is observable (e.g., ipmitool sel shows HUU start events). "
            "An attacker who knows the approximate boot time can narrow the nanosecond timestamp "
            "to a window of seconds (~10^10 candidates per second of uncertainty), "
            "then brute-force MD5 prefixes offline. "
            "At 10M MD5/sec (single GPU), a 10-second boot-time uncertainty window "
            "= 10^11 candidates = ~27 GPU-hours. "
            "This is independent of the HCMD-F1 unauthenticated exposure -- "
            "it matters if HCMD-F1 is patched but the password generation remains weak."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_c245m8_260180_re",
    "iso": "ucs-c245m8-huu-6.0.2.260180.iso",
    "decrypt_key_confirmed": "zfguijkophju@*%1] (same as all prior HUU versions)",
    "redfish_stack_exposed": {
        "nginx_user": "root",
        "tls": "disabled (commented out)",
        "access_log": "off",
        "port": "80 (HTTP)",
        "bind": "0.0.0.0",
    },
    "critical_endpoint": "GET /redfish/v1/Oem/GetBmcToHostScpCredentials -> {Username, Password} no auth",
    "finding_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 192, "MEDIUM": 182, "LOW": 171},
    "cumulative_total": 600,
}
