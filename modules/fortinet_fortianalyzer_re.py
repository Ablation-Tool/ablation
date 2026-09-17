"""
Fortinet FortiAnalyzer FAZ_VM64_KVM 8.0.0 RE
Source: FAZ_VM64_KVM-v8.0.0.F-build0105-FORTINET.qcow2
Build date: 2026-04-20 | kernel: Linux 6.12.32 (built 2026-04-20)
Extraction path: QCOW2 -> virtioa.raw -> P1 (sector 8193, dd) -> /mnt/faz-p1
Accessible layers: P1 boot partition (ext2), rootfs-ext.tar.xz (Django app)
Encrypted layers: vmlinuz payload, rootfs.gz (custom format 0x5b6758cb...)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":        "Fortinet FortiAnalyzer VM64-KVM",
    "os":             "FortiOS 8.0.0.F",
    "build":          "0105",
    "build_date":     "2026-04-20",
    "kernel":         "Linux 6.12.32",
    "kernel_builder": "root@49192c769448",
    "arch":           "x86-64",

    "image_structure": {
        "qcow2":       "FAZ_VM64_KVM-v8.0.0.F-build0105-FORTINET.qcow2",
        "p1_offset":   "sector 8193 (4196352 bytes)",
        "p1_size":     "1GB (2097152 sectors)",
        "p1_files":    ["vmlinuz (5.2MB bzImage)", "rootfs.gz (143MB encrypted)", "rootfs-ext.tar.xz (standard XZ, accessible)"],
        "bootline":    "KERNEL vmlinuz APPEND loglevel=3 panic=5 console=ttyS0,9600 rdinit=/bin/init initrd=/rootfs.gz",
    },

    "encryption_status": {
        "vmlinuz_payload": (
            "Encrypted. bzImage setup code at 0x0-0x3e63 is plaintext. "
            "Payload at offset 0x42c4 starts 0xba21fbe6bd04c048 -- no known compression signature. "
            "Kernel version string readable at file offset 0x3860 in setup code."
        ),
        "rootfs_gz": (
            "Encrypted. Magic bytes 0x5b6758cb067eb1d0 match no known format. "
            "NOT gzip, NOT FortiOS 7.x custom XZ format. "
            "Inaccessible without decryption key."
        ),
        "rootfs_ext_tar_xz": "Standard XZ. Accessible. Contains Python 3.11 Django application.",
    },
}


# ---------------------------------------------------------
# FAZ-F01: Redis global pub/sub - no session scoping on
#          tool call response/permission/cancel endpoints
# ---------------------------------------------------------
FAZ_F01_REDIS_CROSS_SESSION_TOOL_INJECTION = {
    "id":       "FAZ-F01",
    "product":  "Fortinet FortiAnalyzer 8.0.0",
    "severity": "MEDIUM -- cross-session agent interference by authenticated user",
    "class":    "Cross-session Redis pub/sub injection (IDOR on global channels)",
    "cwe":      "CWE-862 (Missing Authorization), CWE-330 (insufficient entropy only partially mitigates)",

    "description": (
        "All AI agent pub/sub channels are global Redis channels with no session or user scoping. "
        "Four endpoints accept an attacker-supplied ID and publish to the global channel without "
        "validating that the ID belongs to the caller's session. An authenticated user can "
        "interfere with other users' running agent conversations."
    ),

    "channels": {
        "gui_ai_agent_tool_call_channel":            "tool call responses (result injection)",
        "gui_ai_agent_tool_call_permission_channel": "tool call permission approvals (bypass gate)",
        "gui_any_gui_function_call_channel":         "generic GUI function responses",
        "gui_ai_agent_stop_conversation_channel":    "conversation abort signal",
    },

    "source": "proj/ai/agent/util/const.py (REDIS_TOOL_CALL_CHANNEL et al.)",

    "vulnerable_endpoints": {
        "POST /p/ai/tool_call_resp": {
            "handler":    "send_tool_call_response",
            "input":      {"tool_call_id": "str", "result": "str"},
            "validation": "NONE -- no session check",
            "impact":     "Inject arbitrary tool result into any agent waiting on that tool_call_id",
        },
        "POST /p/ai/tool_call_permission": {
            "handler":    "send_tool_call_permission_response",
            "input":      {"tool_call_id": "str", "allowed": "bool", "final_jsondata": "any"},
            "validation": "NONE -- no session check",
            "impact":     "Approve tool calls that require user confirmation for another session",
        },
        "POST /p/ai/cancel_tool_call": {
            "handler":    "cancel_tool_call",
            "input":      {"tool_call_id": "str"},
            "validation": "NONE -- no session check",
            "impact":     "Cancel another user's in-progress tool call",
        },
        "POST /p/ai/stop_conversation": {
            "handler":    "stop_conversation",
            "input":      {"request_ids": "list[str]"},
            "validation": "NONE -- no session check",
            "impact":     "Abort any agent conversation by ID; DoS against other users' sessions",
        },
        "POST /p/ai/any_gui_function_call_resp": {
            "handler":    "any_gui_function_call_resp",
            "input":      {"id": "str", "result": "dict"},
            "validation": "NONE -- no session check",
            "impact":     "Inject GUI function result into any waiting agent",
        },
    },

    "id_entropy": (
        "tool_call_id = str(uuid4()) -- UUIDv4 (122 bits of randomness). "
        "Prevents brute-force guessing. Exploitation requires: (a) attacker observed the ID "
        "via shared Redis access, compromised session, or WebSocket interception; "
        "or (b) attacker knows the conversation_id for stop_conversation (client-supplied, "
        "may not be UUIDs)."
    ),

    "datamask_idor": {
        "endpoint":    "POST /p/ai/current_datamask",
        "handler":     "current_datamask",
        "key_format":  "fortiai::datamask::conversation_id:{conversation_id}",
        "validation":  "NONE -- submit_datamask has session check; current_datamask does NOT",
        "contrast":    "submit_datamask (write) checks saved_conversation_id == conversation_id; read path omits this check",
        "impact":      "Read another user's IP address datamask (maps real IPs to masked values)",
        "source":      "proj/ai/agent/util/datamask.py:get_datamask_storage_key",
    },

    "remediation": (
        "Scope all Redis channel subscriptions and publish lookups to the session_id. "
        "Add session validation to current_datamask matching the pattern in submit_datamask. "
        "At minimum, scope stop_conversation to the caller's session."
    ),
}


# ---------------------------------------------------------
# FAZ-F02: Cookie exposure in webmcpserver cmdline args
# ---------------------------------------------------------
FAZ_F02_COOKIE_CMDLINE_EXPOSURE = {
    "id":       "FAZ-F02",
    "product":  "Fortinet FortiAnalyzer 8.0.0",
    "severity": "LOW -- session cookie readable by local privileged processes",
    "class":    "Process cmdline secret exposure (CWE-214)",

    "description": (
        "When the FAZ AI stack uses STDIO MCP mode, it spawns "
        "/usr/bin/webmcpserver --cookies <json_cookies> as a subprocess. "
        "The full JSON cookie blob is visible in /proc/[pid]/cmdline to any local process "
        "that can read it (typically root and processes in the same UID)."
    ),

    "source": "proj/ai/faz_mcp/mcp.py -- StdioMCPClient.__aenter__",
    "subprocess_cmdline": ["/usr/bin/webmcpserver", "--cookies", "<json_cookies>"],

    "cookie_origin": (
        "Caller's HTTP session cookies, passed from the Django view context. "
        "An attacker with local root access could read and replay these to impersonate "
        "the authenticated FAZ session."
    ),

    "scope_note": (
        "webmcpserver binary is in encrypted rootfs.gz (inaccessible without decryption key). "
        "Authentication posture of the launched server is unconfirmed from static analysis."
    ),

    "remediation": (
        "Pass credentials via environment variable (subprocess env) or stdin pipe, "
        "not as a positional argument. "
        "Alternatively, use a Unix socket with credential passing."
    ),
}


# ---------------------------------------------------------
# FAZ-F03: SSRF via server_url in MCP endpoints (DEBUG-gated)
# ---------------------------------------------------------
FAZ_F03_MCP_SSRF_SERVER_URL = {
    "id":       "FAZ-F03",
    "product":  "Fortinet FortiAnalyzer 8.0.0",
    "severity": "LOW (production) / HIGH (debug build) -- SSRF via user-controlled MCP server URL",
    "class":    "Server-Side Request Forgery via user-controlled MCP server URL",

    "description": (
        "Three endpoints at /p/ai/faz_mcp/ accept a user-controlled server_url and forward "
        "requests (including the caller's session cookies) to the specified URL. "
        "This is a full SSRF primitive: attacker controls the destination, method, and a "
        "copy of the auth headers. Protected by CONFIG_DEBUG=0 hardcoded in production."
    ),

    "endpoints": {
        "POST /p/ai/faz_mcp/call_tool":   "call_tool -- forwards tool call to server_url",
        "POST /p/ai/faz_mcp/list_tools":  "list_tools -- connects to server_url and lists MCP tools",
        "POST /p/ai/faz_mcp/diagnose/completions": "mcp_diagnose_completions -- user-controlled tools/messages/model",
    },

    "gate": {
        "check":   "if not SYS.CONFIG_DEBUG: raise Http404",
        "value":   "SYS.CONFIG_DEBUG = 0 (hardcoded in proj/util/proxy/macros.py:SYS class)",
        "runtime": "Not user-settable. Requires a debug firmware build.",
    },

    "ssrf_mechanism": (
        "StreamableHTTPMCPClient(server_url=user_supplied_url) -- uses httpx async client. "
        "All caller request headers forwarded via 'headers=request.headers'. "
        "Result: session cookies sent to attacker-controlled endpoint."
    ),

    "source": {
        "views":  "proj/ai/faz_mcp/views.py -- call_tool, list_tools",
        "client": "proj/ai/faz_mcp/mcp.py -- StreamableHTTPMCPClient",
        "macro":  "proj/util/proxy/macros.py -- SYS.CONFIG_DEBUG = 0",
    },

    "remediation": (
        "Allowlist valid MCP server URLs (must start with fmg:// or 127.0.0.1). "
        "Do not forward raw request.headers to external hosts. "
        "The CONFIG_DEBUG gate must remain absent in production builds."
    ),
}


# ---------------------------------------------------------
# FAZ-F04: Local MCP server at :11345 - auth posture unknown
# ---------------------------------------------------------
FAZ_F04_LOCAL_MCP_SERVER_11345 = {
    "id":       "FAZ-F04",
    "product":  "Fortinet FortiAnalyzer 8.0.0",
    "severity": "INFO -- local MCP server, auth posture unconfirmed from static analysis",
    "class":    "Unauthenticated local service (unconfirmed)",

    "description": (
        "The device diagnostics agent connects to http://127.0.0.1:11345/sse "
        "without any authentication headers. The server is started by the webmcpserver binary "
        "which lives in the encrypted rootfs.gz. Its authentication requirements cannot "
        "be confirmed without decrypting rootfs.gz or dynamic analysis."
    ),

    "endpoints_observed": {
        "http://127.0.0.1:11345/sse":              "SSE channel -- device_diagnostics_agent connects here",
        "fmg://agents/toolsets/advanced/tag_map":  "resource read for tool tag map",
        "fmg://agents/toolsets/dvm_diagnose":      "DVM diagnostic toolset",
        "fmg://agents/toolsets/advanced/*":        "General/VPN/SDWAN/routing/utility toolsets",
    },

    "concern": (
        "If :11345 accepts unauthenticated local connections, any local process (or a "
        "process executing via another vulnerability) could invoke FortiGate device "
        "diagnostic and configuration tools through the MCP interface."
    ),

    "source": {
        "diagnostics_agent": "proj/ai/agent/agent_definitions/dvm_agent/device_diagnostics_agent.py",
        "mcp_client":        "proj/ai/faz_mcp/mcp.py -- StdioMCPClient",
    },

    "remediation": "Require authentication (token or Unix socket credential) on :11345.",
}


# ---------------------------------------------------------
# FAZ-F05: Log search filter passthrough to fazsvcd C daemon
# ---------------------------------------------------------
FAZ_F05_LOGSEARCH_FILTER_PASSTHROUGH = {
    "id":       "FAZ-F05",
    "product":  "Fortinet FortiAnalyzer 8.0.0",
    "severity": "UNCONFIRMED -- requires C daemon analysis; surface confirmed open",
    "class":    "Potential SQL/query injection via log search filter passthrough",

    "description": (
        "The logsearch_run endpoint at POST /p/logview/logsearch_run/ passes the user-supplied "
        "'filter' field directly to the fazsvcd C daemon at :31723 via JSON-RPC without any "
        "Python-layer sanitization. Whether fazsvcd constructs SQL queries using this string "
        "without parameterization is unconfirmed (binary in encrypted rootfs.gz). "
        "The surface is confirmed open from static analysis."
    ),

    "source": "proj/logview/views/log_search.py -- logsearch_run",

    "filter_flow": {
        "input":    "request.body['filter'] -- user-controlled string",
        "augment":  "if is_local_event and adom != 'root': filter += ' adom=' + current_adom",
        "backend":  "FazAPI.add({'adom': adom, 'params': [{'filter': _filter, ...}]})",
        "proxy":    "JSON-RPC to http://127.0.0.1:31723/fazsvcd via jsonrpc.ServiceProxy",
        "sanitize": "NONE in Python layer",
    },

    "auth_gate": "@login_required + @r_required_any(ADMINPRIV_LOG_VIEWER or ADMINPRIV_SYSTEM_SYS_SETTING)",

    "exploitation_note": (
        "If fazsvcd passes filter directly into ClickHouse/SQL query string (not parameterized), "
        "an authenticated log viewer could inject arbitrary SQL. "
        "Confirmation requires binary analysis of fazsvcd or dynamic testing."
    ),

    "remediation": "Validate/restrict filter syntax in the Python layer before forwarding to the daemon.",
}


# ---------------------------------------------------------
# FAZ-F06: SOAR connector TLS verification bypass
# ---------------------------------------------------------
FAZ_F06_SOAR_TLS_VERIFY_FALSE = {
    "id":       "FAZ-F06",
    "product":  "Fortinet FortiAnalyzer 8.0.0 -- SOAR connector framework",
    "severity": "MEDIUM -- TLS certificate verification disabled in multiple production connectors; enables MITM on third-party integrations",
    "class":    "TLS verification bypass (CWE-295 Improper Certificate Validation)",

    "affected_connectors": {
        "FMQ": {
            "file":   "SOAR/FMQ/operator.py:285",
            "target": "https://api.fortimq.fortinet.net (Fortinet cloud messaging queue)",
            "code":   "requests.post(url, ..., verify=False)",
            "note":   "Hardcoded False; no user-configurable override. On-path attacker between FAZ and Fortinet cloud can MITM the FortiMQ session.",
        },
        "SERVICENOW": {
            "file":    "SOAR/SERVICENOW/operator.py:64",
            "target":  "User-configured ServiceNow instance",
            "code":    "self.verify_ssl = False (class __init__)",
            "note":    "Class default is False. If find_servicenow_connector_params() returns False for verify-ssl, never overridden. Affects POST /api/now/v2/table/incident calls.",
        },
        "MS_TEAMS": {
            "file":   "SOAR/MS_TEAMS/operator.py:56",
            "target": "Microsoft Teams webhook URLs / OAuth endpoints",
            "code":   "self.verify_ssl = False",
            "note":   "Hardcoded at class init; all Teams HTTP requests bypass cert validation.",
        },
    },

    "impact": (
        "An on-path attacker (BGP hijack, ISP, rogue AP, compromised upstream router) "
        "between the FortiAnalyzer and any of these endpoints can intercept SOAR automation "
        "traffic in cleartext, inject false responses, or steal API credentials transmitted "
        "in request headers/bodies."
    ),

    "source":        "rootfs-ext (SOAR connector Python source, accessible layer)",
    "verification":  "CONFIRMED -- source code read; verify=False at stated lines",

    "remediation": (
        "Set verify=True and supply CA bundle path (certifi or system trust store). "
        "For FMQ: use the bundled Fortinet CA chain. For customer connectors: read verify-ssl "
        "from connector config and default to True, not False."
    ),
}


# ---------------------------------------------------------
# FAZ-F07: SOAR WEBHOOK connector SSRF
# ---------------------------------------------------------
FAZ_F07_SOAR_WEBHOOK_SSRF = {
    "id":       "FAZ-F07",
    "product":  "Fortinet FortiAnalyzer 8.0.0 -- SOAR WEBHOOK connector",
    "severity": "MEDIUM -- admin-level SSRF; FAZ can be directed to issue HTTP/HTTPS requests to arbitrary internal hosts",
    "class":    "Server-Side Request Forgery via WEBHOOK connector URL override (CWE-918)",

    "description": (
        "The WEBHOOK connector execute_action() accepts an action-level URL override via "
        "params.get('url', self.server_url) with no allowlist or host validation. "
        "The only normalization is prefix enforcement (http:// or https://). "
        "An authenticated SOAR playbook designer can configure a playbook action that "
        "directs the FortiAnalyzer to issue GET/POST/PUT/DELETE/PATCH requests to any "
        "reachable address (internal RFC1918, metadata services, localhost)."
    ),

    "code_path": {
        "file":      "SOAR/WEBHOOK/operator.py",
        "override":  "execute_action(): self.server_url = params.get('url', self.server_url)",
        "no_filter": "No scheme restriction beyond http/https prefix. No IP/hostname allowlist.",
        "methods":   ["GET", "POST", "PUT", "DELETE", "PATCH"],
    },

    "reach": {
        "internal_network": "FAZ can reach any host on its management/data network segments",
        "cloud_metadata":   "169.254.169.254 reachable if FAZ runs in cloud (AWS/Azure/GCP VM)",
        "localhost":        "127.0.0.1:10745 (backend API, no TLS), :11345 (MCP server), :31723 (fazsvcd), :9000 (ClickHouse), :6379/:6384 (Redis) all reachable",
    },

    "privilege_req": "SOAR playbook designer role (not full admin)",

    "source":       "SOAR/WEBHOOK/operator.py -- WebhookBaseOperator.execute_action()",
    "verification": "CONFIRMED -- source code read",

    "remediation": (
        "Validate server_url against a configurable allowlist of permitted hostnames/CIDRs. "
        "Reject RFC1918 addresses, 127.0.0.1/::1, and link-local (169.254.x.x, fe80::) unless "
        "explicitly permitted. Do not allow URL override at action level; fix at connector config."
    ),
}


# ---------------------------------------------------------
# FAZ-F08: SOAR credential architecture -- Redis-backed
#          credential store with plaintext ClickHouse password
# ---------------------------------------------------------
FAZ_F08_SOAR_CREDENTIAL_ARCHITECTURE = {
    "id":       "FAZ-F08",
    "product":  "Fortinet FortiAnalyzer 8.0.0 -- SOAR credential store",
    "severity": "INFO/MEDIUM -- credential architecture; impact depends on Redis accessibility",
    "class":    "Sensitive credential storage architecture (CWE-312, CWE-256)",

    "description": (
        "All SOAR connector credentials (API keys, passwords, auth tokens for ServiceNow, "
        "vSphere, VirusTotal, MS Teams, FMQ, etc.) are encrypted and stored in Redis. "
        "Decryption requires two native library calls via ctypes. "
        "ClickHouse SIEM database password is stored in plaintext at /etc/clickhouse-security. "
        "If an attacker reaches Redis (e.g., via FAZ-F07 SSRF to :6379/:6384) with knowledge "
        "of the decryption library interface, all stored connector credentials are at risk."
    ),

    "redis_ports": {
        6379:     "main Redis instance",
        6384:     "SOAR Redis instance (connector credential store)",
        "DKAP":   "DKAP (Dynamic Key and Password) Redis; connection via REDIS_DKAP_CONN_ID Airflow hook",
    },

    "decryption_chain": {
        "step1":  "redis_security_get_password(redis_port) -- native lib via ctypes; returns Redis AUTH password",
        "step2":  "Connect authenticated to Redis; read encrypted credential blob",
        "step3":  "decrypt_with_redis_port(encrypted_blob, redis_port) -- native lib via ctypes; returns plaintext credential",
        "native": "Library loaded from disk via ctypes RTLD_LAZY; likely libRedisExt.so or similar in encrypted rootfs.gz",
    },

    "clickhouse_credential": {
        "file":   "/etc/clickhouse-security",
        "format": "plaintext password string",
        "access": "read at runtime by LOCALHOST connector SOAR operator for ClickHouse SIEM queries",
        "db":     "ClickHouse host=localhost user=default database=siem",
        "note":   "Any process with root access that survives the fortism domain model can read this file",
    },

    "airflow_stack": {
        "framework":  "Apache Airflow (DAG-based SOAR orchestration)",
        "metadata_db": "PostgreSQL 11 (/usr/local/pg11/) -- Airflow DAG/task state",
        "log_db":     "ClickHouse (636MB binary, NOT stripped, BuildID 54e3c62019aeb33bf592492e196e9017a8fb30b7)",
        "cache_queue": "Redis (3 ports)",
    },

    "source": (
        "SOAR connector health_check.py files (FGD, SERVICENOW, FORTIANALYZER_CLOUD, VSPHERE); "
        "LOCALHOST/operator.py (ClickHouse credential read at line 3449)"
    ),
    "verification": "CONFIRMED -- source code read",

    "remediation": (
        "Restrict Redis ports to localhost or Unix sockets; require AUTH with strong passwords. "
        "Move ClickHouse password to a secrets manager or at minimum 0600 root-only file. "
        "Audit which fortism domains have permission to read /etc/clickhouse-security."
    ),
}


# ---------------------------------------------------------
# FAZ-F09: Apache custom module + unencrypted backend proxy
# ---------------------------------------------------------
FAZ_F09_APACHE_BACKEND_PROXY = {
    "id":       "FAZ-F09",
    "product":  "Fortinet FortiAnalyzer 8.0.0 -- Apache/web stack",
    "severity": "INFO -- internal proxy architecture; relevant if SSRF reaches :10745",
    "class":    "Internal backend proxy without TLS; custom Apache module in binary",

    "architecture": {
        "apache_ports":  [443, 8082, 80],
        "backend_port":  10745,
        "backend_proto": "HTTP (no TLS)",
        "proxy_config":  "ProxyPass / http://localhost:10745/ keepalive=On ttl=15 retry=0",
        "ws_proxy":      "ProxyPass /ws ws://localhost:10745/ws",
    },

    "custom_modules": {
        "fmg_request.so": "LoadModule fmg_request_module -- replaces standard request processing; in encrypted rootfs.gz",
        "fmg_rewrite.so": "LoadModule rewrite_module fmg_rewrite.so -- replaces standard mod_rewrite; in encrypted rootfs.gz",
    },

    "ssl_config": {
        "cert":     "/usr/local/apache2/server.crt",
        "key":      "/usr/local/apache2/server.key",
        "protocol": "TLSv1.2 + TLSv1.3 (primary); TLSv1.1 allowed in legacy config section",
        "servername": "fmg.fortinet.com:443 (FAZ and FMG share web stack identity)",
    },

    "clickhouse_binary": {
        "path":       "/usr/local/clickhouse/clickhouse",
        "size":       "636MB",
        "stripped":   False,
        "elf_class":  "ELF 64-bit x86-64 LSB pie",
        "build_id":   "54e3c62019aeb33bf592492e196e9017a8fb30b7",
        "note":       "NOT stripped -- all function names preserved; full static analysis possible without source",
    },

    "source":       "rootfs-ext/usr/local/apache2/conf/httpd.conf + httpd-ssl.conf (accessible layer)",
    "verification": "CONFIRMED -- config files read",

    "ssrf_relevance": (
        "FAZ-F07 WEBHOOK SSRF can reach http://127.0.0.1:10745/ directly, bypassing Apache "
        "authentication and SSL termination. The backend receives unauthenticated HTTP requests."
    ),
}


# ---------------------------------------------------------
# Kernel + rootfs analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "vmlinuz": {
        "status":  "BLOCKED -- payload encrypted",
        "method":  "bzImage setup code parsed (plaintext); payload at 0x42c4 encrypted",
        "version": "Linux 6.12.32 PREEMPT_DYNAMIC (built 2026-04-20); kernel builder root@49192c769448",
        "posture": "RO-rootFS (read-only root); 6.12 LTS branch (modern, maintained)",
    },
    "rootfs_gz": {
        "status":  "BLOCKED -- custom encryption format 0x5b6758cb",
        "note":    "Not gzip, not FortiOS 7.x XZ-with-bad-CRC format; 143MB",
        "blocked": ["webmcpserver binary", "fmg_request.so", "fmg_rewrite.so", "fazsvcd", "native SOAR decrypt library"],
    },
    "rootfs_ext_tar_xz": {
        "status":  "ACCESSIBLE -- standard XZ",
        "content": "Python 3.11 Django application; AI agent framework; FAZ MCP server code; SOAR connector Python source (18 connector types)",
        "key_dirs": [
            "proj/ai/faz_mcp/  -- MCP proxy (SSRF gated by CONFIG_DEBUG)",
            "proj/ai/agent/    -- multi-agent framework (router, diagnostics, script gen, policy)",
            "proj/ai/faz/      -- FAZ chat completion views",
        ],
    },
    "syntax_tar_xz": {
        "status":  "ACCESSIBLE -- standard XZ",
        "content": "FortiOS CMDB syntax definitions (800.txt 61K lines), FMG/FAZ JSON-RPC API schemas, connector_syntax.json, fmg_cmdb_syntax.json (611KB), fmglog_syntax.json (206KB), fmg_dvm_syntax.json (48KB)",
    },
    "webmcpserver": {
        "status":  "BLOCKED -- binary in encrypted rootfs.gz",
        "impact":  "Cannot confirm auth posture of :11345 from static analysis",
    },
    "soar_connectors": {
        "status":   "ANALYZED -- 18 connector Python sources read",
        "findings": ["FAZ-F06 (TLS bypass: FMQ/SERVICENOW/MS_TEAMS)", "FAZ-F07 (WEBHOOK SSRF)", "FAZ-F08 (Redis credential store)"],
        "connectors": ["AD", "EMS", "FAC", "FCASB", "FEDR", "FGD", "FML", "FMQ",
                       "FORTIANALYZER_CLOUD", "FOS", "FSA", "FWEB", "LOCALHOST",
                       "MS_TEAMS", "SERVICENOW", "VIRUSTOTAL", "VSPHERE", "WEBHOOK"],
    },
    "partition_signature": {
        "file":   "faz_db_x -- PKCS#7 Signed Data",
        "signer": "fortinet-ca2 (Fortinet CA, Sunnyvale CA, US)",
        "valid":  "2022-02-04 to 2056-05-26 (34-year cert)",
        "note":   "Same partition signing pattern as FGT (flatkc.sig). Cross-product FAZ/FGT architecture.",
    },
    "unique_findings": ["FAZ-F01", "FAZ-F02", "FAZ-F03", "FAZ-F04", "FAZ-F05", "FAZ-F06", "FAZ-F07", "FAZ-F08", "FAZ-F09", "FAZ-F10", "FAZ-F11"],
}

FAZ_F10_SOAR_CLICKHOUSE_SQLI = {
    "id":       "FAZ-F10",
    "product":  "Fortinet FortiAnalyzer 8.0.0 -- SOAR FindLateralMovementOperator ClickHouse SQL injection",
    "severity": "HIGH -- unsanitized trigger data injected into ClickHouse SQL; full SIEM database read (all security logs, all monitored devices)",
    "class":    "SQL injection in SOAR connector Python code (CWE-89); ClickHouse database",
    "cwe":      "CWE-89",
    "source":   "fmg800_rootfs_ext/usr/local/builtin_connectors/builtin_connectors.tar.gz -> LOCALHOST/operator.py",

    "vulnerable_code": {
        "file":      "LOCALHOST/operator.py",
        "class":     "FindLateralMovementOperator",
        "function":  "build_filter_string (L2466-2468) + build_query (L2451-2464)",
        "injection_point": "L2467: filters = [f\"{key} in {tuple(value)}\" for key, value in targets.items()]",
        "sink":      "L2505-2510: requests.post('http://127.0.0.1:8123/?database=siem&default_format=JSON', data=query)",
    },

    "description": (
        "The SOAR FindLateralMovementOperator (lateral movement hunt playbook) constructs a ClickHouse SQL "
        "query using Python f-strings with NO parameterization or escaping: "
        "  build_filter_string: "
        "    filters = [f'{key} in {tuple(value)}' for key, value in targets.items()] "
        "    return ' or '.join(filters) "
        "  build_query: "
        "    return f'SELECT ... FROM adom{self.adom_oid}_SIM_Xlog WHERE ({filter_str}) ...' "
        "The resulting SQL string is sent as the raw HTTP POST body to ClickHouse on 127.0.0.1:8123. "
        "The `value` in `targets.items()` originates from SOAR trigger data: "
        "  parse_trigger_data reads indicator.value and targets from self.trigger_data. "
        "  trigger_data = FAZUtilsOperator.parse_multi_input(context, self.trigger_data, context_dict). "
        "  context_dict is populated from SOAR incident data (network security events from FAZ). "
        "Attack path: "
        "  1. Attacker crafts network traffic that generates a FAZ security event with a controlled "
        "     source IP or endpoint ID field. "
        "  2. FAZ SOAR creates an incident with the attacker-controlled value in indicator.value. "
        "  3. FindLateralMovementOperator playbook fires on the incident. "
        "  4. parse_trigger_data populates unique_targets with the attacker-controlled value. "
        "  5. build_filter_string produces: \"src_ip in (') UNION SELECT ... --,)\" "
        "  6. build_query wraps it in a full SELECT, sent to ClickHouse at 127.0.0.1:8123. "
        "  7. ClickHouse executes the injected query -- attacker can read any table in the 'siem' database. "
        "ClickHouse 'siem' database contains: all FAZ log records from all monitored FortiGates/FortiWalls, "
        "security events, endpoint telemetry, network flow data for all monitored sessions. "
        "Exfiltration of this database = complete network visibility across all monitored devices. "
        "The ClickHouse instance on 127.0.0.1:8123 uses HTTP basic auth: "
        "  auth=('default', password) -- the default user's password is passed in as a SOAR connector param. "
        "If ClickHouse is configured with the default empty password for the 'default' user, "
        "no auth bypass needed -- the connector supplies the password anyway."
    ),

    "proof_of_concept": (
        "trigger_data with indicator.value = [\"') UNION SELECT version(), 2, 3, 4 FROM system.one-- \"] "
        "Produces: "
        "  filter_str = \"src_ip in (') UNION SELECT version(), 2, 3, 4 FROM system.one-- ',)\" "
        "  Full query: SELECT dstepid, dst_ip, ... "
        "              FROM adom1_SIM_Xlog "
        "              WHERE (src_ip in (') UNION SELECT version(), 2, 3, 4 FROM system.one-- ',)) "
        "              AND itime >= '...' AND ... "
        "ClickHouse executes the UNION, returns ClickHouse version string in the result set."
    ),

    "data_model": {
        "database":   "siem (ClickHouse on 127.0.0.1:8123)",
        "tables":     "adom{N}_SIM_Xlog (lateral movement log), plus other SIEM tables accessible via UNION",
        "auth_model": "HTTP basic auth (default/<connector_password>); password from SOAR connector config",
    },

    "remediation": (
        "Use ClickHouse parameterized queries: "
        "  ClickHouse supports query parameters via URL: ?param_name=value "
        "  Replace: f'{key} in {tuple(value)}' "
        "  With: parameterized placeholders and pass values via the params= argument to requests.post "
        "Alternatively, validate that `value` matches the expected IP/epid format (IP regex, integer check) "
        "before including in the filter string."
    ),

    "related_findings": ["FAZ-F07 (WEBHOOK SSRF)", "FAZ-F08 (Redis credential store)"],
}

FAZ_F11_SOAR_CONNECTOR_URL_PATH_TRAVERSAL = {
    "id":       "FAZ-F11",
    "product":  "Fortinet FortiAnalyzer 8.0.0 -- SOAR FAC/FML connector URL path traversal",
    "severity": "MEDIUM -- attacker-influenced SOAR trigger data injected into FAC/FML API URL path; enables access to unauthorized API endpoints on external Fortinet servers using SOAR connector credentials",
    "class":    "URL path traversal / SSRF via SOAR connector (CWE-22/CWE-918); affects external servers",
    "cwe":      "CWE-22, CWE-918",
    "source":   "builtin_connectors.tar.gz -> FAC/operator.py, FML/operator.py",

    "affected_connectors": {
        "FAC (FortiAuthenticator)": {
            "file":     "FAC/operator.py",
            "location": "FACGetUserListOperator.execute_action (L142), FACGetUserOperator.execute_action (L201/206), FACUpdateUserStatusOperator.execute_action (L292)",
            "pattern":  "endpoint='api/v1/{user_type}/' or endpoint='api/v1/{user_type}/{userid}/'",
            "how_triggered": "FAZUtilsOperator.parse_input(context, user_type/userid, context_dict) at execute() L158/229/311 -- template-expands from SOAR context",
        },
        "FML (FortiMail)": {
            "file":     "FML/operator.py",
            "location": "FMLAddSenderToBlocklistOperator.add_sender_to_blocklist (L561)",
            "pattern":  "url = f'https://{ip}/api/v1/SenderListV2/{domain_name}'",
            "how_triggered": "FAZUtilsOperator.parse_input(context, domain_name, context_dict) at execute() L595 -- template-expands from SOAR context",
        },
    },

    "description": (
        "Multiple SOAR builtin connectors construct HTTP API URLs by interpolating SOAR context "
        "values (resolved via FAZUtilsOperator.parse_input) directly into URL path segments "
        "with no validation or normalization. "
        "In FAC (FortiAuthenticator connector): "
        "  execute_action: url = self.server_url + 'api/v1/{user_type}/{userid}/' "
        "  user_type and userid are template-expanded from SOAR trigger/incident context at execute(). "
        "  If playbook config uses {{ trigger.field }} for user_type or userid, attacker controls the URL path. "
        "  FACBaseOperator.make_api_call constructs: url = self.server_url + endpoint "
        "  and sends it via make_https_request (no URL normalization). "
        "In FML (FortiMail connector): "
        "  url = f'https://{ip}/api/v1/SenderListV2/{domain_name}' "
        "  domain_name is template-expanded from SOAR context at execute() L595. "
        "Attack: attacker crafts network event with domain_name = '../../unauthorized_endpoint'. "
        "The FAZ SOAR connector sends the request to the FortiMail/FortiAuthenticator server "
        "using the connector's admin credentials (Basic auth, cookie session). "
        "The attacker can reach any API endpoint on the target server reachable from FAZ. "
        "Prerequisite: SOAR playbook author uses {{ trigger.X }} template variables for the affected fields. "
        "This is plausible for automation that queries user info or manages block lists based on "
        "detected threat indicators (common SOAR use case). "
        "The external FAC/FML server's own URL normalization may limit impact (most web servers "
        "normalize ../; however, percent-encoded paths like %2e%2e%2f may bypass normalization). "
        "Combined with FAZ-F10 (trigger-data SQL injection) this completes a pattern: "
        "all SOAR data flows from trigger data through parse_input with no sanitization."
    ),

    "attack_chain": (
        "1. Attacker crafts spam/phishing email with controlled sender domain. "
        "2. FortiMail creates a SOAR incident with domain = '../../admin'. "
        "3. SOAR FMLAddSenderToBlocklistOperator fires; parse_input resolves domain_name = '../../admin'. "
        "4. URL: https://fml.example.com/api/v1/SenderListV2/../../admin -- resolved to /api/v1/admin. "
        "5. FortiMail admin API call with SOAR connector session credentials. "
        "FAC variant: controlled username/userid in network event -> FACGetUserOperator -> "
        "  https://fac.example.com/api/v1/localusers/../../admin/config/."
    ),

    "remediation": (
        "Validate user_type, userid, and domain_name against a whitelist of allowed values "
        "before constructing the URL. For user_type: only 'localusers', 'ldapusers', 'radiususers' "
        "are valid FAC endpoints. For userid: enforce integer or UUID format. "
        "For domain_name: enforce hostname label format (regex: ^[a-zA-Z0-9.-]+$). "
        "Use urllib.parse.quote(..., safe='') to percent-encode values before interpolation."
    ),

    "related_findings": ["FAZ-F07 (WEBHOOK SSRF -- same SSRF class against external URLs)", "FAZ-F10 (SOAR trigger-data SQL injection)"],
}
