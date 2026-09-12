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
# Kernel + rootfs analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "vmlinuz": {
        "status":  "BLOCKED -- payload encrypted",
        "method":  "bzImage setup code parsed (plaintext); payload at 0x42c4 encrypted",
        "version": "Linux 6.12.32 (read from setup code at file offset 0x3860)",
    },
    "rootfs_gz": {
        "status":  "BLOCKED -- custom encryption format 0x5b6758cb",
        "note":    "Not gzip, not FortiOS 7.x XZ-with-bad-CRC format",
    },
    "rootfs_ext_tar_xz": {
        "status":  "ACCESSIBLE -- standard XZ",
        "content": "Python 3.11 Django application; AI agent framework; FAZ MCP server code",
        "key_dirs": [
            "proj/ai/faz_mcp/  -- MCP proxy (SSRF gated by CONFIG_DEBUG)",
            "proj/ai/agent/    -- multi-agent framework (router, diagnostics, script gen, policy)",
            "proj/ai/faz/      -- FAZ chat completion views",
        ],
    },
    "syntax_tar_xz": {
        "status":  "NOT YET EXTRACTED -- standard XZ (87MB)",
        "pending": True,
    },
    "webmcpserver": {
        "status":  "BLOCKED -- binary in encrypted rootfs.gz",
        "impact":  "Cannot confirm auth posture of :11345 from static analysis",
    },
}
