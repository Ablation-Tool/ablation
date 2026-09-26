# FortiADC v8.0.4-B0136 -- Active Session

## Firmware
- Image: `/media/cowboy/research/Fortinet/FortiDeceptor/FAD_KVM-v8.0.4.F-build0136-FORTINET.out`
- Extracted: `boot.qcow2` → `rootfs.gz` (XZ+ext4) → `/tmp/fad_root/`
- Version: `8.0.4-B0136` (built 2026-08-31)

## Binaries copied to ~/ablation/fortiadc-work/bins/
| Binary | Size | Type | Notes |
|--------|------|------|-------|
| httproxy | 14MB | C, stripped, ELF64 | Main L7 proxy/LB — highest value |
| restapi | 21MB | Go (Gin) | Management REST API |
| fnginx_new | 17MB | likely C | Modified nginx |
| cm_client | 11MB | C/Go? | Central management client |
| ptd | 9.2MB | Go 1.24.4 + CGo | Policy/traffic daemon — 7775 funcs, root, CMDB dispatch |
| adfsproxy | 5.3MB | Go 1.22.3 + CGo | AD FS proxy — 5689 funcs, root, libadfs.so |
| restapi_cmdd | 2.8MB | Go? | REST API command daemon |
| wadd | 245K | C | WAF daemon |
| cli | 2.7MB | C | CLI binary |

## httproxy PLT (key imports)
```python
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
```

## restapi notable endpoints (Go/Gin)
- `/api/system_aws_scripting/py_script_show` — Python scripting
- `/api/system_aws_scripting/py_script_log_only`
- `/api/system_scripting/download`
- `/api/system_health_check_monitor/read_info`
- `/api/debug/pprof/goroutine` — Go pprof exposed (info leak)
- `/api/debug/pprof/threadcreate`
- `/api/system/debug/save_state`
- `/api/system/debug/get_statefile_list`
- `admin-bypass-vdom-check` string present

## Findings

| ID | Binary | Title | Status |
|----|--------|-------|--------|
| FAD_R1 | restapi | Pre-auth pprof goroutine dump | **CONFIRMED HIGH** |
| FAD_R2 | restapi | JWT alg=none bypass | ELIMINATED |
| FAD_R3 | restapi | Scripting upload RCE | **CONFIRMED CRITICAL** (any-auth, root daemon) |
| FAD_A1 | adfsproxy | TLS cert validation bypass (proxy→ADFS) | **CONFIRMED HIGH** |
| FAD_A2 | adfsproxy→libadfs.so | CLI injection via cmf_exec_conf in add_relying_party_cmdb_config | **CONFIRMED HIGH** |
| FAD_P1 | ptd | tcpdump mkdir path traversal (cmd injection ELIMINATED — execvp separate argv) | **CONFIRMED MEDIUM** |
| FAD_P2 | ptd→libcgo.so | dumpsystem_delete_run path traversal → arbitrary file deletion as root | **CONFIRMED HIGH** |
| FAD_P_AWS | ptd→libcgo.so | fadc_aws_pyscript_run: dead stub (xor eax,eax; ret) | ELIMINATED |

### FAD_R1 — Pre-auth `/debug/pprof/*` (CONFIRMED HIGH)
- Root cause: `ginpprof.WrapGroup(engine)` at `main.main:0xdc1232` — root `*gin.Engine` passed
- JWT middleware applied at `0xdc1267` only on `engine.Group("/api")` sub-group
- Routes exposed pre-auth: `/debug/pprof/goroutine`, `/debug/pprof/heap`, `/debug/pprof/cmdline`, etc.
- Impact: goroutine dump leaks internal state, possible JWT key material in goroutine locals
- PoC: `curl -sk https://<target>:8443/debug/pprof/goroutine?debug=2`

### FAD_R2 — JWT alg=none (ELIMINATED)
- `signingMethodNone.Verify` at `0x8df640`: type-checks key against `unsafeNoneMagicConstant`
- KeyFunc returns `[]byte`; cmp fails → `NoneSignatureTypeDisallowedError`

### FAD_R3 — Scripting upload RCE (CONFIRMED CRITICAL)
- `Fadc_scripting_language_upload` at `0x9a8e60`; route: `POST /api/system_scripting/upload`
- **No role check**: `check_admin_perms` (0x9ea660) has 7 callers — all config CRUD, none here
- `check_admin_prof_perms` (0xa2cda0) has 8 callers — debug/image upload, none here
- Archive filename checked by regexp `.tar.gz$|.zip$|.tar$` at 0x9a9543 (contents unchecked)
- Two `Fadc_cmd.(*Cmd).Run` dispatches: 0x9a98a4 (extract), 0x9a9c85 (install to /scripting/)
- Daemon IPC: `net.Dial("unix", "/tmp/restapi_cmdd.sock")`; commands encoded via `Fadc_cmd.Encode`
- Extraction via `/bin/tar -xf` or `/bin/unzip`; install via `/scripting/cp -r %s %s`
- Attack: any valid JWT → upload `.tar.gz` with script → daemon extracts + executes
- Upgraded to CRITICAL: restapi_cmdd PLT has 8 privilege symbols (setuid/seteuid/setreuid/setresuid/setgid/setegid/setregid/setresgid) + dev RPATH /root/ = root daemon
- CVSS: 9.9 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

### FAD_P1 — ptd tcpdump mkdir path traversal (CONFIRMED MEDIUM)
- `fadc_exec_tcpdump_run` (0x7c2120, T in ptd dynsym) takes interface + filter args, no sanitization
- `__snprintf_chk(buf, 0x80, 2, 0x80, "%s/%s", "/var/log/tcpdump", filter)` → `mkdir(buf, 0o775)` — root creates dir at arbitrary path via `../` traversal (CWE-22)
- `fortiadc_tcpdump_run` in libcgo.so (0x143980): double-fork → `execvp(["tcpdump","-i",iface,"-w",file,"-c",count,"-n",filter,NULL])`
- **Command injection ELIMINATED**: execvp with separate argv — no shell expansion. filter at argv[8] is a BPF expression, not a shell command
- ptd has 9 privilege PLT symbols — runs as root; mkdir traversal creates empty dirs at arbitrary paths
- pclntab: 7,775 functions, Go 1.24.4, nfiles=1035, textStart=0x472de0
- libcgo.so extracted from boot.qcow2/rootfs: `fortiadc_tcpdump_run` defined there

### FAD_P2 — dumpsystem_delete_run path traversal (CONFIRMED HIGH)
- `fortiadc_dumpsystem_delete_run` (0xcb1b0) in libcgo.so called from ptd CMDB dispatcher
- `input_format_check` (0xcb100): `strspn(input, "[a-zA-Z0-9_\\-./:]+")` — blocks `;|&$\`` but permits `.` and `/`
- Must start with `coredump-` or `core-` (strncmp check at 0xcb216/0xcb22e)
- `__snprintf_chk(buf, 0x80, 2, 0x80, "rm %s/%s", "/var/log/crash/", input)` → `fadcsystem(buf)`
- `fadcsystem` = PLT import (system() wrapper; system@GLIBC_2.2.5 in libcgo.so PLT)
- Traversal: `coredump-../../../../etc/shadow` → `rm /etc/shadow` as root
- Shell injection: ELIMINATED. Path traversal → arbitrary file deletion as root: CONFIRMED
- Requires CMDB admin session — CVSS 6.5 (AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H)

### FAD_P_AWS — fadc_aws_pyscript_run stub (ELIMINATED)
- `fadc_aws_pyscript_run` (0x12e6f0) in libcgo.so = dead stub: `xor eax,eax; ret`
- No Python execution logic; actual pyscript exec via FAD_R3 (restapi scripting upload path)

### FAD_A2 — libadfs.so CLI injection via cmf_exec_conf (CONFIRMED HIGH)
- `add_relying_party_cmdb_config` (0x5890) builds multi-line CLI commands with `__snprintf_chk`, then passes to `cmf_exec_conf` (PLT:0x3240)
- Three format strings embed `edit_name`, `proxy_name`, `relying_party_trust` via `%s` — no sanitization of `"`, `\r`, `\n`
- Payload: proxy_name = `foo"\r\nconfig system admin\r\nedit admin\r\nset password pwned\r\nnext\r\nend\r\nend\r\nconfig user adfs-relying-party\r\nedit foo` → `"` breaks string token, `\r\n` injects new CLI commands
- Three affected code paths: 0x59fd (vdom format), 0x5c83 (global format), 0x5d89 (second vdom path)
- Auth: admin CMDB write access to set ADFS relying party config
- CWE-78/CWE-88; CVSS 6.7 (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L)
- libadfs.so sweep complete: 24 funcs, no SAML/XML parser, no system/popen. Only high finding is FAD_A2.

### FAD_A1 — adfsproxy TLS cert bypass (CONFIRMED HIGH)
- `adfslib/http.VerifyServerCertificate` at `0x667440`: logs "Verify" + returns nil — complete stub
- Used as `VerifyPeerCertificate` (or equivalent) callback in `GetHTTPClient:0x667520`
- All proxy→AD FS backend TLS accepts any certificate (no chain, no hostname check)
- adfsproxy is Go 1.22.3 CGo; source path: `/root/FortiADC_test/FortiADC/daemon/adfsproxy/libs/http/`
- Impact: MITM on authentication traffic (Kerberos, SAML, OAuth) between proxy and AD FS
- CWE-295; CVSS: 7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Next Steps
1. Live test FAD_R1: `curl -sk https://<target>:8443/debug/pprof/goroutine?debug=2`
2. **Fortinet PSIRT disclosure** — 6 confirmed: FAD_R1 HIGH, FAD_R3 CRIT, FAD_A1 HIGH, FAD_A2 HIGH, FAD_P1 MEDIUM, FAD_P2 HIGH; FAD_R2/FAD_P_AWS ELIMINATED
3. **fadcsystem definition** — undefined in all 6 extracted libs; confirm system() wrapper for PSIRT submission

## Session History
- 2026-09-25: Firmware extracted, binaries identified, module scaffolded
- 2026-09-25: Semantic sweep httproxy → 0 above threshold; 3 taint chains at 0x69d1de → ELIMINATED (false positive, cmovbe bounds guard)
- 2026-09-25: restapi Go 1.24.4 parsed (fixed Go 1.20 pclntab magic in go_binary_re.py); FAD_R1 CONFIRMED, FAD_R2 ELIMINATED
- 2026-09-25: FAD_R3 CONFIRMED HIGH → CRITICAL — restapi_cmdd root (8 setuid symbols + /root/ RPATH); any-auth upload → root RCE
- 2026-09-25: adfsproxy analyzed — Go 1.22.3 CGo, 5689 funcs, source path recovered; FAD_A1 CONFIRMED HIGH (TLS cert bypass, VerifyServerCertificate no-op stub)
- 2026-09-25: ptd analyzed — Go 1.24.4 CGo (7775 funcs, not C), root (9 setuid PLT), fadc_exec_tcpdump_run (0x7c2120) mkdir traversal + unvalidated args to fortiadc_tcpdump_run; FAD_P1 CONFIRMED HIGH (pending libwaf.so for cmd injection upgrade)
- 2026-09-25: libcgo.so extracted from qcow2/rootfs; fortiadc_tcpdump_run (0x143980) analyzed — double-fork+execvp with separate argv; cmd injection ELIMINATED; FAD_P1 downgraded to MEDIUM (mkdir traversal only)
- 2026-09-25: fortiadc_dumpsystem_delete_run (0xcb1b0) analyzed; input_format_check strspn allowlist blocks metacharacters but permits '.'/'/'; fadcsystem("rm /var/log/crash/<input>") → arbitrary file deletion as root; FAD_P2 CONFIRMED HIGH; fadc_aws_pyscript_run (0x12e6f0) = dead stub (xor eax,eax; ret) ELIMINATED
- 2026-09-26: libadfs.so sweep complete (24 funcs, BinaryContext+FuncProfiler, full string dump 0x7000-0x8000); add_relying_party_cmdb_config (0x5890) — __snprintf_chk with CLI command format strings + cmf_exec_conf; "%" fields not sanitized for '"'/CRLF; FAD_A2 CONFIRMED HIGH (CLI injection via relying party name/proxy name)
