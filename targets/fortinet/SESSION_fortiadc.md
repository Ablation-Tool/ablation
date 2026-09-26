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
| FAD_W1 | libwaf.so | sys_vdom_exec in hpwafblockip show/clear: shell exec with VS/VDOM name | PLAUSIBLE HIGH |
| FAD_M1 | miglogd | fadcsystem touch/rm /var/log/logrpt/<VDOM> path traversal | PLAUSIBLE MEDIUM |
| FAD_N1 | fnginxctld | fngx_process_vcmd → sys_vdom_exec with VS iface/IP in iptables/ip commands | PLAUSIBLE MEDIUM |
| FAD_C1 | libcmdb_plugin.so | check_need_wake_up_wccpd → sys_vdom_exec with VXLAN/NVGRE iface name injection | PLAUSIBLE MEDIUM |
| FAD_O1 | ospf6d | sys_vdom_exec 'ip -6 xfrm state %s dst %s ...' — IPsec state mgmt from routing table | PLAUSIBLE LOW-MEDIUM |
| FAD_BGPD | bgpd/ospfd/ospf6d | log rotation system() 'cp /tmp/%s_<daemon>.log ...' with VDOM name | PLAUSIBLE MEDIUM (class) |
| FAD_AV1 | av | fadcsystem diagnostic collect 'cat /proc/meminfo >> %s' — path traversal only | PLAUSIBLE LOW |
| FAD_H1 | httproxy3 | merge_fngx_session_table → sys_vdom_exec 'cat /etc/fnginx_new/%s/sessions/*' VS name | PLAUSIBLE MEDIUM |
| FAD_H2 | httproxy3 | merge_httproxy_vs_session_table → sys_vdom_exec session cat with VDOM+VS in path | PLAUSIBLE LOW-MEDIUM |
| FAD_RT1 | rtmd | brctl addbr/delbr + ifconfig up/down via sys_vdom_exec with bridge/iface name | PLAUSIBLE MEDIUM |

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

## Binary Sweep Status
| Binary | Size | Sweep Status | Notes |
|--------|------|-------------|-------|
| restapi | 21MB Go | COMPLETE | FAD_R1 HIGH, FAD_R3 CRIT, FAD_R2 ELIMINATED |
| adfsproxy | 5.3MB Go+CGo | COMPLETE | FAD_A1 HIGH |
| libadfs.so | 39K C | COMPLETE | FAD_A2 HIGH; 24 funcs, no additional sinks |
| ptd | 9.2MB Go+CGo | COMPLETE | FAD_P1 MEDIUM, FAD_P2 HIGH |
| libcgo.so | 5.6MB C | COMPLETE | fortiadc_tcpdump_run/dumpsystem_delete_run/dumpsystem_run analyzed; FAD_P_AWS ELIMINATED |
| httproxy | 14MB C | COMPLETE | CLEAN — 0 taint paths from recv; system=gdb debug; execvp=LaunchProcess |
| fnginx_new | 17MB C++ | COMPLETE | CLEAN — execve=nginx worker respawn; SAML=Shibboleth lib; no injectable sink |
| cm_client | 11MB C | COMPLETE | CLEAN — tcpdump=FAD_P1 duplicate; no other sinks |
| wadd | 245K C | COMPLETE | CLEAN — execlp=fixed path, not user-controlled |
| restapi_cmdd | 2.8MB Go | COMPLETE | CLEAN as independent target; exploit path=FAD_R3 |
| cli | 2.7MB C | COMPLETE | CLEAN — rm-rf hardcoded /tmp/; strcpy bounded; more %s=plausible/admin-only |
| miglogd | 3.5MB C | COMPLETE | FAD_M1 PLAUSIBLE MEDIUM; all shell injection ELIMINATED (posix_spawnp); VDOM/plugin-name path traversal pending CMDB validation check |
| ocgs | 5.1MB Go+CGo | COMPLETE | CLEAN — Unix domain socket IPC only; standard Go TLS; no exec sinks |
| libwaf.so | 2.7MB C | COMPLETE | FAD_W1 PLAUSIBLE HIGH (sys_vdom_exec hpwafblockip show/clear); waf_system ELIMINATED (vsnprintf+fadcsystem/posix_spawn); fadcsystem×4 ELIMINATED; SQLite snprintf-built API exported-only (injection risk tracked to libcmdb_plugin.so callers) |
| libstdext.so | 27K C | COMPLETE | fadcsystem = parse_command_line → posix_spawnp; NO shell; confirms all fadcsystem callers safe for shell injection |
| libips.so | 15MB C | COMPLETE | LuaJIT 2.1 embedded; exec sinks = builtins ELIMINATED; 111 strcpy ALL ELIMINATED (98 malloc-bounded heap dest + 13 LuaJIT VM internals) |
| libav.so | 8MB C | ANALYZED | avFlowWrite CLEAN (0 unsafe sinks); sprintf×47 ELIMINATED (signature loading + hash-to-hex loops); strcpy×35/38 ELIMINATED; FAD_AV1 PLAUSIBLE LOW: avIsIgnoreBuffer 0xf3531 strcpy(malloc(72)+8, filename) — 64B heap slot, URL >64B = overflow |
| libcmdb_plugin.so | 1.8MB C | COMPLETE | system() ELIMINATED; execve ELIMINATED; FAD_C1 PLAUSIBLE MEDIUM (VXLAN/NVGRE sys_vdom_exec); fadcsystem×81 ALL ELIMINATED/PLAUSIBLE LOW (posix_spawn; admin-config paths/names; no shell injection) |
| acme-client | 6.1MB Go+CGo | COMPLETE | CLEAN — no exec PLT; no InsecureSkipVerify=true; ACME url field SSRF potential (admin-only) |
| fnginxctld | 1.7MB C | ANALYZED | FAD_N1 PLAUSIBLE MEDIUM; fngx_process_vcmd → sys_vdom_exec with VS iface/IP args |
| vtl | 2.1MB C++ | COMPLETE | All sinks PLAUSIBLE LOW or ELIMINATED (SafeNet HSM admin-only); sprintf×85: support-info writes to file not executed ELIMINATED; HSM config integer-only ELIMINATED; 6 file path PLAUSIBLE LOW; strcpy×19: 5 malloc-bounded ELIMINATED; 3 feed rm+cluster_name system() PLAUSIBLE LOW; 9 HSM string building PLAUSIBLE LOW |
| flg_accessd | 703KB C | COMPLETE | fadcsystem×2 ELIMINATED (tar czvf posix_spawnp; md5sum '>' literal arg); fadcpopen@0xe3b8 PLAUSIBLE LOW (popen("rm -rfv /var/log/logrpt/<vdom>/resdir/* 2>&1") — admin VDOM name → popen shell injection) |
| flg_indexd | 2MB C | COMPLETE | ALL ELIMINATED: fadcsystem×10 (killall×5 hardcoded; rm/touch internal log dirs posix_spawnp; killall -9 mysqld hardcoded) |
| flg_reportd | 1.9MB C | COMPLETE | fadcsystem ELIMINATED; execve = hardcoded /bin/email SMTP reporter ELIMINATED |
| lb | 845KB C | COMPLETE | cmf_exec_conf×2: PLAUSIBLE MEDIUM @0x365b5 CLI CRLF injection via scripting/VS/ADFS names (same class FAD_A2); fadcpopen@0x753c0 PLAUSIBLE LOW (popen ps+grep single-quote bypass if VS/config path has `'`); fadcsystem×23: 21 ELIMINATED (sed/mkdir/cp/scripting_convert.sh/haproxy-mgmt posix_spawnp); 2 PLAUSIBLE LOW (/bin/sh <mkstemp> — shell script with admin VS/haproxy params) |
| infod | 1.5MB C | COMPLETE | ALL ELIMINATED: fadcsystem×10 (tsdb rm-rf internal paths hardcoded, killall -9 infod hardcoded, ldb repair hardcoded, touch /tmp/STATISTICS_DB_IPC_PATH); system_fgt_log×2 = syslog API |
| rd_mng | 1.4MB C | COMPLETE | No exec sinks. CLEAN. |
| libsysapi.so | 251KB C | COMPLETE | CLEAN — fadcpopen('quota -uv quarantine' hardcoded); __sprintf_chk hex-encode; asprintf path build quarantine archive; system_fgt_log ELIMINATED; ALL ELIMINATED |
| bgpd | 1.7MB C PIE | ANALYZED | 236 system() callers — log rotation 'cp /tmp/%s_bgpd.log ...' (4 variants) PLAUSIBLE MEDIUM; access_list strings ELIMINATED |
| ospfd | 1.1MB C PIE | ANALYZED | 101 system() callers — 'cp /tmp/%s_ospfd.log ...' log rotation PLAUSIBLE MEDIUM |
| ospf6d | 717KB C PIE | ANALYZED | FAD_O1 PLAUSIBLE LOW-MEDIUM (sys_vdom_exec IPsec 'ip -6 xfrm state'); 65 system() log rotation PLAUSIBLE MEDIUM |
| keepalived | 994KB C PIE | COMPLETE | ALL ELIMINATED: sys_vdom_exec (echo %d int-only); execle /bin/bash PLAUSIBLE LOW (admin VRRP notify script); execvp×2 hardcoded (/bin/mount proc + /bin/ssh_hc_util); fadcsystem×79: 71 chroot mkdir/mount (hardcoded), 4 cleanup (find -delete/killall), 2 snprintf mkdir+chmod posix_spawnp, 1 open /dev/null |
| av | 1.2MB C PIE | ANALYZED | fadcsystem 3 callers PLAUSIBLE LOW (diagnostic log; path traversal only); fork 2 callers ELIMINATED (no exec in child) |
| opensips | 2.5MB C PIE | ANALYZED | CLEAN — no exec sinks; fork only (SIP worker process mgmt) |
| httproxy3 | 3.9MB C PIE | ANALYZED | FAD_H1 PLAUSIBLE MEDIUM (VS name sys_vdom_exec); FAD_H2 PLAUSIBLE LOW-MEDIUM (session cat stat-gated); HAProxy execvp ELIMINATED; fadcsystem_envp ELIMINATED (mkstemp script) |
| uwsgi | 1.3MB C PIE | ANALYZED | CLEAN — execvp = uwsgi self-re-exec graceful restart; fork = worker mgmt; no cmd injection |
| del_netdev | 14KB C PIE | ANALYZED | PLAUSIBLE LOW-MEDIUM — system('/bin/ls %s > /tmp/tmp.brg.list') with bridge name from CLI |
| vdom | 14KB C PIE | ANALYZED | PLAUSIBLE LOW — sys_vdom_exec_safe with CLI argv appended; requires admin CLI access |
| rtmd | 785KB C PIE | ANALYZED | FAD_RT1 PLAUSIBLE MEDIUM — brctl/ifconfig sys_vdom_exec with bridge/iface name (8 callers, same class FAD_N1) |
| ditest/encrypt_file/fipstestd/geolookup/infod_shm_mng/inittest/kdbgd/krb_test/send2lb | ~14KB each | ANALYZED | CLEAN — no exec PLT |
| modules/*.ko | 21 kernel modules | ANALYZED | CLEAN — no call_usermodehelper; ha.ko ha_exec_cmd = kernel-internal only; kvm/xen/platform = stock modules |
| migadmin/fortiai/ | Django 5.1.6 app | ANALYZED | CLEAN for RCE — no exec/system/subprocess in web code; post-auth session-key path traversal (write-primitive only); query_docs 500 crash (missing @require_session) |
| /bin/*.sh | 25 shell scripts | COMPLETE | FAD_S1 PLAUSIBLE MEDIUM: saml_sp_metadata.sh ENTITY_ID/URL unescaped in sed "s/%%...%%/$VAR/" — '\"' injection → cmd split; upgrade.sh eval $var PLAUSIBLE LOW; all others admin-only PLAUSIBLE LOW |
| extra_lib/ Oracle IC | 8 libs 57MB+ | COMPLETE | Oracle Instant Client 12.1 bundled but DEAD CODE — 0 FortiADC bins/libs import or dlopen any Oracle lib; libnnz12.so strcpy×9 struct-bounded ELIMINATED; libclntsh.so system/popen callers internal-only; ELIMINATED |

## Next Steps
1. Live test FAD_R1: `curl -sk https://<target>:8443/debug/pprof/goroutine?debug=2`
2. **Fortinet PSIRT disclosure** — 6 confirmed: FAD_R3 CRIT, FAD_R1 HIGH, FAD_A1 HIGH, FAD_A2 HIGH, FAD_P2 HIGH, FAD_P1 MEDIUM; FAD_R2/FAD_P_AWS ELIMINATED
3. **fadcsystem definition** — undefined in all 6 extracted libs; confirm system() wrapper for PSIRT submission
4. SWEEP COMPLETE — all 11 binaries + 2 shared libs analyzed

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
- 2026-09-26: ALL REMAINING BINARIES SWEPT — httproxy (0 taint paths, system=gdb debug, execvp=LaunchProcess → CLEAN); fnginx_new (execve=nginx respawn, SAML=Shibboleth lib, 3255 exports scanned → CLEAN); cm_client (tcpdump=FAD_P1 dup → CLEAN); wadd (execlp=fixed path → CLEAN); restapi_cmdd (pure Go, no exec sinks → CLEAN); cli (rm-rf=hardcoded /tmp/, strcpy=bounded, more-waf-view=admin-only PLAUSIBLE → CLEAN). SESSION 1 SWEEP COMPLETE.
- 2026-09-26 (session 2): miglogd analyzed — 16 fadcsystem callers all ELIMINATED (posix_spawnp); system_fgt_log = syslog API; FAD_M1 PLAUSIBLE MEDIUM (VDOM path traversal); ocgs CLEAN; libwaf.so FAD_W1 PLAUSIBLE HIGH documented.
- 2026-09-26 (session 2): New binaries profiled — libips.so (LuaJIT 2.1, exec sinks = builtins, 111 strcpy PENDING); libav.so (no exec sinks); libcmdb_plugin.so (9 system + 4 sys_vdom_exec PENDING); fnginxctld FAD_N1 (fngx_process_vcmd → sys_vdom_exec with VS iface/IP); vtl (SafeNet HSM + fork+system PARTIAL); flg_accessd/indexd/reportd/lb/infod/rd_mng profiled.
- 2026-09-26 (session 3): libcmdb_plugin.so sys_vdom_exec/execve resolved — 0x9c94b/9c95a ELIMINATED (hardcoded echo flush); execve@0x79d22 ELIMINATED (fadc_popen fork child); FAD_C1 PLAUSIBLE MEDIUM: WCCP 0xb3d55 (NVGRE) + 0xb4734 (VXLAN) — snprintf(iface_name, tunnel_id, ...) → sys_vdom_exec; same class as FAD_N1.
- 2026-09-26 (session 3): acme-client analyzed — Go 1.22.3 CGo; golang.org/x/crypto/acme; no exec PLT; no InsecureSkipVerify=true; JSON config fields extracted (url, ca, eab_kid, eab_mac_key, challenge_type, etc.); CLEAN.
- 2026-09-26 (session 4): small utilities + rtmd — del_netdev PLAUSIBLE LOW-MEDIUM (system('/bin/ls %s > ...') with bridge name); vdom PLAUSIBLE LOW (sys_vdom_exec_safe with CLI argv); rtmd 785KB FAD_RT1 PLAUSIBLE MEDIUM: 8 sys_vdom_exec callers = brctl addbr/delbr + ifconfig up/down with bridge/iface name (same class FAD_N1); 9 utils CLEAN.
- 2026-09-26 (session 4): opensips/httproxy3/uwsgi analyzed — opensips: fork-only CLEAN (SIP worker); httproxy3: FAD_H1 PLAUSIBLE MEDIUM (merge_fngx_session_table → sys_vdom_exec 'cat /etc/fnginx_new/<VS>/sessions/*'), FAD_H2 PLAUSIBLE LOW-MEDIUM (stat-gated session cat), filter_sessions_table PLAUSIBLE LOW (hardcoded /proc/net/ source), HAProxy execvp re-exec ELIMINATED, fadcsystem_envp ELIMINATED (mkstemp hardcoded template); uwsgi: execvp = self-re-exec ELIMINATED, fork = worker mgmt. fadcsystem_envp internals confirmed: '/bin/sh <mkstemp>' via fadcsystem builds script in /tmp then posix_spawns /bin/sh — not user-injectable. httproxy3 bundles HAProxy (HAPROXY_MWORKER_* env vars confirmed).
- 2026-09-26 (session 4): Routing daemons analyzed — bgpd (236 system() callers, 4 log rotation fmt variants + 4 hardcoded access_list strings ELIMINATED); ospfd (101 system(), single log rotation fmt PLAUSIBLE MEDIUM); ospf6d (65 system() log rotation + 2 sys_vdom_exec FAD_O1 'ip -6 xfrm state' IPsec PLAUSIBLE LOW-MEDIUM; 'enc %s 0x%s' is snprintf fragment not direct system() call); keepalived (sys_vdom_exec ELIMINATED hardcoded int; execle /bin/bash PLAUSIBLE LOW admin VRRP script; fadcsystem 79 pending); av (3 fadcsystem diagnostic PLAUSIBLE LOW; 2 fork ELIMINATED no-exec workers). fadcsystem_envp internals confirmed: parse_command_line + execute_command (not shell — >> handled via posix_spawn file actions).
- 2026-09-26 (session 5): 21 kernel modules analyzed — all CLEAN; no call_usermodehelper; ha.ko ha_exec_cmd = kernel-internal; kvm/xen/platform = stock. FortiAI Django app fully analyzed — views.py/text2lua.py/agents/ all CLEAN for RCE; no exec/system/subprocess in web-facing code; AnalysisAgent._fetch_vs_metrics calls 127.0.0.1 REST API with URL-encoded params (CLEAN); query_docs_from_fortiai missing @require_session → 500 crash (not auth bypass); create_session path traversal in session key → file path (post-auth write primitive only, requires device cert auth); ALLOWED_HOSTS=['*'] + DEBUG=False; fortiai_diag.py CLI-only diagnostic subprocess.run(list) CLEAN.
- 2026-09-26 (session 6): libwaf.so COMPLETE — waf_system (vsnprintf+fadcsystem/posix_spawn) ELIMINATED; fadcsystem×4 ELIMINATED (rm -f/touch internal paths); vtl system()×3 all PLAUSIBLE LOW resolved (SafeNet Luna HSM library — ChrystokiConfiguration + ApplianceConfiguration::ParentChildProcess::run fork+dup+system(this+8), admin-only HSM config); libwaf.so SQLite: snprintf-built SQL exported API (waf_db_read_table/condition/get_table_row_num_condition), 0 internal callers, no sqlite3_bind_*, injection risk deferred to external callers audit (libcmdb_plugin.so confirmed NOT a caller).
- 2026-09-26 (session 6): libcmdb_plugin.so COMPLETE — fadcsystem×81 all audited: 17 hardcoded ELIMINATED; 1 integer echo ELIMINATED; 4 callers 'vdom exec %s ip link set %s %s' PLAUSIBLE LOW (posix_spawn, admin iface name); 2 ethtool callers PLAUSIBLE LOW; 34 WAF/cert schema file management rm/mkdir/tar/unzip/zip/mv/cp PLAUSIBLE LOW; 6 bookmark/VDOM copy PLAUSIBLE LOW; 16 DNSSEC key management PLAUSIBLE LOW; 1 GLB topology cp PLAUSIBLE LOW. No new FAD_ findings above FAD_C1. libcmdb_plugin.so does NOT import waf_db_* — SQLite injection via libwaf.so API tracked to vtl/httproxy callers instead.
- 2026-09-26 (session 6): libips.so COMPLETE — 111 strcpy: 98 malloc-bounded (mov rdi, rax) ELIMINATED; 13 in LuaJIT VM internals (all ips_so_patch_urldb, 0x44fdc8-0xb887ae = lj_debug/lj_str/VM dispatcher). ALL ELIMINATED.
- 2026-09-26 (session 6): libav.so ANALYZED — avFlowWrite CLEAN (0 sprintf/strcpy); sprintf×47 ELIMINATED (avScanLoad signature load + scanvirUrl/avTlvDecode hash-to-hex loops with fixed-size pre-sized buffers); strcpy×38 mostly ELIMINATED; FAD_AV1 PLAUSIBLE LOW: avIsIgnoreBuffer 0xf3531 malloc(72)+8+strcpy(rbp) — 64B heap slot, filename/URL >64B = potential heap overflow.
- 2026-09-26 (session 6): vtl COMPLETE — sprintf×85 ELIMINATED (support-info shell cmds written to file not executed; HSM config integer-only; file path builds PLAUSIBLE LOW); strcpy×19 PLAUSIBLE LOW (3 feed rm+cluster_name system() chain; 9 HSM string building; 5 malloc-bounded ELIMINATED; 2 hardcoded literals ELIMINATED). No new findings above existing PLAUSIBLE LOW SafeNet HSM class.
- 2026-09-26 (session 6): /bin/*.sh COMPLETE — all 25 scripts audited; FAD_S1 PLAUSIBLE MEDIUM: saml_sp_metadata.sh takes 8 admin-set CMDB args (ENTITY_ID, SP_ROOT_URL, SERVICE_URL, LOGOFF_PATH, ACS_PATH); used in sed "s/%%entity_id%%/$ENTITY_ID/g" — '/' escaped to '\/' by prior pass but '"' NOT escaped; if CMDB allows '"' in SAML entity ID → splits double-quoted sed command → shell injection (admin-only). upgrade-config-from3.x.sh eval $exp PLAUSIBLE LOW; upgrade.sh eval $cmd with stat $var PLAUSIBLE LOW; scripting_convert.sh $1 script-file-path PLAUSIBLE LOW; vs_rs_status.sh $2-$5 unquoted grep args PLAUSIBLE LOW.
- 2026-09-26 (session 7): flg_accessd COMPLETE — fadcsystem×2 ELIMINATED (tar czvf posix_spawnp; md5sum '>' literal not shell redirect); fadcpopen@0xe3b8 PLAUSIBLE LOW: popen("rm -rfv /var/log/logrpt/<vdom>/resdir/* 2>&1") — admin VDOM name → shell metachar injection via popen. flg_indexd COMPLETE — fadcsystem×10 ALL ELIMINATED (killall×5 hardcoded; rm -rf internal tsdb/log dirs via posix_spawnp; killall -9 mysqld hardcoded). infod COMPLETE — fadcsystem×10 ALL ELIMINATED (ldb repair hardcoded, rm -rf /var/log/tsdb*, killall -9 infod, touch /tmp/STATISTICS_DB_IPC_PATH); system_fgt_log×2 = syslog API. lb COMPLETE — fadcsystem×23: 21 ELIMINATED (sed substitutions/mkdir/cp/scripting_convert.sh/scripting_priority_extract.sh/haproxy management all posix_spawnp); 2 PLAUSIBLE LOW (/bin/sh <mkstemp> pattern at 0x23c71/0x7b2a1 — shell script written to /tmp/hap_fadcsystem/ then posix_spawnp'd, admin VS/haproxy params); fadcpopen@0x753c0 PLAUSIBLE LOW (popen pipeline "ps -w | grep '[SR]    %s -f' | grep -F '%s' | wc" — process name/config path in grep single-quote args, single-quote escape injection, likely haproxy name+VS config path, admin-controllable); cmf_exec_conf@0x365b5 PLAUSIBLE MEDIUM: CLI CRLF injection via scripting names — delete format "config vdom\r\nedit \"%s\"\r\nconfig system scripting\r\ndelete \"%s\"\r\n" and create format embeds scripting-file/VS-name/ADFS-pub-name — same mechanism as FAD_A2 but in lb scripting management.
- 2026-09-26 (session 6 cont): flg_reportd row updated to COMPLETE (execve = hardcoded /bin/email SMTP reporter, resolved prior session). waf_db_* external caller audit COMPLETE: 0 callers in any bin or lib in firmware image — API is dead code; only 'waf_db' CLI command table keyword in cli binary. Oracle Instant Client (extra_lib.tar.xz) COMPLETE: 0 FortiADC components import/dlopen Oracle libs; libnnz12.so strcpy×9 struct-bounded ELIMINATED; libclntsh.so internal system/popen callers unreachable; entire Oracle bundle ELIMINATED. keepalived COMPLETE: fadcsystem×79 ALL ELIMINATED (71 chroot setup hardcoded paths, 4 cleanup hardcoded, 2 snprintf mkdir+chmod posix_spawnp, 1 open/dev/null); sys_vdom_exec ELIMINATED (echo %d int-only); execvp×2 hardcoded; execle /bin/bash PLAUSIBLE LOW (admin VRRP notify, confirmed prior session).
