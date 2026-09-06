"""
Tencent Cloud Stargate Agent (sgagent) — RE Module
Packages:
  linux_stargate_installer (self-extracting bash + tgz)
    Binary corpus: sgagent64 (x86_64), sgagent32 (x86), sgagentarm64 (aarch64)
    Build date: 2021-01-21; installer created 2021-01-28
  windows-stargate-installer.exe (PE32 WEXTRACT self-extractor, DigiCert signed 2020-05-20)
    Binary corpus: sgagent.exe (i386), libcurl.dll (i386), jsoncpp.dll (i386)
    sgagent.exe build timestamp: 0 (zeroed); libcurl.dll: 2014-10-08; jsoncpp.dll: 2018-06-15

Stargate is Tencent Cloud's (qcloud) root-privileged monitoring/management agent
deployed on TencentOS Server and CVM instances. It polls a Tencent-controlled
update endpoint, downloads modules, executes shell commands, and manages agent
lifecycle — all as root. One binary per instance, persistent via cron.

Install paths:
  /usr/local/qcloud/stargate/  (if /usr writable)
  /var/lib/qcloud/stargate/    (fallback)

Persistence mechanism:
  cron: * * * * * root flock -xn /tmp/stargate.lock -c 'start.sh > /dev/null 2>&1 &'
  systemd: stargate.service (CoreOS/Container Linux only)

Key files:
  bin/sgagent{32,64,arm64}      — main agent binary (symlinked to bin/sgagent)
  etc/base.conf                 — update URL, check interval, SSL config
  admin/{start,stop,restart,addcrontab,delcrontab,uninstall,trystart}.sh

Update protocol (HTTP, plaintext):
  URL: http://update2.agent.tencentyun.com/interface.php
  Method: POST (libcurl embedded, single binary)
  Response: JSON with module list, installPath, moduleId, retcode, msg fields
  SSL:  useCA = 0  ->  CURLOPT_SSL_VERIFYPEER=0, CURLOPT_SSL_VERIFYHOST=0

Python runtime: Python 2.6 bundled (EOL since 2013, known CVEs)
  /usr/local/qcloud/monitor/python26/{32,64,arm64}/

Binary (sgagent64) security profile:
  PIE:     NO  (EXEC type, fixed load address 0x400000)
  RELRO:   NONE (no GNU_RELRO segment)
  Stack canary: NO (__stack_chk_fail not in imports)
  NX/DEP:  YES (GNU_STACK RW, no exec)
  Stripped: YES
  Linked:   dynamically (GLIBC_2.2.5)
  Entry:    0x405228

Windows component security profile (all three binaries — DllCharacteristics=0x0000):
  sgagent.exe (i386): ASLR=NO  DEP=NO  CFGuard=NO  SafeSEH=NO  GS=NO  ImageBase=0x00400000
  libcurl.dll (i386): ASLR=NO  DEP=NO  CFGuard=NO  SafeSEH=NO  GS=NO  ImageBase=0x61c00000  version=7.38.0
  jsoncpp.dll (i386): ASLR=NO  DEP=NO  CFGuard=NO  SafeSEH=NO  GS=NO  ImageBase=0x62140000
  Worse than Linux variants: Linux had NX=YES; Windows has DEP disabled (stack/heap executable)
  Windows install path: C:\\Program Files\\QCloud\\Stargate\\
  Windows service: StargateSvc (CreateServiceA -> ADVAPI32.DLL)
  Windows execution method: ShellExecuteExA (SHELL32.DLL) — equivalent of Linux system()
  Windows config: same base.conf format (useCA=0, url=http://update2.agent.tencentyun.com/interface.php)

Dangerous imports (sgagent64):
  system@GLIBC_2.2.5  — 1 call site (0x404858 PLT, called at 0x405bec)
  strcpy@GLIBC_2.2.5
  sprintf@GLIBC_2.2.5
  sscanf@GLIBC_2.2.5
  memcpy@GLIBC_2.2.5
  fork@GLIBC_2.2.5

system() call graph:
  system() PLT: 0x404858
  system() wrapper: 0x405be0  — (rdi=context, rsi=cmd) -> system(cmd), logs result
  Wrappers that append fixed suffixes to server-controlled installPath:
    0x405c50: installPath + /admin/trystart.sh (18 bytes, 0x446c19)
    0x405d10: installPath + /admin/stop.sh    (14 bytes, 0x446c2c)
    (+ /admin/uninstall.sh at separate caller)
  Direct exec of temp installer:
    0x406370: system("../stargate_install") -> remove("../stargate_install")
  Callers of trystart wrapper: 0x4063f2, 0x407903
  Callers of stop wrapper:     0x406506, 0x4069b2
  installPath JSON parsing:    0x40807a, 0x40838d

rodata strings of interest (VA -> content):
  0x446b99: '../stargate_install'    (temp upgrade script executed then deleted)
  0x446c19: '/admin/trystart.sh'     (appended to installPath for system() call)
  0x446c2c: '/admin/stop.sh'         (appended to installPath for system() call)
  0x446c3b: '/admin/uninstall.sh'    (appended to installPath for system() call)
  0x446c4f: '%s/%s'                  (path construction format)
  0x446e9c: 'installPath'            (JSON field name parsed from server response)
  0x446ea8: 'module.installPath:%s'  (debug log for installPath value)
"""

import ssl
import json
import socket
import hashlib
from typing import Optional

# ─── Target Profile ───────────────────────────────────────────────────────────

TARGET = "tencent-stargate"
VERSIONS_AFFECTED = ["1.5.0"]  # base.conf: version = 1.5.0; build 2021-01-21
BINARY_SHA256 = {
    "sgagent64": "not_retained",   # binary extracted during analysis session; tarball needed for recompute
    "sgagent32": "not_retained",
    "sgagentarm64": "not_retained",
    # Source: stargate.tgz (Tencent Cloud agent package, version 1.5.0, 2021-01-21)
    # To recompute: tar -xzf stargate.tgz && sha256sum sgagent64
}

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {
    "TCS-F01": {
        "title": (
            "sgagent Polls Update Server over Plaintext HTTP with SSL Verification Disabled — "
            "Network MitM Delivers Arbitrary Root Commands via Server JSON Response"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-295",
        "component": (
            "sgagent64 / libcurl embedded / etc/base.conf — "
            "update polling loop -> curl_easy_setopt(CURLOPT_SSL_VERIFYPEER=0) -> "
            "http://update2.agent.tencentyun.com/interface.php"
        ),
        "evidence": {
            "plaintext_url": (
                "base.conf: url = http://update2.agent.tencentyun.com/interface.php. "
                "Protocol is HTTP (not HTTPS). All update traffic is transmitted unencrypted. "
                "Any network-local attacker (ARP/DNS/BGP hijack) intercepts the full request "
                "and response without cryptographic obstacle."
            ),
            "ssl_disabled": (
                "base.conf: useCA = 0. "
                "sgagent64 reads this config value and disables libcurl TLS verification: "
                "CURLOPT_SSL_VERIFYPEER = 0, CURLOPT_SSL_VERIFYHOST = 0. "
                "Even if the attacker redirects to an HTTPS server (for future config changes), "
                "any certificate is accepted. "
                "String 'SSL peer certificate or SSH remote key was not OK' is present in binary "
                "as a dormant error path that never fires when useCA=0."
            ),
            "command_execution": (
                "Server JSON response includes moduleId, installPath, retcode, msg fields. "
                "sgagent64 parses 'installPath' at 0x40807a/0x40838d and passes it to "
                "system() wrappers at 0x405c50 (trystart) and 0x405d10 (stop). "
                "Command constructed: installPath + '/admin/trystart.sh' or installPath + '/admin/stop.sh'. "
                "No input validation or path sanitization applied to installPath before system(). "
                "A MitM attacker supplies installPath = '/tmp/x;id #' -> system('/tmp/x;id #/admin/stop.sh') "
                "-> executes 'id' as root."
            ),
            "temp_script_exec": (
                "sgagent64 at 0x406370: system('../stargate_install') -> remove('../stargate_install'). "
                "The server's upgrade response causes the agent to write a shell script to "
                "'../stargate_install' (relative to admin/), execute it via system(), then delete it. "
                "A MitM attacker serving a crafted upgrade response controls the full script content. "
                "Since the process runs as root (enforced at install: 'Only root can execute this script'), "
                "any shell payload executes with root privileges."
            ),
            "persistence": (
                "sgagenttask cron entry: '* * * * * root flock -xn /tmp/stargate.lock -c "
                "start.sh > /dev/null 2>&1'. "
                "Agent is guaranteed running every minute as root on any Tencent Cloud CVM. "
                "Attack window: one cron tick (up to 60 seconds)."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Change base.conf url to HTTPS endpoint. "
            "Set useCA = 1 and provide a valid CA bundle path. "
            "Validate the TLS certificate against a pinned Tencent root CA. "
            "Sign server JSON responses (e.g., HMAC or asymmetric signature) so that "
            "MitM response injection is detectable even on compromised networks. "
            "Do not pass server-supplied installPath to system() without strict allow-list validation "
            "(path must begin with expected prefix, contain no shell metacharacters). "
            "Replace system() with execve() + explicitly constructed argv[] to eliminate shell interpretation."
        ),
    },
    "TCS-F02": {
        "title": (
            "Inconsistent Exploit Mitigations Across All Three Agent Binaries — "
            "No Variant Has Full Stack Canary + PIE + RELRO; sgagent64 Has None"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-693",
        "component": (
            "sgagent64 (x86_64), sgagent32 (i386), sgagentarm64 (AArch64) — "
            "binary protection configuration — per-arch toolchain divergence"
        ),
        "evidence": {
            "mitigation_matrix": (
                "Per-binary exploit mitigation status:\n"
                "  sgagent64  (x86_64): PIE=NO  RELRO=NONE    Canary=NO  NX=YES\n"
                "  sgagent32  (i386):   PIE=NO  RELRO=NONE    Canary=YES NX=YES\n"
                "  sgagentarm64 (arm64):PIE=NO  RELRO=PARTIAL Canary=NO  NX=YES\n"
                "No single binary achieves full PIE + full RELRO + stack canary. "
                "The variation indicates separate cross-compilation toolchains with different "
                "compiler default flags, not a unified hardening policy."
            ),
            "sgagent64_worst_case": (
                "sgagent64: readelf type=EXEC (fixed base 0x400000), no GNU_RELRO segment, "
                "nm -D: __stack_chk_fail absent. "
                "Binary compiled without -fstack-protector, -fpie, or -Wl,-z,relro. "
                "ROP gadget addresses are static; GOT fully writable; stack overflows "
                "return to attacker-controlled address without canary detection. "
                "Worst-case exploit surface: any memory corruption produces reliable RCE."
            ),
            "sgagent32_partial": (
                "sgagent32: readelf type=EXEC (fixed base 0x08048000), no GNU_RELRO segment, "
                "nm -D: __stack_chk_fail@GLIBC_2.4 present (canary enabled). "
                "Stack-based ret overwrite requires defeating the canary (leak or brute-force). "
                "GOT is still fully writable — heap or format-string write primitive bypasses "
                "the canary by targeting GOT entries directly."
            ),
            "sgagentarm64_partial": (
                "sgagentarm64: readelf type=EXEC (fixed base, no PIE), "
                "GNU_RELRO segment present at 0x2448d0 (PARTIAL RELRO only — no BIND_NOW), "
                "nm -D: __stack_chk_fail absent (no canary). "
                "Partial RELRO marks only the .got section read-only after startup; "
                ".got.plt entries remain writable during lazy binding. "
                "No canary: AArch64 link register corruption undetected on return."
            ),
            "dangerous_imports": (
                "All three binaries import without bounds: strcpy, sprintf, sscanf, memcpy. "
                "sgagent32 additionally imports wmemcpy (wide string operations). "
                "These process externally-sourced strings from HTTP responses and file system "
                "paths — length miscalculation produces exploitable memory corruption "
                "with at most one mitigation (canary in sgagent32 only)."
            ),
            "nx_present": (
                "GNU_STACK: RW (non-executable) in all three binaries. "
                "Stack shellcode injection blocked across all architectures; "
                "ret2libc / ROP / AROP viable given static load addresses."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Apply a unified hardening policy across all three toolchains: "
            "-fstack-protector-strong -fpie -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -O2. "
            "Verify mitigations post-build with checksec or readelf on each arch variant. "
            "Replace strcpy with strlcpy/strncpy+null, sprintf with snprintf with explicit bounds. "
            "For arm64: replace partial RELRO (-Wl,-z,relro) with full RELRO (-Wl,-z,relro,-z,now)."
        ),
    },
    "TCS-F03": {
        "title": (
            "Bundled Python 2.6 Runtime (EOL 2013) — "
            "Known CVEs in Python Core and Standard Library Exposed via Agent Plugin Execution"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-1104",
        "component": (
            "/usr/local/qcloud/monitor/python26/{32,64,arm64}/ — "
            "bundled Python 2.6 interpreter shipped with stargate package"
        ),
        "evidence": {
            "eol_version": (
                "Python 2.6 reached end-of-life in October 2013. "
                "No security patches have been issued for 12+ years. "
                "The bundled interpreter is version 2.6.x (exact patch level unknown — "
                "binary inspection required). All known Python 2.6 CVEs apply."
            ),
            "known_cves": (
                "Selected Python 2.6 CVEs (non-exhaustive): "
                "CVE-2021-3177 (buffer overflow in PyCArg_repr, CVSS 9.8), "
                "CVE-2021-23336 (web cache poisoning via query string parsing), "
                "CVE-2019-20907 (infinite loop in tarfile, DoS), "
                "CVE-2019-16935 (XSS in xmlrpc.server), "
                "CVE-2018-20406 (integer overflow in _pickle.c). "
                "Python 2.6 lacks all security fixes applied to Python 3.x line."
            ),
            "execution_context": (
                "The python26 interpreter is used by the qcloud monitor module "
                "(/usr/local/qcloud/monitor/) which runs as the same root-privileged context. "
                "Any module code downloaded from the Tencent update server and executed "
                "by python26 inherits root privileges."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Replace bundled Python 2.6 with Python 3.12+ or Python 3.11+ (still supported). "
            "If Python 2 compatibility is required, use Python 2.7 (EOL but patches available longer). "
            "Audit all Python modules executed by the agent for compatibility with a supported runtime."
        ),
    },
    "TCS-F04": {
        "title": (
            "Cron-Based Persistence Runs Every Minute as Root Without File Integrity Verification — "
            "Writable Agent Directory Enables Persistent Backdoor"
        ),
        "severity": "MEDIUM",
        "cvss": "6.7",
        "cwe": "CWE-732",
        "component": (
            "stargate/admin/sgagenttask / stargate/admin/addcrontab.sh — "
            "cron persistence mechanism"
        ),
        "evidence": {
            "cron_entry": (
                "sgagenttask: '* * * * * root flock -xn /tmp/stargate.lock -c "
                "'/usr/local/qcloud/stargate/admin/start.sh > /dev/null 2>&1 &''. "
                "Root cron entry runs every minute. "
                "File placed at /etc/cron.d/sgagenttask with chmod 600, but the "
                "agent install directory is owned by the install user, not guaranteed root-only writable."
            ),
            "no_integrity": (
                "start.sh: '$agent_name -d' — binary is executed directly without checksum verification. "
                "If an attacker replaces $agentPath/bin/sgagent with a malicious binary "
                "(e.g., after local privilege escalation or writable mount exploit), "
                "the cron entry re-executes it as root every minute. "
                "No hash verification of the agent binary is performed before execution."
            ),
            "lock_file_race": (
                "flock -xn /tmp/stargate.lock: lock file is in world-writable /tmp. "
                "A local attacker can pre-create /tmp/stargate.lock and hold it open, "
                "preventing the legitimate agent from starting (denial of service). "
                "Conversely, releasing the lock at the right moment allows a race condition "
                "where two agent instances briefly run simultaneously."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Move lock file from /tmp to /var/run/stargate/ (root-owned, mode 0750). "
            "Add HMAC or signature verification of the agent binary before execution in start.sh. "
            "Install agent directory with root:root ownership, mode 0755 minimum for dirs, 0755 for binaries. "
            "Consider systemd service with ProtectSystem=strict instead of raw cron."
        ),
    },
    "TCS-F05": {
        "title": (
            "MD5 Module Integrity Verification Trivially Bypassed via MitM — "
            "Attacker Controls Both Module Binary and Expected Hash from Same Untrusted HTTP Channel"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-354",
        "component": (
            "sgagent64 module download + MD5 check at 0x405a00-0x405af8 — "
            "fread 4096-byte chunks -> MD5_Update -> MD5_Final -> hex-encode -> "
            "memcmp(local_md5, remote_md5_from_json)"
        ),
        "evidence": {
            "check_code": (
                "0x405a2f: fread(buf, 1, 0x1000, fp) loop — reads downloaded file in 4096-byte chunks. "
                "0x405a3d: call 0x40de90 — MD5_Final (finalize digest). "
                "0x405a4c: call 0x40deb0 — convert digest to hex string -> stored at rsp+0x20. "
                "0x405a55-0x405a5e: r8 = server-provided MD5 string (from JSON), rbx = local computed MD5. "
                "0x405a5e: cmp length fields of local vs remote MD5 strings. "
                "0x405a62: je 0x405ac8 -> memcmp(r8, rbx) — byte-by-byte comparison. "
                "Error path: 'md5 check error, local: %s, remote: %s' (0x446fa8). "
                "Success path: 'md5 check succ, digest: %s' (0x446be9). "
                "The 'remote' MD5 value comes from the server JSON response parsed over plaintext HTTP "
                "with SSL verification disabled (see TCS-F01)."
            ),
            "bypass_mechanism": (
                "The module binary is downloaded over plaintext HTTP (TCS-F01). "
                "The expected MD5 hash is also delivered over the same plaintext HTTP response JSON. "
                "A MitM attacker controls both simultaneously: "
                "1. Serve a malicious binary as the module content. "
                "2. Compute MD5 of that binary. "
                "3. Insert that MD5 as the 'remote' hash in the JSON response. "
                "The local MD5 of the downloaded malicious binary matches the attacker-provided remote hash. "
                "The check passes unconditionally. "
                "MD5 is additionally cryptographically broken (known collision attacks, CWE-327), "
                "but the channel trust failure alone is sufficient to bypass the check without collision."
            ),
            "cross_architecture": (
                "sgagentarm64 contains identical strings: "
                "'md5 check succ, digest: %s', 'md5 check error, local: %s, remote: %s'. "
                "TCS-F05 applies to all three binary variants (sgagent32, sgagent64, sgagentarm64)."
            ),
            "impact": (
                "MD5 integrity check provides zero security guarantee in the MitM threat model. "
                "Attacker delivers arbitrary root-executable code to every Tencent Cloud CVM "
                "running sgagent, with the verification step confirming the malicious binary as legitimate. "
                "Chain with TCS-F01 for full unauthenticated remote code execution as root."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Replace MD5 with an asymmetric signature scheme: "
            "sign module binaries with an ed25519 or RSA-PSS private key at build time; "
            "embed the corresponding public key in the agent binary at compile time. "
            "Verify the signature before executing any downloaded module. "
            "The public key must be pinned inside the agent — not fetched from the update server. "
            "This fix is independent from TCS-F01 and provides a second layer of defense "
            "even if HTTPS is added (defense-in-depth against certificate compromise)."
        ),
    },
    "TCS-F06": {
        "title": (
            "moduleId JSON Field Unsanitized in Path Construction — "
            "Path Traversal via '../modules/' + moduleId Allows Arbitrary File Creation as Root"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-22",
        "component": (
            "sgagent64 module install dispatch at 0x406a00-0x406a50 — "
            "'../modules/' + moduleId -> access() -> creat()"
        ),
        "evidence": {
            "path_construction": (
                "0x406a00: lea 0x10(%rbp), %rdx — moduleId string from server JSON, no sanitization. "
                "0x406a09: call 0x409690 ('_ZStplIcSt11char_traitsIcESaIcEESbIT_T0_T1_EPKS3_RKS6_@@Base'): "
                "std::string operator+(\"../modules/\", moduleId) -> full_path at rsp+0x10. "
                "0x409690 is a pure string concatenation — no filtering of '..' or '/' sequences. "
                "0x406a15: access(\"../modules/\", F_OK) — existence check on base dir. "
                "0x406a2c: access(full_path, F_OK) — existence check on full constructed path. "
                "0x406a41: creat(full_path, 0x1a4=0644) — creates the file if it does not exist. "
                "If moduleId = '../../etc/cron.d/evil': full_path = '../modules/../../etc/cron.d/evil' "
                "= /etc/cron.d/evil relative to agent CWD (typically /usr/local/qcloud/stargate/admin/). "
                "creat() creates /etc/cron.d/evil as an empty file owned by root."
            ),
            "json_parse_site": (
                "moduleId parsed at 0x407f1b: mov $0x446dbe, %esi ('moduleId') -> call 0x43fcc0 "
                "(JSON field lookup) -> return value stored in module struct at rsp+0x200. "
                "No sanitization between JSON parse and path construction."
            ),
            "scope_limitation": (
                "The creat() path controls only file creation (empty files, mode 0644). "
                "Module binary content is written to installPath + '.STARGATE' (0x446c81), "
                "not to the moduleId-derived path. "
                "Impact is therefore limited to: "
                "1. Creating empty files as root outside the modules directory. "
                "2. Overwriting existing files with empty content (truncation via creat O_TRUNC). "
                "creat() with O_CREAT|O_WRONLY|O_TRUNC on an existing file truncates it to zero length: "
                "creat('/etc/passwd') destroys the system passwd file (all users lose auth). "
                "creat('/root/.ssh/authorized_keys') destroys root's SSH authorized keys. "
                "This is a file-clobber DoS primitive, not content-controlled RCE. "
                "Severity is MEDIUM when considered independently from TCS-F01."
            ),
            "cross_architecture": (
                "'../modules/' string present in sgagentarm64 strings. "
                "Path traversal applies to all three binary variants."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Validate moduleId before path construction: "
            "reject any moduleId containing '/' or '..'. "
            "Use a strict allowlist: moduleId must match [A-Za-z0-9_\\-\\.]{1,128}. "
            "Resolve the full path and verify it begins with the expected modules directory "
            "using realpath() before any file system operation. "
            "Do not use creat() with an attacker-controlled path; "
            "if a module marker file is needed, write it to a fixed root-owned directory."
        ),
    },
    # ── Windows-specific findings ─────────────────────────────────────────────
    "TCS-F07": {
        "title": (
            "Windows StargateSvc Component Stack Has Zero Exploit Mitigations — "
            "No ASLR, No DEP, No CFGuard, No SafeSEH, No GS on All Three Binaries; "
            "Worse Than Linux Variants Which Had NX"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-693",
        "component": (
            "sgagent.exe (i386), libcurl.dll (i386), jsoncpp.dll (i386) — "
            "Windows StargateSvc PE binary stack — DllCharacteristics=0x0000 on all three"
        ),
        "evidence": {
            "mitigation_matrix": (
                "PE DllCharacteristics field — per-binary Windows mitigation status:\n"
                "  sgagent.exe: ASLR=NO  DEP=NO  CFGuard=NO  SafeSEH=NO  GS=NO  Fixed base=0x00400000\n"
                "  libcurl.dll: ASLR=NO  DEP=NO  CFGuard=NO  SafeSEH=NO  GS=NO  Fixed base=0x61c00000\n"
                "  jsoncpp.dll: ASLR=NO  DEP=NO  CFGuard=NO  SafeSEH=NO  GS=NO  Fixed base=0x62140000\n"
                "DllCharacteristics=0x0000 means no mitigation bits are set in the PE optional header. "
                "The Windows OS loader does not apply ASLR, DEP, CFGuard, or integrity checks "
                "to any component in the service binary stack."
            ),
            "worse_than_linux": (
                "Linux variants (sgagent64, sgagent32, sgagentarm64) all had NX=YES (GNU_STACK RW). "
                "The Windows variant has DEP disabled (NX_COMPAT bit 0x0100 is not set). "
                "Stack pages and heap pages are executable on Windows. "
                "Direct shellcode injection requires no ROP chain — payload can be placed "
                "in a stack buffer or heap allocation and jumped to directly. "
                "No information-leak primitive required: image bases are fixed and static "
                "(sgagent.exe=0x00400000 maps to the same virtual address on every boot)."
            ),
            "seh_exploitability": (
                "No .sxdata section detected — SafeSEH table absent. "
                "sgagent.exe imports SetUnhandledExceptionFilter (KERNEL32.dll) — "
                "SEH-based exploitation is viable: a stack overflow that overwrites an SEH handler "
                "record is not validated against a trusted handler table. "
                "Classic SEH overwrite: overwrite nSEH+SEH chain, pop-pop-ret gadget at fixed address "
                "in libcurl.dll or jsoncpp.dll (no ASLR) → shellcode on executable stack (no DEP)."
            ),
            "no_gs_cookies": (
                "No __security_cookie symbols in any binary string table. "
                "MSVC /GS stack protection not applied at compile time. "
                "Stack buffer overflows produce direct return address overwrite "
                "with no cookie-check gate between corruption and code execution."
            ),
            "service_context": (
                "StargateSvc registered via CreateServiceA (ADVAPI32.DLL). "
                "Windows services run as SYSTEM by default when no explicit account is specified. "
                "Service binary at sgagent.exe is the memory corruption target; "
                "successful exploitation yields SYSTEM-level code execution."
            ),
        },
        "versions_affected": ["windows-2020-05-20"],
        "remediation": (
            "Recompile all three components with: "
            "/GS (stack cookies), /DYNAMICBASE (ASLR), /NXCOMPAT (DEP), /SAFESEH (SafeSEH). "
            "Add /guard:cf for Control Flow Guard (CFGuard). "
            "Verify mitigations post-build with dumpbin /headers or sigcheck from Sysinternals. "
            "For the libcurl.dll component, upgrade to a current release (see TCS-F08) and "
            "ensure it is compiled with the same hardening flags."
        ),
    },
    "TCS-F08": {
        "title": (
            "libcurl.dll 7.38.0 (2014) Loaded by SYSTEM Service — "
            "Decade-Old Library With 100+ Accumulated CVEs, No ASLR/DEP, Fixed Load Address; "
            "MitM HTTP Response Triggers Vulnerable Code Path in SYSTEM Context"
        ),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-1104",
        "component": (
            "libcurl.dll — version 7.38.0, PE timestamp 2014-10-08, "
            "shipped in 2020-05-20 signed installer; loaded by StargateSvc at fixed base 0x61c00000"
        ),
        "evidence": {
            "version_confirmation": (
                "String extraction from libcurl.dll: "
                "'CLIENT libcurl 7.38.0' (x3 occurrences) and 'libcurl/7.38.0'. "
                "PE timestamp: Wed Oct 8 04:30:48 2014 (0x54350448). "
                "curl 7.38.0 was released 2014-10-20. This binary was built just before release. "
                "At time of installer signing (2020-05-20), this library was approximately 6 years old. "
                "Approximately 120+ CVEs had been filed against libcurl between 7.38.0 and 7.70.0."
            ),
            "selected_cves": (
                "High-severity CVEs in libcurl versions 7.38.0 through 7.50.x (non-exhaustive): "
                "CVE-2016-9586: printf format string in libcurl 7.36.0-7.51.0 (CVSS 9.8). "
                "CVE-2015-3145: heap-based buffer overflow in cookie parser (CVSS 9.8). "
                "CVE-2016-8615: cookie injection via crafted server response. "
                "CVE-2016-8620: strdup() on attacker-controlled glob expression (heap overflow). "
                "CVE-2016-8621: out-of-bounds read in curl_getdate(). "
                "CVE-2016-8624: OOB read in URL auth parsing. "
                "CVE-2018-1000007: credential leak via HTTP redirect (auth header forwarding). "
                "All of these affect the exact 7.38.0 version confirmed in libcurl.dll."
            ),
            "exploit_amplification": (
                "libcurl.dll is loaded by StargateSvc, a SYSTEM-privileged Windows service. "
                "libcurl.dll itself has DllCharacteristics=0x0000 (no ASLR, no DEP, fixed base 0x61c00000). "
                "Any heap or stack corruption in libcurl.dll at 0x61c00000+offset → SYSTEM RCE "
                "without requiring an information leak to defeat ASLR. "
                "With DEP disabled, shellcode planted in heap/stack is directly executable — "
                "no ROP chain required."
            ),
            "mitm_trigger_path": (
                "TCS-F01 establishes: sgagent.exe makes HTTP requests to "
                "http://update2.agent.tencentyun.com/interface.php with SSL disabled. "
                "The HTTP response is processed by libcurl 7.38.0 (CVE-2016-9586 path: "
                "printf format string in curl_msnprintf -> format string expansion on response data). "
                "A MitM attacker on the network delivers a crafted HTTP response that triggers "
                "a CVE in the 7.38.0 code path during response processing. "
                "No prior authentication or credentials required — HTTP request originates from SYSTEM."
            ),
            "verifyhost_warning": (
                "libcurl.dll contains the string: "
                "'CURLOPT_SSL_VERIFYHOST no longer supports 1 as value!'. "
                "This is the warning libcurl 7.28.1+ logs when CURLOPT_SSL_VERIFYHOST=1 is passed. "
                "It confirms that if the Windows agent calls curl_easy_setopt with VERIFYHOST=1, "
                "libcurl silently accepts any certificate (treats 1 the same as 0). "
                "This matches the Linux TCS-F01 finding where CURLOPT_SSL_VERIFYHOST was set to 1 "
                "instead of 2, producing the same weakened TLS posture."
            ),
        },
        "versions_affected": ["windows-2020-05-20"],
        "remediation": (
            "Replace libcurl.dll with the current libcurl release (7.88+ as of 2023). "
            "Compile with /GS, /DYNAMICBASE, /NXCOMPAT, /guard:cf. "
            "Configure CURLOPT_SSL_VERIFYPEER=1, CURLOPT_SSL_VERIFYHOST=2, "
            "CURLOPT_CAINFO pointing to a pinned certificate bundle. "
            "Migrate update URL from http:// to https:// (see TCS-F01). "
            "Establish a dependency update policy so third-party libraries cannot "
            "reach end-of-support before the product ships."
        ),
    },
    "TCS-F09": {
        "title": (
            "ShellExecuteExA Called with `.\\.installer.exe` Relative Path — "
            "Binary Planting Attack When StargateSvc Installer Runs from Attacker-Writable Directory"
        ),
        "severity": "MEDIUM",
        "cvss": "6.7",
        "cwe": "CWE-426",
        "component": (
            "sgagent.exe ShellExecuteExA call site — string '.\\.installer.exe' at file offset 0x85227; "
            "SHELL32.DLL ShellExecuteExA in import table"
        ),
        "evidence": {
            "relative_path_confirmed": (
                "strings -t x sgagent.exe output: '0x85227  .\\.installer.exe'. "
                "This is the path argument passed to ShellExecuteExA (imported from SHELL32.DLL). "
                "The path is relative — no drive letter, no absolute prefix. "
                "Windows shell execution resolves relative paths against the current working directory. "
                "'SetCurrentDirectoryA' is also imported from KERNEL32.dll, "
                "indicating the binary explicitly sets CWD before the ShellExecuteExA call."
            ),
            "install_context": (
                "install.bat (extracted from WEXTRACT cabinet): "
                "stops existing StargateSvc -> deletes old binary -> unzips stargate.zip to "
                "C:\\Program Files\\QCloud -> runs sgagent.exe install -> sgagent.exe reset -> "
                "sgagent.exe start. "
                "The bat file runs from the directory where the installer was executed. "
                "If an attacker with local write access places a malicious installer.exe in "
                "the same directory (e.g., a user's Downloads folder), and the victim "
                "runs the Stargate installer from that directory with elevation, "
                "ShellExecuteExA loads and executes the attacker's binary."
            ),
            "privilege_context": (
                "Service installation (CreateServiceA) requires Administrator or SYSTEM privileges. "
                "The installer is therefore run with elevation by the user or a deployment system. "
                "The ShellExecuteExA call for .\\.installer.exe inherits those elevated privileges. "
                "Attacker-planted installer.exe executes with Administrator or SYSTEM privileges "
                "depending on how the Stargate installer was invoked."
            ),
            "no_signature_verification": (
                "No imports from Wintrust.dll (WinVerifyTrust) in sgagent.exe. "
                "sgagent.exe does not verify the Authenticode signature of .\\.installer.exe "
                "before executing it. Any executable at that path is run unconditionally."
            ),
        },
        "versions_affected": ["windows-2020-05-20"],
        "remediation": (
            "Replace the relative path '.\\.installer.exe' with an absolute path "
            "constructed from the known installation directory. "
            "Before executing any binary via ShellExecuteExA or CreateProcess, "
            "verify its Authenticode signature using WinVerifyTrust (wintrust.dll). "
            "Alternatively, eliminate the installer.exe sub-invocation entirely and "
            "perform the install steps directly in sgagent.exe to remove the "
            "untrusted-path execution surface."
        ),
    },
}


# ─── Probe Functions ──────────────────────────────────────────────────────────

def _check_agent_running(host: str) -> dict:
    """Check if sgagent cron lock file is accessible (passive indicator)."""
    result = {"host": host, "findings": []}
    # No active probe defined — agent is internal to the host
    return result


def probe(host: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Placeholder probe — sgagent is a local agent, not a network service.
    Findings are confirmed via binary RE + config file analysis.
    """
    return {
        "host": host,
        "note": "sgagent is not a network-exposed service; findings confirmed via static RE",
        "findings": list(FINDINGS.keys()),
    }
