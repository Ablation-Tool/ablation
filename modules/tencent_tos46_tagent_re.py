"""
TencentOS 4.6 — tagent main daemon reverse engineering module.

Binary: tagent (packaged in tagent-2.1.6-1.tl4)
Path: /usr/local/tagent/tagent
ELF: 64-bit LSB executable, x86-64, BuildID=814da67e7c7a9adeac644a789209167cd295330e
Stripped: YES (no symbol table)
Size: 1.8MB
Language: C++ with jsoncpp, log4cplus, libcron, zlib (all statically linked)
Runtime: runs as root daemon; starts from /usr/local/tagent/start.sh

Source tree (extracted from embedded __FILE__ paths in .rodata):
  /data/landun/workspace/src/main.cpp
  /data/landun/workspace/src/main/ConfigFile.h
  /data/landun/workspace/src/main/CPULimiter.cpp
  /data/landun/workspace/src/main/ExcMonitor.cpp
  /data/landun/workspace/src/main/MemMonitor.cpp
  /data/landun/workspace/src/main/Sender.cpp
  /data/landun/workspace/src/main/Worker.cpp
  /data/landun/workspace/src/mod/config/ConfigManager.cpp
  /data/landun/workspace/src/mod/crontab/CrontabManager.cpp
  /data/landun/workspace/src/mod/ModManager.cpp
  /data/landun/workspace/src/utils/cgroup.cpp
  /data/landun/workspace/src/utils/func_utils.cpp
  /data/landun/workspace/src/utils/io_utils.cpp
  /data/landun/workspace/src/utils/MetricsReport.cpp
  /data/landun/workspace/src/utils/tms_utils.cpp

Build system: Tencent 'Landun' CI/CD (蓝盾 Blue Shield), same as wujing

Libraries:
  log4cplus (logging)
  jsoncpp (JSON serialization)
  libcron (cron-style task scheduling)
  zlib (compress2/compressBound — data compression before C2 transmission)
  pthreads (multi-threaded daemon: Worker, Sender, ExcMonitor, MemMonitor)

C2: port 53333 (hardcoded, extracted from .rodata; connects to Tencent cloud)

SysV IPC:
  Shared memory key for IPC string channel: extracted from 'tlinux-tagent-shm-' prefix
    + hash (from get ipc mem key / make ipc sem key strings at 0x541542)
  The IPC push channel from tmp-tagent-push (shmkey=0x5fe8) is READ by tagent.

PLT imports relevant to execution:
  popen@plt 0x409860 — 16 call sites found
  execvp@plt 0x409d70 — 1 call site (0x46e724, in fork+exec pattern)
  fork@plt — child process spawning
  kill@plt — signal delivery
  connect@plt, bind@plt, accept@plt — TCP socket management
  mmap@plt — memory-mapped I/O
  daemon@plt — daemonization
  compress2@plt — zlib compression before C2 send
"""

METADATA = {
    "target": "TencentOS 4.6",
    "binary": "tagent",
    "build_id": "814da67e7c7a9adeac644a789209167cd295330e",
    "stripped": True,
    "debug_info": False,
    "c2_port": 53333,
    "popen_sites": 16,
    "execvp_sites": 1,
    "source_base": "/data/landun/workspace/",
    "build_system": "Tencent Landun (蓝盾)",
}

# Hardcoded credential strings extracted from .rodata
HARDCODED_CREDENTIALS = {
    "key_package_template": {
        "va": "0x53f3a0",
        "value": '{"key":"KRm1yXsnj/3zlPnq5KdzjzG4OdwUApSjdtgKX9Ecckw4luiWe7mKyg==", "id": 126, "ts": ',
        "full_template": '{"key":"KRm1yXsnj/3zlPnq5KdzjzG4OdwUApSjdtgKX9Ecckw4luiWe7mKyg==", "id": 126, "ts": [TS], "mod":"agent", "type": "str", "data": "[DATA]"}',
        "sig": "KRm1yXsnj/3zlPnq5KdzjzG4OdwUApSjdtgKX9Ecckw4luiWe7mKyg==",
        "mod": "agent",
        "id": 126,
        "type": "str",
        "signed_msg": "tagent+agent126+kh3ynYGL9uByKZ5",
        "purpose": "heartbeat/registration packet sent to C2 on startup and periodically",
    },
    "hardcoded_push_invocation": {
        "va": "0x541b60",
        "full_command_template": "/usr/local/tagent/tmp-tagent-push ccfuonaI0KfnA42KtM3CRctBZbb4tz+7dFp0658KfZ4nU3/AnUfCeA== agent 134 json '<data_arg>'",
        "sig": "ccfuonaI0KfnA42KtM3CRctBZbb4tz+7dFp0658KfZ4nU3/AnUfCeA==",
        "mod": "agent",
        "id": 134,
        "type": "json",
        "signed_msg": "tagent+agent134+kh3ynYGL9uByKZ5",
        "purpose": "tagent pushes data to its own push channel via tmp-tagent-push subprocess",
        "data_is_substituted_unescaped": True,
    },
    "hardcoded_tms_push_invocation": {
        "va": "0x541b00",
        "full_command_template": "/usr/local/tagent/tms-push-json --plugin tagent-push-monitor --version v0.0.1 --data '<data_arg>'",
        "purpose": "tagent status reporting via tms-push-json",
        "data_is_substituted_unescaped": True,
    },
}

POPEN_CALL_SITES = {
    "total": 16,
    "addresses": [
        "0x4116d4", "0x418342", "0x4278ef", "0x42c477", "0x42d409",
        "0x442dff", "0x446101", "0x449751", "0x44cfb5", "0x450633",
        "0x456855", "0x45a77d", "0x45e749", "0x45f89d", "0x460a47",
        "0x465eaf", "0x46e16e",
    ],
    "command_builder_at_0x44e2de": {
        "purpose": "builds tms-push-json command",
        "pattern": "ostringstream: '' + tms-push-json_prefix + data_arg + \"'\"",
        "data_arg_escaped": False,
    },
    "command_builder_at_0x44e46e": {
        "purpose": "builds tmp-tagent-push command",
        "pattern": "ostringstream: '' + tmp-tagent-push_prefix + data_arg + \"'\"",
        "data_arg_escaped": False,
    },
}

EXECVP_SITE = {
    "addr": "0x46e724",
    "pattern": "fork -> child: build argv[] from string vector, execvp(argv[0], argv), _exit(0)",
    "details": (
        "pipe() called before fork. In child: string vector elements converted to char* argv[] "
        "on the stack (VLA, aligned to 0x10 bytes). execvp(argv[0], argv) then _exit(0). "
        "execvp with argv[0] as program path — standard fork+exec pattern used for "
        "module/plugin launcher or watchdog restart. "
        "The argv vector source determines what program runs — investigate callers for "
        "user-influenced paths."
    ),
}

IPC_PROTOCOL = {
    "shm_name_prefix": "tlinux-tagent-shm-",
    "sem_name_prefix": "tlinux-tagent-sem-",
    "shm_lock_file": "/var/lib/tagent/ipc-string-shm",
    "sem_lock_file": "/var/lib/tagent/ipc-string-sem",
    "push_read_key": 0x5fe8,  # same key used by tmp-tagent-push adv_attr_set
    "push_shm_size": 0x200000,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Hardcoded DSA signatures burned into tagent binary — (agent, 126) and (agent, 134) auth tokens exposed",
        "detail": (
            "Two hardcoded DSA signatures are embedded in the tagent binary .rodata: "
            "1. Key package sig (0x53f3a0): KRm1yXsnj/3zlPnq5KdzjzG4OdwUApSjdtgKX9Ecckw4luiWe7mKyg== "
            "   Signs: 'tagent+agent126+kh3ynYGL9uByKZ5' (mod=agent, id=126). "
            "   Full JSON template: {\"key\":\"KRm1...\",\"id\":126,\"ts\":[ts],\"mod\":\"agent\",\"type\":\"str\",\"data\":\"[DATA]\"} "
            "   Purpose: heartbeat/registration packet sent to C2 at startup. "
            "2. Push invocation sig (0x541b60): ccfuonaI0KfnA42KtM3CRctBZbb4tz+7dFp0658KfZ4nU3/AnUfCeA== "
            "   Signs: 'tagent+agent134+kh3ynYGL9uByKZ5' (mod=agent, id=134). "
            "   Used in: popen('/usr/local/tagent/tmp-tagent-push ccfuonaI0K... agent 134 json \\'<data>\\'') "
            "Per F1 of the tmp-tagent-push module: the data argument is NOT included in the signed message. "
            "An attacker extracting these signatures can push arbitrary payloads to (agent, 126) and (agent, 134) "
            "on any TOS host running tagent 2.1.6, by replaying the hardcoded signature with a forged payload."
        ),
        "evidence": [
            ".rodata VA 0x53f3a0: {\"key\":\"KRm1yXsnj/3zlPnq5KdzjzG4OdwUApSjdtgKX9Ecckw4luiWe7mKyg==\", ...}",
            ".rodata VA 0x541b60: /usr/local/tagent/tmp-tagent-push ccfuonaI0KfnA42KtM3CRctBZbb4tz+7dFp0658KfZ4nU3/AnUfCeA== agent 134 json '",
        ],
        "impact": (
            "Replay attack: send forged push payloads to (agent, 126) and (agent, 134) on any TOS host. "
            "Bypass requirement: only the SysV IPC shared memory write is needed (F2 in tmp-tagent-push module) "
            "OR the extracted signatures allow external push via any tmp-tagent-push binary."
        ),
    },
    {
        "id": "F2",
        "severity": "CRITICAL",
        "title": "popen() with unescaped data argument — shell command injection if data flows to command builder",
        "functions": ["0x44e2de (tms-push-json builder)", "0x44e46e (tmp-tagent-push builder)"],
        "detail": (
            "Two command-building functions at 0x44e2de and 0x44e46e construct shell commands via ostringstream "
            "without any shell escaping of the data argument: "
            "  '/usr/local/tagent/tmp-tagent-push ccfuonaI0K... agent 134 json \\'' + data_arg + '\\'' "
            "The data_arg is directly concatenated with no shell metacharacter escaping (no quoting beyond the literal '). "
            "A data_arg containing a closing single-quote followed by shell commands: "
            "  data_arg = \"x'; <SHELLCMD>; echo '\" "
            "would result in: tmp-tagent-push ... json 'x'; <SHELLCMD>; echo '' "
            "The injection surface: any code path that passes externally-influenced data "
            "(from the push channel, config files, network, or procfs reads) into these command builders. "
            "With the SysV IPC bypass from the push module (F2), an attacker can write to the push channel, "
            "and if that data flows to a popen() command builder, the result is RCE as the tagent process owner (root)."
        ),
        "disasm_evidence": [
            "44e4f2: mov esi, 0x541b60  ; '/usr/local/tagent/tmp-tagent-push ccfuona...'",
            "44e50f: call _ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKSbIS4_S5_T1_E  ; append data_arg",
            "44e514: mov esi, 0x541b57  ; append closing single-quote",
            "No escaping between the two << operations",
        ],
        "precondition": "data_arg must flow from an attacker-controlled source to the command builder callers",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Source path + build system identity disclosed — /data/landun/workspace/ in 15 embedded paths",
        "detail": (
            "15 __FILE__ strings from assert/exception paths are embedded in the tagent binary .text/.rodata: "
            "/data/landun/workspace/src/main.cpp "
            "/data/landun/workspace/src/main/Sender.cpp — C2 communication module "
            "/data/landun/workspace/src/main/Worker.cpp — task execution "
            "/data/landun/workspace/src/mod/ModManager.cpp — plugin loading "
            "/data/landun/workspace/src/mod/crontab/CrontabManager.cpp — cron job execution "
            "/data/landun/workspace/src/utils/tms_utils.cpp — TMS utilities "
            "These reveal: internal project structure, class names, module boundaries, "
            "and confirm the same Landun CI/CD system found in wujing. "
            "lib search paths: /data/landun/workspace/./lib/linux/log4cplus, /lib/linux/libcron, /lib/linux/jsoncpp"
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "16 popen() call sites — extensive shell command execution surface",
        "detail": (
            "16 popen() call sites are present in the tagent binary (grep for <popen@plt>). "
            "popen() spawns /bin/sh -c '<command>', meaning every popen() call is a shell execution. "
            "Call sites span multiple source modules (from source path distribution): "
            "Sender.cpp, Worker.cpp, CrontabManager.cpp (cron job execution via shell), "
            "ModManager.cpp (module lifecycle via shell), utils/ helpers. "
            "The CrontabManager is particularly notable: cron jobs would be defined via the "
            "push channel or config files, and if their command strings flow unescaped to popen(), "
            "this is a systematic injection surface."
        ),
        "popen_addresses": [
            "0x4116d4", "0x418342", "0x4278ef", "0x42c477", "0x42d409",
            "0x442dff", "0x446101", "0x449751", "0x44cfb5", "0x450633",
            "0x456855", "0x45a77d", "0x45e749", "0x45f89d", "0x460a47",
            "0x465eaf", "0x46e16e",
        ],
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "title": "C2 push channel: zlib-compressed JSON to port 53333 — traffic analysis surface",
        "detail": (
            "tagent imports compress2/compressBound (zlib) — the Sender module compresses "
            "JSON payloads before transmitting to the C2 at port 53333. "
            "The heartbeat key package (KRm1 sig, id=126, mod=agent) reveals the auth format: "
            "the 'key' field IS the DSA signature (same finding as in tmp-tagent-push analysis). "
            "The C2 protocol: zlib-compressed JSON with DSA signature as the 'key' bearer token. "
            "Port 53333 is used on the C2 server side; tagent connects OUTBOUND to the C2 "
            "(not the opposite — no inbound accept except for log4cplus SocketAppender on localhost)."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "execvp fork+exec at 0x46e724 — single process launcher for plugin or watchdog",
        "detail": (
            "One execvp call at 0x46e724. The pattern: "
            "1. pipe() to create a communication channel with the child. "
            "2. fork() (not visible in the 0x46e6xx window but implied by execvp+_exit pattern). "
            "3. Child: VLA-allocate argv[] from string vector, execvp(argv[0], argv), _exit(0). "
            "4. Parent: reads from pipe fd. "
            "The argv[0] and subsequent elements come from a std::vector<std::string> (rbp-0xb0). "
            "This is likely the module spawning mechanism in ModManager.cpp — each plugin is "
            "launched as a child process. The ostringstream at rbp-0x90 with key 0x9c40 at "
            "0x46e4c8 suggests a config-driven process name."
        ),
        "disasm_evidence": [
            "46e664: lea rdx, [rax*8+0x0]  ; sizeof argv = (n+1) * 8 bytes (VLA)",
            "46e713: mov rdx, [rbp-0x60]   ; argv[] pointer",
            "46e71b: mov rax, [rax]         ; argv[0] = first element",
            "46e721: mov rdi, rax           ; execvp path",
            "46e724: call execvp@plt",
            "46e729: mov edi, 0             ; _exit(0) — child never returns",
        ],
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "Plugin/module system loads from /usr/local/tagent/mod/ — runtime plugin management",
        "detail": (
            "tagent loads plugins from /usr/local/tagent/mod/. "
            "Discovered from ModManager.cpp source path and string 'mod_vmrss' (wujing VM RSS module). "
            "Module configs from /usr/local/tagent/mod-config/: "
            "  rue.conf, tagent_monitor.conf, agent.conf, crashdump.conf, "
            "  sysinfo_collector.conf, wujing.conf, plugins_status_collector.conf, "
            "  tmanager.conf, os_monitor.conf, heartbeat.conf. "
            "Each module appears to be a separate binary launched via execvp() from ModManager. "
            "If any module config contains an attacker-controlled command string, it flows to execvp."
        ),
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "Lock file path and IPC naming convention — tlinux-tagent-{shm,sem}-* prefix",
        "detail": (
            "Shared memory and semaphore are identified via: "
            "'tlinux-tagent-shm-' + [hash] — IPC string shared memory name "
            "'tlinux-tagent-sem-' + [hash] — IPC semaphore name "
            "Lock files: /var/lib/tagent/ipc-string-shm and /var/lib/tagent/ipc-string-sem "
            "Tagent lock file: /var/lib/tagent/tagent.lock (prevents duplicate instances). "
            "The naming convention and lock file paths are common across all TOS versions "
            "that ship tagent-2.x — useful for cross-version fingerprinting."
        ),
    },
]

if __name__ == '__main__':
    print(f"tagent RE — {len(FINDINGS)} findings")
    for f in FINDINGS:
        print(f"  [{f['severity']:8s}] {f['id']}: {f['title']}")
    print(f"\nHardcoded sigs: {list(HARDCODED_CREDENTIALS.keys())}")
    print(f"popen sites: {POPEN_CALL_SITES['total']}")
    print(f"C2 port: {METADATA['c2_port']}")
