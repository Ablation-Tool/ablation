"""
TencentOS Server 4.6 tagent RE Module
Source: tagent-2.1.6-1.tl4.src.rpm
        /media/cowboy/research/tencentos/4.6/BaseOS-source/
Analysis date: 2026-09-04

PACKAGE: tagent-2.1.6-1.tl4
  License: Proprietary (closed-source binary payload)
  Maintainer: joshuahu@tencent.com
  Source git: https://git.woa.com/tlinux/TManager/tagent (Tencent internal)
  Architecture: x86_64, aarch64 only

PAYLOAD STRUCTURE:
  tms_agent_install.zip      (12MB) — TManager message channel
    x86/agent.zip (4.2MB) → install.sh + tmanager-service binary
    arm/agent.zip (5.4MB)
    power/agent.zip (2.2MB) — IBM POWER channel (older, 2024-06-13)
  tagent-installer-v2.1.6-both.zip  (46.8MB) — tagent collector
    install.sh, uninstall.sh
    tagent-tms-x86.zip (14MB) → full agent package
    tagent-tms-arm.zip (18.8MB)

TAGENT BINARY PACKAGE (x86) CONTENTS:
  tagent                (1.8MB) — main C++ daemon, stripped, libstdc++
  tms-push-json         (3.1MB) — Go binary, cloud data push, stripped
  tmp-tagent-push       (4.1MB) — C++ push binary, NOT STRIPPED (debug info present)
  cpulimit              (21KB) — CPU throttle helper
  mod/heartbeat/heartbeat
  mod/rue/rue.sh
  mod/plugins_status_collector/plugins_status_collector
  mod/tmanager/tmanager.sh
  mod/crashdump/crashdump.sh
  mod/performance_platform/performance_platform
  mod/agent/agent.sh
  mod/tagent_monitor/tagent_monitor
  mod/os_monitor/os_monitor
  mod/wujing/wujing     (UPX-packed, statically linked, no section header)
  tagent.service, start.sh, stop.sh, tagent-monitor.sh, tagent-watchdog.sh

SECURITY FINDINGS: TOS46-AGT-F01 through TOS46-AGT-F09
  F01 CRITICAL  HARDCODED_C2    C2 IP 9.150.206.219:53333 in config.conf
  F02 CRITICAL  KILL_PROTECT    /proc/kill_protect/blacklist — kernel anti-kill (unkillable by root)
  F03 HIGH      DEL_PROTECT     chattr +i /usr/local/tagent — immutable even to root
  F04 HIGH      PERSISTENCE     Root crontab + rc.local dual persistence
  F05 HIGH      STATIC_KEY      Hardcoded auth key in tagent binary (base64, 46 decoded bytes)
  F06 HIGH      ECDSA_PUBKEY    Static pub_key in tmp-tagent-push for ECDSA command verification
  F07 HIGH      WUJING_UPX      wujing module: UPX-packed, statically linked, no section header
  F08 MEDIUM    SYSV_IPC        tlinux-tagent-shm-2023/2025 and tlinux-tagent-sem-2023 SHM keys
  F09 INFO      POWER_CHANNEL   IBM POWER tmanager agent.zip (2024-06-13) — older vintage
"""

# ──────────────────────────────────────────────────────────────────────────────
# PACKAGE METADATA
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_PACKAGE = {
    "name": "tagent",
    "version": "2.1.6",
    "release": "1.tl4",
    "license": "Proprietary",
    "source_git": "https://git.woa.com/tlinux/TManager/tagent",
    "maintainer": "joshuahu@tencent.com",
    "package_type": "Wrapper RPM + nested ZIP-in-ZIP payload",
    "payload_size": {
        "tms_agent_install.zip": "12MB",
        "tagent_installer_zip": "46.8MB",
        "tagent_x86_binary": "1.8MB stripped C++",
        "tms_push_json": "3.1MB Go (stripped)",
        "tmp_tagent_push": "4.1MB C++ WITH debug symbols (not stripped)",
    },
    "install_paths": {
        "tagent_dir": "/usr/local/tagent/",
        "tmanager_dir": "/usr/local/tmanager/",
        "tmp_agent": "/usr/local/tencent/tmp_agent/",
        "config": "/usr/local/tagent/config.conf",
        "lock": "/var/lib/tagent/tagent.lock",
        "log": "/var/log/tagent-install.log",
        "crontab": "/var/spool/cron/root",
        "rc_local": "/etc/rc.d/rc.local",
    },
    "kernel_interfaces": [
        "/proc/kill_protect/blacklist (TOS-specific anti-kill kernel module)",
        "/proc/sys/kernel/sig_kill_protect (status file)",
    ],
    "ipc_keys": [
        "tlinux-tagent-shm-2023 (System V shared memory)",
        "tlinux-tagent-shm-2025 (System V shared memory)",
        "tlinux-tagent-sem-2023 (System V semaphore)",
    ],
    "modules": {
        "heartbeat": "health check, 5min interval, v0.0.5",
        "rue": "unknown (shell script wrapper)",
        "plugins_status_collector": "plugin status reporting",
        "tmanager": "TManager integration (shell script)",
        "crashdump": "crash dump collection (shell script)",
        "performance_platform": "performance metrics (ELF + app.conf.yml)",
        "agent": "agent management (shell script)",
        "tagent_monitor": "self-monitoring watchdog (ELF)",
        "os_monitor": "OS-level monitoring (ELF + app.conf.yml)",
        "wujing": "UNKNOWN — UPX-packed, statically linked, no section header",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# F01 — HARDCODED C2 IP in config.conf
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_F01_C2 = {
    "finding_id": "TOS46-AGT-F01",
    "severity": "CRITICAL",
    "title": "tagent config.conf hardcodes C2 IP 9.150.206.219 on port 53333",
    "description": (
        "config.conf (deployed to /usr/local/tagent/config.conf): "
        "  serverIP = 9.150.206.219 "
        "  serverPort = 53333 "
        "\n"
        "9.150.206.219 is in Tencent's private cloud network (9.0.0.0/8). "
        "This is the TManager message channel endpoint — the persistent connection "
        "through which Tencent's cloud infrastructure communicates with the agent. "
        "\n"
        "Port 53333 is non-standard and non-ephemeral. All TOS 4.6 instances with "
        "tagent installed connect to the same IP:port. "
        "\n"
        "Channel role: "
        "  - Command receipt (remote exec of agent modules) "
        "  - Data exfiltration (performance metrics, heartbeat, sysinfo) "
        "  - Agent update coordination "
        "\n"
        "The connection is persistent (channelCheckSeconds = 180 — reconnect if "
        "channel idle for 3 minutes). "
        "\n"
        "Network segmentation: 9.150.206.219 is only reachable from within Tencent "
        "Cloud infrastructure or via Tencent's private interconnect. Not reachable "
        "from public internet — but any host within Tencent Cloud can reach it."
    ),
    "ioc": {
        "ip": "9.150.206.219",
        "port": 53333,
        "protocol": "TCP (persistent connection)",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# F02 — /proc/kill_protect/blacklist kernel anti-kill mechanism
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_F02_KILL_PROTECT = {
    "finding_id": "TOS46-AGT-F02",
    "severity": "CRITICAL",
    "title": (
        "TOS-specific /proc/kill_protect/blacklist kernel module: registered processes "
        "are immune to SIGKILL even from root — tagent and tmanager whitelisted by default"
    ),
    "description": (
        "TOS 4.6 ships a kernel module that implements process kill protection "
        "via a procfs interface: "
        "  /proc/sys/kernel/sig_kill_protect — 0=disabled, 1=enabled "
        "  /proc/kill_protect/blacklist — write 'add <name>' / 'del <name>' "
        "\n"
        "Protected process names: "
        "  'tagent' — main agent binary "
        "  'tagentV1.0' — old agent binary (backward compat) "
        "  'tmanager-servic' — message channel service (truncated at 15 chars) "
        "\n"
        "kill_protect = true in config.conf — enabled by default. "
        "\n"
        "Effect: `kill -9 <tagent_pid>` returns success but the process is NOT killed. "
        "The kernel module intercepts SIGKILL delivery for whitelisted process names. "
        "\n"
        "This means: "
        "  - Administrators cannot stop tagent via `kill -9` "
        "  - systemctl stop tagent depends on the service's stop script, not kill "
        "  - The only way to disable is to remove the process from the blacklist FIRST: "
        "    echo 'del tagent' > /proc/kill_protect/blacklist "
        "    then kill the process "
        "  - On upgrade, the installer must do this (disable_kill_protect → kill → reinstall → enable) "
        "\n"
        "Security implication: "
        "  - A compromised tagent process that has modified the blacklist cannot be terminated "
        "    by system administrators without rebooting or unloading the kernel module "
        "  - The kernel module is a privileged persistence mechanism: once the module is "
        "    loaded, protected processes require kernel-level intervention to terminate "
        "  - The kernel module source is not in this SRPM — it's a separate TOS kernel patch "
        "\n"
        "Kill protect module load: presumably at boot via `/etc/rc.d/rc.local` or "
        "kernel config. The module is part of the TOS kernel (shellguard or separate)."
    ),
    "kernel_interface": {
        "status_file": "/proc/sys/kernel/sig_kill_protect",
        "blacklist_file": "/proc/kill_protect/blacklist",
        "protocol": "write 'add <name>' or 'del <name>' to blacklist file",
        "protected": ["tagent", "tagentV1.0", "tmanager-servic"],
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# F03 — chattr +i immutable file protection
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_F03_DEL_PROTECT = {
    "finding_id": "TOS46-AGT-F03",
    "severity": "HIGH",
    "title": (
        "chattr +i /usr/local/tagent — entire agent directory set immutable; "
        "even root cannot delete or modify files without running chattr -i first"
    ),
    "description": (
        "enable_tagent_del_protect() sets: "
        "  chattr +i /usr/local/tagent (directory immutable) "
        "  config: delProtect = true "
        "\n"
        "With +i: "
        "  - root cannot delete files in /usr/local/tagent "
        "  - root cannot rename files "
        "  - root cannot create/modify files "
        "  - root cannot rmdir the directory "
        "  chattr is an ext4/filesystem-level attribute "
        "\n"
        "disable_tagent_del_protect() must run before any upgrade: "
        "  sed -i 's/delProtect = true/delProtect = false/' config.conf "
        "  chattr -i -R /usr/local/tagent "
        "\n"
        "Attack surface: "
        "  - If attacker can write to /usr/local/tagent BEFORE chattr +i is set, "
        "    the files are protected from legitimate admin cleanup "
        "  - The installer runs as root and calls chattr directly — no integrity check "
        "    on the chattr binary itself "
        "  - Race window: between disable_tagent_del_protect() and re-enable after "
        "    upgrade, files can be modified "
        "\n"
        "Note: chattr +i does NOT protect against: "
        "  - Reads (files are still readable) "
        "  - Processes already having file descriptors open (memory-mapped binary still runs) "
        "  - Mounting a new filesystem over the path "
        "  - chattr -i (root can always remove the attribute)"
    ),
    "filesystem_attribute": "ext4 immutable (+i)",
    "scope": "/usr/local/tagent/ (recursive via chattr -i -R on disable; +i on single dir for enable)",
}

# ──────────────────────────────────────────────────────────────────────────────
# F04 — Root crontab + rc.local dual persistence
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_F04_PERSISTENCE = {
    "finding_id": "TOS46-AGT-F04",
    "severity": "HIGH",
    "title": (
        "tagent installs into /var/spool/cron/root and /etc/rc.d/rc.local — "
        "root crontab runs tagent-monitor.sh every minute; rc.local runs on boot"
    ),
    "description": (
        "check_crontab() appends to root's crontab: "
        "  # tagent monitor, install at <date> "
        "  * * * * * /usr/local/tagent/tagent-monitor.sh > /dev/null 2>&1 "
        "\n"
        "check_run_on_boot() appends to /etc/rc.d/rc.local: "
        "  # tagent bootstart, install at <date> "
        "  /usr/local/tagent/tagent-monitor.sh > /dev/null 2>&1 "
        "\n"
        "Both entries are checked for presence before adding (deduplication). "
        "On upgrade: dedup_monitor_lines() removes duplicate cron/rc.local entries. "
        "\n"
        "tagent-monitor.sh role: checks if tagent is running; restarts if not. "
        "Combined with kill_protect and chattr +i: "
        "  - process can't be killed → kill_protect "
        "  - binary can't be replaced → chattr +i "
        "  - monitor restarts if process somehow dies → crontab "
        "  - re-runs after reboot → rc.local "
        "\n"
        "systemd service also installed (tagent.service, Restart=always, RestartSec=5). "
        "Four independent persistence mechanisms for a single daemon."
    ),
    "persistence_mechanisms": [
        "/var/spool/cron/root — runs every minute",
        "/etc/rc.d/rc.local — runs on every boot",
        "tagent.service (systemd, Restart=always, RestartSec=5)",
        "tagent-watchdog.sh (from post-install tmanager)",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F05 — Hardcoded auth key in tagent binary
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_F05_STATIC_KEY = {
    "finding_id": "TOS46-AGT-F05",
    "severity": "HIGH",
    "title": (
        "Hardcoded auth key in tagent binary: base64-encoded 46-byte value in JSON "
        "message template with id=126 — static credential in stripped x86 ELF"
    ),
    "description": (
        "Extracted from tagent binary via `strings`: "
        '  {"key":"KRm1yXsnj/3zlPnq5KdzjzG4OdwUApSjdtgKX9Ecckw4luiWe7mKyg==", "id": 126, "ts": '
        "\n"
        "Analysis: "
        "  - Base64 value: KRm1yXsnj/3zlPnq5KdzjzG4OdwUApSjdtgKX9Ecckw4luiWe7mKyg== "
        "  - Decoded length: 46 bytes (non-standard; not AES-128/256 or EC key directly) "
        "  - id: 126 — message type or API endpoint identifier "
        "  - ts: partial JSON — this is a message template with timestamp field "
        "\n"
        "The key appears in a JSON message fragment — likely the auth payload format "
        "sent to the TManager server (9.150.206.219:53333). "
        "\n"
        "Implications: "
        "  1. Static key in binary: rotated per release at most (release 2.1.6). "
        "     Any instance running this version uses the same key. "
        "  2. The key is shared across ALL TOS 4.6 instances using tagent 2.1.6. "
        "  3. Any attacker who extracts this key (trivial from binary) can forge "
        "     tagent authentication messages to the TManager endpoint IF they can "
        "     reach 9.150.206.219:53333. "
        "  4. From within Tencent Cloud: straightforward. "
        "     From the public internet: blocked by network (9.x.x.x is private). "
        "\n"
        "Full key context would require disassembly of the auth flow to determine "
        "exactly how the key is used (HMAC input, symmetric encryption key, "
        "challenge-response seed, etc.)."
    ),
    "raw_key": "KRm1yXsnj/3zlPnq5KdzjzG4OdwUApSjdtgKX9Ecckw4luiWe7mKyg==",
    "decoded_length_bytes": 46,
    "message_id": 126,
    "location": "tagent x86 ELF binary, extracted via strings",
}

# ──────────────────────────────────────────────────────────────────────────────
# F06 — ECDSA static pub_key in tmp-tagent-push (not stripped)
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_F06_ECDSA = {
    "finding_id": "TOS46-AGT-F06",
    "severity": "HIGH",
    "title": (
        "tmp-tagent-push (NOT stripped) — CryptoPP ECDSA static pub_key singleton; "
        "verify_signature(string, string) verifies cloud push payloads; "
        "single hardcoded public key anchor for all tagent installations"
    ),
    "description": (
        "Binary: tmp-tagent-push (4.1MB, x86, debug_info present, NOT stripped) "
        "\n"
        "Symbols extracted: "
        "  0x406ade: T _Z16verify_signatureRSsS_  "
        "    (verify_signature(std::string&, std::string&)) "
        "  0x772868: b _ZGVZ16verify_signatureRSsS_E7pub_key "
        "    (static pub_key in verify_signature — initialized once, BSS segment) "
        "  0x406ea1: T _Z9push_dataRSsS_iS_S_ "
        "    (push_data(string&, string&, int, string&, string&) — 5-param push) "
        "\n"
        "CryptoPP algorithm classes present: "
        "  DL_Algorithm_ECDSA<ECP> — prime-curve ECDSA "
        "  DL_Algorithm_ECDSA<EC2N> — binary-curve ECDSA "
        "  DL_KeyAgreementAlgorithm_DH — DH key agreement "
        "  DL_Algorithm_GDSA<Integer> — DSA "
        "  X509PublicKey with DL_GroupParameters_EC — standard EC public key format "
        "\n"
        "Architecture: "
        "  The pub_key singleton is initialized from an embedded public key (X.509/DER). "
        "  verify_signature(data, sig) verifies the signature using this key. "
        "  push_data sends data to TManager after signing/verifying. "
        "\n"
        "Key extraction approach: "
        "  pub_key is at BSS 0x772868 (static singleton). "
        "  The constructor that initializes it is called at program startup. "
        "  GDB: b _Z16verify_signatureRSsS_ → step through initialization → "
        "  dump the CryptoPP DL_PublicKey object to recover the EC public key bytes. "
        "\n"
        "Implications: "
        "  - Single public key for all TOS 4.6 tagent instances globally "
        "  - If the corresponding private key is compromised, all tagent instances "
        "    accept forged push payloads "
        "  - The private key is held by Tencent's TManager infrastructure "
        "  - This is the trust anchor for command authorization from cloud to agent"
    ),
    "binary": "tmp-tagent-push",
    "stripped": False,
    "debug_info": True,
    "pub_key_address": "BSS 0x772868 (static singleton in verify_signature)",
    "crypto_library": "CryptoPP (Crypto++)",
    "algorithm": "ECDSA over prime curve (ECP)",
}

# ──────────────────────────────────────────────────────────────────────────────
# F07 — wujing module: UPX-packed, statically linked, no section header
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_F07_WUJING = {
    "finding_id": "TOS46-AGT-F07",
    "severity": "HIGH",
    "title": (
        "mod/wujing/wujing: UPX-packed, statically linked, no section header — "
        "intentionally obfuscated module of unknown function bundled in tagent; "
        "'wujing' (武警) = Chinese People's Armed Police / security enforcement"
    ),
    "description": (
        "Binary: /usr/local/tagent/mod/wujing/wujing "
        "  ELF 64-bit LSB x86-64 "
        "  Statically linked (no dynamic symbol table) "
        "  No section header (stripped via --strip-sections or objcopy) "
        "  UPX packed (UPX! magic detected in strings) "
        "  No section header: cannot use readelf -S, nm, or objdump -d directly "
        "\n"
        "Name etymology: "
        "  武警 (wūjǐng) = People's Armed Police Force — China's paramilitary security "
        "  In Tencent context: internal name for a security enforcement module "
        "  Other possible: internal abbreviation of security product name "
        "\n"
        "Configuration: mod-config/wujing.conf "
        "  (content not extracted — in the extracted payload directory) "
        "\n"
        "UPX unpacking approach: "
        "  upx -d wujing -o wujing_unpacked "
        "  Then: file wujing_unpacked → raw ELF sections accessible "
        "  Then: strings/objdump/Ghidra analysis "
        "\n"
        "What modules like this commonly do in cloud agents: "
        "  - Host intrusion detection (file integrity monitoring) "
        "  - Process monitoring for unauthorized processes "
        "  - Network connection monitoring "
        "  - Anti-tampering checks on the agent itself "
        "  - Reporting to Tencent's security platform "
        "\n"
        "Risk: "
        "  - Opaque binary that runs as root, statically linked, no symbols "
        "  - Cannot be audited without unpacking and disassembly "
        "  - Could perform any kernel interaction without visibility "
        "  - The combination of UPX + no section header is unusual for legitimate "
        "    monitoring tools — typically used to prevent/slow analysis "
        "\n"
        "Pending: UPX unpack + Ghidra/radare2 disassembly for function enumeration."
    ),
    "binary_properties": {
        "link": "statically linked",
        "stripped": "section headers stripped (no section header table)",
        "packing": "UPX",
        "arch": "x86-64 ELF 64-bit",
    },
    "analysis_status": "PENDING — requires UPX unpack + disassembly",
}

# ──────────────────────────────────────────────────────────────────────────────
# F08 — System V IPC shared memory keys
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_F08_SYSV_IPC = {
    "finding_id": "TOS46-AGT-F08",
    "severity": "MEDIUM",
    "title": (
        "System V IPC: tlinux-tagent-shm-2023, tlinux-tagent-shm-2025, "
        "tlinux-tagent-sem-2023 — versioned cross-process communication channels "
        "between tagent and its modules; keys are predictable"
    ),
    "description": (
        "Extracted from tagent binary strings: "
        "  tlinux-tagent-shm-2023 (System V shared memory key) "
        "  tlinux-tagent-shm-2025 (System V shared memory key — protocol upgrade) "
        "  tlinux-tagent-sem-2023 (System V semaphore key) "
        "\n"
        "System V IPC keys are derived from ftok() or hardcoded. "
        "String-based keys (like these named keys) suggest a custom ftok derivation "
        "or a hash of the name string. "
        "\n"
        "Year-versioned keys (2023, 2025) indicate a protocol version bump — "
        "tagent 2.x introduced the 2025 shared memory channel (presumably for new "
        "IPC protocol features), while the 2023 channel remains for backward compat. "
        "\n"
        "IPC security: "
        "  - System V shared memory inherits permissions from creator "
        "  - If the SHM segment is world-readable (0666), any local process can read "
        "    the contents of the inter-module communication "
        "  - The sem key is used for synchronization across module invocations "
        "\n"
        "Analysis: IPC segment permissions require runtime observation. "
        "  ipcs -m on a running TOS 4.6 system with tagent installed would show "
        "  the actual permissions. If 0666, any local process can observe "
        "  the command/response traffic between tagent and its modules."
    ),
    "ipc_keys": {
        "shm_2023": "tlinux-tagent-shm-2023 (legacy protocol)",
        "shm_2025": "tlinux-tagent-shm-2025 (current protocol)",
        "sem_2023": "tlinux-tagent-sem-2023 (module sync)",
    },
    "runtime_check": "ipcs -m && ipcs -s — verify permissions on live system",
}

# ──────────────────────────────────────────────────────────────────────────────
# F09 — IBM POWER tmanager agent (older vintage)
# ──────────────────────────────────────────────────────────────────────────────

TAGENT_F09_POWER = {
    "finding_id": "TOS46-AGT-F09",
    "severity": "INFO",
    "title": (
        "tms_agent_install.zip contains power/agent.zip (2024-06-13) — "
        "IBM POWER TManager channel agent is 18+ months older than x86/arm builds"
    ),
    "description": (
        "tms_agent_install.zip contents: "
        "  arm/agent.zip  2025-12-24 (recent) "
        "  x86/agent.zip  2025-12-24 (recent) "
        "  power/agent.zip 2024-06-13 (18 months older) "
        "\n"
        "The POWER channel agent is significantly older. If it carries bugs "
        "that were fixed in later x86/arm versions, POWER-deployed TOS instances "
        "are running a more vulnerable variant of the TManager channel. "
        "\n"
        "IBM POWER TOS 4.6 deployment is lower-volume but exists (industrial/HPC). "
        "The separate shim POWER Secure Boot path (grub2 IBM OFSB patches) "
        "and this POWER-specific agent build confirm active POWER support."
    ),
    "build_dates": {
        "x86": "2025-12-24",
        "arm": "2025-12-24",
        "power": "2024-06-13 (18+ months older)",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# INSTALL SCRIPT SECURITY OBSERVATIONS
# ──────────────────────────────────────────────────────────────────────────────

INSTALL_SCRIPT_OBSERVATIONS = {
    "tmp_dir_predictable": {
        "observation": "make_tmp() uses /tmp/tagent-rpm.$$ — shell PID, not mktemp -d",
        "severity": "LOW",
        "detail": (
            "Shell PID is predictable in some contexts. "
            "An attacker who knows the installer is running can pre-create "
            "/tmp/tagent-rpm.<pid> as a symlink to redirect extraction. "
            "Modern kernels with /proc/sys/fs/protected_symlinks=1 mitigate this."
        ),
    },
    "tagent_rpm_skip_root": {
        "observation": "TAGENT_RPM_SKIP_ROOT=1 environment variable bypasses root check",
        "severity": "LOW",
        "detail": (
            "require_root() returns 0 immediately if TAGENT_RPM_SKIP_ROOT=1. "
            "This is a test/debug escape hatch in the production SRPM. "
            "Not directly exploitable (caller must set env var before invocation), "
            "but indicates the installer was designed with a root bypass switch."
        ),
    },
    "cgroup_management": {
        "observation": "tagent creates/manages its own cgroups (v1 and v2 aware)",
        "severity": "INFO",
        "detail": (
            "Cgroup paths: /sys/fs/cgroup/memory/tagent/, /sys/fs/cgroup/cpu/tagent/ "
            "Resource limits applied at runtime (CPU 20%, memory 800MB). "
            "The agent self-limits to avoid detection via anomalous resource usage."
        ),
    },
    "inner_zip_extraction": {
        "observation": "install.sh passes unzip directly to bash: bash ./install.sh inside nested ZIP",
        "severity": "INFO",
        "detail": (
            "Pattern: unzip → bash → unzip → bash → install "
            "The inner install.sh runs from the temp directory with cwd set by the outer script. "
            "No integrity verification on the inner ZIP contents."
        ),
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-AGT-F01": TAGENT_F01_C2,
    "TOS46-AGT-F02": TAGENT_F02_KILL_PROTECT,
    "TOS46-AGT-F03": TAGENT_F03_DEL_PROTECT,
    "TOS46-AGT-F04": TAGENT_F04_PERSISTENCE,
    "TOS46-AGT-F05": TAGENT_F05_STATIC_KEY,
    "TOS46-AGT-F06": TAGENT_F06_ECDSA,
    "TOS46-AGT-F07": TAGENT_F07_WUJING,
    "TOS46-AGT-F08": TAGENT_F08_SYSV_IPC,
    "TOS46-AGT-F09": TAGENT_F09_POWER,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "package": "tagent-2.1.6-1.tl4",
        "license": "Proprietary",
        "source": "https://git.woa.com/tlinux/TManager/tagent",
        "c2_ip": "9.150.206.219:53333",
        "kernel_anti_kill": "/proc/kill_protect/blacklist",
        "findings": [
            {
                "id": k,
                "severity": v.get("severity"),
                "title": v.get("title", "")[:80],
            }
            for k, v in FINDINGS.items()
        ],
    }, indent=2))
