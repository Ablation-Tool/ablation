"""
Cisco UCS VIC M85 Firmware RE module
Target: ucs-m85-vic.5.4.2.47.bin (extracted from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Codename: Beverly (confirmed: bin/load_rtdb.sh detects 'Beverly' ASIC)
Build tag: cspgre-260131-13:31:41 (January 31, 2026)
Version: 5.4(2.47)

VIC M85 firmware structure:
  Outer:    Cisco SN header (964B, magic=6401534E) + gzip stream
  Inner:    54,948,328B decompressed
  At 0x7c:  gzip (original name: mpf113555)
  At 0xffd000: CPIO archive (641 entries) — main VIC MIPS Linux rootfs
  ELFs in inner:
    0x520000:  32-bit MIPS LE SO — Linux kernel/DTS (contains 'Cisco VIC Beverly', 'cisco,bodega-intc')
    0x934400:  32-bit MIPS LE SO — libcrypto (OpenSSL AES, EVP)
    0xbd2e00:  32-bit MIPS LE SO — libmicrohttpd 12.46.0 + libmicrohttpd.so.12 (HTTP server)
    0x237aa00: 32-bit MIPS LE SO — VIC management tools (amp_setdebug, palotool_dbg_cmds_init)
  VIC architecture: MIPS 32-bit LE, BusyBox/uClibc, JFFS2 rootfs overlay on NAND

CPIO rootfs contents (key binaries):
  bin/mcp (2.3MB)     — management control plane
  bin/nictool (371KB) — NIC tool
  bin/vniccfgd        — VNIC config daemon
  bin/redfish (333KB) — Redfish API server (libmicrohttpd)
  bin/launcher        — starts mcp.sh, macd.sh, vniccfgd, ecom, nfe, redfish
  bin/dbgsh           — restricted debug CLI shell (readline + cli_run)
  lib/libchallenge.so — challenge/response auth library (uses /dev/urandom)

Management channels:
  127.7.254.1 sam1, 127.8.254.1 sam2 — loopback addresses for CIMC-to-VIC management
  NCSI (ncsi_enable=1)  — BMC sideband interface to VIC
  TCP/23 (telnet)       — xinetd, BusyBox telnetd, dbgsh login program
  TCP/513 (rlogin)      — xinetd, in.rlogind (BSD r-commands)
  HTTPS (libmicrohttpd) — Redfish API server (bin/redfish)

Files analyzed:
  etc/xinetd.conf, etc/inittab, etc/init.d/rcS, etc/passwd, etc/shadow, etc/securetty
  bin/securechk, bin/consolelogin, bin/bmcdebugshell
  etc/nosec/{login,consolelogin,debugplugin,iptables-rules,iptables-manage,iptables-netflow}
  bin/mcp.sh, bin/macd.sh, bin/launcher
  bin/dbgsh (strings), bin/redfish (strings)
  usr/sbin/telnetd (busybox symlink), usr/sbin/in.rlogind
"""

FIRMWARE = {
    "target":    "Cisco UCS VIC M85 (Beverly) firmware 5.4(2.47)",
    "file":      "ucs-m85-vic.5.4.2.47.bin",
    "codename":  "Beverly (ASIC); mpf113555 (archive name)",
    "build":     "cspgre-260131-13:31:41 (2026-01-31)",
    "arch":      "MIPS 32-bit LE, BusyBox/uClibc Linux",
    "kernel":    "MIPS LE ELF SO at inner+0x520000 (device tree: cisco,bodega-intc)",
    "rootfs":    "CPIO archive at inner+0xffd000 (641 entries) + JFFS2 at inner+0x123e00",
    "findings":  ["VIC-M85-F1", "VIC-M85-F2", "VIC-M85-F3", "VIC-M85-F4", "VIC-M85-F5", "VIC-M85-F6"],
}

# VIC-M85-F1: Telnet enabled on TCP/23 with dbgsh as no-auth login program
VIC_M85_F1 = {
    "id":       "VIC-M85-F1",
    "title":    "Telnet (TCP/23) enabled via xinetd on VIC M85 — BusyBox telnetd configured "
                "with '-l dbgsh' which executes the debug CLI shell directly without any "
                "password authentication challenge",
    "severity": "HIGH",
    "status":   "CONFIRMED — etc/xinetd.conf extracted from CPIO; service telnet disable=no; "
                "server=/usr/sbin/telnetd; server_args=-i -l dbgsh; "
                "BusyBox telnetd -l <prog> skips /bin/login and executes <prog> directly; "
                "bin/dbgsh is a readline-based debug CLI (cli_init + cli_run) with no auth logic",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-319 (Cleartext Transmission of Sensitive Information)"],
    "files":    ["etc/xinetd.conf", "usr/sbin/telnetd (busybox symlink)", "bin/dbgsh"],
    "verbatim_xinetd": """
service telnet
{
    disable         = no
    flags           = REUSE IPv6
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/telnetd
    server_args     = -i -l dbgsh
    log_on_failure  += USERID
}
""",
    "busybox_telnetd_flag": {
        "-l <loginprog>": "BusyBox telnetd: execute <loginprog> INSTEAD of /bin/login. "
                          "No password exchange occurs — the login program receives the "
                          "connection and determines auth. With -l dbgsh, /bin/dbgsh "
                          "is exec'd immediately upon connection without any challenge.",
        "contrast":       "With -l /bin/login (default), login prompts for user+password. "
                          "With -l dbgsh, authentication is entirely delegated to dbgsh "
                          "which does not implement any authentication challenge.",
    },
    "dbgsh_analysis": {
        "binary":    "bin/dbgsh — 15,948B MIPS LE ELF",
        "imports":   ["cli_init", "cli_run", "g_prompt", "rl_line_buffer",
                      "rl_completion_matches", "history_length", "history_get"],
        "auth_strings": "ZERO auth/password/login/credential strings in binary",
        "behavior":  "Initializes a readline-based CLI (cli_run) immediately on connection. "
                     "No password prompt, no PAM, no shadow lookup. "
                     "Exposes VIC debug command set to any connecting client.",
    },
    "nosec_escalation": {
        "condition": "If /config/devel.cfg has security=0 (see VIC-M85-F3), "
                     "bin/securechk replaces /bin/debugplugin with etc/nosec/debugplugin",
        "nosec_debugplugin": "#!/bin/sh\nexec /bin/sh -l",
        "result":    "In nosec mode, any operation in dbgsh that invokes debugplugin "
                     "drops to an interactive root shell over the telnet connection",
    },
    "network_exposure": {
        "tcp_23":     "Telnet listens on all interfaces when xinetd starts (rcS: xinetd)",
        "ipv6_flag":  "REUSE IPv6 — dual-stack listener",
        "interfaces": "VIC management interfaces: SAM channels (127.7.254.1/127.8.254.1), "
                      "NCSI BMC sideband (ncsi_enable=1 in palo.cfg), "
                      "optional management VNIC (mgmtvnic_enable configurable)",
    },
    "threat_model": "Any host that can reach TCP/23 on the VIC M85 management interface "
                    "(via NCSI, SAM loopback, or management VNIC) connects with telnet and "
                    "immediately receives the VIC debug CLI (dbgsh) without any credential "
                    "exchange. The debug CLI exposes VIC ASIC diagnostic commands, "
                    "configuration reads, and potentially privileged operations.",
}

# VIC-M85-F2: rlogin TCP/513 enabled via in.rlogind
VIC_M85_F2 = {
    "id":       "VIC-M85-F2",
    "title":    "rlogin (TCP/513) enabled on VIC M85 via xinetd/in.rlogind — BSD "
                "r-command trust-based authentication with .rhosts/hosts.equiv",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — etc/xinetd.conf service login disable=no; "
                "server=/usr/sbin/in.rlogind; in.rlogind binary extracted (13,792B); "
                "contains: deny_all_rhosts_hequiv, allow_root_rhosts, use_rhosts, ruserok",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-319 (Cleartext Transmission of Sensitive Information)"],
    "files":    ["etc/xinetd.conf", "usr/sbin/in.rlogind"],
    "verbatim_xinetd": """
service login
{
    disable        = no
    socket_type    = stream
    wait           = no
    user           = root
    log_on_success += USERID
    log_on_failure += USERID
    server         = /usr/sbin/in.rlogind
}
""",
    "rlogind_analysis": {
        "binary":    "usr/sbin/in.rlogind — 13,792B MIPS LE ELF (custom build, not BusyBox)",
        "auth_funcs": ["deny_all_rhosts_hequiv", "allow_root_rhosts", "use_rhosts",
                       "__check_rhosts_file", "ruserok"],
        "auth_model": "BSD .rhosts / /etc/hosts.equiv hostname-based trust. "
                      "If any CIMC or blade management host is in the VIC's trust list, "
                      "a compromised CIMC can rlogin to the VIC without a password.",
        "root_exposure": "allow_root_rhosts function present — root logins via .rhosts possible",
    },
    "threat_model": "A host listed in the VIC's /etc/hosts.equiv or a user's .rhosts "
                    "can rlogin to the VIC M85 as root without a password. In UCSM-managed "
                    "mode, the CIMC (blade management controller) likely has hostname trust "
                    "configured for management channel communication — a compromised CIMC "
                    "can pivot to the VIC over rlogin TCP/513.",
}

# VIC-M85-F3: nosec mode activation via writable /config partition
VIC_M85_F3 = {
    "id":       "VIC-M85-F3",
    "title":    "Persistent nosec mode activation via writable /config UBIFS partition — "
                "writing 'security = 0' to /config/devel.cfg causes securechk to replace "
                "production auth binaries with no-password equivalents at next boot; "
                "additionally, /config/early_rc, mid_rc, and late_rc are sourced as "
                "root during boot from the same writable partition",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — bin/securechk + etc/nosec/* extracted from CPIO; "
                "etc/init.d/rcS sources /config/early_rc before securechk; "
                "securechk replaces consolelogin+debugplugin+login in /bin; "
                "nosec equivalents confirmed: login=no-password, consolelogin=exec login root, "
                "debugplugin=exec /bin/sh -l; iptables rules = exit 0 in nosec mode",
    "cwe":      ["CWE-284 (Improper Access Control)", "CWE-732 (Incorrect Permission Assignment)",
                 "CWE-693 (Protection Mechanism Failure)"],
    "files":    ["bin/securechk", "etc/init.d/rcS", "etc/nosec/login",
                 "etc/nosec/consolelogin", "etc/nosec/debugplugin",
                 "etc/nosec/iptables-rules", "etc/nosec/iptables-manage",
                 "etc/nosec/iptables-netflow"],
    "verbatim_securechk": """
#!/bin/sh

if grep -q '^security[ ]*=[ ]*0' /config/devel.cfg 2>/dev/null
then
    cd /bin
    rm consolelogin debugplugin login
    cd /etc/nosec
    mv consolelogin debugplugin login /bin
fi
""",
    "verbatim_rcS_boot_hooks": """
# Early hook — runs BEFORE securechk in boot sequence:
if [ -f /config/early_rc ]; then . /config/early_rc; fi

# securechk runs here (checks /config/devel.cfg)
securechk

# ... later in boot ...
if [ -f /config/mid_rc ]; then . /config/mid_rc; fi

# ... at end of boot ...
if [ -f /config/late_rc ]; then . /config/late_rc; fi
""",
    "nosec_mode_effects": {
        "login":          "No password check — defaults to root shell if no user specified",
        "consolelogin":   "exec /bin/login root — auto-logins as root on ttyS0",
        "debugplugin":    "exec /bin/sh -l — full interactive root shell",
        "iptables-rules": "exit 0 — no iptables rules installed (all connections allowed)",
        "iptables-manage": "exit 0 — management interface firewall bypassed",
        "iptables-netflow": "exit 0 — netflow interface firewall bypassed",
    },
    "activation_method": {
        "trigger":  "Write file: /config/devel.cfg containing 'security = 0'",
        "timing":   "Effect on NEXT reboot (securechk reads the file at boot time)",
        "persistence": "/config is UBIFS on NAND flash — persists across firmware updates "
                       "if /config partition is not wiped",
        "write_paths": [
            "VIC Redfish API (bin/redfish) — authenticated POST/PUT to config endpoints",
            "MCP management protocol (bin/mcp) — UCSM/CIMC sends config to VIC",
            "SAM management channel (127.7.254.1/127.8.254.1) — CIMC-to-VIC IPC",
            "VIC tech support export (configurable remote destination via Redfish) "
            "— may allow file write via path traversal in remote path parameter",
        ],
    },
    "boot_hook_threat": {
        "early_rc": "/config/early_rc sourced BEFORE securechk — any file here runs "
                    "before security options are even checked. Even if nosec mode is "
                    "detected and reverted, early_rc already executed as root.",
        "mid_rc":   "/config/mid_rc sourced after securechk and xinetd — full management "
                    "stack is already running. Arbitrary commands execute as root.",
        "late_rc":  "/config/late_rc at end of boot — all daemons running. "
                    "Can add services, modify running processes.",
    },
    "threat_model": "An attacker who achieves any write to the VIC's /config UBIFS partition "
                    "(via authenticated VIC management API, CIMC-to-VIC management channel, "
                    "or configuration injection from UCSM) can create /config/devel.cfg with "
                    "'security = 0'. After VIC reboot, all authentication is bypassed, "
                    "all iptables rules are disabled, and the nosec debugplugin turns the "
                    "existing telnet service into a full root shell.",
}

# VIC-M85-F4: /config/mcp and /config/macd persistent binary override
VIC_M85_F4 = {
    "id":       "VIC-M85-F4",
    "title":    "launcher executes /config/mcp and /config/macd as root if those files "
                "exist on writable UBIFS /config partition — persistent VIC management "
                "control plane compromise via config-partition binary placement",
    "severity": "HIGH",
    "status":   "CONFIRMED — bin/mcp.sh and bin/macd.sh extracted from CPIO; "
                "both check /config/<binary> and exec it instead of production binary; "
                "bin/launcher references /bin/mcp.sh and /bin/macd.sh; "
                "the override produces banner warning to /dev/console but still executes",
    "cwe":      ["CWE-284 (Improper Access Control)", "CWE-732 (Incorrect Permission Assignment)"],
    "files":    ["bin/mcp.sh", "bin/macd.sh", "bin/launcher"],
    "verbatim_mcp_sh": """
#!/bin/sh
# For debugging, check for /config/mcp and run that one if found.
if [ -x /config/mcp ]; then
    cat > /etc/mcp_banner << EOF
=============================================================
=                          WARNING                          =
=        Running /config/mcp instead of /bin/mcp            =
=============================================================
EOF
    cat /etc/mcp_banner > /dev/console
    exec /config/mcp $*
fi
exec mcp $*
""",
    "verbatim_macd_sh": """
#!/bin/sh
# For debugging, check for /config/macd and run that one if found.
if [ -x /config/macd ]; then
    exec /config/macd $*
fi
exec macd $*
""",
    "launcher_evidence": "bin/launcher (17,584B) references /bin/mcp.sh and /bin/macd.sh "
                         "as the startup scripts for the VIC management control plane",
    "threat_model": "An attacker who can write a MIPS LE ELF or shell script to /config/ "
                    "as 'mcp' or 'macd' (executable) achieves persistent code execution "
                    "as the VIC management control plane on every boot. These processes "
                    "run as root and have access to VIC ASIC control interfaces, network "
                    "configuration, and the NCSI/SAM management channels to the CIMC. "
                    "This survives VIC firmware updates since /config is a separate partition.",
}

# VIC-M85-F5: bmcdebugshell on ttyS1 — no-auth serial debug shell
VIC_M85_F5 = {
    "id":       "VIC-M85-F5",
    "title":    "inittab spawns bmcdebugshell on ttyS1 (hardware UART3, 38400 baud) "
                "without any authentication — direct debug CLI access via serial",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — etc/inittab and bin/bmcdebugshell extracted from CPIO; "
                "ttyS1::respawn:/bin/bmcdebugshell /dev/ttyS1 38400 vt100 in inittab; "
                "bmcdebugshell: stty + conf + /bin/dbgsh — no password challenge",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "files":    ["etc/inittab", "bin/bmcdebugshell"],
    "verbatim_inittab": "ttyS1::respawn:/bin/bmcdebugshell /dev/ttyS1 38400 vt100",
    "verbatim_bmcdebugshell": """
#!/bin/sh
dev=$1; speed=$2; term=$3
stty -F $dev speed $speed crtscts >/dev/null 2>&1
export TERM=$term
echo ''
conf
/bin/dbgsh
""",
    "threat_model": "Physical access to the VIC M85's hardware UART3 pins provides immediate "
                    "access to the VIC debug CLI (dbgsh) without any credential. The UART "
                    "is the 'BMC debug shell' channel — it is separate from the host-side "
                    "UART and connects to the VIC's MIPS management CPU. "
                    "respawn ensures the shell restarts automatically if killed.",
}

# VIC-M85-F6: root DES crypt hash embedded in production firmware
VIC_M85_F6 = {
    "id":       "VIC-M85-F6",
    "title":    "Root account DES crypt password hash embedded in production VIC firmware "
                "(/etc/shadow: root:lAV031WHrUqto) — firmware extraction yields hash "
                "for offline cracking; dbgsh account has empty password hash",
    "severity": "HIGH",
    "status":   "CONFIRMED — etc/shadow extracted from CPIO; "
                "root:lAV031WHrUqto (DES crypt, salt 'lA', 11-char hash); "
                "dbgsh:: (empty hash — password field empty); "
                "etc/securetty is 0 bytes (root login allowed on any TTY)",
    "cwe":      ["CWE-256 (Plaintext Storage of Password)", "CWE-916 (Use of Password Hash "
                 "With Insufficient Computational Effort)"],
    "file":     "etc/shadow",
    "verbatim_shadow": """
root:lAV031WHrUqto:14396:0:99999:7:::
dbgsh::14396:0:99999:7:::
""",
    "hash_analysis": {
        "root_hash":    "lAV031WHrUqto — DES crypt (Unix crypt(3)); "
                        "salt='lA', hash='V031WHrUqto'; "
                        "DES crypt brute-force rate: ~850M/s on RTX 4090 (hashcat -m 1500); "
                        "8-char keyspace crackable in hours; default passwords tested: NONE MATCHED",
        "dbgsh_hash":   ":: (empty) — in shadow, empty hash field means passwordless account; "
                        "used by: consolelogin (calls '/bin/login dbgsh'), "
                        "telnet via -l dbgsh flag (bypasses /bin/login entirely)",
        "securetty":    "etc/securetty is 0 bytes — empty securetty = root login allowed "
                        "from any TTY (no restriction to secure terminals)",
    },
    "firmware_extraction_path": "ucs-k9-bundle-b-series.6.0.2b.B.bin → "
                                "SN header (852B) → gzip → tar (582 entries) → "
                                "ucs-m85-vic.5.4.2.47.bin → SN header (964B) → gzip → "
                                "tar → ./blob (20MB) → CPIO at +0xffd000 → etc/shadow",
    "threat_model": "Any researcher or attacker with access to the publicly distributed "
                    "B-Series firmware bundle can extract /etc/shadow from the VIC firmware "
                    "and run hashcat -m 1500 against 'lAV031WHrUqto'. If the root password "
                    "is shared across all M85 VIC deployments (common for embedded firmware "
                    "with static shadow files), the cracked password grants root access "
                    "to any M85 VIC reachable via telnet TCP/23 (see VIC-M85-F1). "
                    "The dbgsh empty hash additionally means any login attempt for the "
                    "dbgsh account on console (ttyS0) succeeds with any password.",
}

FINDINGS = [VIC_M85_F1, VIC_M85_F2, VIC_M85_F3, VIC_M85_F4, VIC_M85_F5, VIC_M85_F6]
