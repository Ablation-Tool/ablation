"""
Cisco IP Phone 88xx MPP 14.4.1 RE Module (Delta from 12.0.7)
Target: cmterm-88xx.14-4-1-0301-6.zip
Models: 8841, 8851, 8861, 8865
Architecture: Tri-chip (PLATFORM_1, PLATFORM_2, PLATFORM_3), ARM 32-bit
Source: /media/cowboy/research/Cisco-IP PHONE/cmterm-88xx.14-4-1-0301-6.zip
Version: 14.4.1 MPP (0301-6); built 2026-06-09 (from SquashFS creation timestamp)

Baseline: cisco_88xx_12_mpp_re.py (12.0.7)
This module documents the delta between 12.0.7 and 14.4.1 for the 88xx family.

Key changes from 12.0.7:
  REGRESSION: debug account re-activated (same hash as all other 14.4.1 targets)
  PARTIAL FIX: wlanmgr now runs as app:services (privilege lowered from root:root)
  PERSISTENT:  btman + btrl still root:root (uncommented fix not applied)
  PERSISTENT:  preloader still non-secure loader + UART fallback
  NEW:         debugsh binary ships in P1 and P3 (14728-byte shell ELF, ncurses+readline+system())

SBN delta (14.4.1 vs 12.0.7):
  rootfs88xx:  +11 MB (61.7 MB -> 72.8 MB, 1902 inodes)
  rootfs288xx: +15 MB
  rootfs388xx: +0.8 MB
  preloader:   40852 -> 41528 bytes (v2.6.0.C-rc2 -> v2.6.0.C-rc2-dirty)
  m0patch:     same size (14728 bytes), same 2016-04-05 timestamp, different SHA256
               (SBN wrapper updated; uImage payload may be identical)
"""

METADATA = {
    "target":   "Cisco IP Phone 88xx MPP Firmware 14.4.1 (0301-6)",
    "models":   "8841, 8851, 8861, 8865",
    "platform": "Tri-chip: P1 SquashFS + P2 SquashFS + P3 UBI (same as 12.0.7)",
    "built":    "2026-06-09 (from rootfs88xx SquashFS creation timestamp)",
    "accounts": {
        "P1_P3": {
            "debug": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71 ACTIVE -- password: debug (cracked)",
            "shell": "/usr/sbin/debugsh (stripped ELF, ncurses+readline, system() call)",
            "root":  "!:0:0:root:/home/root:/sbin/nologin (locked)",
        },
    },
    "preloader": {
        "version":      "Bootastic v2.6.0.C-rc2-dirty",
        "note":         "-dirty suffix = built from tree with uncommitted changes (CI artifact in production)",
        "uart_fallback": ", backup not exist, try UART / , backup failed, try UART (both strings present)",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug:debug Account Re-Activated in 14.4.1 with debugsh Interactive Shell Replacing /bin/false",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "In 88xx 12.0.7, the debug account is locked (`debug:*`, shell `/bin/false`) "
            "on all three platforms. In 14.4.1, the debug account has an active MD5-crypt "
            "hash `$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71` confirmed in both P1 (SquashFS) "
            "and P3 (UBI). The password was cracked as `debug` (confirmed in "
            "cisco_phoneos_5_0_1_re.py F1 across all 14.4.1 model families). "
            "The shell changed from `/bin/false` to `/usr/sbin/debugsh` -- a purpose-built "
            "interactive debug shell (stripped ARM ELF 32-bit, dynamically linked). "
            "debugsh imports: `libncurses.so.6`, `libedit.so.0` (readline-compatible), "
            "`libplatform.so.0.0`, `libnetsd.so`, `libupgapi.so.0.0`, and libc `system()`. "
            "The binary contains a `start_interactive_shell` function and exposes the "
            "following commands via its CLI: `btcli`, `cipcfg`, `clrdns`, `date`, `debug`, "
            "`dmesg`, `netstat`, `ping`, `ping6`, `help`, `commands`. "
            "The presence of `system()` + `start_interactive_shell` indicates the shell "
            "can spawn subprocesses and likely provides a path to unrestricted command "
            "execution. "
            "This regression affects all 88xx models (8841, 8851, 8861, 8865) in 14.4.1. "
            "Cross-reference: cisco_phoneos_5_0_1_re.py F1 documents the same regression "
            "across 7832, 78xx, 8832, 88xx, and 8845_65 in 14.4.1."
        ),
        "hash":            "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "password":        "debug (cracked)",
        "shell_12_0_7":    "/bin/false",
        "shell_14_4_1":    "/usr/sbin/debugsh (interactive shell, ncurses+readline+system())",
        "debugsh_commands": ["btcli", "cipcfg", "clrdns", "date", "debug", "dmesg", "netstat", "ping", "ping6", "help", "commands"],
        "debugsh_internals": ["system() syscall", "start_interactive_shell()", "libncurses.so.6", "libedit.so.0"],
        "platforms_confirmed": ["P1 (rootfs88xx 14.4.1)", "P3 (rootfs388xx 14.4.1)"],
        "impact": [
            "debug:debug SSH login on any 88xx phone running 14.4.1",
            "debugsh shell: netstat, dmesg, btcli, cipcfg accessible from SSH session",
            "system() + start_interactive_shell = unrestricted command execution from debug shell",
            "cipcfg (Cisco IP phone config) from shell may bypass web admin auth",
        ],
        "remediation": (
            "Lock the debug account by replacing the active hash with `!` in /etc/passwd/shadow. "
            "Change debug shell from /usr/sbin/debugsh to /bin/false or /sbin/nologin. "
            "See cisco_phoneos_5_0_1_re.py F1 for fleet-wide impact."
        ),
        "yara": """rule cisco_88xx_14_debug_regression {
    meta:
        description = "Cisco 88xx 14.4.1 debug account re-activated with debugsh shell"
        severity = "CRITICAL"
    strings:
        $debug_hash = "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71" ascii
        $debugsh    = "/usr/sbin/debugsh" ascii
    condition:
        $debug_hash and $debugsh
}""",
    },
    {
        "id": "F2",
        "title": "Bluetooth Manager (btman, btrl) Still root:root in 14.4.1 -- wlanmgr Privilege Fixed",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "description": (
            "Between 12.0.7 and 14.4.1, Cisco applied a partial privilege fix: "
            "`wlanmgr.sh` now uses `BEUID=app:services` (no comment prefix) in 14.4.1. "
            "The Wi-Fi manager privilege escalation from cisco_88xx_12_mpp_re.py F1 "
            "is resolved for wlanmgr in this version. "
            "However, `btman.sh` and `btrl.sh` still retain the identical pattern "
            "from 12.0.7: `#BEUID=app:services` commented out, `BEUID=root:root` active. "
            "btman (Bluetooth manager) and btrl (Bluetooth rate limiter) continue to "
            "run as root across all platforms in 14.4.1. "
            "The partial fix demonstrates that Cisco recognized the privilege issue for wlanmgr "
            "but did not extend the same correction to the Bluetooth stack processes."
        ),
        "wlanmgr_status": "FIXED in 14.4.1 -- BEUID=app:services (not commented out)",
        "btman_status":   "UNFIXED in 14.4.1 -- BEUID=root:root (#BEUID=app:services commented out)",
        "btrl_status":    "UNFIXED in 14.4.1 -- BEUID=root:root (#BEUID=app:services commented out)",
        "impact": [
            "btman root:root: Bluetooth stack exploit gives root on 8861/8865 models",
            "btrl root:root: same root attack surface on BT rate limiter",
            "wlanmgr fixed -- Wi-Fi exploit now limited to app:services context",
        ],
        "remediation": (
            "Apply the same fix used for wlanmgr to btman.sh and btrl.sh: "
            "uncomment BEUID=app:services and remove BEUID=root:root."
        ),
    },
    {
        "id": "F3",
        "title": "Preloader Still Non-Secure with UART Fallback -- Now Built from Dirty Tree (v2.6.0.C-rc2-dirty)",
        "severity": "MEDIUM",
        "cvss": 6.8,
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-494",
        "description": (
            "The 14.4.1 preloader (`preloader88xx.BE-01-008.sbn`, 41528 bytes) "
            "is version `Bootastic v2.6.0.C-rc2-dirty`. "
            "The `-dirty` suffix indicates the binary was built from a git tree "
            "that had uncommitted or unstaged changes at build time -- a development "
            "artifact that should not appear in production firmware. "
            "The preloader retains both characteristics documented in 12.0.7 F2: "
            "(1) `non-secure loader` self-description, "
            "(2) UART fallback path -- both variants present: "
            "`, backup not exist, try UART` and `, backup failed, try UART`. "
            "The second string (`, backup failed, try UART`) is new in 14.4.1 "
            "(not present in 12.0.7). "
            "The preloader is 676 bytes larger than 12.0.7 (40852 -> 41528 bytes). "
            "No secure boot enforcement was added in this version."
        ),
        "version_14_4_1": "Bootastic v2.6.0.C-rc2-dirty (dirty suffix = CI artifact)",
        "version_12_0_7": "Bootastic v2.6.0.C-rc2",
        "uart_fallback":  "Both strings present: 'try UART' paths unchanged + new 'backup failed, try UART'",
        "impact": [
            "Physical unsigned firmware load via UART still possible in 14.4.1",
            "-dirty build artifact leaked to production firmware",
        ],
        "remediation": (
            "Clean CI build pipeline to prevent -dirty tagged binaries in production. "
            "Enforce secure boot and remove UART fallback path."
        ),
    },
]

SUMMARY = {
    "total":    3,
    "critical": 1,
    "high":     1,
    "medium":   1,
    "low":      0,
    "version_delta": (
        "14.4.1 vs 12.0.7: debug account regressed (CRITICAL); "
        "wlanmgr privilege fixed (partial win); btman+btrl still root (partial regression); "
        "debugsh ships as active shell for debug account; "
        "preloader UART fallback unchanged (now -dirty build artifact). "
        "See cisco_phoneos_5_0_1_re.py F1 for full fleet debug regression scope."
    ),
}
