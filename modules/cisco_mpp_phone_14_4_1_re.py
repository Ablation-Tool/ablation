"""
Cisco MPP IP Phone Firmware 14.4.1 RE Module
Target: cmterm-7832.14-4-1-0301-6.zip (Cisco IP Conference Phone 7832)
Format: SBN container (magic CD 34 12 AB, header 340 bytes) wrapping UBI erase image
UBI -> UBIFS -> Linux ARM rootfs (BusyBox 1.36.1)
Build: Jun 9 2026 06:03:34 UTC
"""

METADATA = {
    "target":    "Cisco IP Conference Phone 7832, MPP 14.4.1",
    "binary":    "rootfs7832.14-4-1-0301-6.sbn",
    "format":    "SBN container (magic CD 34 12 AB, 340-byte header) -> UBI -> UBIFS",
    "arch":      "ARM 32-bit (EABI5), Linux 2.6.16 ABI",
    "busybox":   "BusyBox v1.36.1 (2026-06-09 06:03:34 UTC)",
    "version":   "14.4.1 (sip7832.14-4-1-0301-6)",
    "build_date": "2026-06-09",
    "source":    "/media/cowboy/research/Cisco-IP PHONE/cmterm-7832.14-4-1-0301-6.zip",
    "rootfs_size": 45744128,
    "hw_platform": "Cisco 7832 IP Conference Phone (MIPS-to-ARM successor, wired)",
    "bt_chip":   "Broadcom BCM20705 (firmware: BCM20702B0_002.001.014.0628.1026.hcd)",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Hardcoded debug Account with Password debug Starts Root Command Daemon on Boot",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The firmware ships with a hardcoded `debug` account in `/etc/passwd` "
            "with password hash `$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71` (MD5-crypt, "
            "cracked: password = `debug`). The account's login shell is "
            "`/usr/sbin/debugsh`, which connects to `debugshd` (the debug shell "
            "daemon). The init script `debugshd.sh` starts `debugshd` on every "
            "boot with `--chuid root:root`, meaning debugshd runs with root "
            "privileges. An attacker who reaches SSH (when enabled) authenticates "
            "as `debug:debug` and gains a root command execution path via debugshd."
        ),
        "passwd_line": "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:65532:100:debug:/tmp:/usr/sbin/debugsh",
        "hash_type": "MD5-crypt ($1$)",
        "cracked_password": "debug",
        "init_script": "/etc/init.d/debugshd.sh",
        "beuid": "root:root",
        "daemon": "/usr/sbin/debugshd",
        "shell": "/usr/sbin/debugsh",
        "trigger_path": [
            "SSH enabled (when activated by TAC or config) -> port 22",
            "authenticate as debug / debug",
            "debugsh client connects to debugshd Unix socket",
            "debugshd (root) executes commands",
        ],
        "impact": [
            "Full root code execution on the conference phone",
            "Access to audio capture via getmicdata (libsecuremic.so)",
            "Read private call data, SIP credentials, provisioning config",
            "Persistent rootkit installation to flash",
        ],
        "remediation": (
            "Remove the debug account from /etc/passwd in production builds. "
            "If debug access is required for TAC, use ephemeral one-time SSH "
            "keys generated per device per session, not a shared static password. "
            "debugshd should not run as root; drop to a restricted service user."
        ),
        "yara": """rule cisco_mpp_debug_account_backdoor {
    meta:
        description = "Cisco MPP phone firmware has hardcoded debug:debug account with root access"
        severity = "CRITICAL"
    strings:
        $passwd_debug = "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71" ascii
        $debugshd     = "/usr/sbin/debugshd" ascii
        $shell        = "/usr/sbin/debugsh" ascii
        $root_chuid   = "root:root" ascii
    condition:
        $passwd_debug and $debugshd and $shell
}""",
    },
    {
        "id": "F2",
        "title": "SSH Service Configured but Disabled - debug Account Provides Root Shell When Activated",
        "severity": "HIGH",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-912",
        "description": (
            "The xinetd service definition at `/etc/xinetd.default/sshd` has "
            "`disable = yes`. Cisco TAC and engineering frequently re-enable SSH "
            "on phone handsets for troubleshooting. When SSH is activated (e.g., "
            "via phone web UI or a provisioned configuration), the debug account "
            "(F1) immediately becomes exploitable from the network. The xinetd "
            "sshd config runs the SSH daemon as root (`user = root`). The service "
            "has no allow_from or address restriction — accepting connections from "
            "any host."
        ),
        "xinetd_config": {
            "service":     "ssh",
            "disable":     "yes",
            "user":        "root",
            "server":      "/usr/sbin/sshd",
            "server_args": "/usr/sbin/sshd -i",
            "instances":   "3",
        },
        "impact": [
            "When SSH enabled for TAC troubleshooting, debug/debug is a permanent backdoor",
            "No address restriction - any host on the network can connect",
            "SSH process runs as root",
        ],
        "remediation": (
            "Restrict SSH to management VLAN via xinetd `only_from` directive. "
            "Remove debug account (F1) to eliminate the static backdoor credential. "
            "Log all SSH enable/disable events to syslog."
        ),
        "yara": """rule cisco_mpp_ssh_xinetd_no_restrict {
    meta:
        description = "Cisco MPP phone SSH service configured with no host restriction"
        severity = "HIGH"
    strings:
        $ssh_service = "service ssh" ascii
        $disable_yes = "disable     = yes" ascii
        $user_root   = "user        = root" ascii
        $sshd_path   = "/usr/sbin/sshd" ascii
    condition:
        all of them
}""",
    },
    {
        "id": "F3",
        "title": "getmicdata Binary Exposes Raw Microphone Access via Secure Audio API",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-284",
        "description": (
            "The binary `/usr/sbin/getmicdata` links against `libsecuremic.so` "
            "and calls `cprReadRawSecureData` / `cprGetRawSecureDataLen` to "
            "capture raw microphone PCM data from the DSP (via `libdspg.so`). "
            "The binary runs on the 7832 conference phone which has built-in "
            "microphones. An attacker with root shell access (F1/F2) can execute "
            "`getmicdata` to capture audio from the conference room, enabling "
            "passive eavesdropping on any meeting conducted via the phone."
        ),
        "libraries": [
            "libsecuremic.so",
            "libdspg.so",
            "libsecureapi.so",
            "libsecureStorage.so",
            "libplatformAbstraction.so",
        ],
        "api_calls": [
            "cprReadRawSecureData",
            "cprGetRawSecureDataLen",
        ],
        "impact": [
            "Remote audio surveillance of any meeting room where the phone is installed",
            "Combined with F1/F2: network-accessible root + microphone = passive room bug",
            "Persistent surveillance possible via rootkit installed to flash",
        ],
        "remediation": (
            "getmicdata should require explicit user authorization (physical button press) "
            "before opening the microphone channel. The API should not be callable from "
            "a shell without a user-visible indicator (e.g., LED). Remove the binary "
            "from production builds if not needed for shipped features."
        ),
        "yara": """rule cisco_mpp_getmicdata_audio_capture {
    meta:
        description = "Cisco MPP phone getmicdata binary can capture microphone audio"
        severity = "HIGH"
    strings:
        $binary      = "getmicdata" ascii
        $secure_mic  = "libsecuremic.so" ascii
        $cpr_read    = "cprReadRawSecureData" ascii
        $dspg        = "libdspg.so" ascii
    condition:
        $secure_mic and ($cpr_read or $dspg)
}""",
    },
    {
        "id": "F4",
        "title": "FTP Daemon Present - Potential Unauthenticated File Access",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-284",
        "description": (
            "The phone ships with an FTP daemon binary at `/usr/sbin/ftpd`. "
            "The binary is a BusyBox-linked ftpd. If it is started by xinetd "
            "or the phone's init scripts, anonymous or authenticated FTP access "
            "to the phone's filesystem may be possible. The debug account (F1) "
            "with password `debug` would provide FTP access to `/tmp` (the "
            "debug account's home directory)."
        ),
        "impact": [
            "File read/write access to /tmp via FTP using debug:debug",
            "Enables file drop for follow-on exploitation if SSH unavailable",
        ],
        "remediation": "Remove ftpd from the firmware or ensure no xinetd config enables it.",
        "yara": """rule cisco_mpp_ftpd_present {
    meta:
        description = "Cisco MPP phone firmware includes FTP daemon"
        severity = "MEDIUM"
    strings:
        $ftpd = "/usr/sbin/ftpd" ascii
        $bb   = "BusyBox" ascii
    condition:
        $ftpd
}""",
    },
    {
        "id": "F5",
        "title": "SBN Container Format - No Runtime Integrity Check After Flash Write",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-345",
        "description": (
            "The SBN container format (magic `CD 34 12 AB`, 340-byte header) "
            "wraps each firmware component with a signature block. Binwalk "
            "identifies no runtime integrity check performed after the rootfs "
            "UBIFS is mounted - verification happens at download/flash time only. "
            "An attacker with root access (F1) can modify the mounted UBIFS "
            "in-memory or write to flash partitions directly via `flash_erase` / "
            "`flash_eraseall` without re-signing the SBN container, achieving "
            "persistent firmware modification."
        ),
        "flash_tools": [
            "/usr/sbin/flash_erase",
            "/usr/sbin/flash_eraseall",
        ],
        "impact": [
            "Persistent rootkit survives reboots once root access is obtained via F1",
            "Signed firmware validation is bypassed for in-memory or direct flash writes",
        ],
        "remediation": (
            "Implement secure boot that validates the rootfs signature at mount time, "
            "not just at download time. Protect MTD flash partitions as read-only "
            "from userspace via kernel config (MTD_PARTITIONS_READONLY)."
        ),
        "yara": """rule cisco_mpp_flash_write_tools {
    meta:
        description = "Cisco MPP phone includes flash erase tools enabling persistent modification"
        severity = "MEDIUM"
    strings:
        $flash_erase    = "/usr/sbin/flash_erase" ascii
        $flash_eraseall = "/usr/sbin/flash_eraseall" ascii
    condition:
        any of them
}""",
    },
]

SUMMARY = {
    "total":    5,
    "critical": 1,
    "high":     2,
    "medium":   2,
    "low":      0,
}
