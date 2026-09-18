"""
Cisco IP Phone 6901 SIP/SCCP RE Module
Targets:
  cmterm-6901-sip.9-3-1-SR3-1.zip  -- 6901 SIP firmware
  cmterm-6901-sccp.9-3-1-SR3-1.zip -- 6901 SCCP firmware
Model: CP-6901 wired entry-level (single line, no display)
Architecture: TI TNETV1050/1055 (Avalanche AR7, MIPS LE), Linux 2.6.10 MontaVista 4.01

SBN format (both SIP and SCCP):
  Magic: 01 00 02 01 01 02 00 02 (same as 6901/8831 legacy series)
  CN=someSigner placeholder certificate (no real signing chain)
  APP*.zz.sgn: SBN header (416 bytes) + SquashFS v2.1 (lzma-adaptive, NOT gzip)
  KNL*.zz.sgn: SBN header (416 bytes) + raw MIPS bootable kernel image
  *.loads: SBN-wrapped manifest listing APP and KNL .zz.sgn files

SquashFS v2.1 note:
  Standard unsquashfs 4.x fails: header advertises gzip, data is lzma-adaptive.
  Required tool: sasquatch (devttys0/sasquatch) patched squashfs-tools 4.3.
  APP6901SIP: 264 inodes, 133 files, 96 symlinks, blocksize 65536, created 2023-07-17
  APP6901SCCP: 241 inodes, 143 files, 96 symlinks (adds 12 IVR .wav + libfips.so/libfipstest.so)

SoC:
  TI TNETV1050/1051/1052/1053/1055 (Avalanche AR7 MIPS family)
  Also supports TNETV1056 in the CPGMAC path (from eswitch_dhcp_ip4 script)
  Internal codenames: IGRAINE (standard 6901), ALETA (alternative project type)
  Kernel: Linux 2.6.10 mvl401-malta-mips2_fp_len (MontaVista Linux 4.01)
  Compiler: GCC 3.4.3 (MontaVista 3.4.3-25.0.70.0501961 2005-12-17)
  Libc: glibc 2.3.3

SCCP vs SIP differences:
  SCCP adds: libfips.so, libfipstest.so, 12 extra IVR .wav files (54-65)
  SCCP removes: libcpr.so, libcprmemory.a, libcprstring.a, libsipcc.so
  Shared: identical /etc/dss DSS private key (MD5: 4b99d3ce01aec6586b4f0dc102808570)
  Shared: identical stdioSwitch binary and stdioSwitch.ini credentials
  Shared: identical ggsvca_ipp dropbear launch command and all other binaries

Boot sequence (rcS):
  1. Mount /proc, /var (ramfs), /sys, /dev
  2. udevstart (TI udev)
  3. Mount jffs2 /dev/mtdblock/5 to /var/voice_conf
  4. insmod avalanche_eswitch.ko, avalanche_keypad.ko
  5. ifconfig lo 127.0.0.1, ifconfig esw0 up
  6. Create named pipes under /var/cliPipes/ (MXP and FOX CLI channels)
  7. Copy and start secdaemon (CAPF handler)
  8. kill -20 1 (SIGWINCH to init triggers restartApp.sh via inittab foxapp entry)
  restartApp.sh: loads kernel modules, starts ggsvca_ipp (main phone app)
  ggsvca_ipp: cp dropbear /var/dropbear && /var/dropbear -d /etc/dss -l /usr/sbin/stdioSwitch

SSH shell chain:
  dropbear -d /etc/dss -l /usr/sbin/stdioSwitch
  -> all SSH sessions exec stdioSwitch (Cisco-patched dropbear adds -l flag)
  -> stdioSwitch presents its own login: / password: prompt
  -> authenticate -> stdioSwitch CLI with commands: switch (SHELL|mxp|ACOS), show, help, exit
  -> 'switch SHELL' executes: execlp("/bin/sh") (from stdioSwitch.ini cli_execute_pathname)
"""

METADATA = {
    "targets": "Cisco 6901 SIP (cmterm-6901-sip.9-3-1-SR3-1) and SCCP (cmterm-6901-sccp.9-3-1-SR3-1)",
    "soc": "TI TNETV1050/1055 Avalanche AR7, MIPS LE, Linux 2.6.10 MontaVista 4.01",
    "compiler": "GCC 3.4.3 MontaVista 3.4.3-25.0.70.0501961 2005-12-17",
    "libc": "glibc 2.3.3",
    "ssh_daemon": "Dropbear 0.52 (2006), Cisco-patched with -l login-shell override flag",
    "squashfs": "v2.1 with lzma-adaptive compression (header claims gzip -- requires sasquatch)",
    "dss_key_md5": "4b99d3ce01aec6586b4f0dc102808570 (identical SIP and SCCP, all 6901 phones)",
    "key_files": {
        "/etc/dss": "full DSS-1024 private key (p+q+g+y+x, 457 bytes, wire format)",
        "/etc/passwd": "symlink to /var/passwd (runtime ramfs -- not in rootfs)",
        "/etc/shadow": "symlink to /var/shadow (runtime ramfs -- not in rootfs)",
    },
    "drodbear_launch": "cp /usr/sbin/dropbear /var/dropbear && /var/dropbear -d /etc/dss -l /usr/sbin/stdioSwitch",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Fleet-Wide DSS Private Key Hardcoded in /etc/dss -- All 6901 SIP and SCCP Phones Identical",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-321",
        "description": (
            "The file /etc/dss in both the SIP and SCCP 6901 firmware contains "
            "the complete DSS-1024 SSH host private key in SSH wire format: "
            "type (ssh-dss) + p (129 bytes) + q (21 bytes) + g (128 bytes) + "
            "y (128 bytes) + x (20 bytes private key), 457 bytes total. "
            "MD5: 4b99d3ce01aec6586b4f0dc102808570 -- identical across both firmware variants. "
            "Every CP-6901 phone ships with the same private key. "
            "Dropbear 0.52 loads this key via '/var/dropbear -d /etc/dss -l /usr/sbin/stdioSwitch' "
            "(ggsvca_ipp copies dropbear to /var/ and launches it with the hardcoded /etc/dss path). "
            "Consequences: (1) Passive network MitM -- the known private key lets an attacker impersonate "
            "any 6901 SSH host with zero computational cost. "
            "(2) Active MitM -- intercept and re-sign any SSH handshake. "
            "(3) Client key verification bypass -- SSH clients configured to trust the key fingerprint "
            "will silently connect to a rogue host. "
            "The SCCP variant ships the same key despite having FIPS libraries (libfips.so, libfipstest.so) "
            "added to the rootfs, making the FIPS inclusion cosmetically contradictory. "
            "The key is embedded in the read-only SquashFS rootfs and cannot be replaced without "
            "firmware modification."
        ),
        "key_md5": "4b99d3ce01aec6586b4f0dc102808570",
        "key_path": "/etc/dss",
        "key_fields": "p(129)+q(21)+g(128)+y(128)+x(20) = 457 bytes DSS-1024 full private key",
        "scope": "All CP-6901 SIP (9-3-1-SR3-1) and SCCP (9-3-1-SR3-1) phones",
        "impact": [
            "Passive SSH MitM against any 6901 using the known private key",
            "Active forgery of 6901 SSH host identity",
            "All CUCM/SIP provisioning over SSH trusting this key is compromised fleet-wide",
        ],
        "remediation": (
            "Generate a unique DSS (or Ed25519) host key per device at first boot, "
            "store in JFFS2 (/var/voice_conf/), not in the read-only rootfs. "
            "Short-term: rotate the fleet key via firmware update; any phone running "
            "9-3-1-SR3-1 or earlier should be treated as having a known host identity."
        ),
    },
    {
        "id": "F2",
        "title": "stdioSwitch Binary Contains Hardcoded Backdoor Credentials: debuguser/3edc!qaz",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The stdioSwitch binary (/usr/sbin/stdioSwitch, 70596 bytes, MIPS LE) "
            "contains hardcoded credentials in the .rodata section: "
            "username 'debuguser', password '3edc!qaz' (keyboard pattern: "
            "columns 3,e,d,c and Shift+1,q,a,z on QWERTY). "
            "These credentials appear directly before the login:/password:/invalid username! "
            "strings and are compiled into the binary, not read from any configuration file. "
            "They cannot be changed without firmware replacement. "
            "stdioSwitch is executed as the SSH login shell for all SSH sessions "
            "(Dropbear 0.52 Cisco-patched flag: -l /usr/sbin/stdioSwitch). "
            "The stdioSwitch CLI supports three sub-CLIs: SHELL (executes /bin/sh), "
            "mxp (MXP application CLI), and ACOS (voice signaling CLI). "
            "The SHELL CLI is configured in /etc/stdioSwitch.ini with "
            "'cli_execute_pathname = /bin/sh'. "
            "Full exploit chain: SSH connect to port 22 on the phone, "
            "authenticate with any valid Linux account (or via a default account), "
            "stdioSwitch prompts login:/password:, "
            "enter debuguser/3edc!qaz, "
            "type 'switch SHELL', "
            "stdioSwitch calls execlp('/bin/sh') -> root shell. "
            "The stdioSwitch.ini also contains 'supervisor/12345' and 'user/12345' "
            "as a second credential layer (see F3), but the hardcoded debuguser/3edc!qaz "
            "in the binary is primary and always present."
        ),
        "hardcoded_creds": {
            "username": "debuguser",
            "password": "3edc!qaz",
            "location": "stdioSwitch binary .rodata, before login: prompt strings",
        },
        "shell_chain": "SSH -> stdioSwitch (debuguser/3edc!qaz) -> 'switch SHELL' -> execlp('/bin/sh')",
        "impact": [
            "Network-accessible root shell on any 6901 phone",
            "Authentication bypass: credentials are static and known fleet-wide",
            "Combined with F1 (known host key) -- silent MitM plus full compromise",
        ],
        "remediation": (
            "Remove hardcoded credentials from stdioSwitch binary. "
            "Disable SSH access entirely or restrict to management VLAN. "
            "Replace stdioSwitch with a proper PAM-authenticated mechanism."
        ),
    },
    {
        "id": "F3",
        "title": "stdioSwitch.ini Hardcoded Credentials -- supervisor/12345 and user/12345 -> /bin/sh",
        "severity": "HIGH",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1392",
        "description": (
            "The file /etc/stdioSwitch.ini contains two credential pairs with default passwords: "
            "supervisor_name=supervisor, supervisor_password=12345 and "
            "first_user_name=user, first_user_password=12345. "
            "The SHELL CLI entry in the same file sets cli_execute_pathname=/bin/sh. "
            "Unlike the F2 hardcoded binary credentials, these could theoretically be changed "
            "if the file were writable, but /etc is in the read-only SquashFS rootfs. "
            "The stdioSwitch binary reads /etc/stdioSwitch.ini at startup and loads these "
            "credentials for its own authentication layer. "
            "When authenticated as supervisor or user, the 'switch SHELL' command "
            "causes stdioSwitch to call execlp('/bin/sh'). "
            "The supervisor account has the higher privilege ('client_mode=1') while "
            "user has 'client_mode=1' as well. "
            "Secondary attack path: same shell chain as F2 but using ini-file credentials."
        ),
        "ini_credentials": {
            "supervisor": "12345",
            "user": "12345",
        },
        "shell_cli": "cli_execute_pathname = /bin/sh (SHELL instance in stdioSwitch.ini)",
        "config_path": "/etc/stdioSwitch.ini (read-only SquashFS, cannot be modified at runtime)",
        "impact": [
            "Alternative path to root shell (same outcome as F2)",
            "supervisor and user accounts have identical access to SHELL CLI",
        ],
        "remediation": "Remove or password-protect the SHELL CLI instance in stdioSwitch.ini.",
    },
    {
        "id": "F4",
        "title": "gdbserver Present in /sbin -- Allows Remote Process Debugging",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-489",
        "description": (
            "A functional gdbserver binary is present at /sbin/gdbserver in the 6901 rootfs "
            "(MIPS LE ELF, for GNU/Linux 2.4.17, stripped). "
            "gdbserver is a remote debugging stub that allows a remote GDB instance to "
            "attach to and control any process on the device. "
            "From strings: 'Listening on port %d', 'HOST:PORT to listen for a TCP connection', "
            "'gdbserver COMM PROG [ARGS ...]', 'gdbserver COMM --attach PID'. "
            "gdbserver is not started at boot (not in rcS or restartApp.sh). "
            "However, an attacker who obtains shell access via F2/F3 can start "
            "'gdbserver 0.0.0.0:1234 --attach <pid_of_ggsvca_ipp>' to "
            "attach to the main phone process and extract memory (SIP credentials, CUCM TLS keys, "
            "CAPF certificate material, call audio buffers) in real time. "
            "This tool has no legitimate purpose in a production phone firmware."
        ),
        "binary_path": "/sbin/gdbserver",
        "activation": "Not started at boot; requires shell access to invoke",
        "impact": [
            "Real-time memory extraction from ggsvca_ipp (SIP creds, TLS session keys, call audio)",
            "Process control and arbitrary code injection into running phone application",
        ],
        "remediation": "Remove gdbserver from production firmware.",
    },
    {
        "id": "F5",
        "title": "Dropbear SSH 0.52 (2006, EOL) -- Multiple Known CVEs",
        "severity": "HIGH",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-119",
        "description": (
            "The 6901 ships Dropbear SSH version 0.52, released 2006, "
            "banner: SSH-2.0-dropbear_0.52. "
            "This version predates fixes for multiple critical CVEs: "
            "CVE-2016-7406 (format string vulnerability in dbclient, pre-2016.73), "
            "CVE-2016-7407 (dropbearconvert format string, pre-2016.73), "
            "CVE-2016-7408 (format string in dbclient progress display, pre-2016.73), "
            "CVE-2016-7409 (out-of-bounds read via %s in dbclient, pre-2016.73), "
            "CVE-2012-0920 (use-after-free in channel handling, pre-0.52 officially but "
            "Dropbear 0.52 predates the disclosure-era fixes), "
            "CVE-2013-4421 (DoS via compression). "
            "The Cisco-patched version adds the -l flag (shell override) but does not "
            "update the underlying version or apply CVE fixes. "
            "Dropbear 0.52 also lacks modern cipher suites and MAC algorithms: "
            "it will negotiate des-cbc, arcfour, hmac-md5, and other broken algorithms. "
            "No RSA host key -- only DSS-1024 (the hardcoded /etc/dss key from F1)."
        ),
        "version": "0.52 (2006)",
        "banner": "SSH-2.0-dropbear_0.52",
        "cves": [
            "CVE-2016-7406 (format string RCE, pre-2016.73)",
            "CVE-2016-7407 (format string, pre-2016.73)",
            "CVE-2016-7408 (format string, pre-2016.73)",
            "CVE-2016-7409 (OOB read, pre-2016.73)",
            "CVE-2012-0920 (use-after-free)",
            "CVE-2013-4421 (DoS)",
        ],
        "impact": [
            "Remote code execution via known CVEs against Dropbear 0.52",
            "Weak cipher negotiation (des-cbc, arcfour, hmac-md5)",
        ],
        "remediation": "Replace Dropbear 0.52 with a current version (2022+) and update cipher configuration.",
    },
    {
        "id": "F6",
        "title": "Linux 2.6.10 MontaVista 4.01 EOL Kernel -- No Security Mitigations",
        "severity": "MEDIUM",
        "cvss": 6.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1104",
        "description": (
            "The 6901 runs Linux 2.6.10 with MontaVista Linux 4.01 patches, "
            "compiled with GCC 3.4.3 (MontaVista 3.4.3-25.0.70.0501961 2005-12-17). "
            "Kernel 2.6.10 reached EOL in 2005. "
            "No security mitigations in kernel or binaries: "
            "no ASLR (ASLR added in 2.6.12), no stack canaries (GCC 3.4.3 supports -fstack-protector "
            "but MontaVista build does not use it), no NX/XN (MIPS lacks hardware XN on TNETV1050), "
            "no PIE (all binaries are fixed-address ELF executables). "
            "glibc 2.3.3 (2003) -- predates heap hardening, FORTIFY_SOURCE, and safe unlinking. "
            "The MXP application (ggsvca_ipp, 3.7MB) runs all phone logic as a single process "
            "with no privilege separation, making any memory corruption in ggsvca_ipp "
            "an immediate full-system compromise. "
            "libpthread-0.10.so -- pthread 0.10, pre-NPTL (LinuxThreads), predates all "
            "thread-safety improvements and POSIX compliance requirements."
        ),
        "kernel": "2.6.10 mvl401-malta-mips2_fp_len (EOL 2005)",
        "compiler": "GCC 3.4.3 (MontaVista 2005-12-17)",
        "libc": "glibc 2.3.3 (2003)",
        "mitigations_absent": ["ASLR", "stack canaries", "NX/XN", "PIE", "FORTIFY_SOURCE"],
        "impact": [
            "Any memory corruption in ggsvca_ipp = unconstrained code execution at MIPS ring 0",
            "glibc heap corruption trivially exploitable (no safe unlinking or malloc hardening)",
        ],
        "remediation": "Platform replacement required; 2.6.10 is not patchable to a secure baseline.",
    },
    {
        "id": "F7",
        "title": "Telnetd (Busybox) Present and Commented Out -- Trivially Re-Activatable",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-912",
        "description": (
            "The busybox telnetd binary is present at /usr/sbin/telnetd (symlink to ../../bin/busybox). "
            "rcS contains two commented-out telnetd invocations: "
            "###/usr/sbin/telnetd -p 7870 & (debug port) and "
            "###/usr/sbin/telnetd -p 23 -s 15 -l /usr/sbin/stdioSwitch (console port). "
            "The ### comment prefix is the same used throughout rcS for disabled debug lines "
            "(telnet was active during development and disabled before release). "
            "An attacker with root access via F2/F3 can start telnetd directly: "
            "/usr/sbin/telnetd -p 7870 -l /bin/sh & -- no authentication, immediate shell. "
            "The -l /usr/sbin/stdioSwitch variant would require the stdioSwitch credentials (F2/F3) "
            "but the plain -l /bin/sh variant is an unauthenticated backdoor. "
            "The phone also has a secondary commented-out shell respawn in inittab: "
            "#console::respawn:/etc/shell.sh (which spawns /bin/sh in an infinite loop)."
        ),
        "telnetd_path": "/usr/sbin/telnetd -> ../../bin/busybox",
        "commented_invocations": [
            "###/usr/sbin/telnetd -p 7870 & (debug port, no auth)",
            "###/usr/sbin/telnetd -p 23 -s 15 -l /usr/sbin/stdioSwitch (console port)",
        ],
        "impact": [
            "Attacker with initial access can re-activate telnetd as persistent unauthenticated backdoor",
        ],
        "remediation": "Remove telnetd binary from production firmware entirely.",
    },
    {
        "id": "F8",
        "title": "TI TNETV1050/1055 SoC, IGRAINE/ALETA Codename, MontaVista Toolchain Exposure",
        "severity": "LOW",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "The 6901 firmware discloses full supply-chain and SoC details: "
            "(1) TI TNETV1050/1051/1052/1053/1055 SoC family (Avalanche AR7 MIPS LE) -- "
            "identified from kernel module paths (avalanche_eswitch.ko, avalanche_keypad.ko), "
            "eswitch_dhcp_ip4 script (case statements for SOC=1050/1051/1052/1053/1055/1056), "
            "and ggsvca_ipp strings (TNETV1050). "
            "(2) Internal project codenames: IGRAINE (primary 6901 config) and ALETA (default fallback) -- "
            "exposed in rcS, restartApp.sh, and /etc/project.mak (IPP_PROJECT_TYPE=ALETA). "
            "The IGRAINE path mounts a second squashfs from mtdblock for the apps partition. "
            "(3) MontaVista Linux 4.01 toolchain: GCC 3.4.3 dated 2005-12-17/18 in all binaries. "
            "(4) /proc/avalanche/ filesystem: exposes boot config (BOOT_CFG=PRI/SEC), "
            "environment variables (MEMSZ, SOC_READ), and upgrader info via the proc interface."
        ),
        "soc": "TI TNETV1050/1051/1052/1053/1055 (Avalanche AR7 MIPS LE)",
        "codenames": ["IGRAINE (6901 standard)", "ALETA (default/fallback project type)"],
        "toolchain": "GCC 3.4.3 MontaVista 3.4.3-25.0.70.0501961 2005-12-17",
        "impact": ["SoC and toolchain knowledge enables targeted exploit development"],
        "remediation": "N/A -- informational finding.",
    },
]

SUMMARY = {
    "total":    8,
    "critical": 2,
    "high":     3,
    "medium":   2,
    "low":      1,
    "notes": (
        "The 6901 represents the oldest architecture in the Cisco IP Phone research set: "
        "2005-era TI TNETV1050 MIPS, Linux 2.6.10, glibc 2.3.3, GCC 3.4.3, Dropbear 0.52. "
        "F1 (fleet-wide private SSH key) + F2 (hardcoded backdoor credentials) form a "
        "complete unauthenticated RCE chain reachable over the network on any 6901 running "
        "9-3-1-SR3-1 or earlier. "
        "The SCCP variant shares all vulnerabilities with the SIP variant "
        "(identical /etc/dss key, identical stdioSwitch binary and credentials). "
        "No BEUID privilege model (this is pre-BEUID legacy firmware). "
        "The SquashFS v2.1 + lzma-adaptive compression format mismatch "
        "(header claims gzip, data is lzma-adaptive) is a vendor firmware tool artifact, "
        "not a security measure."
    ),
}
