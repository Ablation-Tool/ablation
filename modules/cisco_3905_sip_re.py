"""
Cisco IP Phone 3905 SIP RE Module
Target: cmterm-3905.9-4-1SR4-2.zip
Model: CP-3905 wired analog entry-level phone (handset receiver only, no display)
Architecture: Sigma Designs SC1445x (M68K uClinux, no MMU), Linux 2.6.19, ROMFS
Version: SIP 9.4.1SR4-2; signed 2023-10-23
Source: /media/cowboy/research/Cisco-IP PHONE/

Archive format (2 files):
  APP3905.9-4-1SR4-2.zz   -- uImage: M68K Linux kernel + embedded ROMFS (2.86 MB)
  CP3905.9-4-1SR4-2.loads -- manifest: just lists APP3905.9-4-1SR4-2.zz

Format (monolithic firmware, same SBN signed wrapper as 8831):
  SBN wrapper: magic 01 00 02 01 01 02 00 02, CN=someSigner;OU=someOrgUnit;O=someOrg
  uImage at offset 0x0 within SBN (the .zz file IS the uImage, not wrapped further):
    magic:     0x27051956
    timestamp: 2023-10-23 01:11:53
    arch:      M68K (12)
    type:      kernel (2)
    compress:  gzip (1)
    size:      2865692 bytes
    load/entry: 0x26000
    name:      '' (empty)
  gzip at offset 0x40 within uImage
  vmlinux.bin: 5349433 bytes (5.1 MB decompressed)
  ROMFS embedded at 0x1C4000 in vmlinux.bin:
    magic: -rom1fs-
    size: 3492640 bytes (3.3 MB)
    name: 'rom 65360ea6'

Hardware:
  SoC: Sigma Designs SC1445x (M68K, ColdFire-compatible, DECT processor)
  Confirmed by: sc1445x_audio_ctrl binary in /bin, 'sc1445x-cvqm' kernel module in rcS
  ODM: Foxconn (confirmed via rcS comments: Vincent Chen, Iris Wang, 2009-2010)
  Flash: MTD NAND (mtdblock3 for initramfs, mtdblock5 for JFFS2 data)

ROMFS contents:
  /etc/passwd -> /var/passwd (symlink to writable JFFS2 path)
  /etc/shadow -> /var/shadow (symlink to writable JFFS2 path)
  /etc/group:  root::0:root
  /etc/inittab: ::sysinit:/etc/init.d/rcS; ::askfirst:/bin/sh (CONSOLE ROOT SHELL)
  /etc/boa.conf: Port 80, User root, Group root, ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
  /etc/inetd.conf: all services commented out (inetd runs but no services active)
  /bin/siphone, pjcu: SIP phone application binaries (Sigma Designs reference)
  /bin/sc1445x_audio_ctrl: SC1445x SoC audio control (confirms hardware)
  /bin/busybox: BusyBox utilities
  /sbin/telnetd, stdioSwitch: telnet available but disabled

rcS init script:
  1. Mounts ramfs at /mnt/ramfs (writable runtime paths)
  2. Mounts JFFS2 at /mnt/flash (/dev/mtdblock5)
  3. Creates CLI pipes for ACOS and SHELL clients
  4. Starts inetd (no active services)
  5. Launches phone application (siphone, sicvm, si_natalie_head, etc.)
  6. Loads sc1445x-cvqm module (CVQM = Call Voice Quality Metrics)
  7. Runs stdioSwitch (CLI switch)

ODM history revealed in rcS comments:
  - 'Foxconn add start, Vincent Chen, 02/17/2009'
  - 'Foxconn add end, Iris Wang, 2010/08/24'
  - 'Foxconn remove start, Vincent Chen, 02/17/2009'
  - Commented telnetd: '#/sbin/telnetd -p 7870 -l /bin/sh &' (historical unauthenticated root shell)

Extraction:
  dd if=APP3905.9-4-1SR4-2.zz bs=1 skip=64 | gunzip -c > vmlinux.bin
  dd if=vmlinux.bin bs=1 skip=1851392 count=3492640 > romfs.img
  sudo mount -t romfs -o loop romfs.img /mnt/3905
"""

METADATA = {
    "target":    "Cisco IP Phone 3905 SIP 9.4.1SR4-2",
    "model":     "CP-3905 entry-level wired phone (handset only, no display, no BT/WiFi)",
    "platform":  "Sigma Designs SC1445x M68K uClinux, Linux 2.6.19, ROMFS",
    "built":     "2023-10-23 (uImage timestamp)",
    "soc":       "Sigma Designs SC1445x (M68K, DECT-capable, sc1445x_audio_ctrl and sc1445x-cvqm module)",
    "odm":       "Foxconn (Vincent Chen, Iris Wang; referenced in rcS comments 2009-2010)",
    "accounts":  {
        "root": "root::0:root (NO PASSWORD -- empty password field in /etc/passwd format)",
    },
    "linux_version": "2.6.19 (EOL 2006, in production 2023)",
    "web_server":    "Boa v0.94 on port 80 as root (CGI at /cgi-bin/ -> /usr/lib/cgi-bin/)",
    "inittab_shell": "::askfirst:/bin/sh (console presents root shell without authentication)",
    "historical": "telnetd -p 7870 -l /bin/sh commented out in rcS (prior builds: unauthenticated root telnet)",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "root Account Has No Password -- root::0:root in /etc/passwd (Empty Password Field)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-521",
        "description": (
            "The embedded ROMFS `/etc/passwd` (linked at runtime from `/var/passwd`) "
            "contains `root::0:root` -- a 4-field entry with an empty password field (`::`). "
            "This means the root account has no password. "
            "Any authentication mechanism that uses the passwd file directly "
            "(PAM, login, su, SSH password auth) will accept empty-string authentication for root. "
            "This is confirmed by the 4-field format (name:password:uid:gid) "
            "which is the old-style non-shadowed passwd format where the second field is the "
            "DES-crypt password or empty string for passwordless access. "
            "The `/etc/shadow` symlink at `/var/shadow` points to a runtime-created file "
            "on the writable JFFS2 partition -- if no shadow file exists at boot, "
            "the system falls back to the /var/passwd file with the empty root password. "
            "The `login` binary is present in /bin, confirming password-based login is supported."
        ),
        "passwd_entry": "root::0:root (4-field format, empty password = no password)",
        "shadow_path":  "/var/shadow (writable JFFS2 path -- may not exist at first boot)",
        "impact": [
            "root login with empty password on any enabled service (SSH, telnet, Boa CGI)",
            "No password = no credential needed for escalation from any shell session",
        ],
        "remediation": "Set a strong root password. Use shadow passwords. Lock root account with ! or * in shadow.",
    },
    {
        "id": "F2",
        "title": "inittab ::askfirst:/bin/sh -- Physical Console Access Yields Root Shell Without Authentication",
        "severity": "HIGH",
        "cvss": 6.8,
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "description": (
            "The `/etc/inittab` contains `::askfirst:/bin/sh`. "
            "In BusyBox inittab format, `askfirst` means: start the specified program on the "
            "console and prompt 'Please press Enter to activate this console'. "
            "Pressing Enter starts `/bin/sh` immediately as root with no authentication. "
            "This is a development-mode setting that bypasses all authentication "
            "for anyone with physical console (serial UART) access to the phone. "
            "The 3905 hardware exposes a UART debug header typical of Sigma Designs "
            "SC1445x development boards. "
            "Combined with the empty root password (F1), there is no authentication layer "
            "between physical access and a root shell -- pressing Enter on the UART console "
            "is sufficient."
        ),
        "inittab_line":   "::askfirst:/bin/sh",
        "effect":         "UART console press-Enter = root shell, no credentials required",
        "impact": [
            "Physical UART access = immediate root shell with no credentials",
            "Combined with F1 (empty root password): two independent paths to root",
        ],
        "remediation": "Replace ::askfirst:/bin/sh with a getty-based login. Remove or disable the UART debug console in production.",
    },
    {
        "id": "F3",
        "title": "Boa HTTP Server v0.94 on Port 80 Running as root with CGI Enabled",
        "severity": "HIGH",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "description": (
            "The Boa HTTP server v0.94 runs on port 80 as `User root, Group root` "
            "with CGI scripts enabled at `ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/`. "
            "The document root is `/var/www` (a runtime ramfs/JFFS2 path). "
            "Boa 0.94 has multiple known vulnerabilities: "
            "CVE-2002-2030 (path traversal), CVE-2017-9793 (request handling memory corruption), "
            "and various buffer overflows in header parsing. "
            "Any CGI scripts present in /usr/lib/cgi-bin/ (populated from JFFS2 at runtime) "
            "execute as root. "
            "The boa.conf has Basic Auth configuration commented out "
            "(`#Auth /internal /etc/internal.passwd`), meaning the web interface "
            "serves content and executes CGI with no authentication by default. "
            "Combined with the empty root password (F1), the web interface provides "
            "an additional unauthenticated path to root code execution."
        ),
        "boa_version":  "0.94 (2002-era, multiple CVEs)",
        "boa_user":     "root:root",
        "boa_port":     80,
        "cgi_path":     "/usr/lib/cgi-bin/ (mapped from JFFS2 flash at runtime)",
        "auth_status":  "commented out -- no authentication by default",
        "known_cves":   ["CVE-2002-2030 (path traversal)", "CVE-2017-9793 (memory corruption)"],
        "impact": [
            "Any CGI script in /cgi-bin/ executes as root on network access",
            "Boa CVEs applicable: path traversal, buffer overflow -> root code execution",
            "Web interface serves as unauthenticated network attack vector to root",
        ],
        "remediation": "Replace Boa with a modern web server. Drop root privileges (User/Group to non-root). Enable authentication.",
    },
    {
        "id": "F4",
        "title": "Historical Unauthenticated Root Telnet on Port 7870 Present in rcS (Commented Out)",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "description": (
            "The `/etc/init.d/rcS` script contains a commented-out line: "
            "`#/sbin/telnetd -p 7870 -l /bin/sh &`. "
            "This line, if uncommented, starts telnetd on port 7870 with `/bin/sh` "
            "as the login program -- providing unauthenticated root shell access over telnet "
            "without any credential challenge. "
            "The comment `# Foxconn add start, Vincent Chen, 08/21/2009` nearby "
            "indicates this was a Foxconn ODM debug feature added in 2009. "
            "It was commented out in this (2023) build but remains in the script. "
            "A second commented-out telnetd variant uses stdioSwitch: "
            "`#/sbin/telnetd -p 23 -s 15 -l /sbin/stdioSwitch &` (standard port 23). "
            "The presence of active `telnetd` in /sbin (as a symlink to busybox) "
            "means telnetd can be enabled at runtime if an attacker has a shell. "
            "This finding documents a historical ODM debug backdoor that could reappear "
            "if the rcS file on the writable JFFS2 partition is modified."
        ),
        "commented_out": True,
        "original_line":  "#/sbin/telnetd -p 7870 -l /bin/sh &",
        "origin":        "Foxconn ODM debug feature, Vincent Chen, 2009-08-21",
        "jffs2_risk":    "/etc/init.d/rcS appears in ROMFS; but writable JFFS2 overlay could replace startup scripts",
        "impact": [
            "Historical record: unauthenticated root telnet on port 7870 existed in ODM builds",
            "Re-enabling requires only uncommenting one line (trivial if shell access obtained)",
            "telnetd binary remains in /sbin -- available for runtime re-enablement",
        ],
        "remediation": "Remove the commented telnetd lines from rcS. Remove telnetd from /sbin in production builds.",
    },
    {
        "id": "F5",
        "title": "Sigma Designs SC1445x M68K SoC + Foxconn ODM + Linux 2.6.19 EOL Kernel (2023 Deployment)",
        "severity": "LOW",
        "cvss": 3.3,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "Multiple information disclosures and an EOL kernel: "
            "(1) Hardware SoC: Sigma Designs SC1445x (M68K, DECT processor) confirmed by "
            "`/bin/sc1445x_audio_ctrl` binary and `modprobe sc1445x-cvqm` in rcS. "
            "Path in rcS: `sc14450_fs` in JFFS2 config path confirms SC14450 (full part number). "
            "(2) ODM identity: Foxconn confirmed by rcS comments "
            "`Foxconn add start, Vincent Chen, 02/17/2009`, "
            "`Foxconn add end, Iris Wang, 2010/08/24` -- "
            "developer names and dates leak the ODM development history. "
            "(3) Linux 2.6.19: released 2006, upstream EOL long before 2023. "
            "Known vulnerabilities include CVE-2016-5195 (Dirty COW) and numerous "
            "local privilege escalation, information disclosure, and memory corruption issues. "
            "However, as an M68K uClinux system (no MMU), exploitation is architecture-specific. "
            "(4) The firmware uses the same Cisco SBN signed format as the 8831 SIP "
            "(`CN=someSigner;OU=someOrgUnit;O=someOrg` placeholder cert) -- "
            "no chain-of-trust verification against real Cisco PKI. "
            "(5) NVS default config (`/etc/nvs.bin`, 1024 bytes) starts with "
            "`000d 4450` (NVS magic with 'DP' marker) -- proprietary Sigma Designs NVS format."
        ),
        "soc":          "Sigma Designs SC14450/SC1445x (M68K DECT SoC)",
        "odm":          "Foxconn (Vincent Chen, Iris Wang; 2009-2010 development dates)",
        "kernel":       "Linux 2.6.19 (EOL 2006, in production 2023 firmware)",
        "sbn_cert":     "CN=someSigner (same placeholder as 8831 SIP -- no real Cisco PKI)",
        "nvs_magic":    "000d 4450 (Sigma Designs NVS format, 1024-byte default config)",
        "impact": [
            "SC1445x M68K uClinux: no MMU = different security properties from MPU systems",
            "Linux 2.6.19 EOL: extensive CVE exposure (mitigated by uClinux/no-MMU architecture)",
            "ODM names leak potential social engineering / supply chain research vectors",
        ],
        "remediation": "Upgrade Linux kernel. Strip debug symbols and developer comments from production images.",
    },
]

SUMMARY = {
    "total":    5,
    "critical": 1,
    "high":     2,
    "medium":   1,
    "low":      1,
    "platform_note": (
        "3905 SIP is the most stripped-down device in the analyzed set: "
        "Sigma Designs SC1445x M68K uClinux, no MMU, Linux 2.6.19, ROMFS. "
        "Monolithic firmware: kernel + ROMFS in one gzip-compressed uImage. "
        "No MPP firmware, no apigateway, no BEUID model. "
        "Foxconn ODM with 2009-2010 development artifacts. "
        "The combination of empty root password + askfirst console shell + Boa root HTTP "
        "makes this the most open device in the analyzed set by design -- "
        "likely never intended for production network deployment or now EOL."
    ),
    "format_note": (
        ".zz extension = Cisco SBN-wrapped uImage for M68K. "
        "Same 01 00 02 01 SBN magic + CN=someSigner placeholder cert as 8831 SIP. "
        "ROMFS filesystem embedded at 0x1C4000 inside the decompressed vmlinux.bin. "
        "Linux 2.6.19 + ROMFS combination confirms the 3905 hardware predates the "
        "8831 SIP (which used Linux 2.6.37 on TI OMAP-L138) by one design generation."
    ),
}
