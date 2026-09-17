"""
FortiAP 231G v7.04 firmware RE
Sources:
  - FAP_231G-v7-build0634-FORTINET.out (34MB, gzip outer)
  - Inner: U-Boot FIT image (FDT, 45MB) -> UBI volume -> SquashFS rootfs
  - Architecture: ARM64 aarch64 / Qualcomm IPQ (Cortex-A53) / musl-1.1.16 / GCC 5.2.0
Product: FortiAP 231G, firmware 7.04-AP-build0634-231228-patch02
"""

# ---------------------------------------------------------
# FortiAP 231G -- product context
# ---------------------------------------------------------
FORTIAP_231G = {
    "id":       "FAP-231G",
    "product":  "FortiAP 231G",
    "firmware": "7.04-AP-build0634-231228-patch02",
    "arch":     "ARM64 aarch64 (Qualcomm IPQ, Cortex-A53)",
    "os":       "OpenWrt-based embedded Linux / musl libc 1.1.16 / GCC 5.2.0",
    "source":   "FAP_231G-v7-build0634-FORTINET.out (gzip -> FIT -> UBI -> SquashFS)",

    "firmware_format": {
        "outer":        "gzip; inner filename: FP231G-7.04-AP-build0634-231228-patch02",
        "inner_fit":    "U-Boot FIT image (FDT magic 0xd00dfeed, 45MB, version 17)",
        "ubi_volumes":  {
            "kernel":       "4.8MB FDT (nested FIT image with kernel + device tree)",
            "ubi_rootfs":   "34.9MB SquashFS 4.x little-endian (main rootfs)",
            "rootfs_data":  "0 bytes (sparse/empty)",
            "wifi_fw":      "3.7MB WiFi firmware",
        },
        "ubi_params":   "erase_block=128KB, vid_hdr_offset=0x800, data_offset=0x1000",
        "extraction":   (
            "gunzip -> ubireader_extract_images -> unsquashfs "
            "(rootfs magic: 6873 7173 = hsqs SquashFS4 LE)"
        ),
    },

    "filesystem_layout": {
        "fap_backend":  "fap_backend.so, fap_backend.conf, ffdhe4096.pem",
        "web":          "www/cgi-bin/luci (Lua), www/luci-static/",
        "auth":         "etc/cwp_auth.py (captive portal, Python 2)",
        "ssh":          "etc/config/dropbear, etc/init.d/dropbear",
        "cli":          "etc/fap/cli_cmds (fapcli allowlist)",
        "monit":        "etc/monitrc (process monitor with web UI)",
        "certs":        "etc/easy-rsa/, etc/ipsec.d/",
    },
}

# ---------------------------------------------------------
# FORTIAP-F01: Empty admin password + SSH root auth enabled
# ---------------------------------------------------------
FORTIAP_F01_EMPTY_ADMIN_PASS = {
    "id":       "FORTIAP-F01",
    "product":  "FortiAP 231G -- default admin credential",
    "severity": "CRITICAL -- unauthenticated SSH access as root on factory/unmanaged AP",
    "class":    "Empty default credential (CWE-1392 / CWE-521)",
    "source":   "etc/shadow, etc/config/dropbear, etc/passwd",

    "description": (
        "etc/shadow contains an empty password hash for the admin account: "
        "  admin::0:0:99999:7::: "
        "The hash field (second colon-delimited field) is empty, "
        "meaning the account requires no password for authentication. "
        "etc/config/dropbear has: "
        "  option PasswordAuth 'on' "
        "  option RootPasswordAuth 'on' "
        "  option Port '22' "
        "The dropbear init script only adds -g (disable root password auth) when "
        "RootPasswordAuth='off'; the default 'on' leaves root password auth active. "
        "etc/passwd shows: "
        "  admin:x:0:0:root:/:/usr/bin/fapcli "
        "admin = UID 0 (root-equivalent). Shell = /usr/bin/fapcli (restricted CLI). "
        "On a factory-reset or unmanaged FortiAP, SSH login as admin with no password "
        "succeeds and drops the attacker into fapcli as UID 0."
    ),

    "attack_path": (
        "1. SSH admin@ with empty password (or press Enter) "
        "2. fapcli restricted shell opens as UID 0 "
        "3. Execute hidden commands (see FORTIAP-F02) "
        "4. devmem /dev/mem -> full physical memory RW"
    ),

    "evidence": {
        "shadow":   "admin::0:0:99999:7:::",
        "passwd":   "admin:x:0:0:root:/:/usr/bin/fapcli",
        "dropbear": "option RootPasswordAuth 'on' / option PasswordAuth 'on'",
    },

    "scope_note": (
        "In managed FortiAP deployments, the controller (FortiGate) sets the admin password "
        "via CAPWAP provisioning. This finding applies to: "
        "  (a) factory-reset APs before controller provisioning "
        "  (b) APs that have lost controller connectivity and retained original firmware "
        "  (c) APs managed by older controllers that may not set a password"
    ),

    "remediation": (
        "Set a non-empty default password in the firmware image. "
        "Lock SSH until CAPWAP controller provisioning completes. "
        "Disable RootPasswordAuth in dropbear config; require key-based auth only."
    ),
}

# ---------------------------------------------------------
# FORTIAP-F02: devmem in fapcli hidden commands
# ---------------------------------------------------------
FORTIAP_F02_DEVMEM_HIDDEN_CMD = {
    "id":       "FORTIAP-F02",
    "product":  "FortiAP 231G -- fapcli hidden command devmem",
    "severity": "HIGH -- physical memory read/write from restricted shell (chains with F01)",
    "class":    "Dangerous capability exposed in restricted shell (CWE-782)",
    "source":   "etc/fap/cli_cmds",

    "description": (
        "The fapcli restricted shell uses /etc/fap/cli_cmds as the command allowlist. "
        "The file has a '# hidden commands' section with: "
        "  /sbin/devmem "
        "  /sbin/kdbg "
        "  /usr/sbin/dropbear "
        "  /sbin/h_diag "
        "devmem on ARM64 Linux reads and writes /dev/mem (physical memory). "
        "As UID 0, /dev/mem is accessible. "
        "Execution of devmem from fapcli allows: "
        "  devmem <phys_addr> -- read physical address "
        "  devmem <phys_addr> <byte|short|word> <value> -- write physical address "
        "This bypasses all OS-level access controls and allows: "
        "  - Extracting kernel memory (cryptographic keys, session tokens, process data) "
        "  - Patching running kernel code "
        "  - Disabling security features in memory "
    ),

    "hidden_commands": [
        "/bin/df",
        "/usr/sbin/dropbear",
        "/usr/sbin/ethtool",
        "/sbin/fap-factory-license",
        "/sbin/fap-ntpc",
        "/sbin/h_diag",
        "/sbin/radartool",
        "/sbin/wifitool",
        "/sbin/ft_rate_config",
        "/usr/bin/ftftp",
        "/bin/kill",
        "/usr/bin/killall",
        "/sbin/lsmod",
        "/bin/ps",
        "/sbin/wlanconfig",
        "/usr/bin/iperf",
        "/sbin/devmem",
        "/sbin/kdbg",
        "/sbin/get_led_status",
        "/usr/sbin/lldpcli",
        "/usr/sbin/cnss_diag",
    ],

    "chain": "FORTIAP-F01 (empty admin SSH) -> FORTIAP-F02 (devmem) -> full memory compromise",

    "remediation": (
        "Remove devmem from the fapcli allowlist. "
        "devmem has no legitimate remote-management use case; "
        "it is a factory/hardware debug tool that should not be accessible over SSH."
    ),
}

# ---------------------------------------------------------
# FORTIAP-F03: Monit hardcoded admin:monit credentials
# ---------------------------------------------------------
FORTIAP_F03_MONIT_HARDCODED_CREDS = {
    "id":       "FORTIAP-F03",
    "product":  "FortiAP 231G -- monit web interface hardcoded credentials",
    "severity": "MEDIUM -- hardcoded credentials for process monitoring web UI",
    "class":    "Hardcoded credential (CWE-798)",
    "source":   "etc/monitrc",

    "description": (
        "etc/monitrc contains: "
        "  allow admin:monit      # require user 'admin' with password 'monit' "
        "Monit is a process monitoring daemon with a built-in web interface. "
        "Default port: 2812. "
        "Credentials admin/monit are hardcoded in the firmware; "
        "there is no per-device credential generation. "
        "Monit web interface allows: starting/stopping services, viewing process state, "
        "executing configured action scripts. "
        "Combined with F01 (empty admin SSH), the AP is accessible via two independent "
        "credential-free or hardcoded-credential vectors."
    ),

    "evidence": "allow admin:monit  # etc/monitrc",

    "remediation": (
        "Generate per-device monit credentials during manufacture or first boot. "
        "Bind monit to localhost only (loopback interface) to prevent network access. "
        "Disable monit in production firmware; it is a development/monitoring tool."
    ),
}

# ---------------------------------------------------------
# FORTIAP-F04: kdbg kernel debug tool with /proc/sys/net write
# ---------------------------------------------------------
FORTIAP_F04_KDBG_PROC_WRITE = {
    "id":       "FORTIAP-F04",
    "product":  "FortiAP 231G -- kdbg kernel parameter modification",
    "severity": "LOW -- kernel network debug parameter write via /proc; chains with F01",
    "class":    "Kernel parameter modification via restricted shell (CWE-264)",
    "source":   "sbin/kdbg (hidden command in cli_cmds)",

    "description": (
        "kdbg is a hidden CLI command that writes to /proc/sys/net/* kernel parameters: "
        "  echo '%s' > /proc/sys/net/'%s'/debug "
        "This modifies kernel network subsystem debug levels at runtime. "
        "From the restricted shell (as UID 0 via F01), kdbg can: "
        "  - Enable verbose logging of network events (traffic visibility) "
        "  - Modify kernel network parameters that affect packet handling "
        "  - Potentially trigger kernel debug paths with unexpected behavior "
    ),

    "remediation": "Remove kdbg from the fapcli hidden allowlist in production firmware.",
}

# ---------------------------------------------------------
# FORTIAP-F05: Build path / toolchain disclosure
# ---------------------------------------------------------
FORTIAP_F05_BUILD_PATH_DISCLOSURE = {
    "id":       "FORTIAP-F05",
    "product":  "FortiAP 231G -- build environment path in fap_backend.so",
    "severity": "INFO -- build path leaked; reveals old toolchain with potential unpatched CVEs",
    "class":    "Information disclosure (CWE-200)",
    "source":   "fap_backend/fap_backend.so (strings)",

    "build_path": "/fapdev-ipq/toolchain-aarch64_cortex-a53_gcc-5.2.0_musl-1.1.16/",
    "build_details": {
        "platform":   "IPQ (Qualcomm Atheros IPQ series WiFi SoC)",
        "cpu":        "Cortex-A53 AArch64",
        "gcc":        "5.2.0 (released 2015; EOL)",
        "musl":       "1.1.16 (released 2016)",
        "build_dir":  "/fapdev-ipq/",
    },

    "description": (
        "fap_backend.so DWARF debug paths reveal the complete build toolchain path. "
        "GCC 5.2.0 (2015) predates many hardening improvements: "
        "  - No control-flow integrity (CFI) "
        "  - Limited stack protector coverage "
        "  - No retpoline Spectre mitigation "
        "musl 1.1.16 (2016) predates musl CVE-2020-28928 and other allocator improvements. "
        "The Qualcomm IPQ platform path confirms this is an IPQ-series SoC (likely IPQ6010/6018 "
        "or similar 802.11ax-capable chip used in the 231G)."
    ),

    "remediation": "Update toolchain. GCC 5.2.0 is 11 years old at time of this firmware build.",
}

# ---------------------------------------------------------
# FORTIAP architecture summary
# ---------------------------------------------------------
FORTIAP_ARCH = {
    "id":       "FAP-231G-ARCH",
    "product":  "FortiAP 231G architecture",

    "components": {
        "capwap_daemon":   "cwWtpd (10KB loader; cwWtpd_apcmd/cldc/spectral/wss are symlinks) -- CAPWAP protocol",
        "backend":         "fap_backend.so (207KB) -- auth, config, web API",
        "web_interface":   "LuCI (OpenWrt web framework, Lua-based, served via cgi-bin/luci)",
        "captive_portal":  "cwp_auth.py (Python 2, urllib2) -- client captive portal auth",
        "ssh":             "dropbear on port 22",
        "process_monitor": "monit (default port 2812, admin:monit)",
        "cli_shell":       "fapcli (restricted shell; /etc/fap/cli_cmds allowlist)",
    },

    "web_auth_functions": [
        "webDoAuth", "webNotifyLoginSuccess", "webNotifyLoginFailure",
        "tickAdminTimer", "restLogin", "is_password_value", "secret_checksum",
    ],

    "certificate_paths": {
        "wan1x":    "/fap_data/cfg/cert/wan1x/",
        "local_cer": "/fap_data/cfg/cert/local/Fortinet_Uploaded.cer",
        "local_key": "/fap_data/cfg/cert/local/Fortinet_Uploaded.key",
    },

    "pending_re": [
        "fap_backend.so BERT semantic sweep (ARM64 capstone, 207KB)",
        "cwWtpd CAPWAP daemon (10KB, not stripped) -- protocol auth handling",
        "cwp_auth.py captive portal injection surface",
        "LuCI Lua controller auth bypass",
    ],
}

unique_findings = [
    "FORTIAP-F01",  # CRITICAL: empty admin password + SSH enabled
    "FORTIAP-F02",  # HIGH: devmem in hidden CLI commands
    "FORTIAP-F03",  # MEDIUM: monit admin:monit hardcoded
    "FORTIAP-F04",  # LOW: kdbg /proc/sys/net write
    "FORTIAP-F05",  # INFO: GCC 5.2.0 / musl 1.1.16 EOL toolchain
]
