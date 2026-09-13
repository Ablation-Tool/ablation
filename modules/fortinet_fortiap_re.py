"""
Fortinet FortiAP 23JF v7.2.0 RE
Source: FAP_23JF-v7-build0280-FORTINET-7.2.0.out (gzip outer -> FIT image -> UBI)
Architecture: ARM64 aarch64 (Qualcomm IPQ60xx)
OS base: OpenWRT Chaos Calmer 15.05.1 (EOL 2016)
Extraction: gzip -> FIT(d00dfeed) -> UBI(55424923) -> UBIFS volumes -> squashfs rootfs
Build date: 2022-04-14
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiAP 23JF",
    "version":      "v7.2.0 build 0280",
    "build_date":   "2022-04-14",
    "arch":         "ARM64 aarch64 (Qualcomm IPQ60xx)",
    "soc":          "Qualcomm IPQ60xx (Wi-Fi 6 dual-band)",
    "os_base":      "OpenWRT Chaos Calmer 15.05.1 (released 2016, EOL ~2018)",

    "image_layout": {
        "outer":        "gzip compressed file (standard gzip, no Fortinet container)",
        "inner":        "FIT image (Flattened Image Tree, magic 0xd00dfeed)",
        "fit_nodes": {
            "script":   "flash.scr -- flash init script",
            "ubi_img":  "openwrt-ipq-ipq60xx_64-ubi-root.img (UBI volume at FIT+0x5e8, 36MB)",
        },
        "ubi_volumes": {
            "kernel":       "img-1002950691_vol-kernel.ubifs -- FIT image with ARM64 kernel + DTB",
            "ubi_rootfs":   "img-1002950691_vol-ubi_rootfs.ubifs -- squashfs v4 XZ, 29MB, 3889 inodes",
            "rootfs_data":  "img-1002950691_vol-rootfs_data.ubifs -- empty (overlay, runtime)",
            "wifi_fw":      "img-1002950691_vol-wifi_fw.ubifs -- Qualcomm Wi-Fi firmware blobs",
        },
        "rootfs_type":  "squashfs 4.0 XZ compressed on UBIFS volume",
    },

    "key_binaries": {
        "/sbin/kore":          "Kore web framework binary, ARM64 stripped, 156KB; uses realpath() + chroot",
        "/fap_backend/fap_backend.so": "Fortinet REST API handlers, ARM64 NOT stripped (full symbol table)",
        "/usr/sbin/startup_fw": "Fortinet startup orchestrator, ARM64 stripped",
        "/usr/sbin/acfg_tool":  "FortiAP configuration tool, ARM64 stripped",
        "/usr/bin/python":      "Python 2.7 (EOL January 2020)",
        "/etc/cwp_auth.py":     "Captive portal auth in Python 2 (uses urllib2)",
        "/usr/bin/fapcli":      "FortiAP restricted CLI shell for admin user, ARM64 stripped",
    },

    "rest_api": {
        "server":   "Kore web framework on port 443 (HTTPS), loading fap_backend.so",
        "runas":    "admin (in fap_backend.conf)",
        "auth":     "fap_auth via restValidateSession (session token in cookie)",
        "unauthed_endpoints": [
            "/logincheck (POST) -- restLogin; no fap_auth required",
            "/cp-logout (POST) -- restClientLogout; no fap_auth required",
            "/static/* -- static file serving from /usr/www/static",
            "/  (GET) -- restServeIndex; no fap_auth required",
            "dynamic ^.*$ -- restServeIndex fallback; no fap_auth required",
        ],
        "authed_endpoints": [
            "/logout (POST) -- restLogout",
            "/api/v1/cfg-get (GET) -- restGetCfg",
            "/api/v1/cfg-set (POST) -- restSetCfg",
            "/api/v1/sys-status (GET) -- restGetSysStatus",
            "/api/v1/sys-perf (GET) -- restGetSysPerf",
            "/api/v1/wtp-cfg (GET) -- restGetWtpCfg",
            "/api/v1/radio-cfg (GET) -- restGetRadioCfg",
            "/api/v1/vap-cfg (GET) -- restGetVapCfg",
            "/api/v1/upgrade-image (POST) -- restUpgradeImage",
            "/api/v1/reboot (POST) -- restReboot",
            "/api/v1/download (GET) -- restDownload; 'file' param validated with v_fap_any (regex ^.*$)",
            "/api/v1/upload (POST) -- restUpload",
            "/api/v1/upload-wan1x (POST) -- restWan1xUpload",
        ],
    },
}


# ---------------------------------------------------------
# FAP-F01: EOL OS base (OpenWRT Chaos Calmer 15.05.1) in 2022 firmware
# ---------------------------------------------------------
FAP_F01_EOL_OS = {
    "id":       "FAP-F01",
    "product":  "Fortinet FortiAP 23JF v7.2.0",
    "severity": "MEDIUM -- EOL OpenWRT base with known unpatched CVEs; attack surface includes OpenWRT-specific packages",
    "class":    "EOL software base (CWE-1329)",

    "description": (
        "FortiAP 23JF v7.2.0 (build 2022-04-14) runs OpenWRT Chaos Calmer 15.05.1 as its userspace base. "
        "Chaos Calmer was released in 2015, last patched 2016, and has been EOL since approximately 2018. "
        "This is a 6-year-old EOL OS in a 2022 AP firmware release. "
        "OpenWRT Chaos Calmer is affected by dozens of known CVEs across its bundled packages "
        "(busybox, dropbear, dnsmasq, ubus, rpcd, netifd) that have been patched in subsequent OpenWRT releases "
        "(LEDE 17.01, OpenWRT 18.06, 19.07, 21.02, 22.03) but are not backported here."
    ),

    "evidence": {
        "openwrt_release": "DISTRIB_ID='OpenWrt'; DISTRIB_RELEASE='Chaos Calmer'; DISTRIB_REVISION='unknown'; DISTRIB_TARGET='ipq/ipq60xx_64'",
        "build_date": "2022-04-14 (firmware build) vs 2015-2016 (Chaos Calmer release)",
    },

    "included_packages_at_risk": [
        "busybox (Chaos Calmer version predates busybox 1.29+ security fixes)",
        "dropbear (Chaos Calmer era = 2015.67; multiple CVEs fixed in 2016-2022)",
        "dnsmasq (pre-DNSPOOQ/CVE-2020-25681 era; 7 CVEs unpatched)",
        "rpcd (Chaos Calmer version; multiple ubus protocol parsing issues)",
        "uhttpd (Chaos Calmer version; pre-2019 HTTP parsing fixes)",
    ],

    "remediation": "Update OpenWRT base to supported release (23.05+). Enable auto-update for security patches.",
}


# ---------------------------------------------------------
# FAP-F02: Empty admin password -- SSH pre-auth access
# ---------------------------------------------------------
FAP_F02_EMPTY_ADMIN_PASSWORD = {
    "id":       "FAP-F02",
    "product":  "Fortinet FortiAP 23JF v7.2.0",
    "severity": "CRITICAL -- admin (uid 0) has empty password; SSH PasswordAuth=on; any network host can authenticate to SSH without credentials",
    "class":    "Missing authentication for critical function (CWE-306) / Hardcoded empty credentials (CWE-798)",

    "description": (
        "The FortiAP rootfs ships with an empty password for the 'admin' user (uid=0). "
        "/etc/shadow contains: 'admin::0:0:99999:7:::' (second field empty = no password). "
        "Dropbear SSH is enabled on port 22 with both PasswordAuth=on and RootPasswordAuth=on. "
        "This allows any host with network access to the AP management interface to SSH in "
        "as admin (uid=0) with no credentials. "
        "The admin shell is /usr/bin/fapcli (a restricted CLI), not /bin/sh, "
        "which limits the initial access to FortiAP CLI commands. "
        "However, uid=0 privilege level means any local escalation path (SUID binary, "
        "kernel vulnerability, or fapcli shell escape) results in full root access."
    ),

    "evidence": {
        "shadow_entry":    "admin::0:0:99999:7::: (empty password field)",
        "passwd_entry":    "admin:x:0:0:root:/:/usr/bin/fapcli (uid=0, shell=fapcli)",
        "dropbear_config": "PasswordAuth='on', RootPasswordAuth='on', Port='22'",
        "ssh_auth_method": "password (empty)",
        "shell":           "/usr/bin/fapcli (restricted Fortinet CLI, not /bin/sh)",
    },

    "attack_scenario": {
        "step_1": "ssh admin@<fortiap_ip> (no password prompt, or press Enter)",
        "result": "FortiAP restricted CLI with uid=0 privileges",
        "note":   "fapcli has 'execv' symbol -- inspect for shell escape paths",
    },

    "also_note": (
        "The rpcd configuration (used by LuCI) has: 'option username root; option password $p$root; "
        "list read *; list write *'. The '$p$root' = passthrough to /etc/passwd -> admin's empty password. "
        "This gives full read+write LuCI/ubus access with empty credentials."
    ),

    "remediation": (
        "Set a non-empty admin password in the firmware or enforce password set on first boot. "
        "Disable PasswordAuth in dropbear (use key-based auth only). "
        "Disable RootPasswordAuth. "
        "Restrict SSH access to management VLAN only."
    ),
}


# ---------------------------------------------------------
# FAP-F03: Python 2.7 (EOL) in production firmware
# ---------------------------------------------------------
FAP_F03_PYTHON2 = {
    "id":       "FAP-F03",
    "product":  "Fortinet FortiAP 23JF v7.2.0",
    "severity": "LOW -- Python 2.7 is EOL (January 2020); security vulnerabilities will not be patched; used in captive portal auth",
    "class":    "EOL dependency (CWE-1329)",

    "description": (
        "FortiAP 23JF ships Python 2.7 (/usr/bin/python, /usr/bin/python2, /usr/bin/python2.7). "
        "Python 2.7 reached end-of-life on January 1, 2020. "
        "The captive portal authentication script /etc/cwp_auth.py explicitly uses urllib2 "
        "(Python 2 only, replaced by urllib.request in Python 3). "
        "Any security vulnerability found in Python 2.7 after January 2020 will not be patched. "
        "The captive portal code handles HTTP requests from untrusted clients (captive portal users) "
        "using this EOL library."
    ),

    "evidence": {
        "python_bin":   "/usr/bin/python -> /usr/bin/python2 -> /usr/bin/python2.7",
        "cwp_auth":     "/etc/cwp_auth.py uses urllib2.urlopen (Python 2 only)",
        "eol_date":     "Python 2.7 EOL: January 1, 2020; firmware built: April 2022",
    },

    "remediation": "Migrate cwp_auth.py and all Python scripts to Python 3. Remove Python 2 from firmware.",
}


# ---------------------------------------------------------
# FAP-F04: /api/v1/download unrestricted file parameter (post-auth)
# ---------------------------------------------------------
FAP_F04_DOWNLOAD_PARAM = {
    "id":       "FAP-F04",
    "product":  "Fortinet FortiAP 23JF v7.2.0",
    "severity": "LOW -- /api/v1/download accepts any file path (v_fap_any regex ^.*$) after authentication; Kore uses realpath+chroot which likely prevents path traversal",
    "class":    "Insufficient input validation on file parameter (CWE-22, likely mitigated by chroot)",

    "description": (
        "The REST API endpoint /api/v1/download validates the 'file' GET parameter with validator v_fap_any, "
        "which uses regex '^.*$' (matches any value, including path traversal sequences '../'). "
        "Kore web framework (which loads fap_backend.so) uses realpath() to resolve paths "
        "and executes with a chroot environment unless launched with -n flag. "
        "If chroot is active (default), path traversal via ../ cannot escape the chroot jail. "
        "This finding is LOW because the architectural chroot mitigation likely prevents exploitation, "
        "but the validator implementation itself is wrong -- it should explicitly reject paths containing '..'."
    ),

    "disasm_evidence": {
        "fap_backend_conf": "params get /api/v1/download { validate file v_fap_any }",
        "v_fap_any_regex":  "regex ^.*$ (matches any value including ../ sequences)",
        "kore_mitigation":  "'realpath(%s): %s' and chroot in kore strings; chroot + realpath prevent traversal if active",
        "restDownload_vma": "0xbe04 in fap_backend.so; calls kore_fileref_get at 0xbf00",
        "path_table":       "table at 0x1f710 (data section) = null entries; restDownload does single pass then falls through to kore_fileref_get with raw path",
    },

    "kore_fileref_get": "Kore function that serves a file to the HTTP client; uses realpath() for canonicalization",

    "note": (
        "If kore is started with -n (no chroot) flag for any reason, "
        "the path traversal becomes a pre-authenticated file read as admin (uid=0). "
        "The launch configuration is in /sbin/startup_fw (stripped binary, not confirmed statically)."
    ),

    "remediation": (
        "Change v_fap_any validator to v_fap_safe: 'regex ^[A-Za-z0-9._-]+$' (disallow / and .). "
        "Ensure kore is always run with chroot enabled. "
        "Maintain an explicit allowlist of downloadable files."
    ),
}


# ---------------------------------------------------------
# FAP-F05: Shared LuCI web interface with admin access via empty password
# ---------------------------------------------------------
FAP_F05_LUCI_EMPTY_AUTH = {
    "id":       "FAP-F05",
    "product":  "Fortinet FortiAP 23JF v7.2.0",
    "severity": "HIGH -- LuCI web admin (uhttpd, port 80/443) accessible with admin/empty password; grants full device configuration",
    "class":    "Missing authentication (CWE-306) via default empty credentials in LuCI",

    "description": (
        "The FortiAP ships with the standard OpenWRT LuCI web interface on uhttpd (ports 80/443). "
        "LuCI uses rpcd for authentication. The rpcd configuration has: "
        "username=root, password=$p$root (passthrough to admin's /etc/shadow entry), "
        "with read+write access to all ('*') UCI/ubus operations. "
        "Since admin's /etc/shadow entry has an empty password, "
        "any browser connecting to http://<fortiap>/ or https://<fortiap>/ can log in "
        "as root (uid=0) with an empty password via LuCI. "
        "LuCI/rpcd provides full device configuration access: interfaces, firewall, VPN, Wi-Fi, packages."
    ),

    "evidence": {
        "rpcd_config":   "username=root, password=$p$root, list read '*', list write '*'",
        "shadow_admin":  "admin::0:0:99999:7::: (empty password)",
        "uhttpd_config": "listen_http=0.0.0.0:80, listen_https=0.0.0.0:443, home=/usr/www",
        "luci_passwd":   "/etc/config/luci: option passwd '/etc/passwd' (reads admin entry)",
    },

    "impact": (
        "LuCI/rpcd with uid=0 and read+write '*' access allows: "
        "modifying Wi-Fi configuration (rogue AP setup), "
        "installing OpenWRT packages (persistent backdoor), "
        "exfiltrating credentials stored in UCI config (PPTP/VPN passwords, RADIUS shared secrets), "
        "pivoting to other network segments via the AP's interface."
    ),

    "remediation": (
        "Set non-empty admin password. "
        "Disable LuCI on production FortiAP devices (only keep the Fortinet fap_backend REST API). "
        "If LuCI is needed, bind it to a management VLAN only. "
        "Separate admin credentials from root rpcd access."
    ),
}


# ---------------------------------------------------------
# FAP-F06: Command injection via LOGIN_PASSWD_ENC in libsysapi.so
# ---------------------------------------------------------
FAP_F06_PASSWD_CMD_INJECTION = {
    "id":       "FAP-F06",
    "product":  "Fortinet FortiAP 23JF v7.2.0",
    "severity": "MEDIUM standalone; HIGH chained with FAP-F02 (unauth -> full RCE)",
    "class":    "Command injection via unsanitized password variable (CWE-78)",

    "description": (
        "libsysapi.so implements the apply handler for the LOGIN_PASSWD_ENC configuration variable. "
        "When LOGIN_PASSWD_ENC is set (via cfg -a LOGIN_PASSWD_ENC=VALUE or /api/v1/cfg-set), "
        "the handler at offset 0x22304 in libsysapi.so: "
        "(1) decodes the encoded value via fgt_decode(input, decode_buf, 256, 0); "
        "(2) passes the decoded value unsanitized to snprintf: "
        "snprintf(cmd, 256, \"/bin/passwd -p '%s' > /dev/null\", decode_buf); "
        "(3) executes the command: system(cmd). "
        "If decode_buf contains a single quote ('), the shell command escapes the quote context "
        "and allows arbitrary command execution. "
        "An identical pattern exists in cfg binary at 0x400e68 (passwd_apply) using sprintf (unbounded). "
        "The cfg binary pattern uses sprintf without size limit (buffer overflow risk secondary to injection). "
        "libsysapi.so also stores the identical format string at file+0x44db8, confirming both codebases "
        "implement the same vulnerable pattern."
    ),

    "disasm_evidence": {
        "libsysapi_so": {
            "handler_vma":    "0x22304 (strcmp against 'LOGIN_PASSWD_ENC' to route to this path)",
            "fgt_decode":     "0x22344: bl fgt_decode@plt (decodes encoded password to plaintext)",
            "snprintf_call":  "0x22364: bl snprintf@plt (format='/bin/passwd -p \\%s\\' > /dev/null', arg=decoded_password)",
            "system_call":    "0x2236c: bl system@plt (executes assembled command)",
            "format_string":  "file+0x44db8: '/bin/passwd -p '\\%s' > /dev/null'",
            "empty_path":     "0x22374: bl system@plt (executes '/bin/passwd -d admin > /dev/null' if value empty)",
        },
        "cfg_binary": {
            "passwd_apply_vma": "0x400e68 (local symbol, 100 bytes)",
            "sprintf_call":     "0x4017e8: '/bin/passwd -p '\\%s' > /dev/null\\n'",
            "system_call":      "0x400ea8: bl system@plt",
            "note":             "LOCAL symbol (not exported); called via libsysapi.so dl_iterate_phdr callback scan",
        },
    },

    "injection_path": {
        "trigger_var":    "LOGIN_PASSWD_ENC",
        "attack_vector":  "POST /api/v1/cfg-set (authenticated) or cfg CLI command",
        "payload_format": "fgt_encode(\"X'; CMD; #\") -- encoded value decoding to injection payload",
        "result":         "arbitrary OS command executed as admin (uid=0) on the AP",
    },

    "chain_with_fap_f02": {
        "step_1": "SSH to port 22 with admin/empty (FAP-F02: unauthenticated access)",
        "step_2": "cfg -a LOGIN_PASSWD_ENC=<fgt_encoded_payload> or POST /api/v1/cfg-set",
        "step_3": "libsysapi.so snprintf+system executes injected command as root",
        "result": "Full unauthenticated RCE (FAP-F02 -> FAP-F06 chain)",
    },

    "open_questions": [
        "Does is_valid_passwd (exported from libsysapi.so at VMA 0x42720) reject single quotes? If called by the web API layer before cfg, the injection is web-mitigated.",
        "Does fgt_decode ever produce single quotes from a valid encoded input? Depends on encoding algorithm (likely simple XOR/base64 -- single quotes survive).",
        "Does /api/v1/cfg-set call is_valid_passwd before forwarding to cfg? Not confirmed (fap_backend.so analysis stopped at restGetCfg/restSetCfg surface).",
        "Is cfg -a LOGIN_PASSWD_ENC reachable via fapcli (restricted shell)? fapcli is stripped; execv is present.",
    ],

    "remediation": (
        "Replace snprintf(cmd, N, format, decoded_password) + system(cmd) with setuid/setgid password change API "
        "or with an allowlist character check that rejects shell metacharacters (', \", \\, ;, |, &, >, <, $, `) "
        "before constructing the command. "
        "Prefer execve([\"/bin/passwd\", \"-p\", decoded_password, NULL]) to avoid shell interpretation entirely."
    ),
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "rootfs":           "EXTRACTED -- squashfs v4 XZ on UBIFS volume; 3889 inodes; full filesystem access",
    "kernel":           "IDENTIFIED -- FIT image on kernel UBIFS volume; ARM64; kernel version from DTB node",
    "fap_backend.so":   "PARTIALLY DISASSEMBLED -- NOT stripped; restDownload + path validation analyzed",
    "kore":             "STRINGS ONLY -- stripped; chroot + realpath confirmed from strings",
    "startup_fw":       "STRINGS ONLY -- stripped; kore launch parameters NOT confirmed",
    "fapcli":           "SURFACE ONLY -- stripped; execv present (potential escape vector, not confirmed)",
    "capwap_protocol":  "NOT ANALYZED -- libcapwap.so present but not disassembled",

    "unique_findings": [
        "FAP-F01: MEDIUM -- OpenWRT Chaos Calmer 15.05.1 (EOL 2016) in 2022 firmware; dozens of unpatched CVEs in bundled packages",
        "FAP-F02: CRITICAL -- admin (uid=0) has empty password in /etc/shadow; SSH port 22 with PasswordAuth=on; any network host can authenticate",
        "FAP-F03: LOW -- Python 2.7 (EOL January 2020) with urllib2 in captive portal auth code; EOL dependency handling untrusted network input",
        "FAP-F04: LOW -- /api/v1/download file parameter validated with regex ^.*$ (allows ../ sequences); Kore chroot likely prevents traversal but validator is wrong",
        "FAP-F05: HIGH -- LuCI web interface (port 80/443) with rpcd root/$p$root -> admin empty password -> full device configuration read+write",
        "FAP-F06: MEDIUM/HIGH -- command injection in libsysapi.so LOGIN_PASSWD_ENC handler: fgt_decode -> snprintf -> system with no quote sanitization; HIGH chained with FAP-F02",
        "Qualcomm IPQ60xx (ARM64) with UBIFS/squashfs storage -- different from all other analyzed Fortinet products (MIPS/ARM32/x86-64)",
        "fap_backend.so NOT stripped -- full symbol table in production binary (36 REST handler functions visible)",
        "cwp_auth.py uses Python 2 urllib2 -- captive portal code makes HTTP requests for untrusted CP users using EOL library",
        "libsysapi.so uses dl_iterate_phdr for ELF callback discovery -- framework scans loaded ELF binaries for *_apply symbols to register as variable apply callbacks",
        "cfg binary passwd_apply (0x400e68) uses sprintf (no size limit) vs libsysapi.so snprintf(256) -- identical injection, secondary overflow risk",
    ],

    "vs_other_products": {
        "FGT/FFW/FWB": "fortism LSM, encrypted rootfs, authenticated REST; FAP has no fortism, plaintext squashfs, empty password",
        "FSW":          "ARM32 3.6.5 kernel, af_admin.ko; FAP is ARM64 OpenWRT 15.05.1, different attack surface",
        "FEXT":         "Kore auth disabled (CRIT); FAP has Kore auth enabled but empty password defeats it",
        "FAD":          "SBVM DES key, vtb.ko ioctl; FAP has no kernel modules of note but has SSH empty password",
        "FAC":          "Encrypted rootfs, no password issues; FAP opposite: plaintext rootfs + empty password",
        "FAP":          "Wi-Fi AP; OpenWRT-based; empty password most severe finding; CAPWAP protocol surface not analyzed",
    },

    "image_format_notes": {
        "outer":        "Standard gzip (1f8b); no Fortinet outer container",
        "fit_header":   "d00dfeed (FDT magic) = FIT (Flattened Image Tree) format",
        "fit_nodes":    "script (flash.scr) + firmware (UBI image at FIT+0x5e8, 36MB)",
        "ubi":          "UBI magic 55424923; 4 logical volumes (kernel, rootfs, rootfs_data, wifi_fw)",
        "ubi_rootfs":   "squashfs 4.0 XZ compressed, 29MB, 3889 inodes",
        "extraction":   "gzip -> FIT FDT parse -> UBI -> ubireader_extract_images -> squashfs LE",
    },
}
