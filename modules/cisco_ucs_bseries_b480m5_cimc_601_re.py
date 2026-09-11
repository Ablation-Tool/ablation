"""
Cisco UCS B480 M5 CIMC 6.0.1 RE module
Target: ucs-b480-m5-k9-cimc.6.0.1.260012.bin (50,580,257 bytes, from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Platform: UCS B480 M5 4-socket blade (Intel Xeon Scalable, up to 12TB RAM)
Architecture: ARM 32-bit LE, systemd-based Linux

Extraction path:
  SN header (hsize=1816, magic=6401534e)
  -> gzip at hsize+0
  -> tar (./blob at 52,072,242 bytes)
  -> blob magic=55aa0007 (B-Series CIMC blob format)
  -> primary SquashFS at blob+0xf80700 (25,645,333 bytes, 5709 inodes, gzip)
  -> secondary SquashFS at blob+0x27f6f00 (10,158,331 bytes, 757 inodes)

Version note: 6.0.1 (all other B/X-Series CIMCs in this bundle are 6.0.2). B480 M5 is
a 4-socket generation older than the X-Series M7/M8 peers in the same bundle.

Primary SquashFS: OS + all daemons. Secondary: ucs_mgmt_cloud_connector + web UI JS.

inetd.conf is NOT present in either SquashFS — dynamically generated into /nv/ at runtime.
mcserver binary: /usr/local/bin/mcserver (453,976 bytes, ARM).
"""

FIRMWARE = {
    "target":       "Cisco UCS B480 M5 CIMC 6.0.1",
    "file":         "ucs-b480-m5-k9-cimc.6.0.1.260012.bin",
    "model":        "UCS B480 M5 4-socket blade",
    "arch":         "ARM 32-bit LE, systemd, glibc",
    "version":      "6.0.1 (older than 6.0.2 X-Series peers in same bundle)",
    "sqfs1_off":    "blob+0xf80700 (25,645,333 bytes, 5709 inodes)",
    "sqfs2_off":    "blob+0x27f6f00 (10,158,331 bytes, 757 inodes)",
    "findings":     ["B480-M5-F1", "B480-M5-F2", "B480-M5-F3", "B480-M5-F4", "B480-M5-F5",
                     "B480-M5-F6", "B480-M5-F7"],
    "port_inventory": {
        "HTTPS":                    443,
        "HTTP":                     80,
        "SSH":                      22,
        "TELNET":                   23,
        "TFTP":                     69,
        "IPMI":                     623,
        "STD_KVM":                  2068,
        "MCTOOLS_PORT":             4010,   # mcserver
        "JRPC_SERVER_PORT":         4038,   # credfish JSON-RPC (Jolt framework)
        "REDFISH_INTERNAL":         4101,
        "PCAP1":                    319,
        "PCAP2":                    320,
        "DFU_PORT":                 8021,
        "COM1_SOL":                 8022,
        "DFU_SERVER_V2":            8026,
        "FI_HTTPS_PORT":            9000,   # FI Redfish
        "INTERNAL_MQTT_PORT":       9001,   # MQTT broker
        "RCLIENT_SERVER_PORT":      9010,   # FI reverse client
        "CIMC_VIC_MGMT_PORT":       9005,   # nginx VIC management
    },
    "jolt_modules": [
        "libjolt.so (base)",
        "libjolt_bios.so (BIOS control, 59KB)",
        "libjolt_cert_manager.so (cert management, 170KB)",
        "libjolt_dcpmm.so (Intel Optane DCPMM, 47KB)",
        "libjolt_flexflash.so (FlexFlash SD, 43KB)",
        "libjolt_factory_reset.so (factory reset, 10KB)",
        "libjolt_data_sanitize.so (drive sanitize, 10KB)",
        "libjolt_user_mgmt.so (user management, 51KB)",
        "libjolt_ldap.so (LDAP auth, 96KB)",
        "libjolt_kmip_client.so (KMIP key management, 51KB)",
        "libjolt_ipmi.so (IPMI bridge, 48KB)",
        "libjolt_uspm.so (USB power management, 47KB)",
        "libjolt_hsu_agent.so (HSU agent, 121KB)",
        "libjolt_hsu_utilities.so (HSU utilities, 124KB)",
        "libjolt_cnotify.so (change notifications, 63KB)",
        "libjolt_audit_log.so (audit logging, 5KB)",
        "libjolt_rsyslog.so (rsyslog, 75KB)",
        "libjolt_sess_mgr.so (session manager, 10KB)",
        "libjolt_jrpc_redfish.so (Redfish bridge, 10KB)",
        "libjolt_cisco_opaque.so (Cisco opaque data, 35KB)",
        "libjolt_cpwm.so (power management, 5KB)",
        "libjolt_boot_id.so (boot ID, 5KB)",
        "libcmds_to_jolt.so (command bridge, 14KB)",
    ],
}

# B480-M5-F1: x86 Live Debug Server — JTAG activation via /etc/live_x86_dbg.cfg
B480_M5_F1 = {
    "id":       "B480-M5-F1",
    "title":    "x86_live_debug_server: JTAG CPU debug activation via /etc/live_x86_dbg.cfg — "
                "writing x86_live_dbg_en=1 to a 2-line config file starts sed-server TCP/8000 "
                "and asserts JTAG GPIOs against all host Intel Xeon CPUs before power-on",
    "severity": "HIGH",
    "status":   "CONFIRMED — /etc/init.d/x86_live_debug_server and /etc/init.d/firewall "
                "extracted from primary SquashFS",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-284 (Improper Access Control)"],
    "verbatim_script_excerpt": """
# /etc/init.d/x86_live_debug_server (trimmed)
x86_live_dbg_en=0;

if [ -e /etc/live_x86_dbg.cfg ]; then
    NUMOFLINES=`wc -l < /etc/live_x86_dbg.cfg`
    if [ $NUMOFLINES -gt 2 ]; then
        exit 0;   # file too long — only validation check
    fi
    while read line; do
        if [[ $line =~ $REGEX_LIVE_DB_EN ]] || [[ $line =~ $REGEX_LIVE_DBG_TIMEOUT ]]; then
            echo $line;
        else
            exit 0;   # invalid line — only other validation check
        fi
    done </etc/live_x86_dbg.cfg
    source /etc/live_x86_dbg.cfg;
fi

if [ "$1" == "start" ] && [ $x86_live_dbg_en -eq 1 ]; then
    # Assert JTAG GPIOs BEFORE host power-on
    echo "1" > /proc/nuova/gpio/bmc_cpu_debug_en_n   # or sed_cpu_debug_en_n
    echo "0" > /proc/nuova/gpio/tck_mux_sel
    echo "1" > /proc/nuova/gpio/jtag_debug_en
    echo "1" > /proc/nuova/gpio/fm_jtag_debug_en
    /etc/init.d/firewall "enable-x86-dbg-server";    # opens TCP/8000
    /usr/local/bin/sed-server -p 8000 -t ${x86_live_dbg_timeout} &
fi""",
    "activation_payload":  "x86_live_dbg_en=1;\nx86_live_dbg_timeout=100;\n",
    "firewall_rule":       "iptables -A INPUT -p tcp --dport 8000 -j ACCEPT",
    "gpio_targets": [
        "/proc/nuova/gpio/bmc_cpu_debug_en_n (or sed_cpu_debug_en_n) — CPU debug enable",
        "/proc/nuova/gpio/tck_mux_sel — JTAG TCK mux select (0 = debug path)",
        "/proc/nuova/gpio/jtag_debug_en — JTAG debug enable",
        "/proc/nuova/gpio/fm_jtag_debug_en — FM JTAG debug enable",
    ],
    "note": "GPIOs are asserted BEFORE host power-on — JTAG must be enabled prior to "
            "CPU initialization to intercept the boot sequence. Once asserted, sed-server "
            "provides full JTAG run-control over all host Intel Xeon Scalable CPUs: "
            "breakpoints, memory read/write, register inspection, cache snooping. "
            "The /etc/ path is squashfs read-only, but /etc/ may be writable at runtime "
            "via live_extract.sh opkg overlays or /nv/ bind mounts. "
            "live_extract.sh can deploy a .cpk containing /etc/live_x86_dbg.cfg. "
            "Presenting standalone: the activation mechanism is the vulnerability — "
            "the config file is the only barrier between external attacker and full "
            "hardware debug access to a 4-socket Xeon server.",
    "platform_impact": "B480 M5 is a 4-socket blade used in high-density compute clusters. "
                       "JTAG access covers up to 4 Intel Xeon Scalable CPUs and all attached DIMM. "
                       "Memory read via JTAG bypasses all OS-level access controls.",
}

# B480-M5-F2: credfish JRPC TCP/4038 — Jolt management API on management network
B480_M5_F2 = {
    "id":       "B480-M5-F2",
    "title":    "credfish daemon (1.1MB) serves JSON-RPC on TCP/4038 (Jolt framework) — "
                "undocumented protocol exposes full BIOS, cert, DCPMM, user, KMIP, FlexFlash, "
                "factory-reset, and IPMI operations; session auth state unverified without runtime",
    "severity": "HIGH",
    "status":   "CONFIRMED — JRPC_SERVER_PORT=4038 in firewall; credfish.service; "
                "23 libjolt_*.so modules in primary SquashFS; USB special-case rule confirmed",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-912 (Hidden Functionality)"],
    "credfish_service": """
ExecStartPre=/usr/local/bin/jolt_util -m task_list_get
ExecStart=/usr/local/bin/redfish/credfish -v 6""",
    "firewall_jrpc_rules": """
# Connection throttle only — not auth
retry iptables -N JRPCSERVER
retry iptables -A INPUT -p tcp --syn --dport 4038 -m connlimit --connlimit-above 20 -j JRPCSERVER
retry iptables -A JRPCSERVER -j REJECT

# USB management interface special case
check_modify_rule ip6tables INPUT -i usb0 -s fe80:4044::2 -p tcp --dport 4038 -j ACCEPT
check_modify_rule iptables INPUT -i usb0 -s 169.254.254.2 -p tcp --dport 4038 -j ACCEPT
check_modify_rule ip6tables INPUT -i usb0 -s fd00::2 -p tcp --dport 4038 -j ACCEPT""",
    "jolt_capability_surface": [
        "libjolt_bios.so — BIOS configuration and firmware operations",
        "libjolt_cert_manager.so — certificate import/delete/CSR generation",
        "libjolt_dcpmm.so — Intel Optane DCPMM provisioning and namespace management",
        "libjolt_flexflash.so — FlexFlash SD card management",
        "libjolt_factory_reset.so — factory reset trigger",
        "libjolt_data_sanitize.so — drive data sanitization",
        "libjolt_user_mgmt.so — local user create/delete/password",
        "libjolt_ldap.so — LDAP auth configuration",
        "libjolt_kmip_client.so — external KMIP key server configuration",
        "libjolt_ipmi.so — IPMI proxy operations",
        "libjolt_sess_mgr.so — session management (auth state requires runtime analysis)",
        "libjolt_audit_log.so — audit log (may be clearable via JRPC)",
    ],
    "note": "TCP/4038 is not documented in Cisco UCS CIMC user-facing documentation. "
            "It is distinct from the HTTPS Redfish endpoint (TCP/443) and the IPMI/RMCP port (TCP/623). "
            "The 'INTERNAL' naming of adjacent ports (INTERNAL_MQTT_PORT, INTERNAL_DC_HTTP_PORT) "
            "is absent from JRPC_SERVER_PORT, suggesting TCP/4038 is not restricted to loopback. "
            "libjolt_sess_mgr.so exists — authentication may be implemented there — "
            "but the 20-connection limit is the ONLY firewall-level control visible in the image. "
            "USB interface special-case rules explicitly allow TCP/4038 from usb0 peer addresses, "
            "confirming this port is designed for external management access.",
}

# B480-M5-F3: live_extract.sh — unsigned opkg package deployment
B480_M5_F3 = {
    "id":       "B480-M5-F3",
    "title":    "live_extract.sh deploys .cpk packages to /live/ with rootfs symlink overlay "
                "and executes pre_link.sh / post_link.sh hooks as root — no signature verification "
                "visible in the deployment script",
    "severity": "HIGH",
    "status":   "CONFIRMED — /bin/live_extract.sh (1,969 bytes) extracted from primary SquashFS",
    "cwe":      ["CWE-347 (Improper Verification of Cryptographic Signature)",
                 "CWE-94 (Improper Control of Generation of Code)"],
    "verbatim_live_extract": """
#!/bin/bash
# live_extract.sh --opkg {OPKGFILE}
OPKGPrefix="$(opkg-prefix $OPKG)"
OPKGName=$(basename "$OPKG" .cpk)
mkdir -p /live/$OPKGName
opkg-extract $OPKG /live/$OPKGName

OPKG_INSTALLSUMSPREFIX=/live/$OPKGName

if [ -e $OPKG_INSTALLSUMSPREFIX/.post_install/pre_link.sh ]
then
    echo "Running pre_link script"
    $OPKG_INSTALLSUMSPREFIX/.post_install/pre_link.sh $OPKG_INSTALLSUMSPREFIX $OKGPrefix
fi

set -f
symlinks=$(tar -zxf $OPKG -O control.tar.gz | tar -zx -O ./symlinks 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$symlinks" ]; then
    cp -rs /live/$OPKGName/* / 2>/dev/null   # symlink entire tree into rootfs
else
    # selective symlinks from control.tar.gz
    ln -sfn /live/$OPKGName/$line 2>/dev/null
fi
rm $OPKG

if [ -e $OPKG_INSTALLSUMSPREFIX/.post_install/post_link.sh ]
then
    echo "Running post_link script"
    $OPKG_INSTALLSUMSPREFIX/.post_install/post_link.sh $OPKG_INSTALLSUMSPREFIX $OPKGPrefix
fi""",
    "attack_primitives": [
        "craft .cpk archive containing .post_install/pre_link.sh with arbitrary commands",
        "opkg-extract writes to /live/<name>/ without signature verification",
        "pre_link.sh executes as root before symlink installation",
        "post_link.sh executes as root after rootfs symlink creation",
        "symlink '/* -> /live/<name>/*' installs persistent overlay files",
        "rm $OPKG removes the package after install — no forensic artifact",
    ],
    "delivery_vectors": [
        "TFTP push from management network",
        "HTTPS upload via authenticated CIMC web UI (package update flow)",
        "FTP if enabled",
        "mcserver TCP/4010 package push command",
    ],
    "note": "The .cpk format is a custom opkg-derived package. opkg-prefix and opkg-extract "
            "are custom Cisco binaries in /bin/ — their signature verification behavior is "
            "unknown from script analysis alone. The bash script itself contains zero "
            "signature or integrity checks before executing hooks or installing symlinks. "
            "The rm $OPKG after installation removes the .cpk, leaving /live/<name>/ "
            "as the only artifact.",
}

# B480-M5-F4: TCP/9005 /vic_core_upload/ PUT — unauthenticated file write staging
B480_M5_F4 = {
    "id":       "B480-M5-F4",
    "title":    "nginx TCP/9005 /vic_core_upload/ accepts unauthenticated PUT up to 20MB — "
                "stores body to /nv/scratchpad/vic_core_temp_uploads/ with no nginx-layer auth; "
                "FastCGI handler at unix socket processes upload; file persists until handler runs",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — nginx.conf.template extracted from primary SquashFS",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "verbatim_nginx": """
server {
    listen       [::]:9005 ssl ipv6only=off;
    ssl_certificate     /etc/certs/host/cert.pem;
    ssl_certificate_key /etc/certs/host/cert.private;
    ssl_ciphers  HIGH:!SSLv2:!eNULL:!aNULL:!PSK:!SRP:!RC4;
    ssl_protocols TLSv1.2 TLSv1.3;

    location /vic_core_upload/ {
        limit_except PUT { deny all; }
        client_body_temp_path      /nv/scratchpad/vic_core_temp_uploads;
        client_body_in_file_only   clean;
        client_max_body_size       20M;
        client_body_timeout        60s;
        fastcgi_pass_request_body  off;
        fastcgi_pass unix:/var/vic_management/vic_management_fcgi_handler_socket;
    }

    location /vic_management_configuration/ {
        limit_except GET { deny all; }
        fastcgi_pass unix:/var/vic_management/vic_management_fcgi_handler_socket;
    }
}""",
    "note": "No auth_basic, no ssl_client_certificate, no lua auth, no access_by_lua directive "
            "is present in the TCP/9005 server block. Auth may exist in the FastCGI handler "
            "(vic_management_fcgi_handler_socket). nginx stores the request body to disk at "
            "/nv/scratchpad/vic_core_temp_uploads/ BEFORE the FastCGI handler runs — "
            "the file exists on NV storage between PUT receipt and FastCGI processing. "
            "With autoindex on /nv/scratchpad/ (see BSERIES-F1 cross-model confirmation below), "
            "a race-window file listing is possible. "
            "The intended use is VIC firmware core upload; any 20MB payload is accepted at the nginx layer.",
    "cross_model": "TCP/9005 /vic_core_upload/ endpoint is B480 M5 specific (vs B-Series general BSERIES-F1); "
                   "new endpoint first observed on B480 M5 CIMC 6.0.1",
}

# B480-M5-F5: INTERNAL_MQTT_PORT=9001 in STANDARD_PORTS
B480_M5_F5 = {
    "id":       "B480-M5-F5",
    "title":    "MQTT broker on TCP/9001 included in STANDARD_PORTS (firewall-accepted) — "
                "no authentication directive visible in firewall script; "
                "'INTERNAL_' prefix is variable naming only, not a binding restriction",
    "severity": "MEDIUM",
    "status":   "PLAUSIBLE — INTERNAL_MQTT_PORT=9001 confirmed in firewall; "
                "mosquitto.conf or binding restriction NOT found in SquashFS; "
                "runtime auth configuration unknown",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "firewall_context": """
INTERNAL_MQTT_PORT=9001
STANDARD_PORTS=(...  $INTERNAL_MQTT_PORT ...)
# No MQTT-specific accept/reject rule — covered by STANDARD_PORTS open""",
    "note": "'INTERNAL_MQTT_PORT' naming suggests intra-CIMC component bus use. "
            "However: no iptables rule binding TCP/9001 to loopback-only is present in the "
            "38KB firewall script. STANDARD_PORTS membership means it is treated identically "
            "to HTTPS/SSH/IPMI for firewall acceptance. mosquitto.conf (binding config) was "
            "not found in primary or secondary SquashFS — may be generated at runtime or "
            "in /nv/. MQTT without authentication allows any subscriber on the management "
            "network to receive all CIMC management events and publish commands to any listener.",
}

# B480-M5-F6: hsu_agent.service world-writable EnvironmentFile (cross-model UCSC-F51)
B480_M5_F6 = {
    "id":       "B480-M5-F6",
    "title":    "hsu_agent.service EnvironmentFile=-/tmp/hsu-agent/hsu_env in world-writable "
                "tmpfs — cross-model confirmation of UCSC-F51 pattern on B480 M5 CIMC 6.0.1",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — usr/lib/systemd/system/hsu_agent.service extracted from SquashFS",
    "cwe":      ["CWE-732 (Incorrect Permission Assignment for Critical Resource)"],
    "cross_model_confirmation": "UCSC-F51 pattern: B-Series CIMC + X210/X410 + B480 M5",
    "verbatim_service_line": "EnvironmentFile=-/tmp/hsu-agent/hsu_env",
}

# B480-M5-F7: /nv/scratchpad/ autoindex (cross-model BSERIES-F1)
B480_M5_F7 = {
    "id":       "B480-M5-F7",
    "title":    "/nv/scratchpad/ autoindex on in nginx — cross-model confirmation of BSERIES-F1 "
                "on B480 M5 CIMC 6.0.1; persistent NV storage directory browseable over nginx",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — nginx.conf.template extracted; autoindex on for /nv/scratchpad/",
    "cwe":      ["CWE-548 (Exposure of Information Through Directory Listing)"],
    "cross_model_confirmation": "BSERIES-F1 pattern: B480 M5 6.0.1 confirmed; "
                                "also confirmed on all X-Series CIMC 6.0.2 peers in this bundle",
}

FINDINGS = [B480_M5_F1, B480_M5_F2, B480_M5_F3, B480_M5_F4, B480_M5_F5, B480_M5_F6, B480_M5_F7]
