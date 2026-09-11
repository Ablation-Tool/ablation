"""
Cisco UCS X410C M7 CIMC 6.0.2 RE module
Target: ucs-x410-m7-cimc.6.0.2.260040.bin (from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Platform: UCS X410C M7 (4-socket Intel Xeon Scalable 4th Gen, X-Series Compute Node)
Architecture: ARM 32-bit LE, systemd-based Linux

Extraction path:
  Outer bundle gzip at offset 0x354 → 1163MB decompressed stream
  SN entry "ucs-x410-m7-cimc.6.0.2.260040.bin" at decomp+896769536
  GZIP at SN+784 → 65MB TAR → ./blob (68549149 bytes)
  Blob magic: 55aa0011 (X-Series CIMC family, differs from B-Series 55aa0007)
  Primary SquashFS at blob+29495552 (6179 inodes, 27MB, ARM32 LE gzip)
  Secondary SquashFS at blob+58321152 (760 inodes, 9MB — cloud connector/web UI)

Primary SquashFS layout (differs from B480 M5):
  bin/, configs/, debug/, etc/, lib/, nuova/, nv/, sbin/, usr/, var/
  'configs/' and 'debug/' and 'nuova/' are X-Series additions over B-Series

Build date: Feb 14 2026 (from SquashFS mtime fields)
Version: 6.0.2.260040 (newer than B480 M5's 6.0.1.260012)
Firmware version string in imghdr.bin: 784 bytes at ./isan/etc/imghdr.bin

Cross-model context:
  B480 M5 (6.0.1): blob magic 55aa0007, 5709 inodes, ARM32, no debug/ dir
  X410C M7 (6.0.2): blob magic 55aa0011, 6179 inodes, ARM32, adds debug/ configs/ nuova/
  Port inventory and core daemons (credfish, mcserver, firewall ports) are identical.
  B480 M5-F2/F4/F6/F7 confirmed cross-model on X410C M7 6.0.2.
"""

FIRMWARE = {
    "target":    "Cisco UCS X410C M7 CIMC 6.0.2",
    "file":      "ucs-x410-m7-cimc.6.0.2.260040.bin",
    "model":     "UCS X410C M7 (4-socket Intel Xeon Scalable 4th Gen, X-Series Compute Node)",
    "arch":      "ARM 32-bit LE, systemd-based Linux",
    "blob_magic": "55aa0011 (X-Series family; B-Series uses 55aa0007)",
    "sqfs_primary_off": "blob+29495552",
    "sqfs_secondary_off": "blob+58321152",
    "sqfs_primary_inodes": 6179,
    "sqfs_secondary_inodes": 760,
    "findings":  ["X410M7-F1", "X410M7-F2", "X410M7-F3", "X410M7-F4", "X410M7-F5"],
    "cross_model_confirmations": [
        "B480-M5-F2: credfish TCP/4038 Jolt JRPC — confirmed on X410C M7 6.0.2",
        "B480-M5-F4: /vic_core_upload/ TCP/9005 PUT no-nginx-auth — confirmed",
        "B480-M5-F6: hsu_agent EnvironmentFile=-/tmp/hsu-agent/hsu_env — confirmed",
        "B480-M5-F7: /nv/scratchpad/ autoindex on — confirmed (BSERIES-F1 class)",
        "B480-M5-F3: live_extract.sh unsigned .cpk hooks — confirmed (extended version)",
    ],
    "port_inventory": {
        "MCTOOLS_PORT":                 4010,
        "JRPC_SERVER_PORT":             4038,
        "DFU_PORT":                     8021,
        "COM1_SOL_PORT":                8022,
        "PTPD_PORT":                    8192,
        "RCLIENT_SERVER_PORT":          9010,
        "COM2_SOL_PORT":                23000,
        "MCTP_BROKER_PORT":             23001,
        "REDFISH_EVENTS_MC_PORT":       23002,
        "HTTP":                         80,
        "HTTPS":                        443,
        "INTERNAL_DC_HTTP_PORT":        444,
        "INTERNAL_READONLY_HTTP_PORT":  445,
        "FI_HTTPS_PORT":                9000,
        "INTERNAL_MQTT_PORT":           9001,
        "CIMC_VIC_MGMT_PORT":           9005,
        "REDFISH_INTERNAL_SERVICE_PORT": 4101,
        "DFU_SERVER_PORT_V2":           8026,
    },
    "note": "X410C M7 adds 3 directories absent from B480 M5: debug/ (memtester + MrT ARM32 "
            "binaries), configs/ (BIOS post code decoder symlink chain), nuova/ (cloud connector "
            "installer scripts using eval). credfish binary is at /usr/local/bin/redfish/credfish "
            "(identical service definition to B480 M5). 91 systemd services vs B480 M5's fewer.",
}

# X410M7-F1: /cisco/blob/ Cisco Opaque Handler — no HTTP method restriction at nginx layer
X410M7_F1 = {
    "id":       "X410M7-F1",
    "title":    "nginx TCP/443 /cisco/blob/ location: no limit_except — all HTTP methods "
                "(GET/POST/PUT/DELETE/PATCH) forwarded to fcgi_cisco_opaque; fcgi reads BIOS "
                "post codes and Jolt opaque blobs via libjolt_cisco_opaque.so; no nginx-layer "
                "auth; endpoint present on main HTTPS port alongside Redfish",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — nginx.conf.template extracted from primary SquashFS at "
                "blob+29495552; fcgi_cisco_opaque binary at /usr/local/bin/fcgi_cisco_opaque "
                "(ARM32 pie, references libjolt_cisco_opaque.so, libbiostokenmgmt.so); "
                "/var/cisco_opaque/ socket path confirmed",
    "cwe":      ["CWE-284 (Improper Access Control)"],
    "verbatim_nginx": """
        # Cisco Opaque Handler
        location /cisco/blob/ {
            fastcgi_buffering off;
            fastcgi_pass   unix:/var/cisco_opaque/cisco_opaque_fcgi_handler_socket;
            fastcgi_param  REQUEST_URI $request_uri_path;
            fastcgi_param  QUERY_STRING $query_string_new;
            include        fastcgi_params;
            fastcgi_read_timeout 600;
        }
        # Cisco Opaque Handler""",
    "fcgi_strings": [
        "libjolt_cisco_opaque.so",
        "libbiostokenmgmt.so",
        "Opaque.URI",
        "OpaqueItemType",
        "FileSize",
        "FileOffset",
        "cisco_opaque_fetch",
        "get_intersight_config",
        "jolti_method_invoke",
        "bios_post",
        "BiosPostComplete",
        "get_bios_post_complete",
        "/var/cisco_opaque",
        "src/fcgi_cisco_opaque_handler.c",
    ],
    "note": "The B480 M5 nginx config does not contain /cisco/blob/. This endpoint is X-Series "
            "specific. The Jolt opaque store (libjolt_cisco_opaque.so) handles arbitrary binary "
            "blob storage with FileSize/FileOffset parameters — the blast radius depends on what "
            "methods fcgi_cisco_opaque accepts and whether the blob items can be written externally. "
            "No limit_except in nginx means all 7 HTTP verbs reach the handler; internal auth in "
            "fcgi is the only gate.",
}

# X410M7-F2: /vic_upload/ 100MB PUT endpoint on TCP/443 — 5x larger attack window than /vic_core_upload/
X410M7_F2 = {
    "id":       "X410M7-F2",
    "title":    "nginx TCP/443 /vic_upload/ PUT endpoint: 100MB body limit (5x /vic_core_upload/), "
                "stores to /nv/scratchpad/vic_tech_uploads via client_body_in_file_only clean; "
                "no nginx-layer auth; distinct fcgi handler (vic_upload_fcgi_handler_socket); "
                "X-Series only — not present in B480 M5 nginx config",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — nginx.conf.template on primary SquashFS; /nv/scratchpad/ autoindex "
                "on (cross-model, confirms scratchpad is readable); fcgi_vic_upload binary has "
                "verify_authentication symbol (auth in handler, not nginx)",
    "cwe":      ["CWE-434 (Unrestricted Upload of File with Dangerous Type)"],
    "verbatim_nginx": """
        location /vic_upload/ {
            limit_except PUT { deny all; }
            client_body_temp_path      /nv/scratchpad/vic_tech_uploads;
            client_body_in_file_only   clean;
            client_max_body_size       100M;
            client_body_timeout        60s;
            fastcgi_pass_request_body  off;
            fastcgi_param REQUEST_BODY_FILE $request_body_file;
            fastcgi_pass   unix:/var/vic_upload/vic_upload_fcgi_handler_socket;
        }""",
    "comparison": {
        "/vic_upload/  (X-Series, TCP/443)":   "100MB, /nv/scratchpad/vic_tech_uploads, fcgi_vic_upload",
        "/vic_core_upload/ (all, TCP/9005)":   " 20MB, /nv/scratchpad/vic_core_temp_uploads, vic_management_fcgi_handler_socket",
    },
    "note": "The main HTTPS port (443) exposes a 100MB file staging endpoint. client_body_in_file_only "
            "clean means nginx writes the body to disk before FastCGI can read it. If fcgi_vic_upload's "
            "verify_authentication is bypassable (session replay, token reuse), a 100MB arbitrary "
            "file can be staged to /nv/scratchpad/. With /nv/scratchpad/ autoindex on, the file "
            "is immediately listed via HTTP GET /nv/scratchpad/.",
}

# X410M7-F3: remserial TCP serial forwarding via inetd when bmc2host-pppd.sh enables PPP mode
X410M7_F3 = {
    "id":       "X410M7-F3",
    "title":    "bmc2host-pppd.sh enables 'remserial' in /etc/inetd.conf (dynamic write) and "
                "restarts inetd; remserial maps /dev/ttySrv1 (virtual UART to host CPU COM2) to "
                "TCP; inetd spawns remserial per-connection via PPP mode activation; no "
                "authentication layer on the remserial TCP service",
    "severity": "HIGH",
    "status":   "CONFIRMED — bmc2host-pppd.sh at /usr/local/bin/ extracted from primary SquashFS; "
                "remserial binary at /usr/local/bin/remserial (ARM32 pie); inetd.service confirms "
                "ExecStart=/usr/sbin/inetd -f; /dev/ttySrv1 string confirmed in remserial binary",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "verbatim_bmc2host": """
# bmc2host-pppd.sh stop path (removes remserial from inetd):
if (`grep -q emserial /etc/inetd.conf`); then
    /bin/sed -i -e 's/remserial/#Remserial/g' /etc/inetd.conf
    /usr/bin/systemctl restart inetd
fi
/usr/bin/killall -9 /usr/local/bin/remserial
/usr/bin/killall -9 remserial

# bmc2host-pppd.sh start path (adds remserial to inetd):
if (`grep -q emserial /etc/inetd.conf`); then
    /bin/sed -i -e 's/#Remserial/remserial/g' /etc/inetd.conf
    /usr/bin/systemctl restart inetd
fi""",
    "remserial_strings": [
        "/dev/ttySrv1",
        "%s:%d:Socket Closed ... exit",
        "%s:%d:Socket Error [%m] ... exit",
        "<--- %s: pid(%d): New Connection --->",
        "%s:%d:Failed to get access to Uart and TCP Port, Exit Now",
    ],
    "threat_model": "When the BMC-to-host PPP session is active (management path between BMC and "
                    "host CPU is PPP tunnel), bmc2host-pppd.sh writes remserial into /etc/inetd.conf "
                    "and restarts inetd. Any host on the management segment can connect to the "
                    "remserial TCP port and reach /dev/ttySrv1 — the virtual UART mapped to host "
                    "COM2. This gives serial console access to the Intel Xeon host without credentials. "
                    "PPP mode is a normal operational state triggered by UCSM or CLI.",
}

# X410M7-F4: Mosquitto UNIX socket allow_anonymous true — any local process injects MQTT
X410M7_F4 = {
    "id":       "X410M7-F4",
    "title":    "Mosquitto UNIX socket at /var/run/mymqtt.sock: allow_anonymous true — "
                "any local process publishes/subscribes without credentials; 'cups' daemon "
                "(ARM32, 67KB) calls jolt_execute_cmd via this socket; TCP/9001 (STANDARD_PORTS) "
                "binds 127.0.0.1 only but inetd and FastCGI handlers can reach the socket",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — /etc/mosquitto/mosquitto-broker.conf extracted from primary SquashFS; "
                "cups binary at /usr/local/bin/cups (ARM32, references mosquitto_connect_bind_v5, "
                "jolt_execute_cmd, /var/run/mymqtt.sock); systemd confirms cups depends on "
                "mosquitto_broker-systemd.service",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-285 (Improper Authorization)"],
    "verbatim_mosquitto_conf": """
per_listener_settings true
user root
log_dest syslog

# localhost listener — auth required
listener 9001 127.0.0.1
allow_anonymous false

# socket listener — NO AUTHENTICATION
listener 0 /var/run/mymqtt.sock
allow_anonymous true""",
    "cups_strings": [
        "mosquitto_connect_bind_v5",
        "mosquitto_publish",
        "jolt_execute_cmd",
        "/var/run/mymqtt.sock",
        "system.cpu",
        "system.cpu.utilization",
        "%s:%d:Error: Failed to connect to mosquitto broker [%m], exiting...",
    ],
    "note": "MQTT socket anonymous access means any inetd handler, FCGI worker, or other "
            "network-reachable local process that can write to /var/run/mymqtt.sock can inject "
            "MQTT messages. 'cups' calling jolt_execute_cmd via MQTT suggests Jolt framework "
            "actions are triggered by MQTT topic messages — injecting to the right topic may "
            "invoke Jolt capabilities (BIOS control, cert management, DCPMM, user mgmt as seen "
            "on B480 M5) without going through credfish TCP/4038.",
}

# X410M7-F5: live_extract.sh extended with /tmp/live/ fallback — novel unsigned deployment path
X410M7_F5 = {
    "id":       "X410M7-F5",
    "title":    "live_extract.sh extended version: when /live/ is read-only, falls back to "
                "/tmp/live/$OPKGName with cp -a to user-controlled --lti directory; "
                "pre_link.sh and post_link.sh hooks executed as root in both main and fallback "
                "paths; no .cpk signature verification in either path",
    "severity": "HIGH",
    "status":   "CONFIRMED — /bin/live_extract.sh extracted from primary SquashFS at blob+29495552; "
                "opkg-extract at /bin/opkg-extract, opkg-prefix at /bin/opkg-prefix (ARM32); "
                "fallback path at /tmp/live/ with cp -a confirmed in script",
    "cwe":      ["CWE-345 (Insufficient Verification of Data Authenticity)",
                 "CWE-434 (Unrestricted Upload of File with Dangerous Type)"],
    "verbatim_main_path": """
if mkdir -p "/live/$OPKGName" 2>/dev/null; then
    opkg-extract $OPKG /live/$OPKGName
    if [ -e $OPKG_INSTALLSUMSPREFIX/.post_install/pre_link.sh ]; then
        $OPKG_INSTALLSUMSPREFIX/.post_install/pre_link.sh $OPKG_INSTALLSUMSPREFIX $OPKGPrefix
    fi
    cp -rs /live/$OPKGName/* / 2>/dev/null   # symlink overlay to rootfs
    rm $OPKG
    if [ -e $OPKG_INSTALLSUMSPREFIX/.post_install/post_link.sh ]; then
        $OPKG_INSTALLSUMSPREFIX/.post_install/post_link.sh ...
    fi""",
    "verbatim_fallback_path": """
# When /live/ is read-only (firmware update in progress or SquashFS mounted RO):
mkdir -p /tmp/live/$OPKGName
opkg-extract "$OPKG" "/tmp/live/$OPKGName"
if [ -e "$OPKG_INSTALLSUMSPREFIX/.post_install/pre_link.sh" ]; then
    $OPKG_INSTALLSUMSPREFIX/.post_install/pre_link.sh $OPKG_INSTALLSUMSPREFIX $OPKGPrefix
fi
INSTALLER_MODULE_LOC="$LOC_TO_INSTALL"/"$OPKGName"
mkdir -p "$INSTALLER_MODULE_LOC"
cp -a "/tmp/live/$OPKGName"/* "$INSTALLER_MODULE_LOC" 2>/dev/null
rm -f "$OPKG"
if [ -e "$OPKG_INSTALLSUMSPREFIX/.post_install/post_link.sh" ]; then
    "$OPKG_INSTALLSUMSPREFIX/.post_install/post_link.sh" ...
fi""",
    "diff_vs_b480m5": "B480 M5 live_extract.sh: single path to /live/, 33 lines. "
                      "X410C M7 live_extract.sh: dual-path with /tmp/live/ fallback via --lti flag, "
                      "extended control flow, 120+ lines. Both paths execute pre/post link hooks "
                      "as root with no signature check on .cpk content.",
    "threat_model": "Attacker stages a .cpk file containing a malicious .post_install/post_link.sh "
                    "to any writable path the live_extract.sh is invoked with. Script executes "
                    "post_link.sh as root. Fallback path to /tmp/ makes this reachable even when "
                    "primary /live/ mount is read-only. --lti flag controls the install destination, "
                    "enabling placement outside /live/ to persist across SquashFS remounts.",
}

FINDINGS = [X410M7_F1, X410M7_F2, X410M7_F3, X410M7_F4, X410M7_F5]
