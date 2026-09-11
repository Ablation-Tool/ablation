"""
Cisco UCS B-Series CIMC 6.0.2b — BXSeriesM6 (X210C M6) RE module
Target: ucs-BXSeriesM6.6.0.2.260040.bin (53.8MB, extracted from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Board: ucs-bx210c-m6 (UCS X210c M6 in X-Series chassis — brdprog filename confirms BX210C)

BXSeriesM6 vs B200 M6 differences:
  - Blob magic: 55aa0007 (same M6 type as B200 M6)
  - Primary SquashFS: 27.37MB / 5898 inodes (vs 24.85MB / 5689 on B200 M6) — 209 extra files
  - No inetd.conf / no mcserver on TCP/4010 — BXM6 uses pure systemd architecture
  - Adds: mosquitto MQTT broker, MCTP daemon, SPDM trust store, VIC proxy, io_blade_runner,
           cpwm (Chassis Power/Wake Management), gpud, LLDP test, Aries retimer tools,
           libtacacs.so (TACACS+), libmbedtls, elftools Python package, libredfish_client.so
  - Same kernel: Linux 5.15.196.1 ARM 32-bit, same offsets as B200 M6

Files analyzed:
  etc/mosquitto/mosquitto-broker.conf  — MQTT broker config
  usr/lib/systemd/system/*.service     — systemd service configs
  usr/local/bin/vic_proxy              — VIC proxy binary
  usr/local/bin/spdm_trust_store.sh   — SPDM cert initialization
  usr/local/bin/io_blade_runner        — GPU/PCIe blade management
  usr/local/lib/libjolt_mqtt.so        — MQTT jolt plugin
  nv/security/SPDMcerts/              — pre-loaded SPDM trust anchors
  usr/local/nginx/conf/nginx.conf.template — nginx config (same as B200 M6)
"""

FIRMWARE = {
    "target":   "Cisco UCS BXSeriesM6 (X210C M6) CIMC 6.0.2b",
    "file":     "ucs-BXSeriesM6.6.0.2.260040.bin",
    "board":    "ucs-bx210c-m6 (UCS X210c M6 in X-Series chassis)",
    "kernel":   "Linux 5.15.196.1 ARM 32-bit (same as B200 M6)",
    "rootfs":   "SquashFS 4.0 zlib (27.37MB primary, 5898 inodes)",
    "findings": ["BSERIES-BXM6-F1", "BSERIES-BXM6-F2", "BSERIES-BXM6-F3"],
    "shared_with_b200m6": ["BSERIES-F1 (nginx /nv/scratchpad/ autoindex — same nginx.conf.template)"],
}

# BSERIES-BXM6-F1: Mosquitto MQTT Unix socket with allow_anonymous true
BSERIES_BXMG_F1 = {
    "id":       "BSERIES-BXM6-F1",
    "title":    "Mosquitto MQTT Unix socket (/var/run/mymqtt.sock) configured with allow_anonymous=true "
                "and auth plugin disabled — any CIMC-local process can publish/subscribe to MQTT "
                "telemetry topics without authentication",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — mosquitto-broker.conf extracted from primary SquashFS; "
                "Unix socket listener has allow_anonymous true; "
                "libmqtt_auth_plugin.so commented out; "
                "per_listener_settings true makes socket settings independent of TCP listener",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-284 (Improper Access Control)"],
    "file":     "etc/mosquitto/mosquitto-broker.conf",
    "verbatim_config": """
per_listener_settings true
user root
log_dest syslog

# localhost listener
listener 9001 127.0.0.1
allow_anonymous false
# protocol websockets
# plugin /usr/local/lib/libmqtt_auth_plugin.so    <-- AUTH PLUGIN DISABLED

#socket listener
listener 0 /var/run/mymqtt.sock
allow_anonymous true    <-- ANONYMOUS ON UNIX SOCKET
""",
    "mqtt_usage": {
        "libjolt_mqtt.so":  "Jolt plugin system MQTT bridge — publishes CIMC telemetry over MQTT; "
                            "topics fetched from /var/schemas/Telemetry/CISCO/CIMC/Topics.v1.0.json",
        "topic_schemas":    [
            "/var/schemas/Telemetry/CISCO/CIMC/BoardPower.v1.0.json",
            "/var/schemas/Telemetry/CISCO/CIMC/ProcessorThermal.v1.0.json",
            "/var/schemas/Telemetry/CISCO/CIMC/ProcessorPerformance.v1.0.json",
            "/var/schemas/Telemetry/CISCO/CIMC/NodeManagerPower.v1.0.json",
            "/var/schemas/Telemetry/OTLP/CIMC/*  (OpenTelemetry Protocol telemetry topics)",
        ],
        "mosquitto_broker-systemd.service": "Runs as root, started at application.target",
    },
    "auth_gap": {
        "tcp_9001":     "127.0.0.1:9001 has allow_anonymous false — requires credentials",
        "unix_socket":  "/var/run/mymqtt.sock has allow_anonymous true — zero auth required",
        "plugin":       "libmqtt_auth_plugin.so is in the filesystem but NOT loaded (commented out)",
        "root_process": "mosquitto broker runs as user root (user root in config)",
    },
    "threat_model": "Any process executing on the BX210C M6 CIMC can connect to "
                    "/var/run/mymqtt.sock and publish arbitrary payloads to CIMC telemetry "
                    "topics (BoardPower, ProcessorThermal, NodeManager) or subscribe to "
                    "real-time sensor data without any credential. If any CIMC service subscribes "
                    "to MQTT topics and takes action on message content (beyond logging), "
                    "unauthenticated message injection could trigger those actions. "
                    "Even without action triggers, subscribing enables persistent covert "
                    "sensor monitoring from any CIMC local foothold.",
}

# BSERIES-BXM6-F2: rlogin and rcp plaintext remote access tools present in production firmware PATH
BSERIES_BXMG_F2 = {
    "id":       "BSERIES-BXM6-F2",
    "title":    "rlogin and rcp plaintext remote access binaries present in /usr/local/bin/ "
                "in production BX210C M6 CIMC firmware — BSD r-commands available for re-activation",
    "severity": "LOW",
    "status":   "CONFIRMED — ELF ARM binaries at /usr/local/bin/rlogin and /usr/local/bin/rcp; "
                "not active via inetd (no inetd.conf present on BXM6); "
                "binaries are in PATH and callable by any CIMC script; "
                "ANALOGOUS: UCS FI 1.0.5.1 UCSFI-F1 (rlogin + pam_permit.so auth bypass)",
    "cwe":      ["CWE-319 (Cleartext Transmission of Sensitive Information)",
                 "CWE-306 (Missing Authentication for Critical Function)"],
    "files":    [
        "usr/local/bin/rlogin (ELF ARM 32-bit, stripped)",
        "usr/local/bin/rcp    (ELF ARM 32-bit, stripped)",
    ],
    "contrast_b200m6": "B200 M6 CIMC primary SquashFS does NOT include rlogin or rcp — "
                        "these are BX210C M6 specific",
    "activation_paths": [
        "inetd re-enabled: an attacker with NV write access writes /etc/inetd.conf "
        "enabling rlogin (TCP/513) and rsh/rcp",
        "direct invocation: any CIMC script that sources user input could invoke "
        "rlogin/rcp directly from PATH",
        "maintenance mode: Cisco may enable inetd with r-commands in factory/debug mode",
    ],
    "protocol_risk": {
        "rlogin": "BSD rlogin transmits credentials in cleartext; "
                  "authenticates via .rhosts or /etc/hosts.equiv; "
                  "TCP/513 standard port; no encryption",
        "rcp":    "BSD rcp relies on rsh trust (/.rhosts); "
                  "no authentication beyond hostname trust; "
                  "TCP/514",
    },
    "threat_model": "rlogin/rcp binaries in PATH on a CIMC that has /etc/hosts.equiv or "
                    "trusted host configuration would allow lateral movement between blade CIMCs "
                    "without credentials once any one is compromised. An attacker with write "
                    "access to /nv/ (CIMC NV storage) or /etc/ could create .rhosts / "
                    "hosts.equiv to enable trusted-host authentication.",
}

# BSERIES-BXM6-F3: SPDM user cert directory cleanup pattern leaves non-numeric files
BSERIES_BXMG_F3 = {
    "id":       "BSERIES-BXM6-F3",
    "title":    "spdm_trust_store.sh clears user SPDM cert directory with pattern *.*[0-9] — "
                "files without digit suffix survive reboots in /nv/security/SPDMcerts_user/, "
                "enabling persistent rogue SPDM CA injection across CIMC reboots",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — spdm_trust_store.sh extracted and analyzed; "
                "cleanup command `rm -f $SPDM_USER_CERT_DIR/*.*[0-9]` removes only numbered certs; "
                "files named *.pem or any non-digit-terminated name survive",
    "cwe":      ["CWE-281 (Improper Preservation of Permissions)",
                 "CWE-284 (Improper Access Control)"],
    "file":     "usr/local/bin/spdm_trust_store.sh",
    "verbatim_script": """
SPDM_CERT_DIR="/nv/security/SPDMcerts"
SPDM_USER_CERT_DIR="/nv/security/SPDMcerts_user"
SPDM_CERT_BUILD_DIR="/opt/flash"$SPDM_CERT_DIR

rm -rf $SPDM_CERT_DIR/*                    # vendor certs: fully reset from flash
ln -sf $SPDM_CERT_BUILD_DIR/*.pem $SPDM_CERT_DIR/   # repopulate from flash
rm -f  $SPDM_USER_CERT_DIR/*.*[0-9]        # user certs: only removes *.[digit] files
""",
    "cleanup_gap": {
        "removed":     "*.*[0-9] — e.g., cacert.0, spdm_root.1 (OpenSSL hash symlink format)",
        "NOT_removed": "Any .pem file or filename not ending in a digit survives reboots: "
                       "rogue_ca.pem, evil.trust, attacker.cert — all survive `rm -f *.*[0-9]`",
    },
    "spdm_context": {
        "purpose":      "SPDM (Security Protocol and Data Model, DMTF DSP0274) authenticates "
                        "PCIe devices (GPUs, NICs, retimers) to the CIMC BMC",
        "pre_loaded":   [
            "broadcom_avenger_fcs_root_ca.pem (Broadcom DCSG Root CA, ECDSA-SHA512, valid 1970-9999)",
            "broadcom_fcs_root_ca.pem (Broadcom DCSG Root CA variant)",
            "knox_root_ca.pem (Microchip Technology Crypto Authentication Signer CA DCS)",
        ],
        "user_dir":     "/nv/security/SPDMcerts_user/ — user-installable additional trust anchors",
        "mctpd":        "MCTP daemon calls authenticate_device() using certs from both directories",
    },
    "requires_write": "Writing to /nv/security/SPDMcerts_user/ requires write access to /nv/ "
                      "(CIMC non-volatile storage). This is a prerequisite — the finding is "
                      "that once any write is achieved, the rogue CA PERSISTS across reboots.",
    "threat_model": "An attacker who achieves a write to /nv/security/SPDMcerts_user/ "
                    "(e.g., via an exploited CIMC service, or authenticated operator) "
                    "can plant a PEM file named without a digit suffix (e.g., rogue_ca.pem). "
                    "This cert survives all CIMC reboots because spdm_trust_store.sh only "
                    "removes *.*[0-9] pattern files. The rogue CA can be used to generate "
                    "certificates for unauthorized PCIe devices that MCTP/SPDM will trust, "
                    "enabling persistent unauthorized device authentication on the X-Series chassis.",
}

FINDINGS = [BSERIES_BXMG_F1, BSERIES_BXMG_F2, BSERIES_BXMG_F3]
