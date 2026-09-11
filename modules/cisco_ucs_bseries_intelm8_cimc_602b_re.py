"""
Cisco UCS B-Series CIMC 6.0.2b — Intel Blade M8 RE module
Target: Intel Blade M8 CIMC firmware (ucs-k9-bundle-b-series.6.0.2b.B.bin → plugin_img)
Magic: 55aa000e (vs 55aa0007 for M6)

Intel M8 blob structure (extracted from B-Series bundle):
  Primary SquashFS:   46.18MB, 7327 inodes (ARM 32-bit)
  Secondary SquashFS: ~9-11MB (Intersight connector, web UI)

M8 vs M6 differences:
  - Full embedded Linux (/etc/shadow, /etc/passwd, /etc/pam.d/, SELinux, mosquitto, Python 3.10)
  - Intel Granite Rapids (Xeon 6) host CPU support
  - Additional binaries: apml_tool, aries_* (PCIe retimer), bmc-update, bseries_uemd_config
  - inetd.conf.mctools adds mcserver on TCP/4010 (all interfaces) in addition to jrpc_server_lo

Files analyzed:
  etc/init.d/platform_last           — M8 startup sequence
  etc/init.d/firewall                — mctools port exposure rules
  etc/inetd.conf → inetd.conf.mctools — inetd service config (mcserver + jrpc_server_lo)
  etc/inetd.conf.nomctools           — alternate config (jrpc_server_lo only)
  etc/services                       — port assignments
  usr/local/bin/mcserver             — main management server (ARM 32-bit ELF, stripped)
  usr/local/bin/jrpc_server          — JRPC server (ARM 32-bit ELF, stripped)
  etc/pam.d/                         — auth configs (sshd, kvm, redfish, other — NO mcserver entry)
  lib/libdfu/dfu                     — DFU support shell (bash script, support account login shell)
  configs/godfather/mmsp/*.yaml      — MMSP manifests (BtG reference)
  usr/local/nginx/conf/nginx.conf.template — nginx config (scratchpad autoindex)
"""

FIRMWARE = {
    "target":   "Cisco UCS Intel Blade M8 CIMC 6.0.2b",
    "bundle":   "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "magic":    "55aa000e",
    "kernel":   "Linux 5.15.x ARM 32-bit (AST2600 BMC)",
    "rootfs":   "SquashFS 4.0 zlib (46.18MB primary, 7327 inodes)",
    "board":    "ucs-x210c-m8 (Godfather platform, Granite Rapids host CPU)",
    "findings": ["BSERIES-M8-F1", "BSERIES-M8-F2", "BSERIES-M8-F3"],
}

# BSERIES-M8-F1: Intel Boot Guard CIMC enforcement gate unconditionally disabled
BSERIES_M8_F1 = {
    "id":       "BSERIES-M8-F1",
    "title":    "Intel Boot Guard CIMC power-gating check unconditionally disabled in platform_last "
                "init script — CIMC never gates host CPU power based on Boot Guard measurement outcome",
    "severity": "HIGH",
    "status":   "CONFIRMED — platform_last script extracted from primary SquashFS; "
                "unconditional `echo 0 > /proc/cisco/bootguard_enabled_cpu` present with TODO comment; "
                "MMSP manifests confirm 'REL signed BtG Enabled BIOS' was intended enforcement target",
    "cwe":      ["CWE-693 (Protection Mechanism Failure)", "CWE-284 (Improper Access Control)"],
    "file":     "etc/init.d/platform_last",
    "verbatim_code": """
    # TODO_M8: Update! For now, just disable the BtG enabled CPU so that
    # the driver doesn't check/gate host power on
    /usr/bin/logger -t $title -p user.notice "Overriding the FD0V GPIO host power gate
        until we figure out what to do with this"
    echo 0 > /proc/cisco/bootguard_enabled_cpu
""",
    "intended_logic": """
    # What was supposed to happen (all commented out):
    if [[ $CPU_NAME == "graniterapids" ]]; then
        # Min supported Granite Rapids CPUID for BtG is 0xdXXX? (???? decimal)
        # if [ $CPUID_DEC -lt 1778 ]
        # then
        #     echo 0 > /proc/cisco/bootguard_enabled_cpu  # non-BtG CPU
        # else
        #     [leave in place — BtG CPU, gate enforced]
        # fi
    fi
""",
    "mmsp_evidence": {
        "manifest_4.1":  "configs/godfather/mmsp/godfather-mmsp-manifest-4.1.yaml",
        "artifact_name": "BIOS-PKG",
        "verbatim":      "REL signed BtG Enabled BIOS",
        "versions":      "manifests 3.0 through 4.1 all reference BtG Enabled BIOS",
        "board":         "ucs-x210c-m8 (Godfather)",
    },
    "mechanism": {
        "proc_path":    "/proc/cisco/bootguard_enabled_cpu (Cisco kernel driver interface)",
        "value_0":      "0 = CIMC does NOT check/gate host power based on Boot Guard status",
        "value_1":      "1 = CIMC gates FD0V GPIO (host power) on Boot Guard measurement outcome",
        "fd0v_gpio":    "FD0V GPIO is the host CPU power gate — controls whether host boots",
        "effect":       "With bootguard_enabled_cpu=0, CIMC applies no power-gate enforcement "
                        "even if Boot Guard measurement fails or is absent",
    },
    "threat_model": "A BIOS modification (via authenticated CIMC BIOS update API or physical flash) "
                    "that causes an Intel Boot Guard measurement failure would normally cause the "
                    "CIMC to withhold host power via FD0V GPIO, preventing the compromised BIOS from "
                    "executing. With bootguard_enabled_cpu=0, the CIMC never gates power — the host "
                    "boots unconditionally regardless of Boot Guard outcome. Combined with CIMC's "
                    "BIOS update capability (__jolt_cisco_opaque_set_one_time_boot), this removes "
                    "the CIMC's role as a Boot Guard enforcement anchor on the M8 platform.",
    "note": "This is a CIMC-side enforcement bypass, not a bypass of Intel Boot Guard fuse programming "
            "in the CPU itself. The CPU still performs Boot Guard ACM verification; this disables "
            "the CIMC's response to that verification result. CIMC-enforced power gating is an "
            "additional defense-in-depth layer on top of CPU-internal Boot Guard.",
    "regression": "The intended logic would gate power based on CPUID BtG support level. "
                  "The TODO comment confirms Cisco developers knew this was incomplete: "
                  "'For now, just disable' + 'until we figure out what to do with this'.",
}

# BSERIES-M8-F2: mcserver TCP/4010 runs as root with no application-level authentication
BSERIES_M8_F2 = {
    "id":       "BSERIES-M8-F2",
    "title":    "mcserver (TCP/4010, all interfaces) runs as root via inetd with no PAM configuration "
                "and no application-level authentication — firewall-only protection for a root-privileged "
                "JSON/XML management command protocol",
    "severity": "HIGH",
    "status":   "CONFIRMED — inetd.conf.mctools extracted from primary SquashFS; "
                "mcserver has no /etc/pam.d/mcserver entry; all other services (sshd, kvm, redfish) "
                "use pam_bmc.so; firewall.sh restricts to outofband VLANs but no app-level auth",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-284 (Improper Access Control)"],
    "files":    [
        "etc/inetd.conf.mctools",
        "etc/pam.d/  (no mcserver entry)",
        "etc/init.d/firewall",
        "etc/services",
        "usr/local/bin/mcserver",
    ],
    "inetd_entry": "mcserver  stream tcp  nowait root  /usr/local/bin/mcserver mcserver",
    "port":         4010,
    "protocol":     "JSON (cJSON) + XML (Expat) — Cisco system command protocol over TCP",
    "firewall_model": {
        "outofband_allowed": ["eth0.1 (VLAN 1)", "eth0.4044 (VLAN 4044)", "eth1.1", "eth1.4044"],
        "inband_blocked":    "external management interface (admin-facing NIC)",
        "enable_call":       "platform_last calls `firewall enable-ucsm-mctools` at end of boot",
        "mode_toggle":       "127.5.254.1 / 127.6.254.1 REJECT rules toggle UCSM-mode access",
    },
    "auth_gap": {
        "pam_modules":  "sshd, kvm, redfish, vm, other all use pam_bmc.so (SQLCipher user DB)",
        "mcserver":     "NO pam.d entry — mcserver has no PAM auth path whatsoever",
        "binary":       "mcserver binary has user management, IPMI config, session tracking "
                        "but zero auth challenge/credential-validation string references",
    },
    "mcserver_capabilities": {
        "user_mgmt":        "create/delete/modify CIMC local users (libuser_mgmt.so)",
        "ipmi_user_config": "set IPMI user access (mcserver_set_ipmi_users)",
        "bios_tokens":      "write BIOS token files (/nv/etc/BIOS/bt/BiosToken/ UUID-keyed)",
        "host_power":       "power_on, host power gating (via /proc/nuova/gpio, /dev/host_power)",
        "vmedia":           "virtual media database management (vmdb_insert_local_media)",
        "session_kill":     "terminate KVM/vMedia sessions (kvm_rpc_kill_session)",
        "pam_disable":      "write /var/pam-localuser-disable (disables PAM local user auth globally)",
        "jolt_dispatch":    "jolti_init + jolti_method_invoke (full Jolt plugin system access)",
    },
    "pam_localuser_disable": {
        "path":    "/var/pam-localuser-disable",
        "effect":  "When this file exists, PAM local user authentication is disabled globally",
        "created": "mcserver creates this file when transitioning blade to UCSM-managed mode",
        "risk":    "Any process reaching mcserver on TCP/4010 via outofband VLAN can trigger "
                   "user management commands that write this file, locking out all local users",
    },
    "threat_model": "A process on the UCSM-facing VLANs (e.g., from a compromised Fabric Interconnect, "
                    "or via VLAN escape from the management network) connects to TCP/4010 and issues "
                    "Cisco system command XML/JSON — creating admin users, modifying BIOS tokens, "
                    "writing /var/pam-localuser-disable to lock out local auth, or controlling host power. "
                    "mcserver processes all commands as root with no credential check.",
}

# BSERIES-M8-F3: jrpc_server loopback TCP6/4037 has zero authentication strings (root, inetd)
BSERIES_M8_F3 = {
    "id":       "BSERIES-M8-F3",
    "title":    "jrpc_server (TCP6/4037 loopback) runs as root via inetd with zero authentication "
                "strings in binary — unauthenticated JRPC protocol access from any CIMC-local process",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — inetd.conf.mctools extracted; jrpc_server binary has zero "
                "auth/credential/token/password strings; port 4037 labeled 'CIMC JRPC port (loopback)' "
                "in /etc/services; pattern matches CMC-F3 (confirmed unauthenticated JRPC on CMC firmware)",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "files":    ["etc/inetd.conf.mctools", "etc/services", "usr/local/bin/jrpc_server"],
    "inetd_entry": "jrpc_server_lo  stream tcp6 nowait root  /usr/local/bin/jrpc_server jrpc_server -v 6",
    "port":     4037,
    "binding":  "TCP6 loopback only (::1)",
    "services_comment": "'# CIMC JRPC port (loopback)' — Cisco's own label confirms loopback-restricted design",
    "also_port_4038": {
        "service":   "jrpc_server (without _lo suffix) on 4038",
        "comment":   "'# CIMC JRPC port' (no loopback qualifier)",
        "in_inetd":  "only _lo (4037) is in inetd.conf.mctools; 4038 may be a second instance or legacy",
    },
    "auth_evidence": {
        "strings_search": "grep -i 'auth|login|password|session|token|credential' on jrpc_server binary",
        "result":         "ZERO MATCHES",
        "conclusion":     "jrpc_server performs no authentication — accepts all connections on ::1:4037",
    },
    "analog": {
        "cmc_f3": "CMC-F3: jrpc_server TCP/4037 explicitly labeled 'not secured' in CMC source; "
                  "M8 CIMC shows the same pattern with zero auth strings",
        "m6":     "M6 CIMC inetd.conf.mctools has identical jrpc_server_lo entry",
    },
    "threat_model": "Any process executing on the M8 blade CIMC (e.g., via BSERIES-F1 file drop, "
                    "credfish bug, or other CIMC foothold) can connect to ::1:4037 and issue "
                    "unauthenticated JRPC commands to jrpc_server running as root. "
                    "JRPC protocol scope: firmware management, system configuration, platform diagnostics.",
}

FINDINGS = [BSERIES_M8_F1, BSERIES_M8_F2, BSERIES_M8_F3]
