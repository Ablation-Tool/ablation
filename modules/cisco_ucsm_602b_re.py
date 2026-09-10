"""
Cisco UCS Manager 6.0(2b)A — Reverse Engineering Module
Source: ucs-manager-k9.6.0.2b.bin extracted from ucs-x-direct-k9-infra.6.0.2b.A.bin
Bundle structure: Cisco SN header (748 bytes) → gzip → tar containing:
  - sam_plugin (16KB): Startup plugin with SAM init scripts
  - sam_plugin_main (1020MB): Full UCSM application
  - ucs-fi-connector (9.6MB): Cloud connector + web UI
FI connector version: 1.0.11-20250225214452343 (@andromeda/an-apollo)
"""

FIRMWARE = {
    "target":    "Cisco UCS Manager (UCSM)",
    "version":   "6.0(2b)A",
    "source":    "ucs-manager-k9.6.0.2b.bin",
    "origin":    "Nested Cisco SN bundle inside ucs-x-direct-k9-infra.6.0.2b.A.bin",
    "branding":  "pmon.conn.conf copyright 2017: 'NUOVA SYSTEMS, Inc.' — original acquisition branding in production 2026 firmware",
    "components": {
        "sam_plugin":      "SAM startup init scripts, libsamcli_cmd.so",
        "sam_plugin_main": "Full UCSM application (1020MB)",
        "ucs-fi-connector": "Intersight cloud connector daemon + Apache web UI symlink",
    },
    "findings":  ["UCSM-F1", "UCSM-F2", "UCSM-F3", "UCSM-F4", "UCSM-F5"],
}

# ─────────────────────────────────────────────────────────
# UCSM-F1: securityDisabled=yes in /opt/db/sam.config skips all iptables rules
#           — single config flag bypasses FI firewall entirely on boot
# ─────────────────────────────────────────────────────────
UCSM_F1 = {
    "id":       "UCSM-F1",
    "title":    "sam.config 'securityDisabled=yes' causes S97load-sam to skip all iptables setup on boot — "
                "full firewall bypass via single config file key",
    "status":   "CONFIRMED — S97load-sam initFirewallRules() in sam_plugin, path /isan/etc/rc.d/rc.isan-start/S97load-sam",
    "severity": "CRITICAL",

    "vulnerable_code": (
        "initFirewallRules() {\n"
        "    if [ -f $SAM_CONFIG ]; then\n"
        "        SECMODE=`cat ${SAM_CONFIG} | grep ${SEC_FLAG} | awk -F'=' '{print $2}'`\n"
        "        if [ \"$SECMODE\" = \"yes\" ]; then\n"
        "            echo \"Security disable mode is on, skipping iptables setup\"\n"
        "            return;        # ← returns immediately, no iptables rules applied\n"
        "        fi\n"
        "    fi\n"
        "    /sbin/iptables -P INPUT DROP   # ← only reached if securityDisabled != yes\n"
        "    ... (full whitelist follows)\n"
        "}"
    ),

    "config_key":    "securityDisabled=yes  (in /opt/db/sam.config, key=SEC_FLAG=securityDisabled)",
    "sam_config_path": "/opt/db/sam.config",

    "firewall_rules_skipped": (
        "Normal iptables policy: INPUT DROP, FORWARD DROP, OUTPUT ACCEPT. "
        "Whitelist: SSH/22, ICMP, ESTABLISHED, FTP on vlan4047, port 4025 on vlan4044, "
        "HTTPS/443 on vlan4046, all traffic on vlan4042 (internal), "
        "DHCP/TFTP/NTP/PTP/syslog. "
        "When securityDisabled=yes: ALL traffic accepted by default (no DROP policy, no rules). "
        "The firewall comment 'Allow only SSH traffic during startup' becomes void."
    ),

    "attack_path": (
        "1. Any write path to /opt/db/sam.config (requires access to the SAM partition, "
        "   which is mounted at /opt — writable by root and andro/samdme accounts)\n"
        "2. Set securityDisabled=yes in sam.config\n"
        "3. Reboot the FI (or wait for next boot)\n"
        "4. All ports open on all interfaces — FI management plane fully exposed\n"
        "Alternative: the sam.config is on the SAM partition (/opt) which is backed by "
        "a physical disk label 'sam'. If this partition is accessible during maintenance "
        "mode or via the upgrade path, the flag can be set without root shell access."
    ),

    "impact": "FI firewall bypass on reboot — all management plane ports exposed on all interfaces",
}

# ─────────────────────────────────────────────────────────
# UCSM-F2: /opt/db/sam.config holds admin password hash, Intersight shared secret,
#           cluster credentials — single file exposure = full credential set
# ─────────────────────────────────────────────────────────
UCSM_F2 = {
    "id":       "UCSM-F2",
    "title":    "sam.config at /opt/db/sam.config stores admin password hash, Intersight cloud connector "
                "shared secret, and cluster virtual IP — single file read yields full credential set",
    "status":   "CONFIRMED — sam_init_securityfiles_sam.sh + common_defs + S97load-sam (sam_plugin)",
    "severity": "HIGH",

    "credentials_in_sam_config": {
        "adminPasswd":  "Admin account password hash (applied to /etc/shadow on every boot)",
        "sharedSecret": "Intersight cloud connector authentication secret (PASADENA_SECRET)",
        "clusterState": "Cluster peer state and VIP for FI cluster operations",
        "oobIpAddr":    "Management interface IP (written to eth0 on boot)",
        "oobIpGateway": "Default gateway",
        "virtualIpAddr": "Cluster virtual IP for FI-A/B HA pair",
        "registryIp":   "Intersight cloud registry IP (PASADENA_SERVER key)",
        "securityDisabled": "Firewall bypass flag (UCSM-F1)",
    },

    "password_flow": (
        "sam_init_securityfiles_sam.sh reads adminPasswd from sam.config:\n"
        "  ADMIN_PASSWORD=`grep ${ADMIN_PASSWD} ${SAM_CONFIG} | awk -F'=' '{print $2}'`\n"
        "  (substitutes into /etc/shadow on every boot)\n"
        "The hash format in sam.config is whatever the admin set at initial config. "
        "If stored as MD5-crypt ($1$...), offline cracking is feasible. "
        "Linux shadow DES or MD5 hashes in sam.config are directly crackable."
    ),

    "file_permissions_note": (
        "/opt/db/sam.config is on the 'sam' LVM partition mounted at /opt. "
        "Permissions are set during initial install. "
        "The file is read by scripts running as root and samdme. "
        "Any path to /opt that bypasses the access controls (e.g., mount the partition "
        "offline, extract from backup, or access during upgrade extraction to /spare or /opt) "
        "yields the full credential set."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSM-F3: exec_sam_upgrade set SUID root on every boot
#           — upgrade binary always executes as root regardless of caller
# ─────────────────────────────────────────────────────────
UCSM_F3 = {
    "id":       "UCSM-F3",
    "title":    "S97load-sam sets SUID root on /isan/bin/exec_sam_upgrade on every boot — "
                "upgrade binary permanently runs as root regardless of calling user's privilege",
    "status":   "CONFIRMED — S97load-sam line: /bin/chmod +s /isan/bin/exec_sam_upgrade",
    "severity": "HIGH",

    "suid_set_cmd":    "/bin/chmod +s /isan/bin/exec_sam_upgrade",
    "suid_purpose":    "Allow remote modifications to file systems during SAM upgrade (from comments)",
    "binary_path":     "/isan/bin/exec_sam_upgrade",

    "analysis": (
        "SETUID is applied on every boot via S97load-sam, making the SUID persistent "
        "across any manual chmod removal. Even if an administrator removes the SUID bit, "
        "the next reboot re-applies it. "
        "Any argument injection, path traversal, or command injection vulnerability in "
        "exec_sam_upgrade executes with root privilege. "
        "The binary's stated purpose ('remote modifications to file systems') means it "
        "takes user-supplied paths or operations as arguments — a typical SUID attack surface. "
        "Binary not extracted for analysis (lives in sam_plugin_main, 1020MB)."
    ),

    "attack_surface": (
        "exec_sam_upgrade likely takes a firmware image path or command as argument. "
        "Any non-admin user who can invoke exec_sam_upgrade (via NX-OS CLI, web API, or "
        "direct Linux shell access) can leverage the SUID to:\n"
        "  - Write to root-only paths by passing a crafted destination\n"
        "  - Execute arbitrary commands if the binary eval()s or system()s its arguments\n"
        "Requires binary-level analysis of exec_sam_upgrade to confirm specific exploitation."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSM-F4: Inter-FI cluster SSH with StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null
#           — MITM-vulnerable cluster coordination channel
# ─────────────────────────────────────────────────────────
UCSM_F4 = {
    "id":       "UCSM-F4",
    "title":    "UCSM common_utils.sh execute_remote_command() uses SSH with StrictHostKeyChecking=no "
                "and UserKnownHostsFile=/dev/null to samdme@127.12.0.1/127.12.0.2 — cluster channel is MITM-vulnerable",
    "status":   "CONFIRMED — common_utils.sh execute_remote_command() (sam_plugin /isan/etc/common_utils.sh)",
    "severity": "MEDIUM",

    "vulnerable_invocation": (
        "${UCS_SH_CMD_SUDO} ${UCS_SH_CMD_SSH} "
        "-o ConnectTimeout=5 "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "samdme@$otherswitchip \"${remote_cmd}\""
    ),

    "target_ips": {
        "switch_a": "127.12.0.1",
        "switch_b": "127.12.0.2",
    },

    "logging": (
        "The verbose mode invocation is ALSO logged:\n"
        "${UCS_SH_CMD_SSH} -v -o ConnectTimeout=5 -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null samdme@$otherswitchip \"${remote_cmd}\"\n"
        "This logs the SSH session verbosely to /var/sysmgr/sam_logs/exec_remote.log "
        "including key exchange details. The log file is chmod ugo+w — world-writable."
    ),

    "impact": (
        "127.12.0.1/127.12.0.2 are loopback addresses. In a clustered FI pair, "
        "these are routed over the cluster interconnect link between FI-A and FI-B. "
        "The cluster link is typically a dedicated hardware connection, "
        "but any position on that link (physical tap, compromised switch, FI-side bridge) "
        "can MITM the samdme SSH session. "
        "samdme is in the network-operator group with /bin/bash shell. "
        "MITM yields execution of arbitrary remote_cmd as samdme + NOPASSWD sudo scope. "
        "Additionally: world-writable exec_remote.log logs all SSH session details."
    ),

    "related": "Same StrictHostKeyChecking=no pattern as ISA-F3 (diag.py) and HUU-M5-F3",
}

# ─────────────────────────────────────────────────────────
# UCSM-F5: Version string '0.1.0.*' bypasses version check in install-connector.sh
#           — development override in production connector upgrade logic
# ─────────────────────────────────────────────────────────
UCSM_F5 = {
    "id":       "UCSM-F5",
    "title":    "install-connector.sh compareVersion() treats version '0.1.0.*' as always newer — "
                "development version override bypasses downgrade protection in production connector",
    "status":   "CONFIRMED — install-connector.sh compareVersion() in ucs-fi-connector bundle",
    "severity": "LOW",

    "vulnerable_code": (
        "compareVersion () {\n"
        "    ...\n"
        "    # Iterate over each sub version string starting comparing each\n"
        "    # If incoming version is a development override the version check\n"
        "    if [[ ${1:0:5} == '0.1.0' ]];then\n"
        "        return 1  # ← '1' means 'first arg is greater than second' → install proceeds\n"
        "    fi\n"
        "    ...\n"
        "}"
    ),

    "analysis": (
        "Any connector bundle with a version string starting with '0.1.0' (first 5 chars) "
        "is treated as 'newer than everything' and the upgrade proceeds unconditionally. "
        "This was intended as a development override to allow test builds to always install. "
        "In production, an attacker who can stage a connector bundle with version '0.1.0.x' "
        "can force installation regardless of the currently-running version, "
        "bypassing the downgrade protection built into compareVersion()."
    ),

    "impact": (
        "Prerequisite: attacker can write a connector bundle to /spare/tmpConnector/ or "
        "/opt/tmpConnector/ and trigger install-connector.sh (via the FI upgrade flow). "
        "With version '0.1.0.*': downgrade or sidegrade to any version including a backdoored "
        "connector with 0.1.0.1 version string. "
        "The connector (ucsfi binary) runs with ulimit -v 500000 and manages the Intersight "
        "cloud communication channel — a backdoored connector can exfiltrate all UCSM telemetry."
    ),
}

SAMDME_ACCOUNT = {
    "created_by":    "sam_init_securityfiles_sam.sh via: useradd -d ${SAMDME_HOME} -s /bin/bash samdme -g network-operator",
    "shell":         "/bin/bash",
    "home":          "/var/home/samdme",
    "group":         "network-operator",
    "ssh_keys":      "/opt/ssh_keys/samdme → /var/home/samdme/.ssh/ (copied on boot)",
    "ssh_auth_only": "sshd_config: Match user samdme → PasswordAuthentication no (key-only auth)",
    "cluster_role":  "Used for inter-FI SSH communication at 127.12.0.1/127.12.0.2",
}

FINDINGS = [UCSM_F1, UCSM_F2, UCSM_F3, UCSM_F4, UCSM_F5]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
