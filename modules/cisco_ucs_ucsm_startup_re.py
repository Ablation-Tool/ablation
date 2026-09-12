"""
Cisco UCSM 6.0(2b) Startup Plugin RE Module
Source: ucs-manager-k9.6.0.2b.bin (inside ucs-6400-k9-bundle-infra.6.0.2b.A.bin)
Component: ucs_manager_startup_plugin.bin (SN-wrapped, 16KB)
Extracted from: UCSM inner tar -> ./isan/plugin_img/sam_plugin

Files analyzed:
  isan/bin/sam_startup.sh          (19KB startup orchestrator)
  isan/bin/sam_init_securityfiles_sam.sh
  isan/etc/rc.d/rc.isan-start/S97load-sam
  isan/etc/common_defs
  isan/lib/libsamcli_cmd.so        (32-bit x86 ELF .so)

UCSM inner tar structure:
  ./isan/plugin_img/ucs-fi-connector  (10006507 bytes, SN-wrapped)
  ./isan/plugin_img/sam_plugin        (16045 bytes, SN-wrapped -- this file)
  ./isan/etc/imghdr.bin               (748 bytes, SN header copy)
  ./isan/plugin_img/sam_plugin_main   (1069097946 bytes, SN-wrapped, main UCSM process)

SN nesting depth: outer bundle SN -> gzip-tar -> UCSM SN -> gzip-tar -> sam_plugin SN -> gzip-tar -> startup scripts
SWID: +swid-nuova-ca-mgmt (+ prefix, not 0/4/5 as in FI/FEX bundles)

8 findings: 0C/4H/3M/1L
Cumulative: 630 [55C+202H+194M+179L]
"""

# ============================================================
# UCSM COMPONENT STRUCTURE
# ============================================================

UCSM_INNER_TAR = {
    "sn_filename": "ucs-manager-k9.6.0.2b.bin",
    "swid": "+swid-nuova-ca-mgmt",
    "sn_offset": 748,
    "sn_hash": "648a83b99bbd9df355fe83fa49c06d65",
    "version": "6.0(2b)",
    "components": {
        "ucs-fi-connector": {
            "size_bytes": 10006507,
            "format": "SN-wrapped (offset 748, magic 6401534e)",
            "role": "FI connectivity plugin for UCSM",
        },
        "sam_plugin": {
            "size_bytes": 16045,
            "format": "SN-wrapped (offset 748), inner gzip-tar",
            "inner_filename": "ucs_manager_startup_plugin.bin",
            "role": "UCSM startup scripts and libsamcli_cmd.so",
            "contents": [
                "isan/lib/libsamcli_cmd.so (13684 bytes, ELF 32-bit i386)",
                "isan/bin/sam_startup.sh (19025 bytes, startup orchestrator)",
                "isan/bin/sam_init_securityfiles_sam.sh (997 bytes)",
                "isan/bin/backup_log_sam.sh (613 bytes)",
                "isan/bin/transfer_diag_log_sam.sh (1288 bytes)",
                "isan/etc/common_defs (8474 bytes, shared variable definitions)",
                "isan/etc/common_utils.sh",
                "isan/etc/rc.d/rc.isan-start/S97load-sam (9732 bytes)",
                "isan/etc/routing-sw/cli/samcli.cli",
            ],
        },
        "sam_plugin_main": {
            "size_bytes": 1069097946,
            "format": "SN-wrapped (offset 748)",
            "role": "main UCSM process image (1GB, not further extracted)",
        },
    },
}

# ============================================================
# COMMON DEFINITIONS (isan/etc/common_defs)
# ============================================================

COMMON_DEFS = {
    "switch_ips": {
        "SWITCH_A_IP": "127.12.0.1",
        "SWITCH_B_IP": "127.12.0.2",
        "INITIAL_ETH0_IP": "192.168.0.1",
    },
    "credential_paths": {
        "SAM_CONFIG": "/opt/db/sam.config",
        "SSL_KEYFILE": "/opt/certstore/default.key",
        "SSL_CERTFILE": "/opt/certstore/default.crt",
        "ROOT_SSH": "/opt/ssh_keys/root",
        "SAMDME_SSH": "/opt/ssh_keys/samdme",
        "HOST_SSH": "/opt/ssh_keys/host",
    },
    "config_keys": {
        "SEC_FLAG": "securityDisabled",
        "ADMIN_PASSWD": "adminPasswd",
        "PASADENA_SERVER": "registryIp",
        "PASADENA_SECRET": "sharedSecret",
    },
    "boot_images": {
        "SAM_BOOT_IMAGE": "/bootflash/nuova-sim-mgmt-nsg.0.1.0.001.bin",
        "SAM_SP_BOOT_IMAGE": "/bootflash/nuova-sim-mgmt-sp-nsg.0.1.0.001.bin",
    },
    "ipc_path": "BASH_TO_CGI=/tmp/bash_to_cgi",
    "container_mode": (
        "If /etc/ucsm-container exists: commands run via /ucs/isan/bin/ucscmd_env.sh. "
        "Otherwise: unshare -m (mount namespace only) + /ucs/isan/bin/ucscmd_env.sh."
    ),
}

# ============================================================
# IPTABLES RULESET (S97load-sam / initFirewallRules)
# ============================================================

IPTABLES_RULES = {
    "default_policy": "INPUT DROP (but overridden by terminal ACCEPT rule -- see UCSM-SAM-F2)",
    "explicit_drops": [
        "-A INPUT -i eth0 -d 127.0.0.0/8 -j DROP",
        "-A INPUT -i eth5 -d 127.0.0.0/8 -j DROP",
    ],
    "explicit_accepts": [
        "-A INPUT -p tcp --dport 22 -j ACCEPT (SSH)",
        "-A INPUT -i bond0 -j ACCEPT (all traffic on fabric bond)",
        "-A INPUT -i vlan4042 -j ACCEPT (all traffic on VLAN 4042)",
        "-A INPUT -p tcp -i vlan4047 --dport 21 -j ACCEPT (FTP on VLAN 4047)",
        "-A INPUT -p tcp -i vlan4044 --dport 4025 -j ACCEPT",
        "-A INPUT -p tcp -i vlan4044 --sport 4010 -j ACCEPT",
        "-A INPUT -p tcp -i vlan4046 --sport 443 -j ACCEPT",
        "-A INPUT -p tcp -i vlan4046 --dport 443 -j ACCEPT",
        "-A INPUT -p udp --dport 514 -j ACCEPT (syslog, no interface restriction)",
        "-A INPUT -p udp --dport 69 -j ACCEPT (TFTP, no interface restriction)",
        "-A INPUT -p udp --dport 67 -j ACCEPT (DHCP server, no interface restriction)",
        "-A INPUT -p udp --dport 68 -j ACCEPT (DHCP client, no interface restriction)",
        "-A INPUT -p udp --dport 123 -j ACCEPT (NTP, no interface restriction)",
        "-A INPUT -p udp --dport 319 -j ACCEPT (PTP event, no interface restriction)",
        "-A INPUT -p udp --dport 320 -j ACCEPT (PTP general, no interface restriction)",
        "-A INPUT -p icmp -j ACCEPT",
        "-A INPUT -p UDP -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "-A INPUT -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ],
    "terminal_rules": [
        "-A INPUT -i ! eth0 -j LOG --log-prefix 'FELL OFF INPUT-rules: '",
        "-A INPUT -j ACCEPT  <-- catch-all ACCEPT, matches all remaining traffic",
    ],
    "security_bypass": "securityDisabled=yes in /opt/db/sam.config skips ALL iptables setup",
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "UCSM-SAM-F1",
        "severity": "HIGH",
        "title": "PASSWORDLESS_ADMIN_SSH_CONFIGURED_EVERY_BOOT_VIA_INTERNAL_ID_RSA",
        "detail": (
            "sam_startup.sh calls setup_admin_passwordless_login() on every boot: "
            "copies /opt/internal_id_rsa and /opt/internal_id_rsa.pub into /var/home/admin/.ssh/, "
            "then writes /opt/internal_id_rsa.pub to /var/home/admin/.ssh/authorized_keys. "
            "Startup comment: 'During the initial setup configure admin user for passwordless login. "
            "This is needed to access the NXOS shell.' "
            "The key is sourced from /opt/internal_id_rsa -- the /opt persistent partition. "
            "If /opt/internal_id_rsa is pre-placed in the UCSM image (static across deployments), "
            "possession of the private key provides SSH admin access to any UCSM 6.0(2b) instance "
            "without a password. "
            "The key generation origin is not present in the analyzed startup scripts -- "
            "it is either generated during a first-boot step not included in sam_plugin, "
            "or shipped as a static image artifact in sam_plugin_main (1GB binary, not fully extracted). "
            "Severity rated HIGH pending confirmation that the key is generated fresh per deployment. "
            "If key is static, severity escalates to CRITICAL."
        ),
    },
    {
        "id": "UCSM-SAM-F2",
        "severity": "HIGH",
        "title": "IPTABLES_TERMINAL_ACCEPT_ALL_RULE_NEGATES_DROP_DEFAULT_POLICY",
        "detail": (
            "The UCSM iptables ruleset (initFirewallRules in S97load-sam) sets INPUT default policy DROP, "
            "then appends '-A INPUT -j ACCEPT' as the last rule. "
            "This terminal ACCEPT matches all traffic not previously DROPped by earlier rules. "
            "Effect: any new TCP/UDP connection to the UCSM on any port, from any source, "
            "that is not specifically blocked by prior rules reaches the terminal ACCEPT. "
            "The specific DROP rules only block loopback-spoofed traffic on eth0 and eth5. "
            "Any service bound on the UCSM management interface (eth0) on any non-SSH port "
            "accepts connections from the management network. "
            "Prior rule '-A INPUT -i ! eth0 -j LOG' logs non-eth0 falls-through, but does not DENY them. "
            "Result: the firewall provides PORT-level filtering only for traffic that matches "
            "specific interface+port combinations; all other traffic is accepted."
        ),
    },
    {
        "id": "UCSM-SAM-F3",
        "severity": "HIGH",
        "title": "SECURITY_DISABLED_FLAG_IN_SAM_CONFIG_BYPASSES_ALL_IPTABLES_RULES",
        "detail": (
            "initFirewallRules() reads 'securityDisabled' from /opt/db/sam.config: "
            "if its value is 'yes', the function returns immediately with "
            "\"Security disable mode is on, skipping iptables setup\". "
            "No iptables rules are installed -- INPUT default policy remains ACCEPT. "
            "Attack path: an attacker who can write to /opt/db/sam.config "
            "(the persistent SAM configuration partition) "
            "and trigger a reboot gains a fully open UCSM with no firewall protection. "
            "The flag key is 'securityDisabled' (mapped to SEC_FLAG in common_defs). "
            "Format: 'securityDisabled=yes' as a line in sam.config. "
            "No additional authentication gate separates this flag from network exposure."
        ),
    },
    {
        "id": "UCSM-SAM-F4",
        "severity": "HIGH",
        "title": "EXEC_SAM_UPGRADE_SET_SUID_EVERY_BOOT_FOR_REMOTE_FILESYSTEM_MODIFICATION",
        "detail": (
            "S97load-sam executes '/bin/chmod +s /isan/bin/exec_sam_upgrade' on every boot. "
            "Comment: 'Set S bit on the sam upgrade binary. This is to allow remote "
            "modifications to the file systems during SAM upgrade.' "
            "The SUID bit is re-set on every boot, restoring it even if manually removed. "
            "exec_sam_upgrade runs as root (SUID binary) and permits file system modification "
            "during UCSM upgrade operations. "
            "If exec_sam_upgrade accepts caller-controlled paths or arguments without "
            "sufficient validation, any process that can invoke it gains root-level file write. "
            "The binary content is inside sam_plugin_main (1GB SN-wrapped binary, not extracted). "
            "Severity: HIGH based on SUID + comment describing 'remote modifications to file systems'; "
            "escalates to CRITICAL if the binary accepts unsanitized paths."
        ),
    },
    {
        "id": "UCSM-SAM-F5",
        "severity": "MEDIUM",
        "title": "ADMIN_PASSWORD_HASH_IN_SAM_CONFIG_APPLIED_TO_SHADOW_EVERY_BOOT",
        "detail": (
            "sam_init_securityfiles_sam.sh reads the admin password from /opt/db/sam.config: "
            "ADMIN_PASSWORD=$(grep adminPasswd /opt/db/sam.config | awk -F= '{print $2}') "
            "This value is then written directly into /etc/shadow as the admin account hash. "
            "Implication 1: /opt/db/sam.config stores the admin shadow hash. "
            "If sam.config is read by any lower-privileged UCSM process or backed up without "
            "access controls, the admin shadow hash is exposed for offline cracking. "
            "Implication 2: modifying adminPasswd= in sam.config and rebooting "
            "installs an attacker-controlled shadow hash for admin. "
            "sam.config also stores: oobIpAddr, oobIpNetmask, oobIpGateway, "
            "virtualIpAddr, registryIp (Pasadena), sharedSecret, systemID -- "
            "a comprehensive credential and configuration store in a single file."
        ),
    },
    {
        "id": "UCSM-SAM-F6",
        "severity": "MEDIUM",
        "title": "CORS_CONFIG_INJECTED_FROM_WRITABLE_OPT_HTTP_TMP_ON_EVERY_BOOT",
        "detail": (
            "sam_startup.sh copies CORS configuration from /opt/http-tmp/httpd.conf.cors "
            "to /isan/apache/conf/httpd.conf.cors on every boot: "
            "'if [ -f ${HTTPD_PERSISTED_CORS_CONF_FILE} ]; then "
            "${CP} ${HTTPD_PERSISTED_CORS_CONF_FILE} ${HTTPD_CORS_CONF_FILE}; fi' "
            "/opt is the UCSM persistent partition (LABEL=sam, mounted at boot). "
            "/opt/http-tmp/ is a UCSM-managed directory. "
            "If an attacker can write to /opt/http-tmp/httpd.conf.cors, "
            "arbitrary Apache CORS configuration is installed at next boot. "
            "An attacker-controlled CORS policy could enable cross-origin requests "
            "to UCSM's web API from arbitrary domains, enabling CSRF against authenticated sessions. "
            "Additionally, Apache configuration injection (Header, Allow from, etc.) "
            "in this file may allow further Apache misconfiguration."
        ),
    },
    {
        "id": "UCSM-SAM-F7",
        "severity": "MEDIUM",
        "title": "FTP_PORT_21_EXPLICITLY_OPENED_ON_INTERNAL_FABRIC_VLAN_4047",
        "detail": (
            "S97load-sam installs the rule: "
            "'/sbin/iptables -A INPUT -p tcp -i vlan4047 --dport 21 -j ACCEPT' "
            "FTP (port 21) is a cleartext protocol. VLAN 4047 is a UCSM internal fabric VLAN "
            "(used for management plane communication between FIs and UCSM). "
            "An attacker with access to VLAN 4047 traffic (fabric-level access, insider, "
            "or compromised FI) can reach the FTP service on the UCSM management plane. "
            "FTP transmits credentials in cleartext (USER/PASS commands). "
            "If UCSM uses FTP to receive firmware images or configuration from FIs, "
            "a MITM on VLAN 4047 can substitute malicious files. "
            "The explicit iptables rule confirms FTP is an intentional, not accidental, service."
        ),
    },
    {
        "id": "UCSM-SAM-F8",
        "severity": "LOW",
        "title": "NUOVA_SIMULATION_MGMT_IMAGE_AS_FALLBACK_BOOT_PATH_IN_UCSM_STARTUP",
        "detail": (
            "sam_startup.sh defines the default management image path as "
            "mgmtimg='/bootflash/nuova-sim-mgmt-nsg.0.1.0.001.bin' "
            "(also SAM_SP_BOOT_IMAGE='/bootflash/nuova-sim-mgmt-sp-nsg.0.1.0.001.bin'). "
            "The 'nuova' prefix refers to Nuova Systems (pre-Cisco UCS acquisition; "
            "Cisco acquired Nuova Systems in 2008). "
            "The 'sim' component suggests a simulation mode image. "
            "extractMainPluginFromMgmt() extracts UCSM components from this image by "
            "running imghdr to get the SN block size, then dd+tar. "
            "If the fallback image is absent, UCSM boot proceeds to NX-OS-only mode "
            "('start_vshboot isan-ready'). "
            "The hardcoded filename 'nsg.0.1.0.001.bin' is a version 0.1.0 build number "
            "inconsistent with production versioning, suggesting this is a legacy/simulation "
            "artifact path that persists across production firmware versions."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_ucsm_startup_re",
    "source": "ucs-manager-k9.6.0.2b.bin -> sam_plugin (ucs_manager_startup_plugin.bin)",
    "extraction_path": (
        "ucs-6400-k9-bundle-infra.6.0.2b.A.bin "
        "-> SN(offset 808, gzip-tar) "
        "-> ./isan/plugin_img/ucs-manager-k9.6.0.2b.bin "
        "-> SN(offset 748, gzip-tar) "
        "-> ./isan/plugin_img/sam_plugin "
        "-> SN(offset 748, gzip-tar) "
        "-> startup scripts + libsamcli_cmd.so"
    ),
    "swid": "+swid-nuova-ca-mgmt",
    "key_observations": {
        "passwordless_admin": "setup_admin_passwordless_login() installs /opt/internal_id_rsa to admin authorized_keys every boot",
        "firewall_bypass": "securityDisabled=yes in sam.config skips all iptables setup",
        "terminal_accept": "final iptables rule '-A INPUT -j ACCEPT' negates DROP default policy",
        "suid_upgrade": "exec_sam_upgrade set SUID every boot for filesystem modification during upgrades",
        "cors_injection": "httpd.conf.cors copied from /opt/http-tmp/ on every boot",
        "admin_cred_store": "/opt/db/sam.config stores admin shadow hash, sharedSecret, oob config",
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 4, "MEDIUM": 3, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 202, "MEDIUM": 194, "LOW": 179},
    "cumulative_total": 630,
}
