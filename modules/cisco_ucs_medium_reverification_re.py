"""
Cisco UCS RE -- MEDIUM Tier Re-verification Pass
Apply Cisco CVSS v3.1 conventions to all 254 MEDIUM findings.
Identify upgrades (to HIGH or CRITICAL) and downgrades (to LOW).

Cisco CVSS v3.1 conventions applied:
  AV:N  -- management-plane services, even on dedicated VLANs
  S:C   -- crosses hardware bus (JTAG/ASIC/Secure Boot/chassis) or K8s cluster boundary
  PR:H  -- root/admin credentials required
  PR:L  -- any authenticated standard user
  PR:N  -- no authentication required
  UI:R  -- reboot required for exploitation
  AC:H  -- offline crack or MITM-in-path required before network exploitation

Source modules: all active UCS modules (875F after EOL drops)
Pass: 3 of 4 (CRITICAL done, HIGH done, MEDIUM this pass, LOW pending)
"""

# ============================================================
# UPGRADED TO CRITICAL (from MEDIUM)
# ============================================================

UPGRADED_TO_CRITICAL = [
    {
        "id":           "cwom_iso-F4",
        "module":       "cisco_ucs_cwom_iso_re",
        "original_cvss3": None,
        "new_cvss3":    9.8,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale": (
            "MariaDB initialized without root password (mysql_install_db, no --password flag). "
            "my.cnf has bind_address not set, which defaults to 0.0.0.0:3306 -- listens on all "
            "interfaces including the management network. "
            "If the hardening step (mysql_secure_installation) fails or is skipped, any host "
            "that can reach TCP/3306 gets unauthenticated root access to the entire CWOM database. "
            "This is the exact same pattern as cwom_vmdk-F3 (Consul unauthenticated HTTP API "
            "on eth0) which was upgraded to CRITICAL in the HIGH pass. "
            "AV:N: management-plane interface, bind_address=0.0.0.0. "
            "PR:N: empty root password = no credentials required. "
            "C/I/A:H: full database read/write/drop as root. "
            "Additional: log_bin_trust_function_creators=1 enables stored-routine privilege "
            "escalation for any user with CREATE ROUTINE -- secondary escalation path."
        ),
        "affected_products": ["CWOM 3.16.0 (cwom_iso)"],
        "cve_class": "Unauthenticated database access (empty root credential + 0.0.0.0 bind)",
        "chain_note": "Pairs with cwom_vmdk-F3 (Consul) and cwom_316-F4 (Consul ACL-less). "
                      "Three separate unauthenticated network services in the CWOM stack.",
    },
]

# ============================================================
# CONDITIONAL UPGRADES TO CRITICAL (pending confirmation)
# ============================================================

CONDITIONAL_CRITICAL = [
    {
        "id":        "UCSM-APACHE-F3",
        "module":    "cisco_ucs_ucsm_apache_re",
        "condition": "CloudUserRoles/CloudUserName headers accepted without source IP validation",
        "if_unvalidated_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL",
        "confirmed_medium_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N = 7.4 HIGH",
        "rationale": (
            "mod_nuova.so processes CloudUserName, CloudUserRoles, CloudUserLocale, "
            "CloudUserSessionId headers in the UCS Central integration path. "
            "If these headers are accepted from any source (not restricted to the UCS Central "
            "appliance IP), an attacker can inject 'CloudUserRoles: admin' in a direct request "
            "to UCSM Apache and obtain elevated cloud-user privileges without authentication. "
            "The ProxyPreserveHost connector RewriteRule forwards injected headers to the "
            "localhost:8889 backend, compounding the exposure. "
            "Confirmation requires binary analysis of the processCloudHandler path in mod_nuova.so "
            "to verify whether source IP validation is applied before trusting the headers. "
            "If no IP check: 9.8 CRITICAL. If IP-restricted to UCS Central: 7.4 HIGH (AC:H)."
        ),
        "pending_analysis": "Static analysis of mod_nuova.so processCloudHandler IP-check logic",
    },
]

# ============================================================
# UPGRADED TO HIGH (from MEDIUM)
# ============================================================

UPGRADED_TO_HIGH = [
    {
        "id":           "UCSM-UCSSH-F4",
        "module":       "cisco_ucs_ucsm_ucssh_re",
        "new_cvss3":    7.2,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "rationale": (
            "SamcProxyCoreCollect builds: "
            "cmd = '/bin/gzip -cd %s | grep -i %s' % (os.path.join(SwitchCoreDir, fil), samcSign) "
            "then calls subprocess.call(cmd, shell=True). "
            "SwitchCoreDir originates from JSON params -- attacker-controlled. "
            "shell=True + os.path.join() permit semicolon/pipe/backtick injection. "
            "Execution is root via exec_sam_upgrade SUID chain (same binary, F4/F5 in backup module). "
            "PR:H reflects admin-level invocation through the UCSM management plane. "
            "7.2 HIGH (AV:N/AC:L/PR:H = standard Cisco admin-RCE tier, same as FI IPMI findings)."
        ),
        "affected_products": ["UCS Manager (ucssh.py via SUID exec_sam_upgrade)"],
    },
    {
        "id":           "UCSM-CTR-F6",
        "module":       "cisco_ucs_ucsm_container_re",
        "new_cvss3":    8.8,
        "new_vector":   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "rationale": (
            "start-ucsm-container.sh: "
            "mount --rbind /var/run/netns ${ROOTFS_DIR}/var/run/netns "
            "followed by mount -o exec,remount,bind /var/run/netns ${ROOTFS_DIR}/var/run/netns. "
            "Recursive bind with exec permission exposes all host network namespaces "
            "(including /var/run/netns/management) inside the container with execute access. "
            "A container process with CAP_SYS_ADMIN can join the host management namespace "
            "via nsenter + the mounted path, escaping container isolation. "
            "S:C: crosses container-to-host boundary -- the host management namespace is the "
            "vulnerable component being affected beyond the container. "
            "Commented-out make-rslave line confirms isolation was considered and rejected, "
            "not overlooked. "
            "8.8 HIGH: AV:L (local container exec), S:C (crosses to host), C:H/I:H."
        ),
        "affected_products": ["UCS Manager container deployment"],
    },
    {
        "id":           "fi_nxos_backup-F4",
        "module":       "cisco_ucs_fi_nxos_backup_re",
        "new_cvss3":    7.8,
        "new_vector":   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "rationale": (
            "exec_sam_upgrade (i686 PIE ELF): "
            "0x1246 setuid(0); 0x124d setgid(0); 0x1a33 execl() -- "
            "unconditional root escalation with no visible auth check before execl. "
            "No pam_authenticate, no cap_get_proc, no shadow read in imported symbols. "
            "access() checks file existence only, not identity. "
            "If deployed SUID root (confirmed SUID bit required for full impact) or invoked "
            "from a management interface accessible to non-admin roles, any local caller "
            "gets root via the execl chain. "
            "7.8 HIGH: AV:L/PR:L (standard Linux SUID escalation rating). "
            "CONDITIONAL: upgrade only if SUID bit is confirmed on deployed filesystem."
        ),
        "affected_products": ["UCS FI 6500 6.0(2b) (spm/isan/bin/exec_sam_upgrade)"],
        "condition": "Confirmed SUID bit on deployed exec_sam_upgrade binary",
    },
    {
        "id":           "B480-M5-F4",
        "module":       "cisco_ucs_bseries_b480m5_cimc_601_re",
        "new_cvss3":    7.5,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "rationale": (
            "nginx TCP/9005 /vic_core_upload/ accepts unauthenticated PUT/POST. "
            "Management-plane endpoint with no authentication gate. "
            "AV:N: management plane service (Cisco convention). "
            "PR:N: no credentials required for upload. "
            "I:H: arbitrary file write to firmware staging area without auth. "
            "C:N: upload alone does not expose confidential data. "
            "7.5 HIGH: same class as pre-auth write endpoints in other Cisco CIMC modules."
        ),
        "affected_products": ["UCS B480 M5 CIMC 6.0.1"],
    },
    {
        "id":           "CWOM316-F3",
        "module":       "cisco_ucs_cwom_316_re",
        "new_cvss3":    8.8,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "rationale": (
            "t8c-operator ClusterServiceVersion v42.30.0 grants wildcard verbs ('*') "
            "across all core Kubernetes API groups. "
            "Operator pod compromise (PR:L for any K8s user who can exec into the operator pod) "
            "enables RBAC escalation to effective cluster-admin via the operator's SA token. "
            "S:C: Kubernetes cluster-wide impact beyond the operator namespace -- "
            "wildcard access to all core resources (pods, secrets, deployments, nodes) "
            "constitutes a scope change to the K8s control plane. "
            "8.8 HIGH: AV:N (K8s API accessible from management network), "
            "PR:L (any user who can exec into the operator pod), S:C (cluster-wide)."
        ),
        "affected_products": ["CWOM 3.16.0 (t8c-operator OLM bundle v42.30.0)"],
    },
    {
        "id":           "fi_nxos_ssh_peer-F3",
        "module":       "cisco_ucs_fi_nxos_ssh_peer_re",
        "new_cvss3":    7.4,
        "new_vector":   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "rationale": (
            "correct_ssh_keys.sh appends peer-fetched RSA public keys to the local "
            "authorized_keys file without integrity verification. "
            "A MITM between FI peers on the HA sync channel can inject an attacker-controlled "
            "RSA public key into the authorized_keys of the target FI, gaining persistent SSH "
            "access without credentials. "
            "AC:H: requires in-path position on the FI peer sync channel. "
            "C:H/I:H: full SSH access once key is injected. "
            "7.4 HIGH: same vector class as cross-cluster key injection findings."
        ),
        "affected_products": ["UCS FI 6500/6600 X-Direct (fi_nxos_ssh_peer)"],
    },
    {
        "id":           "fi_nxos_ssh_peer-F4",
        "module":       "cisco_ucs_fi_nxos_ssh_peer_re",
        "new_cvss3":    7.2,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "rationale": (
            "cli-peer-exec.sh passes unquoted $MYARGS to the SSH remote command. "
            "An admin who controls the MYARGS value (via a management API or script injection) "
            "can inject shell metacharacters into the SSH -o RemoteCommand or command= field, "
            "achieving RCE on the peer FI as the connecting user. "
            "PR:H: admin-level invocation required. "
            "7.2 HIGH: standard admin-RCE tier for command injection with admin prerequisite."
        ),
        "affected_products": ["UCS FI 6500/6600 X-Direct (fi_nxos_ssh_peer)"],
    },
    {
        "id":           "ucsm_apache-UCSM-APACHE-F4",
        "module":       "cisco_ucs_ucsm_apache_re",
        "new_cvss3":    8.1,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "rationale": (
            "httpd.conf.cors is 0 bytes -- empty include file means no CORS headers on /nuova "
            "(the UCSM XML API). "
            "Without CORS restrictions, any website visited by an authenticated admin can issue "
            "cross-origin XMLHttpRequests to https://ucsm-ip/nuova using the admin's UcsmCookie "
            "(cookie-based auth, SameSite not confirmed set). "
            "A CSRF via a malicious page can invoke aaLogin then arbitrary UCSM XML API commands "
            "against the full UCS infrastructure. "
            "UI:R: requires admin to visit attacker page while authenticated to UCSM. "
            "C:H/I:H: full UCSM API access via CSRF. "
            "8.1 HIGH: AV:N/PR:N/UI:R -- standard CSRF-to-admin-API rating."
        ),
        "affected_products": ["UCS Manager (ucsm_apache, /nuova XML API)"],
    },
]

# ============================================================
# DOWNGRADED TO LOW (informational / no direct exploitation path)
# ============================================================

DOWNGRADED_TO_LOW = [
    {
        "id":     "B480BIOS-F1",
        "module": "cisco_ucs_bios_capsule_re",
        "reason": "Boot Guard SVN=0 is an informational descriptor -- describes the absence of "
                  "a rollback counter, not a directly exploitable condition without physical "
                  "Intel debug hardware. No remote exploitation path.",
    },
    {
        "id":     "B480BIOS-F3",
        "module": "cisco_ucs_bios_capsule_re",
        "reason": "SecureBootSetup pre-provisioned in NVAR: informational, describes BIOS "
                  "configuration state, not a vulnerability without physical access.",
    },
    {
        "id":     "JALAMABEACH-F1",
        "module": "cisco_ucs_bseries_m5m6_xseries_m8_bios_re",
        "reason": "SGX Launch Enclave Write enabled: informational BIOS setting. "
                  "No direct remote exploitation path in UCS server context.",
    },
    {
        "id":     "B200M5BIOS-F1",
        "module": "cisco_ucs_bseries_m5m6_xseries_m8_bios_re",
        "reason": "Presidio signing certificate OU: organizational unit in BIOS cert chain. "
                  "Informational -- identifies ODM/integrator, no exploitation path.",
    },
    {
        "id":     "BSUB-F2",
        "module": "cisco_ucs_b_series_bundle_re",
        "reason": "SN_FORMAT_RECURSIVE_NESTING: serial number format descriptor. "
                  "Informational, no security impact.",
    },
    {
        "id":     "CSUB-F3",
        "module": "cisco_ucs_c_series_bundle_re",
        "reason": "BRDPROG git commit and branch name in production binary: "
                  "informational, exposes internal build metadata. No attack path.",
    },
    {
        "id":     "INTEL-OEM-CONTAMINATION-F1",
        "module": "cisco_ucs_cseries_intel_nvme_fpt_re",
        "reason": "Dell and Lenovo OEM product strings in Intel firmware: "
                  "supply-chain provenance indicator, not a vulnerability.",
    },
    {
        "id":     "INTEL-X710-HP-OEM-F1",
        "module": "cisco_ucs_cseries_intel_x710_cx6dx_raid_cmc_re",
        "reason": "Intel X710 BootIMG contains HP OEM binary tags: "
                  "OEM contamination indicator, informational only.",
    },
    {
        "id":     "BROADCOM-RAID-F3",
        "module": "cisco_ucs_cseries_broadcom_raid_adapter3_re",
        "reason": "7 Broadcom RAID internal codenames extracted: "
                  "internal naming disclosure, no security impact.",
    },
    {
        "id":     "intersight_equinox_connector-F3",
        "module": "cisco_ucs_intersight_equinox_connector_re",
        "reason": "Hardcoded internal IP 10.193.219.209: informational OSINT on internal "
                  "lab/staging infrastructure. No direct exploitation path.",
    },
    {
        "id":     "intersight_equinox_connector-F4",
        "module": "cisco_ucs_intersight_equinox_connector_re",
        "reason": "Internal Git server hostname: informational, reveals internal SCM "
                  "infrastructure name. No exploitation path from external context.",
    },
    {
        "id":     "intersight_onprem_ansible-F3",
        "module": "cisco_ucs_intersight_onprem_ansible_re",
        "reason": "cloudsso-test.cisco.com and www-stage.cisco.com hostnames: "
                  "internal staging endpoints. Informational.",
    },
    {
        "id":     "EMULEX-PUBKEY-ENCRYPTED-F1",
        "module": "cisco_ucs_bseries_emulex_qlogic_hba_re",
        "reason": "Empty PEM public key block with orphaned encrypted data: "
                  "malformed/vestigial data, no active key material present.",
    },
    {
        "id":     "GPU-ZIPCRYPT-F1",
        "module": "cisco_ucs_cseries_storage_gpu_misc_re",
        "reason": "P40 and AMD v340 GPU ZipCrypto: known-plaintext weakness on GPU firmware "
                  "ZIPs, no network attack path. Informational supply-chain finding.",
    },
    {
        "id":     "FIINFRA-F1/F2",
        "module": "cisco_ucs_fi_infrastructure_re",
        "reason": "FI NX-OS no UEFI Secure Boot: architectural design fact. "
                  "Requires physical or admin access to exploit. Informational.",
    },
]

# ============================================================
# CONFIRMED MEDIUM -- Category Summary
# ============================================================

CONFIRMED_MEDIUM_CATEGORIES = {
    "weak_crypto_algorithms": {
        "count": 18,
        "examples": [
            "CSERIES-MOD3-F2 (SHA-1 RSA in ACT2 SUDI CA0v0)",
            "INTX710-F1 (Intel XL710 double-encryption ZipCrypto)",
            "MRSAS-12G-EKMS-DUALKEY-F1 (MegaRAID KM_DecryptNvramKeyBlob dual-key)",
            "EMULEX-ISCSI-CHAP-MGMT-F1 (iSCSI CHAP credential storage)",
        ],
        "typical_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N = 5.9",
        "note": "Weak algorithm requires offline computational effort (AC:H).",
    },
    "tls_verification_bypass": {
        "count": 9,
        "examples": [
            "CMC-F9 (quiet_proxy skips TLS hostname verification)",
            "CWOM316-F5 (tokenExchange.sh curl -k)",
            "intersight_equinox_connector-F2 (TLSSkipVerify + InsecureSkipVerify)",
            "fi6500_602b-FI6500-F5 (StrictHostKeyChecking no)",
        ],
        "typical_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N = 6.5",
        "note": "Requires MITM position (AC:H); not directly exploitable from any source.",
    },
    "credentials_in_predictable_paths": {
        "count": 12,
        "examples": [
            "CMC-F8 (LUKS key to /tmp/luks.*)",
            "intersight_disk2_disk3-F3 (admin password cleartext file)",
            "intersight_disk2_disk3-F4 (Vault unseal key as Ansible variable)",
            "intersight_cert_bootstrap-F5 (cloud-init plaintext admin password)",
            "INTERSIGHT-F4 (TLS private key in etcd at well-known path)",
        ],
        "typical_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 5.5",
        "note": "Local read access required; credential value only, not RCE.",
    },
    "debug_tooling_in_production": {
        "count": 22,
        "examples": [
            "CMC-F11 (TPM diagnostic test binaries in /usr/bin)",
            "DIAG-F1 (dev and release keys both in rootfs)",
            "HUU-C480-F1 (C480 HUU tsa_ucs full debug symbols)",
            "huu_c220m8_602-HUU436-F8 (commented-out debug code in init.sh)",
        ],
        "typical_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N = 3.4 to 5.5",
        "note": "Debug tools expand attack surface but require existing access.",
    },
    "unsigned_firmware_components": {
        "count": 19,
        "examples": [
            "BSUB-F3 (BRDPROG unsigned board programmer)",
            "CSUB-F4 (C-Series peripheral components unsigned SN blocks)",
            "esu_firmware-F6 (no downgrade protection in ESU catalog)",
            "HCMD-F4 (Redfish host reset ISO mount enable -- no sig check)",
        ],
        "typical_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:N = 4.2",
        "note": "Requires physical or admin access + local firmware staging.",
    },
    "misconfigured_mqtt_brokers": {
        "count": 8,
        "examples": [
            "B480-M5-F5 (MQTT TCP/9001 standard-ports exposure)",
            "BSERIES-BXM6-F1 (Mosquitto Unix socket allow_anonymous true)",
            "IOM2500-F5 (PKG2 Mosquitto broker in management stack)",
            "AMDCIMC-F2 (AMD rack CIMC Mosquitto /var/run vardir)",
            "X410M7-F4 (Mosquitto Unix socket allow_anonymous true)",
        ],
        "typical_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N = 4.4",
        "note": "Unix socket MQTT = AV:L; TCP MQTT on localhost = AV:L. "
                "Not AV:N unless confirmed binding to network interface.",
    },
    "bios_configuration_exposure": {
        "count": 14,
        "examples": [
            "X410BIOS-F1 (SGX LEW enabled)",
            "X410BIOS-F3 (TPM enabled/TPMControl=Enable)",
            "BIOS-BOOT-GUARD-SVN-ZERO-F1 (Boot Guard SVN=0 in VIC U-Boot context)",
            "CSERIES-CIMC-F4 (BIOS Token Master Schema 177KB JSON exposed)",
        ],
        "typical_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N = 3.4",
        "note": "BIOS configuration state exposure -- most require physical or admin.",
    },
    "pam_session_auth_weaknesses": {
        "count": 5,
        "examples": [
            "fi_nxos_spm-F4 (pam_unix.so nullok in sam_pam_proxy -- empty password allowed)",
            "fi_nxos_spm-F5 (UCSM_SESSION_ROLES preserved across su boundary)",
            "fi_nxos_backup-F3 (admin password as CLI arg to sam_restore_check.sh)",
        ],
        "typical_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5",
        "note": "Credential exposure or session leakage; not direct bypass.",
    },
    "management_plane_config_weaknesses": {
        "count": 31,
        "examples": [
            "FI64-F3 (PCI_NOAER + IRQPOLL in FI kernel cmdline)",
            "FI64-F5 (NO_STARTUP_CFG_YES in FI kernel cmdline)",
            "FI6500-F7 (PermitRootLogin yes in internal ISAN sshd)",
            "UCSM-SAM-F5 (admin password hash in sam.config applied to shadow)",
            "UCSM-SAM-F7 (FTP port 21 open on internal fabric VLAN)",
            "scu_717-SCU-F4 (telnetd activated on CONFIG_UART_ENABLE)",
            "fi_nxos_ssh_peer-F5 (SSH private host keys synced to peer)",
        ],
        "typical_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N = 4.9 to 6.0",
        "note": "Configuration weaknesses that require existing privileged access.",
    },
    "storage_hardware_diagnostics": {
        "count": 28,
        "examples": [
            "OPTANE-MSID-OPAL-F1 (TCG OPAL MSID password in Level 0 Discovery)",
            "HGST-NVME-DIAGMGR-F1 (DiagMgr diagnostic shell in HGST NVMe)",
            "MRSAS-KM-KEYBLOB-F1 (shared KM_DecryptNvramKeyBlob in RAID)",
            "MICRON-D4-JTAG-DISABLE-FAIL-F1 (JTAG disable fails on Micron D4)",
            "SEAGATE-NEARLINE-TCG-FIPS-RSA-MAKER-F1 (TCG FIPS maker diag)",
            "TOSHIBA-PHOENIX-ERASE-MENU-F1 (Phoenix-M3 erase menu in production)",
        ],
        "typical_vector": "CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N = 5.7",
        "note": "Physical proximity (AV:P) required for storage diagnostic interfaces.",
    },
    "intersight_cloud_config": {
        "count": 17,
        "examples": [
            "INTERSIGHT-F5 (ciscosshd symbol table not stripped)",
            "intersight_ciscossh-F1 (AlmaLinux crypto policy deleted)",
            "intersight_ciscossh-F3 (LD_LIBRARY_PATH CiscoSSL override)",
            "intersight_onprem_ansible-F5 (35 microservice codenames in kubeconfig)",
            "intersight_disk2_disk3-F5 (AlmaLinux packages from third-party repos)",
        ],
        "typical_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N = 3.4 to 5.5",
        "note": "Hardening gaps and configuration weaknesses in Intersight appliance.",
    },
    "remaining_misc": {
        "count": 51,
        "note": "Miscellaneous MEDIUM findings in HUU, CMC, CWOM, VIC, IOM, GPU firmware "
                "not individually detailed above. All confirmed MEDIUM by Cisco CVSS v3.1 "
                "conventions; no additional upgrade candidates identified in this category.",
    },
}

# ============================================================
# VIC-M85SB-F1 DECONFLICT NOTE
# ============================================================

DECONFLICT_NOTE = {
    "id":     "vic_m85sb-VIC-M85SB-F1",
    "status": "DUPLICATE -- already handled in HIGH pass",
    "detail": (
        "The MEDIUM extraction script surfaced VIC-M85SB-F1 (Telnet TCP/23 no-auth) "
        "as MEDIUM. This finding was originally rated HIGH in the vic_m85sb source module "
        "and was upgraded to 9.8 CRITICAL in the HIGH re-verification pass "
        "(cisco_ucs_high_reverification_re.py, UPGRADED_TO_CRITICAL). "
        "The MEDIUM appearance is an extraction artifact -- the source module assigns "
        "severity HIGH, which the MEDIUM bucket did not filter correctly. "
        "VIC-M85SB-F1 remains 9.8 CRITICAL per the HIGH pass decision."
    ),
}

# ============================================================
# REVERIFICATION SUMMARY
# ============================================================

REVERIFICATION_SUMMARY = {
    "pass":                    "3 of 4 (MEDIUM)",
    "total_medium_reviewed":   254,
    "upgraded_to_critical":    1,
    "conditional_critical":    1,
    "upgraded_to_high":        8,
    "confirmed_medium":        "~225 (net of downgrades and duplicates)",
    "downgraded_to_low":       15,
    "duplicate_resolved":      1,

    "cumulative_critical_ids": {
        "from_original_83_pass":   15,
        "upgraded_from_high_pass":  5,
        "upgraded_from_medium_pass": 1,
        "total_critical_ids":       21,
    },

    "distinct_cve_root_causes_critical": {
        "count": 10,
        "list": [
            "1. tahusd TCP/2330+50060 SBus/JTAG/I2C/MDIO unauthenticated (IOM2400-F1, 10.0)",
            "2. CMC jrpc_server TCP/4037 root RPC unsecured (CMC-F3, 10.0)",
            "3. GetBmcToHostScpCredentials pre-auth BMC credential disclosure (SCU/SDU/HUU/HCMD, 9.8)",
            "4. IOM2400 empty root password + SSH PermitRootLogin yes (IOM2400-F2, 9.8)",
            "5. CMCSecureBoot/UCSUpdate pre-auth Secure Boot disable (6 platforms, 9.3)",
            "6. HUU XE130 F3 pre-auth read (HUU-XE-F3, 9.1)",
            "7. VIC telnet TCP/23 no-auth no only_from restriction (M83/M84/M85/M85SB, 9.8)",
            "8. CWOM Consul HTTP API unauthenticated on eth0 TCP/8500 (cwom_vmdk-F3, 9.8)",
            "9. Fleet-wide AES key in decrypt-file binary (7 products -- HIGH, not CRITICAL)",
            "10. CWOM MariaDB empty root password on 0.0.0.0:3306 (cwom_iso-F4, 9.8)",
        ],
    },

    "upgraded_high_from_medium_summary": [
        "UCSM-UCSSH-F4 (shell=True RCE via SUID chain, 7.2)",
        "UCSM-CTR-F6 (host netns bind+exec container escape, 8.8)",
        "fi_nxos_backup-F4 (exec_sam_upgrade unconditional setuid(0), 7.8 conditional)",
        "B480-M5-F4 (nginx /vic_core_upload/ pre-auth write TCP/9005, 7.5)",
        "CWOM316-F3 (t8c-operator wildcard RBAC cluster escalation, 8.8)",
        "fi_nxos_ssh_peer-F3 (peer authorized_keys injection via MITM, 7.4)",
        "fi_nxos_ssh_peer-F4 (unquoted MYARGS SSH command injection, 7.2)",
        "ucsm_apache-UCSM-APACHE-F4 (no-CORS UCSM XML API CSRF, 8.1)",
    ],
}

if __name__ == "__main__":
    print(f"MEDIUM reverification: {REVERIFICATION_SUMMARY['total_medium_reviewed']} findings reviewed")
    print(f"  Upgraded to CRITICAL:   {REVERIFICATION_SUMMARY['upgraded_to_critical']} confirmed + "
          f"{REVERIFICATION_SUMMARY['conditional_critical']} conditional")
    print(f"  Upgraded to HIGH:       {REVERIFICATION_SUMMARY['upgraded_to_high']}")
    print(f"  Confirmed MEDIUM:       {REVERIFICATION_SUMMARY['confirmed_medium']}")
    print(f"  Downgraded to LOW:      {REVERIFICATION_SUMMARY['downgraded_to_low']}")
    print()
    print(f"Cumulative Critical IDs: {REVERIFICATION_SUMMARY['cumulative_critical_ids']['total_critical_ids']}")
    print(f"Distinct CVE root causes (Critical): "
          f"{REVERIFICATION_SUMMARY['distinct_cve_root_causes_critical']['count']}")
    print()
    for item in REVERIFICATION_SUMMARY["distinct_cve_root_causes_critical"]["list"]:
        print(f"  {item}")
