"""
Cisco UCS Intel Blade M8 CIMC 6.0.2 RE module (FULL BLOB EXTRACTION)
Target: ucs-intel-blade-m8-cimc.6.0.2.260040.bin (from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Platform: Intel Blade M8 (Granite Rapids / Xeon 6, Godfather platform); ARM 32-bit LE; systemd-based
Architecture: ARM 32-bit LE, AST2600 BMC, systemd-based Linux

Extraction path:
  Outer bundle gzip at offset 0x354 → 1163MB decompressed stream
  SN entry "ucs-intel-blade-m8-cimc.6.0.2.260040.bin" at decomp+1016347648
  hsize: 50593792 (BIG ENDIAN — vs X-Series which uses LE; raw LE read gives wrong 1027)
  GZIP at SN+772 (wbits=47 auto-detect required; wbits=-15 yields 0 bytes — different from X-Series)
  → 85.5MB TAR (larger than X-Series 65MB)
  → ./blob (89655248 bytes = 85.5MB)
  Blob magic: 55aa000e801b80c2 (new family — B-Series = 55aa0007, X-Series = 55aa0011)
  Primary SquashFS at blob+31002240 (bytes_used=48421274 = 46.2MB, gzip compression)
  Secondary SquashFS at blob+79427200 (bytes_used=10077886 = ~9.6MB)

NOTE: This supersedes the prior cisco_ucs_bseries_intelm8_cimc_602b_re.py module which was
written from "plugin_img" extraction without the actual CIMC blob. Prior module findings
(BSERIES-M8-F1/F2/F3) are verified and enriched here. New findings added: M8-F4 through M8-F6.

Extraction diff vs X-Series:
  - hsize field is Big Endian (X-Series was LE)
  - GZIP wbits=47 required (X-Series: wbits=-15 worked)
  - Blob magic: 55aa000e (new, neither B-Series 0007 nor X-Series 0011)
  - SquashFS offsets different from X-Series (blob+31002240 vs blob+29495552)
  - Primary SquashFS 46.2MB vs 27MB for X-Series (Intel M8 has 2x the rootfs size)

Jolt module inventory (54 modules — 6 more than X-Series 48):
  All X-Series modules present PLUS:
  libjolt_hsu_agent.so, libjolt_intersight.so, libjolt_ipmi.so,
  libjolt_priv.so, libjolt_rsyslog.so, libjolt_sess_mgr.so,
  libjolt_sw_update.so, libjolt_trim.so, libjolt_util.so

Cross-platform anomaly: apml_tool binary present in Intel M8 CIMC
  apml_tool contains AMD EPYC APML/SB-RMI functions (esmi_oob, sbrmi, clear_sbrmi_ras_status)
  These are AMD-specific and serve no functional purpose on Granite Rapids Intel hardware.
  Also present: aries_* (Astera Labs PCIe 5.0 retimer tools) confirming Intel host platform.
"""

FIRMWARE = {
    "target":    "Cisco UCS Intel Blade M8 CIMC 6.0.2",
    "file":      "ucs-intel-blade-m8-cimc.6.0.2.260040.bin",
    "model":     "Intel Blade M8 (Granite Rapids / Xeon 6, Godfather platform)",
    "arch":      "ARM 32-bit LE, AST2600 BMC, systemd-based Linux",
    "blob_magic": "55aa000e801b80c2 (new family; B-Series=55aa0007, X-Series=55aa0011)",
    "sqfs_primary_off":  "blob+31002240",
    "sqfs_secondary_off": "blob+79427200",
    "sqfs_primary_size_mb": 46.2,
    "sqfs_secondary_size_mb": 9.6,
    "findings":  ["M8-F1", "M8-F2", "M8-F3", "M8-F4", "M8-F5", "M8-F6"],
    "cross_model_confirmations": [
        "X410M7-F1: /cisco/blob/ nginx no limit_except — CONFIRMED on Intel M8",
        "X410M7-F2: /vic_upload/ 100MB PUT TCP/443 — CONFIRMED",
        "X410M7-F4: Mosquitto UNIX socket allow_anonymous — CONFIRMED",
        "X410M7-F5: live_extract.sh /tmp/live/ fallback unsigned .cpk — CONFIRMED",
        "B480-M5-F2: credfish TCP/4038 JRPC (JRPC_SERVER_PORT in firewall) — CONFIRMED",
        "B480-M5-F7: /nv/scratchpad/ nginx autoindex — CONFIRMED",
    ],
    "jolt_module_count": 54,
    "jolt_vs_xseries": "Intel M8 54 vs X-Series 48 — 6 additional modules expand credfish attack surface",
    "jolt_intel_m8_additions": [
        "libjolt_hsu_agent.so",
        "libjolt_intersight.so",
        "libjolt_ipmi.so",
        "libjolt_priv.so (jolti_check_privilege_and_audit — privilege enforcement layer)",
        "libjolt_rsyslog.so",
        "libjolt_sess_mgr.so (__jolt_session_get, __jolt_session_delete)",
        "libjolt_sw_update.so (remote URL firmware update)",
        "libjolt_trim.so",
        "libjolt_util.so",
    ],
    "host_platform_tools": [
        "aries_direct_eeprom, aries_eeprom, aries_fw_update, aries_link_logs, "
        "aries_link_monitor, aries_margin_test, aries_prbs, aries_retimer_link_capture, aries_test "
        "(Astera Labs PCIe 5.0 retimer tools — confirms Granite Rapids Intel host)",
        "pirom (Intel Processor Information ROM reader over I2C — caches to /nv/etc/cpu0_info)",
    ],
    "cross_platform_anomaly": (
        "apml_tool (AMD APML/SB-RMI binary: esmi_oob, sbrmi, clear_sbrmi_ras_status) present "
        "in Intel M8 CIMC firmware. AMD-specific interfaces nonfunctional on Granite Rapids "
        "but binary is deployed in production image — firmware build cross-contamination."
    ),
}

# M8-F1: Boot Guard enforcement disabled unconditionally — verbatim platform_last script
M8_F1 = {
    "id":       "M8-F1",
    "title":    "platform_last.init.d script unconditionally writes 0 to "
                "/proc/cisco/bootguard_enabled_cpu on every Granite Rapids M8 boot; "
                "CPU CPUID threshold check for Boot Guard support (CPUID_DEC < 1778 threshold "
                "for Granite Rapids BtG) is fully commented out with TODO_M8 markers; "
                "BMC disables its own Boot Guard enforcement gate before host powers on",
    "severity": "HIGH",
    "status":   "CONFIRMED — /etc/init.d/platform_last extracted from primary SquashFS; "
                "echo 0 > /proc/cisco/bootguard_enabled_cpu unconditional; "
                "TODO_M8 comments confirm known-incomplete implementation in production",
    "cwe":      ["CWE-693 (Protection Mechanism Failure)"],
    "verbatim_platform_last": """
check_host_cpu_type() {
    ...
    if [[ $CPU_NAME == "graniterapids" ]]
    then
        # TODO_M8: Need to understand how this needs to work with new BtG scheme
        /usr/bin/logger -t $title -p user.notice "Granite Rapids CPU detected"
        # Min supported Granite Rapids CPUID for BtG is 0xdXXX? (???? decimal)
        #if [ $CPUID_DEC -lt 1778 ]
        #then
        #    echo 0 > /proc/cisco/bootguard_enabled_cpu
        #else
        #    echo ""   # leaving FD0V GPIO host power gate in place
        #fi
    fi
}
start)
    # TODO_M8: Update! For now, just disable the BtG enabled CPU so that the driver
    # doesn't check/gate host power on
    /usr/bin/logger -t $title "Overriding the FD0V GPIO host power gate until we figure
                               out what to do with this"
    echo 0 > /proc/cisco/bootguard_enabled_cpu""",
    "note": "The CPU CPUID threshold check was present in the M7 generation and gated whether "
            "non-BtG CPUs needed the override. In M8, the entire conditional block is commented "
            "out and replaced with an unconditional override. MMSP manifests elsewhere in the "
            "bundle reference 'REL signed BtG Enabled BIOS' as the intended target, confirming "
            "Boot Guard was intended to be enforced on this platform.",
}

# M8-F2: mcserver TCP/4010 — capabilities include BIOS token write and remote power ops
M8_F2 = {
    "id":       "M8-F2",
    "title":    "mcserver (TCP/4010, all interfaces via firewall 'enable-ucsm-mctools') handles "
                "BIOS token write, UCSM cert operations, show-techsupport with -ip/-path args, "
                "and host power ops; JRPC_SERVER_PORT=4038 (credfish) co-exists; "
                "mcserver references /var/pam-localuser-disable sentinel — file creation disables "
                "PAM local-user auth for IPMI (mcserver_cfg_pam_ipmi_user_access)",
    "severity": "HIGH",
    "status":   "CONFIRMED — mcserver binary (465KB) at /usr/local/bin/mcserver; "
                "MCTOOLS_PORT=4010 in firewall.sh opened on all interfaces via enable-ucsm-mctools; "
                "/var/pam-localuser-disable path confirmed in binary strings; "
                "sess_mgr_session_get integration found (session-based, auth details require live probe)",
    "cwe":      ["CWE-284 (Improper Access Control)", "CWE-668 (Exposure of Resource to Wrong Sphere)"],
    "mcserver_capabilities": [
        "set_ucsm_bios_tokens — writes BIOS tokens from UCSM-controlled config at "
        "/nv/etc/BIOS/bt/BiosToken/<UUID>-3-ServiceProfileName",
        "bios_password_clear",
        "__jolt_ucsm_del_cert",
        "kvm_rpc_kill_session",
        "mcserver_cfg_pam_ipmi_user_access — creates /var/pam-localuser-disable to bypass PAM",
        "showTechSupport.sh -ip %s -path %s — IP and path from network input, no sanitization seen",
    ],
    "showtechsupport_call": (
        "mcserver calls showTechSupport.sh with -ip and -path arguments taken from TCP/4010 "
        "protocol input. showTechSupport.sh builds workDir at /mnt/scratchpad/techsupport_pid$$, "
        "tarballs /nv/ content (logs, BIOS tokens, audit dir, redfish task repo) to "
        "/var/nuova/BIOS/techsupport.tgz and SFTPs to the -ip/-path target. "
        "If -ip or -path values are unsanitized in mcserver's format string expansion, "
        "injection into showTechSupport.sh is possible — CANDIDATE pending live probe."
    ),
}

# M8-F3: jrpc_server on 4037 — referenced in prior module; credfish on 4038 confirmed here
M8_F3 = {
    "id":       "M8-F3",
    "title":    "credfish Jolt JRPC daemon on TCP/4038 (labeled JRPC_SERVER_PORT in firewall); "
                "prior plugin_img extraction referenced jrpc_server on TCP/4037 loopback — "
                "NOT confirmed in this full blob extraction; credfish on 4038 confirmed with "
                "54 libjolt modules; no separate jrpc_server service or binary found",
    "severity": "HIGH",
    "status":   "UPDATED — TCP/4038 credfish confirmed (JRPC_SERVER_PORT in firewall.sh); "
                "TCP/4037 jrpc_server from prior module NOT found in this blob; "
                "credfish.service confirmed active with 54 libjolt module plugins",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "note": "The prior BSERIES-M8-F3 finding about jrpc_server TCP6/4037 loopback from "
            "plugin_img extraction is not confirmed in this full blob. May be a version "
            "difference or the plugin_img source was from a different firmware revision. "
            "credfish on 4038 is the primary JRPC surface on this 6.0.2 CIMC.",
}

# M8-F4: libjolt_sw_update.so remote URL firmware update — network-initiated BIOS/BMC update
M8_F4 = {
    "id":       "M8-F4",
    "title":    "libjolt_sw_update.so exports __jolt_start_sw_download_and_update accepting "
                "remote URL (yuarel_parse, valid_remote_protocol, valid_hostname_or_ip, "
                "valid_ipv6_address); authenticated credfish/Jolt JRPC caller can initiate "
                "BIOS update (start_bios_update), BMC update (start_bmc_update), and "
                "set_live_sw_update from a remote download URL without secondary authorization; "
                "set_bios_active_index and set_bmc_active_index allow active image flip via JRPC",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — libjolt_sw_update.so extracted from primary SquashFS; "
                "all function symbols confirmed (yuarel_parse, valid_remote_protocol, "
                "__jolt_start_sw_download_and_update, __jolt_set_live_sw_update, "
                "__jolt_sw_update_set_active_image, __jolt_get_catalog_from_signed_img, "
                "__jolt_verify_upd_img_features_v2); present in Intel M8 only (absent X-Series)",
    "cwe":      ["CWE-494 (Download of Code Without Integrity Check — candidate; signed image "
                 "verification present via __jolt_verify_upd_img_features_v2 but requires live "
                 "confirmation that signature is validated before execution)"],
    "libjolt_sw_update_functions": [
        "start_bmc_update / get_bmc_update_status / get_bmc_update_progress",
        "start_bios_update / get_bios_update_status / get_bios_update_progress",
        "set_bios_active_index / set_bmc_active_index",
        "__jolt_start_sw_download_and_update (remote URL, yuarel_parse, valid_remote_protocol)",
        "__jolt_set_live_sw_update",
        "__jolt_sw_update_set_active_image",
        "__jolt_get_catalog_from_signed_img",
        "__jolt_verify_upd_img_features_v2 (signature verification — confirm path is mandatory)",
        "start_catalog_update / delete_catalog_update",
        "system / popen / system_exec_command_devnull_background",
    ],
    "note": "Intel M8 is the only CIMC variant with libjolt_sw_update.so in this bundle. "
            "X-Series and B480 M5 do not have this module. The module includes "
            "__jolt_verify_upd_img_features_v2 which suggests signature verification, "
            "but the 'system' and 'popen' direct execution paths are also present. "
            "Live probe required to confirm whether __jolt_verify_upd_img_features_v2 "
            "is called in the __jolt_start_sw_download_and_update code path.",
}

# M8-F5: install-connector-early.sh eval $1 — cloud connector update command injection
M8_F5 = {
    "id":       "M8-F5",
    "title":    "install-connector-early.sh EXECUTE() function uses 'eval $1' (unquoted); "
                "called as EXECUTE \"nice $FLASHCP -v -X -o $OFFSET,$SIZE $1 $selected_mtd\" "
                "where $1 is the script's first argument (cloud connector image path); "
                "if $1 contains shell metacharacters (e.g., path with '; cmd'), eval executes "
                "injected commands as root; activation path: libjolt_priv.so "
                "update_dc_firmware_remote → install-connector-early.sh",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — /nuova/bin/install-connector-early.sh extracted; "
                "EXECUTE() uses eval $1 at line 11; called at line 377 with expanded $1 arg; "
                "update_dc_firmware_remote string in libjolt_priv.so; "
                "same vulnerability class as install-connector.sh eval $1 (X410C M7 note)",
    "cwe":      ["CWE-78 (Improper Neutralization of Special Elements used in an OS Command)"],
    "verbatim_execute": """
EXECUTE() {
  if [ -e /etc/install.debug ]; then
    LOGGER "$1"
  else
    eval $1      # $1 is the full command string, expanded before EXECUTE() call
  fi
  return $?
}
...
SIZE=`cat $1 | wc -c`         # $1 = script argument (cloud connector image path)
LOGGER "Installing $1 to $selected_mtd"
EXECUTE "nice $FLASHCP -v -X -o $OFFSET,$SIZE $1 $selected_mtd"  # eval on expanded string""",
    "note": "The /etc/install.debug file causes EXECUTE to log-only instead of eval — "
            "this is the debug bypass path. Production systems should not have this file. "
            "The cloud connector image path ($1) is set by the caller of install-connector-early.sh "
            "and originates from the Andromeda cloud connector update flow (update_dc_firmware_remote). "
            "If the download destination path is attacker-controlled (e.g., via JRPC "
            "__jolt_start_sw_download_and_update specifying a crafted URL with semicolons "
            "that influence the local save path), injection is achievable from the network.",
}

# M8-F6: libjolt_priv.so privilege bypass risk — jolti_check_privilege_and_audit non-enforcement
M8_F6 = {
    "id":       "M8-F6",
    "title":    "libjolt_priv.so jolti_check_privilege_and_audit uses /nv/etc/device-connector/"
                "intersight-mode to determine platform privilege context; "
                "KMIP cert management operations (set_ipmi_key, kmip_client_cert_exits, "
                "kmip_root_ca_cert_exists, kmip_client_cert_download_status), SPDM cert "
                "operations (get_spdm_certificate, get_spdm_certificate_chain, "
                "get_mctp_cert_upload_status), and system-level ops (reboot_cimc, "
                "update_dc_firmware_remote) are listed in privilege config — "
                "privilege enforcement depends on jolti_check_privilege_and_audit "
                "which reads Intersight mode from writable NV path",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — libjolt_priv.so extracted from primary SquashFS; "
                "all operation names, /nv/etc/device-connector/intersight-mode path, "
                "and jolti_check_privilege_and_audit confirmed in binary strings; "
                "libpal_platform_bit_map.so dependency for platform privilege read",
    "cwe":      ["CWE-284 (Improper Access Control)"],
    "privilege_controlled_operations": [
        "reboot_cimc",
        "update_dc_firmware_remote",
        "set_ipmi_key",
        "kmip_client_cert_exits / kmip_client_private_cert_exists",
        "kmip_root_ca_cert_exists / kmip_root_ca_cert_download_status / export_status",
        "get_spdm_certificate / get_spdm_certificate_chain / get_spdm_certificate_collection",
        "get_mctp_cert_upload_status",
        "kmip_client_cert_download_status / kmip_client_cert_export_status",
    ],
    "note": "The privilege level check reads from /nv/etc/device-connector/intersight-mode "
            "to determine whether Intersight or local management context applies. If this NV "
            "path is writable (e.g., via /vic_upload/ PUT endpoint or live_extract.sh .cpk hook), "
            "the platform privilege context can be altered. The privilege check error paths "
            "log 'platform privilege get failed' and 'Invalid mask for the current platform' "
            "without clear indication of whether failure defaults to permit or deny.",
}

FINDINGS = [M8_F1, M8_F2, M8_F3, M8_F4, M8_F5, M8_F6]
