"""
Cisco UCS X215C M8 CIMC 6.0.2 RE module
Target: ucs-x215-m8-cimc.6.0.2.260040.bin (from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Platform: UCS X215C M8 (2-socket AMD EPYC Genoa/Rome, X-Series Compute Node)
Architecture: ARM 32-bit LE, systemd-based Linux

Extraction path:
  Outer bundle gzip at offset 0x354 → 1163MB decompressed stream
  SN entry "ucs-x215-m8-cimc.6.0.2.260040.bin" at decomp+956559872
  GZIP at SN+776 (differs from X410C M7's SN+784)
  → 65MB TAR → ./blob (68549149 bytes)
  Blob magic: 55aa0011 (X-Series family; 55aa0011002080cb vs X410C M7's 55aa0011002080 17)
  Primary SquashFS at blob+29495552 (6179 inodes, 27MB, ARM32 LE gzip)
  Secondary SquashFS at blob+58321152 (760 inodes, 9MB)

Image comparison with X410C M7 (same 6.0.2 build set):
  SquashFS offsets and inode counts: IDENTICAL
  Libjolt modules: 48 modules, IDENTICAL (same size and hash)
  Systemd service set: IDENTICAL (91 services)
  Differing binaries (same size, different content — platform-specific defines):
    cnotify, gpud, isight, mcclient, ntpd, credfish, stressapptest, tpm2, libpython3.10.so.1.0
  Blob header byte 7: 0xcb (X215C M8) vs 0x17 (X410C M7) — hardware type discriminator

Platform difference: X215C M8 uses AMD EPYC Genoa (vs Intel Xeon on X410C M7).
AMD-specific components: amd_bmcpsb.service, amd_addc.service, libcisco_bmcpsb.so,
libpal_amderr.so, libamderr.so — all absent from X410C M7.

Jolt module inventory (48 modules — 2x B480 M5's 23):
  All X410C M7 modules confirmed + same set on X215C M8.
  B480 M5 notable gap: no libjolt_mqtt, libjolt_vmedia, libjolt_gpu, libjolt_sudi,
  libjolt_pldm, libjolt_reach, libjolt_stash, libjolt_techsupport, libjolt_storage (200KB).
  X-Series adds 25 modules over B480 M5 — TCP/4038 attack surface doubled.
"""

FIRMWARE = {
    "target":    "Cisco UCS X215C M8 CIMC 6.0.2",
    "file":      "ucs-x215-m8-cimc.6.0.2.260040.bin",
    "model":     "UCS X215C M8 (2-socket AMD EPYC Genoa/Rome, X-Series Compute Node)",
    "arch":      "ARM 32-bit LE, systemd-based Linux",
    "blob_magic": "55aa0011002080cb (X215C M8; X410C M7 = 55aa0011002080 17)",
    "sqfs_primary_off":  "blob+29495552 (identical to X410C M7)",
    "sqfs_secondary_off": "blob+58321152 (identical to X410C M7)",
    "sqfs_primary_inodes": 6179,
    "sqfs_secondary_inodes": 760,
    "findings":  ["X215M8-F1", "X215M8-F2"],
    "cross_model_confirmations": [
        "X410M7-F1: /cisco/blob/ nginx no limit_except — CONFIRMED IDENTICAL on X215C M8",
        "X410M7-F2: /vic_upload/ 100MB PUT TCP/443 — CONFIRMED IDENTICAL",
        "X410M7-F3: bmc2host-pppd.sh remserial TCP serial via inetd — CONFIRMED IDENTICAL",
        "X410M7-F4: Mosquitto UNIX socket allow_anonymous true — CONFIRMED IDENTICAL",
        "X410M7-F5: live_extract.sh /tmp/live/ fallback unsigned .cpk — CONFIRMED IDENTICAL",
        "B480-M5-F2/F4/F6/F7: credfish/vic_core_upload/hsu_agent/scratchpad — CONFIRMED",
    ],
    "jolt_module_count": 48,
    "jolt_vs_b480m5": "X-Series 48 vs B480 M5 23 modules — credfish TCP/4038 attack surface 2x larger",
    "jolt_new_modules_vs_b480m5": [
        "libjolt_mqtt.so",
        "libjolt_vmedia.so",
        "libjolt_gpu.so",
        "libjolt_sudi.so",
        "libjolt_pldm.so",
        "libjolt_reach.so",
        "libjolt_stash.so",
        "libjolt_techsupport.so",
        "libjolt_storage.so (200KB — largest Jolt module)",
        "libjolt_cisco_opaque.so",
        "libjolt_audit_log.so",
        "libjolt_boot_id.so",
        "libjolt_boot_progress.so",
        "libjolt_cnotify.so",
        "libjolt_cpwm.so",
        "libjolt_dimmbl.so",
        "libjolt_drive_sensors.so",
        "libjolt_host_crash.so",
        "libjolt_hsu_utilities.so",
        "libjolt_hsu_version.so",
        "libjolt_jrpc_redfish.so",
        "libjolt_mailer.so",
        "libjolt_mezz.so",
        "libjolt_network_v2.so",
        "libjolt_node_inventory.so",
        "libjolt_nvfs.so",
        "libjolt_personality.so",
        "libjolt_reach.so",
        "libjolt_set_hif.so",
        "libjolt_ucs_attention.so",
        "libjolt_uem_config.so",
        "libjolt_user_interface.so",
        "libjolt_uspm.so",
        "libjolt_vic_proxy.so",
    ],
    "amd_specific_binaries": [
        "/usr/local/bin/amd_bmcpsb (ARM32 pie, libcisco_bmcpsb.so, libsystemsecure.so)",
        "/usr/local/bin/amd_addc (ARM32 pie, esmi_oob_cpuid, libjolt_inf.so)",
        "/usr/local/lib/libcisco_bmcpsb.so",
        "/usr/local/lib/libpal_amderr.so",
        "/usr/local/lib/libamderr.so",
    ],
}

# X215M8-F1: AMD PSB dev key bypass path via CIMC flash environment
X215M8_F1 = {
    "id":       "X215M8-F1",
    "title":    "libcisco_bmcpsb.so exports cs_rommon_platform_allow_dev_keys — AMD Platform "
                "Secure Boot dev key bypass path; dev public key at "
                "/mnt/emmc/bmc_nv/security/dev_keys/M7_BIOS_AMD_PSB_DEV_PublicKey.bin; "
                "CIMC flash environment (get_cimc_env_offset/get_cimc_env_size) controls "
                "whether dev key path is activated; amd_bmcpsb writes psb_status via "
                "/proc/cisco/psb_status; /dev/mem and /dev/crypto access from BMC ARM",
    "severity": "HIGH",
    "status":   "CONFIRMED — libcisco_bmcpsb.so extracted from primary SquashFS; "
                "cs_rommon_platform_allow_dev_keys and cs_rommon_platform_get_dev_image_load_status "
                "symbols confirmed; dev key path /mnt/emmc/bmc_nv/security/dev_keys/ confirmed; "
                "amd_bmcpsb binary references /dev/mem, /dev/crypto, /proc/cisco/psb_status",
    "cwe":      ["CWE-295 (Improper Certificate Validation)",
                 "CWE-327 (Use of Broken or Risky Cryptographic Algorithm)"],
    "libcisco_bmcpsb_strings": [
        "cs_rommon_platform_allow_dev_keys",
        "cs_rommon_platform_get_dev_image_load_status",
        "cs_rommon_verify_key_file",
        "get_cimc_env_offset",
        "get_cimc_env_size",
        "bios_key_backup",
        "bios_key_primary",
        "/mnt/emmc/bmc_nv/security/dev_keys/M7_BIOS_AMD_PSB_DEV_PublicKey.bin",
        "/etc/M7_BIOS_AMD_PSB_REL_PublicKey.bin",
        "/var/bios_images/active_image_index",
        "/var/bios_images/update_status",
        "/dev/crypto",
        "/dev/mem",
    ],
    "amd_bmcpsb_key_strings": [
        "%s:%d:Validate_bios_partition: Openssl DEV Key Verify of RTM_L1 Failed %d %d",
        "%s:%d:For Dev Image of BIOS, Copy Dev Public Key at /etc/",
        "%s:%d:Validate_bios_partition: Check 16MB BIOS Image in flash SUCCESS",
        "echo 0 > /proc/cisco/psb_status",
        "echo 1 > /proc/cisco/psb_status",
        "/proc/nuova/watchdog_reset",
        "/sbin/modprobe unified_spi_map_host_driver.ko",
        "/proc/mtd",
    ],
    "dev_key_bypass_path": (
        "1. Place M7_BIOS_AMD_PSB_DEV_PublicKey.bin in /mnt/emmc/bmc_nv/security/dev_keys/ "
        "(requires write to eMMC NV storage — achievable via /vic_upload/ PUT endpoint or "
        "live_extract.sh .cpk deployment). "
        "2. cs_rommon_platform_allow_dev_keys returns true if CIMC flash environment encodes "
        "dev mode (get_cimc_env_offset/get_cimc_env_size parse flash). "
        "3. amd_bmcpsb validates BIOS with dev key instead of production release key, "
        "allowing unsigned/self-signed BIOS to pass PSB check. "
        "4. BMC asserts psb_status=1 (pass) via /proc/cisco/psb_status, "
        "host boots unsigned firmware."
    ),
    "note": "X215C M8 is AMD EPYC Genoa platform — AMD PSB is the hardware root of trust. "
            "The dev key path is present in production firmware with 'Development images not "
            "supported' / 'Development images cannot be loaded' error strings suggesting the "
            "activation gate IS checked. The attack chain requires both writing to eMMC NV "
            "AND triggering the CIMC environment flash entry — not one-shot from network alone. "
            "CIMC env flash access via /vic_upload/ or live_extract.sh post_link.sh hook.",
}

# X215M8-F2: amd_addc AMD RAS OOB configuration via Jolt framework — CPU error threshold control
X215M8_F2 = {
    "id":       "X215M8-F2",
    "title":    "amd_addc daemon (ARM32) calls jolti_method_invoke on libjolt_inf.so to read "
                "and WRITE AMD EPYC RAS (Reliability/Availability/Serviceability) OOB configuration: "
                "set_bmc_ras_oob_config, set_bmc_ras_err_threshold, clear_sbrmi_ras_status; "
                "reads PPIN fuse (Protected Processor ID) and CPUID via AMD eSMI OOB interface; "
                "if Jolt method invoke is reachable from credfish TCP/4038, AMD CPU error "
                "thresholds and RAS collection behavior are configurable from the network",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — amd_addc binary extracted from primary SquashFS; "
                "jolti_init + jolti_method_invoke + libjolt_inf.so string confirmed; "
                "all esmi_oob_* and ras_* function symbols confirmed in binary; "
                "amd_addc.service ExecStart=/usr/local/bin/amd_addc (no pre/post auth)",
    "cwe":      ["CWE-668 (Exposure of Resource to Wrong Sphere)",
                 "CWE-284 (Improper Access Control)"],
    "amd_addc_strings": [
        "esmi_oob_cpuid",
        "esmi_get_processor_info",
        "read_ppin_fuse",
        "read_ucode_revision",
        "read_ras_df_err_validity_check",
        "read_ras_df_err_dump",
        "read_bmc_ras_mca_msr_dump",
        "read_bmc_ras_mca_validity_check",
        "read_sbrmi_ras_status",
        "clear_sbrmi_ras_status",
        "get_bmc_ras_run_time_error_info",
        "get_bmc_ras_oob_config",
        "set_bmc_ras_oob_config",
        "set_bmc_ras_err_threshold",
        "pal_amd_addc_config",
        "pal_amd_addc_get",
        "pal_get_addc_recovery_mechanism",
        "jolti_init",
        "jolti_method_invoke",
        "libjolt_inf.so",
    ],
    "note": "amd_addc acts as a Jolt CLIENT — it calls jolti_method_invoke to expose AMD CPU "
            "RAS data and configuration through the Jolt framework. If credfish TCP/4038 routes "
            "JRPC calls into libjolt_inf.so which proxies to amd_addc, then AMD EPYC RAS "
            "configuration (error thresholds, OOB behavior, RAS status clearing) is reachable "
            "from the management network via credfish without direct AMD eSMI OOB credentials. "
            "read_ppin_fuse gives the Protected Processor ID — a hardware unique identifier "
            "that should not be externally readable; its exposure constitutes a hardware "
            "fingerprinting primitive.",
}

FINDINGS = [X215M8_F1, X215M8_F2]
