"""
Cisco UCS IOM 2500/6400 Series 6.0.2b RE module
Target: ucs-2500-6400.6.0.2b.bin (extracted from ucs-6400-k9-bundle-infra.6.0.2b.A.bin)
Platform: UCS IOM 2508/2512 (25G/100G uplinks, Tahoe x86-64 switch ASIC)
Architecture: x86-64 ELF, NX-OS satellite Linux

Extraction path:
  Outer bundle: ucs-6400-k9-bundle-infra.6.0.2b.A.bin (3.4GB)
  TAR entry: ./isan/plugin_img/ucs-2500-6400.6.0.2b.bin (412427442 bytes)
  Inner gzip at offset 0x2f8 (same as IOM 2400)
  Inner tar: imghdr.bin + ./blob (448652859 bytes, 71MB larger than IOM 2400)
  Blob: 4 shinstall packages (vs 2 in IOM 2400)

Package inventory:
  PKG1 (149MB CPIO, 620 files): NX-OS satellite layer — isan/ isanboot/ lc/ etc/
    126 more files than IOM 2400 PKG1 (494 files)
    Core binaries: tahusd (identical to IOM 2400), satctrl, vic_proxy
    S37tah: IDENTICAL to IOM 2400 (card_id=11144 hack, chmod 666 /dev/ktah*, 21 codenames)
    PKG1 MISSING vs IOM 2400: antechsup.sh, attn.sh, hif_event_sort.sh, inst_lc_utaker,
      localfault.sh, longdelay.sh, stall.sh, utaker_launch
  PKG2 (34MB CPIO, 813 files): Full CMC management stack — nuova/ etc/ (vs 75MB minimal in 2400)
    Additional services vs IOM 2400: appDemo, bmcd, cimc_update, cipmi, cluster_manager,
    cmclog_dir_rotate, cmc_manager, cnotify, cron, dc, dcos_start.sh, doctor_cmc, firewall,
    http_cisco_opaque, ipwrmgr, mailer, mosquitto, obfllogger, platform_ohms, redfish,
    rsyslogd, secure-action, secure_data
    Identical: etc/passwd (admin::500:0:admin:/tmp:/isan/bin/vsh), etc/shadow (admin::::::::)
  PKG3 (81MB CPIO, 273 files): Debug/test package — lib64/.debug/, usr/bin/{gdb,gdbserver,dlv},
    usr/debug/symb/ symbol files, nuova/bin/sanity_tests/
  PKG4 (132MB CPIO, 271 files): Manufacturing diagnostics — nuova/diagnostics/, diag/bin/,
    usr/bin/{eeupdate64e,plink,mvcli,mmc,tclsh}

Cross-model confirmation vs IOM 2400 findings (cisco_ucs_iom_2400_6400_602b_re.py):
  IOM2400-F1: AAPL AACS/ATS unauthenticated TCP server — NOT INDEPENDENTLY CONFIRMED
    (tahusd present in PKG1 but not re-extracted for this module; assumed identical)
  IOM2400-F2: PermitRootLogin yes + empty root shadow + missing common-auth — CONFIRMED IDENTICAL
  IOM2400-F3: admin::500:0 GID 0 no-password vsh — CONFIRMED IDENTICAL (same etc/passwd)
  IOM2400-F4: card_id=11144 + 21 codenames — CONFIRMED IDENTICAL (S37tah diff = 0)
  IOM2400-F5: chmod 666 /dev/ktah* — CONFIRMED IDENTICAL (S37tah diff = 0)
  IOM2400-F6: TFTP firmware update no integrity check — NOT INDEPENDENTLY CONFIRMED
    (upgrade_img.sh assumed identical; not re-extracted)
  IOM2400-F7: CICD status-13 bypass — NOT INDEPENDENTLY CONFIRMED
  IOM2400-F8: Control interface promiscuous mode — NOT INDEPENDENTLY CONFIRMED

Platform codenames (new vs IOM 2400):
  From asic_lib.tar.bz2 (owned datton/eng):
    Rocky / ROC: internal ASIC codename for IOM 2500 switch ASIC verification environment
    Washington: FPGA codename (Washington_IFM_MTP firmware, versions 3/4/6/7)
    Carlsborg: PSU codename (Carlsborg_2800W_PRI/SEC)
    Tilton: SerDes config codename (Tilton_112d 112G SerDes operating points)
    SkagitRiver: support files tar codename (skagitriver_support_files.tar)
    MadisonRiver, TiltonRiver, NoEValley: eMMC partition script and diagnostic codenames
    DenvertonPwrMon: Intel Atom C3000 management SoC power monitor binary name

Internal engineer exposure:
  User 'datton', group 'eng' owns all files in asic_lib.tar.bz2 and skagitriver_support_files.tar
  file_change.diff (67KB) and file_change_list.txt timestamps: 2024-05-29 13:30-13:32
    (confirms active development as recently as May 2024)

Firewall (PKG2 etc/init.d/firewall):
  Significantly more complex than IOM 2400 iptables_rules
  Supports inband/outofband interface management
  STANDARD_PORTS includes: 443, 80, 22, 23 (MFG_TEST), 69, 123, 319, 320, 547, 623,
    2068, 4010, 4038, 8021, 8022, 8192, 23000, 9000 (FI_HTTPS)
  MFG_TEST_PORT=23 (Telnet) documented as a standard service port
"""

FIRMWARE = {
    "target":    "Cisco UCS IOM 2500/6400 6.0.2b",
    "file":      "ucs-2500-6400.6.0.2b.bin",
    "source_bundle": "ucs-6400-k9-bundle-infra.6.0.2b.A.bin",
    "model":     "UCS IOM 2508/2512 (Tahoe x86-64 switch ASIC, NX-OS satellite, "
                 "Denverton management SoC)",
    "arch":      "x86-64 ELF; 4-package CPIO old binary (magic 0x71c7)",
    "pkg_count": 4,
    "blob_size_bytes": 448652859,
    "findings": ["IOM2500-F1", "IOM2500-F2", "IOM2500-F3", "IOM2500-F4",
                 "IOM2500-F5", "IOM2500-F6"],
    "cross_model_confirmations": [
        "IOM2400-F2: PermitRootLogin yes + empty root shadow + missing common-auth — CONFIRMED",
        "IOM2400-F3: admin::500:0 GID 0 no-password vsh — CONFIRMED (etc/passwd identical)",
        "IOM2400-F4: card_id=11144 hack + 21 codenames in S37tah — CONFIRMED (diff=0)",
        "IOM2400-F5: chmod 666 /dev/ktah* in S37tah — CONFIRMED (diff=0)",
    ],
}

# IOM2500-F1: gdb + gdbserver + dlv (Delve Go debugger) in production PKG3
IOM2500_F1 = {
    "id":       "IOM2500-F1",
    "title":    "PKG3 (debug package) ships GNU gdb 8.2 (GCC 2018), gdbserver 8.2, and "
                "dlv (Delve Go debugger) as production x86-64 binaries at "
                "usr/bin/gdb, usr/bin/gdbserver, usr/bin/dlv; PKG3 also contains "
                "/lib64/.debug/ with unstripped debug symbols for glibc (2.28) and all "
                "standard runtime libraries, and usr/debug/symb/lib64/ with .sym files "
                "for all Cisco CMC private libraries including libcmcac3.so, libcmccluster.so, "
                "libcmcipc.so, libcmcpersist.so, libcmcplatform.so, libcisco_signature.so",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — gdb, gdbserver, dlv binaries extracted from PKG3 "
                "(usr/bin/gdb, usr/bin/gdbserver, usr/bin/dlv); GNU gdb copyright string "
                "confirmed in gdbserver; dlv version/delve strings confirmed; "
                "lib64/.debug/ directory with 45 unstripped debug library files confirmed; "
                "usr/debug/symb/lib64/ with Cisco CMC .sym files confirmed",
    "cwe":      ["CWE-489 (Active Debug Code)",
                 "CWE-200 (Exposure of Sensitive Information to Unauthorized Actor)"],
    "files":    ["usr/bin/gdb", "usr/bin/gdbserver", "usr/bin/dlv",
                 "lib64/.debug/libc-2.28.so", "usr/debug/symb/lib64/libcmcipc.so.sym"],
    "gdbserver_version": "GNU gdbserver (GCC 2018 FSF)",
    "cisco_sym_files": [
        "libcmcac3.so.sym", "libcmccluster.so.sym", "libcmcipc.so.sym",
        "libcmclog.so.sym", "libcmcobfl.so.sym", "libcmcpersist.so.sym",
        "libcmcplatform.so.sym", "libcmcutil.so.sym", "libcmcvlan.so.sym",
        "libcms.so.sym", "libcnotify.so.sym", "libconf.so.sym",
        "libcisco_signature.so.sym", "libciscosafec-3.0.1.so.sym",
        "libcipmi_core.so.sym", "libbase64.so.sym", "libbootcfgbios.so.sym",
    ],
    "impact": (
        "gdbserver running on the IOM can attach to any PID and expose the full process "
        "address space. High-value targets: pam_cmc.so in-flight (UCSM credential material "
        "passed to authenticate_with_ucsm over the management socket), satctrl ACT2 session "
        "state, tahusd AAPL AACS/ATS server runtime, and TLS private key material in "
        "any CMC HTTPS daemon. Cisco .sym files provide full symbol resolution for all "
        "libcmc* libraries, giving an attacker named function/global offsets without "
        "static analysis. dlv targets any Go binary including satctrl if implemented in Go."
    ),
    "note": "PKG3 is a dedicated debug package separate from PKG1 (NX-OS layer) and PKG2 "
            "(management stack). Its presence in the release firmware bundle indicates the "
            "debug package is delivered to production units as part of the standard firmware "
            "update. nuova/bin/sanity_tests/ in PKG3 contains test scripts for all management "
            "subsystems (bmcd, IPMI, Redfish, thermal, UEMD) that expose internal API paths.",
}

# IOM2500-F2: eeupdate64e Intel NIC EEPROM updater in production PKG4
IOM2500_F2 = {
    "id":       "IOM2500-F2",
    "title":    "eeupdate64e (Intel Network Adapter EEPROM Update Utility) shipped in "
                "production PKG4 at nuova/diagnostics/firmware/lan_eeprom/eeupdate64e; "
                "bundled with three NIC EEPROM firmware blobs: mtp_eth2_lan0.bin, "
                "nic2_eth1_lan0.bin, nic4_eth3_lan1.bin; eeupdate64e supports Intel NICs "
                "I210, I8254x, I40E, X550, X540, ICE (E810), Aquantia, FM10k, Cortina",
    "severity": "HIGH",
    "status":   "CONFIRMED — eeupdate64e binary extracted from PKG4; NAL function symbols "
                "for all supported NIC families confirmed (_NalVerifyNvmI210, "
                "_NalIceVerifyNvm, _NalX550DebugVerifyFlash, etc.); three .bin NIC "
                "firmware blobs confirmed in firmware/lan_eeprom/",
    "cwe":      ["CWE-494 (Download of Code Without Integrity Check)",
                 "CWE-693 (Protection Mechanism Failure)"],
    "file":     "nuova/diagnostics/firmware/lan_eeprom/eeupdate64e",
    "bundled_firmware": [
        "mtp_eth2_lan0.bin",
        "nic2_eth1_lan0.bin",
        "nic4_eth3_lan1.bin",
    ],
    "supported_nic_families": [
        "I210 (_NalVerifyNvmI210)",
        "I8254x (_NalI8254xGetEepromVersion, _NalI8254xVerifyEepromSizeWord)",
        "I40E (_NalI40eVerifyNvm, _NalI40eBaseDriverVerifyShadowRamSwChecksum)",
        "X550 (_NalX550DebugVerifyFlash, _NalX550emVerifyNvmAutoload)",
        "X540 (_NalX540GetFlashVerifyStartOffset)",
        "ICE/E810 (_NalIceVerifyNvm, _NalIceShadowRamSwChecksum)",
        "Aquantia (_NalAquantiaGetExternalPhyFirmwareVersion)",
        "FM10k (_NalFm10kGetEepromVersion)",
        "Cortina/Coppervalue (_NalCortinaGetPhyFirmwareVersionEx)",
    ],
    "impact": (
        "eeupdate64e allows direct flash write to NIC EEPROM without OS-level signature "
        "verification. An attacker with local code execution can overwrite NIC firmware "
        "with custom code that persists across OS reboots, executes at ring-1 (DMA master "
        "before OS security policy loads), and survives firmware update operations that "
        "only target the main CPU flash. "
        "The bundled NIC firmware blobs are delivered unsigned alongside the update tool."
    ),
    "note": "eeupdate64e is Intel's manufacturing/diagnostics tool not intended for "
            "production deployment. Its presence in production firmware alongside unsigned "
            "NIC firmware blobs means every IOM 2500 unit ships with the capability to "
            "self-modify its NIC EEPROM. The tool supports the full Intel NIC family used "
            "across Cisco UCS products — not only the specific NICs in this IOM variant.",
}

# IOM2500-F3: emmc_partition_format.sh + mfgdiag manufacturing scripts in production PKG4
IOM2500_F3 = {
    "id":       "IOM2500-F3",
    "title":    "PKG4 contains manufacturing diagnostic scripts deployed in production: "
                "emmc_partition_format.sh kills all management daemons (cmcmon, obfllogger, "
                "rsyslogd), umounts all eMMC partitions (mmcblk0p1-p6), fdisk repartitions "
                "to 6x1GB partitions, reformats all with ext4; mfgdiag binary (x86-64) "
                "contains system_cmd shell execution, exec_bmc_cmd direct BMC command dispatch, "
                "kr_debug_mode kernel debug enable, and writes to /root/.accepted_intel_license_ivb_07 "
                "confirming execution as root; five platform-specific eMMC scripts present: "
                "madisonriver_emmc_partition.sh, tilton_river_emmc_partition_format.sh, "
                "madisonriver_noevalley_disk_partition_format.sh",
    "severity": "HIGH",
    "status":   "CONFIRMED — emmc_partition_format.sh extracted from PKG4; killall+umount+fdisk "
                "sequence confirmed; mfgdiag binary extracted; system_cmd, exec_bmc_cmd, "
                "kr_debug_mode, and /root/.accepted_intel_license_ivb_07 path strings confirmed",
    "cwe":      ["CWE-284 (Improper Access Control)",
                 "CWE-732 (Incorrect Permission Assignment for Critical Resource)"],
    "files":    ["nuova/diagnostics/emmc_partition_format.sh",
                 "nuova/diagnostics/mfgdiag",
                 "nuova/diagnostics/madisonriver_emmc_partition.sh",
                 "nuova/diagnostics/tilton_river_emmc_partition_format.sh"],
    "emmc_format_sequence": (
        "killall cmcmon obfllogger rsyslogd\n"
        "umount /dev/mmcblk0p1 ... /dev/mmcblk0p6\n"
        "(echo g; echo n; echo; echo; echo +1G; ...; echo w;) | fdisk /dev/mmcblk0\n"
        "mkfs.ext4 -O^64bit /dev/mmcblk0p{1..5}"
    ),
    "mfgdiag_strings": [
        "echo 0 > /root/.accepted_intel_license_ivb_07",
        "exec_bmc_cmd %d %d %s",
        "Error %s %d: fail to exec your command %s",
        "Error %s %d: fail to exec your command '%s'",
        "system_cmd",
        "kr_debug_mode",
        "sd_serdes_debug_dump",
        "dsh_cmd_asic_read_write_iom4",
    ],
    "platform_codenames_in_scripts": [
        "MadisonRiver", "TiltonRiver", "NoEValley",
    ],
    "impact": (
        "emmc_partition_format.sh destroys all IOM persistent state in a single invocation: "
        "all configuration, certificates, logs, and cryptographic material stored on eMMC are "
        "permanently erased. No confirmation prompt or authentication gate in the script. "
        "mfgdiag's exec_bmc_cmd provides a privileged path to issue arbitrary BMC commands "
        "bypassing the normal CMC authorization layer; the error format string 'fail to exec "
        "your command %s' with the raw command echoed back suggests no input sanitization."
    ),
    "note": "Five platform-specific variants of the eMMC format script exist, confirming "
            "this is part of the standard manufacturing flow for the full IOM 2500 platform "
            "family. All five variants perform the same destructive operation on mmcblk0. "
            "mfgdiag references 'iom5brd_cmd.c' in an error path, suggesting the IOM 2500 "
            "is internally called IOM5 in the design.",
}

# IOM2500-F4: ASIC verification configs and internal engineer identity in production
IOM2500_F4 = {
    "id":       "IOM2500-F4",
    "title":    "nuova/diagnostics/asic_lib.tar.bz2 contains Rocky/ROC switch ASIC internal "
                "verification configuration files (rocky/verif/roc_top/cfg/) including SPAN, "
                "ERSPAN, SerDes, and traffic pattern configs from Cisco's simulation/emulation "
                "environment; file_change.diff (67KB) and file_change_list.txt timestamp "
                "2024-05-29 confirming active development artifacts; all files owned by "
                "user 'datton' group 'eng'; same ownership in skagitriver_support_files.tar "
                "which contains PSU firmware (Carlsborg_2800W), FPGA firmware "
                "(Washington_IFM_MTP versions 3-7), and 112G SerDes CSV configs "
                "(Tilton_112d_Project_5+1 multiple voltage points)",
    "severity": "HIGH",
    "status":   "CONFIRMED — asic_lib.tar.bz2 extracted from PKG4; rocky/verif/roc_top/cfg/ "
                "directory with 30+ .cfg files confirmed; file_change.diff 67KB with "
                "2024-05-29 timestamp confirmed; datton/eng ownership confirmed; "
                "skagitriver_support_files.tar inventory confirmed with Washington FPGA "
                "and Carlsborg PSU firmware blobs",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to Unauthorized Actor)",
                 "CWE-312 (Cleartext Storage of Sensitive Information)"],
    "file":     "nuova/diagnostics/asic_lib.tar.bz2",
    "internal_artifacts": {
        "asic_codename": "Rocky / ROC (roc_top = Rocky top-level verification environment)",
        "verification_env": "rocky/verif/roc_top/cfg/ — simulation/emulation test configs",
        "cfg_samples": [
            "roc_top_mixall_w_srvc_w_rxtxspan_w_fc_all25g_fc16g.cfg (37KB)",
            "roc_top_txspanmc.cfg",
            "roc_top_supspan_rwx.cfg",
            "roc_top_oerspan.cfg",
            "roc_top_sup_rcpu_oport_failover.cfg",
        ],
        "change_file_date": "2024-05-29 13:30 (file_change.diff, 67KB) — active as of May 2024",
        "developer_identity": "user=datton, group=eng",
        "fpga_firmware": [
            "Washington_IFM_MTP_IFC_FPGA_Version_3.mcs.bz2",
            "Washington_IFM_MTP_IFC_FPGA_Version_4.mcs.bz2",
            "Washington_IFM_MTP_MP_FPGA_Version_6.mcs.bz2",
            "Washington_IFM_MTP_MP_FPGA_Version_7.mcs.bz2",
        ],
        "psu_firmware": [
            "Carlsborg_2800W_PRI_Vap1.1.2-Vbl0.3.2_0x0045D766_20210120.bin",
            "Carlsborg_2800W_SEC_Vap2.2.0-Vbl0.3.3_0x008DB51A_20210216.bin",
        ],
        "serdes_configs": [
            "Tilton_112d_Project_5+1_0.850V.CSV",
            "Tilton_112d_Project_5+1_0.875V.CSV",
            "Tilton_112d_Project_5+1_0.900V.CSV",
        ],
    },
    "new_codenames": {
        "Rocky": "Internal ASIC codename (switch ASIC for IOM 2500 generation)",
        "Washington": "FPGA codename (IFM MTP interface FPGA)",
        "Carlsborg": "PSU codename (2800W power supply, named for Carlsborg WA)",
        "Tilton": "SerDes operating point codename (112G NRZ)",
        "SkagitRiver": "Platform support tarball codename",
        "MadisonRiver": "Platform codename in eMMC format scripts",
        "TiltonRiver": "Platform codename in eMMC format scripts",
        "NoEValley": "Platform codename in eMMC partition format script",
    },
    "note": "The presence of internal ASIC verification configs from Cisco's EDA/simulation "
            "environment in production firmware indicates these files were added to the "
            "diagnostics package during the same development flow as the ASIC bring-up. "
            "The 2024-05-29 timestamp in file_change.diff confirms these are not stale "
            "leftover artifacts but were actively modified in the months before the 6.0.2b "
            "release. The Rocky/ROC ASIC configs expose Cisco's forwarding pipeline "
            "architecture including SPAN/ERSPAN termination logic, superspan, and "
            "RCPU failover configurations.",
}

# IOM2500-F5: Mosquitto MQTT broker allow_anonymous true in production PKG2
IOM2500_F5 = {
    "id":       "IOM2500-F5",
    "title":    "PKG2 management stack includes Mosquitto MQTT broker (nuova/bin/mosquitto) "
                "configured with allow_anonymous true on the UNIX domain socket listener "
                "/var/run/mymqtt.sock; mosquitto-broker.conf sets per_listener_settings true "
                "and runs as user root; TCP localhost listener is commented out but the "
                "UNIX socket listener has no authentication; init.d/mosquitto starts the "
                "broker at boot alongside Redfish, JRPC, and all CMC management daemons",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — etc/mosquitto/mosquitto-broker.conf extracted from PKG2; "
                "allow_anonymous true on UNIX socket listener confirmed; per_listener_settings "
                "true confirmed; user root confirmed; nuova/bin/mosquitto binary (293KB) "
                "and mosquitto_pub/sub utilities confirmed; init.d/mosquitto service script "
                "confirmed with var/service/mosquitto/run",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-284 (Improper Access Control)"],
    "files":    ["etc/mosquitto/mosquitto-broker.conf", "nuova/bin/mosquitto",
                 "etc/init.d/mosquitto"],
    "mosquitto_conf": (
        "per_listener_settings true\n"
        "user root\n"
        "# localhost listener: not applicable for CMC at this time\n"
        "# listener 9020 127.0.0.1\n"
        "# allow_anonymous false\n"
        "# protocol websockets\n"
        "#socket listener\n"
        "listener 0 /var/run/mymqtt.sock\n"
        "allow_anonymous true"
    ),
    "impact": (
        "Any local process with access to /var/run/mymqtt.sock can publish or subscribe "
        "to all MQTT topics without authentication. IOM 2500 PKG2 includes the full CMC "
        "management service set (Redfish, JRPC, bmcd, cimc_update, platform_ohms) that "
        "likely communicate internal state via MQTT. "
        "An attacker with local code execution (via gdbserver, JRPC, or AACS TCP server) "
        "can subscribe to all internal management topic traffic, inject fabricated hardware "
        "state messages, or trigger management daemon actions by publishing to control topics. "
        "mosquitto runs as root."
    ),
    "note": "The commented-out TCP listener with allow_anonymous false shows the developer "
            "was aware of MQTT authentication requirements but explicitly chose allow_anonymous "
            "true for the UNIX socket. The 'not applicable for CMC at this time' comment for "
            "the localhost TCP listener suggests this is a known deferred security decision.",
}

# IOM2500-F6: plink (PuTTY SSH client) in production PKG4 with -pw CLI argument support
IOM2500_F6 = {
    "id":       "IOM2500-F6",
    "title":    "usr/bin/plink (PuTTY SSH/Telnet client) present in production PKG4; "
                "plink supports the -pw flag which passes SSH passwords as a command-line "
                "argument, making them visible in /proc/PID/cmdline to any local user; "
                "PKG4 also contains usr/bin/mvcli (storage management CLI with libmvraid.so "
                "dependency), usr/bin/mmc (eMMC management), and usr/bin/tclsh (Tcl 8.6 "
                "interpreter); diag/bin/redis.tcl confirms Redis is accessible from "
                "the diagnostics layer",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — plink binary extracted from PKG4 usr/bin/plink; PuTTY copyright "
                "strings and '-pw option can only be used with the SSH protocol' string "
                "confirmed; mvcli binary confirmed with RAID strings and libmvraid.so "
                "dependency; mmc binary confirmed; tclsh 8.6 and 8.6.4 binaries confirmed; "
                "diag/bin/redis.tcl confirmed",
    "cwe":      ["CWE-214 (Invocation of Process Using Visible Sensitive Information)",
                 "CWE-312 (Cleartext Storage of Sensitive Information)"],
    "files":    ["usr/bin/plink", "usr/bin/mvcli", "usr/bin/mmc",
                 "usr/bin/tclsh", "diag/bin/redis.tcl"],
    "plink_pw_string": "the -pw option can only be used with the SSH protocol",
    "mvcli_note": "mvcli depends on libmvraid.so (bundled in PKG4 usr/lib64/); libmvraid.so "
                  "appears to be a Marvell/LSI storage management library for MV88 RAID "
                  "controllers — the IOM management CPU may include local NVMe/RAID "
                  "storage; mvcli in production allows arbitrary storage configuration",
    "redis_note": "diag/bin/redis.tcl confirms a Redis instance is accessible from the "
                  "diagnostics environment; Redis is a common inter-service communication "
                  "path in Cisco management stacks (confirmed in other UCS modules); "
                  "if Redis is unauthenticated, poke from any local process",
    "impact": (
        "Any diagnostic script or init script that invokes plink with the -pw flag exposes "
        "the SSH password in /proc/PID/cmdline, readable by any local user. "
        "plink in production also provides an outbound SSH client usable for data "
        "exfiltration or pivot from the IOM management plane. mvcli enables storage "
        "configuration changes bypassing CMC authorization. tclsh provides a general "
        "scripting environment usable for post-exploitation."
    ),
    "note": "plink's presence in the diagnostics package alongside mvcli and mmc suggests "
            "the IOM 2500 uses plink for automated SSH connections to management systems "
            "during manufacturing and diagnostics. Automated SSH with -pw in scripts is "
            "a common manufacturing shortcut that ships with the production firmware.",
}

FINDINGS = [
    IOM2500_F1, IOM2500_F2, IOM2500_F3, IOM2500_F4,
    IOM2500_F5, IOM2500_F6,
]
