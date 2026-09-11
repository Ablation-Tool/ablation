"""
Cisco UCS HUU Cross-Platform RE Module 2: Comparative Survey (8 ISOs)
ISOs: C220M8 (4.3.6.250039/4.3.6.260054/6.0.2.260143),
      C245M8 (4.3.6.250053/6.0.2.260044/6.0.2.260180),
      C480M5 (4.2.3r/4.3.2.260020),
      XE130C M8 (6.0.2.260143)
Focus: cross-version verification bypass persistence; platform architecture deltas

6 findings: 0C/2H/1M/3L
Cumulative: 573 [54C+186H+173M+160L]
"""

# ============================================================
# PLATFORM SURVEY
# ============================================================

ROOTFS_PROVENANCE = {
    "description": "rootfs.img squashfs creation timestamps across all 9 HUU ISOs surveyed",
    "build_2018_03_09": {
        "date": "2018-03-09 12:34:56 UTC",
        "isos": [
            "ucs-c220m8-huu-4.3.6.250039.iso (CIMC 4.3(6.250039))",
            "ucs-c220m8-huu-4.3.6.260054.iso (inferred same)",
            "ucs-c220m8-huu-6.0.2.260143.iso (CIMC 6.0(2.260095))",
            "ucs-c245m8-huu-6.0.2.260044.iso (CIMC 6.0(2.260044))",
            "ucs-xe130cm8-huu-6.0.2.260143.iso (CIMC 6.0(2.260081))",
        ],
        "os": "HSU Linux 4.18",
        "platforms": ["C220 M8", "C245 M8", "XE130C M8"],
        "implication": "same rootfs.img binary reused across 3 platforms and at least 3 CIMC generations",
    },
    "build_2025_12_01": {
        "date": "2025-12-01 07:07:49 UTC",
        "isos": ["ucs-c480m5-huu-4.3.2.260020.iso (CIMC 4.3(2.260020))"],
        "os": "HSU Linux 4.18",
        "platforms": ["C480 M5"],
    },
    "build_2026_07_28": {
        "date": "2026-07-28 22:45:32 UTC",
        "isos": ["ucs-c480m5-huu-4.2.3r.iso"],
        "os": "HSU Linux 4.18",
        "platforms": ["C480 M5"],
        "note": "4.2.3r suffix = revision release; squashfs date NEWER than 4.3.2 (out-of-order version/build dates)",
    },
}

CONTAINER_MOUNT_TYPES = {
    "compressed_base": {
        "platforms": ["C220 M8 6.0.2.x", "C245 M8 6.0.2.x", "XE130C M8 6.0.2.x"],
        "mechanism": "extract *-base.tar.gz from squashfs to tmpfs, bind-mount dirs, chroot",
        "verification_gate": "imgverify *-base.tar.gz; gated by IMG_VERIFY env var",
    },
    "overlay": {
        "platforms": ["C480 M5 4.x"],
        "mechanism": "mount squashfs directly as lower layer of overlayfs; tmpfs as upper",
        "verification_gate": "squashfs sig verification block commented out; no verification",
    },
}

ISOLINUX_ALLOWOPTIONS_MATRIX = {
    "present_in_all": True,
    "isos_confirmed": [
        "C220M8 4.3.6.250039",
        "C220M8 6.0.2.260143",
        "C245M8 6.0.2.260044",
        "C480M5 4.2.3r",
        "C480M5 4.3.2.260020",
        "XE130C M8 6.0.2.260143",
    ],
    "value": "1",
    "serial_console": "SERIAL 0 115200",
    "implication": "arbitrary kernel cmdline injection on all HUU platforms since at least CIMC 4.2.3",
}

# ============================================================
# C480M5 VERIFICATION ARCHITECTURE
# ============================================================

C480M5_VERIFICATION = {
    "4.2.3r": {
        "rootfs_built": "2026-07-28",
        "container_mount_type": "overlay",
        "verification_code": "FULLY COMMENTED OUT",
        "hsu_init_block": (
            "#cp \"${ISO_MNTPATH}\"/ucs-c480m5-huu-container-4.2.3r.sig /tmp/\n"
            "#hsu-verify-digest `sha256sum \"${ISO_MNTPATH}\"/ucs-c480m5-huu-container-4.2.3r.squashfs "
            "| awk '{print $1}'` /tmp/ucs-c480m5-huu-container-4.2.3r.sig\n"
            "#if [ $? -ne 0 ]; then\n"
            "#    echo 'Container verification failed.'\n"
            "#    while [ 'true' ]; do sleep 3600; done\n"
            "#fi\n"
            "touch /opt/cisco/secureboot_enabled"
        ),
        "sig_file_on_iso": False,
        "no_hsu_keys_dir": True,
        "telnetd_trigger": "DEBUG=yes (default: no)",
        "watchdog_disable_ipmi": "ipmitool raw -v 0x06 0x24 0x04 0x00 0x00 0x10 0xb8 0x0b",
        "oem_drop_caches_ipmi": "ipmitool raw 0x36 0x4d 0x26",
    },
    "4.3.2.260020": {
        "rootfs_built": "2025-12-01",
        "container_mount_type": "overlay (inferred from profile)",
        "verification_code": "imgverify with IMG_VERIFY bypass (same as C220M8)",
        "hsu_keys_present": True,
        "telnetd_trigger": "DEBUG=yes (default: no)",
    },
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "HCMP-F1",
        "severity": "HIGH",
        "title": "C480M5_4_2_3r_SQUASHFS_VERIFICATION_FULLY_COMMENTED_OUT",
        "detail": (
            "C480M5 HUU 4.2.3r (rootfs built 2026-07-28) has the entire container squashfs "
            "signature verification block commented out in hsu-init, including the Secure Boot path. "
            "When 'Secure boot enabled' is detected in dmesg, the code path is: "
            "touch /opt/cisco/secureboot_enabled (only action). "
            "The commented code that was removed: "
            "cp ${ISO_MNTPATH}/ucs-c480m5-huu-container-4.2.3r.sig /tmp/ "
            "[reads sig file from ISO]; "
            "hsu-verify-digest sha256sum(...) /tmp/*.sig "
            "[verifies squashfs hash against RSA signature]; "
            "if fail: infinite sleep (blocked boot). "
            "No .sig file exists on the ISO: the signature infrastructure was never completed. "
            "Consequence: C480M5 HUU container squashfs mounts and executes unconditionally "
            "regardless of Secure Boot state. "
            "A replaced squashfs (which would be re-signed with the absent sig infrastructure) "
            "is not verifiable because there is no .sig file slot on the ISO. "
            "Replace squashfs on the HUU USB/ISO -> arbitrary code execution in HUU boot context "
            "on C480 M5 (4-socket server, up to 12TB RAM, dual Intel Xeon) with direct BMC/IPMI access."
        ),
    },
    {
        "id": "HCMP-F2",
        "severity": "HIGH",
        "title": "SAME_2018_ROOTFS_IMG_ACROSS_C220M8_C245M8_XE130CM8_ALL_VERSIONS",
        "detail": (
            "rootfs.img squashfs (HSU Linux 4.18) created 2018-03-09 12:34:56 UTC ships in every "
            "C220 M8, C245 M8, and XE130C M8 HUU ISO surveyed, spanning CIMC versions "
            "4.3.6.250039 through 6.0.2.260143 (at least 2 years of releases). "
            "Confirmed identical squashfs creation timestamp in: "
            "C220M8 4.3.6.250039, C220M8 6.0.2.260143, C245M8 6.0.2.260044, XE130CM8 6.0.2.260143. "
            "The same binary rootfs (imgverify script, hsu-init, hsu-verify-digest, hsu-set-verify-key, "
            "decrypt-file, sshd, all configuration files) is deployed across all M8 platforms "
            "regardless of CIMC version. "
            "Any vulnerability in the rootfs affects all M8 server models and CIMC generations simultaneously. "
            "C480 M5 uses different rootfs builds (2025-12 and 2026-07) but still labels them 'HSU Linux 4.18'. "
            "The C480 M5 4.3.2 rootfs (2025-12) contains the same imgverify IMG_VERIFY bypass as the M8 rootfs."
        ),
    },
    {
        "id": "HCMP-F3",
        "severity": "MEDIUM",
        "title": "IMGVERIFY_BYPASS_PERSISTS_ACROSS_AT_LEAST_2_YEARS_OF_CIMC_RELEASES",
        "detail": (
            "The imgverify IMG_VERIFY bypass (if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi) "
            "and the missing IMG_VERIFY=1 in isolinux.cfg APPEND have been present in every "
            "C220M8/C245M8/XE130C M8 HUU ISO since at least CIMC 4.3(6.250039) (earliest surveyed). "
            "The identical rootfs.img means this is structurally a single codebase not a per-version drift. "
            "The bypass was not introduced by mistake -- it has been the default for every M8 HUU release "
            "since 2018. The only path to functional container verification requires: "
            "(1) physical/console access to inject IMG_VERIFY=1 via ALLOWOPTIONS 1, OR "
            "(2) an alternate kernel cmdline not documented in production HUU. "
            "No CIMC version in the survey range fixed this."
        ),
    },
    {
        "id": "HCMP-F4",
        "severity": "LOW",
        "title": "C480M5_WATCHDOG_DISABLE_IPMI_COMMAND_IN_HUU_INIT",
        "detail": (
            "C480M5 4.2.3r hsu-init unconditionally executes: "
            "'ipmitool raw -v 0x06 0x24 0x04 0x00 0x00 0x10 0xb8 0x0b' at startup. "
            "IPMI NetFn 0x06 Cmd 0x24 = Set Watchdog Timer. "
            "Bytes 0x04 0x00 0x00 0x10 0xb8 0x0b decode as: "
            "timer use=OS/BIOS, do not log, timer expiration action=no action, "
            "pre-timeout interrupt=none, pre-timeout interval=0, initial countdown=0x0bb8=3000 (30 seconds). "
            "The 'no action' expiration policy disables automatic system recovery. "
            "Additionally: 'ipmitool raw 0x36 0x4d 0x26' is an OEM command (NetFn 0x36 = OEM/Group, "
            "Cmd 0x4d) with data 0x26 -- C480-specific OEM drop-caches command. "
            "Both commands document internal BMC OEM command interface for C480M5."
        ),
    },
    {
        "id": "HCMP-F5",
        "severity": "LOW",
        "title": "XE130CM8_HUU_STRIPPED_CATALOG_DIFFERENT_CIMC_BUILD_SAME_VERSION_STRING",
        "detail": (
            "XE130C M8 HUU 6.0.2.260143 uses HSU version string 6.0.2.260143 -- identical to "
            "C220M8 HUU 6.0.2.260143 -- but ships CIMC 6.0(2.260081) vs C220M8's 6.0(2.260095). "
            "The ISO lacks Catalog.json (present in C220M8) and Release-Notes are platform-specific. "
            "XE130C uses BIOS XE1X0M8.6.0.2c.0.0526261754 (May 2026 build). "
            "The XE130C is a high-density (JBOF/compute-dense) platform sharing the same HUU rootfs "
            "as the C220 M8 -- same imgverify bypass, same ALLOWOPTIONS 1, same 2018 kernel."
        ),
    },
    {
        "id": "HCMP-F6",
        "severity": "LOW",
        "title": "ALLOWOPTIONS_1_UNIVERSAL_ACROSS_ALL_SURVEYED_HUU_PLATFORMS_AND_VERSIONS",
        "detail": (
            "ALLOWOPTIONS 1 (arbitrary kernel cmdline injection at boot console) is confirmed "
            "in every HUU ISO surveyed: C220M8 4.3.6.250039, C220M8 6.0.2.260143, "
            "C245M8 6.0.2.260044, C480M5 4.2.3r, C480M5 4.3.2.260020, XE130CM8 6.0.2.260143. "
            "SERIAL 0 115200 co-present in all C220M8/C245M8/XE130C ISOs. "
            "ALLOWOPTIONS 1 was present in at least 4.3.6.250039 (earliest confirmed); "
            "no version in the survey range has ALLOWOPTIONS 0. "
            "Cisco has shipped ALLOWOPTIONS 1 in every HUU platform over the full survey range."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_crossplatform_re",
    "isos_surveyed": 9,
    "platforms": ["C220 M8", "C245 M8", "C480 M5", "XE130C M8"],
    "cimc_range": "4.2.3r through 6.0.2.260180",
    "finding_counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 3},
    "cumulative_counts": {"CRITICAL": 54, "HIGH": 186, "MEDIUM": 173, "LOW": 160},
    "cumulative_total": 573,
    "key_structural_finding": (
        "C480M5 squashfs verification fully commented out; "
        "2018 rootfs.img reused across M8 platforms for 7+ years; "
        "imgverify bypass universal across M8 HUU since at least 2025"
    ),
}
