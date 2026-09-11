"""
Cisco UCS FI 6400 Infrastructure Bundle RE Module
Bundle: ucs-6400-k9-bundle-infra.6.0.2b.A.bin (3.3GB)
Platform: UCS Fabric Interconnect 6400 series + FEX 2400/2500
Version: 6.0(2b)A

7 findings: 0C/2H/3M/2L
Cumulative: 617 [55C+197H+189M+176L]
"""

# ============================================================
# TARGET
# ============================================================

TARGET = {
    "bundle": "ucs-6400-k9-bundle-infra.6.0.2b.A.bin",
    "size_gb": 3.3,
    "version": "6.0(2b)A",
    "swid": "0swid-bundle-6400-infra",
    "sp_version": "6.0(2)SP0",
    "outer_sn_offset": 808,
    "inner_components": {
        "fi_nxos_image": {
            "filename": "ucsfi.10.5.1.I60.2b.F.bin",
            "size_bytes": 1589095936,
            "format": "mknbi-linux-1.2-6 (NOT SN-wrapped)",
            "kernel": "Linux 5.10.216 (nxbld@bes240223232923) #1 SMP Sun Mar 1 06:58:04 GMT 2026",
        },
        "ucsm": {
            "filename": "ucs-manager-k9.6.0.2b.bin",
            "size_bytes": 1074133822,
            "format": "SN-wrapped, gzip at offset 748",
            "hash_at_0x38": "648a83b99bbd9df355fe83fa49c06d65",
            "inner_tar": {"./isan/plugin_img/ucs-fi-connector": "10006507 bytes"},
        },
        "fex_2400": {
            "filename": "ucs-2400-6400.6.0.2b.bin",
            "size_bytes": 360592681,
            "format": "SN-wrapped, gzip at offset 760",
            "swid": "5swid-iocard-6400-summerville",
            "inner_tar": {
                "./isan/etc/imghdr.bin": "760 bytes (SN header copy)",
                "./isan/etc/climib/": "directory (NX-OS CLI MIB)",
                "./blob": "396326577 bytes (raw FEX 2400 firmware)",
            },
        },
        "fex_2500": {
            "filename": "ucs-2500-6400.6.0.2b.bin",
            "size_bytes": 412427442,
            "format": "SN-wrapped, gzip at offset 760",
            "swid": "5swid-iocard-6400-skagitriver",
            "inner_tar": {
                "./isan/etc/imghdr.bin": "760 bytes (SN header copy)",
                "./isan/etc/climib/": "directory (NX-OS CLI MIB)",
                "./blob": "448652859 bytes (raw FEX 2500 firmware)",
            },
        },
        "imghdr_bin": {
            "filename": "imghdr.bin",
            "size_bytes": 808,
            "format": "SN header copy (outer bundle metadata)",
        },
    },
}

# ============================================================
# FI SYSTEM IMAGE ANALYSIS
# ============================================================

MKNBI_LINUX_FORMAT = {
    "magic": "36 13 03 1b",
    "version_string": "mknbi-linux-1.2-6",
    "format_origin": "Network Boot Image (MKNBI) format; originally for PXE/netboot; Cisco uses it for FI flash boot",
    "kernel_cmdline_location": "cleartext in image header region before payload",
    "kernel_cmdline": (
        "rw root=/dev/ram0 rdbase=0x8000000 noefi ip=off panic=5 quiet "
        "coredump_filter=0x9 "
        "mtdparts=physmap-flash.0:256k(RR_LOG),512k(mtdoops),16M(plog),16M(trace) "
        "intel_idle.max_cstate=2 pcie_ports=native nopat "
        "mtdoops.dump_oops=0 slub_debug=- cpuidle.off=1 "
        "libata.force=rstonce eagerfpu=on "
        "no_startup_cfg=yes "
        "module.sig_enforce=1 irqpoll pci=noaer"
    ),
    "cmdline_security_flags": {
        "module.sig_enforce": "1 (kernel module signing enforced -- positive control)",
        "pci_noaer": "pci=noaer (PCIe Advanced Error Reporting disabled)",
        "irqpoll": "irqpoll (all IRQs polled rather than interrupt-driven)",
        "no_startup_cfg": "no_startup_cfg=yes (NX-OS startup config NOT loaded at boot)",
        "noefi": "noefi (EFI disabled)",
        "panic": "panic=5 (reboot after 5s kernel panic)",
    },
    "kernel_version_string": "5.10.216 (nxbld@bes240223232923) #1 SMP Sun Mar 1 06:58:04 GMT 2026",
    "external_signature": None,
    "note": (
        "mknbi-linux image has no external signature mechanism. "
        "Integrity relies solely on the outer SN bundle hash (16B at 0x38, unknown algorithm). "
        "The FI NX-OS image is NOT SN-wrapped unlike all other bundle components."
    ),
}

MTD_PARTITION_MAP = {
    "device": "physmap-flash.0",
    "partitions": {
        "RR_LOG": {"size": "256KB", "purpose": "reset reason log (records why FI last rebooted)"},
        "mtdoops": {"size": "512KB", "purpose": "kernel oops/panic capture to flash (mtdoops driver)"},
        "plog": {"size": "16MB", "purpose": "platform log (persistent event log)"},
        "trace": {"size": "16MB", "purpose": "trace buffer (execution traces)"},
    },
    "source": "kernel cmdline mtdparts= argument in cleartext mknbi-linux header",
    "implication": (
        "Full flash partition layout for FI forensic/crash storage exposed in firmware image. "
        "An attacker with flash read/write access (e.g., via UART, JTAG, or boot ROM exploit) "
        "can locate crash evidence in mtdoops, tamper with plog to hide activity, "
        "or poison RR_LOG to falsify reboot history."
    ),
}

# ============================================================
# SWID / CODENAME REGISTRY
# ============================================================

SWID_CODENAMES = {
    "bundle": "0swid-bundle-6400-infra",
    "fex_2400": "5swid-iocard-6400-summerville",
    "fex_2500": "5swid-iocard-6400-skagitriver",
    "sp_version_field": "swid-lwu-sp-version = 6.0(2)SP0",
    "geographic_pattern": "Pacific Northwest rivers (Skagit River WA, Summerville OR)",
    "note": (
        "Codenames follow Cisco's standard Pacific Northwest geography pattern. "
        "SWID numeric prefix (0=bundle, 5=iocard) encodes component category. "
        "'lwu' in SP version field = possibly 'Lightweight Update' or internal build track."
    ),
}

# ============================================================
# FEX ARCHITECTURE ANALYSIS
# ============================================================

FEX_ARCHITECTURE = {
    "fex_2400_2500": {
        "role": "Fabric Extender -- extends UCS FI fabric ports to rack servers",
        "protocol": "HIF (Host Interface) uplink to FI; forwards all management to FI parent",
        "tar_structure": {
            "./isan/etc/imghdr.bin": "SN header copy (metadata)",
            "./isan/etc/climib/": "NX-OS CLI MIB definitions directory",
            "./blob": "raw FEX firmware binary (396/448MB)",
        },
        "climib_significance": (
            "Presence of './isan/etc/climib/' confirms FEX units run NX-OS CLI subsystem. "
            "NX-OS CLI MIB provides management plane commands accessible locally or via parent FI. "
            "FEX is not a passive pass-through -- it runs an active NX-OS instance "
            "with its own CLI parser, MIB tree, and management surface."
        ),
        "firmware_signing": "unsigned blob (same SN 16B hash pattern as peripheral components)",
    },
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "FI64-F1",
        "severity": "HIGH",
        "title": "FI_NXOS_SYSTEM_IMAGE_USES_MKNBI_LINUX_NOT_SN_CONTAINER",
        "detail": (
            "The FI 6400 NX-OS system image (ucsfi.10.5.1.I60.2b.F.bin, 1.5GB) uses "
            "mknbi-linux-1.2-6 format and is NOT wrapped in an SN container. "
            "Every other component in the same bundle uses SN format: "
            "UCSM 1.0GB (SN offset 748), FEX 2400 344MB (SN offset 760), FEX 2500 394MB (SN offset 760). "
            "The SN container provides the only per-component integrity mechanism in the bundle "
            "(16B hash at SN header offset 0x38). "
            "The FI system image -- the largest and most critical component -- bypasses this entirely. "
            "It is protected only by the outer bundle SN hash, which covers the entire 3.3GB bundle "
            "as a single unit. "
            "A targeted replacement of the FI system image within the bundle requires recomputing "
            "only one 16B hash (the outer bundle hash) vs per-component hashes for other components. "
            "mknbi-linux has no external signature mechanism and carries no per-image signing "
            "observable in the header. "
            "module.sig_enforce=1 in the kernel cmdline enforces module signing at runtime "
            "but does not authenticate the kernel image itself before it executes."
        ),
    },
    {
        "id": "FI64-F2",
        "severity": "HIGH",
        "title": "UCSM_AND_FEX_FIRMWARE_UNSIGNED_SN_ONLY_IN_INFRASTRUCTURE_BUNDLE",
        "detail": (
            "UCSM binary (ucs-manager-k9.6.0.2b.bin, 1.0GB) and both FEX firmware images "
            "(FEX 2400 ucs-2400-6400.6.0.2b.bin 344MB, FEX 2500 ucs-2500-6400.6.0.2b.bin 394MB) "
            "use SN container with only a 16B hash field at offset 0x38 -- "
            "no RSA/ECDSA signature in any SN header. "
            "UCSM inner tar: ./isan/plugin_img/ucs-fi-connector (10MB NX-OS plugin). "
            "FEX 2400/2500 inner tars: ./isan/etc/imghdr.bin (metadata) + "
            "./isan/etc/climib/ (NX-OS CLI MIB) + ./blob (396/448MB raw firmware). "
            "Both FEX units run NX-OS CLI subsystem (climib/ directory confirms active NX-OS instance, "
            "not passive hardware). "
            "SWID codenames: FEX 2400 = summerville, FEX 2500 = skagitriver. "
            "An attacker with access to the bundle distribution path can replace any of these "
            "without triggering a signature verification failure visible to bundle consumers. "
            "UCSM compromise grants management plane control over the entire UCS fabric; "
            "FEX firmware compromise affects all servers connected to that FEX."
        ),
    },
    {
        "id": "FI64-F3",
        "severity": "MEDIUM",
        "title": "PCI_NOAER_AND_IRQPOLL_IN_PRODUCTION_FI_KERNEL_CMDLINE",
        "detail": (
            "The FI 6400 NX-OS kernel cmdline embedded in the mknbi-linux image header contains "
            "two hardware-compatibility diagnostic flags in the production build: "
            "'pci=noaer' disables PCIe Advanced Error Reporting (AER) entirely. "
            "AER is the PCIe mechanism for propagating uncorrectable/correctable hardware errors "
            "to the OS. With AER disabled, the kernel does not receive PCIe error events, "
            "does not log them, and does not trigger error recovery. "
            "This masks PCIe-level fault injection and hardware exploitation artifacts. "
            "'irqpoll' forces the kernel to poll all interrupt sources instead of responding "
            "to hardware interrupts -- a workaround for broken APIC/interrupt routing. "
            "In production, irqpoll degrades IRQ latency and masks interrupt routing anomalies. "
            "Both flags are atypical in production builds; their presence suggests either "
            "unresolved hardware compatibility issues on the FI 6400 platform or "
            "debug flags that were not removed before release."
        ),
    },
    {
        "id": "FI64-F4",
        "severity": "MEDIUM",
        "title": "MTD_FLASH_PARTITION_LAYOUT_EXPOSED_IN_CLEARTEXT_KERNEL_CMDLINE",
        "detail": (
            "The FI 6400 NX-OS kernel cmdline contains the full MTD partition map in plaintext: "
            "'mtdparts=physmap-flash.0:256k(RR_LOG),512k(mtdoops),16M(plog),16M(trace)'. "
            "Partition layout: "
            "RR_LOG (256KB) = reset reason log recording why the FI last rebooted; "
            "mtdoops (512KB) = kernel oops/panic dump to flash (mtdoops driver, written on crash); "
            "plog (16MB) = persistent platform event log; "
            "trace (16MB) = execution trace buffer. "
            "The kernel cmdline also includes 'mtdoops.dump_oops=0' (crash dump disabled in cmdline "
            "but mtdoops partition reserved). "
            "Combined with the outer bundle's SN offset (808 bytes), this maps the entire "
            "FI flash storage layout for forensic/tamper purposes. "
            "An attacker with UART or JTAG access can use these partition offsets directly "
            "to locate, read, or overwrite crash evidence before IR responders access the device."
        ),
    },
    {
        "id": "FI64-F5",
        "severity": "MEDIUM",
        "title": "NO_STARTUP_CFG_YES_IN_FI_PRODUCTION_KERNEL_CMDLINE",
        "detail": (
            "The FI 6400 NX-OS kernel cmdline contains 'no_startup_cfg=yes'. "
            "In NX-OS, this parameter bypasses loading the local startup-configuration file at boot. "
            "In UCSM-managed FI deployments, the FI configuration is managed by UCSM, "
            "which pushes configuration to the FI after it boots. "
            "'no_startup_cfg=yes' ensures the FI boots into an unconfigured state "
            "and waits for UCSM to provision it. "
            "Consequence: if UCSM becomes unavailable (failure, network isolation, active attack), "
            "a FI reload results in a fully unconfigured device with no ACLs, "
            "no management authentication, and no routing -- "
            "the FI may accept all management connections on default services "
            "until UCSM reconnects and re-provisions it. "
            "The window between FI boot and UCSM reconnection is an exposure period."
        ),
    },
    {
        "id": "FI64-F6",
        "severity": "LOW",
        "title": "BUILD_HOSTNAME_AND_DATE_IN_NX_OS_KERNEL_VERSION_STRING",
        "detail": (
            "The FI 6400 NX-OS kernel version string, embedded in cleartext in the mknbi-linux header: "
            "'5.10.216 (nxbld@bes240223232923) #1 SMP Sun Mar 1 06:58:04 GMT 2026'. "
            "Reveals: build user 'nxbld', hostname 'bes240223232923' (Cisco internal build server). "
            "The hostname format 'bes' + date string '240223' = Feb 23 2024 (YYYYMMDD) + '232923' "
            "suggests the build server name encodes provisioning date. "
            "Build date: March 1, 2026 (6.0(2b) release timeline). "
            "Kernel: Linux 5.10.216 (LTS; 5.10 maintained through Dec 2026). "
            "Build information is accessible to any party with the firmware image."
        ),
    },
    {
        "id": "FI64-F7",
        "severity": "LOW",
        "title": "INTERNAL_SWID_CODENAMES_AND_SP_VERSION_IN_SN_METADATA",
        "detail": (
            "Internal SWID (Software ID) names embedded in SN header metadata fields: "
            "Outer bundle: '0swid-bundle-6400-infra'; "
            "FEX 2400: '5swid-iocard-6400-summerville'; "
            "FEX 2500: '5swid-iocard-6400-skagitriver'. "
            "SWID prefix digit encodes component category: 0=bundle, 5=iocard. "
            "Geographic codenames follow Cisco's Pacific Northwest pattern: "
            "Summerville (Oregon) = FEX 2400, Skagit River (Washington) = FEX 2500. "
            "Service pack version field: 'swid-lwu-sp-version = 6.0(2)SP0'. "
            "'lwu' in SP field is an undocumented internal build track identifier. "
            "These names are readable from the first 808 bytes of any SN-wrapped component "
            "without decompressing the payload."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_fi6400_bundle_re",
    "bundle": "ucs-6400-k9-bundle-infra.6.0.2b.A.bin",
    "component_count": 5,
    "fi_nxos_kernel": "Linux 5.10.216 (nxbld@bes240223232923) #1 SMP Sun Mar 1 06:58:04 GMT 2026",
    "fi_nxos_format": "mknbi-linux-1.2-6 (NOT SN-wrapped)",
    "module_sig_enforce": "1 (kernel module signing enforced at runtime)",
    "pci_noaer": True,
    "no_startup_cfg": True,
    "mtd_partitions": ["RR_LOG 256KB", "mtdoops 512KB", "plog 16MB", "trace 16MB"],
    "fex_codenames": {
        "2400": "summerville",
        "2500": "skagitriver",
    },
    "fex_runs_nxos": True,
    "finding_counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 3, "LOW": 2},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 197, "MEDIUM": 189, "LOW": 176},
    "cumulative_total": 617,
}
