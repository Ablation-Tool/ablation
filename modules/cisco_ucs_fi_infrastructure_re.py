"""
Cisco UCS FI Infrastructure RE Module 1: FI 6400/6500/6600/X-Direct Bundle Analysis
Bundles: ucs-{6400,6500,6600}-k9-bundle-infra.6.0.2b.A.bin, ucs-x-direct-k9-infra.6.0.2b.A.bin
Targets: ucsfi NX-OS, UCSM, FEX 2400 (Summerville), FEX 2500 (Skagit River)

8 findings: 0C/0H/2M/6L
Cumulative: 543 [54C+179H+165M+145L]
"""

# ============================================================
# BUNDLE STRUCTURE
# ============================================================

FI_BUNDLE_MAP = {
    "format": "SN(gzip) -> TAR with 4-5 inner SN-wrapped components",
    "bundles": {
        "6400": "ucs-6400-k9-bundle-infra.6.0.2b.A.bin",
        "6500": "ucs-6500-k9-bundle-infra.6.0.2b.A.bin",
        "6600": "ucs-6600-k9-bundle-infra.6.0.2b.A.bin",
        "x-direct": "ucs-x-direct-k9-infra.6.0.2b.A.bin",
    },
    "inner_components_6400": [
        {"name": "ucsfi.10.5.1.I60.2b.F.bin", "size_mb": 1515, "description": "NX-OS kernel+initramfs (mknbi format)"},
        {"name": "ucs-manager-k9.6.0.2b.bin",  "size_mb": 1024, "description": "UCSM management software"},
        {"name": "ucs-2500-6400.6.0.2b.bin",   "size_mb": 393,  "description": "FEX 2500 Series (Skagit River) firmware"},
        {"name": "ucs-2400-6400.6.0.2b.bin",   "size_mb": 343,  "description": "FEX 2400 Series (Summerville) firmware"},
    ],
    "inner_components_xdirect": [
        {"name": "ucsfi.10.5.1.I60.2b.F.bin", "size_mb": 1515},
        {"name": "ucs-manager-k9.6.0.2b.bin",  "size_mb": 1024},
        {"name": "ucs-2500-6400.6.0.2b.bin",   "size_mb": 393},
    ],
    "version": "6.0(2b)A",
    "swid_lwu_sp_version": "6.0(2)SP0",
}

FI_NX_OS = {
    "file": "ucsfi.10.5.1.I60.2b.F.bin",
    "format": "mknbi-linux-1.2-6",
    "mknbi_magic": "0x3613031b",
    "mknbi_header_size_bytes": 21504,
    "kernel_version": "Linux 5.10.216",
    "kernel_build": "nxbld@bes240223232923",
    "kernel_build_date": "Sun Mar 1 06:58:04 GMT 2026",
    "full_cmdline": (
        "rw root=/dev/ram0 rdbase=0x8000000 noefi ip=off panic=5 quiet "
        "coredump_filter=0x9 mtdparts=physmap-flash.0:256k(RR_LOG),512k(mtdoops),16M(plog),16M(trace) "
        "intel_idle.max_cstate=2 pcie_ports=native nopat mtdoops.dump_oops=0 "
        "slub_debug=- cpuidle.off=1 libata.force=rstonce eagerfpu=on "
        "no_startup_cfg=yes module.sig_enforce=1 irqpoll pci=noaer"
    ),
    "cmdline_notes": {
        "noefi": "UEFI disabled; boots via legacy BIOS path; no UEFI Secure Boot; no Boot Guard",
        "module.sig_enforce=1": "Kernel module signature enforcement ENABLED (positive control)",
        "slub_debug=-": "SLUB heap allocator debugging disabled; no red zones/poison/use-after-free detection",
        "pci=noaer": "PCIe Advanced Error Reporting disabled; PCIe hardware errors undetected/unlogged",
        "coredump_filter=0x9": "Crash dumps include anonymous private+shared memory; keys/tokens/session data in core dumps",
        "root=/dev/ram0": "Root filesystem is read-write RAM disk; no dm-verity; in-memory modification possible",
        "mtdparts": "Exposes flash partition layout: 256KB(RR_LOG), 512KB(mtdoops), 16MB(plog), 16MB(trace)",
        "no_startup_cfg=yes": "FI never loads local startup config; UCSM is authoritative configuration source",
        "eagerfpu=on": "Eager FPU save/restore ON; mitigates CVE-2018-3665 FPU information disclosure",
        "nopat": "PAT (Page Attribute Table) disabled; NOT nopti -- Meltdown mitigation active",
    },
    "mtd_flash_partitions": {
        "RR_LOG": "256KB -- Router Reboot Log (crash/reset context)",
        "mtdoops": "512KB -- Kernel oops dump (mtdoops.dump_oops=0 disables writing oops to flash)",
        "plog": "16MB -- Persistent system log",
        "trace": "16MB -- Trace/debug buffer",
        "device": "physmap-flash.0",
    },
    "identical_across_platforms": ["6400", "6500", "6600", "x-direct"],
}

FEX_2400_SUMMERVILLE = {
    "file": "ucs-2400-6400.6.0.2b.bin",
    "codename": "Summerville",
    "swid": "swid-iocard-6400-summerville",
    "inner_format": "SN(gzip) -> TAR -> blob (377MB)",
    "blob_magic": "55aa0007",
    "strings_in_blob": 591071,
    "certificate_dn": "-CN=CiscoSystems;OU=Summerville;O=CiscoSystems",
    "kernel_kaslr": "KASLR disabled: 'nokaslr' on cmdline.",
    "secondary_kaslr_msg": "Physical KASLR disabled: no suitable memory region!",
    "uefi_state": "EFI system table not found",
    "fpga_file": "fpga_signed_nomcu_rsu.rpd",
    "fpga_notes": "Intel/Altera FPGA, signed bitstream, RSU (Remote System Update) capability; in-service FPGA reprogram",
    "scripts": ["ciscosundownpkg.sh", "debugpkg.sh", "diagpkg.sh"],
    "trust_mechanism": {
        "DCBG_IOM_Consent_Tokens": "I/O Module consent token system for FEX-to-FI trust establishment",
        "utok_keyhash": "User/universal token key hash; near hotham ASIC codename",
        "SDTNonces": "Secure Device Token nonce-based authentication",
        "pubkeyhash": "Public key hash for firmware verification",
        "hotham": "ASIC codename candidate (near utok_keyhash context)",
    },
    "other_strings": ["bootpoltype", "bootpolres", "UserDefFCon", "modmem_comp_bypass_seq"],
}

FEX_2500_SKAGITRIVER = {
    "file": "ucs-2500-6400.6.0.2b.bin",
    "codename": "Skagit River",
    "swid": "swid-iocard-6400-skagitriver",
    "inner_format": "SN(gzip) -> TAR -> blob",
    "note": "Surface-level scan only; deeper analysis pending disk extraction",
}

UCSM_BINARY = {
    "file": "ucs-manager-k9.6.0.2b.bin",
    "size_mb": 1024,
    "format": "SN(gzip) wrapper; inner format pending extraction",
    "sn_hsize": 748,
    "note": "1GB UCSM binary; deeper analysis pending disk extraction",
}

MODULE_SUMMARY = {
    "module": "cisco_ucs_fi_infrastructure_re",
    "bundles": ["ucs-6400/6500/6600-k9-bundle-infra.6.0.2b.A.bin", "ucs-x-direct-k9-infra.6.0.2b.A.bin"],
    "findings": [
        {
            "id": "FI-INFRA-F1",
            "severity": "MEDIUM",
            "title": "FI_NX_OS_NOEFI_NO_UEFI_SECURE_BOOT",
            "detail": (
                "All four FI platforms (6400/6500/6600/X-Direct) boot NX-OS via mknbi-linux-1.2-6 "
                "with 'noefi' kernel parameter, disabling UEFI and using legacy BIOS path. "
                "No UEFI Secure Boot, no Boot Guard, no UEFI-layer cryptographic verification of bootloader. "
                "mknbi-linux-1.2-6 is a legacy PXE boot format from 2002-era tools. "
                "Boot chain: FI ROM -> mknbi loader -> Linux 5.10.216 (built 2026-03-01) -> initramfs -> NX-OS. "
                "module.sig_enforce=1 enforces kernel module signing, but chain of trust does not "
                "extend above the kernel -- the kernel itself is loaded from flash without UEFI verification. "
                "A tampered mknbi image on the boot flash would boot without detection."
            ),
        },
        {
            "id": "FI-INFRA-F2",
            "severity": "MEDIUM",
            "title": "FEX_2400_SUMMERVILLE_NOKASLR_KERNEL",
            "detail": (
                "FEX 2400 Series (codename: Summerville) runs embedded Linux with KASLR explicitly disabled "
                "via 'nokaslr' kernel boot parameter. Confirmed by kernel dmesg string: "
                "'KASLR disabled: nokaslr on cmdline.' and secondary: 'Physical KASLR disabled: no suitable memory region!'. "
                "Also: 'EFI system table not found' confirms no UEFI on FEX. "
                "Without KASLR, kernel addresses are deterministic, eliminating the need for KASLR-bypass "
                "in exploit chains targeting the FEX. Any vulnerability with arbitrary read or ROP gadget reuse "
                "on the FEX works without KASLR offset leaks."
            ),
        },
        {
            "id": "FI-INFRA-F3",
            "severity": "LOW",
            "title": "FEX_IOM_CONSENT_TOKEN_TRUST_SYSTEM_STRINGS",
            "detail": (
                "FEX 2400 blob contains token-based FEX trust mechanism strings: "
                "'DCBG_IOM_Consent_Tokens' (I/O Module consent token system), "
                "'utok_keyhash' (token key hash), 'SDTNonces' (Secure Device Token nonce auth), "
                "'pubkeyhash' (public key hash for firmware verify). "
                "Context around 'utok_keyhash': 'hotham' (ASIC codename candidate), 'SDTNonces', "
                "'dynregs', 'fia_mux', 'lockreg', 'permuob', 'preuob', 'prof10-13'. "
                "The combination of utok_keyhash + SDTNonces suggests nonce-based challenge-response "
                "for FEX-to-FI trust. If token keys are extractable from FEX flash, "
                "unauthorized FEX impersonation becomes possible."
            ),
        },
        {
            "id": "FI-INFRA-F4",
            "severity": "LOW",
            "title": "FEX_2400_FPGA_INTEL_RSU_IN_SERVICE_REPROGRAM",
            "detail": (
                "FEX 2400 (Summerville) firmware package contains 'fpga_signed_nomcu_rsu.rpd' -- "
                "an Intel/Altera FPGA bitstream (RPD = Raw Programming Data) with RSU (Remote System Update) "
                "capability. RSU enables in-service FPGA reprogramming without power cycle. "
                "Bitstream is signed ('fpga_signed_nomcu_rsu' prefix). "
                "Associated with 'diagpkg.sh' -- the diagnostic package triggers FPGA updates. "
                "If diagpkg.sh is triggerable via UCSM or FEX management interface without authentication, "
                "RSU provides in-service FPGA firmware injection path."
            ),
        },
        {
            "id": "FI-INFRA-F5",
            "severity": "LOW",
            "title": "ALL_4_FI_PLATFORMS_IDENTICAL_INNER_SOFTWARE",
            "detail": (
                "ucs-6400, ucs-6500, ucs-6600, and ucs-x-direct bundles all contain identical "
                "inner components: ucsfi.10.5.1.I60.2b.F.bin (1515MB), ucs-manager-k9.6.0.2b.bin (1024MB), "
                "ucs-2500-6400.6.0.2b.bin (393MB). FEX 2400 (343MB) absent from X-Direct. "
                "No platform-specific build, no hardware binding below the SN wrapper. "
                "Cross-platform vulnerability: a firmware exploit against one FI platform applies to all four."
            ),
        },
        {
            "id": "FI-INFRA-F6",
            "severity": "LOW",
            "title": "NX_OS_KERNEL_CMDLINE_SECURITY_PARAMETERS",
            "detail": (
                "Full FI NX-OS kernel cmdline exposes several security-relevant parameters: "
                "'slub_debug=-' disables SLUB heap allocator debugging (no red zones, poison, UAF detection). "
                "'pci=noaer' disables PCIe Advanced Error Reporting (PCIe hardware/DMA errors undetected). "
                "'coredump_filter=0x9' includes anonymous private+shared memory in crash dumps "
                "(encryption keys, TLS state, tokens potentially captured in core). "
                "'mtdparts=physmap-flash.0:256k(RR_LOG),512k(mtdoops),16M(plog),16M(trace)' "
                "reveals full internal flash partition layout and sizes in plain text. "
                "'no_startup_cfg=yes' hardcoded: FI always boots without local startup config; "
                "UCSM is sole configuration authority."
            ),
        },
        {
            "id": "FI-INFRA-F7",
            "severity": "LOW",
            "title": "FEX_PRODUCTION_FIRMWARE_CONTAINS_DEBUG_SCRIPTS",
            "detail": (
                "FEX 2400 (Summerville) production firmware bundle contains shell scripts "
                "in the deployed image: 'ciscosundownpkg.sh', 'debugpkg.sh', 'diagpkg.sh'. "
                "debugpkg.sh = debug package manager; diagpkg.sh = diagnostic package; "
                "ciscosundownpkg.sh = 'sundown' (decommission/retire) package handler. "
                "These scripts could provide privileged execution paths if accessible "
                "via the FEX CLI or UCSM management interface."
            ),
        },
        {
            "id": "FI-INFRA-F8",
            "severity": "LOW",
            "title": "FEX_CERTIFICATE_DN_EXPOSES_SUMMERVILLE_CODENAME",
            "detail": (
                "X.509 certificate embedded in FEX 2400 firmware has Subject DN: "
                "'-CN=CiscoSystems;OU=Summerville;O=CiscoSystems'. "
                "OU=Summerville discloses the internal FEX 2400 platform codename in a production certificate. "
                "Also: FEX 2500 SWID tag 'swid-iocard-6400-skagitriver' discloses 'Skagit River' codename. "
                "FEX 2400 SWID: 'swid-iocard-6400-summerville'. "
                "ucsfi NX-OS version tag: '6.0(2b)A', SP version: '6.0(2)SP0'."
            ),
        },
    ],
    "finding_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 6},
    "cumulative_counts": {"CRITICAL": 54, "HIGH": 179, "MEDIUM": 165, "LOW": 145},
    "cumulative_total": 543,
    "codenames_discovered": {
        "FEX_2400_6400": "Summerville",
        "FEX_2500_6400": "Skagit River (Skagit River)",
    },
    "kernel": "Linux 5.10.216 built 2026-03-01 (nxbld@bes240223232923)",
}
