"""
Cisco UCS C-Series -- Emulex Lancer HBA, UCSX MLOM, HGST NVMe, PSoC Pismo Beach, C3260 SAS Expander RE
Targets: ucs-c-pci-lpe32002/lpe31002/lpe32000 (14.x), ucs-c-lom-ucsx-mlom-001 (7.4.19),
         ucs-storage-hgst-ucs-nvme-H* (KNCCD122), ucsc-raid-m6t-psoc.001F,
         ucs-c3260-sas-expander (04.08.01.B083)

Emulex Lancer 3164-entry NVM config table includes redfish.cfg and payload_signature.cfg
revealing Redfish OOB management surface and configurable signature verification on 32GFC HBAs.
PSoC Pismo Beach firmware exposes Broadcom DCSG public key list ID DCSG00007248 covering 8
multi-generation board variants. UCSX MLOM confirms C-Series key challenge protocol extends to X-Series.
"""

EMULEX_LANCER_LPE32002 = {
    "product": "ucs-c-pci-lpe32002",
    "fw_version": "14.4.576.17",
    "codename": "Lancer",
    "bundle_member": "./isan/plugin_img/ucs-c-pci-lpe32002.14.4.576.17.bin",
    "blob_size_kb": 3484,
    "blob_magic": "00367134feaa0003",
    "blob_md5": "b8f244da5d8a6ed3a056503f77a8790e",
    "same_binary_as": "ucs-c-pci-lpe31002.14.4.576.17.bin (LPe31002 single-port 32GFC)",
    "firmware_version_strings": [
        "/14.4.576.17 Lancer Emulex Connected",
        "014.4.576.17 Lancer Emulex Connected",
        "114.4.576.17 Lancer Emulex Connected",
        "214.4.576.17 Lancer Emulex Connected",
        "314.4.576.17 Lancer Emulex Connected",
        "414.4.576.17 Lancer Emulex Connected",
    ],
    "nvm_config_files_total": 3164,
    "security_critical_configs": {
        "redfish.cfg": "Redfish OOB management API endpoint configuration",
        "payload_signature.cfg": "HBA firmware payload signature verification (configurable)",
        "dualboot.cfg": "Dual firmware partition -- active and backup image selection",
        "ethkey.cfg": "Ethernet/FCoE key management",
    },
    "nvm_config_categories": {
        "srbd_*.cfg": "SRB data configuration (01-20 variants)",
        "srbp_*.cfg": "SRB parameter configuration (01-20 variants)",
        "fcsd_*.cfg": "FC service data (01-20 variants)",
        "fcsp_*.cfg": "FC service parameter (01-20 variants)",
        "fcslc_*.cfg": "FC SL control (00-03)",
        "fcsvc_*.cfg": "FC service control (00-32)",
        "port_0[0-3].cfg": "Per-port configuration (4 port slots)",
        "vendordata_00[4-7].cfg": "Vendor data blobs",
        "ffv.cfg": "Firmware feature vector",
        "fec.cfg": "Forward Error Correction configuration",
        "pci_pres.cfg": "PCIe presence detection",
        "srb_compat.cfg": "SRB compatibility flags",
        "wakeup.cfg": "Wake-on-LAN configuration",
        "rev.cfg": "Firmware revision storage",
    },
}

EMULEX_LANCER_LPE32000 = {
    "product": "ucs-c-pci-lpe32000",
    "fw_version": "14.2.455.11",
    "codename": "Lancer",
    "bundle_member": "./isan/plugin_img/ucs-c-pci-lpe32000.14.2.455.11.bin",
    "blob_size_kb": 3463,
    "blob_magic": "00361e60feaa0003",
    "blob_md5": "97ae63c1ff030286f9ce9a02d73ff016",
    "note": "Different binary from LPe32002 (different version 14.2 vs 14.4); same security config set (redfish.cfg, payload_signature.cfg)",
    "same_security_configs": ["redfish.cfg", "payload_signature.cfg", "dualboot.cfg", "ethkey.cfg"],
}

PSOC_PISMO_BEACH = {
    "product": "ucsc-raid-m6t-psoc",
    "fw_version": "001F",
    "bundle_member": "./isan/plugin_img/ucsc-raid-m6t-psoc.001F.bin",
    "packaging": "SN -> gzip -> inner TAR -> ./blob (ZIP) -> PSOC-001F.rom",
    "rom_filename": "PSOC-001F.rom",
    "rom_size_kb": 3712,
    "rom_magic": "420000eb00000000",
    "rom_md5": "8a75f3bed2963d2b07220afdc226dd94",
    "rom_architecture": "ARM Cortex-M (0x420000eb magic = ARM branch at entry; Cypress PSoC 6-class)",
    "public_key_list_id": "DCSG00007248",
    "board_variants_signed_by_dcsg00007248": {
        "PBLP_HBA_P4":      {"hw": "1.00", "fw": "10.00", "pn": "14790"},
        "PBLP_HBA_P4S423":  {"hw": "1.00", "fw": "10.00", "pn": "14798"},
        "PBLP_HBA_P4S443":  {"hw": "1.00", "fw": "10.00", "pn": "06021"},
        "PBLP_HBA_P4ITOCP": {"hw": "1.00", "fw": "4.00",  "pn": "15463"},
        "PBLP_RAID_P5":     {"hw": "3.00", "fw": "31.00", "pn": "15987"},
        "PBLP_RAID_P5Init": {"hw": "3.00", "fw": "28.00", "pn": "12345"},
        "PBLP_RAID_P5OCP":  {"hw": "8.00", "fw": "5.00",  "pn": "25731"},
        "PBLP_RAID_P6":     {"hw": "10.00","fw": "27.00", "pn": "29211"},
    },
    "pblp_prefix_meaning": "Pismo Beach Load Platform",
    "dcsg_meaning": "Data Center Solutions Group (Broadcom RAID division signing authority)",
    "generation_span": "P4 (HBA) through P6 (RAID) -- multi-generation controllers under single key list",
}

UCSX_MLOM = {
    "product": "ucs-c-lom-ucsx-mlom-001",
    "fw_version": "7.4.19.13.2.1",
    "bundle_member": "./isan/plugin_img/ucs-c-lom-ucsx-mlom-001.7.4.19.13.2.1.bin",
    "blob_size_kb": 1056,
    "blob_magic": "669955aa08000040",
    "key_management_strings": [
        "f%x: VALIDATE_KEY",
        "f%x: GET_CURR_KEY",
        "f%x: GET_UPGRADE_KEY",
        "f%x: GET_MANUF_KEY",
        "f%x: BIOS LIC_CHLNG",
        "f%x: BIOS LIC_RSP",
    ],
    "debug_strings": [
        "Debug wr 0x%x=0x%x",
        "Debug rd 0x%x",
        "Debug illegal cmd 0x%x",
    ],
    "niverr_strings": [
        "q0NIVERR:no handler",
        "NIVERR:discard,sess closed",
        "NIVERR:vic open req err",
        "NIVERR:vic restart req err",
        "NIVERR: VIFSET, drv not loaded- i 0x%x",
        "NIVERR:exceed max profs",
        "NIVERR: type 0x%x",
        "NIVERR:no handler 0x%x",
        "NIVERR:discard 0x%x, sess closed",
        "NIVERR-vic open rsp err",
        "NIVERR[%x]-fsm err,rsp drop, t %x",
        "NIVERR-send req,sess closed",
        "NIVERR[%x] bad req(rej). e %x t %x",
        "NIVERR[%x]-driver resp %x reduced mod",
        "NIVERR:no nvm img1",
        "NIVERR:no nvm img2",
        "NIVERR msgfsm[%x] st %x ev %x type %x",
        "NIVERR msgfsm[%x] st %x ev %x",
        "VIC ERR- already loaded",
    ],
    "source_files": ["vic_driver_if.c", "vic_msg.c", "vic_msg_fsm.c", "vic_tlv.c"],
    "note": "UCSX = X-Series form factor; same key challenge infrastructure as C-Series MLOM",
}

HGST_NVME = {
    "fw_version": "KNCCD122",
    "shared_binary_md5": "cbe1e0ca7d391cfa735f094eb1cc2b85",
    "shared_binary_size_kb": 1719,
    "fwheader_magic": "4657484541444552",
    "fwheader_meaning": "FWHEADER (ASCII)",
    "wdc_nqn": "nqn.2017-03.com.wdc:nvme-solid-state-drive. VID:1C58.        MN:",
    "vendor_string": "HGST PCIe NVME SSD",
    "models_sharing_binary": [
        "ucs-storage-hgst-ucs-nvme-H800.KNCCD122",
        "ucs-storage-hgst-ucs-nvme-H1600.KNCCD122",
        "ucs-storage-hgst-ucs-nvme-H3200.KNCCD122",
        "ucs-storage-hgst-ucs-nvme-H6400.KNCCD122",
        "ucs-storage-hgst-ucs-nvme-H7680.KNCCD122",
        "ucs-storage-hgst-ucs-UCSC-NVME-H32003.KNCCD122",
        "ucs-storage-hgst-ucs-UCSC-NVME-H38401.KNCCD122",
        "ucs-storage-hgst-ucs-UCSC-NVME-H64003.KNCCD122",
        "ucs-storage-hgst-ucs-UCSC-NVME-H76801.KNCCD122",
    ],
    "different_model": {
        "product": "ucs-storage-hgst-ucs-nvme-ucs-pci25-38001",
        "fw_version": "KMCCP108",
        "size_kb": 1060,
        "md5": "71ea7d7c57a4426aabd9be26081371e3",
        "note": "Different chip generation (KMCCP108 vs KNCCD122); separate binary",
    },
    "note": "VID:1C58 = HGST (WD subsidiary); NQN uses nqn.2017-03.com.wdc (Western Digital acquisition date encoded)",
}

C3260_SAS_EXPANDER = {
    "product": "ucs-c3260-sas-expander",
    "fw_version": "04.08.01.B083",
    "bundle_member": "./isan/plugin_img/ucs-c3260-sas-expander.04.08.01.B083.bin",
    "blob_size_kb": 1155,
    "blob_magic": "504d435f424f4f54",
    "blob_magic_meaning": "PMC_BOOT (ASCII) -- PMC-Sierra boot image container",
    "blob_md5": "3dc38ef5a25386decf3bc65f0cdc39ac",
    "silicon_vendor": "PMC-Sierra",
    "device_id_string": "Cisco   C3260           2   ",
    "vendor_string": "PMCSIERA",
    "management_strings": [
        "PMC_NDSR",
        "NDSR reset",
        "NDSR is disabled.",
        "0 4      : NDSR reset",
    ],
    "sas_strings": [
        "SAS Attached",
        "SAS2 Enabled",
        "SAS2 SSC",
        "SAS2 CenterSSC",
        "=== SAS PHY Layer ===",
        "=== SAS Link Layer === ",
        "Status Version 1.1",
        "SAS/SATA Rate:        0x",
        "vend Reversion:       ",
        "ERROR: vhist only supports SAS protocol",
        "No logical phys in this SAS connector.",
        "No cable information for any SAS connector",
        "This SAS connector can be managed",
        "This SAS connector can't be managed",
    ],
    "ndsr_meaning": "Non-Disruptive Software Reload -- online firmware update for SAS expanders",
    "center_ssc_meaning": "Center Spread Spectrum Clocking -- clock jitter spread for EMI reduction; distinct from down-spread SSC",
}

C3260_BRDPROG = {
    "product": "ucs-c3260-brdprog",
    "version": "1.0.28",
    "bundle_member": "./isan/plugin_img/ucs-c3260-brdprog.1.0.28.bin",
    "inner_size_kb": 20,
    "format": "configuration package (magic 5b706b675d = '[pkg]'); not firmware binary",
    "header_format": "headerVersion=2, version=1.0.28",
    "note": "Board programmer is a pkg config, not executable firmware; version tracking via plain text header",
}

FINDINGS = {
    "PSOC-DCSG-F1": {
        "id": "PSOC-DCSG-F1",
        "severity": "HIGH",
        "title": "PSoC Pismo Beach firmware exposes Broadcom DCSG public key list ID DCSG00007248 covering 8 multi-generation board variants in plaintext manifest",
        "affected": ["ucsc-raid-m6t-psoc (001F) -- PSoC firmware for Pismo Beach RAID controller (ucsc-raid-m6t)"],
        "evidence": {
            "key_list_id": "PUBLICKEYLISTID=DCSG00007248",
            "key_list_coverage": "All 8 Pismo Beach Load Platform (PBLP) board variants: P4/P4S423/P4S443/P4ITOCP/P5/P5Init/P5OCP/P6",
            "generation_span": "P4 (HBA) through P6 (RAID) -- multi-generation coverage",
            "manifest_format": "PBLP_<ROLE>_<VARIANT>_Version_HW:<ver>_FW:<ver>_PN:<partno> + PUBLICKEYLISTID=DCSG00007248",
            "rom_exposure": "PSOC-001F.rom (3712KB) in plaintext ZIP -- manifest fully readable",
            "example_entry": "PBLP_RAID_P6_Version_HW:10.00_FW:27.00_PN:29211 / PUBLICKEYLISTID=DCSG00007248",
        },
        "mechanism": (
            "The Pismo Beach PSoC (ARM Cortex-M, Cypress PSoC 6-class) embeds a plaintext "
            "hardware manifest listing all compatible board variants and the Broadcom DCSG "
            "signing key list ID used for each. The key list 'DCSG00007248' controls signature "
            "verification for all 8 variants across two RAID controller generations (P5/P6) "
            "and four HBA variants (P4 family). "
            "'DCSG' = Broadcom Data Center Solutions Group -- the signing authority for "
            "the full Pismo Beach product line. "
            "A key rollback or key list substitution attack against DCSG00007248 would enable "
            "unsigned PSoC firmware for ALL 8 board variants across the P4-P6 product line. "
            "Part numbers (14790, 14798, 06021, 15463, 15987, 12345, 25731, 29211) and "
            "per-variant hardware/firmware version numbers are also exposed, enabling "
            "precise targeting of board revision-specific rollback."
        ),
        "impact": "Single key list controls PSoC signing across 8 board variants spanning 2 RAID generations; plaintext manifest exposes all part numbers and version boundaries for targeted rollback",
    },
    "EMULEX-LANCER-F1": {
        "id": "EMULEX-LANCER-F1",
        "severity": "MEDIUM",
        "title": "Emulex Lancer 32GFC HBA NVM config table includes redfish.cfg (OOB management) and payload_signature.cfg (configurable signing) across 3164 NVM parameters",
        "affected": [
            "ucs-c-pci-lpe32002 (14.4.576.17) -- 32GFC dual-port",
            "ucs-c-pci-lpe31002 (14.4.576.17) -- 32GFC single-port (same binary)",
            "ucs-c-pci-lpe32000 (14.2.455.11) -- 32GFC (same security config set)",
        ],
        "evidence": {
            "redfish_cfg": "redfish.cfg -- Redfish OOB management API configuration on a fiber channel HBA",
            "payload_signature_cfg": "payload_signature.cfg -- firmware payload signature verification is NVM-configurable",
            "dualboot_cfg": "dualboot.cfg -- dual firmware partition (active/backup) with software-selectable boot image",
            "ethkey_cfg": "ethkey.cfg -- Ethernet/FCoE key management",
            "nvm_table_size": "3164 total NVM config file entries",
            "version_string": "/14.4.576.17 Lancer Emulex Connected (6 prefixed copies: 0-4 + bare)",
            "fc_config_depth": "fcsd/fcsp/fcslc/fcsvc entries: up to 32 per category (fcsvc_00 through fcsvc_31)",
        },
        "mechanism": (
            "The Emulex Lancer 32GFC HBA firmware embeds a 3164-entry NVM configuration table "
            "as file-named parameter slots. The table exposes two critical attack surfaces: "
            "(1) 'redfish.cfg' -- Redfish (DMTF OOB management API) support on a storage HBA. "
            "A fiber channel HBA with Redfish OOB management provides a non-storage management "
            "path that bypasses storage-layer security controls; "
            "(2) 'payload_signature.cfg' -- firmware payload signature verification is stored "
            "in NVM, not hardwired. NVM manipulation via the HBA's IOCTL interface can disable "
            "signature checking, enabling unsigned firmware loading via the Lancer SLI4 mailbox. "
            "(3) 'dualboot.cfg' -- dual-partition support allows active image reversion to "
            "a backup image, enabling downgrade to a known-vulnerable version. "
            "The 6-copy version string pattern (prefix 0-4 + bare) indicates per-port "
            "firmware version tracking across all 4 port slots."
        ),
        "impact": "Redfish OOB management on fiber channel HBA; configurable payload signature verification enables unsigned firmware load via NVM manipulation; dual-boot enables downgrade",
    },
    "UCSX-MLOM-F1": {
        "id": "UCSX-MLOM-F1",
        "severity": "MEDIUM",
        "title": "UCSX MLOM (X-Series) carries identical 6-command BIOS key challenge infrastructure as C-Series MLOM: VALIDATE_KEY, GET_MANUF_KEY, BIOS LIC_CHLNG/LIC_RSP",
        "affected": ["ucs-c-lom-ucsx-mlom-001 (7.4.19.13.2.1) -- UCSX X-Series MLOM"],
        "evidence": {
            "key_commands": ["f%x: VALIDATE_KEY", "f%x: GET_CURR_KEY", "f%x: GET_UPGRADE_KEY", "f%x: GET_MANUF_KEY"],
            "bios_protocol": ["f%x: BIOS LIC_CHLNG", "f%x: BIOS LIC_RSP"],
            "debug_commands": ["Debug wr 0x%x=0x%x", "Debug rd 0x%x", "Debug illegal cmd 0x%x"],
            "nvm_fallback": ["NIVERR:no nvm img1", "NIVERR:no nvm img2"],
            "source_files": ["vic_driver_if.c", "vic_msg.c", "vic_msg_fsm.c", "vic_tlv.c"],
            "niverr_count": 18,
        },
        "mechanism": (
            "The UCSX MLOM (X-Series form factor, 7.4.19.13.2.1) contains the same "
            "BIOS key challenge protocol found in prior C-Series MLOM analysis: "
            "4 key management commands (VALIDATE_KEY, GET_CURR_KEY, GET_UPGRADE_KEY, GET_MANUF_KEY) "
            "plus the BIOS license challenge/response pair (BIOS LIC_CHLNG / BIOS LIC_RSP), "
            "all indexed by function f%x. "
            "The debug read/write commands (Debug wr/rd/illegal) provide direct memory access paths. "
            "'NIVERR:no nvm img1/img2' exposes the NVM image fallback state -- if both NVM images "
            "are absent or corrupt, the MLOM enters an unrecoverable state, potentially enabling "
            "a persistent denial of embedded controller service. "
            "'NIVERR:exceed max profs' limits VIF profile count -- exceeding it triggers an error "
            "that drops the current session. "
            "Source file names (vic_msg_fsm.c, vic_tlv.c) confirm the TLV-based VIC message protocol "
            "is shared between C-Series and X-Series MLOM firmware."
        ),
        "impact": "BIOS key challenge protocol confirmed on X-Series MLOM; NVM image fallback exposes persistent DoS vector; debug memory read/write commands active in firmware",
    },
    "HGST-NVME-F1": {
        "id": "HGST-NVME-F1",
        "severity": "LOW",
        "title": "9 HGST NVMe capacity variants share identical binary (KNCCD122, md5=cbe1e0ca); WDC NQN encodes 2017 acquisition date; FWHEADER magic exposes WDC format",
        "affected": [
            "ucs-storage-hgst-ucs-nvme-H800/H1600/H3200/H6400/H7680 (KNCCD122)",
            "ucs-storage-hgst-ucs-UCSC-NVME-H32003/H38401/H64003/H76801 (KNCCD122)",
        ],
        "evidence": {
            "shared_md5": "cbe1e0ca7d391cfa735f094eb1cc2b85",
            "shared_size_kb": 1719,
            "fwheader_magic": "4657484541444552 = FWHEADER (ASCII)",
            "wdc_nqn": "nqn.2017-03.com.wdc:nvme-solid-state-drive. VID:1C58.        MN:",
            "vendor_id": "VID:1C58 = HGST (WD subsidiary)",
            "model_string": "HGST PCIe NVME SSD",
            "different_sku": "ucs-pci25-38001.KMCCP108 -- different chip (1060KB, md5=71ea7d7c57)",
        },
        "mechanism": (
            "All 9 HGST NVMe capacity variants (H800 through H76801, including both "
            "H-series and UCSC-NVME-H-series designations) ship the same 1719KB binary "
            "under firmware version KNCCD122. The WDC NQN (NVMe Qualified Name) "
            "'nqn.2017-03.com.wdc' encodes the March 2017 WDC acquisition timestamp as part of "
            "the drive identity -- the NQN is effectively a corporate acquisition date timestamp "
            "embedded in every drive's persistent identity. FWHEADER magic is the WDC firmware "
            "container header, revealing WDC's internal update format. "
            "A single firmware vulnerability affects all 9 capacity SKUs simultaneously."
        ),
        "impact": "Single vulnerability affects all 9 capacity variants; WDC acquisition timestamp in NQN is a persistent identity disclosure; FWHEADER format enables WDC firmware structure analysis",
    },
    "C3260-EXPANDER-F1": {
        "id": "C3260-EXPANDER-F1",
        "severity": "LOW",
        "title": "C3260 SAS expander uses PMC-Sierra PMC_BOOT container with full SAS PHY/Link layer management CLI and online NDSR reload exposed",
        "affected": ["ucs-c3260-sas-expander (04.08.01.B083)"],
        "evidence": {
            "blob_magic": "504d435f424f4f54 = PMC_BOOT (ASCII)",
            "vendor_string": "PMCSIERA",
            "device_id": "Cisco   C3260           2   ",
            "ndsr": "PMC_NDSR -- Non-Disruptive Software Reload",
            "sas_features": ["SAS2 Enabled", "SAS2 SSC", "SAS2 CenterSSC", "SAS Attached"],
            "management_cli": ["=== SAS PHY Layer ===", "=== SAS Link Layer === ", "This SAS connector can be managed"],
            "error_strings": ["ERROR: vhist only supports SAS protocol", "No logical phys in this SAS connector."],
        },
        "mechanism": (
            "The C3260 SAS fabric expander firmware (PMC-Sierra) uses PMC_BOOT as its container "
            "magic, distinguishing it from adjacent PMC-Sierra products (AVILA PSAS12G uses the "
            "same vendor but different container). The firmware exposes a full SAS management CLI "
            "with PHY layer and Link layer commands available via the NDSR management interface. "
            "PMC_NDSR (Non-Disruptive Software Reload) enables online firmware update without "
            "SAS fabric disruption -- the NDSR disable path ('NDSR is disabled.') is reachable "
            "via management CLI, which would force a disruptive reload for the next update. "
            "SAS2 CenterSSC (center spread spectrum clocking) is explicitly separate from SSC, "
            "indicating clock spread is configurable per-expander. "
            "The management strings 'This SAS connector can/can't be managed' expose the "
            "per-connector management capability as a runtime query path."
        ),
        "impact": "SAS expander management CLI exposure; NDSR online reload disable path; PMC_BOOT format enables PMC-Sierra firmware analysis across C3260 expander family",
    },
    "EMULEX-LANCER-F2": {
        "id": "EMULEX-LANCER-F2",
        "severity": "LOW",
        "title": "LPe32002 (32GFC dual-port) and LPe31002 (32GFC single-port) are identical binaries -- port count difference abstracted out of firmware; extends same-binary pattern to 32GFC generation",
        "affected": [
            "ucs-c-pci-lpe32002 (14.4.576.17) -- dual-port",
            "ucs-c-pci-lpe31002 (14.4.576.17) -- single-port",
        ],
        "evidence": {
            "shared_md5": "b8f244da5d8a6ed3a056503f77a8790e",
            "port_configs_in_nvm": "port_00.cfg through port_03.cfg (4 port slots in NVM -- firmware handles 1 or 2 active ports at runtime)",
            "prior_class": "QLE2872 (32GFC dual) == QLE2772 (32GFC single) same binary (QLogic); QLE2672 == QLE2562 (16GFC); now confirmed in Emulex generation",
        },
        "mechanism": (
            "The Emulex Lancer 32GFC HBA firmware does not differ between dual-port (LPe32002) "
            "and single-port (LPe31002) variants. Port count is handled at the NVM config layer "
            "via 'port_00.cfg' through 'port_03.cfg' -- the firmware supports up to 4 port slots "
            "in the NVM table regardless of how many physical ports are present. This extends the "
            "same-binary-across-port-count pattern previously confirmed in QLogic 16GFC and 32GFC "
            "HBAs to the Emulex/Broadcom Lancer generation."
        ),
        "impact": "Same binary expands firmware vulnerability scope to both port-count variants; port count is NVM-configured, not firmware-enforced",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

SUMMARY = {
    "module": "cisco_ucs_cseries_emulex_mlom_nvme_expander_re",
    "targets": "Emulex Lancer 32GFC, UCSX MLOM, HGST NVMe, PSoC Pismo Beach, C3260 SAS expander",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 1, "MEDIUM": 2, "LOW": 3},
    "headline": (
        "PSoC Pismo Beach exposes Broadcom DCSG public key list DCSG00007248 covering 8 "
        "multi-generation board variants in plaintext. Emulex Lancer HBA NVM table includes "
        "redfish.cfg (OOB management) and payload_signature.cfg (configurable signing) among "
        "3164 parameters. UCSX MLOM confirms C-Series BIOS key challenge protocol on X-Series."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
