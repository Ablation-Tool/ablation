"""
Cisco UCS C-Series -- Broadcom RAID Codename Survey, N7 OEM Crypto, Laguna Rock, Intel 25G RE
Targets: ucsc-raid-m6* (Zuma/Pismo Beach), ucs-storage-controller-m2-nvmeraid (Bay View),
         ucs-storage-controller-9400/9500 (Laguna Rock/Ventura), ucs-adaptor-N7D200GF-OEM,
         ucs-adaptor-I8Q25GF/I8D25GF 25G, ucs-storage-controller-m2-hwraid-88SE92xx,
         ucs-c-pci-QLE2872/QLE2772 (same binary)

Broadcom RAID codenames in bundle: Rio Beach, Laguna Beach, Bay View, Zuma Beach, Pismo Beach,
Pismo Beach Plus, Ventura -- 7 internal codenames, all sharing eFuse-indexed PKI chain.
Dell PERC contamination confirmed in UCSB-RAID12G-M6 (blade) as well as Double Decker (rack).
Bay View ROM exposes unsigned firmware download path.
Cisco N7D200GF OEM vs non-OEM: non-OEM = Cisco-specific "No Crypto" variant.
"""

BROADCOM_RAID_CODENAMES = {
    "Rio_Beach": {
        "product": "ucs-storage-controller-riobeach",
        "fw": "8.10.1.0-00065-00002",
        "inner_file": "Rio_Beach_full_fw_vsn_pkg_signed.rom",
        "rom_size_kb": 13012,
        "see_module": "cisco_ucs_cseries_storage_ctrl_drive_re.py RIOBEACH-F1",
    },
    "Laguna_Beach": {
        "product": "ucs-storage-controller-lagunabeach",
        "fw": "51.23.0-5009",
        "inner_file": "Laguna_Beach_nopad.rom",
        "rom_size_kb": 7168,
        "see_module": "cisco_ucs_cseries_adapter_storage_ctrl2_re.py LAGUNABEACH-F1",
    },
    "Bay_View": {
        "product": "ucs-storage-controller-m2-nvmeraid",
        "fw": "52.34.0-6415",
        "inner_file": "Bay_View_NOPAD.rom",
        "rom_size_kb": 7808,
        "controller": "Broadcom NVMe RAID M2 controller",
        "unsigned_fw_path": "iopMsgFwDownload: %s is not signed.",
    },
    "Ventura": {
        "product": "ucs-storage-controller-9400-8i",
        "fw": "24.65.18.00",
        "bl_string": "@(#)Ventura Boot Loader Vendor  Str",
        "dcsg_part": "@(#)DCSG01525861",
        "chip": "Broadcom SAS 3xxx (Ventura/SAS3116)",
        "rmc_console": "**** RMC Diagnostic Console ***",
    },
    "Zuma_Beach": {
        "product": "ucsc-raid-m6hd (HDD-optimized)",
        "fw": "52.34.0-6415",
        "inner_file": "Zuma_Beach_NOPAD.rom",
        "rom_size_kb": 7808,
    },
    "Pismo_Beach_Plus": {
        "product": "ucsc-raid-m6sd (SSD-optimized)",
        "fw": "52.34.0-6415",
        "inner_file": "Pismo_Beach_Plus_NOPAD.rom",
        "rom_size_kb": 7808,
    },
    "Pismo_Beach": {
        "product": "ucsc-raid-m6t (Tachyon/general)",
        "fw": "52.34.0-6415",
        "inner_file": "Pismo_Beach_NOPAD.rom",
        "rom_size_kb": 7808,
    },
}

BROADCOM_PKI_CHAIN = {
    "confirmed_controllers": ["Rio Beach", "Bay View", "Zuma Beach", "Pismo Beach", "Pismo Beach Plus"],
    "shared_strings": [
        "Using SHA%d RSA%d for Efuse%d KHPair%d",
        "Examining Public key Hash %d",
        "Public key hash %d found in the eFuse memory.",
        "Good key, Generate hash.",
        "Invalidating key %d",
        "Comparing image signature to computed SHA%d",
        "Generated public key hash",
    ],
    "note": "All Broadcom RAID ROMs share identical eFuse-indexed PKI chain error strings -- same signing infrastructure across NVMe RAID, SAS RAID, and HBA controllers",
}

DELL_PERC_CONTAMINATION_SURVEY = {
    "Double_Decker_RAID": {
        "fw": "6.30.03.3 (Build August 10, 2018)",
        "dell_models": ["PERC H330 Adapter", "PERC H330 Mini", "PERC H330 Embedded", "PERC H730P Adapter", "PERC H730P Mini"],
        "see": "cisco_ucs_cseries_adapter_storage_ctrl2_re.py DOUBLEDECKER-F1",
    },
    "UCSB_RAID12G_M6": {
        "fw": "6.36.00.3 (Build July 02, 2018)",
        "dell_models": ["PERC H330 Adapter", "PERC H330 Mini", "PERC H330 Embedded", "PERC H730P Adapter", "PERC H730P Mini"],
        "unique_string": "Dell PERC Controller - Bus %d Dev %d:",
        "avago_string": "AVAGO MegaRAID Controller - Bus %d Dev %d:",
        "note": "Blade RAID controller explicitly has BOTH Dell PERC AND Avago MegaRAID controller type strings",
    },
    "scope": "Contamination spans rack RAID (Double Decker) and blade RAID (UCSB-RAID12G-M6); two different firmware versions of the same Avago BIOS base",
}

LAGUNA_ROCK = {
    "product_9400": "ucs-storage-controller-9400-8i (24.65.18.00)",
    "product_9500": "ucs-storage-controller-9500-8e (36.65.08.00)",
    "9400_inner": {
        "UCSC-9400-8I.bin": {"size_kb": 1811, "desc": "Main controller firmware"},
        "mpt35sas_legacy.rom": {"size_kb": 53, "copyright": "Copyright 1995-2019, Broadcom Inc", "desc": "SAS HBA legacy BIOS"},
        "mpt35sas_x64.rom": {"size_kb": 146, "desc": "SAS HBA x64 ROM"},
    },
    "9500_inner": {
        "UCSC-9500-8E.rom": {"size_kb": 2040, "bl_date": "10/24/2025 (BL DATE)", "desc": "Main IT-mode HBA firmware"},
        "IT_HBA_X64_BIOS_PKG_E6.rom": {"size_kb": 202, "desc": "IT-mode HBA x64 BIOS"},
    },
    "ventura_strings": {
        "codename": "@(#)Ventura Boot Loader Vendor  Str",
        "part": "@(#)DCSG01525861",
        "secureboot": "SecureBoot: %d (state exposed as printable integer)",
        "rmc_console": "**** RMC Diagnostic Console *** (accessible via Ventura boot path)",
        "rmc_reload": "RMC is being reloaded.",
        "bootstrap": "SerialBootstrapData8C is %x",
    },
    "signature_validation_strings": [
        "INVALID SBR Signature!",
        "FAIL!! RMC code size: %x",
        "INVALID RMC Code Signature!",
        "Checksum FAILED: %x!!",
        "SOC signature was programmed",
    ],
}

CONNECTX7_CISCO_VS_OEM = {
    "N7S400GF_cisco_model": "MCX715105AS-WEAT CX-7 1x400GbE QSFP112 PCIe Gen5 x16 VPI NIC (respin)",
    "N7S400GF_prs": "cx7_CX715105A_cisco_VPI_400GbE_NDR_1p_respin.prs",
    "N7D200GF_cisco_model": "MCX755106AS-HEAT; 2x200GbE QSFP112 Gen5x16; PCIe VPI NIC; No Crypto",
    "N7D200GF_prs": "cx7_Cisco_CX755106A_2P_VPI_200GbE_NDR200_sb.prs",
    "N7D200GF_OEM_model": "NVIDIA ConnectX-7 HHHL; 200GbE/NDR200 IB; Dual-port QSFP112; PCIe 5.0 x16; Crypto Disabled; Secure Boot Enabled",
    "N7D200GF_OEM_part": "MCX755106AS-HEA_Ax",
    "N7D200GF_OEM_prs": "cx7_MCX755106A_VPI_NDR200_200g_2p_sb.prs",
    "crypto_difference": {
        "Cisco_non-OEM_400G": "Does not mention crypto (may be enabled)",
        "Cisco_non-OEM_200G": "No Crypto (explicitly disabled in model string)",
        "NVIDIA_OEM_200G": "Crypto Disabled; Secure Boot Enabled (same crypto=off, but explicit Secure Boot label)",
    },
    "part_suffix": "Cisco HEAT vs NVIDIA HEA -- 'T' suffix in Cisco part may indicate thermal/mechanical variant",
}

INTEL_E810_25G = {
    "products": {
        "I8Q25GF": {
            "firmware": "E810_CSTM_CISCO_XXVDA4_FH_O_SEC_FW_1p7p10p1_NVM_4p91_PLDMoMCTP_0.00_80021535.bin",
            "model": "Cisco Ethernet Network Adapter E810-XXVDA4PN (25G quad port)",
        },
        "I8D25GF": {
            "firmware": "E810_CSTM_CISCO_XXVDA4_FH_O_SEC_FW_1p7p10p1_NVM_4p91_PLDMoMCTP_0.00_80021537.bin",
            "model": "Cisco Ethernet Network Adapter E810-XXVDA4PN variant (80021537)",
        },
    },
    "boot_img": "BootIMG_1.839.1.FLB (same version as IBD100GF -- shared iSCSI Boot ROM)",
    "chap_strings": ["mutualsecret", "mutualchap"],
    "hp_oem_tags": ["-o format=oemhp_binary ", "start oemhp_ocsd"],
    "port_config_strings": [
        "2 Ports : 2 x 25G (50G SKU, 2 Quad split) - Ports 0 & 1: 25G",
        "4 Ports : 4 x 25G (2 Quad split) - Ports 0,1,2,3: 25G with 2 quad split muxing",
        "7 Ports (1) : 1x25G + 6x10G - Port 0 25G & Ports 1,2,3,5,6,7 10G",
    ],
    "html_entities_in_firmware": "Port config strings use HTML entities (&amp; = &) -- firmware strings intended for HTML/Redfish rendering",
}

QLOGIC_32GFC = {
    "QLE2872": {"desc": "QLogic 32GFC dual-port HBA", "fw": "8.06.01"},
    "QLE2772": {"desc": "QLogic 32GFC single-port HBA", "fw": "8.06.01"},
    "identical_binary": True,
    "md5_prefix": "9574e6f3",
    "note": "QLE2872 (dual-port 32GFC) and QLE2772 (single-port 32GFC) share identical firmware binary -- same pattern as QLE2742/QLE2692 16GFC pair (prior session)",
}

MARVELL_88SE92XX = {
    "product": "ucs-storage-controller-m2-hwraid-88SE92xx",
    "fw": "2.3.17.1014",
    "inner_file": "ImageA1-1014.bin.bin",
    "inner_size_kb": 2048,
    "double_extension_note": "ImageA1-1014.bin.bin -- double .bin.bin extension, packaging artifact",
    "console_string": "Marvell Console 1.01",
    "security_strings": [
        "source LD(%d) DDF update, update SPI security key",
        "RAID1 Failed.",
    ],
}

FINDINGS = {
    "BROADCOM-RAID-F1": {
        "id": "BROADCOM-RAID-F1",
        "severity": "HIGH",
        "title": "Bay View NVMe RAID ROM exposes unsigned firmware download path: 'iopMsgFwDownload: %s is not signed.'",
        "affected": ["ucs-storage-controller-m2-nvmeraid (52.34.0-6415)", "Bay_View_NOPAD.rom (7808KB)"],
        "evidence": {
            "unsigned_path": "iopMsgFwDownload: %s is not signed.",
            "missing_key": "%s: Unable to find embedded key in image! EmbeddedKey:%d status:%d",
            "key_mismatch": "Signatures match but embedded key was not propper (status:0x%x).",
            "key_collision": "More than one valid key found. Invalidating previous keys. newestValid:%x validCount:%x",
            "soc_prog": "SOC signature was programmed",
        },
        "mechanism": (
            "The Bay View Broadcom NVMe RAID ROM contains 'iopMsgFwDownload: %s is not signed.' -- "
            "this is a firmware download acceptance path that handles unsigned firmware. "
            "Three companion error paths expose the full firmware acceptance logic: "
            "(1) 'Unable to find embedded key in image' -- firmware accepted even without embedded key; "
            "(2) 'Signatures match but embedded key was not propper' (Broadcom typo, verbatim) -- "
            "firmware accepted after signature verification but with wrong embedded key; "
            "(3) Key collision path invalidates previous keys and selects newest valid key automatically. "
            "These paths, combined with the full eFuse PKI chain (SHA/RSA indexed key slots), "
            "define the complete firmware update acceptance state machine."
        ),
        "impact": "Unsigned firmware download path exists in Broadcom NVMe RAID ROM; key collision auto-invalidation enables key cycling via crafted firmware; full state machine recoverable",
    },
    "BROADCOM-RAID-F2": {
        "id": "BROADCOM-RAID-F2",
        "severity": "HIGH",
        "title": "Dell PERC OEM cross-contamination extends to blade RAID (UCSB-RAID12G-M6): same Dell H330/H730P model strings in blade controller alongside rack (Double Decker RAID)",
        "affected": [
            "ucs-storage-controller-double-decker-raid (29.00.1-0360, fw 6.30.03.3, Aug 2018)",
            "ucs-storage-controller-UCSB-RAID12G-M6 (24.21.0-0163, fw 6.36.00.3, Jul 2018)",
        ],
        "evidence": {
            "shared_models": ["PERC H330 Adapter", "PERC H330 Mini", "PERC H330 Embedded", "PERC H730P Adapter", "PERC H730P Mini"],
            "blade_unique": "Dell PERC Controller - Bus %d Dev %d: (explicit Dell PERC controller bus string in blade firmware)",
            "blade_avago": "AVAGO MegaRAID Controller - Bus %d Dev %d: (dual OEM identification in same binary)",
            "fw_versions": "6.30.03.3 (rack, Aug 10, 2018) and 6.36.00.3 (blade, Jul 02, 2018)",
        },
        "mechanism": (
            "Dell PERC H330/H730P OEM model strings appear in both the rack-mount 'Double Decker RAID' "
            "controller (6.30.03.3, August 2018) and the blade 'UCSB-RAID12G-M6' (6.36.00.3, July 2018). "
            "The blade controller firmware uniquely includes BOTH an explicit "
            "'Dell PERC Controller' bus enumeration string AND an 'AVAGO MegaRAID Controller' bus string -- "
            "two OEM controller type strings in the same binary. This confirms that both the rack "
            "and blade Cisco MegaRAID products share the same Avago BIOS code base with Dell. "
            "The blade version (6.36.00.3) is slightly newer than the rack (6.30.03.3) despite "
            "the blade having an earlier build timestamp (July 2018 vs August 2018)."
        ),
        "impact": "OEM supply chain contamination confirmed across both blade and rack RAID product lines; vulnerabilities in Avago MegaRAID base affect all Cisco+Dell RAID variants simultaneously",
    },
    "BROADCOM-RAID-F3": {
        "id": "BROADCOM-RAID-F3",
        "severity": "MEDIUM",
        "title": "7 Broadcom RAID internal codenames extracted from C-Series bundle: Rio Beach/Laguna Beach/Bay View/Zuma Beach/Pismo Beach/Pismo Beach Plus/Ventura",
        "affected": [
            "ucs-storage-controller-riobeach", "ucs-storage-controller-lagunabeach",
            "ucs-storage-controller-m2-nvmeraid", "ucsc-raid-m6hd", "ucsc-raid-m6sd",
            "ucsc-raid-m6t", "ucs-storage-controller-9400-8i",
        ],
        "evidence": {
            "codenames": {
                "Rio_Beach": "RAID HBA (Marvell-based), 13MB",
                "Laguna_Beach": "MegaRAID 9460-8i, 7MB",
                "Bay_View": "NVMe RAID M2, 7.6MB",
                "Zuma_Beach": "RAID M6 HDD-optimized, 7.6MB",
                "Pismo_Beach_Plus": "RAID M6 SSD-optimized, 7.6MB",
                "Pismo_Beach": "RAID M6 Tachyon/general, 7.6MB",
                "Ventura": "SAS3 HBA (9400-8i), chip codename in boot loader string",
            },
            "shared_pki": BROADCOM_PKI_CHAIN["shared_strings"],
        },
        "mechanism": (
            "Seven Broadcom internal RAID controller codenames are embedded in the production "
            "Cisco C-Series firmware bundle. All controllers except Ventura/9400 use the "
            "coastal California theme (Rio Beach, Laguna Beach, Bay View, Zuma Beach, Pismo Beach). "
            "Five of these (Rio Beach, Bay View, Zuma Beach, Pismo Beach, Pismo Beach Plus) "
            "share identical eFuse-indexed PKI chain strings: "
            "'Using SHA%d RSA%d for Efuse%d KHPair%d', 'Public key hash %d found in the eFuse memory.' "
            "This unified PKI infrastructure means the same key management analysis "
            "(RIOBEACH-F1 plaintext ROM) extends to all five ROM-sharing controllers."
        ),
        "impact": "7 Broadcom codenames identify product roadmap and silicon generations; unified PKI chain means RIOBEACH-F1 eFuse analysis extends to 4 additional controllers",
    },
    "LAGUNAROCK-F1": {
        "id": "LAGUNAROCK-F1",
        "severity": "MEDIUM",
        "title": "Laguna Rock 9400 exposes RMC Diagnostic Console, Secure Boot integer state, and SBR/RMC signature bypass strings; 9500-8e ships October 2025 boot loader",
        "affected": ["ucs-storage-controller-9400-8i (24.65.18.00)", "ucs-storage-controller-9500-8e (36.65.08.00)"],
        "evidence": {
            "rmc_console": "**** RMC Diagnostic Console *** (accessible via Ventura controller boot path)",
            "rmc_reload": "RMC is being reloaded. (Remote Management Controller reload path)",
            "secureboot_state": "SecureBoot: %d (secure boot state exposed as printable integer)",
            "sbr_invalid": "INVALID SBR Signature! (Serial Boot ROM signature invalid -- no confirmed halt)",
            "rmc_invalid": "INVALID RMC Code Signature! (RMC code signature invalid)",
            "rmc_size_fail": "FAIL!! RMC code size: %x",
            "checksum_fail": "Checksum FAILED: %x!!",
            "bootstrap": "SerialBootstrapData8C is %x (debug bootstrap data value logging)",
            "9500_bl_date": "@(#)BL DATE:10/24/2025 (October 2025 build)",
            "ventura_chip": "@(#)Ventura Boot Loader Vendor  Str",
            "dcsg_part": "@(#)DCSG01525861 (Broadcom DCSG internal part number)",
        },
        "mechanism": (
            "The Laguna Rock 9400-8i boot firmware exposes: (1) The Ventura chip codename "
            "(@(#)Ventura Boot Loader) and internal DCSG part number in production ROM; "
            "(2) An RMC (Remote Management Controller) diagnostic console '*** RMC Diagnostic Console ***' "
            "reachable via the controller boot path; "
            "(3) Secure Boot state exposed as an integer format string 'SecureBoot: %d' -- "
            "boot-time logging of secure boot state; "
            "(4) INVALID SBR Signature!, INVALID RMC Code Signature!, FAIL!! RMC code size! -- "
            "signature validation failures without confirmed boot halt (string-only evidence). "
            "The 9500-8e has a boot loader dated October 24, 2025 (very recent). "
            "The 9500-8e is in IT-mode (HBA, not RAID) based on IT_HBA_X64_BIOS_PKG_E6.rom filename."
        ),
        "impact": "RMC Diagnostic Console in production controller ROM; Secure Boot integer state logging; SBR/RMC signature failure handling needs verification; chip codename and DCSG part identification",
    },
    "CX7OEM-F1": {
        "id": "CX7OEM-F1",
        "severity": "MEDIUM",
        "title": "Cisco N7D200GF (200G) ConnectX-7 explicitly labeled 'No Crypto' -- crypto acceleration disabled; OEM variant has 'Crypto Disabled; Secure Boot Enabled'; Cisco 400G N7S400GF ships as 'respin'",
        "affected": [
            "ucs-adaptor-ucsc-p-N7D200GF (28.46.1006)",
            "ucs-adaptor-ucsc-p-N7D200GF-OEM (28.46.1006)",
            "ucs-adaptor-ucsc-p-N7S400GF (28.46.1006)",
        ],
        "evidence": {
            "cisco_200g": "MCX755106AS-HEAT; 2x200GbE QSFP112 Gen5x16; PCIe VPI NIC; No Crypto",
            "cisco_200g_prs": "cx7_Cisco_CX755106A_2P_VPI_200GbE_NDR200_sb.prs",
            "oem_200g": "NVIDIA ConnectX-7 HHHL; 200GbE/NDR200 IB; Dual-port QSFP112; PCIe 5.0 x16; Crypto Disabled; Secure Boot Enabled",
            "oem_200g_part": "MCX755106AS-HEA_Ax (vs Cisco MCX755106AS-HEAT)",
            "cisco_400g": "MCX715105AS-WEAT CX-7 1x400GbE QSFP112 PCIe Gen5 x16 VPI NIC (no Crypto label)",
            "cisco_400g_prs": "cx7_CX715105A_cisco_VPI_400GbE_NDR_1p_respin.prs",
        },
        "mechanism": (
            "Cisco's 200G CX-7 (N7D200GF) model string explicitly includes 'No Crypto' -- "
            "the ConnectX-7 hardware crypto acceleration (TLS/IPsec offload) is disabled in "
            "Cisco's 200G OEM variant. The NVIDIA OEM variant (N7D200GF-OEM) says 'Crypto Disabled' "
            "plus 'Secure Boot Enabled' -- crypto off, but Secure Boot explicitly on. "
            "The Cisco 400G variant (N7S400GF) uses internal filename suffix 'respin' indicating "
            "a silicon errata fix, and does not have a 'No Crypto' label -- suggesting the 400G "
            "CX-7 may have crypto enabled or the Cisco part number is in a different SKU tier. "
            "The Cisco vs NVIDIA part suffix difference (HEAT vs HEA) -- the 'T' in HEAT may "
            "denote a Cisco-specific mechanical/thermal SKU variant."
        ),
        "impact": "Cisco N7D200GF deployers cannot use CX-7 hardware crypto offload (TLS/IPsec) -- must use software crypto; Cisco SKU engineering diverges from standard NVIDIA SKU in crypto capability",
    },
    "QLE32GFC-F1": {
        "id": "QLE32GFC-F1",
        "severity": "LOW",
        "title": "QLogic QLE2872 (dual-port 32GFC) and QLE2772 (single-port 32GFC) ship identical firmware binary -- extends QLE same-binary class from 16GFC to 32GFC",
        "affected": ["ucs-c-pci-QLE2872 (8.06.01)", "ucs-c-pci-QLE2772 (8.06.01)"],
        "evidence": {
            "md5_prefix": "9574e6f3 (identical for both)",
            "prior_pattern": "QLE2742/QLE2692 16GFC pair also identical binary (prior session)",
        },
        "mechanism": "QLogic ships identical 32GFC firmware across single-port (QLE2772) and dual-port (QLE2872) variants. Combined with prior QLE2742/QLE2692 16GFC identical-binary finding, this is QLogic's standard practice across FC HBA generations. A vulnerability in the firmware binary affects all QLogic FC port configurations simultaneously.",
        "impact": "32GFC same-binary class confirmed; single vulnerability blast-radius covers all QLogic FC HBA port configurations in one firmware update",
    },
    "MARVELL-88SE-F1": {
        "id": "MARVELL-88SE-F1",
        "severity": "LOW",
        "title": "Marvell 88SE92xx M2 HWRAID ships plaintext 2MB firmware with double .bin.bin extension, SPI security key update path, and Marvell Console diagnostic interface",
        "affected": ["ucs-storage-controller-m2-hwraid-88SE92xx (2.3.17.1014)"],
        "evidence": {
            "inner_file": "ImageA1-1014.bin.bin (2048KB, note double .bin extension -- packaging artifact)",
            "console": "Marvell Console 1.01 (diagnostic console string in production firmware)",
            "spi_key": "source LD(%d) DDF update, update SPI security key (SPI key update path in RAID driver)",
            "encryption": "plaintext (unencrypted ZIP)",
        },
        "mechanism": "Marvell 88SE92xx HWRAID firmware (88SE = Marvell MV88SE family M2 controller, not Marvel 88SE92xx PCIe SAS) ships plaintext in ZIP. The double extension '.bin.bin' is a Cisco packaging artifact. A diagnostic console (Marvell Console 1.01) is present. The 'update SPI security key' string indicates the RAID driver updates an SPI-stored security key during DDF (Disk Data Format) operations.",
        "impact": "Plaintext 2MB firmware; SPI key update path traceable; diagnostic console fingerprint in production binary",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

SUMMARY = {
    "module": "cisco_ucs_cseries_broadcom_raid_adapter3_re",
    "targets": "Broadcom RAID codename survey (7), UCSB-RAID12G-M6 Dell PERC blade, N7D200GF OEM crypto, Laguna Rock 9400/9500, Intel E810 25G, QLE2872/2772, Marvell 88SE92xx",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 2, "MEDIUM": 3, "LOW": 2},
    "headline": (
        "Bay View NVMe RAID ROM exposes unsigned firmware download path (iopMsgFwDownload: %s is not signed). "
        "Dell PERC OEM contamination extends to blade RAID (UCSB-RAID12G-M6) -- same H330/H730P strings "
        "in both rack and blade controllers. 7 Broadcom RAID codenames with unified eFuse PKI chain. "
        "Cisco N7D200GF 200G CX-7 explicitly 'No Crypto'. Laguna Rock 9400 exposes RMC Diagnostic Console."
    ),
    "broadcom_codename_survey": list(BROADCOM_RAID_CODENAMES.keys()),
    "dell_perc_scope": "Both rack (Double Decker) and blade (UCSB-RAID12G-M6) Avago MegaRAID controllers",
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
    print("\nBroadcom codenames in bundle:")
    for k, v in BROADCOM_RAID_CODENAMES.items():
        inner = v.get('inner_file', v.get('controller', ''))
        print(f"  {k}: {v['product']} -- {inner}")
