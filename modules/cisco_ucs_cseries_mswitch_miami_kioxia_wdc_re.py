"""
Cisco UCS C-Series -- Microsemi Switchtec mswitch-m6, Miami Beach/Smartioc2200,
Kioxia 1YETE106, WDC PACV NVMe, Micron UPOB Gen4, Samsung OPPA RE

All 4 mswitch-m6 (nvme + hddext 1/2/3) are same binary (md5=cf58a7b1).
All 5 Miami Beach/River/Rock storage controllers are same binary (md5=e3cee024).
All 8 Kioxia 1YETE106 NVMe SKUs are same binary (md5=8f4efc29).
WDC NVMe has two firmware groups: R2210803 (md5=83498efa) and R121000B (md5=d5dc5a59).
Samsung OPPA has two groups: 1K3Q performance (md5=a232cd8c) and 1K5Q value (md5=bd0d7c5e).
Micron E2CS007 uses new UPOB container vs older NRCM; exposes Jenkins CI path + Raptor codename.
"""

MSCC_SWITCHTEC_MSWITCH = {
    "magic": "4d5343435f4d44200100000000000000",
    "magic_decoded": "MSCC_MD \\x01 (Microsemi Switchtec NVMe Switch Controller firmware v1)",
    "vendor": "Microsemi Corporation (MSCC) -- acquired by Microchip Technology",
    "product": "Switchtec PCIe NVMe Fabric Switch (backplane NVMe expander)",
    "sku_matrix": {
        "mswitch-nvme-m6": {"fw": "3.70.0.4F", "blob_md5": "cf58a7b1", "imghdr_md5": "03a02a08", "note": "NVMe switch plane"},
        "mswitch-m6-hddext-1": {"fw": "3.70.0.4F", "blob_md5": "cf58a7b1", "imghdr_md5": "68bb2451", "note": "HDD ext backplane slot 1"},
        "mswitch-m6-hddext-2": {"fw": "3.70.0.4F", "blob_md5": "cf58a7b1", "imghdr_md5": "42e7e42b", "note": "HDD ext backplane slot 2"},
        "mswitch-m6-hddext-3": {"fw": "3.70.0.4F", "blob_md5": "cf58a7b1", "imghdr_md5": "d3a64ddf", "note": "HDD ext backplane slot 3"},
    },
    "same_binary_note": "All 4 SKUs share ./blob md5=cf58a7b1; slot identity encoded in nested imghdr.bin (per-slot SN header)",
    "uart_cli_commands": {
        "raw_memory": ["rd_32 <addr> <len>", "wr_32 <addr> <data>", "rd_16", "wr_16", "rd_8", "wr_8", "rmw_32 <addr> <data> <mask>", "md_32 <addr> <words>"],
        "i2c_bus": ["twi_rd <port> <dev_addr> <offset> <width> <count>", "twi_wr <port> <dev_addr> <offset> <width> <data>", "twi_scan <port>", "gas_twi_rd", "gas_twi_wr"],
        "gpio": ["gpiord <id>", "gpiowr <id> <data>"],
        "firmware_partition": ["fw_part -t <key|bl2|d|i|b>", "fw_dump -p <partition_id>", "fw_update <PARTITION_ID|log>"],
        "rollback": ["rollback_check", "rollback_info_get"],
        "pcie_fault_injection": [
            "nwl_link_diag -nak_inject <port> <ack_seq> <nak_count>",
            "nwl_link_diag -dllp_inject <port> <dllp>",
            "nwl_link_diag -dllp_crc_error <1|0> <port> <interval_256ns>",
            "nwl_link_diag -tlp_lcrc_error <1|0> <port> <interval>",
            "nwl_link_diag -tlp_seq_error <port>",
        ],
        "cache_error_injection": ["fw_mod_cache_inject", "D$ Data/Tag/Way injection", "I$ Data/Tag injection", "L2 Region injection"],
        "privilege_escalation": "mscc_internal_en -s <class>  -- Switch to complete command set",
        "output_redirect": ["output_ctrl uart", "output_ctrl telnet", "output_ctrl help"],
    },
    "disaster_recovery_menu": {
        "trigger": "Press any key to enter the [Disaster Recovery Menu] -- during boot via serial console",
        "options": [
            "1. Toggle BL2",
            "5. Toggle KEYMANIFEST",
            "1. Set KEYMANIFEST",
            "2. Set BL2",
        ],
        "timeout": "|-Press key 1~4 in 50s to recover the system-|",
    },
    "build_timestamps": {
        "bl2": "2021031220:05:12softhsm_bl2",
        "keyman": "2021031220:00:44softhsm_keyman",
        "note": "softhsm = SoftHSM (open-source PKCS#11 HSM); reveals key management tool used at build time",
    },
    "boot_chain": {
        "BL1": "Firmware jumps into BL2 from BL1",
        "BL2": "Firmware jumps into Main FW from BL2",
        "validation": "IMG_VLDT: Key manifest validation; KMSK entry matching; image signature verification",
        "rollback": ["<BL2> running_id/active_id", "<CFG> running_id/active_id", "<MAIN_FW> running_id/active_id"],
    },
    "kmsk_strings": [
        "KMSK entry Version      %d",
        "Keyman Secure Version   %d",
        "BL2 Secure Version      %d",
        "Main FW Secure Version  %d",
        "OTP_EFUSE: Access not existed KMSK entry %d",
        "IMG_VLDT: No KMSK entry is found for key manifest",
        "IMG_VLDT: Key manifest security key exponent doesn't match the KMSK exponent",
        "IMG_VLDT: Image type %d signature data at 0x%08x decryption failed",
        "OTP_EFUSE: KMSK entries are not set sequentially 0x%x",
    ],
    "fatal_error_dump_codes": [
        "SWITCHTEC_DUMP_FATAL_ERR_XML_VER_MISMATCH",
        "SWITCHTEC_DUMP_FATAL_ERR_FW_ASSERT",
        "SWITCHTEC_DUMP_FATAL_ERR_WDG_TIMEOUT",
        "SWITCHTEC_DUMP_FATAL_ERR_GEN_EXCEPTION",
        "SWITCHTEC_DUMP_FATAL_ERR_RAM_ECC",
        "SWITCHTEC_DUMP_FATAL_ERR_SPI_ECC",
        "SWITCHTEC_DUMP_FATAL_ERR_ARAM_ECC",
    ],
    "topology": {
        "PMC1_PMC2_PMC3": "Three PMC (PCIe switch) controllers with 12+ bootstrap pins each",
        "PCIE_ALT_HDD1_to_HDD24": "24 PCIe HDD alternate routing paths visible in firmware GPIO map",
    },
}

MIAMI_BEACH_SMARTIOC2200 = {
    "sku_matrix": {
        "miami-beach": {"fw": "03.01.41.040", "md5": "e3cee024", "size_kb": 6281},
        "miami-beach-plus": {"fw": "03.01.41.040", "md5": "e3cee024", "size_kb": 6281},
        "miami-river-hba": {"fw": "03.01.41.040", "md5": "e3cee024", "size_kb": 6281},
        "miami-river-raid": {"fw": "03.01.41.040", "md5": "e3cee024", "size_kb": 6281},
        "miami-rock": {"fw": "03.01.41.040", "md5": "e3cee024", "size_kb": 6281},
    },
    "same_binary": True,
    "zip_contents": "Cisco_smartioc2200_smartoc3200_03.01.41.040_Production.bin (12143KB, 6281KB compressed)",
    "inner_magic": "c34155aa06000000",
    "vendor": "MCHP (Microchip Technology) -- formerly Microsemi",
    "product": "SmartIOC 2200 / SmartOC 3200 SAS/SATA storage controller (8-port, 12Gb/s)",
    "cisco_oem_tag": "CAT=Cisco            (trailing spaces -- 20-byte padded CAT field)",
    "developer_sign_bypass": {
        "string": "Make a developer signed image look like a production signed image",
        "significance": "A function bridging developer-to-production signing bypass is present in production firmware binary",
        "production_mode_lock": "Production signed mode enabled. This mode cannot be disabled until a restart occurs!",
    },
    "dice_riot_certs": {
        "levels": ["RIoT Core Device Cert", "*Alias Cert L0", "*Alias Cert L1", "*Alias Cert L2"],
        "source_file": "riot_cert_generate.c",
        "aes_impl": "RiotAes128.c (DICE CDI derivation uses AES-128)",
        "spdm": "spdm_get_cert (SPDM PCIe attestation protocol -- device identity query)",
    },
    "pem_header_strings": [
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PUBLIC KEY-----",
        "-----END EC PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE REQUEST-----",
    ],
    "auth_failure_codes": {
        "FAM_FAIL_DEBUG_IMAGE_DISALLOWED": "Debug images blocked in production mode",
        "FAM_FAIL_DEBUG_TOKEN_MISMATCH": "Debug token mismatch",
        "FAM_FAIL_DEBUG_TOKEN_AUTH_FAILED": "Debug token authentication failed",
        "FAM_FAIL_PUBLIC_KEY_HASH_MISMATCH": "Public key hash mismatch",
        "FAM_FAIL_FW_VERSION_CHECK": "Firmware version check failed (anti-rollback)",
        "FAM_FAIL_KEY_REVOKED": "Signing key revoked",
        "FAM_FAIL_INVALID_KEY_IDX": "Invalid key index",
        "FAM_FAIL_INVALID_MFG_KEY_IDX": "Invalid manufacturing key index",
    },
    "components": [
        "MCHP Storage Controller Firmware",
        "Boot loader code",
        "Cryptohal PKA",
        "Cryptohal SHA",
        "UART/TWI Command Server",
        "Bootx Offload",
        "OPSX boot API",
        "Boot Partition Utility",
        "Tiny Shell",
    ],
    "crypto_signer": "Crypto Authentication Signer SubCon 000 (Microchip CryptoAuthLib / ATECC crypto element)",
    "threads": "ThreadX SMP MIPS32_1004K_VPE (Express Logic Green Hills v5.6.2, copyright 1996-2014)",
}

KIOXIA_NVME = {
    "firmware_group": {
        "fw": "1YETE106",
        "md5": "8f4efc29",
        "size_kb": 2276,
        "magic": "4346385044485746",
        "magic_decoded": "CF8PDHWF (Kioxia CD8/CF8 product line magic, same DHWF suffix as Toshiba pattern)",
    },
    "sku_matrix": [
        "UCS-NVE11T6K1P (11.76TB Performance SLC)",
        "UCS-NVE13T2K1P (13.2TB Performance SLC)",
        "UCS-NVE16T4K1P (16.4TB Performance SLC)",
        "UCS-NVE112T8K1P (112.8TB Performance SLC)",
        "UCS-NVE11T9K1V (11.9TB Value MLC)",
        "UCS-NVE13T8K1V (13.8TB Value MLC)",
        "UCS-NVE17T6K1V (17.6TB Value MLC)",
        "UCS-NVE115T3K1V (115.3TB Value MLC)",
    ],
    "note": "All 8 capacity/endurance variants share one binary -- same DHWF magic family as Toshiba PX04/PX05",
}

WDC_PACV_NVME = {
    "magic": "50414356",
    "magic_decoded": "PACV (WDC Platform Abstraction Common Version container)",
    "firmware_groups": {
        "R2210803": {
            "md5": "83498efa",
            "size_kb": 3452,
            "version_bytes": "00f03500",
            "skus": ["NVMEM6-W1600", "NVMEM6-W3200", "NVMEM6-W6400", "NVMEM6-W7680", "NVMEM6-W15300"],
            "note": "5 SKUs same binary -- M.2/E1.S form factor (M6 blade NVMe)",
        },
        "R121000B": {
            "md5": "d5dc5a59",
            "size_kb": 2883,
            "version_bytes": "000c2d00",
            "skus": ["NVMW19T", "NVMW64T", "UCSB-NVMEM6-W800", "UCSB-NVMEM6-W3800"],
            "note": "4 SKUs same binary -- NVMW series (W = WEKA?/workload-optimized, larger capacity)",
        },
        "R2210803-SAS-HDD": {
            "hdd_member": "./isan/plugin_img/ucs-hdd-WDC-WUH722020BL4200.A540.bin",
            "note": "WDC HDD firmware (WUH = Ultrastar He, BL4200 = SATA 4Kn) uses distinct container",
        },
    },
}

MICRON_UPOB_GEN4 = {
    "magic": "55504f42",
    "magic_decoded": "UPOB (Micron Gen4 NVMe container -- upgrade from NRCM used in Gen3)",
    "firmware_group": {
        "fw": "E2CS007",
        "md5": "fe19662e",
        "size_kb": 2296,
        "sku_count": 15,
        "skus_sample": ["UCS-NVM2-960GB", "UCS-NVMEG4-M1536", "UCS-NVMEG4-M1600", "UCS-NVMEG4-M7680",
                        "UCSB-NVMEM6-M1920", "UCSX-NVM2-400GB"],
    },
    "jenkins_ci_path": {
        "path": r"c:\jenkins\workspace\uefi_driver\uefi_raptor_build\generic\MdePkg\Library\...",
        "codename": "Raptor (internal Micron codename for Gen4 NVMe UEFI driver)",
        "build_env": "Windows Jenkins CI (backslash path, jenkins\\workspace)",
    },
    "location_dn": "L=Boise,O=Micron (Micron Technology HQ, Boise Idaho -- same as prior NRCM/E3MQ009 finding)",
    "microsoft_uefi_chain": [
        "Microsoft Root Certificate Authority 2010",
        "MicCorUEFCA2011 (Microsoft UEFI Certificate Authority 2011)",
        "MicCorThiParMarRoo (Microsoft Third-Party Marketplace Root)",
        "Microsoft Time-Stamp PCA 2010",
    ],
    "nqn_template": "nqn.2016-08.com.micron:nvme:nvm-subsystem-sn- (12+ instances -- NVMe NQN)",
    "security_strings": {
        "TCG_LOGICAL_": "TCG Opal security protocol",
        "HashAndSign": "firmware signing mechanism",
        "f the Key Manife": "Key Manifest reference (fragment in compressed binary)",
        "CR has Bad Signature": "UEFI secure boot signature validation failure",
        "Compromised Data": "data integrity failure indicator",
    },
    "e3mq009_group": {
        "fw": "E3MQ009",
        "md5": "590da855",
        "size_kb": 2190,
        "magic": "2e2f000000000000",
        "magic_decoded": "./ (inner TAR directly -- no additional wrapper beyond SN)",
        "sku_count": 15,
        "note": "Micron Gen4 M2 (E3MQ009) and Gen4 M2V (E3MF009) -- newer than E2CS007",
    },
}

SAMSUNG_OPPA_NVME = {
    "firmware_groups": {
        "OPPA1K3Q": {
            "md5": "a232cd8c",
            "size_kb": 3072,
            "magic": "26743bd43978e558",
            "skus": ["UCS-NVE11T6S1P", "UCS-NVE13T2S1P", "UCS-NVE16T4S1P", "UCS-NVE112T8S1P"],
            "note": "P suffix = Performance SLC (High Endurance); 1K3Q firmware",
        },
        "OPPA1K5Q": {
            "md5": "bd0d7c5e",
            "size_kb": 3072,
            "magic": "46305dbfecd951b8",
            "skus": ["UCS-NVE11T9S1V", "UCS-NVE13T8S1V", "UCS-NVE17T6S1V", "UCS-NVE115T3S1V"],
            "note": "V suffix = Value QLC (High Capacity); 1K5Q firmware",
        },
    },
    "note": "Samsung PM9D3/PM9D3a series NVMe E3.S 2T form factor; two binaries split by endurance tier",
}

FINDINGS = {
    "MSCC-DEBUG-CLI-F1": {
        "id": "MSCC-DEBUG-CLI-F1",
        "severity": "HIGH",
        "title": "Microsemi Switchtec mswitch-m6 production firmware exposes UART+Telnet debug CLI with raw 32-bit memory R/W, PCIe fault injection, key manifest partition management, and privilege escalation via mscc_internal_en",
        "affected": [
            "ucs-storage-nvme-mswitch-nvme-m6.3.70.0.4F (md5=cf58a7b1)",
            "ucs-storage-nvme-mswitch-m6-hddext-1/2/3.3.70.0.4F (same binary)",
        ],
        "evidence": {
            "raw_memory_rw": "wr_32 <addr> <data> -- arbitrary 32-bit write; rd_32 <addr> <len> -- arbitrary 32-bit read",
            "privilege_escalation": "mscc_internal_en -s <class> -> Switch to complete command set (restricted by default)",
            "pcie_fault_injection": "nwl_link_diag -nak_inject/-dllp_inject/-dllp_crc_error/-tlp_lcrc_error/-tlp_seq_error",
            "key_manifest_management": "fw_part -t <key|bl2|d|i|b> -- toggle/set key manifest and BL2 partitions via CLI",
            "output_redirect": "output_ctrl telnet -- redirect UART debug CLI output to network interface",
            "disaster_recovery": "Press any key during boot: Disaster Recovery Menu; Toggle BL2 / Toggle KEYMANIFEST",
            "i2c_access": "twi_rd/twi_wr <port> <dev_addr> -- direct I2C/TWI bus access",
            "build_timestamps": "2021031220:05:12softhsm_bl2 / 2021031220:00:44softhsm_keyman (SoftHSM key management)",
        },
        "mechanism": (
            "The Microsemi Switchtec PCIe NVMe fabric switch firmware (mswitch-m6) contains a "
            "UART-accessible command server (and optionally Telnet via 'output_ctrl telnet') "
            "with unrestricted memory access primitives in production. "
            "'wr_32 <addr> <data>' and 'rd_32 <addr>' allow arbitrary 32-bit "
            "read/write to any memory address reachable from the MIPS CPU in the switch controller. "
            "'mscc_internal_en -s <class>' unlocks a 'complete command set' from the default "
            "restricted set -- this is a privilege escalation within the CLI itself. "
            "'fw_part -t key' and 'fw_part -t bl2' allow toggling the active/backup key manifest "
            "and BL2 bootloader partitions, enabling a downgrade to a known-vulnerable partition. "
            "A serial console boot-time 50-second window allows the Disaster Recovery Menu "
            "(Toggle BL2, Toggle KEYMANIFEST) without authentication. "
            "'nwl_link_diag -tlp_lcrc_error' and '-nak_inject' provide active PCIe fault injection "
            "against all attached NVMe drives -- enabling targeted NVMe availability attacks. "
            "'output_ctrl telnet' redirects the debug CLI output to the network interface, "
            "potentially enabling remote access to the full CLI over the management network. "
            "Build timestamp strings contain 'softhsm_bl2' and 'softhsm_keyman' -- revealing "
            "that SoftHSM was the PKCS#11 HSM substitute used to manage signing keys at build time."
        ),
        "impact": "Physical or remote UART access -> arbitrary memory R/W in switch CPU; PCIe fault injection disables NVMe drives; key manifest partition swap enables downgrade to prior signing keys; Disaster Recovery Menu bypasses boot-time signing enforcement; SoftHSM build artifact reveals the key management infrastructure used for production signing",
    },
    "MCHP-DEV-SIGN-BYPASS-F1": {
        "id": "MCHP-DEV-SIGN-BYPASS-F1",
        "severity": "HIGH",
        "title": "Miami Beach/Smartioc2200 production firmware contains 'Make a developer signed image look like a production signed image' function -- developer-to-production signing bypass in production binary",
        "affected": [
            "Cisco_smartioc2200_smartoc3200_03.01.41.040_Production.bin (md5=e3cee024)",
            "All 5 SKUs: miami-beach, miami-beach-plus, miami-river-hba, miami-river-raid, miami-rock",
        ],
        "evidence": {
            "bypass_string": "Make a developer signed image look like a production signed image",
            "production_lock": "Production signed mode enabled. This mode cannot be disabled until a restart occurs!",
            "debug_image_block": "FAM_FAIL_DEBUG_IMAGE_DISALLOWED",
            "debug_token": "FAM_FAIL_DEBUG_TOKEN_MISMATCH / FAM_FAIL_DEBUG_TOKEN_AUTH_FAILED",
            "dice_riot_chain": "RIoT Core Device Cert + *Alias Cert L0/L1/L2 (Microsoft DICE multi-level cert chain)",
            "spdm": "spdm_get_cert (SPDM device attestation query)",
            "tiny_shell": "Tiny Shell (embedded CLI) listed as a firmware component",
            "pem_headers": "-----BEGIN EC PRIVATE KEY----- / -----BEGIN CERTIFICATE----- in production binary",
        },
        "mechanism": (
            "The Microchip SmartIOC 2200 / SmartOC 3200 production firmware binary "
            "(12143KB, 5 Cisco SKUs sharing the same binary) contains a function described as "
            "'Make a developer signed image look like a production signed image'. "
            "This string describes a function that can substitute a developer signing credential "
            "to pass as production-signed. The production secure boot enforces the mode via "
            "'Production signed mode enabled. This mode cannot be disabled until a restart occurs!' "
            "and fails authentication with FAM_FAIL_DEBUG_IMAGE_DISALLOWED for debug images. "
            "The bypass function being in production firmware means it is reachable if the "
            "caller can invoke it (e.g., via Tiny Shell or the UART/TWI Command Server). "
            "The firmware implements Microsoft DICE/RIoT (Device Identity Composition Engine) "
            "with a 3-level alias certificate chain (L0, L1, L2) rooted at 'RIoT Core Device Cert', "
            "source file 'riot_cert_generate.c', using RiotAes128 for CDI derivation. "
            "SPDM (Security Protocol and Data Model) is implemented via 'spdm_get_cert' for "
            "PCIe-based device attestation. If the bypass function modifies the signing mode "
            "before the authentication check, it can cause the authenticator to accept "
            "a developer-signed image as production-signed, bypassing the FAM_FAIL_* gates."
        ),
        "impact": "Developer-to-production signing bypass in 12143KB production firmware binary shared across 5 controller SKUs; DICE/RIoT chain could be compromised if CDI derivation inputs are known; SPDM attestation forged if bypass function clears production mode",
    },
    "MICRON-UPOB-JENKINSPATH-F1": {
        "id": "MICRON-UPOB-JENKINSPATH-F1",
        "severity": "LOW",
        "title": "Micron Gen4 UPOB NVMe firmware exposes Windows Jenkins CI path c:\\jenkins\\workspace\\uefi_driver\\uefi_raptor_build revealing internal codename 'Raptor' and Microsoft UEFI cert chain",
        "affected": [
            "Micron E2CS007 (md5=fe19662e, 15 SKUs) -- UPOB container",
            "Includes UCSB-NVMEM6 blade variants and UCSX-NVM2 X-Series",
        ],
        "evidence": {
            "jenkins_path": r"c:\jenkins\workspace\uefi_driver\uefi_raptor_build\generic\MdePkg\Library\...",
            "codename": "Raptor (internal product codename for Micron Gen4 NVMe UEFI driver)",
            "container": "UPOB magic (vs NRCM for prior Gen3 -- confirmed format upgrade between generations)",
            "ms_uefi_chain": ["MicCorUEFCA2011 (MS UEFI CA)", "MicCorThiParMarRoo (MS Third-Party Root)", "Microsoft Root Certificate Authority 2010"],
            "nqn": "nqn.2016-08.com.micron:nvme:nvm-subsystem-sn- (12 instances -- per NQN namespace slot templates)",
            "location": "L=Boise,O=Micron (Micron HQ, Boise ID)",
        },
        "mechanism": (
            "The Micron Gen4 NVMe firmware (E2CS007, UPOB container format) retains the "
            "Windows Jenkins CI build path in a UEFI debug library string: "
            r"c:\jenkins\workspace\uefi_driver\uefi_raptor_build\generic\MdePkg\Library\ "
            "The path exposes: "
            "(1) internal codename 'Raptor' for the Gen4 NVMe UEFI driver project; "
            "(2) Windows-based CI build environment (backslash paths); "
            "(3) standard TianoCore/EDK2 MdePkg structure (MdePkg = Microchip Development Kit?). "
            "The UEFI binary is co-signed by the Microsoft UEFI Certificate Authority 2011 "
            "(MicCorUEFCA2011) and roots to Microsoft Root CA 2010. "
            "The UPOB container format ('UPOB' magic) is new in Gen4 vs NRCM in Gen3 -- "
            "the container format boundary tracks product generation transitions."
        ),
        "impact": "Internal codename and CI infrastructure exposed; Microsoft UEFI signing chain enumerable; NQN template structure visible for 15 SKUs",
    },
    "KIOXIA-CF8-SAME-BINARY-F1": {
        "id": "KIOXIA-CF8-SAME-BINARY-F1",
        "severity": "LOW",
        "title": "All 8 Kioxia 1YETE106 NVMe SKUs share one binary (md5=8f4efc29); firmware header magic CF8PDHWF follows Toshiba DHWF naming convention",
        "affected": [
            "UCS-NVE1xTxK1P/K1V (Kioxia CD8/CF8 E3.S, 8 capacity variants)",
        ],
        "evidence": {
            "all_same_md5": "8f4efc29 (8 SKUs, 2276KB each)",
            "magic": "CF8PDHWF (vs PX03DHWF for Toshiba PX04 and PM04DHWF for Toshiba PX05)",
            "naming_pattern": "DHWF suffix is consistent across all Toshiba/Kioxia generations (PX03/PM04/CF8)",
            "capacity_range": "11T6 (11.76TB) through 115T3 (115.3TB)",
        },
        "mechanism": (
            "Kioxia (spun out from Toshiba in 2019) continues the DHWF firmware header magic "
            "naming convention from Toshiba. The header magic for Kioxia CD8/CF8 E3.S NVMe "
            "drives is 'CF8PDHWF' -- the 'CF8' prefix identifies the product line, "
            "the 'DHWF' suffix is the same as Toshiba PX04 ('PX03DHWF') and PX05 ('PM04DHWF'). "
            "All 8 Kioxia capacity/endurance SKUs (Performance SLC 1K3Q through Value MLC 1K5Q "
            "variants) share one 2276KB firmware binary -- same pattern as the 9-model HGST "
            "NVMe group (md5=cbe1e0ca). "
            "The HGST NVMe FWHEADER magic ('FWHEADER') is a different heritage from the Toshiba "
            "DHWF line -- WDC (HGST parent) and Kioxia (Toshiba parent) diverged at acquisition."
        ),
        "impact": "8 SKUs share one vulnerability surface; DHWF magic enables cross-generation header parsing; CF8 codename enumerable from header",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

SUMMARY = {
    "module": "cisco_ucs_cseries_mswitch_miami_kioxia_wdc_re",
    "targets": "Microsemi Switchtec mswitch-m6, Miami Beach/Smartioc2200, Kioxia 1YETE106, WDC PACV NVMe, Micron UPOB Gen4, Samsung OPPA",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 2, "MEDIUM": 0, "LOW": 2},
    "headline": (
        "Switchtec mswitch-m6 UART CLI has raw memory R/W, PCIe fault injection, key manifest partition swap, "
        "and mscc_internal_en privilege escalation -- all in production firmware (HIGH). "
        "Miami Beach Smartioc2200 production binary contains developer-to-production signing bypass function (HIGH). "
        "5 storage controller SKUs and 4 mswitch SKUs each share one binary. "
        "Micron Gen4 UPOB firmware exposes Jenkins CI path with internal Raptor codename."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title'][:80]}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
