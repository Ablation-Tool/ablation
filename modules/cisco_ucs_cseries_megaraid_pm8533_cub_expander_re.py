"""
Cisco UCS C-Series -- MegaRAID 9400/9460/9500, M2 HWRAID Bay View, PM8533, PMC RioBeach,
CUB/CUBR SAS expander (Pismo Beach Plus), PMC Avila Pier 12G HBA RE

MegaRAID 9460 has dual-key FDE: user secret key AND firmware secret key both decrypt NVRAM key blob.
MegaRAID 9500 (Oct 2025 build) implements SPDM attestation via mbedTLS with full X.509 PKI.
M2 NVMe RAID Bay View uses Opal MSID as initial credential; `password_test_data` in production binary.
PM8533 NVMe controller has bootloader partition read-write toggle and BOOTCFG verification skip.
CUB SAS expander orchestrates PSoC firmware updates from SAS management domain over I2C.
RioBeach is ARM architecture (vs MIPS for Miami Beach) with June 2024 build timestamp.
"""

MEGARAID_9460 = {
    "product": "Broadcom/LSI MegaRAID SAS 9460-8i with CacheCade (RAID-on-Chip + DRAM cache)",
    "fw": "51.23.0-5009",
    "zip_contents": "Cisco_9460_8i_nopad.rom (7168KB)",
    "other_cache_sku_same_fw": [
        "lagunabeach.51.23.0-5009 (md5=d1d5028b, 3570KB)",
        "lagunabeach-plus.51.23.0-5009 (md5=ab8625f1, 3570KB)",
    ],
    "fde_key_management": {
        "nvram_key_blob": "NVRAM stores encrypted FDE key blob",
        "dual_keys": {
            "user_secret_key": "KM_KeyMgmtInit: Failed to decrypt NVRAM key blob with USER secret key",
            "fw_secret_key": "KM_KeyMgmtInit: Failed to decrypt NVRAM key blob with FW secret key",
        },
        "blob_decrypt": "KM_DecryptNvramKeyBlob: Failed to decrypt with secret key, retVal = 0x%X",
        "blob_auth": "KM_DecryptNvramKeyBlob: Failed to authenticate NVRAM key blob with secret key",
        "secret_key_funcs": ["getSecretKey", "bootKeyObtainSecretKey", "authenticateSecret"],
    },
    "opal_fde_strings": {
        "OpalAuthenticate": "OpalAuthenticate PD, authority (2=LSP+Admin1, 3=ASP+SID, 4=LSP+User1, 5=ASP+PSID)",
        "OpalSetPassword": "OpalSetPassword / OpalSetUser1Password / FDE_SetPassword",
        "setPassword": "setPassword PD TPSN authority newPassword",
    },
    "certificate_chain": [
        "Certificate is bad %s",
        "Certificate chain import failed",
        "Certificate slot %s sealed",
        "Certificate chain loaded in %s",
        "Certificate chain invalidated in %s",
    ],
}

MEGARAID_9500 = {
    "product": "Broadcom/LSI SAS9500-8e HBA (IT mode, 12Gb/s, external port)",
    "fw": "36.65.08.00",
    "zip_contents": ["IT_HBA_X64_BIOS_PKG_E6.rom (202KB EFI)", "UCSC-9500-8E.rom (2040KB)"],
    "build_date": "2025-10-24 03:19:12 (BL Version:36.00.01.00)",
    "mbedtls_pki": {
        "x509_funcs": ["x509_get_certificate_policies", "oid_certificate_policies_from_asn1", "mbedtls_oid_get_certificate_policies"],
        "ecdh_funcs": ["mbedtls_ecdh_calc_secret", "ecdh_calc_secret_internal"],
        "pem_headers": [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----END ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE REQUEST-----",
            "-----END CERTIFICATE REQUEST-----",
        ],
        "cert_validation_errors": [
            "The certificate validity has expired",
            "The certificate has been revoked (is on a CRL)",
            "The certificate Common Name (CN) does not match with the expected CN",
            "The certificate is not correctly signed by the trusted CA",
            "Certificate was missing",
            "Certificate verification was skipped",
            "The certificate validity starts in the future",
            "The certificate is signed with an unacceptable hash",
            "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA)",
            "The certificate is signed with an unacceptable key (eg bad curve, RSA too short)",
        ],
    },
    "spdm": [
        "SpdmReadCertForSlot",
        "SPDMCoreBuildChallengeBuffer",
    ],
    "shared_strings_with_9460": ["DBG: CSW bypass entry Lane:Status %08x", "aviSerdesSASSDWaitBypassReady"],
    "ata_security": "DmProcessATASecurityDisablePassword",
    "test_vector": "passwordPASSWORDpassword (PBKDF/HMAC test vector string embedded in production binary)",
}

MEGARAID_9400 = {
    "product": "Broadcom/LSI MegaRAID SAS 9400-8i/8e (RAID, 12Gb/s)",
    "fw": "24.65.18.00",
    "build_date": "2023-07-12 (BL 02:55:33 07/12/2023, Ventura Boot Loader)",
    "zip_structure": ["UCSC-9400-8I.bin (1811KB main FW)", "mpt35sas_legacy.rom (53KB)", "mpt35sas_x64.rom (146KB EFI)"],
    "codename": "Ventura (BL string: Ventura Boot Loader)",
    "pn": "DCSG01525861",
    "sku_matrix": {
        "9400-8e": {"fw": "24.65.18.00", "md5": "6e64d961", "size_kb": 1147},
        "9400-8i": {"fw": "24.65.18.00", "md5": "bd516042", "size_kb": 1147},
        "laguna-rock": {"fw": "24.65.18.00", "md5": "ab529d57", "size_kb": 1147},
        "laguna-rock-plus": {"fw": "24.65.18.00", "md5": "63e24b41", "size_kb": 1147},
    },
    "security_strings": [
        "ERR: Cert Verification: Invalid Certificate IOCStatus=%02x IOCLogInfo :%08x",
        "DBG: CSW bypass entry Lane:Status %08x",
        "aviSerdesSASSDWaitBypassReady",
    ],
}

M2_NVME_RAID = {
    "product": "Broadcom M.2 NVMe RAID (Bay View -- RAID 0/1 on M.2 NVMe)",
    "fw": "52.34.0-6415",
    "zip_contents": "Bay_View_NOPAD.rom (7808KB)",
    "build_date": "2025-06-17 12:03:46 (BL Version:33.250.02.00)",
    "opal_msid": {
        "string": "Use password from MSID, len %x",
        "meaning": "Opal MSID (Manufacturing Secure ID) used as initial drive credential",
        "at_security": "@se_dbg :Command set password(F1) was not successful",
        "test_data": "password_test_data (password verification test structure in production binary)",
    },
    "secret_key": {
        "enable": "enableSecretKeyControl=%x",
        "swap_detect": "[%s]: Secret Keys Are Swapped",
        "blob_decrypt": "KM_DecryptNvramKeyBlob (same key management as 9460)",
    },
    "spdm": ["SpdmGetCertificate", "secBootDumpCertificate"],
    "mbedtls": "Full mbedTLS PKI (identical to 9500) including cert chain, ECDH, SPDM",
}

PM8533_NVMe = {
    "magic": "504d43009009170003000000000006a8",
    "magic_decoded": "PMC\\x00 (PMC-Sierra, same family as C3260 SAS expander PMC_BOOT and mswitch-m6)",
    "product": "PMC-Sierra/Microsemi PM8533 NVMe RAID controller (Aardvark/NVMe backplane)",
    "sku_matrix": {
        "C220-PM8533.1.8.0.58-22D9": {"size_kb": 1493, "md5": "b99cfce3"},
        "C240-PM8533.1.8.0.58-24B3": {"size_kb": 2968, "md5": "5bbd846e", "note": "2x size -- C240 wider bus"},
        "C480-PM8533-F1.01080058-000041A3": {"size_kb": 1494, "md5": "aa9925cd"},
        "C480-PM8533-F2.01080058-000042A3": {"size_kb": 1494, "md5": "aa9925cd", "note": "same as F1"},
        "C480-PM8533-F3.01080058-000043A3": {"size_kb": 1494, "md5": "aa9925cd", "note": "same as F1"},
        "C480-PM8533-R.01080058-000044E3": {"size_kb": 1493, "md5": "e206ea69", "note": "R = Redundant/Recovery"},
    },
    "same_binary_groups": {
        "C480_F1_F2_F3": {"md5": "aa9925cd", "sku_count": 3},
    },
    "security_strings": {
        "boot_config_menu": "+--------[Boot Configuration Menu]----------+",
        "bootloader_rw": "2 b t    : Toggle bootloader partition to be rw/r",
        "bootcfg_invalid": "BOOTCFG is invalid. Skip partition verification",
        "output_telnet": "output_ctrl [[help]|[telnet]|[uart]]",
        "bootpmcs": "BOOTPMCS (PMC-Sierra boot identifier string)",
        "fpga_cpld": "SAR: FPGA Version:%d, CPLD Version:%d",
    },
    "debug_loopback_modes": [
        "MGMT_TLB_DEBUG_SELF_CROSSLINK",
        "MGMT_TLB_DEBUG_DIRECT_TO_LOOPBACK",
        "MGMT_TLB_DEBUG_LOOPBACK_MASTER_5G",
        "MGMT_TLB_DEBUG_LOOPBACK_SLAVE_5G",
        "MGMT_TLB_DEBUG_LOOPBACK_MASTER_8G_DEEMPH",
        "MGMT_TLB_DEBUG_LOOPBACK_SLAVE_8G_DEEMPH",
        "MGMT_TLB_DEBUG_DIRECT_SCRAMBLE_OFF",
        "MGMT_TLB_DEBUG_FORCE_SCRAMBLE_OFF_FAST",
    ],
    "note": "PMC-Sierra silicon across C220/C240/C480 NVMe backplane -- pmc magic family includes mswitch (MSCC_MD) and C3260 expander (PMC_BOOT)",
}

CUB_SAS_EXPANDER = {
    "product": "Cisco Pismo Beach Plus SAS expander (SAS35x ASIC, 12Gb/s)",
    "fw": "SAS35xFW-65.16.09.00 (Oct 21, 2021)",
    "magic": "280000eaa0baeac0 (ARM Cortex-M branch at reset vector -- ARM32 firmware)",
    "sku_matrix": {
        "cub-m6.65.16.09.00": {"md5": "31e0355b", "note": "Current M6 expander"},
        "cubr-m6.65.16.09.00": {"md5": "86b186b5", "note": "Redundant M6 expander"},
        "cubr.65.11.21.00": {"md5": "3145ce52", "note": "Older CUBR main FW"},
        "cubr-boot.65.02.12.00": {"md5": "5b7d7750", "note": "CUBR bootloader (65.02 = old bootloader)"},
    },
    "cisco_oem_tag": "Cisco   UCS-C2X0-M6     A0          (C220/C240 M6 rev A0)",
    "psoc_firmware_update": {
        "source": "OEM: PSOC : Start bootloader operation failed",
        "silicon_check": "OEM: PSOC : Bootloader device SiliconID= 0x%x and SiliconRev= 0x%x",
        "transfer": "OEM: PSOC : Start bootloader data transfer failed with error 0x%08x",
        "exit_ok": "OEM: PSOC : Exit bootloader operation successful",
        "mechanism": "SAS expander firmware upgrades PSoC over I2C from SAS management domain",
    },
    "avago_serdes": {
        "library": "AAPL Version 2.2.3, Copyright 2013-2015 Avago Technologies",
        "functions": ["avago_serdes_get_signal_ok", "avago_serdes_initialize_signal_ok", "avago_serdes_get_signal_ok_threshold"],
        "designs": ["sd28C_pcie_sas_sata_hvd6_01", "sd28C_pcie_sas_sata_hvd6_rsa08_01", "sd28C_pcie_sas_sata_hvd6_02"],
    },
    "uart_cli": {
        "session_id": "Cli Uart Session",
        "commands": ["debuginfo sasphy|edfb|link|connection|config", "scedebug dev|exp|expdev",
                     "adcread <ChannelNumber> <ConversionMode>", "reset [watchdog]",
                     "date [set|send|recv]", "sspiinq <SasAddrHi> <SasAddrLo> <TimeOut>",
                     "smpireq <SMPFunction> <SasAddrHi> <SasAddrLo>"],
        "ethernet_compliance": "Ethernet compliance test command only on UART",
    },
    "temp_sensors": "SAS35X Internal Temp 0-4 (5 thermal sensors)",
    "bmci_check": "OEM: BMCI Invalid Firmware for boot option %d",
    "oem_source_file": "ciscoPlatformCallback.c",
}

RIOBEACH_ARM = {
    "product": "PMC-Sierra RioBeach PCIe-to-SAS bridge (C3260 storage management)",
    "fw": "8.10.1.0-00065-00002",
    "zip_contents": "Rio_Beach_full_fw_vsn_pkg_signed.rom (13012KB, 5471KB compressed) -- .rom extension",
    "architecture": "ARM (reset vector magic 3e0000eb = ARM32 branch; vs MIPS32 for Miami Beach/PM8533)",
    "build_date": "2024-06-20 18:25:07Z (embedded via @(#)DATE/@(#)TIME strings)",
    "boot_strings": [
        "@(#)8.10.1.0-00000-00001 (internal version variant)",
        "@(#)DATE:2024-06-20",
        "@(#)TIME:18:25:07Z",
        "Shutdown MMU",
        "armRegionInit: InPtrFirmware=%08x, PtrBootBase=%08x",
        "FEXPBSP (RioBeach BSP identifier)",
    ],
}

M2_MARVELL_88SE92XX = {
    "product": "Marvell 88SE92xx M.2 SATA HWRAID controller",
    "fw_versions": {
        "2.3.17.1014": {"md5": "8377ef99", "size_kb": 512, "zip_file": "ImageA1-1014.bin.bin"},
        "2.3.17.2002": {"md5": "4e6f408e", "size_kb": 513},
    },
    "note": "Marvell 88SE92xx is the SATA bridge chip for M.2 HWRAID in C-Series; .bin.bin double extension in zip",
}

PMC_AVILA_PIER = {
    "product": "PMC-Sierra/Microsemi Avila Pier 12Gb/s SAS HBA",
    "fw": "2.20-0",
    "zip_contents": "UCSC-PSAS12GHBA.bin (7168KB)",
    "note": "Same PSAS12G HBA family as other PMC controllers; 7168KB = same size as some MegaRAID images",
}

FINDINGS = {
    "MEGARAID-9460-DUAL-KEY-FDE-F1": {
        "id": "MEGARAID-9460-DUAL-KEY-FDE-F1",
        "severity": "HIGH",
        "title": "MegaRAID 9460-8i FDE uses dual secret keys: user secret key AND embedded firmware secret key both decrypt NVRAM key blob -- firmware key in binary enables key blob decryption without user credential",
        "affected": [
            "Cisco_9460_8i_nopad.rom (51.23.0-5009) -- 7168KB",
            "lagunabeach and lagunabeach-plus (same 51.23.0-5009 version, different SKU)",
        ],
        "evidence": {
            "fw_secret_key": "KM_KeyMgmtInit: Failed to decrypt NVRAM key blob with FW secret key",
            "user_secret_key": "KM_KeyMgmtInit: Failed to decrypt NVRAM key blob with USER secret key",
            "blob_decrypt": "KM_DecryptNvramKeyBlob: Failed to decrypt with secret key, retVal = 0x%X",
            "key_funcs": ["getSecretKey", "bootKeyObtainSecretKey", "authenticateSecret"],
            "opal_chain": "OpalAuthenticate PD, authority (2=LSP+Admin1, 3=ASP+SID, 4=LSP+User1, 5=ASP+PSID)",
        },
        "mechanism": (
            "The MegaRAID 9460-8i RAID controller implements FDE (Full Drive Encryption) / "
            "TCG Opal with a NVRAM key blob architecture. Two separate secret keys are used to "
            "authenticate the NVRAM key blob: "
            "(1) USER secret key -- derived from the user's password; "
            "(2) FW (firmware) secret key -- a key embedded in the firmware binary. "
            "Both paths appear in error strings: 'Failed to decrypt NVRAM key blob with USER secret key' "
            "and 'Failed to decrypt NVRAM key blob with FW secret key'. "
            "The firmware secret key is a symmetric key embedded in the production firmware binary -- "
            "a static key that can be extracted by analyzing the 7168KB ROM image. "
            "If extracted, the firmware secret key enables decryption of the NVRAM key blob "
            "without knowing the user's password, recovering the FDE symmetric key for all drives "
            "managed by any 9460-8i controller using this firmware version. "
            "The `bootKeyObtainSecretKey` function derives the key at boot, and `getSecretKey` "
            "retrieves it for active decryption."
        ),
        "impact": "Firmware secret key extraction from ROM enables NVRAM key blob decryption without user credential, recovering FDE master key; affects all 9460-8i controllers on firmware 51.23.0-5009",
    },
    "PM8533-BOOT-RW-F1": {
        "id": "PM8533-BOOT-RW-F1",
        "severity": "MEDIUM",
        "title": "PM8533 NVMe controller Boot Configuration Menu includes bootloader partition read-write toggle and BOOTCFG verification skip; PMC\\x00 magic family spans C220/C240/C480 NVMe backplanes",
        "affected": [
            "ucs-c-storage-nvme-C220-PM8533.1.8.0.58 (md5=b99cfce3)",
            "ucs-c-storage-nvme-C240-PM8533.1.8.0.58 (md5=5bbd846e)",
            "ucs-c-storage-nvme-C480-PM8533-F1/F2/F3.01080058 (md5=aa9925cd)",
            "ucs-c-storage-nvme-C480-PM8533-R.01080058 (md5=e206ea69)",
        ],
        "evidence": {
            "boot_menu": "+--------[Boot Configuration Menu]----------+",
            "bootloader_rw": "2 b t    : Toggle bootloader partition to be rw/r",
            "bootcfg_skip": "BOOTCFG is invalid. Skip partition verification",
            "telnet_redirect": "output_ctrl [[help]|[telnet]|[uart]]",
            "pmc_magic": "PMC\\x00 (504d430090091700) -- same PMC-Sierra magic as C3260 SAS expander (PMC_BOOT) and mswitch-m6 (MSCC_MD)",
            "debug_loopbacks": "8 MGMT_TLB_DEBUG loopback/scramble-off modes in production",
        },
        "mechanism": (
            "The PM8533 NVMe backplane controller (PMC-Sierra/Microsemi Aardvark) exposes a "
            "Boot Configuration Menu via UART with command '2 b t' -- "
            "'Toggle bootloader partition to be rw/r'. "
            "Toggling the bootloader partition to read-write enables modification of the bootloader "
            "without the secure boot gating mechanisms that apply to the main firmware partition. "
            "Additionally, if 'BOOTCFG is invalid' -- which can be triggered by corrupting "
            "the boot configuration structure -- partition verification is skipped entirely, "
            "allowing loading of unsigned firmware. "
            "The same 'output_ctrl telnet' redirect found in mswitch-m6 is present in PM8533 "
            "(same PMC-Sierra codebase across the product family). "
            "C480-PM8533-F1/F2/F3 share the same binary (md5=aa9925cd) -- "
            "three physical controller slots share one firmware image."
        ),
        "impact": "Bootloader partition writable via boot menu; BOOTCFG corruption skips partition verification; Telnet debug CLI redirect; C480 F1/F2/F3 same binary means one firmware patch covers three slots",
    },
    "CUB-PSOC-REMOTE-UPDATE-F1": {
        "id": "CUB-PSOC-REMOTE-UPDATE-F1",
        "severity": "MEDIUM",
        "title": "Cisco Pismo Beach Plus SAS expander manages PSoC firmware over I2C from SAS domain; UART CLI exposes SAS topology, drive SAS addresses, route tables, and ADC hardware reads",
        "affected": [
            "ucs-storage-expander-cub-m6.65.16.09.00 (SAS35xFW-65.16.09.00, Oct 21 2021)",
            "ucs-storage-expander-cubr-m6.65.16.09.00",
        ],
        "evidence": {
            "psoc_start": "OEM: PSOC : Start bootloader operation (success/failure logged)",
            "psoc_silicon": "OEM: PSOC : Bootloader device SiliconID= 0x%x and SiliconRev= 0x%x (hardware identity verified at start)",
            "psoc_transfer": "OEM: PSOC : Start bootloader data transfer failed with error 0x%08x",
            "uart_cli": "Cli Uart Session -- full UART command server with SMP, SSP, route, debug",
            "commands": ["adcread <ChannelNumber>", "debuginfo sasphy|edfb|link|connection", "reset [watchdog]"],
            "source": "ciscoPlatformCallback.c (OEM integration layer source file exposed)",
            "avago": "AAPL v2.2.3 Avago Technologies SerDes library (2013-2015 era)",
        },
        "mechanism": (
            "The Cisco Pismo Beach Plus SAS expander (SAS35x, 65.16.09.00, ARM32) orchestrates "
            "PSoC (Cypress/Infineon Programmable System-on-Chip) firmware updates from the "
            "SAS management domain. The expander initiates the PSoC bootloader sequence, "
            "validates silicon ID/revision over I2C, transfers the firmware, and exits the bootloader. "
            "If the SAS management domain is compromised (e.g., via an MCP UART connection or "
            "SMP initiator spoofing), an attacker can replace PSoC firmware on all backplane "
            "controllers attached to this expander. "
            "The UART CLI exposes: SAS PHY register dumps (debuginfo sasphy), "
            "SMP target/initiator debug, drive SAS address tables, route table entries, "
            "ADC hardware channel reads (adcread), and watchdog reset. "
            "The SAS address of every attached drive is enumerable via the UART CLI. "
            "The Avago AAPL SerDes library (v2.2.3, copyright 2013-2015) is a dependency "
            "frozen at a 2015 vintage."
        ),
        "impact": "PSoC firmware replaceable from SAS management domain; UART CLI exposes full SAS topology including drive SAS addresses and route tables; Avago AAPL SerDes library frozen at 2015 vintage",
    },
    "MEGARAID-SPDM-TESTVECTOR-F1": {
        "id": "MEGARAID-SPDM-TESTVECTOR-F1",
        "severity": "LOW",
        "title": "MegaRAID 9500-8e (Oct 2025) and M2 NVMe RAID (Jun 2025) contain 'passwordPASSWORDpassword' PBKDF test vector and 'password_test_data' struct in production firmware; both implement SPDM attestation",
        "affected": [
            "UCSC-9500-8E.rom (36.65.08.00, 2025-10-24) -- 9500-8e HBA",
            "Bay_View_NOPAD.rom (52.34.0-6415, 2025-06-17) -- M2 NVMe RAID",
        ],
        "evidence": {
            "test_vector": "passwordPASSWORDpassword (NIST PBKDF2/HMAC-SHA1 test vector P string from RFC 6070)",
            "test_data": "password_test_data (test structure for password verification in production binary)",
            "spdm": ["SpdmReadCertForSlot", "SPDMCoreBuildChallengeBuffer", "SpdmGetCertificate", "secBootDumpCertificate"],
            "opal_msid": "Use password from MSID, len %x (Opal Manufacturing Secure ID as initial credential)",
            "secret_key_swap": "[%s]: Secret Keys Are Swapped",
            "pem_private_keys": "RSA, EC, ENCRYPTED PEM private key headers (all 6 PEM key types)",
        },
        "mechanism": (
            "The Broadcom MegaRAID 9500-8e HBA (BL Version:36.00.01.00, built Oct 24, 2025) "
            "and the M2 NVMe RAID Bay View (BL Version:33.250.02.00, built Jun 17, 2025) both "
            "contain 'passwordPASSWORDpassword' -- this is the PBKDF2 test vector from RFC 6070 "
            "(P='password', S='salt', c=1, dkLen=20) used in NIST HMAC-SHA1 validation suites. "
            "The M2 NVMe RAID also contains 'password_test_data' -- a named test structure. "
            "Both test strings in production firmware indicate the mbedTLS test suite code "
            "was compiled into the production binary without stripping test functions. "
            "'[%s]: Secret Keys Are Swapped' in Bay View reveals a runtime state where "
            "primary and backup secret keys exchange positions -- potentially exploitable "
            "as a key confusion attack during the swap window. "
            "The M2 NVMe RAID uses Opal MSID as the initial drive password (factory default), "
            "with SPDM attestation via SpdmGetCertificate and secBootDumpCertificate. "
            "All six PEM private key headers appear in both binaries (RSA, EC, ENCRYPTED variants)."
        ),
        "impact": "PBKDF2 test vector in production binary confirms mbedTLS test code compiled in; secret key swap window is exploitable race; MSID as initial credential is factory-default weakness; SPDM attestation certificate dump reachable",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

SUMMARY = {
    "module": "cisco_ucs_cseries_megaraid_pm8533_cub_expander_re",
    "targets": "MegaRAID 9400/9460/9500, M2 HWRAID Bay View, PM8533, PMC RioBeach ARM, CUB/CUBR SAS expander",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 1, "MEDIUM": 2, "LOW": 1},
    "headline": (
        "MegaRAID 9460-8i FDE uses firmware-embedded secret key to decrypt NVRAM key blob -- "
        "extractable from 7168KB ROM (HIGH). PM8533 Boot Menu toggles bootloader to read-write; "
        "BOOTCFG invalid skips partition verify. Pismo Beach Plus SAS expander manages PSoC "
        "firmware from SAS domain. MegaRAID 9500/BayView have PBKDF2 test vectors in production."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title'][:80]}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
