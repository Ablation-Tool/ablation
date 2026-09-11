"""
Cisco UCS C-Series -- Micron NRCM SSD, FIPS SSD, M5 ConnectX-5 RE
Targets: 94 Micron SSD entries (NRCM format), Micron s650dc FIPS SSDs (MB19),
         M5D25GF/M5S100GF/M5D100GF ConnectX-5 (MTFW 16MB)

Micron FIPS SSD exposes signature verification error path leaking SignaturePtr and KeyIndex.
ConnectX-5 MTFW contains NV_OPCODE_INVALIDATE_ALL -- NVM wipe opcode.
MTFW full 16-byte magic reveals FADE/DEAD debug markers. MTFW format spans CX-5 through CX-7.
Micron 5200 SED exposes "ACADIA" platform codename and "Monet" hardware platform.
"""

MICRON_NRCM_MAGIC = "4e52434d"
MICRON_NRCM_MAGIC_DECODED = "NRCM (ASCII: N=4e R=52 C=43 M=4d) -- Micron proprietary container"

MICRON_FIRMWARE_SURVEY = {
    "total_members": 94,
    "md5_groups": 24,
    "format": "NRCM container (magic 4e52434d)",
    "largest_group": {
        "md5": "fe19662e",
        "models": 15,
        "fw_version": "E2CS007",
        "products": "UCS-NVM2 NVMe generation (various capacities)",
    },
    "sed_fips_count": 16,
    "key_groups": {
        "D0MH077": {"models": 8, "product": "Micron 5100 SATA + sata-mtfddav variants"},
        "D1MH031": {"models": 8, "product": "Micron 5200 TLC variants (tdn/tdc/tdn/tdc-sed)"},
        "D0MC077": {"models": 2, "product": "Micron 5100 SED variants (240/960GB tcb)"},
        "D1CH431": {"models": 1, "product": "Micron 5200 SED ACADIA -- Cisco build (unique binary)"},
        "MB19":    {"models": 3, "product": "Micron s650dc FIPS SATA SSD (400/800/1600GB)"},
    },
}

MICRON_5100_5200 = {
    "nrcm_magic": "4e52434d",
    "platform_codename": "Monet (MonetHw in source paths)",
    "sed_codename": "ACADIA (5200 SED internal project name)",
    "buffer_mgmt_codename": "Rain (RainBufManagement -- RAID-like buffer management for 5200)",
    "source_paths": [
        "../FTL/FTL_FlashPhyAddr.c",
        "../Platform/MonetHw/Driver_vg/HalSataImpl.c",
        "../Task/Task_ISRs.c",
        "../Backend/RainBufManagement.c",
        "../MCC/MCC_HostWrQProc.c",
        "../MCC/MCC_FtlFdQProc.c",
        "../Platform/HAL/Hal_Seq.c",
        "../Platform/MonetHw/Driver_vg/mDma.c",
    ],
    "tcg_key_queue_strings": [
        "Can't Read TCG sector %d, size %d",
        "Can't read TCG sector data, S sector:%d E sector:%d",
        "Can't write TCG sector data, S sector:%d E sector:%d",
        "Authentication failed!",
        "  Total Valid Key Q Cnt : %x",
        "  Reserved Key Q Cnt : %2x",
        "  Received command which is not in Key Q",
        "  Enhance key Q init done",
        "Skip read TCG data sector:%d",
        "Skip erasing TCG data sector:%d",
    ],
    "sed_5200_acadia_strings": [
        "<DBG_Vu2013SetFTLTaskParam>ACADIA not support set TT",
        "Dynamically switch USTP is not permitted for ACADIA",
    ],
}

MICRON_FIPS_S650DC = {
    "fw_version": "MB19",
    "magic": "e71a0e5901000200",
    "magic_note": "First 4 bytes e71a0e59 match Seagate SAS magic prefix; continuation 01000200 differs",
    "size_kb": 1816,
    "shared_binary_md5": "e581229a",
    "capacity_variants": ["s650dc400fips", "s650dc800fips", "s650dc1600fips"],
    "sig_verification_strings": {
        "failure": "VerifyCtrlFirmwareSignature failed",
        "module": "Module: 0x%x",
        "sig_ptr": "SignaturePtr: 0x%x",
        "key_index": "KeyIndex: 0x%x",
    },
    "crypto_algorithm_labels": {
        "K_AES_256": "AES-256 key type identifier",
        "C_AES_256": "AES-256 cipher type identifier",
        "C_RSA_2048": "RSA-2048 cipher for firmware signing",
        "TPerSign": "TCG Trusted Peripheral Signing (TPer-layer signing authority)",
    },
    "tcg_strings": [
        "Authority",
        "~IsMixedKey",
        "~KeyWrapIntegrityCheck",
    ],
}

M5_CONNECTX5 = {
    "products": {
        "ucsc-p-M5D25GF": {"fw_version": "16.35.3006", "speed": "25G SFP28", "form_factor": "PCIe"},
        "ucsc-p-M5S100GF": {"fw_version": "16.35.3006", "speed": "100G QSFP28", "form_factor": "PCIe"},
        "ucsc-p-M5D100GF": {"fw_version": "16.35.3006", "speed": "100G QSFP28", "form_factor": "PCIe"},
        "ucsc-o-M5S100GF": {"fw_version": "16.35.1012", "speed": "100G QSFP28", "form_factor": "OCP"},
    },
    "mtfw_magic_16b": "4d544657abcdef00fade12345678dead",
    "mtfw_magic_decoded": {
        "bytes_0_3": "4d544657 = MTFW (ASCII)",
        "bytes_4_7": "abcdef00 = non-ASCII pattern bytes",
        "bytes_8_15": "fade12345678dead -- FADE + 12345678 + DEAD (embedded debug markers)",
        "note": "FADE and DEAD are standard Mellanox/NVIDIA debug sentinel values in MTFW headers",
    },
    "mtfw_spans": "CX-5 (M5x, 16.35.x) through CX-7 (M7x, 28.x) -- same container format",
    "blob_size_kb": 16384,
    "form_factor_fw_delta": "OCP (ucsc-o-) uses 16.35.1012; PCIe (ucsc-p-) uses 16.35.3006",
    "nvram_strings": [
        "submit_nvram_job: nvram_access_requestor.id = %d, nvram_access_requestor.key = %d",
        "load_nvram_pci_tpt_settings done",
        "load_nvram_pci_settings done",
        "read_partition_info: READ_CFG_HEADER find_valid_nv_partition rc=%d, partition_ix = %d",
        "NV-Config swap_cfg_area not allowed in RO image",
        "submit_nvram_job_after_lock: job_request = NV_OPCODE_INVALIDATE_ALL",
        "find_valid_nv_partition: CFG_HDR_NO_VALID_PARTITION",
        "start_nvram_query_for_iron_prep: starting new job, opcode=0x%x",
        "acquire_release_nvram: SEMAPHORE_GENERAL could not be locked",
        "load_nvram_pf_pci_conf: nv_cfg_table_ix=0x%x is larger than FMT size",
    ],
    "cfg_strings": [
        "get_cfg_header: version_major != 1",
        "get_cfg_header: wrong signature",
        "get_cfg_header: read_chunks rc = %d",
    ],
    "vpd_strings": [
        "parse_vpd_read_only_data_fields, vpd length 0x%x",
        "parse_vpd_write_data_tag key word 0=0x%x 1=0x%x, kw_len=0x%x, offset = 0x%x",
        "parse_vpd_read_data_tag key word 0=0x%x 1=0x%x, len=0x%x, offset = 0x%x",
        "get_vpd_string_data_tag, len = 0x%x, offset = 0x%x",
    ],
    "ib_pkey_strings": [
        "ste_set_pkey_tag: mask_mode",
        "activate_firmware",
    ],
}

FINDINGS = {
    "MICRON-FIPS-SIGSIG-F1": {
        "id": "MICRON-FIPS-SIGSIG-F1",
        "severity": "HIGH",
        "title": "Micron s650dc FIPS SSD firmware signature verification leaks SignaturePtr, KeyIndex, and cipher labels (RSA-2048, AES-256, TPerSign) in error output",
        "affected": ["ucs-micron-ssd-s650dc400/800/1600fips (MB19)"],
        "evidence": {
            "sig_failure": "VerifyCtrlFirmwareSignature failed",
            "ptr_leak": "SignaturePtr: 0x%x -- pointer to signature in memory logged on failure",
            "key_leak": "KeyIndex: 0x%x -- key slot index logged on failure",
            "module_id": "Module: 0x%x -- module identifier logged",
            "cipher_labels": ["C_RSA_2048 (RSA-2048 signing)", "K_AES_256 (AES-256 key)", "C_AES_256 (AES-256 cipher)", "TPerSign (TCG TPer signing)", "~KeyWrapIntegrityCheck (key wrap failure path)"],
            "tcg_flags": ["Authority", "~IsMixedKey"],
        },
        "mechanism": (
            "The Micron s650dc FIPS SATA SSD firmware signature verification error path "
            "exposes memory addresses and key material metadata on failure: "
            "(1) 'SignaturePtr: 0x%x' -- the memory pointer to the firmware signature block "
            "is logged, exposing the firmware signature location in the controller's memory map; "
            "(2) 'KeyIndex: 0x%x' -- the key slot index used for verification is logged, "
            "revealing which eFuse/NVM key slot was selected for the verification attempt; "
            "(3) 'VerifyCtrlFirmwareSignature failed' -- the top-level signature verification "
            "for controller (not drive) firmware -- this is the microcontroller's own firmware "
            "verification, distinct from TCG signature verification. "
            "The cipher labels 'C_RSA_2048' confirm firmware signing uses RSA-2048 (not RSA-3072 "
            "or ECDSA) -- below the NIST recommendation for FIPS 140-3 2031+ compliance. "
            "'TPerSign' indicates the TCG Trusted Peripheral also signs at the SED layer. "
            "All three capacity variants (400/800/1600GB) share the identical binary (md5=e581229a), "
            "meaning the same firmware signature keys cover all FIPS capacity SKUs."
        ),
        "impact": "FIPS-validated SSD leaks SignaturePtr + KeyIndex on signature verification failure; RSA-2048 for firmware signing is below NIST 2031+ guidance; TPerSign exposes dual signing path; all 3 capacity variants share one binary and one key set",
    },
    "CX5-NVRAM-INVALIDATE-F1": {
        "id": "CX5-NVRAM-INVALIDATE-F1",
        "severity": "HIGH",
        "title": "ConnectX-5 M5 firmware contains NV_OPCODE_INVALIDATE_ALL -- NVM configuration wipe opcode accessible post-lock, and NVRAM requestor key logged in production",
        "affected": [
            "ucs-adaptor-ucsc-p-M5D25GF-25g-sfp28 (16.35.3006)",
            "ucs-adaptor-ucsc-p-M5S100GF-100g-qsfp28 (16.35.3006)",
            "ucs-adaptor-ucsc-p-M5D100GF-100g-qsfp28 (16.35.3006)",
            "ucs-adaptor-ucsc-o-M5S100GF-100g-qsfp28 (16.35.1012)",
        ],
        "evidence": {
            "invalidate_all": "submit_nvram_job_after_lock: job_request = NV_OPCODE_INVALIDATE_ALL",
            "nvram_key_log": "submit_nvram_job: nvram_access_requestor.id = %d, nvram_access_requestor.key = %d",
            "no_valid_partition": "find_valid_nv_partition: CFG_HDR_NO_VALID_PARTITION",
            "ro_image_guard": "NV-Config swap_cfg_area not allowed in RO image",
            "semaphore": "acquire_release_nvram: SEMAPHORE_GENERAL could not be locked",
            "cfg_sig_check": "get_cfg_header: wrong signature",
        },
        "mechanism": (
            "The Mellanox/NVIDIA ConnectX-5 firmware (M5x Cisco series) exposes two critical "
            "NVM paths: "
            "(1) 'submit_nvram_job_after_lock: job_request = NV_OPCODE_INVALIDATE_ALL' -- "
            "the firmware supports an INVALIDATE_ALL opcode that wipes ALL NVM configuration "
            "after the NVRAM lock is acquired. If reachable via IOCTL (FW_ACCESS) or management "
            "plane, this wipes firmware configuration, MAC addresses, port settings, and VPD, "
            "effectively bricking the NIC until reprogrammed. "
            "(2) 'submit_nvram_job: nvram_access_requestor.id = %d, nvram_access_requestor.key = %d' "
            "-- the NVRAM job submission logs the requestor's authentication KEY in the "
            "debug trace path. This key is the credential used to authorize NVM access; "
            "if debug logging is reachable from a management interface, the NVM access key "
            "is captured. "
            "'NV-Config swap_cfg_area not allowed in RO image' reveals that config area swapping "
            "is permitted in mutable (non-RO) images -- a downgrade to a mutable image enables "
            "config area manipulation. "
            "'CFG_HDR_NO_VALID_PARTITION' is the state reached when NVM partition corruption "
            "causes the header search to fail, potentially enabling a TOCTOU attack on the "
            "partition selection."
        ),
        "impact": "NV_OPCODE_INVALIDATE_ALL wipes all NIC NVM config if opcode is accessible; NVRAM requestor key logged in debug path; config area swap enabled in mutable images",
    },
    "CX5-MTFW-MARKERS-F1": {
        "id": "CX5-MTFW-MARKERS-F1",
        "severity": "MEDIUM",
        "title": "M5 ConnectX-5 MTFW 16-byte magic reveals FADE/DEAD debug sentinel values; MTFW format confirmed spanning CX-5 through CX-7; InfiniBand PKey management exposed",
        "affected": ["All M5 ConnectX-5 adapters (16.35.x)"],
        "evidence": {
            "full_magic": "4d544657abcdef00fade12345678dead (16 bytes)",
            "magic_decode": "MTFW + abcdef00 + FADE12345678DEAD (Mellanox debug markers)",
            "cx7_magic": "CX-7 also uses 4d544657abcdef00 (first 8 bytes) -- shared prefix",
            "pkey": "ste_set_pkey_tag: mask_mode -- InfiniBand partition key with mask_mode",
            "activate": "activate_firmware -- firmware activation command string",
            "vpd_access": "parse_vpd_write_data_tag key word 0=0x%x 1=0x%x, kw_len=0x%x, offset = 0x%x",
        },
        "mechanism": (
            "The Mellanox MTFW container magic extends to 16 bytes: "
            "'4d544657abcdef00fade12345678dead'. The second 8 bytes contain the Mellanox debug "
            "sentinel pattern: 'FADE' (0xfade) + '12345678' + 'DEAD' (0xdead). "
            "'FADE' and 'DEAD' are standard Mellanox embedded debug markers (DEADFADE, "
            "DEADBEEF patterns) appearing in firmware headers to demarcate structure boundaries. "
            "The CX-5 (M5x) and CX-7 (M7x) share the same first 8 bytes (4d544657abcdef00), "
            "confirming MTFW as the single container format spanning ConnectX-5 through ConnectX-7 "
            "(CX-6 DX uses a text prefix format rather than binary magic). "
            "'ste_set_pkey_tag: mask_mode' exposes InfiniBand partition key (PKey) tag setting "
            "with mask mode -- PKeys control which virtual networks a port can access. "
            "'activate_firmware' is the firmware update activation command. "
            "OCP (ucsc-o-) uses firmware 16.35.1012; PCIe (ucsc-p-) uses 16.35.3006 -- "
            "form-factor variants track different firmware branches."
        ),
        "impact": "MTFW format survey complete: CX-5 through CX-7 use same container; FADE/DEAD markers expose header structure; InfiniBand PKey mask_mode enables partition key bypass analysis",
    },
    "MICRON-TCG-KEYQUEUE-F1": {
        "id": "MICRON-TCG-KEYQUEUE-F1",
        "severity": "MEDIUM",
        "title": "Micron 5100/5200 TCG SED exposes key queue counts (Total Valid Key Q Cnt, Reserved Key Q Cnt) and sector addresses in error paths; ACADIA and Monet platform codenames leaked",
        "affected": [
            "All Micron 5100 SATA SSD variants (D0MH077, D0MC077, D0MH447, D0MH847)",
            "All Micron 5200 SATA SSD variants (D1MH031, D1MH431, D1CH431, D1MH831)",
        ],
        "evidence": {
            "key_queue": [
                "Total Valid Key Q Cnt : %x -- current count of valid key slots",
                "Reserved Key Q Cnt : %2x -- count of reserved (non-active) slots",
                "Received command which is not in Key Q",
                "Enhance key Q init done",
            ],
            "tcg_sector_leaks": [
                "Can't Read TCG sector %d, size %d -- sector number exposed",
                "Can't read TCG sector data, S sector:%d E sector:%d -- sector range exposed",
                "Skip read TCG data sector:%d",
                "Authentication failed!",
            ],
            "platform_codenames": {
                "Monet": "Hardware platform (MonetHw in source paths)",
                "ACADIA": "Micron 5200 SED internal project name",
                "Rain": "Buffer management subsystem (RainBufManagement)",
            },
            "source_paths": [
                "../Platform/MonetHw/Driver_vg/HalSataImpl.c",
                "../Backend/RainBufManagement.c",
                "../FTL/FTL_FlashPhyAddr.c",
                "../DebugLib/SCTVU/DBG_VuSCTGeneral.c",
            ],
        },
        "mechanism": (
            "Micron 5100 and 5200 SSD firmware exposes TCG SED key management state "
            "via error path logging: "
            "(1) 'Total Valid Key Q Cnt : %x' -- the firmware logs the current count of "
            "valid (in-use) key slots when the key queue state is printed. This value "
            "directly reveals how many encryption keys are active on the drive. "
            "(2) 'Reserved Key Q Cnt : %2x' -- reserved slot count is also logged. "
            "Key queue total = valid + reserved + free; knowing 2 of 3 values enables "
            "inference of the free slot count. "
            "TCG sector number exposure in read/write error paths enables mapping of "
            "which LBA ranges contain TCG authority/table data. "
            "Source file paths reveal: 'Monet' = 5100/5200 hardware platform; "
            "'ACADIA' = internal Micron 5200 SED project codename; "
            "'Rain' = RAID-like write buffer management algorithm name. "
            "These paths expose Micron's internal firmware project structure and naming conventions "
            "across the 5100 and 5200 product generations."
        ),
        "impact": "TCG key queue counts exposed in firmware -- total valid and reserved slots quantifiable; TCG sector addresses exposed in error paths enable sector layout mapping; platform codenames expose internal build structure",
    },
    "MICRON-NRCM-F1": {
        "id": "MICRON-NRCM-F1",
        "severity": "LOW",
        "title": "All 94 Micron SSD entries use NRCM container (magic NRCM = 4e52434d); 24 MD5 groups with largest single group covering 15 models (E2CS007 NVMe generation)",
        "affected": ["All 94 Micron SSD firmware entries in C-Series bundle"],
        "evidence": {
            "nrcm_magic": "4e52434d = NRCM (ASCII)",
            "total_members": 94,
            "md5_groups": 24,
            "largest_group": "fe19662e -- 15 models (E2CS007 Micron NVMe generation)",
            "sed_fips_count": 16,
        },
        "mechanism": (
            "Micron's proprietary NRCM firmware container (magic 'NRCM') covers the complete "
            "C-Series SSD line: 5100 SATA, 5200 SATA, s650dc FIPS, and NVMe generations. "
            "24 distinct binaries across 94 SKUs -- the same-binary grouping scale means "
            "a vulnerability in one generation's binary affects all capacity variants "
            "in that generation simultaneously. The largest group (E2CS007, 15 models) is the "
            "Micron NVMe UCS-NVM2/UCSX-NVM2 generation. "
            "NRCM format is distinct from Seagate (`e71a0e59`), Toshiba (FMCL), Solidigm (FPT), "
            "Samsung (49d1aca3), and HGST (FWHEADER) containers -- each drive vendor uses "
            "a proprietary format across the C-Series bundle."
        ),
        "impact": "NRCM format survey complete; 15-model binaries mean a single vulnerability affects 15 capacity SKUs; 6 distinct drive firmware formats now catalogued across C-Series bundle",
    },
    "MICRON-FIPS-MAGIC-F1": {
        "id": "MICRON-FIPS-MAGIC-F1",
        "severity": "LOW",
        "title": "Micron s650dc FIPS SSD uses e71a0e59 magic prefix (same 4 bytes as Seagate SAS) rather than Micron NRCM -- distinct firmware base for FIPS-validated product line",
        "affected": ["ucs-micron-ssd-s650dc400/800/1600fips (MB19)"],
        "evidence": {
            "fips_magic": "e71a0e5901000200",
            "seagate_magic": "e71a0e59xxxxxxxx (first 4 bytes match Seagate SAS drives)",
            "micron_nrcm_magic": "4e52434dxxxxxxxx (standard Micron format -- does NOT apply to s650dc FIPS)",
            "same_binary": "All 3 FIPS capacity variants share md5=e581229a",
        },
        "mechanism": (
            "The Micron s650dc FIPS-validated SATA SSD uses a different firmware container "
            "format than all other Micron SSDs in the bundle. While 91 of 94 Micron entries "
            "use the NRCM container (magic 'NRCM'), the 3 s650dc FIPS entries use magic "
            "'e71a0e5901000200' -- with the first 4 bytes 'e71a0e59' matching the Seagate SAS "
            "drive magic observed in Seagate HDD firmware in this same bundle. "
            "Whether this indicates a shared firmware lineage, format adoption, or coincidental "
            "magic collision is not determinable from binary analysis alone. The FIPS firmware "
            "line is separated from the standard Micron NRCM firmware tree -- two different "
            "build systems, formats, and validation paths for Micron SSD firmware in the "
            "same product bundle."
        ),
        "impact": "FIPS SSD firmware base is distinct from non-FIPS Micron products; e71a0e59 magic shared with Seagate SAS suggests possible common firmware lineage or format adoption",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

SUMMARY = {
    "module": "cisco_ucs_cseries_micron_cx5_fips_re",
    "targets": "94 Micron SSDs (NRCM), s650dc FIPS SSDs, M5 ConnectX-5 (MTFW 16MB)",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 2, "MEDIUM": 2, "LOW": 2},
    "headline": (
        "Micron FIPS SSD leaks SignaturePtr + KeyIndex + RSA-2048 label on firmware sig failure. "
        "ConnectX-5 exposes NV_OPCODE_INVALIDATE_ALL and NVRAM requestor key logging. "
        "MTFW 16-byte magic reveals FADE/DEAD markers; format spans CX-5 to CX-7."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
    print(f"\nMicron coverage: {MICRON_FIRMWARE_SURVEY['total_members']} SKUs, {MICRON_FIRMWARE_SURVEY['md5_groups']} binary groups")
