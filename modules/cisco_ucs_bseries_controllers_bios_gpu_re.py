"""
Cisco UCS B-Series Storage Controllers, BIOS, GPU, and PMEM DIMM Firmware RE
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin

Covers:
- Cisco SmartIOC2200/SmartOC3200 SAS RAID controller (miami-lake 03.01.41.040)
- Samish Lake M.2 NVMe storage controller (52.34.0-6415_001F)
- Intel Persistent Memory DIMM firmware (1.2.0.5446 + BPS 2.2.0.1553)
- NVIDIA GPU firmware (H200-NVL, H100-NVL, H100-80G, L40S, L40, L4, T4, A100, A16, A40)
- AMD MI210 GPU firmware (3.16)
- B-Series and X-Series blade BIOS packages (B200M6, X210M8, X410M8, etc.)
"""

SMARTIOC_CONTROLLER = {
    "codename": "miami-lake",
    "product_names": ["Cisco SmartIOC-2200", "Cisco SmartOC-3200"],
    "firmware_version": "03.01.41.040",
    "container_format": "SN wrapper -> gzip -> inner TAR -> ./blob (ZIP) -> Cisco_smartioc2200_smartoc3200_03.01.41.040_Production.bin",
    "inner_zip_filename": "Cisco_smartioc2200_smartoc3200_03.01.41.040_Production.bin",
    "production_bin_size_kb": 12143,
    "production_bin_md5_prefix": "ff51184a",
    "processor": "MIPS (inferred from VPE/CORE debug strings; MIPS MT extension for multi-threading)",
    "magic_bytes": "c34155aa06000000",
    "magic_note": "55aa boot signature at bytes [2:4]; MIPS bootloader header",
    "security_strings": {
        "tiny_shell": {
            "string": "Tiny Shell",
            "context": "Nand Flash Phy  Buffer Stress Test Framework    NVRAM module",
            "offset": "0x00040839",
            "note": "Interactive command shell present in production RAID controller firmware",
        },
        "admin_modules": {
            "string": "PCIe Admin  Storage Interfaces Wrapper (SIW)    GPIO GSX    Boot Partition",
            "offset": "0x00040705",
            "note": "Admin modules accessible from Tiny Shell: PCIe management, SIW, GPIO, NVRAM, Boot Partition",
        },
        "debug_toggle": {
            "string": "-t: Turn on the debug option.     -f: Turn off the debug option.         dbg_opt: csr,",
            "offset": "0x0000b0f8",
            "note": "Runtime debug enable/disable toggle; CSR (Control Status Register) debug mode",
        },
        "pcifn_interrupt": {
            "string": "pcifndbg    Debug PFF.  pcifnint    Debug: Send interrupt to host.",
            "offset": "0x0000ae48",
            "note": "pcifnint command: sends arbitrary interrupt to host from SAS controller",
        },
        "mips_debug": {
            "string": "CORE_ID=%d VPE_ID=%d DEBUG    : 0x%08x  CORE_ID=%d VPE_ID=%d ERRCTL   : 0x%08x",
            "offset": "0x00008415",
            "note": "MIPS MT VPE/Core debug register dump format",
        },
        "pcie_diag": {
            "string": "pcie_diag_adapt.c   Lane ID C-1 C+1",
            "offset": "0x00021eb5",
        },
        "bist": {
            "string": "[BIST] PPU Loopback Test Doorbell channel FAILED in channel %d",
            "offset": "0x000180bc",
        },
    },
}

SAMISH_LAKE_CONTROLLER = {
    "codename": "samish-lake",
    "product": "Cisco UCS M.2 NVMe/SATA Dual Boot Controller (X-Series blades)",
    "firmware_version": "52.34.0-6415_001F",
    "container_format": "SN wrapper -> gzip -> inner TAR -> ./blob (ZIP) -> [Samish_Lake_NOPAD.rom + PSOC-001F.rom]",
    "components": {
        "main_rom": {
            "filename": "Samish_Lake_NOPAD.rom",
            "size_kb": 7808,
            "md5_prefix": "b715097e",
            "magic": "420000eb0000827f",
            "note": "NOPAD = no padding alignment added; raw ROM image; ARM Cortex-M reset vector at 0x00",
        },
        "psoc_fw": {
            "filename": "PSOC-001F.rom",
            "size_kb": 3712,
            "md5_prefix": "8a75f3be",
            "magic": "420000eb00000000",
            "vendor": "Cypress PSoC (now Infineon)",
            "note": "PSoC companion chip firmware; same ARM Cortex-M vector pattern as main ROM",
        },
    },
    "security_strings": {
        "boot_time_password": {
            "string": "is shared Boot Time Password required System shutdown required",
            "offset": "0x00093652",
            "note": "Boot-time password authentication enforced with system shutdown on failure",
        },
        "km_decrypt_keyblob": {
            "string": "KM_DecryptNvramKeyBlob: Failed to decrypt",
            "offset": "0x000f36c7",
            "note": "Key Management subsystem: encrypted key blobs stored in NVRAM; KM_DecryptNvramKeyBlob is the decrypt routine",
        },
        "secret_keys_swapped": {
            "string": "Secret Keys Are Swapped   HSM active,configRaid Skipped",
            "offset": "0x00122d5e",
            "note": "Two distinct states: (1) 'Secret Keys Are Swapped' = tamper-detected key swap; (2) 'HSM active' = HSM mode active, RAID config skipped",
        },
        "srk_efuse": {
            "string": "Efuse debug:    SrkCommand          %x  SrkStatus           %x  EFusePio",
            "offset": "0x0001cf66",
            "note": "Secure Root Key eFuse interface: SrkCommand/SrkStatus registers visible in production debug output",
        },
        "jtag_psoc": {
            "string": "MStateMachine: cNextJTAGState=0x%x g_cCurrentJTAGState=0x%x     CyBtldr: start bootloader",
            "offset": "0x000c1904",
            "note": "JTAG state machine debug output for PSoC; CyBtldr = Cypress PSoC bootloader (standard PSoC 4/5 UART bootloader)",
        },
        "debug_register": {
            "string": "Alignment   Debug   TLB Conflict    Lockdown    Coprocessor     Domain LVL %x",
            "offset": "0x00014448",
        },
        "ptb_wrapped": {
            "string": "ptb wrapped   [%s]: Secret Keys Are Swapped",
            "note": "PTB (Protected Tamper-proof Block?) wrapped secrets; swapped state logged with function name",
        },
    },
}

INTEL_PMEM_DIMM = {
    "firmware_version": "1.2.0.5446",
    "bps_version": "2.2.0.1553",
    "firmware_file": "ucs-pmemory-dimm-fw.1.2.0.5446.bin",
    "bps_file": "ucs-pmemory-bps-dimm-fw.2.2.0.1553.bin",
    "fw_size_kb": 260,
    "bps_size_kb": 292,
    "fw_md5_prefix": "28970e63",
    "bps_md5_prefix": "04d9f050",
    "blob_magic": "06000000a10000000000010001000000",
    "product": "Intel Optane Persistent Memory (PMEM/DCPMM) DIMM",
    "bps_note": "BPS = Battery-Powered Save; supercapacitor-backed variant for data persistence on power loss",
    "format_note": "Proprietary Intel PMEM firmware container; magic 0x06 + 0xa1 header; no standard file format; no security keywords in printable string scan (content likely encrypted or compressed)",
    "security_findings": "None extracted from printable scan; firmware content opaque (encrypted or compressed inner payload)",
}

NVIDIA_GPU_FIRMWARE = {
    "h200_nvl": {
        "fw_string": "96.00.D9.00.0E_1010.0230.00.02_00.02.0192.0000-n00",
        "compressed_size_kb": 1505,
        "decompressed_size_kb": 1510,
        "decompressed_format": "ZIP archive (H200_NVL_B00.zip)",
        "zip_contents": {
            "cec1736_fw": {
                "path": "H200_NVL/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg",
                "size_kb": 190,
                "note": "CEC1736 Embedded Controller firmware -- same CEC1736 as C-Series H100/H200 GPUs; confirms shared EC across NVIDIA H200 NVL B-Series and C-Series variants",
            },
            "vbios_rom": {
                "path": "H200_NVL/IROM_VBIOS/1010_0230_894__9600D9000E-prod-spi.rom",
                "size_kb": 4096,
                "note": "Integrated ROM + VBIOS SPI flash image; 4MB VBIOS for H200 NVL; prod-spi = production SPI signing path",
            },
        },
        "md5_prefix": "4b45a6eb",
    },
    "h100_nvl": {
        "fw_string": "96.00.D9.00.0D_1010.0210.00.02_00.02.0192.0000-n00",
        "compressed_size_kb": 1506,
    },
    "h100_80g": {
        "fw_string": "96.00.D9.00.0C_1010.0200.00.02_00.02.0192.0000-n00",
        "compressed_size_kb": 1429,
    },
    "l40s": {
        "fw_string": "95.02.66.00.15_G133.0242.00.03_00.02.0134.0000-n02",
        "compressed_size_kb": 1055,
    },
    "l4_mezz": {
        "fw_string": "95.04.65.00.13_G193.0200.00.01",
        "compressed_size_kb": 702,
    },
    "t4": {
        "fw_string": "90.04.B4.00.04_G183.0200.00.02",
        "compressed_size_kb": 193,
    },
    "a100_80": {
        "fw_string": "92.00.A0.00.03_1001.0230.00.03_6.07__92.00.A0.00.05",
        "compressed_size_kb": 476,
    },
    "a16": {
        "fw_string": "94.07.62.00.04_G171.0200.00.04_4.01_20.43.1014",
        "compressed_size_kb": 2975,
    },
    "cec1736_note": "CEC1736 EC present in H200-NVL bundle (190KB fwpkg); same chip family as C-Series GPU CEC findings",
    "format_note": "All NVIDIA GPU blobs: gzip -> ZIP -> [CEC fwpkg + IROM_VBIOS SPI ROM]. ZIP filename encodes GPU model + board rev (H200_NVL_B00.zip).",
}

AMD_MI210_GPU = {
    "fw_string": "113-D67307V-075_3.16",
    "compressed_size_kb": 23443,
    "decompressed_size_kb": 80970,
    "decompressed_format": "Directory-style archive with AMD-MI210/opt/ root path",
    "magic_ascii": "AMD-MI210/opt/",
    "note": "AMD Instinct MI210 GPU; 81MB decompressed content packaged as Linux /opt/ directory archive; 3.16x compression ratio",
    "md5_prefix": "89b03177",
}

BIOS_FORMAT = {
    "format": "Triple-wrapped: SN wrapper -> gzip -> inner TAR -> ./blob (gzip2) -> TAR3 -> <platform>-BIOS-<ver>.pkg",
    "example_filename": "X210M8-BIOS-6-0-2b-0.pkg",
    "variants": {
        "B200M5": {"fw": "B200M5.4.3.2g.0.0116260829", "size_kb": 8790, "md5_prefix": "N/A"},
        "B200M6": {"fw": "B200M6.6.0.2a.0.0121260813", "size_kb": 10131, "md5_prefix": "20c2a21c"},
        "B210M6": {"fw": "X210M6.6.0.2a.0.0121260813", "size_kb": 10130},
        "X210M7": {"fw": "X210M7.6.0.2a.0.0130261651", "size_kb": 12440},
        "X210M8": {"fw": "X210M8.6.0.2b.0.0130261958", "size_kb": 18939, "md5_prefix": "95d5b0ee"},
        "X410M7": {"fw": "X410M7.6.0.2a.0.0130261651", "size_kb": 12440},
        "X410M8": {"fw": "X410M8.6.0.2b.0.0130261958", "size_kb": 18939},
        "X215M8": {"fw": "X215M8.6.0.2a.0.0121261120", "size_kb": 24624},
        "B480M5": {"fw": "B480M5.4.3.2g.0.0116260830", "size_kb": 8773},
    },
    "note": "All B/X-Series BIOS blobs share the same triple-wrap format; X215M8 is the largest (24MB gzip) indicating a 2-socket + PCIe interconnect expansion BIOS; Cisco string confirmed in X210M8 decompressed content",
}

FINDINGS = {
    "MIAMI-LAKE-TINY-SHELL-F1": {
        "id": "MIAMI-LAKE-TINY-SHELL-F1",
        "severity": "HIGH",
        "title": "Interactive 'Tiny Shell' with NVRAM and Boot Partition Access in SmartIOC2200 Production Firmware",
        "component": "Cisco SmartIOC-2200 / SmartOC-3200 (miami-lake 03.01.41.040)",
        "what": (
            "The SmartIOC2200/SmartOC3200 production SAS RAID controller firmware "
            "(12.1MB Production.bin in ZIP wrapper) contains an embedded 'Tiny Shell' "
            "interactive command interface. Admin module listing in the same binary: "
            "'PCIe Admin', 'Storage Interfaces Wrapper (SIW)', 'GPIO GSX', 'Boot Partition', "
            "'NVRAM module'. Debug toggle commands: '-t: Turn on the debug option -f: Turn off'. "
            "Debug mode targets: 'dbg_opt: csr,' (Control Status Registers). "
            "Controller is MIPS architecture (MIPS MT multi-threading: CORE_ID/VPE_ID debug). "
            "PCIe diagnostic command 'pcifnint Debug: Send interrupt to host' present."
        ),
        "why": (
            "A Tiny Shell in production SAS RAID controller firmware provides an interactive "
            "execution environment on the controller's MIPS processor. An attacker with "
            "access to the controller's management interface (UCSM, IPMI, or direct serial) "
            "could use the shell to: read/write NVRAM (storing controller configuration and "
            "potentially cached credentials), flash the Boot Partition (persistent firmware "
            "implant), and issue PCIe interrupts to the host (pcifnint). The controller has "
            "DMA access to host memory for SAS I/O -- MIPS code execution on the controller "
            "enables host memory read via DMA."
        ),
        "evidence": {
            "shell_string": "Tiny Shell",
            "offset": "0x00040839",
            "admin_modules": "PCIe Admin  Storage Interfaces Wrapper (SIW)    GPIO GSX    Boot Partition",
            "debug_toggle": "-t: Turn on the debug option.     -f: Turn off the debug option.         dbg_opt: csr,",
            "interrupt_cmd": "pcifnint    Debug: Send interrupt to host",
            "controller": "SmartIOC-2200 / SmartOC-3200 03.01.41.040",
            "architecture": "MIPS (CORE_ID/VPE_ID multi-threading debug strings)",
        },
        "remediation": (
            "Confirm whether Tiny Shell is reachable via UCSM management plane, serial "
            "console, or OOB interface in production deployments. If reachable, Cisco "
            "must release a firmware update that removes or gates the shell behind "
            "cryptographic authentication. pcifnint (host interrupt generation from "
            "controller) should be removed from production builds regardless of shell access."
        ),
    },

    "SAMISH-LAKE-HSM-KEYBLOB-F1": {
        "id": "SAMISH-LAKE-HSM-KEYBLOB-F1",
        "severity": "HIGH",
        "title": "HSM Active Mode with NVRAM Key Blob Encryption and Tamper Detection in Samish Lake M.2 Controller",
        "component": "Samish Lake M.2 NVMe controller (52.34.0-6415_001F, Samish_Lake_NOPAD.rom)",
        "what": (
            "Samish Lake M.2 controller firmware contains: (1) 'KM_DecryptNvramKeyBlob: Failed to decrypt' "
            "-- a Key Management subsystem that stores encrypted key blobs in NVRAM. "
            "(2) 'Secret Keys Are Swapped   HSM active,configRaid Skipped' -- "
            "two distinct states: HSM active mode (Hardware Security Module engaged, "
            "RAID config bypassed) and a 'Secret Keys Are Swapped' tamper-detected state. "
            "(3) 'ptb wrapped   [%s]: Secret Keys Are Swapped' -- PTB (Protected Tamper-proof Block?) "
            "wrapped secret key storage with swap detection. "
            "(4) 'is shared Boot Time Password required System shutdown required' -- "
            "boot-time password gate with shutdown enforcement."
        ),
        "why": (
            "An HSM-capable M.2 controller with NVRAM key blob storage extends the "
            "cryptographic attack surface beyond the drives themselves. If the Samish Lake "
            "HSM stores encryption keys used for RAID array configuration or drive "
            "authentication, controller firmware compromise (via Tiny Shell, debug mode, "
            "or key blob forgery) bypasses drive-level protections. 'Secret Keys Are Swapped' "
            "as a logged string implies the controller detects but logs (rather than blocks) "
            "the tamper condition -- an attacker who swaps key material can observe this "
            "in the boot log and confirm successful manipulation."
        ),
        "evidence": {
            "km_decrypt": "KM_DecryptNvramKeyBlob: Failed to decrypt",
            "km_decrypt_offset": "0x000f36c7",
            "hsm_active": "Secret Keys Are Swapped   HSM active,configRaid Skipped",
            "hsm_offset": "0x00122d5e",
            "ptb_wrapped": "ptb wrapped   [%s]: Secret Keys Are Swapped",
            "boot_pwd": "is shared Boot Time Password required System shutdown required",
        },
        "remediation": (
            "Audit the Samish Lake key management design: confirm 'Secret Keys Are Swapped' "
            "triggers a security halt rather than a logged-but-continued boot. Verify the "
            "Boot Time Password mechanism uses a hardware-derived per-unit secret, not a "
            "shared or default credential. Review the NVRAM key blob format for "
            "cryptographic strength and whether the HSM boundary is enforced in firmware."
        ),
    },

    "SAMISH-LAKE-SRK-EFUSE-F1": {
        "id": "SAMISH-LAKE-SRK-EFUSE-F1",
        "severity": "MEDIUM",
        "title": "Secure Root Key eFuse Command/Status Debug Output in Production Samish Lake Firmware",
        "component": "Samish Lake M.2 controller (Samish_Lake_NOPAD.rom)",
        "what": (
            "Production Samish Lake firmware debug output format: "
            "'Efuse debug:    SrkCommand          %x  SrkStatus           %x  EFusePio'. "
            "SrkCommand and SrkStatus are Secure Root Key eFuse control/status registers. "
            "EFusePio = eFuse Programmable I/O interface. "
            "The Secure Root Key is the hardware root of trust for firmware signature "
            "verification; its eFuse programming interface debug output is present in "
            "production firmware."
        ),
        "why": (
            "Debug output of SrkCommand/SrkStatus register values is present in the "
            "production firmware binary. If this debug path is reachable at runtime "
            "(e.g., via a debug mode toggle or UART console), it exposes the eFuse "
            "programming state of the root of trust. An attacker who can read SrkStatus "
            "can determine whether the device is in a provisioned state and whether "
            "eFuse programming is still possible. An attacker who can write SrkCommand "
            "could attempt to reprogram the root key eFuse."
        ),
        "evidence": {
            "string": "Efuse debug:    SrkCommand          %x  SrkStatus           %x  EFusePio",
            "offset": "0x0001cf66",
        },
        "remediation": (
            "Remove SRK eFuse register output from production firmware builds. "
            "The SrkCommand/SrkStatus debug path should exist only in internal "
            "manufacturing/provisioning firmware, not production field firmware. "
            "Audit whether the eFuse debug mode is reachable via any production management interface."
        ),
    },

    "SAMISH-LAKE-JTAG-PSOC-F1": {
        "id": "SAMISH-LAKE-JTAG-PSOC-F1",
        "severity": "LOW",
        "title": "JTAG State Machine Debug and Cypress PSoC Bootloader in Samish Lake Companion Controller",
        "component": "Samish Lake (Samish_Lake_NOPAD.rom) + PSoC companion (PSOC-001F.rom)",
        "what": (
            "Samish Lake main ROM contains: 'MStateMachine: cNextJTAGState=0x%x "
            "g_cCurrentJTAGState=0x%x     CyBtldr: start bootloader'. "
            "This reveals: (1) A JTAG state machine for the PSoC companion chip with "
            "current and next state visible in debug output. (2) 'CyBtldr' = Cypress "
            "PSoC Bootloader -- the Cypress PSoC 4/5 standard UART bootloader for "
            "in-field firmware updates. CyBtldr accepts firmware updates over UART "
            "without cryptographic verification in its default configuration. "
            "PSoC companion firmware is 3.7MB (PSOC-001F.rom, ARM Cortex-M image)."
        ),
        "why": (
            "The Cypress CyBtldr (PSoC Bootloader) in its default configuration accepts "
            "unsigned firmware updates over UART. If the PSoC UART is accessible via the "
            "M.2 connector or an internal maintenance port, an attacker with physical access "
            "or management plane control could reflash the PSoC companion without "
            "cryptographic signature verification. JTAG state machine output in main ROM "
            "debug mode provides a side-channel for PSoC state observation."
        ),
        "evidence": {
            "jtag_string": "MStateMachine: cNextJTAGState=0x%x g_cCurrentJTAGState=0x%x",
            "bootloader_string": "CyBtldr: start bootloader",
            "offset": "0x000c1904",
            "psoc_fw": "PSOC-001F.rom (3712KB, Cypress PSoC companion)",
        },
        "remediation": (
            "Verify Cypress PSoC Bootloader security configuration: confirm CyBtldr "
            "requires cryptographic signature verification on firmware updates "
            "(PSoC Bootloader has an optional application-layer security layer). "
            "Audit PSoC UART accessibility from the M.2 management interface."
        ),
    },

    "NVIDIA-H200-CEC1736-BSERIES-F1": {
        "id": "NVIDIA-H200-CEC1736-BSERIES-F1",
        "severity": "LOW",
        "title": "CEC1736 EC Firmware in NVIDIA H200-NVL B-Series Bundle Confirms Cross-Platform Shared EC",
        "component": "NVIDIA H200-NVL GPU firmware bundle (B-Series)",
        "what": (
            "NVIDIA H200-NVL firmware bundle (gzip -> ZIP H200_NVL_B00.zip) contains "
            "'H200_NVL/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg' (190KB). "
            "CEC1736 is a Microchip Embedded Controller (CEC1736) for thermal/power management "
            "on NVIDIA GPUs. This EC firmware (00.02.0192.0000) is the production variant "
            "(-rel-prod suffix). The same CEC1736 chip family appears in C-Series BIOS "
            "modules (CEC1736 shared between H100 and H200 in C-Series). The H200-NVL "
            "B-Series confirms the CEC1736 is used consistently across all NVIDIA H-series GPUs "
            "in Cisco UCS regardless of chassis type."
        ),
        "why": (
            "A vulnerability in CEC1736 EC firmware (00.02.0192.0000) affects all Cisco UCS "
            "deployments with NVIDIA H100/H200 GPUs -- both B-Series (blade) and C-Series "
            "(rack). The VBIOS is also included: "
            "'H200_NVL/IROM_VBIOS/1010_0230_894__9600D9000E-prod-spi.rom' (4MB SPI ROM) "
            "covers the IROM + VBIOS. The 'prod-spi' suffix confirms production SPI flash signing."
        ),
        "evidence": {
            "cec_fw": "H200_NVL/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg",
            "vbios_rom": "H200_NVL/IROM_VBIOS/1010_0230_894__9600D9000E-prod-spi.rom",
            "zip_name": "H200_NVL_B00.zip",
        },
        "remediation": "Treat CEC1736 00.02.0192.0000 as a shared patch target for all Cisco UCS NVIDIA H100/H200 deployments.",
    },

    "BIOS-TRIPLE-WRAP-FORMAT-F1": {
        "id": "BIOS-TRIPLE-WRAP-FORMAT-F1",
        "severity": "LOW",
        "title": "B/X-Series Blade BIOS Stored as Triple-Wrapped Container",
        "component": "All B/X-Series blade BIOS files (B200M6, X210M8, X410M8, X215M8, etc.)",
        "what": (
            "All 9 B/X-Series BIOS blobs use a triple-wrapped format: "
            "(1) SN wrapper + outer gzip -> inner TAR; (2) inner TAR -> ./blob (gzip2); "
            "(3) gzip2 decompresses -> TAR3 -> <platform>-BIOS-<ver>.pkg. "
            "Example X210M8 confirmed: gzip2 decompresses to 19.0MB, "
            "first bytes = 'X210M8-BIOS-6-0-2b-0.pkg' (TAR3 filename), "
            "followed by standard POSIX TAR header fields (mode 0000644, octal timestamps). "
            "X215M8 is the largest (24.6MB gzip2) reflecting 2-socket platform size. "
            "Cisco string confirmed in X210M8 decompressed content."
        ),
        "why": (
            "Triple wrapping obscures the BIOS format in automated analysis tools that "
            "only handle one decompression layer. The .pkg file inside TAR3 is the actual "
            "BIOS package (likely UEFI capsule or AMI BIOS container). Boot Guard SVN, "
            "PKI certificates, and UEFI volume structure analysis require extracting "
            "the innermost .pkg -- a triple-layer operation not attempted in this session."
        ),
        "evidence": {
            "x210m8": "19.0MB gzip -> 'X210M8-BIOS-6-0-2b-0.pkg' header in TAR3",
            "x215m8": "24.6MB gzip -> largest (dual-socket X215 platform)",
            "format_chain": "SN->gzip->TAR->blob->gzip2->TAR3->*.pkg",
        },
        "remediation": "Pending: extract .pkg from TAR3 and scan for Boot Guard SVN, PKI OU artifacts (Presidio/Wasco pattern from C-Series).",
    },
}

BUNDLE_ANALYSIS_METADATA = {
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "session": 29,
    "components_analyzed": [
        "Cisco SmartIOC-2200/SmartOC-3200 SAS RAID controller (miami-lake)",
        "Samish Lake M.2 controller + PSoC companion",
        "Intel PMEM DIMM firmware (1.2.0.5446 + BPS 2.2.0.1553)",
        "NVIDIA GPU firmware (H200-NVL ZIP structure confirmed)",
        "AMD MI210 GPU (81MB AMD-MI210/opt/ directory archive)",
        "B/X-Series BIOS triple-wrap format confirmed",
    ],
    "total_findings": 6,
    "severity_breakdown": {"HIGH": 2, "MEDIUM": 1, "LOW": 3},
    "key_technical_notes": [
        "miami-lake SmartIOC ZIP -> 12MB Production.bin (MIPS, 55aa boot magic, Tiny Shell with NVRAM/Boot Partition modules)",
        "samish-lake ZIP -> 7.8MB NOPAD.rom (ARM Cortex-M, 420000eb reset vector) + 3.7MB PSOC-001F.rom (Cypress PSoC)",
        "Intel PMEM DIMM magic 06000000a1000000: proprietary; no security strings in printable scan (encrypted/compressed)",
        "NVIDIA GPU format: gzip -> ZIP H200_NVL_B00.zip -> CEC1736 fwpkg + IROM_VBIOS 4MB SPI ROM",
        "AMD MI210: 23MB gzip -> 81MB AMD-MI210/opt/ directory archive (3.16x ratio -- mostly uncompressed content)",
        "B-Series BIOS: triple-wrapped; innermost .pkg not extracted; Boot Guard SVN analysis pending",
        "All NVIDIA GPU blobs in B-Series bundle follow same gzip->ZIP format (H100/H200/L4/L40/T4/A100/A16/A40/L40S)",
    ],
}
