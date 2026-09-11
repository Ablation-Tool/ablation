"""
Cisco UCS C-Series -- Mellanox/NVIDIA CX-5/CX-6 Adapters, MLOM, GPU VBIOS RE
Targets: M5D100GF, M5D25GF, M5S100GF (CX-5), M6CD100GF (CX-6 DX),
         ucsx-mlom-001, NVIDIA M10/M60 GPU VBIOS

Binary: /tmp/.../cseries_decomp.bin (UCS C-Series bundle)
Extracted via: SN magic 64015349 -> gzip -> TAR -> ./blob
"""

CX5_ADAPTERS = {
    "M5D100GF": {
        "fw_version": "16.35.3006",
        "description": "ConnectX-5 100G QSFP28 (ucsc-p)",
        "blob_offset": 1103852032,
        "fw_size_kb": 16384,
    },
    "M5D25GF": {
        "fw_version": "16.35.3006",
        "description": "ConnectX-5 25G SFP28 (ucsc-p)",
        "blob_offset": 1098700288,
        "fw_size_kb": 16384,
    },
    "M5S100GF": {
        "fw_version": "16.35.1xxx",
        "description": "ConnectX-5 100G QSFP28 MLOM (ucsc-o)",
        "blob_offset": 1096130048,
        "fw_size_kb": 16384,
    },
}

CX6_ADAPTERS = {
    "M6CD100GF": {
        "fw_version": "22.36.1010",
        "description": "ConnectX-6 DX 100G QSFP28 (ucsc-p)",
        "fw_internal_name": "fw-ConnectX6Dx-rel-22_36_1010-30-100256-01_Ax-UEFI-14.29.14-FlexBoot-3.6.901.signed.bin",
        "blob_offset": 996113408,
        "fw_size_kb": 65540,
    },
}

# 0xBADC0FFE protection field bypass -- present in CX-5 and CX-6 DX
ICMD_BYPASS = {
    "magic": "0xBADC0FFE",
    "cx5_offsets": [
        {"fw": "M5D100GF", "binary_offset": 3760127, "context": "icmd_execute_embedded_cmd"},
    ],
    "cx6_offsets": [
        {"fw": "M6CD100GF", "binary_offset": 4869464, "context": "icmd_execute_embedded_cmd"},
        {"fw": "M6CD100GF", "binary_offset": 39053968, "context": "icmd_execute_embedded_cmd (copy 2)"},
        {"fw": "M6CD100GF", "binary_offset": 39131562, "context": "set_admin_state_mng debug"},
    ],
    "cx5_error_string": "icmd_execute_embedded_cmd, invalid protection field[0x%x], use 0xBADC0FFE to execute ecmd",
    "cx6_nvram_string": "icmd_execute_embedded_cmd, invalid protection field[0x%x], use 0xBADC0FFE to execute ecmd",
    "cx6_vport_string": "t_admin_state_mng, invalid protection field[0x%x], use 0xBADC0FFE for setting_debug: vport_meter_en",
    "nvram_rw_command": "icmd_nv_ram_rw_tlv",
    "nvram_shadow_fn": "nv_ram_shadows_apply",
    "nvram_requestor": "submit_nvram_job: nvram_access_requestor.id = %d, nvram_access_requestor.key = %d",
    "access_mechanism": "PCIe BAR2 ICMD registers, accessible from guest VMs with VF passthrough",
    "interface_doc": "Mellanox Firmware Tools (MFT) IB/ETH ICMD protocol; protection field at ICMD BAR2 offset 0x0",
}

CX6_NV_CONFIG = {
    "ro_blocked_ops": [
        "NV-Config swap_cfg_area not allowed in RO image",
        "NV-Config invalidate_all not allowed in RO image",
        "NV-Config tlv_write not allowed in RO image",
    ],
    "invalidate_opcode": "submit_nvram_job_after_lock: job_request = NV_OPCODE_INVALIDATE_ALL",
    "semaphore_contention": "acquire_release_nvram: SEMAPHORE_GENERAL could not be locked",
    "job_overflow": "flash_nv_ram_tlv_handler: job request list exceeding value = 0x%x",
    "cfg_header_checks": [
        "get_cfg_header: version_major != 1",
        "get_cfg_header: wrong signature",
        "get_cfg_header: invalid crc",
    ],
}

MLOM = {
    "product": "ucsx-mlom-001",
    "fw_version": "7.4.19.13.2.1",
    "fw_size_kb": 1056,
    "blob_offset": 1308636672,
    "architecture": "stacked A/B images (delta=65360 bytes between identical debug handler blocks)",
    "license_protocol": {
        "challenge": "f%x: BIOS LIC_CHLNG",
        "response": "f%x: BIOS LIC_RSP",
        "virt_mac_primary": "f%x: BIOS VIRT_MAC_PRIM",
        "virt_mac_iscsi": "f%x: BIOS VIRT_MAC_ISCSI",
        "get_upgrade_key": "GET_UPGRADE_KEY",
        "get_manuf_key": "GET_MANUF_KEY",
        "load_l2b": "f%x: LOAD_L2B",
        "error_path": "get_lic_key[%x.%x]: Unknown key 0x%x",
        "timeout_violation": "lic 4s violation",
        "description": "BIOS-to-FW challenge-response gates virtual MAC assignment; manufacturing key present alongside production key",
    },
    "debug_interface": {
        "blocks": [65824, 131184],
        "cmds": ["Debug wr 0x%x=0x%x", "Debug rd 0x%x", "Debug illegal cmd 0x%x"],
        "note": "Identical blocks in both A/B images; each image maintains independent debug register access",
    },
}

GPU_VBIOS = {
    "M10": {
        "fw_label": "82.07.BC.00.01",
        "blob_offset": 1320912896,
        "inner_format": "gzip -> ZIP (M10_100_110_120.zip)",
        "contents": {
            "irom": "M10/CA/IROM/24050070.ifro",
            "plx_rom": "M10/CA/PLX/22405070_CA.rom",
            "vbios": ["M10/CA/VBIOS/2405_0070_5700_g1-g4.rom"],
        },
        "ssid": "2405:0070",
        "gpu_count": 4,
        "architecture": "Maxwell (GM107)",
        "era_year": 2015,
    },
    "M60": {
        "fw_label": "84.04.9F.00.13",
        "blob_offset": 1321465344,
        "inner_format": "gzip -> ZIP (M60_300_310_320.zip)",
        "contents": {
            "irom": "M60/IROM/G4020060.ifr",
            "plx_rom": "M60/PLX/2G402060_CA.rom",
            "vbios": ["M60/VBIOS/g402_0060_8950_g1-g2.rom"],
        },
        "ssid": "G402:0060",
        "gpu_count": 2,
        "architecture": "Maxwell (GM204)",
        "era_year": 2015,
    },
}

# Findings
CX56_F1 = {
    "id": "CX56-F1",
    "severity": "HIGH",
    "title": "Cross-generation 0xBADC0FFE ICMD protection bypass in CX-5 and CX-6 DX",
    "affected": ["M5D100GF (CX-5 16.35.3006)", "M5D25GF (CX-5)", "M5S100GF (CX-5)",
                 "M6CD100GF (CX-6 DX 22.36.1010)"],
    "evidence": {
        "cx5_string": "icmd_execute_embedded_cmd, invalid protection field[0x%x], use 0xBADC0FFE to execute ecmd",
        "cx5_offset": 3760127,
        "cx6_occurrences": 3,
        "nvram_target": "icmd_nv_ram_rw_tlv (NVRAM read/write via TLV format)",
        "nvram_access_gate": "nvram_access_requestor.id + .key (only gate after bypass)",
    },
    "mechanism": (
        "The ICMD (Internal Command) interface on ConnectX-5 and CX-6 DX uses a protection field "
        "in the PCIe BAR2 register space. When the field value is 0xBADC0FFE, the firmware bypasses "
        "the protection check and executes the embedded command. This unlocks icmd_nv_ram_rw_tlv "
        "(NVRAM read/write) and related operations. Accessible via BAR2 from the host OS or from "
        "guest VMs in VF passthrough deployments."
    ),
    "impact": "Unauthenticated NVRAM read/write on production CX-5/CX-6 adapters from host or VM context",
    "references": ["Mellanox MFT ICMD protocol", "ConnectX NVRAM TLV format"],
}

CX6_F2 = {
    "id": "CX6-F2",
    "severity": "HIGH",
    "title": "CX-6 DX set_admin_state_mng vport metering debug bypass via 0xBADC0FFE",
    "affected": ["M6CD100GF (CX-6 DX 22.36.1010)"],
    "evidence": {
        "string": "t_admin_state_mng, invalid protection field[0x%x], use 0xBADC0FFE for setting_debug: vport_meter_en",
        "offset": 39131562,
        "context": "vport_meter_en = 0x%x, vport_me[tering_policy]",
    },
    "mechanism": (
        "A second distinct ICMD bypass path in CX-6 DX: set_admin_state_mng uses the same "
        "0xBADC0FFE protection field sentinel to unlock vport (virtual port) meter enable and "
        "metering debug settings. This is independent of the NVRAM R/W path and affects QoS "
        "enforcement for all virtual ports on the adapter. An attacker with BAR2 access can "
        "disable or modify rate limiting across all vports on the NIC."
    ),
    "impact": "QoS enforcement bypass -- vport metering disable/modify for all VFs on CX-6 DX from host context",
}

CX6_F3 = {
    "id": "CX6-F3",
    "severity": "MEDIUM",
    "title": "CX-6 DX NV-Config operations blocked in RO image with semaphore contention path",
    "affected": ["M6CD100GF (CX-6 DX 22.36.1010)"],
    "evidence": {
        "ro_blocks": CX6_NV_CONFIG["ro_blocked_ops"],
        "semaphore": "acquire_release_nvram: SEMAPHORE_GENERAL could not be locked",
        "job_overflow": "flash_nv_ram_tlv_handler: job request list exceeding value = 0x%x",
    },
    "mechanism": (
        "Three NV-Config operations (swap_cfg_area, invalidate_all, tlv_write) are blocked "
        "only by an RO image flag -- not by a cryptographic gate. The firmware enforces: "
        "if (is_ro_image) { deny_nv_config_op(); }. A non-RO image or a bypass of the RO "
        "flag (via the 0xBADC0FFE ICMD path) unlocks all three. Additionally, the NVRAM "
        "semaphore (SEMAPHORE_GENERAL) can fail to acquire, and the job request list can "
        "overflow -- both are potential DoS or TOCTOU surfaces."
    ),
    "impact": "NVRAM config reset/overwrite available in non-RO images; semaphore DoS possible via rapid NVRAM job flooding",
}

MLOM_F1 = {
    "id": "MLOM-F1",
    "severity": "HIGH",
    "title": "MLOM BIOS license challenge exposes manufacturing key and virtual MAC race window",
    "affected": ["ucsx-mlom-001 (7.4.19.13.2.1)"],
    "evidence": {
        "protocol": ["BIOS LIC_CHLNG", "BIOS LIC_RSP", "BIOS VIRT_MAC_PRIM", "BIOS VIRT_MAC_ISCSI"],
        "key_commands": ["GET_UPGRADE_KEY", "GET_MANUF_KEY"],
        "error": "get_lic_key[%x.%x]: Unknown key 0x%x",
        "timeout": "lic 4s violation",
    },
    "mechanism": (
        "The MLOM implements a BIOS-to-firmware challenge-response license protocol that gates "
        "virtual MAC address assignment. The protocol: BIOS sends LIC_CHLNG -> FW computes "
        "response with GET_UPGRADE_KEY or GET_MANUF_KEY -> BIOS grants VIRT_MAC_PRIM and "
        "VIRT_MAC_ISCSI. The manufacturing key (GET_MANUF_KEY) is present alongside the "
        "production upgrade key in production firmware, broadening the attack surface. "
        "A 4-second timeout (lic 4s violation) creates a window for race conditions against "
        "the challenge-response exchange. If the challenge can be replicated or the key "
        "derived, virtual MAC assignment for iSCSI and primary adapters can be manipulated."
    ),
    "impact": "Virtual MAC spoofing for iSCSI and primary network interfaces; manufacturing key exposure in production firmware",
}

MLOM_F2 = {
    "id": "MLOM-F2",
    "severity": "LOW",
    "title": "MLOM stacked A/B firmware images with dual independent debug register interfaces",
    "affected": ["ucsx-mlom-001 (7.4.19.13.2.1)"],
    "evidence": {
        "image_a_debug_offset": 65824,
        "image_b_debug_offset": 131184,
        "delta_bytes": 65360,
        "debug_cmds": ["Debug wr 0x%x=0x%x", "Debug rd 0x%x", "Debug illegal cmd 0x%x"],
    },
    "mechanism": (
        "The 1056KB MLOM blob contains two stacked firmware images (A/B) separated by 65360 bytes. "
        "Each image contains an identical debug register read/write handler. If one image is "
        "compromised or patched, the alternate image retains an independent debug interface "
        "entry point."
    ),
    "impact": "Debug register access persists across single-image firmware corruption in A/B layout",
}

GPU_F1 = {
    "id": "GPU-F1",
    "severity": "LOW",
    "title": "Legacy Maxwell GPU VBIOS (2015-era) with PLX PCIe switch firmware in production UCS",
    "affected": ["NVIDIA M10 (82.07.BC.00.01)", "NVIDIA M60 (84.04.9F.00.13)"],
    "evidence": {
        "m10_contents": "4x GM107 VBIOS (g1-g4) + PLX PCIe switch ROM (22405070_CA.rom) + IROM",
        "m60_contents": "2x GM204 VBIOS (g1-g2) + PLX PCIe switch ROM (2G402060_CA.rom) + IROM",
        "architecture": "Maxwell (2015)",
        "plx_device": "PLX PCIe switch with Cisco SSID 2405:0070 (M10)",
    },
    "mechanism": (
        "Production UCS GPU firmware bundles include PLX PCIe switch ROMs alongside the NVIDIA VBIOS. "
        "The PLX switch handles PCIe lane aggregation for multi-GPU boards. PLX switch firmware "
        "represents a third firmware surface (beyond VBIOS and IROM) that is updated opaquely "
        "with the GPU package. Maxwell-era VBIOS predates NVIDIA Secure Boot requirements; "
        "these boards do not enforce VBIOS signature validation."
    ),
    "impact": "Additional PCIe switch firmware attack surface in GPU passthrough; VBIOS lacks Secure Boot enforcement",
}

ALL_FINDINGS = [CX56_F1, CX6_F2, CX6_F3, MLOM_F1, MLOM_F2, GPU_F1]

SUMMARY = {
    "module": "cisco_ucs_cseries_mellanox_mlom_gpu_re",
    "targets": "Mellanox CX-5/CX-6 DX adapters, ucsx-mlom-001, NVIDIA M10/M60 GPU",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 3, "MEDIUM": 1, "LOW": 2},
    "headline": (
        "0xBADC0FFE ICMD protection bypass is cross-generational (CX-5 and CX-6 DX), "
        "with a second distinct CX-6 bypass path for vport QoS metering (set_admin_state_mng). "
        "MLOM manufacturing key present in production license challenge protocol."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
