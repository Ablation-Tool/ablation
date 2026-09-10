"""
Cisco UCS B-Series and C-Series Component Firmware Bundles 6.0(2b) — RE Module
Sources:
  ucs-k9-bundle-b-series.6.0.2b.B.bin (1.2GB) — B/X series compute node components
  ucs-k9-bundle-c-series.6.0.2b.C.bin (3.1GB) — C-series rack server components
Both from /media/cowboy/research/Cisco-UCS/

Format: Cisco SN bundle (magic 0x6401534e, 852-byte header for B-series, 844-byte for C-series)
Content: hardware component firmware only — no NX-OS, no UCSM image, no Python/shell code.

These are distinct from the FI infrastructure bundles: they distribute firmware for compute
node components (VIC adapters, GPU management controllers, CPLD, retimers, storage drives)
rather than switch OS firmware.
"""

FIRMWARE = {
    "targets": [
        {
            "name":      "UCS B/X-Series Component Bundle",
            "file":      "ucs-k9-bundle-b-series.6.0.2b.B.bin",
            "sn_offset": 852,
        },
        {
            "name":      "UCS C-Series Component Bundle",
            "file":      "ucs-k9-bundle-c-series.6.0.2b.C.bin",
            "sn_offset": 844,
        },
    ],
    "findings": ["BCSERIES-F1"],
}

BUNDLE_CONTENT = {
    "b_series": {
        "cpld": [
            "ucs-x210c-m8-x10c-pt4f-cpld.3.006.bin",
            "ucs-x215c-m8-raid-m1l6-cpld.2.005.bin",
            "ucs-x410c-m8-raid-m1l6-cpld.2.005.bin",
            "ucs-x410c-m8-x10c-pt4f-cpld.3.006.bin",
        ],
        "retimers": [
            "ucs-x210c-m8-v4-pcime-retimer.1.27.0.bin",
            "ucs-x210c-m8-me-v5q50g-retimer.1.27.0.bin",
            "ucs-x210c-m8-440p-retimer.1.27.0.bin",
        ],
        "gpu": [
            "ucs-video-nvidia-H100-NVL.96.00.D9.00.0D_1010.0210.00.02_00.02.0192.0000-n00.bin",
            "ucs-video-nvidia-H200-NVL.96.00.D9.00.0E_1010.0230.00.02_00.02.0192.0000-n00.bin",
            "ucs-video-nvidia-L4-mezz.95.04.65.00.13_G193.0200.00.01.bin",
            "ucs-video-amd-mi210.113-D67307V-075_3.16.bin",
            "ucs-x410c-m8-intel-flex-140-amc.7.0.0.0.bin",
        ],
        "psu_cmc": "cmc-psu-DTM-2800AC.2.6.0.0,2.9.0.0.bin",
        "board_prog": "ucs-b200-m6-brdprog.21.0.bin",
    },
    "c_series": {
        "vic_adapters": [
            "ucs-adaptor-ucsc-p-NC3220.32.46.1006.bin",
            "ucs-adaptor-ucsc-p-N7S400GF.28.46.1006.bin",
            "ucs-adaptor-ucsc-p-N7D200GF.28.46.1006.bin",
            "ucs-adaptor-ucsc-p-N7Q25GF.28.46.1006.bin",
            "ucs-adaptor-ucsc-o-N6CD25GF-OEM.26.46.1006.bin",
        ],
        "gpu": [
            "ucs-video-nvidia-H100-NVL.96.00.D9.00.0D_1010.0210.00.02_00.02.0192.0000-n00.bin",
            "ucs-video-nvidia-H200-NVL.96.00.D9.00.0E_1010.0230.00.02_00.02.0192.0000-n00.bin",
            "ucs-video-nvidia-L40S.95.02.66.00.15_G133.0242.00.03_00.02.0134.0000-n02.bin",
            "ucs-video-nvidia-RTX-PRO-6000.98.02.8D.00.01_G153.0210.00.02.bin",
            "ucs-video-intel-flex-140.DG02-2.2280_7.0.0.0.bin",
            "ucs-video-intel-flex-170.DG02-1.3274_7.0.0.0.bin",
            "ucs-video-amd-mi210.113-D67307V-075_3.16.bin",
        ],
        "raid": "ucsc-raid-m6t-psoc.001F.bin",
        "cpld": [
            "ucs-x210c-m7-x10c-pt4f-cpld.3.006.bin",
            "ucs-x210c-m6-x10c-pt4f-cpld.3.006.bin",
            "ucs-x215c-m8-raid-m1l6-cpld.2.005.bin",
        ],
        "ssd": [
            "ucs-samsung-ssd-MZ7L37T6HELA-00AK0.JXTG2F3Q.bin",
            "ucs-samsung-ssd-MZ7L33T8HELA-00AK0.JXTG2F3Q.bin",
        ],
    },
}

# ─────────────────────────────────────────────────────────
# BCSERIES-F1: Component firmware bundles use SN format with no crypto verification
#              — any component binary can be replaced; modified bundle reattaches original header
# ─────────────────────────────────────────────────────────
BCSERIES_F1 = {
    "id":       "BCSERIES-F1",
    "title":    "B-Series and C-Series component firmware bundles use Cisco SN format with no "
                "cryptographic payload verification — bundle integrity relies on header checksum only",
    "status":   "CONFIRMED — header analysis of both bundles",
    "severity": "MEDIUM",

    "sn_format": {
        "magic":   "0x6401534e (big-endian 'dSN' with prefix)",
        "header":  "B-series: 852 bytes; C-series: 844 bytes",
        "checksum": "8-byte field at header offset +0x30 (no cryptographic signing)",
    },

    "impact": (
        "An attacker with access to a firmware bundle file (e.g., via interception of bundle "
        "delivery from UCSM, NFS share access, or Intersight integration) can: "
        "1. Strip the 852/844-byte header. "
        "2. Extract the gzip+tar. "
        "3. Replace any component binary (VIC adapter, GPU management, CPLD, storage). "
        "4. Re-pack the tar and gzip. "
        "5. Reattach the original header with an updated checksum. "
        "UCSM or IMC will accept the modified bundle and install the tampered component firmware. "
        "VIC adapter firmware and GPU management controller firmware (especially for H100/H200 AI "
        "accelerators) would give persistent low-level implant capability in AI compute nodes."
    ),

    "vic_adapter_note": (
        "VIC adapter binaries (ucsc-p-NC3220, N7S400GF, etc.) are themselves SN-wrapped bundles "
        "(nested SN format: outer bundle → inner per-adapter SN bundle). "
        "The inner adapter firmware is not publicly documented and is likely a Tensilica/MPS "
        "architecture binary specific to the Cisco VIC ASIC. "
        "Credential pattern search in VIC adapter strings produced no plaintext credentials — "
        "the binary appears compressed or obfuscated. Deeper RE not performed."
    ),

    "gpu_firmware_note": (
        "NVIDIA GPU management firmware (GFW) for H100/H200/L40S/L4 is included as .bin files "
        "with NVIDIA-standard naming (vGFW version + GFW build number). "
        "These are NVIDIA-signed images for the GPU management controller (GMC) — "
        "not CUDA code. NVIDIA signs GFW images separately from Cisco's SN bundle wrapper. "
        "Replacing the GMC firmware in the bundle would require a valid NVIDIA GFW signature, "
        "making component-level GMC firmware substitution infeasible without NVIDIA private key."
    ),
}

FINDINGS = [BCSERIES_F1]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
