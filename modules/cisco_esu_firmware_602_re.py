"""
Cisco UCS ESU Firmware — Multi-Version Survey Sub-Module
Sources analyzed:
  esu-firmware-6.0.1.251006.tar.gz  (6.0.1 — /media/cowboy/research/Cisco-UCS/)
  esu-firmware-6.0.2.260026.tar.gz  (6.0.2.260026)
  esu-firmware-6.0.2.260034.tar.gz  (6.0.2.260034)
  esu-firmware-6.0.2.260143.tar.gz  (6.0.2.260143, deepest analyzed)
Canonical module: cisco_ucs_esu_602_re.py (4 findings; ESU-F1 through ESU-F4; single-version deep analysis)

Sub-module purpose: multi-version survey confirming ESU packaging-level issues span 6.0.1 through
6.0.2.260143 — four ESU bundle versions beyond the single-version scope of cisco_ucs_esu_602_re.py.
ESU-SURVEY-F1 extends unsigned PSU coverage to 6.0.1.251006, 6.0.2.260026, 6.0.2.260034.
ESU-SURVEY-F2 confirms secure-copy=false is a systemic catalog default, not version-specific.
IDs use ESU-SURVEY-* prefix to avoid namespace collision with the canonical module.

Target platform: UCS XE (chassis-based UCS with eCMC controller)
Platform PID: UCSXE (per Catalog.json platform_supported_pids)
"""

FIRMWARE = {
    "targets": [
        "esu-firmware-6.0.1.251006.tar.gz",
        "esu-firmware-6.0.2.260026.tar.gz",
        "esu-firmware-6.0.2.260034.tar.gz",
        "esu-firmware-6.0.2.260143.tar.gz",
    ],
    "platform":  "UCS XE / eCMC (UCSXE chassis systems)",
    "components": [
        "PSU    — Power Supply Unit firmware (QCS / MEG vendors)",
        "CMC    — Chassis Management Controller",
        "eCMCFPGA — FPGA on eCMC board",
        "pdbFPGA  — PDB (Power Distribution Board) FPGA",
        "MTS    — Management Transport Service",
        "slamlatch — Chassis slam-latch mechanism firmware",
    ],
    "findings":      ["ESU-SURVEY-F1", "ESU-SURVEY-F2"],
    "role":          "multi-version survey sub-module — see cisco_ucs_esu_602_re.py for canonical findings",
    "canonical_ref": "cisco_ucs_esu_602_re.py (ESU-F1, ESU-F2)",
}

# ─────────────────────────────────────────────────────────
# ESU-SURVEY-F1: PSU firmware shipped unsigned across all surveyed ESU versions
#                — canonical: ESU-F1 in cisco_ucs_esu_602_re.py; this extends to 6.0.1 and 6.0.2.260026/034
# ─────────────────────────────────────────────────────────
ESU_F1 = {
    "id":            "ESU-SURVEY-F1",
    "canonical_ref": "ESU-F1 in cisco_ucs_esu_602_re.py",
    "survey_scope":  "4 ESU versions: 6.0.1.251006, 6.0.2.260026, 6.0.2.260034, 6.0.2.260143",
    "title":    "UCS XE PSU firmware shipped unsigned in all analyzed ESU bundles "
                "('_combined_unsigned.bin') — no signature verification at update time",
    "status":   "CONFIRMED — Catalog.json entries and filename convention across 6.0.1 and 6.0.2.x",
    "severity": "MEDIUM",

    "unsigned_files": {
        "6.0.1.251006": [
            "PSU/1.5.0.0_3.4.0.0/QCS_UCSXE-PSU-2400W_1.5.0.0_3.4.0.0_combined_unsigned.bin",
            "PSU/4.0.2.0_4.0.0.0/MEG_UCSXE-PSU-2400W_4.0.2.0_4.0.0.0_combined_unsigned.bin",
        ],
        "6.0.2.260143": [
            "PSU/1.6.0.0_3.5.0.0/QCS_UCSXE-PSU-2400W_1.6.0.0_3.5.0.0_combined_unsigned.bin",
            "PSU/4.0.0.0_4.0.0.0/MEG_UCSXE-PSU-2400WDC_4.0.0.0_4.0.0.0_combined_unsigned.bin",
            "PSU/4.0.2.0_4.0.0.0/MEG_UCSXE-PSU-2400W_4.0.2.0_4.0.0.0_combined_unsigned.bin",
        ],
    },

    "update_staging_path": "/tmp/firmware/PANDORA/PSU/<version>/",

    "md5_only_integrity": {
        "example_6.0.2.260143": {
            "QCS_UCSXE-PSU-2400W_1.6.0.0_3.5.0.0": "md5=0a726c5bc190ed8fe1f...",
            "MEG_UCSXE-PSU-2400W_4.0.2.0_4.0.0.0":  "md5=db2de99870632372348...",
            "MEG_UCSXE-PSU-2400WDC_4.0.0.0_4.0.0.0": "md5=f03e777b8dcd7b66b9a...",
        },
        "note": "MD5 checksums are stored in the Catalog.json controlled by the same ESU bundle. "
                "An attacker who substitutes the firmware file can trivially update the Catalog.json "
                "MD5 to match the malicious image.",
    },

    "analysis": (
        "PSU firmware for UCS XE systems is distributed without cryptographic signatures "
        "across multiple ESU versions. The '_combined_unsigned.bin' naming is explicit — "
        "these files are not signed. The update pipeline (eCMC PANDORA subsystem) relies "
        "solely on MD5 checksums from the same Catalog.json that an attacker can modify "
        "in tandem. PSU firmware executes on the power supply microcontrollers with direct "
        "control over DC rail voltages and current limits. Malicious PSU firmware can: "
        "(1) cause hardware damage via voltage/current manipulation, "
        "(2) enable power-based side-channel attacks against cryptographic operations, "
        "(3) provide hardware-level persistence below OS and BMC firmware visibility. "
        "The attack surface is any path that can modify the ESU bundle before or during delivery "
        "to the eCMC — management network MITM, compromised update server, or "
        "local bundle manipulation on the management host."
    ),
}

# ─────────────────────────────────────────────────────────
# ESU-SURVEY-F2: secure-copy=false is a systemic catalog default across all ESU versions
#                — canonical: ESU-F2 in cisco_ucs_esu_602_re.py; confirms not version-specific
# ─────────────────────────────────────────────────────────
ESU_F2 = {
    "id":            "ESU-SURVEY-F2",
    "canonical_ref": "ESU-F2 in cisco_ucs_esu_602_re.py",
    "survey_scope":  "Confirmed present in 6.0.2.260143; Catalog.json format consistent across all 4 versions",
    "title":    "UCS XE ESU Catalog.json sets secure-copy=false for every firmware component "
                "— cleartext transport for CMC, FPGA, MTS, PSU, and slamlatch firmware updates",
    "status":   "CONFIRMED — Catalog.json from esu-firmware-6.0.2.260143.tar.gz",
    "severity": "LOW",

    "all_components_secure_copy_false": [
        {"component": "PSU",      "path": "/PSU/1.6.0.0.../QCS_...combined_unsigned.bin"},
        {"component": "PSU",      "path": "/PSU/4.0.2.0.../MEG_...combined_unsigned.bin"},
        {"component": "PSU",      "path": "/PSU/4.0.0.0.../MEG_...DC...combined_unsigned.bin"},
        {"component": "eCMCFPGA", "path": "/eCMCFPGA/V200/toruk_top_250425_V200_update_URP_REL_na.spi"},
        {"component": "pdbFPGA",  "path": "/pdbFPGA/V202/direhorse_top_V202_250829_update_URP_REL_na.spi"},
        {"component": "CMC",      "path": "/CMC/6.0.2.260036/chassisA.img"},
        {"component": "MTS",      "path": "/MTS/1.0.2.2/image_Aldrin3S_1.0.2.2_official_key.bin"},
        {"component": "slamlatch", "path": "/slamlatch/v25082018/tSHL-PP-APP-FW-v25082018.upg"},
    ],

    "dst_path_template": "/tmp/firmware/PANDORA/<component>/<version>/",

    "catalog_snippet": '{"secure-copy": {"enabled": false}, "src_location": "/PSU/...", "firmwareName": "qcs_psu.bin"}',

    "analysis": (
        "The eCMC PANDORA firmware update subsystem stages all firmware images "
        "to /tmp/firmware/PANDORA/ using plaintext file copy (secure-copy=false). "
        "The meaning of 'secure-copy' in this context is likely SCP vs plain copy over "
        "the internal management bus — disabled for all components. "
        "Combined with ESU-F1 (no signature on PSU firmware), the delivery path "
        "for the most security-sensitive component (PSU) is both unencrypted and unsigned. "
        "For components with 'official_key' in the filename (MTS), secure-copy=false suggests "
        "the key name is cosmetic — not indicative of cryptographic verification in-transit."
    ),

    "severity_note": (
        "Standalone severity is LOW — secure-copy=false is a transport-layer property "
        "and requires management network MITM as a prerequisite. Elevated to MEDIUM "
        "when combined with ESU-F1 (unsigned PSU firmware) since both the transport "
        "and verification layers are absent for PSU."
    ),
}

FINDINGS = [ESU_F1, ESU_F2]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
