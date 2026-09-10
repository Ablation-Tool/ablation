"""
Cisco UCS X-Series ESU Firmware 6.0.2.260143 — Reverse Engineering Module
Source: esu-firmware-6.0.2.260143.tar.gz (/media/cowboy/research/Cisco-UCS/)
ESU package: CMC + PSU + FPGA + MTS + slamlatch components
CMC component: CMC/6.0.2.260036/chassisA.img (ARM64 Linux initramfs)
Cloud connector update: dc_update.sh (extracted from chassisA.img)
"""

FIRMWARE = {
    "target":      "Cisco UCS X-Series ESU Firmware Package",
    "version":     "6.0.2.260143",
    "source_pkg":  "esu-firmware-6.0.2.260143.tar.gz",
    "cmc_image":   "CMC/6.0.2.260036/chassisA.img",
    "cmc_image_offset": "initramfs at img offset 44056661 (219MB CPIO), kernel at offset 0",
    "arch":        "AArch64 (ARM64)",
    "findings":    ["ESU-F1", "ESU-F2", "ESU-F3", "ESU-F4"],
}

# ─────────────────────────────────────────────────────────
# ESU-F1 — psufwupdate -N flag creates /var/psufw_signature_validation_disable
#           disabling PSU firmware signature verification on demand
# ─────────────────────────────────────────────────────────
ESU_F1 = {
    "id":       "ESU-F1",
    "title":    "psufwupdate -N flag creates /var/psufw_signature_validation_disable — "
                "PSU firmware signature validation explicitly bypassable at runtime",
    "status":   "CONFIRMED — binary analysis of cmc/bin/psufwupdate in CMC 6.0.2.260036 rootfs",
    "severity": "HIGH",

    "binary":       "cmc/bin/psufwupdate (AArch64 ELF, dynamically linked)",
    "flag_string":  "[ -N, --not signed",
    "bypass_path":  "/var/psufw_signature_validation_disable",
    "bypass_action": "touch %s  — psufwupdate creates this file when -N is passed",

    "psu_firmware_strings": [
        "%s/psu%d/psu%d_combined_unsigned_firmware.bin",
        "Cannot obtain unsigned firmware file from signed file %s",
        "not_signed",
        "remove_psufw_signature",
        "valid_mfg_id",
    ],

    "unsigned_delivery": (
        "The ESU Catalog.json names PSU firmware files as "
        "'qcs_psu_combined_unsigned.bin', 'meg_psu_combined_unsigned_dc.bin', "
        "'meg_psu_combined_unsigned.bin' — all explicitly unsigned. "
        "psufwupdate supports a 'remove_psufw_signature' operation (for signed variants) "
        "but the primary ESU delivery path sends the unsigned variant directly. "
        "The -N flag bypasses any signature check that would otherwise occur on the unsigned path."
    ),

    "mechanism": (
        "1. Attacker or privileged CMC process calls: psufwupdate -N ... <firmware.bin>\n"
        "2. psufwupdate creates /var/psufw_signature_validation_disable via touch\n"
        "3. Subsequent PSU firmware update proceeds without signature verification\n"
        "4. Arbitrary PSU firmware loadable on all power supply units in the chassis\n"
        "PSU firmware runs on independent microcontrollers controlling power delivery. "
        "Malicious PSU firmware can execute outside the CMC's visibility."
    ),

    "impact": (
        "PSU firmware replacement with attacker-controlled code running outside CMC control plane. "
        "Combined with ESU-F2 (secure-copy: false), the unsigned firmware can be delivered "
        "over an unauthenticated channel without copy-time integrity checks. "
        "Requires code execution on CMC or physical access to management interface."
    ),
}

# ─────────────────────────────────────────────────────────
# ESU-F2 — All ESU Catalog.json components have secure-copy: false
# ─────────────────────────────────────────────────────────
ESU_F2 = {
    "id":       "ESU-F2",
    "title":    "ESU Catalog.json declares secure-copy: false for all components — "
                "no copy-time integrity on ESU firmware delivery",
    "status":   "CONFIRMED — esu-firmware-6.0.2.260143/Catalog.json",
    "severity": "MEDIUM",

    "catalog_file": "esu-firmware-6.0.2.260143/Catalog.json",

    "affected_components": {
        "pdbFPGA":   {"secure-copy": False, "file": "pdbFPGA/<version>/pdb_fpga_firmware.bin"},
        "CMC":       {"secure-copy": False, "file": "CMC/6.0.2.260036/chassisA.img"},
        "MTS":       {"secure-copy": False, "file": "MTS/<version>/mts_firmware.bin"},
        "slamlatch": {"secure-copy": False, "file": "slamlatch/<version>/slamlatch_firmware.bin"},
        "PSU_QCS":   {"secure-copy": False, "file": "PSU/<version>/qcs_psu_combined_unsigned.bin"},
        "PSU_MEG_AC": {"secure-copy": False, "file": "PSU/<version>/meg_psu_combined_unsigned.bin"},
        "PSU_MEG_DC": {"secure-copy": False, "file": "PSU/<version>/meg_psu_combined_unsigned_dc.bin"},
        "eCMCFPGA":  {"secure-copy": False, "file": "eCMCFPGA/<version>/ecmcfpga_firmware.bin"},
    },

    "analysis": (
        "secure-copy: false means the ESU update framework does not apply any "
        "transport-layer integrity protection during component delivery. "
        "The CMC's chassisA.img (which carries the full CMC root filesystem) "
        "is delivered to the chassis with the same absence of copy-time verification "
        "as the explicitly unsigned PSU files. "
        "Component integrity depends entirely on whatever signature validation occurs "
        "post-delivery — which for PSU firmware can be bypassed (ESU-F1)."
    ),

    "impact": (
        "An attacker with network access to the ESU delivery path (management network MITM) "
        "can substitute components during delivery. For PSU components, no post-delivery "
        "verification exists. For CMC, img-valid runs post-delivery, "
        "but secure-copy: false eliminates the defense-in-depth layer before that check."
    ),
}

# ─────────────────────────────────────────────────────────
# ESU-F3 — dc_update.sh strips 392-byte signature from cloud connector image
#           using `head -c -392`, then extracts to /cmc/dc/staging
# ─────────────────────────────────────────────────────────
ESU_F3 = {
    "id":       "ESU-F3",
    "title":    "dc_update.sh cloud connector update strips 392-byte appended signature "
                "and extracts to world-writable staging path /cmc/dc/staging",
    "status":   "CONFIRMED — cmc/bin/dc_update.sh extracted from CMC 6.0.2.260036 rootfs",
    "severity": "MEDIUM",

    "script_path":    "cmc/bin/dc_update.sh",
    "signature_size": 392,
    "validation_cmd": "/cmc/bin/img-valid -v -i $SOURCE_IMAGE",
    "extract_cmd":    "head -c -392 $SOURCE_IMAGE > $STAGING_DIR/image.tar.img; tar -xzf image.tar.img -C $STAGING_DIR",
    "staging_dir":    "/cmc/dc/staging",
    "persistent_dir": "/ws/dc/.persistent",
    "trigger_script": "/cmc/dc/staging/install-connector.sh",
    "upgrade_log":    "/obfl/ecmc_cloud_connector_upgrades",

    "signature_model": (
        "img-valid validates the full image (signature appended at end) before extraction. "
        "If validation passes, dc_update.sh strips the last 392 bytes and extracts the "
        "resulting tarball to /cmc/dc/staging, then executes install-connector.sh. "
        "img-valid is an AArch64 ELF that links libcisco_signature.so (RSA + intersight_keys). "
        "The signature covering mechanism is append-at-end rather than prepend-header."
    ),

    "staging_concern": (
        "/cmc/dc/staging is created on demand. install-connector.sh executes from staging "
        "with no further integrity check post-extraction. If img-valid can be bypassed "
        "(e.g., the signature validation logic has a flaw, or the binary is replaced), "
        "arbitrary code executes as the dc_update.sh caller (root). "
        "The cloud connector binary (ecmc_cloud_connector, AArch64, statically linked) "
        "is the agent that makes outbound connections to Intersight cloud management."
    ),

    "operations": {
        "install":          "initial install — runs install-connector.sh install",
        "upgrade":          "upgrade — removes source image after completion",
        "force-upgrade":    "bypasses version check",
        "overwrite-install": "replaces existing install",
    },
}

# ─────────────────────────────────────────────────────────
# ESU-F4 — ESU package version mismatch: tarball is 6.0.2.260143,
#           CMC component directory is 6.0.2.260036
# ─────────────────────────────────────────────────────────
ESU_F4 = {
    "id":       "ESU-F4",
    "title":    "ESU tarball version 6.0.2.260143 contains CMC component at 6.0.2.260036 — "
                "package version does not match constituent component versions",
    "status":   "CONFIRMED — directory listing of esu-firmware-6.0.2.260143.tar.gz",
    "severity": "LOW",

    "tarball_name":    "esu-firmware-6.0.2.260143.tar.gz",
    "cmc_dir_version": "CMC/6.0.2.260036/chassisA.img",

    "analysis": (
        "The ESU tarball is named 6.0.2.260143, implying all components are at this build number. "
        "The CMC component is at build 260036, a different build suffix from the ESU package. "
        "A deployment system verifying 'ESU package version 6.0.2.260143' may not check that "
        "the CMC subcomponent is actually at 6.0.2.260036 — a 107-build difference. "
        "If a supply-chain attacker substitutes the CMC component with an older or modified build "
        "at the same 260036 path, the outer package version check passes."
    ),

    "supply_chain_note": (
        "The esu_utils binary contains 'Package version %s and running version %s is same, "
        "hence skipping upgrade for component %s' — version comparison happens per component. "
        "If a downgrade attack substitutes CMC/6.0.2.260036/chassisA.img with a vulnerable image "
        "from an older 260036 build, esu_utils skips the update because the version strings match."
    ),
}

FINDINGS = [ESU_F1, ESU_F2, ESU_F3, ESU_F4]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
