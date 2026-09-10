"""
Cisco UCS ESU (Extensible Service Unit) CMC Firmware Delta — 6.0.1.251006 vs 6.0.2.260036 — RE Module
Sources:
  esu-firmware-6.0.1.251006.tar.gz (195MB)
  esu-firmware-6.0.2.260143.tar.gz (204MB, contains CMC/6.0.2.260036/)
Both from /media/cowboy/research/Cisco-UCS/
Bundle structure: Catalog.json + component dirs (MTS, eCMCFPGA, PSU, CMC, pdbFPGA, slamlatch)
CMC image: chassisA.img (142MB/150MB) → gzip@0x580 (ecmc_cloud_connector tar) + gzip@offset (mgmt_plugin.tgz)
mgmt_plugin.tgz: ecmcCli.bin + webserver.bin + ui.bin + packages.json
webserver.bin: gzip tar → ism_web (Go ELF, ARM aarch64, stripped) + web_config.ini + install.sh
"""

FIRMWARE = {
    "target":  "Cisco UCS ESU CMC (eCMC) Firmware",
    "versions": {
        "6.0.1": {"build": "251006", "cmc_img_size": "142MB",
                  "ecmcCli": "1.0.11-202510032252", "webserver": "1.0.11-202510032251",
                  "ui": "1.0.12-20251003181450214",
                  "cloud_connector": "1.0.11-20251015125427974"},
        "6.0.2": {"build": "260036", "cmc_img_size": "150MB",
                  "ecmcCli": "1.0.11-202603041902", "webserver": "1.0.11-202603041900",
                  "ui": "1.0.11-20260304181914016",   # minor downgrade 1.0.12 → 1.0.11
                  "cloud_connector": "1.0.11-20260202093858420"},
    },
    "new_in_602": ["slamlatch/v25082018/tSHL-PP-APP-FW-v25082018.upg",
                   "PSU/4.0.0.0_4.0.0.0/MEG_UCSXE-PSU-2400WDC_4.0.0.0_4.0.0.0_combined_unsigned.bin"],
    "unchanged_602": ["eCMCFPGA/V200 (toruk FPGA)", "pdbFPGA/V202 (direhorse FPGA)"],
    "updated_602": ["MTS 1.0.1.3 → 1.0.2.2", "PSU QCS 1.5.0.0 → 1.6.0.0", "CMC 6.0.1.251006 → 6.0.2.260036"],
    "os": "Linux ARM aarch64 (eCMC embedded controller)",
    "findings": ["ESU-CMC-F1"],
}

# ─────────────────────────────────────────────────────────
# ESU-CMC-F1: CompareVersion() dot-stripping bug in 6.0.1 install-connector.sh
#             — version comparison collapses "1.10.0" and "2.0.0" to integers 1100 vs 200,
#               blocking legitimate major-version upgrades
# ─────────────────────────────────────────────────────────
ESU_CMC_F1 = {
    "id":       "ESU-CMC-F1",
    "title":    "eCMC install-connector.sh 6.0.1 CompareVersion() strips dots before integer comparison — "
                "cross-boundary version ordering inverted when major >= 2, blocking upgrades from 1.10.x",
    "status":   "CONFIRMED — install-connector.sh in ecmc_cloud_connector.1.0.11-20251015125427974.tar "
                "embedded at offset 0x580 in CMC/6.0.1.251006/chassisA.img. Fixed in 6.0.2.",
    "severity": "LOW",

    "vulnerable_code_601": (
        "# install-connector.sh (6.0.1) CompareVersion():\n"
        "local VER1_MAIN=\"${VER1_PARTS[0]//./}\"    # strip dots: '1.0.11' → '1011'\n"
        "local VER2_MAIN=\"${VER2_PARTS[0]//./}\"    # strip dots: '2.0.0'  → '200'\n"
        "if [[ \"$VER1_MAIN\" -gt \"$VER2_MAIN\" ]]; then\n"
        "    return 1  # New version is greater\n"
        "elif [[ \"$VER1_MAIN\" -lt \"$VER2_MAIN\" ]]; then\n"
        "    return 2  # Old version is greater\n"
        "fi"
    ),

    "fixed_code_602": (
        "# install-connector.sh (6.0.2) — per-component numeric comparison:\n"
        "IFS='.' read -ra ver1_parts <<< \"$ver1_main\"\n"
        "IFS='.' read -ra ver2_parts <<< \"$ver2_main\"\n"
        "for ((i=0; i<max_parts; i++)); do\n"
        "    if [[ ${ver1_parts[i]:-0} -gt ${ver2_parts[i]:-0} ]]; then return 1; fi\n"
        "    if [[ ${ver1_parts[i]:-0} -lt ${ver2_parts[i]:-0} ]]; then return 2; fi\n"
        "done"
    ),

    "broken_comparisons": {
        "2.0.0 vs 1.10.0": "200 vs 1100 → 200 < 1100 → 2.0.0 treated as OLDER than 1.10.0",
        "2.0.0 vs 1.9.0":  "200 vs 190  → 200 > 190  → correct (only breaks at minor >= 10)",
        "1.11.0 vs 1.9.0": "1110 vs 190 → correct",
        "1.2.0 vs 1.10.0": "120 vs 1100 → 120 < 1100 → 1.2.0 treated as OLDER than 1.10.0 (correct numerically but wrong semantically)",
    },

    "impact": (
        "When the eCMC connector reaches version 2.0.0, the 6.0.1 version comparison would "
        "block any upgrade from a 1.10.x baseline — the script concludes 'Current version is newer. Skipping upgrade.' "
        "An attacker with the ability to stage a 1.10.x-formatted version string on the eCMC "
        "could prevent connector updates from applying, stranding the device at an older version. "
        "Exploiting this requires write access to the version file on the eCMC filesystem, "
        "which requires prior compromise of the CMC. Low severity, fixed in 6.0.2."
    ),

    "note": (
        "The UCSM FI install-connector.sh (see UCSM-F5) has a DIFFERENT version bypass: "
        "explicit '0.1.0' prefix check that unconditionally returns 1 (newer). "
        "The CMC install-connector.sh does NOT have the 0.1.0 bypass — the 6.0.1 bug here is "
        "a separate, lower-severity dot-stripping arithmetic error affecting major version boundaries."
    ),
}

DELTA_SECURITY_OBSERVATIONS = {
    "rollback_not_implemented": (
        "Both 6.0.1 and 6.0.2 install.sh contain: "
        "rollback() { echo '...Unable to rollback installation. TBD!' >> $ISM_UPDATE_LOG; return 0; } "
        "A failed partial install leaves the eCMC management stack in an undefined state. "
        "No corrective action — affects recovery posture, not directly exploitable."
    ),
    "rsync_no_perms": (
        "install.sh uses 'rsync --no-perms' for all file copies to /cmc and /. "
        "This strips SUID/SGID bits and executable permissions from installed files. "
        "For the webserver install this is benign, but it makes any SUID binary in a "
        "malicious connector package lose its SUID bit on install — reduces attack surface."
    ),
    "relative_path_source": (
        "install.sh: source '../install-ism-consts.sh' (relative path). "
        "If an attacker controls the working directory at install time, a crafted "
        "install-ism-consts.sh in the parent directory executes with the install.sh's privileges."
    ),
}

FINDINGS = [ESU_CMC_F1]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
