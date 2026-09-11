"""
Cisco UCS Server Configuration Utility (SCU) 7.1.7 — RE Module
Source: ucs-scu-7.1.7.260100.iso (mounted /mnt)
        /mnt/rootfs.img — SCU boot rootfs (squashfs, mtime 2018-03-09)

SCU is the bootable ISO for C-Series BIOS/RAID/network configuration.
Its bootable rootfs design is SHARED with HUU: same hsu-init, same imgverify,
same telnetd gates. Confirms these vulnerabilities exist in the broader
Cisco boot infrastructure, not just HUU firmware upgrade tooling.

Key difference from HUU: NO builder account in SCU rootfs (builder:builder
credential is HUU-specific, introduced after this 2018 rootfs was built).
"""

FIRMWARE = {
    "targets": [
        {
            "name": "Cisco UCS Server Configuration Utility 7.1.7",
            "file": "ucs-scu-7.1.7.260100.iso",
            "version": "7.1.7.260100",
            "rootfs_mtime": "2018-03-09",
        },
    ],
    "key_files": {
        "rootfs.img":                  "Squashfs boot rootfs (2018-03-09, 147MB)",
        "rootfs/etc/init.d/hsu-init":  "SHARED design with HUU — same telnetd gates + imgverify call",
        "rootfs/usr/sbin/imgverify":   "IMG_VERIFY bypass — same script as HUU 4.3.2/4.3.6/6.0.2",
        "ucs-scu-container-*.squashfs":"SCU tools container (storcli, mvcli, driver packages — no credentials)",
    },
    "no_builder_account": True,
    "findings": ["SCU-F1", "SCU-F2"],
}

# ─────────────────────────────────────────────────────────
# SCU-F1: imgverify IMG_VERIFY bypass in SCU 7.1.7 rootfs
#          Same script, same bypass as HUU 4.3.2/4.3.6/6.0.2
#          Establishes bypass date of at least 2018-03-09
# ─────────────────────────────────────────────────────────
SCU_F1 = {
    "id":       "SCU-F1",
    "title":    "imgverify IMG_VERIFY bypass in SCU 7.1.7 rootfs (mtime 2018-03-09) — "
                "signature verification disabled by default; bypass predates HUU 4.3.x by years",
    "status":   "CONFIRMED — rootfs/usr/sbin/imgverify, hsu-init:90 in SCU 7.1.7 rootfs",
    "severity": "HIGH",

    "bypass_line":    'if [ "$IMG_VERIFY" != "1" ]; then exit 0; fi',
    "call_site":      "hsu-init:90 — imgverify /tmp/*-container-*-base.tar.gz",
    "img_verify_set": False,

    "scope_across_products_and_versions": {
        "SCU 7.1.7 (rootfs 2018)":  "PRESENT — oldest confirmed occurrence",
        "HUU 4.3.2 (C480)":         "PRESENT (HUU432-F3)",
        "HUU 4.3.6 (C220/C245)":    "PRESENT (HUU436-F4)",
        "HUU 6.0.2 (C220M8/C245)":  "PRESENT (HUU-F7)",
    },

    "description": (
        "The imgverify script's bypass check `if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi` "
        "is present in the SCU 7.1.7 rootfs.img with a file mtime of 2018-03-09. "
        "hsu-init calls imgverify on the base container tarball without setting IMG_VERIFY=1, "
        "so the signature check exits 0 (success) unconditionally. "
        "This confirms the bypass is a shared design flaw present in the common Cisco bootable "
        "tool infrastructure used by both HUU and SCU, with an earliest confirmed occurrence "
        "of at least March 2018 — over 7 years before the most recent HUU versions analyzed."
    ),
}

# ─────────────────────────────────────────────────────────
# SCU-F2: CONFIG_SEC_UTILS_SIGN_MODE + !is_cisco_server telnetd in SCU 7.1.7
#          Identical to HUU 6.0.2 — same shared hsu-init infrastructure
# ─────────────────────────────────────────────────────────
SCU_F2 = {
    "id":       "SCU-F2",
    "title":    "SCU 7.1.7 hsu-init activates telnetd on CONFIG_SEC_UTILS_SIGN_MODE=dev "
                "or IPMI !is_cisco_server — identical to HUU 6.0.2 shared boot rootfs",
    "status":   "CONFIRMED — hsu-init:28-35 in SCU 7.1.7 rootfs",
    "severity": "MEDIUM",

    "trigger_1_variable": "CONFIG_SEC_UTILS_SIGN_MODE",
    "trigger_1_value":    "dev",
    "trigger_2_condition": "!is_cisco_server (IPMI raw 0x36 0x4d 0x04 0x03 returns non-zero)",

    "hsu_init_blocks": (
        "28: if [ $CONFIG_SEC_UTILS_SIGN_MODE == 'dev' ]; then\n"
        "29:     echo 'Enabling telnetd...' ; telnetd\n"
        "30: fi\n"
        "33: if ! is_cisco_server; then\n"
        "34:     echo 'Enabling telnetd...' ; telnetd\n"
        "35: fi"
    ),

    "shadow_note": (
        "SCU 7.1.7 rootfs shadow has all accounts locked (root:*, messagebus:!, sshd:!). "
        "Telnetd on BusyBox provides unauthenticated root shell when all shadow passwords "
        "are disabled — no credential required to reach the shell once telnetd binds. "
        "This is the same root shell condition documented in HUU-F3."
    ),

    "no_builder_note": (
        "Unlike HUU 4.3.x, there is no builder account in SCU rootfs. "
        "The telnetd paths provide root access without any credential."
    ),

    "cross_version": {
        "SCU 7.1.7 (rootfs 2018)":  "PRESENT — hsu-init:28,33",
        "HUU 6.0.2 C220M8":         "PRESENT — same lines (HUU-F3)",
        "HUU 6.0.2 C245":           "PRESENT — same lines (HUU-F3 scope)",
        "HUU 4.3.x":                "PARTIAL — CONFIG_SEC gate only; !is_cisco_server gate absent in 4.3.x",
    },
}

CROSS_REFERENCE = {
    "huu_imgverify": "HUU-F7 (6.0.2), HUU436-F4 (4.3.6), HUU432-F3 (4.3.2)",
    "huu_telnetd":   "HUU-F3 (6.0.2 C220M8) — identical hsu-init code",
    "shared_rootfs_note": (
        "The 2018-03-09 mtime on SCU 7.1.7 rootfs.img and the identical code structure "
        "with HUU 6.0.2 confirms both tools share a common boot rootfs codebase. "
        "Security findings in this rootfs are cross-product issues, not HUU-specific."
    ),
}

FINDINGS = [SCU_F1, SCU_F2]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:12s}] {f['id']}: {f['title'][:80]}")
