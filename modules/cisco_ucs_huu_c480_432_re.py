"""
Cisco UCS Host Upgrade Utility 4.3.2 — C480 M5 — RE Module
Source: huu432-c480-base/  — HUU 4.3.2 for UCS C480 M5
        huu432-c480-rootfs-mnt/ — HUU 4.3.2 chroot rootfs

HUU 4.3.2 for C480 M5 (high-density 4-socket server) — earlier release of the
same HUU toolchain. Confirms builder:builder credential existed in the 4.3.x
line before the C220/C245 variants in 4.3.6. No cis@123co artifact here.
"""

FIRMWARE = {
    "targets": [
        {
            "name": "Cisco UCS Host Upgrade Utility 4.3.2 — C480 M5",
            "file": "huu432-c480-base",
            "version": "4.3.2",
            "platform": "UCS C480 M5 (4-socket high-density)",
        },
    ],
    "key_files": {
        "etc/shadow":                      "builder:.gLibiNXn0P12 — same hash as HUU 4.3.6",
        "etc/init.sh":                     "CONFIG_SEC_UTILS_SIGN_MODE dev gate (no cis@123co)",
        "rootfs/etc/init.d/hsu-init":      "telnetd dev gate + imgverify call without IMG_VERIFY=1",
        "rootfs/usr/sbin/imgverify":       "IMG_VERIFY bypass (same script as 4.3.6 and 6.0.2)",
        "hsu-keys/tools-verify-key.der":   "Aliased copy of tools-rel-verify-key.der (not novel)",
    },
    "fix_version": "HUU 6.0.2",
    "findings": ["HUU432-F1", "HUU432-F2", "HUU432-F3"],
}

# ─────────────────────────────────────────────────────────
# HUU432-F1: builder:builder hardcoded credential in HUU 4.3.2 C480
#             Identical hash to HUU 4.3.6 variants — credential spans entire 4.3.x line
# ─────────────────────────────────────────────────────────
HUU432_F1 = {
    "id":       "HUU432-F1",
    "title":    "HUU 4.3.2 C480 ships builder:builder DES crypt credential "
                "(identical hash to HUU 4.3.6) — builder:builder spans entire HUU 4.3.x line",
    "status":   "CONFIRMED — huu432-c480-base/etc/shadow; absent in huu602-c220-base/etc/shadow",
    "severity": "CRITICAL",

    "shadow_entry":   "builder:.gLibiNXn0P12:20423::",
    "hash_type":      "DES crypt (13 chars, 2-char salt '.g')",
    "cracked_pass":   "builder",
    "uid_gid":        "998:998",
    "home_shell":     "/home/builder — /bin/sh",

    "scope_across_versions": {
        "HUU 4.3.2 (C480)":    ".gLibiNXn0P12 — PRESENT (this module)",
        "HUU 4.3.6 (C220)":    ".gLibiNXn0P12 — PRESENT (HUU436-F1)",
        "HUU 4.3.6 (C220-039)": ".gLibiNXn0P12 — PRESENT (HUU436-F1)",
        "HUU 4.3.6 (C245)":    ".gLibiNXn0P12 — PRESENT (HUU436-F1)",
        "HUU 6.0.2 (C220 M8)": "builder ABSENT — FIXED",
        "HUU 6.0.2 (C245-044)": "builder ABSENT — FIXED",
        "HUU 6.0.2 (C245-180)": "builder ABSENT — FIXED",
    },

    "note_uid_difference": (
        "HUU 4.3.2 assigns builder uid 998 vs uid 999 in 4.3.6 — different Debian base "
        "image version (gnats user uid 41 present in 4.3.2 but absent in 4.3.6, "
        "shifting subsequent uid allocations). The password and shell are identical."
    ),

    "cis123co_absent": (
        "The commented-out 'usermod --password $(openssl passwd cis@123co) root' line "
        "present in HUU 4.3.6 init.sh is absent from HUU 4.3.2 C480 init.sh. "
        "That artifact is specific to the 4.3.6 variants."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU432-F2: CONFIG_SEC_UTILS_SIGN_MODE == "dev" enables telnetd (hsu-init)
#             and adds getty TTYs to inittab (init.sh) — same gate as HUU436-F3
# ─────────────────────────────────────────────────────────
HUU432_F2 = {
    "id":       "HUU432-F2",
    "title":    "HUU 4.3.2 C480 hsu-init and init.sh activate telnetd and tty5-7 gettys "
                "on CONFIG_SEC_UTILS_SIGN_MODE=dev — present in 4.3.2, 4.3.6, and 6.0.2",
    "status":   "CONFIRMED — hsu-init:18-20 and init.sh:88-95 in huu432-c480",
    "severity": "MEDIUM",

    "trigger_variable": "CONFIG_SEC_UTILS_SIGN_MODE",
    "trigger_value":    "dev",

    "hsu_init_block": (
        "hsu-init:18 — if [ $CONFIG_SEC_UTILS_SIGN_MODE == 'dev' ]; then\n"
        "hsu-init:19 —     echo 'Enabling telnetd...' ; telnetd\n"
        "hsu-init:20 — fi"
    ),
    "init_sh_block": (
        "init.sh:88 — if [ $CONFIG_SEC_UTILS_SIGN_MODE == 'dev' ]; then\n"
        "    inittab append: tty5/tty6/tty7 respawn gettys"
    ),

    "cross_version": {
        "HUU 4.3.2 C480":   "PRESENT — hsu-init:18, init.sh:88",
        "HUU 4.3.6 C220":   "PRESENT — hsu-init:18, init.sh:94 (HUU436-F3)",
        "HUU 6.0.2 C220M8": "PRESENT — hsu-init:28 (HUU-F3); ADDITIONALLY: telnetd if !is_cisco_server",
        "HUU 6.0.2 C245":   "PRESENT — hsu-init:28; ADDITIONALLY: telnetd if !is_cisco_server",
    },

    "persistence_note": (
        "CONFIG_SEC_UTILS_SIGN_MODE telnetd gate is never removed across any examined HUU "
        "version. HUU 6.0.2 adds a second unconditional telnetd path (!is_cisco_server), "
        "but retains the CONFIG_SEC gate alongside it."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU432-F3: imgverify exits 0 when IMG_VERIFY != "1" in HUU 4.3.2 C480
#             Extends scope of HUU-F7 and HUU436-F4 back to HUU 4.3.2
# ─────────────────────────────────────────────────────────
HUU432_F3 = {
    "id":       "HUU432-F3",
    "title":    "imgverify IMG_VERIFY bypass present in HUU 4.3.2 C480 — bypass exists "
                "in all examined HUU versions (4.3.2, 4.3.6, 6.0.2), never patched",
    "status":   "CONFIRMED — rootfs/usr/sbin/imgverify and hsu-init:75 in huu432-c480",
    "severity": "HIGH",

    "bypass_line":    'if [ "$IMG_VERIFY" != "1" ]; then exit 0; fi',
    "call_site":      "hsu-init:75 — imgverify /tmp/ucs-*-container-*-base.tar.gz",
    "img_verify_set": False,

    "cross_version": {
        "HUU 4.3.2 C480":   "PRESENT",
        "HUU 4.3.6 C220":   "PRESENT (HUU436-F4)",
        "HUU 6.0.2 C220M8": "PRESENT (HUU-F7)",
        "HUU 6.0.2 C245":   "PRESENT — huu602-c245-044-rootfs-mnt/usr/sbin/imgverify confirmed",
    },

    "description": (
        "The imgverify bypass (exit 0 when IMG_VERIFY != '1') is present in every HUU "
        "version examined from 4.3.2 through 6.0.2. The bypass is never patched. "
        "This means container tarball signature verification has been effectively "
        "disabled across the entire HUU lifecycle examined."
    ),
}

CROSS_REFERENCE = {
    "huu436_builder": "HUU436-F1 — builder:builder in HUU 4.3.6 (C220, C220-039, C245)",
    "huu602_telnetd": "HUU-F3 — conditional telnetd in HUU 6.0.2 C220 M8",
    "huu602_imgverify": "HUU-F7 — imgverify bypass in HUU 6.0.2 C220 M8",
}

FINDINGS = [HUU432_F1, HUU432_F2, HUU432_F3]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:12s}] {f['id']}: {f['title'][:80]}")
