"""
Cisco UCS Host Upgrade Utility 4.3.6 — RE Module
Sources:
  huu436-c220-base/   — HUU 4.3.6 for UCS C220 M6/M7 (primary analysis)
  huu436-c220-039-base/ — HUU 4.3.6 for UCS C220 M6 (039 SKU)
  huu436-c245-base/   — HUU 4.3.6 for UCS C245 M6
  huu436-c220-rootfs/ — HUU 4.3.6 chroot rootfs (init.d, imgverify, hsu-init)
Comparison: huu602-c220-base/ (HUU 6.0.2 — fix-scope baseline)

HUU is a bootable ISO delivered via CIMC/iDRAC that upgrades C-Series server firmware.
At boot, the ISO mounts a squashfs container, rsync-copies a base tarball to RAM,
optionally verifies its signature via imgverify, then chroot-execs the container.
The builder account and telnetd dev-mode both exist in the bootable runtime.
"""

FIRMWARE = {
    "targets": [
        {
            "name": "Cisco UCS Host Upgrade Utility 4.3.6 — C220 M6/M7",
            "file": "huu436-c220-base",
            "version": "4.3.6",
            "platform": "UCS C220 M6 / M7",
        },
        {
            "name": "Cisco UCS Host Upgrade Utility 4.3.6 — C220 M6 (SKU 039)",
            "file": "huu436-c220-039-base",
            "version": "4.3.6",
            "platform": "UCS C220 M6 (039 SKU)",
        },
        {
            "name": "Cisco UCS Host Upgrade Utility 4.3.6 — C245 M6",
            "file": "huu436-c245-base",
            "version": "4.3.6",
            "platform": "UCS C245 M6",
        },
    ],
    "key_files": {
        "etc/shadow":                    "Account credential store — builder:DES crypt",
        "etc/init.sh":                   "Container init — cis@123co artifact, dev-mode TTYs",
        "rootfs/etc/init.d/hsu-init":    "Rootfs init — CONFIG_SEC_UTILS_SIGN_MODE telnetd gate",
        "rootfs/usr/sbin/imgverify":     "Image signature verification — IMG_VERIFY bypass",
    },
    "fix_version": "HUU 6.0.2",
    "findings": ["HUU436-F1", "HUU436-F2", "HUU436-F3", "HUU436-F4"],
}

# ─────────────────────────────────────────────────────────
# HUU436-F1: builder:builder hardcoded credential in all HUU 4.3.6 container variants
#             DES crypt hash .gLibiNXn0P12 — cracked: password = "builder"
# ─────────────────────────────────────────────────────────
HUU436_F1 = {
    "id":       "HUU436-F1",
    "title":    "HUU 4.3.6 ships a hardcoded builder:builder credential (DES crypt) "
                "in all three container variants — account absent in HUU 6.0.2",
    "status":   "CONFIRMED — cracked via Python crypt and john; absent in huu602-c220-base/etc/shadow",
    "severity": "CRITICAL",

    "affected_variants": [
        "huu436-c220-base/etc/shadow",
        "huu436-c220-039-base/etc/shadow",
        "huu436-c245-base/etc/shadow",
    ],
    "shadow_entry":   "builder:.gLibiNXn0P12:15069::",
    "hash_type":      "DES crypt (13 chars, 2-char salt '.g')",
    "cracked_pass":   "builder",
    "crack_method":   "python -c \"import crypt; print(crypt.crypt('builder', '.g'))\" → .gLibiNXn0P12",
    "uid_gid":        "999:999",
    "home_shell":     "/home/builder — /bin/sh",
    "fix_evidence":   "huu602-c220-base/etc/shadow does NOT contain builder entry",

    "description": (
        "All three HUU 4.3.6 container base tarballs contain /etc/shadow with an active "
        "builder account using a DES crypt hash. The password is trivially cracked: "
        "the hash '.gLibiNXn0P12' decodes to password 'builder' using the 2-char DES salt '.g'. "
        "The builder account is present at uid/gid 999 with /bin/sh as the login shell. "
        "HUU boots from a Cisco-signed ISO via CIMC/iDRAC and mounts the container in memory; "
        "during the upgrade window, the container OS is reachable and the builder account "
        "provides authenticated shell access. In HUU 6.0.2, the builder account has been "
        "removed: the 6.0.2 shadow file contains only system accounts plus sshd."
    ),

    "attack_conditions": (
        "Attacker can access the HUU runtime during an active firmware upgrade session "
        "(physical KVM, iDRAC SOL/virtual console, or network reachability if HUU NIC is "
        "up during upgrade). Credential is static across all C220 and C245 deployments. "
        "No brute-force required — password matches the username."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F2: cis@123co default root password artifact in container init.sh
#             Commented-out usermod line reveals historic/development default credential
# ─────────────────────────────────────────────────────────
HUU436_F2 = {
    "id":       "HUU436-F2",
    "title":    "HUU 4.3.6 container init.sh contains commented-out root password "
                "'cis@123co' via usermod — default root credential artifact in shipping firmware",
    "status":   "CONFIRMED — extracted from etc/init.sh line 94 in all three HUU 4.3.6 variants",
    "severity": "MEDIUM",

    "source_file": "etc/init.sh",
    "source_line": 94,
    "artifact": (
        "# chroot $ROOTFS_DIR sh -c "
        "\"usermod --password $(openssl passwd cis@123co) root\""
    ),
    "password_value": "cis@123co",
    "current_root_shadow": "root:* (disabled — the commented line is not executed)",

    "description": (
        "The container init script /etc/init.sh in all three HUU 4.3.6 variants contains "
        "a commented-out usermod invocation that would set the container root password to "
        "'cis@123co'. The line is not executed in shipping firmware — the root shadow entry "
        "is 'root:*' (locked). However, the plaintext credential is embedded in the source "
        "of the init script shipped in the production firmware image. "
        "The pattern 'cis@123co' (Cisco + '123' + 'co') suggests a development or QA default "
        "that was never removed from the script before it shipped. Anyone who extracts the HUU "
        "container reads it directly."
    ),

    "impact": (
        "Reveals a Cisco-internal default credential pattern. If this password is reused "
        "in any executed code path (CIMC defaults, BMC factory credential, other HUU variants), "
        "it becomes directly exploitable. For shipping firmware, this is an information "
        "disclosure of a development default credential."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F3: CONFIG_SEC_UTILS_SIGN_MODE == "dev" enables telnetd (hsu-init)
#             and adds getty TTYs to inittab (init.sh base) at container boot
# ─────────────────────────────────────────────────────────
HUU436_F3 = {
    "id":       "HUU436-F3",
    "title":    "HUU 4.3.6 init chain enables telnetd and adds tty5-7 gettys when "
                "CONFIG_SEC_UTILS_SIGN_MODE == 'dev' — unauthenticated remote shell "
                "if variable settable at boot",
    "status":   "CONFIRMED — two independent code paths verified; variable origin not found",
    "severity": "MEDIUM",

    "trigger_variable": "CONFIG_SEC_UTILS_SIGN_MODE",
    "trigger_value":    "dev",

    "code_paths": {
        "hsu-init (rootfs/etc/init.d/hsu-init:18)": (
            "if [ $CONFIG_SEC_UTILS_SIGN_MODE == 'dev' ]; then\n"
            "    echo 'Enabling telnetd...'\n"
            "    telnetd\n"
            "fi"
        ),
        "init.sh (etc/init.sh, setup_rootfs())": (
            "if [ $CONFIG_SEC_UTILS_SIGN_MODE == 'dev' ]; then\n"
            "    cp -f $ROOTFS_DIR/etc/inittab /tmp/\n"
            "    echo '5:12345:respawn:/sbin/getty 38400 tty5' >>/tmp/inittab\n"
            "    echo '6:12345:respawn:/sbin/getty 38400 tty6' >>/tmp/inittab\n"
            "    echo '7:12345:respawn:/sbin/getty 38400 tty7' >>/tmp/inittab\n"
            "    cp -f /tmp/inittab $ROOTFS_DIR/etc/inittab\n"
            "fi"
        ),
    },

    "variable_origin": (
        "CONFIG_SEC_UTILS_SIGN_MODE is read from the process environment in both code paths. "
        "It is referenced but never assigned in any file examined across huu436-c220-base, "
        "huu436-c220-rootfs, or huu436-c220-039-base. The variable is likely injected via "
        "kernel command line (parsed by the initramfs init and exported to the environment) "
        "or a build-time environment file not present in the extracted container. "
        "A kernel cmdline parameter 'CONFIG_SEC_UTILS_SIGN_MODE=dev' at GRUB/UEFI boot "
        "would activate both paths without modifying any on-disk file."
    ),

    "description": (
        "If CONFIG_SEC_UTILS_SIGN_MODE is set to 'dev' at HUU boot time, two independent "
        "code paths activate: (1) hsu-init starts telnetd in the HUU rootfs environment, "
        "providing unauthenticated remote login (telnet has no default auth in BusyBox), "
        "and (2) the container init.sh injects getty processes for tty5, tty6, and tty7 "
        "into the container's inittab. Combined with the builder:builder credential from "
        "HUU436-F1, dev mode provides a complete unauthenticated remote access path "
        "into the HUU upgrade environment."
    ),

    "severity_note": (
        "Rated MEDIUM because CONFIG_SEC_UTILS_SIGN_MODE trigger source is unconfirmed — "
        "requires either kernel cmdline manipulation (physical/UEFI access) or an "
        "undiscovered injection point in the boot chain. If the variable is injectable "
        "remotely via CIMC, severity escalates to CRITICAL."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F4: imgverify exits 0 when IMG_VERIFY != "1" in HUU 4.3.6
#             Confirms HUU-F7 (from 6.0.2 analysis) also present in 4.3.6
#             hsu-init calls imgverify without setting IMG_VERIFY=1
# ─────────────────────────────────────────────────────────
HUU436_F4 = {
    "id":       "HUU436-F4",
    "title":    "imgverify in HUU 4.3.6 rootfs exits 0 when IMG_VERIFY env var is not '1' "
                "— hsu-init invokes imgverify without setting IMG_VERIFY, bypassing "
                "container base-tarball signature verification",
    "status":   "CONFIRMED — extracted from rootfs/usr/sbin/imgverify and hsu-init:75",
    "severity": "HIGH",

    "source_file":    "rootfs/usr/sbin/imgverify",
    "bypass_trigger": 'if [ "$IMG_VERIFY" != "1" ]; then exit 0; fi',
    "call_site":      "hsu-init:75 — imgverify /tmp/ucs-*-container-*-base.tar.gz",
    "img_verify_set": False,

    "hsu_init_call_context": (
        "rsync -az --info=progress2 --info=name0 $TMP_MNTPATH/ucs-*-container-*-base.tar.gz /tmp/\n"
        "if ! imgverify /tmp/ucs-*-container-*-base.tar.gz >> /tmp/imgverify.log 2>&1; then\n"
        "    fatal 'Base container signature verification failed!'\n"
        "fi"
    ),

    "description": (
        "The imgverify script performs RSA signature verification of the base container "
        "tarball before it is extracted into the runtime mount point. The script's first "
        "action is to check whether the IMG_VERIFY environment variable equals '1'; "
        "if it does not, the script exits 0 (success) immediately without performing "
        "any cryptographic check. "
        "hsu-init copies the tarball from the squashfs container into /tmp via rsync, "
        "then calls imgverify — but never sets IMG_VERIFY=1 in the surrounding environment. "
        "The imgverify call therefore always returns exit 0, the 'fatal' error path is never "
        "reached, and the container tarball is extracted without signature verification "
        "regardless of what is in the tarball or whether it has been tampered with."
    ),

    "exploit_path": (
        "An attacker who can write to the squashfs container source (physical access to "
        "the ISO media, or compromise of the CIMC/iDRAC media mount path) can replace "
        "the base container tarball with an unsigned or modified version. imgverify will "
        "return success, and the modified container will be extracted and executed as the "
        "HUU environment."
    ),

    "cross_reference": {
        "huu602_finding": "HUU-F7 in cisco_ucs_huu_c220m8_602_re.py — same bypass, 6.0.2",
        "scope_note":     "Bypass not introduced in 6.0.2; present from at least 4.3.6 forward",
    },
}

FINDINGS = [HUU436_F1, HUU436_F2, HUU436_F3, HUU436_F4]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:12s}] {f['id']}: {f['title'][:80]}")
