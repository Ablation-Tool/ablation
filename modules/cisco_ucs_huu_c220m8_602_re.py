"""
Cisco UCS C220 M8 Host Upgrade Utility (HUU) 6.0.2.260143 — RE findings
Source: ucs-c220m8-huu-6.0.2.260143.iso
Structure:
  rootfs.img     — squashfs v4.0 xz (148MB, 5935 inodes, created 2018-03-09)
  ucs-c220m8-huu-container-6.0.2.260143.squashfs — squashfs v4.0 zlib (937MB, 643 inodes, 2026-06-17)
CIMC version: 6.0(2.260095)
BIOS: C220M8.6.0.2d.0.0527260454
HUU version: 6.0.2.260143
"""

FIRMWARE = {
    "target":      "Cisco UCS C220 M8 Host Upgrade Utility (HUU)",
    "version":     "6.0.2.260143",
    "source_pkg":  "ucs-c220m8-huu-6.0.2.260143.iso",
    "rootfs":      "rootfs.img — squashfs v4.0 xz, 148MB, 5935 inodes, 2018-03-09",
    "container":   "ucs-c220m8-huu-container-6.0.2.260143.squashfs — squashfs v4.0 zlib, 937MB, 643 inodes, 2026-06-17",
    "cimc_ver":    "6.0(2.260095)",
    "bios_ver":    "C220M8.6.0.2d.0.0527260454",
    "features":    {"NonInteractiveSupport": True, "RedfishSupport": True, "UISupport": True},
}

# ─────────────────────────────────────────────────────────
# HUU-F1 — Hardcoded AES-256-CBC firmware decryption key in decrypt-file binary
# ─────────────────────────────────────────────────────────
HUU_F1 = {
    "id":       "HUU-F1",
    "title":    "Hardcoded AES-256-CBC decryption key 'zfguijkophju@*%1]' in decrypt-file binary — all encrypted HUU firmware components decryptable",
    "status":   "CONFIRMED — strings /usr/sbin/decrypt-file in HUU 6.0.2.260143 rootfs",
    "severity": "CRITICAL",

    "binary":          "usr/sbin/decrypt-file (ELF x86-64, stripped)",
    "embedded_key":    "zfguijkophju@*%1]",
    "cipher":          "AES-256-CBC, SHA-256 digest, PBKDF2, no salt (-nosalt flag)",
    "openssl_commands": [
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in <src> -out <dst>.gz -k zfguijkophju@*%1] -nosalt",
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in <src> -out <dst> -k zfguijkophju@*%1] -nosalt",
    ],

    "note": "The decrypt-file utility is called by the ftd verification script before image signature check. "
            "All encrypted firmware component files distributed with the HUU can be decrypted with this key. "
            "The -nosalt flag removes salt-based key derivation protection — any file encrypted with this key "
            "produces the same ciphertext for the same plaintext.",
}

# ─────────────────────────────────────────────────────────
# HUU-F2 — Dev key accepted as fallback after release key verification fails
# ─────────────────────────────────────────────────────────
HUU_F2 = {
    "id":       "HUU-F2",
    "title":    "ftd verification script unconditionally falls back to dev key if release key verification fails — dev-signed firmware accepted by production HUU",
    "status":   "CONFIRMED — /usr/sbin/ftd script in HUU 6.0.2.260143 rootfs",
    "severity": "CRITICAL",

    "binary":   "usr/sbin/ftd (shell script wrapped as ELF)",
    "verification_flow": [
        "1. decrypt-file <src> <tmp>",
        "2. Try rel key: imgverify <tmp>_tmp with /hsu-keys/tools-rel-verify-key.pem",
        "3. IF rel key fails: imgverify <tmp> with /hsu-keys/tools-dev-verify-key.pem",
        "4. IF both fail: verification fails",
    ],

    "script_excerpt": [
        "imgverify ${tmp_dst_file}_tmp",
        "ret=$?",
        "if [ $ret != 0 ]; then",
        "    export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-dev-verify-key.pem",
        "    imgverify $tmp_dst_file",
        "fi",
    ],

    "dev_keys_in_rootfs": [
        "hsu-keys/container-dev-verify-key.pem (RSA-2048, same key as rootfs-dev)",
        "hsu-keys/rootfs-dev-verify-key.pem (RSA-2048)",
        "hsu-keys/tools-dev-verify-key.pem (RSA-2048)",
    ],
    "rel_keys_in_rootfs": [
        "hsu-keys/container-rel-verify-key.pem (RSA-2048)",
        "hsu-keys/rootfs-rel-verify-key.pem (RSA-2048)",
        "hsu-keys/tools-rel-verify-key.pem (RSA-2048)",
    ],

    "note": "The fallback to dev key verification is unconditional — production HUU releases accept any image "
            "signed with the dev private key. The dev and release keys are RSA-2048 with distinct moduli "
            "but both embedded in every production rootfs.img. "
            "Combined with the hardcoded decryption key (HUU-F1), an attacker can: "
            "decrypt a legitimate firmware blob, replace payload, re-encrypt with the same key, "
            "sign with the dev private key → accepted by production HUU.",
}

# ─────────────────────────────────────────────────────────
# HUU-F3 — Telnetd auto-enabled on IPMI Cisco-server check failure
# ─────────────────────────────────────────────────────────
HUU_F3 = {
    "id":       "HUU-F3",
    "title":    "hsu-init enables unauthenticated telnetd when IPMI Cisco-server identification fails or when CONFIG_SEC_UTILS_SIGN_MODE=dev",
    "status":   "CONFIRMED — /etc/init.d/hsu-init in HUU 6.0.2.260143 rootfs",
    "severity": "HIGH",

    "init_script": "etc/init.d/hsu-init",
    "trigger_conditions": [
        "CONFIG_SEC_UTILS_SIGN_MODE == 'dev'  — env var triggers telnetd",
        "ipmitool raw 0x36 0x4d 0x04 0x03 fails — if IPMI call returns non-zero, host is not classified as a Cisco server",
    ],

    "ipmi_check": "ipmitool raw 0x36 0x4d 0x04 0x03",
    "ipmi_note":  "Command 0x36 is Cisco OEM extension. If ipmitool is not available, IPMI controller is unresponsive, "
                  "or the response is non-zero, the check fails → telnetd is enabled.",

    "telnetd_auth": "No credentials configured — telnetd provides root shell (root home: /initramfs/)",
    "root_shell":   "/etc/passwd: root:x:0:0:root:/initramfs/:/bin/sh — root shell is /bin/sh",
    "all_shadow_locked": "All accounts in shadow have * (disabled) except root:* — combined with unlocked telnetd this is a root shell.",
}

# ─────────────────────────────────────────────────────────
# HUU-F4 — run_mode file controls dev/rel key selection — writable path enables dev mode
# ─────────────────────────────────────────────────────────
HUU_F4 = {
    "id":       "HUU-F4",
    "title":    "Verification key selection controlled by /opt/cisco/run_mode file content — writing 'DEV' to this path forces dev key use",
    "status":   "CONFIRMED — /etc/init.d/hsu-init in HUU 6.0.2.260143 rootfs",
    "severity": "HIGH",

    "init_script":   "etc/init.d/hsu-init",
    "file_read":     "run_mode=`cat /opt/cisco/run_mode`",
    "condition":     "if [ $run_mode == 'DEV' ] then use tools-dev-verify-key; elif [ $run_mode == 'REL' ] then use tools-rel-verify-key",

    "note":   "The run_mode file is read from /opt/cisco/run_mode at boot. "
              "This path is under /opt/ which may be writable depending on the runtime environment. "
              "Writing 'DEV' to this file before the HUU initializes forces dev key selection for all "
              "subsequent firmware verification operations.",
}

FINDINGS = [HUU_F1, HUU_F2, HUU_F3, HUU_F4]
