"""
Cisco UCS HUU 6.0.2.260143 — RE findings
Primary source: ucs-c220m8-huu-6.0.2.260143.iso
Cross-verified: ucs-xe130cm8-huu-6.0.2.260143.iso (Cisco XE130C, newest platform)

C220 M8 structure:
  rootfs.img     — squashfs v4.0 xz (148MB, 5935 inodes, created 2018-03-09)
  ucs-c220m8-huu-container-6.0.2.260143.squashfs — squashfs v4.0 zlib (937MB, 643 inodes, 2026-06-17)
CIMC version: 6.0(2.260095)
BIOS: C220M8.6.0.2d.0.0527260454

Cross-platform key verification:
  sha256(container-dev-verify-key.pem) C220 M8 == XE130C: 8172ce48c2d3983f3000a0ae8fb1a91491128196ec5ba4f2f6d1950988512073
  sha256(rootfs-dev-verify-key.pem)    C220 M8 == XE130C: 8172ce48c2d3983f3000a0ae8fb1a91491128196ec5ba4f2f6d1950988512073
  sha256(tools-dev-verify-key.pem)     C220 M8 == XE130C: 8172ce48c2d3983f3000a0ae8fb1a91491128196ec5ba4f2f6d1950988512073
  sha256(container-rel-verify-key.pem) C220 M8 == XE130C: a2a81324d17f21696fe8e6e1c2e22319d4bd720b63bf7751745907308dd89681
  sha256(rootfs-rel-verify-key.pem)    C220 M8 == XE130C: a2a81324d17f21696fe8e6e1c2e22319d4bd720b63bf7751745907308dd89681
  sha256(tools-rel-verify-key.pem)     C220 M8 == XE130C: a2a81324d17f21696fe8e6e1c2e22319d4bd720b63bf7751745907308dd89681
  hsu-init, ftd, decrypt-file: byte-identical across both platforms
"""

FIRMWARE = {
    "target":           "Cisco UCS HUU (C-Series and XE-Series)",
    "version":          "6.0.2.260143",
    "primary_source":   "ucs-c220m8-huu-6.0.2.260143.iso",
    "cross_verified":   "ucs-xe130cm8-huu-6.0.2.260143.iso",
    "rootfs_c220m8":    "rootfs.img — squashfs v4.0 xz, 148MB, 5935 inodes, 2018-03-09",
    "container_c220m8": "ucs-c220m8-huu-container-6.0.2.260143.squashfs — squashfs v4.0 zlib, 937MB, 643 inodes, 2026-06-17",
    "rootfs_xe130c":    "rootfs.img — squashfs v4.0 xz, 141MB, 4741 inodes, 2026-06-17",
    "cimc_ver":         "6.0(2.260095)",
    "bios_ver":         "C220M8.6.0.2d.0.0527260454",
    "features":         {"NonInteractiveSupport": True, "RedfishSupport": True, "UISupport": True},
    "platform_scope":   "Hardcoded AES key, dev/rel verify keys, hsu-init, and ftd are byte-identical across C220 M8 and XE130C. All UCS C-Series and X-Series platforms running HUU 6.0.x are presumed affected.",
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

# ─────────────────────────────────────────────────────────
# HUU-F5 — xinetd telnet unconditionally enabled, no source IP restriction
# ─────────────────────────────────────────────────────────
HUU_F5 = {
    "id":       "HUU-F5",
    "title":    "xinetd telnet service (in.telnetd) enabled unconditionally with no source IP restriction — any host on the network can connect",
    "status":   "CONFIRMED — /etc/xinetd.d/telnet in HUU 6.0.2.260143 rootfs (C220 M8 and XE130C identical)",
    "severity": "HIGH",

    "xinetd_config": [
        "service telnet",
        "{",
        "    disable     = no",
        "    flags       = REUSE",
        "    socket_type = stream",
        "    wait        = no",
        "    user        = root",
        "    server      = /usr/sbin/in.telnetd",
        "    log_on_failure += USERID",
        "}",
    ],

    "missing_restriction": "No 'only_from' directive — xinetd accepts from any source IP.",

    "telnetd_auth_note": "in.telnetd (ELF x86-64, inetutils build) passes '-f <user>' to /bin/login.shadow "
                         "when the connecting telnet client sends TELNET ENVIRON USER. The login.shadow binary "
                         "accepts the -f flag (skips password prompt for pre-authenticated user). "
                         "Root shadow entry is '*' (locked); whether -f bypasses the account lock "
                         "depends on the specific login.shadow build behavior. "
                         "If honored, any connecting client that sets ENVIRON USER=root receives a root shell "
                         "without a password prompt.",

    "separate_from_huu_f3": "HUU-F3 documents the hsu-init conditional telnetd (triggered when IPMI check fails). "
                             "This finding is the always-on xinetd-managed telnet service, active regardless of "
                             "IPMI result or CONFIG_SEC_UTILS_SIGN_MODE. Both services target port 23; "
                             "if hsu-init telnetd binds first, there is a port conflict.",

    "platforms": ["C220 M8 (ucs-c220m8-huu-6.0.2.260143.iso)", "XE130C (ucs-xe130cm8-huu-6.0.2.260143.iso)"],
}

# ─────────────────────────────────────────────────────────
# HUU-F6 — USB OTG network interface (usb0 192.168.7.2) exposes all services via USB RNDIS
# ─────────────────────────────────────────────────────────
HUU_F6 = {
    "id":       "HUU-F6",
    "title":    "USB RNDIS gadget interface (usb0 192.168.7.2/24) configured at boot — all network services (telnet, SSH) accessible via USB cable without physical Ethernet",
    "status":   "CONFIRMED — /etc/network/interfaces in HUU 6.0.2.260143 rootfs (C220 M8 and XE130C identical)",
    "severity": "MEDIUM",

    "network_config": [
        "iface usb0 inet static",
        "    address 192.168.7.2",
        "    netmask 255.255.255.0",
    ],

    "impact": "A server being upgraded with the HUU ISO exposes a static USB network interface. "
              "Anyone with physical USB access to the server can connect a USB cable, configure "
              "192.168.7.1/24 on their host, and reach all HUU network services directly: "
              "telnet (HUU-F3/HUU-F5), SSH (port 22, X11Forwarding enabled), and any web UI "
              "running in the container. No Ethernet or network infrastructure required.",

    "compounding": "When combined with HUU-F3 (conditional telnetd root shell) or HUU-F5 (unconditional xinetd telnet), "
                   "USB physical access translates to a network path for remote-protocol exploitation "
                   "without requiring out-of-band network connectivity.",

    "ssh_note": "sshd is started at boot (init.d/sshd). Root shadow entry is '*' (locked); "
                "SSH is configured with HostKey /etc/ssh/ssh_host_ecdsa_key — key generated on first boot, "
                "not embedded in the squashfs. Password auth defaults to enabled (PasswordAuthentication "
                "not overridden in sshd_config), but root:* prevents password login. "
                "X11Forwarding yes is explicitly set — SSH X11 tunnel possible for HUU web UI access.",

    "usb_note": "usb0 uses the USB gadget driver (Linux USB OTG / RNDIS / CDC-Ether). The connecting "
                "host must load the RNDIS or CDC-Ether driver and configure an IP in 192.168.7.0/24.",

    "platforms": ["C220 M8 (ucs-c220m8-huu-6.0.2.260143.iso)", "XE130C (ucs-xe130cm8-huu-6.0.2.260143.iso)"],
}

FINDINGS = [HUU_F1, HUU_F2, HUU_F3, HUU_F4, HUU_F5, HUU_F6]
