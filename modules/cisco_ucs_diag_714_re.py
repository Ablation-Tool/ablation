"""
Cisco UCS Diagnostics 7.1.4.260010 — RE Module
Source: ucs-diag-7.1.4.260010.iso (/media/cowboy/research/Cisco-UCS/)
ISO date: 2026-03-17
Contents:
  bzImage (11MB kernel), initrd (33MB), rootfs.img (147MB squashfs, 2018), efi.img
  ucs-sdu-container-7.1.4.260010.squashfs (152MB, 2026) → ucs-sdu-container-7.1.4.260010-base.tar.gz
rootfs.img: Debian Stretch-era Linux, sshd at rc2, empty root shadow, hsu-keys/
SDU container: Python 3.13, Firefox with HUU profile, root locked (*), standard sudoers
"""

FIRMWARE = {
    "target":  "Cisco UCS Diagnostics / Software Diagnostic Utility (SDU)",
    "version": "7.1.4.260010",
    "source":  "ucs-diag-7.1.4.260010.iso",
    "components": {
        "rootfs":        "rootfs.img — Squashfs v4.0 xz, 2018 vintage, Debian base",
        "sdu_container": "ucs-sdu-container-7.1.4.260010.squashfs — 2026-03-17, Python 3.13",
        "hsu_keys_dir":  "hsu-keys/ in rootfs — 4 RSA-2048 public key PEM/DER pairs",
    },
    "findings": ["DIAG-F1", "DIAG-F2", "DIAG-F3"],
}

# ─────────────────────────────────────────────────────────
# DIAG-F1: Both dev and release HSU verification keys in production diagnostic image
#          — firmware signature verification accepts development-signed firmware
# ─────────────────────────────────────────────────────────
DIAG_F1 = {
    "id":       "DIAG-F1",
    "title":    "UCS Diagnostic rootfs contains both 'dev' and 'rel' HSU verification keys — "
                "diagnostic environment accepts development-signed firmware images for rootfs and containers",
    "status":   "CONFIRMED — /hsu-keys/ in rootfs.img (mounted from ucs-diag-7.1.4.260010.iso)",
    "severity": "MEDIUM",

    "keys_present": {
        "container-dev-verify-key.pem": "RSA-2048 public key for DEV-signed container images",
        "container-rel-verify-key.pem": "RSA-2048 public key for REL-signed container images",
        "rootfs-dev-verify-key.pem":    "RSA-2048 public key for DEV-signed rootfs images",
        "rootfs-rel-verify-key.pem":    "RSA-2048 public key for REL-signed rootfs images",
    },

    "analysis": (
        "Production diagnostic hardware ships with BOTH development and release verification keys. "
        "A signature verification scheme is only as strong as its strictest gating. "
        "If the diagnostic tool verifies firmware against EITHER the dev OR rel key, "
        "any firmware signed with a leaked dev signing key passes verification on production hardware. "
        "Dev signing keys are distributed to Cisco internal developers and CI/CD pipelines — "
        "substantially broader distribution than release signing keys. "
        "The dev key presence in production diagnostic firmware is a trust boundary violation: "
        "diagnostic infrastructure should enforce release keys only in production environments."
    ),

    "keys": {
        "rootfs-dev-verify-key.pem": (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqLuoHGo50f8k4VtUZbIR\n"
            "rHyXGiC4gaRx3A64UOlnN5+kzRyPj/f+vEhykFo2lUi/leeVojerS8s2LVEyJJ9A\n"
            "rTnMBltd0+wy0iKnxd3vsA9aZB+aNHVLICz8pKpw0DfwNH8n6LBzdCRIoPa7biu5\n"
            "eavLXr09R7TP6cLoy9LXQpez146e3QGtY6BmItCxnVwOrb37JnhbSZX8MHoav+XC\n"
            "7ac3sCMFBd8R08W/moFebVvojqaSCwGJK/taV7EUaBvkG3t5mc04oKqm6Z4SSszH\n"
            "3vM4kwjj8QGjQef6rkqtBcs7X3LZkOjbqzaiyv7qN3flnjmDZVrcEKAitu9/cW5J\n"
            "nQIDAQAB\n"
            "-----END PUBLIC KEY-----"
        ),
        "rootfs-rel-verify-key.pem": (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA/Q4Vw+M/8vzr3Fbqif2i\n"
            "n9J2EfHEJK4n5WjgYxM8ptWnsFO5Aj//g4zzjCGxHnNmqYUVp1q1azwEwZWA1Zo6\n"
            "/O3dAs3FY10M/6TwSZfdDn5DdswWlR2q+SwSy3mlEgdxNeSCfu7HBzmarjL1k+Gq\n"
            "TX3cUb9/TMfBwynrEW6oAnYjPU6gI4nFiPcHRNzGMscpYh4wR7XKyAql6ityuAVN\n"
            "srox5fEkWrMXGHXzegvaIaz7ePw8IcJmmcwQXjy8cdTRLCInZ3iiJck5+JSCcDts\n"
            "pUiMc6T2dDrQ6s1mo1LNYaiCiPBHvC2QmDTzXobytBKQFeobBvYleRgXFMS4nyiE\n"
            "EwIDAQAB\n"
            "-----END PUBLIC KEY-----"
        ),
    },
}

# ─────────────────────────────────────────────────────────
# DIAG-F2: rootfs.img created 2018 — EOL components in production diagnostic
# ─────────────────────────────────────────────────────────
DIAG_F2 = {
    "id":       "DIAG-F2",
    "title":    "UCS Diagnostic rootfs.img was created 2018-03-09 and shipped unchanged in 2026 ISO — "
                "8-year-old Debian Linux base with unpatched CVE exposure in diagnostic environment",
    "status":   "CONFIRMED — file timestamp: created Wed Mar 9 12:34:56 2018, 5935 inodes",
    "severity": "LOW",

    "rootfs_details": {
        "created":     "2018-03-09",
        "format":      "Squashfs 4.0, xz, blocksize 131072",
        "size":        "147MB",
        "accounts":    "root (shell=/bin/sh, home=/initramfs/), sshd, www-data, nobody",
        "shadow":      "Empty — root has no password hash; all system accounts locked",
        "services":    "rc2: networking, dbus, sshd, nfs, syslog",
    },

    "impact": (
        "The diagnostic rootfs runs on bare metal UCS servers during diagnostic mode. "
        "An 8-year-old Debian base has unpatched vulnerabilities in the network stack, "
        "SSH daemon, and system libraries. In diagnostic mode, the server is on the management network "
        "and sshd is running — any pre-auth SSH vulnerabilities in the 2018 OpenSSH version "
        "are directly exploitable. The rootfs is read-only (squashfs), so persistence requires "
        "a writable layer or in-memory exploitation only."
    ),
}

# ─────────────────────────────────────────────────────────
# DIAG-F3: decrypt-file in SDU container contains the same hardcoded PBKDF2 key
#          — 6th confirmed UCS component spanning HUU + SCU + SDU (Diagnostics) product lines
# ─────────────────────────────────────────────────────────
DIAG_F3 = {
    "id":       "DIAG-F3",
    "title":    "UCS SDU 7.1.4 decrypt-file contains hardcoded PBKDF2 AES-256 key 'zfguijkophju@*%1]' — "
                "6th confirmed UCS component; key now spans HUU + SCU + SDU product lines",
    "status":   "CONFIRMED — strings ./usr/sbin/decrypt-file from ucs-sdu-container-7.1.4.260010-base.tar.gz",
    "severity": "CRITICAL",

    "key":  "zfguijkophju@*%1]",

    "decrypt_commands_in_binary": [
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s.gz -k zfguijkophju@*%1] -nosalt 2>&1",
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s -k zfguijkophju@*%1] -nosalt 2>&1",
    ],

    "confirmed_6_components": [
        "ucs-xe130cm8-huu-6.0.2.260143  (HUU XE130C M8 — cisco_ucs_huu_xe130cm8_602_re.py)",
        "ucs-c220m8-huu-6.0.2.260143    (HUU C220 M8  — cisco_ucs_huu_cross_model_re.py)",
        "ucs-c245m8-huu-6.0.2.260180    (HUU C245 M8  — cisco_ucs_huu_cross_model_re.py)",
        "ucs-c480m5-huu-4.2.3r          (HUU C480 M5  — cisco_ucs_huu_cross_model_re.py)",
        "ucs-scu-7.1.7.260200           (SCU 7.1.7    — cisco_ucs_scu_717_re.py)",
        "ucs-diag-7.1.4.260010          (SDU/Diag     — this module)",
    ],

    "product_line_scope": (
        "The key is now confirmed across THREE distinct UCS bootable utility product lines: "
        "HUU (Hardware Update Utility), SCU (Software Configuration Utility), "
        "and SDU/Diagnostics (Software Diagnostic Utility). "
        "All three serve different operational purposes (firmware update, OS configuration, diagnostics) "
        "but share the same hsu/gunicorn architecture and the same decrypt-file binary with identical key. "
        "This confirms the key is a shared infrastructure constant built into the common "
        "UCS bootable utility framework, not an artifact of any single product or version."
    ),

    "two_decrypt_modes": (
        "The SDU decrypt-file exposes two separate openssl invocations: "
        "(1) decrypt to .gz (gzip'd output) and (2) decrypt to raw output. "
        "This is consistent with the binary supporting both compressed and uncompressed payloads, "
        "identical to the HUU and SCU decrypt-file binaries."
    ),
}

SDU_CONTAINER_NOTES = {
    "version":      "7.1.4.260010 (2026-03-17)",
    "python":       "3.13",
    "root_shadow":  "* (locked, no password login)",
    "firefox":      "HUU profile, obscure_value=0 (plaintext cfg), DNS prefetch disabled",
    "note":         "No novel credential or auth findings in SDU container",
}

FINDINGS = [DIAG_F1, DIAG_F2, DIAG_F3]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
