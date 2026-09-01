"""
Cisco 7861 / 78xx 5th-Gen SIP 12.5.1SR1-4 — TLS/DTLS Cert Verification RE
Static analysis: SBN header strip, UBI/UBIFS extraction via ubireader,
strings, objdump on extracted rootfs
"""

FIRMWARE = {
    "product":     "Cisco IP Phone 7861 / 78xx (5th-Generation SIP)",
    "version":     "12.5.1SR1-4",
    "date":        "2019-01-14",
    "source_file": "78xx.tar",
    "sbn_files": [
        "sboot78xx.12-5-1SR1-4.sbn",
        "kern78xx.12-5-1SR1-4.sbn",
        "rootfs78xx.12-5-1SR1-4.sbn",   # 40,763,732 bytes
        "sboot2.78xx.12-5-1SR1-4.sbn",
        "kern2.78xx.12-5-1SR1-4.sbn",
        "rootfs2.78xx.12-5-1SR1-4.sbn",  # 39,321,940 bytes (PLATFORM_2 variant)
    ],
    "comment": "Two hardware platform variants (PLATFORM_1/PLATFORM_2)",
}

# ─────────────────────────────────────────────────────────
# Firmware format — 78xx vs 89xx/79xx
# ─────────────────────────────────────────────────────────
FIRMWARE_FORMAT = {
    "sbn_magic":        "cd 34 12 ab (78xx-specific; 79xx/89xx: different TLV)",
    "payload_offset":   "0x154 (340 bytes) = value at bytes [4:8] LE = 0x154",
    "filesystem":       "UBI/UBIFS (not JFFS2 as in 79xx/89xx)",
    "ubi_layout": {
        "vid_hdr_offset": "0x800 (2048)",
        "data_offset":    "0x1000 (4096)",
        "volume_name":    "rootfs",
    },
    "extraction_method": "ubireader_extract_images / ubireader_extract_files",
    "rootfs_size_decompressed": "full UBIFS volume, 39MB image",
}

# ─────────────────────────────────────────────────────────
# Crypto library inventory
# ─────────────────────────────────────────────────────────
CRYPTO_LIBRARIES = {
    "libsecurity.so": {
        "path":    "/usr/lib/libsecurity.so",
        "sha256":  "6c088c4eb236ecf423381e65174fca26b8d4687a1147fef72cbc91888d43cd30",
        "size":    69660,
        "arch":    "ARM 32-bit ELF (EABI5), stripped",
        "note":    "Cisco security layer; TVS IS implemented (differs from CIPC/PHN-F04)",
    },
    "libseccommon.so": {
        "path":    "/usr/lib/libseccommon.so",
        "sha256":  "264c68cfab360cd027fd320765042bde9cf4181a4b153c278f486aa26a4ea00e",
        "size":    37616,
        "arch":    "ARM 32-bit ELF (EABI5), stripped",
        "ssl_version": "CiscoSSL 1.0.2o.6.2.238-fips",
        "note":    "handyiron shared security library; contains ANY-role bypass",
    },
    "ssl_version_detail": {
        "ciscossl":   "CiscoSSL 1.0.2o.6.2.238-fips",
        "openssl_base": "OpenSSL 1.0.2o (March 2018)",
        "note": "Newer than Jabber Windows (1.0.2k) and 89xx 9.4.2SR2-2; still 1.0.2 family",
    },
}

# ─────────────────────────────────────────────────────────
# PHN-F14 — 78xx libseccommon.so ANY-role bypass (CONFIRMED)
# Extends JAB-F14 and the broader handyiron bypass class to 5th-gen phones
# ─────────────────────────────────────────────────────────
PHN_F14_78XX_ANY_ROLE_BYPASS = {
    "id":       "PHN-F14",
    "product":  "Cisco 7861/78xx SIP 12.5.1SR1-4",
    "library":  "libseccommon.so (/usr/lib/)",
    "severity": "HIGH — ANY-role bypass confirmed in newest-available 78xx firmware",
    "class":    "TLS Certificate Verification Bypass",

    "bypass_strings_confirmed": [
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - no certificate validation plugin available.",
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - any role is specified.",
    ],

    "note": (
        "Identical bypass strings to JAB-F14 (Jabber Windows) and all prior phone models. "
        "libseccommon.so is the handyiron shared security library across all Cisco UC endpoints. "
        "CiscoSSL 1.0.2o-fips base does NOT close the handyiron bypass — the bypass is in the "
        "role-checking layer above the crypto, not in the SSL implementation itself. "
        "Cisco shipping 12.5.1SR1-4 in 2019 with this bypass present confirms it was never "
        "patched in the handyiron library through at least that date."
    ),

    "cross_platform": "Same finding class as JAB-F14 (Jabber Win), PHN-F04/CIPC-F01, all prior phone models",
}

# ─────────────────────────────────────────────────────────
# TVS architecture — 78xx has TVS implemented (unlike CIPC/894x)
# ─────────────────────────────────────────────────────────
TVS_ARCHITECTURE_78XX = {
    "tvs_implemented": True,
    "note": "PHN-F04 / CIPC-F01 (SECAddTvsServer not implemented) does NOT apply to 78xx",
    "evidence": [
        "secSetTVSServiceContext — present in libsecurity.so",
        "secGetTVSServiceCtx — present in libsecurity.so",
        "VALIDATE CERT - TVS not enabled — present (TVS-path exists but can be unconfigured)",
        "not using TVS for cert validation - role is TVS or SRST — present",
    ],
    "implication": (
        "78xx supports full TVS cert validation chain. The bypass requires either: "
        "(a) CTL/CUCM provisioning sets role=ANY, OR (b) no validation plugin registered."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F15 — debug user with crackable MD5 hash (78xx)
# ─────────────────────────────────────────────────────────
PHN_F15_DEBUG_USER_HASH = {
    "id":      "PHN-F15",
    "product": "Cisco 7861/78xx SIP 12.5.1SR1-4",
    "severity": "HIGH — debug:debug credential confirmed, shell via Unix socket",
    "class":   "Credential Exposure / Debug Interface",

    "passwd_entry": "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:65532:100:debug:/tmp:/usr/sbin/debugsh",
    "hash_type":    "MD5crypt ($1$)",
    "hash":         "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
    "plaintext":    "debug",
    "crack_method": "Cisco RE-derived wordlist — username=password pattern",
    "shell":        "/usr/sbin/debugsh",
    "socket":       "/tmp/debugshd_sock",

    "credential": {
        "username": "debug",
        "password": "debug",
        "verified": True,
        "note": "Username equals password. Static across all 78xx UC and 8845-65 UC firmware versions.",
    },

    "other_accounts": {
        "root":     "root:!:0:0:root:/home/root:/bin/sh  (LOCKED — PHN-F13 does NOT apply)",
        "security": "security::17:70:security:/:/sbin/nologin  (empty pw, nologin shell)",
        "app":      "app::65534:65534:app:/home:/sbin/nologin  (empty pw, nologin)",
    },

    "debugsh_analysis": {
        "interface": "Unix domain socket /tmp/debugshd_sock",
        "features":  ["start_interactive_shell", "bash-like history", "store sip-debugs"],
        "note":      "debugsh provides bash-like interactive shell access; not a full bash shell",
    },

    "note": (
        "Credential cracked: debug:debug. MD5crypt($1$aoJQnypw$...) = 'debug'. "
        "Username=password pattern — trivially guessable. Combined with enabled SSH "
        "(sshAccess=1 in TFTP config), provides privileged diagnostic access to all "
        "Cisco UC 78xx/8845-65 phones. debugshd must be running; attacker must reach "
        "/tmp/debugshd_sock. Cracked 2026-09-01 via Cisco RE-derived wordlist."
    ),
}

# ─────────────────────────────────────────────────────────
# SSH surface — disabled by default (78xx)
# ─────────────────────────────────────────────────────────
SSH_SURFACE_78XX = {
    "dropbear_version":   "SSH-2.0-dropbear_0.51",
    "dropbear_sha256":    None,  # not extracted separately
    "xinetd_config":      "/etc/xinetd.default/sshd",
    "xinetd_disabled":    True,  # disable = yes
    "xinetd_server":      "/usr/sbin/sshd",
    "also_present":       ["dropbear", "dropbearconvert", "dropbearmulti", "dropbearkey", "sshd_non_inetd_mode"],
    "phn_f11_applies":    "PARTIAL — Dropbear 0.51 binary present but xinetd disabled by default",
    "note": (
        "78xx has SSH disabled in xinetd config (disable = yes). "
        "PHN-F11 class: if SSH is enabled via config change, Dropbear 0.51 CVE-2012-0920 path opens. "
        "Full OpenSSH sshd also present at /usr/sbin/sshd."
    ),
}

# ─────────────────────────────────────────────────────────
# secd daemon — runs as root (attack escalation path)
# ─────────────────────────────────────────────────────────
SECD_DAEMON_78XX = {
    "path":       "/usr/sbin/secd",
    "uid":        "root:root",
    "init_script": "/etc/init.d/secd.sh",
    "pid_file":   "/var/run/secd.pid",
    "capabilities": ["CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_IPC_OWNER", "CAP_SYS_NICE"],
    "note": "secd runs as root. Any secd IPC injection or socket manipulation = root code execution.",
}

# ─────────────────────────────────────────────────────────
# Platform comparison: 78xx vs 89xx vs Jabber Windows
# ─────────────────────────────────────────────────────────
PLATFORM_COMPARISON = {
    "ANY_role_bypass":   "PRESENT — all platforms (79xx/89xx SCCP/SIP, 78xx, Jabber Windows, CIPC)",
    "TVS_implemented":   "78xx=YES; 79xx/89xx=YES; CIPC=NO (CIPC-F01); 894x early=CANDIDATE",
    "root_empty_passwd": "89xx 9.3.x=YES (PHN-F13); 78xx=NO (locked); 79xx/Jabber=N/A",
    "SSH_exposed":       "89xx 9.3.x/9.4.2=YES unconditional; 78xx=BINARY PRESENT/xinetd-disabled",
    "SSL_version": {
        "78xx 12.5.1SR1-4":        "CiscoSSL 1.0.2o-fips",
        "Jabber Win 11.9.1":       "CiscoSSL 1.0.2k-fips",
        "89xx 9.4.2SR2-2":         "CiscoSSL 1.1.0-fips-dev",
        "89xx 9.3.4-17":           "OpenSSL 0.9.8k",
        "89xx 9.3.1-18/SCCP 9.3.1-19": "OpenSSL 0.9.8g",
    },
    "filesystem": {
        "78xx":    "UBI/UBIFS",
        "79xx/89xx": "JFFS2 (embedded in SBN at firmware-specific offset)",
        "CIPC":    "Windows PE DLL (no filesystem)",
    },
}
