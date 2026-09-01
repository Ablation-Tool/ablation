"""
Cisco 7861/78xx 5th-Gen SIP 12.5.1SR1-4 — PLATFORM_2 (rootfs2) RE
Static analysis: UBI/UBIFS extraction, strings on security libraries and daemons
Compared to PLATFORM_1 (rootfs1) from cisco_7861_78xx_re.py
"""

# ─────────────────────────────────────────────────────────
# PLATFORM_2 identity
# ─────────────────────────────────────────────────────────
PLATFORM_2 = {
    "sbn_file":     "rootfs2.78xx.12-5-1SR1-4.sbn",
    "sbn_size":     39321940,
    "ubi_size":     39321600,
    "volume_id":    550771361,
    "date":         "2019-01-14",

    "hw_architecture": {
        "cpu_endian": "LSB (little-endian ARM)",
        "note": "PLATFORM_1 is MSB (big-endian ARM). Different processor variant, same firmware version.",
    },
}

# ─────────────────────────────────────────────────────────
# Security library SHA256 — differ from PLATFORM_1
# ─────────────────────────────────────────────────────────
CRYPTO_LIBRARIES = {
    "libseccommon.so": {
        "sha256": "919e1280626958371c69ad88cf44c091941644801187581110249eed41f5c456",
        "size":   36664,
        "arch":   "ARM 32-bit LSB ELF (EABI5), stripped",
        "vs_platform1_sha256": "264c68cfab360cd027fd320765042bde9cf4181a4b153c278f486aa26a4ea00e",
        "ssl_version": "CiscoSSL 6.0-fips-dev xx XXX xxxx (DEVELOPMENT BUILD — date unstamped)",
        "note": (
            "Different SHA from PLATFORM_1. CiscoSSL version string 6.0-fips-dev is a "
            "development/unreleased build marker. Date placeholders (xx XXX xxxx) suggest "
            "the build used a dev config that doesn't stamp the version string at compile time."
        ),
    },
    "libsecurity.so": {
        "sha256": "e2a32cc9c6bfd480fce1299787b08edde0cd73da71d6f4061f27ec4a6d401b10",
        "size":   69708,
        "arch":   "ARM 32-bit LSB ELF (EABI5), stripped",
        "vs_platform1_sha256": "6c088c4eb236ecf423381e65174fca26b8d4687a1147fef72cbc91888d43cd30",
    },
    "libcrypto.so.1.0.0": {
        "size": 2431304,
        "note": "2.4MB vs PLATFORM_1's 2.0MB (libcrypto.so.0.9.8). Different naming and larger.",
    },
    "libssl.so.1.0.0": {
        "size": 405986,
        "note": "405KB vs PLATFORM_1's 354KB. LSB ARM build.",
    },
    "libsecuremic.so": {
        "size": 5340,
        "note": "PLATFORM_2-ONLY — not present in PLATFORM_1. Microphone security interface.",
    },
}

# ─────────────────────────────────────────────────────────
# PHN-F14 — PLATFORM_2 ANY-role bypass (CONFIRMED)
# ─────────────────────────────────────────────────────────
PHN_F14_PLATFORM2 = {
    "id":       "PHN-F14 (PLATFORM_2)",
    "product":  "Cisco 7861/78xx SIP 12.5.1SR1-4 (PLATFORM_2 / rootfs2)",
    "library":  "libseccommon.so",
    "severity": "HIGH",

    "bypass_strings_confirmed": [
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - no certificate validation plugin available.",
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - any role is specified.",
    ],

    "note": (
        "PHN-F14 confirmed on both hardware platforms (PLATFORM_1 MSB and PLATFORM_2 LSB) "
        "in the same firmware release (12.5.1SR1-4, 2019-01-14). The handyiron bypass is "
        "present in both ARM variants despite different SHA256 values — the bypass logic "
        "was not removed in either build."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F15 extension — debug hash identical on both platforms
# ─────────────────────────────────────────────────────────
PHN_F15_PLATFORM2 = {
    "id":    "PHN-F15 (PLATFORM_2)",
    "debug_passwd_entry": "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:65532:100:debug:/tmp:/usr/sbin/debugsh",
    "hash_type":  "MD5crypt ($1$)",
    "salt":       "aoJQnypw",

    "cross_platform_identity": {
        "PLATFORM_1_hash": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "PLATFORM_2_hash": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "IDENTICAL": True,
        "note": (
            "Same salt, same hash across both hardware platforms. "
            "This is a static embedded credential — not device-specific. "
            "Cracking it once yields access to all 78xx phones of both hardware variants."
        ),
    },
}

# ─────────────────────────────────────────────────────────
# PHN-F16 NEW — CERT_ANY bypass mode in secureapp (PLATFORM_2)
# ─────────────────────────────────────────────────────────
PHN_F16_CERT_ANY = {
    "id":       "PHN-F16",
    "product":  "Cisco 7861/78xx SIP 12.5.1SR1-4 (PLATFORM_2)",
    "binary":   "/usr/sbin/secureapp",
    "severity": "HIGH",
    "class":    "TLS Certificate Verification Bypass (Config-driven)",

    "bypass_string": "CERT_ANY      : allow all unverified server certs",

    "description": (
        "secureapp (PLATFORM_2 security daemon) has a documented CERT_ANY mode that "
        "disables all certificate validation. Unlike the handyiron ANY-role bypass (which "
        "is triggered by role provisioning), CERT_ANY appears to be a higher-level cert "
        "policy setting. When set to CERT_ANY, all server certificates are accepted without "
        "validation regardless of the underlying handyiron role logic."
    ),

    "consumers": [
        "secureapp (links libseccommon.so)",
        "edge_gateway (links libseccommon.so)",
    ],

    "attack_vector": (
        "If cert type can be provisioned via TFTP-delivered config (similar to "
        "CCMCIP.Host.CertLevel=0 on Jabber Windows / JAB-F15), setting CERT_ANY "
        "provides a config-driven TLS bypass on PLATFORM_2."
    ),

    "note": "Provisioning mechanism for CERT_ANY requires further analysis.",
}

# ─────────────────────────────────────────────────────────
# edge_gateway — new PLATFORM_2 attack surface
# ─────────────────────────────────────────────────────────
EDGE_GATEWAY_SURFACE = {
    "binary": "/usr/sbin/edge_gateway",
    "arch":   "ARM 32-bit LSB ELF, dynamically linked",
    "links":  ["libseccommon.so", "libsecureStorage.so", "libssl.so.1.0.0",
               "libcrypto.so.1.0.0", "libsecmisc.so", "libsecureapi.so", "libsecuremic.so"],

    "security_relevance": (
        "edge_gateway links libseccommon.so — the handyiron bypass library. "
        "Any network-facing function in edge_gateway is subject to the PHN-F14 bypass "
        "if it uses the libseccommon TLS path. Not present in PLATFORM_1 — PLATFORM_2 only. "
        "Name suggests network edge/gateway function (VPN, remote access, or UCM-edge protocol)."
    ),
}

# ─────────────────────────────────────────────────────────
# PLATFORM_1 vs PLATFORM_2 differential
# ─────────────────────────────────────────────────────────
PLATFORM_DIFF = {
    "hw_endianness": {
        "PLATFORM_1": "MSB (big-endian ARM, EABI5)",
        "PLATFORM_2": "LSB (little-endian ARM, EABI5)",
    },
    "ssl_version": {
        "PLATFORM_1": "CiscoSSL 1.0.2o.6.2.238-fips",
        "PLATFORM_2": "CiscoSSL 6.0-fips-dev (development build, unstamped date)",
    },
    "libcrypto_size": {
        "PLATFORM_1": "2014924 bytes (libcrypto.so.0.9.8 symlinked as .1.0.0)",
        "PLATFORM_2": "2431304 bytes (libcrypto.so.1.0.0 direct)",
    },
    "security_daemon": {
        "PLATFORM_1": "secd (/usr/sbin/secd)",
        "PLATFORM_2": "secureapp (/usr/sbin/secureapp) — secd not present",
    },
    "ssh": {
        "PLATFORM_1": "Dropbear 0.51 + OpenSSH sshd, xinetd disabled by default",
        "PLATFORM_2": "OpenSSH sshd only (no Dropbear), xinetd disabled by default",
    },
    "unique_to_platform2": ["edge_gateway", "libsecuremic.so", "dbus_manager", "telnetd",
                             "inetd (not just xinetd)", "espd", "ewcl", "ewCmd"],
    "phn_f14_status": {
        "PLATFORM_1": "CONFIRMED",
        "PLATFORM_2": "CONFIRMED",
    },
    "phn_f15_hash": {
        "PLATFORM_1": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "PLATFORM_2": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "IDENTICAL":  True,
    },
}
