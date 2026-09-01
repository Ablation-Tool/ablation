"""
Cisco 7861/78xx UC 12.8.1 — version delta RE
rootfs78xx.12-8-1-0101-482.sbn  (rootfs1)
rootfs2.78xx.12-8-1-0101-482.sbn (rootfs2)
Compared to 12.5.1SR1-4 baseline (PLATFORM_1 MSB + PLATFORM_2 LSB)
Static analysis: SBN header strip, ubireader_extract_files, strings
"""

# ─────────────────────────────────────────────────────────
# SBN header parameters
# ─────────────────────────────────────────────────────────
SBN_HEADER = {
    "rootfs1": {"sbn_file": "rootfs78xx.12-8-1-0101-482.sbn", "sbn_size": 38666240+0x158, "header_offset": 0x158},
    "rootfs2": {"sbn_file": "rootfs2.78xx.12-8-1-0101-482.sbn", "sbn_size": 39321600+0x158, "header_offset": 0x158},
}

# ─────────────────────────────────────────────────────────
# Security library SHA256 — 12.8.1 vs 12.5.1SR1-4 baseline
# ─────────────────────────────────────────────────────────
SECURITY_LIB_SHA256 = {
    "rootfs1": {
        "libseccommon.so": {
            "sha256": "ef9e3db57bd958c6449a5f72cabaf6befd448fa95b769d0b6913d1af4833339f",
            "size":   37616,
            "arch":   "ARM 32-bit LSB ELF (EABI5), stripped",
            "vs_125_platform1": "264c68cfab360cd027fd320765042bde9cf4181a4b153c278f486aa26a4ea00e (MSB — different arch)",
            "vs_125_platform2": "919e1280626958371c69ad88cf44c091941644801187581110249eed41f5c456 (LSB — same arch, different SHA)",
        },
        "libsecurity.so": {
            "sha256": "c918c6eb343f884a47b4f230c1b129f7d2378855bc6a057c72e8ac6af7932189",
            "size":   69660,
            "arch":   "ARM 32-bit LSB ELF (EABI5), stripped",
        },
        "libssl.so.0.9.8": {
            "sha256": "c03140d3787788672a1875133918202cbe92f6961c2742daacf9e4ad656abcda",
            "size":   354016,
            "ssl_version": "CiscoSSL 1.0.2o.6.2.238-fips",
        },
        "libcrypto.so.1.0.0": {
            "sha256": "f6337fab683c7f52fe008d7f15d51b323e2758996717ad5f0f20896caa437fc6",
            "size":   2426011,
            "note":   "with debug_info, not stripped",
        },
        "secd": {
            "sha256": "67cf926d72a7e9355f68b26cb6b264aeed1e243b72a72cf3b1f920f5f7c4068a",
            "size":   162284,
            "note":   "secd present in rootfs1 12.8.1 — was also present in 12.5.1SR1-4 PLATFORM_1",
        },
        "secureapp": {
            "sha256": "76f4cd2812f109d904dd7a4e8f8f2b47b9125c549427a20e30edca09560b236a",
            "size":   138336,
            "note":   "NEW in rootfs1: secureapp now present alongside secd (not in 12.5.1SR1-4 rootfs1)",
        },
    },
    "rootfs2": {
        "libseccommon.so": {
            "sha256": "4ed2f6ddaf60e07eb78f690774d84c3ff2d09e4df62a10d79342d30aaf93d475",
            "size":   36664,
            "arch":   "ARM 32-bit LSB ELF (EABI5), stripped",
            "vs_125_platform2": "919e1280626958371c69ad88cf44c091941644801187581110249eed41f5c456 — different SHA, same size",
        },
        "libsecurity.so": {
            "sha256": "06083f3f23d3af461638f50b6b8c839afe3981c86d08930c04792e73aed6c724",
            "size":   69708,
        },
        "libssl.so.1.0.0": {
            "sha256": "f67131e33c403cd6bd28cea61fd681babd55fb7e7e5fafd4f91fbbe0539e15c3",
            "size":   405986,
            "ssl_version": "CiscoSSL 1.0.2o.6.2.238-fips",
            "vs_125_platform2": "CiscoSSL 6.0-fips-dev xx XXX xxxx — DEVELOPMENT BUILD replaced by release build",
        },
        "libcrypto.so.1.0.0": {
            "sha256": "5733df2483f738346eaa8f27135b9a84ed544300fbe55006d5be936c25888875",
            "size":   2431304,
        },
        "secureapp": {
            "sha256": "6cba495eac5c731b57d1595234159d03be421366c0d2b79f43c6267de4e8701b",
            "size":   134444,
        },
    },
}

# ─────────────────────────────────────────────────────────
# PHN-F14 — handyiron ANY-role bypass (PERSISTENT across versions)
# ─────────────────────────────────────────────────────────
PHN_F14_VERSION_DELTA = {
    "id":     "PHN-F14",
    "status": "CONFIRMED PERSISTENT — 12.5.1SR1-4 through 12.8.1",

    "bypass_strings_rootfs1": [
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - no certificate validation plugin available.",
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - any role is specified.",
    ],
    "bypass_strings_rootfs2": [
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - no certificate validation plugin available.",
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - any role is specified.",
    ],

    "note": (
        "PHN-F14 handyiron ANY-role bypass persists in BOTH rootfs variants across the "
        "12.5.1SR1-4 → 12.8.1 version upgrade. libseccommon.so SHA changed in both rootfs "
        "(updated code), but the bypass string is present in all variants. Cisco did not "
        "remove the bypass logic in this version delta."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F15 — debug credential (PERSISTENT, hash IDENTICAL)
# ─────────────────────────────────────────────────────────
PHN_F15_VERSION_DELTA = {
    "id":     "PHN-F15",
    "status": "CONFIRMED PERSISTENT — identical across all 78xx versions",

    "passwd_entry": "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:65532:100:debug:/tmp:/usr/sbin/debugsh",
    "hash":         "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",

    "version_hash_identity": {
        "12.5.1SR1-4 rootfs1 (MSB)": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "12.5.1SR1-4 rootfs2 (LSB)": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "12.8.1 rootfs1 (LSB)":      "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "12.8.1 rootfs2 (LSB)":      "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "IDENTICAL_ALL":              True,
    },

    "implication": (
        "Static credential — same salt ($1$aoJQnypw$) and same hash across hardware platforms "
        "and firmware versions. Cracking once yields debug shell access to all 78xx variants."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F16 — CERT_ANY in secureapp (PERSISTENT)
# ─────────────────────────────────────────────────────────
PHN_F16_VERSION_DELTA = {
    "id":     "PHN-F16",
    "status": "CONFIRMED PERSISTENT — 12.5.1SR1-4 through 12.8.1",

    "cert_any_string_rootfs1": "CERT_ANY      : allow all unverified server certs",
    "cert_any_string_rootfs2": "CERT_ANY      : allow all unverified server certs",

    "note": (
        "PHN-F16 CERT_ANY mode persists in secureapp in both rootfs variants of 12.8.1. "
        "In 12.5.1SR1-4, secureapp was PLATFORM_2-only. In 12.8.1, secureapp ships in "
        "BOTH rootfs — CERT_ANY bypass surface now extends to rootfs1 hardware variants."
    ),
}

# ─────────────────────────────────────────────────────────
# Architecture delta — 12.5.1SR1-4 vs 12.8.1
# ─────────────────────────────────────────────────────────
ARCHITECTURE_DELTA = {
    "endianness": {
        "12.5.1SR1-4 rootfs1": "ARM MSB (big-endian) — PLATFORM_1",
        "12.5.1SR1-4 rootfs2": "ARM LSB (little-endian) — PLATFORM_2",
        "12.8.1 rootfs1":      "ARM LSB (little-endian)",
        "12.8.1 rootfs2":      "ARM LSB (little-endian)",
        "significance": (
            "MSB PLATFORM_1 variant DROPPED in 12.8.1. Both rootfs are now LSB ARM. "
            "Cisco consolidated to single endianness between 12.5.1SR1-4 and 12.8.1."
        ),
    },
    "ciscossl_version": {
        "12.5.1SR1-4 rootfs1": "CiscoSSL 1.0.2o.6.2.238-fips",
        "12.5.1SR1-4 rootfs2": "CiscoSSL 6.0-fips-dev xx XXX xxxx (DEVELOPMENT BUILD)",
        "12.8.1 rootfs1":      "CiscoSSL 1.0.2o.6.2.238-fips",
        "12.8.1 rootfs2":      "CiscoSSL 1.0.2o.6.2.238-fips",
        "significance": (
            "The 6.0-fips-dev development build present in 12.5.1SR1-4 PLATFORM_2 was "
            "replaced by the stable 1.0.2o release build in 12.8.1. Both rootfs now run "
            "identical CiscoSSL version. No SSL version upgrade — still 1.0.2o (2018)."
        ),
    },
    "daemon_presence": {
        "12.5.1SR1-4 rootfs1": "secd only",
        "12.5.1SR1-4 rootfs2": "secureapp only",
        "12.8.1 rootfs1":      "secd + secureapp (BOTH present)",
        "12.8.1 rootfs2":      "secureapp only",
        "significance": (
            "rootfs1 12.8.1 gained secureapp (previously rootfs2-only in 12.5.1SR1-4). "
            "PHN-F16 CERT_ANY bypass surface now spans both rootfs in 12.8.1."
        ),
    },
    "edge_gateway": {
        "12.5.1SR1-4 rootfs1": "ABSENT",
        "12.5.1SR1-4 rootfs2": "PRESENT",
        "12.8.1 rootfs1":      "PRESENT",
        "12.8.1 rootfs2":      "PRESENT",
        "significance": (
            "edge_gateway expanded from rootfs2-only to both rootfs in 12.8.1. "
            "edge_gateway links libseccommon.so — PHN-F14 bypass attack surface expanded."
        ),
    },
}

# ─────────────────────────────────────────────────────────
# Security finding persistence summary
# ─────────────────────────────────────────────────────────
FINDING_PERSISTENCE = {
    "PHN-F14": "UNPATCHED — present in 12.5.1SR1-4 and 12.8.1",
    "PHN-F15": "UNPATCHED — identical static debug hash across all versions",
    "PHN-F16": "UNPATCHED — CERT_ANY in secureapp, now in both rootfs variants",
    "note": "Three version upgrades, zero security regression. All bypasses persist.",
}
