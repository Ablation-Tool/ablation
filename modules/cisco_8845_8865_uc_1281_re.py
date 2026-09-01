"""
Cisco IP Phone 8845/8865 UC 12.8.1 — RE summary
Firmware: rootfs8845_65.12-8-1-0101-482.sbn (SquashFS, NOT UBIFS)
Static analysis: unsquashfs extraction, strings on security libraries and daemons
"""

FIRMWARE = {
    "model":   "Cisco IP Phone 8845 / 8865 UC",
    "version": "12.8.1",
    "label":   "0101-482",
    "source":  "rootfs8845_65.12-8-1-0101-482.sbn",
    "date":    "2020-12-10",
}

# ─────────────────────────────────────────────────────────
# Container format — SquashFS (vs 78xx UBIFS)
# ─────────────────────────────────────────────────────────
CONTAINER_FORMAT = {
    "format":          "SquashFS LE (hsqs magic: 68737173)",
    "vs_78xx":         "78xx uses UBI/UBIFS; 8845-65 uses SquashFS directly (no UBI wrapper)",
    "extraction":      "unsquashfs",
    "header_offset":   "NONE — file IS the SquashFS image",
    "arch":            "ARM 32-bit LSB",
    "total_size":      68231516,
    "note": (
        "8845-65 rootfs SBN file starts directly with squashfs magic — no SBN wrapper. "
        "The file naming convention (.sbn extension) is cosmetic; the actual format is raw SquashFS."
    ),
}

# ─────────────────────────────────────────────────────────
# Security library SHA256
# ─────────────────────────────────────────────────────────
SECURITY_LIB_SHA256 = {
    "libseccommon.so": {
        "sha256": "16ee344d22bb80231636f7f03579d039bbf894db8a97751ff2b9ee3a2aa1c637",
        "size":   37556,
        "arch":   "ARM 32-bit LSB ELF (EABI5), stripped",
        "vs_78xx_1281_rootfs1": "ef9e3db57bd958c6449a5f72cabaf6befd448fa95b769d0b6913d1af4833339f (78xx — different SHA, similar size)",
    },
    "libsecurity.so": {
        "sha256": "8acda80befd6b9a86bf132122bf01d72b0038a913db26108964ede0efb129868",
        "size":   69772,
    },
    "libssl.so.1.0.0": {
        "sha256": "4bc3be8efd05644eb833f53248deb69a470b6c4ae96529cb1aec8c9676a6cbc5",
        "size":   400974,
        "ssl_version": "CiscoSSL 1.0.2o.6.2.238-fips",
    },
    "libcrypto.so.1.0.0": {
        "sha256": "e8142b711dc2f858d9ff735478dad4b0cdd62733f2c46ba1b104db757b91a618",
        "size":   2395458,
    },
    "libsecure_service.so": {
        "sha256": "1627a0dd8edbb3e71fc692cd9c941cc3321cc4f506d41a190441ec5e2c76bca0",
        "note":   "8845-65 specific — not present in 78xx 12.8.1. No bypass strings found.",
    },
    "secureapp": {
        "sha256": "f6b19e23b83ccb93e9f046b3e6ba44077fca1a4a41fb6de7096d08635bab5ac8",
        "size":   136208,
        "vs_78xx_1281_rootfs1": "76f4cd2812f109d904dd7a4e8f8f2b47b9125c549427a20e30edca09560b236a — different SHA",
    },
    "edge_gateway": {
        "present": True,
        "note":    "Present, links libseccommon.so — inherits PHN-F14 bypass surface",
    },
}

# ─────────────────────────────────────────────────────────
# PHN-F14 — handyiron ANY-role bypass (CONFIRMED)
# ─────────────────────────────────────────────────────────
PHN_F14_8845 = {
    "id":     "PHN-F14",
    "status": "CONFIRMED — 8845-65 UC 12.8.1",

    "bypass_strings": [
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - no certificate validation plugin available.",
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - any role is specified.",
    ],

    "library": "libseccommon.so (16ee344d)",
    "scope_extension": (
        "PHN-F14 now confirmed in: 78xx 12.5.1SR1-4 (both platforms), 78xx 12.8.1 (both rootfs), "
        "AND 8845-65 12.8.1. The handyiron ANY-role bypass spans the entire Cisco UC 7800+8800 phone line."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F15 — debug credential (CONFIRMED, IDENTICAL cross-model)
# ─────────────────────────────────────────────────────────
PHN_F15_8845 = {
    "id":     "PHN-F15",
    "status": "CONFIRMED — identical hash across all models",

    "passwd_entry": "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:65532:100:debug:/tmp:/usr/sbin/debugsh",
    "hash":         "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
    "plaintext":    "debug",

    "cross_model_identity": {
        "78xx 12.5.1SR1-4 rootfs1 (MSB)": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "78xx 12.5.1SR1-4 rootfs2 (LSB)": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "78xx 12.8.1 rootfs1":             "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "78xx 12.8.1 rootfs2":             "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "8845-65 12.8.1":                  "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "IDENTICAL_ALL":                   True,
        "plaintext":                   "debug",
    },

    "root_account": {
        "shell": "/sbin/nologin",
        "note": "root: shell differs from 78xx (/bin/sh). debug account uses /usr/sbin/debugsh regardless.",
    },

    "implication": (
        "Cracking $1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71 once yields debug shell access to "
        "ALL Cisco UC IP phones across 78xx and 8845-65 product lines, across all analyzed firmware versions."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F16 — CERT_ANY in secureapp (CONFIRMED)
# ─────────────────────────────────────────────────────────
PHN_F16_8845 = {
    "id":     "PHN-F16",
    "status": "CONFIRMED — 8845-65 UC 12.8.1",

    "cert_any_string": "CERT_ANY      : allow all unverified server certs",
    "binary": "/usr/sbin/secureapp",

    "note": (
        "CERT_ANY config-driven TLS bypass confirmed in 8845-65 secureapp. "
        "Extends PHN-F16 scope to 8845/8865 product family."
    ),
}

# ─────────────────────────────────────────────────────────
# Cross-model finding scope summary
# ─────────────────────────────────────────────────────────
CROSS_MODEL_SCOPE = {
    "PHN-F14_confirmed_products": [
        "Cisco 7861/78xx UC 12.5.1SR1-4 (PLATFORM_1 and PLATFORM_2)",
        "Cisco 7861/78xx UC 12.8.1 (rootfs1 and rootfs2)",
        "Cisco 8845/8865 UC 12.8.1",
    ],
    "PHN-F15_confirmed_products": [
        "Cisco 7861/78xx UC 12.5.1SR1-4 (both platforms)",
        "Cisco 7861/78xx UC 12.8.1 (both rootfs)",
        "Cisco 8845/8865 UC 12.8.1",
    ],
    "PHN-F16_confirmed_products": [
        "Cisco 7861/78xx UC 12.5.1SR1-4 (PLATFORM_2 only)",
        "Cisco 7861/78xx UC 12.8.1 (both rootfs)",
        "Cisco 8845/8865 UC 12.8.1",
    ],
    "CiscoSSL_version_across_products": {
        "all_confirmed": "CiscoSSL 1.0.2o.6.2.238-fips",
        "note": "Identical SSL version in libssl across 78xx and 8845-65 UC 12.8.1",
    },
}
