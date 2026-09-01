"""
Cisco IP Phone 78xx/8845-65 MPP 11.3.3 — RE summary and UC vs MPP delta
Compared to UC 12.8.1 baseline
Static analysis: ubireader/unsquashfs extraction, strings on security libraries
"""

FIRMWARE = {
    "78xx_MPP": {
        "source":  "rootfs2.78xx.11-3-3MPP0103-381.sbn",
        "version": "MPP 11.3.3 (0103-381)",
        "date":    "2021-08-12",
        "format":  "UBI/UBIFS (SBN header 0x15c, UBI# magic)",
        "arch":    "ARM 32-bit LSB",
    },
    "8845_MPP": {
        "source":  "rootfs8845_65.11-3-3MPP0103-381.sbn",
        "version": "MPP 11.3.3 (0103-381)",
        "date":    "2021-08-12",
        "format":  "SquashFS LE (hsqs magic — no SBN wrapper)",
        "arch":    "ARM 32-bit",
    },
    "MPP_note": (
        "MPP (Multiplatform Phones) firmware targets third-party PBX (Asterisk/FreePBX/BroadWorks). "
        "Different codebase layer from UC (CUCM-targeted) firmware. Both share the handyiron "
        "TLS library (libseccommon.so) but differ in OS hardening choices."
    ),
}

# ─────────────────────────────────────────────────────────
# Security library SHA256 — MPP variants
# ─────────────────────────────────────────────────────────
SECURITY_LIB_SHA256 = {
    "78xx_MPP_libseccommon.so": {
        "sha256": "738f2cac2aef974c497d998c5d9923412ee191d904cd39c4b9f0ac4cdbc83c29",
        "size":   30812,
        "note":   "Smaller than UC (37556-37616B) — possibly stripped or different compilation",
    },
    "78xx_MPP_libsecurity.so": {
        "sha256": "7a87fe149bea998c6e4c0c71cb2a3d3ea6e30d73cb96d45ad66a8896a0b3ab80",
        "size":   65552,
    },
    "78xx_MPP_libssl.so.1.0.0": {
        "sha256": "43597e170307cd52fb1215c7f1ef1aeaf44088dc36b6b6709ccc6cb117398003",
        "size":   354649,
        "ssl_version": "CiscoSSL-1.0.1c.3.0-fips",
    },
    "8845_MPP_libseccommon.so": {
        "sha256": "8388496cd13d250fe286f2fe5681646095436c68e9412b9891a77828bdcc0f6a",
        "size":   31332,
    },
    "8845_MPP_libssl.so.1.1": {
        "ssl_version": "CiscoSSL 1.1.1d.7.1.113",
        "note":        "OpenSSL 1.1.1-based — significantly newer than UC 1.0.2o",
    },
}

# ─────────────────────────────────────────────────────────
# CiscoSSL version taxonomy across UC and MPP
# ─────────────────────────────────────────────────────────
CISCOSSL_VERSION_TAXONOMY = {
    "78xx UC 12.5.1SR1-4 P1": "CiscoSSL 1.0.2o.6.2.238-fips",
    "78xx UC 12.5.1SR1-4 P2": "CiscoSSL 6.0-fips-dev (dev build, unstamped)",
    "78xx UC 12.8.1 rootfs1":  "CiscoSSL 1.0.2o.6.2.238-fips",
    "78xx UC 12.8.1 rootfs2":  "CiscoSSL 1.0.2o.6.2.238-fips",
    "8845-65 UC 12.8.1":       "CiscoSSL 1.0.2o.6.2.238-fips",
    "78xx MPP 11.3.3":         "CiscoSSL-1.0.1c.3.0-fips (OLDER than UC 1.0.2o!)",
    "8845-65 MPP 11.3.3":      "CiscoSSL 1.1.1d.7.1.113 (NEWER than UC 1.0.2o)",
    "note": (
        "78xx MPP uses an older CiscoSSL (1.0.1c) than UC (1.0.2o). "
        "8845 MPP uses a newer CiscoSSL (1.1.1d) than UC (1.0.2o). "
        "No consistent SSL version update policy across product lines."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F14 — handyiron bypass (CONFIRMED, MPP and UC)
# ─────────────────────────────────────────────────────────
PHN_F14_MPP = {
    "id":     "PHN-F14",
    "status": "CONFIRMED in 78xx MPP 11.3.3 and 8845-65 MPP 11.3.3",

    "bypass_strings_both": [
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - no certificate validation plugin available.",
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - any role is specified.",
    ],

    "full_scope": [
        "78xx UC 12.5.1SR1-4 (PLATFORM_1 and PLATFORM_2)",
        "78xx UC 12.8.1 (both rootfs)",
        "8845-65 UC 12.8.1",
        "78xx MPP 11.3.3",
        "8845-65 MPP 11.3.3",
    ],

    "note": (
        "PHN-F14 handyiron bypass is present in BOTH UC and MPP firmware. "
        "The bypass is in libseccommon.so — a shared library that ships identically "
        "across both firmware families. CiscoSSL version differs, handyiron code is shared."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F15 — debug credential (UC only, NOT in MPP)
# ─────────────────────────────────────────────────────────
PHN_F15_UC_ONLY = {
    "id":     "PHN-F15",
    "title":  "Debug Credential — UC firmware only",

    "UC_status": {
        "passwd_entry": "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:65532:100:debug:/tmp:/usr/sbin/debugsh",
        "shell":        "/usr/sbin/debugsh (ACTIVE)",
        "present_in":   "78xx UC 12.5.1SR1-4, 78xx UC 12.8.1, 8845-65 UC 12.8.1",
    },

    "MPP_status": {
        "passwd_entry_78xx":   "debug:*:65532:100:debug:/tmp:/bin/false",
        "passwd_entry_8845":   "debug:*:65532:100:debug:/tmp:/bin/false",
        "shell":               "/bin/false (DISABLED)",
        "hash":                "* (locked — no hash to crack)",
        "REMEDIATED_IN_MPP":   True,
    },

    "significance": (
        "PHN-F15 is SPECIFIC TO UC FIRMWARE. MPP ships with the debug account disabled "
        "(/bin/false shell, locked password). This is the clearest security delta between "
        "UC and MPP: UC deliberately maintains an active debug shell with a static crackable "
        "credential for service access; MPP disables it."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F16 — CERT_ANY (CONFIRMED in both UC and MPP)
# ─────────────────────────────────────────────────────────
PHN_F16_MPP = {
    "id":     "PHN-F16",
    "status": "CONFIRMED in 78xx MPP 11.3.3 and 8845-65 MPP 11.3.3",
    "cert_any_string": "CERT_ANY      : allow all unverified server certs",
    "full_scope": [
        "78xx UC 12.5.1SR1-4 rootfs2 (PLATFORM_2)",
        "78xx UC 12.8.1 (both rootfs)",
        "8845-65 UC 12.8.1",
        "78xx MPP 11.3.3",
        "8845-65 MPP 11.3.3",
    ],
}

# ─────────────────────────────────────────────────────────
# UC vs MPP security delta summary
# ─────────────────────────────────────────────────────────
UC_VS_MPP_DELTA = {
    "PHN-F14 handyiron bypass":       "BOTH UC and MPP — shared libseccommon.so code path",
    "PHN-F15 debug credential":       "UC ONLY — MPP disabled the debug account",
    "PHN-F16 CERT_ANY":               "BOTH UC and MPP — shared secureapp code path",
    "CiscoSSL version":               "Differs per product (1.0.1c / 1.0.2o / 1.1.1d)",
    "OS hardening":                   "MPP stricter (debug disabled, root /bin/false); UC looser",

    "architectural_conclusion": (
        "The handyiron bypass code is shared between UC and MPP via libseccommon.so. "
        "Cisco's OS hardening choices (disabling debug in MPP) do not address the "
        "library-level TLS bypass — they are parallel and independent security decisions. "
        "An attacker exploiting PHN-F14 doesn't need the debug shell."
    ),
}
