"""
Cisco IP Phone 8961 — sebn encrypted firmware analysis
Versions: 9.3.3 (v1), 9.3.1 (v2)
Static analysis: SBN magic, gzip probe, encryption detection, FEXTRA certificate block
"""

FIRMWARE = {
    "model":    "Cisco IP Phone 8961",
    "versions": {
        "v1": {"source": "cmterm-8961.9-3-3-0000-11.zip",  "date": "2012"},
        "v2": {"source": "cmterm-8961.9-3-1-8000-10.zip",  "date": "2011"},
    },
    "form_factor": "Color touchscreen, 5 programmable lines, higher-end 89xx family",
}

# ─────────────────────────────────────────────────────────
# SBN format — sebn encryption confirmed
# ─────────────────────────────────────────────────────────
SEBN_FORMAT = {
    "magic": b"\x01\x00\x02\x01\x01\x02\x00\x02",
    "note": "Same SBN magic as 7945/7942/7906/78xx/89xx — shared container format",

    "encryption_detection": {
        "gzip_decompression": "FAILED — 'invalid distance too far back'",
        "failure_interpretation": (
            "Payload is AES-encrypted. The gzip-like bytes at 0xb523 were part of the "
            "signature block (28KB FEXTRA), not the actual firmware payload. "
            "The encrypted payload looks like random bytes to zlib."
        ),
        "payload_type": "AES_ENCRYPTED — NOT cleartext compressed firmware",
    },

    "fextra_block": {
        "size": 28672,
        "offset": "gzip header FEXTRA field",
        "content": "Certificate/signature block (X.509 chain + HMAC/signature)",
        "note": (
            "28KB FEXTRA is approximately 7 X.509 certificates at ~4KB each. "
            "Likely the Cisco firmware signing chain: root CA → sub-CA → code signing cert. "
            "Presence of FEXTRA block in gzip header is the sebn (Signed/Encrypted BN) marker."
        ),
    },
}

# ─────────────────────────────────────────────────────────
# Static analysis limitations
# ─────────────────────────────────────────────────────────
STATIC_ANALYSIS_LIMITATION = {
    "handyiron_bypass_status": "CANNOT DETERMINE — firmware AES-encrypted",
    "phn_f12_status":          "CANNOT DETERMINE — CVM not extractable",
    "phn_f14_status":          "CANNOT DETERMINE — libseccommon.so not accessible",
    "phn_f15_status":          "CANNOT DETERMINE — etc/passwd not accessible",

    "reason": (
        "Unlike all other 79xx/89xx IP phone firmware variants analyzed, 8961 uses "
        "sebn (Signed/Encrypted BN) with AES payload encryption. Static string analysis "
        "is NOT APPLICABLE — no security strings are accessible without decryption. "
        "Decryption requires the AES key, which is device-specific or provisioned via CAPF."
    ),

    "vs_89xx_other": (
        "8941/8945 SCCP and SIP firmware (also 89xx family) were analyzable — their "
        "payloads decompressed without issue. The sebn encryption appears selectively "
        "applied to 8961-series only, possibly for higher-security deployment contexts."
    ),

    "vs_7940_7960": (
        "7940/7960 P003 format also resisted static analysis (possible encrypted/compressed "
        "130KB blob). Two distinct older platforms with non-standard payload formats."
    ),
}

# ─────────────────────────────────────────────────────────
# Comparison to 8941/8945 (same 89xx family, analyzable)
# ─────────────────────────────────────────────────────────
FAMILY_COMPARISON = {
    "8941_8945": {
        "firmware_format": "Standard gzip-compressed CVM, analyzable",
        "phn_f12":         "CONFIRMED (getHasDtls/getHasSsl in cvm89sccp)",
        "phn_f14":         "CONFIRMED (handyiron bypass in libseccommon.so)",
        "phn_f15":         "CONFIRMED (debug MD5 hash in etc/passwd)",
        "ssl_stack":       "CiscoSSL in libseccommon.so / libsecurity.so",
    },
    "8961": {
        "firmware_format": "sebn AES-encrypted — NOT analyzable via static methods",
        "phn_f12":         "UNKNOWN",
        "phn_f14":         "UNKNOWN",
        "phn_f15":         "UNKNOWN",
        "ssl_stack":       "UNKNOWN",
    },
    "inference": (
        "Given that 8941/8945 (same hardware generation, same firmware version 9.x, "
        "same secd IPC architecture pattern) carry PHN-F12/F14/F15, the same findings "
        "likely apply to 8961. This is inferred from architectural consistency, not "
        "confirmed from 8961-specific static analysis."
    ),
}

# ─────────────────────────────────────────────────────────
# Decryption path (dynamic analysis requirement)
# ─────────────────────────────────────────────────────────
DECRYPTION_PATH = {
    "requirement": "Physical device or emulation environment with key material",
    "approaches": [
        "Boot 8961 firmware in QEMU or real hardware, dump decrypted memory segments",
        "Extract key from CAPF-provisioned certificate store (requires CUCM access)",
        "Differential analysis vs 8941 binary — find equivalent code paths post-decryption",
        "JTAG/UART root shell on physical device to read /proc/pid/maps + dd",
    ],
    "scope": "Out of scope for static RE program — requires dynamic/hardware access",
}
