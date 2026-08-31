"""
Cisco IOS Switch/Router firmware reverse engineering module.
Target: /media/cowboy/research/Cisco-Voice-01/
Device families: Catalyst 2960/2960L/2960X, 3560/3560C/3560CX/3560E, 3750/3750E,
                 3900 ISR G2, Catalyst 3850 (IOS-XE), Catalyst 4500E (IOS-XE)
Objective: Locate Cisco proprietary voice engine (CPVE) cross-platform;
           surface TLS/DTLS fingerprint bypass equivalents to PHN-F01 / JAB-F13.
"""

# ---- Firmware family inventory ----

FIRMWARE_FAMILIES = {
    "c2960l": {
        "models":    ["Catalyst 2960-L"],
        "versions":  ["15.2(7)E0a", "15.2(7)E2"],
        "format":    "TAR (direct FS access for E0a) + compressed binary",
        "arch":      "MIPS (inferred from IOS naming)",
        "container": "TAR (2960L E0a) — directly extractable",
        "note":      "c2960l-universalk9-tar.152-7.E0a.tar: contains html/odm/cryptoTrustPoints.odm",
    },
    "c2960x": {
        "models":    ["Catalyst 2960-X"],
        "versions":  ["15.2(7)E2"],
        "format":    "MZIP (Cisco proprietary compression) — opaque",
        "arch":      "MIPS",
        "container": "MZIP — custom Cisco LZW, zlib/gzip do not apply",
    },
    "c3560": {
        "models":    ["Catalyst 3560", "Catalyst 3560C"],
        "versions":  ["12.2(55)SE10", "15.0(2)SE7", "15.2(4)E5", "15.2(7)E2", "15.2(7)E9"],
        "format":    "MZIP",
        "arch":      "MIPS",
        "container": "MZIP — not decompressable with standard tools",
        "mzip_magic": b"MZIP",
    },
    "c3750": {
        "models":    ["Catalyst 3750", "Catalyst 3750E"],
        "versions":  ["12.2(55)SE10-12", "15.0(2)SE7-9", "15.2(2-4)E"],
        "format":    "MZIP",
        "arch":      "MIPS",
        "container": "MZIP",
    },
    "c3900": {
        "models":    ["ISR G2 3925", "ISR G2 3945"],
        "versions":  ["15.4(3)M (SPA)", "15.5(1)T (SPA)"],
        "format":    "ELF + Cisco proprietary compression",
        "arch":      "PowerPC (confirmed: stwu/mflr instructions at PT_LOAD start)",
        "elf_machine": 0x00c3,
        "pt_load_offset": 0x144,
        "pt_load_filesz": 0x12379057,
        "compressed_start": 0x8000,
        "compressed_entropy": 7.93,
        "container": "ELF wrapper + Cisco-proprietary compressed payload (no zlib/lzma header)",
        "notable_strings": ["cpveJ", "oCME"],
        "cpve_note": (
            "String 'cpveJ' found in c3900 IOS 15.4(3)M at raw binary search. "
            "Context: high-entropy compressed region — likely coincidental ASCII in compressed stream, "
            "not a confirmed CPVE instance. Full analysis requires decompression of Cisco-proprietary payload."
        ),
    },
    "cat3k": {
        "models":    ["Catalyst 3850"],
        "versions":  ["IOS-XE 16.12.03a", "IOS-XE 3.7.5.E"],
        "format":    "IOSXE2.0 multi-package SPA bundle",
        "arch":      "MIPS64 (mips64, rp_super)",
        "container": "IOSXE2.0 header + sub-packages (rpbase/rpcore/srdriver/webui/guestshell)",
        "packages": {
            "rpbase":    {"offset": 0x320,      "content": "initramfs (boot minimal FS)"},
            "srdriver":  {"offset": 0x1f4dabc,  "content": "SR driver"},
            "webui":     {"offset": 0x227753c,  "content": "Web UI (ewlc JS, ios_config_db_js)"},
            "rpcore":    {"offset": 0x385dfb8,  "content": "IOS-XE IOSD, security stack, main runtime"},
            "guestshell":{"offset": 0x1b62f230, "content": "Docker container runtime"},
        },
        "initramfs": {
            "gzip_offset": 0x438af0,
            "fname":        "initramfs.mips64.cat3k_caa.ramfs.cpio",
            "size_compressed": None,
            "size_decompressed": 75893760,
            "cpio_magic": "070701",
            "kernel_version": "4.9.187",
            "glibc_version": "2.23",
            "extracted_at": "/scratchpad/cat3k/cat3k_fs/",
        },
        "initramfs_libs": {
            "libcrypto_so": "usr/lib64/libcrypto.so.1.0.0",
            "libmaroon_so": "usr/lib64/libmaroon.so (Cisco proprietary, stripped)",
            "libosc_so":    "usr/lib64/libosc.so (Cisco proprietary, stripped)",
            "libcodesign_pd_so": "usr/binos/lib64/libcodesign_pd.so",
            "no_libssl":    "libssl absent from initramfs — security in rpcore package",
            "no_voice_engine": "No voice/CPVE/DSP engine in initramfs — feature packages in rpcore",
        },
        "ewlc": {
            "detected": True,
            "evidence": [
                "ewlc_rogued_common_js.js at 0x34d1d2f",
                "ewlc_green_oper_emul_db_js.js at 0x35ccf4b",
                "ewlc_green_config_db_js.js at 0x3601e63",
                "ewlc_green_oper_alt_db_js.js at 0x3614b1d",
            ],
            "significance": (
                "Catalyst 3850 IOS-XE 16.12 includes the Embedded Wireless LAN Controller (EWLC). "
                "EWLC manages CAPWAP/DTLS tunnels to APs and processes VoWLAN traffic. "
                "This creates a DTLS attack surface separate from the phone-side trust chain."
            ),
            "capwap_dtls": (
                "CAPWAP control channel uses DTLS (RFC 5415). "
                "If the EWLC's DTLS implementation shares code with CPVE, PHN-F01 / JAB-F13 "
                "bypass patterns may apply. rpcore package (381MB) contains the DTLS implementation "
                "but is not directly decompressable."
            ),
        },
        "cpve_evidence": [
            "$cpve at 0x1830b359 (context: compressed stream, not confirmed standalone string)",
            "CPVE at 0x9d236fd (context: compressed stream, coincidental ASCII)",
        ],
        "openssl_in_initramfs": "1.0.0 (libcrypto.so.1.0.0 — same SONAME as 894x but different actual version)",
    },
    "cat4500e": {
        "models":    ["Catalyst 4500E"],
        "versions":  ["IOS-XE 3.9.0.E"],
        "format":    ".NOVA container",
        "arch":      "PowerPC (confirmed from header)",
        "container": "NOVA magic header, powerpc platform, cat4500e-universalk9",
        "nova_magic": b".NOVA",
        "note":      "Not analyzed further — requires NOVA-specific decompressor",
    },
}

# ---- Format analysis ----

FORMAT_ANALYSIS = {
    "MZIP": {
        "magic":    b"MZIP",
        "full_name": "MIPS ZIP — Cisco IOS proprietary compression container",
        "entropy_from_offset_0": True,
        "extractable": False,
        "known_tools": "No open-source MZIP decompressor confirmed available",
        "attack_vector": (
            "Cannot extract MZIP contents with standard tools (zlib, lzma, gzip all fail). "
            "Requires Cisco-proprietary decompressor or hardware execution (GNS3/emulation). "
            "Strings on raw binary yield near-zero useful results."
        ),
    },
    "IOSXE2_0": {
        "magic":    b".IOSXE2.0",
        "full_name": "Cisco IOS-XE 2.0 multi-package SPA bundle",
        "extractable": "partial — initramfs sub-package is gzip+cpio, extractable",
        "sub_package_format": "Feature packages (rpcore etc.) appear to use additional compression — not directly decompressable",
        "known_tools": "jefferson (for JFFS2); cpio for initramfs; standard gzip for outer wrapper",
    },
    "NOVA": {
        "magic":    b".NOVA",
        "full_name": "Cisco NovA IOS-XE PowerPC container",
        "extractable": False,
        "note": "PowerPC-based Catalyst 4500E — requires NOVA-aware decompressor",
    },
}

# ---- Cross-platform CPVE tracking ----

CPVE_CROSS_PLATFORM = {
    "confirmed": {
        "Jabber Android": {
            "finding": "JAB-F13",
            "binary":  "libcpve.so",
            "bypass":  "disableFingerprintVerification flag — strongest bypass; no time-sync gate",
        },
        "Cisco 8845 MPP": {
            "finding": "PHN-F01",
            "binary":  "libhstls.so (BypassTruststore vtable)",
            "bypass":  "NTP-unsync gate + BypassTruststore always-returns-1 verify fn",
        },
    },
    "candidate_inaccessible": {
        "c3900 ISR 15.4M": {
            "evidence":  "String 'cpveJ' in compressed payload",
            "confidence": "LOW — coincidental ASCII in compressed stream",
            "blocker":   "Cisco-proprietary compression format (not zlib/lzma)",
        },
        "cat3k IOS-XE 16.12": {
            "evidence":  "'$cpve' and 'CPVE' in SPA bundle, 'ewlc_*' wireless controller",
            "confidence": "LOW — both in compressed regions",
            "ewlc_angle": "EWLC CAPWAP/DTLS may use CPVE or shared code — rpcore package needed",
            "blocker":   "rpcore sub-package not directly decompressable",
        },
    },
    "next_steps": [
        "Boot c3900 in GNS3/QEMU emulation → memory dump → full CPVE analysis",
        "cat3k: mount ROMMON or use IOS-XE sub-package extraction tooling to access rpcore",
        "2960L TAR: extract html/odm/cryptoTrustPoints.odm → inspect PKI/trust ODM model",
        "CAPWAP DTLS: active probe against live cat3k EWLC for fingerprint bypass surface",
    ],
}

# ---- 2960L TAR: directly extractable component ----

C2960L_TAR_ANALYSIS = {
    "file":       "c2960l-universalk9-tar.152-7.E0a.tar",
    "extractable": True,
    "notable_file": "c2960l-universalk9-mz.152-7.E0a/html/odm/cryptoTrustPoints.odm",
    "odm_significance": (
        "The cryptoTrustPoints.odm file is the web UI's ODM (Object Data Model) for crypto trust point management. "
        "Cisco IOS trust points are where CA certs are stored. This ODM defines the web UI for managing "
        "TLS/HTTPS certificates, CAPF enrollment, and PKI trustpoints. "
        "Attack surface: if the web UI's trust point ODM is exploitable (CSRF, injection), "
        "an attacker can manipulate the phone's or switch's trust anchor state."
    ),
}
