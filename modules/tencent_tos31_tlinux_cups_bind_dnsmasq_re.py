"""
TencentOS 3.1 (TLinux 3 / RHEL 8-based) — cups-filters, bind9.16, dnsmasq, LibRaw RE
Packages: cups-filters-1.20.0-35.tl3, bind9.16-9.16.23-0.22.tl3,
          dnsmasq-2.79-33.tl3, LibRaw-0.19.5-4.tl3, compat-libtiff3-3.9.4-13.tl3
Source: gdrive:tencent-re/3.1/Updates-srpms/
"""

MODULE_ID = "tencent_tos31_tlinux_cups_bind_dnsmasq_re"
TARGET = "TencentOS 3.1 (TLinux 3)"
BASE = "RHEL 8 / packages tagged .tl3"


# ---------------------------------------------------------------------------
# cups-filters-1.20.0-35.tl3  (TOS 3.1)
# Compare: cups-filters-1.0.35-29.tl2.3 (TOS 2.4)
# ---------------------------------------------------------------------------

FINDING_01 = {
    "id": "F01",
    "package": "cups-filters-1.20.0-35.tl3",
    "cve": "CVE-2023-24805",
    "severity": "HIGH",
    "title": "beh backend: system() shell injection eliminated via fork/execv",
    "patch": "beh-cve2023.patch",
    "description": (
        "backend/beh.c call_backend() constructed a shell command via snprintf "
        "and executed it with system(). The scheme component came from the URI "
        "and filename was passed unquoted at the end of the command string — "
        "either could contain shell metacharacters. system() passes the string "
        "to /bin/sh -c, so special characters in scheme or filename led to "
        "arbitrary command execution at the privilege of the CUPS daemon."
    ),
    "mechanism": {
        "old": (
            'snprintf(cmdline, sizeof(cmdline),\n'
            '         "%s/backend/%s \'%s\' \'%s\' \'%s\' \'%s\' \'%s\' %s",\n'
            '         cups_serverbin, scheme, argv[1..5], filename);\n'
            'retval = system(cmdline) >> 8;'
        ),
        "new": (
            'backend_argv[0..6] = {uri, argv[1..5], filename, NULL};\n'
            'snprintf(backend_path, sizeof(backend_path),\n'
            '         "%s/backend/%s", cups_serverbin, scheme);\n'
            'if ((pid = fork()) == 0)\n'
            '    execv(backend_path, backend_argv);  /* no shell involved */'
        ),
        "note": (
            "execv() does not invoke a shell — the filename array is passed "
            "directly to the OS. Shell metacharacters in any argument are inert. "
            "Also fixes exit-code extraction: WEXITSTATUS/WTERMSIG instead of "
            "the old >>8 shift which silently discarded signal kills."
        ),
    },
}

FINDING_02 = {
    "id": "F02",
    "package": "cups-filters-1.20.0-35.tl3",
    "cve": "CVE-2024-47175",
    "severity": "CRITICAL",
    "title": "ppdCreateFromIPP(): IPP attribute injection into generated PPD blocked",
    "patch": "cups-filters-CVE-2024-47175.patch",
    "description": (
        "TOS 3.1 ships cups-filters 1.20.0, which generates PPD files via "
        "ppdCreateFromIPP() rather than through the cups-browsed PPD-line "
        "stripping path used in TOS 2.4 (1.0.35). The 1.20.0 fix patches "
        "ppdgenerator.c directly: sanitizes printer-make-and-model to PPD-safe "
        "characters before writing it to the file, and gates all URI attribute "
        "writes behind ippValidateAttribute(). "
        "TOS 2.4 approach: strip *cupsFilter/FoomaticRIPCommandLine lines from "
        "browsed PPD (cups-browsed.c). "
        "TOS 3.1 approach: prevent attacker-controlled IPP attributes from "
        "reaching ppdCreateFromIPP() in the first place."
    ),
    "mechanism": {
        "make_model_sanitization": (
            "printer-make-and-model fetched and validated with ippValidateAttribute().\n"
            "Each character checked: if < 0x20, >= 127, or '\"' → truncate.\n"
            "Trailing spaces stripped. Empty result → 'Unknown'."
        ),
        "uri_attr_validation": (
            "printer-more-info, printer-charge-info-uri, printer-strings-uri:\n"
            "All gated: if (attr != NULL && ippValidateAttribute(attr)) { write }\n"
            "Invalid attribute → silently skipped, not written to PPD."
        ),
        "pwg_ppdize_name_hardening": (
            "pwg_ppdize_name(): now rejects input if first char is non-alphanumeric.\n"
            "Inner loop: only copy '_', '.', '-', or isalnum(c). Unknown chars skipped.\n"
            "Prevents keyword injection via crafted IPP choice names."
        ),
        "localization_refactor": (
            "InputSlot/MediaType/OutputBin/StapleLocation/FoldType/PunchMedia "
            "choice names written without human-readable text inline — text moved "
            "to new ppd_put_string() helper that escapes ':' and '<' as <%02X>."
        ),
    },
}

FINDING_03 = {
    "id": "F03",
    "package": "cups-filters-1.20.0-35.tl3",
    "cve": "CVE-2024-47076",
    "severity": "HIGH",
    "title": "ippValidateAttributes() gate before any attribute processing",
    "patch": "0001-cfGetPrinterAttributes5-Validate-response-attributes.patch",
    "description": (
        "cups-browsed.c create_remote_printer_entry() and driverless.c "
        "generate_ppd() both call cupsDoRequest() to fetch printer attributes "
        "from remote IPP server. If the attacker returns an IPP response with "
        "invalid attribute encoding, the previous code passed it to ppdCreateFromIPP() "
        "unchanged. Fix: call ippValidateAttributes(response) immediately after "
        "receiving the response; jump to fail: if validation fails."
    ),
    "patch_sites": [
        "utils/cups-browsed.c — create_remote_printer_entry(): after cupsDoRequest()",
        "utils/driverless.c — generate_ppd(): after cupsDoRequest()",
    ],
    "fix": (
        'if (response && !ippValidateAttributes(response)) {\n'
        '    fprintf(stderr, "The printer %s contains invalid attributes.", ...);\n'
        '    goto fail;\n'
        '}'
    ),
}


# ---------------------------------------------------------------------------
# bind9.16-9.16.23-0.22.tl3
# TOS 3.1 middle generation: 9.16 vs 9.11 (TOS 2.4) vs 9.18 (TOS 4.6)
# ---------------------------------------------------------------------------

FINDING_04 = {
    "id": "F04",
    "package": "bind9.16-9.16.23-0.22.tl3",
    "cve": "CVE-2024-1975",
    "severity": "HIGH",
    "title": "SIG(0) removed from named (backport from 9.18 path)",
    "patch": "bind-9.16-CVE-2024-1975.patch",
    "description": (
        "Identical removal strategy to TOS 2.4 9.11 patch: SIG(0) support deleted "
        "from lib/dns/message.c checksig path. 97 lines removed including the "
        "dns_dnssec_keyfromrdata() call for SIG(0) key reconstruction and the "
        "key-matching loop. lib/ns/client.c adds 7-line early rejection of "
        "SIG(0)-signed updates. Test suite updated: SIG(0) update now expected "
        "to fail (test inverted from 'must succeed' to 'must fail')."
    ),
    "patch_files_changed": [
        "lib/dns/message.c — 97 lines deleted (SIG(0) key fetch + validation)",
        "lib/ns/client.c — 7 lines added (early SIG(0) rejection)",
        "bin/tests/system/tsiggss/tests.sh — test inverted",
        "doc/arm/general.rst, reference.rst, security.rst — SIG(0) marked unsupported",
    ],
}

FINDING_05 = {
    "id": "F05",
    "package": "bind9.16-9.16.23-0.22.tl3",
    "cve": "CVE-2024-1737",
    "severity": "MEDIUM",
    "title": "RRset/rdataset hard caps (compile-time default 100, test builds 5000)",
    "patches": [
        "bind-9.16-CVE-2024-1737.patch",
        "bind-9.16-CVE-2024-1737-records.patch",
        "bind-9.16-CVE-2024-1737-records-test.patch",
        "bind-9.16-CVE-2024-1737-records-test2.patch",
        "bind-9.16-CVE-2024-1737-types.patch",
        "bind-9.16-CVE-2024-1737-types-test.patch",
    ],
    "description": (
        "TOS 3.1 splits the CVE-2024-1737 fix into separate patches for records "
        "(per-RRset) and types (per-owner-name), unlike TOS 2.4's single patch. "
        "Default limits identical: 100 for both. configure.ac sets 5000 in "
        "debug/test builds (ISC_MEM_DEFAULTFILL + ISC_LIST_CHECKINIT mode). "
        "Compile-time override via -DDNS_RDATASET_MAX_RECORDS=N."
    ),
    "constants": {
        "DNS_RDATASET_MAX_RECORDS": 100,
        "DNS_RBTDB_MAX_RTYPES": 100,
        "debug_override": 5000,
    },
    "note": (
        "9.16 backports the upstream 9.18 fix but the -records and -types patches "
        "are distinct cherry-picks (commit c5c4d00 + fdabf4b). "
        "9.11 (TOS 2.4) had a single monolithic patch."
    ),
}

FINDING_06 = {
    "id": "F06",
    "package": "bind9.16-9.16.23-0.22.tl3",
    "cve": "CVE-2023-50387",
    "severity": "HIGH",
    "title": "KeyTrap: DNSSEC exhaustion via crafted DNSKEY/RRSIG overload",
    "patches": [
        "bind-9.16-CVE-2023-50387.patch",
        "bind-9.16-isc_hp-CVE-2023-50387.patch",
    ],
    "description": (
        "Same KeyTrap vulnerability patched independently in both named (bind9.16) "
        "and dnsmasq. In named, the fix limits signature-validation work per query; "
        "isc_hp variant covers an additional HP-specific exploit path. "
        "Both patches required because bind and dnsmasq are separate validators — "
        "a TOS 3.1 host running both needs both patched."
    ),
    "additional_cves_in_package": [
        "CVE-2022-0396 — TKEY resource exhaustion",
        "CVE-2022-2795 — send of large UDP response leading to OOM",
        "CVE-2022-3080 — stale CNAME processing crash",
        "CVE-2022-38177 — memory leak after ECDSA verify failure",
        "CVE-2022-38178 — memory leak after EdDSA verify failure",
        "CVE-2022-3094 — UPDATE flood exhaustion (3-part patch)",
        "CVE-2022-3736 — stale RRSIG serving crash",
        "CVE-2022-3924 — stale-answer-timeout race condition DoS",
        "CVE-2023-2828 — cache-sizing bypass via named-checkconf",
        "CVE-2023-3341 — control channel memory exhaustion",
        "CVE-2023-4408 — DNS message parsing complexity DoS",
        "CVE-2023-5517 — nxdomain-redirect + RFC 1918 PTR crash",
        "CVE-2023-5679 — bad-dnssec-algorithms + synth-from-dnssec crash",
        "CVE-2023-6516 — specific recursive query pattern OOM",
        "CVE-2024-4076 — assert in serve-stale (backport from 9.18 patch)",
    ],
    "cross_version_backport": (
        "Patch207 (bind-9.18-CVE-2024-4076.patch) is explicitly named as a 9.18 "
        "patch applied to the 9.16 package — unusual cross-version backport label "
        "preserved in spec file."
    ),
}


# ---------------------------------------------------------------------------
# dnsmasq-2.79-33.tl3  (new in TOS 3.1 analysis — not covered in TOS 2.4)
# ---------------------------------------------------------------------------

FINDING_07 = {
    "id": "F07",
    "package": "dnsmasq-2.79-33.tl3",
    "cve": "CVE-2023-50387 + CVE-2023-50868",
    "severity": "HIGH",
    "title": "KeyTrap/NSEC3: DNSSEC resource limit architecture redesign",
    "patch": "dnsmasq-2.90-CVE-2023-50387-CVE-2023-50868.patch",
    "description": (
        "dnsmasq's DNSSEC validator had a single DNSSEC_WORK=50 limit (max queries "
        "to validate one question). KeyTrap demonstrated this was insufficient: "
        "cross-product of DNSKEY * RRSIG counts = millions of crypto operations "
        "possible within that query budget. "
        "Fix: replace single limit with four independent resource counters."
    ),
    "old_limit": "DNSSEC_WORK 50",
    "new_limits": {
        "DNSSEC_LIMIT_WORK": 40,
        "DNSSEC_LIMIT_SIG_FAIL": 20,
        "DNSSEC_LIMIT_CRYPTO": 200,
        "DNSSEC_LIMIT_NSEC3_ITERS": 150,
    },
    "new_option": "--dnssec-limits=W,F,C,N (overrides defaults, 0 = keep default)",
    "stat_bitmap_redesign": (
        "STAT_* constants moved from sequential integers (1-9) to high 16-bit flags "
        "(0x10000-0x90000). Low 16 bits now encode failure reason bitmap:\n"
        "  DNSSEC_FAIL_NYV        0x0001  key not yet valid\n"
        "  DNSSEC_FAIL_EXP        0x0002  key expired\n"
        "  DNSSEC_FAIL_INDET      0x0004  indetermined\n"
        "  DNSSEC_FAIL_NOKEYSUP   0x0008  unsupported key algorithm\n"
        "  DNSSEC_FAIL_NOSIG      0x0010  no RRSIGs\n"
        "  DNSSEC_FAIL_NOZONE     0x0020  no Zone bit\n"
        "  DNSSEC_FAIL_NONSEC     0x0040  no NSEC\n"
        "  DNSSEC_FAIL_NODSSUP    0x0080  unsupported DS digest\n"
        "  DNSSEC_FAIL_NOKEY      0x0100  no DNSKEY\n"
        "  DNSSEC_FAIL_NSEC3_ITERS 0x0200  NSEC3 iteration limit exceeded\n"
        "  DNSSEC_FAIL_BADPACKET  0x0400  malformed packet\n"
        "  DNSSEC_FAIL_WORK       0x0800  crypto work limit exceeded\n"
        "STAT_ISEQUAL(a,b) macro masks with 0xffff0000 to compare status class."
    ),
    "ds_algo_optimization": (
        "DS validation changed from O(DS * DNSKEY) to O(DS * digest_types). "
        "digest_types is in single digits vs potentially thousands of DNSKEY records."
    ),
}

FINDING_08 = {
    "id": "F08",
    "package": "dnsmasq-2.79-33.tl3",
    "cve": "CVE-2022-0934",
    "severity": "HIGH",
    "title": "DHCPv6 write-after-free: void* → unsigned char*, pointer → local",
    "patch": "dnsmasq-2.87-CVE-2022-0934.patch",
    "description": (
        "dhcp6_maybe_relay() and dhcp6_no_relay() both received inbuff as void*. "
        "Inside dhcp6_no_relay(), outmsgtypep was a pointer into the output buffer. "
        "When the output buffer was reallocated during packet construction, "
        "outmsgtypep became a dangling pointer. Subsequent write through outmsgtypep "
        "corrupted memory at the old buffer location."
    ),
    "fix": {
        "signature_change": (
            "dhcp6_maybe_relay(state, void *inbuff, ...) → "
            "dhcp6_maybe_relay(state, unsigned char *inbuff, ...)\n"
            "dhcp6_no_relay(state, int msg_type, void *inbuff, ...) → "
            "dhcp6_no_relay(state, int msg_type, unsigned char *inbuff, ...)"
        ),
        "output_type_change": (
            "unsigned char *outmsgtypep  (pointer into mutable output buffer)\n"
            "→  unsigned char outmsgtype  (local variable, copy value in/out)\n"
            "Eliminates stale-pointer write after realloc."
        ),
        "cast_removal": (
            "int msg_type = *((unsigned char *)inbuff)  →  int msg_type = *inbuff\n"
            "(valid after signature change to unsigned char*)"
        ),
    },
    "added_field": "int start_msg added alongside start_opts for message boundary tracking",
}

FINDING_09 = {
    "id": "F09",
    "package": "dnsmasq-2.79-33.tl3",
    "cve": "CVE-2021-3448",
    "severity": "MEDIUM",
    "title": "Fixed source port with bound interface: forced to random port",
    "patch": "dnsmasq-2.85-CVE-2021-3448.patch",
    "description": (
        "server=8.8.8.8@1.2.3.4 and server=8.8.8.8@eth0 used a single bound socket "
        "with a fixed (non-random) source port. Fixed source port is a prerequisite "
        "for off-path DNS cache poisoning: attacker can predict the port and forge "
        "responses without needing to monitor traffic. "
        "Fix: use random source ports for interface/source-bound servers unless "
        "an explicit port is configured (server=...@source#PORT)."
    ),
    "scope": (
        "Random ports now used for @interface and @source forms. "
        "server=...@source#port still uses the fixed configured port — "
        "operator explicitly accepted the security tradeoff."
    ),
    "side_effect": (
        "Non-local source address or non-existent interface errors downgraded "
        "from fatal (start-up abort) to runtime-logged. "
        "This is necessary because binding is now deferred to query time."
    ),
}

FINDING_10 = {
    "id": "F10",
    "package": "dnsmasq-2.79-33.tl3",
    "cve": "CVE-2020-25681 / CVE-2020-25684 / CVE-2020-25685 / CVE-2020-25686",
    "severity": "HIGH",
    "title": "DNSpooq cluster: DNSSEC heap overflow + response matching hardening",
    "patches": [
        "dnsmasq-2.79-CVE-2020-25681.patch",
        "dnsmasq-2.79-CVE-2020-25684.patch",
        "dnsmasq-2.79-CVE-2020-25685.patch",
        "dnsmasq-2.79-CVE-2020-25686.patch",
        "dnsmasq-2.79-CVE-2020-25686-2.patch",
    ],
    "cve_map": {
        "CVE-2020-25681": "DNSSEC validation heap buffer overflow (CVSS 8.1)",
        "CVE-2020-25684": "Response accepted on wrong socket (source-port oracle for poisoning)",
        "CVE-2020-25685": "Query ID only, no question-name hash verification",
        "CVE-2020-25686": "Wildcard NSEC record handling error in DNSSEC",
    },
}


# ---------------------------------------------------------------------------
# LibRaw-0.19.5-4.tl3
# TOS 3.1 base: 0.19.5; TOS 4.6 has 0.21.2 (newer, different CVE set)
# ---------------------------------------------------------------------------

FINDING_11 = {
    "id": "F11",
    "package": "LibRaw-0.19.5-4.tl3",
    "cve": "CVE-2021-32142",
    "severity": "MEDIUM",
    "title": "gets() sz<1 guard missing in all three datastream implementations",
    "patch": "LibRaw-CVE-2021-32142.patch",
    "description": (
        "LibRaw_file_datastream::gets(), LibRaw_buffer_datastream::gets(), and "
        "LibRaw_bigfile_datastream::gets() all lacked a check for sz<1 before use. "
        "A caller passing sz=0 (possible via crafted RAW metadata triggering a "
        "negative-size calculation that wraps to a large unsigned value, then "
        "narrowed to int) caused heap buffer overflow."
    ),
    "fix": "if(sz<1) return NULL; added at entry of all three gets() implementations",
    "affected_files": [
        "src/libraw_datastream.cpp — LibRaw_file_datastream::gets (line ~175)",
        "src/libraw_datastream.cpp — LibRaw_buffer_datastream::gets (line ~398)",
        "src/libraw_datastream.cpp — LibRaw_bigfile_datastream::gets (line ~594)",
    ],
}

FINDING_12 = {
    "id": "F12",
    "package": "LibRaw-0.19.5-4.tl3",
    "cve": "CVE-2020-24870",
    "severity": "MEDIUM",
    "title": "DNG color calibration loop: colors unbounded, stack array cc[4][4] overflowed",
    "patch": "LibRaw-CVE-2020-24870.patch",
    "description": (
        "internal/dcraw_common.cpp processes DNG color calibration matrices. "
        "Three loop sites iterated `for(i=0; i<colors; i++)` where colors came "
        "from the DNG file header. Stack array cc[4][4] allocated for 4 colors max. "
        "DNG files with colors>4 triggered out-of-bounds stack write."
    ),
    "fix": "for(int i=0; i<colors; i++) → for(int i=0; i<colors && i<4; i++) (3 sites)",
    "also_fixed": "cam_xyz inner loop: j<colors → j<colors && j<4",
}

FINDING_13 = {
    "id": "F13",
    "package": "LibRaw-0.19.5-4.tl3",
    "cve": "CVE-2020-15503",
    "severity": "MEDIUM",
    "title": "Thumbnail size limits: LIBRAW_MAX_THUMBNAIL_MB cap + minimum 64B check",
    "patch": "LibRaw-CVE-2020-15503.patch",
    "description": (
        "dcraw_make_mem_thumb() allocated T.tlength bytes from heap with no upper "
        "bound. A crafted RAW file could specify a thumbnail length of multiple "
        "gigabytes, causing OOM or massive allocation. "
        "kodak_thumb_loader() multiplied T.theight * T.twidth with no overflow check."
    ),
    "fix": {
        "new_constant": "LIBRAW_MAX_THUMBNAIL_MB = 512 (default, overridable at compile time)",
        "dcraw_make_mem_thumb": (
            "if (T.tlength < 64u) → EINVAL\n"
            "if (INT64(T.tlength) > 1024ULL * 1024ULL * LIBRAW_MAX_THUMBNAIL_MB) → LIBRAW_TOO_BIG"
        ),
        "kodak_thumb_loader": (
            "if (INT64(T.theight) * INT64(T.twidth) > 1024ULL * 1024ULL * LIBRAW_MAX_THUMBNAIL_MB)"
            " → LIBRAW_EXCEPTION_IO_CORRUPT\n"
            "if (INT64(T.theight) * INT64(T.twidth) < 64ULL) → LIBRAW_EXCEPTION_IO_CORRUPT"
        ),
    },
}


# ---------------------------------------------------------------------------
# compat-libtiff3-3.9.4-13.tl3
# Same ancient base as TOS 2.4 (-12.tl2), different revision suffix
# ---------------------------------------------------------------------------

FINDING_14 = {
    "id": "F14",
    "package": "compat-libtiff3-3.9.4-13.tl3",
    "cve": "N/A",
    "severity": "NOTE",
    "title": "Compat libtiff3 patch divergence: TOS 3.1 missing TOS 2.4 security backports",
    "description": (
        "compat-libtiff3 3.9.4 is an ancient ABI-compat shim. "
        "TOS 3.1 (-13.tl3) and TOS 2.4 (-12.tl2.2) share the same base version. "
        "TOS 3.1's patch set stops at CVE-2018-7456 (null pointer deref). "
        "TOS 2.4's .2 rebuild added two Tencent-specific security patches not present "
        "in TOS 3.1: CVE-2025-9900 (Write-What-Where via raster pointer arithmetic) "
        "and CVE-2026-4775 (int32 overflow in YCbCr tile functions). "
        "TOS 3.1 compat-libtiff3 consumers remain exposed to those vulnerabilities "
        "unless updated via a separate rebuild."
    ),
    "tos31_highest_cve": "CVE-2018-7456 (null pointer deref in TIFFPrintDirectory)",
    "missing_vs_tos24": [
        "CVE-2025-9900: TIFFReadRGBAImageOriented raster+delta pointer wrap",
        "CVE-2026-4775: int32 → int64 in putcontig8bitYCbCr{44,42,22,12}tile",
    ],
}


# ---------------------------------------------------------------------------
# Cross-version observations (TOS 2.4 vs 3.1 vs 4.6)
# ---------------------------------------------------------------------------

CROSS_VERSION = {
    "cups_filters_approach_divergence": (
        "TOS 2.4 (1.0.35): patches cups-browsed.c to strip *cupsFilter/FoomaticRIPCommandLine "
        "lines from the browsed PPD at write time.\n"
        "TOS 3.1 (1.20.0): patches ppdgenerator.c to sanitize IPP attributes before PPD "
        "generation; uses ippValidateAttributes() as a gate before any attribute access.\n"
        "Different attack surfaces: 1.0.35 fix addresses line-level PPD injection; "
        "1.20.0 fix addresses attribute-level IPP injection during driverless PPD synthesis."
    ),
    "bind_generation_matrix": {
        "TOS 2.4 (RHEL 7)": "bind-9.11.4-26.P2.tl2.19 — CVE-2024-1975, CVE-2024-1737, CVE-2024-11187",
        "TOS 3.1 (RHEL 8)": "bind9.16-9.16.23-0.22.tl3 — adds 2022-2023 CVE cluster + CVE-2024-4076 from 9.18",
        "TOS 4.6 (RHEL 9)": "bind-9.18.21 — native 9.18 mainline",
    },
    "dnsmasq_new_in_tos31": (
        "dnsmasq not present in TOS 2.4 survey packages. "
        "TOS 3.1 ships 2.79 with full DNSpooq + KeyTrap patch series. "
        "Key security architecture change: KeyTrap introduced multi-dimensional "
        "resource limits replacing the previous single DNSSEC_WORK counter."
    ),
    "libraw_generational_gap": (
        "TOS 3.1: LibRaw 0.19.5 (3 CVE patches: 2020-2021 vintage).\n"
        "TOS 4.6: LibRaw 0.21.2 (different and newer CVE set — CVE-2023-1729, etc.).\n"
        "No version continuity between 0.19.x and 0.21.x patch sets — different bugs."
    ),
}

FINDINGS = [
    FINDING_01, FINDING_02, FINDING_03,
    FINDING_04, FINDING_05, FINDING_06,
    FINDING_07, FINDING_08, FINDING_09, FINDING_10,
    FINDING_11, FINDING_12, FINDING_13,
    FINDING_14,
]
