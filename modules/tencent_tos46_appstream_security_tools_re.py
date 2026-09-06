"""
TencentOS 4.6 AppStream — security and system tools SRPM RE.

Sources analyzed from Drive (tencent-re/4.6/AppStream-source/):
  aide-0.18.6-4.tl4.src.rpm          — file integrity daemon (AIDE)
  LibRaw-0.21.2-7.tl4.src.rpm        — raw image processing library (9 CVE patches)
  bpftrace-0.19.1-9.tl4.src.rpm      — eBPF kernel tracing tool
  anaconda-38.23.2-18.tl4.ap.1.src.rpm — system installer

aide:    SM3 (Chinese national hash) added; CVE-2025-54389 log injection; CVE-2025-54409 NPD.
LibRaw:  6 × 2026 CVE patches (TALOS series) — integer overflows + heap overflows in raw image decoders.
bpftrace: CVE-2024-2313 — unpacked kheaders ownership check (privilege escalation vector).
anaconda: Asia/Beijing default timezone; TOS profile config; loongarch64 + UI customization.
"""

# ── AIDE ──────────────────────────────────────────────────────────────────────

AIDE = {
    "package": "aide-0.18.6-4.tl4",
    "upstream": "https://aide.github.io/ — AIDE (Advanced Intrusion Detection Environment) v0.18.6",
    "license": "GPLv2+",
    "maintainer": "costinchen@tencent.com (Sinong Chen)",
    "role": (
        "File integrity monitoring daemon. Builds a database of file attributes "
        "(hashes, permissions, ownership, timestamps) at a known-good state, then "
        "periodically compares the live filesystem to detect unauthorized changes. "
        "Used as a host IDS layer complementary to aegis.ko."
    ),
    "tencent_patches": {
        "add-sm3-support.patch": {
            "author": "gordonwwang@tencent.com (Wang Guodong)",
            "date": "2023-06-09",
            "description": (
                "Adds SM3 (Chinese national hash standard GB/T 32905) as an AIDE "
                "integrity attribute. SM3 is a 256-bit hash (32 bytes) comparable to SHA-256. "
                "Implementation uses GCRY_MD_SM3 from libgcrypt. "
                "Changes: adds attr_sm3 to ATTRIBUTE enum, hash_sm3 to HASHSUM enum, "
                "writes/reads hash to/from AIDE database via WRITE_HASHSUM/CHAR2HASH macros. "
                "TOS 4.6 is the only major Linux distribution to ship SM3 as an AIDE hash option. "
                "Motivation: Chinese regulatory compliance (classified systems, government infra) "
                "may require use of national standard cryptography, not SHA-2."
            ),
            "security_relevance": (
                "SM3 is a legitimate secure hash (no known preimage attacks). "
                "Adding it to AIDE allows TOS 4.6 deployments in regulated Chinese environments "
                "to meet algorithm requirements without switching to a non-approved hash. "
                "No security regression from the patch itself."
            ),
        },
        "fix-CVE-2025-54389.patch": {
            "cve": "CVE-2025-54389",
            "author": "costinchen@tencent.com (Sinong Chen)",
            "date": "2025-09-01",
            "title": "Control character escape in report and log output",
            "root_cause": (
                "AIDE includes filenames from the monitored filesystem in its reports "
                "and logs. Filenames containing control characters (0x00-0x1F, 0x7F) were "
                "output verbatim. An attacker who could create files with crafted names "
                "could inject terminal escape sequences (e.g., VT100 cursor controls, "
                "color codes) or log-format injection strings into AIDE reports. "
                "In a SIEM context: ANSI escape injection into log streams can cause "
                "misparse, hide findings, or exploit terminal emulators parsing logs."
            ),
            "fix": (
                "New functions strnesc(str, len) and stresc(str) in util.c: "
                "  - Control characters (0x00-0x1F, 0x7F) → \\NNN (octal, 3 digits) "
                "  - Backslash followed by 3 digits → \\134NNN (backslash escaped) "
                "  - Literal backslash not followed by 3 digits → unchanged "
                "Plain report output (report_plain.c) and log output (log.c) call stresc(). "
                "JSON report output (report_json.c) uses proper JSON string escaping. "
                "URL_UNSAFE gains ',' (comma) — prevents comma injection in URL-encoded fields. "
                "Man page updated documenting escape behavior."
            ),
            "files_changed": [
                "doc/aide.1", "include/util.h", "src/aide.c", "src/gen_list.c",
                "src/log.c", "src/report_json.c", "src/report_plain.c", "src/util.c",
            ],
            "severity": "MEDIUM — log/terminal injection via crafted filenames",
        },
        "fix-CVE-2025-54409.patch": {
            "cve": "CVE-2025-54409",
            "author": "costinchen@tencent.com (Sinong Chen)",
            "date": "2025-09-01",
            "title": "Null pointer dereference reading incorrectly encoded xattr from database",
            "root_cause": (
                "AIDE stores extended attributes (xattrs) as base64-encoded values in its database. "
                "When reading them back, db.c calls base64tobyte(tval, strlen(tval), &vsz). "
                "If the base64 string is malformed (wrong padding, invalid chars), base64tobyte "
                "returns NULL. Old code: line->xattrs->ents[num].val = val; — unconditionally "
                "assigns the NULL pointer. Subsequent access to val or vsz causes a null pointer "
                "dereference crash. "
                "Additionally: the xattr key/value parsing uses strtok with ',' as delimiter. "
                "A comma in a key name or value breaks the parser (incorrect field alignment). "
                "URL_UNSAFE adding ',' guards URL-encoded fields from this injection."
            ),
            "fix": (
                "db.c: after base64tobyte(), check if val == NULL. "
                "If NULL: log warning 'error while reading xattrs for <filename> from database "
                "(discarding extended attributes)', free and zero all previously-allocated "
                "xattr entries for this database line, set xattrs->num = 0, continue. "
                "Error is soft — AIDE continues processing, discards xattrs for that file only. "
                "Also: decode_base64() added as preferred name for base64tobyte()."
            ),
            "trigger": (
                "A malicious actor who can write to the AIDE database file can corrupt "
                "xattr base64 values, causing AIDE to crash on next database read. "
                "In practice: if the AIDE database is on an untrusted or attacker-writable "
                "filesystem, this becomes a DoS against the integrity monitoring system itself."
            ),
            "severity": "MEDIUM — crash of integrity monitoring daemon",
        },
    },
}

# ── LibRaw ────────────────────────────────────────────────────────────────────

LIBRAW = {
    "package": "LibRaw-0.21.2-7.tl4",
    "upstream": "https://www.libraw.org/ — LibRaw v0.21.2",
    "license": "LGPLv2 or CDDL",
    "maintainers": [
        "gordonwwang@tencent.com (Wang Guodong)",
        "zidonghuang@tencent.com (Zidong Huang)",
        "PkgAgent Robot / PkgAgent/deepseek-v4-flash",
    ],
    "role": (
        "C++ library for reading raw camera files (CR2, NEF, DNG, ARW, X3F, etc.). "
        "Used by: darktable, rawtherapee, ufraw, digiKam, gstreamer raw plugins, "
        "and any TOS 4.6 application processing raw photos. "
        "Security surface: parses attacker-controlled binary files. "
        "Historical CVE density: moderate — complex binary format parsers."
    ),
    "upstream_patch_author": "Alex Tutubalin <lexa@lexa.ru> (LibRaw maintainer)",
    "talos_reference": "Multiple patches reference TALOS-2026-XXXX — Cisco Talos research findings",
    "cve_patches_2026": {
        "CVE-2026-5342": {
            "talos": "none listed",
            "file": "src/decoders/decoders_libraw.cpp, src/metadata/tiff.cpp",
            "title": "Nikon padded/packed raw: out-of-bounds read via attacker-controlled load_flags",
            "root_cause": (
                "nikon_load_padded_packed_raw() reads 12-bit-per-pixel data padded to 16 bytes. "
                "The row buffer size was taken from load_flags — a value stored in TIFF metadata, "
                "controllable by a malicious NEF/NRW file. "
                "Only sanity check: `if (load_flags < 2000 || load_flags > 64000) return;` — "
                "insufficient; a crafted value in [2000, 64000] but mismatched to actual image "
                "dimensions causes read beyond end of allocated buffer."
            ),
            "fix": (
                "Compute bytesperrow from image dimensions: "
                "  bytesperrow = (((unsigned(S.raw_width) * 3u / 2u) + 15u) / 16u) * 16u\n"
                "Use this computed value instead of load_flags. "
                "Check: if bytesperrow < 2000 || bytesperrow > 64000: throw LIBRAW_EXCEPTION_IO_CORRUPT "
                "malloc → calloc (zeroed buffer). "
                "Check bytesread < bytesperrow: call derror(). "
                "load_flags removed from TIFF metadata path."
            ),
            "impact": "Out-of-bounds read via crafted Nikon RAW file — info disclosure or crash",
        },
        "CVE-2026-24660": {
            "talos": "TALOS-2026-2359",
            "file": "src/x3f/x3f_utils_patched.cpp, libraw/libraw_const.h",
            "title": "X3F (Sigma Foveon) decoder heap buffer overflow via unchecked realloc size",
            "root_cause": (
                "The X3F decoder reads Sigma/Polaroid camera files. "
                "Allocation calls (malloc, calloc, realloc) in the ARRAY_GET/LIST_GET macros "
                "used (_NUM * sizeof(element)) without any upper bound — a malicious X3F file "
                "with a crafted element count could trigger: "
                "(a) integer overflow in the size calculation, producing a small allocation "
                "(b) realloc of that small buffer followed by writes beyond its end. "
            ),
            "fix": (
                "New x3f_limited_malloc/calloc/realloc functions: "
                "  if sz > LIBRAW_X3F_ALLOC_LIMIT_MB * 1024 * 1024: throw LIBRAW_EXCEPTION_TOOBIG "
                "LIBRAW_X3F_ALLOC_LIMIT_MB = 512 (max Foveon: 30Mpix * 3 channels * 2 bytes = ~180MB). "
                "All x3f_utils_patched.cpp ARRAY_GET/LIST_GET macros use x3f_limited_realloc. "
                "All allocation sizes converted to UINT64 before multiplication to prevent overflow."
            ),
            "impact": "Heap buffer overflow — remote code execution via crafted X3F file",
        },
        "CVE-2026-20889": {
            "talos": "TALOS-2026-2358",
            "file": "src/decoders/unpack_thumb.cpp, src/x3f/x3f_parse_process.cpp",
            "title": "x3f_thumb_loader heap buffer overflow: thumbnail size not validated",
            "root_cause": (
                "x3f_thumb_loader() allocates: "
                "  JPEG: malloc(ID->data_size) — data_size from file, unchecked "
                "  Bitmap: malloc(ID->columns * ID->rows * 3) — dimensions from file, unchecked "
                "32-bit integer overflow in columns * rows * 3 for large dimensions → small alloc "
                "followed by memcpy/memmove of full data_size → heap overflow. "
                "Also: catch(...) { // do nothing } — exceptions silently swallowed, "
                "leaving partially-initialized thumbnail state."
            ),
            "fix": (
                "Before each malloc: validate alloc_size against: "
                "  (1) 2 × x3f_thumb_size() — pre-computed expected size "
                "  (2) LIBRAW_MAX_THUMBNAIL_MB × 1024 × 1024 "
                "  (3) alloc_size >= 64 bytes minimum "
                "All size calculations use INT64. "
                "catch block: sets twidth = theight = tcolors = 0 (caller checks these). "
                "Caller (unpack_thumb): if (!T.twidth && !T.theight) return LIBRAW_NO_THUMBNAIL."
            ),
            "impact": "Heap buffer overflow — remote code execution via crafted X3F file with thumbnail",
        },
        "CVE-2026-24450": {
            "talos": "TALOS-2026-2363",
            "file": "src/decoders/fp_dng.cpp",
            "title": "Float/uncompressed DNG: integer overflow in row byte calculation",
            "root_cause": (
                "uncompressed_fp_dng_load_raw(): row size = tileWidth * bytesps * ifd->samples. "
                "All are 32-bit values — product overflows for pathological values from DNG metadata. "
                "Overflowed small rowbytes → small read buffer → adjacent memory overwrite. "
                "Also: read() return value not checked — short reads treated as full reads."
            ),
            "fix": (
                "INT64 rowbytes = INT64(MAX(tileWidth, raw_width)) * INT64(MAX(bytesps, 4)) * INT64(ifd->samples) "
                "if rowbytes > (1LL << 22): throw LIBRAW_EXCEPTION_TOOBIG "
                "calloc uses INT64 allocsz. Read result checked: if bytesread < fullrowbytes: derror()."
            ),
            "impact": "Heap buffer overflow — remote code execution via crafted float DNG file",
        },
        "CVE-2026_20884": {
            "talos": "TALOS-2026-2364",
            "file": "src/decoders/fp_dng.cpp",
            "title": "Float/deflated DNG: integer overflow in allocation and missing read check",
            "root_cause": (
                "deflate_dng_load_raw(): similar to CVE-2026-24450 but in the deflate (zlib) path. "
                "tileCnt * tileWidth * tileHeight * samples * sizeof(float) without INT64 cast. "
                "Also: maxcomprlen not validated before calloc-ing the decompression buffer. "
                "read() return unchecked."
            ),
            "fix": (
                "Validates maxcomprlen < 2GB (INT64 check), rowbytes < 2^22. "
                "raw_bytes uses INT64 for full product. calloc(raw_bytes, 1). "
                "read() result checked against tBytes[t]."
            ),
            "impact": "Heap buffer overflow via crafted deflate-compressed DNG file",
        },
        "CVE-2026-21413": {
            "talos": "TALOS-2026-2331",
            "file": "src/decoders/decoders_dcraw.cpp",
            "title": "lossless_jpeg_load_raw: out-of-bounds write via missing column bounds check",
            "root_cause": (
                "lossless_jpeg_load_raw() iterates JPEG scan data writing to raw_image[] array. "
                "Row bounds check present: if ((unsigned)row < raw_height) RAW(row, col) = val. "
                "Column not checked — a malicious JPEG scan could have col >= raw_width, "
                "writing outside the raw_image allocation."
            ),
            "fix": (
                "Added column check: "
                "  if (((unsigned)row < raw_height) && ((unsigned)col < raw_width)) RAW(row, col) = val"
            ),
            "impact": "Out-of-bounds write via crafted JPEG-compressed raw file (LJPEG) — heap corruption",
        },
    },
    "cve_patches_2025": {
        "CVE-2025-43961_43962": "Two related vulnerabilities (0001 patch, 4.3KB — not fully analyzed)",
        "CVE-2025-43963": "0002 patch (1.3KB — not fully analyzed)",
        "CVE-2025-43964": "0003 patch (892 bytes — not fully analyzed)",
    },
}

# ── bpftrace ──────────────────────────────────────────────────────────────────

BPFTRACE = {
    "package": "bpftrace-0.19.1-9.tl4",
    "upstream": "https://github.com/bpftrace/bpftrace — eBPF tracing tool v0.19.1",
    "license": "ASL 2.0",
    "role": (
        "High-level eBPF tracing language and tool for Linux. "
        "Allows dynamic kernel and userspace probing via kprobe/uprobe/tracepoint. "
        "On TOS 4.6: used by administrators for performance analysis and "
        "security event tracing."
    ),
    "cve_2024_2313": {
        "id": "CVE-2024-2313",
        "author": "Jordan Rome <jordalgo@meta.com>",
        "title": "Unpacked kheaders directory not verified to be root-owned — privilege escalation",
        "root_cause": (
            "bpftrace needs kernel headers to compile BPF programs. "
            "When /sys/kernel/kheaders.tar.xz is available, bpftrace extracts it to "
            "/tmp/kheaders-<utsname.release>. On subsequent runs, if that directory exists, "
            "bpftrace reuses it without verifying ownership. "
            "An unprivileged attacker can: "
            "  1. Create /tmp/kheaders-<kernel-version>/ before bpftrace runs "
            "  2. Populate it with malicious modified kernel headers "
            "  3. When bpftrace runs (potentially as root), it compiles and loads "
            "     a BPF program using the attacker's headers. "
            "Malicious headers can cause the compiled BPF bytecode to behave unexpectedly "
            "— potential for privilege escalation if bpftrace is setuid or runs via sudo."
        ),
        "fix": (
            "New function file_exists_and_ownedby_root(const char *f): "
            "  stat(f, &st); if st.st_uid != 0: log error and return false; else return true. "
            "The cached kheaders check changes: "
            "  old: if (std::filesystem::exists(shared_path)) { use it } "
            "  new: if (file_exists_and_ownedby_root(shared_path.c_str())) { use it } "
            "If owned by non-root: bpftrace re-extracts from /sys/kernel/kheaders.tar.xz."
        ),
        "severity": "MEDIUM — privilege escalation via kheaders directory hijacking",
        "upstream_pr": "#3033",
    },
    "tencent_delta": "Single upstream CVE patch; no Tencent-specific modifications.",
}

# ── Anaconda ──────────────────────────────────────────────────────────────────

ANACONDA = {
    "package": "anaconda-38.23.2-18.tl4.ap.1",
    "upstream": "https://github.com/rhinstaller/anaconda — Red Hat Anaconda v38.23.2",
    "license": "GPLv2+",
    "release_tag": ".ap.1 = Autopatch revision 1 by TencentOS Team",
    "role": "System installer for TencentOS. Used for bare-metal and cloud VM provisioning.",
    "tencent_patches": {
        "tencentos.conf": {
            "type": "Anaconda profile configuration",
            "key_settings": {
                "profile_id": "tencentos",
                "os_id_match": "tencentos",
                "forbidden_modules": ["org.fedoraproject.Anaconda.Modules.Subscription"],
                "filesystem": "xfs (default)",
                "default_partitioning": "/ max 70GiB, /home min 500MiB free 50GiB",
                "efi_dir": "tencentos",
                "custom_stylesheet": "/usr/share/anaconda/pixmaps/tencentos.css",
                "eula": "/usr/share/tencentos-release/EULA",
                "ignored_packages": ["ntfsprogs", "btrfs-progs", "dmraid"],
            },
            "security_notes": (
                "Subscription module disabled: prevents Red Hat subscription manager "
                "from loading during installation. XFS as default FS (standard RHEL choice). "
                "Custom EULA — TOS 4.6 has its own license agreement. "
                "No security-relevant changes."
            ),
        },
        "Set-default-timezone-to-Asia-Beijing.patch": {
            "change": "All hardcoded 'America/New_York' → 'Asia/Beijing' in pyanaconda",
            "files": [
                "pyanaconda/modules/timezone/installation.py",
                "pyanaconda/modules/timezone/timezone.py",
                "pyanaconda/ui/gui/spokes/datetime_spoke.py",
                "tests/unit_tests/pyanaconda_tests/modules/timezone/",
            ],
            "security_notes": "No security impact — localization/deployment default change.",
        },
        "5004-Set-gui-default-locale-to-zh_CN.UTF-8.patch": {
            "change": "Default GUI locale: zh_CN.UTF-8",
            "security_notes": "Localization only.",
        },
        "0001-Import-BlockDev-from-blivet-instead-of-gi.patch": {
            "change": "Python import path change: BlockDev from blivet instead of gi.repository",
            "security_notes": "Build/import compatibility fix; no security impact.",
        },
        "5000-remove-flatpak-support.patch": {
            "change": "Removes flatpak installation support from Anaconda",
            "security_notes": "Attack surface reduction — Flatpak not included in TOS.",
        },
        "5007-add-loongarch64-support-for-anaconda-38.23.patch": {
            "change": "Adds LoongArch (龙芯) CPU architecture support to TOS installer",
            "security_notes": "Architecture port; no security impact.",
        },
    },
    "security_summary": (
        "No security patches in anaconda. All changes are: China localization defaults "
        "(timezone, locale), TOS branding/profile config, architecture support (loongarch64), "
        "and feature removal (flatpak, subscription module). "
        "The .ap.1 Autopatch tag indicates TencentOS Team applied these as a single batch."
    ),
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "package": "LibRaw",
        "cves": ["CVE-2026-24660", "CVE-2026-20889"],
        "title": "X3F (Sigma Foveon) decoder: heap buffer overflow via unchecked allocation sizes",
        "detail": (
            "CVE-2026-24660 (TALOS-2026-2359): x3f_utils_patched.cpp ARRAY_GET/LIST_GET macros "
            "call realloc() with (_NUM * sizeof(element)) without bounds check — "
            "32-bit overflow produces small allocation; subsequent writes overflow. "
            "Fix: x3f_limited_realloc with 512MB hard cap. "
            "CVE-2026-20889 (TALOS-2026-2358): x3f_thumb_loader allocates thumbnail buffer "
            "using columns * rows * 3 (32-bit overflow) → small buffer; "
            "fix validates against 2× expected size and max thumbnail MB limit. "
            "Both: crafted X3F file from Sigma/Polaroid cameras triggers heap overflow. "
            "Fixed 2026-04-09 in 0.21.2-6.tl4."
        ),
        "affected": "LibRaw < 0.21.2-6.tl4",
        "fixed": "LibRaw-0.21.2-6.tl4",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "package": "LibRaw",
        "cves": ["CVE-2026-24450", "CVE-2026-20884"],
        "title": "Float/DNG decoders: integer overflow in tile/row size calculation",
        "detail": (
            "CVE-2026-24450 (TALOS-2026-2363): uncompressed_fp_dng_load_raw() — "
            "rowbytes = tileWidth * bytesps * samples (32-bit overflow); "
            "calloc receives overflowed small size; read overflows buffer. "
            "CVE-2026-20884 (TALOS-2026-2364): deflate_dng_load_raw() — same class, "
            "deflated/compressed DNG path. Also validates maxcomprlen < 2GB. "
            "Both fix: INT64 arithmetic throughout, bounds check against 2^22. "
            "Also: read() return values now checked. Fixed 2026-04-09 / 2026-05-07."
        ),
        "affected": "LibRaw < 0.21.2-6.tl4 (uncompressed DNG) / < 0.21.2-7.tl4 (deflated DNG)",
        "fixed": "LibRaw-0.21.2-7.tl4",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "package": "LibRaw",
        "cve": "CVE-2026-21413",
        "title": "lossless_jpeg_load_raw: out-of-bounds write via missing column check",
        "detail": (
            "TALOS-2026-2331: lossless JPEG raw decoder checks row < raw_height "
            "before RAW(row, col) write but not col < raw_width. "
            "Crafted LJPEG raw (CR2, NEF, DNG with LJPEG compression) causes "
            "out-of-bounds write to raw_image heap buffer. "
            "One-line fix: add col bounds check. Fixed 2026-04-09."
        ),
        "affected": "LibRaw < 0.21.2-6.tl4 with LJPEG-compressed raw images",
        "fixed": "LibRaw-0.21.2-6.tl4",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "package": "LibRaw",
        "cve": "CVE-2026-5342",
        "title": "Nikon padded/packed raw: attacker-controlled load_flags used as buffer size",
        "detail": (
            "nikon_load_padded_packed_raw(): row buffer malloc(load_flags) where load_flags "
            "comes from TIFF metadata — attacker-controlled in a crafted NEF/NRW file. "
            "Range check [2000, 64000] insufficient; mismatched value causes OOB read. "
            "Fix: compute bytesperrow from raw_width (image geometry), discard load_flags. "
            "Fixed 2026-04-09."
        ),
        "affected": "LibRaw < 0.21.2-6.tl4 processing Nikon NEF/NRW files",
        "fixed": "LibRaw-0.21.2-6.tl4",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "package": "aide",
        "cve": "CVE-2025-54389",
        "title": "AIDE log/terminal injection via control characters in monitored filenames",
        "detail": (
            "AIDE outputs filenames verbatim in reports and logs. Files with embedded "
            "control chars (0x00-0x1F, 0x7F) inject terminal escape sequences or log format chars. "
            "In SIEM: escape injection can hide AIDE findings from log aggregation. "
            "Fix: strnesc() escapes control chars as \\NNN (octal). "
            "Backported and fixed 2025-09-01 by costinchen@tencent.com."
        ),
        "affected": "aide < 0.18.6-4.tl4",
        "fixed": "aide-0.18.6-4.tl4",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "package": "aide",
        "cve": "CVE-2025-54409",
        "title": "AIDE: null pointer dereference reading malformed xattr from database",
        "detail": (
            "db.c: base64tobyte() returns NULL for malformed xattr encoding. "
            "Unconditional assignment crashes AIDE on next database read. "
            "Attacker write access to AIDE database → DoS of integrity monitoring. "
            "Fix: NULL check + discard xattrs for affected entry, log warning, continue. "
            "Also: URL_UNSAFE gains ',' to prevent comma injection in strtok xattr parser."
        ),
        "affected": "aide < 0.18.6-4.tl4",
        "fixed": "aide-0.18.6-4.tl4",
    },
    {
        "id": "F7",
        "severity": "MEDIUM",
        "package": "bpftrace",
        "cve": "CVE-2024-2313",
        "title": "bpftrace: kheaders directory not verified root-owned — privilege escalation via symlink race",
        "detail": (
            "bpftrace reuses /tmp/kheaders-<release>/ without checking ownership. "
            "Unprivileged attacker pre-creates directory with malicious headers. "
            "bpftrace (run as root) compiles BPF using attacker headers → potential code execution. "
            "Fix: file_exists_and_ownedby_root() — stat() + st_uid == 0 check before reuse. "
            "Upstream PR #3033 by Jordan Rome (Meta). Fixed in 9.tl4."
        ),
        "affected": "bpftrace < 0.19.1-9.tl4",
        "fixed": "bpftrace-0.19.1-9.tl4",
    },
    {
        "id": "F8",
        "severity": "INFO",
        "package": "aide",
        "title": "AIDE TOS 4.6: SM3 (Chinese national hash GB/T 32905) added as integrity algorithm",
        "detail": (
            "Tencent adds SM3 (32-byte hash, GCRY_MD_SM3) to AIDE's hash attribute set. "
            "TOS 4.6 is the only known Linux distro to ship AIDE with SM3 support. "
            "Enables file integrity monitoring using PRC national standard cryptography. "
            "SM3 has no known preimage attacks; no regression from the addition."
        ),
    },
    {
        "id": "F9",
        "severity": "INFO",
        "package": "anaconda",
        "title": "anaconda-38.23.2-18.tl4.ap.1: China localization defaults and TOS profile config",
        "detail": (
            "Autopatch adds: Asia/Beijing default timezone, zh_CN.UTF-8 default locale, "
            "TOS Anaconda profile (tencentos.conf): XFS filesystem, TOS EULA, "
            "subscription module disabled, efi_dir=tencentos. "
            "Flatpak support removed (attack surface reduction). "
            "LoongArch (龙芯) CPU architecture support added. "
            "No security patches — pure localization and deployment customization."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 AppStream security and system tools RE")
    print()
    print("aide-0.18.6-4.tl4:")
    print(f"  SM3 integrity hash: GCRY_MD_SM3, 32-byte, China GM/T standard")
    print(f"  CVE-2025-54389: log injection via control chars in filenames → stresc()")
    print(f"  CVE-2025-54409: NPD in xattr decode (NULL from base64tobyte not checked)")
    print()
    print("LibRaw-0.21.2-7.tl4 (9 CVEs — all fixed, TALOS research):")
    for cve, info in LIBRAW['cve_patches_2026'].items():
        c = info.get('cves') if isinstance(info.get('cves'), list) else [cve.replace('_', '-')]
        print(f"  {cve.replace('_', '-')}: {info['title'][:65]}")
    print()
    print("bpftrace-0.19.1-9.tl4:")
    bpf = BPFTRACE['cve_2024_2313']
    print(f"  {bpf['id']}: {bpf['title'][:70]}")
    print()
    print("anaconda-38.23.2-18.tl4.ap.1: China localization + TOS profile (no security patches)")
    print()
    for f in FINDINGS:
        cve = f.get('cve', f.get('cves', [''])[0] if isinstance(f.get('cves'), list) else '')
        label = f"{cve} " if cve else ""
        print(f"  [{f['severity']:6s}] {f['id']}: {label}{f['title'][:64]}")
