"""
TencentOS 2.4 (TLinux 2) — ImageMagick-6.9.10.68-15.tl2.1 SRPM RE.

Source from Drive: tencent-re/2.4/tlinux-srpms/ImageMagick-6.9.10.68-15.tl2.1.src.rpm
Upstream: ImageMagick 6.9.10.68 (legacy 6.x line — RHEL 7 era)
Tencent package maintainer: Haitao Huang <kaeyahuang@tencent.com>
Revision tl2.1: Apr 17 2026 — update for koji (build system push only)

Security patches: 8 CVE patches covering 2025-2026 security advisories.
All patches authored by Red Hat / upstream ImageMagick maintainers (Dirk Lemstra, Cristy).
No Tencent-specific security logic.
"""

PACKAGE = {
    "package": "ImageMagick-6.9.10.68-15.tl2.1",
    "upstream": "ImageMagick 6.9.10.68 (ImageMagick 6.x legacy)",
    "base": "RHEL 7 ImageMagick-6.9.10.68-15",
    "license": "ImageMagick",
    "tencent_maintainer": "Haitao Huang <kaeyahuang@tencent.com>",
    "patch_authors": [
        "Dirk Lemstra <dirk@lemstra.org> (ImageMagick upstream)",
        "Cristy <urban-warrior@imagemagick.org> (ImageMagick upstream)",
        "Mohit Vyas <mvyas@redhat.com> (Red Hat)",
    ],
    "role": (
        "Image processing library and CLI toolkit. Handles 200+ image formats including "
        "BMP, DIB, XBM, JBIG, MNG/PNG, SVG, PDF, and raw camera formats. "
        "Security surface: parses attacker-controlled image files. "
        "High historic CVE density — the RHEL 7 6.9.10.68 base is a 2018 release "
        "with a long tail of format-specific memory safety bugs."
    ),
}

# ── 2026 CVE Patches ─────────────────────────────────────────────────────────

CVE_2026_23876 = {
    "id": "CVE-2026-23876",
    "ghsa": "GHSA-r49w-jqq3-3gx8",
    "author": "Dirk Lemstra (ImageMagick upstream)",
    "date": "Jan 18 2026",
    "file": "coders/xbm.c",
    "title": "XBM decoder: integer overflow in bytes_per_line * rows heap allocation",
    "root_cause": (
        "ReadXBMImage() computes pixel buffer size: "
        "  bytes_per_line = (unsigned int)(columns+7)/8 + padding "
        "  length = (unsigned int) rows "
        "  data = AcquireQuantumMemory(length, bytes_per_line * sizeof(*data)) "
        "Both bytes_per_line and length are 32-bit unsigned ints. "
        "For a crafted XBM with large columns (e.g., columns=65535, rows=65535): "
        "  bytes_per_line * sizeof(*data) overflows 32-bit → small allocation "
        "  loop writes bytes_per_line*rows bytes → heap buffer overflow. "
        "XBM is the X11 bitmap format — text-based hex file, trivial to craft."
    ),
    "fix": (
        "Change bytes_per_line and length from unsigned int to size_t. "
        "Add HeapOverflowSanityCheck(bytes_per_line, rows): "
        "  if bytes_per_line * rows would overflow: ThrowReaderException(CorruptImageError). "
        "Compute length = bytes_per_line * rows once as size_t. "
        "Loop bounds use length directly rather than recomputing the product."
    ),
    "severity": "HIGH — heap buffer overflow via crafted XBM file",
}

CVE_2026_25965 = {
    "id": "CVE-2026-25965",
    "ghsa": "GHSA-8jvj-p28h-9gm7",
    "author": "Dirk Lemstra (ImageMagick upstream)",
    "date": "Feb 3 2026",
    "files": ["MagickCore/module.c", "MagickCore/policy.c", "MagickCore/utility-private.h"],
    "title": "Security policy bypass via path traversal — realpath not used before policy check",
    "root_cause": (
        "ImageMagick has a security policy mechanism (policy.xml) that controls access: "
        "  <policy domain='coder' rights='none' pattern='HTTPS' /> — disables HTTPS URLs "
        "  <policy domain='path' rights='none' pattern='/etc/*' /> — blocks /etc/ access "
        "Policy checks use GlobExpression(pattern, p->pattern, MagickFalse) on the raw input path. "
        "A caller that supplies a path like '/etc/./passwd' or '/var/../etc/passwd' "
        "may pass the glob check ('/etc/*' wouldn't match '/var/../etc/passwd') "
        "but realpath() would resolve it to the blocked path. "
        "Also: module path loading used realpath() only under #if MAGICKCORE_HAVE_REALPATH, "
        "which is inconsistently defined."
    ),
    "fix": (
        "New function realpath_utf8() in utility-private.h (10KB) — portable realpath with UTF-8 handling. "
        "module.c: always calls realpath_utf8() before IsPathAccessible() (removes HAVE_REALPATH ifdef). "
        "policy.c IsRightsAuthorized(): "
        "  if domain == PathPolicyDomain: real_pattern = realpath_utf8(pattern) "
        "  use real_pattern (canonical path) for glob matching "
        "  DestroyString(real_pattern) after match "
        "Also: removes FoomaticRIPCommandLine from pass-through PPD (defense-in-depth)."
    ),
    "security_impact": (
        "An attacker-supplied path with .. traversal or symlinks could bypass ImageMagick "
        "security policy restrictions, allowing access to files that should be blocked. "
        "Severity depends on how ImageMagick is used — in web services that process user-supplied "
        "file paths, this could allow reading arbitrary files."
    ),
    "severity": "HIGH — security policy bypass; allows access to policy-blocked paths",
}

CVE_2026_25985 = {
    "id": "CVE-2026-25985",
    "ghsa": "GHSA-v7g2-m8c5-mf84",
    "author": "Cristy (ImageMagick upstream)",
    "date": "Feb 7 2026",
    "file": "magick/draw.c",
    "title": "MVG draw: CheckPrimitiveExtent uses SSIZE_MAX (wrong), Bezier coordinate overflow",
    "root_cause": (
        "CheckPrimitiveExtent() validates: "
        "  if ((extent*quantum) < (double) SSIZE_MAX && ...) — allocate or extend "
        "SSIZE_MAX on 64-bit Linux is 2^63-1 (~9.2e18). "
        "extent is a double; for a crafted MVG with huge padding, extent can be NaN or Inf. "
        "NaN < SSIZE_MAX is false (NaN comparisons always false) → allocation skipped → "
        "later write to unallocated buffer → heap overflow or use of NULL. "
        "Also: TraceBezier() checked alpha > SSIZE_MAX but alpha is a double coordinate; "
        "SSIZE_MAX check is wrong — GetMaxMemoryRequest() is the correct practical limit."
    ),
    "fix": (
        "CheckPrimitiveExtent: "
        "  condition becomes: (extent*quantum) < GetMaxMemoryRequest() && IsNaN(extent) == 0 "
        "  NaN check prevents the silent bypass. "
        "TraceBezier: "
        "  alpha > SSIZE_MAX → alpha > GetMaxMemoryRequest() "
        "  second redundant SSIZE_MAX check for Y coordinate removed "
        "  post-loop quantum check: if quantum > GetMaxMemoryRequest() → throw exception"
    ),
    "severity": "MEDIUM — heap overflow via crafted MVG/SVG file with extreme Bezier coordinates",
}

CVE_2026_28691 = {
    "id": "CVE-2026-28691",
    "ghsa": "GHSA-wj8w-pjxf-9g4f",
    "author": "Cristy (ImageMagick upstream)",
    "date": "Feb 22 2026",
    "file": "coders/jbig.c",
    "title": "JBIG decoder: missing decode status check — use of corrupt decoded data",
    "root_cause": (
        "ReadJBIGImage(): decodes JBIG bitstream via jbg_dec_xxx() API. "
        "Decode loop: do { status = jbg_dec_buf_in(...); } while (status == JBG_EAGAIN || JBG_EOK). "
        "If decode ends with status != JBG_EOK (decode error), code fell through to colormap "
        "creation and image data processing on a partially/incorrectly decoded JBIG image. "
        "The JBIG decoded image data structure may be in an inconsistent state. "
        "Processing corrupt image data could cause memory errors."
    ),
    "fix": (
        "After decode loop: if status != JBG_EOK: "
        "  jbg_dec_free(&jbig_info) "
        "  buffer = RelinquishMagickMemory(buffer) "
        "  ThrowReaderException(CorruptImageError, 'UnableToReadImageData')"
    ),
    "severity": "MEDIUM — use of corrupt JBIG decoded data; dependent on jbg_dec behavior",
}

CVE_2026_28693 = {
    "id": "CVE-2026-28693",
    "pr": "ImageMagick/ImageMagick#8573",
    "author": "Cristy (ImageMagick upstream)",
    "date": "Feb 28 2026",
    "files": ["coders/bmp.c", "coders/dib.c", "magick/memory_.h"],
    "title": "BMP/DIB read+write: integer overflow in bytes_per_line calculation",
    "root_cause": (
        "ReadBMPImage() / ReadDIBImage() / WriteDIBImage(): "
        "  bytes_per_line = 4 * ((image->columns * bits_per_pixel + 31) / 32) "
        "  length = bytes_per_line * image->rows "
        "Both multiplications can overflow 32/64-bit integers for crafted BMP dimensions. "
        "Also: the existing size sanity check was wrong: "
        "  if ((MagickSizeType) length > (256 * GetBlobSize(image))) — incorrect overflow "
        "  256 * GetBlobSize could itself overflow before the comparison! "
        "Result: heap allocations smaller than required → buffer overflow on pixel writes."
    ),
    "new_helpers": {
        "HeapOverflowSanityCheckGetSize(count, quantum, &extent)": (
            "Inline function in memory_.h: "
            "  length = count * quantum "
            "  if quantum != (length/count): return MagickTrue (overflow) "
            "  else: *extent = length; return MagickFalse "
        ),
        "BMPOverflowCheck(x, y)": (
            "  (y != 0) && (x > 4294967295UL/y) — 32-bit specific overflow check "
            "  Used for BMP/DIB 32-bit pixel row calculations."
        ),
    },
    "fix": (
        "All byte calculations use HeapOverflowSanityCheckGetSize or BMPOverflowCheck "
        "before each multiplication in the pipeline: "
        "  columns * bits_per_pixel → extent "
        "  4 * ((extent+31)/32) → bytes_per_line "
        "  bytes_per_line * rows → length "
        "Each step throws ResourceLimitError or CorruptImageError on overflow. "
        "Also fixed: comparison length/256 > GetBlobSize (divides first, avoids overflow)."
    ),
    "severity": "HIGH — heap overflow via crafted BMP/DIB with extreme dimensions",
}

# ── 2025 CVE Patches ─────────────────────────────────────────────────────────

CVE_2025_55154 = {
    "id": "CVE-2025-55154",
    "ghsa": "GHSA-qp29-wxp5-wh82",
    "author": "Mohit Vyas <mvyas@redhat.com> (Red Hat)",
    "date": "Sep 8 2025",
    "file": "coders/png.c (MNG animation decoder)",
    "title": "MNG decoder: magnified_width/height computed as png_uint_32 — 32-bit overflow",
    "root_cause": (
        "ReadOneMNGImage() processes MNG MAGN chunk to magnify frames. "
        "magnified_width and magnified_height declared as png_uint_32 (uint32_t). "
        "Calculation: magnified_width = magn_ml + (columns-2) * magn_mx "
        "For a crafted MNG with large magn_mx * large columns: "
        "  png_uint_32 overflow → small width → buffer smaller than needed for pixel data "
        "→ heap overflow during frame magnification."
    ),
    "fix": "Change magnified_width/height from png_uint_32 to size_t. All casts changed to (size_t).",
    "severity": "HIGH — heap overflow via crafted MNG file",
}

CVE_2025_57803 = {
    "id": "CVE-2025-57803",
    "ghsa": "GHSA-mxvv-97wh-cfmm",
    "author": "Mohit Vyas <mvyas@redhat.com> (Red Hat)",
    "date": "Sep 16 2025",
    "file": "coders/bmp.c",
    "title": "BMP reader: integer overflow in pixel buffer allocation — adds BMPOverflowCheck",
    "root_cause": (
        "BMP ReadBMPImage(): bytes_per_line = 4*((columns*bits_per_pixel+31)/32) "
        "columns * bits_per_pixel can overflow. Also: AcquireVirtualMemory(rows, "
        "MagickMax(bytes_per_line, columns+256) * sizeof(*pixels)) — second multiplication "
        "MagickMax(bytes_per_line, columns+256) * sizeof(*pixels) not checked."
    ),
    "fix": (
        "New inline BMPOverflowCheck(x, y): returns MagickTrue if x*y > UINT32_MAX. "
        "Applied to both rows*extent and extent*sizeof(*pixels) before allocation. "
        "Also fixes length comparison: (MagickSizeType)(length/256) > GetBlobSize() "
        "(was: length > 256*GetBlobSize which could overflow the 256× multiplication)."
    ),
    "severity": "HIGH — heap overflow via crafted BMP file",
}

CVE_2025_62171 = {
    "id": "CVE-2025-62171",
    "ghsa": "GHSA-9pp9-cfwx-54rm",
    "author": "Dirk Lemstra (ImageMagick upstream)",
    "date": "Oct 12 2025",
    "file": "coders/bmp.c",
    "title": "BMP reader: missing overflow check before columns*bits_per_pixel on 32-bit systems",
    "root_cause": (
        "Followup to CVE-2025-57803: the initial fix added BMPOverflowCheck on the result "
        "of columns * bits_per_pixel (for the extent variable), but didn't check "
        "the multiplication itself before storing into extent. "
        "On 32-bit systems where size_t is 32 bits, the multiplication "
        "image->columns * bmp_info.bits_per_pixel can overflow before "
        "HeapOverflowSanityCheckGetSize sees it."
    ),
    "fix": (
        "Add BMPOverflowCheck(image->columns, bmp_info.bits_per_pixel) BEFORE the multiplication "
        "at line 1117: if check fails → ThrowReaderException(ResourceLimitError). "
        "Then proceed to: extent = columns * bits_per_pixel."
    ),
    "severity": "HIGH on 32-bit; LOW on 64-bit — pre-multiply overflow guard missing",
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2026-25965",
        "title": "Security policy bypass via path traversal — realpath not used before glob match",
        "detail": (
            "ImageMagick security policy (policy.xml) can restrict paths and coders. "
            "Policy check used raw input path in GlobExpression without resolving symlinks/traversal. "
            "A path like '/var/../etc/shadow' bypasses '/etc/*' deny policy. "
            "Fix: realpath_utf8() canonicalizes path before policy check. "
            "Critical in web/containerized deployments where ImageMagick processes user-supplied paths."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cves": ["CVE-2026-28693", "CVE-2025-57803", "CVE-2025-62171"],
        "title": "BMP/DIB decoder: integer overflow cluster — three sequential fixes for same class",
        "detail": (
            "Same root class across three CVEs (2025 → 2026): "
            "columns * bits_per_pixel in BMP/DIB pixel buffer calculation overflows 32-bit. "
            "CVE-2025-57803: adds BMPOverflowCheck; CVE-2025-62171: adds pre-multiply check on 32-bit. "
            "CVE-2026-28693: extends to DIB reader/writer, adds HeapOverflowSanityCheckGetSize. "
            "Entire overflow guard family (BMPOverflowCheck, HeapOverflowSanityCheckGetSize) "
            "introduced incrementally over 5 months."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2026-23876",
        "title": "XBM decoder: bytes_per_line*rows overflow — 32-bit unsigned int → size_t fix",
        "detail": (
            "XBM format (X11 bitmap) is trivial to craft. "
            "bytes_per_line and length were unsigned int — overflow for large dimensions. "
            "Fix: size_t + HeapOverflowSanityCheck(). Same class as BMP cluster."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "cve": "CVE-2025-55154",
        "title": "MNG animation decoder: magnified frame dimensions as png_uint_32 — 32-bit overflow",
        "detail": (
            "MAGN chunk frame magnification: magnified_width = magn_ml + (columns-2) * magn_mx "
            "stored in png_uint_32 (32-bit). Fix: size_t. Crafted MNG with large MAGN chunk → overflow."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "cve": "CVE-2026-25985",
        "title": "MVG/draw CheckPrimitiveExtent: SSIZE_MAX bypass via NaN — wrong limit",
        "detail": (
            "NaN < SSIZE_MAX is always false — crafted MVG that produces NaN extent skips allocation "
            "check, writes to NULL or undersized buffer. Fix: add IsNaN() check + use GetMaxMemoryRequest()."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "cve": "CVE-2026-28691",
        "title": "JBIG decoder: missing error check after decode allows corrupt image processing",
        "detail": (
            "jbg_dec_buf_in() failure not checked — corrupt JBIG continues to colormap creation "
            "with uninitialized data. Fix: check status != JBG_EOK, free and throw exception."
        ),
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "Integer overflow pattern spans XBM/BMP/DIB/MNG coders — systematic 32-bit type widening needed",
        "detail": (
            "All 2025-2026 ImageMagick CVEs in this package are the same class: "
            "pixel buffer dimensions computed as 32-bit unsigned ints when size_t required. "
            "The fixes introduce helper functions (HeapOverflowSanityCheck, BMPOverflowCheck) "
            "rather than fixing the root type issue. More coders likely carry the same bug. "
            "ImageMagick 6.x is effectively EOL — 7.x has broader size_t adoption."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 2.4 ImageMagick-6.9.10.68-15.tl2.1 RE")
    print()
    print("2025-2026 CVE patches (8 total):")
    for cve, info in {
        "CVE-2025-55154": CVE_2025_55154, "CVE-2025-57803": CVE_2025_57803,
        "CVE-2025-62171": CVE_2025_62171, "CVE-2026-23876": CVE_2026_23876,
        "CVE-2026-25965": CVE_2026_25965, "CVE-2026-25985": CVE_2026_25985,
        "CVE-2026-28691": CVE_2026_28691, "CVE-2026-28693": CVE_2026_28693,
    }.items():
        print(f"  {cve}: {info['title'][:60]}")
    print()
    for f in FINDINGS:
        cve = f.get('cve', '')
        label = f"{cve} " if cve else ""
        print(f"  [{f['severity']:6s}] {f['id']}: {label}{f['title'][:62]}")
