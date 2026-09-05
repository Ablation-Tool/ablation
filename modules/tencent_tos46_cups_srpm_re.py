"""
TencentOS Server 4.6 CUPS RE Module
Source: cups-2.4.6-{9,10,11}.tl4.src.rpm
        /media/cowboy/research/tencentos/4.6/BaseOS-source/
Analysis date: 2026-09-04

PACKAGE HISTORY:
  cups-2.4.6-9.tl4   6 CVE patches
  cups-2.4.6-10.tl4  +CVE-2026-27447
  cups-2.4.6-11.tl4  +CVE-2026-34978, CVE-2026-34979, CVE-2026-34980, CVE-2026-34990

TENCENT UPSTREAM CONTRIBUTORS:
  nilusyi@tencent.com — CVE-2024-47175 author + co-author CVE-2026-34990
  abushwang@tencent.com — signed CVE-2026-34990 (loopback local cert bypass)

AI PATCH ADAPTATION:
  "Adapted-by: PkgAgent" on CVE-2026-27447, CVE-2026-34978, CVE-2026-34979,
  CVE-2026-34980, CVE-2026-34990

SECURITY FINDINGS: TOS46-CUPS-F01 through TOS46-CUPS-F11
  F01 CRITICAL  CVE-2024-47175  PPD injection via printer-make-and-model (CUPS RCE chain)
  F02 HIGH      CVE-2026-34979  ipp_length() undercount → heap overflow in get_options()
  F03 HIGH      CVE-2026-34980  Control char injection in print job option values
  F04 HIGH      CVE-2026-34990  Local certificate over TCP loopback bypass (AF_LOCAL fix)
  F05 HIGH      CVE-2026-34978  RSS notifier path traversal (../); symlink write
  F06 HIGH      CVE-2025-61915  cupsd: IPv6 OOB write + NULL deref + PeerCred config rewrite
  F07 MEDIUM    CVE-2025-58060  Auth type bypass — wrong auth method accepted pre-check
  F08 MEDIUM    CVE-2026-27447  Username comparison case-insensitive in group auth
  F09 MEDIUM    CVE-2025-58436  Slow client DoS blocks single-threaded cupsd
  F10 MEDIUM    CVE-2025-58364  IPP extension tag NULL deref in ipp_read_io()
  F11 INFO      CVE-2023-4504   PostScript lone backslash OOB read in raster interpreter
"""

# ──────────────────────────────────────────────────────────────────────────────
# F01 — PPD injection via printer-make-and-model (CVE-2024-47175)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F01_PPD_INJECT = {
    "finding_id": "TOS46-CUPS-F01",
    "severity": "CRITICAL",
    "cve": "CVE-2024-47175",
    "title": (
        "_ppdCreateFromIPP2(): printer-make-and-model IPP attribute written to PPD "
        "without sanitization — attacker-controlled printer name injects PPD directives; "
        "author: nilusyi@tencent.com (Tencent upstream contribution)"
    ),
    "description": (
        "cups/ppd-cache.c _ppdCreateFromIPP2() — generates PPD from IPP attributes. "
        "\n"
        "Pre-patch: "
        "  if((attr = ippFindAttribute(supported, 'printer-make-and-model', IPP_TAG_TEXT)) != NULL) "
        "    strlcpy(make, ippGetString(attr, 0, NULL), sizeof(make)); "
        "  [written directly to PPD with cupsFilePrintf] "
        "\n"
        "PPD file format uses '*' directives and special characters. "
        "A printer advertising a malicious name like: "
        "  'LaserJet\\n*cupsFilter: \"application/vnd.cups-raster 0 /tmp/evil.sh\"' "
        "would inject the cupsFilter directive into the generated PPD. "
        "When CUPS processes a print job for this printer, it executes the filter. "
        "\n"
        "Post-patch sanitization in _ppdCreateFromIPP2(): "
        "  1. ippValidateAttribute() called first — reject malformed attr "
        "  2. Loop over make[]: truncate on first char < ' ', >= 127, or == '\"' "
        "  3. Strip trailing whitespace "
        "  4. Use default if nothing remains "
        "  Also: new ppd_put_string() helper with similar sanitization for all string output "
        "\n"
        "Also adds ippValidateAttributes(response) check in scheduler/ipp.c "
        "create_local_bg_thread() — reject the entire IPP response if any "
        "attribute fails validation before PPD creation proceeds. "
        "\n"
        "Attack path (classic 2024 CUPS chain): "
        "  Attacker advertises malicious IPP printer on local network. "
        "  CUPS browsd/cups-browsed discovers it and calls _ppdCreateFromIPP2(). "
        "  Injected cupsFilter executes as root when any job is sent to the printer. "
        "\n"
        "Author: nilusyi@tencent.com — Tencent contributed this fix upstream."
    ),
    "affected_files": ["cups/ppd-cache.c", "scheduler/ipp.c"],
    "author": "nilusyi@tencent.com",
}

# ──────────────────────────────────────────────────────────────────────────────
# F02 — ipp_length() undercount heap overflow (CVE-2026-34979)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F02_IPP_LENGTH = {
    "finding_id": "TOS46-CUPS-F02",
    "severity": "HIGH",
    "cve": "CVE-2026-34979",
    "title": (
        "scheduler/job.c ipp_length() excluded MIMETYPE/NAMELANG/TEXTLANG/URI/URISCHEME "
        "from buffer size calculation; get_options() wrote them anyway — "
        "heap overflow in options buffer (cupsd root process)"
    ),
    "description": (
        "scheduler/job.c: ipp_length() computes buffer size for get_options(). "
        "get_options() writes IPP attributes as a shell options string. "
        "\n"
        "Pre-patch ipp_length() skip list: "
        "  if(attr->value_tag == IPP_TAG_NOVALUE || "
        "     attr->value_tag == IPP_TAG_MIMETYPE || "
        "     attr->value_tag == IPP_TAG_NAMELANG || "
        "     attr->value_tag == IPP_TAG_TEXTLANG || "
        "     attr->value_tag == IPP_TAG_URI || "
        "     attr->value_tag == IPP_TAG_URISCHEME) "
        "    continue; "
        "\n"
        "get_options() wrote all of these types into the buffer. "
        "Result: allocated buffer too small by the total length of all "
        "MIMETYPE + NAMELANG + TEXTLANG + URI + URISCHEME attribute values. "
        "\n"
        "Post-patch: "
        "  Remove the skip list from ipp_length() entirely. "
        "  Add TEXTLANG, NAMELANG, MIMETYPE, URISCHEME to the string-length "
        "  calculation case (same as TEXT, NAME, KEYWORD, etc.). "
        "\n"
        "Exploitability: "
        "  IPP attributes come from client job submission. "
        "  A job with large MIMETYPE or URI attributes overflows the heap buffer "
        "  allocated by get_options() in the root cupsd process. "
        "  Classic heap overflow via crafted print job."
    ),
    "affected_files": ["scheduler/job.c"],
    "ai_adaptation": "Adapted-by: PkgAgent (modified to adapt to opencloudos-stream)",
}

# ──────────────────────────────────────────────────────────────────────────────
# F03 — Control char injection in print job options (CVE-2026-34980)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F03_CTRLCHAR_INJECT = {
    "finding_id": "TOS46-CUPS-F03",
    "severity": "HIGH",
    "cve": "CVE-2026-34980",
    "title": (
        "get_options() writes IPP attribute values including control chars into "
        "shell options string — embedded newlines/tabs allow filter argument injection; "
        "update_job() allows cupsFilter/cupsFilter2 PPD keyword injection via printer response"
    ),
    "description": (
        "scheduler/job.c: two separate injection paths. "
        "\n"
        "Path 1 — get_options() attribute value sanitization: "
        "  Pre-patch: attributes with type IPP_TAG_URI etc. were written: "
        "    if(strchr(' \\t\\n\\\\\\'\\\"', *valptr)) "
        "      *optptr++ = '\\\\'; "
        "    *optptr++ = *valptr++; "
        "  This escaped space/tab/newline with backslash — but control chars "
        "  (0x00-0x1f other than \\t/\\n) were written raw. "
        "  Embedded NUL or \\r could truncate or split the options string. "
        "\n"
        "  Post-patch: "
        "    if(isspace()) → replace with single space "
        "    else if((*valptr & 255) >= ' ' && *valptr != 0x7f) → escape \\, ', \" "
        "    else → discard (control chars dropped) "
        "\n"
        "Path 2 — update_job() PPD keyword allowlist: "
        "  Pre-patch: all PPD keywords from printer update were accepted. "
        "  A printer could send cupsFilter/cupsFilter2 PPD keywords via update_job, "
        "  overriding the filter configuration for in-flight jobs. "
        "  Post-patch: explicit denylist — cupsFilter, cupsFilter2, "
        "  cupsFinishingTemplate, cupsIPPFinishings, cupsIPPReason, "
        "  cupsMarkerName, cupsMaxSize, cupsMediaQualifier*, cupsMinSize, "
        "  cupsPageSizeCategory, cupsPortMonitor, cupsPreFilter, "
        "  cupsPrintQuality, APPrinterPreset are all blocked."
    ),
    "affected_files": ["scheduler/job.c"],
    "ai_adaptation": "Adapted-by: PkgAgent (modified to adapt to opencloudos-stream)",
}

# ──────────────────────────────────────────────────────────────────────────────
# F04 — Local certificate over TCP loopback (CVE-2026-34990)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F04_LOOPBACK_CERT = {
    "finding_id": "TOS46-CUPS-F04",
    "severity": "HIGH",
    "cve": "CVE-2026-34990",
    "title": (
        "cupsd local certificate auth accepted over TCP 127.0.0.1 — "
        "httpAddrLocalhost() returns true for loopback TCP; "
        "fix: require AF_LOCAL (Unix socket) for local-certificate/PeerCred/AuthRef; "
        "also removes file:// device URI write support"
    ),
    "description": (
        "cups/auth.c cups_local_auth() + scheduler/auth.c cupsdAuthorize(): "
        "\n"
        "Pre-patch — cups_local_auth(): "
        "  if(!cups_is_local_connection(http)) return(1); "
        "  cups_is_local_connection() → httpAddrLocalhost() OR hostname == 'localhost' "
        "  httpAddrLocalhost() = TRUE for 127.0.0.1 AND ::1 (TCP loopback) "
        "  Local certificate files are written to the CUPS spool — "
        "  any process on the same machine connecting via TCP 127.0.0.1 "
        "  could present a local certificate and authenticate as root. "
        "\n"
        "Post-patch: "
        "  Removed cups_is_local_connection() entirely. "
        "  Used httpAddrFamily(httpGetAddress(http)) != AF_LOCAL "
        "  Local cert/PeerCred/AuthRef now ONLY work via Unix domain socket. "
        "\n"
        "Same fix applied in: "
        "  cupsdAuthorize() — AuthRef, PeerCred, Local branches "
        "  cupsdSendHeader() — 'trc' (try root cert) parameter "
        "  create_local_printer() — printer creation restricted to AF_LOCAL "
        "\n"
        "File device URI removal: "
        "  Pre-patch: file://, file:///path/to/output could write to arbitrary files "
        "  Post-patch: FileDevice flag required; only /dev/null and raw devices allowed "
        "  Drops O_CREAT|O_TRUNC file creation entirely — no new plain files "
        "\n"
        "Also: device-uri validation in create_local_printer — must be ipp:// or ipps:// "
        "\n"
        "Tencent: patch signed by abushwang@tencent.com; "
        "nilusyi@tencent.com in author chain. "
        "AI adaptation: Adapted-by: PkgAgent."
    ),
    "affected_files": ["cups/auth.c", "scheduler/auth.c", "scheduler/client.c", "scheduler/ipp.c", "scheduler/job.c"],
    "tencent_authors": ["nilusyi@tencent.com", "abushwang@tencent.com"],
    "ai_adaptation": "Adapted-by: PkgAgent",
}

# ──────────────────────────────────────────────────────────────────────────────
# F05 — RSS notifier path traversal (CVE-2026-34978)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F05_RSS_TRAVERSAL = {
    "finding_id": "TOS46-CUPS-F05",
    "severity": "HIGH",
    "cve": "CVE-2026-34978",
    "title": (
        "CUPS RSS notifier: notify-recipient-uri with rss://host/../../../path "
        "traverses outside spool directory; lstat() not called — symlink write "
        "to arbitrary file; fix: strstr(resource, '../') block + lstat() check"
    ),
    "description": (
        "notifier/rss.c + scheduler/ipp.c add_job_subscriptions()/create_subscriptions(): "
        "\n"
        "The CUPS RSS notifier accepts a notify-recipient-uri like: "
        "  rss://127.0.0.1/../../../etc/cron.d/pwned "
        "\n"
        "Pre-patch notifier/rss.c: "
        "  httpSeparateURI() extracts resource from URI (e.g. /../../etc/cron.d/pwned) "
        "  snprintf(filename, sizeof(filename), '%s/rss%s', cachedir, resource) "
        "  → /var/cache/cups/rss/../../etc/cron.d/pwned "
        "  Opens this path for writing with HTTP PUT (via cupsPutFile) "
        "\n"
        "No check that the resolved path stays within cachedir. "
        "No lstat() to verify the path is a regular file (not a symlink). "
        "\n"
        "Post-patch: "
        "  scheduler/ipp.c: reject resource if strstr(resource, '../') != NULL "
        "  notifier/rss.c: same check in URI parser "
        "  notifier/rss.c: lstat(filename, &fileinfo); if(!S_ISREG) → error "
        "\n"
        "Exploitability: requires creating a print subscription with a "
        "notify-recipient-uri — possible as any authenticated print user."
    ),
    "affected_files": ["notifier/rss.c", "scheduler/ipp.c"],
    "ai_adaptation": "Adapted-by: PkgAgent",
}

# ──────────────────────────────────────────────────────────────────────────────
# F06 — cupsd: IPv6 OOB + NULL deref + PeerCred config rewrite (CVE-2025-61915)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F06_CUPSD_BUGS = {
    "finding_id": "TOS46-CUPS-F06",
    "severity": "HIGH",
    "cve": "CVE-2025-61915",
    "title": (
        "cupsd: three bugs — (1) IPv6 OOB write in address handling; "
        "(2) NULL deref on empty ErrorPolicy; "
        "(3) cupsd.conf rewrite via PeerCred from domain socket (local priv-esc)"
    ),
    "description": (
        "scheduler/: Multiple fixes per CVE-2025-61915 (found by @SilverPlate3). "
        "\n"
        "Bug 1 — IPv6 OOB write: "
        "  Specific IPv6 address handling in scheduler incorrectly computed "
        "  buffer bounds for address string → out-of-bounds write. "
        "\n"
        "Bug 2 — NULL dereference: "
        "  scheduler/conf.c: if ErrorPolicy value is empty string, "
        "  subsequent pointer dereference → cupsd crash (DoS). "
        "\n"
        "Bug 3 — cupsd.conf rewrite via PeerCred (most severe): "
        "  PeerCred auth authenticates via Unix domain socket peer credentials. "
        "  An attacker with: (a) access to the CUPS domain socket, AND "
        "  (b) knowledge of a username in a CUPS system group "
        "  could invoke cupsd admin operations using that username's peer cred. "
        "  This allowed rewriting cupsd.conf — persistent configuration change "
        "  enabling further privilege escalation. "
        "\n"
        "Fix for Bug 3: "
        "  New 'PeerCred' directive in cups-files.conf (on/off/root-only). "
        "  Default: on (backward compatible). "
        "  Deployed with 'root-only' to restrict PeerCred to root-owned processes. "
        "  Build option: --with-peer-cred=[on/off/root-only]."
    ),
    "affected_files": [
        "scheduler/auth.c", "scheduler/auth.h", "scheduler/conf.c",
        "scheduler/client.c", "conf/cups-files.conf.in",
    ],
    "reporter": "@SilverPlate3",
}

# ──────────────────────────────────────────────────────────────────────────────
# F07 — Auth type bypass (CVE-2025-58060)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F07_AUTH_BYPASS = {
    "finding_id": "TOS46-CUPS-F07",
    "severity": "MEDIUM",
    "cve": "CVE-2025-58060",
    "title": (
        "cupsd: Basic auth credentials processed before checking if Basic "
        "is enabled — attacker presents Basic to Kerberos-only policy; "
        "fix: type check at top of each auth branch"
    ),
    "description": (
        "scheduler/auth.c cupsdAuthorize(): "
        "\n"
        "Pre-patch Basic branch: "
        "  Parsed and processed Basic credentials (base64 decode, PAM auth). "
        "  if(type == CUPSD_AUTH_BASIC) { /* PAM auth */ } "
        "  type check was INSIDE the branch — after credentials were parsed. "
        "\n"
        "Post-patch: "
        "  if(type != CUPSD_AUTH_BASIC) { "
        "    cupsdLogClient(con, CUPSD_LOG_ERROR, 'Basic authentication is not enabled.'); "
        "    return; "
        "  } "
        "  Added at the START of the Basic branch, before any credential processing. "
        "  Same pattern added for Kerberos/Negotiate branch. "
        "\n"
        "Impact: if a policy required only Negotiate (Kerberos) auth, "
        "a client could present Basic credentials and pass PAM authentication, "
        "bypassing the Negotiate-only policy."
    ),
    "affected_files": ["scheduler/auth.c"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F08 — Username case-insensitive group auth (CVE-2026-27447)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F08_CASE_AUTH = {
    "finding_id": "TOS46-CUPS-F08",
    "severity": "MEDIUM",
    "cve": "CVE-2026-27447",
    "title": (
        "cupsdCheckGroup() and cupsdIsAuthorized() used _cups_strcasecmp() for "
        "username/group comparison — 'Admin' matched 'admin' group member; "
        "fix: strcmp(user->pw_name, ...) against canonical pw_name from getpwnam"
    ),
    "description": (
        "scheduler/auth.c: two affected comparison sites. "
        "\n"
        "Site 1 — cupsdCheckGroup() group membership: "
        "  Pre-patch: !_cups_strcasecmp(username, group->gr_mem[i]) "
        "  Username from client HTTP request compared case-insensitively "
        "  to /etc/group membership. "
        "  'ADMIN' would match 'admin' in group lpadmin. "
        "\n"
        "Site 2 — cupsdIsAuthorized() @OWNER/@SYSTEM checks: "
        "  Pre-patch: !_cups_strcasecmp(username, ownername) for @OWNER "
        "  Pre-patch: !_cups_strcasecmp(username, name) for named user ACLs "
        "\n"
        "Post-patch: all comparisons use pw->pw_name from getpwnam() — "
        "the canonical lowercase username from the password database. "
        "UNIX usernames are case-sensitive; comparisons must match that. "
        "\n"
        "Also fixed: NULL deref — cupsdCheckGroup() checked `if(group != NULL)` "
        "but then accessed `user->pw_gid` without checking if user is NULL. "
        "Post-patch: `if(user && group)`. "
        "\n"
        "AI adaptation: Adapted-by: PkgAgent"
    ),
    "affected_files": ["scheduler/auth.c"],
    "ai_adaptation": "Adapted-by: PkgAgent",
}

# ──────────────────────────────────────────────────────────────────────────────
# F09 — Slow client DoS (CVE-2025-58436)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F09_SLOW_CLIENT = {
    "finding_id": "TOS46-CUPS-F09",
    "severity": "MEDIUM",
    "cve": "CVE-2025-58436",
    "title": (
        "Single-threaded cupsd blocks on slow clients — fix: require complete "
        "HTTP line before reading (unencrypted); complete ClientHello before "
        "TLS upgrade; introduces connection timeout; removes RFC 2817 CONNECT upgrade"
    ),
    "description": (
        "cups/http.c + scheduler/client.c: "
        "\n"
        "cupsd is single-process and single-threaded for client handling. "
        "A client that reads/writes very slowly occupies the main accept loop. "
        "\n"
        "Pre-patch: http_read() would block waiting for data from a slow/stalled client. "
        "\n"
        "Post-patch: "
        "  HTTP read buffer renamed from _buffer[HTTP_MAX_BUFFER] (65536) to "
        "    buffer[_HTTP_MAX_BUFFER] (32768) with new internal layout. "
        "  http_read() now takes a timeout parameter. "
        "  httpGets() (line reader): only proceed if a complete line is buffered. "
        "  TLS: wait for complete ClientHello before starting TLS handshake. "
        "  Connection timeout applied to slow requests. "
        "\n"
        "Side effect: RFC 2817 §3.1 CONNECT-based HTTP→HTTPS upgrade removed. "
        "\n"
        "After-fix: infinite loop in GTK+ path — "
        "  memchr condition 'has no newline AND buffer not full' was too restrictive; "
        "  replaced with simpler 'buffer not full' check."
    ),
    "affected_files": ["cups/http.c", "cups/http-private.h", "cups/tls-openssl.c", "scheduler/client.c"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F10 — IPP extension tag NULL deref (CVE-2025-58364)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F10_IPP_EXTTAG = {
    "finding_id": "TOS46-CUPS-F10",
    "severity": "MEDIUM",
    "cve": "CVE-2025-58364",
    "title": (
        "cups/ipp.c ipp_read_io(): IPP_TAG_EXTENSION handling could leave "
        "corrupted tag state causing NULL dereference downstream — "
        "fix: remove 32-bit extension tag code path entirely; add error on name read fail"
    ),
    "description": (
        "cups/ipp.c ipp_read_io() — IPP binary protocol parser. "
        "\n"
        "IPP_TAG_EXTENSION (0x7f) signals a 4-byte extended tag. "
        "The code read 4 more bytes and assembled the extended tag. "
        "If the extended tag had IPP_TAG_CUPS_CONST set (high bit), it failed. "
        "Otherwise the extended tag was used for subsequent processing. "
        "\n"
        "The extension tag path left the parser in a state where subsequent "
        "code expecting a normal 1-byte tag would process the extended value "
        "incorrectly, leading to NULL dereference in attribute name handling. "
        "\n"
        "Fix: Remove the entire IPP_TAG_EXTENSION code path (25 lines deleted). "
        "CUPS doesn't implement extended tags; the dead code was attack surface. "
        "\n"
        "Also adds: error message when attribute name read fails "
        "(was silently logging DEBUG, now sets _cupsSetError). "
        "\n"
        "Reporter: Thorsten Alteholz (Debian)."
    ),
    "affected_files": ["cups/ipp.c"],
    "reporter": "Thorsten Alteholz",
}

# ──────────────────────────────────────────────────────────────────────────────
# F11 — PostScript lone backslash OOB (CVE-2023-4504)
# ──────────────────────────────────────────────────────────────────────────────

CUPS_F11_PS_BACKSLASH = {
    "finding_id": "TOS46-CUPS-F11",
    "severity": "INFO",
    "cve": "CVE-2023-4504",
    "title": (
        "cups/raster-interpret.c scan_ps(): backslash at end of buffer "
        "not checked for NUL — lone backslash at end of PostScript string "
        "reads one byte past buffer end"
    ),
    "description": (
        "cups/raster-interpret.c scan_ps() — PostScript token scanner. "
        "\n"
        "When scanning a string literal, an escaped character sequence "
        "(backslash + char) was processed as: "
        "  cur++; "
        "  if(*cur == 'b') *valptr++ = '\\b'; "
        "  else if(*cur == 'f') ... "
        "\n"
        "If the buffer ended with a lone backslash (NUL at cur+1), "
        "the code read the NUL byte and fell through all the escape cases, "
        "then continued the outer loop reading past the buffer end. "
        "\n"
        "Post-patch: checks !*cur after incrementing, sets *ptr = NULL and "
        "returns NULL (invalid PostScript). "
        "\n"
        "Conflict: Patch context adaptation noted (minor offset changes)."
    ),
    "affected_files": ["cups/raster-interpret.c"],
}

# ──────────────────────────────────────────────────────────────────────────────
# RELEASE DELTA TABLE
# ──────────────────────────────────────────────────────────────────────────────

RELEASE_DELTA = {
    "cups-2.4.6-9.tl4": {
        "cve_patches": 6,
        "cves": [
            "CVE-2024-47175", "CVE-2023-4504",
            "CVE-2025-58436 (2-patch)", "CVE-2025-61915",
            "CVE-2025-58060", "CVE-2025-58364",
        ],
    },
    "cups-2.4.6-10.tl4": {
        "cve_patches": 1,
        "new_cves": ["CVE-2026-27447"],
    },
    "cups-2.4.6-11.tl4": {
        "cve_patches": 4,
        "new_cves": ["CVE-2026-34978", "CVE-2026-34979", "CVE-2026-34980", "CVE-2026-34990"],
    },
    "total_cve_patches": 11,
    "cve_years": {"2023": 1, "2024": 1, "2025": 4, "2026": 5},
    "tencent_upstream": ["nilusyi@tencent.com", "abushwang@tencent.com"],
    "ai_adapted_patches": 5,
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-CUPS-F01": CUPS_F01_PPD_INJECT,
    "TOS46-CUPS-F02": CUPS_F02_IPP_LENGTH,
    "TOS46-CUPS-F03": CUPS_F03_CTRLCHAR_INJECT,
    "TOS46-CUPS-F04": CUPS_F04_LOOPBACK_CERT,
    "TOS46-CUPS-F05": CUPS_F05_RSS_TRAVERSAL,
    "TOS46-CUPS-F06": CUPS_F06_CUPSD_BUGS,
    "TOS46-CUPS-F07": CUPS_F07_AUTH_BYPASS,
    "TOS46-CUPS-F08": CUPS_F08_CASE_AUTH,
    "TOS46-CUPS-F09": CUPS_F09_SLOW_CLIENT,
    "TOS46-CUPS-F10": CUPS_F10_IPP_EXTTAG,
    "TOS46-CUPS-F11": CUPS_F11_PS_BACKSLASH,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "packages": ["cups-2.4.6-9.tl4", "cups-2.4.6-10.tl4", "cups-2.4.6-11.tl4"],
        "tencent_upstream_authors": RELEASE_DELTA["tencent_upstream"],
        "ai_adapted_patches": RELEASE_DELTA["ai_adapted_patches"],
        "findings": [
            {
                "id": k,
                "cve": v.get("cve"),
                "severity": v.get("severity"),
                "title": v.get("title", "")[:80],
            }
            for k, v in FINDINGS.items()
        ],
        "release_delta": RELEASE_DELTA,
    }, indent=2))
