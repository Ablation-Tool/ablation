"""
TencentOS 2.4 (TLinux 2) — cups-1.6.3, dovecot-2.2.36, compat-libtiff3-3.9.4 SRPM RE.

Sources from Drive: tencent-re/2.4/tlinux-srpms/
  cups-1.6.3-52.tl2.1.src.rpm
  dovecot-2.2.36-8.tl2.2.src.rpm
  compat-libtiff3-3.9.4-12.tl2.2.src.rpm

All three continue active security patching on TOS 2.4 post RHEL 7 EoL (Jun 2024).
Most recent patches: cups Sep 2025, dovecot Jul 2026, libtiff Apr 2026.
"""

# ── cups-1.6.3-52.tl2.1 ──────────────────────────────────────────────────────

CUPS_PACKAGE = {
    "package": "cups-1.6.3-52.tl2.1",
    "upstream": "Apple CUPS 1.6.3",
    "base": "RHEL 7 cups-1.6.3-52",
    "license": "LGPLv2 with exceptions",
    "maintainer": "Bryan Mason <bmason@redhat.com> (Red Hat)",
    "latest_revision": ".1 (Sep 23 2025)",
    "eos_note": "RHEL 7 EoL Jun 2024; this is a Sep 2025 security update — 15 months post-EoL",
}

CVE_2025_58060 = {
    "id": "CVE-2025-58060",
    "revision": ".1 (Sep 23 2025)",
    "author": "Bryan Mason <bmason@redhat.com>",
    "title": "Authentication bypass in CUPS authorization handling",
    "file": "scheduler/auth.c",
    "root_cause": (
        "cupsdAuthorize() handles multiple authentication types in a switch statement. "
        "The `default:` case fell through into `case CUPSD_AUTH_BASIC:` — C switch fallthrough. "
        "A client sending credentials in a format that triggered the `default:` branch "
        "would still have those credentials processed by the PAM authentication path "
        "intended only for CUPSD_AUTH_BASIC requests. "
        "Similarly: the Negotiate (Kerberos/GSSAPI) path had no check that the incoming "
        "request actually requested Negotiate auth — any auth type could reach the "
        "GSSAPI token processing code."
    ),
    "fix": (
        "default: case now logs 'Basic authentication is not enabled' and returns immediately. "
        "case CUPSD_AUTH_BASIC: is its own case, no longer reachable via fallthrough. "
        "Kerberos path: adds early check 'if (type != CUPSD_AUTH_NEGOTIATE) { log; return; }' "
        "before GSSAPI token processing."
    ),
    "patch_diff_key": (
        "Before: default: <falls through> case CUPSD_AUTH_BASIC: { PAM code } "
        "After:  default: { log error; return; } case CUPSD_AUTH_BASIC: { PAM code }"
    ),
    "severity": "HIGH",
    "impact": (
        "CUPS authentication type enforcement bypass. Affects systems using "
        "Kerberos/GSSAPI or restricted auth modes — an unauthenticated client "
        "may authenticate via the wrong code path."
    ),
}

CVE_2023_32360 = {
    "id": "CVE-2023-32360",
    "revision": "52.tl2 base (backported from upstream)",
    "title": "Information leak through Cups-Get-Document operation",
    "file": "conf/cupsd.conf.in",
    "root_cause": (
        "CUPS-Get-Document was grouped with other IPP operations under a single "
        "<Limit> block requiring @OWNER @SYSTEM. The IPP Get-Document operation "
        "returns the raw document data for a print job. The shared Limit block "
        "had a configuration that inadvertently allowed access without proper "
        "AuthType Default enforcement — allowing authentication bypass for "
        "document retrieval."
    ),
    "fix": (
        "CUPS-Get-Document split into its own <Limit CUPS-Get-Document> block "
        "with explicit AuthType Default + Require user @OWNER @SYSTEM. "
        "The remaining operations stay in the original Limit block without "
        "the explicit AuthType setting."
    ),
    "severity": "MEDIUM — print job content disclosure",
}

CUPS_FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2025-58060",
        "title": "CUPS auth type enforcement bypass — default: fallthrough into Basic auth path",
        "detail": (
            "scheduler/auth.c: switch(type) default case falls through to CUPSD_AUTH_BASIC. "
            "Fixed by separating default (return) from Basic auth case. "
            "Kerberos path also lacked type enforcement. "
            "Sep 2025 patch — 15 months post RHEL 7 EoL."
        ),
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "cve": "CVE-2023-32360",
        "title": "CUPS-Get-Document information leak — auth not enforced for document retrieval",
        "detail": (
            "cupsd.conf.in: CUPS-Get-Document split from shared Limit block. "
            "Now requires explicit AuthType Default. "
            "Without this fix, any user could retrieve document data for other users' print jobs."
        ),
    },
]

# ── dovecot-2.2.36-8.tl2.2 ───────────────────────────────────────────────────

DOVECOT_PACKAGE = {
    "package": "dovecot-2.2.36-8.tl2.2",
    "upstream": "Dovecot 2.2.36 (IMAP/POP3 server, Open-Xchange)",
    "base": "RHEL 7 dovecot-2.2.36-8",
    "license": "MIT and LGPLv2",
    "maintainers": [
        "Michal Hlavinka <mhlavink@redhat.com>",
        "Stepan Broz <sbroz@redhat.com>",
        "Kiran Belle <kbelle@redhat.com>",
    ],
    "latest_revision": ".2 (Jul 28 2026)",
    "eos_note": "RHEL 7 EoL Jun 2024; Jul 2026 patch — 25 months post-EoL",
    "security_cluster": (
        "5 CVEs patched May-Jul 2026. All in the IMAP parser, ManageSieve, or doveadm API. "
        "Common theme: pre-auth DoS and timing-safe comparison failures."
    ),
}

CVE_2026_42006 = {
    "id": "CVE-2026-42006",
    "revision": ".2 (Jul 28 2026)",
    "author": "Timo Sirainen <timo.sirainen@open-xchange.com>",
    "title": "IMAP parser list_count_limit counts ')' instead of '(' — bypass",
    "file": "src/lib-imap/imap-parser.c",
    "root_cause": (
        "A previous fix for CVE-2026-27857 (deeply nested IMAP lists) added "
        "`list_count_limit` enforcement in `imap_parser_close_list()` — triggered on ')'. "
        "IMAP lists open with '(' and close with ')'. The limit was supposed to cap "
        "how many nested lists can be opened, but checking on ')' means: "
        "send N '(' without corresponding ')' → limit not enforced; "
        "send N nested empty lists '()()()...' → limit triggered on ')' but still allows "
        "deeply nested '((((...))))' to open unboundedly before any ')' is seen. "
        "The fix moves the check to `imap_parser_open_list()` — triggered on '('. "
        "list_count++ on '(' open; if count >= limit before opening: reject."
    ),
    "fix": (
        "imap_parser_open_list() returns bool; checks list_count >= list_count_limit "
        "before creating the list argument. "
        "imap_parser_close_list() removes the old (wrong) limit check. "
        "list_count increments on open, not close."
    ),
    "severity": "MEDIUM — pre-auth DoS via crafted IMAP command with nested lists",
}

CVE_2026_27857 = {
    "id": "CVE-2026-27857",
    "revision": ".1 (May 21 2026)",
    "author": "Timo Sirainen (Dovecot upstream)",
    "title": "Denial of service via deeply nested IMAP list structures — 5-patch series",
    "root_cause": (
        "imap_parser_create() accepted a `params` argument but it was unused (ATTR_UNUSED). "
        "The `imap_parser_params` struct had a `list_count_limit` field that did nothing. "
        "An unauthenticated client could send an IMAP command with deeply nested lists "
        "(((((((...))))))) and exhaust server memory parsing them."
    ),
    "fix_series": {
        "patch 1/5": "Update all callers of imap_parser_create() to pass NULL for params (preparation)",
        "patch 2/5": (
            "Add list_count and list_count_limit fields to imap_parser struct. "
            "imap_parser_create() now actually reads params.list_count_limit. "
            "Defaults to UINT_MAX if no params or limit=0."
        ),
        "patch 3/5": (
            "imap-login callers: set IMAP_LOGIN_LIST_COUNT_LIMIT=1 via imap_parser_params. "
            "Pre-auth parsers for CMD_ID, client creation, STARTTLS all get limit=1. "
            "After auth, limit is uncapped (normal IMAP commands need nested lists)."
        ),
        "patch 4/5": "const correctness: imap_parser_params structs made const",
        "patch 5/5": "Apply limit to Pigeonhole (Sieve filter) parser callers",
    },
    "severity": "HIGH — pre-auth memory exhaustion DoS; unauthenticated, no login required",
}

CVE_2026_27858 = {
    "id": "CVE-2026-27858",
    "revision": ".1 (May 21 2026)",
    "title": "ManageSieve: denial of service via crafted message before authentication",
    "file": "dovecot-2.2-pigeonhole/src/managesieve-login/client-authenticate.c",
    "root_cause": (
        "ManageSieve AUTHENTICATE command reads SASL initial response from the client. "
        "The code called `i_stream_get_size()` to get the response size but had no upper bound. "
        "A client could send a very large initial SASL response before authentication "
        "completes, causing unbounded memory allocation."
    ),
    "fix": (
        "After `i_stream_get_size()`, check `if (resp_size > LOGIN_MAX_AUTH_BUF_SIZE)`. "
        "If exceeded: call client_destroy('Authentication response too large'); return -1. "
        "LOGIN_MAX_AUTH_BUF_SIZE is a compile-time constant limiting pre-auth buffer."
    ),
    "severity": "HIGH — pre-auth DoS; ManageSieve port 4190",
}

CVE_2026_27856 = {
    "id": "CVE-2026-27856",
    "revision": ".1 (May 21 2026)",
    "title": "doveadm HTTP API credentials not checked using timing-safe comparison",
    "files": [
        "src/doveadm/client-connection.c",
        "src/doveadm/client-connection-http.c",
        "src/lib/strfuncs.c",
    ],
    "root_cause": (
        "doveadm TCP client: compared password with "
        "`strlen(pass) != strlen(conn->set->doveadm_password) || "
        "!mem_equals_timing_safe(pass, ...)`. "
        "The strlen comparison short-circuits before the timing-safe check — "
        "if password lengths differ, it returns immediately, leaking length via timing. "
        "doveadm HTTP client: used `strcmp(creds.data, str_c(b64_value))` — "
        "completely non-timing-safe, leaks password bit by bit. "
        "Also: HTTP API used `doveadm_settings->doveadm_api_key` (global settings) "
        "instead of `conn->client.set->doveadm_api_key` (connection settings). "
        "If multiple connections or scoped settings exist, wrong key checked."
    ),
    "fix": (
        "New function: str_equals_timing_almost_safe(s1, s2) — wraps mem_equals_timing_safe "
        "to handle variable-length strings. Handles NULL. Always compares full length. "
        "TCP client: replaced with str_equals_timing_almost_safe. "
        "HTTP client (Basic): str_equals_timing_almost_safe(str_c(b64_value), creds.data). "
        "HTTP client (X-Dovecot-API): same. Settings bug also fixed."
    ),
    "severity": "MEDIUM — timing oracle on doveadm admin credentials (password oracle attack)",
}

CVE_2025_59032 = {
    "id": "CVE-2025-59032",
    "revision": ".1 (May 21 2026)",
    "title": "ManageSieve SASL: wrong args passed for unfinished command continuation",
    "file": "dovecot-2.2-pigeonhole/src/managesieve-login/client.c",
    "root_cause": (
        "ManageSieve client input handler: "
        "if args[0].type != MANAGESIEVE_ARG_EOL: parse args, ret = cmd->func(client, args). "
        "else: was calling cmd->func(client, args) with the EOL args — wrong. "
        "For unfinished commands (initial SASL response in AUTHENTICATE), the "
        "continuation call should pass NULL to signal 'no new args, continue'. "
        "Passing EOL args instead caused the command function to misinterpret its state, "
        "leading to denial of service via crafted multi-step AUTHENTICATE exchange."
    ),
    "fix": (
        "else branch (EOL case): calls cmd->func(client, NULL) — "
        "explicit NULL signals 'continue unfinished command'."
    ),
    "severity": "HIGH — pre-auth DoS; ManageSieve AUTHENTICATE command",
}

DOVECOT_FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2026-27857",
        "title": "Pre-auth memory exhaustion via deeply nested IMAP lists — 5-patch series",
        "detail": (
            "imap_parser_params.list_count_limit was unimplemented (ATTR_UNUSED). "
            "5-patch series adds real enforcement: list_count field + check on '(' open. "
            "Login process capped at 1 nested list (IMAP_LOGIN_LIST_COUNT_LIMIT=1). "
            "Affects all IMAP ports (143/993). Unauthenticated."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2025-59032",
        "title": "ManageSieve AUTHENTICATE continuation sends wrong args — pre-auth DoS",
        "detail": (
            "Unfinished command continuation passed EOL args instead of NULL. "
            "Multi-step AUTHENTICATE (SASL) could crash/hang ManageSieve process. "
            "Port 4190. Unauthenticated."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2026-27858",
        "title": "ManageSieve: no SASL response size limit — pre-auth memory DoS",
        "detail": (
            "AUTHENTICATE command: unbounded SASL initial response accepted. "
            "Fix: resp_size > LOGIN_MAX_AUTH_BUF_SIZE → destroy connection. "
            "Port 4190. Unauthenticated."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "cve": "CVE-2026-27856",
        "title": "doveadm credentials not timing-safe — password oracle attack",
        "detail": (
            "TCP: strlen short-circuit before timing-safe check leaks password length. "
            "HTTP: strcmp leaks password directly. "
            "Also: HTTP API used wrong settings source for api_key. "
            "Fix: str_equals_timing_almost_safe() in all credential comparison paths."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "cve": "CVE-2026-42006",
        "title": "IMAP list count limit counts ')' not '(' — bypass of CVE-2026-27857 fix",
        "detail": (
            "list_count_limit check in close_list() triggered on ')' — wrong side. "
            "Deep '((((' opens bypass the limit since no ')' was sent yet. "
            "Fix: check moved to open_list() — checked on '(' before creating nested list. "
            "Jul 2026 — this is a bypass of the prior fix, shipped one month later."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "TOS 2.4 dovecot 2.2.36 receives 2026 security patches — 25 months post RHEL 7 EoL",
        "detail": (
            "dovecot-2.2.36 is a 2018-era Dovecot build. Latest patch Jul 28 2026. "
            "All 5 CVEs are pre-auth vectors — no credentials needed to trigger. "
            "ManageSieve (port 4190) is a secondary attack surface alongside IMAP. "
            "TOS 2.4 dovecot has an independent patch lifecycle not tied to RHEL/Fedora."
        ),
    },
]

# ── compat-libtiff3-3.9.4-12.tl2.2 ──────────────────────────────────────────

LIBTIFF_PACKAGE = {
    "package": "compat-libtiff3-3.9.4-12.tl2.2",
    "upstream": "libtiff 3.9.4 (2011)",
    "base": "RHEL 7 compat-libtiff3-3.9.4-12",
    "license": "libtiff",
    "maintainers": [
        "Stepan Broz <sbroz@redhat.com>",
        "Therese Cornell <tcornell@redhat.com>",
    ],
    "latest_revision": ".2 (Apr 24 2026)",
    "eos_note": "libtiff 3.9.4 is a 2011 library; TOS 2.4 ships it as a compat package. "
                "2026 patches applied — 22 months post RHEL 7 EoL.",
    "context": (
        "compat-libtiff3 provides libtiff.so.3 for applications that predate the "
        "libtiff 4.x API changes. Any 32-bit or legacy application on TOS 2.4 linking "
        "libtiff.so.3 is affected. This library processes attacker-controlled TIFF files."
    ),
}

CVE_2025_9900 = {
    "id": "CVE-2025-9900",
    "revision": ".1 (Oct 2 2025)",
    "author": "Stepan Broz <sbroz@redhat.com>",
    "title": "Write-What-Where via TIFFReadRGBAImageOriented — raster pointer before buffer start",
    "file": "libtiff/tif_getimage.c",
    "root_cause": (
        "TIFFReadRGBAImageOriented(tif, rwidth, rheight, raster, orientation, stop): "
        "caller allocates raster = malloc(rwidth * rheight * sizeof(uint32)). "
        "Original code called: "
        "  TIFFRGBAImageGet(&img, raster+(rheight-img.height)*rwidth, rwidth, img.height) "
        "If rheight > img.height: (rheight-img.height)*rwidth is positive → "
        "  ptr starts partway into the raster buffer (normal, places image at bottom). "
        "If rheight < img.height: (rheight-img.height) wraps as unsigned → "
        "  ptr before the raster buffer start — writes TIFF pixel data to arbitrary memory. "
        "An attacker supplying a TIFF file with img.height > rheight triggers OOB write. "
        "The raster pointer is passed as-is into pixel rendering functions that "
        "write decoded pixels — classic Write-What-Where."
    ),
    "fix": (
        "TIFFReadRGBAImageOriented() now calls TIFFRGBAImageGet(&img, raster, rwidth, rheight). "
        "Bounds enforcement moved into TIFFRGBAImageGet(): "
        "  if h > img->height: raster += (h - img->height) * w; h = img->height; "
        "  if w > img->width: warn; w = img->width; "
        "No longer possible to pass a before-the-buffer pointer."
    ),
    "severity": "HIGH — OOB write with attacker-controlled TIFF content",
}

CVE_2026_4775 = {
    "id": "CVE-2026-4775",
    "revision": ".2 (Apr 24 2026)",
    "author": "Therese Cornell <tcornell@redhat.com>",
    "title": "Signed integer overflow in putcontig8bitYCbCr YUV tile rendering functions",
    "file": "libtiff/tif_getimage.c",
    "root_cause": (
        "YCbCr tiled TIFF rendering functions (putcontig8bitYCbCr44tile, 42tile, 22tile, 12tile) "
        "compute `incr` as: "
        "  int32 incr = 3*w + 4*toskew;   // in putcontig8bitYCbCr44tile "
        "  int32 incr = 2*toskew + w;      // in 42tile/22tile/12tile "
        "Both w (image width) and toskew (row stride adjustment) are int32. "
        "For a large TIFF: w=65535, toskew=65535 → 3*65535+4*65535 = 458745 → fits int32. "
        "But w=268435456, toskew=268435456 → overflow. "
        "incr is used as a pixel pointer increment — overflow causes "
        "the rendering loop to compute incorrect destination addresses, writing "
        "decoded YCbCr pixels to wrong memory locations."
    ),
    "fix": (
        "incr changed from int32 to int64 in all four YCbCr tile functions: "
        "  const int64 incr = 3 * (int64)w + 4 * (int64)toskew; "
        "  const int64 incr = 2 * (int64)toskew + w; "
        "Explicit cast to int64 before multiplication prevents overflow. "
        "Four functions patched: putcontig8bitYCbCr44tile, 42tile, 22tile, 12tile."
    ),
    "severity": "HIGH — integer overflow → OOB write on crafted TIFF YCbCr tiles",
}

LIBTIFF_FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2025-9900",
        "title": "Write-What-Where — TIFFReadRGBAImageOriented passes pre-buffer pointer",
        "detail": (
            "libtiff/tif_getimage.c: raster+(rheight-img.height)*rwidth wraps when "
            "img.height > rheight — pointer before raster buffer. "
            "Pixel rendering writes TIFF data to arbitrary memory. "
            "Fix: bounds checking moved inside TIFFRGBAImageGet, raster passed as-is."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2026-4775",
        "title": "int32 incr overflow in YCbCr tile functions — 4 functions patched",
        "detail": (
            "putcontig8bitYCbCr44/42/22/12tile: incr=3*w+4*toskew as int32 overflows "
            "for large TIFF dimensions. Fix: int64 incr with explicit (int64) cast. "
            "Apr 2026 patch — libtiff 3.9.4 from 2011, still maintained in TOS 2.4."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "compat-libtiff3 3.9.4 (2011) receives 2026 patches — 22 months post RHEL 7 EoL",
        "detail": (
            "libtiff 3.9.4 is 15+ years old. TOS 2.4 ships it as a compat library "
            "for legacy application compatibility. 2 security patches in 2025-2026. "
            "Any application on TOS 2.4 that processes TIFF files via the compat library "
            "is exposed to both CVEs on unpatched versions."
        ),
    },
]

# ── dhcp-4.2.5-83.tl2.2.1 ─────────────────────────────────────────────────────

DHCP_PACKAGE = {
    "package": "dhcp-4.2.5-83.tl2.2.1",
    "upstream": "ISC DHCP 4.2.5",
    "base": "RHEL 7 dhcp-4.2.5-83 → CentOS 7 rebrand → TencentOS rebrand",
    "license": "ISC",
    "tl2_maintainer": "Haitao Huang <kaeyahuang@tencent.com>",
    "tl2_patch": "Rebranding — package renamed from centos/rhel to tencentos identifiers",
    "changelog_note": "Reference to Dorischao — internal reviewer/approver name in changelog",
    "security_note": (
        "No Tencent-authored security patches. Last ISC DHCP security fix: "
        "CVE-2021-25217 (buffer over-read in DHCP client option parsing). "
        "DHCP 4.2 is EoL upstream but TOS 2.4 continues shipping it for RHEL 7 compatibility. "
        "The .tl2.2.1 rebuild was triggered by bind ABI changes from CVE-2023-50387 — "
        "DHCP links against bind libraries."
    ),
}

DHCP_FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "cve": "CVE-2021-25217",
        "title": "DHCP client option parsing buffer over-read — last ISC security fix",
        "detail": (
            "CVE-2021-25217: dhclient buffer over-read in option handling. "
            "Fixed in base RHEL 7 build. No additional security patches in TOS 2.4. "
            "The tl2.2.1 rebuild (Jun 2024) updated only for bind ABI compatibility."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "ISC DHCP 4.2.5 is EoL — no upstream security fixes possible",
        "detail": (
            "ISC DHCP 4.2 reached end-of-life in 2022. Any future DHCPv4/DHCPv6 "
            "vulnerabilities will not receive upstream patches. "
            "TOS 2.4 organizations should plan migration to Kea DHCP."
        ),
    },
]

# ── Master findings ───────────────────────────────────────────────────────────

ALL_PACKAGES = {
    "cups-1.6.3-52.tl2.1": CUPS_FINDINGS,
    "dovecot-2.2.36-8.tl2.2": DOVECOT_FINDINGS,
    "compat-libtiff3-3.9.4-12.tl2.2": LIBTIFF_FINDINGS,
    "dhcp-4.2.5-83.tl2.2.1": DHCP_FINDINGS,
}

if __name__ == '__main__':
    print("TOS 2.4 — cups / dovecot / compat-libtiff3 / dhcp RE")
    print()
    for pkg, findings in ALL_PACKAGES.items():
        print(f"  {pkg}:")
        for f in findings:
            cve = f.get('cve', '')
            label = f"{cve} " if cve else ""
            print(f"    [{f['severity']:8s}] {f['id']}: {label}{f['title'][:60]}")
        print()
