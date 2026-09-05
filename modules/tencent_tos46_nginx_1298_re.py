"""
TencentOS 4.6 — nginx 1.29.8 SRPM security RE.

Source: srpm_work/nginx-1.29.8-1.tl4.ap.1/
Method: patch file analysis + spec changelog CVE enumeration

Version jump from previous analysis (nginx-1.26.3) to 1.29.8 (mainline branch).
5 individual CVE patches + CVEs fixed by version upgrade.

Relationship to tencent_tos46_srpm_security_stack_re.py:
  That module analyzed nginx-1.26.3 with CVE-2026-42055. This module covers
  the 1.29.8 update which adds 4 more CVE patches and numerous CVEs via version bump.
"""

PACKAGE = {
    "name": "nginx",
    "version": "1.29.8",
    "release": "1.tl4.ap.1",
    "prior_version_analyzed": "1.26.3",
    "branch": "mainline (1.29.x)",
    "patches": 5,
}

CVE_PATCHES = {
    "CVE-2026-42945": {
        "patch": "nginx-1.29.8-CVE-2026-42945.patch",
        "file": "src/http/ngx_http_script.c",
        "function": "ngx_http_script_regex_end_code",
        "severity": "HIGH",
        "title": "Rewrite: is_args flag not cleared after URL-with-args rewrite → heap buffer overrun",
        "description": (
            "In ngx_http_script_regex_end_code(), when a rewrite directive replaces the URI "
            "with a string containing arguments (e.g., 'rewrite ^(.*) /new?c=1;'), "
            "the e->is_args flag is set to indicate arguments are present. "
            "If a capture variable ($1) is then evaluated in a subsequent 'set' or 'if' block, "
            "the stale e->is_args causes URL escaping to be applied to the capture value "
            "before writing it to the output buffer. "
            "The buffer was allocated by ngx_http_script_complex_value_code() without expecting "
            "escaping overhead — the escaped output can exceed the buffer size, causing "
            "heap buffer overrun (possible segfault/code execution). "
            "Fix: add 'e->is_args = 0;' at the start of ngx_http_script_regex_end_code() "
            "to clear the flag when regex matching ends. "
            "Reporter: Leo Lin."
        ),
        "trigger_config": (
            "location / { "
            "  rewrite ^(.*) /new?c=1; "
            "  set $myvar $1; "
            "  return 200 $myvar; "
            "}"
        ),
        "pre_auth": True,
        "class": "heap-buffer-overflow",
    },
    "CVE-2026-9256": {
        "patch": "nginx-1.29.8-CVE-2026-9256.patch",
        "file": "src/http/ngx_http_script.c",
        "function": "ngx_http_script_regex_start_code",
        "severity": "HIGH",
        "title": "Rewrite: overlapping capture groups undercount buffer size → heap buffer overflow",
        "description": (
            "In ngx_http_script_regex_start_code(), when a rewrite replacement has no variable "
            "parts (code->lengths == NULL) but does have overlapping captures, the buffer size "
            "calculation fails to account for the full expanded capture length. "
            "The bug is triggered when either 'redirect' is specified or query arguments are "
            "present in the replacement string. "
            "Original code: 'e->buf.len += r->captures[n+1] - r->captures[n]' for n in ncaptures. "
            "With overlapping captures (e.g., '^/((.*))$'), this sum can be less than the actual "
            "replacement length — heap buffer overflow on write. "
            "Fix: compute buffer size using local cap[] and p pointer to avoid capture overlap, "
            "and remove the old URI-escaping branch (superseded by direct capture computation). "
            "Reporter: Mufeed VH (Winfunc Research)."
        ),
        "trigger_config": (
            "location / { "
            "  rewrite ^/((.*))$ http://127.0.0.1:8080/$1$2 redirect; "
            "  return 200 foo; "
            "}"
            " — URI: /++++++++++++++++++++++++++++++"
        ),
        "pre_auth": True,
        "class": "heap-buffer-overflow",
    },
    "CVE-2026-40701": {
        "patch": "nginx-1.29.8-CVE-2026-40701.patch",
        "file": "src/event/ngx_event_openssl_stapling.c",
        "function": "ngx_ssl_ocsp_done / ngx_ssl_ocsp_request / ngx_ssl_ocsp_resolve_handler",
        "severity": "HIGH",
        "title": "OCSP stapling: resolver context UAF when SSL connection closes during DNS resolution",
        "description": (
            "In the OCSP stapling path, when a client SSL connection is terminated (e.g., timeout) "
            "while the resolver is still resolving the OCSP responder's hostname, "
            "ngx_ssl_ocsp_done() frees the OCSP context (ngx_ssl_ocsp_ctx_t) but does NOT "
            "call ngx_resolve_name_done() to cancel the outstanding DNS resolution. "
            "When the resolver later calls ngx_ssl_ocsp_resolve_handler() with the result, "
            "the callback accesses the already-freed OCSP context — use-after-free. "
            "Fix: add 'ngx_resolver_ctx_t *resolve' field to ngx_ssl_ocsp_ctx_t; "
            "set ctx->resolve = resolve before ngx_resolve_name(); "
            "in ngx_ssl_ocsp_done(), call ngx_resolve_name_done(ctx->resolve) if non-NULL; "
            "in resolve_handler(), set ctx->resolve = NULL before calling connect or error. "
            "Affected: servers with OCSP stapling enabled (ssl_stapling on). "
            "Reporter: Leo Lin."
        ),
        "requires": "ssl_stapling on; (not default — must be explicitly configured)",
        "pre_auth": True,
        "class": "use-after-free",
    },
    "CVE-2026-42055": {
        "patch": "nginx-1.29.8-CVE-2026-42055.patch",
        "severity": "HIGH",
        "title": "HTTP/2 and gRPC header length limit — heap buffer overflow (also in 1.26.3 analysis)",
        "description": (
            "Documented in tencent_tos46_srpm_security_stack_re.py under nginx-1.26.3. "
            "Carried forward into 1.29.8. "
            "Ported by PkgAgent/deepseek-v4 (AI-authored CVE port, instance 5)."
        ),
        "class": "heap-buffer-overflow",
    },
    "CVE-2026-42533": {
        "patch": "nginx-1.29.8-CVE-2026-42533.patch",
        "file": "src/http/ngx_http_variables.c",
        "function": "ngx_http_regex_exec",
        "severity": "MEDIUM",
        "title": "Regex ncaptures not reset on realloc → uninitialized memory read in subrequests",
        "description": (
            "In ngx_http_regex_exec(), when r->captures is reallocated (r->realloc_captures set), "
            "r->ncaptures is NOT reset to 0. If the regex does not match, ncaptures retains "
            "its previous value (from the main request). "
            "A subsequent subrequest (e.g., slice directive) that uses a named regex capture "
            "will use the stale ncaptures to index into the freshly-allocated (uninitialized) "
            "captures array — uninitialized memory read, potential info disclosure or buffer overrun. "
            "Trigger: 'volatile' map directive + slice + regex capture in same request path. "
            "Fix: one-line: add 'r->ncaptures = 0;' when realloc_captures is true, before realloc. "
            "Bug introduced by commit 746fba0d79c6. "
            "Author: Pavel Pautov (F5)."
        ),
        "trigger_config": (
            "map test $my_map { volatile; ~mismatch(.*) 1; default ''; } "
            "location ~(.*) { slice 50; proxy_set_header Test $my_map$1; "
            "proxy_set_header Range $slice_range; proxy_pass http://backend; }"
        ),
        "pre_auth": True,
        "class": "uninitialized-memory-read",
    },
}

VERSION_BUMP_CVES = {
    "from": "1.26.3",
    "to": "1.29.8",
    "fixed_by_upgrade": [
        "CVE-2025-53859",
        "CVE-2026-28755",
        "CVE-2026-28753",
        "CVE-2026-27784",
        "CVE-2026-27654",
        "CVE-2026-32647",
        "CVE-2026-27651",
        "CVE-2026-1642",
    ],
    "note": "Listed in spec changelog without patch files; fixed by nginx mainline version bump.",
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2026-42945",
        "title": "nginx rewrite: is_args flag not cleared → capture buffer overrun (pre-auth)",
        "detail": (
            "ngx_http_script_regex_end_code: e->is_args not cleared after rewrite with args. "
            "Subsequent $1 capture evaluated with unexpected escaping → output exceeds allocation. "
            "Fix: e->is_args = 0 at function start. Pre-auth via HTTP request. HIGH severity."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2026-9256",
        "title": "nginx rewrite: overlapping capture size undercount → heap buffer overflow (pre-auth)",
        "detail": (
            "ngx_http_script_regex_start_code: buffer size loop undercounts overlapping captures. "
            "Triggered by ^/((.*))$ with redirect/args. Heap overflow writing replacement. "
            "PoC URI: /++++++++++++++++++++++++++++++"
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2026-40701",
        "title": "nginx OCSP stapling: resolver UAF when SSL connection closes mid-resolve (pre-auth)",
        "detail": (
            "ngx_ssl_ocsp_ctx freed without cancelling outstanding DNS resolve. "
            "Resolver callback fires on freed context — UAF. Requires ssl_stapling on. "
            "Fix: ngx_resolve_ctx_t *resolve stored in OCSP ctx, cancelled in cleanup path."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "cve": "CVE-2026-42533",
        "title": "nginx regex ncaptures stale in subrequests → uninitialized read (pre-auth)",
        "detail": (
            "ngx_http_regex_exec: r->ncaptures not zeroed on captures realloc when regex mismatches. "
            "Slice subrequest reads stale ncaptures, indexes uninitialized memory. "
            "Requires: slice + volatile map + regex capture in same location block."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "nginx 1.29.8: 8 additional CVEs fixed by version bump from 1.26.3",
        "detail": (
            "CVE-2025-53859, CVE-2026-28755, CVE-2026-28753, CVE-2026-27784, "
            "CVE-2026-27654, CVE-2026-32647, CVE-2026-27651, CVE-2026-1642. "
            "Details not in patch files — fixed upstream in 1.27.x/1.28.x/1.29.x releases."
        ),
    },
]

if __name__ == '__main__':
    print(f"TOS 4.6 nginx {PACKAGE['version']}-{PACKAGE['release']} RE")
    print(f"  branch: {PACKAGE['branch']}, {PACKAGE['patches']} CVE patches")
    print()
    print("CVE patches (per-file):")
    for cve, d in CVE_PATCHES.items():
        if cve != 'CVE-2026-42055':
            print(f"  [{d['severity']:6s}] {cve}: {d['title'][:60]}")
    print()
    print(f"Version bump {VERSION_BUMP_CVES['from']}→{VERSION_BUMP_CVES['to']}: "
          f"{len(VERSION_BUMP_CVES['fixed_by_upgrade'])} additional CVEs")
    print()
    for f in FINDINGS:
        cve = f"[{f['cve']}] " if f.get('cve') else ""
        print(f"  [{f['severity']:6s}] {f['id']}: {cve}{f['title'][:65]}")
