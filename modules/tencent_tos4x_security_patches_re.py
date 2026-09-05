"""
TencentOS 4.x (tl4) security patch stack RE.

Source: srpm_work/ subdirectories extracted from TOS 4.x SRPMs.
Covers: nginx, PAM, sudo, bind, dnsmasq, squid, haproxy, polkit, sssd, krb5.
Patch attribution: Tencent/OpenCloudOS security team + upstream authors.

NOTE: Several CVEs in this collection are 2026 CVEs — Tencent backported
fixes before public disclosure was complete or patches are in TOS ahead
of upstream stable release. Adapted-by lines identify AI-assisted
porting to OpenCloudOS stream.
"""

METADATA = {
    "tos_version": "4.x (tl4 kernel series)",
    "srpm_source": "srpm_work/ directory — TOS 4.x SRPM patch stacks",
    "patch_tool_note": (
        "Several patches carry 'Adapted-by: PkgAgent/deepseek-v4' or "
        "'Adapted-by: PkgAgent/deepseek-v4-flash' lines, indicating "
        "Tencent uses an AI (DeepSeek V4) to port upstream fixes to the "
        "OpenCloudOS stream kernel/packages."
    ),
}

NGINX_PATCHES = {
    "package": "nginx-1.29.8-1.tl4.ap.1",
    "headers-more-nginx-module": "0.37",
    "nginx-dav-ext-module": "3.0.0",
    "cves": {
        "CVE-2026-40701": {
            "title": "OCSP: use-after-free on connection close during DNS resolution",
            "file": "src/event/ngx_event_openssl_stapling.c",
            "reporter": "Leo Lin",
            "description": (
                "When a client TLS connection was terminated (typically on timeout) "
                "while nginx was resolving an OCSP responder hostname, the OCSP context "
                "was freed but the DNS resolver context (ngx_resolver_ctx_t) was not. "
                "The resolver callback then fired after the OCSP context was freed, "
                "causing use-after-free when it dereferenced the freed OCSP context."
            ),
            "fix": (
                "Added 'ngx_resolver_ctx_t *resolve' field to ngx_ssl_ocsp_ctx_s. "
                "ngx_ssl_ocsp_done() now calls ngx_resolve_name_done(ctx->resolve) before "
                "closing the connection. ctx->resolve is set before ngx_resolve_name() call "
                "and cleared to NULL if ngx_resolve_name() returns immediately with error."
            ),
            "class": "use-after-free",
            "trigger": "TLS client disconnects during OCSP responder DNS resolution",
        },
        "CVE-2026-42055": {
            "title": "gRPC/HTTP2: buffer overflow via oversized method/URI/authority header",
            "file": "src/http/modules/ngx_http_grpc_module.c",
            "reporter": "Mufeed VH of Winfunc Research",
            "description": (
                "ngx_http_grpc_create_request() builds an HTTP/2 header block for upstream "
                "gRPC connections. It computed the required buffer length using method_name.len, "
                "uri_len, and host.len, but did not check if any exceeded NGX_HTTP_V2_MAX_FIELD "
                "before computing the buffer size. Integer overflow in the size calculation then "
                "led to under-allocation, and the header encoding loop wrote past the buffer end."
            ),
            "fix": (
                "Added three explicit length checks before buffer size calculation: "
                "method_name.len, uri_len, and ctx->host.len each checked against NGX_HTTP_V2_MAX_FIELD "
                "with NGX_ERROR returned if exceeded."
            ),
            "class": "buffer-overflow",
            "trigger": "Crafted gRPC request with oversized HTTP method, URI, or host header",
        },
        "CVE-2026-42533": {
            "title": "Regex capture: uninitialized memory read via stale r->ncaptures",
            "file": "src/http/ngx_http_variables.c",
            "description": (
                "ngx_http_regex_exec() reallocates r->captures when r->realloc_captures is set, "
                "but did not reset r->ncaptures to 0 before the realloc. If the new regex did "
                "not match, ncaptures retained its old value while captures pointed to a new "
                "(uninitialized) allocation. Subsequent access of $1 through $ncaptures-1 "
                "read uninitialized memory, and in slice subrequests with volatile map directives "
                "this triggered uninitialized read and potential buffer overrun."
            ),
            "fix": "Added r->ncaptures = 0 immediately after r->realloc_captures = 0.",
            "class": "uninitialized-memory",
            "trigger": (
                "Config with volatile map directive that reallocates captures in a subrequest, "
                "followed by a named capture variable reference."
            ),
        },
        "CVE-2026-42945": {
            "title": "Rewrite: escaping flag not cleared + buffer overrun",
            "file": "src/http/ngx_http_script.c",
            "reporter": "Leo Lin",
            "description": (
                "In ngx_http_script_regex_end_code(), the e->is_args flag was set when a "
                "rewrite replacement string contained arguments. This flag was not cleared "
                "after the rewrite completed. Subsequent set directives or if blocks that "
                "referenced $1 then incorrectly applied URI escaping to the captured groups. "
                "Additionally, ngx_http_script_complex_value_code() allocated a buffer without "
                "reserving space for the escaping that is_args triggered, leading to buffer "
                "overrun and potential segfault."
            ),
            "fix": "Added e->is_args = 0 at the start of ngx_http_script_regex_end_code().",
            "class": "buffer-overflow",
            "trigger": "Rewrite with arguments followed by set directive using $1 capture",
        },
        "CVE-2026-9256": {
            "title": "Rewrite: heap buffer overflow with overlapping captures",
            "file": "src/http/ngx_http_script.c",
            "reporter": "Mufeed VH of Winfunc Research",
            "description": (
                "ngx_http_script_regex_start_code() computed buffer length for rewrite replacements "
                "that had no variables (code->lengths == NULL). In this path, e->buf.len was set to "
                "code->size. When 'redirect' was specified or arguments were present, additional "
                "space for captures was needed but not allocated. With overlapping captures "
                "(e.g., ^/((.*))), the capture groups refer to overlapping substrings of the URI, "
                "and the length calculation using the shorter $2 underestimated the space needed "
                "for $1, resulting in heap buffer overflow when writing the replacement."
            ),
            "fix": (
                "Rewrote the length calculation loop in the no-variables path to iterate "
                "over all capture groups and use the maximum of their lengths, not the last "
                "seen length. The fix adds int *cap and u_char *p variables and a corrected "
                "multi-pass length scan."
            ),
            "class": "heap-buffer-overflow",
            "trigger": "Rewrite with redirect or args + overlapping captures + URI ≥ 32 chars",
            "example_uri": "/++++++++++++++++++++++++++++++",
            "example_config": "rewrite ^/((.*))$ http://127.0.0.1:8080/$1$2 redirect;",
        },
    },
}

PAM_PATCHES = {
    "package": "Linux-PAM-1.5.3-12.tl4",
    "tos_customization": {
        "sm3_support": {
            "author": "zoedong@tencent.com",
            "date": "2023-08-01",
            "title": "pam_unix: add SM3 password hash algorithm support",
            "description": (
                "Adds SM3 (GB/T 32905-2016, Chinese national cryptographic standard) "
                "as a valid password hashing algorithm in pam_unix. "
                "SM3 hash identifier: '$sm3$' (crypt(3) prefix). "
                "Implementation relies on the host crypt(3) providing SM3 support "
                "(available via TOS-patched libxcrypt with libgcrypt SM3 backend)."
            ),
            "changes": {
                "passverify.c": "Added '$sm3$' as algoid when UNIX_SM3_PASS ctrl flag set",
                "support.c": (
                    "UNIX_SM3_PASS added to SHA rounds check and rounds validation "
                    "(same bounds as SHA-256/512: 1000 min, INT_MAX treated as 0)"
                ),
                "support.h": (
                    "UNIX_SM3_PASS = bit 34 (new highest bit). "
                    "UNIX_CTRLS_ incremented from 34 to 35. "
                    "UNIX_DES_CRYPT macro updated to exclude SM3. "
                    "unix_args table: sm3 → _ALL_ON_^(015660420000ULL), flag 040000000000"
                ),
            },
            "pam_unix_option": "sm3",
            "shadow_prefix": "$sm3$",
        },
    },
    "security_cves": {
        "CVE-2025-6020": {
            "title": "pam_namespace: privilege escalation via cross-mount-namespace race",
            "author": "Olivier Bal-Petre (ANSSI), Dmitry V. Levin",
            "description": (
                "protect_dir() and protect_mount() bind-mounted directories on themselves "
                "to prevent symlink/rename attacks. This protection only works for processes "
                "in the SAME mount namespace. A process in a different mount namespace, or "
                "multiple colluding users, could exploit races in the path-based operations "
                "to redirect the bind mount target and escalate to root. "
                "The fix converts all relevant operations to use file descriptors (openat/mkdirat) "
                "instead of absolute paths, eliminating TOCTOU across mount namespace boundaries."
            ),
            "files": ["modules/pam_namespace/pam_namespace.c", "modules/pam_namespace/pam_namespace.h"],
            "approach": "path→fd conversion; MAGIC_LNK_FD_SIZE=64 for fd-based symlink magic path",
            "class": "privilege-escalation",
        },
        "CVE-2024-10041": {
            "title": "pam_unix: hash exposed in audit log",
        },
        "CVE-2024-10963": {
            "title": "pam_access: improper sanitization allows login as root via hostname manipulation",
        },
        "CVE-2024-22365": {
            "title": "pam_namespace: directory traversal via tmpdir",
        },
    },
}

SUDO_PATCHES = {
    "package": "sudo-1.9.15p5-6.tl4",
    "cves": {
        "CVE-2025-32462": {
            "title": "Privilege escalation via -h remote host specification outside -l mode",
            "file": "plugins/sudoers/sudoers.c",
            "description": (
                "sudoers_check_common() did not verify that a remote host (-h flag) "
                "was only specified in list mode (MODE_LIST|MODE_CHECK). "
                "A user could specify an arbitrary remote hostname for command execution, "
                "potentially matching a different sudoers rule than intended for the "
                "actual local host, allowing privilege escalation to a higher-privilege "
                "rule that only applies when running as a specific remote host."
            ),
            "fix": (
                "Added check at top of sudoers_check_common(): if mode is not "
                "MODE_LIST|MODE_CHECK and ctx->runas.host != ctx->user.host, "
                "log audit warning and return false."
            ),
            "class": "privilege-escalation",
        },
        "CVE-2025-32463": {
            "title": "Command path hijack via pivot directory in sudoers command matching",
            "files_removed": ["plugins/sudoers/pivot.c", "plugins/sudoers/pivot.h"],
            "description": (
                "The pivot.c/pivot.h implementation allowed a user-controlled directory "
                "to be used as a pivot point for command resolution. An attacker could "
                "construct a malicious directory structure that caused sudo to match a "
                "different (attacker-controlled) binary than the one specified in sudoers. "
                "The fix removes pivot.c and pivot.h entirely, eliminating the attack surface."
            ),
            "fix": "Deleted pivot.c and pivot.h; rewrote command matching to use direct path resolution.",
            "class": "command-injection",
        },
        "CVE-2026-35535": {
            "title": "Privilege escalation via mailer event log gid race",
            "file": "lib/eventlog/eventlog.c",
            "description": (
                "exec_mailer() dropped uid to mailuid for sending event log emails but "
                "did not drop gid. If the mailer process forked with the original gid "
                "(which could be a privileged group), it retained group privileges while "
                "running the mailer binary. The fix adds mailgid to eventlog_config and "
                "a new eventlog_set_mailuser() function (replaces eventlog_set_mailuid()) "
                "that sets both uid and gid. Also fixes two error paths that called "
                "_exit(127) without properly unwinding — converted to goto bad."
            ),
            "fix": (
                "Added gid_t mailgid to struct eventlog_config. "
                "eventlog_set_mailuid → eventlog_set_mailuser(uid_t uid, gid_t gid). "
                "exec_mailer() now drops both uid and gid."
            ),
            "class": "privilege-escalation",
        },
    },
}

BIND_PATCHES = {
    "package": "bind-9.18.21-6.tl4",
    "cves": {
        "CVE-2026-5946": {
            "patch_count": 5,
            "title": "CHAOS class recursion enables cache poisoning via non-IN class views",
            "description": (
                "ISC BIND allowed recursion in views with non-IN (e.g., CHAOS) DNS classes. "
                "DNS server addresses used in recursive queries for non-IN classes were not "
                "validated to be of the expected format (IN-class addresses). "
                "A remote attacker could craft queries to CHAOS class views that triggered "
                "recursive resolution, potentially poisoning the resolver cache or causing "
                "unexpected behavior with class-CHAOS resource records. "
                "CVE covers ISC Bug Tracker YWH-PGM40640-74 and YWH-PGM40640-75."
            ),
            "fix": (
                "Force recursion off for all non-IN class views. "
                "Set allow-recursion/allow-recursion-on ACLs to none for non-IN views. "
                "Each view now gets its own rootdb so priming responses don't cross views. "
                "Log a config warning if recursion is explicitly enabled for a non-IN view."
            ),
            "class": "cache-poisoning",
        },
        "CVE-2026-11721": {
            "patch_count": 2,
            "title": "DNSSEC wildcard cache poisoning via invalid RRSIG Labels field",
            "description": (
                "An RRSIG record whose Labels field indicates fewer labels than the signer "
                "name requires was accepted by the BIND validator. When such an RRSIG covered "
                "a wildcard, the validator reconstructed a wildcard owner name ABOVE the signer's "
                "zone and cached it as secure. RFC 8198 cache synthesis (synth-from-dnssec) then "
                "served this forged wildcard for unrelated queries, poisoning the resolver cache. "
                "The fix rejects such RRSIG records both at parse time (rdata/generic/rrsig_46.c) "
                "and at verification time (dnssec.c)."
            ),
            "fix": (
                "dns_dnssec_sign/verify: REQUIRE labels > 0 (prevents zero-label assertion bypass). "
                "Reject RRSIG at parse time if Labels field implies fewer labels than signer requires."
            ),
            "class": "cache-poisoning",
        },
        "CVE-2026-12617": {
            "title": "Assertion failure crash via CNAME/DNAME query timing race",
            "description": (
                "Two scenarios trigger a named assertion failure (crash): "
                "(1) Client queries DNAME and A simultaneously; authoritative delays DNAME response; "
                "resolver caches the DNAME from the A answer, then when the delayed DNAME answer "
                "arrives as NOERROR/NODATA, the resolver incorrectly sets result to DNS_R_DNAME. "
                "query.c interprets this as 'follow DNAME chain', calls query_dname(), which "
                "asserts qname is a subdomain — but qname equals owner name, assertion fails. "
                "(2) Self-referential CNAME triggers similar state machine misinterpretation. "
                "Both paths result in a remotely-triggerable named crash (assertion abort)."
            ),
            "fix": "Two-patch fix: corrects result code setting for cached DNAME/CNAME in resolver.",
            "class": "denial-of-service",
        },
        "CVE-2025-8677": {
            "title": "Prior patch backport",
            "description": "Upstream security fix backported to 9.18.x",
        },
        "CVE-2025-40778": {
            "title": "Prior patch backport",
        },
        "CVE-2025-40780": {
            "title": "Prior patch backport",
        },
    },
}

DNSMASQ_PATCHES = {
    "package": "dnsmasq-2.89-6.tl4",
    "cves": {
        "CVE-2026-2291": {
            "title": "struct bigname heap OOB write via undersized DNS name buffer",
            "reporter": "Andrew S. Fasano",
            "description": (
                "union bigname in dnsmasq.h declared its name buffer as char name[MAXDNAME]. "
                "MAXDNAME is the maximum size of a DNS domain name in bytes. However, "
                "dnsmasq's internal domain name representation uses escape sequences, "
                "so the actual maximum storage requirement is 2*MAXDNAME + 1 bytes. "
                "A remote attacker capable of sending DNS queries OR answering DNS queries "
                "(acting as a malicious upstream resolver) can trigger a large out-of-bounds "
                "write in the heap."
            ),
            "fix": "Changed 'char name[MAXDNAME]' to 'char name[(2*MAXDNAME) + 1]' in union bigname.",
            "class": "heap-oob-write",
            "pre_auth": True,
        },
        "CVE-2026-4890": {
            "title": "NSEC bitmap parsing infinite loop (DNSSEC validation DoS)",
            "reporter": "Royce M <royce@xchglabs.com>",
            "description": (
                "In prove_non_existence_nsec() (dnssec.c:1290) and check_nsec3_coverage() "
                "(dnssec.c:1450), the NSEC/NSEC3 bitmap window iteration loop advanced "
                "by p[1] bytes instead of p[1]+2 (missing the 2-byte window type+length header). "
                "With bitmap_length=0, both rdlen and p were unchanged on each loop iteration, "
                "causing an infinite loop. "
                "Reachable before RRSIG validation (source comment at line 2125 confirms this), "
                "so no valid DNSSEC signatures are required to trigger. "
                "dnsmasq stops responding to ALL DNS queries during the loop."
            ),
            "fix": "Changed 'rdlen -= p[1]; p += p[1];' to 'rdlen -= p[1]+2; p += p[1]+2;' (twice).",
            "class": "infinite-loop-dos",
            "pre_auth": True,
        },
        "CVE-2026-4891": {
            "title": "DNSSEC validation denial-of-service #2",
        },
        "CVE-2026-4892": {
            "title": "DNSSEC validation denial-of-service #3",
        },
        "CVE-2026-4893": {
            "title": "DNSSEC validation denial-of-service #4",
        },
    },
}

SQUID_PATCHES = {
    "package": "squid-6.5-11.tl4",
    "cves": {
        "CVE-2026-32748": {
            "title": "ICP v3: use-after-free via HttpRequest lifetime management",
            "description": (
                "ACLFilledChecklist automatically destroys an HttpRequest given to it "
                "as an unlocked object when the checklist goes out of scope. "
                "icpAccessAllowed() created an on-stack ACLFilledChecklist with the request "
                "and then returned; after return, the caller (icpGetRequest) dereferenced "
                "the destroyed request object. "
                "This bug was introduced in 2003 (commit 8000a965 — auto-unlock in ACLChecklist) "
                "and made exploitable in 2007 (commit f72fb56b — using request for ICP v3). "
                "ICP v2 equivalent was fixed in 2005 (commit 319bf5a7) but the v3 case was missed."
            ),
            "fix": (
                "Return HttpRequestPointer (smart pointer) from icpGetRequest() instead of raw ptr. "
                "Moved icpAccessAllowed() inline into icpGetRequest() to deduplicate and ensure "
                "request lifetime is controlled by the smart pointer."
            ),
            "class": "use-after-free",
        },
        "CVE-2026-33515": {
            "title": "ICP: OOB read via non-NUL-terminated or embedded-NUL URL",
            "description": (
                "ICP (Internet Cache Protocol) packet URL parsing in icpGetRequest() "
                "did not validate that the URL field was NUL-terminated. "
                "A malformed ICP query with a URL that ran to the end of the packet buffer "
                "without a NUL byte caused an out-of-bounds read. "
                "Similarly, URLs with embedded NUL bytes or trailing garbage were passed "
                "to URL consumers without sanitization. "
                "New icpGetUrl() function added to encapsulate all URL extraction and validation."
            ),
            "fix": (
                "Added icpGetUrl() that: validates URL is NUL-terminated within packet bounds, "
                "rejects embedded NULs and trailing garbage. "
                "icpGetRequest() now takes const char* url (from icpGetUrl). "
                "Protects icpHandleUdp() from nil icpOutgoingConn dereference."
            ),
            "class": "oob-read",
        },
        "CVE-2025-59362": {
            "title": "Squid security fix (2025 backport)",
        },
        "CVE-2025-62168": {
            "title": "Squid security fix (2025 backport)",
        },
        "CVE-2024-37894": {
            "title": "Squid security fix (2024 backport)",
        },
    },
}

HAPROXY_PATCHES = {
    "package": "haproxy-2.6.19-5.tl4",
    "cves": {
        "CVE-2026-55203": {
            "title": "FCGI mux: uint16_t overflow causes state machine desync",
            "reporter": "Tristan Madani (TristanInSec) / Talence Security",
            "description": (
                "fcgi_conn.drl (demux record length) was declared uint16_t. "
                "In the ignore_record path, 'fconn->drl += fconn->drp' (adding padding bytes). "
                "With contentLength=65535 and paddingLength>=1, this overflowed to 0. "
                "haproxy then considered the record complete without consuming buffer data. "
                "The remaining buffer contents were parsed as new FCGI record headers, "
                "causing the FCGI state machine to desync from the actual protocol stream."
            ),
            "fix": "Widened drl from uint16_t to uint32_t (safe: drp is uint8_t, max 255, no overflow possible).",
            "class": "integer-overflow",
        },
        "CVE-2026-55204": {
            "title": "HPACK: NULL dereference via missing check after hpack_dht_defrag()",
            "reporter": "Tristan Madani (TristanInSec) / Talence Security",
            "description": (
                "hpack_dht_insert() calls hpack_dht_defrag() at three call sites (lines 293, 306, 353). "
                "Lines 293 and 306 correctly check for NULL return and return -1. "
                "Line 353 (data-space defrag path) did not check for NULL before dereferencing dht. "
                "When pool_head_hpack_tbl is exhausted, hpack_dht_alloc() returns NULL, "
                "hpack_dht_defrag() propagates NULL, and the subsequent dereference of "
                "dht->wrap (NULL+offset) causes worker SIGSEGV."
            ),
            "fix": "Added NULL check after hpack_dht_defrag() at line 353, consistent with other call sites.",
            "class": "null-deref",
        },
        "CVE-2025-11230": {
            "title": "HAProxy security fix (2025 backport)",
        },
    },
}

POLKIT_PATCHES = {
    "package": "polkit-123-5.tl4",
    "cves": {
        "CVE-2025-7519": {
            "title": "polkit: XML parsing stack overflow via nested .policy files",
            "author": "Jan Rybar (Red Hat)",
            "file": "src/polkitbackend/polkitbackendactionpool.c",
            "description": (
                "polkitbackend's _start() XML parser callback (expat) incremented pd->stack_depth "
                "for each nested XML element but did not check against PARSER_MAX_DEPTH. "
                "A malformed or maliciously crafted .policy file with deeply nested XML elements "
                "caused stack_depth to overflow, leading to a parser crash. "
                "Attacker needs write access to /usr/share/polkit-1/actions/ (root or vendor-controlled). "
                "Impact: polkitd crash → denial of service for all privilege authorization requests."
            ),
            "fix": (
                "Added guard at start of _start(): if pd->stack_depth < 0 || >= PARSER_MAX_DEPTH, "
                "log 'XML parsing reached max depth?' and goto error."
            ),
            "class": "denial-of-service",
        },
    },
}

SSSD_PATCHES = {
    "package": "sssd-2.9.4-8.tl4",
    "cves": {
        "CVE-2026-14476": {
            "title": "SSSD GPO: path traversal in gPCFileSysPath allows file write outside GPO cache",
            "author": "Alexey Tikhonov (Red Hat), Ian Murphy (Red Hat)",
            "files": ["src/providers/ad/ad_gpo.c", "src/providers/ad/ad_gpo_child.c"],
            "description": (
                "The gPCFileSysPath LDAP attribute from AD Group Policy Objects is processed by "
                "ad_gpo_extract_smb_components() which converts backslashes to forward slashes "
                "but did not reject '..' path traversal sequences. "
                "The resulting smb_path was used directly in gpo_cache_store_file() to construct "
                "a local filesystem path under GPO_CACHE_PATH. "
                "Due to differential path resolution: libsmbclient clamps '..' at the SMB share root "
                "(SMB download succeeds), but the Linux kernel resolves '..' fully (file write escapes cache). "
                "On SELinux-enforcing systems: enables Kerberos config injection via "
                "/var/lib/sss/pubconf/krb5.include.d/ (sssd_public_t, writable by sssd_t). "
                "On non-SELinux systems: enables arbitrary file writes, including cron job injection "
                "for root code execution."
            ),
            "attack_requirement": "Write access to a Group Policy Object in Active Directory",
            "fix": {
                "layer1": (
                    "ad_gpo_extract_smb_components(): reject '..' as a path component using "
                    "component-aware validation (checks '/..' prefix, '../' suffix, exact '..'). "
                    "NOT substring matching to avoid false positives on legit names."
                ),
                "layer2": (
                    "gpo_cache_store_file(): validate resolved cache path stays within GPO_CACHE_PATH "
                    "using realpath() + trailing-slash prefix check to prevent prefix-collision attacks "
                    "(e.g., /var/lib/sss/gpo_cache_evil/ matching /var/lib/sss/gpo_cache)."
                ),
            },
            "class": "path-traversal",
        },
    },
}

KRB5_PATCHES = {
    "package": "krb5-1.21.2-8.tl4",
    "cves": {
        "CVE-2025-3576": {
            "title": "KDC: remove triple-DES session key support (downstream hardening)",
            "description": (
                "Downstream TOS patch removes triple-DES (des3-cbc-sha1) from allowed "
                "KDC session encryption types. The KDC will no longer issue tickets with "
                "triple-DES session keys under any configuration. "
                "allow_des3 variable removed from [libdefaults]. "
                "This is a Tencent-specific hardening (not the upstream CVE fix content, "
                "which concerned preventing weak session key issuance — TOS takes the "
                "stronger position of removing des3 entirely, not just disabling by default)."
            ),
            "class": "cryptographic-hardening",
        },
        "CVE-2024-26458": {
            "title": "Two unlikely memory leaks in SPNEGO",
        },
        "CVE-2024-26461": {
            "title": "Memory leak in SPNEGO (companion to 26458)",
        },
        "CVE-2024-26462": {
            "title": "Memory leak in KDC NDR encoding",
        },
        "CVE-2024-37370": {
            "title": "GSS message token handling vulnerability",
        },
        "CVE-2024-37371": {
            "title": "GSS message token handling vulnerability (companion)",
        },
        "CVE-2025-24528": {
            "title": "Integer overflow in ulog block size calculation",
        },
    },
}

AI_PORTING_OBSERVATION = {
    "title": "TOS uses DeepSeek V4 AI to port upstream security fixes to OpenCloudOS stream",
    "evidence": [
        "nginx-1.29.8-CVE-2026-42055: 'Adapted-by: PkgAgent/deepseek-v4'",
        "bind-9.18.21-CVE-2026-5946-1: 'Adapted-by: PkgAgent/deepseek-v4'",
        "bind-9.18.21-CVE-2026-11721-1: 'Adapted-by: PkgAgent/deepseek-v4'",
        "squid-6.5-CVE-2026-32748: 'Adapted-by: PkgAgent/deepseek-v4-flash'",
        "squid-6.5-CVE-2026-33515: 'Adapted-by: PkgAgent/deepseek-v4-flash'",
    ],
    "implications": (
        "Tencent has an automated security patch porting pipeline (PkgAgent) backed by DeepSeek. "
        "The AI adapts upstream CVE fixes to the OpenCloudOS stream kernel/package API. "
        "AI-ported patches are production-signed with the TOS signing key and shipped to users. "
        "Risk: AI porting errors could introduce subtle bugs or incomplete fixes in security patches. "
        "The 'flash' vs base variant suggests different DeepSeek model tiers for different patch complexity."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2026-2291",
        "package": "dnsmasq-2.89",
        "title": "dnsmasq: struct bigname heap OOB write — pre-auth, remote",
        "detail": (
            "union bigname had char name[MAXDNAME] but internal DNS name representation "
            "requires up to 2*MAXDNAME+1 bytes. Remote attacker (query sender or upstream resolver) "
            "can trigger large OOB heap write with no authentication required."
        ),
        "fix": "char name[(2*MAXDNAME)+1]",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2026-4890",
        "package": "dnsmasq-2.89",
        "title": "dnsmasq: NSEC bitmap infinite loop — pre-auth DNSSEC DoS",
        "detail": (
            "NSEC bitmap window iteration advance-by-p[1] instead of p[1]+2; "
            "zero-length bitmap window causes infinite loop stopping all DNS responses. "
            "Reachable before RRSIG validation."
        ),
        "fix": "p[1] → p[1]+2 (twice, in prove_non_existence_nsec and check_nsec3_coverage)",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2026-14476",
        "package": "sssd-2.9.4",
        "title": "SSSD GPO path traversal: arbitrary file write outside GPO cache via AD",
        "detail": (
            "gPCFileSysPath '..' traversal escapes GPO_CACHE_PATH on local write "
            "(libsmbclient clamps at SMB share root; Linux kernel resolves fully). "
            "On SELinux: Kerberos config injection. Without SELinux: cron root RCE."
        ),
        "attack_requirement": "Write access to AD Group Policy Object",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "cve": "CVE-2026-9256",
        "package": "nginx-1.29.8",
        "title": "nginx rewrite: heap buffer overflow with overlapping captures",
        "detail": (
            "Rewrite replacement buffer underallocated when overlapping capture groups used "
            "with redirect or args present. Length calculation uses last capture length, not max. "
            "Exploitable via crafted URI matching the rewrite regex."
        ),
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "cve": "CVE-2025-32462",
        "package": "sudo-1.9.15",
        "title": "sudo: -h host flag allowed outside -l mode — sudoers rule bypass",
        "detail": (
            "User could specify arbitrary remote host for command execution, "
            "potentially matching a sudoers rule for that host with higher privileges "
            "than the local host's rule allows."
        ),
    },
    {
        "id": "F6",
        "severity": "HIGH",
        "cve": "CVE-2026-5946",
        "package": "bind-9.18.21",
        "title": "BIND: CHAOS class recursion enables cache poisoning",
        "detail": (
            "Non-IN class views (e.g., CHAOS) could do recursive resolution with "
            "non-IN-format server addresses, enabling cache poisoning via class-CHAOS queries."
        ),
    },
    {
        "id": "F7",
        "severity": "HIGH",
        "cve": "CVE-2026-11721",
        "package": "bind-9.18.21",
        "title": "BIND: invalid RRSIG Labels enables wildcard cache poisoning via synth-from-dnssec",
        "detail": (
            "RRSIG with Labels < signer_name_labels accepted by validator. "
            "Forged wildcard cached as secure; RFC 8198 serves it for unrelated queries."
        ),
    },
    {
        "id": "F8",
        "severity": "MEDIUM",
        "cve": "CVE-2025-6020",
        "package": "Linux-PAM-1.5.3",
        "title": "pam_namespace: cross-mount-namespace TOCTOU privilege escalation",
        "detail": (
            "protect_dir/protect_mount path-based operations vulnerable to races "
            "from processes in different mount namespaces. Fix: fd-based operations throughout."
        ),
    },
    {
        "id": "F9",
        "severity": "MEDIUM",
        "cve": "CVE-2026-55203",
        "package": "haproxy-2.6.19",
        "title": "HAProxy FCGI: uint16_t overflow desync state machine",
        "detail": (
            "drl (uint16_t) overflow to 0 when adding drp padding to full-size record. "
            "State machine skips buffer consumption; subsequent bytes parsed as new FCGI headers."
        ),
    },
    {
        "id": "F10",
        "severity": "MEDIUM",
        "cve": "CVE-2026-32748",
        "package": "squid-6.5",
        "title": "Squid: ICP v3 use-after-free via ACLFilledChecklist lifecycle",
        "detail": (
            "HttpRequest auto-destroyed by on-stack ACLFilledChecklist. "
            "Caller dereferences destroyed request. 20-year-old bug triggered by ICP v3."
        ),
    },
    {
        "id": "F11",
        "severity": "MEDIUM",
        "cve": "CVE-2026-42940",
        "package": "nginx-1.29.8",
        "title": "nginx gRPC: HTTP/2 header length check missing — buffer overflow",
        "detail": (
            "NGX_HTTP_V2_MAX_FIELD not checked before buffer allocation for method/URI/host. "
            "Oversized header triggers under-allocation and OOB write."
        ),
    },
    {
        "id": "F12",
        "severity": "INFO",
        "title": "TOS PAM: SM3 password hash added as native pam_unix option",
        "detail": (
            "Tencent added SM3 (GB/T 32905-2016) as a valid pam_unix password hash. "
            "Shadow prefix '$sm3$'. Requires libxcrypt SM3 support. "
            "Non-standard vs upstream PAM — breaks cross-system compatibility for migrated accounts."
        ),
        "tos_specific": True,
    },
    {
        "id": "F13",
        "severity": "INFO",
        "title": "TOS uses AI (DeepSeek V4) to auto-port CVE patches to OpenCloudOS stream",
        "detail": (
            "PkgAgent pipeline (deepseek-v4 and deepseek-v4-flash tiers) adapts upstream CVE patches "
            "to OpenCloudOS API differences. Production-signed patches deployed to TOS users. "
            "AI porting errors in security patches represent a systemic supply chain risk."
        ),
        "affected_packages": ["nginx", "bind", "squid"],
    },
]

if __name__ == '__main__':
    pkgs = [NGINX_PATCHES, PAM_PATCHES, SUDO_PATCHES, BIND_PATCHES,
            DNSMASQ_PATCHES, SQUID_PATCHES, HAPROXY_PATCHES, POLKIT_PATCHES,
            SSSD_PATCHES, KRB5_PATCHES]
    print(f"TOS 4.x security patch RE — {len(pkgs)} packages")
    print()
    for f in FINDINGS:
        cve = f.get('cve', '')
        pkg = f.get('package', '')
        label = f"[{cve}]" if cve else "[INFO]"
        print(f"  [{f['severity']:6s}] {f['id']}: {label} {f['title'][:65]}")
