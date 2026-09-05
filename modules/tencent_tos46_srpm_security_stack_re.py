"""
TencentOS 4.6 — srpm_work security package stack RE.

Source: scratchpad/srpm_work/ (29 package directories)
Coverage: haproxy, nginx, sudo, sssd, krb5, pam, polkit-123, squid, bind,
          dnsmasq, shadow-utils, httpd

Method: patch file inspection + spec CVE enumeration across all package directories.

Notable cross-cutting findings:
  - 5th PkgAgent/deepseek-v4 AI-ported patch: nginx CVE-2026-42055 (HTTP/2 overflow)
  - Tencent-originated CVE: squid CVE-2025-62168 (zidonghuang@tencent.com)
  - Tencent-authored fix: pam CVE-2024-10963 (wynnfeng@tencent.com)
  - sssd CVE-2026-14476: GPO path traversal → root code exec on SELinux-off systems
"""

HAPROXY = {
    "package": "haproxy-2.6.19-5.tl4",
    "cves": {
        "CVE-2025-11230": {
            "title": "mjson strtod O(exp) complexity — CRITICAL DoS via crafted JSON number",
            "severity": "CRITICAL",
            "description": (
                "haproxy's bundled mjson parser uses an iterative O(exp) loop to compute "
                "numeric exponents instead of pow(). A crafted JSON value with a large "
                "exponent (e.g., 1e999999) causes the strtod() loop to run for an "
                "astronomically long time, blocking the haproxy worker process. "
                "Reachable via any HTTP/JSON path that haproxy processes (health check "
                "responses, ACL evaluation, stats API). Single crafted request can "
                "block the worker thread permanently. "
                "Reported by Willy Tarreau; patch replaces iterative loop with a bounded check."
            ),
            "pre_auth": True,
            "class": "resource-exhaustion",
            "vector": "network",
        },
        "CVE-2026-55203": {
            "title": "FCGI mux-fcgi: uint16_t drl overflow — malformed FastCGI record parsing loop",
            "severity": "MEDIUM",
            "description": (
                "In the FastCGI demux path, fconn->drl is uint16_t. "
                "In the ignore_record path, 'fconn->drl += fconn->drp' overflows to 0 "
                "when contentLength=65535 and paddingLength>=1 (65535+1=0 mod 2^16). "
                "The state machine treats drl=0 as 'record complete' and parses the "
                "remaining buffer contents as new FCGI record headers. "
                "Malformed FastCGI record from an upstream application server → "
                "haproxy misparses subsequent data as FCGI headers. "
                "Reported by Tristan @TristanInSec (Talence Security)."
            ),
            "fixed_by": "Widen drl from uint16_t to uint32_t",
            "class": "integer-overflow",
            "pre_auth": False,
            "vector": "backend",
        },
        "CVE-2026-55204": {
            "title": "HPACK table: NULL deref after hpack_dht_defrag() on pool exhaustion",
            "severity": "MEDIUM",
            "description": (
                "hpack_dht_insert() has three call sites for hpack_dht_defrag(). "
                "Two check the return value; the third (line 353, data-space defrag) "
                "does not. When pool_head_hpack_tbl is exhausted, hpack_dht_alloc() "
                "returns NULL, which propagates through defrag — line 354 dereferences "
                "NULL+offsetof, crashing the worker. "
                "HTTP/2 client with high header table utilization can trigger pool "
                "exhaustion and crash the haproxy worker. "
                "Reported by Tristan @TristanInSec."
            ),
            "class": "null-deref",
            "pre_auth": True,
            "vector": "network",
        },
    },
}

NGINX = {
    "package": "nginx-1.29.8-1.tl4.ap.1",
    "cves": {
        "CVE-2026-40701": {
            "title": "OCSP stapling: UAF when SSL connection closes during OCSP resolve",
            "severity": "MEDIUM",
            "description": (
                "ngx_event_openssl_stapling.c: when a client SSL connection is terminated "
                "(e.g., timeout) while resolving an OCSP responder, the OCSP context is freed "
                "but the resolve context is not released. On resolve completion, the resolve "
                "context dereferences the freed OCSP context (use-after-free). "
                "Reachable remotely by clients that trigger OCSP stapling then disconnect."
            ),
            "class": "use-after-free",
            "pre_auth": True,
        },
        "CVE-2026-42055": {
            "title": "HTTP/2 gRPC header buffer overflow — AI-ported by PkgAgent/deepseek-v4",
            "severity": "HIGH",
            "description": (
                "ngx_http_grpc_module.c: HTTP/2 header length limits not applied to "
                "upstream gRPC headers, allowing buffer overflow via crafted oversized "
                "HTTP/2 headers. "
                "Reported by Mufeed VH of Winfunc Research. "
                "PATCH NOTE: adapted by PkgAgent/deepseek-v4 for opencloudos-stream. "
                "This is the 5th PkgAgent-ported security patch identified in TOS 4.6 "
                "(previous: expat CVE-2026-56412, expat CVE-2026-66046, CUPS CVE-2026-27447, "
                "CUPS CVE-2025-58436)."
            ),
            "ai_ported": True,
            "ai_ported_by": "PkgAgent/deepseek-v4",
            "class": "heap-overflow",
            "pre_auth": True,
        },
        "CVE-2026-42533": {
            "title": "Rewrite module: stale regex captures cause uninitialized read + heap OOB",
            "severity": "HIGH",
            "description": (
                "ngx_http_regex_exec() reallocates r->captures array but does not update "
                "r->ncaptures if the regex didn't match. Next use of unnamed regex capture "
                "triggers uninitialized read and potential buffer overrun. "
                "Exploitable with nested rewrite rules in subrequests."
            ),
            "class": "uninitialized-read + heap-oob",
            "pre_auth": True,
        },
        "CVE-2026-42945": {
            "title": "Rewrite module: incorrect escaping + buffer overrun on args in replacement",
            "severity": "HIGH",
            "description": (
                "When a rewrite replacement string has arguments but no variables, "
                "the allocated buffer can be smaller than the replacement string. "
                "Exploitable via: rewrite ^(.*) /new?c=1; set $myvar $1; return 200 $myvar; "
                "with crafted URI containing many '+' chars (URL-encoded spaces)."
            ),
            "class": "heap-overflow",
            "pre_auth": True,
        },
        "CVE-2026-9256": {
            "title": "Rewrite: buffer overflow with overlapping captures",
            "severity": "HIGH",
            "description": (
                "Rewrite replacement with overlapping captures: buffer length calculation "
                "underestimates required size when captures overlap. Heap buffer overflow "
                "on crafted URI. Demonstrated with URI '/'*30 chars."
            ),
            "class": "heap-overflow",
            "pre_auth": True,
        },
    },
}

SUDO = {
    "package": "sudo-1.9.15p5-6.tl4",
    "cves": {
        "CVE-2025-32462": {
            "title": "Host specification in non-list mode: sudoers policy filter bypass",
            "severity": "HIGH",
            "description": (
                "sudoers_check_common() allowed the user to specify a host via ctx->runas.host "
                "for any sudo operation, not just 'sudo -l' (list mode). "
                "A user could run 'sudo -h otherhost cmd' and have the host filter applied "
                "to 'otherhost' instead of the local host, bypassing sudoers host restrictions. "
                "Fix: reject ctx->runas.host != ctx->user.host when mode is not MODE_LIST."
            ),
            "class": "authorization-bypass",
            "pre_auth": False,
            "local_only": True,
        },
        "CVE-2025-32463": {
            "title": "Editor path resolution: symlink attack via pivot.c chroot path",
            "severity": "HIGH",
            "description": (
                "sudo's editor invocation (sudoedit) used pivot.c to create a chroot "
                "environment for path resolution. A symlink attack during path construction "
                "could redirect the editor to open an attacker-controlled path. "
                "Fix: remove pivot.c entirely; replace with safer path resolution in "
                "find_path.c/goodpath.c/match_command.c (large patch, 730+ line change)."
            ),
            "class": "symlink-attack",
            "pre_auth": False,
            "local_only": True,
        },
        "CVE-2026-35535": {
            "title": "Mailer GID not set: event log mailer runs with wrong group identity",
            "severity": "LOW",
            "description": (
                "eventlog_set_mailuid() only set the UID for the mailer process, not GID. "
                "The mailer process (invoked for sudo event logging) ran with the original "
                "group instead of the configured mail user's group. "
                "Fix: rename to eventlog_set_mailuser(uid_t, gid_t); "
                "both UID and GID are now set before exec. "
                "Error handling also improved: goto bad instead of _exit(127) on dup error."
            ),
            "class": "privilege-misconfiguration",
            "pre_auth": False,
            "local_only": True,
        },
    },
}

SSSD = {
    "package": "sssd-2.9.4-8.tl4",
    "cves": {
        "CVE-2026-14476": {
            "title": "GPO gPCFileSysPath path traversal: arbitrary file write → root LPE",
            "severity": "CRITICAL",
            "description": (
                "sssd's AD Group Policy (GPO) backend processes the gPCFileSysPath LDAP "
                "attribute from Active Directory without validating '..' path components. "
                "ad_gpo_extract_smb_components() converts backslashes to forward slashes "
                "but does not reject traversal sequences. "
                "The resulting smb_path is used to construct a local file path under "
                "GPO_CACHE_PATH (e.g., /var/lib/sss/gpo_cache/). "
                "Exploit path: "
                "(1) Attacker with AD GPO write access sets gPCFileSysPath containing '..'. "
                "(2) libsmbclient downloads the file (clamps '..' at SMB share root, succeeds). "
                "(3) Kernel resolves '..' fully, writing outside the cache directory. "
                "Impact WITHOUT SELinux: arbitrary file write as sssd_t → "
                "cron job injection under /etc/cron.d/ → root code execution. "
                "Impact WITH SELinux (sssd_public_t context): "
                "Kerberos configuration injection via /var/lib/sss/pubconf/krb5.include.d/ "
                "→ Kerberos realm manipulation. "
                "Author: Alexey Tikhonov (Red Hat). "
                "Fix: component-aware '..' rejection at parse time: checks for '/..' '../' "
                "and exact '..' (not substring matching to avoid false positives)."
            ),
            "class": "path-traversal",
            "pre_auth": False,
            "requires": "AD GPO write access",
            "severity_without_selinux": "CRITICAL",
            "severity_with_selinux": "HIGH",
        },
    },
}

KRB5 = {
    "package": "krb5-1.21.2-8.tl4",
    "cves": {
        "CVE-2024-26458": {
            "title": "Memory leak in krb5_sendto() error paths",
            "severity": "LOW",
            "description": "Two unlikely memory leaks in error paths of krb5_sendto(). Unlikely DoS.",
            "class": "memory-leak",
        },
        "CVE-2024-26461": {
            "title": "Memory leak in krb5_sendto() error paths (second leak)",
            "severity": "LOW",
            "description": "Second memory leak in same function, different error path.",
            "class": "memory-leak",
        },
        "CVE-2024-26462": {
            "title": "Memory leak in KDC NDR encoding path",
            "severity": "LOW",
            "description": "Memory leak in the NDR encoding path of KDC processing.",
            "class": "memory-leak",
        },
        "CVE-2024-37370": {
            "title": "GSS message token handling: integrity check bypass",
            "severity": "HIGH",
            "description": (
                "Vulnerability in GSS message token handling allows an active network attacker "
                "to alter the plaintext of messages, bypassing integrity checks."
            ),
            "class": "integrity-bypass",
            "pre_auth": False,
            "vector": "network",
        },
        "CVE-2024-37371": {
            "title": "GSS message token: OOB read via crafted message token",
            "severity": "HIGH",
            "description": (
                "Out-of-bounds read in GSS message token processing. "
                "Crafted Kerberos message triggers invalid memory access in krb5 library."
            ),
            "class": "out-of-bounds-read",
            "pre_auth": False,
            "vector": "network",
        },
        "CVE-2025-24528": {
            "title": "kadmind iprop log overflow: authenticated write beyond mapped region",
            "severity": "HIGH",
            "description": (
                "kdb_log.c:resize() calculates block size for iprop (incremental propagation) "
                "log entries. Integer overflow when update_size > max block size (2^16 - 1 = 65535). "
                "kadmind writes beyond the end of the mmap'd region for the iprop log file. "
                "Likely crash; potential memory corruption. "
                "Requires: authenticated kadmin session with iprop enabled. "
                "Reported by Zoltan Borbely (Morgan Stanley)."
            ),
            "class": "integer-overflow + OOB-write",
            "pre_auth": False,
            "requires": "authenticated kadmin",
        },
        "CVE-2025-3576": {
            "title": "Deprecated enctype session keys: 3DES session key negotiation removal",
            "severity": "MEDIUM",
            "description": (
                "KDC could issue session keys using deprecated encryption types (3DES) "
                "even when the policy should exclude them. "
                "Fix: remove 3DES support from init_ctx.c and kdc_util.c. "
                "Downstream patch from Julien Rische (Red Hat): removes all 3DES mentions "
                "from docs, code, and tests."
            ),
            "class": "cryptographic-weakness",
        },
    },
}

PAM = {
    "package": "pam-1.5.3-12.tl4",
    "cves": {
        "CVE-2024-22365": {
            "title": "pam_namespace: O_DIRECTORY not used — FIFO blocking DoS in protect_dir()",
            "severity": "MEDIUM",
            "description": (
                "pam_namespace protect_dir() calls openat() without O_DIRECTORY. "
                "A user can place a FIFO in a user-controlled directory in the mount path; "
                "openat() on the FIFO blocks indefinitely (read end never opened). "
                "PAM module blocks during authentication. "
                "Fix: add O_DIRECTORY to openat() call (from Matthias Gerstner, SUSE)."
            ),
            "class": "local-dos",
            "local_only": True,
            "pre_auth": False,
        },
        "CVE-2024-10041": {
            "title": "pam_unix: shadow password always obtained via helper — timing side channel reduction",
            "severity": "MEDIUM",
            "description": (
                "pam_unix previously tried getspnam() first and fell back to the helper "
                "only on error. The optimization introduced a timing side channel: "
                "presence/absence of a shadow entry was measurable. "
                "Fix: always use the helper binary (pam_unix_chkpwd) to obtain shadow "
                "entries, making the timing uniform."
            ),
            "class": "side-channel",
        },
        "CVE-2024-10963": {
            "title": "pam_access: hostname token resolution security fix",
            "severity": "MEDIUM",
            "description": (
                "pam_access hostname resolution for access control list tokens was "
                "incorrect: host tokens were resolved in a way that allowed "
                "bypass of access controls via crafted hostname entries. "
                "Fix: rework resolving of tokens as hostname with proper validation. "
                "TENCENT-AUTHORED: wynnfeng@tencent.com "
                "(same author as CVE-2026-34182 in OpenSSL and pam_access fix)."
            ),
            "author": "wynnfeng@tencent.com",
            "tencent_originated": True,
            "class": "authorization-bypass",
        },
        "CVE-2025-6020": {
            "title": "pam_namespace: mount namespace race condition — privilege escalation to root",
            "severity": "HIGH",
            "description": (
                "pam_namespace's protect_dir() and protect_mount() bind-mount all directories "
                "in the to-be-secured paths against themselves. This protection is only effective "
                "within the same mount namespace. "
                "A user with an out-of-mount-namespace access (e.g., via unshare, setns) "
                "or multiple users colluding can exploit race conditions to elevate to root. "
                "Three-patch fix series (Olivier Bal-Petre ANSSI + Dmitry Levin): "
                "1. Add fsfd-based path safety checks for polydir and instance directories. "
                "2. Add safety flags indicating if paths are root-owned and writable by root only. "
                "3. Remove group ownership exception in secure_opendir() (root group may contain non-root)."
            ),
            "class": "race-condition",
            "local_only": True,
            "pre_auth": False,
        },
    },
}

POLKIT_123 = {
    "package": "polkit-123-5.tl4",
    "js_engine": "duktape (replaced SpiderMonkey/mozjs60 in polkit 1.x)",
    "note": (
        "polkit 123 is the new version numbering (polkit 1.x rebranded). "
        "This replaces the polkit-0.115 package analyzed in tencent_tos46_polkit_srpm_re.py. "
        "Key change from 0.115: JavaScript engine replaced from mozjs60 (SpiderMonkey) "
        "to duktape (pkgconfig(duktape) BuildRequires). pkexec still SUID root."
    ),
    "cves": {
        "CVE-2025-7519": {
            "title": "Nested .policy files: XML parsing stack depth overflow → crash",
            "severity": "MEDIUM",
            "description": (
                "polkitbackend-actionpool.c:_start() is the expat SAX callback for the "
                "XML start-element event. ParserData->stack_depth tracks XML nesting depth. "
                "Before the fix, no bounds check existed on stack_depth before accessing "
                "the stack array. Deeply nested XML in a .policy file caused a stack "
                "overflow or out-of-bounds array access in polkitd. "
                "Fix: add check 'if (pd->stack_depth < 0 || pd->stack_depth >= PARSER_MAX_DEPTH)' "
                "before processing element; log warning and goto error. "
                "Author: Jan Rybar (Red Hat). "
                ".policy files are in /usr/share/polkit-1/actions/ (typically root-owned); "
                "exploitation requires a writable policy directory or a crafted pkla/policy "
                "installed by a package."
            ),
            "class": "stack-overflow + oob-write",
            "pre_auth": False,
            "requires": "writable .policy file location or crafted package",
        },
    },
}

SQUID = {
    "package": "squid-6.5-11.tl4",
    "cves": {
        "CVE-2024-37894": {
            "title": "SNMP: OOB read via long SNMP OIDs",
            "severity": "MEDIUM",
            "description": "Long SNMP OIDs not handled in asn_build_objid(); OOB read.",
            "class": "out-of-bounds-read",
        },
        "CVE-2025-59362": {
            "title": "SNMP ASN.1: OID encoding insufficient — buffer boundary issue",
            "severity": "MEDIUM",
            "description": "ASN.1 encoding of long SNMP OIDs insufficient in asn1.c.",
            "class": "buffer-boundary",
        },
        "CVE-2025-62168": {
            "title": "UAF/memory corruption (Tencent-authored backport)",
            "severity": "HIGH",
            "description": (
                "Details from upstream commit 0951a0681011dfca3d78c84fd7f1e19c78a4443f. "
                "Manually backported to squid-6.5 by zidonghuang@tencent.com. "
                "TENCENT-ORIGINATED: Zidong Huang <zidonghuang@tencent.com>."
            ),
            "author": "zidonghuang@tencent.com",
            "tencent_originated": True,
        },
        "CVE-2026-32748": {
            "title": "ICP: HttpRequest UAF after ACLFilledChecklist destructor on ICP v3 queries",
            "severity": "HIGH",
            "description": (
                "ACLFilledChecklist correctly locks/unlocks HttpRequest. When given an unlocked "
                "request object, an on-stack checklist destroys it on return. "
                "After icpAccessAllowed(), Squid uses the destroyed request object. "
                "Bug exists since 2007 (ICP v3 requests). ICP queries without auth → UAF."
            ),
            "class": "use-after-free",
            "pre_auth": True,
            "vector": "ICP port (UDP 3130)",
        },
        "CVE-2026-33515": {
            "title": "ICP: malformed packet URL parsing — OOB reads + null-deref",
            "severity": "HIGH",
            "description": (
                "ICP v2/v3 packet validation does not reject: "
                "(1) URLs not NUL-terminated, (2) URLs with embedded NULs, (3) trailing garbage. "
                "Invalid URL pointer passed to consumers → out-of-bounds reads and crashes. "
                "Reachable via UDP ICP queries (no auth required)."
            ),
            "class": "out-of-bounds-read",
            "pre_auth": True,
            "vector": "ICP port (UDP 3130)",
        },
    },
}

DNSMASQ = {
    "package": "dnsmasq-2.89-6.tl4",
    "cves": {
        "CVE-2026-2291": {
            "title": "struct bigname: buffer too small for domain names — overflow",
            "severity": "HIGH",
            "description": (
                "Buffers holding domain names must be MAXDNAME*2+1 bytes minimum "
                "(accounts for escaped chars in internal representation). "
                "struct bigname was undersized; crafted DNS response with max-length "
                "domain names overflows the buffer. "
                "Reported internally."
            ),
            "class": "heap-overflow",
            "pre_auth": True,
            "vector": "DNS",
        },
        "CVE-2026-4890": {
            "title": "NSEC bitmap parsing: infinite loop via missing window size advance",
            "severity": "HIGH",
            "description": (
                "dnssec.c:1290-1306: NSEC bitmap window iteration advances by p[1] "
                "instead of p[1]+2 (skipping the 2-byte window header). "
                "With bitmap_length=0, rdlen and p do not advance → infinite loop. "
                "Crafted DNSSEC response → dnsmasq hangs. "
                "Reported by Royce M <royce@xchglabs.com>."
            ),
            "class": "infinite-loop",
            "pre_auth": True,
            "vector": "DNSSEC",
        },
        "CVE-2026-4891": {
            "title": "RRSIG: negative rdlen on crafted packet → memory access",
            "severity": "HIGH",
            "description": (
                "RRSIG rdlen not validated for minimum size. A crafted packet with "
                "rdlen less than the size of the fixed data + signer name produces "
                "a negative calculated signature length → invalid memory access. "
                "Reported by Royce M."
            ),
            "class": "integer-underflow",
            "pre_auth": True,
            "vector": "DNSSEC",
        },
        "CVE-2026-4892": {
            "title": "helper.c: DHCPv6 CLID hex-encode buffer overflow — root process",
            "severity": "CRITICAL",
            "description": (
                "helper.c:265-270: DHCPv6 CLIDs can be up to 65535 bytes. "
                "When --dhcp-script is configured, the helper hex-encodes raw CLID bytes "
                "via sprintf('%.2x') into daemon->packet (5131 bytes). "
                "A 1000-byte CLID writes ~3000 bytes; a 65535-byte CLID writes ~131070 bytes. "
                "The helper process retains root privileges. "
                "Buffer overflow in a root-privileged process with a DHCPv6 client that "
                "sends a long CLID. "
                "Reported by Royce M."
            ),
            "class": "heap-overflow",
            "pre_auth": True,
            "vector": "DHCPv6",
            "agent_privilege": "root",
        },
        "CVE-2026-4893": {
            "title": "forward.c: OPT record length vs packet length confusion — subnet validation bypass",
            "severity": "MEDIUM",
            "description": (
                "With --add-subnet enabled, process_reply() passes the OPT record length "
                "instead of the packet length to check_source(). "
                "Incorrect packet boundary → subnet validation bypass."
            ),
            "class": "logic-error",
            "pre_auth": True,
            "vector": "DNS",
        },
    },
}

BIND = {
    "package": "bind-9.18.21-6.tl4",
    "cves": {
        "CVE-2023-4408": {"title": "DNS message parsing DoS", "severity": "HIGH"},
        "CVE-2023-5517": {"title": "nxdomain-redirect: assertion failure", "severity": "HIGH"},
        "CVE-2023-5679": {"title": "Assertion failure with recursive resolver", "severity": "HIGH"},
        "CVE-2023-50387": {"title": "DNSSEC: KeyTrap — DNSKEY attack", "severity": "HIGH"},
        "CVE-2023-50868": {"title": "DNSSEC: NSEC3 attack DoS", "severity": "HIGH"},
        "CVE-2025-8677": {"title": "bind CVE-2025-8677 (details in patch)", "severity": "HIGH"},
        "CVE-2025-40778": {"title": "bind CVE-2025-40778 (details in patch)", "severity": "MEDIUM"},
        "CVE-2025-40780": {"title": "bind CVE-2025-40780 (details in patch)", "severity": "MEDIUM"},
    },
}

TENCENT_ORIGINATED_CVES = [
    {
        "cve": "CVE-2024-10963",
        "package": "pam",
        "author": "wynnfeng@tencent.com",
        "description": "pam_access hostname token resolution security fix",
    },
    {
        "cve": "CVE-2025-62168",
        "package": "squid",
        "author": "zidonghuang@tencent.com",
        "description": "squid memory corruption fix (backported upstream)",
    },
]

AI_PORTED_CVES = [
    {
        "cve": "CVE-2026-42055",
        "package": "nginx",
        "ported_by": "PkgAgent/deepseek-v4",
        "target": "opencloudos-stream",
        "description": "HTTP/2 gRPC header length buffer overflow",
        "instance_number": 5,
    },
]

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "cve": "CVE-2026-14476",
        "package": "sssd-2.9.4",
        "title": "GPO path traversal: AD write access → arbitrary file write → root LPE",
        "detail": (
            "gPCFileSysPath LDAP attr with '..' component: libsmbclient clamps at SMB share root "
            "(download succeeds), kernel resolves '..' fully (write escapes cache). "
            "Without SELinux: cron job injection → root exec. "
            "With SELinux: Kerberos config injection via /var/lib/sss/pubconf/krb5.include.d/."
        ),
    },
    {
        "id": "F2",
        "severity": "CRITICAL",
        "cve": "CVE-2026-4892",
        "package": "dnsmasq-2.89",
        "title": "DHCPv6 CLID: heap overflow in root-privileged helper — 65535-byte CLID",
        "detail": (
            "helper.c sprintf('%.2x') loop: 65535-byte CLID writes 131070 bytes into 5131-byte "
            "daemon->packet. Helper runs as root with --dhcp-script. Pre-auth via DHCPv6 client."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2025-11230",
        "package": "haproxy-2.6.19",
        "title": "mjson strtod O(exp) DoS: single crafted JSON number blocks worker",
        "detail": (
            "1e999999 in JSON causes haproxy worker to loop for exponential time. "
            "Reachable via any HTTP path that processes JSON. Pre-auth. Worker blocks permanently."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "cve": "CVE-2026-40701",
        "package": "nginx-1.29.8",
        "title": "OCSP stapling UAF on SSL connection close during resolve",
        "detail": (
            "OCSP context freed on connection close but resolve context not released. "
            "UAF on resolve completion. Remotely exploitable by clients that trigger OCSP and disconnect."
        ),
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "cve": "CVE-2025-32462",
        "package": "sudo-1.9.15p5",
        "title": "sudo -h host filter bypass: non-list mode accepts host specification",
        "detail": (
            "User sets ctx->runas.host to a different host in non-list mode. "
            "sudoers host restrictions applied to specified host instead of local host → bypass. "
            "Fixed: reject runas.host != user.host when not MODE_LIST."
        ),
    },
    {
        "id": "F6",
        "severity": "HIGH",
        "cve": "CVE-2025-32463",
        "package": "sudo-1.9.15p5",
        "title": "sudoedit: symlink attack via pivot.c chroot path — removed entirely",
        "detail": (
            "pivot.c's chroot environment for editor path resolution vulnerable to symlink attack. "
            "Fix: remove pivot.c (730+ line patch). Safer path resolution in find_path.c."
        ),
    },
    {
        "id": "F7",
        "severity": "HIGH",
        "cve": "CVE-2025-6020",
        "package": "pam-1.5.3",
        "title": "pam_namespace: mount namespace race → LPE from user with unshare capability",
        "detail": (
            "protect_dir() bind-mount protection only works in same mount namespace. "
            "User with unshare + colluding exploit races → root. "
            "Three-patch series from ANSSI/Red Hat."
        ),
    },
    {
        "id": "F8",
        "severity": "HIGH",
        "cve": "CVE-2025-24528",
        "package": "krb5-1.21.2",
        "title": "kadmind iprop log: authenticated write beyond mmap boundary",
        "detail": (
            "kdb_log.c:resize() integer overflow on update_size > 65535. "
            "kadmind writes beyond mmap'd region. Authenticated kadmin + iprop enabled."
        ),
    },
    {
        "id": "F9",
        "severity": "HIGH",
        "cve": "CVE-2026-32748",
        "package": "squid-6.5",
        "title": "ICP v3: HttpRequest UAF on ICP query after ACLChecklist destructor",
        "detail": (
            "On-stack ACLFilledChecklist destroys unlocked HttpRequest on return. "
            "Squid dereferences freed request. Reachable via UDP ICP port (3130) without auth."
        ),
    },
    {
        "id": "F10",
        "severity": "HIGH",
        "cve": "CVE-2026-42055",
        "package": "nginx-1.29.8",
        "title": "HTTP/2 gRPC header overflow (AI-ported by PkgAgent/deepseek-v4) — 5th AI patch",
        "detail": (
            "HTTP/2 upstream header length limit not applied to gRPC headers. "
            "Buffer overflow via crafted HTTP/2 headers. AI-ported by PkgAgent/deepseek-v4 "
            "(5th AI-ported security patch in TOS 4.6)."
        ),
    },
    {
        "id": "F11",
        "severity": "MEDIUM",
        "cve": "CVE-2024-10963",
        "package": "pam-1.5.3",
        "title": "pam_access hostname resolution bypass (Tencent-authored: wynnfeng@tencent.com)",
        "detail": (
            "PAM access control host tokens resolved insecurely → auth bypass. "
            "Authored by wynnfeng@tencent.com (same engineer as OpenSSL CVE-2026-34182)."
        ),
    },
    {
        "id": "F12",
        "severity": "INFO",
        "title": "2 Tencent-authored CVE fixes: pam CVE-2024-10963 + squid CVE-2025-62168",
        "detail": (
            "wynnfeng@tencent.com: pam_access hostname resolution. "
            "zidonghuang@tencent.com: squid memory corruption backport. "
            "Confirms TOS engineers are active upstream security contributors."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 srpm_work security stack RE")
    packages = [HAPROXY, NGINX, SUDO, SSSD, KRB5, PAM, POLKIT_123, SQUID, DNSMASQ, BIND]
    total_cves = sum(len(p["cves"]) for p in packages)
    print(f"  packages: {len(packages)}")
    print(f"  total CVEs documented: {total_cves}")
    print(f"  Tencent-originated: {len(TENCENT_ORIGINATED_CVES)}")
    print(f"  AI-ported patches: {len(AI_PORTED_CVES)} (total in TOS 4.6: {AI_PORTED_CVES[0]['instance_number']})")
    print()
    for f in FINDINGS:
        cve = f"[{f.get('cve', '')}] " if f.get('cve') else ""
        print(f"  [{f['severity']:8s}] {f['id']}: {cve}{f['title'][:65]}")
