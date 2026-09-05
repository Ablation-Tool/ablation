"""
TencentOS 4.6 — vsftpd 3.0.5 binary RE.

Binary: vsftpd_work/usr/sbin/vsftpd — 176KB PIE ELF, x86-64, stripped
Source: srpm_work/vsftpd-3.0.5-6.tl4/ — 59 Fedora/RHEL patches + 2 TOS-specific

Method: endbr64 function detection (148 funcs) → capstone disassembly →
BERT semantic sweep (all-MiniLM-L6-v2, 5 profiles) → manual disassembly of
top candidates → strncpy call site audit.

Build: vsftpd 3.0.5-6.tl4 (TOS 4.6)
Security features: PIE, RELRO (full), NX, stack canary, FORTIFY_SOURCE=2,
capabilities (libcap), PAM, chroot+clone isolation, OpenSSL 3.0.0 TLS.
"""

BINARY_INVENTORY = {
    "vsftpd": {
        "path": "vsftpd_work/usr/sbin/vsftpd",
        "size": 180072,
        "type": "ELF 64-bit PIE executable",
        "stripped": True,
        "text_va": 0x7930,
        "text_size": 0x19c16,
        "functions_detected": 148,
        "build_id": "0a92707f65c3a86f872c36f11cdac10cab5826d7",
        "openssl": "OpenSSL 3.0.0",
        "version": "3.0.5",
        "release": "6.tl4",
    },
}

SECURITY_PROPERTIES = {
    "PIE": True,
    "RELRO": "Full (GNU_RELRO + -Wl,-z,now in Makefile)",
    "NX": True,
    "stack_canary": True,
    "FORTIFY_SOURCE": 2,
    "seccomp": "DISABLED — tunable_seccomp_sandbox default 0 (see patch 0034)",
    "capabilities": "libcap: drop all caps after chroot (cap_get_proc/cap_set_proc/cap_set_flag)",
    "isolation": "clone() + chroot() + setuid/setgid for each connection",
    "PAM": "pam_start/pam_authenticate/pam_acct_mgmt/pam_open_session",
    "tls": "OpenSSL 3.0.0 — SSL_CTX_new, SSL_accept, SSL_read/write",
}

PLT_AUDIT = {
    "present": [
        "strncpy (9 call sites)",
        "strlen",
        "memcpy",
        "memset",
        "__snprintf_chk (FORTIFY_SOURCE snprintf)",
        "__sprintf_chk (FORTIFY_SOURCE sprintf)",
        "__fdelt_chk (fd range check)",
        "SSL_read",
        "SSL_write",
        "SSL_accept",
        "SSL_shutdown",
    ],
    "absent": [
        "strcpy (not in PLT)",
        "strcat (not in PLT)",
        "sprintf (raw, non-FORTIFY — not in PLT)",
        "gets",
        "snprintf (raw — uses __snprintf_chk instead)",
    ],
    "note": (
        "vsftpd uses its own string library (str.c, sysstr.c) rather than libc string functions. "
        "All external string copies are via strncpy with explicit literal size limits. "
        "The internal library checks for strings suspiciously longer than 0xfffffff bytes "
        "(die() with 'string suspiciously long' at 0x9860)."
    ),
}

STRNCPY_AUDIT = {
    "call_sites": 9,
    "clusters": {
        "cluster_0xf461_0xf547": {
            "sites": [0xf461, 0xf482, 0xf4a8, 0xf513, 0xf52e, 0xf547],
            "function_context": "FTP LIST timestamp parser",
            "description": (
                "Parse month/day/year/hour/min fields from directory listing response. "
                "Copy sizes: 4, 2, 2, 2, 2, 2 bytes — all literal constants. "
                "Each field followed by explicit zero-terminator write."
            ),
            "verdict": "SAFE — fixed literal sizes, bounded field parsing",
        },
        "cluster_0x1aec0_0x1af11": {
            "sites": [0x1aec0, 0x1af11],
            "function_context": "TLS SNI hostname storage",
            "description": (
                "0x1aec0: strncpy(static_buf, r12, 0x20) — SNI hostname into 32-byte buffer. "
                "0x1af11: strncpy(static_buf, [rbx+0x60], 0x20) — SSL session field, 32 bytes. "
                "Both followed by explicit null write to byte after last position."
            ),
            "verdict": "SAFE — 32-byte bounded with explicit null terminator",
        },
        "site_0x1af3e": {
            "site": 0x1af3e,
            "function_context": "SSL certificate field storage",
            "description": (
                "strncpy(static_buf, [rbx+0x130], 0x100) — certificate subject/CN into 256-byte buffer. "
                "[rbx+0x130] is a field from the vsf_session struct (SSL peer cert info). "
                "0x100 = 256 byte maximum."
            ),
            "verdict": "SAFE — 256-byte bounded; certificate fields are constrained by TLS protocol",
        },
    },
    "overall": "All 9 strncpy call sites safe — no user-controlled unbounded copies",
}

BERT_SWEEP = {
    "method": "5 query profiles, all-MiniLM-L6-v2, cosine similarity, 148 functions",
    "profiles": {
        "FTP_BUF_OVF": {
            "max_score": 0.398,
            "top_hit_va": 0x12f20,
            "top_strings": [],
            "top_calls": ["malloc"],
            "verdict": "FALSE_POSITIVE — simple malloc wrapper (allocate N bytes, return ptr or NULL)",
        },
        "FTP_BUF_OVF_runner_up": {
            "score": 0.392,
            "va": 0x97d0,
            "top_strings": ["string suspiciously long", "(null)"],
            "verdict": "FALSE_POSITIVE — vsftpd's internal string safety check; die() call site",
        },
        "FTP_AUTH_BYPASS": {
            "max_score": 0.367,
            "top_hit_va": 0x17760,
            "top_calls": ["pam_close_session", "pam_setcred", "pam_end"],
            "verdict": "FALSE_POSITIVE — PAM session cleanup on logout, not authentication gate",
        },
        "FTP_PATH_TRAVERSAL": {
            "max_score": 0.300,
            "top_hit_va": 0x16b90,
            "top_calls": ["fork"],
            "verdict": "FALSE_POSITIVE — process fork for connection isolation",
        },
        "FTP_FORMAT_STR": {
            "max_score": 0.293,
            "top_hit_va": 0x17760,
            "verdict": "FALSE_POSITIVE — same PAM cleanup function",
        },
        "FTP_TLS_BYPASS": {
            "max_score": 0.495,
            "top_hit_va": 0x18f00,
            "top_strings": ["DATA", " connection terminated without SSL shutdown.",
                            " Buggy client! Integrity of upload cannot be asserted."],
            "top_calls": ["SSL_get_error", "SSL_get_shutdown"],
            "verdict": "FALSE_POSITIVE — SSL shutdown enforcement function; aborts data connection if peer doesn't send close_notify",
        },
    },
    "overall": (
        "No HIGH-confidence patterns. Max score 0.495 (TLS bypass) resolved to the opposite: "
        "strict_ssl_read_eof enforcement that rejects connections without proper TLS close_notify. "
        "vsftpd's internal string library (str.c) drives false BUF_OVF scores on safety-check functions."
    ),
}

TLS_SHUTDOWN_ANALYSIS = {
    "function_va": 0x18f00,
    "role": "SSL read/write wrapper with strict_ssl_read_eof enforcement",
    "analysis": (
        "Calls a function pointer (rbp) — the actual SSL_read or SSL_write operation. "
        "If return value < 0: checks SSL_get_error, loops on WANT_READ/WANT_WRITE. "
        "If return value == 0 (EOF): calls SSL_get_shutdown(ssl). "
        "If SSL_RECEIVED_SHUTDOWN bit NOT set (== 2): "
        "  - For the data connection: logs 'DATA connection terminated without SSL shutdown.' "
        "    and 'Buggy client! Integrity of upload cannot be asserted.' "
        "  - Calls the error handler at 0x189d0. "
        "This is the strict_ssl_read_eof option enforcement — it protects uploads "
        "from truncation attacks (RFC 5246 §7.2.1) by requiring the peer to send "
        "SSL close_notify before closing. "
        "Verdict: security feature, not a bypass."
    ),
    "verdict": "SECURITY_FEATURE — strict TLS shutdown enforcement prevents upload truncation attacks",
}

SECCOMP_ANALYSIS = {
    "patch": "0034-Turn-off-seccomp-sandbox-because-it-is-too-strict.patch",
    "original_default": "tunable_seccomp_sandbox = 1",
    "new_default": "tunable_seccomp_sandbox = 0",
    "impact": (
        "vsftpd upstream uses a seccomp BPF filter to limit the syscalls available to "
        "the child process after privilege drop. The RHEL/Fedora package disables this "
        "because the default TOS/RHEL deployment adds features (PAM, system logging, "
        "LSM hooks) that the upstream filter blocks. "
        "Effect: any code execution in vsftpd's child process after privilege drop has "
        "access to the full syscall table — the seccomp layer provides no defense-in-depth. "
        "Severity: INFO (seccomp was the last layer after chroot+drop_caps+setuid — "
        "the primary isolation is unaffected; seccomp was belt-and-suspenders)."
    ),
    "note": "seccomp_sandbox=1 can be set in vsftpd.conf to re-enable; requires testing for PAM compatibility",
}

SRPM_PATCHES_SUMMARY = {
    "total_patches": 59,
    "tl4_specific": 2,
    "security_relevant": {
        "0029-Fix-segfault-in-config-file-parser.patch": (
            "str_strdup_trimmed(): `newlen = t - h + 1` where t, h are int; "
            "if t < h (all-whitespace string), newlen is negative, then cast to unsigned int "
            "produces a huge value passed to vsf_sysutil_strndup — heap allocation of ~4GB fails, "
            "or on some allocators truncates. Fix: check `newlen > 0` before use. "
            "Input: whitespace-only value in config file. Config file must be root-owned — "
            "not a remote attack surface."
        ),
        "0034-Turn-off-seccomp-sandbox.patch": "See SECCOMP_ANALYSIS above.",
        "0049-STOU-better-filename-generation.patch": (
            "Adds optional better_stou=YES config knob. New create_unique_file() uses "
            "glibc __gen_tempname() algorithm (time ^ pid seed, 62^6 attempts). "
            "Old algorithm: simple numeric suffix — predictable in some scenarios. "
            "Not a security fix per se, but reduces STOU filename predictability for "
            "anonymous upload deployments."
        ),
        "0059-Fix-SEGFAULT-container-PID1.patch": (
            "handle_sigchld() in standalone.c: when receiving SIGCHLD for a PID not in "
            "s_p_pid_ip_hash (e.g., orphaned child in a container as PID 1), "
            "hash_lookup_entry returns NULL, which was then dereferenced. "
            "Fix: guard drop_ip_count and hash_free_entry on p_ip != NULL. "
            "Requires: vsftpd as PID 1 in container + many rapid connections to trigger race. "
            "Severity: LOW — crash only, no memory corruption."
        ),
        "fix-str_open.patch": (
            "str_open() (sysstr.c): removes dead code path that called bug() on "
            "kVSFSysStrOpenUnknown. No security impact — refactor only."
        ),
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "vsftpd 3.0.5: seccomp sandbox disabled in TOS/RHEL build (tunable_seccomp_sandbox=0)",
        "detail": (
            "Patch 0034 sets tunable_seccomp_sandbox default = 0. Post-exploit code execution "
            "in vsftpd child (post chroot/setuid) has full syscall access. Primary isolation "
            "(chroot, capability drop, setuid, clone) intact. seccomp was defense-in-depth. "
            "Can be re-enabled in vsftpd.conf but requires PAM compatibility testing."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "SIGCHLD NULL deref as PID 1 in container — crash (fixed by 0059 patch)",
        "detail": (
            "handle_sigchld() dereferences hash_lookup_entry() result without NULL check. "
            "Trigger: vsftpd as PID 1 in a container receiving SIGCHLD for orphaned pids. "
            "Fixed in TOS 4.6 build by 0059 patch. "
            "Severity: LOW (crash, no corruption). Not a remote exploit."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "Config parser str_strdup_trimmed: negative newlen cast to uint → huge strndup (fixed by 0029 patch)",
        "detail": (
            "All-whitespace config value: t < h → newlen = t - h + 1 < 0 → "
            "cast to uint ~= 4GB → strndup fails or allocates incorrectly. "
            "Fixed by `newlen > 0` guard. Config must be root-owned — not remote-triggerable."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "vsftpd 3.0.5: 148 functions, BERT sweep — no HIGH-confidence vulnerability patterns",
        "detail": (
            "5 BERT profiles (FTP_BUF_OVF, AUTH_BYPASS, PATH_TRAVERSAL, FORMAT_STR, TLS_BYPASS). "
            "Max score 0.495 (TLS_BYPASS @ 0x18f00) — strict_ssl_read_eof enforcement, not bypass. "
            "9 strncpy sites, all bounded by literal constants. No strcpy/strcat in PLT."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "TLS strict_ssl_read_eof enforcement at 0x18f00: protects uploads from truncation (feature)",
        "detail": (
            "SSL read/write wrapper checks SSL_get_shutdown == 2 on EOF. "
            "If peer closes without close_notify: aborts data connection. "
            "Prevents RFC 5246 §7.2.1 truncation attacks on file uploads."
        ),
    },
]

if __name__ == '__main__':
    print(f"TOS 4.6 vsftpd {BINARY_INVENTORY['vsftpd']['version']}-{BINARY_INVENTORY['vsftpd']['release']} binary RE")
    print(f"  {BINARY_INVENTORY['vsftpd']['size']//1024}KB stripped PIE, "
          f"{BINARY_INVENTORY['vsftpd']['functions_detected']} functions")
    print()
    print("Security properties:")
    for k, v in SECURITY_PROPERTIES.items():
        if isinstance(v, bool):
            print(f"  {k}: {'YES' if v else 'NO'}")
        else:
            print(f"  {k}: {str(v)[:72]}")
    print()
    print("PLT audit: no strcpy/strcat/raw-sprintf; 9 strncpy sites (all bounded)")
    print()
    print("BERT sweep (5 profiles, 148 funcs):")
    max_s = max(v['max_score'] for v in BERT_SWEEP['profiles'].values() if 'max_score' in v)
    print(f"  max score: {max_s:.3f} — TLS enforcement function (security feature)")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
