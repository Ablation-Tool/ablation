"""
TencentOS Server 4.6 vsftpd Full Patch Audit RE Module
Binary: /usr/sbin/vsftpd (ELF 64-bit PIE, 180072 bytes)
SRPM: vsftpd-3.0.5-6.tl4.src.rpm
Patch set: 66 patches (59 numbered + fix-str_open + wc_logs + 5 unnumbered)
Analysis date: 2026-09-04

CORRECTION TO tencent_tos46_vsftpd_re.py TOS46-FTP-F01:
  WRONG: "seccomp sandboxing active"
  CORRECT: seccomp is DISABLED by default
  Evidence: patch 0034 sets tunable_seccomp_sandbox = 0 in tunables.c
  The binary carries the seccomp CODE but the feature is off by default.
  prctl PR_SET_SECCOMP string is present but unreachable in normal operation.

BINARY HARDENING (corrected):
  PIE: yes (-fPIE -pie)
  RELRO: FULL (-Wl,-z,relro -Wl,-z,now confirmed from Makefile in 0047)
  Stack protector: yes (-fstack-protector --param=ssp-buffer-size=4)
  FORTIFY_SOURCE: 2 (-D_FORTIFY_SOURCE=2)
  seccomp: CODE PRESENT, DISABLED by default (tunable_seccomp_sandbox = 0)
  capabilities: cap_get_proc, cap_set_flag, cap_set_proc (DROP at startup)
  NO_NEW_PRIVS: yes (prctl PR_SET_NO_NEW_PRIVS)
  tcp_wrappers: REMOVED (patch 0047 removes -lwrap and VSF_BUILD_TCPWRAPPERS)
"""

# ──────────────────────────────────────────────────────────────────────────────
# BINARY INVENTORY (corrected)
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_BINARY = {
    "path": "/usr/sbin/vsftpd",
    "size_bytes": 180072,
    "build_id": "0a92707f65c3a86f872c36f11cdac10cab5826d7",
    "build_date": "2025-01-15",
    "format": "ELF 64-bit LSB pie executable, x86-64, stripped",
    "pie": True,
    "full_relro": True,
    "stack_protector": True,
    "fortify_source": 2,
    "seccomp_code_present": True,
    "seccomp_enabled_default": False,
    "tcp_wrappers": False,
    "capabilities": ["cap_get_proc", "cap_set_flag", "cap_set_proc"],
    "no_new_privs": True,
    "ssl_library": "OpenSSL (OPENSSL_init_ssl, TLS_server_method)",
    "package": "vsftpd-3.0.5-6.tl4",
    "patch_count": 66,
    "default_listen": "IPv6 (listen_ipv6=YES, listen=NO — patch 0015)",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F01 (CORRECTED): seccomp DISABLED by default
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_SECCOMP_DISABLED = {
    "finding_id": "TOS46-FTP-F01",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "title": (
        "vsftpd-3.0.5-6.tl4: seccomp syscall sandboxing disabled by default "
        "(patch 0034 sets tunable_seccomp_sandbox = 0); binary has seccomp code "
        "but tunable defaults to off — exploitation does not need to bypass seccomp"
    ),
    "description": (
        "Patch 0034 ('Turn off seccomp sandbox because it is too strict') "
        "modifies tunables.c: "
        "\n"
        "  Before: tunable_seccomp_sandbox = 1  (ON by default) "
        "  After:  tunable_seccomp_sandbox = 0  (OFF by default) "
        "\n"
        "The commit message is explicit: 'the sandbox was preventing vsftpd from "
        "working correctly on modern Linux kernels.' This is the same trade-off "
        "made by many distros (RHEL 8+ also disabled vsftpd seccomp). "
        "\n"
        "Impact: a memory corruption vulnerability in vsftpd worker processes "
        "(e.g., heap overflow in data channel handling, or buffer overflow in "
        "TLS layer) does NOT require a seccomp filter bypass to reach execve() "
        "or other dangerous syscalls. The remaining mitigations are: "
        "  - FULL RELRO (no .got.plt overwrites) "
        "  - PIE (ASLR applies) "
        "  - NO_NEW_PRIVS (post-exploit escalation via SUID blocked) "
        "  - capability drop (CAP_NET_BIND_SERVICE only after bind) "
        "\n"
        "Attack chain: if vsftpd worker is exploited, attacker gets code execution "
        "as the vsftpd user (ftp or nobody). NO_NEW_PRIVS blocks SUID escalation. "
        "Lateral movement requires a kernel exploit or a local privilege escalation "
        "in another daemon. "
        "\n"
        "Seccomp can be re-enabled in vsftpd.conf: "
        "  seccomp_sandbox=YES "
        "but this is likely to break vsftpd functionality on TOS 4.6 kernels. "
        "Test before enabling in production."
    ),
    "patch_evidence": {
        "patch_file": "0034-Turn-off-seccomp-sandbox-because-it-is-too-strict.patch",
        "change": "tunables.c: tunable_seccomp_sandbox default 1 -> 0",
        "binary_string": "prctl PR_SET_SECCOMP failed (present but unreachable)",
    },
    "recommendation": (
        "Evaluate seccomp_sandbox=YES on the specific kernel version. "
        "If it works, enable it. If not, rely on the remaining mitigations "
        "and keep vsftpd updated for any new CVEs in the TLS/data-channel code."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F02: config parser heap corruption (patch 0029)
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_CONFIG_HEAP_OVERFLOW = {
    "finding_id": "TOS46-FTP-F02",
    "severity": "LOW",
    "cvss_v3": 2.5,
    "cvss_vector": "AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L",
    "title": (
        "vsftpd config parser heap corruption: all-whitespace config line causes "
        "negative newlen cast to unsigned int (~4GB), passed to strndup(); "
        "fixed in TOS 4.6 by patch 0029 (return newlen -> return (newlen > 0))"
    ),
    "description": (
        "Upstream vsftpd str.c str_alloc_trimmed_realpath(): "
        "\n"
        "  h = leading whitespace count; t = trailing whitespace end index "
        "  newlen = t - h + 1  "
        "  return newlen ? vsf_sysutil_strndup(p+h, (unsigned int)newlen) : NULL "
        "\n"
        "When the config line is entirely whitespace: h > t after trimming, "
        "so newlen is negative (e.g., -8 for an 8-space line). The conditional "
        "'return newlen ?' evaluates TRUE for any non-zero value including "
        "negative. Cast to unsigned int: (unsigned int)(-8) = 4294967288. "
        "strndup(p + h, 4294967288) is called — allocation of ~4GB. "
        "\n"
        "On 64-bit Linux, malloc(4294967289) returns NULL (ENOMEM). "
        "vsftpd config parser then dereferences the NULL return → SIGSEGV. "
        "This is a DoS against the config loader, not a code execution path. "
        "\n"
        "Trigger: write a line of only spaces to vsftpd.conf (requires root). "
        "Impact: vsftpd fails to start, causing service outage. "
        "\n"
        "Fix: patch 0029 changes the conditional to 'return (newlen > 0) ?' "
        "so negative values return NULL (empty trim) rather than triggering strndup."
    ),
    "patch_evidence": {
        "patch_file": "0029-Fix-segfault-in-config-file-parser.patch",
        "change": "str.c: 'return newlen ?' -> 'return (newlen > 0) ?'",
        "source_function": "str_alloc_trimmed_realpath()",
        "affected_upstream_versions": "vsftpd 3.0.5 upstream and prior distro patches",
    },
    "attack_chain": (
        "Local root writes whitespace-only line to vsftpd.conf → "
        "vsftpd restart (e.g., cron reload or manual) → config parse crash → "
        "service unavailable. Denial-of-service, not code execution."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F03: deny_file filter bypass via relative path (patch 0007)
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_DENY_FILE_BYPASS = {
    "finding_id": "TOS46-FTP-F03",
    "severity": "MEDIUM",
    "cvss_v3": 5.4,
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "title": (
        "vsftpd deny_file filter bypass via relative path: ./secret or ../path/secret "
        "bypasses deny_file glob match in ls.c; fixed by resolving to absolute path "
        "before applying filter (patch 0007)"
    ),
    "description": (
        "vsftpd supports deny_file=<glob> to hide/block specific filenames. "
        "The upstream filter compared the literal filename against the glob pattern. "
        "A file named '.htaccess' could be accessed as './.htaccess' because the "
        "filter matched on the base name after the last slash, not the resolved path. "
        "\n"
        "Patch 0007 ('Make filename filters smarter') fixes ls.c to resolve the "
        "file path to an absolute canonical form before applying the deny_file "
        "glob check. Relative path components ('.' and '..') are resolved before "
        "comparison. "
        "\n"
        "Attack scenario: "
        "  deny_file=.htaccess in vsftpd.conf "
        "  GET ./.htaccess → bypass → file returned "
        "  Before fix: filter only matches bare 'name', not './name' "
        "\n"
        "This requires the operator to rely on deny_file for access control "
        "(not the default). Operators who use deny_file to hide sensitive "
        "dotfiles (.env, .git, config files) are at risk without this patch."
    ),
    "patch_evidence": {
        "patch_file": "0007-Make-filename-filters-smarter.patch",
        "change": "ls.c: resolve to absolute path before deny_file glob filter",
    },
    "default_config_status": "NOT AFFECTED unless operator sets deny_file=",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F04: timezone OOB stack read (patch 0055)
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_TZ_STACK_READ = {
    "finding_id": "TOS46-FTP-F04",
    "severity": "LOW",
    "cvss_v3": 3.7,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "title": (
        "vsftpd vsf_sysutil_get_tz(): size_t used for read() return value; "
        "on read() error, rcnt = SIZE_MAX → buff[SIZE_MAX-1] OOB stack access; "
        "fixed by patch 0055 (size_t -> ssize_t + error return path)"
    ),
    "description": (
        "vsf_sysutil_get_tz() in sysutil.c reads /etc/localtime to determine "
        "the local timezone offset. Original code: "
        "\n"
        "  char buff[BUFTZSIZ];  /* stack buffer */ "
        "  size_t rcnt = read(fd, buff, BUFTZSIZ); "
        "  if (rcnt && buff[rcnt-1] == '\\n') ... "
        "\n"
        "If read() returns -1 (error): "
        "  rcnt = (size_t)(-1) = 18446744073709551615 (SIZE_MAX on 64-bit) "
        "  condition: rcnt && buff[18446744073709551614] == '\\n' "
        "  → reads from stack address BUFF_ADDR + SIZE_MAX - 1 "
        "  → OOB stack read (segfault or information disclosure from adjacent stack) "
        "\n"
        "Trigger: /etc/localtime unreadable (tampered permissions, disk error, "
        "or container with missing localtime). "
        "\n"
        "Fix (patch 0055): changes to ssize_t + adds explicit error check: "
        "  ssize_t rcnt = read(fd, buff, BUFTZSIZ); "
        "  if (rcnt < 0) { close(fd); return NULL; } "
        "\n"
        "Also: lseek and calloc return values now checked; close() error checked. "
        "\n"
        "In context: vsf_sysutil_get_tz() is called early in vsftpd startup. "
        "Information disclosure from adjacent stack frames could expose "
        "stack canary or pointer values if an attacker can control /etc/localtime "
        "readability (unlikely in normal operation)."
    ),
    "patch_evidence": {
        "patch_file": "0055-vsf_sysutil_get_tz-Check-the-return-value-of-syscall.patch",
        "change": "sysutil.c: size_t rcnt -> ssize_t rcnt; error return on rcnt < 0",
        "source_function": "vsf_sysutil_get_tz()",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F05: container PID 1 SIGCHLD null deref (patch 0059)
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_PID1_SIGCHLD_NULLDEREF = {
    "finding_id": "TOS46-FTP-F05",
    "severity": "LOW",
    "cvss_v3": 4.3,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "title": (
        "vsftpd SIGCHLD handler: NULL deref when vsftpd runs as PID 1 in a container "
        "and a client connects then disconnects rapidly; p_ip NULL check missing; "
        "fixed by patch 0059"
    ),
    "description": (
        "In standalone.c, the SIGCHLD handler handle_sigchld() calls "
        "drop_ip_count() with p_ip which can be NULL when a connection attempt "
        "is rejected at the accept() layer (before client struct is fully initialized). "
        "\n"
        "When vsftpd runs as PID 1 (typical in Docker/container deployments), "
        "the process inherits all orphaned child signal delivery. A rapid "
        "connect-disconnect sequence by an unauthenticated client can race the "
        "SIGCHLD handler and trigger a NULL pointer dereference → process crash → "
        "FTP service unavailable. "
        "\n"
        "Fix (patch 0059): adds NULL check for p_ip before calling drop_ip_count(): "
        "  if (p_ip != NULL) { drop_ip_count(p_ip); } "
        "\n"
        "Attack chain (unauthenticated): "
        "  1. vsftpd running as container PID 1 "
        "  2. Rapid TCP connections to port 21 with immediate RST "
        "  3. SIGCHLD race → NULL deref → vsftpd crash → DoS "
        "\n"
        "Not applicable when vsftpd runs under systemd (not PID 1)."
    ),
    "patch_evidence": {
        "patch_file": "0059-Fix-SEGFAULT-when-running-in-a-container-as-PID-1.patch",
        "change": "standalone.c: add NULL check for p_ip before drop_ip_count()",
    },
    "default_config_status": "Only affects container/PID-1 deployments",
    "attack_chain_severity": "Pre-auth DoS in container deployments",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F06: default write_enable=YES with local_enable=YES
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_WRITE_ENABLE_DEFAULT = {
    "finding_id": "TOS46-FTP-F06",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "title": (
        "vsftpd default config: write_enable=YES with local_enable=YES — "
        "all locally authenticated users can STOR, DELE, MKD, RMD by default"
    ),
    "description": (
        "Default /etc/vsftpd/vsftpd.conf on TOS 4.6: "
        "  anonymous_enable=NO   (correct — anon disabled) "
        "  local_enable=YES      (local system users can authenticate) "
        "  write_enable=YES      (all write FTP commands enabled) "
        "  listen_ipv6=YES       (listening on IPv6 :: = dual-stack) "
        "\n"
        "write_enable=YES enables: STOR, APPE, MKD, RMD, RNFR, RNTO, DELE, STOU. "
        "\n"
        "Any local user with a valid shell (/etc/shells check via pam_shells.so) "
        "can authenticate and write to any directory they have filesystem write "
        "permission on. Combined with chroot_local_user=NO (default), users can "
        "traverse the entire filesystem. "
        "\n"
        "Attack chain: "
        "  1. Attacker compromises low-privilege local user (web app, leaked creds). "
        "  2. FTP to vsftpd on port 21 (default open). "
        "  3. write_enable=YES → upload webshell to web root if user has write access. "
        "  4. Or overwrite ~/.bashrc / ~/.ssh/authorized_keys for persistence. "
        "\n"
        "Note: pam_shells.so + ftpusers deny-list provide some filtering, "
        "but write_enable=YES ships on by default without any explicit opt-in."
    ),
    "default_config_lines": [
        "anonymous_enable=NO",
        "local_enable=YES",
        "write_enable=YES",
        "listen_ipv6=YES",
    ],
    "recommendation": "Set write_enable=NO in default config; require explicit opt-in.",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F07: tcp_wrappers removed — pre-auth host ACL eliminated
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_TCPWRAPPERS_REMOVED = {
    "finding_id": "TOS46-FTP-F07",
    "severity": "INFO",
    "title": (
        "vsftpd-3.0.5-6.tl4: tcp_wrappers support removed (patch 0047); "
        "/etc/hosts.allow and /etc/hosts.deny have NO EFFECT on vsftpd FTP access; "
        "operators who relied on this for pre-auth IP filtering are unprotected"
    ),
    "description": (
        "Patch 0047 removes VSF_BUILD_TCPWRAPPERS from builddefs.h and -lwrap from "
        "Makefile. The vsftpd binary does NOT call libwrap. "
        "\n"
        "tcp_wrappers allowed /etc/hosts.allow and /etc/hosts.deny entries to "
        "restrict vsftpd connections before authentication. Removing it means: "
        "  - vsftpd accepts TCP connections from all IPs regardless of hosts.{allow,deny} "
        "  - Any pre-auth filtering must now be done at the firewall (iptables/nftables) "
        "\n"
        "This matches the RHEL 8+ behavior (libwrap also deprecated there). "
        "Operators migrating from TOS 3.x or RHEL 7 who had hosts.deny FTP rules "
        "are exposed if they haven't added equivalent firewall rules. "
        "\n"
        "Confirmed from Makefile in patch 0047: "
        "  Before: LIBS = -lwrap -lnsl -lpam -lcap -ldl -lcrypto "
        "  After:  LIBS = -lnsl -lpam -lcap -ldl -lcrypto "
        "(Note: 0050 also removes -lnsl)"
    ),
    "patch_evidence": {
        "patch_file": "0047-Disable-tcp_wrappers-support.patch",
        "change": "Remove -lwrap link, remove VSF_BUILD_TCPWRAPPERS define",
    },
    "recommendation": (
        "Enforce IP-based FTP restrictions at the firewall layer using "
        "iptables/nftables rules. Do not rely on /etc/hosts.allow."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F08: 3DES in original cipher list removed by 0040
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_3DES_CIPHER = {
    "finding_id": "TOS46-FTP-F08",
    "severity": "INFO",
    "title": (
        "vsftpd upstream cipher list included DES-CBC3-SHA (3DES); "
        "patch 0040 replaces hard-coded cipher list with PROFILE=SYSTEM, "
        "delegating to system-wide crypto policy (SWEET32 mitigated)"
    ),
    "description": (
        "Upstream vsftpd 3.0.5 ssl_ciphers default: "
        "  'AES128-SHA:DES-CBC3-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA' "
        "\n"
        "DES-CBC3-SHA (3DES) is vulnerable to SWEET32 (CVE-2016-2183): "
        "birthday attack after 2^32 (~32GB) blocks on a 64-bit block cipher. "
        "A long-lived FTPS session (large file transfer) could expose data. "
        "\n"
        "Patch 0040 changes ssl_ciphers default to 'PROFILE=SYSTEM', which "
        "reads from /etc/crypto-policies. TOS 4.6 ships with the DEFAULT crypto "
        "policy, which excludes 3DES. "
        "\n"
        "Impact: without patch 0040, an unpatched vsftpd 3.0.5 would offer "
        "3DES cipher suites. TOS 4.6 is patched and does NOT offer 3DES. "
        "\n"
        "DHE/ECDHE support added by patches 0021/0022 ensures forward secrecy "
        "is available when ssl_enable=YES is configured."
    ),
    "patch_evidence": {
        "patch_file": "0040-Use-system-wide-crypto-policy.patch",
        "original_ciphers": "AES128-SHA:DES-CBC3-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA",
        "new_ciphers": "PROFILE=SYSTEM",
    },
    "status": "MITIGATED in TOS 4.6 by patch 0040",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F09: chroot_local_user breakout (unchanged from prior module)
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_CHROOT_BREAKOUT = {
    "finding_id": "TOS46-FTP-F09",
    "severity": "MEDIUM",
    "cvss_v3": 5.1,
    "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "title": (
        "vsftpd chroot_local_user=YES: chroot breakout if homedir is writable "
        "and allow_writeable_chroot=YES is set; classic vsftpd issue"
    ),
    "description": (
        "When chroot_local_user=YES: vsftpd calls chroot($HOME) then chdir('/'). "
        "If the chroot directory (home) is writable by the user AND "
        "allow_writeable_chroot=YES is set (to suppress vsftpd's own warning), "
        "the chroot can be escaped via: "
        "  - Hard-link attacks on some filesystems "
        "  - /proc-based path traversal if /proc bind-mounted into chroot "
        "  - Kernel chroot escape via open-fd tricks on old kernels "
        "\n"
        "Patch 0053 (chdir after chroot) adds chdir('/') after chroot() — this "
        "is already correct vsftpd behavior; 0053 ensures it's consistent. "
        "\n"
        "Default TOS 4.6: chroot_local_user NOT set — not vulnerable by default."
    ),
    "default_config_status": "NOT ENABLED — requires operator opt-in for both "
                             "chroot_local_user=YES and allow_writeable_chroot=YES",
}

# ──────────────────────────────────────────────────────────────────────────────
# FULL PATCH CLASSIFICATION TABLE
# ──────────────────────────────────────────────────────────────────────────────

PATCH_CLASSIFICATION = {
    "security_fixes": [
        {
            "patch": "0034-Turn-off-seccomp-sandbox",
            "change": "seccomp DEFAULT changed from ON to OFF",
            "impact": "MEDIUM — removes syscall filter from worker process",
            "finding": "TOS46-FTP-F01",
        },
        {
            "patch": "0029-Fix-segfault-in-config-file-parser",
            "change": "negative newlen cast to uint before strndup → heap corruption on whitespace-only line",
            "impact": "LOW — DoS on config reload (requires root write to vsftpd.conf)",
            "finding": "TOS46-FTP-F02",
        },
        {
            "patch": "0007-Make-filename-filters-smarter",
            "change": "deny_file bypass via relative paths (./ prefix) fixed in ls.c",
            "impact": "MEDIUM — auth bypass of deny_file ACL",
            "finding": "TOS46-FTP-F03",
        },
        {
            "patch": "0055-vsf_sysutil_get_tz-Check-return-value",
            "change": "size_t→ssize_t for read() return; OOB stack read on /etc/localtime error",
            "impact": "LOW — stack info disclosure if localtime read fails",
            "finding": "TOS46-FTP-F04",
        },
        {
            "patch": "0059-Fix-SEGFAULT-when-running-as-PID-1",
            "change": "NULL check for p_ip in SIGCHLD handler; crash when running as container PID 1",
            "impact": "LOW — pre-auth DoS in container deployments",
            "finding": "TOS46-FTP-F05",
        },
        {
            "patch": "0011-Fix-listing-with-more-than-one-star",
            "change": "glob regression: *.txt*.log style patterns broken → incorrect directory listing",
            "impact": "LOW — information disclosure through glob logic mismatch",
            "finding": None,
        },
        {
            "patch": "0031-Fix-question-mark-wildcard",
            "change": "? wildcard worked only at end of name; now works anywhere in filter",
            "impact": "LOW — filename filter logic fix",
            "finding": None,
        },
        {
            "patch": "0026-Prevent-hanging-in-SIGCHLD-handler",
            "change": "wait() → waitpid(-1, WNOHANG); prevents hang when pam_exec.so creates child processes",
            "impact": "LOW — service hang prevention",
            "finding": None,
        },
    ],
    "hardening": [
        {
            "patch": "0040-Use-system-wide-crypto-policy",
            "change": "ssl_ciphers default 'AES128-SHA:DES-CBC3-SHA:...' → 'PROFILE=SYSTEM'",
            "impact": "POSITIVE — removes 3DES from default FTPS cipher list",
        },
        {
            "patch": "0047-Disable-tcp_wrappers-support",
            "change": "Remove libwrap; LDFLAGS confirm FULL RELRO (-Wl,-z,relro -Wl,-z,now)",
            "impact": "NEUTRAL/NEGATIVE — RELRO confirmed; tcp_wrappers ACL layer removed",
        },
        {
            "patch": "0053-Always-do-chdir-after-chroot",
            "change": "chdir('/') added after chroot() in vsf_sysutil_chroot()",
            "impact": "POSITIVE — ensures working directory is inside chroot",
        },
        {
            "patch": "0054-Check-setsockopt-return",
            "change": "setsockopt SO_RCVTIMEO: die() on failure instead of ignoring error",
            "impact": "POSITIVE — prevents silently broken timeout on data socket",
        },
        {
            "patch": "fix-str_open.patch",
            "change": "str_open() simplified; removed code path that could call bug() on re-open",
            "impact": "POSITIVE — defensive cleanup",
        },
    ],
    "features": [
        {
            "patch": "0015-Listen-on-IPv6-by-default",
            "change": "Default config: listen=NO, listen_ipv6=YES (IPv6 :: accepts both IPv4/IPv6)",
            "impact": "Default changed from IPv4-only to dual-stack",
        },
        {
            "patch": "0016-Increase-VSFTP_AS_LIMIT",
            "change": "VSFTP_AS_LIMIT 200MB → 400MB (address space limit for vsftpd worker)",
            "impact": "Allows LDAP/PAM modules that need more memory",
        },
        {
            "patch": "0019-reverse_lookup_enable",
            "change": "New option reverse_lookup_enable=YES/NO to control gethostbyaddr before PAM",
            "impact": "Resolves performance issues; DNS resolution before auth is now configurable",
        },
        {
            "patch": "0021-DHE-cipher-suites",
            "change": "dh_param_file config option; ssl.c adds DH callback for PFS",
            "impact": "Forward secrecy available for FTPS",
        },
        {
            "patch": "0022-ECDHE-cipher-suites",
            "change": "ecdh_param_file config option; SSL_OP_SINGLE_ECDH_USE added",
            "impact": "Elliptic curve PFS for FTPS",
        },
        {
            "patch": "0024-Return-value-450",
            "change": "FTP 450 'Temporarily failed to open file' on EAGAIN instead of 550",
            "impact": "Proper handling of temporarily locked/busy files",
        },
        {
            "patch": "0025-Improve-local_max_rate",
            "change": "bw_rate: unsigned int → unsigned long; cumulative rather than per-chunk",
            "impact": "Bandwidth limiting now works correctly for large files",
        },
        {
            "patch": "0027-Delete-files-on-upload-failure",
            "change": "tunable_delete_failed_uploads; cleans up incomplete uploads",
            "impact": "Prevents partial file accumulation on disk",
        },
        {
            "patch": "0032-NFS-quota-error-propagation",
            "change": "FTP 552 DISKQUOTA for EDQUOT; checks close() for NFS quota errors",
            "impact": "Proper quota enforcement over NFS",
        },
        {
            "patch": "0049-Better-STOU-filename-generation",
            "change": "better_stou=YES option; glibc __gen_tempname()-based 62^6 alphanumeric suffix",
            "impact": "More entropy in STOU filenames, harder to predict upload file names",
        },
        {
            "patch": "vsftpd-3.0.5-enable_wc_logs-replace_unprintable_with_hex.patch",
            "change": "wc_logs_enable option; wide-char log sanitization; hex escaping of non-printable bytes",
            "impact": "Prevents log injection via crafted filenames with control characters",
        },
        {
            "patch": "0056-Log-die-calls-to-syslog",
            "change": "vsf_log_die() sends die()/die2()/bug() messages to syslog before exit",
            "impact": "Crash messages now visible in systemd journal",
        },
        {
            "patch": "0036-Redefine-VSFTP_COMMAND_FD-to-1",
            "change": "VSFTP_COMMAND_FD 0 (stdin) → 1 (stdout); startup errors reach systemd",
            "impact": "Error messages on startup are captured by journald",
        },
        {
            "patch": "0058-bind-retries-tunable",
            "change": "bind_retries config option; PASV bind retry count now configurable",
            "impact": "Tuning for environments with slow port release",
        },
        {
            "patch": "0014-Square-brackets-in-ls",
            "change": "ls.c: [abc] character class patterns in deny_file/anon_root globs",
            "impact": "Richer glob patterns for file filtering",
        },
    ],
    "documentation_only": [
        "0013", "0017", "0018", "0023", "0028", "0030", "0037", "0038",
        "0039", "0041", "0045", "0046", "0048", "0051", "0057",
    ],
    "build_system": [
        "0001-Don-t-use-provided-script-to-locate-libraries",
        "0002-Enable-build-with-SSL",
        "0003-Enable-build-with-TCP-Wrapper",
        "0004-Use-etc-vsftpd-dir-for-config",
        "0010-Improve-daemonizing",
        "0012-Replace-__NR_clone-with-clone",
        "0020-unsigned-int-uid-gid",
        "0035-DH-patch-OpenSSL-1.1-compat",
        "0044-Disable-anonymous-in-default-config",
        "0050-Don-t-link-with-libnsl",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAINS
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS = [
    {
        "chain_id": "TOS46-FTP-CHAIN-01",
        "title": "Unauthenticated pre-auth DoS via container PID 1 SIGCHLD race",
        "severity": "LOW",
        "steps": [
            "1. vsftpd deployed as container PID 1 (Docker/Podman without init)",
            "2. Attacker floods TCP port 21 with rapid connect-RST sequences",
            "3. SIGCHLD delivered for rejected connections before client struct init",
            "4. handle_sigchld() calls drop_ip_count(NULL) → NULL deref → SIGSEGV",
            "5. vsftpd process dies → FTP service unavailable",
        ],
        "prerequisites": ["vsftpd running as container PID 1"],
        "mitigated_by": "patch 0059 (NULL check); tini/dumb-init as container PID 1",
    },
    {
        "chain_id": "TOS46-FTP-CHAIN-02",
        "title": "Authenticated local user → arbitrary file write via write_enable=YES",
        "severity": "HIGH",
        "steps": [
            "1. Attacker has any local user account with valid shell",
            "2. FTP authenticate: local_enable=YES passes pam_shells.so + pam_unix.so",
            "3. write_enable=YES allows STOR to any directory user can write",
            "4. If user can write to web root: upload webshell → RCE",
            "5. If user can write ~/.ssh: add authorized_keys → persistent access",
            "6. If user in writable cron path: add cron job → code execution",
        ],
        "prerequisites": ["local user account", "write_enable=YES (default)", "no chroot"],
        "mitigated_by": "chroot_local_user=YES (not default), deny_file restrictions",
    },
    {
        "chain_id": "TOS46-FTP-CHAIN-03",
        "title": "Worker process memory corruption → no seccomp to bypass",
        "severity": "CRITICAL (if vsftpd CVE found)",
        "steps": [
            "1. Future CVE in vsftpd data channel / TLS handler causes heap overflow",
            "2. seccomp is OFF (patch 0034) — no syscall filter to bypass",
            "3. FULL RELRO prevents .got.plt overwrites but ROP chains viable",
            "4. PIE + ASLR still active — requires info leak or ASLR spray",
            "5. NO_NEW_PRIVS blocks SUID escalation post-exploitation",
            "6. If successful: code exec as ftp/nobody user → lateral movement",
        ],
        "prerequisites": ["hypothetical vsftpd memory corruption CVE"],
        "mitigated_by": "PIE+ASLR, FULL RELRO, stack canary, FORTIFY_SOURCE=2, NO_NEW_PRIVS",
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-FTP-F01": VSFTPD_SECCOMP_DISABLED,
    "TOS46-FTP-F02": VSFTPD_CONFIG_HEAP_OVERFLOW,
    "TOS46-FTP-F03": VSFTPD_DENY_FILE_BYPASS,
    "TOS46-FTP-F04": VSFTPD_TZ_STACK_READ,
    "TOS46-FTP-F05": VSFTPD_PID1_SIGCHLD_NULLDEREF,
    "TOS46-FTP-F06": VSFTPD_WRITE_ENABLE_DEFAULT,
    "TOS46-FTP-F07": VSFTPD_TCPWRAPPERS_REMOVED,
    "TOS46-FTP-F08": VSFTPD_3DES_CIPHER,
    "TOS46-FTP-F09": VSFTPD_CHROOT_BREAKOUT,
}


def get_findings():
    return FINDINGS


def get_attack_chains():
    return ATTACK_CHAINS


if __name__ == "__main__":
    import json
    summary = {
        "binary": "vsftpd-3.0.5-6.tl4",
        "patches_audited": 66,
        "seccomp_enabled": False,
        "tcp_wrappers": False,
        "full_relro": True,
        "default_listen": "IPv6 (dual-stack)",
        "findings": [
            {
                "id": k,
                "severity": v.get("severity", "?"),
                "cvss": v.get("cvss_v3"),
                "title": v["title"][:80] + "..." if len(v["title"]) > 80 else v["title"],
            }
            for k, v in FINDINGS.items()
        ],
        "attack_chains": [c["chain_id"] for c in ATTACK_CHAINS],
    }
    print(json.dumps(summary, indent=2))
