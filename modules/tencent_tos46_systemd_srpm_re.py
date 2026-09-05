"""
TencentOS Server 4.6 systemd RE Module
Source: systemd-255-20.tl4 SRPM
        /media/cowboy/research/tencentos/4.6/BaseOS-source/
Patch count: 1,188 (extremely heavy patching vs upstream ~300-400)
Analysis date: 2026-09-04

PACKAGE: systemd-255-20.tl4
  Upstream: systemd 255
  Tencent release: 20 (very high — active backport stream)
  Patches: 1,188 (vs typical distro: 300-600 for a mature systemd fork)

CVE PATCHES:
  CVE-2025-4598  coredump: grant_user_access() missing dumpable==1 check
  CVE-2023-7008  resolved: DNSSEC SOA auth check on wrong transaction object

SECURITY FINDINGS: TOS46-SD-F01 through TOS46-SD-F12
  F01 MEDIUM  CVE-2025-4598  coredump dumpable gate bypass
  F02 HIGH    CVE-2023-7008  DNSSEC authenticated flag wrong tx pointer
  F03 HIGH               machined Rename() D-Bus UAF (image_cache hashmap)
  F04 HIGH               journal-remote alloca+MHD_RESPMEM_PERSISTENT UAF
  F05 HIGH               sd-radv stack buffer undersize (iov pref64/HA missing)
  F06 MEDIUM             tc qdisc/tclass mutual-recursion stack overflow
  F07 LOW                sigbus_pop off-by-one overflow detection
  F08 MEDIUM             seccomp_suppress_sync() negative FD bypass
  F09 MEDIUM             nspawn CAP_NET_BIND_SERVICE check-before-settings
  F10 LOW                PrivateDev /dev mount RO-too-soon (bind mounts fail)
  F11 INFO               @sandbox syscall set added to @default (hardening)
  F12 LOW                exec_fd double-close on execution failure path

ATTACK CHAINS:
  CHAIN-1: pre-auth journal-remote HTTP → UAF → potential RCE
  CHAIN-2: DNSSEC bypass → DNS poison → service redirection
  CHAIN-3: coredump + setuid process → dumpable info leak
  CHAIN-4: IPv6 RA flood → sd-radv iov OOB → networkd crash/corruption
"""

# ──────────────────────────────────────────────────────────────────────────────
# PACKAGE INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_PACKAGE = {
    "name": "systemd",
    "version": "255",
    "release": "20.tl4",
    "upstream_version": "255",
    "tencent_release": 20,
    "patch_count": 1188,
    "cve_patches": ["CVE-2025-4598", "CVE-2023-7008"],
    "source_srpm": "systemd-255-20.tl4.src.rpm",
    "key_components": [
        "systemd-coredump",
        "systemd-resolved",
        "systemd-nspawn",
        "systemd-networkd",
        "sd-radv",
        "journal-remote",
        "machined",
        "sd-exec (exec-invoke.c)",
    ],
    "notes": (
        "1,188 patches is extremely high for systemd. Upstream v255 carries ~250-300 "
        "in RHEL/Fedora forks; Tencent's 20-point release number indicates sustained "
        "CVE backport + feature patching. This is a continuously-maintained fork, "
        "not a one-time vendor delta."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# F01 — CVE-2025-4598: coredump grant_user_access() dumpable bypass
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_CVE_2025_4598 = {
    "finding_id": "TOS46-SD-F01",
    "cve": "CVE-2025-4598",
    "severity": "MEDIUM",
    "cvss_v3": 4.7,
    "cvss_vector": "AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "component": "systemd-coredump",
    "patch_file": "CVE-2025-4598.patch",
    "title": (
        "systemd-coredump grant_user_access(): missing dumpable==1 gate allows "
        "non-dumpable (setuid/privilege-elevated) process core files to be "
        "world-accessible if uid==euid and gid==egid and at_secure==0"
    ),
    "description": (
        "grant_user_access() in coredump.c decides whether a core dump file is "
        "made accessible to the crashing user. Pre-patch check: "
        "  ret = at_secure==0 && uid==euid && gid==egid\n"
        "\n"
        "When a setuid-root or capability-raised binary crashes, PR_SET_DUMPABLE "
        "is set to 0 (non-dumpable) or 2 (suid_dumpable=2). The kernel passes "
        "this as the %%d field in core_pattern. Pre-patch, core_pattern did NOT "
        "include %%d, so systemd-coredump never received it, and grant_user_access() "
        "had no awareness of the process's dumpable state. "
        "\n"
        "Result: a privileged process (CAP_NET_ADMIN, CAP_DAC_OVERRIDE, etc.) "
        "running as a regular UID (uid==euid) could dump core files that were "
        "made world-accessible, leaking memory contents (heap, stack, mapped "
        "credentials, secrets) to the owning user. "
        "\n"
        "Fix (two-part): "
        "  1. kernel.core_pattern: add %%d to pass dumpable value as argv "
        "  2. grant_user_access(): add context->dumpable == 1 && condition "
        "     (only dumpable==1 grants access; 0=not dumpable, 2=suid_dumpable) "
        "\n"
        "Affected configurations: "
        "  - TOS 4.6 sets fs.suid_dumpable=2 (from sysctl.d comment in patch) "
        "  - Any service running as a non-root UID with inherited capabilities "
        "  - dumpable=0 processes: their cores stay inaccessible regardless "
        "  - dumpable=2 (suid_dumpable): cores written but restricted to root+adm"
    ),
    "patch_delta": {
        "kernel.core_pattern": "added %d field to capture PR_SET_DUMPABLE value",
        "coredump.c": "grant_user_access() condition: added context->dumpable == 1 &&",
        "META_ARGV_DUMPABLE": "new enum slot; parsed as unsigned; >2 triggers log_notice",
    },
    "references": ["CVE-2025-4598", "PR_SET_DUMPABLE(2const)", "fs.suid_dumpable"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F02 — CVE-2023-7008: systemd-resolved DNSSEC wrong transaction pointer
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_CVE_2023_7008 = {
    "finding_id": "TOS46-SD-F02",
    "cve": "CVE-2023-7008",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "component": "systemd-resolved",
    "patch_file": "fix-CVE-2023-7008.patch",
    "title": (
        "systemd-resolved dns_transaction_requires_rrsig(): DNSSEC authenticated "
        "flag checked against calling transaction t->answer_query_flags instead of "
        "SOA lookup transaction dt->answer_query_flags — allows unauthenticated "
        "negative DNS responses to bypass DNSSEC validation"
    ),
    "description": (
        "dns_transaction_requires_rrsig() determines whether a resource record "
        "requires DNSSEC signature verification. For negative answers (NXDOMAIN, "
        "NODATA), DNSSEC requires a signed SOA record. The code finds the SOA "
        "lookup transaction (dt) and checks whether it was authenticated. "
        "\n"
        "Bug: two separate instances in the function both check "
        "  FLAGS_SET(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED) "
        "where t is the CALLING transaction, not dt (the SOA lookup transaction). "
        "\n"
        "Exploitable scenario: "
        "  1. Attacker performs MITM or DNS cache poisoning "
        "  2. Returns unauthenticated negative answer (NXDOMAIN) for a domain "
        "  3. systemd-resolved looks up the SOA for DNSSEC verification "
        "  4. SOA transaction is authenticated (real signed SOA exists) BUT "
        "     the calling transaction t is NOT flagged authenticated "
        "  5. The bug checks t, which is false → requires_rrsig returns false "
        "  6. The unauthenticated negative answer is ACCEPTED as if DNSSEC-valid "
        "\n"
        "Impact: DNSSEC bypass for negative responses. A domain with DNSSEC "
        "enabled (NXDOMAIN/NODATA responses signed) can be spoofed via MITM. "
        "Any service relying on DNSSEC validation (mail server TLSA, DANE, "
        "nsec-based nonexistence proofs) is bypassed. "
        "\n"
        "Fix: replace t->answer_query_flags with dt->answer_query_flags in both "
        "affected branches of dns_transaction_requires_rrsig(). "
        "\n"
        "Note: DNSSEC is only enforced when systemd-resolved is configured with "
        "DNSSEC=yes or DNSSEC=allow-downgrade. Default on TOS 4.6: "
        "typically DNSSEC=no (requires explicit configuration)."
    ),
    "patch_delta": {
        "resolved-dns-transaction.c": (
            "Two instances: "
            "  - return FLAGS_SET(t->answer_query_flags, ...) "
            "  + return FLAGS_SET(dt->answer_query_flags, ...)"
        ),
    },
    "references": [
        "CVE-2023-7008",
        "https://github.com/systemd/systemd/issues/25676",
        "RFC 4035 DNSSEC negative response authentication",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F03 — machined Rename() D-Bus UAF
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_MACHINED_UAF = {
    "finding_id": "TOS46-SD-F03",
    "severity": "HIGH",
    "cvss_v3": 7.8,
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "component": "machined (systemd-machined)",
    "patch_file": "0656-machine-fix-use-after-free-in-Rename-DBus-method.patch",
    "title": (
        "machined bus_image_method_rename(): image_cache hashmap retains pointer "
        "to Image object after image_rename() frees/reallocates it — UAF via "
        "Rename() D-Bus method triggerable by local user with machinectl access"
    ),
    "description": (
        "bus_image_method_rename() in image-dbus.c: "
        "\n"
        "Pre-patch sequence: "
        "  1. Image object is retrieved from image_cache hashmap (keyed by name) "
        "  2. image_rename(image, new_name) is called "
        "     → internally frees/reallocates image->name "
        "  3. image_cache still holds the pointer under the OLD name key "
        "  4. On failure, image_unref() was NOT called → leak "
        "  5. On success, hashmap still has old_name→image but image->name is new_name "
        "     → the cached object is in an inconsistent state "
        "\n"
        "With the preceding commit (which pre-caches the Image object), this "
        "became triggerable via machinectl rename (not just raw busctl Rename()). "
        "\n"
        "Fix: "
        "  1. hashmap_remove_value(image_cache, image->name, image) before rename "
        "  2. On failure: image_unref(image) + return r "
        "  3. On success: hashmap_put(image_cache, image->name, image) with new name "
        "\n"
        "Attack vector: "
        "  - Requires D-Bus access to org.freedesktop.machine1 "
        "  - On TOS 4.6: regular users in the 'wheel' group or with polkit auth "
        "    can invoke machinectl rename "
        "  - Race condition: call Rename() repeatedly while machinectl clone/list "
        "    is iterating the cache → UAF read in the other method's image_unref "
        "\n"
        "Exploitability: depends on heap layout and concurrent D-Bus method calls. "
        "systemd-machined runs as root; heap corruption in PID 1's companion "
        "process is high impact."
    ),
    "affected_trigger": ["machinectl rename", "busctl call org.freedesktop.machine1 ... Rename"],
    "references": [
        "systemd PR: 1ddb263d + 3b1b2d4e",
        "https://github.com/systemd/systemd/issues/ (Rename UAF)",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F04 — journal-remote alloca + MHD_RESPMEM_PERSISTENT UAF
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_JOURNAL_REMOTE_UAF = {
    "finding_id": "TOS46-SD-F04",
    "severity": "HIGH",
    "cvss_v3": 8.1,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "component": "systemd-journal-remote",
    "patch_file": "0194-journal-remote-use-macro-wrapper-instead-of-alloca-t.patch",
    "title": (
        "journal-remote mhd_respond(): alloca() buffer passed to libmicrohttpd "
        "with MHD_RESPMEM_PERSISTENT — MHD sends the response asynchronously "
        "after the alloca frame pops, resulting in UAF/stack read over HTTP"
    ),
    "description": (
        "mhd_respond() in microhttpd-util.c builds an HTTP response body by "
        "concatenating the message string with a newline via alloca(): "
        "  char *buf = alloca(len + 1); "
        "  memcpy(buf, msg, len); buf[len] = '\\n'; "
        "\n"
        "It then creates the MHD response with: "
        "  MHD_create_response_from_buffer(len+1, buf, MHD_RESPMEM_PERSISTENT) "
        "\n"
        "MHD_RESPMEM_PERSISTENT tells libmicrohttpd: 'this buffer lives forever; "
        "do not copy it.' MHD caches the response object and sends it asynchronously. "
        "But the buffer is on the stack (alloca). After mhd_respond() returns, the "
        "alloca frame is gone. MHD later reads from a dangling stack pointer. "
        "\n"
        "journal-remote is an HTTP receiver for remote journal forwarding. It runs "
        "as a network-facing daemon. An attacker can trigger error responses by "
        "sending malformed journal data — every call to mhd_respond() hits this "
        "UAF path when the response is actually transmitted. "
        "\n"
        "Fix: replace alloca + runtime concatenation with a compile-time macro "
        "that appends '\\n' at build time (string literal concatenation). "
        "No runtime allocation; no MHD ownership issue. "
        "\n"
        "Exploitability: "
        "  - Network-accessible if journal-remote is enabled "
        "  - Default TOS 4.6: journal-remote not started unless explicitly configured "
        "  - When running: any malformed POST to /upload triggers error path "
        "  - The dangling stack is in systemd-journal-remote's HTTP worker thread; "
        "    exploiting to RCE requires controlling what lands on the freed stack "
        "    (possible with thread-specific stack layout)"
    ),
    "service": "systemd-journal-remote.service",
    "default_enabled": False,
    "network_port": 19532,
    "references": [
        "https://github.com/systemd/systemd/issues/9858",
        "commit 320ff932658fb1e3c2aeb1832ff6c10d755e5a56",
        "MHD_RESPMEM_PERSISTENT vs MHD_RESPMEM_MUST_COPY",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F05 — sd-radv iov stack buffer undersize (pref64 + home agent missing)
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_SDRADV_IOV_OVERFLOW = {
    "finding_id": "TOS46-SD-F05",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "component": "sd-radv (systemd-networkd IPv6 Router Advertisement)",
    "patch_file": "0250-sd-radv-fix-potential-buffer-overflow.patch",
    "title": (
        "sd-radv radv_send(): iov[] stack array sized without pref64 prefixes "
        "and home agent option — sending RA with pref64 entries writes beyond "
        "the stack array, corrupting networkd's stack frame"
    ),
    "description": (
        "radv_send() in sd-radv.c declares a VLA (variable-length array) on the stack: "
        "  struct iovec iov[5 + ra->n_prefixes + ra->n_route_prefixes]; "
        "\n"
        "Pre-patch comment describes: 'RA header, linkaddr, MTU, N prefixes, N routes, "
        "RDNSS and DNSSL' — but the code also sends: "
        "  - pref64 prefixes (RA option type 38 — PREF64 for NAT64) "
        "  - home agent option (mobile IPv6) "
        "\n"
        "Both were added in commit 1925f829 + 6a6d27bc (v255) but the iov[] size "
        "was not updated. When networkd is configured with pref64 prefixes "
        "(Pref64Prefix= in networkd .network file), radv_send() fills iov entries "
        "past the end of the array. "
        "\n"
        "Fix: "
        "  struct iovec iov[6 + ra->n_prefixes + ra->n_route_prefixes + ra->n_pref64_prefixes]; "
        "  (6 = RA hdr + linkaddr + MTU + RDNSS + DNSSL + home_agent) "
        "\n"
        "Attack scenario: "
        "  - Attacker can influence RA options if they control a networkd config "
        "    (e.g., container manager with CAP_NET_ADMIN writing .network files) "
        "  - OR: any operator-configured pref64 prefix triggers the OOB on every "
        "    periodic RA send (every MaxRtrAdvInterval seconds, default 600s) "
        "  - networkd runs as a system service; stack corruption → crash or RCE "
        "    depending on what's adjacent on the stack "
        "\n"
        "Note: pref64/NAT64 is a common operator config in dual-stack IPv6 deployments "
        "where Tencent's cloud infrastructure frequently operates."
    ),
    "trigger_config": "Pref64Prefix= option in systemd-networkd .network file",
    "affected_version": "systemd v255 (regression from v255 commit 1925f829)",
    "references": [
        "systemd commit ac63c8df (fix)",
        "systemd commits 1925f829 + 6a6d27bc (introduced the bug)",
        "RFC 8781 — PREF64 Router Advertisement option",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F06 — tc qdisc/tclass mutual-recursion stack overflow
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_TC_STACK_OVERFLOW = {
    "finding_id": "TOS46-SD-F06",
    "severity": "MEDIUM",
    "cvss_v3": 5.5,
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
    "component": "systemd-networkd network/tc",
    "patch_file": "0528-network-tc-fix-stack-overflow-when-dropping-tclass-o.patch",
    "title": (
        "networkd qdisc_drop()/tclass_drop(): mutual recursion without visited "
        "marking causes stack overflow when dropping deeply-nested tc hierarchy; "
        "introduced in v255 by be8e93390003"
    ),
    "description": (
        "qdisc_drop() iterates link->tclasses and calls tclass_drop() for each "
        "tclass whose classid belongs to the qdisc. tclass_drop() in turn iterates "
        "link->qdiscs and calls qdisc_drop() for each child qdisc. "
        "\n"
        "Without a visited marker, this mutual recursion continues until the "
        "kernel stack is exhausted. In a deeply nested HTB/HFSC hierarchy "
        "(e.g., QoS configs with 3+ levels of parent/child qdiscs), networkd "
        "crashes with SIGSEGV on stack overflow. "
        "\n"
        "Fix: mark/unmark pattern — "
        "  qdisc_mark(qdisc) before iterating tclasses; skip tclass_is_marked(); "
        "  tclass_mark(tclass) before iterating qdiscs; skip qdisc_is_marked(); "
        "  unmark after iteration completes "
        "\n"
        "Trigger: any network configuration with hierarchical tc classes "
        "(typical in QoS setups). Crash occurs when networkd processes config "
        "or handles link state change."
    ),
    "trigger_config": "HTB/HFSC qdisc with multiple tclass levels in .network file",
    "references": [
        "systemd commit 632d321050 (fix)",
        "systemd commit be8e93390003 (introduced)",
        "https://github.com/systemd/systemd/issues/32247",
        "https://github.com/systemd/systemd/issues/32254",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F07 — sigbus_pop off-by-one overflow detection
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_SIGBUS_OFFBYONE = {
    "finding_id": "TOS46-SD-F07",
    "severity": "LOW",
    "cvss_v3": 3.3,
    "cvss_vector": "AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L",
    "component": "libsystemd basic/sigbus.c",
    "patch_file": "0118-basic-fix-overflow-detection-in-sigbus_pop.patch",
    "title": (
        "sigbus_pop(): off-by-one in overflow check — c >= SIGBUS_QUEUE_MAX "
        "returns -EOVERFLOW when queue is exactly full (c == SIGBUS_QUEUE_MAX) "
        "but not yet overflowed; should be c > SIGBUS_QUEUE_MAX"
    ),
    "description": (
        "sigbus_pop() in sigbus.c detects queue overflow with: "
        "  if (_unlikely_(c >= SIGBUS_QUEUE_MAX)) return -EOVERFLOW; "
        "\n"
        "When c == SIGBUS_QUEUE_MAX the queue is exactly full but NOT overflowed. "
        "The correct overflow sentinel is c > SIGBUS_QUEUE_MAX (set by sigbus_push() "
        "via the overflow counter logic). Returning -EOVERFLOW prematurely prevents "
        "callers from processing the last valid queue entry. "
        "\n"
        "Impact: under heavy mmap SIGBUS scenarios (e.g., journal file corruption, "
        "cgroup memory pressure causing many simultaneous SIGBUS signals), the last "
        "queue slot is never processed, causing the caller to treat it as an "
        "unrecoverable overflow when it is actually fully recoverable. "
        "\n"
        "Concretely: systemd-journald uses SIGBUS handling for mmap'd journal files; "
        "on a write failure, this off-by-one causes the journal daemon to report "
        "overflow and potentially abandon valid SIGBUS address recovery, leading to "
        "a spurious journal rotation or corruption detection."
    ),
    "references": ["systemd commit b4a9d19e4ec527a7b2d774a1349a6133f7739847"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F08 — seccomp_suppress_sync() negative FD bypass
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_SECCOMP_NEGFD_BYPASS = {
    "finding_id": "TOS46-SD-F08",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
    "component": "libsystemd shared/seccomp-util.c",
    "patch_file": "0876-seccomp-util-pass-negative-fds-as-is-to-fsync-and-fr.patch",
    "title": (
        "seccomp_suppress_sync(): seccomp rule silently returns success (errno=0) "
        "for fsync(-1)/fdatasync(-1) calls instead of EBADF — bypasses the "
        "intended 'fdatasync must fail' contract for sandboxed services"
    ),
    "description": (
        "seccomp_suppress_sync() installs a seccomp filter that intercepts @sync "
        "syscalls and returns 0 (synthetic success) to prevent sandboxed services "
        "from performing disk synchronization. This is used by ProtectSystem= and "
        "related sandboxing directives. "
        "\n"
        "Pre-patch: the seccomp rule matched ALL arguments unconditionally, including "
        "negative file descriptors. POSIX specifies fsync(-1) must return EBADF. "
        "A sandboxed service calling fsync(-1) got errno=0 instead of EBADF, "
        "creating an inconsistency with the service's error-handling expectations. "
        "\n"
        "More critically: some code uses errno==EBADF as a sentinel to detect "
        "whether an FD was already closed. If fsync(-1) succeeds instead, the "
        "service may incorrectly believe the operation succeeded and leave "
        "resources in an inconsistent state. "
        "\n"
        "Fix: conditional seccomp rule for fd-accepting syscalls (fdatasync, fsync, "
        "sync_file_range, sync_file_range2, syncfs): "
        "  SCMP_A0(SCMP_CMP_LE, INT_MAX) — match only non-negative fds "
        "Negative fds fall through to the real syscall and get EBADF from the kernel. "
        "\n"
        "Note: the @sandbox syscall set (seccomp, landlock syscalls) was also "
        "added to @default in patch 0891, separately improving sandbox capability "
        "for all services."
    ),
    "references": [
        "https://github.com/systemd/systemd/issues/34478",
        "systemd commit 144fbbac235b6b89d5d31795be1cc0dca9852ccc",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F09 — nspawn CAP_NET_BIND_SERVICE check-before-settings
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_NSPAWN_CAP_RACE = {
    "finding_id": "TOS46-SD-F09",
    "severity": "MEDIUM",
    "cvss_v3": 4.4,
    "cvss_vector": "AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "component": "systemd-nspawn",
    "patch_file": "0020-nspawn-Check-later-whether-to-keep-drop-CAP_NET_BIND.patch",
    "title": (
        "nspawn parse_argv(): CAP_NET_BIND_SERVICE dropped before loading nspawn "
        "settings file — settings file cannot restore the capability; container "
        "started without bind-privileged-ports capability even when configured"
    ),
    "description": (
        "nspawn drops CAP_NET_BIND_SERVICE during parse_argv() (CLI processing phase) "
        "when: user namespace is active (--private-users) AND network namespace is "
        "NOT isolated (--network-*) AND uid_shift > 0. "
        "\n"
        "The logic is: 'we can't bind ports < 1024 without NET_BIND_SERVICE when "
        "uid-shifted into a user namespace.' But the check happens BEFORE the "
        "settings file (.nspawn file) is loaded. Settings files can legitimately "
        "change the capability mask (Capability=/DropCapability= directives). "
        "\n"
        "Effect: a .nspawn settings file that re-adds CAP_NET_BIND_SERVICE has "
        "no effect — the capability was already cleared from arg_caps_retain before "
        "the file was read. The capability cannot be restored by settings files. "
        "\n"
        "Secondary concern: if an attacker can write a .nspawn settings file "
        "(world-writable /etc/systemd/nspawn/ or user-controlled machine directory), "
        "this creates a capability-state discrepancy — the running container "
        "believes it has bind privileges, but the mask was already cleared. "
        "\n"
        "Fix: move the CAP_NET_BIND_SERVICE capability drop from parse_argv() "
        "into run() — after settings file processing completes, so the final "
        "effective capability set reflects ALL configuration sources."
    ),
    "references": [
        "systemd commit dd78141c530a141f170867b3fc5572b577168759",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F10 — PrivateDev /dev mount read-only too early
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_PRIVATE_DEV_RDONLY_EARLY = {
    "finding_id": "TOS46-SD-F10",
    "severity": "LOW",
    "cvss_v3": 2.3,
    "cvss_vector": "AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N",
    "component": "systemd core/namespace.c",
    "patch_file": "0028-core-do-not-make-private-dev-read-only-too-soon.patch",
    "title": (
        "mount_private_dev(): MS_RDONLY applied to /dev before bind mounts are "
        "added — services using PrivateDevices=yes with BindPaths=/dev/kvm or "
        "similar device bind-mounts fail to mount"
    ),
    "description": (
        "mount_private_dev() sets up a private /dev for services with "
        "PrivateDevices=yes. Pre-patch: "
        "  1. Sets up device tree at temporary_mount "
        "  2. Remounts read-only (MS_REMOUNT|MS_BIND|MS_RDONLY) "
        "  3. Creates /dev directory "
        "  4. Tries to add BindPaths= bind mounts → FAILS because /dev is RO "
        "\n"
        "This breaks services that use PrivateDevices=yes AND need to bind-mount "
        "additional device files (e.g., GPU passthrough, /dev/kvm for VMs, "
        "hardware accelerators). On TOS 4.6, cloud/VM workloads using systemd "
        "services with KVM or GPU acceleration would silently fail to start with "
        "PrivateDevices=yes. "
        "\n"
        "Fix: remove the early MS_RDONLY remount from mount_private_dev(). "
        "The read-only bit is applied AFTER all bind mounts are configured in the "
        "outer namespace setup loop."
    ),
    "references": [
        "https://github.com/systemd/systemd/issues/30372",
        "systemd commit ae7482b994e6a9bc8e033de9accd24b1e1ffe2ed",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F11 — @sandbox added to @default seccomp set (hardening improvement)
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_SECCOMP_SANDBOX_DEFAULT = {
    "finding_id": "TOS46-SD-F11",
    "severity": "INFO",
    "component": "libsystemd shared/seccomp-util.c",
    "patch_file": "0891-seccomp-util-include-sandbox-in-default.patch",
    "title": (
        "seccomp @sandbox syscall set added to @default: seccomp/landlock syscalls "
        "now always permitted in all services without explicit SystemCallFilter=+@sandbox"
    ),
    "description": (
        "@sandbox syscall set includes: seccomp(2), landlock_add_rule(2), "
        "landlock_create_ruleset(2), landlock_restrict_self(2). "
        "\n"
        "Pre-patch: a service using SystemCallFilter=~@default would block these "
        "syscalls, preventing the service from applying its own seccomp/landlock "
        "self-restrictions. "
        "\n"
        "Post-patch: any service can call seccomp()/landlock_*() to self-restrict, "
        "even under the default syscall filter. This enables defense-in-depth: "
        "services can implement their own sandboxing without systemd configuration "
        "changes. "
        "\n"
        "The nspawn-specific seccomp entry in add_syscall_filters() was removed as "
        "redundant — it's now covered by @sandbox in @default. "
        "\n"
        "Security posture improvement: unprivileged services running as non-root "
        "(especially container workloads) can now more aggressively self-restrict "
        "their syscall surface."
    ),
    "references": [
        "systemd commit e9966634754b8c9ee3f3c579f25d938e185c282e",
        "Landlock LSM — linux-doc landlock.rst",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F12 — exec_fd double-close on execution failure
# ──────────────────────────────────────────────────────────────────────────────

SYSTEMD_EXEC_FD_DOUBLE_CLOSE = {
    "finding_id": "TOS46-SD-F12",
    "severity": "LOW",
    "cvss_v3": 3.3,
    "cvss_vector": "AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L",
    "component": "systemd core/exec-invoke.c",
    "patch_files": [
        "0016-core-exec-invoke-prevent-potential-double-close-of-e.patch",
        "0043-executor-don-t-duplicate-FD-array-to-avoid-double-cl.patch",
    ],
    "title": (
        "exec-invoke add_shifted_fd(): exec_fd double-close when FD is rearranged "
        "via close_and_replace() but execution fails — caller and exec_params_shallow_clear() "
        "both close the same FD"
    ),
    "description": (
        "Two related patches address FD lifecycle bugs in exec-invoke.c: "
        "\n"
        "Patch 0016: add_shifted_fd() rearranges exec_fd by calling close_and_replace(). "
        "If exec_fd < 3+n_fds, it duplicates exec_fd to a higher slot and closes "
        "the original. But the CALLER still holds the old FD value. If execution "
        "fails after rearrangement, exec_params_shallow_clear() closes exec_fd "
        "again — double-close. Fix: pass exec_fd as int* so the caller's copy "
        "is updated in-place. "
        "\n"
        "Patch 0043: broader refactor — the FD array was duplicated into a local "
        "copy, creating a scenario where both the FD array and exec_params_shallow_clear() "
        "free the same FDs. Fix: use ExecParameters directly instead of copying, "
        "consolidating ownership. "
        "\n"
        "Double-close impact: "
        "  - The closed FD number may be reused by a concurrent allocation "
        "  - Closing the reused FD corrupts unrelated I/O (e.g., socket FD "
        "    passed to the service, cgroup FD, notification FD) "
        "  - On systemd PID 1 or sd-execute (exec serializer), corruption of "
        "    any service socket or cgroup FD is a local privilege escalation "
        "    vector if FD reuse timing can be controlled"
    ),
    "references": [
        "https://github.com/systemd/systemd/issues/30412",
        "systemd commits 5a5fdfe3 (0016) + 1eeaa93d (0043)",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAINS
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS = {
    "CHAIN-1": {
        "title": "Pre-auth journal-remote HTTP → alloca UAF → potential RCE",
        "severity": "CRITICAL",
        "steps": [
            "1. Confirm journal-remote service is enabled (ss -tlnp port 19532)",
            "2. Send malformed HTTP POST to /upload (malformed Content-Type or missing header)",
            "3. mhd_respond() is called with an error message",
            "4. alloca() allocates the response body on the stack",
            "5. MHD_create_response_from_buffer(..., MHD_RESPMEM_PERSISTENT) caches the alloca pointer",
            "6. mhd_respond() returns; stack frame pops; alloca memory is freed",
            "7. libmicrohttpd sends the response from the dangling pointer",
            "8. Read UAF: attacker receives stack memory contents (info leak)",
            "9. Write primitive: if network timing permits filling the freed stack before read",
            "10. Thread context: journal-remote HTTP worker → root process",
        ],
        "chain_links": ["F04"],
        "prerequisites": "journal-remote enabled (not default); network access to port 19532",
    },
    "CHAIN-2": {
        "title": "DNSSEC bypass → DNS poison → service hostname redirection",
        "severity": "HIGH",
        "steps": [
            "1. Target uses systemd-resolved with DNSSEC=yes or allow-downgrade",
            "2. Attacker is on-path (MITM on LAN/VPN) or controls an upstream resolver",
            "3. Return unsigned NXDOMAIN for a domain that SHOULD be DNSSEC-protected",
            "4. systemd-resolved looks up SOA for zone authentication",
            "5. SOA transaction (dt) is authenticated; calling transaction (t) is not",
            "6. Bug: check uses t->answer_query_flags → returns false (RRSIG not required)",
            "7. Unsigned NXDOMAIN accepted as DNSSEC-valid",
            "8. DNS cache poisoned with attacker-controlled negative answer",
            "9. Services using DNS (mail, TLS, DANE/TLSA) connect to wrong host",
        ],
        "chain_links": ["F02"],
        "prerequisites": "DNSSEC=yes in resolved.conf (not default on TOS 4.6)",
    },
    "CHAIN-3": {
        "title": "setuid binary crash → coredump dumpable bypass → heap/stack info leak",
        "severity": "MEDIUM",
        "steps": [
            "1. Identify a setuid-root binary running as uid==euid (e.g., vulnerability in sudo, polkit)",
            "2. Trigger crash (SIGSEGV, SIGABRT) in the privileged binary",
            "3. systemd-coredump receives: pid, uid, gid, euid, egid, at_secure=0, dumpable field",
            "4. Pre-patch: dumpable field absent from core_pattern → grant_user_access() has no dumpable check",
            "5. uid==euid && gid==egid && at_secure==0 → access GRANTED",
            "6. Core file world-accessible to the running UID",
            "7. Core contains: full heap (secrets, auth tokens), stack frames, mapped files",
            "8. Chained with: any vulnerability causing setuid-root crash (e.g., malloc corruption)",
        ],
        "chain_links": ["F01"],
        "prerequisites": "Pre-patch TOS 4.6 without CVE-2025-4598 fix applied",
    },
    "CHAIN-4": {
        "title": "IPv6 RA pref64 config → sd-radv iov OOB → networkd crash/code exec",
        "severity": "HIGH",
        "steps": [
            "1. Attacker can write networkd .network config (container manager, cloud-init, API)",
            "2. Add Pref64Prefix=64:ff9b::/96 to [IPv6Prefix] section",
            "3. networkd enables sd-radv for RA sending; n_pref64_prefixes becomes 1",
            "4. radv_send() called at periodic RA interval (default every 600s)",
            "5. iov[] VLA sized as [5 + n_prefixes + n_route_prefixes] — pref64 not counted",
            "6. Code writes pref64 iovec entry past end of iov[] array",
            "7. Overwrite adjacent stack variables (msghdr fields, local variables)",
            "8. sendmsg() called with corrupted msghdr → networkd crash or SIGSEGV",
            "9. networkd runs as root; exploitable stack corruption → privesc",
        ],
        "chain_links": ["F05"],
        "prerequisites": "Ability to write networkd .network config with Pref64Prefix=",
    },
    "CHAIN-5": {
        "title": "machined D-Bus UAF → local privilege escalation via machinectl",
        "severity": "HIGH",
        "steps": [
            "1. User with D-Bus access to org.freedesktop.machine1 (wheel group or polkit auth)",
            "2. machinectl clone <image> <clone_name> to create a cached image object",
            "3. machinectl rename <clone_name> <new_name> triggers bus_image_method_rename()",
            "4. image_rename() modifies image->name in-place; image_cache still holds old pointer",
            "5. Concurrent machinectl list iterates image_cache → reads freed/renamed image object",
            "6. UAF read in systemd-machined (root process)",
            "7. Race to heap: trigger many concurrent renames to control heap layout",
            "8. UAF write: overwrite image->ops function pointer → control flow hijack",
        ],
        "chain_links": ["F03"],
        "prerequisites": "D-Bus access to machined; polkit auth or wheel group on TOS 4.6",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# PATCH CLASSIFICATION
# ──────────────────────────────────────────────────────────────────────────────

PATCH_CLASSIFICATION = {
    "total": 1188,
    "cve_fixes": {
        "count": 2,
        "entries": ["CVE-2025-4598", "CVE-2023-7008"],
    },
    "memory_safety_fixes": {
        "count": 7,
        "key_patches": [
            "0656 — machined Rename() UAF (image_cache)",
            "0194 — journal-remote alloca+MHD_RESPMEM_PERSISTENT UAF",
            "0110 — networkd queue double-free on OOM",
            "0016 — exec_fd double-close (add_shifted_fd)",
            "0043 — exec FD array double-close (ownership consolidation)",
            "0118 — sigbus_pop off-by-one overflow detection",
            "0511 — sd-event FD leak when FD owned by IO event source",
        ],
    },
    "overflow_fixes": {
        "count": 3,
        "key_patches": [
            "0250 — sd-radv iov[] stack undersize (pref64 + home agent)",
            "0528 — tc qdisc/tclass mutual recursion stack overflow",
            "0118 — sigbus_pop off-by-one (overflow detection)",
        ],
    },
    "sandbox_hardening": {
        "count": 4,
        "key_patches": [
            "0891 — @sandbox added to @default syscall set",
            "0876 — seccomp negative FD bypass fix",
            "0001 — PR_SET_MEMORY_MERGE prctl missing args fix",
            "0033 — exec-invoke static var cleanup on SELinux failure path",
        ],
    },
    "namespace_isolation": {
        "count": 3,
        "key_patches": [
            "0020 — nspawn CAP_NET_BIND_SERVICE check timing fix",
            "0028 — PrivateDev /dev mount RO-too-soon fix",
            "0069 — cgroup delegated attributes update",
        ],
    },
    "tencent_additions": {
        "note": "1,188 patches vs ~300-400 typical for a systemd v255 fork.",
        "inference": (
            "Heavy Tencent cloud infrastructure integration: "
            "custom cgroup policies, cloud-init compatibility, "
            "container runtime integration (machined), networkd cloud networking "
            "(NAT64/pref64), SMBIOS credential injection for VM provisioning."
        ),
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-SD-F01": SYSTEMD_CVE_2025_4598,
    "TOS46-SD-F02": SYSTEMD_CVE_2023_7008,
    "TOS46-SD-F03": SYSTEMD_MACHINED_UAF,
    "TOS46-SD-F04": SYSTEMD_JOURNAL_REMOTE_UAF,
    "TOS46-SD-F05": SYSTEMD_SDRADV_IOV_OVERFLOW,
    "TOS46-SD-F06": SYSTEMD_TC_STACK_OVERFLOW,
    "TOS46-SD-F07": SYSTEMD_SIGBUS_OFFBYONE,
    "TOS46-SD-F08": SYSTEMD_SECCOMP_NEGFD_BYPASS,
    "TOS46-SD-F09": SYSTEMD_NSPAWN_CAP_RACE,
    "TOS46-SD-F10": SYSTEMD_PRIVATE_DEV_RDONLY_EARLY,
    "TOS46-SD-F11": SYSTEMD_SECCOMP_SANDBOX_DEFAULT,
    "TOS46-SD-F12": SYSTEMD_EXEC_FD_DOUBLE_CLOSE,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "package": "systemd-255-20.tl4",
        "patch_count": 1188,
        "cves": ["CVE-2025-4598", "CVE-2023-7008"],
        "attack_chains": list(ATTACK_CHAINS.keys()),
        "findings": [
            {
                "id": k,
                "severity": v.get("severity", "?"),
                "cvss": v.get("cvss_v3"),
                "cve": v.get("cve"),
                "component": v.get("component", "?"),
            }
            for k, v in FINDINGS.items()
        ],
    }, indent=2))
