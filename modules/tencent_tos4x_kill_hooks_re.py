"""
TencentOS 4.x — kill_protect.ko and kill_block.ko binary RE module.

Two TOS 4.x process protection modules using the TOS-specific kill hook ABI:
  kill_protect v1.0 — protect process blacklist from SIGKILL/SIGTERM
  kill_block   v1.3 — block signals between cgroups with glob-pattern whitelist

Both use `register_kill_hook` / `unregister_kill_hook` — TOS 4.x kernel exports
analogous to `ptrace_pre_hook` in TOS 3.3. This is the TOS 4.x process protection
framework: ttools protected from ptrace; kill_protect + kill_block protect from signals.

Sources (TOS 4.6, kernel 6.6.119-51.3.tl4.x86_64):
  kill_protect.ko (27078B) — Yongliang Gao <leonylgao@tencent.com>
  kill_block.ko   (31014B) — herberthbli
"""

METADATA = {
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "modules": {
        "kill_protect": {
            "size_bytes": 27078,
            "version": "1.0",
            "author": "Yongliang Gao <leonylgao@tencent.com>",
            "description": "Protect some processes from being killed",
            "srcversion": "88B1180AF9FA1E718789A16",
        },
        "kill_block": {
            "size_bytes": 31014,
            "version": "1.3",
            "author": "herberthbli",
            "description": "kill_block_mod",
            "srcversion": "67B4EEF26776F67A4506136",
        },
    },
    "shared_kernel_imports": ["register_kill_hook", "unregister_kill_hook"],
    "hook_origin": "TOS 4.x kernel export — analogous to ptrace_pre_hook in TOS 3.3",
}

KILL_HOOK_ABI = {
    "register_kill_hook": {
        "type": "TOS 4.x kernel export (not upstream Linux)",
        "signature": "int register_kill_hook(struct kill_hook *hook)",
        "analogous_to": "register_trace_signal_deliver / security_task_kill LSM hook",
        "hook_func_args": {
            "arg1_rdi": "int signo — signal number being sent",
            "arg2_rsi": "int signo (second copy, passed to blacklist match)",
            "arg3_rdx": "struct task_struct *target — signal recipient",
        },
        "hook_func_return": "0 = allow signal, non-zero = block signal (EPERM)",
        "note": (
            "TOS 4.x kernel maintains a linked list of registered kill hooks. "
            "Before delivering a signal, the kernel calls each registered hook. "
            "If any hook returns non-zero, the kill is blocked. "
            "This is a custom TOS kernel hook point — absent in upstream 6.6."
        ),
    },
}

KILL_PROTECT_ANALYSIS = {
    "module": "kill_protect",
    "protection_model": "Blacklist: listed processes protected from SIGKILL and SIGTERM",
    "signals_blocked": [9, 15],
    "hook_function": {
        "name": "kill_protect_hook_func",
        "addr": 0x0780,
        "size": 42,
        "logic": [
            "0x785: cmp $0x9, %edi — SIGKILL?",
            "0x788: je 0x796 — yes, check blacklist",
            "0x78c: cmp $0xf, %edi — SIGTERM?",
            "0x78f: je 0x796 — yes, check blacklist",
            "0x791: jmp 0x796 — fall through (other signals: return 0 = allow)",
            "0x796: mov %edi, %esi; mov %rdx, %rdi — set up blacklist_match args",
            "0x79b: call kill_protect_blacklist_match",
            "0x7a0: movzbl %al, %eax",
            "0x7a3: neg %eax — negate result (match=1 → -1=EPERM, no match=0 → allow)",
            "0x7a5: jmp 0x7aa — return",
        ],
        "signals_other_than_9_15": "returned 0 immediately (allowed, no blacklist check)",
    },
    "blacklist_match": {
        "name": "kill_protect_blacklist_match",
        "addr": 0x05c0,
        "args": {
            "rdi": "task_struct* target (process being killed)",
            "rsi": "int signo",
        },
        "fast_path": "if kp_rule_cnt == 0: return 0 immediately (no rules, allow all)",
        "match_algorithm": (
            "1. Acquire blacklist_list read lock (_raw_read_lock). "
            "2. Iterate blacklist_list linked list. "
            "3. For each entry: compare entry against current_task identity (pcpu_hot+0xe48). "
            "4. AND compare entry against target_task identity (task_struct+0xe48). "
            "5. If both match: set r15b=1 (protected), break. "
            "6. Return r15b (1=blocked, 0=allowed)."
        ),
        "task_id_offset": 0xe48,
        "task_id_note": (
            "task_struct+0xe48 is the identity field used for matching in TOS 4.6 (6.6.119 kernel). "
            "In upstream 6.6, pcpu_hot.current_task is the fast path to current task_struct. "
            "Offset 0xe48 within the task_struct at 6.6 kernel is deep into the structure — "
            "likely comm[TASK_COMM_LEN] (process name, at ~0xe48 in a padded TOS task_struct) "
            "or a TOS-specific identifier field."
        ),
        "lock_type": "_raw_read_lock (read-write spinlock, allows concurrent readers)",
    },
    "proc_interface": {
        "path": "/proc/kill_protect/",
        "files": {
            "blacklist": "Seq file — read/write blacklist entries (strncpy_from_user for write)",
            "stat": "proc_create_single_data — statistics",
        },
        "sysctl": "sysctl entry via register_sysctl_sz, uses proc_douintvec_minmax",
    },
    "bss_globals": {
        "blacklist_list": "doubly-linked list of blacklist entries",
        "blacklist_lock": "rwlock for the list",
        "kill_protect_hook": "kill_hook struct registered with kernel",
        "kp_proc_dir": "pointer to /proc/kill_protect/",
        "kp_protect_cnt": "count of protected processes",
        "kp_rule_cnt": "count of rules (fast-exit gate)",
        "kp_sysctl_header": "sysctl header for cleanup",
    },
}

KILL_BLOCK_ANALYSIS = {
    "module": "kill_block",
    "protection_model": "Whitelist: signals between cgroups allowed only if whitelist matches; else blocked",
    "approach": "Inverse of kill_protect — kill_block blocks by default, whitelist allows",
    "cgroup_aware": True,
    "glob_matching": True,
    "hook_function": {
        "name": "kill_block_hook_func",
        "addr": 0x0a80,
        "note": "Calls kill_block_whitelist_match and part.0 helper",
    },
    "whitelist_match": {
        "name": "kill_block_whitelist_match",
        "addr": 0x0690,
        "args": {
            "rdi_0x10rsp": "source task_struct* (sender)",
            "rsi_0x1crsp": "int signo",
            "rdx_0x8rsp": "source cgroup path (from kernfs_path_from_node)",
            "rcx_0x20rsp": "destination cgroup path",
            "r8": "destination task_struct* (recipient)",
            "r9_rsp": "additional context",
        },
        "fast_path": "if kb_rule_cnt == 0: return 0 immediately (no rules, allow all)",
        "match_algorithm": (
            "1. If rule count == 0: allow immediately. "
            "2. glob_match(src_cgrp_path, src_task_info) — check if src matches rule. "
            "3. glob_match(dst_cgrp_path, dst_task_info) — check if dst matches rule. "
            "4. If either doesn't match: return 0 (allowed). "
            "5. kernfs_path_from_node(src_cgrp_node, NULL) → src path string. "
            "6. kernfs_path_from_node(dst_cgrp_node, NULL) → dst path string. "
            "7. Use strchr to find last '/' in each path. "
            "8. Compare path component lengths (sub %r13d, %r14d / sub %ebx, %eax). "
            "9. If src and dst paths have equal-length components: they're in same cgroup subtree → allow. "
            "10. Otherwise: block (return 1 = EPERM)."
        ),
        "glob_import": "glob_match — kernel glob pattern matching (supports * ? wildcards)",
        "cgroup_resolution": [
            "cpu_cgrp_subsys — access CPU cgroup subsystem",
            "kernfs_name — get cgroup directory name",
            "kernfs_path_from_node — get full cgroup path",
        ],
        "log_on_block": (
            "'block signal %d from [%d]%s to [%d]%s; "
            "src_cgrp_path %s src_cgrp_name %s -> dst_cgrp_path %s dst_cgrp_name %s'"
        ),
    },
    "proc_interface": {
        "path": "/proc/kill_block/",
        "files": {
            "whitelist": "Read/write whitelist rules (strncpy_from_user write path)",
            "stat": "proc_create_single_data statistics",
        },
        "sysctl": "register_sysctl_sz with proc_douintvec_minmax",
        "note": "Same /proc structure pattern as kill_protect",
    },
    "bss_globals": {
        "kill_block_hook": "kill_hook struct",
        "kb_proc_dir": "pointer to /proc/kill_block/",
        "kb_rule_cnt": "rule count (fast-exit gate)",
        "kb_cnt_child": "blocked kill counter — child cgroup",
        "kb_cnt_root": "blocked kill counter — root level",
    },
}

KILL_HOOK_ABI_EVOLUTION = {
    "tos_33": {
        "hook_point": "ptrace_pre_hook",
        "module": "ttools.ko",
        "protects_from": "ptrace (PTRACE_ATTACH, PTRACE_SEIZE)",
        "mechanism": "doubly-linked list of protected PIDs, registered via ioctl",
        "identification": "task_struct+0xb40 (TOS 3.3-specific field)",
    },
    "tos_4x": {
        "hook_point": "register_kill_hook / unregister_kill_hook",
        "modules": ["kill_protect.ko", "kill_block.ko"],
        "protects_from": "kill signals (SIGKILL, SIGTERM)",
        "mechanism": "blacklist/whitelist linked lists + cgroup-aware filtering",
        "identification": "task_struct+0xe48 (TOS 4.6-specific field), cgroup path resolution",
    },
    "pattern": (
        "Each TOS version exports a custom hook point in the kernel for security modules. "
        "TOS 3.3: ptrace_pre_hook (one hook, one module). "
        "TOS 4.x: kill_hook (one hook type, two modules). "
        "Both generations use custom task_struct field offsets for identity — not PIDs. "
        "The hook registration model allows multiple independent modules to hook the same event. "
        "This is TOS's alternative to the LSM (Linux Security Module) framework — "
        "custom hook points instead of using security_ops/security_hook_heads."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "kill_protect blocks SIGKILL from root — any blacklisted process cannot be terminated by any user",
        "detail": (
            "kill_protect_hook_func blocks signals 9 (SIGKILL) and 15 (SIGTERM) for blacklisted processes. "
            "SIGKILL is the kernel's unconditional kill signal — even root cannot normally stop a process "
            "that ignores all signals (D-state, zombie). "
            "kill_protect extends this immunity: if a process is in the blacklist, even "
            "SIGKILL from root (uid=0, CAP_KILL) is blocked by the kill hook. "
            "A process that registers itself in kill_protect's blacklist (via /proc/kill_protect/blacklist) "
            "becomes unkillable via standard signals. "
            "The only way to stop it is: (1) rmmod kill_protect, (2) kernel oops, (3) power cycle. "
            "If a compromised or malicious process gains write access to /proc/kill_protect/blacklist, "
            "it can make itself unkillable."
        ),
        "signals_blocked": [9, 15],
        "bypass": "rmmod kill_protect (requires CAP_SYS_MODULE)",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "register_kill_hook is a TOS-specific kernel export — not in upstream 6.6, no LSM audit trail",
        "detail": (
            "kill_protect and kill_block both import `register_kill_hook` and `unregister_kill_hook`. "
            "These symbols do not exist in upstream Linux 6.6. "
            "They are TOS 4.x additions to the kernel's kill(2) path. "
            "The hook runs before security_task_kill (LSM hook), before capable() checks, "
            "potentially before any audit logging. "
            "A kill blocked by kill_protect generates no audit log entry — "
            "the signal delivery attempt is silently aborted without SELinux/audit records. "
            "Security teams relying on kernel audit to track kill delivery will miss these blocks."
        ),
        "upstream_present": False,
        "hook_runs_before_lsm": True,
        "audit_trail": None,
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "kill_block cgroup path comparison uses length equality — path prefix confusion possible",
        "detail": (
            "kill_block_whitelist_match uses strchr to find the last '/' and computes "
            "the length of the final path component via subtraction (sub %r13d, %r14d). "
            "It then compares lengths: if lengths are equal, the signal is allowed (same subtree). "
            "Path comparison by length is weak: '/cgroup/web' and '/cgroup/app' "
            "have the same component length ('web' == 'app' == 3 chars). "
            "A kill FROM any cgroup with a 3-char name TO any cgroup with a 3-char name "
            "would be allowed if the lengths match, regardless of whether they're "
            "actually the same cgroup. "
            "This is a logic flaw: length equality ≠ path equality."
        ),
        "comparison_type": "length equality of last path component",
        "correct_comparison_would_be": "strncmp(last_component_src, last_component_dst, len)",
        "evasion": "Attacker cgroup name with same length as target cgroup name",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "kill_protect /proc/kill_protect/blacklist writable — unprivileged write access adds protection",
        "detail": (
            "proc_create('blacklist', ...) is called without explicit mode in the first call, "
            "defaulting to world-readable or owner-readable. "
            "The write handler (`blacklist_write`) accepts process names via strncpy_from_user. "
            "If the proc file is writable by non-root (mode 0666 or similar), "
            "any process can add its own name to the kill_protect blacklist, "
            "making itself unkillable by SIGKILL. "
            "Mode not confirmed from binary — requires runtime check of /proc/kill_protect/blacklist permissions."
        ),
        "risk": "Self-protection: process adds itself to blacklist → SIGKILL blocked",
        "requires_confirmation": "Verify proc file permissions at runtime",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "task identity at task_struct+0xe48 — TOS 4.6-specific field, breaks on upstream or kernel update",
        "detail": (
            "Both kill_protect_blacklist_match and kill_block read task_struct+0xe48 "
            "as the process identity for matching. "
            "task_struct+0xe48 is not a standard upstream Linux 6.6 field at that offset. "
            "In TOS 4.6 (6.6.119 with CONFIG options and padding), this offset likely maps "
            "to task_struct->comm (process name, 16 bytes at ~0xe40-0xe50) in the padded TOS struct. "
            "If TencentOS updates the kernel and task_struct padding shifts, "
            "both modules read the wrong identity field — matching fails, protection breaks silently. "
            "No static assertion or compile-time check is visible for this offset."
        ),
        "offset": 0xe48,
        "likely_field": "task_struct->comm (process name string) at TOS 4.6 padded offset",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "kill_block uses ratelimited printk on block — log flooding possible by repeated kill attempts",
        "detail": (
            "kill_block_hook_func calls ___ratelimit + _printk to log blocked kills. "
            "The log format includes src/dst cgroup paths and names. "
            "A process sending rapid kill signals to a protected target generates a ratelimited "
            "log stream. The ratelimit mechanism controls the printk frequency, "
            "but each blocked kill still runs the full cgroup path resolution "
            "(kernfs_path_from_node on both src and dst). "
            "At high signal rates, this is a kernel-side performance impact in the kill path."
        ),
        "ratelimit": True,
        "path_resolution_per_blocked_kill": True,
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "TOS 3.3 → 4.x protection model evolution: ptrace (ttools) → kill signals (kill_protect+kill_block)",
        "detail": (
            "TOS 3.3: ttools.ko protects from PTRACE_ATTACH via ptrace_pre_hook. "
            "TOS 4.x: ttools removed; kill_protect+kill_block protect from SIGKILL/SIGTERM via kill hook. "
            "TOS 4.x also adds Yama LSM for ptrace protection (CONFIG_SECURITY_YAMA=y). "
            "The signal hook architecture mirrors the ptrace hook architecture: "
            "same pattern (custom kernel export, linked list of handlers, "
            "per-process identity check, early exit with EPERM). "
            "Tencent's security module design is consistent across kernel generations."
        ),
        "architecture_pattern": "Custom kernel hook points → per-process security modules",
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "kill_block supports glob patterns via glob_match — flexible cgroup matching",
        "detail": (
            "kill_block imports `glob_match` (kernel function, include/linux/glob.h). "
            "glob_match supports * (any chars), ? (any single char), [...] character classes. "
            "Whitelist rules can specify cgroup patterns: '/kubepods/*/web-*' "
            "to allow kills from any pod to web service containers. "
            "This makes kill_block suitable for Kubernetes pod-level signal isolation. "
            "The CPU cgroup subsystem is used for cgroup resolution, suggesting "
            "kill_block was designed for CPU cgroup hierarchy in Kubernetes."
        ),
        "glob_import": "glob_match (kernel built-in pattern matching)",
        "cgroup_subsystem": "cpu (cpu_cgrp_subsys)",
    },
]

if __name__ == '__main__':
    print("kill_protect + kill_block (TOS 4.6) RE analysis")
    print()
    print("Kill hook ABI evolution:")
    for ver, info in KILL_HOOK_ABI_EVOLUTION.items():
        if ver == "pattern":
            continue
        print(f"  {ver}: {info['hook_point']} ({info['modules'] if isinstance(info.get('modules'), list) else info.get('module', '?')})")
    print()
    print("kill_protect signals blocked:", KILL_PROTECT_ANALYSIS["signals_blocked"])
    print("kill_block model:", KILL_BLOCK_ANALYSIS["protection_model"])
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
