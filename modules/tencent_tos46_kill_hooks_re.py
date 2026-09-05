"""
TencentOS 4.6 — kill_protect.ko + kill_block.ko kernel module RE.

kill_protect.ko: "Protect some processes from being killed" (v1.0)
kill_block.ko:   "kill_block_mod" (v1.3) — cross-cgroup signal blocking

Both modules register with the TOS 4.6 custom kill hook kernel API
(register_kill_hook / unregister_kill_hook) — a kernel extension point
added by Tencent that intercepts signal delivery before it reaches a process.

These form a process protection suite with ttools.ko:
  ttools.ko        — blocks ptrace (ptrace_pre_hook, via kallsyms)
  kill_protect.ko  — blocks kill() on all processes not in a blacklist
  kill_block.ko    — blocks cross-cgroup kill() unless in a whitelist

The kill hook API is exported (not kallsyms-resolved), indicating Tencent
added register_kill_hook / unregister_kill_hook as stable kernel symbols
in their 5.4.241 kernel.
"""

BINARY_INVENTORY = {
    "kill_protect.ko": {
        "path": "/tmp/scratchpad/kill_protect.ko",
        "type": "ELF 64-bit relocatable, x86-64, not stripped",
        "text_size": 0x7aa,
        "version": "1.0",
        "description": "Protect some processes from being killed",
        "license": "GPL v2",
        "author": "Yongliang Gao <leonylgao@tencent.com>",
        "proc_entries": [
            "/proc/kill_protect/blacklist",
            "/proc/kill_protect/stat",
        ],
        "sysctl_table": True,
    },
    "kill_block.ko": {
        "path": "/tmp/scratchpad/kill_block.ko",
        "type": "ELF 64-bit relocatable, x86-64, not stripped",
        "text_size": 0xa9e,
        "version": "1.3",
        "description": "kill_block_mod",
        "license": "(not in strings — GPL assumed)",
        "author": "herberthbli (Tencent internal)",
        "proc_entries": [
            "/proc/kill_block/whitelist",
            "/proc/kill_block/stat",
        ],
        "sysctl_table": True,
        "kubernetes_aware": True,
    },
}

KERNEL_HOOK_API = {
    "exported_symbols": ["register_kill_hook", "unregister_kill_hook"],
    "note": (
        "register_kill_hook and unregister_kill_hook are EXPORTED kernel symbols — "
        "unlike ptrace_pre_hook in ttools.ko which is resolved via kallsyms_lookup_name. "
        "This means Tencent added kill interception as a stable ABI in TOS 4.6's kernel. "
        "The hook fires on every kill(2), tgkill(2), tkill(2), and signal delivery "
        "before the standard permission check (or after it, depending on hook placement). "
        "Hook signature: likely int (*hook)(struct task_struct *sender, "
        "struct task_struct *target, int sig)."
    ),
    "vs_ttools": (
        "ttools.ko uses kallsyms_lookup_name for ptrace_pre_hook — unstable internal symbol. "
        "kill_protect and kill_block use register_kill_hook — stable exported API. "
        "Difference suggests the kill hooks were designed first (with a proper API), "
        "and ttools.ko was added later using the older ptrace interception pattern."
    ),
}

KILL_PROTECT_ANALYSIS = {
    "mechanism": "blacklist",
    "semantics": (
        "PROTECT ALL except blacklisted. "
        "The 'blacklist' contains process names/patterns that ARE allowed to be killed. "
        "Anything NOT in the blacklist is protected from kill signals. "
        "Hook function (kill_protect_hook_func at 0x780) calls "
        "kill_protect_blacklist_match(0x5c0) to check if the target process is blacklisted. "
        "If NOT blacklisted: deny the kill (return error). "
        "If blacklisted: allow the kill to proceed."
    ),
    "proc_interface": {
        "/proc/kill_protect/blacklist": {
            "ops": "seq_file (read) + write",
            "read": "lists current blacklisted process names",
            "write": (
                "blacklist_write() at 0x180: "
                "reads userspace string via strncpy_from_user, "
                "parses entries with strsep, kmalloc each entry, "
                "inserts into blacklist linked list. "
                "Also handles 'flush' command to clear the blacklist."
            ),
        },
        "/proc/kill_protect/stat": "rule count + protect count (signals blocked)",
    },
    "sysctl": {
        "path": "/proc/sys/kernel/kill_protect (likely)",
        "note": "proc_douintvec_minmax used — unsigned int with min/max bounds; likely an enable/disable toggle",
    },
    "log_format": "4kill_protect: %s/%d send signal %d to %s/%d is not allowed",
    "log_components": "sender_comm/sender_pid, signal_number, target_comm/target_pid",
    "imports_of_note": {
        "strncpy_from_user": "safe userspace string copy (bounded) for blacklist entries",
        "strsep": "tokenizes input on whitespace/newline",
        "strcmp": "exact match comparison for blacklist lookup",
        "seq_list_*": "standard seq_file list iteration for /proc output",
    },
}

KILL_BLOCK_ANALYSIS = {
    "mechanism": "whitelist",
    "semantics": (
        "BLOCK ALL cross-cgroup except whitelisted pairs. "
        "kill_block_hook_func intercepts signals sent across cgroup boundaries. "
        "It gets sender and receiver cgroup paths (kernfs_path_from_node, kernfs_name). "
        "Checks kill_block_whitelist_match: if the src/dst cgroup pair is whitelisted, allow. "
        "If not whitelisted and cgroups differ: block the signal. "
        "Kubernetes-aware: recognizes '*kubepods*' cgroup pattern (glob_match). "
        "Logs blocked signals with full cgroup path + name for both src and dst."
    ),
    "proc_interface": {
        "/proc/kill_block/whitelist": {
            "read": "lists allowed (src_cgroup, dst_cgroup) pairs",
            "write": "add/remove whitelist entries; 'flush' to clear",
        },
        "/proc/kill_block/stat": "stat_proc_show — signal block counts, root/child breakdown",
    },
    "stat_format": "root %lld\nchild %lld\nsrc_comm\tdst_comm\tdst_cgrp",
    "log_format": (
        "6block signal %d from [%d]%s to [%d]%s; "
        "src_cgrp_path %s src_cgrp_name %s -> dst_cgrp_path %s dst_cgrp_name %s"
    ),
    "kubernetes_pattern": {
        "glob": "*kubepods*",
        "note": (
            "kill_block is explicitly Kubernetes-aware: it matches cgroup paths containing "
            "'kubepods' (the standard Kubernetes cgroup hierarchy). "
            "This enables cross-pod signal blocking — by default, processes in one k8s pod "
            "cannot kill processes in another pod even if they are on the same host, "
            "unless the whitelist permits it."
        ),
    },
    "imports_of_note": {
        "glob_match": "kernel glob matching for *kubepods* cgroup pattern",
        "kernfs_name": "get cgroup name from kernfs node",
        "kernfs_path_from_node": "get full cgroup path",
        "cpu_cgrp_subsys": "reference to CPU cgroup subsystem for cgroup lookup",
        "strcasecmp": "case-insensitive comparison (cgroup names)",
        "strstr": "substring search (for *kubepods* detection?)",
    },
}

PROCESS_PROTECTION_SUITE = {
    "modules": {
        "ttools.ko":       "blocks ptrace (anti-debugger, anti-forensics)",
        "kill_protect.ko": "blocks kill() on non-blacklisted processes",
        "kill_block.ko":   "blocks cross-cgroup kill() (Kubernetes isolation)",
    },
    "design_rationale": (
        "Together these modules harden TOS 4.6 containerized workloads: "
        "a privileged Kubernetes pod cannot kill, trace, or debug another pod's processes "
        "on the same node, even if the attacker has container-root. "
        "kill_protect protects critical system daemons from being killed. "
        "kill_block provides cgroup-boundary enforcement for Kubernetes pods. "
        "ttools prevents ptrace-based process inspection across pod boundaries. "
        "The suite is controlled via /proc interfaces, allowing runtime configuration "
        "without module reload."
    ),
    "hook_architecture": (
        "TOS 4.6 kernel exports: ptrace_pre_hook (pointer, resolved via kallsyms in ttools), "
        "register_kill_hook / unregister_kill_hook (exported symbols, used by kill_protect + kill_block). "
        "These are Tencent-specific kernel additions not present in mainline Linux 5.4."
    ),
}

SECURITY_ANALYSIS = {
    "proc_interface_access": (
        "/proc/kill_protect/blacklist and /proc/kill_block/whitelist are writable proc entries. "
        "proc_create() without explicit permissions creates files with default mode 0444 (read) "
        "or 0644 (read/write). The write handler uses strncpy_from_user (safe, bounded). "
        "If these proc files are world-writable: any process can modify the blacklist/whitelist, "
        "bypassing the protection for target processes or unblocking cross-pod signals. "
        "Expected: root-only write (mode 0644 or 0600)."
    ),
    "no_pid_recycling_issue": (
        "kill_protect operates on process names (comm), not PIDs. "
        "No PID recycling race (unlike ttools.ko's PID list). "
        "kill_block operates on cgroup paths, which are managed by the kernel — "
        "cgroup paths don't suffer from recycling issues."
    ),
    "stable_api": (
        "register_kill_hook is an exported symbol — stable across kernel updates (within TOS 4.6). "
        "Unlike ttools.ko, no kallsyms dependency, no hard kernel-version coupling. "
        "Both modules will safely load on any TOS 4.6 kernel that exports register_kill_hook."
    ),
    "bypass_scenario": (
        "To bypass kill_protect on a specific process: "
        "1. Write target process comm to /proc/kill_protect/blacklist "
        "2. Process is now killable "
        "Requires write access to /proc/kill_protect/blacklist. "
        "If proc file is world-writable: any container-root process can bypass protection. "
        "Mitigated if proc file is root-only and LSM (SELinux/AppArmor) is enforcing."
    ),
    "version_delta": {
        "kill_protect_44.ko": "44 = TOS 4.4 variant (different kernel version, same logic)",
        "kill_block_44.ko": "44 = TOS 4.4 variant",
        "note": "Both old and new versions present in scratchpad — indicates TOS version upgrade path",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "kill_protect/kill_block /proc interfaces: write access to blacklist/whitelist bypasses protection",
        "detail": (
            "/proc/kill_protect/blacklist write: adds process name to 'may be killed' list. "
            "/proc/kill_block/whitelist write: adds cgroup pair to 'may send signals' list. "
            "If proc files are world-writable or accessible to container-root: "
            "attacker can unprotect any process or enable cross-pod signal injection. "
            "Severity depends on /proc file permissions — not recoverable from .ko binary alone."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "kill_block: Kubernetes cgroup isolation — cross-pod kill() blocked by default",
        "detail": (
            "kill_block_hook_func enforces cgroup-boundary signal isolation. "
            "Kubernetes pod processes in different kubepods/* cgroups cannot kill each other "
            "unless whitelisted. "
            "Security feature for multi-tenant k8s nodes; note: this is a control-plane protection, "
            "not a container escape barrier. Privilege escalation beyond cgroup boundaries "
            "uses different vectors (kernel exploits, namespace escape)."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "register_kill_hook: Tencent-exported kernel API for signal interception — stable ABI",
        "detail": (
            "Both modules use register_kill_hook (exported symbol) rather than kallsyms. "
            "TOS 4.6 kernel adds signal hook as stable API — unlike ttools.ko's kallsyms approach. "
            "Safe across TOS 4.6 kernel updates; not present in mainline Linux 5.4."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "Process protection suite: ttools + kill_protect + kill_block — defense-in-depth",
        "detail": (
            "ttools.ko blocks ptrace. kill_protect blocks kill(). kill_block blocks cross-cgroup kill(). "
            "Together: privileged processes on TOS 4.6 k8s nodes are hardened against "
            "debugging, termination, and inter-pod signal injection by co-tenant containers."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "kill_protect: name-based matching (no PID recycling race unlike ttools.ko)",
        "detail": (
            "Blacklist/whitelist use process comm strings, not PIDs. "
            "No PID recycling race condition. "
            "Downside: process name spoofing (PR_SET_NAME) by a malicious process could "
            "impersonate a protected process name and gain kill immunity."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 kill_protect.ko + kill_block.ko RE")
    print()
    for name, info in BINARY_INVENTORY.items():
        print(f"  {name}: v{info['version']}, {info['text_size']:04x} bytes .text")
        print(f"    {info['description']}")
    print()
    print("Kernel hook API: register_kill_hook / unregister_kill_hook (exported symbols)")
    print("  (compare: ttools.ko uses kallsyms_lookup_name for ptrace_pre_hook)")
    print()
    print("kill_protect mechanism: PROTECT ALL, blacklist exceptions")
    print("kill_block mechanism: BLOCK cross-cgroup, whitelist exceptions")
    print("kill_block: Kubernetes-aware (glob '*kubepods*', kernfs cgroup path resolution)")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
