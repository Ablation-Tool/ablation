"""
TencentOS/OpenCloudOS /dev/ttools Kernel Driver — RE Module
Source: kernel/tkernel/ttools/ttools_module.c + ttools.h (OpenCloudOS kernel 5.4.119)
        /media/cowboy/research/tencentos-kernel/opencloudos-5.4.119/kernel/tkernel/ttools/
Kernel versions: all TencentOS 2.x, 3.x (5.4.119/5.4.241 TK4 branch)
Analysis date: 2026-09-04

Overview: ttools is a Tencent kernel extension providing three capabilities via /dev/ttools:
  1. TTOOLS_PTRACE_PROTECT  (ioctl 0xEE00) — add calling process to ptrace-immune list
  2. TTOOLS_PTRACE_UNPROTECT (ioctl 0xEE01) — remove calling process from ptrace-immune list
  3. TTOOLS_GET_FD_REFS_CNT (ioctl 0xEE02) — query file descriptor reference count

Device registration: misc device, minor=254, mode=0666 (world-writable, intentional)
  /dev/ttools: crw-rw-rw- misc 10,254

Hook mechanism: sets ptrace_pre_hook = ttools_ptrace_hook (global fn ptr in patched ptrace.c)
  ptrace_pre_hook is a Tencent addition to the stock 5.4.x kernel; absent in upstream Linux.
  When a ptrace(2) call is made, ttools_ptrace_hook() returns -EPERM if target is protected.

Protection model: any process (any UID, any capability set) can protect itself from ptrace
  by any caller — including root, CAP_SYS_PTRACE, debuggers, strace, incident response tools.
  Intended use: protect Tencent agents (tat_agent, sgagent, qcloudd) from user debugging.
  Security impact: malware can self-protect from forensic analysis on affected TencentOS hosts.

Findings: TTLS-F01 through TTLS-F04
"""

IOCTL_MAP = {
    0xEE00: {
        "name": "TTOOLS_PTRACE_PROTECT",
        "direction": "_IO (no data transfer)",
        "action": "ttools_ptrace_protect_task(current->group_leader)",
        "effect": "adds calling process's task_struct* to ttools_protected_pids list",
        "permission_check": None,
    },
    0xEE01: {
        "name": "TTOOLS_PTRACE_UNPROTECT",
        "direction": "_IO (no data transfer)",
        "action": "ttools_ptrace_unprotect_task(current->group_leader)",
        "effect": "removes calling process's task_struct* from ttools_protected_pids list",
        "permission_check": None,
    },
    0xEE02: {
        "name": "TTOOLS_GET_FD_REFS_CNT",
        "direction": "_IOWR (read + write, struct ttools_fd_ref {int fd; long ref_cnt})",
        "action": "ttools_get_fd_refs_cnt(&fd_ref)",
        "effect": "returns f_count or dentry->d_lockref.count for caller's fd",
        "permission_check": None,
    },
}

FINDINGS = {
    "TTLS-F01": {
        "title": (
            "/dev/ttools mode=0666 Exposes TTOOLS_PTRACE_PROTECT to Any Process — "
            "No Permission Check in ttools_dev_ioctl(); "
            "Unprivileged Process or Malware Can Permanently Block Forensic ptrace Analysis"
        ),
        "severity": "HIGH",
        "cvss": "7.0",
        "cwe": "CWE-862",
        "component": (
            "ttools_dev.mode=0666 (ttools_module.c:179); "
            "ttools_dev_ioctl: no CAP_SYS_PTRACE or UID check before TTOOLS_PTRACE_PROTECT"
        ),
        "description": (
            "/dev/ttools is registered with mode=0666, granting read/write access to all users. "
            "ttools_dev_ioctl() has no capability or UID check before any ioctl. "
            "Any process — uid=0 through uid=65534, container process, web application, malware — "
            "can call ioctl(/dev/ttools, TTOOLS_PTRACE_PROTECT=0xEE00) to add itself to the "
            "ttools_protected_pids list. Once protected: "
            "  ptrace_pre_hook (the Tencent-added ptrace hook in ptrace.c) returns -EPERM "
            "  for any ptrace() call targeting the protected process, regardless of the caller's "
            "  privilege level. root with CAP_SYS_PTRACE cannot ptrace a ttools-protected process. "
            "Forensic tools relying on ptrace (strace, gdb, rr, perf, ltrace, ftrace, bpftrace "
            "with uprobe) all fail on protected processes. Incident response on a live host cannot "
            "examine a malicious process that has self-protected. "
            "The OpenCloudOS kernel source confirms this behavior at ttools_module.c:97-102: "
            "  static int ttools_ptrace_hook(long request, long pid, struct task_struct *task, ...) { "
            "    if (ttools_task_ptrace_protected(task->group_leader)) return -EPERM; "
            "    return 0; }"
        ),
        "exploit_sequence": [
            "open('/dev/ttools', O_RDWR)  # succeeds for any uid — mode=0666",
            "ioctl(fd, 0xEE00)            # TTOOLS_PTRACE_PROTECT: no args, no check",
            "# Now ptrace(PTRACE_ATTACH, getpid()) from root returns -EPERM",
            "# strace -p <pid> from root returns 'attach: Operation not permitted'",
            "# Same for GDB, rr, perf record -p, bpftrace uprobe on this process",
        ],
        "chain": (
            "TTLS-F01 + presence of malware on TencentOS host: malware calls "
            "TTOOLS_PTRACE_PROTECT at startup → incident response cannot strace/gdb malware "
            "process → forensic gap; pair with KASLR-disabled (TOSXK-F01) for rootkit that "
            "also cannot be examined post-root."
        ),
        "remediation": (
            "Change mode to 0640 (root:trusted_group) or add CAP_SYS_PTRACE check in ioctl. "
            "Remove ttools entirely if sgagent/tat_agent protection is not required. "
            "Alternative: implement protection via seccomp or LSM hook without 0666 device."
        ),
        "affected_kernels": [
            "5.4.119-19 (TencentOS 2.4, TK4, OpenCloudOS 5.4.119)",
            "5.4.241-24 (TencentOS 3.3, confirmed present per kernel config)",
        ],
        "references": ["CWE-862", "tencent_opencloudos_kernel_re.py TCS-K04"],
    },
    "TTLS-F02": {
        "title": (
            "ttools_protected_pids Stores Raw task_struct* Without get_task_struct() — "
            "Dangling Pointer When Protected Process Exits; "
            "New Process Allocated at Same Address Inherits Ptrace Protection Without Consent"
        ),
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-416",
        "component": (
            "ttools_ptrace_protect_task(): pid_item->task = p_task (no get_task_struct()); "
            "ttools_module.c:54; no task exit callback registered"
        ),
        "description": (
            "ttools_ptrace_protect_task() stores task->group_leader as a raw pointer "
            "without incrementing the task's reference count via get_task_struct(). "
            "When the protected process exits: "
            "(1) The task_struct is released to kernel slab cache after put_task_struct(). "
            "(2) ttools_protected_pids still holds the freed task_struct address. "
            "(3) Kernel may allocate a NEW task_struct at the same slab address for a new process. "
            "(4) ttools_task_ptrace_protected() compares raw pointers: if new task_struct is "
            "    at the same address, the NEW process is incorrectly flagged as protected. "
            "Result: a newly-forked process that never called TTOOLS_PTRACE_PROTECT becomes "
            "immune to ptrace without its knowledge. "
            "Additionally: ttools_clean_task_list() is called on module unload only — not on "
            "process exit. If the module is loaded long-term (it is: auto-loaded at boot), "
            "the protected list accumulates dead task_struct pointers from all processes "
            "that ever called TTOOLS_PTRACE_PROTECT and then exited. "
            "This is a use-after-free: the code dereferences task->group_leader on "
            "ttools_module.c:99 when checking protection status; if the task_struct has been "
            "freed and repurposed, this is an access to freed memory."
        ),
        "uaf_path": (
            "ttools_task_ptrace_protected() → list_for_each_entry() iterates ttools_protected_pids "
            "→ p_item->task compared as raw pointer → if freed task_struct reused at same VA, "
            "comparison succeeds → new process marked protected → forensic anomaly; "
            "If task_struct struct layout changed (unlikely in 5.4.x backport), deref "
            "p_item->task is UB on freed memory"
        ),
        "remediation": (
            "Use get_task_struct() on protect, put_task_struct() on unprotect and on process exit. "
            "Register a task_exit callback (notifier_block on task_exit_notifier) to clean the list. "
            "Alternatively: store PID integers instead of raw task_struct pointers and re-validate "
            "via pid_task() on each check."
        ),
        "references": ["CWE-416", "Linux kernel get_task_struct()/put_task_struct() API"],
    },
    "TTLS-F03": {
        "title": (
            "ptrace_pre_hook Is a Writable Kernel Function Pointer at Fixed VA (KASLR Disabled) — "
            "Kernel Write Primitive Targeting ptrace_pre_hook Redirects All ptrace(2) Calls; "
            "KASLR Disabled on All TencentOS 2.x/3.x Makes VA Predictable"
        ),
        "severity": "CRITICAL",
        "cvss": "8.8",
        "cwe": "CWE-1281",
        "component": (
            "ptrace_pre_hook (global fn ptr, Tencent addition to arch/x86/kernel/ptrace.c); "
            "ttools_module.c:202: ptrace_pre_hook = ttools_ptrace_hook; "
            "on KASLR-disabled kernels: located at deterministic VA (offsetted from 0xffffffff81000000)"
        ),
        "description": (
            "The OpenCloudOS kernel adds ptrace_pre_hook as a global function pointer called "
            "in arch/x86/kernel/ptrace.c (and arch/arm64) before every ptrace() operation. "
            "This hook is intentional (supports ttools protection) but creates a write target: "
            "Any attacker with a kernel write primitive (e.g., kernel buffer overflow, "
            "use-after-free, race condition CVE on 5.4.x) can overwrite ptrace_pre_hook "
            "to point to attacker-controlled code. "
            "On TencentOS 2.x and 3.x where KASLR is DISABLED (see TOSXK-F01): "
            "  - ptrace_pre_hook VA is predictable at boot (fixed offset from 0xffffffff81000000) "
            "  - No info-leak prerequisite required to target this pointer "
            "  - A single 8-byte kernel write achieves ptrace(2) interception for ALL processes "
            "  - The interceptor runs with kernel context: full privilege, no sandboxing "
            "The hook signature: int (*ptrace_pre_hook)(long req, long pid, struct task_struct*, "
            "                                           long addr, long data); "
            "Return value -EPERM blocks ptrace; 0 allows. Overwriting to attacker gadget "
            "achieves kernel RCE on every ptrace call."
        ),
        "exploitation_path": (
            "1. Identify ptrace_pre_hook VA from System.map (public for TencentOS kernels): "
            "   cat /boot/System.map-<kver> | grep ptrace_pre_hook "
            "   (or: fixed offset from _text=0xffffffff81000000 — no runtime lookup needed) "
            "2. Obtain kernel write primitive via any 5.4.x UAF/overflow CVE "
            "3. Write 8 bytes (pointer to shellcode/gadget) to ptrace_pre_hook VA "
            "4. Trigger ptrace() from any process → arbitrary kernel code execution "
            "5. No KASLR bypass needed; no heap spray needed; single write-to-known-VA"
        ),
        "chain": (
            "TTLS-F03 + TOSXK-F01 (KASLR disabled) + TOSXK-F03 (no FORTIFY_SOURCE) + "
            "any 5.4.x kernel CVE: "
            "kernel buffer overflow → ptrace_pre_hook overwrite at known VA → "
            "root process triggers ptrace → kernel RCE → rootkit with ptrace monitoring"
        ),
        "remediation": (
            "Make ptrace_pre_hook const or __read_mostly protected. "
            "Enable KASLR (CONFIG_RANDOMIZE_BASE=y) to remove VA predictability. "
            "Enable FORTIFY_SOURCE and HARDENED_USERCOPY to reduce overflow probability. "
            "Remove ttools entirely if the protection mechanism is not strictly required. "
            "Note: this finding does NOT apply to TencentOS 4.4+ where KASLR is enabled."
        ),
        "affected_kernels": [
            "5.4.119-19 (TencentOS 2.4 + OpenCloudOS 5.4.119) — KASLR disabled",
            "5.4.241-24 (TencentOS 3.3) — KASLR disabled",
            "NOT affected: 6.6.x (TencentOS 4.4+ use stock ptrace without ttools)",
        ],
        "references": ["CWE-1281", "TOSXK-F01 (tencent_kernel_cross_version.py)", "CAPEC-123"],
    },
    "TTLS-F04": {
        "title": (
            "TTOOLS_GET_FD_REFS_CNT Exposes Anonymous Inode Detection to Any Process — "
            "Side-Channel: Caller Can Probe Kernel FD Internals of Own Process; "
            "is_annon_inode() Uses Cached anon_inode_inode* Resolved via kallsyms"
        ),
        "severity": "INFO",
        "cvss": "0",
        "cwe": "CWE-203",
        "component": (
            "ttools_get_fd_refs_cnt(): fdget(p_ref->fd) + f_count/dentry->d_lockref.count; "
            "ttools_init(): kallsyms_lookup_name('anon_inode_inode') → p_anon_inode_inode"
        ),
        "description": (
            "TTOOLS_GET_FD_REFS_CNT (ioctl 0xEE02) allows any process to query the reference "
            "count of its own file descriptors, distinguishing regular file FDs (dentry count) "
            "from anonymous inode FDs (f_count — used for eventfd, epoll, inotify, etc.). "
            "The driver resolves anon_inode_inode via kallsyms at init time — this requires "
            "CONFIG_KALLSYMS=y and means the module succeeds loading only when that symbol "
            "is exported. "
            "The ioctl is scoped to calling process's own FDs only (fdget uses current's table), "
            "so direct cross-process leakage is not present. "
            "The information exposed (f_count and dentry ref counts) could be used to infer "
            "shared memory or dentry reuse patterns in the kernel heap — minor side-channel "
            "with no clear exploitation path in isolation."
        ),
        "remediation": "No immediate action required. Document intended use in ttools design spec.",
        "references": ["CWE-203"],
    },
}

SOURCE_ANALYSIS = {
    "ttools_module.c_critical_lines": {
        "L19":   "TTOOLS_MINOR = 254  (hardcoded misc minor)",
        "L29":   "ttools_protected_pids: static global list (persists for kernel lifetime)",
        "L38-62": "ttools_ptrace_protect_task: kmalloc without get_task_struct — UAF root",
        "L97-102": "ttools_ptrace_hook: returns -EPERM if group_leader in protected list",
        "L141-166": "ttools_dev_ioctl: no permission check before any case",
        "L174-179": "ttools_dev registered with mode=0666",
        "L202": "ptrace_pre_hook = ttools_ptrace_hook  (writable fn ptr set here)",
    },
    "ttools.h_ioctl_numbers": {
        "TTOOLS_IO": "0xEE (magic byte)",
        "TTOOLS_PTRACE_PROTECT":  "_IO(0xEE, 0x00) = 0xEE00 (approx; actual = (0x00<<8)|0xEE00)",
        "TTOOLS_PTRACE_UNPROTECT":"_IO(0xEE, 0x01)",
        "TTOOLS_GET_FD_REFS_CNT": "_IOWR(0xEE, 0x02, struct ttools_fd_ref)",
    },
}


def probe():
    return {
        "critical": ["TTLS-F03"],
        "high": ["TTLS-F01"],
        "medium": ["TTLS-F02"],
        "info": ["TTLS-F04"],
    }


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "driver": "/dev/ttools (misc minor=254, mode=0666)",
        "kernel_versions": ["5.4.119-19 (TencentOS 2.4/3.1)", "5.4.241-24 (TencentOS 3.3)"],
        "ioctl_count": 3,
        "findings": list(FINDINGS.keys()),
        "critical": "TTLS-F03: ptrace_pre_hook writable at known VA (KASLR disabled)",
    }, indent=2))
