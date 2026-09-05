"""
TencentOS 4.6 — ttools.ko kernel module RE.

Binary: ttools.ko — "ttools 2.0 for 5.4.241-24.0017.41.1"
Type: x86-64 kernel module (ELF relocatable), NOT stripped
Size: 0x464 bytes .text; full module ~12KB

Method: nm symbol extraction → capstone disassembly of all 6 functions →
import table analysis → hook pattern identification.

Role: Kernel module that registers ptrace_pre_hook to block ptrace(2) on
configured PIDs. Protects privileged Tencent processes from debugger attachment.
"""

BINARY_INVENTORY = {
    "ttools.ko": {
        "path": "/tmp/scratchpad/ttools.ko",
        "description": "ttools 2.0 for 5.4.241-24.0017.41.1",
        "type": "ELF relocatable (kernel module), x86-64, NOT stripped",
        "license": "GPL",
        "text_size": 0x464,
        "kernel_target": "5.4.241-24.0017.41.1",
        "signing": "Tencent: Tkernel signing key (signature appended)",
        "vermagic": "5.4.241-24.0017.41.1 SMP mod_unload modversions",
    },
}

SYMBOL_TABLE = {
    "ttools_ptrace_hook":    {"offset": 0x20,  "type": "function", "role": "ptrace pre-hook callback"},
    "ttools_pids_lock":      {"offset": 0x08,  "type": "data",     "role": "spinlock protecting ttools_protected_pids"},
    "ttools_protected_pids": {"offset": 0x190, "type": "data",     "role": "head of doubly-linked PID list"},
    "ttools_dev_ioctl":      {"offset": 0x90,  "type": "function", "role": "misc device ioctl handler"},
    "ttools_init":           {"offset": 0x330, "type": "function", "role": "module init; misc_register + hook install"},
    "ttools_exit":           {"offset": 0x3a0, "type": "function", "role": "module exit; list flush + misc_deregister"},
    "ttools_dev":            {"type": "data",  "role": "miscdevice struct for /dev/ttools"},
    "ttools_chardev_ops":    {"type": "data",  "role": "file_operations struct; only .ioctl + noop_llseek"},
}

IMPORTED_SYMBOLS = {
    "kallsyms_lookup_name":    "used in ttools_init to resolve ptrace_pre_hook at runtime",
    "ptrace_pre_hook":         "kernel hook point for ptrace interception (resolved via kallsyms)",
    "misc_register":           "registers /dev/ttools as a misc device",
    "misc_deregister":         "unregisters /dev/ttools in ttools_exit",
    "smp_call_function":       "used to install/clear ptrace hook on ALL CPUs atomically via IPI",
    "kmem_cache_alloc_trace":  "allocates 24-byte PID list entries from slab cache",
    "kfree":                   "frees PID list entries in ioctl and ttools_exit",
    "_raw_spin_lock":          "protects ttools_protected_pids linked list",
    "_copy_from_user":         "ioctl 0xc010ee02: copy 16-byte struct from user",
    "_copy_to_user":           "ioctl 0xc010ee02: write result back to user",
    "__fdget":                 "ioctl 0xc010ee02: get file reference from fd",
    "fput":                    "ioctl 0xc010ee02: release file reference",
    "anon_inode_inode":        "ioctl 0xc010ee02: check if fd is an anon_inode (filter non-file fds)",
    "__list_add_valid":        "kernel list safety check for list_add",
    "__list_del_entry_valid":  "kernel list safety check for list_del",
    "current_task":            "per-CPU pointer to current task_struct",
    "noop_llseek":             "llseek op in ttools_chardev_ops — device is not seekable",
    "printk":                  "prints load/unload messages to kernel log",
    "pv_ops":                  "paravirtualization ops (used by spinlock implementation)",
    "__fentry__":              "function tracer entry point (CONFIG_FUNCTION_TRACER)",
    "__stack_chk_fail":        "stack canary failure handler",
}

PTRACE_HOOK_ANALYSIS = {
    "function": "ttools_ptrace_hook",
    "offset": 0x20,
    "hook_symbol": "ptrace_pre_hook",
    "hook_type": (
        "ptrace_pre_hook is an internal Linux kernel hook point (not a public API). "
        "It is a function pointer that, when set, is called before ptrace() attaches to a task. "
        "The hook signature is: int (*hook)(task_struct *tracer, task_struct *tracee). "
        "ttools installs its function here; returning -1 (0xffffffff) denies the attach."
    ),
    "hook_installation": (
        "ttools_init calls kallsyms_lookup_name('ptrace_pre_hook') to get the kernel address "
        "of the hook pointer at runtime. It then calls smp_call_function() to install its "
        "callback on ALL CPUs via IPI, ensuring no CPU is missed during installation. "
        "This eliminates a race window where a CPU's cached hook pointer might be stale."
    ),
    "disassembly_analysis": {
        "task_struct_pid_offset": 0xb40,
        "offset_note": (
            "ttools_ptrace_hook reads [rdx+0xb40] to get the target task's PID. "
            "On Linux 5.4 x86-64, task_struct->pid is at offset 0xb40 (confirmed for 5.4.241). "
            "rdx is the second argument (tracee task_struct *), consistent with the pre-hook signature."
        ),
        "algorithm": (
            "1. Load task PID: mov rbp, [rdx+0xb40] — target process PID from task_struct "
            "2. Acquire spinlock: _raw_spin_lock(&ttools_pids_lock) "
            "3. Load list head: rbx = ttools_protected_pids "
            "4. Walk linked list: for each entry, compare entry[+0x10] (pid field) with rbp "
            "5. If match found: set edx = 0xffffffff (-EPERM), release lock, return (deny ptrace) "
            "6. If no match: set edx = 0 (allow), release lock, return "
        ),
        "pid_entry_layout": {
            "size": 24,
            "offset_0x00": "list_head.next pointer",
            "offset_0x08": "list_head.prev pointer",
            "offset_0x10": "pid_t protected_pid (the value compared against task->pid)",
        },
    },
    "effect": (
        "Any process whose PID is in ttools_protected_pids will be immune to ptrace(2) attachment. "
        "This blocks: gdb, strace, ltrace, perf attach, /proc/$pid/mem reads via ptrace, "
        "and any kernel subsystem that uses ptrace internally (e.g., some seccomp notifications). "
        "ptrace_pre_hook fires before the kernel's own permission checks, so this is the "
        "earliest possible denial point."
    ),
}

IOCTL_ANALYSIS = {
    "device": "/dev/ttools",
    "device_type": "misc device (minor = MISC_DYNAMIC_MINOR; assigned dynamically at load)",
    "file_operations": "only .unlocked_ioctl = ttools_dev_ioctl, .llseek = noop_llseek",
    "commands": {
        "0xee00": {
            "name": "TTOOLS_PROTECT_SELF",
            "args": "none (third ioctl arg ignored)",
            "behavior": (
                "Adds the CALLING PROCESS's PID to ttools_protected_pids. "
                "PID is read from current_task->pid (gs:[0] → [task+0xb40]) — "
                "the kernel supplies it; the caller cannot forge a different PID. "
                "Allocates a 24-byte slab entry, sets entry[+0x10] = current PID, "
                "locks and prepends to ttools_protected_pids. "
                "Returns 0 on success, -ENOMEM if allocation fails."
            ),
            "notes": (
                "Self-protection only: a process can only add itself to the list. "
                "No privilege check evident in disassembly — any process that can "
                "open /dev/ttools can call this, making device file permissions critical."
            ),
        },
        "0xee01": {
            "name": "TTOOLS_UNPROTECT_SELF",
            "args": "none (third ioctl arg ignored)",
            "behavior": (
                "Removes the CALLING PROCESS's PID from ttools_protected_pids. "
                "Same PID derivation as 0xee00 (current_task). "
                "Walks the list for a matching entry, calls __list_del_entry_valid, "
                "poisons list pointers with 0xdead000000000100 / 0xdead000000000122 "
                "(standard Linux list debug poison), then kfree()s the entry. "
                "Returns 0 on success (whether or not the PID was in the list)."
            ),
        },
        "0xc010ee02": {
            "name": "TTOOLS_QUERY_FD",
            "encoding": "_IOWR(0xee, 2, struct { u32 fd; u32 flags; u64 result; })",
            "args": "pointer to 16-byte struct (u32 fd, u32 flags, u64 result)",
            "behavior": (
                "Copies 16 bytes from userspace. First 4 bytes are treated as an fd (file descriptor). "
                "Calls __fdget() to get the associated file, validates it is not an anon_inode "
                "(checks against anon_inode_inode). "
                "Then extracts two 64-bit values from the task associated with that file's "
                "f_owner or the file's f_inode fields — specifics at offsets [task+0x38], "
                "[task+0x18], [task+0x20] suggest stack base, mm, and active_mm fields. "
                "Computes a combined u64 result and writes 16 bytes back to user. "
                "Calls fput() to release the file reference. "
                "Returns 0 on success, -EFAULT on copy failure, -ESRCH if fd lookup fails."
            ),
            "likely_role": (
                "Given the fields extracted (stack base at [task+0x38], mm-related at [task+0x18]), "
                "this is likely a query to get the task's address-space layout info "
                "for a process referenced by fd — possibly used by Tencent's runtime to verify "
                "that a protected process's memory hasn't been tampered with, or to resolve "
                "the protection status of a process given one of its file descriptors."
            ),
        },
    },
}

MODULE_INIT_EXIT = {
    "ttools_init": {
        "sequence": [
            "1. Call kallsyms_lookup_name('ptrace_pre_hook') — get hook pointer address",
            "2. Test result: if NULL, return -ENODEV (0xffffffed = -19)",
            "3. Store hook pointer in module-private global",
            "4. Zero ttools_protected_pids list head",
            "5. Call smp_call_function() with IPI to set *ptrace_pre_hook = ttools_ptrace_hook on all CPUs",
            "6. Call misc_register(&ttools_dev) — creates /dev/ttools",
            "7. If misc_register fails: clear hook via smp_call_function, return error",
            "8. printk('ttools 2.0 loaded')",
        ],
        "note": (
            "The smp_call_function before misc_register means the hook is live before the "
            "device file is created. Tiny window where the hook filters PIDs that nobody "
            "has added yet (protected_pids is empty at init time, so hook is a no-op pass)."
        ),
    },
    "ttools_exit": {
        "sequence": [
            "1. Call smp_call_function() with IPI to clear *ptrace_pre_hook = NULL on all CPUs",
            "2. Walk ttools_protected_pids: list_del + kfree each entry (using poison check)",
            "3. Call misc_deregister(&ttools_dev) — removes /dev/ttools",
            "4. printk('ttools 2.0 unloaded')",
        ],
        "note": (
            "Hook is cleared before device is removed. Any in-flight ioctl would fail after "
            "misc_deregister. No use-after-free risk in normal unload path."
        ),
    },
}

SECURITY_ANALYSIS = {
    "threat_model": (
        "ttools.ko is anti-forensic infrastructure: any process on the protected list cannot be "
        "ptraced. Legitimate use: Tencent service processes (anti-cheat, DRM, HSM agents) "
        "registering themselves at startup to prevent debugging. "
        "Risk: the same mechanism that protects legitimate processes also protects malicious ones. "
        "If an attacker gains code execution in a process with /dev/ttools access, they can "
        "prevent forensic analysis of their implant."
    ),
    "device_permissions_critical": (
        "/dev/ttools permissions determine who can call 0xee00/0xee01. "
        "If world-writable (mode 0666): any user can self-protect from ptrace — "
        "anti-cheat bypass, rootkit persistence, forensic evasion. "
        "Expected secure config: 0600 or 0640, owned by root:root or a ttools-specific group. "
        "Actual permissions depend on udev rules not visible in the .ko binary."
    ),
    "kernel_api_stability": (
        "ptrace_pre_hook is NOT a stable kernel API — it is an internal function pointer. "
        "kallsyms_lookup_name for a non-exported symbol requires CONFIG_KALLSYMS_ALL. "
        "A kernel update that removes or changes ptrace_pre_hook silently breaks ttools "
        "or, worse, causes ttools_init to install a hook at a garbage address. "
        "This is a tightly kernel-version-coupled implementation — the tl4 package "
        "enforces this by vermagic=5.4.241-24.0017.41.1."
    ),
    "smp_call_function": (
        "Using smp_call_function to install the hook ensures all CPUs atomically see "
        "the new hook value. Without this, a thread migrated to another CPU after hook "
        "installation could temporarily escape the hook. Tencent got this right."
    ),
    "signing": (
        "The module is signed with 'Tencent: Tkernel signing key'. On systems with "
        "Secure Boot + kernel module signature enforcement, only Tencent-signed modules "
        "load. This prevents tampering with ttools itself but is not a security boundary "
        "for the protected-PID list (any process with /dev/ttools access can manipulate it)."
    ),
    "pid_recycling": (
        "PIDs are not removed on process exit. If a protected process exits and its PID is "
        "recycled by a new unrelated process, the new process inherits ptrace protection "
        "until the slot is cleaned. PID recycling window = up to 2^22 new processes. "
        "This is a time-limited false-positive rather than a persistent bug, but could "
        "complicate forensics during incident response."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "ttools.ko: any process with /dev/ttools access can self-register as ptrace-immune",
        "detail": (
            "ioctl 0xee00 (TTOOLS_PROTECT_SELF) adds the calling process to the ptrace block list. "
            "No capability check in disassembly — access is gated solely by /dev/ttools file permissions. "
            "If device is world-writable: unprivileged code can defeat gdb, strace, perf, "
            "/proc/$pid/mem, and any ptrace-based forensics tool. "
            "Anti-cheat bypass, rootkit persistence, incident response evasion all become trivial. "
            "Severity depends on deployment permissions — udev rules not recoverable from .ko alone."
        ),
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "PID recycling: protected slot persists after process exit — new process inherits immunity",
        "detail": (
            "ttools_protected_pids entries are only removed via ioctl 0xee01 (explicit self-removal). "
            "No exit hook (task_exit_notifier) removes the entry when the process dies. "
            "Recycled PID acquires ptrace immunity for the interval until slot is reaped. "
            "On busy systems with short-lived processes: forensic blind spot for process N+1."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "Hook via kallsyms_lookup_name(ptrace_pre_hook): unstable internal API",
        "detail": (
            "ptrace_pre_hook is not a EXPORT_SYMBOL'd kernel API. Requires CONFIG_KALLSYMS_ALL. "
            "ttools_init returns -ENODEV if kallsyms fails (safe fail). "
            "But any kernel update that removes or renames this hook silently disables protection "
            "without error after the initial load. Module is version-pinned by vermagic to 5.4.241."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "smp_call_function for hook install: correct IPI-based atomic update across all CPUs",
        "detail": (
            "Hook installation and removal use smp_call_function() for cross-CPU atomicity. "
            "No race window where a migrated thread escapes the hook on install. "
            "Exit path clears hook before misc_deregister — no UAF on module unload. "
            "Implementation is correct for an SMP kernel."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "0xc010ee02 QUERY_FD ioctl: reads task memory layout via fd reference",
        "detail": (
            "Copies 16 bytes from userspace (u32 fd + padding + u64 result). "
            "Calls __fdget(fd), validates against anon_inode_inode, extracts task fields "
            "at offsets 0x38 (stack)/0x18 (mm)/0x20 (active_mm) from the associated task. "
            "Returns a computed u64 result. Likely used by Tencent runtime to verify "
            "memory layout integrity of protected processes or to query protection status by fd."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "Module signed with Tencent kernel signing key — prevents tampering on Secure Boot systems",
        "detail": (
            "'Tencent: Tkernel signing key' appended per standard kernel module signing. "
            "Prevents an attacker from patching ttools.ko and loading the modified version "
            "on systems with module signature enforcement. "
            "Does not protect the protected_pids list at runtime — that is accessible via /dev/ttools."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 ttools.ko — kernel ptrace protection module RE")
    print()
    print(f"  Module: {BINARY_INVENTORY['ttools.ko']['description']}")
    print(f"  License: {BINARY_INVENTORY['ttools.ko']['license']}")
    print(f"  Signing: {BINARY_INVENTORY['ttools.ko']['signing']}")
    print()
    print("Functions:")
    for sym, info in SYMBOL_TABLE.items():
        if info.get('type') == 'function':
            print(f"  {sym} @ +0x{info['offset']:02x}: {info['role']}")
    print()
    print("Hook: ptrace_pre_hook (resolved via kallsyms_lookup_name at module load)")
    print(f"  task_struct->pid offset: 0x{PTRACE_HOOK_ANALYSIS['disassembly_analysis']['task_struct_pid_offset']:x} (5.4.241)")
    print(f"  Returns 0=allow / -1=deny based on ttools_protected_pids list")
    print()
    print("IOCTLs:")
    for cmd, info in IOCTL_ANALYSIS['commands'].items():
        print(f"  {cmd}: {info['name']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
