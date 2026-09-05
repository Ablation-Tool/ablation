"""
TencentOS — AEGIS kernel HIDS module RE.

Binary: aegis.ko
Kernel: 6.6.47-12.tl4.x86_64 (intermediate TOS 4.x — NOT current TOS 4.6 6.6.119)
Authors: zhipingdu/zgpeng/huntazhang (Tencent)
Version: 0.1
Signed: Tkernel signing key (D8:37:BC:3B:9C:28:FD:F6)
Source: scratchpad/aegis.ko

NOTE: The module's vermagic (6.6.47-12.tl4) differs from TOS 4.6 (6.6.119-51.3.tl4).
This is a build from an intermediate TOS 4.x kernel release. The architecture
and API surface are documented here from the binary.

IMPORTANT: This is NOT the crypto aegis128 cipher (crypto/aegis128.c).
This is Tencent's proprietary HIDS (Host Intrusion Detection System) kernel module
that hooks execve syscalls and exports process telemetry to userspace agents.
"""

BINARY_METADATA = {
    "module_name": "aegis",
    "version": "0.1",
    "authors": ["zhipingdu", "zgpeng", "huntazhang"],
    "kernel_vermagic": "6.6.47-12.tl4.x86_64 SMP preempt mod_unload modversions",
    "license": "GPL",
    "intree_claim": "Y",
    "signing_key": "D8:37:BC:3B:9C:28:FD:F6",
    "signer": "Tkernel signing key",
    "sig_hash": "sha512",
    "retpoline": "Y",
    "size_bytes": None,  # not measured
    "depends": [],
}

FUNCTION_CATALOG = {
    "execve_monitoring": [
        "get_execve_info",       # hook execve syscall; captures command + args
        "execinfo_to_user",      # copies execve info struct to userspace consumer
        "extra_execinfo_free",   # releases extra info allocation after export
    ],

    "process_environment": [
        "get_task_environ",      # captures /proc/<pid>/environ content at execve time
        "clear_task_environ",    # frees captured environment buffer
    ],

    "process_metadata": [
        "get_task_ids",          # captures UID/GID/PID/TGID
        "get_task_para",         # captures task parameters (argc, argv pointers)
        "get_task_pwd",          # captures working directory path
        "get_task_start_time",   # captures process start time (monotonic ns)
        "get_pidns_inum",        # gets PID namespace inode number (identifies container)
        "nsec_to_clock_t",       # nanosecond to clock_t conversion for timestamps
    ],

    "network_monitoring": [
        "get_sock_info",         # captures socket source/dest addr+port
        "sockinfo_to_user",      # copies socket info to userspace consumer
    ],

    "hook_framework": [
        "hook_info_func_register",    # register a hook function by name/ID
        "hook_info_func_unregister",  # unregister a hook function
        "hook_info_percpu_create",    # allocate per-CPU hook state
        "hook_info_percpu_delete",    # free per-CPU hook state
        "hookinfo_list_in",           # enqueue event to per-CPU ring buffer
        "hookinfo_drop_stats",        # record dropped events (ring buffer full)
        "hookinfo_total_numb",        # total event count across CPUs
        "hook_disable",               # disable a specific hook
        "clear_hookinfo_list",        # flush ring buffer
        "info_ptr_hold_ref",          # reference-count info struct to prevent free during export
        "init_wait_queue",            # init wait queue for blocking userspace reader
        "para_len_sum_handler",       # compute total parameter length for buffer sizing
        "percpu_total_num",           # per-CPU event counter
        "percpu_total_num_atomic64",  # atomic64 variant of percpu_total_num
    ],

    "kernel_interfaces": {
        "procfs": [
            "hook_info_proc_create",   # create /proc/aegis/<hook> entry
            "hook_info_proc_delete",   # remove /proc/aegis/<hook> entry
            "hook_info_read",          # procfs read: userspace reads events here
            "list_module_init",        # init module-list procfs entry
            "list_module_exit",        # teardown module-list entry
        ],
        "sysfs": [
            "hook_sysfs_init",         # create sysfs attribute group
            "hook_sysfs_exit",         # remove sysfs attribute group
        ],
        "sysctl": [
            "secur_sysctl_handler",    # handles read/write of security sysctl
            "mod_sysctl_add",          # dynamically add a sysctl entry
            "mod_sysctl_del",          # remove a sysctl entry
        ],
    },

    "cpu_management": [
        "clear_cpu_list",              # clear CPU affinity list for hook delivery
    ],
}

EXTERNAL_SYMBOLS_USED = {
    "process": [
        "task_active_pid_ns",    # get PID namespace of task
        "init_pid_ns",           # initial (host) PID namespace
        "put_pid_ns",            # release PID namespace reference
        "__task_pid_nr_ns",      # get PID number within specific namespace
        "from_kuid_munged",      # UID kernel→user-visible conversion
        "init_pid",              # PID 1 struct (used to detect init)
        "acti_pid",              # active PID
        "init_ppid",             # init process PPID
    ],
    "procfs": [
        "proc_create",
        "proc_create_data",
        "proc_remove",
        "proc_mkdir",
    ],
    "sysctl": [
        "register_sysctl_sz",
        "unregister_sysctl_table",
    ],
    "sysfs": [
        "sysfs_create_group",
        "sysfs_remove_group",
    ],
    "security": [
        "security_sysctl",     # hooks into LSM security sysctl path
    ],
}

ARCHITECTURE = {
    "overview": (
        "aegis.ko is a kernel HIDS that intercepts execve syscalls and network connections, "
        "buffers the events per-CPU, and exports them to a userspace agent via procfs reads. "
        "Userspace opens /proc/aegis/<hook_name>, blocks in read(), and receives binary structs "
        "describing process launch events (path, argv, env, uid/gid, pid, cwd, start_time, "
        "network socket state)."
    ),
    "event_pipeline": [
        "1. hook_info_func_register() registers get_execve_info for the execve hook point",
        "2. On each execve: get_execve_info() captures command, argv, get_task_environ() captures env",
        "3. get_task_ids() captures UIDs/GIDs/PIDs; get_task_pwd() captures cwd; get_sock_info() captures sockets",
        "4. hookinfo_list_in() enqueues to per-CPU ring buffer",
        "5. Userspace agent blocking on hook_info_read() wakes up and drains the buffer",
        "6. execinfo_to_user() / sockinfo_to_user() copies structs to user address space",
        "7. extra_execinfo_free() releases kernel-side buffer",
    ],
    "container_awareness": (
        "get_pidns_inum() extracts the PID namespace inode number — a unique identifier for "
        "each container's PID namespace. Events include the namespace ID, allowing the "
        "userspace agent to attribute execve events to specific containers."
    ),
    "drop_detection": (
        "hookinfo_drop_stats() records events dropped due to full ring buffer. "
        "percpu_total_num() and hookinfo_total_numb() expose counters via sysfs. "
        "A userspace agent that is too slow to drain the ring buffer loses events — "
        "the drop rate is observable but events themselves are unrecoverable."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "aegis.ko claims intree:Y — false declaration to bypass out-of-tree signing scrutiny",
        "detail": (
            "Module metadata: intree=Y. The aegis module is NOT in the upstream Linux kernel "
            "source tree. Claiming intree=Y can bypass certain out-of-tree module warnings and "
            "changes the module's tainting behavior. A tainting event for out-of-tree modules "
            "would appear in dmesg; an intree=Y claim suppresses it. "
            "On TOS, the module is Tkernel-signed, so it loads regardless — but the false claim "
            "makes the module harder to identify as third-party kernel code."
        ),
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "get_task_environ: full process environment captured at execve — key material at risk",
        "detail": (
            "aegis.ko captures the complete process environment (all env vars) on every execve. "
            "If a process is launched with secret material in its environment "
            "(API keys, passwords, tokens as env vars), the aegis kernel module captures them "
            "and exports them to the HIDS userspace agent. This is by design for security monitoring, "
            "but constitutes a systematic credential collection path from the kernel."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "Procfs ring buffer: events dropped silently if userspace agent is slow",
        "detail": (
            "hookinfo_drop_stats() tracks dropped events. When the per-CPU ring buffer is full "
            "and the userspace HIDS agent has not drained it, events are dropped. "
            "An attacker can induce a high-volume execve burst to fill the ring buffer and "
            "cause subsequent events to be silently dropped — an evasion against the HIDS "
            "monitoring capability without killing the agent or removing the module."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "security_sysctl hook: aegis intercepts all security sysctl operations",
        "detail": (
            "aegis.ko registers a hook on security_sysctl — the LSM hook that runs for every "
            "sysctl read/write. secur_sysctl_handler handles the callback. "
            "This gives aegis visibility into all sysctl modifications, including attempts to "
            "disable TOS security modules via sysctl."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "aegis.ko vermagic 6.6.47-12.tl4: intermediate kernel, not current TOS 4.6",
        "detail": (
            "Module signed for 6.6.47-12.tl4. Current TOS 4.6 runs 6.6.119-51.3.tl4. "
            "The module in scratchpad is from an intermediate TOS 4.x release. "
            "Confirms aegis.ko existed and was shipped in TOS kernel line prior to current release."
        ),
    },
]

if __name__ == '__main__':
    print("TencentOS AEGIS HIDS kernel module RE")
    print(f"  module: aegis.ko v{BINARY_METADATA['version']}")
    print(f"  kernel: {BINARY_METADATA['kernel_vermagic']}")
    print(f"  authors: {', '.join(BINARY_METADATA['authors'])}")
    print(f"  signing_key: {BINARY_METADATA['signing_key']}")
    print()
    print("Function categories:")
    for cat, funcs in FUNCTION_CATALOG.items():
        if isinstance(funcs, list):
            print(f"  {cat}: {len(funcs)} functions")
        else:
            total = sum(len(v) for v in funcs.values())
            print(f"  {cat}: {total} functions")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
