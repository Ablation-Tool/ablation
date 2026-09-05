"""
TencentOS 4.x — aegis.ko binary RE module.

aegis v0.1 — TOS exec monitoring and security hook framework.
Authors: zhipingdu/zgpeng/huntazhang (Tencent)
Source: TOS 4.x (kernel 6.6.47-12.tl4.x86_64 — earlier TOS 4.x, not 4.6)
Size: 72495B (not stripped, full symbols)

aegis is a split-architecture security framework:
  - aegis.ko = data collection engine + userspace delivery (this module)
  - hook consumer module (external) = provides hook_func_array (not found in TOS 4.6)

Monitored events: execve (exec info + cmdline + environ + pwd), socket connections,
SSH sessions (ssh_info_head, ssh_tty_head), per-task identity.

Data delivery: char device with poll/read (fops_poll, fops_read) + /proc files.
Architecture: per-CPU ring buffers, CPU-hotplug safe, RCU-protected reads.
"""

METADATA = {
    "kernel": "6.6.47-12.tl4.x86_64",
    "module": "aegis",
    "version": "0.1",
    "size_bytes": 72495,
    "authors": ["zhipingdu", "zgpeng", "huntazhang"],
    "license": "GPL",
    "srcversion": "820070783924C5C4F491405",
    "intree": True,
    "intree_correct": False,
    "note": "TOS 4.x minor version earlier than 4.6 (6.6.47 vs 4.6's 6.6.119)",
}

ARCHITECTURE = {
    "design_pattern": "Split framework: aegis.ko = engine, hook consumer module = sensors",
    "external_imports": {
        "hook_func_array": "Function pointer array provided by external hook consumer module",
        "hook_info_flag": "Flags from external consumer (which events to capture)",
        "hookinfo_nr": "Number of registered hook handlers",
        "data_release": "Release function for hook data buffers (consumer-provided)",
    },
    "exported_for_consumers": [
        "hook_info_func_register",
        "hook_info_func_unregister",
        "hookinfo_list_in",
        "hook_info_percpu_create",
        "hook_info_percpu_delete",
        "hook_info_proc_create",
        "hook_info_proc_delete",
        "get_execve_info",
        "get_sock_info",
        "get_task_environ",
        "get_task_ids",
        "get_task_para",
        "get_task_pwd",
        "get_task_start_time",
        "execinfo_to_user",
        "sockinfo_to_user",
        "get_pidns_inum",
        "clear_hookinfo_list",
        "clear_task_environ",
    ],
    "userspace_interface": {
        "char_device": "fops_open/read/release/poll (poll for new events, read to consume)",
        "proc_files": "hook_info_proc_create registers /proc entries per hook",
        "sysfs": "hook_sysfs_init creates sysfs kobject with disable_attr",
        "sysctl": "mod_sysctl_add/del — runtime sysctl parameters",
    },
}

EXECVE_INFO_STRUCT = {
    "name": "execve_info",
    "size_bytes": 0xc0,
    "allocation": "kmem_cache_alloc(cache, GFP_KERNEL | __GFP_ZERO = 0xdc0, 0xc0)",
    "magic_at_0x10": 0x12345601,
    "fields": {
        "[0x00]": "?? (unknown — likely list linkage or type)",
        "[0x10]": "magic = 0x12345601 (execve_info type marker)",
        "[0x18]": "hook_id (zeroed at init)",
        "[0x1c]": "refcount (initialized to 0x90 = 144; decremented on partial failures)",
        "[0x28]": "size field (subtracted from refcount on get_task_para failure)",
        "[0x58]": "start_time (ns → unit via 0xd6bf94d5e57a42bd reciprocal, shr 0x17)",
        "[0xb0]": "pointer to extra data (freed on allocation failure)",
    },
    "start_time_calculation": {
        "source": "task_struct + 0xca0 (task start timestamp in TOS 4.x)",
        "multiplier": "0xd6bf94d5e57a42bd",
        "shift": "shr 0x17 (23 bits)",
        "semantics": "Fast division by ~10^7: converts nanoseconds to 100ms units (or centiseconds)",
    },
}

HOOK_INFO_ARRAY = {
    "symbol": "hook_info_array",
    "addr": 0x02e0,
    "type": "data section (initialized)",
    "entry_size": 160,
    "entry_stride_formula": "(index * 4 + index) * 32 = index * 160",
    "fields_per_entry": {
        "[0x00]": "int index/id",
        "[0x10]": "next pointer in linked list of hook functions",
        "[readlock]": "per-entry rwlock (hook_info_array[i].readlock referenced in strings)",
        "[wait_queue]": "per-entry wait queue (hook_info_array[i].wait_queue)",
    },
}

HOOK_INFO_FUNC_REGISTER = {
    "function": "hook_info_func_register",
    "addr": 0x0c80,
    "purpose": (
        "Fill function pointer slots in hook_func_array from a linked list of hook_info entries. "
        "Takes: hook_info linked list (via external import). "
        "Traverses the list via entry[0x10] next pointer. "
        "For each entry: reads int at entry[0x00], uses it to index hook_func_array[rdx]. "
        "Sets hook_func_array[rdx] = entry pointer (192-bit slot). "
        "Returns 0 on success, -16 (0xfffffff0) if list traversal fails."
    ),
    "returns": "0 on success, -16 on error",
    "note": "Registers hook functions by populating the external hook_func_array — dispatch table",
}

DATA_COLLECTION_FUNCTIONS = {
    "get_execve_info": {
        "addr": 0x2080,
        "args": {
            "rdi": "int hook_id (which hook triggered the exec)",
            "rsi": "user info pointer (from syscall context)",
            "rdx": "additional context",
            "rcx": "pointer for extra exec data",
        },
        "flow": [
            "1. Increment per-CPU counter (%gs:[counter_ptr])",
            "2. Check if per-CPU queue is full — if full, drop and return",
            "3. Allocate 0xc0 (192B) zero-filled struct from slab cache",
            "4. Set magic at [rbx+0x10] = 0x12345601",
            "5. Zero [rbx+0x18]; refcount [rbx+0x1c] += 0x90",
            "6. Call get_task_ids(rbx, r14d, rbp) — fill PID/UID fields",
            "7. Call get_task_para(rbx, r13) — fill cmdline/argv",
            "8. Call get_task_environ(rbx) — fill environment variables",
            "9. Call get_task_pwd(rbx) — fill working directory",
            "10. Compute start_time from task_struct+0xca0, store at [rbx+0x58]",
            "11. Call get_task_start_time(rbx) — fill additional time fields",
            "12. Call hookinfo_list_in(rbx, 0) — add to per-CPU queue",
            "13. On error: free extra data at [rbx+0xb0], kfree(rbx)",
        ],
    },
    "get_task_environ": {
        "addr": 0x1600,
        "purpose": "Read /proc/self/environ equivalent — full environment of executing process",
        "note": "Uses strnlen_user to measure env strings from userspace memory",
    },
    "get_task_para": {
        "addr": 0x1930,
        "purpose": "Read process cmdline/argv — full command line including arguments",
        "note": "Bounded by sysctl_para_len (D), sysctl_para_sum (D) — configurable limits",
    },
    "get_task_pwd": {
        "addr": 0x1dc0,
        "purpose": "Get process working directory via d_path() — absolute path string",
        "imports_used": ["d_path", "path_get", "path_put"],
    },
    "get_task_ids": {
        "addr": 0x1c90,
        "purpose": "Fill PID/PPID/UID/EUID/GID/EGID fields into execve_info",
        "fields_collected": ["acti_pid", "acti_ppid", "acti_uid", "acti_euid", "init_pid", "init_ppid"],
        "namespace_aware": True,
        "imports": ["task_active_pid_ns", "__task_pid_nr_ns", "from_kuid_munged", "from_kgid_munged"],
    },
    "get_task_start_time": {
        "addr": 0x1f60,
        "purpose": "Process start timestamp from task_struct",
    },
    "get_sock_info": {
        "addr": 0x10f0,
        "purpose": "Collect socket connection info (src/dst IP, port, protocol) for network events",
    },
    "get_pidns_inum": {
        "addr": 0x1c00,
        "purpose": "Get PID namespace inode number for container identification",
        "imports": ["init_pid_ns", "put_pid_ns"],
        "note": "Used to distinguish between host and container processes",
    },
}

SSH_MONITORING = {
    "symbols": ["ssh_info_head", "ssh_tty_head"],
    "type": "data section — global doubly-linked list heads",
    "purpose": (
        "aegis maintains separate linked lists for SSH session data and SSH TTY data. "
        "This allows dedicated SSH session monitoring distinct from general exec event monitoring. "
        "When an SSH connection is established, a new ssh_info entry is added to ssh_info_head. "
        "TTY allocation for SSH sessions is tracked in ssh_tty_head. "
        "This lets aegis correlate SSH sessions with exec events that occur within them."
    ),
}

SYSCTL_PARAMETERS = {
    "sysctl_set_max": {
        "addr": 0x0280,
        "purpose": "Maximum number of events in the hook queue",
    },
    "sysctl_set_min": {
        "addr": 0x0288,
        "purpose": "Minimum queue drain size",
    },
    "sysctl_poll_wakeup_length": {
        "addr": 0x0290,
        "purpose": "Number of queued events before waking userspace poll",
    },
    "sysctl_info_num": {
        "addr": 0x0298,
        "purpose": "Current number of events in queue",
    },
    "sysctl_para_len": {
        "addr": 0x02a8,
        "purpose": "Max cmdline length to capture per process",
    },
    "sysctl_para_sum": {
        "addr": 0x02a0,
        "purpose": "Max total cmdline bytes accumulated",
    },
    "max_para_len": {
        "addr": 0x02b0,
        "purpose": "Hard maximum for para_len",
    },
    "min_para_len": {
        "addr": 0x02b8,
        "purpose": "Hard minimum for para_len",
    },
    "para_len_current": {
        "addr": 0x02c4,
        "purpose": "Runtime cmdline length limit (min/max bounded by sysctl)",
    },
}

PERCPU_ARCHITECTURE = {
    "design": "Per-CPU ring buffers for hook events",
    "creation": "hook_info_percpu_create — alloc_percpu(hook_info_data)",
    "deletion": "hook_info_percpu_delete — free_percpu",
    "cpu_hotplug": {
        "online": "cpu_online_func via __cpuhp_setup_state — initialize per-CPU data",
        "offline": "cpu_offline_func via __cpuhp_setup_state — drain per-CPU queue",
    },
    "consumer_sync": "fops_poll — wait_event via wait queue; fops_read — consume from per-CPU queues",
    "concurrency": "RCU for list reads, spinlock (raw_spin_lock_bh) for list writes",
    "rationale": (
        "Per-CPU design avoids cross-CPU contention for high-frequency exec events. "
        "On a 64-CPU server running thousands of exec/sec (container orchestration), "
        "a single global queue would serialize all producers. "
        "Per-CPU means each CPU enqueues without cross-CPU locking. "
        "Userspace reads drain all per-CPU queues in sequence."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "aegis collects full process environment variables — pre-exec secrets visible",
        "detail": (
            "get_task_environ captures the full environment of every exec'd process. "
            "This includes: API_KEY, AWS_SECRET_ACCESS_KEY, DATABASE_PASSWORD, JWT_SECRET, "
            "and any other secret passed via environment variable (common in 12-factor apps). "
            "The environment is captured BEFORE the exec completes — "
            "even if the process scrubs its own environment after start, aegis has already read it. "
            "This data is delivered to userspace via /dev/aegis to any process that opens it. "
            "If the consumer process (e.g., tagent) is compromised, "
            "an attacker can read secrets from every process that starts on the host."
        ),
        "data_captured": "Full process environment (env vars, including secrets)",
        "timing": "At execve() time, before process image is mapped",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "hook_func_array is an external import — unresolved at module load, dependent on consumer module",
        "detail": (
            "aegis imports `hook_func_array`, `hook_info_flag`, and `hookinfo_nr` from an external module. "
            "These are not from the kernel — they are INTER-MODULE dependencies. "
            "If the consumer module is not loaded (or is loaded in the wrong order), "
            "aegis's hook framework is non-functional: hook_info_func_register returns 0 "
            "immediately without registering any hooks. "
            "No error is logged if hook_func_array is NULL — aegis silently becomes a no-op. "
            "An attacker who can rmmod the consumer module before committing malicious exec "
            "will not be detected by aegis."
        ),
        "external_dependency": "hook_func_array (consumer module)",
        "failure_mode": "Silent no-op — no error logged on NULL array",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "fops_read consumer gets full argv+environment — no filtering, no truncation guard",
        "detail": (
            "get_task_para captures cmdline bounded by sysctl_para_len. "
            "get_task_environ captures the full environment (strnlen_user for each var). "
            "Both are included in the 192-byte execve_info struct plus linked extra data at [0xb0]. "
            "execinfo_to_user calls _copy_to_user to deliver data to any process with the /dev/aegis fd. "
            "There is no visible access control on the char device (mode not confirmed from binary). "
            "If /dev/aegis is world-readable or accessible to non-root, "
            "any process can read all exec events including environments of root processes."
        ),
        "risk": "exec event + environment + cmdline delivered to /dev/aegis opener",
        "requires_runtime_check": "Verify /dev/aegis permissions at runtime",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "intree:Y false — aegis is not in upstream 6.6 tree; avoids kernel taint",
        "detail": (
            "aegis.ko declares intree:Y like netatop.ko. "
            "aegis is not in the upstream Linux 6.6 kernel tree — it is a TOS-specific module. "
            "intree:Y avoids the 'O' (out-of-tree) kernel taint flag. "
            "All security tooling that checks for kernel taint to assess integrity "
            "will not see this module as out-of-tree, "
            "reducing visibility of TOS's custom security framework."
        ),
        "intree_declared": True,
        "intree_actual": False,
        "taint_avoided": "O",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "per-CPU queue drop — events silently lost if queue full",
        "detail": (
            "get_execve_info checks if per-CPU queue is full by comparing the per-CPU counter "
            "against a threshold. If full: increments the full counter, returns without capturing. "
            "The exec event is silently dropped — no error returned to the kernel hook, "
            "no log message. "
            "On a high-exec-rate host (e.g., shell command burst, build system, CI), "
            "exec events are silently lost if userspace is not consuming fast enough. "
            "An attacker generating rapid exec() calls could exhaust the queue, "
            "causing their malicious execs to be dropped from aegis's audit trail."
        ),
        "failure_mode": "Silent drop when per-CPU queue full",
        "evasion": "Burst of exec() calls to exhaust queue before malicious exec",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "SSH session tracking via ssh_info_head — TTY allocation monitored separately",
        "detail": (
            "aegis maintains ssh_info_head and ssh_tty_head as global linked list heads. "
            "These track SSH sessions and their TTY allocations. "
            "This suggests aegis was designed as a CSIRT/HIDS tool — "
            "SSH session correlation (who logged in) + exec events (what they ran) + "
            "environment (with what credentials). "
            "An attacker connecting via SSH and running commands generates: "
            "1) ssh_info entry, 2) TTY allocation, 3) exec events for each command. "
            "These three streams can be correlated by session ID."
        ),
        "ssh_tracking": ["ssh_info_head (session)", "ssh_tty_head (TTY)"],
    },
    {
        "id": "F7",
        "severity": "MEDIUM",
        "title": "PID namespace inode (get_pidns_inum) — container process identification",
        "detail": (
            "get_pidns_inum (0x1c00) returns the PID namespace's inode number. "
            "On Kubernetes nodes: each pod has a unique PID namespace inode. "
            "aegis embeds this inode in exec events, enabling "
            "per-container exec event attribution: "
            "which container (by namespace inode) executed which process. "
            "This is more reliable than using cgroup paths for attribution. "
            "The init_pid_ns import provides the root namespace for comparison — "
            "execs in the root namespace (host processes) vs. pod namespaces are distinguishable."
        ),
        "container_aware": True,
        "namespace_inode": "PID namespace inode as unique container identifier",
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "execve_info magic 0x12345601 — deterministic struct identifier for forensics",
        "detail": (
            "get_execve_info writes 0x12345601 at execve_info+0x10. "
            "This is a compile-time constant type marker for the struct. "
            "In a kernel memory dump or heap spray scenario, "
            "searching for 0x12345601 identifies aegis execve_info structs in memory. "
            "Conversely, a kernel exploit that overwrites aegis structs should avoid "
            "this offset to prevent detection via magic mismatch. "
            "The magic also distinguishes execve_info from other aegis info types "
            "(sock_info likely has a different magic value)."
        ),
        "magic": 0x12345601,
        "offset": 0x10,
    },
]

if __name__ == '__main__':
    print("aegis.ko (TOS 4.x, 6.6.47) RE analysis")
    print(f"Authors: {', '.join(METADATA['authors'])}")
    print()
    print("Architecture:")
    print(f"  Engine: aegis.ko (data collection, per-CPU queues, userspace delivery)")
    print(f"  Sensors: external consumer module via hook_func_array")
    print()
    print("execve_info struct:")
    print(f"  Size: {EXECVE_INFO_STRUCT['size_bytes']:x}h (192B)")
    print(f"  Magic: {hex(EXECVE_INFO_STRUCT['magic_at_0x10'])}")
    print()
    print("Data collected per exec:")
    for fn, info in DATA_COLLECTION_FUNCTIONS.items():
        print(f"  {fn}: {info['purpose'][:60]}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
