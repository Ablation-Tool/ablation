"""
TencentOS 4.6 — dim_core.ko binary RE module.

DIM = Dynamic Integrity Measurement.
TOS's out-of-tree IMA-equivalent: hashes kernel text, module text, and user process
text segments against static (pre-signed) or dynamic (runtime-built) baselines.
On mismatch: log alert, optionally send SIGKILL.

No author or description in modinfo (unlike other TOS modules).
Vermagic: 6.6.119-51.3.tl4.x86_64 (TOS 4.6). Also exists as dim_core_44.ko (TOS 4.4).
186510B — the largest TOS security module in the scratchpad.

Boot requirement: kernel cmdline must include integrity=dim or init fails with
"boot parameter 'integrity=dim' not set".

Source path inferred: likely kernel/tkernel/dim/ (consistent with other TOS module paths).
"""

METADATA = {
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "module": "dim_core",
    "size_bytes": 186510,
    "tos44_counterpart": "dim_core_44.ko (185367B, 6.6.110-42.4.tl4)",
    "boot_requirement": "kernel cmdline: integrity=dim",
    "parameters": {
        "measure_log_capacity": "Max number of measure log entries (uint)",
        "measure_schedule": "Schedule time (ms) per measure object (uint)",
        "measure_hash": "Hash algorithm for measurement (charp, e.g., 'sha256')",
        "measure_pcr": "TPM PCR index to extend measure log into (uint)",
        "measure_interval": "Interval time (min) for automatic measurement (uint)",
        "signature": "Require signature for policy and static baseline (bool)",
    },
}

ARCHITECTURE = {
    "design": (
        "DIM is TOS's integrity measurement subsystem — similar to Linux IMA but "
        "implemented as a standalone kernel module rather than a kernel subsystem. "
        "It measures three targets: kernel text, module text, and user process text. "
        "Measurements are compared against baselines. "
        "Baselines can be static (pre-computed, signed) or dynamic (built at first measurement). "
        "TPM PCR extension is optional — measured values can be extended into a PCR for attestation."
    ),
    "measurement_targets": {
        "KERNEL_TEXT": {
            "task": "dim_core_measure_task_kernel_text",
            "function": "kernel_text_measure at 0x18e0",
            "measures": "Kernel .text section — the running kernel code",
        },
        "MODULE_TEXT": {
            "task": "dim_core_measure_task_module_text",
            "function": "module_text_measure + measure_module at 0x1bd0",
            "measures": "Loaded kernel module .text sections",
            "policy_required": "name= field in policy (module name)",
        },
        "BPRM_TEXT": {
            "task": "dim_core_measure_task_user_text",
            "function": "user_text_measure at 0x27c0",
            "measures": "User process text VMAs (executable pages)",
            "policy_required": "path= field in policy (executable path)",
        },
    },
    "baseline_types": {
        "static": {
            "source": "Pre-computed hash file (signed if signature=Y)",
            "init": "baseline_prepare at 0x0a50",
            "check": "mismatch → KERN_WARNING + optional kill",
        },
        "dynamic": {
            "source": "First measurement becomes the baseline",
            "init": "baseline_work_cb at 0x09d0 → 'no baseline, do baseline init instead'",
            "check": "subsequent measurements compared to this baseline",
        },
    },
    "mismatch_actions": {
        "log": "KERN_ERR/KERN_WARNING: 'mismatch static/dynamic baseline of user/kernel %s'",
        "kill": "SIGKILL via kill_task() when 'kill action' is set in policy",
        "restrictions": [
            "Won't kill current process ('don't kill the current process')",
            "Won't kill PID 1 ('the pid of tampered task is 1, don't kill it')",
        ],
    },
}

KEY_FUNCTIONS = {
    "dim_core_kallsyms_init": {
        "addr": 0x1080,
        "purpose": "Resolve unexported kernel symbols using the kprobe trick",
        "mechanism": (
            "8 consecutive pattern: mov $symbol_ptr → rdi; call (kprobe); mov result → BSS. "
            "Zeroes a kprobe struct with rep stosq (10 quadwords = 80B). "
            "Calls the kprobe resolver 8 times, storing each resolved address in BSS. "
            "Checks all 8 pointers for NULL — if any is NULL, returns -ENOENT (0xfffffffe). "
            "Final check: cmpq $0x1 on one stored value (likely kallsyms_lookup_name check). "
            "This is the same kprobe symbol-address technique as tdm-kernel-guard."
        ),
        "symbols_resolved": "8 symbols (addresses not visible — stored in BSS via relocs)",
        "returns": "0 on success, -ENOENT (0xfffffffe) if any symbol lookup fails",
    },
    "kernel_text_measure": {
        "addr": 0x18e0,
        "purpose": "Measure kernel .text section integrity",
        "called_by": "dim_core_measure_task_kernel_text",
    },
    "do_calc_kernel_digest": {
        "addr": 0x17b0,
        "suffix": ".isra.0",
        "purpose": "Calculate hash of a kernel memory region",
        "note": "Separate from user-space measurement to handle vmalloc/direct-map addresses",
    },
    "module_text_measure": {
        "addr": 0x1b60,
        "purpose": "Measure a kernel module's .text section",
    },
    "measure_module": {
        "addr": 0x1bd0,
        "purpose": "Measure one module: iterate VMAs via next_module_text_vma",
    },
    "next_module_text_vma": {
        "addr": 0x2200,
        "purpose": "Iterator: find next executable VMA for a module",
    },
    "dim_vm_hash_update_vmas": {
        "addr": 0x1fd0,
        "purpose": "Update hash state across all VMAs in a process",
    },
    "dim_vm_hash_calculate_vma": {
        "addr": 0x2030,
        "purpose": "Calculate hash contribution of one VMA",
    },
    "user_text_measure": {
        "addr": 0x27c0,
        "purpose": "Measure user process text (BPRM_TEXT) — walks executable VMAs",
    },
    "measure_text_vma": {
        "addr": 0x2840,
        "purpose": "Measure one text VMA (hash the page contents)",
    },
    "check_process_digest": {
        "addr": 0x2100,
        "purpose": "Compare measured digest against baseline; trigger action on mismatch",
    },
    "kill_task": {
        "addr": 0x22c0,
        "purpose": "Send SIGKILL to tampered process (only if not self, not PID 1)",
        "signature": "bool kill_task(struct task_struct *task)",
        "key_ops": [
            "cmp %rax,%rdi where rax=%gs:0x0 (current) — skip if self",
            "mov $0x9,%edi — SIGKILL",
            "call send_sig(SIGKILL, task, 1)",
            "returns 1 if killed, 0 if skipped",
        ],
    },
    "dim_core_sig_verify": {
        "addr": 0x1280,
        "purpose": "Verify signature on policy or baseline file",
        "note": "Only called if signature=Y parameter is set",
    },
    "dim_read_verify_file": {
        "addr": 0x13a0,
        "purpose": "Read file from filesystem and optionally verify signature",
    },
    "dim_core_sig_init": {
        "addr": 0x1540,
        "purpose": "Load X.509 certificate for signature verification",
    },
    "dim_core_destroy_fs": {
        "addr": 0x0570,
        "purpose": "Remove dim securityfs entries",
    },
    "dim_core_create_fs": {
        "addr": 0x05b0,
        "purpose": "Create securityfs/dim/ directory with control and log files",
    },
    "dim_mem_pool_init": {
        "addr": 0x0750,
        "purpose": "Initialize DIM custom memory pool (slab-like allocator)",
    },
    "dim_mem_pool_alloc": {
        "addr": 0x0870,
        "purpose": "Allocate from DIM memory pool",
    },
    "measure_work_cb": {
        "addr": 0x0b00,
        "purpose": "Work queue callback for periodic measurement",
        "scheduling": (
            "measure_interval (min) × 0xdf8475800 (nanoseconds multiplier) "
            "= scheduling period in nanoseconds for queue_delayed_work"
        ),
    },
    "dim_core_measure_blocking": {
        "addr": 0x0cf0,
        "purpose": "Synchronous (blocking) measurement trigger",
    },
    "dim_core_baseline_blocking": {
        "addr": 0x0d90,
        "purpose": "Synchronous (blocking) baseline initialization trigger",
    },
}

POLICY_FORMAT = {
    "prefix": "Each policy line must start with a recognized prefix",
    "types": {
        "KERNEL_TEXT": "No additional parameters required",
        "MODULE_TEXT": "name=<module_name> (path ignored; action ignored)",
        "BPRM_TEXT": "path=<executable_path> (name ignored for path; action= for kill)",
    },
    "parse_functions": ["dim_core parse policy key and value", "failed to parse policy at line %d"],
    "limit": "Max policy items; 'more than %d policy items will be ignored'",
}

BASELINE_FORMAT = {
    "fields": ["prefix", "type", "algorithm", "digest", "name"],
    "validation": [
        "invalid baseline prefix at line %d",
        "invalid baseline type at line %d",
        "invalid baseline algo at line %d",
        "invalid baseline digest at line %d",
        "no baseline name at line %d",
        "invalid baseline name at line %d",
    ],
    "signature": "Optional PKCS7/X.509 signature verification before parsing",
}

FILESYSTEM_INTERFACE = {
    "root": "/sys/kernel/security/dim/ (securityfs)",
    "files": {
        "measure_log": {
            "read": "measure_log_read_{start,next,stop,show} — seq_file interface",
            "open": "dim_measure_log_open",
            "content": "One entry per measured object: hash + name",
        },
        "tampered_action": {
            "read": "dim_tampered_action_read",
            "write": "dim_tampered_action_write — set action on mismatch",
            "values": "log | kill",
        },
        "interval": {
            "read": "dim_interval_read",
            "write": "dim_interval_write — set measure_interval",
        },
        "status": {
            "read": "dim_status_read — print current DIM status",
        },
        "measure_trigger": {
            "write": "dim_measure_trigger — trigger immediate measurement",
        },
        "baseline_init_trigger": {
            "write": "dim_baseline_init_trigger — trigger baseline initialization",
        },
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "integrity=dim cmdline required — DIM silently does not start without it",
        "detail": (
            "dim_core_init checks for 'integrity=dim' in kernel cmdline. "
            "If not present, logs KERN_ERR 'boot parameter integrity=dim not set' and returns -EINVAL. "
            "On a TOS system where dim_core is in initramfs but the kernel cmdline lacks integrity=dim, "
            "DIM never initializes — no measurement, no baseline, no kill action. "
            "The module loads successfully (init_module returns 0), "
            "but all security functions are absent. "
            "Operators who add dim_core to the module list without updating the cmdline "
            "believe DIM is active when it is not."
        ),
        "required_cmdline": "integrity=dim",
        "silent_failure": "No dmesg log for successful boot without the parameter",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "kill_task() won't kill PID 1 — an init process that loads malicious code is untouchable",
        "detail": (
            "kill_task() explicitly skips PID 1 ('the pid of tampered task is 1, don't kill it'). "
            "If systemd (PID 1) loads a malicious shared library into its address space, "
            "or if a tampered binary is exec'd as PID 1 during boot, "
            "DIM detects the mismatch but cannot kill the process. "
            "It logs the alert and continues. "
            "An attacker who achieves code execution in PID 1 (e.g., via LD_PRELOAD in systemd) "
            "is permanently immune to DIM's kill action."
        ),
        "pid1_exemption": True,
        "also_exempted": "current process (self-kill prevention)",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Dynamic baseline race: first measurement = baseline; attacker present before baseline init can register malicious code",
        "detail": (
            "Dynamic baselines are built from the first measurement. "
            "baseline_work_cb logs 'no baseline, do baseline init instead' and builds "
            "the baseline from the current system state. "
            "If an attacker loads a rootkit before dim_core is loaded (or before measure_interval fires), "
            "the rootkit's code pages become part of the 'good' baseline. "
            "DIM then permanently considers the rootkit as trusted. "
            "measure_interval default is unknown (module parameter, not visible in binary), "
            "but if measurement doesn't happen immediately at load time, "
            "there is a window for baseline poisoning."
        ),
        "attack": "Load rootkit → load dim_core with dynamic baseline → rootkit is in the baseline",
        "static_baseline": "Partially mitigates this — but requires pre-computed, signed hash files",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "dim_core_kallsyms_init: 8 kernel symbols via kprobe trick — full kernel function table built privately",
        "detail": (
            "DIM resolves 8 unexported kernel symbols at init time using the kprobe trick. "
            "These pointers are stored in BSS — accessible to anyone who can read kernel memory. "
            "The 8 symbols are critical kernel functions (likely: security_inode_read, "
            "get_fs_root, mm_access, kernel_text_*). "
            "An attacker with read access to BSS (via /proc/kcore, eBPF, or another vuln) "
            "gets a partial kernel symbol table from DIM's private cache, "
            "defeating KASLR for those 8 symbols without needing kallsyms. "
            "More importantly: DIM's own use of kprobes means registering a kprobe "
            "on these symbols could interfere with DIM's measurements "
            "(Insight from aegis: kprobe on a measured function = measurement includes the kprobe handler)."
        ),
        "symbols_cached_in_bss": 8,
        "kaslr_leakage": "8 kernel function addresses in BSS, readable via privileged memory access",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "measure_process_module_text_vma — user process module text measured separately; JIT-generated code not covered",
        "detail": (
            "measure_process_module_text_vma at 0x2a60 handles VMAs from loaded .so files "
            "in a user process. "
            "JIT-compiled code (Java, JavaScript V8, LLVM JIT, BPF JIT) creates anonymous "
            "executable VMAs that are not backed by a file. "
            "dim_vm_hash_calculate_vma measures VMA contents by reading page contents. "
            "JIT pages change on every JVM invocation — their hash changes every run. "
            "Either DIM has a JIT exemption (and an attacker can stage malicious code "
            "in a JIT-like anonymous executable VMA), or DIM triggers false positives "
            "on every JIT-heavy workload (Kafka, Elasticsearch, etc.)."
        ),
        "jit_code": "Anonymous executable VMAs — JVM, V8, eBPF JIT — not file-backed",
        "impact": "Either JIT exempted (bypass) or constant false positives on JIT workloads",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "signature=bool default unknown — policy/baseline can be unsigned if not set",
        "detail": (
            "The signature parameter controls whether policy and static baseline files "
            "must be signed. Default not visible in binary (module parameter default). "
            "If signature=N (or default off), anyone with write access to the baseline "
            "or policy filesystem path can inject arbitrary measurement rules. "
            "A policy that adds malicious binaries to a baseline, or removes KERNEL_TEXT "
            "from measurement scope, requires only write access to the policy file — "
            "not kernel privileges. "
            "The path for policy and baseline files is read via read_file_root (root filesystem path)."
        ),
        "sensitive_files": ["policy file", "static baseline file", "DIM cert file"],
    },
    {
        "id": "F7",
        "severity": "MEDIUM",
        "title": "TPM PCR extension not verified — measure_pcr could extend wrong PCR, corrupting attestation",
        "detail": (
            "measure_pcr parameter selects which TPM PCR to extend measurement values into. "
            "There is no validation visible that measure_pcr is a valid/reserved PCR index. "
            "PCRs 0-7 are used by firmware (UEFI/BIOS). PCR 11 is used by systemd-boot. "
            "If measure_pcr is set to an already-used PCR (e.g., 0), "
            "DIM's extension corrupts that PCR's value — "
            "the TPM's attestation quote for that PCR becomes meaningless. "
            "Remote attestation (IMA attestation, TPM quote) on the affected PCR would fail. "
            "This is a configuration issue but has no enforcement in the module."
        ),
        "dangerous_pcr_values": [0, 1, 2, 3, 4, 5, 6, 7, 11],
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "DIM memory pool (dim_mem_pool_*) — custom slab allocator for measurement data",
        "detail": (
            "dim_mem_pool_init/alloc/free/destroy implement a chunked memory pool. "
            "dim_mem_pool_walk_chunk iterates chunks; free_chunk frees individual chunks. "
            "dim_mem_pool_expand allocates new chunks when the pool is exhausted. "
            "This is a custom allocator (rather than kmalloc) — likely because measurement "
            "data has predictable sizes and high-frequency allocation, "
            "and the module author wanted to avoid kmalloc fragmentation. "
            "Memory leak is detected at destroy time: "
            "'dim_mem_pool_destroy failed, memory leak detected'."
        ),
        "custom_allocator": True,
        "leak_detection": "dim_mem_pool_destroy — logs if pool is not fully freed",
    },
]

if __name__ == '__main__':
    print("dim_core.ko (TOS 4.6) RE analysis")
    print()
    print("Measurement targets:")
    for target, info in ARCHITECTURE['measurement_targets'].items():
        print(f"  {target}: {info['measures']}")
    print()
    print("Securityfs interface: /sys/kernel/security/dim/")
    for fname, info in FILESYSTEM_INTERFACE['files'].items():
        print(f"  {fname}: {info.get('values', info.get('content', '?'))[:50]}")
    print()
    print("Boot requirement:", METADATA['boot_requirement'])
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
