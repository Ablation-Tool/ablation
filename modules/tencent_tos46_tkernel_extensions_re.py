"""
TencentOS 4.6 — tkernel extension kernel modules reverse engineering.

Modules under /usr/lib/modules/6.6.119-51.3.tl4.x86_64/kernel/kernel/tkernel/:
  async-fork/async-fork.ko.xz   (83KB, GPL v2)
  emm/emm_coreutils.ko.xz       (25KB, GPL)
  emm/emm_extentions.ko.xz      (23KB, GPL)
  emm/emm_zram.ko.xz            (209KB, Dual BSD/GPL)
  irqlatency/irqlatency.ko.xz   (40KB, GPL v2)

All signed by 'Tkernel signing key' (01:9D:01:14:84:D7, sha256).
All NOT stripped — full symbol tables present.

These are TOS-specific kernel extensions not present in upstream Linux 6.6.
"""

METADATA = {
    "signer": "Tkernel signing key",
    "sig_key_fingerprint": "01:9D:01:14:84:D7",
    "vermagic": "6.6.119-51.3.tl4.x86_64 SMP mod_unload modversions",
    "all_stripped": False,
}

ASYNC_FORK = {
    "module": "async_fork",
    "source": "kernel/tkernel/async-fork/async_fork.c",
    "size_bytes": 83 * 1024,
    "purpose": (
        "Deferred page table copy during fork(). "
        "Instead of copying all PMD/PTE entries synchronously at fork() time "
        "(which blocks both parent and child), async-fork marks the parent mm_struct "
        "with an 'async fork pending' bit and defers PTE copying to background work. "
        "The child process starts running immediately while the page table copy completes."
    ),
    "mm_struct_async_bit": {
        "offset": "0x558",
        "bit": 0,
        "instruction": "lock bts QWORD PTR [rbx+0x558], 0x0",
        "note": (
            "TOS-specific field in mm_struct at offset 0x558. "
            "Not present in upstream Linux 6.6 mm_struct. "
            "This offset is injected by TOS kernel patches. "
            "Knowledge of this offset is required to interact with async-fork "
            "from other modules."
        ),
    },
    "ops_struct": {
        "async_fork_ops": "Pluggable operations struct for async fork implementation",
        "dummy_async_fork_ops": "No-op stub when async fork is disabled",
        "security_note": (
            "The ops structure pointer could be a target for kernel exploitation. "
            "If a write primitive exists to async_fork_ops, "
            "arbitrary function pointers can be installed in the fork path."
        ),
    },
    "external_imports": [
        "copy_huge_pmd",
        "copy_huge_pud",
        "copy_hugetlb_page_range",
        "copy_pte_range_atom",
        "folio_prealloc",
        "kill_pid",
        "__mmu_notifier_invalidate_range_start/end",
        "klp_sched_try_switch",
    ],
    "key_functions": {
        "asfk_prepare": {
            "addr": "0x24e0",
            "desc": "Marks mm_struct async-fork-pending via atomic lock bts at mm+0x558",
        },
        "asfk_fast": {
            "desc": "Fast path: defer PMD copy, child runs with lazily populated page tables",
        },
        "asfk_rest": {
            "desc": "Completion path: actual PMD/PTE copy after child starts",
        },
        "__async_fork_fallback": {
            "addr": "0x2590",
            "desc": "Falls back to synchronous fork on error (e.g., huge page copy failure)",
        },
        "asfk_fixup_pmd": {
            "desc": "Fixes PMD entries after lazy copy — handles THP/COW race",
        },
    },
    "log_strings": [
        "child async fork success, mm=%pK, oldmm=%pK",
        "vma not founded for addr:%08lx",
        "pte copied in %lx-%lx mm=%pK",
        "async fork fallback in pmd fix, oldmm=%pK",
        "pmd is already made async fork pmd=%lx",
    ],
}

EMM_COREUTILS = {
    "module": "emm_coreutils",
    "description": "EMM: memmory management interface extention",
    "source": "emm_coreutils (TOS extended memory management)",
    "size_bytes": 25 * 1024,
    "purpose": (
        "Extended cgroup memory controller with workingset statistics. "
        "Adds refault distance tracking at 1m/10m/30m rolling windows, "
        "watermark tracking, and valid eviction counters to the memcg interface. "
        "Exports as cgroup files alongside standard memory.stat."
    ),
    "cgroup_files": {
        "legacy": "emm_memcg_legacy_files",
        "dfl": "emm_memcg_dfl_files",
    },
    "key_functions": {
        "evict_eval_work": "Async workqueue handler for page eviction evaluation",
        "mem_cgroup_workingset_read": "Reads extended workingset stats from cgroup",
        "__emm_memcg_core_opsa": "Core memory cgroup ops adapter (TOS extension point)",
    },
    "workingset_metrics": [
        "workingset_refault_distance_last",
        "workingset_refault_distance_avg_1m",
        "workingset_refault_distance_avg_10m",
        "workingset_refault_distance_avg_30m",
        "workingset_watermark_last",
        "workingset_watermark_avg_1m",
        "workingset_watermark_avg_10m",
        "workingset_watermark_avg_30m",
        "workingset_valid_eviction_last",
        "workingset_valid_eviction_avg_1m",
        "workingset_valid_eviction_avg_10m",
        "workingset_valid_eviction_avg_30m",
    ],
    "note": "Description has typo 'memmory' — confirms internal TOS codebase without external review",
}

EMM_EXTENTIONS = {
    "module": "emm_extentions",
    "description": "EMM: memmory management interface extention",
    "source": "emm_extentions (TOS MGLRU and swappiness extensions)",
    "size_bytes": 23 * 1024,
    "purpose": (
        "Extended cgroup memory interface — MGLRU (Multi-Gen LRU) EMM integration "
        "and per-cgroup swappiness control via traverse write interface. "
        "Adds memory.swappiness write support with cgroup hierarchy traversal."
    ),
    "key_functions": {
        "mem_cgroup_swappiness_read": "Reads per-cgroup swappiness value",
        "mem_cgroup_swappiness_traverse_write": (
            "Writes swappiness to cgroup and traverses hierarchy. "
            "Traverse pattern: walks parent-to-child cgroup tree — "
            "if input validation is weak, may allow swappiness out of 0-200 range."
        ),
        "memcg_lru_gen_emm_show": "MGLRU per-cgroup stats via EMM interface",
        "mem_cgroup_emm_run": "Main EMM cgroup control dispatch",
        "page_counter_memparse": "Parses memory limit strings (e.g. '4G', '512M')",
    },
    "note": "Same 'memmory' typo as emm_coreutils — same developer, same code origin",
}

EMM_ZRAM = {
    "module": "emm_zram",
    "description": "Compressed RAM Block Device",
    "license": "Dual BSD/GPL",
    "size_bytes": 209 * 1024,
    "purpose": (
        "TOS's extended ZRAM implementation with BPF tracepoints and multiple "
        "compression algorithms. Fork of upstream zram with TOS-specific extensions "
        "including hot-add/remove of zram devices and 842 compression algorithm."
    ),
    "module_params": {
        "num_devices": "Number of pre-created zram devices (uint)",
    },
    "bpf_tracepoints": [
        "__bpf_trace_zram_write_page",
        "__bpf_trace_zram_read_from_zspool",
        "__bpf_trace_zram_free_page",
        "__bpf_trace_tp_map_zram_write_page",
        "__bpf_trace_tp_map_zram_read_from_zspool",
        "__bpf_trace_tp_map_zram_free_page",
    ],
    "compression_algorithms": ["842", "deflate"],
    "hot_plug": {
        "class_attr_hot_add": "Sysfs handler: dynamically add a zram device",
        "class_attr_hot_remove": "Sysfs handler: dynamically remove a zram device",
        "security_note": (
            "Hot-add/remove via sysfs requires CAP_SYS_ADMIN. "
            "The hot_remove path must properly quiesce all I/O before device removal; "
            "a race condition in removal could cause use-after-free on in-flight I/O."
        ),
    },
    "key_functions": {
        "algorithm_params_store": "Sysfs write handler for compression algorithm parameters",
        "comp_algorithm_show": "Sysfs read for current compression algorithm",
        "__comp_algorithm_store": "Sets compression algorithm after validating device state",
        "compress_842": "842 compression implementation",
        "decompress_842": "842 decompression implementation",
        "create_842": "Creates 842 compression context",
        "debug_stat_show": "Per-device debug statistics via sysfs",
    },
}

IRQLATENCY = {
    "module": "irqlatency",
    "source": "kernel/tkernel/irqlatency/irqlatency.c",
    "size_bytes": 40 * 1024,
    "purpose": (
        "IRQ disable and softirq disable latency measurement module. "
        "Uses high-resolution timers to measure how long IRQs or softirqs "
        "remain disabled, captures kernel stacks at latency events, "
        "and provides latency distribution histograms via debugfs/procfs."
    ),
    "sysfs_interface": {
        "enable": "Toggle latency monitoring (write 0/1)",
        "freq_ms": "Sampling frequency in milliseconds",
        "latency_thresh_ms": "Threshold above which events are recorded",
    },
    "key_functions": {
        "irq_hrtimer_func": "hrtimer callback measuring hardirq disable duration",
        "softirq_timer_func": "hrtimer callback measuring softirq disable duration",
        "record_latency": "Records latency sample with timestamp and stack trace",
        "save_stack.isra.0": "Captures kernel stack trace at latency event",
        "reset_latency_trace": "Clears all accumulated latency data",
        "percpu_timers_start": "Initializes per-CPU hrtimers for latency tracking",
        "latency_timers_stop": "Stops all per-CPU hrtimers",
    },
    "output_format": [
        "latency distribution",
        "irq-disable: <histogram>",
        "softirq-disable: <histogram>",
        "irq_latency_ms: %llu",
        " irq: <stack>",
        " softirq: <stack>",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "async-fork mm_struct offset 0x558 bit 0 — TOS-specific field injected into kernel struct",
        "detail": (
            "async-fork writes to mm_struct at offset 0x558, bit 0 via 'lock bts'. "
            "This field is NOT in upstream Linux 6.6 mm_struct — it is injected by TOS "
            "kernel patches. Any code that iterates over mm_struct fields (e.g., GDB, "
            "crash dump analysis, kernel modules expecting upstream layout) will mis-parse "
            "mm_struct on TOS 4.6 kernels. "
            "A kernel exploit targeting mm_struct overwrite must account for this "
            "TOS-specific field layout to avoid corrupting the async-fork state bit."
        ),
        "mm_struct_offset": "0x558",
        "upstream_divergence": True,
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "async-fork pluggable ops struct pointer — potential function pointer overwrite target",
        "detail": (
            "async_fork_ops and dummy_async_fork_ops are global operation structs. "
            "The active ops are selected at init time and used throughout the fork path. "
            "With a kernel write primitive at the async_fork_ops address "
            "(obtainable via /proc/kallsyms if not locked down), "
            "function pointers in the struct can be replaced to redirect fork() "
            "execution to attacker-controlled code at next fork()."
        ),
        "symbol": "async_fork_ops",
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "async-fork deferred copy creates a race window: child runs with incompletely copied page tables",
        "detail": (
            "The core async-fork design: child process starts executing before PMD/PTE "
            "copy completes. During this window, the child's address space references "
            "the parent's page tables with a 'pending' flag. "
            "If the child accesses a page whose PTE has not yet been lazily copied, "
            "asfk_fixup_pmd/asfk_fixup_vma handles the fault. "
            "A use-after-free or race in asfk_fixup_pmd during this window "
            "could corrupt both parent and child page tables, "
            "as both share physical pages with different reference counts."
        ),
        "race_window": "Between fork() return and asfk_rest completion",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "irqlatency save_stack records kernel addresses — KASLR bypass via world-readable output",
        "detail": (
            "irqlatency's record_latency calls save_stack.isra.0 to capture the kernel "
            "call stack at latency events. The stack is output via lat_show (sysfs read). "
            "Stack output includes kernel text addresses (e.g. 'irq: <addr> <addr> ...'). "
            "If /sys/kernel/debug/irqlatency/ or the irqlatency sysfs entry is world-readable "
            "(depends on mount options), any local user can read kernel addresses and "
            "defeat KASLR without requiring any exploit or elevated privilege."
        ),
        "output_path": "/sys/kernel/debug/irqlatency/ (or equivalent)",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "emm_zram hot-remove race: removal while I/O in flight may cause UAF",
        "detail": (
            "class_attr_hot_remove allows runtime removal of a zram device via sysfs write. "
            "If I/O is in flight against the device during removal "
            "(bio_list or request_queue not fully drained), "
            "the device structure can be freed while a bio completion callback "
            "still holds a reference to the freed zram_dev. "
            "The hot-remove path in TOS's emm_zram may not call blk_sync_queue() "
            "before freeing — needs live kernel testing to confirm."
        ),
        "sysfs_path": "/sys/class/zram-control/hot_remove",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "emm_coreutils/emm_extentions: 'memmory' typo in description — same developer, unreviewed code",
        "detail": (
            "Both emm_coreutils and emm_extentions have description string: "
            "'EMM: memmory management interface extention.' "
            "Two independent spelling errors ('memmory' vs 'memory', 'extention' vs 'extension') "
            "in a security-critical kernel module description indicates "
            "limited external code review. "
            "Consistent typos across two modules suggest the same developer wrote both "
            "without review — the security posture of internal code is unverified."
        ),
        "typos": ["memmory (×2)", "extention (×2)"],
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "All tkernel modules share the same Tkernel signing key — single key compromise affects all",
        "detail": (
            "All five tkernel modules are signed by 'Tkernel signing key' (01:9D:01:14:84:D7). "
            "A single key signs: async-fork, emm_coreutils, emm_extentions, emm_zram, "
            "irqlatency, kill_protect, kill_block, dim_core, dim_monitor. "
            "If the private key for 01:9D:01:14:84:D7 is extracted (from a TOS build server, "
            "SRPM with key material, or insider access), any kernel module can be signed "
            "and loaded on any TOS 4.6 system with Secure Boot trusting this key."
        ),
        "affected_modules": [
            "async-fork", "emm_coreutils", "emm_extentions", "emm_zram",
            "irqlatency", "kill_protect", "kill_block", "dim_core", "dim_monitor",
        ],
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "emm_extentions mem_cgroup_swappiness_traverse_write — per-cgroup swappiness hierarchy write",
        "detail": (
            "mem_cgroup_swappiness_traverse_write at writes swappiness to a cgroup "
            "and traverses the cgroup hierarchy. Swappiness controls the relative weight "
            "of anon vs file pages in reclaim (0-200 range). "
            "A privileged cgroup admin can set swappiness to 0 in a container, "
            "suppressing swap usage for that subtree. "
            "The traverse write (writing to parent applies to all children) "
            "requires careful bounds checking to avoid integer overflow on the traverse count."
        ),
    },
]

if __name__ == '__main__':
    mods = {
        "async_fork": ASYNC_FORK,
        "emm_coreutils": EMM_COREUTILS,
        "emm_extentions": EMM_EXTENTIONS,
        "emm_zram": EMM_ZRAM,
        "irqlatency": IRQLATENCY,
    }
    print(f"TOS 4.6 tkernel extensions — {len(mods)} modules, {len(FINDINGS)} findings")
    for name, m in mods.items():
        print(f"  {name}: {m.get('purpose', m.get('desc', ''))[:60]}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
