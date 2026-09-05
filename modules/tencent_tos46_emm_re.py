"""
TencentOS 4.6 — EMM (Extended Memory Management) module suite RE.

Three-tier memory management framework:
  emm_coreutils.ko  (25422B) — memcg statistics extension (workingset moving averages)
  emm_extentions.ko (23134B) — memcg policy extension (swappiness, lru_gen reclaim)
  emm_zram.ko      (213942B) — modified ZRAM block driver (THP swap, BPF tracepoints)

Authors: Zeng Jingxiang <linuszeng@tencent.com>, Kairui Song <kasong@tencent.com>
Sources: kernel/tkernel/emm/{memcg,driver/block/zram}/
All three: kernel 6.6.119-51.3.tl4.x86_64 (TOS 4.6), intree:Y (incorrect for emm_zram)

EMM extends the Linux memory subsystem with:
1. Finer workingset statistics with exponential moving averages
2. Custom memcg reclaim paths (memcg_emm_reclaim, memcg_lru_gen_emm_reclaim)
3. THP-aware ZRAM swap with multi-algorithm compression
"""

METADATA = {
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "authors": ["Zeng Jingxiang <linuszeng@tencent.com>", "Kairui Song <kasong@tencent.com>"],
    "modules": {
        "emm_coreutils": {
            "size_bytes": 25422,
            "srcversion": "C95DFDF953E29D21374422B",
            "srcfile": "kernel/tkernel/emm/memcg/emm_coreutils.c",
            "description": "memcg statistics extension with workingset moving averages",
        },
        "emm_extentions": {
            "size_bytes": 23134,
            "srcversion": "D1596E4B1BA31D405E17374",
            "description": "memcg policy extension with swappiness and lru_gen reclaim",
        },
        "emm_zram": {
            "size_bytes": 213942,
            "srcfile": "kernel/tkernel/emm/driver/block/zram/zram_drv.c",
            "description": "Modified ZRAM driver with THP swap and BPF tracepoints",
            "compress_algorithms": ["842", "deflate", "lz4", "zstd"],
        },
    },
}

EMM_COREUTILS_ANALYSIS = {
    "purpose": "Extend memcg cgroup interface with workingset statistics and moving averages",
    "cgroup_interface": {
        "registered_via": ["cgroup_add_dfl_cftypes", "cgroup_add_legacy_cftypes"],
        "files": {
            "emm_memcg_dfl_files": "cgroup v2 (dfl) file array",
            "emm_memcg_legacy_files": "cgroup v1 (legacy) file array",
        },
    },
    "new_stats_per_memcg": {
        "workingset_refault_anon": "Anonymous pages refaulted from LRU",
        "workingset_refault_file": "File-backed pages refaulted from LRU",
        "workingset_activate_anon": "Anonymous pages promoted active",
        "workingset_activate_file": "File pages promoted active",
        "workingset_restore_anon": "Anonymous pages restored in shadow tree",
        "workingset_restore_file": "File pages restored in shadow tree",
        "workingset_nodereclaim": "Node-level reclaim events",
        "workingset_refault_distance_last": "Last refault distance",
        "workingset_refault_distance_avg_1m": "1-minute EMA of refault distance",
        "workingset_refault_distance_avg_10m": "10-minute EMA of refault distance",
        "workingset_refault_distance_avg_30m": "30-minute EMA of refault distance",
        "workingset_watermark_last": "Last workingset watermark",
        "workingset_watermark_avg_1m": "1-minute EMA of workingset watermark",
        "workingset_watermark_avg_10m": "10-minute EMA of workingset watermark",
        "workingset_watermark_avg_30m": "30-minute EMA of workingset watermark",
    },
    "moving_average_windows": [
        ("1m", "1-minute exponential moving average"),
        ("10m", "10-minute EMA"),
        ("30m", "30-minute EMA"),
    ],
    "imported_primitives": {
        "lruvec_page_state": "read per-node LRU vector page state",
        "memcg_page_state": "read memcg-level page state",
        "mem_cgroup_iter": "iterate over memcg hierarchy",
        "emm_init": "imported from unknown module — EMM framework init",
        "emm_exit": "imported from unknown module — EMM framework cleanup",
    },
    "evict_eval_work": {
        "type": "delayed_work (queue_delayed_work_on / system_wq)",
        "purpose": "Periodic evaluation of workingset eviction rates — updates moving averages",
        "avgs_work": "BSS: delayed_work struct for periodic average computation",
    },
}

EMM_EXTENTIONS_ANALYSIS = {
    "purpose": "Policy layer: per-memcg swappiness override + lru_gen-aware reclaim",
    "key_functions": {
        "mem_cgroup_emm_run": {
            "addr": 0x0300,
            "purpose": "Run EMM reclaim on a memcg: call memcg_emm_reclaim and memcg_lru_gen_emm_reclaim",
            "imports": ["memcg_emm_reclaim", "memcg_lru_gen_emm_reclaim"],
        },
        "memcg_lru_gen_emm_show": {
            "addr": 0x00c0,
            "purpose": "seq_printf output for lru_gen stats per-node per-memcg",
            "format": "'node %5d' followed by per-generation stats",
        },
        "mem_cgroup_swappiness_traverse_write": {
            "addr": 0x0050,
            "purpose": "Write swappiness value across memcg tree via traversal",
            "note": "Modifies swappiness for entire cgroup subtree in one operation",
        },
        "page_counter_memparse": {
            "addr": 0x0460,
            "purpose": "Parse memory size string (e.g., '512M') via memparse",
        },
    },
    "lru_gen_integration": {
        "import": "lru_gen_caps",
        "purpose": "LRU gen (MGLRU) capability flags — enables MGLRU-specific reclaim paths",
        "note": "MGLRU (Multi-Generational LRU) was merged upstream in 6.1; TOS extends it",
    },
    "cgroup_extension": {
        "files": "Adds swappiness control files to both dfl and legacy cgroup hierarchies",
        "swappiness_read": "mem_cgroup_swappiness_read — returns per-memcg swappiness",
        "swappiness_write": "mem_cgroup_swappiness_traverse_write — propagates to subtree",
        "global_swappiness": "vm_swappiness imported as reference for default value",
    },
}

EMM_ZRAM_ANALYSIS = {
    "purpose": "Modified ZRAM block driver with THP swap and enhanced monitoring",
    "key_additions_vs_upstream": [
        "THP (Transparent Huge Page) swap support — swap THP as unit, not broken into 4K pages",
        "BPF tracepoints: zram_free_page, zram_read_from_zspool, zram_write_page",
        "Multi-algorithm params via algorithm_params_store",
        "Hot-add/remove via class_attr_hot_add/hot_remove",
        "cgroup memory statistics integration (cgroup_rstat_flush, cgroup_memory_nokmem)",
    ],
    "thp_swap_stats": {
        "thp_swap_out": "Large folio (THP) swap out count",
        "thp_swap_out_fail": "THP swap out failures",
        "thp_swap_out_partial": "THP partially swapped (broken into subpages)",
        "thp_swap_in": "THP swap in (restore from ZRAM)",
        "thp_swap_in_fail": "THP swap in failures",
        "thp_swap_in_partial": "THP partially restored",
        "swap_out": "4K page swap out",
        "swap_in": "4K page swap in",
        "note": "Both THP and 4K stats tracked separately — upstream ZRAM only tracks 4K",
    },
    "compression_algorithms": {
        "842": {
            "functions": ["create_842", "destroy_842", "compress_842", "decompress_842"],
            "note": "IBM 842 hardware compression algorithm, software fallback",
        },
        "deflate": {
            "functions": [
                "deflate_create", "deflate_decompress", "deflate_compress",
                "deflate_destroy", "deflate_setup_params", "deflate_release_params",
            ],
            "note": "zlib deflate — better ratio than lz4, slower",
        },
    },
    "bpf_tracepoints": {
        "zram_write_page": "bpf_trace_run6 — triggered on page write to ZRAM",
        "zram_read_from_zspool": "bpf_trace_run7 — triggered on page read from zsmalloc pool",
        "zram_free_page": "bpf_trace_run3 — triggered on page free from ZRAM",
        "significance": (
            "BPF tracepoints allow eBPF programs to monitor ZRAM I/O without modifying "
            "the module. This enables live performance analysis of swap behavior "
            "using bpftrace or custom eBPF programs."
        ),
    },
    "block_device_interface": {
        "disk_allocation": "__blk_alloc_disk",
        "queue_limits": [
            "blk_queue_logical_block_size", "blk_queue_physical_block_size",
            "blk_queue_io_min", "blk_queue_io_opt",
            "blk_queue_max_discard_sectors", "blk_queue_max_write_zeroes_sectors",
        ],
        "io_accounting": ["bdev_start_io_acct", "bdev_end_io_acct", "bio_end_io_acct_remapped"],
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "emm_coreutils imports emm_init/emm_exit from unknown module — hidden dependency",
        "detail": (
            "emm_coreutils.ko imports `emm_init` and `emm_exit` from an unknown module. "
            "These are not kernel-exported symbols — they come from another EMM module "
            "not present in the scratchpad (possibly emm_core.ko or emm_base.ko). "
            "If the base module is not loaded before emm_coreutils, the module fails to load "
            "with an 'Unknown symbol' error. "
            "This creates a silent dependency: emm_coreutils's security/monitoring value "
            "depends on a module that may not be in the scratchpad — an incomplete picture "
            "of the EMM framework. "
            "The missing module likely contains the core EMM data structures and reclaim engine."
        ),
        "missing_dependency": "Module exporting emm_init/emm_exit (not found in scratchpad)",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "emm_extentions imports memcg_emm_reclaim — adds custom reclaim path outside standard LRU",
        "detail": (
            "emm_extentions calls memcg_emm_reclaim (imported) when mem_cgroup_emm_run is triggered. "
            "This is a TOS-specific reclaim function — not the standard try_to_free_mem_cgroup_pages. "
            "Custom reclaim paths that bypass the standard LRU can interact badly with: "
            "(1) memory.min/low protection — reclaim may target protected pages, "
            "(2) oom_score_adj — processes with low oom_score may still have pages reclaimed, "
            "(3) KASAN/SLUB debugging — custom reclaim skips sanitizer instrumentation. "
            "memcg_emm_reclaim and memcg_lru_gen_emm_reclaim are not in upstream — "
            "their semantics can only be determined by finding the module that exports them."
        ),
        "custom_reclaim_functions": ["memcg_emm_reclaim", "memcg_lru_gen_emm_reclaim"],
        "upstream_equivalent": None,
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "emm_zram THP swap — THP swap out to ZRAM compresses 2MB pages, one I/O failure corrupts THP",
        "detail": (
            "emm_zram adds thp_swap_out_partial — THP partially swapped. "
            "If THP swap-out fails midway (zram allocation failure, compression failure), "
            "the page is partially swapped: some 4K subpages in ZRAM, others still in RAM. "
            "This 'partial' state is tracked in thp_swap_out_partial. "
            "A THP with pages in both RAM and ZRAM during a concurrent memory pressure event "
            "could be double-freed or accessed while partially swapped — "
            "a potential use-after-swap race condition on partial THP swap-out. "
            "Upstream avoided this by not swapping THP as a unit."
        ),
        "race_scenario": "THP partial swap + concurrent memory pressure = potential use-after-swap",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "workingset_refault_distance moving averages — window-based anomaly detection not the design intent",
        "detail": (
            "emm_coreutils adds workingset_refault_distance_avg_1m/10m/30m per memcg. "
            "These moving averages measure the 'distance' between page eviction and refault — "
            "a proxy for working set fit: low distance = working set fits in memory, "
            "high distance = memory pressure. "
            "While useful for capacity planning, these stats can be read by any process "
            "that can read memcg cgroup files. "
            "An unprivileged process in a container can read its own memcg stats, "
            "gaining visibility into memory pressure trends — potentially useful for "
            "timing attacks (e.g., heap grooming: wait for low-refault-distance period)."
        ),
        "information_disclosed": "Per-memcg workingset refault distance with 1m/10m/30m averages",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "emm_zram BPF tracepoints — ZRAM I/O observable by any eBPF program with CAP_BPF",
        "detail": (
            "emm_zram registers three BPF tracepoints: zram_write_page, zram_read_from_zspool, zram_free_page. "
            "Any eBPF program with CAP_BPF (or CAP_SYS_ADMIN on older kernels) can attach to these. "
            "An eBPF program attached to zram_write_page observes: page address, cgroup, "
            "compression ratio, flags — for every page being swapped out. "
            "On a multi-tenant host where ZRAM is the swap device, "
            "a privileged tenant with CAP_BPF can observe swap patterns of all other tenants."
        ),
        "tracepoints": ["zram_write_page", "zram_read_from_zspool", "zram_free_page"],
        "attacker_capability": "CAP_BPF or CAP_SYS_ADMIN",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "emm_extentions swappiness traverse write — propagates swappiness to cgroup subtree",
        "detail": (
            "mem_cgroup_swappiness_traverse_write propagates a swappiness write to all "
            "descendant cgroups via mem_cgroup_iter. "
            "This is more powerful than upstream mem_cgroup_swappiness_write (per-cgroup only). "
            "An admin can set swappiness=0 on a parent cgroup to prevent any memory swapping "
            "in a pod's entire cgroup tree — effective memory pinning without mlock. "
            "On a Kubernetes node: kubectl exec + writing to /sys/fs/cgroup/.../memory.swappiness "
            "propagates to all pod containers in one write."
        ),
        "capability": "Subtree swappiness propagation — effective pinning alternative to mlock",
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "emm_zram hot-add/remove — runtime ZRAM device management without reboot",
        "detail": (
            "class_attr_hot_add and class_attr_hot_remove allow creating/destroying "
            "ZRAM devices at runtime. "
            "Upstream ZRAM also supports hot-add since 3.15, but emm_zram's version "
            "integrates with EMM's cgroup accounting (cgroup_rstat_flush, cgroup_memory_nokmem). "
            "Hot-add creates a new /dev/zramN with full cgroup memory tracking — "
            "each ZRAM device's memory usage is tracked per-memcg. "
            "This enables per-container swap quotas: each pod gets its own ZRAM device "
            "with memory charged to its memcg."
        ),
        "feature": "Per-cgroup ZRAM device with hot-add/remove + memcg accounting",
    },
]

if __name__ == '__main__':
    print("EMM module suite (TOS 4.6) RE analysis")
    print(f"Authors: {', '.join(METADATA['authors'])}")
    print()
    for name, info in METADATA['modules'].items():
        print(f"  {name}: {info['description']}")
    print()
    print("emm_coreutils workingset stats (per-memcg):")
    for stat in list(EMM_COREUTILS_ANALYSIS['new_stats_per_memcg'].keys())[:5]:
        print(f"  {stat}")
    print("  ...")
    print()
    print("emm_zram THP swap counters:")
    for stat in list(EMM_ZRAM_ANALYSIS['thp_swap_stats'].keys())[:6]:
        print(f"  {stat}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
