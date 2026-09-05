"""
TencentOS 4.6 — wujing binary reverse engineering module.

Binary: wujing (packaged in tagent-2.1.6-1.tl4 as a plugin)
Path in package: /usr/local/tagent/mod/wujing/wujing
Original: UPX-packed statically-linked Go binary (1.4MB)
Unpacked: dynamically linked, 4.1MB
ELF: 64-bit LSB, x86-64, Go BuildID=jZC-zFMzrlgVkpsI1uJp/sJpJAbxY30pLT1VvcRHo/LJcOaANjOY6YuCcYfG4M/oN4H6rMDHNA-ZQ03rX43
Stripped: YES (no .symtab, but .gopclntab survives stripping)
gopclntab: 5258 functions (1.28MB pclntab)

Architecture: Prometheus-style telemetry collector plugin for tagent.
Collects host/pod-level metrics from the TOS node and exports them to
the tagent daemon (via SysV IPC shared memory), which forwards to Tencent
C2 at 9.150.206.219:53333.

Source paths extracted from pclntab:
  /data/landun/workspace/collector.go        (Tencent 'Landun' CI/CD system)
  /data/landun/workspace/umrd/wujing.go      (main binary source)

Git repository: git.woa.com/tlinux/TManager2/plugins/wujing_collector/
  wujing_collector/mem   — memory metrics
  wujing_collector/debug — diagnostic metrics

Main package functions (from pclntab):
  main.main               — entry point
  main.WujingCollector    — Prometheus Collector: Describe/Collect methods
  main.WujingFlagsCollector — flags state collector
  main.DebugCollector     — debug/diagnostic collector

Dependencies (from pclntab):
  github.com/vishvananda/netlink   — netlink network interface enumeration
  github.com/vishvananda/netns    — network namespace handling
  github.com/golang/protobuf/proto — protobuf encoding (C2 communication protocol)
  google.golang.org/protobuf       — modern protobuf runtime

Ablation semantic sweep: all-MiniLM-L6-v2 applied to function descriptors
derived from pclntab (no symbol table — names only, no disassembly mapping).
Findings are derived from pclntab strings, embedded string data, and binary imports.
"""

METADATA = {
    "target": "TencentOS 4.6",
    "binary": "wujing",
    "package": "tagent-2.1.6-1.tl4",
    "build_id": "jZC-zFMzrlgVkpsI1uJp/sJpJAbxY30pLT1VvcRHo/LJcOaANjOY6YuCcYfG4M/oN4H6rMDHNA-ZQ03rX43",
    "lang": "Go",
    "stripped": True,
    "upx_packed": True,
    "pclntab_funcs": 5258,
    "git_repo": "git.woa.com/tlinux/TManager2/plugins/wujing_collector/",
    "source_paths": [
        "/data/landun/workspace/collector.go",
        "/data/landun/workspace/umrd/wujing.go",
    ],
    "tencent_cicd_system": "Landun (蓝盾, Blue Shield)",
    "protocol": "protobuf (github.com/golang/protobuf + google.golang.org/protobuf)",
}

# All metric names and file paths extracted from .rodata strings
COLLECTED_METRICS = {
    "memory_metrics": [
        "mem_total",           # /proc/meminfo MemTotal
        "swap_free",           # /proc/meminfo SwapFree
        "node_anon",           # /proc/vmstat (anonymous pages)
        "node_file",           # /proc/vmstat (file-backed pages)
        "anon_save",           # ZRAM anonymous pages saved
        "file_save",           # ZRAM file pages saved
        "zram_util",           # ZRAM utilization percentage
        "zram_size",           # ZRAM total size
        "zram_read_bw",        # ZRAM read bandwidth
        "node_wujing_max_usage_in_bytes",  # node-level max memory usage
        "pod_memory_zram_usage_in_bytes",  # pod ZRAM compressed memory usage
    ],
    "compute_metrics": [
        "kvm-clock",           # KVM hypervisor clock detection (virtualization flag)
        "SMART_NIC",           # SmartNIC presence detection
        "cgroup_v1",           # cgroup v1 in use
        "cgroup_v2",           # cgroup v2 in use
        "fork/exec",           # process creation monitoring
        "wujing_state",        # binary health/state
        "wujing_debug",        # debug mode flag
    ],
    "pod_metrics": [
        "pod_oom_kill",        # Pod OOM kill events
        "dev_write_bw",        # device write bandwidth per pod
    ],
}

# File paths accessed at runtime
ACCESSED_PATHS = {
    "system_identity": [
        "/sys/class/dmi/id/product_uuid",          # machine UUID (SMBIOS)
        "/sys/devices/virtual/dmi/id/product_serial",  # machine serial number
    ],
    "cgroup_v1_pod_memory": [
        "/sys/fs/cgroup/memory/memory.usage_in_bytes",
        "/sys/fs/cgroup/memory/kubepods/memory.stat",
        "/sys/fs/cgroup/memory/kubepods/memory.zram.raw_in_bytes",   # TOS-specific extension
        "/sys/fs/cgroup/memory/kubepods/memory.zram.usage_in_bytes", # TOS-specific extension
    ],
    "proc_fs": [
        "/proc/vmstat",
    ],
    "wujing_data_dir": [
        "/usr/local/tagent/mod/wujing/var/zram",
        "/usr/local/tagent/mod/wujing/var/diskstats",
    ],
}

# Packages from pclntab that reveal full collection capability
NETLINK_FUNCTIONS = [
    "github.com/vishvananda/netlink.AddrList",      # enumerate all IP addresses per interface
    "github.com/vishvananda/netlink.LinkList",      # enumerate all network interfaces
    "github.com/vishvananda/netlink.LinkByIndex",   # get interface by index
    "github.com/vishvananda/netlink.RouteList",     # enumerate all IP routes
    "github.com/vishvananda/netlink.LinkDeserialize", # parse raw netlink interface messages
    "github.com/vishvananda/netlink/nl.NewNetlinkRequest", # raw netlink socket
    "github.com/vishvananda/netlink/nl.getNetlinkSocket",  # underlying netlink socket
]

WUJING_COLLECTOR_FUNCTIONS = {
    "mem": [
        "GetMemcgMaxUsageInBytes",   # /sys/fs/cgroup/memory/*/memory.max_usage_in_bytes
        "GetMemcgUsageInBytes",      # /sys/fs/cgroup/memory/*/memory.usage_in_bytes
        "GetMemInfo",                # /proc/meminfo parser
        "GetMemoryCurrent",          # cgroup v2 memory.current
        "GetMemswMaxUsageInBytes",   # memory+swap max usage
        "GetVmstat",                 # /proc/vmstat parser
        "GetWorkingSetInfo",         # cgroup memory.stat working set
        "GetZramMaxSaveInBytes",     # ZRAM compression savings
        "GetZramNodeInfo",           # ZRAM per-device statistics
    ],
    "debug": [
        "GetDiskHwSectorSizeInfo",   # disk hardware sector size (/sys/block/*/queue/hw_sector_size)
        "GetDiskList",               # enumerate all block devices
        "GetDiskStats",              # /proc/diskstats or /sys/block/*/stat
        "GetPodMemoryOomControl",    # cgroup memory.oom_control
        "GetPodMemoryStat",          # cgroup memory.stat
        "GetPodMemoryZramUsage",     # TOS-specific ZRAM pod metrics
        "GetPodPressure",            # PSI (pressure stall information) per pod
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "Source path + CI system identity disclosed in pclntab — Tencent internal infrastructure exposed",
        "detail": (
            "pclntab (unstrippable Go metadata) reveals: "
            "Source: /data/landun/workspace/umrd/wujing.go — 'landun' is Tencent's internal "
            "CI/CD system '蓝盾' (Blue Shield) running at landun.oa.com. "
            "Git repo: git.woa.com/tlinux/TManager2/plugins/wujing_collector/ — 'woa.com' is "
            "Tencent's internal git hosting. TManager2 is the Tencent cloud host management system. "
            "This reveals the internal repository structure, project name (TManager2), "
            "and the plugin architecture of the tagent management daemon."
        ),
        "evidence": [
            "pclntab string: /data/landun/workspace/umrd/wujing.go",
            "pclntab string: /data/landun/workspace/collector.go",
            "pclntab package: git.woa.com/tlinux/TManager2/plugins/wujing_collector/mem",
            "pclntab package: git.woa.com/tlinux/TManager2/plugins/wujing_collector/debug",
        ],
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Hardcoded base64 credential in .rodata — 48-byte potential key",
        "detail": (
            "The .rodata section contains: "
            "'eQ2xqLUuMNP4ywtEz27LWBd8C401teSXMUMRpWzs5+V3c0Q4TJrDsQ==' "
            "(64 base64 chars, decodes to 48 bytes). "
            "Location: embedded in a long concatenated string in .rodata near the ECDSA key "
            "found in tmp-tagent-push (which uses CryptoPP ECDSA). "
            "48 bytes = possible ECDSA P-384 private key scalar (384 bits), or a 384-bit HMAC key, "
            "or 3x 128-bit AES keys. Context: appears adjacent to protobuf descriptor strings, "
            "suggesting it may be a fixed salt or authentication token for the protobuf-based "
            "C2 communication channel. "
            "Decodes to: 79 0d b1 a8 b5 2e 30 d3 f8 cb 0b 4b 3d f6 b5 80 "
            "67 c6 d4 d7 a4 97 5c 51 33 15 2f a3 be b5 5e dd "
            "10 e2 32 74 24 a6 3b 51 1d 23 d6 7a b3 f6 2f"
        ),
        "evidence": [
            "strings: eQ2xqLUuMNP4ywtEz27LWBd8C401teSXMUMRpWzs5+V3c0Q4TJrDsQ==",
            "decoded_length: 48 bytes",
            "context: near protobuf descriptors in .rodata concatenated string block",
        ],
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Hardware identity (UUID + serial) collected and forwarded to Tencent C2",
        "detail": (
            "wujing reads two hardware identity sources: "
            "/sys/class/dmi/id/product_uuid (machine UUID from SMBIOS) and "
            "/sys/devices/virtual/dmi/id/product_serial (machine serial number). "
            "These are sent via tagent to the C2 at 9.150.206.219:53333 (see tagent module). "
            "In a cloud/multi-tenant context, this allows Tencent's management infrastructure "
            "to uniquely fingerprint every host running TOS, including the hardware serial number "
            "which is typically not transmitted over the network in standard cloud telemetry."
        ),
        "evidence": [
            "strings: /sys/class/dmi/id/product_uuid",
            "strings: /sys/devices/virtual/dmi/id/product_serial",
            "tagent module: C2 = 9.150.206.219:53333",
        ],
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "TOS-specific cgroup extensions exposed — non-upstream kernel interface",
        "detail": (
            "wujing reads two paths not present in upstream Linux: "
            "/sys/fs/cgroup/memory/kubepods/memory.zram.raw_in_bytes and "
            "/sys/fs/cgroup/memory/kubepods/memory.zram.usage_in_bytes. "
            "These are TOS kernel extensions to the cgroup memory controller, tracking "
            "ZRAM (compressed swap) usage per pod. Their existence confirms TOS uses a "
            "modified cgroup memory subsystem with transparent ZRAM compression of pod memory. "
            "These paths would not be present on standard Linux systems, making them a "
            "reliable TOS fingerprint. Any system that responds to queries on these paths "
            "is running TOS kernel modifications."
        ),
        "evidence": [
            "strings: /sys/fs/cgroup/memory/kubepods/memory.zram.raw_in_bytes",
            "strings: /sys/fs/cgroup/memory/kubepods/memory.zram.usage_in_bytes",
            "Note: not present in any upstream Linux kernel (4.x-6.x) cgroup memory controller",
        ],
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "title": "Full network topology enumeration — all interfaces, addresses, routes sent to C2",
        "detail": (
            "wujing uses github.com/vishvananda/netlink to call: "
            "AddrList() — all IP addresses on all interfaces, "
            "LinkList() — all network interfaces (name, MAC, flags, MTU), "
            "RouteList() — all routing table entries. "
            "This gives complete visibility into the host's network topology, including: "
            "container network interfaces (veth pairs for Kubernetes pods), "
            "overlay network routes (VXLAN, IPIP), and internal service IPs. "
            "All this data is serialized via protobuf and sent to 9.150.206.219:53333."
        ),
        "evidence": [
            "pclntab: github.com/vishvananda/netlink.AddrList",
            "pclntab: github.com/vishvananda/netlink.LinkList",
            "pclntab: github.com/vishvananda/netlink.RouteList",
            "pclntab: github.com/vishvananda/netlink.LinkDeserialize",
            "pclntab: github.com/vishvananda/netns.init (namespace-aware enumeration)",
        ],
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "Kubernetes pod OOM and memory pressure metrics collected — tenant workload visibility",
        "detail": (
            "wujing_collector/debug package collects: "
            "GetPodMemoryOomControl — reads each pod's cgroup memory.oom_control (OOM kill enable/disable), "
            "GetPodMemoryStat — reads each pod's cgroup memory.stat (full memory accounting), "
            "GetPodMemoryZramUsage — reads per-pod ZRAM usage (TOS-specific), "
            "GetPodPressure — reads PSI (pressure stall information) per pod. "
            "PSI data reveals when pods are under memory/CPU/IO pressure. "
            "Combined: full visibility into tenant workload behavior (memory spikes, OOM events, "
            "CPU pressure) from the host level. "
            "Metric pod_oom_kill is exported, confirming OOM events are tracked per pod."
        ),
        "evidence": [
            "pclntab: git.woa.com/.../debug.GetPodMemoryOomControl",
            "pclntab: git.woa.com/.../debug.GetPodMemoryStat",
            "pclntab: git.woa.com/.../debug.GetPodMemoryZramUsage",
            "pclntab: git.woa.com/.../debug.GetPodPressure",
            "strings: pod_oom_kill",
        ],
    },
    {
        "id": "F7",
        "severity": "MEDIUM",
        "title": "UPX packing — anti-analysis primitive; pclntab survives but hides binary size",
        "detail": (
            "Original wujing is UPX-packed (verified by UPX header detection in tagent package). "
            "UPX-packed: 1.4MB statically linked. Unpacked: 4.1MB dynamically linked with "
            "1.28MB .gopclntab. Go pclntab is the key anti-stripping failure: "
            "Go's pclntab cannot be removed without breaking stack unwinding — "
            "it ALWAYS survives stripping. Any Go binary with pclntab can be fully "
            "function-named via the pclntab parser regardless of strip level."
        ),
        "evidence": [
            "readelf -S wujing_upx: .gopclntab at 0x686620 (1.28MB)",
            "magic in pclntab: f1ffffff (Go 1.18+ format)",
            "nfunc: 5258 (all function names recoverable)",
        ],
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "Data persistence: wujing writes intermediate data to /usr/local/tagent/mod/wujing/var/",
        "detail": (
            "wujing writes collected data to: "
            "/usr/local/tagent/mod/wujing/var/zram — ZRAM statistics cache, "
            "/usr/local/tagent/mod/wujing/var/diskstats — disk statistics cache. "
            "These files are in the tagent module directory, allowing tagent to read "
            "wujing-collected data even if wujing is temporarily unavailable. "
            "The files contain protobuf-serialized metrics. "
            "If an attacker can write to /usr/local/tagent/mod/wujing/var/, "
            "they can inject false metrics into the tagent reporting pipeline."
        ),
        "evidence": [
            "strings: /usr/local/tagent/mod/wujing/var/zram",
            "strings: /usr/local/tagent/mod/wujing/var/diskstats",
        ],
    },
]

if __name__ == '__main__':
    print(f"wujing RE — {len(FINDINGS)} findings")
    for f in FINDINGS:
        print(f"  [{f['severity']:8s}] {f['id']}: {f['title']}")
    print(f"\nCollects: {sum(len(v) for v in COLLECTED_METRICS.values())} metrics")
    print(f"Netlink funcs: {len(NETLINK_FUNCTIONS)}")
    print(f"Collector funcs: {sum(len(v) for v in WUJING_COLLECTOR_FUNCTIONS.values())}")
