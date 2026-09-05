"""
TencentOS 3.3 — netatop.ko binary RE module.

netatop v0.7 — per-task network statistics via netfilter hooks.
Author: Gerlof Langeveld <gerlof.langeveld@atoptool.nl> (upstream atoptool project)
Source: kernel/kernel/tkernel/netatop/netatop.ko.xz (TOS 3.3)
Size: 36110B. Signed with TOS 3.3 dev 'ning key' (sha512).

netatop intercepts all IPv4 TCP/UDP/ICMP packets via two NF_INET hooks,
attributes each packet to the owning task via socket hash table lookup,
and accumulates per-task byte/packet counters accessible via getsockopt.

This is upstream atoptool code signed with TencentOS keys and declared intree:Y.
The intree:Y flag is false — netatop is not in the upstream 5.4 kernel tree.
"""

METADATA = {
    "kernel": "5.4.241-24.0017.41.1",
    "module": "netatop",
    "version": "0.7",
    "size_bytes": 36110,
    "author": "Gerlof Langeveld <gerlof.langeveld@atoptool.nl>",
    "srcversion": "0866FAB10755CF0D8E33A72",
    "license": "GPL",
    "signer": "TOS Tkernel signing key (dev 'ning key')",
    "sig_algo": "sha512",
    "intree": True,
    "intree_correct": False,
}

FUNCTIONS = {
    "update_sockcounters": {
        "addr": 0x0000,
        "size": 94,
        "purpose": (
            "Update per-task packet/byte counters for a socket. "
            "Reads sock->sk_sndbuf (0x238) and sock->sk_rcvbuf (0x246) for normalization. "
            "Reads sock->sk_wmem_alloc (0x88) as packet size. "
            "Writes to taskinfo fields: [0x4c] packs (send), [0x50] packs (recv), "
            "[0x58] bytes (send), [0x60] bytes (recv). "
            "Direction distinguished by caller: 'i' (0x69) = inbound/ICMP, else outbound."
        ),
        "sock_offsets": {
            "0x238": "sk_sndbuf (send buffer size)",
            "0x246": "movzwl — 16-bit sock field",
            "0x88": "sk_wmem_alloc or related accounting field",
        },
        "taskinfo_counter_offsets": {
            "0x4c": "send packet count",
            "0x50": "recv packet count",
            "0x58": "send byte count",
            "0x60": "recv byte count",
        },
    },
    "netatop_open": {
        "addr": 0x0060,
        "size": 32,
        "purpose": "proc file open — delegates to single_open(file, netatop_show, NULL)",
    },
    "netatop_show": {
        "addr": 0x0080,
        "size": 123,
        "purpose": (
            "proc seq_show — dumps global counters via seq_printf. "
            "Pushes many counter addresses onto stack before call. "
            "Outputs: #sockinfo, #taskinfo, #taskexit with overflow counts, "
            "and per-protocol stats (tcprcv/tcpsnd/udprcv/udpsnd/icmprcv/icmpsnd/unknownproto)."
        ),
        "output_format": (
            "#sockinfo:    %12lu (overflow: %8lu)\n"
            "#taskinfo:    %12lu (overflow: %8lu)\n"
            "#taskexit:    %12lu"
        ),
    },
    "find_sockinfo": {
        "addr": 0x0100,
        "size": 121,
        "purpose": (
            "Hash table lookup for sockinfo by (addr, port, proto). "
            "Hash index = (pid + af_family) & 0x3ff → bucket in shash. "
            "Each bucket: 24-byte doubly-linked list head. "
            "Iterates bucket list, calls memcmp against 14-byte key at [entry+0x14]. "
            "Also checks af_family byte at [entry+0x11]. "
            "On match: updates [entry+0x68] with current jiffies_64 (LRU timestamp). "
            "Returns entry* on match, NULL if not found."
        ),
        "hash_function": "(pid + af_family) & 0x3ff",
        "key_offset": 0x14,
        "key_size": 14,
        "lru_offset": 0x68,
    },
    "get_taskinfo": {
        "addr": 0x0180,
        "size": 402,
        "purpose": (
            "Hash table lookup for taskinfo by (pid, af_family). "
            "Hash index = (pid + af_family) & 0x3ff → bucket in thash. "
            "If not found: kmem_cache_alloc(Netatop_taskinfo_cache, GFP_KERNEL=0xa20). "
            "New entry size: 120 bytes (0x78). "
            "Stores: entry[0x10] = pid (4B), entry[0x14] = af_family (1B). "
            "Inserts at bucket head. "
            "Tracks total task count; refuses allocation if count > 0x200000 entries (2M cap). "
            "Returns entry* (existing or new), NULL if over-limit or OOM."
        ),
        "slab_name": "Netatop_taskinfo",
        "entry_size": 0x78,
        "gfp_flags": 0xa20,
        "hash_function": "(pid + af_family) & 0x3ff",
        "entry_fields": {
            "[0x00]": "next ptr (linked list next in bucket)",
            "[0x08]": "prev ptr (linked list prev in bucket)",
            "[0x10]": "pid (4 bytes)",
            "[0x14]": "af_family (1 byte)",
            "[0x28]": "start_time (jiffies-based, normalized with 0x44b82fa09b5a53 multiplier)",
            "[0x4c]": "send_packet_count",
            "[0x50]": "recv_packet_count",
            "[0x58]": "send_byte_count",
            "[0x60]": "recv_byte_count",
        },
        "time_normalization": (
            "0x44b82fa09b5a53 multiplier and shift-right-11 — converts raw jiffies to "
            "seconds relative to boottime. This is 1e15 / HZ (where HZ=1000): "
            "divides nanosecond timestamps to produce milliseconds."
        ),
        "max_entries": 0x200000,
    },
    "sock2task": {
        "addr": 0x0330,
        "size": 576,
        "purpose": (
            "Map a socket struct to its owning taskinfo. "
            "Reads sock->sk_family (0xcc), sock->sk_prot (0xe8), sock->sk_wmem_alloc (0x88). "
            "Checks protocol byte at prot+0x9 for IP protocol number. "
            "Handles TCP (0x06) and UDP (0x11) differently. "
            "Uses find_sockinfo to locate the socket in shash by (local IP, local port, proto). "
            "If found: calls update_sockcounters on the associated taskinfo. "
            "If not found: increments unidentTCP/UDP counters."
        ),
        "sock_field_offsets": {
            "0xcc": "sk_family (AF_INET=2, AF_INET6=10)",
            "0xe8": "sk_prot pointer",
            "0x88": "sk_wmem_alloc",
            "prot+0x9": "IP protocol number byte",
        },
        "protocols_handled": [0x06, 0x11, 0x69],
    },
    "analyze_tcpv4_packet": {
        "addr": 0x0a50,
        "size": None,
        "purpose": "Extract TCP header fields from IPv4 packet and locate sock2task mapping",
    },
    "analyze_udp_packet": {
        "addr": 0x1060,
        "purpose": "Extract UDP header fields from packet for sock2task mapping",
    },
    "ipv4_hookin": {
        "addr": 0x11c0,
        "hook_type": "NF_INET_LOCAL_IN (ingress)",
        "purpose": "Netfilter hook for inbound packets — calls analyze_tcp/udp, attributes to task",
    },
    "ipv4_hookout": {
        "addr": 0x1280,
        "hook_type": "NF_INET_LOCAL_OUT (egress)",
        "purpose": "Netfilter hook for outbound packets — calls analyze_tcp/udp, attributes to task",
    },
    "getsockopt": {
        "addr": 0x1350,
        "cap_check": "capable(CAP_NET_ADMIN=0xc) — required for all commands",
        "commands": {
            0x3d2f: "Retrieve exit list (recently exited task stats)",
            0x3d31: "Retrieve socket info for a specific connection",
            0x3d32: "Retrieve task info by (pid, af_family) — copies 0x74 bytes to userspace",
        },
        "max_copy_size": 0x74,
        "note": (
            "getsockopt returns -EPERM if caller lacks CAP_NET_ADMIN. "
            "Command 0x3d32 retrieves taskinfo by hash lookup on user-supplied (pid, af_family). "
            "Copies max 0x74 bytes of taskinfo (first 116 bytes of 120-byte struct). "
            "No length enforcement beyond min(user_supplied_len, 0x60) — "
            "user_supplied_len clamped to 0x60 at 0x13e1 ('movl $0x60, (%r12)')."
        ),
    },
    "garbage_collector": {
        "addr": 0x0c60,
        "purpose": (
            "Kernel thread body — periodically scans taskinfo and sockinfo hash tables. "
            "Removes stale entries (tasks that have exited, sockets that have closed). "
            "Uses gclast timestamp to throttle GC runs. "
            "Moves taskinfo for exited tasks to exitlist for userspace pickup."
        ),
    },
    "init_module": {
        "addr": 0x1840,
        "sequence": [
            "kmem_cache_create('Netatop_taskinfo', 0x78, 0, 0, NULL) → thash_cache",
            "kmem_cache_create('Netatop_sockinfo', 0x70, 0, 0, NULL) → shash_cache",
            "Initialize shash: 1024 × 24-byte circular list heads (0x6000 bytes at shash)",
            "Initialize thash: 1024 × 24-byte circular list heads (0x6000 bytes at thash)",
            "getboottime64() → boottime (for relative time calculations)",
            "proc_create('netatop', 0, NULL, &netatop_proc_fops) → /proc/netatop",
            "kthread_create_on_node(netatop_thread, NULL, NUMA_NO_NODE, 'netatop') → knetatop_task",
            "nf_register_net_hook(&init_net, &hookout_ipv4) — register egress hook",
            "nf_register_sockopt(&sockopts) — register getsockopt handler",
            "nf_register_net_hook(&init_net, &hookin_ipv4) — register ingress hook",
            "wake_up_process(knetatop_task) — start GC thread",
        ],
    },
}

HASH_TABLE_ARCHITECTURE = {
    "shash": {
        "purpose": "Socket info hash table",
        "bss_offset": 0x0000,
        "size_bytes": 0x6000,
        "bucket_count": 1024,
        "bucket_size": 24,
        "slab_name": "Netatop_sockinfo",
        "entry_size_bytes": 0x70,
        "hash_function": "(pid + af_family) & 0x3ff",
    },
    "thash": {
        "purpose": "Task info hash table",
        "bss_offset": 0x6000,
        "size_bytes": 0x6000,
        "bucket_count": 1024,
        "bucket_size": 24,
        "slab_name": "Netatop_taskinfo",
        "entry_size_bytes": 0x78,
        "hash_function": "(pid + af_family) & 0x3ff",
    },
    "exit_list": {
        "purpose": "Linked list of taskinfo for recently exited tasks (pending userspace read)",
        "symbols": ["exithead", "exittail", "exitlock", "exitlist_empty", "exitlist_filled"],
        "sentinel": "0x8000000000000001 (written to exitlist_filled at init)",
    },
}

GLOBAL_COUNTERS = {
    "protocol_counters": [
        "tcprcvpacks", "tcpsndpacks",
        "udprcvpacks", "udpsndpacks",
        "icmprcvbytes", "icmprcvpacks", "icmpsndbytes", "icmpsndpacks",
        "unknownproto",
    ],
    "unident_counters": [
        "unidenttcprcvpacks", "unidenttcpsndpacks",
        "unidentudprcvpacks", "unidentudpsndpacks",
    ],
    "size_counters": ["nre", "nrs", "nrt", "nrs_ovf", "nrt_ovf"],
    "note": (
        "These are global (not per-task). "
        "Accessible via /proc/netatop. "
        "Per-task counters are in taskinfo structs in thash."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "intree:Y is false — netatop declares itself upstream when it is not",
        "detail": (
            "netatop.ko declares `intree: Y` in its module info. "
            "This tells the kernel module loader that the module is part of the upstream tree. "
            "netatop is NOT in the upstream Linux 5.4 kernel tree — it is an out-of-tree "
            "module from the atoptool project, signed by Tencent and shipped with TOS 3.3. "
            "The intree:Y flag affects: (1) module tainting semantics — normally "
            "out-of-tree modules taint the kernel with 'O'; intree:Y avoids this taint. "
            "(2) Some kernel security features apply different policies to in-tree vs out-of-tree. "
            "By claiming in-tree status, netatop avoids the 'module taint' that would flag "
            "the kernel as running unverified code."
        ),
        "intree_declared": True,
        "intree_actual": False,
        "taint_avoided": "O (out-of-tree)",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "NF_INET hooks observe ALL IPv4 traffic — full east-west packet visibility",
        "detail": (
            "netatop registers hooks at NF_INET_LOCAL_IN and NF_INET_LOCAL_OUT. "
            "These hooks fire for every IPv4 packet entering and leaving the host — "
            "including inter-container traffic, loopback, and all application traffic. "
            "netatop can see source/dest IP, port, protocol, and byte counts "
            "for every connection on the host. "
            "This gives netatop (and any process with CAP_NET_ADMIN reading getsockopt) "
            "a complete network traffic map: who is talking to whom, how many bytes. "
            "On a multi-tenant host (e.g., shared CVM), this is a tenant-isolation concern "
            "if the host allows tenants to load kernel modules or read /proc/netatop."
        ),
        "hooks": ["NF_INET_LOCAL_IN", "NF_INET_LOCAL_OUT"],
        "visibility": "All IPv4 TCP/UDP/ICMP traffic on host",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "taskinfo hash collision — pid + af_family hash with 1024 buckets causes O(n) lookup at high PID count",
        "detail": (
            "Hash function: (pid + af_family) & 0x3ff → 1024 buckets. "
            "PIDs on Linux are 32768 by default (wrapping). "
            "With 32768 possible PIDs and 1024 buckets, average bucket depth = 32. "
            "On busy servers (many short-lived processes), find_sockinfo and get_taskinfo "
            "degrade to linear scan. "
            "At max_entries limit (0x200000 = 2M), each bucket has ~2048 entries — "
            "get_taskinfo becomes O(2048) per packet. "
            "Since ipv4_hookin/hookout run in softirq context (NF_INET hook), "
            "O(n) hash lookups hold the per-bucket lock in softirq, blocking softirq "
            "delivery for the duration of the scan. "
            "This is a potential softirq stall / network latency spike under load."
        ),
        "hash_bits": 10,
        "bucket_count": 1024,
        "worst_case_depth": "2048 entries per bucket at max_entries=0x200000",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "getsockopt 0x3d32 copies taskinfo without full length validation",
        "detail": (
            "getsockopt(0x3d32) takes a user-supplied length. "
            "At 0x13cc: if len <= 3, returns error. "
            "At 0x13d5: if len > 0x60, clamps to 0x60. "
            "Then copies from taskinfo into userspace. "
            "The taskinfo struct is 0x78 = 120 bytes. "
            "getsockopt copies at most 0x60 = 96 bytes — leaving the last 24 bytes inaccessible. "
            "There is no version field in the copied struct — "
            "if struct layout changes between netatop versions, userspace consumers "
            "silently read wrong fields without any error."
        ),
        "max_copy": 0x60,
        "struct_size": 0x78,
        "uncopyable_tail": 24,
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Exit list holds taskinfo until garbage-collected — completed-task stats persist in kernel memory",
        "detail": (
            "When a task exits (gctaskexit), its taskinfo is not immediately freed. "
            "Instead it is moved to the exitlist (exithead/exittail linked list). "
            "The exitlist holds stats until userspace reads them via getsockopt(0x3d2f) "
            "or until the GC thread runs and clears them. "
            "If userspace never reads the exit list (e.g., atop not running), "
            "exited task stats accumulate in kernel memory indefinitely. "
            "Combined with a high-churn process environment (many short-lived processes), "
            "this could exhaust slab memory from Netatop_taskinfo unclaimed exit entries."
        ),
        "risk": "Unbounded kernel memory growth if exit list is not drained",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "Signed with TOS 3.3 dev 'ning key' (sha512) — same weak signing key as ttools.ko",
        "detail": (
            "netatop.ko is signed with the same 'Tkernel signing key' (ASCII 'ning key,') as ttools.ko. "
            "This is a development signing key present in TOS 3.3 production systems. "
            "The sha512 algorithm is stronger than sha256 (used for TOS 4.4/4.6 modules), "
            "but the key management weakness remains: the private key for this cert "
            "is shipped with or derivable from TOS 3.3 build infrastructure. "
            "A compromised TOS 3.3 build system could sign arbitrary kernel modules "
            "that the kernel would load as trusted."
        ),
        "sig_algo": "sha512",
        "key_fingerprint": "6E:69:6E:67:20:6B:65:79:2C",
        "shared_with": ["ttools.ko"],
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "netatop /proc/netatop readable without capability — only getsockopt requires CAP_NET_ADMIN",
        "detail": (
            "The /proc/netatop file created at `proc_create('netatop', 0, ...)` "
            "uses mode 0 (no permissions explicitly set) — defaults to 0444 or 0 depending "
            "on kernel proc create behavior. "
            "netatop_show outputs global protocol counters (tcprcvpacks, udprcvpacks, etc.) "
            "to /proc/netatop without any capability check. "
            "Any local user can read global network stats (total packets/bytes per protocol). "
            "Only per-task stats (getsockopt path) require CAP_NET_ADMIN. "
            "The global /proc interface is a lower-privilege information disclosure."
        ),
        "proc_mode": "0 (effectively readable by all)",
        "cap_required_for": "getsockopt(0x3d2f, 0x3d31, 0x3d32) only",
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "Upstream atoptool module signed and shipped by Tencent — no TOS-specific modifications visible",
        "detail": (
            "netatop v0.7 by Gerlof Langeveld is the upstream atoptool netatop module. "
            "The srcversion (0866FAB10755CF0D8E33A72) can be compared against upstream builds. "
            "No TOS-specific function names or custom symbols are present — "
            "the full symbol table matches expected upstream netatop v0.7. "
            "Tencent's contribution is: (1) compiling against TOS 3.3's 5.4.241 kernel, "
            "(2) signing with the TOS Tkernel key, (3) placing it in tkernel/ tree. "
            "This contrasts with ttools.ko (entirely Tencent-custom) — netatop is a "
            "standard upstream module with no TOS modifications."
        ),
        "tos_modified": False,
        "upstream_source": "https://github.com/Atoptool/netatop",
    },
]

if __name__ == '__main__':
    print("netatop.ko (TOS 3.3) RE analysis")
    print(f"Size: {METADATA['size_bytes']}B | intree:Y (INCORRECT — out-of-tree)")
    print()
    print("Hash tables:")
    for name, ht in HASH_TABLE_ARCHITECTURE.items():
        if name == "exit_list":
            continue
        print(f"  {name}: {ht['bucket_count']} buckets × {ht['bucket_size']}B = {ht['size_bytes']:x}h bytes")
        print(f"    entry size: {ht['entry_size_bytes']:x}h bytes ({ht['slab_name']} slab)")
    print()
    print("getsockopt commands (CAP_NET_ADMIN required):")
    for cmd, desc in FUNCTIONS['getsockopt']['commands'].items():
        print(f"  0x{cmd:04x}: {desc}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
