"""
TencentOS 4.2 — aegis.ko kernel security monitoring module reverse engineering.

Source: /mnt/tos42_re/usr/lib/modules/6.6.47-12.tl4.x86_64/kernel/kernel/tkernel/aegis/aegis.ko.xz
Extracted (71KB, ELF relocatable, NOT stripped — full symbols present).

aegis.ko is TOS 4.2's kernel-level security monitoring agent.
It hooks execve() to capture process execution telemetry and exposes it
to userspace via procfs/sysfs poll interface.

ABSENT in TOS 4.4 and 4.6 — replaced by the dim_core/dim_monitor integrity
measurement system in TOS 4.6. Evolution: aegis (4.2) → kill_protect+kill_block (4.4)
→ dim_core+dim_monitor (4.6).

Authors: zhipingdu / zgpeng / huntazhang (Tencent internal usernames, embedded in module metadata)
"""

METADATA = {
    "module": "aegis",
    "version": "0.1",
    "authors": ["zhipingdu", "zgpeng", "huntazhang"],
    "license": "GPL",
    "source": "/mnt/tos42_re/usr/lib/modules/6.6.47-12.tl4.x86_64/kernel/kernel/tkernel/aegis/aegis.ko.xz",
    "size_bytes": 71 * 1024,
    "vermagic": "6.6.47-12.tl4.x86_64 SMP preempt mod_unload modversions",
    "present_in_versions": ["TOS 4.2"],
    "absent_in_versions": ["TOS 4.4", "TOS 4.6"],
    "stripped": False,
    "signer": "Tkernel signing key",
    "sig_key": "D8:37:BC:3B:9C:28:FD:F6",
    "sig_hashalgo": "sha512",
    "signing_key_note": (
        "aegis uses key D8:37:BC:3B:9C:28:FD:F6 (sha512). "
        "TOS 4.4/4.6 tkernel modules use 01:9D:01:14:84:D7 (sha256). "
        "The aegis key is RETIRED — no longer used in current TOS. "
        "This indicates a key rotation between TOS 4.2 and 4.4."
    ),
}

PURPOSE = (
    "aegis is a kernel security monitoring framework that hooks execve() "
    "to capture process execution events. For each exec, it collects: "
    "environment variables, command-line arguments, UIDs/GIDs, PID namespace inode, "
    "socket/network info, working directory, and start time. "
    "Events are buffered per-CPU and delivered to userspace via a poll/read interface "
    "exposed through procfs and sysfs."
)

HOOK_ARCHITECTURE = {
    "hook_func_array": (
        "External symbol — the hook registration table is exported by another "
        "module or the TOS kernel itself. aegis registers its execve hook into "
        "this array at init_module via hook_info_func_register."
    ),
    "hook_info_func_register": "Register aegis hook into hook_func_array",
    "hook_info_func_unregister": "Unregister at module exit",
    "per_cpu_design": (
        "hook_info_percpu_create/delete: each CPU has its own hook_info ring buffer. "
        "hook_info_array[i].readlock (spinlock) protects per-CPU access. "
        "hook_info_array[i].wait_queue: userspace poll() waits here for events."
    ),
    "hook_disable": "Sysctl-exposed toggle to disable the exec hook at runtime (requires CAP_SYS_ADMIN)",
}

DATA_COLLECTION = {
    "get_execve_info": {
        "addr": "0x2080",
        "magic_tag": "0x12345601 (written to struct offset 0x10 — event type identifier)",
        "size_allocated": "0xdc0 bytes (3520 bytes) per exec event struct",
        "note": (
            "Allocs 3520-byte struct, writes magic 0x12345601 at offset 0x10. "
            "Calls get_task_ids, get_task_para, get_task_environ, "
            "get_task_pwd, get_task_start_time, get_sock_info, get_pidns_inum. "
            "On success: inserts into per-CPU ring buffer. "
            "On failure (OOM/quota): increments hookinfo_drop_stats counter."
        ),
    },
    "get_task_environ": {
        "addr": "0x1600",
        "buffer_limit": "0x20000 (131072 bytes = 128KB)",
        "mechanism": "strnlen_user → kmalloc(0x20000) → copy_from_user from task mm_struct",
        "security_note": (
            "Environment collection is capped at 128KB. "
            "Content beyond 128KB is silently truncated. "
            "An attacker who controls the exec'd process can place malicious "
            "content (shellcode, tokens, passwords) after 128KB of padding "
            "to evade aegis environment capture."
        ),
    },
    "get_task_para": {
        "addr": "0x1930",
        "sysctl_controls": ["min_para_len", "max_para_len"],
        "mechanism": "Reads argv[] from task mm_struct with user-space strnlen",
        "sysctl_note": "min/max para length bounds are sysctl-tunable — affects capture window",
    },
    "get_task_ids": {
        "collects": ["uid", "gid", "euid", "egid", "suid", "sgid"],
        "conversion": "from_kuid_munged / from_kgid_munged — user namespace mapping applied",
    },
    "get_pidns_inum": {
        "mechanism": "task_active_pid_ns → put_pid_ns + get inode number",
        "purpose": "Container identification: unique inode per PID namespace identifies containers",
    },
    "get_sock_info": {
        "mechanism": "Reads socket info from task file descriptors",
        "collects": ["local/remote IP", "port", "protocol"],
        "output": "sockinfo_to_user via copy_to_user",
    },
}

USERSPACE_INTERFACE = {
    "procfs": {
        "create": "proc_create / proc_create_data",
        "fops": {
            "fops_open": "Opens per-CPU hook info stream",
            "fops_read": "Reads buffered exec events (blocks if empty)",
            "fops_poll": "poll/select — wakes on sysctl_poll_wakeup_length events",
            "fops_release": "Closes and flushes",
            "fops_statistics_read": "Reports hookinfo_total_numb, hookinfo_drop_stats",
        },
    },
    "sysfs": {
        "kset": "hook_sysfs_kset — kset created under /sys/kernel/",
        "attrs": "hook_attrs_group / security_moni_attrs / security_control_table",
        "hook_disable": "Sysfs write to disable exec hook",
    },
    "sysctl": {
        "table": "security_table",
        "entries": [
            "sysctl_info_num — current event count",
            "sysctl_para_len — current total arg length seen",
            "sysctl_para_sum — total arg length accumulator",
            "sysctl_poll_wakeup_length — events before poll() wakes userspace",
            "sysctl_set_max — max para length (writable)",
            "sysctl_set_min — min para length (writable)",
        ],
    },
}

EXTERNAL_SYMBOLS = {
    "hook_func_array": "Exec hook registration table — external, TOS kernel or companion module",
    "hook_info_flag": "External flag controlling hook activation state",
    "hookinfo_nr": "External event counter",
    "d_path": "VFS path resolution for working directory",
    "_copy_to_user/_copy_from_user": "Userspace data exchange",
    "strnlen_user": "Safe string length from user memory (used in environ collection)",
    "from_kuid_munged/from_kgid_munged": "UID/GID user namespace mapping",
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "get_task_environ 128KB buffer cap — environment content after 128KB evades capture",
        "detail": (
            "get_task_environ at 0x1600 allocates max 0x20000 (131072) bytes "
            "for environment capture. Any environment variable content beyond "
            "the 128KB boundary is silently truncated. "
            "An attacker who controls exec() can prepend 128KB of dummy padding "
            "before sensitive environment variables (tokens, DSA keys, passwords) "
            "to prevent aegis from recording them. "
            "The allocation uses kmalloc(0x20000) — always exactly 128KB, "
            "not the actual environment size."
        ),
        "buffer_limit": 131072,
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "hook_disable sysctl — exec monitoring can be disabled by root",
        "detail": (
            "aegis exposes a hook_disable control via sysfs and potentially sysctl. "
            "Writing to hook_disable stops exec event capture without unloading the module. "
            "An attacker with CAP_SYS_ADMIN (root) can silently disable aegis monitoring "
            "before executing malicious binaries, then re-enable it afterward. "
            "The disable/enable state is not logged — no audit trail of the disable action itself "
            "unless auditd captures the sysfs write syscall."
        ),
        "sysfs_path": "Under hook_sysfs_kset in /sys/kernel/",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "hook_func_array external symbol — zero it to disable all aegis hooks",
        "detail": (
            "aegis registers its exec hook by calling hook_info_func_register, "
            "which writes into the external hook_func_array. "
            "The hook_func_array is defined in the TOS kernel or a companion module "
            "and is reachable via /proc/kallsyms (if not locked down). "
            "A kernel exploit with an arbitrary write primitive can zero hook_func_array "
            "to prevent aegis from receiving any exec notifications, "
            "without loading a new module or calling sysfs."
        ),
        "symbol": "hook_func_array",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "execinfo_to_user / sockinfo_to_user — potential kernel info leak via uninitialized padding",
        "detail": (
            "execinfo_to_user and sockinfo_to_user copy kernel structs to userspace. "
            "The exec event struct is 3520 bytes (0xdc0). "
            "If the struct has padding between fields that is not explicitly zeroed "
            "(only 0x90 at offset 0x1c is explicitly set), "
            "uninitialized kernel heap data can be copied to userspace "
            "via copy_to_user, leaking kernel addresses or heap data."
        ),
        "struct_size": 3520,
        "magic_at_offset_0x10": "0x12345601",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Different signing key from TOS 4.4/4.6 modules — key D8:37:BC:3B:9C:28:FD:F6 is retired",
        "detail": (
            "aegis.ko is signed with D8:37:BC:3B:9C:28:FD:F6 (sha512). "
            "All TOS 4.4/4.6 tkernel modules use 01:9D:01:14:84:D7 (sha256). "
            "A key rotation occurred between TOS 4.2 and 4.4. "
            "The old key (D8:37:BC:3B:9C:28:FD:F6) is likely still trusted "
            "in the TOS 4.2 kernel's keyring. "
            "If a TOS 4.2 kernel is still in production and the old key's private key "
            "can be recovered (from legacy build infrastructure), "
            "arbitrary modules can be signed with the old key and loaded."
        ),
        "retired_key": "D8:37:BC:3B:9C:28:FD:F6",
        "current_key": "01:9D:01:14:84:D7",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "aegis v0.1 — early prototype. Authors in module metadata: zhipingdu/zgpeng/huntazhang",
        "detail": (
            "Version 0.1 and three named Tencent authors indicate aegis was an internal "
            "prototype that shipped in TOS 4.2. "
            "It was deprecated by TOS 4.4 (kill_protect/kill_block) and replaced by "
            "the more sophisticated dim_core/dim_monitor integrity measurement system in TOS 4.6. "
            "The evolution reflects TOS security architecture maturing from "
            "behavioral monitoring (aegis) to cryptographic integrity measurement (dim)."
        ),
        "authors": ["zhipingdu", "zgpeng", "huntazhang"],
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "para_len_current / para_sum_current — per-CPU exec argument length tracking via sysctl",
        "detail": (
            "aegis tracks command-line argument lengths across all exec events "
            "via sysctl_para_len and sysctl_para_sum. "
            "These sysctls allow userspace to monitor total argument data volume "
            "without reading the raw exec events. "
            "The min/max para length bounds (sysctl_set_min, sysctl_set_max) "
            "restrict what argument lengths trigger capture, "
            "potentially allowing an attacker to use very short or very long argv[0] "
            "to fall outside the capture window."
        ),
    },
]

if __name__ == '__main__':
    print(f"aegis.ko (TOS 4.2) — {len(FINDINGS)} findings")
    print(f"Authors: {', '.join(METADATA['authors'])}")
    print(f"Signing key: {METADATA['sig_key']} ({METADATA['sig_hashalgo']})")
    print(f"Absent in: {', '.join(METADATA['absent_in_versions'])}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
