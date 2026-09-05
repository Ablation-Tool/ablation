"""
TencentOS 4.6 — aegis.ko kernel HIDS sensor module RE.

Binary: aegis.ko
Type: ELF 64-bit relocatable, x86-64, not stripped
Text size: 0x247c bytes (51 functions)
Version: 0.1
Authors: zhipingdu/zgpeng/huntazhang (Tencent Security)
License: GPL

Role: Kernel-space sensor for a Host Intrusion Detection System (HIDS) or
Endpoint Detection and Response (EDR) platform. Captures execve events, socket
creation, process environment, and process metadata, then exports to userspace
via a polled character device.

This is the kernel component of Tencent's 'Aegis' security monitoring system
(腾讯主机安全 / Tencent Host Security). The userspace agent consumes events
from aegis.ko and reports to Tencent's cloud-based threat detection backend.
"""

BINARY_INVENTORY = {
    "aegis.ko": {
        "path": "/tmp/scratchpad/aegis.ko",
        "type": "ELF 64-bit relocatable, x86-64, not stripped",
        "text_size": 0x247c,
        "functions": 51,
        "version": "0.1",
        "license": "GPL",
        "authors": ["zhipingdu", "zgpeng", "huntazhang"],
        "description": "Tencent Aegis HIDS kernel sensor",
    },
}

HOOK_ARCHITECTURE = {
    "base_module_dependency": (
        "aegis.ko imports hook_func_array, hook_info_flag, hookinfo_nr, and "
        "hook_info as EXTERN symbols — these are not standard kernel APIs. "
        "They are exported by a companion base security module (possibly 'security.ko' or "
        "a module named after its sysfs path 'security/module'). "
        "The string 'security/module:online' suggests a kobject at /sys/kernel/security/module/ "
        "or /sys/bus/.../security/module. "
        "aegis.ko is a PLUGIN that registers specific event hooks with the base module."
    ),
    "hook_registration": {
        "api": [
            "hook_info_func_register (0xc80) — register a hook provider",
            "hook_info_func_unregister (0xd30) — unregister a hook provider",
            "hookinfo_list_in (0x770) — add hook info to active list",
            "clear_hookinfo_list (0x5e0) — flush all registered hooks",
        ],
        "hook_types_observed": ["execve_info", "sock_info"],
        "note": (
            "The hook_info_array stores registered hook providers. "
            "hook_func_array (imported) is the base module's table of hook entry points "
            "(per-CPU or per-hook-type function pointers). "
            "When a monitored kernel event fires, the base module calls the registered "
            "hook providers via hook_func_array."
        ),
    },
    "cpu_hotplug": {
        "callbacks": ["cpu_online_func (0x10)", "cpu_offline_func (0x30)"],
        "mechanism": "__cpuhp_setup_state / __cpuhp_remove_state",
        "hook_cpu_mask": "per-CPU mask controlling which CPUs have active hooks",
        "note": "CPU hotplug callbacks update hook_cpu_mask to ensure no CPU is left with a stale hook after hotadd/remove",
    },
}

CAPTURED_DATA = {
    "execve_info": {
        "function": "get_execve_info (0x2080)",
        "captured_fields": [
            "process name (comm)",
            "full executable path (d_path)",
            "command line arguments",
            "environment variables (get_task_environ)",
            "working directory (get_task_pwd)",
            "PID namespace inode number (get_pidns_inum) — identifies container namespace",
            "UIDs/GIDs (get_task_ids, from_kuid_munged/from_kgid_munged)",
            "process start time (get_task_start_time)",
            "process parameters (get_task_para)",
            "task start time in monotonic clock",
        ],
        "export": "execinfo_to_user (0x12e0) — copies execve_info struct to userspace ring buffer",
        "environment": {
            "get_task_environ (0x1600)": "reads /proc/$pid/environ via task_struct mm->env_start",
            "clear_task_environ (0x1580)": "frees environment buffer",
            "strnlen_user": "safe userspace string length for environment reading",
        },
        "container_detection": (
            "get_pidns_inum (0x1c00): calls task_active_pid_ns() + init_pid_ns comparison. "
            "If the task's PID namespace != init_pid_ns, the process is in a container. "
            "Returns the PID namespace inode number for correlation with /proc/$pid/ns/pid."
        ),
    },
    "sock_info": {
        "function": "get_sock_info (0x10f0)",
        "captured_fields": [
            "socket family (AF_INET/AF_INET6/AF_UNIX)",
            "socket type (SOCK_STREAM/SOCK_DGRAM/etc.)",
            "local address and port",
            "remote address and port",
            "socket state",
        ],
        "note": "Captures network connections made by monitored processes",
    },
}

USERSPACE_INTERFACE = {
    "character_device": {
        "fops": {
            "open":    "fops_open (0x2d0) — set up per-fd context, wait_queue",
            "read":    "fops_read (0x300) — blocking read of event ring buffer",
            "release": "fops_release (0x2a0) — cleanup per-fd context",
            "poll":    "fops_poll (0x560) — poll()/select() support for event notification",
        },
        "design": (
            "The device uses a wait_queue per hook_info entry (__wake_up + init_waitqueue_head). "
            "Userspace agent can block in read() or use poll() to wait for new security events. "
            "When an event fires in the kernel, __wake_up wakes the polling userspace process. "
            "Efficient: no busy-wait; event-driven delivery."
        ),
    },
    "proc_interface": {
        "fops_statistics_read (0x410)": "exports per-hook statistics (event counts)",
        "proc_mkdir": "creates /proc directory for aegis",
        "proc_create / proc_create_data": "creates individual proc files",
    },
    "sysfs_interface": {
        "kset_create_and_add": "creates kobject set at /sys/kernel/security/ or similar",
        "sysfs_create_group": "creates attribute group (disable, statistics_info)",
        "disable_show (0x60)": "reads current disable state",
        "disable_store (0x140)": "writes to enable/disable hook (sysfs attr)",
        "kernel_kobj": "parent kobject is the kernel kobject (/sys/kernel/)",
    },
    "sysctl": {
        "register_sysctl_sz": "registers sysctl table under security_sysctl namespace",
        "proc_doulongvec_minmax": "secur_poll_wakeup_length — long value with bounds",
        "note": "secur_poll_wakeup_length likely controls how many events must accumulate before waking poll()",
    },
}

SECURITY_ANALYSIS = {
    "data_exfiltration_surface": (
        "aegis.ko captures process environment variables (via mm->env_start) for every execve. "
        "Environment variables commonly contain secrets: AWS_ACCESS_KEY_ID, GITHUB_TOKEN, "
        "DATABASE_URL, private keys passed as env vars, etc. "
        "These are sent to a Tencent-controlled cloud backend by the userspace agent. "
        "This is intentional (HIDS telemetry) but is a significant data collection surface "
        "on multi-tenant TOS 4.6 systems."
    ),
    "container_boundary_crossing": (
        "get_pidns_inum enables the host-level aegis agent to identify which container "
        "each execve originated from. The sensor sees across ALL containers on the host "
        "from the host kernel's privileged vantage point — no container can hide from it."
    ),
    "base_module_dependency": (
        "aegis.ko requires a base security module that exports hook_func_array and hookinfo_nr. "
        "This base module is not present in the scratchpad — may be built into the kernel or "
        "in a separate package. Without the base module, aegis.ko fails to load."
    ),
    "cpu_hotplug_correct": (
        "CPU hotplug handling with cpus_read_lock and per-CPU mask is correct — "
        "prevents hook execution on offline CPUs and handles online/offline transitions. "
        "The hook_cpu_mask tracks active CPUs."
    ),
    "disable_via_sysfs": (
        "The disable_store function allows disabling aegis hooks at runtime via sysfs. "
        "If /sys/.../disable is world-writable or accessible to a container, "
        "a malicious workload could disable the HIDS sensor, creating a blind spot."
    ),
    "environment_read_safety": (
        "get_task_environ reads from task_struct->mm->env_start using strnlen_user and "
        "__get_user_4/__get_user_8 — proper userspace memory access primitives with page fault "
        "handling. The read is bounded by strnlen_user result. No buffer overflow surface here."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "aegis.ko captures process environment variables from ALL execve events on host",
        "detail": (
            "get_task_environ reads mm->env_start for every monitored process. "
            "Environment commonly contains AWS keys, tokens, DB passwords, certificates. "
            "Captured data sent to Tencent cloud backend by userspace agent. "
            "Affects all workloads on TOS 4.6 including other tenants' containers. "
            "This is INTENTIONAL HIDS telemetry — flagged as a data collection disclosure."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "aegis.ko has host-level visibility into all containers via PID namespace crossing",
        "detail": (
            "get_pidns_inum identifies container namespace from host kernel vantage. "
            "Host kernel sensor sees all process events across container boundaries. "
            "No container isolation prevents aegis from monitoring containerized workloads. "
            "Intentional design for HIDS coverage; relevant for shared-tenant risk assessment."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "aegis sysfs disable attribute: disabling sensor possible if attribute is writable",
        "detail": (
            "disable_store() at 0x140 disables aegis hooks via sysfs. "
            "If the sysfs attribute is accessible (non-root-only), "
            "a privileged container (cap_sys_admin) or local attacker can blind the HIDS. "
            "Creates a coverage gap for ongoing malicious activity."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "aegis.ko: plugin architecture — depends on base security module (not in scratchpad)",
        "detail": (
            "Imports hook_func_array, hook_info_flag, hookinfo_nr as external symbols. "
            "These are from a companion base module (not standard kernel exports). "
            "Without the base module, aegis.ko cannot load. "
            "Base module likely provides the central hook dispatch table."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "aegis.ko: event-driven character device with poll() — correct design",
        "detail": (
            "fops_poll + wait_queue + __wake_up pattern: no busy-wait. "
            "CPU hotplug handling with cpus_read_lock + per-CPU hook_cpu_mask: correct. "
            "Environment reading uses strnlen_user/__get_user_*: safe userspace access. "
            "Overall kernel programming quality is high for a v0.1 module."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 aegis.ko — Tencent HIDS kernel sensor RE")
    print()
    info = BINARY_INVENTORY['aegis.ko']
    print(f"  {info['text_size']:04x} bytes .text, {info['functions']} functions, v{info['version']}")
    print(f"  Authors: {', '.join(info['authors'])}")
    print()
    print("Captured events:")
    for event, details in CAPTURED_DATA.items():
        print(f"  {event}: {details.get('function', '').split()[0]}")
    print()
    print("Userspace interface: character device (read/poll) + /proc + sysfs")
    print("Hook system: plugin registration with external base security module")
    print("Container-aware: get_pidns_inum identifies container namespace crossing")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
