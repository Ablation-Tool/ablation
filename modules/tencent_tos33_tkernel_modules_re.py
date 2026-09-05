"""
TencentOS 3.3 — ttools.ko and netatop.ko kernel module reverse engineering.

Source: /mnt/tos33_re/usr/lib/modules/5.4.241-24.0017.41.1/kernel/kernel/tkernel/
  ttools/ttools.ko.xz    (13KB, GPL, TOS-specific anti-ptrace protection)
  netatop/netatop.ko.xz  (36KB, GPL, per-task network statistics)

Both modules use the SAME signing key: 6E:69:6E:67:20:6B:65:79:2C (hex)
= "ning key," in ASCII — a development or improperly named key.
Signer field is " sig" (space + "sig").

Kernel: 5.4.241-24.0017.41.1 (Linux 5.4 LTS, TOS 3.3)
"""

METADATA = {
    "kernel_version": "5.4.241-24.0017.41.1",
    "tos_version": "3.3",
    "signer": " sig",
    "sig_key_raw": "6E:69:6E:67:20:6B:65:79:2C:94:15:C6:82:EA:DB:06:CF:5A:37:57",
    "sig_key_ascii_prefix": "ning key,",
    "signing_note": (
        "The signing key fingerprint begins 6E:69:6E:67:20:6B:65:79:2C = 'ning key,' in ASCII. "
        "The signer name is ' sig' (literal space + 'sig'). "
        "This is a development/test key with an improperly generated or intentionally "
        "obfuscated fingerprint. Not the same key as TOS 4.x modules."
    ),
}

TTOOLS = {
    "module": "ttools",
    "description": "ttools 2.0 for 5.4.241-24.0017.41.1",
    "license": "GPL",
    "size_bytes": 13 * 1024,
    "purpose": (
        "Anti-ptrace protection module for TOS 3.3. "
        "Maintains a list of protected PIDs. When ptrace() is called against "
        "a protected PID, the TOS kernel's ptrace_pre_hook invokes ttools_ptrace_hook, "
        "which returns -EPERM to deny the trace. "
        "Managed via misc char device ioctl interface."
    ),
    "hook_mechanism": {
        "symbol": "ptrace_pre_hook",
        "note": (
            "ptrace_pre_hook is a TOS 5.4 kernel-exported hook point "
            "NOT present in upstream Linux 5.4. "
            "ttools installs ttools_ptrace_hook into this slot at init_module. "
            "The kernel calls ptrace_pre_hook before executing ptrace() — "
            "if it returns non-zero, ptrace is denied."
        ),
    },
    "ioctl_interface": {
        "device": "ttools_dev (misc char device via misc_register)",
        "ioctls": {
            "0xee00": "List/query protected PIDs — reads linked list",
            "0xee01": (
                "Remove CURRENT task from protected list. "
                "The calling process removes ITSELF. Uses list_del "
                "with 0xdead000000000100 poison (LIST_POISON1 standard). "
                "Security implication: any process in the protected list "
                "can self-remove, then become ptrace-able."
            ),
            "0xc010ee02": (
                "Add a PID to protected list. _IOWR(0xee, 2, 16-byte struct). "
                "Requires CAP_SYS_ADMIN (capability check via capable())."
            ),
        },
        "task_struct_offset": "0xb40 (PID/task field in TOS 5.4 kernel — NOT upstream layout)",
    },
    "kernel_text_patching": {
        "kallsyms_lookup_name": "Runtime kernel symbol resolution",
        "flush_icache_1": "CPU instruction cache flush after code patch",
        "smp_call_function": "Cross-CPU call for coherent text patching",
        "note": (
            "The combination of kallsyms_lookup_name + flush_icache_1 + smp_call_function "
            "indicates ttools installs the ptrace hook by patching kernel text at runtime "
            "(similar to live kernel patching). "
            "This is how ptrace_pre_hook is activated: ttools locates the function address "
            "via kallsyms, patches the call site, flushes icache on all CPUs."
        ),
    },
    "protected_pids_bypass": [
        "ioctl(ttools_dev, 0xee01) removes calling process from protected list — self-bypass",
        "A process that shares task_struct identity (e.g. via CLONE_THREAD) may bypass the PID match",
        "Without CAP_SYS_ADMIN, cannot add PIDs, but any process already protected can self-remove",
        "If ttools device node is world-writable, any process can add itself to protected list",
    ],
}

NETATOP = {
    "module": "netatop",
    "author": "Gerlof Langeveld <gerlof.langeveld@atoptool.nl>",
    "version": "0.7",
    "description": "Per-task network statistics",
    "license": "GPL",
    "size_bytes": 36 * 1024,
    "purpose": (
        "Per-task and per-socket network traffic accounting. "
        "Uses netfilter hooks (NF_INET_LOCAL_IN / NF_INET_LOCAL_OUT) "
        "and a getsockopt hook to associate network traffic with Linux tasks. "
        "Maintains sockinfo (per-socket) and taskinfo (per-task) structures "
        "exported via procfs."
    ),
    "upstream_project": "github.com/Atoptool/netatop — open source, Tencent modified version",
    "netfilter_hooks": {
        "ipv4_hookin": "NF_INET_LOCAL_IN hook — counts inbound TCP/UDP bytes per socket",
        "ipv4_hookout": "NF_INET_LOCAL_OUT hook — counts outbound TCP/UDP bytes per socket",
        "analyze_tcpv4_packet": "TCP v4 packet accounting",
        "analyze_udp_packet.constprop.5": "UDP packet accounting",
    },
    "getsockopt_hook": {
        "function": "getsockopt",
        "hook_registration": "nf_register_sockopt",
        "note": "Intercepts getsockopt() calls to return per-socket traffic stats to userspace",
    },
    "data_structures": {
        "sockinfo": "Per-socket traffic counters (bytes in/out, packets)",
        "taskinfo": "Per-task aggregated network stats",
        "procfs_interface": "netatop_proc_fops — /proc/netatop",
        "kernel_thread": "netatop_thread — background garbage collector",
    },
    "buffer_overflow_string": (
        "'Buffer overflow detected (%d < %lu)!' — explicit bounds check with printk. "
        "The check at least logs the overflow but may not prevent it depending on "
        "what happens after the check."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "ttools ioctl 0xee01 allows self-removal from protected list — anti-ptrace bypass",
        "detail": (
            "ttools_dev_ioctl at ioctl 0xee01 removes the CALLING process "
            "from the protected PID list. No capability check is required for self-removal — "
            "only the add ioctl (0xc010ee02) requires CAP_SYS_ADMIN. "
            "Any process that has been placed in the protected list can call "
            "ioctl(ttools_fd, 0xee01) to remove itself, then immediately become "
            "ptrace-able. "
            "This is likely intentional (allowing a process to self-unprotect for debugging) "
            "but creates a race window: attacker code inside a protected process "
            "can call ioctl(0xee01) then raise(SIGSTOP) to allow external ptrace attachment."
        ),
        "ioctl": "0xee01",
        "list_poison": "0xdead000000000100 (LIST_POISON1)",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "ttools installs ptrace hook via kernel text patching (kallsyms + flush_icache + smp_call_function)",
        "detail": (
            "ttools.ko imports kallsyms_lookup_name, flush_icache_1, smp_call_function — "
            "the standard triad for kernel live patching. "
            "At init, ttools locates ptrace_pre_hook via kallsyms, "
            "patches the kernel call site, and flushes icache on all CPUs. "
            "This kernel text patching mechanism can be exploited: "
            "if ttools is loaded by an unprivileged module (e.g., via a kernel bug that "
            "bypasses module signature checking), it can install arbitrary function pointers "
            "into the patched ptrace call site. "
            "The patching also means ttools cannot be cleanly unloaded "
            "without restoring the original call site — if cleanup_module fails, "
            "the patch persists."
        ),
        "imports_used": ["kallsyms_lookup_name", "flush_icache_1", "smp_call_function"],
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "TOS-specific ptrace_pre_hook kernel symbol — not in upstream Linux 5.4",
        "detail": (
            "ptrace_pre_hook is exported by the TOS 5.4 kernel as a function pointer slot. "
            "This symbol does NOT exist in upstream Linux 5.4. "
            "Its presence means the TOS kernel has been patched to support pluggable "
            "pre-ptrace authorization hooks. "
            "task_struct offset 0xb40 used by ttools also differs from upstream — "
            "the TOS kernel struct layout diverges at offset 0xb40."
        ),
        "tos_specific_symbol": "ptrace_pre_hook",
        "upstream_absent": True,
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "Signing key 'ning key,' (6E:69:6E:67:20:6B:65:79:2C) — improperly named development key",
        "detail": (
            "Both ttools.ko and netatop.ko are signed with key fingerprint "
            "6E:69:6E:67:20:6B:65:79:2C (first 9 bytes = ASCII 'ning key,'). "
            "The signer name field is ' sig' (a space followed by 'sig'). "
            "This is a TOS 3.3 development/build key, separate from TOS 4.x keys. "
            "If this key's private key material exists on any TOS build server, "
            "arbitrary modules can be signed for TOS 3.3 kernels still trusting this key. "
            "The ASCII prefix in the fingerprint suggests this is a signing key "
            "whose name (or a prefix of the cert CN) leaked into the fingerprint display."
        ),
        "affected_modules": ["ttools", "netatop", "irqlatency"],
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "netatop buffer overflow check — bounds check present but post-check action unclear",
        "detail": (
            "'Buffer overflow detected (%d < %lu)!' in netatop strings. "
            "This is a runtime bounds check that logs the overflow condition. "
            "The printk indicates the developer anticipated the overflow scenario. "
            "Without analyzing the post-check code path: if execution continues "
            "after the printk (common in 'defensive' checks that don't abort), "
            "the overflow still occurs and can corrupt adjacent sockinfo/taskinfo entries."
        ),
        "module": "netatop",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "netatop getsockopt hook intercepts all getsockopt() calls — latency and DoS surface",
        "detail": (
            "netatop registers a getsockopt hook via nf_register_sockopt. "
            "This hook runs in the getsockopt() syscall path for all sockets. "
            "A bug in getsockopt() handler (memory leak, incorrect return code) "
            "affects all processes calling getsockopt() on any socket type. "
            "High-frequency getsockopt callers (e.g., curl, wget, HTTP clients) "
            "all pass through netatop's hook — a crash or stall in the hook "
            "causes a system-wide getsockopt DoS."
        ),
        "hook_registration": "nf_register_sockopt",
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "ttools task_struct offset 0xb40 — TOS 3.3 kernel struct layout diverges from upstream 5.4",
        "detail": (
            "ttools reads task->pid at task_struct offset 0xb40 (2880 bytes). "
            "In upstream Linux 5.4, task_struct.pid is at approximately 0x690 (with default config). "
            "The offset 0xb40 divergence indicates TOS has added significant fields "
            "to task_struct before the pid field — consistent with KASAN shadow, "
            "additional scheduling fields, or TOS-specific metadata. "
            "This offset is hardcoded in ttools.ko — a TOS kernel update that moves "
            "this field would silently break ttools' PID matching without compilation error."
        ),
        "task_struct_pid_offset": "0xb40",
        "upstream_offset_approx": "0x690",
    },
]

if __name__ == '__main__':
    print(f"TOS 3.3 tkernel modules — {len(FINDINGS)} findings")
    print(f"Signing key: {METADATA['sig_key_ascii_prefix']} ({METADATA['sig_key_raw'][:23]}...)")
    print()
    for f in FINDINGS:
        mod = f.get('module', '')
        mod_tag = f'[{mod}] ' if mod else ''
        print(f"  [{f['severity']:6s}] {f['id']}: {mod_tag}{f['title']}")
