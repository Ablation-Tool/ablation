"""
TencentOS 3.3 — ttools.ko binary disassembly RE module.

ttools 2.0 — TOS-specific anti-ptrace module for kernel 5.4.241-24.0017.41.1.
Size: 12886B (stripped). License: GPL. Source: kernel/kernel/tkernel/ttools/ttools.ko.xz

ttools implements per-PID ptrace protection via a custom ptrace_pre_hook kernel
export present in TOS 3.3's 5.4.241 kernel but absent in upstream Linux 5.4.
This module was removed in TOS 4.x (replaced by Yama LSM alone).

Signing: 'Tkernel signing key' — the development 'ning key' (ASCII fingerprint),
confirming TOS 3.3 uses a dev key, not a production key.
"""

METADATA = {
    "kernel": "5.4.241-24.0017.41.1",
    "module": "ttools",
    "size_bytes": 12886,
    "description": "ttools 2.0 for 5.4.241-24.0017.41.1",
    "srcversion": "2D9C63F571D22FE4E451A04",
    "signer": "Tkernel signing key (dev 'ning key')",
    "vermagic": "5.4.241-24.0017.41.1 SMP mod_unload modversions",
}

SYMBOLS = {
    "ttools_ptrace_hook": {"addr": 0x0020, "type": "t"},
    "ttools_dev_ioctl": {"addr": 0x0090, "type": "t"},
    "flush_icache_1": {"addr": 0x0000, "type": "t"},
    "ttools_init": {"addr": 0x0330, "type": "t"},
    "ttools_exit": {"addr": 0x03a0, "type": "t"},
    "ttools_protected_pids": {"addr": 0x0190, "type": "d", "note": "doubly-linked list head"},
    "ttools_pids_lock": {"addr": 0x0008, "type": "b", "note": "spinlock for protected_pids list"},
    "ttools_dev": {"addr": 0x0000, "type": "d", "note": "miscdevice registration struct"},
    "p_anon_inode_inode": {"addr": 0x0000, "type": "b", "note": "cached anon_inode_inode pointer"},
}

IMPORTED_SYMBOLS = [
    "ptrace_pre_hook",         # TOS-specific kernel export — hook registration point
    "kallsyms_lookup_name",    # used to resolve ptrace_pre_hook address at load time
    "anon_inode_inode",        # pointer to the kernel's anon inode (for fd checking)
    "current_task",            # per-CPU pointer to running task_struct
    "smp_call_function",       # cross-CPU hook installation
    "kmalloc_caches",          # GFP-based slab allocator
    "kmem_cache_alloc_trace",  # slab allocation trace
    "kfree",
    "misc_register",
    "misc_deregister",
    "_raw_spin_lock",
    "_raw_spin_unlock",
    "__fdget",
    "fput",
    "__list_add_valid",
    "__list_del_entry_valid",
    "_copy_from_user",
    "_copy_to_user",
    "noop_llseek",
    "printk",
    "pv_ops",
    "__stack_chk_fail",
]

TASK_STRUCT_OFFSET = {
    "ttools_task_id_field": 0xb40,
    "kernel": "5.4.241-24.0017.41.1",
    "note": (
        "Both ttools_ptrace_hook and ttools_dev_ioctl read task_struct+0xb40 "
        "as the identity field for protected process matching. "
        "This offset is NOT a standard upstream Linux 5.4 task_struct offset — "
        "it likely reflects CONFIG_TOS_TTOOLS or other TOS-specific padding added "
        "to task_struct in the TOS 3.3 kernel. "
        "The field is compared between: (1) the task that registered itself at "
        "ioctl time, and (2) the task being ptrace'd at hook time. "
        "Most likely this is task_struct->pid or task_struct->tgid at the "
        "TOS 3.3 padded offset — not the canonical 0x50-ish upstream offset."
    ),
}

IOCTL_INTERFACE = {
    "device_name": "ttools",
    "device_type": "misc (major 10)",
    "commands": {
        0xee00: {
            "name": "TTOOLS_ADD_PROTECTION",
            "args": "none",
            "action": (
                "Allocate a 24-byte list entry (kmalloc(0x18, GFP_KERNEL=0xcc0)). "
                "Record current task's id field (task_struct+0xb40) at entry[0x10]. "
                "Insert at head of ttools_protected_pids doubly-linked list. "
                "The calling process is now ptrace-protected."
            ),
            "returns": "0 on success, -ENOMEM, -EBUSY (already protected)",
        },
        0xee01: {
            "name": "TTOOLS_REMOVE_PROTECTION",
            "args": "none",
            "action": (
                "Search ttools_protected_pids for entry matching current task+0xb40. "
                "If found: unlink from list, poison with 0xdead000000000100/0x122, kfree. "
                "The calling process is no longer ptrace-protected."
            ),
            "returns": "0 on success, 0 if not found (idempotent)",
        },
        0xc010ee02: {
            "name": "TTOOLS_QUERY_FD",
            "args": "16-byte user struct: [u32 fd, pad, u64 value]",
            "action": (
                "Copy 16 bytes from userspace. "
                "Call __fdget(fd) to get file pointer. "
                "Check if file->f_inode == anon_inode_inode (is the fd anonymous?). "
                "Read file->f_pos (+0x38), file->f_inode (+0x20), inode->i_ino (+0x5c via dentry). "
                "Copy 16 bytes back to userspace with result."
            ),
            "returns": "0 on success, -EFAULT if copy_from_user fails, -EBADF if fd invalid",
        },
    },
}

FLUSH_ICACHE_ANALYSIS = {
    "function": "flush_icache_1",
    "addr": 0x0000,
    "size": 32,
    "technique": "IRETQ pipeline serialization",
    "disasm": [
        "00: call +5              ; push RIP (thunk for self-modifying patching)",
        "05: lock addl $0, -4(%rsp) ; mfence-equivalent memory barrier",
        "0b: mov %ss, %eax       ; save SS",
        "0d: push %rax           ; SS on stack",
        "0e: push %rsp           ; RSP on stack",
        "0f: add $8, (%rsp)      ; RSP+8 = past iretq frame",
        "14: pushf               ; RFLAGS on stack",
        "15: mov %cs, %eax       ; save CS",
        "17: push %rax           ; CS on stack",
        "18: push $0x0           ; RIP placeholder (patched at runtime to return address)",
        "1d: iretq               ; serialize: flush CPU pipeline, BPU, i-cache",
        "1f: ret                 ; (reached by iretq stack unwinding)",
    ],
    "purpose": (
        "IRETQ is a privileged instruction that atomically restores CS:RIP from the stack. "
        "Used here as a serialization barrier — forces CPU to flush the instruction pipeline "
        "before executing code that was patched at runtime (hook installation). "
        "This technique is used for safe live-patching: after modifying kernel code in place, "
        "call flush_icache_1 to ensure CPUs do not execute stale cached instructions. "
        "smp_call_function is used to run this on all CPUs simultaneously."
    ),
}

PTRACE_HOOK_ANALYSIS = {
    "function": "ttools_ptrace_hook",
    "addr": 0x0020,
    "size": 97,
    "hook_point": "ptrace_pre_hook (TOS 3.3-specific kernel export in 5.4.241)",
    "disasm_annotated": [
        "20: call +5              ; thunk for position-independent code",
        "25: push %rbx",
        "26: mov $<lock_addr>, %rdi  ; spin_lock arg",
        "2d: mov 0xb40(%rdx), %rbx   ; rbx = target_task->id_field (task being ptrace'd)",
        "34: call <_raw_spin_lock>",
        "39: mov [ttools_protected_pids], %rax ; load list head",
        "40: cmp $0, %rax             ; empty list?",
        "46: je 0x66                  ; if empty, not protected",
        "  --- list traversal ---",
        "48: mov $-1, %edx            ; edx = EPERM (-1) -> denied",
        "4d: cmp 0x10(%rax), %rbx     ; entry->task_id == target task?",
        "51: jne 0x5b                 ; no, try next entry",
        "53: jmp 0x68                 ; FOUND -> go to result path with edx=-1",
        "5b: cmp 0x10(%rax), %rbx     ; second check (likely loop structure artifact)",
        "5f: je 0x7a                  ; match found -> EPERM",
        "61: mov (%rax), %rax         ; next = entry->next",
        "64: cmp $0, %rax             ; end of list?",
        "66: xor %edx, %edx           ; edx = 0 (allowed)",
        "68: call *<ptrace_pre_hook+8>; call original hook (chain next hook)",
        "76: mov %edx, %eax",
        "78: pop %rbx",
        "79: ret                      ; return 0 (allowed) or -1 (denied)",
        "7a: mov $-1, %edx",
        "7f: jmp 0x68",
    ],
    "hook_calling_convention": (
        "ptrace_pre_hook (TOS 3.3 kernel ABI): "
        "  arg1 (%rdi) = ptrace request type (PTRACE_ATTACH, etc.) "
        "  arg2 (%rdx) = task_struct* of target process being ptrace'd "
        "Return: 0 = allow, non-zero = deny ptrace operation"
    ),
    "protection_logic": (
        "If target_task->id_field (at offset 0xb40) matches any entry in "
        "ttools_protected_pids, return -EPERM to deny the ptrace. "
        "Otherwise call the next hook in the chain and return its result."
    ),
}

TTOOLS_ENTRY_STRUCT = {
    "name": "ttools_pid_entry",
    "size": 24,
    "allocated_by": "kmalloc(24, GFP_KERNEL)",
    "fields": {
        "[0x00]": "struct ttools_pid_entry *next  (linked list next pointer)",
        "[0x08]": "struct ttools_pid_entry *prev  (linked list prev pointer)",
        "[0x10]": "unsigned long task_id  (task_struct+0xb40 of protected process)",
    },
    "list_head": "ttools_protected_pids (.data section)",
    "lock": "ttools_pids_lock (spinlock, .bss section)",
    "free_poison": {
        "next": "0xdead000000000100",
        "prev": "0xdead000000000122",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "ttools requires no capability — any unprivileged process can self-protect from ptrace",
        "detail": (
            "ttools_dev_ioctl has no capability check (no capable(CAP_SYS_PTRACE) call visible). "
            "Any process that can open /dev/ttools can call ioctl(0xee00) to add itself "
            "to the protected list, blocking all subsequent PTRACE_ATTACH attempts. "
            "This includes unprivileged user processes. "
            "A rogue service or malware running as a non-root user could self-protect, "
            "preventing debuggers, strace, and anti-virus scanners that use ptrace. "
            "Only processes with CAP_SYS_PTRACE can bypass Yama, but ttools blocks "
            "even CAP_SYS_PTRACE holders — the kernel hook runs before ptrace permission checks."
        ),
        "ioctl": 0xee00,
        "cap_required": "None detected",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "TOS-specific ptrace_pre_hook at task_struct+0xb40 — custom kernel ABI, not auditable",
        "detail": (
            "ttools_ptrace_hook reads task_struct+0xb40 on TOS 3.3's 5.4.241 kernel. "
            "This offset is not present in upstream Linux 5.4 task_struct. "
            "The ptrace_pre_hook export is also absent from upstream — it is a TOS kernel modification. "
            "No public documentation exists for this hook's ABI or lifecycle guarantees. "
            "A bug in the offset calculation (wrong field read) could allow a process to "
            "spoof its identity and register a protection entry for another PID — "
            "protecting a different process than intended (or protecting init)."
        ),
        "task_struct_offset": 0xb40,
        "hook_export": "ptrace_pre_hook (TOS 3.3 only)",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Linked list not protected against concurrent modification without RCU — use-after-free window",
        "detail": (
            "The ttools_protected_pids list is protected by ttools_pids_lock (spinlock). "
            "However, ttools_ptrace_hook acquires the lock, traverses the list, then calls "
            "the next hook in the chain while holding the lock. "
            "If the hook call is slow (e.g., disk I/O in the next hook), the lock is held "
            "across a potentially blocking operation — deadlock risk if the blocked code "
            "also needs ttools_pids_lock. "
            "Separately: the list is a simple doubly-linked list. If a process exits while "
            "its entry is in the list, the entry's task_struct pointer is freed but the "
            "entry remains (until the process calls TTOOLS_REMOVE_PROTECTION). "
            "The protected_pids entry at [0x10] stores `task_struct+0xb40`, not task_struct* "
            "directly, but the comparison at hook time dereferences the target's "
            "task_struct+0xb40 — if target's task_struct was freed, this is a use-after-free."
        ),
        "uaf_scenario": "Protected process exits without calling ioctl(REMOVE) → stale entry → dangling task_struct at hook time",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "ioctl 0xc010ee02 — anonymous fd oracle for privilege probing",
        "detail": (
            "The TTOOLS_QUERY_FD ioctl reads file->f_pos (offset 0x38), file->f_inode (0x20), "
            "inode->i_ino (via dentry at 0x5c), and whether the inode is anon_inode_inode. "
            "This exposes kernel-internal inode and position information for any fd the caller can open. "
            "A non-root process with access to /dev/ttools can query file metadata "
            "for any fd it holds, including fd 0/1/2 (stdin/stdout/stderr). "
            "This is effectively a kernel information disclosure ioctl — "
            "file structure internals (position, inode number) without CAP_SYS_ADMIN."
        ),
        "ioctl": 0xc010ee02,
        "data_disclosed": ["file->f_pos", "file->f_inode", "inode->i_ino", "anon_inode_inode match"],
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "ttools removed in TOS 4.x — security regression for deployments migrating from TOS 3.3",
        "detail": (
            "ttools.ko is present in TOS 3.3 only. TOS 4.x uses Yama LSM instead. "
            "Yama restricts ptrace to parent-child relationships. "
            "ttools allowed any process to self-protect — Yama does NOT provide per-process opt-in. "
            "Organizations migrating TOS 3.3 → 4.x lose the per-process ptrace protection. "
            "Any service that relied on ioctl(TTOOLS_ADD_PROTECTION) for runtime protection "
            "will silently have no equivalent protection after migration. "
            "The protection model changed from opt-in (ttools) to structural (Yama) — "
            "a regression for self-protecting services that used the ttools ioctl."
        ),
        "present_in": ["TOS_3.3"],
        "absent_in": ["TOS_4.4", "TOS_4.6"],
        "replacement": "CONFIG_SECURITY_YAMA (less granular, no per-PID opt-in)",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "flush_icache_1 uses IRETQ for pipeline serialization — correct live-patching technique",
        "detail": (
            "ttools installs its ptrace hook at runtime using smp_call_function to run on all CPUs. "
            "flush_icache_1 uses IRETQ (exception return) to serialize the CPU instruction pipeline "
            "after patching the hook. This is the correct and safe technique for in-kernel "
            "live patching on x86 — IRETQ flushes the CPU frontend, ensuring no stale "
            "pre-decoded instructions from before the patch survive in the i-cache. "
            "This approach is functionally equivalent to the kpatch/livepatch serialization model. "
            "The lock addl at the start provides the necessary memory barrier."
        ),
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "DEADBEEF poison values 0xdead000000000100/0x122 — standard kernel list poisoning",
        "detail": (
            "When removing an entry: ttools_dev_ioctl poisons ->next with 0xdead000000000100 "
            "and ->prev with 0xdead000000000122 before calling kfree. "
            "This matches Linux's standard LIST_POISON1 / LIST_POISON2 values "
            "(defined in include/linux/poison.h). "
            "Correct use of list poisoning — any use-after-free attempt to traverse the "
            "freed entry's links will dereference invalid addresses, producing an oops "
            "rather than silently returning stale data."
        ),
        "LIST_POISON1": "0xdead000000000100",
        "LIST_POISON2": "0xdead000000000122",
    },
]

if __name__ == '__main__':
    print("ttools.ko (TOS 3.3) binary RE analysis")
    print(f"Size: {METADATA['size_bytes']}B | srcversion: {METADATA['srcversion']}")
    print()
    print("Ioctl interface:")
    for cmd, info in IOCTL_INTERFACE["commands"].items():
        print(f"  0x{cmd:08x}: {info['name']} — {info['action'][:60]}")
    print()
    print("Entry struct: 24B doubly-linked list node")
    for offset, field in TTOOLS_ENTRY_STRUCT["fields"].items():
        print(f"  {offset}: {field}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
