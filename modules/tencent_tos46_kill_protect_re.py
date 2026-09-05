"""
TencentOS 4.6 — kill_protect.ko reverse engineering module.

Binary: kill_protect.ko
Source: /mnt/tos46_re (nbd10, TOS 4.6 kernel 6.6.119-51.3.tl4.x86_64)
Build:  BuildID[sha1]=22709b1c2b5f12c3f2de008b1bf072f81e444078
Size:   27KB ELF relocatable x86-64 NOT stripped
Author: Yongliang Gao <leonylgao@tencent.com> (from .rodata)
vermagic: 6.6.119-51.3.tl4.x86_64 SMP mod_unload modversions

Purpose: kernel module implementing process kill protection via:
  /proc/kill_protect/blacklist  — rw procfs: add/del <name>
  /proc/sys/kernel/sig_kill_protect — sysctl 0/1/2 global enable flag

The module exports register_kill_hook / unregister_kill_hook calls —
these are not in upstream Linux; they are TOS-specific kernel hook API
that allows modules to intercept signal delivery in do_send_sig_info().

Ablation semantic sweep: all-MiniLM-L6-v2, 9 functions encoded.
"""

METADATA = {
    "target": "TencentOS 4.6",
    "binary": "kill_protect.ko",
    "build_id": "22709b1c2b5f12c3f2de008b1bf072f81e444078",
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "arch": "x86-64",
    "stripped": False,
    "module_author": "leonylgao@tencent.com",
    "tos_specific_api": ["register_kill_hook", "unregister_kill_hook"],
}

# Ablation semantic sweep output — all-MiniLM-L6-v2, 9-function corpus
SEMANTIC_SWEEP = {
    "model": "all-MiniLM-L6-v2",
    "corpus_size": 9,
    "queries": [
        {
            "tag": "race_rwlock",
            "query": "kernel mutex read write lock race condition signal delivery",
            "top": [
                {"score": 0.437, "name": "kill_protect_hook_func", "addr": "0x780"},
                {"score": 0.436, "name": "blacklist_seq_stop", "addr": "0x150"},
            ]
        },
        {
            "tag": "signal_bypass",
            "query": "signal filter bypass hook process name comparison",
            "top": [
                {"score": 0.347, "name": "kill_protect_hook_func", "addr": "0x780"},
                {"score": 0.268, "name": "kill_protect_blacklist_match", "addr": "0x5c0"},
            ]
        },
        {
            "tag": "procfs_write_handler",
            "query": "procfs write handler userspace input parsing strsep",
            "top": [
                {"score": 0.203, "name": "blacklist_write", "addr": "0x180"},
            ]
        },
    ]
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "kill-protection bypass via prctl(PR_SET_NAME) — process name impersonation",
        "function": "kill_protect_blacklist_match",
        "addr": "0x5c0",
        "detail": (
            "kill_protect_blacklist_match identifies protected processes solely by task_struct->comm "
            "(the 15-char process name, settable by any process via prctl(PR_SET_NAME)). "
            "The function implements a 'friendly fire' exemption at offset +0x7b: if the SENDER's comm "
            "matches a blacklist entry, the kill is permitted against any other protected target. "
            "Disassembly at 0x64e/0x654: first comparison is strcmp(entry, current->comm) via "
            "gs:0x0+0xe48 (current->comm). At 0x68c: if sender_comm matches entry, then checks "
            "if target_comm also matches; if YES (both protected), the kill is ALLOWED (jne 727 -> r15=0). "
            "This means: any unprivileged process that runs prctl(PR_SET_NAME, 'tagent', 0) acquires "
            "the same comm as a protected process and can SIGKILL any other protected process. "
            "No executable path verification, no UID check, no capability check on the sender side."
        ),
        "disasm_evidence": [
            "0x632: mov r12, QWORD PTR gs:0x0  ; r12 = current task_struct",
            "0x63e: add r12, 0xe48              ; r12 = &current->comm",
            "0x645: lea r14, [rbp+0xe48]        ; r14 = &target->comm",
            "0x654: call strcmp/strcmp_rel       ; strcmp(entry, current->comm)",
            "0x659: test eax, eax",
            "0x65b: je 0x68c                    ; sender match -> go to friendly-fire path",
            "0x668: call strcmp_rel             ; strcmp(entry, target->comm)",
            "0x66f: sete r15b                   ; r15=1 if target also matches",
            "0x68c: test r15b, r15b",
            "0x68f: jne 0x727                   ; target-already-matched: r15=0, allow kill",
        ],
        "exploit_primitive": (
            "prctl(PR_SET_NAME, 'tagent', 0, 0, 0);  // rename attacker process\n"
            "kill(target_pid, SIGKILL);               // now allowed by hook"
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Signal filter scope: SIGKILL+SIGTERM only — SIGSTOP achieves persistent DoS",
        "function": "kill_protect_hook_func",
        "addr": "0x780",
        "detail": (
            "The hook at 0x785 checks ONLY signal 9 (SIGKILL) and 15 (SIGTERM). "
            "cmp edi, 0x9 / je 0x796 / xor eax, eax / cmp edi, 0xf / je 0x796. "
            "All other signals proceed to the reloc jump at 0x791 (returns 0 = allow). "
            "SIGSTOP (19) is NOT intercepted. Any process with CAP_KILL (default for same-uid) "
            "can send SIGSTOP to a protected process, suspending it indefinitely. "
            "SIGTSTP (20), SIGPWR (30), and any RT signal are similarly unprotected. "
            "A suspended tagent fails its cloud heartbeat, triggering a liveness timeout "
            "and potential host deregistration from the TOS control plane."
        ),
        "disasm_evidence": [
            "0x785: cmp edi, 0x9    ; SIGKILL?",
            "0x788: je 0x796        ; yes -> check blacklist",
            "0x78a: xor eax, eax   ; default: allow",
            "0x78c: cmp edi, 0xf    ; SIGTERM?",
            "0x78f: je 0x796        ; yes -> check blacklist",
            "0x791: jmp reloc       ; all other signals -> return 0 (allow)",
        ],
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Global kill-protection disable via sig_kill_protect sysctl",
        "function": "kill_protect_blacklist_match",
        "addr": "0x5d3",
        "detail": (
            "First instruction in kill_protect_blacklist_match reads the sig_kill_protect sysctl "
            "at 0x5d3: mov eax, DWORD PTR [rip+reloc_to_sig_kill_protect]. "
            "test eax, eax; jne 0x5fa — if sysctl == 0, immediately returns r15d=0 (no protection). "
            "The sysctl is registered with proc_douintvec_minmax (bounds-checked unsigned int) "
            "and with mode 0x1a4 (0644) — root-writable. "
            "Writing 0 to /proc/sys/kernel/sig_kill_protect disables all kill protection globally. "
            "Any process with CAP_SYS_ADMIN (or any root-equivalent) can trivially bypass all "
            "protection: echo 0 > /proc/sys/kernel/sig_kill_protect; kill -9 <protected_pid>. "
            "The sysctl also supports value 2 (verbose mode): triggers _printk logging of blocked "
            "signals with format 'kill_protect: %s/%d send signal %d to %s/%d is not allowed'."
        ),
        "disasm_evidence": [
            "0x5d3: mov eax, DWORD PTR [rip+sig_kill_protect]",
            "0x5dd: test eax, eax",
            "0x5df: jne 0x5fa    ; nonzero -> continue with protection",
            "0x5e1: xor r15d, r15d  ; return 0: allow kill",
            "init_module+0x66: mov esi, 0x1a4  ; mode=0644 for sysctl proc entry",
        ],
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "Blacklist capacity cap (127 entries) — DoS via blacklist exhaustion",
        "function": "blacklist_write",
        "addr": "0x2ab",
        "detail": (
            "blacklist_write at 0x2ab: mov eax, DWORD PTR [rip+blacklist_count]; cmp eax, 0x7f; "
            "jg 0x595 (returns error). Maximum 127 blacklist entries enforced. "
            "Any process with write access to /proc/kill_protect/blacklist can fill all 127 slots "
            "with garbage names, preventing legitimate protection entries from being added. "
            "The file permission on /proc/kill_protect/blacklist determines the attack surface. "
            "If writable by non-root, this is an unprivileged DoS against the protection subsystem."
        ),
        "disasm_evidence": [
            "0x2a5: mov eax, DWORD PTR [rip+blacklist_count]",
            "0x2ab: cmp eax, 0x7f    ; max 127 entries",
            "0x2ae: jg 0x595         ; full -> return error",
        ],
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Module unload race — hook vs. list free in cleanup_module",
        "function": "cleanup_module (.exit.text)",
        "addr": ".exit.text:0x10",
        "detail": (
            "cleanup_module (.exit.text at 0x10) first calls unregister_kill_hook, then traverses "
            "and frees all blacklist entries via kfree. However, a registered hook invocation "
            "may already be mid-execution in kill_protect_hook_func -> kill_protect_blacklist_match "
            "at the time unregister_kill_hook returns. If the hook is inside the rwlock-protected "
            "list traversal (at 0x60c-0x680) when the module unload frees those same list nodes, "
            "a use-after-free occurs on the blacklist entry structs. "
            "cleanup_module uses the 0xdead000000000100/0x122 poison pattern (movabs at .exit.text+0x57) "
            "for freed entries — indicating developer awareness of concurrent access — but there is "
            "no synchronize_rcu() or equivalent completion barrier between unregister_kill_hook "
            "and the list teardown."
        ),
        "disasm_evidence": [
            ".exit.text+0x1d: call unregister_kill_hook (reloc)",
            ".exit.text+0x2b: call remove_proc_subtree (reloc)",
            ".exit.text+0x57: movabs r13, 0xdead000000000100  ; poison next ptr",
            ".exit.text+0x61: movabs r12, 0xdead000000000122  ; poison prev ptr",
            ".exit.text+0x88: mov QWORD PTR [rbx+0x10], r13  ; poison and free entry",
            ".exit.text+0x96: call kfree (reloc)",
        ],
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "Struct layout: {list_head (16B) | char name[16]} = 32B per entry, kmalloc flags 0xdc0",
        "function": "blacklist_write",
        "addr": "0x2c5",
        "detail": (
            "kmalloc_trace(slab_cache, GFP_KERNEL|__GFP_RETRY_MAYFAIL=0xdc0, 0x20) allocates "
            "32 bytes per blacklist entry. Struct layout: bytes 0-7 = list.next, bytes 8-15 = list.prev, "
            "bytes 16-31 = char name[16]. Name stored via strncpy with max 15 bytes + explicit NUL "
            "at offset [r14 + strlen_or_15]. Matches TASK_COMM_LEN-1 (15 printable chars max in Linux). "
            "Stack buffer in blacklist_write: 64 bytes at [rsp+0x18], zeroed before strncpy_from_user, "
            "NUL terminated at min(count, 0x3f)-1. Stack canary present (__stack_chk_fail import)."
        ),
        "disasm_evidence": [
            "0x1a9: mov eax, 0x3f       ; strncpy_from_user max = 63",
            "0x2c5: call kmalloc_trace  ; size=0x20 (32 bytes), flags=0xdc0",
            "0x2de: mov edx, 0xf        ; name copy max = 15 bytes",
            "0x302: mov BYTE PTR [r14+rbx], 0  ; NUL terminate at copy length",
        ],
    },
]

FUNCTION_MAP = {
    "kill_protect_hook_func": {
        "addr": "0x780",
        "size": 42,
        "role": "signal_interception_hook",
        "description": (
            "Registered via register_kill_hook(). Called from TOS kernel do_send_sig_info() path. "
            "Checks signal == SIGKILL(9) OR SIGTERM(15); all other signals return 0 immediately. "
            "For SIGKILL/SIGTERM: calls kill_protect_blacklist_match(target_task, signal). "
            "Returns neg(match_result): 1->-1 (EPERM), 0->0 (allow). "
            "No capability check performed in this function."
        ),
    },
    "kill_protect_blacklist_match": {
        "addr": "0x5c0",
        "size": 425,
        "role": "name_comparison_with_friendly_fire_exemption",
        "description": (
            "1. Read sig_kill_protect sysctl; if 0, return 0 (unprotected). "
            "2. Acquire read lock (_raw_read_lock on blacklist rwlock). "
            "3. Traverse doubly-linked blacklist; for each entry: "
            "   a. strcmp(entry.name, current->comm) — check if sender is protected "
            "   b. If sender NOT in blacklist: strcmp(entry.name, target->comm) — check if target protected "
            "   c. If sender IS in blacklist AND target is also in some entry: allow kill (friendly-fire exemption) "
            "4. If target matched (and sender not also matched): return 1 (block kill). "
            "5. If sig_kill_protect==2: emit printk with sender/target pids and comms. "
            "6. Release read lock (lock xadd -0x200 pattern). "
            "Offset 0xe48 from task_struct = comm field (TOS kernel 6.6.119 layout)."
        ),
    },
    "blacklist_write": {
        "addr": "0x180",
        "size": 1062,
        "role": "procfs_write_handler",
        "description": (
            "Handles writes to /proc/kill_protect/blacklist. Protocol: 'add <name>' or 'del <name>'. "
            "strncpy_from_user(stack_buf, user_buf, min(count, 63)). "
            "NUL terminate at position [min(count,63)-1]. "
            "strsep twice to split command and name. "
            "Add path: check count<128, kmalloc(32, GFP_KERNEL|RETRY), strncpy(entry.name, name, 15). "
            "Del path: traverse list, strcmp match, unlink (list_del pattern), kfree. "
            "Write lock held during list modification. Stack canary active."
        ),
    },
    "stat_proc_show": {
        "addr": "0x10",
        "size": 57,
        "role": "procfs_read_handler_stat",
        "description": (
            "Handles reads from /proc/kill_protect/stat (or similar stat entry). "
            "Calls seq_printf twice: first with the sig_kill_protect sysctl value (edx=32-bit DWORD), "
            "then with a 'protect count: %lld' format and 64-bit blacklist count. "
            "Returns 0 (success). No locking visible; stats may race with blacklist modifications."
        ),
    },
}

if __name__ == '__main__':
    print(f"kill_protect.ko RE — {len(FINDINGS)} findings")
    for f in FINDINGS:
        print(f"  [{f['severity']:8s}] {f['id']}: {f['title']}")
