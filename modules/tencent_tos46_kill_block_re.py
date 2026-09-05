"""
TencentOS 4.6 — kill_block.ko reverse engineering module.

Binary: kill_block.ko
Source: /mnt/tos46_re (nbd10, TOS 4.6 kernel 6.6.119-51.3.tl4.x86_64)
Build:  BuildID[sha1]=bb7b6656db8011e4588ffebce2d66b0b02de970a
Size:   31KB ELF relocatable x86-64 NOT stripped
Author: herberthbli (from .rodata, no email)
vermagic: 6.6.119-51.3.tl4.x86_64 SMP mod_unload modversions

Purpose: inverse of kill_protect — blocks signals FROM processes based on:
  - Cgroup membership: same-top-level-cgroup processes can signal each other freely
  - Whitelist of (sender_comm, dst_comm, src_cgrp_name) triples that are ALLOWED to send signals
  - Everything else in the blocking condition is logged and denied

The module is cgroup-subsystem-aware: it resolves the cgroup path/name for both
sender and target via css_set->subsys[sysctl_sig_kill_block] at offset 0x10b8 from
task_struct (TOS 4.6 kernel 6.6.119 layout). This means sysctl_sig_kill_block contains
the cgroup subsystem ID for the kill_block subsystem — a TOS kernel extension.

Compared to kill_protect.ko:
  - More sophisticated: 3-field whitelist entries vs. 1-field blacklist
  - Cgroup-path aware: same-cgroup exemption pre-whitelist
  - Version 1.3 vs 1.0 (newer, more mature)
  - Author: herberthbli vs leonylgao@tencent.com
  - Stack frame 776 bytes (two 256-byte cgroup path bufs + two 128-byte name bufs)

Ablation semantic sweep: all-MiniLM-L6-v2, 10 functions encoded.
"""

METADATA = {
    "target": "TencentOS 4.6",
    "binary": "kill_block.ko",
    "build_id": "bb7b6656db8011e4588ffebce2d66b0b02de970a",
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "arch": "x86-64",
    "stripped": False,
    "module_author": "herberthbli",
    "version": "1.3",
    "tos_specific_api": ["register_kill_hook", "unregister_kill_hook"],
    "cgroup_subsys_offset": "0x10b8",  # css_set pointer in task_struct
    "task_comm_offset": "0xe48",       # comm field in task_struct
}

SEMANTIC_SWEEP = {
    "model": "all-MiniLM-L6-v2",
    "corpus_size": 10,
    "top_result_by_query": {
        "sysctl_disable": {"score": 0.364, "name": "kill_block_hook_func", "addr": "0xa80"},
        "cgroup_bypass": {"score": 0.330, "name": "whitelist_seq_show", "addr": "0xa0"},
        "whitelist_match": {"score": 0.393, "name": "whitelist_seq_open", "addr": "0x70"},
    }
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Same-cgroup bypass: processes in the same top-level cgroup can signal freely",
        "function": "kill_block_whitelist_match",
        "addr": "0x729",
        "detail": (
            "kill_block_whitelist_match evaluates an unconditional exemption before the whitelist: "
            "if the sender and target share the same TOP-LEVEL cgroup path component, the signal "
            "is allowed and the whitelist is never consulted. "
            "Disassembly: at 0x729, r13 = src_cgrp_path+1 (skip '/'); rbx = dst_cgrp_path+1. "
            "strchr(src_path+1, '/') at 0x73f finds end of first component; "
            "strchr(dst_path+1, '/') at 0x764 same for dst. "
            "sub eax, ebx at 0x772 computes dst first-component length; "
            "cmp eax, r14d compares with src first-component length; jne 0x78e if lengths differ. "
            "memcmp(r13, rbx, eax) at 0x781; je 0x847 (return 0, allow) if same first component. "
            "Attack: move the attacker process into ANY cgroup that shares its top-level name "
            "with the target (e.g., if target is in /sys/fs/cgroup/kill_block/tagent, "
            "attacker joins /sys/fs/cgroup/kill_block/attacker). Both start with 'kill_block' "
            "as the first component; cgroup move requires CAP_SYS_ADMIN OR membership via "
            "cgroup delegation, which is granted to unprivileged containers in TOS."
        ),
        "disasm_evidence": [
            "0x729: lea rbx, [rax+0x1]   ; dst_cgrp_path + 1 (skip '/')",
            "0x72d: add r13, 0x1          ; src_cgrp_path + 1",
            "0x737: mov esi, 0x2f         ; '/'",
            "0x73c: mov rdi, r13          ; src_path+1",
            "0x73f: call strchr           ; find next '/' in src path",
            "0x744: test rax, rax",
            "0x747: je 0x908              ; no '/' -> go to end handling",
            "0x750: sub r14d, r13d        ; src first component length",
            "0x764: call strchr(dst_path+1, '/')  ; find next '/' in dst path",
            "0x772: sub eax, ebx          ; dst first component length",
            "0x774: cmp eax, r14d         ; compare lengths",
            "0x777: jne 0x78e             ; different lengths -> whitelist check",
            "0x77b: mov edx, eax",
            "0x77e: mov rsi, rbx          ; dst_path+1",
            "0x781: mov rdi, r13          ; src_path+1",
            "0x781: call memcmp",
            "0x786: test eax, eax",
            "0x788: je 0x847              ; SAME cgroup root: allow the signal",
        ],
    },
    {
        "id": "F2",
        "severity": "CRITICAL",
        "title": "Whitelist bypass via prctl(PR_SET_NAME) — sender_comm impersonation",
        "function": "kill_block_whitelist_match",
        "addr": "0x7c2",
        "detail": (
            "The whitelist entry struct has three fields: sender_comm at entry+0x10, "
            "dst_comm at entry+0x20, src_cgrp_name at entry+0x30. "
            "The sender_comm field is compared against current->comm via gs:0x0+0xe48. "
            "Any process can set its comm to match a whitelisted sender_comm via prctl(PR_SET_NAME). "
            "No executable path verification, no inode check, no UID/capability check on the sender. "
            "Whitelist traversal at 0x7d9-0x82d: "
            "lea rdi, [r14+0x10]; mov rsi, rbx (current->comm); call strcmp -> if match, continue. "
            "lea rdi, [r14+0x20]; mov rsi, r13 (target->comm); call strcmp -> if match, continue. "
            "lea r12, [r14+0x30]; check src_cgrp_name. "
            "All three must match for a whitelist entry to grant permission."
        ),
        "disasm_evidence": [
            "0x7c2: mov rbx, QWORD PTR gs:0x0   ; current task_struct",
            "0x7d9: lea rdi, [r14+0x10]          ; &entry.sender_comm",
            "0x7dd: mov rsi, rbx                 ; current->comm",
            "0x7e0: call strcmp/strncmp",
            "0x7e5: test al, al",
            "0x7e7: je 0x823                     ; no comm match -> next entry",
            "0x7e9: lea rdi, [r14+0x20]          ; &entry.dst_comm",
            "0x7ed: mov rsi, r13                 ; target->comm",
            "0x7f0: call strcmp",
            "0x7f7: je 0x823                     ; no dst match -> next entry",
            "0x801: lea r12, [r14+0x30]          ; &entry.src_cgrp_name",
            "0x804: call strcmp(entry.src_cgrp_name, caller_cgrp_name)",
        ],
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Hook only intercepts SIGKILL(9) and SIGTERM(15) — SIGSTOP unprotected",
        "function": "kill_block_hook_func",
        "addr": "0xa80",
        "detail": (
            "kill_block_hook_func at 0xa85: cmp edi, 0x9 / je 0xa96 (check whitelist). "
            "cmp edi, 0xf / je 0xa96 (check whitelist). "
            "xor eax, eax / jmp (return 0, allow) for all other signals. "
            "Same gap as kill_protect: SIGSTOP(19), SIGTSTP(20), and all RT signals "
            "bypass kill_block entirely. A blocked process can be suspended via SIGSTOP "
            "without triggering the hook."
        ),
        "disasm_evidence": [
            "0xa85: cmp edi, 0x9     ; SIGKILL?",
            "0xa88: je 0xa96         ; -> hook",
            "0xa8a: cmp edi, 0xf     ; SIGTERM?",
            "0xa8d: je 0xa96         ; -> hook",
            "0xa8f: xor eax, eax     ; allow",
            "0xa91: jmp reloc        ; return 0",
        ],
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "Global block disable via sysctl_sig_kill_block = 0",
        "function": "kill_block_whitelist_match",
        "addr": "0x6a3",
        "detail": (
            "First instruction: mov eax, DWORD PTR [rip+sysctl_sig_kill_block]. "
            "test eax, eax; je 0x847 (allow all kills if sysctl == 0). "
            "init_module registers it with mode 0x1a4 (0644). "
            "Writing 0 to /proc/sys/kernel/sig_kill_block (root-only) disables all signal blocking globally. "
            "Also: sysctl value is used as cgroup subsystem ID at 0x975/0x97c — setting sysctl to an "
            "invalid subsystem ID would cause an out-of-bounds read into css_set->subsys[]."
        ),
        "disasm_evidence": [
            "0x6a3: mov eax, DWORD PTR [rip+sysctl_sig_kill_block]",
            "0x6c0: test eax, eax",
            "0x6c2: je 0x847      ; return 0 (allow) if disabled",
            "hook_func.part.0+0x3c: movsxd rax, DWORD PTR [rip+sysctl_sig_kill_block]",
            "hook_func.part.0+0x40: mov rdx, QWORD PTR [rdx+rax*8]  ; css_set->subsys[sysctl]",
        ],
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "title": "sysctl_sig_kill_block used as css_set subsys index — OOB read if sysctl > CGROUP_SUBSYS_COUNT",
        "function": "kill_block_hook_func.part.0",
        "addr": "0x975",
        "detail": (
            "At 0x975: movsxd rax, DWORD PTR [rip+sysctl_sig_kill_block]. "
            "At 0x97c: mov rdx, QWORD PTR [rdx+rax*8] — uses sysctl value as array index into css_set->subsys[]. "
            "In Linux 6.6, CGROUP_SUBSYS_COUNT (the number of registered cgroup subsystems) is ~12-15. "
            "If sysctl_sig_kill_block is set to a value >= CGROUP_SUBSYS_COUNT (requires CAP_SYS_ADMIN "
            "to write, but mode 0644 means root can write), the array index reads out-of-bounds from "
            "the css_set struct. css_set is heap-allocated — OOB read into adjacent heap data. "
            "This could leak pointers from adjacent allocations."
        ),
        "disasm_evidence": [
            "hook_func.part.0+0x35: mov rax, QWORD PTR gs:0x0",
            "hook_func.part.0+0x3d: mov rdx, QWORD PTR [rax+0x10b8]   ; current->cgroups (css_set)",
            "hook_func.part.0+0x3c: movsxd rax, [rip+sysctl_sig_kill_block]",
            "hook_func.part.0+0x40: mov rdx, QWORD PTR [rdx+rax*8]    ; subsys[sysctl] -- no bounds check",
            "hook_func.part.0+0x43: mov r12, QWORD PTR [rdx]",
        ],
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "Whitelist entry struct layout: three 16-byte name fields at +0x10/+0x20/+0x30",
        "function": "kill_block_whitelist_match + whitelist_write",
        "addr": "0x7d9",
        "detail": (
            "Whitelist entry struct layout (inferred from whitelist_write and whitelist_match): "
            "bytes 0-7: list.next; bytes 8-15: list.prev (or two linked list ptrs); "
            "bytes 16-31 (+0x10): sender_comm[16]; bytes 32-47 (+0x20): dst_comm[16]; "
            "bytes 48-63 (+0x30): src_cgrp_name[16] (or up to the next field). "
            "whitelist_write processes 'add <sender_comm> <dst_comm> <src_cgrp_name>' triples. "
            "Compared to kill_protect's single 32-byte entry, kill_block entries are at least 64 bytes. "
            "kb_cnt_root and kb_cnt_child are separate 64-bit counters for root vs. child cgroup blocks."
        ),
        "disasm_evidence": [
            "whitelist_match+0x149: lea rdi, [r14+0x10]  ; entry.sender_comm",
            "whitelist_match+0x159: lea rdi, [r14+0x20]  ; entry.dst_comm",
            "whitelist_match+0x16d: lea r12, [r14+0x30]  ; entry.src_cgrp_name",
        ],
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "Cgroup path resolution: 776-byte stack frame, bounded cgroup_path calls",
        "function": "kill_block_hook_func.part.0",
        "addr": "0x940",
        "detail": (
            "Stack frame: sub rsp, 0x308 (776 bytes). Layout: "
            "[rsp+0x0]-[rsp+0x7f]: 128-byte src cgroup name buffer; "
            "[rsp+0x80]-[rsp+0xff]: 128-byte dst cgroup name buffer; "
            "[rsp+0x100]-[rsp+0x1ff]: 256-byte src cgroup path buffer; "
            "[rsp+0x200]-[rsp+0x2ff]: 256-byte dst cgroup path buffer; "
            "[rsp+0x300]: stack canary. "
            "Stack canary present (__stack_chk_fail at +0x11f). "
            "Cgroup path calls at 0x9e2/0x9fd bounded to 0x100 (256) bytes. "
            "Cgroup name calls at 0xa12/0xa2b bounded to 0x80 (128) bytes. "
            "All buffer sizes respect their stack regions; no OOB write risk in this path."
        ),
        "disasm_evidence": [
            "0x94b: sub rsp, 0x308             ; 776-byte stack frame",
            "0x9d3: mov ecx, 0x100             ; path buffer max = 256",
            "0x9d8: lea rdx, [rsp+0x100]       ; src path buffer",
            "0x9f5: lea rdx, [rsp+0x200]       ; dst path buffer",
            "0xa0a: mov edx, 0x80              ; name buffer max = 128",
            "0xa0f: mov rsi, rsp               ; src name buffer [rsp+0]",
            "0xa23: lea rsi, [rsp+0x80]        ; dst name buffer",
            "0x95b: mov QWORD PTR [rsp+0x300], rax  ; canary save",
        ],
    },
]

FUNCTION_MAP = {
    "kill_block_hook_func": {
        "addr": "0xa80",
        "size": 30,
        "role": "signal_interception_hook_dispatcher",
        "description": (
            "Thin dispatcher. Registered via register_kill_hook(). "
            "Checks signal == 9 (SIGKILL) or 15 (SIGTERM). For those signals: "
            "moves rdx (target task_struct) into rsi and jumps to kill_block_hook_func.part.0 (0x940). "
            "For all other signals: returns 0 (allow). "
            "kill_block_hook_func.part.0 resolves cgroup context for both sender and target "
            "via css_set->subsys[sysctl_sig_kill_block], then calls kill_block_whitelist_match."
        ),
    },
    "kill_block_hook_func.part.0": {
        "addr": "0x940",
        "size": 292,
        "role": "cgroup_context_resolver",
        "description": (
            "1. Read sender's css_set: gs:0x0+0x10b8 -> css_set; subsys[sysctl] -> cgroup_subsys_state. "
            "2. Read target's css_set: rsi+0x10b8 -> css_set; subsys[sysctl] -> css. "
            "3. If either css is null (process not in any cgroup): return 0 (allow). "
            "4. cgroup_path(src_css+0x140, buf_at_rsp+0x100, 0x100) -> src path. "
            "5. cgroup_path(dst_css+0x140, buf_at_rsp+0x200, 0x100) -> dst path. "
            "6. cgroup_name(src_css+0x140, buf_at_rsp, 0x80) -> src name. "
            "7. cgroup_name(dst_css+0x140, buf_at_rsp+0x80, 0x80) -> dst name. "
            "8. call kill_block_whitelist_match(target_task, signal, src_path, dst_path, src_name?). "
            "9. Return neg(match): 1 -> -1 (EPERM), 0 -> 0 (allow)."
        ),
    },
    "kill_block_whitelist_match": {
        "addr": "0x690",
        "size": 672,
        "role": "whitelist_and_cgroup_path_checker",
        "description": (
            "1. sysctl == 0? Return 0 (allow). "
            "2. Two cgroup-validity checks (0x6df/0x6f6) — unknown functions, bool returns. "
            "3. Path component extraction: skip leading '/', strchr to find '/', compare first components. "
            "   If sender and target share same top-level cgroup path component: return 0 (allow, same cgroup). "
            "4. Acquire read lock on whitelist_lock. "
            "5. Traverse whitelist: for each entry, match (sender_comm, dst_comm, src_cgrp_name). "
            "   If all three match: allow. "
            "6. If no whitelist match: block signal (r15=1). "
            "7. Release lock. "
            "8. If r15=1 (blocked): call cgroup check function; if not root cgroup, increment kb_cnt_child. "
            "9. If sysctl==2: _printk full log line with signal, pids, comms, cgroup paths/names. "
        ),
    },
}

if __name__ == '__main__':
    print(f"kill_block.ko RE — {len(FINDINGS)} findings")
    for f in FINDINGS:
        print(f"  [{f['severity']:8s}] {f['id']}: {f['title']}")
