"""
TencentOS 4.6 — dim_monitor.ko reverse engineering module.

Binary: dim_monitor.ko
Source: /mnt/tos46_re (kernel/security/integrity/dim/, TOS 4.6 kernel 6.6.119-51.3.tl4.x86_64)
Size:   95KB ELF relocatable x86-64 NOT stripped
Depends: dim_core (TOS-specific module, not analyzed here)
Module params:
  measure_pcr:uint        — TPM PCR index to extend measurement log
  measure_hash:charp      — Hash algorithm for measurement
  measure_log_capacity:uint — Max number of measure log entries
Boot req: kernel cmdline must contain 'integrity=dim' (checked in dim_monitor_init)

Purpose: Dynamic Integrity Measurement for TOS. Measures:
  - Kernel module text sections (dim_measure_task_measure, module_text_measure)
  - Process executable files (dim_entry_create_list, dim_get_absolute_path)
  - Kernel symbols (dim_monitor_kallsyms_init, find_kernel_symbol, dim_get_symbol_lookup_func)
Against a baseline loaded from policy file. Baseline mismatches are logged and can trigger
blocking (dim_monitor_baseline_blocking) or monitoring-only mode.

Measurement results extend a TPM PCR (dim_tpm_pcr_extend) for remote attestation.
Measurement log exposed via procfs (dim_monitor_files: monitor_ascii_runtime_measurements).

Ablation semantic sweep: all-MiniLM-L6-v2, 66 functions encoded.
"""

METADATA = {
    "target": "TencentOS 4.6",
    "binary": "dim_monitor.ko",
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "arch": "x86-64",
    "stripped": False,
    "depends": "dim_core",
    "module_params": {
        "measure_pcr": "TPM PCR index (uint)",
        "measure_hash": "hash algorithm name (str)",
        "measure_log_capacity": "max log entries (uint)",
    },
    "hash_struct_hash_field_offset": 0x98,  # offset of hash data in baseline entry struct
    "policy_field_max_bytes": 0x2000,       # 8192 bytes max per policy field
}

SEMANTIC_SWEEP = {
    "model": "all-MiniLM-L6-v2",
    "corpus_size": 66,
    "top_results": {
        "baseline_bypass": {"score": 0.398, "name": "dim_hash_destroy"},
        "tpm_tamper": {"score": 0.447, "name": "measure_log_read_next"},
        "kallsyms_write": {"score": 0.290, "name": "dim_monitor_kallsyms_init"},
        "policy_parse": {"score": 0.293, "name": "dim_entry_create"},
        "hash_mismatch": {"score": 0.357, "name": "dim_measure_dynamic_baseline_search"},
        "toctou": {"score": 0.353, "name": "dim_measure_dynamic_baseline_search"},
    }
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "Static baseline ENOENT treated as success — unmeasured files bypass integrity check",
        "function": "dim_measure_process_static_result",
        "addr": "0x281f",
        "detail": (
            "dim_measure_process_static_result at 0x281f: cmp eax, 0xffffffef; je 0x283c. "
            "ENOENT (-17 = 0xffffffef) from the baseline search is treated identically to "
            "success (0). When a measurement target is not found in the static baseline, "
            "the function continues to 0x283c (static_baseline_search + add to baseline path) "
            "rather than reporting a violation. "
            "This implements 'learning mode': first-time measured files are added to the baseline. "
            "But the design flaw: if an attacker can cause an existing baseline entry to be "
            "evicted (via dim_baseline_destroy_tree during a baseline refresh triggered from "
            "procfs at dim_monitor_baseline_trigger), the next measurement cycle will treat "
            "the tampered file as NEW and add it to the baseline instead of detecting the "
            "modification. The window between baseline destroy and re-measurement is the attack surface."
        ),
        "disasm_evidence": [
            "0x2810: call dim_baseline_search (reloc)",
            "0x281a: test eax, eax",
            "0x281c: jns 0x283c      ; if >= 0 (found), go to baseline add",
            "0x281f: cmp eax, 0xffffffef  ; -ENOENT?",
            "0x2822: je 0x283c       ; if NOT FOUND: also go to baseline add (treat as success)",
            "0x2824: mov rdx, rbx",
            "0x282b: call dim_measure_status_error (reloc)  ; only OTHER errors are flagged",
        ],
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Hash algorithm code jump table — unchecked values above 19 fall to raw hash init",
        "function": "dim_baseline_match",
        "addr": "0x1b30",
        "detail": (
            "dim_baseline_match at 0x1b27: reads hash algo code from baseline descriptor "
            "(movsxd rax, DWORD PTR [rsi]). "
            "At 0x1b30: cmp eax, 0x13 (compare with 19); jbe 0x1b95 — if code <= 19, do jump table lookup. "
            "At 0x1b95: movsxd rdx, DWORD PTR [rax*4+reloc] — jump table with rax as unsigned index. "
            "If algo code >= 20 but < some max: falls through to generic hash init at 0x1b35 "
            "(add rsi, 0x4 / call hash_init). "
            "The jump table bounds: only 'jbe 0x13' is checked. Algorithm codes 20+ fall through "
            "without table lookup. If an unsupported code reaches the hash_init path, the init "
            "may succeed with wrong parameters or fail silently — in either case the measurement "
            "hash is invalid. "
            "The baseline policy file is loaded from user-space via the dim_monitor_baseline_trigger "
            "procfs handler (open+write to the baseline trigger file). A malformed policy with an "
            "invalid algorithm code will produce wrong measurements that don't match any real hash."
        ),
        "disasm_evidence": [
            "0x1b27: movsxd rax, DWORD PTR [rsi]    ; hash algorithm code",
            "0x1b30: cmp eax, 0x13                   ; 19 = max jump table index",
            "0x1b33: jbe 0x1b95                      ; <= 19 -> jump table",
            "0x1b35: add rsi, 0x4                    ; >= 20 -> raw init path",
            "0x1b39: lea rdi, [rsp+0x28]",
            "0x1b3e: call hash_init (reloc)",
            "0x1b95: movsxd rdx, DWORD PTR [rax*4+jump_table_reloc]  ; unchecked index",
        ],
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "TOCTOU: measurement window between baseline destroy and re-measurement",
        "function": "dim_monitor_baseline_trigger + dim_measure_process_static_result",
        "addr": "0x170",
        "detail": (
            "dim_monitor_baseline_trigger (0x170) is a procfs write handler that triggers "
            "a baseline refresh: calls baseline_prepare -> dim_baseline_destroy_tree -> "
            "repopulate from policy file. The destroy and repopulate are NOT atomic. "
            "During the window when the baseline tree is destroyed but not yet repopulated, "
            "ANY measurement will find ENOENT (F1) and add the current (potentially tampered) "
            "file to the new baseline rather than detecting tampering. "
            "Similarly, dim_measure_process_dynamic_result at 0x2950 has the same pattern. "
            "dim_measure_schedule (0x2fb0) can trigger a measurement at any time via delayed work. "
            "Race: trigger baseline_refresh (destroys tree) simultaneously with a scheduled "
            "measurement — measurement sees empty baseline, records tampered hash as trusted."
        ),
        "disasm_evidence": [
            "0x170: dim_monitor_baseline_trigger (procfs write handler)",
            "0x360: baseline_prepare -> calls dim_baseline_destroy_tree + repopulate",
            "0x1dc0: dim_baseline_destroy_tree (frees all rbtree nodes)",
            "0x2fb0: dim_measure_schedule -> calls queue_delayed_work (reloc)",
            "F1 path: empty tree = ENOENT = treated as 'new file' = added to baseline",
        ],
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "kallsyms-based symbol lookup — depends on unexported kernel function pointer",
        "function": "dim_get_symbol_lookup_func + find_kernel_symbol",
        "addr": "0x2200",
        "detail": (
            "dim_monitor_kallsyms_init (0x580) calls dim_get_symbol_lookup_func (0x2200) "
            "which calls find_kernel_symbol (0x2100). These functions resolve kernel symbol "
            "addresses using kallsyms lookup. find_kernel_symbol locates an unexported function "
            "(likely kallsyms_lookup_name or a TOS-internal symbol resolver) by name. "
            "If the kernel symbol layout changes (or if KALLSYMS_ALL is not enabled), "
            "dim_get_symbol_lookup_func will fail, and DIM initialization will fail entirely "
            "('fail to initialize dim kernel symbol: %d'). "
            "More critically: if an attacker can remap kernel symbols (e.g., via a writable "
            "kernel data page after an exploit), dim_monitor will measure using wrong addresses "
            "and TPM attestation will be silently invalidated."
        ),
        "disasm_evidence": [
            "0x580: dim_monitor_kallsyms_init",
            "0x2200: dim_get_symbol_lookup_func",
            "0x2100: find_kernel_symbol   ; reads symbol address from kallsyms",
            "init_module error path: '3%s: fail to initialize dim kernel symbol: %d'",
        ],
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Policy field size limit 8192 bytes — fields > 8192 trigger ENOMEM path",
        "function": "dim_parse_line_buf",
        "addr": "0xdd3",
        "detail": (
            "dim_parse_line_buf at 0xdd3: cmp rdi, 0x2000; ja 0xe91. "
            "If a policy field (space-delimited token within a line) exceeds 8192 bytes, "
            "jumps to 0xe91 which prints an error and returns -ENOMEM (-12). "
            "The field size rdi is computed as [field_end - field_start + 2]. "
            "If a very long line (no spaces or newlines for 8192+ bytes) reaches the field "
            "size check, the error path frees any previously allocated buffer (0xe91: _printk + return). "
            "This is a denial of service: a malformed policy file with 8193+ byte tokens "
            "will fail to load the baseline. Since dim_monitor requires a baseline to function, "
            "failing to load the baseline means all subsequent measurements return ENOENT (F1 path), "
            "adding every measured file to a new empty baseline — silently accepting all tampered files."
        ),
        "disasm_evidence": [
            "0xdd3: cmp rdi, 0x2000    ; field > 8192 bytes?",
            "0xdda: ja 0xe91           ; yes -> error",
            "0xe91: mov rsi, 0          ; _printk error",
            "0xe9f: call _printk (reloc)",
            "0xea4: mov eax, 0xfffffff4  ; return -ENOMEM",
        ],
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "dim_monitor_baseline_blocking vs dim_monitor_measure_blocking — separate lock paths",
        "function": "dim_monitor_baseline_blocking + dim_monitor_measure_blocking",
        "addr": "0x430 / 0x3e0",
        "detail": (
            "dim_monitor_baseline_blocking (0x430, 67b) and dim_monitor_measure_blocking (0x3e0, 64b) "
            "are two separate procfs handlers. Baseline blocking halts new baseline additions; "
            "measure blocking halts active measurements. These are independent state variables. "
            "If an attacker triggers dim_monitor_baseline_trigger while measure blocking is active "
            "but baseline blocking is not, the baseline can be destroyed and repopulated while "
            "measurements are suspended — opening a larger TOCTOU window than the normal race (F3). "
            "The state machine between these two blocking flags is not protected by a single lock."
        ),
        "disasm_evidence": [
            "0x3e0: dim_monitor_measure_blocking  (64b — sets measure suspend flag)",
            "0x430: dim_monitor_baseline_blocking (67b — sets baseline suspend flag)",
            "0x210: dim_monitor_measure_trigger   (141b — procfs write handler: triggers measurement)",
            "0x170: dim_monitor_baseline_trigger  (141b — procfs write handler: triggers refresh)",
        ],
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "Baseline entry hash at struct+0x98 — SHA-2/SM3 64-byte field",
        "function": "static_baseline_match.constprop.0 + dim_baseline_compare",
        "addr": "0x2710 / 0x1880",
        "detail": (
            "static_baseline_match.constprop.0 (0x2710): add rdi, 0x98 before compare. "
            "The baseline entry struct has the hash field at offset 0x98 (152 bytes from start). "
            "Struct layout (inferred from dim_baseline_compare traversal and kmalloc sizes): "
            "0x00: rb_node (24 bytes for rbtree embedding); "
            "0x18: algo_id (4 bytes); "
            "0x1c: padding; "
            "0x20-0x97: name/path fields (120 bytes); "
            "0x98-0xd7: hash data (64 bytes, SHA-512 or SM3). "
            "dim_baseline_compare.part.0 (0x17a0, 203b) does the actual hash comparison "
            "between measured hash and stored hash using memcmp equivalent."
        ),
        "disasm_evidence": [
            "0x2710: add rdi, 0x98       ; skip to hash field in baseline entry",
            "0x271f: xor edx, edx        ; no initial offset",
            "0x2721: jmp [reloc]         ; call hash compare",
            "0x17a0: dim_baseline_compare.part.0 (main comparison logic)",
            "0x1880: dim_baseline_compare (wrapper, 88b)",
        ],
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "TPM PCR extension path — dim_tpm_pcr_extend at 0x2010",
        "function": "dim_tpm_pcr_extend",
        "addr": "0x2010",
        "detail": (
            "dim_tpm_pcr_extend (0x2010, 135b) extends the TPM PCR specified by measure_pcr param. "
            "The extension hash is the aggregated dim_measure_log digest computed by cal_measure_log_digest. "
            "dim_tpm_init (0x1eb0, 331b) initializes the TPM context — if measure_pcr is 0 or "
            "TPM is absent, DIM still measures but doesn't extend. "
            "dim_tpm_destroy (0x20b0, 62b) tears down the TPM context on module exit. "
            "The TPM path is only reachable when measure_pcr > 0 and dim_tpm_init succeeds. "
            "If measure_pcr is set to a valid PCR index but the TPM PCR is already extended by "
            "another subsystem, the DIM measurement will XOR/hash-chain with the existing value "
            "and remote attestation becomes dependent on the other subsystem's state."
        ),
        "disasm_evidence": [
            "0x1eb0: dim_tpm_init",
            "0x2010: dim_tpm_pcr_extend",
            "0x20b0: dim_tpm_destroy",
        ],
    },
]

FUNCTION_MAP = {
    "dim_monitor_init": {
        "addr": ".init.text",
        "role": "module_initialization",
        "description": (
            "Checks 'integrity=dim' boot param. Calls: dim_monitor_kallsyms_init -> "
            "dim_measure_init (create measurement context, hash algorithm, log) -> "
            "dim_monitor_create_fs (create procfs entries: monitor_status, ascii_runtime_measurements) -> "
            "dim_measure_tasks_register (register measurement tasks for modules, processes, kernel symbols) -> "
            "dim_monitor_handle (initial measurement pass). "
            "Fails with error codes if any step fails."
        ),
    },
    "dim_measure_task_measure": {
        "addr": "0x2c80",
        "size": 310,
        "role": "per_target_measurement",
        "description": (
            "Main measurement loop. For each registered measurement task: "
            "call task->measure_func(entry) -> get hash of target. "
            "Call dim_measure_process_static_result or dim_measure_process_dynamic_result "
            "depending on mode. Log result via dim_measure_log_add. "
            "If result is VIOLATION: set measure status to error."
        ),
    },
    "dim_baseline_match": {
        "addr": "0x1aa0",
        "size": 260,
        "role": "baseline_lookup_and_compare",
        "description": (
            "Looks up a measured hash in the baseline rbtree. "
            "1. Null checks on all args. "
            "2. If hash type (edx) <= 3: return early with no-match. "
            "3. Read algo_id from hash descriptor [rsi]. "
            "4. If algo_id <= 0x13: jump table dispatch (20 algo codes supported). "
            "5. If algo_id > 0x13: raw hash init path. "
            "6. Traverse rbtree calling dim_baseline_compare per node. "
            "7. Return 1 if match found, 0 otherwise. "
            "Lock acquired via lock xadd pattern at 0x1b82 (similar to rcu readlock)."
        ),
    },
    "dim_parse_line_buf": {
        "addr": "0xd70",
        "size": 326,
        "role": "policy_file_parser",
        "description": (
            "Parses a policy file buffer line by line. "
            "Iterates over bytes looking for '\\n'. "
            "For each line: finds space-separated fields; field > 8192 bytes -> ENOMEM error. "
            "Calls line_callback(line_buf, line_num, out_ptr, private) per line. "
            "ENOENT from callback (-7 = 0xfffffff9) is treated as 0 (success) at 0xe68. "
            "Returns 0 on success, negative errno on error."
        ),
    },
}

if __name__ == '__main__':
    print(f"dim_monitor.ko RE — {len(FINDINGS)} findings")
    for f in FINDINGS:
        print(f"  [{f['severity']:8s}] {f['id']}: {f['title']}")
