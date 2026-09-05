"""
TencentOS 4.6 — dim_core.ko kernel module reverse engineering.

Source: /mnt/tos46_re/usr/lib/modules/6.6.119-51.3.tl4.x86_64/kernel/security/integrity/dim/dim_core.ko.xz
Extracted to scratchpad, decompressed (183KB ELF relocatable).

dim_core is TOS's Dynamic Integrity Measurement kernel module.
It measures running processes, kernel text, and loaded modules against a
hash baseline, and can SIGKILL processes whose text diverges from baseline.

Module info:
  name:        dim_core
  license:     GPL
  vermagic:    6.6.119-51.3.tl4.x86_64 SMP mod_unload modversions
  sig_id:      PKCS#7
  signer:      Tkernel signing key
  sig_key:     01:9D:01:14:84:D7
  sig_hashalgo: sha256
  intree:      Y
  retpoline:   Y
  srcversion:  32EB1C75A74D042FBAF570D

Activation gate:
  Requires kernel boot parameter 'integrity=dim'.
  Without it: prints "dim_core: boot parameter 'integrity=dim' not set." and exits init.

Symbol count: 271 (NOT stripped — full debug symbols retained in .ko)
"""

METADATA = {
    "module": "dim_core",
    "source": "/usr/lib/modules/6.6.119-51.3.tl4.x86_64/kernel/security/integrity/dim/dim_core.ko.xz",
    "size_bytes": 183 * 1024,
    "arch": "x86-64",
    "stripped": False,
    "function_count": 271,
    "signer": "Tkernel signing key",
    "sig_key_fingerprint": "01:9D:01:14:84:D7",
}

MODULE_PARAMS = {
    "measure_log_capacity": {
        "type": "uint",
        "desc": "Max number of entries in measurement log",
        "sysfs": "/sys/module/dim_core/parameters/measure_log_capacity",
    },
    "measure_schedule": {
        "type": "uint",
        "desc": "Schedule time (ms) for each measure object",
        "sysfs": "/sys/module/dim_core/parameters/measure_schedule",
    },
    "measure_hash": {
        "type": "charp",
        "desc": "Hash algorithm for measurement (string, e.g. 'sha256')",
        "sysfs": "/sys/module/dim_core/parameters/measure_hash",
    },
    "measure_pcr": {
        "type": "uint",
        "desc": "TPM PCR index to extend measurement log into",
        "sysfs": "/sys/module/dim_core/parameters/measure_pcr",
    },
    "measure_interval": {
        "type": "uint",
        "desc": "Interval time (min) for automatic measurement",
        "sysfs": "/sys/module/dim_core/parameters/measure_interval",
    },
    "signature": {
        "type": "bool",
        "desc": "Require PKCS#7 signature for policy and static baseline files",
        "sysfs": "/sys/module/dim_core/parameters/signature",
        "security_note": (
            "When signature=N (false), dim_core accepts unsigned policy and "
            "baseline files. Anyone who can write policy/baseline paths AND "
            "flip this param (requires CAP_SYS_ADMIN or writable sysfs) "
            "can bypass the integrity verification chain entirely."
        ),
    },
}

EXPORTED_GPL_SYMBOLS = [
    "dim_mem_pool_walk_chunk",
    "dim_root_entry",
]

IMPORTED_KERNEL_SYMBOLS = {
    "dim_enabled": "External control gate — if 0, module init fails. Likely exported by the kernel or a companion module. Writing 0 to this symbol (via /proc/kallsyms + /dev/mem or kernel module) disables DIM.",
    "verify_signature": "PKCS#7 verification for policy/baseline file authentication",
    "send_sig": "Used by kill_task to deliver SIGKILL to tampered processes",
    "tpm_pcr_extend": "TPM PCR extension for measurement log anchoring",
    "sprint_symbol": "Kernel symbol name resolution (kallsyms bridge)",
    "kernel_read_file": "Reads policy/baseline files from kernel context",
    "get_user_pages_remote": "Accesses remote process VM pages for text measurement",
    "key_create_or_update": "Keyring management for DIM certificate store",
}

POLICY_OBJECT_TYPES = [
    "BPRM_TEXT",    # process text on exec (bprm = binary parameters)
    "MODULE_TEXT",  # loaded kernel module text
    "KERNEL_TEXT",  # running kernel text
]

POLICY_CONSTRAINTS = {
    "BPRM_TEXT": {
        "required": "path",
        "ignored": "name (warning logged)",
        "action": "KILL if tampered",
    },
    "MODULE_TEXT": {
        "required": "name",
        "ignored": "path, action (warnings logged)",
    },
    "KERNEL_TEXT": {
        "note": "all parameters ignored (warning logged)",
    },
}

FUNCTION_ANALYSIS = {
    "kill_task": {
        "addr": "0x22c0",
        "size": 73,
        "disasm_summary": [
            "22c8: mov rax, gs:0x0         ; current task_struct ptr",
            "22d1: cmp rdi, rax            ; target == current?",
            "22d4: je  22ef               ; if yes: skip kill (log 'don't kill current process')",
            "22d6: mov edx, 0x1            ; flags",
            "22db: mov edi, 0x9            ; SIGKILL",
            "22e0: call send_sig           ; deliver SIGKILL to target task",
            "22ef: mov rsi, 0x0            ; (log path — print pid=1 exempt msg if needed)",
        ],
        "kill_exemptions": [
            "target task == current (executing) task",
            "target task pid == 1 (init/systemd exempt)",
        ],
        "note": (
            "PID 1 exemption is a design choice to avoid kernel panic. "
            "A tampered systemd/init is DETECTED but not killed — "
            "dim_core logs the tamper but cannot act on it."
        ),
    },
    "dim_core_sig_verify": {
        "addr": "0x1280",
        "size": 259,
        "disasm_summary": [
            "12fa: test r8, r8             ; null check: file ptr",
            "12fd: je   1377              ; return -ENOENT if null",
            "1305: je   1377              ; return -ENOENT if data null",
            "1307: lea rcx, [rsp+0x4]     ; prepare sig_size output ptr",
            "1316: call <parse_sig_header> ; extract PKCS#7 sig header",
            "1339: cmp eax, 0x13          ; sig_size > 0x13 (19 bytes)?",
            "133c: jbe  136e              ; if <= 19: use error table lookup",
            "1345: call verify_signature  ; full PKCS#7 verification",
        ],
        "min_sig_size": 19,
        "note": "Signatures shorter than 20 bytes trigger error table path, not verification.",
    },
    "dim_core_kallsyms_init": {
        "addr": "0x1080",
        "note": (
            "Initializes the kallsyms bridge used by kernel_text_measure. "
            "dim_core calls sprint_symbol for symbol resolution. "
            "If kallsyms is disabled (CONFIG_KALLSYMS=n), this fails at init."
        ),
    },
    "check_process_digest": {
        "addr": "0x2100",
        "note": (
            "Core user-text measurement comparison. Hashes process VMAs "
            "and compares against baseline. On mismatch: logs tamper event, "
            "calls kill_task if action=KILL in policy."
        ),
    },
    "baseline_match_policy": {
        "addr": "0x3690",
        "disasm_summary": [
            "36b8: cmp r12d, 0x1           ; policy type == BPRM_TEXT (type=1)?",
            "36bc: jne 370a               ; non-BPRM: use simpler match",
            "36c3: call <match_name>       ; BPRM: match binary name",
            "36d5: test eax, eax",
            "36d7: je  3730               ; no match: return (type=MODULE, name=null)",
            "36d9: lea eax, [rbp+0x2]     ; rbp = path_len",
            "36dc: cmp eax, r13d          ; check path component count",
            "36f7: cmp BYTE PTR [rbx+rbp], 0x2f ; check for '/' separator",
        ],
        "note": "Policy matching uses prefix path matching. No glob/regex support.",
    },
    "dim_tpm_pcr_extend": {
        "addr": "see dim_tpm_pcr_extend",
        "note": (
            "Extends TPM PCR with SHA256 of measurement log entry. "
            "Uses tpm_pcr_extend kernel call. If TPM unavailable, "
            "extension silently fails — DIM continues without TPM anchoring. "
            "measure_pcr parameter defaults to a specific PCR index (not verified from strings)."
        ),
    },
}

BASELINE_FILE_FORMAT = {
    "location": "/etc/dim/policy (policy); /etc/dim/static_baseline (baseline)",
    "signature_file": ".sig extension co-located with policy/baseline",
    "format": "One entry per line: <type> <algo> <digest> <name>",
    "algorithms": "Any kernel-supported shash (sha256, sha512, sm3)",
    "baseline_prefix": "DIM_BASELINE_KERNEL (for kernel type)",
    "parse_limits": "Max items per file (exact count from param or default)",
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "signature=N module param disables PKCS#7 verification for policy and baseline",
        "detail": (
            "dim_core has a module param 'signature' (bool) at "
            "/sys/module/dim_core/parameters/signature. "
            "When set to N/false, dim_core skips PKCS#7 signature verification "
            "for both the policy file (/etc/dim/policy) and static baseline file "
            "(/etc/dim/static_baseline). "
            "An attacker with CAP_SYS_ADMIN (or writable sysfs) and write access "
            "to /etc/dim/ can: "
            "(1) flip signature=N, "
            "(2) replace baseline with a file containing attacker-controlled digests, "
            "(3) trigger a re-measure — dim_core now considers the attacker's binary 'clean'. "
            "This completely subverts the integrity measurement chain."
        ),
        "bypass_steps": [
            "echo N > /sys/module/dim_core/parameters/signature",
            "cp <attacker_baseline> /etc/dim/static_baseline",
            "echo 1 > /sys/kernel/security/dim/trigger",
        ],
        "prerequisite": "CAP_SYS_ADMIN",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "dim_enabled external symbol import — disabling it prevents DIM initialization",
        "detail": (
            "dim_core imports 'dim_enabled' from the kernel symbol table. "
            "At init_module, if dim_enabled evaluates to false/0, initialization aborts. "
            "This symbol is NOT defined in dim_core itself — it is exported by the kernel "
            "or a companion module. "
            "On a live system, if an attacker can patch this symbol's memory location "
            "(via kernel module with direct ksym write, or /dev/mem if available), "
            "dim_core init will fail silently and no measurement occurs. "
            "Also: boot parameter 'integrity=dim' is the primary gate — "
            "removing this from GRUB cmdline (requires /boot/grub2/grubenv write) "
            "prevents dim_core from activating at next boot."
        ),
        "boot_gate_cmdline": "integrity=dim",
        "boot_gate_file": "/boot/grub2/grubenv",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "PID 1 exempted from kill_task — tampered init/systemd is detected but not remediated",
        "detail": (
            "kill_task() at 0x22c0 explicitly exempts PID 1 from SIGKILL. "
            "String evidence: '4%s: the pid of tampered task is 1, don't kill it'. "
            "Design rationale: killing PID 1 would trigger kernel panic. "
            "Security consequence: if an attacker replaces systemd/init text "
            "(via writable memory mapping or kernel page modification), "
            "dim_core will log the tamper event and extend the TPM PCR, "
            "but systemd continues running. "
            "The tamper is RECORDED but not STOPPED."
        ),
        "exempt_pids": [1],
        "exempt_condition": "target task_struct == current (self-exemption also present)",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "KERNEL_TEXT policy type ignores all parameters — unmeasurable via policy",
        "detail": (
            "When policy obj type is KERNEL_TEXT, dim_core logs "
            "'all parameters are ignored for KERNEL_TEXT policy'. "
            "KERNEL_TEXT measurement is always-on when the module is active — "
            "there is no policy-level opt-out. "
            "This means kernel text measurement cannot be disabled via policy file modification "
            "without also flipping the signature param (F1) and replacing the baseline (F1). "
            "Conversely, BPRM_TEXT requires 'path' — if path is missing, "
            "the policy line is rejected with error, not silently ignored."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Min signature size check in dim_core_sig_verify: sig ≤ 19 bytes routes to error table",
        "detail": (
            "At 0x1339 in dim_core_sig_verify: 'cmp eax, 0x13; jbe 136e'. "
            "If the parsed signature size is <= 19 bytes, execution jumps to an error "
            "table path (mov edx, DWORD PTR [rax*4+0x0]) rather than calling verify_signature. "
            "A crafted .sig file with a 19-byte or shorter stub may produce a predictable "
            "error return rather than a verification failure, depending on what the error "
            "table path returns. If the error path returns success, a truncated sig passes. "
            "Full verification requires disassembly of the error table at 0x136e."
        ),
        "sig_size_threshold": 19,
        "jump_target": "0x136e (error table lookup, not verify_signature)",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "DIM policy uses prefix path matching — no glob support",
        "detail": (
            "baseline_match_policy at 0x3690 performs prefix-based path matching. "
            "BPRM_TEXT policies match on binary name prefix + '/' separator check. "
            "No glob, wildcard, or regex support is present. "
            "An attacker placing a binary at a path that matches only the prefix "
            "(e.g. /usr/bin/ssh_backdoor matching a /usr/bin/ policy prefix) "
            "would be measured. However, a binary placed at a path NOT covered "
            "by any policy line is not measured at all."
        ),
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "TPM PCR extension via tpm_pcr_extend — measurement log anchored to TPM",
        "detail": (
            "dim_core calls tpm_pcr_extend at dim_tpm_pcr_extend. "
            "measure_pcr parameter specifies the PCR index. "
            "If no TPM is available (tpm_default_chip returns null), "
            "PCR extension fails but dim_core continues. "
            "Measurement is RECORDED in the in-memory log but NOT TPM-anchored. "
            "On a VM or container without a vTPM, the measurement log provides "
            "no cryptographic binding — log entries can be replayed or replaced "
            "in memory without TPM attestation failing."
        ),
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "dim_core signed by 'Tkernel signing key' — TOS-specific module signing chain",
        "detail": (
            "modinfo shows: sig_id=PKCS#7, signer='Tkernel signing key', "
            "sig_key=01:9D:01:14:84:D7. "
            "TOS uses a separate kernel module signing key from upstream RHEL/CentOS. "
            "The 'Tkernel signing key' is not publicly disclosed. "
            "If the private key is compromised, unsigned modules can be signed "
            "with this key and loaded on any TOS 4.6 system with Secure Boot "
            "trusting the Tencent key. "
            "Cert fingerprint 01:9D:01:14:84:D7 can be used to identify the "
            "signing certificate in the TOS trust store."
        ),
        "signing_key_fingerprint": "01:9D:01:14:84:D7",
        "sig_algorithm": "sha256",
    },
]

if __name__ == '__main__':
    print(f"dim_core.ko — {len(FINDINGS)} findings")
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
    print()
    print("Module params (potential bypass surfaces):")
    for k, v in MODULE_PARAMS.items():
        note = v.get('security_note', '')
        flag = ' *** BYPASS ***' if note else ''
        print(f"  {k} ({v['type']}): {v['desc']}{flag}")
    print()
    print("kill_task exemptions:", FUNCTION_ANALYSIS['kill_task']['kill_exemptions'])
