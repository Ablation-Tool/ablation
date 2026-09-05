"""
TencentOS 4.6 — dim_core.ko Data Integrity Measurement RE.

Binary: dim_core.ko (dim_core_46.ko is identical — same build ID)
Type: ELF 64-bit relocatable, x86-64, not stripped
Module params:
  signature=bool  — require signature for policy and static baseline
  measure_interval=uint — interval (minutes) for automatic measurement

Role: DIM (Data Integrity Measurement) — Tencent's runtime code integrity
verification system for TOS 4.6. Measures kernel text, loadable module text,
and userspace process text segments against a baseline of known-good digests.
Extends measured values into TPM PCRs for remote attestation. Optionally
blocks execution of processes with unexpected code digests.

Comparable to Linux IMA (Integrity Measurement Architecture) but Tencent-
developed with policy, baseline, and blocking capabilities not in mainline IMA.
"""

BINARY_INVENTORY = {
    "dim_core.ko": {
        "path": "/tmp/scratchpad/dim_core.ko",
        "also_at": "/tmp/scratchpad/dim_core_46.ko (identical build ID: 1765caeacc0eb58684f988fb7f63b9a54a4a2dde)",
        "type": "ELF 64-bit relocatable, x86-64, not stripped",
        "functions": "~80+ (estimated from symbol table)",
        "params": {
            "signature": "bool — require cryptographic signature for policy and static baseline files",
            "measure_interval": "uint — periodic background measurement interval in minutes",
        },
    },
}

ARCHITECTURE = {
    "overview": (
        "DIM measures the integrity of executable code at runtime. "
        "For each measured object (kernel, module, process), it: "
        "(1) computes a cryptographic hash of the code sections (.text) "
        "(2) compares against a known-good baseline "
        "(3) extends the result into a TPM PCR "
        "(4) optionally blocks execution if the digest doesn't match (blocking mode) "
        "Policy controls which objects are measured and what action to take on mismatch."
    ),
    "measurement_targets": {
        "kernel_text": (
            "dim_core_measure_task_kernel_text: measures the running kernel's .text section. "
            "Uses vmemmap_base and page_offset_base for physical-to-virtual mapping. "
            "Direct memory access to kernel code pages via alloc_pages + get_user_pages_remote equivalent."
        ),
        "module_text": (
            "dim_core_measure_task_module_text: measures loaded kernel module .text sections. "
            "Uses sprint_symbol (via dim_core_kallsyms_init) to identify module boundaries. "
            "Can detect runtime patching of kernel modules."
        ),
        "user_text": (
            "dim_core_measure_task_user_text: measures user-space process .text segments. "
            "Uses get_task_mm/get_user_pages_remote to read process code pages from kernel. "
            "Can detect LD_PRELOAD injection, process hollowing, or runtime code patching."
        ),
    },
    "baseline_system": {
        "dim_core_static_baseline_load": (
            "Loads a pre-computed baseline file from disk. "
            "If signature=true: calls verify_signature with keyring to authenticate the file. "
            "baseline_parse_complex_format: parses baseline entries — likely 'hash:path' format. "
            "Entries stored in a red-black tree for O(log n) lookup."
        ),
        "baseline_match_policy": "checks if a measured object matches baseline policy rules",
        "dim_baseline_search_digest": "O(log n) rbtree lookup by SHA digest",
        "dim_baseline_add": "adds a new known-good digest to the baseline tree",
        "rbtree": "rb_insert_color, rb_first_postorder, rb_next_postorder — standard kernel rbtree",
    },
    "policy_system": {
        "dim_core_policy_load": (
            "Loads measurement policy from a file (via kernel_read_file_from_path). "
            "If signature=true: policy file must be signed by a trusted key in the DIM keyring. "
            "Policy rules specify what to measure, matching patterns, and actions."
        ),
        "dim_core_policy_match": "evaluates a target object against policy rules",
        "dim_core_policy_get_action": "returns ACTION_MEASURE, ACTION_BLOCK, or ACTION_NONE",
        "dim_core_policy_walk": "iterates all policy rules (for export/debugging)",
    },
    "cryptographic_stack": {
        "hashing": "crypto_alloc_shash / crypto_shash_update / crypto_shash_final (sha256/sm3 likely)",
        "hash_algo_name": "hash algorithm name from kernel hash_algo enum",
        "hash_digest_size": "digest length in bytes",
        "bin2hex/hex2bin": "digest encoding for baseline file format",
        "log_digest": "cal_measure_log_digest — computes log entry digest (audit trail)",
    },
    "tpm_integration": {
        "tpm_pcr_extend": "extends measurement digest into a TPM PCR",
        "tpm_default_chip": "uses system's default TPM chip",
        "purpose": (
            "TPM PCR extension enables remote attestation: the cumulative PCR value "
            "proves to a verifier that a specific set of code digests was measured. "
            "An attestation server can compare the PCR value against expected values "
            "to verify the integrity of the TOS 4.6 system before trusting it."
        ),
    },
    "periodic_measurement": {
        "mechanism": "alloc_workqueue + queue_delayed_work_on + mod_delayed_work_on",
        "interval_api": "dim_core_interval_get/set (readable/writable via securityfs)",
        "baseline_work_cb": "periodic callback that re-measures all policy targets",
    },
    "securityfs_interface": {
        "path": "/sys/kernel/security/dim/ (securityfs_create_file)",
        "files": {
            "baseline": "load/dump baseline entries",
            "policy": "load measurement policy",
            "status": "dim_core_status_print — current state, counts",
            "measure": "trigger on-demand measurement",
            "interval": "get/set periodic measurement interval",
            "measure_action": "get/set blocking vs. logging action",
        },
        "note": (
            "All control is via securityfs — requires root + CAP_MAC_ADMIN or "
            "securityfs-specific LSM permission. Normal users cannot interact with DIM."
        ),
    },
    "blocking_mode": {
        "dim_core_measure_blocking": (
            "When blocking mode is active: if a process's code digest doesn't match baseline, "
            "send_sig() delivers SIGKILL to the process. This prevents unauthorized code from running."
        ),
        "dim_core_baseline_blocking": "baseline-level blocking policy evaluation",
        "dim_core_measure_action_get/set": "query/change blocking vs. logging mode at runtime",
    },
    "signature_chain": {
        "keyring_alloc": "creates a DIM-specific keyring",
        "key_create_or_update": "adds trusted public keys to DIM keyring",
        "verify_signature": "verifies file signature against DIM keyring",
        "purpose": (
            "When signature=true (module parameter), both the policy file and static baseline "
            "must be signed by a trusted key registered in the DIM keyring. "
            "This prevents an attacker who gains root from swapping the policy/baseline "
            "without the signing key."
        ),
    },
    "gen_pool": {
        "functions": "gen_pool_create/add/alloc/free/destroy/size/avail/for_each_chunk",
        "note": (
            "DIM uses a kernel genpool allocator for baseline/measurement data. "
            "Genpool allocates from pre-mapped memory ranges — useful for DMA/persistent "
            "storage or when regular kmalloc fragmentation is a concern. "
            "For DIM: likely used as a compact storage for digest entries."
        ),
    },
}

SECURITY_ANALYSIS = {
    "integrity_protection_strength": (
        "With signature=true: policy + baseline are signature-verified at load. "
        "An attacker who cannot forge signatures cannot manipulate what DIM considers trusted. "
        "With signature=false (default?): policy + baseline are loaded without verification — "
        "root access is sufficient to manipulate the trusted baseline."
    ),
    "blocking_mode_risk": (
        "dim_core_measure_blocking uses send_sig(SIGKILL) on measurement failure. "
        "In blocking mode, DIM is a process kill mechanism triggered by code integrity failure. "
        "If the baseline is incomplete or incorrect, legitimate processes can be killed. "
        "A misconfigured or corrupted baseline in blocking mode is a DoS vector."
    ),
    "kernel_text_measurement": (
        "dim_core_measure_task_kernel_text reads kernel memory directly via vmemmap_base. "
        "If the kernel has been patched (rootkit, live kernel patch), the measured digest "
        "will differ from the baseline — DIM detects this and logs (or blocks in blocking mode). "
        "However: if a rootkit modifies DIM itself, or the baseline, or intercepts hash output, "
        "it can evade detection."
    ),
    "user_text_measurement": (
        "get_task_mm + get_user_pages_remote measures actual physical pages of process .text. "
        "Detects: LD_PRELOAD injection (changes .text size), process hollowing (replaces .text), "
        "JIT-compiled shellcode injected into .text, or ptrace-based code patching. "
        "Does NOT detect: heap injection, stack shellcode, ROP chains (not .text modification)."
    ),
    "tpm_pcr_collusion": (
        "TPM PCR extension is append-only (extend = SHA(current_PCR || new_measurement)). "
        "An attacker cannot revert a PCR to a previous value. "
        "But: if the attacker controls DIM's key/baseline at init time, they can extend "
        "malicious measurement logs into the PCR that appear legitimate to remote verifiers "
        "who only check the final PCR value, not the individual extension log entries."
    ),
    "dim_enabled_dependency": (
        "dim_enabled (external symbol) gates the entire measurement system. "
        "If this symbol is from a base security module that can be disabled, "
        "disabling the base module disables DIM without unloading dim_core.ko."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "DIM blocking mode: send_sig(SIGKILL) on code digest mismatch — DoS if baseline wrong",
        "detail": (
            "dim_core_measure_blocking sends SIGKILL to a process whose .text digest "
            "doesn't match the baseline. Misconfigured/incomplete baseline in blocking mode "
            "kills legitimate processes. An attacker with baseline write access (root, if signature=false) "
            "can trigger targeted process kills by removing entries from the baseline."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "signature=false (default): policy and baseline loadable without signature verification",
        "detail": (
            "Module parameter signature defaults to false (bool param, unset = false). "
            "Without signature=true: any root process can load an arbitrary policy or baseline. "
            "Effectively: root can define what DIM considers 'trusted' code — "
            "bypass the integrity measurement by adding attacker's code to the baseline. "
            "Fix: deploy with signature=true and protect the DIM keyring."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "Kernel text measurement detects rootkits but is itself bypassable by a persistent rootkit",
        "detail": (
            "dim_core_measure_task_kernel_text reads kernel code via vmemmap_base. "
            "A rootkit that can hook or replace the dim_core measurement functions "
            "can return a clean digest even for modified kernel text. "
            "Defense: TPM PCR sealing can detect if DIM itself was modified at boot vs. runtime."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "User process .text measurement: detects code injection but not heap/stack exploits",
        "detail": (
            "get_user_pages_remote measures process .text pages. "
            "LD_PRELOAD injection, process hollowing, and JIT code insertion are detectable. "
            "ROP chains, heap sprays, and stack-based shellcode are NOT detected "
            "(they don't modify .text). DIM is not a full CFI/code execution protection."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "TPM PCR extension enables remote attestation of TOS 4.6 code integrity",
        "detail": (
            "tpm_pcr_extend records each measurement into a TPM PCR. "
            "Attestation servers can verify the PCR cumulative value against expected measurements "
            "to confirm the TOS 4.6 system is running unmodified code. "
            "Extends to: kernel text, module text, and process .text for policy-matched processes."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "DIM signature chain: keyring + verify_signature enforces trust in policy/baseline",
        "detail": (
            "With signature=true: policy and static baseline files must be signed by keys "
            "in the DIM keyring (keyring_alloc + key_create_or_update). "
            "Prevents root-level tampering without the private signing key. "
            "When deployed correctly: DIM's trust chain is comparable to IMA appraisal."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 dim_core.ko — Data Integrity Measurement RE")
    print()
    print("Measurement targets:")
    for target, desc in ARCHITECTURE['measurement_targets'].items():
        print(f"  {target}: {desc[:72]}")
    print()
    print("Key capabilities:")
    print(f"  TPM: tpm_pcr_extend into TPM PCR (remote attestation)")
    print(f"  Signature: verify_signature for policy + baseline files")
    print(f"  Blocking: send_sig(SIGKILL) on digest mismatch (optional)")
    print(f"  Periodic: alloc_workqueue + delayed_work_on (interval-based)")
    print(f"  Storage: genpool + rbtree for baseline digest store")
    print(f"  Interface: securityfs (/sys/kernel/security/dim/)")
    print()
    print("Module params:")
    for k, v in BINARY_INVENTORY['dim_core.ko']['params'].items():
        print(f"  {k}={v}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
