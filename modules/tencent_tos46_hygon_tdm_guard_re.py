"""
TencentOS 4.6 — Hygon tdm-kernel-guard.ko reverse engineering.

Source: /mnt/tos46_re/usr/lib/modules/6.6.119-51.3.tl4.x86_64/kernel/drivers/crypto/ccp/hygon/tdm-kernel-guard.ko.xz
Extracted: 24686 bytes, ELF relocatable, GPL

tdm-kernel-guard is a Hygon-authored kernel module that uses Hygon's PSP
(Platform Security Processor) Trusted Dynamic Measurement (TDM) capability
to hardware-measure and detect tampering of the kernel syscall table (SCT)
and Interrupt Descriptor Table (IDT) at runtime.

This is the Hygon/TOS equivalent of AMD CCP integrity measurement, adapted
for Hygon CRH CPUs. It is separate from and complementary to dim_core.ko.

Author: niuyongwen@hygon.cn (Hygon employee)
Signed with: Tkernel signing key (TencentOS key, not Hygon-native key)
"""

METADATA = {
    "module_name": "tdm_kernel_guard",
    "version": "0.1",
    "author": "niuyongwen@hygon.cn",
    "description": "Kernel security enhancement module by TDM",
    "license": "GPL",
    "size_bytes": 24686,
    "source_file": "tdm-kernel-guard.c",
    "signer": "Tkernel signing key",
    "signing_cert_cn": "TencentOS Kernel Sign ICA",
    "signing_cert_email": "tencentos_secure@tencent.com",
    "signing_org": "O=Tencent,OU=TencentOS",
    "vermagic": "6.6.119-51.3.tl4.x86_64 SMP mod_unload modversions",
    "depends": "ccp",
    "tdm_origin": "Hygon TDM (Trusted Dynamic Measurement) — Hygon PSP-based hardware integrity measurement",
    "note": (
        "Authored by a Hygon engineer, signed with TencentOS key. "
        "This is a Hygon-Tencent joint module: Hygon provides the TDM PSP capability, "
        "Tencent signs and ships it in TOS 4.6. The signing key is the standard "
        "TOS tkernel key (same as kill_protect, kill_block, etc.), not a Hygon-native key."
    ),
}

MODULE_PARAMS = {
    "eh_obj": {
        "type": "int",
        "description": "Bitmap of kernel targets protected by Hygon TDM (bit0: SCT, bit1: IDT, default: both)",
        "default": "both (0x3)",
        "bit0": "SCT = sys_call_table protection",
        "bit1": "IDT = Interrupt Descriptor Table protection",
    },
    "tdm_guard": {
        "type": "charp",
        "description": "Enable TDM protection for selected targets (on=enable, off=disable, default: off)",
        "default": "off",
        "security_note": (
            "TDM protection is DISABLED by default. "
            "The module loads and initializes but does not activate hardware measurement "
            "unless explicitly set to 'on'. A TOS 4.6 system with this module loaded "
            "but without tdm_guard=on in module parameters has no SCT/IDT TDM protection."
        ),
    },
}

PSP_API = {
    "psp_check_tdm_support": (
        "Checks whether the Hygon PSP firmware supports TDM. "
        "Called at init; if unsupported, module aborts loading. "
        "TDM is a Hygon-specific PSP capability, not present in AMD PSP firmware."
    ),
    "psp_create_measure_task": (
        "Creates a TDM measurement task in the Hygon PSP. "
        "The task configures which memory regions to measure and at what interval. "
        "Returns a task_id used for all subsequent PSP operations."
    ),
    "psp_destroy_measure_task": (
        "Destroys the PSP measurement task. Called at module exit or on init failure."
    ),
    "psp_register_measure_exception_handler": (
        "Registers tdm_regi_callback_handler as the PSP callback for integrity violations. "
        "When the PSP detects a deviation from the expected measurement, "
        "it triggers this callback in the kernel. "
        "The PSP runs measurement in hardware; the callback is the kernel-side notification."
    ),
    "psp_startstop_measure_task": (
        "Starts (flag=1) or stops (flag=0) the PSP measurement task. "
        "Start = PSP begins hardware-measuring the registered memory regions. "
        "Stop = PSP stops measurement (called during cleanup or error)."
    ),
}

FUNCTIONS = {
    "init_module": {
        "addr": ".init.text+0x10",
        "size": 523,
        "flow": [
            "0x0031: psp_check_tdm_support() — abort if PSP lacks TDM",
            "0x0046: kprobe_symbol_address_byname() — locate sys_call_table",
            "0x0082: sidt [rsp+6] — capture current IDTR (IDT base + limit)",
            "0x0087: psp_check_tdm_support() again for SCT bit check",
            "0x00c5: zero addr_range[] (10 entries) and addr_info[] (10 entries)",
            "0x00cd: set MAX_OBJ=4",
            "0x00da: read eh_obj param — which objects to protect",
            "0x00f8: if bit0 set: populate SCT addr_range",
            "0x0100: if bit1 set: populate IDT addr_range from IDTR",
            "0x0129: register_kprobe for tdm_regi_callback_handler",
            "0x0135: return 0 (success)",
        ],
        "note": (
            "The SIDT instruction at 0x0082 reads the hardware IDTR directly — "
            "this is the actual IDT base/limit, not a kernel variable. "
            "IDT baseline established at module load time."
        ),
    },
    "calc_expected_hash": {
        "addr": ".text+0x90",
        "size": 249,
        "flow": [
            "0x00a7: crypto_alloc_shash(algo, 0, 0) — allocate hash TFM",
            "0x00b6: gs:[0x28] — stack canary check",
            "0x00e1: check TFM flags for algorithm validity",
            "0x00e7: get shash_alg from TFM (vtable lookup)",
            "0x00f2: crypto_shash_init(shash_desc) — init hash state",
            "0x0104: crypto_shash_update(desc, data, len) — hash the memory region",
            "0x0113: crypto_shash_final(desc, out) — finalize digest",
            "0x011e: crypto_destroy_tfm() — cleanup",
        ],
        "hash_algo": "Determined at runtime from shash_alg TFM — not hardcoded in module",
    },
    "tdm_service_run": {
        "addr": ".text+0x1a0",
        "size": 404,
        "flow": [
            "0x01ac: kmalloc(0xdc0=3520, 0x14) — allocate measure_data struct",
            "0x01da: or [rbx+0x48], 0x40000 — set flags in task context",
            "0x01e1: kmalloc(0xdc0=3520, 0x12) — allocate authcode_2b buffer",
            "0x0215: setup task parameters from rbx struct",
            "0x022d: calc_expected_hash(data, size, hash_dest) — compute baseline",
            "0x0247: psp_create_measure_task(task_id, measure_data, flags, &measure_handle)",
            "0x025c: psp_startstop_measure_task(task_id, &handle, 0) — stop first",
            "0x0273: psp_startstop_measure_task(task_id, &handle, 1) — then start",
            "0x028e: on error: printk KERN_ERR with error details",
            "0x029a: psp_destroy_measure_task(handle) — cleanup on error",
        ],
        "buffer_size": 3520,
        "note": "0xdc0 (3520) byte buffer — same size as aegis exec event struct (coincidence or shared struct?)",
    },
    "tdm_regi_callback_handler": {
        "addr": ".text+0x30",
        "size": 79,
        "flow": [
            "0x0035: compare edi (task_id) against known task_ids",
            "0x003d: second comparison for IDT task_id",
            "0x0043: mov eax, 1 — set return value on match",
            "0x0053: compute lookup into eh_objs array (5*id*8 addressing)",
            "0x0064: load object name string from eh_objs[]",
            "0x006c: printk KERN_WARNING: 'Obj: %s, Task:%d, corruption detected!'",
            "0x0071: printk KERN_WARNING: 'Please check... machine may be on danger!'",
        ],
        "action_on_detect": (
            "ONLY logs KERN_WARNING (level 4). "
            "Does NOT kill processes, halt system, or trigger panic. "
            "Pure detection-and-log; no remediation or enforcement."
        ),
    },
    "kprobe_symbol_address_byname": {
        "addr": ".text+0x3e0",
        "size": 157,
        "mechanism": (
            "Registers a kprobe at the named symbol to extract its address. "
            "Uses register_kprobe() with symbol_name = target function name, "
            "reads the resolved kp.addr field, then immediately unregisters. "
            "This is the standard kallsyms_lookup_name() workaround for kernels "
            "that no longer export kallsyms_lookup_name directly."
        ),
        "target": "sys_call_table",
        "failure_string": "kallsyms_lookup_name for sys_call_table failed!",
    },
}

ERROR_TABLE = {
    "DYN_NORMAL": "0 — success",
    "DYN_ERR_API": "API call error",
    "DYN_ERR_MEM": "Memory allocation failure",
    "DYN_ERR_HASH_ALGO": "Hash algorithm error",
    "DYN_ERR_PCR_NUM": "Invalid PCR number",
    "DYN_ERR_ORIG_TPM_PCR": "TPM PCR read failure — original PCR value unavailable",
    "DYN_ERR_REPORT_TYPE": "Invalid report type",
    "DYN_ERR_ADDR_MAPPING": "Address mapping failure",
    "DYN_ERR_KEY_ID": "Key ID error",
    "DYN_ERR_AUTH_LEN": "Auth data length error",
    "DYN_ERR_SIZE_SMALL": "Buffer too small",
    "DYN_AUTH_FAIL": "Authentication/verification failure",
    "DYN_EEXIST": "Already exists",
    "DYN_NOT_EXIST": "Does not exist",
    "DYN_NULL_POINTER": "Null pointer dereference",
    "DYN_BEYOND_MAX": "Exceeds maximum",
    "DYN_DA_PERIOD": "DA period error",
    "DYN_NO_ALLOW_UPDATE": "Update not permitted",
    "DYN_STATUS_NOT_SUIT": "Status not suitable for operation",
}

PROTECTED_OBJECTS = {
    "SCT": {
        "name": "sys_call_table",
        "eh_obj_bit": 0,
        "description": "Kernel syscall table — 256 x function pointer array",
        "location": "Resolved at runtime via kprobe symbol lookup",
        "attack_surface": (
            "Overwriting SCT entries is the classic kernel rootkit technique. "
            "Any write to sys_call_table[] replaces a syscall handler globally. "
            "TDM measures the SCT region; PSP detects changes asynchronously."
        ),
    },
    "IDT": {
        "name": "Interrupt Descriptor Table",
        "eh_obj_bit": 1,
        "description": "x86 IDT — 256 x interrupt/exception gate descriptors",
        "location": "IDTR register read via SIDT instruction at init time",
        "attack_surface": (
            "Modifying IDT entries redirects interrupt/exception handlers. "
            "IDT overwrite is used to hook int 0x80 (legacy syscall), "
            "breakpoint (int 3), or general protection faults. "
            "TDM measures the IDT region; PSP detects changes."
        ),
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "tdm_guard=off by default — Hygon TDM hardware protection disabled unless explicitly enabled",
        "detail": (
            "Module param tdm_guard defaults to 'off'. "
            "The module loads, PSP support is checked, and sys_call_table/IDT addresses "
            "are resolved — but hardware measurement does NOT start. "
            "A TOS 4.6 system with this module in initramfs but without "
            "'options tdm_kernel_guard tdm_guard=on' in modprobe.conf "
            "provides zero SCT/IDT integrity protection from this module. "
            "Default-off is safe from a compatibility standpoint but "
            "makes the feature opt-in, meaning most deployments are unprotected."
        ),
        "param": "tdm_guard=off (default)",
        "required_to_activate": "tdm_guard=on in /etc/modprobe.d/*.conf",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Detection-only response — corruption triggers KERN_WARNING log, no enforcement action",
        "detail": (
            "tdm_regi_callback_handler at 0x30 is the sole response to TDM-detected corruption. "
            "It calls printk at KERN_WARNING (level 4) with: "
            "'Obj: %s, Task:%d, corruption detected! Please check if intended...' "
            "There is NO kernel panic, NO process kill, NO system halt, NO audit event. "
            "The detection is informational only. An attacker who overwrites the SCT "
            "will have their rootkit active for the full window between the PSP detection "
            "cycle and syslog delivery — and even then, the rootkit stays running. "
            "Compare: dim_core kills tampered processes (kill_task). TDM only warns."
        ),
        "response": "printk KERN_WARNING — log only",
        "handler_addr": "0x0030 (tdm_regi_callback_handler)",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "kprobe-based sys_call_table resolution — fails silently if kprobe unavailable",
        "detail": (
            "kprobe_symbol_address_byname at 0x3e0 uses register_kprobe() "
            "to resolve the sys_call_table virtual address at runtime. "
            "If register_kprobe fails (kprobes disabled, CONFIG_KPROBES=n, "
            "or kprobe blacklist blocks sys_call_table), the error string "
            "'kallsyms_lookup_name for sys_call_table failed!' is printed "
            "and init_module returns an error. "
            "However: the module may still load with partial initialization. "
            "A system that has been hardened to prevent kprobe-based SCT lookup "
            "will see this module fail to protect the SCT while appearing to be loaded."
        ),
        "failure_string": "tdm_kernel_guard: kallsyms_lookup_name for sys_call_table failed!",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "SIDT at init captures IDT baseline — window between SIDT and PSP measurement start",
        "detail": (
            "init_module reads IDTR at 0x0082 via `sidt [rsp+6]` to capture the IDT base. "
            "This baseline is established at module load time. "
            "Between the SIDT read and psp_startstop_measure_task() activating hardware "
            "measurement, the IDT could be modified. The baseline hash would then "
            "reflect the modified IDT, and the 'original' state would be incorrectly "
            "captured as legitimate. The window is narrow (microseconds) but exists. "
            "Additionally: if the module is loaded AFTER a rootkit has already modified "
            "the IDT, the corrupted state becomes the baseline and is never detected."
        ),
        "vulnerable_window": "SIDT read → psp_startstop_measure_task(task_id, handle, 1)",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "DYN_ERR_ORIG_TPM_PCR error code — TPM PCR read failure disables measurement baseline",
        "detail": (
            "The error table includes DYN_ERR_ORIG_TPM_PCR. "
            "This error is returned when the PSP cannot read the original TPM PCR value "
            "needed to establish the measurement baseline. "
            "If the system has no TPM, or TPM communication with PSP is broken, "
            "this error aborts TDM task creation. "
            "A system-level attack that disrupts TPM-PSP communication before "
            "tdm_guard loads would prevent TDM from activating without any detection."
        ),
        "error_code": "DYN_ERR_ORIG_TPM_PCR",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "Hygon-authored module signed with TencentOS key — dual-vendor trust dependency",
        "detail": (
            "tdm-kernel-guard.ko was written by niuyongwen@hygon.cn (Hygon employee) "
            "but is signed with the TencentOS Tkernel signing key "
            "(C=CN,ST=Shanghai,O=Tencent,OU=TencentOS,CN=TencentOS Kernel Sign ICA). "
            "This creates a dual-vendor dependency: "
            "1) Hygon writes the PSP interface code (closed PSP firmware). "
            "2) Tencent signs and ships it (controls the signing key). "
            "Neither Hygon PSP firmware source nor tdm-kernel-guard.c source is public. "
            "The security guarantee depends entirely on trusting both vendors."
        ),
        "authors": ["niuyongwen@hygon.cn"],
        "signing_key_org": "O=Tencent,OU=TencentOS",
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "tdm_service_run uses 0xdc0 (3520B) measure_data struct — same size as aegis exec event",
        "detail": (
            "tdm_service_run allocates kmalloc(0xdc0=3520) for measure_data. "
            "aegis.ko (TOS 4.2) allocates 3520 bytes (0xdc0) for its exec event struct "
            "with magic tag 0x12345601. The size match is notable — "
            "possibly shared or evolved from the same internal struct definition, "
            "suggesting common internal development lineage between aegis and TDM."
        ),
        "buffer_size_hex": "0xdc0",
        "buffer_size_dec": 3520,
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "Hygon TDM requires PSP hardware — absent on non-Hygon systems (including AMD, Intel)",
        "detail": (
            "psp_check_tdm_support() gates all TDM functionality. "
            "Hygon TDM is a Hygon-proprietary PSP capability not available on "
            "AMD EPYC (uses different PSP firmware) or Intel (no PSP). "
            "This module is non-functional on any non-Hygon CPU. "
            "On TOS 4.6 deployed on Intel or standard AMD hardware, "
            "this module loads but psp_check_tdm_support() returns failure, "
            "and the SCT/IDT protection silently doesn't activate."
        ),
        "hygon_dependency": "psp_check_tdm_support() — Hygon-specific PSP API",
    },
]

if __name__ == '__main__':
    print(f"tdm-kernel-guard.ko (TOS 4.6) — {len(FINDINGS)} findings")
    print(f"Author: {METADATA['author']}")
    print(f"Signer: {METADATA['signing_cert_cn']}")
    print()
    print("Protected objects:")
    for obj_name, obj in PROTECTED_OBJECTS.items():
        print(f"  {obj_name} (bit {obj['eh_obj_bit']}): {obj['description']}")
    print()
    print(f"Default state: tdm_guard={MODULE_PARAMS['tdm_guard']['default']} — protection DISABLED")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
