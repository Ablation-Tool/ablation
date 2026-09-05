"""
TencentOS 4.6 — tdm-kernel-guard.ko RE.

Binary: tdm-kernel-guard.ko
Type: ELF 64-bit relocatable, x86-64, not stripped
Text size: 0x047d bytes
Author: niuyongwen@hygon.cn (Hygon Corporation)
License: GPL
Version: 0.1
Depends: ccp (AMD/Hygon Cryptographic Co-Processor driver)

Module parameters:
  tdm_guard=<charp>  — list of kernel objects to guard
  eh_obj=<int>       — exception handler object ID

Role: Hardware-assisted kernel runtime integrity verification using Hygon PSP
(Platform Security Processor). Monitors kernel objects (sys_call_table, kernel
.text) for tampering using both software kprobes and hardware PSP measurements.
Detects rootkits and kernel memory corruption.

Context: Hygon is a Chinese x86 CPU vendor (joint venture with AMD). Hygon CPUs
include a PSP (Platform Security Processor) similar to AMD ASP. The CCP kernel
module provides psp_* functions for PSP interaction. This module is built for
TOS 4.6 systems running on Hygon hardware.
"""

BINARY_INVENTORY = {
    "tdm-kernel-guard.ko": {
        "path": "/tmp/scratchpad/tdm-kernel-guard.ko",
        "type": "ELF 64-bit relocatable, x86-64, not stripped",
        "text_size": 0x047d,
        "version": "0.1",
        "license": "GPL",
        "author": "niuyongwen@hygon.cn (Hygon Corporation)",
        "description": "Kernel security enhancement module by TDM",
        "kernel_dependency": "ccp (Hygon CCP/PSP driver)",
        "params": {
            "tdm_guard": "charp — comma-separated list of kernel objects to guard",
            "eh_obj": "int — exception handler object identifier for PSP callbacks",
        },
    },
}

PSP_INTEGRATION = {
    "what_is_psp": (
        "PSP = Platform Security Processor. Hygon CPUs include a dedicated security "
        "co-processor (similar to AMD ASP) that operates independently of the main CPU. "
        "The PSP can measure memory regions and compare against expected values. "
        "If the measured value diverges (tampering detected), the PSP generates an "
        "exception that the Linux driver handles. "
        "This is hardware-assisted integrity measurement — harder to subvert than "
        "pure software approaches because the measurement runs outside the main CPU "
        "and its caches/TLB/microcode."
    ),
    "psp_functions_used": {
        "psp_check_tdm_support": "verify the PSP hardware supports TDM (Trusted Domain Measurement)",
        "psp_create_measure_task": "register a kernel object with the PSP for periodic measurement",
        "psp_destroy_measure_task": "unregister a PSP measurement task",
        "psp_startstop_measure_task": "start or stop a registered PSP measurement task (task_id)",
        "psp_register_measure_exception_handler": "register callback for PSP tampering alerts",
    },
    "measurement_flow": (
        "1. At init: psp_check_tdm_support() — verify hardware capability "
        "2. For each guarded object (tdm_guard param): "
        "   a. Resolve object address via kprobe_symbol_address_byname "
        "   b. calc_expected_hash() — compute SHA hash of the object "
        "   c. psp_create_measure_task() — register with PSP (address + expected hash) "
        "   d. psp_register_measure_exception_handler(tdm_regi_callback_handler, eh_obj) "
        "   e. psp_startstop_measure_task(task_id, start=true) "
        "3. PSP hardware periodically measures the object asynchronously "
        "4. On mismatch: PSP generates exception → tdm_regi_callback_handler fires "
        "5. Callback logs: 'tdm_kernel_guard: Obj: %s, Task:%d, corruption detected!'"
    ),
}

KPROBE_MECHANISM = {
    "what_it_does": (
        "kprobe_symbol_address_byname at 0x3e0: resolves kernel symbol addresses "
        "by registering a kprobe at the symbol and reading the kprobe's addr field. "
        "This works even on kernels where kallsyms_lookup_name is not directly exported. "
        "After getting the address, it unregisters the kprobe — clean probe-based lookup."
    ),
    "sys_call_table": (
        "The module calls kallsyms_lookup_name('sys_call_table') to get the syscall table. "
        "If this fails: logs 'kallsyms_lookup_name for sys_call_table failed!' and stops. "
        "The syscall table address is then passed to the PSP for hardware monitoring. "
        "Any modification to a syscall pointer (rootkit hook) changes the measured value "
        "→ PSP detects mismatch → callback fires."
    ),
    "p_tmp_kprobe_handler": (
        "p_tmp_kprobe_handler at 0x10: the kprobe pre-handler for address resolution. "
        "It's a minimal stub (0x10 bytes) that returns immediately — the kprobe is only "
        "used to resolve the symbol address from kp.addr, not to actually hook calls."
    ),
    "tdm_service_run/exit": (
        "tdm_service_run at 0x1a0: main service loop — initializes PSP tasks and "
        "waits (msleep) in a loop for exception callbacks. "
        "tdm_service_exit at 0x350: stops all PSP tasks and cleans up."
    ),
}

SECURITY_ANALYSIS = {
    "hardware_vs_software": (
        "The PSP-based measurement is harder to subvert than dim_core's software approach. "
        "A rootkit that modifies kernel memory: "
        "- Can evade software measurements by hooking the measurement code "
        "- Cannot easily fake PSP results without compromising PSP firmware "
        "The PSP has its own trusted firmware, isolated from the main OS kernel. "
        "Hardware-assisted measurement is the right architecture for kernel integrity."
    ),
    "kprobe_race": (
        "The syscall table is protected by the PSP AFTER psp_create_measure_task. "
        "A rootkit that hooks the syscall table BEFORE this module loads is not detected "
        "at load time — the expected hash is computed from the CURRENT state (already modified). "
        "The module should compare against a boot-time measurement (PCR value) not the "
        "current state. This is a fundamental limitation of any runtime integrity system."
    ),
    "exception_handler_only_logs": (
        "tdm_regi_callback_handler at 0x30: logs 'corruption detected'. "
        "The handler does NOT take action: no process kill, no panic, no lockdown. "
        "Detection only; response is by the userspace agent reading the kernel log. "
        "An attacker who gains code execution can disable the klog or the handler."
    ),
    "tdm_guard_param": (
        "The tdm_guard=<charp> module parameter controls which objects are guarded. "
        "If the parameter is not set or set to an empty list, no objects are measured. "
        "Default value (if any) is not visible in strings — likely empty. "
        "Deployment with no tdm_guard value = security module that does nothing."
    ),
    "psp_depends_ccp": (
        "The module depends on the CCP (ccp.ko) driver for PSP access. "
        "On non-Hygon hardware (standard Intel TOS 4.6 systems), "
        "the CCP driver may not load or psp_check_tdm_support() returns false. "
        "On such systems, tdm-kernel-guard.ko fails to initialize (hardware not available). "
        "This module is Hygon-specific."
    ),
    "kprobe_subversion": (
        "A sufficiently privileged rootkit can unregister kprobes "
        "via unregister_kprobe() or by directly patching the kprobe mechanism. "
        "However, the kprobe in this module is only used for address resolution "
        "(not for ongoing monitoring) — the actual monitoring is PSP-based."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "PSP measures sys_call_table — but expected hash computed from current state (pre-load race)",
        "detail": (
            "calc_expected_hash computes the expected hash from the CURRENT sys_call_table at load time. "
            "If a rootkit hooks the syscall table before tdm-kernel-guard loads, "
            "the modified table becomes the 'expected' value — the rootkit is invisible to PSP. "
            "Fix: compare against a boot-time measurement (e.g., UEFI Secure Boot PCR) "
            "or a pre-computed golden hash embedded in the module."
        ),
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "Corruption detection is log-only — no automatic response action taken",
        "detail": (
            "tdm_regi_callback_handler logs 'corruption detected' and returns. "
            "No SIGKILL, no kernel panic, no lockdown. "
            "An attacker who controls the system (or disables kernel logging) can silence alerts. "
            "Compare: dim_core.ko optionally sends SIGKILL (blocking mode)."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "tdm_guard parameter: empty default means module may guard nothing by default",
        "detail": (
            "If tdm_guard= not set at modprobe time, no objects are registered with PSP. "
            "Module loads and runs but provides zero protection. "
            "Deployment must explicitly set tdm_guard= (e.g., 'sys_call_table,kernel_text'). "
            "Hardcoded defaults would be safer."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "Hygon PSP hardware measurement: stronger than software measurement (PSP firmware isolated)",
        "detail": (
            "PSP operates independently of the main CPU — compromised kernel cannot fake PSP measurements. "
            "Requires Hygon hardware — not active on Intel-based TOS 4.6 systems (psp_check_tdm_support fails). "
            "Hardware-assisted integrity is the right architecture for high-assurance environments."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "kprobe_symbol_address_byname: clever symbol resolution without direct kallsyms export",
        "detail": (
            "Registers a no-op kprobe at the target symbol, reads kp.addr, then unregisters. "
            "Works on kernels where kallsyms_lookup_name is not exported. "
            "Technique also used by rootkits for symbol resolution — dual-use."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 tdm-kernel-guard.ko — Hygon PSP hardware integrity RE")
    print()
    info = BINARY_INVENTORY['tdm-kernel-guard.ko']
    print(f"  v{info['version']}, {info['text_size']:04x} bytes .text")
    print(f"  Author: {info['author']}")
    print(f"  Depends: {info['kernel_dependency']}")
    print()
    print("Mechanism:")
    print("  1. kallsyms_lookup_name(sys_call_table) -> address")
    print("  2. calc_expected_hash(address) -> SHA digest of guarded object")
    print("  3. psp_create_measure_task(address, expected_hash)")
    print("  4. psp_register_measure_exception_handler(tdm_regi_callback_handler)")
    print("  5. psp_startstop_measure_task(task_id, start=true)")
    print("  6. PSP hardware measures async -> exception on mismatch -> 'corruption detected'")
    print()
    print("Hardware: Hygon PSP (Platform Security Processor) — isolated from main CPU")
    print("Limitation: expected hash from current state — pre-load rootkits evade detection")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
