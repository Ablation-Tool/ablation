"""
TencentOS 4.6 — kernel configuration reverse engineering.

Source: /boot/config-6.6.119-51.3.tl4.x86_64 (plain text, 7496 CONFIG_ entries)
Compiler: gcc (Tencent Compiler 12.3.1.8) 12.3.1 20230912 (TencentOS 12.3.1.8-4)

This module documents TOS-specific kernel configuration options,
security hardening choices, and architecture support divergences from upstream Linux 6.6.
"""

METADATA = {
    "kernel_version": "6.6.119-51.3.tl4.x86_64",
    "config_entries": 7496,
    "compiler": "gcc (Tencent Compiler 12.3.1.8) 12.3.1 20230912 (TencentOS 12.3.1.8-4)",
    "gcc_version": "12.3.1",
    "compiler_note": (
        "TOS 4.6 uses a Tencent-internal GCC fork (12.3.1.8). "
        "The fork version string 'TencentOS 12.3.1.8-4' indicates Tencent maintains "
        "a proprietary compiler with TOS-specific patches on top of GCC 12.3. "
        "Compiler-level bugs or backdoors in this fork would affect all TOS 4.6 binaries."
    ),
}

TOS_SPECIFIC_CONFIG = {
    "TKERNEL=y": "TOS tkernel subsystem — root Kconfig enabling all TOS-specific kernel features",
    "TKERNEL_SECURITY_MONITOR=y": "Security monitoring subsystem built into kernel (not a module)",
    "TKERNEL_KILL_HOOK=y": (
        "Kill hook API built into kernel. "
        "Exports register_kill_hook / unregister_kill_hook as kernel symbols. "
        "This confirms the kill hook API is always-available on TOS 4.6 "
        "regardless of whether kill_protect.ko or kill_block.ko are loaded."
    ),
    "TKERNEL_KILL_BLOCK=m": "kill_block.ko loadable module",
    "TKERNEL_KILL_PROTECT=m": "kill_protect.ko loadable module",
    "TKERNEL_IRQ_LATENCY=m": "irqlatency.ko loadable module",
    "TKERNEL_TTOOLS not set": "ttools anti-ptrace module DISABLED in TOS 4.6 (was in TOS 3.3 only)",
    "TKERNEL_NETATOP not set": "netatop disabled in TOS 4.6",
    "TKERNEL_AEGIS_MODULE not set": "aegis disabled in TOS 4.6 (was in TOS 4.2 only)",
    "ASYNC_FORK=y": "Async fork built into kernel (not modular). Always active on TOS 4.6.",
    "SHELL_GUARD=y": "Shell guard built into kernel. TOS-specific exec-path protection.",
    "EMM_FORCE_SWAPPINESS=y": "Extended memory management: forced swappiness",
    "EMM_RAMDISK_SWAP=y": "EMM: ramdisk as swap backing store",
    "EMM_WORKINGSET_TRACKING=y": "EMM: workingset refault distance tracking",
    "EMM_MEMCG=y": "EMM: memory cgroup extensions",
    "EMM_RECLAIM=y": "EMM: reclaim extensions",
    "EMM_ZRAM_CONF=y": "EMM: zram configuration extensions",
    "EMM_BATCH_DIRTY_TLB_FLUSH=y": "EMM: batched dirty TLB flush optimization",
    "DIM=y": "Dynamic Integrity Measurement subsystem enabled",
    "DIM_CORE=m": "dim_core.ko — integrity measurement core (loadable)",
    "DIM_HASH_SUPPORT_SM3=y": "DIM can use SM3 (Chinese national hash) for measurements",
    "DIM_MONITOR=m": "dim_monitor.ko — integrity measurement monitor (loadable)",
}

CHINESE_CRYPTO_SUITE = {
    "SM2": {
        "config": "CRYPTO_SM2=y",
        "standard": "GM/T 0003 (asymmetric encryption, like ECC)",
        "use": "DIM policy/baseline signature verification (via dim_core_sig_verify)",
        "zhaoxin": "CRYPTO_SM2_ZHAOXIN_GMI=m (hardware acceleration on Zhaoxin CPUs)",
    },
    "SM3": {
        "config": "CRYPTO_SM3=y, CRYPTO_SM3_GENERIC=y",
        "standard": "GM/T 0004 (256-bit hash, similar to SHA-256)",
        "use": "DIM measurements (CONFIG_DIM_HASH_SUPPORT_SM3=y). Default hash for dim_core.",
        "avx": "CRYPTO_SM3_AVX_X86_64=m",
        "zhaoxin": "CRYPTO_SM3_ZHAOXIN_GMI=m",
    },
    "SM4": {
        "config": "CRYPTO_SM4=m",
        "standard": "GM/T 0002 (128-bit block cipher, similar to AES)",
        "use": "Potential use in TLS TLCP (Commercial Cryptography TLS) extension",
        "avx": "CRYPTO_SM4_AESNI_AVX_X86_64=m, CRYPTO_SM4_AESNI_AVX2_X86_64=m",
        "zhaoxin": "CRYPTO_SM4_ZHAOXIN_GMI=m",
    },
}

ZHAOXIN_SUPPORT = {
    "CPU_SUP_ZHAOXIN=y": "Zhaoxin x86 CPU support enabled",
    "description": (
        "Zhaoxin (兆芯) is a Chinese x86 CPU manufacturer (CRH CPU). "
        "TOS 4.6 includes Zhaoxin-specific optimizations and hardware support, "
        "indicating TOS is deployed on Chinese domestic x86 hardware. "
        "Zhaoxin provides hardware-accelerated SM2/SM3/SM4 (via GMI extension)."
    ),
    "modules": [
        "AHCI_ZHAOXIN_SGPIO=m",
        "SATA_ZHAOXIN=m",
        "HW_RANDOM_ZHAOXIN=m",
        "I2C_ZHAOXIN=m",
        "I2C_ZHAOXIN_SMBUS=m",
        "PINCTRL_ZHAOXIN=m",
        "SENSORS_ZHAOXIN_CPUTEMP=m",
        "CRYPTO_SM4_ZHAOXIN_GMI=m",
        "CRYPTO_SM3_ZHAOXIN_GMI=m",
        "CRYPTO_SM2_ZHAOXIN_GMI=m",
    ],
}

SECURITY_HARDENING = {
    "KASLR": {
        "RANDOMIZE_BASE=y": "Kernel ASLR — text base randomized at boot",
        "RANDOMIZE_MEMORY=y": "Memory layout randomization",
        "RANDOMIZE_MEMORY_PHYSICAL_PADDING=0xa": "10-page physical memory padding",
        "RANDOMIZE_KSTACK_OFFSET=y": "Per-syscall kernel stack offset randomization",
    },
    "stack": {
        "STACKPROTECTOR=y": "Stack canaries enabled",
        "STACKPROTECTOR_STRONG=y": "Strong stack protection (all non-leaf functions)",
        "VMAP_STACK=y": "Virtual-mapped kernel stacks (guard pages, overflow detection)",
    },
    "memory": {
        "STRICT_KERNEL_RWX=y": "Kernel text RO+X, data RW — no W+X mappings",
        "STRICT_MODULE_RWX=y": "Module text similarly enforced",
        "STRICT_DEVMEM=y": "/dev/mem access restricted to non-RAM regions",
        "KFENCE=y": "Kernel Electric Fence — probabilistic OOB/UAF detection",
        "KFENCE_SAMPLE_INTERVAL=100": "1% of allocations checked (every 100ms)",
        "KFENCE_NUM_OBJECTS=255": "255 fenced objects in pool",
    },
    "spectre": {
        "RETPOLINE=y": "Retpoline indirect branch speculation mitigation",
    },
    "lsm_stack": {
        "SECURITY_SELINUX=y": "SELinux — primary MAC system",
        "SECURITY_BIBA=y": "Biba MAC model (integrity-focused, unusual in production)",
        "SECURITY_YAMA=y": "Yama LSM — ptrace restriction policy",
        "SECURITY_LANDLOCK=y": "Landlock LSM — sandboxing framework",
        "note": (
            "TOS 4.6 runs 4 LSMs simultaneously: SELinux + Biba + Yama + Landlock. "
            "This is an unusually deep MAC stack. SELinux + Biba together provide "
            "both confidentiality (SELinux) and integrity (Biba) enforcement. "
            "Yama's ptrace restrictions complement the ttools anti-ptrace from TOS 3.3 — "
            "in 4.6, Yama handles ptrace restriction instead of the ttools module."
        ),
    },
    "integrity": {
        "INTEGRITY=y": "IMA/EVM framework enabled",
        "INTEGRITY_AUDIT=y": "Integrity violation audit logging",
        "IMA=y": "Integrity Measurement Architecture (complement to DIM)",
        "IMA_MEASURE_PCR_IDX=10": "IMA uses PCR 10 (DIM uses configurable PCR via dim_core param)",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "Tencent proprietary GCC fork — all TOS 4.6 binaries compiled with Tencent Compiler 12.3.1.8",
        "detail": (
            "CONFIG_CC_VERSION_TEXT shows 'gcc (Tencent Compiler 12.3.1.8) 12.3.1 20230912'. "
            "All kernel code, modules, and userspace binaries are compiled with this fork. "
            "Tencent-specific compiler patches are not publicly audited. "
            "A compiler-level backdoor (similar to Thompson's 'Trusting Trust' attack) "
            "would be undetectable from source code alone. "
            "Tencent Compiler 12.3.1.8 is not open-source."
        ),
        "compiler_version": "gcc (Tencent Compiler 12.3.1.8) 12.3.1 20230912 (TencentOS 12.3.1.8-4)",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "CONFIG_TKERNEL_KILL_HOOK=y — kill hook API built into kernel, always present",
        "detail": (
            "register_kill_hook / unregister_kill_hook are kernel-built symbols "
            "available to ANY kernel module on TOS 4.6, not just kill_protect/kill_block. "
            "A malicious kernel module or kernel exploit could register its own kill hook "
            "to intercept or suppress SIGKILL delivery to any process. "
            "The hook runs in the process-kill path before the signal is delivered. "
            "There is no policy limiting which modules can register kill hooks."
        ),
        "config": "CONFIG_TKERNEL_KILL_HOOK=y",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "CONFIG_SHELL_GUARD=y — undocumented shell exec protection built into TOS kernel",
        "detail": (
            "SHELL_GUARD is enabled as a kernel built-in (=y), not a module. "
            "This feature is not present in upstream Linux 6.6. "
            "No public documentation on SHELL_GUARD behavior or bypass conditions. "
            "From name and context: likely restricts shell exec (execve of /bin/sh, /bin/bash) "
            "in certain contexts (container/user namespace restrictions?). "
            "Since it's kernel-built, it cannot be disabled by unloading a module. "
            "Bypass requires kernel parameter or sysctl if exposed."
        ),
        "config": "CONFIG_SHELL_GUARD=y",
        "public_documentation": "None found",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "SM3 as default DIM measurement hash — Chinese national standard (not SHA-256)",
        "detail": (
            "CONFIG_DIM_HASH_SUPPORT_SM3=y enables SM3 (GM/T 0004) as a measurement "
            "algorithm option for dim_core. "
            "SM3 is the Chinese national standard hash function (256-bit output). "
            "While computationally similar to SHA-256, its security is not as widely "
            "externally audited as SHA-256. "
            "TOS systems configured to use SM3 for DIM measurements cannot directly "
            "interoperate with IMA/TPM ecosystems expecting SHA-256 PCR values. "
            "DIM measurement logs using SM3 cannot be verified by non-China-aware tools."
        ),
        "sm3_config": "CRYPTO_SM3=y, DIM_HASH_SUPPORT_SM3=y",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Zhaoxin x86 CPU support — TOS deployed on Chinese domestic hardware",
        "detail": (
            "CONFIG_CPU_SUP_ZHAOXIN=y and multiple Zhaoxin-specific driver modules "
            "confirm TOS 4.6 is deployed on Zhaoxin (兆芯) CRH x86 CPUs. "
            "Zhaoxin provides hardware SM2/SM3/SM4 acceleration (GMI extension). "
            "Zhaoxin CPUs are not fully publicly documented — microarchitectural attacks "
            "(cache timing, speculative execution) against Zhaoxin are not well-studied. "
            "The HW_RANDOM_ZHAOXIN=m driver indicates a hardware RNG that feeds "
            "kernel entropy — a weak or backdoored RNG would compromise all crypto."
        ),
        "zhaoxin_configs": ["CPU_SUP_ZHAOXIN=y", "HW_RANDOM_ZHAOXIN=m", "CRYPTO_SM*_ZHAOXIN_GMI=m"],
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "CONFIG_SECURITY_BIBA=y — Biba MAC model active alongside SELinux (unusual production config)",
        "detail": (
            "Biba integrity model is enabled in the TOS 4.6 kernel alongside SELinux. "
            "Biba enforces: subjects cannot read down (lower integrity), cannot write up. "
            "This is the integrity dual of BLP confidentiality. "
            "Running Biba + SELinux simultaneously creates complex policy interactions. "
            "If Biba policy is not carefully configured, it can create privilege-escalation "
            "paths where a low-integrity process writes to a high-integrity file "
            "that SELinux permits but Biba should block, or vice versa."
        ),
        "config": "CONFIG_SECURITY_BIBA=y",
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "KFENCE enabled with 1% sample rate — OOB/UAF detection at low overhead",
        "detail": (
            "CONFIG_KFENCE=y, KFENCE_SAMPLE_INTERVAL=100 (1 allocation per 100ms sampled). "
            "KFENCE catches out-of-bounds and use-after-free on sampled allocations. "
            "The 1% sample rate means 99% of buggy allocations go undetected. "
            "KFENCE is a production safety net, not a complete memory safety solution. "
            "Security finding: KFENCE's guard pages are in virtual memory — "
            "an exploit that uses a physical address alias bypass will not trigger KFENCE."
        ),
        "kfence_params": {"interval": 100, "objects": 255},
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "IMA on PCR 10, DIM on configurable PCR — dual TPM measurement systems",
        "detail": (
            "TOS 4.6 runs both IMA (CONFIG_IMA=y, PCR 10) and DIM (dim_core.ko, configurable PCR). "
            "These are two independent integrity measurement systems targeting the same TPM. "
            "IMA measures files at open/exec; DIM measures running process/module/kernel text. "
            "Both extend separate PCRs. Attestation must validate both PCR chains. "
            "A system that only checks IMA PCR 10 misses DIM measurements, "
            "and vice versa."
        ),
        "ima_pcr": 10,
        "dim_pcr": "configurable via measure_pcr module param",
    },
]

DISABLED_IN_TOS46 = {
    "TKERNEL_TTOOLS": "Anti-ptrace module (was TOS 3.3 only)",
    "TKERNEL_NETATOP": "Per-task network stats (was TOS 3.3 only)",
    "TKERNEL_AEGIS_MODULE": "Exec monitoring (was TOS 4.2 only)",
}

if __name__ == '__main__':
    print(f"TOS 4.6 kernel config RE — {len(FINDINGS)} findings")
    print(f"Compiler: {METADATA['compiler'][:60]}...")
    print()
    print("TOS-specific kernel features:")
    for k, v in TOS_SPECIFIC_CONFIG.items():
        if 'not set' not in k:
            print(f"  {k}: {v[:50]}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
