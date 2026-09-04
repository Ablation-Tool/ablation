"""
TencentOS 2.4 Kernel 5.4.119 — RE Module (Delta vs OpenCloudOS 5.4.119-20)
Package: kernel-5.4.119-19.0009.tl2.x86_64.rpm (TencentOS Server 2.4, tl2 = TencentLinux 2)
Source: tlinux-tkernel4/RPMS/ on TencentOS 2.4 repo
Kernel config: boot/config-5.4.119-19-0009
System.map confirmed: _text = _stext = 0xffffffff81000000 (KASLR disabled, fixed base)

Base findings (inherited from tencent_opencloudos_kernel_re.py TCS-K01 through TCS-K05):
  TCS-K01  KASLR disabled — CONFIG_RANDOMIZE_BASE not set; _text at fixed 0xffffffff81000000
  TCS-K02  Module signing disabled — CONFIG_MODULE_SIG not set; arbitrary modules loaded
  TCS-K03  FORTIFY_SOURCE + HARDENED_USERCOPY disabled — no bounds checking on kernel copies
  TCS-K04  IMA/integrity subsystem disabled — CONFIG_INTEGRITY not set
  TCS-K05  CONFIG_DEVMEM=y without IO_STRICT_DEVMEM — raw /dev/mem access to I/O regions

Delta from OpenCloudOS 5.4.119-20 (this build is more conservative, not less):
  POSITIVE: ttools device ABSENT (world-writable ptrace bypass present in -20, absent here)
  POSITIVE: BPF_KPROBE_OVERRIDE disabled (enabled in -20 as explicit override)
  SAME: shield_mounts and netbind Tencent extensions present
  SAME: SLAB_FREELIST_RANDOM/HARDENED disabled; INIT_ON_ALLOC/FREE disabled

Confirmed present Tencent-specific kernel extensions (from System.map):
  shield_mounts: /proc/shield_mounts mount path blocking
  netbind: privileged port protection (prot_sock_flag array)
"""

KERNEL_VERSION = "5.4.119-19.0009.tl2"
KERNEL_BASE_ADDR = "0xffffffff81000000"

MITIGATIONS_ENABLED = {
    "PAGE_TABLE_ISOLATION": True,     # PTI/Meltdown
    "RETPOLINE": True,                # Spectre v2
    "STACKPROTECTOR_STRONG": True,    # Stack canaries (strong)
    "STRICT_KERNEL_RWX": True,        # Kernel W^X
    "STRICT_MODULE_RWX": True,        # Module W^X
    "STRICT_DEVMEM": True,            # /dev/mem restricted (not I/O)
    "X86_SMAP": True,                 # Supervisor Mode Access Prevention
    "SECURITY_APPARMOR": True,        # AppArmor LSM
    "INTEL_IOMMU": True,              # IOMMU DMA protection
    "AMD_IOMMU": True,
}

MITIGATIONS_ABSENT = {
    "RANDOMIZE_BASE": False,          # KASLR — CRITICAL
    "FORTIFY_SOURCE": False,          # Libc bounds checking
    "HARDENED_USERCOPY": False,       # User<>kernel copy bounds
    "KASAN": False,                   # Kernel ASAN
    "SLAB_FREELIST_RANDOM": False,    # Slab randomization
    "SLAB_FREELIST_HARDENED": False,  # Slab metadata protection
    "INIT_ON_ALLOC_DEFAULT_ON": False,# Memory zero-on-alloc
    "INIT_ON_FREE_DEFAULT_ON": False, # Memory zero-on-free
    "MODULE_SIG": False,              # Module signing
    "INTEGRITY": False,               # IMA/EVM
    "SHUFFLE_PAGE_ALLOCATOR": False,  # Page allocator entropy
    "IO_STRICT_DEVMEM": False,        # I/O port /dev/mem restriction
    "STATIC_USERMODEHELPER": False,   # Restrict usermode helpers
    "INTEL_IOMMU_DEFAULT_ON": False,  # IOMMU off by default
}

FINDINGS = {
    "TOS24K-F01": {
        "title": (
            "KASLR Disabled in TencentOS 2.4 Kernel 5.4.119-19.0009 — "
            "CONFIG_RANDOMIZE_BASE not set; System.map Confirms _text at Fixed 0xffffffff81000000; "
            "All Kernel Exploitation Techniques Work Without Info-Leak Prerequisite; "
            "Matches TCS-K01 in OpenCloudOS 5.4.119-20"
        ),
        "severity": "CRITICAL",
        "cvss": "8.1",
        "cwe": "CWE-330",
        "component": (
            "boot/config-5.4.119-19-0009: # CONFIG_RANDOMIZE_BASE is not set; "
            "System.map: ffffffff81000000 T _text = ffffffff81000000 T _stext"
        ),
        "description": (
            "Kernel ASLR is disabled across all TencentOS 2.4 deployments using this kernel. "
            "The kernel text segment, heap, stack, and module area load at fixed, "
            "deterministic virtual addresses (kernel text base: 0xffffffff81000000). "
            "Any kernel exploit that requires knowing a kernel virtual address — ROP chains, "
            "overwrite-to-known-function, struct offset arithmetic — works without an "
            "information-disclosure prerequisite. This eliminates the hardest step in most "
            "modern kernel exploitation chains."
        ),
        "chain": (
            "TOS24K-F01 + TOS24K-F02 (MODULE_SIG disabled): trivial persistence — "
            "load unsigned rootkit module at known kernel addresses; "
            "TOS24K-F01 + TOS24K-F03 (FORTIFY_SOURCE disabled): stack/heap overflow → "
            "fixed ROP gadget chain → privilege escalation without needing a leak; "
            "TOS24K-F01 + CVE-2022-27666 (ESP4/ESP6 heap OOB): heap overflow → "
            "overwrite kernel function pointer at predictable address → root"
        ),
        "remediation": "Enable CONFIG_RANDOMIZE_BASE=y and rebuild. No known performance penalty on x86_64.",
        "references": ["CWE-330", "TCS-K01 (opencloudos)"],
    },
    "TOS24K-F02": {
        "title": (
            "Kernel Module Signing Disabled — CONFIG_MODULE_SIG not set; "
            "Any Kernel Module Loads Without Signature Verification; "
            "Persistent Rootkit Insertion Surface; Matches TCS-K02"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-347",
        "component": "boot/config-5.4.119-19-0009: # CONFIG_MODULE_SIG is not set",
        "description": (
            "The kernel accepts any .ko module for loading without signature verification. "
            "A local attacker with CAP_SYS_MODULE (or root) can load an arbitrary kernel module. "
            "Combined with KASLR disabled (TOS24K-F01), the rootkit can reference hardcoded "
            "kernel symbol addresses from System.map for syscall table replacement, "
            "hook installation, or direct kernel structure manipulation."
        ),
        "chain": (
            "TOS24K-F02 + TOS24K-F01: insmod <rootkit.ko> → hooks sys_call_table at "
            "fixed address from System.map → full kernel control; "
            "TOS24K-F02 + tat_agent TAT-F01 (command exec as root): "
            "TAT command executes insmod → module loaded → persistent root"
        ),
        "remediation": (
            "Enable CONFIG_MODULE_SIG=y and CONFIG_MODULE_SIG_FORCE=y. "
            "Generate module signing keys during build and sign all in-tree modules. "
            "Test that only signed modules load in production."
        ),
        "references": ["CWE-347", "TCS-K02 (opencloudos)"],
    },
    "TOS24K-F03": {
        "title": (
            "FORTIFY_SOURCE and HARDENED_USERCOPY Both Disabled — "
            "No Bounds Checking on Kernel String/Memory Operations; "
            "No User<>Kernel Copy Range Validation"
        ),
        "severity": "HIGH",
        "cvss": "7.0",
        "cwe": "CWE-120",
        "component": (
            "boot/config-5.4.119-19-0009: "
            "# CONFIG_FORTIFY_SOURCE is not set; "
            "# CONFIG_HARDENED_USERCOPY is not set"
        ),
        "description": (
            "FORTIFY_SOURCE disabled: kernel memcpy, strcpy, sprintf, etc. have no "
            "compile-time or runtime object-size bounds checking. A buffer overflow in a "
            "kernel string operation silently corrupts adjacent memory. "
            "HARDENED_USERCOPY disabled: copy_to_user/copy_from_user have no validation "
            "that source/destination addresses are within the correct bounds. "
            "Over-read or over-write of kernel memory via crafted syscall arguments is "
            "possible without triggering any mitigation."
        ),
        "chain": (
            "TOS24K-F03 + TOS24K-F01 (KASLR disabled): buffer overflow in kernel driver → "
            "overwrite known function pointer → fixed ROP chain → privilege escalation; "
            "TOS24K-F03 + DEVMEM=y (TOS24K-F04): over-read kernel struct → "
            "leak credentials to /dev/mem accessible region"
        ),
        "remediation": (
            "Enable CONFIG_FORTIFY_SOURCE=y and CONFIG_HARDENED_USERCOPY=y. "
            "Both are supported on 5.4.x kernels with no known incompatibilities."
        ),
        "references": ["CWE-120", "TCS-K03 (opencloudos)"],
    },
    "TOS24K-F04": {
        "title": (
            "CONFIG_DEVMEM=y Without IO_STRICT_DEVMEM — "
            "Raw Physical Memory and I/O Port Access via /dev/mem; "
            "CAP_SYS_RAWIO Grants Direct Hardware Register Access"
        ),
        "severity": "MEDIUM",
        "cvss": "6.0",
        "cwe": "CWE-284",
        "component": (
            "boot/config-5.4.119-19-0009: "
            "CONFIG_DEVMEM=y; "
            "CONFIG_STRICT_DEVMEM=y (restricts RAM but NOT I/O regions); "
            "# CONFIG_IO_STRICT_DEVMEM is not set"
        ),
        "description": (
            "/dev/mem allows access to physical RAM through STRICT_DEVMEM enforcement. "
            "However, without IO_STRICT_DEVMEM, I/O port regions (PCI configuration space, "
            "memory-mapped device registers) remain accessible through /dev/mem. "
            "A process with CAP_SYS_RAWIO can read or write hardware registers directly, "
            "enabling firmware modification, memory controller manipulation, or "
            "hardware RNG substitution via PCI MMIO regions."
        ),
        "chain": "TOS24K-F04 + TOS24K-F02 (insmod): kernel module maps MMIO → persists through OS reinstall",
        "remediation": "Enable CONFIG_IO_STRICT_DEVMEM=y.",
        "references": ["CWE-284", "TCS-K05 (opencloudos)"],
    },
    "TOS24K-F05": {
        "title": (
            "SLAB Allocator Without Freelist Randomization or Metadata Hardening — "
            "CONFIG_SLAB_FREELIST_RANDOM and CONFIG_SLAB_FREELIST_HARDENED Both Disabled; "
            "Deterministic Heap Layout Enables Reliable Use-After-Free Exploitation"
        ),
        "severity": "MEDIUM",
        "cvss": "6.4",
        "cwe": "CWE-416",
        "component": (
            "boot/config-5.4.119-19-0009: "
            "# CONFIG_SLAB_FREELIST_RANDOM is not set; "
            "# CONFIG_SLAB_FREELIST_HARDENED is not set"
        ),
        "description": (
            "The SLAB/SLUB allocator returns objects in a predictable order from freelist. "
            "Without SLAB_FREELIST_RANDOM, a use-after-free attack that requires reusing a "
            "specific object type succeeds with high reliability — no spray required. "
            "Without SLAB_FREELIST_HARDENED, freelist pointer corruption is undetected; "
            "a write-what-where to the freelist can redirect the next kmalloc to an attacker-"
            "controlled address. Combined with KASLR disabled (TOS24K-F01), all target "
            "addresses are known."
        ),
        "chain": (
            "TOS24K-F05 + TOS24K-F01: UAF in kernel driver → deterministic slab reuse → "
            "type confusion → privilege escalation at known kernel address"
        ),
        "remediation": (
            "Enable CONFIG_SLAB_FREELIST_RANDOM=y and CONFIG_SLAB_FREELIST_HARDENED=y. "
            "Both are available in 5.4.x."
        ),
        "references": ["CWE-416"],
    },
}

DELTA_FROM_OPENCLOUDOS = {
    "ttools_device": {
        "opencloudos_5_4_119_20": "PRESENT — world-writable ptrace bypass device (TCS-K04 CRITICAL)",
        "tos24_5_4_119_19": "ABSENT — not in System.map; this build does not expose ttools",
        "security_impact": "POSITIVE — removes world-writable ptrace bypass from attack surface",
    },
    "bpf_kprobe_override": {
        "opencloudos_5_4_119_20": "ENABLED — CONFIG_BPF_KPROBE_OVERRIDE=y",
        "tos24_5_4_119_19": "DISABLED — # CONFIG_BPF_KPROBE_OVERRIDE is not set",
        "security_impact": "POSITIVE — removes BPF-based kernel probe override capability",
    },
    "kaslr": {
        "opencloudos_5_4_119_20": "DISABLED (TCS-K01)",
        "tos24_5_4_119_19": "DISABLED — confirmed same; _text = 0xffffffff81000000",
        "security_impact": "NO CHANGE — both builds share the KASLR-disabled deficiency",
    },
    "module_sig": {
        "opencloudos_5_4_119_20": "DISABLED (TCS-K02)",
        "tos24_5_4_119_19": "DISABLED — same",
        "security_impact": "NO CHANGE",
    },
}

ATTACK_CHAIN = {
    "title": "TOS24K-F01 + F02 + F05 → Persistent Root via UAF + Module Load at Known Addresses",
    "steps": [
        "1. Exploit use-after-free in NFS/io_uring/ext4 driver (CVE-2022-29582 / CVE-2022-25636)",
        "2. No SLAB randomization (TOS24K-F05): deterministic kmalloc reuse, no spray needed",
        "3. Overwrite kernel creds struct or function pointer at known address (TOS24K-F01: _text fixed)",
        "4. Escalate to root; insmod unsigned rootkit (TOS24K-F02: no module signing)",
        "5. Rootkit hooks sys_call_table at fixed address 0xffffffff81e01340 (from System.map)",
        "6. Persistent root; all CAP checks bypassed",
    ],
    "prerequisite": "Initial code execution as any unprivileged user",
}


def probe():
    return {
        "critical": ["TOS24K-F01"],
        "high": ["TOS24K-F02", "TOS24K-F03"],
        "medium": ["TOS24K-F04", "TOS24K-F05"],
        "low": [],
    }


def chain():
    return ATTACK_CHAIN


def delta():
    return DELTA_FROM_OPENCLOUDOS


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "kernel": KERNEL_VERSION,
        "base_addr": KERNEL_BASE_ADDR,
        "findings": list(FINDINGS.keys()),
        "delta": DELTA_FROM_OPENCLOUDOS,
    }, indent=2))
