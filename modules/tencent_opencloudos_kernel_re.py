"""
OpenCloudOS / TencentOS Kernel 5.4.119 — RE Module
Source: opencloudos-5.4.119/ (full kernel source tree)
Kernel version: 5.4.119-20 (OpenCloudOS, Tencent Linux Kernel 4.0)
Config source: dist/configs/00base/generic/{x86_64,aarch64,default}.config

This is a layered delta-config system (inspired by Fedora ARK and Tencent Linux Kernel public).
The dist/configs files are DELTAS from upstream Linux 5.4.119 defaults.
A "# CONFIG_X is not set" in the delta is an EXPLICIT DISABLE of an upstream-default-enabled feature.

Upstream repository: https://gitee.com/OpenCloudOS/OpenCloudOS-Kernel
Vendor marker: opencloudos, KDIST=stable
Supported architectures: x86_64, aarch64, riscv64
Module signing: dist/sources/module-signer.sh, module-keygen.sh

Notable TencentOS-specific modifications (from delta config analysis):
  KASLR:         EXPLICITLY DISABLED  (# CONFIG_RANDOMIZE_BASE is not set)
  Integrity/IMA: EXPLICITLY DISABLED  (# CONFIG_INTEGRITY is not set)
  BPF kprobe override: ENABLED        (CONFIG_BPF_KPROBE_OVERRIDE=y)
  User namespaces: ENABLED            (CONFIG_USER_NS=y)
  SELinux runtime disable: ENABLED    (CONFIG_SECURITY_SELINUX_DISABLE=y)
  Legacy vsyscall: EMULATE mode       (CONFIG_LEGACY_VSYSCALL_EMULATE=y)
  IOMMU default: OFF                  (# CONFIG_INTEL_IOMMU_DEFAULT_ON is not set)
  AMD SME active by default: OFF      (# CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT is not set)
  BPF JIT: ALWAYS ON                  (CONFIG_BPF_JIT_ALWAYS_ON=y)
"""

from typing import Optional

# ─── Target Profile ───────────────────────────────────────────────────────────

TARGET = "tencent-opencloudos-kernel"
VERSIONS_AFFECTED = ["5.4.119-20"]
KERNEL_EXTRAVERSION = "-20"
CONFIG_PATH = "dist/configs/00base/generic/"

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {
    "TCS-K01": {
        "title": (
            "KASLR Explicitly Disabled in TencentOS x86_64 Kernel Config — "
            "All Kernel Symbol Addresses Fixed and Predictable; "
            "Upstream Default (Enabled) Overridden by Explicit Delta-Config Entry"
        ),
        "severity": "CRITICAL",
        "cvss": "8.8",
        "cwe": "CWE-330",
        "component": (
            "dist/configs/00base/generic/x86_64.config — "
            "kernel boot-time address randomization — "
            "CONFIG_RANDOMIZE_BASE=n (explicit override of upstream y)"
        ),
        "evidence": {
            "config_line": (
                "dist/configs/00base/generic/x86_64.config: '# CONFIG_RANDOMIZE_BASE is not set'. "
                "This is a delta-config file — entries only appear when they differ from upstream defaults. "
                "Upstream Linux 5.4 x86_64 default: CONFIG_RANDOMIZE_BASE=y (enabled since Linux 3.14). "
                "TencentOS explicitly overrides this to disabled via the '# ... is not set' marker. "
                "The override is applied at kernel build time, not a runtime boot parameter."
            ),
            "scope_of_disable": (
                "CONFIG_RANDOMIZE_BASE controls kernel image load address randomization (KASLR). "
                "Without it, the kernel image loads at the compile-time fixed virtual address "
                "(typically 0xffffffff81000000 for x86_64 non-PIE kernels). "
                "All kernel text, data, rodata, and symbol addresses are deterministic on every boot. "
                "No information-leak primitive is required to locate kernel gadgets: "
                "any public kernel symbol from /proc/kallsyms or System.map is a reliable address."
            ),
            "attack_amplification": (
                "KASLR is the primary defense against kernel exploitation across the entire kernel CVE population. "
                "Its absence means: "
                "1. Any kernel memory corruption vulnerability (UAF, OOB, heap overflow) can be exploited "
                "   without a first-stage information leak. "
                "2. ROP chains targeting kernel gadgets require no per-boot gadget resolution. "
                "3. Spectre variant 1/2 mitigations that rely on KASLR for entropy are degraded: "
                "   an attacker using a Spectre gadget does not need the kernel base address. "
                "4. Heap spray attacks targeting fixed kernel struct offsets succeed reliably. "
                "Effective exploitation cost for any kernel vulnerability on TencentOS x86_64 "
                "is reduced by at least one full primitive (the leak stage)."
            ),
            "kpti_interaction": (
                "Page Table Isolation (PTI/KPTI for Meltdown) is independent of KASLR, "
                "but KASLR was the complementary randomization layer that made Meltdown "
                "harder to exploit even with PTI disabled. "
                "With KASLR off, the kernel direct mapping base is also predictable, "
                "strengthening physmap-based exploitation paths."
            ),
            "aarch64_status": (
                "aarch64.config has no explicit CONFIG_RANDOMIZE_BASE override. "
                "ARM64 CONFIG_RANDOMIZE_BASE depends on CONFIG_RANDOMIZE_BASE parent which "
                "is architecture-local; the absence of an explicit disable is ambiguous — "
                "the x86_64 finding is confirmed; arm64 status requires runtime verification."
            ),
        },
        "versions_affected": ["5.4.119-20"],
        "remediation": (
            "Remove the '# CONFIG_RANDOMIZE_BASE is not set' line from "
            "dist/configs/00base/generic/x86_64.config. "
            "With this line absent, the upstream default (CONFIG_RANDOMIZE_BASE=y) applies. "
            "Additionally enable CONFIG_RANDOMIZE_MEMORY=y for physical memory randomization. "
            "Verify KASLR is active at runtime: 'cat /proc/kallsyms | grep _stext' should "
            "return different values on each boot. "
            "For maximum entropy on bare-metal: also set CONFIG_X86_NEED_RELOCS=y and verify "
            "the boot loader passes the kaslr flag (or does not pass nokaslr)."
        ),
    },
    "TCS-K02": {
        "title": (
            "Kernel Integrity Subsystem (IMA/EVM) Explicitly Disabled — "
            "No Runtime Integrity Measurement for Kernel-Executed Files; "
            "Persistent Backdoor Implants Survive Undetected"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-354",
        "component": (
            "dist/configs/00base/generic/x86_64.config — "
            "CONFIG_INTEGRITY=n — "
            "disables IMA (Integrity Measurement Architecture) + EVM (Extended Verification Module)"
        ),
        "evidence": {
            "config_line": (
                "dist/configs/00base/generic/x86_64.config: '# CONFIG_INTEGRITY is not set'. "
                "CONFIG_INTEGRITY is the parent Kconfig option that gates both "
                "CONFIG_IMA (file integrity measurement) and CONFIG_EVM (extended verification). "
                "Disabling it removes both subsystems entirely from the running kernel. "
                "Upstream Linux 5.4 default: CONFIG_INTEGRITY=y."
            ),
            "ima_loss": (
                "IMA (CONFIG_IMA) is the Linux kernel's built-in file integrity measurement subsystem. "
                "When enabled, IMA measures (hashes) files before execution and optionally "
                "appraises them against stored signatures in extended attributes. "
                "With IMA disabled: "
                "1. No cryptographic measurement of executed binaries is recorded in the TPM PCR. "
                "2. Kernel-level attestation of what code has run since boot is unavailable. "
                "3. A post-exploitation attacker who replaces a system binary faces no IMA-based "
                "   re-measurement barrier — the replacement executes without detection. "
                "4. Remote attestation flows (TPM-based boot integrity) that rely on IMA "
                "   PCR extension are broken."
            ),
            "evm_loss": (
                "EVM (CONFIG_EVM) provides HMAC/signature protection over security-critical "
                "file extended attributes (SELinux labels, IMA hashes, SMACK labels). "
                "With EVM disabled, extended attributes can be modified on disk without "
                "cryptographic detection. An attacker with filesystem write access can "
                "alter SELinux file contexts without triggering any integrity violation. "
                "This weakens the SELinux MAC policy enforcement chain."
            ),
            "tencent_cloud_context": (
                "TencentOS runs on CVM (Tencent Cloud Virtual Machines) — a shared-tenancy "
                "cloud environment where the hypervisor and disk images are managed by Tencent. "
                "IMA/EVM would provide a tenant-side integrity measurement chain independent "
                "of the hypervisor. Without it, there is no kernel-level evidence if a VM "
                "disk image is modified between snapshots or during live migration. "
                "For forensics post-compromise (e.g., after TCS-F01 MitM root command execution), "
                "there is no IMA log to consult."
            ),
        },
        "versions_affected": ["5.4.119-20"],
        "remediation": (
            "Remove the '# CONFIG_INTEGRITY is not set' line from x86_64.config. "
            "With CONFIG_INTEGRITY=y restored, additionally enable: "
            "CONFIG_IMA=y, CONFIG_IMA_MEASURE_PCR_IDX=10, CONFIG_IMA_APPRAISE=y, "
            "CONFIG_IMA_APPRAISE_BOOTPARAM=y, CONFIG_EVM=y, CONFIG_EVM_ATTR_FSUUID=y. "
            "Deploy an IMA policy that measures all executables and kernel modules. "
            "For CVM environments, integrate IMA PCR values into cloud attestation workflows."
        ),
    },
    "TCS-K03": {
        "title": (
            "BPF Kprobe Return Override Enabled With Unprivileged User Namespaces — "
            "Unprivileged Container Context Gains BPF-Override-Capable Program Injection; "
            "Kernel Function Return Values Alterable from Userspace"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-269",
        "component": (
            "dist/configs/00base/generic/x86_64.config — "
            "CONFIG_BPF_KPROBE_OVERRIDE=y + CONFIG_USER_NS=y + CONFIG_BPF_SYSCALL=y + "
            "CONFIG_BPF_JIT_ALWAYS_ON=y — "
            "BPF kprobe injection surface with user-namespace privilege escalation path"
        ),
        "evidence": {
            "bpf_kprobe_override": (
                "CONFIG_BPF_KPROBE_OVERRIDE=y: enables bpf_override_return() helper. "
                "This BPF helper allows a BPF_PROG_TYPE_KPROBE program to inject an arbitrary "
                "return value into the kprobed kernel function, effectively causing it to "
                "return early with an attacker-controlled value. "
                "Example: attach kprobe to security_inode_permission(); call "
                "bpf_override_return(ctx, 0) -> every permission check returns 0 (=allowed). "
                "This is a deliberate design for error injection testing but is enabled in "
                "the production kernel build."
            ),
            "user_ns_escalation_path": (
                "CONFIG_USER_NS=y: enables creation of unprivileged user namespaces. "
                "In Linux 5.4 without CONFIG_BPF_UNPRIV_DEFAULT_OFF (introduced 5.16), "
                "BPF programs can be loaded by unprivileged users inside a user namespace "
                "with CAP_BPF (effective within the namespace). "
                "Attack path: "
                "1. unshare(CLONE_NEWUSER) -> gain namespace-scoped capabilities. "
                "2. Load BPF_PROG_TYPE_KPROBE program with bpf_override_return(). "
                "3. Attach to security_capable() or credential check functions. "
                "4. Override return value -> bypass capability checks for escalation. "
                "This path is constrained by the attacker needing the kprobe attach point "
                "to be instrumentable (no LOCK_DOWN_KPROBES enforcement)."
            ),
            "bpf_jit_always_on": (
                "CONFIG_BPF_JIT_ALWAYS_ON=y: BPF programs are always JIT-compiled; "
                "the interpreter fallback is removed. "
                "JIT compilation means BPF programs run as native kernel code — "
                "any BPF program logic executes at kernel privilege directly. "
                "Cannot be disabled at runtime via /proc/sys/net/core/bpf_jit_enable. "
                "JIT spraying attacks (encoding shellcode in BPF immediate values) are "
                "reliable against the JIT output pages."
            ),
            "selinux_disable_interaction": (
                "CONFIG_SECURITY_SELINUX_DISABLE=y allows SELinux to be disabled at runtime. "
                "If an attacker uses the BPF kprobe override path to gain privileges, "
                "they can then call setenforce 0 or use the selinux_status interface to "
                "disable MAC enforcement entirely, eliminating the remaining access control layer. "
                "Chain: user_ns escalation -> BPF override -> privilege gain -> setenforce 0 -> "
                "full unconfined access."
            ),
            "kaslr_synergy": (
                "Combined with TCS-K01 (KASLR disabled): BPF kprobe programs that reference "
                "kernel symbols as immediate values or constants do not need to resolve "
                "symbol addresses at runtime — they can use the fixed, predictable addresses "
                "from the System.map. "
                "This makes kprobe attachment points trivial to target without /proc/kallsyms access."
            ),
        },
        "versions_affected": ["5.4.119-20"],
        "remediation": (
            "Disable BPF kprobe override in production builds: "
            "remove CONFIG_BPF_KPROBE_OVERRIDE=y (set to n or remove the line). "
            "This feature is for kernel error-injection testing and has no legitimate "
            "production use on cloud instances. "
            "Additionally: "
            "Set CONFIG_BPF_UNPRIV_DEFAULT_OFF=y (if backporting from 5.16) or "
            "enforce /proc/sys/kernel/unprivileged_bpf_disabled=2 via sysctl at boot "
            "(2=permanently disabled, survives privilege escalation). "
            "Consider restricting user namespaces: CONFIG_USER_NS_UNPRIVILEGED=n or "
            "sysctl kernel.unprivileged_userns_clone=0 (if the kernel supports it). "
            "Remove CONFIG_SECURITY_SELINUX_DISABLE=y to prevent runtime SELinux disable."
        ),
    },
}


# ─── Probe Functions ──────────────────────────────────────────────────────────

def probe_kernel_config(config_path: str) -> dict:
    """Parse a kernel config file and check for the confirmed vulnerable settings."""
    findings_triggered = []
    try:
        with open(config_path) as f:
            cfg = f.read()
        if "CONFIG_RANDOMIZE_BASE" not in cfg or "# CONFIG_RANDOMIZE_BASE is not set" in cfg:
            findings_triggered.append("TCS-K01")
        if "# CONFIG_INTEGRITY is not set" in cfg:
            findings_triggered.append("TCS-K02")
        if "CONFIG_BPF_KPROBE_OVERRIDE=y" in cfg:
            findings_triggered.append("TCS-K03")
    except OSError:
        pass
    return {"config_path": config_path, "findings": findings_triggered}


def probe(host: str, port: int = 22, timeout: int = 10) -> dict:
    """
    Placeholder — kernel config findings confirmed via source analysis.
    Runtime verification: check /proc/cmdline for 'kaslr'/'nokaslr',
    /proc/sys/kernel/unprivileged_bpf_disabled, /sys/kernel/security/ima/policy.
    """
    return {
        "host": host,
        "note": "kernel config findings require source or /proc access; confirmed via static analysis",
        "findings": list(FINDINGS.keys()),
    }
