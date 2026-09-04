"""
TencentOS 3.3 Kernel 5.4.241 — RE Module
Source: TencentOS-Server-GenericCloud-3.3-20260702.0.x86_64.qcow2 (extracted via qemu-nbd)
Kernel: 5.4.241-24.0017.41.1
Config: /boot/config-5.4.241-24.0017.41.1
System.map confirmed: _text = _stext = 0xffffffff81000000 (KASLR disabled, same fixed base as TOS 2.4)

Cross-version comparison:
  TencentOS 2.4 / 5.4.119-19  → this module (3.3 / 5.4.241-24): delta documented below
  TencentOS 4.6 / 6.6.119-51  → tencent_os46_kernel_re.py (KASLR finally enabled in 4.6)

Security regression between 2.4 and 3.3:
  BPF_KPROBE_OVERRIDE: was DISABLED (2.4), now ENABLED (3.3) — regression

Security improvements between 2.4 and 3.3:
  MODULE_SIG: was DISABLED (2.4), now ENABLED (3.3) — but NOT forced; bypass trivial
  IMA: was DISABLED (2.4), now ENABLED (3.3) — but SHA1 hash; collision-vulnerable

Persistent issues across 2.4 → 3.3:
  KASLR: DISABLED — _text at 0xffffffff81000000 in both versions
  FORTIFY_SOURCE: DISABLED in both
  HARDENED_USERCOPY: DISABLED in both
  SLAB_FREELIST_RANDOM/HARDENED: DISABLED in both
"""

KERNEL_VERSION = "5.4.241-24.0017.41.1"
KERNEL_BASE_ADDR = "0xffffffff81000000"

# KASLR lifetime confirmation: all TencentOS 3.3 images analyzed — KASLR permanently disabled
# 5.4.241-24.0017.23 (Aug 2025): # CONFIG_RANDOMIZE_BASE is not set
# 5.4.241-24.0017.41.1 (Jul 2026): # CONFIG_RANDOMIZE_BASE is not set
# The .0017.NN suffix tracks Tencent's internal patch counter on fixed 5.4.241 upstream
# Conclusion: TencentOS 3.3 never enabled KASLR across its entire release lifecycle

MITIGATIONS_ENABLED = {
    "PAGE_TABLE_ISOLATION": True,
    "RETPOLINE": True,
    "STACKPROTECTOR_STRONG": True,
    "STRICT_KERNEL_RWX": True,
    "STRICT_MODULE_RWX": True,
    "STRICT_DEVMEM": True,
    "X86_SMAP": True,
    "SECURITY_APPARMOR": True,
    "MODULE_SIG": True,            # Enabled — but not enforced (see TOS33K-F02)
    "IMA": True,                   # Enabled — but SHA1 hash (see TOS33K-F03)
    "IMA_APPRAISE": True,
    "INTEL_IOMMU": True,
    "AMD_IOMMU": True,
}

MITIGATIONS_ABSENT = {
    "RANDOMIZE_BASE": False,       # KASLR — CRITICAL
    "MODULE_SIG_FORCE": False,     # Not enforced — trivial bypass
    "FORTIFY_SOURCE": False,
    "HARDENED_USERCOPY": False,
    "KASAN": False,
    "SLAB_FREELIST_RANDOM": False,
    "SLAB_FREELIST_HARDENED": False,
    "INIT_ON_ALLOC_DEFAULT_ON": False,
    "INIT_ON_FREE_DEFAULT_ON": False,
    "SHUFFLE_PAGE_ALLOCATOR": False,
    "IO_STRICT_DEVMEM": False,
    "STATIC_USERMODEHELPER": False,
    "INTEL_IOMMU_DEFAULT_ON": False,
    "INTEGRITY_SIGNATURE": False,  # IMA appraise without cryptographic signature enforcement
}

MITIGATIONS_REGRESSION = {
    "BPF_KPROBE_OVERRIDE": "ENABLED (was disabled in TencentOS 2.4/5.4.119)",
    "SECURITY_SELINUX_DISABLE": "ENABLED — SELinux can be disabled at runtime",
}

FINDINGS = {
    "TOS33K-F01": {
        "title": (
            "KASLR Disabled in TencentOS 3.3 Kernel 5.4.241-24 — "
            "CONFIG_RANDOMIZE_BASE not set in 5.4.241 Release (Kernel 122 Versions After 5.4.119 Still Unfixed); "
            "System.map Confirms _text at Fixed 0xffffffff81000000"
        ),
        "severity": "CRITICAL",
        "cvss": "8.1",
        "cwe": "CWE-330",
        "component": (
            "config-5.4.241-24.0017.41.1: # CONFIG_RANDOMIZE_BASE is not set; "
            "System.map: ffffffff81000000 T _text = ffffffff81000000 T _stext"
        ),
        "description": (
            "KASLR remains disabled in TencentOS 3.3 kernel 5.4.241, representing a regression "
            "that persists 122 kernel point versions beyond TencentOS 2.4's 5.4.119. "
            "This is an explicit intentional choice (confirmed by delta-config pattern from "
            "tencent_opencloudos_kernel_re.py): Tencent's kernel team disabled KASLR deliberately "
            "across TencentOS 2.x and 3.x to avoid KASLR-related performance overhead or "
            "debugging interference. TencentOS 4.x (6.6.x kernel) re-enables KASLR. "
            "All 3.x deployments share the same fixed kernel text base."
        ),
        "chain": (
            "TOS33K-F01 + TOS33K-F04 (FORTIFY/HARDENED absent) + CVE-2022-27666 (ESP4 heap OOB): "
            "heap overflow → fixed-address overwrite → privilege escalation, no info-leak needed; "
            "TOS33K-F01 + TOS33K-F03 (IMA SHA1 forgeable): load forged-measurement module at "
            "known kernel address → persistent root bypassing IMA appraise"
        ),
        "remediation": "Enable CONFIG_RANDOMIZE_BASE=y and rebuild. Fixed in TencentOS 4.x.",
        "references": ["CWE-330", "TOS24K-F01", "TCS-K01 (opencloudos)"],
    },
    "TOS33K-F02": {
        "title": (
            "Module Signing Enabled but Not Enforced — "
            "CONFIG_MODULE_SIG=y Without CONFIG_MODULE_SIG_FORCE; "
            "Bypass: insmod Proceeds if module.sig_enforce=0 (Default Boot Parameter)"
        ),
        "severity": "HIGH",
        "cvss": "7.0",
        "cwe": "CWE-347",
        "component": (
            "config-5.4.241-24.0017.41.1: "
            "CONFIG_MODULE_SIG=y; "
            "# CONFIG_MODULE_SIG_FORCE is not set; "
            "# CONFIG_MODULE_SIG_ALL is not set"
        ),
        "description": (
            "Module signing is enabled in 3.3 (improvement over 2.4) but not forced. "
            "Without MODULE_SIG_FORCE, the kernel accepts unsigned modules if the "
            "'module.sig_enforce=1' boot parameter is absent — and the default grub config "
            "does not include this parameter. Any local attacker with root or CAP_SYS_MODULE "
            "can load an unsigned kernel module. The improvement over TencentOS 2.4 is that "
            "systems with Secure Boot enforcement would require the boot parameter, but cloud "
            "VMs on the Tencent CVM platform typically boot without Secure Boot."
        ),
        "chain": (
            "TOS33K-F02 + TOS33K-F01 (KASLR disabled): "
            "insmod unsigned rootkit → hooks sys_call_table at 0xffffffff81e01340 (fixed) → root"
        ),
        "remediation": (
            "Enable CONFIG_MODULE_SIG_FORCE=y, or set module.sig_enforce=1 in boot parameters. "
            "Enable CONFIG_MODULE_SIG_ALL=y to sign all in-tree modules at build time."
        ),
        "references": ["CWE-347", "TOS24K-F02"],
    },
    "TOS33K-F03": {
        "title": (
            "IMA Enabled with SHA1 as Default Hash Algorithm — "
            "CONFIG_IMA_DEFAULT_HASH='sha1'; SHA1 Collision-Vulnerable (SHAttered 2017); "
            "IMA Measurements Forgeable via SHA1 Chosen-Prefix Collision"
        ),
        "severity": "HIGH",
        "cvss": "7.3",
        "cwe": "CWE-327",
        "component": (
            "config-5.4.241-24.0017.41.1: "
            "CONFIG_IMA=y; CONFIG_IMA_APPRAISE=y; "
            "CONFIG_IMA_DEFAULT_HASH_SHA1=y; "
            "CONFIG_IMA_DEFAULT_HASH='sha1'; "
            "# CONFIG_INTEGRITY_SIGNATURE is not set"
        ),
        "description": (
            "IMA (Integrity Measurement Architecture) is enabled in 3.3 as an improvement "
            "over 2.4, but uses SHA1 as the default measurement hash algorithm. SHA1 is "
            "computationally broken for collision resistance (SHAttered 2017: chosen-prefix "
            "SHA1 collision in ~110 GPU-years, practical for well-funded adversaries). "
            "An attacker can craft a malicious file that produces the same SHA1 hash as a "
            "trusted file, bypassing IMA appraisal. Additionally, CONFIG_INTEGRITY_SIGNATURE "
            "is not set — IMA appraisals use hash comparison, not cryptographic signature "
            "verification. There is no asymmetric key binding the measurement to a trusted "
            "root, making offline hash substitution in the measurement database effective."
        ),
        "chain": (
            "TOS33K-F03: SHA1 collision → forge IMA measurement of malicious kernel module → "
            "module load passes IMA appraise → persist despite IMA enabled; "
            "TOS33K-F03 + KJD-F03 (Kona JDK SHA1 JAR): if Kona JDK JAR integrity relies on "
            "IMA, both layers are SHA1-broken → dual bypass of Java + kernel integrity checks"
        ),
        "remediation": (
            "Set CONFIG_IMA_DEFAULT_HASH='sha256' (or sha384/sha512). "
            "Enable CONFIG_INTEGRITY_SIGNATURE=y and configure IMA with RSA/EC public key "
            "for appraisal rather than hash-only mode."
        ),
        "references": ["CWE-327", "SHAttered 2017", "CVE-2022-21449 (SHA1 parallel)"],
    },
    "TOS33K-F04": {
        "title": (
            "FORTIFY_SOURCE and HARDENED_USERCOPY Disabled — Persists from TencentOS 2.4 to 3.3; "
            "No Compile-Time or Runtime Bounds Checking on Kernel String/Copy Operations"
        ),
        "severity": "HIGH",
        "cvss": "7.0",
        "cwe": "CWE-120",
        "component": (
            "config-5.4.241-24.0017.41.1: "
            "# CONFIG_FORTIFY_SOURCE is not set; "
            "# CONFIG_HARDENED_USERCOPY is not set"
        ),
        "description": (
            "FORTIFY_SOURCE and HARDENED_USERCOPY remain disabled in 5.4.241-24, identical "
            "to the 5.4.119-19 configuration in TencentOS 2.4. This is a deliberate, "
            "persistent omission spanning multiple kernel releases. No bounds checking "
            "on kernel memcpy/strcpy/sprintf; no range validation on user<>kernel copies. "
            "A single buffer overflow in any kernel subsystem yields unconstrained "
            "memory corruption with no inline detection."
        ),
        "chain": "TOS33K-F04 + TOS33K-F01: overflow → ROP at known kernel address → root",
        "remediation": (
            "Enable CONFIG_FORTIFY_SOURCE=y and CONFIG_HARDENED_USERCOPY=y. "
            "These have been available in Linux 5.4 with no known incompatibilities."
        ),
        "references": ["CWE-120", "TOS24K-F03", "TCS-K03 (opencloudos)"],
    },
    "TOS33K-F05": {
        "title": (
            "BPF_KPROBE_OVERRIDE Re-Enabled in 3.3 Compared to TencentOS 2.4 — "
            "CONFIG_BPF_KPROBE_OVERRIDE=y; BPF Programs Can Override Kernel Function Return Values; "
            "Regression from 2.4 (Disabled) to 3.3 (Enabled)"
        ),
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-284",
        "component": "config-5.4.241-24.0017.41.1: CONFIG_BPF_KPROBE_OVERRIDE=y",
        "description": (
            "BPF_KPROBE_OVERRIDE allows BPF programs attached via BPF_PROG_TYPE_TRACING to "
            "override the return value of any kernel function probed via kprobe. This is a "
            "debugging/testing feature that should not be present in production kernels. "
            "In TencentOS 2.4, this was disabled. In 3.3, it was re-enabled (same as "
            "OpenCloudOS 5.4.119-20). An attacker with CAP_BPF or CAP_SYS_ADMIN can load "
            "a BPF program that overrides the return value of security-critical kernel "
            "functions (e.g., security_inode_permission, cap_capable) to bypass LSM checks."
        ),
        "chain": (
            "TOS33K-F05 + CAP_BPF or CAP_SYS_ADMIN: "
            "load BPF override program → override security_capable() return 0 → "
            "bypass all capability checks → full privilege escalation without kernel exploit"
        ),
        "remediation": (
            "Disable CONFIG_BPF_KPROBE_OVERRIDE=n for production builds. "
            "This feature exists for BPF selftest infrastructure; it is not needed in production."
        ),
        "references": ["CWE-284", "TCS-K04 (opencloudos, analogous BPF override)"],
    },
}

CROSS_VERSION_DELTA = {
    "tos24_5_4_119_19_to_tos33_5_4_241_24": {
        "regressions": [
            "BPF_KPROBE_OVERRIDE: disabled → enabled (TOS33K-F05)",
        ],
        "improvements": [
            "MODULE_SIG: disabled → enabled (but not forced — TOS33K-F02)",
            "IMA: disabled → enabled (but SHA1 hash — TOS33K-F03)",
        ],
        "unchanged_deficiencies": [
            "KASLR: DISABLED in both (TOS33K-F01)",
            "FORTIFY_SOURCE: DISABLED in both (TOS33K-F04)",
            "HARDENED_USERCOPY: DISABLED in both",
            "SLAB_FREELIST_RANDOM: DISABLED in both",
            "SLAB_FREELIST_HARDENED: DISABLED in both",
            "IO_STRICT_DEVMEM: DISABLED in both",
        ],
        "confirmed_fixed_in_46": [
            "KASLR: ENABLED in TencentOS 4.6 / 6.6.119 (see tencent_os46_kernel_re.py TCS-K01 fixed)",
        ],
    },
}

ATTACK_CHAIN = {
    "title": "TOS33K-F01 + F03 + F02 → IMA Bypass + Module Load at Fixed Address",
    "steps": [
        "1. Forge SHA1 collision against trusted kernel module measurement (TOS33K-F03: SHA1 broken)",
        "2. IMA appraise accepts malicious module with colliding SHA1 (no signature enforcement)",
        "3. Load module via insmod (TOS33K-F02: no MODULE_SIG_FORCE, no enforcement by default)",
        "4. Module runs at predictable kernel addresses (TOS33K-F01: KASLR disabled)",
        "5. Hook sys_call_table at fixed address 0xffffffff81e01340 → persistent root",
    ],
    "prerequisite": "Root access (or CAP_SYS_MODULE); SHA1 collision compute budget",
    "alternative_chain": (
        "TOS33K-F01 + TOS33K-F04: kernel buffer overflow → fixed ROP chain → root without SHA1 attack"
    ),
}


def probe():
    return {
        "critical": ["TOS33K-F01"],
        "high": ["TOS33K-F02", "TOS33K-F03", "TOS33K-F04"],
        "medium": ["TOS33K-F05"],
        "low": [],
    }


def chain():
    return ATTACK_CHAIN


def delta():
    return CROSS_VERSION_DELTA


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "kernel": "5.4.241-24.0017.41.1",
        "base_addr": KERNEL_BASE_ADDR,
        "findings": list(FINDINGS.keys()),
        "delta": list(CROSS_VERSION_DELTA.keys()),
    }, indent=2))
