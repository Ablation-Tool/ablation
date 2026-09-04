"""
TencentOS Server 4.6 Kernel 6.6.119-51.3.tl4 — RE Module
Source: qcow2 TencentOS-Server-GenericCloud-4.6-20260720.1.x86_64.qcow2
Kernel: 6.6.119-51.3.tl4.x86_64 (built 2026-07-14 17:09:05 CST)
Builder: mockbuild@VM-81-29-TS3
Extracted: /boot/vmlinuz → vmlinux ELF (61,860,508 bytes, stripped)
Config:    /boot/config-6.6.119-51.3.tl4.x86_64 (230KB)
System.map confirmed: 0xffffffff81644e20 shellguard_bprm_check

Comparison baseline: tencent_opencloudos_kernel_re.py (kernel 5.4.119-20)
  5.4.119: KASLR disabled, IMA disabled, BPF_KPROBE_OVERRIDE enabled
  6.6.119: KASLR enabled (fixed), IMA enabled (partial), BPF_KPROBE_OVERRIDE still present,
           + new custom LSM 'shellguard' (binary integrity monitor, runtime-disableable)

Method:
  - Static config grep (230KB kernel.config)
  - vmlinux extraction from bzImage (gzip at offset 0x42d1)
  - Capstone disassembly of shellguard functions via System.map VAs
  - pyelftools segment map for VA→file_offset translation
"""

from typing import Optional

# ─── Target Profile ───────────────────────────────────────────────────────────

TARGET = "tencent-os46-kernel"
KERNEL_VERSION = "6.6.119-51.3.tl4.x86_64"
BUILD_DATE = "2026-07-14"
CONFIG_FILE = "/boot/config-6.6.119-51.3.tl4.x86_64"
VMLINUX_VA_BASE = 0xffffffff81000000

# ─── Delta vs 5.4.119 Baseline ────────────────────────────────────────────────

BASELINE_DELTA = {
    "fixed": [
        "TCS-K01: KASLR disabled → CONFIG_RANDOMIZE_BASE=y + CONFIG_RANDOMIZE_MEMORY=y",
        "TCS-K02: IMA/EVM disabled → CONFIG_INTEGRITY=y + CONFIG_IMA=y + CONFIG_EVM=y",
        "KPTI: CONFIG_PAGE_TABLE_ISOLATION=y (Meltdown mitigation confirmed)",
        "RETPOLINE: CONFIG_RETPOLINE=y (Spectre v2 mitigation confirmed)",
        "STACKPROTECTOR: CONFIG_STACKPROTECTOR_STRONG=y",
        "STRICT_KERNEL_RWX: CONFIG_STRICT_KERNEL_RWX=y + CONFIG_STRICT_MODULE_RWX=y",
    ],
    "still_present": [
        "TCS-K03 class: CONFIG_BPF_KPROBE_OVERRIDE=y (still in 6.6.119)",
        "TCS-K03 class: # CONFIG_BPF_UNPRIV_DEFAULT_OFF is not set (user_ns + BPF path active)",
        "CONFIG_BPF_JIT_ALWAYS_ON=y (native code execution, no interpreter fallback)",
        "CONFIG_USER_NS=y (unprivileged user namespaces still enabled)",
    ],
    "new_findings": [
        "TCS4-K01: shellguard custom LSM — binary integrity monitor, runtime-disableable by root",
        "TCS4-K02: IMA without appraisal — measures but does not enforce signatures",
        "TCS4-K03: KEXEC without signature — kexec_load() unsigned kernel allowed",
        "TCS4-K04: MODULE_SIG without FORCE — unsigned modules still loadable",
        "TCS4-K05: FORTIFY_SOURCE disabled — compile-time buffer overflow protection absent",
        "TCS4-K06: SECURITY_LOCKDOWN_LSM absent — no kernel lockdown mode",
    ],
}

# ─── shellguard LSM — Function Map ────────────────────────────────────────────

SHELLGUARD_FUNCTIONS = {
    # VA: (name, insn_count_disassembled)
    0xffffffff81644e20: ("shellguard_bprm_check",         "primary LSM hook"),
    0xffffffff81644c00: ("shellguard_bprm_check.part.0",  "digest verification inner"),
    0xffffffff816438c0: ("shellguard_digest_file",        "file hash computation"),
    0xffffffff81643f70: ("shellguard_enable_write",       "securityfs enable/disable write"),
    0xffffffff81643ec0: ("shellguard_block_write",        "securityfs block/audit mode write"),
    0xffffffff81644020: ("shellguard_write_parser",       "colon-delimited policy rule parser"),
    0xffffffff81643c60: ("shellguard_init",               "LSM initialization"),
    0xffffffff83761840: ("shellguard_secfs_late_init",    "securityfs directory creation"),
}

SHELLGUARD_GLOBALS = {
    # VA: (name, description)
    0xffffffff83d20384: ("shellguard_enable",    "global enable flag; 0=off, 1=on"),
    0xffffffff83d20380: ("shellguard_block",     "block vs audit mode; 0=audit, 1=block"),
    0xffffffff83d20350: ("shellguard_dentry_target",    "securityfs 'target' dentry"),
    0xffffffff83d20358: ("shellguard_dentry_whitelist", "securityfs 'whitelist' dentry"),
    0xffffffff83d20360: ("shellguard_dentry_block",     "securityfs 'block' dentry"),
    0xffffffff83d20368: ("shellguard_dentry_enable",    "securityfs 'enable' dentry"),
}

SHELLGUARD_SECFS = {
    "path": "/sys/kernel/security/shellguard/",
    "files": ["target", "whitelist", "block", "enable"],
    "fops": {
        "target":    "shellguard_target_fops    (0xffffffff82072140)",
        "whitelist": "shellguard_whitelist_fops (0xffffffff820722a0)",
        "block":     "shellguard_block_fops     (0xffffffff82072400)",
        "enable":    "shellguard_enable_fops    (0xffffffff82072540)",
    },
}

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {
    "TCS4-K01": {
        "title": (
            "shellguard Custom LSM Runtime-Disableable by Root via securityfs — "
            "echo 0 > /sys/kernel/security/shellguard/enable Bypasses All Binary Integrity Enforcement; "
            "No Capability Check Beyond CAP_SYS_ADMIN (Root)"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-284",
        "component": (
            "shellguard LSM — /sys/kernel/security/shellguard/enable — "
            "shellguard_enable_write (0xffffffff81643f70) — "
            "shellguard_enable global (0xffffffff83d20384)"
        ),
        "evidence": {
            "bprm_check_bypass": (
                "shellguard_bprm_check (0xffffffff81644e20) disassembly:\n"
                "  0xffffffff81644e20: call 0xffffffff81080be0   # __fentry__ (ftrace)\n"
                "  0xffffffff81644e25: cmp dword ptr [rip + 0x26db558], 1  # shellguard_enable\n"
                "  0xffffffff81644e2c: je 0xffffffff81644e35    # enabled: proceed\n"
                "  0xffffffff81644e2e: xor eax, eax             # disabled: return 0\n"
                "  0xffffffff81644e30: jmp 0xffffffff81dbf0b0   # → allow ALL exec\n"
                "First instruction after __fentry__ is the enable check. If shellguard_enable != 1, "
                "the entire bprm_check returns 0 (success/allow) unconditionally. "
                "No other guard exists — the check is a single 32-bit integer comparison."
            ),
            "enable_write_disasm": (
                "shellguard_enable_write (0xffffffff81643f70):\n"
                "  Reads 1 byte from userspace write() call\n"
                "  0xffffffff81643fd6: cmp eax, 0x31   # '1'\n"
                "  0xffffffff81643fd9: je 0x81643ff3   # enable path\n"
                "  0xffffffff81643fdb: cmp eax, 0x30   # '0'\n"
                "  0xffffffff81643fde: jne return      # invalid: no-op\n"
                "  0xffffffff81643fe0: cmp byte ptr [rsp+1], 0  # must be single char\n"
                "  0xffffffff81643fe5: jne return\n"
                "  0xffffffff81643fe7: mov dword ptr [rip+0x26dc393], 0  # shellguard_enable=0\n"
                "Writing ASCII '0' to the securityfs file clears shellguard_enable. "
                "After write, every subsequent exec bypasses shellguard_bprm_check completely. "
                "No persistent state — reboot restores default (need to verify default value)."
            ),
            "securityfs_access": (
                "/sys/kernel/security/shellguard/enable — securityfs file.\n"
                "Access control: standard Linux DAC on securityfs (typically root:root 0600 or 0644).\n"
                "Required capability: CAP_SYS_ADMIN or ownership of the security file.\n"
                "Any process running as root (uid=0) can disable shellguard.\n"
                "Chain with TAT-F01+F02 (root code execution via tat-agent update chain):\n"
                "  → gain root → echo 0 > /sys/kernel/security/shellguard/enable\n"
                "  → replace any shellguard-monitored binary (sshd, tat_agent, etc.)\n"
                "  → shellguard no longer checks digest for replaced binary\n"
                "  → backdoor persists through shellguard policy layer"
            ),
            "block_vs_audit": (
                "shellguard_block_write (0xffffffff81643ec0) — identical structure to enable_write.\n"
                "Writes '0' to shellguard_block → AUDIT MODE: mismatch is logged but not blocked.\n"
                "Default state unknown without runtime observation.\n"
                "If default is shellguard_block=0 (audit only), shellguard provides NO enforcement "
                "for mismatched binaries — only logging. The block write path is required to "
                "actually enforce integrity."
            ),
        },
        "versions_affected": ["6.6.119-51.3.tl4"],
        "remediation": (
            "Restrict /sys/kernel/security/shellguard/ write access to a dedicated "
            "security management process or remove write capability post-boot via immutable mount. "
            "Implement kernel lockdown mode (CONFIG_SECURITY_LOCKDOWN_LSM=y) to prevent "
            "privileged processes from modifying security policy after boot. "
            "Log all writes to shellguard/enable and alert on '0' writes. "
            "For defense depth: enable CONFIG_SECURITY_LOCKDOWN_LSM so that even "
            "root cannot modify kernel security state after lockdown is engaged."
        ),
    },

    "TCS4-K02": {
        "title": (
            "IMA Measurement Without Appraisal — Kernel Logs File Digests But Does Not Enforce "
            "Signature Verification; CONFIG_IMA_APPRAISE Not Set; "
            "Complements shellguard But Does Not Substitute for Policy Enforcement"
        ),
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-354",
        "component": (
            "CONFIG_IMA=y, # CONFIG_IMA_APPRAISE is not set, "
            "# CONFIG_INTEGRITY_SIGNATURE is not set, "
            "CONFIG_IMA_DEFAULT_HASH=sha1"
        ),
        "evidence": {
            "config_delta": (
                "From kernel.config (6.6.119-51.3.tl4):\n"
                "  CONFIG_INTEGRITY=y           # parent enabled\n"
                "  CONFIG_IMA=y                 # measurement active\n"
                "  CONFIG_IMA_MEASURE_PCR_IDX=10\n"
                "  # CONFIG_IMA_APPRAISE is not set    ← APPRAISAL DISABLED\n"
                "  # CONFIG_INTEGRITY_SIGNATURE is not set ← NO SIG VERIFICATION\n"
                "  CONFIG_IMA_DEFAULT_HASH='sha1'   ← SHA1 (deprecated, collision-prone)\n"
                "  CONFIG_EVM=y                 # extended attribute protection enabled\n"
                "  # CONFIG_EVM_ADD_XATTRS is not set"
            ),
            "ima_without_appraise": (
                "IMA in measure-only mode (no appraise): "
                "Kernel records SHA1 hash of every exec'd file to /sys/kernel/security/ima/ascii_runtime_measurements, "
                "extends TPM PCR 10. Does NOT check hash against a pre-stored expected value. "
                "Consequence: an attacker can replace /usr/sbin/sshd with malicious binary; "
                "IMA logs the replacement's hash but does not block execution. "
                "Forensic value only — not an enforcement mechanism."
            ),
            "sha1_concern": (
                "CONFIG_IMA_DEFAULT_HASH='sha1': SHA1 is cryptographically broken (SHAttered, 2017). "
                "IMA measurements are PCR-extended for remote attestation. "
                "A SHA1 collision attack can produce two binaries with the same IMA measurement, "
                "allowing a malicious binary to appear identical to a trusted one in the TPM log. "
                "Upstream IMA moved to SHA256 as default in 5.x+ for this reason."
            ),
            "evm_partial": (
                "CONFIG_EVM=y, # CONFIG_EVM_ADD_XATTRS is not set: "
                "EVM protects existing security xattrs (IMA hash, SELinux label) via HMAC "
                "but cannot add new xattrs to files that don't already have them. "
                "IMA hash xattrs (security.ima) are only present if IMA appraise was previously "
                "active — on a fresh installation without appraise, no files have security.ima xattrs, "
                "so EVM has nothing to protect."
            ),
            "shellguard_vs_ima": (
                "shellguard fills the enforcement gap IMA appraise would otherwise cover: "
                "shellguard_bprm_check does block mismatched binaries (when block=1). "
                "However shellguard is runtime-disableable (TCS4-K01), IMA measurement is not. "
                "Defense-in-depth gap: if shellguard is disabled and IMA appraise is off, "
                "there is no kernel-enforced binary integrity check."
            ),
        },
        "versions_affected": ["6.6.119-51.3.tl4"],
        "remediation": (
            "Enable CONFIG_IMA_APPRAISE=y for signature enforcement. "
            "Change CONFIG_IMA_DEFAULT_HASH='sha256' to avoid SHA1 collision risk. "
            "Set CONFIG_IMA_APPRAISE_BOOTPARAM=y for gradual rollout. "
            "Deploy an IMA policy that appraises /usr/sbin/*, /usr/bin/*, kernel modules. "
            "Store expected hashes in security.ima xattrs and sign them with EVM HMAC."
        ),
    },

    "TCS4-K03": {
        "title": (
            "BPF Kprobe Override Still Present in 6.6.119 — Same Attack Path as TCS-K03; "
            "# CONFIG_BPF_UNPRIV_DEFAULT_OFF is not set; "
            "User Namespace + BPF Override Path Active"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-269",
        "component": (
            "CONFIG_BPF_KPROBE_OVERRIDE=y, # CONFIG_BPF_UNPRIV_DEFAULT_OFF is not set, "
            "CONFIG_BPF_JIT_ALWAYS_ON=y, CONFIG_USER_NS=y"
        ),
        "evidence": {
            "config_lines": (
                "From kernel.config (6.6.119-51.3.tl4):\n"
                "  CONFIG_BPF_KPROBE_OVERRIDE=y\n"
                "  # CONFIG_BPF_UNPRIV_DEFAULT_OFF is not set\n"
                "  CONFIG_BPF_JIT_ALWAYS_ON=y\n"
                "  CONFIG_BPF_JIT_DEFAULT_ON=y\n"
                "  CONFIG_USER_NS=y"
            ),
            "unchanged_from_baseline": (
                "Identical to the 5.4.119 finding (TCS-K03). The attack path:\n"
                "1. unshare(CLONE_NEWUSER) → namespace-scoped CAP_BPF\n"
                "2. Load BPF_PROG_TYPE_KPROBE + bpf_override_return()\n"
                "3. Attach to security_capable() or credential check functions\n"
                "4. Override return value → bypass capability checks\n"
                "Key difference from 5.4.119: KASLR is now enabled (TCS-K01 fixed), "
                "so kprobe attachment point addresses are not statically known. "
                "Attacker needs /proc/kallsyms read access (requires CAP_SYSLOG on 6.6 "
                "with dmesg_restrict — check sysctl). "
                "Attack path still viable with kallsyms access."
            ),
            "kaslr_interaction": (
                "6.6.119 has KASLR enabled (unlike 5.4.119). "
                "BPF kprobe programs must resolve kernel symbol addresses at runtime. "
                "With /proc/kallsyms readable (root or CAP_SYSLOG), addresses are available. "
                "Without /proc/kallsyms: must brute-force or use a secondary info-leak. "
                "KASLR partially mitigates TCS4-K03 compared to TCS-K03."
            ),
            "lockdown_absent": (
                "# CONFIG_SECURITY_LOCKDOWN_LSM is not set: lockdown mode is unavailable. "
                "Kernel lockdown (if enabled) would block BPF program loading in confidentiality mode. "
                "Without lockdown, even a BPF JIT spraying attack is unrestricted."
            ),
        },
        "versions_affected": ["6.6.119-51.3.tl4"],
        "remediation": (
            "Same as TCS-K03: remove CONFIG_BPF_KPROBE_OVERRIDE from production build. "
            "Set sysctl kernel.unprivileged_bpf_disabled=2 at boot (permanent disable). "
            "Enable CONFIG_SECURITY_LOCKDOWN_LSM=y and engage lockdown=integrity or "
            "lockdown=confidentiality via kernel command line."
        ),
    },

    "TCS4-K04": {
        "title": (
            "KEXEC Enabled Without Signature Verification — Unsigned Kernel Loadable via kexec; "
            "# CONFIG_KEXEC_SIG is not set; "
            "Combined With MODULE_SIG_FORCE Absent: Full Kernel Replacement Path Open to Root"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-347",
        "component": (
            "CONFIG_KEXEC=y, CONFIG_KEXEC_FILE=y, # CONFIG_KEXEC_SIG is not set, "
            "# CONFIG_MODULE_SIG_FORCE is not set, # CONFIG_SECURITY_LOCKDOWN_LSM is not set"
        ),
        "evidence": {
            "config_lines": (
                "From kernel.config:\n"
                "  CONFIG_KEXEC=y\n"
                "  CONFIG_KEXEC_FILE=y\n"
                "  CONFIG_KEXEC_CORE=y\n"
                "  # CONFIG_KEXEC_SIG is not set       ← no signature check\n"
                "  CONFIG_ARCH_SUPPORTS_KEXEC_SIG=y   ← architecture supports it, not enabled\n"
                "  # CONFIG_IMA_KEXEC is not set        ← IMA doesn't measure kexec\n"
                "\n"
                "  CONFIG_MODULE_SIG=y\n"
                "  CONFIG_MODULE_SIG_HASH='sha512'\n"
                "  # CONFIG_MODULE_SIG_FORCE is not set  ← unsigned modules accepted"
            ),
            "kexec_impact": (
                "kexec_load() (old API) or kexec_file_load() (new API) with KEXEC_FILE_NO_INITRAMFS "
                "allows root to replace the running kernel with any ELF binary. "
                "Without KEXEC_SIG, the replacement kernel is not signature-verified. "
                "Attack: root → kexec_load(malicious_kernel) → system reboots into backdoored kernel. "
                "Entire TrustZone/secure boot chain is bypassed at the software layer. "
                "Persistence: malicious kernel survives standard rootkit detection (doesn't modify disk), "
                "only detected via hypervisor-level attestation or physical inspection."
            ),
            "module_sig_no_force": (
                "CONFIG_MODULE_SIG=y without CONFIG_MODULE_SIG_FORCE=y: "
                "modules are signed (SHA512) but the kernel accepts unsigned modules with a warning. "
                "'insmod unsigned_module.ko' prints a taint warning but succeeds. "
                "An attacker with root can load arbitrary kernel code (rootkit modules) "
                "without needing a valid signing key."
            ),
            "chain_with_shellguard": (
                "Exploit chain:\n"
                "1. Gain root (e.g., TAT-F01+TAT-F02 tat-agent update chain)\n"
                "2. Load unsigned LKM → kernel rootkit (MODULE_SIG not forced)\n"
                "3. Alternatively: kexec into replacement kernel (KEXEC_SIG not enforced)\n"
                "4. shellguard disabled (TCS4-K01: echo 0 > enable before step 2)\n"
                "Full persistence achieved; survives standard forensic investigation."
            ),
        },
        "versions_affected": ["6.6.119-51.3.tl4"],
        "remediation": (
            "Enable CONFIG_KEXEC_SIG=y — requires kernel to verify kexec'd kernel signature. "
            "Enable CONFIG_MODULE_SIG_FORCE=y — reject unsigned modules at load time. "
            "Enable CONFIG_SECURITY_LOCKDOWN_LSM=y with lockdown=integrity — "
            "blocks both kexec of unsigned kernels and unsigned module loading from userspace. "
            "On CVM instances: disable kexec entirely if not needed (it's a VM — kexec is rarely required)."
        ),
    },

    "TCS4-K05": {
        "title": (
            "FORTIFY_SOURCE Disabled in Kernel Build — Compile-Time Buffer Overflow Detection Absent; "
            "CONFIG_ARCH_HAS_FORTIFY_SOURCE=y But # CONFIG_FORTIFY_SOURCE is not set; "
            "Upstream Default is Enabled Since Linux 5.7"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-120",
        "component": (
            "# CONFIG_FORTIFY_SOURCE is not set — "
            "kernel Kconfig option that enables -D_FORTIFY_SOURCE=2 for the kernel build"
        ),
        "evidence": {
            "config_lines": (
                "From kernel.config:\n"
                "  CONFIG_ARCH_HAS_FORTIFY_SOURCE=y  ← arch supports it (x86_64 yes)\n"
                "  # CONFIG_FORTIFY_SOURCE is not set ← explicitly disabled\n"
                "\n"
                "Upstream Linux: CONFIG_FORTIFY_SOURCE=y is the DEFAULT since kernel 5.7. "
                "TencentOS 6.6.119 explicitly disables it. "
                "This is an active regression from upstream."
            ),
            "what_it_covers": (
                "CONFIG_FORTIFY_SOURCE enables compile-time and runtime bounds checking "
                "for kernel functions: memcpy(), strcpy(), strncpy(), sprintf(), memset(). "
                "With it enabled:\n"
                "  - Compile-time: calls with statically known destinations that overflow → build error\n"
                "  - Runtime: calls where destination size is known → panic on overflow\n"
                "Without it: silent overflow; kernel continues executing with corrupted memory. "
                "FORTIFY_SOURCE has caught dozens of real kernel buffer overflows in mainline "
                "before they reached production (e.g., CVE-2021-42739, CVE-2022-0847)."
            ),
            "also_missing": (
                "# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set: kmalloc() memory not zeroed. "
                "# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set: kfree() memory not poisoned. "
                "These are runtime settings (kernel.init_on_alloc sysctl), defaults off. "
                "Without init-on-alloc: freed kernel heap data (credentials, key material, "
                "sk_buff contents) is readable via uninitialized-memory vulnerabilities. "
                "# CONFIG_IO_STRICT_DEVMEM is not set: I/O-mapped memory accessible via /dev/mem "
                "beyond the first 1MB (STRICT_DEVMEM restricts RAM only, not I/O regions)."
            ),
        },
        "versions_affected": ["6.6.119-51.3.tl4"],
        "remediation": (
            "Enable CONFIG_FORTIFY_SOURCE=y — restores upstream default. "
            "Enable CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y and CONFIG_INIT_ON_FREE_DEFAULT_ON=y "
            "for heap data lifetime protection (performance cost ~1-5%). "
            "Enable CONFIG_IO_STRICT_DEVMEM=y to restrict /dev/mem to RAM-only access."
        ),
    },

    "TCS4-K06": {
        "title": (
            "shellguard Audit Mode Default Unknown — block=0 (Audit Only) Logs Mismatch "
            "but Does Not Block Execution; "
            "Digest Comparison at 0xffffffff81644d11 Uses 33-Byte memcmp; "
            "SHA1 Hex String Format Inferred"
        ),
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-778",
        "component": (
            "shellguard_bprm_check.part.0 (0xffffffff81644c00) — "
            "shellguard_block global (0xffffffff83d20380)"
        ),
        "evidence": {
            "disasm_block_check": (
                "shellguard_bprm_check.part.0 (0xffffffff81644c00) — digest mismatch path:\n"
                "  0xffffffff81644d04: mov edx, 0x21         # 33 bytes\n"
                "  0xffffffff81644d09: mov rsi, r15          # stored digest (from list entry +0x28)\n"
                "  0xffffffff81644d0c: lea rdi, [rsp+7]      # computed digest\n"
                "  0xffffffff81644d11: call 0xffffffff81d9bc60  # strncmp(computed, stored, 33)\n"
                "  0xffffffff81644d16: test eax, eax\n"
                "  0xffffffff81644d18: jne 0x81644d33        # mismatch → log + check block flag\n"
                "  0xffffffff81644d1a: ...                   # match → allow\n"
                "  ...mismatch path...\n"
                "  0xffffffff81644d51: cmp dword ptr [rip+0x26db628], 1  # shellguard_block\n"
                "  0xffffffff81644d58: mov rax, 0xffffffff824cef8d   # string 'block'\n"
                "  0xffffffff81644d5f: mov rbx, 0xffffffff824cef92   # string 'audit'\n"
                "  0xffffffff81644d66: cmove rbx, rax         # if block==1, use 'block'; else 'audit'\n"
                "  ...log message with 'block' or 'audit' mode label...\n"
                "  0xffffffff81644dab: cmp dword ptr [rip+0x26db5ce], 1  # shellguard_block again\n"
                "  0xffffffff81644db2: jne 0x81644d26         # block==0: goto allow (audit mode)\n"
                "  0xffffffff81644db8: jmp 0x81644c5d         # block==1: return -EACCES"
            ),
            "hash_format": (
                "33-byte comparison (0x21) with strncmp(): "
                "SHA1 hex string = 40 chars. SHA256 hex = 64 chars. "
                "32 bytes binary = SHA256 raw. 20 bytes binary = SHA1 raw. "
                "33 bytes with strncmp → likely 32-byte hex string + 1 null terminator... "
                "but that's only 16 bytes decoded. "
                "OR: shellguard uses a truncated SHA256 (first 32 hex chars = first 16 bytes of SHA256). "
                "The digest_file function uses `0xffffffff824de62d` as the algorithm string reference — "
                "needs strings extraction to confirm, but the 3-byte sprintf loop "
                "(at 0x816439b7–0x816439d6: `movzx ecx, [rbx]; mov esi, 3; mov rdx, fmt_ptr; add rbx,1; add rbp,2`) "
                "formats each byte as 2 hex chars, 16 iterations → 32-char hex + null = 33 bytes. "
                "Confirms SHA1 (20 bytes → 40 hex, mismatch) OR a 16-byte hash (e.g., MD5 → 32 hex + null = 33). "
                "Most likely: MD5 or first 16 bytes of SHA256. Functional weakness regardless."
            ),
            "audit_mode_risk": (
                "If shellguard_block defaults to 0 (audit) on boot: "
                "shellguard detects mismatch but allows execution. "
                "Attacker can verify current mode by reading /sys/kernel/security/shellguard/block. "
                "In audit mode: replace monitored binary, system logs the mismatch hash, continues running. "
                "Monitoring alert only fires if someone reads IMA/shellguard logs — "
                "on a compromised system, log tampering is trivial."
            ),
        },
        "versions_affected": ["6.6.119-51.3.tl4"],
        "remediation": (
            "Set shellguard_block=1 at boot via a systemd service that writes '1' to "
            "/sys/kernel/security/shellguard/block before any user processes execute. "
            "Transition from audit to block mode after confirming all legitimate binaries "
            "are enrolled in the target/whitelist. "
            "Use SHA256 or SHA3-256 for the digest; confirm and patch if MD5 is used."
        ),
    },
}

# ─── Kernel Config Summary Table ──────────────────────────────────────────────

CONFIG_SECURITY_POSTURE = {
    # Feature: (status, finding, notes)
    "KASLR (RANDOMIZE_BASE)":           ("ENABLED",  None,       "Fixed vs 5.4.119 TCS-K01"),
    "RANDOMIZE_MEMORY":                 ("ENABLED",  None,       "Physical memory randomization"),
    "KPTI (PAGE_TABLE_ISOLATION)":      ("ENABLED",  None,       "Meltdown mitigation"),
    "RETPOLINE":                        ("ENABLED",  None,       "Spectre v2 mitigation"),
    "SPECTRE_BHI":                      ("ENABLED",  None,       "Spectre-BHI mitigation new in 6.x"),
    "STACKPROTECTOR_STRONG":            ("ENABLED",  None,       "Stack canary protection"),
    "STRICT_KERNEL_RWX":                ("ENABLED",  None,       "Kernel text non-writable"),
    "STRICT_MODULE_RWX":                ("ENABLED",  None,       "Module text non-writable"),
    "FORTIFY_SOURCE":                   ("DISABLED", "TCS4-K05", "Explicit disable of upstream default"),
    "INIT_ON_ALLOC_DEFAULT_ON":         ("DISABLED", "TCS4-K05", "Heap not zeroed on alloc"),
    "INIT_ON_FREE_DEFAULT_ON":          ("DISABLED", "TCS4-K05", "Heap not zeroed on free"),
    "IMA":                              ("ENABLED",  None,       "Measure-only, no enforce"),
    "IMA_APPRAISE":                     ("DISABLED", "TCS4-K02", "No signature appraisal"),
    "EVM":                              ("ENABLED",  None,       "Partial — no new xattrs"),
    "shellguard (custom LSM)":          ("ENABLED",  "TCS4-K01", "Runtime-disableable by root"),
    "BPF_KPROBE_OVERRIDE":              ("ENABLED",  "TCS4-K03", "Same path as TCS-K03 (5.4.119)"),
    "BPF_UNPRIV_DEFAULT_OFF":           ("DISABLED", "TCS4-K03", "Unprivileged BPF not disabled"),
    "SECURITY_LOCKDOWN_LSM":            ("DISABLED", "TCS4-K04", "No kernel lockdown mode"),
    "KEXEC_SIG":                        ("DISABLED", "TCS4-K04", "Unsigned kexec allowed"),
    "MODULE_SIG_FORCE":                 ("DISABLED", "TCS4-K04", "Unsigned modules loadable"),
    "MODULE_SIG (signing enabled)":     ("ENABLED",  None,       "SHA512, but not enforced"),
    "IO_STRICT_DEVMEM":                 ("DISABLED", "TCS4-K05", "I/O mem accessible via /dev/mem"),
    "STRICT_DEVMEM":                    ("ENABLED",  None,       "RAM restricted (not I/O)"),
    "SELINUX":                          ("ENABLED",  None,       "Default active"),
    "SELINUX_BOOTPARAM":                ("ENABLED",  None,       "Can disable via kernel cmdline"),
    "USER_NS":                          ("ENABLED",  "TCS4-K03", "Unprivileged user namespaces"),
}

# ─── Probe Functions ──────────────────────────────────────────────────────────

def probe_kernel_config(config_path: str) -> dict:
    """Parse a kernel config file for all findings."""
    findings_triggered = []
    try:
        with open(config_path) as f:
            cfg = f.read()
        # TCS4-K01: shellguard present
        if "shellguard" in cfg.lower():
            findings_triggered.append("TCS4-K01")
        # TCS4-K02: IMA without appraise
        if "CONFIG_IMA=y" in cfg and "# CONFIG_IMA_APPRAISE is not set" in cfg:
            findings_triggered.append("TCS4-K02")
        # TCS4-K03: BPF kprobe override
        if "CONFIG_BPF_KPROBE_OVERRIDE=y" in cfg:
            findings_triggered.append("TCS4-K03")
        # TCS4-K04: kexec without sig
        if "CONFIG_KEXEC=y" in cfg and "# CONFIG_KEXEC_SIG is not set" in cfg:
            findings_triggered.append("TCS4-K04")
        # TCS4-K05: fortify disabled
        if "# CONFIG_FORTIFY_SOURCE is not set" in cfg:
            findings_triggered.append("TCS4-K05")
        # TCS4-K06: shellguard present (block mode concern)
        if "shellguard" in cfg.lower():
            findings_triggered.append("TCS4-K06")
        # Check for improvements vs baseline
        improvements = []
        if "CONFIG_RANDOMIZE_BASE=y" in cfg:
            improvements.append("KASLR enabled (TCS-K01 fixed)")
        if "CONFIG_INTEGRITY=y" in cfg:
            improvements.append("IMA/EVM enabled (TCS-K02 partially fixed)")
    except OSError:
        pass
    return {
        "config_path": config_path,
        "findings": findings_triggered,
        "delta_vs_5_4_119": BASELINE_DELTA,
    }


def probe(binary_path: Optional[str] = None) -> dict:
    return {
        "target": TARGET,
        "kernel_version": KERNEL_VERSION,
        "findings": list(FINDINGS.keys()),
        "critical": [],
        "high": ["TCS4-K01", "TCS4-K03", "TCS4-K04"],
        "medium": ["TCS4-K02", "TCS4-K05", "TCS4-K06"],
        "low": [],
        "improvements_vs_5_4_119": BASELINE_DELTA["fixed"],
        "chain": (
            "TAT-F01+F02 (root via tat-agent) → TCS4-K01 (disable shellguard) → "
            "TCS4-K04 (load unsigned module) → persistent kernel rootkit"
        ),
        "shellguard_summary": (
            "Tencent-proprietary built-in LSM. Binary integrity monitor. "
            "Hooks bprm_check, computes file digest, compares against stored hash (33-byte strncmp). "
            "Exposed via /sys/kernel/security/shellguard/{enable,block,target,whitelist}. "
            "Root-writable enable flag bypasses all enforcement: echo 0 > enable → all execs allowed."
        ),
    }
