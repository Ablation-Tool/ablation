"""
TencentOS 4.6 — Hygon/Zhaoxin hardware crypto and security module suite RE.

Six modules forming TOS's Chinese-hardware-accelerated crypto + kernel integrity stack:

  sm2_zhaoxin.ko  (14998B) — SM2 ECC signatures via Zhaoxin GMI hardware (repnz montmul)
  sm3_zhaoxin.ko  (19166B) — SM3 hash (GB/T 32905-2016) via Zhaoxin GMI
  sm4_zhaoxin.ko  (34414B) — SM4 block cipher (ECB/CBC/CTR/CFB/OFB) via Zhaoxin GMI (rep xcrypt*)
  tcm_hygon.ko    (18214B) — TCM2 (Chinese national TPM, GM/T 0012) via Hygon PSP
  tpm_hygon.ko    (15774B) — TPM2 via Hygon PSP
  tdm-kernel-guard.ko (24686B) — SCT/IDT integrity guard via Hygon PSP hardware measurement

All six: kernel 6.6.119-51.3.tl4.x86_64 (TOS 4.6).
SM2/SM3/SM4 unsigned (no sig_id in modinfo).
TCM/TPM Hygon: production key 01:9D:01:14:84:D7 (sha256, same as TOS 4.6 ttools/kill_protect).
tdm-kernel-guard: no signature listed in modinfo (not shown).

This suite reflects TOS's localization for Chinese domestic hardware:
  Zhaoxin: Shanghai-based x86 CPU (Via/THATIC JV) with national crypto hw extensions
  Hygon: Tianjin AMD-licensed x86 CPU with PSP-based security coprocessor
"""

METADATA = {
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "hardware_targets": {
        "Zhaoxin": "Via/Shanghai Municipal Gov JV, x86 CPUs with GMI (Guomi Instructions)",
        "Hygon": "AMD-licensed x86 CPUs for China (via THATIC JV), with PSP security coprocessor",
    },
    "modules": {
        "sm2_zhaoxin": {
            "size_bytes": 14998,
            "description": "SM2 Zhaoxin GMI Algorithm",
            "author": "YunShen <yunshen@zhaoxin.com>",
            "name": "sm2_zhaoxin_gmi",
            "cpu_feature": "feature:*00A0*",
            "aliases": ["crypto-zhaoxin-gmi-sm2", "zhaoxin-gmi-sm2"],
        },
        "sm3_zhaoxin": {
            "size_bytes": 19166,
            "description": "SM3 Secure Hash Algorithm",
            "name": "sm3_zhaoxin_gmi",
            "aliases": ["crypto-sm3-zhaoxin-gmi", "sm3-zhaoxin-gmi", "crypto-sm3-zhaoxin", "sm3-zhaoxin"],
        },
        "sm4_zhaoxin": {
            "size_bytes": 34414,
            "description": "SM4-ECB/CBC/CTR/CFB/OFB using Zhaoxin GMI",
            "author": "GRX",
            "name": "sm4_zhaoxin_gmi",
        },
        "tcm_hygon": {
            "size_bytes": 18214,
            "description": "TCM2 device driver for Hygon PSP",
            "author": "mayuanchen (mayuanchen@hygon.cn)",
            "name": "tcm_hygon",
            "acpi_id": "HYGT0201",
            "depends": "ccp",
        },
        "tpm_hygon": {
            "size_bytes": 15774,
            "description": "TPM2 device driver for Hygon PSP",
            "author": "mayuanchen (mayuanchen@hygon.cn)",
            "name": "tpm_hygon",
            "acpi_id": "HYGT0101",
            "depends": "ccp",
        },
        "tdm_kernel_guard": {
            "size_bytes": 24686,
            "description": "Kernel security enhancement module by TDM",
            "author": "niuyongwen@hygon.cn",
            "version": "0.1",
            "name": "tdm_kernel_guard",
            "depends": "ccp",
            "parameters": {
                "tdm_guard": "Enable TDM protection (on|off, default: off)",
                "eh_obj": "Bitmap of protected targets (bit0=SCT, bit1=IDT, default: both)",
            },
        },
    },
}

ZHAOXIN_GMI_ANALYSIS = {
    "architecture": "Zhaoxin GMI (Guomi Instructions, 国密指令)",
    "encoding": (
        "GMI instructions reuse the VIA Padlock encoding space — x87/MMX instruction "
        "prefixes (0xf2 0x0f 0xa6 / 0xf3 0x0f 0xa7) followed by opcode bytes. "
        "objdump disassembles these as '(bad)' or 'repz/repnz (bad)' because it "
        "does not recognize the Zhaoxin-specific opcodes."
    ),
    "instructions": {
        "rep xcryptecb (f3 0f a7 f0)": "SM4 hardware ECB block cipher — one or more 128-bit blocks",
        "rep xcryptcbc (f3 0f a7 d0)": "SM4 hardware CBC mode",
        "rep xcryptctr (f3 0f a7 d8)": "SM4 hardware CTR mode",
        "rep xcryptcfb (f3 0f a7 e0)": "SM4 hardware CFB mode",
        "rep xcryptofb (f3 0f a7 e8)": "SM4 hardware OFB mode",
        "repnz montmul (f2 0f a6 c0)": "SM2 hardware Montgomery multiplication for ECC",
    },
    "cpu_detection": "CPU feature bit 0x00A0 in CPUID extended feature flags",
    "fallback": "Software implementations (_zxc suffix variants) for non-Zhaoxin CPUs",
}

SM2_ANALYSIS = {
    "standard": "GB/T 32918 — SM2 Elliptic Curve Public Key Cryptography",
    "curve": "256-bit prime field Fp, defined by Chinese national standard",
    "operations": {
        "zhaoxin_sm2_init_tfm": {
            "addr": 0x0080,
            "purpose": "Allocate SM2 transform context, GFP_KERNEL=0xcc0 (14 bytes?)",
        },
        "zhaoxin_sm2_set_pub_key": {
            "addr": 0x00c0,
            "purpose": "Set public key for verification",
        },
        "zhaoxin_sm2_verify": {
            "addr": 0x00f0,
            "purpose": "Verify SM2 digital signature using GMI hardware",
            "key_ops": [
                "GFP_KERNEL=0xcc0 for initial alloc",
                "GFP_KERNEL|__GFP_ZERO=0xdc0 for 0x2000 (8192B) working buffer",
                "repnz montmul (f2 0f a6 c0) — hardware Montgomery multiplication",
                "Returns 0 on success, -129 (0xffffff7f) on verify failure",
            ],
        },
    },
    "kernel_api": "akcipher_alg registered via crypto_register_akcipher",
    "note": "No imports from other modules — fully self-contained except kernel crypto API",
}

SM3_ANALYSIS = {
    "standard": "GB/T 32905-2016 — SM3 Cryptographic Hash Algorithm",
    "output": "256-bit (32 bytes)",
    "initial_values": {
        "IV0": "0x7380166f419da8b4",
        "IV1": "0x68adad7422417",
        "IV2": "0xaa383116bc306fa9",
        "IV3": "0x4e0efbb04dee8de3",
        "note": (
            "These are the SM3 initial hash values from GB/T 32905 §5.3.3. "
            "IV splits: 7380166f 4192b878 (two 32-bit words each) → confirmed from zx_sm3_init "
            "loading them as 64-bit immediate values."
        ),
    },
    "functions": {
        "zx_sm3_init": {
            "addr": 0x0010,
            "purpose": "Load SM3 IV into state struct at caller-provided pointer",
            "size": 4,
            "returns": "0 on success, -22 (EINVAL) if NULL state pointer",
        },
        "zx_sm3_update": {
            "addr": 0x0360,
            "purpose": "Process 64-byte blocks, handling partial blocks",
        },
        "zx_sm3_final": {
            "addr": 0x0080,
            "purpose": "Pad message, process final blocks, output 32B digest",
        },
        "sm3_generic_block_fn": {
            "addr": 0x04e0,
            "purpose": "Software SM3 compression function for non-hardware path",
        },
    },
    "kernel_api": "shash_alg registered via crypto_register_shash",
}

SM4_ANALYSIS = {
    "standard": "GB/T 32907-2016 — SM4 Block Cipher Algorithm (128-bit key, 128-bit block)",
    "modes": {
        "ECB": {"encrypt": "ecb_encrypt at 0x04f0", "decrypt": "ecb_decrypt at 0x0480"},
        "CBC": {"encrypt": "cbc_encrypt at 0x0410", "decrypt": "cbc_decrypt at 0x03a0"},
        "CTR": {"encrypt": "ctr_encrypt at 0x0b50", "decrypt": "ctr_decrypt at 0x0ae0"},
        "CFB": {"encrypt": "cfb_encrypt at 0x0250", "decrypt": "cfb_decrypt at 0x01e0"},
        "OFB": {"encrypt": "ofb_encrypt at 0x0330", "decrypt": "ofb_decrypt at 0x02c0"},
    },
    "hardware_path": {
        "suffix": "_zxc (e.g., ctr_encrypt_zxc)",
        "mechanism": "rep xcrypt* GMI instructions",
        "rep_xcrypt": {
            "addr": 0x00c0,
            "function": "rep_xcrypt.isra.0",
            "mechanism": (
                "Sets up register state (rdi=src, rsi=dst, rcx=key, rdx=iv, r8=flags), "
                "then emits f3 0f a7 (followed by opcode byte) — the GMI hardware instruction. "
                "The 'REP' prefix triggers repeated 128-bit block processing. "
                "Objdump decodes the GMI bytes as 'repz (bad) lock pop %rdi' — unrecognized encoding."
            ),
        },
    },
    "software_path": {
        "function": "sm4_cipher_common at 0x0110",
        "suffix": "(no _zxc) — runs on non-Zhaoxin x86",
    },
    "simd": "simd_skcipher wrappers registered for CRYPTO_ALG_ASYNC support",
    "kernel_api": "crypto_register_skciphers (multiple algorithms at once)",
}

TCM_HYGON_ANALYSIS = {
    "standard": "GM/T 0012-2020 — TCM2 (Trusted Cryptography Module v2, Chinese national TPM)",
    "hardware": "Hygon PSP (Platform Security Processor) — AMD PSP fork via THATIC JV",
    "acpi_id": "HYGT0201",
    "psp_interface": {
        "psp_do_cmd": "Submit command to PSP — imported from ccp (Crypto Co-Processor module)",
        "tpmm_chip_alloc": "Allocate TCM/TPM chip structure (uses kernel TPM subsystem)",
        "tpm_chip_register": "Register device with /dev/tcm subsystem",
    },
    "device_nodes": {
        "tcm%d": "Standard TCM interface — /dev/tcm0",
        "tcmrm%d": "TCM Resource Manager — /dev/tcmrm0 (management interface)",
    },
    "ops": {
        "tcm_c_send": {
            "addr": 0x00a0,
            "purpose": "Send TCM command to PSP hardware",
        },
        "tcm_c_recv": {
            "addr": 0x0040,
            "purpose": "Receive TCM response from PSP hardware",
        },
    },
    "tcm_header_t": "TCM2 command header structure (standard GM/T 0012 format)",
    "note": (
        "TCM and TPM coexist: tcm_hygon and tpm_hygon are separate modules on the same PSP. "
        "HYGT0201 = TCM (Chinese standard), HYGT0101 = TPM (international standard). "
        "The Hygon PSP implements both, selectable by ACPI device ID."
    ),
}

TPM_HYGON_ANALYSIS = {
    "standard": "TCG TPM 2.0 (international standard) via Hygon PSP",
    "acpi_id": "HYGT0101",
    "relationship_to_tcm": (
        "Parallel module to tcm_hygon — same PSP hardware, different protocol. "
        "TPM follows TCG specification; TCM follows Chinese GM/T 0012. "
        "They cannot be loaded simultaneously (both claim /dev/tpm0 node)."
    ),
}

TDM_KERNEL_GUARD_ANALYSIS = {
    "purpose": "Hardware-backed kernel integrity monitor: SCT + IDT corruption detection via Hygon PSP",
    "protected_objects": {
        "bit0_SCT": "System Call Table — sys_call_table array of function pointers",
        "bit1_IDT": "Interrupt Descriptor Table — interrupt/exception handler pointers",
        "default": "Both (eh_obj=3)",
    },
    "mechanism": {
        "step1_find_sct": {
            "function": "kprobe_symbol_address_byname",
            "addr": 0x03e0,
            "technique": (
                "Linux 5.7+ unexported kallsyms_lookup_name from modules. "
                "The standard bypass: register_kprobe with symbol name → kprobe.addr = symbol address. "
                "Function zeroes a kprobe struct (rep stosq), sets kp.symbol_name = 'sys_call_table', "
                "calls register_kprobe → kernel populates kp.addr. "
                "Extracts addr from kp+0x28 (kprobe.addr offset), then unregister_kprobe. "
                "Logs 'kallsyms_lookup_name for sys_call_table failed!' if kprobe fails."
            ),
        },
        "step2_hash": {
            "function": "calc_expected_hash",
            "addr": 0x0090,
            "purpose": "Compute expected hash of SCT or IDT memory region",
            "algorithm": "crypto_alloc_shash → shash_init → shash_update(addr_range) → shash_final",
            "stack": "0x180 bytes local + canary at 0x178(%rsp)",
        },
        "step3_psp": {
            "functions": [
                "psp_check_tdm_support — verify Hygon PSP has TDM capability",
                "psp_create_measure_task — create PSP hardware measurement task",
                "psp_register_measure_exception_handler — register callback on corruption",
                "psp_startstop_measure_task — start/stop hardware monitoring",
            ],
            "note": "All PSP functions imported from ccp module (Crypto Co-Processor)",
        },
        "step4_detect": {
            "handler": "tdm_regi_callback_handler at 0x0030",
            "trigger": "PSP hardware detects that SCT or IDT memory changed",
            "action": "Log KERN_WARNING: 'Obj: %s, Task:%d, corruption detected!'",
        },
    },
    "tdm_service_run": {
        "addr": 0x01a0,
        "purpose": "Main service function: set up measurement task for one protected object",
        "key_ops": [
            "GFP_KERNEL|__GFP_ZERO = 0xdc0 for 20B task struct",
            "GFP_KERNEL|__GFP_ZERO = 0xdc0 for 18B measurement buffer",
            "orl $0x40000,0x48(%rbx) — set flag 0x40000 in task struct",
            "call calc_expected_hash → hash the protected memory region",
            "call psp_register_measure_exception_handler — register corruption callback",
            "call psp_startstop_measure_task(task_id, 1) — start monitoring",
        ],
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "Zhaoxin GMI instructions unrecognized by analysis tools — objdump decodes as (bad)",
        "detail": (
            "SM4 and SM2 use Zhaoxin GMI hardware instructions (rep xcrypt*, repnz montmul). "
            "These instructions are not in any standard x86 disassembler database (objdump, radare2, IDA, Ghidra). "
            "Any security analysis of code that uses these instructions will silently skip them — "
            "a disassembler that emits '(bad)' and a CFG builder that stops at unknown opcodes "
            "will miss the actual crypto operation. "
            "If a TOS system uses Zhaoxin GMI for TLS/kernel crypto operations, "
            "analysis tools that can't decode these instructions cannot verify correctness. "
            "Fuzzing at the instruction level also fails: the GMI instructions have "
            "implicit memory operands (src/dst in specific registers) that fuzzers won't know to reach."
        ),
        "gmi_encoding": "f3 0f a7 / f2 0f a6 prefix bytes in VIA Padlock encoding space",
        "affected_tools": ["objdump", "Ghidra", "radare2", "LLDB", "most CFG analysis tools"],
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "tdm-kernel-guard uses kprobe trick to find sys_call_table — bypassable via kprobe disable",
        "detail": (
            "kprobe_symbol_address_byname registers a kprobe on 'sys_call_table' to get its address. "
            "If the kernel is compiled with CONFIG_KPROBES=n, or if kprobes are disabled at runtime "
            "(via /proc/sys/debug/kprobes-optimization), the symbol lookup fails and "
            "TDM protection never starts — silently. "
            "The error path just logs 'kprobe_symbol_address_byname failed!' at KERN_ERR. "
            "An attacker with CAP_SYS_ADMIN who wants to replace sys_call_table entries "
            "can first disable kprobes, then load tdm-kernel-guard (it starts with no protection), "
            "then re-enable kprobes — SCT is permanently unmonitored. "
            "Alternatively: tdm_guard=off parameter disables all protection at load time."
        ),
        "attack": "disable kprobes → load guard (no protection) → hook SCT → enable kprobes",
        "default_state": "tdm_guard=off — disabled by default, must be explicitly enabled",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "tdm-kernel-guard default off — SCT/IDT integrity protection is opt-in, not default",
        "detail": (
            "Module parameter tdm_guard defaults to 'off'. "
            "Loading tdm-kernel-guard without specifying tdm_guard=on provides zero protection. "
            "The module loads successfully, logs 'Hygon TDM guard load successfully!', "
            "and does nothing. "
            "On TOS systems where tdm-kernel-guard is in initramfs but not configured with tdm_guard=on "
            "in the module options, the security benefit is completely absent. "
            "Administrators may believe the module provides protection when it does not."
        ),
        "default_parameter": "tdm_guard=off",
        "observable_confusion": "Module load success log is identical whether protection is on or off",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "TCM (GM/T 0012) and TPM (TCG) cannot coexist — one blocks /dev/tpm0",
        "detail": (
            "tcm_hygon and tpm_hygon both call tpm_chip_register to claim the /dev/tpm device node. "
            "Both use the same Hygon PSP hardware. "
            "Loading both simultaneously means the second registration fails "
            "or they share the PSP command path, corrupting each other's command sequences. "
            "TCM (Chinese national standard) is required for compliance with Chinese cryptographic regulations; "
            "TPM (international TCG) is required by many enterprise tools (measured boot, BitLocker, Kubernetes attestation). "
            "A TOS host that needs both standards has no clear resolution — "
            "the modules are designed as alternatives, not complements."
        ),
        "conflict": "Both claim /dev/tpm0 via tpm_chip_register on the same PSP hardware",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "SM2 verify: -129 (0xffffff7f) return on failure — non-standard error code",
        "detail": (
            "zhaoxin_sm2_verify returns 0xffffff7f on signature mismatch. "
            "In the Linux kernel, -EBADMSG is typically -74 (0xffffffba), "
            "and signature verification failures should return -EKEYREJECTED (-129 = 0xffffff7f). "
            "0xffffff7f = -129 = -EKEYREJECTED. "
            "This is actually the correct Linux error code for key/signature rejection. "
            "However, the return value is checked at 0x17f: 'cmovne %eax,%ebx' where eax=0xffffff7f, "
            "so if rcx != 1, the failure code is used — the condition check for rcx=1 is unclear "
            "without full context. The verify semantics need confirming against the SM2 spec."
        ),
        "return_on_failure": 0xffffff7f,
        "linux_ekeyrejected": -129,
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "SM4 software fallback (_zxc vs non-_zxc) — mode selection unclear without runtime check",
        "detail": (
            "SM4 has two implementations of each mode: software (no suffix) and hardware (_zxc). "
            "The selection between them is not visible in the module's exported symbols — "
            "presumably done via the simd_skcipher mechanism or CPU feature check at registration. "
            "If the CPU feature check incorrectly reports Zhaoxin GMI support on a non-Zhaoxin CPU, "
            "the hardware path executes the unknown GMI opcodes, causing an Illegal Instruction exception. "
            "The cpu:type:x86,ven*fam*mod*:feature:*00A0* alias auto-loads this module "
            "when the CPU reports feature 0x00A0 — module loading is automatic, "
            "not operator-controlled."
        ),
        "auto_load_alias": "cpu:type:x86,ven*fam*mod*:feature:*00A0*",
        "risk": "wrong CPU feature → illegal instruction on GMI opcode",
    },
    {
        "id": "F7",
        "severity": "MEDIUM",
        "title": "tdm-kernel-guard corruption alert is log-only — no kill, no panic, no enforcement",
        "detail": (
            "When PSP detects SCT or IDT corruption, tdm_regi_callback_handler fires "
            "and logs at KERN_WARNING: 'corruption detected! Please check if it's intended, "
            "or your machine may be on danger!' "
            "There is no: process kill, kernel panic, securityfs notification, netlink alert, "
            "or sysrq trigger. "
            "A rootkit that replaces a syscall entry gets a warning in dmesg and continues running. "
            "The protection is detection-only, not prevention. "
            "If dmesg is not monitored (no SIEM, no auditd), the alert is silently discarded."
        ),
        "response_on_detection": "KERN_WARNING log only (no enforcement action)",
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "Hygon PSP is AMD PSP fork — CCP module provides PSP command interface",
        "detail": (
            "All four Hygon modules depend on 'ccp' (AMD Crypto Co-Processor). "
            "Hygon licensed AMD's Zen 1 (Naples) architecture via the THATIC joint venture. "
            "The Hygon PSP (Platform Security Processor) is a fork of AMD's PSP. "
            "Both use the same AMD CCP driver (ccp.ko) as the kernel interface. "
            "psp_do_cmd / psp_create_measure_task etc. are PSP commands submitted "
            "via the CCP mailbox protocol. "
            "Hygon adds TDM (Trusted Data Measurement) extensions not present in AMD's PSP — "
            "these are PSP firmware extensions specific to Hygon CPUs."
        ),
        "hygon_psp_extensions": ["TCM2 (GM/T 0012)", "TDM hardware measurement"],
        "shared_ccp_driver": True,
    },
]

if __name__ == '__main__':
    print("Hygon/Zhaoxin hardware crypto + security suite (TOS 4.6) RE analysis")
    print()
    for name, info in METADATA['modules'].items():
        print(f"  {name}: {info['description']} ({info['size_bytes']}B)")
    print()
    print("Zhaoxin GMI hardware instructions:")
    for instr, desc in ZHAOXIN_GMI_ANALYSIS['instructions'].items():
        print(f"  {instr}: {desc[:60]}")
    print()
    print("TDM guard mechanism:")
    print(f"  1. {TDM_KERNEL_GUARD_ANALYSIS['mechanism']['step1_find_sct']['technique'][:80]}")
    print(f"  2. calc_expected_hash via crypto_alloc_shash")
    print(f"  3. psp_create_measure_task + psp_register_measure_exception_handler")
    print(f"  4. On corruption: KERN_WARNING log only")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
