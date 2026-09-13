"""
Fortinet FortiFirewall FFW_VM64_KVM 8.0.0 RE
Source: FFW_VM64_KVM-v8.0.0.F-build0167-FORTINET.out.kvm.zip -> fortios.qcow2
Build date: 2026-04-20 | kernel: Linux 4.19.13 (root@3ff2a6779e73)
Extraction path: QCOW2 -> virtioa.raw -> P1 (sector 2048, dd) -> ext2 mount -> flatkc (bzImage)
Accessible layers: P1 boot partition (ext2), flatkc kernel (gzip bzImage, decompressed)
Encrypted layers: rootfs.gz (custom magic 0xa3ba56c6, NOT gzip, NOT FGT/FAZ format)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":        "Fortinet FortiFirewall VM64-KVM",
    "os":             "FortiFirewall OS 8.0.0.F",
    "build":          "0167",
    "build_date":     "2026-04-20",
    "kernel":         "Linux 4.19.13",
    "kernel_builder": "root@3ff2a6779e73",
    "arch":           "x86-64",

    "image_structure": {
        "out_file":    "FFW_VM64_KVM-v8.0.0.F-build0167-FORTINET.out (gzip, inner name FFWKVM-8.00-FW-build0167-260420)",
        "kvm_zip":     "FFW_VM64_KVM-v8.0.0.F-build0167-FORTINET.out.kvm.zip -> fortios.qcow2 (128MB)",
        "raw_size":    "2GB virtual disk",
        "p1_offset":   "sector 2048 (1048576 bytes)",
        "p1_size":     "256MB (524288 sectors)",
        "p1_type":     "0x83 Linux ext2",
        "p2":          "type 0x83 Linux, 1727MB (data partition)",
        "p3":          "type 0xef EFI system, 64MB",
        "p1_files":    ["flatkc (7.6MB bzImage)", "rootfs.gz (91MB encrypted)", "datafs.tar.gz (20MB)"],
        "bootline":    "DEFAULT flatkc ro panic=5 endbase=0xA0000 console=ttyS0, root=/dev/ram0 ramdisk_size=65536 initrd=/rootfs.gz",
    },

    "kernel_details": {
        "format":              "bzImage with MZ header",
        "payload_compression": "gzip (1f 8b magic)",
        "payload_offset_field": "0x248 (boot protocol 0x020d)",
        "payload_foff":        "0x43b1 (setup_size=16384 + payload_off=0x3b1)",
        "decompressed_size":   "26MB ELF vmlinux",
        "vmlinux_entry":       "0xffffffff80200000",
        "text_segment":        "VMA 0xffffffff80200000 / file offset 0x200000",
        "kernel_version_note": (
            "Linux 4.19.13 -- SIGNIFICANTLY older than FGT/FAZ/FMG 8.0.0 (which uses 6.12.32). "
            "FFW is on a different, older kernel branch. Different mitigation profile."
        ),
    },

    "encryption_status": {
        "rootfs_gz": (
            "Encrypted. Magic bytes 0xa3ba56c6c411eba1 -- no known format. "
            "DIFFERENT from FAZ/FMG 8.0.0 (0x5b6758cb), DIFFERENT from gzip (0x1f8b). "
            "FFW-specific encryption format. Inaccessible without decryption key."
        ),
        "flatkc": "Accessible (gzip bzImage). vmlinux extracted.",
        "datafs_tar_gz": "Standard gzip. Not yet analyzed.",
    },
}


# ---------------------------------------------------------
# fortism ioctl dispatch -- FFW 8.0.0 (Linux 4.19.13)
# ---------------------------------------------------------
FORTISM_DISPATCH = {
    "dispatch_foff":    "0x55d636",
    "dispatch_vma":     "0xffffffff8055d636",
    "mutex_vma":        "0xffffffff8165f9e0",
    "mutex_lock":       "0xffffffff8033d488",
    "mutex_unlock":     "0xffffffff8033d647",
    "object_lookup":    "0x8055df2b",
    "copy_from_user":   "0x8060269e",
    "copy_to_user":     "0x80602670",
    "kmalloc":          "0x8042748d",

    "ioctl_map": {
        "0x9002": {
            "foff":      "0x55d725 (cmp then fall-through to handler)",
            "handler":   "0x55d725-0x55d76c",
            "privilege": "GATED -- task-struct field check via 0x80310e91; compares to 0xffffffff81645640",
            "action":    "copy_from_user 4 bytes, call 0x80566fd6(dword)",
        },
        "0x9003": {
            "foff":      "0x55d7bd",
            "privilege": "ABSENT",
            "action":    "copy_from_user 0x24, object_lookup, read fields [+4/+0xc/+0x14/+0x1c], copy_to_user 0x24",
            "ref":       "FFW-F02",
        },
        "0x9004": {
            "foff":      "0x55d687",
            "privilege": "ABSENT",
            "action":    "copy_from_user 8, object_lookup, write dword to object[+0x44]",
            "ref":       "FFW-F01",
        },
        "0x9005": {
            "foff":      "0x55d7a0",
            "privilege": "ABSENT",
            "action":    "copy_to_user(user, 0xffffffff81888410, 4) -- unconditional global read",
            "ref":       "FFW-F03",
        },
        "0x9007": {
            "foff":      "0x55d82d",
            "privilege": "ABSENT",
            "action":    "copy_from_user 0x10, kmalloc(size+1), copy_from_user(heap, user_ptr, size), string oracle call",
            "ref":       "FFW-F04",
        },
        "0x9009": {
            "foff":      "0x55d6df",
            "privilege": "ABSENT",
            "action":    "copy_from_user 4, object_lookup, if object[+0x30]==3 return global at 0x81888410; else return object[+0x30]",
            "ref":       "FFW-F03 (same global as 0x9005)",
        },
    },
}


# ---------------------------------------------------------
# FFW-F01: ioctl 0x9004 unauth write to kernel object[+0x44]
#          Cross-product: FGT-F19
# ---------------------------------------------------------
FFW_F01_IOCTL_0x9004_UNAUTH_WRITE = {
    "id":       "FFW-F01",
    "product":  "Fortinet FortiFirewall OS 8.0.0 (fortism kernel module, Linux 4.19.13)",
    "severity": "HIGH -- unauth write to kernel object field; escalation path depends on field semantics",
    "class":    "Unprivileged write to kernel object field via fortism ioctl 0x9004",
    "cwe":      "CWE-284 (Improper Access Control)",
    "cross_product": "FGT-F19 (fortinet_fortigate_re.py) -- identical code, confirmed in FFW",

    "foff_handler": "0x55d687",

    "attack_flow": """\
; User-supplied: { uint32_t index; int32_t value; }  (8 bytes)
; Call: ioctl(any_fd, 0x9004, &user_struct)
;
; ioctl 0x9004 path (no privilege check):
copy_from_user(&kbuf, user_ptr, 8)        ; read {index, value}
mov edi, kbuf[0:4]                        ; index
cmp edi, 0x40
ja  -> EINVAL
call object_lookup(index)                  ; rax = object ptr (NULL if unregistered)
test rax, rax
je  -> EFAULT
movsxd rbx, kbuf[4:8]                     ; value (sign-extended to 64-bit)
mov dword ptr [rax + 0x44], ebx           ; WRITE value to object[+0x44]
return 0
""",

    "disasm_evidence": [
        "0xffffffff8055d6bb  movsxd rbx, dword ptr [rbp - 0x5c]",
        "0xffffffff8055d6bf  mov dword ptr [rax + 0x44], ebx  ; <-- WRITE",
        "0xffffffff8055d6c2  jmp 0xffffffff8055d775           ; return 0",
    ],

    "write_target": {
        "field_offset": "+0x44 in kernel object struct",
        "alignment":    "DWORD (4 bytes), NOT pointer-aligned for 64-bit",
        "value_range":  "Any 32-bit value, sign-extended to 64-bit for storage",
        "precondition": "Object table populated by Fortinet daemons at runtime (NULL in static binary)",
    },

    "impact": {
        "if_security_flag":  "Bypass a per-object security decision by flipping its flag",
        "if_size_field":     "Trigger out-of-bounds access in adjacent operations that use this field as a length",
        "if_enum":           "Force unexpected state transitions in the Fortinet daemon state machine",
        "static_limit":      "Cannot determine exact semantics without live system or rootfs decryption",
    },

    "combined_primitive": (
        "Combined with FFW-F02 (ioctl 0x9003 read), enables read-before-write: "
        "enumerate populated objects via 0x9003, read object[+0x44] region via repeated probes, "
        "then write a targeted value to steer daemon behavior."
    ),

    "remediation": "Add privilege check before ioctl 0x9004 handler (pattern: check task->cred->uid == 0 or CAP_SYS_ADMIN).",
}


# ---------------------------------------------------------
# FFW-F02: ioctl 0x9003 unauth kernel object multi-field read
#          Cross-product: FGT-F20
# ---------------------------------------------------------
FFW_F02_IOCTL_0x9003_UNAUTH_READ = {
    "id":       "FFW-F02",
    "product":  "Fortinet FortiFirewall OS 8.0.0 (fortism kernel module, Linux 4.19.13)",
    "severity": "MEDIUM -- 28 bytes of kernel object internals readable by any local process",
    "class":    "Unprivileged read of kernel object fields via fortism ioctl 0x9003",
    "cwe":      "CWE-200 (Information Exposure Through Returned Data)",
    "cross_product": "FGT-F20 (fortinet_fortigate_re.py) -- identical code, confirmed in FFW",

    "foff_handler": "0x55d7bd",

    "attack_flow": """\
; User-supplied: { uint32_t index; uint8_t pad[32]; }  (36 bytes)
; Call: ioctl(any_fd, 0x9003, &user_struct) -> fills pad with 28 bytes of object data
;
; ioctl 0x9003 path (no privilege check):
copy_from_user(&kbuf, user_ptr, 0x24)     ; read 36 bytes
mov edi, kbuf[0:4]                        ; index
cmp edi, 0x40
ja  -> EINVAL
call object_lookup(index)
test rax, rax
je  -> EFAULT
kbuf[8:16]  = object[4:12]               ; QWORD at +0x04
kbuf[16:24] = object[12:20]              ; QWORD at +0x0c
kbuf[24:32] = object[20:28]              ; QWORD at +0x14
kbuf[32:36] = object[28:32]              ; DWORD at +0x1c
copy_to_user(user_ptr, &kbuf, 0x24)      ; return 36 bytes (28 bytes of object data)
return 0
""",

    "disasm_evidence": [
        "0xffffffff8055d7ed  mov rdx, qword ptr [rax + 4]",
        "0xffffffff8055d7f5  mov rdx, qword ptr [rax + 0xc]",
        "0xffffffff8055d7fd  mov rdx, qword ptr [rax + 0x14]",
        "0xffffffff8055d805  mov eax, dword ptr [rax + 0x1c]",
        "0xffffffff8055d817  call 0xffffffff80602670  ; copy_to_user(user, kbuf, 0x24)",
    ],

    "leaked_fields": {
        "kbuf[8:16]  (object[+0x04])": "Unknown -- QWORD",
        "kbuf[16:24] (object[+0x0c])": "Unknown -- QWORD",
        "kbuf[24:32] (object[+0x14])": "Unknown -- QWORD",
        "kbuf[32:36] (object[+0x1c])": "Unknown -- DWORD",
    },

    "kaslr_potential": (
        "If any leaked QWORD is a kernel pointer (VMA in 0xffffffff8....... range), "
        "FFW-F02 enables KASLR bypass for any local process. "
        "Cannot confirm without live system (object table NULL in static binary)."
    ),

    "status": "CONFIRMED attack primitive -- 28 bytes of kernel object internal state disclosed, impact scales with runtime object content.",
}


# ---------------------------------------------------------
# FFW-F03: ioctl 0x9005/0x9009 unauth kernel global read
#          Cross-product: FGT-F21
# ---------------------------------------------------------
FFW_F03_IOCTL_UNAUTH_GLOBAL_READ = {
    "id":       "FFW-F03",
    "product":  "Fortinet FortiFirewall OS 8.0.0 (fortism kernel module, Linux 4.19.13)",
    "severity": "LOW-MEDIUM -- 4-byte global disclosed; KASLR bypass potential if pointer",
    "class":    "Unauth kernel global read via ioctl 0x9005 (and 0x9009 conditionally)",
    "cwe":      "CWE-200",
    "cross_product": "FGT-F21 (fortinet_fortigate_re.py) -- same pattern, different global VMA",

    "0x9005": {
        "foff_handler": "0x55d7a0",
        "global_vma":   "0xffffffff81888410",
        "disasm": [
            "0xffffffff8055d7a5  mov rsi, 0xffffffff81888410  ; hardcoded (vs FGT RIP-relative)",
            "0xffffffff8055d7af  call 0xffffffff80602670      ; copy_to_user(user, global, 4)",
        ],
        "transfer":         "4 bytes unconditional, no privilege check",
        "vs_fgt_800_note":  "FGT 8.0.0 global was at 0xffffffff8188a410 (0x2000 higher). Same region.",
    },

    "0x9009": {
        "foff_handler":  "0x55d6df",
        "dual_behavior": (
            "If object[+0x30] != 3: returns object[+0x30] itself (4 bytes). "
            "If object[+0x30] == 3: returns global at 0x81888410 (4 bytes). "
            "Both paths have no privilege check."
        ),
        "disasm": [
            "0xffffffff8055d713  movsxd rbx, dword ptr [rax + 0x30]",
            "0xffffffff8055d717  cmp ebx, 3",
            "0xffffffff8055d71a  jne 0x8055d775   ; return object[+0x30]",
            "0xffffffff8055d71c  movsxd rbx, dword ptr [rip + 0x132aced]  ; = 0x81888410",
        ],
    },

    "runtime_global_significance": (
        "0xffffffff81888410 is in the static data/BSS section. "
        "Zero in static vmlinux. Populated by Fortinet daemons at runtime. "
        "Content unknown without live system analysis. "
        "If it contains a kernel pointer at runtime, FFW-F03 enables KASLR bypass."
    ),
}


# ---------------------------------------------------------
# FFW-F04: ioctl 0x9007 integer overflow + controlled heap allocation
#          Cross-product: FGT-F22 / FGT-F16 (BEHAVIOR DIFFERS)
# ---------------------------------------------------------
FFW_F04_IOCTL_0x9007_OVERFLOW = {
    "id":       "FFW-F04",
    "product":  "Fortinet FortiFirewall OS 8.0.0 (fortism kernel module, Linux 4.19.13)",
    "severity": "MEDIUM-HIGH -- integer overflow + controlled heap allocation; DoS plausible; heap overflow POSSIBLE",
    "class":    "Unauth integer overflow + heap overflow via fortism ioctl 0x9007",
    "cross_product": "FGT-F22 (oracle) + FGT-F16 (overflow) -- SAME code path, DIFFERENT copy_from_user behavior",

    "foff_handler": "0x55d82d",

    "integer_overflow": {
        "input":      "size = second DWORD of 16-byte user input",
        "trigger":    "size = 0xffffffff",
        "overflow":   "`lea edi, [rax + 1]` with rax=0xffffffff -> edi=0 (32-bit wrap, same as FGT)",
        "kmalloc":    "kmalloc(0) -> valid SLUB ptr (~64 bytes), NOT NULL",
    },

    "copy_from_user_behavior_4_19": {
        "function":   "0xffffffff8060269e",
        "truncation": "`mov edx, r12d` before inner call -> count truncated to 32-bit (0xffffffff stays 0xffffffff)",
        "inner_func": "0xffffffff80cbc0f0 -- standard mov-based loop (NOT rep stosq)",
        "loop_type":  "Aligned 64-byte chunk copy via mov r8/r9/r10/r11; then byte-by-byte tail",
        "vs_fgt_800": (
            "FGT 8.0.0 (Linux 6.12.32): custom copy_from_user memset'd destination via rep stosq, "
            "causing immediate kernel crash when count=SIZE_MAX (FGT-F16). "
            "FFW 8.0.0 (Linux 4.19.13): standard mov loop. Does NOT crash via memset. "
            "FGT-F16 DoS as described DOES NOT APPLY to FFW."
        ),
    },

    "heap_overflow_path": {
        "scenario": (
            "If size=0xffffffff: kmalloc(0) allocates ~64 bytes. "
            "Then copy_from_user(heap, user_ptr, 0xffffffff) tries to copy 4GB from user space. "
            "If user has large contiguous mmap (e.g. 128MB), the loop copies into adjacent heap objects "
            "before hitting an unmapped page and returning EFAULT. "
            "This constitutes a controlled kernel heap overflow (attacker controls source data)."
        ),
        "attacker_control": "Full control over the source bytes (up to mapped user pages)",
        "impact": (
            "Heap corruption of kernel objects adjacent to the kmalloc(0) SLUB allocation. "
            "Exploitation complexity HIGH (requires heap grooming). "
            "Could lead to kernel privilege escalation on a live system."
        ),
    },

    "dos_path": {
        "scenario": (
            "Large user mmap + valid user_ptr: copy loop runs for hundreds of MB before fault. "
            "Each call ties up the fortism mutex (global lock at 0x8165f9e0). "
            "No parallelism: all fortism ioctl callers block. "
            "Repeated calls: sustained CPU consumption + blocking of all ioctl-dependent daemons."
        ),
        "severity": "DoS confirmed-plausible (differs from FGT-F16 guaranteed crash).",
    },

    "oracle_behavior": {
        "description": (
            "For valid sizes (< 0xffffffff): same boolean string query oracle as FGT-F22. "
            "Looks up user string in per-object hash table, returns 0 or 1 from object[+0x390]."
        ),
        "ref": "FGT-F22 oracle analysis in fortinet_fortigate_re.py for full detail.",
    },
}


# ---------------------------------------------------------
# FFW-F05: Shared fgt2.key private key -- cross-product
#          Cross-product: FGA-F01, FGT-F05
# ---------------------------------------------------------
FFW_F05_SHARED_FGT2_KEY = {
    "id":       "FFW-F05",
    "product":  "Fortinet FortiFirewall OS 8.0.0 (datafs.tar.gz -> etc/fgt2.key)",
    "severity": "CRITICAL -- cross-product shared RSA private key; same key in FGT ARM64, FGT x86-64, and FFW",
    "class":    "Hardcoded shared private key (CWE-321)",
    "cross_product": [
        "FGA-F01 (fortinet_fortigate_arm64_re.py) -- FGT ARM64 8.0.0 fgt2.key",
        "FGT-F05 (fortinet_fortigate_re.py) -- FGT x86-64 8.0.0 fgt2.key",
    ],

    "key_material": {
        "path":   "/etc/fgt2.key (inside datafs.tar.gz in P1 partition)",
        "format": "PKCS#1 RSA private key",
        "modulus_prefix": "A75C115F690B67C32834D43FE1BD50DB301CE34F...",
        "confirmed_identical": (
            "Modulus of FFW /etc/fgt2.key == FGT ARM64 8.0.0 fgt2.key modulus == FGT x86-64 8.0.0 fgt2.key modulus. "
            "All three share a single RSA private key pair."
        ),
    },

    "scope": (
        "Cross-product: FGT (ARM64 G-series), FGT (x86-64 VM), FFW (x86-64 VM) all ship the same key. "
        "Scope likely extends to all Fortinet products shipping fgt2.key, including FortiManager and FortiAnalyzer "
        "(not yet verified in FAZ/FMG 8.0.0 -- P1 rootfs encrypted in those images). "
        "Key use case: device authentication, Security Fabric PKI, VPN certificates."
    ),

    "source":       "datafs.tar.gz extracted from FFW p1.raw via debugfs; openssl rsa -noout -modulus",
    "verification": "CONFIRMED -- modulus compared byte-for-byte across three firmware images",

    "remediation": (
        "Generate unique RSA key pairs per device at first boot or manufacturing time. "
        "Rotate existing deployments. Revoke the shared fgt2.key from all PKI trust anchors."
    ),
}


# ---------------------------------------------------------
# FFW-F06: fortism LSM hook names in stripped vmlinux
#          (INFO: symbol table stripped but LSM hooks preserved as strings)
# ---------------------------------------------------------
FFW_F06_FORTISM_SYMBOLS_IN_VMLINUX = {
    "id":       "FFW-F06",
    "product":  "Fortinet FortiFirewall OS 8.0.0 -- vmlinux (decompressed from flatkc)",
    "severity": "INFO -- fortism LSM function names preserved in stripped kernel; accelerates reverse engineering",
    "class":    "Symbol disclosure in production kernel binary",

    "preserved_symbols": [
        "fortism_file_open", "fortism_path_link", "fortism_path_symlink",
        "fortism_kernel_load_data", "fortism_run_trigger", "fortism_learn_policy",
        "fortism_check_result", "fortism_check_acl", "fortism_add_acl_policy",
        "fortism_policy_to_1path_acl", "fortism_file_ioctl", "fortism_file_mprotect",
        "fortism_file_mmap", "__fortism_capable", "fortism_path_chroot",
    ],

    "mechanism": (
        "Linux LSM hooks are registered via security_add_hooks() with a string name. "
        "These strings survive stripping because they are referenced by the LSM framework. "
        "The vmlinux is marked 'stripped' by file(1) (ELF symbol table absent) but LSM hook "
        "registration strings remain in the .rodata section."
    ),

    "research_value": (
        "fortism_policy_to_1path_acl and fortism_add_acl_policy are policy enforcement functions. "
        "fortism_learn_policy suggests a dynamic learning mode (disabled at runtime?). "
        "Combined with ioctl analysis (FFW-F01 through FFW-F04), these names enable "
        "precise code navigation in the 4.19.13 vmlinux at known file offsets."
    ),

    "source":       "strings output from FFW vmlinux (decompressed 27MB ELF)",
    "verification": "CONFIRMED -- strings | grep fortism returns 15 named hooks",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "flatkc_vmlinux":  "ACCESSIBLE (extracted, 27MB ELF). fortism module confirmed at 0x55d636.",
    "rootfs_gz":       "BLOCKED -- custom encryption 0xa3ba56c6. NOT gzip, NOT FAZ/FMG format.",
    "datafs_tar_gz": {
        "status":      "ANALYZED",
        "key_finding": "FFW-F05 -- fgt2.key modulus identical to FGT ARM64 and x86-64 8.0.0",
        "files":       ["etc/fgt2.key", "etc/fgt_512.key", "etc/fgt2.crt", "etc/fortism_config.json"],
    },
    "fortism_ioctls":  "COMPLETE -- all 6 ioctls mapped (0x9002, 0x9003, 0x9004, 0x9005, 0x9007, 0x9009).",
    "cross_products":  "FGT-F19/F20/F21/F22 confirmed in FFW 8.0.0; FFW-F05 extends FGA-F01/FGT-F05 cross-product key scope.",
    "kernel_age":      "Linux 4.19.13 (2019 kernel, EOL LTS; Fortinet patched build 2026-04-20).",
    "unique_findings": ["FFW-F01", "FFW-F02", "FFW-F03", "FFW-F04", "FFW-F05", "FFW-F06"],
}
