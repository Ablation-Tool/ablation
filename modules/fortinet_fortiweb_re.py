"""
Fortinet FortiWeb FWB_KVM 8.0.6 RE
Source: FWB_KVM-v8.0.6.M-build0116-FORTINET.out.kvm.zip -> boot.qcow2 (296MB)
Build date: 2026-07-09 | kernel: Linux 6.1.62 (root@ad5e2f99860f)
Extraction path: QCOW2 -> boot.raw (32GB sparse) -> P1 (sector 12194) -> ext2 mount -> vmlinuz
Accessible layers: P1 boot partition (ext2), vmlinuz kernel (XZ bzImage, decompressed 46MB ELF)
Encrypted layers: rootfs.gz (custom magic 0x84fe53de), krootfs.gz (custom magic 0xb63606e9)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":        "Fortinet FortiWeb VM64-KVM",
    "os":             "FortiWeb OS 8.0.6.M",
    "build":          "0116",
    "build_date":     "2026-07-09",
    "kernel":         "Linux 6.1.62",
    "kernel_builder": "root@ad5e2f99860f",
    "arch":           "x86-64",

    "image_structure": {
        "kvm_zip":      "FWB_KVM-v8.0.6.M-build0116-FORTINET.out.kvm.zip (581MB) -> image-kvm-64/",
        "boot_qcow2":   "boot.qcow2 (296MB compressed, 32GB virtual)",
        "boot2g_qcow2": "boot_2g.qcow2 (296MB -- backup/primary swap image)",
        "log_qcow2":    "log.qcow2 (7.3MB -- separate log disk)",
        "partitions": {
            "P1": "type 0x83 Linux ext2, sector 12194, 781MB -- boot partition",
            "P2": "type 0x83 Linux ext2, 781MB -- dual-image redundancy",
            "P3": "type 0x83 Linux ext2, 195MB -- config partition",
            "P4": "type 0x83 Linux ext2, 30720MB -- data/log partition (sparse)",
        },
        "p1_files": ["vmlinuz (7.9MB bzImage)", "rootfs.gz (137MB encrypted)", "krootfs.gz (3MB encrypted)", "datafs.tar.gz (18MB)"],
        "bootline":  "DEFAULT vmlinuz ramdisk_size=870400 crashkernel=192M softlockup_panic=0 hung_task_panic=0 initrd=/rootfs.gz tpm_tis.interrupts=0 pcie_aspm=off",
    },

    "kernel_details": {
        "format":              "bzImage (boot protocol 0x020f)",
        "payload_compression": "XZ (fd 37 7a 58 5a magic)",
        "vmlinux_decompressed": "46MB ELF",
        "vmlinux_entry":       "0xffffffff80200000 (standard kernel text base)",
        "kernel_version_note": (
            "Linux 6.1.62 -- intermediate age. "
            "FGT/FAZ/FMG 8.0.0 = Linux 6.12.32 (latest). "
            "FWB 8.0.6 = Linux 6.1.62 (LTS series). "
            "FFW 8.0.0 = Linux 4.19.13 (oldest). "
            "FortiWeb uses a different kernel branch from FortiGate/FortiFirewall."
        ),
    },

    "encryption_status": {
        "rootfs_gz":   "Encrypted. Magic 0x84fe53de572ead53. FWB-specific format, NOT gzip/FAZ/FFW.",
        "krootfs_gz":  "Encrypted. Magic 0xb63606e97dfd76b9. Different format from rootfs.gz.",
        "vmlinuz":     "Accessible (XZ bzImage). vmlinux (46MB ELF) extracted.",
        "datafs_tar_gz": "Standard gzip. Not yet analyzed.",
    },
}


# ---------------------------------------------------------
# fortism ioctl dispatch -- FortiWeb 8.0.6 (Linux 6.1.62)
# ---------------------------------------------------------
FORTISM_DISPATCH = {
    "dispatch_foff":    "0x75e905",
    "dispatch_vma":     "0xffffffff8075e905",

    "dispatch_differences_from_fgt_800": {
        "mutex_pattern": (
            "NOT a simple mutex_lock/unlock pair. Uses a reference-counted gate: "
            "'mov rdi, 0x823ab1d8; call 0x80f38010' returns a value (stored in rbp). "
            "Checks and decrements [rip + 0x1c4c8a7] (semaphore count). "
            "Unlocks via 'call 0x80f37ef0' before handlers. "
            "Pattern is closer to a semaphore down/up or RCU read-lock."
        ),
        "object_table_base": "0xffffffff82caf4c0 (vs FGT 0x8188a440 -- different region)",
        "object_table_slots": "max index 0x20 (32 slots) vs FGT's 0x40 (64 slots)",
        "copy_fn":          "0xffffffff802050e0 (same signature; mov-based loop, NOT rep stosq)",
        "object_lookup_expr": "[rax * 8 - 0x7d350b40] (rax = index, -0x7d350b40 = table base)",
        "0x9005_global":    "0xffffffff823ab360 (vs FGT 0x8188a410 / FFW 0x81888410)",
        "frame_pointer":    "Omitted in dispatch; uses push rbp/r14/rbx + sub rsp,0x50 prologue",
    },

    "ioctl_map": {
        "0x9002": {
            "foff":      "0x75ea4b",
            "privilege": (
                "GATED -- different mechanism from FGT/FFW. "
                "Reads gs:[0x2b0c0] (per-CPU field), deref [+0x608], "
                "then checks [rax + rcx*16 + 0x68] == 0xffffffff823c8ba8. "
                "If pointer does not match, returns EPERM. "
                "Gated by process-specific kernel pointer match (not UID/capability check)."
            ),
            "if_gated_passes": "copy_from_user 4 bytes, call 0x80766a00(dword)",
        },
        "0x9003": {
            "foff":      "0x75eac1",
            "privilege": "ABSENT",
            "action":    "copy_from_user 0x24, object_lookup (max 0x20), read [+4/+0xc/+0x14/+0x1c], copy_to_user 0x24",
            "ref":       "FWB-F02",
        },
        "0x9004": {
            "foff":      "0x75e989",
            "privilege": "ABSENT",
            "action":    "copy_from_user 8, object_lookup (max 0x20), write dword to object[+0x44]",
            "ref":       "FWB-F01",
        },
        "0x9005": {
            "foff":      "0x75ea10",
            "privilege": "ABSENT",
            "action":    "copy_to_user(r14, 0x823ab360, 4) -- unconditional global read",
            "ref":       "FWB-F03",
        },
        "0x9007": {
            "foff":      "0x75ebcd",
            "privilege": "ABSENT",
            "partial_mitigation": "js check on signed size prevents overflow copy (see FWB-F04)",
            "ref":       "FWB-F04",
        },
        "0x9009": {
            "foff":      "0x75eb63",
            "privilege": "ABSENT",
            "action":    "object_lookup, if object[+0x30]==3 return global at 0x823ab360; else return object[+0x30]",
            "ref":       "FWB-F03",
        },
    },
}


# ---------------------------------------------------------
# FWB-F01: ioctl 0x9004 unauth write to kernel object[+0x44]
#          Cross-product: FGT-F19, FFW-F01
# ---------------------------------------------------------
FWB_F01_IOCTL_0x9004_UNAUTH_WRITE = {
    "id":       "FWB-F01",
    "product":  "Fortinet FortiWeb OS 8.0.6 (fortism kernel module, Linux 6.1.62)",
    "severity": "HIGH -- unauth write to kernel object field; no privilege gate",
    "class":    "Unprivileged write to kernel object field via fortism ioctl 0x9004",
    "cwe":      "CWE-284 (Improper Access Control)",
    "cross_product": "FGT-F19 / FFW-F01 -- same pattern; FortiWeb-specific table address",

    "foff_handler": "0x75e989",

    "attack_flow": """\
; User-supplied: { uint32_t index; int32_t value; }  (8 bytes)
; Call: ioctl(any_fd, 0x9004, &user_struct)
;
; ioctl 0x9004 path (no privilege check):
; user ptr range check (0x7fffffffeffc limit -- FWB user-space check)
copy_from_user(rsp, r14, 8)                 ; read {index, value}
mov eax, dword ptr [rsp]                    ; index (NOT sign-extended yet)
cmp rax, 0x20                               ; BOUNDS CHECK: 0x20 (32), NOT 0x40 as in FGT!
ja  -> EINVAL
mov rax, qword ptr [rax*8 - 0x7d350b40]    ; object_lookup: table at 0x82caf4c0
test rax, rax
je  -> EFAULT
mov ebp, dword ptr [rsp + 4]               ; value (second 4 bytes)
mov dword ptr [rax + 0x44], ebp            ; WRITE to object[+0x44]
jmp -> return 0
""",

    "disasm_evidence": [
        "0xffffffff8075e9c5  cmp rax, 0x20               ; bounds check",
        "0xffffffff8075e9cf  mov rax, [rax*8 - 0x7d350b40]  ; object_lookup",
        "0xffffffff8075e9e0  mov ebp, dword ptr [rsp + 4] ; value",
        "0xffffffff8075e9e4  mov dword ptr [rax + 0x44], ebp  ; WRITE",
        "0xffffffff8075e9e7  jmp 0xffffffff8075ec89       ; return 0",
    ],

    "vs_fgt_ffw": {
        "same_field": "object[+0x44] write -- identical offset",
        "diff_bounds": "FWB: index <= 0x20 (32 slots) vs FGT/FFW: index <= 0x40 (64 slots)",
        "diff_table":  "FWB: 0x82caf4c0 vs FGT: 0x8188a440 vs FFW: ~0x8188a440",
    },

    "status": "CONFIRMED attack primitive -- unauth write to kernel object field at +0x44.",
}


# ---------------------------------------------------------
# FWB-F02: ioctl 0x9003 unauth kernel object multi-field read
#          Cross-product: FGT-F20, FFW-F02
# ---------------------------------------------------------
FWB_F02_IOCTL_0x9003_UNAUTH_READ = {
    "id":       "FWB-F02",
    "product":  "Fortinet FortiWeb OS 8.0.6 (fortism kernel module, Linux 6.1.62)",
    "severity": "MEDIUM -- 28 bytes of kernel object internals readable by any local process",
    "class":    "Unprivileged read of kernel object fields via fortism ioctl 0x9003",
    "cwe":      "CWE-200 (Information Exposure Through Returned Data)",
    "cross_product": "FGT-F20 / FFW-F02 -- identical field reads; FortiWeb-specific table",

    "foff_handler": "0x75eac1",

    "attack_flow": """\
; User-supplied: { uint32_t index; uint8_t pad[32]; }  (36 bytes)
; Call: ioctl(any_fd, 0x9003, &user_struct) -> fills pad with 28 bytes of object data
;
; ioctl 0x9003 path (no privilege check):
copy_from_user(rsp, r14, 0x24)             ; read 36 bytes
mov eax, dword ptr [rsp]                   ; index
cmp rax, 0x20                              ; bounds: 32 slots in FWB
ja  -> EINVAL
mov rax, [rax*8 - 0x7d350b40]             ; object_lookup
test rax, rax
je  -> EFAULT
stack[8:16]  = object[4:12]               ; QWORD at +0x04
stack[16:24] = object[12:20]              ; QWORD at +0x0c
stack[24:32] = object[20:28]              ; QWORD at +0x14
stack[32:36] = object[28:32]              ; DWORD at +0x1c
copy_to_user(r14, rsp, 0x24)             ; return 36 bytes
return 0
""",

    "disasm_evidence": [
        "0xffffffff8075eaf6  mov eax, dword ptr [rsp]",
        "0xffffffff8075eb00  cmp rax, 0x20",
        "0xffffffff8075eb0a  mov rax, qword ptr [rax*8 - 0x7d350b40]",
        "0xffffffff8075eb1b  mov ecx, dword ptr [rax + 0x1c]  ; DWORD",
        "0xffffffff8075eb22  mov rcx, qword ptr [rax + 0x14]  ; QWORD",
        "0xffffffff8075eb2b  mov rcx, qword ptr [rax + 4]     ; QWORD",
        "0xffffffff8075eb2f  mov rax, qword ptr [rax + 0xc]   ; QWORD",
    ],

    "kaslr_potential": (
        "Same as FGT-F20: if any leaked QWORD is a kernel pointer, enables KASLR bypass. "
        "Cannot confirm without live system (objects NULL in static binary)."
    ),

    "status": "CONFIRMED attack primitive -- 28 bytes of kernel object internal state disclosed.",
}


# ---------------------------------------------------------
# FWB-F03: ioctl 0x9005/0x9009 unauth kernel global read
#          Cross-product: FGT-F21, FFW-F03
# ---------------------------------------------------------
FWB_F03_IOCTL_UNAUTH_GLOBAL_READ = {
    "id":       "FWB-F03",
    "product":  "Fortinet FortiWeb OS 8.0.6 (fortism kernel module, Linux 6.1.62)",
    "severity": "LOW-MEDIUM -- 4-byte global read; KASLR bypass potential if pointer",
    "class":    "Unauth kernel global read via ioctl 0x9005 (and 0x9009 conditionally)",
    "cwe":      "CWE-200",
    "cross_product": "FGT-F21 / FFW-F03 -- same pattern; FWB-specific global VMA",

    "0x9005": {
        "foff_handler": "0x75ea10",
        "global_vma":   "0xffffffff823ab360",
        "disasm": [
            "0xffffffff8075ea32  mov rsi, 0xffffffff823ab360  ; kernel global src",
            "0xffffffff8075ea39  call 0x802050e0              ; copy_to_user(user, global, 4)",
        ],
        "privilege": "ABSENT",
        "vs_fgt": "FGT global: 0x8188a410 / FFW: 0x81888410 / FWB: 0x823ab360 -- all different",
    },

    "0x9009": {
        "foff_handler": "0x75eb63",
        "behavior":     "Same dual-behavior as FGT/FFW: object[+0x30]==3 returns global; else returns object[+0x30]",
        "global_vma":   "0xffffffff823ab360 (same as 0x9005)",
    },

    "runtime_global_significance": (
        "0x823ab360 is in FortiWeb's BSS/data section. "
        "Zero in static vmlinux. Populated by Fortinet daemons at runtime. "
        "If contains a kernel pointer: KASLR bypass for any local process."
    ),
}


# ---------------------------------------------------------
# FWB-F04: ioctl 0x9007 integer overflow -- PARTIAL MITIGATION
#          Cross-product: FGT-F22/FGT-F16 (BEHAVIOR DIFFERS SIGNIFICANTLY)
# ---------------------------------------------------------
FWB_F04_IOCTL_0x9007_OVERFLOW = {
    "id":       "FWB-F04",
    "product":  "Fortinet FortiWeb OS 8.0.6 (fortism kernel module, Linux 6.1.62)",
    "severity": "LOW -- integer overflow EXISTS but MITIGATED by signed size check; heap overflow NOT possible",
    "class":    "Integer overflow in fortism ioctl 0x9007 -- partially mitigated",
    "cross_product": "FGT-F16 / FGT-F22 / FFW-F04 -- SAME overflow; DIFFERENT mitigation",

    "foff_handler": "0x75ebcd",

    "overflow_path": {
        "trigger":        "size = 0xffffffff (second dword of 16-byte input)",
        "overflow":       "`inc eax` with eax=0xffffffff -> eax=0 (32-bit wrap)",
        "kmalloc":        "kmalloc(0) -- valid SLUB allocation (~64 bytes)",
        "mitigation":     "`movsxd r14, dword ptr [rsp+4]` re-reads size: r14 = 0xffffffff sign-extended = -1",
        "signed_check":   "`test r14, r14; js 0x8075ed79` -- SF=1 (r14 is negative), branch TAKEN",
        "result":         "Returns to error path WITHOUT calling copy_from_user. No heap overflow. kmalloc(0) allocated but freed.",
    },

    "vs_fgt_ffw": {
        "fgt_800": "No js check. copy_from_user(heap, user, 0xffffffff) -> rep stosq crash (FGT-F16 DoS CONFIRMED).",
        "ffw_800": "No js check. Standard mov-loop copy -> heap overflow POSSIBLE if user has mapped pages.",
        "fwb_806": "js check PRESENT. copy_from_user with 0xffffffff size BLOCKED. DoS NOT possible via this path.",
    },

    "partial_fix_analysis": (
        "FWB 8.0.6 appears to have independently mitigated the integer overflow in 0x9007 "
        "by adding a signed size check after the sign-extension. FGT and FFW lack this check. "
        "The kmalloc(0) allocation still occurs (minor resource leak) but the dangerous copy is blocked. "
        "This suggests Fortinet was aware of an issue in this path for FortiWeb specifically, "
        "or the fix was introduced in the newer kernel base (6.1.62 vs 6.12.32 for FGT / 4.19.13 for FFW). "
        "The mitigation is NOT present in FGT-F16 or FFW-F04."
    ),

    "oracle_still_active": {
        "description": "For valid sizes (>= 0, < 0x80000000): same boolean string query oracle as FGT-F22.",
        "ref":         "FGT-F22 in fortinet_fortigate_re.py for oracle semantics detail.",
    },

    "copy_from_user_behavior": {
        "function": "0xffffffff802050e0",
        "type":     "Standard aligned 64-byte chunk mov-loop (same as FFW/FGT); NOT rep stosq",
        "note":     "FWB-F04 DoS would NOT apply even without the js mitigation (no rep stosq)",
    },
}


# ---------------------------------------------------------
# Cross-product vulnerability map
# ---------------------------------------------------------
CROSS_PRODUCT_MAP = {
    "FGT-F19 (FGT 8.0.0)": "FWB-F01 -- same 0x9004 write to object[+0x44], different table (0x82caf4c0 vs 0x8188a440), smaller table (32 vs 64 slots)",
    "FGT-F20 (FGT 8.0.0)": "FWB-F02 -- same 0x9003 field read pattern; same field offsets (+4/+0xc/+0x14/+0x1c)",
    "FGT-F21 (FGT 8.0.0)": "FWB-F03 -- same 0x9005 global read; different global VMA (0x823ab360)",
    "FGT-F22 (FGT 8.0.0)": "FWB-F04 -- same integer overflow in 0x9007; but FWB has js MITIGATION",
    "FGT-F16 (FGT 8.0.0)": "NOT applicable in FWB -- js check + no rep stosq",
    "FFW-F01 (FFW 8.0.0)": "FWB-F01 -- equivalent",
    "FFW-F02 (FFW 8.0.0)": "FWB-F02 -- equivalent",
    "FFW-F03 (FFW 8.0.0)": "FWB-F03 -- equivalent",
    "FFW-F04 (FFW 8.0.0)": "FWB-F04 -- same overflow, different mitigation status",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "vmlinuz":        "ACCESSIBLE (46MB ELF vmlinux extracted). fortism confirmed at 0x75e905.",
    "rootfs_gz":      "BLOCKED -- custom encryption 0x84fe53de. FWB-specific.",
    "krootfs_gz":     "BLOCKED -- custom encryption 0xb63606e9. Different from rootfs.gz.",
    "datafs_tar_gz":  "NOT YET ANALYZED (standard gzip, 18MB).",
    "fortism_ioctls": "COMPLETE -- all 6 ioctls mapped (0x9002, 0x9003, 0x9004, 0x9005, 0x9007, 0x9009).",
    "cross_products":  "FGT-F19/F20/F21 confirmed; FGT-F16/F22 confirmed but partially mitigated.",
    "unique_findings": [
        "FWB uses SMALLER object table (32 slots vs FGT/FFW's 64 slots)",
        "FWB has DIFFERENT object table address (0x82caf4c0)",
        "FWB has js MITIGATION for 0x9007 integer overflow -- FGT/FFW lack this",
        "FWB uses Linux 6.1.62 (different from FGT's 6.12.32 and FFW's 4.19.13)",
        "Dual-image boot (P1 and P2 both 781MB)",
    ],
}
