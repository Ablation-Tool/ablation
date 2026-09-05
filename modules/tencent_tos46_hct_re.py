"""
TencentOS 4.6 — hct.ko RE: Hygon CCP hardware passthrough via mdev + VFIO.

HCT = Hygon Crypto Through-passthrough. Presents Hygon CCP (Crypto
Co-Processor) as a mediated device (mdev) to VM guests. Two operating
modes: hct_iommu (VFIO IOMMU isolation) and hct_noiommu (direct physical
memory, no isolation).

Source:  drivers/crypto/ccp/hygon/hct.c
Author:  HYGON Corporation
Target:  6.6.119-51.3.tl4.x86_64 (TOS 4.6)
"""

METADATA = {
    "module": "hct",
    "size_bytes": 98438,
    "version": "0.6",
    "author": "HYGON Corporation",
    "license": "GPL",
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "tos_version": "4.6",
    "sig_key": "01:9D:01:14:84:D7",
    "sig_hashalgo": "sha256",
    "signer": "Tkernel signing key",
    "srcfile": "drivers/crypto/ccp/hygon/hct.c",
    "depends": ["mdev", "vfio"],
    "intree_claimed": True,
    "intree_actual": False,
    "char_device_pattern": "hct-ccp-%d",
    "pci_device_string": "HYGON CCH",
    "ccp_imports": ["ccp_queue_state", "ccps_ref", "ccps_ref_lock", "ccp_state"],
}

OPERATING_MODES = {
    "hct_noiommu": {
        "mdev_type": "hct_noiommu",
        "iommu": False,
        "isolation": "none",
        "description": (
            "Direct physical memory sharing. No IOMMU domain. Guest VM accesses "
            "Hygon CCP via shared physical pages. hct_noiommu_set_memory_wb changes "
            "cache attributes on host physical pages to write-back for CCP DMA. "
            "Security model: host trusts guest to not issue DMA outside intended region."
        ),
        "ioctl_handler": "hct_noiommu_ioctl",
        "ioctl_offset": 0x0a50,
    },
    "hct_share": {
        "mdev_type": "hct_share",
        "iommu": True,
        "isolation": "VFIO IOMMU domain",
        "description": (
            "IOMMU-isolated passthrough. hct_iommu_alloc creates an IOMMU domain "
            "and maps guest physical memory into it. CCP DMA is constrained to "
            "the mapped IOVA space. 48 IOMMU slots available per physical device."
        ),
        "ioctl_handler": "hct_ioctl",
        "ioctl_offset": 0x1430,
    },
}

KEY_FUNCTIONS = {
    "hct_pci_probe": {
        "offset": 0x1d50,
        "disassembly": [
            "call  <hct_pci_probe+0x5>",
            "jmp   hct_iommu_alloc          ; thin trampoline — probe = alloc",
        ],
        "note": "hct_pci_probe is a 5-byte trampoline directly into hct_iommu_alloc. No separate probe logic.",
    },
    "hct_iommu_alloc": {
        "offset": 0x1bc0,
        "description": "Allocates IOMMU domain + initializes device command queue for hct_share mode.",
        "slot_bitmap": {
            "mechanism": "64-bit bitmap, tzcnt finds first zero bit",
            "disassembly": [
                "movabs $0xffff000000000000,%rbx",
                "or     0x0(%rip),%rbx          ; OR with current bitmap",
                "cmp    $0xffffffffffffffff,%rbx ; all slots taken?",
                "je     <error_path>",
                "not    %rbx",
                "tzcnt  %rbx,%rbx               ; index of first free slot",
                "cmp    $0x30,%rbx              ; max 48 slots (0x30)",
                "je     <error_path>",
                "bts    %r13,0x0(%rip)          ; atomically claim slot",
            ],
            "max_slots": 0x30,
        },
        "iommu_domain": {
            "offset_in_device": 0x150,
            "alloc_call": "iommu_domain_alloc",
            "attach_call": "iommu_attach_device",
        },
        "embedded_constant": {
            "value": 0x3d6a9c5728633b9e,
            "disassembly": "movabs $0x3d6a9c5728633b9e,%rcx  ; stored into device struct",
            "purpose": "Unknown — likely protocol version tag or device capability flags",
        },
        "cmd_queue_init": "hct_dev_cmd_queue_init at 0xe90 — initializes CCP command queue state",
    },
    "hct_noiommu_ioctl": {
        "offset": 0x0a50,
        "description": "IOCTL handler for no-IOMMU mode. Two commands: set-WB and copy-to-user.",
        "ioctl_validation": {
            "magic_check": "movzbl %ah,%edx; cmp $0x43,%edx  ; magic byte = 0x43 ('C' for CCP)",
            "size_check": "shr $0x10,%edx; and $0x3fff; cmp $0x20  ; IOC_SIZE must = 32 bytes",
            "dir_check": "cmp $0x1,%sil  ; IOC_WRITE (0x1)",
            "error_return": "0xffffffffffffffea = -EINVAL on mismatch",
        },
        "commands": {
            "0x1": {
                "name": "HCT_NOIOMMU_SET_WB",
                "action": (
                    "Call hct_noiommu_set_memory_wb iteratively over page range. "
                    "Loop at 0xb2c: sub $1, test, jne — decrements page count, "
                    "advances base by 0x1000 per iteration."
                ),
            },
            "0x2": {
                "name": "HCT_NOIOMMU_COPY_OUT",
                "action": "copy_to_user: reads stored pointer from stack[+0x8], copies 32 bytes to user.",
            },
        },
    },
    "hct_ioctl": {
        "offset": 0x1430,
        "description": "IOCTL handler for IOMMU (hct_share) mode. Five command codes in 0x3b6x range.",
        "dispatch_table": {
            0x3b6b: "Command 0 — handled (path through 177b)",
            0x3b6c: "Command 1 — copy_from_user 32-byte struct, process via device+0x440",
            0x3b6d: "Command 2 — handled (path through 15cf)",
            0x3b6e: "Command 3 — handled (path through 1654)",
            0x3b6f: "Command 4 — ENOTTY (-25); not implemented",
        },
        "device_state_chain": [
            "mov  (%rdi),%r13         ; file->private_data = hct_file",
            "mov  0x88(%r13),%r12     ; hct_file+0x88 = hct_mdev_state",
            "mov  0x440(%r12),%rax    ; hct_mdev_state+0x440 = hct_ops vtable",
            "cmpq $0x0,0x28(%rax)     ; vtable[5] NULL check before dispatch",
        ],
        "command_1_depth": {
            "size_limit_check": "cmpl $0x1f,0x8(%rsp)  ; field at struct[0] must be ≤ 0x1f (31)",
            "queue_index": "cmp $0x8,%r13d  ; queue index must be ≤ 8",
            "slot_math": "shl $0x28,%rsi  ; slot * 0x28 = 40-byte stride into queue table",
        },
    },
    "is_invalid_reserved_pfn": {
        "offset": 0x05e0,
        "description": (
            "PFN validity check before DMA mapping. Multi-stage: "
            "(1) above-52-bit check, (2) PFN range bound, (3) mem_section walk."
        ),
        "stages": [
            {
                "stage": 1,
                "check": "bits 52+ of PFN",
                "disassembly": "shr $0x34,%rax; jne <invalid>  ; 0x34=52; any bit above 52 = invalid PFN",
            },
            {
                "stage": 2,
                "check": "PFN upper bound",
                "disassembly": "shr $0xf,%rax; cmp $0x2000000,%rax; jae <invalid>  ; PFN must be < 0x20000000 (512GB)",
            },
            {
                "stage": 3,
                "check": "mem_section radix tree walk",
                "disassembly": [
                    "shr $0x17,%rcx           ; L1 index = PFN >> 23",
                    "mov (%rdx,%rcx,8),%rdx   ; L1 pointer from mem_section table",
                    "test %rdx,%rdx; je <not_present>",
                    "movzbl %al,%eax",
                    "shl $0x4,%rax            ; L2 index = (PFN & 0xff) << 4",
                    "add %rax,%rdx",
                    "mov (%rdx),%rax",
                    "test $0x2,%al; je <not_present>   ; SECTION_MARKED_PRESENT",
                    "test $0x8,%al; jne <skip_bitmap>  ; SECTION_IS_ONLINE",
                    "mov 0x8(%rdx),%rdx",
                    "shr $0x9,%rax; and $0x3f,%eax",
                    "bt %rax,0x10(%rdx)       ; per-page valid bit",
                    "jae <not_present>",
                ],
            },
        ],
        "return_value": "1 = invalid PFN, 0 = valid",
        "race_window": (
            "Reads mem_section pointer twice (at L1 and L2 dereference) without holding "
            "mem_hotplug_lock. Memory section can be hot-removed between the two reads."
        ),
    },
    "hct_pin_memory": {
        "offset": 0x28d0,
        "description": "Pins guest user pages for DMA. Handles both small (kmalloc) and large (vmalloc) page arrays.",
        "page_count_calc": [
            "add  %rsi,%rdx          ; end = addr + size",
            "jb   <overflow>         ; unsigned overflow check",
            "shr  $0xc,%rax          ; start_pfn = addr >> 12",
            "sub  $0x1,%rdx",
            "shr  $0xc,%rdx          ; end_pfn = (addr+size-1) >> 12",
            "sub  %rax,%rbx",
            "add  %rdx,%rbx          ; count = end_pfn - start_pfn + 1",
            "cmp  $0x7fffffff,%rbx   ; max 2G pages",
            "ja   <error>",
        ],
        "alloc_strategy": {
            "small": "cmp $0x1000,%rdi; jbe <kmalloc>  ; ≤ 4KB page array → kmalloc(GFP_KERNEL=0xcc0)",
            "large": "vmalloc path for > 512 pages",
        },
        "pin_api": "pin_user_pages() — correct DMA-safe pinning API (avoids get_user_pages DMA lifetime bug)",
        "gfp_kernel": 0xcc0,
    },
    "hct_cdev_vma_fault": {
        "offset": 0x1100,
        "description": "VMA fault handler for char device mmap. Maps host IOMMU pages into guest VMA.",
        "address_translation": [
            "mov  (%rdi),%rax          ; vmf->vma",
            "mov  0x18(%rdi),%rbx      ; vmf->address",
            "mov  0x88(%rax),%rax      ; vma->vm_file->private_data",
            "mov  0xc8(%rax),%rax      ; hct_state->iommu_region base",
            "sub  0x30(%rax),%rbx      ; offset = fault_addr - region_base",
            "shr  $0xc,%rbx            ; page_index = offset >> 12",
            "cmp  max_pages,%rbx; jae <SIGBUS>  ; bounds check",
        ],
        "page_refcount": "lock incl 0x34(%rax)  ; atomic page->_refcount increment before mapping",
        "double_read": {
            "first_read": "mov 0x0(,%r12,8),%rax  ; read page array[index]",
            "second_read": "mov 0x0(,%r12,8),%rax  ; read page array[index] AGAIN",
            "issue": "No lock between reads. Page can be freed between first and second fetch.",
        },
        "return_values": {
            "VM_FAULT_NOPAGE": 0,
            "VM_FAULT_SIGBUS": 2,
        },
    },
    "hct_noiommu_set_memory_wb": {
        "offset": 0x07d0,
        "description": "Set pages to write-back cache attribute for DMA from no-IOMMU CCP.",
        "loop": "0xb2c: sub $1,%eax; test %eax,%eax; jne loop — per-page iteration, +0x1000 stride",
    },
    "hct_cmd_queue_intr_handler": {
        "offset": 0x0e40,
        "description": "Top-half IRQ handler for CCP command queue interrupts.",
    },
    "hct_cmd_queue_intr_task": {
        "offset": 0x0d00,
        "description": "Bottom-half tasklet — processes completed CCP command queue entries.",
    },
    "hct_mdev_probe": {
        "description": "mdev device creation — called when guest opens a new HCT mdev instance.",
    },
    "hct_mdev_remove": {
        "description": "mdev device teardown — unlinks mdev state, frees IOMMU domain or page array.",
    },
    "hct_mdev_get_available": {
        "description": "Reports available HCT mdev slots to the mdev framework (via sysfs).",
    },
    "hct_mdev_show_description": {
        "description": "Sysfs show handler — returns 'hct mdev type' description string.",
    },
    "hct_iommu_map": {
        "offset": 0x29a0,
        "description": "Maps guest physical pages into IOMMU domain for IOMMU-mode DMA.",
    },
    "hct_iommu_unmap_all": {
        "offset": 0x2530,
        "description": "Unmaps all IOMMU mappings for a slot on teardown or error path.",
    },
    "hct_share_mmap": {
        "description": "mmap handler for hct_share mode — installs hct_cdev_vma_fault as vm_ops.",
    },
}

PCI_DEVICE = {
    "vendor": "HYGON",
    "product_string": "HYGON CCH",
    "char_device_fmt": "hct-ccp-%d",
    "init_sequence": [
        "pci_enable_device",
        "pci_set_master",
        "pci_alloc_irq_vectors",
        "hct_iommu_alloc (via hct_pci_probe trampoline)",
        "hct_dev_cmd_queue_init",
    ],
    "cleanup_sequence": [
        "pci_free_irq_vectors",
        "hct_iommu_unmap_all",
        "iommu_domain_free",
        "pci_disable_device",
    ],
}

MDEV_INTERFACE = {
    "parent_registration": "mdev_register_parent — registers hct_mdev type with mdev framework",
    "driver_registration": "mdev_register_driver — registers hct_share and hct_noiommu types",
    "sysfs_types": ["hct_noiommu", "hct_share", "hct_mdev"],
    "ops": {
        "probe": "hct_mdev_probe",
        "remove": "hct_mdev_remove",
        "open_device": "hct_share_open / hct_noiommu_open",
        "close_device": "hct_share_close / hct_noiommu_close",
        "ioctl": "hct_share_ioctl → hct_ioctl / hct_noiommu_ioctl",
        "mmap": "hct_share_mmap (installs hct_cdev_vma_fault)",
        "get_available": "hct_mdev_get_available",
        "show_description": "hct_mdev_show_description",
    },
}

INTREE_PATTERN = {
    "claimed": "intree:Y",
    "actual": "out-of-tree",
    "evidence": [
        "Module author: HYGON Corporation — not a Linux kernel maintainer",
        "srcfile: drivers/crypto/ccp/hygon/hct.c — not in upstream kernel tree",
        "Uses TOS-specific kABI (vermagic 51.3.tl4) not compatible with vanilla 6.6",
        "Depends on mdev — upstream mdev API changed; this version is TOS-specific",
        "sig_key 01:9D:01:14:84:D7 — TOS production signing key, not upstream",
    ],
    "effect": "Avoids 'O' (out-of-tree) taint flag in dmesg. Same pattern as aegis.ko, netatop.ko.",
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "hct_noiommu mode: no IOMMU isolation — guest DMA reaches host physical memory",
        "detail": (
            "hct_noiommu mdev type allocates no IOMMU domain. "
            "Guest VM gets direct physical access to Hygon CCP pages. "
            "hct_noiommu_set_memory_wb changes host physical page cache attributes "
            "to write-back — a page cache attribute change callable from ioctl. "
            "is_invalid_reserved_pfn gates the operation, but the check has a race "
            "window (see F2). With no IOMMU, a compromised guest driver targeting "
            "the no-IOMMU path can issue DMA operations to arbitrary host PFNs "
            "that survive the PFN validity check."
        ),
        "mode": "hct_noiommu only",
        "mitigation": "Use hct_share (IOMMU mode) instead of hct_noiommu in multi-tenant deployments.",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "is_invalid_reserved_pfn: mem_section TOCTOU — hot-remove race on L1/L2 dereference",
        "detail": (
            "is_invalid_reserved_pfn walks the mem_section two-level radix tree with two "
            "sequential pointer dereferences (L1 at +0x20, L2 at +0x34 in the function). "
            "Memory hotplug (memory_hotremove) can remove a section between these two reads. "
            "After the L1 lookup succeeds (section present), if the section is removed before "
            "the L2 dereference, the L2 pointer is now a stale pointer to freed memory. "
            "The subsequent `test $0x2,%al` and `bt %rax,0x10(%rdx)` operate on freed/recycled memory. "
            "mem_hotplug_lock is not held during the walk. "
            "This is a known pattern in no-IOMMU VFIO contexts; Linux upstream fixed equivalent "
            "races in vfio_pin_pages() via mem_hotplug_lock. TOS hct.ko does not use it."
        ),
        "function": "is_invalid_reserved_pfn at 0x05e0",
        "race_window": "Between L1 dereference and L2 dereference",
        "impact": "Kernel use-after-free / NULL deref on memory section teardown during active DMA",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "hct_cdev_vma_fault: page array double-read without lock — use-after-free race",
        "detail": (
            "hct_cdev_vma_fault reads the page array at page_index twice: "
            "once to check non-NULL (lock incl follows) and once after the refcount bump. "
            "If a concurrent hct_mdev_remove races between these two reads and frees "
            "the page array, the second read returns a dangling pointer. "
            "The function then calls vm_insert_page() with a freed struct page*, "
            "mapping a freed physical page into the guest VMA. "
            "No spinlock or RCU read lock is held across the double-read. "
            "The page refcount increment (lock incl 0x34) occurs BETWEEN the two reads, "
            "so it does not protect against the page array itself being freed."
        ),
        "function": "hct_cdev_vma_fault at 0x1100",
        "first_read_offset": 0x46,
        "second_read_offset": 0x7b,
        "impact": "Use-after-free: freed struct page* mapped into guest VM",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "hct_iommu_alloc: 48-slot global bitmap — slot exhaustion denies all CCP VMs",
        "detail": (
            "hct_iommu_alloc uses a global 64-bit bitmap (bits 0–47 valid; 0x30=48 max). "
            "tzcnt finds the first free slot; if all 48 are taken, the function returns "
            "an error and the PCI probe fails for any new hct_share device. "
            "No per-tenant or per-VM slot quotas. A tenant that opens 48 hct_share "
            "mdev instances exhausts the bitmap globally — no other VM can obtain an "
            "hct_share CCP device until the 48 mdev instances are released. "
            "hct_noiommu has no equivalent slot limit, making it immune to this DoS "
            "but subject to F1."
        ),
        "max_slots": 48,
        "bitmap_op": "tzcnt to find first free slot; bts to claim atomically",
        "impact": "Denial of Hygon CCP hardware to all other VMs on the host",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "hct_ioctl: undocumented commands 0x3b6b–0x3b6e expose device state vtable",
        "detail": (
            "hct_ioctl handles five commands (0x3b6b–0x3b6f) with no public documentation "
            "or header definitions visible in the scratchpad. "
            "Command 0x3b6c accepts a 32-byte struct from user space, validates only "
            "one field (≤ 0x1f) and one queue index (≤ 8), then dispatches into "
            "device_state+0x440 (the ops vtable). "
            "If the 32-byte struct contains additional pointer-sized fields that are "
            "passed without validation into the ops vtable, an unprivileged VM "
            "with access to the hct char device can trigger confused-deputy operations. "
            "Command 0x3b6f returns ENOTTY — placeholder for future extension."
        ),
        "command_range": "0x3b6b–0x3b6f",
        "validated_fields": ["struct[0] ≤ 0x1f", "queue_index ≤ 8"],
        "unvalidated": "Remaining 28 bytes of 32-byte input struct",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "intree:Y false — hct.ko declares intree but is out-of-tree, suppresses 'O' taint",
        "detail": (
            "hct.ko (HYGON Corporation) declares intree:Y in module info. "
            "The module is clearly out-of-tree: authored by HYGON Corporation (not kernel maintainer), "
            "source path drivers/crypto/ccp/hygon/hct.c not in upstream kernel, "
            "vermagic 51.3.tl4 is TOS-specific. "
            "intree:Y suppresses the 'O' (out-of-tree) flag in /proc/sys/kernel/tainted. "
            "Security tooling and integrity systems that gate on taint state will not flag "
            "this module as out-of-tree. Third pattern observed: aegis.ko, netatop.ko, hct.ko."
        ),
        "taint_bit_suppressed": "TAINT_OOT_MODULE (bit 12)",
        "pattern_count": 3,
    },
    {
        "id": "F7",
        "severity": "MEDIUM",
        "title": "pci_user_write_config_{dword,byte} reachable from ioctl — guest PCI config space writes",
        "detail": (
            "hct.ko imports pci_user_write_config_dword and pci_user_write_config_byte. "
            "These functions write to PCI configuration space of the Hygon CCP device "
            "using the 'user' variants (which bypass normal driver-only restrictions). "
            "If a code path from hct_ioctl reaches these without verifying caller privilege "
            "beyond basic ioctl access, a guest VM with the hct char device can issue "
            "arbitrary PCI config writes: reconfiguring BARs, disabling the device, or "
            "setting the PCI Command register to enable bus mastering for DMA attacks."
        ),
        "imports": ["pci_user_write_config_dword", "pci_user_write_config_byte"],
        "risk": "Guest-controlled PCI config space write to physical Hygon CCP hardware",
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "hct_pin_memory: pin_user_pages() used correctly — DMA pinning API is right",
        "detail": (
            "hct_pin_memory uses pin_user_pages() (not get_user_pages()). "
            "pin_user_pages() is the correct API for DMA-backed memory pinning: "
            "it marks pages with FOLL_PIN, preventing transparent page migration "
            "during active DMA (which would cause DMA to stale physical addresses). "
            "GFP_KERNEL=0xcc0 consistent with TOS 4.6 kmalloc path. "
            "Page array allocation strategy: kmalloc for ≤ 4KB arrays (≤ 512 pages = ≤ 2GB range), "
            "vmalloc for larger arrays. Overflow check: cmp $0x7fffffff (max 2G page entries)."
        ),
        "correct_api": "pin_user_pages() vs deprecated get_user_pages() for DMA",
        "gfp_kernel": "0xcc0 (consistent with TOS 4.6)",
    },
]

if __name__ == '__main__':
    print(f"hct.ko — Hygon CCP passthrough ({METADATA['size_bytes']}B, TOS {METADATA['tos_version']})")
    print(f"Modes: {', '.join(OPERATING_MODES.keys())}")
    print(f"Max IOMMU slots: {KEY_FUNCTIONS['hct_iommu_alloc']['slot_bitmap']['max_slots']}")
    print()
    print("Key functions:")
    for name, info in KEY_FUNCTIONS.items():
        offset = info.get('offset')
        if offset:
            print(f"  0x{offset:04x}  {name}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
