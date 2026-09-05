"""
TencentOS 4.6 — Hygon hardware trust chain reverse engineering.

Three Hygon-authored modules that form the hardware root-of-trust infrastructure:

1. tcm_hygon.ko (18214B)  — TCM2 driver (China's TPM equivalent, GM/T 0012)
2. tpm_hygon.ko (15774B)  — TPM2 driver (international standard)
3. hct.ko      (97327B)   — Hygon Crypto Technology PCI device driver (VFIO mdev)

Author for TCM/TPM: mayuanchen@hygon.cn (Hygon)
Author for HCT: HYGON Corporation
All three signed with TOS Tkernel signing key (01:9D:01:14:84:D7, sha256)

These modules give TOS 4.6 a dual trust architecture:
- TCM path: Chinese national standard (GM/T 0012) using SM algorithms
- TPM path: International standard (TPM2.0) using SHA-256/RSA
Both run on the same Hygon PSP hardware, selectable by module load.
"""

METADATA = {
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "sig_key": "01:9D:01:14:84:D7 (sha256, Tkernel signing key)",
    "modules": {
        "tcm_hygon": {
            "size_bytes": 18214,
            "author": "mayuanchen@hygon.cn",
            "description": "TCM2 device driver for Hygon PSP",
            "acpi_hid": "HYGT0201",
            "standard": "GM/T 0012 — Chinese national trusted cryptography module standard",
        },
        "tpm_hygon": {
            "size_bytes": 15774,
            "author": "mayuanchen@hygon.cn",
            "description": "TPM2 device driver for Hygon PSP",
            "acpi_hid": "HYGT0101",
            "standard": "TCG TPM 2.0 — international trusted platform module standard",
        },
        "hct": {
            "size_bytes": 97327,
            "author": "HYGON Corporation",
            "version": "0.6",
            "description": "Hygon Crypto Technology hardware accelerator with VFIO mdev support",
            "depends": "mdev, vfio",
            "pci_device": "Hygon CCH (Crypto Co-processor Hardware) PCI device",
        },
    },
}

TCM_VS_TPM = {
    "comparison": {
        "TCM": {
            "standard": "GM/T 0012 (Chinese national standard)",
            "algorithms": "SM2 (asymmetric), SM3 (hash), SM4 (symmetric)",
            "pcr_count": "24 (same as TPM2)",
            "acpi_id": "HYGT0201 (Hygon TCM2)",
            "psp_cmd": "0x100 (Hygon PSP TCM command code)",
            "endianness": "Big-endian header (bswap in tcm_c_send/recv)",
        },
        "TPM": {
            "standard": "TCG TPM 2.0 (international standard)",
            "algorithms": "SHA-256, RSA-2048, ECC",
            "acpi_id": "HYGT0101 (Hygon TPM2)",
            "psp_cmd": "psp_do_cmd via 'sev do cmd' path (AMD SEV-derived interface)",
            "interop": "Interoperable with IMA, GRUB2 measured boot, TLS attestation",
        },
    },
    "dual_trust_note": (
        "TOS 4.6 ships BOTH tcm_hygon.ko AND tpm_hygon.ko. "
        "Loading tcm_hygon provides a /dev/tcm0 device and integrates with "
        "DIM (dim_core.ko with DIM_HASH_SUPPORT_SM3=y) for SM3-based PCR measurements. "
        "Loading tpm_hygon provides /dev/tpm0 and integrates with IMA, GRUB, and "
        "international attestation infrastructure. "
        "These are mutually exclusive device drivers for the same Hygon PSP hardware — "
        "loading both would create two competing char devices for one PSP."
    ),
}

TCM_FUNCTIONS = {
    "tcm_c_send": {
        "addr": ".text+0x00a0",
        "size": 154,
        "max_cmd_size": 0xff8,
        "flow": [
            "0x00c1: cmp rdx, 0xff8 — bounds check: max command 4088 bytes",
            "0x00cc: [rbx] = 0x100000 — write PSP buffer type/magic field",
            "0x00d6: bswap eax — convert length to big-endian (TCM wire format)",
            "0x00d8: [rbx+4] = eax — write big-endian length at PSP buffer+4",
            "0x00db: memcpy(rbx+8, payload, size) — copy TCM command to PSP buffer",
            "0x00e3: edi = 0x100 — PSP command code for TCM",
            "0x00ed: psp_do_cmd(PSP_CMD=0x100, psp_buf, &result) — send to PSP",
            "0x00f4: if psp_do_cmd fails: printk + return -5 (EIO)",
        ],
        "bounds_check": "size > 0xff8 returns -7 (EFAULT) — no overflow",
        "psp_cmd_code": 0x100,
    },
    "tcm_c_recv": {
        "addr": ".text+0x0040",
        "size": 72,
        "flow": [
            "0x004f: rsi = [rax+0x88] — load PSP response buffer from chip struct",
            "0x0056: eax = [rsi+0xa] — read TCM response size from header offset 10",
            "0x005b: bswap ebx — convert big-endian response size to host order",
            "0x005f: cmp rcx, rdx — if caller_buf_size < response_size: return -7",
            "0x0074: memcpy(dst, psp_buf+8, response_size) — copy response",
        ],
        "chip_struct_psp_buf_offset": "0x88 — PSP buffer pointer in tcm_chip struct",
        "header_size_offset": "0x0a — TCM response header size field (big-endian)",
    },
    "hygon_tcm2_acpi_add": {
        "addr": ".text+0x0150",
        "size": 480,
        "purpose": "ACPI probe: allocates tcm_chip, maps PSP buffer, registers /dev/tcm0",
    },
}

HCT_ARCHITECTURE = {
    "description": (
        "HCT (Hygon Crypto Technology) is a PCI crypto accelerator driver. "
        "It exposes Hygon's CCH hardware to userspace via multiple interfaces. "
        "The mdev (mediated device) path allows VMs to directly use Hygon crypto hardware "
        "via VFIO pass-through — the hardware context is partitioned per mdev instance."
    ),
    "interfaces": {
        "hct_fops": "Standard char device (open/read/write/ioctl/mmap)",
        "hct_noiommu_fops": "NOIOMMU mode — direct hardware access without IOMMU containment",
        "hct_share_fops": "Shared memory interface (hct_share_mmap, hct_share_ioctl)",
        "hct_vd_fops": "Virtual device interface",
        "hct_mdev_ops": "VFIO mediated device for VM crypto pass-through",
    },
    "memory_model": {
        "hct_iommu_alloc": "Allocate IOMMU domain for DMA containment",
        "hct_iommu_map": "Map guest physical pages into IOMMU domain",
        "hct_iommu_unmap_all": "Unmap all IOMMU mappings (called on close)",
        "hct_pin_memory": "Pin host pages for DMA (GPA → HPA translation)",
        "vaddr_get_pfn": "Translate virtual address to page frame number",
        "hct_mmap_fault": "Page fault handler for mmap'd hardware buffer regions",
    },
    "command_queue": {
        "hct_dev_cmd_queue_init": "Initialize hardware command queue",
        "hct_cmd_queue_intr_handler": "Interrupt handler for completed async crypto ops",
        "hct_cmd_queue_intr_task": "Tasklet for interrupt bottom half processing",
    },
    "vm_support": {
        "hct_mdev_probe": "New mdev instance created — allocate per-VM crypto context",
        "hct_mdev_remove": "mdev instance removed — cleanup VM crypto context",
        "hct_mdev_get_available": "Report number of available mdev instances",
        "hct_mdev_show_description": "sysfs description: 'hct mdev type'",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "Dual TCM/TPM boot — attestation reports diverge depending on loaded module",
        "detail": (
            "TOS 4.6 includes both tcm_hygon.ko (GM/T 0012, SM algorithms) and tpm_hygon.ko (TPM2). "
            "System boot with TCM produces SM3-based PCR measurements (not SHA-256). "
            "Remote attestation tools expecting SHA-256 PCR values (IMA, GRUB, TPM2-tools) "
            "will see mismatched or empty PCRs if TCM is loaded instead of TPM. "
            "An attacker who can influence module load order (via modprobe.d, initramfs) "
            "can switch from TPM to TCM (or vice versa), invalidating existing "
            "remote attestation policies without triggering security alerts. "
            "No enforcement mechanism prevents loading both or either."
        ),
        "acpi_ids": {"TCM": "HYGT0201", "TPM": "HYGT0101"},
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "hct_noiommu mode — direct hardware DMA without IOMMU containment",
        "detail": (
            "hct.ko exposes hct_noiommu_fops providing /dev/hct in NOIOMMU mode. "
            "In NOIOMMU mode, DMA operations are not constrained by IOMMU address translation. "
            "Hardware can DMA to arbitrary physical memory ranges. "
            "If a malicious or compromised process opens /dev/hct in NOIOMMU mode "
            "and submits crafted crypto commands with manipulated DMA source/destination, "
            "the hardware can read from or write to arbitrary physical addresses. "
            "NOIOMMU mode bypasses the entire IOMMU containment model."
        ),
        "interface": "hct_noiommu_fops, hct_noiommu_ioctl",
        "iommu_bypass": True,
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "hct_pin_memory + vaddr_get_pfn — GPA→HPA translation available to ioctl callers",
        "detail": (
            "hct_pin_memory and vaddr_get_pfn perform guest physical address to host "
            "physical frame translation. When called from userspace via ioctl, "
            "these expose the physical address of any pinned page. "
            "Combined with NOIOMMU DMA, this creates a path: "
            "1) Pin any virtual address via hct_pin_memory. "
            "2) Get the physical address via vaddr_get_pfn. "
            "3) Issue a DMA command targeting that physical address. "
            "This bypasses virtual memory isolation between processes."
        ),
        "functions": ["hct_pin_memory", "vaddr_get_pfn"],
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "TCM PSP command code 0x100 — fixed command code for all TCM operations",
        "detail": (
            "tcm_c_send uses PSP command code 0x100 for all TCM operations. "
            "The TCM command type is encoded in the TCM header (at PSP_buffer+0 = 0x100000). "
            "The fixed PSP command code 0x100 means all TCM operations share one PSP entry point. "
            "PSP firmware validation of the 0x100000 magic field is not verifiable "
            "from the Linux driver side. If PSP firmware treats this field as a type selector "
            "without bounds checking, a crafted magic value might redirect to unintended PSP operations."
        ),
        "psp_cmd_code": "0x100 (fixed for all TCM ops)",
        "magic_at_buf_0": "0x100000",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "TCM command max size 0xff8 (4088B) — under-enforced on the recv side",
        "detail": (
            "tcm_c_send enforces max command size 0xff8 bytes via `cmp rdx, 0xff8; ja error`. "
            "tcm_c_recv bounds checks caller buffer against response size (`cmp rcx, rdx`). "
            "The receive check is: if caller_buf_size < response_size, return -7 without copy. "
            "This is correct behavior. However: there is no check that response_size <= 0xff8. "
            "If Hygon PSP firmware returns a response larger than 0xff8, "
            "tcm_c_recv would attempt to copy it without the send-side bound, "
            "potentially overflowing the PSP buffer if it's sized to 0xff8."
        ),
        "send_max": 4088,
        "recv_max": "Unbounded — only caller buffer checked",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "hct_mdev VFIO pass-through — VM can use Hygon crypto hardware directly",
        "detail": (
            "hct_mdev_ops registers a VFIO mediated device allowing VMs to use Hygon HCT hardware. "
            "A VM with hct mdev attached gets direct access to a Hygon crypto hardware partition. "
            "If the hardware partition isolation in Hygon firmware is incomplete, "
            "a compromised VM could interfere with another VM's crypto operations "
            "or with the host's crypto operations. "
            "Hygon firmware partitioning is not publicly documented."
        ),
        "mdev_type": "hct mdev type",
        "vfio_path": "hct_mdev_probe → hct_mdev_get_available",
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "TCM chip struct PSP buffer at offset 0x88 — tcm_chip layout diverges from upstream tpm_chip",
        "detail": (
            "tcm_c_recv reads the PSP buffer pointer from [rax+0x88] in the tcm_chip struct. "
            "The upstream Linux tpm_chip struct does not have a PSP buffer pointer at 0x88 — "
            "this is a Hygon TCM-specific field. "
            "The TCM wire format uses big-endian length at header offset 0x0a "
            "(matching the TCM2 spec), with bswap conversions in both send and recv. "
            "This is structurally correct for the GM/T 0012 TCM2 command format."
        ),
        "chip_struct_psp_buf_offset": 0x88,
        "header_length_offset": 0x0a,
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "Hygon ACPI IDs HYGT0101/HYGT0201 — detectable via ACPI table enumeration",
        "detail": (
            "acpi*:HYGT0201:* (TCM2) and acpi*:HYGT0101:* (TPM2) are the Hygon ACPI Hardware IDs. "
            "These are unique to Hygon hardware and absent on any non-Hygon x86 platform. "
            "A system with these ACPI IDs is definitively a Hygon-based server. "
            "The IDs are visible in ACPI tables without root: "
            "`cat /sys/bus/acpi/devices/HYGT0201*/status` or `acpidump | grep HYGT`."
        ),
        "tcm_acpi_id": "HYGT0201",
        "tpm_acpi_id": "HYGT0101",
    },
]

if __name__ == '__main__':
    print("Hygon trust chain modules (TOS 4.6)")
    print(f"Modules: {', '.join(METADATA['modules'].keys())}")
    print()
    print("TCM vs TPM:")
    for name, details in TCM_VS_TPM["comparison"].items():
        print(f"  {name}: {details['standard']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
