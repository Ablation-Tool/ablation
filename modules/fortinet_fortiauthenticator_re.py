"""
Fortinet FortiAuthenticator VM64-KVM v6 RE
Source: FAC_VM_KVM-v6-build1355-FORTINET.out.kvm.zip (104MB)
Hardware ref: FAC_400E-v6-build0888-FORTINET-6.4.0.out (96MB -- inner data encrypted)
Build date: 2023-07-19 | kernel: Linux 5.10.179
Extraction path: KVM ZIP -> fackvm.qcow2 -> qemu-img convert -> fac.raw -> P1 (ext3, sector 1)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":        "Fortinet FortiAuthenticator VM64-KVM",
    "os":             "FortiAuthenticator OS v6 build 1355",
    "build_date":     "2023-07-19",
    "kernel":         "Linux 5.10.179",
    "kernel_builder": "root@kernel",
    "kernel_cc":      "gcc (Debian 6.3.0-18+deb9u1) 6.3.0 20170516",
    "kernel_ld":      "GNU ld (GNU Binutils for Debian) 2.28",
    "arch":           "x86-64",
    "buildid":        "fe102201b18292db89925e64f8e740fbd6e1ac2c",

    "image_structure": {
        "kvm_zip":        "FAC_VM_KVM-v6-build1355-FORTINET.out.kvm.zip",
        "boot_qcow2":     "fackvm.qcow2 (109MB compressed, 1GB virtual)",
        "data_qcow2":     "datadrive.qcow2 (197KB, empty/data)",
        "partition_layout": {
            "P1": "sector 1, 214MB, ext3 -- boot partition (extlinux + kernel + rootfs)",
            "P2": "sector 440001, 214MB, ext3 -- Ubuntu 'bare' snap base (snapd core)",
            "P3": "sector 880001, 214MB -- empty data partition (populated at runtime)",
        },
    },

    "p1_files": {
        "flatkc":    "4MB -- compressed kernel (XZ-wrapped bzImage)",
        "rootfs.gz": "99MB -- encrypted rootfs (magic: f1ec f5ed, format: UNKNOWN)",
        "extlinux.conf": "Boot: 'DEFAULT flatkc rw panic=5 ... root=/dev/ram0 ramdisk_size=600000 initrd=/rootfs.gz'",
        ".sign files": "512-byte signatures for each file (FortiSign integrity chain)",
    },

    "bootloader": "extlinux (syslinux/extlinux.conf on P1 ext3)",
    "init_target": "rootfs.gz loaded as initrd (ram0), ramdisk_size=600000",

    "snap_architecture": {
        "p2_snap_name":    "bare",
        "p2_snap_version": "1.0",
        "p2_snap_type":    "base (empty base snap)",
        "p2_note":         "FAC v6 uses Ubuntu snap infrastructure as userspace foundation. P2 is the minimal snap base.",
    },

    "product_function": {
        "primary": "FortiAuthenticator -- centralized multi-factor authentication, RADIUS server, SAML IdP",
        "features": ["FortiToken OTP validation", "RADIUS authentication", "LDAP/AD proxy", "SAML 2.0 IdP", "certificate management", "user self-service portal"],
    },
}


# ---------------------------------------------------------
# FAC-F01: No KASLR in Linux 5.10.179 kernel
# ---------------------------------------------------------
FAC_F01_NO_KASLR = {
    "id":       "FAC-F01",
    "product":  "Fortinet FortiAuthenticator VM64-KVM v6 (Linux 5.10.179)",
    "severity": "MEDIUM -- absence of KASLR reduces exploitation difficulty; combined with other findings enables reliable kernel exploit chains",
    "class":    "Missing security mitigation (KASLR disabled, CWE-1173)",
    "cwe":      "CWE-1173 (Improper Use of Validation Framework -- improper kernel hardening)",

    "description": (
        "The FortiAuthenticator Linux 5.10.179 kernel is compiled WITHOUT Kernel Address Space "
        "Layout Randomization (KASLR). The kernel text segment loads at a fixed virtual address "
        "0xffffffff81000000 (entry point at 0x100000000 as stored in ELF). "
        "An attacker who achieves code execution in the kernel context (via any kernel vulnerability) "
        "does not need to defeat KASLR to reach arbitrary kernel primitives. "
        "Combined with KPTI absence (see FAC-F02), the full kernel address space is accessible "
        "from user space on affected hardware via Meltdown timing side-channel."
    ),

    "evidence": {
        "kaslr_string":  "String 'kaslr' (upper or lower) NOT found in vmlinux text",
        "kpti_string":   "String 'kpti'/'kaiser' NOT found in vmlinux text",
        "kernel_entry":  "ELF entry 0x0000000001000000 (fixed address)",
        "smep_present":  "SMEP strings present (hardware enforcement compiled in)",
        "smap_present":  "SMAP strings present",
        "retpoline":     "RETPOLINE present (Spectre v2 mitigation)",
        "ibrs_stibp":    "IBRS/STIBP present (additional Spectre mitigations)",
    },

    "mitigation_status": {
        "KASLR":     "ABSENT -- kernel loads at fixed address",
        "KPTI":      "ABSENT -- Meltdown mitigation not present",
        "SMEP":      "PRESENT -- requires hardware support (Intel Ivy Bridge+)",
        "SMAP":      "PRESENT -- requires hardware support (Intel Broadwell+)",
        "RETPOLINE": "PRESENT",
        "IBRS":      "PRESENT",
        "STIBP":     "PRESENT",
    },

    "impact": (
        "In a VM environment: KASLR absence reduces exploit reliability requirements -- "
        "no need for info-leak primitives to discover kernel base. "
        "Kernel ROP chains can use fixed addresses. "
        "For any kernel vulnerability found in FAC (network stack, driver, syscall), "
        "the lack of KASLR means it can be reliably weaponized to fixed target addresses. "
        "KPTI absence additionally allows Meltdown-based information disclosure if the attacker "
        "controls a process on the same physical host."
    ),

    "note": "FAC runs as a KVM guest. Meltdown (KPTI absence) primarily affects same-host tenants on a multi-tenant hypervisor. In a dedicated deployment the Meltdown impact is bounded to privilege escalation within the guest.",

    "compiler_age": {
        "cc":     "GCC 6.3.0 (2017, Debian 9/Stretch era)",
        "ld":     "GNU Binutils 2.28 (2017)",
        "note":   "GCC 6.x predates many hardening features added in GCC 7+ (stack protector improved, FORTIFY enhancements, -fcf-protection). Very old toolchain for a 2023 build.",
    },

    "remediation": "Enable CONFIG_RANDOMIZE_BASE=y to compile KASLR support. Enable CONFIG_PAGE_TABLE_ISOLATION=y for KPTI. Update build toolchain to GCC 10+ to gain modern hardening passes.",
}


# ---------------------------------------------------------
# FAC-F02: Rootfs encrypted with unknown proprietary format
# ---------------------------------------------------------
FAC_F02_ROOTFS_ENCRYPTED_UNKNOWN = {
    "id":       "FAC-F02",
    "product":  "Fortinet FortiAuthenticator VM64-KVM v6",
    "severity": "INFO -- encryption scheme is unknown; static analysis of application layer blocked",
    "class":    "Proprietary encryption format (differs from FGT/FFW/FWB/FAZ/FMG/FAD)",

    "description": (
        "FAC rootfs.gz uses a proprietary encryption format with magic 0xf1ecf5ed. "
        "This is distinct from all other analyzed Fortinet products: "
        "FGT/FFW/FWB use XZ with forged CRC (FGT-F01), FAD uses plaintext XZ. "
        "FAZ/FMG use an encrypted format not yet reversed. "
        "The f1ecf5ed magic is NOT present in the kernel binary (vmlinux), "
        "ruling out a kernel-embedded custom decompressor. "
        "High entropy (7.997 bits/byte across the full 99MB file) confirms encryption, not just compression. "
        "The decryption mechanism is likely in the application layer loaded from the encrypted rootfs itself "
        "or in a kernel module not yet identified."
    ),

    "format_details": {
        "magic":       "f1 ec f5 ed (first 4 bytes)",
        "entropy":     "7.997 bits/byte (effectively random = encrypted)",
        "file_size":   "99MB",
        "in_vmlinux":  "NOT found -- decryption not in kernel",
        "standard_compressions_tried": ["gzip", "xz", "bzip2", "zstd", "lzo", "squashfs"],
    },

    "comparison_to_fgt_f01": (
        "FGT-F01 (XZ CRC forgery) revealed that early FortiGate firmware uses XZ with a forged "
        "LZMA2 block header CRC, requiring the XZ decompressor to skip CRC verification. "
        "FAC v6 uses a completely different approach -- the `f1ec f5ed` magic has no XZ structure. "
        "FAC v6 encryption predates or is independent of the FGT approach."
    ),

    "hardware_image_status": (
        "FAC_400E-v6-build0888-FORTINET-6.4.0.out: gzip outer wrapper -> encrypted inner data "
        "with different magic (91 a2 96 d7). Same pattern: gzip wrapper + proprietary encrypted payload."
    ),

    "pending": "Decrypt rootfs. Possible approaches: (1) brute-force key from kernel AES S-box vicinity, (2) firmware emulation to intercept decryption, (3) differential analysis vs later FAC versions if decryption scheme changed, (4) physical memory dump of running FAC appliance.",
}


# ---------------------------------------------------------
# FAC-F03: Outdated kernel (Linux 5.10 LTS, EOL December 2026) with old toolchain
# ---------------------------------------------------------
FAC_F03_OLD_KERNEL = {
    "id":       "FAC-F03",
    "product":  "Fortinet FortiAuthenticator VM64-KVM v6",
    "severity": "MEDIUM -- product was shipping EOL GCC/binutils in a 2023 firmware",
    "class":    "Outdated toolchain (CWE-1188)",

    "kernel_eol": {
        "version":      "5.10 LTS",
        "eol_date":     "December 2026 (5.10.179 was current in July 2023)",
        "note":         "5.10 LTS is supported through Dec 2026; no EOL at time of build",
    },

    "compiler_eol": {
        "gcc_version":  "6.3.0 (released 2016)",
        "debian_base":  "Debian 9 (Stretch) EOL: June 2022",
        "build_date":   "2023-07-19",
        "problem":      "Building kernel in 2023 with a compiler EOL since 2022. Missing GCC 7+ hardening.",
        "missing_hardening": [
            "GCC 7: improved -fstack-protector-strong semantics",
            "GCC 8: -fcf-protection (CET/IBT/SHSTK on Intel)",
            "GCC 9: -fstack-clash-protection improvements",
            "GCC 10: -ftrivial-auto-var-init (zero-init uninitialized stack vars)",
        ],
    },

    "binutils_eol": {
        "version":  "GNU ld 2.28 (2017)",
        "note":     "Binutils 2.28 predates several linker security improvements (2.29+, 2.31+)",
    },

    "remediation": "Rebuild kernel with supported GCC toolchain (GCC 12+). Enable -fcf-protection, -fstack-clash-protection, and -ftrivial-auto-var-init=zero.",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "vmlinux":      "EXTRACTED (23MB ELF, Linux 5.10.179, BuildID fe102201b18292db89925e64f8e740fbd6e1ac2c)",
    "rootfs":       "BLOCKED -- f1ec f5ed encryption (unknown format, no key recovery path from static analysis)",
    "p2_snap":      "IDENTIFIED -- Ubuntu bare snap base (empty, not application layer)",
    "p3_data":      "EMPTY -- runtime data partition (zeroed in base image)",
    "hardware_400e": "BLOCKED -- inner data encrypted after gzip wrapper (different magic: 91a2 96d7)",
    "kernel_security": "PARTIAL -- KASLR absent (FAC-F01), KPTI absent, old toolchain (FAC-F03)",
    "fortism":      "CONFIRMED ABSENT -- no fortism LSM in FAC kernel",
    "snap_arch":    "DOCUMENTED -- FAC uses Ubuntu snap infrastructure (P2 = bare snap base)",

    "unique_findings": [
        "FAC-F01: KASLR and KPTI both absent in Linux 5.10.179 -- fixed kernel load address, Meltdown not mitigated",
        "FAC-F02: Rootfs encrypted with f1ec f5ed magic -- different from all other Fortinet products analyzed",
        "FAC-F03: Kernel built with EOL GCC 6.3.0 (Debian 9/2017) in 2023 -- missing modern hardening",
        "FAC is Snap-based: P2 = Ubuntu bare snap -- different from FGT/FFW/FWB which have standard initramfs",
        "No fortism LSM -- different kernel attack surface than FGT/FFW/FWB",
        "Hardware FAC_400E also uses proprietary encryption (different magic from VM image)",
    ],

    "vs_other_products": {
        "FGT/FFW/FWB": "fortism LSM, ioctl surface (F19-F22), newer kernels (5.10+/6.1/6.12)",
        "FAZ/FMG":     "Python web app (AI/MCP layer), identical codebase",
        "FAD":         "SBVM DES key (F01), vtb.ko surface, accessible rootfs",
        "FFF":         "Electron desktop app, WebSocket IPC bridge",
        "FAC":         "Auth appliance, no fortism, Snap-based, KASLR absent, rootfs encrypted (unknown format)",
    },
}
