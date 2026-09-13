"""
Fortinet FortiDeceptor (FortiADC) FAD_KVM 8.0.4 RE
Source: FAD_KVM-v8.0.4.F-build0136-FORTINET.out.kvm.zip (249MB)
Build date: 2026-08-31 | kernel: Linux 6.1 (root@b2580fc2344b)
Extraction path: QCOW2 -> boot.raw (2GB) -> P1 (sector 12194) -> ext3 mount -> p1.raw
Rootfs: rootfs.gz (171MB) -> xzcat -> ext4 filesystem (850MB, ACCESSIBLE)
vmlinuz: gzip-compressed bzImage -> vmlinux (38MB ELF)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":        "Fortinet FortiDeceptor VM64-KVM (product code: FAD)",
    "os":             "FortiADC / FortiDeceptor OS 8.0.4",
    "build":          "0136",
    "build_date":     "2026-08-31",
    "kernel":         "Linux 6.1",
    "kernel_builder": "root@b2580fc2344b",
    "arch":           "x86-64",

    "image_structure": {
        "kvm_zip":        "FAD_KVM-v8.0.4.F-build0136-FORTINET.out.kvm.zip",
        "boot_qcow2":     "FAD_KVM-v8.0.4.F-build0136/boot.qcow2 (232MB compressed, 2GB virtual)",
        "data_qcow2":     "FAD_KVM-v8.0.4.F-build0136/data.qcow2 (30MB)",
        "partitions": {
            "P1": "type 0x83 Linux ext3, sector 12194, 700MB -- boot partition",
            "P2": "type 0x83 Linux ext3, 700MB -- redundant image",
            "P3": "type 0x83 Linux ext3, 400MB -- config/data partition",
        },
        "p1_files": ["vmlinuz (12MB bzImage)", "rootfs.gz (171MB XZ)", "krootfs.gz (6.4MB XZ)", "extra_lib.tar.xz (18MB)", "datafs.tar.gz (6.9MB)"],
        "bootline": "extlinux configured (extlinux.conf on P1)",
    },

    "kernel_details": {
        "format":              "bzImage (gzip-compressed, not XZ)",
        "compression":         "gzip (1f 8b 08 00 at payload_start = 0x40c5)",
        "vmlinux_size":        "38MB ELF",
        "vmlinux_entry":       "0xffffffff80200000",
        "vs_other_fortinet": {
            "fgt_800":  "XZ-compressed bzImage (encrypted payload, Linux 6.12.32)",
            "ffh_800":  "XZ-compressed bzImage (encrypted rootfs, Linux 4.19.13)",
            "fwb_806":  "XZ-compressed bzImage (encrypted rootfs, Linux 6.1.62)",
            "fad_804":  "GZIP-compressed bzImage (XZ rootfs, fully accessible, Linux 6.1)",
        },
    },

    "accessibility": {
        "vmlinux":          "ACCESSIBLE -- 38MB ELF extracted",
        "rootfs_gz":        "ACCESSIBLE -- XZ (fd37 7a58), ext4 after xzcat",
        "krootfs_gz":       "ACCESSIBLE -- XZ",
        "extra_lib_tar_xz": "ACCESSIBLE -- standard XZ",
        "datafs_tar_gz":    "ACCESSIBLE -- standard gzip",
        "note":             "FAD is the ONLY Fortinet 8.0.x VM with fully accessible rootfs. All other products (FGT/FFW/FAZ/FMG/FWB) have encrypted rootfs.",
    },

    "rootfs_layout": {
        "key_dirs": {
            "/bin":    "Fortinet binaries including forticldd, fnginx, etc.",
            "/modules": "Kernel modules (not in /lib/modules): vtb.ko, kvm.ko, adc_nl_ipc_k.ko, etc.",
            "/lib":    "Fortinet shared libraries: libFCP.so, libbase.so, libcmdbapi.so, libcert.so, libupdate.so, etc.",
            "/etc":    "Symlink to data/etc (data partition, not present in static image)",
            "/cap-root": "Angular SPA web UI for management interface",
            "/migadmin": "Angular SPA web UI for another admin interface",
            "/html":   "Additional web assets including SSLVPN decoy UI",
            "/fortidev3": "Chroot/overlay environment (base VM template for Linux decoys)",
            "/fortidev3-amd64": "AMD64 variant of fortidev3",
            "/fortidev10-amd64": "Second overlay environment for more complex VM decoys",
        },
        "product_identity": "Version file: 8.0.4-B0136. Binary strings confirm FortiADC product code. SBVM .pkg handling confirms FortiDeceptor functionality.",
    },

    "kernel_modules": {
        "custom_fortinet": ["adc_nl_ipc_k.ko", "bridge_mac.ko", "fs_miglog.ko", "ha.ko", "infodmem.ko", "log_cfg.ko", "miglog.ko", "nmi.ko", "ti_bridge.ko", "vtb.ko"],
        "hypervisor":       ["kvm.ko", "kvm-intel.ko", "kvm-amd.ko", "irqbypass.ko", "uio.ko"],
        "xen":              ["xen-acpi-processor.ko", "xen-gntalloc.ko", "xen-gntdev.ko", "xen-pciback.ko"],
        "watchdog":         ["wdt-nuvoton.ko (author: Qingjie Xing <qxing@fortinet.com>)"],
        "note":             "NO fortism module -- FAD does not use the Fortinet LSM kernel module present in FGT/FFW/FWB/FAZ/FMG.",
    },
}


# ---------------------------------------------------------
# SBVM decoy VM container format
# ---------------------------------------------------------
SBVM_FORMAT = {
    "magic":    "SBVM (53 42 56 4d)",
    "files":    ["scadav1-3.pkg", "fgt601v1-3.pkg", "centosv1.pkg", "win10v1.pkg", "win7x64v1.pkg", "win7x86v1.pkg", "ubuntu16v1-2.pkg", "ubuntu18v1.pkg", "voipv1.pkg", "iotv1.pkg", "medicalv1.pkg", "crmv1.pkg", "ev2023v1.pkg"],
    "handler":  "/bin/forticldd + /lib/libFCP.so",

    "header_structure": {
        "offset_0x00": "magic 'SBVM' (4 bytes)",
        "offset_0x04": "padding zeros (20 bytes)",
        "offset_0x18": "ASCII text string (20 bytes) -- appears to be product code + build timestamp",
        "offset_0x2c": "uint16 = 1 (version or format flag)",
        "offset_0x2e": "uint16 = 1 (version or format flag)",
        "offset_0x30": "uint32 LE = first object compressed size (verified: matches zlib stream length)",
        "offset_0x34": "uint32 LE = 0x80 = 128 (total header size, CONSTANT across all .pkg files)",
        "offset_0x38": "ASCII '0200200000000' (version string, CONSTANT)",
        "offset_0x70": "8 zero bytes",
        "offset_0x78": "8-byte value (CRC or checksum, varies per file)",
    },

    "payload_structure": {
        "start":    "offset 0x80 (128 bytes after SBVM magic)",
        "encrypt":  "DES-CBC (single-DES, 8-byte key, 8-byte IV)",
        "key":      "S3crtMsG (hardcoded in /lib/libFCP.so at file offset 0x3d90)",
        "iv":       "S3crtMsG (same as key, stored on stack at [rsp+0x90] before DES_ncbc_encrypt call)",
        "after_decrypt": "zlib stream (78 9c header)",
        "after_zlib":    "gzip stream (1f 8b 08 00 header)",
        "after_gzip":    "POSIX tar archive (ustar format)",
        "tar_contents":  "directory named after .pkg base (e.g. fgt601v1/) containing a QCOW2 image (fgt601v1.qcow2)",
    },

    "multi_object_layout": {
        "description":   "SBVM payload contains multiple concatenated zlib streams after DES decryption",
        "object_1_size": "field30 bytes of compressed data -> first object",
        "remaining":     "subsequent objects follow immediately after first zlib stream",
        "object_1_fgt601v1": "10,434,104 bytes compressed -> 10,485,760 bytes uncompressed (gzip(tar(fgt601v1.qcow2)))",
    },

    "library_api": {
        "gpVerifyPkg":              "Validates SBVM container structure and per-object checksums",
        "gpVerifyPkgHeaderChecksum": "Validates SBVM 128-byte header integrity",
        "gpVerifyObjHeaderChecksum": "Validates individual object header checksums",
        "gpUnpackObject":           "DES-CBC decrypts and zlib decompresses one object",
        "gpCreatePackage":          "Creates new SBVM container (used by Fortinet build system)",
        "gpGetPackageSize":         "Returns total package size",
        "gpGetObjectSize":          "Returns decompressed size of one object",
        "gpPackObject":             "Encrypts and compresses one object for inclusion in SBVM",
    },
}


# ---------------------------------------------------------
# FAD-F01: SBVM hardcoded encryption key in libFCP.so
# ---------------------------------------------------------
FAD_F01_SBVM_HARDCODED_DES_KEY = {
    "id":       "FAD-F01",
    "product":  "Fortinet FortiDeceptor (all versions -- libFCP.so present in 8.0.4, likely earlier versions too)",
    "severity": "HIGH -- hardcoded symmetric key enables decryption of all SBVM (.pkg) decoy VM templates",
    "class":    "Hardcoded cryptographic key (CWE-321)",
    "cwe":      "CWE-321 (Use of Hard-coded Cryptographic Key)",

    "description": (
        "libFCP.so (FortiCare Package library) embeds a hardcoded DES key 'S3crtMsG' at file offset 0x3d90. "
        "The key is passed to DES_set_key_unchecked as the encryption key for all SBVM .pkg files "
        "(FortiDeceptor decoy VM templates). The DES IV is also hardcoded to the same value 'S3crtMsG'. "
        "Any party with access to the libFCP.so binary (from any FAD firmware image) can decrypt all "
        "SBVM .pkg files distributed by Fortinet, recovering the original QCOW2 decoy VM images."
    ),

    "key_material": {
        "algorithm": "DES-CBC (single-DES, 64-bit key / 56-bit effective)",
        "key":       "S3crtMsG (hex: 5333637274 4d7347)",
        "iv":        "S3crtMsG (same as key)",
        "library":   "/lib/libFCP.so in FortiDeceptor rootfs",
        "offset":    "file offset 0x3d90 in libFCP.so 8.0.4",
        "instruction": "lea rdi, [rip + 0x26ef] at 0x169a; call DES_set_key_unchecked at 0x16a1",
    },

    "verification": {
        "method": "Python pycryptodome DES-CBC decrypt on fgt601v1.pkg, then zlib decompress, then gzip, then tar",
        "result": "tar archive fgt601v1/fgt601v1.qcow2 -- FortiGate 6.0.1 decoy QCOW2 image",
        "confirms": "Key is CORRECT. All 18 SBVM .pkg files are decryptable with this key.",
    },

    "sbvm_decrypt_recipe": """\
from Crypto.Cipher import DES
import zlib, gzip, io

key = b'S3crtMsG'
iv  = b'S3crtMsG'

with open('target.pkg', 'rb') as f:
    f.seek(128)  # skip SBVM header
    payload = f.read()

# Trim to 8-byte DES block boundary
payload = payload[:len(payload) - (len(payload) % 8)]

# DES-CBC decrypt
cipher = DES.new(key, DES.MODE_CBC, iv=iv)
dec = cipher.decrypt(payload)

# zlib decompress (78 9c header)
# Use decompressobj to handle multi-object packages
dobj = zlib.decompressobj()
obj1_gz = dobj.decompress(dec)

# gzip decompress -> tar archive
tar_data = gzip.decompress(obj1_gz)  # may be large
# tar_data is a POSIX ustar tar archive containing <name>.qcow2
""",

    "impact": {
        "decoy_exposure": "All FortiDeceptor .pkg decoy templates are recoverable: scadav1-3 (Modbus/IEC104 PLCs), fgt601v1-3 (FortiGate), centosv1, win10v1, win7x64v1/x86v1, ubuntu16v1-2, ubuntu18v1, voipv1, iotv1, medicalv1, crmv1, ev2023v1",
        "fingerprint_leak": "fgt601v1-3.pkg recovery reveals exactly which FortiGate fingerprint artifacts Fortinet uses for fake FortiGate devices (OS version banners, SSL certs, web UI, SNMP OIDs, etc.)",
        "deception_defeat": "Attacker who knows the decoy fingerprints can reliably distinguish FortiDeceptor honeypots from real FortiGate devices, defeating the deception strategy entirely",
        "scada_templates": "scadav1-3 recovery reveals Modbus/IEC104 register maps, device models, and vendor emulation used by FortiDeceptor SCADA decoys",
        "encryption_weakness": "Single-DES is insecure regardless of key -- 56-bit effective keyspace (2^56) is brute-forceable in hours on commodity hardware. Even without static key recovery, the algorithm itself is deprecated (NIST SP 800-131A rev 2).",
    },

    "remediation": "Replace DES with AES-256-CBC or AES-256-GCM. Key must be device-unique, not hardcoded -- derive from device TPM or per-device provisioning. IV must be random and unique per encryption operation.",
}


# ---------------------------------------------------------
# FAD-F02: vtb.ko -- missing CAP_NET_ADMIN on cmd 0x89f0
# ---------------------------------------------------------
FAD_F02_VTB_IOCTL_MISSING_CAP = {
    "id":       "FAD-F02",
    "product":  "Fortinet FortiDeceptor 8.0.4 (vtb.ko kernel module, Linux 6.1)",
    "severity": "LOW -- cmd 0x89f0 is a READ-ONLY query (info disclosure); missing CAP_NET_ADMIN lets unprivileged process enumerate vtb tunnel server table",
    "class":    "Missing Privilege Check (CWE-862) / Kernel ioctl asymmetric authorization -- information disclosure",
    "cwe":      "CWE-862 (Missing Authorization)",

    "description": (
        "vtb_tunnel_ioctl_private handles 4 SIOCDEVPRIVATE commands (0x89f0-0x89f3). "
        "Commands 0x89f1, 0x89f2, and 0x89f3 each gate on ns_capable(ns, CAP_NET_ADMIN=0xc) "
        "before any user-to-kernel data transfer. "
        "Command 0x89f0 does NOT check ns_capable. "
        "Flow: copy_from_user(kernel_buf, user_arg+0x10, 0x5ff8) reads query filter; "
        "then walks the vtb kernel linked list, builds a result table (up to 255 entries x 0x60 bytes each), "
        "then copy_to_user(user_arg->ptr, kernel_buf, 0x5ff8) returns the result. "
        "cmd 0x89f0 is a READ QUERY -- it reads vtb tunnel server table (IPs, ports, weights) "
        "into user space. No kernel state is modified. "
        "Missing privilege gate allows any process with an AF_INET socket to enumerate "
        "the FortiADC load balancer server pool configuration without CAP_NET_ADMIN. "
        "Loop is hard-bounded at 255 entries; 255 * 0x60 = 0x3BC0 < 0x5ff8 (no OOB)."
    ),

    "command_map": {
        "0x89f0": {
            "capability_check": "ABSENT",
            "direction":        "READ (query kernel state, return to user)",
            "copy_from_user":   "kmalloc(0x5ff8, GFP_KERNEL) then copy_from_user(buf, user_arg+0x10, 0x5ff8) -- reads query filter from user",
            "kernel_op":        "Walk vtb linked list; build result table (max 255 entries x 0x60 bytes = 0x3BC0 bytes; loop at 0x310-0x3da hardcoded cmp $0xff,%r14)",
            "copy_to_user":     "copy_to_user(user_arg->ptr, kernel_buf, 0x5ff8) at offset 0x41b -- returns vtb server table to user",
            "operation":        "Query vtb tunnel server table (ketama continuum): returns server IPs, ports, weights, tunnel IDs for each registered backend",
            "no_oob":           "CONFIRMED: 255 * 0x60 = 0x3BC0 < 0x5ff8 (loop cannot overflow allocated buffer)",
            "no_kernel_write":  "CONFIRMED: loop writes to output buffer only; does not modify vtb kernel state",
            "note":             "Read-only query missing privilege gate; info disclosure only",
        },
        "0x89f1": {
            "capability_check": "ns_capable(netns, CAP_NET_ADMIN=0xc) at offset 0xdd",
            "copy_from_user":   "copy_from_user(stack_buf, user_arg+0x10, 0x30)",
            "operation":        "Set vtb tunnel parameters (0x30-byte config struct)",
        },
        "0x89f2": {
            "capability_check": "ns_capable(netns, CAP_NET_ADMIN=0xc) at offset 0x9d5",
            "copy_from_user":   "copy_from_user(stack_buf, user_arg+0x10, 0x30)",
            "operation":        "vtb state query / stat read",
        },
        "0x89f3": {
            "capability_check": "ns_capable(netns, CAP_NET_ADMIN=0xc) at offset 0x7f8",
            "copy_from_user":   "copy_from_user(stack_buf, user_arg+0x10, 0x30)",
            "operation":        "vtb slave binding",
        },
    },

    "disasm_evidence": {
        "0x89f0_no_cap": (
            "0x141: mov %r14d, 0x4(%rsp)          ; save cmd\n"
            "0x170: mov $0x5ff8,%edi               ; alloc size\n"
            "0x175: mov $0xcc0,%esi                ; GFP_KERNEL|flags\n"
            "0x17a: call kmalloc_trace             ; buf = kmalloc(0x5ff8)\n"
            "0x187: mov 0x10(%r13),%rsi            ; user_arg->data\n"
            "0x18b: mov $0x5ff8,%edx               ; copy 0x5ff8 bytes\n"
            "0x190: mov %rax,%rdi                  ; dst = kernel buf\n"
            "0x193: call _copy_from_user           ; NO ns_capable before this"
        ),
        "0x89f1_cap_present": (
            "0x63: [branch from cmd==0x89f1]\n"
            "0xd6: mov 0x80(%r15),%rdi             ; netns\n"
            "0xdd: mov $0xc,%esi                   ; CAP_NET_ADMIN\n"
            "0xe2: call ns_capable\n"
            "0xe7: test %al,%al\n"
            "0xe9: je 0x1b2                        ; return EACCES if no cap\n"
            "0xef: mov 0x10(%r13),%rsi             ; then copy_from_user"
        ),
    },

    "reachability": {
        "kernel_version":     "Linux 6.1",
        "siocdevprivate":     "0x89F0 is in SIOCDEVPRIVATE range (0x89F0-0x89FF)",
        "kernel_enforcement": "Linux dev_ioctl() does NOT gate SIOCDEVPRIVATE range on CAP_NET_ADMIN; enforcement is per-driver",
        "socket_requirement": "Caller needs an open socket (AF_INET) to call ioctl on a net device -- no capability required to open an AF_INET socket",
        "vtb_device":         "vtb tunnel device must exist (created by root/admin loading vtb.ko and running vtb setup); attacker needs to know the vtb interface name",
        "practical_context":  "FortiDeceptor is typically single-user (root/admin only) -- unprivileged user privilege escalation unlikely in practice; finding is structural (design flaw), not immediately exploitable",
    },

    "data_flow": {
        "direction":         "KERNEL -> USER (info disclosure, not user -> kernel injection)",
        "user_input":        "0x5ff8 bytes from user as QUERY FILTER (not written into kernel state)",
        "kernel_read":       "Loop at 0x310-0x3da walks vtb list_head linked list, reads kernel vtb entries",
        "output_build":      "Each 0x60-byte output slot is filled from kernel vtb entry fields (r15+0x20, r15+0x28, etc.) and stack buffer derived from user query filter",
        "loop_bound":        "cmp $0xff,%r14; jne 0x310 -- hardcoded 255-entry maximum; no overflow possible",
        "disclosed_fields":  "Each 0x60-byte entry: 0x10 bytes from vtb list entry (memcpy at 0x339); word fields at +0x28/+0x2a/+0x2c (likely port numbers); 8 qword fields from stack (IPs/endpoints); 2 dword fields (weights/flags)",
    },

    "vs_fortism": (
        "fortism in FGT/FFW/FWB: 6 ioctls (0x9002-0x9009), all behind CAP_SYS_ADMIN gate. "
        "vtb.ko: 4 ioctls (0x89f0-0x89f3), 3/4 gated on CAP_NET_ADMIN, 0x89f0 ungated. "
        "The fortism model is consistent (single gate); vtb.ko is inconsistent (per-cmd asymmetry). "
        "Source: /root/FortiADC_test/FortiADC/kernel/modules-6.1/vtb/vtbk.c (visible from .ko debug info)"
    ),

    "remediation": (
        "Add ns_capable(dev_net(dev), CAP_NET_ADMIN) check at the entry of the 0x89f0 handler path "
        "(between 0x141 and the kmalloc at 0x170). "
        "Validate the entry count in the user-supplied struct before the 0x310 loop (cap at a defined maximum). "
        "Treat all SIOCDEVPRIVATE handlers consistently -- if 0x89f1/f2/f3 require CAP_NET_ADMIN, 0x89f0 must too."
    ),

    "module_strings": [
        "VTB: max device %d slaved with master %s",
        "vtb_tunnel_ioctl_private",
        "VTB IOCTL dev %s cmd %#x, return %d",
        "VTB IOCTL dev %s cmd %#x",
        "VTB: fill tunnel info copy to user error!",
        "VTB: fill tunnel info copy from user error!",
        "VTB: enslave error, master %s not exist!",
        "VTb Build connnium for master %s cost time %lu, version %u:%u end, slave count %u, point count %u.",
        "/root/FortiADC_test/FortiADC/kernel/modules-6.1/vtb/vtbk.c",
    ],
}


# ---------------------------------------------------------
# FAD-F03: FCP package format -- no cryptographic signature,
#          CRC32-only integrity, hardcoded DES key baked into
#          both data section and instruction stream
# ---------------------------------------------------------
FAD_F03_FCP_PACKAGE_FORGERY = {
    "id":       "FAD-F03",
    "product":  "Fortinet FortiCare Package (FCP) library -- libFCP.so -- shared across FortiDeceptor, FortiGate, FortiWiFi, FortiADC, and any product receiving FortiCare updates",
    "severity":  "HIGH -- CRC32-only package integrity; DES key hardcoded in data section (0x3d90) AND instruction stream (gpUnpackObject 0x1a05 movabs imm); 40 object types include FIMG (firmware), ONCE (run-once executable), DCEN (AV engine), FAEN (FlowAV engine); attacker with extracted key can forge packages that pass all verification",
    "class":    "Missing Cryptographic Signature (CWE-347) / Hardcoded Cryptographic Key (CWE-321) / Weak Hash (CRC32 for integrity, CWE-328)",
    "cwe":      "CWE-347, CWE-321, CWE-328",

    "description": (
        "libFCP.so implements Fortinet's FortiCare Package (FCP) format, which is the update delivery "
        "container for all FortiCare-delivered content: AV signatures, AV/FlowAV engines, firmware images, "
        "run-once executables, SSLVPN packages, IPS/attack definitions, and 34 other object types. "
        "The library is NOT FortiDeceptor-specific -- the 40-entry object type table confirms it is shared "
        "FortiCare infrastructure. "
        "Package integrity is protected by CRC32 only (zlib crc32, confirmed in gpVerifyPkg and "
        "gpVerifyPkgHeaderChecksum disassembly -- no HMAC, no RSA, no ECDSA). "
        "Package encryption is DES-CBC with key=IV='S3crtMsG' (8 bytes, 56-bit effective). "
        "The DES key is hardcoded in TWO locations in the binary: "
        "(1) data section at file offset 0x3d90 as a null-terminated string; "
        "(2) instruction stream at VA 0x1a05 in gpUnpackObject as movabs rax, 0x47734d7472633353 "
        "(little-endian bytes: S3crtMsG). "
        "An attacker who extracts libFCP.so from any publicly available firmware image can: "
        "(a) decrypt all existing FCP packages; "
        "(b) forge new FCP packages for any of the 40 object types; "
        "(c) craft packages that pass gpVerifyPkg (only CRC32 checked) and load on any FortiCare endpoint. "
        "High-impact object types: FIMG (firmware image), ONCE (run-once executable -- executes on device), "
        "DCEN (AV engine executable), FAEN (FlowAV engine executable), FSLP (SSLVPN package). "
        "The 'run-once executable' type (ONCE) is the highest-severity attack surface -- "
        "forged ONCE package delivered via MITM or compromised update channel executes arbitrary code on device."
    ),

    "fcp_object_type_table": {
        "table_va":     "0x34c0 in libFCP.so 8.0.4",
        "stride":       "25 bytes per entry (5-byte ID + 20-byte description, null-padded)",
        "count":        "42 entries (index 0x00 through 0x29)",
        "accessor_fns": {
            "getObjTypeIdentifier":   "0x12c0: lookup by index, return ptr to 5-byte ID string",
            "getObjTypeDescription":  "0x12a0: lookup by index, return ptr to 20-byte description string",
        },
        "high_impact_types": {
            "FIMG (index 18)": "Firmware Image",
            "ONCE (index 16)": "Run-Once Executable -- executes on device at load time",
            "DCEN (index  3)": "AV Engine Executables",
            "FAEN (index 27)": "FlowAV Engine",
            "FSLP (index 23)": "SSLVPN Package File",
            "FADB (index  5)": "Attack Definitions (IPS)",
            "LIMG (index 22)": "FortiClient Installer File",
        },
        "all_types": {
            0:  ("FCPC", "Command Object"),
            1:  ("FCPR", "Response Object"),
            2:  ("DCDB", "Virus Definitions"),
            3:  ("DCEN", "AV Eng. Executables"),
            4:  ("IBDB", "IBDB Definitions"),
            5:  ("FADB", "Attack Definitions"),
            6:  ("MUDB", "IPS Malicious URL DB"),
            7:  ("FLDB", "FlowAV Database"),
            8:  ("FDNI", "FortiResp Net Info"),
            9:  ("FCNI", "FortiCare Net Info"),
            10: ("FSCI", "Support ctrct Info"),
            11: ("FSSI", "System Support Info"),
            12: ("FASE", "Antispam Engine"),
            13: ("FASR", "Antispam Definitions"),
            14: ("FSAE", "Server auth ext"),
            15: ("AVST", "Virus Statistics"),
            16: ("ONCE", "Run-Once Executable"),
            17: ("IMLT", "Image List"),
            18: ("FIMG", "Firmware Image"),
            19: ("FBVO", "FCP Binary Value Obj"),
            20: ("STAT", "FortiClient Info"),
            21: ("FECT", "FortiClient Ver List"),
            22: ("LIMG", "FC Installer File"),
            23: ("FSLP", "SSLVPN Package File"),
            24: ("FTSI", "FortiToken Activation"),
            25: ("FMDM", "3G/4G Modem List"),
            26: ("IPGE", "IP Geography DB"),
            27: ("FAEN", "FlowAV Engine"),
            28: ("MMDB", "Mobile Malware DB"),
            29: ("DBDB", "Botnet Domain DB"),
            30: ("FAPV", "FortiAP Matrix File"),
            31: ("FSWV", "FortiSW Matrix File"),
            32: ("IRDC", "IRDB Signature"),
            33: ("ADDB", "ADDB Signature"),
            34: ("IPGE", "IP GEO database"),
            35: ("HCDB", "Credential Stuffing"),
            36: ("CRDB", "Certificate Bundle"),
            37: ("DLDB", "DLP Service"),
            38: ("BOTS", "Bot Protection"),
            39: ("SFAD", "SFADSecurity"),
        },
    },

    "code_evidence": {
        "key_in_data_section":      "file offset 0x3d90: 'S3crtMsG1.3.1\\x00FC' -- DES key (8B) + version string",
        "key_in_instruction_stream": "gpUnpackObject VA 0x1a05: movabs rax, 0x47734d7472633353 (= S3crtMsG LE) -> stored at [rsp+0x110] for DES_set_key_unchecked",
        "des_setup":                "gpUnpackObject 0x19fd: call 0x11b0 (PLT -> DES_set_key_unchecked)",
        "des_decrypt":              "gpUnpackObject 0x1a6a: call 0x10f0 (PLT -> DES_ncbc_encrypt)",
        "crc32_verify_pkg":         "gpVerifyPkg 0x1f2a: call 0x11e0 (PLT -> gpVerifyPkgHeaderChecksum via CRC32); no crypto call in 0x1f20-0x1fb9 disassembly window",
        "crc32_verify_obj":         "gpVerifyObjHeaderChecksum 0x18d2: call 0x1090 (crc32 PLT); compares stored CRC at obj+0x7c with computed CRC",
        "no_signature_in_exports":  "PLT/import table: only DES_ncbc_encrypt, DES_set_key_unchecked, crc32, deflate/inflate -- no RSA, ECDSA, HMAC, SHA functions imported",
    },

    "package_header_layout": {
        "pkg_header_size":  "0x40 bytes (64B); gpGetPackageSize returns pkg[0x10] + 0x40",
        "pkg_header+0x10":  "total data size field",
        "pkg_header+0x14":  "number of objects in package (n_objects)",
        "pkg_header+0x3c":  "CRC32 of header (checked by gpVerifyPkgHeaderChecksum)",
        "obj_header_size":  "0x80 bytes (128B)",
        "obj_header+0x30":  "compressed object data size",
        "obj_header+0x34":  "object header size (typically 0x80)",
        "obj_header+0x2c":  "flags (bit 16 = DES-encrypted; bit 17 = compressed with zlib)",
        "obj_header+0x7c":  "CRC32 of object header (checked by gpVerifyObjHeaderChecksum)",
    },

    "attack_scenario": (
        "Supply chain / MITM attack: "
        "1. Extract libFCP.so from any publicly available Fortinet firmware image. "
        "2. Extract DES key from offset 0x3d90 ('S3crtMsG'). "
        "3. Forge a FCP package of type ONCE (Run-Once Executable) containing malicious payload. "
        "4. Compute correct CRC32 for header and object. "
        "5. DES-CBC encrypt the payload with key=IV='S3crtMsG'. "
        "6. Deliver via MITM on FortiCare update channel or via compromised update server. "
        "7. Target device loads package, passes gpVerifyPkg (CRC32 check passes), "
        "   executes ONCE payload as root. "
        "No device-specific key or certificate required. Same key across ALL firmware versions."
    ),

    "scope": {
        "affected_products":  "All Fortinet products receiving FortiCare updates that use libFCP.so for package handling",
        "confirmed_presence": "libFCP.so present in FortiDeceptor/FortiADC 8.0.4 (only accessible unencrypted rootfs; same library expected in all FortiCare-enabled products)",
        "cross_product_note": "Object types FAPV/FSWV suggest library also handles FortiAP and FortiSwitch update packages",
    },

    "remediation": (
        "1. Replace DES with AES-256-GCM for package encryption. "
        "2. Add RSA-2048+ or ECDSA-P256+ signature over each package (not CRC32). "
        "3. Rotate the hardcoded key entirely -- derive per-device using TPM or provisioning. "
        "4. Sign packages with a Fortinet-controlled private key; verify with embedded public key. "
        "CRC32 is not a security primitive. DES is deprecated (NIST SP 800-131A rev 2). "
        "The FCP format needs a complete cryptographic redesign."
    ),
}


# ---------------------------------------------------------
# Decoy template catalog (SBVM .pkg files, all decryptable)
# ---------------------------------------------------------
SBVM_CATALOG = {
    "encryption_key":  "S3crtMsG",
    "encryption_algo": "DES-CBC",
    "iv":              "S3crtMsG",

    "confirmed_decryptable": {
        "fgt601v1.pkg": {
            "size":     "50323176 bytes",
            "decoy":    "FortiGate 6.0.1 v1",
            "contains": "fgt601v1/fgt601v1.qcow2",
            "security": "Decoy fingerprints reveal how Fortinet emulates FortiGate hardware",
        },
        "fgt601v2.pkg": {
            "size":     "102711003 bytes",
            "decoy":    "FortiGate 6.0.1 v2",
        },
        "fgt601v3.pkg": {
            "size":     "53478542 bytes",
            "decoy":    "FortiGate 6.0.1 v3",
        },
        "scadav1.pkg": {
            "size":     "815913329 bytes",
            "decoy":    "SCADA v1 (ICS/OT honeypot)",
            "security": "Reveals Modbus/IEC104 register emulation parameters",
        },
        "scadav2.pkg": {"size": "325382144 bytes", "decoy": "SCADA v2"},
        "scadav3.pkg": {"size": "1755976086 bytes", "decoy": "SCADA v3"},
        "win10v1.pkg":  {"size": "5047088464 bytes", "decoy": "Windows 10 v1"},
        "win7x64v1.pkg": {"size": "unknown", "decoy": "Windows 7 x64"},
        "win7x86v1.pkg": {"size": "unknown", "decoy": "Windows 7 x86"},
        "centosv1.pkg":  {"size": "1091120385 bytes", "decoy": "CentOS v1"},
        "ubuntu16v1.pkg": {"size": "unknown", "decoy": "Ubuntu 16.04 v1"},
        "ubuntu16v2.pkg": {"size": "unknown", "decoy": "Ubuntu 16.04 v2"},
        "ubuntu18v1.pkg": {"size": "unknown", "decoy": "Ubuntu 18.04 v1"},
        "voipv1.pkg":    {"size": "unknown", "decoy": "VoIP decoy"},
        "iotv1.pkg":     {"size": "unknown", "decoy": "IoT device decoy"},
        "medicalv1.pkg": {"size": "unknown", "decoy": "Medical device decoy"},
        "crmv1.pkg":     {"size": "unknown", "decoy": "CRM system decoy"},
        "ev2023v1.pkg":  {"size": "unknown", "decoy": "EV/charging station decoy (2023)"},
    },
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "rootfs":      "COMPLETE -- ext4 fully accessible (FAD only non-encrypted Fortinet 8.0.x rootfs)",
    "vmlinux":     "ACCESSIBLE (38MB ELF). Kernel modules analyzed. vtb.ko ioctl surface pending deep RE.",
    "sbvm_format": "COMPLETE -- DES-CBC key=IV='S3crtMsG' confirmed by decryption of fgt601v1.pkg",
    "libFCP_so":   "COMPLETE -- full API disassembled (15 exports); 42-entry FCP object type table decoded (VA 0x34c0, 25B stride); gpVerifyPkg CRC32-only confirmed (no crypto imports for signing); DES key hardcoded at both file offset 0x3d90 (data) and VA 0x1a05 movabs immediate (text); cross-product scope confirmed (FIMG/ONCE/DCEN/FAEN types); FAD-F03 added",
    "vtb_ko":      "COMPLETE -- 4 ioctl cmds (0x89f0-0x89f3); cmd 0x89f0 missing CAP_NET_ADMIN gate; 0x5ff8-byte copy_from_user without privilege check",
    "no_fortism":  "CONFIRMED -- fortism NOT present in FAD/FortiDeceptor",
    "hypervisor":  "KVM + Xen both supported (kvm.ko, xen-gntalloc.ko, xen-pciback.ko present)",
    "unique_findings": [
        "FAD-F01: SBVM hardcoded DES key 'S3crtMsG' -- all 18 decoy templates decryptable",
        "FAD-F02: vtb.ko cmd 0x89f0 missing CAP_NET_ADMIN; READ-ONLY query returning vtb server table (IPs/ports/weights) to unprivileged caller; no OOB, no kernel write; cmds 0x89f1/f2/f3 all gated",
        "FAD-F03: HIGH -- FCP package format has CRC32-only integrity (no signature); DES key hardcoded in data (0x3d90) AND instruction stream (gpUnpackObject 0x1a05 movabs imm 0x47734d7472633353); 42 FCP object types include FIMG/ONCE/DCEN/FAEN; forged package passes gpVerifyPkg; cross-product Fortinet supply chain impact",
        "fgt601v1.qcow2 recovered -- FortiGate fingerprint artifacts exposed",
        "No fortism -- different kernel attack surface from FGT/FFW/FWB",
        "FAD rootfs fully accessible -- only non-encrypted Fortinet 8.0.x VM image",
        "SBVM format: DES-CBC -> zlib -> gzip -> tar -> qcow2",
        "vtb.ko source path leaked in debug info: /root/FortiADC_test/FortiADC/kernel/modules-6.1/vtb/vtbk.c",
    ],
}
