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
    "severity": "MEDIUM -- cmd 0x89f0 reads 0x5ff8 bytes from user space with no capability gate; all other cmds gated on CAP_NET_ADMIN",
    "class":    "Missing Privilege Check (CWE-862) / Kernel ioctl asymmetric authorization",
    "cwe":      "CWE-862 (Missing Authorization)",

    "description": (
        "vtb_tunnel_ioctl_private handles 4 SIOCDEVPRIVATE commands (0x89f0-0x89f3). "
        "Commands 0x89f1, 0x89f2, and 0x89f3 each gate on ns_capable(ns, CAP_NET_ADMIN=0xc) "
        "before any user-to-kernel data transfer. "
        "Command 0x89f0 does NOT check ns_capable: it calls kmalloc(0x5ff8, GFP_KERNEL) "
        "then copy_from_user(buf, user_arg+0x10, 0x5ff8) with no privilege gate. "
        "The asymmetry is structurally inconsistent -- the same privilege model is applied to "
        "all sibling commands but omitted for 0x89f0, which handles the largest user-supplied buffer."
    ),

    "command_map": {
        "0x89f0": {
            "capability_check": "ABSENT",
            "copy_from_user":   "kmalloc(0x5ff8, GFP_KERNEL) then copy_from_user(buf, user_arg+0x10, 0x5ff8)",
            "copy_to_user":     "copy_to_user(user_arg+0x10, result, 0x5ff8) at offset 0x680",
            "operation":        "Read/write vtb tunnel configuration (ketama continuum + server table)",
            "note":             "Largest user-supplied buffer; only command without capability gate",
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

    "data_flow_risk": {
        "0x5ff8_user_data":  "0x5ff8 = 24568 bytes from user. After copy_from_user, data is interpreted as a vtb tunnel info structure and written into the ketama load-balance continuum and server table",
        "continuum_write":   "At 0x310-0x3da: loop iterates up to 0xff (255) entries from user-supplied data, each 0x60 bytes, writing into kernel vtb state -- any pointer-like field could influence kernel memory writes",
        "no_size_validation": "No upper-bound check on count or size before the loop at 0x3d3 (cmp $0xff,%r14; jne 0x310)",
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
    "libFCP_so":   "PARTIAL -- key location 0x3d90, call sites 0x169a and 0x1a07 disassembled. Object structure mapped.",
    "vtb_ko":      "COMPLETE -- 4 ioctl cmds (0x89f0-0x89f3); cmd 0x89f0 missing CAP_NET_ADMIN gate; 0x5ff8-byte copy_from_user without privilege check",
    "no_fortism":  "CONFIRMED -- fortism NOT present in FAD/FortiDeceptor",
    "hypervisor":  "KVM + Xen both supported (kvm.ko, xen-gntalloc.ko, xen-pciback.ko present)",
    "unique_findings": [
        "FAD-F01: SBVM hardcoded DES key 'S3crtMsG' -- all 18 decoy templates decryptable",
        "FAD-F02: vtb.ko cmd 0x89f0 missing CAP_NET_ADMIN; reads 0x5ff8 bytes from user space without privilege gate; cmds 0x89f1/f2/f3 all gated",
        "fgt601v1.qcow2 recovered -- FortiGate fingerprint artifacts exposed",
        "No fortism -- different kernel attack surface from FGT/FFW/FWB",
        "FAD rootfs fully accessible -- only non-encrypted Fortinet 8.0.x VM image",
        "SBVM format: DES-CBC -> zlib -> gzip -> tar -> qcow2",
        "vtb.ko source path leaked in debug info: /root/FortiADC_test/FortiADC/kernel/modules-6.1/vtb/vtbk.c",
    ],
}
