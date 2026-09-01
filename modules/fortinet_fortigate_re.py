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
