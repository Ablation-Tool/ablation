"""
Fortinet FortiSwitch 224E-POE v7.2.0 RE
Source: FSW_224E_POE-v7-build0393-FORTINET-7.2.0.out (29MB)
Additional: FSW_108E_FPOE-v7-build0022-FORTINET-7.0.0.out (21MB)
Architecture: ARM32 (Cortex-A9, Broadcom BCM)
Extraction: Fortinet outer header -> uImage(kernel) at 0x10000 + uImage(ramdisk) at 0x510000
Kernel: Linux 3.6.5-Broadcom-Linux+ (2012), ARM32
Compiler: GCC 4.9.3 (Buildroot 2016.05)
Rootfs: gzip(ext2 ramdisk) -> mounts as /dev/ram0 -> bin.tar.xz (Fortinet CRC-bypass XZ)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiSwitch 224E-POE",
    "version":      "v7.2.0 build 0393",
    "build_date":   "2022-04-12",
    "arch":         "ARM32 (ARMv7, Broadcom BCM, Cortex-A9)",
    "libc":         "musl/glibc ARM32",
    "kernel":       "Linux 3.6.5-Broadcom-Linux+",
    "kernel_build": "GCC 4.9.3 (Buildroot 2016.05) -- EOL 2016 toolchain in 2022 firmware",

    "image_layout": {
        "outer_header":   "4-byte proprietary magic (0x83f6c30b) + ASCII size + model string, 0x10000-byte padded header",
        "uimage_kernel":  "uImage at 0x10000: uncompressed ARM32 kernel, 4MB, load/entry=0x61008000",
        "uimage_ramdisk": "uImage at 0x510000: gzip-wrapped ext2 ramdisk (~87MB uncompressed), type=3 (ramdisk)",
        "kernel_config":  "gzip(.config) at 0x2c64d0: Linux 3.6.5 ARM kernel Kconfig",
        "extraction": {
            "kernel":  "dd bs=1 skip=$((0x10040)) count=$((0x3db8e4)) -> ARM kernel image",
            "ramdisk": "dd bs=1 skip=$((0x510040)) count=$((0x16bce46)) -> gunzip -> ext2 ramdisk",
            "bin.tar": "XZ with Fortinet CRC bypass (block_hdr_size=2, filter=0x21/LZMA2, props=0x1c/dict=64MB)",
        },
    },

    "key_binaries": {
        "/bin/init": "12MB ARM32 stripped monolith; ALL daemons (cmdbsvr, ctrld, fdsmgmtd, httpd, etc.) symlinked here",
        "/lib/modules/af_admin.ko":         "Fortinet proprietary AF_ADMIN socket family; NOT stripped; 1.7KB text",
        "/lib/modules/fsw_kern_export.ko":  "Exports fsw_kern_export_queue_work, register/unregister_netevent_notifier",
        "/lib/modules/linux-kernel-bde.ko": "Broadcom Device Engine (switch ASIC driver)",
        "/lib/modules/linux-bcm-diag-full.ko": "Broadcom diagnostic interface",
    },

    "default_services": {
        "https": "443 (ALLOWED by default on mgmt/internal interfaces)",
        "ssh":   "22 (ALLOWED by default)",
        "ping":  "ICMP (ALLOWED by default)",
        "telnet": "NOT enabled by default (support present in binary but requires explicit config)",
    },

    "default_admin": {
        "user":     "admin",
        "password": "ENC XXUp2ozpdysrQ (in /etc/system.conf.def; same string embedded in /bin/init)",
        "note":     "FSW uses Fortinet ENC obfuscation distinct from standard FortiOS AES-CBC with bcpbFortinet@#$%",
    },
}


# ---------------------------------------------------------
# FSW-F01: Linux kernel 3.6.5 (EOL 2013) -- zero kernel mitigations
# ---------------------------------------------------------
FSW_F01_ANCIENT_KERNEL = {
    "id":       "FSW-F01",
    "product":  "Fortinet FortiSwitch 224E-POE v7.2.0",
    "severity": "MEDIUM -- ancient EOL kernel with zero modern mitigations; any kernel vuln is trivially exploitable",
    "class":    "Missing security mitigation -- EOL kernel (CWE-1188)",

    "description": (
        "FortiSwitch 7.2.0 (released April 2022) ships Linux 3.6.5 built in April 2022. "
        "Linux 3.6.5 was released in October 2012 and was EOL by late 2012 (3.x was EOL 2016). "
        "This is a ~10-year-old kernel in a 2022 product release. "
        "Every kernel mitigation added between 2012 and 2022 is absent: "
        "no KASLR (added 3.14, 2014), no KPTI (4.14, 2018), no KASLR+PIE (4.15, 2018), "
        "no speculative execution mitigations (Spectre/Meltdown, 4.14-4.15, 2018), "
        "no kernel stack protector (CONFIG_CC_STACKPROTECTOR=n), no SECCOMP (not set). "
        "The compiler is GCC 4.9.3 from Buildroot 2016 -- EOL since 2016."
    ),

    "kernel_config_evidence": {
        "CC_STACKPROTECTOR":        "# CONFIG_CC_STACKPROTECTOR is not set",
        "SECCOMP":                  "# CONFIG_SECCOMP is not set",
        "SECURITY":                 "# CONFIG_SECURITY is not set (no LSM framework)",
        "SECURITY_DMESG_RESTRICT":  "# CONFIG_SECURITY_DMESG_RESTRICT is not set",
        "STRICT_DEVMEM":            "# CONFIG_STRICT_DEVMEM is not set (any process can read /dev/mem)",
        "KASLR":                    "ABSENT -- 3.6 kernel predates KASLR by 2 years; kernel loads at fixed address",
        "KPTI":                     "ABSENT -- 3.6 predates Meltdown mitigation by 6 years",
        "PIE_ASLR":                 "CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE=y (userspace PIE only, not kernel)",
    },

    "mitigation_status": {
        "KASLR":            "ABSENT -- kernel at fixed ARM load address 0x61008000",
        "KPTI":             "ABSENT",
        "SMEP/SMAP":        "ABSENT -- ARM32 has no equivalent in 3.6",
        "CC_STACKPROTECTOR": "ABSENT",
        "SECCOMP":          "ABSENT",
        "CONFIG_SECURITY":  "ABSENT -- no LSM framework (no SELinux, no AppArmor, no Yama)",
        "STRICT_DEVMEM":    "ABSENT -- /dev/mem grants full physical memory access",
        "RETPOLINE":        "ABSENT -- 3.6 predates Spectre by 6 years",
    },

    "compiler_details": {
        "gcc":     "4.9.3 (Buildroot 2016.05)",
        "gcc_eol": "GCC 4.9 support ended 2015; used in 2022 firmware",
        "missing": [
            "GCC 7: -fstack-clash-protection",
            "GCC 8: -fcf-protection (CET)",
            "GCC 9: -ftrivial-auto-var-init",
            "GCC 12: improved -fanalyzer",
        ],
    },

    "impact": (
        "A kernel vulnerability (buffer overflow, use-after-free, race condition) in any "
        "network-reachable kernel path (TCP stack, SCTP, packet socket, netfilter, switch ASIC driver) "
        "is trivially exploitable: fixed kernel load address eliminates KASLR bypass requirement, "
        "no stack canary eliminates stack smashing detection, no NX in some paths. "
        "The switch ASIC Broadcom BDE driver is exposed to the control plane and has a documented "
        "history of kernel bugs in embedded network devices."
    ),

    "remediation": "Upgrade to Linux 5.15 LTS minimum. Enable CONFIG_CC_STACKPROTECTOR_STRONG, CONFIG_SECCOMP, CONFIG_SECURITY. Update to GCC 12+.",
}


# ---------------------------------------------------------
# FSW-F02: af_admin.ko -- Fortinet kernel socket with weak privilege gate
# ---------------------------------------------------------
FSW_F02_AF_ADMIN_WEAK_CAP = {
    "id":       "FSW-F02",
    "product":  "Fortinet FortiSwitch 224E-POE v7.2.0",
    "severity": "MEDIUM -- admin_create requires only CAP_NET_BIND_SERVICE (not CAP_NET_ADMIN); admin_sendmsg has NO capability check",
    "class":    "Insufficient privilege gate on kernel IPC socket (CWE-269)",

    "description": (
        "af_admin.ko implements a Fortinet proprietary AF_ADMIN socket family. "
        "admin_create (socket creation) requires capable(CAP_NET_BIND_SERVICE) == capable(13). "
        "CAP_NET_BIND_SERVICE is a weaker gate than CAP_NET_ADMIN (12) or CAP_SYS_ADMIN (21). "
        "In a properly isolated system, only privileged processes should create AF_ADMIN sockets. "
        "More critically: admin_sendmsg (message send) has NO capability check at all. "
        "Once an AF_ADMIN socket is created, ANY message can be sent to the kernel admin IPC path "
        "without any per-message privilege validation. "
        "Combined with FSW-F01 (no CONFIG_SECURITY, no LSM), there is no secondary enforcement layer."
    ),

    "disasm_evidence": {
        "admin_create_cap_check": (
            "offset 0x05b4: mov r0, #0xd        ; r0 = 13 = CAP_NET_BIND_SERVICE\n"
            "offset 0x05c0: bl  capable          ; capable(13)\n"
            "offset 0x05c4: cmp r0, #0\n"
            "offset 0x05c8: beq #0x684           ; if !capable: return -EPERM"
        ),
        "admin_sendmsg_no_cap": (
            "offset 0x02dc-0x03d8: full admin_sendmsg disasm\n"
            "NO capable() call anywhere in admin_sendmsg\n"
            "Calls: sock_alloc_send_skb, memcpy_fromiovec, kfree_skb\n"
            "Final: bl to 0x00ac (message delivery path)"
        ),
        "cap_asymmetry": (
            "admin_create: capable(CAP_NET_BIND_SERVICE) -- required at socket creation\n"
            "admin_sendmsg: NO capability check -- once socket is open, all messages pass\n"
            "admin_recvmsg: NO capability check -- any process can read admin socket responses\n"
            "admin_setsockopt/getsockopt: return -EAFNOSUPPORT immediately (no functional surface)"
        ),
    },

    "function_map": {
        "admin_create":     {"offset": "0x05a4", "size": 268, "cap": "capable(13/CAP_NET_BIND_SERVICE)"},
        "admin_sendmsg":    {"offset": "0x02dc", "size": 256, "cap": "NONE"},
        "admin_recvmsg":    {"offset": "0x0208", "size": 212, "cap": "NONE"},
        "admin_bind":       {"offset": "0x03dc", "size": 84,  "cap": "NONE"},
        "admin_setsockopt": {"offset": "0x0084", "size": 20,  "note": "returns -EAFNOSUPPORT"},
        "admin_getsockopt": {"offset": "0x0098", "size": 20,  "note": "returns -EAFNOSUPPORT"},
        "admin_init":       {"offset": "0x0000", "size": 32,  "note": "module init"},
    },

    "exported_symbol": {
        "kernel_send_admin_packet": "exported by af_admin.ko; called from admin_sendmsg path; sends skb to admin socket receive queue",
    },

    "impact": (
        "Any process with CAP_NET_BIND_SERVICE (granted to most network-facing daemons) can create "
        "an AF_ADMIN socket and then inject arbitrary admin IPC messages without per-message "
        "authorization. Combined with no CONFIG_SECURITY (FSW-F01), a compromised web daemon "
        "or switch management process can directly inject into the admin socket channel "
        "that the init monolith uses for inter-daemon coordination."
    ),

    "remediation": (
        "Change capable(CAP_NET_BIND_SERVICE) to capable(CAP_SYS_ADMIN) or capable(CAP_NET_ADMIN) in admin_create. "
        "Add per-message capability check in admin_sendmsg. "
        "Add socket-level credential caching so send side inherits creation-time privilege."
    ),
}


# ---------------------------------------------------------
# FSW-F03: Shared HTTPS private key across all devices of same firmware version
# ---------------------------------------------------------
FSW_F03_SHARED_TLS_KEY = {
    "id":       "FSW-F03",
    "product":  "Fortinet FortiSwitch 224E-POE v7.2.0",
    "severity": "HIGH -- shared 2048-bit RSA private key in firmware enables HTTPS MITM for all devices of this firmware version",
    "class":    "Hardcoded cryptographic key shared across devices (CWE-321)",

    "description": (
        "The FortiSwitch firmware ships with a pre-generated 2048-bit RSA key pair "
        "(/etc/fsw.crt + /etc/fsw.key) embedded in the ext2 ramdisk. "
        "This key pair is identical across ALL devices running this firmware version. "
        "An attacker who extracts this key from the firmware image (no physical access needed -- "
        "the image is publicly downloadable from Fortinet) can impersonate any FortiSwitch device "
        "running this firmware in an HTTPS MITM position. "
        "This breaks TLS trust for management sessions on any network segment where the attacker "
        "can intercept traffic to the switch management interface."
    ),

    "key_details": {
        "file":         "/etc/fsw.crt + /etc/fsw.key",
        "type":         "RSA 2048-bit",
        "cert_subject":  "CN=FortiSwitch, O=Fortinet, OU=FortiSwitch",
        "cert_issuer":   "CN=support, O=Fortinet, OU=Certificate Authority",
        "cert_validity": "2017-04-21 to 2038-01-19 (21-year validity)",
        "key_md5":      "4ee4502d2e4f4d6cdd4c62f8139d8b69 (pubkey MD5; same across all devices with this firmware)",
    },

    "additional_shared_certs": {
        "/etc/802.1x.crt": (
            "auth-cert.fortinet.com (DigiCert-signed, CN=auth-cert.fortinet.com). "
            "Subject: Fortinet, Inc. Expired: 2022-05-24. "
            "Shared 802.1x authentication cert for all switches -- "
            "expired cert blocks 802.1x auth when server requires valid cert chain. "
            "Private key (/etc/802.1x.key) is also shared."
        ),
        "/etc/802.1x_ca.crt": "Shared CA cert for 802.1x",
    },

    "attack_scenario": {
        "step_1": "Download FortiSwitch 7.2.0 firmware image from Fortinet public site",
        "step_2": "Extract ramdisk: dd -> gunzip -> mount ext2 -> /etc/fsw.key",
        "step_3": "Use extracted key in MITM position: openssl s_server -key fsw.key -cert fsw.crt",
        "step_4": "Admin HTTPS sessions to any FortiSwitch 7.2.0 device are decryptable",
        "no_device_access": "Key extraction requires only the firmware image, not a physical device",
    },

    "scope": (
        "Affects all FortiSwitch devices shipped with v7.2.0 build 0393 firmware. "
        "Different firmware builds may have different keys but same architectural flaw. "
        "A properly implemented device generates a unique key per-device on first boot; "
        "this firmware ships with a static build-time key."
    ),

    "remediation": (
        "Generate a unique RSA key per device on first boot (similar to SSH host key generation). "
        "Remove the pre-generated key from the firmware image. "
        "Ship a factory certificate and provision device-unique certs via the management plane. "
        "Rotate the 802.1x cert (already expired) and generate per-device 802.1x credentials."
    ),
}


# ---------------------------------------------------------
# FSW-F04: Default admin password in system.conf.def
# ---------------------------------------------------------
FSW_F04_DEFAULT_ADMIN_PASSWORD = {
    "id":       "FSW-F04",
    "product":  "Fortinet FortiSwitch 224E-POE v7.2.0",
    "severity": "MEDIUM -- default admin password stored in ENC format in firmware; format is FSW-specific obfuscation, not strong encryption",
    "class":    "Hardcoded credentials (CWE-798)",

    "description": (
        "The firmware ships /etc/system.conf.def with a default admin password: "
        "'set password ENC XXUp2ozpdysrQ'. "
        "The 'ENC' prefix is a Fortinet obfuscation encoding (not strong cryptographic hashing). "
        "The same ENC string appears verbatim inside the /bin/init monolith "
        "adjacent to the string 'Please input the old password!', suggesting it is "
        "a comparison sentinel rather than a salted hash. "
        "Any device that ships with this default configuration and where the admin "
        "does not change the password on first login is at risk. "
        "FortiSwitch does not enforce mandatory password change on first login in all deployments."
    ),

    "evidence": {
        "system.conf.def": "config system admin; edit admin; set password ENC XXUp2ozpdysrQ; set accprofile 'super_admin'",
        "binary_match":    "grep 'XXUp2ozpdysrQ' /bin/init -> found adjacent to 'Please input the old password!'",
        "encoding_note":   "FSW ENC format differs from standard FortiOS bcpbFortinet@#$% AES-CBC key; FSW-specific scheme",
    },

    "remediation": (
        "Remove the hardcoded default from system.conf.def. "
        "Enforce password change on first admin login. "
        "Use a device-unique derived password (e.g., derived from hardware serial number) "
        "or require out-of-band initial password provisioning."
    ),
}


# ---------------------------------------------------------
# FSW-F05: Unencrypted rootfs and full binary exposure
# ---------------------------------------------------------
FSW_F05_PLAINTEXT_ROOTFS = {
    "id":       "FSW-F05",
    "product":  "Fortinet FortiSwitch 224E-POE v7.2.0",
    "severity": "INFO -- entire rootfs is plaintext (ext2 ramdisk in gzip uImage); all binaries, keys, and configs are extractable without the device",
    "class":    "Sensitive information in firmware (CWE-200)",

    "description": (
        "Unlike FortiGate (XZ with CRC bypass -- requires RE), FortiAuthenticator (f1ec f5ed encryption), "
        "FortiFirewall/FortiAnalyzer/FortiManager (proprietary encryption), FortiSwitch ships "
        "its root filesystem as a standard gzip-wrapped ext2 ramdisk in a U-Boot uImage. "
        "No proprietary encryption or obfuscation layer. "
        "Any analyst with the firmware image can extract and analyze the complete system, "
        "including all private keys (FSW-F03), configuration defaults (FSW-F04), "
        "and all management daemon binaries."
    ),

    "extraction_path": {
        "firmware":  "FSW_224E_POE-v7-build0393-FORTINET-7.2.0.out (public download)",
        "scan":      "Find uImage ramdisk at 0x510000 (type=3/ramdisk, compress=1/gzip)",
        "extract":   "dd + gunzip -> 87MB ext2 filesystem",
        "mount":     "mount -o loop,ro ramdisk.ext2 /mnt/fsw",
        "bin_tar":   "Fortinet CRC-bypass XZ at /bin.tar.xz (dict_size=64MB, block_hdr=12 bytes)",
        "result":    "174 binaries + all /etc config files + private keys",
    },

    "contrast_with_other_products": {
        "FGT/FFW/FWB/FAC/FAZ/FMG": "Proprietary encrypted rootfs or custom XZ",
        "FAD":                      "Plaintext XZ (accessible) but no TLS key sharing",
        "FEXT":                     "squashfs (accessible), stripped binaries, Kore auth disabled",
        "FSW":                      "Plaintext ext2 ramdisk -- easiest extraction path in the product line",
    },

    "remediation": "Apply the same encrypted rootfs approach used in FGT/FFW/FAC to protect firmware contents.",
}


# ---------------------------------------------------------
# FSW-F06: /bin/init attack surface -- no-stack-protector + unsafe function density + CANDIDATE command injection
# ---------------------------------------------------------
FSW_F06_INIT_ATTACK_SURFACE = {
    "id":       "FSW-F06",
    "product":  "Fortinet FortiSwitch 224E-POE v7.2.0",
    "severity": "HIGH -- 12MB stripped ARM32 monolith with no stack protector; 836 strcpy + 424 sprintf call sites; any network-reachable buffer overflow = direct RCE",
    "class":    "Missing stack protector + unsafe function density (CWE-121, CWE-676)",

    "description": (
        "/bin/init is a 12MB stripped ARM32 ELF that implements ALL management daemons "
        "(httpd, cmdbsvr, ctrld, fdsmgmtd, etc.) as symlinked entry points. "
        "Compiled with GCC 4.9.3 (Buildroot 2016), no -fstack-protector-strong, no FORTIFY_SOURCE, "
        "no RELRO, no PIE (static base). "
        "BERT semantic sweep (all-MiniLM-L6-v2, WhiteningTransform) across 9,464 functions with 10 "
        "vulnerability query profiles (BUFFER_OVERFLOW, FORMAT_STRING, COMMAND_INJECT, AUTH_BYPASS, "
        "INTEGER_OVERFLOW, HTTP_PARSE, STACK_OVERFLOW, SNMP_PARSE, TYPE_CONFUSION, UNAUTH_ACCESS) "
        "returned max similarity 0.237 -- below automated high-confidence threshold (0.35+). "
        "Manual PLT-based call site enumeration found: 128 system() calls, 3 popen() calls, "
        "836 strcpy() calls, 424 sprintf() calls, 1 vsprintf() call, 543 strncpy() calls. "
        "With no stack protector anywhere in the binary, ANY stack-based buffer overflow is directly "
        "exploitable: no canary to detect/abort, return address overwrite succeeds on first attempt."
    ),

    "attack_surface_metrics": {
        "binary_size":       "12,615,168 bytes (12MB) ARM32 ELF",
        "total_functions":   "9,464 prologues found (ARM32 STMFD pattern scan)",
        "system_calls":      128,
        "popen_calls":       3,
        "strcpy_calls":      836,
        "sprintf_calls":     424,
        "vsprintf_calls":    1,
        "strncpy_calls":     543,
        "snprintf_calls":    2163,
        "memcpy_calls":      1877,
        "stack_protector":   "ABSENT -- compiled with GCC 4.9.3 without -fstack-protector-strong",
        "ASLR":              "Limited -- ARM32 PIE not used; binary loaded at static address; kernel has no KASLR (FSW-F01)",
        "RELRO":             "ABSENT -- GOT fully writable at runtime",
    },

    "bert_sweep_results": {
        "model":         "sentence-transformers/all-MiniLM-L6-v2 + WhiteningTransform",
        "functions":     9464,
        "queries":       10,
        "top_sim":       0.237,
        "interpretation": (
            "Max cosine similarity 0.237 for STACK_OVERFLOW query against function at foff=0x5dad24 "
            "(8 insns, tiny stub, disassembly shows simple field store -- BERT false positive). "
            "Multi-profile hits (3+ queries): foff=0x5dad24 (4 queries, fp), "
            "foff=0x37373c (3 queries: BUFFER_OVERFLOW, AUTH_BYPASS, SNMP_PARSE; 97-insn refcount teardown function). "
            "No function scored above 0.30 on any single query. "
            "Semantic sweep: NEGATIVE (no high-confidence automated vulnerability finds). "
            "Negative result documented: the BERT signal-to-noise ratio on ARM32 stripped code "
            "is lower than x86-64 (fewer semantic cues in normalized instruction mix). "
            "Attack surface metrics (above) remain valid regardless of sweep result."
        ),
    },

    "candidate_command_injection": {
        "id":       "FSW-F06a (CANDIDATE -- requires authenticated management access path confirmation)",
        "function": "0x6356f4 (foff=0x6256f4) and 0x635810",
        "template": "ifconfig %s hw ether %s 2> /dev/null",
        "vma_fmt1": "0x971878: '%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx' (MAC formatter)",
        "vma_fmt2": "0x9718a4: 'ifconfig %s hw ether %s 2> /dev/null'",
        "analysis": (
            "Function at 0x6356f4 receives (r0=interface_name_ptr, r1=mac_bytes_ptr). "
            "First snprintf: format MAC bytes as 'xx:xx:xx:xx:xx:xx' into 30-byte stack buffer. "
            "Second snprintf: 'ifconfig %s hw ether %s' with r3=[fp-0xc0] (first param) and buf1 (MAC string). "
            "system() then executes the result. "
            "The %s for interface name comes from struct pointer (r0=struct_ptr at caller 0x6358bc, "
            "struct found via linked-list iteration matching struct[0xdc] against a search key). "
            "If the struct's interface name field (at struct base) can be populated with shell "
            "metacharacters via management plane (CLI, SNMP, web), this is authenticated command injection. "
            "Caller 2 (0x636cc8): r0=[fp-0x20] (struct pointer), r1=struct+0xed (MAC). "
            "Confirmation requires tracing how struct[base] interface name field is populated -- "
            "management CLI set commands are the expected source."
        ),
        "status": "CANDIDATE -- ifconfig template confirmed; struct source requires CLI/SNMP write path tracing",
    },

    "no_canary_impact": (
        "With no stack protector, any of the 836 strcpy() call sites where the destination is "
        "a stack buffer and the source length is user-controlled is directly exploitable: "
        "no stack canary = no abort on overflow = return address overwrite on first attempt. "
        "Combined with no kernel KASLR (fixed kernel VA 0x61008000) and no RELRO (writable GOT), "
        "a confirmed stack overflow chains to: overwrite return address -> ROP pivot -> "
        "GOT overwrite of trusted function (e.g., strlen, strncpy) -> arbitrary code execution as root. "
        "All management daemons run as root (single monolith with no privilege separation)."
    ),

    "remediation": (
        "Immediate: recompile with -fstack-protector-strong and -D_FORTIFY_SOURCE=2. "
        "Replace all strcpy/sprintf calls in network-parsing paths with strncpy/snprintf+bounds check. "
        "Longer term: privilege-separate management daemons (httpd, SNMP, CLI) into separate processes "
        "with minimal capabilities. Enable PIE+ASLR for all daemons. Upgrade to GCC 12+ with -fanalyzer."
    ),
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "kernel":          "ANALYZED -- Linux 3.6.5 ARM32, uncompressed uImage at 0x10040; strings extracted",
    "kernel_config":   "EXTRACTED -- gzip at 0x2c64d0; ARM3 config confirms all mitigation absences",
    "ramdisk":         "EXTRACTED -- ext2, 87MB; /bin.tar.xz -> 174 binaries via Fortinet XZ CRC bypass",
    "af_admin.ko":     "FULLY DISASSEMBLED -- NOT stripped; 6 functions mapped; cap asymmetry confirmed",
    "init_monolith":   "BERT SWEEP COMPLETE -- 9,464 functions; 10 query profiles; max sim 0.237 (negative); PLT call-site enumeration done; ifconfig CANDIDATE documented in FSW-F06a",
    "tls_keys":        "EXTRACTED -- fsw.key + fsw.crt + 802.1x.key + 802.1x.crt all plaintext in ext2",

    "unique_findings": [
        "FSW-F01: MEDIUM -- Linux 3.6.5 EOL kernel (2012) with GCC 4.9.3 (Buildroot 2016) in 2022 firmware; zero modern mitigations (no KASLR, no KPTI, no stack protector, no SECCOMP, no LSM)",
        "FSW-F02: MEDIUM -- af_admin.ko admin_create requires only CAP_NET_BIND_SERVICE (not CAP_NET_ADMIN); admin_sendmsg has NO capability check; kernel IPC path accessible to any process with basic network cap",
        "FSW-F03: HIGH -- shared 2048-bit RSA private key across all devices of same firmware version; enables HTTPS MITM; key extractable without device from public firmware image",
        "FSW-F04: MEDIUM -- default admin password 'ENC XXUp2ozpdysrQ' in system.conf.def; found verbatim in /bin/init binary; FSW-specific encoding not standard FortiOS AES-CBC",
        "FSW-F05: INFO -- plaintext ext2 ramdisk (gzip uImage); easiest rootfs extraction path in Fortinet product line; no encryption layer",
        "FSW-F06: HIGH -- /bin/init 12MB monolith: no stack protector; 836 strcpy + 424 sprintf call sites; BERT sweep negative (max 0.237); ifconfig command injection CANDIDATE (FSW-F06a, authenticated)",
        "802.1x cert (auth-cert.fortinet.com) expired 2022-05-24 -- shared across all devices; expired cert blocks 802.1x auth requiring valid chain",
        "CONFIG_SECURITY=not set -- NO LSM framework; no secondary enforcement layer for any privilege escalation",
        "CONFIG_STRICT_DEVMEM=not set -- /dev/mem grants full physical memory access to any process",
    ],

    "vs_other_products": {
        "FGT/FFW/FWB": "fortism LSM, modern kernels (5.x/6.x), encrypted rootfs (XZ CRC bypass)",
        "FAC":          "KASLR absent but encrypted rootfs (f1ec f5ed), Snap-based, no fortism",
        "FAD":          "vtb.ko ioctl surface, plaintext XZ rootfs, SBVM DES key, modern kernel",
        "FEXT":         "Kore auth disabled (CRITICAL), ARM aarch64, plaintext squashfs",
        "FSW":          "Oldest kernel in product line (3.6.5 2012), weakest mitigation profile, plaintext ext2 ramdisk, shared TLS key",
    },

    "image_format_notes": {
        "outer_header":     "4-byte magic (0x83f6c30b) + ASCII size + model string; 0x10000-byte zero-padded header",
        "uimage_kernel":    "0x10000: uImage, type=2 (kernel), arch=2 (ARM), compress=0 (none), 4MB, load=0x61008000",
        "gzip_kconfig":     "0x2c64d0: gzip(.config) -- ARM 3.6.5 Kconfig; 53KB uncompressed",
        "uimage_ramdisk":   "0x510000: uImage, type=3 (ramdisk), arch=2 (ARM), compress=1 (gzip), 24MB compressed",
        "ramdisk_inner":    "gzip -> ext2, 87MB; UUID=fbfeb683-cbe0-4479-ac65-2ba4a235f872; rdimg",
        "bin_tar_xz":       "/bin.tar.xz: Fortinet XZ CRC bypass (SHA-256 stream flags 0x000a, LZMA2 props=0x1c/64MB dict); 15.9MB decompressed tar",
    },
}
