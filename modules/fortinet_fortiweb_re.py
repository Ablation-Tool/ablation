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

    "blocker": "Cannot confirm at static analysis whether FortiWeb sets a WVS password at startup (startup scripts in encrypted rootfs); this remains CANDIDATE pending runtime confirmation",

    "remediation": "FortiWeb should always pass a randomly-generated SHA512 password hash to w3af_api at startup; bind w3af_api to a Unix domain socket instead of TCP loopback if feasible; restrict /scans/ to http(s) scheme targets only.",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "vmlinuz":        "ACCESSIBLE (46MB ELF vmlinux extracted). fortism confirmed at 0x75e905.",
    "rootfs_gz":      "BLOCKED -- custom encryption 0x84fe53de. FWB-specific.",
    "krootfs_gz":     "BLOCKED -- custom encryption 0xb63606e9. Different from rootfs.gz.",
    "datafs_tar_gz":  "COMPLETE -- 18MB standard gzip; extracted from p1.raw ext4 (SYSLINUX boot partition); contents: bin/, config/, etc/, lib/, var/; key attack surfaces analyzed (Redis, wassd_ws.py, Shibboleth SAML, MCP schemas, Python cloud connectors)",
    "fortism_ioctls": "COMPLETE -- all 6 ioctls mapped (0x9002, 0x9003, 0x9004, 0x9005, 0x9007, 0x9009).",
    "cross_products":  "FGT-F19/F20/F21 confirmed; FGT-F16/F22 confirmed but partially mitigated.",

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
        "lib/": "libfpm.so, libsigfunc.so.1 (signature engine), libav.so.orig",
        "lib_packge/": "wvs.tar.xz ANALYZED -- complete w3af 1.x REST API (59MB); permissive-auth-by-default (FWB-F09); python-libs.tar.xz not yet analyzed",
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
        "FWB-F09: CANDIDATE -- wvs.tar.xz w3af REST API requires_auth bypasses all auth when PASSWORD not configured; POST /scans/ accepts file:// and internal targets -> local file read + SSRF; blocker: startup auth config in encrypted rootfs",
        "FortiWeb ships HSM (Luna/SafeNet) client config (Chrystoki.conf); HSM integration available but config has no credentials",
    ],
}
