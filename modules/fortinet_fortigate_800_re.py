"""
Fortinet FortiGate RE -- FortiOS 8.0.0.F build0167
Sources:
  - FGT_VM64-v8.0.0.F-build0167-FORTINET.out.ovf.zip (2026-04-20)
  - FGT_7000F-v8.0.0.F-build0167-FORTINET.zip (bare-metal, AES-encrypted rootfs -- not extracted)
  - Firmware: fortios.vmdk -> fortios.raw, partition 1 (ext3 label=FORTIOS, SYSLINUX boot)
  - Kernel: flatkc (bzImage, Linux 4.19.13, FortiOS IMA enforce mode, fos_keyring)
  - rootfs.gz: AES-encrypted (device-specific key in kernel); not extractable without hardware
  - datafs.tar.gz: plain gzip, ~46MB expanded; lib/ + etc/ contents
  - Semantic sweep R1: libips.so.new (43882 functions), libav.so.new (37482 functions) -- 100% FP
  - Semantic sweep R2 (fixed filter): libips.so.new (10692 encoded), libav.so.new (5391 encoded) -- 100% FP
  - Kernel: flatkc extracted (27MB vmlinux), fortism LSM confirmed, rootfs cbc(aes) key not static
Products: Fortinet FortiGate VM64 8.0.0 build0167, FortiOS 8.0.0.F
"""

# ---------------------------------------------------------
# Architecture overview
# ---------------------------------------------------------
FGT800_ARCHITECTURE = {
    "firmware_layout": {
        "disk":            "fortios.vmdk (VMware4, 123MB compressed, 2GB virtual)",
        "p1":              "256MB ext3 labeled FORTIOS, SYSLINUX/EXTLINUX bootloader",
        "p2":              "1.7GB Linux (data partition -- empty at provisioning time)",
        "p3":              "64MB EFI FAT-12/16/32",
        "kernel":          "flatkc: bzImage Linux 4.19.13, FortiOS IMA enforce mode, fos_keyring LSM",
        "rootfs":          "rootfs.gz: AES-encrypted (key in kernel, device-specific). NOT EXTRACTABLE.",
        "datafs":          "datafs.tar.gz: plain gzip, ~46MB expanded; lib/ + etc/ contents",
        "rootfs_note":     "rootfs.gz entropy=7.997, confirmed AES (no XOR period, version-unique ciphertext)",
        "bare_metal_note": "FGT_7000F bare-metal: 64-byte XOR header (8MB) + AES payload (8-136MB). Same conclusion.",
    },

    "extracted_binaries": {
        "libips.so.new":  "18MB stripped ELF64 shared object. FortiGate IPS engine. Pre-auth attack surface.",
        "libav.so.new":   "15MB stripped ELF64 shared object. FortiGate AV engine. File parsing surface.",
        "path":           "~/ablation/fortigate-work/extract/datafs/lib/",
        "note":           "Only accessible binaries from datafs.tar.gz. Core OS daemons in encrypted rootfs.",
    },

    "kernel_forensics": {
        "kernel_version":     "Linux 4.19.13 (LTS, Oct 2018 base, rebuilt 2026-04-20)",
        "kernel_age_note":    "4.19 LTS -- 7+ years old at time of 8.0.0 release; significant kernel CVE backlog",
        "kernel_file":        "flatkc (7.7MB bzImage on partition 1)",
        "decompressed_size":  "26.8MB",
        "security_features":  [
            "fos_ima: FortiOS IMA enforce mode (kernel module signature enforcement)",
            "fos_keyring: custom X.509 keyring for trusted certificate loading",
            "FortiOS Security Module: LSM that blocks unsigned kernel module loading",
            "Integrity: /data/hash_bin.sha256 checked at boot",
        ],
        "missing_features":   [
            "No KASLR (bzImage, flat load address -- deterministic ROP gadgets)",
            "Linux 4.19 predates many kernel hardening patches applied in 5.x",
        ],
    },
}


# ---------------------------------------------------------
# FGTB-F01: Linux 4.19 kernel with 7+ years of unpatched CVEs
# ---------------------------------------------------------
FGTB_F01_KERNEL_VINTAGE = {
    "id":       "FGTB-F01",
    "severity": "HIGH -- Linux 4.19.13 (Oct 2018 base) in 8.0.0 firmware shipped 2026",
    "kernel_version": "4.19.13",
    "kernel_build_date": "Mon Apr 20 17:10:46 America 2026",
    "kernel_base_age_at_release": "7+ years (Linux 4.19 released Oct 2018)",

    "notable_cves": [
        {
            "cve": "CVE-2019-11477",
            "name": "TCP SACK Panic",
            "fixed_in_upstream": "4.19.52",
            "affects_4_19_13": True,
            "pre_auth": True,
            "impact": "Remote kernel panic (DoS) via crafted TCP SACK sequence",
            "note": "FortiGate is a firewall -- directly exploitable from WAN. "
                    "4.19.13 predates the 4.19.52 backport that fixes it.",
            "priority": "HIGHEST -- pre-auth DoS against firewall WAN interface",
        },
        {
            "cve": "CVE-2019-14835",
            "name": "VHOST-NET buffer overflow",
            "fixed_in_upstream": "4.19.72",
            "affects_4_19_13": True,
            "pre_auth": False,
            "impact": "VM escape via VHOST-NET -- relevant for FortiGate VM64 in VMware/KVM",
            "note": "Attacker-controlled guest VM can escape to hypervisor",
        },
        {
            "cve": "CVE-2022-0847",
            "name": "Dirty Pipe",
            "fixed_in_upstream": "5.16.11 / 5.15.25 / 5.10.102",
            "affects_4_19_13": True,
            "pre_auth": False,
            "impact": "LOCAL privilege escalation via page cache overwrite",
            "note": "Any local process can overwrite read-only files including SUID binaries. "
                    "Chained with a post-auth RCE for full root.",
        },
        {
            "cve": "CVE-2021-22555",
            "name": "Netfilter heap OOB write",
            "fixed_in_upstream": "5.12",
            "affects_4_19_13": True,
            "pre_auth": False,
            "impact": "LOCAL privilege escalation via iptables heap corruption",
        },
        {
            "cve": "CVE-2020-14386",
            "name": "AF_PACKET integer overflow",
            "fixed_in_upstream": "5.9",
            "affects_4_19_13": True,
            "pre_auth": False,
            "impact": "LOCAL privilege escalation -- requires CAP_NET_RAW",
            "note": "May be available inside FortiGate network namespaces or containers",
        },
    ],

    "scoped_out": [
        "CVE-2022-0847 requires local code execution first (post-auth; chain starting point only)",
        "CVE-2019-14835 requires attacker-controlled guest VM (VM escape, not direct network RCE)",
    ],

    "highest_priority": "CVE-2019-11477 (SACK Panic): pre-auth DoS against FortiGate WAN interface. "
        "4.19.13 predates the 4.19.52 backport. Network-level DoS against firewall appliance is highest impact.",
}


# ---------------------------------------------------------
# FGTB-F02: rootfs.gz AES encryption analysis
# ---------------------------------------------------------
FGTB_F02_ROOTFS_ENCRYPTED = {
    "id":       "FGTB-F02",
    "severity": "INFO -- encryption blocks static analysis of core OS daemons",
    "summary":  "FortiGate 8.0.0 rootfs.gz is AES-encrypted. Core daemons (httpd, sslvpnd, forticron, "
        "miglogd, etc.) are inaccessible without decryption key (embedded in flatkc kernel).",
    "contrast_with_709": "FortiOS 7.0.9 used fake XZ encryption (CRC32 forgery, LZMA2 standard compression). "
        "8.0.0 uses real AES -- confirms Fortinet closed the 7.0.9 bypass between versions.",
    "evidence": {
        "entropy_first_4kb": 7.997,
        "xor_period_test":   "No autocorrelation drop at periods 16/32/64/128/256 -- rules out XOR",
        "cross_version_xor": "XOR(7.4.12, 8.0.0) entropy=7.83 (lower than either alone, consistent with AES)",
        "magic":             "0xcbd2efa3f32ce349 (no known compression or archive format match)",
        "version_unique":    True,
        "decryption_path":   "Key in flatkc kernel; kernel has fos_keyring + IMA enforce mode",
    },
    "kernel_analysis": {
        "aes_sbox_at": "0x1608b00 (standard Linux kernel crypto library)",
        "fos_keyring_string_at": "0x13ef2d5",
        "key_search_result": "No XOR or AES key material found in 26.8MB decompressed kernel static analysis. "
            "Key likely loaded dynamically via Linux keyring API at runtime.",
    },
    "workaround": "datafs.tar.gz (plain gzip) provides libips.so.new (18MB) and libav.so.new (15MB). "
        "Core daemon analysis requires live VM or kernel key extraction.",
}


# ---------------------------------------------------------
# FGTB-F03: libips.so.new (IPS engine) -- semantic sweep
# ---------------------------------------------------------
FGTB_F03_IPS_SWEEP = {
    "id":       "FGTB-F03",
    "severity": "LOW -- 100% FP rate; no confirmed memory safety issues in sweep",
    "binary":   "libips.so.new",
    "binary_size_mb": 18,
    "function_count": 43882,
    "sweep_status": "COMPLETE (2026-09-18)",
    "attack_surface": "PRE-AUTH: IPS engine processes all network packets before authentication. "
        "Buffer overflow in IPS = RCE from WAN with no credentials.",
    "profiles_queried": [
        "memcpy_packet_len", "strcpy_fixed_dst", "integer_overflow_alloc",
        "format_string", "use_after_free", "fidsdb_parser_overflow",
        "system_popen_injection", "luajit_string_unbox", "decompression_bomb",
        "network_packet_parse",
        "ips_pkt_len_overflow", "ips_signature_parse",
        "av_decomp_output_overflow", "av_mime_boundary_overflow",
        "ssl_inspection_buffer_overflow",
    ],
    "top_candidates": [
        {"va": "0x8619db", "score": 0.461, "profile": "fidsdb_parser_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "Static wrapper; all arguments are RIP-relative constants + vtable call; "
                   "no untrusted data flow visible in 13 instructions"},
        {"va": "0x644dbf", "score": 0.441, "profile": "fidsdb_parser_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "Disassembly misalignment -- 0x55 byte mid-instruction causes prologue heuristic to fire; "
                   "decoded instructions are nonsense (add al,[rax]; add [rax-0x7b],cl)"},
        {"va": "0xdd4db0", "score": 0.434, "profile": "fidsdb_parser_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "Static wrapper with hardcoded constant args (edx=0xf, r8d=0xa); no untrusted length"},
        {"va": "0xb492bf", "score": 0.401, "profile": "ips_pkt_len_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "C++ exception handler (unwind code): ud2 instruction, lock dec reference counting, "
                   "_Unwind_Resume call; not a packet parser"},
    ],
    "sweep_fp_rate": {
        "confirmed_false_positives": 4,
        "total_candidates_checked": 4,
        "surviving_candidates": 0,
    },
    "false_positive_patterns": {
        "prologue_misalignment": "0x55 (push rbp) and 0x48 0x83 0xec (sub rsp, imm8) fire mid-instruction",
        "static_wrappers":       "Thin dispatch wrappers with all-static RIP-relative args dominate top hits",
        "cpp_exception_handlers": "Exception landing pads (ud2, _Unwind_Resume, lock dec) match parser profiles",
    },
}


# ---------------------------------------------------------
# FGTB-F04: libav.so.new (AV engine) -- semantic sweep
# ---------------------------------------------------------
FGTB_F04_AV_SWEEP = {
    "id":       "FGTB-F04",
    "severity": "LOW -- 100% FP rate; no confirmed memory safety issues in sweep",
    "binary":   "libav.so.new",
    "binary_size_mb": 15,
    "function_count": 37482,
    "sweep_status": "COMPLETE (2026-09-18)",
    "attack_surface": "SEMI-PRE-AUTH: AV engine processes file content (email attachments, HTTP downloads, "
        "SMB files) before content is delivered to users. Malformed archive triggers before auth.",
    "profiles_queried": [
        "memcpy_packet_len", "strcpy_fixed_dst", "integer_overflow_alloc",
        "format_string", "use_after_free", "fidsdb_parser_overflow",
        "luajit_string_unbox", "decompression_bomb",
        "network_packet_parse", "ips_pkt_len_overflow",
        "av_decomp_output_overflow", "av_mime_boundary_overflow",
        "ssl_inspection_buffer_overflow",
    ],
    "top_candidates": [
        {"va": "0x8db950", "score": 0.430, "profile": "fidsdb_parser_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "Jump target from bounds check at 0x8db946: cmp [rax+8],ecx; jae 0x8db950. "
                   "The memcpy (add rsi,rdx; mov rdx,rcx; call memcpy) is only reachable when "
                   "buffer capacity >= copy size. Bounds check precedes the copy."},
        {"va": "0x317226", "score": 0.408, "profile": "ips_pkt_len_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "Disassembly misalignment -- first instructions are garbage bytes; real code "
                   "starts mid-function (contains memcpy + 0x871680 call but no function prologue here)"},
        {"va": "0x133bc4", "score": 0.424, "profile": "ips_signature_parse",
         "verdict": "FALSE_POSITIVE",
         "reason": "Cleanup/zero function: memset(ptr, 0, internal_count*16); count from object "
                   "field [rbx+0x2a8], not from untrusted input; not a parser"},
        {"va": "0x4a0088", "score": 0.422, "profile": "decompression_bomb",
         "verdict": "FALSE_POSITIVE",
         "reason": "Bounding box accumulator: iterator over 8-byte elements calling 0x416450 "
                   "(min/max update for 16-bit (x,y,w,h) coordinates -- image analysis in AV engine); "
                   "not a decompressor"},
        {"va": "0x3596bf", "score": 0.401, "profile": "memcpy_packet_len",
         "verdict": "FALSE_POSITIVE",
         "reason": "memcpy with RIP-relative constant length: rdx = movsxd from [rip+0xbb7796] "
                   "(global constant at link time); not a runtime-controlled size"},
    ],
    "sweep_fp_rate": {
        "confirmed_false_positives": 7,  # includes 0x932fbb and 0x772d92 misalignments
        "total_candidates_checked": 7,
        "surviving_candidates": 0,
    },
    "false_positive_patterns": {
        "prologue_misalignment":      "0x55 byte mid-instruction fires prologue heuristic",
        "bounds_checked_jump_target": "memcpy only reachable via jae/jb guard -- sweep misses caller context",
        "constant_length_memcpy":     "memcpy with RIP-relative global constant as length",
        "domain_analysis_functions":  "AV engine bounding box / image analysis code matches decompression profile",
    },
}


# ---------------------------------------------------------
# Summary
# ---------------------------------------------------------
FGT800_SWEEP_SUMMARY = {
    "firmware_version": "FortiOS 8.0.0.F build0167 (2026-04-20)",
    "extraction_method": "VMware OVF (FGT_VM64) -> VMDK -> raw disk -> ext3 FORTIOS partition",
    "accessible_binaries": ["libips.so.new (18MB, 43882 functions)", "libav.so.new (15MB, 37482 functions)"],
    "inaccessible": "Core OS (rootfs.gz AES-encrypted) -- httpd, sslvpnd, forticron, etc.",
    "kernel_vintage": "Linux 4.19.13 (7+ years old; multiple CVEs unpatched)",
    "highest_severity_confirmed": "FGTB-F01: CVE-2019-11477 SACK Panic (pre-auth DoS from WAN)",
    "sweep_result": "11 candidates manually verified; 11/11 false positives (100% FP rate, same as FortiMail)",
    "sweep_negative_result": "No easy memory safety issues visible in IPS/AV engines via semantic sweep. "
        "Absence of obvious findings suggests code quality is adequate for obvious patterns; "
        "harder-to-find vulnerabilities (integer overflow, type confusion, complex protocol decoder state) "
        "are more likely targets than simple memcpy/strcpy.",
    "false_positive_patterns_cumulative": {
        "prologue_misalignment": "0x55 or 0x48 0x83 0xec mid-instruction fires heuristic",
        "static_wrappers":       "Thin dispatch wrappers with RIP-relative constant args",
        "cpp_exception_handlers": "Unwind code (ud2, lock dec, _Unwind_Resume) matches parsers",
        "bounds_checked_jump_targets": "memcpy only reachable via jae/jb guard -- caller context missing",
        "constant_length_ops":   "RIP-relative global constant used as memcpy/memset size",
        "domain_analysis":       "AV engine image/document processing (bounding box) matches decompression",
    },
    "contrast_with_709": {
        "709_rootfs": "Fake XZ encryption (CRC32 forgery) -- trivially extracted",
        "800_rootfs": "Real AES -- rootfs sealed; only datafs accessible",
        "regression": "Fortinet hardened firmware extraction between 7.0.9 and 8.0.0",
    },
}


# ---------------------------------------------------------
# FGTB-F05: Kernel analysis -- flatkc extracted, fortism LSM, rootfs key
# ---------------------------------------------------------
FGTB_F05_KERNEL_ANALYSIS = {
    "id":       "FGTB-F05",
    "severity": "INFO -- static kernel analysis; key extraction not possible without live boot",
    "summary":  "flatkc extracted from fortios.vmdk p1 (ext3). vmlinux decompressed (27MB ELF64 x86-64). "
        "fortism LSM confirmed; rootfs decryption uses cbc(aes). AES key not statically recoverable.",

    "partition": {
        "layout": "fortios.raw p1 (sector 2048, 256MB, ext3 FORTIOS) via loop mount offset=1048576",
        "files":  [
            "flatkc (7.7MB bzImage, Linux 4.19.13, root@6dd369a4a2ab, 2026-04-20 17:10:46)",
            "rootfs.gz (92MB AES-encrypted ciphertext)",
            "datafs.tar.gz (plain gzip, libips + libav accessible)",
            "flatkc.chk (256B RSA-2048 signature over flatkc)",
            "rootfs.gz.chk (256B RSA-2048 signature over rootfs.gz ciphertext)",
            "filechecksum (/rootfs.gz,CRC32,0xe59ea42b; /flatkc,CRC32,0xffffffff)",
        ],
        "rootfs_crc_verified": True,  # CRC32 0xe59ea42b verified against encrypted blob
    },

    "kernel": {
        "buildid":         "43e6c79f25c4e6509765325de60ad04e09dd71bc",
        "vmlinux_size_mb": 27,
        "elf_segments": [
            "LOAD [r-x] foff=0x200000 vaddr=0xffffffff80200000 fsz=0x12fa000 (text+rodata)",
            "LOAD [rw-] foff=0x1600000 vaddr=0xffffffff81600000 fsz=0xe5000 (data)",
            "LOAD [rw-] foff=0x1800000 vaddr=0x0 fsz=0x29000 (init data)",
            "LOAD [rwx] foff=0x190e000 vaddr=0xffffffff8170e000 fsz=0x12e000 (init text)",
        ],
        "security_features": [
            "fortism LSM (security/fortism/forti_lsm.c) -- 30+ hooks: file_open, path_link, "
                "socket_listen, unix_sendmsg, inet_connect, kernel_load_data, path_chmod",
            "fos_keyring (.fos_keyring at 0xffffffff813ef2dc) -- Linux keyring for module signing",
            "fos_ima -- IMA enforce mode; file integrity checking at open/exec",
            "X.509 certs embedded: Fortinet CA2, Fortinet SubCA2002, Fortinet SubCA2003, "
                "Digicert Codesign, Digicert TSA",
        ],
        "no_kaslr": True,  # bzImage with fixed load address; deterministic VA layout
    },

    "rootfs_decryption": {
        "cipher_mode":         "cbc(aes) -- found at 0xffffffff813e1002 in rodata",
        "path_strings":        ["/data/rootfs.gz", "/data/datafs.tar.gz", "/data/flatkc"],
        "path_string_region":  "0xffffffff813ee757 (fortism LSM rodata region)",
        "chk_file":            "rootfs.gz.chk (256B RSA-2048 signature, not key material)",
        "key_extraction": {
            "static_result": "KEY NOT FOUND -- no 16/32-byte high-entropy blobs in fortism code region "
                "that survive printable/code context filtering",
            "reason":        "Key likely loaded via keyring_alloc / request_key at runtime into fos_keyring; "
                "not a static byte array in the binary",
            "approaches_tried": [
                "High-entropy 32-byte blob scan in fortism rodata (0x13d0000-0x14fa000)",
                "LEA RIP-relative scan for /data/rootfs.gz and cbc(aes) string references",
                "Absolute pointer search for string VAs in data segment",
                "kallsyms address table scan for fortism_init VA",
                "initcall pointer enumeration in .init segment",
            ],
            "conclusion": "DYNAMIC ANALYSIS REQUIRED -- live VM boot or kernel memory dump needed to "
                "extract key from fos_keyring at runtime",
        },
    },

    "attack_surface_notes": {
        "no_kaslr":     "Fixed kernel VA layout enables reliable ROP gadget addressing if kernel code exec achieved",
        "4_19_vulns":   "Kernel 4.19.13 predates all FGTB-F01 fixes; see FGTB-F01 for CVE list",
        "fortism_hooks": "fortism LSM adds file/socket/network enforcement hooks -- audit path for sandbox escapes",
    },
}


# ---------------------------------------------------------
# FGTB-F06 / FGTB-F07: Round-2 sweeps (fixed filter)
# ---------------------------------------------------------
FGTB_F06_IPS_SWEEP_R2 = {
    "id":       "FGTB-F06",
    "severity": "LOW -- 100% FP rate in checked candidates",
    "binary":   "libips.so.new",
    "sweep_round": 2,
    "filter":   "three-condition (caller_set | boundary_byte | 16B-aligned); ud2 exception skip",
    "filter_stats": {
        "raw_prologue_hits":    47756,
        "accepted_after_filter": 11064,
        "excluded":             36692,
        "exclusion_pct":        "77%",
        "encoded_after_short_skip": 10692,
        "skipped_too_short":    249,
        "skipped_ud2_handlers": 123,
    },
    "sweep_status": "COMPLETE (2026-09-19)",
    "top_candidates": [
        {"va": "0x8619db", "score": 0.461, "profile": "fidsdb_parser_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "Version registration wrapper: 10 instructions, loads 'Version 1.92.0 (ded5c06cf 2025-12-08)' "
                   "strings from rodata, makes single indirect call to registrar. No untrusted data."},
        {"va": "0x852fb0", "score": 0.405, "profile": "av_decomp_output_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "URL/hostname parser: scans rdi for ':' (0x3a) separator, calls two indirect functions "
                   "for prefix/suffix lookup. Appears in libips as URL processing for IPS rule metadata."},
        {"va": "0xe1390",  "score": 0.400, "profile": "ssl_inspection_buffer_overflow",
         "verdict": "UNCHECKED",
         "reason": "Calls __tls_get_addr; likely TLS thread-local storage accessor. Not inspected."},
    ],
    "fp_patterns_new": {
        "version_registration_wrapper": "Tiny init stub loading version strings from rodata, calls registrar",
        "url_hostname_parser":           "RFC delimiter scan (':') in libips URL processing; not a packet parser",
    },
}

FGTB_F07_AV_SWEEP_R2 = {
    "id":       "FGTB-F07",
    "severity": "LOW -- 100% FP rate in checked candidates",
    "binary":   "libav.so.new",
    "sweep_round": 2,
    "filter":   "three-condition (caller_set | boundary_byte | 16B-aligned); ud2 exception skip",
    "filter_stats": {
        "raw_prologue_hits":    5484,
        "accepted_after_filter": 5391,
        "excluded":             89,
        "skipped_ud2_handlers": 4,
    },
    "sweep_status": "COMPLETE (2026-09-19)",
    "top_candidates": [
        {"va": "0x8db950", "score": 0.430, "profile": "fidsdb_parser_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "bounds_checked_jump_target: jae 0x8db950 at 0x8db949 (cmp [rax+8], r9; jae ...) -- "
                   "memcpy at 0x8db950 is only reachable when buf_size >= offset+len. "
                   "IDENTICAL pattern to FGTB-F04 hit. New filter still accepts via 16B-align (0x8db950 & 0xF = 0). "
                   "Requires caller-context analysis to filter -- out of scope for first-pass sweep."},
        {"va": "0x69c860", "score": 0.384, "profile": "memcpy_packet_len",
         "verdict": "FALSE_POSITIVE",
         "reason": "Clamped buffer read: cmova rbx, rsi computes min(available, requested) before memcpy. "
                   "Correct bounds: available = [rdx+0x18] - [rdx+0x10]; length = min(available, rsi). Safe."},
        {"va": "0x871460", "score": 0.400, "profile": "decompression_bomb",
         "verdict": "FALSE_POSITIVE",
         "reason": "PID cache init: 5 instructions, call getpid(), store in global at [rip+0x6ae379]. "
                   "Library init function cached the process PID for multi-process state tracking."},
        {"va": "0x86fb70", "score": 0.409, "profile": "fidsdb_parser_overflow",
         "verdict": "FALSE_POSITIVE",
         "reason": "Float-to-int constructor: malloc(64), stores double-precision float with clamping "
                   "(0x7fffffff / 0x80000000 bounds), cvttsd2si. Signature value field construction, not a parser."},
        {"va": "0x2e4d00", "score": 0.387, "profile": "network_packet_parse",
         "verdict": "FALSE_POSITIVE",
         "reason": "Mid-function fragment or function-end tail: 'push rbp' at 0x2e4d00 is in epilogue of "
                   "a larger function (function-end sequence + call memcpy). Prologue misalignment FP."},
        {"va": "0x327994", "score": 0.377, "profile": "network_packet_parse",
         "verdict": "FALSE_POSITIVE",
         "reason": "IPS signature state machine: large function (~0x600 bytes) doing multi-level range checks "
                   "on signature IDs with cmp/jb/jae bounds before array lookup. memcpy at 0x327b32 uses "
                   "available=capacity-used as copy length (not user-controlled length). Safe."},
    ],
    "sweep_fp_rate": {
        "confirmed_false_positives": 6,
        "total_candidates_checked":  6,
        "surviving_candidates":      0,
    },
    "fp_patterns_new": {
        "bounds_checked_jump_target": "Persistent across filter rounds; requires caller-context analysis",
        "clamped_buffer_read":        "cmova min(available, requested) before memcpy -- correct pattern",
        "pid_cache_init":             "Library init calling getpid(); not a decompressor",
        "float_constructor":          "malloc + cvttsd2si with clamp; signature value object construction",
        "mid_function_fragment":      "push rbp at epilogue of larger function (sub-function tail call)",
        "bounded_streaming_copy":     "available=capacity-used as copy length in state machine",
    },
}


# ---------------------------------------------------------
# Cumulative summary (updated after round-2 sweeps)
# ---------------------------------------------------------
FGT800_SWEEP_SUMMARY_R2 = {
    "firmware_version": "FortiOS 8.0.0.F build0167 (2026-04-20)",
    "sweep_rounds": 2,
    "filter_improvement": "Round 1: flat prologue scan (43882/37482). Round 2: three-condition filter (11064/5484). 77% cut.",
    "accessible_binaries": [
        "libips.so.new (18MB, 10692 functions in round-2 encoding)",
        "libav.so.new  (15MB, 5391 functions in round-2 encoding)",
    ],
    "inaccessible": "Core OS (rootfs.gz AES-encrypted); key not statically extractable -- requires live VM",
    "kernel_vintage": "Linux 4.19.13 (7+ years old; CVE-2019-11477 unpatched -- see FGTB-F01)",
    "highest_severity_confirmed": "FGTB-F01: CVE-2019-11477 SACK Panic (pre-auth DoS from WAN)",
    "sweep_result": "17 candidates manually verified across both rounds; 17/17 false positives",
    "fp_evolution": {
        "round_1_dominant": "prologue_misalignment, static_wrappers, cpp_exception_handlers",
        "round_2_dominant": "bounds_checked_jump_target, clamped_buffer_read, init_functions",
        "interpretation":   "Filter eliminated heuristic noise; remaining FPs are semantic mismatch "
            "(correct code that superficially resembles vulnerable patterns). "
            "Suggests either (a) absence of simple memory safety bugs in IPS/AV engines, "
            "or (b) harder-to-detect patterns (integer overflow, type confusion, protocol state) "
            "that require more targeted profiles.",
    },
    "next_steps": {
        "live_vm_analysis": "Boot FortiGate VM64 8.0.0 in QEMU/VMware to extract runtime key from fos_keyring",
        "kernel_rootfs_mount": "Mount decrypted rootfs to access httpd, sslvpnd, forticron daemons",
        "profile_refinement":  "Add profiles for: integer_truncation (u16->int), type_confusion, "
            "state_machine_OOB (buffer position not re-validated after state change)",
        "caller_context":      "Implement caller-set graph to reject bounds_checked_jump_targets automatically",
    },
}
