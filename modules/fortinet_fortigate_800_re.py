"""
Fortinet FortiGate RE -- FortiOS 8.0.0.F build0167
Sources:
  - FGT_VM64-v8.0.0.F-build0167-FORTINET.out.ovf.zip (2026-04-20)
  - FGT_7000F-v8.0.0.F-build0167-FORTINET.zip (bare-metal, AES-encrypted rootfs -- not extracted)
  - Firmware: fortios.vmdk -> fortios.raw, partition 1 (ext3 label=FORTIOS, SYSLINUX boot)
  - Kernel: flatkc (bzImage, Linux 4.19.13, FortiOS IMA enforce mode, fos_keyring)
  - rootfs.gz: AES-encrypted (device-specific key in kernel); not extractable without hardware
  - datafs.tar.gz: plain gzip, ~46MB expanded; lib/ + etc/ contents
  - Semantic sweep: libips.so.new (43882 functions), libav.so.new (TBD)
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
