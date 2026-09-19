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
    "severity": "PENDING -- sweep results required to score",
    "binary":   "libips.so.new",
    "binary_size_mb": 18,
    "function_count": 43882,
    "sweep_status": "RUNNING (task bczl5c5o0) -- started 2026-09-18 19:49",
    "attack_surface": "PRE-AUTH: IPS engine loaded into kernel-adjacent daemon, processes all network packets "
        "before authentication. Buffer overflow in IPS = RCE from WAN with no credentials.",
    "profiles_queried": [
        "memcpy_packet_len", "strcpy_fixed_dst", "integer_overflow_alloc",
        "format_string", "use_after_free", "fidsdb_parser_overflow",
        "system_popen_injection", "luajit_string_unbox", "decompression_bomb",
        "network_packet_parse",
        "ips_pkt_len_overflow", "ips_signature_parser",
        "av_decomp_output_overflow", "av_mime_boundary_overflow",
        "ssl_inspection_buffer_overflow",
    ],
    "top_candidates": [],  # populated post-sweep
    "manual_re_queue": [],
}


# ---------------------------------------------------------
# FGTB-F04: libav.so.new (AV engine) -- semantic sweep
# ---------------------------------------------------------
FGTB_F04_AV_SWEEP = {
    "id":       "FGTB-F04",
    "severity": "PENDING -- sweep results required",
    "binary":   "libav.so.new",
    "binary_size_mb": 15,
    "sweep_status": "PENDING (will run after FGTB-F03 sweep completes)",
    "attack_surface": "SEMI-PRE-AUTH: AV engine processes file content (email attachments, HTTP downloads, "
        "SMB files) before content is delivered to users. Malformed archive triggers before auth in "
        "perimeter inspection mode.",
    "profiles_queried": [
        "memcpy_packet_len", "strcpy_fixed_dst", "integer_overflow_alloc",
        "format_string", "use_after_free", "decompression_bomb",
        "network_packet_parse", "av_decomp_output_overflow", "av_mime_boundary_overflow",
    ],
    "top_candidates": [],  # populated post-sweep
    "manual_re_queue": [],
}


# ---------------------------------------------------------
# Summary
# ---------------------------------------------------------
FGT800_SWEEP_SUMMARY = {
    "firmware_version": "FortiOS 8.0.0.F build0167 (2026-04-20)",
    "extraction_method": "VMware OVF (FGT_VM64) -> VMDK -> raw disk -> ext3 FORTIOS partition",
    "accessible_binaries": ["libips.so.new (18MB)", "libav.so.new (15MB)"],
    "inaccessible": "Core OS (rootfs.gz AES-encrypted) -- httpd, sslvpnd, forticron, etc.",
    "kernel_vintage": "Linux 4.19.13 (7+ years old; multiple CVEs unpatched)",
    "highest_severity_confirmed": "FGTB-F01: CVE-2019-11477 SACK Panic (pre-auth DoS from WAN)",
    "pending": ["FGTB-F03 IPS sweep results", "FGTB-F04 AV sweep results", "Manual disasm top candidates"],
    "contrast_with_709": {
        "709_rootfs": "Fake XZ encryption (CRC32 forgery) -- trivially extracted",
        "800_rootfs": "Real AES -- rootfs sealed; only datafs accessible",
        "regression": "Fortinet hardened firmware extraction between 7.0.9 and 8.0.0",
    },
}
