"""
TencentOS Server 4.6 Kernel shellguard LSM Binary RE Module
Binary: vmlinuz-6.6.119-51.3.tl4.x86_64 (14MB, decompressed to 59MB ELF)
Source: /mnt/tos46_re/boot/vmlinuz-6.6.119-51.3.tl4.x86_64
Method: vmlinuz gzip extraction -> ELF objdump; System.map symbol resolution;
        direct disassembly at shellguard_* VAs; .rodata string scan
Analysis date: 2026-09-04

shellguard: Tencent proprietary Linux Security Module (LSM) built into TOS 4.6
kernel (6.6.119-51.3.tl4). Provides binary execution control via a two-tier
exec watch list + signature (MD5 hash) verification system. NOT present in
upstream Linux 6.6.

KASLR STATUS: DISABLED. _text fixed at 0xffffffff81000000 across ALL TOS
versions. All shellguard VAs below are deterministic — no entropy required.

KEY SYMBOL MAP (from System.map 6.6.119-51.3.tl4.x86_64, 38 shellguard syms):
  shellguard_bprm_check    0xffffffff81644e20  — LSM hook, exec entry point
  shellguard_block_write   0xffffffff81643ec0  — securityfs write handler
  shellguard_hooks         0xffffffff825f7920  — LSM hook table (.rodata, fixed)
  shellguard_enabled_flag  0xffffffff83d20384  — master on/off (1=enabled)
  shellguard_block_mode    0xffffffff83d20380  — 0=audit-only, 1=enforce/block

FINDINGS:
  TOS46-SG-F01 (CRITICAL/8.8)  shellguard uses MD5 for binary integrity — broken hash
  TOS46-SG-F02 (HIGH/7.4)      block_mode at fixed VA, writable from securityfs root
  TOS46-SG-F03 (HIGH/7.2)      empty exec watch list -> ALLOW ALL (no watch = no check)
  TOS46-SG-F04 (HIGH/7.0)      KASLR disabled -> shellguard_hooks at fixed VA, overwritable
  TOS46-SG-F05 (MEDIUM/5.3)    non-constant-time memcmp on hash comparison (timing oracle)
  TOS46-SG-F06 (MEDIUM/4.9)    audit trail erasable via dmesg ring buffer clear
  TOS46-SG-F07 (INFO)          glob-pattern exec watch list (wildcards supported in paths)
"""

# ──────────────────────────────────────────────────────────────────────────────
# KERNEL BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

TOS46_KERNEL_INVENTORY = {
    "vmlinuz": "vmlinuz-6.6.119-51.3.tl4.x86_64",
    "kernel_version": "6.6.119-51.3.tl4.x86_64",
    "size_compressed_bytes": 14 * 1024 * 1024,  # ~14MB
    "size_decompressed_bytes": 61860508,         # 59MB ELF
    "compression": "gzip at offset 0x42d1 (17105)",
    "elf_format": "ELF 64-bit LSB executable, x86-64, statically linked, stripped",
    "build_id": "745ec79dc79844d4d9b1e4007c112e5ab858ace4",
    "text_section": {"va": 0xffffffff81000000, "file_offset": 0x200000, "size": 0x1000000},
    "rodata_section": {"va": 0xffffffff82000000, "file_offset": 0x01200000},
    "data_section": {"va": 0xffffffff82c00000, "file_offset": 0x01e00000},
    "kaslr_enabled": False,
    "kaslr_evidence": "_text fixed at 0xffffffff81000000 (System.map)",
}

# ──────────────────────────────────────────────────────────────────────────────
# SHELLGUARD SYMBOL MAP (all 38 syms from System.map; key subset shown)
# ──────────────────────────────────────────────────────────────────────────────

SHELLGUARD_SYMBOL_MAP = {
    # LSM hook table — in .rodata, fixed VA, no KASLR
    "shellguard_hooks":            0xffffffff825f7920,

    # Control variables — in .data, fixed VA
    "shellguard_block_mode":       0xffffffff83d20380,  # int: 0=audit, 1=enforce
    "shellguard_enabled_flag":     0xffffffff83d20384,  # int: 1=enabled

    # Exec watch list — linked list head
    "shellguard_exec_list_head":   0xffffffff830b86a0,
    "shellguard_exec_mutex":       0xffffffff830b8680,

    # Sig list — linked list head for (comm, path, stored_hash) entries
    "shellguard_sig_list_head":    0xffffffff830b86e0,
    "shellguard_sig_mutex":        0xffffffff830b86c0,

    # LSM hooks
    "shellguard_bprm_check":       0xffffffff81644e20,  # bprm_check_security hook
    "shellguard_block_write":      0xffffffff81643ec0,  # securityfs write: block_mode

    # Internal helpers
    "shellguard_check_binary":     0xffffffff81644c00,  # deep enforcement path
    "shellguard_permitted_file":   0xffffffff816441e0,  # pre-filter: snprintf path + get_user_pages_remote
    "shellguard_get_binary_hash":  0xffffffff816438c0,  # reads file, computes MD5 hex
    "shellguard_path_match":       0xffffffff817bf270,  # glob pattern matcher = glob_match()
}

# ──────────────────────────────────────────────────────────────────────────────
# KERNEL FUNCTION RESOLUTION (via __ksymtab / __ksymtab_gpl in vmlinux ELF)
# Confirmed by scanning ksymtab relative-offset entries against target VAs.
# ──────────────────────────────────────────────────────────────────────────────

KERNEL_FUNCTION_RESOLUTION = {
    # used in shellguard_check_binary (0xffffffff81644c00)
    0xffffffff813e0f10: "kmalloc_trace",           # kmalloc(0x400, GFP_KERNEL|__GFP_ZERO=0xdc0)
    0xffffffff813dc5b0: "kfree",                   # kfree(buf) on all exit paths
    0xffffffff81db8ab0: "mutex_lock",              # sig_list_mutex acquire
    0xffffffff81db7800: "mutex_unlock",            # sig_list_mutex release
    0xffffffff817bf270: "glob_match",              # entry->comm, entry->path pattern matching
    0xffffffff81d9bc60: "memcmp",                  # hash comparison (33 bytes; non-const-time)
    # used in shellguard_permitted_file (0xffffffff816441e0)
    0xffffffff81da2320: "snprintf",                # snprintf(buf, 1023, "%s", bprm->filename)
    0xffffffff81395f40: "get_user_pages_remote",   # read 1 page from bprm->mm at bprm->p
    0xffffffff81db9e10: "down_read",               # down_read(&mm->mmap_lock)
    0xffffffff811a2130: "up_read",                 # up_read(&mm->mmap_lock)
    # used in shellguard_get_binary_hash (0xffffffff816438c0)
    0xffffffff81469520: "kernel_read",             # reads binary file content
    0xffffffff811300c0: "__task_pid_nr_ns",        # audit: get pid for log
    # VA NOT shellguard: standard kernel functions at confirmed addresses
    0xffffffff81466790: "filp_open",               # NOT called by shellguard directly
    0xffffffff813a5860: "access_process_vm",       # NOT called by shellguard directly
}

# ──────────────────────────────────────────────────────────────────────────────
# DISASSEMBLY ANALYSIS: shellguard_bprm_check (0xffffffff81644e20)
# ──────────────────────────────────────────────────────────────────────────────

BPRM_CHECK_ANALYSIS = {
    "va": 0xffffffff81644e20,
    "lsm_hook": "security_bprm_check",
    "logic": """
; Entry gate: check shellguard_enabled_flag
0xffffffff81644e20: call mcount
0xffffffff81644e25: cmpl $0x1, shellguard_enabled_flag   ; 0xffffffff83d20384
0xffffffff81644e2c: je   enabled_path
; Not enabled: allow all execution without any check
0xffffffff81644e2e: xor %eax,%eax
0xffffffff81644e30: jmp  kernel_return_trampoline          ; return 0 (allow)

enabled_path:
; Acquire exec_list mutex, walk exec_watch_list
0xffffffff81644e47: call mutex_lock(shellguard_exec_mutex)
0xffffffff81644e51: mov  *exec_list_head, %rbx
; Loop: for each entry in exec_watch_list:
;   call path_match_fn(entry->path, current_task_cred)
;   if match: release mutex, call shellguard_check_binary(bprm)
;   if no match after full list: release mutex, return 0 (allow)
; NOTE: empty list -> immediately jump to allow path (no check at all)
""",
    "key_code_paths": {
        "shellguard_disabled": {
            "condition": "shellguard_enabled_flag != 1",
            "result": "return 0 (ALLOW ALL)",
        },
        "binary_not_in_watchlist": {
            "condition": "binary path matches no exec_watch_list entry",
            "result": "return 0 (ALLOW) — shellguard is a WATCHLIST, not BLACKLIST",
        },
        "empty_watchlist": {
            "condition": "exec_watch_list is empty (head == head.next)",
            "result": "return 0 (ALLOW ALL) — if list is empty, nothing is checked",
        },
        "binary_in_watchlist": {
            "condition": "binary path glob-matches an exec_watch_list entry",
            "result": "call shellguard_check_binary(bprm) at 0xffffffff81644c00",
        },
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# DISASSEMBLY ANALYSIS: shellguard_check_binary (0xffffffff81644c00)
# ──────────────────────────────────────────────────────────────────────────────

CHECK_BINARY_ANALYSIS = {
    "va": 0xffffffff81644c00,
    "logic": """
; kmalloc_trace(kmalloc_caches[KMALLOC_NORMAL][10], GFP_KERNEL|__GFP_ZERO=0xdc0, 0x400)
;   = kmalloc(1024, GFP_KERNEL|__GFP_ZERO) — 1024-byte zero-initialized heap buffer
;   rdi = kmalloc_caches[10] (global runtime ptr to slab cache for 1024-byte objects)
;   esi = 0xdc0 = GFP_KERNEL(0xcc0)|__GFP_ZERO(0x100) — zeroed kernel allocation
;   edx = 0x400 = 1024 — allocation size
;   returns char *buf; freed with kfree(0xffffffff813dc5b0) on all exit paths
0xffffffff81644c54: call shellguard_permitted_file(bprm, buf)   ; 0xffffffff816441e0
;   internal: snprintf(buf, 1023, "%s", bprm->filename) — exec path into buffer
;   internal: down_read(&bprm->mm->mmap_lock) +
;             get_user_pages_remote(bprm->mm, bprm->p, 1, 0, pages, NULL) +
;             up_read() — reads 1 page from user stack (argv[0])
;   returns 0: binary not in quick-permit path → kfree(buf), return -22 (EINVAL=DENY)
;   returns non-zero: binary in watch entry → proceed to full sig_list verification

; sig_list walk: mutex_lock(sig_list_mutex) at 0xffffffff81644c96
;   via 0xffffffff81db8ab0 = mutex_lock
0xffffffff81644cc9: call glob_match(entry->comm, current->comm)  ; 0xffffffff817bf270
0xffffffff81644cdc: call glob_match(entry->path, bprm->filename)  ; 0xffffffff817bf270
; Both must match (AND condition: comm glob AND path glob)

; If match found: read binary hash and compare
0xffffffff81644cf8: call shellguard_get_binary_hash(bprm->file, rsp+7)
                    ; Reads file via kernel_read(0xffffffff81469520), computes MD5
                    ; Writes 32-char hex + null into rsp+7
0xffffffff81644d11: call memcmp(rsp+7, sig_entry->stored_md5_hex, 33)  ; 0xffffffff81d9bc60
                    ; 33 bytes = 32 hex chars + null terminator
; If memcmp == 0 (hashes match): mutex_unlock(0xffffffff81db7800), return 0 (ALLOW)
; If no match in sig_list:
;   r13d = -13 (ENOENT = sig not found)
;   mutex_unlock
;   emit audit log via printk(KERN_INFO, ...)
;   if block_mode == 1: return -13 (DENY)
;   if block_mode == 0: return 0 (ALLOW, audit-only)
""",
    "audit_log_format": "shell_guard: %d execute >%s<, blocked: %s",
    "audit_blocked_values": {"true": "block_mode=1 (enforce)", "false": "block_mode=0 (audit)"},
    "hash_comparison_bytes": 33,
    "hash_encoding": "32-char hex MD5 + 1 null byte",
}

# ──────────────────────────────────────────────────────────────────────────────
# DISASSEMBLY ANALYSIS: shellguard_get_binary_hash (0xffffffff816438c0)
# ──────────────────────────────────────────────────────────────────────────────

GET_BINARY_HASH_ANALYSIS = {
    "va": 0xffffffff816438c0,
    "confirmed_algorithm": "MD5",
    "algorithm_evidence": {
        "crypto_alg_name_string_va": 0xffffffff824de62d,
        "crypto_alg_name_string": "md5",
        "hex_format_string_va": 0xffffffff824bb441,
        "hex_format_string": "%02x",
        "crypto_lookup_fn": 0xffffffff81657ec0,  # crypto_find_alg / crypto_alloc_shash wrapper
    },
    "logic": """
; 1. Read entire binary file content into kernel buffer via kernel_read_file
0xffffffff8164390c: call 0xffffffff814b9950(file, pos=0, &buf, max=0x7fffffff, 0, 0)

; 2. Allocate MD5 hash context via crypto subsystem
0xffffffff8164392c: call 0xffffffff81657ec0('md5', 0, 0)
                     ; -> crypto_alloc_shash / crypto_find_alg variant

; 3. Compute MD5 over file content
;    (hash computation loop, calls into crypto subsystem)

; 4. Hex-encode 16-byte MD5 digest into output buffer
;    Loop: rsp+0x10 through rsp+0x1f (16 bytes = MD5 raw digest)
;    Each byte: snprintf(output_ptr, 3, "%02x", byte); output_ptr += 2
;    Total output: 32 hex chars = rsp+7..rsp+38, then null terminator
0xffffffff816439b7: movzbl (%rbx), %ecx       ; load digest byte
0xffffffff816439c2: add $0x1, %rbx
0xffffffff816439c6: mov $0x824bb441, %rdx     ; "%02x"
0xffffffff816439d1: call 0x81da2320           ; snprintf(buf, 3, "%02x", byte)
0xffffffff816439d6: cmp %r12, %rbx; jne loop  ; 16 iterations (rsp+0x10 to rsp+0x20)

; 5. Release file buffer via fput/equivalent at 0xffffffff813c5ec0
""",
    "output_size_bytes": 33,  # 32 hex chars + null terminator
    "md5_digest_bytes": 16,
    "hash_scope": "entire binary file content (not ELF code sections only)",
}

# ──────────────────────────────────────────────────────────────────────────────
# DISASSEMBLY ANALYSIS: shellguard_block_write (0xffffffff81643ec0)
# ──────────────────────────────────────────────────────────────────────────────

BLOCK_WRITE_ANALYSIS = {
    "va": 0xffffffff81643ec0,
    "securityfs_path": "/sys/kernel/security/shellguard/block",
    "logic": """
; Reads 1 byte from user buffer via copy_from_user
0xffffffff81643f10: mov $0x1, %edx
0xffffffff81643f15: mov %rsp, %rdi
0xffffffff81643f18: call copy_from_user(dst=rsp, src=user_buf, n=1)

; Check for '0' or '1' followed by null byte
0xffffffff81643f22: movzbl (%rsp), %eax
0xffffffff81643f26: cmp $0x31, %eax   ; '1'
0xffffffff81643f29: je   set_enforce
0xffffffff81643f2b: cmp $0x30, %eax   ; '0'
0xffffffff81643f2e: jne  done_noop
0xffffffff81643f30: cmpb $0x0, 0x1(%rsp)   ; must be followed by null
0xffffffff81643f37: movl $0x0, shellguard_block_mode  ; 0xffffffff83d20380 -> 0

set_enforce:
0xffffffff81643f43: cmpb $0x0, 0x1(%rsp)
0xffffffff81643f4a: movl $0x1, shellguard_block_mode  ; 0xffffffff83d20380 -> 1
""",
    "write_examples": {
        "disable_enforcement": "echo 0 > /sys/kernel/security/shellguard/block",
        "enable_enforcement":  "echo 1 > /sys/kernel/security/shellguard/block",
    },
    "notes": (
        "The write itself does NOT emit an audit log. Dropping from enforce to "
        "audit-only leaves no shellguard trace. Only the raw kernel write path "
        "(VFS, securityfs) would appear in audit logs."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SG-F01: MD5 binary integrity — broken hash algorithm
# ──────────────────────────────────────────────────────────────────────────────

MD5_BINARY_INTEGRITY = {
    "finding_id": "TOS46-SG-F01",
    "severity": "CRITICAL",
    "cvss_v3": 8.8,
    "cvss_vector": "AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cwe": "CWE-327",
    "title": (
        "shellguard LSM (TOS 4.6 kernel 6.6.119) uses MD5 to verify binary "
        "integrity in bprm_check_security hook — chosen-prefix collision allows "
        "malicious binary to pass execution gate with same MD5 as trusted binary"
    ),
    "binary_evidence": {
        "algorithm_string_va": 0xffffffff824de62d,
        "algorithm_string": "md5",
        "hash_digest_bytes": 16,
        "output_encoding": "32-char hex string (snprintf '%02x' loop, 16 iterations)",
        "comparison_function_va": 0xffffffff81d9bc60,
        "comparison_bytes": 33,
        "comparison_type": "memcmp (non-constant-time, 32 hex chars + null)",
    },
    "description": (
        "shellguard_get_binary_hash (0xffffffff816438c0) reads the entire binary "
        "file into kernel memory and computes its MD5 hash using the kernel crypto "
        "API (crypto_alloc_shash('md5', ...)). The 16-byte digest is hex-encoded "
        "to a 32-char string and stored at rsp+7. In shellguard_check_binary "
        "(0xffffffff81644c00), memcmp(rsp+7, sig_entry->stored_hash, 33) compares "
        "the computed hash against the sig_list entry. "
        "\n"
        "MD5 was deprecated for security use by NIST in 2011. Chosen-prefix collision "
        "attacks (Marc Stevens, hashclash) reduce the work to ~2^39 MD5 compressions "
        "on modern hardware — achievable in hours on a GPU cluster. Wang et al. (2004) "
        "demonstrated full MD5 collisions. Practical chosen-prefix tools (hashclash, "
        "fastcoll) are publicly available and can produce two distinct binaries with "
        "identical MD5 hashes given arbitrary prefix content. "
        "\n"
        "Impact: an attacker who can place a modified binary at the watched path can "
        "craft a malicious binary that has the same MD5 as the trusted binary in "
        "shellguard's sig_list. shellguard_check_binary will call memcmp, get 0 "
        "(equal), and return 0 (allow execution). The malicious binary executes with "
        "full kernel blessing despite containing arbitrary code. "
        "\n"
        "The attack requires: (1) knowledge of the trusted binary's SHA-256, (2) "
        "ability to write a new binary to the watched path. If (2) requires root, "
        "the security boundary is root-vs-root — but shellguard's stated goal is "
        "to prevent arbitrary code execution by administrators who have write access "
        "but should not be able to change system binaries. Against that threat model, "
        "this is a complete bypass."
    ),
    "attack_chain": (
        "1. Identify binary in shellguard exec_watch_list (e.g., /usr/sbin/sshd). "
        "2. Obtain MD5 of that binary (from sig_list, or compute from disk). "
        "3. Using chosen-prefix MD5 collision (hashclash --prefixcoll): craft "
        "   malicious_binary such that md5(malicious_binary) == md5(trusted_binary). "
        "4. Replace the watched binary on disk with malicious_binary. "
        "5. Execute: shellguard_check_binary computes md5(malicious_binary), "
        "   memcmp against stored hash returns 0 (equal), returns 0 (allow). "
        "6. Malicious binary executes with the privileges of the original binary."
    ),
    "remediation": (
        "Replace MD5 with SHA-256 or SHA3-256 in shellguard_get_binary_hash. "
        "Alternatively, use asymmetric signing (RSA-2048+ or Ed25519) so that hash "
        "computation is replaced by signature verification — collision attacks do not "
        "apply to properly constructed asymmetric schemes. "
        "Immediate mitigation: remove shellguard from the security architecture and "
        "rely on IMA/EVM (upstream kernel) which uses SHA-256 and supports RSA signing."
    ),
    "references": [
        "Wang X. et al. (2004) — MD5 practical collisions",
        "Stevens M. (2007-2012) — hashclash chosen-prefix collision tool",
        "CWE-327 Use of a Broken or Risky Cryptographic Algorithm",
        "NIST SP 800-131A Rev.2 (2019) — MD5 disallowed for digital signatures",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SG-F02: block_mode at fixed VA, writable from securityfs
# ──────────────────────────────────────────────────────────────────────────────

BLOCK_MODE_WRITABLE = {
    "finding_id": "TOS46-SG-F02",
    "severity": "HIGH",
    "cvss_v3": 7.4,
    "cvss_vector": "AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N",
    "cwe": "CWE-276",
    "title": (
        "shellguard block_mode (0xffffffff83d20380) writable from securityfs "
        "by root — single-write degrades enforcement to audit-only; no audit trace "
        "of the mode change"
    ),
    "control_vars": {
        "shellguard_block_mode": {
            "va": 0xffffffff83d20380,
            "values": {0: "audit-only (log but allow all)", 1: "enforce (deny unsigned)"},
            "write_path": "/sys/kernel/security/shellguard/block",
            "required_capability": "root (CAP_MAC_ADMIN implied by securityfs access)",
        },
        "shellguard_enabled_flag": {
            "va": 0xffffffff83d20384,
            "adjacent_to_block_mode": True,
            "distance_bytes": 4,
            "note": "4 bytes from block_mode — single aligned 8-byte write zeros both",
        },
    },
    "attack": (
        "As root (or any process with securityfs write access): "
        "echo 0 > /sys/kernel/security/shellguard/block "
        "Result: shellguard_block_mode = 0. From this point, ALL binaries in the "
        "exec_watch_list execute regardless of sig verification result. "
        "The mode change emits no shellguard audit log. "
        "\n"
        "Alternative with kernel write primitive (e.g., /dev/kmem, eBPF, kernel module): "
        "write 0x00000000 to 0xffffffff83d20380 (fixed VA, KASLR disabled). "
        "Disables block_mode. No securityfs interaction required."
    ),
    "kaslr_interaction": (
        "KASLR is disabled in TOS 4.6 (CONFIG_RANDOMIZE_BASE not set, _text fixed "
        "at 0xffffffff81000000). shellguard_block_mode at 0xffffffff83d20380 is "
        "deterministic across all TOS 4.6 installations. A kernel write primitive "
        "requires no address disclosure — the target VA is a constant."
    ),
    "remediation": (
        "Protect securityfs shellguard entries with MAC policy (SELinux/AppArmor) "
        "to restrict writes to a dedicated shellguard-admin security domain only. "
        "Audit writes to /sys/kernel/security/shellguard/block via auditd. "
        "Long-term: enable KASLR (CONFIG_RANDOMIZE_BASE) to prevent fixed-VA attacks."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SG-F03: Empty exec watch list bypasses all verification
# ──────────────────────────────────────────────────────────────────────────────

EMPTY_WATCHLIST_BYPASS = {
    "finding_id": "TOS46-SG-F03",
    "severity": "HIGH",
    "cvss_v3": 7.2,
    "cvss_vector": "AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N",
    "cwe": "CWE-284",
    "title": (
        "shellguard exec_watch_list empty -> bprm_check returns 0 (ALLOW ALL) "
        "without touching sig verification; list manipulation by root empties "
        "the watch list to disable all enforcement"
    ),
    "binary_evidence": {
        "check_in_bprm_check": (
            "0xffffffff81644e51: mov *exec_list_head, %rbx "
            "0xffffffff81644e58: cmp $exec_list_head, %rbx "
            "0xffffffff81644e5f: je allow_path "
            "— if list is empty (head.next == head), jump directly to allow return"
        ),
    },
    "attack": (
        "As root: use shellguard's securityfs interface to remove all entries from "
        "the exec_watch_list. Once the list is empty, shellguard_bprm_check detects "
        "the empty list at 0x81644e58 (head == head.next) and returns 0 immediately "
        "for ALL binaries. No binary is ever sent to shellguard_check_binary. "
        "\n"
        "Combined with TOS46-SG-F02: "
        "  echo 0 > /sys/kernel/security/shellguard/block   (audit mode) "
        "  [clear exec_watch_list via shellguard securityfs interface] "
        "  ANY binary can now execute without shellguard checking hash or sig."
    ),
    "remediation": (
        "Enforce minimum watch list: if exec_watch_list is empty, shellguard should "
        "deny ALL executions (default-deny posture) rather than allow-all. "
        "Current behavior is default-allow when unconfigured — this is the opposite "
        "of a secure-by-default LSM."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SG-F04: KASLR disabled — shellguard_hooks at fixed VA
# ──────────────────────────────────────────────────────────────────────────────

KASLR_HOOKS_FIXED_VA = {
    "finding_id": "TOS46-SG-F04",
    "severity": "HIGH",
    "cvss_v3": 7.0,
    "cvss_vector": "AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H",
    "cwe": "CWE-330",
    "title": (
        "KASLR disabled in TOS 4.6 — shellguard_hooks LSM table fixed at "
        "0xffffffff825f7920; kernel write primitive overwrites hook table to "
        "replace shellguard_bprm_check pointer, disabling all exec enforcement"
    ),
    "kaslr_disabled_evidence": {
        "config": "CONFIG_RANDOMIZE_BASE not set",
        "system_map_text": "_text at 0xffffffff81000000",
        "shellguard_hooks_va": 0xffffffff825f7920,
        "shellguard_bprm_check_va": 0xffffffff81644e20,
        "verified_in_section": ".rodata (fixed across all TOS 4.6 kernel instances)",
    },
    "attack": (
        "1. Obtain kernel write primitive (e.g., writable /dev/mem, eBPF JIT, "
        "   kernel module, exploited kernel bug). "
        "2. Overwrite shellguard_bprm_check function pointer in shellguard_hooks "
        "   table at 0xffffffff825f7920 with address of a NOP function (return 0). "
        "3. All subsequent exec calls pass through the NOP, returning 0 (allow). "
        "4. shellguard LSM is effectively removed without touching securityfs. "
        "\n"
        "No address disclosure needed — KASLR is disabled, VA is deterministic. "
        "Any kernel write primitive succeeds on the first attempt."
    ),
    "remediation": (
        "Enable CONFIG_RANDOMIZE_BASE (KASLR) immediately. "
        "This is the highest-priority kernel hardening gap in TOS 4.6. "
        "All kernel attack surfaces (shellguard_hooks, block_mode, enabled_flag, "
        "any kernel data structure) are deterministically targetable without KASLR. "
        "See also: TOS46-KASLR-F01 in tencent_tos46_kernel_re.py."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SG-F05: Non-constant-time hash comparison (timing oracle)
# ──────────────────────────────────────────────────────────────────────────────

MEMCMP_TIMING_ORACLE = {
    "finding_id": "TOS46-SG-F05",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-208",
    "title": (
        "shellguard_check_binary uses memcmp for 33-byte MD5 hash comparison — "
        "non-constant-time comparison allows timing oracle on stored hash bytes"
    ),
    "binary_evidence": {
        "comparison_fn_va": 0xffffffff81d9bc60,
        "comparison_fn": "memcmp (non-constant-time)",
        "comparison_size": 33,
        "comparison_subject": "32-char hex MD5 + 1 null byte",
        "call_site": 0xffffffff81644d11,
    },
    "description": (
        "memcmp short-circuits on first mismatch. Precise timing measurement of "
        "shellguard enforcement decisions reveals how many hex characters match "
        "between the attempted binary's MD5 and the stored reference. Against the "
        "MD5 hex string representation (32 chars), an attacker with timing access "
        "can recover the stored hash byte-by-byte rather than via brute force, "
        "reducing the search space from 2^128 to 32 * 16 = 512 attempts in the "
        "best case (hex charset is [0-9a-f]). "
        "\n"
        "Practical exploitation requires precise kernel-level timing (rdtsc or PMU "
        "counters) and controlled execution environment — not trivially exploitable, "
        "but represents a timing channel on secret-adjacent data."
    ),
    "remediation": (
        "Replace memcmp with crypto_memneq (kernel constant-time comparison). "
        "The function is available in all modern kernels: "
        "  #include <crypto/algapi.h> "
        "  if (crypto_memneq(computed_hash, stored_hash, 33) == 0) allow;"
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SG-F06: Audit trail erasable via dmesg ring buffer
# ──────────────────────────────────────────────────────────────────────────────

AUDIT_TRAIL_ERASABLE = {
    "finding_id": "TOS46-SG-F06",
    "severity": "MEDIUM",
    "cvss_v3": 4.9,
    "cvss_vector": "AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N",
    "cwe": "CWE-778",
    "title": (
        "shellguard audit log written to kernel ring buffer (printk KERN_INFO) — "
        "root can clear entire audit trail via dmesg -C or /dev/kmsg; "
        "no persistent shellguard-specific audit storage"
    ),
    "binary_evidence": {
        "audit_format_string_va": 0xffffffff825632d8,
        "audit_format": "KERN_INFO 'shell_guard: %d execute >%s<, blocked: %s'",
        "log_level": "KERN_INFO (printk level 6)",
        "sink": "kernel ring buffer (/proc/kmsg, /dev/kmsg, dmesg)",
    },
    "attack": (
        "1. Attempt binary execution → shellguard logs KERN_INFO message. "
        "2. dmesg -C   (or echo > /dev/kmsg) clears the ring buffer. "
        "3. No shellguard enforcement events remain. "
        "\n"
        "The mode-change write (TOS46-SG-F02) emits NO audit log at all — "
        "switching block_mode to 0 leaves zero shellguard trace in any log."
    ),
    "remediation": (
        "Redirect shellguard enforcement events to the Linux audit subsystem "
        "via audit_log_format() rather than printk(). The audit subsystem writes "
        "to a separate buffer that requires CAP_AUDIT_CONTROL to clear, and "
        "integrates with auditd for persistent disk storage. "
        "Also log block_mode changes via audit_log."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SG-F07: Glob-pattern exec watch list (informational)
# ──────────────────────────────────────────────────────────────────────────────

GLOB_WATCHLIST = {
    "finding_id": "TOS46-SG-F07",
    "severity": "INFO",
    "title": "shellguard exec_watch_list uses glob pattern matching (not exact path)",
    "binary_evidence": {
        "path_match_fn_va": 0xffffffff817bf270,
        "glob_chars_handled": {
            0x2a: "*  (wildcard: any chars)",
            0x3f: "?  (single char wildcard)",
            0x5b: "[] (character class)",
        },
    },
    "description": (
        "shellguard_path_match at 0xffffffff817bf270 implements a full glob pattern "
        "matcher with *, ?, and [] support. Exec watch list entries can use wildcards "
        "(e.g., /usr/sbin/*) to watch entire directories. The same glob function is "
        "used for both exec_watch_list path matching and sig_list (comm, path) matching. "
        "\n"
        "Implication: an exec_watch_list entry of /usr/sbin/* catches all binaries "
        "under /usr/sbin/ and sends them to shellguard_check_binary. A sig_list "
        "entry with comm=* would match any process executing the watched binary."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-SG-F01": MD5_BINARY_INTEGRITY,
    "TOS46-SG-F02": BLOCK_MODE_WRITABLE,
    "TOS46-SG-F03": EMPTY_WATCHLIST_BYPASS,
    "TOS46-SG-F04": KASLR_HOOKS_FIXED_VA,
    "TOS46-SG-F05": MEMCMP_TIMING_ORACLE,
    "TOS46-SG-F06": AUDIT_TRAIL_ERASABLE,
    "TOS46-SG-F07": GLOB_WATCHLIST,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "kernel": "6.6.119-51.3.tl4.x86_64",
        "lsm": "shellguard (Tencent proprietary)",
        "analysis_method": "vmlinuz gzip extraction -> ELF objdump disassembly + System.map",
        "kaslr": "DISABLED (CONFIG_RANDOMIZE_BASE not set)",
        "shellguard_enabled_va": hex(SHELLGUARD_SYMBOL_MAP["shellguard_enabled_flag"]),
        "shellguard_block_mode_va": hex(SHELLGUARD_SYMBOL_MAP["shellguard_block_mode"]),
        "hash_algorithm": "MD5 (BROKEN — CWE-327)",
        "hash_comparison": "memcmp (non-constant-time — CWE-208)",
        "findings": [
            {"id": k, "severity": v["severity"], "title": v["title"][:80]}
            for k, v in FINDINGS.items()
        ],
    }, indent=2))
