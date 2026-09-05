"""
TencentOS 4.6 — performance and hardware kernel module RE.

Modules:
  async-fork.ko       — Tencent async copy-on-write fork optimization
  sm2_zhaoxin.ko      — SM2 ECC hardware acceleration (Zhaoxin GMI)
  sm3_zhaoxin.ko      — SM3 hash hardware acceleration (Zhaoxin GMI)
  sm4_zhaoxin.ko      — SM4 block cipher hardware acceleration (ECB/CBC/CTR/CFB/OFB)
  emm_coreutils.ko    — Extended Memory Management core utils (Tencent)
  emm_extentions.ko   — EMM LRU generation extensions (Tencent)
  emm_zram.ko         — ZRAM compressed RAM block device (Tencent-extended)
  irqlatency.ko       — IRQ latency measurement (Tencent)
  netatop.ko          — Per-task network statistics for atop (open source v0.7)
  hct46.ko            — HYGON hardware-specific driver (Hygon Corp, v0.6)
  smc_kernel.ko       — SMC-R (Shared Memory Communications) socket AF (IBM upstream)

These are performance optimization, hardware-specific, or monitoring modules
with no novel security surface. Documented for completeness of TOS 4.6 coverage.
"""

ASYNC_FORK_MODULE = {
    "name": "async-fork.ko",
    "author": "Tencent Corporation",
    "text_size": 0x2dfd,
    "description": (
        "Async copy-on-write fork optimization. Standard Linux fork() copies page tables "
        "synchronously in the parent's context before returning. Async-fork defers the "
        "bulk of page table copying to a background thread or the child itself, reducing "
        "fork() latency. Used in Tencent's server workloads where fork() is a hot path."
    ),
    "key_functions": {
        "asfk_fast (0x1ed0)": (
            "Fast fork path — initiates async page table copy. "
            "Iterates page table levels: p4d → pud → pmd via async_fork_iter_* functions. "
            "Uses folio_prealloc to pre-allocate pages before the fork, reducing allocation "
            "pressure in the critical path."
        ),
        "asfk_prepare (0x24e0)": "prepares the async fork context: mm_bind, madvise, VMA setup",
        "asfk_fixup_vma/vmas (0x2210/0x2400)": "fixes up VMA state after async copy",
        "asfk_fixup_pmd (0x580)": "fixes up PMD (page middle directory) entries after async copy",
        "async_copy_pmd_one (0x2c0)": "copies one PMD entry asynchronously",
        "asfk_rest (0x2930)": "remainder work after fast path — handles huge pages and edge cases",
        "asfk_fast_done (0x2d10)": "completion handler — runs cleanup after async copy finishes",
        "async_fork_rest_success (0x170)": "success path after async fork completion",
    },
    "kernel_dependencies": {
        "async_fork_ops": "external ops table (kernel or base module) defining the async fork callbacks",
        "async_fork_staging": "staging area for in-progress async forks",
        "copy_pte_range_atom": "atomic PTE range copy (TOS 4.6 kernel extension)",
        "folio_prealloc": "page pre-allocation before fork (TOS 4.6 extension)",
        "klp_sched_try_switch": "scheduling hook (KLP = Kernel Live Patch aware scheduling?)",
        "dummy_async_fork_ops": "fallback no-op ops when async fork is disabled",
    },
    "huge_page_support": ["copy_huge_pmd", "copy_huge_pud", "copy_hugetlb_page_range"],
    "security_notes": (
        "Async fork introduces a window where parent and child share page tables "
        "in an incomplete state. The module must handle: "
        "(1) parent exiting before child finishes fixup (kill_pid usage) "
        "(2) COW races during the async copy window "
        "(3) huge page splits during copy. "
        "The module uses mmu_notifier_invalidate_range for TLB consistency. "
        "No privilege escalation surface — this is a pure performance optimization. "
        "The async fork pattern is well-studied; Tencent's implementation follows "
        "the same patterns as Google's UFFD-based async fork."
    ),
}

ZHAOXIN_CRYPTO_MODULES = {
    "vendor": "Zhaoxin (国芯通用处理器)",
    "description": (
        "Zhaoxin is a Chinese x86-compatible CPU vendor (joint venture with VIA Technologies). "
        "These modules accelerate China national standard (GM/T) cryptographic algorithms "
        "using Zhaoxin's GMI (Guomi Instructions — 国密指令) hardware acceleration. "
        "Registered with Linux crypto framework — transparent to applications."
    ),
    "sm2_zhaoxin": {
        "crypto_alias": "zhaoxin-gmi-sm2",
        "operations": ["verify (zhaoxin_sm2_verify)"],
        "missing": ["sign — only verify is implemented (or hardware only supports verify)"],
        "security": (
            "SM2 signature verification uses hardware acceleration. "
            "Implementation is a thin wrapper — actual computation in Zhaoxin GMI hardware. "
            "No software fallback visible — if GMI not available, the algorithm is unavailable."
        ),
    },
    "sm3_zhaoxin": {
        "crypto_alias": "sm3-zhaoxin / sm3-zhaoxin-gmi",
        "operations": ["hash (zx_sm3_update)", "final (zx_sm3_final)", "finup (zx_sm3_finup)"],
        "block_fn": "sm3_generic_block_fn — compression function (may be shared with generic SM3)",
        "security": "SM3 is a 256-bit hash (GB/T 32905). Zhaoxin accelerates the compression function.",
    },
    "sm4_zhaoxin": {
        "crypto_alias": "__ctr(sm4), __cfb(sm4), __ofb(sm4)",
        "modes": ["ECB", "CBC", "CTR", "CFB", "OFB"],
        "functions": {
            "plain (software)": ["cbc_encrypt", "cbc_decrypt", "cfb_encrypt", "cfb_decrypt",
                                 "ctr_encrypt", "ctr_decrypt"],
            "hardware (_zxc suffix)": ["cfb_decrypt_zxc", "cfb_encrypt_zxc",
                                       "ctr_decrypt_zxc", "ctr_encrypt_zxc"],
        },
        "security": "SM4 is a 128-bit block cipher (GB/T 32907). Hardware and software paths available.",
    },
    "overall_security": (
        "All three modules are straightforward hardware crypto drivers. "
        "No memory safety issues expected — they use the kernel crypto framework's "
        "shash/akcipher/skcipher APIs, which enforce buffer bounds. "
        "Correctness of the hardware implementation is unverifiable from the driver alone."
    ),
}

REMAINING_MODULES_SUMMARY = {
    "emm_coreutils.ko": {
        "author": "Zeng Jingxiang <linuszeng@tencent.com>",
        "description": "EMM (Extended Memory Management) core utilities",
        "role": (
            "Provides data structures and interfaces for Tencent's memory management "
            "extensions. Exports emm_lruvec_zero_data and emm_memcg_zero_data — "
            "zero-initialized data for LRU vector and memory cgroup EMM state. "
            "Base module for emm_extentions.ko."
        ),
        "security_notes": "No security surface — pure memory management data structures",
    },
    "emm_extentions.ko": {
        "author": "Zeng Jingxiang <linuszeng@tencent.com>",
        "description": "EMM LRU generation extensions",
        "role": (
            "Extends Linux's MGLRU (Multi-Generation LRU) with EMM-specific data. "
            "memcg_lru_gen_emm_show: displays per-cgroup LRU generation data. "
            "Allows Tencent's memory management policy to integrate with cgroup LRU tracking."
        ),
        "security_notes": "No security surface — memory management observability extension",
    },
    "emm_zram.ko": {
        "description": "Compressed RAM Block Device — Tencent-extended ZRAM",
        "compression_backends": ["lz4", "lz4hc", "deflate", "842"],
        "role": (
            "Extended ZRAM implementation with algorithm configuration. "
            "algorithm_params_store: allows runtime algorithm parameter tuning. "
            "backend_* data structures define per-algorithm operations."
        ),
        "security_notes": (
            "ZRAM decompresses kernel memory on access — a bug in the decompressor "
            "could be exploited by a process that controls zram compressed data. "
            "This is upstream-equivalent risk — same as standard kernel ZRAM."
        ),
    },
    "irqlatency.ko": {
        "author": "shookliu@tencent.com",
        "description": "IRQ latency measurement tool",
        "role": (
            "Measures IRQ handling latency. Provides /proc interface: "
            "enable_write to enable/disable measurement, freq_open for frequency data. "
            "Used for kernel performance analysis on TOS 4.6 production systems."
        ),
        "security_notes": "No security surface — kernel tracing/observability tool",
    },
    "netatop.ko": {
        "description": "Per-task network statistics for atop v0.7 (open source, Gerlof Langeveld)",
        "source": "https://www.atoptool.nl/netatop.php",
        "role": "Hooks TCP/UDP socket events to attribute network traffic to individual processes",
        "security_notes": "Standard open-source module — no TOS-specific modifications found",
    },
    "hct46.ko": {
        "author": "HYGON Corporation",
        "version": "0.6",
        "description": "Hygon hardware-specific driver (HCT = Hygon Crypto Token?)",
        "role": (
            "Character device driver with VMA mapping (hct_cdev_vma_fault). "
            "Maps hardware memory into userspace via mmap. "
            "Likely provides direct hardware access for Hygon-specific functionality "
            "(potentially crypto hardware or hardware security module interface)."
        ),
        "security_notes": (
            "VMA fault handler (hct_cdev_vma_fault) maps hardware pages into user VA. "
            "If mapping is not properly restricted, could expose hardware registers "
            "to unprivileged users. Device file permissions are the primary gate."
        ),
    },
    "smc_kernel.ko": {
        "author": "Ursula Braun <ubraun@linux.vnet.ibm.com> (IBM, upstream Linux)",
        "description": "SMC-R (Shared Memory Communications over RDMA) — AF_SMC socket family",
        "role": (
            "Implements AF_SMC socket family for high-performance RDMA-based communication "
            "between applications. Transparent to applications that use TCP — the kernel "
            "automatically upgrades eligible TCP connections to SMC-R. "
            "BPF tracepoints for SMC message events and link management."
        ),
        "security_notes": "Standard upstream Linux module — no TOS-specific security modifications",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "async-fork.ko: async COW fork optimization — no direct security surface",
        "detail": (
            "Tencent's async fork defers page table copying to reduce fork() latency. "
            "Async copy window handled with mmu_notifier and kill_pid for cleanup. "
            "No privilege escalation surface — pure performance optimization. "
            "Depends on TOS 4.6 kernel extensions (copy_pte_range_atom, folio_prealloc)."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "Zhaoxin SM2/SM3/SM4: hardware crypto drivers for Chinese national standard algorithms",
        "detail": (
            "Thin wrappers over Zhaoxin GMI hardware. SM2 verify only (no sign). "
            "SM3 256-bit hash with hardware block function. SM4 128-bit cipher with "
            "ECB/CBC/CTR/CFB/OFB modes (hardware _zxc variants + software fallbacks). "
            "Registered as Linux crypto framework drivers — transparent to TLS/CFS/DIM."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "hct46.ko: Hygon VMA-mapped hardware device — device file permissions are the security gate",
        "detail": (
            "Character device maps hardware memory into userspace via hct_cdev_vma_fault. "
            "Unprivileged access to hardware pages could expose hardware registers. "
            "Security depends on /dev/hct device file permissions."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "emm_*.ko: Tencent Extended Memory Management — no security surface",
        "detail": (
            "emm_coreutils + emm_extentions provide MGLRU and memcg data extensions. "
            "emm_zram extends ZRAM compression. All are performance/capacity optimizations. "
            "emm_zram decompressor bugs carry same risk as upstream ZRAM."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 performance and hardware kernel modules RE")
    print()
    print("async-fork.ko (Tencent):")
    print(f"  {ASYNC_FORK_MODULE['text_size']:04x} bytes .text — async COW page table copy on fork()")
    print(f"  Deps: async_fork_ops, copy_pte_range_atom, folio_prealloc (TOS 4.6 kernel)")
    print()
    print("Zhaoxin GMI hardware crypto (Zhaoxin/ZX):")
    for name, info in ZHAOXIN_CRYPTO_MODULES.items():
        if name.startswith("sm"):
            print(f"  {name}: {info['crypto_alias']}")
    print()
    print("Remaining modules (summary):")
    for name, info in REMAINING_MODULES_SUMMARY.items():
        print(f"  {name}: {info['description'][:60]}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
