"""
TencentOS 4.6 — async-fork.ko binary RE module.

async-fork — TOS-specific fork() acceleration via deferred page table copy.
Author: Tencent Corporation
Source: kernel/tkernel/async-fork/async_fork.c
Vermagic: 6.6.119-51.3.tl4.x86_64 (TOS 4.6)
Signed: Tkernel signing key 01:9D:01:14:84:D7 (sha256, production key)
Size: 84182B

async-fork converts fork() page table copy from synchronous O(VMAs) work into an
asynchronous deferred path. The parent marks PMD entries with custom flag bits
instead of copying PTEs at fork time. The child's first access to each PMD region
triggers a lazy copy (asfk_fixup_pmd). A fallback path (__async_fork_fallback)
handles cases where async copy cannot complete cleanly.

External dependencies: async_fork_staging, async_fork_ops, dummy_async_fork_ops
are IMPORTED — a separate staging controller module (not in scratchpad) drives
when async fork activates. This module implements the mechanics.
"""

METADATA = {
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "module": "async_fork",
    "size_bytes": 84182,
    "author": "Tencent Corporation",
    "srcfile": "kernel/tkernel/async-fork/async_fork.c",
    "license": "GPL v2",
    "srcversion": "C6D245DEE1B6DB1AAC63ADF",
    "signer": "Tkernel signing key",
    "sig_key": "01:9D:01:14:84:D7",
    "intree_declared": True,
    "intree_actual": False,
}

DESIGN = {
    "problem": (
        "Linux fork() copies all page tables synchronously. For large-address-space "
        "processes, this is O(VMAs × PTE entries) work on the critical path of fork(). "
        "Copy-on-write (CoW) handles data pages lazily, but the PTE structures themselves "
        "must be allocated and populated at fork time."
    ),
    "solution": (
        "async-fork defers PTE copy: at fork(), parent PMD entries are marked with custom "
        "async-fork flag bits instead of being fully copied. The child gets mm structs with "
        "async-fork PMD markers. On first child access to any async-fork region, "
        "asfk_fixup_pmd copies the actual PTEs from parent to child on-demand. "
        "If the parent exits or modifies the region before the child accesses it, "
        "__async_fork_fallback performs a synchronous catch-up copy."
    ),
    "two_paths": {
        "fast": "asfk_fast / __asfk_fast — marks PMDs in parent, returns quickly from fork()",
        "fallback": "__async_fork_fallback — full synchronous copy when async path cannot proceed",
    },
}

PMD_FLAG_ANALYSIS = {
    "function": "is_pmd_async_fork",
    "addr": 0x0010,
    "size_bytes": 0x9b,
    "purpose": "Classify a PMD value as an async-fork PMD (vs. normal/huge/absent PMD)",
    "logic": {
        "step1": "test $0xffffffffffffff9f,%rdi  # check bits 5-6; if clear, not async fork (normal PMD type bits)",
        "step2": "if bits 5-6 clear → return 0 (plain present PMD, not async fork)",
        "step3": "if bit 57 set → return 0 (software bit used for another purpose, not ours)",
        "step4": "test $0x200000000000080: check bit 57 | bit 7 combo",
        "step5": "if bit 7 only (0x80) → huge-page marker without P bit; not async fork",
        "step6": "if (pmd & 0xc2) == 0xc0 → bits 7,6 set, bit 1 clear → normal huge PMD; return 0",
        "step7": "if (pmd & 0xc0) != 0xc0 → not huge; check remaining bits",
        "conclusion": "Async-fork PMD = present PMD with custom bits in positions 5-6 (software-reserved)",
    },
    "async_fork_pmd_marker": "Bits 5-6 of PMD (software-reserved in x86 PTEs for OS use)",
    "note": (
        "x86-64 4-level/5-level paging reserves bits 9-11 (software) and bit 57-62 (with PKS/MPK). "
        "Bits 5-6 are NOT generally software-reserved in x86 PTEs — bit 6 is the 'dirty' bit, "
        "bit 5 is the 'accessed' bit. Using A/D bits as async-fork markers means async-fork PMDs "
        "appear both 'accessed' and 'dirty' to the hardware MMU — unexpected for a newly-forked "
        "child that has never accessed the region."
    ),
}

ASFK_STRUCT = {
    "name": "asfk_state (inferred)",
    "embedded_in": "mm_struct at TOS-specific offset",
    "field_offsets": {
        "+0x000": "refcount (atomic_t) — lock decl / lock incl pattern",
        "+0x550": "paired_mm pointer — parent↔child linkage (mm_struct *)",
        "+0x558": "flags (byte) — bit 0=in_progress, bit 1=bound, bit 2=fallback_active",
    },
    "flags_byte_0x558": {
        "bit_0": "asfk_in_progress — set by asfk_prepare lock btsq $0x0; cleared on completion",
        "bit_1": "asfk_bound — set by asfk_mm_bind lock orb $0x2; cleared on unbind",
        "bit_2": "unknown — lock andb $0xfb clears it in __async_fork_fallback",
    },
    "counter_0xe8": "mm+0xe8: count of PTEs/PMDs successfully copied async (incremented in success path)",
}

FUNCTIONS = {
    "is_pmd_async_fork": {
        "addr": 0x0010,
        "exported": False,
        "purpose": "Test whether a PMD value has the async-fork marker bits set",
        "returns": "1 if async-fork PMD, 0 if normal/huge/absent",
    },
    "async_fork_init": {
        "addr": 0x00c0,
        "alias": "init_module",
        "purpose": "Module init: registers async-fork ops via async_fork_ops pointer",
        "sequence": [
            "call + lock addl $0 (flush/serialization nop — same pattern as ttools)",
            "movq $0x0 to async_fork_staging (disable staging)",
            "lock incl pending counter",
            "log 'ASYNC FORK module installed' (KERN_INFO = 0x36)",
        ],
    },
    "async_fork_exit": {
        "addr": 0x0100,
        "alias": "cleanup_module",
        "purpose": "Module exit: wait for pending async forks to complete, then unregister",
        "spinloop": {
            "pattern": "pause; mov pending; test; jne (loop)",
            "addr": "0x128 → 0x128 (busy-wait)",
            "note": "Spinloop prevents unload while any async fork is in flight",
        },
        "sequence": [
            "read pending counter to %esi",
            "log 'ASYNC FORK is going down, pending=%d'",
            "lock decl pending",
            "mov pending → test; if != 0 → spin with pause",
            "call unregister function",
            "movq $0x0 to async_fork_staging",
            "log final message",
        ],
    },
    "async_fork_rest_success": {
        "addr": 0x0170,
        "purpose": "Completion handler when child async fork succeeds",
        "signature": "void async_fork_rest_success(struct mm_struct *child_mm, struct mm_struct *parent_mm)",
        "sequence": [
            "lock btrq $0x1,+0x558(%parent_mm) — test-and-clear bound bit; if not set → BUG(ud2)",
            "lock andb $0xfd,+0x558(%child_mm) — clear bit 1",
            "movq $0x0,+0x550(%child_mm) — clear paired_mm pointer",
            "iterate: lea +0xb0(%child_mm) → down_write (mmap_lock on child_mm)",
            "process remaining async-fork VMA entries",
            "lock decl +0x0(%child_mm) — decrement child refcount; if 0 → mmput(child_mm)",
            "lock decl +0x0(%parent_mm) — decrement parent refcount; if 0 → mmput(parent_mm)",
        ],
        "log": "%s: child async fork success, mm=%pK, oldmm=%pK",
    },
    "async_copy_pmd_one": {
        "addr": 0x02c0,
        "purpose": "Copy one PMD range from parent to child, handling async-fork markers",
        "key_checks": [
            "call is_pmd_async_fork(parent_pmd) — skip if not async-fork PMD",
            "cmpq $0,+0xb8(%child_vma) — skip if child VMA has no backing",
            "iterate VMA range via mas_find (maple tree VMA iterator)",
            "for each VMA: call copy_pte_range_atom or copy_huge_pmd",
            "error -11 (ENOMEM) → try folio_prealloc",
            "error 0xfffffff4 (-12) or 0xfffffff5 (-11) → debug log",
            "if count > 0 and pmd is still async-fork: call async_fork_mkpmd to update marker",
        ],
        "returns": "0 on success, negative errno on failure",
    },
    "asfk_fixup_pmd": {
        "addr": 0x0580,
        "exported": True,
        "purpose": "Fix up one PMD entry in child: copy PTEs from parent on first child access",
        "trigger": "Called from child page fault handler when async-fork PMD is hit",
    },
    "async_fork_iter_pmd_range": {
        "addr": 0x0fd0,
        "purpose": "Iterate PMD range and call async_copy_pmd_one for each async-fork PMD",
    },
    "async_fork_iter_pud_range": {
        "addr": 0x17d0,
        "suffix": ".isra.0",
        "purpose": "Iterate PUD range, calls async_fork_iter_pmd_range per PMD",
    },
    "async_fork_iter_p4d_range": {
        "addr": 0x1a80,
        "purpose": "Iterate P4D range, calls async_fork_iter_pud_range per PUD",
    },
    "__async_fork_iter_page_range": {
        "addr": 0x1d10,
        "purpose": "Full page range iterator — walks P4D→PUD→PMD hierarchy for async copy",
    },
    "asfk_fast": {
        "addr": 0x1ed0,
        "exported": True,
        "purpose": "Fast path: mark parent PMDs as async-fork, skip PTE copy at fork time",
        "log": [
            "%s: parent async fork fast begin",
            "%s: fast path vma=%pK mm=%pK addr: %08lx-%08lx",
            "%s: parent async fork fast end, mm=%pK err=%d",
        ],
    },
    "asfk_madvise_vma": {
        "addr": 0x2170,
        "exported": True,
        "purpose": "Handle madvise() call on async-fork VMA region",
        "log": [
            "%s: async fork madvise, oldmm=%pK vma=%08lx-%08lx",
            "%s: async fork madvise finished",
        ],
    },
    "asfk_fixup_vma": {
        "addr": 0x2210,
        "exported": True,
        "purpose": "Fix up one VMA in child: synchronize after async fork completes for VMA",
        "log": [
            "%s: async fork fixup vma, oldmm=%pK mm=%pK vma=%08lx-%08lx",
            "%s: async fork fixup vma finished",
        ],
    },
    "asfk_fixup_vmas": {
        "addr": 0x2400,
        "exported": True,
        "purpose": "Fix up all VMAs in child mm — called when child needs full synchronization",
        "log": "%s: async fork is fix vmas, pid=%d comm=%s child=%pK",
    },
    "asfk_prepare": {
        "addr": 0x24e0,
        "exported": True,
        "purpose": "Prepare mm_struct for async fork — set in_progress flag",
        "key_ops": [
            "lock btsq $0x0,+0x558(%mm) — atomically set bit 0 (in_progress)",
            "if bit was already set (jae) → concurrent async fork in progress, fallback",
            "read %gs:0xc50 — current task context (pid or CPU state)",
            "log 'async fork begin on pid=%d mm=%pK oldmm=%pK'",
        ],
        "returns": "0 on success; falls through to fallback if already in progress",
    },
    "__async_fork_fallback": {
        "addr": 0x25a0,
        "purpose": "Synchronous fallback: copy all async-fork pages normally when async path fails",
        "trigger_conditions": [
            "Concurrent async fork in progress (in_progress bit set)",
            "Parent mm teardown before child copy completes",
            "Memory allocation failure during async copy",
        ],
        "key_ops": [
            "lock andb $0xfb,+0x558(%r13) — clear bit 2",
            "lock andb $0xfd,+0x558(%r13) — clear bit 1 (bound)",
            "movq $0x0,+0x550(%r13) — clear paired_mm",
            "lock decl (%r14) — decrement parent refcount",
            "lock decl 0x0(%r13) — decrement child refcount",
            "call __async_fork_iter_page_range — full synchronous copy",
            "read %gs:0xe48 — task identity (TOS-specific task_struct offset, same as kill_protect)",
            "read %gs:0xc50 — task PID/context",
        ],
        "log": [
            "%s: async fork is fallback, pid=%d comm=%s mm=%pK,%pK",
            "%s: async fork fallback skipped, pid=%d comm=%s",
            "%s: async fork fallback in pmd fix, oldmm=%pK",
            "%s: async fork fallback in vma fix",
            "%s: fallback vma: vma1=%pK, vma2=%pK",
        ],
        "stack_frame": "0x48 bytes local + canary at 0x40(%rsp) = 0x50 total",
    },
    "asfk_mm_bind": {
        "addr": 0x2830,
        "exported": True,
        "purpose": "Link parent mm ↔ child mm for async fork",
        "signature": "int asfk_mm_bind(struct mm_struct *parent_mm, struct mm_struct *child_mm, int flags)",
        "key_ops": [
            "if flags != 0 → call __async_fork_fallback(parent_mm, 0) and return",
            "cmpq $0,+0x550(%parent_mm) — check parent has no existing pair",
            "movq %child_mm,+0x550(%parent_mm) — parent.paired = child",
            "movq %parent_mm,+0x550(%child_mm) — child.paired = parent",
            "lock orb $0x2,+0x558(%child_mm) — set bound bit on child",
            "lock incl +0x0(%parent_mm) — increment parent refcount",
            "lock incl +0x0(%child_mm) — increment child refcount",
        ],
        "log": "%s: vma is binded, vma=%pK vma=%pK mm=%pK,%pK",
    },
    "asfk_rest": {
        "addr": 0x2930,
        "exported": True,
        "purpose": "Resume/complete async fork after initial fast path",
    },
    "asfk_fast_done": {
        "addr": 0x2d10,
        "purpose": "Called when fast path is done — triggers child copy or fallback",
        "key_ops": [
            "mov +0x550(%rdi) → %rbp (get paired_mm)",
            "if paired_mm is NULL → return",
            "if success=0 → call __async_fork_fallback",
            "call down_write (mmap_write_lock on VMA list)",
            "call __async_fork_fallback (NULL, 0) for cleanup",
            "increment mm.e8 counter (async copies completed)",
        ],
    },
}

IMPORTED_SYMBOLS = {
    "async_fork_staging": {
        "type": "external — not exported by this module",
        "purpose": "Global staging state variable — controls whether async fork is active",
        "module": "Unknown — staging controller module not in scratchpad",
    },
    "async_fork_ops": {
        "type": "external",
        "purpose": "Ops table pointer — asfk_* functions are registered here at init",
    },
    "dummy_async_fork_ops": {
        "type": "external",
        "purpose": "No-op ops table — installed at cleanup to disable async fork",
    },
    "copy_pte_range_atom": {
        "type": "TOS kernel export (not upstream)",
        "purpose": "Atomic PTE range copy — TOS-modified copy_pte_range that is preemptable",
        "note": "Upstream copy_pte_range is not split into atomic units",
    },
    "folio_prealloc": {
        "type": "TOS kernel export (not upstream)",
        "purpose": "Pre-allocate a folio for async copy when allocation fails mid-copy",
    },
    "mas_find": {
        "type": "Upstream (maple tree VMA iterator)",
        "purpose": "Find next VMA in maple tree",
    },
    "alloc_pages": "Page allocator",
    "__folio_put": "Release folio reference",
    "__free_pages": "Free allocated pages",
    "find_vma": "Find VMA containing address",
    "init_mm": "Kernel's initial mm_struct (reference)",
    "kill_pid": "Send signal to process by PID",
    "__klp_sched_try_switch": "KLP live patch scheduling hook (same as irqlatency)",
    "klp_sched_try_switch_key": "KLP jump label key",
    "down_write": "Take write lock (mmap_lock)",
    "pv_ops": "Paravirt ops table",
    "__mmap_lock_do_trace_*": "mmap lock tracing hooks",
    "__cond_resched": "Conditional reschedule point",
    "__dynamic_pr_debug": "Dynamic debug print",
    "copy_huge_pmd": "Copy huge PMD entry (for THP)",
    "copy_huge_pud": "Copy huge PUD entry",
    "copy_hugetlb_page_range": "Copy hugetlb page range",
}

TASK_STRUCT_OFFSETS = {
    "0xe48": {
        "field": "task identity (comm/pid) — TOS-specific",
        "seen_in": ["kill_protect_blacklist_match", "__async_fork_fallback"],
        "consistent_with": "kill_protect module (also reads +0xe48 for process identity)",
    },
    "0xc50": {
        "field": "unknown task context field — accessed via %gs:0xc50",
        "seen_in": ["asfk_prepare", "__async_fork_fallback", "asfk_mm_bind"],
        "note": (
            "Not the same as 0xe48. Possibly nsproxy-relative PID, or CPU scheduler state. "
            "Accessed as 32-bit value (mov 0xc50(%rax),%ecx) suggesting it's a 32-bit field."
        ),
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "async-fork race: parent exit while child async copy pending → UAF on parent PMD",
        "detail": (
            "When async fork is in progress (parent PMDs marked, child not yet copied): "
            "if the parent calls exit() before the child copies the PMDs, the parent mm_struct "
            "and its page tables are freed. The child's asfk_fixup_pmd then reads freed PMD memory. "
            "async-fork tracks this via the refcount at mm+0x0 (lock incl/decl in asfk_mm_bind and "
            "async_fork_rest_success). If the refcount logic has a race window — specifically, "
            "if the parent decrements its refcount to 0 before the child's fixup path takes its "
            "refcount — mmput(parent_mm) frees the page tables while the child is copying them. "
            "The cleanup_module spinloop shows the module itself is aware of this lifetime issue: "
            "it won't unload until pending=0, but the parent-exit path is independent of pending."
        ),
        "race_window": "parent exit → mmput(parent_mm) vs child asfk_fixup_pmd reading parent PMDs",
        "mitigation_claimed": "Refcount at mm+0x0 incremented by asfk_mm_bind",
        "concern": "Refcount increment must happen before parent exit path, which is a scheduling constraint",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "async-fork PMD marker uses A/D bits (bits 5-6) — hardware MMU may clear them",
        "detail": (
            "is_pmd_async_fork classifies PMDs by checking bits 5-6 (the x86 'accessed' and 'dirty' bits). "
            "The hardware MMU sets A/D bits on page walk, and the kernel may clear them during "
            "page reclaim (clear_young_dirty_refs, ptep_clear_flush_young). "
            "If the kernel clears the A or D bit on an async-fork PMD as part of normal page aging, "
            "is_pmd_async_fork returns 0 and the PMD is misidentified as a normal PMD. "
            "The child's asfk_fixup_pmd then skips the lazy copy, "
            "and the child accesses the region without it ever being copied from the parent — "
            "either a page fault into unmapped memory or a silent use of stale data."
        ),
        "affected_bits": "bit 5 (accessed), bit 6 (dirty) in x86 PMD entries",
        "risk": "A/D bit cleared by kernel → async-fork PMD misidentified → child reads stale/unmapped memory",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "async_fork_staging imported from unknown module — incomplete auditability",
        "detail": (
            "async_fork_ops, async_fork_staging, and dummy_async_fork_ops are IMPORTED "
            "(type U in nm output). The staging controller that activates async fork is a "
            "separate module not present in the scratchpad. "
            "Without auditing the staging module: "
            "(1) unknown which processes/conditions trigger async fork activation, "
            "(2) unknown whether async fork can be triggered by unprivileged processes, "
            "(3) unknown whether dummy_async_fork_ops (the disable-path) can be "
            "raced to disable async fork mid-operation."
        ),
        "missing_module": "Exports: async_fork_ops, async_fork_staging, dummy_async_fork_ops",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "cleanup_module spinloop with pause — no timeout; module unload blocks indefinitely",
        "detail": (
            "cleanup_module at 0x128: pause; mov pending; test; jne 0x128. "
            "If an async fork is stuck (child hung, async copy blocked on memory allocation), "
            "the spinloop never exits. 'modprobe -r async_fork' hangs the process calling it "
            "(typically root's rmmod). "
            "No timeout, no killable wait — a stuck async fork makes the module permanently unremovable. "
            "On a system where async fork is stuck in __async_fork_fallback holding a mmap_lock, "
            "this creates a dependency cycle: rmmod blocks, hung task timeout fires, kernel BUG."
        ),
        "spinloop_addr": 0x0128,
        "spinloop_type": "busy-wait with pause (no timeout, no interruptible wait)",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "task_struct+0xe48 confirmed TOS ABI — second module referencing this offset",
        "detail": (
            "async-fork's __async_fork_fallback reads %gs:0xe48 for task identity "
            "(same offset as kill_protect_blacklist_match). "
            "This is the second TOS 4.x module confirmed using task_struct+0xe48. "
            "Both modules treat this as 'comm' or identity without validation. "
            "If task_struct layout changes between TOS 4.x point releases, "
            "both modules silently read wrong fields — kill_protect would misidentify processes, "
            "and async-fork would log wrong comm strings (lower severity). "
            "task_struct+0xe48 is not an upstream field at this offset in 6.6.x "
            "(upstream comm is at +0x758 in 6.6 x86_64)."
        ),
        "tos_abi_offset": 0xe48,
        "modules_referencing": ["kill_protect.ko", "async-fork.ko"],
        "upstream_comm_offset": 0x758,
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "copy_pte_range_atom imported — TOS-specific atomic PTE copy not in upstream",
        "detail": (
            "async-fork imports copy_pte_range_atom (not copy_pte_range from upstream). "
            "The '_atom' suffix suggests this is a preemptable atomic version that can be "
            "interrupted mid-copy. Upstream copy_pte_range holds mmap_lock read and "
            "cannot be preempted between PTEs. "
            "An atomic version that yields between chunks introduces a window where "
            "the parent can modify PTEs after the child has already copied some of them "
            "but before copying the rest — inconsistent PTE snapshot in the child."
        ),
        "tos_only_import": "copy_pte_range_atom",
        "concern": "Preemptable PTE copy creates inconsistent snapshot window",
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "KLP integration — async-fork imports __klp_sched_try_switch (same as irqlatency)",
        "detail": (
            "async-fork imports __klp_sched_try_switch and klp_sched_try_switch_key, "
            "same as irqlatency.ko. "
            "This is a TOS-wide pattern: TOS kernel modules participate in the "
            "KLP quiescence protocol even when not themselves being patched. "
            "The call site is likely in asfk_rest or the completion path — "
            "async-fork yields for KLP at task scheduling points during async copy. "
            "Unlike irqlatency (which called KLP from hrtimer context), "
            "async-fork's KLP call is likely in task context (safer)."
        ),
        "klp_pattern": "Third TOS module observed importing __klp_sched_try_switch",
    },
]

if __name__ == '__main__':
    print("async-fork.ko (TOS 4.6) RE analysis")
    print(f"Source: {METADATA['srcfile']}")
    print()
    print("Design:")
    print(f"  Problem: {DESIGN['problem'][:80]}")
    print(f"  Fast path: {DESIGN['two_paths']['fast']}")
    print(f"  Fallback:  {DESIGN['two_paths']['fallback']}")
    print()
    print("PMD flag analysis:")
    print(f"  async-fork marker: {PMD_FLAG_ANALYSIS['async_fork_pmd_marker']}")
    print()
    print("asfk_state offsets (inferred from mm_struct):")
    for off, desc in ASFK_STRUCT['field_offsets'].items():
        print(f"  {off}: {desc}")
    print()
    print("Key TOS offsets confirmed:")
    for off, data in TASK_STRUCT_OFFSETS.items():
        print(f"  task_struct+{off}: {data['field']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
