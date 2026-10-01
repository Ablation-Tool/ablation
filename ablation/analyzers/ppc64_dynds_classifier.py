"""
ppc64_dynds_classifier.py — PPC64/Cell PPU dynamic data structure pattern classifier.

Classifies stripped functions as instances of dynamic data structure traversal or
manipulation patterns without requiring any string cross-references.  Detection is
purely structural, derived from PPC64 big-endian instruction encoding patterns.

Patterns are derived from Chou & Amarasinghe, "Compilation of Dynamic Sparse Tensor
Algebra", OOPSLA 2022.  That paper shows that sparse dynamic data structures — BSTs,
block linked lists, C-trees, B-trees — produce code with predictable structural shapes
when traversed or modified.  Each shape maps to a distinct combination of:

  - Recursive self-calls (BST/C-tree traversal)
  - Backward conditional branches (for-loops over array chunks)
  - Multiple BLR (return) sites with literal 0/1 values (coroutine iterators)
  - Pointer self-loads LWZ/LD rX, off(rX) (pointer-chain walking)

On Cell PPU / CryEngine 3 PS3, these patterns appear in AI pathfinding (BST open/closed
sets), physics broadphase (C-tree contact queries), particle and entity lists (BLL
traversal/append), and spatial query iterators (coroutine yield pattern).

Detected patterns:
  bst_traversal    Recursive BST node walk.  ≥2 self-calls, null-check within
                   first 8 instructions, zero backward branches.  Maps to
                   seq = l, e, r schema (in-order traversal).
  ctree_traversal  C-tree: BST spine + chunk array.  Recursive like BST but
                   also has ≥1 backward branch (inner for-loop over chunk).
  bll_traversal    Block linked list traversal.  Nested while+for loops (≥2
                   backward branches), pointer self-loads (LWZ rX, off(rX)),
                   no recursion.
  coroutine_iter   State-machine iterator.  ≥3 BLR sites, both LI rX,0 and
                   LI rX,1 present anywhere in the function (yield-true /
                   exhausted-false return values).
  bll_append       Block linked list append.  Small (4-48 insns), ≥1 external
                   call (alloc), ≤1 backward branch, ≥1 pointer self-load.

Usage:
    from ablation.analyzers.ppc64_dynds_classifier import DynDSClassifier

    clf = DynDSClassifier.from_context(ctx)   # BinaryContext (ppc64)
    findings = clf.classify()
    print(clf.report(findings))

    # Group by pattern
    by_pat = clf.by_pattern(findings)
    for va_finding in by_pat.get("bst_traversal", []):
        ctx.set_name(va_finding.va, f"ds_bst_{va_finding.va:x}", source="dynds")
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

try:
    import numpy as np
    _NUMPY_OK = True
except ImportError:
    _NUMPY_OK = False

# Reuse ELF helpers from the VMX density module to avoid duplication.
from ablation.analyzers.ppc64_vmx_density import (
    _load_code_segment,
    _extract_func_starts,
)


# ── Pattern labels ───────────────────────────────────────────────────────────

BST_TRAVERSAL   = "bst_traversal"
CTREE_TRAVERSAL = "ctree_traversal"
BLL_TRAVERSAL   = "bll_traversal"
COROUTINE_ITER  = "coroutine_iter"
BLL_APPEND      = "bll_append"

# Priority when multiple patterns match (higher wins)
_PRIORITY: Dict[str, int] = {
    CTREE_TRAVERSAL: 5,
    BST_TRAVERSAL:   4,
    COROUTINE_ITER:  3,
    BLL_TRAVERSAL:   2,
    BLL_APPEND:      1,
}

# PPC64 primary opcodes
_OP_CMPLWI = 10   # compare logical word immediate
_OP_CMPWI  = 11   # compare word immediate (L=1 → cmpdi)
_OP_ADDI   = 14   # encodes LI when rA=0
_OP_BC     = 16   # branch conditional
_OP_B      = 18   # branch (BL = link variant, LK=1)
_OP_LWZ    = 32   # load word and zero
_OP_LD     = 58   # load doubleword (PPC64)

_BLR_WORD  = 0x4E800020  # blr: opcode 19, XO=16, BO=20, BI=0


# ── Data types ───────────────────────────────────────────────────────────────

@dataclass
class DynDSFeatures:
    """Raw structural features for one function."""
    va:             int
    n_insns:        int   # word-aligned instruction count
    n_bl:           int   # total BL (call) instructions
    n_self_calls:   int   # BL targeting own function VA
    n_backward_bc:  int   # backward conditional branches (loop back-edges)
    n_blr:          int   # BLR (return) instruction count
    n_ptr_chain:    int   # LWZ/LD rX, off(rX) — pointer self-loads
    has_cmp0_entry: bool  # cmpwi/cmplwi rX, 0 within first 8 instructions
    has_li0:        bool  # LI rX, 0 anywhere in function
    has_li1:        bool  # LI rX, 1 anywhere in function


@dataclass
class DynDSFinding:
    """Classification result for one function."""
    va:       int
    pattern:  str
    features: DynDSFeatures

    def fmt(self, name_fn=None) -> str:
        f = self.features
        name = name_fn(self.va) if name_fn else f"0x{self.va:x}"
        return (
            f"0x{self.va:010x}  [{self.pattern:<16}]"
            f"  insns={f.n_insns:5d}"
            f"  sc={f.n_self_calls}"
            f"  loops={f.n_backward_bc}"
            f"  ret={f.n_blr}"
            f"  ptrc={f.n_ptr_chain}"
            f"  {name}"
        )


# ── Classifier ───────────────────────────────────────────────────────────────

class DynDSClassifier:
    """
    Classifies PPC64/Cell PPU functions as dynamic data structure patterns.

    Operates in O(N log F) time via numpy vectorized feature extraction: all
    boolean feature arrays are built over the whole code segment in one pass,
    then aggregated per-function using searchsorted + bincount.

    No string cross-references required.  Complements VMXDensityScanner (VMX
    labels vector-math functions; DynDSClassifier labels DS traversal functions).
    Combine their outputs to cover both math-heavy and pointer-heavy residuals.
    """

    def __init__(
        self,
        func_starts: List[int],
        code_data: bytes,
        code_va: int,
    ) -> None:
        self._func_starts = sorted(func_starts)
        self._code_data   = code_data
        self._code_va     = code_va

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_context(cls, ctx) -> "DynDSClassifier":
        """Build from a BinaryContext (must be ppc64 or ppc32 arch)."""
        if ctx.arch not in ("ppc64", "ppc32"):
            raise ValueError(
                f"DynDSClassifier requires ppc64/ppc32, got {ctx.arch!r}"
            )
        path = getattr(ctx, "_path", None)
        if not path:
            raise ValueError("BinaryContext has no _path attribute")
        with open(path, "rb") as fh:
            raw = fh.read()
        code_data, code_va = _load_code_segment(raw)
        if not code_data:
            raise ValueError(f"Could not locate executable LOAD segment in {path}")
        return cls(list(ctx.func_starts), code_data, code_va)

    @classmethod
    def from_path(cls, elf_path: str) -> "DynDSClassifier":
        """Build directly from an ELF path without a BinaryContext."""
        with open(elf_path, "rb") as fh:
            raw = fh.read()
        code_data, code_va = _load_code_segment(raw)
        if not code_data:
            raise ValueError(f"No executable LOAD segment in {elf_path}")
        return cls(_extract_func_starts(raw), code_data, code_va)

    # ── Classification ────────────────────────────────────────────────────────

    def classify(self, min_insns: int = 4) -> List[DynDSFinding]:
        """
        Classify all functions, returning those that match a pattern.

        Args:
            min_insns: Skip functions shorter than this (filters prologue stubs).

        Returns:
            List of DynDSFinding, sorted by VA.
        """
        if not self._func_starts or not self._code_data:
            return []
        if _NUMPY_OK:
            features = self._extract_features_numpy(min_insns)
        else:
            features = self._extract_features_python(min_insns)
        findings: List[DynDSFinding] = []
        for fva, feat in sorted(features.items()):
            pattern = self._classify_one(feat)
            if pattern:
                findings.append(DynDSFinding(va=fva, pattern=pattern, features=feat))
        return findings

    def _classify_one(self, f: DynDSFeatures) -> Optional[str]:
        """Return the highest-priority pattern matching this function's features."""
        candidates: List[str] = []

        # C-tree: recursive AND has inner for-loop (takes priority over pure BST)
        if f.n_self_calls >= 2 and f.has_cmp0_entry and f.n_backward_bc >= 1:
            candidates.append(CTREE_TRAVERSAL)
        elif f.n_self_calls >= 1 and f.n_backward_bc >= 1 and f.n_bl >= 3:
            candidates.append(CTREE_TRAVERSAL)

        # BST: recursive, null-checked entry, no loops
        if f.n_self_calls >= 2 and f.has_cmp0_entry and f.n_backward_bc == 0:
            candidates.append(BST_TRAVERSAL)
        elif (f.n_self_calls >= 1 and f.has_cmp0_entry
              and f.n_backward_bc == 0 and f.n_bl >= 2):
            candidates.append(BST_TRAVERSAL)

        # BLL traversal: nested loops + pointer chain, no recursion
        if (f.n_self_calls == 0 and f.n_backward_bc >= 2
                and f.n_ptr_chain >= 1 and f.n_insns >= 16):
            candidates.append(BLL_TRAVERSAL)

        # Coroutine: ≥3 returns, both 0 and 1 literal return values present
        if f.n_blr >= 3 and f.has_li0 and f.has_li1:
            candidates.append(COROUTINE_ITER)

        # BLL append: small, allocates, conditional, pointer self-load
        if (f.n_self_calls == 0 and f.n_bl >= 1
                and 4 <= f.n_insns <= 48 and f.n_backward_bc <= 1
                and f.n_ptr_chain >= 1):
            candidates.append(BLL_APPEND)

        if not candidates:
            return None
        return max(candidates, key=lambda p: _PRIORITY[p])

    # ── Feature extraction — numpy ────────────────────────────────────────────

    def _extract_features_numpy(self, min_insns: int) -> Dict[int, DynDSFeatures]:
        buf     = self._code_data
        code_va = self._code_va
        fa      = np.array(self._func_starts, dtype=np.int64)
        n_funcs = len(fa)

        # Align to 4-byte boundary
        aligned_len = len(buf) - (len(buf) % 4)
        words = np.frombuffer(buf[:aligned_len], dtype=np.dtype('>u4')).astype(np.int64)
        n = len(words)
        if n == 0:
            return {}

        insn_vas = code_va + np.arange(n, dtype=np.int64) * 4
        opcode   = words >> 26  # top 6 bits of each word

        # ── Boolean feature arrays ────────────────────────────────────────────

        # BL: opcode 18, AA=0 (bit 30), LK=1 (bit 31)
        is_bl = (opcode == _OP_B) & ((words & 1) == 1) & (((words >> 1) & 1) == 0)

        # BL target: sign-extend 24-bit LI field, multiply by 4, add PC
        bl_li_u = (words >> 2) & 0xFFFFFF
        bl_li   = np.where(bl_li_u >= 0x800000, bl_li_u - 0x1000000, bl_li_u)
        bl_tgts = insn_vas + bl_li * 4

        # BC backward: opcode 16, AA=0, LK=0, 14-bit BD negative
        bc_aa   = (words >> 1) & 1
        bc_lk   = words & 1
        bc_bd_u = (words >> 2) & 0x3FFF
        bc_bd   = np.where(bc_bd_u >= 0x2000, bc_bd_u - 0x4000, bc_bd_u)
        is_bc_bwd = (opcode == _OP_BC) & (bc_aa == 0) & (bc_lk == 0) & (bc_bd < 0)

        # BLR: exact word match
        is_blr = words == _BLR_WORD

        # CMP rX, 0: opcode 10 or 11, SIMM field = 0
        is_cmp0 = ((opcode == _OP_CMPLWI) | (opcode == _OP_CMPWI)) & ((words & 0xFFFF) == 0)

        # LI rD, 0/1: opcode 14 (ADDI), rA field = 0, SIMM in {0, 1}
        li_rA   = (words >> 16) & 0x1F
        li_simm = words & 0xFFFF
        is_li0  = (opcode == _OP_ADDI) & (li_rA == 0) & (li_simm == 0)
        is_li1  = (opcode == _OP_ADDI) & (li_rA == 0) & (li_simm == 1)

        # Pointer self-load: LWZ/LD where rD == rA (and rA != 0)
        rD = (words >> 21) & 0x1F
        rA = (words >> 16) & 0x1F
        is_ptr = ((opcode == _OP_LWZ) | (opcode == _OP_LD)) & (rD == rA) & (rA != 0)

        # ── Assign instructions to functions ──────────────────────────────────

        func_idxs = np.searchsorted(fa, insn_vas, side='right') - 1
        in_func   = func_idxs >= 0
        fi_v      = func_idxs[in_func]

        # Per-function counts via bincount
        n_total = np.bincount(fi_v, minlength=n_funcs)
        n_bl    = np.bincount(fi_v[is_bl[in_func]], minlength=n_funcs)
        n_bcbwd = np.bincount(fi_v[is_bc_bwd[in_func]], minlength=n_funcs)
        n_blr   = np.bincount(fi_v[is_blr[in_func]], minlength=n_funcs)
        n_ptr   = np.bincount(fi_v[is_ptr[in_func]], minlength=n_funcs)
        n_li0   = np.bincount(fi_v[is_li0[in_func]], minlength=n_funcs)
        n_li1   = np.bincount(fi_v[is_li1[in_func]], minlength=n_funcs)

        # Self-call detection: BL target lands in same function as the BL instruction
        bl_in_func = is_bl & in_func
        bl_fi  = func_idxs[bl_in_func]
        tgt_fi = np.searchsorted(fa, bl_tgts[bl_in_func], side='right') - 1
        is_self = (bl_fi == tgt_fi) & (tgt_fi >= 0)
        n_self  = np.bincount(bl_fi[is_self], minlength=n_funcs)

        # Null-check at entry: cmp0 within the first 8 words of each function.
        # Strategy: for each cmp0 position, compute how many instructions into
        # its function it falls; mark function as having early cmp0 if < 8.
        cmp0_pos = np.where(is_cmp0 & in_func)[0]
        func_starts_word = np.searchsorted(insn_vas, fa, side='left')  # word-index of each func start
        has_cmp0_entry = np.zeros(n_funcs, dtype=bool)
        if len(cmp0_pos):
            cmp0_fi = func_idxs[cmp0_pos]  # function each cmp0 belongs to
            cmp0_offset = cmp0_pos - func_starts_word[cmp0_fi]  # offset within function (in words)
            early = cmp0_offset < 8
            # Mark each function that has at least one early cmp0
            early_fi = cmp0_fi[early]
            if len(early_fi):
                has_cmp0_entry[early_fi] = True

        # ── Build result dict ─────────────────────────────────────────────────

        result: Dict[int, DynDSFeatures] = {}
        for fi in np.where(n_total >= min_insns)[0].tolist():
            result[int(fa[fi])] = DynDSFeatures(
                va            = int(fa[fi]),
                n_insns       = int(n_total[fi]),
                n_bl          = int(n_bl[fi]),
                n_self_calls  = int(n_self[fi]),
                n_backward_bc = int(n_bcbwd[fi]),
                n_blr         = int(n_blr[fi]),
                n_ptr_chain   = int(n_ptr[fi]),
                has_cmp0_entry= bool(has_cmp0_entry[fi]),
                has_li0       = bool(n_li0[fi] > 0),
                has_li1       = bool(n_li1[fi] > 0),
            )
        return result

    # ── Feature extraction — pure Python fallback ─────────────────────────────

    def _extract_features_python(self, min_insns: int) -> Dict[int, DynDSFeatures]:
        buf     = self._code_data
        buf_len = len(buf)
        code_va = self._code_va
        fa      = self._func_starts

        result: Dict[int, DynDSFeatures] = {}
        for fi, fva in enumerate(fa):
            f_end = fa[fi + 1] if fi + 1 < len(fa) else code_va + buf_len
            f_off = fva - code_va
            e_off = min(f_end - code_va, buf_len - 3)
            if f_off < 0 or f_off >= e_off:
                continue

            n_insns = n_bl = n_self = n_bcbwd = n_blr = n_ptr = n_li0 = n_li1 = 0
            has_cmp0_entry = False

            for i, off in enumerate(range(f_off, e_off, 4)):
                n_insns += 1
                w = int.from_bytes(buf[off:off+4], 'big')
                op = w >> 26

                # BL
                if op == _OP_B and (w & 1) and not ((w >> 1) & 1):
                    n_bl += 1
                    li = (w >> 2) & 0xFFFFFF
                    if li >= 0x800000:
                        li -= 0x1000000
                    tgt = code_va + off + li * 4
                    if tgt == fva:
                        n_self += 1

                # BC backward
                elif op == _OP_BC and not (w & 1) and not ((w >> 1) & 1):
                    bd = (w >> 2) & 0x3FFF
                    if bd >= 0x2000:
                        bd -= 0x4000
                    if bd < 0:
                        n_bcbwd += 1

                # BLR
                elif w == _BLR_WORD:
                    n_blr += 1

                # CMP rX, 0
                elif op in (_OP_CMPLWI, _OP_CMPWI) and (w & 0xFFFF) == 0:
                    if i < 8:
                        has_cmp0_entry = True

                # LI rD, 0/1
                elif op == _OP_ADDI and ((w >> 16) & 0x1F) == 0:
                    simm = w & 0xFFFF
                    if simm == 0:
                        n_li0 += 1
                    elif simm == 1:
                        n_li1 += 1

                # Pointer self-load
                elif op in (_OP_LWZ, _OP_LD):
                    rD = (w >> 21) & 0x1F
                    rA = (w >> 16) & 0x1F
                    if rD == rA and rA != 0:
                        n_ptr += 1

            if n_insns < min_insns:
                continue
            result[fva] = DynDSFeatures(
                va=fva, n_insns=n_insns, n_bl=n_bl, n_self_calls=n_self,
                n_backward_bc=n_bcbwd, n_blr=n_blr, n_ptr_chain=n_ptr,
                has_cmp0_entry=has_cmp0_entry,
                has_li0=n_li0 > 0, has_li1=n_li1 > 0,
            )
        return result

    # ── Reporting ─────────────────────────────────────────────────────────────

    def report(
        self,
        findings: List[DynDSFinding],
        name_fn=None,
        top_n: int = 80,
    ) -> str:
        """Format findings as a pattern-grouped table."""
        if not findings:
            return "DynDSClassifier: no findings"
        by_pat = self.by_pattern(findings)
        sections: List[str] = [
            f"DynDSClassifier — {len(findings)} findings across "
            f"{len(by_pat)} pattern(s)"
        ]
        for pattern in sorted(by_pat, key=lambda p: -_PRIORITY.get(p, 0)):
            group = by_pat[pattern]
            sections.append(
                f"\n[{pattern}] — {len(group)} function(s)\n" + "-" * 68
            )
            for finding in group[:top_n]:
                sections.append("  " + finding.fmt(name_fn))
            if len(group) > top_n:
                sections.append(f"  ... {len(group) - top_n} more")
        return "\n".join(sections)

    def by_pattern(
        self,
        findings: List[DynDSFinding],
    ) -> Dict[str, List[DynDSFinding]]:
        """Group findings by pattern label."""
        groups: Dict[str, List[DynDSFinding]] = {}
        for f in findings:
            groups.setdefault(f.pattern, []).append(f)
        return groups

    def summary(self, findings: List[DynDSFinding]) -> str:
        """One-line count per pattern."""
        by_pat = self.by_pattern(findings)
        parts = []
        for pat in sorted(by_pat, key=lambda p: -_PRIORITY.get(p, 0)):
            parts.append(f"{pat}={len(by_pat[pat])}")
        return "DynDSClassifier: " + "  ".join(parts) if parts else "no findings"
