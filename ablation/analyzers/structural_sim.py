"""
Custom structural similarity for cross-version stripped binary function matching.

Replaces PLT-call Jaccard with a weighted composite that works on ALL functions,
not just the 12% that have 2+ external PLT calls.

Five signals (weights adjusted for signal availability per pair):
  1. Opcode category histogram : cosine similarity of 12-category frequency vectors
  2. Immediate value Jaccard   : shared constants (magic bytes, struct offsets, sizes)
  3. PLT call overlap          : external function call set (existing signal, lower weight)
  4. Branch density proximity  : control flow shape (linear / switch / loop-heavy)
  5. Size proximity            : instruction count ratio

Immediates are the key unlock: RIP-relative offsets are filtered (position-dependent),
but struct field offsets, magic constants, and buffer sizes survive recompilation.
"""

import re
from collections import Counter
from typing import NamedTuple

import numpy as np


# ---------------------------------------------------------------------------
# Opcode category mapping (12 BinFuse-style categories)
# ---------------------------------------------------------------------------

_OPCODE_CATS = {
    # data movement
    "mov": "DATA", "movs": "DATA", "movz": "DATA", "movq": "DATA",
    "lea": "DATA", "push": "DATA", "pop": "DATA", "xchg": "DATA",
    "movap": "DATA", "movup": "DATA", "movdq": "DATA", "movsd": "DATA",
    "movss": "DATA", "lddqu": "DATA", "vmov": "DATA",
    # arithmetic
    "add": "ARITH", "sub": "ARITH", "imul": "ARITH", "mul": "ARITH",
    "div": "ARITH", "idiv": "ARITH", "inc": "ARITH", "dec": "ARITH",
    "neg": "ARITH", "adc": "ARITH", "sbb": "ARITH",
    # bitwise
    "and": "BIT", "or": "BIT", "xor": "BIT", "not": "BIT",
    "shl": "BIT", "shr": "BIT", "sar": "BIT", "rol": "BIT", "ror": "BIT",
    "bsf": "BIT", "bsr": "BIT", "bt": "BIT", "bts": "BIT",
    # compare/test
    "cmp": "CMP", "test": "CMP", "cmov": "CMP",
    # branch
    "jmp": "BRANCH", "je": "BRANCH", "jne": "BRANCH", "jl": "BRANCH",
    "jle": "BRANCH", "jg": "BRANCH", "jge": "BRANCH", "jb": "BRANCH",
    "jbe": "BRANCH", "ja": "BRANCH", "jae": "BRANCH", "js": "BRANCH",
    "jns": "BRANCH", "jp": "BRANCH", "jnp": "BRANCH", "jo": "BRANCH",
    "jno": "BRANCH", "jrcxz": "BRANCH", "loop": "BRANCH",
    "jecxz": "BRANCH",
    # call / ret
    "call": "CALL", "ret": "RET", "retn": "RET",
    # stack frame
    "enter": "FRAME", "leave": "FRAME",
    # memory string ops
    "rep": "MEMOP", "movs": "MEMOP", "stos": "MEMOP", "lods": "MEMOP",
    "scas": "MEMOP", "cmps": "MEMOP",
    # float
    "fld": "FLOAT", "fst": "FLOAT", "fadd": "FLOAT", "fsub": "FLOAT",
    "fmul": "FLOAT", "fdiv": "FLOAT", "fcom": "FLOAT", "fxch": "FLOAT",
    # SSE/AVX
    "addss": "SIMD", "addsd": "SIMD", "addps": "SIMD", "subss": "SIMD",
    "mulss": "SIMD", "divss": "SIMD", "sqrts": "SIMD", "xmm": "SIMD",
    "pcmp": "SIMD", "pand": "SIMD", "por": "SIMD", "pxor": "SIMD",
    "padd": "SIMD", "psub": "SIMD", "punpck": "SIMD", "packss": "SIMD",
    "movdqa": "SIMD", "movaps": "SIMD", "movdqu": "SIMD",
    # misc
    "nop": "NOP", "endbr": "NOP", "ud2": "NOP",
    "syscall": "SYSCALL", "int": "SYSCALL",
    "cpuid": "MISC", "rdtsc": "MISC", "mfence": "MISC",
}

_BRANCH_MNEMS = frozenset([
    "call", "jmp", "je", "jne", "jl", "jle", "jg", "jge",
    "jb", "jbe", "ja", "jae", "js", "jns", "jp", "jnp",
    "jo", "jno", "jrcxz", "jecxz", "loop", "loope", "loopne",
])

_IMM_RE = re.compile(r"0x([0-9a-f]{2,})", re.IGNORECASE)


def _categorize(mnem: str) -> str:
    mnem = mnem.lower()
    # exact match first
    if mnem in _OPCODE_CATS:
        return _OPCODE_CATS[mnem]
    # prefix match (handles cmovne -> CMP, movaps -> DATA, etc.)
    for prefix_len in (5, 4, 3, 2):
        prefix = mnem[:prefix_len]
        if prefix in _OPCODE_CATS:
            return _OPCODE_CATS[prefix]
    return "OTHER"


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

class FunctionFingerprint(NamedTuple):
    va: int
    n_insns: int
    opcode_hist: dict    # category -> fraction of total insns
    immediates: frozenset  # int values: struct offsets, magic bytes, sizes
    calls: list          # PLT-resolved call names
    branch_density: float  # branch insns / total insns


def extract_fingerprint(
    va: int,
    insns: list,   # list of instruction strings "mnemonic op_str"
    calls: list,   # from disasm_function (PLT-resolved or 0x... addresses)
) -> FunctionFingerprint:
    """Build a FunctionFingerprint from disassembly output."""
    n = len(insns)
    if n == 0:
        return FunctionFingerprint(
            va=va, n_insns=0,
            opcode_hist={}, immediates=frozenset(),
            calls=calls, branch_density=0.0,
        )

    cat_counts: Counter = Counter()
    imm_set: set = set()
    n_branches = 0

    for line in insns:
        parts = line.split(None, 1)
        mnem = parts[0].lower()
        op_str = parts[1] if len(parts) > 1 else ""

        cat = _categorize(mnem)
        cat_counts[cat] += 1

        if cat == "BRANCH":
            n_branches += 1

        # Immediate extraction: skip branches/calls (code addresses)
        # and RIP-relative (position-dependent data addresses)
        if mnem in _BRANCH_MNEMS:
            continue
        if "rip" in op_str:
            continue

        for m in _IMM_RE.finditer(op_str):
            val = int(m.group(1), 16)
            # Keep: larger offsets, magic values, buffer sizes
            # Skip: trivial small constants (0-0xff): these are generic struct offsets
            # that appear in thousands of functions. Values >= 0x100 are discriminative.
            if 0x100 <= val <= 0xFFFFFFFF:
                imm_set.add(val)

    # Normalize histogram to fractions
    opcode_hist = {cat: count / n for cat, count in cat_counts.items()}

    return FunctionFingerprint(
        va=va,
        n_insns=n,
        opcode_hist=opcode_hist,
        immediates=frozenset(imm_set),
        calls=calls,
        branch_density=n_branches / n,
    )


# ---------------------------------------------------------------------------
# Similarity
# ---------------------------------------------------------------------------

_CATS_ORDERED = [
    "DATA", "ARITH", "BIT", "CMP", "BRANCH", "CALL", "RET",
    "FLOAT", "SIMD", "MEMOP", "FRAME", "NOP", "SYSCALL", "MISC", "OTHER",
]


def fingerprint_sim(fp_a: FunctionFingerprint, fp_b: FunctionFingerprint) -> float:
    """
    Weighted composite similarity [0, 1]. Weights are normalized based on
    which signals are available for the given pair.

    Base weights (before normalization):
      opcode histogram : 0.35  (always available)
      immediates       : 0.30  (only if both functions have immediates)
      PLT calls        : 0.20  (only if either function has PLT calls)
      branch density   : 0.10  (always available)
      size proximity   : 0.05  (always available)
    """
    components: list = []  # (score, weight)

    # 1. Size proximity
    sz_ratio = fp_b.n_insns / max(fp_a.n_insns, 1)
    # 1.0 at same size, 0.0 at 3x or 0.33x
    sz_score = max(0.0, 1.0 - abs(1.0 - sz_ratio) / 0.67)
    components.append((sz_score, 0.05))

    # 2. Opcode histogram cosine
    va = np.array([fp_a.opcode_hist.get(c, 0.0) for c in _CATS_ORDERED])
    vb = np.array([fp_b.opcode_hist.get(c, 0.0) for c in _CATS_ORDERED])
    na, nb = np.linalg.norm(va), np.linalg.norm(vb)
    op_score = float(np.dot(va, vb) / (na * nb)) if na > 0 and nb > 0 else 0.0
    components.append((op_score, 0.35))

    # 3. Immediate value Jaccard (only when both have immediates)
    imm_a, imm_b = fp_a.immediates, fp_b.immediates
    if imm_a and imm_b:
        imm_j = len(imm_a & imm_b) / len(imm_a | imm_b)
        components.append((imm_j, 0.30))

    # 4. PLT call Jaccard (only when either has named calls)
    named_a = frozenset(c for c in fp_a.calls if not c.startswith("0x"))
    named_b = frozenset(c for c in fp_b.calls if not c.startswith("0x"))
    if named_a or named_b:
        plt_j = len(named_a & named_b) / max(len(named_a | named_b), 1)
        components.append((plt_j, 0.20))

    # 5. Branch density proximity
    bd_diff = abs(fp_a.branch_density - fp_b.branch_density)
    bd_score = max(0.0, 1.0 - bd_diff * 4.0)  # 0.0 at density diff >= 0.25
    components.append((bd_score, 0.10))

    # Normalize weights (handles missing signals gracefully)
    total_w = sum(w for _, w in components)
    if total_w == 0:
        return 0.0
    return sum(s * w for s, w in components) / total_w


# ---------------------------------------------------------------------------
# Cross-version orphan detection
# ---------------------------------------------------------------------------

def find_structural_orphans(
    corpus_a: list,   # list of FunctionFingerprint (version A, baseline)
    corpus_b: list,   # list of FunctionFingerprint (version B, target)
    threshold: float = 0.40,
    min_insns: int = 20,
    progress: bool = True,
) -> list:
    """
    For each function in corpus_b, find its best structural match in corpus_a.
    Returns list of dicts for functions in B with best_score < threshold,
    sorted by best_score ascending (most isolated = most novel first).

    min_insns: skip functions smaller than this (too short for reliable matching).
    """
    # Pre-bucket corpus_a by instruction count for fast candidate retrieval
    # bucket = n_insns // 20
    bucket_size = 20
    buckets: dict = {}
    for fp in corpus_a:
        b = fp.n_insns // bucket_size
        for delta in (-2, -1, 0, 1, 2):  # ±40 insns search window
            buckets.setdefault(b + delta, []).append(fp)

    orphans = []
    total = len(corpus_b)

    for i, fp_b in enumerate(corpus_b):
        if fp_b.n_insns < min_insns:
            continue
        if progress and i % 500 == 0:
            print(f"  {i}/{total}", end="\r")

        bucket_key = fp_b.n_insns // bucket_size
        candidates = buckets.get(bucket_key, [])

        best_score = 0.0
        best_match_va = None
        for fp_a in candidates:
            score = fingerprint_sim(fp_a, fp_b)
            if score > best_score:
                best_score = score
                best_match_va = fp_a.va

        if best_score < threshold:
            imm_signal = bool(fp_b.immediates)
            named_calls = [c for c in fp_b.calls if not c.startswith("0x")]
            orphans.append({
                "va": fp_b.va,
                "n_insns": fp_b.n_insns,
                "best_score": round(best_score, 4),
                "best_match_va": best_match_va,
                "calls": named_calls[:8],
                "immediates": sorted(fp_b.immediates)[:8],
                "branch_density": round(fp_b.branch_density, 3),
                "has_imm_signal": imm_signal,
            })

    if progress:
        print(f"  {total}/{total}")

    orphans.sort(key=lambda x: x["best_score"])
    return orphans


# ---------------------------------------------------------------------------
# Score distribution helper (calibration)
# ---------------------------------------------------------------------------

def score_distribution(
    corpus_a: list,
    corpus_b: list,
    sample_n: int = 500,
    min_insns: int = 20,
    seed: int = 42,
) -> dict:
    """
    Sample score_n functions from corpus_b and compute best-match score
    distribution. Used to calibrate the orphan threshold.
    """
    import random
    random.seed(seed)

    eligible = [fp for fp in corpus_b if fp.n_insns >= min_insns]
    sample = random.sample(eligible, min(sample_n, len(eligible)))

    bucket_size = 20
    buckets: dict = {}
    for fp in corpus_a:
        b = fp.n_insns // bucket_size
        for delta in (-2, -1, 0, 1, 2):
            buckets.setdefault(b + delta, []).append(fp)

    scores = []
    for fp_b in sample:
        bucket_key = fp_b.n_insns // bucket_size
        candidates = buckets.get(bucket_key, [])
        best = max((fingerprint_sim(fp_a, fp_b) for fp_a in candidates), default=0.0)
        scores.append(best)

    scores.sort()
    n = len(scores)
    pcts = {}
    for p in [5, 10, 25, 50, 75, 90, 95]:
        idx = int(p / 100 * n)
        pcts[f"p{p:02d}"] = round(scores[idx], 4)

    return {
        "n_sampled": n,
        "mean": round(float(np.mean(scores)), 4),
        "percentiles": pcts,
        "scores": scores,
    }
