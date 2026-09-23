"""
subsequence_searcher.py -- Behavioral subsequence pattern search.

Finds all functions in a binary that contain a specified behavioral
sub-pattern. Two modes:

1. Exact: "find all functions containing [COMPARISON_OP, CONDITIONAL_OP,
   DATA_TRANSFER_OP, UNCONDITIONAL_OP] in sequence" -- literal subsequence
   match with optional wildcards.

2. DTW approximate: sliding window DTW to find approximate matches,
   warp-invariant (handles small insertions within the pattern).

3. "Like this function": use an existing function's sequence as the pattern
   and find all similar functions in the binary.

Primary RE use cases:
- "Find all handlers that look like the exec handler" (search_like)
- "Find all functions with a cmp+jmp+syscall pattern" (search)
- "Find all functions containing a Tcl_Eval call followed by no error check" (search)

Usage:
    ss = SubsequenceSearcher.from_path('/path/to/binary', ctx=ctx)

    # Exact pattern with wildcards (None = any category):
    pattern = [CAT_INDEX['COMPARISON_OP'], CAT_INDEX['CONDITIONAL_OP'],
               None, CAT_INDEX['UNCONDITIONAL_OP']]
    results = ss.search(pattern)

    # Pattern from category names (more readable):
    pattern = ss.pattern('COMPARISON_OP CONDITIONAL_OP * UNCONDITIONAL_OP')
    results = ss.search(pattern)

    # DTW approximate sliding window:
    results = ss.search_dtw(ref_seq, threshold=0.6)

    # Find functions similar to an existing function:
    results = ss.search_like(ref_va=0x1000, end_va=0x1200, top_k=10)
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from .opseq import OpSeqEncoder, CAT_INDEX, CAT_NAMES, NUM_CATS
from .dtw_matcher import dtw_similarity


# ── pattern spec ──────────────────────────────────────────────────────────────

def parse_pattern(spec: str) -> List[Optional[int]]:
    """
    Parse a pattern string into a List[Optional[int]].

    Accepts category names (case-insensitive, with or without _OP suffix)
    or '*' for wildcard.

    Examples:
        'COMPARISON_OP CONDITIONAL_OP * UNCONDITIONAL_OP'
        'comparison conditional * unconditional'
        'C J * U'   (using seq_to_str abbreviations)
    """
    ABBREV = {
        'A': 'ARITHMETIC_OP', 'D': 'DATA_TRANSFER_OP', 'C': 'COMPARISON_OP',
        'L': 'LOGIC_OP', 'S': 'BIT_SHIFT_OP', 'U': 'UNCONDITIONAL_OP',
        'J': 'CONDITIONAL_OP', 'M': 'MEMORY_MGMT_OP', 'P': 'PROCESSOR_STATE_OP',
        'Y': 'SYNCHRONIZATION_OP', 'V': 'VECTOR_MGMT_OP', '?': 'OTHER_OP',
    }
    result: List[Optional[int]] = []
    for token in spec.upper().split():
        if token == '*':
            result.append(None)  # wildcard
            continue
        # Try exact match
        if token in CAT_INDEX:
            result.append(CAT_INDEX[token])
            continue
        # Try without _OP suffix
        with_op = token + '_OP'
        if with_op in CAT_INDEX:
            result.append(CAT_INDEX[with_op])
            continue
        # Try abbreviation
        if token in ABBREV:
            result.append(CAT_INDEX[ABBREV[token]])
            continue
        # Try integer
        try:
            result.append(int(token))
            continue
        except ValueError:
            pass
        raise ValueError(f"Unknown pattern token: {token!r}")
    return result


def _pattern_matches(seq: List[int], pattern: List[Optional[int]], start: int) -> bool:
    """Check if pattern matches seq starting at position start."""
    for i, p in enumerate(pattern):
        if start + i >= len(seq):
            return False
        if p is not None and seq[start + i] != p:
            return False
    return True


def _find_pattern_occurrences(
    seq: List[int],
    pattern: List[Optional[int]],
) -> List[int]:
    """Return all start positions in seq where pattern matches."""
    plen = len(pattern)
    return [i for i in range(len(seq) - plen + 1) if _pattern_matches(seq, pattern, i)]


# ── result types ──────────────────────────────────────────────────────────────

@dataclass
class PatternMatch:
    func_va: int
    binary: str
    match_offsets: List[int]  # instruction positions where pattern was found
    seq_len: int
    score: float = 1.0  # 1.0 for exact, <1.0 for DTW approximate

    def __str__(self) -> str:
        name = Path(self.binary).name
        offsets_str = ','.join(f"+{o}" for o in self.match_offsets[:5])
        return (
            f"0x{self.func_va:x}  {name}  "
            f"offsets=[{offsets_str}]  score={self.score:.3f}  len={self.seq_len}"
        )


# ── main class ────────────────────────────────────────────────────────────────

class SubsequenceSearcher:
    """
    Behavioral subsequence pattern search over a binary's functions.

    Answers: "which functions in this binary contain this behavioral pattern?"

    Three search modes:
    1. Exact: literal category sequence with optional wildcards
    2. DTW: sliding window approximate match (warp-invariant)
    3. Like: find functions similar to an existing function
    """

    def __init__(
        self,
        binary_path: str,
        ctx=None,
    ):
        self._path = binary_path
        self._enc = OpSeqEncoder(binary_path)
        self._ctx = ctx
        self._func_seqs: Optional[Dict[int, List[int]]] = None

    @classmethod
    def from_path(cls, binary_path: str, ctx=None) -> "SubsequenceSearcher":
        return cls(binary_path, ctx)

    # ── pattern helper ────────────────────────────────────────────────────────

    @staticmethod
    def pattern(spec: str) -> List[Optional[int]]:
        """Parse a pattern spec string. See module docstring for format."""
        return parse_pattern(spec)

    # ── exact search ──────────────────────────────────────────────────────────

    def search(
        self,
        pattern: List[Optional[int]],
        min_func_len: int = 4,
        max_funcs: int = 20000,
    ) -> List[PatternMatch]:
        """
        Find all functions containing the exact (wildcard-aware) pattern.

        Returns matches sorted by number of occurrences (most occurrences first).
        """
        results: List[PatternMatch] = []
        for va, seq in self._iter_funcs(max_funcs):
            if len(seq) < min_func_len:
                continue
            offsets = _find_pattern_occurrences(seq, pattern)
            if offsets:
                results.append(PatternMatch(
                    func_va=va,
                    binary=self._path,
                    match_offsets=offsets,
                    seq_len=len(seq),
                    score=1.0,
                ))
        results.sort(key=lambda x: (-len(x.match_offsets), x.func_va))
        return results

    # ── DTW sliding window search ─────────────────────────────────────────────

    def search_dtw(
        self,
        ref_seq: List[int],
        threshold: float = 0.6,
        window_scale: float = 1.5,
        max_funcs: int = 20000,
    ) -> List[PatternMatch]:
        """
        Find functions containing a subsequence approximately matching ref_seq.

        Uses sliding window DTW: for each function, slides a window of
        len(ref_seq) * window_scale over the sequence and scores each window.

        threshold: minimum similarity score (0..1) to report a match.
        """
        ref_len = len(ref_seq)
        win_len = int(ref_len * window_scale)
        results: List[PatternMatch] = []

        for va, seq in self._iter_funcs(max_funcs):
            if len(seq) < ref_len:
                continue
            best_score = 0.0
            best_offset = 0
            # Slide window over function sequence
            for i in range(0, len(seq) - ref_len + 1, max(1, ref_len // 4)):
                end = min(i + win_len, len(seq))
                window = seq[i:end]
                score = dtw_similarity(ref_seq, window)
                if score > best_score:
                    best_score = score
                    best_offset = i
            if best_score >= threshold:
                results.append(PatternMatch(
                    func_va=va,
                    binary=self._path,
                    match_offsets=[best_offset],
                    seq_len=len(seq),
                    score=best_score,
                ))

        results.sort(key=lambda x: -x.score)
        return results

    # ── "search like this function" ───────────────────────────────────────────

    def search_like(
        self,
        ref_va: int,
        end_va: int = 0,
        top_k: int = 10,
        threshold: float = 0.5,
        mode: str = 'dtw',
        max_funcs: int = 20000,
    ) -> List[PatternMatch]:
        """
        Find functions behaviorally similar to the function at ref_va.

        mode: 'dtw' (default) or 'sax' (faster pre-filter).

        Example: find all handlers that look like the stress exec handler.
            ss.search_like(ref_va=0x1000, end_va=0x1200, top_k=10)
        """
        ref_seq = self._enc.encode_va(ref_va, end_va)
        if not ref_seq:
            return []

        if mode == 'dtw':
            results = self.search_dtw(ref_seq, threshold=threshold, max_funcs=max_funcs)
        else:
            # SAX pre-filter then DTW score
            from .sax_index import SAXIndex, encode_sax
            ref_word = encode_sax(ref_seq)
            results_all = self.search_dtw(ref_seq, threshold=threshold, max_funcs=max_funcs)
            results = results_all

        # Exclude the reference function itself
        results = [r for r in results if r.func_va != ref_va]
        return results[:top_k]

    # ── pattern frequency analysis ────────────────────────────────────────────

    def pattern_frequency(
        self,
        patterns: Dict[str, List[Optional[int]]],
        max_funcs: int = 20000,
    ) -> Dict[str, int]:
        """
        Count how many functions contain each named pattern.

        Returns {pattern_name: count_of_functions_containing_it}.

        Useful for characterizing a binary: how many functions do
        compare-and-branch? How many call a syscall after a comparison?
        """
        counts = {name: 0 for name in patterns}
        for va, seq in self._iter_funcs(max_funcs):
            for name, pat in patterns.items():
                if _find_pattern_occurrences(seq, pat):
                    counts[name] += 1
        return counts

    def common_patterns(
        self,
        top_k: int = 20,
        ngram_len: int = 3,
        max_funcs: int = 5000,
    ) -> List[Tuple[str, int]]:
        """
        Find the most common opcode category n-grams across all functions.

        Returns [(pattern_str, count)] sorted by frequency.
        Useful for discovering what behavioral patterns are structurally common
        (and therefore NOT useful as discriminators vs. rare = interesting).
        """
        from collections import Counter
        counts: Counter = Counter()
        for va, seq in self._iter_funcs(max_funcs):
            for i in range(len(seq) - ngram_len + 1):
                gram = tuple(seq[i:i + ngram_len])
                counts[gram] += 1
        results = []
        for gram, cnt in counts.most_common(top_k):
            names = [CAT_NAMES[c] if c < len(CAT_NAMES) else f'CAT{c}' for c in gram]
            results.append((' -> '.join(n.replace('_OP','') for n in names), cnt))
        return results

    # ── iterator ──────────────────────────────────────────────────────────────

    def _iter_funcs(self, max_funcs: int = 20000):
        """Yield (func_va, seq) for each function in the binary."""
        if self._func_seqs is not None:
            for va, seq in self._func_seqs.items():
                yield va, seq
            return

        if self._ctx and self._ctx.func_starts:
            starts = self._ctx.func_starts[:max_funcs]
            for i, va in enumerate(starts):
                end_va = starts[i + 1] if i + 1 < len(starts) else 0
                seq = self._enc.encode_va(va, end_va)
                yield va, seq
        else:
            from .binary_context import BinaryContext
            ctx = BinaryContext.load_or_build(self._path)
            starts = ctx.func_starts[:max_funcs]
            for i, va in enumerate(starts):
                end_va = starts[i + 1] if i + 1 < len(starts) else 0
                seq = self._enc.encode_va(va, end_va)
                yield va, seq

    def precompute(self, max_funcs: int = 20000) -> None:
        """Pre-compute all function sequences and cache in memory for repeated queries."""
        self._func_seqs = {}
        for va, seq in self._iter_funcs(max_funcs):
            self._func_seqs[va] = seq
