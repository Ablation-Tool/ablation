"""
sax_index.py -- SAX-based fast function corpus index.

SAX (Symbolic Aggregate approXimation) encodes an opcode category sequence as
a short symbolic word. Similar sequences produce the same or nearby words,
enabling approximate nearest-neighbor lookup without running BERT on every
function.

Use as a pre-filter before SemanticSearcher: SAX narrows candidates in
microseconds, BERT scores the shortlist.

Usage:
    idx = SAXIndex(word_size=8, alphabet_size=8)
    idx.add_binary('/firmware/lib/libcdb.so', ctx=ctx)
    idx.add_binary('/firmware/lib/libdmapi.so')

    # Query by sequence:
    enc = OpSeqEncoder('/path/to/binary')
    seq = enc.encode_va(0x15a78a, 0x15a8ef)
    results = idx.query_seq(seq, top_k=10)

    # Query by function VA:
    results = idx.query_va('/path/to/binary', 0x15a78a, top_k=10)

    # Save / load index:
    idx.save('/path/to/index.pkl')
    idx2 = SAXIndex.load('/path/to/index.pkl')

    print(idx.summary())

SAX parameters:
  word_size:    length of the symbolic word (default 8)
  alphabet_size: number of symbols (default 8, maps to letters 'a'..'h')
  window:       PAA window size (default = seq_len / word_size, auto)

Implementation: histogram-based PAA (categorical sequence adaptation of
standard SAX -- uses category frequency per segment rather than mean value).
"""

from __future__ import annotations

import math
import pickle
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from .opseq import OpSeqEncoder, NUM_CATS, seq_histogram

# Gaussian breakpoints for alphabet sizes 2..20 (standard SAX breakpoints)
# Rows are breakpoints for alphabet size 2..20 (index 0 = alphabet_size 2)
_BREAKPOINTS = {
    2:  [-0.0],
    3:  [-0.431, 0.431],
    4:  [-0.674, 0.0, 0.674],
    5:  [-0.842, -0.253, 0.253, 0.842],
    6:  [-0.967, -0.431, 0.0, 0.431, 0.967],
    7:  [-1.067, -0.565, -0.180, 0.180, 0.565, 1.067],
    8:  [-1.150, -0.674, -0.319, 0.0, 0.319, 0.674, 1.150],
    10: [-1.282, -0.842, -0.524, -0.253, 0.0, 0.253, 0.524, 0.842, 1.282],
    12: [-1.382, -1.000, -0.674, -0.431, -0.210, 0.0,
         0.210, 0.431, 0.674, 1.000, 1.382],
}

def _get_breakpoints(alphabet_size: int) -> List[float]:
    if alphabet_size in _BREAKPOINTS:
        return _BREAKPOINTS[alphabet_size]
    # Linear interpolation fallback
    lo_k = max(k for k in _BREAKPOINTS if k <= alphabet_size)
    return _BREAKPOINTS[lo_k]


def _paa_histogram(seq: List[int], word_size: int) -> np.ndarray:
    """
    Piecewise Aggregate Approximation for categorical sequences.

    Divides the sequence into word_size segments and computes a histogram
    of opcode categories per segment. Returns shape (word_size, NUM_CATS).
    """
    n = len(seq)
    if n == 0 or word_size == 0:
        return np.zeros((max(word_size, 1), NUM_CATS))

    seg_len = n / word_size
    paa = np.zeros((word_size, NUM_CATS))
    for i in range(word_size):
        lo = int(round(i * seg_len))
        hi = int(round((i + 1) * seg_len))
        hi = max(hi, lo + 1)
        segment = seq[lo:hi]
        for c in segment:
            if 0 <= c < NUM_CATS:
                paa[i, c] += 1
        total = hi - lo
        if total > 0:
            paa[i] /= total
    return paa


def _paa_to_sax(paa: np.ndarray, alphabet_size: int) -> str:
    """
    Convert PAA histogram matrix to SAX word.

    For each segment, the dominant category determines the base value,
    then its frequency within the segment determines the breakpoint bin.
    """
    breakpoints = _get_breakpoints(alphabet_size)
    chars = []
    for i in range(len(paa)):
        seg = paa[i]
        # Dominant category in this segment
        dominant_cat = int(np.argmax(seg))
        dominant_freq = seg[dominant_cat]
        # Z-score the frequency relative to uniform distribution
        uniform = 1.0 / NUM_CATS
        z = (dominant_freq - uniform) / max(uniform, 1e-6)
        # Map z-score to alphabet symbol
        sym_idx = 0
        for bp in breakpoints:
            if z >= bp:
                sym_idx += 1
        sym_idx = min(sym_idx, alphabet_size - 1)
        chars.append(chr(ord('a') + sym_idx))
    return ''.join(chars)


def encode_sax(seq: List[int], word_size: int = 8, alphabet_size: int = 8) -> str:
    """Encode a category sequence as a SAX word."""
    if not seq:
        return 'a' * word_size
    paa = _paa_histogram(seq, word_size)
    return _paa_to_sax(paa, alphabet_size)


def sax_mindist(w1: str, w2: str, seq_len: int, alphabet_size: int = 8) -> float:
    """
    MINDIST lower bound on the true Euclidean distance between two sequences.

    This is the standard SAX lower bounding function. If MINDIST > threshold,
    we can prune without computing the full distance.
    """
    if len(w1) != len(w2):
        return float('inf')
    breakpoints = _get_breakpoints(alphabet_size)
    # Build lookup table for symbol distances
    n = len(w1)
    total_sq = 0.0
    for c1, c2 in zip(w1, w2):
        i1 = ord(c1) - ord('a')
        i2 = ord(c2) - ord('a')
        if abs(i1 - i2) <= 1:
            continue  # adjacent symbols: MINDIST = 0
        lo = min(i1, i2)
        hi = max(i1, i2)
        dist = breakpoints[hi - 1] - breakpoints[lo] if hi - 1 < len(breakpoints) else 0.0
        total_sq += dist * dist
    n_frac = seq_len / n if n > 0 else 1.0
    return math.sqrt(n_frac * total_sq)


# ── index entry ───────────────────────────────────────────────────────────────

@dataclass
class IndexEntry:
    binary: str
    func_va: int
    sax_word: str
    seq_len: int


@dataclass
class SAXMatch:
    binary: str
    func_va: int
    sax_word: str
    seq_len: int
    mindist: float
    edit_dist: int  # SAX word edit distance

    def __str__(self) -> str:
        name = Path(self.binary).name
        return (
            f"0x{self.func_va:x}  {name}  "
            f"sax={self.sax_word}  mindist={self.mindist:.3f}  "
            f"edit={self.edit_dist}  len={self.seq_len}"
        )


# ── main index ────────────────────────────────────────────────────────────────

class SAXIndex:
    """
    In-memory SAX index for fast approximate function corpus search.

    Encodes every function in a binary as a SAX word and builds a word ->
    [IndexEntry] lookup. Query with a sequence or function VA to find
    approximately similar functions across all indexed binaries.

    Persistence: save/load via pickle.
    """

    def __init__(self, word_size: int = 8, alphabet_size: int = 8):
        self.word_size = word_size
        self.alphabet_size = alphabet_size
        # word -> [IndexEntry]
        self._index: Dict[str, List[IndexEntry]] = defaultdict(list)
        self._total_funcs = 0

    @classmethod
    def load(cls, path: str) -> "SAXIndex":
        with open(path, 'rb') as f:
            return pickle.load(f)

    def save(self, path: str) -> None:
        with open(path, 'wb') as f:
            pickle.dump(self, f)

    # ── indexing ──────────────────────────────────────────────────────────────

    def add_binary(
        self,
        binary_path: str,
        ctx=None,
        max_funcs: int = 10000,
    ) -> int:
        """
        Index all functions in a binary.

        ctx: optional BinaryContext to get func_starts and function bounds.
        Returns number of functions indexed.
        """
        enc = OpSeqEncoder(binary_path)
        added = 0

        if ctx and ctx.func_starts:
            starts = ctx.func_starts[:max_funcs]
            for i, va in enumerate(starts):
                end_va = starts[i + 1] if i + 1 < len(starts) else 0
                seq = enc.encode_va(va, end_va)
                if len(seq) < self.word_size:
                    continue
                word = encode_sax(seq, self.word_size, self.alphabet_size)
                self._index[word].append(IndexEntry(binary_path, va, word, len(seq)))
                added += 1
        else:
            # Fallback: use XRefGraph-detected function starts
            from .binary_context import BinaryContext
            ctx2 = BinaryContext.load_or_build(binary_path)
            for i, va in enumerate(ctx2.func_starts[:max_funcs]):
                end_va = ctx2.func_starts[i + 1] if i + 1 < len(ctx2.func_starts) else 0
                seq = enc.encode_va(va, end_va)
                if len(seq) < self.word_size:
                    continue
                word = encode_sax(seq, self.word_size, self.alphabet_size)
                self._index[word].append(IndexEntry(binary_path, va, word, len(seq)))
                added += 1

        self._total_funcs += added
        return added

    def add_seq(self, binary: str, va: int, seq: List[int]) -> None:
        """Add a single pre-computed sequence to the index."""
        if len(seq) < self.word_size:
            return
        word = encode_sax(seq, self.word_size, self.alphabet_size)
        self._index[word].append(IndexEntry(binary, va, word, len(seq)))
        self._total_funcs += 1

    # ── query ─────────────────────────────────────────────────────────────────

    def query_seq(
        self,
        seq: List[int],
        top_k: int = 10,
        max_edit: int = 2,
    ) -> List[SAXMatch]:
        """
        Find the top_k most similar indexed functions for a query sequence.

        max_edit: maximum SAX word edit distance to include (controls recall).
        """
        if not seq:
            return []
        query_word = encode_sax(seq, self.word_size, self.alphabet_size)
        query_len = len(seq)

        candidates: Dict[Tuple[str, int], SAXMatch] = {}

        # Exact match first
        for entry in self._index.get(query_word, []):
            md = sax_mindist(query_word, entry.sax_word, query_len, self.alphabet_size)
            ed = 0
            candidates[(entry.binary, entry.func_va)] = SAXMatch(
                binary=entry.binary, func_va=entry.func_va,
                sax_word=entry.sax_word, seq_len=entry.seq_len,
                mindist=md, edit_dist=ed,
            )

        # Neighbors within max_edit
        if max_edit > 0:
            for word, entries in self._index.items():
                if word == query_word:
                    continue
                ed = _edit_dist(query_word, word)
                if ed > max_edit:
                    continue
                for entry in entries:
                    key = (entry.binary, entry.func_va)
                    if key in candidates:
                        continue
                    md = sax_mindist(query_word, entry.sax_word, query_len, self.alphabet_size)
                    candidates[key] = SAXMatch(
                        binary=entry.binary, func_va=entry.func_va,
                        sax_word=entry.sax_word, seq_len=entry.seq_len,
                        mindist=md, edit_dist=ed,
                    )

        results = sorted(candidates.values(), key=lambda x: (x.edit_dist, x.mindist))
        return results[:top_k]

    def query_va(
        self,
        binary_path: str,
        func_va: int,
        end_va: int = 0,
        top_k: int = 10,
        max_edit: int = 2,
    ) -> List[SAXMatch]:
        """Query by function VA in a binary."""
        enc = OpSeqEncoder(binary_path)
        seq = enc.encode_va(func_va, end_va)
        return self.query_seq(seq, top_k, max_edit)

    def sax_word(self, seq: List[int]) -> str:
        """Encode a sequence to its SAX word (without adding to index)."""
        return encode_sax(seq, self.word_size, self.alphabet_size)

    def summary(self) -> str:
        unique_words = len(self._index)
        avg_bucket = self._total_funcs / max(unique_words, 1)
        return (
            f"SAXIndex: {self._total_funcs} functions  "
            f"{unique_words} unique words  "
            f"avg bucket={avg_bucket:.1f}  "
            f"word_size={self.word_size}  alphabet={self.alphabet_size}"
        )


def _edit_dist(a: str, b: str) -> int:
    """Levenshtein edit distance between two SAX words."""
    if len(a) != len(b):
        # For same word_size, they should be equal length; count mismatches
        return sum(1 for x, y in zip(a, b) if x != y) + abs(len(a) - len(b))
    return sum(1 for x, y in zip(a, b) if x != y)
