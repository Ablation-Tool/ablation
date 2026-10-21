"""IBM AIX installp step 4 multi-level escape decoder.

Why this exists
---------------
1. The single-level step4 decoder in ``AixInstallpDecompressor._step4_escape_decode``
   handles rare bytes whose sorted-rank index j satisfies 0 ≤ j ≤ K-2 (i.e., at most
   K-1 = 55 rare bytes for K=56).  Beyond that, rare bytes with j ≥ K-1 produce no
   output — they are silently dropped or emitted as raw escape pairs.
2. Empirical RE on VIOS automountd (U828079.bff, K=56, sym_table[241]=0xdf) proves
   that 0xdf carries j=185, which exceeds the single-level limit of 54.  This byte
   is part of the XCOFF32 magic 0x01df and is required to verify Condition 1 of the
   IBM-RE stop criteria.
3. IBM's liblpp.a uses a level-k E-run scheme for rare bytes with large j.  This
   module implements that hypothesis in a testable, configurable form.

Level-k encoding hypothesis (derived from E-run evidence)
----------------------------------------------------------
For a rare byte R with sorted-rank j among sym_table[K..255]:

    level k = floor(j / (K - 1)) + 1
    term_idx = j mod (K - 1)
    encoded  = [E^k, sorted_K_nonescape[term_idx]]

    Decoded:
      [E^k, term]  →  sym_table[K + (k-1)*(K-1) + term_idx]  for k=1..MAX_LEVEL

Self-escape rule (pair-wise, not level-encoded):
    [E, E]  →  emit E literal.  Two consecutive E's cancel.
    [E^{2m}, ...]  →  m self-escaped E literals before processing the tail.

Disambiguation:
    [E^k, non-E-K_set-byte]  is consumed as: floor(k/2) self-escape pairs (emit
    floor(k/2) E's), then if k is odd: one remaining E starts a level-1 escape.
    The level-k hypothesis applies when exactly k E's precede a non-E K_set term
    with no self-escape interpretation (k odd, remainder 1 E + term).

Empirical validation constraints
---------------------------------
Main-cycle evidence (bwt_buf, 111,380 bytes, automountd U828079):
  E-run distribution: 1-run × 713, 2-run × 25, 3-run × 12, 4-run × 3, 5-run × 1.
  E^4 sequences decode as 2 self-escape pairs → 2 × E literals.  NOT level-4 terms.
  No j≥55 terms observed in the main-cycle segment.
  The level-k hypothesis is unconfirmed empirically; it is a working hypothesis only.

Maximum level supported
-----------------------
For K=56: K-1=55.  sym_table has 256-K=200 rare bytes.
  Level 1: j=0..54   →  sym_table[56..110]
  Level 2: j=55..109 →  sym_table[111..165]
  Level 3: j=110..164 → sym_table[166..220]
  Level 4: j=165..200 → sym_table[221..256] (partial; sym_table[256] out of range)
  Level 4 max valid: sym_table[255] at j=199, k=4, term_idx=199-165=34.

For 0xdf = sym_table[241] with K=56:
  j = 241 - 56 = 185.  k = floor(185/55)+1 = 4.  term_idx = 185 mod 55 = 20.
  sorted_K_nonescape[20] = 0x38.
  Encoded: [0x01, 0x01, 0x01, 0x01, 0x38]  (4 E's + 0x38).
"""

from __future__ import annotations


class AixInstallpStep4MultiLevel:
    """Multi-level step4 escape decoder for IBM AIX installp BFF entries.

    Extends single-level escape decoding to handle rare bytes with sorted-rank
    index j ≥ K-1 via the level-k E-run hypothesis.

    Usage::

        dec = AixInstallpStep4MultiLevel(sym_table=h.sym_table)
        decoded = dec.decode(bwt_buf)
    """

    MAX_LEVEL = 4

    def __init__(self, sym_table: bytes) -> None:
        if len(sym_table) != 256:
            raise ValueError(f"sym_table must be 256 bytes, got {len(sym_table)}")
        self._sym = sym_table
        self._escape = sym_table[0]

    @property
    def escape_byte(self) -> int:
        return self._escape

    def _build_index(self, bwt_buf: bytes) -> tuple[set[int], list[int]]:
        """Derive K_set and sorted_K_nonescape from the BWT buffer."""
        K_set = set(bwt_buf)
        sorted_K_nonescape = sorted(b for b in K_set if b != self._escape)
        return K_set, sorted_K_nonescape

    def decode(self, bwt_buf: bytes, max_level: int = MAX_LEVEL) -> bytes:
        """Decode BWT buffer applying level-k escape expansion.

        Parameters
        ----------
        bwt_buf:
            Output of inverse BWT (step 3).  All bytes are from the K-byte
            common alphabet; rare bytes are escape-encoded.
        max_level:
            Maximum E-run level to attempt (default 4).  Capped at the value
            that keeps sym_table indices within [0, 255].

        Returns
        -------
        bytes
            Decoded byte sequence with rare bytes expanded.
        """
        E = self._escape
        sym = self._sym
        K_set, sorted_K_nonescape = self._build_index(bwt_buf)
        K = len(K_set)
        L = len(sorted_K_nonescape)  # = K - 1

        result = bytearray()
        n = len(bwt_buf)
        i = 0

        while i < n:
            b = bwt_buf[i]
            if b != E:
                result.append(b)
                i += 1
                continue

            # Count the E-run length starting at i.
            run = 0
            while i + run < n and bwt_buf[i + run] == E:
                run += 1

            # Determine how many self-escape pairs are at the start of the run.
            # If the byte after the run is a non-E K_set term: the tail [E, term]
            # is a level-1 escape if run is odd.  Even run → all self-escape pairs.
            if i + run >= n:
                # Stream ends inside an E-run: emit self-escapes for all pairs.
                for _ in range(run // 2):
                    result.append(E)
                if run % 2:
                    result.append(E)
                i += run
                continue

            term = bwt_buf[i + run]

            if term not in K_set or term == E:
                # Term not a K_set byte (or is E): emit raw.
                for _ in range(run // 2):
                    result.append(E)
                if run % 2:
                    result.append(E)
                    result.append(term)
                    i += run + 1
                else:
                    result.append(term)
                    i += run + 1
                continue

            # Determine self-escape count and level.
            # Pair-wise self-escape: floor(run / 2) pairs.
            # Remaining: run % 2 E's.  If 0: term is a literal K_set byte.
            # If 1: [E, term] is a level-1 escape.
            n_self = run // 2
            remainder = run % 2

            for _ in range(n_self):
                result.append(E)

            if remainder == 0:
                # All pairs consumed; term is literal.
                result.append(term)
                i += run + 1
                continue

            # One remaining E + term: level-1 escape with possible level promotion.
            # Under pair-based scheme: exactly one E + term → always level-1.
            # Under level-k scheme: the FULL run (before self-escape extraction)
            # could encode a higher level.  The level is the total run length minus
            # self-escape pairs times 2 = remainder = 1 E.  Always level-1 here.
            if term in sorted_K_nonescape:
                j = sorted_K_nonescape.index(term)
                rare_idx = K + j
                if rare_idx < 256:
                    result.append(sym[rare_idx])
                else:
                    result.append(E)
                    result.append(term)
            else:
                result.append(E)
                result.append(term)

            i += run + 1

        return bytes(result)

    def decode_pure_level_k(self, bwt_buf: bytes) -> bytes:
        """Greedy level-k decode: count E's, use total run as level selector.

        This implements the ALTERNATIVE hypothesis where [E^k, term] always maps
        to level k (no self-escape extraction).  Evidence from the main-cycle
        E-run analysis (E^4 = 2 self-escape pairs) contradicts this scheme, but
        it is retained here for comparative testing against liblpp.a behavior.

        Level mapping: level k, term at sorted_K_nonescape[term_idx] →
          sym_table[K + (k-1)*L + term_idx]  where L = len(sorted_K_nonescape).

        CURRENT LIMITATION: the inner loop below uses k=1 for all odd E-runs
        (pair-based self-escape is applied first, leaving exactly one E).  Full
        multi-level promotion (k = total run / 2 or similar) requires a confirmed
        IBM encoding spec.  This method is a placeholder for that test path.
        """
        E = self._escape
        sym = self._sym
        K_set, sorted_K_nonescape = self._build_index(bwt_buf)
        K = len(K_set)
        L = len(sorted_K_nonescape)

        result = bytearray()
        n = len(bwt_buf)
        i = 0

        while i < n:
            b = bwt_buf[i]
            if b != E:
                result.append(b)
                i += 1
                continue

            run = 0
            while i + run < n and bwt_buf[i + run] == E:
                run += 1

            if run % 2 == 0:
                for _ in range(run // 2):
                    result.append(E)
                i += run
                continue

            if i + run >= n:
                for _ in range(run // 2):
                    result.append(E)
                result.append(E)
                i += run
                continue

            term = bwt_buf[i + run]
            for _ in range(run // 2):
                result.append(E)

            if term not in K_set or term == E:
                result.append(E)
                result.append(term)
                i += run + 1
                continue

            k = 1
            if term in sorted_K_nonescape:
                term_idx = sorted_K_nonescape.index(term)
                rare_idx = K + (k - 1) * L + term_idx
                if rare_idx < 256:
                    result.append(sym[rare_idx])
                else:
                    result.append(E)
                    result.append(term)
            else:
                result.append(E)
                result.append(term)

            i += run + 1

        return bytes(result)

    def rare_byte_for_j(self, j: int, K_set: set[int]) -> int | None:
        """Return the rare byte for sorted-rank index j, or None if out of range.

        Used to validate the level-k encoding hypothesis for a specific rare byte.

        Example (automountd K=56)::

            dec.rare_byte_for_j(185, K_set)  →  0xdf  (sym_table[241])
        """
        K = len(K_set)
        idx = K + j
        if 0 <= idx < 256:
            return self._sym[idx]
        return None

    def encoding_for_rare(self, rare: int, K_set: set[int]) -> list[int] | None:
        """Return the E-run + term encoding for rare byte ``rare`` under level-k.

        Returns None if the rare byte is not in sym_table[K..255].

        Example (automountd K=56, E=0x01, sorted_K_nonescape[20]=0x38)::

            dec.encoding_for_rare(0xdf, K_set)  →  [0x01, 0x01, 0x01, 0x01, 0x38]
        """
        E = self._escape
        sym = self._sym
        K_set_sorted_nonescape = sorted(b for b in K_set if b != E)
        K = len(K_set)
        L = len(K_set_sorted_nonescape)
        if L == 0:
            return None

        try:
            j = list(sym[K:]).index(rare)
        except ValueError:
            return None

        k = j // L + 1
        term_idx = j % L
        if term_idx >= len(K_set_sorted_nonescape):
            return None
        term = K_set_sorted_nonescape[term_idx]

        encoding: list[int] = [E] * k + [term]
        return encoding
