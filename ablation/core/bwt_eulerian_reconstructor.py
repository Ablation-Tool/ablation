"""BWT full-text Eulerian circuit reconstructor.

Why this exists
---------------
IBM's installp multi-cycle BWT (K < 256) leaves part of the original text
T_step4 unrecoverable when following the LF-map from the recorded bwt_index.
For automountd (U828079.bff, K=56, n=199,196):

    19 disjoint cycles; bwt_index=794 lies in the main cycle (111,380 bytes).
    T_step4[0..87815] are unrecoverable by LF-map traversal from bwt_index.

An Eulerian circuit on the K-node directed multigraph of the BWT last-column
visits every row exactly once and produces a valid candidate ordering for the
full text T_step4.  The circuit is guaranteed to exist because every node
(byte value) has equal in-degree and out-degree in the transition graph:
    node u→v edge: row r contributes L[r]→F_byte[r] (F_byte = sorted(L)).

Key definitions:
    L = bwt_last (last column of BWT matrix, length n).
    F_byte[r] = sorted(L)[r] (F-column byte value at row r; NOT the LF-map).
    Node: byte value b in {0..255} that appears in L.
    Edge: (L[r], F_byte[r]) for each row r.  Multigraph: same edge weight may
          appear multiple times.

The circuit order yields a candidate T_step4 sequence.  IBM's proprietary cycle
ordering in liblpp.a is not derivable from the BWT data alone; this module
produces A valid Eulerian circuit, not necessarily IBM's.  The
``verify_against_known_segment`` method reports where the circuit matches a
known partial T_step4 segment (e.g., the main-cycle bwt_buf).

Edge selection policies
-----------------------
Different policies explore the IBM circuit-ordering space:

    GREEDY        First available edge (adjacency list order).
    NON_MAIN_FIRST  Edges leaving non-main-cycle nodes are preferred.
    BWT_INDEX_FIRST Start from the known bwt_index node before circuit build.

Empirical results (automountd K=56, n=199,196):
    GREEDY: T_step4[87816]=0x6e ≠ bwt_buf[0]=0x01.  Not IBM's ordering.
    NON_MAIN_FIRST: same mismatch.
    IBM's cycle ordering requires liblpp.a; cannot be derived from this data.
"""

from __future__ import annotations

import enum

import numpy as np


class EdgePolicy(enum.Enum):
    """Edge selection policy for Hierholzer's algorithm."""
    GREEDY = "greedy"
    NON_MAIN_FIRST = "non_main_first"
    BWT_INDEX_FIRST = "bwt_index_first"


class BwtEulerianReconstructor:
    """Reconstruct full BWT text via Eulerian circuit on K-node multigraph.

    The circuit visits every row of the BWT matrix exactly once, yielding a
    199,196-byte (for automountd) candidate T_step4.  The ordering is A valid
    Eulerian circuit; IBM's specific ordering requires proprietary liblpp.a.

    Usage::

        rec = BwtEulerianReconstructor(bwt_last)
        circuit = rec.reconstruct(policy=EdgePolicy.GREEDY)
        # circuit is a bytes object of length n containing T_step4 candidate
        match = rec.verify_against_known_segment(circuit, known_segment, offset)
    """

    def __init__(self, bwt_last: bytes | np.ndarray) -> None:
        """
        Parameters
        ----------
        bwt_last:
            The L column of the BWT matrix (last column).  Length n = total
            BWT text size.  All byte values must be in the K-byte common
            alphabet (no rare bytes; this is the post-step4-encoded text).
        """
        if isinstance(bwt_last, (bytes, bytearray)):
            self._L = np.frombuffer(bwt_last, dtype=np.uint8)
        else:
            self._L = np.asarray(bwt_last, dtype=np.uint8)
        self._n = len(self._L)
        self._F_byte: np.ndarray | None = None
        self._adjacency: dict[int, list[int]] | None = None

    @property
    def n(self) -> int:
        return self._n

    def _build_f_byte(self) -> np.ndarray:
        """F_byte[r] = sorted(L)[r] — the F-column byte values."""
        if self._F_byte is None:
            self._F_byte = np.sort(self._L)
        return self._F_byte

    def _build_adjacency(self) -> dict[int, list[int]]:
        """Build adjacency list: node b → list of row indices r where L[r] = b.

        Each row r contributes directed edge L[r] → F_byte[r].  The adjacency
        list for node b is the ordered list of row indices leaving b.
        """
        if self._adjacency is not None:
            return self._adjacency
        F = self._build_f_byte()
        adj: dict[int, list[int]] = {}
        for r in range(self._n):
            b = int(self._L[r])
            if b not in adj:
                adj[b] = []
            adj[b].append(r)
        self._adjacency = adj
        return adj

    def cycle_structure(self) -> dict[int, int]:
        """Return {cycle_id: length} for all disjoint LF-map cycles.

        The LF-map lf_map[r] is the standard BWT LF-function.  Cycle
        structure determines how many cycles partition the text.

        Returns a dict mapping an arbitrary cycle representative (first row
        visited) to the cycle length.
        """
        F = self._build_f_byte()
        L = self._L
        cumcount = np.zeros(256, dtype=np.int64)
        for v in range(255):
            cumcount[v + 1] = cumcount[v] + np.sum(L == v)
        rank_arr = np.zeros(self._n, dtype=np.int64)
        cnt = np.zeros(256, dtype=np.int64)
        for r in range(self._n):
            b = int(L[r])
            rank_arr[r] = cnt[b]
            cnt[b] += 1
        lf_map = cumcount[L.astype(np.int64)] + rank_arr

        visited = np.zeros(self._n, dtype=bool)
        cycles: dict[int, int] = {}
        for start in range(self._n):
            if visited[start]:
                continue
            cur = start
            length = 0
            while not visited[cur]:
                visited[cur] = True
                cur = int(lf_map[cur])
                length += 1
            cycles[start] = length
        return cycles

    def reconstruct(
        self,
        policy: EdgePolicy = EdgePolicy.GREEDY,
        start_node: int | None = None,
        main_cycle_rows: set[int] | None = None,
    ) -> bytes:
        """Run Hierholzer's algorithm under the given edge selection policy.

        Parameters
        ----------
        policy:
            Edge selection strategy (see ``EdgePolicy``).
        start_node:
            Byte value to start the circuit from.  If None: GREEDY starts
            from the numerically smallest node in the graph; NON_MAIN_FIRST
            starts from a non-main-cycle node if one exists.
        main_cycle_rows:
            Set of row indices belonging to the main BWT cycle.  Required
            for NON_MAIN_FIRST policy.  Derived from ``cycle_structure()``
            in combination with the bwt_index.

        Returns
        -------
        bytes
            Eulerian circuit as a byte sequence of length n.  Each byte is
            F_byte[r] for each row r in circuit order; this equals the
            T_step4 text in IBM's ordering IFF the circuit matches IBM's.
        """
        adj = self._build_adjacency()
        F = self._build_f_byte()

        adj_working: dict[int, list[int]] = {k: list(v) for k, v in adj.items()}
        used = np.zeros(self._n, dtype=bool)

        nodes = sorted(adj_working.keys())
        if not nodes:
            return b''

        if start_node is None:
            if policy == EdgePolicy.NON_MAIN_FIRST and main_cycle_rows:
                for node in nodes:
                    rows = adj_working[node]
                    if rows and any(r not in main_cycle_rows for r in rows):
                        start_node = node
                        break
            if start_node is None:
                start_node = nodes[0]

        ptr: dict[int, int] = {b: 0 for b in nodes}

        stack = [start_node]
        circuit_rows: list[int] = []

        while stack:
            v = stack[-1]
            rows = adj_working.get(v, [])
            advanced = False

            if policy == EdgePolicy.NON_MAIN_FIRST and main_cycle_rows:
                # Prefer the first unused non-main edge from current ptr position.
                # Scan forward; if none found before end of list, fall through to
                # the standard scan below which picks any unused edge.
                # NOTE: worst-case O(n²) if every edge is main-cycle — acceptable
                # for RE analysis where n < 200K and non-main edges are plentiful.
                save = ptr[v]
                while ptr[v] < len(rows):
                    r = rows[ptr[v]]
                    if not used[r] and r not in main_cycle_rows:
                        break
                    ptr[v] += 1
                else:
                    ptr[v] = save  # no non-main found; restore for standard fallback

            while ptr[v] < len(rows) and used[rows[ptr[v]]]:
                ptr[v] += 1

            if ptr[v] < len(rows):
                r = rows[ptr[v]]
                ptr[v] += 1
                used[r] = True
                w = int(F[r])
                stack.append(w)
                circuit_rows.append(r)
                advanced = True

            if not advanced:
                stack.pop()

        if len(circuit_rows) != self._n:
            raise RuntimeError(
                f"Eulerian circuit incomplete: got {len(circuit_rows)} edges, "
                f"expected {self._n}.  Graph may not be Eulerian."
            )

        result = bytearray(self._n)
        for i, r in enumerate(circuit_rows):
            result[i] = int(F[r])
        return bytes(result)

    def verify_against_known_segment(
        self,
        circuit: bytes,
        known_segment: bytes,
        offset: int,
    ) -> dict[str, object]:
        """Compare a circuit reconstruction against a known T_step4 segment.

        Parameters
        ----------
        circuit:
            Full Eulerian circuit output from ``reconstruct()``.
        known_segment:
            A verified partial T_step4 sequence (e.g., main-cycle bwt_buf
            decoded through step4).
        offset:
            Position in the circuit where known_segment should appear.

        Returns
        -------
        dict with keys:
            match (bool): True if circuit[offset:offset+len] == known_segment.
            mismatch_pos (int|None): First differing position, or None.
            circuit_byte (int|None): circuit byte at mismatch_pos.
            expected_byte (int|None): known_segment byte at mismatch_pos.
            match_count (int): Number of matching prefix bytes.
        """
        seg_len = len(known_segment)
        window = circuit[offset: offset + seg_len]
        if window == known_segment:
            return {
                "match": True,
                "mismatch_pos": None,
                "circuit_byte": None,
                "expected_byte": None,
                "match_count": seg_len,
            }
        mismatch_pos = next(
            (i for i, (a, b) in enumerate(zip(window, known_segment)) if a != b),
            min(len(window), seg_len),
        )
        return {
            "match": False,
            "mismatch_pos": mismatch_pos,
            "circuit_byte": window[mismatch_pos] if mismatch_pos < len(window) else None,
            "expected_byte": known_segment[mismatch_pos] if mismatch_pos < seg_len else None,
            "match_count": mismatch_pos,
        }
