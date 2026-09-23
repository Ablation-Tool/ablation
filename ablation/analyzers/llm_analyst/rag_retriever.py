"""
rag_retriever.py — Retrieves prior RE findings from func_id_db for LLM context injection.

Retrieval strategy (ordered by signal strength):
  1. Exact VA + binary match — same function we've confirmed before
  2. Callee-set overlap — functions sharing PLT imports are in the same family
  3. Role-based — known functions in the same role class
  4. Name fuzzy match — LIKE search on func_id_db name column

Results are ranked, deduped, and trimmed to a token budget before injection.
No vector DB required — all retrieval is SQLite queries against func_id_db.
"""

from __future__ import annotations

import json
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────

_MAX_RESULTS = 8
_MAX_IMPORT_OVERLAP_RESULTS = 4


class RAGRetriever:
    def __init__(self, func_db):
        self._db = func_db

    def retrieve(
        self,
        func_addr:     int,
        binary_sha256: str = '',
        callees:       list[str] | None = None,
        role_hint:     str = '',
        name_hint:     str = '',
    ) -> list[dict]:
        """
        Retrieve prior findings relevant to the function under analysis.
        Returns a list of finding dicts ready for context_builder injection.
        """
        seen_ids = set()
        results = []

        def _add(rows):
            for r in rows:
                rid = r.get('id')
                if rid in seen_ids:
                    continue
                seen_ids.add(rid)
                results.append(self._trim_row(r))

        # 1. Exact binary + VA match — highest confidence prior
        if binary_sha256:
            _add(self._exact_match(binary_sha256, func_addr))

        # 2. Callee-set overlap — strongest structural signal
        if callees:
            _add(self._callee_overlap(callees, limit=_MAX_IMPORT_OVERLAP_RESULTS))

        # 3. Role-based — prior functions in the same role class
        if role_hint:
            _add(self._db.match_by_role(role_hint)[:_MAX_IMPORT_OVERLAP_RESULTS])

        # 4. Name fuzzy — useful when we have a partial name from strings
        if name_hint:
            _add(self._db.match_by_name(name_hint)[:3])

        return results[:_MAX_RESULTS]

    # ── retrieval strategies ──────────────────────────────────────────────────

    def _exact_match(self, binary_sha256: str, va: int) -> list[dict]:
        con = self._db._con
        rows = con.execute(
            'SELECT f.*, b.sha256 AS binary_sha256, b.product, b.version'
            ' FROM functions f JOIN binaries b ON f.binary_id=b.id'
            ' WHERE b.sha256=? AND f.va=?',
            (binary_sha256, va)
        ).fetchall()
        return [dict(r) for r in rows]

    def _callee_overlap(self, callees: list[str], limit: int = 4) -> list[dict]:
        """
        Find functions in func_id_db that share at least one callee with the
        target function. Callees are PLT import names (e.g., 'strcpy', 'malloc').
        """
        if not callees:
            return []
        con = self._db._con
        results = []
        # Search each callee name independently, then deduplicate by caller rank
        seen = set()
        for callee in callees:
            rows = con.execute(
                'SELECT f.*, b.sha256 AS binary_sha256, b.product, b.version'
                ' FROM functions f JOIN binaries b ON f.binary_id=b.id'
                " WHERE f.call_targets LIKE ? AND f.confidence='CONFIRMED'",
                (f'%{callee}%',)
            ).fetchall()
            for r in rows:
                rid = r['id']
                if rid not in seen:
                    seen.add(rid)
                    results.append(dict(r))
            if len(results) >= limit * 2:
                break

        # Rank by how many callees match (more overlap = more relevant)
        callee_set = set(callees)

        def overlap_score(row):
            try:
                targets = json.loads(row.get('call_targets', '[]'))
                return sum(1 for t in targets if t in callee_set)
            except Exception:
                return 0

        results.sort(key=overlap_score, reverse=True)
        return results[:limit]

    # ── output normalization ──────────────────────────────────────────────────

    def _trim_row(self, row: dict) -> dict:
        """Trim a func_id_db row to fields relevant for LLM context injection."""
        return {
            'id':         row.get('id'),
            'name':       row.get('name', ''),
            'role':       row.get('role', ''),
            'confidence': row.get('confidence', ''),
            'product':    row.get('product', ''),
            'version':    row.get('version', ''),
            'notes':      (row.get('notes') or '')[:200],
            'va':         row.get('va', 0),
        }
