"""
sig_library.py -- Function signature matching for stripped binaries.

Matches unknown stripped functions against a behavioral signature library using
the same BERT model already loaded for semantic search. A match above the
confidence threshold renames the function in the corpus (e.g. fn_0x1d700
becomes likely:memcpy).

Architecture:
  SigLibrary.load()           -- loads sigs.json, encodes all descriptions once
  SigLibrary.match(function_desc) -> SigMatch | None
  SigLibrary.auto_name(corpus_db) -> int  -- renames all ANGR_INFERRED fns in DB

Usage:
    from ablation.analyzers.sig_library import SigLibrary

    lib = SigLibrary()
    lib.load_model()  # loads sentence-transformers model

    match = lib.match_description("copies bytes from src to dst; no bounds check")
    if match:
        print(f"likely:{match.name}  confidence={match.score:.3f}")

    # Auto-name all functions in a corpus DB
    n = lib.auto_name('/tmp/ablation_demo.db')
    print(f"Named {n} functions")
"""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import numpy as np

_SIGS_JSON = Path(__file__).parent.parent / 'data' / 'sigs.json'
_CACHE_DIR = Path('~/.ablation/sig_cache').expanduser()
_MODEL_NAME = 'sentence-transformers/all-mpnet-base-v2'
_DEFAULT_THRESHOLD = 0.62


@dataclass
class SigMatch:
    name: str
    aliases: List[str]
    category: str
    cwe_risk: Optional[str]
    score: float

    def label(self) -> str:
        return f"likely:{self.name}"


class SigLibrary:
    """
    Behavioral function signature library.

    Encodes each signature description once with BERT, then does cosine similarity
    against incoming function descriptions.  Subsequent calls use the cached
    embedding matrix -- matching 40 signatures costs ~1ms per function.
    """

    def __init__(
        self,
        sigs_path: str = str(_SIGS_JSON),
        threshold: float = _DEFAULT_THRESHOLD,
    ):
        self._sigs_path = Path(sigs_path)
        self.threshold = threshold
        self._sigs: List[dict] = []
        self._vectors: Optional[np.ndarray] = None
        self._model = None
        self._load_sigs()

    def _load_sigs(self):
        with open(self._sigs_path) as f:
            data = json.load(f)
        self._sigs = data.get('signatures', [])

    def load_model(self):
        """Load the sentence-transformers model (shared with SemanticSearcher)."""
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(_MODEL_NAME, device='cpu')
        self._ensure_vectors()

    def _cache_path(self) -> Path:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        import hashlib
        h = hashlib.sha256(self._sigs_path.read_bytes()).hexdigest()[:12]
        return _CACHE_DIR / f'sig_vectors_{h}.pkl'

    def _ensure_vectors(self):
        if self._vectors is not None:
            return

        cache = self._cache_path()
        if cache.exists():
            with open(cache, 'rb') as f:
                self._vectors = pickle.load(f)
            return

        descriptions = [s['description'] for s in self._sigs]
        self._vectors = self._model.encode(
            descriptions,
            normalize_embeddings=True,
            show_progress_bar=False,
            batch_size=64,
        ).astype(np.float32)

        with open(cache, 'wb') as f:
            pickle.dump(self._vectors, f)

    def match_description(self, description: str) -> Optional[SigMatch]:
        """
        Match a function description string against all signatures.
        Returns the best match if score >= threshold, else None.
        """
        if self._model is None or self._vectors is None:
            raise RuntimeError("call load_model() first")
        if not description.strip():
            return None

        q = self._model.encode(
            description,
            normalize_embeddings=True,
            show_progress_bar=False,
        ).astype(np.float32)

        scores = self._vectors @ q
        best_idx = int(np.argmax(scores))
        best_score = float(scores[best_idx])

        if best_score < self.threshold:
            return None

        sig = self._sigs[best_idx]
        return SigMatch(
            name=sig['name'],
            aliases=sig.get('aliases', []),
            category=sig.get('category', ''),
            cwe_risk=sig.get('cwe_risk'),
            score=best_score,
        )

    def match_function(
        self,
        name: str,
        call_targets: str,
        string_xrefs: str,
        notes: str = '',
    ) -> Optional[SigMatch]:
        """
        Match a function record (as stored in func_id_db) against signatures.
        Builds a behavioral description from the DB fields, then matches.
        """
        # Fast path: if the function already has a meaningful name, skip matching
        if name and not name.startswith(('fn_', 'sub_', 'loc_')):
            return None

        # Build a description from what we know about the function
        parts = []
        if call_targets and call_targets not in ('[]', 'null', ''):
            try:
                callees = json.loads(call_targets)
                if callees:
                    named = [c for c in callees if not c.startswith(('0x', 'fn_', 'sub_'))]
                    if named:
                        parts.append(f"calls {', '.join(named[:5])}")
            except Exception:
                pass

        if string_xrefs and string_xrefs not in ('[]', 'null', ''):
            try:
                strings = json.loads(string_xrefs)
                if strings:
                    parts.append(f"references strings: {', '.join(str(s) for s in strings[:3])}")
            except Exception:
                pass

        if notes:
            parts.append(notes)

        if not parts:
            return None

        desc = '; '.join(parts)
        return self.match_description(desc)

    def auto_name(self, db_path: str, dry_run: bool = False) -> int:
        """
        Scan func_id_db for ANGR_INFERRED functions with placeholder names
        (fn_0x...) and rename them using signature matching.

        Returns the number of functions renamed.
        """
        import sqlite3

        if self._model is None:
            self.load_model()

        con = sqlite3.connect(str(Path(db_path).expanduser()))
        rows = con.execute(
            """SELECT va, name, call_targets, string_xrefs, notes
               FROM functions
               WHERE confidence = 'ANGR_INFERRED'
               AND (name LIKE 'fn_%' OR name LIKE 'sub_%')"""
        ).fetchall()

        renamed = 0
        for va, name, call_targets, string_xrefs, notes in rows:
            match = self.match_function(
                name,
                call_targets or '[]',
                string_xrefs or '[]',
                notes or '',
            )
            if match is None:
                continue

            new_name = match.label()
            if not dry_run:
                con.execute(
                    "UPDATE functions SET name = ? WHERE va = ?",
                    (new_name, va),
                )
            renamed += 1

        if not dry_run:
            con.commit()
        con.close()
        return renamed

    def known_signatures(self) -> List[dict]:
        return list(self._sigs)


# ── CLI ────────────────────────────────────────────────────────────────────────

def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="Match function signatures in a corpus DB")
    ap.add_argument("db", help="func_id DB path (e.g. ~/.ablation/func_id.db)")
    ap.add_argument("--threshold", type=float, default=_DEFAULT_THRESHOLD)
    ap.add_argument("--dry-run", action="store_true", help="report matches without writing")
    ap.add_argument("--list", action="store_true", help="list all signatures in the library")
    args = ap.parse_args()

    lib = SigLibrary(threshold=args.threshold)

    if args.list:
        for s in lib.known_signatures():
            print(f"  {s['name']:<25s} [{s['category']}]  {s['description'][:60]}")
        return

    print("Loading model ...")
    lib.load_model()
    print(f"Matching {len(lib._sigs)} signatures against {args.db} ...")
    n = lib.auto_name(args.db, dry_run=args.dry_run)
    tag = "(dry-run) would rename" if args.dry_run else "renamed"
    print(f"{tag} {n} functions")


if __name__ == "__main__":
    _cli()
