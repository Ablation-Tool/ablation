"""
Ablation plugin for Binary Ninja.

Installation:
    1. Copy this file to your Binary Ninja plugins directory:
         macOS : ~/Library/Application Support/Binary Ninja/plugins/
         Linux : ~/.binaryninja/plugins/
         Windows: %APPDATA%\\Binary Ninja\\plugins\\
    2. Restart Binary Ninja.
    3. Use the "Ablation" menu or run Sweep from Tools > Ablation.

What it does:
  - On binary open: checks ~/.ablation/func_id.db for an existing corpus entry
    (matched by SHA-256). If found, renames functions and adds "likely:*" tags.
  - Ablation > Sweep Binary: runs a full pattern sweep on the open binary.
    Results appear as bookmarks with score annotations.
  - Ablation > Semantic Search: prompts for a plain-English query, highlights
    the top-k matching functions in the current view.
  - Ablation > Show Findings: lists all findings from the local findings DB
    in a side panel.

Requirements: ablation package must be installed in the same Python environment
that Binary Ninja uses. Verify with: import ablation from Binary Ninja's Python
console.
"""

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Optional

try:
    import binaryninja as bn
    from binaryninja import BinaryView, Function, PluginCommand
    from binaryninjaui import UIContext
    _BN_AVAILABLE = True
except ImportError:
    _BN_AVAILABLE = False

_DB_PATH = Path("~/.ablation/func_id.db").expanduser()
_SWEEP_TAG = "Ablation-Sweep"
_SIG_TAG   = "Ablation-Sig"


# ── helpers ───────────────────────────────────────────────────────────────────

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def _db_has_binary(binary_sha: str) -> bool:
    if not _DB_PATH.exists():
        return False
    con = sqlite3.connect(str(_DB_PATH))
    row = con.execute(
        "SELECT 1 FROM binaries WHERE sha256 LIKE ? LIMIT 1", (binary_sha + "%",)
    ).fetchone()
    con.close()
    return row is not None


def _load_corpus(binary_sha: str):
    """Return {va: name} for functions matching this binary's SHA."""
    if not _DB_PATH.exists():
        return {}
    con = sqlite3.connect(str(_DB_PATH))
    rows = con.execute(
        """SELECT f.va, f.name FROM functions f
           JOIN binaries b ON f.binary_id = b.id
           WHERE b.sha256 LIKE ?""",
        (binary_sha + "%",),
    ).fetchall()
    con.close()
    return {va: name for va, name in rows}


# ── plugin actions ────────────────────────────────────────────────────────────

def annotate_from_corpus(bv: BinaryView):
    """Load Ablation corpus names into Binary Ninja function list."""
    if not _DB_PATH.exists():
        bn.show_message_box(
            "Ablation",
            f"No corpus DB found at {_DB_PATH}.\n\n"
            "Run:  ablation corpus <binary>  to build one.",
        )
        return

    sha = _sha256(bv.file.filename)
    corpus = _load_corpus(sha)
    if not corpus:
        bn.show_message_box(
            "Ablation",
            f"No corpus entry for this binary (SHA {sha[:8]}).\n\n"
            "Run:  ablation corpus " + bv.file.filename,
        )
        return

    tag_type = bv.get_tag_type(_SIG_TAG) or bv.create_tag_type(_SIG_TAG, "A")
    renamed = 0
    for func in bv.functions:
        va = func.start
        if va in corpus:
            new_name = corpus[va]
            if new_name and not new_name.startswith(("fn_", "sub_")):
                func.name = new_name
                renamed += 1

    bn.show_message_box("Ablation", f"Applied corpus names to {renamed} functions.")


def sweep_binary(bv: BinaryView):
    """Run Ablation pattern sweep and bookmark results."""
    try:
        from ablation.analyzers.corpus_builder import CorpusBuilder
        from ablation.analyzers.semantic_search import SemanticSearcher
        from ablation.analyzers.pattern_library import PatternLibrary
    except ImportError:
        bn.show_message_box(
            "Ablation",
            "ablation package not found in this Python environment.\n"
            "Install with: pip install ablation",
        )
        return

    path = bv.file.filename
    bn.show_message_box("Ablation", "Building corpus... this may take 30s on first run.")

    tmp_db = Path(f"/tmp/ablation_binja_{Path(path).stem}.db")
    cb = CorpusBuilder(db_path=str(tmp_db))
    cb.build(path, product=Path(path).stem, version="binja", progress=False)

    searcher = SemanticSearcher(str(tmp_db))
    searcher.build_corpus()

    pl = PatternLibrary()
    results = pl.sweep(searcher, top_k=5, min_score=0.30)

    tag_type = bv.get_tag_type(_SWEEP_TAG) or bv.create_tag_type(_SWEEP_TAG, "!")

    hits_total = 0
    for query, sr in results.items():
        for va, score in sr.hits:
            func = bv.get_function_at(va)
            if func:
                msg = f"[{sr.tag}] {query[:60]} (score={score:.3f})"
                func.add_tag(tag_type, msg)
                hits_total += 1

    bn.show_message_box(
        "Ablation",
        f"Sweep complete: {hits_total} pattern hits across {len(results)} patterns.\n"
        "Results tagged with '!' in the function list.",
    )


def semantic_search(bv: BinaryView):
    """Prompt for a query and navigate to the top result."""
    try:
        from ablation.analyzers.corpus_builder import CorpusBuilder
        from ablation.analyzers.semantic_search import SemanticSearcher
    except ImportError:
        bn.show_message_box("Ablation", "ablation package not found.")
        return

    query = bn.get_text_line_input("Query", "Ablation Semantic Search")
    if not query:
        return

    path = bv.file.filename
    tmp_db = Path(f"/tmp/ablation_binja_{Path(path).stem}.db")

    if not tmp_db.exists():
        cb = CorpusBuilder(db_path=str(tmp_db))
        cb.build(path, product=Path(path).stem, version="binja", progress=False)

    searcher = SemanticSearcher(str(tmp_db))
    searcher.build_corpus()

    results = searcher.query(query, top_k=10)
    if not results:
        bn.show_message_box("Ablation", f"No results for: {query!r}")
        return

    # Jump to highest-scoring result
    best = results[0]
    bv.navigate(bv.view, best.va)

    summary = "\n".join(
        f"  0x{r.va:x}  {r.name or 'unknown':<40s}  {r.score:.3f}"
        for r in results[:10]
    )
    bn.show_message_box(
        "Ablation",
        f"Top results for: {query!r}\n\nNavigated to 0x{best.va:x}\n\n{summary}",
    )


# ── register commands ─────────────────────────────────────────────────────────

if _BN_AVAILABLE:
    PluginCommand.register(
        "Ablation\\Annotate from Corpus",
        "Load Ablation corpus function names into Binary Ninja",
        annotate_from_corpus,
    )
    PluginCommand.register(
        "Ablation\\Sweep Binary",
        "Run full Ablation pattern sweep and bookmark results",
        sweep_binary,
    )
    PluginCommand.register(
        "Ablation\\Semantic Search",
        "Search for functions by plain-English behavioral description",
        semantic_search,
    )
