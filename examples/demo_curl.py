#!/usr/bin/env python3
"""
Demo: analyze /usr/bin/curl (or any stripped ELF) with Ablation.

What this shows:
  1. BinaryContext  -- binary summary: func count, strings, imports
  2. XRefGraph      -- call graph + string cross-references (O(N) vectorized)
  3. CFGBuilder     -- per-function control-flow graph
  4. CorpusBuilder  -- build behavioral corpus into ~/.ablation/func_id.db
  5. SemanticSearcher -- query in plain English, get ranked function VAs

Run:
    python examples/demo_curl.py
    python examples/demo_curl.py /path/to/your/firmware.so
"""

import sys
import time
from pathlib import Path

BINARY = sys.argv[1] if len(sys.argv) > 1 else '/usr/bin/curl'
# Use a demo-specific DB so the example is self-contained and fast.
# For production use across multiple binaries, use ~/.ablation/func_id.db.
DB     = Path('/tmp/ablation_demo.db')


def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


# ── 1. Binary summary ────────────────────────────────────────────────────────

section("1 / BinaryContext -- binary summary")

from ablation.analyzers.binary_context import BinaryContext

t0 = time.perf_counter()
ctx = BinaryContext.load_or_build(BINARY)
elapsed = time.perf_counter() - t0

print(ctx.summary())
print(f"  (loaded in {elapsed:.2f}s)")


# ── 2. XRefGraph ─────────────────────────────────────────────────────────────

section("2 / XRefGraph -- call graph + string xrefs")

from ablation.analyzers.xref_graph import XRefGraph

t0 = time.perf_counter()
xg = XRefGraph.from_path(BINARY)
xg.build()
elapsed = time.perf_counter() - t0

stats = xg.stats()
print(f"  functions        : {stats['functions']}")
print(f"  PLT entries      : {stats['plt_entries']}")
print(f"  strings          : {stats['strings']}")
print(f"  call edges       : {stats['call_edges']}")
print(f"  funcs with xrefs : {stats['funcs_with_string_refs']}")
print(f"  (built in {elapsed:.2f}s)")


# ── 3. CFGBuilder ────────────────────────────────────────────────────────────

section("3 / CFGBuilder -- control-flow graph for first 3 functions")

from ablation.analyzers.cfg_builder import CFGBuilder

builder = CFGBuilder(BINARY, xref=xg)
func_starts = sorted(xg._func_starts)[:3]

for fva in func_starts:
    cfg = builder.build_function(fva)
    s   = cfg.stats()
    print(f"  0x{fva:x}  blocks={s['blocks']}  edges={s['edges']}  insns={s['instructions']}")


# ── 4. CorpusBuilder ─────────────────────────────────────────────────────────

section("4 / CorpusBuilder -- behavioral corpus -> ~/.ablation/func_id.db")

from ablation.analyzers.corpus_builder import CorpusBuilder

DB.parent.mkdir(parents=True, exist_ok=True)
t0 = time.perf_counter()
cb = CorpusBuilder(db_path=str(DB))
product = Path(BINARY).stem
n = cb.build(BINARY, product=product, version='demo', progress=True)
elapsed = time.perf_counter() - t0

print(f"\n  {n} functions indexed in {elapsed:.1f}s  ->  {DB}")


# ── 5. SemanticSearcher ──────────────────────────────────────────────────────

section("5 / SemanticSearcher -- plain-English queries")

from ablation.analyzers.semantic_search import SemanticSearcher

print("Loading sentence-transformers model (may download on first run) ...")
t0 = time.perf_counter()
searcher = SemanticSearcher(str(DB))
n = searcher.build_corpus()
elapsed = time.perf_counter() - t0
print(f"Corpus: {n} functions, embeddings built in {elapsed:.1f}s\n")

QUERIES = [
    "URL parser that copies input into a fixed-size stack buffer",
    "TLS certificate verification that can be bypassed",
    "function that reads untrusted length field and passes it to memcpy",
    "authentication check that returns success on error path",
]

for q in QUERIES:
    print(f"  Query: {q!r}")
    results = searcher.query(q, top_k=3)
    for r in results:
        name = r.name or 'sub_' + hex(r.va)[2:]
        print(f"    0x{r.va:x}  {name:<45s}  score={r.score:.3f}")
    print()

print("Done.")
