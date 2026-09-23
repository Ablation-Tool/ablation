"""
ablation.cli -- command-line interface.

Usage:
    ablation analyze <binary>              ELF/PE/Mach-O summary, strings, entropy
    ablation search  <binary> <query>      semantic search across all functions
    ablation taint   <binary>              taint trace from network sources to sinks
    ablation cfg     <binary> <va>         control-flow graph for one function (hex VA)
    ablation crypto  <binary>              entropy scan + XOR/AES key search
    ablation corpus  <binary>              build or rebuild the semantic function corpus
    ablation sweep   <binary>              run all registered patterns against a binary
    ablation findings                      list confirmed findings in ~/.ablation/findings.db
"""

import argparse
import sys
from pathlib import Path

_DEFAULT_DB = Path('~/.ablation/func_id.db').expanduser()


def _require_binary(path: str) -> Path:
    p = Path(path)
    if not p.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    return p


def _build_corpus_for(binary_path: str, db: Path) -> None:
    """Ensure func_id.db contains an up-to-date corpus entry for binary_path."""
    from ablation.analyzers.corpus_builder import CorpusBuilder
    product = Path(binary_path).stem
    cb = CorpusBuilder(db_path=str(db))
    cb.build(binary_path, product=product, version='unknown', progress=False)


def cmd_analyze(args):
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.entropy_mapper import EntropyMapper

    ctx = BinaryContext.load_or_build(str(_require_binary(args.binary)))
    print(ctx.summary())

    if args.entropy:
        em = EntropyMapper(str(args.binary))
        regions = em.scan()
        print(f"\nEntropy regions ({len(regions)} found):")
        for r in regions[:20]:
            print(f"  {r}")


def cmd_search(args):
    from ablation.analyzers.semantic_search import SemanticSearcher

    p = str(_require_binary(args.binary))
    db = Path(args.db).expanduser()

    print(f"Building corpus for {Path(p).name} ...")
    _build_corpus_for(p, db)

    searcher = SemanticSearcher(str(db))
    n = searcher.build_corpus()
    print(f"Corpus: {n} functions. Querying ...")

    results = searcher.query(args.query, top_k=args.top_k)
    if not results:
        print("No results.")
        return

    print(f"\nTop {len(results)} matches for: {args.query!r}\n")
    for r in results:
        name = r.name or hex(r.va)
        print(f"  0x{r.va:x}  {name:<50s}  score={r.score:.3f}")


def cmd_taint(args):
    from ablation.analyzers.xref_graph import XRefGraph
    from ablation.analyzers.taint_tracker_x86 import TaintTracker

    p = str(_require_binary(args.binary))
    xg = XRefGraph.from_path(p)
    xg.build()

    tracker = TaintTracker(p, xref=xg)
    findings = tracker.run()

    if not findings:
        print("No taint paths found.")
        return

    print(f"{len(findings)} taint finding(s):\n")
    for f in findings:
        print(f)


def cmd_cfg(args):
    from ablation.analyzers.cfg_builder import CFGBuilder

    p = str(_require_binary(args.binary))
    va = int(args.va, 16)

    builder = CFGBuilder(p)
    cfg = builder.build_function(va)

    s = cfg.stats()
    print(f"CFG for 0x{va:x}: {s['blocks']} blocks, {s['edges']} edges, {s['instructions']} instructions\n")
    for bb_va, bb in sorted(cfg.blocks.items()):
        succs = ', '.join(f'0x{s:x}' for s in bb.succs)
        print(f"  0x{bb_va:x}..0x{bb.end:x}  succs=[{succs}]")
        if args.insns:
            for insn_va, mnem, ops in bb.insns:
                print(f"    0x{insn_va:x}  {mnem} {ops}")


def cmd_crypto(args):
    from ablation.analyzers.crypto_audit import CryptoAudit

    p = str(_require_binary(args.binary))
    audit = CryptoAudit(p)
    report = audit.run()
    print(report)


def cmd_corpus(args):
    from ablation.analyzers.corpus_builder import CorpusBuilder

    p = str(_require_binary(args.binary))
    db = Path(args.db).expanduser()
    product = args.product or Path(p).stem
    version = args.version or 'unknown'

    cb = CorpusBuilder(db_path=str(db))
    n = cb.build(p, product=product, version=version, progress=True)
    print(f"\nCorpus built: {n} functions indexed")
    print(f"DB: {db}")


def cmd_sweep(args):
    from ablation.analyzers.semantic_search import SemanticSearcher
    from ablation.analyzers.pattern_library import PatternLibrary

    p = str(_require_binary(args.binary))
    db = Path(args.db).expanduser()

    print(f"Building corpus for {Path(p).name} ...")
    _build_corpus_for(p, db)

    searcher = SemanticSearcher(str(db))
    n = searcher.build_corpus()
    print(f"Corpus: {n} functions. Running pattern sweep ...")

    pl = PatternLibrary()
    results = pl.sweep(searcher, top_k=args.top_k, min_score=args.min_score)
    print(pl.fmt_sweep(results, binary_name=Path(p).name))


def cmd_findings(args):
    from ablation.analyzers.finding_registry import FindingRegistry

    reg = FindingRegistry()
    findings = reg.list()

    if not findings:
        print("No confirmed findings recorded.")
        return

    print(f"{len(findings)} finding(s):\n")
    for f in findings:
        print(f"  [{f.severity}] 0x{f.va:x}  {f.binary}  {f.pattern}")


def main():
    parser = argparse.ArgumentParser(
        prog='ablation',
        description='Semantic firmware analysis for vulnerability researchers.',
    )
    sub = parser.add_subparsers(dest='command', metavar='<command>')
    sub.required = True

    # analyze
    p_analyze = sub.add_parser('analyze', help='binary summary, strings, entropy')
    p_analyze.add_argument('binary')
    p_analyze.add_argument('--entropy', action='store_true', help='include entropy scan')
    p_analyze.set_defaults(func=cmd_analyze)

    # search
    p_search = sub.add_parser('search', help='semantic function search')
    p_search.add_argument('binary')
    p_search.add_argument('query')
    p_search.add_argument('--top-k', type=int, default=10)
    p_search.add_argument('--db', default=str(_DEFAULT_DB), help='func_id DB path')
    p_search.set_defaults(func=cmd_search)

    # taint
    p_taint = sub.add_parser('taint', help='taint analysis: network sources to sinks')
    p_taint.add_argument('binary')
    p_taint.set_defaults(func=cmd_taint)

    # cfg
    p_cfg = sub.add_parser('cfg', help='control-flow graph for one function')
    p_cfg.add_argument('binary')
    p_cfg.add_argument('va', help='function VA in hex, e.g. 0x1234')
    p_cfg.add_argument('--insns', action='store_true', help='print instructions')
    p_cfg.set_defaults(func=cmd_cfg)

    # crypto
    p_crypto = sub.add_parser('crypto', help='entropy scan and crypto key detection')
    p_crypto.add_argument('binary')
    p_crypto.set_defaults(func=cmd_crypto)

    # corpus
    p_corpus = sub.add_parser('corpus', help='build semantic function corpus')
    p_corpus.add_argument('binary')
    p_corpus.add_argument('--product', default=None)
    p_corpus.add_argument('--version', default=None)
    p_corpus.add_argument('--db', default=str(_DEFAULT_DB), help='func_id DB path')
    p_corpus.set_defaults(func=cmd_corpus)

    # sweep
    p_sweep = sub.add_parser('sweep', help='run all registered patterns against a binary')
    p_sweep.add_argument('binary')
    p_sweep.add_argument('--top-k', type=int, default=5)
    p_sweep.add_argument('--min-score', type=float, default=0.30)
    p_sweep.add_argument('--db', default=str(_DEFAULT_DB), help='func_id DB path')
    p_sweep.set_defaults(func=cmd_sweep)

    # findings
    p_findings = sub.add_parser('findings', help='list confirmed findings')
    p_findings.set_defaults(func=cmd_findings)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        if '--debug' in sys.argv:
            raise
        sys.exit(1)


if __name__ == '__main__':
    main()
