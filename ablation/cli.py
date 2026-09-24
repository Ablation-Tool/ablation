"""
ablation.cli -- command-line interface.

Usage:
    ablation analyze  <binary>              binary summary: arch, PLT, exports, funcs
    ablation search   <binary> <query>      semantic search across all functions
    ablation taint    <binary>              taint trace from network sources to sinks (arch-aware)
    ablation overflow <binary>              ARM32 integer overflow scan (MUL -> malloc without check)
    ablation window   <binary> <va>         annotated disassembly window around a VA
    ablation profile  <binary> <va>         full function profile: strings + call args + sinks
    ablation cfg      <binary> <va>         control-flow graph for one function (hex VA)
    ablation crypto   <binary>              entropy scan + XOR/AES key search
    ablation corpus   <binary>              build or rebuild the semantic function corpus
    ablation sweep    <binary>              run all registered patterns against a binary
    ablation findings                       list confirmed findings in ~/.ablation/findings.db

claude.ai workflow (no Claude Code access):
    Run any command above, copy the output, paste into claude.ai.
    ablation analyze  gives the full binary context block to start a session.
    ablation window   gives disassembly you can ask claude.ai to annotate.
    ablation taint    gives source-to-sink findings to ask about.
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
    from ablation.analyzers.binary_context import BinaryContext

    p = str(_require_binary(args.binary))
    ctx = BinaryContext.load_or_build(p)

    if ctx.arch == 'arm32':
        from ablation.analyzers.taint_tracker_arm32 import ARM32TaintTracker
        tracker = ARM32TaintTracker.from_context(ctx)
        findings = tracker.run_interprocedural()
        if not findings:
            print("No taint paths found.")
            return
        print(tracker.report(findings))
    else:
        from ablation.analyzers.xref_graph import XRefGraph
        from ablation.analyzers.taint_tracker_x86 import TaintTracker
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


def cmd_overflow(args):
    """ARM32 integer overflow scan: MUL/UMULL with wire-controlled operands before allocation."""
    from ablation.analyzers.binary_context import BinaryContext

    p = str(_require_binary(args.binary))
    ctx = BinaryContext.load_or_build(p)

    if ctx.arch != 'arm32':
        print(f"overflow scan is ARM32-only (binary arch: {ctx.arch})")
        return

    from ablation.analyzers.intoverflow_scanner_arm32 import ARM32IntOverflowScanner
    scanner = ARM32IntOverflowScanner.from_context(ctx)
    findings = scanner.scan()
    print(scanner.report(findings))


def cmd_window(args):
    """Annotated disassembly window around a VA -- suitable for pasting into claude.ai."""
    from ablation.analyzers.window_analyzer import WindowAnalyzer

    p = str(_require_binary(args.binary))
    va = int(args.va, 16)
    back = args.back
    window = args.window

    wa = WindowAnalyzer.from_path(p)
    text = wa.dump_text(va=va, window=window, align_back=back, header=True)
    print(text)

    if args.calls:
        calls = wa.calls_in_window(va=va, window=window, align_back=back)
        if calls:
            print(f"\nCall sites ({len(calls)}):")
            for site, target, label in calls:
                tag = f"  -> {label}" if label else ""
                print(f"  0x{site:x}  ->  0x{target:x}{tag}")

    if args.funcs:
        starts = wa.find_func_starts(va=va, window=window, align_back=back)
        if starts:
            print(f"\nFunction starts ({len(starts)}):")
            for s in starts:
                print(f"  0x{s:x}")


def cmd_profile(args):
    """Full function profile: strings + call site args + sink flags."""
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.func_profiler import FuncProfiler

    p = str(_require_binary(args.binary))
    va = int(args.va, 16)
    ctx = BinaryContext.load_or_build(p)

    fp = FuncProfiler.from_context(ctx)
    profile = fp.profile(va=va)
    print(profile.fmt())

    if profile.sink_calls:
        print(f"\nSink calls ({len(profile.sink_calls)}):")
        for sc in profile.sink_calls:
            print(f"  0x{sc.va:x}  {sc.target_name}  [SINK]")


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

    if args.sigs:
        from ablation.analyzers.sig_library import SigLibrary
        print("\nRunning signature matching on unnamed functions ...")
        lib = SigLibrary()
        renamed = lib.auto_name(str(db), dry_run=False)
        if renamed:
            print(f"Renamed {renamed} fn_0x* functions via signature matching")
        else:
            print("No unnamed functions matched known signatures")


def cmd_sweep(args):
    import json as _json
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

    if args.sarif:
        from ablation.export.sarif import sweep_to_sarif
        doc = sweep_to_sarif(results, binary_path=p, min_score=args.min_score)
        Path(args.sarif).write_text(_json.dumps(doc, indent=2))
        print(f"SARIF written to {args.sarif}")
    elif args.json:
        from ablation.export.json_export import sweep_to_json
        doc = sweep_to_json(results, binary_path=p, min_score=args.min_score)
        Path(args.json).write_text(_json.dumps(doc, indent=2))
        print(f"JSON written to {args.json}")
    else:
        print(pl.fmt_sweep(results, binary_name=Path(p).name))


def cmd_findings(args):
    import json as _json
    from ablation.analyzers.finding_registry import FindingRegistry

    reg = FindingRegistry()
    findings = reg.list_findings()

    if not findings:
        print("No confirmed findings recorded.")
        return

    if args.sarif:
        from ablation.export.sarif import findings_to_sarif
        doc = findings_to_sarif(findings)
        Path(args.sarif).write_text(_json.dumps(doc, indent=2))
        print(f"SARIF written to {args.sarif}")
        return

    if args.json:
        from ablation.export.json_export import findings_to_json
        doc = findings_to_json(findings)
        Path(args.json).write_text(_json.dumps(doc, indent=2))
        print(f"JSON written to {args.json}")
        return

    print(f"{len(findings)} finding(s):\n")
    for f in findings:
        print(f"  [{f.get('severity','?')}] {f.get('product','')}  {f.get('title','')}")


def cmd_sigs(args):
    from ablation.analyzers.sig_library import SigLibrary

    lib = SigLibrary(threshold=args.threshold)

    if args.list:
        for s in lib.known_signatures():
            print(f"  {s['name']:<25s} [{s.get('category','')}]  {s['description'][:60]}")
        return

    db = Path(args.db).expanduser()
    if not db.exists():
        print(f"error: DB not found: {db}", file=sys.stderr)
        sys.exit(1)

    print("Loading model ...")
    lib.load_model()
    print(f"Matching {len(lib.known_signatures())} signatures against {db.name} ...")
    n = lib.auto_name(str(db), dry_run=args.dry_run)
    tag = "(dry-run) would rename" if args.dry_run else "renamed"
    print(f"{tag} {n} functions")


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
    p_taint = sub.add_parser('taint', help='taint analysis: network sources to sinks (arch-aware)')
    p_taint.add_argument('binary')
    p_taint.set_defaults(func=cmd_taint)

    # overflow
    p_overflow = sub.add_parser('overflow', help='ARM32 integer overflow scan: MUL -> alloc without check')
    p_overflow.add_argument('binary')
    p_overflow.set_defaults(func=cmd_overflow)

    # window
    p_window = sub.add_parser('window', help='annotated disassembly window around a VA')
    p_window.add_argument('binary')
    p_window.add_argument('va', help='center VA in hex, e.g. 0x1234')
    p_window.add_argument('--window', type=int, default=1536, help='bytes to disassemble (default 1536)')
    p_window.add_argument('--back', type=int, default=0, help='bytes before VA to include')
    p_window.add_argument('--calls', action='store_true', help='list call sites in window')
    p_window.add_argument('--funcs', action='store_true', help='list function starts in window')
    p_window.set_defaults(func=cmd_window)

    # profile
    p_profile = sub.add_parser('profile', help='full function profile: strings + call args + sinks')
    p_profile.add_argument('binary')
    p_profile.add_argument('va', help='function VA in hex, e.g. 0x1234')
    p_profile.set_defaults(func=cmd_profile)

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
    p_corpus.add_argument('--sigs', action='store_true', help='auto-name fn_0x* functions after build')
    p_corpus.set_defaults(func=cmd_corpus)

    # sweep
    p_sweep = sub.add_parser('sweep', help='run all registered patterns against a binary')
    p_sweep.add_argument('binary')
    p_sweep.add_argument('--top-k', type=int, default=5)
    p_sweep.add_argument('--min-score', type=float, default=0.30)
    p_sweep.add_argument('--db', default=str(_DEFAULT_DB), help='func_id DB path')
    p_sweep.add_argument('--sarif', metavar='FILE', default=None, help='write SARIF 2.1.0 to FILE')
    p_sweep.add_argument('--json', metavar='FILE', default=None, help='write JSON to FILE')
    p_sweep.set_defaults(func=cmd_sweep)

    # findings
    p_findings = sub.add_parser('findings', help='list confirmed findings')
    p_findings.add_argument('--sarif', metavar='FILE', default=None, help='write SARIF 2.1.0 to FILE')
    p_findings.add_argument('--json', metavar='FILE', default=None, help='write JSON to FILE')
    p_findings.set_defaults(func=cmd_findings)

    # sigs
    p_sigs = sub.add_parser('sigs', help='match and auto-name functions from signature library')
    p_sigs.add_argument('--db', default=str(_DEFAULT_DB), help='func_id DB path')
    p_sigs.add_argument('--threshold', type=float, default=0.62, help='similarity threshold (0-1)')
    p_sigs.add_argument('--dry-run', action='store_true', help='report matches without writing')
    p_sigs.add_argument('--list', action='store_true', help='list all signatures in the library')
    p_sigs.set_defaults(func=cmd_sigs)

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
