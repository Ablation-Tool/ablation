"""
ablation.cli: command-line interface.

Usage:
    ablation analyze  <binary>              binary summary: arch, PLT, exports, funcs
    ablation search   <binary> <query>      semantic search across all functions
    ablation taint    <binary>              taint trace from network sources to sinks (arch-aware)
    ablation taint    <binary> --interprocedural      cross-function BFS taint chains
    ablation taint    <binary> --flow-sensitive        CFG MFP + interprocedural (most precise)
    ablation overflow <binary>              ARM32 integer overflow scan (MUL -> malloc without check)
    ablation window   <binary> <va>         annotated disassembly window around a VA
    ablation profile  <binary> <va>         full function profile: strings + call args + sinks
    ablation cfg      <binary> <va>         control-flow graph for one function (hex VA)
    ablation crypto   <binary>              entropy scan + XOR/AES key search
    ablation corpus   <binary>              build or rebuild the semantic function corpus
    ablation sweep    <binary>              run all registered patterns against a binary
    ablation findings                       list confirmed findings in ~/.ablation/findings.db
    ablation driver   <binary.sys>          Windows kernel driver: IOCTL, callbacks, dangerous patterns
    ablation byovd    <binary.sys>          BYOVD risk score: signed driver + IOCTL surface + dangerous primitive
    ablation fmtstr   <binary>              format string scan: printf/syslog with non-literal format arg
    ablation news                           show recent updates

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
        return

    from ablation.analyzers.xref_graph import XRefGraph
    from ablation.analyzers.taint_tracker_x86 import TaintTracker
    xg = XRefGraph.from_path(p)
    xg.build()
    tracker = TaintTracker(p, xref=xg)

    if getattr(args, 'flow_sensitive', False):
        print("[*] Running flow-sensitive CFG taint analysis (MFP + interprocedural BFS) ...")
        findings, chains = tracker.run_flow_sensitive()
        if not findings and not chains:
            print("No taint paths found.")
            return
        if findings:
            print(f"{len(findings)} intraprocedural finding(s):\n")
            for f in findings:
                print(f)
        if chains:
            print(f"\n{len(chains)} interprocedural chain(s):\n")
            for c in chains:
                print(c)
    elif getattr(args, 'interprocedural', False):
        depth = getattr(args, 'depth', 4)
        print(f"[*] Running interprocedural taint analysis (depth={depth}) ...")
        chains = tracker.run_interprocedural(depth=depth)
        if not chains:
            print("No taint paths found.")
            return
        print(f"{len(chains)} interprocedural chain(s):\n")
        for c in chains:
            print(c)
    else:
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
    """Annotated disassembly window around a VA: suitable for pasting into claude.ai."""
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


def cmd_driver(args):
    from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer
    import json as _json2

    p = _require_binary(args.binary)
    kda = KernelDriverAnalyzer.from_path(str(p))
    report = kda.analyze()

    if report.error:
        print(f"error: {report.error}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        Path(args.json).write_text(_json2.dumps(report.summary(), indent=2))
        print(f"JSON written to {args.json}")
        return

    print(report.fmt())


def cmd_byovd(args):
    from ablation.analyzers.byovd_detector import BYOVDDetector
    import json as _json3

    p = _require_binary(args.binary)
    det = BYOVDDetector.from_path(str(p))
    report = det.analyze()

    if args.json:
        Path(args.json).write_text(_json3.dumps(report.summary(), indent=2))
        print(f"JSON written to {args.json}")
        return

    print(report.fmt())


_RECENT_UPDATES = """\
v2.8.0 (2026-09-24)  PowerPC 64-bit taint tracker
  ablation ppc64   <binary> [--le] [--interprocedural] [--depth N] [--json FILE]
  - PPC64TaintTracker: ELFv2 (OpenPOWER Linux) and ELFv1 (AIX/old Linux PPC64)
    ABI; r3-r10 args (8 regs), r3 return, r14-r31 callee-saved; no delay slots
  - Sources: recv/recvfrom/read/fgets/gets/fread (return value in r3)
  - Sinks: system/execve/execl/execvp/popen/strcpy/sprintf/snprintf/memcpy/strcat
  - 64-bit ops: LD/STD/STDU/MULLD/DIVD/DIVDU/SLD/SRD/RLDICL/RLDICR/EXTSW
  - Prologue scan: stdu r1, -N(r1) for function-start discovery without symbols
  - Interprocedural BFS: follows tainted args r3-r10 through direct bl callees
  - Big-endian (IBM POWER/AIX, old OpenPOWER, Apple G5, Juniper MX/PTX)
  - Little-endian: POWER8+ OpenPOWER Linux
  - DisasmEngine: ppc64 arch stdu prologue detection added

v2.7.0 (2026-09-24)  PowerPC 32-bit taint tracker
  ablation ppc32   <binary> [--le] [--interprocedural] [--depth N] [--json FILE]
  - PPC32TaintTracker: System V / EABI ABI; r3-r10 args (8 regs), r3 return,
    r13-r31 callee-saved; no branch delay slots
  - Sources: recv/recvfrom/read/fgets/gets/fread (return value in r3)
  - Sinks: system/execve/execl/execvp/popen/strcpy/sprintf/snprintf/memcpy/strcat
  - Call detection: bl (direct), bctrl (indirect via CTR for PLT stubs)
  - Return detection: blr/blrl
  - Prologue scan: stwu r1, -N(r1) for function-start discovery without symbols
  - Interprocedural BFS: follows tainted args r3-r10 through direct bl callees
  - Big-endian (Cisco IOS 7200/3700, MikroTik RB600, VxWorks)
  - Little-endian: POWER LE Linux userspace
  - DisasmEngine: arch='ppc'/'ppc32'/'ppc64' + endian kwarg;
    _is_prologue stwu detection; stream() PPC branch/call/ret classification

v2.6.0 (2026-09-24)  MIPS 32+nM and MIPS 64 support
  ablation mips64   <binary> [--le] [--json FILE]
  ablation nanomips <binary> [--le] [--json FILE]
  - MIPS64TaintTracker: N64 ABI; 8 arg regs ($a0-$a3 + $t0-$t3 for $8-$11);
    64-bit ops LD/SD/DADDU/DADDIU/DMULT; delay-slot aware; interprocedural BFS
    big-endian (Cisco IOS/OCTEON) and little-endian (RouterOS 64)
  - NanoMIPSDecoder: variable-length frame walker P16/P32/P48 (16/32/48-bit);
    full decode with capstone 6.x; branch-hint fallback on capstone 5.x;
    function-start prologue heuristic; Ingenic SoC and MediaTek embedded
  - DisasmEngine: arch='mips32'/'mips64'/'mips32r6'/'nanomips' + endian kwarg;
    MIPS prologue detection (addiu/daddiu $sp,$sp,-N); MIPS stream() classification

v2.5.0 (2026-09-24)  HeapUAFScanner, MIPS32FuncProfiler, ByovdDetector aliases

v2.4.0 (2026-09-24)  MIPS32 taint tracker + cross-binary taint + IOCTL surface
  ablation mips <binary> [--le]
  ablation ioctl-surface <driver.sys>
  - MIPS32TaintTracker: O32 ABI; $a0-$a3 args, $v0 return; caller/callee-saved model
  - Sources: recv/recvfrom/read/fgets/gets/fread
  - Sinks: system/execve/execl/execvp/popen/strcpy/sprintf/memcpy/strcat/snprintf
  - Load-delay slot aware (delay slot instruction executes before branch takes effect)
  - Big-endian (RouterOS, Broadcom) and little-endian (embedded CPE) support
  - Intraprocedural + interprocedural BFS up to depth 4
  - CrossBinaryTaintTracker: follows taint across library boundaries via LibGraph;
    seeds tainted return values at each export crossing
  - IoctlAttackSurface: per-IOCTL handler attack surface report; pairs CTL_CODE
    decode with METHOD_NEITHER flag and handler disassembly window

v2.3.0 (2026-09-24)  Heap vulnerability scanner
  ablation heap <binary>
  - INT_OVERFLOW_BEFORE_ALLOC: IMUL/MUL/SHL result to malloc without overflow check
    (TAOSSA Ch6 L6-2 width*height pattern, L6-3 nresp*sizeof pattern)
  - USE_AFTER_FREE: free(ptr) then dereference of same register in same function
  - DOUBLE_FREE: same register freed twice without intervening reassignment
  - OFF_BY_ONE_ALLOC: strlen result to malloc without +1 for NUL terminator

v2.2.0 (2026-09-24)  BYOVD detector
  ablation byovd <file.sys>
  - Wraps KernelDriverAnalyzer with BYOVD-specific scoring (0-100)
  - 8 attack paths: PHYS_MEM_ARBITRARY_RW, MDL_KERNEL_WRITE,
    MSR_LSTAR_MANIPULATION, SSDT_HOOK, TOKEN_STEALING_LPE, SMEP_BYPASS,
    APC_KERNEL_INJECTION, VIRTUAL_MEM_WRITE
  - Signed driver + METHOD_NEITHER IOCTL + dangerous primitive = BYOVD_CONFIRMED
  - Grounded in PRE ch3 IRP walk-through: MmMapIoSpace, MapMdl sequence,
    KeServiceDescriptorTable SSDT hook, MSR_LSTAR read/write

v2.1.0 (2026-09-24)  Format string vulnerability scanner
  ablation fmtstr <binary>
  - Scans x86-64 ELF for printf/fprintf/syslog/err/warn family calls
    where the format argument is not a string literal
  - 28 format string sinks: printf, fprintf, sprintf, snprintf, syslog,
    err, errx, warn, warnx, wprintf, fwprintf, vsnprintf, and variants
  - Static backward trace from each call site: LEA [rip+offset] into
    .rodata = SAFE; MOV from stack slot or arg register = VULNERABLE
  - Two-hop detection: vsnprintf output buffer reused as syslog format arg
  - Verdicts: VULNERABLE / SUSPICIOUS / SAFE with write instruction context

v2.0.0 (2026-09-24)  Windows kernel driver RE
  ablation driver <file.sys>
  - IRP/IOCTL dispatch extraction (capstone DriverEntry disassembly)
  - CTL_CODE decoder; METHOD_NEITHER (raw user pointer) flagged
  - 40+ kernel API risk classifications across 12 classes
  - 20+ callback registrations (edr_like / rootkit_risk / info)
  - Pool tag extraction from MOV R8D byte pattern
  - Dangerous patterns: CR0/CR4 sequences, MSR_LSTAR read/write,
    L"KeServiceDescriptorTable" wide-string scan, RDMSR/WRMSR,
    CLI/STI/HLT, SWAPGS, IRETQ, I/O ports
  - WDM / KMDF / minifilter classification; PDB path; Authenticode

v1.9.1 (2026-09-24)  see CHANGELOG.md for earlier entries
"""


def cmd_fmtstr(args):
    from ablation.analyzers.format_string_scanner import FormatStringScanner

    p = str(_require_binary(args.binary))
    scanner = FormatStringScanner.from_path(p)
    findings = scanner.scan()

    if args.json:
        import json
        out = [f.as_dict() for f in findings if f.verdict != 'SAFE']
        with open(args.json, 'w') as fh:
            json.dump(out, fh, indent=2)
        print(f"Wrote {len(out)} findings to {args.json}")
    else:
        non_safe = [f for f in findings if f.verdict != 'SAFE']
        print(scanner.report(non_safe))


def cmd_heap(args):
    from ablation.analyzers.heap_vuln_scanner import HeapVulnScanner

    p = str(_require_binary(args.binary))
    scanner = HeapVulnScanner.from_path(p)
    findings = scanner.scan()

    if args.json:
        import json
        data = [
            {
                'kind': f.kind, 'func_va': hex(f.func_va), 'site_va': hex(f.site_va),
                'severity': f.severity, 'description': f.description,
                'alloc_sym': f.alloc_sym, 'freed_at': hex(f.freed_at) if f.freed_at else '',
            }
            for f in findings
        ]
        Path(args.json).write_text(json.dumps(data, indent=2))
        print(f"Wrote {len(data)} findings to {args.json}")
    else:
        print(scanner.report(findings))


def cmd_mips(args):
    from ablation.analyzers.taint_tracker_mips import MIPS32TaintTracker

    p = str(_require_binary(args.binary))
    be = not args.le
    tracker = MIPS32TaintTracker.from_path(p, big_endian=be)
    findings = tracker.run()

    if args.json:
        import json
        data = [
            {
                'func_va': hex(f.func_va), 'sink_va': hex(f.sink_va),
                'sink': f.sink, 'severity': f.severity, 'description': f.description,
            }
            for f in findings
        ]
        Path(args.json).write_text(json.dumps(data, indent=2))
        print(f"Wrote {len(data)} findings to {args.json}")
    else:
        print(tracker.report(findings))


def cmd_mips64(args):
    from ablation.analyzers.taint_tracker_mips64 import MIPS64TaintTracker

    p = str(_require_binary(args.binary))
    endian = 'little' if args.le else 'big'
    tracker = MIPS64TaintTracker.from_path(p, endian=endian)
    if args.interprocedural:
        findings = tracker.run_interprocedural(depth=args.depth)
    else:
        findings = tracker.run()

    if args.json:
        import json
        data = [
            {
                'func_va': hex(f.func_va), 'func_name': f.func_name,
                'sink_va': hex(f.sink_va), 'sink_name': f.sink_name,
                'tainted_args': f.tainted_args, 'source': f.source_name,
            }
            for f in findings
        ]
        Path(args.json).write_text(json.dumps(data, indent=2))
        print(f"Wrote {len(data)} findings to {args.json}")
    else:
        print(tracker.report(findings))


def cmd_nanomips(args):
    from ablation.analyzers.nanomips_decoder import NanoMIPSDisasm

    binary_path = _require_binary(args.binary)
    data = binary_path.read_bytes()
    endian = 'little' if args.le else 'big'
    dis = NanoMIPSDisasm(endian=endian)

    if args.frames:
        print(dis.report_frames(data, base_addr=args.base, limit=args.limit))
        return

    starts = dis.find_function_starts(data, base_addr=args.base)
    if args.json:
        import json
        out = [{'func_va': hex(va)} for va in starts]
        Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"Wrote {len(out)} function starts to {args.json}")
    else:
        print(f"nanoMIPS function starts ({len(starts)} found, base={hex(args.base)}):")
        for va in starts:
            print(f"  {hex(va)}")
        if not dis.has_full_decode:
            print("\nNote: install capstone 6.x for full nanoMIPS decode.")


def cmd_ppc64(args):
    from ablation.analyzers.taint_tracker_ppc64 import PPC64TaintTracker

    p = str(_require_binary(args.binary))
    endian = 'little' if args.le else 'big'
    tracker = PPC64TaintTracker.from_path(p, endian=endian)
    if args.interprocedural:
        findings = tracker.run_interprocedural(depth=args.depth)
    else:
        findings = tracker.run()

    if args.json:
        import json
        data = [
            {
                'func_va': hex(f.func_va), 'func_name': f.func_name,
                'sink_va': hex(f.sink_va), 'sink_name': f.sink_name,
                'tainted_args': f.tainted_args, 'source': f.source_name,
            }
            for f in findings
        ]
        Path(args.json).write_text(json.dumps(data, indent=2))
        print(f"Wrote {len(data)} findings to {args.json}")
    else:
        print(tracker.report(findings))


def cmd_ppc32(args):
    from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker

    p = str(_require_binary(args.binary))
    endian = 'little' if args.le else 'big'
    tracker = PPC32TaintTracker.from_path(p, endian=endian)
    if args.interprocedural:
        findings = tracker.run_interprocedural(depth=args.depth)
    else:
        findings = tracker.run()

    if args.json:
        import json
        data = [
            {
                'func_va': hex(f.func_va), 'func_name': f.func_name,
                'sink_va': hex(f.sink_va), 'sink_name': f.sink_name,
                'tainted_args': f.tainted_args, 'source': f.source_name,
            }
            for f in findings
        ]
        Path(args.json).write_text(json.dumps(data, indent=2))
        print(f"Wrote {len(data)} findings to {args.json}")
    else:
        print(tracker.report(findings))


def cmd_news(args):
    print(_RECENT_UPDATES)


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
    p_taint.add_argument('--interprocedural', action='store_true',
                         help='cross-function BFS taint tracking (x86-64)')
    p_taint.add_argument('--flow-sensitive', action='store_true',
                         help='CFG MFP fixpoint + interprocedural BFS (most precise, x86-64)')
    p_taint.add_argument('--depth', type=int, default=4,
                         help='max hop depth for interprocedural analysis (default 4)')
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

    # driver
    p_driver = sub.add_parser('driver', help='Windows .sys kernel driver analysis (IOCTL, callbacks, dangerous patterns)')
    p_driver.add_argument('binary')
    p_driver.add_argument('--json', metavar='FILE', default=None, help='write JSON summary to FILE')
    p_driver.set_defaults(func=cmd_driver)

    # byovd
    p_byovd = sub.add_parser('byovd', help='BYOVD risk score: signed driver + IOCTL + dangerous primitive')
    p_byovd.add_argument('binary')
    p_byovd.add_argument('--json', metavar='FILE', default=None, help='write JSON summary to FILE')
    p_byovd.set_defaults(func=cmd_byovd)

    # fmtstr
    p_fmtstr = sub.add_parser('fmtstr', help='format string vulnerability scan (printf/syslog/err with non-literal format arg)')
    p_fmtstr.add_argument('binary')
    p_fmtstr.add_argument('--json', metavar='FILE', default=None, help='write JSON to FILE')
    p_fmtstr.set_defaults(func=cmd_fmtstr)

    # heap
    p_heap = sub.add_parser('heap', help='heap vulnerability scan: int overflow before alloc, UAF, double-free, off-by-one')
    p_heap.add_argument('binary')
    p_heap.add_argument('--json', metavar='FILE', default=None, help='write JSON to FILE')
    p_heap.set_defaults(func=cmd_heap)

    # mips (MIPS32 O32)
    p_mips = sub.add_parser('mips', help='MIPS 32+nM taint analysis: recv/read to system/strcpy/exec (O32 ABI)')
    p_mips.add_argument('binary')
    p_mips.add_argument('--le', action='store_true', help='little-endian (default: big-endian)')
    p_mips.add_argument('--json', metavar='FILE', default=None, help='write JSON to FILE')
    p_mips.set_defaults(func=cmd_mips)

    # mips64 (MIPS64 N64)
    p_mips64 = sub.add_parser('mips64', help='MIPS 64 taint analysis: N64 ABI; Cisco IOS/OCTEON + RouterOS 64')
    p_mips64.add_argument('binary')
    p_mips64.add_argument('--le', action='store_true', help='little-endian (default: big-endian)')
    p_mips64.add_argument('--interprocedural', action='store_true', help='cross-function BFS (default: intraprocedural)')
    p_mips64.add_argument('--depth', type=int, default=4, help='BFS depth (default: 4)')
    p_mips64.add_argument('--json', metavar='FILE', default=None, help='write JSON to FILE')
    p_mips64.set_defaults(func=cmd_mips64)

    # nanomips (nanoMIPS frame decoder)
    p_nm = sub.add_parser('nanomips', help='nanoMIPS frame decoder: function-start detection, frame walk (Ingenic/MediaTek)')
    p_nm.add_argument('binary')
    p_nm.add_argument('--le', action='store_true', help='little-endian (default: big-endian)')
    p_nm.add_argument('--base', type=lambda x: int(x, 0), default=0, help='base address (default: 0)')
    p_nm.add_argument('--frames', action='store_true', help='dump frame listing instead of function starts')
    p_nm.add_argument('--limit', type=int, default=0, help='max frames to print (0 = all)')
    p_nm.add_argument('--json', metavar='FILE', default=None, help='write function starts JSON to FILE')
    p_nm.set_defaults(func=cmd_nanomips)

    # ppc32 (PowerPC 32-bit taint tracker)
    p_ppc32 = sub.add_parser('ppc32', help='PPC32 taint analysis: System V/EABI; Cisco IOS, VxWorks, MikroTik RB600')
    p_ppc32.add_argument('binary')
    p_ppc32.add_argument('--le', action='store_true', help='little-endian (default: big-endian)')
    p_ppc32.add_argument('--interprocedural', action='store_true', help='cross-function BFS (default: intraprocedural)')
    p_ppc32.add_argument('--depth', type=int, default=4, help='BFS depth (default: 4)')
    p_ppc32.add_argument('--json', metavar='FILE', default=None, help='write JSON to FILE')
    p_ppc32.set_defaults(func=cmd_ppc32)

    # ppc64 (PowerPC 64-bit taint tracker)
    p_ppc64 = sub.add_parser('ppc64', help='PPC64 taint analysis: ELFv2/ELFv1; IBM POWER, OpenPOWER Linux, AIX')
    p_ppc64.add_argument('binary')
    p_ppc64.add_argument('--le', action='store_true', help='little-endian POWER8+ (default: big-endian)')
    p_ppc64.add_argument('--interprocedural', action='store_true', help='cross-function BFS (default: intraprocedural)')
    p_ppc64.add_argument('--depth', type=int, default=4, help='BFS depth (default: 4)')
    p_ppc64.add_argument('--json', metavar='FILE', default=None, help='write JSON to FILE')
    p_ppc64.set_defaults(func=cmd_ppc64)

    # news
    p_news = sub.add_parser('news', help='show recent updates')
    p_news.set_defaults(func=cmd_news)

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
