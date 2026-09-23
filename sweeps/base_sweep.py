#!/usr/bin/env python3
"""
base_sweep.py -- generic semantic vulnerability sweep template.

Usage:
    python3 sweeps/base_sweep.py /path/to/binary

Encodes every function in the binary and runs all VULN_PROFILES against it.
Output: ranked candidates per vulnerability class, sorted by score descending.

Customize VULN_PROFILES for the target binary's threat model.
Add PLT entries for the specific binary (use `objdump -d` to find PLT addresses).
"""

import sys
import re
import struct
import argparse
from datetime import datetime
from pathlib import Path
import numpy as np

from ablation.analyzers import SemanticSearcher, describe_function, FindingRegistry
from ablation.analyzers.xref_graph import XRefGraph
from ablation.analyzers.taint_tracker_x86 import TaintTracker, InterproceduralPath
import capstone

# ── vulnerability query profiles ─────────────────────────────────────────────

VULN_PROFILES = [
    ("unsafe_memcpy",
     "FUNC | calls: memcpy | "
     "vuln: memcpy called with length from packet data or untrusted field without upper bound check"),

    ("strcpy_overflow",
     "FUNC | calls: strcpy | "
     "vuln: strcpy on user-controlled string into fixed-size stack or heap buffer"),

    ("int_overflow",
     "FUNC | calls: malloc calloc | "
     "vuln: integer overflow in size arithmetic before allocation, wraps to small allocation"),

    ("double_free",
     "FUNC | calls: free | "
     "vuln: double free or use-after-free, same pointer freed twice or accessed after free"),

    ("format_string",
     "FUNC | calls: printf sprintf fprintf | "
     "vuln: user-controlled string passed as format argument without format specifier"),

    ("recv_overflow",
     "FUNC | calls: recv recvfrom recvmsg read | "
     "vuln: network recv into stack buffer with no size validation or insufficient bounds check"),

    ("heap_spray",
     "FUNC | calls: malloc realloc | "
     "vuln: allocation size derived from untrusted input, attacker controls heap layout"),

    ("cmd_injection",
     "FUNC | calls: system popen execve execl | "
     "vuln: command string built from user input via snprintf sprintf, shell injection"),
]

# ── ELF function extraction ───────────────────────────────────────────────────

PLT_RE = re.compile(r"@plt$")


def _find_prologue_starts(data: bytes, start: int, end: int) -> list:
    """Return VAs of likely x86-64 function starts (push rbp; mov rbp,rsp)."""
    hits = []
    for i in range(start, min(end, len(data)) - 4):
        if data[i] == 0x55 and data[i + 1:i + 3] == b'\x48\x89':
            hits.append(i)
    return hits


def extract_functions(binary_path: str, plt: dict = None,
                      scan_start: int = None, scan_end: int = None,
                      max_bytes: int = 2048,
                      xref: XRefGraph = None) -> list:
    """
    Disassemble binary and return a list of function dicts:
        {'va': int, 'desc': str, 'calls': list[str]}

    plt: {va: name} -- optional PLT table for call resolution.
    scan_start / scan_end: VA range to scan (defaults to .text heuristic).
    xref: XRefGraph instance -- if provided, enriches descriptions with
          string refs and caller context.
    """
    plt = plt or {}

    with open(binary_path, "rb") as f:
        data = f.read()

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False

    # Default scan range: skip ELF headers, stop before end
    if scan_start is None:
        scan_start = 0x200000  # typical .text start; adjust per binary
    if scan_end is None:
        scan_end = len(data)

    # Merge PLT from xref graph (better resolution) with caller-supplied PLT
    if xref is not None and xref._plt:
        plt = {**xref._plt, **plt}

    funcs = []
    for va in _find_prologue_starts(data, scan_start, scan_end):
        lines, calls = [], []
        for insn in md.disasm(data[va: va + max_bytes], va):
            text = f"{insn.mnemonic} {insn.op_str}".strip()
            lines.append(text)
            if insn.mnemonic == "call":
                try:
                    target = int(insn.op_str, 16)
                    calls.append(plt.get(target, insn.op_str))
                except ValueError:
                    calls.append(insn.op_str)
            if insn.mnemonic in ("ret", "retq"):
                break
        if len(lines) < 5:
            continue

        # Get xref-enriched string and caller context
        str_refs = xref.strings_at(va) if xref else []
        caller_names = xref.caller_names(va)[:4] if xref else []

        base_desc = describe_function(
            name=f"func_{va:07x}",
            role="FUNC",
            call_targets=calls,
            strings=str_refs,
            asm_lines=lines,
        )
        # Enrich with caller context (strings already in describe_function via str_refs)
        if xref and caller_names:
            base_desc = xref.enrich_desc(va, base_desc)

        funcs.append({
            "va": va,
            "desc": base_desc,
            "calls": calls,
            "strings": str_refs,
        })
    return funcs


# ── sweep ─────────────────────────────────────────────────────────────────────

def sweep(binary_path: str, plt: dict = None,
          scan_start: int = None, scan_end: int = None,
          top_k: int = 5, register_threshold: float = 0.0,
          vendor: str = "", product: str = "", version: str = "",
          use_xref: bool = True) -> dict:
    """
    Run all VULN_PROFILES plus prior confirmed findings from the registry against binary_path.
    Returns dict: profile_name -> list of (score, va, calls, desc).

    use_xref: build XRefGraph (string xrefs + call graph) for richer function descriptions.
    register_threshold: if > 0, auto-register hits above this score (use --register CLI flag).
    """
    from sentence_transformers import SentenceTransformer

    registry = FindingRegistry()
    s = registry.stats()
    print(f"[*] Registry: {s['total']} findings ({s['with_embedding']} with embeddings) from {len(s['by_vendor'])} vendors")

    # Build XRefGraph for string xrefs + call graph enrichment
    xg = None
    if use_xref:
        print(f"[*] Building xref graph (strings + call graph) ...")
        try:
            xg = XRefGraph.from_path(binary_path)
            xg.build()
            xs = xg.stats()
            print(f"[*] XRef: {xs['functions']} funcs, {xs['plt_entries']} PLT, "
                  f"{xs['strings']} strings, {xs['call_edges']} call edges, "
                  f"{xs['funcs_with_string_refs']} funcs with string refs")
        except Exception as e:
            print(f"[!] XRefGraph failed ({e}), continuing without")
            xg = None

    print(f"[*] Extracting functions from {binary_path}")
    funcs = extract_functions(binary_path, plt=plt,
                              scan_start=scan_start, scan_end=scan_end,
                              xref=xg)
    print(f"[*] {len(funcs)} functions extracted")
    if xg:
        with_strs = sum(1 for f in funcs if f.get("strings"))
        print(f"[*] {with_strs} functions have string xref context in descriptions")

    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    print("[*] Encoding corpus ...")
    corpus = model.encode(
        [f["desc"] for f in funcs],
        normalize_embeddings=True,
        batch_size=128,
        show_progress_bar=True,
    ).astype(np.float32)

    # Build embeddings for any registry entries that lack them
    n_built = registry.build_embeddings(model)
    if n_built:
        print(f"[*] Built {n_built} embeddings for registry entries")

    # Assemble full profile set: static + prior findings from registry
    all_profiles = list(VULN_PROFILES)
    prior = registry.prior_queries(top_n=15)
    for i, desc in enumerate(prior):
        label = f"prior:{i:02d}:{desc[:35].replace(' ', '_').replace('|','').strip('_')}"
        all_profiles.append((label, desc))
    if prior:
        print(f"[*] Added {len(prior)} prior-finding queries from registry")

    results = {}
    for name, query in all_profiles:
        qvec = model.encode(query, normalize_embeddings=True).astype(np.float32)
        scores = corpus @ qvec
        top = np.argsort(scores)[::-1][:top_k]
        results[name] = [
            (float(scores[i]), funcs[i]["va"], funcs[i]["calls"], funcs[i]["desc"])
            for i in top
        ]

    registry.close()

    # Static taint analysis: intraprocedural + interprocedural BFS
    taint_findings = []
    taint_chains = []
    if use_xref and xg is not None:
        try:
            print("[*] Running static taint analysis (sources -> sinks) ...")
            tracker = TaintTracker(binary_path, xref=xg)
            taint_findings = tracker.run()
            if taint_findings:
                print(f"[!] Taint analysis: {len(taint_findings)} direct sink hit(s) found")
                for tf in taint_findings:
                    print(f"    {tf}")
            else:
                print("[*] Taint analysis: no direct source->sink paths found")

            print("[*] Running interprocedural taint analysis (depth=4) ...")
            taint_chains = tracker.run_interprocedural(depth=4)
            if taint_chains:
                print(f"[!] Interprocedural: {len(taint_chains)} cross-function chain(s) found")
                for tc in taint_chains:
                    print(f"    {tc}")
            else:
                print("[*] Interprocedural: no cross-function chains found")
        except Exception as e:
            print(f"[!] Taint analysis failed ({e}), skipping")

    return results, xg, taint_findings, taint_chains


def print_results(results: dict) -> None:
    for name, hits in results.items():
        print(f"\n--- {name} ---")
        for item in hits:
            score, va, calls = item[0], item[1], item[2]
            calls_short = calls[:4]
            print(f"  {va:#010x}  score={score:.4f}  calls={calls_short}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Semantic vulnerability sweep")
    ap.add_argument("binary", help="Path to stripped ELF binary")
    ap.add_argument("--start", help="Scan start VA (hex)", default=None)
    ap.add_argument("--end", help="Scan end VA (hex)", default=None)
    ap.add_argument("--top", type=int, default=5, help="Candidates per class")
    ap.add_argument("--vendor", default="", help="Vendor name (for registry)")
    ap.add_argument("--product", default="", help="Product name (for registry)")
    ap.add_argument("--version", default="", help="Product version (for registry)")
    ap.add_argument("--no-xref", action="store_true", help="Skip XRefGraph build (faster, lower quality)")
    ap.add_argument("--report", default="", help="Write markdown report to this path")
    ap.add_argument(
        "--register", type=float, default=0.0, metavar="THRESHOLD",
        help="Interactively register hits above THRESHOLD score into the finding registry",
    )
    args = ap.parse_args()

    scan_start = int(args.start, 16) if args.start else None
    scan_end = int(args.end, 16) if args.end else None

    results, xg, taint_findings, taint_chains = sweep(
        args.binary,
        scan_start=scan_start, scan_end=scan_end,
        top_k=args.top,
        vendor=args.vendor, product=args.product, version=args.version,
        use_xref=not args.no_xref,
    )
    print_results(results)

    if args.report:
        from sweeps.report_generator import generate_report
        report_path = args.report
        report_md = generate_report(
            results=results,
            binary_path=args.binary,
            vendor=args.vendor, product=args.product, version=args.version,
            xref=xg,
            taint_findings=taint_findings,
            taint_chains=taint_chains,
            top_k=args.top,
            output_path=report_path,
        )
        print(f"\n[*] Report written to {report_path}")
    elif args.vendor or args.product:
        # Auto-report path when vendor/product specified
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
        slug = "_".join(filter(None, [args.vendor, args.product, args.version, ts]))
        report_path = f"reports/sweep_{slug}.md"
        Path("reports").mkdir(exist_ok=True)
        from sweeps.report_generator import generate_report
        generate_report(
            results=results,
            binary_path=args.binary,
            vendor=args.vendor, product=args.product, version=args.version,
            xref=xg,
            taint_findings=taint_findings,
            taint_chains=taint_chains,
            top_k=args.top,
            output_path=report_path,
        )
        print(f"\n[*] Report written to {report_path}")

    if args.register > 0.0:
        _register_interactive(results, args.binary, args.register, args.vendor, args.product, args.version)


def _register_interactive(results: dict, binary: str, threshold: float,
                           vendor: str, product: str, version: str) -> None:
    from ablation.analyzers.finding_registry import FindingRegistry
    from sentence_transformers import SentenceTransformer
    import os

    reg = FindingRegistry()
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")

    candidates = []
    for profile_name, hits in results.items():
        for item in hits:
            score, va, calls, desc = item
            if score >= threshold:
                candidates.append((score, va, profile_name, calls, desc))
    candidates.sort(reverse=True)

    if not candidates:
        print(f"\n[registry] No hits above threshold {threshold:.2f}")
        reg.close()
        return

    print(f"\n[registry] {len(candidates)} hits above {threshold:.2f} -- review each:")
    registered = 0
    for score, va, profile, calls, desc in candidates:
        print(f"\n  profile={profile}  va={va:#010x}  score={score:.4f}")
        print(f"  calls={calls[:6]}")
        ans = input("  Register this finding? [y/N/q]: ").strip().lower()
        if ans == "q":
            break
        if ans != "y":
            continue
        v = vendor or input("  vendor   : ").strip()
        p = product or input("  product  : ").strip()
        ver = version or input("  version  : ").strip()
        cwe = input("  cwe_class (e.g. CWE-78): ").strip()
        sev = input("  severity [CRITICAL/HIGH/MEDIUM/LOW]: ").strip().upper()
        title = input("  title    : ").strip()
        embedding = model.encode(desc, normalize_embeddings=True)
        fid = reg.register(
            vendor=v, product=p, version=ver,
            binary=os.path.basename(binary), func_addr=va,
            cwe_class=cwe, severity=sev, title=title, description=desc,
            embedding=embedding, source="sweep",
        )
        print(f"  Registered id={fid}")
        registered += 1

    print(f"\n[registry] {registered} findings registered. Total: {reg.stats()['total']}")
    reg.close()


if __name__ == "__main__":
    main()
