#!/usr/bin/env python3
"""
sweeps/fortinet_sweep.py — FortiOS-specific binary vulnerability sweep.

Pipeline
--------
Phase 0 (directory mode): batch_plt_intersect triage — filters ELFs to only
         those whose PLT includes known exec-class sinks.  Auto-CLEAN binaries
         are skipped; saves 30–120 s per uninteresting binary.

Phase 1 (every remaining binary): BinaryContext + XRefGraph + SemanticSearcher.
         Runs all VULN_PROFILES (base + FortiOS-specific) and prior-finding
         queries from the FindingRegistry.

Phase 2 (every binary): arch-routed TaintTracker.
         x86-64 → TaintTracker (full interprocedural, depth 4)
         ARM32   → ARM32TaintTracker (intraprocedural only; different init path)
         ARM64   → ARM64TaintTracker (intraprocedural; requires bounds)
         PPC32/64, MIPS32/64 → respective trackers via from_path()/from_context()
         Other   → skipped with note in report

Phase 3 (x86-64 only): SinkArgClassifier + VendorProfile(fortinet) +
         SanitizerDetector.  Classifies exec sink argument origin
         (RODATA_CONST / SNPRINTF_RODATA / ARG_PROPAGATED / UNKNOWN).
         SanitizerDetector is mandatory before marking any PLAUSIBLE finding.

Usage
-----
Single binary:
    python3 sweeps/fortinet_sweep.py /tmp/fwb743/httpsd --product fortiweb --version 7.4.3

Directory scan:
    python3 sweeps/fortinet_sweep.py /tmp/fwb743/ --product fortiweb --version 7.4.3

Output:
    reports/sweep_fortinet_<product>_<version>_<ts>.md
"""
from __future__ import annotations

import argparse
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# ── arch constants ────────────────────────────────────────────────────────────

_ARCH_X86_64 = "ARCH.X86_64"
_ARCH_ARM32  = "ARCH.ARM"
_ARCH_ARM64  = "ARCH.AARCH64"
_ARCH_MIPS   = "ARCH.MIPS"
_ARCH_PPC32  = "ARCH.PPC"
_ARCH_PPC64  = "ARCH.PPC64"


# ── arch detection ────────────────────────────────────────────────────────────

def _detect_arch(binary_path: str) -> Tuple[Optional[str], bool]:
    """
    Parse ELF header and return (arch_str, is_64bit).
    Returns (None, False) on any parse failure.

    arch_str matches the ARCH.* constants above.
    """
    try:
        import lief
        b = lief.parse(binary_path)
        if b is None:
            return None, False
        arch_str = str(b.header.machine_type)
        is_64 = (b.header.identity_class == lief.ELF.Header.CLASS.ELF64)
        return arch_str, is_64
    except Exception:
        return None, False


# ── FortiOS-specific vulnerability profiles ───────────────────────────────────
#
# Extend base_sweep.VULN_PROFILES with FortiOS CVE-class patterns.
# These queries are empirically tuned for FortiOS daemon naming conventions
# and the specific call patterns seen in FortiGate, FortiWeb, FortiADC,
# FortiManager, and FortiAnalyzer binaries.

FORTIOS_PROFILES: List[Tuple[str, str]] = [
    # Path traversal — CVE-2025-64446 class (FortiOS VDOM path traversal)
    ("fortios_path_traversal",
     "FUNC | calls: fopen open stat realpath access | "
     "vuln: file path from HTTP request URI or API parameter not normalized; "
     "../ sequence not stripped before fopen or stat; directory traversal to "
     "read /etc/passwd or write outside web root; FortiOS CVE-2025-64446 class"),

    # FGFM protocol heap — CVE-2024-47575 FortiJump class
    ("fortios_fgfm_heap",
     "FUNC | calls: malloc realloc memcpy recv SSL_read | "
     "vuln: FortiGate-to-FortiManager FGFM TLS protocol; message length field "
     "from packet controls malloc size or memcpy length without upper bound check; "
     "unauthenticated heap overflow in fgfmd daemon; CVE-2024-47575 FortiJump"),

    # SSL-VPN pre-auth heap overflow — CVE-2023-27997 / CVE-2022-42475 class
    ("fortios_sslvpn_heap",
     "FUNC | calls: SSL_read recv memcpy memmove | "
     "vuln: SSL-VPN TLS client hello or DTLS handshake parsing; integer wrap "
     "in packet length converts 0 to MAX_UINT before memcpy into fixed heap slot; "
     "unauthenticated pre-auth RCE on port 443 or 10443; sslvpnd daemon"),

    # Web management httpsd command injection — authenticated
    ("fortios_httpsd_injection",
     "FUNC | calls: fadcsystem fadcpopen system popen execvp execl | "
     "vuln: HTTP management API (httpsd) passes REST or CGI request parameter "
     "into fadcsystem or popen without is_valid_host_name sanitization; "
     "admin-authenticated CLI command injection via CMDB config endpoint"),

    # SAML assertion bypass — CVE-2022-29081 / samld class
    ("fortios_saml_bypass",
     "FUNC | calls: xmlParseDoc xmlXPathEval xmlXPathEvalExpression strcmp strstr | "
     "vuln: SAML assertion XML parsed without entity expansion limit; XPath "
     "expression constructed from user assertion attribute; authentication bypass "
     "or privilege escalation; samld daemon, FortiAuthenticator / FortiGate SAML SP"),

    # Format string via syslog / log daemon — CVE-2023-24113 class
    ("fortios_format_string_log",
     "FUNC | calls: syslog vsyslog vprintf vfprintf vsnprintf | "
     "vuln: network-controlled log message or hostname passed as format string "
     "argument without %s wrapper; stack read or arbitrary write; "
     "pre-authentication via log collector or FAMS protocol"),

    # Firmware update integer overflow — authenticated path
    ("fortios_fwupdate_intovf",
     "FUNC | calls: malloc memcpy fread | "
     "vuln: firmware update image size field read as 32-bit signed integer; "
     "large image causes wrap to negative or small size_t before malloc; "
     "heap overflow during subsequent memcpy; authenticated but pre-reboot "
     "code path in migadmin or fwupdate daemon"),

    # REST API JSON depth / type confusion
    ("fortios_json_type_confusion",
     "FUNC | calls: cJSON_Parse json_object_get jansson | "
     "vuln: REST API parses user JSON without depth limit or array size cap; "
     "recursive stack overflow or type confusion in recycled node; "
     "unauthenticated on exposed management API or authenticated privilege path"),
]


def _build_all_profiles() -> List[Tuple[str, str]]:
    """Return base VULN_PROFILES + FortiOS-specific profiles (no duplicates)."""
    from sweeps.base_sweep import VULN_PROFILES as BASE
    seen = {name for name, _ in BASE}
    extra = [(n, q) for n, q in FORTIOS_PROFILES if n not in seen]
    return list(BASE) + extra


# ── semantic sweep ────────────────────────────────────────────────────────────

def _semantic_sweep(
    binary_path: str,
    model,
    profiles: List[Tuple[str, str]],
    top_k: int = 5,
    xref=None,
) -> Dict[str, List[Tuple[float, int, List[str], str]]]:
    """
    Run semantic similarity sweep against all profiles.

    Returns {profile_name: [(score, va, calls, desc), ...]} top_k per profile.
    model must already be loaded (loaded once by caller, not here).
    xref: XRefGraph instance (optional; enriches function descriptions).

    Falls back to xref._func_starts when push-rbp prologue scan finds nothing
    (frame-pointer-omitted binaries, which are common in FortiOS firmware).
    """
    from ablation.analyzers import FindingRegistry, describe_function
    from sweeps.base_sweep import extract_functions, _find_prologue_starts
    import capstone

    registry = FindingRegistry()

    funcs = extract_functions(binary_path, xref=xref)

    # Fallback: use eh_frame func_starts from XRefGraph when prologue scan is empty
    if not funcs and xref is not None and xref._func_starts:
        print(f"  [~] Prologue scan empty; using {len(xref._func_starts)} eh_frame func_starts")
        with open(binary_path, "rb") as f:
            data = f.read()
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = False
        plt_map: Dict = {**getattr(xref, '_plt', {})}
        func_starts_sorted = sorted(xref._func_starts)
        funcs = []
        for idx, va in enumerate(func_starts_sorted):
            # Determine end boundary: next func start or +2048
            end_va = (func_starts_sorted[idx + 1]
                      if idx + 1 < len(func_starts_sorted)
                      else va + 2048)
            chunk_len = min(end_va - va, 2048)
            if va >= len(data) or chunk_len <= 0:
                continue
            lines, calls = [], []
            for insn in md.disasm(data[va:va + chunk_len], va):
                text = f"{insn.mnemonic} {insn.op_str}".strip()
                lines.append(text)
                if insn.mnemonic == "call":
                    try:
                        target = int(insn.op_str, 16)
                        calls.append(plt_map.get(target, insn.op_str))
                    except ValueError:
                        calls.append(insn.op_str)
                if insn.mnemonic in ("ret", "retq"):
                    break
            if len(lines) < 4:
                continue
            str_refs = xref.strings_at(va) if xref else []
            desc = describe_function(
                name=f"func_{va:07x}",
                role="FUNC",
                call_targets=calls,
                strings=str_refs,
                asm_lines=lines,
            )
            funcs.append({"va": va, "desc": desc, "calls": calls, "strings": str_refs})
        print(f"  [~] Fallback extracted {len(funcs)} functions from eh_frame starts")

    if not funcs:
        print(f"  [!] No functions extracted from {binary_path}")
        registry.close()
        return {}

    print(f"  [*] {len(funcs)} functions; encoding ...")
    corpus = model.encode(
        [f["desc"] for f in funcs],
        normalize_embeddings=True,
        batch_size=128,
        show_progress_bar=False,
    ).astype(np.float32)

    # Augment profiles with prior registry findings
    all_profiles = list(profiles)
    prior = registry.prior_queries(top_n=15)
    for i, desc in enumerate(prior):
        label = f"prior:{i:02d}:{desc[:35].replace(' ', '_').replace('|', '').strip('_')}"
        all_profiles.append((label, desc))
    if prior:
        print(f"  [*] +{len(prior)} prior-finding queries from registry")

    # Build embeddings for registry entries lacking them
    n_built = registry.build_embeddings(model)
    if n_built:
        print(f"  [*] Built {n_built} registry embeddings")

    results: Dict = {}
    for name, query in all_profiles:
        qvec = model.encode(query, normalize_embeddings=True).astype(np.float32)
        scores = corpus @ qvec
        top = np.argsort(scores)[::-1][:top_k]
        results[name] = [
            (float(scores[i]), funcs[i]["va"], funcs[i]["calls"], funcs[i]["desc"])
            for i in top
        ]

    registry.close()
    return results


# ── taint analysis ────────────────────────────────────────────────────────────

def _taint_x86(binary_path: str, xref=None):
    """Run x86-64 TaintTracker. Returns (direct_findings, chain_findings)."""
    from ablation.analyzers import TaintTracker
    try:
        tracker = TaintTracker(binary_path, xref=xref)
        findings = tracker.run()
        chains   = tracker.run_interprocedural(depth=4)
        return findings, chains
    except Exception as e:
        print(f"  [!] x86 TaintTracker error: {e}")
        return [], []


def _taint_arm32(binary_path: str):
    """Run ARM32TaintTracker. Returns (findings, [])."""
    from ablation.analyzers import ARM32TaintTracker
    try:
        import lief
        b = lief.parse(binary_path)
        data = Path(binary_path).read_bytes()
        base = b.imagebase
        tracker = ARM32TaintTracker(data, base)
        findings = tracker.run() if hasattr(tracker, "run") else []
        return findings, []
    except Exception as e:
        print(f"  [!] ARM32TaintTracker error: {e}")
        return [], []


def _taint_arm64(binary_path: str):
    """Run ARM64TaintTracker with lief-extracted bounds. Returns (findings, [])."""
    from ablation.analyzers import ARM64TaintTracker
    try:
        import lief
        b = lief.parse(binary_path)
        data = Path(binary_path).read_bytes()
        text = b.get_section(".text")
        if text is None:
            print("  [!] ARM64: no .text section found")
            return [], []
        base_va    = b.imagebase
        text_start = text.virtual_address
        text_end   = text_start + text.size
        plt: Dict[int, str] = {}
        if hasattr(b, "symbols"):
            for s in b.symbols:
                if "@plt" in s.name.lower() and s.value:
                    plt[s.value] = s.name
        tracker = ARM64TaintTracker(data, base_va, text_start, text_end, plt, [])
        findings = tracker.run() if hasattr(tracker, "run") else []
        return findings, []
    except Exception as e:
        print(f"  [!] ARM64TaintTracker error: {e}")
        return [], []


def _taint_ppc(binary_path: str, is_64: bool):
    """Run PPC32 or PPC64 TaintTracker. Returns (findings, chains)."""
    try:
        if is_64:
            from ablation.analyzers import PPC64TaintTracker as Klass
        else:
            from ablation.analyzers import PPC32TaintTracker as Klass
        tracker = Klass(binary_path)
        findings = tracker.run() if hasattr(tracker, "run") else []
        chains   = tracker.run_interprocedural(depth=4) if hasattr(tracker, "run_interprocedural") else []
        return findings, chains
    except Exception as e:
        print(f"  [!] PPC TaintTracker error: {e}")
        return [], []


def _run_taint(binary_path: str, arch_str: str, is_64: bool, xref=None):
    """Dispatch taint analysis to the correct arch tracker."""
    if arch_str == _ARCH_X86_64:
        return _taint_x86(binary_path, xref=xref)
    elif arch_str == _ARCH_ARM32:
        return _taint_arm32(binary_path)
    elif arch_str == _ARCH_ARM64:
        return _taint_arm64(binary_path)
    elif arch_str in (_ARCH_PPC32, _ARCH_PPC64):
        return _taint_ppc(binary_path, is_64=(arch_str == _ARCH_PPC64 or is_64))
    else:
        print(f"  [~] No taint tracker for arch {arch_str} — skipping taint phase")
        return [], []


# ── SinkArgClassifier + VendorProfile (x86-64 only) ──────────────────────────

def _classify_sinks_x86(binary_path: str, vendor_profile) -> str:
    """
    Run SinkArgClassifier + VendorProfile + SanitizerDetector on an x86-64 binary.

    Returns a formatted string suitable for inclusion in the report.
    MUST be called only after confirming arch == _ARCH_X86_64.
    """
    from ablation.analyzers import SinkArgClassifier, SanitizerDetector

    lines: List[str] = []
    try:
        clf = SinkArgClassifier.from_path(binary_path)
        if vendor_profile is not None:
            vendor_profile.apply_to(clf)
        results = clf.classify_all()  # returns List[SinkClassification]
        report_str = clf.report(results)
        lines.append("### SinkArgClassifier\n")
        lines.append(report_str)
    except Exception as e:
        lines.append(f"SinkArgClassifier failed: {e}\n")

    try:
        san = SanitizerDetector(binary_path)
        san_report = san.report() if hasattr(san, "report") else str(san.detect())
        lines.append("\n### SanitizerDetector\n")
        lines.append(san_report)
    except Exception as e:
        lines.append(f"\nSanitizerDetector failed: {e}\n")

    return "\n".join(lines)


# ── per-binary sweep orchestrator ─────────────────────────────────────────────

def _sweep_one(
    binary_path: str,
    model,
    profiles: List[Tuple[str, str]],
    vendor_profile,
    top_k: int,
    args,
) -> dict:
    """
    Run all four phases against a single binary.

    Returns a result dict:
        {
          'path': str,
          'arch': str,
          'is_64': bool,
          'semantic': {profile: [(score, va, calls, desc)]},
          'taint_findings': [...],
          'taint_chains': [...],
          'classifier_report': str,
          'error': str or None,
        }
    """
    name = Path(binary_path).name
    arch_str, is_64 = _detect_arch(binary_path)
    print(f"\n[{name}] arch={arch_str or 'unknown'}  64bit={is_64}")

    result: dict = {
        "path": binary_path,
        "arch": arch_str or "unknown",
        "is_64": is_64,
        "semantic": {},
        "taint_findings": [],
        "taint_chains": [],
        "classifier_report": "",
        "error": None,
    }

    # Phase 1 — BinaryContext + XRefGraph + Semantic sweep
    xref = None
    try:
        from ablation.analyzers.xref_graph import XRefGraph
        print(f"  [*] Building XRefGraph ...")
        xref = XRefGraph.from_path(binary_path)
        xref.build()
        xs = xref.stats()
        print(f"  [*] XRef: {xs['functions']} funcs, {xs['plt_entries']} PLT, "
              f"{xs['strings']} strings")
    except Exception as e:
        print(f"  [!] XRefGraph failed ({e}), continuing without")
        xref = None

    try:
        print(f"  [*] Semantic sweep ({len(profiles)} profiles) ...")
        result["semantic"] = _semantic_sweep(
            binary_path, model, profiles, top_k=top_k, xref=xref
        )
    except Exception as e:
        result["error"] = f"semantic: {e}\n{traceback.format_exc()}"
        print(f"  [!] Semantic sweep failed: {e}")

    # Phase 2 — Taint analysis (arch-routed)
    try:
        print(f"  [*] Taint analysis ({arch_str}) ...")
        findings, chains = _run_taint(binary_path, arch_str, is_64, xref=xref)
        result["taint_findings"] = findings
        result["taint_chains"] = chains
        if findings:
            print(f"  [!] Taint: {len(findings)} direct hit(s)")
        if chains:
            print(f"  [!] Interprocedural: {len(chains)} chain(s)")
    except Exception as e:
        print(f"  [!] Taint analysis error: {e}")

    # Phase 3 — SinkArgClassifier + VendorProfile + SanitizerDetector (x86-64 only)
    if arch_str == _ARCH_X86_64:
        try:
            print(f"  [*] SinkArgClassifier + SanitizerDetector ...")
            result["classifier_report"] = _classify_sinks_x86(binary_path, vendor_profile)
        except Exception as e:
            result["classifier_report"] = f"Classifier failed: {e}"
            print(f"  [!] Classifier error: {e}")
    else:
        result["classifier_report"] = (
            f"SinkArgClassifier skipped: x86-64 only (arch={arch_str}).\n"
            "Manual analysis required for exec-class sink classification."
        )

    return result


# ── report generation ─────────────────────────────────────────────────────────

def _render_report(
    results: List[dict],
    binary_paths: List[str],
    vendor: str,
    product: str,
    version: str,
    top_k: int,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: List[str] = [
        f"# Fortinet Sweep Report",
        f"",
        f"**Vendor:** {vendor}  **Product:** {product}  **Version:** {version}",
        f"**Generated:** {ts}  **Targets:** {len(results)} binaries",
        f"",
    ]

    for r in results:
        name = Path(r["path"]).name
        lines += [
            f"---",
            f"",
            f"## {name}",
            f"",
            f"**Path:** `{r['path']}`  **Arch:** `{r['arch']}`  **64-bit:** {r['is_64']}",
            f"",
        ]

        if r.get("error"):
            lines += [f"**ERROR:** {r['error']}", ""]

        # Semantic results
        if r["semantic"]:
            lines += ["### Semantic Sweep", ""]
            for profile_name, hits in r["semantic"].items():
                if not hits:
                    continue
                top = hits[0]
                score, va, calls, desc = top
                if score < 0.30:
                    continue
                lines.append(f"**{profile_name}** — top score `{score:.4f}` @ `{va:#010x}`")
                calls_str = ", ".join(calls[:6]) or "none"
                lines.append(f"  calls: {calls_str}")
                lines.append("")
        else:
            lines += ["*No semantic results.*", ""]

        # Taint findings
        if r["taint_findings"]:
            lines += ["### Taint Analysis — Direct Hits", ""]
            for tf in r["taint_findings"]:
                lines.append(f"- {tf}")
            lines.append("")

        if r["taint_chains"]:
            lines += ["### Taint Analysis — Interprocedural Chains", ""]
            for tc in r["taint_chains"]:
                lines.append(f"- {tc}")
            lines.append("")

        # Classifier report
        if r["classifier_report"]:
            lines += ["", r["classifier_report"], ""]

    return "\n".join(lines)


# ── directory sweep (Phase 0 triage + per-binary) ─────────────────────────────

def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def sweep_directory(
    directory: str,
    model,
    profiles: List[Tuple[str, str]],
    vendor_profile,
    args,
) -> List[dict]:
    """
    Phase 0: batch_plt_intersect on all ELFs in directory.
    Phase 1–3: _sweep_one for each ELF with matching sinks.
    """
    from ablation.analyzers import batch_plt_intersect

    dir_path = Path(directory)
    print(f"\n[Phase 0] PLT triage: {directory}")
    try:
        triage = batch_plt_intersect(directory)
    except Exception as e:
        print(f"[!] batch_plt_intersect failed ({e}), scanning all ELFs")
        triage = {}

    # Fall back to scanning all ELFs if triage returned nothing
    if triage:
        candidates = sorted(triage.keys())
        print(f"[Phase 0] {len(candidates)} binary(ies) with matching sinks:")
        for p, sinks in sorted(triage.items()):
            print(f"  {Path(p).name}: {sinks}")
    else:
        candidates = [
            str(dir_path / f)
            for f in sorted(os.listdir(directory))
            if (dir_path / f).is_file() and _is_elf(str(dir_path / f))
        ]
        print(f"[Phase 0] triage empty — scanning all {len(candidates)} ELF(s)")

    results: List[dict] = []
    for path in candidates:
        try:
            r = _sweep_one(path, model, profiles, vendor_profile, args.top, args)
            results.append(r)
        except Exception as e:
            print(f"[!] SKIP {path}: {e}")
            results.append({
                "path": path, "arch": "unknown", "is_64": False,
                "semantic": {}, "taint_findings": [], "taint_chains": [],
                "classifier_report": "", "error": str(e),
            })
    return results


# ── main / CLI ────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="FortiOS-specific binary vulnerability sweep",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("target",
                    help="Path to ELF binary OR directory of ELFs")
    ap.add_argument("--vendor",   default="fortinet", help="Vendor name")
    ap.add_argument("--product",  default="",         help="Product name (e.g. fortiweb)")
    ap.add_argument("--version",  default="",         help="Firmware version (e.g. 7.4.3)")
    ap.add_argument("--top",      type=int, default=5,
                    help="Candidates per semantic profile (default 5)")
    ap.add_argument("--report",   default="",
                    help="Write report to this .md path (default: auto-named in reports/)")
    ap.add_argument("--no-vendor-profile", action="store_true",
                    help="Skip loading the Fortinet vendor profile YAML")
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] Target not found: {target}")
        sys.exit(1)

    # Load shared sentence transformer model (once per run)
    print("[*] Loading sentence transformer (all-MiniLM-L6-v2) ...")
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    print("[*] Model loaded")

    # Build merged profile list
    profiles = _build_all_profiles()
    print(f"[*] Profiles: {len(profiles)} (base + {len(FORTIOS_PROFILES)} FortiOS-specific)")

    # Load vendor profile
    vendor_profile = None
    if not args.no_vendor_profile:
        try:
            from ablation.analyzers import VendorProfile
            vendor_profile = VendorProfile.from_vendor("fortinet")
            print(f"[*] {vendor_profile.summary().splitlines()[0]}")
        except Exception as e:
            print(f"[!] VendorProfile load failed: {e} — continuing without")

    # Run sweep
    if target.is_dir():
        results = sweep_directory(
            str(target), model, profiles, vendor_profile, args
        )
    else:
        if not _is_elf(str(target)):
            print(f"[!] {target} does not look like an ELF binary")
            sys.exit(1)
        r = _sweep_one(str(target), model, profiles, vendor_profile, args.top, args)
        results = [r]

    # Write report
    if args.report:
        report_path = Path(args.report)
    else:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
        slug = "_".join(filter(None, [args.vendor, args.product, args.version, ts]))
        report_path = Path("reports") / f"sweep_{slug}.md"

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_md = _render_report(
        results,
        binary_paths=[r["path"] for r in results],
        vendor=args.vendor,
        product=args.product,
        version=args.version,
        top_k=args.top,
    )
    report_path.write_text(report_md, encoding="utf-8")
    print(f"\n[*] Report written to {report_path}")

    # Summary
    n_taint = sum(len(r["taint_findings"]) for r in results)
    n_chains = sum(len(r["taint_chains"]) for r in results)
    print(f"[*] Summary: {len(results)} binary(ies) swept, "
          f"{n_taint} taint hit(s), {n_chains} chain(s)")


if __name__ == "__main__":
    main()
