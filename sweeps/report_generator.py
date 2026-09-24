"""
report_generator.py -- structured markdown report from sweep output.

Produces a per-binary findings report: ranked candidates per vuln class,
registry correlations (prior confirmed findings with similar embeddings),
and a manual verification checklist.

Usage:
    from sweeps.report_generator import generate_report

    report_md = generate_report(
        results=sweep_results,          # output of sweep()
        binary_path='/path/to/binary',
        vendor='my-vendor', product='my-target', version='1.0',
        registry_hits=registry_hits,    # optional: {va: [similar findings]}
        xref=xg,                        # optional: XRefGraph instance
        top_k=5,
        min_score=0.75,
    )
    Path('sweep_report.md').write_text(report_md)
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "?": 5}


def _sev_badge(sev: str) -> str:
    badges = {
        "CRITICAL": "CRIT",
        "HIGH": "HIGH",
        "MEDIUM": "MED",
        "LOW": "LOW",
    }
    return badges.get(sev.upper(), "?")


def generate_report(
    results: Dict[str, List[tuple]],
    binary_path: str,
    vendor: str = "",
    product: str = "",
    version: str = "",
    registry_hits: Optional[Dict[int, list]] = None,
    xref=None,
    taint_findings: Optional[list] = None,
    taint_chains: Optional[list] = None,
    top_k: int = 5,
    min_score: float = 0.70,
    output_path: Optional[str] = None,
) -> str:
    """
    Generate markdown report from sweep results.

    results: {profile_name -> [(score, va, calls, desc), ...]}
    registry_hits: {func_va -> [{'title', 'vendor', 'cwe', 'severity', 'similarity'}, ...]}
    xref: XRefGraph instance (optional, for string context)
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    binary_name = os.path.basename(binary_path)
    target_label = " ".join(filter(None, [vendor, product, version])) or binary_name

    lines = [
        f"# Ablation Sweep Report -- {target_label}",
        "",
        f"**Binary:** `{binary_path}`  ",
        f"**Generated:** {now}  ",
        "",
    ]

    # Count meaningful candidates
    candidates = []
    for profile, hits in results.items():
        for item in hits:
            score, va, calls = item[0], item[1], item[2]
            if score >= min_score:
                desc = item[3] if len(item) > 3 else ""
                candidates.append((score, va, profile, calls, desc))
    candidates.sort(reverse=True)

    lines += [
        "## Summary",
        "",
        f"| Stat | Value |",
        f"|------|-------|",
        f"| Profiles run | {len(results)} |",
        f"| Candidates above {min_score:.2f} | {len(candidates)} |",
    ]

    if registry_hits:
        total_reg = sum(len(v) for v in registry_hits.values())
        lines.append(f"| Registry correlations | {total_reg} |")

    lines += ["", "---", "", "## Top Candidates (all profiles, score >= {:.2f})".format(min_score), ""]

    if not candidates:
        lines.append("_No candidates above threshold._")
    else:
        lines.append("| Score | VA | Profile | Calls |")
        lines.append("|-------|----|---------|-------|")
        for score, va, profile, calls, _ in candidates[:30]:
            calls_short = ", ".join(str(c) for c in calls[:5])
            lines.append(f"| {score:.4f} | `{va:#010x}` | {profile} | `{calls_short}` |")

    lines += ["", "---", ""]

    # Per-profile sections
    lines.append("## Per-Profile Findings")
    for profile, hits in sorted(results.items()):
        # Separate prior-registry queries from static profiles
        is_prior = profile.startswith("prior:")
        section_label = f"### `{profile}`" + (" _(registry prior)_" if is_prior else "")
        lines += ["", section_label, ""]

        above = [(s, va, c, d) for (s, va, c, d) in
                 [(i[0], i[1], i[2], i[3] if len(i) > 3 else "") for i in hits]
                 if s >= min_score]

        if not above:
            lines.append(f"_No candidates above {min_score:.2f}._")
            continue

        for score, va, calls, desc in above[:top_k]:
            calls_str = ", ".join(str(c) for c in calls[:6])
            lines += [
                f"**`{va:#010x}`** score=`{score:.4f}`",
                f"- calls: `{calls_str}`",
            ]
            # Add string context from xref
            if xref is not None:
                strs = xref.strings_at(va)
                if strs:
                    quoted = ", ".join(f'`"{s}"` ' for s in strs[:6])
                    lines.append(f"- strings: {quoted}")
                caller_names = xref.caller_names(va)
                if caller_names:
                    lines.append(f"- callers: {', '.join(caller_names[:4])}")
            # Registry correlation
            if registry_hits and va in registry_hits:
                for rhit in registry_hits[va][:3]:
                    sev = _sev_badge(rhit.get("severity", "?"))
                    lines.append(
                        f"- REGISTRY [{sev}] sim={rhit['similarity']:.3f}: "
                        f"{rhit['vendor']}/{rhit['product']} -- {rhit['title']}"
                    )
            lines.append("")

    # Registry correlation summary
    if registry_hits:
        lines += ["---", "", "## Registry Correlations", ""]
        all_hits = []
        for va, hits_list in registry_hits.items():
            for h in hits_list:
                all_hits.append((h["similarity"], va, h))
        all_hits.sort(reverse=True)

        if all_hits:
            lines.append("| Sim | VA | Vendor/Product | CWE | Title |")
            lines.append("|-----|----|----------------|-----|-------|")
            for sim, va, h in all_hits[:20]:
                vp = f"{h['vendor']}/{h['product']}"
                cwe = h.get("cwe") or "?"
                title = h["title"][:60]
                lines.append(f"| {sim:.3f} | `{va:#010x}` | {vp} | {cwe} | {title} |")
        else:
            lines.append("_No registry correlations above threshold._")

    lines += ["", "---", "", "## Manual Verification Checklist", ""]

    checklist_done = set()
    for score, va, profile, calls, desc in candidates[:15]:
        if va in checklist_done:
            continue
        checklist_done.add(va)
        lines.append(f"- [ ] `{va:#010x}` ({profile}, score={score:.3f}): manual capstone trace + taint source")

    # Static taint analysis findings
    if taint_findings:
        lines += ["", "---", "", "## Static Taint Analysis Findings", "",
                  f"_{len(taint_findings)} direct source->sink data-flow path(s) confirmed._", ""]
        lines.append("| Func VA | Sink VA | Sink | Args | Sources |")
        lines.append("|---------|---------|------|------|---------|")
        for tf in taint_findings:
            args = " ".join(f"arg{i}" for i in tf.tainted_args)
            src = ", ".join(tf.source_calls) or "?"
            lines.append(
                f"| `{tf.func_va:#010x}` | `{tf.sink_va:#010x}` | "
                f"`{tf.sink_name}` | {args} | {src} |"
            )
        lines += ["", "> These are confirmed register-level data-flow paths.",
                  "> Verify manually that source calls are reachable from network input.", ""]

    # Interprocedural taint chains
    if taint_chains:
        lines += ["", "---", "", "## Interprocedural Taint Chains", "",
                  f"_{len(taint_chains)} cross-function source->sink chain(s) found._", ""]
        lines.append("| Source | Chain | Sink | Args |")
        lines.append("|--------|-------|------|------|")
        for tc in taint_chains:
            chain_str = " -> ".join(f"`0x{va:x}`" for va in tc.func_chain)
            args = " ".join(f"arg{i}" for i in tc.tainted_args)
            lines.append(
                f"| `{tc.source_name}` | {chain_str} | `{tc.sink_name}` | {args} |"
            )
        lines += ["", "> Full call chains crossing function boundaries.",
                  "> Verify that each hop actually passes the tainted value as shown.", ""]

    lines += [
        "",
        "---",
        "",
        f"_Report generated by Ablation. Target: {target_label}. Binary: {binary_name}._",
    ]

    md = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(md)

    return md
