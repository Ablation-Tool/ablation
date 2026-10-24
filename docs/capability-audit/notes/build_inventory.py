"""
build_inventory.py — Generate INVENTORY.md from capabilities.json

Reads capabilities.json, assigns each record to one of 10 taxonomy groups,
and writes ~/ablation/docs/capability-audit/INVENTORY.md.

Run: python3 -I build_inventory.py
"""

import json
import textwrap
from pathlib import Path
from collections import defaultdict

JSON_PATH = Path(__file__).parent.parent / "capabilities.json"
OUT_PATH  = Path(__file__).parent.parent / "INVENTORY.md"

# ---------------------------------------------------------------------------
# Group metadata
# ---------------------------------------------------------------------------

GROUPS = {
    1: {
        "title": "Binary Parsing & Session Infrastructure",
        "desc": (
            "The foundation layer: format-specific binary parsers (ELF, PE, XCOFF, M88K COFF, "
            "Mach-O, APK, BEAM, flat ROM), the BinaryContext parse-and-cache contract that all "
            "downstream tools depend on, disassembly engines, entropy mapping, and cross-reference "
            "indexing."
        ),
        "summary": (
            "Load any supported binary once; every downstream tool receives a populated "
            "BinaryContext with PLT, exports, call graph, and string cross-references."
        ),
    },
    2: {
        "title": "Control Flow & ISA Models",
        "desc": (
            "CFG builders for all supported ISAs, per-arch ISA/ABI data models, instruction "
            "decode backends (insn_*.py), non-ECU standalone decoders (V850, ARC, LoongArch, "
            "NanoMIPS, HiSiRV32), dataflow engines (reaching definitions, constant propagation), "
            "dominator analysis, function discovery, and function-start scanners."
        ),
        "summary": (
            "Build a control-flow graph, decode instructions, or enumerate function starts for "
            "any of the 10+ supported ISAs."
        ),
    },
    3: {
        "title": "Taint Analysis",
        "desc": (
            "Intraprocedural and interprocedural taint trackers across every supported ISA: "
            "x86-64, x86-32, ARM64, ARM32, MIPS32/64/nanoMIPS, PPC32/PPC64, RISC-V 32/64, "
            "ARC EM/HS, LoongArch64, V850/RH850, TriCore, s390x. Includes labeled-taint variants, "
            "cross-binary interprocedural chaining, BSS taint, IFDS-style field-writer finders, "
            "and source-code taint trackers."
        ),
        "summary": (
            "Trace attacker-controlled data from a source register to an exec/format/memcpy sink "
            "on any supported ISA with optional label and bound propagation."
        ),
    },
    4: {
        "title": "Sink Classification",
        "desc": (
            "The SinkArgClassifier family — per-architecture classifiers that label exec-sink "
            "call arguments as RODATA_CONST / SNPRINTF_RODATA / ARG_PROPAGATED / UNKNOWN, "
            "eliminating constant-argument sinks before taint analysis runs. Also covers "
            "sanitizer detection/filtering (x86-64), static-link sink scanning, network sink "
            "reachability, and PE sink classification."
        ),
        "summary": (
            "Classify all exec-sink call sites so taint analysis runs only on "
            "ARG_PROPAGATED / UNKNOWN sinks, not on safe RODATA_CONST calls."
        ),
    },
    5: {
        "title": "Vulnerability Scanners",
        "desc": (
            "Single-purpose scanners targeting specific vulnerability classes: format strings, "
            "heap corruption, SQL injection, sscanf overflow, integer overflow/underflow, "
            "deprecated functions, privilege escalation, BYOVD, Windows kernel drivers, web "
            "framework auth surfaces, AI/MCP security, supply-chain, SCA, build-time gates, "
            "compiler-bug detectors, and source-code scanners (Lua, Perl, Go, MCP)."
        ),
        "summary": (
            "Run a targeted scanner for a specific CWE class against a binary or source tree "
            "without building a full taint model."
        ),
    },
    6: {
        "title": "Firmware Extraction & Decryption",
        "desc": (
            "Firmware image extraction pipelines (FortiOS hardware appliance, OVF/ZIP, partition "
            "table), XOR key recovery, BMP-steganography key extraction, AIX installp/BFF archive "
            "decompression, Huawei VRP squashfs v4, AMI/ASPEED BMC CramFS, Mac Classic resource "
            "forks, and self-extracting installer binaries."
        ),
        "summary": (
            "Unpack or decrypt a firmware image and recover the embedded filesystem or "
            "executable content before analysis."
        ),
    },
    7: {
        "title": "Platform-Specific Analysis",
        "desc": (
            "Analysis tooling targeting formats or platforms beyond standard ELF/PE: ECU "
            "automotive ISAs (C166/C167, C28x, M68k, SH2a, VLE, MCS-51), HarmonyOS ArkTS/ARK "
            "bytecode, Android APK/DEX/JNI, Go (pclntab, garble, vmnetd), IBM POWER/PS3/Cell BE, "
            "Windows PE security analysis, C++ vtable reconstruction, MicroPython .mpy, Java "
            "JARs, VxWorks, and video container forensics."
        ),
        "summary": (
            "Analyze a binary targeting a specific non-standard platform, VM bytecode, or "
            "proprietary ISA not covered by the core ELF analysis chain."
        ),
    },
    8: {
        "title": "Semantic Search & Learning",
        "desc": (
            "The AI/ML-assisted analysis layer: SemanticSearcher (sentence embeddings over "
            "function descriptions using BAAI/bge-small-en-v1.5 via fastembed), CorpusBuilder "
            "(populates the embedding corpus), PatternLibrary (confirmed-pattern replay), "
            "FindingRegistry (de-duplication), AgentLoop (ReAct LLM loop), HypothesisEngine "
            "(probe selection and scoring), DTWMatcher, MatrixProfileDiff, and SAXIndex."
        ),
        "summary": (
            "Query a function corpus with plain-English descriptions, replay confirmed patterns "
            "across new binaries, or drive an LLM-supervised ReAct analysis loop."
        ),
    },
    9: {
        "title": "Host & Network Enumeration",
        "desc": (
            "Runtime enumeration and attack-surface analysis of live systems: Docker/container "
            "posture, Kubernetes cluster enumeration, network packet analysis (PCAP), Cisco "
            "IOS/NX-OS/HyperFlex/APIC, SIP/VoIP/RTP, lateral movement and C2 detection, "
            "forensics (physical memory, ELF), Windows live system, streaming infrastructure, "
            "and syscall tracing."
        ),
        "summary": (
            "Enumerate a live host or network, inspect running containers, or parse PCAP data "
            "for attack-surface enumeration and lateral-movement detection."
        ),
    },
    10: {
        "title": "Session Management & Tooling",
        "desc": (
            "Infrastructure that orchestrates the RE session: FORGE quality gate and local module "
            "store, WorkflowDocument stage pipeline, ScanResultVersionCache, StageCommitment "
            "audit chain, VendorProfile sink registration, MITRE ATT&CK technique labeling, "
            "sweep orchestration scripts (fortinet_sweep, ti_sweep, pe_sweep, corpus_miner, "
            "and others), and miscellaneous shared utilities (RegAnnotator, IPRegAnnotator, "
            "FuncProfiler, i386 XRef, syscall tables)."
        ),
        "summary": (
            "Gate new modules through FORGE, run an end-to-end sweep against a target, "
            "and record findings in a tamper-evident audit chain."
        ),
    },
}

# ---------------------------------------------------------------------------
# Group assignment
# ---------------------------------------------------------------------------

def assign_group(cap: dict) -> int:
    """Return a taxonomy group number 1-10 for a capability record."""
    unit = cap.get("unit", "")
    cat  = cap.get("category", "") or ""
    name = cap.get("name", "") or ""

    # Units that are wholly one group
    if unit == "A01": return 1
    if unit == "A02": return 2
    if unit == "A03": return 2
    if unit == "A04": return 3
    if unit == "A05": return 3
    if unit == "A07": return 4
    if unit == "A08": return 5
    if unit == "A12": return 8
    if unit == "M01": return 9

    # C01 — all core parsers and engines → Group 1
    if unit == "C01": return 1

    # -----------------------------------------------------------------------
    # A06 — taint variants, source-code auditing, vuln scanning
    # -----------------------------------------------------------------------
    if unit == "A06":
        if "Taint" in cat:         return 3
        if "Ingestion" in cat:     return 10
        return 5  # source-code auditing / vulnerability scanning

    # -----------------------------------------------------------------------
    # A09 — firmware extraction + Windows PE security
    # -----------------------------------------------------------------------
    if unit == "A09":
        if "Windows PE" in cat or "Symbol Integration" in cat:
            return 7
        return 6

    # -----------------------------------------------------------------------
    # A10 — ECU/automotive vs. generic ISA decoders
    # -----------------------------------------------------------------------
    if unit == "A10":
        ecu_keywords = ("ECU", "Automotive", "AI-MCU")
        if any(k in cat for k in ecu_keywords):
            return 7
        # FlatBinaryFuncStartScanner is ECU context (function discovery for flat ECU ROMs)
        if "Function Discovery / ECU" in cat:
            return 7
        # TiCoffLoader — TI embedded platform
        if "Binary Format Parser" in cat:
            return 7
        # Generic CFG / ISA decoders
        return 2

    # -----------------------------------------------------------------------
    # A11 — mobile, browser, Go, Java, Python bytecode platform tools
    # -----------------------------------------------------------------------
    if unit == "A11": return 7

    # -----------------------------------------------------------------------
    # A13 — IBM/PS3 platform RE + a few infrastructure/sink records
    # -----------------------------------------------------------------------
    if unit == "A13":
        g1_cats = {
            "XCOFF32/64 Symbol Table Parser / BinaryContext Populator",
            "ELF32 BE Utility Wrapper",
        }
        if cat in g1_cats:
            return 1
        g4_cats = {
            "Verified PLT Import Caller Tracer",
            "BL Call-Site Scanner (stripped PPC64 BE)",
            "Sink Argument Classifier — PPC64 BE ELFv1",
        }
        if cat in g4_cats:
            return 4
        if cat == "ABI Correctness / Vulnerability Scanner":
            return 5
        if "PPC32 Instruction Classifier" in cat:
            return 2  # ISA-level helper
        return 7

    # -----------------------------------------------------------------------
    # A14 — mixed: function discovery, taint helpers, firmware, semantic,
    #        crypto scanners, session tooling
    # -----------------------------------------------------------------------
    if unit == "A14":
        fd_cats = {
            "Function Discovery",
            "Function Discovery + Naming",
            "Function Discovery + Naming (Linux kernel modules)",
        }
        if cat in fd_cats:
            return 2
        taint_cats = {
            "False-Positive Reduction / Taint Classification",
            "Call-Chain Taint Analysis",
            "Call-Chain Taint Analysis (Multi-level)",
        }
        if cat in taint_cats:
            return 3
        if cat == "Steganography / Key Extraction":  return 6
        if cat == "Firmware XOR Decryption":         return 6
        if cat == "Shared Encoding Utility":         return 2  # low-level opcode helper
        semantic_cats = {
            "Dynamic Analysis / Behavioral Evidence",
            "Dynamic Analysis Safety Gate",
            "Hypothesis Engine Integration",
            "Game Engine Code Labeling",
            "Cross-Version Function Tracking",
        }
        if cat in semantic_cats:
            return 8
        if cat == "Crypto Pattern Detection":                    return 5
        if cat == "Dead Code Detection / False-Positive Reduction": return 5
        # Everything else is session management / tooling infrastructure
        return 10

    # -----------------------------------------------------------------------
    # M02 — AI/ML security scanners
    # -----------------------------------------------------------------------
    if unit == "M02":
        return 5

    # -----------------------------------------------------------------------
    # M03 — platform-specific RE + some firmware + taint helpers + scanners
    # -----------------------------------------------------------------------
    if unit == "M03":
        fw_cats = {
            "Firmware extraction — AMI/ASPEED BMC CramFS",
            "IBM AIX BFF archive decompressor",
            "Huawei VRP firmware squashfs v4 reader",
            "Self-extracting installer binary extractor",
        }
        if cat in fw_cats:
            return 6
        taint_cats = {
            "IFDS-style demand-driven inter-procedural field-writer finder — ARM64",
            "EmTaint-inspired ARM64 SSE backward slicer — BSS/GOT writer finder",
        }
        if cat in taint_cats:
            return 3
        scanner_cats = {
            "Exploit helper — MSF module ranking via BARE",
            "Windows kernel driver IOCTL attack surface generator",
            "PPC32 heap slot overflow pattern scanner",
        }
        if cat in scanner_cats:
            return 5
        return 7

    # -----------------------------------------------------------------------
    # M04 — vulnerability scanners + platform + ML/cross-version + tooling
    # -----------------------------------------------------------------------
    if unit == "M04":
        platform_cats = {
            "Platform-Specific Analysis — VxWorks PPC32",
            "Automotive — CAN Protocol",
            "Automotive — ECU Calibration (Nissan/Pytrex)",
            "Mobile RE — JNI Surface (Target-Specific Script)",
            "Mobile RE — JNI Structural Analysis (Target-Specific Script)",
        }
        if cat in platform_cats:
            return 7
        if "Taint Analysis" in cat:
            return 3
        semantic_cats = {
            "Cross-Version Diffing — Function Similarity",
            "Cross-Version Diffing — ML Fine-tuning",
            "Function Recognition — PLT Slot Classification",
            "String Analysis — Obfuscated String Decoding",
            "Malware Analysis — Defense Evasion Detection",
        }
        if cat in semantic_cats:
            return 8
        tooling_cats = {
            "Reporting — ATT&CK Technique Auto-Assignment",
            "Internal Infrastructure — Shared Disassembly",
        }
        if cat in tooling_cats:
            return 10
        return 5

    # -----------------------------------------------------------------------
    # S01 — sweeps and workflow documents
    # -----------------------------------------------------------------------
    if unit == "S01":
        return 10

    return 0  # uncategorized fallback


# ---------------------------------------------------------------------------
# Markdown helpers
# ---------------------------------------------------------------------------

def _safe(s: object, maxlen: int = 0) -> str:
    """Return a string safe for a Markdown table cell."""
    t = str(s or "").strip()
    # collapse internal newlines
    t = " ".join(t.split())
    if maxlen and len(t) > maxlen:
        t = t[: maxlen - 1] + "…"
    return t or "—"


def _paths(cap: dict) -> str:
    p = cap.get("paths") or []
    if isinstance(p, list):
        # keep only the filename part
        short = []
        for item in p:
            item = str(item)
            # extract first path-like token
            tokens = item.split()
            if tokens:
                short.append(tokens[0])
        return ", ".join(short[:2]) + ("…" if len(p) > 2 else "")
    return _safe(p, 80)


def build_table(records: list[dict]) -> str:
    rows = ["| Name | What it does | Scope | Status | Path |",
            "|------|-------------|-------|--------|------|"]
    for cap in records:
        name   = _safe(cap.get("name"), 60)
        what   = _safe(cap.get("what_it_does"), 160)
        scope  = _safe(cap.get("scope"), 80)
        status = _safe(cap.get("status"), 20)
        path   = _paths(cap)
        rows.append(f"| {name} | {what} | {scope} | {status} | {path} |")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    caps: list[dict] = json.loads(JSON_PATH.read_text())

    # Assign groups
    by_group: dict[int, list[dict]] = defaultdict(list)
    unassigned = []
    for cap in caps:
        g = assign_group(cap)
        if g == 0:
            unassigned.append(cap)
        else:
            by_group[g].append(cap)

    # Build INVENTORY.md
    lines = []

    lines.append("# Ablation Capability Inventory")
    lines.append("")
    lines.append(f"**Version:** 2.86.0  ")
    lines.append(f"**Generated:** 2026-10-24  ")
    lines.append(f"**Source:** {len(caps)} capability records across 20 audit units  ")
    lines.append(f"**Plus:** 6 undocumented capabilities (cli.py, sarif.py, binja_plugin.py, "
                 "loongarch_decoder_v2.py, json_export.py, demo_curl.py)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Contents")
    lines.append("")
    for gnum, gmeta in GROUPS.items():
        count = len(by_group[gnum])
        lines.append(f"- [Group {gnum}: {gmeta['title']}](#{gnum}-{gmeta['title'].lower().replace(' ', '-').replace('&', '').replace('/', '').replace('--', '-')}) ({count})")
    lines.append("- [Undocumented Capabilities](#undocumented-capabilities) (6)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Per-group sections
    for gnum, gmeta in GROUPS.items():
        records = by_group[gnum]
        lines.append(f"## Group {gnum}: {gmeta['title']} ({len(records)})")
        lines.append("")
        lines.append(gmeta["desc"])
        lines.append("")
        lines.append(build_table(records))
        lines.append("")
        lines.append(f"**What you can do with this:** {gmeta['summary']}")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Undocumented capabilities section (from UNMAPPED.md)
    lines.append("## Undocumented Capabilities")
    lines.append("")
    lines.append(
        "Six files identified by the Phase 1 COVERAGE audit as uncovered in the main "
        "capability notes. Each has a full record in "
        "`docs/capability-audit/notes/UNMAPPED.md`."
    )
    lines.append("")

    undoc_rows = [
        ("ablation.cli.main / cmd_* dispatch",
         "The package's CLI entry point. Implements 30+ subcommands (analyze, taint, sweep, "
         "findings, driver, byovd, fmtstr, heap, mips, mips64, ppc32/64, riscv32/64, arc, "
         "v850, loongarch64, nanomips, nanomips-taint, sigs, cfg, search, corpus, crypto, "
         "news, window, profile, overflow, arc-decode, v850-decode, loongarch64-decode) "
         "via argparse with lazy imports. Supports --json/--sarif output on sweep and findings.",
         "All subcommands and binary formats supported by the analyzers",
         "implemented",
         "ablation/ablation/cli.py"),
        ("sweep_to_json, findings_to_json, write_json, write_sarif",
         "Converts PatternLibrary.sweep() results and FindingRegistry.list_findings() output "
         "to a flat custom JSON schema. write_sarif() is a thin alias for write_json() — it "
         "does not validate SARIF structure; use sarif.py for standards-compliant SARIF.",
         "Sweep results and confirmed findings only; no BinaryContext or corpus serialization",
         "implemented",
         "ablation/ablation/export/json_export.py"),
        ("sweep_to_sarif, findings_to_sarif, _severity_to_sarif",
         "Produces SARIF 2.1.0 documents for GitHub Code Scanning, VS Code Problems panel, "
         "and OASIS-compliant SAST platforms. Maps CWE severity to SARIF levels. Known issue: "
         "ruleId collision when two queries share a tag prefix after slugification.",
         "Sweep results and confirmed findings; no per-arch taint output (mips/ppc/riscv subcommands do not emit SARIF)",
         "implemented",
         "ablation/ablation/export/sarif.py"),
        ("binja_plugin — annotate_from_corpus, sweep_binary, semantic_search",
         "Three Binary Ninja menu commands under Ablation\\: corpus-name annotation from "
         "~/.ablation/func_id.db, PatternLibrary sweep with bookmark tagging, and "
         "SemanticSearcher query with navigation to highest-scoring function. Note: "
         "auto-annotation on binary open described in the module docstring is NOT implemented.",
         "Any BN-supported binary format indexed via ablation corpus",
         "implemented",
         "ablation/ablation/integrations/binja_plugin.py"),
        ("LoongArchDecoderV2, LoongArchFrameV2, LoongArchDisasmV2",
         "Extends LoongArchDecoder (V1) with a two-pass KASAN/KCOV instrumentation-stripping "
         "layer for CONFIG_KASAN=y / CONFIG_KCOV=y debug kernels. Tags bl calls to KASAN/KCOV "
         "VAs and marks the shadow-address preamble sequence (srli.d, lu12i.w, addi.d, ld.b). "
         "decode_frames_clean() yields only real program-logic instructions. Not wired to any "
         "CLI subcommand; loongarch64-decode routes through V1.",
         "LoongArch64 fixed-width 32-bit instructions; KASAN/KCOV debug kernels (TencentOS 4.6 6.6.119)",
         "implemented",
         "ablation/ablation/analyzers/loongarch_decoder_v2.py"),
        ("demo_curl.py",
         "End-to-end walkthrough script demonstrating BinaryContext, XRefGraph, CFGBuilder, "
         "CorpusBuilder, and SemanticSearcher against /usr/bin/curl or any ELF binary. "
         "Timed sections, no assertions. Documentation example, not a capability.",
         "Exercises 5 core capabilities only; no taint, scanners, or export modules",
         "implemented (example code)",
         "ablation/docs/demo_curl.py"),
    ]

    undoc_lines = [
        "| Name | What it does | Scope | Status | Path |",
        "|------|-------------|-------|--------|------|",
    ]
    for name, what, scope, status, path in undoc_rows:
        undoc_lines.append(f"| {name} | {what} | {scope} | {status} | {path} |")
    lines.extend(undoc_lines)
    lines.append("")
    lines.append("---")
    lines.append("")

    # Summary
    total = len(caps) + 6
    group_counts = {g: len(by_group[g]) for g in range(1, 11)}
    lines.append("## Summary")
    lines.append("")
    lines.append(f"Total capabilities listed: **{total}** ({len(caps)} from audit + 6 undocumented)")
    lines.append("")
    lines.append("| Group | Title | Count |")
    lines.append("|-------|-------|-------|")
    for gnum, gmeta in GROUPS.items():
        lines.append(f"| {gnum} | {gmeta['title']} | {group_counts[gnum]} |")
    lines.append(f"| — | Undocumented | 6 |")
    lines.append(f"| — | **Total** | **{total}** |")
    lines.append("")
    if unassigned:
        lines.append(f"**Unassigned records ({len(unassigned)}):**")
        for cap in unassigned:
            lines.append(f"- {cap.get('id')}: {cap.get('name')} (unit={cap.get('unit')}, cat={cap.get('category')!r})")
        lines.append("")

    OUT_PATH.write_text("\n".join(lines) + "\n")
    print(f"Written: {OUT_PATH}")
    print(f"Total records mapped: {sum(group_counts.values())} + {len(unassigned)} unassigned")
    for g in range(1, 11):
        print(f"  Group {g} ({GROUPS[g]['title'][:40]}): {group_counts[g]}")


if __name__ == "__main__":
    main()
