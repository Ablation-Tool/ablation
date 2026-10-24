#!/usr/bin/env python3
"""
extract_capabilities.py — Phase 1 capability audit extractor.

Reads the 20 unit notes files (A01–S01), extracts all named capability records,
normalises them into a canonical JSON schema, and writes:
  - ~/ablation/docs/capability-audit/capabilities.json
  - ~/ablation/docs/capability-audit/capabilities.csv
"""

import re
import json
import csv
import os
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

NOTES_DIR = Path(__file__).parent
OUTPUT_DIR = NOTES_DIR.parent  # docs/capability-audit/

UNIT_FILES = [
    "A01.md", "A02.md", "A03.md", "A04.md", "A05.md",
    "A06.md", "A07.md", "A08.md", "A09.md", "A10.md",
    "A11.md", "A12.md", "A13.md", "A14.md", "C01.md",
    "M01.md", "M02.md", "M03.md", "M04.md", "S01.md",
]

# ---------------------------------------------------------------------------
# Heading patterns that identify a capability record (not a section header)
# ---------------------------------------------------------------------------

NON_RECORD_TITLE_PATTERNS = [
    r"^(Summary|Support Matrix|Key Findings|Architecture gaps|Doc-Code|Tests Coverage"
    r"|from_context\(\)|Coverage|Discrepanc|Reference doc|Top Discrepanc"
    r"|Summary Statistics|Notes for|Dependencies Not|Sub-theme|ISA Support"
    r"|Module inventory|Files covered|ECU ISA Support|Verdict class"
    r"|Dependencies|Summary of|HIGH — Likely|MEDIUM — |LOW — |Capabilities$"
    r"|Capability Records$|Sub-capabilities|Session \d|Support Matrix"
    r"|Key sub-capabilities|Doc/Code Discrepancies|Known |Architecture support"
    r"|Strategy|Verdicts|Constructor note|Scope note|Default sinks"
    r"|snprintf-family|Key methods|Key helpers|Key sub-cap|Key difference"
    r"|Algorithm|Four capabilities|Three reclassif|Stripped binary"
    r"|PPC64-SAC|Power10|GEP handling|Fallback scan|Pointer reads|Scope limit"
    r"|Byte verification|Extended default|PLT fallback|Session \d|Scope limitation"
    r"|Lookback window|SinkClassification|Architecture dispatch|ABI:|String-load"
    r"|String patterns|State transitions|Call sites|GOT resolution|N32 detection"
    r"|snprintf-family|Key methods|Key helpers|Extended default|PLT fallback"
    r"|Default sinks|Format string|Call site|Func starts|Far-call|String XRef"
    r"|PLT extraction|func_starts extraction|Call graph|Sub-theme"
    r"|Doc-Unit|Files in|file section|ARM32 mode|Thumb|Sub-theme|arm64|arm32"
    r"|\d+ capabilities)",
    r"\.py \(lines",  # file section headers like "## ami_cramfs_extractor.py (lines...)"
    r"\.py$",         # bare file headers like "## arm64_global_tracker.py"
]
_NON_RECORD_RE = re.compile("|".join(NON_RECORD_TITLE_PATTERNS), re.IGNORECASE)

# Regex to detect a capability record body.
# Notes use BOTH forms: **field:** value  AND  **field**: value  AND  **field** : value
# We match `**fieldname` followed by optional colon, then closing `**`, then colon/space.
_FIELD_NAMES = (
    r"name|category|what\s+it\s+does|entry\s+point|paths?|status"
    r"|inputs?|outputs?|scope|evidence|docs|limitations|dependencies"
    r"|File|Class|Purpose|Architecture scope|Verdict classes?"
    r"|what it does|entry point|ref docs|reference docs|deps"
)

RECORD_FIELD_SIGNALS = re.compile(
    r"(?:^|\n)[ \t]*[-*]?\s*\*\*(?:" + _FIELD_NAMES + r"):?\*\*",
    re.IGNORECASE | re.MULTILINE
)

# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

def _strip_markdown(text: str) -> str:
    """Remove backticks, bold/italic markers, trailing spaces from a value string."""
    text = re.sub(r"`([^`]*)`", r"\1", text)   # backticks
    text = re.sub(r"\*\*([^*]*)\*\*", r"\1", text)  # bold
    text = re.sub(r"\*([^*]*)\*", r"\1", text)       # italic
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _field_pattern(field: str) -> re.Pattern:
    """Build a regex that matches **field:** or **field**: in a section body.

    Handles all observed variants:
      - **field:** value   (colon inside bold)
      - **field**: value   (colon after bold)
      - **field** : value  (colon with space after bold)
    Followed by value up to the next field marker or heading.
    """
    esc = re.escape(field)
    # Matches:
    #  optional line-start + optional list marker + **fieldname:?** + optional colon + spaces + value
    return re.compile(
        r"(?:(?:^|\n)[ \t]*[-*]?\s*)?"   # optional line-start and list marker
        r"\*\*" + esc + r":?\*\*\s*[:：]?\s*"  # **field:** or **field**: or **field**:
        r"(.+?)"                                  # captured value
        r"(?=\n[ \t]*[-*]?\s*\*\*|\n#{1,6}\s|\n---+\s*\n|\Z)",
        re.IGNORECASE | re.DOTALL
    )


# Pre-build patterns for common field names (handles colon-inside and colon-outside)
_FIELD_SYNONYMS = {
    "name":          ["name"],
    "category":      ["category"],
    "paths":         ["paths", "path"],
    "entry_point":   ["entry point", "entry_point", "entry-point"],
    "what_it_does":  ["what it does", "what_it_does", "purpose", "Purpose"],
    "inputs":        ["inputs / outputs", "inputs/outputs", "inputs", "input"],
    "outputs":       ["outputs", "output"],
    "scope":         ["scope", "Architecture scope", "target formats", "arches"],
    "status":        ["status"],
    "evidence":      ["evidence", "tests", "test"],
    "docs":          ["docs", "ref docs", "reference docs", "documentation"],
    "limitations":   ["limitations", "known gaps", "known-anomalies", "Limitations"],
    "dependencies":  ["dependencies", "deps", "dep"],
    "claims":        ["claims to verify", "claims"],
    "file":          ["file", "File"],
    "class":         ["class", "Class"],
}


def _extract_field(body: str, *field_names) -> str:
    """Extract value for the first matching field name from a section body."""
    for fname in field_names:
        pat = _field_pattern(fname)
        m = pat.search(body)
        if m:
            val = m.group(1).strip()
            # Remove trailing markdown horizontal rule
            val = re.sub(r"\n---+\s*$", "", val).strip()
            # Collapse excessive newlines
            val = re.sub(r"\n\s*\n", "\n", val).strip()
            return _strip_markdown(val)
    return ""


def _extract_paths(body: str) -> list:
    """Extract paths field as a list."""
    raw = _extract_field(body, "paths", "path", "file", "File")
    if not raw:
        return []
    items = []
    for part in re.split(r"[,\n;]", raw):
        part = part.strip().lstrip("-*").strip()
        if part and len(part) > 2:
            items.append(part)
    return items[:10]  # cap at 10


def _infer_workflow_stage(category: str, name: str) -> str:
    """Map category string to a workflow stage."""
    cat_lower = category.lower()
    name_lower = name.lower()

    if any(k in cat_lower for k in ["firmware unpacking", "extraction", "xor decryption",
                                      "firmware decrypt", "container", "firmware extraction"]):
        return "unpack"
    if any(k in cat_lower for k in ["binary pars", "session infrastructure",
                                      "elf pars", "pe pars", "macho",
                                      "xcoff", "coff", "format dispatch",
                                      "universal magic"]):
        return "ingest"
    if any(k in cat_lower for k in ["cfg construction", "isa/abi", "isa model", "insn",
                                      "decoder", "disassem", "instruction model",
                                      "function discovery", "func_start",
                                      "syscall class", "shared encoding",
                                      "abi model"]):
        return "decode"
    if any(k in cat_lower for k in ["taint analys", "sink class", "sink arg", "sanitizer",
                                      "network sink", "static.*sink", "pe sink",
                                      "argv build", "format string", "heap", "sql injection",
                                      "buffer overflow", "integer", "deprecated",
                                      "privilege escal", "vulnerability", "vuln",
                                      "exploit", "byovd", "kernel driver", "kernel module",
                                      "code injection", "shell injection", "web framework",
                                      "attack surface", "pre-auth", "apache", "cmdb",
                                      "go.*subprocess", "source analysis", "ai/mcp",
                                      "build system", "compiler", "false-positive",
                                      "abi correctness", "process analys",
                                      "windows kernel", "dispatch table"]):
        return "find_vulns"
    if any(k in cat_lower for k in ["register annotation", "function profiling",
                                      "call-chain taint", "interprocedural",
                                      "cross-version", "game engine", "dead code",
                                      "command table", "cross-reference", "xref",
                                      "dataflow", "cfg fix", "reaching def",
                                      "const prop", "entropy", "window anal",
                                      "struct", "encoding dag", "expr",
                                      "call-site", "steganograph", "crypto",
                                      "binary pars", "parser",
                                      "ecu", "ecu arch", "ecu rom",
                                      "enum", "enumerator",
                                      "isa/abi", "isa model"]):
        return "analyze"
    if any(k in cat_lower for k in ["dynamic analys", "path solver", "sandbox",
                                      "probing", "hypothesis", "evidence"]):
        return "verify"
    if any(k in cat_lower for k in ["report", "finding registr", "session manag",
                                      "caching", "audit chain", "tamper",
                                      "workflow", "stage commit", "quality gate",
                                      "vendor config", "vendor sink",
                                      "module quality", "local module"]):
        return "report"
    if any(k in cat_lower for k in ["semantic search", "corpus", "pattern lib",
                                      "name registr", "sax index", "subsequence",
                                      "dtw", "matrix profile", "sig lib",
                                      "probe rank", "learning", "llm-analyst",
                                      "rag", "tool registr", "context builder"]):
        return "learn"
    if any(k in cat_lower for k in ["sweep", "enumerat"]):
        return "find_vulns"
    if any(k in name_lower for k in ["sweep", "fortinet_sweep", "base_sweep"]):
        return "find_vulns"
    return "analyze"


def _normalise_status(status: str) -> str:
    """Normalise status to one of the enum values."""
    s = status.lower()
    if "partial" in s:
        return "partial"
    if "stub" in s:
        return "stub"
    if "experimental" in s:
        return "experimental"
    if "implemented" in s:
        return "implemented"
    return status.strip() or "unknown"


def _infer_doc_match(body: str, docs: list) -> str:
    """Infer doc_match from body text."""
    body_lower = body.lower()
    if any(k in body_lower for k in ["mismatch", "incorrect", "outdated", "inaccurate",
                                       "refuted", "partially outdated", "minor inaccuracy",
                                       "doc says", "not verified against"]):
        return "mismatch"
    if not docs or all(any(neg in d.lower() for neg in ["none", "no dedicated", "not read",
                                                          "not found", "no matching"])
                        for d in docs):
        return "none"
    return "matches"


# ---------------------------------------------------------------------------
# Section splitting
# ---------------------------------------------------------------------------

def split_into_sections(text: str):
    """Yield (heading_level, heading_text, section_body) tuples."""
    lines = text.split("\n")
    current_level = 0
    current_title = ""
    current_body_lines = []

    for line in lines:
        m = re.match(r"^(#{1,6})\s+(.*)", line)
        if m:
            if current_title or current_body_lines:
                yield current_level, current_title, "\n".join(current_body_lines)
            current_level = len(m.group(1))
            current_title = m.group(2).strip()
            current_body_lines = []
        else:
            current_body_lines.append(line)

    if current_title or current_body_lines:
        yield current_level, current_title, "\n".join(current_body_lines)


def is_capability_record(title: str, body: str) -> bool:
    """Return True if this section is a capability record."""
    if _NON_RECORD_RE.search(title):
        return False

    content_lines = [l for l in body.split("\n") if l.strip()]
    if len(content_lines) < 2:
        return False

    if RECORD_FIELD_SIGNALS.search(body):
        return True

    return False


def extract_name_from_heading(title: str) -> str:
    """Extract the capability name from a heading string."""
    # CAP-A07-01 — ClassName (description) or CAP-A07-01 — ClassName
    m = re.match(r"CAP-[A-Z0-9]+-\d+[a-z]?\s*[—:-]+\s*(.+)", title, re.IGNORECASE)
    if m:
        name = m.group(1).strip()
        name = re.sub(r"\s+\([^)]*\)\s*$", "", name).strip()
        return name

    # N. ClassName or N. ClassName (description)
    m = re.match(r"^\d+[a-z]?\.\s+(.+)", title)
    if m:
        name = m.group(1).strip()
        name = re.sub(r"\s+\([^)]*\)\s*$", "", name).strip()
        return name

    # Capability: ClassName — description
    m = re.match(r"Capability:\s*(.+?)(?:\s+[—-]+\s+|\s*$)", title, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    # CAP: ClassName — description
    m = re.match(r"CAP:\s*(.+?)(?:\s+[—-]+\s+|\s*$)", title, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    # SWEEP: name
    m = re.match(r"SWEEP:\s*(.+)", title, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    return title.strip()


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_unit(filepath: Path, unit_id: str):
    """Parse a single notes file and return list of capability dicts."""
    text = filepath.read_text(encoding="utf-8")
    records = []
    seq = 0

    for level, title, body in split_into_sections(text):
        if level < 2:
            continue

        if not is_capability_record(title, body):
            continue

        # Extract name: prefer body field, fall back to heading
        name_from_field = _extract_field(body, "name")
        name_from_heading = extract_name_from_heading(title)

        if name_from_field and len(name_from_field) < 100:
            name = name_from_field.strip("`").strip()
        else:
            name = name_from_heading.strip("`").strip()

        # Trim very long names
        if len(name) > 120:
            name = name[:120]

        category = _extract_field(body, "category")
        paths = _extract_paths(body)

        # Entry point - check multiple field names
        entry_point = _extract_field(body, "entry point", "entry_point",
                                      "entry-point", "constructors",
                                      "Constructors")

        what_it_does = _extract_field(body, "what it does", "what_it_does",
                                       "purpose", "Purpose")

        # Inputs/outputs
        inputs_raw = _extract_field(body, "inputs / outputs", "inputs/outputs",
                                     "inputs", "input")
        outputs_raw = _extract_field(body, "outputs", "output")

        # If combined, try to split
        if inputs_raw and not outputs_raw:
            if "→" in inputs_raw or " -> " in inputs_raw:
                parts = re.split(r"[→]| -> ", inputs_raw, maxsplit=1)
                if len(parts) == 2:
                    inputs_raw, outputs_raw = parts[0].strip(), parts[1].strip()

        scope = _extract_field(body, "scope", "Architecture scope",
                                "target formats", "arches")

        status_raw = _extract_field(body, "status")
        status = _normalise_status(status_raw)

        # Evidence
        evidence_raw = _extract_field(body, "evidence", "tests", "test")
        evidence = []
        if evidence_raw:
            for part in re.split(r"[;\n]", evidence_raw):
                part = part.strip().lstrip("-*").strip()
                if part and len(part) > 3 and "no " not in part.lower()[:4]:
                    evidence.append(part)

        # Docs
        docs_raw = _extract_field(body, "docs", "ref docs", "reference docs",
                                   "documentation")
        docs = []
        if docs_raw:
            for part in re.split(r"[;\n]", docs_raw):
                part = part.strip().lstrip("-*").strip()
                if part and len(part) > 3:
                    docs.append(part)

        doc_match = _infer_doc_match(body, docs)

        limitations = _extract_field(body, "limitations", "known gaps",
                                      "Limitations")

        # Dependencies
        deps_raw = _extract_field(body, "dependencies", "deps", "dep")
        dependencies = []
        if deps_raw:
            for part in re.split(r"[,\n]", deps_raw):
                part = part.strip().lstrip("-*").strip()
                part = re.sub(r"\s*\(.*?\)", "", part).strip()
                if part and len(part) > 1 and part != "None":
                    dependencies.append(part)

        # Claims to verify
        claims_raw = _extract_field(body, "claims to verify", "claims")
        claims = []
        if claims_raw:
            for part in re.split(r"[;\n]", claims_raw):
                part = part.strip().lstrip("-*").strip()
                if part and len(part) > 5:
                    claims.append(part)

        workflow_stage = _infer_workflow_stage(category, name)

        seq += 1
        cap_id = f"{unit_id}-{seq:03d}"

        record = {
            "id": cap_id,
            "name": name,
            "unit": unit_id,
            "category": category,
            "final_category": "",
            "paths": paths,
            "entry_point": entry_point[:600] if entry_point else "",
            "what_it_does": what_it_does[:600] if what_it_does else "",
            "inputs": inputs_raw[:400] if inputs_raw else "",
            "outputs": outputs_raw[:400] if outputs_raw else "",
            "scope": scope[:400] if scope else "",
            "status": status,
            "evidence": evidence,
            "docs": docs,
            "doc_match": doc_match,
            "limitations": limitations[:400] if limitations else "",
            "dependencies": dependencies,
            "workflow_stage": workflow_stage,
            "claims": claims,
        }
        records.append(record)

    return records


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    all_records = []
    parse_errors = []
    unit_counts = {}

    for fname in UNIT_FILES:
        unit_id = fname.replace(".md", "")
        fpath = NOTES_DIR / fname
        if not fpath.exists():
            parse_errors.append(f"MISSING: {fpath}")
            continue

        try:
            records = parse_unit(fpath, unit_id)
            all_records.extend(records)
            unit_counts[unit_id] = len(records)
        except Exception as e:
            parse_errors.append(f"ERROR in {fname}: {e}")
            import traceback
            traceback.print_exc()

    # Write JSON
    json_path = OUTPUT_DIR / "capabilities.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2, ensure_ascii=False)

    # Write CSV
    csv_path = OUTPUT_DIR / "capabilities.csv"
    CSV_FIELDS = ["id", "name", "unit", "final_category", "what_it_does",
                  "scope", "status", "entry_point"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in all_records:
            writer.writerow(rec)

    # Print summary
    print(f"\n=== Extraction Complete ===")
    print(f"Total capability records: {len(all_records)}")
    print(f"\nRecords per unit:")
    for unit_id in [u.replace(".md", "") for u in UNIT_FILES]:
        count = unit_counts.get(unit_id, 0)
        print(f"  {unit_id:6s}: {count:3d}")

    from collections import Counter
    cat_counts = Counter(r["category"] for r in all_records if r["category"])
    print(f"\nTop categories ({len(cat_counts)} distinct):")
    for cat, count in cat_counts.most_common(40):
        print(f"  {count:3d}  {cat}")

    if parse_errors:
        print(f"\nParse errors ({len(parse_errors)}):")
        for e in parse_errors:
            print(f"  {e}")

    print(f"\nOutput files:")
    print(f"  {json_path}")
    print(f"  {csv_path}")

    return all_records


if __name__ == "__main__":
    main()
