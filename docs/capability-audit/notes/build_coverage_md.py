#!/usr/bin/env python3
"""
Build COVERAGE.md for the Ablation capability audit.
Maps every code file to capabilities documented in the 20 unit notes files.
"""

import os
import re
import sys
from pathlib import Path
from collections import defaultdict

NOTES_DIR = Path(__file__).parent
AUDIT_DIR = NOTES_DIR.parent
FILE_LIST = NOTES_DIR / "file-list.txt"
OUTPUT = AUDIT_DIR / "COVERAGE.md"

CODE_TYPES = {"code-ablation", "code-modules", "code-sweep", "code-other", "code"}

UNIT_FILES = [
    "A01.md", "A02.md", "A03.md", "A04.md", "A05.md",
    "A06.md", "A07.md", "A08.md", "A09.md", "A10.md",
    "A11.md", "A12.md", "A13.md", "A14.md",
    "C01.md",
    "M01.md", "M02.md", "M03.md", "M04.md",
    "S01.md",
]

# Human-readable unit titles
UNIT_TITLES = {
    "A01": "Core Infrastructure",
    "A02": "CFG Builders + Analysis Engines",
    "A03": "ISA + Instruction Models",
    "A04": "Taint Trackers",
    "A05": "Path / Constraint Solvers",
    "A06": "Scanners: Format String, Overflow, Stack, Heap",
    "A07": "Protocol + Service Analyzers",
    "A08": "Platform-Specific Analyzers",
    "A09": "Utility / Support Analyzers",
    "A10": "Archive + Firmware Extractors",
    "A11": "Corpus + Pattern Infrastructure",
    "A12": "LLM-Assisted Analysis",
    "A13": "Cross-Version Diff + Version Tracking",
    "A14": "Specialized Scanners",
    "C01": "FORGE Audit Engine",
    "M01": "Modules: Network/Cloud Enumeration",
    "M02": "Modules: Post-Exploitation",
    "M03": "Modules: Exploitation + Payloads",
    "M04": "Modules: Cisco + IoT Platform",
    "S01": "Sweep Drivers",
}


def load_code_files():
    """Return list of (type, size, lines, path) for all code files."""
    entries = []
    with open(FILE_LIST) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|", 3)
            if len(parts) != 4:
                continue
            ftype, size, nlines, path = parts
            if ftype in CODE_TYPES:
                entries.append((ftype, int(size), int(nlines), path))
    return entries


def load_unit_contents():
    """Return dict: unit_name -> full text content."""
    units = {}
    for fname in UNIT_FILES:
        fpath = NOTES_DIR / fname
        unit = fname.replace(".md", "")
        if fpath.exists():
            units[unit] = fpath.read_text()
        else:
            units[unit] = ""
    return units


def extract_capability_names_for_file(basename, filepath, unit_text):
    """
    Extract capability names from unit_text that are associated with basename/filepath.
    Returns list of capability name strings.
    """
    caps = []
    # Split into sections by ## or ### headers
    # Find sections that mention the file
    sections = re.split(r'\n(?=##+ )', unit_text)
    for section in sections:
        # Check if this section mentions the file
        if basename not in section and filepath not in section:
            continue
        # Extract the header as the capability name
        header_match = re.match(r'##+ (.+)', section.strip())
        if header_match:
            cap_title = header_match.group(1).strip()
            # Clean up common prefixes
            cap_title = re.sub(r'^(CAP-[A-Z0-9]+-\d+:\s*|CAP:\s*|Capability:\s*)', '', cap_title)
            # Skip structural headers that aren't capabilities
            skip_words = {'Files covered', 'Files read', 'Summary', 'Cross-cutting',
                         'Doc/code discrepancies', 'Observations', 'Capabilities',
                         'Module inventory', 'ISA Support Matrix', 'CFGResult Schema',
                         'Capability Records', 'SWEEP:'}
            if any(cap_title.startswith(w) for w in skip_words):
                # Try to find a - **name**: field in this section
                name_match = re.search(r'\*\*name\*\*[:\s]+[`"]?([^`"\n]+)[`"]?', section)
                if name_match:
                    cap_title = name_match.group(1).strip()
                else:
                    continue
            caps.append(cap_title)

    # Also look for - **name**: entries that mention the file nearby
    # This catches files mentioned in capability records with a **paths**: field
    # Parse blocks: find all **paths**: lines and check if they contain our file,
    # then look backward for the capability name
    lines = unit_text.split('\n')
    for i, line in enumerate(lines):
        if basename in line or filepath in line:
            # Search backward (up to 30 lines) for a capability header
            for j in range(i-1, max(0, i-30), -1):
                hdr = lines[j]
                if re.match(r'##+ ', hdr):
                    cap_title = re.sub(r'^##+ ', '', hdr).strip()
                    cap_title = re.sub(r'^(CAP-[A-Z0-9]+-\d+:\s*|CAP:\s*|Capability:\s*)', '', cap_title)
                    if cap_title and cap_title not in caps:
                        caps.append(cap_title)
                    break
                # Also check for - **name**:
                name_m = re.match(r'\s*-\s*\*\*name\*\*[:\s]+[`"]?([^`"\n,]+)', hdr)
                if name_m:
                    nm = name_m.group(1).strip()
                    if nm and nm not in caps:
                        caps.append(nm)
                    break

    # Deduplicate preserving order
    seen = set()
    result = []
    for c in caps:
        c_clean = c.strip().strip('`').strip('"').strip("'")
        if c_clean and c_clean not in seen:
            seen.add(c_clean)
            result.append(c_clean)

    return result[:4]  # Cap at 4 capability names per file per unit to keep table readable


def find_primary_unit(path, covered_by, unit_contents):
    """
    Determine the primary unit for a file when covered by multiple units.
    Rules:
    - For sweeps/: S01
    - For modules/: M-series
    - For analyzers/: A-series
    Priority: unit where file is most prominently mentioned (closer to "Files covered" list).
    """
    if path.startswith("sweeps/"):
        for u in covered_by:
            if u.startswith("S"):
                return u
    if path.startswith("ablation/modules/"):
        for u in covered_by:
            if u.startswith("M"):
                return u
    # For covered_by with one entry, trivial
    if len(covered_by) == 1:
        return covered_by[0]
    # For multiple, prefer A-series then others, and pick lowest unit number
    # But first check which unit's "Files covered" section mentions this file
    basename = os.path.basename(path)
    for u in sorted(covered_by):
        text = unit_contents[u]
        # Look for file list at top (within first 50 lines)
        top = '\n'.join(text.split('\n')[:50])
        if basename in top:
            return u
    return sorted(covered_by)[0]


def get_file_status(path, covered_by, unit_contents):
    """Determine status: covered | partial | stub | unmapped"""
    if not covered_by:
        return "unmapped"
    basename = os.path.basename(path)
    # Check if there's a meaningful capability description for this file
    for u in covered_by:
        text = unit_contents[u]
        caps = extract_capability_names_for_file(basename, path, text)
        if caps:
            return "covered"
    # Mentioned but no capability description extracted
    return "partial"


def classify_uncovered(path, lines, ftype):
    """Classify why a file is uncovered."""
    basename = os.path.basename(path)
    # demo/example
    if "demo" in basename or path.startswith("docs/"):
        return "example/demo script", "S01 (example only)"
    # CLI
    if basename == "cli.py":
        return "genuine gap — CLI entry point undocumented", "A04 or A12"
    # export
    if "export" in path:
        return "genuine gap — export module undocumented", "A14"
    # integration
    if "integrations" in path or "binja" in path:
        return "genuine gap — Binary Ninja plugin undocumented", "A14"
    # LoongArch v2
    if "loongarch" in basename and "v2" in basename:
        return "genuine gap — KASAN/KCOV-aware LoongArch64 decoder undocumented", "A03"
    return "genuine gap — not documented in any unit", "??"


def build_coverage_md():
    code_files = load_code_files()
    unit_contents = load_unit_contents()

    # Find coverage for each file
    file_coverage = []
    for ftype, size, nlines, path in code_files:
        basename = os.path.basename(path)
        covered_by = []
        for unit, text in unit_contents.items():
            if basename in text or path in text:
                covered_by.append(unit)
        file_coverage.append({
            "type": ftype,
            "size": size,
            "lines": nlines,
            "path": path,
            "basename": basename,
            "covered_by": covered_by,
            "covered": len(covered_by) > 0,
        })

    covered = [r for r in file_coverage if r["covered"]]
    uncovered = [r for r in file_coverage if not r["covered"]]
    total = len(file_coverage)
    coverage_pct = 100 * len(covered) // total if total else 0

    # Build per-unit stats
    # For each unit, find files where this unit is the primary unit
    unit_files = defaultdict(list)
    for r in covered:
        primary = find_primary_unit(r["path"], r["covered_by"], unit_contents)
        unit_files[primary].append(r)

    # Count files in file-list by unit (for denominator)
    # Use: a unit covers files it primarily owns
    unit_total = defaultdict(int)
    for r in file_coverage:
        if r["covered"]:
            primary = find_primary_unit(r["path"], r["covered_by"], unit_contents)
            unit_total[primary] += 1

    # Build the markdown
    lines_out = []
    lines_out.append("# Ablation Capability Audit — Coverage Matrix")
    lines_out.append("")
    lines_out.append(f"Generated: 2026-10-24  ")
    lines_out.append(f"Tool: `check_coverage.py` + `build_coverage_md.py`")
    lines_out.append("")
    lines_out.append("---")
    lines_out.append("")
    lines_out.append("## 1. Coverage Summary")
    lines_out.append("")
    lines_out.append(f"| Metric | Count |")
    lines_out.append(f"|--------|-------|")
    lines_out.append(f"| Total code files | {total} |")
    lines_out.append(f"| Covered (≥1 unit) | {len(covered)} |")
    lines_out.append(f"| Unmapped | {len(uncovered)} |")
    lines_out.append(f"| Coverage | {coverage_pct}% |")
    lines_out.append("")
    lines_out.append("**File type breakdown:**")
    lines_out.append("")
    lines_out.append("| Type | Files |")
    lines_out.append("|------|-------|")
    type_counts = defaultdict(int)
    for r in file_coverage:
        type_counts[r["type"]] += 1
    for t in sorted(type_counts):
        lines_out.append(f"| {t} | {type_counts[t]} |")
    lines_out.append("")
    lines_out.append("---")
    lines_out.append("")
    lines_out.append("## 2. Per-Unit Coverage")
    lines_out.append("")
    lines_out.append("| Unit | Title | Primary Files | Covered | % |")
    lines_out.append("|------|-------|--------------|---------|---|")

    for unit_id in [u.replace(".md", "") for u in UNIT_FILES]:
        title = UNIT_TITLES.get(unit_id, "")
        n_covered = unit_total.get(unit_id, 0)
        # Mention count from coverage_raw logic
        mention_count = sum(1 for r in file_coverage if unit_id in r["covered_by"])
        pct = "100" if n_covered > 0 else "n/a"
        lines_out.append(f"| {unit_id} | {title} | {n_covered} | {n_covered} | {pct}% |")

    lines_out.append("")
    lines_out.append("*'Primary Files' = files for which this unit is the primary documenting unit.*")
    lines_out.append("*'Covered' = those files are mentioned in the unit notes.*")
    lines_out.append("")
    lines_out.append("---")
    lines_out.append("")
    lines_out.append("## 3. Full File-to-Capability Mapping")
    lines_out.append("")
    lines_out.append("Grouped by primary unit. Status key: **covered** = full capability entry; **partial** = mentioned but no capability block extracted; **stub** = file exists but minimal content; **unmapped** = not in any unit.")
    lines_out.append("")

    # Group covered files by primary unit, emit per unit
    for unit_id in [u.replace(".md", "") for u in UNIT_FILES]:
        unit_title = UNIT_TITLES.get(unit_id, "")
        files_in_unit = [r for r in covered if find_primary_unit(r["path"], r["covered_by"], unit_contents) == unit_id]
        if not files_in_unit:
            continue
        lines_out.append(f"### {unit_id}: {unit_title}")
        lines_out.append("")
        lines_out.append("| File | Lines | Capabilities | Status |")
        lines_out.append("|------|-------|-------------|--------|")
        for r in sorted(files_in_unit, key=lambda x: x["path"]):
            # Gather capabilities from all covering units for this file
            all_caps = []
            for u in r["covered_by"]:
                caps = extract_capability_names_for_file(r["basename"], r["path"], unit_contents[u])
                all_caps.extend(caps)
            # Deduplicate
            seen = set()
            deduped_caps = []
            for c in all_caps:
                if c not in seen:
                    seen.add(c)
                    deduped_caps.append(c)
            caps_str = "; ".join(deduped_caps[:5]) if deduped_caps else "—"

            # Determine status
            status = get_file_status(r["path"], r["covered_by"], unit_contents)
            # Mark also_in if covered by multiple units
            extra_units = [u for u in r["covered_by"] if u != unit_id]
            also_str = f" *(also: {', '.join(extra_units)})*" if extra_units else ""

            # Shorten path for display
            display_path = r["path"]
            lines_out.append(f"| `{display_path}` | {r['lines']} | {caps_str}{also_str} | {status} |")
        lines_out.append("")

    lines_out.append("---")
    lines_out.append("")
    lines_out.append("## 4. Unmapped Files")
    lines_out.append("")
    if not uncovered:
        lines_out.append("All code files are mapped.")
    else:
        lines_out.append(f"{len(uncovered)} file(s) not mentioned in any unit notes:")
        lines_out.append("")
        lines_out.append("| File | Lines | Classification | Suggested Unit |")
        lines_out.append("|------|-------|---------------|----------------|")
        for r in sorted(uncovered, key=lambda x: x["path"]):
            reason, suggested = classify_uncovered(r["path"], r["lines"], r["type"])
            lines_out.append(f"| `{r['path']}` | {r['lines']} | {reason} | {suggested} |")
        lines_out.append("")
        lines_out.append("### Notes on unmapped files")
        lines_out.append("")
        for r in sorted(uncovered, key=lambda x: x["path"]):
            reason, suggested = classify_uncovered(r["path"], r["lines"], r["type"])
            lines_out.append(f"**`{r['path']}`** ({r['lines']} lines, {r['type']})")
            lines_out.append(f": {reason}. Suggested unit: {suggested}.")
            lines_out.append("")

    lines_out.append("---")
    lines_out.append("")
    lines_out.append("## 5. Coverage by File Type")
    lines_out.append("")
    lines_out.append("| Type | Total | Covered | % |")
    lines_out.append("|------|-------|---------|---|")
    type_covered = defaultdict(int)
    for r in covered:
        type_covered[r["type"]] += 1
    for t in sorted(type_counts):
        tc = type_covered.get(t, 0)
        tt = type_counts[t]
        pct = f"{100*tc//tt}%" if tt else "n/a"
        lines_out.append(f"| {t} | {tt} | {tc} | {pct} |")
    lines_out.append("")

    result = '\n'.join(lines_out)
    OUTPUT.write_text(result)
    print(f"Written: {OUTPUT}")
    print(f"Total: {total} code files, {len(covered)} covered ({coverage_pct}%), {len(uncovered)} unmapped")
    return total, len(covered), uncovered


if __name__ == "__main__":
    build_coverage_md()
