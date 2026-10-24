#!/usr/bin/env python3
"""
Coverage check: maps every code file in file-list.txt to the unit notes that mention it.
"""

import os
import re
import sys
from pathlib import Path

NOTES_DIR = Path(__file__).parent
FILE_LIST = NOTES_DIR / "file-list.txt"

CODE_TYPES = {"code-ablation", "code-modules", "code-sweep", "code-other", "code"}

UNIT_FILES = [
    "A01.md", "A02.md", "A03.md", "A04.md", "A05.md",
    "A06.md", "A07.md", "A08.md", "A09.md", "A10.md",
    "A11.md", "A12.md", "A13.md", "A14.md",
    "C01.md",
    "M01.md", "M02.md", "M03.md", "M04.md",
    "S01.md",
]

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
        if fpath.exists():
            units[fname.replace(".md", "")] = fpath.read_text()
        else:
            units[fname.replace(".md", "")] = ""
    return units

def find_coverage(code_files, unit_contents):
    """For each code file, find which units mention it by basename."""
    results = []
    for ftype, size, nlines, path in code_files:
        basename = os.path.basename(path)
        # Also try the path itself (some notes use relative paths)
        covered_by = []
        for unit, text in unit_contents.items():
            # Match basename as a word boundary match to avoid partial hits
            if basename in text or path in text:
                covered_by.append(unit)
        results.append({
            "type": ftype,
            "size": size,
            "lines": nlines,
            "path": path,
            "basename": basename,
            "covered_by": covered_by,
            "covered": len(covered_by) > 0,
        })
    return results

def infer_unit_from_path(path):
    """Best-guess unit assignment from path alone (for unmapped files)."""
    if path.startswith("sweeps/"):
        return "S01"
    if path.startswith("ablation/modules/"):
        return "M??"
    if path.startswith("ablation/analyzers/") or path.startswith("ablation/"):
        return "A??"
    return "??"

def main():
    code_files = load_code_files()
    unit_contents = load_unit_contents()
    results = find_coverage(code_files, unit_contents)

    total = len(results)
    covered = [r for r in results if r["covered"]]
    uncovered = [r for r in results if not r["covered"]]

    print(f"=== COVERAGE SUMMARY ===")
    print(f"Total code files: {total}")
    print(f"Covered (mentioned in ≥1 unit): {len(covered)} ({100*len(covered)//total}%)")
    print(f"Uncovered: {len(uncovered)} ({100*len(uncovered)//total}%)")
    print()

    # Per-unit coverage: count which files each unit covers
    unit_file_counts = {u: 0 for u in unit_contents}
    for r in results:
        for u in r["covered_by"]:
            unit_file_counts[u] += 1

    print("=== PER-UNIT FILE MENTIONS ===")
    for unit in sorted(unit_contents.keys()):
        print(f"  {unit}: {unit_file_counts[unit]} file(s) mentioned")
    print()

    # Covered file details
    print("=== COVERED FILES ===")
    for r in sorted(covered, key=lambda x: x["path"]):
        units_str = ", ".join(r["covered_by"])
        print(f"  {r['path']} | {r['type']} | {r['lines']} lines | units: {units_str}")
    print()

    # Uncovered file details
    print("=== UNCOVERED FILES ===")
    for r in sorted(uncovered, key=lambda x: x["path"]):
        suggested = infer_unit_from_path(r["path"])
        print(f"  {r['path']} | {r['type']} | {r['lines']} lines | suggested: {suggested}")

if __name__ == "__main__":
    main()
