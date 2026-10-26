"""
verilog_semantic.py — Verilog and VHDL source semantic analyzer.

Regex-based semantic sweep over Verilog (.v) and VHDL (.vhd) source trees.
Extracts module/entity names, constants, FSM state encodings, port widths,
and pattern-searchable signal assignments. Does not build a full AST.

Designed for hardware RE where the goal is:
  - mapping protocol constants (opcodes, register addresses, frame lengths)
  - extracting FSM state tables for comparison against binary analysis
  - querying for signal names related to a vulnerability class
  - confirming hardware-level encodings against captured bitstreams

Supports:
  Verilog:  module NAME, parameter NAME = VALUE, assign NAME = N'bVALUE,
            casex (STATE) + state encodings, always @
  VHDL:     entity NAME is, constant NAME : type := VALUE, signal NAME : type,
            type ENUM is (state1, state2, ...), process / case

Usage:
    vs = VerilogSemantic.from_directory('/tmp/abcn_rtl/rtl_final/')
    print(vs.summary())
    for hit in vs.query("command opcode broadcast"):
        print(hit['file'], hit['line'], hit['context'])

    consts = vs.constants()
    print(consts.get('BROADCASTID'))  # {'value': '"111111"', 'file': ..., 'line': ...}

    states = vs.state_encodings()
    for name, enc in states.items():
        print(f"  {name}: {enc}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Regexes — Verilog ─────────────────────────────────────────────────────────

# module NAME (  — captures the module name
_VL_MODULE_RE = re.compile(
    r'^\s*module\s+(\w+)\s*[#(;]', re.MULTILINE
)

# parameter [N:0] NAME = VALUE  or  parameter NAME = VALUE
# Handles optional bit-width annotation before the name
_VL_PARAM_RE = re.compile(
    r'^\s*parameter\s+(?:\[\s*\d+\s*:\s*\d+\s*\]\s+)?(\w+)\s*=\s*([^;,\n]+)',
    re.MULTILINE
)

# assign NAME = N'bVALUE  or  assign NAME = N'hVALUE
_VL_ASSIGN_RE = re.compile(
    r'^\s*assign\s+(\w+)\s*=\s*(\{[^;]+\}|[0-9]*\'[bBoOhH][0-9a-fA-F_xXzZ]+[^;]*)',
    re.MULTILINE
)

# casex (SIGNAL) or case (SIGNAL)
_VL_CASE_RE = re.compile(
    r'^\s*casex?\s*\(\s*(\w+)\s*\)', re.MULTILINE
)

# port width: input/output/inout [N:0] NAME  — capture width and name
_VL_PORT_RE = re.compile(
    r'^\s*(?:input|output|inout)\s+(?:wire|reg)?\s*(?:\[\s*(\d+)\s*:\s*(\d+)\s*\])?\s+(\w+)',
    re.MULTILINE
)

# `define NAME VALUE
_VL_DEFINE_RE = re.compile(
    r'^`define\s+(\w+)\s+(.+)', re.MULTILINE
)


# ── Regexes — VHDL ────────────────────────────────────────────────────────────

# entity NAME is
_VH_ENTITY_RE = re.compile(
    r'^\s*entity\s+(\w+)\s+is\b', re.MULTILINE | re.IGNORECASE
)

# constant NAME : TYPE := VALUE;
_VH_CONST_RE = re.compile(
    r'^\s*constant\s+(\w+)\s*:\s*[^:=]+:=\s*([^;]+)',
    re.MULTILINE | re.IGNORECASE
)

# signal NAME : TYPE;  (captures name and type for port width inference)
_VH_SIGNAL_RE = re.compile(
    r'^\s*signal\s+(\w+)\s*:\s*([^;:=]+)',
    re.MULTILINE | re.IGNORECASE
)

# type ENUM is (state1, state2, ...)  — FSM enumerated type
_VH_ENUM_RE = re.compile(
    r'^\s*type\s+(\w+)\s+is\s*\(([^)]+)\)',
    re.MULTILINE | re.IGNORECASE
)

# std_logic_vector width: bit_vector(N downto 0) or std_logic_vector(N downto 0)
_VH_WIDTH_RE = re.compile(
    r'(?:std_logic_vector|bit_vector|unsigned|signed)\s*\(\s*(\d+)\s+downto\s+\d+\s*\)',
    re.IGNORECASE
)


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class _SourceEntry:
    """A single extracted semantic item from a source file."""
    kind: str       # "module", "entity", "constant", "define", "state", "assign", "port"
    name: str
    value: str      # raw value string or comma-separated state list
    file: str
    line: int


@dataclass
class QueryHit:
    """One result from VerilogSemantic.query()."""
    file: str
    line: int
    module: str     # enclosing module/entity name, or ''
    signal: str     # signal/constant name
    context: str    # raw source line text


# ── Main class ────────────────────────────────────────────────────────────────

class VerilogSemantic:
    """
    Semantic analyzer for Verilog/VHDL source directories.

    Regex-based: no full grammar parser. Optimised for hardware RE where the
    goal is recovering protocol constants and FSM encodings, not synthesis.
    """

    def __init__(self, entries: List[_SourceEntry], src_dir: str) -> None:
        self._entries = entries
        self._src_dir = src_dir
        # Build keyword index over all raw line text for fast query()
        self._lines: List[Tuple[str, int, str]] = []  # (file, lineno, text)
        # Map file -> list of (module_name, start_line) for context lookup
        self._module_ranges: Dict[str, List[Tuple[str, int]]] = {}

    @classmethod
    def from_directory(cls, src_dir: str,
                       extensions: Optional[List[str]] = None) -> "VerilogSemantic":
        """Parse all .v and .vhd files under *src_dir* and return an analyzer."""
        if extensions is None:
            extensions = [".v", ".vhd", ".vhdl"]
        root = Path(src_dir)
        entries: List[_SourceEntry] = []
        lines_index: List[Tuple[str, int, str]] = []
        module_ranges: Dict[str, List[Tuple[str, int]]] = {}

        for ext in extensions:
            for fp in sorted(root.rglob(f"*{ext}")):
                try:
                    text = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                fname = str(fp)
                file_lines = text.splitlines()
                # Index all lines for query()
                for lineno, line in enumerate(file_lines, 1):
                    lines_index.append((fname, lineno, line))

                # Extract semantic entries based on file type
                if ext in (".v",):
                    _extract_verilog(text, fname, entries, module_ranges)
                else:
                    _extract_vhdl(text, fname, entries)

        obj = cls(entries, src_dir)
        obj._lines = lines_index
        obj._module_ranges = module_ranges
        return obj

    def summary(self) -> str:
        """Return a one-block summary of what was parsed."""
        mods = sum(1 for e in self._entries if e.kind in ("module", "entity"))
        consts = sum(1 for e in self._entries if e.kind in ("constant", "define"))
        states = sum(1 for e in self._entries if e.kind == "state")
        ports = sum(1 for e in self._entries if e.kind == "port")
        assigns = sum(1 for e in self._entries if e.kind == "assign")
        total_lines = len(self._lines)
        return (
            f"VerilogSemantic: {self._src_dir}\n"
            f"  modules/entities : {mods}\n"
            f"  constants/defines: {consts}\n"
            f"  FSM states       : {states}\n"
            f"  port declarations: {ports}\n"
            f"  assign constants : {assigns}\n"
            f"  total lines      : {total_lines:,}"
        )

    def query(self, pattern: str, vuln_class: str = "") -> List[QueryHit]:
        """
        Search all source lines for *pattern* (space-separated keywords,
        all must be present, case-insensitive). Returns QueryHit list.

        *vuln_class* is accepted for interface compatibility with SemanticSearcher
        but is not used in the regex approach.
        """
        keywords = [k.lower() for k in pattern.split() if k]
        if not keywords:
            return []
        results: List[QueryHit] = []
        for fname, lineno, line in self._lines:
            ll = line.lower()
            if all(k in ll for k in keywords):
                module = self._enclosing_module(fname, lineno)
                # Extract the signal/constant name if present
                m = re.search(r'\b(\w{3,})\b', line.strip())
                signal = m.group(1) if m else ""
                results.append(QueryHit(
                    file=fname, line=lineno,
                    module=module, signal=signal,
                    context=line.rstrip(),
                ))
        return results

    def modules(self) -> List[str]:
        """Return all module and entity names found."""
        return [e.name for e in self._entries if e.kind in ("module", "entity")]

    def constants(self) -> Dict[str, Dict]:
        """
        Return all named constants (Verilog parameter/`define, VHDL constant).
        Maps name -> {'value': str, 'file': str, 'line': int}.
        """
        result: Dict[str, Dict] = {}
        for e in self._entries:
            if e.kind in ("constant", "define"):
                result[e.name] = {
                    "value": e.value.strip(),
                    "file": e.file,
                    "line": e.line,
                }
        return result

    def state_encodings(self) -> Dict[str, Dict]:
        """
        Return FSM state names and their encodings.
        Maps state_name -> {'encoding': str, 'source': str, 'file': str, 'line': int}.
        For VHDL enumerated types the encoding is the enum index as a string.
        For Verilog one-hot parameters the encoding is the parameter value.
        """
        result: Dict[str, Dict] = {}
        # Explicit one-hot/binary state parameters (Verilog)
        for e in self._entries:
            if e.kind == "constant" and re.match(r"[A-Z_]+[0-9]*$", e.name):
                # Heuristic: ALL_CAPS parameters that look like state names
                v = e.value.strip()
                if re.match(r"\d+\'[bh][01a-fA-F_xX]+", v):
                    result[e.name] = {
                        "encoding": v,
                        "source": "verilog_parameter",
                        "file": e.file,
                        "line": e.line,
                    }
        # VHDL enum types (state machine type declarations)
        for e in self._entries:
            if e.kind == "state":
                for i, sname in enumerate(e.value.split(",")):
                    sname = sname.strip().strip('"')
                    if sname:
                        result[sname] = {
                            "encoding": str(i),
                            "source": f"vhdl_enum:{e.name}",
                            "file": e.file,
                            "line": e.line,
                        }
        return result

    def port_widths(self) -> Dict[str, int]:
        """
        Return signal/port names with their bit widths (number of bits).
        Maps signal_name -> bit_width.
        """
        result: Dict[str, int] = {}
        for e in self._entries:
            if e.kind == "port" and e.value:
                try:
                    result[e.name] = int(e.value)
                except (ValueError, TypeError):
                    pass
        return result

    def _enclosing_module(self, fname: str, lineno: int) -> str:
        """Return the module/entity name that encloses (fname, lineno), or ''."""
        ranges = self._module_ranges.get(fname, [])
        best = ""
        for mname, mline in ranges:
            if mline <= lineno:
                best = mname
            else:
                break
        return best


# ── Verilog extractor ─────────────────────────────────────────────────────────

def _extract_verilog(text: str, fname: str,
                     entries: List[_SourceEntry],
                     module_ranges: Dict[str, List[Tuple[str, int]]]) -> None:
    lines = text.splitlines()
    line_of: Dict[int, int] = {}  # character offset -> line number
    offset = 0
    for i, ln in enumerate(lines, 1):
        line_of[offset] = i
        offset += len(ln) + 1

    def _lineno(match_obj: re.Match) -> int:
        pos = match_obj.start()
        # Find the last offset entry <= pos
        best = 1
        for off, lno in sorted(line_of.items()):
            if off <= pos:
                best = lno
        return best

    # Modules
    mr: List[Tuple[str, int]] = []
    for m in _VL_MODULE_RE.finditer(text):
        lno = _lineno(m)
        entries.append(_SourceEntry("module", m.group(1), "", fname, lno))
        mr.append((m.group(1), lno))
    if mr:
        module_ranges[fname] = sorted(mr, key=lambda x: x[1])

    # Parameters
    for m in _VL_PARAM_RE.finditer(text):
        lno = _lineno(m)
        val = m.group(2).strip().rstrip(",").rstrip(";")
        # Skip commented-out lines
        line_text = lines[lno - 1] if lno <= len(lines) else ""
        stripped = line_text.lstrip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        entries.append(_SourceEntry("constant", m.group(1), val, fname, lno))

    # `define macros
    for m in _VL_DEFINE_RE.finditer(text):
        lno = _lineno(m)
        entries.append(_SourceEntry("define", m.group(1), m.group(2).strip(), fname, lno))

    # Assign constants
    for m in _VL_ASSIGN_RE.finditer(text):
        lno = _lineno(m)
        entries.append(_SourceEntry("assign", m.group(1), m.group(2).strip(), fname, lno))

    # Port declarations
    for m in _VL_PORT_RE.finditer(text):
        lno = _lineno(m)
        hi = m.group(1)
        lo = m.group(2)
        name = m.group(3)
        if hi is not None and lo is not None:
            width = abs(int(hi) - int(lo)) + 1
        else:
            width = 1
        entries.append(_SourceEntry("port", name, str(width), fname, lno))


# ── VHDL extractor ────────────────────────────────────────────────────────────

def _extract_vhdl(text: str, fname: str, entries: List[_SourceEntry]) -> None:
    lines = text.splitlines()

    def _lineno_for_pos(pos: int) -> int:
        return text[:pos].count("\n") + 1

    # Entities
    for m in _VH_ENTITY_RE.finditer(text):
        entries.append(_SourceEntry("entity", m.group(1), "", fname, _lineno_for_pos(m.start())))

    # Constants
    for m in _VH_CONST_RE.finditer(text):
        val = m.group(2).strip().rstrip(";")
        entries.append(_SourceEntry("constant", m.group(1), val, fname, _lineno_for_pos(m.start())))

    # Signals with width
    for m in _VH_SIGNAL_RE.finditer(text):
        type_str = m.group(2).strip()
        wm = _VH_WIDTH_RE.search(type_str)
        if wm:
            width = int(wm.group(1)) + 1
            entries.append(_SourceEntry("port", m.group(1), str(width), fname, _lineno_for_pos(m.start())))

    # Enumerated type (FSM states)
    for m in _VH_ENUM_RE.finditer(text):
        entries.append(_SourceEntry("state", m.group(1), m.group(2), fname, _lineno_for_pos(m.start())))


# ── CLI ───────────────────────────────────────────────────────────────────────

def _main() -> None:
    import sys
    if len(sys.argv) < 2:
        print("Usage: verilog_semantic.py <directory> [query terms...]")
        sys.exit(1)
    src_dir = sys.argv[1]
    query = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else ""
    vs = VerilogSemantic.from_directory(src_dir)
    print(vs.summary())
    if query:
        print(f"\nQuery: {query!r}")
        hits = vs.query(query)
        print(f"{len(hits)} hits")
        for h in hits[:20]:
            print(f"  {h.file}:{h.line}  [{h.module}]  {h.context.strip()[:80]}")
    else:
        print("\nConstants (first 20):")
        for name, info in list(vs.constants().items())[:20]:
            print(f"  {name} = {info['value']!r}  ({Path(info['file']).name}:{info['line']})")
        print("\nFSM states (first 20):")
        for name, info in list(vs.state_encodings().items())[:20]:
            print(f"  {name} = {info['encoding']}  ({info['source']})")


if __name__ == "__main__":
    _main()
