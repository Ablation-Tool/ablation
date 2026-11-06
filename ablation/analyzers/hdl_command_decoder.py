"""
hdl_command_decoder.py — HDL command-decoder extraction and guard analysis.

Finds case-statement command dispatch in VHDL (.vhd) and Verilog (.v) sources,
resolves each arm's constant to its encoded value, records the signal effects
of each arm, and reports whether the dispatch is gated by anything beyond a
clock/reset/strobe condition.

Designed for hardware RE questions such as:
  - which bus-visible command values exist in this FPGA firmware?
  - what does each command do at the signal level?
  - is there any authorization, mode, or state check on the dispatch, or does
    a bare command strobe reach the effects directly?

This is a regex/structural sweep, not an AST or elaboration. It covers the
dominant command-decoder idiom (constant declarations plus a single case on a
command signal inside a clocked process) and reports its own limits: nested
case statements, generate loops, and dispatch through subprograms are not
followed.

Usage:
    dec = HDLCommandDecoder.from_directory('analysis/alice-optin/')
    for report in dec.reports:
        print(report.file, report.selector, report.unguarded)
        for cmd in report.commands:
            print(f"  {cmd.value} {cmd.name}: {cmd.effects_text()}")
    print(dec.summary())
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Constants ─────────────────────────────────────────────────────────────────

# constant NAME : std_logic_vector (31 downto 0) := X"FF000000";
# Also accepts plain std_logic, unsigned, bit_vector, and B"..." literals.
_VH_CONST_RE = re.compile(
    r"constant\s+(\w+)\s*:\s*[\w\s]+?\(.*?\)\s*:=\s*([XB])\"([0-9A-Fa-f_]+)\"",
    re.IGNORECASE,
)
_VH_CONST_SCALAR_RE = re.compile(
    r"constant\s+(\w+)\s*:\s*\w+\s*:=\s*([XB])\"([0-9A-Fa-f_]+)\"",
    re.IGNORECASE,
)
# parameter/localparam NAME = 8'hA0;  or  = 32'hFF000000;
_VL_PARAM_RE = re.compile(
    r"(?:localparam|parameter)\s+(?:\[[^\]]+\]\s+)?(\w+)\s*=\s*(\d+)?\s*'\s*([hHbBdD])([0-9A-Fa-f_xXzZ]+)"
)

# Terms that, when present in a guard expression, mean the dispatch is gated
# by something other than a bare enable/strobe.
_STROBE_TOKENS = {
    "en", "enable", "strobe", "valid", "req", "request", "we", "write_en",
    "clk", "clock", "reset", "reset_n", "rst", "rst_n", "rst_i",
}
_AUTH_TERMS = ("password", "passwd", "auth", "unlock", "allowlist", "whitelist",
               "privilege", "permission", "secure", "key", "token", "credential")


def _signal_base(name: str) -> str:
    """Reduce a guard signal reference to its comparable base name."""
    name = name.strip().lower()
    name = re.sub(r"\(.*?\)", "", name)  # bit selects / slices
    return name.strip()


def _is_strobe_only(guard: str) -> bool:
    """True when every signal referenced in the guard is a strobe/clock/reset."""
    refs = re.findall(r"[A-Za-z_]\w*", guard)
    for ref in refs:
        base = _signal_base(ref)
        if base in {"if", "then", "and", "or", "not", "xor", "nand", "nor", "event"}:
            continue
        if base in _STROBE_TOKENS:
            continue
        # command_en, optin_command_en, processing_command_en, write_strobe ...
        if any(base.endswith("_" + tok) or base.endswith(tok) and tok in {"en", "strobe"} for tok in _STROBE_TOKENS):
            continue
        return False
    return True


@dataclass
class CommandEffect:
    signal: str
    value: str
    line: int

    def __str__(self) -> str:
        return f"{self.signal} <= {self.value}"


@dataclass
class Command:
    name: str
    value: str
    effects: List[CommandEffect] = field(default_factory=list)
    line: int = 0

    def effects_text(self) -> str:
        return "; ".join(str(e) for e in self.effects)


@dataclass
class DecoderReport:
    file: str
    selector: str
    line: int
    guards: List[str] = field(default_factory=list)
    commands: List[Command] = field(default_factory=list)
    unguarded: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "file": self.file,
            "selector": self.selector,
            "line": self.line,
            "guards": self.guards,
            "unguarded": self.unguarded,
            "commands": [
                {
                    "name": c.name,
                    "value": c.value,
                    "line": c.line,
                    "effects": [str(e) for e in c.effects],
                }
                for c in self.commands
            ],
            "notes": self.notes,
        }


def _strip_comments(text: str, lang: str) -> str:
    if lang == "vhdl":
        return re.sub(r"--[^\n]*", "", text)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


class HDLCommandDecoder:
    """Extract command decoders from HDL sources."""

    def __init__(self) -> None:
        self.reports: List[DecoderReport] = []

    # ── Entry points ──────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str) -> "HDLCommandDecoder":
        dec = cls()
        dec.add_file(path)
        return dec

    @classmethod
    def from_directory(cls, path: str) -> "HDLCommandDecoder":
        dec = cls()
        root = Path(path)
        for pattern in ("*.vhd", "*.vhdl", "*.v"):
            for source in sorted(root.rglob(pattern)):
                dec.add_file(str(source))
        return dec

    def add_file(self, path: str) -> None:
        text = Path(path).read_text(encoding="iso-8859-1")
        if path.lower().endswith((".vhd", ".vhdl")):
            self.reports.extend(_scan_vhdl(text, str(path)))
        elif path.lower().endswith(".v"):
            self.reports.extend(_scan_verilog(text, str(path)))

    # ── Reporting ─────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict:
        return {
            "decoders": [r.to_dict() for r in self.reports],
            "total_commands": sum(len(r.commands) for r in self.reports),
            "unguarded_decoders": sum(1 for r in self.reports if r.unguarded),
        }

    def summary(self) -> str:
        lines = []
        for r in self.reports:
            state = "UNGUARDED (strobe-only dispatch)" if r.unguarded else "guarded"
            lines.append(f"{r.file}:{r.line} case {r.selector} — {state}")
            for g in r.guards:
                lines.append(f"  guard: {g}")
            for c in r.commands:
                lines.append(f"  {c.value} {c.name}: {c.effects_text()}")
            for n in r.notes:
                lines.append(f"  note: {n}")
        if not lines:
            return "no command decoders found"
        return "\n".join(lines)


# ── VHDL ──────────────────────────────────────────────────────────────────────

_VH_CASE_RE = re.compile(r"case\s*\(?\s*([\w() ]+?)\s*\)?\s+is\b", re.IGNORECASE)
_VH_WHEN_RE = re.compile(r"when\s+([\w\"'.]+)\s*=>", re.IGNORECASE)
_VH_ASSIGN_RE = re.compile(r"(\w+(?:\([^)]*\))?)\s*<=\s*([^;]+);", re.IGNORECASE)
_VH_IF_RE = re.compile(r"\bif\s*\(?([^;]+?)\)?\s+then\b", re.IGNORECASE)


def _vhdl_constants(text: str) -> Dict[str, str]:
    consts: Dict[str, str] = {}
    for match in list(_VH_CONST_RE.finditer(text)) + list(_VH_CONST_SCALAR_RE.finditer(text)):
        name, base, digits = match.group(1), match.group(2).upper(), match.group(3).replace("_", "")
        consts[name] = _format_value(base, digits)
    return consts


def _format_value(base: str, digits: str) -> str:
    if base == "X":
        return "0x" + digits.upper()
    if base == "B":
        return "0b" + digits
    return digits


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _clean_effect_value(value: str) -> str:
    value = re.sub(r"\bafter\s+\w+(\s+\w+)?", "", value, flags=re.IGNORECASE)
    return " ".join(value.split())


_VH_IF_TOKEN_RE = re.compile(r"\bend\s+if\s*;|\bif\b", re.IGNORECASE)


def _vhdl_enclosing_ifs(text: str, pos: int) -> List[str]:
    """Return the if-conditions whose bodies enclose offset `pos`."""
    stack: List[str] = []
    for token in _VH_IF_TOKEN_RE.finditer(text, 0, pos):
        if token.group(0).lower().startswith("end"):
            if stack:
                stack.pop()
            continue
        condition = re.match(r"\s*\(?([^;]+?)\)?\s+then\b", text[token.end():], re.IGNORECASE)
        if not condition:
            continue  # not a plain if-then (e.g. 'end if' handled above)
        stack.append(" ".join(condition.group(1).split()))
    return [g for g in stack if "event" not in g.lower()]


def _scan_vhdl(text: str, filename: str) -> List[DecoderReport]:
    clean = _strip_comments(text, "vhdl")
    consts = _vhdl_constants(clean)
    reports: List[DecoderReport] = []
    for case_match in _VH_CASE_RE.finditer(clean):
        selector = " ".join(case_match.group(1).split())
        end = re.search(r"end\s+case\s*;", clean[case_match.end():], re.IGNORECASE)
        if not end:
            continue
        body = clean[case_match.end():case_match.end() + end.start()]
        whens = list(_VH_WHEN_RE.finditer(body))
        if not whens:
            continue
        report = DecoderReport(file=filename, selector=selector,
                               line=_line_of(clean, case_match.start()))
        for index, when in enumerate(whens):
            name = when.group(1)
            arm_end = whens[index + 1].start() if index + 1 < len(whens) else len(body)
            arm = body[when.end():arm_end]
            if name.lower() == "others":
                continue
            value = consts.get(name)
            if value is None:
                literal = re.fullmatch(r"([XB])\"([0-9A-Fa-f_]+)\"", name, re.IGNORECASE)
                if literal:
                    value = _format_value(literal.group(1).upper(), literal.group(2))
                else:
                    value = name  # enum state or unresolved symbol
            command = Command(name=name, value=value,
                              line=_line_of(clean, case_match.end() + when.start()))
            for assign in _VH_ASSIGN_RE.finditer(arm):
                signal = assign.group(1)
                if signal.lower().startswith(("assert", "report")):
                    continue
                command.effects.append(CommandEffect(
                    signal=signal,
                    value=_clean_effect_value(assign.group(2)),
                    line=_line_of(clean, case_match.end() + when.end() + assign.start()),
                ))
            report.commands.append(command)
        # Guards: only if-conditions whose body actually encloses the case.
        # A token scan tracks if/end-if nesting so sibling statements (e.g. an
        # unrelated automatic-reset if before the dispatch) are not mistaken
        # for guards.
        report.guards.extend(_vhdl_enclosing_ifs(clean, case_match.start()))
        if not report.guards:
            report.guards.append("(no enclosing if; case is unconditional in process)")
        dispatch_guards = [
            g for g in report.guards
            if not re.match(r"^\s*(reset|reset_n|rst|rst_n|rst_i)\s*=", g, re.IGNORECASE)
        ]
        report.unguarded = all(_is_strobe_only(g) for g in dispatch_guards)
        for term in _AUTH_TERMS:
            if term in clean.lower():
                report.notes.append(f"file contains auth-related term '{term}'; review manually")
                break
        if report.commands:
            if "state" in selector.lower():
                report.notes.append("selector looks like an FSM state register, not a bus command")
            reports.append(report)
    return reports


# ── Verilog ───────────────────────────────────────────────────────────────────

_VL_CASE_RE = re.compile(r"\bcasex?\s*\(\s*([\w()\[\]: ]+?)\s*\)", re.IGNORECASE)
_VL_ITEM_RE = re.compile(r"([\w'\"\[\]:]+)\s*:\s*(?:begin)?", re.IGNORECASE)
_VL_ASSIGN_RE = re.compile(r"(\w+(?:\[[^\]]*\])?)\s*(?:<=|(?<![<>=!])=(?!=))\s*([^;]+);")


def _scan_verilog(text: str, filename: str) -> List[DecoderReport]:
    clean = _strip_comments(text, "verilog")
    consts: Dict[str, str] = {}
    for match in _VL_PARAM_RE.finditer(clean):
        name, _width, base, digits = match.groups()
        prefix = {"h": "0x", "b": "0b", "d": ""}[base.lower()]
        consts[name] = prefix + digits.upper()
    reports: List[DecoderReport] = []
    for case_match in _VL_CASE_RE.finditer(clean):
        selector = " ".join(case_match.group(1).split())
        end = re.search(r"\bendcase\b", clean[case_match.end():], re.IGNORECASE)
        if not end:
            continue
        body = clean[case_match.end():case_match.end() + end.start()]
        items = list(_VL_ITEM_RE.finditer(body))
        if not items:
            continue
        report = DecoderReport(file=filename, selector=selector,
                               line=_line_of(clean, case_match.start()))
        for index, item in enumerate(items):
            name = item.group(1)
            if name.lower() in {"default", "begin", "end"}:
                continue
            item_end = items[index + 1].start() if index + 1 < len(items) else len(body)
            arm = body[item.end():item_end]
            value = consts.get(name, name)
            command = Command(name=name, value=value,
                              line=_line_of(clean, case_match.end() + item.start()))
            for assign in _VL_ASSIGN_RE.finditer(arm):
                command.effects.append(CommandEffect(
                    signal=assign.group(1),
                    value=" ".join(assign.group(2).split()),
                    line=_line_of(clean, case_match.end() + item.end() + assign.start()),
                ))
            report.commands.append(command)
        always = None
        for always_match in re.finditer(r"\balways\b", clean[:case_match.start()], re.IGNORECASE):
            always = always_match
        guard_region = clean[always.end():case_match.start()] if always else clean[:case_match.start()]
        for if_match in re.finditer(r"\bif\s*\(([^)]+)\)", guard_region, re.IGNORECASE):
            report.guards.append(" ".join(if_match.group(1).split()))
        if not report.guards:
            report.guards.append("(no enclosing if; case is unconditional in always block)")
        report.unguarded = all(_is_strobe_only(g) for g in report.guards)
        if report.commands:
            reports.append(report)
    return reports
