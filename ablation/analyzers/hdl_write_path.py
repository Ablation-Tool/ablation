"""
hdl_write_path.py — VHDL register write-path dataflow tracer.

Answers the question left open by HDLCommandDecoder: a command decoder is
unguarded at the case statement, but how does a bus write actually reach it?
This module builds a signal dependency graph from VHDL sources and traces a
target signal (command register, command strobe) back to the primary input
ports that drive it, carrying every enclosing condition along the way.

Covered constructs (the ALICE Pixel Trigger register-file idiom):
  - concurrent assignments, including when/else conditional forms
  - sequential assignments inside processes, with enclosing if/case conditions
  - alias declarations (bit slices exposed under a second name)
  - component/entity instantiations and their port maps, so traces cross from
    a decoder input port through the top level into the register entity and
    out to the bus-side ports
  - address-decode comparisons resolved through constant declarations

Not covered (reported as notes, never guessed): subprogram calls, generate
loops, record-typed ports, resolution functions, and Verilog sources. The
graph is structural; it shows which inputs *can* drive a signal and under
which textual conditions, not a timed simulation.

Usage:
    tracer = HDLWritePath.from_directory('analysis/alice-optin/')
    report = tracer.trace('optin_registers.optin_command_en')
    print(report.summary())
    # or straight from a HDLCommandDecoder report:
    reports = tracer.trace_decoder('optin_command_decoder',
                                   selector='optin_command',
                                   strobe='optin_command_en')
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass
class Hop:
    """One step backwards through the dependency graph."""
    entity: str
    signal: str
    via: str            # 'assignment' | 'alias' | 'portmap' | 'start'
    expression: str = ""
    conditions: List[str] = field(default_factory=list)
    file: str = ""
    line: int = 0

    def scoped(self) -> str:
        return f"{self.entity}.{self.signal}"


@dataclass
class WritePathReport:
    target: str
    paths: List[List[Hop]] = field(default_factory=list)
    primary_inputs: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)
    address_constants: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"write path: {self.target}"]
        for index, path in enumerate(self.paths, 1):
            lines.append(f"  path {index}:")
            for hop in path:
                cond = f"  when {', '.join(hop.conditions)}" if hop.conditions else ""
                lines.append(f"    {hop.scoped()}  [{hop.via} {hop.expression}]{cond}")
        if self.primary_inputs:
            lines.append("  primary inputs: " + ", ".join(sorted(set(self.primary_inputs))))
        if self.address_constants:
            for name, value in sorted(self.address_constants.items()):
                lines.append(f"  address constant: {name} = {value}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "primary_inputs": sorted(set(self.primary_inputs)),
            "conditions": self.conditions,
            "address_constants": self.address_constants,
            "paths": [
                [
                    {
                        "entity": h.entity, "signal": h.signal, "via": h.via,
                        "expression": h.expression, "conditions": h.conditions,
                        "file": h.file, "line": h.line,
                    }
                    for h in path
                ]
                for path in self.paths
            ],
            "notes": self.notes,
        }


@dataclass
class _Assignment:
    target: str
    expression: str
    conditions: List[str]
    file: str
    line: int
    kind: str = "assignment"


@dataclass
class _Entity:
    name: str
    file: str
    ports: Dict[str, str] = field(default_factory=dict)       # port -> direction
    assignments: List[_Assignment] = field(default_factory=list)
    aliases: Dict[str, str] = field(default_factory=dict)     # alias -> source expr
    constants: Dict[str, str] = field(default_factory=dict)
    instances: Dict[str, str] = field(default_factory=dict)   # instance label -> entity
    portmaps: List[Tuple[str, str, str, str]] = field(default_factory=list)
    # (instance label, child entity, formal, actual)


# ── Parsing helpers ───────────────────────────────────────────────────────────

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_VHDL_KEYWORDS = {
    "entity", "architecture", "is", "begin", "end", "process", "port", "generic",
    "signal", "constant", "variable", "alias", "component", "type", "subtype",
    "if", "then", "elsif", "else", "case", "when", "others", "loop", "for",
    "in", "out", "inout", "of", "and", "or", "not", "nand", "nor", "xor",
    "map", "assert", "report", "severity", "after", "wait", "until", "to",
    "downto", "std_logic", "std_logic_vector", "unsigned", "signed", "integer",
    "boolean", "time", "ns", "us", "ms", "true", "false", "open", "event",
    "block", "library", "use", "all", "work", "rising_edge", "falling_edge",
    "conv_integer", "to_integer", "resize", "generate", "while", "return",
    "procedure", "function", "package", "body", "shared", "array", "range",
    "stable", "quiet", "delayed", "transaction", "postponed", "unaffected",
    "select", "with", "guarded", "register", "bus", "disconnect", "group",
    "attribute", "new", "null", "on", "transport", "inertial", "reject",
}


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _strip_comments(text: str) -> str:
    return re.sub(r"--[^\n]*", "", text)


def _split_top_level(text: str, separator: str) -> List[str]:
    """Split on a separator, ignoring separators inside parentheses/quotes."""
    parts, depth, current, in_quote = [], 0, [], False
    for char in text:
        if char == "'":
            # VHDL tick: attribute or character literal; only '...' of len 3
            # is a character literal, but treating every tick as a quote toggle
            # breaks clk'event. Handle only double quotes below instead.
            pass
        if char == '"':
            in_quote = not in_quote
        if not in_quote:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            if char == separator and depth == 0:
                parts.append("".join(current))
                current = []
                continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _refs(expression: str) -> List[str]:
    """Signal references in an expression, excluding keywords and literals."""
    expression = re.sub(r'"[^"]*"', "", expression)          # string/bit literals
    expression = re.sub(r"'\w'", "", expression)              # character literals
    expression = re.sub(r"\b\d+(\.\d+)?\b", "", expression)   # numbers
    refs = []
    for match in _IDENT_RE.finditer(expression):
        name = match.group(0)
        if name.lower() in _VHDL_KEYWORDS:
            continue
        # Attribute suffixes (clk'event) and attribute names are skipped.
        if match.start() > 0 and expression[match.start() - 1] == "'":
            continue
        refs.append(name)
    return refs


def _base_signal(name: str) -> str:
    return re.sub(r"\(.*?\)", "", name).strip()


def _balanced_end(text: str, open_pos: int) -> int:
    """Index of the ')' matching the '(' at open_pos, or -1."""
    depth = 0
    in_quote = False
    for index in range(open_pos, len(text)):
        char = text[index]
        if char == '"':
            in_quote = not in_quote
        if in_quote:
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


class HDLWritePath:
    """Build a dependency graph from VHDL sources and trace signal drivers."""

    def __init__(self) -> None:
        self.entities: Dict[str, _Entity] = {}
        self.notes: List[str] = []

    # ── Entry points ──────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str) -> "HDLWritePath":
        tracer = cls()
        tracer.add_file(path)
        return tracer

    @classmethod
    def from_directory(cls, path: str) -> "HDLWritePath":
        tracer = cls()
        for pattern in ("*.vhd", "*.vhdl"):
            for source in sorted(Path(path).rglob(pattern)):
                tracer.add_file(str(source))
        return tracer

    def add_file(self, path: str) -> None:
        text = _strip_comments(Path(path).read_text(encoding="iso-8859-1"))
        entities = self._parse_entities(text, path)
        for entity in entities.values():
            if entity.name in self.entities:
                self.notes.append(f"duplicate entity {entity.name} in {path}; first definition kept")
                continue
            self.entities[entity.name] = entity
        self._parse_architectures(text, path, entities)
        self._parse_instantiations(text, path, entities)

    # ── Entity / port parsing ─────────────────────────────────────────────────

    def _parse_entities(self, text: str, path: str) -> Dict[str, _Entity]:
        entities: Dict[str, _Entity] = {}
        for match in re.finditer(
            r"\bentity\s+(\w+)\s+is\b(.*?)\bend\s+(?:entity\s+)?\1?\s*;",
            text, re.IGNORECASE | re.DOTALL,
        ):
            name, body = match.group(1), match.group(2)
            entity = _Entity(name=name, file=path)
            port_match = re.search(r"\bport\s*\(", body, re.IGNORECASE)
            if port_match:
                close = _balanced_end(body, port_match.end() - 1)
                if close < 0:
                    continue
                for entry in _split_top_level(body[port_match.end():close], ";"):
                    decl = re.match(
                        r"\s*([\w\s,]+?)\s*:\s*(in|out|inout|buffer)\b", entry, re.IGNORECASE
                    )
                    if not decl:
                        continue
                    direction = decl.group(2).lower()
                    for port_name in decl.group(1).split(","):
                        port_name = port_name.strip()
                        if port_name:
                            entity.ports[port_name] = direction
            for const in re.finditer(
                r"constant\s+(\w+)\s*:\s*[\w\s]+?\(.*?\)\s*:=\s*([XB])\"([0-9A-Fa-f_]+)\"",
                body, re.IGNORECASE,
            ):
                entity.constants[const.group(1)] = _format_const(const.group(2), const.group(3))
            entities[name] = entity
        return entities

    # ── Architecture body parsing ─────────────────────────────────────────────

    def _parse_architectures(self, text: str, path: str,
                             entities: Dict[str, _Entity]) -> None:
        for match in re.finditer(
            r"\barchitecture\s+(\w+)\s+of\s+(\w+)\s+is\b(.*?)\bend\s+(?:architecture\s+)?\1?\s*;",
            text, re.IGNORECASE | re.DOTALL,
        ):
            entity_name = match.group(2)
            entity = entities.get(entity_name) or self.entities.get(entity_name)
            if entity is None:
                continue
            body = match.group(3)
            base = match.start(3)
            for const in re.finditer(
                r"constant\s+(\w+)\s*:\s*[\w\s]+?\(.*?\)\s*:=\s*([XB])\"([0-9A-Fa-f_]+)\"",
                body, re.IGNORECASE,
            ):
                entity.constants[const.group(1)] = _format_const(const.group(2), const.group(3))
            for alias in re.finditer(
                r"\balias\s+(\w+)\s*:\s*[^;]+?\bis\s+(\w+(?:\([^)]*\))?)\s*;", body, re.IGNORECASE
            ):
                entity.aliases[alias.group(1)] = alias.group(2)
                entity.assignments.append(_Assignment(
                    target=alias.group(1), expression=alias.group(2), conditions=[],
                    file=path, line=_line_of(text, base + alias.start()), kind="alias",
                ))
            self._parse_concurrent(body, text, base, path, entity)
            self._parse_processes(body, text, base, path, entity)

    def _parse_concurrent(self, body: str, text: str, base: int, path: str,
                          entity: _Entity) -> None:
        # Remove process blocks first; what remains at statement level is
        # concurrent assignments (and instantiations, parsed separately).
        scrubbed = re.sub(r"\bprocess\b.*?\bend\s+process(?:\s+\w+)?\s*;", "", body,
                          flags=re.IGNORECASE | re.DOTALL)
        for match in re.finditer(r"(\w+(?:\([^)]*\))?)\s*<=\s*([^;]+);", scrubbed):
            target = match.group(1)
            if target.lower() in {"assert", "report"}:
                continue
            expression = match.group(2)
            when = re.search(r"\bwhen\s+(.+?)\s+else\b", expression, re.IGNORECASE | re.DOTALL)
            conditions = []
            if when:
                condition = " ".join(when.group(1).split())
                if condition.startswith("(") and condition.endswith(")"):
                    if _balanced_end(condition, 0) == len(condition) - 1:
                        condition = condition[1:-1].strip()
                conditions.append(condition)
            source = re.split(r"\bwhen\b", expression, flags=re.IGNORECASE)[0]
            source = re.split(r"\bafter\b", source, flags=re.IGNORECASE)[0]
            entity.assignments.append(_Assignment(
                target=target, expression=" ".join(source.split()), conditions=conditions,
                file=path, line=_line_of(text, base + match.start()),
            ))

    def _parse_processes(self, body: str, text: str, base: int, path: str,
                         entity: _Entity) -> None:
        for proc in re.finditer(r"\bprocess\b(.*?)begin(.*?)end\s+process(?:\s+\w+)?\s*;",
                                body, re.IGNORECASE | re.DOTALL):
            proc_body = proc.group(2)
            for assign in re.finditer(r"(\w+(?:\([^)]*\))?)\s*<=\s*([^;]+);", proc_body):
                target = assign.group(1)
                if target.lower() in {"assert", "report"}:
                    continue
                conditions = _enclosing_conditions(proc_body, assign.start())
                expression = re.split(r"\bafter\b", assign.group(2), flags=re.IGNORECASE)[0]
                entity.assignments.append(_Assignment(
                    target=target,
                    expression=" ".join(expression.split()),
                    conditions=conditions,
                    file=path,
                    line=_line_of(text, base + proc.start(2) + assign.start()),
                ))

    # ── Instantiation / port-map parsing ──────────────────────────────────────

    def _parse_instantiations(self, text: str, path: str,
                              entities: Dict[str, _Entity]) -> None:
        header_re = re.compile(r"(\w+)\s*:\s*(?:entity\s+(?:\w+\.)?(\w+)|(\w+))", re.IGNORECASE)
        for match in header_re.finditer(text):
            label = match.group(1)
            child = match.group(2) or match.group(3)
            if child.lower() in _VHDL_KEYWORDS:
                continue
            pos = match.end()
            generic = re.match(r"\s*generic\s+map\s*\(", text[pos:], re.IGNORECASE)
            if generic:
                close = _balanced_end(text, pos + generic.end() - 1)
                if close < 0:
                    continue
                pos = close + 1
            port = re.match(r"\s*port\s+map\s*\(", text[pos:], re.IGNORECASE)
            if not port:
                continue
            open_pos = pos + port.end() - 1
            close = _balanced_end(text, open_pos)
            if close < 0:
                continue
            host = self._host_entity_at(text, match.start(), entities)
            if host is None:
                continue
            host.instances[label] = child
            for entry in _split_top_level(text[open_pos + 1:close], ","):
                pair = re.match(r"\s*(\w+(?:\([^)]*\))?)\s*=>\s*([\w().' ]+?)\s*$", entry)
                if not pair:
                    continue
                formal = _base_signal(pair.group(1))
                actual = pair.group(2).strip()
                if actual.lower() == "open" or not actual:
                    continue
                host.portmaps.append((label, child, formal, actual))

    def _host_entity_at(self, text: str, pos: int,
                        entities: Dict[str, _Entity]) -> Optional[_Entity]:
        host = None
        for match in re.finditer(r"\barchitecture\s+\w+\s+of\s+(\w+)\s+is\b", text[:pos], re.IGNORECASE):
            host = entities.get(match.group(1)) or self.entities.get(match.group(1))
        return host

    # ── Tracing ───────────────────────────────────────────────────────────────

    def trace(self, target: str, max_depth: int = 24, max_paths: int = 32) -> WritePathReport:
        """Trace 'entity.signal' back to primary input ports."""
        if "." not in target:
            matches = [name for name in self.entities if self._has_signal(name, target)]
            if len(matches) == 1:
                target = f"{matches[0]}.{target}"
            else:
                raise ValueError(
                    f"unscoped target '{target}' matches {len(matches)} entities; use entity.signal"
                )
        entity_name, signal = target.split(".", 1)
        report = WritePathReport(target=target)
        start = Hop(entity=entity_name, signal=signal, via="start")
        self._bfs(start, report, max_depth, max_paths)
        report.notes.extend(self.notes)
        for condition in report.conditions:
            for const in re.findall(r"\b(ADDR_\w+)\b", condition):
                for entity in self.entities.values():
                    if const in entity.constants:
                        report.address_constants[const] = entity.constants[const]
        return report

    def trace_decoder(self, decoder_entity: str, selector: str,
                      strobe: Optional[str] = None) -> Dict[str, WritePathReport]:
        """Trace a decoder's command (selector) and strobe signals."""
        reports = {"command": self.trace(f"{decoder_entity}.{selector}")}
        if strobe:
            reports["strobe"] = self.trace(f"{decoder_entity}.{strobe}")
        return reports

    def _has_signal(self, entity_name: str, signal: str) -> bool:
        entity = self.entities.get(entity_name)
        if entity is None:
            return False
        if signal in entity.ports or signal in entity.aliases:
            return True
        return any(_base_signal(a.target) == signal for a in entity.assignments)

    def _bfs(self, start: Hop, report: WritePathReport,
             max_depth: int, max_paths: int, max_expansions: int = 4000) -> None:
        """Breadth-first driver search; one shortest path per primary input.

        Each (entity, signal) node is expanded once, which bounds the search
        even on large bus-target logic cones. Paths are reconstructed through
        parent links, so every reported path is a shortest driver chain.
        """
        from collections import deque

        nodes: List[Hop] = [start]
        parents: List[Optional[int]] = [None]
        depths: List[int] = [0]
        expanded: Set[Tuple[str, str]] = set()
        endpoints: Dict[str, int] = {}
        queue = deque([0])
        expansions = 0
        while queue:
            index = queue.popleft()
            hop = nodes[index]
            key = (hop.entity, hop.signal)
            if key in expanded:
                continue
            expanded.add(key)
            for condition in hop.conditions:
                if condition not in report.conditions:
                    report.conditions.append(condition)
            entity = self.entities.get(hop.entity)
            direction = entity.ports.get(hop.signal) if entity else None
            drivers = self._drivers(hop.entity, hop.signal) if depths[index] < max_depth else []
            if not drivers:
                if direction in {"in", "inout"}:
                    report.primary_inputs.append(hop.scoped())
                    endpoints.setdefault(hop.scoped(), index)
                elif index != 0:
                    # Undriven non-port: terminal but not a primary input.
                    endpoints.setdefault(f"(undriven) {hop.scoped()}", index)
                if depths[index] >= max_depth:
                    report.notes.append(f"trace depth cap reached at {hop.scoped()}")
                continue
            expansions += 1
            if expansions > max_expansions:
                report.notes.append(f"expansion cap reached ({max_expansions}); partial results")
                break
            for driver in drivers:
                dkey = (driver.entity, driver.signal)
                if dkey in expanded:
                    continue
                nodes.append(driver)
                parents.append(index)
                depths.append(depths[index] + 1)
                queue.append(len(nodes) - 1)
        for name, index in endpoints.items():
            path: List[Hop] = []
            cursor: Optional[int] = index
            while cursor is not None:
                path.append(nodes[cursor])
                cursor = parents[cursor]
            report.paths.append(list(reversed(path)))
            if len(report.paths) >= max_paths:
                report.notes.append(f"path list capped at {max_paths}")
                break
        if not endpoints:
            report.paths.append([start])

    def _drivers(self, entity_name: str, signal: str) -> List[Hop]:
        """All hops that drive entity.signal: assignments, conditions, port maps."""
        hops: List[Hop] = []
        entity = self.entities.get(entity_name)
        if entity is None:
            return hops
        for assign in entity.assignments:
            if _base_signal(assign.target) != signal:
                continue
            for ref in _refs(assign.expression):
                if ref in entity.constants:
                    continue
                hops.append(Hop(
                    entity=entity_name, signal=ref, via=assign.kind,
                    expression=assign.expression, conditions=list(assign.conditions),
                    file=assign.file, line=assign.line,
                ))
            # Strobe paths continue through the condition logic: a strobe
            # assigned '1' under `write_en='1' and address=CONST` is driven by
            # those condition signals, not by the literal.
            for condition in assign.conditions:
                for ref in _refs(condition):
                    if ref in entity.constants:
                        continue
                    hops.append(Hop(
                        entity=entity_name, signal=ref, via="condition",
                        expression=condition, conditions=[condition],
                        file=assign.file, line=assign.line,
                    ))
        # Port maps: a formal *input* of this entity is driven by the parent's
        # actual; an actual connected to a child *output* is driven inside the
        # child. Unknown child entities are skipped (primitives, black boxes).
        for parent in self.entities.values():
            for label, child, formal, actual in parent.portmaps:
                child_entity = self.entities.get(child)
                if child_entity is None:
                    continue
                direction = child_entity.ports.get(formal)
                if entity_name == parent.name and signal == _base_signal(actual):
                    if direction in {"out", "inout", "buffer"}:
                        hops.append(Hop(
                            entity=child, signal=formal, via="portmap",
                            expression=f"{parent.name}:{label} port {formal} => {actual}",
                        ))
                elif entity_name == child and signal == formal and direction == "in":
                    hops.append(Hop(
                        entity=parent.name, signal=_base_signal(actual), via="portmap",
                        expression=f"{parent.name}:{label} port {formal} => {actual}",
                    ))
        return hops


# ── Condition tracking ────────────────────────────────────────────────────────

_COND_TOKEN_RE = re.compile(
    r"\bend\s+if\s*;|\bend\s+case\s*;|\bif\b|\bcase\b|\bwhen\b|\belsif\b|\belse\b",
    re.IGNORECASE,
)


def _enclosing_conditions(body: str, pos: int) -> List[str]:
    """Conditions of if/case constructs enclosing offset `pos` in a process.

    A frame stack tracks each enclosing construct's *current* condition:
    `elsif`/`else` rewrite the innermost if-frame, and each `when` rewrites
    the innermost case-frame's arm condition. Conditions therefore reflect
    exactly the branch containing the assignment, never stale sibling arms.
    """
    frames: List[Tuple[str, Optional[str]]] = []
    for token in _COND_TOKEN_RE.finditer(body, 0, pos):
        word = token.group(0).lower()
        if word.startswith("end"):
            if frames:
                frames.pop()
            continue
        if word == "if":
            condition = re.match(r"\s*\(?([^;]+?)\)?\s+then\b", body[token.end():], re.IGNORECASE)
            if condition:
                frames.append(("if", " ".join(condition.group(1).split())))
        elif word == "elsif":
            condition = re.match(r"\s*\(?([^;]+?)\)?\s+then\b", body[token.end():], re.IGNORECASE)
            if condition and frames and frames[-1][0] == "if":
                frames[-1] = ("if", " ".join(condition.group(1).split()))
        elif word == "else":
            if frames and frames[-1][0] == "if" and frames[-1][1]:
                frames[-1] = ("if", f"not ({frames[-1][1]})")
        elif word == "case":
            selector = re.match(r"\s*\(?\s*([\w() ]+?)\s*\)?\s+is\b", body[token.end():], re.IGNORECASE)
            if selector:
                frames.append(("case", None))
                frames[-1] = ("case:" + " ".join(selector.group(1).split()), None)
        elif word == "when":
            arm = re.match(r"\s+([\w\"'.]+)\s*=>", body[token.end():], re.IGNORECASE)
            if arm and frames and frames[-1][0].startswith("case:"):
                selector = frames[-1][0][5:]
                frames[-1] = (frames[-1][0], f"{selector} = {arm.group(1)}")
    conditions: List[str] = []
    for kind, condition in frames:
        if condition and "event" not in condition.lower():
            conditions.append(condition)
    return conditions


def _format_const(base: str, digits: str) -> str:
    digits = digits.replace("_", "")
    if base.upper() == "X":
        return "0x" + digits.upper()
    if base.upper() == "B":
        return "0b" + digits
    return digits
