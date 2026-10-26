"""
one_hot_fsm_extractor.py — One-hot FSM transition table extractor for Verilog.

Parses next-state combinational assign chains of the form:
    assign d_statem[N] = rst_b & (
        statemachine[A] & condition_1 |
        statemachine[B] & condition_2 & ~condition_3);

Returns the full state transition table and output signal assignments
without requiring a full Verilog parser.

Designed for ATLAS ASIC RTL (ABCn ROL, ROC, and compatible designs) where
one-hot FSMs are encoded as individual combinational assigns per next-state bit.

Usage:
    fsm = OneHotFSMExtractor.from_file('/tmp/abcn_rtl/rtl_final/rol_cntrl_hdl.v')
    print(fsm.report())
    print(fsm.as_python_dict())
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ── Transition edge ────────────────────────────────────────────────────────────

@dataclass
class FSMEdge:
    """One transition arc: from source_state under guard → dest_state."""
    source_state: int          # index of the current state (statemachine[M])
    dest_state: int            # index of the next state (d_statem[N])
    guard: str                 # boolean guard string (Python-readable)
    raw_guard: str             # original Verilog expression fragment


# ── Main class ─────────────────────────────────────────────────────────────────

class OneHotFSMExtractor:
    """
    Extract one-hot FSM transition tables from Verilog combinational assigns.

    Handles multi-line assign blocks terminated by ';'. Extracts:
      - next-state transitions (d_<reg>[N] = ...)
      - output signal assignments (assign signal = statemachine[K] | ...)
      - state names from commented-out parameter declarations

    Construct via from_file() or from_directory().
    """

    def __init__(
        self,
        edges: List[FSMEdge],
        output_map: Dict[str, List[int]],
        state_names: Dict[int, str],
        state_reg: str,
        next_reg: str,
        source_file: str,
    ) -> None:
        self._edges = edges
        self._output_map = output_map
        self._state_names = state_names
        self._state_reg = state_reg
        self._next_reg = next_reg
        self._source_file = source_file

    # ── Constructors ───────────────────────────────────────────────────────────

    @classmethod
    def from_file(
        cls,
        path: str,
        next_state_pattern: str = "d_statem",
        state_reg_pattern: str = "statemachine",
    ) -> "OneHotFSMExtractor":
        """
        Parse one Verilog file and extract the one-hot FSM.

        next_state_pattern: prefix of the next-state register (default 'd_statem').
        state_reg_pattern:  name of the current-state register (default 'statemachine').
        """
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
        return _parse(text, path, next_state_pattern, state_reg_pattern)

    @classmethod
    def from_directory(
        cls,
        dir_path: str,
        next_state_pattern: str = "d_statem",
        state_reg_pattern: str = "statemachine",
    ) -> List["OneHotFSMExtractor"]:
        """
        Scan all .v files under dir_path and return one extractor per file
        that contains the next_state_pattern. Empty files are skipped.
        """
        import os
        results = []
        for root, _, files in os.walk(dir_path):
            for fname in sorted(files):
                if not fname.endswith(".v"):
                    continue
                full = os.path.join(root, fname)
                try:
                    fsm = cls.from_file(full, next_state_pattern, state_reg_pattern)
                    if fsm._edges:
                        results.append(fsm)
                except OSError:
                    pass
        return results

    # ── Accessors ──────────────────────────────────────────────────────────────

    def states(self) -> List[int]:
        """Sorted list of all state indices found (dest states in transitions)."""
        return sorted({e.dest_state for e in self._edges})

    def transitions(self) -> Dict[int, List[Tuple[int, str]]]:
        """
        Dict: dest_state → [(source_state, guard_str), ...].

        Read as: "state N is entered from source_state when guard is true."
        """
        result: Dict[int, List[Tuple[int, str]]] = {}
        for e in self._edges:
            result.setdefault(e.dest_state, []).append((e.source_state, e.guard))
        return {k: result[k] for k in sorted(result)}

    def output_signals(self) -> Dict[str, List[int]]:
        """
        Dict: signal_name → [state_indices where it is active].
        Derived from assign signal = statemachine[K] | statemachine[L] | ...
        """
        return dict(self._output_map)

    def state_names(self) -> Dict[int, str]:
        """
        Dict: state_index → name string.
        Sources: uncommented parameters, commented-out defines, fallback 'ST{N}'.
        """
        return dict(self._state_names)

    def name(self, idx: int) -> str:
        """Return the state name for index idx, or 'ST{idx}' if unknown."""
        return self._state_names.get(idx, f"ST{idx}")

    # ── Output ─────────────────────────────────────────────────────────────────

    def report(self) -> str:
        """Full formatted transition table and output signal list."""
        import os
        lines: List[str] = [
            f"OneHotFSMExtractor: {os.path.basename(self._source_file)}",
            f"  next_reg={self._next_reg!r}  state_reg={self._state_reg!r}",
            f"  {len(self.states())} states, {len(self._edges)} edges",
            "",
        ]
        trans = self.transitions()
        for dest in sorted(trans):
            dname = self.name(dest)
            lines.append(f"  {dname} ({dest:0{max(len(self.states()), 1)}d}):")
            for src, guard in trans[dest]:
                sname = self.name(src)
                lines.append(f"    from {sname:<12s}  if  {guard}")
        if self._output_map:
            lines.append("")
            lines.append("  Output signals:")
            for sig, state_idxs in sorted(self._output_map.items()):
                snames = ", ".join(self.name(i) for i in sorted(state_idxs))
                lines.append(f"    {sig}: active in {snames}")
        return "\n".join(lines)

    def as_python_dict(self, var_name: str = "FSM_TRANSITIONS") -> str:
        """
        Return a Python dict literal for the transition table, ready to paste
        into an RE module.
        """
        trans = self.transitions()
        lines: List[str] = [f"{var_name} = {{"]
        for dest in sorted(trans):
            dname = self.name(dest)
            edges_str = ",\n             ".join(
                f'({self.name(src)!r}, {guard!r})' for src, guard in trans[dest]
            )
            lines.append(f'    "{dname}": [{edges_str}],')
        lines.append("}")
        return "\n".join(lines)


# ── Parser ─────────────────────────────────────────────────────────────────────

# Matches the start of a next-state assign: assign d_statem[N] = ...
_NEXT_STATE_RE = re.compile(
    r"assign\s+(?P<nreg>[A-Za-z_]\w*)\[(?P<dest>\d+)\]\s*=\s*(?P<body>[^;]+;)",
    re.DOTALL,
)

# Matches a source-state term inside an assign body: statemachine[M]
_SRC_STATE_RE = re.compile(r"(?P<sreg>[A-Za-z_]\w*)\[(?P<src>\d+)\]")

# Matches output signal assigns: assign signal[N] = statemachine[K] | ...
# or: assign signal = statemachine[K] | statemachine[L] | ...
_OUTPUT_ASSIGN_RE = re.compile(
    r"assign\s+(?P<sig>[A-Za-z_]\w*(?:\[\d+\])?)\s*=\s*(?P<body>[^;]+;)",
    re.DOTALL,
)

# Commented-out parameter or `define: // ... define ST1 / parameter ST1
_COMMENTED_STATE_RE = re.compile(
    r"//.*?(?:define|parameter)\s+([A-Z_][A-Z0-9_]*)\s+\d*\'[bh]([01a-fA-F_]+)"
)

# Active parameter: parameter ST_FOO = N'bXXX
_PARAM_RE = re.compile(
    r"\bparameter\s+([A-Z_][A-Z0-9_]*)\s*=\s*\d+\'[bh]([01a-fA-F_]+)"
)


def _guard_to_python(expr: str, src_idx: int, state_reg: str) -> str:
    """
    Convert a Verilog guard expression fragment to a readable Python-style string.
    Removes the source-state term (statemachine[src_idx]) since it is implicit.
    Replaces & → and, | → or, ~ → not .
    """
    # Remove the source state reference (may appear with & on either side)
    expr = re.sub(
        r"\s*&?\s*" + re.escape(state_reg) + r"\[" + str(src_idx) + r"\]\s*&?\s*",
        " ",
        expr,
    )
    expr = re.sub(
        r"\s*" + re.escape(state_reg) + r"\[" + str(src_idx) + r"\]\s*",
        " ",
        expr,
    )
    # Normalise boolean operators
    expr = expr.replace("~", "not ").replace("&", "and").replace("|", "or")
    # Collapse whitespace
    expr = re.sub(r"\s+", " ", expr).strip()
    # Strip a single enclosing ( ) pair if present
    if expr.startswith("(") and expr.endswith(")"):
        inner = expr[1:-1].strip()
        depth = 0
        balanced = True
        for ch in inner:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    balanced = False
                    break
        if balanced:
            expr = inner
    if not expr:
        return "unconditional"
    return expr


def _one_hot_value(val_str: str) -> Optional[int]:
    """
    Convert a one-hot binary string to its bit index.

    Binary strings are MSB-first: '10000000000' (11 bits) has bit 10 set.
    Returns bit index (0 = LSB = rightmost), or None if not one-hot.
    """
    v = val_str.replace("_", "")
    if v.count("1") == 1:
        return len(v) - 1 - v.index("1")
    return None


def _parse(
    text: str,
    source_file: str,
    next_state_pattern: str,
    state_reg_pattern: str,
) -> OneHotFSMExtractor:
    """Parse Verilog text and return an extractor instance."""

    edges: List[FSMEdge] = []
    output_map: Dict[str, List[int]] = {}
    state_names: Dict[int, str] = {}

    # ── Collect state names from parameters / commented defines ──────────────
    for m in _PARAM_RE.finditer(text):
        name, val = m.group(1), m.group(2)
        idx = _one_hot_value(val)
        if idx is not None:
            state_names[idx] = name

    for m in _COMMENTED_STATE_RE.finditer(text):
        name, val = m.group(1), m.group(2)
        idx = _one_hot_value(val)
        if idx is not None and idx not in state_names:
            state_names[idx] = name

    # ── Next-state assigns ────────────────────────────────────────────────────
    for m in _NEXT_STATE_RE.finditer(text):
        reg_name = m.group("nreg")
        if not reg_name.startswith(next_state_pattern):
            continue
        dest = int(m.group("dest"))
        body = m.group("body").rstrip(";")

        # Collect all source-state references in this assign body
        for sm in _SRC_STATE_RE.finditer(body):
            if sm.group("sreg") != state_reg_pattern:
                continue
            src = int(sm.group("src"))

            # Extract the guard: the AND-clause containing this source state
            # Find the term statemachine[src] in a disjunction of AND-clauses
            guard_raw = _extract_clause(body, state_reg_pattern, src)
            guard_py = _guard_to_python(guard_raw, src, state_reg_pattern)
            edges.append(FSMEdge(
                source_state=src,
                dest_state=dest,
                guard=guard_py,
                raw_guard=guard_raw,
            ))

    # ── Output signal assigns ─────────────────────────────────────────────────
    for m in _OUTPUT_ASSIGN_RE.finditer(text):
        sig = m.group("sig")
        body = m.group("body").rstrip(";")
        active: List[int] = []
        for sm in _SRC_STATE_RE.finditer(body):
            if sm.group("sreg") == state_reg_pattern:
                active.append(int(sm.group("src")))
        if active and not sig.startswith(next_state_pattern):
            # Only include if this is a pure state-reference assign (no arithmetic)
            non_state = re.sub(
                r"\b" + re.escape(state_reg_pattern) + r"\[\d+\]", "", body
            )
            non_state = re.sub(r"[|&~()\s]", "", non_state)
            if not non_state:  # purely composed of state references
                output_map[sig] = sorted(set(active))

    return OneHotFSMExtractor(
        edges=edges,
        output_map=output_map,
        state_names=state_names,
        state_reg=state_reg_pattern,
        next_reg=next_state_pattern,
        source_file=source_file,
    )


def _extract_clause(body: str, state_reg: str, src_idx: int) -> str:
    """
    Extract the AND-clause containing statemachine[src_idx] from a disjunction.

    Handles two common RTL styles:
      Style A (flat): statemachine[A] & cond | statemachine[B] & cond2
      Style B (grouped): rst_b & (statemachine[A] & cond | statemachine[B] & cond2)

    In style B, the | operators are inside a paren group, so a top-level split
    finds nothing. We strip the outermost ( ) and retry.
    """
    pattern = re.compile(
        re.escape(state_reg) + r"\[" + str(src_idx) + r"\]"
    )

    # Pass 1: split on top-level |
    clauses = _split_top_level_or(body)
    if len(clauses) > 1:
        for clause in clauses:
            if pattern.search(clause):
                return clause.strip()

    # Pass 2: strip the outermost paren group and retry (handles rst_b & (...))
    inner = _extract_paren_content(body)
    if inner and inner != body:
        clauses = _split_top_level_or(inner)
        for clause in clauses:
            if pattern.search(clause):
                return clause.strip()

    return body.strip()


def _extract_paren_content(expr: str) -> str:
    """Return the content of the outermost ( ) group, or expr unchanged."""
    start = expr.find("(")
    if start == -1:
        return expr
    depth = 0
    for i, ch in enumerate(expr[start:], start):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return expr[start + 1 : i]
    return expr


def _split_top_level_or(expr: str) -> List[str]:
    """Split expression on '|' operators that are not inside parentheses."""
    parts: List[str] = []
    depth = 0
    current: List[str] = []
    for ch in expr:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "|" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts
