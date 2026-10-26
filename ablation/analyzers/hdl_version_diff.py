"""
hdl_version_diff.py — Cross-version diff of Verilog/VHDL source trees.

Compares two VerilogSemantic snapshots and reports what changed between
versions: added/removed/changed constants, signal widths, FSM states,
and module/entity names.

Designed for multi-version HDL collections (e.g. BCC VHDL v0.2–v0.9)
where the goal is identifying which design decisions changed between releases
without reading every file manually.

Usage:
    diff = HDLVersionDiff.from_directories('bcc_vhdl_0.8/', 'bcc_vhdl_0.9/')
    print(diff.report())
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from ablation.analyzers.verilog_semantic import VerilogSemantic


def _normalise(value: str) -> str:
    """Strip outer whitespace and enclosing quotes for value comparison."""
    v = value.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1].strip()
    return v


@dataclass
class ConstantChange:
    name: str
    old_value: str
    new_value: str
    file_old: str
    file_new: str
    line_old: int
    line_new: int


@dataclass
class SignalChange:
    name: str
    old_width: int
    new_width: int


@dataclass
class StateChange:
    name: str
    old_encoding: str
    new_encoding: str


class HDLVersionDiff:
    """
    Diff between two Verilog/VHDL source versions.

    Compare constants, signal widths, FSM states, and module names.
    Construct via from_directories() or from_snapshots().
    """

    def __init__(
        self,
        vs_old: VerilogSemantic,
        vs_new: VerilogSemantic,
        label_old: str = "old",
        label_new: str = "new",
    ) -> None:
        self._old = vs_old
        self._new = vs_new
        self._label_old = label_old
        self._label_new = label_new
        self._compute()

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_directories(
        cls,
        old_dir: str,
        new_dir: str,
        label_old: str = "",
        label_new: str = "",
    ) -> "HDLVersionDiff":
        """Build a diff from two source directories."""
        import os
        vs_old = VerilogSemantic.from_directory(old_dir)
        vs_new = VerilogSemantic.from_directory(new_dir)
        lo = label_old or os.path.basename(old_dir.rstrip("/\\"))
        ln = label_new or os.path.basename(new_dir.rstrip("/\\"))
        return cls(vs_old, vs_new, lo, ln)

    @classmethod
    def from_snapshots(
        cls,
        vs_old: VerilogSemantic,
        vs_new: VerilogSemantic,
        label_old: str = "old",
        label_new: str = "new",
    ) -> "HDLVersionDiff":
        """Build a diff from two pre-built VerilogSemantic instances."""
        return cls(vs_old, vs_new, label_old, label_new)

    # ── Internal diff computation ─────────────────────────────────────────────

    def _compute(self) -> None:
        c_old = self._old.constants()
        c_new = self._new.constants()
        names_old = set(c_old)
        names_new = set(c_new)

        self._added_constants: Dict[str, dict] = {
            n: c_new[n] for n in (names_new - names_old)
        }
        self._removed_constants: Dict[str, dict] = {
            n: c_old[n] for n in (names_old - names_new)
        }
        self._changed_constants: Dict[str, ConstantChange] = {}
        for name in names_old & names_new:
            ov = _normalise(c_old[name]["value"])
            nv = _normalise(c_new[name]["value"])
            if ov != nv:
                self._changed_constants[name] = ConstantChange(
                    name=name,
                    old_value=c_old[name]["value"].strip(),
                    new_value=c_new[name]["value"].strip(),
                    file_old=c_old[name].get("file", ""),
                    file_new=c_new[name].get("file", ""),
                    line_old=c_old[name].get("line", 0),
                    line_new=c_new[name].get("line", 0),
                )

        pw_old = self._old.port_widths()
        pw_new = self._new.port_widths()
        sigs_old = set(pw_old)
        sigs_new = set(pw_new)
        self._added_signals: Dict[str, int] = {
            n: pw_new[n] for n in (sigs_new - sigs_old)
        }
        self._removed_signals: Dict[str, int] = {
            n: pw_old[n] for n in (sigs_old - sigs_new)
        }
        self._changed_signals: Dict[str, SignalChange] = {
            n: SignalChange(n, pw_old[n], pw_new[n])
            for n in sigs_old & sigs_new
            if pw_old[n] != pw_new[n]
        }

        se_old = self._old.state_encodings()
        se_new = self._new.state_encodings()
        states_old = set(se_old)
        states_new = set(se_new)
        self._added_states: Dict[str, dict] = {
            n: se_new[n] for n in (states_new - states_old)
        }
        self._removed_states: Dict[str, dict] = {
            n: se_old[n] for n in (states_old - states_new)
        }
        self._changed_states: Dict[str, StateChange] = {
            n: StateChange(n, se_old[n]["encoding"], se_new[n]["encoding"])
            for n in states_old & states_new
            if se_old[n]["encoding"] != se_new[n]["encoding"]
        }

        mods_old = set(self._old.modules())
        mods_new = set(self._new.modules())
        self._added_modules: List[str] = sorted(mods_new - mods_old)
        self._removed_modules: List[str] = sorted(mods_old - mods_new)

    # ── Public accessors ─────────────────────────────────────────────────────

    def added_constants(self) -> Dict[str, dict]:
        """Constants in new but not old."""
        return self._added_constants

    def removed_constants(self) -> Dict[str, dict]:
        """Constants in old but not new."""
        return self._removed_constants

    def changed_constants(self) -> Dict[str, ConstantChange]:
        """Constants present in both with different normalised values."""
        return self._changed_constants

    def added_signals(self) -> Dict[str, int]:
        """Signals/ports added in new (name → bit width)."""
        return self._added_signals

    def removed_signals(self) -> Dict[str, int]:
        """Signals/ports removed in new (name → bit width)."""
        return self._removed_signals

    def changed_signals(self) -> Dict[str, SignalChange]:
        """Signals whose bit width changed."""
        return self._changed_signals

    def added_states(self) -> Dict[str, dict]:
        """FSM state names added in new."""
        return self._added_states

    def removed_states(self) -> Dict[str, dict]:
        """FSM state names removed in new."""
        return self._removed_states

    def changed_states(self) -> Dict[str, StateChange]:
        """FSM states present in both with different encodings."""
        return self._changed_states

    def added_modules(self) -> List[str]:
        """Module/entity names added in new."""
        return self._added_modules

    def removed_modules(self) -> List[str]:
        """Module/entity names removed in new."""
        return self._removed_modules

    def is_empty(self) -> bool:
        """True if no changes detected in any category."""
        return (
            not self._added_constants
            and not self._removed_constants
            and not self._changed_constants
            and not self._added_signals
            and not self._removed_signals
            and not self._changed_signals
            and not self._added_states
            and not self._removed_states
            and not self._changed_states
            and not self._added_modules
            and not self._removed_modules
        )

    # ── Reporting ────────────────────────────────────────────────────────────

    def summary(self) -> str:
        """One-line change count summary."""
        parts = []
        nc = len(self._added_constants) + len(self._removed_constants) + len(self._changed_constants)
        ns = len(self._added_signals) + len(self._removed_signals) + len(self._changed_signals)
        nst = len(self._added_states) + len(self._removed_states) + len(self._changed_states)
        nm = len(self._added_modules) + len(self._removed_modules)
        if nc:
            parts.append(
                f"{nc} constant change(s) "
                f"(+{len(self._added_constants)} -{len(self._removed_constants)} ~{len(self._changed_constants)})"
            )
        if ns:
            parts.append(
                f"{ns} signal change(s) "
                f"(+{len(self._added_signals)} -{len(self._removed_signals)} ~{len(self._changed_signals)})"
            )
        if nst:
            parts.append(
                f"{nst} FSM state change(s) "
                f"(+{len(self._added_states)} -{len(self._removed_states)} ~{len(self._changed_states)})"
            )
        if nm:
            parts.append(f"{nm} module/entity change(s)")
        if not parts:
            return f"{self._label_old} → {self._label_new}: no changes detected"
        return f"{self._label_old} → {self._label_new}: " + ", ".join(parts)

    def report(self) -> str:
        """Full formatted diff grouped by category."""
        lines: List[str] = [
            f"HDLVersionDiff: {self._label_old} → {self._label_new}",
            "=" * 60,
        ]
        if self.is_empty():
            lines.append("  (no changes detected)")
            return "\n".join(lines)

        if self._added_constants or self._removed_constants or self._changed_constants:
            lines.append("\nConstants:")
            for name, entry in sorted(self._added_constants.items()):
                lines.append(f"  + {name} = {entry['value'].strip()!r}  ({entry.get('file','')}:{entry.get('line','')})")
            for name, entry in sorted(self._removed_constants.items()):
                lines.append(f"  - {name} = {entry['value'].strip()!r}  ({entry.get('file','')}:{entry.get('line','')})")
            for name, chg in sorted(self._changed_constants.items()):
                lines.append(f"  ~ {name}: {chg.old_value!r} → {chg.new_value!r}")

        if self._added_signals or self._removed_signals or self._changed_signals:
            lines.append("\nSignals / ports:")
            for name, w in sorted(self._added_signals.items()):
                lines.append(f"  + {name} [{w}b]")
            for name, w in sorted(self._removed_signals.items()):
                lines.append(f"  - {name} [{w}b]")
            for name, chg in sorted(self._changed_signals.items()):
                lines.append(f"  ~ {name}: {chg.old_width}b → {chg.new_width}b")

        if self._added_states or self._removed_states or self._changed_states:
            lines.append("\nFSM states:")
            for name, entry in sorted(self._added_states.items()):
                lines.append(f"  + {name}  (encoding {entry['encoding']})")
            for name, entry in sorted(self._removed_states.items()):
                lines.append(f"  - {name}  (encoding {entry['encoding']})")
            for name, chg in sorted(self._changed_states.items()):
                lines.append(f"  ~ {name}: encoding {chg.old_encoding} → {chg.new_encoding}")

        if self._added_modules or self._removed_modules:
            lines.append("\nModules / entities:")
            for name in self._added_modules:
                lines.append(f"  + {name}")
            for name in self._removed_modules:
                lines.append(f"  - {name}")

        return "\n".join(lines)
