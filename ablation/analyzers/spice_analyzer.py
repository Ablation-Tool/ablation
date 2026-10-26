"""
spice_analyzer.py — SPICE netlist topology extractor for analog IC RE.

Parses flat and subcircuit SPICE netlists to extract:
  - transistor count by type (NMOS/PMOS)
  - supply rail voltages from voltage source declarations
  - topology classification: current mirror, diff pair, LVDS, inverter
  - known structure identification with node and device lists

Handles the TSMC 0.25um BCC SPICE format:
    M1 drain gate source bulk PMOS L=480n W=35.64u ...
    VVDD VDD 0 2.5
    R_TERM P M 100

Usage:
    sa = SpiceAnalyzer.from_path('/path/to/bcc_spice_test_1.cir')
    print(sa.topology_summary())
    print(sa.classify())
    print(sa.transistor_count())
    print(sa.supply_rails())
    for s in sa.known_structures():
        print(s)
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class _Mosfet:
    name: str
    drain: str
    gate: str
    source: str
    bulk: str
    model: str      # PMOS / NMOS / pfet / nfet / etc.
    width_um: float = 0.0
    length_nm: float = 0.0

    @property
    def is_pmos(self) -> bool:
        return "p" in self.model.lower()

    @property
    def is_nmos(self) -> bool:
        return "n" in self.model.lower()


@dataclass
class _Resistor:
    name: str
    node_a: str
    node_b: str
    value: float  # ohms


@dataclass
class StructureHit:
    """One identified analog topology structure."""
    type: str           # "current_mirror" | "diff_pair" | "lvds" | "inverter" | "pullup" | "pulldown"
    devices: List[str]  # transistor instance names involved
    nodes: List[str]    # signal/supply nodes involved
    description: str


# ── Parsing helpers ───────────────────────────────────────────────────────────

_WL_RE = re.compile(r'W\s*=\s*([\d.]+)\s*u', re.IGNORECASE)
_L_RE  = re.compile(r'L\s*=\s*([\d.]+)\s*(n|u)?', re.IGNORECASE)
_VSRC_RE = re.compile(
    r'^V\w+\s+(\S+)\s+(\S+)\s+([\d.]+)\s*$', re.IGNORECASE | re.MULTILINE
)


def _parse_wl(tokens: List[str]) -> Tuple[float, float]:
    rest = " ".join(tokens)
    wm = _WL_RE.search(rest)
    lm = _L_RE.search(rest)
    w = float(wm.group(1)) if wm else 0.0
    if lm:
        val = float(lm.group(1))
        unit = (lm.group(2) or "").lower()
        l_nm = val * 1000 if unit == "u" else val  # u -> nm
    else:
        l_nm = 0.0
    return w, l_nm


def _norm_model(model: str) -> str:
    """Normalise model name to 'nmos' or 'pmos'."""
    m = model.lower()
    if m.startswith("p") or "pfet" in m:
        return "pmos"
    if m.startswith("n") or "nfet" in m:
        return "nmos"
    return m


# ── Main class ────────────────────────────────────────────────────────────────

class SpiceAnalyzer:
    """
    SPICE netlist topology extractor.

    File-based. No SPICE simulation is run. Topology classification is based
    on graph connectivity patterns between transistor terminals.
    """

    def __init__(
        self,
        path: str,
        mosfets: List[_Mosfet],
        resistors: List[_Resistor],
        supply_nodes: Dict[str, float],
        gnd_nodes: Set[str],
    ) -> None:
        self._path = path
        self._mosfets = mosfets
        self._resistors = resistors
        self._supply_nodes = supply_nodes   # node_name -> voltage
        self._gnd_nodes = gnd_nodes

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str) -> "SpiceAnalyzer":
        """Parse a SPICE .cir or .sp file at *path*."""
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        mosfets, resistors, supply_nodes, gnd_nodes = _parse_spice(text)
        return cls(path, mosfets, resistors, supply_nodes, gnd_nodes)

    # ── Public API ────────────────────────────────────────────────────────────

    def transistor_count(self) -> int:
        return len(self._mosfets)

    def transistors_by_type(self) -> Dict[str, int]:
        """Return {'pmos': N, 'nmos': M} counts."""
        counts: Dict[str, int] = {"pmos": 0, "nmos": 0}
        for m in self._mosfets:
            key = "pmos" if m.is_pmos else "nmos"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def supply_rails(self) -> List[float]:
        """Return unique positive supply voltages found in the netlist."""
        seen: Set[float] = set()
        for v in self._supply_nodes.values():
            if v > 0:
                seen.add(round(v, 3))
        return sorted(seen)

    def known_structures(self) -> List[StructureHit]:
        """Identify known analog topologies by transistor connectivity."""
        hits: List[StructureHit] = []
        hits.extend(_find_current_mirrors(self._mosfets))
        hits.extend(_find_diff_pairs(self._mosfets))
        hits.extend(_find_lvds(self._mosfets, self._resistors, self._supply_nodes))
        hits.extend(_find_inverters(self._mosfets))
        return hits

    def classify(self) -> str:
        """Return the dominant topology label for this netlist."""
        structs = self.known_structures()
        if not structs:
            counts = self.transistors_by_type()
            if counts.get("pmos", 0) > 0 and counts.get("nmos", 0) == 0:
                return "pmos_pad_array"
            if counts.get("nmos", 0) > 0 and counts.get("pmos", 0) == 0:
                return "nmos_pad_array"
            return "unknown"
        types = [s.type for s in structs]
        if "lvds" in types:
            return "lvds"
        if "diff_pair" in types:
            return "diff_pair"
        if "current_mirror" in types:
            return "current_mirror"
        if "inverter" in types:
            return "cmos_logic"
        return types[0]

    def topology_summary(self) -> str:
        """Return a one-block human-readable summary."""
        counts = self.transistors_by_type()
        rails = self.supply_rails()
        structs = self.known_structures()
        lines = [
            f"SpiceAnalyzer: {Path(self._path).name}",
            f"  transistors : {self.transistor_count()} "
            f"(pmos={counts.get('pmos', 0)}, nmos={counts.get('nmos', 0)})",
            f"  supply rails: {rails}",
            f"  classify    : {self.classify()}",
            f"  structures  : {len(structs)} identified",
        ]
        for s in structs[:6]:
            lines.append(f"    [{s.type}] {s.description[:70]}")
        return "\n".join(lines)


# ── Topology detectors ────────────────────────────────────────────────────────

def _find_current_mirrors(mosfets: List[_Mosfet]) -> List[StructureHit]:
    """
    Detect current mirror: two transistors of the same type where one has
    gate == drain (diode-connected reference) and the other has gate connected
    to that drain node.
    """
    results: List[StructureHit] = []
    # Find diode-connected transistors (gate == drain)
    diode_nodes: Dict[str, List[_Mosfet]] = defaultdict(list)
    for m in mosfets:
        if m.gate == m.drain:
            diode_nodes[m.drain].append(m)

    for ref_node, refs in diode_nodes.items():
        # Find mirrors: same type, gate == ref_node, gate != drain
        mirrors = [
            m for m in mosfets
            if m.gate == ref_node and m.drain != ref_node
            and m.is_pmos == refs[0].is_pmos
        ]
        if mirrors:
            mtype = "pmos" if refs[0].is_pmos else "nmos"
            all_devs = [r.name for r in refs] + [m.name for m in mirrors]
            results.append(StructureHit(
                type="current_mirror",
                devices=all_devs,
                nodes=[ref_node],
                description=f"{mtype} current mirror: ref={refs[0].name} "
                             f"mirrors={[m.name for m in mirrors[:3]]}",
            ))
    return results


def _find_diff_pairs(mosfets: List[_Mosfet]) -> List[StructureHit]:
    """
    Detect differential pair: two transistors of the same type with the same
    source node (tail current), different gate nodes (inputs), different drains.
    """
    results: List[StructureHit] = []
    # Group by (model_type, source_node)
    by_source: Dict[Tuple[str, str], List[_Mosfet]] = defaultdict(list)
    for m in mosfets:
        key = ("pmos" if m.is_pmos else "nmos", m.source)
        by_source[key].append(m)

    for (mtype, src), group in by_source.items():
        # Need at least 2 with different gates and different drains
        for i, ma in enumerate(group):
            for mb in group[i + 1:]:
                if ma.gate != mb.gate and ma.drain != mb.drain:
                    results.append(StructureHit(
                        type="diff_pair",
                        devices=[ma.name, mb.name],
                        nodes=[src, ma.gate, mb.gate, ma.drain, mb.drain],
                        description=f"{mtype} diff pair: tail={src} "
                                     f"inp={ma.gate}/{mb.gate}",
                    ))
    return results[:4]  # cap at 4 to avoid noise from wide arrays


def _find_lvds(
    mosfets: List[_Mosfet],
    resistors: List[_Resistor],
    supply_nodes: Dict[str, float],
) -> List[StructureHit]:
    """
    Detect LVDS: resistor of ~100Ω between two differential output nodes, combined
    with transistors driving those nodes from a common tail.
    """
    results: List[StructureHit] = []
    for r in resistors:
        if 80 <= r.value <= 120:
            results.append(StructureHit(
                type="lvds",
                devices=[r.name],
                nodes=[r.node_a, r.node_b],
                description=f"LVDS termination {r.value:.0f}Ω "
                             f"between {r.node_a}/{r.node_b}",
            ))
    return results


def _find_inverters(mosfets: List[_Mosfet]) -> List[StructureHit]:
    """
    Detect CMOS inverter: a PMOS and an NMOS with the same gate and same drain.
    """
    results: List[StructureHit] = []
    pmos_by_gate_drain: Dict[Tuple[str, str], List[_Mosfet]] = defaultdict(list)
    nmos_by_gate_drain: Dict[Tuple[str, str], List[_Mosfet]] = defaultdict(list)
    for m in mosfets:
        key = (m.gate, m.drain)
        if m.is_pmos:
            pmos_by_gate_drain[key].append(m)
        else:
            nmos_by_gate_drain[key].append(m)

    for key in pmos_by_gate_drain:
        if key in nmos_by_gate_drain:
            gate, drain = key
            p = pmos_by_gate_drain[key]
            n = nmos_by_gate_drain[key]
            results.append(StructureHit(
                type="inverter",
                devices=[p[0].name, n[0].name],
                nodes=[gate, drain],
                description=f"CMOS inverter: in={gate} out={drain}",
            ))
    return results[:8]  # cap to avoid listing every gate in a logic array


# ── SPICE parser ──────────────────────────────────────────────────────────────

def _parse_spice(
    text: str,
) -> Tuple[List[_Mosfet], List[_Resistor], Dict[str, float], Set[str]]:
    """Parse a flat SPICE netlist. Returns (mosfets, resistors, supply_nodes, gnd_nodes)."""
    mosfets: List[_Mosfet] = []
    resistors: List[_Resistor] = []
    supply_nodes: Dict[str, float] = {}
    gnd_nodes: Set[str] = set()

    # Continuation lines: SPICE joins lines ending with + prefix
    joined = _join_lines(text)

    for raw_line in joined.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("*") or line.startswith("."):
            continue

        tokens = line.split()
        if not tokens:
            continue
        inst = tokens[0].upper()

        # MOSFET: Mxxx drain gate source bulk MODEL [params]
        if inst.startswith("M") and len(tokens) >= 6:
            try:
                name, drain, gate, source, bulk, model = tokens[:6]
                w, l_nm = _parse_wl(tokens[6:])
                mosfets.append(_Mosfet(
                    name=name, drain=drain, gate=gate,
                    source=source, bulk=bulk,
                    model=_norm_model(model),
                    width_um=w, length_nm=l_nm,
                ))
            except (ValueError, IndexError):
                pass

        # Resistor: Rxxx node_a node_b value
        elif inst.startswith("R") and len(tokens) >= 4:
            try:
                val = _parse_value(tokens[3])
                resistors.append(_Resistor(
                    name=tokens[0], node_a=tokens[1],
                    node_b=tokens[2], value=val,
                ))
            except (ValueError, IndexError):
                pass

        # Voltage source: Vxxx node+ node- value  (DC only)
        elif inst.startswith("V") and len(tokens) >= 4:
            node_p = tokens[1]
            node_m = tokens[2]
            val_str = tokens[3]
            if val_str.replace(".", "").isdigit():
                try:
                    v = float(val_str)
                    if v == 0:
                        gnd_nodes.add(node_p)
                    else:
                        supply_nodes[node_p] = v
                except ValueError:
                    pass

    return mosfets, resistors, supply_nodes, gnd_nodes


def _join_lines(text: str) -> str:
    """Join SPICE continuation lines (lines starting with '+')."""
    lines = text.splitlines()
    out: List[str] = []
    for line in lines:
        if line.startswith("+"):
            if out:
                out[-1] = out[-1].rstrip() + " " + line[1:].lstrip()
            else:
                out.append(line[1:])
        else:
            out.append(line)
    return "\n".join(out)


_SI_PREFIXES = {"f": 1e-15, "p": 1e-12, "n": 1e-9, "u": 1e-6, "m": 1e-3,
                "k": 1e3, "meg": 1e6, "g": 1e9, "t": 1e12}


def _parse_value(s: str) -> float:
    """Parse a SPICE value string like '100' '2.5' '480n' '35.64u'."""
    s = s.lower().strip()
    for prefix, mult in sorted(_SI_PREFIXES.items(), key=lambda x: -len(x[0])):
        if s.endswith(prefix):
            return float(s[:-len(prefix)]) * mult
    return float(s)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _main() -> None:
    import sys
    if len(sys.argv) < 2:
        print("Usage: spice_analyzer.py <file.cir> [file.cir ...]")
        sys.exit(1)
    for arg in sys.argv[1:]:
        try:
            sa = SpiceAnalyzer.from_path(arg)
            print(sa.topology_summary())
            print()
            for s in sa.known_structures():
                print(f"  [{s.type}] devices={s.devices[:3]} nodes={s.nodes[:4]}")
        except (OSError, ValueError) as exc:
            print(f"ERROR {arg}: {exc}")
        print()


if __name__ == "__main__":
    _main()
