"""
parsers/sctdaq_result_parser.py — ATLAS SCTDAQ test result file parser.

Parses structured ASCII result files produced by SCTDAQ (the ATLAS SCT/ITk
strip detector DAQ software). Files contain one or more %NewTest blocks.

File structure:
  %NewTest            — start of a test block; header key:value pairs follow
  %DAQ_INFO           — DAQ host/version/DUT/time
  %DCS_INFO           — temperature, voltage, current readings
  %StrobeDelay        — per-chip optimal strobe delay in BCO cycles
  %SCAN_INFO          — scan configuration (only in full calibration runs)
  %ThreePointGain     — 3-point gain fit (only in full calibration runs)
  %Defect             — per-chip defect record (one per failed chip/channel)
  %Comment            — free-form comment line (COMMENT : <text>)
  %TEST Rawdata       — large raw hit-count table (last section, often MB-sized)

Lines beginning with '#' are field names or comments. Values follow on the
next non-empty, non-'#' line (or on the same line after the key).

Typical use:
    tests = SCTDAQResultParser.parse('/path/to/ABCNx10_side0_20091214.txt')
    for t in tests:
        print(t.serial, t.date, t.passed)
        print(t.strobe_delays)   # dict: chip_label -> optimal_delay (int)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class DCSReadings:
    """Detector Control System slow-control readings for one test."""
    t0:    float = 0.0   # temperature sensor 0 (°C)
    t1:    float = 0.0   # temperature sensor 1 (°C)
    vdet:  float = 0.0   # detector bias voltage (V)
    idet:  float = 0.0   # detector bias current (μA)
    vcc:   float = 0.0   # digital supply voltage (V)
    icc:   float = 0.0   # digital supply current (mA)
    vdd:   float = 0.0   # analog supply voltage (V)
    idd:   float = 0.0   # analog supply current (mA)


@dataclass
class SCTDAQTest:
    """One parsed test block from an SCTDAQ result file."""
    serial:        str  = ""          # module serial number
    tested_by:     str  = ""          # operator initials
    location:      str  = ""          # test site (e.g. STFC_RAL)
    run_number:    str  = ""          # run number string (e.g. "417-2")
    date:          str  = ""          # TEST_DATE (DD/MM/YYYY)
    passed:        bool = False
    problem:       bool = False
    daq_version:   str  = ""
    daq_time:      str  = ""
    dcs:           DCSReadings = field(default_factory=DCSReadings)

    # %StrobeDelay: chip_label → optimal BCO delay (-1 = chip absent)
    strobe_delays: Dict[str, int] = field(default_factory=dict)

    # %ThreePointGain: chip_label → gain value (float)
    gain:          Dict[str, float] = field(default_factory=dict)

    # %Defect: list of (chip_label, defect_description) tuples
    defects:       List[tuple] = field(default_factory=list)

    # %Comment: list of comment strings
    comments:      List[str] = field(default_factory=list)

    # scan type from %SCAN_INFO (if present)
    scan_type:     str = ""

    # raw section dict: section_name → list of content lines
    raw_sections:  Dict[str, List[str]] = field(default_factory=dict)


# ── Parser ─────────────────────────────────────────────────────────────────────

class SCTDAQResultParser:
    """Parse SCTDAQ ASCII result files into SCTDAQTest objects."""

    @classmethod
    def parse(cls, path: str | Path) -> List[SCTDAQTest]:
        """
        Parse a result file and return a list of SCTDAQTest objects.
        One object per %NewTest block. %TEST Rawdata sections are skipped
        (they can be MB-sized and contain redundant raw hit counts).
        """
        text = Path(path).read_text(errors="replace")
        return cls._split_and_parse(text)

    @classmethod
    def parse_text(cls, text: str) -> List[SCTDAQTest]:
        """Parse from a string directly (for testing)."""
        return cls._split_and_parse(text)

    # ── Internals ──────────────────────────────────────────────────────────────

    @classmethod
    def _split_and_parse(cls, text: str) -> List[SCTDAQTest]:
        results: List[SCTDAQTest] = []
        # Split on %NewTest (keep the delimiter in subsequent chunks)
        blocks = re.split(r'(?=^%NewTest)', text, flags=re.MULTILINE)
        for block in blocks:
            block = block.strip()
            if not block.startswith("%NewTest"):
                continue
            results.append(cls._parse_block(block))
        return results

    @classmethod
    def _parse_block(cls, block: str) -> SCTDAQTest:
        test = SCTDAQTest()
        lines = block.splitlines()

        # Split into sections at every %SectionName line.
        # Repeated section names (e.g. multiple %Comment blocks) get a numeric
        # suffix: "Comment", "Comment_1", "Comment_2", ... so no block is lost.
        sections: Dict[str, List[str]] = {}
        section_counts: Dict[str, int] = {}
        current_section = "NewTest"
        current_lines: List[str] = []

        def _flush(name: str, body: List[str]) -> None:
            if name == "__SKIP__":
                return
            if not any(line.strip() for line in body):
                return  # skip empty sections (e.g. the pre-first-% initial state)
            if name in sections:
                section_counts[name] = section_counts.get(name, 1) + 1
                name = f"{name}_{section_counts[name]}"
            sections[name] = body

        for line in lines:
            if line.startswith("%"):
                _flush(current_section, current_lines)
                current_section = line[1:].strip()
                current_lines = []
                if current_section.startswith("TEST "):
                    current_section = "__SKIP__"
            else:
                if current_section != "__SKIP__":
                    current_lines.append(line)
        _flush(current_section, current_lines)
        test.raw_sections = {k: v for k, v in sections.items() if not k.startswith("__")}

        # Parse each known section
        cls._parse_newtest_header(test, sections.get("NewTest", []))
        cls._parse_daq_info(test, sections.get("DAQ_INFO", []))
        cls._parse_dcs_info(test, sections.get("DCS_INFO", []))
        cls._parse_strobe_delay(test, sections.get("StrobeDelay", []))
        cls._parse_scan_info(test, sections.get("SCAN_INFO", []))
        cls._parse_three_point_gain(test, sections.get("ThreePointGain", []))
        cls._parse_defects(test, sections)
        cls._parse_comments(test, sections)
        return test

    @staticmethod
    def _kv_pairs(lines: List[str]) -> Dict[str, str]:
        """Extract KEY : VALUE or KEY\nVALUE pairs from section lines."""
        result: Dict[str, str] = {}
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line or line.startswith("#"):
                i += 1
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                result[key.strip()] = val.strip()
            i += 1
        return result

    @classmethod
    def _parse_newtest_header(cls, test: SCTDAQTest, lines: List[str]) -> None:
        kv = cls._kv_pairs(lines)
        test.serial     = kv.get("SERIAL NUMBER", "")
        test.tested_by  = kv.get("TEST MADE BY", "")
        test.location   = kv.get("LOCATION NAME", "")
        test.run_number = kv.get("Run number", "")
        test.date       = kv.get("TEST_DATE", "")
        test.passed     = kv.get("PASSED", "NO").upper() == "YES"
        test.problem    = kv.get("PROBLEM", "NO").upper() == "YES"

    @classmethod
    def _parse_daq_info(cls, test: SCTDAQTest, lines: List[str]) -> None:
        # VERSION and TIME follow "#VERSION" / "#TIME" markers as quoted strings
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == "#VERSION" and i + 1 < len(lines):
                test.daq_version = lines[i + 1].strip().strip('"')
            elif stripped == "#TIME" and i + 1 < len(lines):
                test.daq_time = lines[i + 1].strip().strip('"')

    @classmethod
    def _parse_dcs_info(cls, test: SCTDAQTest, lines: List[str]) -> None:
        dcs = test.dcs
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#") and i + 1 < len(lines):
                key = stripped.lstrip("#").strip()
                val_line = lines[i + 1].strip()
                vals = val_line.split()
                try:
                    if key == "T0\tT1" or key == "T0 T1":
                        if len(vals) >= 2:
                            dcs.t0, dcs.t1 = float(vals[0]), float(vals[1])
                    elif key == "VDET\tIDET" or key == "VDET IDET":
                        if len(vals) >= 2:
                            dcs.vdet, dcs.idet = float(vals[0]), float(vals[1])
                    elif key == "VCC\tICC" or key == "VCC ICC":
                        if len(vals) >= 2:
                            dcs.vcc, dcs.icc = float(vals[0]), float(vals[1])
                    elif key == "VDD\tIDD" or key == "VDD IDD":
                        if len(vals) >= 2:
                            dcs.vdd, dcs.idd = float(vals[0]), float(vals[1])
                except (ValueError, IndexError):
                    pass

    @classmethod
    def _parse_strobe_delay(cls, test: SCTDAQTest, lines: List[str]) -> None:
        """
        Parse the strobe delay section. Format:
            #DELAY
            #M0 S1  S2  S3  S4  E5
            20 21 20 22 20 -1 -1 -1 -1 -1
            #M8 S9  S10 S11 S12 E13
            19 18 19 21 18 21 18 19 21 18
        """
        current_labels: List[str] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            if line.startswith("#M") or line.startswith("#E") or line.startswith("#S"):
                # Chip label line: "#M0 S1 S2 S3 ..."
                current_labels = re.findall(r'[MES]\d+', line)
            elif current_labels and not line.startswith("#"):
                # Delay values — one per label; may be more values than labels (padding)
                vals = line.split()
                for label, val_str in zip(current_labels, vals):
                    try:
                        test.strobe_delays[label] = int(val_str)
                    except ValueError:
                        pass
                current_labels = []
            i += 1

    @classmethod
    def _parse_scan_info(cls, test: SCTDAQTest, lines: List[str]) -> None:
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("SCAN_TYPE") or "SCAN_TYPE" in stripped:
                _, _, val = stripped.partition(":")
                test.scan_type = val.strip()
                break

    @classmethod
    def _parse_three_point_gain(cls, test: SCTDAQTest, lines: List[str]) -> None:
        """
        Parse ThreePointGain: '#M0 S1 S2 ...' then values line.
        Values can be gain floats or '-1' for absent chips.
        """
        current_labels: List[str] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#M") or stripped.startswith("#E") or stripped.startswith("#S"):
                current_labels = re.findall(r'[MES]\d+', stripped)
            elif current_labels and not stripped.startswith("#"):
                vals = stripped.split()
                for label, val_str in zip(current_labels, vals):
                    try:
                        v = float(val_str)
                        if v >= 0:
                            test.gain[label] = v
                    except ValueError:
                        pass
                current_labels = []

    @classmethod
    def _parse_defects(cls, test: SCTDAQTest, sections: Dict[str, List[str]]) -> None:
        for sec_name, lines in sections.items():
            if sec_name.startswith("Defect"):
                for line in lines:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        # Format: CHIP_LABEL DEFECT_TYPE [details]
                        parts = stripped.split(None, 1)
                        if len(parts) == 2:
                            test.defects.append((parts[0], parts[1]))
                        elif parts:
                            test.defects.append((parts[0], ""))

    @classmethod
    def _parse_comments(cls, test: SCTDAQTest, sections: Dict[str, List[str]]) -> None:
        for sec_name, lines in sections.items():
            if sec_name.startswith("Comment"):
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("COMMENT"):
                        _, _, val = stripped.partition(":")
                        test.comments.append(val.strip())
