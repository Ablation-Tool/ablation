"""
Tests for HDLVersionDiff and the VerilogSemantic VHDL signal extractor.

Key regression: single-bit std_logic signals were previously invisible
because _VH_WIDTH_RE only matched std_logic_vector. Both the extraction
(VerilogSemantic) and the diff (HDLVersionDiff) must handle them.
"""

import tempfile
import os
import pytest

from ablation.analyzers.verilog_semantic import VerilogSemantic
from ablation.analyzers.hdl_version_diff import HDLVersionDiff


# ── VerilogSemantic: std_logic signal extraction ──────────────────────────────

VHDL_SINGLE_BIT = """\
architecture rtl of uut is
  signal my_flag   : std_logic;
  signal my_vec    : std_logic_vector(3 downto 0);
  signal my_enable : std_logic;
begin
end architecture rtl;
"""

VHDL_NO_SIGNALS = """\
architecture rtl of uut is
begin
end architecture rtl;
"""


def _write_dir(tmp_path: str, files: dict) -> str:
    for name, content in files.items():
        path = os.path.join(tmp_path, name)
        with open(path, "w") as f:
            f.write(content)
    return tmp_path


def test_std_logic_signal_extracted():
    """std_logic signals must appear in port_widths() with width=1."""
    with tempfile.TemporaryDirectory() as tmp:
        _write_dir(tmp, {"uut.vhd": VHDL_SINGLE_BIT})
        vs = VerilogSemantic.from_directory(tmp)
        pw = vs.port_widths()
        assert "my_flag" in pw, "std_logic signal my_flag not extracted"
        assert pw["my_flag"] == 1
        assert "my_enable" in pw, "std_logic signal my_enable not extracted"
        assert pw["my_enable"] == 1


def test_std_logic_vector_still_extracted():
    """std_logic_vector signals must still work after the fix."""
    with tempfile.TemporaryDirectory() as tmp:
        _write_dir(tmp, {"uut.vhd": VHDL_SINGLE_BIT})
        vs = VerilogSemantic.from_directory(tmp)
        pw = vs.port_widths()
        assert "my_vec" in pw
        assert pw["my_vec"] == 4  # (3 downto 0) = 4 bits


def test_std_logic_not_matched_as_std_logic_vector():
    """std_logic_vector must not produce width=1 (they're separate patterns)."""
    with tempfile.TemporaryDirectory() as tmp:
        _write_dir(tmp, {"uut.vhd": VHDL_SINGLE_BIT})
        vs = VerilogSemantic.from_directory(tmp)
        pw = vs.port_widths()
        # my_vec is 4-bit, not 1-bit
        assert pw.get("my_vec") == 4


# ── HDLVersionDiff: detects added std_logic signal between versions ───────────

VHDL_V1 = """\
architecture rtl of uut is
  signal data_out : std_logic_vector(7 downto 0);
begin
end architecture rtl;
"""

VHDL_V2 = """\
architecture rtl of uut is
  signal data_out    : std_logic_vector(7 downto 0);
  signal enable_new  : std_logic;
begin
end architecture rtl;
"""


def test_hdlversiondiff_detects_added_std_logic():
    """Adding a std_logic signal must appear as an added signal in the diff."""
    with tempfile.TemporaryDirectory() as v1, tempfile.TemporaryDirectory() as v2:
        _write_dir(v1, {"uut.vhd": VHDL_V1})
        _write_dir(v2, {"uut.vhd": VHDL_V2})
        diff = HDLVersionDiff.from_directories(v1, v2, "v1", "v2")
        assert not diff.is_empty()
        added = diff.added_signals()
        assert "enable_new" in added, (
            "enable_new (std_logic) not detected as added signal — "
            "regression: single-bit signals were invisible before the fix"
        )
        assert added["enable_new"] == 1


def test_hdlversiondiff_stable_std_logic_no_change():
    """std_logic signal present in both versions must not show as a change."""
    VHDL_BOTH = """\
architecture rtl of uut is
  signal clk_en : std_logic;
begin
end architecture rtl;
"""
    with tempfile.TemporaryDirectory() as v1, tempfile.TemporaryDirectory() as v2:
        _write_dir(v1, {"uut.vhd": VHDL_BOTH})
        _write_dir(v2, {"uut.vhd": VHDL_BOTH})
        diff = HDLVersionDiff.from_directories(v1, v2, "v1", "v2")
        assert diff.is_empty(), "Identical std_logic signals must produce empty diff"


def test_hdlversiondiff_bcc_regression():
    """
    Regression against the actual BCC v0.8→v0.9 case:
    abcn_bco2x_en is a std_logic signal added in v0.9.
    Must appear as an added signal, not be invisible.
    """
    BCC_V8 = """\
architecture rtl of bcc_control is
  signal constdata_mode : std_logic;
  signal col_data       : std_logic_vector(1 downto 0);
begin
end architecture rtl;
"""
    BCC_V9 = """\
architecture rtl of bcc_control is
  signal abcn_bco2x_en  : std_logic;
  signal constdata_mode : std_logic;
  signal col_data       : std_logic_vector(1 downto 0);
begin
end architecture rtl;
"""
    with tempfile.TemporaryDirectory() as v8, tempfile.TemporaryDirectory() as v9:
        _write_dir(v8, {"bcc_control_rtl.vhd": BCC_V8})
        _write_dir(v9, {"bcc_control_rtl.vhd": BCC_V9})
        diff = HDLVersionDiff.from_directories(v8, v9, "v0.8", "v0.9")
        added = diff.added_signals()
        assert "abcn_bco2x_en" in added, (
            "abcn_bco2x_en must be detected — this was the original missed signal"
        )
        assert added["abcn_bco2x_en"] == 1
        assert "constdata_mode" not in added, "constdata_mode was in both versions"
        assert "col_data" not in added, "col_data was in both versions"
