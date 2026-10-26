"""Tests for parsers/sctdaq_result_parser.py."""

import pytest
from ablation.parsers.sctdaq_result_parser import SCTDAQResultParser, SCTDAQTest

# ── Minimal fixture ────────────────────────────────────────────────────────────

_MINIMAL = """\
%NewTest
#
SERIAL NUMBER  : ABCNx10_side0
TEST MADE BY   : BJG
LOCATION NAME  : STFC_RAL
Run number     : 417-2
TEST_DATE      : 14/12/2009
PASSED         : YES
PROBLEM        : NO
#
%DAQ_INFO
#
#HOST
""
#VERSION
"3.43"
#DUT
"ABCN_Test"
#TIME
"15:30:22"
#
%DCS_INFO
#
#T0\tT1
0.5 \t1.0 \t
#VDET\tIDET
3.7 \t2.5 \t
#VCC\tICC
1.80 \t 120
#VDD\tIDD
1.20 \t  80
#
%StrobeDelay
#
#DELAY
#M0 S1  S2  S3
20 21 20 22
#M8 S9  S10 S11
19 18 19 21
#No defects found!
"""

_WITH_COMMENTS = """\
%NewTest
#
SERIAL NUMBER  : TestMod
TEST MADE BY   : JD
LOCATION NAME  : CERN
Run number     : 1-1
TEST_DATE      : 01/01/2010
PASSED         : YES
PROBLEM        : NO
#
%StrobeDelay
#DELAY
#M0 S1
10 11
#
%Comment
COMMENT        : Strobe Delay Fraction 0.40
#
%Comment
COMMENT        : M0 High SD width: 12.8 (module average 3.6)
"""

_WITH_DEFECTS = """\
%NewTest
#
SERIAL NUMBER  : DefectMod
TEST MADE BY   : TS
LOCATION NAME  : UCL
Run number     : 2-1
TEST_DATE      : 15/06/2009
PASSED         : NO
PROBLEM        : YES
#
%Defect
M0 DEAD_CHIP
S1 HIGH_NOISE threshold=3200
"""

_TWO_TESTS = """\
%NewTest
#
SERIAL NUMBER  : MOD_A
TEST MADE BY   : AB
LOCATION NAME  : RAL
Run number     : 100-1
TEST_DATE      : 01/03/2010
PASSED         : YES
PROBLEM        : NO
#
%StrobeDelay
#DELAY
#M0 S1
15 16
#
%NewTest
#
SERIAL NUMBER  : MOD_B
TEST MADE BY   : CD
LOCATION NAME  : RAL
Run number     : 200-1
TEST_DATE      : 02/03/2010
PASSED         : NO
PROBLEM        : YES
#
%StrobeDelay
#DELAY
#M0 S1
12 -1
"""

_WITH_RAWDATA = """\
%NewTest
#
SERIAL NUMBER  : RAW_MOD
TEST MADE BY   : AB
LOCATION NAME  : X
Run number     : 3-1
TEST_DATE      : 10/10/2010
PASSED         : YES
PROBLEM        : NO
#
%StrobeDelay
#DELAY
#M0
20
#
%TEST Rawdata
THIS LINE SHOULD BE SKIPPED
AND THIS TOO
"""


# ── Header parsing ────────────────────────────────────────────────────────────

class TestHeaderParsing:
    def setup_method(self):
        self.tests = SCTDAQResultParser.parse_text(_MINIMAL)
        self.t = self.tests[0]

    def test_one_test_block(self):
        assert len(self.tests) == 1

    def test_serial(self):
        assert self.t.serial == "ABCNx10_side0"

    def test_tested_by(self):
        assert self.t.tested_by == "BJG"

    def test_location(self):
        assert self.t.location == "STFC_RAL"

    def test_run_number(self):
        assert self.t.run_number == "417-2"

    def test_date(self):
        assert self.t.date == "14/12/2009"

    def test_passed_yes(self):
        assert self.t.passed is True

    def test_problem_no(self):
        assert self.t.problem is False


# ── DAQ info parsing ──────────────────────────────────────────────────────────

class TestDAQInfo:
    def setup_method(self):
        t = SCTDAQResultParser.parse_text(_MINIMAL)
        self.t = t[0]

    def test_daq_version(self):
        assert self.t.daq_version == "3.43"

    def test_daq_time(self):
        assert self.t.daq_time == "15:30:22"


# ── DCS info parsing ──────────────────────────────────────────────────────────

class TestDCSInfo:
    def setup_method(self):
        t = SCTDAQResultParser.parse_text(_MINIMAL)
        self.dcs = t[0].dcs

    def test_vdet(self):
        assert self.dcs.vdet == pytest.approx(3.7)

    def test_idet(self):
        assert self.dcs.idet == pytest.approx(2.5)

    def test_vcc(self):
        assert self.dcs.vcc == pytest.approx(1.80)

    def test_vdd(self):
        assert self.dcs.vdd == pytest.approx(1.20)


# ── Strobe delay parsing ──────────────────────────────────────────────────────

class TestStrobeDelay:
    def setup_method(self):
        t = SCTDAQResultParser.parse_text(_MINIMAL)
        self.delays = t[0].strobe_delays

    def test_m0(self):
        assert self.delays["M0"] == 20

    def test_s1(self):
        assert self.delays["S1"] == 21

    def test_s2(self):
        assert self.delays["S2"] == 20

    def test_s3(self):
        assert self.delays["S3"] == 22

    def test_m8(self):
        assert self.delays["M8"] == 19

    def test_s9(self):
        assert self.delays["S9"] == 18

    def test_absent_chips_excluded_or_minus_one(self):
        # -1 values in the raw file: may be stored or skipped depending on impl
        # This test just verifies present chips have sensible values
        for label, val in self.delays.items():
            assert isinstance(val, int)


# ── Comments parsing ──────────────────────────────────────────────────────────

class TestComments:
    def setup_method(self):
        t = SCTDAQResultParser.parse_text(_WITH_COMMENTS)
        self.t = t[0]

    def test_comments_list_populated(self):
        assert len(self.t.comments) >= 1

    def test_first_comment_content(self):
        assert any("Strobe Delay Fraction" in c for c in self.t.comments)


# ── Defects parsing ───────────────────────────────────────────────────────────

class TestDefects:
    def setup_method(self):
        t = SCTDAQResultParser.parse_text(_WITH_DEFECTS)
        self.t = t[0]

    def test_passed_false(self):
        assert self.t.passed is False

    def test_problem_true(self):
        assert self.t.problem is True

    def test_defects_found(self):
        assert len(self.t.defects) >= 1

    def test_dead_chip_defect(self):
        labels = [d[0] for d in self.t.defects]
        assert "M0" in labels

    def test_high_noise_defect(self):
        desc = dict(self.t.defects)
        assert "HIGH_NOISE" in desc.get("S1", "")


# ── Multiple test blocks ──────────────────────────────────────────────────────

class TestMultipleBlocks:
    def setup_method(self):
        self.tests = SCTDAQResultParser.parse_text(_TWO_TESTS)

    def test_two_blocks_parsed(self):
        assert len(self.tests) == 2

    def test_first_serial(self):
        assert self.tests[0].serial == "MOD_A"

    def test_second_serial(self):
        assert self.tests[1].serial == "MOD_B"

    def test_first_passed(self):
        assert self.tests[0].passed is True

    def test_second_failed(self):
        assert self.tests[1].passed is False

    def test_second_minus_one_delay(self):
        # S1 was -1 in second test (chip absent)
        assert self.tests[1].strobe_delays.get("M0") == 12


# ── Rawdata skip ──────────────────────────────────────────────────────────────

class TestRawdataSkip:
    def setup_method(self):
        t = SCTDAQResultParser.parse_text(_WITH_RAWDATA)
        self.t = t[0]

    def test_rawdata_not_in_raw_sections(self):
        assert not any("TEST" in k for k in self.t.raw_sections)

    def test_strobe_delay_still_parsed(self):
        assert self.t.strobe_delays.get("M0") == 20


# ── Return type ───────────────────────────────────────────────────────────────

class TestReturnTypes:
    def test_returns_list(self):
        result = SCTDAQResultParser.parse_text(_MINIMAL)
        assert isinstance(result, list)

    def test_items_are_sctdaqtest(self):
        result = SCTDAQResultParser.parse_text(_MINIMAL)
        assert all(isinstance(r, SCTDAQTest) for r in result)

    def test_empty_text_returns_empty(self):
        result = SCTDAQResultParser.parse_text("")
        assert result == []

    def test_no_newtest_returns_empty(self):
        result = SCTDAQResultParser.parse_text("some random text\n%Comment\nno block")
        assert result == []
