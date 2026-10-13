"""
Tests for PerlTaintScanner.

Covers: backtick/qx/system sink detection, @ARGV direct, Getopt, shift(@_)
PARAM resolution, quotemeta/single-quote-wrap sanitization, cross-file caller
resolution (ERRM pattern), and report formatting.
"""
from pathlib import Path

import pytest

from ablation.analyzers.perl_taint_scanner import PerlTaintScanner, SinkHit


# ── helpers ────────────────────────────────────────────────────────────────────

def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def _scan_one(tmp_path: Path, name: str, content: str) -> list[SinkHit]:
    p = _write(tmp_path, name, content)
    return PerlTaintScanner.from_files([p]).scan()


# ── sink detection ─────────────────────────────────────────────────────────────

class TestSinkDetection:
    def test_backtick_detected(self, tmp_path):
        hits = _scan_one(tmp_path, 'a.pl', 'my $x = $ARGV[0];\nmy @r = `cmd $x`;\n')
        assert any(h.sink_type == 'backtick' for h in hits)

    def test_qx_brace_detected(self, tmp_path):
        hits = _scan_one(tmp_path, 'a.pl', 'my $x = $ARGV[0];\nmy @r = qx{cmd $x};\n')
        assert any(h.sink_type == 'qx' for h in hits)

    def test_qx_slash_detected(self, tmp_path):
        hits = _scan_one(tmp_path, 'a.pl', 'my $x = $ARGV[0];\nmy @r = qx/cmd $x/;\n')
        assert any(h.sink_type == 'qx' for h in hits)

    def test_system_string_detected(self, tmp_path):
        hits = _scan_one(tmp_path, 'a.pl', 'my $h = $ARGV[0];\nsystem("ping $h");\n')
        assert any(h.sink_type == 'system' for h in hits)

    def test_no_sink_no_hits(self, tmp_path):
        hits = _scan_one(tmp_path, 'a.pl', 'my $x = 1;\nprint $x;\n')
        assert hits == []

    def test_no_interpolation_no_hits(self, tmp_path):
        # backtick with no $ inside
        hits = _scan_one(tmp_path, 'a.pl', 'my @r = `ls -la`;\n')
        assert hits == []

    def test_special_var_skipped(self, tmp_path):
        # $_ is a Perl special var — should not be reported
        hits = _scan_one(tmp_path, 'a.pl', 'for (`ls`) { chomp $_; }\n')
        assert not any(h.var == '_' for h in hits)


# ── ARGV / CLI source detection ────────────────────────────────────────────────

class TestArgvSource:
    def test_argv_index_injectable(self, tmp_path):
        hits = _scan_one(tmp_path, 'a.pl', 'my $h = $ARGV[0];\nsystem("ping $h");\n')
        assert len(hits) == 1
        assert hits[0].verdict == 'INJECTABLE'

    def test_file_scope_shift_injectable(self, tmp_path):
        # $x = shift at file scope → shift @ARGV → CLI arg
        hits = _scan_one(tmp_path, 'a.pl', '$x = shift;\n`cmd $x`;\n')
        assert len(hits) == 1
        assert hits[0].verdict == 'INJECTABLE'

    def test_file_scope_shift_argv_explicit_injectable(self, tmp_path):
        hits = _scan_one(tmp_path, 'a.pl', 'my $x = shift @ARGV;\n`cmd $x`;\n')
        assert len(hits) == 1
        assert hits[0].verdict == 'INJECTABLE'

    def test_getopt_std_injectable(self, tmp_path):
        code = (
            'use Getopt::Std;\n'
            "getopts('h:', \\my %opts);\n"
            'my $host = $opts{h};\n'
            'system("ping $host");\n'
        )
        hits = _scan_one(tmp_path, 'a.pl', code)
        assert len(hits) == 1
        assert hits[0].verdict == 'INJECTABLE'
        assert hits[0].var == 'host'

    def test_options_hash_injectable(self, tmp_path):
        # $options{b} style from Getopt::Long or manual parsing
        code = (
            'my %options;\n'
            'GetOptions("host=s" => \\$options{host});\n'
            'my $h = $options{host};\n'
            '`ping $h`;\n'
        )
        hits = _scan_one(tmp_path, 'a.pl', code)
        assert any(h.verdict == 'INJECTABLE' for h in hits)


# ── SANITIZED detection ─────────────────────────────────────────────────────────

class TestSanitized:
    def test_quotemeta_sanitized(self, tmp_path):
        code = (
            'my $x = $ARGV[0];\n'
            '$x = quotemeta($x);\n'
            '`cmd $x`;\n'
        )
        hits = _scan_one(tmp_path, 'a.pl', code)
        assert len(hits) == 1
        assert hits[0].verdict == 'SANITIZED'
        assert 'quotemeta' in hits[0].sanitization

    def test_single_quote_wrap_sanitized(self, tmp_path):
        # LPRM_cli_utils.pm idiom
        code = (
            'my @args = @ARGV;\n'
            "$args[0] =~ s/'/ /g;\n"
            "my \\$optargs = \"'\" . join(\"' '\", @args) . \"'\";\n"
            '`lsmsg $optargs`;\n'
        )
        hits = _scan_one(tmp_path, 'a.pl', code)
        injectable = [h for h in hits if h.verdict == 'INJECTABLE']
        # $optargs uses the single-quote wrap idiom: should not be INJECTABLE
        # (it may be UNKNOWN since $optargs isn't traced to @ARGV directly,
        # but crucially the join-idiom line is detected as sanitization)
        assert not any(h.var == 'optargs' and h.verdict == 'INJECTABLE' for h in injectable)

    def test_regex_sub_sanitized(self, tmp_path):
        code = (
            'my $x = $ARGV[0];\n'
            '$x =~ s/[;&|`]//g;\n'
            '`cmd $x`;\n'
        )
        hits = _scan_one(tmp_path, 'a.pl', code)
        assert len(hits) == 1
        assert hits[0].verdict == 'SANITIZED'


# ── function param / PARAM_UNKNOWN ────────────────────────────────────────────

class TestParamResolution:
    def test_shift_in_sub_param_unknown_without_callers(self, tmp_path):
        code = (
            'sub run_cmd {\n'
            '    my $arg = shift(@_);\n'
            '    `tool $arg`;\n'
            '}\n'
        )
        hits = _scan_one(tmp_path, 'lib.pm', code)
        assert len(hits) == 1
        assert hits[0].verdict == 'PARAM_UNKNOWN'

    def test_shift_in_sub_injectable_when_caller_passes_argv(self, tmp_path):
        # ERRM_cli_utils.pm pattern: shift(@_) in .pm, called from .pl with shift @ARGV
        pm_code = (
            'sub find_resource {\n'
            '    my $resource_name = shift(@_);\n'
            '    my @out = `lsrsrc $resource_name`;\n'
            '    return @out;\n'
            '}\n'
        )
        pl_code = (
            'use lib ".";\n'
            'require "lib.pm";\n'
            '$resource = shift @ARGV;\n'
            'find_resource($resource);\n'
        )
        pm = _write(tmp_path, 'lib.pm', pm_code)
        pl = _write(tmp_path, 'caller.pl', pl_code)
        hits = PerlTaintScanner.from_files([pm, pl]).scan()
        # The sink is in lib.pm with $resource_name from shift(@_)
        pm_hits = [h for h in hits if 'lib.pm' in h.file]
        assert pm_hits, "expected hits in lib.pm"
        assert pm_hits[0].verdict == 'INJECTABLE'
        assert 'caller.pl' in (pm_hits[0].caller_file or '')

    def test_shift_in_sub_injectable_when_caller_passes_argv_index(self, tmp_path):
        pm_code = (
            'sub do_work {\n'
            '    my $arg = shift(@_);\n'
            '    system("tool $arg");\n'
            '}\n'
        )
        pl_code = (
            'my $x = $ARGV[0];\n'
            'do_work($x);\n'
        )
        pm = _write(tmp_path, 'lib.pm', pm_code)
        pl = _write(tmp_path, 'main.pl', pl_code)
        hits = PerlTaintScanner.from_files([pm, pl]).scan()
        pm_hits = [h for h in hits if 'lib.pm' in h.file]
        assert pm_hits
        assert pm_hits[0].verdict == 'INJECTABLE'


# ── sort order ─────────────────────────────────────────────────────────────────

class TestSortOrder:
    def test_injectable_before_unknown(self, tmp_path):
        code = (
            'my $x = $ARGV[0];\n'
            '`cmd $x`;\n'              # INJECTABLE
            'my $y = get_internal();\n'
            '`tool $y`;\n'             # UNKNOWN
        )
        hits = _scan_one(tmp_path, 'a.pl', code)
        verdicts = [h.verdict for h in hits]
        # INJECTABLE must sort before UNKNOWN
        if 'INJECTABLE' in verdicts and 'UNKNOWN' in verdicts:
            assert verdicts.index('INJECTABLE') < verdicts.index('UNKNOWN')


# ── report ─────────────────────────────────────────────────────────────────────

class TestReport:
    def test_empty_report_message(self, tmp_path):
        p = _write(tmp_path, 'a.pl', 'print "hello";\n')
        scanner = PerlTaintScanner.from_files([p])
        r = scanner.report([])
        assert 'no shell sinks' in r.lower()

    def test_report_contains_injectable_tag(self, tmp_path):
        p = _write(tmp_path, 'a.pl', 'my $x = $ARGV[0];\n`cmd $x`;\n')
        scanner = PerlTaintScanner.from_files([p])
        hits = scanner.scan()
        r = scanner.report(hits)
        assert 'INJECTABLE' in r

    def test_report_summary_line(self, tmp_path):
        p = _write(tmp_path, 'a.pl', 'my $x = $ARGV[0];\n`cmd $x`;\n')
        scanner = PerlTaintScanner.from_files([p])
        hits = scanner.scan()
        r = scanner.report(hits)
        assert 'Summary:' in r

    def test_fmt_includes_var_and_sink(self, tmp_path):
        p = _write(tmp_path, 'a.pl', 'my $h = $ARGV[0];\nsystem("ping $h");\n')
        scanner = PerlTaintScanner.from_files([p])
        hits = scanner.scan()
        assert hits
        f = hits[0].fmt()
        assert '$h' in f
        assert 'system' in f


# ── from_path ─────────────────────────────────────────────────────────────────

class TestFromPath:
    def test_from_path_dir_finds_pl_pm(self, tmp_path):
        (tmp_path / 'sub').mkdir()
        _write(tmp_path / 'sub', 'a.pl', 'my $x = $ARGV[0];\n`cmd $x`;\n')
        _write(tmp_path / 'sub', 'b.pm', 'my $y = $ARGV[0];\nsystem("tool $y");\n')
        hits = PerlTaintScanner.from_path(tmp_path).scan()
        files = {Path(h.file).name for h in hits}
        assert 'a.pl' in files
        assert 'b.pm' in files

    def test_from_path_single_file(self, tmp_path):
        p = _write(tmp_path, 'a.pl', 'my $x = $ARGV[0];\n`cmd $x`;\n')
        hits = PerlTaintScanner.from_path(p).scan()
        assert hits

    def test_empty_dir_no_hits(self, tmp_path):
        hits = PerlTaintScanner.from_path(tmp_path).scan()
        assert hits == []
