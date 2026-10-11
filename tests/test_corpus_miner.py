"""
Tests for sweeps/corpus_miner.py — FindingCorpusMiner.

Tests use synthetic RE module files written to tmp_path, not the real re/ directory.
"""
import textwrap
from pathlib import Path

import pytest

from sweeps.corpus_miner import (
    FindingCorpusMiner,
    CorpusEntry,
    CoverageGap,
    CrossTargetPattern,
    _normalize_cwe,
    _infer_cwe_from_title,
    _vendor_from_path,
    _extract_file,
)


# ── _normalize_cwe ────────────────────────────────────────────────────────────

class TestNormalizeCwe:
    def test_standard_string(self):
        assert _normalize_cwe('CWE-78') == ('CWE-78', False)

    def test_case_insensitive(self):
        assert _normalize_cwe('cwe-78') == ('CWE-78', False)

    def test_bare_integer_string(self):
        assert _normalize_cwe('121') == ('CWE-121', False)

    def test_integer(self):
        assert _normalize_cwe(78) == ('CWE-78', False)

    def test_list_takes_first(self):
        assert _normalize_cwe(['CWE-78', 'CWE-77']) == ('CWE-78', False)

    def test_none_returns_unknown(self):
        assert _normalize_cwe(None) == ('unknown', False)

    def test_empty_list(self):
        assert _normalize_cwe([]) == ('unknown', False)

    def test_no_cwe_prefix_in_string(self):
        cwe, inferred = _normalize_cwe('OS Command Injection')
        assert cwe == 'unknown'


# ── _infer_cwe_from_title ─────────────────────────────────────────────────────

class TestInferCweFromTitle:
    def test_sql_injection(self):
        assert _infer_cwe_from_title('SQL injection in login form') == 'CWE-89'

    def test_command_injection(self):
        assert _infer_cwe_from_title('OS command injection via system()') == 'CWE-78'

    def test_hardcoded_key(self):
        assert _infer_cwe_from_title('Hardcoded secret key in settings.py') == 'CWE-321'

    def test_cert_bypass(self):
        assert _infer_cwe_from_title('TLS cert bypass — VerifyServerCertificate is a no-op') == 'CWE-295'

    def test_heap_overflow(self):
        assert _infer_cwe_from_title('Heap overflow in RADIUS parser') == 'CWE-122'

    def test_path_traversal(self):
        assert _infer_cwe_from_title('path traversal via unvalidated filter arg') == 'CWE-22'

    def test_cleartext(self):
        assert _infer_cwe_from_title('HTTPS→Telnet cleartext credential fallback') == 'CWE-319'

    def test_no_match_returns_unknown(self):
        assert _infer_cwe_from_title('Miscellaneous optimization issue') == 'unknown'

    def test_xss(self):
        assert _infer_cwe_from_title('XSS via unsanitized HTML in chat message') == 'CWE-79'


# ── _vendor_from_path ─────────────────────────────────────────────────────────

class TestVendorFromPath:
    def test_flat_vendor(self):
        p = Path('/home/cowboy/ablation/re/fortinet/fortianalyzer_re.py')
        assert _vendor_from_path(p) == 'fortinet'

    def test_nested_vendor(self):
        p = Path('/home/cowboy/ablation/re/auo/v15315/combus_re.py')
        assert _vendor_from_path(p) == 'auo'

    def test_single_level(self):
        p = Path('/home/cowboy/ablation/re/ibm/ibm_fctool_re.py')
        assert _vendor_from_path(p) == 'ibm'


# ── _extract_file ─────────────────────────────────────────────────────────────

def _write_re_module(tmp_path: Path, filename: str, content: str) -> Path:
    f = tmp_path / filename
    f.write_text(textwrap.dedent(content))
    return f


class TestExtractFile:
    def test_extracts_confirmed_finding(self, tmp_path):
        f = _write_re_module(tmp_path, 'test_re.py', """
            FINDINGS = {
                'FOO-001': {
                    'status': 'CONFIRMED',
                    'severity': 'HIGH',
                    'cwe': 'CWE-78',
                    'title': 'Command injection in handler',
                },
            }
        """)
        entries = _extract_file(f)
        assert len(entries) == 1
        e = entries[0]
        assert e.finding_id == 'FOO-001'
        assert e.cwe == 'CWE-78'
        assert e.severity == 'HIGH'
        assert e.cwe_inferred is False

    def test_skips_plausible(self, tmp_path):
        f = _write_re_module(tmp_path, 'test_re.py', """
            FINDINGS = {
                'FOO-001': {
                    'status': 'PLAUSIBLE',
                    'severity': 'HIGH',
                    'cwe': 'CWE-78',
                    'title': 'Maybe an issue',
                },
            }
        """)
        entries = _extract_file(f)
        assert entries == []

    def test_skips_eliminated(self, tmp_path):
        f = _write_re_module(tmp_path, 'test_re.py', """
            FINDINGS = {
                'FOO-001': {
                    'status': 'ELIMINATED',
                    'severity': 'HIGH',
                    'cwe': 'CWE-78',
                    'title': 'False positive',
                },
            }
        """)
        entries = _extract_file(f)
        assert entries == []

    def test_infers_cwe_from_title_when_missing(self, tmp_path):
        f = _write_re_module(tmp_path, 'test_re.py', """
            FINDINGS = {
                'BAR-001': {
                    'status': 'CONFIRMED',
                    'severity': 'CRITICAL',
                    'title': 'Hardcoded secret key in settings.py',
                },
            }
        """)
        entries = _extract_file(f)
        assert len(entries) == 1
        assert entries[0].cwe == 'CWE-321'
        assert entries[0].cwe_inferred is True

    def test_handles_list_cwe(self, tmp_path):
        f = _write_re_module(tmp_path, 'test_re.py', """
            FINDINGS = {
                'BAZ-001': {
                    'status': 'CONFIRMED',
                    'severity': 'HIGH',
                    'cwe': ['CWE-78', 'CWE-77'],
                    'title': 'Multi-CWE finding',
                },
            }
        """)
        entries = _extract_file(f)
        assert entries[0].cwe == 'CWE-78'

    def test_multiple_findings(self, tmp_path):
        f = _write_re_module(tmp_path, 'test_re.py', """
            FINDINGS = {
                'X-001': {'status': 'CONFIRMED', 'severity': 'HIGH', 'cwe': 'CWE-78', 'title': 'a'},
                'X-002': {'status': 'CONFIRMED', 'severity': 'MEDIUM', 'cwe': 'CWE-89', 'title': 'b'},
                'X-003': {'status': 'ELIMINATED', 'severity': 'HIGH', 'cwe': 'CWE-78', 'title': 'c'},
            }
        """)
        entries = _extract_file(f)
        assert len(entries) == 2
        assert {e.finding_id for e in entries} == {'X-001', 'X-002'}

    def test_vendor_from_path_parts(self, tmp_path):
        # Create path under a re/fortinet/ structure
        vendor_dir = tmp_path / 're' / 'fortinet'
        vendor_dir.mkdir(parents=True)
        f = vendor_dir / 'test_re.py'
        f.write_text(textwrap.dedent("""
            FINDINGS = {
                'F-001': {'status': 'CONFIRMED', 'severity': 'HIGH', 'cwe': 'CWE-78', 'title': 'x'},
            }
        """))
        entries = _extract_file(f)
        assert entries[0].vendor == 'fortinet'

    def test_syntax_error_returns_empty(self, tmp_path):
        f = tmp_path / 'bad_re.py'
        f.write_text('def broken(:\n    pass\n')
        entries = _extract_file(f)
        assert entries == []


# ── FindingCorpusMiner (integration) ─────────────────────────────────────────

def _build_test_corpus(tmp_path: Path) -> Path:
    """Build a minimal synthetic re/ directory with multiple vendors.

    Uses one file per (vendor, cwe) pair to avoid same-file overwrite.
    """
    specs = [
        ('vendorA', 'CWE-295', 'HIGH'),
        ('vendorA', 'CWE-295', 'CRITICAL'),
        ('vendorB', 'CWE-295', 'HIGH'),
        ('vendorC', 'CWE-295', 'HIGH'),
        ('vendorA', 'CWE-78',  'HIGH'),
        ('vendorB', 'CWE-78',  'CRITICAL'),
    ]
    # Group by (vendor, cwe) so multiple findings for same vendor+cwe go in one dict
    from collections import defaultdict
    grouped = defaultdict(list)
    for vendor, cwe, sev in specs:
        grouped[(vendor, cwe)].append(sev)

    for (vendor, cwe), sevs in grouped.items():
        d = tmp_path / 're' / vendor
        d.mkdir(parents=True, exist_ok=True)
        entries = {}
        for i, sev in enumerate(sevs):
            fid = f'{vendor.upper()}-{i+1:03d}-{cwe.replace("-","")}'
            entries[fid] = {
                'status': 'CONFIRMED', 'severity': sev,
                'cwe': cwe, 'title': f'{cwe} finding in {vendor}',
            }
        lines = ['FINDINGS = {']
        for fid, fdata in entries.items():
            lines.append(f"    {fid!r}: {fdata!r},")
        lines.append('}')
        filename = f'{vendor}_{cwe.replace("-","_")}_re.py'
        (d / filename).write_text('\n'.join(lines))
    return tmp_path / 're'


class TestFindingCorpusMiner:
    def test_extract_finds_all_confirmed(self, tmp_path):
        re_dir = _build_test_corpus(tmp_path)
        miner = FindingCorpusMiner(re_dir=re_dir)
        entries = miner.extract()
        # 4 CWE-295 + 2 CWE-78 = 6
        assert len(entries) == 6

    def test_coverage_gaps_identifies_unscanned(self, tmp_path):
        re_dir = _build_test_corpus(tmp_path)
        entries = FindingCorpusMiner(re_dir=re_dir).extract()
        gaps = FindingCorpusMiner.coverage_gaps(entries, min_count=2)
        gap_cwes = {g.cwe for g in gaps}
        # CWE-295 has no scanner; CWE-78 is covered
        assert 'CWE-295' in gap_cwes

    def test_coverage_gaps_marks_covered(self, tmp_path):
        re_dir = _build_test_corpus(tmp_path)
        entries = FindingCorpusMiner(re_dir=re_dir).extract()
        gaps = FindingCorpusMiner.coverage_gaps(entries, min_count=2)
        covered = [g for g in gaps if g.scanner is not None]
        cwe78 = next((g for g in covered if g.cwe == 'CWE-78'), None)
        assert cwe78 is not None

    def test_cross_target_patterns_finds_multivendor(self, tmp_path):
        re_dir = _build_test_corpus(tmp_path)
        entries = FindingCorpusMiner(re_dir=re_dir).extract()
        patterns = FindingCorpusMiner.cross_target_patterns(entries, min_vendors=2)
        cwe295 = next((p for p in patterns if p.cwe == 'CWE-295'), None)
        assert cwe295 is not None
        assert cwe295.vendor_count == 3

    def test_cross_target_patterns_sorted_by_vendor_count(self, tmp_path):
        re_dir = _build_test_corpus(tmp_path)
        entries = FindingCorpusMiner(re_dir=re_dir).extract()
        patterns = FindingCorpusMiner.cross_target_patterns(entries, min_vendors=2)
        # CWE-295 has 3 vendors, CWE-78 has 2 → CWE-295 first
        assert patterns[0].cwe == 'CWE-295'

    def test_min_count_filter(self, tmp_path):
        re_dir = _build_test_corpus(tmp_path)
        entries = FindingCorpusMiner(re_dir=re_dir).extract()
        gaps_strict = FindingCorpusMiner.coverage_gaps(entries, min_count=5)
        gaps_loose = FindingCorpusMiner.coverage_gaps(entries, min_count=2)
        assert len(gaps_strict) <= len(gaps_loose)

    def test_render_report_smoke(self, tmp_path):
        re_dir = _build_test_corpus(tmp_path)
        miner = FindingCorpusMiner(re_dir=re_dir)
        entries = miner.extract()
        gaps = miner.coverage_gaps(entries, min_count=2)
        patterns = miner.cross_target_patterns(entries, min_vendors=2)
        report = miner.render_report(entries, gaps, patterns)
        assert 'CWE-295' in report
        assert 'Cross-Target' in report
        assert 'Coverage Gaps' in report
        assert 'vendorA' in report or 'vendora' in report.lower()
