"""Tests for SARIF and JSON export modules."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class _FakeSweepResult:
    def __init__(self, tag, hits):
        self.tag = tag
        self.hits = hits


FAKE_SWEEP = {
    "function reads untrusted length and passes to memcpy": _FakeSweepResult(
        "memory-safety", [(0x1000, 0.42), (0x2000, 0.38)]
    ),
    "authentication check returns success on error path": _FakeSweepResult(
        "auth", [(0x3000, 0.31)]
    ),
    "empty pattern with no hits": _FakeSweepResult("dos", []),
}

FAKE_BINARY = '/usr/bin/ls'


def test_sweep_to_sarif_schema():
    from ablation.export.sarif import sweep_to_sarif
    doc = sweep_to_sarif(FAKE_SWEEP, FAKE_BINARY)
    assert doc['version'] == '2.1.0'
    assert '$schema' in doc
    assert len(doc['runs']) == 1


def test_sweep_to_sarif_result_count():
    from ablation.export.sarif import sweep_to_sarif
    doc = sweep_to_sarif(FAKE_SWEEP, FAKE_BINARY)
    # 2 hits + 1 hit = 3 total; empty pattern contributes 0
    assert len(doc['runs'][0]['results']) == 3


def test_sweep_to_sarif_has_rules():
    from ablation.export.sarif import sweep_to_sarif
    doc = sweep_to_sarif(FAKE_SWEEP, FAKE_BINARY)
    rules = doc['runs'][0]['tool']['driver']['rules']
    assert len(rules) >= 2


def test_sweep_to_sarif_min_score_filter():
    from ablation.export.sarif import sweep_to_sarif
    doc = sweep_to_sarif(FAKE_SWEEP, FAKE_BINARY, min_score=0.40)
    # Only hits with score >= 0.40: (0x1000, 0.42)
    assert len(doc['runs'][0]['results']) == 1


def test_sweep_to_sarif_artifact_uri():
    from ablation.export.sarif import sweep_to_sarif
    doc = sweep_to_sarif(FAKE_SWEEP, FAKE_BINARY)
    artifacts = doc['runs'][0]['artifacts']
    assert len(artifacts) == 1
    assert 'file://' in artifacts[0]['location']['uri']


def test_sweep_to_sarif_result_has_address():
    from ablation.export.sarif import sweep_to_sarif
    doc = sweep_to_sarif(FAKE_SWEEP, FAKE_BINARY)
    result = doc['runs'][0]['results'][0]
    loc = result['locations'][0]['physicalLocation']
    assert 'address' in loc
    assert loc['address']['absoluteAddress'] == 0x1000


def test_sweep_to_json():
    from ablation.export.json_export import sweep_to_json
    doc = sweep_to_json(FAKE_SWEEP, FAKE_BINARY)
    assert doc['total_hits'] == 3
    assert len(doc['findings']) == 2  # empty pattern excluded
    assert doc['binary'].endswith('ls')


def test_sweep_to_json_serializable():
    from ablation.export.json_export import sweep_to_json
    doc = sweep_to_json(FAKE_SWEEP, FAKE_BINARY)
    s = json.dumps(doc)
    assert len(s) > 0


def test_findings_to_sarif():
    from ablation.export.sarif import findings_to_sarif
    findings = [
        {'vendor': 'test', 'product': 'fw', 'cwe': 'CWE-120', 'severity': 'high',
         'title': 'Buffer overflow in parser', 'created_at': '2026-01-01'},
        {'vendor': 'test', 'product': 'fw', 'cwe': 'CWE-835', 'severity': 'medium',
         'title': 'Infinite loop on zero-length field', 'created_at': '2026-01-01'},
    ]
    doc = findings_to_sarif(findings)
    assert doc['version'] == '2.1.0'
    assert len(doc['runs'][0]['results']) == 2


def test_sarif_write_to_file(tmp_path):
    from ablation.export.sarif import sweep_to_sarif
    from ablation.export.json_export import write_sarif
    doc = sweep_to_sarif(FAKE_SWEEP, FAKE_BINARY)
    out = tmp_path / 'results.sarif'
    write_sarif(doc, str(out))
    assert out.exists()
    loaded = json.loads(out.read_text())
    assert loaded['version'] == '2.1.0'
