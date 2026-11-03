from types import SimpleNamespace

from ablation.analyzers.analysis_result import AnalysisResult, AnalysisStatus
from ablation.analyzers.hypothesis_engine import HypothesisEngine
from ablation.analyzers.hypothesis_models import ProbeRecord
from ablation.analyzers.probe_adapters import execute_probe_result


def _session(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    engine = HypothesisEngine.from_binary(
        str(target),
        ctx=SimpleNamespace(path=str(target)),
    )
    engine.seed_one("function_entry", {"va": "0x1000"}, {"entry": "0x1000"})
    return engine


def test_unknown_adapter_is_not_a_successful_empty_result(tmp_path):
    engine = _session(tmp_path)
    probe = ProbeRecord.create("not-a-backend", [engine.session.hypotheses[0].id], "missing")

    result = execute_probe_result(probe, SimpleNamespace(), engine.session)

    assert result.status is AnalysisStatus.UNSUPPORTED
    assert not result.succeeded
    assert result.diagnostics[0].code == "unsupported_adapter"


def test_engine_preserves_failed_probe_outcome(tmp_path, monkeypatch):
    engine = _session(tmp_path)
    result = AnalysisResult.failed("backend_crashed", "backend exited without a result")
    monkeypatch.setattr(
        "ablation.analyzers.hypothesis_engine._lazy_execute_probe_result",
        lambda *_args: result,
    )

    probe = engine.step(kind="cfg", approved=True)

    assert probe.status == AnalysisStatus.FAILED.value
    assert not probe.executed
    assert probe.diagnostics[0]["code"] == "backend_crashed"
    assert "backend_crashed" in engine.report()


def test_successful_empty_probe_is_complete_and_scoped(tmp_path, monkeypatch):
    engine = _session(tmp_path)
    result = AnalysisResult.complete(coverage={"functions_requested": 1, "functions_analyzed": 1})
    monkeypatch.setattr(
        "ablation.analyzers.hypothesis_engine._lazy_execute_probe_result",
        lambda *_args: result,
    )

    probe = engine.step(kind="cfg", approved=True)

    assert probe.status == AnalysisStatus.COMPLETE.value
    assert probe.executed
    assert probe.coverage["functions_analyzed"] == 1


def test_probe_evidence_carries_artifact_and_execution_provenance(tmp_path):
    engine = _session(tmp_path)
    hypothesis = engine.session.hypotheses[0]
    probe = ProbeRecord.create("manual", [hypothesis.id], "analyst", {"reason": "review"})
    ctx = SimpleNamespace(path=engine.session.binary_path, sha256=engine.session.binary_sha256, arch="arm64")

    result = execute_probe_result(probe, ctx, engine.session)

    assert result.succeeded
    evidence = result.evidence[0]
    assert evidence.artifact_hashes == [engine.session.binary_sha256]
    assert evidence.parameters["probe_id"] == probe.id
    assert evidence.parameters["probe_parameters"] == {"reason": "review"}
    assert evidence.source_location == {
        "binary_path": engine.session.binary_path,
        "architecture": "arm64",
    }
