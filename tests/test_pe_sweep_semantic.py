import sys
import types

import pytest

from sweeps import pe_sweep


def test_main_returns_error_for_incomplete_semantic_results(
    tmp_path, monkeypatch, capsys
):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    report = tmp_path / "report.md"

    sentence_transformers = types.ModuleType("sentence_transformers")
    sentence_transformers.SentenceTransformer = lambda *args, **kwargs: object()
    monkeypatch.setitem(sys.modules, "sentence_transformers", sentence_transformers)
    monkeypatch.setattr(pe_sweep, "_is_pe", lambda path: True)
    monkeypatch.setattr(
        pe_sweep, "_detect_pe_arch", lambda path: ("ARCH.AMD64", True)
    )
    monkeypatch.setattr(
        pe_sweep,
        "_sweep_pe_one",
        lambda *args, **kwargs: {
            "path": str(target),
            "arch": "ARCH.AMD64",
            "is_64": True,
            "functions_found": 1,
            "iat_size": 0,
            "firmware_auth_bypass": None,
            "semantic": {},
            "error": "semantic: encoder failed",
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["pe_sweep.py", str(target), "--report", str(report)],
    )

    with pytest.raises(SystemExit) as exc_info:
        pe_sweep.main()

    assert exc_info.value.code == 2
    assert "1 binary(ies) could NOT be scored" in capsys.readouterr().out
    assert "**ERROR:** semantic: encoder failed" in report.read_text(encoding="utf-8")
