import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from ablation.analyzers.window_analyzer import WindowAnalyzer
from ablation.hpux import PaRiscDecoder

IBM_RE = Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE"))
SOM = IBM_RE / "analysis/Lotus123/42bdf512ad55cd70/20261106T195800Z-motif-som/input/123_motif"


def _synthetic_dispatcher():
    analyzer = WindowAnalyzer(b"")
    analyzer.arch = "pa-risc"
    analyzer._som = SimpleNamespace(decoder=PaRiscDecoder())
    analyzer.data = b"".join(word.to_bytes(4, "big") for word in (
        0x6BC23FD9,
        0x37DE0100,
        0x6BDA3EB9,
        0x6BD93EB1,
        0x08000240,
        0x08000240,
        0x08000240,
        0xE8400A08,
    ))
    analyzer.base_va = 0x23330
    analyzer._is_pie = False
    analyzer._func_starts = {0x23330}
    analyzer.plt = {0x23858: "type_flags"}
    return analyzer


def test_pa_risc_adapter_decodes_words_and_direct_calls_without_corpus():
    analyzer = _synthetic_dispatcher()
    listing = analyzer.dump_text(0x23330, window=32)
    assert "0x23330: stw" in listing
    assert "0x23334: ldo" in listing
    assert "imul" not in listing
    assert "[FUNC_START?]" in listing
    assert "PLT -> type_flags" in listing
    assert analyzer.calls_in_window(0x23330, window=32) == [(0x2334C, 0x23858, "type_flags")]


def test_pa_risc_adapter_ignores_trailing_partial_word():
    analyzer = _synthetic_dispatcher()
    analyzer.data += b"\x01\x02"
    assert len(analyzer.dump(0x23330, window=34)) == 8


@pytest.mark.skipif(not SOM.is_file(), reason="SOM corpus unavailable")
def test_som_window_uses_native_loader_and_unwind_alignment():
    analyzer = WindowAnalyzer.from_path(str(SOM))
    assert analyzer.arch == "pa-risc"
    assert analyzer.base_va == 0x1000
    assert analyzer.plt[0x2F8DC] == "execlp"
    assert 0x23330 in analyzer._func_starts
    assert analyzer.align_to_func_start(0x23358, search_back=0x40) == 0x23330

    listing = analyzer.dump_text(0x23330, window=0x40)
    assert "0x23330: stw" in listing
    assert "0x2334c: b" in listing
    assert "imul" not in listing
    calls = analyzer.calls_in_window(0x2F9BC, window=0x30)
    assert (0x2F9DC, 0x2F8DC, "execlp") in calls
