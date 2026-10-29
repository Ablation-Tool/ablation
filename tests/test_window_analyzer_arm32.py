"""Legacy ARM32 and bFLT tests for WindowAnalyzer."""

import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from ablation.analyzers.bflt_context import BfltBinaryContext
from ablation.analyzers.window_analyzer import WindowAnalyzer
from ablation.parsers.caen_hex import CaenHexFirmware


def _arm32_with(data: bytes) -> WindowAnalyzer:
    analyzer = WindowAnalyzer(b"")
    analyzer.arch = "arm32"
    analyzer.data = data
    analyzer.base_va = 0
    return analyzer


def test_arm32_rel_plt_uses_resolver_and_twelve_byte_stubs():
    rel_plt = SimpleNamespace(content=struct.pack("<II", 0x2000, 0) + struct.pack("<II", 0x2004, 1 << 8))
    plt = SimpleNamespace(content=b"", virtual_address=0x1000)
    binary = SimpleNamespace(
        dynamic_symbols=[SimpleNamespace(name="usleep"), SimpleNamespace(name="strcmp")],
        get_section=lambda name: {".rel.plt": rel_plt, ".plt": plt}.get(name),
    )
    analyzer = WindowAnalyzer(b"")
    analyzer.arch = "arm32"
    analyzer._build_plt_arm32(binary)
    assert analyzer.plt == {0x1014: "usleep", 0x1020: "strcmp"}


def test_arm32_jump_slot_fallback():
    relocation = SimpleNamespace(
        has_symbol=True,
        type="TYPE.ARM_JUMP_SLOT",
        address=0x2000,
        symbol=SimpleNamespace(name="strcmp"),
    )
    binary = SimpleNamespace(
        dynamic_symbols=[],
        relocations=[relocation],
        get_section=lambda name: None,
    )
    analyzer = WindowAnalyzer(b"")
    analyzer.arch = "arm32"
    analyzer._build_plt_arm32(binary)
    assert analyzer.plt == {0x2000: "strcmp"}


def test_direct_bl_calls_do_not_depend_on_formatted_text():
    analyzer = _arm32_with(bytes.fromhex("04 00 00 eb 00 00 a0 e1"))
    analyzer.plt = {0x18: "strcmp"}
    assert analyzer.calls_in_window(0, window=8) == [(0, 0x18, "strcmp")]
    analyzer.plt = {}
    assert analyzer.calls_in_window(0, window=8) == [(0, 0x18, "")]
    assert analyzer.calls_in_window(0x100, window=8) == []


def test_arm32_literal_string_annotation_is_bounded():
    data = bytearray(0x20)
    data[0:4] = bytes.fromhex("04 00 9f e5")
    data[4:8] = bytes.fromhex("00 00 a0 e1")
    data[8:12] = bytes.fromhex("00 00 a0 e1")
    data[12:16] = (0x18).to_bytes(4, "little")
    data[0x18:0x1C] = b"TEST"
    analyzer = _arm32_with(bytes(data))
    analyzer.strings = {0x18: "TEST"}
    assert '"TEST"' in analyzer.dump_text(0, window=0x20)
    analyzer.strings = {0x1000: "outside"}
    assert '"outside"' not in analyzer.dump_text(0, window=0x20)


def test_a1676_recovers_legacy_plt_and_update_call():
    source = Path("/media/cowboy/research/CERN/analysis/caen-firmware/extracted/CAEN-1075174/a1676_3_02")
    if not source.exists():
        pytest.skip("A1676 fixture is unavailable")
    image = CaenHexFirmware.from_path(source)
    analyzer = WindowAnalyzer(image.payload, path=str(source))
    assert analyzer.arch == "arm32"
    assert len(analyzer.plt) == 39
    assert analyzer.plt[0x89D4] == "strcmp"
    calls = analyzer.calls_in_window(0x1091C, window=128)
    assert (0x10980, 0x10D38, "") in calls
    listing = analyzer.dump_text(0x10980, window=128, align_back=64)
    assert "0x10980: bl" in listing


def test_bflt_window_uses_relocated_context():
    source = Path("/media/cowboy/research/CERN/analysis/caen-firmware/c111c-full/jenet")
    if not source.exists():
        pytest.skip("C111C fixture is unavailable")
    context = BfltBinaryContext.from_path(source)
    analyzer = WindowAnalyzer.from_bflt(context)
    assert analyzer.arch == "arm32"
    assert analyzer._text_start == 0x40
    assert analyzer._text_end == context.source_image.data_start
    calls = analyzer.calls_in_window(0x1518, window=0x300)
    assert (0x1788, 0x33D34, "") in calls
    listing = analyzer.dump_text(0x1780, window=16)
    assert '"CLMR"' in listing


def test_from_bflt_rejects_non_bflt_context():
    with pytest.raises(TypeError, match="BfltBinaryContext"):
        WindowAnalyzer.from_bflt(object())
