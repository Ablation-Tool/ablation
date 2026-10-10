"""Tests for EcuROMLayoutAnalyzer.is_calibration_only()."""

import pytest

from ablation.analyzers.ecu_rom_layout_analyzer import (
    EcuROMLayoutAnalyzer,
    ROMLayout,
    ROMRegion,
)


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _layout_from_types(*region_types: str) -> ROMLayout:
    """Build a synthetic ROMLayout with one 4096-byte region per type."""
    ws = 4096
    regions = []
    for i, rtype in enumerate(region_types):
        ent = {
            "ERASED": 0.0,
            "PADDING": 0.3,
            "CALIBRATION": 4.5,
            "MIXED": 6.6,
            "CODE": 5.8,
        }.get(rtype, 4.0)
        regions.append(ROMRegion(
            start=i * ws,
            end=(i + 1) * ws,
            region_type=rtype,
            entropy=ent,
            window_count=1,
        ))
    return ROMLayout(
        file_size=len(region_types) * ws,
        regions=regions,
        window_size=ws,
        fill_byte=0xFF,
    )


# ------------------------------------------------------------------ #
# is_calibration_only — positive cases                                #
# ------------------------------------------------------------------ #

def test_is_calibration_only_pure_calibration():
    layout = _layout_from_types("CALIBRATION", "CALIBRATION")
    cal, reason = layout.is_calibration_only()
    assert cal is True
    assert "cal-only" in reason or "program flash" in reason


def test_is_calibration_only_erased_then_calibration():
    # Mirrors actual EDC16C34 corpus image: large erased gap then calibration data
    layout = _layout_from_types("ERASED", "ERASED", "CALIBRATION", "PADDING", "CALIBRATION")
    cal, reason = layout.is_calibration_only()
    assert cal is True


def test_is_calibration_only_calibration_padding_mix():
    layout = _layout_from_types("CALIBRATION", "PADDING", "CALIBRATION", "ERASED")
    cal, reason = layout.is_calibration_only()
    assert cal is True


# ------------------------------------------------------------------ #
# is_calibration_only — negative cases                                #
# ------------------------------------------------------------------ #

def test_is_calibration_only_false_when_code_present():
    layout = _layout_from_types("CODE", "CALIBRATION")
    cal, reason = layout.is_calibration_only()
    assert cal is False
    assert reason == ""


def test_is_calibration_only_false_when_code_only():
    layout = _layout_from_types("CODE", "CODE", "CODE")
    cal, reason = layout.is_calibration_only()
    assert cal is False


def test_is_calibration_only_false_when_mixed_with_code():
    layout = _layout_from_types("ERASED", "CODE", "CALIBRATION")
    cal, reason = layout.is_calibration_only()
    assert cal is False


# ------------------------------------------------------------------ #
# is_calibration_only — edge cases                                    #
# ------------------------------------------------------------------ #

def test_is_calibration_only_fully_erased_image():
    # A fully erased image is not a calibration dump — no active data at all
    layout = _layout_from_types("ERASED", "ERASED")
    cal, reason = layout.is_calibration_only()
    assert cal is False
    assert "erased" in reason


def test_is_calibration_only_empty_regions():
    layout = ROMLayout(file_size=0, regions=[], window_size=4096, fill_byte=0xFF)
    cal, reason = layout.is_calibration_only()
    assert cal is False


def test_is_calibration_only_single_calibration_region():
    layout = _layout_from_types("CALIBRATION")
    cal, reason = layout.is_calibration_only()
    assert cal is True


# ------------------------------------------------------------------ #
# Integration: analyzer round-trip with synthetic data               #
# ------------------------------------------------------------------ #

def _make_erased_block(size: int, fill: int = 0xFF) -> bytes:
    return bytes([fill]) * size


def _make_calibration_block(size: int) -> bytes:
    # Structured low-entropy bytes: repeating small values 0x00-0x0F
    pattern = bytes(range(16))
    full, rem = divmod(size, 16)
    return pattern * full + pattern[:rem]


def test_analyzer_is_calibration_only_synthetic_obd_dump():
    # Simulate EDC16C34 pattern: 1 MB erased + 128 KB calibration
    erased = _make_erased_block(1024 * 1024)
    cal = _make_calibration_block(128 * 1024)
    rom = erased + cal
    ana = EcuROMLayoutAnalyzer.from_bytes(rom, window_size=4096)
    layout = ana.analyze()
    cal_only, reason = layout.is_calibration_only()
    assert cal_only is True, f"Expected cal-only; got CODE regions: {layout.code_regions()}"


def test_analyzer_is_calibration_only_false_for_code_image():
    # High-entropy bytes simulate a code region
    import os
    code_block = bytes(range(256)) * (4096 // 256)  # flat distribution = high entropy
    # Repeat to make 256 KB of code-like data
    code = code_block * 64
    ana = EcuROMLayoutAnalyzer.from_bytes(code, window_size=4096)
    layout = ana.analyze()
    cal_only, _ = layout.is_calibration_only()
    # Flat distribution always classifies as CODE (entropy ~8.0)
    assert cal_only is False
