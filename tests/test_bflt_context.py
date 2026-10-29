"""Relocation and BinaryContext tests for bFLT v4 executables."""

import hashlib
import struct
from pathlib import Path

import pytest

from ablation.analyzers.bflt_context import (
    BfltBinaryContext,
    BfltRelocationError,
    relocate_bflt,
)
from ablation.parsers.bflt import BfltImage


def _image(text: bytes, data: bytes, offsets: list[int]) -> bytes:
    data_end = 0x40 + len(text) + len(data)
    relocations = b"".join(offset.to_bytes(4, "big") for offset in offsets)
    header = struct.pack(
        ">4s15I", b"bFLT", 4, 0x40, 0x40 + len(text), data_end,
        data_end + 0x10, 0x1000, data_end, len(offsets), 1, 0, *([0] * 5),
    )
    return header + text + data + relocations


def _text(pointer: int) -> bytes:
    return b"".join((
        bytes.fromhex("10 40 2d e9"),
        bytes.fromhex("01 00 00 eb"),
        bytes.fromhex("04 00 9f e5"),
        bytes.fromhex("00 00 a0 e1"),
        bytes.fromhex("10 40 2d e9"),
        pointer.to_bytes(4, "big"),
        bytes(8),
    ))


def _context_program() -> bytes:
    return _image(_text(0x24), bytes(4) + b"TEST\0" + bytes(7), [0x14])


def _relocation_program() -> bytes:
    data = b"".join(value.to_bytes(4, "big") for value in (
        0x10, 0, 0x00FFFFFF, 0x0A000000,
    ))
    return _image(_text(0x10), data, [0x14, 0x20, 0x24, 0x28, 0x2C])


def test_relocation_maps_slots_values_and_runtime_endianness():
    loaded = relocate_bflt(
        BfltImage.from_bytes(_relocation_program()),
        base_va=0x100000,
        allow_unresolved=True,
    )
    assert loaded.complete is False
    assert [(record.address, record.stored_value, record.value, record.status)
            for record in loaded.relocations] == [
        (0x100054, 0x10, 0x100050, "RELOCATED"),
        (0x100060, 0x10, 0x100050, "RELOCATED"),
        (0x100064, 0, 0, "ZERO"),
        (0x100068, 0x00FFFFFF, 0x00FFFFFF, "UNRESOLVED_OUT_OF_RANGE"),
        (0x10006C, 0x0A000000, 0x0A000000, "UNRESOLVED_SHARED_LIBRARY"),
    ]
    assert loaded.memory_image[0x54:0x58] == (0x100050).to_bytes(4, "little")
    assert loaded.memory_image[0x68:0x6C] == (0x00FFFFFF).to_bytes(4, "big")
    assert len(loaded.unresolved) == 2


def test_strict_relocation_rejects_unmapped_value():
    with pytest.raises(BfltRelocationError, match="relocation 3"):
        relocate_bflt(BfltImage.from_bytes(_relocation_program()))


def test_relocation_rejects_invalid_slot_and_overflow():
    raw = bytearray(_relocation_program())
    raw[-20:-16] = (0x41).to_bytes(4, "big")
    with pytest.raises(BfltRelocationError, match="slot offset"):
        relocate_bflt(BfltImage.from_bytes(raw))
    with pytest.raises(BfltRelocationError, match="32-bit address space"):
        relocate_bflt(BfltImage.from_bytes(_relocation_program()), base_va=0xFFFFFFFF)
    with pytest.raises(ValueError, match="pointer_byteorder"):
        relocate_bflt(BfltImage.from_bytes(_relocation_program()), pointer_byteorder="middle")


def test_binary_context_recovers_functions_calls_strings_and_xrefs():
    raw = _context_program()
    context = BfltBinaryContext.from_bytes(raw, base_va=0x100000)
    assert context.arch == "arm32"
    assert context.base_va == 0x100000
    assert context.sha256 == hashlib.sha256(raw).hexdigest()
    assert context.relocation_complete is True
    assert context.func_starts == [0x100040, 0x100050]
    assert context.call_edges == [(0x100040, 0x100050, "")]
    assert context.strings == {0x100064: "TEST"}
    assert context.string_xrefs(0x100064) == [0x100048]
    assert context.funcs_referencing_string(0x100064) == [0x100040]
    assert context.strings_in_func(0x100040) == [(0x100064, "TEST")]
    assert context.callees_of(0x100040) == [(0x100050, "0x100050")]
    assert context.callers_of(0x100050) == [(0x100040, "0x100040")]
    references = context.literal_references(0x100064)
    assert len(references) == 1
    assert references[0].instruction_address == 0x100048
    assert references[0].literal_address == 0x100054
    assert references[0].value == 0x100064
    assert context.read_memory(0x100054, 4) == (0x100064).to_bytes(4, "little")
    assert context.metadata()["relocation_complete"] is True
    assert context.metadata()["call_edges"] == 1
    assert "arm32" in context.summary()
    with pytest.raises(BfltRelocationError, match="outside"):
        context.read_memory(0, 1)


def test_from_path_hashes_original_bytes(tmp_path):
    raw = _context_program()
    path = tmp_path / "program"
    path.write_bytes(raw)
    context = BfltBinaryContext.from_path(path)
    assert context.path == str(path)
    assert context.sha256 == hashlib.sha256(raw).hexdigest()
    assert context.relocation_complete


def test_from_image_validates_type_and_digest():
    with pytest.raises(TypeError, match="parsed BfltImage"):
        BfltBinaryContext.from_image(b"not an image")
    first = BfltBinaryContext.from_image(BfltImage.from_bytes(_context_program()))
    second = BfltBinaryContext.from_image(BfltImage.from_bytes(_context_program()))
    assert first.sha256 == second.sha256


C111C = Path("/media/cowboy/research/CERN/analysis/caen-firmware/c111c-full")


def test_tinyws_relocation_slots_and_completion():
    if not (C111C / "tinyws").exists():
        pytest.skip("C111C fixture is unavailable")
    loaded = relocate_bflt(BfltImage.from_path(C111C / "tinyws"))
    assert loaded.complete is True
    assert loaded.unresolved == ()
    assert [(record.address, record.stored_value, record.value)
            for record in loaded.relocations[:2]] == [
        (0x74, 0x17B3C, 0x17B7C),
        (0x78, 0x17B44, 0x17B84),
    ]


def test_all_c111c_relocations_complete():
    if not (C111C / "jenet").exists():
        pytest.skip("C111C fixture is unavailable")
    for name in ("tinyws", "jenet", "jcomsrv", "jappliman", "hw_rtc", "msntp"):
        loaded = relocate_bflt(BfltImage.from_path(C111C / name))
        assert loaded.complete is True, name
        assert loaded.unresolved == (), name


def test_jenet_context_tracks_relocated_ws_cmd_pointer():
    if not (C111C / "jenet").exists():
        pytest.skip("C111C fixture is unavailable")
    context = BfltBinaryContext.from_path(C111C / "jenet")
    record = next(record for record in context.relocations if record.address == 0x1938)
    assert record.stored_value == 0x3D204
    assert record.value == 0x3D244
    assert context.relocation_complete is True
    references = context.literal_references(0x3D244)
    assert [reference.instruction_address for reference in references] == [0x1780]
    assert context.string_xrefs(0x3D244) == [0x1780]
