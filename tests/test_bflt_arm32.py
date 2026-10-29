"""Tests for link-time bFLT ARM32 pointer and literal recovery."""

import struct

import pytest

from ablation.analyzers.bflt_arm32 import BfltArm32
from ablation.parsers.bflt import BfltImage


def _image() -> BfltImage:
    text = (
        bytes.fromhex("04 00 9f e5")
        + bytes.fromhex("00 00 a0 e1")
        + bytes.fromhex("00 00 a0 e1")
        + (0x20000).to_bytes(4, "big")
        + bytes.fromhex("04 10 9f e5")
        + bytes.fromhex("00 00 a0 e1")
        + bytes.fromhex("00 00 a0 e1")
        + (0x20000).to_bytes(4, "big")
    )
    header = struct.pack(
        ">4s15I", b"bFLT", 4, 0x40, 0x60, 0x68, 0x20040, 0x1000,
        0x68, 0, 0, 0, *([0] * 5),
    )
    return BfltImage.from_bytes(header + text + bytes(8))


def test_read_pointer_uses_explicit_byte_order():
    image = _image()
    assert BfltArm32(image, pointer_byteorder="big").read_pointer(0x4C) == 0x20000
    assert BfltArm32(image, pointer_byteorder="little").read_pointer(0x4C) == 0x200


def test_pointer_references_are_aligned_candidates():
    context = BfltArm32(_image(), pointer_byteorder="big")
    assert context.pointer_references(0x20000) == [0x4C, 0x5C]
    assert context.pointer_references(0x20000, start=0x50) == [0x5C]
    assert context.pointer_references(0x12345) == []


def test_literal_references_resolve_two_levels():
    context = BfltArm32(_image(), pointer_byteorder="big")
    references = context.literal_references(0x20000)
    assert [reference.instruction_address for reference in references] == [0x40, 0x50]
    assert [reference.literal_address for reference in references] == [0x4C, 0x5C]
    assert [reference.value for reference in references] == [0x20000, 0x20000]
    assert references[0].mnemonic == "ldr"
    assert references[0].operands == "r0, [pc, #4]"


def test_literal_references_can_keep_literal_address():
    context = BfltArm32(_image(), pointer_byteorder="big")
    references = context.literal_references(0x4C, dereference=False)
    assert len(references) == 1
    assert references[0].instruction_address == 0x40
    assert references[0].value is None


def test_out_of_image_literal_is_skipped():
    raw = bytearray(_image().memory_image)
    raw[0x40:0x44] = bytes.fromhex("ff 0f 1f e5")
    context = BfltArm32(BfltImage.from_bytes(raw), pointer_byteorder="big")
    instruction = next(context.instructions(0x40, 0x44))
    assert context.literal_address(instruction) < 0
    references = context.literal_references(0x20000)
    assert [reference.instruction_address for reference in references] == [0x50]


def test_instruction_range_is_bounded():
    context = BfltArm32(_image(), pointer_byteorder="big")
    assert [insn.address for insn in context.instructions(0x40, 0x44)] == [0x40]
    with pytest.raises(ValueError, match="outside bFLT text"):
        list(context.instructions(0x40, 0x64))
    with pytest.raises(ValueError, match="four-byte aligned"):
        list(context.instructions(0x41))


def test_invalid_inputs_are_rejected():
    image = _image()
    with pytest.raises(ValueError, match="pointer_byteorder"):
        BfltArm32(image, pointer_byteorder="middle")
    with pytest.raises(TypeError, match="parsed BfltImage"):
        BfltArm32(image.memory_image, pointer_byteorder="big")
    context = BfltArm32(image, pointer_byteorder="big")
    with pytest.raises(ValueError, match="32-bit pointer"):
        context.pointer_references(-1)
    with pytest.raises(ValueError, match="four-byte aligned"):
        context.pointer_references(0x20000, start=0x41)
    with pytest.raises(ValueError, match="outside initialized"):
        context.pointer_references(0x20000, end=0x6C)
