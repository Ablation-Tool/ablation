import struct

import pytest

import ablation.analyzers.microblaze_decoder as microblaze_module
from ablation.analyzers.microblaze_decoder import MicroBlazeDecoder
from ablation.analyzers.versal_pdi import VersalPdi


_GCI_BOOT = "/media/cowboy/research/CERN/fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi"


def decode(*words: int, base: int = 0):
    data = b"".join(struct.pack(">I", word) for word in words)
    return MicroBlazeDecoder(data, base).disassemble()


def test_addik_signed_immediate():
    insn = decode(0x3021FFE0)[0]
    assert insn.mnemonic == "addik"
    assert (insn.rd, insn.ra, insn.imm) == (1, 1, -32)
    assert insn.operands == "r1, r1, -32"


def test_imm_extends_next_instruction_only():
    insns = decode(0xB000FFFF, 0x30A00000, 0x30600001)
    assert insns[0].mnemonic == "imm"
    assert insns[1].imm == -0x10000
    assert insns[1].extended_imm
    assert insns[2].imm == 1
    assert not insns[2].extended_imm


def test_imm_ori_uses_unsigned_bit_pattern():
    insns = decode(0xB0000001, 0xA1A0C148)
    assert insns[1].mnemonic == "ori"
    assert insns[1].imm == 0x1C148
    assert insns[1].operands == "r13, r0, 0x1c148"


def test_relative_call_target_and_delay_slot():
    insn = decode(0xB9F40128, base=0xF6130050)[0]
    assert insn.mnemonic == "brlid"
    assert insn.rd == 15
    assert insn.target == 0xF6130178
    assert insn.flow == "call"
    assert insn.delay_slot


def test_absolute_call_target():
    insns = decode(0xB000F613, 0xB9FC1234, base=0x1000)
    assert insns[1].mnemonic == "bralid"
    assert insns[1].target == 0xF6131234


def test_conditional_relative_target():
    insn = decode(0xBE030010, base=0x2000)[0]
    assert insn.mnemonic == "beqid"
    assert insn.ra == 3
    assert insn.target == 0x2010
    assert insn.flow == "conditional"
    assert insn.delay_slot


def test_return_and_register_branch():
    ret = decode(0xB60F0008)[0]
    assert ret.mnemonic == "rtsd"
    assert ret.flow == "return"
    assert ret.delay_slot
    branch = decode(0x98007800)[0]
    assert branch.mnemonic == "br"
    assert branch.rb == 15


def test_load_store_and_nop():
    insns = decode(0xF9E10000, 0xE8E30004, 0x00000000)
    assert insns[0].mnemonic == "swi"
    assert (insns[0].rd, insns[0].ra, insns[0].imm) == (15, 1, 0)
    assert insns[1].mnemonic == "lwi"
    assert (insns[1].rd, insns[1].ra, insns[1].imm) == (7, 3, 4)
    assert insns[2].mnemonic == "nop"


def test_shifts():
    insns = decode(0x64610003, 0x64610203, 0x64610403)
    assert [i.mnemonic for i in insns] == ["bsrli", "bsrai", "bslli"]
    assert all(i.imm == 3 for i in insns)


def test_special_registers():
    mfs = decode(0x96808000)[0]
    assert mfs.mnemonic == "mfs"
    assert mfs.rd == 20
    msr = decode(0x94308000)[0]
    assert msr.mnemonic == "msrset"


def test_invalid_instruction_is_explicit():
    insn = decode(0xFC000000)[0]
    assert not insn.valid
    assert insn.mnemonic == ".word"


def test_call_targets_and_prologue_function_starts():
    decoder = MicroBlazeDecoder(
        b"".join(struct.pack(">I", w) for w in (
            0x3021FFE0, 0xF9E10000, 0xB9F40008, 0x80000000,
            0xB60F0008, 0x00000000, 0x3021FFF0, 0xF9E10000,
        )),
        0x1000,
    )
    assert decoder.call_targets() == [0x1010]
    assert decoder.function_starts() == [0x1000, 0x1010, 0x1018]


@pytest.mark.skipif(not __import__("os").path.isfile(_GCI_BOOT), reason="GEP boot PDI not found")
def test_real_gep_plm_segment_disassembles():
    pdi = VersalPdi.from_path(_GCI_BOOT)
    segments = sorted(
        (s for s in pdi.dma_write_segments() if 0xF6130000 <= s.address < 0xF6140000),
        key=lambda segment: segment.address,
    )
    assert [s.address for s in segments] == [0xF6130000, 0xF6130050]
    assert segments[0].end_address == segments[1].address
    image = b"".join(s.data for s in segments)
    decoder = MicroBlazeDecoder(image, 0xF6130000, byte_order="little")
    instructions = decoder.disassemble()
    assert [i.mnemonic for i in instructions[:5]] == ["imm", "brai", "imm", "brai", "imm"]
    assert sum(i.valid for i in instructions) / len(instructions) > 0.99
    assert 0xF6130194 in decoder.call_targets()


def test_image_size_limit_for_buffer_and_path(monkeypatch, tmp_path):
    monkeypatch.setattr(microblaze_module, "MAX_IMAGE_BYTES", 4)
    with pytest.raises(ValueError, match="exceeds 4 bytes"):
        MicroBlazeDecoder(b"\x00" * 5)
    image = tmp_path / "oversize.bin"
    image.write_bytes(b"\x00" * 5)
    with pytest.raises(ValueError, match="exceeds 4 bytes"):
        MicroBlazeDecoder.from_path(image)
