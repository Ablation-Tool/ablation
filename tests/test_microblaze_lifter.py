import os
import struct

import pytest

from ablation.analyzers.microblaze_cfg import (
    JumpTableSpec,
    MicroBlazeBlock,
    MicroBlazeFunction,
    MicroBlazeRecovery,
    no_return_addresses,
    recover_cfg,
    resolve_jump_tables,
)
from ablation.analyzers.microblaze_decoder import MicroBlazeDecoder, MicroBlazeInsn
from ablation.analyzers.microblaze_lifter import MicroBlazeLifter
from ablation.analyzers.versal_pdi import VersalPdi


_GCI_BOOT = "/media/cowboy/research/CERN/fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi"


def decoder_for(*words: int, base: int = 0x1000) -> MicroBlazeDecoder:
    return MicroBlazeDecoder(b"".join(struct.pack(">I", word) for word in words), base)


def test_arithmetic_reverse_subtraction_and_zero_store():
    recovery = recover_cfg(decoder_for(
        0x30600005, 0x34830002, 0xF8010000, 0xB60F0008, 0x00000000,
    ))
    output = MicroBlazeLifter(recovery).lift_function(0x1000)

    assert "r3 = r0 + 0x5;" in output
    assert "r4 = 0x2 - r3;" in output
    assert "*(uint32_t *)r1 = r0;" in output
    assert "return r3;" in output


def test_delay_slot_is_emitted_before_direct_call():
    recovery = recover_cfg(decoder_for(
        0xB9F40010, 0x30A00001, 0xB60F0008, 0x00000000,
        0xB60F0008, 0x00000000,
    ))
    output = MicroBlazeLifter(recovery).lift_function(0x1000)

    assert output.index("r5 = r0 + 0x1;") < output.index("r3 = sub_00001010(r5")
    assert "r3 = sub_00001010(r5, r6, r7, r8, r9, r10);" in output


def test_conditional_and_indirect_control_flow_are_explicit():
    conditional = recover_cfg(decoder_for(
        0xBE030008, 0x00000000, 0xB60F0008, 0x00000000,
    ))
    output = MicroBlazeLifter(conditional).lift_function(0x1000)
    assert "if (r3 == 0) goto loc_00001008; else goto loc_00001008;" not in output
    assert "if (r3 == 0) goto loc_00001008;" in output

    indirect = recover_cfg(decoder_for(
        0x99FC1800, 0x00000000, 0xB60F0008, 0x00000000,
    ))
    output = MicroBlazeLifter(indirect).lift_function(0x1000)
    assert "r3 = indirect_call_r3(r5, r6, r7, r8, r9, r10);" in output


def test_load_store_widths_and_shifts():
    recovery = recover_cfg(decoder_for(
        0xE0E30004, 0xF4C30002, 0x64610003, 0xB60F0008, 0x00000000,
    ))
    output = MicroBlazeLifter(recovery).lift_function(0x1000)
    assert "r7 = *(uint8_t *)(r3 + 4);" in output
    assert "*(uint16_t *)(r3 + 2) = r6;" in output
    assert "r3 = r1 >> 3;" in output


def test_unknown_valid_operation_is_not_dropped():
    insn = MicroBlazeInsn(0, 0x1000, 0, "new_instruction", "r1, r2")
    block = MicroBlazeBlock(0x1000, [insn])
    function = MicroBlazeFunction(0x1000, {0x1000: block}, {}, [])
    recovery = MicroBlazeRecovery(0x1000, 4, {0x1000: function}, {0x1000: insn}, [])
    output = MicroBlazeLifter(recovery).lift_function(0x1000)
    assert "unlifted: new_instruction r1, r2" in output


def test_lift_validation_and_limits():
    recovery = recover_cfg(decoder_for(0x30210001, 0xB60F0008, 0x00000000))
    lifter = MicroBlazeLifter(recovery)
    with pytest.raises(ValueError, match="no recovered"):
        lifter.lift_function(0x2000)
    with pytest.raises(ValueError, match="2 lifted instructions"):
        MicroBlazeLifter(recovery, max_instructions=2).lift_function(0x1000)
    with pytest.raises(ValueError, match="positive"):
        MicroBlazeLifter(recovery, max_blocks=0)
    with pytest.raises(ValueError, match="recovery exceeds"):
        MicroBlazeLifter(recovery, max_instructions=2).lift_recovery()


@pytest.mark.skipif(not os.path.isfile(_GCI_BOOT), reason="GEP boot PDI not found")
def test_real_gep_plm_structural_lift():
    pdi = VersalPdi.from_path(_GCI_BOOT)
    segments = sorted(
        (s for s in pdi.dma_write_segments() if 0xF6130000 <= s.address < 0xF6140000),
        key=lambda segment: segment.address,
    )
    decoder = MicroBlazeDecoder(
        b"".join(segment.data for segment in segments), 0xF6130000, byte_order="little"
    )
    initial = recover_cfg(decoder, [0xF6130050])
    targets = resolve_jump_tables(decoder, initial, {
        0xF61311E8: JumpTableSpec(0xF6146DA4, 19, 0xF6110000),
        0xF613C664: JumpTableSpec(0xF6146DF4, 5, 0xF6110000),
    })
    with_fallthrough = recover_cfg(decoder, [0xF6130050], jump_table_targets=targets)
    recovery = recover_cfg(
        decoder,
        [0xF6130050],
        jump_table_targets=targets,
        no_return=no_return_addresses(with_fallthrough),
    )
    lifter = MicroBlazeLifter(recovery)

    startup = lifter.lift_function(0xF6130050)
    callbacks = lifter.lift_function(0xF613091C)
    switch = lifter.lift_function(0xF6130ED0)
    assert "sub_f6130194" in startup
    assert callbacks.count("indirect_call_r7") == 3
    assert "jump_table(r3" in switch
    assert "loc_f61311f8" in switch
    assert "indirect_jump" not in switch
