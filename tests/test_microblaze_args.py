import os
import struct

import pytest

from ablation.analyzers.microblaze_args import call_arguments
from ablation.analyzers.microblaze_cfg import (
    JumpTableSpec,
    no_return_addresses,
    recover_cfg,
    resolve_jump_tables,
)
from ablation.analyzers.microblaze_decoder import MicroBlazeDecoder
from ablation.analyzers.versal_pdi import VersalPdi


_GCI_BOOT = "/media/cowboy/research/CERN/fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi"


def decoder_for(*words: int, base: int = 0x1000) -> MicroBlazeDecoder:
    return MicroBlazeDecoder(b"".join(struct.pack(">I", word) for word in words), base)


def test_recovers_delay_slot_and_register_copy_arguments():
    recovery = recover_cfg(decoder_for(
        0x30801000, 0x10A40000, 0x30C0002B, 0xB9F40010,
        0x30E00048, 0xB60F0008, 0x00000000,
        0xB60F0008, 0x00000000,
    ))
    arguments = call_arguments(recovery.functions[0x1000], 0x100C)

    assert {register: argument.value for register, argument in arguments.items()} == {
        5: 0x1000, 6: 43, 7: 72,
    }
    assert arguments[5].definition == 0x1004
    assert arguments[7].definition == 0x1010


def test_unknown_argument_and_input_validation():
    recovery = recover_cfg(decoder_for(
        0xE8A00000, 0xB9F40008, 0x00000000, 0xB60F0008, 0x00000000,
    ))
    function = recovery.functions[0x1000]
    arguments = call_arguments(function, 0x1004)
    assert arguments[5].value is None
    assert arguments[5].definition == 0x1000

    with pytest.raises(ValueError, match="no direct call"):
        call_arguments(function, 0x1000)
    with pytest.raises(ValueError, match="between 1 and 4096"):
        call_arguments(function, 0x1004, max_instructions=0)
    with pytest.raises(ValueError, match="between r0 and r31"):
        call_arguments(function, 0x1004, registers=(32,))
    with pytest.raises(ValueError, match="too many argument registers"):
        call_arguments(function, 0x1004, registers=iter([5] * 33))


@pytest.mark.skipif(not os.path.isfile(_GCI_BOOT), reason="GEP boot PDI not found")
def test_real_plm_copy_call_lengths():
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

    calls = [
        (entry, address, function)
        for entry, function in recovery.functions.items()
        for address, target in function.calls.items()
        if target == 0xF613072C
    ]
    assert len(calls) == 3
    results = {
        address: call_arguments(function, address)
        for _, address, function in calls
    }
    assert {address: arguments[7].value for address, arguments in results.items()} == {
        0xF61326D8: 72,
        0xF61347A4: 72,
        0xF613D894: 43,
    }
    assert results[0xF61326D8][5].value == 0x1C4F8
    assert results[0xF61326D8][6].value == 0x1C8C4
    assert results[0xF61347A4][5].value == 0x1C4F8
    assert results[0xF61347A4][6].value == 0x1C8C4
    assert results[0xF613D894][5].value == 0x1C658
    assert results[0xF613D894][6].value == 0x36D60
