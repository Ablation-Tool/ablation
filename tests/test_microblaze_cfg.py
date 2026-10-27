import os
import struct

import pytest

from ablation.analyzers.microblaze_cfg import JumpTableSpec, recover_cfg, resolve_jump_tables
from ablation.analyzers.microblaze_decoder import MicroBlazeDecoder
from ablation.analyzers.versal_pdi import VersalPdi


_GCI_BOOT = "/media/cowboy/research/CERN/fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi"


def decoder_for(*words: int, base: int = 0x1000) -> MicroBlazeDecoder:
    return MicroBlazeDecoder(b"".join(struct.pack(">I", word) for word in words), base)


def test_recursive_recovery_skips_unreachable_data_and_discovers_callee():
    words = [0xB8000020] + [0xFC000000] * 7 + [
        0xB9F40020, 0x00000000, 0xB60F0008, 0x00000000,
        0xFC000000, 0xFC000000, 0xFC000000, 0xFC000000,
        0xB60F0008, 0x00000000,
    ]
    recovery = recover_cfg(decoder_for(*words))

    assert set(recovery.functions) == {0x1000, 0x1040}
    assert recovery.functions[0x1000].calls == {0x1020: 0x1040}
    assert set(recovery.code) == {0x1000, 0x1020, 0x1024, 0x1028, 0x102C, 0x1040, 0x1044}
    assert (0x1004, 0x1020) in recovery.unclassified_ranges
    assert (0x1030, 0x1040) in recovery.unclassified_ranges


def test_conditional_delay_slot_and_successors():
    recovery = recover_cfg(decoder_for(
        0xBE000018, 0x00000000, 0x3021FFFC, 0xB60F0008,
        0x00000000, 0xFC000000, 0xB60F0008, 0x00000000,
    ))
    function = recovery.functions[0x1000]
    entry = function.blocks[0x1000]

    assert [insn.address for insn in entry.insns] == [0x1000, 0x1004]
    assert entry.succs == [0x1018, 0x1008]
    assert function.blocks[0x1008].preds == [0x1000]
    assert 0x1014 not in recovery.code


def test_imm_absolute_branch_target():
    recovery = recover_cfg(decoder_for(
        0xB0000000, 0xB9981020, 0x00000000, *([0xFC000000] * 5),
        0xB60F0008, 0x00000000,
    ))
    assert set(recovery.code) == {0x1000, 0x1004, 0x1008, 0x1020, 0x1024}


def test_indirect_call_has_fallthrough_and_unresolved_issue():
    recovery = recover_cfg(decoder_for(
        0x99FC7800, 0x00000000, 0xB60F0008, 0x00000000,
    ))
    function = recovery.functions[0x1000]
    assert function.blocks[0x1000].succs == [0x1008]
    assert [(issue.address, issue.reason) for issue in function.issues] == [
        (0x1000, "unresolved indirect call")
    ]


def test_invalid_and_truncated_paths_do_not_linear_sweep():
    invalid = recover_cfg(decoder_for(0xFC000000, 0x00000000))
    assert invalid.code == {}
    assert invalid.issues[0].reason == "invalid instruction"

    truncated = recover_cfg(MicroBlazeDecoder(b"\x00\x00", 0x1000))
    assert truncated.code == {}
    assert truncated.issues[0].reason == "entry outside image"
    assert truncated.unclassified_ranges == [(0x1000, 0x1002)]


def test_overlapping_explicit_entry_is_not_a_second_function():
    recovery = recover_cfg(decoder_for(
        0x30210001, 0xB60F0008, 0x00000000,
    ), [0x1000, 0x1004])
    assert set(recovery.functions) == {0x1000}
    assert any(issue.reason == "entry overlaps another function" for issue in recovery.issues)


def test_recovery_limits():
    with pytest.raises(ValueError, match="1 instructions"):
        recover_cfg(decoder_for(0x30210001, 0x00000000), max_instructions=1)
    with pytest.raises(ValueError, match="1 functions"):
        recover_cfg(decoder_for(
            0xB9F40010, 0x00000000, 0xB60F0008, 0x00000000,
            0xB60F0008, 0x00000000,
        ), max_functions=1)
    with pytest.raises(ValueError, match="positive"):
        recover_cfg(decoder_for(0), max_functions=0)
    with pytest.raises(ValueError, match="initial entry"):
        recover_cfg(decoder_for(0), entries=iter(range(3)), max_functions=2)
    with pytest.raises(ValueError, match="too many targets"):
        recover_cfg(decoder_for(0), jump_table_targets={0x1000: iter(range(5000))})


def test_bounded_jump_table_resolution_recovers_case_blocks():
    decoder = decoder_for(
        0x64630402, 0xB0000000, 0x30631030, 0xE8630000, 0x98081800,
        0xB60F0008, 0x00000000, 0xB60F0008, 0x00000000,
        0xFC000000, 0xFC000000, 0xFC000000, 0x1014, 0x101C,
    )
    initial = recover_cfg(decoder)
    targets = resolve_jump_tables(decoder, initial, {0x1010: JumpTableSpec(0x1030, 2)})
    recovery = recover_cfg(decoder, jump_table_targets=targets)

    assert targets == {0x1010: (0x1014, 0x101C)}
    assert recovery.functions[0x1000].blocks[0x1000].succs == [0x1014, 0x101C]
    assert set(recovery.code) == {0x1000, 0x1004, 0x1008, 0x100C, 0x1010, 0x1014, 0x1018, 0x101C, 0x1020}
    assert not any(issue.reason == "unresolved indirect jump" for issue in recovery.issues)


def test_jump_table_resolver_rejects_bad_pattern_and_target():
    decoder = decoder_for(0x98081800, 0xFC000000)
    recovery = recover_cfg(decoder)
    with pytest.raises(ValueError, match="invalid indirect-branch site"):
        resolve_jump_tables(decoder, recovery, {0x1000: JumpTableSpec(0x1000, 1)})

    decoder = decoder_for(
        0x64630402, 0xB0000000, 0x30631020, 0xE8630000, 0x98081800,
        0xFC000000, 0xFC000000, 0xFC000000, 0x2000,
    )
    recovery = recover_cfg(decoder)
    with pytest.raises(ValueError, match="target outside image"):
        resolve_jump_tables(decoder, recovery, {0x1010: JumpTableSpec(0x1020, 1)})


@pytest.mark.skipif(not os.path.isfile(_GCI_BOOT), reason="GEP boot PDI not found")
def test_real_gep_plm_recursive_recovery():
    pdi = VersalPdi.from_path(_GCI_BOOT)
    segments = sorted(
        (s for s in pdi.dma_write_segments() if 0xF6130000 <= s.address < 0xF6140000),
        key=lambda segment: segment.address,
    )
    image = b"".join(segment.data for segment in segments)
    decoder = MicroBlazeDecoder(image, 0xF6130000, byte_order="little")
    initial = recover_cfg(decoder, [0xF6130050])
    targets = resolve_jump_tables(decoder, initial, {
        0xF61311E8: JumpTableSpec(0xF6146DA4, 19, 0xF6110000),
        0xF613C664: JumpTableSpec(0xF6146DF4, 5, 0xF6110000),
    })
    recovery = recover_cfg(decoder, [0xF6130050], jump_table_targets=targets)

    assert len(initial.code) > 10000
    assert len(recovery.code) > len(initial.code)
    assert len(recovery.functions) > 50
    assert not any(issue.reason == "unresolved indirect jump" for issue in recovery.issues)
    assert set(recovery.code) <= set(range(0xF6130000, 0xF6146F80, 4))
    assert all(function.blocks for function in recovery.functions.values())
    assert all(insn.valid for insn in recovery.code.values())
    assert sum(len(function.instructions) for function in recovery.functions.values()) == len(recovery.code)
    assert sum(end - start for start, end in recovery.code_ranges) == 4 * len(recovery.code)
    assert sum(end - start for start, end in recovery.unclassified_ranges) == len(image) - 4 * len(recovery.code)
