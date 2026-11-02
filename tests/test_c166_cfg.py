from pathlib import Path

import pytest

from ablation.analyzers.c166_cfg import direct_data_xref, recover_c166_cfg
from ablation.analyzers.ecu_c166_decoder import EcuC166Decoder


A1396 = Path('/media/cowboy/research/CERN/analysis/edms-firmware/a1396.bin')


def decoder_with(words: dict[int, str], *, base: int = 0x20000, size: int = 0x60) -> EcuC166Decoder:
    image = bytearray(size)
    for address, raw in words.items():
        data = bytes.fromhex(raw)
        offset = address - base
        image[offset:offset + len(data)] = data
    return EcuC166Decoder(bytes(image), base)


def test_recursive_cfg_discovers_calls_and_excludes_unreachable_bytes():
    decoder = decoder_with({
        0x20000: 'da024000',
        0x20004: '3d02',
        0x20006: 'f3f8fe84',
        0x2000A: 'ea001200',
        0x2000E: 'f7f8fe84',
        0x20010: '0d00',
        0x20012: 'cb00',
        0x20040: 'f7f8fe84',
        0x20044: 'db00',
    })

    recovery = recover_c166_cfg(decoder, [0x20000])

    assert set(recovery.functions) == {0x20000, 0x20040}
    assert set(recovery.code) == {
        0x20000, 0x20004, 0x20006, 0x2000A, 0x20012, 0x20040, 0x20044,
    }
    assert 0x2000E not in recovery.code
    assert recovery.functions[0x20000].calls == {0x20000: 0x20040}
    assert recovery.functions[0x20000].blocks[0x2000A].succs == [0x20012]
    assert [xref.access for xref in recovery.xrefs_to(0x84FE)] == ['read', 'write']
    assert recovery.data_xrefs[0].instruction == 0x20006
    assert recovery.data_xrefs[0].dpp_index == 2
    assert recovery.data_xrefs[0].page_offset == 0x04FE


def test_direct_xref_classes_exclude_immediates_and_indirect_accesses():
    decoder = decoder_with({
        0x20000: '05f88883',
        0x20004: 'e6f5fe84',
        0x20008: '64f50480',
        0x2000C: 'f68efe84',
        0x20010: 'b9a4',
        0x20012: 'cb00',
    }, size=0x20)

    recovery = recover_c166_cfg(decoder, [0x20000])

    assert [(xref.instruction, xref.address, xref.access) for xref in recovery.data_xrefs] == [
        (0x20000, 0x8388, 'read_write'),
        (0x20008, 0x8004, 'read_write'),
        (0x2000C, 0x84FE, 'write'),
    ]
    assert direct_data_xref(recovery.code[0x20004]) is None
    assert direct_data_xref(recovery.code[0x20010]) is None


def test_unresolved_indirect_conditional_branch_has_fallthrough():
    recovery = recover_c166_cfg(decoder_with({
        0x20000: '9c34',
        0x20002: 'cb00',
    }), [0x20000])

    assert set(recovery.code) == {0x20000, 0x20002}
    assert [(issue.address, issue.reason) for issue in recovery.issues] == [
        (0x20000, 'unresolved conditional branch'),
    ]


def test_unresolved_indirect_unconditional_jump_has_no_fallthrough():
    recovery = recover_c166_cfg(decoder_with({
        0x20000: '9c04',
        0x20002: 'cb00',
    }), [0x20000])

    assert set(recovery.code) == {0x20000}
    assert recovery.issues[0].reason == 'unresolved indirect jump'


def test_unknown_instruction_is_explicit_but_does_not_invent_a_control_transfer():
    recovery = recover_c166_cfg(decoder_with({
        0x20000: 'ff00',
        0x20002: 'cb00',
    }), [0x20000])

    assert set(recovery.code) == {0x20000, 0x20002}
    assert recovery.issues[0].reason == 'unknown instruction encoding; linear decoding retained'
    assert recovery.functions[0x20000].blocks[0x20000].succs == []


def test_overlapping_entry_is_reported_without_duplicating_function_code():
    recovery = recover_c166_cfg(decoder_with({
        0x20000: 'da020800',
        0x20004: 'cb00',
        0x20008: 'db00',
    }), [0x20000, 0x20004])

    assert set(recovery.functions) == {0x20000, 0x20008}
    assert any(issue.reason == 'entry overlaps another function' for issue in recovery.issues)


def test_limits_and_empty_entries_fail_closed():
    decoder = decoder_with({
        0x20000: 'da020800',
        0x20004: 'cb00',
        0x20008: 'db00',
    })
    with pytest.raises(ValueError, match='1 instructions'):
        recover_c166_cfg(decoder, [0x20000], max_instructions=1)
    with pytest.raises(ValueError, match='1 functions'):
        recover_c166_cfg(decoder, [0x20000], max_functions=1)
    with pytest.raises(ValueError, match='at least one'):
        recover_c166_cfg(decoder, [])
    with pytest.raises(ValueError, match='positive'):
        recover_c166_cfg(decoder, [0x20000], max_issues=0)


def test_entry_outside_image_and_metadata_ranges():
    decoder = decoder_with({0x20000: 'cb00'}, size=2)
    recovery = recover_c166_cfg(decoder, [0x1FFFE])

    assert recovery.code == {}
    assert recovery.issues[0].reason == 'entry outside image'
    assert recovery.unclassified_ranges == [(0x20000, 0x20002)]
    assert decoder.contains_pa(0x20000)
    assert not decoder.contains_pa(0x20001)
    assert decoder.base_pa == 0x20000
    assert decoder.image_size == 2
    with pytest.raises(ValueError, match='positive'):
        decoder.contains_pa(0x20000, 0)


def test_json_export_is_stable_and_includes_unclassified_ranges():
    recovery = recover_c166_cfg(decoder_with({0x20000: 'cb00'}, size=4), [0x20000])
    payload = recovery.to_dict()

    assert payload['schema'] == 'ablation.c166-recovery.v1'
    assert payload['coverage']['instructions'] == 1
    assert payload['coverage']['code_ranges'] == [['0x020000', '0x020002']]
    assert payload['coverage']['unclassified_ranges'] == [['0x020002', '0x020004']]
    assert payload['functions'][0]['blocks'][0]['instructions'][0]['raw'] == 'cb 00'


@pytest.mark.skipif(not A1396.is_file(), reason='A1396 analysis image not available')
def test_real_a1396_update_dispatch_and_state_xrefs():
    recovery = recover_c166_cfg(EcuC166Decoder(A1396), [0x237B2])

    assert {0x24792, 0x24802, 0x24868, 0x2487A, 0x248A4} <= set(recovery.code)
    accesses = {(xref.instruction, xref.access) for xref in recovery.xrefs_to(0x84FE)}
    assert (0x247E6, 'write') in accesses
    assert (0x24868, 'read') in accesses
    assert recovery.functions[0x237B2].instructions
