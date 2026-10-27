import os
import struct

import pytest

from ablation.analyzers.microblaze_cfg import (
    JumpTableSpec,
    no_return_addresses,
    recover_cfg,
    resolve_jump_tables,
)
from ablation.analyzers.microblaze_decoder import MicroBlazeDecoder
from ablation.analyzers.microblaze_xrefs import direct_memory_references, reference_neighbors
from ablation.analyzers.versal_pdi import VersalPdi


_GCI_BOOT = "/media/cowboy/research/CERN/fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi"


def decoder_for(*words: int, base: int = 0x1000) -> MicroBlazeDecoder:
    return MicroBlazeDecoder(b"".join(struct.pack(">I", word) for word in words), base)


def test_absolute_references_and_neighbors():
    recovery = recover_cfg(decoder_for(
        0xB0000001, 0x30A02000, 0xB0000001, 0x30603000, 0xB0000001,
        0xF8004000, 0xB60F0008, 0x00000000,
    ))
    references = direct_memory_references(recovery)

    assert set(references) == {0x12000, 0x13000, 0x14000}
    assert references[0x14000][0].mnemonic == "swi"
    neighbors = reference_neighbors(references, 0x13000)
    assert (neighbors.lower, neighbors.upper) == (0x12000, 0x14000)
    assert set(direct_memory_references(recovery, 0x12000, 0x13000)) == {0x12000}
    with pytest.raises(ValueError, match="32-bit"):
        direct_memory_references(recovery, 4, 4)


@pytest.mark.skipif(not os.path.isfile(_GCI_BOOT), reason="GEP boot PDI not found")
def test_real_plm_memory_layout_and_sources():
    pdi = VersalPdi.from_path(_GCI_BOOT)
    segments = sorted(pdi.dma_write_segments(), key=lambda segment: segment.address)
    code_segments = [
        segment for segment in segments if 0xF6130000 <= segment.address < 0xF6140000
    ]
    decoder = MicroBlazeDecoder(
        b"".join(segment.data for segment in code_segments), 0xF6130000, byte_order="little"
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
    references = direct_memory_references(recovery, 0x1C000, 0x20000)

    assert len(references[0x1C4F8]) == 3
    assert reference_neighbors(references, 0x1C4F8).upper == 0x1C5D0
    assert 0x1C5D0 - 0x1C4F8 == 216
    assert len(references[0x1C658]) == 1
    assert reference_neighbors(references, 0x1C658).upper == 0x1C683
    assert 0x1C683 - 0x1C658 == 43

    bss = next(segment for segment in segments if segment.address == 0xF612C000)
    assert len(bss.data) == 0x4000
    assert sum(byte != 0 for byte in bss.data) == 37
    assert bss.data[0x50:0x50 + 0x28] == bytes(0x28)
    assert bss.data[0x4F8:0x4F8 + 216] == bytes(216)
    assert bss.data[0x658:0x658 + 43] == bytes(43)
    assert bss.data[0x8C4:0x8C4 + 72] == bytes(72)
    table_source = decoder._data[0x36D60 - 0x20000:0x36D60 - 0x20000 + 43]
    assert len(table_source) == 43
    assert any(byte < 32 or byte >= 127 for byte in table_source)
    assert not any(
        segment.address <= 0xF6110000 < segment.end_address for segment in segments
    )
    assert sum(issue.reason == "unresolved indirect call" for issue in recovery.issues) == 6
