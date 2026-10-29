import struct

import pytest

from ablation.analyzers.mips_string_xrefs import MIPSStringXrefResolver


def test_resolver_recovers_pic_function_start_after_invalid_word():
    resolver = MIPSStringXrefResolver.__new__(MIPSStringXrefResolver)
    resolver._big_endian = True
    resolver._text_va = 0x400000
    resolver._text_data = b"".join([
        b"\xff\xff\xff\xff",
        struct.pack(">I", 0x3C1C0016),
        struct.pack(">I", 0x279CF1A0),
        struct.pack(">I", 0x0399E021),
        struct.pack(">I", 0x3C051ACC),
        struct.pack(">I", 0x24A5CA7C),
    ])
    import capstone
    resolver._decoder = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN)
    resolver._decoder.skipdata = True
    resolver._rodata_ranges = [(0x1ACB0000, 0x1ACC0000)]
    resolver._loads = []

    results = resolver.resolve({0x1ACBCA7C})

    assert len(results) == 1
    assert results[0].function_va == 0x400004
    assert results[0].instruction_va == 0x400014
    assert results[0].register == "a1"
    assert results[0].string_va == 0x1ACBCA7C


@pytest.mark.integration
def test_real_flowd_vrf_string_xrefs():
    from pathlib import Path
    binary = Path("/media/cowboy/research/Juniper/srx/15.1X49/extracted/D170.4/junos-root-xorriso/usr/sbin/flowd_octeon")
    if not binary.exists():
        pytest.skip("SRX integration fixture is unavailable")

    results = MIPSStringXrefResolver(binary).resolve({0x1ACBCA7C, 0x1ACBCAB4, 0x1ACBCAF4, 0x1ACBCC48, 0x1ACBCEAC})

    assert len(results) == 7
    assert all(result.function_va != 0 for result in results)
    assert {result.string_va for result in results} == {0x1ACBCA7C, 0x1ACBCAB4, 0x1ACBCAF4, 0x1ACBCC48, 0x1ACBCEAC}
    assert any(result.function_va == 0x18822420 for result in results)
