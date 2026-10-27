import struct
from pathlib import Path

import pytest

from ablation.analyzers.mips_elf import inspect_mips_elf
from ablation.analyzers.mips_reg_annotator import MIPSRegAnnotator


def test_inspect_mips64r2_o32():
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 1
    header[5] = 2
    struct.pack_into(">H", header, 18, 8)
    struct.pack_into(">I", header, 36, 0x808B1101)

    info = inspect_mips_elf(bytes(header))

    assert info["bits"] == 32
    assert info["abi"] == "o32"
    assert info["isa"] == "mips64r2"
    assert info["big_endian"]


def test_operand_parser_normalizes_capstone_dollar_prefix():
    assert MIPSRegAnnotator._parts("$a0, $zero, 0x20") == ["a0", "zero", "0x20"]


@pytest.mark.integration
def test_real_junos_o32_profile():
    binary = Path("/media/cowboy/research/Juniper/srx/15.1X49/extracted/D170.4/junos-root-xorriso/usr/sbin/fwauthd")
    if not binary.exists():
        pytest.skip("SRX integration fixture is unavailable")
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.window_analyzer import WindowAnalyzer

    context = BinaryContext.build(str(binary))
    result = MIPSRegAnnotator.from_context(context).annotate_calls(0x4247D0, 0x424894)
    assert [call.target_name for call in result.calls] == ["pthread_mutex_init", "pthread_create", "usleep"]

    lines = WindowAnalyzer.from_path(str(binary)).dump(0x4247D0, window=196)
    assert any("jalr" in line for line in lines)
    assert not any("no data" in line for line in lines)
