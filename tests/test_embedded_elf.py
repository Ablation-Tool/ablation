import struct

import pytest

from ablation.analyzers.embedded_elf import find_embedded_elf
from ablation.analyzers.versal_pdi import VersalPdi


def elf_header(bits=64, byte_order="little", machine=62):
    endian = "<" if byte_order == "little" else ">"
    ident = b"\x7fELF" + bytes((bits // 32, 1 if byte_order == "little" else 2, 1)) + bytes(9)
    if bits == 32:
        return ident + struct.pack(
            f"{endian}HHIIIIIHHHHHH", 2, machine, 1, 0, 0, 0, 0, 52, 32, 0, 40, 0, 0
        )
    return ident + struct.pack(
        f"{endian}HHIQQQIHHHHHH", 2, machine, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0
    )


def test_discovers_elf64_and_exact_payload():
    data = b"prefix" + elf_header() + b"trailing"
    results = find_embedded_elf(data)
    assert len(results) == 1
    result = results[0]
    assert result.offset == 6
    assert result.bits == 64
    assert result.architecture == "x86-64"
    assert result.byte_order == "little"
    assert result.payload == elf_header()


def test_discovers_big_endian_elf32():
    data = elf_header(32, "big", 20)
    result = find_embedded_elf(data)[0]
    assert result.bits == 32
    assert result.architecture == "PowerPC"
    assert result.byte_order == "big"


def test_rejects_magic_truncation_and_bad_tables():
    assert find_embedded_elf(b"\x7fELF" + bytes(20)) == []
    header = bytearray(elf_header())
    struct.pack_into("<Q", header, 32, 0x1000)
    struct.pack_into("<H", header, 56, 1)
    assert find_embedded_elf(bytes(header)) == []


def test_total_payload_limit(monkeypatch):
    import ablation.analyzers.embedded_elf as module
    monkeypatch.setattr(module, "MAX_TOTAL_PAYLOAD_BYTES", 100)
    with pytest.raises(ValueError, match="total size limit"):
        find_embedded_elf(elf_header() + elf_header())


def test_real_transceiver_has_no_embedded_elf():
    import os
    for index in range(1, 10):
        suffix = f"_{index}" if index > 1 else ""
        path = f"/media/cowboy/research/CERN/fw/gep/transceiver_versal_interlaken_exdes_vio{suffix}.pdi"
        if not os.path.isfile(path):
            pytest.skip("transceiver PDI not found")
        assert VersalPdi.from_path(path).embedded_elf() == []
