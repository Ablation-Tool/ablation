"""Instruction-level dynamic validation for the CERN ARM64 shim."""

import struct
from pathlib import Path

import pytest

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, UC_PROT_ALL
    from unicorn.arm64_const import (
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X8,
        UC_ARM64_REG_X20,
    )
    _UNICORN_AVAILABLE = True
except ImportError:
    _UNICORN_AVAILABLE = False

_SHIM = (
    Path(__file__).parent.parent
    / "re/cern/gep_gcm4/rootfs/usr/bin/versalTcpIpbusShim"
)


@pytest.mark.skipif(not _UNICORN_AVAILABLE, reason="unicorn required")
@pytest.mark.skipif(not _SHIM.is_file(), reason="CERN GCM4 shim not extracted")
def test_gwic_length_prefix_drives_four_gigabyte_stack_adjustment():
    data = _SHIM.read_bytes()
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0, 0x100000, UC_PROT_ALL)
    uc.mem_write(0, data)
    uc.mem_map(0x10000000, 0x10000, UC_PROT_ALL)
    for base in (0x20000000, 0x30000000, 0x40000000):
        uc.mem_map(base, 0x1000, UC_PROT_ALL)

    uc.mem_write(0x1FF98, struct.pack("<Q", 0x40000000))
    uc.mem_write(0x40000000, struct.pack("<Q", 0x1122334455667788))
    uc.mem_write(0x20000000, struct.pack("<I", 1))
    uc.reg_write(UC_ARM64_REG_X0, 0x20000000)
    uc.reg_write(UC_ARM64_REG_X1, 0xFFFFFFFF)
    uc.reg_write(UC_ARM64_REG_X8, 0x30000000)
    uc.reg_write(UC_ARM64_REG_SP, 0x10010000)
    captured = {}

    def hook(uc, address, size, user_data):
        if address == 0x5FE8:
            captured["frame_sp"] = uc.reg_read(UC_ARM64_REG_SP)
        elif address == 0x2050:
            captured["recv_size"] = uc.reg_read(UC_ARM64_REG_X2)
            captured["recv_sp"] = uc.reg_read(UC_ARM64_REG_SP)
            uc.reg_write(UC_ARM64_REG_X0, uc.reg_read(UC_ARM64_REG_X20))
            uc.reg_write(UC_ARM64_REG_PC, 0x6014)

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(0x5FC0, 0x6014, count=1000)

    allocation = (captured["frame_sp"] - captured["recv_sp"]) & 0xFFFFFFFFFFFFFFFF
    assert captured["recv_size"] == 0xFFFFFFFF
    assert allocation == 0x100000000
