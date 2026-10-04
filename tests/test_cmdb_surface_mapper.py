"""Unit and integration tests for CMDBSurfaceMapper."""

import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ablation.analyzers.cmdb_surface_mapper import (
    CMDBSurfaceMapper,
    CMDBTableEntry,
    _EM_X86_64,
)

# ── helpers to build minimal x86-64 ELF stubs ──────────────────────────────

def _elf_header(e_machine: int = _EM_X86_64) -> bytes:
    """64-byte minimal ELF header (enough for arch checks)."""
    hdr = bytearray(64)
    hdr[0:4] = b'\x7fELF'  # magic
    hdr[4] = 2              # EI_CLASS = ELFCLASS64
    hdr[5] = 1              # EI_DATA = ELFDATA2LSB
    hdr[6] = 1              # EI_VERSION
    struct.pack_into('<H', hdr, 18, e_machine)
    return bytes(hdr)


# ── _extract_rdi ─────────────────────────────────────────────────────────────

class _FakeInsn:
    def __init__(self, mnemonic, op_str):
        self.mnemonic = mnemonic
        self.op_str = op_str


def test_extract_rdi_mov_edi_hex():
    insns = [
        _FakeInsn("push", "rbp"),
        _FakeInsn("mov", "edi, 0x427c"),
        _FakeInsn("call", "0x1000"),
    ]
    result = CMDBSurfaceMapper._extract_rdi(insns, 2)
    assert result == 0x427c


def test_extract_rdi_mov_rdi_hex():
    insns = [
        _FakeInsn("mov", "rdi, 0x4290"),
        _FakeInsn("call", "0x1000"),
    ]
    result = CMDBSurfaceMapper._extract_rdi(insns, 1)
    assert result == 0x4290


def test_extract_rdi_xor_zero():
    """xor edi, edi → table_id = 0 (not None)."""
    insns = [
        _FakeInsn("xor", "edi, edi"),
        _FakeInsn("call", "0x1000"),
    ]
    result = CMDBSurfaceMapper._extract_rdi(insns, 1)
    assert result == 0


def test_extract_rdi_no_rdi_set_returns_none():
    """When no rdi-loading instruction is found, must return None — not crash."""
    insns = [
        _FakeInsn("push", "rbp"),
        _FakeInsn("mov", "rax, 0x1234"),
        _FakeInsn("call", "0x1000"),
    ]
    result = CMDBSurfaceMapper._extract_rdi(insns, 2)
    assert result is None


def test_extract_rdi_beyond_window_returns_none():
    """rdi set more than 20 instructions before the call is not resolved."""
    insns = [_FakeInsn("push", "rbp")] * 25
    insns[0] = _FakeInsn("mov", "edi, 0x1234")
    insns.append(_FakeInsn("call", "0x1000"))
    result = CMDBSurfaceMapper._extract_rdi(insns, len(insns) - 1)
    assert result is None


def test_extract_rdi_only_last_write_counts():
    """When rdi is overwritten, the most recent assignment wins."""
    insns = [
        _FakeInsn("mov", "edi, 0x1111"),
        _FakeInsn("push", "rdi"),
        _FakeInsn("mov", "edi, 0x2222"),
        _FakeInsn("call", "0x1000"),
    ]
    result = CMDBSurfaceMapper._extract_rdi(insns, 3)
    assert result == 0x2222


# ── _validate_arch ───────────────────────────────────────────────────────────

def test_validate_arch_x86_64_ok():
    data = _elf_header(_EM_X86_64) + b'\x00' * 100
    mapper = CMDBSurfaceMapper(data)
    mapper._validate_arch()  # must not raise


def test_validate_arch_arm64_raises():
    data = _elf_header(0xB7) + b'\x00' * 100  # EM_AARCH64 = 0xB7
    mapper = CMDBSurfaceMapper(data)
    with pytest.raises(ValueError, match="x86-64"):
        mapper._validate_arch()


def test_validate_arch_non_elf_raises():
    mapper = CMDBSurfaceMapper(b'\x00' * 64)
    with pytest.raises(ValueError, match="not an ELF"):
        mapper._validate_arch()


def test_validate_arch_too_short_raises():
    mapper = CMDBSurfaceMapper(b'\x7fELF\x00')
    with pytest.raises(ValueError, match="too short"):
        mapper._validate_arch()


# ── report ───────────────────────────────────────────────────────────────────

def test_report_empty():
    text = CMDBSurfaceMapper.report({})
    assert "no cmdb tables" in text.lower()


def test_report_no_exec_reach():
    e = CMDBTableEntry("waf_policy")
    e.callers = [0x1000]
    e.field_read_count = 3
    text = CMDBSurfaceMapper.report({0x1000: e})
    assert "Tables mapped: 1" in text
    assert "Callers reach exec sink: 0" in text
    assert "REACHES EXEC" not in text


def test_report_exec_reach_flagged():
    e = CMDBTableEntry("auth_saml")
    e.callers = [0x5a930]
    e.reaches_exec = True
    e.exec_func_va = 0x5a930
    e.exec_call_va = 0x5ad1a
    e.exec_sink_name = "system"
    text = CMDBSurfaceMapper.report({0x6000: e})
    assert "Callers reach exec sink: 1" in text
    assert "REACHES EXEC SINK" in text
    assert "0x5ad1a" in text
    assert "system()" in text


def test_report_exec_tables_sorted_first():
    e_clean = CMDBTableEntry("table_clean")
    e_clean.callers = [0x1000]

    e_exec = CMDBTableEntry("table_exec")
    e_exec.callers = [0x2000]
    e_exec.reaches_exec = True
    e_exec.exec_func_va = 0x2000
    e_exec.exec_call_va = 0x2100
    e_exec.exec_sink_name = "system"

    # exec table should appear before clean table in report
    text = CMDBSurfaceMapper.report({0xAAAA: e_clean, 0xBBBB: e_exec})
    assert text.index("table_exec") < text.index("table_clean")


def test_report_contains_co_location_warning():
    """The co-location limitation disclaimer must always appear in reports."""
    text = CMDBSurfaceMapper.report({})
    # Even empty report has the warning
    assert "co-location" in text.lower() or "not verified" in text.lower()


# ── integration test: cmdbsvr FortiWeb 7.4.3 ────────────────────────────────
# Skipped automatically if the binary is not present (CI / fresh checkout).

CMDBSVR = "/tmp/fwb743/rootfs_mount/bin/cmdbsvr"

@pytest.mark.skipif(
    not Path(CMDBSVR).exists(),
    reason=f"{CMDBSVR} not present"
)
def test_integration_cmdbsvr_table_count():
    """cmdbsvr must produce ≥19 CMDB tables."""
    mapper = CMDBSurfaceMapper.from_path(CMDBSVR)
    surface = mapper.map()
    assert len(surface) >= 19, f"expected ≥19 tables, got {len(surface)}"


@pytest.mark.skipif(
    not Path(CMDBSVR).exists(),
    reason=f"{CMDBSVR} not present"
)
def test_integration_cmdbsvr_table_0x226_present():
    """Table 0x226 (automation_action_exec) must be in the surface map.
    Note: reaches_exec is False for cmdbsvr — the caller (0x45020) and the
    execvp at 0x44fcd are in different functions.  All cmdbsvr exec-reach
    sites were eliminated during the FortiWeb 7.4.3 RE session."""
    mapper = CMDBSurfaceMapper.from_path(CMDBSVR)
    surface = mapper.map()
    assert 0x226 in surface, "Table 0x226 not found in surface map"
    # The table is in the surface but in a different function from execvp.
    # reaches_exec == False here is the CORRECT result.
    assert surface[0x226].callers, "Table 0x226 should have at least one caller"


LIBCMDB = "/tmp/fwb743/rootfs_mount/lib/libcmdb_plugin.so"

@pytest.mark.skipif(
    not Path(LIBCMDB).exists(),
    reason=f"{LIBCMDB} not present"
)
def test_integration_libcmdb_krb_exec_reach():
    """
    libcmdb_plugin.so contains FWB-KRB-1: the Kerberos auth_saml table
    (0x6000) must have a caller that co-locates system() — this is the
    origin signal that led to FWB-KRB-1 CONFIRMED.
    """
    mapper = CMDBSurfaceMapper.from_path(LIBCMDB)
    surface = mapper.map()
    exec_tables = [tid for tid, e in surface.items() if e.reaches_exec]
    assert exec_tables, "libcmdb_plugin.so: expected ≥1 exec-reach table (FWB-KRB-1 origin)"


SAMLD = "/tmp/fwb743/rootfs_mount/bin/samld"

@pytest.mark.skipif(
    not Path(SAMLD).exists(),
    reason=f"{SAMLD} not present"
)
def test_integration_samld_no_cmdb():
    """samld has no cmf_query_create in PLT — must return empty dict cleanly."""
    mapper = CMDBSurfaceMapper.from_path(SAMLD)
    surface = mapper.map()
    assert surface == {}, f"samld should return empty surface, got {list(surface.keys())}"
