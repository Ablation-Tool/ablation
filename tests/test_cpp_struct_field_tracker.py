"""Tests for CppStructFieldTracker.

Synthetic known-positive:
  Minimal x86-64 function (hand-assembled) with:
    lea rdi, [rbx + 0x50]       ; src field
    call c_str_va
    mov rsi, rax
    lea rdi, [rbx + 0x100]      ; dst field
    call assign_va
    ret
  Expected: one FieldFlow with src_offset=0x50, dst_offset=0x100, carrier='rax'.

Integration known-positive (PanGPS 6.3.3-c42):
  fn@0xe9850 ('RecvFromSocket') — 3 c_str→assign chains copying string fields
  from rbx-based struct to r14-based struct.
  VAs byte-verified 2026-10-26:
    flow 1: c_str@0xe9bde → call 0x83e90  assign@0xe9bed → call 0x838c0
    flow 2: c_str@0xe9df1 → call 0x83e90  assign@0xe9e00 → call 0x838c0
    flow 3: c_str@0xea00e → call 0x83e90  assign@0xea01d → call 0x838c0
"""

import struct
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ablation.analyzers.cpp_struct_field_tracker import CppStructFieldTracker

PANGPS = '/tmp/pangp_re/6.3.3-c42/extracted/opt/paloaltonetworks/globalprotect/PanGPS'
PANGPS_CSTR_VA   = 0x83e90
PANGPS_ASSIGN_VA = 0x838c0


# ── Synthetic binary fixture ──────────────────────────────────────────────────

def _build_synthetic_binary() -> bytes:
    """
    Build a minimal x86-64 byte string containing:
      - Function at VA 0x1000 with one c_str→assign chain
      - c_str PLT stub at VA 0x2000
      - assign PLT stub at VA 0x2010

    Instruction layout (hand-assembled, VAs are file offsets = VAs for PIE base=0):

      0x1000  48 8D 7B 50          lea rdi, [rbx + 0x50]
      0x1004  E8 F7 0F 00 00       call 0x2000   ; c_str
      0x1009  48 89 C6             mov rsi, rax
      0x100C  48 8D BB 00 01 00 00 lea rdi, [rbx + 0x100]
      0x1013  E8 F8 0F 00 00       call 0x2010   ; assign
      0x1018  C3                   ret
    """
    size = 0x2020
    buf = bytearray(size)

    fn_off = 0x1000
    c_str_off = 0x2000
    assign_off = 0x2010

    fn_bytes = (
        b'\x48\x8D\x7B\x50'             # lea rdi, [rbx + 0x50]
        b'\xE8' + struct.pack('<i', c_str_off - (fn_off + 4 + 5))   # call c_str
        + b'\x48\x89\xC6'               # mov rsi, rax
        + b'\x48\x8D\xBB\x00\x01\x00\x00'  # lea rdi, [rbx + 0x100]
        + b'\xE8' + struct.pack('<i', assign_off - (fn_off + 4 + 5 + 3 + 7 + 5))  # call assign
        + b'\xC3'                        # ret
    )

    buf[fn_off: fn_off + len(fn_bytes)] = fn_bytes
    # PLT stubs — just NOP sleds; they are never disassembled by the tracker
    buf[c_str_off] = 0x90    # nop
    buf[assign_off] = 0x90   # nop
    return bytes(buf)


class MockCtx:
    """Minimal BinaryContext stand-in for unit tests."""

    def __init__(self, path: str, func_starts, plt):
        self.path = path
        self.func_starts = list(func_starts)
        self.plt = dict(plt)


# ── Unit tests: synthetic binary ─────────────────────────────────────────────

class TestSynthetic:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        binary = _build_synthetic_binary()
        self._elf = str(tmp_path / 'synthetic.bin')
        Path(self._elf).write_bytes(binary)
        ctx = MockCtx(
            path=self._elf,
            func_starts=[0x1000],
            plt={0x2000: 'c_str', 0x2010: 'assign'},
        )
        self._tracker = CppStructFieldTracker.from_context(
            ctx, c_str_va=0x2000, assign_va=0x2010
        )

    def test_finds_one_flow(self):
        flows = self._tracker.find_flows()
        assert len(flows) == 1, f'expected 1 flow, got {len(flows)}: {flows}'

    def test_src_offset(self):
        flows = self._tracker.find_flows()
        assert flows[0].src_offset == 0x50

    def test_dst_offset(self):
        flows = self._tracker.find_flows()
        assert flows[0].dst_offset == 0x100

    def test_carrier_is_rax(self):
        flows = self._tracker.find_flows()
        assert flows[0].carrier_reg == 'rax'

    def test_src_base_is_rbx(self):
        flows = self._tracker.find_flows()
        assert flows[0].src_base_reg == 'rbx'

    def test_dst_base_is_rbx(self):
        flows = self._tracker.find_flows()
        assert flows[0].dst_base_reg == 'rbx'

    def test_owning_fn(self):
        flows = self._tracker.find_flows()
        assert flows[0].fn_va == 0x1000

    def test_src_call_va(self):
        flows = self._tracker.find_flows()
        assert flows[0].src_call_va == 0x1004

    def test_dst_call_va(self):
        flows = self._tracker.find_flows()
        assert flows[0].dst_call_va == 0x1013

    def test_flows_to_offset_filter(self):
        assert len(self._tracker.flows_to_offset(0x100)) == 1
        assert len(self._tracker.flows_to_offset(0x999)) == 0

    def test_flows_from_offset_filter(self):
        assert len(self._tracker.flows_from_offset(0x50)) == 1
        assert len(self._tracker.flows_from_offset(0x99)) == 0

    def test_report_non_empty(self):
        flows = self._tracker.find_flows()
        report = self._tracker.report(flows)
        assert '1 flow' in report
        assert '0x50' in report
        assert '0x100' in report


# ── Integration tests: PanGPS 6.3.3-c42 ─────────────────────────────────────

def _has_pangps():
    return Path(PANGPS).exists()


@pytest.mark.skipif(not _has_pangps(), reason='PanGPS 6.3.3-c42 binary not extracted')
class TestPanGPS:
    @pytest.fixture(autouse=True)
    def _setup(self):
        from ablation.analyzers.binary_context import BinaryContext
        ctx = BinaryContext.load_or_build(PANGPS)
        self._tracker = CppStructFieldTracker.from_context(
            ctx, c_str_va=PANGPS_CSTR_VA, assign_va=PANGPS_ASSIGN_VA
        )
        self._flows = self._tracker.find_flows()

    def test_finds_three_flows(self):
        assert len(self._flows) == 3, (
            f'expected 3 flows in PanGPS, got {len(self._flows)}'
        )

    def test_all_flows_in_recv_from_socket(self):
        fn_vas = {f.fn_va for f in self._flows}
        assert fn_vas == {0xe9850}, f'unexpected owning functions: {[hex(v) for v in fn_vas]}'

    def test_flow1_src_offset(self):
        offsets = {f.src_offset for f in self._flows}
        assert 0xd78 in offsets, f'0xd78 not in {[hex(o) for o in offsets]}'

    def test_flow2_src_offset(self):
        offsets = {f.src_offset for f in self._flows}
        assert 0xd38 in offsets, f'0xd38 not in {[hex(o) for o in offsets]}'

    def test_flow3_src_offset(self):
        offsets = {f.src_offset for f in self._flows}
        assert 0xd58 in offsets, f'0xd58 not in {[hex(o) for o in offsets]}'

    def test_all_flows_write_to_same_dst(self):
        dst_offsets = {f.dst_offset for f in self._flows}
        assert dst_offsets == {0xbb8}, f'unexpected dst offsets: {[hex(o) for o in dst_offsets]}'

    def test_flow1_call_vas_byte_verified(self):
        f = next(f for f in self._flows if f.src_call_va == 0xe9bde)
        assert f.dst_call_va == 0xe9bed

    def test_flow2_call_vas_byte_verified(self):
        f = next(f for f in self._flows if f.src_call_va == 0xe9df1)
        assert f.dst_call_va == 0xe9e00

    def test_flow3_call_vas_byte_verified(self):
        f = next(f for f in self._flows if f.src_call_va == 0xea00e)
        assert f.dst_call_va == 0xea01d

    def test_report_lists_flows(self):
        report = self._tracker.report(self._flows)
        assert '3 flow' in report
        assert '0xe9850' in report
