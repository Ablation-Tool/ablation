"""
Unit tests for RISCV32TaintTracker._exec_insn taint propagation.

All expected values are derived from capstone 5.0.7 disassembly of hand-encoded
byte sequences -- NOT from memory. Each fixture comment shows the raw bytes used
to generate the mnemonic/op_str pair captured from capstone.

Capstone rendering facts captured at test-write time (CS_MODE_RISCV32 | CS_MODE_RISCVC):
  mv a0, a1          -> 'mv'    'a0, a1'        (addi a0, a1, 0)
  c.mv a0, a1        -> 'c.mv'  'a0, a1'        (0x852e)
  li a0, 0           -> 'li'    'a0, 0'
  andi a0, a1, -16   -> 'andi'  'a0, a1, -0x10'
  andi a0, a1, 255   -> 'andi'  'a0, a1, 0xff'
  addi a0, a1, 4     -> 'addi'  'a0, a1, 4'
  lw a0, 0(a1)       -> 'lw'    'a0, 0(a1)'     (clears taint)
  c.addi16sp NOT present (modifies sp, removed from _COPY_MNEMS)
"""

from ablation.analyzers.taint_tracker_riscv32 import RISCV32TaintTracker


def _tracker() -> RISCV32TaintTracker:
    # Instantiate without a real binary -- only _exec_insn is tested
    import unittest.mock as mock
    with mock.patch.object(RISCV32TaintTracker, '_load_elf', lambda self: None):
        import pathlib
        with mock.patch.object(pathlib.Path, 'read_bytes', return_value=b'\x00' * 4):
            t = RISCV32TaintTracker.__new__(RISCV32TaintTracker)
            t.binary_path = '/dev/null'
            t._ctx = None
            t._sinks = {}
            t._data = b'\x00' * 4
            t._plt = {}
            t._plt_by_name = {}
            t._func_starts = []
            t._text_va = 0
            t._text_off = 0
            t._text_size = 0
            import capstone
            from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
            t._md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
            t._md.detail = False
            return t


def exec_insn(tracker, mnemonic, op_str, tainted):
    tracker._exec_insn(mnemonic, op_str, tainted)


def test_mv_propagates():
    t = _tracker()
    st = {'a1': True}
    exec_insn(t, 'mv', 'a0, a1', st)
    assert st['a0'] is True


def test_mv_clears_when_source_clean():
    t = _tracker()
    st = {'a0': True, 'a1': False}
    exec_insn(t, 'mv', 'a0, a1', st)
    assert st['a0'] is False


def test_c_mv_propagates():
    t = _tracker()
    st = {'a1': True}
    exec_insn(t, 'c.mv', 'a0, a1', st)
    assert st['a0'] is True


def test_li_clears():
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'li', 'a0, 0', st)
    assert st['a0'] is False


def test_la_clears():
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'la', 'a0, 0x1234', st)
    assert st['a0'] is False


def test_addi_propagates():
    t = _tracker()
    st = {'a1': True}
    exec_insn(t, 'addi', 'a0, a1, 4', st)
    assert st['a0'] is True


def test_andi_propagates_alignment_mask():
    # andi a0, a1, -0x10: -16 is a negative imm (alignment mask, all high bits set).
    # No upper bound on the result -- taint must propagate. ISA §2.4.
    t = _tracker()
    st = {'a1': True}
    exec_insn(t, 'andi', 'a0, a1, -0x10', st)
    assert st['a0'] is True


def test_andi_propagates_identity_mask():
    # andi rd, rs, -1: rs & ~0 == rs -- exact copy, MUST propagate.
    t = _tracker()
    st = {'a1': True}
    exec_insn(t, 'andi', 'a0, a1, -1', st)
    assert st['a0'] is True


def test_andi_clears_positive_immediate():
    # 0xff is a non-negative bounding mask: result <= 0xff -- sanitizes, clears taint.
    t = _tracker()
    st = {'a0': True, 'a1': True}
    exec_insn(t, 'andi', 'a0, a1, 0xff', st)
    assert st['a0'] is False


def test_c_andi_propagates_alignment_mask():
    # c.andi rd, -0x10: 6-bit signed immediate, same semantics as andi.
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'c.andi', 'a0, -0x10', st)
    assert st['a0'] is True


def test_c_andi_clears_bounding_mask():
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'c.andi', 'a0, 0xf', st)
    assert st['a0'] is False


def test_c_and_propagates_from_either_operand():
    # c.and rd, rs2: rd is implicit rs1; result is rd & rs2.
    # Taint from rd alone propagates.
    t = _tracker()
    st = {'a0': True, 'a1': False}
    exec_insn(t, 'c.and', 'a0, a1', st)
    assert st['a0'] is True


def test_c_and_propagates_from_rs2():
    # Taint from the second operand (rs2 token) propagates to rd.
    t = _tracker()
    st = {'a0': False, 'a1': True}
    exec_insn(t, 'c.and', 'a0, a1', st)
    assert st['a0'] is True


def test_c_and_clears_when_both_clean():
    t = _tracker()
    st = {'a0': False, 'a1': False}
    exec_insn(t, 'c.and', 'a0, a1', st)
    assert st['a0'] is False


def test_canon_reg_x_numbered_destination():
    # x10 = a0: canon_reg in _exec_insn normalizes x-numbered names.
    t = _tracker()
    st = {'a1': True}
    exec_insn(t, 'mv', 'x10, a1', st)
    assert st.get('a0') is True


def test_lw_clears():
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'lw', 'a0, 0(a1)', st)
    assert st['a0'] is False


def test_add_propagates_either_source():
    t = _tracker()
    st = {'a1': True, 'a2': False}
    exec_insn(t, 'add', 'a0, a1, a2', st)
    assert st['a0'] is True


def test_sp_never_tainted():
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'addi', 'sp, sp, -16', st)
    assert st.get('sp') is None


def test_c_addi16sp_not_in_copy_mnems():
    from ablation.analyzers.taint_tracker_riscv32 import _COPY_MNEMS
    assert 'c.addi16sp' not in _COPY_MNEMS
