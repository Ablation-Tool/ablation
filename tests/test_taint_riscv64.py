"""
Unit tests for RISCV64TaintTracker._exec_insn taint propagation.

Capstone 5.0.7 rendering facts (CS_MODE_RISCV64 | CS_MODE_RISCVC):
  addiw a0, a0, 0    -> 'sext.w'  'a0, a0'   (narrowing copy -- propagates conservatively)
  c.addiw a0, 0      -> 'c.addiw' 'a0, 0'
  ld a0, 0(a1)       -> 'ld'      'a0, 0(a1)' (clears taint)
  addw a0, a0, zero  -> 'addw'    'a0, a0, zero'
"""

from ablation.analyzers.taint_tracker_riscv64 import RISCV64TaintTracker


def _tracker() -> RISCV64TaintTracker:
    import unittest.mock as mock
    import capstone
    from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC
    t = RISCV64TaintTracker.__new__(RISCV64TaintTracker)
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
    t._md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    t._md.detail = False
    return t


def exec_insn(tracker, mnemonic, op_str, tainted):
    tracker._exec_insn(mnemonic, op_str, tainted)


def test_sext_w_propagates():
    # addiw a0, a0, 0 -> 'sext.w' 'a0, a0' -- taint must survive sign extension
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'sext.w', 'a0, a0', st)
    assert st['a0'] is True


def test_sext_w_clears_when_source_clean():
    t = _tracker()
    st = {'a0': False, 'a1': False}
    exec_insn(t, 'sext.w', 'a0, a1', st)
    assert st['a0'] is False


def test_ld_clears():
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'ld', 'a0, 0(a1)', st)
    assert st['a0'] is False


def test_addw_propagates():
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'addw', 'a0, a0, zero', st)
    assert st['a0'] is True


def test_c_addiw_propagates():
    # c.addiw a0, 4 -> 'c.addiw' 'a0, 4' -- immediate variant, propagates rs1
    t = _tracker()
    st = {'a0': True}
    exec_insn(t, 'c.addiw', 'a0, 4', st)
    assert st['a0'] is True


def test_c_addi16sp_not_in_copy_mnems():
    from ablation.analyzers.taint_tracker_riscv64 import _COPY_MNEMS
    assert 'c.addi16sp' not in _COPY_MNEMS


def test_mv_propagates():
    t = _tracker()
    st = {'a1': True}
    exec_insn(t, 'mv', 'a0, a1', st)
    assert st['a0'] is True


def test_andi_clears():
    t = _tracker()
    st = {'a0': True, 'a1': True}
    exec_insn(t, 'andi', 'a0, a1, 0xff', st)
    assert st['a0'] is False
