"""
Regression guard for RISC-V call mnemonic set ISA correctness.

c.jal (RV32C encoding 001..01) is reused as c.addiw on RV64C (ISA spec §16.5).
These assertions prevent a future cleanup from adding c.jal to the RV64 set.
"""

from ablation.analyzers.taint_tracker_riscv32 import _CALL_MNEMS as RV32_CALL
from ablation.analyzers.taint_tracker_riscv64 import _CALL_MNEMS as RV64_CALL


def test_c_jal_in_rv32_call_mnems():
    # c.jal is RV32C only (ISA spec §16.5 -- same encoding is c.addiw on RV64C)
    assert 'c.jal' in RV32_CALL


def test_c_jal_not_in_rv64_call_mnems():
    # RV64C reuses the c.jal encoding for c.addiw -- adding it here would mis-classify
    # every c.addiw as a call
    assert 'c.jal' not in RV64_CALL


def test_jal_in_both():
    assert 'jal' in RV32_CALL
    assert 'jal' in RV64_CALL


def test_rv32_copy_mnems_no_rv64_only():
    from ablation.analyzers.taint_tracker_riscv32 import _COPY_MNEMS as RV32_COPY
    rv64_only = {'addiw', 'slliw', 'srliw', 'sraiw', 'lwu'}
    overlap = rv64_only & RV32_COPY
    assert not overlap, f"RV64-only mnemonics in RV32 _COPY_MNEMS: {overlap}"
