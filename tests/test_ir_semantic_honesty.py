from types import SimpleNamespace

from ablation.analyzers.ir import (
    AlphaIRLifter,
    IRBranch,
    IRConst,
    IRUnknown,
    PseudoCEmitter,
    X86_64IRLifter,
)


def test_alpha_unknown_instruction_is_not_rewritten_as_zero():
    lifter = AlphaIRLifter(data=b"", sections={})
    block = SimpleNamespace(insns=[(0x1000, 0x1C000000)], succs=[], preds=[], is_ret=False)

    lifted = lifter.lift_block(0x1000, block)

    assert len(lifted.stmts) == 1
    assert isinstance(lifted.stmts[0], IRUnknown)
    assert lifted.stmts[0].raw == 0x1C000000
    assert "UNKNOWN" in PseudoCEmitter(_graph(lifted)).emit()


def test_x86_conditional_branch_has_explicit_unknown_condition():
    lifter = X86_64IRLifter()
    instruction = SimpleNamespace(
        mnemonic="jne",
        operands=[SimpleNamespace(type=2, imm=0x2000)],
        address=0x1000,
        size=2,
    )

    lifted = lifter._lift_insn(instruction)

    assert isinstance(lifted[0], IRBranch)
    assert isinstance(lifted[0].cond, IRUnknown)
    assert lifted[0].cond.reason == "x86 condition code jne requires unresolved flags"


def test_x86_unconditional_branch_is_not_a_conditional_placeholder():
    lifter = X86_64IRLifter()
    instruction = SimpleNamespace(
        mnemonic="jmp",
        operands=[SimpleNamespace(type=2, imm=0x2000)],
        address=0x1000,
        size=2,
    )

    lifted = lifter._lift_insn(instruction)

    assert lifted == [IRBranch(cond=None, taken=0x2000, fallthrough=None)]


def test_alpha_signed_and_fp_conditions_keep_their_semantics():
    lifter = AlphaIRLifter(data=b"", sections={})

    signed = lifter._lift_insn(0x1000, (0x3E << 26) | (1 << 21))
    floating = lifter._lift_insn(0x1004, (0x31 << 26) | (1 << 21))

    assert signed[0].cond.op == ">="
    assert isinstance(floating[0].cond, IRUnknown)


def test_x86_unmodeled_stack_operation_is_explicit():
    instruction = SimpleNamespace(mnemonic="push", operands=[], address=0x1000, size=1)

    lifted = X86_64IRLifter()._lift_insn(instruction)

    assert isinstance(lifted[0], IRUnknown)
    assert lifted[0].reason == "x86 stack operation push is not modeled"


def _graph(block):
    return SimpleNamespace(
        arch="alpha_axp",
        entry=block.start_va,
        blocks={block.start_va: block},
    )
