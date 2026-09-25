"""Control-flow graph construction over a decoded V850/RH850 instruction stream.

Blocks end at any control transfer or at any address that is a jump/branch
target. No delay slots. Edges:

* b[cond] / loop            -> fall-through and target
* jr (direct jump)          -> target only
* jmp [lp] / dispose ...[lp] -> no successors (return)
* jmp [reg]                 -> no successors (indirect jump)
* jarl disp, lp             -> fall-through only (call; callee abstracted)
* reti / ctret / eiret      -> no successors (interrupt return)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .insn_v850 import Imm, Insn, Mem, Reg, RegList
from .isa_v850 import Variant, _BRANCH, _BRANCH_RH, _JUMP, isa_for

_LP_REGS = frozenset({"lp", "r31"})


@dataclass
class Block:
    start: int
    insns: List[Insn] = field(default_factory=list)
    succs: List[int] = field(default_factory=list)
    preds: List[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        last = self.insns[-1]
        return last.address + last.size

    def __str__(self) -> str:
        return f"block {self.start:#x}-{self.end:#x} -> {[hex(s) for s in self.succs]}"


@dataclass
class CFG:
    blocks: Dict[int, Block]
    entry: int

    def block_at(self, addr: int) -> Optional[Block]:
        return self.blocks.get(addr)

    def __iter__(self):
        return iter(sorted(self.blocks.values(), key=lambda b: b.start))


def _imm_target(insn: Insn) -> Optional[int]:
    for op in reversed(insn.ops):
        if isinstance(op, Imm):
            return op.value
    return None


def _dispose_returns(insn: Insn) -> bool:
    if insn.mnemonic != "dispose":
        return False
    for op in insn.ops:
        if isinstance(op, RegList) and any(r in _LP_REGS for r in op.regs):
            return True
        if isinstance(op, Reg) and op.name in _LP_REGS:
            return True
    return False


def _is_return(insn: Insn) -> bool:
    isa = isa_for(Variant.RH850)
    if insn.mnemonic in isa.ret_mnems:
        return True
    if insn.mnemonic == "jmp":
        op = insn.ops[0] if insn.ops else None
        if isinstance(op, Mem) and op.base in _LP_REGS:
            return True
        if isinstance(op, Reg) and op.name in _LP_REGS:
            return True
    if _dispose_returns(insn):
        return True
    return False


def _is_indirect_jump(insn: Insn) -> bool:
    return insn.mnemonic == "jmp" and not _is_return(insn)


def _is_call(insn: Insn) -> bool:
    isa = isa_for(Variant.RH850)
    return insn.mnemonic in isa.call_mnems


def _is_direct_jump(insn: Insn) -> bool:
    return insn.mnemonic == "jr"


def _is_cond_branch(insn: Insn) -> bool:
    return insn.mnemonic in _BRANCH or insn.mnemonic in _BRANCH_RH


def _is_terminator(insn: Insn) -> bool:
    return (_is_return(insn) or _is_indirect_jump(insn) or _is_call(insn)
            or _is_direct_jump(insn) or _is_cond_branch(insn))


def _branch_target(insn: Insn) -> Optional[int]:
    if _is_cond_branch(insn) or _is_direct_jump(insn):
        return _imm_target(insn)
    if _is_call(insn):
        return None
    return None


def _falls_through(insn: Insn) -> bool:
    if _is_return(insn) or _is_indirect_jump(insn) or _is_direct_jump(insn):
        return False
    return True


def build_cfg(insns: Sequence[Insn], variant: Variant = Variant.RH850,
              entry: Optional[int] = None) -> CFG:
    insns = sorted(insns, key=lambda i: i.address)
    if not insns:
        raise ValueError("no instructions")
    by_addr = {i.address: i for i in insns}
    entry = insns[0].address if entry is None else entry

    leaders: Set[int] = {entry, insns[0].address}
    for idx, insn in enumerate(insns):
        if _is_terminator(insn):
            t = _branch_target(insn)
            if t is not None and t in by_addr:
                leaders.add(t)
            if idx + 1 < len(insns):
                leaders.add(insns[idx + 1].address)

    blocks: Dict[int, Block] = {}
    cur: Optional[Block] = None
    for insn in insns:
        if insn.address in leaders or cur is None:
            cur = Block(insn.address)
            blocks[cur.start] = cur
        cur.insns.append(insn)

    ordered = sorted(blocks)
    nxt = {a: ordered[i + 1] for i, a in enumerate(ordered[:-1])}
    for b in blocks.values():
        last = b.insns[-1]
        t = _branch_target(last)
        if t is not None and t in blocks:
            b.succs.append(t)
        if _falls_through(last):
            if b.start in nxt and nxt[b.start] == last.address + last.size:
                b.succs.append(nxt[b.start])
            elif b.start in nxt and not _is_terminator(last):
                b.succs.append(nxt[b.start])
    for b in blocks.values():
        for s in b.succs:
            if s in blocks:
                blocks[s].preds.append(b.start)
    return CFG(blocks, entry)
