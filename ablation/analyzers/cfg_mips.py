"""Control-flow graph construction over a decoded MIPS32/64 instruction stream.

Blocks end at any control transfer or at any address that is a jump/branch
target. MIPS delay slots (the instruction immediately after a branch/jump)
are included in the same block as the branch.  Edges:

* beq/bne/... (conditional) -> fall-through (after delay slot) and target
* j / b (unconditional)     -> target only
* jal / bal                 -> fall-through only (call; callee abstracted)
* jr $ra                    -> no successors (return)
* jr $X / jalr              -> no successors (indirect jump/call)
* compact branches (bc/jic) -> same as equivalent regular branches, no slot
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .insn_mips import Imm, Insn, Reg
from .isa_mips import (
    BRANCH_COND, CALL_DIRECT, CALL_INDIRECT, COMPACT_CALL, COMPACT_COND,
    COMPACT_JUMP, DELAY_SLOT, FP_BRANCH, JUMP, JUMP_REG,
)

_RA_REGS = frozenset({"$ra", "$31", "ra"})


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


def _has_delay_slot(insn: Insn) -> bool:
    return insn.mnemonic in DELAY_SLOT


def _is_return(insn: Insn) -> bool:
    if insn.mnemonic not in JUMP_REG:
        return False
    r = insn.ops[0] if insn.ops else None
    return isinstance(r, Reg) and r.name in _RA_REGS


def _is_indirect_jump(insn: Insn) -> bool:
    return insn.mnemonic in JUMP_REG and not _is_return(insn)


def _is_call(insn: Insn) -> bool:
    return insn.mnemonic in CALL_DIRECT or insn.mnemonic in CALL_INDIRECT or insn.mnemonic in COMPACT_CALL


def _is_uncond_jump(insn: Insn) -> bool:
    return insn.mnemonic in JUMP or insn.mnemonic in COMPACT_JUMP


def _is_cond_branch(insn: Insn) -> bool:
    return insn.mnemonic in BRANCH_COND or insn.mnemonic in FP_BRANCH or insn.mnemonic in COMPACT_COND


def _is_terminator(insn: Insn) -> bool:
    return (_is_return(insn) or _is_indirect_jump(insn) or _is_call(insn)
            or _is_uncond_jump(insn) or _is_cond_branch(insn))


def _branch_target(insn: Insn) -> Optional[int]:
    if _is_cond_branch(insn) or _is_uncond_jump(insn) or _is_call(insn):
        if insn.mnemonic in CALL_DIRECT or insn.mnemonic in JUMP:
            return _imm_target(insn)
        return _imm_target(insn)
    return None


def _falls_through(insn: Insn) -> bool:
    if _is_return(insn) or _is_indirect_jump(insn):
        return False
    if _is_uncond_jump(insn):
        return False
    return True


def build_cfg(insns: Sequence[Insn], entry: Optional[int] = None) -> CFG:
    insns = sorted(insns, key=lambda i: i.address)
    if not insns:
        raise ValueError("no instructions")
    by_addr = {i.address: i for i in insns}
    entry = insns[0].address if entry is None else entry

    delay_slots: Set[int] = set()
    for i, insn in enumerate(insns):
        if _has_delay_slot(insn) and i + 1 < len(insns):
            delay_slots.add(insns[i + 1].address)

    leaders: Set[int] = {entry, insns[0].address}
    for idx, insn in enumerate(insns):
        if insn.address in delay_slots:
            continue
        if _is_terminator(insn):
            t = _branch_target(insn)
            if t is not None and t in by_addr:
                leaders.add(t)
            slot_end_idx = idx + 2 if _has_delay_slot(insn) else idx + 1
            if slot_end_idx < len(insns):
                leaders.add(insns[slot_end_idx].address)

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
        prev = b.insns[-2] if len(b.insns) >= 2 else None
        branch = prev if (prev is not None and _has_delay_slot(prev)) else (last if not _has_delay_slot(last) else None)
        branch_insn = prev if (prev is not None and _has_delay_slot(prev)) else last

        if _has_delay_slot(last):
            branch_insn = last

        if _is_terminator(branch_insn):
            t = _branch_target(branch_insn)
            if t is not None and t in blocks:
                b.succs.append(t)
            if _falls_through(branch_insn):
                ft = last.address + last.size
                if ft in blocks:
                    b.succs.append(ft)
                elif b.start in nxt:
                    b.succs.append(nxt[b.start])
        elif _falls_through(last) and not _is_terminator(last):
            if b.start in nxt:
                b.succs.append(nxt[b.start])

    for b in blocks.values():
        for s in b.succs:
            if s in blocks:
                blocks[s].preds.append(b.start)
    return CFG(blocks, entry)
