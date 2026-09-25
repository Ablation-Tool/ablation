"""Control-flow graph construction over a decoded ARC EM/HS instruction stream.

Blocks end at any control transfer or at any address that is a jump/branch
target. ARC delay slots are opt-in: only instructions with the ``.d`` suffix
carry a delay slot. The delay slot instruction is included in the same block
as the branch. Edges:

* b.cc / brcc / bbit0/1     -> fall-through (after slot) and target
* b (unconditional)         -> target only
* bl                        -> fall-through only (call; callee abstracted)
* j [blink]                 -> no successors (return)
* jl [reg]                  -> fall-through only (indirect call)
* j [reg]                   -> no successors (indirect jump)
* bi / bih                  -> no successors (computed jump)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .insn_arc import Imm, Insn, Mem, Reg
from .isa_arc import BLINK, BRANCH, BRANCH_INDEXED, BRCC, CALL, JUMP, JUMP_LINK


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


def _is_return(insn: Insn) -> bool:
    if insn.mnemonic not in JUMP:
        return False
    op = insn.ops[0] if insn.ops else None
    if isinstance(op, Mem):
        return op.base == BLINK
    if isinstance(op, Reg):
        return op.name == BLINK
    return False


def _is_indirect_jump(insn: Insn) -> bool:
    return (insn.mnemonic in JUMP and not _is_return(insn)) or insn.mnemonic in BRANCH_INDEXED


def _is_indirect_call(insn: Insn) -> bool:
    return insn.mnemonic in JUMP_LINK


def _is_call(insn: Insn) -> bool:
    return insn.mnemonic in CALL or _is_indirect_call(insn)


def _is_uncond_branch(insn: Insn) -> bool:
    return insn.mnemonic in BRANCH and insn.cond is None


def _is_cond_branch(insn: Insn) -> bool:
    return (insn.mnemonic in BRANCH and insn.cond is not None) or insn.mnemonic in BRCC


def _is_terminator(insn: Insn) -> bool:
    return (_is_return(insn) or _is_indirect_jump(insn) or _is_call(insn)
            or _is_uncond_branch(insn) or _is_cond_branch(insn))


def _branch_target(insn: Insn) -> Optional[int]:
    if _is_cond_branch(insn) or _is_uncond_branch(insn):
        return _imm_target(insn)
    return None


def _falls_through(insn: Insn) -> bool:
    if _is_return(insn) or _is_indirect_jump(insn) or _is_uncond_branch(insn):
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
        if insn.delay and i + 1 < len(insns):
            delay_slots.add(insns[i + 1].address)

    leaders: Set[int] = {entry, insns[0].address}
    for idx, insn in enumerate(insns):
        if insn.address in delay_slots:
            continue
        if _is_terminator(insn):
            t = _branch_target(insn)
            if t is not None and t in by_addr:
                leaders.add(t)
            slot_end_idx = idx + 2 if insn.delay else idx + 1
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
        branch_insn = prev if (prev is not None and prev.delay) else last

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
        elif not _is_terminator(last):
            if b.start in nxt:
                b.succs.append(nxt[b.start])

    for b in blocks.values():
        for s in b.succs:
            if s in blocks:
                blocks[s].preds.append(b.start)
    return CFG(blocks, entry)
