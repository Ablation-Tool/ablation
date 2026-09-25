"""Control-flow graph construction over a decoded AArch64 instruction stream.

Blocks end at any control transfer or at any address that is a jump/branch
target. No delay slots. Edges:

* b.cc / cbz / cbnz / tbz / tbnz -> fall-through and target
* b (unconditional)               -> target only
* bl / blr / blraa*               -> fall-through only (call; callee abstracted)
* ret / retaa / eret              -> no successors
* br / braa*                      -> no successors (indirect jump)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .insn_arm64 import Imm, Insn
from .isa_arm64 import ISA


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


def _is_cond_branch(insn: Insn) -> bool:
    m = insn.mnemonic
    return m in ISA.cond_branch_mnems or m in ISA.reg_branch_mnems


def _is_terminator(insn: Insn) -> bool:
    m = insn.mnemonic
    return (m in ISA.ret_mnems or m in ISA.call_mnems or m in ISA.indirect_jump_mnems
            or m in ISA.uncond_branch_mnems or _is_cond_branch(insn))


def _branch_target(insn: Insn) -> Optional[int]:
    m = insn.mnemonic
    if _is_cond_branch(insn) or m in ISA.uncond_branch_mnems:
        return _imm_target(insn)
    return None


def _falls_through(insn: Insn) -> bool:
    m = insn.mnemonic
    if m in ISA.ret_mnems or m in ISA.indirect_jump_mnems or m in ISA.uncond_branch_mnems:
        return False
    return True


def build_cfg(insns: Sequence[Insn], entry: Optional[int] = None) -> CFG:
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
