"""Control-flow graph construction over a decoded RISC-V instruction stream.

Blocks end at any control transfer or at any address that is a jump/branch
target. Edges:

* conditional branch  -> fall-through and target
* j/c.j/jal zero     -> target only (jump, not a call)
* call (jal rd!=x0, jalr rd!=x0, c.jal RV32, c.jalr, call)
  -> fall-through only; the callee is summarized by the tracker's psABI model
* ret/jr/tail/jalr zero -> no successors
* ecall, everything else -> fall-through
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .insn_riscv import Insn, jal_link_and_target
from .isa_riscv import IsaModel


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


def _branch_target(insn: Insn, isa: IsaModel) -> Optional[int]:
    m = insn.mnemonic
    if m in isa.cond_branch_mnems:
        for op in reversed(insn.ops):
            if hasattr(op, "value"):
                return op.value
        return None
    if m in ("j", "c.j"):
        return jal_link_and_target(insn)[1]
    if m == "jal":
        link, target = jal_link_and_target(insn)
        return target if link == "zero" else None
    return None


def _is_terminator(insn: Insn, isa: IsaModel) -> bool:
    m = insn.mnemonic
    return (
        m in isa.cond_branch_mnems
        or m in isa.uncond_jump_mnems
        or m in isa.ret_mnems
        or m in ("jalr", "c.jalr")
        or m == "jal"
        or m == "c.jal"
        or m == "call"
    )


def _falls_through(insn: Insn, isa: IsaModel) -> bool:
    m = insn.mnemonic
    if m in isa.ret_mnems or m in ("j", "c.j", "jr", "c.jr", "tail"):
        return False
    if m == "jal":
        return jal_link_and_target(insn)[0] != "zero"
    if m == "jalr":
        from .insn_riscv import jalr_link_and_base
        return jalr_link_and_base(insn)[0] != "zero"
    return True


def build_cfg(insns: Sequence[Insn], isa: IsaModel, entry: Optional[int] = None) -> CFG:
    """Build a CFG from a flat instruction sequence."""
    insns = sorted(insns, key=lambda i: i.address)
    if not insns:
        raise ValueError("no instructions")
    by_addr = {i.address: i for i in insns}
    entry = insns[0].address if entry is None else entry

    # 1. leaders
    leaders: Set[int] = {entry, insns[0].address}
    for idx, insn in enumerate(insns):
        if _is_terminator(insn, isa):
            t = _branch_target(insn, isa)
            if t is not None and t in by_addr:
                leaders.add(t)
            if idx + 1 < len(insns):
                leaders.add(insns[idx + 1].address)

    # 2. blocks
    blocks: Dict[int, Block] = {}
    cur: Optional[Block] = None
    for insn in insns:
        if insn.address in leaders or cur is None:
            cur = Block(insn.address)
            blocks[cur.start] = cur
        cur.insns.append(insn)

    # 3. edges
    ordered = sorted(blocks)
    nxt = {a: ordered[i + 1] for i, a in enumerate(ordered[:-1])}
    for b in blocks.values():
        last = b.insns[-1]
        t = _branch_target(last, isa)
        if t is not None and t in blocks:
            b.succs.append(t)
        if _falls_through(last, isa) and b.start in nxt and nxt[b.start] == last.address + last.size:
            b.succs.append(nxt[b.start])
        elif _falls_through(last, isa) and b.start in nxt and not _is_terminator(last, isa):
            b.succs.append(nxt[b.start])
    for b in blocks.values():
        for s in b.succs:
            blocks[s].preds.append(b.start)
    return CFG(blocks, entry)
