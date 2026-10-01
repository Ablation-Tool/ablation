"""Control-flow graph construction for LoongArch64 instruction streams.

Block termination rules:
  b   target          -> target only (unconditional direct branch)
  bl  target          -> fall-through only (direct call; callee abstracted)
  jirl $zero,$ra,0    -> no successors (return)
  jirl $ra,rj,0       -> fall-through only (indirect call; callee abstracted)
  jirl $zero,rj,*     -> no successors (indirect branch)
  beqz/bnez/beq/bne/blt/bge/bltu/bgeu/bceqz/bcnez -> fall-through + target
  ertn                -> no successors (exception return; kernel only)
  syscall             -> fall-through only (like a call; returns to next insn)
  break / dbcl        -> no successors (trap; treated as unreachable)
  .word (unknown)     -> fall-through (treated as data)

No delay slots. All instructions are 4 bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .insn_loongarch64 import Insn
from .isa_loongarch64 import (
    CALL_MNEMS, COND_BRANCH_MNEMS, JUMP_MNEMS, RA_REG, ZERO_REG,
)

_INDIRECT_BRANCH_MNEM = "jirl"


_TRAP_MNEMS = frozenset({"break", "dbcl"})  # unconditional trap — no successors

def _is_ret(insn: Insn) -> bool:
    if insn.mnemonic == "ertn":
        return True   # exception return from kernel handler
    if insn.mnemonic in _TRAP_MNEMS:
        return True   # trap is unreachable past this point
    if insn.mnemonic != _INDIRECT_BRANCH_MNEM:
        return False
    rd = insn.reg(0)
    rj = insn.reg(1)
    off = insn.imm(2)
    return rd == ZERO_REG and rj == RA_REG and off == 0


def _is_indirect_call(insn: Insn) -> bool:
    if insn.mnemonic != _INDIRECT_BRANCH_MNEM:
        return False
    rd = insn.reg(0)
    return rd == RA_REG


def _is_indirect_branch(insn: Insn) -> bool:
    return insn.mnemonic == _INDIRECT_BRANCH_MNEM and not _is_ret(insn) and not _is_indirect_call(insn)


def _is_direct_call(insn: Insn) -> bool:
    return insn.mnemonic in CALL_MNEMS


def _is_direct_branch(insn: Insn) -> bool:
    return insn.mnemonic in JUMP_MNEMS


def _is_cond_branch(insn: Insn) -> bool:
    return insn.mnemonic in COND_BRANCH_MNEMS


def _is_terminator(insn: Insn) -> bool:
    return (_is_ret(insn) or _is_indirect_branch(insn) or
            _is_direct_call(insn) or _is_indirect_call(insn) or
            _is_direct_branch(insn) or _is_cond_branch(insn))


def _branch_target(insn: Insn) -> Optional[int]:
    """PC-relative target for direct branch/call mnemonics, or None."""
    if insn.mnemonic in (JUMP_MNEMS | CALL_MNEMS | COND_BRANCH_MNEMS):
        # For b/bl: ops = [Imm(offset)], computed as address + offset in decoder
        # For beqz/bnez: ops = [Reg(rj), Imm(offset)]
        # For beq/etc.:  ops = [Reg(rj), Reg(rd), Imm(offset)]
        # Target is already resolved as an absolute VA in LoongArchFrame.target.
        # At this layer we work from the Insn opaque offset; the caller
        # provides frames so we look at the last Imm operand and add base_va.
        for op in reversed(insn.ops):
            from .insn_loongarch64 import Imm
            if isinstance(op, Imm):
                # offset; absolute target = insn.address + offset
                return (insn.address + op.value) & 0xffffffffffffffff
    return None


def _falls_through(insn: Insn) -> bool:
    if _is_ret(insn) or _is_indirect_branch(insn) or _is_direct_branch(insn):
        return False
    return True


# ---------------------------------------------------------------------------
# Block and CFG
# ---------------------------------------------------------------------------

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
    entry:  int

    def block_at(self, addr: int) -> Optional[Block]:
        return self.blocks.get(addr)

    def __iter__(self):
        return iter(sorted(self.blocks.values(), key=lambda b: b.start))


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
            fa = last.address + last.size
            if fa in blocks:
                b.succs.append(fa)
            elif b.start in nxt and not _is_terminator(last):
                b.succs.append(nxt[b.start])

    for b in blocks.values():
        for s in b.succs:
            if s in blocks:
                blocks[s].preds.append(b.start)

    return CFG(blocks, entry)
