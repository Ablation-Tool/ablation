"""Control-flow graph construction over a decoded x86-64 instruction stream.

Blocks end at any control transfer or at any address that is a jump/branch
target. Edges:

* conditional j* / loop*  -> fall-through and target
* jmp (direct)            -> target only
* jmp (indirect)          -> no successors (unresolvable at listing level)
* call                    -> fall-through only (callee abstracted by ABI model)
* ret / iret              -> no successors
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .insn_x86 import Imm, Insn, Mem
from .isa_x86 import CALL, JMP, RET

_COND_BRANCH: frozenset = frozenset({
    "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
    "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle",
    "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz",
    "loop", "loope", "loopne", "jcxz", "jecxz", "jrcxz",
})


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


def _is_indirect(insn: Insn) -> bool:
    return any(isinstance(op, Mem) for op in insn.ops)


def _is_terminator(insn: Insn) -> bool:
    m = insn.mnemonic
    return m in _COND_BRANCH or m in JMP or m in RET or m in CALL


def _branch_target(insn: Insn) -> Optional[int]:
    m = insn.mnemonic
    if m in _COND_BRANCH or m in JMP:
        return _imm_target(insn)
    return None


def _falls_through(insn: Insn) -> bool:
    m = insn.mnemonic
    if m in RET:
        return False
    if m in JMP:
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
