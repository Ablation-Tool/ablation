"""Control-flow graph construction over a decoded SH-2A instruction stream.

SH-2A delay-slot semantics: after BRA, BT/S, BF/S, BSR, JSR, RTS, and RTE
the CPU always executes one more instruction (the "delay slot") before the
branch takes effect.  The exception is RTS/N, a SH-2A-specific no-delay-slot
return.  BT and BF (without /S) also have no delay slot.

CFG model: the delay-slot instruction is appended to the terminating block.
Successors are set as if the branch had already fired.

Block terminators and their edges:
  rts, rte  (RETURN with delay slot)   -> no successors
  rts/n     (RETURN, no delay slot)    -> no successors
  bra       (unconditional, DS)        -> [target]
  bt/s,bf/s (conditional, DS)          -> [target, fall-through after DS]
  bt, bf    (conditional, no DS)       -> [target, fall-through]
  bsr, jsr  (call, DS)                 -> [fall-through after DS]
  fall-through (no branch)             -> [next block start]

Indirect jumps (braf, jmp @Rn) are classified MISC by the current decoder and
fall through; they create open blocks with no successors when encountered.

The Block/CFG types are duck-type compatible with DomTree and LoopInfo from
ablation.analyzers.dataflow_engine, allowing dominator-tree and loop analysis
without any adaptation.

Usage::

    from ablation.analyzers.ecu_sh2a_decoder import EcuSH2aDecoder
    from ablation.analyzers.cfg_sh2a import build_cfg

    dec = EcuSH2aDecoder(rom, base_va=0)
    insns = dec.disassemble(0, len(rom))
    cfg = build_cfg(insns)

    for block in cfg:
        print(block)

    # Dominator tree (same API as dataflow_engine.DomTree)
    from ablation.analyzers.dataflow_engine import DomTree, LoopInfo
    dom   = DomTree(cfg)
    loops = LoopInfo(cfg, dom)
    print("back edges:", dom.back_edges())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .ecu_sh2a_decoder import SH2aInsn


# ── Mnemonic sets ──────────────────────────────────────────────────────────────

# Conditional branches WITH delay slot
_COND_WITH_DS: frozenset[str] = frozenset({"bt/s", "bf/s"})
# Conditional branches WITHOUT delay slot
_COND_NO_DS: frozenset[str] = frozenset({"bt", "bf"})
# Unconditional direct branches WITH delay slot
_UNCOND_DIRECT: frozenset[str] = frozenset({"bra"})
# Returns with delay slot
_RETURNS_WITH_DS: frozenset[str] = frozenset({"rts", "rte"})
# Returns WITHOUT delay slot (SH-2A: combined return+nop instruction)
_RETURNS_NO_DS: frozenset[str] = frozenset({"rts/n"})


def _has_delay_slot(insn: SH2aInsn) -> bool:
    m = insn.mnemonic
    return (m in _COND_WITH_DS or m in _UNCOND_DIRECT or
            m in _RETURNS_WITH_DS or insn.insn_type == "CALL")


def _is_return(insn: SH2aInsn) -> bool:
    return insn.insn_type == "RETURN"


def _is_call(insn: SH2aInsn) -> bool:
    return insn.insn_type == "CALL"


def _is_cond_branch(insn: SH2aInsn) -> bool:
    return insn.mnemonic in _COND_WITH_DS or insn.mnemonic in _COND_NO_DS


def _is_uncond_branch(insn: SH2aInsn) -> bool:
    return insn.mnemonic in _UNCOND_DIRECT


def _is_terminator(insn: SH2aInsn) -> bool:
    return (
        _is_return(insn) or _is_call(insn) or
        _is_cond_branch(insn) or _is_uncond_branch(insn)
    )


def _insn_size(insn: SH2aInsn) -> int:
    return 4 if insn.is_32bit else 2


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class Block:
    """A basic block in the SH-2A CFG.

    When the terminator has a delay slot, the delay-slot instruction is the
    last entry in *insns*.  ``succs`` and ``preds`` store block-start VAs.
    """
    start: int
    insns: List[SH2aInsn] = field(default_factory=list)
    succs: List[int] = field(default_factory=list)
    preds: List[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        if not self.insns:
            return self.start
        last = self.insns[-1]
        return last.offset + _insn_size(last)

    def terminator(self) -> Optional[SH2aInsn]:
        """Return the control-transfer instruction in this block, if any."""
        for insn in self.insns:
            if _is_terminator(insn):
                return insn
        return None

    def delay_slot(self) -> Optional[SH2aInsn]:
        """Return the delay-slot instruction if the terminator has one."""
        for idx, insn in enumerate(self.insns):
            if _is_terminator(insn) and _has_delay_slot(insn):
                if idx + 1 < len(self.insns):
                    return self.insns[idx + 1]
        return None

    def __str__(self) -> str:
        return (f"block {self.start:#x}-{self.end:#x} "
                f"[{len(self.insns)} insns] -> {[hex(s) for s in self.succs]}")


@dataclass
class CFG:
    """Control-flow graph for a single SH-2A function.

    The `flow` property and `flow_r()` method make this type duck-type
    compatible with `dataflow_engine.CFG`, allowing `DomTree` and `LoopInfo`
    from that module to be used directly without adaptation.
    """
    blocks: Dict[int, Block]
    entry: int

    @property
    def flow(self) -> List[Tuple[int, int]]:
        """All (src, dst) forward edges — compatible with dataflow_engine.DomTree."""
        return [(b.start, s) for b in self.blocks.values() for s in b.succs]

    def flow_r(self) -> List[Tuple[int, int]]:
        """Reversed edges for backward dataflow passes."""
        return [(dst, src) for src, dst in self.flow]

    def block_at(self, addr: int) -> Optional[Block]:
        return self.blocks.get(addr)

    def __iter__(self):
        return iter(sorted(self.blocks.values(), key=lambda b: b.start))


# ── CFG construction ───────────────────────────────────────────────────────────

def build_cfg(insns: Sequence[SH2aInsn],
              entry: Optional[int] = None) -> CFG:
    """Build a CFG from a flat list of decoded SH-2A instructions.

    *insns* is sorted by ``.offset`` (ascending) before use.  Extra
    instructions beyond the last RETURN are silently included as dead blocks.

    *entry* defaults to the VA of the first instruction.
    """
    if not insns:
        raise ValueError("no instructions")

    insns = sorted(insns, key=lambda i: i.offset)
    by_offset: Dict[int, SH2aInsn] = {i.offset: i for i in insns}
    entry_va: int = insns[0].offset if entry is None else entry

    # ── 1. Discover leaders ────────────────────────────────────────────────────
    # A leader is the first instruction of a basic block.
    leaders: Set[int] = {entry_va}

    i = 0
    while i < len(insns):
        insn = insns[i]
        if _is_terminator(insn):
            # Branch target is always a leader
            if insn.target is not None and insn.target in by_offset:
                leaders.add(insn.target)

            if _has_delay_slot(insn):
                # The delay slot at i+1 is NOT a leader (it belongs to this block).
                # The instruction at i+2 is the fall-through leader for calls and
                # conditional branches; for returns/unconditional branches it is
                # dead code but may still be targeted by another branch.
                if i + 2 < len(insns):
                    leaders.add(insns[i + 2].offset)
                i += 2  # consume branch + delay slot together
            else:
                # No delay slot — next instruction is a potential fall-through leader.
                if i + 1 < len(insns):
                    leaders.add(insns[i + 1].offset)
                i += 1
        else:
            i += 1

    # ── 2. Partition instructions into blocks ──────────────────────────────────
    blocks: Dict[int, Block] = {}
    cur: Optional[Block] = None

    i = 0
    while i < len(insns):
        insn = insns[i]

        # Start a new block at each leader (or when no current block).
        if insn.offset in leaders or cur is None:
            cur = Block(insn.offset)
            blocks[cur.start] = cur

        cur.insns.append(insn)

        if _is_terminator(insn):
            if _has_delay_slot(insn) and i + 1 < len(insns):
                # Consume delay slot into the same block without checking leaders.
                cur.insns.append(insns[i + 1])
                i += 2
            else:
                i += 1
            cur = None  # end block after terminator (+ optional delay slot)
        else:
            i += 1

    # ── 3. Set successor edges ─────────────────────────────────────────────────
    for b in blocks.values():
        term = b.terminator()
        ds = b.delay_slot()

        if term is None:
            # Pure fall-through block (cut by a leader, no branch)
            if b.end in blocks:
                b.succs.append(b.end)
            continue

        if _is_return(term):
            pass  # no successors

        elif _is_uncond_branch(term):
            if term.target is not None and term.target in blocks:
                b.succs.append(term.target)

        elif _is_cond_branch(term):
            # Branch target
            if term.target is not None and term.target in blocks:
                b.succs.append(term.target)
            # Fall-through: the instruction after the delay slot (if any)
            if _has_delay_slot(term) and ds is not None:
                fall_va = ds.offset + _insn_size(ds)
            else:
                fall_va = term.offset + _insn_size(term)
            if fall_va in blocks:
                b.succs.append(fall_va)

        elif _is_call(term):
            # Callee abstracted — only the fall-through after the delay slot
            if _has_delay_slot(term) and ds is not None:
                fall_va = ds.offset + _insn_size(ds)
            else:
                fall_va = term.offset + _insn_size(term)
            if fall_va in blocks:
                b.succs.append(fall_va)

    # ── 4. Set predecessor edges ───────────────────────────────────────────────
    for b in blocks.values():
        for s in b.succs:
            if s in blocks:
                blocks[s].preds.append(b.start)

    return CFG(blocks, entry_va)
