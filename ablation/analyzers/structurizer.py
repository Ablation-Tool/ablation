"""Structured control-flow reconstruction for compiled MCU/ECU firmware.

Converts a basic-block CFG into a tree of structured nodes (Sequence, If,
While) using dominator-tree and natural-loop information.  The output is
equivalent to the source-level control flow of the original C code, without
the goto statements a naive lifter produces.

Algorithm
---------
All compiled automotive firmware (AUTOSAR classic, plain-C ECU code) produces
*reducible* CFGs — every back edge has a unique dominating header.  This lets
us use a dominator-driven Relooper variant that is simpler than the full
Emscripten Relooper:

    1. Walk blocks in RPO (dominators before dominated nodes).
    2. If a block is a loop header (LoopInfo.is_loop_header), emit a WhileNode
       that covers all blocks in the natural loop body, then recurse on the
       blocks beyond the loop exit.
    3. If a block has two successors, look for their closest common post-
       dominator ("join" block).  Emit an IfNode with then/else sub-trees up
       to the join, then continue from the join block.
    4. Otherwise, append the block to the current Sequence and continue.

ISA independence
----------------
The structurizer works on any CFG that exposes:
    - cfg.blocks : Dict[int, Block]   (Block has .start, .succs, .preds, .insns)
    - cfg.entry  : int
    - cfg.flow   : List[(src, dst)]   (forward edges)
    - cfg.flow_r(): List[(dst, src)]  (backward edges — for post-dom)

This matches both `cfg_sh2a.CFG` and `dataflow_engine.CFG`.

Usage::

    from ablation.analyzers.ecu_sh2a_decoder import EcuSH2aDecoder
    from ablation.analyzers.cfg_sh2a import build_cfg
    from ablation.analyzers.structurizer import Structurizer

    dec  = EcuSH2aDecoder(rom, base_va=0)
    insns = dec.disassemble(0, len(rom))
    cfg  = build_cfg(insns)
    s    = Structurizer(cfg)
    tree = s.structure()

    def emitter(insn):
        return f"  // {insn.mnemonic}"

    print(s.emit(emitter))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple, Any

from .dataflow_engine import DomTree, LoopInfo


# ── Structured node types ──────────────────────────────────────────────────────

class StructuredNode:
    """Base class for all structured control-flow nodes."""


@dataclass
class SequenceNode(StructuredNode):
    """Ordered list of children (instructions + nested structures)."""
    children: List[StructuredNode] = field(default_factory=list)


@dataclass
class InsnNode(StructuredNode):
    """A single basic block, emitted as sequential instructions."""
    block_start: int
    insns: list = field(default_factory=list)     # List[SH2aInsn] or compatible
    is_loop_header: bool = False


@dataclass
class IfNode(StructuredNode):
    """if (cond) { then_body } else { else_body }  — join is the merge point."""
    cond_block: int
    then_body: StructuredNode
    else_body: Optional[StructuredNode]
    join_block: Optional[int]


@dataclass
class WhileNode(StructuredNode):
    """while (cond) { body }"""
    header_block: int
    body: StructuredNode
    exit_block: Optional[int]


@dataclass
class BreakNode(StructuredNode):
    """break — exits the innermost loop."""


@dataclass
class ContinueNode(StructuredNode):
    """continue — jumps to the innermost loop header."""


@dataclass
class ReturnNode(StructuredNode):
    """return from function."""
    block_start: int
    insns: list = field(default_factory=list)


@dataclass
class _RevBlock:
    """Reversed-CFG block used only by PostDomTree._compute()."""
    start: int
    succs: List[int] = field(default_factory=list)
    preds: List[int] = field(default_factory=list)
    insns: list = field(default_factory=list)


# ── Post-dominator tree (reversed CFG dominators) ─────────────────────────────

class PostDomTree:
    """
    Post-dominator tree: block A post-dominates block B if every path from B
    to any exit goes through A.

    Built by reversing the CFG, adding a synthetic super-exit → all exit nodes,
    then running the standard DomTree algorithm.
    """

    def __init__(self, cfg) -> None:
        self._pdom: Dict[int, Optional[int]] = {}
        self._compute(cfg)

    def _compute(self, cfg) -> None:
        # Build a reversed mini-CFG as a plain object (duck-type for DomTree).
        exits = [b.start for b in cfg.blocks.values() if not b.succs]
        SUPER_EXIT = -1

        rev_blocks: Dict[int, _RevBlock] = {}
        for b in cfg.blocks.values():
            rev_blocks[b.start] = _RevBlock(start=b.start)
        rev_blocks[SUPER_EXIT] = _RevBlock(start=SUPER_EXIT)

        for b in cfg.blocks.values():
            for s in b.succs:
                if s in rev_blocks:
                    rev_blocks[s].succs.append(b.start)
                    rev_blocks[b.start].preds.append(s)

        for e in exits:
            # SUPER_EXIT → exit in the reversed graph (so DomTree from SUPER_EXIT
            # reaches all original exit nodes, making them its immediate successors).
            rev_blocks[SUPER_EXIT].succs.append(e)
            rev_blocks[e].preds.append(SUPER_EXIT)

        class _RevCFG:
            def __init__(self):
                self.blocks = rev_blocks
                self.entry = SUPER_EXIT

            @property
            def flow(self):
                return [(b.start, s) for b in self.blocks.values() for s in b.succs]

            def flow_r(self):
                return [(b, a) for a, b in self.flow]

        rev_cfg = _RevCFG()
        dom = DomTree(rev_cfg)
        for n in cfg.blocks:
            idom = dom.idom(n)
            if idom == SUPER_EXIT:
                idom = None
            self._pdom[n] = idom

    def ipdom(self, n: int) -> Optional[int]:
        """Immediate post-dominator of n."""
        return self._pdom.get(n)

    def post_dominates(self, a: int, b: int) -> bool:
        """True if a post-dominates b."""
        cur = b
        seen: Set[int] = set()
        while True:
            if cur == a:
                return True
            parent = self._pdom.get(cur)
            if parent is None or cur in seen:
                return False
            seen.add(cur)
            cur = parent

    def closest_common_post_dominator(self, a: int, b: int) -> Optional[int]:
        """
        Find the closest block that post-dominates both a and b.
        This is the "join" point after an if/else diamond.
        """
        ancestors_a: Set[int] = set()
        cur = a
        seen: Set[int] = set()
        while cur is not None and cur not in seen:
            ancestors_a.add(cur)
            seen.add(cur)
            cur = self._pdom.get(cur)

        cur = b
        seen = set()
        while cur is not None and cur not in seen:
            if cur in ancestors_a:
                return cur
            seen.add(cur)
            cur = self._pdom.get(cur)
        return None


# ── Main structurizer ──────────────────────────────────────────────────────────

class Structurizer:
    """
    Dominator-driven structured control-flow reconstruction.

    Works on any reducible CFG (all compiled automotive firmware is reducible).
    Produces a tree of StructuredNode objects that map directly to C constructs.

    Parameters
    ----------
    cfg : any object with .blocks, .entry, .flow, .flow_r() attributes
        Typically cfg_sh2a.CFG, but accepts any compatible type.
    """

    def __init__(self, cfg) -> None:
        self.cfg = cfg
        self.dom = DomTree(cfg)
        self.loops = LoopInfo(cfg, self.dom)
        if not self.loops.is_reducible():
            raise ValueError(
                "irreducible CFG — structurizer requires a reducible graph; "
                "caller should fall back to linear emission"
            )
        self.pdom = PostDomTree(cfg)
        self._back_edge_tails: Set[int] = {t for t, _ in self.dom.back_edges()}

    def structure(self) -> StructuredNode:
        """Build and return the structured node tree rooted at the entry block."""
        rpo = self.dom.rpo()
        done: Set[int] = set()
        root = SequenceNode()
        self._build(rpo, 0, None, root, done, loop_header=None)
        return root

    def _build(self,
               rpo: List[int],
               idx: int,
               stop_at: Optional[int],
               parent: SequenceNode,
               done: Set[int],
               loop_header: Optional[int]) -> int:
        """
        Recursively emit structured nodes into *parent* for rpo[idx:].

        Returns the index of the next unprocessed block after we should stop.
        *stop_at* is the label of the first block we must NOT emit (join point
        or loop-exit block).
        """
        while idx < len(rpo):
            label = rpo[idx]

            if label == stop_at:
                return idx
            if label in done:
                idx += 1
                continue

            block = self.cfg.blocks.get(label)
            if block is None:
                idx += 1
                continue

            # ── Case 1: loop header ────────────────────────────────────────────
            if self.loops.is_loop_header(label):
                loop = self.loops._header_map[label]  # intentional: same-package internal coupling
                loop_body_set = loop.body

                # Find the exit block: first block in RPO after the loop header
                # that is NOT in the loop body.
                exit_label: Optional[int] = None
                for i in range(idx + 1, len(rpo)):
                    if rpo[i] not in loop_body_set:
                        exit_label = rpo[i]
                        break

                # Build loop body sub-tree.
                body_seq = SequenceNode()
                body_rpo = [n for n in rpo if n in loop_body_set and n != label]
                # header is processed first (it's the while-condition block)
                body_rpo_with_hdr = [label] + body_rpo
                body_done: Set[int] = set(done)
                # Mark back-edge tails so they become ContinueNode.
                self._build_loop_body(body_rpo_with_hdr, loop, body_seq, body_done,
                                      loop_header=label)

                while_node = WhileNode(
                    header_block=label,
                    body=body_seq,
                    exit_block=exit_label,
                )
                parent.children.append(while_node)

                # Mark all loop blocks done.
                for n in loop_body_set:
                    done.add(n)

                # Continue from the exit block.
                if exit_label is not None:
                    while idx < len(rpo) and rpo[idx] in loop_body_set:
                        idx += 1
                else:
                    idx += 1
                continue

            # ── Case 2: if/else diamond ────────────────────────────────────────
            if len(block.succs) == 2:
                s0, s1 = block.succs[0], block.succs[1]
                # Exclude back edges from if/else treatment.
                s0_is_back = self.dom.dominates(s0, label)
                s1_is_back = self.dom.dominates(s1, label)

                if not s0_is_back and not s1_is_back:
                    join = self.pdom.closest_common_post_dominator(s0, s1)

                    # Build then/else sub-trees up to join.
                    then_rpo = [n for n in rpo
                                if n != join and self.dom.dominates(s0, n)
                                and n not in done and n != label]
                    else_rpo = [n for n in rpo
                                if n != join and self.dom.dominates(s1, n)
                                and n not in done and n != label]

                    then_seq = SequenceNode()
                    else_seq = SequenceNode()
                    sub_done: Set[int] = set(done)
                    sub_done.add(label)

                    self._build([s0] + [n for n in then_rpo if n != s0],
                                0, join, then_seq, sub_done, loop_header)
                    self._build([s1] + [n for n in else_rpo if n != s1],
                                0, join, else_seq, sub_done, loop_header)

                    if_node = IfNode(
                        cond_block=label,
                        then_body=then_seq,
                        else_body=else_seq if else_seq.children else None,
                        join_block=join,
                    )
                    # Prepend the condition block's instructions as an InsnNode
                    # before the IfNode so emit() sees them.
                    cond_insn = InsnNode(block_start=label, insns=list(block.insns))
                    parent.children.append(cond_insn)
                    parent.children.append(if_node)

                    done.add(label)
                    for n in then_rpo + else_rpo:
                        done.add(n)
                    done.add(s0)
                    done.add(s1)

                    # Advance to join block.
                    if join is not None:
                        while idx < len(rpo) and rpo[idx] != join:
                            idx += 1
                    else:
                        idx += 1
                    continue

            # ── Case 3: return ─────────────────────────────────────────────────
            if not block.succs:
                ret_node = ReturnNode(block_start=label, insns=list(block.insns))
                parent.children.append(ret_node)
                done.add(label)
                idx += 1
                continue

            # ── Case 4: unconditional (fall-through or single-successor) ───────
            insn_node = InsnNode(block_start=label, insns=list(block.insns))
            parent.children.append(insn_node)
            done.add(label)
            idx += 1

        return idx

    def _build_loop_body(self,
                         body_rpo: List[int],
                         loop,
                         parent: SequenceNode,
                         done: Set[int],
                         loop_header: int) -> None:
        """
        Build the body of a while loop.  Back-edge-tail blocks (blocks that
        jump back to the header) become ContinueNode.
        """
        idx = 0
        while idx < len(body_rpo):
            label = body_rpo[idx]
            if label in done:
                idx += 1
                continue

            block = self.cfg.blocks.get(label)
            if block is None:
                idx += 1
                continue

            # Back-edge tail → continue
            if label in self._back_edge_tails and loop_header in block.succs:
                tail_node = InsnNode(block_start=label, insns=list(block.insns))
                parent.children.append(tail_node)
                parent.children.append(ContinueNode())
                done.add(label)
                idx += 1
                continue

            # Break: successor is outside the loop body
            if block.succs and all(s not in loop.body for s in block.succs):
                tail_node = InsnNode(block_start=label, insns=list(block.insns))
                parent.children.append(tail_node)
                parent.children.append(BreakNode())
                done.add(label)
                idx += 1
                continue

            # Nested if/else inside the loop
            if len(block.succs) == 2:
                s0, s1 = block.succs[0], block.succs[1]
                if s0 in loop.body and s1 in loop.body:
                    join = self.pdom.closest_common_post_dominator(s0, s1)
                    then_seq = SequenceNode()
                    else_seq = SequenceNode()
                    sub_done: Set[int] = set(done)
                    sub_done.add(label)
                    then_rpo = [n for n in body_rpo
                                if n != join and n not in sub_done
                                and self.dom.dominates(s0, n)]
                    else_rpo = [n for n in body_rpo
                                if n != join and n not in sub_done
                                and self.dom.dominates(s1, n)]
                    self._build_loop_body([s0] + [n for n in then_rpo if n != s0],
                                         loop, then_seq, sub_done, loop_header)
                    self._build_loop_body([s1] + [n for n in else_rpo if n != s1],
                                         loop, else_seq, sub_done, loop_header)
                    cond_insn = InsnNode(block_start=label, insns=list(block.insns))
                    parent.children.append(cond_insn)
                    parent.children.append(IfNode(
                        cond_block=label,
                        then_body=then_seq,
                        else_body=else_seq if else_seq.children else None,
                        join_block=join,
                    ))
                    done.add(label)
                    for n in then_rpo + else_rpo:
                        done.add(n)
                    if join is not None:
                        while idx < len(body_rpo) and body_rpo[idx] != join:
                            idx += 1
                    else:
                        idx += 1
                    continue

            # Default: plain block
            insn_node = InsnNode(block_start=label, insns=list(block.insns))
            parent.children.append(insn_node)
            done.add(label)
            idx += 1

    # ── Emit structured pseudo-C ───────────────────────────────────────────────

    def emit(self, insn_emitter: Callable[[Any], str],
             func_name: str = "func") -> str:
        """
        Render the structured tree to a pseudo-C string.

        *insn_emitter* is called with each instruction object and must return a
        string.  The string is indented automatically by the emit layer.

        Parameters
        ----------
        insn_emitter : callable
            Maps an instruction object to a pseudo-C statement string.
        func_name : str
            Name emitted in the function header comment.
        """
        tree = self.structure()
        lines: List[str] = [f"// {func_name} @ {self.cfg.entry:#x}", "{"]
        self._emit_node(tree, lines, indent=2, insn_emitter=insn_emitter)
        lines.append("}")
        return "\n".join(lines)

    def _emit_node(self, node: StructuredNode, lines: List[str], indent: int,
                   insn_emitter: Callable[[Any], str]) -> None:
        pad = " " * indent

        if isinstance(node, SequenceNode):
            for child in node.children:
                self._emit_node(child, lines, indent, insn_emitter)

        elif isinstance(node, InsnNode):
            for insn in node.insns:
                line = insn_emitter(insn)
                if line:
                    lines.append(f"{pad}{line}")

        elif isinstance(node, ReturnNode):
            for insn in node.insns:
                line = insn_emitter(insn)
                if line:
                    lines.append(f"{pad}{line}")

        elif isinstance(node, WhileNode):
            lines.append(f"{pad}while (/* cond @ {node.header_block:#x} */) {{")
            self._emit_node(node.body, lines, indent + 2, insn_emitter)
            lines.append(f"{pad}}}")

        elif isinstance(node, IfNode):
            lines.append(f"{pad}if (/* cond @ {node.cond_block:#x} */) {{")
            self._emit_node(node.then_body, lines, indent + 2, insn_emitter)
            if node.else_body is not None:
                lines.append(f"{pad}}} else {{")
                self._emit_node(node.else_body, lines, indent + 2, insn_emitter)
            lines.append(f"{pad}}}")

        elif isinstance(node, BreakNode):
            lines.append(f"{pad}break;")

        elif isinstance(node, ContinueNode):
            lines.append(f"{pad}continue;")
