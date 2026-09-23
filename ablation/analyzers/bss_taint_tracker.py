"""
BSS taint tracker: find functions that walk a [start, end) range from adjacent
pointer-sized BSS globals.

Primary use case: locate decrypt loops that consume initrd_start/initrd_end in
stripped Fortinet kernel binaries.

Algorithm:
  1. Collect all BSS loads (mov reg, [abs_addr]) where addr is in a BSS-like region
  2. Find adjacent pointer-pair loads in the same basic block (start_sym, end_sym)
  3. Forward taint propagation over the CFG (register-level only)
  4. Detect loops (back-edges) where a tainted reg is used as both a memory base
     and a comparison bound

Requirements: capstone, ablation.core.ELFParser for ELF-based section detection.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import (
        X86_INS_MOV, X86_INS_MOVZX, X86_INS_MOVSX, X86_INS_MOVQ, X86_INS_LEA,
        X86_INS_ADD, X86_INS_SUB, X86_INS_CMP, X86_INS_TEST,
        X86_INS_JA, X86_INS_JAE, X86_INS_JB, X86_INS_JBE,
        X86_INS_JG, X86_INS_JGE, X86_INS_JL, X86_INS_JLE,
        X86_INS_JE, X86_INS_JNE,
        X86_OP_MEM, X86_OP_REG, X86_OP_IMM, X86_GRP_JUMP,
        X86_REG_RIP,
    )
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

POINTER_SIZE = 8

COND_JUMPS = frozenset([
    X86_INS_JA, X86_INS_JAE, X86_INS_JB, X86_INS_JBE,
    X86_INS_JG, X86_INS_JGE, X86_INS_JL, X86_INS_JLE,
    X86_INS_JE, X86_INS_JNE,
]) if HAS_CAPSTONE else frozenset()


@dataclass
class BSSSymbol:
    addr: int
    size: int
    name: str = ""


@dataclass
class Instr:
    addr: int
    size: int
    insn: object


@dataclass
class BasicBlock:
    start: int
    end: int
    instrs: List[Instr] = field(default_factory=list)
    succs: List[int] = field(default_factory=list)


@dataclass
class Function:
    start: int
    end: int
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    name: str = ""


try:
    from capstone.x86 import X86_INS_JMP, X86_INS_RET, X86_INS_HLT
    _UNCOND_TERM = frozenset([X86_INS_JMP, X86_INS_RET, X86_INS_HLT])
except ImportError:
    _UNCOND_TERM = frozenset()


def build_function(data: bytes, fn_va: int, fn_size: int) -> Function:
    if not HAS_CAPSTONE:
        raise RuntimeError("capstone required")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    raw = data[fn_va:fn_va + fn_size]
    insns = list(md.disasm(raw, fn_va))

    fn = Function(start=fn_va, end=fn_va + fn_size)
    if not insns:
        return fn

    # Pass 1: split into blocks at every control-flow instruction.
    bb = BasicBlock(start=insns[0].addr, end=insns[0].addr)
    for insn in insns:
        bb.instrs.append(Instr(insn.address, insn.size, insn))
        bb.end = insn.address + insn.size
        if insn.group(X86_GRP_JUMP) or insn.id in _UNCOND_TERM:
            fn.blocks[bb.start] = bb
            bb = BasicBlock(start=bb.end, end=bb.end)
    if bb.instrs:
        fn.blocks[bb.start] = bb

    # Pass 2: wire successor edges.
    for bstart, bb in fn.blocks.items():
        if not bb.instrs:
            continue
        last = bb.instrs[-1].insn
        fall_through = bb.end

        if last.id in _UNCOND_TERM and last.id != X86_INS_JMP:
            pass  # ret / hlt: no successors
        elif last.group(X86_GRP_JUMP):
            # Extract jump target from immediate operand.
            for op in last.operands:
                if op.type == X86_OP_IMM:
                    target = op.imm
                    if fn.start <= target < fn.end and target in fn.blocks:
                        bb.succs.append(target)
                    break
            # Conditional jumps also fall through.
            if last.id not in _UNCOND_TERM:
                if fall_through in fn.blocks:
                    bb.succs.append(fall_through)
        else:
            # Straight-line: fall through to next block.
            if fall_through in fn.blocks:
                bb.succs.append(fall_through)

    return fn


class BssTaintTracker:
    """
    Find functions that read adjacent BSS pointer pairs and walk [start, end).

    Usage:
        bss_syms = [BSSSymbol(addr=0xffff..., size=8), ...]
        tracker = BssTaintTracker(bss_syms)
        for fn in functions:
            report = tracker.analyze(fn)
            if report:
                print(report)
    """

    def __init__(self, bss_symbols: List[BSSSymbol]):
        self._syms = sorted(bss_symbols, key=lambda s: s.addr)
        self._by_addr = {s.addr: s for s in self._syms}

    def analyze(self, fn: Function) -> Optional[dict]:
        bss_loads = self._collect_bss_loads(fn)
        if not bss_loads:
            return None

        pairs = self._find_pairs(bss_loads)
        if not pairs:
            return None

        taint = self._forward_taint(fn, bss_loads)
        loops = self._detect_loops(fn, taint, pairs)
        if not loops:
            return None

        return {
            "fn_start": fn.start,
            "fn_name": fn.name,
            "bss_pairs": [(s.addr, e.addr) for _, _, s, e in pairs],
            "loops": loops,
        }

    def _collect_bss_loads(self, fn: Function):
        loads = defaultdict(list)
        for bstart, bb in fn.blocks.items():
            for instr in bb.instrs:
                ins = instr.insn
                if ins.id not in (X86_INS_MOV, X86_INS_LEA) or len(ins.operands) < 2:
                    continue
                dst, src = ins.operands[0], ins.operands[1]
                if dst.type != X86_OP_REG or src.type != X86_OP_MEM:
                    continue
                mem = src.mem
                if mem.base == X86_REG_RIP:
                    target = (instr.addr + instr.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
                elif mem.base == 0 and mem.index == 0:
                    target = mem.disp & 0xFFFFFFFFFFFFFFFF
                else:
                    continue
                sym = self._by_addr.get(target)
                if sym and sym.size >= POINTER_SIZE:
                    loads[bstart].append((instr.addr, sym, dst.reg))
        return loads

    def _find_pairs(self, bss_loads):
        pairs = []
        for bstart, load_list in bss_loads.items():
            by_addr = sorted(load_list, key=lambda x: x[1].addr)
            for i in range(len(by_addr) - 1):
                a_addr, a_sym, _ = by_addr[i]
                b_addr, b_sym, _ = by_addr[i + 1]
                if b_sym.addr == a_sym.addr + POINTER_SIZE:
                    pairs.append((bstart, a_addr, a_sym, b_sym))
        return pairs

    def _forward_taint(self, fn: Function, bss_loads) -> Dict[int, Dict[int, Dict[int, Set]]]:
        taint: Dict[int, Dict[int, Dict[int, Set]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        in_state = {b: defaultdict(set) for b in fn.blocks}
        changed = {b: True for b in fn.blocks}
        wq = deque(fn.blocks.keys())

        while wq:
            bstart = wq.popleft()
            if not changed[bstart]:
                continue
            changed[bstart] = False

            bb = fn.blocks[bstart]
            reg_taint = {r: set(v) for r, v in in_state[bstart].items()}

            for instr in bb.instrs:
                for ld_addr, sym, dest_reg in bss_loads.get(bstart, []):
                    if ld_addr == instr.addr:
                        reg_taint[dest_reg].add(sym)

                taint[bstart][instr.addr] = {r: set(v) for r, v in reg_taint.items()}
                self._propagate(instr.insn, reg_taint)

            for succ in bb.succs:
                local_changed = False
                for r, v in reg_taint.items():
                    before = len(in_state[succ][r])
                    in_state[succ][r].update(v)
                    if len(in_state[succ][r]) > before:
                        local_changed = True
                if local_changed:
                    changed[succ] = True
                    wq.append(succ)

        return taint

    def _propagate(self, ins, reg_taint):
        if len(ins.operands) < 2:
            return
        dst, src = ins.operands[0], ins.operands[1]
        if ins.id in (X86_INS_MOV, X86_INS_MOVZX, X86_INS_MOVSX, X86_INS_LEA):
            if dst.type == X86_OP_REG:
                if src.type == X86_OP_REG and reg_taint.get(src.reg):
                    reg_taint[dst.reg] = set(reg_taint[src.reg])
                elif src.type == X86_OP_IMM:
                    reg_taint[dst.reg].clear()
        elif ins.id in (X86_INS_ADD, X86_INS_SUB):
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                if reg_taint.get(dst.reg) or reg_taint.get(src.reg):
                    reg_taint[dst.reg].update(reg_taint.get(src.reg, set()))

    def _detect_loops(self, fn: Function, taint, pairs):
        back_edges = [
            (tail, head)
            for tail, bb in fn.blocks.items()
            for head in bb.succs
            if head <= tail
        ]

        pair_syms = {(s, e) for _, _, s, e in pairs}
        reports = []

        for tail, head in back_edges:
            loop_blocks = sorted(b for b in fn.blocks if head <= b <= tail)
            has_mem_from_tainted = False
            has_tainted_cmp = False
            involved: Set = set()

            for bstart in loop_blocks:
                bb = fn.blocks[bstart]
                for idx, instr in enumerate(bb.instrs):
                    ins = instr.insn
                    tstate = taint[bstart].get(instr.addr, {})

                    for op in ins.operands:
                        if op.type == X86_OP_MEM and op.mem.base != 0:
                            ts = tstate.get(op.mem.base, set())
                            if ts:
                                has_mem_from_tainted = True
                                involved.update(ts)

                    if ins.id in COND_JUMPS and idx > 0:
                        prev = bb.instrs[idx - 1].insn
                        if prev.id in (X86_INS_CMP, X86_INS_TEST) and len(prev.operands) >= 2:
                            for op in prev.operands:
                                if op.type == X86_OP_REG:
                                    ts = tstate.get(op.reg, set())
                                    if ts:
                                        has_tainted_cmp = True
                                        involved.update(ts)

            if not (has_mem_from_tainted and has_tainted_cmp):
                continue

            matched = [(s.addr, e.addr) for s, e in pair_syms
                       if s in involved or e in involved]
            if matched:
                reports.append({
                    "head": head,
                    "tail": tail,
                    "bss_pairs": matched,
                })

        return reports
