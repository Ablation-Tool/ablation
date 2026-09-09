"""
dataflow_engine.py — MFP worklist engine + analysis instances for binary RE.

Implements Nielson/Nielson/Hankin §2.4.1 Table 2.8: generic Monotone Framework
worklist algorithm over (L, flow, E, ι, f_.) instances. Terminates via ACC.

Also implements Muchnick §7.3/§7.4/§12.6:
  DomTree          — immediate dominator tree (Cooper-Harvey-Kennedy iterative)
  LoopInfo         — natural loop detection from dominator back edges
  SCCPAnalysis     — sparse conditional constant propagation (Wegman-Zadeck)

Lattice instances
-----------------
ConstPropAnalysis    — ARM32/ARM64 register constant propagation
                       Resolves pool loads, immediate chains, and GOT-seeded values.
ReachingDefsAnalysis — ARM32/ARM64 register reaching definitions
                       Produces ud-chains for any (reg, call-site) pair.
SCCPAnalysis         — conditional CP; only propagates through executable edges.
                       Fixes the switch-table (tbh) fragmentation problem.

Quick start
-----------
  data = open('netd', 'rb').read()
  cp = ConstPropAnalysis(data, base_addr=0, arch='arm32')
  mfp_o, _ = cp.solve(func_addr=0x1e6ae)

  # What is r7 at 0x1ed7a?
  print(cp.const_at(mfp_o, 'r7', 0x1ed7a))     # int or None

  rd = ReachingDefsAnalysis(data, base_addr=0, arch='arm32')
  mfp_o, _ = rd.solve(func_addr=0x1e6ae)
  defs = rd.ud_chain(mfp_o, 'r0', 0x1ed80)      # set of definition addresses

  # Dominator tree + loop info
  cfg = CFGBuilder(make_arch('thumb'), data, 0).build(0x1e6ae)
  dom = DomTree(cfg)
  loops = LoopInfo(cfg, dom)
  print(loops.loop_depth(0x1ed68))   # nesting depth of a block
  print(dom.back_edges())            # (tail, header) pairs

  # SCCP — sparse conditional CP
  sccp = SCCPAnalysis(data, base_addr=0, arch='thumb')
  cp_vals, exec_edges = sccp.solve(func_addr=0x1e6ae)
  print(sccp.const_at(cp_vals, 'r7', 0x1ed68))  # only if edge proven executable
"""

from __future__ import annotations

import struct
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

import capstone
from capstone import arm as C_ARM
from capstone import arm64 as C_ARM64

# ⊤ in Z^T (non-constant — register value is unknown)
_TOP = object()


# ─── Lattice ──────────────────────────────────────────────────────────────────

class Lattice(ABC):
    """(L, ⊑, ⊔, ⊥)"""

    @abstractmethod
    def bottom(self) -> Any: ...

    @abstractmethod
    def join(self, a: Any, b: Any) -> Any: ...

    @abstractmethod
    def leq(self, a: Any, b: Any) -> bool:
        """a ⊑ b"""


# ─── CFG types ────────────────────────────────────────────────────────────────

@dataclass
class BasicBlock:
    label: int                            # first instruction address
    insns: list                           # list of capstone CsInsn
    succs: List[int] = field(default_factory=list)
    preds: List[int] = field(default_factory=list)


@dataclass
class CFG:
    blocks: Dict[int, BasicBlock]
    flow: List[Tuple[int, int]]           # (ℓ, ℓ') forward edges
    entry: int

    def flow_r(self) -> List[Tuple[int, int]]:
        return [(b, a) for a, b in self.flow]


# ─── Architecture config ───────────────────────────────────────────────────────

class ArchConfig(ABC):
    """CFG and register semantics for a target architecture."""

    @abstractmethod
    def cs(self) -> capstone.Cs: ...

    @abstractmethod
    def is_return(self, insn) -> bool: ...

    @abstractmethod
    def is_unconditional_branch(self, insn) -> bool: ...

    @abstractmethod
    def is_conditional_branch(self, insn) -> bool: ...

    @abstractmethod
    def branch_target(self, insn) -> Optional[int]: ...

    @abstractmethod
    def is_call(self, insn) -> bool: ...

    @abstractmethod
    def call_clobbers(self) -> List[str]: ...

    @abstractmethod
    def dest_reg(self, insn) -> Optional[str]: ...

    @abstractmethod
    def pc_relative_load(self, insn) -> Optional[Tuple[str, int]]:
        """If insn is LDR rd, [pc, #off], return (rd, pool_addr). Else None."""

    @abstractmethod
    def all_regs(self) -> List[str]: ...


class ARM32Config(ArchConfig):
    _BRANCH_MN  = frozenset(['b', 'beq', 'bne', 'bcs', 'bcc', 'bmi', 'bpl',
                              'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble'])
    _RETURN_MN  = frozenset(['bx', 'bxeq', 'bxne'])
    _CALL_MN    = frozenset(['bl', 'blx', 'bleq', 'blne', 'blge', 'bllt',
                              'blgt', 'blle', 'blcs', 'blcc'])
    _COND_SUFFIXES = frozenset(['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
                                 'hi', 'ls', 'ge', 'lt', 'gt', 'le'])

    def __init__(self):
        self._cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self._cs.detail = True
        self._cs.skipdata = True

    def cs(self): return self._cs

    def _mn(self, insn) -> str:
        return insn.mnemonic.lower()

    def is_return(self, insn) -> bool:
        mn = self._mn(insn)
        op = insn.op_str.lower()
        # BX LR (all condition variants)
        if mn.startswith('bx') and 'lr' in op:
            return True
        # POP {…, pc} or LDM … pc
        if (mn.startswith('pop') or mn.startswith('ldm')) and 'pc' in op:
            return True
        return False

    def is_unconditional_branch(self, insn) -> bool:
        return self._mn(insn) == 'b'

    def is_conditional_branch(self, insn) -> bool:
        mn = self._mn(insn)
        if mn == 'b':
            return False
        for suf in self._COND_SUFFIXES:
            if mn.endswith(suf) and len(mn) > len(suf) and mn[:-len(suf)] == 'b':
                return True
        return False

    def branch_target(self, insn) -> Optional[int]:
        try:
            for op in insn.operands:
                if op.type == C_ARM.ARM_OP_IMM:
                    return op.imm
        except Exception:
            pass
        try:
            return int(insn.op_str.strip().lstrip('#'), 16)
        except Exception:
            return None

    def is_call(self, insn) -> bool:
        mn = self._mn(insn)
        return mn in self._CALL_MN or mn.startswith('bl')

    def call_clobbers(self) -> List[str]:
        return ['r0', 'r1', 'r2', 'r3', 'r12']

    def dest_reg(self, insn) -> Optional[str]:
        mn = self._mn(insn)
        # Instructions that don't write a dest reg
        if mn.startswith(('str', 'stm', 'cmp', 'tst', 'cmn', 'teq', 'b', 'nop')):
            return None
        try:
            ops = insn.operands
        except Exception:
            return None
        if ops:
            op0 = ops[0]
            if op0.type == C_ARM.ARM_OP_REG:
                return insn.reg_name(op0.reg).lower()
        return None

    def pc_relative_load(self, insn) -> Optional[Tuple[str, int]]:
        mn = self._mn(insn)
        if not mn.startswith('ldr'):
            return None
        try:
            ops = insn.operands
        except Exception:
            return None
        if len(ops) < 2:
            return None
        op1 = ops[1]
        if op1.type != C_ARM.ARM_OP_MEM:
            return None
        if op1.mem.base != C_ARM.ARM_REG_PC:
            return None
        rd = insn.reg_name(insn.operands[0].reg).lower()
        # ARM32: PC = insn_addr + 8, word-aligned
        pool_addr = (insn.address & ~3) + 8 + op1.mem.disp
        return (rd, pool_addr)

    def all_regs(self) -> List[str]:
        return [f'r{i}' for i in range(13)] + ['sp', 'lr', 'pc']


class ARM64Config(ArchConfig):
    _COND_BRANCH = frozenset([
        C_ARM64.ARM64_INS_CBZ, C_ARM64.ARM64_INS_CBNZ,
        C_ARM64.ARM64_INS_TBZ, C_ARM64.ARM64_INS_TBNZ,
    ])

    def __init__(self):
        self._cs = capstone.Cs(capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
        self._cs.detail = True
        self._cs.skipdata = True

    def cs(self): return self._cs

    def _norm(self, name: str) -> str:
        """Normalise w-registers to x-registers."""
        if name.startswith('w') and name[1:].isdigit():
            return 'x' + name[1:]
        return name

    def is_return(self, insn) -> bool:
        return insn.id == C_ARM64.ARM64_INS_RET

    def _is_cond_b(self, insn) -> bool:
        if insn.id in self._COND_BRANCH:
            return True
        if insn.id == C_ARM64.ARM64_INS_B:
            cc = insn.cc
            return cc not in (C_ARM64.ARM64_CC_AL, C_ARM64.ARM64_CC_INVALID, 0)
        return False

    def is_unconditional_branch(self, insn) -> bool:
        return (insn.id in (C_ARM64.ARM64_INS_B, C_ARM64.ARM64_INS_BR)
                and not self._is_cond_b(insn))

    def is_conditional_branch(self, insn) -> bool:
        return self._is_cond_b(insn)

    def branch_target(self, insn) -> Optional[int]:
        for op in insn.operands:
            if op.type == C_ARM64.ARM64_OP_IMM:
                return op.imm
        return None

    def is_call(self, insn) -> bool:
        return insn.id in (C_ARM64.ARM64_INS_BL, C_ARM64.ARM64_INS_BLR)

    def call_clobbers(self) -> List[str]:
        return [f'x{i}' for i in range(18)]

    def dest_reg(self, insn) -> Optional[str]:
        mn = insn.mnemonic.lower()
        if mn.startswith(('str', 'stp', 'cmp', 'tst', 'b', 'nop', 'ret')):
            return None
        if insn.operands:
            op0 = insn.operands[0]
            if op0.type == C_ARM64.ARM64_OP_REG:
                return self._norm(insn.reg_name(op0.reg))
        return None

    def pc_relative_load(self, insn) -> Optional[Tuple[str, int]]:
        # LDR xd, label (literal form: operands[1].mem.base = PC)
        mn = insn.mnemonic.lower()
        if not mn.startswith('ldr'):
            return None
        if len(insn.operands) < 2:
            return None
        op1 = insn.operands[1]
        if op1.type == C_ARM64.ARM64_OP_IMM:
            rd = self._norm(insn.reg_name(insn.operands[0].reg))
            return (rd, op1.imm)
        if op1.type == C_ARM64.ARM64_OP_MEM and op1.mem.base == C_ARM64.ARM64_REG_PC:
            rd = self._norm(insn.reg_name(insn.operands[0].reg))
            return (rd, insn.address + op1.mem.disp)
        return None

    def all_regs(self) -> List[str]:
        return [f'x{i}' for i in range(31)] + ['sp']


def make_arch(arch: str) -> ArchConfig:
    if arch in ('arm32', 'arm'):
        return ARM32Config()
    if arch in ('arm64', 'aarch64'):
        return ARM64Config()
    if arch in ('thumb', 'thumb2', 'arm32t'):
        return THUMB2Config()
    raise ValueError(f'Unknown arch: {arch!r}')


class THUMB2Config(ArchConfig):
    """ARMv7 THUMB-2 mixed 16/32-bit encoding (CS_MODE_THUMB).

    PC-relative address formula differs from ARM32:
      pool_addr = Align(insn.address + 4, 4) + disp
                = ((insn.address + 4) & ~3) + disp
    """

    _CALL_MN = frozenset(['bl', 'blx'])
    _COND_SUFFIXES = frozenset(['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
                                 'hi', 'ls', 'ge', 'lt', 'gt', 'le'])

    def __init__(self):
        self._cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self._cs.detail = True
        self._cs.skipdata = True

    def cs(self): return self._cs

    def _mn(self, insn) -> str:
        return insn.mnemonic.lower()

    def is_return(self, insn) -> bool:
        mn = self._mn(insn)
        op = insn.op_str.lower()
        if mn.startswith('bx') and 'lr' in op:
            return True
        if (mn.startswith('pop') or mn.startswith('ldm')) and 'pc' in op:
            return True
        return False

    def _bare(self, mn: str) -> str:
        """Strip THUMB .w suffix and ARM condition code suffix."""
        if mn.endswith('.w'):
            mn = mn[:-2]
        for suf in self._COND_SUFFIXES:
            if mn.endswith(suf) and len(mn) > len(suf):
                return mn[:-len(suf)]
        return mn

    def is_unconditional_branch(self, insn) -> bool:
        mn = self._mn(insn)
        return self._bare(mn) == 'b' and mn in ('b', 'b.w')

    def is_conditional_branch(self, insn) -> bool:
        mn = self._mn(insn)
        bare = self._bare(mn)
        return bare == 'b' and mn not in ('b', 'b.w')

    def branch_target(self, insn) -> Optional[int]:
        try:
            for op in insn.operands:
                if op.type == C_ARM.ARM_OP_IMM:
                    return op.imm
        except Exception:
            pass
        try:
            return int(insn.op_str.strip().lstrip('#'), 16)
        except Exception:
            return None

    def is_call(self, insn) -> bool:
        mn = self._mn(insn)
        return mn in self._CALL_MN or mn.startswith('bl')

    def call_clobbers(self) -> List[str]:
        return ['r0', 'r1', 'r2', 'r3', 'r12']

    def dest_reg(self, insn) -> Optional[str]:
        mn = self._mn(insn)
        if mn.startswith(('str', 'stm', 'cmp', 'tst', 'cmn', 'teq', 'b', 'nop')):
            return None
        try:
            ops = insn.operands
        except Exception:
            return None
        if ops:
            op0 = ops[0]
            if op0.type == C_ARM.ARM_OP_REG:
                return insn.reg_name(op0.reg).lower()
        return None

    def pc_relative_load(self, insn) -> Optional[Tuple[str, int]]:
        mn = self._mn(insn)
        if not mn.startswith('ldr'):
            return None
        try:
            ops = insn.operands
        except Exception:
            return None
        if len(ops) < 2:
            return None
        op1 = ops[1]
        if op1.type != C_ARM.ARM_OP_MEM:
            return None
        if op1.mem.base != C_ARM.ARM_REG_PC:
            return None
        rd = insn.reg_name(ops[0].reg).lower()
        # THUMB: pool_addr = Align(insn.address + 4, 4) + disp
        pool_addr = ((insn.address + 4) & ~3) + op1.mem.disp
        return (rd, pool_addr)

    def all_regs(self) -> List[str]:
        return [f'r{i}' for i in range(13)] + ['sp', 'lr', 'pc']


# ─── CFG builder ──────────────────────────────────────────────────────────────

_MAX_FUNC_BYTES = 0xC000   # 48 KB ceiling

class CFGBuilder:
    def __init__(self, arch: ArchConfig, data: bytes, base_addr: int):
        self.arch = arch
        self.data = data
        self.base = base_addr

    def _raw_insns(self, addr: int, n_bytes: int = 512) -> list:
        off = addr - self.base
        if off < 0 or off >= len(self.data):
            return []
        return list(self.arch.cs().disasm(
            self.data[off: off + n_bytes], addr
        ))

    def build(self, func_addr: int) -> CFG:
        arch = self.arch
        # addr → capstone insn
        insn_map: Dict[int, Any] = {}
        # last insn addr of each run → its successor addresses
        term_succs: Dict[int, List[int]] = {}

        to_visit: deque = deque([func_addr])
        visited: Set[int] = set()
        ceiling = func_addr + _MAX_FUNC_BYTES

        while to_visit:
            start = to_visit.popleft()
            if start in visited or start < func_addr or start >= ceiling:
                continue
            visited.add(start)

            raw = self._raw_insns(start)
            if not raw:
                continue

            for i, insn in enumerate(raw):
                if insn.address in insn_map:
                    # merged into previously decoded region
                    if i > 0:
                        prev_addr = raw[i - 1].address
                        if prev_addr not in term_succs:
                            term_succs[prev_addr] = [insn.address]
                    break

                insn_map[insn.address] = insn
                next_addr = insn.address + insn.size

                if arch.is_return(insn):
                    term_succs[insn.address] = []
                    break

                if arch.is_call(insn):
                    # do not recurse into callee; call ends this BB
                    term_succs[insn.address] = [next_addr]
                    to_visit.append(next_addr)
                    break

                if arch.is_unconditional_branch(insn):
                    tgt = arch.branch_target(insn)
                    term_succs[insn.address] = [tgt] if tgt else []
                    if tgt:
                        to_visit.append(tgt)
                    break

                if arch.is_conditional_branch(insn):
                    tgt = arch.branch_target(insn)
                    succs = [next_addr]
                    if tgt:
                        succs.append(tgt)
                        to_visit.append(tgt)
                    term_succs[insn.address] = succs
                    to_visit.append(next_addr)
                    break

                if i == len(raw) - 1:
                    # window exhausted; add fall-through
                    term_succs[insn.address] = [next_addr]
                    to_visit.append(next_addr)

        # Leaders: function entry + every successor of a terminator
        leaders: Set[int] = {func_addr}
        for succs in term_succs.values():
            leaders.update(succs)

        # Partition insn_map into basic blocks
        sorted_addrs = sorted(insn_map.keys())
        blocks: Dict[int, BasicBlock] = {}
        cur_leader: Optional[int] = None
        cur_insns: List[Any] = []

        for addr in sorted_addrs:
            if addr in leaders:
                if cur_leader is not None and cur_insns:
                    blocks[cur_leader] = BasicBlock(cur_leader, cur_insns)
                cur_leader = addr
                cur_insns = []
            cur_insns.append(insn_map[addr])
            if addr in term_succs:
                blocks[cur_leader] = BasicBlock(cur_leader, cur_insns)
                cur_leader = None
                cur_insns = []

        if cur_leader is not None and cur_insns:
            blocks[cur_leader] = BasicBlock(cur_leader, cur_insns)

        # Wire flow edges and pred/succ lists
        flow: List[Tuple[int, int]] = []
        for label, block in blocks.items():
            if not block.insns:
                continue
            last_addr = block.insns[-1].address
            for succ in term_succs.get(last_addr, []):
                if succ in blocks:
                    flow.append((label, succ))
                    block.succs.append(succ)
                    blocks[succ].preds.append(label)

        return CFG(blocks=blocks, flow=flow, entry=func_addr)


# ─── MFP worklist (Table 2.8) ─────────────────────────────────────────────────

class MFPEngine:
    """
    Monotone Framework MFP solver.

    For forward analysis (default):
      Analysis[ℓ] = entry state.
      f_ℓ maps entry → exit.
      Flow (ℓ, ℓ') propagates exit of ℓ to entry of ℓ'.

    For backward analysis (backward=True):
      Pass cfg.flow_r() as the flow or set backward=True to auto-reverse.
    """

    def solve(
        self,
        lattice: Lattice,
        cfg: CFG,
        transfer: Dict[int, Callable[[Any], Any]],
        extremal_labels: Set[int],
        extremal_value: Any,
        backward: bool = False,
    ) -> Tuple[Dict[int, Any], Dict[int, Any]]:
        """
        Returns (MFP_o, MFP_bullet):
          MFP_o[ℓ]      = entry state at ℓ (= Analysis[ℓ] at termination)
          MFP_bullet[ℓ] = f_ℓ(MFP_o[ℓ])
        """
        flow = cfg.flow_r() if backward else cfg.flow
        bot = lattice.bottom()
        identity: Callable = lambda s: s

        # Step 1 — initialise
        analysis: Dict[int, Any] = {
            lbl: (extremal_value if lbl in extremal_labels else bot)
            for lbl in cfg.blocks
        }
        worklist: deque = deque(flow)

        # Step 2 — iterate
        while worklist:
            (l, l_prime) = worklist.popleft()
            if l not in cfg.blocks or l_prime not in cfg.blocks:
                continue
            f_l = transfer.get(l, identity)
            propagated = f_l(analysis[l])
            if not lattice.leq(propagated, analysis[l_prime]):
                analysis[l_prime] = lattice.join(analysis[l_prime], propagated)
                for (lp, lpp) in flow:
                    if lp == l_prime:
                        worklist.append((lp, lpp))

        # Step 3 — present
        mfp_o = dict(analysis)
        mfp_bullet = {
            lbl: transfer.get(lbl, identity)(analysis[lbl])
            for lbl in cfg.blocks
        }
        return mfp_o, mfp_bullet


# ─── Constant Propagation ─────────────────────────────────────────────────────
# State_CP = None | dict[reg → int | _TOP]
# None  = ⊥ (unreachable)
# _TOP  = ⊤ (non-constant)

class _ConstPropLattice(Lattice):
    def __init__(self, regs: List[str]):
        self._regs = regs

    def bottom(self) -> Any:
        return None

    def _join_z(self, a, b):
        if a is _TOP or b is _TOP:
            return _TOP
        if a == b:
            return a
        return _TOP

    def join(self, a, b):
        if a is None:
            return b
        if b is None:
            return a
        return {r: self._join_z(a.get(r, _TOP), b.get(r, _TOP))
                for r in self._regs}

    def _leq_z(self, a, b) -> bool:
        if b is _TOP:
            return True
        if a is _TOP:
            return False
        return a == b

    def leq(self, a, b) -> bool:
        if a is None:
            return True
        if b is None:
            return False
        return all(self._leq_z(a.get(r, _TOP), b.get(r, _TOP))
                   for r in self._regs)


def _cp_transfer_block(
    block: BasicBlock,
    state,
    arch: ArchConfig,
    data: bytes,
    base: int,
    got_seed: Dict[int, int],
) -> Any:
    """Apply block transfer function for Constant Propagation."""
    if state is None:
        return None

    s: Dict[str, Any] = dict(state)

    for insn in block.insns:
        if insn.id == 0:       # skipdata / data byte — no operands available
            continue
        mn = insn.mnemonic.lower()

        # --- pool-relative load: LDR rd, [pc, #off] ---
        pc_rel = arch.pc_relative_load(insn)
        if pc_rel is not None:
            rd, pool_addr = pc_rel
            off = pool_addr - base
            if 0 <= off <= len(data) - 4:
                val = struct.unpack_from('<I', data, off)[0]
                s[rd] = val
                continue
            s[rd] = _TOP
            continue

        # --- GOT dereference: LDR rd, [rn] where rn holds a GOT addr ---
        if mn.startswith('ldr') and len(insn.operands) >= 2:
            op1 = insn.operands[1]
            rd = arch.dest_reg(insn)
            if rd is None:
                continue
            if hasattr(op1, 'mem') and op1.mem.disp == 0:
                base_reg = insn.reg_name(op1.mem.base).lower() if op1.mem.base else None
                if base_reg and base_reg in s and isinstance(s[base_reg], int):
                    got_addr = s[base_reg]
                    if got_addr in got_seed:
                        s[rd] = got_seed[got_addr]
                        continue
            s[rd] = _TOP
            continue

        # --- any LDR without pc-rel ---
        if mn.startswith('ldr'):
            rd = arch.dest_reg(insn)
            if rd:
                s[rd] = _TOP
            continue

        # --- MOV rd, #imm ---
        if mn.startswith('mov') and len(insn.operands) >= 2:
            rd = arch.dest_reg(insn)
            if rd is None:
                continue
            op1 = insn.operands[1]
            if hasattr(op1, 'imm') and op1.type in (
                C_ARM.ARM_OP_IMM, C_ARM64.ARM64_OP_IMM
            ):
                s[rd] = op1.imm & 0xFFFFFFFF
            elif hasattr(op1, 'reg') and op1.type in (
                C_ARM.ARM_OP_REG, C_ARM64.ARM64_OP_REG
            ):
                src = insn.reg_name(op1.reg).lower()
                if src.startswith('w') and src[1:].isdigit():
                    src = 'x' + src[1:]
                s[rd] = s.get(src, _TOP)
            else:
                s[rd] = _TOP
            continue

        # --- ADD rd, PC (THUMB special: 2-op, rd += PC, no alignment) ---
        if mn == 'add' and len(insn.operands) == 2:
            rd = arch.dest_reg(insn)
            op1 = insn.operands[1]
            if rd and hasattr(op1, 'reg') and op1.type == C_ARM.ARM_OP_REG:
                src_name = insn.reg_name(op1.reg).lower()
                if src_name == 'pc':
                    # THUMB arithmetic PC = insn_addr + 4 (no word-alignment)
                    pc_val = insn.address + 4
                    old_rd = s.get(rd, _TOP)
                    if isinstance(old_rd, int):
                        s[rd] = (old_rd + pc_val) & 0xFFFFFFFF
                    else:
                        s[rd] = _TOP
                else:
                    src_val = s.get(src_name, _TOP)
                    old_rd = s.get(rd, _TOP)
                    if isinstance(old_rd, int) and isinstance(src_val, int):
                        s[rd] = (old_rd + src_val) & 0xFFFFFFFF
                    else:
                        s[rd] = _TOP
            elif rd:
                s[rd] = _TOP
            continue

        # --- ADD/SUB rd, rn, #imm ---
        if (mn.startswith('add') or mn.startswith('sub')) and len(insn.operands) >= 3:
            rd = arch.dest_reg(insn)
            if rd is None:
                continue
            op1 = insn.operands[1]
            op2 = insn.operands[2]
            rn_name = None
            if hasattr(op1, 'reg') and op1.type in (
                C_ARM.ARM_OP_REG, C_ARM64.ARM64_OP_REG
            ):
                rn_name = insn.reg_name(op1.reg).lower()
                if rn_name.startswith('w') and rn_name[1:].isdigit():
                    rn_name = 'x' + rn_name[1:]
            rn_val = s.get(rn_name, _TOP) if rn_name else _TOP
            imm = None
            if hasattr(op2, 'imm') and op2.type in (
                C_ARM.ARM_OP_IMM, C_ARM64.ARM64_OP_IMM
            ):
                imm = op2.imm
            if isinstance(rn_val, int) and imm is not None:
                delta = imm if mn.startswith('add') else -imm
                s[rd] = (rn_val + delta) & 0xFFFFFFFFFFFFFFFF
            else:
                s[rd] = _TOP
            continue

        # --- MOVZ / MOVK (ARM64 constant construction) ---
        if mn in ('movz', 'movn') and len(insn.operands) >= 2:
            rd = arch.dest_reg(insn)
            if rd:
                op1 = insn.operands[1]
                shift = insn.operands[2].imm if len(insn.operands) > 2 else 0
                if hasattr(op1, 'imm') and op1.type == C_ARM64.ARM64_OP_IMM:
                    val = op1.imm << shift
                    if mn == 'movn':
                        val = (~val) & 0xFFFFFFFFFFFFFFFF
                    s[rd] = val
                else:
                    s[rd] = _TOP
            continue

        if mn == 'movk' and len(insn.operands) >= 2:
            rd = arch.dest_reg(insn)
            if rd:
                op1 = insn.operands[1]
                shift = insn.operands[2].imm if len(insn.operands) > 2 else 0
                if hasattr(op1, 'imm') and op1.type == C_ARM64.ARM64_OP_IMM:
                    old = s.get(rd, _TOP)
                    if isinstance(old, int):
                        mask = ~(0xFFFF << shift) & 0xFFFFFFFFFFFFFFFF
                        s[rd] = (old & mask) | ((op1.imm & 0xFFFF) << shift)
                    else:
                        s[rd] = _TOP
                else:
                    s[rd] = _TOP
            continue

        # --- ADRP / ADR (ARM64) ---
        if mn in ('adrp', 'adr') and len(insn.operands) >= 2:
            rd = arch.dest_reg(insn)
            if rd:
                op1 = insn.operands[1]
                if hasattr(op1, 'imm') and op1.type == C_ARM64.ARM64_OP_IMM:
                    if mn == 'adrp':
                        s[rd] = (insn.address & ~0xFFF) + op1.imm
                    else:
                        s[rd] = insn.address + op1.imm
                else:
                    s[rd] = _TOP
            continue

        # --- calls: clobber ABI caller-saved registers ---
        if arch.is_call(insn):
            for r in arch.call_clobbers():
                s[r] = _TOP
            continue

        # --- stores, comparisons, branches: no register write ---
        if mn.startswith(('str', 'stp', 'stm', 'cmp', 'tst', 'cmn', 'teq',
                          'b', 'nop', 'push')):
            continue

        # --- fallthrough: any other instruction with a dest reg → TOP ---
        rd = arch.dest_reg(insn)
        if rd:
            s[rd] = _TOP

    return s


class ConstPropAnalysis:
    """
    Monotone Framework instance: Constant Propagation for binary RE.

    Resolves pool-relative loads, immediate MOV chains, MOVZ/MOVK sequences
    (ARM64), ADRP+ADD patterns, and GOT entries when pre-seeded.
    """

    def __init__(
        self,
        data: bytes,
        base_addr: int,
        arch: str = 'arm32',
        got_seed: Optional[Dict[int, int]] = None,
    ):
        self._arch = make_arch(arch)
        self._data = data
        self._base = base_addr
        self._got = got_seed or {}
        self._lattice = _ConstPropLattice(self._arch.all_regs())
        self._builder = CFGBuilder(self._arch, data, base_addr)
        self._engine = MFPEngine()

    def solve(
        self,
        func_addr: int,
        initial_regs: Optional[Dict[str, int]] = None,
    ) -> Tuple[Dict[int, Any], Dict[int, Any]]:
        """
        Compute MFP for func_addr.

        initial_regs: seed specific register values at entry
                      (e.g. {'r0': 0x5cd00} to model a known argument).
        Returns (MFP_o, MFP_bullet) — entry and exit states per basic block label.
        """
        cfg = self._builder.build(func_addr)
        if not cfg.blocks:
            return {}, {}

        all_regs = self._arch.all_regs()
        extremal: Dict[str, Any] = {r: _TOP for r in all_regs}
        if initial_regs:
            extremal.update(initial_regs)

        # Build per-block transfer functions
        transfer: Dict[int, Callable] = {}
        for label, block in cfg.blocks.items():
            _block = block
            _arch = self._arch
            _data = self._data
            _base = self._base
            _got = self._got
            transfer[label] = (lambda b, a, d, bs, g:
                lambda s: _cp_transfer_block(b, s, a, d, bs, g)
            )(_block, _arch, _data, _base, _got)

        return self._engine.solve(
            self._lattice,
            cfg,
            transfer,
            extremal_labels={cfg.entry},
            extremal_value=extremal,
        )

    def const_at(self, mfp_o: Dict[int, Any], reg: str, block_label: int) -> Optional[int]:
        """
        Return the constant value of reg at entry of block_label, or None.
        block_label is the address of the first instruction in the block.
        """
        state = mfp_o.get(block_label)
        if state is None:
            return None
        v = state.get(reg, _TOP)
        return None if (v is _TOP or v is None) else v

    def const_before(self, mfp_o: Dict[int, Any], mfp_bul: Dict[int, Any],
                     reg: str, insn_addr: int, cfg: Optional[CFG] = None) -> Optional[int]:
        """
        Return the constant value of reg *immediately before* insn_addr.
        Requires replaying the block transfer up to insn_addr.
        """
        # find the block containing insn_addr
        if cfg is None:
            return self.const_at(mfp_o, reg, insn_addr)
        for label, block in cfg.blocks.items():
            addrs = [i.address for i in block.insns]
            if insn_addr not in addrs:
                continue
            # replay from block entry state up to (but not including) insn_addr
            state = mfp_o.get(label)
            if state is None:
                return None
            s = dict(state)
            for insn in block.insns:
                if insn.address == insn_addr:
                    v = s.get(reg, _TOP)
                    return None if (v is _TOP or v is None) else v
                s = _cp_transfer_block(
                    BasicBlock(insn.address, [insn]), s,
                    self._arch, self._data, self._base, self._got
                ) or s
        return None


# ─── Reaching Definitions ─────────────────────────────────────────────────────
# State_RD = frozenset of (reg: str, def_addr: int | None)
# None as def_addr = initial undefined value (the '?' marker)

class _ReachingDefsLattice(Lattice):
    def bottom(self) -> FrozenSet:
        return frozenset()

    def join(self, a, b) -> FrozenSet:
        return a | b

    def leq(self, a, b) -> bool:
        return a <= b


def _rd_transfer_block(
    block: BasicBlock,
    state: FrozenSet,
    arch: ArchConfig,
) -> FrozenSet:
    """Apply block transfer function for Reaching Definitions."""
    s: Set = set(state)

    for insn in block.insns:
        if insn.id == 0:
            continue
        rd = arch.dest_reg(insn)
        if rd is None:
            # calls clobber ABI registers — treat each as a new def
            if arch.is_call(insn):
                for r in arch.call_clobbers():
                    s = {(reg, lbl) for (reg, lbl) in s if reg != r}
                    s.add((r, insn.address))
            continue
        # kill all prior defs for rd; gen one new def
        s = {(reg, lbl) for (reg, lbl) in s if reg != rd}
        s.add((rd, insn.address))

    return frozenset(s)


class ReachingDefsAnalysis:
    """
    Monotone Framework instance: Reaching Definitions for binary RE.

    Produces ud-chains: the set of definition sites that reach a
    given register at a given instruction address.
    """

    def __init__(self, data: bytes, base_addr: int, arch: str = 'arm32'):
        self._arch = make_arch(arch)
        self._data = data
        self._base = base_addr
        self._lattice = _ReachingDefsLattice()
        self._builder = CFGBuilder(self._arch, data, base_addr)
        self._engine = MFPEngine()

    def solve(self, func_addr: int) -> Tuple[Dict[int, FrozenSet], Dict[int, FrozenSet]]:
        """
        Compute RD MFP for func_addr.
        Initial value: each register has one def entry (reg, None) — the '?' initial defs.
        """
        cfg = self._builder.build(func_addr)
        if not cfg.blocks:
            return {}, {}

        # ι = {(r, None) for r in all_regs}  (each reg initially undefined)
        extremal: FrozenSet = frozenset(
            (r, None) for r in self._arch.all_regs()
        )

        transfer: Dict[int, Callable] = {}
        for label, block in cfg.blocks.items():
            _block = block
            _arch = self._arch
            transfer[label] = (lambda b, a: lambda s: _rd_transfer_block(b, s, a))(
                _block, _arch
            )

        return self._engine.solve(
            self._lattice,
            cfg,
            transfer,
            extremal_labels={cfg.entry},
            extremal_value=extremal,
        )

    def ud_chain(
        self,
        mfp_o: Dict[int, FrozenSet],
        reg: str,
        block_label: int,
    ) -> Set[Optional[int]]:
        """
        Return the set of instruction addresses where reg was defined
        that reach the entry of block_label.
        None in the returned set means the initial (function-parameter) definition.
        """
        state = mfp_o.get(block_label, frozenset())
        return {lbl for (r, lbl) in state if r == reg}

    def reaching_defs(
        self,
        mfp_o: Dict[int, FrozenSet],
        block_label: int,
    ) -> Dict[str, Set[Optional[int]]]:
        """All ud-chains at block_label entry, keyed by register name."""
        state = mfp_o.get(block_label, frozenset())
        out: Dict[str, Set] = {}
        for (r, lbl) in state:
            out.setdefault(r, set()).add(lbl)
        return out


# ─── Dominator Tree (Cooper-Harvey-Kennedy 2001) ──────────────────────────────

class DomTree:
    """
    Immediate dominator computation — Cooper, Harvey, Kennedy 2001.

    Iterative O(n²) algorithm. Converges in ~2-3 passes on reducible CFGs,
    which covers virtually all compiled firmware functions.

    Usage:
      cfg = CFGBuilder(...).build(func_addr)
      dom = DomTree(cfg)
      dom.dominates(a, b)     -> bool
      dom.idom(n)             -> int | None  (None for entry)
      dom.back_edges()        -> [(tail, header), ...]
      dom.rpo()               -> [label, ...]  (reverse post-order)
    """

    def __init__(self, cfg: CFG):
        self.cfg = cfg
        self._idom: Dict[int, int] = {}   # label → immediate dominator label
        self._rpo: List[int] = []
        self._rpo_num: Dict[int, int] = {}
        if cfg.blocks:
            self._compute()

    def _compute(self) -> None:
        entry = self.cfg.entry

        # 1. Iterative DFS to get post-order, then reverse for RPO
        visited: Set[int] = set()
        post: List[int] = []
        stack: List[Tuple[int, bool]] = [(entry, False)]

        while stack:
            n, processed = stack.pop()
            if processed:
                post.append(n)
                continue
            if n in visited or n not in self.cfg.blocks:
                continue
            visited.add(n)
            stack.append((n, True))
            for s in reversed(self.cfg.blocks[n].succs):
                if s not in visited and s in self.cfg.blocks:
                    stack.append((s, False))

        self._rpo = list(reversed(post))
        self._rpo_num = {n: i for i, n in enumerate(self._rpo)}

        # 2. CHA fixed-point: idom[entry] = entry; others start undefined
        idom: Dict[int, Optional[int]] = {n: None for n in self.cfg.blocks}
        idom[entry] = entry

        changed = True
        while changed:
            changed = False
            for n in self._rpo:
                if n == entry:
                    continue
                # processed predecessors only
                preds = [
                    p for p in self.cfg.blocks[n].preds
                    if p in self.cfg.blocks and idom.get(p) is not None
                ]
                if not preds:
                    continue
                new_idom = preds[0]
                for p in preds[1:]:
                    new_idom = self._intersect(p, new_idom, idom)
                if idom[n] != new_idom:
                    idom[n] = new_idom
                    changed = True

        self._idom = {k: v for k, v in idom.items() if v is not None}

    def _intersect(self, b1: int, b2: int, idom: Dict[int, Optional[int]]) -> int:
        """Walk both fingers up the dominator tree until they meet (CHA §3)."""
        while b1 != b2:
            while self._rpo_num.get(b1, 0) > self._rpo_num.get(b2, 0):
                b1 = idom[b1]
            while self._rpo_num.get(b2, 0) > self._rpo_num.get(b1, 0):
                b2 = idom[b2]
        return b1

    def idom(self, n: int) -> Optional[int]:
        """Immediate dominator of n. None for the entry block."""
        v = self._idom.get(n)
        if v is None or v == n:
            return None
        return v

    def dominates(self, a: int, b: int) -> bool:
        """True if a dominates b (reflexive: a dominates itself)."""
        cur = b
        seen: Set[int] = set()
        while True:
            if cur == a:
                return True
            parent = self._idom.get(cur)
            if parent is None or parent == cur or cur in seen:
                return False
            seen.add(cur)
            cur = parent

    def back_edges(self) -> List[Tuple[int, int]]:
        """
        CFG edges (tail, header) where header dominates tail.
        These are the loop back edges (Muchnick §7.4).
        """
        result = []
        for (src, dst) in self.cfg.flow:
            if dst in self.cfg.blocks and self.dominates(dst, src):
                result.append((src, dst))
        return result

    def rpo(self) -> List[int]:
        """Block labels in reverse post-order — the standard worklist iteration order."""
        return list(self._rpo)

    def children(self, n: int) -> List[int]:
        """Blocks whose immediate dominator is n (dominator tree children)."""
        return [b for b, d in self._idom.items() if d == n and b != n]

    def dom_frontier(self) -> Dict[int, Set[int]]:
        """
        Dominance frontiers for all blocks — the set of blocks where a block's
        dominance ends. Required for SSA phi-function placement (Muchnick §8.11).
        """
        df: Dict[int, Set[int]] = {n: set() for n in self.cfg.blocks}
        for n in self.cfg.blocks:
            if len(self.cfg.blocks[n].preds) >= 2:
                for pred in self.cfg.blocks[n].preds:
                    runner = pred
                    while runner != self._idom.get(n) and runner is not None:
                        df[runner].add(n)
                        parent = self._idom.get(runner)
                        if parent is None or parent == runner:
                            break
                        runner = parent
        return df


# ─── Natural Loop Detection (Muchnick §7.4) ───────────────────────────────────

@dataclass
class Loop:
    header: int                   # single loop header (entry point)
    back_edge_tails: List[int]    # tails b of back edges b→header
    body: Set[int]                # all blocks in loop body (includes header)


class LoopInfo:
    """
    Natural loop detection from a DomTree's back edges.

    A natural loop for back edge (b→h):
      body = {n | n can reach b via backward CFG without crossing h} ∪ {h}

    Multiple back edges to the same header merge into one loop (Muchnick §7.4).

    Usage:
      loops = LoopInfo(cfg, dom)
      loops.loop_depth(block_label)     -> int (nesting depth)
      loops.loops_containing(label)     -> [Loop, ...]
      loops.is_loop_header(label)       -> bool
      loops.is_reducible()              -> bool
    """

    def __init__(self, cfg: CFG, dom: DomTree):
        self.cfg = cfg
        self.dom = dom
        self.loops: List[Loop] = []
        self._header_map: Dict[int, Loop] = {}
        self._block_loops: Dict[int, List[Loop]] = {}
        self._compute()

    def _compute(self) -> None:
        back = self.dom.back_edges()
        header_to_tails: Dict[int, List[int]] = {}
        for (b, h) in back:
            header_to_tails.setdefault(h, []).append(b)

        for header, tails in header_to_tails.items():
            body = self._natural_loop_body(header, tails)
            loop = Loop(header=header, back_edge_tails=list(tails), body=body)
            self.loops.append(loop)
            self._header_map[header] = loop
            for n in body:
                self._block_loops.setdefault(n, []).append(loop)

    def _natural_loop_body(self, header: int, tails: List[int]) -> Set[int]:
        body: Set[int] = {header}
        worklist: deque = deque()
        for b in tails:
            if b not in body:
                body.add(b)
                worklist.append(b)
        while worklist:
            n = worklist.popleft()
            for pred in self.cfg.blocks[n].preds:
                if pred in self.cfg.blocks and pred not in body:
                    body.add(pred)
                    worklist.append(pred)
        return body

    def is_loop_header(self, block: int) -> bool:
        return block in self._header_map

    def loops_containing(self, block: int) -> List[Loop]:
        return self._block_loops.get(block, [])

    def loop_depth(self, block: int) -> int:
        return len(self.loops_containing(block))

    def is_reducible(self) -> bool:
        """
        CFG is reducible iff every cycle has a unique dominating header.
        Equivalent: every retreating DFS edge is also a dominator back edge.
        Reducible CFGs arise from structured control flow — essentially all
        compiled (non-obfuscated) firmware (Muchnick §7.5).
        """
        back = set(self.dom.back_edges())
        visited: Set[int] = set()
        on_stack: Set[int] = set()
        stack: List[Tuple[int, List[int]]] = [(self.cfg.entry, list(self.cfg.blocks[self.cfg.entry].succs))]
        visited.add(self.cfg.entry)
        on_stack.add(self.cfg.entry)

        while stack:
            n, succs = stack[-1]
            if succs:
                s = succs.pop()
                if s not in self.cfg.blocks:
                    continue
                if s in on_stack:
                    if (n, s) not in back:
                        return False
                elif s not in visited:
                    visited.add(s)
                    on_stack.add(s)
                    stack.append((s, list(self.cfg.blocks[s].succs)))
            else:
                stack.pop()
                on_stack.discard(n)

        return True


# ─── SCCP — Sparse Conditional Constant Propagation (Muchnick §12.6) ──────────

def _arm_flags(rn: int, op2: int, subtract: bool = True) -> Dict[str, bool]:
    """Compute ARM N, Z, C, V flags for CMP rn, op2 (rn - op2) or TST (rn & op2)."""
    if subtract:
        result = rn - op2
        unsigned_result = (rn & 0xFFFFFFFF) - (op2 & 0xFFFFFFFF)
        signed_rn   = rn   if rn   < 0x80000000 else rn   - 0x100000000
        signed_op2  = op2  if op2  < 0x80000000 else op2  - 0x100000000
        signed_res  = signed_rn - signed_op2
        n = bool((result & 0x80000000))
        z = ((result & 0xFFFFFFFF) == 0)
        c = (unsigned_result >= 0)
        v = (signed_res < -0x80000000 or signed_res > 0x7FFFFFFF)
    else:
        result = rn & op2
        n = bool(result & 0x80000000)
        z = ((result & 0xFFFFFFFF) == 0)
        c = False
        v = False
    return {'n': n, 'z': z, 'c': c, 'v': v}


def _eval_arm_cond(cond: str, flags: Dict[str, bool]) -> Optional[bool]:
    """Return True/False if condition is determined; None if unknown condition code."""
    n, z, c, v = flags['n'], flags['z'], flags['c'], flags['v']
    return {
        'eq':  z,
        'ne':  not z,
        'cs':  c,   'hs': c,
        'cc':  not c, 'lo': not c,
        'mi':  n,
        'pl':  not n,
        'vs':  v,
        'vc':  not v,
        'hi':  (c and not z),
        'ls':  (not c or z),
        'ge':  (n == v),
        'lt':  (n != v),
        'gt':  (not z and n == v),
        'le':  (z or n != v),
    }.get(cond)


class SCCPAnalysis:
    """
    Sparse Conditional Constant Propagation — Wegman & Zadeck 1991, Muchnick §12.6.

    Unlike dense ConstPropAnalysis (which propagates through all edges regardless
    of executability), SCCP tracks per-edge executability:
      - Start with only the entry's outgoing edges executable.
      - When a conditional branch's condition register is a constant,
        only the taken edge is marked executable.
      - Blocks with no executable in-edges remain ⊥ (unreachable / None).

    This eliminates the switch-table contamination problem: blocks beyond an
    opaque branch with TOP condition are still reached (both edges open), but
    blocks beyond a branch with a KNOWN constant condition are precisely pruned.

    No SSA form required. Block-granularity (not instruction-granularity) SCCP.
    """

    def __init__(
        self,
        data: bytes,
        base_addr: int,
        arch: str = 'arm32',
        got_seed: Optional[Dict[int, int]] = None,
    ):
        self._arch = make_arch(arch)
        self._data = data
        self._base = base_addr
        self._got = got_seed or {}
        self._builder = CFGBuilder(self._arch, data, base_addr)

    def solve(
        self,
        func_addr: int,
        initial_regs: Optional[Dict[str, int]] = None,
    ) -> Tuple[Dict[int, Any], Set[Tuple[int, int]]]:
        """
        Returns:
          cp_vals:    block_label → register state dict (None = unreachable / ⊥)
          exec_edges: set of (src, dst) proven executable CFG edges
        """
        cfg = self._builder.build(func_addr)
        if not cfg.blocks:
            return {}, set()

        arch = self._arch
        all_regs = arch.all_regs()

        cp_vals: Dict[int, Any] = {lbl: None for lbl in cfg.blocks}
        exec_edges: Set[Tuple[int, int]] = set()

        # Seed entry block
        extremal: Dict[str, Any] = {r: _TOP for r in all_regs}
        if initial_regs:
            extremal.update(initial_regs)
        cp_vals[cfg.entry] = extremal

        # Worklists
        flow_wl: deque = deque()        # CFG edges to process
        block_wl: deque = deque()       # blocks to re-evaluate

        # Seed: process entry block immediately
        block_wl.append(cfg.entry)

        def _join_z(a, b):
            if a is _TOP or b is _TOP:
                return _TOP
            if a == b:
                return a
            return _TOP

        def _join(a, b):
            if a is None:
                return b
            if b is None:
                return a
            return {r: _join_z(a.get(r, _TOP), b.get(r, _TOP)) for r in all_regs}

        def _leq_z(a, b) -> bool:
            if b is _TOP:
                return True
            if a is _TOP:
                return False
            return a == b

        def _leq(a, b) -> bool:
            if a is None:
                return True
            if b is None:
                return False
            return all(_leq_z(a.get(r, _TOP), b.get(r, _TOP)) for r in all_regs)

        def _exit_state(lbl: int) -> Any:
            """Transfer function: block entry → block exit."""
            st = cp_vals.get(lbl)
            if st is None:
                return None
            return _cp_transfer_block(
                cfg.blocks[lbl], st, arch, self._data, self._base, self._got
            )

        def _resolve_condition(block: BasicBlock, exit_st) -> Optional[bool]:
            """
            Return True if conditional branch is taken, False if not taken,
            None if undecidable (register is TOP or condition code unrecognised).
            """
            if exit_st is None or not block.insns:
                return None
            last = block.insns[-1]
            if not arch.is_conditional_branch(last):
                return None

            # Find most recent CMP/TST before branch (scan backward)
            cmp_insn = None
            for i in range(len(block.insns) - 2, -1, -1):
                mn = block.insns[i].mnemonic.lower()
                if mn.startswith(('cmp', 'tst', 'cmn', 'teq')):
                    cmp_insn = block.insns[i]
                    break
                # flag-clobbering instructions invalidate the search
                if not mn.startswith(('b', 'ldr', 'str', 'push', 'pop', 'nop')):
                    if arch.dest_reg(block.insns[i]) is not None:
                        pass  # dest reg writes don't touch flags; keep scanning
            if cmp_insn is None:
                return None

            try:
                ops = cmp_insn.operands
            except Exception:
                return None
            if len(ops) < 2:
                return None

            def _reg_val(op) -> Optional[int]:
                if hasattr(op, 'reg') and op.type in (
                    C_ARM.ARM_OP_REG, C_ARM64.ARM64_OP_REG
                ):
                    name = cmp_insn.reg_name(op.reg).lower()
                    v = exit_st.get(name, _TOP)
                    return None if (v is _TOP or v is None) else v
                if hasattr(op, 'imm') and op.type in (
                    C_ARM.ARM_OP_IMM, C_ARM64.ARM64_OP_IMM
                ):
                    return op.imm
                return None

            rn_val = _reg_val(ops[0])
            op2_val = _reg_val(ops[1])
            if rn_val is None or op2_val is None:
                return None

            cmp_mn = cmp_insn.mnemonic.lower()
            subtract = not cmp_mn.startswith('tst')
            flags = _arm_flags(rn_val & 0xFFFFFFFF, op2_val & 0xFFFFFFFF, subtract)

            # Extract condition code from branch mnemonic
            branch_mn = last.mnemonic.lower()
            if isinstance(arch, THUMB2Config):
                bare = arch._bare(branch_mn)
                cond = branch_mn.replace('.w', '')
                if bare == 'b':
                    cond = cond[len(bare):]
                else:
                    cond = ''
            elif isinstance(arch, ARM32Config):
                bare = 'b'
                cond = branch_mn[1:] if branch_mn.startswith('b') else ''
            else:
                cond = branch_mn[1:] if branch_mn.startswith('b') else ''

            return _eval_arm_cond(cond, flags)

        while flow_wl or block_wl:
            # Drain flow worklist first
            while flow_wl:
                edge = flow_wl.popleft()
                src, dst = edge
                if edge in exec_edges:
                    continue
                exec_edges.add(edge)

                # Recompute dst entry state from all executable predecessor exits
                new_entry = None
                for p in cfg.blocks[dst].preds:
                    if (p, dst) in exec_edges:
                        new_entry = _join(new_entry, _exit_state(p))

                if not _leq(new_entry, cp_vals.get(dst)):
                    cp_vals[dst] = new_entry
                    block_wl.append(dst)

            # Process one block
            if block_wl:
                n = block_wl.popleft()
                if n not in cfg.blocks:
                    continue
                block = cfg.blocks[n]
                state = cp_vals.get(n)
                if state is None:
                    continue

                exit_st = _cp_transfer_block(
                    block, state, arch, self._data, self._base, self._got
                )

                if not block.insns:
                    for s in block.succs:
                        flow_wl.append((n, s))
                    continue

                last = block.insns[-1]

                if arch.is_return(last):
                    pass  # no successors

                elif arch.is_call(last):
                    fall = last.address + last.size
                    if fall in cfg.blocks:
                        flow_wl.append((n, fall))

                elif arch.is_unconditional_branch(last):
                    tgt = arch.branch_target(last)
                    if tgt and tgt in cfg.blocks:
                        flow_wl.append((n, tgt))

                elif arch.is_conditional_branch(last):
                    taken = _resolve_condition(block, exit_st)
                    tgt = arch.branch_target(last)
                    fall = last.address + last.size

                    if taken is True and tgt and tgt in cfg.blocks:
                        flow_wl.append((n, tgt))
                    elif taken is False and fall in cfg.blocks:
                        flow_wl.append((n, fall))
                    else:
                        # Unknown condition: both edges executable
                        for s in block.succs:
                            flow_wl.append((n, s))
                else:
                    for s in block.succs:
                        flow_wl.append((n, s))

        return cp_vals, exec_edges

    def const_at(self, cp_vals: Dict[int, Any], reg: str, block_label: int) -> Optional[int]:
        """Constant value of reg at block_label entry, or None (TOP or unreachable)."""
        state = cp_vals.get(block_label)
        if state is None:
            return None
        v = state.get(reg, _TOP)
        return None if (v is _TOP or v is None) else v

    def reachable_blocks(
        self, cp_vals: Dict[int, Any], exec_edges: Set[Tuple[int, int]]
    ) -> Set[int]:
        """Set of block labels with at least one executable incoming edge (or entry)."""
        cfg = self._builder.build(list(cp_vals.keys())[0]) if cp_vals else None
        reachable = set()
        for (src, dst) in exec_edges:
            reachable.add(src)
            reachable.add(dst)
        # entry is always reachable
        for lbl, st in cp_vals.items():
            if st is not None:
                reachable.add(lbl)
        return reachable
