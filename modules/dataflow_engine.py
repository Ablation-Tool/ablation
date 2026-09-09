"""
dataflow_engine.py — MFP worklist engine + analysis instances for binary RE.

Implements Nielson/Nielson/Hankin §2.4.1 Table 2.8: generic Monotone Framework
worklist algorithm over (L, flow, E, ι, f_.) instances. Terminates via ACC.

Lattice instances
-----------------
ConstPropAnalysis    — ARM32/ARM64 register constant propagation
                       Resolves pool loads, immediate chains, and GOT-seeded values.
ReachingDefsAnalysis — ARM32/ARM64 register reaching definitions
                       Produces ud-chains for any (reg, call-site) pair.

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
