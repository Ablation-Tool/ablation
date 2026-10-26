"""
ir.py — Unified IR node hierarchy + arch-specific lifters + pseudo-C emitter.

Why this exists:
  1. binary_lifter.py uses string-based NativeVal emission — every instruction
     appends a formatted string rather than building a node tree. This makes
     it impossible to run type recovery, constant folding, or struct-field
     annotation over the output before emitting C.
  2. taint_tracker_*.py and trace_arg() operate on raw instructions. Neither
     can represent cross-block flow because there is no IR to attach it to.
  3. A frozen dataclass IR is structurally hashable — useful for value
     numbering, CSE, and def-use edges keyed by expression identity.

The IR here is intentionally minimal: just enough to represent exec-class
sink arguments (the primary RE use case) through conditional branches and
function call boundaries. It is NOT a general-purpose compiler IR.

IR node hierarchy:

  IRNode (frozen base)
    ├─ IRConst          literal integer value
    ├─ IRReg            register reference (SSA name via ver)
    ├─ IRPhi            phi node (list of incoming values)
    ├─ IRLoad           memory dereference
    ├─ IRStore          memory write (statement)
    ├─ IRBinop          binary operation (+, -, &, |, ^, <<, >>, /)
    ├─ IRCmp            comparison (==, !=, <, <=, >, >=, u<, u>)
    ├─ IRCall           function call (value = return, statement = void)
    ├─ IRBranch         conditional or unconditional branch (statement)
    ├─ IRReturn         function return (statement)
    └─ IRAssign         assignment dest = rhs (statement)

Blocks and function graph:

  IRBlock   basic block of IR statements
  IRIG      IR function graph (dict of IRBlock)

Lifters (arch-specific):

  IRLifter(ABC)       build(cfg) -> IRIG
    AlphaIRLifter     RawInsn / alpha_cfg.BasicBlock → IRBlock
    X86_64IRLifter    CsInsn / dataflow_engine.BasicBlock → IRBlock

Emitter:

  PseudoCEmitter(irig)   emit() -> str

Usage:

    from ablation.analyzers.alpha_cfg import AlphaCFGBuilder
    from ablation.analyzers.arch_configs_raw import AlphaAXPConfig
    from ablation.analyzers.ir import AlphaIRLifter, PseudoCEmitter

    builder = AlphaCFGBuilder(data, sections, gp)
    cfg = builder.build(func_va)
    lifter = AlphaIRLifter(data=data, sections=sections, gp_value=gp)
    irig = lifter.lift_cfg(cfg)
    print(PseudoCEmitter(irig).emit())
"""

from __future__ import annotations

import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ─── IR node types ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IRNode:
    """Frozen base for all IR nodes. Structural equality and hashing are free."""


@dataclass(frozen=True)
class IRConst(IRNode):
    value: int
    width: int = 64   # bits


@dataclass(frozen=True)
class IRReg(IRNode):
    name:  str
    ver:   int = 0   # SSA version (0 = pre-SSA / unknown)


@dataclass(frozen=True)
class IRPhi(IRNode):
    reg:  str
    args: Tuple[IRNode, ...]   # incoming values in predecessor order


@dataclass(frozen=True)
class IRLoad(IRNode):
    addr:  IRNode
    width: int = 64


@dataclass(frozen=True)
class IRStore(IRNode):
    addr:  IRNode
    val:   IRNode
    width: int = 64


@dataclass(frozen=True)
class IRBinop(IRNode):
    op:  str        # '+' '-' '*' '/' '&' '|' '^' '<<' '>>' 'u>>'
    lhs: IRNode
    rhs: IRNode


@dataclass(frozen=True)
class IRCmp(IRNode):
    op:  str        # '==' '!=' '<' '<=' '>' '>=' 'u<' 'u<=' 'u>' 'u>='
    lhs: IRNode
    rhs: IRNode


@dataclass(frozen=True)
class IRCall(IRNode):
    target:  IRNode
    args:    Tuple[IRNode, ...]
    ret_reg: str = 'r0'   # arch return register


@dataclass(frozen=True)
class IRBranch(IRNode):
    cond:        Optional[IRNode]  # None → unconditional
    taken:       int               # VA of taken target
    fallthrough: Optional[int]     # None for unconditional


@dataclass(frozen=True)
class IRReturn(IRNode):
    val: Optional[IRNode]


@dataclass(frozen=True)
class IRAssign(IRNode):
    dest: IRReg
    rhs:  IRNode


# ─── IR block and function graph ──────────────────────────────────────────────

@dataclass
class IRBlock:
    start_va: int
    stmts:    List[IRNode] = field(default_factory=list)
    succs:    List[int]    = field(default_factory=list)
    preds:    List[int]    = field(default_factory=list)
    is_ret:   bool         = False


@dataclass
class IRIG:
    """IR function graph."""
    blocks: Dict[int, IRBlock]
    entry:  int
    arch:   str


# ─── Lifter ABC ───────────────────────────────────────────────────────────────

class IRLifter(ABC):
    """Lift a raw CFG to an IRIG."""

    @abstractmethod
    def lift_block(self, block_va: int, block) -> IRBlock:
        ...

    def lift_cfg(self, cfg) -> IRIG:
        """
        Lift every BasicBlock in cfg to an IRBlock, preserving successor /
        predecessor edges and the entry point.
        """
        irig_blocks: Dict[int, IRBlock] = {}
        for va, block in cfg.blocks.items():
            irig_blocks[va] = self.lift_block(va, block)
        # Wire edges from the original CFG
        for va, block in cfg.blocks.items():
            irig_blocks[va].succs = list(block.succs)
            irig_blocks[va].preds = list(block.preds)
            irig_blocks[va].is_ret = getattr(block, 'is_ret', False)
        return IRIG(blocks=irig_blocks, entry=cfg.entry, arch=self._arch_name())

    @abstractmethod
    def _arch_name(self) -> str:
        ...


# ─── Alpha AXP lifter ─────────────────────────────────────────────────────────

# Alpha opcode constants
_A_OP_LDA    = 0x08
_A_OP_LDAH   = 0x09
_A_OP_LDQ    = 0x29
_A_OP_LDL    = 0x28
_A_OP_LDQ_U  = 0x0B
_A_OP_STQ    = 0x2D
_A_OP_STL    = 0x2C
_A_OP_BSR    = 0x34
_A_OP_BR     = 0x30
_A_OP_JSR    = 0x1A   # hint distinguishes JMP/JSR/RET

# integer ops: function field selects the operation
_A_INTOPS = {
    0x10: {  # INTA
        0x00: '+',    # ADDL
        0x20: '+',    # ADDQ
        0x09: '-',    # SUBL
        0x29: '-',    # SUBQ
        0x02: '*',    # MUL (S4ADDL)
        0x12: '*',    # S8ADDL
    },
    0x11: {  # INTL (logical)
        0x00: '&',    # AND
        0x20: '|',    # BIS (OR / MOV)
        0x26: '|',    # CMOVNE
        0x40: 'xor',  # XOR
        0x08: 'andnot',
        0x28: 'ornot',
    },
    0x12: {  # INTS (shift)
        0x39: '<<',   # SLL
        0x3C: '>>',   # SRA (arith)
        0x34: 'u>>',  # SRL
    },
}


def _sign_ext16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def _alpha_reg(n: int) -> str:
    return f'r{n}'


def _alpha_ra(word: int) -> int:
    return (word >> 21) & 0x1F


def _alpha_rb(word: int) -> int:
    return (word >> 16) & 0x1F


def _alpha_rc(word: int) -> int:
    return word & 0x1F


def _alpha_disp16(word: int) -> int:
    return _sign_ext16(word & 0xFFFF)


def _alpha_lit8(word: int) -> int:
    return (word >> 13) & 0xFF


def _alpha_use_lit(word: int) -> bool:
    return bool((word >> 12) & 1)


class AlphaIRLifter(IRLifter):
    """
    Lifts Alpha AXP basic blocks (from AlphaCFGBuilder) to IR blocks.

    Covers the subset of Alpha instructions relevant to taint tracing:
    integer arithmetic, loads, stores, BSR/JSR calls, branches, and RET.
    Unrecognised instructions are emitted as IRAssign(dest, IRConst(0)) so
    the register map stays consistent without aborting the lift.
    """

    def __init__(self,
                 data:      bytes,
                 sections:  Dict,
                 gp_value:  Optional[int] = None):
        self._data     = data
        self._sections = sections
        self._gp       = gp_value or 0

    def _arch_name(self) -> str:
        return 'alpha_axp'

    def lift_block(self, block_va: int, block) -> IRBlock:
        ib = IRBlock(start_va=block_va)
        for va, word in block.insns:
            stmts = self._lift_insn(va, word)
            ib.stmts.extend(stmts)
        return ib

    def _lift_insn(self, va: int, word: int) -> List[IRNode]:
        op = (word >> 26) & 0x3F
        ra = _alpha_ra(word)
        rb = _alpha_rb(word)
        rc = _alpha_rc(word)
        disp16 = _alpha_disp16(word)
        use_lit = _alpha_use_lit(word)
        lit = _alpha_lit8(word)

        dest_name = _alpha_reg(ra)
        rb_node: IRNode = IRConst(lit) if use_lit else IRReg(_alpha_reg(rb))

        # LDA  ra, disp(rb) — literal or GP-relative address
        if op == _A_OP_LDA:
            if rb == 31:   # lda ra, disp($zero) → constant
                rhs: IRNode = IRConst(disp16)
            else:
                rhs = IRBinop('+', IRReg(_alpha_reg(rb)), IRConst(disp16))
            return [IRAssign(IRReg(dest_name), rhs)]

        # LDAH  ra, disp(rb)  — shifted constant
        if op == _A_OP_LDAH:
            if rb == 31:
                rhs = IRConst(disp16 << 16)
            else:
                rhs = IRBinop('+', IRReg(_alpha_reg(rb)), IRConst(disp16 << 16))
            return [IRAssign(IRReg(dest_name), rhs)]

        # LDQ  ra, disp(rb) — 64-bit load
        if op == _A_OP_LDQ:
            addr: IRNode = IRBinop('+', IRReg(_alpha_reg(rb)), IRConst(disp16))
            return [IRAssign(IRReg(dest_name), IRLoad(addr, width=64))]

        # LDL  ra, disp(rb) — 32-bit sign-extending load
        if op == _A_OP_LDL:
            addr = IRBinop('+', IRReg(_alpha_reg(rb)), IRConst(disp16))
            return [IRAssign(IRReg(dest_name), IRLoad(addr, width=32))]

        # STQ  ra, disp(rb) — 64-bit store
        if op == _A_OP_STQ:
            addr = IRBinop('+', IRReg(_alpha_reg(rb)), IRConst(disp16))
            return [IRStore(addr, IRReg(_alpha_reg(ra)), width=64)]

        # STL  ra, disp(rb) — 32-bit store
        if op == _A_OP_STL:
            addr = IRBinop('+', IRReg(_alpha_reg(rb)), IRConst(disp16))
            return [IRStore(addr, IRReg(_alpha_reg(ra)), width=32)]

        # BSR  ra, target — branch-and-link (call)
        if op == _A_OP_BSR:
            hint = word & 0x3FFF
            call_target_va = (va + 4) + hint * 4
            return [IRAssign(
                IRReg(_alpha_reg(ra)),
                IRCall(IRConst(call_target_va), args=(), ret_reg='r0'),
            )]

        # JMP/JSR/RET  (op 0x1A)
        if op == _A_OP_JSR:
            hint = (word >> 14) & 0x3
            if hint == 2:    # RET
                return [IRReturn(IRReg('r0'))]
            # JSR (hint=1) or JMP (hint=0): indirect call/jump
            target_reg = _alpha_reg(rb)
            return [IRAssign(
                IRReg(_alpha_reg(ra)),
                IRCall(IRReg(target_reg), args=(), ret_reg='r0'),
            )]

        # BR  ra, target — unconditional branch (ra = link, usually r31)
        if op == _A_OP_BR:
            disp21 = word & 0x1FFFFF
            if disp21 & 0x100000:
                disp21 -= 0x200000
            taken = (va + 4) + disp21 * 4
            return [IRBranch(cond=None, taken=taken, fallthrough=None)]

        # Conditional branches (0x38–0x3F, 0x31–0x37)
        _COND_OPS = {
            0x39: 'BEQ', 0x3D: 'BNE', 0x3B: 'BLT', 0x3F: 'BLE',
            0x3C: 'BGT', 0x38: 'BGE', 0x31: 'FBEQ', 0x35: 'FBNE',
            0x32: 'FBLT', 0x36: 'FBLE', 0x33: 'FBGT', 0x37: 'FBGE',
        }
        if op in _COND_OPS:
            disp21 = word & 0x1FFFFF
            if disp21 & 0x100000:
                disp21 -= 0x200000
            taken = (va + 4) + disp21 * 4
            fall  = va + 4
            cmp_op = '==' if _COND_OPS[op] in ('BEQ', 'FBEQ') else '!='
            cond = IRCmp(cmp_op, IRReg(_alpha_reg(ra)), IRConst(0))
            return [IRBranch(cond=cond, taken=taken, fallthrough=fall)]

        # Integer arithmetic (op groups 0x10–0x12)
        if op in _A_INTOPS:
            fn = (word >> 5) & 0x7F
            arith_op = _A_INTOPS[op].get(fn)
            if arith_op == 'xor':
                rhs = IRBinop('^', IRReg(_alpha_reg(rb)), rb_node)
            elif arith_op:
                rhs = IRBinop(arith_op, IRReg(_alpha_reg(rb)), rb_node)
            else:
                rhs = IRConst(0)   # unrecognised function code
            return [IRAssign(IRReg(_alpha_reg(rc)), rhs)]

        # Unrecognised: preserve dest register with a zero constant
        return [IRAssign(IRReg(_alpha_reg(ra)), IRConst(0))]


# ─── x86-64 lifter ────────────────────────────────────────────────────────────

# Capstone x86 operand types
_X86_OP_REG = 1
_X86_OP_IMM = 2
_X86_OP_MEM = 3

# Register canonicalisation: sub-registers → 64-bit name
_X86_CANON: Dict[str, str] = {
    'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
    'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
    'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
    'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
    'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
    'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
    'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
    'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
    'r8d': 'r8',  'r8w': 'r8',  'r8b': 'r8',
    'r9d': 'r9',  'r9w': 'r9',  'r9b': 'r9',
    'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
    'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
    'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
    'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
    'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
    'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15',
}


def _x86_reg(name: str) -> str:
    return _X86_CANON.get(name, name)


def _x86_operand(op) -> IRNode:
    """Convert a Capstone x86 operand to an IRNode."""
    if op.type == _X86_OP_IMM:
        return IRConst(op.imm)
    if op.type == _X86_OP_REG:
        return IRReg(_x86_reg(op.reg_name if hasattr(op, 'reg_name') else str(op.reg)))
    if op.type == _X86_OP_MEM:
        m = op.mem
        base  = IRReg(_x86_reg(str(m.base)))  if m.base  else None
        index = IRReg(_x86_reg(str(m.index))) if m.index else None
        disp  = IRConst(m.disp)
        # Build address expression
        if base and index and m.scale != 1:
            scaled = IRBinop('*', index, IRConst(m.scale))
            addr: IRNode = IRBinop('+', base, IRBinop('+', scaled, disp))
        elif base and index:
            addr = IRBinop('+', base, IRBinop('+', index, disp))
        elif base:
            addr = IRBinop('+', base, disp) if m.disp else base
        else:
            addr = disp
        return IRLoad(addr, width=op.size * 8 if hasattr(op, 'size') else 64)
    return IRConst(0)


class X86_64IRLifter(IRLifter):
    """
    Lifts x86-64 basic blocks (from CFGBuilder with X86_64Config) to IR blocks.
    Covers the instruction forms most commonly found in exec-class taint paths:
    MOV, LEA, arithmetic, calls, conditional jumps, RET.
    """

    def _arch_name(self) -> str:
        return 'x86_64'

    def lift_block(self, block_va: int, block) -> IRBlock:
        ib = IRBlock(start_va=block_va)
        for insn in block.insns:
            ib.stmts.extend(self._lift_insn(insn))
        return ib

    def _lift_insn(self, insn) -> List[IRNode]:
        mn = insn.mnemonic.lower()
        ops = insn.operands if hasattr(insn, 'operands') else []

        if mn == 'ret' or mn == 'retq':
            return [IRReturn(IRReg('rax'))]

        if mn in ('call', 'callq'):
            if ops:
                target = _x86_operand(ops[0])
            else:
                target = IRConst(0)
            return [IRAssign(IRReg('rax'), IRCall(target, args=(), ret_reg='rax'))]

        if mn in ('mov', 'movq', 'movl', 'movzx', 'movsx', 'movabs'):
            if len(ops) >= 2:
                src = _x86_operand(ops[1])
                dst_op = ops[0]
                if dst_op.type == _X86_OP_REG:
                    return [IRAssign(
                        IRReg(_x86_reg(str(dst_op.reg))), src
                    )]
                if dst_op.type == _X86_OP_MEM:
                    store_addr = _x86_operand(dst_op)
                    assert isinstance(store_addr, IRLoad)
                    return [IRStore(store_addr.addr, src)]
            return []

        if mn == 'lea' and len(ops) >= 2:
            m = ops[1].mem
            base  = IRReg(_x86_reg(str(m.base)))  if m.base  else None
            index = IRReg(_x86_reg(str(m.index))) if m.index else None
            disp  = IRConst(m.disp)
            if base and m.disp:
                addr: IRNode = IRBinop('+', base, disp)
            elif base:
                addr = base
            else:
                addr = disp
            if ops[0].type == _X86_OP_REG:
                return [IRAssign(IRReg(_x86_reg(str(ops[0].reg))), addr)]

        _ARITH = {
            'add': '+', 'addq': '+', 'sub': '-', 'subq': '-',
            'imul': '*', 'and': '&', 'or': '|', 'xor': '^',
            'shl': '<<', 'sar': '>>', 'shr': 'u>>',
        }
        if mn in _ARITH and len(ops) >= 2:
            dst_op = ops[0]
            rhs_node = _x86_operand(ops[1])
            if dst_op.type == _X86_OP_REG:
                dst_reg = _x86_reg(str(dst_op.reg))
                lhs_node: IRNode = IRReg(dst_reg)
                rhs_combined = IRBinop(_ARITH[mn], lhs_node, rhs_node)
                return [IRAssign(IRReg(dst_reg), rhs_combined)]

        # push/pop: treat as stack ops — skip for taint purposes
        if mn in ('push', 'pushq', 'pop', 'popq'):
            return []

        # Conditional jumps: emit IRBranch with a placeholder condition
        if mn.startswith('j') and len(ops) == 1 and ops[0].type == _X86_OP_IMM:
            taken = ops[0].imm
            fall  = insn.address + insn.size
            cond  = IRCmp('!=', IRConst(0), IRConst(0))   # placeholder
            return [IRBranch(cond=cond, taken=taken, fallthrough=fall)]

        if mn == 'jmp' and ops and ops[0].type == _X86_OP_IMM:
            return [IRBranch(cond=None, taken=ops[0].imm, fallthrough=None)]

        return []


# ─── Pseudo-C emitter ─────────────────────────────────────────────────────────

class PseudoCEmitter:
    """
    Emit a human-readable pseudo-C representation of an IRIG.

    Not a real decompiler: names are register names with SSA versions,
    types are all 64-bit integers unless decorated by struct analysis,
    and all memory accesses are pointer dereferences.

    For exec-class RE the output is good enough to see whether a `system()`
    argument is a constant, a GP-relative string, or a function argument.
    """

    def __init__(self, irig: IRIG, names: Optional[Dict[int, str]] = None):
        self._irig  = irig
        self._names = names or {}   # VA → function name (from BinaryContext)

    def _func_name(self, va: int) -> str:
        return self._names.get(va, f'sub_{va:x}')

    def _node(self, n: IRNode, indent: int = 0) -> str:
        if isinstance(n, IRConst):
            if -1024 <= n.value <= 1024:
                return str(n.value)
            return hex(n.value)
        if isinstance(n, IRReg):
            if n.ver:
                return f'{n.name}_{n.ver}'
            return n.name
        if isinstance(n, IRPhi):
            args_s = ', '.join(self._node(a) for a in n.args)
            return f'phi({args_s})'
        if isinstance(n, IRLoad):
            addr_s = self._node(n.addr)
            w = n.width // 8
            return f'*(u{n.width}*){addr_s}' if w != 8 else f'*{addr_s}'
        if isinstance(n, IRBinop):
            return f'({self._node(n.lhs)} {n.op} {self._node(n.rhs)})'
        if isinstance(n, IRCmp):
            return f'({self._node(n.lhs)} {n.op} {self._node(n.rhs)})'
        if isinstance(n, IRCall):
            tgt = self._func_name(n.target.value) if isinstance(n.target, IRConst) \
                  else self._node(n.target)
            args_s = ', '.join(self._node(a) for a in n.args)
            return f'{tgt}({args_s})'
        return repr(n)

    def _stmt(self, s: IRNode, pad: str) -> str:
        if isinstance(s, IRAssign):
            return f'{pad}{self._node(s.dest)} = {self._node(s.rhs)};'
        if isinstance(s, IRStore):
            return f'{pad}*({self._node(s.addr)}) = {self._node(s.val)};'
        if isinstance(s, IRReturn):
            v = self._node(s.val) if s.val else 'void'
            return f'{pad}return {v};'
        if isinstance(s, IRBranch):
            if s.cond is None:
                return f'{pad}goto 0x{s.taken:x};'
            return (f'{pad}if ({self._node(s.cond)}) '
                    f'goto 0x{s.taken:x}; '
                    f'else goto 0x{s.fallthrough:x};')
        return f'{pad}// {repr(s)}'

    def emit(self) -> str:
        lines: List[str] = [f'// IRIG arch={self._irig.arch}']
        cfg = self._irig
        # Emit in topological order (approximate: sorted VA, entry first)
        order = [cfg.entry] + sorted(
            va for va in cfg.blocks if va != cfg.entry
        )
        for va in order:
            block = cfg.blocks.get(va)
            if block is None:
                continue
            lines.append(f'BB_0x{va:x}:')
            for stmt in block.stmts:
                lines.append(self._stmt(stmt, '  '))
            if not block.stmts:
                lines.append('  // (empty)')
        return '\n'.join(lines)
