"""
path_solver.py -- Bounded symbolic execution + Z3 path constraint solver for x86-64.

Implements the "First-Order Logic / Constraint Solving" phase from the
Semantic Binary Analysis & Bounded Execution Architecture:

  For each path entry -> ... -> target_block:
    phi = AND(state_constraints) AND AND(path_constraints)
  Z3 solves phi to produce concrete register values at function entry.

Pipeline position:
  cfg_builder  ->  taint_tracker (finds sink VA)  ->  path_solver (finds input)

Workflow:
  1. Enumerate all simple paths from entry block to target block in the CFG
     (bounded by MAX_PATH_BLOCKS -- the "loop boundary" from doc section 2)
  2. Symbolically execute each path:
     - Registers = Z3 BitVec(64) symbolic variables at entry
     - Instructions update register expressions (state constraints)
     - Branch instructions add direction constraints (path constraints)
  3. Solve each path's phi with Z3
  4. Return SAT model as concrete register assignments (the PoC inputs)

Limitations:
  - Memory reads: modeled as unconstrained symbolic values (sound over-approximation)
  - Calls: caller-saved regs cleared to fresh unconstrained symbols after each call
  - Indirect jumps/calls: path enumeration stops at indirect branch
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Set

import capstone
from capstone.x86_const import (
    X86_INS_MOV, X86_INS_MOVZX, X86_INS_MOVSX, X86_INS_MOVAPS, X86_INS_MOVD,
    X86_INS_LEA, X86_INS_ADD, X86_INS_SUB, X86_INS_XOR, X86_INS_AND,
    X86_INS_OR, X86_INS_NOT, X86_INS_NEG, X86_INS_IMUL, X86_INS_MUL,
    X86_INS_SHL, X86_INS_SAL, X86_INS_SHR, X86_INS_SAR,
    X86_INS_TEST, X86_INS_CMP,
    X86_INS_CALL, X86_INS_RET,
    X86_INS_JMP,
    X86_INS_JE,  X86_INS_JNE,
    X86_INS_JL,  X86_INS_JLE,
    X86_INS_JG,  X86_INS_JGE,
    X86_INS_JB,  X86_INS_JBE,
    X86_INS_JA,  X86_INS_JAE,
    X86_INS_JS,  X86_INS_JNS,
    X86_INS_JO,  X86_INS_JNO,
    X86_OP_IMM, X86_OP_REG, X86_OP_MEM,
    X86_REG_INVALID,
    X86_REG_RAX, X86_REG_EAX, X86_REG_AX,  X86_REG_AL,  X86_REG_AH,
    X86_REG_RBX, X86_REG_EBX, X86_REG_BX,  X86_REG_BL,  X86_REG_BH,
    X86_REG_RCX, X86_REG_ECX, X86_REG_CX,  X86_REG_CL,  X86_REG_CH,
    X86_REG_RDX, X86_REG_EDX, X86_REG_DX,  X86_REG_DL,  X86_REG_DH,
    X86_REG_RSI, X86_REG_ESI, X86_REG_SI,  X86_REG_SIL,
    X86_REG_RDI, X86_REG_EDI, X86_REG_DI,  X86_REG_DIL,
    X86_REG_RSP, X86_REG_ESP,
    X86_REG_RBP, X86_REG_EBP,
    X86_REG_R8,  X86_REG_R8D,  X86_REG_R8W,  X86_REG_R8B,
    X86_REG_R9,  X86_REG_R9D,  X86_REG_R9W,  X86_REG_R9B,
    X86_REG_R10, X86_REG_R10D, X86_REG_R10W, X86_REG_R10B,
    X86_REG_R11, X86_REG_R11D, X86_REG_R11W, X86_REG_R11B,
    X86_REG_R12, X86_REG_R12D,
    X86_REG_R13, X86_REG_R13D,
    X86_REG_R14, X86_REG_R14D,
    X86_REG_R15, X86_REG_R15D,
    X86_REG_RIP,
)

import z3

# ── register model ────────────────────────────────────────────────────────────

# (canonical_64_name, lsb, width_in_bits)
_REG_MAP: Dict[int, Tuple[str, int, int]] = {
    X86_REG_RAX: ("rax", 0, 64), X86_REG_EAX: ("rax", 0, 32),
    X86_REG_AX:  ("rax", 0, 16), X86_REG_AL:  ("rax", 0,  8),
    X86_REG_AH:  ("rax", 8,  8),
    X86_REG_RBX: ("rbx", 0, 64), X86_REG_EBX: ("rbx", 0, 32),
    X86_REG_BX:  ("rbx", 0, 16), X86_REG_BL:  ("rbx", 0,  8),
    X86_REG_BH:  ("rbx", 8,  8),
    X86_REG_RCX: ("rcx", 0, 64), X86_REG_ECX: ("rcx", 0, 32),
    X86_REG_CX:  ("rcx", 0, 16), X86_REG_CL:  ("rcx", 0,  8),
    X86_REG_CH:  ("rcx", 8,  8),
    X86_REG_RDX: ("rdx", 0, 64), X86_REG_EDX: ("rdx", 0, 32),
    X86_REG_DX:  ("rdx", 0, 16), X86_REG_DL:  ("rdx", 0,  8),
    X86_REG_DH:  ("rdx", 8,  8),
    X86_REG_RSI: ("rsi", 0, 64), X86_REG_ESI: ("rsi", 0, 32),
    X86_REG_SI:  ("rsi", 0, 16), X86_REG_SIL: ("rsi", 0,  8),
    X86_REG_RDI: ("rdi", 0, 64), X86_REG_EDI: ("rdi", 0, 32),
    X86_REG_DI:  ("rdi", 0, 16), X86_REG_DIL: ("rdi", 0,  8),
    X86_REG_RSP: ("rsp", 0, 64), X86_REG_ESP: ("rsp", 0, 32),
    X86_REG_RBP: ("rbp", 0, 64), X86_REG_EBP: ("rbp", 0, 32),
    X86_REG_R8:  ("r8",  0, 64), X86_REG_R8D: ("r8",  0, 32),
    X86_REG_R8W: ("r8",  0, 16), X86_REG_R8B: ("r8",  0,  8),
    X86_REG_R9:  ("r9",  0, 64), X86_REG_R9D: ("r9",  0, 32),
    X86_REG_R9W: ("r9",  0, 16), X86_REG_R9B: ("r9",  0,  8),
    X86_REG_R10: ("r10", 0, 64), X86_REG_R10D:("r10", 0, 32),
    X86_REG_R10W:("r10", 0, 16), X86_REG_R10B:("r10", 0,  8),
    X86_REG_R11: ("r11", 0, 64), X86_REG_R11D:("r11", 0, 32),
    X86_REG_R11W:("r11", 0, 16), X86_REG_R11B:("r11", 0,  8),
    X86_REG_R12: ("r12", 0, 64), X86_REG_R12D:("r12", 0, 32),
    X86_REG_R13: ("r13", 0, 64), X86_REG_R13D:("r13", 0, 32),
    X86_REG_R14: ("r14", 0, 64), X86_REG_R14D:("r14", 0, 32),
    X86_REG_R15: ("r15", 0, 64), X86_REG_R15D:("r15", 0, 32),
    X86_REG_RIP: ("rip", 0, 64),
}

_ALL_REGS = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
]

# Caller-saved per System V AMD64 ABI
_CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}

_BRANCH_IDS = frozenset({
    X86_INS_JE,  X86_INS_JNE,
    X86_INS_JL,  X86_INS_JLE,
    X86_INS_JG,  X86_INS_JGE,
    X86_INS_JB,  X86_INS_JBE,
    X86_INS_JA,  X86_INS_JAE,
    X86_INS_JS,  X86_INS_JNS,
    X86_INS_JO,  X86_INS_JNO,
})


# ── struct-aware memory seeding ───────────────────────────────────────────────

@dataclass
class MemoryConstraint:
    """Describes a struct field to seed into the Z3 memory model.

    Maps a (base_register, byte_offset) memory read to a named Z3 symbol
    with optional bounds. When the same field is read multiple times on a
    path, the same symbol is reused -- Z3 sees consistent constraints across
    all branches that test the field.

    Example (RADIUS attribute struct):
        MemoryConstraint("attr_type", width=8, lo=0, hi=255)
        MemoryConstraint("attr_len",  width=8, lo=4, hi=255)
        MemoryConstraint("vendor_id", width=32, exact=311)  # Microsoft
    """
    name: str              # Z3 symbol name (must be unique within one StructSeed)
    width: int             # field width in bits: 8, 16, 32, or 64
    lo: Optional[int] = None    # lower bound, inclusive (unsigned); None = no bound
    hi: Optional[int] = None    # upper bound, inclusive (unsigned); None = no bound
    exact: Optional[int] = None # pin to one exact value (overrides lo/hi)


# Key: (base_register_name, byte_offset_decimal)
# Example: {("rbx", 0x2b): MemoryConstraint("attr_type", 8, 0, 255)}
StructSeed = Dict[Tuple[str, int], MemoryConstraint]


# ── result types ──────────────────────────────────────────────────────────────

@dataclass
class PathResult:
    sat: bool
    path: List[int]                  # block VAs
    model: Dict[str, int]            # concrete register values at entry (if sat)
    clauses: int                     # Z3 clauses added
    note: str = ""                   # "timeout", "unsat", etc.
    seeded_fields: List[str] = field(default_factory=list)  # struct fields that constrained the path

    def __str__(self) -> str:
        path_str = " -> ".join(hex(v) for v in self.path)
        if not self.sat:
            return f"[{self.note or 'UNSAT'}] path={path_str} clauses={self.clauses}"
        regs = ", ".join(f"{k}={hex(v)}" for k, v in self.model.items() if v != 0)
        fields = f" seeded={self.seeded_fields}" if self.seeded_fields else ""
        return f"[SAT] path={path_str} clauses={self.clauses} model=({regs}){fields}"


# ── core engine ───────────────────────────────────────────────────────────────

class PathSolver:
    """
    Bounded symbolic executor + Z3 path constraint solver for x86-64.

    Implements document phases 2-3:
      Phase 2: bounds loop depth (max_path_blocks), isolates target block
      Phase 3: symbolic execution + Z3 FOL constraint solving

    Usage:
        ps = PathSolver(data, func_va, func_end_va, plt, cfg, md)
        results = ps.solve(target_va=0x5747a)
        for r in results:
            print(r)
    """

    def __init__(
        self,
        data: bytes,
        func_va: int,
        func_end_va: int,
        plt: Dict[int, str],
        cfg: Any,
        md: capstone.Cs,
        max_path_blocks: int = 40,
        max_paths: int = 50,
        z3_timeout_ms: int = 5000,
        struct_seed: Optional[StructSeed] = None,
    ):
        self.data = data
        self.func_va = func_va
        self.func_end_va = func_end_va
        self.plt = plt
        self.cfg = cfg
        self.md = md
        self.max_path_blocks = max_path_blocks
        self.max_paths = max_paths
        self.z3_timeout_ms = z3_timeout_ms
        self.struct_seed: StructSeed = struct_seed or {}

        # Per-path solve state (set at start of each _solve_path call)
        self._solver: Optional[z3.Solver] = None
        self._mem_cache: Dict[Tuple[str, int], z3.ExprRef] = {}
        self._seeded_fields_used: Set[str] = set()

    # ── public API ────────────────────────────────────────────────────────────

    def solve(self, target_va: int) -> List[PathResult]:
        """Enumerate paths to target_va and solve each with Z3. Returns all results."""
        results = []
        for path in self._enum_paths(self.func_va, target_va):
            result = self._solve_path(path, target_va)
            results.append(result)
            if len(results) >= self.max_paths:
                break
        return results

    def solve_first_sat(self, target_va: int) -> Optional[PathResult]:
        """Return the first SAT result, or None if all paths are UNSAT."""
        for path in self._enum_paths(self.func_va, target_va):
            result = self._solve_path(path, target_va)
            if result.sat:
                return result
        return None

    # ── path enumeration (doc section 2: loop boundary) ──────────────────────

    def _enum_paths(self, start: int, target: int):
        """DFS from start to target. Yields simple paths (no repeated blocks)."""
        stack = [(start, [start], {start})]
        while stack:
            node, path, visited = stack.pop()
            if node == target:
                yield path
                continue
            if len(path) >= self.max_path_blocks:
                continue
            block = self.cfg.blocks.get(node)
            if not block:
                continue
            for succ in block.succs:
                if succ not in visited and succ in self.cfg.blocks:
                    stack.append((succ, path + [succ], visited | {succ}))

    # ── symbolic register state ───────────────────────────────────────────────

    def _fresh_state(self) -> Dict[str, z3.ExprRef]:
        """Initial state: each register is a free 64-bit symbolic variable."""
        return {name: z3.BitVec(f"{name}_0", 64) for name in _ALL_REGS}

    def _read(self, regs: Dict[str, z3.ExprRef], reg_id: int) -> z3.ExprRef:
        info = _REG_MAP.get(reg_id)
        if not info:
            return z3.BitVec(f"unknown_reg_{reg_id}", 64)
        name, lsb, width = info
        expr = regs.get(name, z3.BitVec(f"{name}_0", 64))
        if width == 64:
            return expr
        extracted = z3.Extract(lsb + width - 1, lsb, expr)
        return extracted

    def _write(self, regs: Dict[str, z3.ExprRef], reg_id: int, val: z3.ExprRef):
        info = _REG_MAP.get(reg_id)
        if not info:
            return
        name, lsb, width = info
        actual_width = val.size()
        if width == 64:
            if actual_width < 64:
                val = z3.ZeroExt(64 - actual_width, val)
            regs[name] = val
        elif width == 32:
            # 32-bit write zero-extends upper 32 bits (x86-64 behavior)
            if actual_width > 32:
                val = z3.Extract(31, 0, val)
            elif actual_width < 32:
                val = z3.ZeroExt(32 - actual_width, val)
            regs[name] = z3.ZeroExt(32, val)
        else:
            # 8/16-bit: insert into parent keeping other bits
            parent = regs.get(name, z3.BitVec(f"{name}_0", 64))
            if actual_width > width:
                val = z3.Extract(width - 1, 0, val)
            elif actual_width < width:
                val = z3.ZeroExt(width - actual_width, val)
            # Clear the target bits, then OR in the new value
            mask = ((1 << width) - 1) << lsb
            cleared = parent & z3.BitVecVal((~mask) & 0xFFFFFFFFFFFFFFFF, 64)
            inserted = z3.ZeroExt(64 - width, val) << z3.BitVecVal(lsb, 64)
            regs[name] = cleared | inserted

    def _op_expr(self, regs: Dict[str, z3.ExprRef],
                 op, va: int) -> z3.ExprRef:
        if op.type == X86_OP_IMM:
            v = op.imm & 0xFFFFFFFFFFFFFFFF
            return z3.BitVecVal(v, 64)
        if op.type == X86_OP_REG:
            return self._read(regs, op.reg)
        if op.type == X86_OP_MEM:
            m = op.mem
            # Struct-seeded lookup: (base_reg_name, byte_offset) -> MemoryConstraint
            if self.struct_seed and m.base and m.base != X86_REG_INVALID:
                base_info = _REG_MAP.get(m.base)
                if base_info:
                    base_name, _, _ = base_info
                    key = (base_name, m.disp)
                    if key in self.struct_seed:
                        mc = self.struct_seed[key]
                        if key in self._mem_cache:
                            return self._mem_cache[key]
                        sym = z3.BitVec(f"{mc.name}_s", mc.width)
                        if self._solver is not None:
                            if mc.exact is not None:
                                self._solver.add(sym == z3.BitVecVal(mc.exact, mc.width))
                            else:
                                if mc.lo is not None:
                                    self._solver.add(z3.UGE(sym, z3.BitVecVal(mc.lo, mc.width)))
                                if mc.hi is not None:
                                    self._solver.add(z3.ULE(sym, z3.BitVecVal(mc.hi, mc.width)))
                        self._mem_cache[key] = sym
                        self._seeded_fields_used.add(mc.name)
                        if mc.width < 64:
                            return z3.ZeroExt(64 - mc.width, sym)
                        return sym
            # Unconstrained symbolic memory read -- sound over-approximation
            return z3.BitVec(f"mem@{va:#x}", 64)
        return z3.BitVec(f"unk@{va:#x}", 64)

    # ── branch constraint builder (doc section 3D: FOL) ──────────────────────

    def _branch_constraint(
        self,
        jmp_id: int,
        a: z3.ExprRef,
        b: z3.ExprRef,
        taken: bool,
    ) -> Optional[z3.ExprRef]:
        """
        Translate branch semantics into a Z3 boolean constraint.
        `taken` is True when the branch goes to the target address.
        Implements doc section 3D: phi contains one clause per branch on the path.
        """
        def norm(x: z3.ExprRef) -> z3.ExprRef:
            if x.size() < 64:
                return z3.ZeroExt(64 - x.size(), x)
            return x

        a, b = norm(a), norm(b)
        zero = z3.BitVecVal(0, 64)

        # Z3 Python: < <= > >= on BitVec = signed; ULT/ULE/UGT/UGE = unsigned
        if jmp_id == X86_INS_JE:
            cond = (a == b)
        elif jmp_id == X86_INS_JNE:
            cond = (a != b)
        elif jmp_id == X86_INS_JL:
            cond = (a < b)
        elif jmp_id == X86_INS_JLE:
            cond = (a <= b)
        elif jmp_id == X86_INS_JG:
            cond = (a > b)
        elif jmp_id == X86_INS_JGE:
            cond = (a >= b)
        elif jmp_id == X86_INS_JB:
            cond = z3.ULT(a, b)
        elif jmp_id == X86_INS_JBE:
            cond = z3.ULE(a, b)
        elif jmp_id == X86_INS_JA:
            cond = z3.UGT(a, b)
        elif jmp_id == X86_INS_JAE:
            cond = z3.UGE(a, b)
        elif jmp_id == X86_INS_JS:
            cond = (a < zero)
        elif jmp_id == X86_INS_JNS:
            cond = (a >= zero)
        elif jmp_id in (X86_INS_JO, X86_INS_JNO):
            return None  # overflow flag -- too complex without full flag tracking
        else:
            return None

        return cond if taken else z3.Not(cond)

    # ── symbolic execution of one path ───────────────────────────────────────

    def _solve_path(self, path: List[int], target_va: int) -> PathResult:
        """
        Execute one path symbolically and solve with Z3.

        For each block on the path:
          - Process instructions as state constraints (register assignments)
          - At the terminating branch, add direction constraint (path constraint)
        Combined phi = AND of all constraints = document's section 3D formula.
        """
        regs = self._fresh_state()
        solver = z3.Solver()
        solver.set("timeout", self.z3_timeout_ms)
        clauses = 0
        last_cmp: Optional[Tuple[z3.ExprRef, z3.ExprRef]] = None
        call_idx = 0

        # Reset per-path struct-seed state
        self._solver = solver
        self._mem_cache = {}
        self._seeded_fields_used = set()

        for step, block_va in enumerate(path):
            block = self.cfg.blocks.get(block_va)
            if not block:
                continue

            next_block_va = path[step + 1] if step + 1 < len(path) else None
            offset = block_va - self.func_va
            if offset < 0 or offset >= len(self.data):
                continue

            chunk = self.data[offset:]

            # Cap at the last instruction VA in this block -- avoids spilling into
            # successor blocks when block.end is a short distance from the next boundary.
            last_insn_va = block.insns[-1][0] if block.insns else block_va

            for insn in self.md.disasm(chunk, block_va):
                if insn.address > last_insn_va:
                    break
                if insn.address >= self.func_end_va:
                    break

                ops = insn.operands or []
                mid = insn.id

                # ── data transfer ──────────────────────────────────────────
                if mid in (X86_INS_MOV, X86_INS_MOVAPS, X86_INS_MOVD):
                    if len(ops) == 2 and ops[0].type == X86_OP_REG:
                        self._write(regs, ops[0].reg,
                                    self._op_expr(regs, ops[1], insn.address))

                elif mid == X86_INS_MOVZX:
                    if len(ops) == 2 and ops[0].type == X86_OP_REG:
                        src = self._op_expr(regs, ops[1], insn.address)
                        sw = ops[1].size * 8 if ops[1].size else src.size()
                        if src.size() > sw:
                            src = z3.Extract(sw - 1, 0, src)
                        self._write(regs, ops[0].reg, z3.ZeroExt(64 - sw, src))

                elif mid == X86_INS_MOVSX:
                    if len(ops) == 2 and ops[0].type == X86_OP_REG:
                        src = self._op_expr(regs, ops[1], insn.address)
                        sw = ops[1].size * 8 if ops[1].size else src.size()
                        if src.size() > sw:
                            src = z3.Extract(sw - 1, 0, src)
                        self._write(regs, ops[0].reg, z3.SignExt(64 - sw, src))

                elif mid == X86_INS_LEA:
                    if len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
                        m = ops[1].mem
                        addr: z3.ExprRef = z3.BitVecVal(m.disp & 0xFFFFFFFFFFFFFFFF, 64)
                        if m.base and m.base != X86_REG_INVALID:
                            addr = addr + self._read(regs, m.base)
                        if m.index and m.index != X86_REG_INVALID:
                            idx = self._read(regs, m.index)
                            addr = addr + idx * z3.BitVecVal(m.scale or 1, 64)
                        self._write(regs, ops[0].reg, addr)

                # ── arithmetic ─────────────────────────────────────────────
                elif mid == X86_INS_ADD:
                    if len(ops) == 2 and ops[0].type == X86_OP_REG:
                        dst = self._read(regs, ops[0].reg)
                        src = self._op_expr(regs, ops[1], insn.address)
                        if dst.size() != 64: dst = z3.ZeroExt(64 - dst.size(), dst)
                        if src.size() != 64: src = z3.ZeroExt(64 - src.size(), src)
                        self._write(regs, ops[0].reg, dst + src)

                elif mid == X86_INS_SUB:
                    if len(ops) == 2 and ops[0].type == X86_OP_REG:
                        dst = self._read(regs, ops[0].reg)
                        src = self._op_expr(regs, ops[1], insn.address)
                        if dst.size() != 64: dst = z3.ZeroExt(64 - dst.size(), dst)
                        if src.size() != 64: src = z3.ZeroExt(64 - src.size(), src)
                        self._write(regs, ops[0].reg, dst - src)

                elif mid == X86_INS_XOR:
                    if len(ops) == 2 and ops[0].type == X86_OP_REG:
                        if ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
                            # Axiomatic reduction: xor x,x -> 0 (doc section 3B)
                            self._write(regs, ops[0].reg, z3.BitVecVal(0, 64))
                        else:
                            dst = self._read(regs, ops[0].reg)
                            src = self._op_expr(regs, ops[1], insn.address)
                            if dst.size() != src.size():
                                w = max(dst.size(), src.size())
                                dst = z3.ZeroExt(w - dst.size(), dst)
                                src = z3.ZeroExt(w - src.size(), src)
                            self._write(regs, ops[0].reg, dst ^ src)

                elif mid == X86_INS_AND:
                    if len(ops) == 2 and ops[0].type == X86_OP_REG:
                        dst = self._read(regs, ops[0].reg)
                        src = self._op_expr(regs, ops[1], insn.address)
                        if dst.size() != 64: dst = z3.ZeroExt(64 - dst.size(), dst)
                        if src.size() != 64: src = z3.ZeroExt(64 - src.size(), src)
                        if ops[1].type == X86_OP_IMM and ops[1].imm == 0:
                            result = z3.BitVecVal(0, 64)  # and x,0 -> 0
                        else:
                            result = dst & src
                        self._write(regs, ops[0].reg, result)
                        last_cmp = (result, z3.BitVecVal(0, 64))

                elif mid == X86_INS_OR:
                    if len(ops) == 2 and ops[0].type == X86_OP_REG:
                        dst = self._read(regs, ops[0].reg)
                        src = self._op_expr(regs, ops[1], insn.address)
                        if dst.size() != 64: dst = z3.ZeroExt(64 - dst.size(), dst)
                        if src.size() != 64: src = z3.ZeroExt(64 - src.size(), src)
                        self._write(regs, ops[0].reg, dst | src)

                elif mid in (X86_INS_SHL, X86_INS_SAL):
                    if len(ops) >= 1 and ops[0].type == X86_OP_REG:
                        dst = self._read(regs, ops[0].reg)
                        amt = (self._op_expr(regs, ops[1], insn.address)
                               if len(ops) > 1 else self._read(regs, X86_REG_CL))
                        if dst.size() != 64: dst = z3.ZeroExt(64 - dst.size(), dst)
                        if amt.size() != 64: amt = z3.ZeroExt(64 - amt.size(), amt)
                        self._write(regs, ops[0].reg, dst << amt)

                elif mid == X86_INS_SHR:
                    if len(ops) >= 1 and ops[0].type == X86_OP_REG:
                        dst = self._read(regs, ops[0].reg)
                        amt = (self._op_expr(regs, ops[1], insn.address)
                               if len(ops) > 1 else self._read(regs, X86_REG_CL))
                        if dst.size() != 64: dst = z3.ZeroExt(64 - dst.size(), dst)
                        if amt.size() != 64: amt = z3.ZeroExt(64 - amt.size(), amt)
                        self._write(regs, ops[0].reg, z3.LShR(dst, amt))

                elif mid == X86_INS_SAR:
                    if len(ops) >= 1 and ops[0].type == X86_OP_REG:
                        dst = self._read(regs, ops[0].reg)
                        amt = (self._op_expr(regs, ops[1], insn.address)
                               if len(ops) > 1 else self._read(regs, X86_REG_CL))
                        if dst.size() != 64: dst = z3.ZeroExt(64 - dst.size(), dst)
                        if amt.size() != 64: amt = z3.ZeroExt(64 - amt.size(), amt)
                        self._write(regs, ops[0].reg, dst >> amt)

                elif mid == X86_INS_NOT:
                    if len(ops) == 1 and ops[0].type == X86_OP_REG:
                        dst = self._read(regs, ops[0].reg)
                        self._write(regs, ops[0].reg, ~dst)

                elif mid == X86_INS_NEG:
                    if len(ops) == 1 and ops[0].type == X86_OP_REG:
                        dst = self._read(regs, ops[0].reg)
                        self._write(regs, ops[0].reg, -dst)

                elif mid in (X86_INS_IMUL, X86_INS_MUL):
                    if len(ops) >= 2 and ops[0].type == X86_OP_REG:
                        if len(ops) == 3:
                            a = self._op_expr(regs, ops[1], insn.address)
                            b = self._op_expr(regs, ops[2], insn.address)
                        else:
                            a = self._read(regs, ops[0].reg)
                            b = self._op_expr(regs, ops[1], insn.address)
                        if a.size() != 64: a = z3.ZeroExt(64 - a.size(), a)
                        if b.size() != 64: b = z3.ZeroExt(64 - b.size(), b)
                        self._write(regs, ops[0].reg, a * b)

                # ── flag setters ───────────────────────────────────────────
                elif mid == X86_INS_TEST:
                    if len(ops) == 2:
                        a = self._op_expr(regs, ops[0], insn.address)
                        b = self._op_expr(regs, ops[1], insn.address)
                        if a.size() != 64: a = z3.ZeroExt(64 - a.size(), a)
                        if b.size() != 64: b = z3.ZeroExt(64 - b.size(), b)
                        last_cmp = (a & b, z3.BitVecVal(0, 64))

                elif mid == X86_INS_CMP:
                    if len(ops) == 2:
                        a = self._op_expr(regs, ops[0], insn.address)
                        b = self._op_expr(regs, ops[1], insn.address)
                        if a.size() != 64: a = z3.ZeroExt(64 - a.size(), a)
                        if b.size() != 64: b = z3.ZeroExt(64 - b.size(), b)
                        last_cmp = (a, b)

                # ── calls: clear caller-saved (conservative) ───────────────
                elif mid == X86_INS_CALL:
                    call_idx += 1
                    for reg_name in _CALLER_SAVED:
                        regs[reg_name] = z3.BitVec(
                            f"{reg_name}_call{call_idx}", 64)
                    last_cmp = None

                # ── branch constraints (doc 3D: phi clauses) ──────────────
                elif mid in _BRANCH_IDS:
                    if next_block_va is not None and last_cmp is not None:
                        target_of_branch = (ops[0].imm
                                            if ops and ops[0].type == X86_OP_IMM
                                            else None)
                        taken = (target_of_branch == next_block_va)
                        constraint = self._branch_constraint(
                            mid, last_cmp[0], last_cmp[1], taken)
                        if constraint is not None:
                            solver.add(constraint)
                            clauses += 1

        status = solver.check()
        sat = (status == z3.sat)
        note = ""
        model_dict: Dict[str, int] = {}

        if status == z3.unknown:
            note = "timeout"
        elif not sat:
            note = "unsat"

        if sat:
            m = solver.model()
            for name in _ALL_REGS:
                sym = z3.BitVec(f"{name}_0", 64)
                val = m.eval(sym, model_completion=True)
                if z3.is_bv_value(val):
                    model_dict[name] = val.as_long()

        return PathResult(sat=sat, path=path, model=model_dict,
                          clauses=clauses, note=note,
                          seeded_fields=sorted(self._seeded_fields_used))


# ── convenience wrapper ───────────────────────────────────────────────────────

def solve_for_sink(
    data: bytes,
    func_va: int,
    func_end_va: int,
    plt: Dict[int, str],
    cfg: Any,
    md: capstone.Cs,
    target_va: int,
    **kwargs,
) -> Optional[PathResult]:
    """
    One-call wrapper: find the first SAT path from func_va to target_va.
    Returns None if no satisfiable path exists within bounds.
    """
    ps = PathSolver(data, func_va, func_end_va, plt, cfg, md, **kwargs)
    return ps.solve_first_sat(target_va)
